use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;

use rand::{RngExt, SeedableRng};
use rand_pcg::Pcg32;

use crate::congestion::ControllerMetrics;
use crate::congestion::bbr::bw_estimation::BandwidthEstimation;
use crate::connection::RttEstimator;
use crate::{Duration, Instant};

use super::{BASE_DATAGRAM_SIZE, Controller, ControllerFactory};

mod bw_estimation;
mod min_max;

/// Experimental! Use at your own risk.
///
/// Aims for reduced buffer bloat and improved performance over high bandwidth-delay product networks.
/// Based on google's quiche implementation <https://source.chromium.org/chromium/chromium/src/+/master:net/third_party/quiche/src/quic/core/congestion_control/bbr_sender.cc>
/// of BBR <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control>.
/// More discussion and links at <https://groups.google.com/g/bbr-dev>.
#[derive(Debug, Clone)]
pub struct Bbr {
    config: Arc<BbrConfig>,
    current_mtu: u64,
    max_bandwidth: BandwidthEstimation,
    acked_bytes: u64,
    mode: Mode,
    loss_state: LossState,
    recovery_state: RecoveryState,
    recovery_window: u64,
    is_at_full_bandwidth: bool,
    pacing_gain: f32,
    high_gain: f32,
    drain_gain: f32,
    cwnd_gain: f32,
    high_cwnd_gain: f32,
    last_cycle_start: Option<Instant>,
    current_cycle_offset: u8,
    init_cwnd: u64,
    min_cwnd: u64,
    prev_in_flight_count: u64,
    exit_probe_rtt_at: Option<Instant>,
    probe_rtt_last_started_at: Option<Instant>,
    min_rtt: Duration,
    exiting_quiescence: bool,
    pacing_rate: u64,
    max_acked_packet_number: u64,
    max_sent_packet_number: u64,
    end_recovery_at_packet_number: u64,
    cwnd: u64,
    current_round_trip_end_packet_number: u64,
    round_count: u64,
    bw_at_last_round: u64,
    round_wo_bw_gain: u64,
    ack_aggregation: AckAggregationState,
    detect_overshooting: bool,
    bytes_lost_while_detecting_overshooting: u64,
    bytes_lost_multiplier_while_detecting_overshooting: u8,
    last_sample_is_app_limited: bool,
    loss_events_in_round: u64,
    bytes_lost_in_round: u64,
    last_event_packet_number: Option<u64>,
    last_event_packet_bytes_in_flight_at_send: Option<u64>,
    random_number_generator: Pcg32,
}

impl Bbr {
    /// Construct a state using the given `config` and current time `now`
    pub fn new(config: Arc<BbrConfig>, current_mtu: u16) -> Self {
        let initial_window = config.initial_window;
        let high_gain = config.high_gain;
        let high_cwnd_gain = config.high_cwnd_gain;
        let detect_overshooting = config.detect_overshooting;
        let bytes_lost_multiplier_while_detecting_overshooting =
            config.bytes_lost_multiplier_while_detecting_overshooting;
        let ack_aggregation = AckAggregationState::new(
            if config.enable_overestimate_avoidance {
                2.0
            } else {
                1.0
            },
            config.reduce_extra_acked_on_bandwidth_increase,
        );
        let mut max_bandwidth = BandwidthEstimation::default();
        if config.enable_overestimate_avoidance {
            max_bandwidth.enable_overestimate_avoidance();
        }
        Self {
            config,
            current_mtu: current_mtu as u64,
            max_bandwidth,
            acked_bytes: 0,
            mode: Mode::Startup,
            loss_state: Default::default(),
            recovery_state: RecoveryState::NotInRecovery,
            recovery_window: 0,
            is_at_full_bandwidth: false,
            pacing_gain: high_gain,
            high_gain,
            drain_gain: 1.0 / high_gain,
            cwnd_gain: high_cwnd_gain,
            high_cwnd_gain,
            last_cycle_start: None,
            current_cycle_offset: 0,
            init_cwnd: initial_window,
            min_cwnd: calculate_min_window(current_mtu as u64),
            prev_in_flight_count: 0,
            exit_probe_rtt_at: None,
            probe_rtt_last_started_at: None,
            min_rtt: Default::default(),
            exiting_quiescence: false,
            pacing_rate: 0,
            max_acked_packet_number: 0,
            max_sent_packet_number: 0,
            end_recovery_at_packet_number: 0,
            cwnd: initial_window,
            current_round_trip_end_packet_number: 0,
            round_count: 0,
            bw_at_last_round: 0,
            round_wo_bw_gain: 0,
            ack_aggregation,
            detect_overshooting,
            bytes_lost_while_detecting_overshooting: 0,
            bytes_lost_multiplier_while_detecting_overshooting,
            last_sample_is_app_limited: false,
            loss_events_in_round: 0,
            bytes_lost_in_round: 0,
            last_event_packet_number: None,
            last_event_packet_bytes_in_flight_at_send: None,
            random_number_generator: Pcg32::from_rng(&mut rand::rng()),
        }
    }

    fn enter_startup_mode(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.high_gain;
        self.cwnd_gain = self.high_cwnd_gain;
    }

    fn enter_probe_bandwidth_mode(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = self.config.congestion_window_gain;
        self.last_cycle_start = Some(now);
        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
        // excluded because in that case increased gain and decreased gain would not
        // follow each other.
        let mut rand_index = self
            .random_number_generator
            .random_range(0..K_PACING_GAIN.len() as u8 - 1);
        if rand_index >= 1 {
            rand_index += 1;
        }
        self.current_cycle_offset = rand_index;
        self.pacing_gain = K_PACING_GAIN[rand_index as usize];
    }

    fn update_recovery_state(&mut self, is_round_start: bool) {
        // quic-go disables recovery during STARTUP. Loss-based STARTUP exit is handled separately
        // after enough loss events have accumulated in a round.
        if !self.is_at_full_bandwidth {
            return;
        }

        // Exit recovery when there are no losses for a round.
        if self.loss_state.has_losses() {
            self.end_recovery_at_packet_number = self.max_sent_packet_number;
        }
        match self.recovery_state {
            // Enter conservation on the first loss.
            RecoveryState::NotInRecovery if self.loss_state.has_losses() => {
                self.recovery_state = RecoveryState::Conservation;
                // This will cause the |recovery_window| to be set to the
                // correct value in CalculateRecoveryWindow().
                self.recovery_window = 0;
                // Since the conservation phase is meant to be lasting for a whole
                // round, extend the current round as if it were started right now.
                self.current_round_trip_end_packet_number = self.max_sent_packet_number;
            }
            RecoveryState::Growth | RecoveryState::Conservation => {
                if self.recovery_state == RecoveryState::Conservation && is_round_start {
                    self.recovery_state = RecoveryState::Growth;
                }
                // Exit recovery if appropriate.
                if !self.loss_state.has_losses()
                    && self.max_acked_packet_number > self.end_recovery_at_packet_number
                {
                    self.recovery_state = RecoveryState::NotInRecovery;
                }
            }
            _ => {}
        }
    }

    fn update_gain_cycle_phase(&mut self, now: Instant, in_flight: u64) {
        // In most cases, the cycle is advanced after an RTT passes.
        let mut should_advance_gain_cycling = self
            .last_cycle_start
            .map(|last_cycle_start| now.duration_since(last_cycle_start) > self.min_rtt)
            .unwrap_or(false);
        // If the pacing gain is above 1.0, the connection is trying to probe the
        // bandwidth by increasing the number of bytes in flight to at least
        // pacing_gain * BDP.  Make sure that it actually reaches the target, as
        // long as there are no losses suggesting that the buffers are not able to
        // hold that much.
        if self.pacing_gain > 1.0
            && !self.loss_state.has_losses()
            && self.prev_in_flight_count < self.get_target_cwnd(self.pacing_gain)
        {
            should_advance_gain_cycling = false;
        }

        // If pacing gain is below 1.0, the connection is trying to drain the extra
        // queue which could have been incurred by probing prior to it.  If the
        // number of bytes in flight falls down to the estimated BDP value earlier,
        // conclude that the queue has been successfully drained and exit this cycle
        // early.
        if self.pacing_gain < 1.0 && in_flight <= self.get_target_cwnd(1.0) {
            should_advance_gain_cycling = true;
        }

        if should_advance_gain_cycling {
            self.current_cycle_offset = (self.current_cycle_offset + 1) % K_PACING_GAIN.len() as u8;
            self.last_cycle_start = Some(now);
            // Stay in low gain mode until the target BDP is hit.  Low gain mode
            // will be exited immediately when the target BDP is achieved.
            if self.config.drain_to_target
                && self.pacing_gain < 1.0
                && (K_PACING_GAIN[self.current_cycle_offset as usize] - 1.0).abs() < f32::EPSILON
                && in_flight > self.get_target_cwnd(1.0)
            {
                return;
            }
            self.pacing_gain = K_PACING_GAIN[self.current_cycle_offset as usize];
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Instant, in_flight: u64) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.cwnd_gain = self.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && in_flight <= self.get_target_cwnd(1.0) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    fn is_min_rtt_expired(&self, now: Instant, app_limited: bool) -> bool {
        !app_limited
            && self
                .probe_rtt_last_started_at
                .map(|last| now.saturating_duration_since(last) > Duration::from_secs(10))
                .unwrap_or(true)
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        bytes_in_flight: u64,
        app_limited: bool,
    ) {
        let min_rtt_expired = self.is_min_rtt_expired(now, app_limited);
        if min_rtt_expired && !self.exiting_quiescence && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            // Do not decide on the time to exit ProbeRtt until the
            // |bytes_in_flight| is at the target small value.
            self.exit_probe_rtt_at = None;
            self.probe_rtt_last_started_at = Some(now);
        }

        if self.mode == Mode::ProbeRtt {
            match self.exit_probe_rtt_at {
                None => {
                    // If the window has reached the appropriate size, schedule exiting
                    // ProbeRtt.  The CWND during ProbeRtt is
                    // kMinimumCongestionWindow, but we allow an extra packet since QUIC
                    // checks CWND before sending a packet.
                    if bytes_in_flight < self.get_probe_rtt_cwnd() + self.current_mtu {
                        const K_PROBE_RTT_TIME: Duration = Duration::from_millis(200);
                        self.exit_probe_rtt_at = Some(now + K_PROBE_RTT_TIME);
                    }
                }
                Some(exit_time) if is_round_start && now >= exit_time => {
                    if !self.is_at_full_bandwidth {
                        self.enter_startup_mode();
                    } else {
                        self.enter_probe_bandwidth_mode(now);
                    }
                }
                Some(_) => {}
            }
        }

        self.exiting_quiescence = false;
    }

    fn get_target_cwnd(&self, gain: f32) -> u64 {
        let bw = self.max_bandwidth.get_estimate();
        let bdp = self.min_rtt.as_micros() as u64 * bw;
        let bdpf = bdp as f64;
        let cwnd = ((gain as f64 * bdpf) / 1_000_000f64) as u64;
        // BDP estimate will be zero if no bandwidth samples are available yet.
        if cwnd == 0 {
            return self.init_cwnd;
        }
        cwnd.max(self.min_cwnd)
    }

    fn get_probe_rtt_cwnd(&self) -> u64 {
        const K_MODERATE_PROBE_RTT_MULTIPLIER: f32 = 0.75;
        if PROBE_RTT_BASED_ON_BDP {
            return self.get_target_cwnd(K_MODERATE_PROBE_RTT_MULTIPLIER);
        }
        self.min_cwnd
    }

    fn calculate_pacing_rate(&mut self) {
        let bw = self.max_bandwidth.get_estimate();
        if bw == 0 {
            return;
        }
        let target_rate = (bw as f64 * self.pacing_gain as f64) as u64;
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        // Pace at the rate of initial_window / RTT as soon as RTT measurements are
        // available.
        if self.pacing_rate == 0 && self.min_rtt.as_nanos() != 0 {
            self.pacing_rate =
                BandwidthEstimation::bw_from_delta(self.init_cwnd, self.min_rtt).unwrap();
            return;
        }

        if self.detect_overshooting {
            self.bytes_lost_while_detecting_overshooting = self
                .bytes_lost_while_detecting_overshooting
                .saturating_add(self.loss_state.lost_bytes);
            let loss_proves_overshoot = self
                .bytes_lost_while_detecting_overshooting
                .saturating_mul(u64::from(
                    self.bytes_lost_multiplier_while_detecting_overshooting,
                ))
                > self.init_cwnd;
            if self.pacing_rate > target_rate
                && self.bytes_lost_while_detecting_overshooting > 0
                && (self.max_bandwidth.has_non_app_limited_sample() || loss_proves_overshoot)
            {
                let minimum_rate =
                    BandwidthEstimation::bw_from_delta(self.init_cwnd, self.min_rtt).unwrap_or(0);
                self.pacing_rate = target_rate.max(minimum_rate);
                self.bytes_lost_while_detecting_overshooting = 0;
                self.detect_overshooting = false;
            }
        }

        // Do not decrease the pacing rate during startup.
        if self.pacing_rate < target_rate {
            self.pacing_rate = target_rate;
        }
    }

    fn calculate_cwnd(&mut self, bytes_acked: u64, excess_acked: u64) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let mut target_window = self.get_target_cwnd(self.cwnd_gain);
        if self.is_at_full_bandwidth {
            // Add the max recently measured ack aggregation to CWND.
            target_window += self.ack_aggregation.max_ack_height.get();
        } else if self.config.enable_ack_aggregation_during_startup {
            // Add the most recent excess acked.  Because CWND never decreases in
            // STARTUP, this will automatically create a very localized max filter.
            target_window += excess_acked;
        }
        // Instead of immediately setting the target CWND as the new one, BBR grows
        // the CWND towards |target_window| by only increasing it |bytes_acked| at a
        // time.
        if self.is_at_full_bandwidth {
            self.cwnd = target_window.min(self.cwnd + bytes_acked);
        } else if (self.cwnd_gain < target_window as f32) || (self.acked_bytes < self.init_cwnd) {
            // If the connection is not yet out of startup phase, do not decrease
            // the window.
            self.cwnd += bytes_acked;
        }

        // Enforce the limits on the congestion window.
        if self.cwnd < self.min_cwnd {
            self.cwnd = self.min_cwnd;
        }
    }

    fn calculate_recovery_window(&mut self, bytes_acked: u64, bytes_lost: u64, in_flight: u64) {
        if !self.recovery_state.in_recovery() {
            return;
        }
        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window = self.min_cwnd.max(in_flight + bytes_acked);
            return;
        }

        // Remove losses from the recovery window, while accounting for a potential
        // integer underflow.
        if self.recovery_window >= bytes_lost {
            self.recovery_window -= bytes_lost;
        } else {
            // k_max_segment_size = current_mtu
            self.recovery_window = self.current_mtu;
        }
        // In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
        // release additional |bytes_acked| to achieve a slow-start-like behavior.
        if self.recovery_state == RecoveryState::Growth {
            self.recovery_window += bytes_acked;
        }

        // Sanity checks.  Ensure that we always allow to send at least an MSS or
        // |bytes_acked| in response, whichever is larger.
        self.recovery_window = self
            .recovery_window
            .max(in_flight + bytes_acked)
            .max(self.min_cwnd);
    }

    /// <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control#section-4.3.2.2>
    fn check_if_full_bw_reached(&mut self, app_limited: bool) {
        if app_limited {
            return;
        }
        let target = (self.bw_at_last_round as f64 * K_STARTUP_GROWTH_TARGET as f64) as u64;
        let bw = self.max_bandwidth.get_estimate();
        if bw >= target {
            self.bw_at_last_round = bw;
            self.round_wo_bw_gain = 0;
            if self.config.expire_ack_aggregation_in_startup {
                self.ack_aggregation
                    .max_ack_height
                    .reset(0, self.round_count);
            }
            return;
        }

        self.round_wo_bw_gain += 1;
        if self.round_wo_bw_gain >= u64::from(self.config.startup_rounds_without_growth)
            || self.should_exit_startup_due_to_loss()
        {
            self.is_at_full_bandwidth = true;
        }
    }

    fn should_exit_startup_due_to_loss(&self) -> bool {
        const STARTUP_FULL_LOSS_COUNT: u64 = 8;
        const STARTUP_LOSS_THRESHOLD: f64 = 0.02;

        if self.loss_events_in_round < STARTUP_FULL_LOSS_COUNT {
            return false;
        }
        let Some(in_flight_at_send) = self.last_event_packet_bytes_in_flight_at_send else {
            return false;
        };
        in_flight_at_send > 0
            && self.bytes_lost_in_round
                > (in_flight_at_send as f64 * STARTUP_LOSS_THRESHOLD) as u64
    }

    fn record_last_event_packet(&mut self, packet_number: u64, bytes_in_flight_at_send: u64) {
        if self
            .last_event_packet_number
            .is_none_or(|last| packet_number >= last)
        {
            self.last_event_packet_number = Some(packet_number);
            self.last_event_packet_bytes_in_flight_at_send = Some(bytes_in_flight_at_send);
        }
    }
}

impl Controller for Bbr {
    fn on_sent(
        &mut self,
        now: Instant,
        bytes: u64,
        last_packet_number: u64,
        bytes_in_flight_before: u64,
    ) {
        self.max_sent_packet_number = last_packet_number;
        self.max_bandwidth.on_sent(
            now,
            last_packet_number,
            bytes,
            bytes_in_flight_before,
        );
    }

    fn on_begin_congestion_event(&mut self, prior_bytes_in_flight: u64) {
        if prior_bytes_in_flight < self.get_target_cwnd(1.0) {
            self.max_bandwidth
                .on_app_limited(self.max_sent_packet_number);
        }
    }

    fn on_packet_lost(&mut self, packet_number: u64, _bytes: u64) {
        self.max_bandwidth.on_packet_lost(packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        packet_number: u64,
        bytes: u64,
        bytes_in_flight_at_send: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.record_last_event_packet(packet_number, bytes_in_flight_at_send);
        self.max_bandwidth
            .on_ack(now, packet_number, self.round_count);
        self.acked_bytes += bytes;
        if self.is_min_rtt_expired(now, app_limited) || self.min_rtt > rtt.min() {
            self.min_rtt = rtt.min();
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let bytes_acked = self.max_bandwidth.bytes_acked_this_window();
        if let Some(app_limited_sample) = self.max_bandwidth.window_sample_app_limited() {
            self.last_sample_is_app_limited = app_limited_sample;
        }
        let bandwidth_increased = self.max_bandwidth.estimate_increased_this_window();
        let excess_acked = self.ack_aggregation.update_ack_aggregation_bytes(
            bytes_acked,
            now,
            self.round_count,
            self.max_bandwidth.get_estimate(),
            bandwidth_increased,
        );
        self.max_bandwidth
            .end_acks(self.round_count, app_limited, bytes_acked > 0 && excess_acked == 0);
        if let Some(largest_acked_packet) = largest_packet_num_acked {
            self.max_acked_packet_number = largest_acked_packet;
        }

        let mut is_round_start = false;
        if bytes_acked > 0 {
            is_round_start =
                self.max_acked_packet_number > self.current_round_trip_end_packet_number;
            if is_round_start {
                self.current_round_trip_end_packet_number = self.max_sent_packet_number;
                self.round_count += 1;
            }
        }

        self.update_recovery_state(is_round_start);

        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle_phase(now, in_flight);
        }

        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bw_reached(self.last_sample_is_app_limited);
        }

        self.maybe_exit_startup_or_drain(now, in_flight);

        self.maybe_enter_or_exit_probe_rtt(now, is_round_start, in_flight, app_limited);

        // After the model is updated, recalculate the pacing rate and congestion window.
        self.calculate_pacing_rate();
        self.calculate_cwnd(bytes_acked, excess_acked);
        self.calculate_recovery_window(bytes_acked, self.loss_state.lost_bytes, in_flight);

        self.prev_in_flight_count = in_flight;
        self.loss_state.reset();
        self.last_event_packet_number = None;
        self.last_event_packet_bytes_in_flight_at_send = None;
        if is_round_start {
            self.loss_events_in_round = 0;
            self.bytes_lost_in_round = 0;
        }
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
        lost_packets: u64,
        last_packet_number: Option<u64>,
        last_packet_bytes_in_flight_at_send: Option<u64>,
    ) {
        self.loss_state.lost_bytes += lost_bytes;
        if lost_packets > 0 {
            self.loss_events_in_round += 1;
            self.bytes_lost_in_round += lost_bytes;
        }
        if let (Some(packet_number), Some(bytes_in_flight_at_send)) = (
            last_packet_number,
            last_packet_bytes_in_flight_at_send,
        ) {
            self.record_last_event_packet(packet_number, bytes_in_flight_at_send);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.min_cwnd = calculate_min_window(self.current_mtu);
        self.init_cwnd = self.config.initial_window.max(self.min_cwnd);
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    fn window(&self) -> u64 {
        if self.mode == Mode::ProbeRtt {
            return self.get_probe_rtt_cwnd();
        } else if self.recovery_state.in_recovery() && self.mode != Mode::Startup {
            return self.cwnd.min(self.recovery_window);
        }
        self.cwnd
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: Some(self.pacing_rate * 8),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the [`Bbr`] congestion controller
#[derive(Debug, Clone)]
pub struct BbrConfig {
    initial_window: u64,
    high_gain: f32,
    high_cwnd_gain: f32,
    congestion_window_gain: f32,
    startup_rounds_without_growth: u8,
    drain_to_target: bool,
    enable_ack_aggregation_during_startup: bool,
    expire_ack_aggregation_in_startup: bool,
    detect_overshooting: bool,
    bytes_lost_multiplier_while_detecting_overshooting: u8,
    enable_overestimate_avoidance: bool,
    reduce_extra_acked_on_bandwidth_increase: bool,
}

impl BbrConfig {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }

    /// Set the STARTUP pacing gain.
    pub fn high_gain(&mut self, value: f32) -> &mut Self {
        self.high_gain = value;
        self
    }

    /// Set the STARTUP congestion-window gain.
    pub fn high_cwnd_gain(&mut self, value: f32) -> &mut Self {
        self.high_cwnd_gain = value;
        self
    }

    /// Set the congestion-window gain used during PROBE_BW.
    pub fn congestion_window_gain(&mut self, value: f32) -> &mut Self {
        self.congestion_window_gain = value;
        self
    }

    /// Set the rounds without bandwidth growth before leaving STARTUP.
    pub fn startup_rounds_without_growth(&mut self, value: u8) -> &mut Self {
        self.startup_rounds_without_growth = value;
        self
    }

    /// Keep the low-gain PROBE_BW phase active until the queue drains to its target.
    pub fn drain_to_target(&mut self, value: bool) -> &mut Self {
        self.drain_to_target = value;
        self
    }

    /// Include ACK aggregation in the congestion window during STARTUP.
    pub fn enable_ack_aggregation_during_startup(&mut self, value: bool) -> &mut Self {
        self.enable_ack_aggregation_during_startup = value;
        self
    }

    /// Expire ACK aggregation measurements when bandwidth grows during STARTUP.
    pub fn expire_ack_aggregation_in_startup(&mut self, value: bool) -> &mut Self {
        self.expire_ack_aggregation_in_startup = value;
        self
    }

    /// Detect excessive startup pacing from loss and lower the rate to measured capacity.
    pub fn detect_overshooting(&mut self, value: bool) -> &mut Self {
        self.detect_overshooting = value;
        self
    }

    /// Multiplier applied to accumulated startup loss when confirming an overshoot.
    pub fn bytes_lost_multiplier_while_detecting_overshooting(
        &mut self,
        value: u8,
    ) -> &mut Self {
        self.bytes_lost_multiplier_while_detecting_overshooting = value;
        self
    }

    /// Anchor ACK-rate samples to prior aggregation epochs to avoid ACK-compression overestimates.
    pub fn enable_overestimate_avoidance(&mut self, value: bool) -> &mut Self {
        self.enable_overestimate_avoidance = value;
        self
    }

    /// Recalculate retained ACK-height samples when the bandwidth estimate rises.
    pub fn reduce_extra_acked_on_bandwidth_increase(&mut self, value: bool) -> &mut Self {
        self.reduce_extra_acked_on_bandwidth_increase = value;
        self
    }
}

impl Default for BbrConfig {
    fn default() -> Self {
        Self {
            initial_window: K_MAX_INITIAL_CONGESTION_WINDOW * BASE_DATAGRAM_SIZE,
            high_gain: K_DEFAULT_HIGH_GAIN,
            high_cwnd_gain: K_DERIVED_HIGH_CWNDGAIN,
            congestion_window_gain: K_DERIVED_HIGH_CWNDGAIN,
            startup_rounds_without_growth: K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
            drain_to_target: DRAIN_TO_TARGET,
            enable_ack_aggregation_during_startup: true,
            expire_ack_aggregation_in_startup: true,
            detect_overshooting: false,
            bytes_lost_multiplier_while_detecting_overshooting: 2,
            enable_overestimate_avoidance: false,
            reduce_extra_acked_on_bandwidth_increase: false,
        }
    }
}

impl ControllerFactory for BbrConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr::new(self, current_mtu))
    }
}

#[derive(Debug, Copy, Clone)]
struct AckAggregationState {
    max_ack_height: AckHeightFilter,
    aggregation_epoch_start_time: Option<Instant>,
    aggregation_epoch_bytes: u64,
    bandwidth_threshold: f64,
    reduce_on_bandwidth_increase: bool,
}

impl AckAggregationState {
    fn new(bandwidth_threshold: f64, reduce_on_bandwidth_increase: bool) -> Self {
        Self {
            max_ack_height: AckHeightFilter::default(),
            aggregation_epoch_start_time: None,
            aggregation_epoch_bytes: 0,
            bandwidth_threshold,
            reduce_on_bandwidth_increase,
        }
    }

    fn update_ack_aggregation_bytes(
        &mut self,
        newly_acked_bytes: u64,
        now: Instant,
        round: u64,
        max_bandwidth: u64,
        bandwidth_increased: bool,
    ) -> u64 {
        if self.reduce_on_bandwidth_increase && bandwidth_increased {
            self.max_ack_height.recalculate(max_bandwidth);
        }

        // Compute how many bytes are expected to be delivered, assuming max
        // bandwidth is correct.
        let expected_bytes_acked = max_bandwidth
            * now
                .saturating_duration_since(self.aggregation_epoch_start_time.unwrap_or(now))
                .as_micros() as u64
            / 1_000_000;

        // Reset the current aggregation epoch as soon as the ack arrival rate is
        // less than or equal to the max bandwidth.
        if self.aggregation_epoch_bytes
            <= (expected_bytes_acked as f64 * self.bandwidth_threshold) as u64
        {
            // Reset to start measuring a new aggregation epoch.
            self.aggregation_epoch_bytes = newly_acked_bytes;
            self.aggregation_epoch_start_time = Some(now);
            return 0;
        }

        // Compute how many extra bytes were delivered vs max bandwidth.
        // Include the bytes most recently acknowledged to account for stretch acks.
        self.aggregation_epoch_bytes += newly_acked_bytes;
        let diff = self.aggregation_epoch_bytes - expected_bytes_acked;
        self.max_ack_height.update(AckHeightEvent {
            extra_acked: diff,
            bytes_acked: self.aggregation_epoch_bytes,
            time_delta: now
                .saturating_duration_since(self.aggregation_epoch_start_time.unwrap_or(now)),
            round,
        });
        diff
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct AckHeightEvent {
    extra_acked: u64,
    bytes_acked: u64,
    time_delta: Duration,
    round: u64,
}

#[derive(Debug, Copy, Clone)]
struct AckHeightFilter {
    window: u64,
    samples: [AckHeightEvent; 3],
}

impl AckHeightFilter {
    fn get(&self) -> u64 {
        self.samples[0].extra_acked
    }

    fn reset(&mut self, extra_acked: u64, round: u64) {
        self.samples.fill(AckHeightEvent {
            extra_acked,
            round,
            ..AckHeightEvent::default()
        });
    }

    fn update(&mut self, sample: AckHeightEvent) {
        if self.samples[0].extra_acked == 0
            || sample.extra_acked >= self.samples[0].extra_acked
            || sample.round - self.samples[2].round > self.window
        {
            self.samples.fill(sample);
            return;
        }

        if sample.extra_acked >= self.samples[1].extra_acked {
            self.samples[1] = sample;
            self.samples[2] = sample;
        } else if sample.extra_acked >= self.samples[2].extra_acked {
            self.samples[2] = sample;
        }
        self.update_subwindow(sample);
    }

    fn update_subwindow(&mut self, sample: AckHeightEvent) {
        let elapsed = sample.round - self.samples[0].round;
        if elapsed > self.window {
            self.samples[0] = self.samples[1];
            self.samples[1] = self.samples[2];
            self.samples[2] = sample;
            if sample.round - self.samples[0].round > self.window {
                self.samples[0] = self.samples[1];
                self.samples[1] = self.samples[2];
                self.samples[2] = sample;
            }
        } else if self.samples[1].round == self.samples[0].round && elapsed > self.window / 4 {
            self.samples[1] = sample;
            self.samples[2] = sample;
        } else if self.samples[2].round == self.samples[1].round && elapsed > self.window / 2 {
            self.samples[2] = sample;
        }
    }

    fn recalculate(&mut self, bandwidth: u64) {
        let samples = self.samples;
        self.samples.fill(AckHeightEvent::default());
        for mut sample in samples {
            let expected = bandwidth
                .saturating_mul(sample.time_delta.as_micros() as u64)
                / 1_000_000;
            if expected < sample.bytes_acked {
                sample.extra_acked = sample.bytes_acked - expected;
                self.update(sample);
            }
        }
    }
}

impl Default for AckHeightFilter {
    fn default() -> Self {
        Self {
            window: 10,
            samples: [AckHeightEvent::default(); 3],
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Mode {
    // Startup phase of the connection.
    Startup,
    // After achieving the highest possible bandwidth during the startup, lower
    // the pacing rate in order to drain the queue.
    Drain,
    // Cruising mode.
    ProbeBw,
    // Temporarily slow down sending in order to empty the buffer and measure
    // the real minimum RTT.
    ProbeRtt,
}

// Indicates how the congestion control limits the amount of bytes in flight.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RecoveryState {
    // Do not limit.
    NotInRecovery,
    // Allow an extra outstanding byte for each byte acknowledged.
    Conservation,
    // Allow two extra outstanding bytes for each byte acknowledged (slow
    // start).
    Growth,
}

impl RecoveryState {
    pub(super) fn in_recovery(&self) -> bool {
        !matches!(self, Self::NotInRecovery)
    }
}

#[derive(Debug, Clone, Default)]
struct LossState {
    lost_bytes: u64,
}

impl LossState {
    pub(super) fn reset(&mut self) {
        self.lost_bytes = 0;
    }

    pub(super) fn has_losses(&self) -> bool {
        self.lost_bytes != 0
    }
}

fn calculate_min_window(current_mtu: u64) -> u64 {
    4 * current_mtu
}

// The gain used for the STARTUP, equal to 2/ln(2).
const K_DEFAULT_HIGH_GAIN: f32 = 2.885;
// The newly derived CWND gain for STARTUP, 2.
const K_DERIVED_HIGH_CWNDGAIN: f32 = 2.0;
// The cycle of gains used during the ProbeBw stage.
const K_PACING_GAIN: [f32; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

const K_STARTUP_GROWTH_TARGET: f32 = 1.25;
const K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: u8 = 3;

// Do not allow initial congestion window to be greater than 200 packets.
const K_MAX_INITIAL_CONGESTION_WINDOW: u64 = 200;

const PROBE_RTT_BASED_ON_BDP: bool = true;
const DRAIN_TO_TARGET: bool = true;

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn configured_profile_controls_initialize_and_drive_bbr() {
        let mut config = BbrConfig::default();
        config
            .initial_window(38_400)
            .high_gain(3.0)
            .high_cwnd_gain(2.25)
            .congestion_window_gain(2.5)
            .startup_rounds_without_growth(4)
            .drain_to_target(false)
            .enable_ack_aggregation_during_startup(true)
            .expire_ack_aggregation_in_startup(true)
            .detect_overshooting(false)
            .bytes_lost_multiplier_while_detecting_overshooting(2)
            .enable_overestimate_avoidance(true)
            .reduce_extra_acked_on_bandwidth_increase(true);
        let mut bbr = Bbr::new(Arc::new(config), 1200);

        assert_eq!(bbr.init_cwnd, 38_400);
        assert_eq!(bbr.pacing_gain, 3.0);
        assert_eq!(bbr.cwnd_gain, 2.25);
        assert_eq!(bbr.drain_gain, 1.0 / 3.0);
        assert_eq!(bbr.config.startup_rounds_without_growth, 4);
        assert!(!bbr.config.drain_to_target);
        assert!(bbr.config.enable_ack_aggregation_during_startup);
        assert!(bbr.config.expire_ack_aggregation_in_startup);
        assert!(!bbr.detect_overshooting);
        assert_eq!(bbr.bytes_lost_multiplier_while_detecting_overshooting, 2);
        assert!(bbr.max_bandwidth.overestimate_avoidance_enabled());
        assert_eq!(bbr.ack_aggregation.bandwidth_threshold, 2.0);
        assert!(bbr.ack_aggregation.reduce_on_bandwidth_increase);

        bbr.enter_probe_bandwidth_mode(Instant::now());
        assert_eq!(bbr.cwnd_gain, 2.5);
    }

    #[test]
    fn startup_overshoot_reduces_pacing_rate_like_go_bbr() {
        let mut config = BbrConfig::default();
        config
            .initial_window(38_400)
            .high_gain(2.25)
            .detect_overshooting(true)
            .bytes_lost_multiplier_while_detecting_overshooting(1);
        let mut bbr = Bbr::new(Arc::new(config), 1200);
        let start = Instant::now();
        bbr.max_bandwidth.on_sent(start, 1, 1200, 0);
        bbr.max_bandwidth
            .on_sent(start + Duration::from_millis(10), 2, 1200, 1200);
        bbr.max_bandwidth
            .on_ack(start + Duration::from_millis(20), 1, 0);
        bbr.max_bandwidth
            .on_ack(start + Duration::from_millis(30), 2, 0);
        assert_eq!(bbr.max_bandwidth.get_estimate(), 80_000);

        bbr.min_rtt = Duration::from_millis(100);
        bbr.pacing_rate = 1_000_000;
        bbr.loss_state.lost_bytes = 40_000;
        bbr.calculate_pacing_rate();

        assert_eq!(bbr.pacing_rate, 384_000);
        assert!(!bbr.detect_overshooting);
        assert_eq!(bbr.bytes_lost_while_detecting_overshooting, 0);
    }

    #[test]
    fn startup_loss_exit_requires_eight_events_and_two_percent_of_inflight() {
        let mut bbr = Bbr::new(Arc::new(BbrConfig::default()), 1200);
        let now = Instant::now();

        for packet_number in 1..8 {
            bbr.on_congestion_event(
                now,
                now,
                false,
                250,
                1,
                Some(packet_number),
                Some(100_000),
            );
        }
        assert!(!bbr.should_exit_startup_due_to_loss());

        bbr.on_congestion_event(now, now, false, 250, 1, Some(8), Some(100_000));
        assert!(!bbr.should_exit_startup_due_to_loss());

        bbr.on_congestion_event(now, now, false, 1, 1, Some(9), Some(100_000));
        assert!(bbr.should_exit_startup_due_to_loss());
    }

    #[test]
    fn recovery_stays_disabled_until_startup_has_exited() {
        let mut bbr = Bbr::new(Arc::new(BbrConfig::default()), 1200);
        bbr.loss_state.lost_bytes = 1200;

        bbr.update_recovery_state(false);
        assert_eq!(bbr.recovery_state, RecoveryState::NotInRecovery);

        bbr.is_at_full_bandwidth = true;
        bbr.update_recovery_state(false);
        assert_eq!(bbr.recovery_state, RecoveryState::Conservation);
    }

    #[test]
    fn conservative_ack_threshold_starts_a_new_epoch_at_twice_bandwidth() {
        let start = Instant::now();
        let mut conservative = AckAggregationState::new(2.0, false);
        assert_eq!(
            conservative.update_ack_aggregation_bytes(1000, start, 1, 6000, false),
            0
        );
        assert_eq!(
            conservative.update_ack_aggregation_bytes(
                1000,
                start + Duration::from_millis(100),
                1,
                6000,
                false,
            ),
            0
        );

        let mut standard = AckAggregationState::new(1.0, false);
        standard.update_ack_aggregation_bytes(1000, start, 1, 6000, false);
        assert_eq!(
            standard.update_ack_aggregation_bytes(
                1000,
                start + Duration::from_millis(100),
                1,
                6000,
                false,
            ),
            1400
        );
    }

    #[test]
    fn bandwidth_growth_recalculates_retained_ack_height() {
        let mut filter = AckHeightFilter::default();
        filter.update(AckHeightEvent {
            extra_acked: 900,
            bytes_acked: 1000,
            time_delta: Duration::from_millis(100),
            round: 1,
        });

        filter.recalculate(8000);
        assert_eq!(filter.get(), 200);
    }
}
