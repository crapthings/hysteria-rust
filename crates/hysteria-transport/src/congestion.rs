use crate::TransportError;
use portable_atomic::AtomicU64;
use quinn::{
    Connection,
    congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics, NewRenoConfig},
};
use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const SAMPLE_SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE_NUMERATOR: u64 = 4;
const MIN_ACK_RATE_DENOMINATOR: u64 = 5;
const CONGESTION_WINDOW_MULTIPLIER: u128 = 2;
const INITIAL_WINDOW: u64 = 10_240;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrProfile {
    Conservative,
    Standard,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    Bbr(BbrProfile),
    Reno,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionSettings {
    pub algorithm: CongestionAlgorithm,
    pub disable_loss_compensation: bool,
}

impl Default for CongestionSettings {
    fn default() -> Self {
        Self {
            algorithm: CongestionAlgorithm::Bbr(BbrProfile::Standard),
            disable_loss_compensation: false,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AdaptiveCongestionConfig {
    settings: CongestionSettings,
}

impl AdaptiveCongestionConfig {
    pub(crate) fn new(settings: CongestionSettings) -> Self {
        Self { settings }
    }
}

impl ControllerFactory for AdaptiveCongestionConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let fallback: Box<dyn Controller> = match self.settings.algorithm {
            CongestionAlgorithm::Bbr(profile) => {
                let mut config = BbrConfig::default();
                config.initial_window(u64::from(current_mtu) * 32);
                match profile {
                    BbrProfile::Conservative => {
                        config
                            .high_gain(2.25)
                            .high_cwnd_gain(1.75)
                            .congestion_window_gain(1.75)
                            .startup_rounds_without_growth(2)
                            .drain_to_target(true)
                            .enable_ack_aggregation_during_startup(false)
                            .expire_ack_aggregation_in_startup(false)
                            .detect_overshooting(true)
                            .bytes_lost_multiplier_while_detecting_overshooting(1)
                            .enable_overestimate_avoidance(true)
                            .reduce_extra_acked_on_bandwidth_increase(true);
                    }
                    BbrProfile::Standard => {
                        config
                            .high_gain(2.885)
                            .high_cwnd_gain(2.0)
                            .congestion_window_gain(2.0)
                            .startup_rounds_without_growth(3)
                            .drain_to_target(false)
                            .enable_ack_aggregation_during_startup(false)
                            .expire_ack_aggregation_in_startup(false)
                            .detect_overshooting(false)
                            .bytes_lost_multiplier_while_detecting_overshooting(2)
                            .enable_overestimate_avoidance(false)
                            .reduce_extra_acked_on_bandwidth_increase(false);
                    }
                    BbrProfile::Aggressive => {
                        config
                            .high_gain(3.0)
                            .high_cwnd_gain(2.25)
                            .congestion_window_gain(2.5)
                            .startup_rounds_without_growth(4)
                            .drain_to_target(false)
                            .enable_ack_aggregation_during_startup(true)
                            .expire_ack_aggregation_in_startup(true)
                            .detect_overshooting(false)
                            .bytes_lost_multiplier_while_detecting_overshooting(2)
                            .enable_overestimate_avoidance(false)
                            .reduce_extra_acked_on_bandwidth_increase(false);
                    }
                }
                Arc::new(config).build(now, current_mtu)
            }
            CongestionAlgorithm::Reno => Arc::new(NewRenoConfig::default()).build(now, current_mtu),
        };
        let control = Arc::new(BrutalControl {
            enabled: AtomicBool::new(false),
            bandwidth: AtomicU64::new(0),
            disable_loss_compensation: self.settings.disable_loss_compensation,
        });
        Box::new(AdaptiveCongestion {
            brutal: Brutal::new(Arc::clone(&control), now, current_mtu),
            fallback,
            control,
        })
    }
}

/// Switches an adaptive connection from its configured BBR/Reno fallback to Brutal.
///
/// # Errors
///
/// Returns an error for zero bandwidth or a connection not created by Hysteria's adaptive factory.
pub fn set_brutal_bandwidth(
    connection: &Connection,
    bytes_per_second: u64,
) -> Result<(), TransportError> {
    if bytes_per_second == 0 {
        return Err(TransportError::Configuration(
            "Brutal bandwidth must be greater than zero".to_owned(),
        ));
    }
    let controller = connection
        .congestion_state()
        .into_any()
        .downcast::<AdaptiveCongestion>()
        .map_err(|_| {
            TransportError::Configuration(
                "connection does not use Hysteria adaptive congestion control".to_owned(),
            )
        })?;
    controller
        .control
        .bandwidth
        .store(bytes_per_second, Ordering::Release);
    controller.control.enabled.store(true, Ordering::Release);
    Ok(())
}

#[cfg(test)]
pub(crate) fn brutal_bandwidth(connection: &Connection) -> Option<u64> {
    let controller = connection
        .congestion_state()
        .into_any()
        .downcast::<AdaptiveCongestion>()
        .ok()?;
    controller
        .control
        .enabled
        .load(Ordering::Acquire)
        .then(|| controller.control.bandwidth.load(Ordering::Acquire))
}

struct BrutalControl {
    enabled: AtomicBool,
    bandwidth: AtomicU64,
    disable_loss_compensation: bool,
}

impl std::fmt::Debug for BrutalControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrutalControl")
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .field("bandwidth", &self.bandwidth.load(Ordering::Relaxed))
            .field("disable_loss_compensation", &self.disable_loss_compensation)
            .finish()
    }
}

struct AdaptiveCongestion {
    control: Arc<BrutalControl>,
    brutal: Brutal,
    fallback: Box<dyn Controller>,
}

impl std::fmt::Debug for AdaptiveCongestion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdaptiveCongestion")
            .field("control", &self.control)
            .field("brutal", &self.brutal)
            .finish_non_exhaustive()
    }
}

impl AdaptiveCongestion {
    fn brutal_enabled(&self) -> bool {
        self.control.enabled.load(Ordering::Acquire)
    }
}

impl Controller for AdaptiveCongestion {
    fn on_sent(&mut self, now: Instant, bytes: u64, packet_number: u64, bytes_in_flight: u64) {
        if self.brutal_enabled() {
            self.brutal
                .on_sent(now, bytes, packet_number, bytes_in_flight);
        } else {
            self.fallback
                .on_sent(now, bytes, packet_number, bytes_in_flight);
        }
    }

    fn on_begin_congestion_event(&mut self, prior_bytes_in_flight: u64) {
        if self.brutal_enabled() {
            self.brutal.on_begin_congestion_event(prior_bytes_in_flight);
        } else {
            self.fallback
                .on_begin_congestion_event(prior_bytes_in_flight);
        }
    }

    fn on_packet_lost(&mut self, packet_number: u64, bytes: u64) {
        self.brutal.on_packet_lost(packet_number, bytes);
        self.fallback.on_packet_lost(packet_number, bytes);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        packet_number: u64,
        bytes: u64,
        bytes_in_flight_at_send: u64,
        app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        if self.brutal_enabled() {
            self.brutal.on_ack(
                now,
                sent,
                packet_number,
                bytes,
                bytes_in_flight_at_send,
                app_limited,
                rtt,
            );
        } else {
            self.fallback.on_ack(
                now,
                sent,
                packet_number,
                bytes,
                bytes_in_flight_at_send,
                app_limited,
                rtt,
            );
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        if self.brutal_enabled() {
            self.brutal
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        } else {
            self.fallback
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        persistent: bool,
        lost_bytes: u64,
        lost_packets: u64,
        last_packet_number: Option<u64>,
        last_packet_bytes_in_flight_at_send: Option<u64>,
    ) {
        if self.brutal_enabled() {
            self.brutal.on_congestion_event(
                now,
                sent,
                persistent,
                lost_bytes,
                lost_packets,
                last_packet_number,
                last_packet_bytes_in_flight_at_send,
            );
        } else {
            self.fallback.on_congestion_event(
                now,
                sent,
                persistent,
                lost_bytes,
                lost_packets,
                last_packet_number,
                last_packet_bytes_in_flight_at_send,
            );
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.brutal.on_mtu_update(new_mtu);
        self.fallback.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        if self.brutal_enabled() {
            self.brutal.window()
        } else {
            self.fallback.window()
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        if self.brutal_enabled() {
            self.brutal.metrics()
        } else {
            self.fallback.metrics()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            control: Arc::clone(&self.control),
            brutal: self.brutal.clone(),
            fallback: self.fallback.clone_box(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.fallback.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PacketInfo {
    timestamp: Option<u64>,
    ack_count: u64,
    loss_count: u64,
}

#[derive(Debug, Clone)]
struct Brutal {
    control: Arc<BrutalControl>,
    origin: Instant,
    mtu: u64,
    smoothed_rtt: Duration,
    slots: [PacketInfo; SAMPLE_SLOT_COUNT],
    ack_rate_numerator: u64,
    ack_rate_denominator: u64,
}

impl Brutal {
    fn new(control: Arc<BrutalControl>, origin: Instant, mtu: u16) -> Self {
        Self {
            control,
            origin,
            mtu: u64::from(mtu),
            smoothed_rtt: Duration::ZERO,
            slots: [PacketInfo::default(); SAMPLE_SLOT_COUNT],
            ack_rate_numerator: 1,
            ack_rate_denominator: 1,
        }
    }

    fn record(&mut self, now: Instant, acknowledgements: u64, losses: u64) {
        let timestamp = now.saturating_duration_since(self.origin).as_secs();
        let slot = usize::try_from(timestamp % SAMPLE_SLOT_COUNT as u64)
            .expect("slot index always fits usize");
        let info = &mut self.slots[slot];
        if info.timestamp == Some(timestamp) {
            info.ack_count = info.ack_count.saturating_add(acknowledgements);
            info.loss_count = info.loss_count.saturating_add(losses);
        } else {
            *info = PacketInfo {
                timestamp: Some(timestamp),
                ack_count: acknowledgements,
                loss_count: losses,
            };
        }
        self.update_ack_rate(timestamp);
    }

    fn update_ack_rate(&mut self, timestamp: u64) {
        if self.control.disable_loss_compensation {
            self.ack_rate_numerator = 1;
            self.ack_rate_denominator = 1;
            return;
        }
        let minimum_timestamp = timestamp.saturating_sub(SAMPLE_SLOT_COUNT as u64);
        let (acknowledgements, losses) = self
            .slots
            .iter()
            .filter(|slot| {
                slot.timestamp
                    .is_some_and(|value| value >= minimum_timestamp)
            })
            .fold((0_u64, 0_u64), |(ack, loss), slot| {
                (
                    ack.saturating_add(slot.ack_count),
                    loss.saturating_add(slot.loss_count),
                )
            });
        let samples = acknowledgements.saturating_add(losses);
        if samples < MIN_SAMPLE_COUNT {
            self.ack_rate_numerator = 1;
            self.ack_rate_denominator = 1;
            return;
        }
        if acknowledgements.saturating_mul(MIN_ACK_RATE_DENOMINATOR)
            < samples.saturating_mul(MIN_ACK_RATE_NUMERATOR)
        {
            self.ack_rate_numerator = MIN_ACK_RATE_NUMERATOR;
            self.ack_rate_denominator = MIN_ACK_RATE_DENOMINATOR;
        } else {
            self.ack_rate_numerator = acknowledgements;
            self.ack_rate_denominator = samples;
        }
    }

    fn target_window(&self) -> u64 {
        if self.smoothed_rtt.is_zero() {
            return INITIAL_WINDOW;
        }
        let numerator = u128::from(self.control.bandwidth.load(Ordering::Acquire))
            .saturating_mul(self.smoothed_rtt.as_nanos())
            .saturating_mul(CONGESTION_WINDOW_MULTIPLIER)
            .saturating_mul(u128::from(self.ack_rate_denominator));
        let denominator =
            1_000_000_000_u128.saturating_mul(u128::from(self.ack_rate_numerator.max(1)));
        u64::try_from(numerator / denominator)
            .unwrap_or(u64::MAX)
            .max(self.mtu)
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _packet_number: u64,
        _bytes: u64,
        _bytes_in_flight_at_send: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.smoothed_rtt = rtt.get();
        self.record(now, 1, 0);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _persistent: bool,
        _lost_bytes: u64,
        lost_packets: u64,
        _last_packet_number: Option<u64>,
        _last_packet_bytes_in_flight_at_send: Option<u64>,
    ) {
        if lost_packets > 0 {
            self.record(now, 0, lost_packets);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu);
    }

    fn window(&self) -> u64 {
        self.target_window()
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        let pacing_bytes_per_second = u128::from(self.control.bandwidth.load(Ordering::Acquire))
            .saturating_mul(u128::from(self.ack_rate_denominator))
            / u128::from(self.ack_rate_numerator.max(1));
        metrics.pacing_rate = Some(
            u64::try_from(pacing_bytes_per_second)
                .unwrap_or(u64::MAX)
                .saturating_mul(8),
        );
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brutal_loss_compensation_matches_go_samples() {
        for (acknowledgements, losses, expected) in [
            (100, 0, (100, 100)),
            (80, 20, (80, 100)),
            (50, 50, (4, 5)),
            (10, 5, (1, 1)),
        ] {
            let origin = Instant::now();
            let control = Arc::new(BrutalControl {
                enabled: AtomicBool::new(true),
                bandwidth: AtomicU64::new(1_000_000),
                disable_loss_compensation: false,
            });
            let mut brutal = Brutal::new(control, origin, 1200);
            brutal.record(origin + Duration::from_secs(5), acknowledgements, losses);
            assert_eq!(
                (brutal.ack_rate_numerator, brutal.ack_rate_denominator),
                expected
            );
        }
    }

    #[test]
    fn brutal_window_tracks_rtt_bandwidth_and_loss() {
        let origin = Instant::now();
        let control = Arc::new(BrutalControl {
            enabled: AtomicBool::new(true),
            bandwidth: AtomicU64::new(1_000_000),
            disable_loss_compensation: false,
        });
        let mut brutal = Brutal::new(control, origin, 1200);
        assert_eq!(brutal.window(), INITIAL_WINDOW);
        brutal.smoothed_rtt = Duration::from_millis(100);
        assert_eq!(brutal.window(), 200_000);
        brutal.record(origin + Duration::from_secs(1), 80, 20);
        assert_eq!(brutal.window(), 250_000);
        assert_eq!(brutal.metrics().pacing_rate, Some(10_000_000));
    }

    #[test]
    fn brutal_counts_lost_packets_and_uses_one_datagram_minimum() {
        let origin = Instant::now();
        let control = Arc::new(BrutalControl {
            enabled: AtomicBool::new(true),
            bandwidth: AtomicU64::new(1),
            disable_loss_compensation: false,
        });
        let mut brutal = Brutal::new(control, origin, 1200);
        brutal.smoothed_rtt = Duration::from_nanos(1);
        assert_eq!(brutal.window(), 1200);
        brutal.on_congestion_event(
            origin + Duration::from_secs(1),
            origin,
            false,
            2401,
            3,
            Some(3),
            Some(3600),
        );
        assert_eq!(brutal.slots[1].loss_count, 3);
    }

    #[test]
    fn disabling_compensation_pins_ack_rate() {
        let origin = Instant::now();
        let control = Arc::new(BrutalControl {
            enabled: AtomicBool::new(true),
            bandwidth: AtomicU64::new(1_000_000),
            disable_loss_compensation: true,
        });
        let mut brutal = Brutal::new(control, origin, 1200);
        brutal.record(origin + Duration::from_secs(1), 1, 99);
        assert_eq!(
            (brutal.ack_rate_numerator, brutal.ack_rate_denominator),
            (1, 1)
        );
    }
}
