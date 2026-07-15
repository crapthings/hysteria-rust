use std::collections::{BTreeMap, VecDeque};
use std::fmt::{Debug, Display, Formatter};

use super::min_max::MinMax;
use crate::{Duration, Instant};

const A0_CANDIDATE_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AckPoint {
    time: Instant,
    total_acked: u64,
}

#[derive(Clone, Copy, Debug)]
struct SentPacketState {
    sent_time: Instant,
    size: u64,
    total_sent: u64,
    total_acked: u64,
    total_sent_at_last_ack: u64,
    last_acked_packet_sent_time: Option<Instant>,
    last_acked_packet_ack_time: Option<Instant>,
    app_limited: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    total_sent: u64,
    total_sent_at_last_ack: u64,
    last_acked_packet_sent_time: Option<Instant>,
    last_acked_packet_ack_time: Option<Instant>,
    sent_packets: BTreeMap<u64, SentPacketState>,
    is_app_limited: bool,
    end_of_app_limited_phase: Option<u64>,
    has_non_app_limited_sample: bool,
    window_max_sample: u64,
    window_max_sample_app_limited: Option<bool>,
    max_filter: MinMax,
    acked_at_last_window: u64,
    estimate_at_last_window: u64,
    overestimate_avoidance: bool,
    recent_ack_points: [Option<AckPoint>; 2],
    a0_candidates: VecDeque<AckPoint>,
}

impl BandwidthEstimation {
    pub(crate) fn enable_overestimate_avoidance(&mut self) {
        self.overestimate_avoidance = true;
    }

    #[cfg(test)]
    pub(crate) fn overestimate_avoidance_enabled(&self) -> bool {
        self.overestimate_avoidance
    }

    pub(crate) fn on_sent(
        &mut self,
        now: Instant,
        packet_number: u64,
        bytes: u64,
        bytes_in_flight_before: u64,
    ) {
        if bytes == 0 {
            return;
        }
        self.total_sent += bytes;

        if bytes_in_flight_before == 0 {
            self.last_acked_packet_ack_time = Some(now);
            self.total_sent_at_last_ack = self.total_sent;
            self.last_acked_packet_sent_time = Some(now);
            if self.overestimate_avoidance {
                self.recent_ack_points = [None; 2];
                self.update_recent_ack_point(now);
                self.a0_candidates.clear();
                self.push_a0_candidate(self.recent_ack_points[1].unwrap());
            }
        }

        self.sent_packets.insert(
            packet_number,
            SentPacketState {
                sent_time: now,
                size: bytes,
                total_sent: self.total_sent,
                total_acked: self.total_acked,
                total_sent_at_last_ack: self.total_sent_at_last_ack,
                last_acked_packet_sent_time: self.last_acked_packet_sent_time,
                last_acked_packet_ack_time: self.last_acked_packet_ack_time,
                app_limited: self.is_app_limited,
            },
        );
    }

    pub(crate) fn on_ack(
        &mut self,
        now: Instant,
        packet_number: u64,
        round: u64,
    ) -> Option<bool> {
        let sent = self.sent_packets.remove(&packet_number)?;
        self.total_acked += sent.size;
        self.total_sent_at_last_ack = sent.total_sent;
        self.last_acked_packet_sent_time = Some(sent.sent_time);
        self.last_acked_packet_ack_time = Some(now);
        if self.overestimate_avoidance {
            self.update_recent_ack_point(now);
        }

        if self.is_app_limited
            && self
                .end_of_app_limited_phase
                .is_none_or(|end| packet_number > end)
        {
            self.is_app_limited = false;
        }

        let last_acked_sent = sent.last_acked_packet_sent_time?;
        let send_rate = if sent.sent_time > last_acked_sent {
            Self::bw_from_delta(
                sent.total_sent - sent.total_sent_at_last_ack,
                sent.sent_time - last_acked_sent,
            )
            .unwrap_or(0)
        } else {
            u64::MAX
        };

        let a0 = self
            .overestimate_avoidance
            .then(|| self.choose_a0_point(sent.total_acked))
            .flatten();
        let ack_rate = if let Some(a0) = a0 {
            if now <= a0.time || self.total_acked < a0.total_acked {
                0
            } else {
                Self::bw_from_delta(self.total_acked - a0.total_acked, now - a0.time)
                    .unwrap_or(0)
            }
        } else if let Some(last_acked_time) = sent.last_acked_packet_ack_time {
            if now <= last_acked_time {
                return None;
            }
            Self::bw_from_delta(self.total_acked - sent.total_acked, now - last_acked_time)
                .unwrap_or(0)
        } else {
            return None;
        };

        let bandwidth = send_rate.min(ack_rate);
        if !sent.app_limited || self.max_filter.get() < bandwidth {
            self.max_filter.update_max(round, bandwidth);
        }
        if bandwidth > self.window_max_sample {
            self.window_max_sample = bandwidth;
            self.window_max_sample_app_limited = Some(sent.app_limited);
        }
        self.has_non_app_limited_sample |= !sent.app_limited;
        Some(sent.app_limited)
    }

    pub(crate) fn on_packet_lost(&mut self, packet_number: u64) {
        self.sent_packets.remove(&packet_number);
    }

    pub(crate) fn on_app_limited(&mut self, end_packet_number: u64) {
        self.is_app_limited = true;
        self.end_of_app_limited_phase = Some(end_packet_number);
    }

    pub(crate) fn window_sample_app_limited(&self) -> Option<bool> {
        self.window_max_sample_app_limited
    }

    pub(crate) fn has_non_app_limited_sample(&self) -> bool {
        self.has_non_app_limited_sample
    }

    pub(crate) fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub(crate) fn estimate_increased_this_window(&self) -> bool {
        self.get_estimate() > self.estimate_at_last_window
    }

    pub(crate) fn end_acks(
        &mut self,
        _current_round: u64,
        _app_limited: bool,
        new_aggregation_epoch: bool,
    ) {
        self.acked_at_last_window = self.total_acked;
        self.estimate_at_last_window = self.get_estimate();
        self.window_max_sample = 0;
        self.window_max_sample_app_limited = None;
        if self.overestimate_avoidance && new_aggregation_epoch {
            if let Some(point) = self.recent_ack_points[0].or(self.recent_ack_points[1]) {
                self.push_a0_candidate(point);
            }
        }
    }

    pub(crate) fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub(crate) const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_ns = delta.as_nanos();
        if window_duration_ns == 0 {
            return None;
        }
        let b_ns = bytes * 1_000_000_000;
        let bytes_per_second = b_ns / (window_duration_ns as u64);
        Some(bytes_per_second)
    }

    fn update_recent_ack_point(&mut self, time: Instant) {
        let point = AckPoint {
            time,
            total_acked: self.total_acked,
        };
        match self.recent_ack_points[1] {
            None => self.recent_ack_points[1] = Some(point),
            Some(recent) if time < recent.time => {
                self.recent_ack_points[1] = Some(AckPoint { time, ..recent });
            }
            Some(recent) if time > recent.time => {
                self.recent_ack_points = [Some(recent), Some(point)];
            }
            Some(_) => self.recent_ack_points[1] = Some(point),
        }
    }

    fn push_a0_candidate(&mut self, point: AckPoint) {
        if self.a0_candidates.len() == A0_CANDIDATE_CAPACITY {
            self.a0_candidates.pop_front();
        }
        self.a0_candidates.push_back(point);
    }

    fn choose_a0_point(&mut self, total_bytes_acked_at_send: u64) -> Option<AckPoint> {
        if self.a0_candidates.len() <= 1 {
            return self.a0_candidates.front().copied();
        }

        let selected = self
            .a0_candidates
            .iter()
            .position(|point| point.total_acked > total_bytes_acked_at_send)
            .map_or(self.a0_candidates.len() - 1, |index| index.saturating_sub(1));
        let point = self.a0_candidates[selected];
        for _ in 0..selected {
            self.a0_candidates.pop_front();
        }
        Some(point)
    }
}

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a0_selection_uses_bytes_acked_when_packet_was_sent_and_prunes_history() {
        let now = Instant::now();
        let mut estimation = BandwidthEstimation::default();
        estimation.a0_candidates = VecDeque::from([
            AckPoint {
                time: now,
                total_acked: 0,
            },
            AckPoint {
                time: now + Duration::from_millis(1),
                total_acked: 100,
            },
            AckPoint {
                time: now + Duration::from_millis(2),
                total_acked: 200,
            },
        ]);

        assert_eq!(
            estimation.choose_a0_point(150).unwrap().total_acked,
            100
        );
        assert_eq!(estimation.a0_candidates.len(), 2);
    }

    #[test]
    fn overestimate_avoidance_anchors_ack_rate_to_a0() {
        let start = Instant::now();
        let mut estimation = BandwidthEstimation::default();
        estimation.enable_overestimate_avoidance();
        estimation.on_sent(start, 1, 1000, 0);
        estimation.on_sent(start + Duration::from_millis(10), 2, 1000, 1000);
        estimation.on_ack(start + Duration::from_millis(100), 1, 0);

        assert_eq!(estimation.get_estimate(), 10_000);
    }

    #[test]
    fn packet_samples_use_send_state_captured_for_that_packet() {
        let start = Instant::now();
        let mut estimation = BandwidthEstimation::default();
        estimation.on_sent(start, 1, 1000, 0);
        estimation.on_sent(start + Duration::from_millis(10), 2, 1000, 1000);

        estimation.on_ack(start + Duration::from_millis(20), 1, 0);
        estimation.on_ack(start + Duration::from_millis(30), 2, 0);

        // Packet 2 was sent 10 ms after the opening packet (100 KB/s send rate), while 2 KB
        // were acknowledged over 30 ms (66.666 KB/s ACK rate). BBR uses the lower rate.
        assert_eq!(estimation.get_estimate(), 66_666);
    }

    #[test]
    fn app_limited_state_exits_only_after_acknowledging_beyond_the_marker() {
        let start = Instant::now();
        let mut estimation = BandwidthEstimation::default();
        estimation.on_sent(start, 1, 1000, 0);
        estimation.on_app_limited(1);
        estimation.on_sent(start + Duration::from_millis(10), 2, 1000, 1000);

        assert_eq!(
            estimation.on_ack(start + Duration::from_millis(20), 1, 0),
            Some(false)
        );
        assert!(estimation.is_app_limited);
        assert_eq!(
            estimation.on_ack(start + Duration::from_millis(30), 2, 0),
            Some(true)
        );
        assert!(!estimation.is_app_limited);
        assert_eq!(estimation.get_estimate(), 66_666);
        assert_eq!(estimation.window_sample_app_limited(), Some(true));

        estimation.on_sent(start + Duration::from_millis(40), 3, 1000, 0);
        assert_eq!(
            estimation.on_ack(start + Duration::from_millis(50), 3, 0),
            Some(false)
        );
        assert!(estimation.has_non_app_limited_sample());
    }

    #[test]
    fn lost_packets_are_removed_from_sampler_state() {
        let start = Instant::now();
        let mut estimation = BandwidthEstimation::default();
        estimation.on_sent(start, 7, 1200, 0);
        assert!(estimation.sent_packets.contains_key(&7));

        estimation.on_packet_lost(7);
        assert!(!estimation.sent_packets.contains_key(&7));
    }
}
