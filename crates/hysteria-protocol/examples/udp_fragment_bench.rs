//! Isolated UDP fragmentation timing, identical source for baseline and candidate.
use hysteria_protocol::{Defragger, UdpMessage, fragment_udp_message};
use std::{hint::black_box, time::Instant};

fn main() {
    println!("[");
    for (case, size) in [1200, 3000, 4000].into_iter().enumerate() {
        let message = UdpMessage {
            session_id: 1,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 1,
            address: "127.0.0.1:443".to_owned(),
            data: vec![42; size],
        };
        for _ in 0..1000 {
            black_box(fragment_udp_message(black_box(&message), 1100).unwrap());
        }
        let samples: Vec<_> = (0..7)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..100_000 {
                    black_box(fragment_udp_message(black_box(&message), 1100).unwrap());
                }
                start.elapsed().as_nanos() / 100_000
            })
            .collect();
        let fragments = fragment_udp_message(&message, 1100).unwrap();
        let reassembly: Vec<_> = (0..7)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..100_000 {
                    let mut defragger = Defragger::default();
                    for fragment in &fragments {
                        black_box(defragger.feed(black_box(fragment.clone())));
                    }
                }
                start.elapsed().as_nanos() / 100_000
            })
            .collect();
        if case > 0 {
            println!(",");
        }
        print!(
            "{{\"payload_bytes\":{size},\"ns_per_fragmentation_samples\":{samples:?},\"ns_per_reassembly_samples\":{reassembly:?}}}"
        );
    }
    println!("\n]");
}
