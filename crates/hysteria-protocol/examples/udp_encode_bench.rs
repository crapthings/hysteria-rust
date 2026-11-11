//! Compares the old owned-payload send pipeline with direct borrowed encoding.
//! Run with `cargo run --release -p hysteria-protocol --example udp_encode_bench`.
//! Codec-only timing: no QUIC, network, allocator instrumentation or throughput claim.
use hysteria_protocol::{UdpMessage, fragment_udp_message};
use std::{hint::black_box, time::Instant};

const MTU: usize = 1200;
const ITERATIONS: u32 = 10_000;

fn owned(data: &[u8]) {
    let message = UdpMessage {
        session_id: 1,
        packet_id: 1,
        fragment_id: 0,
        fragment_count: 1,
        address: "127.0.0.1:443".into(),
        data: data.to_vec(),
    };
    if message.encoded_size() <= MTU {
        black_box(message.encode().unwrap());
    } else {
        for fragment in fragment_udp_message(&message, MTU).unwrap() {
            black_box(fragment.encode().unwrap());
        }
    }
}

fn borrowed(data: &[u8]) {
    let mut message = UdpMessage {
        session_id: 1,
        packet_id: 1,
        fragment_id: 0,
        fragment_count: 1,
        address: "127.0.0.1:443".into(),
        data: Vec::new(),
    };
    if message.header_size() + data.len() <= MTU {
        black_box(message.encode_with_payload(data).unwrap());
    } else {
        let capacity = MTU - message.header_size();
        message.fragment_count = u8::try_from(data.len().div_ceil(capacity)).unwrap();
        for (index, payload) in data.chunks(capacity).enumerate() {
            message.fragment_id = u8::try_from(index).unwrap();
            black_box(message.encode_with_payload(payload).unwrap());
        }
    }
}

fn measure(operation: fn(&[u8]), data: &[u8]) -> u128 {
    let started = Instant::now();
    for _ in 0..ITERATIONS {
        operation(black_box(data));
    }
    started.elapsed().as_nanos() / u128::from(ITERATIONS)
}

fn main() {
    println!("[");
    for (case, size) in [64, 1000, 1200, 3000, 4000].into_iter().enumerate() {
        let data = vec![42; size];
        for _ in 0..1000 {
            owned(&data);
            borrowed(&data);
        }
        let mut before = Vec::new();
        let mut after = Vec::new();
        for round in 0..7 {
            if round % 2 == 0 {
                before.push(measure(owned, &data));
                after.push(measure(borrowed, &data));
            } else {
                after.push(measure(borrowed, &data));
                before.push(measure(owned, &data));
            }
        }
        if case > 0 {
            println!(",");
        }
        print!(
            "{{\"payload_bytes\":{size},\"owned_ns_samples\":{before:?},\"borrowed_ns_samples\":{after:?}}}"
        );
    }
    println!("\n]");
}
