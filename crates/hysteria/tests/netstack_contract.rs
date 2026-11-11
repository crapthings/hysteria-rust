//! Exercises the actual userspace stack with synthetic IP packets, without a TUN device.
#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{
    StackBuilder,
    smoltcp::{
        phy::ChecksumCapabilities,
        wire::{
            IpAddress, IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet, TcpControl, TcpPacket, TcpRepr,
            TcpSeqNumber, UdpPacket, UdpRepr,
        },
    },
};
use std::{net::SocketAddr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn builder() -> StackBuilder {
    StackBuilder::default()
        .stack_buffer_size(512)
        .tcp_buffer_size(64 * 1024)
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(1500)
}

fn ip_frame(src: SocketAddr, dst: SocketAddr, protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
    let ip = IpRepr::new(
        src.ip().into(),
        dst.ip().into(),
        protocol,
        payload.len(),
        64,
    );
    let mut frame = vec![0; ip.header_len() + payload.len()];
    ip.emit(&mut frame[..], &ChecksumCapabilities::default());
    frame[ip.header_len()..].copy_from_slice(payload);
    frame
}

fn transport(frame: &[u8]) -> (IpAddress, IpAddress, &[u8]) {
    if frame[0] >> 4 == 4 {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        assert!(ip.verify_checksum());
        (
            ip.src_addr().into(),
            ip.dst_addr().into(),
            &frame[usize::from(ip.header_len())..],
        )
    } else {
        let ip = Ipv6Packet::new_checked(frame).unwrap();
        (ip.src_addr().into(), ip.dst_addr().into(), &frame[40..])
    }
}

fn udp_frame(src: SocketAddr, dst: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut payload = vec![0; 8 + data.len()];
    UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut payload[..]),
        &src.ip().into(),
        &dst.ip().into(),
        data.len(),
        |buffer| buffer.copy_from_slice(data),
        &ChecksumCapabilities::default(),
    );
    ip_frame(src, dst, IpProtocol::Udp, &payload)
}

fn tcp_frame(
    src: SocketAddr,
    dst: SocketAddr,
    control: TcpControl,
    seq: i32,
    ack: Option<TcpSeqNumber>,
    data: &[u8],
) -> Vec<u8> {
    let repr = TcpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
        control,
        seq_number: TcpSeqNumber(seq),
        ack_number: ack,
        window_len: 65535,
        window_scale: None,
        max_seg_size: Some(1200),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: data,
    };
    let mut payload = vec![0; repr.buffer_len()];
    repr.emit(
        &mut TcpPacket::new_unchecked(&mut payload[..]),
        &src.ip().into(),
        &dst.ip().into(),
        &ChecksumCapabilities::default(),
    );
    ip_frame(src, dst, IpProtocol::Tcp, &payload)
}

/// Verifies UDP payload/address handling and valid emitted checksums for both IP families.
#[tokio::test]
async fn userspace_stack_udp_ipv4_ipv6_roundtrip() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (mut stack, runner, udp, _tcp) = builder().build().unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(runner.unwrap());
        let (mut receive, mut send) = udp.unwrap().split();
        for (source, destination) in [
            ("192.0.2.2:12345", "198.51.100.4:443"),
            ("[2001:db8::2]:12345", "[2001:db8::4]:443"),
        ] {
            let source: SocketAddr = source.parse().unwrap();
            let destination: SocketAddr = destination.parse().unwrap();
            stack
                .send(udp_frame(source, destination, b"request"))
                .await
                .unwrap();
            let (data, from, to) = receive.next().await.unwrap();
            assert_eq!(
                (data.as_slice(), from, to),
                (b"request".as_slice(), source, destination)
            );
            send.send((b"response".to_vec(), destination, source))
                .await
                .unwrap();
            let frame = stack.next().await.unwrap().unwrap();
            let (from, to, payload) = transport(&frame);
            let udp = UdpPacket::new_checked(payload).unwrap();
            assert!(udp.verify_checksum(&from, &to));
            assert_eq!((from, to), (destination.ip().into(), source.ip().into()));
            assert_eq!(
                (udp.src_port(), udp.dst_port()),
                (destination.port(), source.port())
            );
            assert_eq!(udp.payload(), b"response");
        }
    })
    .await
    .expect("in-memory UDP stack exceeded deadline");
}

/// Completes synthetic TCP handshakes and exchanges stream data without OS sockets.
#[tokio::test]
async fn userspace_stack_tcp_ipv4_ipv6_handshake_and_data() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for (source, destination) in [
            ("192.0.2.2:12345", "198.51.100.4:443"),
            ("[2001:db8::2]:12345", "[2001:db8::4]:443"),
        ] {
            let (mut stack, runner, _udp, tcp) = builder().build().unwrap();
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(runner.unwrap());
            let mut listener = tcp.unwrap();
            let source: SocketAddr = source.parse().unwrap();
            let destination: SocketAddr = destination.parse().unwrap();
            stack
                .send(tcp_frame(
                    source,
                    destination,
                    TcpControl::Syn,
                    100,
                    None,
                    b"",
                ))
                .await
                .unwrap();
            let syn_ack = stack.next().await.unwrap().unwrap();
            let (from, to, payload) = transport(&syn_ack);
            let packet = TcpPacket::new_checked(payload).unwrap();
            assert!(packet.syn() && packet.ack() && packet.verify_checksum(&from, &to));
            assert_eq!(packet.ack_number(), TcpSeqNumber(101));
            let ack = packet.seq_number() + 1;
            stack
                .send(tcp_frame(
                    source,
                    destination,
                    TcpControl::None,
                    101,
                    Some(ack),
                    b"hello",
                ))
                .await
                .unwrap();
            let (mut stream, from, to) = listener.next().await.unwrap();
            assert_eq!((from, to), (source, destination));
            let mut data = [0; 5];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"hello");
            stream.write_all(b"world").await.unwrap();
            loop {
                let frame = stack.next().await.unwrap().unwrap();
                let (from, to, payload) = transport(&frame);
                let packet = TcpPacket::new_checked(payload).unwrap();
                assert!(packet.verify_checksum(&from, &to));
                if packet.payload().is_empty() {
                    continue;
                }
                assert_eq!(packet.payload(), b"world");
                stack
                    .send(tcp_frame(
                        source,
                        destination,
                        TcpControl::Rst,
                        106,
                        Some(ack + 5),
                        b"",
                    ))
                    .await
                    .unwrap();
                break;
            }
        }
    })
    .await
    .expect("in-memory TCP stack exceeded deadline");
}
