//! Chrome-shaped client transport parameter encoding.
//!
//! Reference: apernet/quic-go 184d081eef3e, internal/wire/transport_parameters_chrome.go.
//! This is an encoder, not a complete Chrome TLS or packet fingerprint profile.

use super::*;

impl TransportParameters {
    /// Encode client parameters with the upstream Chrome parameter layout.
    ///
    /// Values are preserved, not replaced with Chrome defaults. The caller must configure the
    /// actual connection consistently, and must reuse the result across handshake retries.
    /// This does not enable Chrome-shaped TLS or packet generation.
    ///
    /// # Errors
    ///
    /// Rejects server parameters and non-default settings that this layout cannot advertise.
    /// On error, the output is unchanged.
    pub fn write_chrome<W: BufMut>(
        &self,
        w: &mut W,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<(), TransportError> {
        if self.original_dst_cid.is_some()
            || self.retry_src_cid.is_some()
            || self.stateless_reset_token.is_some()
            || self.preferred_address.is_some()
            || self.initial_src_cid.is_none()
            || self.ack_delay_exponent != VarInt(3)
            || self.max_ack_delay != VarInt(25)
            || self.active_connection_id_limit != VarInt(2)
            || self.disable_active_migration
            || self.grease_quic_bit
            || self.min_ack_delay.is_some()
        {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "incompatible Chrome client transport parameters",
            ));
        }

        let mut params = Vec::with_capacity(13);
        for (id, value) in [
            (0x01, self.max_idle_timeout),
            (0x03, self.max_udp_payload_size),
            (0x04, self.initial_max_data),
            (0x05, self.initial_max_stream_data_bidi_local),
            (0x06, self.initial_max_stream_data_bidi_remote),
            (0x07, self.initial_max_stream_data_uni),
            (0x08, self.initial_max_streams_bidi),
            (0x09, self.initial_max_streams_uni),
        ] {
            let mut value_bytes = Vec::new();
            value_bytes.write(value);
            params.push(parameter(id, &value_bytes));
        }
        params.push(parameter(0x0f, self.initial_src_cid.as_ref().unwrap()));

        // RFC 9368: chosen version, then two available versions. Only QUIC v1 is supported
        // by this profile; the other version exercises RFC 9000's reserved version space.
        let grease_version = (rng.random::<u32>() & 0xf0f0_f0f0) | 0x0a0a_0a0a;
        let mut available = [1u32, grease_version];
        available.shuffle(rng);
        let mut versions = Vec::with_capacity(12);
        versions.put_u32(1);
        for version in available {
            versions.put_u32(version);
        }
        params.push(parameter(0x11, &versions));

        if let Some(size) = self.max_datagram_frame_size {
            let mut value = Vec::new();
            value.write(size);
            params.push(parameter(0x20, &value));
        }
        params.push(parameter(0x3128, b"ORIG"));

        // Reserved IDs are 31*N+27. Require an eight-byte QUIC varint.
        const N_MIN: u64 = ((1u64 << 30) - 27).div_ceil(31);
        const N_MAX: u64 = ((1u64 << 62) - 1 - 27) / 31;
        let id = 31 * rng.random_range(N_MIN..N_MAX) + 27;
        let mut value = vec![0; rng.random_range(0..=15)];
        rng.fill_bytes(&mut value);
        params.push(parameter(id, &value));

        params.shuffle(rng);
        for param in params {
            w.put_slice(&param);
        }
        Ok(())
    }
}

fn parameter(id: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.write_var(id);
    bytes.write_var(value.len() as u64);
    bytes.put_slice(value);
    bytes
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{RandomConnectionIdGenerator, TransportConfig, config::EndpointConfig};

    fn profile() -> TransportParameters {
        TransportParameters {
            max_idle_timeout: VarInt(30_000),
            max_udp_payload_size: VarInt(1472),
            initial_max_data: VarInt(15_728_640),
            initial_max_stream_data_bidi_local: VarInt(6_291_456),
            initial_max_stream_data_bidi_remote: VarInt(6_291_456),
            initial_max_stream_data_uni: VarInt(6_291_456),
            initial_max_streams_bidi: VarInt(100),
            initial_max_streams_uni: VarInt(103),
            initial_src_cid: Some(ConnectionId::new(&[])),
            max_datagram_frame_size: Some(VarInt(65_536)),
            ..TransportParameters::default()
        }
    }

    #[test]
    fn chrome_configured_profile_matches_advertised_limits() {
        let mut transport = TransportConfig::default();
        transport
            .stream_receive_window(VarInt::from_u32(6 * 1024 * 1024))
            .receive_window(VarInt::from_u32(15 * 1024 * 1024))
            .max_concurrent_bidi_streams(VarInt::from_u32(100))
            .max_concurrent_uni_streams(VarInt::from_u32(103))
            .max_idle_timeout(Some(VarInt::from_u32(30_000).into()))
            .initial_mtu(1250)
            .ack_frequency_supported(false)
            .datagram_receive_buffer_size(Some(65_536))
            .max_datagram_frame_size(Some(VarInt::from_u32(65_536)));
        let mut endpoint = EndpointConfig::default();
        endpoint.grease_quic_bit(false);
        let cid_generator = RandomConnectionIdGenerator::new(0);
        let params = TransportParameters::new(
            &transport,
            &endpoint,
            &cid_generator,
            ConnectionId::new(&[]),
            None,
            &mut StdRng::seed_from_u64(7),
        );
        let mut encoded = Vec::new();
        params
            .write_chrome(&mut encoded, &mut StdRng::seed_from_u64(8))
            .unwrap();
        let decoded = TransportParameters::read(Side::Server, &mut encoded.as_slice()).unwrap();
        assert_eq!(decoded.max_idle_timeout, VarInt(30_000));
        assert_eq!(decoded.max_udp_payload_size, VarInt(1472));
        assert_eq!(decoded.initial_max_data, VarInt(15 * 1024 * 1024));
        assert_eq!(
            decoded.initial_max_stream_data_bidi_local,
            VarInt(6 * 1024 * 1024)
        );
        assert_eq!(decoded.initial_max_streams_bidi, VarInt(100));
        assert_eq!(decoded.initial_max_streams_uni, VarInt(103));
        assert_eq!(decoded.max_datagram_frame_size, Some(VarInt(65_536)));
        assert_eq!(decoded.initial_src_cid, Some(ConnectionId::new(&[])));
        assert_eq!(decoded.min_ack_delay, None);
        assert!(!decoded.grease_quic_bit);
    }

    #[test]
    fn chrome_layout_roundtrip_and_randomization() {
        let mut rng = StdRng::seed_from_u64(42);
        let expected = profile();
        let mut orders = BTreeSet::new();
        let mut grease_lengths = BTreeSet::new();
        let mut version_orders = BTreeSet::new();
        for _ in 0..256 {
            let mut encoded = Vec::new();
            expected.write_chrome(&mut encoded, &mut rng).unwrap();
            assert_eq!(
                TransportParameters::read(Side::Server, &mut encoded.as_slice()).unwrap(),
                expected
            );
            let mut input = encoded.as_slice();
            let mut values = BTreeMap::new();
            let mut order = Vec::new();
            while input.has_remaining() {
                let id = input.get_var().unwrap();
                let len = input.get_var().unwrap() as usize;
                let value = input.copy_to_bytes(len);
                assert!(values.insert(id, value).is_none());
                order.push(if id >= 1 << 30 { u64::MAX } else { id });
            }
            assert_eq!(values.len(), 13);
            let ids: Vec<_> = values.keys().copied().filter(|id| *id < 1 << 30).collect();
            assert_eq!(ids, [1, 3, 4, 5, 6, 7, 8, 9, 15, 17, 32, 0x3128]);
            assert_eq!(values[&0x3128].as_ref(), b"ORIG");
            assert!(values[&15].is_empty());
            let mut versions = values[&17].as_ref();
            assert_eq!(versions.remaining(), 12);
            assert_eq!(versions.get_u32(), 1);
            let first = versions.get_u32();
            let second = versions.get_u32();
            let grease = if first == 1 { second } else { first };
            assert!(first == 1 || second == 1);
            assert_eq!(grease & 0x0f0f_0f0f, 0x0a0a_0a0a);
            version_orders.insert(first == 1);
            let (&id, value) = values.last_key_value().unwrap();
            assert_eq!((id - 27) % 31, 0);
            assert_eq!(VarInt::from_u64(id).unwrap().size(), 8);
            assert!(value.len() <= 15);
            grease_lengths.insert(value.len());
            orders.insert(order);
        }
        assert_eq!(grease_lengths.len(), 16);
        assert_eq!(version_orders.len(), 2);
        assert!(orders.len() > 1);
    }

    #[test]
    fn chrome_preserves_nonstandard_values_and_optional_datagrams() {
        let mut params = profile();
        params.initial_max_data = VarInt(12345);
        params.initial_src_cid = Some(ConnectionId::new(&[1, 2, 3]));
        params.max_datagram_frame_size = None;
        let mut encoded = Vec::new();
        params
            .write_chrome(&mut encoded, &mut StdRng::seed_from_u64(0))
            .unwrap();
        assert_eq!(
            TransportParameters::read(Side::Server, &mut encoded.as_slice()).unwrap(),
            params
        );
    }

    #[test]
    fn chrome_rejects_unadvertised_settings_without_writing() {
        let original = profile();
        let mut cases = [original; 11];
        cases[0].original_dst_cid = Some(ConnectionId::new(&[]));
        cases[1].retry_src_cid = Some(ConnectionId::new(&[]));
        cases[2].stateless_reset_token = Some([0; 16].into());
        cases[3].initial_src_cid = None;
        cases[4].ack_delay_exponent = VarInt(2);
        cases[5].max_ack_delay = VarInt(26);
        cases[6].active_connection_id_limit = VarInt(3);
        cases[7].disable_active_migration = true;
        cases[8].grease_quic_bit = true;
        cases[9].min_ack_delay = Some(VarInt(1000));
        cases[10].preferred_address = Some(PreferredAddress {
            address_v4: None,
            address_v6: None,
            connection_id: ConnectionId::new(&[1]),
            stateless_reset_token: [0; 16].into(),
        });
        for params in cases {
            let mut encoded = vec![42];
            assert!(
                params
                    .write_chrome(&mut encoded, &mut StdRng::seed_from_u64(0))
                    .is_err()
            );
            assert_eq!(encoded, [42]);
        }
    }
}
