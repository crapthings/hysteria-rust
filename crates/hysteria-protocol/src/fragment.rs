use crate::{ProtocolError, UdpMessage};

/// Splits a UDP message without exceeding `max_size`, including each Hysteria header.
///
/// # Errors
///
/// Returns [`ProtocolError::TooManyFragments`] if more than 255 fragments are needed.
pub fn fragment_udp_message(
    message: &UdpMessage,
    max_size: usize,
) -> Result<Vec<UdpMessage>, ProtocolError> {
    if message.encoded_size() <= max_size {
        return Ok(vec![message.clone()]);
    }
    let max_payload_size = max_size.saturating_sub(message.header_size());
    if max_payload_size == 0 {
        return Ok(Vec::new());
    }
    let fragment_count = message.data.len().div_ceil(max_payload_size);
    let count = u8::try_from(fragment_count)
        .map_err(|_| ProtocolError::TooManyFragments(fragment_count))?;
    let mut fragments = Vec::with_capacity(fragment_count);
    for (index, data) in message.data.chunks(max_payload_size).enumerate() {
        let mut fragment = message.clone();
        fragment.fragment_id =
            u8::try_from(index).map_err(|_| ProtocolError::TooManyFragments(fragment_count))?;
        fragment.fragment_count = count;
        fragment.data = data.to_vec();
        fragments.push(fragment);
    }
    Ok(fragments)
}

/// Stateful single-packet defragmenter matching Hysteria's per-session behavior.
#[derive(Debug, Default)]
pub struct Defragger {
    packet_id: u16,
    fragments: Vec<Option<UdpMessage>>,
    received: usize,
}

impl Defragger {
    /// Returns a complete message once all fragments arrive. A new packet ID or
    /// fragment count discards any incomplete packet.
    pub fn feed(&mut self, message: UdpMessage) -> Option<UdpMessage> {
        if message.fragment_count <= 1 {
            return Some(message);
        }
        if message.fragment_id >= message.fragment_count {
            return None;
        }
        let index = usize::from(message.fragment_id);
        let expected = usize::from(message.fragment_count);
        if message.packet_id != self.packet_id || self.fragments.len() != expected {
            self.packet_id = message.packet_id;
            self.fragments = vec![None; expected];
            self.fragments[index] = Some(message);
            self.received = 1;
        } else if self.fragments[index].is_none() {
            self.fragments[index] = Some(message.clone());
            self.received += 1;
            if self.received == self.fragments.len() {
                let total_size = self
                    .fragments
                    .iter()
                    .flatten()
                    .map(|fragment| fragment.data.len())
                    .sum();
                let mut data = Vec::with_capacity(total_size);
                for fragment in self.fragments.iter().flatten() {
                    data.extend_from_slice(&fragment.data);
                }
                let mut complete = message;
                complete.fragment_id = 0;
                complete.fragment_count = 1;
                complete.data = data;
                return Some(complete);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(data: &[u8]) -> UdpMessage {
        UdpMessage {
            session_id: 123,
            packet_id: 987,
            fragment_id: 0,
            fragment_count: 1,
            address: "test:123".into(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn fragments_match_go_vectors() {
        let fragments = fragment_udp_message(&message(b"abcdefgh"), 19).unwrap();
        assert_eq!(fragments.len(), 4);
        assert_eq!(
            fragments
                .iter()
                .map(|item| item.data.as_slice())
                .collect::<Vec<_>>(),
            vec![b"ab", b"cd", b"ef", b"gh"]
        );
        assert_eq!(
            fragments
                .iter()
                .map(|item| item.fragment_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert!(fragments.iter().all(|item| item.fragment_count == 4));
    }

    #[test]
    fn defragments_out_of_order_and_ignores_duplicates() {
        let mut fragments = fragment_udp_message(&message(b"hello moto"), 21).unwrap();
        assert_eq!(fragments.len(), 3);
        let mut defragger = Defragger::default();
        assert!(defragger.feed(fragments[2].clone()).is_none());
        assert!(defragger.feed(fragments[2].clone()).is_none());
        assert!(defragger.feed(fragments[0].clone()).is_none());
        let complete = defragger.feed(fragments.swap_remove(1)).unwrap();
        assert_eq!(complete.data, b"hello moto");
        assert_eq!((complete.fragment_id, complete.fragment_count), (0, 1));
    }

    #[test]
    fn rejects_impossible_fragment_counts() {
        let mut large = message(&vec![0; 256]);
        large.address.clear();
        assert!(matches!(
            fragment_udp_message(&large, large.header_size() + 1),
            Err(ProtocolError::TooManyFragments(256))
        ));
    }
}
