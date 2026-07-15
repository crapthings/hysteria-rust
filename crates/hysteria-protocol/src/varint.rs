use crate::ProtocolError;

/// Largest integer representable by the QUIC variable-length integer encoding.
pub const MAX_VARINT: u64 = (1_u64 << 62) - 1;

#[must_use]
pub const fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Appends an RFC 9000 variable-length integer to `output`.
///
/// # Errors
///
/// Returns [`ProtocolError::VarintTooLarge`] when `value` exceeds 62 bits.
pub fn encode_varint(value: u64, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
    if value > MAX_VARINT {
        return Err(ProtocolError::VarintTooLarge(value));
    }
    match varint_len(value) {
        1 => output.push(u8::try_from(value).map_err(|_| ProtocolError::VarintTooLarge(value))?),
        2 => output.extend_from_slice(
            &(u16::try_from(value).map_err(|_| ProtocolError::VarintTooLarge(value))? | 0x4000)
                .to_be_bytes(),
        ),
        4 => output.extend_from_slice(
            &(u32::try_from(value).map_err(|_| ProtocolError::VarintTooLarge(value))?
                | 0x8000_0000)
                .to_be_bytes(),
        ),
        8 => output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
        _ => unreachable!(),
    }
    Ok(())
}

/// Decodes one RFC 9000 variable-length integer and advances `input`.
///
/// # Errors
///
/// Returns [`ProtocolError::UnexpectedEnd`] when the encoded value is truncated.
pub fn decode_varint(input: &mut &[u8]) -> Result<u64, ProtocolError> {
    let first = *input.first().ok_or(ProtocolError::UnexpectedEnd)?;
    let len = 1_usize << (first >> 6);
    if input.len() < len {
        return Err(ProtocolError::UnexpectedEnd);
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    *input = &input[len..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_vectors_match_rfc_9000() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (63, &[0x3f]),
            (64, &[0x40, 0x40]),
            (16_383, &[0x7f, 0xff]),
            (16_384, &[0x80, 0x00, 0x40, 0x00]),
            (1_073_741_823, &[0xbf, 0xff, 0xff, 0xff]),
            (
                1_073_741_824,
                &[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
            ),
            (MAX_VARINT, &[0xff; 8]),
        ];
        for &(value, expected) in cases {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).unwrap();
            assert_eq!(encoded, expected);
            let mut input = encoded.as_slice();
            assert_eq!(decode_varint(&mut input).unwrap(), value);
            assert!(input.is_empty());
        }
    }

    #[test]
    fn accepts_non_minimal_encoding() {
        let mut input = &[0x80, 0, 0, 1][..];
        assert_eq!(decode_varint(&mut input), Ok(1));
    }

    #[test]
    fn rejects_truncation_and_overflow() {
        assert_eq!(
            decode_varint(&mut &[0x40][..]),
            Err(ProtocolError::UnexpectedEnd)
        );
        assert_eq!(
            encode_varint(MAX_VARINT + 1, &mut Vec::new()),
            Err(ProtocolError::VarintTooLarge(MAX_VARINT + 1))
        );
    }
}
