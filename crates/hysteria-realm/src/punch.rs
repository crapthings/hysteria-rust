use getrandom::fill as random_fill;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const MAX_PUNCH_PADDING: usize = 1024;
const SALT_LENGTH: usize = 8;
const HEADER_LENGTH: usize = 25;
const MINIMUM_WIRE_LENGTH: usize = SALT_LENGTH + HEADER_LENGTH;
const MAXIMUM_WIRE_LENGTH: usize = MINIMUM_WIRE_LENGTH + MAX_PUNCH_PADDING;
const MAGIC: &[u8; 8] = b"HYRLMv1\0";

#[derive(Debug, Error)]
pub enum PunchPacketError {
    #[error("invalid punch packet: {0}")]
    Invalid(String),
    #[error("secure random generation failed: {0}")]
    Random(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PunchMetadata {
    pub nonce: String,
    pub obfs: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PunchPacketType {
    Hello = 0x01,
    Ack = 0x02,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchPacket {
    pub kind: PunchPacketType,
    pub padding_length: usize,
}

/// Generates fresh Go-compatible nonce and obfuscation values.
///
/// # Errors
///
/// Returns an error if the operating system random source fails.
pub fn new_punch_metadata() -> Result<PunchMetadata, PunchPacketError> {
    let mut nonce = [0; 16];
    let mut obfs = [0; 32];
    fill_random(&mut nonce)?;
    fill_random(&mut obfs)?;
    Ok(PunchMetadata {
        nonce: encode_hex(&nonce),
        obfs: encode_hex(&obfs),
    })
}

impl PunchPacket {
    /// Encodes a randomized Realm punch packet.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed metadata or random-source failure.
    pub fn encode(
        kind: PunchPacketType,
        metadata: &PunchMetadata,
    ) -> Result<Vec<u8>, PunchPacketError> {
        let padding_length = random_padding_length()?;
        let mut salt = [0; SALT_LENGTH];
        fill_random(&mut salt)?;
        encode_with(kind, metadata, salt, padding_length)
    }

    /// Decodes and authenticates the Realm packet marker, kind, and nonce.
    ///
    /// # Errors
    ///
    /// Returns an error for bad lengths, metadata, magic, kind, or nonce.
    pub fn decode(packet: &[u8], metadata: &PunchMetadata) -> Result<Self, PunchPacketError> {
        if !(MINIMUM_WIRE_LENGTH..=MAXIMUM_WIRE_LENGTH).contains(&packet.len()) {
            return Err(PunchPacketError::Invalid(
                "invalid packet length".to_owned(),
            ));
        }
        let (nonce, obfs) = decode_metadata(metadata)?;
        let (salt, encrypted) = packet.split_at(SALT_LENGTH);
        let mut plaintext = encrypted.to_vec();
        xor_packet(&mut plaintext, &obfs, salt);
        if plaintext.get(..MAGIC.len()) != Some(MAGIC) {
            return Err(PunchPacketError::Invalid("bad magic".to_owned()));
        }
        let kind = match plaintext[MAGIC.len()] {
            0x01 => PunchPacketType::Hello,
            0x02 => PunchPacketType::Ack,
            _ => return Err(PunchPacketError::Invalid("unknown packet type".to_owned())),
        };
        if plaintext[MAGIC.len() + 1..HEADER_LENGTH] != nonce {
            return Err(PunchPacketError::Invalid("nonce mismatch".to_owned()));
        }
        Ok(Self {
            kind,
            padding_length: plaintext.len() - HEADER_LENGTH,
        })
    }
}

fn encode_with(
    kind: PunchPacketType,
    metadata: &PunchMetadata,
    salt: [u8; SALT_LENGTH],
    padding_length: usize,
) -> Result<Vec<u8>, PunchPacketError> {
    if padding_length > MAX_PUNCH_PADDING {
        return Err(PunchPacketError::Invalid("padding is too large".to_owned()));
    }
    let (nonce, obfs) = decode_metadata(metadata)?;
    let mut packet = vec![0; MINIMUM_WIRE_LENGTH + padding_length];
    packet[..SALT_LENGTH].copy_from_slice(&salt);
    let plaintext = &mut packet[SALT_LENGTH..];
    plaintext[..MAGIC.len()].copy_from_slice(MAGIC);
    plaintext[MAGIC.len()] = kind as u8;
    plaintext[MAGIC.len() + 1..HEADER_LENGTH].copy_from_slice(&nonce);
    if padding_length != 0 {
        fill_random(&mut plaintext[HEADER_LENGTH..])?;
    }
    xor_packet(plaintext, &obfs, &salt);
    Ok(packet)
}

fn decode_metadata(metadata: &PunchMetadata) -> Result<([u8; 16], [u8; 32]), PunchPacketError> {
    Ok((
        decode_hex::<16>("nonce", &metadata.nonce)?,
        decode_hex::<32>("obfs", &metadata.obfs)?,
    ))
}

fn decode_hex<const N: usize>(name: &str, value: &str) -> Result<[u8; N], PunchPacketError> {
    if value.len() != N * 2 {
        return Err(PunchPacketError::Invalid(format!("invalid {name} length")));
    }
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| PunchPacketError::Invalid(format!("invalid {name}")))?;
    }
    Ok(output)
}

fn encode_hex(input: &[u8]) -> String {
    use std::fmt::Write as _;
    input.iter().fold(
        String::with_capacity(input.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        },
    )
}

fn xor_packet(packet: &mut [u8], obfs: &[u8; 32], salt: &[u8]) {
    let mask = Sha256::new()
        .chain_update(obfs)
        .chain_update(salt)
        .finalize();
    for (index, byte) in packet.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
}

fn random_padding_length() -> Result<usize, PunchPacketError> {
    const RANGE: u16 = 1025;
    const LIMIT: u16 = u16::MAX - (u16::MAX % RANGE);
    loop {
        let mut bytes = [0; 2];
        fill_random(&mut bytes)?;
        let value = u16::from_be_bytes(bytes);
        if value < LIMIT {
            return Ok(usize::from(value % RANGE));
        }
    }
}

fn fill_random(output: &mut [u8]) -> Result<(), PunchPacketError> {
    random_fill(output).map_err(|error| PunchPacketError::Random(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> PunchMetadata {
        PunchMetadata {
            nonce: "00112233445566778899aabbccddeeff".to_owned(),
            obfs: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
        }
    }

    #[test]
    fn fixed_go_wire_vector_and_random_round_trips() {
        let fixed = encode_with(PunchPacketType::Hello, &metadata(), *b"12345678", 0).unwrap();
        assert_eq!(
            encode_hex(&fixed),
            "31323334353637388edd4620b83237bcd488c59d2cbdb841796e2045c6cc132ba0"
        );
        assert_eq!(
            PunchPacket::decode(&fixed, &metadata()).unwrap(),
            PunchPacket {
                kind: PunchPacketType::Hello,
                padding_length: 0
            }
        );
        for kind in [PunchPacketType::Hello, PunchPacketType::Ack] {
            let encoded = PunchPacket::encode(kind, &metadata()).unwrap();
            let decoded = PunchPacket::decode(&encoded, &metadata()).unwrap();
            assert_eq!(decoded.kind, kind);
            assert!(decoded.padding_length <= MAX_PUNCH_PADDING);
        }
    }

    #[test]
    fn rejects_wrong_metadata_corruption_and_lengths() {
        let packet = PunchPacket::encode(PunchPacketType::Hello, &metadata()).unwrap();
        let mut wrong = metadata();
        wrong.nonce = "ff".repeat(16);
        assert!(PunchPacket::decode(&packet, &wrong).is_err());
        wrong = metadata();
        wrong.obfs = "ff".repeat(32);
        assert!(PunchPacket::decode(&packet, &wrong).is_err());
        assert!(PunchPacket::decode(&[0; MINIMUM_WIRE_LENGTH - 1], &metadata()).is_err());
        assert!(PunchPacket::decode(&[0; MAXIMUM_WIRE_LENGTH + 1], &metadata()).is_err());
    }

    #[test]
    fn metadata_is_lowercase_hex_with_exact_sizes() {
        let metadata = new_punch_metadata().unwrap();
        assert_eq!(metadata.nonce.len(), 32);
        assert_eq!(metadata.obfs.len(), 64);
        assert!(
            metadata
                .nonce
                .bytes()
                .chain(metadata.obfs.bytes())
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}
