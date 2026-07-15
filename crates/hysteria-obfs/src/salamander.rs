use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use std::fmt;

pub const SALT_LENGTH: usize = 8;
const KEY_LENGTH: usize = 32;
const MIN_PASSWORD_LENGTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SalamanderError {
    PasswordTooShort,
    PacketTooShort,
}

impl fmt::Display for SalamanderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordTooShort => {
                write!(f, "password must be at least {MIN_PASSWORD_LENGTH} bytes")
            }
            Self::PacketTooShort => write!(
                f,
                "packet must contain an {SALT_LENGTH}-byte salt and a payload"
            ),
        }
    }
}

impl std::error::Error for SalamanderError {}

/// Hysteria's Salamander per-packet obfuscator.
///
/// The salt is intentionally supplied by the caller so the eventual UDP transport
/// can use its platform random source without coupling this codec to an async runtime.
#[derive(Debug, Clone)]
pub struct Salamander {
    password: Box<[u8]>,
}

impl Salamander {
    /// Creates an obfuscator from a pre-shared password.
    ///
    /// # Errors
    ///
    /// Returns [`SalamanderError::PasswordTooShort`] for passwords shorter than four bytes.
    pub fn new(password: impl AsRef<[u8]>) -> Result<Self, SalamanderError> {
        let password = password.as_ref();
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(SalamanderError::PasswordTooShort);
        }
        Ok(Self {
            password: password.into(),
        })
    }

    /// Prepends `salt` and XORs `payload` with `BLAKE2b-256(password || salt)`.
    #[must_use]
    pub fn obfuscate(&self, payload: &[u8], salt: [u8; SALT_LENGTH]) -> Vec<u8> {
        let key = self.packet_key(&salt);
        let mut output = Vec::with_capacity(SALT_LENGTH + payload.len());
        output.extend_from_slice(&salt);
        output.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ key[index % KEY_LENGTH]),
        );
        output
    }

    /// Removes Salamander framing and reverses its XOR operation.
    ///
    /// # Errors
    ///
    /// Returns [`SalamanderError::PacketTooShort`] if no payload follows the salt.
    pub fn deobfuscate(&self, packet: &[u8]) -> Result<Vec<u8>, SalamanderError> {
        if packet.len() <= SALT_LENGTH {
            return Err(SalamanderError::PacketTooShort);
        }
        let (salt, payload) = packet.split_at(SALT_LENGTH);
        let key = self.packet_key(salt);
        Ok(payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % KEY_LENGTH])
            .collect())
    }

    fn packet_key(&self, salt: &[u8]) -> [u8; KEY_LENGTH] {
        let mut hasher = Blake2bVar::new(KEY_LENGTH).expect("BLAKE2b-256 has a valid output size");
        hasher.update(&self.password);
        hasher.update(salt);
        let mut key = [0; KEY_LENGTH];
        hasher
            .finalize_variable(&mut key)
            .expect("output buffer has the configured size");
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_cross_language_blake2b_vector() {
        let salamander = Salamander::new(b"average_password").unwrap();
        let packet = salamander.obfuscate(b"hello hysteria", [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            packet,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x70, 0x45, 0x8c, 0xbe, 0x79, 0x42,
                0x85, 0x60, 0x9c, 0xd5, 0xa7, 0xb5, 0x0a, 0x01,
            ]
        );
        assert_eq!(salamander.deobfuscate(&packet).unwrap(), b"hello hysteria");
    }

    #[test]
    fn key_repeats_for_payloads_larger_than_digest() {
        let salamander = Salamander::new(b"test").unwrap();
        let payload: Vec<u8> = (0..=255).collect();
        let packet = salamander.obfuscate(&payload, [0x42; SALT_LENGTH]);
        assert_eq!(salamander.deobfuscate(&packet).unwrap(), payload);
    }

    #[test]
    fn validates_password_and_packet_lengths() {
        assert!(matches!(
            Salamander::new(b"abc"),
            Err(SalamanderError::PasswordTooShort)
        ));
        let salamander = Salamander::new(b"abcd").unwrap();
        assert_eq!(
            salamander.deobfuscate(&[]),
            Err(SalamanderError::PacketTooShort)
        );
        assert_eq!(
            salamander.deobfuscate(&[0; SALT_LENGTH]),
            Err(SalamanderError::PacketTooShort)
        );
    }
}
