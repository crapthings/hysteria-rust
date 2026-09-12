//! Explicit QUIC-only ALPS configuration (experimental extension codepoint 17613).
use crate::Error;
use alloc::vec::Vec;

// Leave headroom for other TLS extensions and bound per-connection allocation.
const MAX_SETTINGS: usize = 16 * 1024;

pub(crate) fn validate(settings: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Error> {
    let mut length = 0usize;
    for (i, (protocol, value)) in settings.iter().enumerate() {
        if protocol.is_empty()
            || protocol.len() > 255
            || value.len() > MAX_SETTINGS
            || settings[..i].iter().any(|(p, _)| p == protocol)
        {
            return Err(Error::General(
                "invalid or duplicate QUIC application settings".into(),
            ));
        }
        length += protocol.len() + 1;
        if length > MAX_SETTINGS {
            return Err(Error::General(
                "QUIC application settings protocol list too long".into(),
            ));
        }
    }
    Ok(())
}
