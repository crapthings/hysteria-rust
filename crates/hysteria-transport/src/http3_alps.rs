//! Bounded ALPS framing inspection; this does not apply HTTP/3 settings.
//! The live HTTP/3 driver must not accept ALPS merely because parsing succeeds.

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) values: Option<std::collections::BTreeMap<u64, u64>>,
    pub(crate) accept_ch_frames: usize,
}

impl Settings {
    /// Limits usable by the current stateless h3 encoder. QPACK peer settings
    /// are upper bounds: zero dynamic capacity and zero blocked streams obey
    /// every advertised value (RFC 9204 sections 2.1.2 and 3.2.3).
    pub(crate) fn supported_header_limit(&self) -> Result<Option<u64>, &'static str> {
        if self.accept_ch_frames != 0 {
            return Err("ALPS ACCEPT_CH handling is not implemented");
        }
        let Some(values) = &self.values else {
            return Ok(None);
        };
        for (&id, &value) in values {
            if value != 0 && matches!(id, 8 | 0x33 | 0x00ff_d277 | 0x2b60_3742 | 0x2b60_3743) {
                return Err("unsupported HTTP/3 ALPS setting");
            }
            // QPACK bounds require no dynamic state; id 6 is returned below.
            // Unknown SETTINGS (including GREASE) have no semantics for us.
            // Reserved HTTP/2 settings and duplicates were rejected by inspect.
        }
        Ok(values.get(&6).copied())
    }
}

/// Inspect authenticated TLS data without allocating based on peer lengths.
pub(crate) fn inspect(mut input: &[u8]) -> Result<Settings, &'static str> {
    if input.len() > 16 * 1024 {
        return Err("ALPS exceeds 16 KiB");
    }
    let mut result = Settings::default();
    while !input.is_empty() {
        let kind = varint(&mut input)?;
        let mut payload = length_prefixed(&mut input)?;
        match kind {
            4 => {
                if result.values.is_some() {
                    return Err("duplicate ALPS SETTINGS frame");
                }
                let mut values = std::collections::BTreeMap::new();
                while !payload.is_empty() {
                    let id = varint(&mut payload)?;
                    let value = varint(&mut payload)?;
                    if matches!(id, 2..=5) {
                        return Err("HTTP/2 setting in HTTP/3 ALPS");
                    }
                    if matches!(id, 8 | 0x33) && value > 1 {
                        return Err("invalid boolean ALPS setting");
                    }
                    if values.insert(id, value).is_some() {
                        return Err("duplicate ALPS setting identifier");
                    }
                }
                result.values = Some(values);
            }
            // ACCEPT_CH contains length-prefixed origin / field-value pairs.
            // Do not interpret or expose these bytes as request headers.
            0x89 => {
                while !payload.is_empty() {
                    length_prefixed(&mut payload)?;
                    length_prefixed(&mut payload)?;
                }
                result.accept_ch_frames += 1;
            }
            0..=3 | 5..=9 | 0xd | 0xf0700 | 0xf0701 => {
                return Err("forbidden HTTP/3 frame in ALPS");
            }
            // Unknown extension frames are length-delimited and ignored.
            _ => {}
        }
    }
    Ok(result)
}

fn varint(input: &mut &[u8]) -> Result<u64, &'static str> {
    let first = *input.first().ok_or("truncated ALPS varint")?;
    let width = 1_usize << (first >> 6);
    let bytes = input.get(..width).ok_or("truncated ALPS varint")?;
    let mut value = u64::from(first & 0x3f);
    for &byte in &bytes[1..] {
        value = (value << 8) | u64::from(byte);
    }
    *input = &input[width..];
    Ok(value)
}

fn length_prefixed<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], &'static str> {
    let length = usize::try_from(varint(input)?).map_err(|_| "ALPS length overflow")?;
    let bytes = input.get(..length).ok_or("truncated ALPS payload")?;
    *input = &input[length..];
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateless_encoder_accepts_qpack_bounds_and_disabled_extensions() {
        for bound in [0, 1, 4096, (1_u64 << 62) - 1] {
            let settings = Settings {
                values: Some([(1, bound), (7, bound), (6, 8192), (8, 0), (0x33, 0)].into()),
                accept_ch_frames: 0,
            };
            assert_eq!(settings.supported_header_limit(), Ok(Some(8192)));
        }
        for id in [8, 0x33, 0x00ff_d277, 0x2b60_3742, 0x2b60_3743] {
            let settings = Settings {
                values: Some([(id, 1)].into()),
                accept_ch_frames: 0,
            };
            assert!(settings.supported_header_limit().is_err());
        }
        assert!(
            Settings {
                values: None,
                accept_ch_frames: 1
            }
            .supported_header_limit()
            .is_err()
        );
    }

    #[test]
    fn unknown_settings_are_ignored_but_still_validated() {
        // GREASE id 0x21 followed by a recognized header limit.
        let settings = inspect(&[4, 4, 0x21, 63, 6, 42]).unwrap();
        assert_eq!(settings.supported_header_limit(), Ok(Some(42)));
        // An arbitrary unrecognized id, not only a GREASE id.
        let settings = inspect(&[4, 3, 0x52, 0x34, 1]).unwrap();
        assert_eq!(settings.supported_header_limit(), Ok(None));
        assert!(inspect(&[4, 4, 0x21, 0, 0x21, 1]).is_err());
        assert!(inspect(&[4, 1, 0x21]).is_err());
        for frame in [2, 6, 8, 9] {
            assert!(inspect(&[frame, 0]).is_err());
        }
    }

    #[test]
    fn empty_and_absent_settings_are_distinct() {
        assert_eq!(inspect(&[]).unwrap().values, None);
        assert_eq!(
            inspect(&[4, 0]).unwrap().values,
            Some(std::collections::BTreeMap::new())
        );
        let settings = inspect(&[4, 4, 6, 42, 8, 1]).unwrap();
        assert_eq!(settings.values.unwrap().get(&6), Some(&42));
    }

    #[test]
    fn accepts_unknown_frames_and_wide_varints() {
        assert_eq!(inspect(&[0x21, 1, 0xff]).unwrap(), Settings::default());
        assert!(inspect(&[0x40, 4, 0x40, 0]).unwrap().values.is_some());
        for width in [1, 2, 4, 8] {
            let mut data = vec![0; width];
            data[0] = match width {
                1 => 0,
                2 => 0x40,
                4 => 0x80,
                _ => 0xc0,
            };
            let mut input = data.as_slice();
            assert_eq!(varint(&mut input), Ok(0));
            assert!(input.is_empty());
            for end in 0..width {
                assert!(varint(&mut &data[..end]).is_err());
            }
        }
    }

    #[test]
    fn rejects_duplicates_invalid_settings_and_forbidden_frames() {
        for data in [
            &[4, 0, 4, 0][..],
            &[4, 4, 6, 1, 6, 2],
            &[4, 2, 2, 0],
            &[4, 2, 8, 2],
            &[4, 2, 0x33, 2],
            &[0, 0],
            &[1, 0],
            &[3, 0],
            &[5, 0],
            &[7, 0],
            &[0xd, 0],
        ] {
            assert!(inspect(data).is_err(), "{data:?}");
        }
    }

    #[test]
    fn validates_accept_ch_pairs_and_frame_boundaries() {
        let frame = [0x40, 0x89, 4, 1, b'a', 1, b'b'];
        assert_eq!(inspect(&frame).unwrap().accept_ch_frames, 1);
        for end in 1..frame.len() {
            assert!(inspect(&frame[..end]).is_err());
        }
        assert!(inspect(&[0x40, 0x89, 2, 1, b'a']).is_err());
        assert!(inspect(&[4, 1, 6]).is_err());
        assert!(inspect(&[0x21, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(inspect(&vec![0; 16 * 1024 + 1]).is_err());
    }
}
