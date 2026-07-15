use crate::{SALT_LENGTH, Salamander, SalamanderError};
use std::{
    collections::HashMap,
    fmt,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

const FRAGMENT_FLAG: u8 = 0x80;
const HEADER_SIZE: usize = 5;
const MIN_FRAGMENT_COUNT: u8 = 2;
const MAX_FRAGMENT_COUNT: u8 = 8;
const BUFFER_SIZE: usize = 2048;
const MAX_REASSEMBLIES: usize = 4096;
const MAX_REASSEMBLIES_PER_SOURCE: usize = 8;
const REASSEMBLY_TTL: Duration = Duration::from_secs(8);

pub const DEFAULT_MIN_PACKET_SIZE: usize = 512;
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeckoOptions {
    pub min_packet_size: usize,
    pub max_packet_size: usize,
}

impl Default for GeckoOptions {
    fn default() -> Self {
        Self {
            min_packet_size: DEFAULT_MIN_PACKET_SIZE,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeckoError {
    MissingPassword,
    InvalidPacketSizeRange,
    InvalidFragmentCount(u8),
    InvalidChunkIndex { index: u8, total: u8 },
    TruncatedFrame,
    RandomSource,
    Salamander(SalamanderError),
}

impl fmt::Display for GeckoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPassword => f.write_str("gecko password is required"),
            Self::InvalidPacketSizeRange => {
                f.write_str("invalid Gecko minimum/maximum packet size")
            }
            Self::InvalidFragmentCount(total) => write!(f, "invalid Gecko fragment count {total}"),
            Self::InvalidChunkIndex { index, total } => write!(
                f,
                "Gecko chunk index {index} is outside fragment count {total}"
            ),
            Self::TruncatedFrame => f.write_str("truncated Gecko frame"),
            Self::RandomSource => f.write_str("operating-system random source failed"),
            Self::Salamander(error) => write!(f, "Salamander error: {error}"),
        }
    }
}

impl std::error::Error for GeckoError {}

impl From<SalamanderError> for GeckoError {
    fn from(error: SalamanderError) -> Self {
        Self::Salamander(error)
    }
}

/// One cleartext Gecko fragment frame (before Salamander obfuscation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeckoFrame {
    pub message_id: u8,
    pub chunk_index: u8,
    pub total_chunks: u8,
    pub padding: Vec<u8>,
    pub payload: Vec<u8>,
}

impl GeckoFrame {
    /// Encodes the five-byte Gecko header, padding, and fragment payload.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported fragment count, invalid index, or padding over 65535 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, GeckoError> {
        validate_fragment(self.chunk_index, self.total_chunks)?;
        let padding_len =
            u16::try_from(self.padding.len()).map_err(|_| GeckoError::TruncatedFrame)?;
        let mut output = Vec::with_capacity(HEADER_SIZE + self.padding.len() + self.payload.len());
        output.push(FRAGMENT_FLAG);
        output.push(self.message_id);
        output.push((self.chunk_index << 4) | (self.total_chunks & 0x0f));
        output.extend_from_slice(&padding_len.to_be_bytes());
        output.extend_from_slice(&self.padding);
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    /// Decodes a Gecko frame from a complete cleartext datagram.
    ///
    /// # Errors
    ///
    /// Returns an error for missing headers, invalid fragment metadata, or truncated padding.
    pub fn decode(input: &[u8]) -> Result<Self, GeckoError> {
        if input.len() < HEADER_SIZE {
            return Err(GeckoError::TruncatedFrame);
        }
        if input[0] & FRAGMENT_FLAG == 0 {
            return Err(GeckoError::InvalidFragmentCount(0));
        }
        let chunk_index = input[2] >> 4;
        let total_chunks = input[2] & 0x0f;
        validate_fragment(chunk_index, total_chunks)?;
        let padding_len = usize::from(u16::from_be_bytes([input[3], input[4]]));
        let payload_offset = HEADER_SIZE
            .checked_add(padding_len)
            .filter(|offset| *offset <= input.len())
            .ok_or(GeckoError::TruncatedFrame)?;
        Ok(Self {
            message_id: input[1],
            chunk_index,
            total_chunks,
            padding: input[HEADER_SIZE..payload_offset].to_vec(),
            payload: input[payload_offset..].to_vec(),
        })
    }
}

/// Gecko packet-shape obfuscation composed with Salamander encryption.
///
/// QUIC long-header packets are split into 2–8 independently padded datagrams.
/// Short-header packets remain a single Salamander datagram.
#[derive(Debug)]
pub struct Gecko {
    salamander: Salamander,
    options: GeckoOptions,
    next_message_id: AtomicU32,
    reassembler: Mutex<Reassembler>,
}

impl Gecko {
    /// Creates a Gecko codec using Hysteria-compatible defaults when either packet size is zero.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/short password or an invalid packet-size range.
    pub fn new(password: impl AsRef<[u8]>, mut options: GeckoOptions) -> Result<Self, GeckoError> {
        let password = password.as_ref();
        if password.is_empty() {
            return Err(GeckoError::MissingPassword);
        }
        if options.min_packet_size == 0 {
            options.min_packet_size = DEFAULT_MIN_PACKET_SIZE;
        }
        if options.max_packet_size == 0 {
            options.max_packet_size = DEFAULT_MAX_PACKET_SIZE;
        }
        if options.min_packet_size > options.max_packet_size
            || options.max_packet_size > BUFFER_SIZE
        {
            return Err(GeckoError::InvalidPacketSizeRange);
        }
        Ok(Self {
            salamander: Salamander::new(password)?,
            options,
            next_message_id: AtomicU32::new(0),
            reassembler: Mutex::new(Reassembler::default()),
        })
    }

    /// Converts one QUIC packet into one or more wire datagrams.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating-system random source fails.
    pub fn encode_packet(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>, GeckoError> {
        if packet.is_empty() {
            return Ok(Vec::new());
        }
        if packet[0] & FRAGMENT_FLAG == 0 {
            return Ok(vec![self.obfuscate(packet)?]);
        }

        let random_chunk_offset =
            random_below(u32::from(MAX_FRAGMENT_COUNT - MIN_FRAGMENT_COUNT + 1))?;
        let total_chunks = MIN_FRAGMENT_COUNT
            + u8::try_from(random_chunk_offset).map_err(|_| GeckoError::RandomSource)?;
        let message_id = self
            .next_message_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .to_le_bytes()[0];
        let chunk_size = packet.len() / usize::from(total_chunks);
        let mut output = Vec::with_capacity(usize::from(total_chunks));
        for chunk_index in 0..total_chunks {
            let start = usize::from(chunk_index) * chunk_size;
            let end = if chunk_index == total_chunks - 1 {
                packet.len()
            } else {
                start + chunk_size
            };
            let payload = &packet[start..end];
            let padding_len = self.random_padding_len(payload.len())?;
            let mut padding = vec![0; padding_len];
            fill_random(&mut padding)?;
            let frame = GeckoFrame {
                message_id,
                chunk_index,
                total_chunks,
                padding,
                payload: payload.to_vec(),
            };
            output.push(self.obfuscate(&frame.encode()?)?);
        }
        Ok(output)
    }

    /// Accepts one wire datagram and returns a complete QUIC packet when available.
    ///
    /// Malformed frames are returned as errors so a transport wrapper can silently drop them.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid Salamander or Gecko framing.
    pub fn receive_packet(
        &self,
        source: &str,
        wire_packet: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, GeckoError> {
        let cleartext = self.salamander.deobfuscate(wire_packet)?;
        if cleartext[0] & FRAGMENT_FLAG == 0 {
            return Ok(Some(cleartext));
        }
        let frame = GeckoFrame::decode(&cleartext)?;
        let mut reassembler = self
            .reassembler
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(reassembler.accept(source, frame, now))
    }

    /// Removes expired incomplete messages. The UDP wrapper should call this periodically.
    pub fn expire(&self, now: Instant) {
        self.reassembler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .expire(now);
    }

    #[cfg(test)]
    fn pending(&self) -> usize {
        self.reassembler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .len()
    }

    fn random_padding_len(&self, chunk_len: usize) -> Result<usize, GeckoError> {
        let base = SALT_LENGTH + HEADER_SIZE + chunk_len;
        let low = self.options.min_packet_size.max(base);
        if low > self.options.max_packet_size {
            return Ok(0);
        }
        let choices = self.options.max_packet_size - low + 1;
        Ok(low - base
            + usize::try_from(random_below(
                u32::try_from(choices).map_err(|_| GeckoError::RandomSource)?,
            )?)
            .map_err(|_| GeckoError::RandomSource)?)
    }

    fn obfuscate(&self, cleartext: &[u8]) -> Result<Vec<u8>, GeckoError> {
        let mut salt = [0; SALT_LENGTH];
        fill_random(&mut salt)?;
        Ok(self.salamander.obfuscate(cleartext, salt))
    }
}

fn validate_fragment(index: u8, total: u8) -> Result<(), GeckoError> {
    if !(MIN_FRAGMENT_COUNT..=MAX_FRAGMENT_COUNT).contains(&total) {
        return Err(GeckoError::InvalidFragmentCount(total));
    }
    if index >= total {
        return Err(GeckoError::InvalidChunkIndex { index, total });
    }
    Ok(())
}

fn fill_random(output: &mut [u8]) -> Result<(), GeckoError> {
    getrandom::fill(output).map_err(|_| GeckoError::RandomSource)
}

fn random_below(exclusive_max: u32) -> Result<u32, GeckoError> {
    if exclusive_max <= 1 {
        return Ok(0);
    }
    let mut bytes = [0; 4];
    fill_random(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes) % exclusive_max)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReassemblyKey {
    source: String,
    message_id: u8,
}

#[derive(Debug)]
struct ReassemblyEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    total: u8,
    deadline: Instant,
}

#[derive(Debug, Default)]
struct Reassembler {
    entries: HashMap<ReassemblyKey, ReassemblyEntry>,
    per_source: HashMap<String, usize>,
}

impl Reassembler {
    fn accept(&mut self, source: &str, frame: GeckoFrame, now: Instant) -> Option<Vec<u8>> {
        let key = ReassemblyKey {
            source: source.to_owned(),
            message_id: frame.message_id,
        };
        if let Some(entry) = self.entries.get(&key) {
            if entry.total != frame.total_chunks {
                return None;
            }
        } else {
            if self.per_source.get(source).copied().unwrap_or(0) >= MAX_REASSEMBLIES_PER_SOURCE {
                return None;
            }
            if self.entries.len() >= MAX_REASSEMBLIES {
                self.evict_oldest();
            }
            self.entries.insert(
                key.clone(),
                ReassemblyEntry {
                    chunks: vec![None; usize::from(frame.total_chunks)],
                    received: 0,
                    total: frame.total_chunks,
                    deadline: now + REASSEMBLY_TTL,
                },
            );
            *self.per_source.entry(source.to_owned()).or_default() += 1;
        }

        let entry = self.entries.get_mut(&key)?;
        let index = usize::from(frame.chunk_index);
        if entry.chunks.get(index)?.is_some() {
            return None;
        }
        entry.chunks[index] = Some(frame.payload);
        entry.received += 1;
        if entry.received < usize::from(entry.total) {
            return None;
        }
        let size = entry.chunks.iter().flatten().map(Vec::len).sum();
        let mut packet = Vec::with_capacity(size);
        for chunk in entry.chunks.iter().flatten() {
            packet.extend_from_slice(chunk);
        }
        self.drop_entry(&key);
        Some(packet)
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| now > entry.deadline)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.drop_entry(&key);
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.deadline)
            .map(|(key, _)| key.clone())
        {
            self.drop_entry(&key);
        }
    }

    fn drop_entry(&mut self, key: &ReassemblyKey) {
        if self.entries.remove(key).is_none() {
            return;
        }
        if let Some(count) = self.per_source.get_mut(&key.source) {
            *count -= 1;
            if *count == 0 {
                self.per_source.remove(&key.source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec() -> Gecko {
        Gecko::new(b"test", GeckoOptions::default()).unwrap()
    }

    #[test]
    fn frame_vector_matches_go_layout() {
        let frame = GeckoFrame {
            message_id: 0xa5,
            chunk_index: 1,
            total_chunks: 4,
            padding: vec![0xaa, 0xbb],
            payload: vec![0xa1, 0xb2, 0xc3, 0xd4],
        };
        let encoded = frame.encode().unwrap();
        assert_eq!(
            encoded,
            [0x80, 0xa5, 0x14, 0, 2, 0xaa, 0xbb, 0xa1, 0xb2, 0xc3, 0xd4]
        );
        assert_eq!(GeckoFrame::decode(&encoded).unwrap(), frame);
    }

    #[test]
    fn frame_rejects_go_malformed_vectors() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x80, 0x55, 0x22, 0],
            &[0, 0, 0x22, 0, 0],
            &[0x80, 0, 0, 0, 0],
            &[0x80, 0, 1, 0, 0],
            &[0x80, 0, 9, 0, 0],
            &[0x80, 0, 0x44, 0, 0],
            &[0x80, 0, 2, 0, 0x12, 1, 2],
        ];
        for input in cases {
            assert!(GeckoFrame::decode(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn short_header_round_trip_uses_one_datagram() {
        let gecko = codec();
        let mut packet = vec![0x40; 400];
        packet[10] = 7;
        let wire = gecko.encode_packet(&packet).unwrap();
        assert_eq!(wire.len(), 1);
        assert_eq!(wire[0].len(), packet.len() + SALT_LENGTH);
        assert_eq!(
            gecko
                .receive_packet("peer", &wire[0], Instant::now())
                .unwrap(),
            Some(packet)
        );
    }

    #[test]
    fn long_header_round_trip_reassembles_out_of_order() {
        let gecko = codec();
        let packet: Vec<u8> = std::iter::once(0xc0)
            .chain((1_u16..=1199).map(|value| value.to_le_bytes()[0]))
            .collect();
        let wire = gecko.encode_packet(&packet).unwrap();
        assert!(
            (usize::from(MIN_FRAGMENT_COUNT)..=usize::from(MAX_FRAGMENT_COUNT))
                .contains(&wire.len())
        );
        assert!(
            wire.iter()
                .all(|item| (DEFAULT_MIN_PACKET_SIZE..=DEFAULT_MAX_PACKET_SIZE)
                    .contains(&item.len()))
        );
        let now = Instant::now();
        let mut completed = None;
        for datagram in wire.iter().rev() {
            let result = gecko.receive_packet("peer", datagram, now).unwrap();
            if result.is_some() {
                completed = result;
            }
        }
        assert_eq!(completed, Some(packet));
        assert_eq!(gecko.pending(), 0);
    }

    #[test]
    fn supports_tiny_long_header_packets() {
        for size in [1, 2, 5, 10, 27, 64, 128] {
            let gecko = codec();
            let mut packet = vec![0; size];
            packet[0] = 0xc0;
            let wire = gecko.encode_packet(&packet).unwrap();
            let mut complete = None;
            for datagram in wire {
                complete = complete.or(gecko
                    .receive_packet("peer", &datagram, Instant::now())
                    .unwrap());
            }
            assert_eq!(complete, Some(packet));
        }
    }

    #[test]
    fn duplicate_and_expired_fragments_do_not_complete() {
        let gecko = codec();
        let packet = vec![0xc0; 900];
        let wire = gecko.encode_packet(&packet).unwrap();
        let now = Instant::now();
        assert!(
            gecko
                .receive_packet("peer", &wire[0], now)
                .unwrap()
                .is_none()
        );
        assert!(
            gecko
                .receive_packet("peer", &wire[0], now)
                .unwrap()
                .is_none()
        );
        assert_eq!(gecko.pending(), 1);
        gecko.expire(now + REASSEMBLY_TTL + Duration::from_millis(1));
        assert_eq!(gecko.pending(), 0);
        for datagram in &wire[1..] {
            assert!(
                gecko
                    .receive_packet("peer", datagram, now)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn enforces_per_source_reassembly_cap() {
        let gecko = codec();
        let now = Instant::now();
        let source_cap = u8::try_from(MAX_REASSEMBLIES_PER_SOURCE).unwrap();
        for message_id in 0..=source_cap {
            let frame = GeckoFrame {
                message_id,
                chunk_index: 0,
                total_chunks: 2,
                padding: Vec::new(),
                payload: vec![message_id],
            };
            let cleartext = frame.encode().unwrap();
            let wire = gecko
                .salamander
                .obfuscate(&cleartext, [message_id; SALT_LENGTH]);
            assert!(gecko.receive_packet("peer", &wire, now).unwrap().is_none());
        }
        assert_eq!(gecko.pending(), MAX_REASSEMBLIES_PER_SOURCE);
    }

    #[test]
    fn evicts_oldest_entry_at_global_cap() {
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        for index in 0..MAX_REASSEMBLIES {
            let source = format!("peer-{index}");
            assert!(
                reassembler
                    .accept(
                        &source,
                        GeckoFrame {
                            message_id: 1,
                            chunk_index: 0,
                            total_chunks: 2,
                            padding: Vec::new(),
                            payload: vec![1],
                        },
                        now + Duration::from_nanos(u64::try_from(index).unwrap()),
                    )
                    .is_none()
            );
        }
        assert_eq!(reassembler.entries.len(), MAX_REASSEMBLIES);

        assert!(
            reassembler
                .accept(
                    "new-peer",
                    GeckoFrame {
                        message_id: 2,
                        chunk_index: 0,
                        total_chunks: 2,
                        padding: Vec::new(),
                        payload: vec![2],
                    },
                    now + Duration::from_secs(1),
                )
                .is_none()
        );
        assert_eq!(reassembler.entries.len(), MAX_REASSEMBLIES);
        assert!(!reassembler.entries.contains_key(&ReassemblyKey {
            source: "peer-0".to_owned(),
            message_id: 1,
        }));
        assert!(reassembler.entries.contains_key(&ReassemblyKey {
            source: "new-peer".to_owned(),
            message_id: 2,
        }));
    }

    #[test]
    fn validates_options() {
        assert!(matches!(
            Gecko::new([], GeckoOptions::default()),
            Err(GeckoError::MissingPassword)
        ));
        assert!(matches!(
            Gecko::new(
                b"test",
                GeckoOptions {
                    min_packet_size: 1201,
                    max_packet_size: 1200
                }
            ),
            Err(GeckoError::InvalidPacketSizeRange)
        ));
        assert!(matches!(
            Gecko::new(
                b"test",
                GeckoOptions {
                    min_packet_size: 1,
                    max_packet_size: BUFFER_SIZE + 1
                }
            ),
            Err(GeckoError::InvalidPacketSizeRange)
        ));
    }
}
