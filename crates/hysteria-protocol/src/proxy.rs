use crate::{ProtocolError, decode_varint, encode_varint, varint_len};

pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
pub const MAX_ADDRESS_LENGTH: usize = 2048;
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;
pub const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;
pub const MAX_UDP_SIZE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRequest {
    pub address: String,
}

impl TcpRequest {
    /// Encodes the complete request, including the `0x401` stream frame type.
    ///
    /// # Errors
    ///
    /// Returns an error if the address or padding exceeds protocol limits.
    pub fn encode(&self, padding: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        check_write_lengths(self.address.len(), padding.len(), 0)?;
        let mut output = Vec::with_capacity(
            varint_len(FRAME_TYPE_TCP_REQUEST)
                + varint_len(self.address.len() as u64)
                + self.address.len()
                + varint_len(padding.len() as u64)
                + padding.len(),
        );
        encode_varint(FRAME_TYPE_TCP_REQUEST, &mut output)?;
        encode_varint(self.address.len() as u64, &mut output)?;
        output.extend_from_slice(self.address.as_bytes());
        encode_varint(padding.len() as u64, &mut output)?;
        output.extend_from_slice(padding);
        Ok(output)
    }

    /// Decodes a complete request and leaves stream payload bytes untouched.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong frame type, truncated input, or invalid lengths.
    pub fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let frame_type = decode_varint(input)?;
        if frame_type != FRAME_TYPE_TCP_REQUEST {
            return Err(ProtocolError::InvalidFrameType(frame_type));
        }
        Self::decode_body(input)
    }

    /// Decodes the request after a QUIC stream dispatcher has consumed its frame type.
    ///
    /// # Errors
    ///
    /// Returns an error for truncated input or invalid address and padding lengths.
    pub fn decode_body(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let address_len = decode_varint(input)?;
        if address_len == 0 || address_len > MAX_ADDRESS_LENGTH as u64 {
            return Err(ProtocolError::InvalidAddressLength(address_len));
        }
        let address_len = usize::try_from(address_len)
            .map_err(|_| ProtocolError::InvalidAddressLength(address_len))?;
        let address_bytes = take(input, address_len)?;
        let padding_len = decode_varint(input)?;
        if padding_len > MAX_PADDING_LENGTH as u64 {
            return Err(ProtocolError::InvalidPaddingLength(padding_len));
        }
        let padding_len = usize::try_from(padding_len)
            .map_err(|_| ProtocolError::InvalidPaddingLength(padding_len))?;
        take(input, padding_len)?;
        let address = String::from_utf8_lossy(address_bytes).into_owned();
        Ok(Self { address })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    pub ok: bool,
    pub message: String,
}

impl TcpResponse {
    /// Encodes the response followed by caller-provided random padding.
    ///
    /// # Errors
    ///
    /// Returns an error if the message or padding exceeds protocol limits.
    pub fn encode(&self, padding: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        check_write_lengths(0, padding.len(), self.message.len())?;
        let mut output = Vec::with_capacity(
            1 + varint_len(self.message.len() as u64)
                + self.message.len()
                + varint_len(padding.len() as u64)
                + padding.len(),
        );
        output.push(u8::from(!self.ok));
        encode_varint(self.message.len() as u64, &mut output)?;
        output.extend_from_slice(self.message.as_bytes());
        encode_varint(padding.len() as u64, &mut output)?;
        output.extend_from_slice(padding);
        Ok(output)
    }

    /// Decodes a response and leaves proxied stream bytes untouched.
    ///
    /// # Errors
    ///
    /// Returns an error for truncated input or invalid message and padding lengths.
    pub fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let status = take(input, 1)?[0];
        let message_len = decode_varint(input)?;
        if message_len > MAX_MESSAGE_LENGTH as u64 {
            return Err(ProtocolError::InvalidMessageLength(message_len));
        }
        let message_len = usize::try_from(message_len)
            .map_err(|_| ProtocolError::InvalidMessageLength(message_len))?;
        let message_bytes = take(input, message_len)?;
        let padding_len = decode_varint(input)?;
        if padding_len > MAX_PADDING_LENGTH as u64 {
            return Err(ProtocolError::InvalidPaddingLength(padding_len));
        }
        let padding_len = usize::try_from(padding_len)
            .map_err(|_| ProtocolError::InvalidPaddingLength(padding_len))?;
        take(input, padding_len)?;
        Ok(Self {
            ok: status == 0,
            message: String::from_utf8_lossy(message_bytes).into_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: String,
    pub data: Vec<u8>,
}

impl UdpMessage {
    #[must_use]
    pub fn header_size(&self) -> usize {
        8 + varint_len(self.address.len() as u64) + self.address.len()
    }

    #[must_use]
    pub fn encoded_size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    /// Encodes this message as a Hysteria QUIC datagram payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is longer than the protocol limit.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.address.len() > MAX_MESSAGE_LENGTH {
            return Err(ProtocolError::InvalidAddressLength(
                self.address.len() as u64
            ));
        }
        let mut output = Vec::with_capacity(self.encoded_size());
        output.extend_from_slice(&self.session_id.to_be_bytes());
        output.extend_from_slice(&self.packet_id.to_be_bytes());
        output.push(self.fragment_id);
        output.push(self.fragment_count);
        encode_varint(self.address.len() as u64, &mut output)?;
        output.extend_from_slice(self.address.as_bytes());
        output.extend_from_slice(&self.data);
        Ok(output)
    }

    /// Decodes one complete Hysteria QUIC datagram payload.
    ///
    /// # Errors
    ///
    /// Returns an error for truncated input, invalid address length, or empty payload.
    pub fn decode(mut input: &[u8]) -> Result<Self, ProtocolError> {
        let fixed = take(&mut input, 8)?;
        let session_id = u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
        let packet_id = u16::from_be_bytes([fixed[4], fixed[5]]);
        let fragment_id = fixed[6];
        let fragment_count = fixed[7];
        let address_len = decode_varint(&mut input)?;
        if address_len == 0 || address_len > MAX_MESSAGE_LENGTH as u64 {
            return Err(ProtocolError::InvalidAddressLength(address_len));
        }
        // The Go implementation requires at least one payload byte.
        let address_len = usize::try_from(address_len)
            .map_err(|_| ProtocolError::InvalidAddressLength(address_len))?;
        if input.len() <= address_len {
            return Err(ProtocolError::InvalidMessageLength(input.len() as u64));
        }
        let address_bytes = take(&mut input, address_len)?;
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address: String::from_utf8_lossy(address_bytes).into_owned(),
            data: input.to_vec(),
        })
    }
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], ProtocolError> {
    if input.len() < len {
        return Err(ProtocolError::UnexpectedEnd);
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

fn check_write_lengths(
    address: usize,
    padding: usize,
    message: usize,
) -> Result<(), ProtocolError> {
    if address > MAX_ADDRESS_LENGTH {
        return Err(ProtocolError::InvalidAddressLength(address as u64));
    }
    if padding > MAX_PADDING_LENGTH {
        return Err(ProtocolError::InvalidPaddingLength(padding as u64));
    }
    if message > MAX_MESSAGE_LENGTH {
        return Err(ProtocolError::InvalidMessageLength(message as u64));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_request_matches_go_vector_and_preserves_payload() {
        let request = TcpRequest {
            address: "google.com:443".into(),
        };
        let encoded = request.encode(b"gg").unwrap();
        assert_eq!(&encoded[..17], b"\x44\x01\x0egoogle.com:443");
        let mut stream = [encoded, b"payload".to_vec()].concat();
        let mut input = stream.as_slice();
        assert_eq!(TcpRequest::decode(&mut input).unwrap(), request);
        assert_eq!(input, b"payload");
        stream[0] = 0;
        assert_eq!(
            TcpRequest::decode(&mut stream.as_slice()),
            Err(ProtocolError::InvalidFrameType(0))
        );
    }

    #[test]
    fn tcp_body_and_response_match_go_vectors() {
        let mut body = &b"\x0bholy.cc:443\x02gg"[..];
        assert_eq!(
            TcpRequest::decode_body(&mut body).unwrap().address,
            "holy.cc:443"
        );
        let response = TcpResponse {
            ok: false,
            message: "stop!!".into(),
        };
        assert_eq!(
            response.encode(b"xxxxx").unwrap(),
            b"\x01\x06stop!!\x05xxxxx"
        );
        let mut encoded = response.encode(b"xxxxx").unwrap();
        encoded.extend_from_slice(b"proxied bytes");
        let mut input = encoded.as_slice();
        assert_eq!(TcpResponse::decode(&mut input).unwrap(), response);
        assert_eq!(input, b"proxied bytes");
    }

    #[test]
    fn rejects_malformed_tcp_messages() {
        assert_eq!(
            TcpRequest::decode_body(&mut &b"\0\0"[..]),
            Err(ProtocolError::InvalidAddressLength(0))
        );
        assert_eq!(
            TcpRequest::decode_body(&mut &b"\x0bhoho"[..]),
            Err(ProtocolError::UnexpectedEnd)
        );
        assert_eq!(
            TcpResponse::decode(&mut &b"\x01\x05jesus\x05x"[..]),
            Err(ProtocolError::UnexpectedEnd)
        );
    }

    #[test]
    fn udp_message_matches_go_vector() {
        let message = UdpMessage {
            session_id: 1,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 1,
            address: "example.com:80".into(),
            data: b"GET /nothing HTTP/1.1\r\n".to_vec(),
        };
        let expected = b"\0\0\0\x01\0\x01\0\x01\x0eexample.com:80GET /nothing HTTP/1.1\r\n";
        assert_eq!(message.encode().unwrap(), expected);
        assert_eq!(UdpMessage::decode(expected).unwrap(), message);
    }

    #[test]
    fn rejects_malformed_udp_messages() {
        for data in [&b""[..], &b"\0\0\0\0"[..], &b"\0\0\0\0\0\0\0\0\0\0"[..]] {
            assert!(UdpMessage::decode(data).is_err());
        }
    }
}
