/// HTTP authority used by the Hysteria authentication request.
pub const AUTH_HOST: &str = "hysteria";
pub const AUTH_PATH: &str = "/auth";
pub const AUTH_STATUS_OK: u16 = 233;
pub const HEADER_AUTH: &str = "Hysteria-Auth";
pub const HEADER_UDP_ENABLED: &str = "Hysteria-UDP";
pub const HEADER_CC_RX: &str = "Hysteria-CC-RX";
pub const HEADER_PADDING: &str = "Hysteria-Padding";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub auth: String,
    /// Maximum receive rate in bytes per second; zero means unknown.
    pub rx: u64,
}

impl AuthRequest {
    /// Matches the Go implementation: absent or malformed bandwidth becomes zero.
    #[must_use]
    pub fn from_header_values(auth: Option<&str>, rx: Option<&str>) -> Self {
        Self {
            auth: auth.unwrap_or_default().to_owned(),
            rx: rx
                .and_then(|value| value.strip_prefix('+').unwrap_or(value).parse().ok())
                .unwrap_or(0),
        }
    }

    #[must_use]
    pub fn header_values(&self) -> [(&'static str, String); 2] {
        [
            (HEADER_AUTH, self.auth.clone()),
            (HEADER_CC_RX, self.rx.to_string()),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthResponse {
    pub udp_enabled: bool,
    /// Maximum receive rate; zero means unlimited.
    pub rx: u64,
    /// Ask the peer to select a congestion controller automatically.
    pub rx_auto: bool,
}

impl AuthResponse {
    /// Matches Go's `strconv` behavior for the accepted protocol header values.
    #[must_use]
    pub fn from_header_values(udp_enabled: Option<&str>, rx: Option<&str>) -> Self {
        let rx_value = rx.unwrap_or_default();
        Self {
            udp_enabled: udp_enabled.and_then(parse_go_bool).unwrap_or(false),
            rx: if rx_value == "auto" {
                0
            } else {
                rx_value.parse().unwrap_or(0)
            },
            rx_auto: rx_value == "auto",
        }
    }

    #[must_use]
    pub fn header_values(self) -> [(&'static str, String); 2] {
        [
            (HEADER_UDP_ENABLED, self.udp_enabled.to_string()),
            (
                HEADER_CC_RX,
                if self.rx_auto {
                    "auto".to_owned()
                } else {
                    self.rx.to_string()
                },
            ),
        ]
    }
}

fn parse_go_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_values_match_go_semantics() {
        assert_eq!(
            AuthRequest::from_header_values(Some("secret"), Some("1000")),
            AuthRequest {
                auth: "secret".into(),
                rx: 1000
            }
        );
        assert_eq!(AuthRequest::from_header_values(None, Some("oops")).rx, 0);
        assert_eq!(AuthRequest::from_header_values(None, Some("+42")).rx, 42);
        assert_eq!(
            AuthResponse::from_header_values(Some("true"), Some("auto")),
            AuthResponse {
                udp_enabled: true,
                rx: 0,
                rx_auto: true
            }
        );
        assert_eq!(
            AuthResponse {
                udp_enabled: false,
                rx: 42,
                rx_auto: false
            }
            .header_values()[1]
                .1,
            "42"
        );
        assert!(AuthResponse::from_header_values(Some("TRUE"), Some("0")).udp_enabled);
        assert!(AuthResponse::from_header_values(Some("1"), Some("0")).udp_enabled);
    }
}
