use std::{error::Error, fmt};

/// Stable CLI categories. Classify at the operation boundary, never by matching messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    RuntimeFailure,
    TunParent,
    TunDevice,
    TunIdentity,
    TunRoutes,
    TunRouteInspection,
    TunAddressConflict,
    CaptureConflict,
    ListenerBind,
    TlsRead,
    TlsInvalid,
    ConnectionFailed,
    AuthenticationRejected,
    ConfigurationRead,
    ConfigurationParse,
    ConfigurationTooLarge,
    ConfigurationInvalid,
}

impl ErrorCode {
    /// Stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeFailure => "runtime_failure",
            Self::TunParent => "tun_parent",
            Self::TunDevice => "tun_device",
            Self::TunIdentity => "tun_identity",
            Self::TunRoutes => "tun_routes",
            Self::TunRouteInspection => "tun_route_inspection",
            Self::TunAddressConflict => "tun_address_conflict",
            Self::CaptureConflict => "capture_conflict",
            Self::ListenerBind => "listener_bind",
            Self::TlsRead => "tls_read",
            Self::TlsInvalid => "tls_invalid",
            Self::ConnectionFailed => "connection_failed",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::ConfigurationRead => "configuration_read",
            Self::ConfigurationParse => "configuration_parse",
            Self::ConfigurationTooLarge => "configuration_too_large",
            Self::ConfigurationInvalid => "configuration_invalid",
        }
    }
}

/// User-facing context with an optional typed cause and an actionable suggestion.
#[derive(Debug)]
pub struct CliError {
    code: ErrorCode,
    message: String,
    hint: Option<&'static str>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl CliError {
    /// Compatibility constructor for errors not yet classified at their boundary.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self::classified(ErrorCode::RuntimeFailure, message, None)
    }

    /// Creates an error without embedding its cause in the display message.
    #[must_use]
    pub fn classified(
        code: ErrorCode,
        message: impl Into<String>,
        hint: Option<&'static str>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            hint,
            source: None,
        }
    }

    /// Adds an operation boundary only when the underlying error has no specific category.
    pub(crate) fn at_stage(mut self, code: ErrorCode) -> Self {
        if self.code == ErrorCode::RuntimeFailure {
            self.code = code;
        }
        self
    }

    /// Attaches a cause approved for diagnostic output. Never attach raw config parse errors.
    #[must_use]
    pub fn with_source(mut self, source: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Classifies a failed bind using the operating system's typed error kind.
    pub(crate) fn bind(listener: &str, error: std::io::Error) -> Self {
        let hint = match error.kind() {
            std::io::ErrorKind::AddrInUse => {
                "The address/port is already in use; stop the conflicting listener or choose another port."
            }
            std::io::ErrorKind::PermissionDenied => {
                "Check permission to bind this address/port; consider an unprivileged port."
            }
            std::io::ErrorKind::AddrNotAvailable => {
                "Choose an address assigned to this machine, or a wildcard listen address."
            }
            _ => "Check the listen address, port and local socket support.",
        };
        Self::classified(
            ErrorCode::ListenerBind,
            format!("failed to bind {listener}"),
            Some(hint),
        )
        .with_source(error)
    }

    /// Classifies only facts available from the transport API, without inspecting strings.
    pub(crate) fn connection(error: hysteria_transport::TransportError) -> Self {
        if let hysteria_transport::TransportError::AuthenticationFailed(status) = error {
            return Self::classified(ErrorCode::AuthenticationRejected,
                format!("server rejected the authentication request (HTTP {status})"),
                Some("Check the server address, credentials and server authentication policy; an unexpected HTTP endpoint can also reject the request."))
                .with_source(error);
        }
        // Transport strings may contain untrusted peer text. Keep them out of reports
        // until transport provides structured, reviewed cause types.
        Self::classified(
            ErrorCode::ConnectionFailed,
            "failed to establish the Hysteria connection",
            Some(
                "Check server reachability, UDP access, TLS name/trust and server logs. A failed connection alone does not identify the cause.",
            ),
        )
    }

    /// Classifies legacy semantic-validator errors without discarding existing context.
    #[must_use]
    pub fn configuration(mut self) -> Self {
        if self.code == ErrorCode::RuntimeFailure {
            self.code = ErrorCode::ConfigurationInvalid;
            self.hint = Some("Correct the reported configuration field and run check again.");
        }
        self
    }

    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    #[must_use]
    pub const fn hint(&self) -> Option<&'static str> {
        self.hint
    }

    /// Returns a bounded cause chain for explicit diagnostic output.
    #[must_use]
    pub fn causes(&self) -> Vec<String> {
        let mut causes = Vec::new();
        let mut source = self.source();
        while let Some(error) = source {
            if causes.len() == 8 {
                break;
            }
            causes.push(error.to_string());
            source = error.source();
        }
        causes
    }

    /// Formats user guidance, optionally including approved underlying causes.
    #[must_use]
    pub fn report(&self, diagnostic: bool) -> String {
        let mut text = format!("error: {} [{}]", self, self.code.as_str());
        if let Some(hint) = self.hint {
            text.push_str("\n  hint: ");
            text.push_str(hint);
        }
        if diagnostic {
            for cause in self.causes() {
                text.push_str("\n  caused by: ");
                text.push_str(&cause);
            }
        }
        text
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|error| error as &(dyn Error + 'static))
    }
}

// Preserve legacy rendering until each runtime operation supplies explicit context.
impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}
impl From<hysteria_transport::TransportError> for CliError {
    fn from(error: hysteria_transport::TransportError) -> Self {
        Self::new(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_errors_preserve_sources_and_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CliError>();
        let error = CliError::classified(
            ErrorCode::ConfigurationRead,
            "failed to read config.yaml",
            Some("Check the path."),
        )
        .with_source(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(
            error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .is_some()
        );
        assert_eq!(error.to_string(), "failed to read config.yaml");
        assert!(!error.report(false).contains("caused by:"));
        assert!(error.report(true).contains("caused by:"));
        assert_eq!(error.configuration().code(), ErrorCode::ConfigurationRead);
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;

    #[test]
    fn connection_classification_does_not_guess_or_echo_peer_text() {
        let rejected = CliError::connection(
            hysteria_transport::TransportError::AuthenticationFailed(403),
        );
        assert_eq!(rejected.code(), ErrorCode::AuthenticationRejected);
        assert!(rejected.source().is_some());
        let unknown = CliError::connection(hysteria_transport::TransportError::Connect(
            "private-secret timed out".into(),
        ));
        assert_eq!(unknown.code(), ErrorCode::ConnectionFailed);
        assert!(!unknown.report(true).contains("private-secret"));
        assert!(
            unknown
                .hint()
                .unwrap()
                .contains("does not identify the cause")
        );
    }

    #[test]
    fn bind_hints_follow_io_kinds() {
        for (kind, hint) in [
            (std::io::ErrorKind::AddrInUse, "already in use"),
            (std::io::ErrorKind::PermissionDenied, "permission"),
            (
                std::io::ErrorKind::AddrNotAvailable,
                "assigned to this machine",
            ),
        ] {
            let error = CliError::bind("test listener", kind.into());
            assert_eq!(error.code(), ErrorCode::ListenerBind);
            assert!(error.hint().unwrap().contains(hint));
            assert!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .is_some()
            );
        }
    }
    #[test]
    fn stage_classification_preserves_specific_errors() {
        assert_eq!(
            CliError::new("failure")
                .at_stage(ErrorCode::TunDevice)
                .code(),
            ErrorCode::TunDevice
        );
        assert_eq!(
            CliError::classified(ErrorCode::CaptureConflict, "conflict", None)
                .at_stage(ErrorCode::TunRoutes)
                .code(),
            ErrorCode::CaptureConflict
        );
    }
}
