//! This module represents the shared state of the h3 connection

use std::{
    borrow::Cow,
    sync::{atomic::AtomicBool, OnceLock},
};

use futures_util::task::AtomicWaker;

use crate::{config::Settings, error::internal_error::ErrorOrigin};

#[derive(Debug)]
/// This struct represents the shared state of the h3 connection and the stream structs
pub struct SharedState {
    /// The settings, sent by the peer
    settings: OnceLock<Settings>,
    /// Authenticated pre-control-stream limit. Does not consume the SETTINGS slot.
    pub(crate) alps_max_field_section_size: Option<u64>,
    /// The connection error
    connection_error: OnceLock<ErrorOrigin>,
    /// The connection is closing
    closing: AtomicBool,
    /// Waker for the connection
    waker: AtomicWaker,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            settings: OnceLock::new(),
            alps_max_field_section_size: None,
            connection_error: OnceLock::new(),
            closing: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }
}

impl ConnectionState for SharedState {
    fn shared_state(&self) -> &SharedState {
        self
    }
}

impl SharedState {
    pub(crate) fn alps_allows_settings(&self, settings: &Settings) -> bool {
        self.alps_max_field_section_size
            .map_or(true, |limit| settings.max_field_section_size >= limit)
    }
}

#[cfg(test)]
mod alps_tests {
    use super::*;
    use crate::proto::frame;

    #[test]
    fn control_settings_keep_raise_or_omit_early_limit() {
        for later in [Some(128), Some(256), None] {
            let mut state = SharedState::default();
            state.alps_max_field_section_size = Some(128);
            assert_eq!(state.settings().max_field_section_size, 128);
            assert!(state.settings.get().is_none());
            let mut frame = frame::Settings::default();
            if let Some(limit) = later {
                frame.insert(frame::SettingId::MAX_HEADER_LIST_SIZE, limit).unwrap();
            }
            let received: Settings = (&frame).into();
            assert!(state.alps_allows_settings(&received));
            state.set_settings(received);
            assert_eq!(state.settings().max_field_section_size,
                later.unwrap_or((1_u64 << 62) - 1));
            assert!(state.settings.get().is_some());
        }
    }

    #[test]
    fn reductions_fail_without_changing_early_state() {
        let mut state = SharedState::default();
        state.alps_max_field_section_size = Some(128);
        let mut received = Settings::default();
        received.max_field_section_size = 127;
        assert!(!state.alps_allows_settings(&received));
        assert_eq!(state.settings().max_field_section_size, 128);
        assert!(state.settings.get().is_none());
    }

    #[test]
    fn ordinary_settings_still_replace_defaults() {
        let state = SharedState::default();
        let mut received = Settings::default();
        received.max_field_section_size = 0;
        assert!(state.alps_allows_settings(&received));
        state.set_settings(received);
        assert_eq!(state.settings().max_field_section_size, 0);
    }
}

/// This trait can be implemented for all types which have a shared state
pub trait ConnectionState {
    /// Get the shared state
    fn shared_state(&self) -> &SharedState;
    /// Get the connection error if the connection is in error state because of another task
    ///
    /// Return the error as an Err variant if it is set in order to allow using ? in the calling function
    fn get_conn_error(&self) -> Option<ErrorOrigin> {
        self.shared_state().connection_error.get().cloned()
    }

    /// tries to set the connection error
    fn set_conn_error(&self, error: ErrorOrigin) -> ErrorOrigin {
        let err = self
            .shared_state()
            .connection_error
            .get_or_init(move || error);
        err.clone()
    }

    /// set the connection error and wake the connection
    fn set_conn_error_and_wake<T: Into<ErrorOrigin>>(&self, error: T) -> ErrorOrigin {
        let err = self.set_conn_error(error.into());
        self.waker().wake();
        err
    }

    /// Get the settings
    fn settings(&self) -> Cow<Settings> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# Each endpoint SHOULD use
        //# these initial values to send messages before the peer's SETTINGS
        //# frame has arrived, as packets carrying the settings can be lost or
        //# delayed.
        self.shared_state()
            .settings
            .get()
            .map(|s| Cow::Borrowed(s))
            .unwrap_or_else(|| {
                let mut settings = Settings::default();
                if let Some(limit) = self.shared_state().alps_max_field_section_size {
                    settings.max_field_section_size = limit;
                }
                Cow::Owned(settings)
            })
    }
    /// Set the connection to closing
    fn set_closing(&self) {
        self.shared_state()
            .closing
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// Check if the connection is closing
    fn is_closing(&self) -> bool {
        self.shared_state()
            .closing
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Set the settings
    fn set_settings(&self, settings: Settings) {
        let _ = self.shared_state().settings.set(settings);
    }

    /// Returns the waker for the connection
    fn waker(&self) -> &AtomicWaker {
        &self.shared_state().waker
    }
}
