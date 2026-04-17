//! Base orchestrator for the host-mediated composition experiment.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use thiserror::Error;

/// Result type for switchboard operations.
pub type SwitchboardResult<T> = Result<T, SwitchboardError>;

/// Errors returned by the switchboard orchestrator.
#[derive(Debug, Clone, PartialEq, Eq, Error, uniffi::Error)]
pub enum SwitchboardError {
    /// Processor names must be non-empty.
    #[error("processor name must not be empty")]
    InvalidProcessorName,
    /// Registering a duplicate processor name is rejected.
    #[error("processor `{name}` is already registered")]
    ProcessorAlreadyRegistered {
        /// Duplicate processor name.
        name: String,
    },
    /// A requested processor name was not registered.
    #[error("processor `{name}` was not found")]
    ProcessorNotFound {
        /// Missing processor name.
        name: String,
    },
    /// Unexpected callback errors from UniFFI are surfaced explicitly.
    #[error("unexpected UniFFI callback error: {reason}")]
    UnexpectedUniFFICallback {
        /// Reason reported by UniFFI.
        reason: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for SwitchboardError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallback {
            reason: error.reason,
        }
    }
}

/// Host-provided driver interface used by the switchboard.
#[uniffi::export(with_foreign)]
pub trait ProcessorDriver: Send + Sync {
    /// Processes a JSON request and returns a JSON response.
    fn process(&self, request_json: String) -> SwitchboardResult<String>;
}

/// Registry and dispatcher for named processors.
#[derive(uniffi::Object)]
pub struct Switchboard {
    registry: RwLock<HashMap<String, Arc<dyn ProcessorDriver>>>,
}

impl Default for Switchboard {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl Switchboard {
    /// Creates an empty switchboard.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            registry: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a named processor implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is blank or already registered.
    pub fn register_processor(
        &self,
        name: String,
        processor: Arc<dyn ProcessorDriver>,
    ) -> SwitchboardResult<()> {
        let normalized_name = normalize_name(name)?;
        let mut registry = self
            .registry
            .write()
            .expect("switchboard registry lock should not be poisoned");

        if registry.contains_key(&normalized_name) {
            return Err(SwitchboardError::ProcessorAlreadyRegistered {
                name: normalized_name,
            });
        }

        registry.insert(normalized_name, processor);
        Ok(())
    }

    /// Returns all registered processor names in sorted order.
    pub fn available_processors(&self) -> Vec<String> {
        let mut processors = self
            .registry
            .read()
            .expect("switchboard registry lock should not be poisoned")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        processors.sort();
        processors
    }

    /// Dispatches a JSON request to the selected processor.
    ///
    /// # Errors
    ///
    /// Returns an error if the processor is unknown or its callback fails.
    pub fn process_with(
        &self,
        name: String,
        request_json: String,
    ) -> SwitchboardResult<String> {
        let normalized_name = normalize_name(name)?;
        let processor = self
            .registry
            .read()
            .expect("switchboard registry lock should not be poisoned")
            .get(&normalized_name)
            .cloned()
            .ok_or(SwitchboardError::ProcessorNotFound {
                name: normalized_name,
            })?;

        processor.process(request_json)
    }
}

fn normalize_name(name: String) -> SwitchboardResult<String> {
    let normalized_name = name.trim().to_string();
    if normalized_name.is_empty() {
        return Err(SwitchboardError::InvalidProcessorName);
    }

    Ok(normalized_name)
}

uniffi::setup_scaffolding!("switchboard");

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{ProcessorDriver, Switchboard, SwitchboardError, SwitchboardResult};

    struct FakeDriver {
        prefix: &'static str,
    }

    impl ProcessorDriver for FakeDriver {
        fn process(&self, request_json: String) -> SwitchboardResult<String> {
            Ok(format!("{}:{request_json}", self.prefix))
        }
    }

    #[test]
    fn registers_and_dispatches_to_named_processors() {
        let board = Switchboard::new();
        board
            .register_processor(
                "shouty".to_string(),
                Arc::new(FakeDriver { prefix: "a" }),
            )
            .expect("register shouty");
        board
            .register_processor(
                "mirror".to_string(),
                Arc::new(FakeDriver { prefix: "b" }),
            )
            .expect("register mirror");

        assert_eq!(
            board.available_processors(),
            vec!["mirror".to_string(), "shouty".to_string()]
        );
        assert_eq!(
            board
                .process_with("shouty".to_string(), "payload".to_string())
                .expect("dispatch shouty"),
            "a:payload"
        );
        assert_eq!(
            board
                .process_with("mirror".to_string(), "payload".to_string())
                .expect("dispatch mirror"),
            "b:payload"
        );
    }

    #[test]
    fn rejects_duplicate_registration() {
        let board = Switchboard::new();
        board
            .register_processor(
                "shouty".to_string(),
                Arc::new(FakeDriver { prefix: "a" }),
            )
            .expect("first registration should succeed");

        let error = board
            .register_processor(
                "shouty".to_string(),
                Arc::new(FakeDriver { prefix: "b" }),
            )
            .expect_err("duplicate registration should fail");

        assert_eq!(
            error,
            SwitchboardError::ProcessorAlreadyRegistered {
                name: "shouty".to_string(),
            }
        );
    }

    #[test]
    fn rejects_unknown_processors() {
        let board = Switchboard::new();
        let error = board
            .process_with("missing".to_string(), "payload".to_string())
            .expect_err("unknown processor should fail");

        assert_eq!(
            error,
            SwitchboardError::ProcessorNotFound {
                name: "missing".to_string(),
            }
        );
    }
}
