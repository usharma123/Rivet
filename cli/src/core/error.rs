//! Stable failures for CLI consumers. Classification follows types, not message text.
use std::fmt;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
    pub suggestion: &'static str,
    #[serde(skip)]
    pub exit_code: i32,
}

impl Failure {
    pub fn new(code: &'static str, message: impl Into<String>, suggestion: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
            suggestion,
            exit_code: 1,
        }
    }

    pub fn retry(mut self) -> Self {
        self.retryable = true;
        self
    }

    pub fn from_error(error: &anyhow::Error) -> Self {
        let mut failure = if let Some(failure) = error.downcast_ref::<Self>() {
            failure.clone()
        } else if error.downcast_ref::<super::policy::Refusal>().is_some() {
            Self::new(
                "POLICY_REFUSED",
                "",
                "Inspect the release and project policy; do not automatically bypass the refusal.",
            )
        } else if let Some(request) = error.downcast_ref::<reqwest::Error>() {
            if let Some(status) = request.status() {
                Self::http(status, request.to_string())
            } else if request.is_connect() || request.is_timeout() {
                Self::new(
                    "REGISTRY_UNAVAILABLE",
                    "",
                    "Check registry connectivity and retry with backoff.",
                )
                .retry()
            } else {
                Self::new(
                    "REGISTRY_REQUEST_FAILED",
                    "",
                    "Check registry configuration and response.",
                )
            }
        } else if error.downcast_ref::<std::io::Error>().is_some() {
            Self::new(
                "IO_ERROR",
                "",
                "Check the referenced path, permissions, and available disk space.",
            )
        } else {
            Self::new(
                "OPERATION_FAILED",
                "",
                "Inspect the error; automatic retries or permission changes are not recommended.",
            )
        };
        failure.message = format!("{error:#}");
        failure
    }

    pub fn http(status: reqwest::StatusCode, message: String) -> Self {
        let (code, suggestion) = match status.as_u16() {
            401 | 403 => (
                "AUTH_REQUIRED",
                "Check your registry token and permissions.",
            ),
            404 => (
                "PACKAGE_NOT_FOUND",
                "Check the package name, version, and registry.",
            ),
            409 => (
                "REGISTRY_CONFLICT",
                "Refresh registry state and inspect the conflicting operation.",
            ),
            422 => (
                "POLICY_REFUSED",
                "Inspect the requested release and project policy.",
            ),
            429 => (
                "REGISTRY_BUSY",
                "Retry with backoff; reduce concurrent requests.",
            ),
            500..=599 => (
                "REGISTRY_UNAVAILABLE",
                "Retry with backoff; check registry health.",
            ),
            _ => (
                "REGISTRY_REQUEST_FAILED",
                "Check the request and registry configuration.",
            ),
        };
        let mut failure = Self::new(
            code,
            format!("registry request failed ({status}): {message}"),
            suggestion,
        );
        failure.retryable = status.as_u16() == 429 || status.is_server_error();
        failure
    }

    pub fn registry(status: reqwest::StatusCode, value: &serde_json::Value) -> Self {
        let message = value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("registry rejected request")
            .to_string();
        let mut failure = Self::http(status, message);
        match value.get("code").and_then(serde_json::Value::as_str) {
            Some("POLICY_REFUSED") => {
                failure.code = "POLICY_REFUSED";
                failure.retryable = false;
                failure.suggestion = "Inspect the requested release and project policy; do not automatically bypass it.";
            }
            Some("INTEGRITY_FAILED") => {
                failure.code = "INTEGRITY_FAILED";
                failure.retryable = false;
                failure.suggestion = "Investigate the artifact mismatch before retrying.";
            }
            Some("INVALID_REQUEST") => {
                failure.code = "INVALID_REQUEST";
                failure.retryable = false;
            }
            _ => {}
        }
        failure
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Failure {}
