use std::error::Error as StdError;

use reqwest::StatusCode;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum RequestError<E>
where
    E: StdError + Send + Sync + 'static,
{
    #[error("failed to build endpoint URL")]
    Url(#[from] url::ParseError),

    #[error("failed to send request")]
    SendRequest(#[source] reqwest::Error),

    #[error("failed to read response body")]
    ReadResponseBody(#[source] reqwest::Error),

    #[error("endpoint returned unexpected status {status}")]
    UnexpectedStatus { status: StatusCode, body: String },

    #[error("failed to parse successful response")]
    ParseSuccessJson(#[source] serde_json::Error),

    #[error("API response was invalid")]
    InvalidResponse(#[source] E),
}
