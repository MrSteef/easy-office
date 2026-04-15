use crate::{
    auth::models::{
        DeviceCodeStartConversionError, TokenSetConversionError, UnexpectedDeviceCodePollError,
    },
    error::RequestError,
};
use reqwest::StatusCode;
use thiserror::Error as ThisError;

pub type StartDeviceCodeError = RequestError<DeviceCodeStartConversionError>;

#[derive(Debug, ThisError)]
pub enum RedeemDeviceCodeError {
    #[error("failed to build token endpoint URL")]
    Url(#[from] url::ParseError),

    #[error("failed to send device code token request")]
    SendRequest(#[source] reqwest::Error),

    #[error("failed to read device code token response body")]
    ReadResponseBody(#[source] reqwest::Error),

    #[error("token endpoint returned unexpected status {status}")]
    UnexpectedStatus { status: StatusCode, body: String },

    #[error("failed to parse successful token response")]
    ParseSuccessJson(#[source] serde_json::Error),

    #[error("successful token response was invalid")]
    InvalidSuccessResponse(#[from] TokenSetConversionError),

    #[error("failed to parse error response")]
    ParseErrorJson(#[source] serde_json::Error),

    #[error("token endpoint returned OAuth error {error}")]
    OAuthError {
        status: StatusCode,
        error: String,
        description: Option<String>,
        body: String,
    },

    #[error("device code poll error response was invalid")]
    InvalidPollResponse(#[from] UnexpectedDeviceCodePollError),
}

#[derive(Debug, ThisError)]
pub enum RefreshTokenError {
    #[error("failed to build token endpoint URL")]
    Url(#[from] url::ParseError),

    #[error("failed to send refresh token request")]
    SendRequest(#[source] reqwest::Error),

    #[error("failed to read refresh token response body")]
    ReadResponseBody(#[source] reqwest::Error),

    #[error("token endpoint returned unexpected status {status}")]
    UnexpectedStatus { status: StatusCode, body: String },

    #[error("failed to parse successful token response")]
    ParseSuccessJson(#[source] serde_json::Error),

    #[error("successful token response was invalid")]
    InvalidResponse(#[from] TokenSetConversionError),

    #[error("failed to parse error response")]
    ParseErrorJson(#[source] serde_json::Error),

    #[error("token endpoint returned OAuth error {error}")]
    OAuthError {
        status: StatusCode,
        error: String,
        description: Option<String>,
        body: String,
    },
}

#[derive(Debug, ThisError)]
pub(crate) enum PostFormError {
    #[error("failed to send request")]
    Send(#[source] reqwest::Error),

    #[error("failed to read response body")]
    Read(#[source] reqwest::Error),
}

#[derive(Debug, ThisError)]
pub(crate) enum TokenEndpointRequestError {
    #[error("failed to build token endpoint URL")]
    Url(#[from] url::ParseError),

    #[error("failed to send token request")]
    Send(#[source] reqwest::Error),

    #[error("failed to read token response body")]
    Read(#[source] reqwest::Error),

    #[error("token endpoint returned unexpected status {status}")]
    UnexpectedStatus { status: StatusCode, body: String },

    #[error("failed to parse successful token response")]
    ParseSuccessJson(#[source] serde_json::Error),

    #[error("failed to parse error response")]
    ParseErrorJson(#[source] serde_json::Error),
}

impl From<PostFormError> for StartDeviceCodeError {
    fn from(value: PostFormError) -> Self {
        match value {
            PostFormError::Send(source) => Self::SendRequest(source),
            PostFormError::Read(source) => Self::ReadResponseBody(source),
        }
    }
}

impl From<PostFormError> for TokenEndpointRequestError {
    fn from(value: PostFormError) -> Self {
        match value {
            PostFormError::Send(source) => Self::Send(source),
            PostFormError::Read(source) => Self::Read(source),
        }
    }
}

impl From<TokenEndpointRequestError> for RedeemDeviceCodeError {
    fn from(value: TokenEndpointRequestError) -> Self {
        match value {
            TokenEndpointRequestError::Url(source) => Self::Url(source),
            TokenEndpointRequestError::Send(source) => Self::SendRequest(source),
            TokenEndpointRequestError::Read(source) => Self::ReadResponseBody(source),
            TokenEndpointRequestError::UnexpectedStatus { status, body } => {
                Self::UnexpectedStatus { status, body }
            }
            TokenEndpointRequestError::ParseSuccessJson(source) => Self::ParseSuccessJson(source),
            TokenEndpointRequestError::ParseErrorJson(source) => Self::ParseErrorJson(source),
        }
    }
}

impl From<TokenEndpointRequestError> for RefreshTokenError {
    fn from(value: TokenEndpointRequestError) -> Self {
        match value {
            TokenEndpointRequestError::Url(source) => Self::Url(source),
            TokenEndpointRequestError::Send(source) => Self::SendRequest(source),
            TokenEndpointRequestError::Read(source) => Self::ReadResponseBody(source),
            TokenEndpointRequestError::UnexpectedStatus { status, body } => {
                Self::UnexpectedStatus { status, body }
            }
            TokenEndpointRequestError::ParseSuccessJson(source) => Self::ParseSuccessJson(source),
            TokenEndpointRequestError::ParseErrorJson(source) => Self::ParseErrorJson(source),
        }
    }
}
