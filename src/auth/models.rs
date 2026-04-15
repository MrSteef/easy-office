use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::auth::config::{MicrosoftIdentityConfig, ParseScopesError, Scopes};

const DEFAULT_DEVICE_CODE_INTERVAL_SECS: u64 = 5;
const MIN_DEVICE_CODE_INTERVAL_SECS: u64 = 1;
const DEVICE_CODE_SLOW_DOWN_INCREMENT_SECS: u64 = 5;

macro_rules! secret_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug)]
        pub struct $name(SecretString);

        impl $name {
            pub fn expose(&self) -> &str {
                self.0.expose_secret()
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value.into())
            }
        }
    };
}

secret_newtype!(AccessToken);
secret_newtype!(RefreshToken);
secret_newtype!(IdToken);
secret_newtype!(DeviceCode);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserCode(String);

impl From<String> for UserCode {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for UserCode {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for UserCode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for UserCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::ops::Deref for UserCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenType {
    Bearer,
    DPoP,
    PoP,
    NotApplicable, // N_A
    Other(String),
}

impl From<&str> for TokenType {
    fn from(s: &str) -> Self {
        if s.eq_ignore_ascii_case("bearer") {
            Self::Bearer
        } else if s.eq_ignore_ascii_case("dpop") {
            Self::DPoP
        } else if s.eq_ignore_ascii_case("pop") {
            Self::PoP
        } else if s.eq_ignore_ascii_case("n_a") {
            Self::NotApplicable
        } else {
            Self::Other(s.to_string())
        }
    }
}

// step 1 - start device code flow

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct DeviceCodeStartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: Option<u64>,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct DeviceCodeStart {
    pub device_code: DeviceCode,
    pub user_code: UserCode,
    pub verification_uri: Url,
    pub interval: Duration,
    pub message: String,
    pub issued_at: OffsetDateTime,
    pub expires_in: Duration,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DeviceCodeStartConversionError {
    #[error("invalid verification URI: {0}")]
    InvalidVerificationUri(#[source] url::ParseError),

    #[error("device code response contained zero `expires_in`")]
    ZeroExpiresIn,
}

impl DeviceCodeStart {
    /// Converts a response using an explicit `issued_at` timestamp.
    /// This is useful for tests and for callers that want to control
    /// exactly when the device code is considered issued.
    pub(crate) fn from_response_at(
        value: DeviceCodeStartResponse,
        issued_at: OffsetDateTime,
    ) -> Result<Self, DeviceCodeStartConversionError> {
        let verification_uri = Url::parse(&value.verification_uri)
            .map_err(DeviceCodeStartConversionError::InvalidVerificationUri)?;

        if value.expires_in == 0 {
            return Err(DeviceCodeStartConversionError::ZeroExpiresIn);
        }

        let interval_secs = value
            .interval
            .unwrap_or(DEFAULT_DEVICE_CODE_INTERVAL_SECS)
            .max(MIN_DEVICE_CODE_INTERVAL_SECS);

        Ok(Self {
            device_code: value.device_code.into(),
            user_code: value.user_code.into(),
            verification_uri,
            interval: Duration::from_secs(interval_secs),
            message: value.message,
            issued_at,
            expires_in: Duration::from_secs(value.expires_in),
        })
    }
}

impl TryFrom<DeviceCodeStartResponse> for DeviceCodeStart {
    type Error = DeviceCodeStartConversionError;

    /// Converts a response using `OffsetDateTime::now_utc()` as `issued_at`.
    fn try_from(value: DeviceCodeStartResponse) -> Result<Self, Self::Error> {
        let issued_at = OffsetDateTime::now_utc();

        DeviceCodeStart::from_response_at(value, issued_at)
    }
}

// step 2a - polling the device code status, success response

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct TokenSuccessResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    // pub ext_expires_in: Option<u64>, // not used
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TokenSet {
    pub access_token: AccessToken,
    pub token_type: TokenType,
    pub refresh_token: Option<RefreshToken>,
    pub scopes: Option<Scopes>,
    pub id_token: Option<IdToken>,
    pub issued_at: OffsetDateTime,
    pub expires_in: Duration,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TokenSetConversionError {
    #[error("missing `expires_in` in token response")]
    MissingExpiresIn,

    #[error("token response contained zero `expires_in`")]
    ZeroExpiresIn,

    #[error("invalid scopes: {0}")]
    InvalidScopes(#[source] ParseScopesError),
}

impl TokenSet {
    /// Converts a response using an explicit `issued_at` timestamp.
    /// This is useful for tests and for callers that want to control
    /// exactly when the token is considered issued.
    pub(crate) fn from_response_at(
        value: TokenSuccessResponse,
        issued_at: OffsetDateTime,
    ) -> Result<Self, TokenSetConversionError> {
        let expires_in = value
            .expires_in
            .ok_or(TokenSetConversionError::MissingExpiresIn)?;

        if expires_in == 0 {
            return Err(TokenSetConversionError::ZeroExpiresIn);
        }

        let scopes = value
            .scope
            .map(|raw| raw.parse().map_err(TokenSetConversionError::InvalidScopes))
            .transpose()?;

        Ok(Self {
            access_token: value.access_token.into(),
            token_type: TokenType::from(value.token_type.as_str()),
            refresh_token: value.refresh_token.map(Into::into),
            scopes,
            id_token: value.id_token.map(Into::into),
            issued_at,
            expires_in: Duration::from_secs(expires_in),
        })
    }

    pub(crate) fn from_refresh_response_at(
        value: TokenSuccessResponse,
        issued_at: OffsetDateTime,
        existing_refresh_token: &RefreshToken,
    ) -> Result<Self, TokenSetConversionError> {
        let mut token_set = Self::from_response_at(value, issued_at)?;

        if token_set.refresh_token.is_none() {
            token_set.refresh_token = Some(existing_refresh_token.clone());
        }

        Ok(token_set)
    }
}

impl TryFrom<TokenSuccessResponse> for TokenSet {
    type Error = TokenSetConversionError;

    fn try_from(value: TokenSuccessResponse) -> Result<Self, Self::Error> {
        let issued_at = OffsetDateTime::now_utc();

        TokenSet::from_response_at(value, issued_at)
    }
}

// step 2b - polling the device code status, failure response

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct OAuthErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("unexpected device code poll error: {error}")]
pub struct UnexpectedDeviceCodePollError {
    pub error: String,
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceCodePollStatus {
    Pending { description: Option<String> },
    SlowDown { description: Option<String> },
    Declined { description: Option<String> },
    Expired { description: Option<String> },
    BadVerificationCode { description: Option<String> },
}

impl TryFrom<OAuthErrorResponse> for DeviceCodePollStatus {
    type Error = UnexpectedDeviceCodePollError;

    fn try_from(value: OAuthErrorResponse) -> Result<Self, Self::Error> {
        match value.error.as_str() {
            "authorization_pending" => Ok(Self::Pending {
                description: value.error_description,
            }),
            "slow_down" => Ok(Self::SlowDown {
                description: value.error_description,
            }),
            "access_denied" | "authorization_declined" => Ok(Self::Declined {
                description: value.error_description,
            }),
            "expired_token" => Ok(Self::Expired {
                description: value.error_description,
            }),
            "bad_verification_code" => Ok(Self::BadVerificationCode {
                description: value.error_description,
            }),
            _ => Err(UnexpectedDeviceCodePollError {
                error: value.error,
                description: value.error_description,
            }),
        }
    }
}

// step 2c - both status and authorized

#[derive(Clone, Debug)]
pub enum DeviceCodePollOutcome {
    Status(DeviceCodePollStatus),
    Authorized(TokenSet),
}

impl From<TokenSet> for DeviceCodePollOutcome {
    fn from(value: TokenSet) -> Self {
        DeviceCodePollOutcome::Authorized(value)
    }
}

impl From<DeviceCodePollStatus> for DeviceCodePollOutcome {
    fn from(value: DeviceCodePollStatus) -> Self {
        DeviceCodePollOutcome::Status(value)
    }
}

// extra methods on public api types

impl DeviceCodeStart {
    #[must_use]
    pub fn recommended_poll_interval_for(&self, status: &DeviceCodePollStatus) -> Duration {
        status.recommended_interval_from(self.interval)
    }

    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.issued_at + self.expires_in
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() >= self.expires_at()
    }

    #[must_use]
    pub fn is_expired_with_skew(&self, skew: Duration) -> bool {
        OffsetDateTime::now_utc() + skew >= self.expires_at()
    }
}

impl DeviceCodePollStatus {
    #[must_use]
    pub fn recommended_interval_from(&self, base_interval: Duration) -> Duration {
        match self {
            Self::SlowDown { .. } => base_interval
                .saturating_add(Duration::from_secs(DEVICE_CODE_SLOW_DOWN_INCREMENT_SECS)),
            _ => base_interval,
        }
    }
}

impl TokenSet {
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.issued_at + self.expires_in
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() >= self.expires_at()
    }

    #[must_use]
    pub fn is_expired_with_skew(&self, skew: Duration) -> bool {
        OffsetDateTime::now_utc() + skew >= self.expires_at()
    }
}

#[derive(Serialize)]
pub(crate) struct DeviceCodeRequest<'a> {
    client_id: &'a Uuid,
    scope: &'a Scopes,
}

impl<'a> DeviceCodeRequest<'a> {
    pub(crate) fn new(config: &'a MicrosoftIdentityConfig) -> Self {
        Self {
            client_id: &config.client_id,
            scope: &config.scopes,
        }
    }
}

fn serialize_device_code<S>(value: &DeviceCode, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.expose())
}

#[derive(Serialize)]
pub(crate) struct DeviceTokenRequest<'a> {
    grant_type: &'static str,
    client_id: &'a Uuid,
    #[serde(serialize_with = "serialize_device_code")]
    device_code: &'a DeviceCode,
}

impl<'a> DeviceTokenRequest<'a> {
    pub(crate) fn new(config: &'a MicrosoftIdentityConfig, device_code: &'a DeviceCode) -> Self {
        Self {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            client_id: &config.client_id,
            device_code,
        }
    }
}

fn serialize_refresh_token<S>(value: &RefreshToken, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.expose())
}

#[derive(Serialize)]
pub(crate) struct RefreshTokenRequest<'a> {
    grant_type: &'static str,
    client_id: &'a Uuid,
    #[serde(serialize_with = "serialize_refresh_token")]
    refresh_token: &'a RefreshToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a Scopes>,
}

impl<'a> RefreshTokenRequest<'a> {
    pub(crate) fn new(
        config: &'a MicrosoftIdentityConfig,
        refresh_token: &'a RefreshToken,
    ) -> Self {
        Self {
            grant_type: "refresh_token",
            client_id: &config.client_id,
            refresh_token,
            scope: config.refresh_scopes.as_ref(),
        }
    }
}
