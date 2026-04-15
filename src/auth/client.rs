use std::time::Duration;

use reqwest::{Client, StatusCode, redirect};
use serde::Serialize;
use time::OffsetDateTime;

use crate::auth::{config::*, error::*, models::*};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct MicrosoftIdentityClient {
    http: Client,
    config: MicrosoftIdentityConfig,
}

struct HttpResponseSnapshot {
    status: StatusCode,
    body: String,
    request_timestamp: OffsetDateTime,
}

enum TokenEndpointResponse {
    Success {
        json: TokenSuccessResponse,
        request_timestamp: OffsetDateTime,
    },
    OAuthError {
        status: StatusCode,
        body: String,
        error: OAuthErrorResponse,
    },
}

impl MicrosoftIdentityClient {
    pub fn new(config: MicrosoftIdentityConfig) -> Result<Self, reqwest::Error> {
        let http = Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .redirect(redirect::Policy::none())
            .build()?;

        Ok(Self { http, config })
    }

    pub fn with_http_client(http: Client, config: MicrosoftIdentityConfig) -> Self {
        Self { http, config }
    }

    pub fn config(&self) -> &MicrosoftIdentityConfig {
        &self.config
    }

    pub async fn start_device_code(&self) -> Result<DeviceCodeStart, StartDeviceCodeError> {
        let url = self.device_code_url()?;
        let form = DeviceCodeRequest::new(&self.config);
        let snapshot = self.post_form(url, &form).await?;

        if !snapshot.status.is_success() {
            return Err(StartDeviceCodeError::UnexpectedStatus {
                status: snapshot.status,
                body: snapshot.body,
            });
        }

        let json: DeviceCodeStartResponse =
            serde_json::from_str(&snapshot.body).map_err(StartDeviceCodeError::ParseSuccessJson)?;

        Ok(
            DeviceCodeStart::from_response_at(json, snapshot.request_timestamp)
                .map_err(StartDeviceCodeError::InvalidResponse)?,
        )
    }

    pub async fn redeem_device_code(
        &self,
        device_code: &DeviceCode,
    ) -> Result<DeviceCodePollOutcome, RedeemDeviceCodeError> {
        let form = DeviceTokenRequest::new(&self.config, device_code);
        let response = self.send_token_form(&form).await?;

        match response {
            TokenEndpointResponse::Success {
                json,
                request_timestamp,
            } => Ok(DeviceCodePollOutcome::Authorized(
                TokenSet::from_response_at(json, request_timestamp)?,
            )),
            TokenEndpointResponse::OAuthError {
                status,
                body,
                error,
            } => match DeviceCodePollStatus::try_from(error) {
                Ok(poll_status) => Ok(poll_status.into()),
                Err(unexpected) => Err(RedeemDeviceCodeError::OAuthError {
                    status,
                    error: unexpected.error,
                    description: unexpected.description,
                    body,
                }),
            },
        }
    }

    pub async fn refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<TokenSet, RefreshTokenError> {
        let form = RefreshTokenRequest::new(&self.config, refresh_token);
        let response = self.send_token_form(&form).await?;

        match response {
            TokenEndpointResponse::Success {
                json,
                request_timestamp,
            } => Ok(TokenSet::from_refresh_response_at(
                json,
                request_timestamp,
                refresh_token,
            )?),
            TokenEndpointResponse::OAuthError {
                status,
                body,
                error,
            } => Err(RefreshTokenError::OAuthError {
                status,
                error: error.error,
                description: error.error_description,
                body,
            }),
        }
    }

    fn device_code_url(&self) -> Result<url::Url, url::ParseError> {
        self.join_authority_path("devicecode")
    }

    fn token_url(&self) -> Result<url::Url, url::ParseError> {
        self.join_authority_path("token")
    }

    fn join_authority_path(&self, segment: &str) -> Result<url::Url, url::ParseError> {
        let mut base = self.config.authority_url()?;
        let mut path = base.path().trim_end_matches('/').to_owned();

        if path.is_empty() {
            path.push('/');
        } else if !path.ends_with('/') {
            path.push('/');
        }

        path.push_str(segment);
        base.set_path(&path);

        Ok(base)
    }

    async fn send_token_form<T: Serialize>(
        &self,
        form: &T,
    ) -> Result<TokenEndpointResponse, TokenEndpointRequestError> {
        let url = self.token_url()?;
        let snapshot = self.post_form(url, form).await?;

        if snapshot.status.is_success() {
            let json: TokenSuccessResponse = serde_json::from_str(&snapshot.body)
                .map_err(TokenEndpointRequestError::ParseSuccessJson)?;

            return Ok(TokenEndpointResponse::Success {
                json,
                request_timestamp: snapshot.request_timestamp,
            });
        }

        if snapshot.status != StatusCode::BAD_REQUEST
            && snapshot.status != StatusCode::UNAUTHORIZED
        {
            return Err(TokenEndpointRequestError::UnexpectedStatus {
                status: snapshot.status,
                body: snapshot.body,
            });
        }

        match serde_json::from_str::<OAuthErrorResponse>(&snapshot.body) {
            Ok(error) => Ok(TokenEndpointResponse::OAuthError {
                status: snapshot.status,
                body: snapshot.body,
                error,
            }),
            Err(parse_error) => Err(TokenEndpointRequestError::ParseErrorJson(parse_error)),
        }
    }

    async fn post_form<T: Serialize>(
        &self,
        url: url::Url,
        form: &T,
    ) -> Result<HttpResponseSnapshot, PostFormError> {
        // Prefer a more pessimistic time before the request over an optimistic
        // time by the time we get the response back.
        let request_timestamp = OffsetDateTime::now_utc();

        let response = self
            .http
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(PostFormError::Send)?;

        let status = response.status();
        let body = response.text().await.map_err(PostFormError::Read)?;

        Ok(HttpResponseSnapshot {
            status,
            body,
            request_timestamp,
        })
    }
}
