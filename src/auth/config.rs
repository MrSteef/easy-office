use std::str::FromStr;

use bon::Builder;
use serde::{Serialize, Serializer};
use thiserror::Error;
use url::{ParseError, Url};
use uuid::Uuid;

#[derive(Debug, Clone, Builder)]
pub struct MicrosoftIdentityConfig {
    pub tenant: MicrosoftTenant,
    pub client_id: Uuid,
    pub scopes: Scopes,
    /// Optional scopes to send on refresh.
    ///
    /// When omitted, the library lets the provider infer scopes from the
    /// original grant instead of forcing the configured scope set again.
    pub refresh_scopes: Option<Scopes>,
    pub authority_base_url: Url,
    pub graph_base_url: Url,
}

impl MicrosoftIdentityConfig {
    pub fn authority_url(&self) -> Result<Url, ParseError> {
        Ok(url_with_appended_path_segments(
            self.authority_base_url.clone(),
            &[self.tenant.as_ref(), "oauth2", "v2.0"],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MicrosoftTenantKind {
    Common,
    Organizations,
    Consumers,
    Identifier(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrosoftTenant(MicrosoftTenantKind);

impl MicrosoftTenant {
    #[must_use]
    pub fn common() -> Self {
        Self(MicrosoftTenantKind::Common)
    }

    #[must_use]
    pub fn organizations() -> Self {
        Self(MicrosoftTenantKind::Organizations)
    }

    #[must_use]
    pub fn consumers() -> Self {
        Self(MicrosoftTenantKind::Consumers)
    }

    pub fn identifier(value: impl AsRef<str>) -> Result<Self, ParseMicrosoftTenantError> {
        let value = normalize_tenant_identifier(value.as_ref())?;
        Ok(Self(MicrosoftTenantKind::Identifier(value)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            MicrosoftTenantKind::Common => "common",
            MicrosoftTenantKind::Organizations => "organizations",
            MicrosoftTenantKind::Consumers => "consumers",
            MicrosoftTenantKind::Identifier(value) => value.as_str(),
        }
    }

    #[must_use]
    pub fn is_identifier(&self) -> bool {
        matches!(&self.0, MicrosoftTenantKind::Identifier(_))
    }
}

impl AsRef<str> for MicrosoftTenant {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for MicrosoftTenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseMicrosoftTenantError {
    #[error("tenant identifier cannot be blank")]
    Empty,
    #[error("tenant identifier cannot contain whitespace")]
    ContainsWhitespace,
    #[error("tenant identifier must be a single path segment")]
    ContainsPathSeparator,
    #[error("tenant identifier cannot contain reserved URL characters ('?', '#', or '%')")]
    ContainsReservedUrlCharacters,
    #[error("tenant identifier cannot be '.' or '..'")]
    ReservedDotSegment,
}

impl FromStr for MicrosoftTenant {
    type Err = ParseMicrosoftTenantError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = normalize_tenant_identifier(s)?;

        if s.eq_ignore_ascii_case("common") {
            Ok(Self::common())
        } else if s.eq_ignore_ascii_case("organizations") {
            Ok(Self::organizations())
        } else if s.eq_ignore_ascii_case("consumers") {
            Ok(Self::consumers())
        } else {
            Ok(Self(MicrosoftTenantKind::Identifier(s)))
        }
    }
}

impl TryFrom<&str> for MicrosoftTenant {
    type Error = ParseMicrosoftTenantError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for MicrosoftTenant {
    type Error = ParseMicrosoftTenantError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

fn normalize_tenant_identifier(s: &str) -> Result<String, ParseMicrosoftTenantError> {
    let s = s.trim();

    if s.is_empty() {
        return Err(ParseMicrosoftTenantError::Empty);
    }

    if s.chars().any(char::is_whitespace) {
        return Err(ParseMicrosoftTenantError::ContainsWhitespace);
    }

    if s.contains('/') || s.contains('\\') {
        return Err(ParseMicrosoftTenantError::ContainsPathSeparator);
    }

    if s.contains('?') || s.contains('#') || s.contains('%') {
        return Err(ParseMicrosoftTenantError::ContainsReservedUrlCharacters);
    }

    if s == "." || s == ".." {
        return Err(ParseMicrosoftTenantError::ReservedDotSegment);
    }

    Ok(s.to_owned())
}

fn url_with_appended_path_segments(mut url: Url, segments: &[&str]) -> Url {
    let mut path = url.path().trim_end_matches('/').to_owned();

    for segment in segments {
        if segment.is_empty() {
            continue;
        }

        if path.is_empty() {
            path.push('/');
        } else if !path.ends_with('/') {
            path.push('/');
        }

        path.push_str(segment);
    }

    if path.is_empty() {
        url.set_path("/");
    } else {
        url.set_path(&path);
    }

    url
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Scope(String);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseScopeError {
    #[error("scope cannot be empty")]
    Empty,
    #[error("scope must be a single scope value, not multiple space-separated scopes")]
    ContainsWhitespace,
    #[error("scope must not contain commas; pass multiple scopes as separate list items")]
    ContainsComma,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParseScopesError {
    #[error("at least one scope is required")]
    Empty,
    #[error("invalid scope at index {index} ({value:?}): {source}")]
    InvalidScope {
        index: usize,
        value: String,
        #[source]
        source: ParseScopeError,
    },
}

impl Scope {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Scope {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Scope {
    type Err = ParseScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if s.is_empty() {
            return Err(ParseScopeError::Empty);
        }

        if s.chars().any(char::is_whitespace) {
            return Err(ParseScopeError::ContainsWhitespace);
        }

        if s.contains(',') {
            return Err(ParseScopeError::ContainsComma);
        }

        Ok(Self(s.to_owned()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scopes(Vec<Scope>);

impl Scopes {
    pub fn as_slice(&self) -> &[Scope] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<Scope> {
        self.0
    }

    pub fn scope_string(&self) -> String {
        self.0
            .iter()
            .map(Scope::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl Serialize for Scopes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.scope_string();
        serializer.serialize_str(&s)
    }
}

impl FromStr for Scopes {
    type Err = ParseScopesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let scopes = s
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .enumerate()
            .map(|(index, part)| {
                part.parse()
                    .map_err(|source| ParseScopesError::InvalidScope {
                        index,
                        value: part.to_owned(),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if scopes.is_empty() {
            return Err(ParseScopesError::Empty);
        }

        Ok(Self(scopes))
    }
}

impl From<Scope> for String {
    fn from(value: Scope) -> Self {
        value.0
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
