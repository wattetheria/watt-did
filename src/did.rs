use crate::error::{DidError, Result};
use crate::methods::{parse_did_web_id, validate_did_key_id};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did {
    method: String,
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DidUrl {
    did: Did,
    path: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
}

impl Did {
    pub fn parse(input: &str) -> Result<Self> {
        if !input.starts_with("did:") {
            return Err(DidError::InvalidDidSyntax(
                "did must start with 'did:'".into(),
            ));
        }
        if input.contains('/') || input.contains('?') || input.contains('#') {
            return Err(DidError::InvalidDidSyntax(
                "base did cannot include path, query, or fragment; parse as DidUrl instead".into(),
            ));
        }

        let mut parts = input.splitn(3, ':');
        let _prefix = parts.next();
        let method = parts
            .next()
            .ok_or_else(|| DidError::InvalidDidSyntax("missing did method".into()))?
            .trim()
            .to_lowercase();
        let id = parts
            .next()
            .ok_or_else(|| DidError::InvalidDidSyntax("missing method-specific-id".into()))?
            .trim()
            .to_owned();

        validate_method(&method)?;
        validate_method_specific_id(&method, &id)?;

        Ok(Self { method, id })
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn as_str(&self) -> String {
        self.to_string()
    }
}

impl Display for Did {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)
    }
}

impl DidUrl {
    pub fn parse(input: &str) -> Result<Self> {
        let path_start = input.find('/');
        let query_start = input.find('?');
        let fragment_start = input.find('#');
        let did_end = [path_start, query_start, fragment_start]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(input.len());
        let did = Did::parse(&input[..did_end])?;

        let mut path = None;
        let mut query = None;
        let mut fragment = None;
        let remainder = &input[did_end..];

        if !remainder.is_empty() {
            let query_index = remainder.find('?');
            let fragment_index = remainder.find('#');

            if remainder.starts_with('/') {
                let path_end = [query_index, fragment_index]
                    .into_iter()
                    .flatten()
                    .min()
                    .unwrap_or(remainder.len());
                path = Some(remainder[..path_end].to_owned());
            }

            if let Some(index) = query_index {
                let query_end = fragment_index.unwrap_or(remainder.len());
                query = Some(remainder[index + 1..query_end].to_owned());
            }

            if let Some(index) = fragment_index {
                fragment = Some(remainder[index + 1..].to_owned());
            }
        }

        Ok(Self {
            did,
            path,
            query,
            fragment,
        })
    }

    pub fn did(&self) -> &Did {
        &self.did
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    pub fn as_str(&self) -> String {
        self.to_string()
    }
}

impl Display for DidUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.did)?;
        if let Some(path) = &self.path {
            write!(f, "{path}")?;
        }
        if let Some(query) = &self.query {
            write!(f, "?{query}")?;
        }
        if let Some(fragment) = &self.fragment {
            write!(f, "#{fragment}")?;
        }
        Ok(())
    }
}

fn validate_method(method: &str) -> Result<()> {
    if method.is_empty() {
        return Err(DidError::InvalidMethod("method cannot be empty".into()));
    }
    if !method
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
    {
        return Err(DidError::InvalidMethod(
            "method must use lowercase ascii letters and digits only".into(),
        ));
    }
    Ok(())
}

fn validate_method_specific_id(method: &str, id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(DidError::InvalidMethodSpecificId(
            "method-specific-id cannot be empty".into(),
        ));
    }

    match method {
        "key" => validate_did_key_id(id),
        "web" => {
            parse_did_web_id(id)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_did() {
        let did = Did::parse("did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S").unwrap();
        assert_eq!(did.method(), "key");
    }

    #[test]
    fn rejects_did_with_url_parts() {
        let err = Did::parse("did:web:example.com#key-1").unwrap_err();
        assert!(matches!(err, DidError::InvalidDidSyntax(_)));
    }

    #[test]
    fn parses_did_url() {
        let did_url = DidUrl::parse("did:web:example.com:users:alice/path?view=1#key-1").unwrap();
        assert_eq!(did_url.did().to_string(), "did:web:example.com:users:alice");
        assert_eq!(did_url.path(), Some("/path"));
        assert_eq!(did_url.query(), Some("view=1"));
        assert_eq!(did_url.fragment(), Some("key-1"));
    }
}
