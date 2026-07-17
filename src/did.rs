use crate::error::{DidError, Result};
use crate::methods::{parse_did_web_id, validate_did_key_id};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssi_dids_core::{DIDBuf as SsiDidBuf, DIDURLBuf as SsiDidUrlBuf};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    method: String,
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DidUrl {
    did: Did,
    path: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
}

impl Did {
    pub fn parse(input: &str) -> Result<Self> {
        let parsed = SsiDidBuf::from_string(input.to_owned())
            .map_err(|error| DidError::InvalidDidSyntax(error.to_string()))?;
        let method = parsed.method_name().to_owned();
        let id = parsed.method_specific_id().to_owned();
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

impl Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Representation {
            String(String),
            Legacy { method: String, id: String },
        }

        let value = match Representation::deserialize(deserializer)? {
            Representation::String(value) => value,
            Representation::Legacy { method, id } => format!("did:{method}:{id}"),
        };
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl Display for Did {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)
    }
}

impl DidUrl {
    pub fn parse(input: &str) -> Result<Self> {
        let parsed = SsiDidUrlBuf::from_string(input.to_owned())
            .map_err(|error| DidError::InvalidDidUrl(error.to_string()))?;
        let did = Did::parse(parsed.did().as_str())?;
        let path = (!parsed.path().is_empty()).then(|| parsed.path().as_str().to_owned());
        let query = parsed.query().map(|value| value.as_str().to_owned());
        let fragment = parsed.fragment().map(|value| value.as_str().to_owned());

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

impl Serialize for DidUrl {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DidUrl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Representation {
            String(String),
            Legacy {
                did: Did,
                path: Option<String>,
                query: Option<String>,
                fragment: Option<String>,
            },
        }

        let value = match Representation::deserialize(deserializer)? {
            Representation::String(value) => value,
            Representation::Legacy {
                did,
                path,
                query,
                fragment,
            } => {
                let mut value = did.to_string();
                if let Some(path) = path {
                    value.push_str(&path);
                }
                if let Some(query) = query {
                    value.push('?');
                    value.push_str(&query);
                }
                if let Some(fragment) = fragment {
                    value.push('#');
                    value.push_str(&fragment);
                }
                value
            }
        };
        Self::parse(&value).map_err(serde::de::Error::custom)
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
        assert_eq!(
            serde_json::to_string(&did).unwrap(),
            "\"did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S\""
        );
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
        assert_eq!(
            serde_json::to_string(&did_url).unwrap(),
            "\"did:web:example.com:users:alice/path?view=1#key-1\""
        );
    }

    #[test]
    fn rejects_non_w3c_did_syntax() {
        assert!(Did::parse("did:WEB:example.com").is_err());
        assert!(Did::parse("did:web:example.com ").is_err());
        assert!(DidUrl::parse("did:web:example.com#bad%").is_err());
    }

    #[test]
    fn reads_legacy_object_representations() {
        let did: Did = serde_json::from_value(serde_json::json!({
            "method": "web",
            "id": "example.com"
        }))
        .unwrap();
        assert_eq!(did.to_string(), "did:web:example.com");

        let did_url: DidUrl = serde_json::from_value(serde_json::json!({
            "did": {"method": "web", "id": "example.com"},
            "path": "/users/alice",
            "query": "view=1",
            "fragment": "key-1"
        }))
        .unwrap();
        assert_eq!(
            did_url.to_string(),
            "did:web:example.com/users/alice?view=1#key-1"
        );
    }
}
