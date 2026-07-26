use crate::did::Did;
use crate::document::{DidDocument, VerificationMethod};
use crate::error::{DidError, Result};
use crate::jwk::{JsonWebKey, JwkPublicKey};
use did_method_key::DIDKey as SsiDidKey;
use did_web::DIDWeb as SsiDidWeb;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use ssi_dids_core::{
    DIDMethod,
    document::representation::MediaType,
    resolution::{DIDMethodResolver, Options as SsiResolutionOptions},
};
use std::net::IpAddr;

const DID_KEY_BASE58BTC: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_PUBLIC_KEY_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
const X25519_PUBLIC_KEY_MULTICODEC_PREFIX: [u8; 2] = [0xec, 0x01];
const SECP256K1_PUBLIC_KEY_MULTICODEC_PREFIX: [u8; 2] = [0xe7, 0x01];
const DID_WEB_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b':')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'[')
    .add(b']')
    .add(b'@')
    .add(b'%')
    .add(b' ');

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidKey {
    pub did: Did,
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidWeb {
    pub did: Did,
    pub host: String,
    pub path_segments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidKeyPublicKey {
    Ed25519([u8; 32]),
    X25519([u8; 32]),
    Secp256k1Compressed([u8; 33]),
}

pub(crate) fn validate_did_key_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(DidError::InvalidDidKey(
            "missing multibase public key".into(),
        ));
    }
    if !id.starts_with('z') {
        return Err(DidError::InvalidDidKey(
            "did:key currently requires base58btc multibase starting with 'z'".into(),
        ));
    }
    if !id.chars().skip(1).all(|ch| DID_KEY_BASE58BTC.contains(ch)) {
        return Err(DidError::InvalidDidKey(
            "did:key contains non-base58btc characters".into(),
        ));
    }
    Ok(())
}

pub(crate) fn parse_did_web_id(id: &str) -> Result<(String, Vec<String>)> {
    if id.trim().is_empty() {
        return Err(DidError::InvalidDidWeb("missing host".into()));
    }

    let mut parts = id.split(':');
    let host_part = parts
        .next()
        .ok_or_else(|| DidError::InvalidDidWeb("missing host".into()))?;
    let host = percent_decode_str(host_part)
        .decode_utf8()
        .map_err(|_| DidError::InvalidPercentEncoding(host_part.to_owned()))?
        .trim()
        .to_lowercase();

    if host.is_empty() {
        return Err(DidError::InvalidDidWeb("host cannot be empty".into()));
    }
    if host.contains('/') {
        return Err(DidError::InvalidDidWeb("host cannot contain '/'".into()));
    }

    let mut segments = Vec::new();
    for raw in parts {
        let segment = percent_decode_str(raw)
            .decode_utf8()
            .map_err(|_| DidError::InvalidPercentEncoding(raw.to_owned()))?
            .trim()
            .to_owned();
        if segment.is_empty() {
            return Err(DidError::InvalidDidWeb(
                "path segment cannot be empty".into(),
            ));
        }
        segments.push(segment);
    }

    Ok((host, segments))
}

fn encode_did_web_segment(value: &str) -> String {
    utf8_percent_encode(value, DID_WEB_ENCODE_SET).to_string()
}

pub(crate) fn is_loopback_host(authority: &str) -> bool {
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split_once(']').map(|(host, _)| host)
    } else {
        authority
            .rsplit_once(':')
            .filter(|(_, port)| port.chars().all(|ch| ch.is_ascii_digit()))
            .map(|(host, _)| host)
    }
    .unwrap_or(authority);

    host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

impl DidKey {
    pub fn from_ed25519_public_key(public_key: [u8; 32]) -> Result<Self> {
        let mut multicodec =
            Vec::with_capacity(ED25519_PUBLIC_KEY_MULTICODEC_PREFIX.len() + public_key.len());
        multicodec.extend_from_slice(&ED25519_PUBLIC_KEY_MULTICODEC_PREFIX);
        multicodec.extend_from_slice(&public_key);
        let public_key_multibase = format!("z{}", bs58::encode(multicodec).into_string());
        let did = Did::parse(&format!("did:key:{public_key_multibase}"))?;
        Self::from_did(did)
    }

    pub fn from_did(did: Did) -> Result<Self> {
        if did.method() != SsiDidKey::DID_METHOD_NAME {
            return Err(DidError::UnsupportedMethod(did.method().to_owned()));
        }
        validate_did_key_id(did.id())?;
        Ok(Self {
            public_key_multibase: did.id().to_owned(),
            did,
        })
    }

    pub fn verification_method(&self, fragment: &str) -> Result<VerificationMethod> {
        let fragment = fragment.trim().trim_start_matches('#');
        if fragment.is_empty() {
            return Err(DidError::InvalidDocument(
                "verification method fragment cannot be empty".into(),
            ));
        }

        Ok(VerificationMethod {
            id: format!("#{}", fragment),
            method_type: "Multikey".into(),
            controller: self.did.to_string(),
            public_key_multibase: Some(self.public_key_multibase.clone()),
            public_key_jwk: None,
            blockchain_account_id: None,
        })
    }

    pub fn to_document(&self) -> Result<DidDocument> {
        let output = pollster::block_on(SsiDidKey.resolve_method_representation(
            self.did.id(),
            SsiResolutionOptions {
                accept: Some(MediaType::Json),
                ..Default::default()
            },
        ))
        .map_err(|error| DidError::InvalidDidKey(error.to_string()))?;
        let mut document: DidDocument =
            serde_json::from_slice(&output.document).map_err(|error| {
                DidError::InvalidDocument(format!(
                    "did-method-key returned an invalid DID document: {error}"
                ))
            })?;
        let verification_method = format!("{}#{}", self.did, self.public_key_multibase);
        document
            .capability_invocation
            .push(verification_method.clone());
        document.capability_delegation.push(verification_method);
        document.validate()?;
        Ok(document)
    }

    pub fn decode_public_key(&self) -> Result<DidKeyPublicKey> {
        let decoded = bs58::decode(self.public_key_multibase.trim_start_matches('z'))
            .into_vec()
            .map_err(|error| {
                DidError::InvalidDidKey(format!("base58btc decode failed: {error}"))
            })?;

        if decoded.len() == 34 && decoded[..2] == ED25519_PUBLIC_KEY_MULTICODEC_PREFIX {
            let mut key = [0u8; 32];
            key.copy_from_slice(&decoded[2..]);
            return Ok(DidKeyPublicKey::Ed25519(key));
        }

        if decoded.len() == 34 && decoded[..2] == X25519_PUBLIC_KEY_MULTICODEC_PREFIX {
            let mut key = [0u8; 32];
            key.copy_from_slice(&decoded[2..]);
            return Ok(DidKeyPublicKey::X25519(key));
        }

        if decoded.len() == 35 && decoded[..2] == SECP256K1_PUBLIC_KEY_MULTICODEC_PREFIX {
            let mut key = [0u8; 33];
            key.copy_from_slice(&decoded[2..]);
            return Ok(DidKeyPublicKey::Secp256k1Compressed(key));
        }

        Err(DidError::InvalidDidKey(
            "unsupported multicodec key type".into(),
        ))
    }

    pub fn to_jwk(&self) -> Result<Option<JsonWebKey>> {
        match self.decode_public_key()? {
            DidKeyPublicKey::Ed25519(bytes) => Ok(Some(JsonWebKey::from_public_key(
                &JwkPublicKey::Ed25519(bytes),
            ))),
            DidKeyPublicKey::X25519(bytes) => Ok(Some(JsonWebKey::from_public_key(
                &JwkPublicKey::X25519(bytes),
            ))),
            DidKeyPublicKey::Secp256k1Compressed(_) => Ok(None),
        }
    }
}

impl DidWeb {
    pub fn from_did(did: Did) -> Result<Self> {
        if did.method() != SsiDidWeb::DID_METHOD_NAME {
            return Err(DidError::UnsupportedMethod(did.method().to_owned()));
        }
        let (host, path_segments) = parse_did_web_id(did.id())?;
        Ok(Self {
            did,
            host,
            path_segments,
        })
    }

    pub fn from_parts(host: impl AsRef<str>, path_segments: &[impl AsRef<str>]) -> Result<Self> {
        let host = host.as_ref().trim().to_lowercase();
        if host.is_empty() {
            return Err(DidError::InvalidDidWeb("host cannot be empty".into()));
        }
        let segments = path_segments
            .iter()
            .map(|segment| segment.as_ref().trim().to_owned())
            .collect::<Vec<_>>();
        if segments.iter().any(|segment| segment.is_empty()) {
            return Err(DidError::InvalidDidWeb(
                "path segment cannot be empty".into(),
            ));
        }

        let mut id_parts = vec![encode_did_web_segment(&host)];
        id_parts.extend(
            segments
                .iter()
                .map(|segment| encode_did_web_segment(segment)),
        );
        let did = Did::parse(&format!(
            "did:{}:{}",
            SsiDidWeb::DID_METHOD_NAME,
            id_parts.join(":")
        ))?;
        Ok(Self {
            did,
            host,
            path_segments: segments,
        })
    }

    pub fn to_url(&self) -> String {
        let scheme = if is_loopback_host(&self.host) {
            "http"
        } else {
            "https"
        };

        if self.path_segments.is_empty() {
            format!("{scheme}://{}/.well-known/did.json", self.host)
        } else {
            let path = self
                .path_segments
                .iter()
                .map(|segment| encode_did_web_segment(segment))
                .collect::<Vec<_>>()
                .join("/");
            format!("{scheme}://{}/{}/did.json", self.host, path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_did_key_base58btc() {
        assert!(validate_did_key_id("z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S").is_ok());
        assert!(validate_did_key_id("x123").is_err());
        assert!(validate_did_key_id("z0OIl").is_err());
    }

    #[test]
    fn parses_did_web_and_builds_url() {
        let did = Did::parse("did:web:example.com:users:alice").unwrap();
        let web = DidWeb::from_did(did).unwrap();
        assert_eq!(web.host, "example.com");
        assert_eq!(web.path_segments, vec!["users", "alice"]);
        assert_eq!(web.to_url(), "https://example.com/users/alice/did.json");
    }

    #[test]
    fn localhost_did_web_uses_http() {
        let web = DidWeb::from_parts("localhost:3000", &["agents", "demo"]).unwrap();
        assert_eq!(web.did.as_str(), "did:web:localhost%3A3000:agents:demo");
        assert_eq!(web.to_url(), "http://localhost:3000/agents/demo/did.json");
    }

    #[test]
    fn localhost_prefix_domain_still_requires_https() {
        let web = DidWeb::from_parts("localhost.example.com", &[] as &[&str]).unwrap();
        assert_eq!(
            web.to_url(),
            "https://localhost.example.com/.well-known/did.json"
        );
    }

    #[test]
    fn did_key_can_build_minimal_document() {
        let did = Did::parse("did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S").unwrap();
        let did_key = DidKey::from_did(did).unwrap();
        let document = did_key.to_document().unwrap();
        let expected_method = "did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S#z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S";
        assert_eq!(document.authentication, vec![expected_method]);
        assert_eq!(document.assertion_method, vec![expected_method]);
        assert_eq!(document.capability_invocation, vec![expected_method]);
        assert_eq!(document.capability_delegation, vec![expected_method]);
        assert_eq!(document.verification_method.len(), 1);
        assert_eq!(document.verification_method[0].id, expected_method);
        assert_eq!(
            document.verification_method[0]
                .public_key_multibase
                .as_deref(),
            Some("z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S")
        );
    }

    #[test]
    fn did_key_document_uses_w3c_json_names() {
        let did = Did::parse("did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S").unwrap();
        let document = DidKey::from_did(did).unwrap().to_document().unwrap();
        let value = serde_json::to_value(document).unwrap();

        assert!(value["id"].is_string());
        assert!(value.get("verificationMethod").is_some());
        assert!(value.get("capabilityInvocation").is_some());
        assert!(value.get("verification_method").is_none());
    }

    #[test]
    fn did_web_url_keeps_encoded_path_boundaries() {
        let did = Did::parse("did:web:example.com:users%2Falice").unwrap();
        let web = DidWeb::from_did(did).unwrap();
        assert_eq!(web.to_url(), "https://example.com/users%2Falice/did.json");
    }

    #[test]
    fn did_key_decodes_ed25519_multicodec_key() {
        let mut bytes = Vec::from(ED25519_PUBLIC_KEY_MULTICODEC_PREFIX);
        bytes.extend_from_slice(&[7u8; 32]);
        let encoded = format!("z{}", bs58::encode(bytes).into_string());
        let did = Did::parse(&format!("did:key:{encoded}")).unwrap();
        let did_key = DidKey::from_did(did).unwrap();
        assert_eq!(
            did_key.decode_public_key().unwrap(),
            DidKeyPublicKey::Ed25519([7u8; 32])
        );
    }

    #[test]
    fn did_key_builds_from_ed25519_public_key() {
        let did_key = DidKey::from_ed25519_public_key([7u8; 32]).unwrap();

        assert_eq!(
            did_key.decode_public_key().unwrap(),
            DidKeyPublicKey::Ed25519([7u8; 32])
        );
        assert_eq!(
            did_key.did.to_string(),
            format!("did:key:{}", did_key.public_key_multibase)
        );
    }

    #[test]
    fn did_key_decodes_x25519_multicodec_key() {
        let mut bytes = Vec::from(X25519_PUBLIC_KEY_MULTICODEC_PREFIX);
        bytes.extend_from_slice(&[8u8; 32]);
        let encoded = format!("z{}", bs58::encode(bytes).into_string());
        let did = Did::parse(&format!("did:key:{encoded}")).unwrap();
        let did_key = DidKey::from_did(did).unwrap();
        assert_eq!(
            did_key.decode_public_key().unwrap(),
            DidKeyPublicKey::X25519([8u8; 32])
        );
    }

    #[test]
    fn did_key_decodes_secp256k1_compressed_multicodec_key() {
        let mut bytes = Vec::from(SECP256K1_PUBLIC_KEY_MULTICODEC_PREFIX);
        bytes.extend_from_slice(&[2u8; 33]);
        let encoded = format!("z{}", bs58::encode(bytes).into_string());
        let did = Did::parse(&format!("did:key:{encoded}")).unwrap();
        let did_key = DidKey::from_did(did).unwrap();
        assert_eq!(
            did_key.decode_public_key().unwrap(),
            DidKeyPublicKey::Secp256k1Compressed([2u8; 33])
        );
    }
}
