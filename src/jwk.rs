use crate::error::{DidError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonWebKey {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_ops: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwkPublicKey {
    Ed25519([u8; 32]),
    X25519([u8; 32]),
    P256 { x: [u8; 32], y: [u8; 32] },
}

impl JsonWebKey {
    pub fn validate_public(&self) -> Result<()> {
        match (self.kty.as_str(), self.crv.as_deref()) {
            ("OKP", Some("Ed25519")) | ("OKP", Some("X25519")) => {
                let x = self
                    .x
                    .as_deref()
                    .ok_or_else(|| DidError::InvalidJwk("okp jwk missing x".into()))?;
                if self.y.is_some() {
                    return Err(DidError::InvalidJwk("okp jwk must not include y".into()));
                }
                decode_fixed_b64url::<32>(x)?;
                Ok(())
            }
            ("EC", Some("P-256")) => {
                let x = self
                    .x
                    .as_deref()
                    .ok_or_else(|| DidError::InvalidJwk("ec jwk missing x".into()))?;
                let y = self
                    .y
                    .as_deref()
                    .ok_or_else(|| DidError::InvalidJwk("ec jwk missing y".into()))?;
                decode_fixed_b64url::<32>(x)?;
                decode_fixed_b64url::<32>(y)?;
                Ok(())
            }
            _ => Err(DidError::InvalidJwk(format!(
                "unsupported public jwk kty/crv combination: {}/{}",
                self.kty,
                self.crv.as_deref().unwrap_or("<none>")
            ))),
        }
    }

    pub fn to_public_key(&self) -> Result<JwkPublicKey> {
        self.validate_public()?;
        match (self.kty.as_str(), self.crv.as_deref()) {
            ("OKP", Some("Ed25519")) => Ok(JwkPublicKey::Ed25519(decode_fixed_b64url::<32>(
                self.x.as_deref().unwrap_or_default(),
            )?)),
            ("OKP", Some("X25519")) => Ok(JwkPublicKey::X25519(decode_fixed_b64url::<32>(
                self.x.as_deref().unwrap_or_default(),
            )?)),
            ("EC", Some("P-256")) => Ok(JwkPublicKey::P256 {
                x: decode_fixed_b64url::<32>(self.x.as_deref().unwrap_or_default())?,
                y: decode_fixed_b64url::<32>(self.y.as_deref().unwrap_or_default())?,
            }),
            _ => Err(DidError::InvalidJwk("unsupported public jwk".into())),
        }
    }

    pub fn from_public_key(key: &JwkPublicKey) -> Self {
        match key {
            JwkPublicKey::Ed25519(bytes) => Self {
                kty: "OKP".into(),
                crv: Some("Ed25519".into()),
                x: Some(URL_SAFE_NO_PAD.encode(bytes)),
                y: None,
                alg: Some("EdDSA".into()),
                kid: None,
                use_: None,
                key_ops: vec![],
            },
            JwkPublicKey::X25519(bytes) => Self {
                kty: "OKP".into(),
                crv: Some("X25519".into()),
                x: Some(URL_SAFE_NO_PAD.encode(bytes)),
                y: None,
                alg: None,
                kid: None,
                use_: None,
                key_ops: vec![],
            },
            JwkPublicKey::P256 { x, y } => Self {
                kty: "EC".into(),
                crv: Some("P-256".into()),
                x: Some(URL_SAFE_NO_PAD.encode(x)),
                y: Some(URL_SAFE_NO_PAD.encode(y)),
                alg: Some("ES256".into()),
                kid: None,
                use_: None,
                key_ops: vec![],
            },
        }
    }
}

fn decode_fixed_b64url<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| DidError::InvalidJwk(format!("invalid base64url field: {error}")))?;
    if bytes.len() != N {
        return Err(DidError::InvalidJwk(format!(
            "expected {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_okp_jwk() {
        let key = JwkPublicKey::Ed25519([5u8; 32]);
        let jwk = JsonWebKey::from_public_key(&key);
        assert_eq!(jwk.to_public_key().unwrap(), key);
    }

    #[test]
    fn round_trips_p256_jwk() {
        let key = JwkPublicKey::P256 {
            x: [7u8; 32],
            y: [9u8; 32],
        };
        let jwk = JsonWebKey::from_public_key(&key);
        assert_eq!(jwk.to_public_key().unwrap(), key);
    }
}
