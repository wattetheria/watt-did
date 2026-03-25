use crate::did::{Did, DidUrl};
use crate::error::{DidError, Result};
use crate::jwk::JsonWebKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: Did,
    #[serde(default)]
    pub also_known_as: Vec<String>,
    #[serde(default)]
    pub controller: Vec<String>,
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(default)]
    pub assertion_method: Vec<String>,
    #[serde(default)]
    pub key_agreement: Vec<String>,
    #[serde(default)]
    pub capability_invocation: Vec<String>,
    #[serde(default)]
    pub capability_delegation: Vec<String>,
    #[serde(default)]
    pub service: Vec<Service>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blockchain_account_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: Vec<String>,
    pub service_endpoint: ServiceEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceEndpoint {
    One(String),
    Many(Vec<String>),
    Json(Value),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRelationship {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[derive(Debug, Clone)]
pub struct DidDocumentBuilder {
    document: DidDocument,
}

impl DidDocument {
    pub fn new(id: Did) -> Self {
        Self {
            id,
            also_known_as: vec![],
            controller: vec![],
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
        }
    }

    pub fn validate(&self) -> Result<()> {
        let mut known_method_ids = HashSet::new();
        for method in &self.verification_method {
            if method.id.trim().is_empty() {
                return Err(DidError::InvalidDocument(
                    "verification method id cannot be empty".into(),
                ));
            }
            if method.method_type.trim().is_empty() {
                return Err(DidError::InvalidDocument(
                    "verification method type cannot be empty".into(),
                ));
            }
            if method.controller.trim().is_empty() {
                return Err(DidError::InvalidDocument(
                    "verification method controller cannot be empty".into(),
                ));
            }
            if method.public_key_multibase.is_none()
                && method.public_key_jwk.is_none()
                && method.blockchain_account_id.is_none()
            {
                return Err(DidError::InvalidDocument(format!(
                    "verification method {} has no key material",
                    method.id
                )));
            }
            if method.id.starts_with('#') {
                known_method_ids.insert(method.id.clone());
            } else {
                DidUrl::parse(&method.id)
                    .map_err(|_| DidError::InvalidVerificationMethodReference(method.id.clone()))?;
                known_method_ids.insert(method.id.clone());
            }
        }

        for refs in [
            &self.authentication,
            &self.assertion_method,
            &self.key_agreement,
            &self.capability_invocation,
            &self.capability_delegation,
        ] {
            validate_references(&known_method_ids, refs)?;
        }

        for service in &self.service {
            if service.id.trim().is_empty() {
                return Err(DidError::InvalidDocument(
                    "service id cannot be empty".into(),
                ));
            }
            if service.service_type.is_empty()
                || service
                    .service_type
                    .iter()
                    .any(|service_type| service_type.trim().is_empty())
            {
                return Err(DidError::InvalidDocument(
                    "service type cannot be empty".into(),
                ));
            }
        }

        Ok(())
    }

    pub fn builder(id: Did) -> DidDocumentBuilder {
        DidDocumentBuilder {
            document: Self::new(id),
        }
    }

    pub fn verification_method_by_reference(&self, reference: &str) -> Option<&VerificationMethod> {
        self.verification_method.iter().find(|method| {
            method.id == reference || format!("{}{}", self.id, method.id) == reference
        })
    }

    pub fn relationship_references(&self, relationship: VerificationRelationship) -> &[String] {
        match relationship {
            VerificationRelationship::Authentication => &self.authentication,
            VerificationRelationship::AssertionMethod => &self.assertion_method,
            VerificationRelationship::KeyAgreement => &self.key_agreement,
            VerificationRelationship::CapabilityInvocation => &self.capability_invocation,
            VerificationRelationship::CapabilityDelegation => &self.capability_delegation,
        }
    }

    pub fn has_relationship(
        &self,
        relationship: VerificationRelationship,
        reference: &str,
    ) -> bool {
        self.relationship_references(relationship)
            .iter()
            .any(|candidate| candidate == reference)
    }
}

impl DidDocumentBuilder {
    pub fn also_known_as(mut self, value: impl Into<String>) -> Self {
        self.document.also_known_as.push(value.into());
        self
    }

    pub fn controller(mut self, value: impl Into<String>) -> Self {
        self.document.controller.push(value.into());
        self
    }

    pub fn verification_method(mut self, method: VerificationMethod) -> Self {
        self.document.verification_method.push(method);
        self
    }

    pub fn relationship(
        mut self,
        relationship: VerificationRelationship,
        reference: impl Into<String>,
    ) -> Self {
        let target = match relationship {
            VerificationRelationship::Authentication => &mut self.document.authentication,
            VerificationRelationship::AssertionMethod => &mut self.document.assertion_method,
            VerificationRelationship::KeyAgreement => &mut self.document.key_agreement,
            VerificationRelationship::CapabilityInvocation => {
                &mut self.document.capability_invocation
            }
            VerificationRelationship::CapabilityDelegation => {
                &mut self.document.capability_delegation
            }
        };
        target.push(reference.into());
        self
    }

    pub fn service(mut self, service: Service) -> Self {
        self.document.service.push(service);
        self
    }

    pub fn build(self) -> Result<DidDocument> {
        self.document.validate()?;
        Ok(self.document)
    }
}

impl VerificationMethod {
    pub fn public_key_jwk_model(&self) -> Result<Option<JsonWebKey>> {
        match &self.public_key_jwk {
            Some(value) => Ok(Some(serde_json::from_value(value.clone()).map_err(
                |error| DidError::InvalidJwk(format!("invalid jwk json: {error}")),
            )?)),
            None => Ok(None),
        }
    }

    pub fn set_public_key_jwk_model(&mut self, jwk: &JsonWebKey) -> Result<()> {
        jwk.validate_public()?;
        self.public_key_jwk = Some(
            serde_json::to_value(jwk)
                .map_err(|error| DidError::InvalidJwk(format!("serialize jwk failed: {error}")))?,
        );
        Ok(())
    }
}

fn validate_references(known_method_ids: &HashSet<String>, refs: &[String]) -> Result<()> {
    for reference in refs {
        if reference.starts_with('#') {
            if !known_method_ids.contains(reference) {
                return Err(DidError::InvalidVerificationMethodReference(
                    reference.clone(),
                ));
            }
        } else {
            DidUrl::parse(reference)
                .map_err(|_| DidError::InvalidVerificationMethodReference(reference.clone()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_document_with_local_fragment_reference() {
        let document = DidDocument {
            id: Did::parse("did:web:example.com").unwrap(),
            also_known_as: vec![],
            controller: vec![],
            verification_method: vec![VerificationMethod {
                id: "#sig-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_multibase: Some(
                    "z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S".into(),
                ),
                public_key_jwk: None,
                blockchain_account_id: None,
            }],
            authentication: vec!["#sig-1".into()],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
        };

        assert!(document.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_fragment_reference() {
        let document = DidDocument {
            id: Did::parse("did:web:example.com").unwrap(),
            also_known_as: vec![],
            controller: vec![],
            verification_method: vec![],
            authentication: vec!["#missing".into()],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
        };

        assert!(matches!(
            document.validate(),
            Err(DidError::InvalidVerificationMethodReference(_))
        ));
    }

    #[test]
    fn builder_can_attach_relationships() {
        let did = Did::parse("did:web:example.com").unwrap();
        let document = DidDocument::builder(did)
            .verification_method(VerificationMethod {
                id: "#sig-1".into(),
                method_type: "Multikey".into(),
                controller: "did:web:example.com".into(),
                public_key_multibase: Some(
                    "z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S".into(),
                ),
                public_key_jwk: None,
                blockchain_account_id: None,
            })
            .relationship(VerificationRelationship::Authentication, "#sig-1")
            .build()
            .unwrap();

        assert!(document.has_relationship(VerificationRelationship::Authentication, "#sig-1"));
        assert!(
            document
                .verification_method_by_reference("#sig-1")
                .is_some()
        );
    }
}
