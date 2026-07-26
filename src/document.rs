use crate::did::{Did, DidUrl};
use crate::error::{DidError, Result};
use crate::jwk::JsonWebKey;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    pub id: Did,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<AgentDocumentType>,
    #[serde(
        default,
        alias = "also_known_as",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub also_known_as: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_one_or_many"
    )]
    pub controller: Vec<String>,
    #[serde(
        default,
        alias = "verification_method",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    #[serde(
        default,
        alias = "assertion_method",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub assertion_method: Vec<String>,
    #[serde(
        default,
        alias = "key_agreement",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub key_agreement: Vec<String>,
    #[serde(
        default,
        alias = "capability_invocation",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_invocation: Vec<String>,
    #[serde(
        default,
        alias = "capability_delegation",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_delegation: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentDocumentType {
    NetworkAgent,
    ServiceAgent,
    OrganizationAgent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(
        default,
        alias = "public_key_multibase",
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key_multibase: Option<String>,
    #[serde(
        default,
        alias = "public_key_jwk",
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key_jwk: Option<Value>,
    #[serde(
        default,
        alias = "blockchain_account_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub blockchain_account_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    #[serde(rename = "type", deserialize_with = "deserialize_one_or_many")]
    pub service_type: Vec<String>,
    #[serde(alias = "service_endpoint")]
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
            agent_type: None,
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
                known_method_ids.insert(self.absolute_verification_reference(&method.id));
            } else {
                DidUrl::parse(&method.id)
                    .map_err(|_| DidError::InvalidVerificationMethodReference(method.id.clone()))?;
                known_method_ids.insert(self.absolute_verification_reference(&method.id));
            }
        }

        for refs in [
            &self.authentication,
            &self.assertion_method,
            &self.key_agreement,
            &self.capability_invocation,
            &self.capability_delegation,
        ] {
            let references = refs
                .iter()
                .map(|reference| self.absolute_verification_reference(reference))
                .collect::<Vec<_>>();
            validate_references(&known_method_ids, &references)?;
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
            self.validate_wattetheria_service(service)?;
        }

        match self.agent_type {
            Some(AgentDocumentType::NetworkAgent) => {
                if !self.has_service_type(WATTETHERIA_NODE_ENDPOINT) {
                    return Err(DidError::InvalidDocument(
                        "NetworkAgent requires a WattetheriaNodeEndpoint service".into(),
                    ));
                }
            }
            Some(AgentDocumentType::ServiceAgent) => {
                if !self.has_service_type(WATTETHERIA_SERVICE_ENDPOINT) {
                    return Err(DidError::InvalidDocument(
                        "ServiceAgent requires a WattetheriaServiceEndpoint service".into(),
                    ));
                }
            }
            Some(AgentDocumentType::OrganizationAgent) | None => {}
        }

        Ok(())
    }

    pub fn builder(id: Did) -> DidDocumentBuilder {
        DidDocumentBuilder {
            document: Self::new(id),
        }
    }

    pub fn verification_method_by_reference(&self, reference: &str) -> Option<&VerificationMethod> {
        let reference = self.absolute_verification_reference(reference);
        self.verification_method
            .iter()
            .find(|method| self.absolute_verification_reference(&method.id) == reference)
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
            .any(|candidate| {
                self.absolute_verification_reference(candidate)
                    == self.absolute_verification_reference(reference)
            })
    }

    fn absolute_verification_reference(&self, reference: &str) -> String {
        if reference.starts_with('#') {
            format!("{}{reference}", self.id)
        } else {
            reference.to_owned()
        }
    }

    fn has_service_type(&self, expected: &str) -> bool {
        self.service
            .iter()
            .any(|service| service.service_type.iter().any(|item| item == expected))
    }

    fn validate_wattetheria_service(&self, service: &Service) -> Result<()> {
        if service
            .service_type
            .iter()
            .any(|item| item == WATTETHERIA_NODE_ENDPOINT)
        {
            self.validate_wattetheria_node_endpoint(service)?;
        }
        if service
            .service_type
            .iter()
            .any(|item| item == WATTETHERIA_SERVICE_ENDPOINT)
        {
            self.validate_wattetheria_service_endpoint(service)?;
        }
        Ok(())
    }

    fn validate_wattetheria_node_endpoint(&self, service: &Service) -> Result<()> {
        let endpoint = endpoint_object(service, WATTETHERIA_NODE_ENDPOINT)?;
        let network = required_endpoint_string(endpoint, "network")?;
        let agent_did = required_endpoint_string(endpoint, "agentDid")?;
        let address = required_endpoint_string(endpoint, "address")?;
        let public_id = required_endpoint_string(endpoint, "publicId")?;
        let transport = required_endpoint_string(endpoint, "transport")?;
        if agent_did != self.id.to_string() {
            return Err(DidError::InvalidDocument(
                "WattetheriaNodeEndpoint agentDid must match document id".into(),
            ));
        }
        let expected_address = format!("wattetheria://{network}/identity/{agent_did}");
        if address != expected_address {
            return Err(DidError::InvalidDocument(
                "WattetheriaNodeEndpoint address must be wattetheria://<network>/identity/<agentDid>"
                    .into(),
            ));
        }
        if public_id.starts_with('@') {
            return Err(DidError::InvalidDocument(
                "WattetheriaNodeEndpoint publicId must not include @".into(),
            ));
        }
        if transport != "wattswarm" {
            return Err(DidError::InvalidDocument(
                "WattetheriaNodeEndpoint transport must be wattswarm".into(),
            ));
        }
        Ok(())
    }

    fn validate_wattetheria_service_endpoint(&self, service: &Service) -> Result<()> {
        let endpoint = endpoint_object(service, WATTETHERIA_SERVICE_ENDPOINT)?;
        let network = required_endpoint_string(endpoint, "network")?;
        let agent_id = required_endpoint_string(endpoint, "agentId")?;
        let service_address = required_endpoint_string(endpoint, "serviceAddress")?;
        let provider_did = required_endpoint_string(endpoint, "providerDid")?;
        let address = required_endpoint_string(endpoint, "address")?;
        let transport = required_endpoint_string(endpoint, "transport")?;
        Did::parse(provider_did).map_err(|_| {
            DidError::InvalidDocument(
                "WattetheriaServiceEndpoint providerDid must be a valid DID".into(),
            )
        })?;
        let expected_address = format!("wattetheria://{network}/service/{agent_id}");
        if address != expected_address {
            return Err(DidError::InvalidDocument(
                "WattetheriaServiceEndpoint address must be wattetheria://<network>/service/<agentId>"
                    .into(),
            ));
        }
        if service_address.starts_with('@') {
            return Err(DidError::InvalidDocument(
                "WattetheriaServiceEndpoint serviceAddress must not include @".into(),
            ));
        }
        if !self
            .also_known_as
            .iter()
            .any(|alias| alias == service_address)
        {
            return Err(DidError::InvalidDocument(
                "ServiceAgent alsoKnownAs must include serviceAddress".into(),
            ));
        }
        if transport != "servicenet" {
            return Err(DidError::InvalidDocument(
                "WattetheriaServiceEndpoint transport must be servicenet".into(),
            ));
        }
        Ok(())
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
        DidUrl::parse(reference)
            .map_err(|_| DidError::InvalidVerificationMethodReference(reference.clone()))?;
        if !known_method_ids.contains(reference) {
            return Err(DidError::InvalidVerificationMethodReference(
                reference.clone(),
            ));
        }
    }
    Ok(())
}

const WATTETHERIA_NODE_ENDPOINT: &str = "WattetheriaNodeEndpoint";
const WATTETHERIA_SERVICE_ENDPOINT: &str = "WattetheriaServiceEndpoint";

fn endpoint_object<'a>(
    service: &'a Service,
    service_type: &str,
) -> Result<&'a serde_json::Map<String, Value>> {
    match &service.service_endpoint {
        ServiceEndpoint::Json(Value::Object(object)) => Ok(object),
        _ => Err(DidError::InvalidDocument(format!(
            "{service_type} requires a JSON serviceEndpoint object"
        ))),
    }
}

fn required_endpoint_string<'a>(
    endpoint: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str> {
    endpoint
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DidError::InvalidDocument(format!("serviceEndpoint.{field} is required")))
}

fn deserialize_one_or_many<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_document_with_local_fragment_reference() {
        let document = DidDocument {
            id: Did::parse("did:web:example.com").unwrap(),
            agent_type: None,
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
            agent_type: None,
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

    #[test]
    fn validates_wattetheria_network_agent_endpoint() {
        let did = Did::parse("did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S").unwrap();
        let document = DidDocument {
            id: did.clone(),
            agent_type: Some(AgentDocumentType::NetworkAgent),
            also_known_as: vec![],
            controller: vec![],
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![Service {
                id: "#wattetheria-node".to_owned(),
                service_type: vec![WATTETHERIA_NODE_ENDPOINT.to_owned()],
                service_endpoint: ServiceEndpoint::Json(serde_json::json!({
                    "network": "mainnet.watt-etheria",
                    "address": format!("wattetheria://mainnet.watt-etheria/identity/{did}"),
                    "agentDid": did.to_string(),
                    "publicId": "agent-test.aa02a834d64b68b8",
                    "transport": "wattswarm"
                })),
                description: None,
            }],
        };

        assert!(document.validate().is_ok());
    }

    #[test]
    fn validates_wattetheria_service_agent_endpoint() {
        let did = Did::parse("did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S").unwrap();
        let document = DidDocument {
            id: did.clone(),
            agent_type: Some(AgentDocumentType::ServiceAgent),
            also_known_as: vec!["dumpling@wattetheria".to_owned()],
            controller: vec![did.to_string()],
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![Service {
                id: "#wattetheria-servicenet".to_owned(),
                service_type: vec![WATTETHERIA_SERVICE_ENDPOINT.to_owned()],
                service_endpoint: ServiceEndpoint::Json(serde_json::json!({
                    "network": "mainnet.watt-etheria",
                    "address": "wattetheria://mainnet.watt-etheria/service/jingyuan-dumpling-7eb89abd",
                    "agentId": "jingyuan-dumpling-7eb89abd",
                    "serviceAddress": "dumpling@wattetheria",
                    "providerDid": did.to_string(),
                    "transport": "servicenet"
                })),
                description: None,
            }],
        };

        assert!(document.validate().is_ok());
    }

    #[test]
    fn rejects_service_agent_missing_alias() {
        let did = Did::parse("did:key:z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S").unwrap();
        let document = DidDocument {
            id: did.clone(),
            agent_type: Some(AgentDocumentType::ServiceAgent),
            also_known_as: vec![],
            controller: vec![],
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![Service {
                id: "#wattetheria-servicenet".to_owned(),
                service_type: vec![WATTETHERIA_SERVICE_ENDPOINT.to_owned()],
                service_endpoint: ServiceEndpoint::Json(serde_json::json!({
                    "network": "mainnet.watt-etheria",
                    "address": "wattetheria://mainnet.watt-etheria/service/jingyuan-dumpling-7eb89abd",
                    "agentId": "jingyuan-dumpling-7eb89abd",
                    "serviceAddress": "dumpling@wattetheria",
                    "providerDid": did.to_string(),
                    "transport": "servicenet"
                })),
                description: None,
            }],
        };

        assert!(matches!(
            document.validate(),
            Err(DidError::InvalidDocument(_))
        ));
    }

    #[test]
    fn serializes_w3c_did_document_property_names() {
        let did = Did::parse("did:web:example.com").unwrap();
        let document = DidDocument::builder(did.clone())
            .controller(did.to_string())
            .verification_method(VerificationMethod {
                id: format!("{did}#key-1"),
                method_type: "Multikey".into(),
                controller: did.to_string(),
                public_key_multibase: Some(
                    "z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S".into(),
                ),
                public_key_jwk: None,
                blockchain_account_id: None,
            })
            .relationship(
                VerificationRelationship::Authentication,
                format!("{did}#key-1"),
            )
            .service(Service {
                id: format!("{did}#messages"),
                service_type: vec!["Messaging".into()],
                service_endpoint: ServiceEndpoint::One("https://example.com/messages".into()),
                description: None,
            })
            .build()
            .unwrap();

        let value = serde_json::to_value(document).unwrap();
        assert_eq!(value["id"], "did:web:example.com");
        assert!(value.get("verificationMethod").is_some());
        assert!(value.get("verification_method").is_none());
        assert!(value.get("assertionMethod").is_none());
        assert_eq!(
            value["verificationMethod"][0]["publicKeyMultibase"],
            "z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S"
        );
        assert_eq!(
            value["service"][0]["serviceEndpoint"],
            "https://example.com/messages"
        );
    }

    #[test]
    fn deserializes_w3c_one_or_many_properties() {
        let document: DidDocument = serde_json::from_value(serde_json::json!({
            "id": "did:web:example.com",
            "controller": "did:web:controller.example",
            "service": [{
                "id": "did:web:example.com#messages",
                "type": "Messaging",
                "serviceEndpoint": "https://example.com/messages"
            }]
        }))
        .unwrap();

        assert_eq!(document.controller, vec!["did:web:controller.example"]);
        assert_eq!(document.service[0].service_type, vec!["Messaging"]);
    }

    #[test]
    fn reads_legacy_snake_case_document_properties() {
        let document: DidDocument = serde_json::from_value(serde_json::json!({
            "id": {"method": "web", "id": "example.com"},
            "verification_method": [{
                "id": "#key-1",
                "type": "Multikey",
                "controller": "did:web:example.com",
                "public_key_multibase":
                    "z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S"
            }],
            "assertion_method": ["#key-1"]
        }))
        .unwrap();

        assert_eq!(document.id.to_string(), "did:web:example.com");
        assert_eq!(document.assertion_method, vec!["#key-1"]);
        assert_eq!(document.verification_method.len(), 1);
    }
}
