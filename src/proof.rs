use crate::did::Did;
use crate::document::{DidDocument, VerificationMethod};
use crate::error::{DidError, Result};
use crate::methods::{DidKey, DidKeyPublicKey};
use crate::resolver::DidResolver;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofAlgorithm {
    Jws,
    Jwt,
    Ucan,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEnvelope {
    pub algorithm: ProofAlgorithm,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcanCapability {
    pub resource: String,
    pub ability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caveat: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcanDelegation {
    pub issuer_did: Did,
    pub audience_did: Did,
    #[serde(default)]
    pub capabilities: Vec<UcanCapability>,
    pub issued_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub facts: Vec<serde_json::Value>,
    pub proof: ProofEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentNodeBindingProof {
    pub agent_did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_peer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_public_key_multibase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_did: Option<Did>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub issued_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub proof: ProofEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentAccountCustody {
    WatchOnly,
    LocalGenerated,
    ImportedKey,
    ExternalSigner,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentAccountBindingProof {
    pub agent_did: Did,
    pub payment_address: String,
    pub rail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub custody: PaymentAccountCustody,
    pub receive_only: bool,
    pub can_sign: bool,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub issued_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub agent_proof: ProofEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_account_proof: Option<ProofEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedAgentContext {
    pub agent_did: Did,
    pub controller_node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_node_id: Option<String>,
    pub envelope_verified: bool,
    pub source_node_verified: bool,
    pub controller_binding_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_binding_proof: Option<AgentNodeBindingProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_account_binding: Option<PaymentAccountBindingProof>,
    pub verified_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
}

pub trait AgentNodeBindingVerifier {
    fn verify_agent_node_binding(&self, proof: &AgentNodeBindingProof) -> Result<()>;
}

pub trait PaymentAccountBindingVerifier {
    fn verify_payment_account_binding(&self, proof: &PaymentAccountBindingProof) -> Result<()>;
}

pub trait VerifiedAgentContextVerifier {
    fn verify_verified_agent_context(&self, context: &VerifiedAgentContext) -> Result<()>;
}

pub trait ProofVerifier {
    fn verify(
        &self,
        proof: &ProofEnvelope,
        expected_signer: &Did,
        document: &DidDocument,
    ) -> Result<()>;
}

pub trait UcanDelegationVerifier {
    fn verify_ucan_delegation(&self, delegation: &UcanDelegation) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct JoseValidationOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_audience: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_time_ms: Option<u64>,
    #[serde(default)]
    pub require_exp: bool,
    #[serde(default)]
    pub require_sub: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct UcanVerificationContext<'a> {
    pub now_ms: Option<u64>,
    pub parent: Option<&'a UcanDelegation>,
}

#[derive(Debug, Clone)]
pub struct ResolverBackedBindingVerifier<R, V> {
    resolver: R,
    proof_verifier: V,
}

#[derive(Debug, Clone)]
pub struct ResolverBackedUcanVerifier<R, V> {
    resolver: R,
    proof_verifier: V,
}

#[derive(Debug, Clone)]
pub struct AgentPaymentContextVerifier<C, P> {
    controller_binding_verifier: C,
    payment_account_binding_verifier: P,
    require_payment_account_binding: bool,
}

impl<R, V> ResolverBackedBindingVerifier<R, V> {
    pub fn new(resolver: R, proof_verifier: V) -> Self {
        Self {
            resolver,
            proof_verifier,
        }
    }
}

impl<R, V> ResolverBackedUcanVerifier<R, V> {
    pub fn new(resolver: R, proof_verifier: V) -> Self {
        Self {
            resolver,
            proof_verifier,
        }
    }
}

impl<C, P> AgentPaymentContextVerifier<C, P> {
    pub fn new(controller_binding_verifier: C, payment_account_binding_verifier: P) -> Self {
        Self {
            controller_binding_verifier,
            payment_account_binding_verifier,
            require_payment_account_binding: true,
        }
    }

    pub fn with_optional_payment_binding(
        controller_binding_verifier: C,
        payment_account_binding_verifier: P,
    ) -> Self {
        Self {
            controller_binding_verifier,
            payment_account_binding_verifier,
            require_payment_account_binding: false,
        }
    }
}

impl AgentNodeBindingProof {
    pub fn validate_basic(&self) -> Result<()> {
        if self.node_did.is_none()
            && self.node_peer_id.as_deref().unwrap_or_default().is_empty()
            && self
                .node_public_key_multibase
                .as_deref()
                .unwrap_or_default()
                .is_empty()
        {
            return Err(DidError::InvalidBindingProof(
                "binding proof must reference at least one node target".into(),
            ));
        }

        if self.proof.value.trim().is_empty() {
            return Err(DidError::InvalidBindingProof(
                "proof value cannot be empty".into(),
            ));
        }

        if let Some(expires_at_ms) = self.expires_at_ms
            && expires_at_ms <= self.issued_at_ms
        {
            return Err(DidError::InvalidBindingProof(
                "expires_at_ms must be greater than issued_at_ms".into(),
            ));
        }

        Ok(())
    }
}

impl PaymentAccountBindingProof {
    pub fn validate_basic(&self) -> Result<()> {
        if self.payment_address.trim().is_empty() {
            return Err(DidError::InvalidBindingProof(
                "payment_address cannot be empty".into(),
            ));
        }
        if self.rail.trim().is_empty() {
            return Err(DidError::InvalidBindingProof("rail cannot be empty".into()));
        }
        if self
            .network
            .as_deref()
            .is_some_and(|network| network.trim().is_empty())
        {
            return Err(DidError::InvalidBindingProof(
                "network cannot be empty when present".into(),
            ));
        }
        if self.receive_only && self.can_sign {
            return Err(DidError::InvalidBindingProof(
                "receive_only accounts cannot also can_sign".into(),
            ));
        }
        match self.custody {
            PaymentAccountCustody::WatchOnly => {
                if !self.receive_only || self.can_sign {
                    return Err(DidError::InvalidBindingProof(
                        "watch_only accounts must be receive_only and cannot sign".into(),
                    ));
                }
            }
            PaymentAccountCustody::LocalGenerated
            | PaymentAccountCustody::ImportedKey
            | PaymentAccountCustody::ExternalSigner
            | PaymentAccountCustody::Custom(_) => {
                if !self.can_sign {
                    return Err(DidError::InvalidBindingProof(
                        "spending-capable custody must set can_sign".into(),
                    ));
                }
                if self.payment_account_proof.is_none() {
                    return Err(DidError::InvalidBindingProof(
                        "spending-capable accounts require payment_account_proof".into(),
                    ));
                }
            }
        }
        if self.agent_proof.value.trim().is_empty() {
            return Err(DidError::InvalidBindingProof(
                "agent_proof value cannot be empty".into(),
            ));
        }
        if let Some(payment_account_proof) = &self.payment_account_proof {
            if payment_account_proof.value.trim().is_empty() {
                return Err(DidError::InvalidBindingProof(
                    "payment_account_proof value cannot be empty".into(),
                ));
            }
            if payment_account_proof
                .challenge
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                return Err(DidError::InvalidBindingProof(
                    "payment_account_proof challenge cannot be empty".into(),
                ));
            }
        }
        if let Some(expires_at_ms) = self.expires_at_ms
            && expires_at_ms <= self.issued_at_ms
        {
            return Err(DidError::InvalidBindingProof(
                "expires_at_ms must be greater than issued_at_ms".into(),
            ));
        }
        Ok(())
    }
}

impl VerifiedAgentContext {
    pub fn validate_basic(&self) -> Result<()> {
        if self.controller_node_id.trim().is_empty() {
            return Err(DidError::InvalidBindingProof(
                "controller_node_id cannot be empty".into(),
            ));
        }
        if self
            .source_node_id
            .as_deref()
            .is_some_and(|source_node_id| source_node_id.trim().is_empty())
        {
            return Err(DidError::InvalidBindingProof(
                "source_node_id cannot be empty when present".into(),
            ));
        }
        if self.source_node_verified {
            let source_node_id = self.source_node_id.as_deref().ok_or_else(|| {
                DidError::InvalidBindingProof("source_node_verified requires source_node_id".into())
            })?;
            if source_node_id != self.controller_node_id {
                return Err(DidError::InvalidBindingProof(
                    "source_node_id must match controller_node_id when source is verified".into(),
                ));
            }
        }
        if self.controller_binding_verified {
            let proof = self.controller_binding_proof.as_ref().ok_or_else(|| {
                DidError::InvalidBindingProof(
                    "controller_binding_verified requires controller_binding_proof".into(),
                )
            })?;
            proof.validate_basic()?;
            if proof.agent_did != self.agent_did {
                return Err(DidError::InvalidBindingProof(
                    "controller binding agent_did does not match context agent_did".into(),
                ));
            }
            if proof.node_peer_id.as_deref() != Some(self.controller_node_id.as_str()) {
                return Err(DidError::InvalidBindingProof(
                    "controller binding node_peer_id does not match controller_node_id".into(),
                ));
            }
        }
        if let Some(binding) = &self.payment_account_binding {
            binding.validate_basic()?;
            if binding.agent_did != self.agent_did {
                return Err(DidError::InvalidBindingProof(
                    "payment account binding agent_did does not match context agent_did".into(),
                ));
            }
        }
        if let Some(expires_at_ms) = self.expires_at_ms
            && expires_at_ms <= self.verified_at_ms
        {
            return Err(DidError::InvalidBindingProof(
                "expires_at_ms must be greater than verified_at_ms".into(),
            ));
        }
        Ok(())
    }
}

impl UcanDelegation {
    pub fn validate_basic(&self) -> Result<()> {
        if self.capabilities.is_empty() {
            return Err(DidError::VerificationFailed(
                "ucan delegation must include at least one capability".into(),
            ));
        }
        if self
            .capabilities
            .iter()
            .any(|cap| cap.resource.trim().is_empty() || cap.ability.trim().is_empty())
        {
            return Err(DidError::VerificationFailed(
                "ucan capability resource and ability are required".into(),
            ));
        }
        if let Some(not_before_ms) = self.not_before_ms
            && not_before_ms < self.issued_at_ms
        {
            return Err(DidError::VerificationFailed(
                "ucan not_before_ms must be >= issued_at_ms".into(),
            ));
        }
        if let Some(expires_at_ms) = self.expires_at_ms
            && expires_at_ms <= self.issued_at_ms
        {
            return Err(DidError::VerificationFailed(
                "ucan expires_at_ms must be > issued_at_ms".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_time_window(&self, now_ms: u64) -> Result<()> {
        if let Some(not_before_ms) = self.not_before_ms
            && now_ms < not_before_ms
        {
            return Err(DidError::VerificationFailed(
                "ucan delegation not active yet".into(),
            ));
        }
        if let Some(expires_at_ms) = self.expires_at_ms
            && now_ms >= expires_at_ms
        {
            return Err(DidError::VerificationFailed(
                "ucan delegation expired".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_attenuation(&self, parent: &UcanDelegation) -> Result<()> {
        if self.issuer_did != parent.audience_did {
            return Err(DidError::VerificationFailed(
                "ucan child issuer must equal parent audience".into(),
            ));
        }
        if let Some(parent_not_before) = parent.not_before_ms
            && self.not_before_ms.unwrap_or(self.issued_at_ms) < parent_not_before
        {
            return Err(DidError::VerificationFailed(
                "ucan child not_before expands parent window".into(),
            ));
        }
        if let Some(parent_expires) = parent.expires_at_ms
            && self.expires_at_ms.unwrap_or(parent_expires) > parent_expires
        {
            return Err(DidError::VerificationFailed(
                "ucan child expiry exceeds parent expiry".into(),
            ));
        }
        for capability in &self.capabilities {
            let allowed = parent
                .capabilities
                .iter()
                .any(|candidate| capability_is_attenuated_by(capability, candidate));
            if !allowed {
                return Err(DidError::VerificationFailed(format!(
                    "ucan capability not attenuated by parent: {} {}",
                    capability.resource, capability.ability
                )));
            }
        }
        Ok(())
    }

    pub fn validate_with_context(&self, context: UcanVerificationContext<'_>) -> Result<()> {
        if let Some(now_ms) = context.now_ms {
            self.validate_time_window(now_ms)?;
        }
        if let Some(parent) = context.parent {
            self.validate_attenuation(parent)?;
        }
        Ok(())
    }
}

impl<R, V> AgentNodeBindingVerifier for ResolverBackedBindingVerifier<R, V>
where
    R: DidResolver,
    V: ProofVerifier,
{
    fn verify_agent_node_binding(&self, proof: &AgentNodeBindingProof) -> Result<()> {
        proof.validate_basic()?;
        let resolution = self.resolver.resolve(&proof.agent_did)?;
        resolution.document.validate()?;

        if let Some(reference) = &proof.proof.verification_method {
            let is_known = resolution
                .document
                .verification_method
                .iter()
                .any(|method| {
                    method.id == *reference
                        || format!("{}{}", proof.agent_did, method.id) == *reference
                });
            if !is_known {
                return Err(DidError::VerificationFailed(format!(
                    "verification method not present in agent document: {reference}"
                )));
            }
        }

        self.proof_verifier
            .verify(&proof.proof, &proof.agent_did, &resolution.document)
    }
}

impl<R, V> UcanDelegationVerifier for ResolverBackedUcanVerifier<R, V>
where
    R: DidResolver,
    V: ProofVerifier,
{
    fn verify_ucan_delegation(&self, delegation: &UcanDelegation) -> Result<()> {
        delegation.validate_basic()?;
        let resolution = self.resolver.resolve(&delegation.issuer_did)?;
        resolution.document.validate()?;
        self.proof_verifier.verify(
            &delegation.proof,
            &delegation.issuer_did,
            &resolution.document,
        )
    }
}

impl<C, P> VerifiedAgentContextVerifier for AgentPaymentContextVerifier<C, P>
where
    C: AgentNodeBindingVerifier,
    P: PaymentAccountBindingVerifier,
{
    fn verify_verified_agent_context(&self, context: &VerifiedAgentContext) -> Result<()> {
        context.validate_basic()?;
        if !context.envelope_verified {
            return Err(DidError::InvalidBindingProof(
                "verified agent context requires envelope_verified".into(),
            ));
        }
        if !context.source_node_verified {
            return Err(DidError::InvalidBindingProof(
                "verified agent context requires source_node_verified".into(),
            ));
        }
        if !context.controller_binding_verified {
            return Err(DidError::InvalidBindingProof(
                "verified agent context requires controller_binding_verified".into(),
            ));
        }
        let controller_binding = context.controller_binding_proof.as_ref().ok_or_else(|| {
            DidError::InvalidBindingProof(
                "verified agent context requires controller_binding_proof".into(),
            )
        })?;
        self.controller_binding_verifier
            .verify_agent_node_binding(controller_binding)?;

        match context.payment_account_binding.as_ref() {
            Some(payment_account_binding) => self
                .payment_account_binding_verifier
                .verify_payment_account_binding(payment_account_binding),
            None if self.require_payment_account_binding => Err(DidError::InvalidBindingProof(
                "verified agent payment context requires payment_account_binding".into(),
            )),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompactJoseEdDsaVerifier {
    options: JoseValidationOptions,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize, Default)]
struct JoseClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    aud: Option<AudienceClaim>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

impl CompactJoseEdDsaVerifier {
    pub fn new(options: JoseValidationOptions) -> Self {
        Self { options }
    }
}

impl ProofVerifier for CompactJoseEdDsaVerifier {
    fn verify(
        &self,
        proof: &ProofEnvelope,
        expected_signer: &Did,
        document: &DidDocument,
    ) -> Result<()> {
        let (header_b64, payload_b64, signature_b64) = split_compact_jws(&proof.value)?;
        let header_json = URL_SAFE_NO_PAD.decode(header_b64).map_err(|error| {
            DidError::VerificationFailed(format!("invalid jws header encoding: {error}"))
        })?;
        let header: JwsHeader = serde_json::from_slice(&header_json).map_err(|error| {
            DidError::VerificationFailed(format!("invalid jws header json: {error}"))
        })?;
        if header.alg != "EdDSA" {
            return Err(DidError::VerificationFailed(format!(
                "unsupported jws alg: {}",
                header.alg
            )));
        }

        let verification_method = resolve_verification_method(
            document,
            expected_signer,
            proof
                .verification_method
                .as_deref()
                .or(header.kid.as_deref()),
        )?;
        match proof.algorithm {
            ProofAlgorithm::Jws | ProofAlgorithm::Jwt | ProofAlgorithm::Ucan => {}
            ProofAlgorithm::Custom(_) => {
                return Err(DidError::VerificationFailed(
                    "compact jose verifier only supports jws/jwt/ucan".into(),
                ));
            }
        }
        let payload_json = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|error| {
            DidError::VerificationFailed(format!("invalid jose payload encoding: {error}"))
        })?;
        validate_jose_claims(
            &self.options,
            &payload_json,
            expected_signer,
            matches!(proof.algorithm, ProofAlgorithm::Jwt | ProofAlgorithm::Ucan),
        )?;
        let verifying_key = verifying_key_from_method(expected_signer, verification_method)?;
        let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|error| {
            DidError::VerificationFailed(format!("invalid jws signature encoding: {error}"))
        })?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|error| {
            DidError::VerificationFailed(format!("invalid jws signature bytes: {error}"))
        })?;
        let signing_input = format!("{header_b64}.{payload_b64}");
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|error| {
                DidError::VerificationFailed(format!("signature verification failed: {error}"))
            })?;
        Ok(())
    }
}

fn validate_jose_claims(
    options: &JoseValidationOptions,
    payload_json: &[u8],
    expected_signer: &Did,
    parse_claims: bool,
) -> Result<()> {
    if !parse_claims {
        return Ok(());
    }

    let claims: JoseClaims = serde_json::from_slice(payload_json).map_err(|error| {
        DidError::VerificationFailed(format!("invalid jose payload json: {error}"))
    })?;

    if options.require_exp && claims.exp.is_none() {
        return Err(DidError::VerificationFailed("missing exp claim".into()));
    }
    if options.require_sub && claims.sub.is_none() {
        return Err(DidError::VerificationFailed("missing sub claim".into()));
    }

    let expected_signer_string = expected_signer.to_string();
    let expected_issuer = options
        .expected_issuer
        .as_deref()
        .unwrap_or(expected_signer_string.as_str());
    if let Some(iss) = claims.iss.as_deref()
        && iss != expected_issuer
    {
        return Err(DidError::VerificationFailed(
            "issuer claim does not match expected signer".into(),
        ));
    }

    if let Some(expected_subject) = options.expected_subject.as_deref()
        && claims.sub.as_deref() != Some(expected_subject)
    {
        return Err(DidError::VerificationFailed(
            "subject claim mismatch".into(),
        ));
    }

    if !options.expected_audience.is_empty() {
        let audience_matches = match claims.aud {
            Some(AudienceClaim::One(ref aud)) => options.expected_audience.iter().any(|v| v == aud),
            Some(AudienceClaim::Many(ref audiences)) => options
                .expected_audience
                .iter()
                .any(|expected| audiences.iter().any(|actual| actual == expected)),
            None => false,
        };
        if !audience_matches {
            return Err(DidError::VerificationFailed(
                "audience claim mismatch".into(),
            ));
        }
    }

    if let Some(now_ms) = options.current_time_ms {
        if let Some(nbf) = claims.nbf
            && now_ms < nbf
        {
            return Err(DidError::VerificationFailed("token not active yet".into()));
        }
        if let Some(exp) = claims.exp
            && now_ms >= exp
        {
            return Err(DidError::VerificationFailed("token expired".into()));
        }
        if let Some(iat) = claims.iat
            && iat > now_ms
        {
            return Err(DidError::VerificationFailed(
                "issued-at claim is in the future".into(),
            ));
        }
    }

    Ok(())
}

fn capability_is_attenuated_by(child: &UcanCapability, parent: &UcanCapability) -> bool {
    let resource_ok = parent.resource == "*" || parent.resource == child.resource;
    let ability_ok = parent.ability == "*" || parent.ability == child.ability;
    let caveat_ok = caveat_is_attenuated_by(child.caveat.as_ref(), parent.caveat.as_ref());
    resource_ok && ability_ok && caveat_ok
}

fn caveat_is_attenuated_by(child: Option<&Value>, parent: Option<&Value>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(child), Some(parent)) => value_contains(child, parent),
    }
}

fn value_contains(child: &Value, parent: &Value) -> bool {
    match (child, parent) {
        (Value::Object(child_obj), Value::Object(parent_obj)) => {
            parent_obj.iter().all(|(key, value)| {
                child_obj
                    .get(key)
                    .is_some_and(|child_value| value_contains(child_value, value))
            })
        }
        _ => child == parent,
    }
}

fn split_compact_jws(value: &str) -> Result<(&str, &str, &str)> {
    let mut parts = value.split('.');
    let header = parts
        .next()
        .ok_or_else(|| DidError::VerificationFailed("jws missing header".into()))?;
    let payload = parts
        .next()
        .ok_or_else(|| DidError::VerificationFailed("jws missing payload".into()))?;
    let signature = parts
        .next()
        .ok_or_else(|| DidError::VerificationFailed("jws missing signature".into()))?;
    if parts.next().is_some() {
        return Err(DidError::VerificationFailed(
            "jws must have exactly three segments".into(),
        ));
    }
    if header.is_empty() || signature.is_empty() {
        return Err(DidError::VerificationFailed(
            "jws header and signature cannot be empty".into(),
        ));
    }
    Ok((header, payload, signature))
}

fn resolve_verification_method<'a>(
    document: &'a DidDocument,
    expected_signer: &Did,
    reference: Option<&str>,
) -> Result<&'a VerificationMethod> {
    if let Some(reference) = reference {
        return document
            .verification_method
            .iter()
            .find(|method| {
                method.id == reference || format!("{expected_signer}{}", method.id) == reference
            })
            .ok_or_else(|| {
                DidError::VerificationFailed(format!(
                    "verification method not found in did document: {reference}"
                ))
            });
    }

    if expected_signer.method() == "key" {
        return document.verification_method.first().ok_or_else(|| {
            DidError::VerificationFailed("did:key document has no verification methods".into())
        });
    }

    document
        .verification_method
        .iter()
        .find(|method| {
            document.authentication.iter().any(|reference| {
                reference == &method.id || format!("{expected_signer}{}", method.id) == *reference
            })
        })
        .or_else(|| document.verification_method.first())
        .ok_or_else(|| {
            DidError::VerificationFailed("did document has no verification methods".into())
        })
}

fn verifying_key_from_method(
    expected_signer: &Did,
    method: &VerificationMethod,
) -> Result<VerifyingKey> {
    if let Some(multibase) = &method.public_key_multibase {
        let did_key = DidKey::from_did(Did::parse(&format!("did:key:{multibase}"))?)?;
        match did_key.decode_public_key()? {
            DidKeyPublicKey::Ed25519(bytes) => {
                return VerifyingKey::from_bytes(&bytes).map_err(|error| {
                    DidError::VerificationFailed(format!("invalid ed25519 key bytes: {error}"))
                });
            }
            DidKeyPublicKey::X25519(_) | DidKeyPublicKey::Secp256k1Compressed(_) => {
                return Err(DidError::VerificationFailed(
                    "verification method key type is not supported for EdDSA verification".into(),
                ));
            }
        }
    }

    if expected_signer.method() == "key" {
        let did_key = DidKey::from_did(expected_signer.clone())?;
        match did_key.decode_public_key()? {
            DidKeyPublicKey::Ed25519(bytes) => {
                return VerifyingKey::from_bytes(&bytes).map_err(|error| {
                    DidError::VerificationFailed(format!("invalid ed25519 key bytes: {error}"))
                });
            }
            DidKeyPublicKey::X25519(_) | DidKeyPublicKey::Secp256k1Compressed(_) => {
                return Err(DidError::VerificationFailed(
                    "did:key is not an Ed25519 verification key".into(),
                ));
            }
        }
    }

    Err(DidError::VerificationFailed(
        "verification method does not expose supported public key material".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::DidDocument;
    use crate::resolver::{DidResolutionMetadata, DidResolutionResult, StaticDidResolver};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Debug, Clone, Default)]
    struct AcceptAllProofVerifier;

    impl ProofVerifier for AcceptAllProofVerifier {
        fn verify(
            &self,
            proof: &ProofEnvelope,
            _expected_signer: &Did,
            _document: &DidDocument,
        ) -> Result<()> {
            if proof.value.trim().is_empty() {
                return Err(DidError::VerificationFailed(
                    "proof value cannot be empty".into(),
                ));
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Default)]
    struct AcceptControllerBindingVerifier;

    impl AgentNodeBindingVerifier for AcceptControllerBindingVerifier {
        fn verify_agent_node_binding(&self, proof: &AgentNodeBindingProof) -> Result<()> {
            proof.validate_basic()
        }
    }

    #[derive(Debug, Clone, Default)]
    struct AcceptPaymentAccountBindingVerifier;

    impl PaymentAccountBindingVerifier for AcceptPaymentAccountBindingVerifier {
        fn verify_payment_account_binding(&self, proof: &PaymentAccountBindingProof) -> Result<()> {
            proof.validate_basic()
        }
    }

    #[test]
    fn validates_basic_binding_proof() {
        let proof = AgentNodeBindingProof {
            agent_did: Did::parse("did:web:example.com:agents:alice").unwrap(),
            node_did: None,
            node_peer_id: Some("12D3KooWExample".into()),
            node_public_key_multibase: None,
            wallet_did: None,
            capabilities: vec!["invoke".into()],
            issued_at_ms: 100,
            expires_at_ms: Some(200),
            nonce: Some("n-1".into()),
            proof: ProofEnvelope {
                algorithm: ProofAlgorithm::Jws,
                value: "eyJhbGciOiJFZERTQSJ9..sig".into(),
                verification_method: Some("#sig-1".into()),
                challenge: None,
                nonce: None,
                created_at: None,
                expires_at: None,
            },
        };

        assert!(proof.validate_basic().is_ok());
    }

    #[test]
    fn rejects_binding_without_node_target() {
        let proof = AgentNodeBindingProof {
            agent_did: Did::parse("did:web:example.com:agents:alice").unwrap(),
            node_did: None,
            node_peer_id: None,
            node_public_key_multibase: None,
            wallet_did: None,
            capabilities: vec![],
            issued_at_ms: 100,
            expires_at_ms: None,
            nonce: None,
            proof: ProofEnvelope {
                algorithm: ProofAlgorithm::Jws,
                value: "sig".into(),
                verification_method: None,
                challenge: None,
                nonce: None,
                created_at: None,
                expires_at: None,
            },
        };

        assert!(matches!(
            proof.validate_basic(),
            Err(DidError::InvalidBindingProof(_))
        ));
    }

    fn sample_proof(value: &str) -> ProofEnvelope {
        ProofEnvelope {
            algorithm: ProofAlgorithm::Jws,
            value: value.into(),
            verification_method: Some("#sig-1".into()),
            challenge: None,
            nonce: None,
            created_at: None,
            expires_at: None,
        }
    }

    fn sample_payment_account_proof() -> PaymentAccountBindingProof {
        PaymentAccountBindingProof {
            agent_did: Did::parse("did:web:example.com:agents:alice").unwrap(),
            payment_address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".into(),
            rail: "x402".into(),
            network: Some("base-sepolia".into()),
            custody: PaymentAccountCustody::ImportedKey,
            receive_only: false,
            can_sign: true,
            capabilities: vec!["authorize_payment".into(), "submit_payment".into()],
            issued_at_ms: 100,
            expires_at_ms: Some(200),
            nonce: Some("n-1".into()),
            agent_proof: sample_proof("agent-sig"),
            payment_account_proof: Some(ProofEnvelope {
                challenge: Some("bind did:web:example.com:agents:alice to 0x742d".into()),
                ..sample_proof("payment-account-sig")
            }),
        }
    }

    fn sample_verified_agent_context(
        payment_account_binding: Option<PaymentAccountBindingProof>,
    ) -> VerifiedAgentContext {
        let agent_did = Did::parse("did:web:example.com:agents:alice").unwrap();
        let controller_binding_proof = AgentNodeBindingProof {
            agent_did: agent_did.clone(),
            node_did: None,
            node_peer_id: Some("12D3KooWExample".into()),
            node_public_key_multibase: None,
            wallet_did: None,
            capabilities: vec!["invoke".into()],
            issued_at_ms: 100,
            expires_at_ms: Some(200),
            nonce: None,
            proof: sample_proof("controller-sig"),
        };
        VerifiedAgentContext {
            agent_did,
            controller_node_id: "12D3KooWExample".into(),
            source_node_id: Some("12D3KooWExample".into()),
            envelope_verified: true,
            source_node_verified: true,
            controller_binding_verified: true,
            controller_binding_proof: Some(controller_binding_proof),
            payment_account_binding,
            verified_at_ms: 150,
            expires_at_ms: Some(190),
        }
    }

    #[test]
    fn validates_payment_account_binding_for_spending_wallet() {
        let proof = sample_payment_account_proof();

        assert!(proof.validate_basic().is_ok());
    }

    #[test]
    fn rejects_payment_account_binding_without_account_control_proof() {
        let mut proof = sample_payment_account_proof();
        proof.payment_account_proof = None;

        assert!(matches!(
            proof.validate_basic(),
            Err(DidError::InvalidBindingProof(_))
        ));
    }

    #[test]
    fn validates_watch_only_payment_account_as_receive_only() {
        let proof = PaymentAccountBindingProof {
            agent_did: Did::parse("did:web:example.com:agents:alice").unwrap(),
            payment_address: "0x122F8Fcaf2152420445Aa424E1D8C0306935B5c9".into(),
            rail: "x402".into(),
            network: Some("base-sepolia".into()),
            custody: PaymentAccountCustody::WatchOnly,
            receive_only: true,
            can_sign: false,
            capabilities: vec!["receive_payment".into()],
            issued_at_ms: 100,
            expires_at_ms: None,
            nonce: None,
            agent_proof: sample_proof("agent-sig"),
            payment_account_proof: None,
        };

        assert!(proof.validate_basic().is_ok());
    }

    #[test]
    fn rejects_watch_only_payment_account_that_can_sign() {
        let mut proof = PaymentAccountBindingProof {
            agent_did: Did::parse("did:web:example.com:agents:alice").unwrap(),
            payment_address: "0x122F8Fcaf2152420445Aa424E1D8C0306935B5c9".into(),
            rail: "x402".into(),
            network: Some("base-sepolia".into()),
            custody: PaymentAccountCustody::WatchOnly,
            receive_only: true,
            can_sign: true,
            capabilities: vec!["receive_payment".into()],
            issued_at_ms: 100,
            expires_at_ms: None,
            nonce: None,
            agent_proof: sample_proof("agent-sig"),
            payment_account_proof: None,
        };

        assert!(matches!(
            proof.validate_basic(),
            Err(DidError::InvalidBindingProof(_))
        ));
        proof.can_sign = false;
        assert!(proof.validate_basic().is_ok());
    }

    #[test]
    fn validates_verified_agent_context_with_controller_and_payment_binding() {
        let context = sample_verified_agent_context(Some(sample_payment_account_proof()));

        assert!(context.validate_basic().is_ok());
    }

    #[test]
    fn verifies_agent_payment_context_chain() {
        let context = sample_verified_agent_context(Some(sample_payment_account_proof()));
        let verifier = AgentPaymentContextVerifier::new(
            AcceptControllerBindingVerifier,
            AcceptPaymentAccountBindingVerifier,
        );

        verifier.verify_verified_agent_context(&context).unwrap();
    }

    #[test]
    fn rejects_agent_payment_context_without_required_payment_binding() {
        let context = sample_verified_agent_context(None);
        let verifier = AgentPaymentContextVerifier::new(
            AcceptControllerBindingVerifier,
            AcceptPaymentAccountBindingVerifier,
        );

        assert!(matches!(
            verifier.verify_verified_agent_context(&context),
            Err(DidError::InvalidBindingProof(_))
        ));
    }

    #[test]
    fn optionally_verifies_agent_context_without_payment_binding() {
        let context = sample_verified_agent_context(None);
        let verifier = AgentPaymentContextVerifier::with_optional_payment_binding(
            AcceptControllerBindingVerifier,
            AcceptPaymentAccountBindingVerifier,
        );

        verifier.verify_verified_agent_context(&context).unwrap();
    }

    #[test]
    fn rejects_verified_agent_context_source_controller_mismatch() {
        let context = VerifiedAgentContext {
            agent_did: Did::parse("did:web:example.com:agents:alice").unwrap(),
            controller_node_id: "12D3KooController".into(),
            source_node_id: Some("12D3KooSource".into()),
            envelope_verified: true,
            source_node_verified: true,
            controller_binding_verified: false,
            controller_binding_proof: None,
            payment_account_binding: None,
            verified_at_ms: 150,
            expires_at_ms: None,
        };

        assert!(matches!(
            context.validate_basic(),
            Err(DidError::InvalidBindingProof(_))
        ));
    }

    #[test]
    fn resolver_backed_verifier_checks_document_reference() {
        let agent_did = Did::parse("did:web:example.com:agents:alice").unwrap();
        let mut document = DidDocument::new(agent_did.clone());
        document
            .verification_method
            .push(crate::document::VerificationMethod {
                id: "#sig-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: agent_did.to_string(),
                public_key_multibase: Some(
                    "z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S".into(),
                ),
                public_key_jwk: None,
                blockchain_account_id: None,
            });
        document.authentication.push("#sig-1".into());

        let mut resolver = StaticDidResolver::new();
        resolver.insert(DidResolutionResult {
            metadata: DidResolutionMetadata::default(),
            document,
            document_metadata: crate::resolver::DidDocumentMetadata::default(),
        });

        let verifier = ResolverBackedBindingVerifier::new(resolver, AcceptAllProofVerifier);
        let proof = AgentNodeBindingProof {
            agent_did,
            node_did: None,
            node_peer_id: Some("12D3KooWExample".into()),
            node_public_key_multibase: None,
            wallet_did: None,
            capabilities: vec!["invoke".into()],
            issued_at_ms: 100,
            expires_at_ms: Some(200),
            nonce: None,
            proof: ProofEnvelope {
                algorithm: ProofAlgorithm::Jws,
                value: "sig".into(),
                verification_method: Some("#sig-1".into()),
                challenge: None,
                nonce: None,
                created_at: None,
                expires_at: None,
            },
        };

        assert!(verifier.verify_agent_node_binding(&proof).is_ok());
    }

    #[test]
    fn compact_jose_verifier_accepts_valid_signature() {
        let agent_did = Did::parse("did:web:example.com:agents:alice").unwrap();
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut multibase_bytes = vec![0xed, 0x01];
        multibase_bytes.extend_from_slice(verifying_key.as_bytes());
        let multibase = format!("z{}", bs58::encode(multibase_bytes).into_string());

        let mut document = DidDocument::new(agent_did.clone());
        document
            .verification_method
            .push(crate::document::VerificationMethod {
                id: "#sig-1".into(),
                method_type: "Multikey".into(),
                controller: agent_did.to_string(),
                public_key_multibase: Some(multibase),
                public_key_jwk: None,
                blockchain_account_id: None,
            });
        document.authentication.push("#sig-1".into());

        let header = URL_SAFE_NO_PAD.encode(r##"{"alg":"EdDSA","kid":"#sig-1"}"##);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"hello":"world"}"#);
        let signing_input = format!("{header}.{payload}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let compact_jws = format!(
            "{header}.{payload}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );

        let verifier = CompactJoseEdDsaVerifier::default();
        let proof = ProofEnvelope {
            algorithm: ProofAlgorithm::Jws,
            value: compact_jws,
            verification_method: Some("#sig-1".into()),
            challenge: None,
            nonce: None,
            created_at: None,
            expires_at: None,
        };

        assert!(verifier.verify(&proof, &agent_did, &document).is_ok());
    }

    #[test]
    fn resolver_backed_ucan_verifier_checks_issuer_document() {
        let issuer_did = Did::parse("did:web:example.com:agents:issuer").unwrap();
        let mut document = DidDocument::new(issuer_did.clone());
        document
            .verification_method
            .push(crate::document::VerificationMethod {
                id: "#sig-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: issuer_did.to_string(),
                public_key_multibase: Some(
                    "z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S".into(),
                ),
                public_key_jwk: None,
                blockchain_account_id: None,
            });
        document.authentication.push("#sig-1".into());

        let mut resolver = StaticDidResolver::new();
        resolver.insert(DidResolutionResult {
            metadata: DidResolutionMetadata::default(),
            document,
            document_metadata: crate::resolver::DidDocumentMetadata::default(),
        });

        let verifier = ResolverBackedUcanVerifier::new(resolver, AcceptAllProofVerifier);
        let delegation = UcanDelegation {
            issuer_did,
            audience_did: Did::parse("did:web:example.com:agents:audience").unwrap(),
            capabilities: vec![UcanCapability {
                resource: "urn:watt:task".into(),
                ability: "invoke".into(),
                caveat: None,
            }],
            issued_at_ms: 100,
            not_before_ms: Some(100),
            expires_at_ms: Some(200),
            facts: vec![],
            proof: ProofEnvelope {
                algorithm: ProofAlgorithm::Ucan,
                value: "header.payload.sig".into(),
                verification_method: Some("#sig-1".into()),
                challenge: None,
                nonce: None,
                created_at: None,
                expires_at: None,
            },
        };

        assert!(verifier.verify_ucan_delegation(&delegation).is_ok());
    }

    #[test]
    fn jwt_claims_are_validated() {
        let agent_did = Did::parse("did:web:example.com:agents:alice").unwrap();
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut multibase_bytes = vec![0xed, 0x01];
        multibase_bytes.extend_from_slice(verifying_key.as_bytes());
        let multibase = format!("z{}", bs58::encode(multibase_bytes).into_string());

        let mut document = DidDocument::new(agent_did.clone());
        document
            .verification_method
            .push(crate::document::VerificationMethod {
                id: "#sig-1".into(),
                method_type: "Multikey".into(),
                controller: agent_did.to_string(),
                public_key_multibase: Some(multibase),
                public_key_jwk: None,
                blockchain_account_id: None,
            });
        document.authentication.push("#sig-1".into());

        let header = URL_SAFE_NO_PAD.encode(r##"{"alg":"EdDSA","kid":"#sig-1"}"##);
        let payload = URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"iss":"{agent_did}","sub":"session-1","aud":["wattetheria"],"iat":100,"nbf":100,"exp":200}}"#
            ),
        );
        let signing_input = format!("{header}.{payload}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let compact_jwt = format!(
            "{header}.{payload}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        let verifier = CompactJoseEdDsaVerifier::new(JoseValidationOptions {
            expected_issuer: Some(agent_did.to_string()),
            expected_subject: Some("session-1".into()),
            expected_audience: vec!["wattetheria".into()],
            current_time_ms: Some(150),
            require_exp: true,
            require_sub: true,
        });
        let proof = ProofEnvelope {
            algorithm: ProofAlgorithm::Jwt,
            value: compact_jwt,
            verification_method: Some("#sig-1".into()),
            challenge: None,
            nonce: None,
            created_at: None,
            expires_at: None,
        };

        assert!(verifier.verify(&proof, &agent_did, &document).is_ok());
    }

    #[test]
    fn ucan_child_must_attenuate_parent() {
        let parent = UcanDelegation {
            issuer_did: Did::parse("did:web:example.com:agents:root").unwrap(),
            audience_did: Did::parse("did:web:example.com:agents:child").unwrap(),
            capabilities: vec![UcanCapability {
                resource: "urn:watt:task".into(),
                ability: "invoke".into(),
                caveat: Some(serde_json::json!({"scope":"team-a"})),
            }],
            issued_at_ms: 100,
            not_before_ms: Some(100),
            expires_at_ms: Some(300),
            facts: vec![],
            proof: ProofEnvelope {
                algorithm: ProofAlgorithm::Ucan,
                value: "a.b.c".into(),
                verification_method: None,
                challenge: None,
                nonce: None,
                created_at: None,
                expires_at: None,
            },
        };
        let child = UcanDelegation {
            issuer_did: Did::parse("did:web:example.com:agents:child").unwrap(),
            audience_did: Did::parse("did:web:example.com:agents:worker").unwrap(),
            capabilities: vec![UcanCapability {
                resource: "urn:watt:task".into(),
                ability: "invoke".into(),
                caveat: Some(serde_json::json!({"scope":"team-a","region":"au"})),
            }],
            issued_at_ms: 120,
            not_before_ms: Some(120),
            expires_at_ms: Some(200),
            facts: vec![],
            proof: ProofEnvelope {
                algorithm: ProofAlgorithm::Ucan,
                value: "a.b.c".into(),
                verification_method: None,
                challenge: None,
                nonce: None,
                created_at: None,
                expires_at: None,
            },
        };

        assert!(
            child
                .validate_with_context(UcanVerificationContext {
                    now_ms: Some(150),
                    parent: Some(&parent),
                })
                .is_ok()
        );
    }

    #[test]
    fn ucan_child_cannot_expand_parent_scope() {
        let parent = UcanDelegation {
            issuer_did: Did::parse("did:web:example.com:agents:root").unwrap(),
            audience_did: Did::parse("did:web:example.com:agents:child").unwrap(),
            capabilities: vec![UcanCapability {
                resource: "urn:watt:task".into(),
                ability: "invoke".into(),
                caveat: Some(serde_json::json!({"scope":"team-a"})),
            }],
            issued_at_ms: 100,
            not_before_ms: None,
            expires_at_ms: Some(300),
            facts: vec![],
            proof: ProofEnvelope {
                algorithm: ProofAlgorithm::Ucan,
                value: "a.b.c".into(),
                verification_method: None,
                challenge: None,
                nonce: None,
                created_at: None,
                expires_at: None,
            },
        };
        let child = UcanDelegation {
            issuer_did: Did::parse("did:web:example.com:agents:child").unwrap(),
            audience_did: Did::parse("did:web:example.com:agents:worker").unwrap(),
            capabilities: vec![UcanCapability {
                resource: "urn:watt:task".into(),
                ability: "invoke".into(),
                caveat: Some(serde_json::json!({"scope":"team-b"})),
            }],
            issued_at_ms: 120,
            not_before_ms: None,
            expires_at_ms: Some(200),
            facts: vec![],
            proof: ProofEnvelope {
                algorithm: ProofAlgorithm::Ucan,
                value: "a.b.c".into(),
                verification_method: None,
                challenge: None,
                nonce: None,
                created_at: None,
                expires_at: None,
            },
        };

        assert!(
            child
                .validate_with_context(UcanVerificationContext {
                    now_ms: Some(150),
                    parent: Some(&parent),
                })
                .is_err()
        );
    }
}
