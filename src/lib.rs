pub mod did;
pub mod document;
pub mod error;
pub mod jwk;
pub mod methods;
pub mod proof;
pub mod resolver;

pub use crate::did::{Did, DidUrl};
pub use crate::document::{
    AgentDocumentType, DidDocument, DidDocumentBuilder, Service, ServiceEndpoint,
    VerificationMethod, VerificationRelationship,
};
pub use crate::error::{DidError, Result};
pub use crate::jwk::{JsonWebKey, JwkPublicKey};
pub use crate::methods::{DidKey, DidKeyPublicKey, DidWeb};
pub use crate::proof::{
    AgentNodeBindingProof, AgentNodeBindingVerifier, AgentPaymentContextVerifier,
    CompactJoseEdDsaVerifier, JoseValidationOptions, PaymentAccountBindingProof,
    PaymentAccountBindingVerifier, PaymentAccountCustody, ProofAlgorithm, ProofEnvelope,
    ResolverBackedUcanVerifier, UcanCapability, UcanDelegation, UcanDelegationVerifier,
    UcanVerificationContext, VerifiedAgentContext, VerifiedAgentContextVerifier,
};
pub use crate::resolver::{
    CachedDidResolver, DidDocumentMetadata, DidResolutionCache, DidResolutionMetadata,
    DidResolutionResult, DidResolver, DidWebResolver, DidWebResolverOptions, FallbackDidResolver,
    InMemoryDidResolutionCache, StaticDidDocumentFetcher, StaticDidResolver,
};
