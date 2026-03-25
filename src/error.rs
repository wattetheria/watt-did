use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidError {
    #[error("invalid did syntax: {0}")]
    InvalidDidSyntax(String),
    #[error("invalid did url syntax: {0}")]
    InvalidDidUrl(String),
    #[error("unsupported did method: {0}")]
    UnsupportedMethod(String),
    #[error("invalid did method: {0}")]
    InvalidMethod(String),
    #[error("invalid method-specific identifier: {0}")]
    InvalidMethodSpecificId(String),
    #[error("invalid did:key value: {0}")]
    InvalidDidKey(String),
    #[error("invalid did:web value: {0}")]
    InvalidDidWeb(String),
    #[error("invalid percent encoding: {0}")]
    InvalidPercentEncoding(String),
    #[error("invalid did document: {0}")]
    InvalidDocument(String),
    #[error("invalid jwk: {0}")]
    InvalidJwk(String),
    #[error("invalid verification method reference: {0}")]
    InvalidVerificationMethodReference(String),
    #[error("invalid binding proof: {0}")]
    InvalidBindingProof(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

pub type Result<T> = std::result::Result<T, DidError>;
