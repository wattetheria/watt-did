use crate::did::Did;
use crate::document::DidDocument;
use crate::error::{DidError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DidResolutionMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieved_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidResolutionResult {
    pub document: DidDocument,
    #[serde(default)]
    pub metadata: DidResolutionMetadata,
}

pub trait DidResolver {
    fn resolve(&self, did: &Did) -> Result<DidResolutionResult>;
}

pub trait DidResolutionCache {
    fn get(&self, did: &Did) -> Option<DidResolutionResult>;
    fn put(&self, did: &Did, result: &DidResolutionResult);
}

pub trait DidDocumentFetcher {
    fn fetch_document(&self, url: &str) -> Result<FetchedDidDocument>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedDidDocument {
    pub body: String,
    pub content_type: Option<String>,
    pub etag: Option<String>,
}

#[derive(Debug, Default)]
pub struct InMemoryDidResolutionCache {
    entries: Mutex<HashMap<Did, DidResolutionResult>>,
}

#[derive(Debug, Clone)]
pub struct CachedDidResolver<R, C> {
    inner: R,
    cache: C,
}

#[derive(Debug, Clone)]
pub struct FallbackDidResolver<A, B> {
    primary: A,
    secondary: B,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidWebResolverOptions {
    pub max_document_bytes: usize,
    pub require_tls_except_loopback: bool,
}

impl Default for DidWebResolverOptions {
    fn default() -> Self {
        Self {
            max_document_bytes: 512 * 1024,
            require_tls_except_loopback: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StaticDidResolver {
    documents: HashMap<Did, DidResolutionResult>,
}

#[derive(Debug, Clone)]
pub struct StaticDidDocumentFetcher {
    body: String,
    content_type: Option<String>,
    etag: Option<String>,
}

impl StaticDidResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, result: DidResolutionResult) {
        self.documents.insert(result.document.id.clone(), result);
    }
}

impl InMemoryDidResolutionCache {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DidResolutionCache for InMemoryDidResolutionCache {
    fn get(&self, did: &Did) -> Option<DidResolutionResult> {
        self.entries.lock().ok()?.get(did).cloned()
    }

    fn put(&self, did: &Did, result: &DidResolutionResult) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(did.clone(), result.clone());
        }
    }
}

impl<R, C> CachedDidResolver<R, C> {
    pub fn new(inner: R, cache: C) -> Self {
        Self { inner, cache }
    }
}

impl<A, B> FallbackDidResolver<A, B> {
    pub fn new(primary: A, secondary: B) -> Self {
        Self { primary, secondary }
    }
}

impl<R, C> DidResolver for CachedDidResolver<R, C>
where
    R: DidResolver,
    C: DidResolutionCache,
{
    fn resolve(&self, did: &Did) -> Result<DidResolutionResult> {
        if let Some(cached) = self.cache.get(did) {
            return Ok(cached);
        }
        let resolved = self.inner.resolve(did)?;
        self.cache.put(did, &resolved);
        Ok(resolved)
    }
}

impl<A, B> DidResolver for FallbackDidResolver<A, B>
where
    A: DidResolver,
    B: DidResolver,
{
    fn resolve(&self, did: &Did) -> Result<DidResolutionResult> {
        self.primary
            .resolve(did)
            .or_else(|_| self.secondary.resolve(did))
    }
}

impl StaticDidDocumentFetcher {
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            content_type: Some("application/did+json".into()),
            etag: Some("static".into()),
        }
    }

    pub fn with_metadata(
        body: impl Into<String>,
        content_type: Option<String>,
        etag: Option<String>,
    ) -> Self {
        Self {
            body: body.into(),
            content_type,
            etag,
        }
    }
}

impl DidDocumentFetcher for StaticDidDocumentFetcher {
    fn fetch_document(&self, _url: &str) -> Result<FetchedDidDocument> {
        Ok(FetchedDidDocument {
            body: self.body.clone(),
            content_type: self.content_type.clone(),
            etag: self.etag.clone(),
        })
    }
}

impl DidResolver for StaticDidResolver {
    fn resolve(&self, did: &Did) -> Result<DidResolutionResult> {
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| DidError::VerificationFailed(format!("did not found: {did}")))
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReqwestDidDocumentFetcher;

impl DidDocumentFetcher for ReqwestDidDocumentFetcher {
    fn fetch_document(&self, url: &str) -> Result<FetchedDidDocument> {
        let response = reqwest::blocking::get(url)
            .map_err(|error| DidError::VerificationFailed(format!("fetch failed: {error}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(DidError::VerificationFailed(format!(
                "fetch failed with status {status}"
            )));
        }
        let headers = response.headers().clone();
        let content_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_owned());
        let etag = headers
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_owned());
        let body = response
            .text()
            .map_err(|error| DidError::VerificationFailed(format!("read body failed: {error}")))?;
        Ok(FetchedDidDocument {
            body,
            content_type,
            etag,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DidWebResolver<F = ReqwestDidDocumentFetcher> {
    fetcher: F,
    options: DidWebResolverOptions,
}

impl Default for DidWebResolver<ReqwestDidDocumentFetcher> {
    fn default() -> Self {
        Self::new(ReqwestDidDocumentFetcher)
    }
}

impl<F> DidWebResolver<F> {
    pub fn new(fetcher: F) -> Self {
        Self {
            fetcher,
            options: DidWebResolverOptions::default(),
        }
    }

    pub fn with_options(fetcher: F, options: DidWebResolverOptions) -> Self {
        Self { fetcher, options }
    }
}

impl<F> DidResolver for DidWebResolver<F>
where
    F: DidDocumentFetcher,
{
    fn resolve(&self, did: &Did) -> Result<DidResolutionResult> {
        let did_web = crate::methods::DidWeb::from_did(did.clone())?;
        let url = did_web.to_url();
        if self.options.require_tls_except_loopback
            && url.starts_with("http://")
            && !(did_web.host.starts_with("localhost")
                || did_web.host.starts_with("127.0.0.1")
                || did_web.host.starts_with("[::1]"))
        {
            return Err(DidError::InvalidDidWeb(
                "did:web resolver refuses insecure http for non-loopback hosts".into(),
            ));
        }

        let fetched = self.fetcher.fetch_document(&url)?;
        if fetched.body.len() > self.options.max_document_bytes {
            return Err(DidError::InvalidDocument(format!(
                "did document exceeds max size of {} bytes",
                self.options.max_document_bytes
            )));
        }
        let document: DidDocument = serde_json::from_str(&fetched.body).map_err(|error| {
            DidError::InvalidDocument(format!("invalid did document json: {error}"))
        })?;
        if document.id != *did {
            return Err(DidError::InvalidDocument(format!(
                "resolved did document id mismatch: expected {did}, got {}",
                document.id
            )));
        }
        document.validate()?;
        Ok(DidResolutionResult {
            document,
            metadata: DidResolutionMetadata {
                content_type: fetched
                    .content_type
                    .or_else(|| Some("application/did+json".into())),
                source_url: Some(url),
                etag: fetched.etag,
                retrieved_at_ms: None,
                version_id: None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::DidDocument;

    #[test]
    fn static_resolver_returns_registered_document() {
        let did = Did::parse("did:web:example.com").unwrap();
        let document = DidDocument::new(did.clone());
        let mut resolver = StaticDidResolver::new();
        resolver.insert(DidResolutionResult {
            document,
            metadata: DidResolutionMetadata {
                content_type: Some("application/did+json".into()),
                source_url: None,
                etag: None,
                retrieved_at_ms: Some(123),
                version_id: None,
            },
        });

        let resolved = resolver.resolve(&did).unwrap();
        assert_eq!(resolved.document.id, did);
        assert_eq!(
            resolved.metadata.content_type.as_deref(),
            Some("application/did+json")
        );
        assert_eq!(resolved.metadata.source_url.as_deref(), None);
    }

    #[test]
    fn did_web_resolver_parses_document_from_fetcher() {
        let did = Did::parse("did:web:example.com:agents:alice").unwrap();
        let document = DidDocument::new(did.clone());
        let resolver = DidWebResolver::new(StaticDidDocumentFetcher::with_metadata(
            serde_json::to_string(&document).unwrap(),
            Some("application/did+json".into()),
            Some("etag-1".into()),
        ));

        let resolved = resolver.resolve(&did).unwrap();
        assert_eq!(resolved.document.id, did);
        assert_eq!(
            resolved.metadata.content_type.as_deref(),
            Some("application/did+json")
        );
        assert_eq!(
            resolved.metadata.source_url.as_deref(),
            Some("https://example.com/agents/alice/did.json")
        );
        assert_eq!(resolved.metadata.etag.as_deref(), Some("etag-1"));
    }

    #[test]
    fn did_web_resolver_rejects_oversized_document() {
        let did = Did::parse("did:web:example.com").unwrap();
        let resolver = DidWebResolver::with_options(
            StaticDidDocumentFetcher::new("x".repeat(32)),
            DidWebResolverOptions {
                max_document_bytes: 4,
                require_tls_except_loopback: true,
            },
        );

        let err = resolver.resolve(&did).unwrap_err();
        assert!(matches!(err, DidError::InvalidDocument(_)));
    }

    #[test]
    fn cached_resolver_returns_cached_copy_after_first_fetch() {
        let did = Did::parse("did:web:example.com").unwrap();
        let document = DidDocument::new(did.clone());
        let resolver = DidWebResolver::new(StaticDidDocumentFetcher::new(
            serde_json::to_string(&document).unwrap(),
        ));
        let cached = CachedDidResolver::new(resolver, InMemoryDidResolutionCache::new());
        let first = cached.resolve(&did).unwrap();
        let second = cached.resolve(&did).unwrap();
        assert_eq!(first.document.id, second.document.id);
    }

    #[test]
    fn fallback_resolver_uses_secondary_when_primary_misses() {
        let did = Did::parse("did:web:example.com").unwrap();
        let document = DidDocument::new(did.clone());
        let primary = StaticDidResolver::new();
        let mut secondary = StaticDidResolver::new();
        secondary.insert(DidResolutionResult {
            document,
            metadata: DidResolutionMetadata::default(),
        });

        let resolver = FallbackDidResolver::new(primary, secondary);
        let resolved = resolver.resolve(&did).unwrap();
        assert_eq!(resolved.document.id, did);
    }
}
