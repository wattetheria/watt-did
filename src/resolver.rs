use crate::did::{Did, DidUrl};
use crate::document::{DidDocument, VerificationMethod, VerificationRelationship};
use crate::error::{DidError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DidResolutionMetadata {
    #[serde(
        default,
        alias = "content_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    #[serde(default, alias = "source_url", skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(
        default,
        alias = "retrieved_at_ms",
        skip_serializing_if = "Option::is_none"
    )]
    pub retrieved_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
    #[serde(default, alias = "version_id", skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub equivalent_id: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidResolutionResult {
    #[serde(rename = "didResolutionMetadata", alias = "metadata", default)]
    pub metadata: DidResolutionMetadata,
    #[serde(rename = "didDocument", alias = "document")]
    pub document: DidDocument,
    #[serde(rename = "didDocumentMetadata", default)]
    pub document_metadata: DidDocumentMetadata,
}

impl DidResolutionResult {
    pub fn verification_method(
        &self,
        reference: &DidUrl,
        relationship: Option<VerificationRelationship>,
    ) -> Result<VerificationMethod> {
        if self.document_metadata.deactivated == Some(true) {
            return Err(DidError::DeactivatedDid(self.document.id.to_string()));
        }
        if reference.did() != &self.document.id
            || reference.path().is_some()
            || reference.query().is_some()
            || reference.fragment().is_none()
        {
            return Err(DidError::InvalidVerificationMethodReference(
                reference.to_string(),
            ));
        }
        let reference_value = reference.to_string();
        let method = self
            .document
            .verification_method_by_reference(&reference_value)
            .ok_or_else(|| DidError::InvalidVerificationMethodReference(reference_value.clone()))?;
        if let Some(relationship) = relationship
            && !self
                .document
                .has_relationship(relationship, &reference_value)
        {
            return Err(DidError::VerificationRelationshipMismatch {
                reference: reference_value,
                relationship,
            });
        }
        Ok(method.clone())
    }
}

pub trait DidResolver {
    fn resolve(&self, did: &Did) -> Result<DidResolutionResult>;
}

#[derive(Clone, Default)]
pub struct DidResolverRegistry {
    resolvers: BTreeMap<String, Arc<dyn DidResolver + Send + Sync>>,
}

impl Debug for DidResolverRegistry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DidResolverRegistry")
            .field("methods", &self.resolvers.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DidKeyResolver;

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

#[derive(Debug)]
pub struct InMemoryDidResolutionCache {
    entries: Mutex<HashMap<Did, CachedDidResolution>>,
    ttl: Duration,
}

#[derive(Debug)]
struct CachedDidResolution {
    inserted_at: Instant,
    result: DidResolutionResult,
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

impl DidResolverRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_default_methods() -> Self {
        let mut registry = Self::new();
        registry
            .register("key", DidKeyResolver)
            .expect("built-in did:key method name must be valid");
        registry
            .register("web", DidWebResolver::default())
            .expect("built-in did:web method name must be valid");
        registry
    }

    pub fn register(
        &mut self,
        method: &str,
        resolver: impl DidResolver + Send + Sync + 'static,
    ) -> Result<()> {
        validate_method_name(method)?;
        if self.resolvers.contains_key(method) {
            return Err(DidError::ResolverAlreadyRegistered(method.to_owned()));
        }
        self.resolvers.insert(method.to_owned(), Arc::new(resolver));
        Ok(())
    }

    #[must_use]
    pub fn supports(&self, method: &str) -> bool {
        self.resolvers.contains_key(method)
    }

    pub fn resolve_verification_method(
        &self,
        reference: &DidUrl,
        relationship: Option<VerificationRelationship>,
    ) -> Result<VerificationMethod> {
        let result = self.resolve(reference.did())?;
        result.verification_method(reference, relationship)
    }
}

impl DidResolver for DidResolverRegistry {
    fn resolve(&self, did: &Did) -> Result<DidResolutionResult> {
        self.resolvers
            .get(did.method())
            .ok_or_else(|| DidError::UnsupportedMethod(did.method().to_owned()))?
            .resolve(did)
    }
}

impl DidResolver for DidKeyResolver {
    fn resolve(&self, did: &Did) -> Result<DidResolutionResult> {
        let document = crate::methods::DidKey::from_did(did.clone())?.to_document()?;
        Ok(DidResolutionResult {
            metadata: DidResolutionMetadata {
                content_type: Some("application/did+json".to_owned()),
                ..DidResolutionMetadata::default()
            },
            document,
            document_metadata: DidDocumentMetadata::default(),
        })
    }
}

fn validate_method_name(method: &str) -> Result<()> {
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(DidError::InvalidMethod(method.to_owned()));
    }
    Ok(())
}

impl InMemoryDidResolutionCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }
}

impl Default for InMemoryDidResolutionCache {
    fn default() -> Self {
        Self::with_ttl(Duration::from_secs(300))
    }
}

impl DidResolutionCache for InMemoryDidResolutionCache {
    fn get(&self, did: &Did) -> Option<DidResolutionResult> {
        let mut entries = self.entries.lock().ok()?;
        let entry = entries.get(did)?;
        if entry.inserted_at.elapsed() >= self.ttl {
            entries.remove(did);
            return None;
        }
        Some(entry.result.clone())
    }

    fn put(&self, did: &Did, result: &DidResolutionResult) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                did.clone(),
                CachedDidResolution {
                    inserted_at: Instant::now(),
                    result: result.clone(),
                },
            );
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

#[derive(Debug, Clone)]
pub struct ReqwestDidDocumentFetcher {
    max_response_bytes: usize,
    allow_private_network: bool,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl Default for ReqwestDidDocumentFetcher {
    fn default() -> Self {
        Self::new(512 * 1024, false)
    }
}

impl ReqwestDidDocumentFetcher {
    #[must_use]
    pub fn new(max_response_bytes: usize, allow_private_network: bool) -> Self {
        Self {
            max_response_bytes,
            allow_private_network,
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(10),
        }
    }

    fn client(&self) -> Result<reqwest::blocking::Client> {
        reqwest::blocking::Client::builder()
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                DidError::VerificationFailed(format!("build HTTP client failed: {error}"))
            })
    }
}

impl DidDocumentFetcher for ReqwestDidDocumentFetcher {
    fn fetch_document(&self, url: &str) -> Result<FetchedDidDocument> {
        validate_fetch_target(url, self.allow_private_network)?;
        let response = self
            .client()?
            .get(url)
            .send()
            .map_err(|error| DidError::VerificationFailed(format!("fetch failed: {error}")))?;
        if !self.allow_private_network {
            let remote_address = response.remote_addr().ok_or_else(|| {
                DidError::VerificationFailed(
                    "fetch response did not expose its remote address".to_owned(),
                )
            })?;
            if !is_public_address(remote_address.ip()) {
                return Err(DidError::InvalidDidWeb(
                    "did:web resolver connected to a private, local, reserved, or multicast target"
                        .to_owned(),
                ));
            }
        }
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
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(DidError::InvalidDocument(format!(
                "did document exceeds max size of {} bytes",
                self.max_response_bytes
            )));
        }
        let mut bytes = Vec::with_capacity(self.max_response_bytes.min(16 * 1024));
        response
            .take(self.max_response_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| DidError::VerificationFailed(format!("read body failed: {error}")))?;
        if bytes.len() > self.max_response_bytes {
            return Err(DidError::InvalidDocument(format!(
                "did document exceeds max size of {} bytes",
                self.max_response_bytes
            )));
        }
        let body = String::from_utf8(bytes).map_err(|error| {
            DidError::InvalidDocument(format!("document is not UTF-8: {error}"))
        })?;
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
        Self::new(ReqwestDidDocumentFetcher::default())
    }
}

fn validate_fetch_target(url: &str, allow_private_network: bool) -> Result<()> {
    let url = reqwest::Url::parse(url)
        .map_err(|error| DidError::InvalidDidWeb(format!("invalid resolution URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(DidError::InvalidDidWeb(
            "did:web resolution URL must use http or https".to_owned(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DidError::InvalidDidWeb(
            "did:web resolution URL must not contain credentials".to_owned(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| DidError::InvalidDidWeb("resolution URL has no host".to_owned()))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        DidError::InvalidDidWeb("resolution URL has no known destination port".to_owned())
    })?;
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| DidError::VerificationFailed(format!("DNS resolution failed: {error}")))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(DidError::VerificationFailed(
            "DNS resolution returned no addresses".to_owned(),
        ));
    }
    if !allow_private_network
        && addresses
            .iter()
            .any(|address| !is_public_address(address.ip()))
    {
        return Err(DidError::InvalidDidWeb(
            "did:web resolver refuses private, local, reserved, or multicast targets".to_owned(),
        ));
    }
    Ok(())
}

fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, _, _] = address.octets();
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_unspecified()
                && first != 0
                && !(first == 100 && (64..=127).contains(&second))
                && !(first == 192 && second == 0)
                && !(first == 198 && (second == 18 || second == 19))
                && first < 224
        }
        IpAddr::V6(address) => {
            if let Some(address) = address.to_ipv4() {
                return is_public_address(IpAddr::V4(address));
            }
            let segments = address.segments();
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && (segments[0] & 0xfe00) != 0xfc00
                && (segments[0] & 0xffc0) != 0xfe80
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
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
            && !crate::methods::is_loopback_host(&did_web.host)
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
            metadata: DidResolutionMetadata {
                content_type: fetched
                    .content_type
                    .or_else(|| Some("application/did+json".into())),
                source_url: Some(url),
                etag: fetched.etag,
                retrieved_at_ms: None,
            },
            document,
            document_metadata: DidDocumentMetadata::default(),
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
            metadata: DidResolutionMetadata {
                content_type: Some("application/did+json".into()),
                source_url: None,
                etag: None,
                retrieved_at_ms: Some(123),
            },
            document,
            document_metadata: DidDocumentMetadata::default(),
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
    fn in_memory_cache_expires_entries_after_its_ttl() {
        let did = Did::parse("did:web:example.com").unwrap();
        let result = DidResolutionResult {
            metadata: DidResolutionMetadata::default(),
            document: DidDocument::new(did.clone()),
            document_metadata: DidDocumentMetadata::default(),
        };
        let cache = InMemoryDidResolutionCache::with_ttl(Duration::ZERO);

        cache.put(&did, &result);

        assert!(cache.get(&did).is_none());
    }

    #[test]
    fn fallback_resolver_uses_secondary_when_primary_misses() {
        let did = Did::parse("did:web:example.com").unwrap();
        let document = DidDocument::new(did.clone());
        let primary = StaticDidResolver::new();
        let mut secondary = StaticDidResolver::new();
        secondary.insert(DidResolutionResult {
            metadata: DidResolutionMetadata::default(),
            document,
            document_metadata: DidDocumentMetadata::default(),
        });

        let resolver = FallbackDidResolver::new(primary, secondary);
        let resolved = resolver.resolve(&did).unwrap();
        assert_eq!(resolved.document.id, did);
    }

    #[test]
    fn serializes_standard_did_resolution_result_shape() {
        let did = Did::parse("did:web:example.com").unwrap();
        let result = DidResolutionResult {
            metadata: DidResolutionMetadata {
                content_type: Some("application/did+json".into()),
                ..Default::default()
            },
            document: DidDocument::new(did),
            document_metadata: DidDocumentMetadata {
                version_id: Some("1".into()),
                ..Default::default()
            },
        };

        let value = serde_json::to_value(result).unwrap();
        assert_eq!(
            value["didResolutionMetadata"]["contentType"],
            "application/did+json"
        );
        assert_eq!(value["didDocument"]["id"], "did:web:example.com");
        assert_eq!(value["didDocumentMetadata"]["versionId"], "1");
        assert!(value.get("document").is_none());
        assert!(value.get("metadata").is_none());
    }

    #[test]
    fn registry_routes_did_key_and_resolves_authorized_verification_method() {
        let did = Did::parse("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap();
        let registry = DidResolverRegistry::with_default_methods();
        let resolved = registry.resolve(&did).unwrap();
        let method = resolved.document.verification_method[0].clone();
        let reference = DidUrl::parse(&method.id).unwrap();

        let selected = registry
            .resolve_verification_method(
                &reference,
                Some(VerificationRelationship::CapabilityInvocation),
            )
            .unwrap();

        assert_eq!(selected, method);
        assert!(registry.supports("key"));
        assert!(registry.supports("web"));
    }

    #[test]
    fn registry_rejects_duplicate_and_unknown_methods() {
        let mut registry = DidResolverRegistry::new();
        registry.register("key", DidKeyResolver).unwrap();

        let duplicate = registry.register("key", DidKeyResolver).unwrap_err();
        let unsupported = registry
            .resolve(&Did::parse("did:example:alice").unwrap())
            .unwrap_err();

        assert_eq!(
            duplicate,
            DidError::ResolverAlreadyRegistered("key".to_owned())
        );
        assert_eq!(
            unsupported,
            DidError::UnsupportedMethod("example".to_owned())
        );
    }

    #[test]
    fn resolution_accepts_relative_relationship_and_rejects_deactivated_did() {
        let did = Did::parse("did:web:example.com").unwrap();
        let reference = DidUrl::parse("did:web:example.com#key-1").unwrap();
        let document = DidDocument {
            id: did,
            agent_type: None,
            also_known_as: vec![],
            controller: vec![],
            verification_method: vec![VerificationMethod {
                id: "did:web:example.com#key-1".to_owned(),
                method_type: "Multikey".to_owned(),
                controller: "did:web:example.com".to_owned(),
                public_key_multibase: Some(
                    "z6MkvQ4QZz7T1cA7GJYk7oPK5vVsQt1zAr72Xd23LgzX776S".to_owned(),
                ),
                public_key_jwk: None,
                blockchain_account_id: None,
            }],
            authentication: vec!["#key-1".to_owned()],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
        };
        document.validate().unwrap();
        let mut result = DidResolutionResult {
            metadata: DidResolutionMetadata::default(),
            document,
            document_metadata: DidDocumentMetadata::default(),
        };

        assert!(
            result
                .verification_method(&reference, Some(VerificationRelationship::Authentication),)
                .is_ok()
        );

        result.document_metadata.deactivated = Some(true);
        assert!(matches!(
            result.verification_method(&reference, None),
            Err(DidError::DeactivatedDid(_))
        ));
    }

    #[test]
    fn network_fetcher_rejects_loopback_targets_by_default() {
        let fetcher = ReqwestDidDocumentFetcher::default();

        let error = fetcher
            .fetch_document("http://127.0.0.1/.well-known/did.json")
            .unwrap_err();

        assert!(matches!(error, DidError::InvalidDidWeb(_)));
    }
}
