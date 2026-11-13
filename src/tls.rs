//! Optional TLS transport for the HTTP server.
//!
//! The TLS listener is opt-in: plain HTTP stays the default and its response
//! bytes stay identical. With `OPR_TLS=1` the server speaks HTTPS on the
//! same bind address. `OPR_TLS_CERT` and `OPR_TLS_KEY` point at PEM files;
//! without them a self-signed certificate is generated at startup and only
//! its SHA-256 fingerprint is logged. The private key is never logged.
//!
//! `OPR_MTLS=1` with `OPR_CLIENT_CA` makes the listener require and verify a
//! client certificate during the rustls handshake. `OPR_REVOKED` is a static,
//! comma-separated SHA-256 fingerprint deny list. `OPR_CRL_FILE` and
//! `OPR_OCSP_FILE` add required static local DER status sources; both are
//! checked on every mTLS handshake and fail closed when unusable. Both TLS
//! modes advertise `h2` and `http/1.1` through ALPN; real HTTP/2 frames are
//! served when `h2` is selected.
//!
//! The status sources are local files that are read at every handshake. There
//! is no live OCSP responder fetch, no CRL distribution point and no
//! certificate transparency; the cipher suites and protocol versions are the
//! library defaults.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ServerConfig, ServerConnection, WebPkiClientVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};

use crate::cert_status::{self, StatusChecker, StatusSource};

/// Environment variable that enables the TLS listener.
pub const TLS_ENV: &str = "OPR_TLS";

/// Environment variable holding the PEM certificate path.
pub const TLS_CERT_ENV: &str = "OPR_TLS_CERT";

/// Environment variable holding the PEM private key path.
pub const TLS_KEY_ENV: &str = "OPR_TLS_KEY";

/// Environment variable that requires client-certificate authentication.
pub const MTLS_ENV: &str = "OPR_MTLS";

/// Environment variable holding a client CA PEM path or inline PEM.
pub const CLIENT_CA_ENV: &str = "OPR_CLIENT_CA";

/// Environment variable holding a comma-separated fingerprint deny list.
pub const REVOKED_ENV: &str = "OPR_REVOKED";

/// Environment variable holding a required local DER CRL file path.
pub const CRL_FILE_ENV: &str = "OPR_CRL_FILE";

/// Environment variable holding a required local DER BasicOCSPResponse path.
pub const OCSP_FILE_ENV: &str = "OPR_OCSP_FILE";

/// The protocols advertised through ALPN, in server preference order.
pub const ALPN_PROTOCOLS: &[&str] = &["h2", "http/1.1"];

/// The names the generated self-signed certificate is valid for.
pub const DEFAULT_TLS_NAMES: &[&str] = &["localhost", "127.0.0.1", "::1"];

/// A TLS configuration failure. The message is written for an operator.
#[derive(Debug)]
pub struct TlsError {
    message: String,
}

impl TlsError {
    fn new(message: impl Into<String>) -> TlsError {
        TlsError {
            message: message.into(),
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TlsError {}

/// One opt-in mTLS configuration: trusted client CA certificates, the
/// SHA-256 fingerprints of certificates that must be denied and optional
/// required static local certificate status sources.
#[derive(Clone, Debug, Default)]
pub struct MtlsOptions {
    /// PEM bytes of one or more trusted client CA certificates.
    pub client_ca_pem: Vec<u8>,
    /// SHA-256 fingerprints, with or without colons, in any hex case.
    pub revoked: Vec<String>,
    /// A required DER CRL source, when `OPR_CRL_FILE` or a test supplies one.
    pub crl: Option<StatusSource>,
    /// A required DER BasicOCSPResponse source, when `OPR_OCSP_FILE` or a test supplies one.
    pub ocsp: Option<StatusSource>,
}

impl MtlsOptions {
    /// Read the opt-in mTLS configuration. `None` means `OPR_MTLS` is off.
    pub fn from_env() -> Result<Option<MtlsOptions>, TlsError> {
        if !mtls_enabled() {
            return Ok(None);
        }
        let raw = std::env::var(CLIENT_CA_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                TlsError::new(format!(
                    "{} is set but {} is missing: a client CA PEM is needed for mutual TLS",
                    MTLS_ENV, CLIENT_CA_ENV
                ))
            })?;
        let client_ca_pem = if raw.contains("-----BEGIN CERTIFICATE-----") {
            raw.into_bytes()
        } else {
            fs::read(&raw).map_err(|err| {
                TlsError::new(format!("cannot read the client CA PEM {}: {}", raw, err))
            })?
        };
        let revoked = parse_revoked(&std::env::var(REVOKED_ENV).unwrap_or_default())?;
        Ok(Some(MtlsOptions {
            client_ca_pem,
            revoked,
            crl: cert_status::status_source_from_env(CRL_FILE_ENV),
            ocsp: cert_status::status_source_from_env(OCSP_FILE_ENV),
        }))
    }
}

/// The TLS configuration of one server.
#[derive(Clone)]
pub struct TlsConfig {
    config: Arc<ServerConfig>,
    /// The SHA-256 fingerprint of the leaf certificate, uppercase hex.
    fingerprint: String,
    /// The DER bytes of the leaf certificate.
    certificate_der: Vec<u8>,
    /// True when the certificate was generated at startup.
    self_signed: bool,
    /// True when the handshake requires a verified client certificate.
    mtls: bool,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("fingerprint", &self.fingerprint)
            .field("self_signed", &self.self_signed)
            .field("mtls", &self.mtls)
            .finish()
    }
}

impl TlsConfig {
    /// The shared rustls server configuration.
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }

    /// The SHA-256 fingerprint of the leaf certificate.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The DER bytes of the leaf certificate. A client that trusts this
    /// certificate can complete a real handshake against this server.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// True when the certificate was generated at startup by `rcgen`.
    pub fn is_self_signed(&self) -> bool {
        self.self_signed
    }

    /// True when the handshake requires a verified client certificate.
    pub fn requires_client_auth(&self) -> bool {
        self.mtls
    }

    /// Start one server-side TLS connection.
    pub fn connect(&self) -> Result<ServerConnection, rustls::Error> {
        ServerConnection::new(self.server_config())
    }
}

/// True when `OPR_TLS` or `OPR_MTLS` is set to a truthy value.
pub fn tls_enabled() -> bool {
    truthy_env(TLS_ENV) || truthy_env(MTLS_ENV)
}

/// True when `OPR_MTLS` is set to a truthy value.
pub fn mtls_enabled() -> bool {
    truthy_env(MTLS_ENV)
}

fn truthy_env(name: &str) -> bool {
    std::env::var(name).is_ok_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Build the TLS configuration described by the environment.
///
/// `OPR_TLS_CERT` and `OPR_TLS_KEY` must be set together. Without them a
/// self-signed certificate is generated for [`DEFAULT_TLS_NAMES`].
pub fn config_from_env() -> Result<TlsConfig, TlsError> {
    let mtls = MtlsOptions::from_env()?;
    let cert_path = std::env::var(TLS_CERT_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let key_path = std::env::var(TLS_KEY_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            config_from_pem_files_with(Path::new(&cert_path), Path::new(&key_path), mtls.as_ref())
        }
        (None, None) => self_signed_config_with(DEFAULT_TLS_NAMES, mtls.as_ref()),
        (Some(_), None) => Err(TlsError::new(format!(
            "{} is set but {} is missing: both are needed for a TLS certificate",
            TLS_CERT_ENV, TLS_KEY_ENV
        ))),
        (None, Some(_)) => Err(TlsError::new(format!(
            "{} is set but {} is missing: both are needed for a TLS certificate",
            TLS_KEY_ENV, TLS_CERT_ENV
        ))),
    }
}

/// Build a TLS configuration from PEM certificate and key files.
pub fn config_from_pem_files(cert_path: &Path, key_path: &Path) -> Result<TlsConfig, TlsError> {
    config_from_pem_files_with(cert_path, key_path, None)
}

fn config_from_pem_files_with(
    cert_path: &Path,
    key_path: &Path,
    mtls: Option<&MtlsOptions>,
) -> Result<TlsConfig, TlsError> {
    let cert_bytes = fs::read(cert_path).map_err(|err| {
        TlsError::new(format!(
            "cannot read the TLS certificate {}: {}",
            cert_path.display(),
            err
        ))
    })?;
    let key_bytes = fs::read(key_path).map_err(|err| {
        TlsError::new(format!(
            "cannot read the TLS private key {}: {}",
            key_path.display(),
            err
        ))
    })?;
    let cert_name = cert_path.display().to_string();
    let key_name = key_path.display().to_string();
    let (certs, key) = parse_pem_pair(&cert_bytes, &key_bytes, &cert_name, &key_name)?;
    let pair = format!(
        "the TLS certificate {} and private key {}",
        cert_name, key_name
    );
    make_tls_config(certs, key, &pair, mtls, false)
}

/// Build a TLS configuration from in-memory PEM bytes. The caller supplies
/// the certificate chain, its private key and optional mTLS options.
pub fn config_from_pem_bytes(
    cert_pem: &[u8],
    key_pem: &[u8],
    mtls: Option<&MtlsOptions>,
) -> Result<TlsConfig, TlsError> {
    let (certs, key) = parse_pem_pair(cert_pem, key_pem, "PEM", "PEM")?;
    make_tls_config(
        certs,
        key,
        "the supplied certificate and private key",
        mtls,
        false,
    )
}

/// Generate a self-signed certificate and build a TLS configuration from it.
pub fn self_signed_config() -> Result<TlsConfig, TlsError> {
    self_signed_config_for(DEFAULT_TLS_NAMES)
}

/// Generate a self-signed certificate for `names`.
pub fn self_signed_config_for(names: &[&str]) -> Result<TlsConfig, TlsError> {
    self_signed_config_with(names, None)
}

fn self_signed_config_with(
    names: &[&str],
    mtls: Option<&MtlsOptions>,
) -> Result<TlsConfig, TlsError> {
    let mut params = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<String>>(),
    )
    .map_err(|err| TlsError::new(format!("cannot build the certificate parameters: {}", err)))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "opurom-server self-signed certificate",
    );
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|err| TlsError::new(format!("cannot generate the private key: {}", err)))?;
    let certificate = params
        .self_signed(&key_pair)
        .map_err(|err| TlsError::new(format!("cannot self-sign the certificate: {}", err)))?;

    let certs = vec![certificate.der().clone()];
    let key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    make_tls_config(
        certs,
        key,
        "the generated certificate and private key",
        mtls,
        true,
    )
}

fn parse_pem_pair(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    cert_name: &str,
    key_name: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            TlsError::new(format!(
                "the TLS certificate {} is not a valid PEM chain: {}",
                cert_name, err
            ))
        })?;
    if certs.is_empty() {
        return Err(TlsError::new(format!(
            "the TLS certificate {} has no CERTIFICATE block",
            cert_name
        )));
    }
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes))
        .map_err(|err| {
            TlsError::new(format!(
                "the TLS private key {} is not a valid PEM key: {}",
                key_name, err
            ))
        })?
        .ok_or_else(|| {
            TlsError::new(format!(
                "the TLS private key {} has no PRIVATE KEY block",
                key_name
            ))
        })?;
    Ok((certs, key))
}

fn make_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pair: &str,
    mtls: Option<&MtlsOptions>,
    self_signed: bool,
) -> Result<TlsConfig, TlsError> {
    let fingerprint = fingerprint_of(certs[0].as_ref());
    let certificate_der = certs[0].as_ref().to_vec();
    let config = build_server_config(certs, key, pair, mtls)?;
    Ok(TlsConfig {
        config: Arc::new(config),
        fingerprint,
        certificate_der,
        self_signed,
        mtls: mtls.is_some(),
    })
}

fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pair: &str,
    mtls: Option<&MtlsOptions>,
) -> Result<ServerConfig, TlsError> {
    let builder = ServerConfig::builder();
    let mut config = match mtls {
        Some(options) => builder
            .with_client_cert_verifier(client_cert_verifier(options)?)
            .with_single_cert(certs, key),
        None => builder.with_no_client_auth().with_single_cert(certs, key),
    }
    .map_err(|err| TlsError::new(format!("{} do not form a usable pair: {}", pair, err)))?;
    config.alpn_protocols = ALPN_PROTOCOLS
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(config)
}

fn client_cert_verifier(options: &MtlsOptions) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
    let mut roots = RootCertStore::empty();
    let cas = rustls_pemfile::certs(&mut BufReader::new(options.client_ca_pem.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            TlsError::new(format!(
                "{} is not a valid client CA PEM chain: {}",
                CLIENT_CA_ENV, err
            ))
        })?;
    if cas.is_empty() {
        return Err(TlsError::new(format!(
            "{} has no CERTIFICATE block",
            CLIENT_CA_ENV
        )));
    }
    for ca in &cas {
        roots
            .add(CertificateDer::from(ca.as_ref().to_vec()))
            .map_err(|err| {
                TlsError::new(format!(
                    "{} has an unusable CA certificate: {}",
                    CLIENT_CA_ENV, err
                ))
            })?;
    }
    let inner = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|err| {
            TlsError::new(format!(
                "cannot require client certificates from {}: {}",
                CLIENT_CA_ENV, err
            ))
        })?;
    let revoked: BTreeSet<String> = parse_revoked(&options.revoked.join(","))?
        .into_iter()
        .collect();
    let status = if options.crl.is_some() || options.ocsp.is_some() {
        Some(
            StatusChecker::new(&cas, options.crl.clone(), options.ocsp.clone()).map_err(|err| {
                TlsError::new(format!(
                    "cannot use the certificate status sources: {}",
                    err
                ))
            })?,
        )
    } else {
        None
    };
    if revoked.is_empty() && status.is_none() {
        Ok(inner)
    } else {
        Ok(Arc::new(RevokingClientCertVerifier {
            inner,
            revoked,
            status,
        }))
    }
}

fn parse_revoked(raw: &str) -> Result<Vec<String>, TlsError> {
    raw.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            let normalized = part.replace(':', "").to_ascii_uppercase();
            if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                Ok(normalized)
            } else {
                Err(TlsError::new(format!(
                    "{} contains an invalid SHA-256 certificate fingerprint: {}",
                    REVOKED_ENV, part
                )))
            }
        })
        .collect()
}

/// A client-certificate verifier that delegates chain and signature checks to
/// rustls and then applies the static deny list and required status sources.
#[derive(Debug)]
struct RevokingClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    revoked: BTreeSet<String>,
    status: Option<StatusChecker>,
}

impl ClientCertVerifier for RevokingClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        // The fingerprint is computed from the DER bytes rustls received from
        // the peer, never from a header or another client-supplied string.
        let presented = std::iter::once(end_entity).chain(intermediates);
        if presented
            .into_iter()
            .any(|cert| self.revoked.contains(&denylist_fingerprint(cert.as_ref())))
        {
            return Err(RustlsError::InvalidCertificate(CertificateError::Revoked));
        }
        if let Some(status) = &self.status {
            status
                .check(end_entity.as_ref(), now.as_secs())
                .map_err(|err| {
                    RustlsError::General(format!("certificate status refused: {}", err))
                })?;
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The plain uppercase SHA-256 hex digest used by the deny list.
fn denylist_fingerprint(der: &[u8]) -> String {
    fingerprint_of(der).replace(':', "")
}

/// The SHA-256 fingerprint of one DER certificate, uppercase hex, colons
/// between the bytes.
pub fn fingerprint_of(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(":")
}
