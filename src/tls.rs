//! Optional TLS transport for the HTTP server.
//!
//! The TLS listener is opt-in: plain HTTP stays the default and its response
//! bytes stay identical. With `OPR_TLS=1` the server speaks HTTPS on the
//! same bind address. `OPR_TLS_CERT` and `OPR_TLS_KEY` point at PEM files;
//! without them a self-signed certificate is generated at startup and only
//! its SHA-256 fingerprint is logged. The private key is never logged.
//!
//! Honest scope: no client-certificate mTLS, no OCSP/CRL, no certificate
//! revocation, no HSM and no cipher-suite tuning beyond the library defaults.

use std::fmt;
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, ServerConnection};
use sha2::{Digest, Sha256};

/// Environment variable that enables the TLS listener.
pub const TLS_ENV: &str = "OPR_TLS";

/// Environment variable holding the PEM certificate path.
pub const TLS_CERT_ENV: &str = "OPR_TLS_CERT";

/// Environment variable holding the PEM private key path.
pub const TLS_KEY_ENV: &str = "OPR_TLS_KEY";

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
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("fingerprint", &self.fingerprint)
            .field("self_signed", &self.self_signed)
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

    /// Start one server-side TLS connection.
    pub fn connect(&self) -> Result<ServerConnection, rustls::Error> {
        ServerConnection::new(self.server_config())
    }
}

/// True when `OPR_TLS` is set to a truthy value.
pub fn tls_enabled() -> bool {
    match std::env::var(TLS_ENV) {
        Ok(raw) => matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Build the TLS configuration described by the environment.
///
/// `OPR_TLS_CERT` and `OPR_TLS_KEY` must be set together. Without them a
/// self-signed certificate is generated for [`DEFAULT_TLS_NAMES`].
pub fn config_from_env() -> Result<TlsConfig, TlsError> {
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
            config_from_pem_files(Path::new(&cert_path), Path::new(&key_path))
        }
        (None, None) => self_signed_config(),
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

    let certs: Vec<CertificateDer<'static>> = {
        let certs = rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                TlsError::new(format!(
                    "the TLS certificate {} is not a valid PEM chain: {}",
                    cert_path.display(),
                    err
                ))
            })?;
        if certs.is_empty() {
            return Err(TlsError::new(format!(
                "the TLS certificate {} has no CERTIFICATE block",
                cert_path.display()
            )));
        }
        certs
    };

    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
            .map_err(|err| {
                TlsError::new(format!(
                    "the TLS private key {} is not a valid PEM key: {}",
                    key_path.display(),
                    err
                ))
            })?
            .ok_or_else(|| {
                TlsError::new(format!(
                    "the TLS private key {} has no PRIVATE KEY block",
                    key_path.display()
                ))
            })?;

    let fingerprint = fingerprint_of(certs[0].as_ref());
    let certificate_der = certs[0].as_ref().to_vec();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| {
            TlsError::new(format!(
                "the TLS certificate {} and private key {} do not form a usable pair: {}",
                cert_path.display(),
                key_path.display(),
                err
            ))
        })?;
    Ok(TlsConfig {
        config: Arc::new(config),
        fingerprint,
        certificate_der,
        self_signed: false,
    })
}

/// Generate a self-signed certificate and build a TLS configuration from it.
pub fn self_signed_config() -> Result<TlsConfig, TlsError> {
    self_signed_config_for(DEFAULT_TLS_NAMES)
}

/// Generate a self-signed certificate for `names`.
pub fn self_signed_config_for(names: &[&str]) -> Result<TlsConfig, TlsError> {
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
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .map_err(|err| {
            TlsError::new(format!(
                "the generated certificate and private key do not form a usable pair: {}",
                err
            ))
        })?;
    let fingerprint = fingerprint_of(certs[0].as_ref());
    let certificate_der = certs[0].as_ref().to_vec();
    Ok(TlsConfig {
        config: Arc::new(config),
        fingerprint,
        certificate_der,
        self_signed: true,
    })
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
