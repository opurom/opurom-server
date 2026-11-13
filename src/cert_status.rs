//! Static local certificate status sources for the opt-in mTLS path.
//!
//! `OPR_CRL_FILE` and `OPR_OCSP_FILE` name local DER files; there is no network
//! fetch, responder, certificate transparency log or distributed revocation.
//! The DER CRL is parsed by `x509-parser`. `BasicOCSPResponse` is read by a
//! small strict DER reader because this crate has no generic ASN.1 dependency.
//! Both sources are cryptographically checked against the configured client
//! CA certificates and are re-read and checked on every handshake. Every
//! input is capped before parsing; any unavailable, malformed, stale,
//! unauthenticated or unknown source refuses the handshake.

use std::borrow::Cow;
use std::env::VarError;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::asn1_rs::{BitString, FromDer};
use x509_parser::prelude::{parse_x509_certificate, parse_x509_crl, AlgorithmIdentifier};
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::verify::verify_signature;
use x509_parser::x509::SubjectPublicKeyInfo;

/// Maximum size of one DER certificate, CRL or OCSP response.
pub const MAX_STATUS_DER_BYTES: usize = 256 * 1024;

/// RFC 5280 requires support for serial numbers of up to 20 octets.
const MAX_SERIAL_BYTES: usize = 20;
const MAX_OCSP_SINGLE_RESPONSES: usize = 64;
const CLOCK_SKEW_SECS: u64 = 60;
const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";

/// A certificate status refusal. The message is written for an operator.
#[derive(Clone, Debug)]
pub struct StatusError(String);

impl StatusError {
    fn new(message: impl Into<String>) -> StatusError {
        StatusError(message.into())
    }
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StatusError {}

#[derive(Clone, Debug)]
enum StatusSourceKind {
    Bytes(Vec<u8>),
    File(PathBuf),
    Unavailable(String),
}

/// One required status source, with the name of its environment variable.
#[derive(Clone, Debug)]
pub struct StatusSource {
    label: &'static str,
    kind: StatusSourceKind,
}

impl StatusSource {
    /// A status source supplied as in-memory DER bytes, used by tests.
    pub fn in_memory(label: &'static str, bytes: Vec<u8>) -> StatusSource {
        StatusSource {
            label,
            kind: StatusSourceKind::Bytes(bytes),
        }
    }

    /// A status source read from a local DER file on every handshake.
    pub fn file(label: &'static str, path: impl Into<PathBuf>) -> StatusSource {
        StatusSource {
            label,
            kind: StatusSourceKind::File(path.into()),
        }
    }

    /// A status source that is known to be unavailable.
    pub fn unavailable(label: &'static str, message: impl Into<String>) -> StatusSource {
        StatusSource {
            label,
            kind: StatusSourceKind::Unavailable(message.into()),
        }
    }

    /// The environment variable naming this source.
    pub fn label(&self) -> &'static str {
        self.label
    }

    fn load(&self) -> Result<Cow<'_, [u8]>, StatusError> {
        match &self.kind {
            StatusSourceKind::Bytes(bytes) => Ok(Cow::Borrowed(bytes.as_slice())),
            StatusSourceKind::File(path) => Ok(Cow::Owned(read_bounded_file(path, self.label)?)),
            StatusSourceKind::Unavailable(message) => Err(StatusError::new(message.clone())),
        }
    }
}

/// Read the named environment variable as a required local DER file path.
/// An empty or non-UTF-8 value becomes an unavailable source, never an
/// optional one: the mTLS handshake must refuse rather than silently skip it.
pub fn status_source_from_env(name: &'static str) -> Option<StatusSource> {
    match std::env::var(name) {
        Ok(raw) => {
            let path = raw.trim();
            if path.is_empty() {
                Some(StatusSource::unavailable(
                    name,
                    format!("{} is empty", name),
                ))
            } else {
                Some(StatusSource::file(name, PathBuf::from(path)))
            }
        }
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => Some(StatusSource::unavailable(
            name,
            format!("{} is not valid UTF-8", name),
        )),
    }
}

fn read_bounded_file(path: &Path, label: &str) -> Result<Vec<u8>, StatusError> {
    let file = File::open(path).map_err(|err| {
        StatusError::new(format!(
            "{}: cannot read {}: {}",
            label,
            path.display(),
            err
        ))
    })?;
    // take() bounds the read even when metadata reports a much larger file.
    let mut reader = file.take(MAX_STATUS_DER_BYTES as u64 + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|err| {
        StatusError::new(format!(
            "{}: cannot read {}: {}",
            label,
            path.display(),
            err
        ))
    })?;
    if bytes.len() > MAX_STATUS_DER_BYTES {
        return Err(StatusError::new(format!(
            "{}: {} exceeds the {} byte DER limit",
            label,
            path.display(),
            MAX_STATUS_DER_BYTES
        )));
    }
    if bytes.is_empty() {
        return Err(StatusError::new(format!(
            "{}: {} is empty",
            label,
            path.display()
        )));
    }
    Ok(bytes)
}

#[derive(Debug)]
struct CaIdentity {
    /// DER of the CA subject Name, including its SEQUENCE tag and length.
    subject: Vec<u8>,
    name_hash: [u8; 32],
    key_hash: [u8; 32],
    /// DER of the CA SubjectPublicKeyInfo, used to verify status signatures.
    public_key_der: Vec<u8>,
}

impl CaIdentity {
    fn public_key(&self) -> Result<SubjectPublicKeyInfo<'_>, StatusError> {
        let (rem, key) = SubjectPublicKeyInfo::from_der(&self.public_key_der)
            .map_err(|_| StatusError::new("the client CA has an invalid SubjectPublicKeyInfo"))?;
        if !rem.is_empty() {
            return Err(StatusError::new(
                "the client CA SubjectPublicKeyInfo has trailing DER bytes",
            ));
        }
        Ok(key)
    }
}

/// The status checks attached to one mTLS client-certificate verifier.
#[derive(Debug)]
pub(crate) struct StatusChecker {
    cas: Vec<CaIdentity>,
    crl: Option<StatusSource>,
    ocsp: Option<StatusSource>,
}

impl StatusChecker {
    pub(crate) fn new(
        cas: &[CertificateDer<'_>],
        crl: Option<StatusSource>,
        ocsp: Option<StatusSource>,
    ) -> Result<StatusChecker, StatusError> {
        let cas = cas
            .iter()
            .map(|ca| ca_identity(ca.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        if cas.is_empty() {
            return Err(StatusError::new(
                "certificate status sources need at least one client CA",
            ));
        }
        Ok(StatusChecker { cas, crl, ocsp })
    }

    /// Check every configured source against the presented end-entity DER.
    /// `now` is the Unix time rustls uses for chain verification.
    pub(crate) fn check(&self, cert_der: &[u8], now: u64) -> Result<(), StatusError> {
        let client = parse_client_certificate(cert_der)?;
        let ca = self
            .cas
            .iter()
            .find(|ca| ca.subject == client.issuer)
            .ok_or_else(|| {
                StatusError::new("no configured client CA matches the client certificate issuer")
            })?;

        if let Some(source) = &self.crl {
            let der = source.load()?;
            if crl_revokes(der.as_ref(), &client.serial, ca, now)
                .map_err(|err| labeled(source.label(), err))?
            {
                return Err(StatusError::new(format!(
                    "{}: client certificate serial is revoked by the DER CRL",
                    source.label()
                )));
            }
        }
        if let Some(source) = &self.ocsp {
            let der = source.load()?;
            let status = ocsp_status(der.as_ref(), &client.serial, ca, now)
                .map_err(|err| labeled(source.label(), err))?;
            match status {
                OcspStatus::Good => {}
                OcspStatus::Revoked => {
                    return Err(StatusError::new(format!(
                        "{}: OCSP reports the client certificate serial as revoked",
                        source.label()
                    )));
                }
                OcspStatus::Unknown => {
                    return Err(StatusError::new(format!(
                        "{}: OCSP reports the client certificate serial as unknown",
                        source.label()
                    )));
                }
            }
        }
        Ok(())
    }
}

fn labeled(label: &str, err: StatusError) -> StatusError {
    StatusError::new(format!("{}: {}", label, err))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn checked_der(der: &[u8], label: &str) -> Result<(), StatusError> {
    if der.is_empty() {
        Err(StatusError::new(format!("{} DER is empty", label)))
    } else if der.len() > MAX_STATUS_DER_BYTES {
        Err(StatusError::new(format!(
            "{} DER exceeds the {} byte limit",
            label, MAX_STATUS_DER_BYTES
        )))
    } else {
        Ok(())
    }
}

fn ca_identity(der: &[u8]) -> Result<CaIdentity, StatusError> {
    checked_der(der, "client CA certificate")?;
    let (rem, cert) = parse_x509_certificate(der)
        .map_err(|_| StatusError::new("client CA certificate DER is malformed"))?;
    if !rem.is_empty() {
        return Err(StatusError::new(
            "client CA certificate DER has trailing bytes",
        ));
    }
    let subject = cert.subject().as_raw();
    let key = cert.public_key().subject_public_key.data.as_ref();
    Ok(CaIdentity {
        subject: subject.to_vec(),
        name_hash: sha256(subject),
        key_hash: sha256(key),
        public_key_der: cert.public_key().raw.to_vec(),
    })
}

struct ClientCertificate {
    serial: Vec<u8>,
    issuer: Vec<u8>,
}

fn parse_client_certificate(der: &[u8]) -> Result<ClientCertificate, StatusError> {
    checked_der(der, "client certificate")?;
    let (rem, cert) = parse_x509_certificate(der)
        .map_err(|_| StatusError::new("client certificate DER is malformed"))?;
    if !rem.is_empty() {
        return Err(StatusError::new(
            "client certificate DER has trailing bytes",
        ));
    }
    Ok(ClientCertificate {
        serial: canonical_serial(cert.raw_serial())?.to_vec(),
        issuer: cert.issuer().as_raw().to_vec(),
    })
}

/// DER INTEGER content of a positive serial, without its sign padding.
fn canonical_serial(raw: &[u8]) -> Result<&[u8], StatusError> {
    if raw.is_empty() || raw[0] & 0x80 != 0 {
        return Err(StatusError::new(
            "certificate serial is not a positive DER INTEGER",
        ));
    }
    let first = raw
        .iter()
        .position(|byte| *byte != 0)
        .ok_or_else(|| StatusError::new("certificate serial is zero"))?;
    let value = &raw[first..];
    if value.len() > MAX_SERIAL_BYTES {
        return Err(StatusError::new(format!(
            "certificate serial exceeds {} bytes",
            MAX_SERIAL_BYTES
        )));
    }
    Ok(value)
}

fn crl_revokes(der: &[u8], serial: &[u8], ca: &CaIdentity, now: u64) -> Result<bool, StatusError> {
    checked_der(der, "CRL")?;
    let (rem, crl) = parse_x509_crl(der).map_err(|_| StatusError::new("CRL DER is malformed"))?;
    if !rem.is_empty() {
        return Err(StatusError::new("CRL DER has trailing bytes"));
    }
    if crl.issuer().as_raw() != ca.subject.as_slice() {
        return Err(StatusError::new(
            "CRL issuer does not match the client CA subject",
        ));
    }
    verify_crl_signature(&crl, ca)?;
    crl_freshness(&crl, now)?;
    for entry in crl.iter_revoked_certificates() {
        if canonical_serial(entry.raw_serial())? == serial {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_crl_signature(
    crl: &CertificateRevocationList<'_>,
    ca: &CaIdentity,
) -> Result<(), StatusError> {
    if crl.signature_value.unused_bits != 0 {
        return Err(StatusError::new("CRL signature BIT STRING is not aligned"));
    }
    if crl.signature_algorithm != crl.tbs_cert_list.signature {
        return Err(StatusError::new(
            "CRL inner and outer signature algorithms differ",
        ));
    }
    let key = ca.public_key()?;
    verify_signature(
        &key,
        &crl.signature_algorithm,
        &crl.signature_value,
        crl.tbs_cert_list.as_ref(),
    )
    .map_err(|_| StatusError::new("CRL signature does not verify against the client CA"))
}

fn crl_freshness(crl: &CertificateRevocationList<'_>, now: u64) -> Result<(), StatusError> {
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    let skew = i64::try_from(CLOCK_SKEW_SECS).unwrap_or(i64::MAX);
    let last = crl.last_update().timestamp();
    let next = crl
        .next_update()
        .ok_or_else(|| StatusError::new("CRL has no nextUpdate"))?
        .timestamp();
    if last > now.saturating_add(skew) {
        return Err(StatusError::new("CRL thisUpdate is in the future"));
    }
    if next <= last {
        return Err(StatusError::new("CRL nextUpdate is not after thisUpdate"));
    }
    if next <= now {
        return Err(StatusError::new("CRL is stale: nextUpdate has passed"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

/// Parse a complete DER `BasicOCSPResponse` and return the status of the
/// SingleResponse whose CertID names `serial`. The signature is verified over
/// the full `tbsResponseData` DER before any status is trusted.
fn ocsp_status(
    der: &[u8],
    serial: &[u8],
    ca: &CaIdentity,
    now: u64,
) -> Result<OcspStatus, StatusError> {
    checked_der(der, "OCSP response")?;
    let mut root = Der::new(der);
    let response = root.read(0x30)?;
    root.done()?;
    let mut outer = response.content();
    let tbs = outer.read(0x30)?;
    let signature_algorithm = outer.read(0x30)?;
    let signature = outer.read(0x03)?;
    if outer.peek() == Some(0xa0) {
        return Err(StatusError::new(
            "delegated OCSP responder certificates are not supported",
        ));
    }
    outer.done()?;
    verify_ocsp_signature(tbs, signature_algorithm, signature, ca)?;

    let mut data = tbs.content();
    if let Some(version) = data.maybe(0xa0)? {
        let mut version = version.content();
        let integer = version.read(0x02)?;
        if integer.content != [0] {
            return Err(StatusError::new("unsupported OCSP response version"));
        }
        version.done()?;
    }
    let responder_tag = data
        .peek()
        .ok_or_else(|| StatusError::new("OCSP ResponderID is missing"))?;
    if responder_tag != 0xa1 && responder_tag != 0xa2 {
        return Err(StatusError::new("OCSP ResponderID has an invalid tag"));
    }
    data.read(responder_tag)?;
    let produced_at = generalized_time(data.read(0x18)?)?;
    let responses = data.read(0x30)?;
    if data.peek() == Some(0xa1) {
        data.read(0xa1)?;
    }
    data.done()?;

    let mut list = responses.content();
    if list.is_done() {
        return Err(StatusError::new("OCSP responses is empty"));
    }
    let mut matched: Option<OcspStatus> = None;
    let mut count = 0usize;
    while !list.is_done() {
        count += 1;
        if count > MAX_OCSP_SINGLE_RESPONSES {
            return Err(StatusError::new(
                "OCSP responses exceeds the SingleResponse limit",
            ));
        }
        let single = list.read(0x30)?;
        let (entry_serial, status, this_update, next_update) = parse_single_response(single, ca)?;
        ocsp_freshness(produced_at, this_update, next_update, now)?;
        if entry_serial == serial {
            if matched.is_some() {
                return Err(StatusError::new(
                    "duplicate OCSP status for the client certificate serial",
                ));
            }
            matched = Some(status);
        }
    }
    matched.ok_or_else(|| {
        StatusError::new("OCSP response has no status for the client certificate serial")
    })
}

fn verify_ocsp_signature(
    tbs: Tlv<'_>,
    algorithm: Tlv<'_>,
    signature: Tlv<'_>,
    ca: &CaIdentity,
) -> Result<(), StatusError> {
    let (rem, alg) = AlgorithmIdentifier::from_der(algorithm.full)
        .map_err(|_| StatusError::new("OCSP signatureAlgorithm is malformed"))?;
    if !rem.is_empty() {
        return Err(StatusError::new(
            "OCSP signatureAlgorithm has trailing DER bytes",
        ));
    }
    let (rem, sig) = BitString::from_der(signature.full)
        .map_err(|_| StatusError::new("OCSP signature BIT STRING is malformed"))?;
    if !rem.is_empty() || sig.unused_bits != 0 || sig.data.is_empty() {
        return Err(StatusError::new(
            "OCSP signature BIT STRING is empty or unaligned",
        ));
    }
    let key = ca.public_key()?;
    verify_signature(&key, &alg, &sig, tbs.full)
        .map_err(|_| StatusError::new("OCSP signature does not verify against the client CA"))
}

fn check_sha256_algorithm(algorithm: Tlv<'_>) -> Result<(), StatusError> {
    let (rem, alg) = AlgorithmIdentifier::from_der(algorithm.full)
        .map_err(|_| StatusError::new("OCSP CertID hashAlgorithm is malformed"))?;
    if !rem.is_empty() || alg.algorithm.to_id_string() != SHA256_OID {
        return Err(StatusError::new("OCSP CertID hashAlgorithm is not SHA-256"));
    }
    Ok(())
}

fn parse_single_response<'a>(
    single: Tlv<'a>,
    ca: &CaIdentity,
) -> Result<(&'a [u8], OcspStatus, u64, Option<u64>), StatusError> {
    let mut single = single.content();
    let cert_id = single.read(0x30)?;
    let mut id = cert_id.content();
    check_sha256_algorithm(id.read(0x30)?)?;
    let name_hash = id.read(0x04)?.content;
    let key_hash = id.read(0x04)?.content;
    if name_hash != ca.name_hash.as_slice() || key_hash != ca.key_hash.as_slice() {
        return Err(StatusError::new(
            "OCSP CertID does not identify the configured client CA",
        ));
    }
    let serial = canonical_serial(id.read(0x02)?.content)?;
    id.done()?;

    let status = match single.peek() {
        Some(0x80) => {
            let good = single.read(0x80)?.content();
            good.done()?;
            OcspStatus::Good
        }
        Some(0xa1) => {
            let mut revoked = single.read(0xa1)?.content();
            revoked.read(0x18)?;
            if revoked.peek() == Some(0xa0) {
                revoked.read(0xa0)?;
            }
            revoked.done()?;
            OcspStatus::Revoked
        }
        Some(0x82) => {
            let unknown = single.read(0x82)?.content();
            unknown.done()?;
            OcspStatus::Unknown
        }
        _ => return Err(StatusError::new("OCSP CertStatus has an invalid tag")),
    };
    let this_update = generalized_time(single.read(0x18)?)?;
    let next_update = match single.maybe(0xa0)? {
        Some(next) => {
            let mut next = next.content();
            let time = generalized_time(next.read(0x18)?)?;
            next.done()?;
            Some(time)
        }
        None => None,
    };
    if single.peek() == Some(0xa1) {
        single.read(0xa1)?;
    }
    single.done()?;
    Ok((serial, status, this_update, next_update))
}

fn ocsp_freshness(
    produced_at: u64,
    this_update: u64,
    next_update: Option<u64>,
    now: u64,
) -> Result<(), StatusError> {
    let future = now.saturating_add(CLOCK_SKEW_SECS);
    if produced_at > future || this_update > future {
        return Err(StatusError::new("OCSP response is not yet valid"));
    }
    let next = next_update.ok_or_else(|| StatusError::new("OCSP response has no nextUpdate"))?;
    if next <= this_update {
        return Err(StatusError::new("OCSP nextUpdate is not after thisUpdate"));
    }
    if next <= now {
        return Err(StatusError::new(
            "OCSP response is stale: nextUpdate has passed",
        ));
    }
    Ok(())
}

/// One definite-length DER TLV. The reader refuses indefinite and non-minimal
/// lengths before slicing, so every allocation stays bounded by the input cap.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    full: &'a [u8],
    content: &'a [u8],
}

impl<'a> Tlv<'a> {
    fn content(&self) -> Der<'a> {
        Der::new(self.content)
    }
}

#[derive(Clone, Copy)]
struct Der<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(input: &'a [u8]) -> Der<'a> {
        Der { input, pos: 0 }
    }

    fn is_done(&self) -> bool {
        self.pos == self.input.len()
    }

    fn done(&self) -> Result<(), StatusError> {
        if self.is_done() {
            Ok(())
        } else {
            Err(StatusError::new("DER value has trailing bytes"))
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn byte(&mut self) -> Result<u8, StatusError> {
        let byte = *self
            .input
            .get(self.pos)
            .ok_or_else(|| StatusError::new("DER value is truncated"))?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], StatusError> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or_else(|| StatusError::new("DER length overflows"))?;
        let bytes = self
            .input
            .get(self.pos..end)
            .ok_or_else(|| StatusError::new("DER value is truncated"))?;
        self.pos = end;
        Ok(bytes)
    }

    fn read(&mut self, tag: u8) -> Result<Tlv<'a>, StatusError> {
        let start = self.pos;
        let actual = self.byte()?;
        if actual != tag {
            return Err(StatusError::new(format!(
                "DER tag 0x{:02x} expected, got 0x{:02x}",
                tag, actual
            )));
        }
        let first = self.byte()?;
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return Err(StatusError::new("DER length is indefinite or too long"));
            }
            let bytes = self.take(count)?;
            if bytes[0] == 0 {
                return Err(StatusError::new("DER length is not minimal"));
            }
            let mut length = 0usize;
            for byte in bytes {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or_else(|| StatusError::new("DER length overflows"))?;
            }
            if length < 0x80 {
                return Err(StatusError::new("DER length is not minimal"));
            }
            length
        };
        let content_start = self.pos;
        let end = content_start
            .checked_add(length)
            .ok_or_else(|| StatusError::new("DER length overflows"))?;
        if end > self.input.len() {
            return Err(StatusError::new("DER value is truncated"));
        }
        self.pos = end;
        Ok(Tlv {
            full: &self.input[start..end],
            content: &self.input[content_start..end],
        })
    }

    fn maybe(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, StatusError> {
        if self.peek() == Some(tag) {
            self.read(tag).map(Some)
        } else {
            Ok(None)
        }
    }
}

/// DER GeneralizedTime in the only form RFC 6960 profiles allow here:
/// `YYYYMMDDHHMMSSZ`, with no fractional seconds and no local offset.
fn generalized_time(tlv: Tlv<'_>) -> Result<u64, StatusError> {
    let bytes = tlv.content;
    if bytes.len() != 15 || bytes[14] != b'Z' || !bytes[..14].iter().all(u8::is_ascii_digit) {
        return Err(StatusError::new("OCSP GeneralizedTime is not DER UTC"));
    }
    let part = |start: usize, end: usize| -> u64 {
        bytes[start..end]
            .iter()
            .fold(0u64, |value, byte| value * 10 + u64::from(*byte - b'0'))
    };
    let year = part(0, 4);
    let month = part(4, 6);
    let day = part(6, 8);
    let hour = part(8, 10);
    let minute = part(10, 12);
    let second = part(12, 14);
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return Err(StatusError::new("OCSP GeneralizedTime has an invalid date"));
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(StatusError::new("OCSP GeneralizedTime has an invalid time"));
    }
    let days = days_from_civil(year as i64, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add((hour as i64) * 3600))
        .and_then(|value| value.checked_add((minute as i64) * 60))
        .and_then(|value| value.checked_add(second as i64))
        .ok_or_else(|| StatusError::new("OCSP GeneralizedTime overflows"))?;
    u64::try_from(seconds).map_err(|_| StatusError::new("OCSP GeneralizedTime precedes 1970"))
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01, using Howard Hinnant's civil-date algorithm.
fn days_from_civil(year: i64, month: u64, day: u64) -> i64 {
    let month = month as i64;
    let day = day as i64;
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalized_time_parses_utc_and_rejects_offsets() {
        let mut der = Der::new(b"\x18\x0f20200101000000Z");
        let tlv = der.read(0x18).expect("GeneralizedTime TLV");
        assert_eq!(generalized_time(tlv).expect("UTC timestamp"), 1_577_836_800);
        let mut offset = Der::new(b"\x18\x0f202001010000+01");
        assert!(generalized_time(offset.read(0x18).expect("TLV")).is_err());
    }

    #[test]
    fn canonical_serial_strips_sign_padding_and_rejects_negative() {
        assert_eq!(canonical_serial(&[0, 0, 3]).expect("serial"), &[3]);
        assert!(canonical_serial(&[0x80, 1]).is_err());
        assert!(canonical_serial(&[0; 21]).is_err());
    }

    #[test]
    fn der_reader_rejects_indefinite_and_non_minimal_lengths() {
        let mut indefinite = Der::new(&[0x30, 0x80, 0x00, 0x00]);
        assert!(indefinite.read(0x30).is_err());
        let mut padded = Der::new(&[0x30, 0x81, 0x01, 0x00]);
        assert!(padded.read(0x30).is_err());
    }
}
