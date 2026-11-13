//! In-memory certificate-status fixtures. Every key and certificate is
//! generated with rcgen at test runtime; no private key is checked in. CRLs
//! are DER produced by rcgen, OCSP responses are DER BasicOCSPResponse values
//! signed by the generated CA key. No responder is contacted.

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SerialNumber, SigningKey,
};
use sha2::{Digest, Sha256};
use x509_parser::prelude::parse_x509_certificate;

const THIS_UPDATE: &[u8; 15] = b"20200101000000Z";
const STALE_NEXT_UPDATE: &[u8; 15] = b"20200102000000Z";
const FRESH_NEXT_UPDATE: &[u8; 15] = b"21000101000000Z";
const REVOCATION_TIME: &[u8; 15] = b"20200102000000Z";

// AlgorithmIdentifier { algorithm: id-sha256 } and AlgorithmIdentifier
// { algorithm: ecdsa-with-SHA256 }, both without parameters.
const SHA256_ALGORITHM_ID: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
const ECDSA_SHA256_ALGORITHM_ID: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

#[derive(Clone, Debug)]
pub struct ClientIdentity {
    pub chain_pem: String,
    pub key_pem: String,
    pub serial: Vec<u8>,
}

#[allow(dead_code)]
pub struct Fixture {
    pub ca_pem: String,
    pub ca_der: Vec<u8>,
    pub server_chain_pem: String,
    pub server_key_pem: String,
    pub trusted: ClientIdentity,
    pub other: ClientIdentity,
    pub crl_revokes_trusted: Vec<u8>,
    pub crl_revokes_other: Vec<u8>,
    pub crl_stale: Vec<u8>,
    pub crl_tampered: Vec<u8>,
    pub ocsp_good: Vec<u8>,
    pub ocsp_revoked: Vec<u8>,
    pub ocsp_unknown: Vec<u8>,
    pub ocsp_stale: Vec<u8>,
    pub ocsp_other_serial: Vec<u8>,
    pub ocsp_tampered: Vec<u8>,
}

struct CaHashes {
    subject_raw: Vec<u8>,
    name_hash: Vec<u8>,
    key_hash: Vec<u8>,
}

#[derive(Clone, Copy)]
enum OcspFixtureStatus {
    Good,
    Revoked,
    Unknown,
}

/// Generate a CA, a CA-signed server chain and two CA-signed clients, then
/// derive all CRL and OCSP status fixtures from the same keys and serials.
pub fn fixture() -> Fixture {
    build(None)
}

/// The same fixture with a CRL Distribution Points extension on the trusted
/// client certificate, naming `url`.
#[allow(dead_code)]
pub fn fixture_with_crl_dp(url: &str) -> Fixture {
    build(Some(url))
}

fn build(dp_url: Option<&str>) -> Fixture {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "opurom status test CA");
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    let ca_key = KeyPair::generate().expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let (server_cert, server_key) = signed_leaf(
        &issuer,
        "localhost",
        vec!["localhost".to_string(), "127.0.0.1".to_string()],
        ExtendedKeyUsagePurpose::ServerAuth,
        2,
        None,
    );
    let (trusted_cert, trusted_key) = signed_leaf(
        &issuer,
        "trusted-client",
        vec!["trusted.example".to_string()],
        ExtendedKeyUsagePurpose::ClientAuth,
        3,
        dp_url,
    );
    let (other_cert, other_key) = signed_leaf(
        &issuer,
        "other-trusted-client",
        vec!["other.example".to_string()],
        ExtendedKeyUsagePurpose::ClientAuth,
        4,
        None,
    );

    let ca_pem = ca_cert.pem();
    let ca_der = ca_cert.der().as_ref().to_vec();
    let hashes = ca_hashes(&ca_der);
    let trusted = signed_identity(&trusted_cert, &trusted_key, &ca_pem);
    let other = signed_identity(&other_cert, &other_key, &ca_pem);

    let crl_revokes_trusted = crl_fixture(&issuer, &trusted.serial, (2100, 1, 1));
    let crl_revokes_other = crl_fixture(&issuer, &other.serial, (2100, 1, 1));
    let crl_stale = crl_fixture(&issuer, &trusted.serial, (2020, 1, 2));
    let mut crl_tampered = crl_revokes_trusted.clone();
    flip_last_byte(&mut crl_tampered);

    let ocsp_good = ocsp_fixture(
        &ca_key,
        &hashes,
        &trusted.serial,
        OcspFixtureStatus::Good,
        FRESH_NEXT_UPDATE,
    );
    let ocsp_revoked = ocsp_fixture(
        &ca_key,
        &hashes,
        &trusted.serial,
        OcspFixtureStatus::Revoked,
        FRESH_NEXT_UPDATE,
    );
    let ocsp_unknown = ocsp_fixture(
        &ca_key,
        &hashes,
        &trusted.serial,
        OcspFixtureStatus::Unknown,
        FRESH_NEXT_UPDATE,
    );
    let ocsp_stale = ocsp_fixture(
        &ca_key,
        &hashes,
        &trusted.serial,
        OcspFixtureStatus::Good,
        STALE_NEXT_UPDATE,
    );
    let ocsp_other_serial = ocsp_fixture(
        &ca_key,
        &hashes,
        &other.serial,
        OcspFixtureStatus::Good,
        FRESH_NEXT_UPDATE,
    );
    let mut ocsp_tampered = ocsp_good.clone();
    flip_last_byte(&mut ocsp_tampered);

    Fixture {
        ca_pem: ca_pem.clone(),
        ca_der,
        server_chain_pem: format!("{}{}", server_cert.pem(), ca_pem),
        server_key_pem: server_key.serialize_pem(),
        trusted,
        other,
        crl_revokes_trusted,
        crl_revokes_other,
        crl_stale,
        crl_tampered,
        ocsp_good,
        ocsp_revoked,
        ocsp_unknown,
        ocsp_stale,
        ocsp_other_serial,
        ocsp_tampered,
    }
}

fn signed_leaf<S: SigningKey>(
    issuer: &Issuer<'_, S>,
    common_name: &str,
    names: Vec<String>,
    eku: ExtendedKeyUsagePurpose,
    serial: u64,
    dp_url: Option<&str>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(names).expect("leaf parameters");
    params.serial_number = Some(SerialNumber::from(serial));
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.extended_key_usages.push(eku);
    params.use_authority_key_identifier_extension = true;
    if let Some(url) = dp_url {
        params.custom_extensions.push(crl_dp_extension(url));
    }
    let key = KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, issuer).expect("leaf certificate");
    (cert, key)
}

/// CRLDistributionPoints ::= { DistributionPoint { [0] { [0] { [6] URI } } } }
fn crl_dp_extension(url: &str) -> rcgen::CustomExtension {
    let content = tlv(
        0x30,
        &tlv(0x30, &tlv(0xa0, &tlv(0xa0, &tlv(0x86, url.as_bytes())))),
    );
    rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 31], content)
}

fn signed_identity(cert: &rcgen::Certificate, key: &KeyPair, ca_pem: &str) -> ClientIdentity {
    ClientIdentity {
        chain_pem: format!("{}{}", cert.pem(), ca_pem),
        key_pem: key.serialize_pem(),
        serial: canonical_serial(cert.der().as_ref()),
    }
}

fn canonical_serial(der: &[u8]) -> Vec<u8> {
    let (_, cert) = parse_x509_certificate(der).expect("client certificate DER");
    let raw = cert.raw_serial();
    let first = raw
        .iter()
        .position(|byte| *byte != 0)
        .expect("nonzero client serial");
    raw[first..].to_vec()
}

fn ca_hashes(ca_der: &[u8]) -> CaHashes {
    let (_, cert) = parse_x509_certificate(ca_der).expect("CA certificate DER");
    let subject_raw = cert.subject().as_raw().to_vec();
    let name_hash = Sha256::digest(&subject_raw).to_vec();
    let key_hash = Sha256::digest(cert.public_key().subject_public_key.data.as_ref()).to_vec();
    CaHashes {
        subject_raw,
        name_hash,
        key_hash,
    }
}

fn crl_fixture<S: SigningKey>(
    issuer: &Issuer<'_, S>,
    serial: &[u8],
    next_update: (i32, u8, u8),
) -> Vec<u8> {
    let params = CertificateRevocationListParams {
        this_update: date_time_ymd(2020, 1, 1),
        next_update: date_time_ymd(next_update.0, next_update.1, next_update.2),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from_slice(serial),
            revocation_time: date_time_ymd(2020, 1, 2),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    };
    params
        .signed_by(issuer)
        .expect("CA-signed CRL")
        .der()
        .as_ref()
        .to_vec()
}

fn ocsp_fixture(
    ca_key: &KeyPair,
    ca: &CaHashes,
    serial: &[u8],
    status: OcspFixtureStatus,
    next_update: &[u8; 15],
) -> Vec<u8> {
    let cert_id = sequence(&[
        SHA256_ALGORITHM_ID.to_vec(),
        tlv(0x04, &ca.name_hash),
        tlv(0x04, &ca.key_hash),
        tlv(0x02, serial),
    ]);
    let cert_status = match status {
        OcspFixtureStatus::Good => vec![0x80, 0x00],
        OcspFixtureStatus::Revoked => tlv(0xa1, &generalized_time(REVOCATION_TIME)),
        OcspFixtureStatus::Unknown => vec![0x82, 0x00],
    };
    let single = sequence(&[
        cert_id,
        cert_status,
        generalized_time(THIS_UPDATE),
        tlv(0xa0, &generalized_time(next_update)),
    ]);
    // ResponderID byName is the CA subject Name, wrapped in explicit [1].
    let responder_id = tlv(0xa1, &ca.subject_raw);
    let tbs = sequence(&[
        responder_id,
        generalized_time(THIS_UPDATE),
        sequence(&[single]),
    ]);
    let signature = ca_key.sign(&tbs).expect("CA signs BasicOCSPResponse");
    let mut signature_bits = vec![0u8];
    signature_bits.extend_from_slice(&signature);
    sequence(&[
        tbs,
        ECDSA_SHA256_ALGORITHM_ID.to_vec(),
        tlv(0x03, &signature_bits),
    ])
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for part in parts {
        content.extend_from_slice(part);
    }
    tlv(0x30, &content)
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else if length <= 0xff {
        out.push(0x81);
        out.push(length as u8);
    } else {
        out.push(0x82);
        out.push((length >> 8) as u8);
        out.push(length as u8);
    }
    out.extend_from_slice(content);
    out
}

fn generalized_time(value: &[u8; 15]) -> Vec<u8> {
    tlv(0x18, value)
}

fn flip_last_byte(bytes: &mut [u8]) {
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
}
