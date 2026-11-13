#![allow(dead_code)]

//! Shared real h2 client helper for the TLS integration tests.
//!
//! All requests in one `exchange` call use one TLS connection and one h2
//! connection, with response tasks and body writes driven concurrently.

use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::client::{ResponseFuture, SendRequest};
use h2::SendStream;
use http::{HeaderName, HeaderValue, Method, Request, Version};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::runtime::Builder;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

#[derive(Clone, Debug)]
pub struct Identity {
    pub chain_pem: String,
    pub key_pem: String,
}

#[derive(Clone, Debug)]
pub struct RequestSpec {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RequestSpec {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> RequestSpec {
        RequestSpec {
            method: method.into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn get(path: impl Into<String>) -> RequestSpec {
        RequestSpec::new("GET", path)
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> RequestSpec {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> RequestSpec {
        self.body = body;
        self
    }
}

#[derive(Clone, Debug)]
pub struct ResponseSpec {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ResponseSpec {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Open one ALPN-`h2` TLS connection and exchange every request concurrently.
/// The returned responses are in request order.
pub fn exchange(
    port: u16,
    root_der: &[u8],
    identity: Option<&Identity>,
    requests: Vec<RequestSpec>,
) -> Result<(Option<String>, Vec<ResponseSpec>), String> {
    let root_der = root_der.to_vec();
    let identity = identity.cloned();
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        match tokio::time::timeout(
            Duration::from_secs(20),
            run(port, root_der, identity, requests),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err("h2 exchange timed out".to_string()),
        }
    })
}

async fn run(
    port: u16,
    root_der: Vec<u8>,
    identity: Option<Identity>,
    requests: Vec<RequestSpec>,
) -> Result<(Option<String>, Vec<ResponseSpec>), String> {
    let config = client_config(&root_der, identity.as_ref())?;
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|err| err.to_string())?;
    let server_name = ServerName::try_from("localhost").map_err(|err| err.to_string())?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|err| err.to_string())?;
    let alpn = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
    let (send_request, connection): (SendRequest<Bytes>, _) = h2::client::handshake(tls)
        .await
        .map_err(|err| err.to_string())?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let result = exchange_requests(send_request, requests).await;
    connection_task.abort();
    Ok((alpn, result?))
}

async fn exchange_requests(
    send_request: SendRequest<Bytes>,
    requests: Vec<RequestSpec>,
) -> Result<Vec<ResponseSpec>, String> {
    let count = requests.len();
    let mut responses: JoinSet<(usize, Result<ResponseSpec, String>)> = JoinSet::new();
    let mut writers: JoinSet<Result<(), String>> = JoinSet::new();
    for (index, spec) in requests.iter().enumerate() {
        let mut sender = send_request
            .clone()
            .ready()
            .await
            .map_err(|err| err.to_string())?;
        let mut builder = Request::builder()
            .method(Method::from_bytes(spec.method.as_bytes()).map_err(|err| err.to_string())?)
            .uri(format!("https://localhost{}", spec.path))
            .version(Version::HTTP_2);
        for (name, value) in &spec.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|err| err.to_string())?;
            let value = HeaderValue::from_str(value).map_err(|err| err.to_string())?;
            builder = builder.header(name, value);
        }
        let request = builder.body(()).map_err(|err| err.to_string())?;
        let has_body = !spec.body.is_empty();
        let (response, send_stream) = sender
            .send_request(request, !has_body)
            .map_err(|err| err.to_string())?;
        let _ = responses.spawn(read_response(index, response));
        if has_body {
            let body = spec.body.clone();
            let _ = writers.spawn(write_request_body(send_stream, body));
        } else {
            drop(send_stream);
        }
    }

    let mut slots: Vec<Option<ResponseSpec>> = (0..count).map(|_| None).collect();
    for _ in 0..count {
        let joined = responses
            .join_next()
            .await
            .ok_or_else(|| "missing h2 response".to_string())?;
        let (index, answer) = joined.map_err(|err| err.to_string())?;
        slots[index] = Some(answer?);
    }
    while let Some(result) = writers.join_next().await {
        result.map_err(|err| err.to_string())??;
    }
    slots
        .into_iter()
        .map(|slot| slot.ok_or_else(|| "missing h2 response".to_string()))
        .collect()
}

async fn read_response(
    index: usize,
    response: ResponseFuture,
) -> (usize, Result<ResponseSpec, String>) {
    (index, read_response_inner(response).await)
}

async fn read_response_inner(response: ResponseFuture) -> Result<ResponseSpec, String> {
    let response = response.await.map_err(|err| err.to_string())?;
    let (parts, mut body) = response.into_parts();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|err| err.to_string())?;
        let size = chunk.len();
        bytes.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(size)
            .map_err(|err| err.to_string())?;
    }
    Ok(ResponseSpec {
        status: parts.status.as_u16(),
        headers,
        body: bytes,
    })
}

async fn write_request_body(mut stream: SendStream<Bytes>, body: Vec<u8>) -> Result<(), String> {
    // h2 frames this bounded buffer and applies flow control as the connection
    // task is polled; the test drives several such streams concurrently.
    stream
        .send_data(Bytes::from(body), true)
        .map_err(|err| err.to_string())
}

fn client_config(root_der: &[u8], identity: Option<&Identity>) -> Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .map_err(|err| err.to_string())?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let mut config = match identity {
        Some(identity) => {
            let certs = rustls_pemfile::certs(&mut BufReader::new(identity.chain_pem.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| err.to_string())?;
            let key = rustls_pemfile::private_key(&mut BufReader::new(identity.key_pem.as_bytes()))
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "missing client private key".to_string())?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|err| err.to_string())?
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}
