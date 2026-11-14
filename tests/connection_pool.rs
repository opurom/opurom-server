//! Connection pool integration tests over real loopback TCP.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::time::{Duration, Instant};

use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::MiddlewareChain;
use opurom_server::router::Router;
use opurom_server::server::Server;

const REQUESTS: usize = 32;

fn router() -> Router {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    router
}

fn server(max_connections: usize, idle_timeout: Duration) -> Server {
    Server::bind_with("127.0.0.1:0", router(), MiddlewareChain::new(), 1024 * 1024)
        .expect("server binds")
        .with_max_connections(max_connections)
        .with_idle_timeout(idle_timeout)
}

#[test]
fn a_full_pool_answers_a_fixed_overload() {
    let server = server(1, Duration::from_secs(30)).with_keep_alive();
    let pool = server.pool().expect("the pool is valid").clone();
    let (addr, shutdown) = server.spawn().expect("server spawns");

    let mut busy = TcpStream::connect(addr).expect("busy connection");
    busy.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("busy read timeout");
    busy.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("busy request");

    let mut rejected = TcpStream::connect(addr).expect("rejected connection");
    rejected
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("rejected read timeout");
    let mut raw = Vec::new();
    rejected
        .read_to_end(&mut raw)
        .expect("the rejection is readable");
    let answer = String::from_utf8_lossy(&raw).into_owned();
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
    assert!(answer.contains("server_busy"), "{answer}");
    assert!(
        answer.contains("X-Connection-Pool-Reason: connection_pool_full"),
        "{answer}"
    );
    let metrics = pool.metrics();
    assert!(metrics.rejected >= 1);

    drop(busy);
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn concurrent_loopback_requests_are_measured() {
    let server = server(REQUESTS, Duration::from_secs(5));
    let pool = server.pool().expect("the pool is valid").clone();
    let (addr, shutdown) = server.spawn().expect("server spawns");
    let barrier = Arc::new(Barrier::new(REQUESTS));
    let started = Instant::now();

    let handles = (0..REQUESTS)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let addr: SocketAddr = addr;
            thread::spawn(move || {
                barrier.wait();
                let mut stream = TcpStream::connect(addr).expect("client connects");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("client read timeout");
                stream
                    .write_all(
                        b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .expect("client writes");
                let mut raw = Vec::new();
                stream
                    .read_to_end(&mut raw)
                    .expect("client reads the answer");
                let answer = String::from_utf8_lossy(&raw).into_owned();
                answer.contains("HTTP/1.1 200") && answer.contains("{\"ok\":true}")
            })
        })
        .collect::<Vec<_>>();

    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap_or(false))
        .collect::<Vec<_>>();
    let elapsed = started.elapsed();
    let accepted = results.iter().filter(|ok| **ok).count();
    let lost = REQUESTS - accepted;
    let throughput = REQUESTS as f64 / elapsed.as_secs_f64();

    assert_eq!(accepted, REQUESTS);
    assert_eq!(lost, 0);
    assert!(elapsed.as_nanos() > 0);
    assert!(throughput.is_finite() && throughput > 0.0);
    let metrics = pool.metrics();
    assert_eq!(metrics.accepted, REQUESTS as u64);
    assert_eq!(metrics.rejected, 0);
    println!(
        "[pool] requests={} accepted={} lost={} elapsed_ms={} throughput={:.1}/s",
        REQUESTS,
        accepted,
        lost,
        elapsed.as_millis(),
        throughput
    );

    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
}
