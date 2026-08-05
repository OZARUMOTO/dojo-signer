// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// TRACK — register derived vault addresses with the box's bwt Electrum server.
//
// The MuSig2 vault's taproot receive addresses are derived from the 3-device
// aggregate key, so they CANNOT be derived from any single xpub that bwt could
// be configured with at startup. When the app derives one (vault receive +
// balance discovery), it tells the local bwt instance to watch it through its
// HTTP API:
//
//     POST http://127.0.0.1:3060/track_address
//     { "address": "bc1p...", "rescan_since": "now" }
//
// bwt queues the address as a pending standalone import, runs a sync, and the
// address then shows balances/history over Electrum — which is exactly what the
// vault auto-discovery queries via `blockchain.scripthash.listunspent`.
//
// HOSTED-NOTE: the Passport Prime device itself is BLE-only (quantum-link) and
// never opens sockets; this module exists so the hosted simulator can register
// addresses with the box's bwt directly. On hardware the companion fronts the
// same Electrum endpoint and vault addresses are discovered through the
// quantum-link path instead.
//
// Zero-dependency: `std::net` does the socket, `serde_json` the framing —
// mirrors the relay.rs / electrum.rs conventions.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// bwt HTTP REST API bind (bwt's default is 127.0.0.1:3060).
const BWT_HTTP_HOST: &str = "127.0.0.1";
const BWT_HTTP_PORT: u16 = 3060;

#[derive(Debug)]
pub enum TrackError {
    Io(String),
    BadStatus(String),
}

impl core::fmt::Display for TrackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "track io: {e}"),
            Self::BadStatus(e) => write!(f, "track bad status: {e}"),
        }
    }
}

impl std::error::Error for TrackError {}

/// Register `address` with the local bwt instance so it starts watching it.
/// Best-effort: on failure the app still works (manual txid:vout fallback), so
/// callers log at debug level and continue.
pub fn register(address: &str) -> Result<(), TrackError> {
    register_to(BWT_HTTP_HOST, BWT_HTTP_PORT, address)
}

/// The real implementation — host/port injectable so tests can point at a
/// canned server on an ephemeral port.
fn register_to(host: &str, port: u16, address: &str) -> Result<(), TrackError> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| TrackError::Io(e.to_string()))?
        .next()
        .ok_or_else(|| TrackError::Io("no address resolved".into()))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| TrackError::Io(format!("connect bwt: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| TrackError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| TrackError::Io(e.to_string()))?;

    let body = format!("{{\"address\":\"{}\",\"rescan_since\":\"now\"}}", address);
    let request = format!(
        "POST /track_address HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        host,
        port,
        body.len(),
        body
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| TrackError::Io(format!("send: {e}")))?;
    stream
        .flush()
        .map_err(|e| TrackError::Io(format!("flush: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader
        .read_line(&mut status)
        .map_err(|e| TrackError::Io(format!("read status: {e}")))?;
    if !status.starts_with("HTTP/1.1 2") {
        return Err(TrackError::BadStatus(status.trim().to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// Bind a local server that answers one request with the given status line,
    /// capturing the raw request bytes so tests can assert on the wire format.
    fn canned_server(status: &'static str) -> (u16, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            // Read request HEADERS only (the client keeps the socket open for
            // the response, so read_to_string would deadlock).
            let mut req = String::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = sock.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                req.push_str(&String::from_utf8_lossy(&buf[..n]));
                if req.contains("\r\n\r\n") {
                    break;
                }
            }
            let resp = format!("{}\r\nContent-Length: 2\r\n\r\nOK", status);
            sock.write_all(resp.as_bytes()).unwrap();
            req
        });
        (port, handle)
    }

    #[test]
    fn register_posts_address_and_parses_2xx() {
        let (port, handle) = canned_server("HTTP/1.1 202 Accepted");
        register_to("127.0.0.1", port, "bc1qrvu7qgl6p793k2m7xh0m5e93uwv7gd3tatal6e").unwrap();
        let req = handle.join().unwrap();
        assert!(req.starts_with("POST /track_address HTTP/1.1"));
        assert!(req.contains("Content-Type: application/json"));
        assert!(req.contains("\"address\":\"bc1qrvu7qgl6p793k2m7xh0m5e93uwv7gd3tatal6e\""));
        assert!(req.contains("\"rescan_since\":\"now\""));
    }

    #[test]
    fn register_surfaces_non_2xx_status() {
        let (port, _) = canned_server("HTTP/1.1 400 Bad Request");
        let err =
            register_to("127.0.0.1", port, "bc1qrvu7qgl6p793k2m7xh0m5e93uwv7gd3tatal6e")
                .unwrap_err();
        match err {
            TrackError::BadStatus(s) => assert!(s.starts_with("HTTP/1.1 400")),
            other => panic!("expected BadStatus, got {:?}", other),
        }
    }
}
