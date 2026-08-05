// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// RELAY — submit signed transactions through the surf-relay gateway.
//
// The BLUETOOTH BROWSER surf-relay is a tiny internet arm that speaks JSON
// envelopes over plain TCP (the same wire a future BLE bridge fronts). Its
// `broadcast` envelope takes a signed PSBT (base64), asks the configured
// bitcoind to finalize it (`finalizepsbt`) and submit it
// (`sendrawtransaction`), and returns the node-confirmed txid in a
// `broadcast-result` envelope. No third party ever sees the transaction.
//
// HOSTED-NOTE: the Passport Prime device itself is BLE-only (quantum-link)
// and never opens sockets; this module exists so the hosted simulator can
// talk to the surf-relay on the LAN and push REAL transactions to the box's
// bitcoin node. On hardware the companion app fronts the same envelope
// protocol and the device keeps using the quantum-link PublishPsbt path.
//
// Everything used here is already in the locked dependency tree —
// `std::net` does the socket, `serde_json` does the framing, and
// `coinjoin::base64_encode` (already in this crate) does the RFC-4648
// encoding — so nothing new has to be downloaded on the offline build host.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use ngwallet::bdk_wallet::bitcoin::Psbt;

#[derive(Debug)]
pub enum RelayError {
    Io(String),
    BadReply(String),
    Node(String),
}

impl core::fmt::Display for RelayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "relay io: {e}"),
            Self::BadReply(e) => write!(f, "relay bad reply: {e}"),
            Self::Node(e) => write!(f, "node: {e}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Probe the relay gateway with a `ping` envelope (the settings UI shows
/// relay online/offline from this). Returns Ok(()) when the relay answers
/// `pong` within the timeout.
pub fn ping(relay: &str) -> Result<(), RelayError> {
    let (host, port) = split_addr(relay)?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| RelayError::Io(e.to_string()))?
        .next()
        .ok_or_else(|| RelayError::Io("no address resolved".into()))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| RelayError::Io(format!("connect {relay}: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| RelayError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| RelayError::Io(e.to_string()))?;

    stream
        .write_all(b"{\"type\":\"ping\"}\n")
        .map_err(|e| RelayError::Io(format!("send ping: {e}")))?;
    stream
        .flush()
        .map_err(|e| RelayError::Io(format!("flush: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    reader
        .read_line(&mut reply)
        .map_err(|e| RelayError::Io(format!("read pong: {e}")))?;
    let v: serde_json::Value = serde_json::from_str(reply.trim())
        .map_err(|e| RelayError::BadReply(format!("ping reply not json: {e}")))?;
    if v.get("type").and_then(|t| t.as_str()) == Some("pong") {
        Ok(())
    } else {
        Err(RelayError::BadReply(format!("unexpected ping reply: {reply}")))
    }
}

/// Fetch live Whirlpool pool statistics through the surf-relay gateway.
///
/// The Passport device is BLE-only, so it asks the box (which has internet)
/// to pull whirlpoolstats.xyz and hand back the JSON. The relay replies with
/// a `stats-result` envelope carrying `data` = `{ "summary": {...}, "txs": [...] }`.
pub fn fetch_stats(relay: &str) -> Result<serde_json::Value, RelayError> {
    let (host, port) = split_addr(relay)?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| RelayError::Io(e.to_string()))?
        .next()
        .ok_or_else(|| RelayError::Io("no address resolved".into()))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| RelayError::Io(format!("connect {relay}: {e}")))?;
    // The relay makes two bounded upstream fetches (20s each with the relay's
    // per-request cap), so allow comfortably more than the worst case here.
    stream
        .set_read_timeout(Some(Duration::from_secs(50)))
        .map_err(|e| RelayError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| RelayError::Io(e.to_string()))?;

    stream
        .write_all(b"{\"type\":\"stats\"}\n")
        .map_err(|e| RelayError::Io(format!("send stats: {e}")))?;
    stream
        .flush()
        .map_err(|e| RelayError::Io(format!("flush: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    reader
        .read_line(&mut reply)
        .map_err(|e| RelayError::Io(format!("read stats reply: {e}")))?;
    let v: serde_json::Value = serde_json::from_str(reply.trim())
        .map_err(|e| RelayError::BadReply(format!("stats reply not json: {e}")))?;
    if v.get("type").and_then(|t| t.as_str()) != Some("stats-result") {
        return Err(RelayError::BadReply(format!(
            "unexpected stats reply: {reply}"
        )));
    }
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        if !err.is_empty() {
            return Err(RelayError::Node(err.to_string()));
        }
    }
    v.get("data")
        .cloned()
        .ok_or_else(|| RelayError::BadReply("stats reply missing data".into()))
}

/// Split a "host:port" relay address into its parts.
fn split_addr(relay: &str) -> Result<(String, u16), RelayError> {
    let (host, port) = relay
        .trim()
        .rsplit_once(':')
        .ok_or_else(|| RelayError::Io("expected relay as host:port".into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| RelayError::Io(format!("bad relay port in {relay:?}")))?;
    Ok((host.to_string(), port))
}

/// Submit a signed PSBT through the surf-relay gateway.
///
/// The relay asks its bitcoind to finalize the PSBT and broadcast it, then
/// replies with the node-confirmed txid. Returns that txid, or an error with
/// the node's own rejection message.
pub fn broadcast_psbt(relay: &str, psbt: &Psbt) -> Result<String, RelayError> {
    let (host, port) = split_addr(relay)?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| RelayError::Io(e.to_string()))?
        .next()
        .ok_or_else(|| RelayError::Io("no address resolved".into()))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| RelayError::Io(format!("connect {relay}: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| RelayError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| RelayError::Io(e.to_string()))?;

    let psbt_b64 = crate::coinjoin::base64_encode(&psbt.serialize());
    let envelope = serde_json::json!({
        "type": "broadcast",
        "id": "1",
        "psbt": psbt_b64,
    });
    let mut line = serde_json::to_string(&envelope)
        .map_err(|e| RelayError::Io(format!("encode envelope: {e}")))?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| RelayError::Io(format!("send envelope: {e}")))?;
    stream
        .flush()
        .map_err(|e| RelayError::Io(format!("flush: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader
        .read_line(&mut reply_line)
        .map_err(|e| RelayError::Io(format!("read reply: {e}")))?;

    let reply: serde_json::Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| RelayError::BadReply(format!("not json: {e}")))?;
    if reply.get("type").and_then(|t| t.as_str()) != Some("broadcast-result") {
        return Err(RelayError::BadReply(format!(
            "unexpected envelope type: {:?}",
            reply.get("type")
        )));
    }
    if let Some(err) = reply.get("error").and_then(|e| e.as_str()) {
        if !err.is_empty() {
            return Err(RelayError::Node(err.to_string()));
        }
    }
    match reply.get("txid").and_then(|t| t.as_str()) {
        Some(txid) if txid.len() == 64 => Ok(txid.to_string()),
        _ => Err(RelayError::BadReply(format!(
            "missing txid in {:?}",
            reply.get("txid")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_addr_parses_host_port() {
        assert_eq!(split_addr("127.0.0.1:8787").unwrap(), ("127.0.0.1".into(), 8787));
        assert!(split_addr("no-port").is_err());
        assert!(split_addr("host:notaport").is_err());
    }

    fn empty_psbt() -> Psbt {
        let tx = ngwallet::bdk_wallet::bitcoin::Transaction {
            version: ngwallet::bdk_wallet::bitcoin::transaction::Version(2),
            lock_time: ngwallet::bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    const OK_TXID: &str =
        "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    /// A canned fake relay: reads one broadcast envelope, verifies its shape,
    /// replies with the given response line. Mirrors electrum.rs's
    /// `canned_server_crlf` test convention.
    fn canned_relay(reply: String) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(sock.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let env: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(env["type"], "broadcast");
            let psbt_b64 = env["psbt"].as_str().unwrap_or("");
            assert!(!psbt_b64.is_empty(), "envelope must carry a base64 PSBT");
            assert!(psbt_b64.starts_with("cHNid"), "expected PSBT magic");
            sock.write_all(reply.as_bytes()).unwrap();
        });
        (port, handle)
    }

    #[test]
    fn connection_refused_is_io_error() {
        // Bind a socket and close it so the port is (almost certainly) free,
        // then confirm we get a clean RelayError::Io, not a panic.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = broadcast_psbt(&format!("127.0.0.1:{port}"), &empty_psbt()).unwrap_err();
        assert!(matches!(err, RelayError::Io(_)), "got {err:?}");
    }

    #[test]
    fn happy_path_roundtrips_txid() {
        let reply = format!(
            "{{\"type\":\"broadcast-result\",\"id\":\"1\",\"txid\":\"{}\",\"error\":null}}\n",
            OK_TXID
        );
        let (port, handle) = canned_relay(reply);
        let txid = broadcast_psbt(&format!("127.0.0.1:{port}"), &empty_psbt()).unwrap();
        assert_eq!(txid, OK_TXID);
        handle.join().unwrap();
    }

    #[test]
    fn node_error_reply_is_surfaced() {
        let (port, handle) = canned_relay(
            "{\"type\":\"broadcast-result\",\"id\":\"1\",\"txid\":null,\"error\":\"rpc error -22: TX decode failed\"}\n"
                .into(),
        );
        let err = broadcast_psbt(&format!("127.0.0.1:{port}"), &empty_psbt()).unwrap_err();
        assert!(matches!(err, RelayError::Node(e) if e.contains("TX decode failed")));
        handle.join().unwrap();
    }

    #[test]
    fn bad_reply_type_is_surfaced() {
        let (port, handle) = canned_relay("{\"type\":\"page\",\"id\":\"1\"}\n".into());
        let err = broadcast_psbt(&format!("127.0.0.1:{port}"), &empty_psbt()).unwrap_err();
        assert!(matches!(err, RelayError::BadReply(_)), "got {err:?}");
        handle.join().unwrap();
    }

    /// A canned relay that answers a ping with the given reply.
    fn canned_ping(reply: &'static str) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(sock.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert!(line.contains("\"type\":\"ping\""), "expected ping, got {line}");
            sock.write_all(reply.as_bytes()).unwrap();
        });
        (port, handle)
    }

    #[test]
    fn fetch_stats_happy_path() {
        let reply = "{\"type\":\"stats-result\",\"data\":{\"summary\":{\"tip_height\":961171,\"pools\":[]},\"txs\":[]}}\n";
        let (port, handle) = canned_stats(reply);
        let data = fetch_stats(&format!("127.0.0.1:{port}")).unwrap();
        handle.join().unwrap();
        assert_eq!(data["summary"]["tip_height"], 961171);
    }

    #[test]
    fn fetch_stats_surfaces_relay_error() {
        let reply = "{\"type\":\"stats-result\",\"error\":\"whirlpoolstats.xyz unreachable\"}\n";
        let (port, handle) = canned_stats(reply);
        let err = fetch_stats(&format!("127.0.0.1:{port}")).unwrap_err();
        handle.join().unwrap();
        assert!(matches!(err, RelayError::Node(e) if e.contains("unreachable")));
    }

    #[test]
    fn fetch_stats_bad_reply_type() {
        let (port, handle) = canned_stats("{\"type\":\"page\",\"id\":\"1\"}\n");
        let err = fetch_stats(&format!("127.0.0.1:{port}")).unwrap_err();
        handle.join().unwrap();
        assert!(matches!(err, RelayError::BadReply(_)), "got {err:?}");
    }

    /// A canned relay that answers a stats request with the given reply.
    fn canned_stats(reply: &'static str) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(sock.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert!(line.contains("\"type\":\"stats\""), "expected stats, got {line}");
            sock.write_all(reply.as_bytes()).unwrap();
        });
        (port, handle)
    }

    #[test]
    fn ping_ok_when_pong() {
        let (port, handle) = canned_ping("{\"type\":\"pong\"}\n");
        ping(&format!("127.0.0.1:{port}")).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn ping_fails_on_unexpected_reply() {
        let (port, handle) = canned_ping("{\"type\":\"page\",\"id\":\"1\"}\n");
        let err = ping(&format!("127.0.0.1:{port}")).unwrap_err();
        assert!(matches!(err, RelayError::BadReply(_)), "got {err:?}");
        handle.join().unwrap();
    }
}
