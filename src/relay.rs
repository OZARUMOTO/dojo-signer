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

    #[test]
    fn connection_refused_is_io_error() {
        // Bind a socket and close it so the port is (almost certainly) free,
        // then confirm we get a clean RelayError::Io, not a panic.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let tx = ngwallet::bdk_wallet::bitcoin::Transaction {
            version: ngwallet::bdk_wallet::bitcoin::transaction::Version(2),
            lock_time: ngwallet::bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let err = broadcast_psbt(&format!("127.0.0.1:{port}"), &psbt).unwrap_err();
        assert!(matches!(err, RelayError::Io(_)), "got {err:?}");
    }
}
