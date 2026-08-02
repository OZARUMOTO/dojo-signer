// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ELECTRUM — zero-dependency Electrum JSON-RPC client over plain TCP.
//
// The MuSig2 vault auto-discovers its REAL balance by asking the connected
// Dojo's bundled Electrum server (electrs / Fulcrum on plain TCP 50001, or the
// Dojo indexer) for the unspent outputs of every derived P2TR receive script:
//
//     blockchain.scripthash.listunspent
//
// with the Electrum "scripthash" = byte-reversed SHA256(scriptPubKey).
// Everything used here is already in the locked dependency tree — `std::net`
// does the socket, `serde_json` does the framing, and the bitcoin `sha256`
// hashes come from ngwallet — so nothing new has to be downloaded on the
// offline build host.
//
// HOSTED-NOTE: the Passport Prime device itself is BLE-only (quantum-link) and
// never opens sockets; this module exists so the hosted simulator can talk to
// a real Dojo/electrs on the LAN and pull REAL vault balances — replacing the
// old "bdk wallet that was never synced" discovery, which could never find
// anything on-chain. SSL (50002) is intentionally rejected: a plain-TCP client
// has no TLS machinery, and the UI falls back to the manual txid:vout entry.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use ngwallet::bdk_wallet::bitcoin::hashes::{sha256, Hash};

/// One unspent output as reported by `blockchain.scripthash.listunspent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectrumUtxo {
    /// Transaction id in DISPLAY (reverse) byte order — matches
    /// `Txid::to_string()` and what `VaultTx::build` parses.
    pub tx_hash: String,
    pub tx_pos: u32,
    pub value_sats: u64,
    pub height: i64,
}

#[derive(Debug)]
pub enum ElectrumError {
    Io(String),
    Rpc(String),
    BadResponse(String),
}

impl core::fmt::Display for ElectrumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "electrum io: {e}"),
            Self::Rpc(e) => write!(f, "electrum rpc error: {e}"),
            Self::BadResponse(e) => write!(f, "electrum bad response: {e}"),
        }
    }
}

impl std::error::Error for ElectrumError {}

/// Electrum "scripthash": SHA256(scriptPubKey) with the digest byte-reversed,
/// hex-encoded. This is the lookup key for all `blockchain.scripthash.*`
/// methods, including `listunspent` used for vault balance discovery.
pub fn scripthash_hex(script: &[u8]) -> String {
    let digest = sha256::Hash::hash(script).to_byte_array();
    let mut rev = digest;
    rev.reverse();
    hex::encode(rev)
}

/// Query `blockchain.scripthash.listunspent` for a single scripthash over a
/// plain-TCP connection. Returns the unspent outputs (empty when the address
/// has never received coin), or an error when the server can't be reached or
/// rejects the query.
pub fn list_unspent(
    host: &str,
    port: u16,
    scripthash: &str,
) -> Result<Vec<ElectrumUtxo>, ElectrumError> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| ElectrumError::Io(e.to_string()))?
        .next()
        .ok_or_else(|| ElectrumError::Io("no address resolved".into()))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| ElectrumError::Io(e.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| ElectrumError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| ElectrumError::Io(e.to_string()))?;

    let req = format!(
        "{{\"id\":1,\"method\":\"blockchain.scripthash.listunspent\",\"params\":[\"{}\"]}}\n",
        scripthash
    );
    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| ElectrumError::Io(e.to_string()))?;

    // electrs / Fulcrum speak HTTP-ish "Content-Length:" framing; some servers
    // reply with bare newline-delimited JSON. Handle both.
    let body = read_response(&mut stream)?;

    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| ElectrumError::BadResponse(format!("json: {e}")))?;
    // Successful JSON-RPC responses carry `"error": null`; only a NON-null
    // error object is a failure.
    if let Some(err) = value.get("error").filter(|e| !e.is_null()) {
        return Err(ElectrumError::Rpc(err.to_string()));
    }
    let result = value
        .get("result")
        .and_then(|r| r.as_array())
        .ok_or_else(|| ElectrumError::BadResponse("missing result array".into()))?;

    let mut utxos = Vec::new();
    for u in result {
        utxos.push(ElectrumUtxo {
            tx_hash: u.get("tx_hash").and_then(|h| h.as_str()).unwrap_or("").to_string(),
            tx_pos: u.get("tx_pos").and_then(|p| p.as_u64()).unwrap_or(0) as u32,
            value_sats: u.get("value").and_then(|v| v.as_u64()).unwrap_or(0),
            height: u.get("height").and_then(|h| h.as_i64()).unwrap_or(0),
        });
    }
    Ok(utxos)
}

/// Read a JSON-RPC response body from the socket, handling both the
/// Content-Length framing used by electrs/Fulcrum and the bare
/// newline-delimited protocol used by older servers.
fn read_response(stream: &mut TcpStream) -> Result<String, ElectrumError> {
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    reader
        .read_line(&mut first)
        .map_err(|e| ElectrumError::Io(e.to_string()))?;

    if first.starts_with("Content-Length:") {
        let n: usize = first
            .trim_start_matches("Content-Length:")
            .trim()
            .parse()
            .map_err(|_| ElectrumError::BadResponse("bad Content-Length".into()))?;
        // Drain the remaining headers up to the blank line.
        loop {
            let mut line = String::new();
            let read = reader
                .read_line(&mut line)
                .map_err(|e| ElectrumError::Io(e.to_string()))?;
            if read == 0 || line.trim().is_empty() {
                break;
            }
        }
        let mut body = vec![0u8; n];
        reader
            .read_exact(&mut body)
            .map_err(|e| ElectrumError::Io(e.to_string()))?;
        String::from_utf8(body).map_err(|e| ElectrumError::BadResponse(e.to_string()))
    } else {
        // Newline-delimited protocol: the first line is the JSON response.
        Ok(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// Bind a local server that answers one request with the given body using
    /// Content-Length framing, and return (port, handle).
    fn canned_server_crlf(body: &'static str) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = String::new();
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            reader.read_line(&mut req).unwrap();
            assert!(req.contains("blockchain.scripthash.listunspent"));
            let framed = format!("Content-Length: {}\r\n\r\n{}", body.len(), body);
            sock.write_all(framed.as_bytes()).unwrap();
        });
        (port, handle)
    }

    #[test]
    fn scripthash_matches_known_answers() {
        // Vector 1: P2TR script OP_1 <32×0x11>.
        let s1 = hex::decode(
            "51201111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        assert_eq!(
            scripthash_hex(&s1),
            "994a2bf6fea18f26cf5a88124cfb2d9f993b3717641b9be3b5c2a963a987c9e8"
        );
        // Vector 2: P2PKH script.
        let s2 = hex::decode("76a914111111111111111111111111111111111111111188ac").unwrap();
        assert_eq!(
            scripthash_hex(&s2),
            "0e86768a14a61e71306f240f5b8bb92ced2f1abfb246b82d9356549834c2f6e2"
        );
        // Vector 3: P2TR script with distinct bytes.
        let s3 = hex::decode("5120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        assert_eq!(
            scripthash_hex(&s3),
            "043ac9f1efb5c820391e10d2f1cc071d8a97ac84722dad0b1b747670aeae4a12"
        );
    }

    #[test]
    fn list_unspent_parses_canned_response() {
        let body = r#"{"id":1,"result":[{"height":840000,"tx_hash":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899","tx_pos":0,"value":5000000},{"height":840001,"tx_hash":"112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00","tx_pos":1,"value":750000}],"error":null}"#;
        let (port, handle) = canned_server_crlf(body);
        let utxos = list_unspent("127.0.0.1", port, "994a2bf6fea18f26cf5a88124cfb2d9f993b3717641b9be3b5c2a963a987c9e8")
            .unwrap();
        handle.join().unwrap();
        assert_eq!(utxos.len(), 2);
        assert_eq!(utxos[0].value_sats, 5_000_000);
        assert_eq!(utxos[0].tx_pos, 0);
        assert_eq!(utxos[0].tx_hash, "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
        assert_eq!(utxos[1].value_sats, 750_000);
        assert_eq!(utxos[1].tx_pos, 1);
        assert_eq!(utxos[1].height, 840_001);
    }

    #[test]
    fn list_unspent_empty_result() {
        let body = r#"{"id":1,"result":[],"error":null}"#;
        let (port, handle) = canned_server_crlf(body);
        let utxos = list_unspent("127.0.0.1", port, "994a2bf6fea18f26cf5a88124cfb2d9f993b3717641b9be3b5c2a963a987c9e8")
            .unwrap();
        handle.join().unwrap();
        assert!(utxos.is_empty());
    }

    #[test]
    fn list_unspent_surfaces_rpc_error() {
        let body = r#"{"id":1,"result":null,"error":{"code":-32601,"message":"method not found"}}"#;
        let (port, handle) = canned_server_crlf(body);
        let err = list_unspent("127.0.0.1", port, "994a2bf6fea18f26cf5a88124cfb2d9f993b3717641b9be3b5c2a963a987c9e8")
            .unwrap_err();
        handle.join().unwrap();
        assert!(matches!(err, ElectrumError::Rpc(_)));
        assert!(err.to_string().contains("method not found"));
    }

    #[test]
    fn newline_framed_response_parses() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = String::new();
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            reader.read_line(&mut req).unwrap();
            // Bare newline-delimited JSON, no Content-Length header.
            sock.write_all(
                br#"{"id":1,"result":[{"height":0,"tx_hash":"00","tx_pos":0,"value":42}],"error":null}"#
                    .as_slice(),
            )
            .and_then(|_| sock.write_all(b"\n"))
            .unwrap();
        });
        let utxos = list_unspent("127.0.0.1", port, "00").unwrap();
        handle.join().unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].value_sats, 42);
    }

    #[test]
    fn connection_refused_is_io_error() {
        // Bind then drop the listener so nothing is listening on the port.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = list_unspent("127.0.0.1", port, "00").unwrap_err();
        assert!(matches!(err, ElectrumError::Io(_)));
    }
}
