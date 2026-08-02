// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// At-rest credential protection for config.json.
//
// The Dojo node RPC password is a network credential (not Bitcoin key
// material), but we still refuse to persist it in plaintext. It is encrypted
// with a key derived from the device-bound, app-scoped seed
// (security::app_seed) — so the ciphertext in config.json is useless without
// THIS device and THIS app.
//
// Construction (Encrypt-then-MAC, built ONLY from the sha256/HashEngine
// primitives already in the dependency tree — the os/crypto AES-GCM path is
// stubbed in the hosted simulator, and no AEAD crate exists in the locked
// tree, so this is the one construction that behaves identically in the
// simulator and on real hardware):
//
//   key        = SHA256(app_seed || "dojo-signer:node-cred:v1")
//   keystream  = HMAC-SHA256(key, nonce || counter)     (CTR mode)
//   ciphertext = plaintext XOR keystream
//   tag        = HMAC-SHA256(key, nonce || ciphertext)
//   envelope   = "v1:" || hex(nonce) || ":" || hex(ct) || ":" || hex(tag)
//
// app_seed() is derived by the security server as HMAC-SHA256(app_id,
// master_seed) — device-bound AND app-scoped, so the blob cannot be
// decrypted on another device or by another app, even with the same seed.

use ngwallet::bdk_wallet::bitcoin::hashes::{sha256, Hash, HashEngine};

const DOMAIN: &[u8] = b"dojo-signer:node-cred:v1";
const NONCE_LEN: usize = 16;

/// Derive the at-rest encryption key from the device-bound app seed.
pub fn derive_key(app_seed: &[u8; 32]) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    e.input(app_seed);
    e.input(DOMAIN);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// HMAC-SHA256 (RFC 2104), built from the sha256 HashEngine already used
/// elsewhere in the app — no new dependencies.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // Hash the key down to one block if it is longer than the block size.
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256::Hash::hash(key).to_byte_array());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = {
        let mut e = sha256::Hash::engine();
        e.input(&ipad);
        e.input(data);
        sha256::Hash::from_engine(e).to_byte_array()
    };
    let mut e = sha256::Hash::engine();
    e.input(&opad);
    e.input(&inner);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// Keystream block `counter` for CTR mode: HMAC-SHA256(key, nonce || counter).
fn keystream_block(key: &[u8; 32], nonce: &[u8; NONCE_LEN], counter: u32) -> [u8; 32] {
    let mut data = Vec::with_capacity(NONCE_LEN + 4);
    data.extend_from_slice(nonce);
    data.extend_from_slice(&counter.to_be_bytes());
    hmac_sha256(key, &data)
}

/// CTR-mode transform (symmetric — decrypt is the same operation).
fn xor_stream(key: &[u8; 32], nonce: &[u8; NONCE_LEN], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let ks = keystream_block(key, nonce, i as u32);
        for (j, b) in chunk.iter_mut().enumerate() {
            *b ^= ks[j];
        }
    }
    out
}

/// Authentication tag over the ciphertext: HMAC-SHA256(key, nonce || ct).
fn tag(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ct: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(NONCE_LEN + ct.len());
    data.extend_from_slice(nonce);
    data.extend_from_slice(ct);
    hmac_sha256(key, &data)
}

/// Encrypt `plaintext` with `key` and a caller-supplied 16-byte nonce, and
/// return the "v1:nonce:ct:tag" envelope string stored in config.json.
pub fn protect(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> String {
    let ct = xor_stream(key, nonce, plaintext);
    let t = tag(key, nonce, &ct);
    format!("v1:{}:{}:{}", hex::encode(nonce), hex::encode(ct), hex::encode(t))
}

/// Decrypt and verify a "v1:nonce:ct:tag" envelope. Returns the plaintext
/// only if the tag verifies; any corruption or a wrong key yields None (the
/// caller must NOT fall back to an unverified value).
pub fn unprotect(key: &[u8; 32], envelope: &str) -> Option<String> {
    let parts: Vec<&str> = envelope.splitn(4, ':').collect();
    if parts.len() != 4 || parts[0] != "v1" {
        return None;
    }
    let nonce = hex::decode(parts[1]).ok()?;
    let ct = hex::decode(parts[2]).ok()?;
    let t = hex::decode(parts[3]).ok()?;
    if nonce.len() != NONCE_LEN || t.len() != 32 {
        return None;
    }
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&nonce);
    if !ct_eq(&tag(key, &n, &ct), &t) {
        return None;
    }
    String::from_utf8(xor_stream(key, &n, &ct)).ok()
}

/// Constant-time comparison for tag verification.
fn ct_eq(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != 32 {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_known_answer() {
        // RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There".
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn protect_roundtrips() {
        let key = derive_key(&[0x11u8; 32]);
        let nonce = [0x22u8; 16];
        let blob = protect(&key, &nonce, b"S3cr3t-D0j0-P@ss!");
        assert!(blob.starts_with("v1:"));
        assert_eq!(unprotect(&key, &blob).unwrap(), "S3cr3t-D0j0-P@ss!");
    }

    #[test]
    fn envelope_hides_plaintext_and_key_material() {
        let key = derive_key(&[0x33u8; 32]);
        let nonce = [0x44u8; 16];
        let pw = "dojo-node-password-9000";
        let blob = protect(&key, &nonce, pw.as_bytes());
        assert!(!blob.contains(pw), "plaintext leaked into envelope");
        assert!(!blob.contains("333333333333"), "key material leaked into envelope");
    }

    #[test]
    fn wrong_key_or_tamper_is_rejected() {
        let key = derive_key(&[0x55u8; 32]);
        let nonce = [0x66u8; 16];
        let blob = protect(&key, &nonce, b"correct horse battery staple");

        // A different device/app seed derives a different key -> no decrypt.
        let other = derive_key(&[0x77u8; 32]);
        assert!(unprotect(&other, &blob).is_none());

        // Corrupt one hex digit in the ciphertext portion (after "v1:" + 32
        // hex chars of nonce): the tag must fail and nothing is returned.
        let mut v = blob.clone().into_bytes();
        let idx = 3 + 32;
        let orig = v[idx];
        v[idx] = if orig == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(v).unwrap();
        assert_ne!(tampered, blob);
        assert!(unprotect(&key, &tampered).is_none());
    }

    #[test]
    fn derive_key_is_deterministic_and_domain_separated() {
        let seed = [0x88u8; 32];
        assert_eq!(derive_key(&seed), derive_key(&seed));
        // Different app seed -> different key.
        assert_ne!(derive_key(&seed), derive_key(&[0x99u8; 32]));
    }
}
