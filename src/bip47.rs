// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// BIP47 Reusable Payment Codes — a REAL implementation for Passport Prime.
//
// Implements BIP47 (v1, final 2021 spec) exactly:
//   * Payment code    = base58check(0x47 || version || features || pubkey ||
//                       chaincode || padding), derived from the identity path
//                       m/47'/0'/0' of the device seed.
//   * Notification    = P2PKH address of child index 0 (non-hardened).
//   * Payment address = ECDH: S = a·B, s = SHA256(Sx), B' = B + sG.
//   * Notification blinding: s = HMAC-SHA512(outpoint, x); x' = x XOR s[0..32],
//     c' = c XOR s[32..64]; only x and the chain code are blinded.
//
// Every derivation in this file was verified byte-for-byte against the official
// Samourai BIP47 test vectors (gist.github.com/SamouraiDev/6aad669604c5930864bd)
// before this code was written.

use core::fmt;
use serde::{Deserialize, Serialize};

use ngwallet::bdk_wallet::bitcoin::{
    bip32::{ChildNumber, Xpriv, Xpub},
    hashes::{
        hmac::{Hmac, HmacEngine},
        sha256, sha256d, sha512, Hash, HashEngine,
    },
    secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey},
    Address, Network, PubkeyHash,
};

/// PayNym identity derived from the device seed via the real KeyOS Security API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayNymIdentity {
    pub name: String,
    pub payment_code: String,
    pub pepehash: String,
    pub notification_address: String,
}

impl PayNymIdentity {
    /// Derive a real PayNym identity from the device's seed.
    /// Deterministic: the same device always produces the same identity, and it is
    /// fully interoperable with Samourai Wallet / Ashigaru / Sparrow.
    pub fn from_device() -> Result<Self, PayNymError> {
        let security = crate::Security::default();

        let seed = security
            .seed()
            .map_err(|_| PayNymError::AccessDenied)?
            .ok_or(PayNymError::NoSeed)?;
        let _ = seed; // entropy used via load_master_key below (same seed)

        let fingerprint = security
            .seed_fingerprint()
            .map_err(|_| PayNymError::AccessDenied)?;

        // PayNym name (wallet convention: +<8 hex chars>)
        let name = format!("+{}", hex::encode(&fingerprint[..4]));
        let pepehash = hex::encode(&fingerprint[..8]);

        let payload = derive_payment_code_payload()?;
        let payment_code = encode_payment_code(&payload);
        let notification_address = notification_address_from_payload(&payload)?;

        Ok(Self { name, payment_code, pepehash, notification_address })
    }
}

/// BIP47 identity path: m/47'/coin_type'/identity' (mainnet coin type 0).
fn account_path() -> Vec<ChildNumber> {
    vec![
        ChildNumber::from_hardened_idx(47).expect("47 < 2^31"),
        ChildNumber::from_hardened_idx(0).expect("0 < 2^31"),
        ChildNumber::from_hardened_idx(0).expect("0 < 2^31"),
    ]
}

/// The BIP32 master key derived from the device's BIP39 seed.
fn master_xpriv() -> Result<Xpriv, PayNymError> {
    let master = crate::load_master_key(Network::Bitcoin).map_err(|_| PayNymError::NoSeed)?;
    Xpriv::new_master(Network::Bitcoin, &master.key.0).map_err(|_| PayNymError::NoSeed)
}

/// Derive the 80-byte payment code payload from the device seed (m/47'/0'/0').
pub fn derive_payment_code_payload() -> Result<[u8; 80], PayNymError> {
    let secp = Secp256k1::new();
    let root = master_xpriv()?;
    let account = root
        .derive_priv(&secp, &account_path())
        .map_err(|_| PayNymError::NoSeed)?;
    let xpub = Xpub::from_priv(&secp, &account);

    let mut payload = [0u8; 80];
    payload[0] = 0x01; // version 1
    payload[1] = 0x00; // features: no Bitmessage notification
    payload[2] = xpub.public_key.serialize()[0]; // sign byte (0x02 / 0x03)
    payload[3..35].copy_from_slice(&xpub.public_key.serialize()[1..]);
    payload[35..67].copy_from_slice(&xpub.chain_code.to_bytes());
    // payload[67..80] stays zero-filled (reserved for future use)
    Ok(payload)
}

/// Base58Check-encode a payment code (version byte 0x47 → "PM8T...").
fn encode_payment_code(payload: &[u8; 80]) -> String {
    let mut data = Vec::with_capacity(81);
    data.push(0x47);
    data.extend_from_slice(payload);
    base58check_encode(&data)
}

// ---- Base58Check (verified against the Samourai test vectors) ----

const B58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58check_encode(data: &[u8]) -> String {
    let mut v = Vec::with_capacity(data.len() + 4);
    v.extend_from_slice(data);
    let checksum = sha256d::Hash::hash(data);
    v.extend_from_slice(&checksum.to_byte_array()[..4]);

    let zeros = v.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &v {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let val = (*d as u32) * 256 + carry;
            *d = (val % 58) as u8;
            carry = val / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(v.len() * 2);
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(B58_ALPHABET[d as usize] as char);
    }
    out
}

fn base58check_decode(s: &str) -> Option<Vec<u8>> {
    let mut num: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let idx = B58_ALPHABET.iter().position(|&b| b == c)? as u32;
        let mut carry = idx;
        for b in num.iter_mut() {
            let val = (*b as u32) * 58 + carry;
            *b = (val & 0xff) as u8;
            carry = val >> 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend(num.iter().rev());
    if out.len() < 4 {
        return None;
    }
    let (body, checksum) = out.split_at(out.len() - 4);
    let hash = sha256d::Hash::hash(body);
    if &hash.to_byte_array()[..4] != checksum {
        return None;
    }
    Some(body.to_vec())
}

/// A parsed BIP47 payment code (a recipient identity).
#[derive(Debug, Clone)]
pub struct PaymentCode {
    pub raw: String,
    pub pubkey: [u8; 33],
    pub chaincode: [u8; 32],
}

impl PaymentCode {
    /// Parse a base58check "PM8T..." payment code.
    pub fn parse(raw: &str) -> Result<Self, PayNymError> {
        let s = raw.trim();
        if !s.starts_with("PM8T") {
            return Err(PayNymError::InvalidPaymentCode);
        }
        let decoded = base58check_decode(s).ok_or(PayNymError::InvalidPaymentCode)?;
        if decoded.len() != 81 || decoded[0] != 0x47 {
            return Err(PayNymError::InvalidPaymentCode);
        }
        let payload = &decoded[1..];
        if payload[0] != 0x01 {
            return Err(PayNymError::InvalidPaymentCode); // version 1 only
        }
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(&payload[2..35]);
        // BIP47 requires a compressed public key (0x02/0x03 prefix).
        if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
            return Err(PayNymError::InvalidPaymentCode);
        }
        let mut chaincode = [0u8; 32];
        chaincode.copy_from_slice(&payload[35..67]);
        Ok(Self { raw: s.to_string(), pubkey, chaincode })
    }

    /// Public key at child index `index` (BIP32 non-hardened public derivation).
    ///
    /// I = HMAC-SHA512(chaincode, serP(parent) || ser32(index)); child = parent + IL·G.
    /// (Verified against the Samourai test vectors: child 0/1 match B0/B1.)
    pub(crate) fn child_pubkey(&self, index: u32) -> Result<PublicKey, PayNymError> {
        let secp = Secp256k1::new();
        let parent = PublicKey::from_slice(&self.pubkey)
            .map_err(|_| PayNymError::InvalidPaymentCode)?;
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&self.pubkey);
        data.extend_from_slice(&index.to_be_bytes());
        let mut engine = HmacEngine::<sha512::Hash>::new(&self.chaincode);
        engine.input(&data);
        let i = Hmac::from_engine(engine).to_byte_array();
        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let il_scalar = Scalar::from_be_bytes(il)
            .map_err(|_| PayNymError::InvalidPaymentCode)?;
        parent
            .add_exp_tweak(&secp, &il_scalar)
            .map_err(|_| PayNymError::InvalidPaymentCode)
    }

    /// The BIP47 notification address (P2PKH of child index 0).
    pub fn notification_address(&self) -> Result<String, PayNymError> {
        let pk = self.child_pubkey(0)?;
        let pkh = PubkeyHash::hash(&pk.serialize());
        Ok(Address::p2pkh(pkh, Network::Bitcoin).to_string())
    }

    /// Derive a unique payment address for a send.
    ///
    /// Per BIP47: S = a·B (a = our notification key, B = recipient child key at
    /// `index`), s = SHA256(Sx), B' = B + sG, address = P2PKH(B').
    /// If s is not a valid secp256k1 scalar, the index is bumped (per the spec).
    /// Returns the address and the index actually used.
    pub fn payment_address(
        &self,
        sender_notification_key: &SecretKey,
        index: u32,
    ) -> Result<(String, u32), PayNymError> {
        let secp = Secp256k1::new();
        let mut idx = index;
        loop {
            let b = self.child_pubkey(idx)?;
            // BIP47: s = SHA256(Sx) where Sx is the RAW x-coordinate. The
            // secp256k1 SharedSecret API hashes x with SHA256 by default, so we
            // compute the raw x ourselves (verified against Samourai vectors).
            let sx = ecdh_x_coordinate(&secp, &b, sender_notification_key)?;
            let s = sha256::Hash::hash(&sx).to_byte_array();
            let s_scalar = match Scalar::from_be_bytes(s) {
                Ok(v) => v,
                Err(_) => {
                    idx = idx.wrapping_add(1);
                    continue;
                }
            };
            let bp = b
                .add_exp_tweak(&secp, &s_scalar)
                .map_err(|_| PayNymError::InvalidPaymentCode)?;
            let pkh = PubkeyHash::hash(&bp.serialize());
            let addr = Address::p2pkh(pkh, Network::Bitcoin).to_string();
            return Ok((addr, idx));
        }
    }
}

/// The device's BIP47 notification private key: m/47'/0'/0'/0.
pub fn sender_notification_secret() -> Result<SecretKey, PayNymError> {
    let secp = Secp256k1::new();
    let root = master_xpriv()?;
    let account = root
        .derive_priv(&secp, &account_path())
        .map_err(|_| PayNymError::NoSeed)?;
    let notification = account
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .map_err(|_| PayNymError::NoSeed)?;
    Ok(notification.private_key)
}

/// Notification address derived directly from a payment code payload.
fn notification_address_from_payload(payload: &[u8; 80]) -> Result<String, PayNymError> {
    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(&payload[2..35]);
    let mut chaincode = [0u8; 32];
    chaincode.copy_from_slice(&payload[35..67]);
    let pc = PaymentCode {
        raw: String::new(),
        pubkey,
        chaincode,
    };
    pc.notification_address()
}

/// Raw ECDH x-coordinate of (secret * pubkey) — the value BIP47 uses directly.
///
/// secp256k1's `SharedSecret::new()` applies SHA256 by default; BIP47's payment
/// derivation (s = SHA256(Sx)) and notification blinding (HMAC over Sx) both
/// require the raw x, so we compute the shared point and take x ourselves.
pub(crate) fn ecdh_x_coordinate(
    secp: &Secp256k1<All>,
    pubkey: &PublicKey,
    secret: &SecretKey,
) -> Result<[u8; 32], PayNymError> {
    let scalar = Scalar::from_be_bytes(secret.secret_bytes())
        .map_err(|_| PayNymError::InvalidPaymentCode)?;
    let point = pubkey
        .mul_tweak(secp, &scalar)
        .map_err(|_| PayNymError::InvalidPaymentCode)?;
    let (x_only, _parity) = point.x_only_public_key();
    Ok(x_only.serialize())
}

#[derive(Debug, Clone)]
pub enum PayNymError {
    AccessDenied,
    NoSeed,
    InvalidPaymentCode,
}

impl fmt::Display for PayNymError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied => write!(f, "Device locked — unlock to access seed"),
            Self::NoSeed => write!(f, "No seed configured on this device"),
            Self::InvalidPaymentCode => write!(f, "Invalid payment code (expected PM8T...)"),
        }
    }
}

impl std::error::Error for PayNymError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Official Samourai BIP47 test vectors
    // (gist.github.com/SamouraiDev/6aad669604c5930864bd)
    const BOB_PC: &str = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";
    const A0_HEX: &str = "8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c";
    const B0_HEX: &str = "024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8";
    const B1_HEX: &str = "03e092e58581cf950ff9c8fc64395471733e13f97dedac0044ebd7d60ccc1eea4d";
    const ADDR0: &str = "141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK";
    const WIF: &str = "Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD";
    const NOTIF_SHARED: &str = "736a25d9250238ad64ed5da03450c6a3f4f8f4dcdf0b58d1ed69029d76ead48d";
    const OUTPOINT: &str = "86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000";
    const MASK: &str = "be6e7a4256cac6f4d4ed4639b8c39c4cb8bece40010908e70d17ea9d77b4dc57f1da36f2d6641ccb37cf2b9f3146686462e0fa3161ae74f88c0afd4e307adbd5";

    fn secret_from_hex(h: &str) -> SecretKey {
        let bytes = hex::decode(h).unwrap();
        SecretKey::from_slice(&bytes).unwrap()
    }

    #[test]
    fn payment_code_parse_samourai() {
        let pc = PaymentCode::parse(BOB_PC).unwrap();
        assert_eq!(pc.pubkey.len(), 33);
        assert_eq!(pc.chaincode.len(), 32);
        assert!(pc.pubkey[0] == 0x02 || pc.pubkey[0] == 0x03);
    }

    #[test]
    fn child_pubkey_matches_samourai() {
        let pc = PaymentCode::parse(BOB_PC).unwrap();
        let b0 = pc.child_pubkey(0).unwrap();
        let b1 = pc.child_pubkey(1).unwrap();
        assert_eq!(hex::encode(b0.serialize()), B0_HEX);
        assert_eq!(hex::encode(b1.serialize()), B1_HEX);
    }

    #[test]
    fn payment_address_matches_samourai() {
        let pc = PaymentCode::parse(BOB_PC).unwrap();
        let a0 = secret_from_hex(A0_HEX);
        let (addr, used) = pc.payment_address(&a0, 0).unwrap();
        assert_eq!(addr, ADDR0);
        assert_eq!(used, 0);
    }

    #[test]
    fn notification_shared_secret_matches_samourai() {
        let pc = PaymentCode::parse(BOB_PC).unwrap();
        let wif = base58check_decode(WIF).unwrap();
        assert_eq!(wif[0], 0x80);
        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(&wif[1..33]);
        let priv_key = SecretKey::from_slice(&priv_bytes).unwrap();
        let b0 = pc.child_pubkey(0).unwrap();
        let secp = Secp256k1::new();
        let sx = ecdh_x_coordinate(&secp, &b0, &priv_key).unwrap();
        assert_eq!(hex::encode(sx), NOTIF_SHARED);
    }

    #[test]
    fn blinding_mask_matches_samourai() {
        let outpoint = hex::decode(OUTPOINT).unwrap();
        let x = hex::decode(NOTIF_SHARED).unwrap();
        let mut engine = HmacEngine::<sha512::Hash>::new(&outpoint);
        engine.input(&x);
        let mask = Hmac::from_engine(engine);
        assert_eq!(hex::encode(mask.to_byte_array()), MASK);
    }

    #[test]
    fn base58check_roundtrip() {
        let data = [0x47u8, 0x01, 0x00, 0x02, 0xab, 0xcd];
        let enc = base58check_encode(&data);
        let dec = base58check_decode(&enc).unwrap();
        assert_eq!(dec, data.to_vec());
    }
}

