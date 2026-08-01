// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// MU SIG VAULT — the app layer for a 3-of-3 MuSig2 (BIP-327) vault.
//
// Three Passport Primes cooperate to form ONE aggregate payment code (PM8T...)
// whose key is the MuSig2 aggregate of all three — the "savings vault". No
// device ever holds the aggregate private key. This module turns the verified
// musig.rs primitives (key_agg, nonce_gen, nonce_agg, sign, partial_sig_agg)
// into a real multi-device flow driven entirely by camera-scanned QR payloads:
//
//   * Setup    — each device exports its own BIP47 payment code; any device
//                scans all N, builds the aggregate payment code, and every
//                device recomputes the SAME vault from the shared codes.
//   * Receive  — the aggregate payment code + notification address are shown
//                as a QR; senders pay the vault like any BIP47 identity.
//   * Spend    — four QR rounds produce a single BIP340 signature:
//                R1 each device exports a pubnonce
//                R2 the coordinator combines them -> session (aggnonce)
//                R3 each device exports a partial signature
//                R4 the coordinator aggregates -> 64-byte signature, verified
//                   on-device against the vault's BIP47 child key.
//
// The message signed is a 32-byte spend-authorization digest (in production,
// the BIP341 sighash of the actual transaction). Every primitive is verified
// byte-for-byte against the official BIP-327 vectors in musig.rs; the tests
// here run the FULL 3-device flow through the QR codec end to end.

use core::fmt;

use ngwallet::bdk_wallet::bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{schnorr, Message, PublicKey, Scalar, Secp256k1, SecretKey},
};
use serde::{Deserialize, Serialize};

use crate::bip47::PaymentCode;
use crate::musig::{
    aggregate_payment_code, key_agg_sorted, key_sort, nonce_agg, nonce_gen, partial_sig_agg,
    partial_sig_verify, sign, SessionContext, Tweak,
};

/// Versioned prefix for every vault QR payload (allows protocol evolution).
pub const QR_PROTOCOL: &str = "DOJOV1";

#[derive(Debug, Clone)]
pub enum VaultError {
    /// Fewer than two participants supplied.
    NotEnoughParticipants,
    /// A payment code failed to parse.
    InvalidPaymentCode,
    /// A cryptographic primitive rejected its inputs.
    Musig(String),
    /// A QR payload was malformed or for a different protocol version.
    MalformedQr,
    /// The spend round sequence is wrong (e.g. signing before a session).
    WrongRound(&'static str),
    /// Not enough nonces / partial signatures collected yet.
    NeedMoreSigners(&'static str),
    /// The final signature failed verification (a signer was wrong).
    SignatureVerificationFailed,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnoughParticipants => write!(f, "Vault needs at least two devices"),
            Self::InvalidPaymentCode => write!(f, "Invalid payment code (expected PM8T...)"),
            Self::Musig(e) => write!(f, "MuSig2 error: {}", e),
            Self::MalformedQr => write!(f, "Malformed vault QR payload"),
            Self::WrongRound(what) => write!(f, "Wrong round: {}", what),
            Self::NeedMoreSigners(what) => write!(f, "Need more {} to continue", what),
            Self::SignatureVerificationFailed => write!(f, "Signature verification FAILED"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<crate::musig::MusigError> for VaultError {
    fn from(e: crate::musig::MusigError) -> Self {
        Self::Musig(e.to_string())
    }
}

/// The persisted vault identity: the N participant payment codes plus the
/// aggregate payment code every device computes from them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultConfig {
    /// Participant BIP47 payment codes (PM8T...), in collection order.
    pub participants: Vec<String>,
    /// The aggregate payment code (PM8T...) — the vault's receive identity.
    pub aggregate_code: String,
}

impl VaultConfig {
    /// Build the vault from the collected participant payment codes.
    /// Order-independent: every device that collects the same codes computes
    /// the same aggregate (musig::aggregate_payment_code sorts internally).
    pub fn build(participants: &[String]) -> Result<Self, VaultError> {
        if participants.len() < 2 {
            return Err(VaultError::NotEnoughParticipants);
        }
        // Deduplicate identical device pubkeys (same device scanned twice).
        // The STORED participant list must match the aggregated key set exactly:
        // signing sessions derive their key list from `participants`, so any
        // duplicate here would aggregate a different key than the vault
        // identity and every signature would fail verification.
        let mut seen = std::collections::HashSet::new();
        let mut clean: Vec<String> = Vec::with_capacity(participants.len());
        let mut pks: Vec<[u8; 33]> = Vec::with_capacity(participants.len());
        let mut chaincodes: Vec<[u8; 32]> = Vec::with_capacity(participants.len());
        for raw in participants {
            let pc = PaymentCode::parse(raw).map_err(|_| VaultError::InvalidPaymentCode)?;
            if !seen.insert(pc.pubkey) {
                continue;
            }
            clean.push(raw.clone());
            pks.push(pc.pubkey);
            chaincodes.push(pc.chaincode);
        }
        if pks.len() < 2 {
            return Err(VaultError::NotEnoughParticipants);
        }
        let agg = aggregate_payment_code(&pks, &chaincodes)?;
        Ok(Self {
            participants: clean,
            aggregate_code: agg.payment_code.raw,
        })
    }

    /// The aggregate payment code, parsed for derivation.
    pub fn payment_code(&self) -> Result<PaymentCode, VaultError> {
        PaymentCode::parse(&self.aggregate_code).map_err(|_| VaultError::InvalidPaymentCode)
    }

    /// The vault's BIP47 notification address (P2PKH child 0).
    pub fn notification_address(&self) -> Result<String, VaultError> {
        self.payment_code()?.notification_address().map_err(|_| VaultError::InvalidPaymentCode)
    }

    /// A vault receive address: the P2PKH of child `index` of the aggregate
    /// payment code. Deterministic per index — rotate the index for fresh
    /// addresses (index 0 equals the notification address).
    pub fn receive_address(&self, index: u32) -> Result<String, VaultError> {
        self.payment_code()?.receive_address(index).map_err(|_| VaultError::InvalidPaymentCode)
    }

    /// Participant public keys in the canonical BIP-327 sorted order — the
    /// EXACT order every signing session must use (key_agg is order-dependent).
    pub fn sorted_pks(&self) -> Result<Vec<[u8; 33]>, VaultError> {
        let pks: Vec<[u8; 33]> = self
            .participants
            .iter()
            .map(|raw| PaymentCode::parse(raw).map(|p| p.pubkey))
            .collect::<Result<_, _>>()
            .map_err(|_| VaultError::InvalidPaymentCode)?;
        Ok(key_sort(&pks))
    }

    /// The x-only serialization of the aggregate key.
    pub fn agg_xonly(&self) -> Result<[u8; 32], VaultError> {
        Ok(key_agg_sorted(&self.sorted_pks()?)?.agg_xonly)
    }
}

// =====================================================================
// QR payload codec — everything a device hands to another device over
// the camera. Hex-encoded binary, pipe-separated, versioned.
// =====================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultQr {
    /// DOJOV1|SETUP|<payment_code> — a device's contribution to the vault.
    Setup(String),
    /// DOJOV1|VAULT|<aggregate_code> — broadcast so every device can verify
    /// it computed the same vault from the same participant codes.
    Vault(String),
    /// DOJOV1|NONCE|<pk hex>|<pubnonce hex> — round 1 contribution.
    Nonce { pk: [u8; 33], pubnonce: [u8; 66] },
    /// DOJOV1|SESSION|<msg hex>|<index>|<aggnonce hex> — round 2 broadcast.
    Session { msg: Vec<u8>, index: u32, aggnonce: [u8; 66] },
    /// DOJOV1|PSIG|<pk hex>|<psig hex> — round 3 contribution.
    Psig { pk: [u8; 33], psig: [u8; 32] },
}

impl VaultQr {
    pub fn encode(&self) -> String {
        match self {
            Self::Setup(code) => format!("{}|SETUP|{}", QR_PROTOCOL, code),
            Self::Vault(code) => format!("{}|VAULT|{}", QR_PROTOCOL, code),
            Self::Nonce { pk, pubnonce } => format!(
                "{}|NONCE|{}|{}",
                QR_PROTOCOL,
                hex::encode(pk),
                hex::encode(pubnonce)
            ),
            Self::Session { msg, index, aggnonce } => format!(
                "{}|SESSION|{}|{}|{}",
                QR_PROTOCOL,
                hex::encode(msg),
                index,
                hex::encode(aggnonce)
            ),
            Self::Psig { pk, psig } => format!(
                "{}|PSIG|{}|{}",
                QR_PROTOCOL,
                hex::encode(pk),
                hex::encode(psig)
            ),
        }
    }

    pub fn decode(s: &str) -> Result<Self, VaultError> {
        // Every valid payload has >= 3 pipe-separated parts (PROTOCOL|TYPE|...).
        // The len check prevents an out-of-bounds panic on scanner input like
        // "DOJOV1" or "DOJOV1|SETUP".
        let parts: Vec<&str> = s.trim().split('|').collect();
        if parts.len() < 3 || parts[0] != QR_PROTOCOL {
            return Err(VaultError::MalformedQr);
        }
        match parts[1] {
            "SETUP" => {
                if parts.len() != 3 {
                    return Err(VaultError::MalformedQr);
                }
                Ok(Self::Setup(parts[2].to_string()))
            }
            "VAULT" => {
                if parts.len() != 3 {
                    return Err(VaultError::MalformedQr);
                }
                Ok(Self::Vault(parts[2].to_string()))
            }
            "NONCE" => {
                if parts.len() != 4 {
                    return Err(VaultError::MalformedQr);
                }
                let pk: [u8; 33] = de_hex(parts[2])?.try_into().map_err(|_| VaultError::MalformedQr)?;
                let pubnonce: [u8; 66] =
                    de_hex(parts[3])?.try_into().map_err(|_| VaultError::MalformedQr)?;
                Ok(Self::Nonce { pk, pubnonce })
            }
            "SESSION" => {
                if parts.len() != 5 {
                    return Err(VaultError::MalformedQr);
                }
                let msg = de_hex(parts[2])?;
                let index: u32 = parts[3].parse().map_err(|_| VaultError::MalformedQr)?;
                let aggnonce: [u8; 66] =
                    de_hex(parts[4])?.try_into().map_err(|_| VaultError::MalformedQr)?;
                Ok(Self::Session { msg, index, aggnonce })
            }
            "PSIG" => {
                if parts.len() != 4 {
                    return Err(VaultError::MalformedQr);
                }
                let pk: [u8; 33] = de_hex(parts[2])?.try_into().map_err(|_| VaultError::MalformedQr)?;
                let psig: [u8; 32] =
                    de_hex(parts[3])?.try_into().map_err(|_| VaultError::MalformedQr)?;
                Ok(Self::Psig { pk, psig })
            }
            _ => Err(VaultError::MalformedQr),
        }
    }
}

fn de_hex(s: &str) -> Result<Vec<u8>, VaultError> {
    hex::decode(s).map_err(|_| VaultError::MalformedQr)
}

// =====================================================================
// The spend state machine — ONE device's view of a 4-round signing
// session. The secret secnonce never leaves this device; only pubnonces,
// the session context and partial signatures cross the camera.
// =====================================================================

#[derive(Clone)]
pub struct VaultSpend {
    /// The 32-byte digest being signed (the spend authorization / sighash).
    pub msg: Vec<u8>,
    /// BIP47 child index whose key is being spent (public tweak).
    pub index: u32,
    /// This device's own public key (from its BIP47 identity payment code).
    pub my_pk: [u8; 33],
    /// Round 1 secret nonce (NEVER exported).
    secnonce: Option<[u8; 97]>,
    /// Round 1 public nonce (exported to the coordinator).
    pubnonce: Option<[u8; 66]>,
    /// Pubnonces collected from the other devices, keyed by their pubkey.
    collected_nonces: Vec<([u8; 33], [u8; 66])>,
    /// Round 2 session context (aggnonce + keys + tweaks + msg).
    session: Option<SessionContext>,
    /// This device's partial signature (exported to the coordinator).
    my_psig: Option<[u8; 32]>,
    /// Partial signatures collected from the other devices, keyed by pubkey.
    collected_psigs: Vec<([u8; 33], [u8; 32])>,
}

impl VaultSpend {
    pub fn new(msg: Vec<u8>, index: u32, my_pk: [u8; 33]) -> Self {
        Self {
            msg,
            index,
            my_pk,
            secnonce: None,
            pubnonce: None,
            collected_nonces: Vec::new(),
            session: None,
            my_psig: None,
            collected_psigs: Vec::new(),
        }
    }

    /// Round 1: generate this device's pubnonce. `rand` MUST be 32 fresh
    /// TRNG bytes (Security::get_random on device).
    pub fn gen_nonce(
        &mut self,
        rand: [u8; 32],
        sk: &SecretKey,
        agg_xonly: [u8; 32],
    ) -> Result<[u8; 66], VaultError> {
        let (sec, pubn) = nonce_gen(
            rand,
            Some(sk),
            &self.my_pk,
            Some(agg_xonly),
            Some(&self.msg),
            &[],
        )?;
        self.secnonce = Some(sec);
        self.pubnonce = Some(pubn);
        Ok(pubn)
    }

    /// Record a pubnonce received from another device (identified by pubkey).
    pub fn add_pubnonce(&mut self, pk: [u8; 33], pubnonce: [u8; 66]) {
        if !self.collected_nonces.iter().any(|(p, _)| *p == pk) {
            self.collected_nonces.push((pk, pubnonce));
        }
    }

    /// Number of pubnonces collected from OTHER devices (for the UI).
    pub fn pubnonce_count(&self) -> usize {
        self.collected_nonces.len()
    }

    /// Number of partial signatures collected from OTHER devices (for the UI).
    pub fn psig_count(&self) -> usize {
        self.collected_psigs.len()
    }

    /// Round 2 (coordinator): combine ALL pubnonces (mine + collected) into
    /// the session context and return the aggnonce for the session broadcast.
    pub fn build_session(&mut self, vault: &VaultConfig) -> Result<[u8; 66], VaultError> {
        let mut all: Vec<[u8; 66]> = Vec::new();
        if let Some(mine) = self.pubnonce {
            all.push(mine);
        }
        all.extend(self.collected_nonces.iter().map(|(_, pn)| *pn));
        if all.len() < 2 {
            return Err(VaultError::NeedMoreSigners("pubnonces"));
        }
        let aggnonce = nonce_agg(&all)?;
        self.session = Some(self.make_session(aggnonce, vault)?);
        Ok(aggnonce)
    }

    /// Round 2 (signer path): reconstruct the session from a scanned
    /// SESSION QR (msg + index + aggnonce) using THIS device's vault config.
    pub fn set_session(
        &mut self,
        msg: Vec<u8>,
        index: u32,
        aggnonce: [u8; 66],
        vault: &VaultConfig,
    ) -> Result<(), VaultError> {
        self.msg = msg;
        self.index = index;
        self.session = Some(self.make_session(aggnonce, vault)?);
        Ok(())
    }

    /// Build the exact BIP-327 SessionContext: sorted participant keys,
    /// the BIP47 child-key tweak (plain tweak, as verified in the musig
    /// child-spend test), and the message.
    fn make_session(
        &self,
        aggnonce: [u8; 66],
        vault: &VaultConfig,
    ) -> Result<SessionContext, VaultError> {
        let il: [u8; 32] = vault
            .payment_code()?
            .child_il(self.index)
            .map_err(|_| VaultError::InvalidPaymentCode)?
            .to_be_bytes();
        Ok(SessionContext {
            aggnonce,
            pks: vault.sorted_pks()?,
            tweaks: vec![Tweak { t: il, is_xonly: false }],
            msg: self.msg.clone(),
        })
    }

    /// Round 3: produce this device's partial signature (requires the
    /// session context — either built here or scanned in via set_session).
    pub fn sign_partial(&mut self, sk: &SecretKey) -> Result<[u8; 32], VaultError> {
        let session = self
            .session
            .clone()
            .ok_or(VaultError::WrongRound("sign before the session context is set"))?;
        let secnonce = self
            .secnonce
            .ok_or(VaultError::WrongRound("sign before generating your nonce"))?;
        let psig = sign(&secnonce, sk, &session)?;
        self.my_psig = Some(psig);
        Ok(psig)
    }

    /// Record a partial signature received from another device.
    pub fn add_psig(&mut self, pk: [u8; 33], psig: [u8; 32]) {
        if !self.collected_psigs.iter().any(|(p, _)| *p == pk) {
            self.collected_psigs.push((pk, psig));
        }
    }

    /// DEMO-ONLY (KEYOS_DEMO_VAULT=1): fabricate R1 pubnonces for all three
    /// fixture devices and record them as collected nonces. The real device
    /// does not participate (its key is not a vault signer); it only
    /// coordinates the simulated session.
    pub fn demo_fabricate_nonces(
        &mut self,
        agg_xonly: [u8; 32],
    ) -> Result<Vec<([u8; 33], [u8; 66])>, VaultError> {
        let mut out = Vec::new();
        for (i, (sk, pk)) in demo_fixture_signing_keys().iter().enumerate() {
            let (_, pubn) = nonce_gen(
                demo_rand(i),
                Some(sk),
                pk,
                Some(agg_xonly),
                Some(&self.msg),
                &[],
            )?;
            self.add_pubnonce(*pk, pubn);
            out.push((*pk, pubn));
        }
        Ok(out)
    }

    /// DEMO-ONLY (KEYOS_DEMO_VAULT=1): fabricate R3 partial signatures for
    /// the three fixture devices against the CURRENT session and record them.
    pub fn demo_fabricate_psigs(
        &mut self,
        agg_xonly: [u8; 32],
    ) -> Result<Vec<([u8; 33], [u8; 32])>, VaultError> {
        let session = self
            .session
            .clone()
            .ok_or(VaultError::WrongRound("demo psigs before the session is set"))?;
        let mut out = Vec::new();
        for (i, (sk, pk)) in demo_fixture_signing_keys().iter().enumerate() {
            // Deterministic re-derivation of the R1 secnonce: same rand, key,
            // aggregate key and message -> same nonce pair -> valid partial.
            let (sec, _) = nonce_gen(
                demo_rand(i),
                Some(sk),
                pk,
                Some(agg_xonly),
                Some(&self.msg),
                &[],
            )?;
            let ps = sign(&sec, sk, &session)?;
            self.add_psig(*pk, ps);
            out.push((*pk, ps));
        }
        Ok(out)
    }

    /// Round 4: verify EVERY partial signature against its pubnonce, aggregate
    /// them into the final BIP340 signature, and verify the result against the
    /// vault's BIP47 child key — all on this device.
    pub fn finalize(&self, vault: &VaultConfig) -> Result<[u8; 64], VaultError> {
        let session = self
            .session
            .clone()
            .ok_or(VaultError::WrongRound("finalize before the session context is set"))?;

        // Assemble (psig, pubnonce, pk) per participant, matching by pubkey.
        let mut triples: Vec<([u8; 32], [u8; 66], [u8; 33])> = Vec::new();
        if let (Some(ps), Some(pn)) = (self.my_psig, self.pubnonce) {
            triples.push((ps, pn, self.my_pk));
        }
        for (pk, pn) in &self.collected_nonces {
            if let Some((_, ps)) = self.collected_psigs.iter().find(|(p, _)| p == pk) {
                triples.push((*ps, *pn, *pk));
            }
        }
        if triples.len() < 2 {
            return Err(VaultError::NeedMoreSigners("partial signatures"));
        }

        // Verify EVERY partial signature — a tampered or wrong-session one
        // fails here (partial_sig_verify is the BIP-327 check).
        for (ps, pn, pk) in &triples {
            partial_sig_verify(ps, pn, pk, &session)?;
        }

        let psigs: Vec<[u8; 32]> = triples.iter().map(|(ps, _, _)| *ps).collect();
        let sig = partial_sig_agg(&psigs, &session)?;

        // The final signature must verify against the CHILD (tweaked) key
        // xonly(X + IL·G) — the key the BIP47 child address spends from.
        let secp = Secp256k1::new();
        let agg = key_agg_sorted(&session.pks)?;
        let il: [u8; 32] = vault
            .payment_code()?
            .child_il(self.index)
            .map_err(|_| VaultError::InvalidPaymentCode)?
            .to_be_bytes();
        let il_scalar = Scalar::from_be_bytes(il).map_err(|_| VaultError::MalformedQr)?;
        let child_xonly = agg
            .agg_pubkey
            .add_exp_tweak(&secp, &il_scalar)
            .map_err(|_| VaultError::Musig("child tweak".into()))?
            .x_only_public_key()
            .0;
        let m = Message::from_digest_slice(&self.msg).map_err(|_| VaultError::MalformedQr)?;
        let s = schnorr::Signature::from_slice(&sig).map_err(|_| VaultError::MalformedQr)?;
        let xonly = &child_xonly;
        if secp.verify_schnorr(&s, &m, xonly).is_err() {
            return Err(VaultError::SignatureVerificationFailed);
        }
        Ok(sig)
    }
}

/// Build the SHA256 digest of a spend authorization string — the message the
/// vault signs. In production this is the BIP341 sighash of the transaction.
pub fn spend_message(authorization: &str) -> [u8; 32] {
    sha256::Hash::hash(authorization.as_bytes()).to_byte_array()
}

/// DEMO-ONLY — deterministic fixture device codes for the hosted simulator.
///
/// Gated behind KEYOS_DEMO_VAULT=1 in main.rs, this produces the SAME three
/// PM8T payment codes the unit-test fixture `three_devices()` derives, so a
/// single simulator device can build the vault and exercise the full receive
/// + spend flow for demo/screenshot purposes. The secrets are fixed test
/// constants — this must never be reachable in a shipped build.
pub fn demo_payment_codes() -> Vec<String> {
    let secp = Secp256k1::new();
    let mut codes = Vec::with_capacity(3);
    for (i, byte) in [0x61u8, 0x62, 0x63].iter().enumerate() {
        let mut sk = [0u8; 32];
        sk[31] = *byte;
        let d = SecretKey::from_slice(&sk).expect("fixture secret");
        let pk = PublicKey::from_secret_key(&secp, &d).serialize();
        let mut payload = [0u8; 80];
        payload[0] = 0x01; // version 1
        payload[1] = 0x00; // no bitmessage
        payload[2..35].copy_from_slice(&pk);
        let mut cc = [0u8; 32];
        cc[0] = (i as u8) + 1;
        payload[35..67].copy_from_slice(&cc);
        codes.push(crate::bip47::encode_payment_code(&payload));
    }
    codes
}

/// DEMO-ONLY — deterministic entropy for a fixture device's fabricated nonce
/// pair. `nonce_gen` is deterministic, so re-deriving with the same rand
/// reproduces the same secnonce, and the R3 partial signature is valid for
/// the pubnonce recorded in R1.
fn demo_rand(i: usize) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = 0xAA;
    r[1] = i as u8;
    r
}

/// DEMO-ONLY (KEYOS_DEMO_VAULT=1) — the three fixture device signing keys
/// (secret + pubkey) the demo vault is built from. The simulator device is
/// NOT one of these; this helper lets it fabricate their contributions so
/// the full 4-round spend can complete and verify on a single device.
pub fn demo_fixture_signing_keys() -> Vec<(SecretKey, [u8; 33])> {
    let secp = Secp256k1::new();
    [0x61u8, 0x62, 0x63]
        .iter()
        .map(|byte| {
            let mut sk = [0u8; 32];
            sk[31] = *byte;
            let d = SecretKey::from_slice(&sk).expect("fixture secret");
            let pk = PublicKey::from_secret_key(&secp, &d).serialize();
            (d, pk)
        })
        .collect()
}

// =====================================================================
// Tests — run the FULL 3-device vault flow through the QR codec.
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip47::encode_payment_code;
    use ngwallet::bdk_wallet::bitcoin::secp256k1::{All, PublicKey, XOnlyPublicKey};

    fn secret(byte: u8) -> SecretKey {
        let mut b = [0u8; 32];
        b[31] = byte;
        SecretKey::from_slice(&b).unwrap()
    }

    /// Build a realistic PM8T payment code payload for a device with the
    /// given secret + chaincode (mirrors derive_payment_code_payload).
    fn device_payment_code(secp: &Secp256k1<All>, d: &SecretKey, cc_byte: u8) -> String {
        let mut payload = [0u8; 80];
        payload[0] = 0x01; // version 1
        payload[1] = 0x00; // no bitmessage
        let pk = PublicKey::from_secret_key(secp, d).serialize();
        payload[2..35].copy_from_slice(&pk);
        let mut cc = [0u8; 32];
        cc[0] = cc_byte;
        payload[35..67].copy_from_slice(&cc);
        encode_payment_code(&payload)
    }

    fn three_devices() -> ([SecretKey; 3], [String; 3]) {
        let secp = Secp256k1::new();
        let secrets = [secret(0x61), secret(0x62), secret(0x63)];
        let codes = [
            device_payment_code(&secp, &secrets[0], 1),
            device_payment_code(&secp, &secrets[1], 2),
            device_payment_code(&secp, &secrets[2], 3),
        ];
        (secrets, codes)
    }

    #[test]
    fn demo_codes_match_fixture_and_build_a_vault() {
        // The simulator demo button injects exactly the fixture codes, so the
        // full vault build is proven here — a screenshot demo can't diverge.
        let codes = demo_payment_codes();
        assert_eq!(codes.len(), 3);
        for c in &codes {
            assert!(c.starts_with("PM8T"), "demo code must be a real payment code");
        }
        let (_, fixture) = three_devices();
        assert_eq!(codes, fixture.to_vec(), "demo == test fixture");
        let v = VaultConfig::build(&codes).unwrap();
        assert!(v.aggregate_code.starts_with("PM8T"));
        assert!(v.notification_address().unwrap().starts_with('1'));
        let mut shuffled = codes.clone();
        shuffled.swap(0, 2);
        assert_eq!(
            VaultConfig::build(&codes).unwrap().aggregate_code,
            VaultConfig::build(&shuffled).unwrap().aggregate_code,
            "order independence holds for demo codes"
        );
    }

    #[test]
    fn demo_fabricated_four_round_spend_verifies() {
        let secp = Secp256k1::new();
        let codes = demo_payment_codes();
        let vault = VaultConfig::build(&codes).unwrap();
        let agg_xonly = vault.agg_xonly().unwrap();
        let msg = spend_message("DEMO VAULT SPEND (simulated signers)");

        // The simulator device is NOT a vault participant — it only
        // coordinates. Its key never enters the session.
        let dummy = secret(0x99);
        let dummy_pk = PublicKey::from_secret_key(&secp, &dummy).serialize();
        let mut spend = VaultSpend::new(msg.to_vec(), 1, dummy_pk);

        // R1: fabricate all three fixture pubnonces (the other devices' QRs).
        let nonces = spend.demo_fabricate_nonces(agg_xonly).unwrap();
        assert_eq!(nonces.len(), 3);
        assert_eq!(spend.pubnonce_count(), 3);

        // R2: the real coordinator path builds the session from them.
        let aggnonce = spend.build_session(&vault).unwrap();
        assert_eq!(aggnonce.len(), 66);

        // R3: fabricate all three fixture partial signatures.
        let psigs = spend.demo_fabricate_psigs(agg_xonly).unwrap();
        assert_eq!(psigs.len(), 3);
        assert_eq!(spend.psig_count(), 3);

        // R4: finalize verifies every partial and the aggregate under the
        // vault's BIP47 child key — the exact R4 the user sees on screen.
        let final_sig = spend.finalize(&vault).unwrap();
        assert_eq!(final_sig.len(), 64);
        let child = vault
            .payment_code()
            .unwrap()
            .child_pubkey(1)
            .unwrap()
            .x_only_public_key()
            .0;
        let m = Message::from_digest_slice(&msg).unwrap();
        let s = schnorr::Signature::from_slice(&final_sig).unwrap();
        assert!(secp.verify_schnorr(&s, &m, &child).is_ok());
    }

    #[test]
    fn vault_build_is_order_independent_and_parses() {
        let (_, codes) = three_devices();
        let a = VaultConfig::build(&[codes[0].clone(), codes[1].clone(), codes[2].clone()]).unwrap();
        let b = VaultConfig::build(&[codes[2].clone(), codes[0].clone(), codes[1].clone()]).unwrap();
        assert_eq!(a.aggregate_code, b.aggregate_code, "order must not change the vault");

        assert!(a.aggregate_code.starts_with("PM8T"));
        let pc = a.payment_code().unwrap();
        assert_eq!(pc.raw, a.aggregate_code);
        let notif = a.notification_address().unwrap();
        assert!(notif.starts_with('1'), "P2PKH notification address");
        assert_eq!(a.sorted_pks().unwrap().len(), 3);
    }

    #[test]
    fn receive_address_is_deterministic_and_rotates() {
        let (_, codes) = three_devices();
        let vault = VaultConfig::build(&codes.to_vec()).unwrap();
        // Index 0 is the BIP47 notification address.
        assert_eq!(vault.receive_address(0).unwrap(), vault.notification_address().unwrap());
        // Same index is deterministic.
        assert_eq!(vault.receive_address(7).unwrap(), vault.receive_address(7).unwrap());
        // Different indexes rotate to fresh addresses.
        assert_ne!(vault.receive_address(1).unwrap(), vault.receive_address(2).unwrap());
        // All are valid mainnet P2PKH addresses.
        for i in 0..5u32 {
            assert!(vault.receive_address(i).unwrap().starts_with('1'), "index {}", i);
        }
    }

    #[test]
    fn vault_rejects_too_few_devices() {
        let (_, codes) = three_devices();
        assert!(VaultConfig::build(&[codes[0].clone()]).is_err());
        // Duplicate scan of the same device is deduplicated, so two distinct
        // devices remain after one is scanned twice.
        let dup = VaultConfig::build(&[codes[0].clone(), codes[0].clone(), codes[1].clone()])
            .unwrap();
        assert_eq!(dup.sorted_pks().unwrap().len(), 2);
    }

    #[test]
    fn qr_codec_roundtrips_all_payloads() {
        let secp = Secp256k1::new();
        let d = secret(0x07);
        let pk = PublicKey::from_secret_key(&secp, &d).serialize();

        let setup = VaultQr::Setup(
            "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97".into(),
        );
        let enc = setup.encode();
        assert_eq!(VaultQr::decode(&enc).unwrap(), setup);

        let nonce = VaultQr::Nonce { pk, pubnonce: [0x11u8; 66] };
        assert_eq!(VaultQr::decode(&nonce.encode()).unwrap(), nonce);

        let session = VaultQr::Session {
            msg: vec![0x22u8; 32],
            index: 3,
            aggnonce: [0x33u8; 66],
        };
        assert_eq!(VaultQr::decode(&session.encode()).unwrap(), session);

        let psig = VaultQr::Psig { pk, psig: [0x44u8; 32] };
        assert_eq!(VaultQr::decode(&psig.encode()).unwrap(), psig);

        // Malformed payloads are rejected, not silently accepted — including
        // short inputs that must never panic the decoder (e.g. "DOJOV1").
        assert!(VaultQr::decode("garbage").is_err());
        assert!(VaultQr::decode("DOJOV1").is_err());
        assert!(VaultQr::decode("DOJOV1|SETUP").is_err());
        assert!(VaultQr::decode("DOJOV2|SETUP|x").is_err());
        assert!(VaultQr::decode("DOJOV1|NONCE|zz|00").is_err());
    }

    #[test]
    fn full_three_device_spend_via_qr_payloads() {
        let secp = Secp256k1::new();
        let (secrets, codes) = three_devices();
        let vault = VaultConfig::build(&codes.to_vec()).unwrap();
        let agg_xonly = vault.agg_xonly().unwrap();
        let msg = spend_message("VAULT SPEND 0.5 BTC to +paynym test");

        // ---- ROUND 1: every device generates and EXPORTS a pubnonce QR ----
        let mut spends: Vec<VaultSpend> = secrets
            .iter()
            .map(|d| {
                let pk = PublicKey::from_secret_key(&secp, d).serialize();
                VaultSpend::new(msg.to_vec(), 1, pk)
            })
            .collect();
        let mut nonce_qrs = Vec::new();
        for (i, spend) in spends.iter_mut().enumerate() {
            let mut rand = [0u8; 32];
            rand[0] = 0x70 + i as u8;
            let pn = spend.gen_nonce(rand, &secrets[i], agg_xonly).unwrap();
            nonce_qrs.push(VaultQr::Nonce { pk: spend.my_pk, pubnonce: pn }.encode());
        }

        // ---- ROUND 2: coordinator scans the other 2 nonce QRs, builds the
        // session, and broadcasts the SESSION QR ----
        let mut coordinator = spends.remove(0);
        for qr in &nonce_qrs[1..] {
            match VaultQr::decode(qr).unwrap() {
                VaultQr::Nonce { pk, pubnonce } => coordinator.add_pubnonce(pk, pubnonce),
                _ => panic!("expected nonce QR"),
            }
        }
        let aggnonce = coordinator.build_session(&vault).unwrap();
        let session_qr = VaultQr::Session {
            msg: msg.to_vec(),
            index: coordinator.index,
            aggnonce,
        }
        .encode();

        // ---- ROUND 3: every signer scans the session QR and signs ----
        let mut psig_qrs = Vec::new();
        for (i, spend) in spends.iter_mut().enumerate() {
            match VaultQr::decode(&session_qr).unwrap() {
                VaultQr::Session { msg, index, aggnonce } => {
                    spend.set_session(msg, index, aggnonce, &vault).unwrap();
                }
                _ => panic!("expected session QR"),
            }
            let ps = spend.sign_partial(&secrets[i + 1]).unwrap();
            psig_qrs.push(VaultQr::Psig { pk: spend.my_pk, psig: ps }.encode());
        }
        // The coordinator signs its own partial too.
        match VaultQr::decode(&session_qr).unwrap() {
            VaultQr::Session { msg, index, aggnonce } => {
                coordinator.set_session(msg, index, aggnonce, &vault).unwrap();
            }
            _ => panic!(),
        }
        let coord_ps = coordinator.sign_partial(&secrets[0]).unwrap();
        psig_qrs.push(VaultQr::Psig { pk: coordinator.my_pk, psig: coord_ps }.encode());

        // ---- ROUND 4: coordinator collects all 3 partial sigs, finalizes ----
        for qr in &psig_qrs {
            match VaultQr::decode(qr).unwrap() {
                VaultQr::Psig { pk, psig } => coordinator.add_psig(pk, psig),
                _ => panic!("expected psig QR"),
            }
        }
        let final_sig = coordinator.finalize(&vault).unwrap();
        assert_eq!(final_sig.len(), 64, "BIP340 signature is 64 bytes");

        // Independent cross-check: the signature verifies under the CHILD key
        // of the aggregate payment code, and NOT under the plain aggregate.
        let child = vault
            .payment_code()
            .unwrap()
            .child_pubkey(1)
            .unwrap()
            .x_only_public_key()
            .0;
        let m = Message::from_digest_slice(&msg).unwrap();
        let s = schnorr::Signature::from_slice(&final_sig).unwrap();
        let xonly = &child;
        assert!(secp.verify_schnorr(&s, &m, xonly).is_ok());
        let plain = XOnlyPublicKey::from_slice(&agg_xonly).unwrap();
        assert!(secp.verify_schnorr(&s, &m, &plain).is_err());
    }

    #[test]
    fn tampered_partial_signature_fails_finalize() {
        let secp = Secp256k1::new();
        let (secrets, codes) = three_devices();
        let vault = VaultConfig::build(&codes.to_vec()).unwrap();
        let agg_xonly = vault.agg_xonly().unwrap();
        let msg = spend_message("VAULT SPEND tamper test");

        // R1: every device generates + exports a pubnonce QR.
        let mut spends: Vec<VaultSpend> = secrets
            .iter()
            .map(|d| {
                let pk = PublicKey::from_secret_key(&secp, d).serialize();
                VaultSpend::new(msg.to_vec(), 1, pk)
            })
            .collect();
        let mut nonce_qrs = Vec::new();
        for (i, spend) in spends.iter_mut().enumerate() {
            let mut rand = [0u8; 32];
            rand[0] = 0x80 + i as u8;
            let pn = spend.gen_nonce(rand, &secrets[i], agg_xonly).unwrap();
            nonce_qrs.push(VaultQr::Nonce { pk: spend.my_pk, pubnonce: pn }.encode());
        }

        // R2: coordinator imports the other two nonces, builds the session.
        let mut coordinator = spends.remove(0);
        for qr in &nonce_qrs[1..] {
            if let VaultQr::Nonce { pk, pubnonce } = VaultQr::decode(qr).unwrap() {
                coordinator.add_pubnonce(pk, pubnonce);
            }
        }
        let aggnonce = coordinator.build_session(&vault).unwrap();
        let session_qr = VaultQr::Session { msg: msg.to_vec(), index: 1, aggnonce }.encode();

        // R3: all three sign honestly.
        let mut honest_psigs = Vec::new();
        for (i, spend) in spends.iter_mut().enumerate() {
            if let VaultQr::Session { msg, index, aggnonce } =
                VaultQr::decode(&session_qr).unwrap()
            {
                spend.set_session(msg, index, aggnonce, &vault).unwrap();
            }
            let ps = spend.sign_partial(&secrets[i + 1]).unwrap();
            honest_psigs.push((spend.my_pk, ps));
        }
        if let VaultQr::Session { msg, index, aggnonce } = VaultQr::decode(&session_qr).unwrap() {
            coordinator.set_session(msg, index, aggnonce, &vault).unwrap();
        }
        let coord_ps = coordinator.sign_partial(&secrets[0]).unwrap();

        // Sanity: with all HONEST partials the final signature verifies.
        // The finalizer (a fresh device-0 view) imports all THREE pubnonces,
        // the session, and all three honest partial signatures.
        let mut finalizer = VaultSpend::new(msg.to_vec(), 1, coordinator.my_pk);
        for qr in &nonce_qrs {
            if let VaultQr::Nonce { pk, pubnonce } = VaultQr::decode(qr).unwrap() {
                finalizer.add_pubnonce(pk, pubnonce);
            }
        }
        if let VaultQr::Session { msg, index, aggnonce } = VaultQr::decode(&session_qr).unwrap() {
            finalizer.set_session(msg, index, aggnonce, &vault).unwrap();
        }
        finalizer.add_psig(coordinator.my_pk, coord_ps);
        for (pk, ps) in &honest_psigs {
            finalizer.add_psig(*pk, *ps);
        }
        assert!(finalizer.finalize(&vault).is_ok(), "honest partials must finalize");

        // Tamper: one device's partial signature is corrupted IN TRANSIT.
        let mut bad = honest_psigs[0].1;
        bad[0] ^= 0x01;
        let mut finalizer2 = VaultSpend::new(msg.to_vec(), 1, coordinator.my_pk);
        for qr in &nonce_qrs {
            if let VaultQr::Nonce { pk, pubnonce } = VaultQr::decode(qr).unwrap() {
                finalizer2.add_pubnonce(pk, pubnonce);
            }
        }
        if let VaultQr::Session { msg, index, aggnonce } = VaultQr::decode(&session_qr).unwrap() {
            finalizer2.set_session(msg, index, aggnonce, &vault).unwrap();
        }
        finalizer2.add_psig(coordinator.my_pk, coord_ps);
        finalizer2.add_psig(honest_psigs[0].0, bad);
        for (pk, ps) in &honest_psigs[1..] {
            finalizer2.add_psig(*pk, *ps);
        }
        // partial_sig_verify must reject the corrupted signature, so no final
        // signature is ever produced.
        assert!(finalizer2.finalize(&vault).is_err());
    }
}
