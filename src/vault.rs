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

use std::str::FromStr;

use ngwallet::bdk_wallet::bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    secp256k1::{schnorr, All, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness, absolute, consensus,
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
    /// The recipient address is invalid or for the wrong network.
    InvalidRecipient,
    /// The vault UTXO can't cover amount + fee (+ dust change).
    InsufficientFunds,
    /// A vault UTXO reference (txid/vout) is malformed.
    InvalidUtxo,
    /// Building the transaction failed.
    TxBuild(String),
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
            Self::InvalidRecipient => write!(f, "Invalid recipient address"),
            Self::InsufficientFunds => write!(f, "Vault UTXO can't cover amount + fee"),
            Self::InvalidUtxo => write!(f, "Invalid vault UTXO (expected txid:vout:value)"),
            Self::TxBuild(e) => write!(f, "Transaction build failed: {}", e),
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

    /// BIP341 taproot context for the vault at a BIP47 child index:
    /// (internal x-only key P, taproot tweak t, output key Q = P + t·G).
    /// Deterministic — every device derives the same keys from the vault
    /// config, so the taproot tweak needs no extra QR round trip.
    pub fn taproot_context(
        &self,
        index: u32,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), VaultError> {
        let secp = Secp256k1::new();
        let agg = key_agg_sorted(&self.sorted_pks()?)?;
        let il: [u8; 32] = self
            .payment_code()?
            .child_il(index)
            .map_err(|_| VaultError::InvalidPaymentCode)?
            .to_be_bytes();
        let il_scalar = Scalar::from_be_bytes(il).map_err(|_| VaultError::MalformedQr)?;
        let child_pk = agg
            .agg_pubkey
            .add_exp_tweak(&secp, &il_scalar)
            .map_err(|_| VaultError::Musig("child tweak".into()))?;
        let (internal, _) = child_pk.x_only_public_key();
        let internal_ser = internal.serialize();
        let t = taproot_tweak(&internal_ser);
        let t_scalar = Scalar::from_be_bytes(t).map_err(|_| VaultError::MalformedQr)?;
        let q_pk = PublicKey::from_x_only_public_key(internal, Parity::Even)
            .add_exp_tweak(&secp, &t_scalar)
            .map_err(|_| VaultError::Musig("taproot tweak".into()))?;
        let (q, _) = q_pk.x_only_public_key();
        Ok((internal_ser, t, q.serialize()))
    }

    /// A taproot (P2TR) receive address for the vault: child `index` of the
    /// aggregate payment code, tweaked to the P2TR output key. Senders pay
    /// the vault to bc1p… addresses; the 4-round ceremony spends them.
    #[allow(dead_code)] // P2TR receive API — test-exercised; wired into the receive-QR flow later
    pub fn receive_taproot_address(&self, index: u32) -> Result<String, VaultError> {
        let (_, _, q) = self.taproot_context(index)?;
        let spk = p2tr_script(&q);
        Address::from_script(&spk, Network::Bitcoin)
            .map(|a| a.to_string())
            .map_err(|_| VaultError::InvalidPaymentCode)
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

    /// THIS device's partial contribution to the BIP47 shared secret when the
    /// vault sends to a recipient payment code.
    ///
    /// BIP47 send: S = a·B where `a` is the sender's notification secret and
    /// `B` is the recipient's payment-code pubkey at the send index. The vault
    /// never reconstructs `a` (it is the sum of the devices' coeff·d shares), so
    /// each device computes its partial point B·(a_i·d_i) and the coordinator
    /// sums them (musig::combine_partials) — ECDH symmetry guarantees the sum
    /// equals a·B, and the recipient recovers the same secret with its own key.
    ///
    /// `my_pk` is this device's identity pubkey; `my_secret` its BIP47 identity
    /// secret (m/47'/0'/0'). Returns this device's 33-byte partial point.
    pub fn ecdh_share(
        &self,
        secp: &Secp256k1<All>,
        recipient_pub: &PublicKey,
        my_pk: [u8; 33],
        my_secret: &SecretKey,
    ) -> Result<[u8; 33], VaultError> {
        let agg = key_agg_sorted(&self.sorted_pks()?)?;
        let pos = agg
            .pks
            .iter()
            .position(|p| *p == my_pk)
            .ok_or_else(|| VaultError::Musig("this device is not a vault participant".into()))?;
        let coeff = &agg.coeffs[pos];
        let share = crate::musig::ecdh_partial(secp, recipient_pub, coeff, my_secret)?;
        Ok(share.serialize())
    }

    /// Sum all devices' ECDH partial points into the shared secret point and
    /// return its raw x-coordinate (Sx) — the BIP47 shared secret the payment
    /// address and the notification blinding both derive from.
    pub fn combine_ecdh_shares(&self, shares: &[[u8; 33]]) -> Result<[u8; 32], VaultError> {
        let partials: Vec<PublicKey> = shares
            .iter()
            .map(|s| PublicKey::from_slice(s).map_err(|_| VaultError::MalformedQr))
            .collect::<Result<_, _>>()?;
        let s = crate::musig::combine_partials(&partials)?;
        let (x, _) = s.x_only_public_key();
        Ok(x.serialize())
    }

    /// A bdk `tr()` descriptor watching the vault's P2TR receive address at
    /// `index` — this is what the vault wallet syncs against so real vault
    /// UTXOs (and thus the vault balance) auto-discover like the single-sig
    /// home wallet does.
    pub fn tr_descriptor(&self, index: u32) -> Result<String, VaultError> {
        let (internal, _, _) = self.taproot_context(index)?;
        Ok(format!("tr({})", hex::encode(internal)))
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
    /// DOJOV1|ECDH|<pk hex>|<share hex> — R0 contribution to a BIP47 send:
    /// this device's partial ECDH point over the recipient's pubkey. Combined
    /// across devices it recovers S = a·B without any device knowing `a`.
    Ecdh { pk: [u8; 33], share: [u8; 33] },
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
            Self::Ecdh { pk, share } => format!(
                "{}|ECDH|{}|{}",
                QR_PROTOCOL,
                hex::encode(pk),
                hex::encode(share)
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
            "ECDH" => {
                if parts.len() != 4 {
                    return Err(VaultError::MalformedQr);
                }
                let pk: [u8; 33] = de_hex(parts[2])?.try_into().map_err(|_| VaultError::MalformedQr)?;
                let share: [u8; 33] =
                    de_hex(parts[3])?.try_into().map_err(|_| VaultError::MalformedQr)?;
                Ok(Self::Ecdh { pk, share })
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
    /// Real-taproot mode: the message is a BIP341 sighash and the session
    /// adds the taproot tweak so the final signature verifies against the
    /// P2TR output key (a spendable, broadcastable transaction).
    taproot: bool,
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
            taproot: false,
        }
    }

    /// Create a spend for a REAL taproot transaction: the message is the
    /// BIP341 key-path sighash and the session is tweaked for taproot.
    pub fn new_for_tx(tx: &VaultTx, my_pk: [u8; 33]) -> Self {
        let mut s = Self::new(tx.sighash.to_vec(), tx.index, my_pk);
        s.taproot = true;
        s
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
        let mut tweaks = vec![Tweak { t: il, is_xonly: false }];
        if self.taproot {
            // BIP-327 taproot: the output key is P + int(TapTweak(P))·G,
            // applied as an x-only tweak so the aggregate signature verifies
            // against the P2TR output key the vault UTXO pays to.
            let (_, tap_t, _) = vault.taproot_context(self.index)?;
            tweaks.push(Tweak { t: tap_t, is_xonly: true });
        }
        Ok(SessionContext {
            aggnonce,
            pks: vault.sorted_pks()?,
            tweaks,
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
        // xonly(X + IL·G) — the key the BIP47 child address spends from —
        // or, in taproot mode, against the P2TR OUTPUT key Q = P + t·G.
        let secp = Secp256k1::new();
        let (internal_xonly, _, output_xonly) = vault.taproot_context(self.index)?;
        let verify_key: [u8; 32] = if self.taproot { output_xonly } else { internal_xonly };
        let m = Message::from_digest_slice(&self.msg).map_err(|_| VaultError::MalformedQr)?;
        let s = schnorr::Signature::from_slice(&sig).map_err(|_| VaultError::MalformedQr)?;
        let xonly = XOnlyPublicKey::from_slice(&verify_key).map_err(|_| VaultError::MalformedQr)?;
        if secp.verify_schnorr(&s, &m, &xonly).is_err() {
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
// REAL TAPROOT SPEND — a VaultTx is an actual P2TR transaction whose
// BIP341 key-path sighash is what the 4 QR rounds sign. R4 yields the
// 64-byte BIP340 signature; attach_signature() returns the broadcastable
// serialized transaction.
// =====================================================================

/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// The BIP-341 taproot tweak t = int(TapTweak(P)) for an internal x-only
/// key (empty merkle root — plain key-path spend).
pub fn taproot_tweak(internal_xonly: &[u8; 32]) -> [u8; 32] {
    tagged_hash(b"TapTweak", internal_xonly)
}

/// P2TR output script: OP_1 <32-byte output key>.
pub(crate) fn p2tr_script(q_ser: &[u8; 32]) -> ScriptBuf {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x51); // OP_1
    spk.push(0x20); // push 32 bytes
    spk.extend_from_slice(q_ser);
    ScriptBuf::from_bytes(spk)
}

/// A real vault spend: a 1-input P2TR transaction paying `recipient` from a
/// vault UTXO, whose BIP341 key-path sighash the 4 QR rounds sign.
#[derive(Debug, Clone)]
pub struct VaultTx {
    /// BIP47 child index whose taproot key the UTXO pays to.
    pub index: u32,
    /// Destination address (mainnet).
    pub recipient: String,
    pub amount_sats: u64,
    /// Actual fee = value - amount - change (dust folded in).
    pub fee_sats: u64,
    pub change_sats: u64,
    /// BIP341 key-path sighash (SIGHASH_DEFAULT) — the session message.
    pub sighash: [u8; 32],
    tx: Transaction,
}

impl VaultTx {
    /// Build a real spend of a vault UTXO paying to a mainnet recipient.
    /// `feerate_sats_vb` is used to estimate the fee; change below dust is
    /// folded into the fee (no dust output). The prevout must pay exactly
    /// the vault's P2TR output key at `index`.
    pub fn build(
        vault: &VaultConfig,
        index: u32,
        recipient: &str,
        amount_sats: u64,
        feerate_sats_vb: u64,
        utxo_txid: &str,
        utxo_vout: u32,
        utxo_value_sats: u64,
    ) -> Result<Self, VaultError> {
        let dest = Address::from_str(recipient)
            .map_err(|_| VaultError::InvalidRecipient)?
            .require_network(Network::Bitcoin)
            .map_err(|_| VaultError::InvalidRecipient)?;
        let dest_script = dest.script_pubkey();

        let (_, _, output_xonly) = vault.taproot_context(index)?;
        let vault_spk = p2tr_script(&output_xonly);

        // 1-in-2-out key-path taproot ≈ 154 vB (10 header + 58 input + 2×43).
        let vsize_est = 10 + 58 + 43 * 2;
        let mut fee_sats = feerate_sats_vb.saturating_mul(vsize_est);
        let total = amount_sats
            .checked_add(fee_sats)
            .ok_or(VaultError::InsufficientFunds)?;
        let mut change_sats = utxo_value_sats
            .checked_sub(total)
            .ok_or(VaultError::InsufficientFunds)?;
        if change_sats < 546 {
            // Fold dust change into the fee; no change output.
            change_sats = 0;
            fee_sats = utxo_value_sats
                .checked_sub(amount_sats)
                .ok_or(VaultError::InsufficientFunds)?;
        }

        let txid = Txid::from_str(utxo_txid).map_err(|_| VaultError::InvalidUtxo)?;
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: dest_script,
        }];
        if change_sats > 0 {
            outputs.push(TxOut {
                value: Amount::from_sat(change_sats),
                script_pubkey: vault_spk.clone(),
            });
        }
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(txid, utxo_vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: outputs,
        };

        let prevout = TxOut {
            value: Amount::from_sat(utxo_value_sats),
            script_pubkey: vault_spk,
        };
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
            .map_err(|e| VaultError::TxBuild(format!("sighash: {e}")))?
            .to_byte_array();

        Ok(Self {
            index,
            recipient: recipient.to_string(),
            amount_sats,
            fee_sats,
            change_sats,
            sighash,
            tx,
        })
    }

    /// Attach the 64-byte BIP340 key-path signature (SIGHASH_DEFAULT → no
    /// sighash byte appended) and return the broadcastable tx hex.
    pub fn attach_signature(&self, sig: [u8; 64]) -> Result<String, VaultError> {
        let mut signed = self.tx.clone();
        signed.input[0].witness = Witness::from_slice(&[sig]);
        Ok(consensus::encode::serialize_hex(&signed))
    }

    /// Finalize the signed spend into a broadcastable PSBT: the unsigned
    /// transaction with the 64-byte BIP340 key-path signature as the finalized
    /// witness. This is the exact payload quantum-link's PublishPsbt expects,
    /// so the R4 signature becomes a real network broadcast.
    pub fn to_finalized_psbt(&self, sig: [u8; 64]) -> Result<Vec<u8>, VaultError> {
        let mut psbt = ngwallet::bdk_wallet::bitcoin::psbt::Psbt::from_unsigned_tx(
            self.tx.clone(),
        )
        .map_err(|e| VaultError::TxBuild(format!("psbt: {e}")))?;
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[sig]));
        Ok(psbt.serialize())
    }
}

/// DEMO-ONLY (KEYOS_DEMO_VAULT=1): a deterministic fake vault UTXO paying
/// the vault's taproot address at index 1 (0.05 BTC at vout 0).
pub fn demo_vault_utxo() -> (String, u32, u64) {
    let txid = sha256::Hash::hash(b"DOJO DEMO VAULT UTXO").to_byte_array();
    (hex::encode(txid), 0, 5_000_000)
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

    #[test]
    fn taproot_context_is_deterministic_and_parses() {
        let (_, codes) = three_devices();
        let vault = VaultConfig::build(&codes.to_vec()).unwrap();
        let (internal, t, q) = vault.taproot_context(1).unwrap();
        assert_eq!(internal.len(), 32);
        assert_eq!(t.len(), 32);
        assert_eq!(q.len(), 32);
        // Deterministic — the same vault+index always derives the same keys.
        assert_eq!(
            vault.taproot_context(1).unwrap(),
            vault.taproot_context(1).unwrap()
        );
        // The output key must differ from the internal key (tweaked).
        assert_ne!(internal, q);
        // The tweak is exactly the BIP341 TapTweak of the internal key.
        assert_eq!(t, taproot_tweak(&internal));
        // And it round-trips through a real P2TR address.
        let addr = vault.receive_taproot_address(1).unwrap();
        assert!(addr.starts_with("bc1p"), "P2TR address: {}", addr);
        assert_ne!(vault.receive_taproot_address(1).unwrap(), vault.receive_taproot_address(2).unwrap());
    }

    #[test]
    fn real_taproot_spend_signs_and_attaches() {
        let secp = Secp256k1::new();
        let (secrets, codes) = three_devices();
        let vault = VaultConfig::build(&codes.to_vec()).unwrap();
        let agg_xonly = vault.agg_xonly().unwrap();
        let (txid, vout, value) = demo_vault_utxo();
        let tx = VaultTx::build(
            &vault,
            1,
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            100_000,
            4,
            &txid,
            vout,
            value,
        )
        .unwrap();
        assert_eq!(tx.sighash.len(), 32);
        assert!(tx.fee_sats > 0);
        assert!(tx.change_sats >= 546, "change {}", tx.change_sats);
        assert_eq!(tx.amount_sats + tx.fee_sats + tx.change_sats, value);

        // R1: every device creates a spend for the SAME real tx.
        let mut spends: Vec<VaultSpend> = secrets
            .iter()
            .map(|d| {
                let pk = PublicKey::from_secret_key(&secp, d).serialize();
                VaultSpend::new_for_tx(&tx, pk)
            })
            .collect();
        let mut nonce_qrs = Vec::new();
        for (i, spend) in spends.iter_mut().enumerate() {
            let mut rand = [0u8; 32];
            rand[0] = 0x50 + i as u8;
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
        let session_qr = VaultQr::Session {
            msg: tx.sighash.to_vec(),
            index: tx.index,
            aggnonce,
        }
        .encode();

        // R3: every signer scans the session and signs the REAL sighash.
        let mut psig_qrs = Vec::new();
        for (i, spend) in spends.iter_mut().enumerate() {
            if let VaultQr::Session { msg, index, aggnonce } = VaultQr::decode(&session_qr).unwrap()
            {
                spend.set_session(msg, index, aggnonce, &vault).unwrap();
            }
            let ps = spend.sign_partial(&secrets[i + 1]).unwrap();
            psig_qrs.push(VaultQr::Psig { pk: spend.my_pk, psig: ps }.encode());
        }
        if let VaultQr::Session { msg, index, aggnonce } = VaultQr::decode(&session_qr).unwrap() {
            coordinator.set_session(msg, index, aggnonce, &vault).unwrap();
        }
        let coord_ps = coordinator.sign_partial(&secrets[0]).unwrap();
        psig_qrs.push(VaultQr::Psig { pk: coordinator.my_pk, psig: coord_ps }.encode());

        // R4: finalize — the sig must verify under the OUTPUT key Q.
        for qr in &psig_qrs {
            if let VaultQr::Psig { pk, psig } = VaultQr::decode(qr).unwrap() {
                coordinator.add_psig(pk, psig);
            }
        }
        let final_sig = coordinator.finalize(&vault).unwrap();
        assert_eq!(final_sig.len(), 64);
        let (_, _, q_bytes) = vault.taproot_context(tx.index).unwrap();
        let q = XOnlyPublicKey::from_slice(&q_bytes).unwrap();
        let m = Message::from_digest_slice(&tx.sighash).unwrap();
        assert!(
            secp.verify_schnorr(&schnorr::Signature::from_slice(&final_sig).unwrap(), &m, &q)
                .is_ok(),
            "final sig must verify under the taproot output key"
        );
        // NOT under the plain internal key — the tweak was applied.
        let (internal_bytes, _, _) = vault.taproot_context(tx.index).unwrap();
        let internal = XOnlyPublicKey::from_slice(&internal_bytes).unwrap();
        assert!(
            secp.verify_schnorr(&schnorr::Signature::from_slice(&final_sig).unwrap(), &m, &internal)
                .is_err(),
            "must NOT verify under the untweaked internal key"
        );

        // Attach → broadcastable tx with the 64-byte key-path witness.
        let signed_hex = tx.attach_signature(final_sig).unwrap();
        let signed: Transaction = consensus::encode::deserialize_hex(&signed_hex).unwrap();
        assert_eq!(signed.input.len(), 1);
        let wit = signed.input[0].witness.to_vec();
        assert_eq!(wit.len(), 1, "one witness element");
        assert_eq!(wit[0].len(), 64, "SIGHASH_DEFAULT → bare 64-byte sig");
        assert_eq!(wit[0], final_sig.to_vec());
        assert_eq!(signed.output.len(), 2);
    }

    #[test]
    fn demo_taproot_send_produces_verified_signed_tx() {
        let secp = Secp256k1::new();
        let codes = demo_payment_codes();
        let vault = VaultConfig::build(&codes).unwrap();
        let agg_xonly = vault.agg_xonly().unwrap();
        let (txid, vout, value) = demo_vault_utxo();
        let tx = VaultTx::build(
            &vault,
            1,
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            100_000,
            4,
            &txid,
            vout,
            value,
        )
        .unwrap();

        // Simulator device coordinates; the fixture devices fabricate.
        let dummy = secret(0x99);
        let dummy_pk = PublicKey::from_secret_key(&secp, &dummy).serialize();
        let mut spend = VaultSpend::new_for_tx(&tx, dummy_pk);
        spend.demo_fabricate_nonces(agg_xonly).unwrap();
        spend.build_session(&vault).unwrap();
        spend.demo_fabricate_psigs(agg_xonly).unwrap();
        let final_sig = spend.finalize(&vault).unwrap();

        // The signature verifies under the output key over the real sighash.
        let (_, _, q_bytes) = vault.taproot_context(tx.index).unwrap();
        let q = XOnlyPublicKey::from_slice(&q_bytes).unwrap();
        let m = Message::from_digest_slice(&tx.sighash).unwrap();
        assert!(secp.verify_schnorr(&schnorr::Signature::from_slice(&final_sig).unwrap(), &m, &q).is_ok());

        let signed_hex = tx.attach_signature(final_sig).unwrap();
        let signed: Transaction = consensus::encode::deserialize_hex(&signed_hex).unwrap();
        assert_eq!(signed.input[0].witness.to_vec()[0], final_sig.to_vec());
    }

    #[test]
    fn qr_payloads_never_expose_secret_material() {
        // The QR codec must ONLY ever carry public material: public keys,
        // public nonces, public partial signatures. This runs the FULL
        // 3-device flow and asserts no encoded QR string contains the hex of
        // any device's secret key or its 97-byte secret secnonce.
        let secp = Secp256k1::new();
        let (secrets, codes) = three_devices();
        let vault = VaultConfig::build(&codes.to_vec()).unwrap();
        let agg_xonly = vault.agg_xonly().unwrap();
        let msg = spend_message("VAULT SPEND leak test");

        // R1: every device generates + exports a pubnonce QR.
        let mut spends: Vec<VaultSpend> = secrets
            .iter()
            .map(|d| {
                let pk = PublicKey::from_secret_key(&secp, d).serialize();
                VaultSpend::new(msg.to_vec(), 1, pk)
            })
            .collect();
        let mut all_qrs: Vec<String> = Vec::new();
        let mut secnonces: Vec<[u8; 97]> = Vec::new();
        for (i, spend) in spends.iter_mut().enumerate() {
            let mut rand = [0u8; 32];
            rand[0] = 0x40 + i as u8;
            let pn = spend.gen_nonce(rand, &secrets[i], agg_xonly).unwrap();
            secnonces.push(spend.secnonce.expect("secnonce set"));
            all_qrs.push(VaultQr::Nonce { pk: spend.my_pk, pubnonce: pn }.encode());
        }

        // R2: coordinator builds the session QR.
        let mut coordinator = spends.remove(0);
        for qr in &all_qrs[1..] {
            if let VaultQr::Nonce { pk, pubnonce } = VaultQr::decode(qr).unwrap() {
                coordinator.add_pubnonce(pk, pubnonce);
            }
        }
        let aggnonce = coordinator.build_session(&vault).unwrap();
        let session_qr =
            VaultQr::Session { msg: msg.to_vec(), index: 1, aggnonce }.encode();
        all_qrs.push(session_qr.clone());

        // R3: every signer exports a partial-signature QR.
        for (i, spend) in spends.iter_mut().enumerate() {
            if let VaultQr::Session { msg, index, aggnonce } = VaultQr::decode(&session_qr).unwrap() {
                spend.set_session(msg, index, aggnonce, &vault).unwrap();
            }
            let ps = spend.sign_partial(&secrets[i + 1]).unwrap();
            all_qrs.push(VaultQr::Psig { pk: spend.my_pk, psig: ps }.encode());
        }
        if let VaultQr::Session { msg, index, aggnonce } = VaultQr::decode(&session_qr).unwrap() {
            coordinator.set_session(msg, index, aggnonce, &vault).unwrap();
        }
        let coord_ps = coordinator.sign_partial(&secrets[0]).unwrap();
        all_qrs.push(VaultQr::Psig { pk: coordinator.my_pk, psig: coord_ps }.encode());

        // Assert: no device secret key hex and no secnonce hex ever appears.
        for d in secrets.iter() {
            let secret_hex = hex::encode(d.secret_bytes());
            for qr in &all_qrs {
                assert!(!qr.contains(&secret_hex), "secret key leaked into QR: {qr}");
            }
        }
        for sec in &secnonces {
            let sec_hex = hex::encode(sec);
            for qr in &all_qrs {
                assert!(!qr.contains(&sec_hex), "secnonce leaked into QR: {qr}");
            }
        }
    }

    #[test]
    fn finalized_psbt_never_exposes_secret_material() {
        // The PSBT that gets broadcast must contain only the public tx and
        // the public 64-byte signature — never a device secret key or the
        // 97-byte secret secnonce.
        let secp = Secp256k1::new();
        let (secrets, codes) = three_devices();
        let vault = VaultConfig::build(&codes.to_vec()).unwrap();
        let agg_xonly = vault.agg_xonly().unwrap();
        let (txid, vout, value) = demo_vault_utxo();
        let tx = VaultTx::build(
            &vault,
            1,
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            100_000,
            4,
            &txid,
            vout,
            value,
        )
        .unwrap();

        // R1: real nonces for the real tx.
        let mut spends: Vec<VaultSpend> = secrets
            .iter()
            .map(|d| {
                let pk = PublicKey::from_secret_key(&secp, d).serialize();
                VaultSpend::new_for_tx(&tx, pk)
            })
            .collect();
        let mut nonce_qrs = Vec::new();
        let mut secnonces: Vec<[u8; 97]> = Vec::new();
        for (i, spend) in spends.iter_mut().enumerate() {
            let mut rand = [0u8; 32];
            rand[0] = 0x50 + i as u8;
            let pn = spend.gen_nonce(rand, &secrets[i], agg_xonly).unwrap();
            secnonces.push(spend.secnonce.expect("secnonce set"));
            nonce_qrs.push(VaultQr::Nonce { pk: spend.my_pk, pubnonce: pn }.encode());
        }

        // R2: coordinator session.
        let mut coordinator = spends.remove(0);
        for qr in &nonce_qrs[1..] {
            if let VaultQr::Nonce { pk, pubnonce } = VaultQr::decode(qr).unwrap() {
                coordinator.add_pubnonce(pk, pubnonce);
            }
        }
        let aggnonce = coordinator.build_session(&vault).unwrap();
        let session_qr =
            VaultQr::Session { msg: tx.sighash.to_vec(), index: 1, aggnonce }.encode();

        // R3: every signer signs.
        let mut psig_qrs = Vec::new();
        for (i, spend) in spends.iter_mut().enumerate() {
            if let VaultQr::Session { msg, index, aggnonce } = VaultQr::decode(&session_qr).unwrap() {
                spend.set_session(msg, index, aggnonce, &vault).unwrap();
            }
            let ps = spend.sign_partial(&secrets[i + 1]).unwrap();
            psig_qrs.push(VaultQr::Psig { pk: spend.my_pk, psig: ps }.encode());
        }
        if let VaultQr::Session { msg, index, aggnonce } = VaultQr::decode(&session_qr).unwrap() {
            coordinator.set_session(msg, index, aggnonce, &vault).unwrap();
        }
        let coord_ps = coordinator.sign_partial(&secrets[0]).unwrap();
        psig_qrs.push(VaultQr::Psig { pk: coordinator.my_pk, psig: coord_ps }.encode());

        // R4: finalize + serialize the broadcastable PSBT.
        for qr in &psig_qrs {
            if let VaultQr::Psig { pk, psig } = VaultQr::decode(qr).unwrap() {
                coordinator.add_psig(pk, psig);
            }
        }
        let final_sig = coordinator.finalize(&vault).unwrap();
        let psbt = tx.to_finalized_psbt(final_sig).unwrap();
        let psbt_hex = hex::encode(&psbt);

        for d in secrets.iter() {
            let secret_hex = hex::encode(d.secret_bytes());
            assert!(!psbt_hex.contains(&secret_hex), "device secret leaked into PSBT hex");
        }
        for sec in &secnonces {
            let sec_hex = hex::encode(sec);
            assert!(!psbt_hex.contains(&sec_hex), "secnonce leaked into PSBT hex");
        }
    }
}
