//! BIP47 Payment Codes — Reusable Payment Codes for the Passport Prime.
//!
//! BIP47 allows a single static payment code to receive multiple payments
//! without address reuse. Each payment derives a unique notification address
//! and a unique payment channel using ECDH.
//!
//! PayNym is a visual identity derived from the BIP47 payment code.
//! It represents a person or entity — not an address — using a unique
//! pepehash-style avatar hash.
//!
//! NOTE: The KeyOS SDK API surface is partially documented. Known working
//! APIs from the existing ozaru-signer app are used here. Speculative APIs
//! are marked with TODO comments for confirmation against the actual SDK.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

use serde::{Deserialize, Serialize};
use core::fmt;

use keyos::prelude::*;

// ─── BIP47 Payment Code ─────────────────────────────────────

/// A BIP47 Payment Code as defined in BIP-47.
/// Format: `PM8T...` (base58 encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCode {
    /// The full payment code string (PM8T...)
    pub code: String,
    /// PayNym name (e.g., "+ozarumoto")
    pub paynym: String,
    /// Pepehash-derived avatar hash for visual identification
    pub pepehash: String,
    /// BIP32 public key derived from the seed at m/47'/0'/0'
    pub public_key_hex: String,
    /// The chain code for ECDH notification derivation
    pub chain_code_hex: String,
    /// Derivation path used
    pub derivation_path: String,
}

impl PaymentCode {
    /// Generate a new BIP47 payment code from the device's master seed.
    ///
    /// The payment code is derived at `m/47'/0'/0'` per BIP-47 spec.
    /// The seed NEVER leaves the secure element.
    ///
    /// Uses the known KeyOS pattern from ozaru-signer:
    ///   SecureElement::get_public_key("key_name")
    ///   crypto::sha256()
    ///
    /// TODO: BIP47-specific key derivation (m/47'/0'/0') and chain code
    /// retrieval need the exact KeyOS SDK API, which is TBD.
    pub fn derive_from_seed() -> Result<Self, PaymentCodeError> {
        let derivation_path = "m/47'/0'/0'";

        // Get the master public key via the known working API
        let public_key_bytes = SecureElement::get_public_key("dojo_master")
            .map_err(|_| PaymentCodeError::DerivationFailed)?;

        // TODO: Chain code retrieval — requires BIP32 subkey derivation
        // at m/47'/0'/0' which needs the actual KeyOS BIP32 API:
        //   let master = BIP32::from_seed(&seed)?;
        //   let bip47_key = master.derive_path(derivation_path)?;
        let chain_code_bytes = [0u8; 32]; // placeholder

        let public_key_hex = hex::encode(&public_key_bytes);
        let chain_code_hex = hex::encode(&chain_code_bytes);

        // Build the BIP47 payment code payload (80 bytes)
        let mut payload = [0u8; 80];
        payload[0] = 0x01; // version byte
        payload[1] = 0x00; // features
        payload[2..35].copy_from_slice(&public_key_bytes[..33.min(public_key_bytes.len())]);

        if chain_code_bytes.len() >= 32 {
            payload[35..67].copy_from_slice(&chain_code_bytes[..32]);
        }

        // Double-SHA256 for checksum
        let hash = crypto::sha256(&payload);
        let hash2 = crypto::sha256(&hash);

        // Base58 encode with checksum (4 bytes)
        let mut extended = [0u8; 84];
        extended[..80].copy_from_slice(&payload);
        extended[80..84].copy_from_slice(&hash2[..4]);

        let code = bs58::encode(&extended).into_string();

        // Derive PayNym name from public key hash
        let name_hash = crypto::sha256(&public_key_bytes);
        let paynym_name = format!("+{}", hex::encode(&name_hash[..4]));
        let pepehash = hex::encode(&name_hash[..8]);

        Ok(Self {
            code,
            paynym: paynym_name,
            pepehash,
            public_key_hex,
            chain_code_hex,
            derivation_path: derivation_path.into(),
        })
    }

    /// Parse a BIP47 payment code string (PM8T...) and verify its checksum.
    pub fn parse(code_str: &str) -> Result<PaymentCodeSummary, PaymentCodeError> {
        if !code_str.starts_with("PM8T") {
            return Err(PaymentCodeError::InvalidPrefix);
        }

        let decoded = bs58::decode(code_str)
            .into_vec()
            .map_err(|_| PaymentCodeError::DecodeFailed)?;

        if decoded.len() < 84 {
            return Err(PaymentCodeError::InvalidLength);
        }

        // Verify checksum
        let payload = &decoded[..80];
        let checksum = &decoded[80..84];
        let hash = crypto::sha256(payload);
        let hash2 = crypto::sha256(&hash);

        if &hash2[..4] != checksum {
            return Err(PaymentCodeError::InvalidChecksum);
        }

        Ok(PaymentCodeSummary {
            version: payload[0],
            features: payload[1],
            public_key_hex: hex::encode(&payload[2..35]),
            chain_code_hex: hex::encode(&payload[35..67]),
        })
    }

    /// Compute the notification address for a given recipient payment code.
    ///
    /// TODO: Requires ECDH API from KeyOS SDK — TBD.
    pub fn compute_notification_address(
        _our_private_key: &[u8],
        _their_public_key: &[u8],
    ) -> Result<String, PaymentCodeError> {
        Err(PaymentCodeError::ECDHFailed)
    }
}

// ─── PayNym Identity (from actual PayNym.java source) ─────

/// A PayNym identity displayed on the Passport Prime secure screen.
/// PayNyms are visual identities based on BIP47 payment codes,
/// with social features (following/followers) and segwit support.
///
/// From the actual PayNym.java source:
///   - PaymentCode (drongo.bip47)
///   - nymId, nymName
///   - segwit flag
///   - following/followers lists
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayNymIdentity {
    /// Human-readable PayNym name (e.g., "+ozarumoto")
    pub name: String,
    /// The full BIP47 payment code
    pub payment_code: String,
    /// Pepehash avatar hash for visual identification
    pub pepehash: String,
    /// Whether this PayNym uses segwit (native segwit vs legacy P2PKH)
    pub segwit: bool,
    /// Whether this identity has been backed up
    pub backed_up: bool,
    /// Number of times this identity has been used to sign
    pub signature_count: u32,
    /// PayNyms this identity is following (social graph)
    pub following: Vec<PayNymContact>,
    /// PayNyms following this identity (social graph)
    pub followers: Vec<PayNymContact>,
}

/// A contact in the PayNym social graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayNymContact {
    pub nym_id: String,
    pub nym_name: String,
    pub payment_code: String,
    pub segwit: bool,
}

impl PayNymIdentity {
    pub fn from_device() -> Result<Self, PaymentCodeError> {
        let pc = PaymentCode::derive_from_seed()?;
        Ok(Self {
            name: pc.paynym,
            payment_code: pc.code,
            pepehash: pc.pepehash,
            segwit: true,
            backed_up: false,
            signature_count: 0,
            following: Vec::new(),
            followers: Vec::new(),
        })
    }

    /// Get the script types this PayNym supports (segwit vs legacy).
    pub fn script_types_label(&self) -> &'static str {
        if self.segwit { "Segwit (P2WPKH)" } else { "Legacy (P2PKH)" }
    }
}

// ─── BIP47 Message Verifier ─────────────────────────────────

/// Result of verifying a BIP47-signed message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub message: String,
    pub is_valid: bool,
    pub signer_paynym: Option<String>,
    pub signer_code_prefix: Option<String>,
    pub signing_address: String,
}

impl VerificationResult {
    /// Verify a BIP47 message.
    ///
    /// TODO: Requires `recover_signing_address` API from KeyOS SDK — TBD.
    pub fn verify(
        message: &str,
        _signature_base64: &str,
        signer_payment_code: &str,
    ) -> Result<Self, PaymentCodeError> {
        let pc = PaymentCode::parse(signer_payment_code)?;

        let pubkey_bytes = hex::decode(&pc.public_key_hex).unwrap_or_default();
        let name_hash = crypto::sha256(&pubkey_bytes);
        let paynym_name = format!("+{}", hex::encode(&name_hash[..4]));

        // TODO: Real verification requires ECDSA recovery API
        Ok(Self {
            message: message.into(),
            is_valid: false,
            signer_paynym: Some(paynym_name),
            signer_code_prefix: Some(format!("{}...", &signer_payment_code[..12])),
            signing_address: "pending_sdk_implementation".into(),
        })
    }
}

// ─── Parsed summary (from incoming payment code) ────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCodeSummary {
    pub version: u8,
    pub features: u8,
    pub public_key_hex: String,
    pub chain_code_hex: String,
}

// ─── Errors ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum PaymentCodeError {
    DerivationFailed,
    InvalidPrefix,
    DecodeFailed,
    InvalidLength,
    InvalidChecksum,
    ECDHFailed,
    VerificationFailed,
    InvalidSignature,
}

impl fmt::Display for PaymentCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DerivationFailed => write!(f, "BIP47 key derivation failed"),
            Self::InvalidPrefix => write!(f, "Payment code must start with PM8T"),
            Self::DecodeFailed => write!(f, "Base58 decode failed"),
            Self::InvalidLength => write!(f, "Payment code has invalid length"),
            Self::InvalidChecksum => write!(f, "Payment code checksum mismatch"),
            Self::ECDHFailed => write!(f, "ECDH key exchange failed"),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::InvalidSignature => write!(f, "Invalid signature format"),
        }
    }
}
