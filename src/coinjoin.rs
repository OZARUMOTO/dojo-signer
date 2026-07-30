//! Whirlpool Coinjoin Protocol v0.23 — Types matching the actual Ashigaru Whirlpool protocol.
//!
//! Based on the actual Ashigaru source code from the Tor Gitea repository:
//!   https://github.com/linkinparkrulz/ashigaru-desktop (public README)
//!   http://ashicode...onion/Ashigaru (full source, accessed via Tor)
//!
//! Actual protocol flow (from the actual Java source):
//!
//!   1. REGISTER_INPUT  →  Join a pool with a UTXO (+ signature proving ownership)
//!   2. CONFIRM_INPUT   →  Confirm participation with blinded bordereau
//!   3. REGISTER_OUTPUT →  Register the receive address
//!   4. REVEAL_OUTPUT   →  Reveal output to peers
//!   5. SIGNING         →  Hardware signing step! User reviews + signs on Passport Prime
//!   6. SUCCESS / FAIL  →  Mix completes or fails
//!
//! The SIGNING step is where DOJO SIGNER comes in:
//!   - Receives: SigningRequest { mixId, witnesses64 (Z85), transaction64 (Z85) }
//!   - User reviews on secure display
//!   - Approves → adds hardware signature to witnesses → returns SigningResponse
//!   - Signed witnesses sent back via BLE → Dojo completes the mix
//!
//! Protocol encoding:
//!   - Binary data is Z85-encoded (witnesses64, transaction64, blindedBordereau64)
//!   - Inputs hash uses SHA512 (not SHA256)
//!   - STOMP WebSocket for coordinator communication
//!   - Protocol version: 0.23
//!   - Partner ID: "dojosigner" (matching Ashigaru's "ashigaruterminal" pattern)
//!
//! Whirlpool accounts (from the actual Whirlpool.java source):
//!   - DEPOSIT    — Premix UTXOs being mixed
//!   - WHIRLPOOL  — Active mixing pool
//!   - POSTMIX    — Clean UTXOs (reached target anonset)
//!   - BADBANK    — Doxxic UTXOs that failed mixing
//!
//! This is the FIRST hardware wallet support for Samurai Wallet / Ashigaru Terminal.

use serde::{Deserialize, Serialize};
use core::fmt;

// ─── Protocol Constants ─────────────────────────────────────

/// Current Whirlpool protocol version (matching Ashigaru's 0.23)
pub const PROTOCOL_VERSION: &str = "0.23";

/// Partner ID identifying this client to the Whirlpool coordinator.
/// Matches Ashigaru Terminal's pattern: "ashigaruterminal"
pub const PARTNER_ID: &str = "dojosigner";

/// Default mix-to minimum mixes before external transfer
pub const DEFAULT_MIXTO_MIN_MIXES: u32 = 3;

/// Default mix-to random factor
pub const DEFAULT_MIXTO_RANDOM_FACTOR: u32 = 4;

// ─── Mix Statuses (from MixStatus.java) ─────────────────────

/// The 6 mix statuses from the actual Ashigaru Whirlpool protocol.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MixStatus {
    /// Waiting for peers to confirm their inputs
    ConfirmInput,
    /// Registering the output address
    RegisterOutput,
    /// Revealing the output to peers
    RevealOutput,
    /// Signing the transaction (hardware signing step!)
    Signing,
    /// Mix completed successfully
    Success,
    /// Mix failed
    Fail,
}

impl MixStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ConfirmInput => "CONFIRM_INPUT",
            Self::RegisterOutput => "REGISTER_OUTPUT",
            Self::RevealOutput => "REVEAL_OUTPUT",
            Self::Signing => "SIGNING",
            Self::Success => "SUCCESS",
            Self::Fail => "FAIL",
        }
    }

    pub fn from_protocol(s: &str) -> Option<Self> {
        match s {
            "CONFIRM_INPUT" => Some(Self::ConfirmInput),
            "REGISTER_OUTPUT" => Some(Self::RegisterOutput),
            "REVEAL_OUTPUT" => Some(Self::RevealOutput),
            "SIGNING" => Some(Self::Signing),
            "SUCCESS" => Some(Self::Success),
            "FAIL" => Some(Self::Fail),
            _ => None,
        }
    }
}

// ─── Register Input (from RegisterInputRequest.java) ───────

/// Register an input for a Whirlpool mix.
/// Sent to the coordinator to join a pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInputRequest {
    pub pool_id: String,
    pub utxo_hash: String,
    pub utxo_index: u64,
    pub signature: String,
    pub liquidity: bool,
    pub block_height: u64,
}

// ─── Confirm Input (from ConfirmInputRequest.java) ─────────

/// Confirm input participation after peers are ready.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmInputRequest {
    pub mix_id: String,
    pub blinded_bordereau_64: String,  // Z85 encoded
    pub user_hash: String,
}

// ─── Reveal Output (from RevealOutputRequest.java) ─────────

/// Reveal the receive address to peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealOutputRequest {
    pub mix_id: String,
    pub receive_address: String,
}

// ─── Signing Request (from SigningRequest.java) ────────────

/// The signing request sent to the hardware wallet for approval.
///
/// From the actual Ashigaru source:
/// ```java
/// public class SigningRequest {
///     public String mixId;
///     public String[] witnesses64;  // Z85 encoded witnesses
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    /// Unique mix identifier (UUID)
    pub mix_id: String,
    /// Z85-encoded witnesses (partial signatures from peers).
    pub witnesses_64: Vec<String>,
    /// The unsigned transaction in Z85 encoding
    pub transaction_64: String,
}

// ─── Mix Status Notifications ──────────────────────────────

/// Base notification for mix status changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixStatusNotification {
    pub mix_status: MixStatus,
    pub mix_id: String,
}

/// Signing notification — contains the unsigned transaction to sign.
/// From SigningMixStatusNotification.java.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningMixStatus {
    pub mix_status: MixStatus,
    pub mix_id: String,
    pub transaction_64: String,
}

/// Register output notification — contains inputs hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterOutputMixStatus {
    pub mix_status: MixStatus,
    pub mix_id: String,
    pub inputs_hash: String,
}

// ─── Mix Params ─────────────────────────────────────────────

/// Parameters for a mixing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixParams {
    pub pool_id: String,
    pub denomination: u64,
    pub fee_value: u64,
    pub fee_address: String,
    pub utxo_hash: String,
    pub utxo_index: u64,
    pub utxo_value: u64,
    pub liquidity: bool,
}

// ─── Mix Destination ────────────────────────────────────────

/// Where mixed funds go (postmix or mix-to).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixDestination {
    pub address: String,
    pub destination_type: DestinationType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DestinationType {
    /// BIP84 postmix (native segwit)
    Bip84,
    /// XPub postmix (external wallet / mix-to)
    XPub,
}

// ─── UTXO Entry ─────────────────────────────────────────────

/// A UTXO entry matching the actual protocol's Utxo beans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub tx_hash: String,
    pub tx_index: u64,
    pub value: u64,
    pub address: String,
    pub mix_status: Option<MixStatus>,
}

// ─── Signing Response ───────────────────────────────────────

/// Response from the hardware wallet after signing.
/// The witnesses are returned with the hardware wallet's signature added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResponse {
    pub mix_id: String,
    pub witnesses_64: Vec<String>,
    pub signed_at: u64,
}

// ─── Whirlpool Accounts (from Whirlpool.java) ─────────────

/// The four Whirlpool wallet accounts, matching the actual Ashigaru source.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum WhirlpoolAccount {
    /// DEPOSIT — Premix UTXOs being mixed
    Deposit,
    /// WHIRLPOOL — Active mixing pool
    Whirlpool,
    /// POSTMIX — Clean UTXOs (reached target anonset)
    Postmix,
    /// BADBANK — Doxxic UTXOs that failed mixing
    Badbank,
}

impl WhirlpoolAccount {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Deposit => "DEPOSIT",
            Self::Whirlpool => "WHIRLPOOL",
            Self::Postmix => "POSTMIX",
            Self::Badbank => "BADBANK",
        }
    }
}

// ─── Tx0 Preview (from Whirlpool.java Tx0Previews) ─────────

/// Preview of Tx0 costs before broadcasting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tx0Preview {
    pub pool_id: String,
    pub denomination: u64,
    pub must_mix_value: u64,
    pub fee_value: u64,
    pub fee_discount_percent: u32,
    pub samourai_fee: u64,
    pub miner_fee: u64,
    pub overshoot: u64,
    pub change_value: u64,
}

/// Result of broadcasting a Tx0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tx0Result {
    pub pool_id: String,
    pub txid: String,
    pub utxos_out: Vec<UtxoEntry>,
    pub samourai_fee: u64,
    pub miner_fee: u64,
}

// ─── Mix Progress (from Whirlpool.java MixProgress) ────────

/// Current progress of a mixing UTXO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixProgress {
    pub mix_id: String,
    pub nb_rounds: u32,
    pub progress: f32,
    pub mix_status: MixStatus,
    pub message: String,
}

// ─── UTXO Mix Data ──────────────────────────────────────────

/// Data about a UTXO's mixing state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoMixData {
    pub mixes_done: u32,
    pub account: Option<WhirlpoolAccount>,
}

// ─── Error ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CoinjoinError {
    InvalidProtocolVersion,
    InvalidMixId,
    Z85DecodeFailed,
    InputRegistrationFailed,
    WitnessMismatch,
    SigningFailed,
    MixNotInProgress,
}

impl fmt::Display for CoinjoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProtocolVersion => write!(f, "Unsupported Whirlpool protocol version"),
            Self::InvalidMixId => write!(f, "Invalid mix ID format"),
            Self::Z85DecodeFailed => write!(f, "Z85 decoding failed for witness/transaction data"),
            Self::InputRegistrationFailed => write!(f, "Failed to register input with coordinator"),
            Self::WitnessMismatch => write!(f, "Witness count mismatch in signing request"),
            Self::SigningFailed => write!(f, "Hardware signing operation failed"),
            Self::MixNotInProgress => write!(f, "Mix is not in progress or has completed"),
        }
    }
}
