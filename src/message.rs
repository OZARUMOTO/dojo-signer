//! BIP47 Message Verifier — Verify messages signed by BIP47 payment codes.
//!
//! This allows the Passport Prime to act as a BIP47 message verifier,
//! similar to Ashigaru Desktop's built-in BIP47 Message Verifier.
//!
//! The flow:
//!   1. User receives a message, signature, and signer's BIP47 payment code
//!   2. User scans the data via QR or pastes via BLE
//!   3. Device derives the expected notification address from the payment code
//!   4. Device recovers the signing address from the signature
//!   5. Device compares the two — if they match, the signature is verified
//!   6. Device shows the signer's PayNym name on the secure display

use serde::{Deserialize, Serialize};
use core::fmt;

// ─── Verification Request ───────────────────────────────────

/// A request to verify a BIP47-signed message.
/// Received via QR scan or BLE from a companion app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// The message that was signed
    pub message: String,
    /// The base64-encoded signature
    pub signature_base64: String,
    /// The signer's BIP47 payment code (PM8T...)
    pub signer_payment_code: String,
}

// ─── Verification Response ──────────────────────────────────

/// The result of verifying a BIP47-signed message.
/// Displayed on the Passport Prime secure screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResponse {
    /// Whether the signature is valid
    pub is_valid: bool,
    /// The signer's PayNym name (if verification succeeded)
    pub signer_paynym: String,
    /// The signer's payment code (truncated for display)
    pub signer_code_display: String,
    /// The message that was verified (truncated for display)
    pub message_display: String,
    /// When the verification was performed
    pub verified_at: u64,
}

impl VerificationResponse {
    /// Create a failed verification response.
    pub fn failed(request: &VerificationRequest) -> Self {
        Self {
            is_valid: false,
            signer_paynym: "UNKNOWN".into(),
            signer_code_display: format!("{}...", &request.signer_payment_code[..12]),
            message_display: truncate_message(&request.message, 40),
            verified_at: current_timestamp(),
        }
    }

    /// Create a successful verification response.
    pub fn verified(request: &VerificationRequest, paynym: &str) -> Self {
        Self {
            is_valid: true,
            signer_paynym: paynym.into(),
            signer_code_display: format!("{}...", &request.signer_payment_code[..12]),
            message_display: truncate_message(&request.message, 40),
            verified_at: current_timestamp(),
        }
    }
}

fn truncate_message(msg: &str, max_len: usize) -> String {
    if msg.len() <= max_len {
        msg.into()
    } else {
        format!("{}...", &msg[..max_len])
    }
}

fn current_timestamp() -> u64 {
    // In a real KeyOS app, this comes from the system clock.
    // For development, use a placeholder.
    2026072900
}

// ─── History Entry ──────────────────────────────────────────

/// A record of a past verification, stored in device memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationHistoryEntry {
    /// When the verification was performed
    pub timestamp: u64,
    /// The signer's PayNym
    pub signer_paynym: String,
    /// Whether the verification passed
    pub is_valid: bool,
    /// Message preview
    pub message_preview: String,
}

// ─── Errors ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum VerificationError {
    InvalidMessageFormat,
    InvalidSignatureFormat,
    InvalidPaymentCode,
    DecodeFailed,
    VerificationFailed,
    DeviceLocked,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessageFormat => write!(f, "Message format is invalid"),
            Self::InvalidSignatureFormat => write!(f, "Signature must be base64 encoded"),
            Self::InvalidPaymentCode => write!(f, "Payment code is not a valid BIP47 code"),
            Self::DecodeFailed => write!(f, "Could not decode the verification data"),
            Self::VerificationFailed => write!(f, "Secure element verification failed"),
            Self::DeviceLocked => write!(f, "Device is locked — unlock to verify"),
        }
    }
}
