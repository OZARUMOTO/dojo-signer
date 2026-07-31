// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// BIP47 Message Verifier — Verify messages signed by BIP47 payment codes.
// Same feature as Ashigaru Desktop's built-in BIP47 Message Verifier.
// Now running on Passport Prime hardware.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use core::fmt;

/// A request to verify a BIP47-signed message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub message: String,
    pub signature_base64: String,
    pub signer_payment_code: String,
}

/// The result of verifying a BIP47-signed message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResponse {
    pub is_valid: bool,
    pub signer_paynym: String,
    pub signer_code_display: String,
    pub message_display: String,
    pub verified_at: u64,
}

impl VerificationResponse {
    pub fn failed(request: &VerificationRequest, paynym: &str, verified_at: u64) -> Self {
        Self {
            is_valid: false,
            signer_paynym: paynym.into(),
            signer_code_display: truncate_str(&request.signer_payment_code, 12),
            message_display: truncate_message(&request.message, 40),
            verified_at,
        }
    }

    pub fn verified(request: &VerificationRequest, paynym: &str, verified_at: u64) -> Self {
        Self {
            is_valid: true,
            signer_paynym: paynym.into(),
            signer_code_display: truncate_str(&request.signer_payment_code, 12),
            message_display: truncate_message(&request.message, 40),
            verified_at,
        }
    }
}

/// A record of a past verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationHistoryEntry {
    pub timestamp: u64,
    pub signer_paynym: String,
    pub is_valid: bool,
    pub message_preview: String,
}

fn truncate_message(msg: &str, max_len: usize) -> String {
    // char-safe: never slice mid-character (multi-byte UTF-8)
    let chars: Vec<char> = msg.chars().collect();
    if chars.len() <= max_len { msg.into() }
    else {
        let cut: String = chars[..max_len].iter().collect();
        format!("{}...", cut)
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max + 3 { s.into() }
    else {
        let cut: String = chars[..max].iter().collect();
        format!("{}...", cut)
    }
}

#[derive(Debug, Clone)]
pub enum VerificationError {
    InvalidMessageFormat,
    InvalidSignatureFormat,
    InvalidPaymentCode,
    DecodeFailed,
    VerificationFailed,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessageFormat => write!(f, "Message format is invalid"),
            Self::InvalidSignatureFormat => write!(f, "Signature must be base64 encoded"),
            Self::InvalidPaymentCode => write!(f, "Payment code is not a valid BIP47 code"),
            Self::DecodeFailed => write!(f, "Could not decode verification data"),
            Self::VerificationFailed => write!(f, "Secure element verification failed"),
        }
    }
}
