// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Whirlpool Coinjoin Protocol v0.23 — Types matching the actual Ashigaru Whirlpool protocol.
// Based on the actual Ashigaru source code from:
//   http://ashicodepbnpvslzsl2bz7l2pwrjvajgumgac423pp3y2deprbnzz7id.onion/Ashigaru

// Protocol types are wired into the real signing flow; the allow mirrors
// message.rs / utxo.rs for wire fields not yet consumed end-to-end.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Current Whirlpool protocol version
pub const PROTOCOL_VERSION: &str = "0.23";
/// Partner ID matching Ashigaru's "ashigaruterminal" pattern
pub const PARTNER_ID: &str = "dojosigner";

/// The 6 mix statuses from the actual Ashigaru Whirlpool protocol.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MixStatus {
    ConfirmInput,
    RegisterOutput,
    RevealOutput,
    Signing,
    Success,
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
}

/// Signing request from Whirlpool coordinator (from SigningRequest.java)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    pub mix_id: String,
    pub witnesses_64: Vec<String>,
    pub transaction_64: String,
}

/// Response after hardware signing (witnesses returned with device signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResponse {
    pub mix_id: String,
    pub witnesses_64: Vec<String>,
    pub signed_at: u64,
}

/// UTXO entry matching the actual protocol's Utxo beans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub tx_hash: String,
    pub tx_index: u64,
    pub value: u64,
    pub address: String,
    pub mix_status: Option<MixStatus>,
}

/// The four Whirlpool wallet accounts (from Whirlpool.java)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum WhirlpoolAccount {
    Deposit,
    Whirlpool,
    Postmix,
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

/// Register input request (from RegisterInputRequest.java)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInputRequest {
    pub pool_id: String,
    pub utxo_hash: String,
    pub utxo_index: u64,
    pub signature: String,
    pub liquidity: bool,
    pub block_height: u64,
}

/// Confirm input request (from ConfirmInputRequest.java)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmInputRequest {
    pub mix_id: String,
    pub blinded_bordereau_64: String,
    pub user_hash: String,
}

/// Reveal output request (from RevealOutputRequest.java)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealOutputRequest {
    pub mix_id: String,
    pub receive_address: String,
}

/// RFC-4648 base64 encoding for the Whirlpool protocol's *_64 wire fields.
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 63) as usize] as char } else { '=' });
    }
    out
}
