// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// UTXO Coin Control — Review and select UTXOs on Passport Prime secure display.
// Before signing any coinjoin, user reviews each UTXO on the secure screen.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use core::fmt;

/// Complete list of UTXOs for review on the secure display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoReviewList {
    pub utxos: Vec<UtxoDisplayItem>,
    pub summary: UtxoSummary,
}

/// Single UTXO shown on the secure display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoDisplayItem {
    pub txid_short: String,
    pub value_sats: u64,
    pub is_doxxic: bool,
    pub anonset: u32,
    pub mix_state_icon: String,
    pub reviewed: bool,
}

/// Summary displayed above the UTXO list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoSummary {
    pub total_count: u32,
    pub total_value_sats: u64,
    pub doxxic_count: u32,
    pub doxxic_value_sats: u64,
    pub premix_count: u32,
    pub postmix_count: u32,
    pub avg_anonset: u32,
}

impl UtxoSummary {
    pub fn from_utxos(utxos: &[UtxoDisplayItem]) -> Self {
        let total_count = utxos.len() as u32;
        let total_value_sats = utxos.iter().map(|u| u.value_sats).sum();
        let doxxic_count = utxos.iter().filter(|u| u.is_doxxic).count() as u32;
        let doxxic_value_sats = utxos.iter().filter(|u| u.is_doxxic).map(|u| u.value_sats).sum();
        let premix_count = utxos.iter().filter(|u| u.anonset > 0 && u.anonset < 50).count() as u32;
        let postmix_count = utxos.iter().filter(|u| u.anonset >= 50).count() as u32;
        let non_doxxic: Vec<u32> = utxos.iter().filter(|u| !u.is_doxxic).map(|u| u.anonset).collect();
        let avg_anonset = if non_doxxic.is_empty() { 0 }
            else { non_doxxic.iter().sum::<u32>() / non_doxxic.len() as u32 };
        Self { total_count, total_value_sats, doxxic_count, doxxic_value_sats, premix_count, postmix_count, avg_anonset }
    }
}

/// Dojo server connection status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DojoConnectionStatus {
    pub connected: bool,
    pub server_url: String,
    pub tor_enabled: bool,
    pub block_height: u32,
    pub peer_count: u32,
    pub verified_reputation: bool,
}

#[derive(Debug, Clone)]
pub enum UtxoError {
    NoUtxos,
    SelectionEmpty,
}

impl fmt::Display for UtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoUtxos => write!(f, "No UTXOs to review"),
            Self::SelectionEmpty => write!(f, "No UTXOs selected"),
        }
    }
}
