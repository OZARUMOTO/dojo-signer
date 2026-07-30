//! UTXO Coin Control — Review and select UTXOs on the Passport Prime secure display.
//!
//! Before signing any coinjoin transaction, the user should review each UTXO
//! on the secure screen. Doxxic UTXOs are highlighted so the user knows which
//! ones reveal their history.

use serde::{Deserialize, Serialize};
use core::fmt;

// ─── UTXO Data for Display ──────────────────────────────────

/// A complete list of UTXOs for the user to review on the secure display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoReviewList {
    /// All UTXOs belonging to this wallet
    pub utxos: Vec<UtxoDisplayItem>,
    /// Summary statistics
    pub summary: UtxoSummary,
}

/// A single UTXO shown on the secure display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoDisplayItem {
    /// Short TXID (first 16 chars) for identification
    pub txid_short: String,
    /// Value in satoshis
    pub value_sats: u64,
    /// Whether this UTXO is considered doxxic (reveals history)
    pub is_doxxic: bool,
    /// Current anonymity set size
    pub anonset: u32,
    /// Mix state
    pub mix_state_icon: &'static str,
    /// Whether the user has selected/reviewed this UTXO
    pub reviewed: bool,
}

/// Summary displayed above the UTXO list on the secure screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoSummary {
    /// Total number of UTXOs
    pub total_count: u32,
    /// Total value in satoshis
    pub total_value_sats: u64,
    /// Number of doxxic UTXOs
    pub doxxic_count: u32,
    /// Value of doxxic UTXOs in sats
    pub doxxic_value_sats: u64,
    /// Number of premix UTXOs
    pub premix_count: u32,
    /// Number of postmix UTXOs
    pub postmix_count: u32,
    /// Average anonset across all non-doxxic UTXOs
    pub avg_anonset: u32,
}

impl UtxoSummary {
    /// Create a summary from a list of UTXOs.
    pub fn from_utxos(utxos: &[UtxoDisplayItem]) -> Self {
        let total_count = utxos.len() as u32;
        let total_value_sats = utxos.iter().map(|u| u.value_sats).sum();
        let doxxic_count = utxos.iter().filter(|u| u.is_doxxic).count() as u32;
        let doxxic_value_sats = utxos.iter().filter(|u| u.is_doxxic).map(|u| u.value_sats).sum();
        let premix_count = utxos.iter().filter(|u| u.anonset > 0 && u.anonset < 50).count() as u32;
        let postmix_count = utxos.iter().filter(|u| u.anonset >= 50).count() as u32;
        let non_doxxic_anonsets: Vec<u32> = utxos.iter()
            .filter(|u| !u.is_doxxic)
            .map(|u| u.anonset)
            .collect();
        let avg_anonset = if non_doxxic_anonsets.is_empty() {
            0
        } else {
            non_doxxic_anonsets.iter().sum::<u32>() / non_doxxic_anonsets.len() as u32
        };

        Self {
            total_count,
            total_value_sats,
            doxxic_count,
            doxxic_value_sats,
            premix_count,
            postmix_count,
            avg_anonset,
        }
    }
}

// ─── UTXO Selection (for signing) ───────────────────────────

/// A selection of UTXOs that the user has reviewed and approved for a
/// coinjoin transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoSelection {
    /// TXIDs of selected UTXOs
    pub selected_txids: Vec<String>,
    /// How many UTXOs were selected
    pub count: u32,
    /// Total value of selected UTXOs in sats
    pub total_value_sats: u64,
    /// Whether the user confirmed this selection on the secure display
    pub confirmed_on_device: bool,
}

// ─── Dojo Server Connection Status ──────────────────────────

/// Status of the connection to a Dojo / Electrum server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DojoConnectionStatus {
    /// Whether connected to a Dojo server
    pub connected: bool,
    /// The server URL/address
    pub server_url: String,
    /// Whether Tor is enabled
    pub tor_enabled: bool,
    /// Block height
    pub block_height: u32,
    /// Number of peers
    pub peer_count: u32,
    /// Whether this connection is using a BIP47 verified reputation
    pub verified_reputation: bool,
}

// ─── Errors ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum UtxoError {
    NoUtxos,
    SelectionEmpty,
    ConfirmationRequired,
}

impl fmt::Display for UtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoUtxos => write!(f, "No UTXOs to review"),
            Self::SelectionEmpty => write!(f, "No UTXOs selected"),
            Self::ConfirmationRequired => write!(f, "Confirm UTXO selection on the device"),
        }
    }
}
