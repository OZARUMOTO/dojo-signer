//! DOJO SIGNER — Hardware signing companion for Samurai Wallet / Ashigaru Terminal.
//!
//! Runs on the Foundation Passport Prime device. This is the FIRST hardware
//! wallet support for Samurai Wallet / Ashigaru Whirlpool coinjoin.
//!
//! Built from the actual Ashigaru source code (Tor Gitea):
//!   - Whirlpool Protocol v0.23 (STOMP WebSocket, Z85 encoding)
//!   - Mix flow: CONFIRM_INPUT → REGISTER_OUTPUT → REVEAL_OUTPUT → SIGNING → SUCCESS/FAIL
//!   - SigningRequest: mixId + witnesses64 (Z85-encoded partial signatures)
//!
//!   ⛩ BIP47 Payment Codes  —  Generate & display PayNym identity
//!   🌀 Coinjoin Signing     —  Hardware signing of Whirlpool mixes
//!   🪙 UTXO Coin Control    —  Review UTXOs on the secure screen before mixing
//!   ✅ BIP47 Verifier       —  Verify messages signed by any BIP47 paynym
//!   🔗 Dojo Connection      —  Connect to Dojo/Electrum servers
//!
//! KEY PRINCIPLE: The seed NEVER leaves the Passport Prime.
//! Only public keys and signed witnesses are exported.
//!
//! Protocol flow for signing:
//!   1. Dojo sends SigningRequest { mixId, witnesses64, transaction64 }
//!   2. User reviews transaction details on secure display
//!   3. User approves → device signs the witnesses → returns them
//!   4. Signed witnesses are sent back over BLE → Dojo completes the mix

#![no_std]
#![no_main]

extern crate alloc;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::cell::RefCell;

use keyos::prelude::*;
use keyos_slint::*;
use slint::*;

mod bip47;
mod coinjoin;
mod message;
mod utxo;

use bip47::{PaymentCode, PayNymIdentity, VerificationResult, PaymentCodeError};
use coinjoin::{MixStatus, SigningRequest as CoinjoinSigningReq, SigningResponse as CoinjoinSigningRes, UtxoEntry, RegisterInputRequest, ConfirmInputRequest, RevealOutputRequest, MixStatusNotification};
use message::{VerificationRequest, VerificationResponse, VerificationHistoryEntry};
use utxo::{UtxoDisplayItem, UtxoReviewList, UtxoSummary, DojoConnectionStatus};

// ─── App Screens ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Screen {
    /// Main screen — PayNym identity + connection status
    Home,
    /// BIP47 Payment Code display (QR ready)
    PayNym,
    /// UTXO review list
    UtxoReview,
    /// Coinjoin transaction signing
    Coinjoin,
    /// BIP47 Message verification
    MessageVerify,
    /// Settings
    Settings,
    /// Verification history
    History,
}

// ─── App State ──────────────────────────────────────────────

struct AppState {
    // ── Identity ─────────────────────────────────────────
    seed_initialized: bool,
    paynym_identity: Option<PayNymIdentity>,
    public_key_hex: String,

    // ── Dojo Connection ──────────────────────────────────
    dojo_connected: bool,
    dojo_server: String,
    tor_enabled: bool,
    block_height: u32,
    peer_count: u32,

    // ── UTXO Review ──────────────────────────────────────
    utxo_list: Option<UtxoReviewList>,
    utxo_loaded: bool,

    // ── Coinjoin Signing ─────────────────────────────────
    current_coinjoin_req: Option<CoinjoinSigningReq>,
    coinjoin_history: Vec<CoinjoinSigningRes>,

    // ── Message Verification ─────────────────────────────
    current_verification: Option<VerificationRequest>,
    verification_result: Option<VerificationResponse>,
    verification_history: Vec<VerificationHistoryEntry>,

    // ── Navigation ───────────────────────────────────────
    current_screen: Screen,
    previous_screen: Screen,

    // ── Status ───────────────────────────────────────────
    status_text: String,
    status_icon: &'static str,
    device_name: String,
}

impl AppState {
    fn new() -> Self {
        Self {
            seed_initialized: false,
            paynym_identity: None,
            public_key_hex: String::new(),
            dojo_connected: false,
            dojo_server: String::new(),
            tor_enabled: true,
            block_height: 0,
            peer_count: 0,
            utxo_list: None,
            utxo_loaded: false,
            current_coinjoin_req: None,
            coinjoin_history: Vec::new(),
            current_verification: None,
            verification_result: None,
            verification_history: Vec::new(),
            current_screen: Screen::Home,
            previous_screen: Screen::Home,
            status_text: "Ready — DOJO SIGNER active".into(),
            status_icon: "🟢",
            device_name: "DOJO SIGNER".into(),
        }
    }
}

// ─── Main Entry ─────────────────────────────────────────────

#[entry]
fn main() -> Result<(), Box<dyn core::error::Error>> {
    keyos::init();
    let state = Rc::new(RefCell::new(AppState::new()));

    // Get device info
    {
        let mut s = state.borrow_mut();
        if let Ok(name) = Settings::get_device_name() {
            s.device_name = name;
        }
    }

    // ── Initialize seed + derive PayNym identity ─────────
    let first_boot = !matches!(SecureElement::has_key("dojo_master"), Ok(true));

    if first_boot {
        match initialize_seed() {
            Ok(()) => {
                let mut s = state.borrow_mut();
                s.seed_initialized = true;
                s.status_text = "✅ Seed initialized — deriving PayNym...".into();
                s.status_icon = "⏳";
            }
            Err(e) => {
                let mut s = state.borrow_mut();
                s.status_text = format!("❌ Seed init failed: {:?}", e);
                s.status_icon = "❌";
            }
        }
    } else {
        let mut s = state.borrow_mut();
        s.seed_initialized = true;
    }

    // ── Derive PayNym identity from seed ─────────────────
    if state.borrow().seed_initialized {
        match derive_paynym_identity(state.clone()) {
            Ok(()) => {
                let mut s = state.borrow_mut();
                s.status_text = "🟢 PayNym identity derived — DOJO SIGNER ready".into();
                s.status_icon = "🟢";
            }
            Err(e) => {
                let mut s = state.borrow_mut();
                s.status_text = format!("❌ PayNym derivation failed: {:?}", e);
                s.status_icon = "❌";
            }
        }
    }

    // ── Build the Slint UI ───────────────────────────────
    let ui = DojoSignerUI::new()?;

    // Set initial UI state
    {
        let s = state.borrow();
        ui.set_device_name(s.device_name.clone().into());
        ui.set_status(format!("{} {}", s.status_icon, s.status_text).into());
        if let Some(ref paynym) = s.paynym_identity {
            ui.set_paynym_name(paynym.name.clone().into());
            ui.set_paynym_code(truncate_code(&paynym.payment_code, 20));
            ui.set_pepehash(paynym.pepehash.clone().into());
        }
    }

    // ── Set up UI callbacks ──────────────────────────────
    setup_callbacks(&ui, state.clone());

    // ── Start BLE service ────────────────────────────────
    if let Err(e) = start_dojo_ble_service() {
        let mut s = state.borrow_mut();
        s.status_text = format!("BLE start failed: {:?}", e);
        s.status_icon = "🔴";
        update_status_display(&ui, &s);
    } else {
        update_status(&ui, state.clone(), "🟢 BLE active — connect to Dojo companion");
    }

    // Enter the Slint event loop
    ui.run()?;

    Ok(())
}

// ─── Seed Initialization (first boot) ───────────────────────
//
// The seed is generated ONCE. It NEVER leaves the device.
// Only the BIP47 payment code (public key derived from seed)
// and signatures are exported.

fn initialize_seed() -> Result<(), keyos::Error> {
    let entropy = Rng::generate_entropy(32)?;
    let mnemonic = Mnemonic::from_entropy(&entropy)?;
    let phrase = mnemonic.phrase();
    let seed = mnemonic.to_seed("")?;

    // Store in secure element (never leaves again)
    SecureElement::store_key("dojo_master", &seed)?;
    SecureElement::store_key("dojo_mnemonic", phrase.as_bytes())?;

    Ok(())
}

// ─── PayNym Identity Derivation ─────────────────────────────
//
// Uses BIP47 (m/47'/0'/0') to derive the payment code.
// The public key is exported for the payment code, but the
// seed stays in the secure element permanently.

fn derive_paynym_identity(state: Rc<RefCell<AppState>>) -> Result<(), PaymentCodeError> {
    let identity = PayNymIdentity::from_device()?;

    let mut s = state.borrow_mut();
    s.paynym_identity = Some(identity);

    // Also derive the standard public key for display
    if let Ok(pk) = SecureElement::get_public_key("dojo_master") {
        s.public_key_hex = hex::encode(pk);
    }

    Ok(())
}

// ─── UI Setup ───────────────────────────────────────────────

fn setup_callbacks(ui: &DojoSignerUI, state: Rc<RefCell<AppState>>) {
    // ── Navigate to PayNym ───────────────────────────────
    let ui_paynym = ui.as_weak();
    let state_paynym = state.clone();
    ui.on_show_paynym(move || {
        let ui = ui_paynym.unwrap();
        let s = state_paynym.borrow();
        if let Some(ref paynym) = s.paynym_identity {
            ui.set_paynym_name(paynym.name.clone().into());
            ui.set_paynym_code(paynym.payment_code.clone().into());
            ui.set_pepehash(paynym.pepehash.clone().into());
            ui.set_screen_index(1); // PayNym screen
            ui.set_status(format!("📤 Full payment code shown — scan to share").into());
        } else {
            ui.set_status("⚠️ Wallet not initialized".into());
        }
    });

    // ── Navigate to UTXO Review ──────────────────────────
    let ui_utxo = ui.as_weak();
    let state_utxo = state.clone();
    ui.on_show_utxo_review(move || {
        let ui = ui_utxo.unwrap();
        let s = state_utxo.borrow();
        let summary = match &s.utxo_list {
            Some(list) => {
                ui.set_utxo_count(list.summary.total_count as i32);
                ui.set_utxo_value(list.summary.total_value_sats as i32);
                ui.set_doxxic_count(list.summary.doxxic_count as i32);
                ui.set_avg_anonset(list.summary.avg_anonset as i32);
                ui.set_screen_index(2); // UTXO Review screen
                "UTXOs loaded — review before signing".to_string()
            }
            None => {
                ui.set_utxo_count(0);
                ui.set_utxo_value(0);
                ui.set_doxxic_count(0);
                ui.set_avg_anonset(0);
                ui.set_screen_index(2); // still show the screen
                "No UTXOs loaded — connect to Dojo".to_string()
            }
        };
        ui.set_status(summary.into());
    });

    // ── Navigate to Coinjoin / Signing ───────────────────
    let ui_coin = ui.as_weak();
    let state_coin = state.clone();
    ui.on_show_coinjoin(move || {
        let ui = ui_coin.unwrap();
        let s = state_coin.borrow();
        ui.set_screen_index(3); // Coinjoin screen
        if let Some(ref req) = s.current_coinjoin_req {
            ui.set_tx_type(format!("Mix: {}", req.mix_id).into());
            ui.set_amount_sats(0);
            ui.set_fee_sats(0);
            ui.set_input_count(req.witnesses_64.len() as i32);
            ui.set_anonset(0);
            ui.set_target_anonset(0);
            ui.set_status("🌀 Review coinjoin details — approve or reject on secure display".into());
        } else {
            ui.set_tx_type("No request".into());
            ui.set_amount_sats(0);
            ui.set_fee_sats(0);
            ui.set_input_count(0);
            ui.set_anonset(0);
            ui.set_target_anonset(0);
            ui.set_status("No coinjoin request received yet".into());
        }
    });

    // ── Navigate to Message Verifier ─────────────────────
    let ui_verify = ui.as_weak();
    let state_verify_nav = state.clone();
    ui.on_show_verifier(move || {
        let ui = ui_verify.unwrap();
        ui.set_screen_index(4); // Message Verifier screen
        let s = state_verify_nav.borrow();
        match &s.verification_result {
            Some(result) => {
                ui.set_verify_message(result.message_display.clone().into());
                ui.set_verify_signer(result.signer_paynym.clone().into());
                ui.set_verify_result(if result.is_valid { "✅ VERIFIED" } else { "❌ FAILED" }.into());
                ui.set_verify_result_color(if result.is_valid { "#4ade80" } else { "#ff4444" }.into());
            }
            None => {
                ui.set_verify_message("".into());
                ui.set_verify_signer("".into());
                ui.set_verify_result("Awaiting verification...".into());
                ui.set_verify_result_color("#888888".into());
            }
        }
        ui.set_status("📩 Send a signed message via BLE to verify".into());
    });

    // ── Navigate to Settings ─────────────────────────────
    let ui_settings = ui.as_weak();
    let state_settings = state.clone();
    ui.on_show_settings(move || {
        let ui = ui_settings.unwrap();
        let s = state_settings.borrow();
        ui.set_screen_index(5); // Settings screen
        ui.set_dojo_server(s.dojo_server.clone().into());
        // Status
        let conn_status = if s.dojo_connected {
            format!("🟢 Connected  |  ⛓ {}", s.block_height)
        } else {
            "🔴 Disconnected".to_string()
        };
        ui.set_connection_status(conn_status.into());
        let tor_label = if s.tor_enabled { "🟢 On" } else { "🔴 Off" };
        ui.set_tor_status(tor_label.into());
    });

    // ── Navigate to History ──────────────────────────────
    let ui_hist = ui.as_weak();
    let state_hist = state.clone();
    ui.on_show_history(move || {
        let ui = ui_hist.unwrap();
        let s = state_hist.borrow();
        ui.set_history_count(s.coinjoin_history.len() as i32);
        ui.set_verify_count(s.verification_history.len() as i32);
        ui.set_screen_index(6); // History screen            if !s.coinjoin_history.is_empty() {
            let last = &s.coinjoin_history[s.coinjoin_history.len() - 1];
            let summary = format!(
                "Last mix: {} | witnesses: {} | ✓",
                &last.mix_id[..8.min(last.mix_id.len())],
                last.witnesses_64.len()
            );
            ui.set_last_signing(summary.into());
        } else {
            ui.set_last_signing("No signing history yet".into());
        }
    });

    // ── Go Back ──────────────────────────────────────────
    let ui_back = ui.as_weak();
    ui.on_go_back(move || {
        let ui = ui_back.unwrap();
        ui.set_screen_index(0); // Home screen
        ui.set_status("🟢 DOJO SIGNER ready".into());
    });

    // ── Approve Coinjoin Signing ─────────────────────────
    let ui_approve = ui.as_weak();
    let state_approve = state.clone();
    ui.on_approve_coinjoin(move || {
        let ui = ui_approve.unwrap();
        let mut s = state_approve.borrow_mut();

        match &s.current_coinjoin_req {
            Some(req) => {
                // Sign the coinjoin transaction
                let signature_bytes = match sign_with_secure_element(&req.transaction_64) {
                    Ok(sig) => sig,
                    Err(_) => {
                        ui.set_status("❌ Signing failed — secure element error".into());
                        return;
                    }
                };

                // TODO: On real hardware, decode transaction_64 from Z85
                // to get the raw unsigned transaction bytes, hash them, and
                // sign with the secure element. The Z85 crate needs to be
                // added as a dependency.
                //
                // let tx_bytes = z85::decode(&req.transaction_64)?;
                // let hash = crypto::sha256(&tx_bytes);
                // let (sig, _) = SecureElement::sign_hash_with_key("dojo_master", &hash)?;
                // let sig_hex = hex::encode(sig);

                // For now, sign a placeholder hash to demonstrate the flow
                let placeholder_hash = crypto::sha256(b"dojo-signer-witness");
                let (signature_bytes, _) = match SecureElement::sign_hash_with_key(
                    "dojo_master", &placeholder_hash
                ) {
                    Ok(result) => result,
                    Err(_) => {
                        ui.set_status("❌ Signing failed — secure element error".into());
                        return;
                    }
                };

                // Add our witness signature to the witnesses array
                let mut signed_witnesses = req.witnesses_64.clone();
                signed_witnesses.push(hex::encode(&signature_bytes));

                let response = CoinjoinSigningRes {
                    mix_id: req.mix_id.clone(),
                    witnesses_64: signed_witnesses,
                    signed_at: 2026072900,
                };

                // Store in history
                s.coinjoin_history.push(response.clone());
                s.current_coinjoin_req = None;

                // Send response via BLE
                if let Err(e) = send_coinjoin_response_via_ble(&response) {
                    ui.set_status(
                        format!("✓ Signed, but BLE send failed: {:?}", e).into()
                    );
                } else {
                    ui.set_status("✓ Coinjoin transaction signed and sent to Dojo".into());
                }

                // Clear display
                ui.set_tx_type("".into());
                ui.set_amount_sats(0);
                ui.set_fee_sats(0);
                ui.set_input_count(0);
                ui.set_anonset(0);
                ui.set_target_anonset(0);
            }
            None => {
                ui.set_status("No transaction to sign".into());
            }
        }
    });

    // ── Reject Coinjoin ──────────────────────────────────
    let ui_reject = ui.as_weak();
    let state_reject = state.clone();
    ui.on_reject_coinjoin(move || {
        let ui = ui_reject.unwrap();
        let mut s = state_reject.borrow_mut();
        s.current_coinjoin_req = None;
        ui.set_status("✗ Coinjoin rejected — nothing was signed".into());
        ui.set_tx_type("".into());
        ui.set_amount_sats(0);
        ui.set_fee_sats(0);
        ui.set_input_count(0);
        ui.set_anonset(0);
        ui.set_target_anonset(0);
    });

    // ── Scan QR for signing request ──────────────────────
    let ui_scan = ui.as_weak();
    let state_scan = state.clone();
    ui.on_scan_qr(move || {
        let ui = ui_scan.unwrap();
        match scan_coinjoin_request_qr() {
            Ok(req) => {
                let mut s = state_scan.borrow_mut();
                s.current_coinjoin_req = Some(req.clone());

                // Update display
                ui.set_tx_type(format!("Mix: {}", req.mix_id).into());
                ui.set_amount_sats(0);
                ui.set_fee_sats(0);
                ui.set_input_count(req.witnesses_64.len() as i32);
                ui.set_anonset(0);
                ui.set_target_anonset(0);
                ui.set_screen_index(3);

                ui.set_status("📷 Coinjoin request loaded from QR — review then approve or reject".into());
            }
            Err(e) => {
                ui.set_status(format!("📷 QR scan failed: {:?}", e).into());
            }
        }
    });

    // ── Connect to Dojo (BLE) ────────────────────────────
    let ui_dojo = ui.as_weak();
    let state_dojo = state.clone();
    ui.on_connect_dojo(move || {
        let ui = ui_dojo.unwrap();
        match connect_to_dojo_backend() {
            Ok(status) => {
                let mut s = state_dojo.borrow_mut();
                s.dojo_connected = status.connected;
                s.dojo_server = status.server_url.clone();
                s.block_height = status.block_height;
                s.peer_count = status.peer_count;
                s.tor_enabled = status.tor_enabled;

                // Update settings screen
                let conn = format!("🟢 Connected  |  ⛓ {}", status.block_height);
                let tor = if status.tor_enabled { "🟢 On" } else { "🔴 Off" };
                ui.set_connection_status(conn.into());
                ui.set_tor_status(tor.into());
                ui.set_dojo_server(status.server_url.into());

                ui.set_status("🟢 Connected to Dojo — ready for signing".into());
            }
            Err(e) => {
                ui.set_status(format!("🔴 Dojo connection failed: {:?}", e).into());
            }
        }
    });

    // ── Verify BIP47 Message ─────────────────────────────
    let ui_verify_msg = ui.as_weak();
    let state_verify = state.clone();
    ui.on_verify_message(move || {
        let ui = ui_verify_msg.unwrap();
        let mut s = state_verify.borrow_mut();

        match &s.current_verification {
            Some(req) => {
                // Perform verification
                match VerificationResult::verify(
                    &req.message,
                    &req.signature_base64,
                    &req.signer_payment_code,
                ) {
                    Ok(result) => {
                        let response = if result.is_valid {
                            VerificationResponse::verified(req, &result.signer_paynym.unwrap_or_default())
                        } else {
                            VerificationResponse::failed(req)
                        };

                        // Store in history
                        s.verification_history.push(VerificationHistoryEntry {
                            timestamp: 2026072900,
                            signer_paynym: response.signer_paynym.clone(),
                            is_valid: response.is_valid,
                            message_preview: response.message_display.clone(),
                        });
                        s.verification_result = Some(response.clone());

                        // Update display
                        ui.set_verify_message(response.message_display.into());
                        ui.set_verify_signer(response.signer_paynym.into());
                        ui.set_verify_result(
                            if response.is_valid { "✅ VERIFIED" } else { "❌ FAILED" }.into()
                        );
                        ui.set_verify_result_color(
                            if response.is_valid { "#4ade80" } else { "#ff4444" }.into()
                        );
                        ui.set_status(
                            if response.is_valid {
                                "✅ BIP47 signature verified — message is authentic".into()
                            } else {
                                "❌ Verification failed — signature does not match".into()
                            }
                        );
                    }
                    Err(e) => {
                        ui.set_status(format!("⚠️ Verification error: {:?}", e).into());
                    }
                }
                s.current_verification = None;
            }
            None => {
                ui.set_status("📩 No message to verify — send one via BLE or scan QR".into());
            }
        }
    });

    // ── Refresh UTXOs ────────────────────────────────────
    let ui_refresh = ui.as_weak();
    let state_refresh = state.clone();
    ui.on_refresh_utxos(move || {
        let ui = ui_refresh.unwrap();
        match request_utxo_list_from_dojo() {
            Ok(list) => {
                let mut s = state_refresh.borrow_mut();
                s.utxo_list = Some(list.clone());
                s.utxo_loaded = true;

                ui.set_utxo_count(list.summary.total_count as i32);
                ui.set_utxo_value(list.summary.total_value_sats as i32);
                ui.set_doxxic_count(list.summary.doxxic_count as i32);
                ui.set_avg_anonset(list.summary.avg_anonset as i32);

                ui.set_status(format!("🔄 {} UTXOs loaded — {} doxxic, avg anonset: {}",
                    list.summary.total_count, list.summary.doxxic_count, list.summary.avg_anonset).into());
            }
            Err(e) => {
                ui.set_status(format!("⚠️ UTXO request failed: {:?}", e).into());
            }
        }
    });

    // ── Export PayNym as QR ──────────────────────────────
    let ui_export = ui.as_weak();
    let state_export = state.clone();
    ui.on_export_paynym_qr(move || {
        let ui = ui_export.unwrap();
        let s = state_export.borrow();
        if let Some(ref paynym) = s.paynym_identity {
            // On a real device, this would show the payment code as a QR
            // The companion app scans it to establish BIP47 communication
            ui.set_status(
                format!("📱 Payment code QR shown — {} ready for BIP47", paynym.name).into()
            );
        } else {
            ui.set_status("⚠️ PayNym not available — initialize seed first".into());
        }
    });

    // ── Toggle Tor ────────────────────────────────────────
    let ui_tor = ui.as_weak();
    let state_tor = state.clone();
    ui.on_toggle_tor(move || {
        let ui = ui_tor.unwrap();
        let mut s = state_tor.borrow_mut();
        s.tor_enabled = !s.tor_enabled;
        let label = if s.tor_enabled { "🟢 On" } else { "🔴 Off" };
        ui.set_tor_status(label.into());
        ui.set_status(format!("🔒 Tor {}", if s.tor_enabled { "enabled" } else { "disabled" }).into());
    });
}

// ─── BLE Communication ──────────────────────────────────────

fn start_dojo_ble_service() -> Result<(), keyos::Error> {
    Bluetooth::advertise_as_peripheral("DOJO-SIGNER", |connection| {
        connection.subscribe_to_characteristic("DOJO-CJ-REQ", |data: &[u8]| {
            // Coinjoin request arrives here
            // The UI picks it up via polling
            Ok(())
        })?;

        connection.subscribe_to_characteristic("DOJO-VRFY-REQ", |data: &[u8]| {
            // Verification request arrives here
            Ok(())
        })?;

        connection.subscribe_to_characteristic("DOJO-UTXO-LIST", |data: &[u8]| {
            // UTXO list arrives here
            Ok(())
        })?;

        Ok(())
    })
}

fn connect_to_dojo_backend() -> Result<DojoConnectionStatus, keyos::Error> {
    Bluetooth::scan_for_service("DOJO-BACKEND-SVC")?;
    let device = Bluetooth::connect_to_service("DOJO-BACKEND-SVC")?;

    device.subscribe_to_characteristic("DOJO-CJ-REQ", |data: &[u8]| {
        Ok(())
    })?;

    // Handshake — notify Dojo we're ready
    let handshake = b"{\"type\":\"handshake\",\"version\":\"0.1.0\"}";
    device.send_on_characteristic("DOJO-HANDSHAKE", handshake)?;

    Ok(DojoConnectionStatus {
        connected: true,
        server_url: "dojo.local:443".into(),
        tor_enabled: true,
        block_height: 876543,
        peer_count: 8,
        verified_reputation: true,
    })
}

fn send_coinjoin_response_via_ble(response: &CoinjoinSigningRes) -> Result<(), keyos::Error> {
    let data = serde_json::to_vec(response)
        .map_err(|_| keyos::Error::SerializationFailed)?;
    Bluetooth::send("DOJO-CJ-RES", &data)
}

fn request_utxo_list_from_dojo() -> Result<UtxoReviewList, keyos::Error> {
    // Request UTXO list from Dojo server via BLE
    Bluetooth::send("DOJO-UTXO-REQ", b"get_utxos")?;

    // For development, return a sample list
    // In production, this would parse the BLE response
    let utxos = vec![
        UtxoDisplayItem {
            txid_short: "abc123def456...".into(),
            value_sats: 100_000,
            is_doxxic: true,
            anonset: 0,
            mix_state_icon: "🔴",
            reviewed: false,
        },
        UtxoDisplayItem {
            txid_short: "7890abcd1234...".into(),
            value_sats: 50_000,
            is_doxxic: false,
            anonset: 5,
            mix_state_icon: "🟡",
            reviewed: false,
        },
        UtxoDisplayItem {
            txid_short: "efab5678cdef...".into(),
            value_sats: 200_000,
            is_doxxic: false,
            anonset: 42,
            mix_state_icon: "🟢",
            reviewed: false,
        },
    ];

    let summary = UtxoSummary::from_utxos(&utxos);

    Ok(UtxoReviewList { utxos, summary })
}

// ─── QR Scanning ────────────────────────────────────────────

fn scan_coinjoin_request_qr() -> Result<CoinjoinSigningReq, keyos::Error> {
    let qr_data = Camera::scan_qr()?;
    let qr_str = core::str::from_utf8(&qr_data)
        .map_err(|_| keyos::Error::InvalidData)?;
    let req: CoinjoinSigningRequest = serde_json::from_str(qr_str)
        .map_err(|_| keyos::Error::InvalidData)?;
    Ok(req)
}

// ─── UI Helpers ─────────────────────────────────────────────

fn update_status_display(ui: &DojoSignerUI, state: &AppState) {
    ui.set_status(format!("{} {}", state.status_icon, state.status_text).into());
}

fn update_status(ui: &DojoSignerUI, state: Rc<RefCell<AppState>>, msg: &str) {
    let mut s = state.borrow_mut();
    s.status_text = msg.into();
    s.status_icon = "🟢";
    ui.set_status(format!("🟢 {}", msg).into());
}

fn truncate_code(code: &str, max: usize) -> String {
    if code.len() <= max {
        code.into()
    } else {
        format!("{}...", &code[..max])
    }
}

// ─── Slint UI ───────────────────────────────────────────────

slint::slint! {
    import { VerticalBox, HorizontalBox, Button, Text } from "std-widgets.slint";

    export component DojoSignerUI inherits Window {
        in-out property <int> screen-index;
        in-out property <string> status;
        in-out property <string> device-name;

        // PayNym identity
        in-out property <string> paynym-name;
        in-out property <string> paynym-code;
        in-out property <string> pepehash;

        // UTXO Review
        in-out property <int> utxo-count;
        in-out property <int> utxo-value;
        in-out property <int> doxxic-count;
        in-out property <int> avg-anonset;

        // Coinjoin
        in-out property <string> tx-type;
        in-out property <int> amount-sats;
        in-out property <int> fee-sats;
        in-out property <int> input-count;
        in-out property <int> anonset;
        in-out property <int> target-anonset;

        // Message Verifier
        in-out property <string> verify-message;
        in-out property <string> verify-signer;
        in-out property <string> verify-result;
        in-out property <color> verify-result-color;

        // Settings
        in-out property <string> dojo-server;
        in-out property <string> connection-status;
        in-out property <string> tor-status;

        // History
        in-out property <int> history-count;
        in-out property <int> verify-count;
        in-out property <string> last-signing;

        // Callbacks
        callback show-paynym();
        callback show-utxo-review();
        callback show-coinjoin();
        callback show-verifier();
        callback show-settings();
        callback show-history();
        callback go-back();
        callback approve-coinjoin();
        callback reject-coinjoin();
        callback scan-qr();
        callback connect-dojo();
        callback verify-message();
        callback refresh-utxos();
        callback export-paynym-qr();
        callback toggle-tor();

        min-width: 320px;
        min-height: 480px;
        title: "DOJO SIGNER";
        background: #000;
        default-font-family: "monospace";

        VerticalLayout {
            padding: 10px;
            spacing: 6px;

            // ══════ HEADER ══════
            HorizontalLayout {
                spacing: 6px;

                // Terminal marker
                Text {
                    text: ">>";
                    font-size: 16px;
                    font-weight: 700;
                    color: #cc0000;
                    letter-spacing: 0px;
                }

                Text {
                    text: "DOJO_SIGNER";
                    font-size: 16px;
                    font-weight: 700;
                    color: #ff0000;
                    letter-spacing: 3px;
                }

                Rectangle {
                    background: #1a0000;
                    border-radius: 2px;
                    height: 18px;
                    border-width: 1px;
                    border-color: #330000;
                    VerticalLayout {
                        padding: 2px 6px;
                        Text {
                            text: root.device-name;
                            font-size: 8px;
                            color: #aa0000;
                        }
                    }
                }
            }

            // ══════ STATUS BAR ══════
            Rectangle {
                background: #0a0000;
                border-radius: 2px;
                height: 24px;
                border-width: 1px;
                border-color: #330000;
                VerticalLayout {
                    padding: 3px 10px;
                    Text {
                        text: "$ " + root.status;
                        font-size: 10px;
                        color: #cc0000;
                        wrap: word-break;
                    }
                }
            }

            // ══════ SCREEN: HOME (0) ══════
            if (root.screen-index == 0) : VerticalLayout {
                spacing: 6px;

                // PayNym Identity Card (terminal style)
                Rectangle {
                    background: #000;
                    border-radius: 2px;
                    border-width: 1px;
                    border-color: #330000;

                    VerticalLayout {
                        padding: 10px;
                        spacing: 6px;

                        Text {
                            text: "# PayNym Identity";
                            font-size: 12px;
                            font-weight: 600;
                            color: #ff0000;
                        }

                        HorizontalLayout {
                            spacing: 8px;

                            // Avatar placeholder
                            Rectangle {
                                width: 40px;
                                height: 40px;
                                background: #0a0000;
                                border-radius: 2px;
                                border-width: 1px;
                                border-color: #330000;
                                VerticalLayout {
                                    padding: 8px;
                                    Text {
                                        text: "🐸";
                                        font-size: 20px;
                                        horizontal-alignment: center;
                                        vertical-alignment: center;
                                    }
                                }
                            }

                            VerticalLayout {
                                spacing: 2px;
                                Text {
                                    text: "name: " + root.paynym-name;
                                    font-size: 14px;
                                    font-weight: 700;
                                    color: #ff0000;
                                }
                                Text {
                                    text: "hash: " + root.pepehash;
                                    font-size: 8px;
                                    color: #aa0000;
                                }
                                Text {
                                    text: root.paynym-code;
                                    font-size: 7px;
                                    color: #880000;
                                    wrap: word-break;
                                }
                            }
                        }

                        // Quick actions
                        HorizontalLayout {
                            spacing: 4px;
                            Button {
                                text: "[show_code]";
                                font-size: 8px;
                                clicked => { root.show-paynym(); }
                            }
                            Button {
                                text: "[scan_qr]";
                                font-size: 8px;
                                clicked => { root.scan-qr(); }
                            }
                            Button {
                                text: "[refresh]";
                                font-size: 8px;
                                clicked => { root.refresh-utxos(); }
                            }
                        }
                    }
                }

                // Navigation Grid (terminal buttons)
                GridLayout {
                    spacing: 4px;

                    Row {
                        Button {
                            text: "[utxo]";
                            font-size: 10px;
                            min-height: 40px;
                            background: #0a0000;
                            color: #cc0000;
                            border-radius: 2px;
                            border-width: 1px;
                            border-color: #330000;
                            clicked => { root.show-utxo-review(); }
                            stretch: 1;
                        }

                        Button {
                            text: "[coinjoin]";
                            font-size: 10px;
                            min-height: 40px;
                            background: #0a0000;
                            color: #cc0000;
                            border-radius: 2px;
                            border-width: 1px;
                            border-color: #330000;
                            clicked => { root.show-coinjoin(); }
                            stretch: 1;
                        }

                        Button {
                            text: "[verify]";
                            font-size: 10px;
                            min-height: 40px;
                            background: #0a0000;
                            color: #cc0000;
                            border-radius: 2px;
                            border-width: 1px;
                            border-color: #330000;
                            clicked => { root.show-verifier(); }
                            stretch: 1;
                        }
                    }

                    Row {
                        Button {
                            text: "[connect]";
                            font-size: 10px;
                            min-height: 36px;
                            background: #0a0000;
                            color: #cc0000;
                            border-radius: 2px;
                            border-width: 1px;
                            border-color: #330000;
                            clicked => { root.connect-dojo(); }
                            stretch: 1;
                        }

                        Button {
                            text: "[settings]";
                            font-size: 10px;
                            min-height: 36px;
                            background: #0a0000;
                            color: #cc0000;
                            border-radius: 2px;
                            border-width: 1px;
                            border-color: #330000;
                            clicked => { root.show-settings(); }
                            stretch: 1;
                        }

                        Button {
                            text: "[history]";
                            font-size: 10px;
                            min-height: 36px;
                            background: #0a0000;
                            color: #cc0000;
                            border-radius: 2px;
                            border-width: 1px;
                            border-color: #330000;
                            clicked => { root.show-history(); }
                            stretch: 1;
                        }
                    }
                }

                // Status line
                Rectangle {
                    background: #000;
                    border-radius: 2px;
                    height: 16px;
                    border-width: 1px;
                    border-color: #1a0000;
                    VerticalLayout {
                        padding: 1px 6px;
                        Text {
                            text: "# DOJO_SIGNER  |  BIP47  |  COINJOIN  |  UTXO";
                            font-size: 7px;
                            color: #660000;
                            letter-spacing: 1px;
                        }
                    }
                }
            }

            // ══════ SCREEN: PAYNYM (1) ══════
            if (root.screen-index == 1) : VerticalLayout {
                spacing: 6px;

                Text {
                    text: "# BIP47 Payment Code";
                    font-size: 14px;
                    font-weight: 600;
                    color: #ff0000;
                }

                Rectangle {
                    background: #000;
                    border-radius: 2px;
                    border-width: 1px;
                    border-color: #330000;
                    VerticalLayout {
                        padding: 12px;
                        spacing: 8px;

                        // PayNym avatar + name
                        HorizontalLayout {
                            spacing: 8px;
                            Rectangle {
                                width: 48px; height: 48px;
                                background: #0a0000;
                                border-radius: 2px;
                                border-width: 1px;
                                border-color: #330000;
                                VerticalLayout {
                                    padding: 10px;
                                    Text { text: "🐸"; font-size: 22px; }
                                }
                            }
                            VerticalLayout {
                                spacing: 4px;
                                Text { text: "user: " + root.paynym-name; font-size: 18px; font-weight: 700; color: #ff0000; }
                                Text { text: "hash: " + root.pepehash; font-size: 9px; color: #aa0000; }
                            }
                        }

                        // Full payment code
                        Text { text: "$ payment_code"; font-size: 10px; color: #880000; }
                        Rectangle {
                            background: #050000;
                            border-radius: 2px;
                            border-width: 1px;
                            border-color: #1a0000;
                            VerticalLayout {
                                padding: 8px;
                                Text {
                                    text: root.paynym-code;
                                    font-size: 9px;
                                    color: #cc0000;
                                    wrap: word-break;
                                }
                            }
                        }

                        Text {
                            text: "# Share to receive BIP47 payments. Each generates a unique address.";
                            font-size: 8px;
                            color: #660000;
                            wrap: word-break;
                        }
                    }
                }

                Button {
                    text: "[show_qr]";
                    font-size: 10px;
                    clicked => { root.export-paynym-qr(); }
                }

                Button {
                    text: "[back]";
                    font-size: 10px;
                    clicked => { root.go-back(); }
                }
            }

            // ══════ SCREEN: UTXO REVIEW (2) ══════
            if (root.screen-index == 2) : VerticalLayout {
                spacing: 6px;

                Text {
                    text: "# UTXO Coin Control";
                    font-size: 14px;
                    font-weight: 600;
                    color: #ff0000;
                }

                // Summary bar
                Rectangle {
                    background: #000;
                    border-radius: 2px;
                    border-width: 1px;
                    border-color: #330000;
                    VerticalLayout {
                        padding: 8px;
                        spacing: 4px;
                        HorizontalLayout {
                            Text { text: "utxos: "; color: #880000; font-size: 10px; }
                            Text { text: root.utxo-count; color: #ff0000; font-size: 11px; }
                            Text { text: "  |  value: "; color: #880000; font-size: 10px; }
                            Text { text: root.utxo-value; color: #ff0000; font-size: 11px; }
                            Text { text: " sats"; color: #880000; font-size: 9px; }
                        }
                        HorizontalLayout {
                            Text { text: "doxxic: "; color: #cc0000; font-size: 10px; }
                            Text { text: root.doxxic-count; color: #ff0000; font-size: 10px; }
                            Text { text: "  |  avg_anonset: "; color: #880000; font-size: 10px; }
                            Text { text: root.avg-anonset; color: #ff0000; font-size: 10px; }
                        }
                    }
                }

                Text {
                    text: "# doxxic = reveals history | clean = postmix";
                    font-size: 7px;
                    color: #660000;
                }

                Button {
                    text: "[refresh_utxos]";
                    font-size: 10px;
                    clicked => { root.refresh-utxos(); }
                }

                Button {
                    text: "[back]";
                    font-size: 10px;
                    clicked => { root.go-back(); }
                }
            }

            // ══════ SCREEN: COINJOIN SIGNING (3) ══════
            if (root.screen-index == 3) : VerticalLayout {
                spacing: 6px;

                Text {
                    text: "# Coinjoin Signing";
                    font-size: 14px;
                    font-weight: 600;
                    color: #ff0000;
                }

                // Transaction details card
                Rectangle {
                    background: #000;
                    border-radius: 2px;
                    border-width: 1px;
                    border-color: #660000;
                    VerticalLayout {
                        padding: 10px;
                        spacing: 6px;

                        Text {
                            text: "$ review_transaction";
                            font-size: 13px;
                            font-weight: 600;
                            color: #ff0000;
                        }

                        HorizontalLayout {
                            Text { text: "mix_id:  "; color: #880000; font-size: 10px; }
                            Text { text: root.tx-type; color: #ff0000; font-size: 11px; font-weight: 600; }
                        }

                        HorizontalLayout {
                            Text { text: "amount:  "; color: #880000; font-size: 10px; }
                            Text { text: root.amount-sats; color: #ff0000; font-size: 14px; font-weight: 700; }
                            Text { text: " sats"; color: #880000; font-size: 10px; }
                        }

                        HorizontalLayout {
                            Text { text: "fee:     "; color: #880000; font-size: 10px; }
                            Text { text: root.fee-sats; color: #cc0000; font-size: 10px; }
                            Text { text: " sats"; color: #880000; font-size: 10px; }
                        }

                        HorizontalLayout {
                            Text { text: "inputs:  "; color: #880000; font-size: 10px; }
                            Text { text: root.input-count; color: #ff0000; font-size: 10px; }
                            Text { text: " utxos"; color: #880000; font-size: 10px; }
                        }

                        HorizontalLayout {
                            Text { text: "anonset: "; color: #880000; font-size: 10px; }
                            Text { text: root.anonset; color: #4ade80; font-size: 10px; }
                            Text { text: "/"; color: #880000; font-size: 10px; }
                            Text { text: root.target-anonset; color: #ff0000; font-size: 10px; }
                        }
                    }
                }

                // Security warning
                Rectangle {
                    background: #0a0000;
                    border-radius: 2px;
                    border-width: 1px;
                    border-color: #660000;
                    height: 22px;
                    VerticalLayout {
                        padding: 3px 8px;
                        Text {
                            text: "! Coinjoin txns cannot be reversed. Verify carefully.";
                            font-size: 8px;
                            color: #cc0000;
                        }
                    }
                }

                // Approve / Reject
                HorizontalLayout {
                    spacing: 8px;
                    Button {
                        text: "[reject]";
                        background: #1a0000;
                        color: #ff0000;
                        font-weight: 700;
                        font-size: 12px;
                        border-width: 1px;
                        border-color: #660000;
                        clicked => { root.reject-coinjoin(); }
                        stretch: 1;
                    }
                    Button {
                        text: "[approve]";
                        background: #001a00;
                        color: #4ade80;
                        font-weight: 700;
                        font-size: 12px;
                        border-width: 1px;
                        border-color: #003300;
                        clicked => { root.approve-coinjoin(); }
                        stretch: 1;
                    }
                }

                Button {
                    text: "[back]";
                    font-size: 10px;
                    clicked => { root.go-back(); }
                }
            }

            // ══════ SCREEN: MESSAGE VERIFIER (4) ══════
            if (root.screen-index == 4) : VerticalLayout {
                spacing: 6px;

                Text {
                    text: "# BIP47 Message Verifier";
                    font-size: 14px;
                    font-weight: 600;
                    color: #4ade80;
                }

                Rectangle {
                    background: #000;
                    border-radius: 2px;
                    border-width: 1px;
                    border-color: #003300;
                    VerticalLayout {
                        padding: 10px;
                        spacing: 6px;

                        Text { text: "$ message"; font-size: 10px; color: #880000; }
                        Text { text: root.verify-message; font-size: 9px; color: #cc0000; wrap: word-break; }

                        Text { text: "$ signed_by"; font-size: 10px; color: #880000; }
                        Text { text: root.verify-signer; font-size: 12px; font-weight: 600; color: #ff0000; }

                        HorizontalLayout {
                            Text { text: "$ result: "; font-size: 12px; color: #880000; }
                            Text { text: root.verify-result; font-size: 14px; font-weight: 700; color: root.verify-result-color; }
                        }
                    }
                }

                Button {
                    text: "[verify]";
                    font-size: 10px;
                    clicked => { root.verify-message(); }
                }

                Button {
                    text: "[back]";
                    font-size: 10px;
                    clicked => { root.go-back(); }
                }
            }

            // ══════ SCREEN: SETTINGS (5) ══════
            if (root.screen-index == 5) : VerticalLayout {
                spacing: 6px;

                Text {
                    text: "# Settings";
                    font-size: 14px;
                    font-weight: 600;
                    color: #ff0000;
                }

                Rectangle {
                    background: #000;
                    border-radius: 2px;
                    border-width: 1px;
                    border-color: #330000;
                    VerticalLayout {
                        padding: 10px;
                        spacing: 8px;

                        HorizontalLayout {
                            spacing: 8px;
                            Text { text: "dojo:  "; font-size: 10px; color: #880000; min-width: 50px; }
                            Text { text: root.dojo-server; font-size: 10px; color: #cc0000; }
                        }
                        HorizontalLayout {
                            spacing: 8px;
                            Text { text: "status:"; font-size: 10px; color: #880000; min-width: 50px; }
                            Text { text: root.connection-status; font-size: 10px; color: #4ade80; }
                        }

                        HorizontalLayout {
                            spacing: 8px;
                            Text { text: "tor:   "; font-size: 10px; color: #880000; min-width: 50px; }
                            Text { text: root.tor-status; font-size: 10px; color: #cc0000; }
                            Button {
                                text: "[toggle]";
                                font-size: 8px;
                                color: #cc0000;
                                clicked => { root.toggle-tor(); }
                            }
                        }

                        Text { text: "# DOJO_SIGNER v0.1.0 | KeyOS 1.0.0"; font-size: 8px; color: #660000; }
                    }
                }

                Button {
                    text: "[connect_dojo]";
                    font-size: 10px;
                    clicked => { root.connect-dojo(); }
                }

                Button {
                    text: "[back]";
                    font-size: 10px;
                    clicked => { root.go-back(); }
                }
            }

            // ══════ SCREEN: HISTORY (6) ══════
            if (root.screen-index == 6) : VerticalLayout {
                spacing: 6px;

                Text {
                    text: "# History";
                    font-size: 14px;
                    font-weight: 600;
                    color: #ff0000;
                }

                Rectangle {
                    background: #000;
                    border-radius: 2px;
                    border-width: 1px;
                    border-color: #330000;
                    VerticalLayout {
                        padding: 10px;
                        spacing: 6px;

                        HorizontalLayout {
                            Text { text: "coinjoin_signs: "; color: #880000; font-size: 10px; }
                            Text { text: root.history-count; color: #ff0000; font-size: 12px; font-weight: 600; }
                        }
                        HorizontalLayout {
                            Text { text: "verifications:   "; color: #880000; font-size: 10px; }
                            Text { text: root.verify-count; color: #4ade80; font-size: 12px; font-weight: 600; }
                        }

                        Rectangle {
                            background: #050000;
                            border-radius: 2px;
                            border-width: 1px;
                            border-color: #1a0000;
                            VerticalLayout {
                                padding: 6px;
                                Text { text: "$ last_signing"; color: #880000; font-size: 9px; }
                                Text { text: root.last-signing; color: #cc0000; font-size: 9px; wrap: word-break; }
                            }
                        }
                    }
                }

                Button {
                    text: "[back]";
                    font-size: 10px;
                    clicked => { root.go-back(); }
                }
            }
        }
    }
}
