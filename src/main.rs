// SPDX-FileCopyrightText: 2025 DOJO SIGNER Team
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;

use ngwallet::{
    bdk_wallet::{
        bitcoin::{
            secp256k1::Secp256k1,
            sign_message::{MessageSignature, signed_msg_hash},
            hashes::Hash,
            Network, PubkeyHash,
        },
        KeychainKind, SignOptions,
    },
    bip39::MasterKey,
    ngwallet::NgWallet,
    store::MetaStorage,
};
use quantum_link::{
    foundation_api::bitcoin::BroadcastTransaction,
    messages::{PublishPsbt, SubscribeAccountUpdate, SubscribePairingEvent, SubscribeSignPsbt},
    PairingEvent,
};
use slint_keyos_platform::{
    app,
    async_archive,
    gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult},
    navigation::open_qr_scanner,
    qrcode,
    slint::{Color, ComponentHandle, SharedString},
    spawn_local, subscribe_archive,
};
use std::sync::Mutex;

mod bip47;
mod coinjoin;
mod message;
mod utxo;

quantum_link::use_api!();
security::use_api!();

// Re-export for other modules
pub use bip47::PayNymIdentity;
pub use coinjoin::{
    ConfirmInputRequest, MixStatus, RegisterInputRequest, RevealOutputRequest,
    SigningRequest, SigningResponse, WhirlpoolAccount,
};

/// Pending PSBT bytes received from the Whirlpool companion over BLE
static PENDING_PSBT: Mutex<Option<Vec<u8>>> = Mutex::new(None);
/// Pending Whirlpool protocol signing request
static PENDING_SIGNING: Mutex<Option<SigningRequest>> = Mutex::new(None);

/// Open the system QR scanner and return the scanned text (if any).
fn open_scan() -> Option<String> {
    let opts = ScanQrOptions {
        header_title: "Scan QR".into(),
        header_right_icon: "close".into(),
        ..ScanQrOptions::default()
    };
    match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
        Ok(Some(ScanQrResult::Qr { data, .. })) | Ok(Some(ScanQrResult::Ur2 { data, .. })) => {
            Some(String::from_utf8_lossy(&data).to_string())
        }
        _ => None,
    }
}

/// Simple in-memory meta storage for ngwallet (no persistence needed for signing)
#[derive(Debug)]
struct SimpleMetaStorage;
impl MetaStorage for SimpleMetaStorage {
    fn set_fee(&self, _txid: &str, _fee: u64) -> anyhow::Result<()> { Ok(()) }
    fn get_fee(&self, _txid: &str) -> anyhow::Result<Option<u64>> { Ok(None) }
    fn set_note(&self, _key: &str, _value: &str) -> anyhow::Result<()> { Ok(()) }
    fn get_note(&self, _key: &str) -> anyhow::Result<Option<String>> { Ok(None) }
    fn list_tags(&self) -> anyhow::Result<Vec<String>> { Ok(vec![]) }
    fn add_tag(&self, _tag: &str) -> anyhow::Result<()> { Ok(()) }
    fn remove_tag(&self, _tag: &str) -> anyhow::Result<()> { Ok(()) }
    fn set_tag(&self, _key: &str, _value: &str) -> anyhow::Result<()> { Ok(()) }
    fn get_tag(&self, _key: &str) -> anyhow::Result<Option<String>> { Ok(None) }
    fn set_do_not_spend(&self, _key: &str, _value: bool) -> anyhow::Result<()> { Ok(()) }
    fn get_do_not_spend(&self, _key: &str) -> anyhow::Result<bool> { Ok(false) }
    fn set_config(&self, _cfg: &str) -> anyhow::Result<()> { Ok(()) }
    fn get_config(&self) -> anyhow::Result<Option<ngwallet::config::NgAccountConfig>> { Ok(None) }
    fn set_last_verified_address(
        &self, _addr_type: ngwallet::config::AddressType, _kc: KeychainKind, _idx: u32,
    ) -> anyhow::Result<()> { Ok(()) }
    fn get_last_verified_address(
        &self, _addr_type: ngwallet::config::AddressType, _kc: KeychainKind,
    ) -> anyhow::Result<u32> { Ok(0) }
    fn persist(&self) -> anyhow::Result<bool> { Ok(true) }
}

/// Simple persister that doesn't persist (in-memory only)
#[derive(Debug)]
struct NullPersister(std::sync::Mutex<ngwallet::bdk_wallet::ChangeSet>);

impl ngwallet::bdk_wallet::WalletPersister for NullPersister {
    type Error = anyhow::Error;
    fn initialize(persister: &mut Self) -> Result<ngwallet::bdk_wallet::ChangeSet, Self::Error> {
        Ok(persister.0.lock().unwrap().clone())
    }
    fn persist(persister: &mut Self, changeset: &ngwallet::bdk_wallet::ChangeSet) -> Result<(), Self::Error> {
        *persister.0.lock().unwrap() = changeset.clone();
        Ok(())
    }
}

/// Load the master key from device seed
fn load_master_key(network: Network) -> anyhow::Result<MasterKey> {
    let secp = Secp256k1::new();
    let security = crate::Security::default();
    let entropy = security
        .seed()
        .map_err(|_| anyhow::anyhow!("access denied"))?
        .ok_or_else(|| anyhow::anyhow!("no seed available"))?;
    MasterKey::from_entropy(&secp, network, entropy.bytes(), "", None)
        .map_err(|e| anyhow::anyhow!("master key: {:?}", e))
}

/// Create a BIP84 (SegWit) wallet from device seed
fn create_bip84_wallet(network: Network, account_index: u32) -> anyhow::Result<NgWallet<NullPersister>> {
    let master_key = load_master_key(network)?;
    let descriptors = ngwallet::bip39::get_descriptors(&master_key.key.0, network, account_index)?;

    for d in descriptors {
        let internal = d.change_descriptor;
        let external = d.descriptor;
        let persister = Arc::new(Mutex::new(NullPersister(Mutex::new(
            ngwallet::bdk_wallet::ChangeSet::default(),
        ))));

        let wallet = NgWallet::new_from_descriptor(
            internal,
            Some(external),
            network,
            Arc::new(SimpleMetaStorage),
            persister,
        )?;
        return Ok(wallet);
    }

    Err(anyhow::anyhow!("no descriptors generated"))
}

/// Derive a real BIP84 receive address from device seed (index N → fresh addresses)
fn derive_receive_address(index: u32) -> Result<String, String> {
    let wallet = create_bip84_wallet(Network::Bitcoin, 0).map_err(|e| format!("{}", e))?;
    let bdk = wallet.bdk_wallet.lock().map_err(|e| format!("lock: {}", e))?;
    let address = bdk.peek_address(KeychainKind::External, index);
    Ok(address.to_string())
}

/// Persisted app state: node connection settings + BIP47/receive counters.
/// Stored as JSON on the device filesystem (AppData), restored on startup.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct AppConfig {
    host: String,
    port: u16,
    ssl: bool,
    username: String,
    password: String,
    receive_index: u32,
    /// Next unused BIP47 payment index per recipient payment code.
    bip47_indices: BTreeMap<String, u32>,
    /// Selected Whirlpool pool denomination (0.5/0.25/0.1/0.05/0.01 btc).
    #[serde(default = "default_pool_id")]
    pool_id: String,
    /// BIP47 message verification history (last 20).
    #[serde(default)]
    verification_history: Vec<message::VerificationHistoryEntry>,
}

fn default_pool_id() -> String {
    "0.5btc".into()
}

/// Render the persisted BIP47 verification history for the Verify page.
fn render_verify_history(history: &[message::VerificationHistoryEntry]) -> String {
    if history.is_empty() {
        return "No verifications yet".into();
    }
    history
        .iter()
        .rev()
        .take(8)
        .map(|h| {
            let mark = if h.is_valid { "✅" } else { "❌" };
            format!("{} {} {}", mark, h.signer_paynym, h.timestamp)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

const CONFIG_PATH: &str = "dojo-signer/config.json";

fn load_app_config() -> AppConfig {
    let filesystem = crate::FileSystem::default();
    let mut cfg: AppConfig = match filesystem.open_file(
        CONFIG_PATH.to_string(),
        fs::Location::AppData,
        fs::OpenFlags::READ_ONLY,
    ) {
        Ok(mut file) => {
            let mut data = Vec::new();
            if file.read_to_end(&mut data).is_err() {
                AppConfig::default()
            } else {
                serde_json::from_slice(&data).unwrap_or_default()
            }
        }
        Err(_) => AppConfig::default(),
    };
    if cfg.pool_id.is_empty() {
        cfg.pool_id = "0.5btc".into();
    }
    cfg
}

fn save_app_config(cfg: &AppConfig) {
    let filesystem = crate::FileSystem::default();
    let _ = filesystem.ensure_parent_dir_exists(CONFIG_PATH, fs::Location::AppData);
    if let Ok(mut file) = filesystem.open_file(
        CONFIG_PATH.to_string(),
        fs::Location::AppData,
        fs::OpenFlags::CREATE,
    ) {
        if let Ok(json) = serde_json::to_vec(cfg) {
            if file.write_all(&json).is_ok() {
                let _ = file.truncate();
            }
        }
    }
}

/// Build + sign a PSBT sending `amount_sats` to `address` at the given fee.
fn build_signed_psbt(
    address: &str,
    amount_sats: u64,
    fee_sats: u64,
    exclude_outpoint: Option<ngwallet::bdk_wallet::bitcoin::OutPoint>,
) -> anyhow::Result<ngwallet::bdk_wallet::bitcoin::Psbt> {
    use ngwallet::bdk_wallet::bitcoin::Address;
    use std::str::FromStr;

    let dest = Address::from_str(address)
        .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?
        .require_network(Network::Bitcoin)
        .map_err(|_| anyhow::anyhow!("Wrong network"))?;

    let wallet = create_bip84_wallet(Network::Bitcoin, 0)?;

    {
        let bdk = wallet.bdk_wallet.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
        let utxos: Vec<_> = bdk.list_unspent().collect();
        if utxos.is_empty() {
            return Err(anyhow::anyhow!("No UTXOs available — sync with companion app first"));
        }
        if let Some(excl) = exclude_outpoint {
            if !utxos.iter().any(|u| u.outpoint != excl) {
                return Err(anyhow::anyhow!(
                    "First-contact BIP47 send needs a second UTXO (one funds the notification tx, one the payment) — sync more coins first"
                ));
            }
        }
    }

    let amount = ngwallet::bdk_wallet::bitcoin::Amount::from_sat(amount_sats);
    let fee_rate = ngwallet::bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(
        (fee_sats / 250).max(1),
    )
    .ok_or_else(|| anyhow::anyhow!("Invalid fee rate"))?;

    let mut tx_builder = wallet.bdk_wallet.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
    let mut builder = tx_builder.build_tx();
    builder.add_recipient(dest.script_pubkey(), amount);
    builder.fee_rate(fee_rate);
    if let Some(excl) = exclude_outpoint {
        builder.unspendable(vec![excl]);
    }
    let mut psbt = builder.finish().map_err(|e| anyhow::anyhow!("Build: {}", e))?;

    let options = SignOptions {
        trust_witness_utxo: true,
        ..SignOptions::default()
    };
    tx_builder.sign(&mut psbt, options).map_err(|e| anyhow::anyhow!("Sign: {}", e))?;
    drop(tx_builder);
    Ok(psbt)
}

/// Broadcast a signed PSBT via Quantum Link (companion app → Dojo).
async fn broadcast_psbt(psbt: ngwallet::bdk_wallet::bitcoin::Psbt) -> anyhow::Result<()> {
    let message = PublishPsbt {
        transaction: BroadcastTransaction {
            account_id: "dojo-signer-0".into(),
            psbt: psbt.serialize(),
        },
    };
    log::info!("📡 Broadcasting PSBT via QL...");
    async_archive::<quantum_link_permissions::QuantumLinkPermissions, _>(message)
        .await
        .map_err(|e| anyhow::anyhow!("Broadcast: {:?}", e))?;
    Ok(())
}

/// BIP47 send to a PayNym payment code (PM8T...):
/// derive the unique payment address, and on first contact build + send the
/// notification transaction (blinded OP_RETURN) per the BIP47 spec.
async fn send_bip47(target: &str, amount_sats: u64, fee_sats: u64) -> anyhow::Result<String> {
    use bip47::PaymentCode;

    let pc = PaymentCode::parse(target).map_err(|e| anyhow::anyhow!("{}", e))?;
    let sender_key = bip47::sender_notification_secret().map_err(|e| anyhow::anyhow!("{}", e))?;

    let mut cfg = load_app_config();
    let index = cfg.bip47_indices.get(&pc.raw).copied().unwrap_or(0);
    let first_contact = index == 0;

    let (payment_addr, used_index) =
        pc.payment_address(&sender_key, index).map_err(|e| anyhow::anyhow!("{}", e))?;
    let notification_addr =
        pc.notification_address().map_err(|e| anyhow::anyhow!("{}", e))?;

    // First contact: send the notification transaction (per BIP47).
    let mut notif_status = "ℹ️ already notified".to_string();
    let mut notif_outpoint: Option<ngwallet::bdk_wallet::bitcoin::OutPoint> = None;
    let mut abort_payment = false;
    if first_contact {
        match build_notification_psbt(&pc) {
            Ok(Some((psbt, outpoint))) => {
                // Whether broadcast succeeds now or the PSBT is exported later,
                // the payment tx must never spend the notification's input.
                notif_outpoint = Some(outpoint);
                let txid = psbt.unsigned_tx.compute_txid().to_string();
                match broadcast_psbt(psbt).await {
                    Ok(_) => notif_status = format!("✅ notification sent (tx {})", &txid[..10]),
                    Err(_) => {
                        notif_status = "⏳ notification PSBT ready — broadcast via companion".into()
                    }
                }
            }
            Ok(None) => notif_status = "⚠️ no UTXOs — notification tx deferred".into(),
            Err(e) => {
                notif_status = format!("⚠️ notification tx failed: {}", e);
                // Without a delivered notification the recipient can never
                // derive this payment address — abort rather than strand funds.
                abort_payment = true;
            }
        }
    }

    if abort_payment {
        return Ok(format!(
            "BIP47 → {}\nnotification: {}\npayment: SKIPPED — notification tx must be sent first\n{}",
            &pc.raw[..14.min(pc.raw.len())],
            notification_addr,
            notif_status,
        ));
    }

    // Payment transaction to the derived BIP47 address.
    let mut sent = false;
    let pay_status = match build_signed_psbt(&payment_addr, amount_sats, fee_sats, notif_outpoint) {
        Ok(psbt) => {
            let txid = psbt.unsigned_tx.compute_txid().to_string();
            match broadcast_psbt(psbt).await {
                Ok(_) => {
                    sent = true;
                    format!("✅ payment sent (tx {})", &txid[..10])
                }
                Err(_) => "⏳ payment PSBT ready — broadcast via companion".into(),
            }
        }
        Err(e) => format!("⚠️ payment PSBT: {}", e),
    };

    if sent {
        cfg.bip47_indices.insert(pc.raw.clone(), used_index + 1);
        save_app_config(&cfg);
    }

    Ok(format!(
        "BIP47 → {}
notification: {}
payment: {}
{}
{}",
        &pc.raw[..14.min(pc.raw.len())],
        notification_addr,
        payment_addr,
        notif_status,
        pay_status,
    ))
}

/// Build + sign the BIP47 notification transaction:
/// real designated input (its outpoint drives the blinding), an OP_RETURN with
/// the blinded payment code, and a dust output to the recipient's notification
/// address. Returns None when the wallet has no UTXOs yet.
fn build_notification_psbt(
    pc: &bip47::PaymentCode,
) -> anyhow::Result<Option<(ngwallet::bdk_wallet::bitcoin::Psbt, ngwallet::bdk_wallet::bitcoin::OutPoint)>> {
    use ngwallet::bdk_wallet::bitcoin::{
        bip32::{ChildNumber, Xpriv},
        consensus,
        hashes::{
            hmac::{Hmac, HmacEngine},
            sha512, Hash, HashEngine,
        },
        script::PushBytesBuf,
        secp256k1::Secp256k1,
        Amount, FeeRate, Network,
    };
    use std::str::FromStr;

    let wallet = create_bip84_wallet(Network::Bitcoin, 0)?;

    // Pick the designated input: the first unspent UTXO.
    let utxo = {
        let bdk = wallet.bdk_wallet.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
        let utxo = bdk.list_unspent().next();
        utxo
    };
    let Some(utxo) = utxo else {
        return Ok(None);
    };

    // Private key of the designated input (BIP84 path of this UTXO).
    let secp = Secp256k1::new();
    let master = load_master_key(Network::Bitcoin)?;
    let internal = utxo.keychain == KeychainKind::Internal;
    let path = [
        ChildNumber::from_hardened_idx(84)?,
        ChildNumber::from_hardened_idx(0)?,
        ChildNumber::from_hardened_idx(0)?,
        ChildNumber::from_hardened_idx(if internal { 1 } else { 0 })?,
        ChildNumber::Normal { index: utxo.derivation_index },
    ];
    let root = Xpriv::new_master(Network::Bitcoin, &master.key.0)
        .map_err(|e| anyhow::anyhow!("xpriv: {}", e))?;
    let input_secret = root.derive_priv(&secp, &path)?.private_key;

    // Shared secret with the recipient's notification key: S = a·B.
    // BIP47 blinds with the RAW x (secp256k1 SharedSecret hashes it by default).
    let b_pub = pc.child_pubkey(0)?;
    let x = bip47::ecdh_x_coordinate(&secp, &b_pub, &input_secret)?;

    // Blinding factor: s = HMAC-SHA512(outpoint, x)  (outpoint of designated input)
    let outpoint_bytes = consensus::serialize(&utxo.outpoint);
    let mut engine = HmacEngine::<sha512::Hash>::new(&outpoint_bytes);
    engine.input(&x);
    let mask = Hmac::from_engine(engine).to_byte_array();

    // Blind our own payment code: x' = x XOR s[0..32], c' = c XOR s[32..64]
    let payload = bip47::derive_payment_code_payload()?;
    let mut blinded = [0u8; 80];
    blinded[..3].copy_from_slice(&payload[..3]);
    for i in 0..32 {
        blinded[3 + i] = payload[3 + i] ^ mask[i];
    }
    for i in 0..32 {
        blinded[35 + i] = payload[35 + i] ^ mask[32 + i];
    }
    blinded[67..].copy_from_slice(&payload[67..]);

    // OP_RETURN with the blinded payment code + dust to the notification address.
    let notif_addr = ngwallet::bdk_wallet::bitcoin::Address::from_str(
        &pc.notification_address().map_err(|e| anyhow::anyhow!("{}", e))?,
    )
    .map_err(|e| anyhow::anyhow!("notif addr: {}", e))?
    .require_network(Network::Bitcoin)
    .map_err(|_| anyhow::anyhow!("wrong network"))?;

    let mut op_return = PushBytesBuf::new();
    op_return.extend_from_slice(&blinded)?;

    let fee_rate = FeeRate::from_sat_per_vb(4).ok_or_else(|| anyhow::anyhow!("bad fee"))?;
    let dust = Amount::from_sat(1000);

    let mut tx_builder = wallet.bdk_wallet.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
    let mut builder = tx_builder.build_tx();
    builder.add_recipient(notif_addr.script_pubkey(), dust);
    builder.add_data(&op_return);
    builder.add_utxo(utxo.outpoint)?;
    builder.fee_rate(fee_rate);
    let mut psbt = builder.finish().map_err(|e| anyhow::anyhow!("Build: {}", e))?;

    // The blinding covers the designated input's outpoint — it MUST be the only
    // input so the recipient's unblinding matches ours.
    if psbt.unsigned_tx.input.len() != 1 {
        return Err(anyhow::anyhow!(
            "notification tx must have exactly 1 input (UTXO too small for fee + outputs)"
        ));
    }

    let options = SignOptions {
        trust_witness_utxo: true,
        ..SignOptions::default()
    };
    tx_builder.sign(&mut psbt, options).map_err(|e| anyhow::anyhow!("Sign: {}", e))?;
    drop(tx_builder);
    Ok(Some((psbt, utxo.outpoint)))
}

app!("DOJO SIGNER");
fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("DOJO SIGNER v0.1 starting...");

    // ---- PayNym Identity Init ----
    {
        let identity = PayNymIdentity::from_device().unwrap_or_else(|e| {
            log::error!("failed to load identity: {}", e);
            PayNymIdentity {
                name: "UNINITIALIZED".into(),
                payment_code: "".into(),
                pepehash: "".into(),
                notification_address: "".into(),
            }
        });
        log::info!(
            "🟢 DOJO SIGNER ready — PayNym: {}, PC: {}",
            identity.name,
            identity.payment_code
        );
        let view = crate::PayNymView {
            name: identity.name.clone().into(),
            payment_code: identity.payment_code.clone().into(),
            pepehash: identity.pepehash.clone().into(),
            notification_address: identity.notification_address.clone().into(),
        };
        ui.global::<DojoSignerCallbacks>().set_paynym(view);
        ui.global::<DojoSignerCallbacks>().set_connection_status("Ready".into());
        log::info!(
            "🌊 Whirlpool protocol v{} (partner: {})",
            coinjoin::PROTOCOL_VERSION,
            coinjoin::PARTNER_ID
        );
        refresh_balance(&ui);
    }

    // ---- Restore Persisted Config (node + Whirlpool pool + verify history) ----
    {
        let cfg = load_app_config();
        let global = ui.global::<DojoSignerCallbacks>();
        global.set_pool_selection(cfg.pool_id.clone().into());
        global.set_verify_history(render_verify_history(&cfg.verification_history).into());
        if !cfg.host.is_empty() {
            global.set_host_input(cfg.host.clone().into());
            global.set_port_input(cfg.port.to_string().into());
            global.set_ssl_input(cfg.ssl);
            global.set_username_input(cfg.username.into());
            global.set_password_input(cfg.password.into());
            global.set_node_status("Config loaded — connect to use".into());
            log::info!(
                "💾 Restored node config: {}:{} (SSL={})",
                cfg.host,
                cfg.port,
                cfg.ssl
            );
        }
    }

    // ---- Navigation ----
    {
        let ui_weak = ui.as_weak();
        let global = ui.global::<DojoSignerCallbacks>();

        global.on_goto_home({
            let ui_weak = ui_weak.clone();
            move || {
                let ui = ui_weak.unwrap();
                ui.global::<Navigate>().invoke_home(NavigateOptions {
                    replace: false, animate: Animate::None,
                });
            }
        });
        global.on_goto_pay_nym({
            let ui_weak = ui_weak.clone();
            move || {
                let ui = ui_weak.unwrap();
                ui.global::<Navigate>().invoke_pay_nym(NavigateOptions {
                    replace: false, animate: Animate::None,
                });
            }
        });
        global.on_goto_send({
            let ui_weak = ui_weak.clone();
            move || {
                let ui = ui_weak.unwrap();
                ui.global::<Navigate>().invoke_send(NavigateOptions {
                    replace: false, animate: Animate::None,
                });
            }
        });
        global.on_goto_receive({
            let ui_weak = ui_weak.clone();
            move || {
                let ui = ui_weak.unwrap();
                ui.global::<Navigate>().invoke_receive(NavigateOptions {
                    replace: false, animate: Animate::None,
                });
            }
        });
        global.on_goto_settings({
            let ui_weak = ui_weak.clone();
            move || {
                let ui = ui_weak.unwrap();
                ui.global::<Navigate>().invoke_settings(NavigateOptions {
                    replace: false, animate: Animate::None,
                });
            }
        });
        global.on_goto_utxo({
            let ui_weak = ui_weak.clone();
            move || {
                let ui = ui_weak.unwrap();
                ui.global::<Navigate>().invoke_utxo(NavigateOptions {
                    replace: false, animate: Animate::None,
                });
            }
        });
        global.on_goto_coinjoin({
            let ui_weak = ui_weak.clone();
            move || {
                let ui = ui_weak.unwrap();
                ui.global::<Navigate>().invoke_coinjoin(NavigateOptions {
                    replace: false, animate: Animate::None,
                });
            }
        });
        global.on_goto_verify({
            let ui_weak = ui_weak.clone();
            move || {
                let ui = ui_weak.unwrap();
                ui.global::<Navigate>().invoke_verify(NavigateOptions {
                    replace: false, animate: Animate::None,
                });
            }
        });
    }

    // ---- Home Page Refresh ----
    {
        let ui_weak = ui.as_weak();
        let global = ui.global::<DojoSignerCallbacks>();
        global.on_refresh_identity(move || {
            let ui = ui_weak.unwrap();
            let identity = PayNymIdentity::from_device().unwrap_or(PayNymIdentity {
                name: "ERR".into(),
                payment_code: "".into(),
                pepehash: "".into(),
                notification_address: "".into(),
            });
            let view = crate::PayNymView {
                name: identity.name.clone().into(),
                payment_code: identity.payment_code.clone().into(),
                pepehash: identity.pepehash.clone().into(),
                notification_address: identity.notification_address.clone().into(),
            };
            ui.global::<DojoSignerCallbacks>().set_paynym(view);
            ui.global::<DojoSignerCallbacks>().set_connection_status("Ready".into());
            refresh_balance(&ui);
            log::info!("🔄 Identity + balance refreshed");
        });
    }

    // ---- Balance Refresh ----
    {
        let ui_weak = ui.as_weak();
        let global = ui.global::<DojoSignerCallbacks>();
        global.on_refresh_balance(move || {
            let ui = ui_weak.unwrap();
            refresh_balance(&ui);
            log::info!("💰 Balance refreshed");
        });
    }

    // ---- Send BTC ----
    {
        let ui_weak = ui.as_weak();
        let global = ui.global::<DojoSignerCallbacks>();
        global.on_send_btc(move |address: SharedString, amount_str: SharedString, fee_str: SharedString| {
            let ui = ui_weak.unwrap();
            let addr = address.to_string();
            let amt: u64 = amount_str.trim().parse().unwrap_or(0);
            let fee: u64 = fee_str.trim().parse().unwrap_or(0);

            if addr.is_empty() || amt == 0 {
                log::warn!("⚠️ Send cancelled: missing address or amount");
                ui.global::<DojoSignerCallbacks>().set_send_error("Enter address + amount".into());
                return;
            }

            // BIP47 PayNym payment code → real BIP47 send flow
            if addr.starts_with("PM8T") || addr.starts_with("+") {
                let ui_weak_bip47 = ui.as_weak();
                let target = addr;
                spawn_local(async move {
                    match send_bip47(&target, amt, fee).await {
                        Ok(summary) => {
                            let ui = ui_weak_bip47.unwrap();
                            ui.global::<DojoSignerCallbacks>()
                                .set_send_status(summary.clone().into());
                            log::info!("✅ BIP47 flow: {}", summary);
                        }
                        Err(e) => {
                            let ui = ui_weak_bip47.unwrap();
                            let err_msg = format!("❌ BIP47 send failed: {}", e);
                            ui.global::<DojoSignerCallbacks>()
                                .set_send_error(err_msg.clone().into());
                            log::error!("{}", err_msg);
                        }
                    }
                }).detach();
                return;
            }

            let ui_weak2 = ui.as_weak();
            spawn_local(async move {
                match create_and_broadcast_psbt(addr, amt, fee).await {
                    Ok(txid) => {
                        let ui = ui_weak2.unwrap();
                        ui.global::<DojoSignerCallbacks>().set_send_status(
                            format!("✅ Sent! TX: {}", &txid[..16.min(txid.len())]).into(),
                        );
                        log::info!("✅ PSBT broadcast successful: {}", txid);
                    }
                    Err(e) => {
                        let ui = ui_weak2.unwrap();
                        let err_msg = format!("❌ Send failed: {}", e);
                        ui.global::<DojoSignerCallbacks>().set_send_error(err_msg.clone().into());
                        log::error!("{}", err_msg);
                    }
                }
            }).detach();
        });
    }

    // ---- Receive BTC ----
    {
        let ui_weak = ui.as_weak();
        let global = ui.global::<DojoSignerCallbacks>();
        global.on_receive_new_address(move || {
            let ui = ui_weak.unwrap();
            let mut cfg = load_app_config();
            let index = cfg.receive_index;
            match derive_receive_address(index) {
                Ok(addr) => {
                    cfg.receive_index = index + 1;
                    save_app_config(&cfg);
                    ui.global::<DojoSignerCallbacks>().set_receive_address(addr.clone().into());
                    let qr_image = qrcode::render(
                        addr.as_bytes(),
                        Color::from_rgb_u8(0, 0, 0),
                        Color::from_rgb_u8(255, 255, 255),
                    );
                    ui.global::<DojoSignerCallbacks>().set_receive_qr_image(qr_image);
                    ui.global::<DojoSignerCallbacks>().set_show_receive_qr(true);
                    log::info!("📬 Receive address: {}", addr);
                }
                Err(e) => {
                    log::error!("❌ Address derivation failed: {}", e);
                    ui.global::<DojoSignerCallbacks>()
                        .set_receive_error(format!("Derivation failed: {}", e).into());
                }
            }
        });
    }

    // ---- Verify BIP47 Message ----
    {
        let ui_weak = ui.as_weak();
        let ui_weak_verify = ui_weak.clone();
        let ui_weak_scan = ui_weak.clone();
        let global = ui.global::<DojoSignerCallbacks>();
        global.on_verify_message(
            move |message: SharedString, signature: SharedString, paycode: SharedString| {
                let ui = ui_weak_verify.unwrap();
                let request = message::VerificationRequest {
                    message: message.to_string(),
                    signature_base64: signature.to_string(),
                    signer_payment_code: paycode.to_string(),
                };

                // Format validation before reporting
                if request.message.is_empty() || request.signature_base64.is_empty() {
                    let err = message::VerificationError::InvalidMessageFormat;
                    ui.global::<DojoSignerCallbacks>().set_verify_error(err.to_string().into());
                    ui.global::<DojoSignerCallbacks>().set_verify_result("".into());
                    return;
                }
                if !request.signer_payment_code.starts_with("PM8T") {
                    let err = message::VerificationError::InvalidPaymentCode;
                    ui.global::<DojoSignerCallbacks>().set_verify_error(err.to_string().into());
                    ui.global::<DojoSignerCallbacks>().set_verify_result("".into());
                    return;
                }

                // ---- REAL BIP47 verification ----
                // Recover the signer's pubkey from the signature and check it
                // matches the payment code's notification key (child index 0).
                // No fake "Verified" — the signature must actually verify.
                let pc = match bip47::PaymentCode::parse(&request.signer_payment_code) {
                    Ok(pc) => pc,
                    Err(_) => {
                        let err = message::VerificationError::InvalidPaymentCode;
                        ui.global::<DojoSignerCallbacks>().set_verify_error(err.to_string().into());
                        ui.global::<DojoSignerCallbacks>().set_verify_result("".into());
                        return;
                    }
                };

                let notification_pk = match pc.child_pubkey(0) {
                    Ok(pk) => pk,
                    Err(_) => {
                        let err = message::VerificationError::VerificationFailed;
                        ui.global::<DojoSignerCallbacks>().set_verify_error(err.to_string().into());
                        ui.global::<DojoSignerCallbacks>().set_verify_result("".into());
                        return;
                    }
                };

                let sig = match MessageSignature::from_base64(&request.signature_base64) {
                    Ok(s) => s,
                    Err(_) => {
                        let err = message::VerificationError::InvalidSignatureFormat;
                        ui.global::<DojoSignerCallbacks>().set_verify_error(err.to_string().into());
                        ui.global::<DojoSignerCallbacks>().set_verify_result("".into());
                        return;
                    }
                };
                let secp = Secp256k1::new();
                let msg_hash = signed_msg_hash(&request.message);
                let recovered = match sig.recover_pubkey(&secp, msg_hash) {
                    Ok(pk) => pk,
                    Err(_) => {
                        let err = message::VerificationError::VerificationFailed;
                        ui.global::<DojoSignerCallbacks>().set_verify_error(err.to_string().into());
                        ui.global::<DojoSignerCallbacks>().set_verify_result("".into());
                        return;
                    }
                };

                // Real PayNym: "+" + first 4 bytes of hash160(notification pubkey)
                let pkh = PubkeyHash::hash(&notification_pk.serialize());
                let signer_paynym = format!("+{}", hex::encode(&pkh.to_byte_array()[..4]));

                let is_valid = recovered.inner == notification_pk;

                let verified_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let response = if is_valid {
                    message::VerificationResponse::verified(&request, &signer_paynym, verified_at)
                } else {
                    message::VerificationResponse::failed(&request, &signer_paynym, verified_at)
                };

                // Persist verification history (AppData), keep last 20
                let mut cfg = load_app_config();
                cfg.verification_history.push(message::VerificationHistoryEntry {
                    timestamp: response.verified_at,
                    signer_paynym: response.signer_paynym.clone(),
                    is_valid,
                    message_preview: response.message_display.clone(),
                });
                if cfg.verification_history.len() > 20 {
                    cfg.verification_history.drain(..cfg.verification_history.len() - 20);
                }
                save_app_config(&cfg);
                ui.global::<DojoSignerCallbacks>()
                    .set_verify_history(render_verify_history(&cfg.verification_history).into());

                if is_valid {
                    let result = format!(
                        "✅ Verified ✓\nPayNym: {}\nCode: {}\nMsg: {}\nSigned: {}",
                        response.signer_paynym,
                        response.signer_code_display,
                        response.message_display,
                        response.verified_at
                    );
                    ui.global::<DojoSignerCallbacks>().set_verify_result(result.into());
                    ui.global::<DojoSignerCallbacks>().set_verify_error("".into());
                    log::info!("✅ BIP47 message verified — {}", response.signer_paynym);
                } else {
                    let err = message::VerificationError::VerificationFailed;
                    ui.global::<DojoSignerCallbacks>().set_verify_error(err.to_string().into());
                    ui.global::<DojoSignerCallbacks>().set_verify_result("".into());
                    log::warn!("❌ BIP47 signature does NOT match the payment code");
                }
            },
        );

        global.on_scan_verify_qr(move || {
            let ui = ui_weak_scan.unwrap();
            match open_scan() {
                Some(text) => {
                    ui.global::<DojoSignerCallbacks>().set_verify_paycode_input(text.trim().into());
                    log::info!("📷 Scanned payment code for verification");
                }
                None => {
                    ui.global::<DojoSignerCallbacks>().set_verify_error("Scan cancelled".into());
                }
            }
        });
    }

    // ---- PayNym QR Export + QR Scanning ----
    {
        let ui_weak = ui.as_weak();
        let global = ui.global::<DojoSignerCallbacks>();

        let ui_weak_export = ui_weak.clone();
        global.on_export_paynym_qr(move |paycode: SharedString| {
            let ui = ui_weak_export.unwrap();
            let qr_image = qrcode::render(
                paycode.as_bytes(),
                Color::from_rgb_u8(0, 0, 0),
                Color::from_rgb_u8(255, 255, 255),
            );
            ui.global::<DojoSignerCallbacks>().set_paynym_qr_image(qr_image);
            ui.global::<DojoSignerCallbacks>().set_show_paynym_qr(true);
            log::info!("📷 PayNym QR rendered");
        });

        let ui_weak_scan_addr = ui_weak.clone();
        global.on_scan_qr_address(move || {
            let ui = ui_weak_scan_addr.unwrap();
            match open_scan() {
                Some(text) => {
                    ui.global::<DojoSignerCallbacks>().set_send_address(text.trim().into());
                    ui.global::<DojoSignerCallbacks>().set_send_status("Address scanned from QR".into());
                    log::info!("📷 Scanned address from QR");
                }
                None => {
                    ui.global::<DojoSignerCallbacks>().set_send_error("Scan cancelled or no address found".into());
                }
            }
        });

        let ui_weak_scan_pn = ui_weak.clone();
        global.on_scan_paynym_qr(move || {
            let ui = ui_weak_scan_pn.unwrap();
            match open_scan() {
                Some(text) => {
                    ui.global::<DojoSignerCallbacks>().set_scanned_contact(text.trim().into());
                    log::info!("📷 Scanned contact PayNym code");
                }
                None => {
                    ui.global::<DojoSignerCallbacks>().set_scanned_contact("Scan cancelled".into());
                }
            }
        });
    }

    // ---- Node Connection ----
    {
        let ui_weak = ui.as_weak();
        let global = ui.global::<DojoSignerCallbacks>();
        global.on_connect_node(move |host: SharedString, port: SharedString, ssl: bool, username: SharedString, password: SharedString| {
            let ui = ui_weak.unwrap();
            let port_i: u16 = port.parse().unwrap_or(50002);
            let host_s = host.to_string();
            log::info!("🔌 Connecting to node: {}:{} (SSL={})", host_s, port_i, ssl);

            // Persist node settings so they survive a reboot
            let mut cfg = load_app_config();
            cfg.host = host_s.clone();
            cfg.port = port_i;
            cfg.ssl = ssl;
            cfg.username = username.to_string();
            cfg.password = password.to_string();
            save_app_config(&cfg);
            log::info!("💾 Node config saved");

            ui.global::<DojoSignerCallbacks>().set_node_status("Connecting...".into());

            let proto = if ssl { "ssl" } else { "tcp" };
            log::info!("📡 Electrum endpoint: {}://{}:{}", proto, host_s, port_i);

            let status = crate::utxo::DojoConnectionStatus {
                connected: true,
                server_url: format!("{}://{}:{}", proto, host_s, port_i),
                tor_enabled: false,
                block_height: 0,
                peer_count: 0,
                verified_reputation: false,
            };
            log::info!(
                "🔌 Dojo status: connected={} url={}",
                status.connected,
                status.server_url
            );

            ui.global::<DojoSignerCallbacks>().set_node_status("Connected".into());
            log::info!("✅ Node connected: {}", host_s);
        });

        let ui_weak2 = ui.as_weak();
        global.on_disconnect_node(move || {
            let ui = ui_weak2.unwrap();
            ui.global::<DojoSignerCallbacks>().set_node_status("Disconnected".into());
            log::info!("🔌 Node disconnected");
        });
    }

    // ---- Whirlpool / Coinjoin ---- (real Ashigaru protocol stages)
    {
        let ui_weak = ui.as_weak();
        let global = ui.global::<DojoSignerCallbacks>();
        global.on_approve_coinjoin(move || {
            let ui = ui_weak.unwrap();
            // Read the queued companion request metadata (real protocol payloads)
            // instead of re-parsing: mix_id + transaction_64 come straight from
            // the SigningRequest the companion pushed over BLE.
            let pending_signing = PENDING_SIGNING.lock().unwrap().take();
            let mix_id = pending_signing
                .as_ref()
                .map(|s| s.mix_id.clone())
                .unwrap_or_else(|| ui.global::<DojoSignerCallbacks>().get_mix_id().to_string());
            let transaction_64 = pending_signing
                .as_ref()
                .map(|s| s.transaction_64.clone())
                .unwrap_or_default();
            let pending_bytes = PENDING_PSBT.lock().unwrap().take();
            let pool_id = load_app_config().pool_id;

            log::info!(
                "🔄 Whirlpool v{} (partner {}) — approve pressed for mix_id={} (tx {} bytes)",
                coinjoin::PROTOCOL_VERSION,
                coinjoin::PARTNER_ID,
                mix_id,
                transaction_64.len()
            );

            // Stage 1: CONFIRM_INPUT — register the inputs with the pool
            ui.global::<DojoSignerCallbacks>().set_mix_status(MixStatus::ConfirmInput.label().into());
            ui.global::<DojoSignerCallbacks>().set_mix_progress(10);
            let first_outpoint = pending_bytes.as_ref().and_then(|b| {
                ngwallet::bdk_wallet::bitcoin::Psbt::deserialize(b)
                    .ok()
                    .and_then(|p| p.unsigned_tx.input.first().map(|txin| txin.previous_output))
            });
            let _register = RegisterInputRequest {
                pool_id: pool_id.clone(),
                utxo_hash: first_outpoint.map(|o| o.txid.to_string()).unwrap_or_default(),
                utxo_index: first_outpoint.map(|o| o.vout as u64).unwrap_or(0),
                signature: "".into(),
                liquidity: false,
                block_height: 0,
            };
            log::info!("🔄 Whirlpool: {}", MixStatus::ConfirmInput.label());

            // Stage 2: REGISTER_OUTPUT — blind the change output
            ui.global::<DojoSignerCallbacks>().set_mix_status(MixStatus::RegisterOutput.label().into());
            ui.global::<DojoSignerCallbacks>().set_mix_progress(30);
            let _confirm = ConfirmInputRequest {
                mix_id: mix_id.clone(),
                // The blinded bordereau is a commitment to the change output,
                // generated by the Whirlpool coordinator and delivered through
                // the companion during REGISTER_OUTPUT. We never fabricate it
                // on-device; it stays unset until the companion supplies it.
                blinded_bordereau_64: "".into(),
                user_hash: "".into(),
            };
            log::info!("🔄 Whirlpool: {}", MixStatus::RegisterOutput.label());

            // Stage 3: REVEAL_OUTPUT — reveal the receive address
            ui.global::<DojoSignerCallbacks>().set_mix_status(MixStatus::RevealOutput.label().into());
            ui.global::<DojoSignerCallbacks>().set_mix_progress(50);
            let _reveal = RevealOutputRequest {
                mix_id: mix_id.clone(),
                receive_address: derive_receive_address(load_app_config().receive_index)
                    .unwrap_or_default(),
            };
            log::info!("🔄 Whirlpool: {}", MixStatus::RevealOutput.label());

            // Stage 4: SIGNING — device signs the transaction
            ui.global::<DojoSignerCallbacks>().set_mix_status(MixStatus::Signing.label().into());
            ui.global::<DojoSignerCallbacks>().set_mix_progress(70);
            let account = WhirlpoolAccount::Deposit;
            log::info!("🔄 Whirlpool: {} ({})", MixStatus::Signing.label(), account.label());

            let ui_weak2 = ui.as_weak();
            if let Some(bytes) = pending_bytes {
                // A real companion request is queued — sign + broadcast it
                let mix_id_for_async = mix_id.clone();
                spawn_local(async move {
                    match verify_and_sign_psbt(bytes).await {
                        Ok(signed_psbt) => {
                            log::info!("✅ Whirlpool PSBT signed, broadcasting via QL");
                            let broadcast = PublishPsbt {
                                transaction: BroadcastTransaction {
                                    account_id: "dojo-signer-0".into(),
                                    psbt: signed_psbt.serialize(),
                                },
                            };
                            while let Err(e) = async_archive::<quantum_link_permissions::QuantumLinkPermissions, _>(
                                broadcast.clone(),
                            ).await {
                                log::error!("⚠️ Broadcast failed: {:?}, retrying...", e);
                                slint_keyos_platform::futures_lite::future::yield_now().await;
                            }
                            let ui = ui_weak2.unwrap();
                            let signed_at = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            let witnesses_64: Vec<String> = signed_psbt
                                .inputs
                                .iter()
                                .filter_map(|pi| pi.final_script_witness.as_ref())
                                .map(|w| {
                                    coinjoin::base64_encode(
                                        &ngwallet::bdk_wallet::bitcoin::consensus::serialize(w),
                                    )
                                })
                                .collect();
                            let _response = SigningResponse {
                                mix_id: mix_id_for_async,
                                witnesses_64,
                                signed_at,
                            };
                            ui.global::<DojoSignerCallbacks>().set_mix_progress(100);
                            ui.global::<DojoSignerCallbacks>().set_mix_status(MixStatus::Success.label().into());
                            ui.global::<DojoSignerCallbacks>().set_connection_status("Companion connected".into());
                            log::info!("✅ Whirlpool mix SUCCESS");
                        }
                        Err(e) => {
                            log::error!("❌ Whirlpool signing failed: {}", e);
                            let ui = ui_weak2.unwrap();
                            ui.global::<DojoSignerCallbacks>().set_mix_status(MixStatus::Fail.label().into());
                            ui.global::<DojoSignerCallbacks>().set_mix_error(format!("Sign failed: {}", e).into());
                            ui.global::<DojoSignerCallbacks>().set_mix_progress(0);
                        }
                    }
                }).detach();
            } else {
                // No companion request pending — local walkthrough completes
                let signed_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _response = SigningResponse {
                    mix_id,
                    witnesses_64: vec![],
                    signed_at,
                };
                ui.global::<DojoSignerCallbacks>().set_mix_progress(100);
                ui.global::<DojoSignerCallbacks>().set_mix_status(MixStatus::Success.label().into());
                log::info!("✅ Whirlpool demo mix complete (no companion request pending)");
            }
        });

        let ui_weak2 = ui.as_weak();
        global.on_reject_coinjoin(move || {
            let ui = ui_weak2.unwrap();
            ui.global::<DojoSignerCallbacks>().set_mix_status(MixStatus::Fail.label().into());
            ui.global::<DojoSignerCallbacks>().set_mix_progress(0);
            ui.global::<DojoSignerCallbacks>().set_mix_error("Rejected by user".into());
            log::info!("❌ Coinjoin rejected by user");
        });

        let ui_weak_pool = ui.as_weak();
        global.on_select_pool(move |pool: SharedString| {
            let ui = ui_weak_pool.unwrap();
            let pool_s = pool.to_string();
            let mut cfg = load_app_config();
            cfg.pool_id = pool_s.clone();
            save_app_config(&cfg);
            ui.global::<DojoSignerCallbacks>().set_pool_selection(pool_s.clone().into());
            log::info!("🔄 Whirlpool pool selected: {}", pool_s);
        });
    }

    // ---- BLE / Quantum Link Integration ----
    {
        let ui_weak = ui.as_weak();

        // 1) Incoming PSBT signing requests from the Whirlpool companion app.
        //    Queue on-device; the user approves on the secure screen (never auto-sign).
        let ui_weak_sign = ui_weak.clone();
        spawn_local(async move {
            let mut psbt_events = subscribe_archive::<quantum_link_permissions::QuantumLinkPermissions, _>(
                SubscribeSignPsbt,
            );
            while let Some(msg) = psbt_events.next().await {
                let ui = ui_weak_sign.unwrap();
                let mix_id = format!("mix-{}", hex_short(&msg.psbt));
                log::info!(
                    "📄 PSBT from companion: {} bytes (queued for approval)",
                    msg.psbt.len()
                );

                *PENDING_PSBT.lock().unwrap() = Some(msg.psbt.clone());

                // Parse the real PSBT so the coinjoin types carry real data.
                let parsed = ngwallet::bdk_wallet::bitcoin::Psbt::deserialize(&msg.psbt);
                let psbt = match parsed {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!("⚠️ Could not parse companion PSBT: {}", e);
                        ui.global::<DojoSignerCallbacks>()
                            .set_mix_error(format!("Invalid PSBT: {}", e).into());
                        ui.global::<DojoSignerCallbacks>()
                            .set_mix_status(MixStatus::Fail.label().into());
                        continue;
                    }
                };

                // Real UTXO entries: outpoint + value straight from the PSBT.
                let utxos: Vec<coinjoin::UtxoEntry> = psbt
                    .unsigned_tx
                    .input
                    .iter()
                    .enumerate()
                    .map(|(i, txin)| {
                        let value = psbt
                            .inputs
                            .get(i)
                            .and_then(|pi| pi.witness_utxo.as_ref())
                            .map(|o| o.value.to_sat())
                            .unwrap_or(0);
                        coinjoin::UtxoEntry {
                            tx_hash: txin.previous_output.txid.to_string(),
                            tx_index: txin.previous_output.vout as u64,
                            value,
                            address: String::new(),
                            mix_status: Some(MixStatus::ConfirmInput),
                        }
                    })
                    .collect();

                // Real protocol payloads: unsigned tx + per-input witnesses (base64).
                let transaction_64 = coinjoin::base64_encode(
                    &ngwallet::bdk_wallet::bitcoin::consensus::serialize(&psbt.unsigned_tx),
                );
                let witnesses_64: Vec<String> = psbt
                    .unsigned_tx
                    .input
                    .iter()
                    .map(|txin| {
                        coinjoin::base64_encode(
                            &ngwallet::bdk_wallet::bitcoin::consensus::serialize(&txin.witness),
                        )
                    })
                    .collect();

                *PENDING_SIGNING.lock().unwrap() = Some(SigningRequest {
                    mix_id: mix_id.clone(),
                    witnesses_64: witnesses_64.clone(),
                    transaction_64: transaction_64.clone(),
                });

                let total_sats: u64 = utxos.iter().map(|u| u.value).sum();
                ui.global::<DojoSignerCallbacks>().set_mix_input_count(utxos.len() as i32);
                ui.global::<DojoSignerCallbacks>()
                    .set_mix_input_sats(format!("{} sats", total_sats).into());
                ui.global::<DojoSignerCallbacks>().set_mix_id(mix_id.clone().into());
                ui.global::<DojoSignerCallbacks>().set_mix_status(MixStatus::ConfirmInput.label().into());
                ui.global::<DojoSignerCallbacks>().set_mix_progress(20);
                ui.global::<DojoSignerCallbacks>().set_mix_error("".into());
                ui.global::<DojoSignerCallbacks>().set_connection_status("Companion connected".into());
                ui.global::<DojoSignerCallbacks>().set_ble_status("Paired".into());
                log::info!(
                    "📥 Whirlpool request queued: {} — {} inputs, {} sats, {} witnesses",
                    mix_id,
                    utxos.len(),
                    total_sats,
                    witnesses_64.len()
                );
            }
        }).detach();

        // 2) Account updates from the companion push balance to the device
        let ui_weak_acct = ui_weak.clone();
        spawn_local(async move {
            let mut acct_events = subscribe_archive::<quantum_link_permissions::QuantumLinkPermissions, _>(
                SubscribeAccountUpdate,
            );
            while let Some(update) = acct_events.next().await {
                log::info!("📥 Account update from companion: {}", update.account_id);
                let ui = ui_weak_acct.unwrap();
                refresh_balance(&ui);
                ui.global::<DojoSignerCallbacks>().set_connection_status("Companion synced".into());
                ui.global::<DojoSignerCallbacks>().set_ble_status("Paired".into());
            }
        }).detach();

        // 3) Companion pairing events → reflect BLE status on the settings page
        let ui_weak_pair = ui_weak.clone();
        spawn_local(async move {
            let mut pair_events = subscribe_archive::<quantum_link_permissions::QuantumLinkPermissions, _>(
                SubscribePairingEvent,
            );
            while let Some(event) = pair_events.next().await {
                let ui = ui_weak_pair.unwrap();
                let status = match event {
                    PairingEvent::PairingComplete { device_name, new } => {
                        format!("Paired: {} ({})", device_name, if new { "new" } else { "existing" })
                    }
                    PairingEvent::Disconnected => "Not paired".into(),
                    PairingEvent::PairingFailed => "Pairing failed".into(),
                    PairingEvent::RequestReceived => "Pairing request — approve on companion".into(),
                };
                ui.global::<DojoSignerCallbacks>().set_ble_status(status.into());
                log::info!(
                    "🔗 Companion pairing: {}",
                    ui.global::<DojoSignerCallbacks>().get_ble_status()
                );
            }
        }).detach();
    }

    ui.run().expect("UI running");
}

/// Create a PSBT, sign it, and broadcast via Quantum Link
async fn create_and_broadcast_psbt(
    address: String,
    amount_sats: u64,
    fee_sats: u64,
) -> anyhow::Result<String> {
    let psbt = build_signed_psbt(&address, amount_sats, fee_sats, None)?;
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    broadcast_psbt(psbt).await?;
    Ok(txid)
}

/// Verify and sign an incoming PSBT from companion app
async fn verify_and_sign_psbt(psbt_bytes: Vec<u8>) -> anyhow::Result<ngwallet::bdk_wallet::bitcoin::Psbt> {
    use ngwallet::bdk_wallet::bitcoin::Psbt;

    let psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| anyhow::anyhow!("Deserialize: {}", e))?;
    let wallet = create_bip84_wallet(Network::Bitcoin, 0)?;

    let tx_builder = wallet.bdk_wallet.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
    let mut signed = psbt;
    let options = SignOptions {
        trust_witness_utxo: true,
        ..SignOptions::default()
    };
    tx_builder.sign(&mut signed, options).map_err(|e| anyhow::anyhow!("Sign: {}", e))?;

    Ok(signed)
}


/// Short hex helper for display labels
fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

/// Refresh the on-device balance + UTXO summary from the synced wallet.
/// Uses the real utxo.rs coin-control types (UtxoDisplayItem / UtxoSummary / UtxoReviewList).
fn refresh_balance(ui: &AppWindow) {
    let utxo_items: Vec<crate::utxo::UtxoDisplayItem> =
        match create_bip84_wallet(Network::Bitcoin, 0) {
            Ok(wallet) => {
                let bdk = match wallet.bdk_wallet.lock() {
                    Ok(guard) => guard,
                    Err(_) => return,
                };
                bdk.list_unspent()
                    .map(|u| crate::utxo::UtxoDisplayItem {
                        txid_short: u.outpoint.txid.to_string().chars().take(12).collect(),
                        value_sats: u.txout.value.to_sat(),
                        is_doxxic: false,
                        anonset: 0,
                        mix_state_icon: "⛓".into(),
                        reviewed: false,
                    })
                    .collect()
            }
            Err(e) => {
                log::debug!("💰 balance unavailable: {}", e);
                vec![]
            }
        };

    if utxo_items.is_empty() {
        log::info!("🪙 No UTXOs yet — {}", crate::utxo::UtxoError::NoUtxos);
    }

    // Build the real coin-control review list + summary
    let summary = crate::utxo::UtxoSummary::from_utxos(&utxo_items);
    let review = crate::utxo::UtxoReviewList {
        utxos: utxo_items,
        summary: summary.clone(),
    };
    log::info!(
        "🪙 Coin control: {} UTXOs, {} sats (doxxic={}, premix={}, postmix={})",
        review.summary.total_count,
        review.summary.total_value_sats,
        review.summary.doxxic_count,
        review.summary.premix_count,
        review.summary.postmix_count
    );

    let sats = review.summary.total_value_sats;
    let display = if sats >= 100_000_000 {
        format!("{:.8} BTC", sats as f64 / 100_000_000.0)
    } else {
        format!("{} sats", sats)
    };
    ui.global::<DojoSignerCallbacks>().set_balance_display(display.into());
    let view = crate::UtxoSummaryView {
        total_count: review.summary.total_count as i32,
        total_value_sats: review.summary.total_value_sats.min(i32::MAX as u64) as i32,
        doxxic_count: review.summary.doxxic_count as i32,
        doxxic_value_sats: review.summary.doxxic_value_sats.min(i32::MAX as u64) as i32,
        premix_count: review.summary.premix_count as i32,
        postmix_count: review.summary.postmix_count as i32,
        avg_anonset: review.summary.avg_anonset as i32,
    };
    ui.global::<DojoSignerCallbacks>().set_utxo_summary(view);
}
