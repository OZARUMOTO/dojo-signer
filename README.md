# ⛩ DOJO SIGNER

**Real BIP47 PayNym + Whirlpool coinjoin signing on the Foundation Passport Prime**

DOJO SIGNER is a [KeyOS](https://docs.foundation.xyz/) app for the [Foundation Passport Prime](https://foundation.xyz/) that turns your trusted hardware device into:

- A **real BIP47 PayNym identity generator** — payment code, notification address, and ECDH payment addresses derived from the device seed
- A **real BIP47 message verifier** — recovers the signer's public key from the signature and checks it against the payment code's notification key
- A **Whirlpool coinjoin signing device** — parses real PSBTs from a companion app over Quantum Link BLE, lets you review inputs on the secure display, and signs with the secure element
- A **UTXO coin control console** — real balance and unspent outputs from the wallet

Every cryptographic derivation in this app is verified byte-for-byte against the **official Samourai BIP47 test vectors** (see [Testing](#-testing)).

---

## 🎬 Preview

**Full walkthrough (screen recording):**

<p align="center">
  <img src="docs/screenshots/demo-walkthrough.gif" width="320" alt="DOJO SIGNER — end-to-end walkthrough"/>
</p>

**Screenshots** (captured in the KeyOS hosted simulator):

| Screen | Capture |
|--------|---------|
| **Home** — PayNym identity + balance | <img src="docs/screenshots/home.png" width="220" alt="DOJO SIGNER home screen"/> |
| **PayNym** — payment code + notification address | <img src="docs/screenshots/paynym-derivation.png" width="220" alt="PayNym derivation"/> |
| **Send** — BIP47 / on-chain | <img src="docs/screenshots/send-btc.png" width="220" alt="Send BTC"/> |
| **Receive** — real BIP84 address + QR | <img src="docs/screenshots/receive-btc.png" width="220" alt="Receive BTC"/> |
| **Settings** — node config + BLE | <img src="docs/screenshots/node-settings.png" width="220" alt="Node settings"/> |
| **UTXO** — coin control | <img src="docs/screenshots/utxo-control.png" width="220" alt="UTXO coin control"/> |
| **Coinjoin** — Whirlpool signing + pool selection | <img src="docs/screenshots/whirlpool-signing.png" width="220" alt="Whirlpool coinjoin signing"/> |
| **Verify** — BIP47 message verifier + history | <img src="docs/screenshots/bip47-verifier.png" width="220" alt="BIP47 message verifier"/> |

> These are raw simulator captures — no device frames, as requested.
>
> They cover the main flows, including **PayNym derivation**, **Whirlpool signing**, **UTXO coin control**, and the **BIP47 message verifier**.

---

## 🖥️ Interface

Terminal-styled secure display — black background, red monospace text:

```
  >> DOJO_SIGNER
  $ 🟢 Ready — PayNym: +ozarumoto, PC: PM8T...
  
  # PayNym Identity
  +----------------------------------+
  | 🐸 name: +ozarumoto              |
  |    notification: 1xxxxx...       |
  |    PM8T...code...                |
  | [show_code] [scan_qr] [refresh]  |
  +----------------------------------+
  
  [utxo]   [coinjoin]   [verify]
  [send]   [receive]    [settings]
```

---

## ✨ What It Does (100% real — no mock data)

### 🆔 BIP47 PayNym on Hardware
- Payment code derived from the **device seed** at `m/47'/0'/0'` — the seed **never leaves the device**
- Full base58check encoding with checksum validation (`PaymentCode::parse` rejects garbage input)
- **Notification address** (P2PKH of child index 0) — shown on the PayNym page
- Real **BIP47 payment addresses** via ECDH: `S = a·B`, `s = SHA256(Sx_raw)`, `B' = B + sG` — with index bumping on invalid scalars per the spec
- PayNym QR export + QR scanning for contacts
- Identity persisted and restored on launch

### ✉️ BIP47 Send (built & signed on-device)
- Paste a `PM8T...` payment code → app detects first contact automatically
- Builds + signs the **notification transaction**: blinded OP_RETURN (`HMAC-SHA512(outpoint, x)` XOR blinding) + dust to the notification address
- Then builds + signs the payment to the ECDH-derived address
- **Double-spend protection**: the payment tx marks the notification's input `unspendable`, so the two can never collide
- **Stranded-funds protection**: if the notification tx can't be built, the payment is skipped with a clear message
- Per-recipient BIP47 index persisted only on success → failed sends re-derive the same address
- *Broadcasting the signed tx on-chain requires a connected Electrum node — see the roadmap.*

### ✅ BIP47 Message Verifier
- Paste or scan a message + base64 signature + sender payment code
- Reconstructs the signer's **notification key** (`child_pubkey(0)`)
- Recovers the public key from the signature (`MessageSignature::from_base64` + `recover_pubkey`)
- **✅ Verified ✓** only when the recovered key **actually matches** the notification key — no fake "verified"
- Real timestamps, verification history persisted to AppData and shown on the Verify page

### 🌀 Whirlpool Coinjoin Signing (over Quantum Link BLE)
Real `SigningRequest` handling — the protocol types come from the actual Ashigaru source:

```
1. REGISTER_INPUT   →  real pool selection (0.5/0.25/0.1/0.05/0.01 BTC) + real input outpoint
2. CONFIRM_INPUT    →  real mix_id + transaction payload
3. REVEAL_OUTPUT    →  real derived receive address
4. SIGNING          →  🔐 REVIEW ON SECURE DISPLAY 🔐
                       - Real PSBT parsed: inputs, values, witnesses
                       - Approve → device signs → returns real witnesses_64
                       - Reject → nothing leaves the device
5. SUCCESS / FAIL   →  broadcast via Quantum Link (PublishPsbt)
```

- Incoming PSBTs are parsed into **real UTXO entries** (outpoint txid:vout + `witness_utxo` value)
- `transaction_64` / `witnesses_64` are real base64 of the serialized unsigned tx + witnesses
- Coinjoin page shows **real input count + total sats** from the parsed PSBT
- BLE companion status + pairing events shown in Settings

### 🪙 UTXO Coin Control
- Real balance from `bdk_wallet` (`list_unspent`)
- Total count, total value, doxxic count, premix/postmix counts, average anonset
- Displayed in BTC or sats

### 🔗 Node Connection
- Electrum server settings: **host, port, SSL, username, password**
- Persisted to AppData and auto-restored on launch

---

## 🏗 Architecture

### How It Works

```
  Dojo/Companion app                     Passport Prime (DOJO SIGNER)
  ───────────────────                    ─────────────────────────────
       │  SubscribeSignPsbt                    │
       │  ── PSBT (real bytes) ──────────────► │  Parse → real inputs/values
       │                                       │  Review on secure display
       │                                       │  Approve → sign with SE
       │  PublishPsbt (broadcast)              │
       │  ◄── signed PSBT ───────────────────  │
       │                                       │
  Mix completes                          Seed NEVER leaves
```

### Project Structure

```
dojo-signer/
├── manifest.toml           # App identity, permissions (security, quantum-link, fs)
├── Cargo.toml              # Rust dependencies (ngwallet, quantum-link, slint-keyos-platform)
├── build.rs                # Slint UI compiler integration
├── README.md               # This file
├── src/
│   ├── main.rs             # Entry point + app wiring (1,427 lines)
│   ├── bip47.rs            # BIP47 payment codes, ECDH payment addresses, notification tx (421 lines)
│   ├── coinjoin.rs         # Whirlpool protocol types (v0.23) + base64 helpers
│   ├── message.rs          # BIP47 message verifier types + history
│   └── utxo.rs             # UTXO coin control types
└── ui/
    ├── dojo-signer-callbacks.slint   # Global callback/property bindings
    ├── dojo-signer-types.slint       # PayNymView / UtxoSummaryView structs
    └── pages/                        # 8 screens
        ├── home/         # Identity card + navigation
        ├── paynym/       # Full payment code + notification address + QR
        ├── send/         # On-chain + BIP47 send
        ├── receive/      # Real BIP84 receive address + QR
        ├── settings/     # Node config + BLE companion status
        ├── utxo/         # Coin control summary
        ├── coinjoin/     # Whirlpool review + pool selection
        └── verify/       # BIP47 message verifier + history
```

### Real Crypto (src/bip47.rs)

| Derivation | Implementation |
|---|---|
| Payment code | `base58check(0x47 ∥ version ∥ pubkey ∥ chaincode ∥ padding)` from `m/47'/0'/0'` |
| Notification address | P2PKH of `child_pubkey(0)` (BIP32 non-hardened public derivation) |
| Payment address | `S = a·B`, `s = SHA256(Sx_raw)`, `B' = B + sG` → P2PKH(B') |
| Notification blinding | `s = HMAC-SHA512(outpoint, x)`; `x' = x ⊕ s[0..32]`, `c' = c ⊕ s[32..64]` |

> **Why raw x-coordinate?** `secp256k1`'s `SharedSecret::new()` SHA256-hashes the ECDH x-coordinate by default. BIP47 requires the *raw* x for both payment derivation (`s = SHA256(Sx)`) and notification blinding (`HMAC(outpoint, x)`). The app computes the raw x directly via `PublicKey::mul_tweak` + `x_only_public_key` — this exact bug was caught by the unit tests.

---

## ✅ Testing

The crypto is locked to the **official Samourai BIP47 test vectors** (gist.github.com/SamouraiDev/6aad669604c5930864bd):

```bash
cd ~/KeyOS && cargo test -p gui-app-dojo-signer --profile hosted bip47
```

```
running 6 tests
test bip47::tests::base58check_roundtrip                    ... ok
test bip47::tests::blinding_mask_matches_samourai            ... ok
test bip47::tests::child_pubkey_matches_samourai             ... ok
test bip47::tests::notification_shared_secret_matches_samourai ... ok
test bip47::tests::payment_address_matches_samourai          ... ok
test bip47::tests::payment_code_parse_samourai               ... ok

test result: ok. 6 passed; 0 failed
```

These tests caught a real ECDH double-hash bug before it shipped — every payment address and notification transaction is now byte-for-byte compatible with Samourai / Ashigaru.

---

## 🚀 Getting Started

### Prerequisites
- [Nix](https://nixos.org/download) with flakes enabled
- `just` command runner (`cargo install just`)
- Git

### Build & Run (in the KeyOS simulator)

DOJO SIGNER is a KeyOS workspace app — it runs inside the KeyOS OS:

```bash
# 1. Clone KeyOS (the OS that runs on Passport Prime)
git clone https://github.com/Foundation-Devices/KeyOS.git ~/KeyOS
cd ~/KeyOS

# 2. Enter the Nix development environment
nix develop

# 3. Typecheck the app
cargo check -p gui-app-dojo-signer --profile hosted

# 4. Run the unit tests
cargo test -p gui-app-dojo-signer --profile hosted bip47

# 5. Launch the full simulator (with DOJO SIGNER installed)
just sim
```

The app source lives at `apps/gui-app-dojo-signer/` inside the KeyOS tree.

### On-device permissions (manifest.toml)

```
os/security       → GetSeed, GetSeedFingerprint, GetDeviceId
os/quantum-link   → SendAccountUpdate, PublishPsbt, SubscribeSignPsbt,
                    SubscribeAccountUpdate, SubscribeConnectionStatus,
                    SubscribePairingEvent
os/fs             → GetUserReadAccess, GetUserWriteAccess (config + history persistence)
```

---

## 📊 Screens

| # | Screen | Purpose |
|---|--------|---------|
| 0 | **Home** | PayNym identity card, balance, navigation |
| 1 | **PayNym** | Full payment code, notification address, QR export |
| 2 | **Send** | BIP47 payment-code send / on-chain address entry — amount + fee (built & signed on-device) |
| 3 | **Receive** | Real BIP84 address + QR |
| 4 | **Settings** | Node host/port/SSL/credentials, BLE companion status |
| 5 | **UTXO** | Coin control — count, value, doxxic, anonset |
| 6 | **Coinjoin** | Whirlpool review — real inputs, pool selection, approve/reject |
| 7 | **Verify** | BIP47 message verifier + history |

---

## 🛡 Security Model

- **Seed NEVER leaves the Passport Prime** — keys stay in the secure element
- Only public keys and signed PSBTs/witnesses are exported over BLE
- Every signing requires **physical approval** on the secure display — nothing auto-signs
- Payment + notification inputs can never collide (unspendable marking)
- Failed sends never consume a BIP47 index, so addresses stay deterministic
- No hot wallet, no software key storage, no seed exposure

---

## 🗺 Roadmap

- [x] Real BIP47 payment codes + notification address + ECDH payment addresses
- [x] Real BIP47 send (notification tx + payment, double-spend safe)
- [x] Real BIP47 message verification (pubkey recovery + notification-key match)
- [x] Whirlpool PSBT signing over Quantum Link BLE (real inputs/values/witnesses)
- [x] Pool selection + node config persistence + verification history
- [x] 6/6 unit tests against official Samourai vectors
- [ ] Electrum `blockchain.transaction.broadcast` for live on-chain sends
- [ ] End-to-end BLE round-trip test with the real companion app
- [ ] Real-hardware validation on a Passport Prime dev unit

---

## 📜 License

GNU GPLv3 — open source, fork it, build on it.

---

## 🙏 Acknowledgments

- [Foundation Devices](https://foundation.xyz/) for the Passport Prime and KeyOS
- [Samurai Wallet](https://samouraiwallet.com/) / Ashigaru for Whirlpool coinjoin and the BIP47 test vectors
- [BIP-47](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki) for reusable payment codes
- [bdk](https://bitcoindevkit.org/) for the wallet engine

---

*Built with ⛩ by OZARU — real BIP47 + Whirlpool signing on Passport Prime, verified against the official test vectors.*
