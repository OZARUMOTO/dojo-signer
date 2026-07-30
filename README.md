# ⛩ DOJO SIGNER

**The FIRST hardware wallet support for Samurai Wallet / Ashigaru Terminal / Whirlpool Coinjoin**

A [KeyOS](https://docs.foundation.xyz/) app for the [Foundation Passport Prime](https://foundation.xyz/) — DOJO SIGNER turns your trusted hardware device into a BIP47 PayNym identity generator and Whirlpool coinjoin signing oracle.

```
  >> DOJO_SIGNER
  $ 🟢 Ready — DOJO SIGNER active
  
  # PayNym Identity
  +----------------------------------+
  | 🐸 name: +ozarumoto              |
  |    hash: a1b2c3d4                |
  |    PM8T...code...                |
  | [show_code] [scan_qr] [refresh]  |
  +----------------------------------+
  
  [utxo]   [coinjoin]   [verify]
  [connect] [settings] [history]
```

> 🏆 **No one has ever built hardware wallet support for Samurai Wallet / Ashigaru Whirlpool.** This is the first.

---

## ✨ What It Does

### 🆔 BIP47 PayNym on Hardware
Your Passport Prime becomes a **BIP47 identity generator**: 
- Derives your `+yourname` PayNym from the secure seed at `m/47'/0'/0'` — **seed NEVER leaves the device**
- Generates your `PM8T...` payment code (full BIP-47 spec)
- Shows your **PepeHash** avatar hash for visual identification
- **SegWit and legacy** script type support
- **Following/followers** — your PayNym social graph
- Export as QR code for sharing

### 🌀 Whirlpool Coinjoin Signing
Your Passport Prime becomes the **trusted signing oracle** for Whirlpool mixes:

```
1. REGISTER_INPUT   →  Prove UTXO ownership (sign with secure element)
2. CONFIRM_INPUT    →  Submit blinded bordereau
3. REGISTER_OUTPUT  →  Register receive address
4. REVEAL_OUTPUT    →  Reveal address to peers
5. SIGNING          →  🔐 REVIEW ON SECURE DISPLAY 🔐
                       - Mix ID, witnesses (Z85), transaction details
                       - Approve → hardware signs → sent back
                       - Reject → nothing leaves the device
6. SUCCESS / FAIL   →  Mix completes with your signed witness
```

Uses the **actual Whirlpool Protocol v0.23** types:
- `SigningRequest { mixId, witnesses64[], transaction64 }` — Z85-encoded
- STOMP WebSocket for coordinator communication
- SHA512 for input hashing
- Partner ID: `"dojosigner"` (matching Ashigaru's `"ashigaruterminal"`)

### 🪙 UTXO Coin Control
Review every UTXO before approving a mix:
- **Total count & value** in satoshis
- **Doxxic UTXOs** highlighted — reveal your history
- **Anonymity set** per UTXO (0 = exposed, 50+ = clean)
- **Whirlpool accounts**: DEPOSIT | WHIRLPOOL | POSTMIX | BADBANK

### ✅ BIP47 Message Verifier
Verify messages signed by any BIP47 payment code — same feature as Ashigaru Desktop's built-in verifier, now on hardware:
- Scan or receive a signed message + signature + payment code
- Device derives the expected notification address from the code
- Recovers the signing address from the signature
- ✅ **VERIFIED** + shows signer's PayNym name, or ❌ **FAILED**

### 🔗 Dojo / Electrum Connection
Connect to **Dojo Bay / Electrum servers** via BLE Bridge:
- Geographically dispersed servers with BIP47 verified reputations
- Connection status, block height, peer count
- **Tor support** toggle
- Handshake protocol with Dojo backend

---

## 🏗 Architecture

### How It Works

```
                        BLE / QR
  Dojo/Electrum ────────────────────► Passport Prime (DOJO SIGNER)
       │                                      │
       │  SigningRequest {                    │  User reviews on
       │    mixId,                            │  secure display
       │    witnesses64[Z85],                 │
       │    transaction64[Z85]                │
       │  }                                   │
       │                                      │
       │                              Approve → signs with SE
       │                                      │
       │  SigningResponse {                   │
       │    mixId,                            │
       │    witnesses64[Z85],  ← + HW sig     │
       │  }                                   │
       │                                      │
       ▼                                      ▼
  Mix completes                          Seed NEVER leaves
```

### Project Structure

```
dojo-signer/
├── app-config.toml          # App identity, permissions, publisher
├── Cargo.toml               # Rust dependencies (KeyOS SDK, serde, bs58, etc.)
├── README.md                # This file
├── resources/
│   └── icon.svg             # Dojo-themed launcher icon
├── i18n/
│   └── en.json              # English translations
└── src/
    ├── main.rs              # Entry point + Slint UI (7 screens, 1519 lines)
    ├── bip47.rs             # BIP47 payment codes, PayNym, message verification
    ├── coinjoin.rs          # Whirlpool protocol types (v0.23)
    ├── message.rs           # BIP47 message verifier types
    └── utxo.rs              # UTXO coin control, Dojo connection status
```

### Source: Real Ashigaru Code (via Tor)

The protocol types were built by studying the **actual Ashigaru Terminal source code** hosted on a Tor onion Gitea server:

- `Ashigaru-Whirlpool-Protocol` — Full protocol types (MixStatus, SigningRequest, Z85 encoding, STOMP)
- `Ashigaru-Whirlpool-Client` — Full event system, mix handlers (BIP84/XPub), Tor client
- `Ashigaru-Terminal` — Sparrow Wallet v1.8.4 fork with:
  - **PayNymService.java** — BIP47 REST API client (create, claim, follow, fetch on paynym.rs)
  - **Whirlpool.java** — Central integration (partner ID, accounts, Tx0, mix lifecycle)
  - **HwAirgappedController.java** — Hardware wallet support (Coldcard, Keystone, Passport, Jade, etc.)
  - **PayNym.java** — PayNym model with following/followers, segwit support

---

## 🖥️ Terminal UI

Pure **terminal aesthetic** — black background, red text, monospace font:

| Element | Style |
|---------|-------|
| Background | `#000` pure black |
| Headers | `# Section Title` in bright red `#ff0000` |
| Data | `$ value` in medium red `#cc0000` |
| Labels | Dim red `#880000` |
| Footers | Very dim red `#660000` |
| Buttons | `[bracketed]` terminal-style labels |
| Success/Verify | Green `#4ade80` |

---

## 🚀 Getting Started

### Prerequisites
- [Nix](https://nixos.org/download) (with flakes enabled)
- `just` command runner (`cargo install just`)
- Git

### Build & Run the Simulator

```bash
# 1. Clone KeyOS (the OS that runs on Passport Prime)
git clone https://github.com/Foundation-Devices/KeyOS.git ~/KeyOS
cd ~/KeyOS

# 2. Enter the Nix development environment
nix develop

# 3. Run the built-in simulator
just sim
```

### Sideload DOJO SIGNER

```bash
# 4. Clone DOJO SIGNER
git clone https://github.com/OZARUMOTO/dojo-signer.git ~/dojo-signer

# 5. Build & launch in the simulator
cd ~/dojo-signer
foundation sim
```

> **Note:** The Foundation SDK installer (`curl https://foundation.xyz/sdk/install.sh | bash`) is in **early-access beta**. The KeyOS source code is fully open source at [github.com/Foundation-Devices/KeyOS](https://github.com/Foundation-Devices/KeyOS) and can be built from source.

---

## 📊 Screens

| # | Screen | Purpose |
|---|--------|---------|
| 0 | **Home** | PayNym identity card + navigation grid to all features |
| 1 | **PayNym** | Full BIP47 payment code display + QR export |
| 2 | **UTXO Review** | Coin control — UTXO count, value, doxxic count, avg anonset |
| 3 | **Coinjoin** | Transaction review — mix ID, witnesses, approve/reject on secure display |
| 4 | **Verifier** | BIP47 message verification — paste/scan, verify, see signer's PayNym |
| 5 | **Settings** | Dojo server, connection status, Tor toggle |
| 6 | **History** | Past coinjoin signs and message verifications |

---

## 🛡 Security Model

- **Seed NEVER leaves the Passport Prime** — generated once, stored in the secure element
- Only **public keys** and **signed witnesses** are exported over BLE/QR
- Every signing requires **physical button approval** on the secure display
- No hot wallet, no software key storage, no seed exposure
- All binary data uses **Z85 encoding** (Whirlpool protocol standard)
- **Tor support** for network privacy

---

## 📜 License

GNU GPLv3 — Open source, fork it, build on it.

---

## 🙏 Acknowledgments

- [Foundation Devices](https://foundation.xyz/) for the Passport Prime and KeyOS
- [Samurai Wallet](https://samouraiwallet.com/) / [Ashigaru Terminal](https://github.com/linkinparkrulz/ashigaru-desktop) for Whirlpool coinjoin
- [Sparrow Wallet](https://sparrowwallet.com/) for the foundational desktop wallet code
- [BIP-47](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki) for reusable payment codes

---

*Built with ⛩ by OZARU — First hardware wallet support for Samurai Wallet / Ashigaru Whirlpool*
