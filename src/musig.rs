// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// MuSig2 (BIP-327) key aggregation — a REAL implementation for Passport Prime.
//
// Implements BIP-327 exactly:
//   * KeySort  — canonical lexicographic order of the individual pubkeys.
//   * KeyAgg   — L = hash_KeyAgg list(pk_1..u); coefficient a_i = 1 for the
//                second distinct key (MuSig2* optimization), otherwise
//                int(hash_KeyAgg coefficient(L || pk_i)) mod n;
//                aggregate X = Σ a_i·P_i.
//   * Tagged   — SHA256(SHA256(tag) || SHA256(tag) || msg) per BIP-340.
//
// Every aggregation result is verified byte-for-byte against the OFFICIAL
// BIP-327 test vectors (bitcoin/bips bip-0327/vectors/key_agg_vectors.json)
// in the tests below.
//
// On top of aggregation this module builds a MULTISIG BIP47 payment code:
// a normal "PM8T..." payment code whose signing key is the MuSig2 aggregate
// of N devices (e.g. three Passport Primes = a 3-of-3 savings vault).
//
// Receiving works without any single device holding the aggregate secret:
// BIP47's shared secret is S = a·B. With X = Σ a_i·P_i and x = Σ a_i·d_i
// (which nobody knows in full), each device computes the partial point
// A·(a_i·d_i) where A is the sender's public key. The sum of the partials
// equals a·X, so the devices jointly recover the exact shared secret the
// sender computed — no aggregate private key ever exists. For payment
// addresses the BIP32 child tweak IL is added publicly (IL·A), since
// B' = B + s·G derivation is public.
//
// NOTE ON THE CHAIN CODE: BIP47 has no multisig standard (the spec's
// "type" byte 0x01 for P2SH was reserved but never defined). We therefore
// derive the aggregate payment code's chain code deterministically as
// hash("KeyOS DojoSigner MuSig2 BIP47 chaincode", sorted pk_i || cc_i pairs).
// All participants share their xpubs, so every device computes the same
// aggregate payment code. This is OUR convention, documented honestly.
//
// The interactive MuSig2 SIGNING rounds (NonceGen / NonceAgg / Sign /
// PartialSigAgg) for spending are NOT implemented here — this module is the
// key-identity + receiving foundation. Spending is a follow-up phase.
//
// allow(dead_code): nothing in main.rs consumes this module yet (only its
// #[cfg(test)] tests do). The multisig setup/UI and signing phases wire it in.
#![allow(dead_code)]

use core::fmt;

use ngwallet::bdk_wallet::bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    secp256k1::{All, Parity, PublicKey, Scalar, Secp256k1, SecretKey},
};

use crate::bip47::{self, PaymentCode};

/// Curve order n of secp256k1 (as a big-endian byte array).
const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

#[derive(Debug, Clone)]
pub enum MusigError {
    /// Fewer than two participants (multisig requires >= 2).
    NotEnoughParticipants,
    /// A supplied public key is not a valid compressed secp256k1 point.
    InvalidPublicKey,
    /// Internal scalar conversion failed.
    InvalidScalar,
    /// Key aggregation produced the point at infinity.
    AggregationFailed,
    /// A secnonce value is zero or out of range (possible nonce reuse).
    InvalidNonce,
    /// A tweak is not in [0, n).
    InvalidTweak,
    /// The signer's public key is not part of the signing session.
    SignerPubkeyMismatch,
    /// A partial signature is zero or out of range.
    InvalidPartialSig,
    /// Nonce generation produced a zero nonce.
    NonceGenFailed,
}

impl fmt::Display for MusigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnoughParticipants => write!(f, "MuSig2 requires at least two participants"),
            Self::InvalidPublicKey => write!(f, "Invalid individual public key"),
            Self::InvalidScalar => write!(f, "Invalid scalar during aggregation"),
            Self::AggregationFailed => write!(f, "Key aggregation resulted in the point at infinity"),
            Self::InvalidNonce => write!(f, "Secnonce value is zero or out of range (possible nonce reuse)"),
            Self::InvalidTweak => write!(f, "Tweak must be less than the curve order n"),
            Self::SignerPubkeyMismatch => write!(f, "Signer's public key is not part of this signing session"),
            Self::InvalidPartialSig => write!(f, "Partial signature is zero or out of range"),
            Self::NonceGenFailed => write!(f, "Nonce generation produced a zero nonce"),
        }
    }
}

impl std::error::Error for MusigError {}

// ---- Tagged hashing (BIP-340 style) ----

/// hash_tag(x) = SHA256(SHA256(tag) || SHA256(tag) || x).
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    let tag_hash = sha256::Hash::hash(tag);
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

// ---- Scalar helpers ----

/// Interpret 32 bytes as an integer modulo n. Since n > 2^255 and any
/// 32-byte value is < 2^256 < 2n, a single subtraction suffices.
fn scalar_from_bytes_mod_n(bytes: &[u8; 32]) -> Scalar {
    let reduced = if *bytes >= CURVE_ORDER { sub_n(bytes) } else { *bytes };
    Scalar::from_be_bytes(reduced).expect("reduced value is < n")
}

/// Compute (a - b) for 32-byte big-endian values, assuming a >= b.
fn sub_n(a: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i64;
    for i in (0..32).rev() {
        let d = a[i] as i64 - CURVE_ORDER[i] as i64 - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    out
}

// ---- BIP-327: Key sorting and aggregation ----

/// BIP-327 KeySort: sort the individual public keys in lexicographical order.
pub fn key_sort(pks: &[[u8; 33]]) -> Vec<[u8; 33]> {
    let mut sorted = pks.to_vec();
    sorted.sort();
    sorted
}

/// Result of BIP-327 KeyAgg.
#[derive(Debug, Clone)]
pub struct KeyAggCtx {
    /// Individual public keys exactly as aggregated (order preserved).
    pub pks: Vec<[u8; 33]>,
    /// Key aggregation coefficients a_i, aligned with `pks`.
    pub coeffs: Vec<Scalar>,
    /// The aggregate public key Q (plain, compressed form).
    pub agg_pubkey: PublicKey,
    /// The x-only serialization of Q (32 bytes).
    pub agg_xonly: [u8; 32],
}

/// BIP-327 KeyAgg over the given public keys IN THE GIVEN ORDER.
///
/// The output depends on the input order (per spec); use `key_agg_sorted`
/// for an order-independent aggregate.
pub fn key_agg(pks: &[[u8; 33]]) -> Result<KeyAggCtx, MusigError> {
    if pks.is_empty() {
        return Err(MusigError::NotEnoughParticipants);
    }
    // GetSecondKey: first key different from pk_1, else 33 zero bytes.
    let pk2: [u8; 33] = pks
        .iter()
        .skip(1)
        .find(|p| **p != pks[0])
        .copied()
        .unwrap_or([0u8; 33]);

    // L = hash_KeyAgg list(pk_1 || ... || pk_u)
    let mut l_data = Vec::with_capacity(pks.len() * 33);
    for pk in pks {
        l_data.extend_from_slice(pk);
    }
    let l = tagged_hash(b"KeyAgg list", &l_data);

    let secp = Secp256k1::new();
    let mut coeffs = Vec::with_capacity(pks.len());
    let mut sum: Option<PublicKey> = None;

    for pk in pks {
        // KeyAggCoeffInternal: coefficient is 1 for the second distinct key
        // (MuSig2* optimization) and any key identical to it.
        let coeff = if *pk == pk2 {
            Scalar::ONE
        } else {
            let mut c_data = Vec::with_capacity(65);
            c_data.extend_from_slice(&l);
            c_data.extend_from_slice(pk);
            let h = tagged_hash(b"KeyAgg coefficient", &c_data);
            scalar_from_bytes_mod_n(&h)
        };

        let point = PublicKey::from_slice(pk).map_err(|_| MusigError::InvalidPublicKey)?;
        let term = point
            .mul_tweak(&secp, &coeff)
            .map_err(|_| MusigError::InvalidPublicKey)?;
        sum = Some(match sum {
            None => term,
            Some(acc) => acc.combine(&term).map_err(|_| MusigError::AggregationFailed)?,
        });
        coeffs.push(coeff);
    }

    let q = sum.ok_or(MusigError::AggregationFailed)?;
    let agg_xonly = q.x_only_public_key().0.serialize();
    Ok(KeyAggCtx { pks: pks.to_vec(), coeffs, agg_pubkey: q, agg_xonly })
}

/// KeySort then KeyAgg — the aggregate is independent of participant order.
pub fn key_agg_sorted(pks: &[[u8; 33]]) -> Result<KeyAggCtx, MusigError> {
    let sorted = key_sort(pks);
    key_agg(&sorted)
}

// ---- Threshold ECDH (the receiving half of multisig BIP47) ----

/// This device's partial contribution to the shared secret:
/// partial_i = A · (a_i · d_i), where A is the sender's public notification
/// key, a_i is this device's key-aggregation coefficient and d_i its own
/// secret key. The sum of all devices' partials equals a·X (the sender-side
/// shared secret) without any device knowing the aggregate secret x.
pub fn ecdh_partial(
    secp: &Secp256k1<All>,
    sender_pub: &PublicKey,
    coeff: &Scalar,
    my_secret: &SecretKey,
) -> Result<PublicKey, MusigError> {
    let tweaked = my_secret.mul_tweak(coeff).map_err(|_| MusigError::InvalidScalar)?;
    let scalar =
        Scalar::from_be_bytes(tweaked.secret_bytes()).map_err(|_| MusigError::InvalidScalar)?;
    sender_pub
        .mul_tweak(secp, &scalar)
        .map_err(|_| MusigError::InvalidPublicKey)
}

/// Sum the devices' partial points into the full shared point.
pub fn combine_partials(partials: &[PublicKey]) -> Result<PublicKey, MusigError> {
    if partials.is_empty() {
        return Err(MusigError::NotEnoughParticipants);
    }
    let mut acc = partials[0];
    for p in &partials[1..] {
        acc = acc.combine(p).map_err(|_| MusigError::AggregationFailed)?;
    }
    Ok(acc)
}

// ---- Multisig BIP47 payment code ----

/// An aggregate (multisig) BIP47 payment code — a normal "PM8T..." payment
/// code whose key is the MuSig2 aggregate of all participants.
#[derive(Debug, Clone)]
pub struct AggregatePaymentCode {
    pub payment_code: PaymentCode,
    /// Sorted participant public keys (canonical order used for aggregation).
    pub participants: Vec<[u8; 33]>,
}

/// Build the aggregate payment code from N devices.
///
/// `pks` and `chaincodes` are each device's BIP47 identity pubkey and chain
/// code (from its m/47'/0'/0' xpub). All participants compute the SAME
/// payment code, regardless of the order the xpubs are collected in.
pub fn aggregate_payment_code(
    pks: &[[u8; 33]],
    chaincodes: &[[u8; 32]],
) -> Result<AggregatePaymentCode, MusigError> {
    if pks.len() < 2 || pks.len() != chaincodes.len() {
        return Err(MusigError::NotEnoughParticipants);
    }

    // Sort participants by public key (BIP-327 KeySort) for a canonical order.
    let mut pairs: Vec<([u8; 33], [u8; 32])> =
        pks.iter().zip(chaincodes.iter()).map(|(p, c)| (*p, *c)).collect();
    pairs.sort_by_key(|(p, _)| *p);

    let sorted_pks: Vec<[u8; 33]> = pairs.iter().map(|(p, _)| *p).collect();
    let agg = key_agg(&sorted_pks)?;

    // Aggregate chain code — our documented convention: a tagged hash over
    // the sorted (pubkey || chaincode) pairs, so every device computes the
    // same value from the shared xpubs.
    let mut cc_data = Vec::new();
    for (pk, cc) in &pairs {
        cc_data.extend_from_slice(pk);
        cc_data.extend_from_slice(cc);
    }
    let agg_cc = tagged_hash(b"KeyOS DojoSigner MuSig2 BIP47 chaincode", &cc_data);

    // Build the 80-byte payment code payload (version 1, no Bitmessage).
    let mut payload = [0u8; 80];
    payload[0] = 0x01;
    payload[1] = 0x00;
    payload[2..35].copy_from_slice(&agg.agg_pubkey.serialize());
    payload[35..67].copy_from_slice(&agg_cc);

    let raw = bip47::encode_payment_code(&payload);
    let payment_code = PaymentCode {
        raw,
        pubkey: agg.agg_pubkey.serialize(),
        chaincode: agg_cc,
    };
    Ok(AggregatePaymentCode { payment_code, participants: sorted_pks })
}

// =====================================================================
// PHASE 2 — BIP-327 SIGNING PROTOCOL
//
// NonceGen / NonceAgg / GetSessionValues / Sign / PartialSigVerify /
// PartialSigAgg, plus ApplyTweak for tweaked aggregate keys. Verified
// against the official bip-0327 sign_verify_vectors.json and
// tweak_vectors.json. With this, the N devices jointly produce a BIP340
// Schnorr signature valid under their aggregate key — i.e. the vault can
// SPEND. The multi-device transport (exchanging pubnonces and partial
// signatures) is the app layer that uses these primitives.
//
// Scalar arithmetic note: secp256k1 0.29.1 exposes no Add/Mul traits on
// Scalar, so addition/negation are done byte-wise mod n (single-subtract
// reduction is valid because n > 2^255 and all operands are < n), and
// multiplication delegates to libsecp256k1's SecretKey::mul_tweak.
// =====================================================================

/// Tagged-hash tags used by the signing protocol.
const TAG_NONCE: &[u8] = b"MuSig/nonce";
const TAG_AUX: &[u8] = b"MuSig/aux";
const TAG_NONCECOEF: &[u8] = b"MuSig/noncecoef";
const TAG_CHALLENGE: &[u8] = b"BIP0340/challenge";

/// A curve point; None is the point at infinity (for nonce sums).
type MaybePoint = Option<PublicKey>;

/// cpoint_ext: 33 zero bytes decode to infinity, otherwise a compressed key.
fn cpoint_ext(bytes: &[u8]) -> Result<MaybePoint, MusigError> {
    if bytes.len() != 33 {
        return Err(MusigError::InvalidPublicKey);
    }
    if bytes.iter().all(|&b| b == 0) {
        return Ok(None);
    }
    PublicKey::from_slice(bytes).map(Some).map_err(|_| MusigError::InvalidPublicKey)
}

fn pt_add(a: MaybePoint, b: MaybePoint) -> Result<MaybePoint, MusigError> {
    match (a, b) {
        (None, x) | (x, None) => Ok(x),
        (Some(x), Some(y)) => {
            // P + (-P) is the point at infinity, which PublicKey::combine
            // rejects. Detect the inverse pair first (identical x, opposite
            // parity byte in the compressed encoding) and return the infinity
            // sentinel — BIP-327 NonceAgg requires this (official
            // nonce_agg_vectors.json case [2,3] sums G and -G to infinity).
            let xs = x.serialize();
            let ys = y.serialize();
            if xs[1..] == ys[1..] && xs[0] != ys[0] {
                return Ok(None);
            }
            x.combine(&y).map(Some).map_err(|_| MusigError::AggregationFailed)
        }
    }
}

fn pt_mul(p: MaybePoint, s: &Scalar) -> Result<MaybePoint, MusigError> {
    match p {
        None => Ok(None),
        Some(pk) => pk
            .mul_tweak(&Secp256k1::new(), s)
            .map(Some)
            .map_err(|_| MusigError::InvalidPublicKey),
    }
}

/// -P: flip the parity byte of the compressed serialization.
fn pt_neg(p: &PublicKey) -> PublicKey {
    let mut ser = p.serialize();
    ser[0] ^= 0x01; // 0x02 <-> 0x03
    PublicKey::from_slice(&ser).expect("negated point is valid")
}

fn point_has_even_y(p: &PublicKey) -> bool {
    p.x_only_public_key().1 == Parity::Even
}

/// Compare two big-endian 32-byte values: a >= b.
fn bytes_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.as_slice() >= b.as_slice()
}

/// (a + b) mod n.
fn scalar_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], MusigError> {
    let mut v = [0u8; 33];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        v[i + 1] = s as u8;
        carry = s >> 8;
    }
    v[0] = carry as u8;
    let ge = if v[0] != 0 { true } else { &v[1..] >= &CURVE_ORDER[..] };
    if ge {
        let mut borrow = 0i64;
        for i in (0..33).rev() {
            let nv: i64 = if i == 0 { 0 } else { CURVE_ORDER[i - 1] as i64 };
            let mut d = v[i] as i64 - nv - borrow;
            if d < 0 {
                d += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            v[i] = d as u8;
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[1..]);
    Ok(out)
}

/// (-a) mod n.
fn scalar_neg_mod_n(a: &[u8; 32]) -> Result<[u8; 32], MusigError> {
    if a.iter().all(|&b| b == 0) {
        return Ok([0u8; 32]);
    }
    let mut out = [0u8; 32];
    let mut borrow = 0i64;
    for i in (0..32).rev() {
        let mut d = CURVE_ORDER[i] as i64 - a[i] as i64 - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = d as u8;
    }
    Ok(out)
}

/// (a * b) mod n, via libsecp256k1's SecretKey::mul_tweak.
fn scalar_mul_mod_n(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], MusigError> {
    if a.iter().all(|&x| x == 0) || b.iter().all(|&x| x == 0) {
        return Ok([0u8; 32]);
    }
    let sk = SecretKey::from_slice(a).map_err(|_| MusigError::InvalidScalar)?;
    let bs = Scalar::from_be_bytes(*b).map_err(|_| MusigError::InvalidScalar)?;
    sk.mul_tweak(&bs).map(|k| k.secret_bytes()).map_err(|_| MusigError::InvalidScalar)
}

/// A single tweak applied to the aggregate key (plain or x-only).
#[derive(Debug, Clone)]
pub struct Tweak {
    pub t: [u8; 32],
    pub is_xonly: bool,
}

/// The BIP-327 session context: everything Sign needs beyond the secnonce.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub aggnonce: [u8; 66],
    pub pks: Vec<[u8; 33]>,
    pub tweaks: Vec<Tweak>,
    pub msg: Vec<u8>,
}

/// Derived session values (Q, gacc, tacc, b, R, e) — BIP-327 GetSessionValues.
struct SessionValues {
    q: PublicKey,
    gacc_sign: i64,
    tacc: [u8; 32],
    b: [u8; 32],
    r: PublicKey,
    e: [u8; 32],
}

/// BIP-327 NonceAgg: combine every signer's 66-byte pubnonce.
pub fn nonce_agg(pubnonces: &[[u8; 66]]) -> Result<[u8; 66], MusigError> {
    if pubnonces.is_empty() {
        return Err(MusigError::NotEnoughParticipants);
    }
    let mut r1: MaybePoint = None;
    let mut r2: MaybePoint = None;
    for pn in pubnonces {
        r1 = pt_add(r1, cpoint_ext(&pn[0..33])?)?;
        r2 = pt_add(r2, cpoint_ext(&pn[33..66])?)?;
    }
    let mut out = [0u8; 66];
    let b1 = match r1 {
        None => [0u8; 33],
        Some(p) => p.serialize(),
    };
    let b2 = match r2 {
        None => [0u8; 33],
        Some(p) => p.serialize(),
    };
    out[0..33].copy_from_slice(&b1);
    out[33..66].copy_from_slice(&b2);
    Ok(out)
}

/// BIP-327 NonceGen. `rand` must be fresh, uniformly random 32 bytes from a
/// high-quality source (the device TRNG in production). Returns
/// (secnonce[97], pubnonce[66]).
pub fn nonce_gen(
    rand: [u8; 32],
    sk: Option<&SecretKey>,
    pk: &[u8; 33],
    aggpk: Option<[u8; 32]>,
    m: Option<&[u8]>,
    extra_in: &[u8],
) -> Result<([u8; 97], [u8; 66]), MusigError> {
    let mut r = rand;
    if let Some(sk) = sk {
        // rand = sk XOR hash_MuSig/aux(rand')  (defense in depth)
        let aux = tagged_hash(TAG_AUX, &rand);
        let skb = sk.secret_bytes();
        for i in 0..32 {
            r[i] = skb[i] ^ aux[i];
        }
    }
    let aggpk_bytes = aggpk.unwrap_or([0u8; 32]);
    let aggpk_len: usize = if aggpk.is_some() { 32 } else { 0 };
    // BIP-327 message encoding: None -> a single 0x00 byte; a present
    // message (even an empty one) -> 0x01 || 8-byte big-endian length || msg.
    // The None-vs-Some(empty) distinction is validated by the official
    // nonce_gen_vectors.json (its empty-message case uses the 0x01 encoding).
    let m_prefixed: Vec<u8> = match m {
        None => vec![0u8],
        Some(m_bytes) => {
            let mut v = Vec::with_capacity(9 + m_bytes.len());
            v.push(1u8);
            v.extend_from_slice(&(m_bytes.len() as u64).to_be_bytes());
            v.extend_from_slice(m_bytes);
            v
        }
    };
    let mut k_input =
        Vec::with_capacity(32 + 1 + 33 + 1 + aggpk_len + m_prefixed.len() + 4 + extra_in.len());
    k_input.extend_from_slice(&r);
    k_input.push(33u8); // bytes(1, len(pk))
    k_input.extend_from_slice(pk);
    k_input.push(aggpk_len as u8); // bytes(1, len(aggpk))
    k_input.extend_from_slice(&aggpk_bytes[..aggpk_len]);
    k_input.extend_from_slice(&m_prefixed);
    k_input.extend_from_slice(&(extra_in.len() as u32).to_be_bytes());
    k_input.extend_from_slice(extra_in);

    let mut k1_in = k_input.clone();
    k1_in.push(0u8); // bytes(1, i-1) for i = 1
    let mut k2_in = k_input.clone();
    k2_in.push(1u8); // bytes(1, i-1) for i = 2

    let k1 = scalar_from_bytes_mod_n(&tagged_hash(TAG_NONCE, &k1_in));
    let k2 = scalar_from_bytes_mod_n(&tagged_hash(TAG_NONCE, &k2_in));
    if k1.to_be_bytes() == [0u8; 32] || k2.to_be_bytes() == [0u8; 32] {
        return Err(MusigError::NonceGenFailed);
    }
    let secp = Secp256k1::new();
    let k1b = k1.to_be_bytes();
    let k2b = k2.to_be_bytes();
    let r1 = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&k1b).map_err(|_| MusigError::InvalidScalar)?,
    );
    let r2 = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&k2b).map_err(|_| MusigError::InvalidScalar)?,
    );

    let mut pubnonce = [0u8; 66];
    pubnonce[0..33].copy_from_slice(&r1.serialize());
    pubnonce[33..66].copy_from_slice(&r2.serialize());
    let mut secnonce = [0u8; 97];
    secnonce[0..32].copy_from_slice(&k1b);
    secnonce[32..64].copy_from_slice(&k2b);
    secnonce[64..97].copy_from_slice(pk);
    Ok((secnonce, pubnonce))
}

/// BIP-327 ApplyTweak over a list of tweaks; returns (Q, gacc, tacc).
fn apply_tweaks(q0: PublicKey, tweaks: &[Tweak]) -> Result<(PublicKey, i64, [u8; 32]), MusigError> {
    let secp = Secp256k1::new();
    let mut q = q0;
    let mut gacc: i64 = 1;
    let mut tacc = [0u8; 32];
    for tw in tweaks {
        if bytes_ge(&tw.t, &CURVE_ORDER) {
            return Err(MusigError::InvalidTweak);
        }
        let g: i64 = if tw.is_xonly && !point_has_even_y(&q) { -1 } else { 1 };
        let gq = if g == -1 { pt_neg(&q) } else { q };
        let tg: MaybePoint = if tw.t.iter().all(|&b| b == 0) {
            None
        } else {
            let sk = SecretKey::from_slice(&tw.t).map_err(|_| MusigError::InvalidTweak)?;
            Some(PublicKey::from_secret_key(&secp, &sk))
        };
        let q2 = pt_add(Some(gq), tg)?.ok_or(MusigError::AggregationFailed)?;
        q = q2;
        gacc *= g;
        let gtacc = if g == -1 { scalar_neg_mod_n(&tacc)? } else { tacc };
        tacc = scalar_add_mod_n(&tw.t, &gtacc)?;
    }
    Ok((q, gacc, tacc))
}

/// BIP-327 GetSessionValues.
fn get_session_values(session: &SessionContext) -> Result<SessionValues, MusigError> {
    let secp = Secp256k1::new();
    let agg = key_agg(&session.pks)?;
    let (q, gacc_sign, tacc) = apply_tweaks(agg.agg_pubkey, &session.tweaks)?;
    let q_x = q.x_only_public_key().0.serialize();

    let mut b_in = Vec::with_capacity(66 + 32 + session.msg.len());
    b_in.extend_from_slice(&session.aggnonce);
    b_in.extend_from_slice(&q_x);
    b_in.extend_from_slice(&session.msg);
    let b = scalar_from_bytes_mod_n(&tagged_hash(TAG_NONCECOEF, &b_in));

    let r1 = cpoint_ext(&session.aggnonce[0..33])?;
    let r2 = cpoint_ext(&session.aggnonce[33..66])?;
    let br2 = pt_mul(r2, &b)?;
    let rp = pt_add(r1, br2)?;
    let r = match rp {
        Some(p) => p,
        // is_infinite(R') => final nonce R = G
        None => {
            let mut gb = [0u8; 32];
            gb[31] = 1;
            PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(&gb).map_err(|_| MusigError::InvalidScalar)?,
            )
        }
    };

    let r_x = r.x_only_public_key().0.serialize();
    let mut e_in = Vec::with_capacity(64 + session.msg.len());
    e_in.extend_from_slice(&r_x);
    e_in.extend_from_slice(&q_x);
    e_in.extend_from_slice(&session.msg);
    let e = scalar_from_bytes_mod_n(&tagged_hash(TAG_CHALLENGE, &e_in));

    Ok(SessionValues { q, gacc_sign, tacc, b: b.to_be_bytes(), r, e: e.to_be_bytes() })
}

/// BIP-327 GetSessionKeyAggCoeff for a participant's public key.
fn session_key_agg_coeff(session: &SessionContext, pk: &[u8; 33]) -> Result<Scalar, MusigError> {
    let ctx = key_agg(&session.pks)?;
    let pos = ctx
        .pks
        .iter()
        .position(|p| p == pk)
        .ok_or(MusigError::SignerPubkeyMismatch)?;
    Ok(ctx.coeffs[pos])
}

/// BIP-327 Sign: produce this signer's partial signature (32 bytes).
pub fn sign(
    secnonce: &[u8; 97],
    sk: &SecretKey,
    session: &SessionContext,
) -> Result<[u8; 32], MusigError> {
    let sv = get_session_values(session)?;
    let secp = Secp256k1::new();

    let mut k1 = [0u8; 32];
    k1.copy_from_slice(&secnonce[0..32]);
    let mut k2 = [0u8; 32];
    k2.copy_from_slice(&secnonce[32..64]);
    if k1 == [0u8; 32]
        || k2 == [0u8; 32]
        || bytes_ge(&k1, &CURVE_ORDER)
        || bytes_ge(&k2, &CURVE_ORDER)
    {
        return Err(MusigError::InvalidNonce);
    }
    if !point_has_even_y(&sv.r) {
        k1 = scalar_neg_mod_n(&k1)?;
        k2 = scalar_neg_mod_n(&k2)?;
    }

    let p = PublicKey::from_secret_key(&secp, sk);
    let pk = p.serialize();
    if pk != secnonce[64..97] {
        return Err(MusigError::SignerPubkeyMismatch);
    }
    let a = session_key_agg_coeff(session, &pk)?;
    let g: i64 = if point_has_even_y(&sv.q) { 1 } else { -1 };
    let mut d = sk.secret_bytes();
    if g * sv.gacc_sign == -1 {
        d = scalar_neg_mod_n(&d)?;
    }

    let bk2 = scalar_mul_mod_n(&k2, &sv.b)?;
    let a_bytes = a.to_be_bytes();
    let ad = scalar_mul_mod_n(&d, &a_bytes)?;
    let ead = scalar_mul_mod_n(&ad, &sv.e)?;
    let s1 = scalar_add_mod_n(&k1, &bk2)?;
    scalar_add_mod_n(&s1, &ead)
}

/// BIP-327 PartialSigVerify: check one signer's partial signature.
pub fn partial_sig_verify(
    psig: &[u8; 32],
    pubnonce: &[u8; 66],
    pk: &[u8; 33],
    session: &SessionContext,
) -> Result<(), MusigError> {
    let sv = get_session_values(session)?;
    let secp = Secp256k1::new();

    if psig == &[0u8; 32] {
        return Err(MusigError::InvalidPartialSig);
    }

    let r1 = cpoint_ext(&pubnonce[0..33])?;
    let r2 = cpoint_ext(&pubnonce[33..66])?;
    let br2 = pt_mul(
        r2,
        &Scalar::from_be_bytes(sv.b).map_err(|_| MusigError::InvalidScalar)?,
    )?;
    let mut re = pt_add(r1, br2)?.ok_or(MusigError::AggregationFailed)?;
    if !point_has_even_y(&sv.r) {
        re = pt_neg(&re);
    }

    let p = PublicKey::from_slice(pk).map_err(|_| MusigError::InvalidPublicKey)?;
    let a = session_key_agg_coeff(session, pk)?;
    let g: i64 = if point_has_even_y(&sv.q) { 1 } else { -1 };
    let gp = g * sv.gacc_sign;
    let a_bytes = a.to_be_bytes();
    let ea = scalar_mul_mod_n(&a_bytes, &sv.e)?;
    let eag = if gp == -1 { scalar_neg_mod_n(&ea)? } else { ea };
    let p_eag = p
        .mul_tweak(
            &secp,
            &Scalar::from_be_bytes(eag).map_err(|_| MusigError::InvalidScalar)?,
        )
        .map_err(|_| MusigError::InvalidPublicKey)?;
    let rhs = pt_add(Some(re), Some(p_eag))?.ok_or(MusigError::AggregationFailed)?;

    let sk_s = SecretKey::from_slice(psig).map_err(|_| MusigError::InvalidPartialSig)?;
    let sg = PublicKey::from_secret_key(&secp, &sk_s);
    if sg != rhs {
        return Err(MusigError::InvalidPartialSig);
    }
    Ok(())
}

/// BIP-327 PartialSigAgg: combine partial signatures into the final BIP340
/// signature (xbytes(R) || bytes(32, s)), 64 bytes.
pub fn partial_sig_agg(psigs: &[[u8; 32]], session: &SessionContext) -> Result<[u8; 64], MusigError> {
    let sv = get_session_values(session)?;
    let mut s = [0u8; 32];
    for ps in psigs {
        if bytes_ge(ps, &CURVE_ORDER) {
            return Err(MusigError::InvalidPartialSig);
        }
        s = scalar_add_mod_n(&s, ps)?;
    }
    let g: i64 = if point_has_even_y(&sv.q) { 1 } else { -1 };
    let gtacc = if g == -1 { scalar_neg_mod_n(&sv.tacc)? } else { sv.tacc };
    let egtacc = scalar_mul_mod_n(&gtacc, &sv.e)?;
    s = scalar_add_mod_n(&s, &egtacc)?;

    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&sv.r.x_only_public_key().0.serialize());
    sig[32..64].copy_from_slice(&s);
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ngwallet::bdk_wallet::bitcoin::{
        hashes::{sha256, Hash},
        secp256k1::{schnorr, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey},
        Address, Network, PubkeyHash,
    };

    // ---- Official BIP-327 key aggregation vectors ----
    // Source: bitcoin/bips bip-0327/vectors/key_agg_vectors.json
    const V_PKS: [&str; 7] = [
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "020000000000000000000000000000000000000000000000000000000000000005",
        "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    ];

    fn vpk(i: usize) -> [u8; 33] {
        let bytes = hex::decode(V_PKS[i]).unwrap();
        bytes.try_into().unwrap()
    }

    fn pk_from_bytes(bytes: &[u8]) -> PublicKey {
        PublicKey::from_slice(bytes).unwrap()
    }

    fn secret(byte: u8) -> SecretKey {
        let mut b = [0u8; 32];
        b[31] = byte;
        SecretKey::from_slice(&b).unwrap()
    }

    #[test]
    fn key_agg_matches_official_bip327_vectors() {
        let cases: [([usize; 3], &str); 3] = [
            ([0, 1, 2], "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C"),
            ([2, 1, 0], "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B"),
            ([0, 0, 0], "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935"),
        ];
        for (idx, expected) in cases {
            let pks: Vec<[u8; 33]> = idx.iter().map(|&i| vpk(i)).collect();
            let agg = key_agg(&pks).unwrap();
            assert_eq!(hex::encode_upper(agg.agg_xonly), expected, "vector {:?}", idx);
        }
        // Duplicate-heavy case [0,0,1,1] (4 keys, two distinct).
        let pks = vec![vpk(0), vpk(0), vpk(1), vpk(1)];
        let agg = key_agg(&pks).unwrap();
        assert_eq!(
            hex::encode_upper(agg.agg_xonly),
            "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E"
        );
    }

    #[test]
    fn key_agg_rejects_invalid_pubkeys() {
        // [0,3] x=5 is not on the curve; [0,4] x exceeds field size;
        // [5,0] uncompressed prefix 0x04.
        for idx in [[0, 3], [0, 4], [5, 0]] {
            let pks: Vec<[u8; 33]> = idx.iter().map(|&i| vpk(i)).collect();
            assert!(key_agg(&pks).is_err(), "expected error for {:?}", idx);
        }
    }

    #[test]
    fn key_agg_sorted_is_order_independent() {
        let a = key_agg_sorted(&[vpk(0), vpk(1), vpk(2)]).unwrap();
        let b = key_agg_sorted(&[vpk(2), vpk(1), vpk(0)]).unwrap();
        let c = key_agg_sorted(&[vpk(1), vpk(2), vpk(0)]).unwrap();
        assert_eq!(a.agg_xonly, b.agg_xonly);
        assert_eq!(a.agg_xonly, c.agg_xonly);
    }

    #[test]
    fn threshold_ecdh_recovers_sender_side_secret() {
        let secp = Secp256k1::new();

        // Three devices, fixed secrets for determinism.
        let secrets = [secret(1), secret(2), secret(3)];
        let pks: Vec<[u8; 33]> = secrets
            .iter()
            .map(|d| PublicKey::from_secret_key(&secp, d).serialize())
            .collect();

        // Sender key pair.
        let a = secret(0x42);
        let a_pub = PublicKey::from_secret_key(&secp, &a);

        // Aggregate key X = Σ a_i·P_i (sorted for order independence).
        let agg = key_agg_sorted(&pks).unwrap();
        let x = agg.agg_pubkey;

        // Sender side: shared point = a·X.
        let sender_side = x
            .mul_tweak(&secp, &Scalar::from_be_bytes(a.secret_bytes()).unwrap())
            .unwrap();

        // Recipient side: each device computes A·(a_i·d_i); sum the partials.
        // Find each device's coefficient by matching its pubkey.
        let partials: Vec<PublicKey> = secrets
            .iter()
            .map(|d| {
                let pk = PublicKey::from_secret_key(&secp, d).serialize();
                let coeff = &agg.coeffs[agg.pks.iter().position(|p| *p == pk).unwrap()];
                ecdh_partial(&secp, &a_pub, coeff, d).unwrap()
            })
            .collect();
        let recipient_side = combine_partials(&partials).unwrap();

        assert_eq!(
            sender_side.x_only_public_key().0.serialize(),
            recipient_side.x_only_public_key().0.serialize(),
            "threshold ECDH must equal sender-side ECDH"
        );
    }

    #[test]
    fn aggregate_payment_code_is_deterministic_and_parses() {
        let secp = Secp256k1::new();
        let secrets = [secret(0x11), secret(0x22), secret(0x33)];
        let pks: Vec<[u8; 33]> = secrets
            .iter()
            .map(|d| PublicKey::from_secret_key(&secp, d).serialize())
            .collect();
        let chaincodes: Vec<[u8; 32]> = (0..3)
            .map(|i| {
                let mut cc = [0u8; 32];
                cc[0] = i + 1;
                cc
            })
            .collect();

        let a = aggregate_payment_code(&pks, &chaincodes).unwrap();
        let b = aggregate_payment_code(
            &[pks[2], pks[0], pks[1]],
            &[chaincodes[2], chaincodes[0], chaincodes[1]],
        )
        .unwrap();

        // Order-independent.
        assert_eq!(a.payment_code.raw, b.payment_code.raw);

        // Real PM8T payment code: parses back and round-trips the key material.
        assert!(a.payment_code.raw.starts_with("PM8T"));
        let parsed = PaymentCode::parse(&a.payment_code.raw).unwrap();
        assert_eq!(parsed.pubkey, a.payment_code.pubkey);
        assert_eq!(parsed.chaincode, a.payment_code.chaincode);

        // Notification address derives (P2PKH child 0).
        let notif = parsed.notification_address().unwrap();
        assert!(notif.starts_with('1'));
    }

    #[test]
    fn recipient_recovers_payment_address_via_threshold_ecdh() {
        let secp = Secp256k1::new();

        // Three devices form the multisig vault.
        let secrets = [secret(0x51), secret(0x52), secret(0x53)];
        let pks: Vec<[u8; 33]> = secrets
            .iter()
            .map(|d| PublicKey::from_secret_key(&secp, d).serialize())
            .collect();
        let chaincodes: Vec<[u8; 32]> = (0..3)
            .map(|i| {
                let mut cc = [0u8; 32];
                cc[31] = i + 1;
                cc
            })
            .collect();
        let agg_pc = aggregate_payment_code(&pks, &chaincodes).unwrap();
        let pc = &agg_pc.payment_code;

        // Sender (a random external BIP47 user) pays the aggregate payment code.
        let sender_secret = secret(0x77);
        let sender_pub = PublicKey::from_secret_key(&secp, &sender_secret);
        let (addr, idx) = pc.payment_address(&sender_secret, 0).unwrap();

        // Recipient side, using ONLY public data + per-device secrets:
        // 1) child key B_idx (public), child tweak IL (public)
        // 2) each device: partial = A·(a_i·d_i)  → sum
        // 3) S = sum + IL·A  (the BIP32 CKDpub tweak applied publicly)
        let b_idx = pc.child_pubkey(idx).unwrap();
        let il = pc.child_il(idx).unwrap();

        let partials: Vec<PublicKey> = secrets
            .iter()
            .map(|d| {
                let pk = PublicKey::from_secret_key(&secp, d).serialize();
                let coeff = &agg_pc_pubkey_coeff(&agg_pc, &pk);
                ecdh_partial(&secp, &sender_pub, coeff, d).unwrap()
            })
            .collect();
        let mut shared = combine_partials(&partials).unwrap();
        let il_term = sender_pub.mul_tweak(&secp, &il).unwrap();
        shared = shared.combine(&il_term).unwrap();

        // Same shared secret as the sender computed: s = SHA256(Sx).
        let sx = shared.x_only_public_key().0.serialize();
        let sender_sx = bip47::ecdh_x_coordinate(&secp, &b_idx, &sender_secret).unwrap();
        assert_eq!(sx, sender_sx, "shared secret must match sender side");

        let s = sha256::Hash::hash(&sx).to_byte_array();
        let s_scalar = Scalar::from_be_bytes(s).unwrap();
        let bp = b_idx.add_exp_tweak(&secp, &s_scalar).unwrap();
        let pkh = PubkeyHash::hash(&bp.serialize());
        let recipient_addr = Address::p2pkh(pkh, Network::Bitcoin).to_string();

        assert_eq!(recipient_addr, addr, "recipient derives the same payment address");
    }

    /// Look up a device's aggregation coefficient by its pubkey.
    fn agg_pc_pubkey_coeff(agg_pc: &AggregatePaymentCode, pk: &[u8; 33]) -> Scalar {
        // Re-run aggregation (cheap, deterministic) to fetch coefficients
        // aligned with the participant order.
        let ctx = key_agg_sorted(&agg_pc.participants).unwrap();
        let pos = ctx.pks.iter().position(|p| p == pk).unwrap();
        ctx.coeffs[pos]
    }

    // ================= Phase 2: official BIP-327 signing vectors ============
    // Source: bitcoin/bips bip-0327/vectors/sign_verify_vectors.json
    const S_SK: &str = "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671";
    const S_PKS: [&str; 4] = [
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
        "020000000000000000000000000000000000000000000000000000000000000007",
    ];
    const S_SECNONCES: [&str; 2] = [
        "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    ];
    const S_AGGNONCES: [&str; 5] = [
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009",
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
    ];
    const S_MSGS: [&str; 3] = [
        "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
        "",
        "2626262626262626262626262626262626262626262626262626262626262626262626262626",
    ];

    fn hx(h: &str) -> Vec<u8> {
        hex::decode(h).unwrap()
    }

    #[test]
    fn sign_matches_official_bip327_vectors() {
        let sk = SecretKey::from_slice(&hx(S_SK)).unwrap();
        // Sanity: the provided sk is the private key of S_PKS[0].
        let secp = Secp256k1::new();
        assert_eq!(
            PublicKey::from_secret_key(&secp, &sk).serialize(),
            hx(S_PKS[0]).as_slice()
        );

        // (key_indices, nonce_indices, aggnonce_index, msg_index, signer, expected)
        let cases: [([usize; 3], [usize; 3], usize, usize, usize, &str); 5] = [
            ([0, 1, 2], [0, 1, 2], 0, 0, 0, "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB"),
            ([1, 0, 2], [1, 0, 2], 0, 0, 1, "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52"),
            ([1, 2, 0], [1, 2, 0], 0, 0, 2, "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900"),
            ([0, 1, 2], [0, 1, 2], 0, 1, 0, "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D"),
            ([0, 1, 2], [0, 1, 2], 0, 2, 0, "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C"),
        ];
        for (keys, nonces, agi, msi, si, expected) in cases {
            let pks: Vec<[u8; 33]> =
                keys.iter().map(|&k| hx(S_PKS[k]).try_into().unwrap()).collect();
            let session = SessionContext {
                aggnonce: hx(S_AGGNONCES[agi]).try_into().unwrap(),
                pks,
                tweaks: vec![],
                msg: hx(S_MSGS[msi]),
            };
            let secnonce: [u8; 97] = hx(S_SECNONCES[nonces[si]]).try_into().unwrap();
            let psig = sign(&secnonce, &sk, &session).unwrap();
            assert_eq!(hex::encode_upper(psig), expected, "case keys={:?}", keys);
        }

        // Infinity-aggnonce case (both halves are the point at infinity).
        let pks: Vec<[u8; 33]> = [0usize, 1].iter().map(|&k| hx(S_PKS[k]).try_into().unwrap()).collect();
        let session = SessionContext {
            aggnonce: hx(S_AGGNONCES[1]).try_into().unwrap(),
            pks,
            tweaks: vec![],
            msg: hx(S_MSGS[0]),
        };
        let secnonce: [u8; 97] = hx(S_SECNONCES[0]).try_into().unwrap();
        let psig = sign(&secnonce, &sk, &session).unwrap();
        assert_eq!(
            hex::encode_upper(psig),
            "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531"
        );
    }

    #[test]
    fn sign_error_cases_match_official_vectors() {
        let sk = SecretKey::from_slice(&hx(S_SK)).unwrap();

        // Signer's pubkey is not in the key list.
        let pks: Vec<[u8; 33]> = [1usize, 2].iter().map(|&k| hx(S_PKS[k]).try_into().unwrap()).collect();
        let session = SessionContext {
            aggnonce: hx(S_AGGNONCES[0]).try_into().unwrap(),
            pks,
            tweaks: vec![],
            msg: hx(S_MSGS[0]),
        };
        assert!(sign(&hx(S_SECNONCES[0]).try_into().unwrap(), &sk, &session).is_err());

        // Invalid pubkey in the list (x = 7 is not on the curve).
        let pks: Vec<[u8; 33]> = [1usize, 0, 3].iter().map(|&k| hx(S_PKS[k]).try_into().unwrap()).collect();
        let session = SessionContext {
            aggnonce: hx(S_AGGNONCES[0]).try_into().unwrap(),
            pks,
            tweaks: vec![],
            msg: hx(S_MSGS[0]),
        };
        assert!(sign(&hx(S_SECNONCES[0]).try_into().unwrap(), &sk, &session).is_err());

        // Invalid aggnonce: wrong tag, bad x, x beyond field size.
        for agi in [2usize, 3, 4] {
            let pks: Vec<[u8; 33]> = [1usize, 2, 0].iter().map(|&k| hx(S_PKS[k]).try_into().unwrap()).collect();
            let session = SessionContext {
                aggnonce: hx(S_AGGNONCES[agi]).try_into().unwrap(),
                pks,
                tweaks: vec![],
                msg: hx(S_MSGS[0]),
            };
            assert!(
                sign(&hx(S_SECNONCES[0]).try_into().unwrap(), &sk, &session).is_err(),
                "aggnonce index {}",
                agi
            );
        }

        // Zero secnonce (possible nonce reuse).
        let pks: Vec<[u8; 33]> = [0usize, 1, 2].iter().map(|&k| hx(S_PKS[k]).try_into().unwrap()).collect();
        let session = SessionContext {
            aggnonce: hx(S_AGGNONCES[0]).try_into().unwrap(),
            pks,
            tweaks: vec![],
            msg: hx(S_MSGS[0]),
        };
        assert!(sign(&hx(S_SECNONCES[1]).try_into().unwrap(), &sk, &session).is_err());
    }

    #[test]
    fn sign_with_tweaks_matches_official_vectors() {
        let sk = SecretKey::from_slice(&hx(S_SK)).unwrap();
        const T_SECNONCE: &str = "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9";
        const T_AGGNONCE: &str = "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9";
        const T_TWEAKS: [&str; 5] = [
            "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
            "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
            "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
            "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        ];
        const T_MSG: &str = "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF";
        // The tweak vectors use their OWN pubkey set — index 2 differs from
        // the sign_verify vectors in its final byte (…BA659, not …BA661).
        const T_PKS: [&str; 3] = [
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        ];

        // (tweak_indices, is_xonly, signer, expected)
        let cases: [(Vec<usize>, Vec<bool>, usize, &str); 5] = [
            (vec![0], vec![true], 2, "E28A5C66E61E178C2BA19DB77B6CF9F7E2F0F56C17918CD13135E60CC848FE91"),
            (vec![0], vec![false], 2, "38B0767798252F21BF5702C48028B095428320F73A4B14DB1E25DE58543D2D2D"),
            (vec![0, 1], vec![false, true], 2, "408A0A21C4A0F5DACAF9646AD6EB6FECD7F7A11F03ED1F48DFFF2185BC2C2408"),
            (vec![0, 1, 2, 3], vec![false, false, true, true], 2, "45ABD206E61E3DF2EC9E264A6FEC8292141A633C28586388235541F9ADE75435"),
            (vec![0, 1, 2, 3], vec![true, false, true, false], 2, "B255FDCAC27B40C7CE7848E2D3B7BF5EA0ED756DA81565AC804CCCA3E1D5D239"),
        ];
        let pks: Vec<[u8; 33]> = [1usize, 2, 0].iter().map(|&k| hx(T_PKS[k]).try_into().unwrap()).collect();
        for (ti, xo, _si, expected) in cases {
            let tweaks: Vec<Tweak> = ti
                .iter()
                .zip(xo.iter())
                .map(|(&t, &x)| Tweak { t: hx(T_TWEAKS[t]).try_into().unwrap(), is_xonly: x })
                .collect();
            let session = SessionContext {
                aggnonce: hx(T_AGGNONCE).try_into().unwrap(),
                pks: pks.clone(),
                tweaks,
                msg: hx(T_MSG),
            };
            let secnonce: [u8; 97] = hx(T_SECNONCE).try_into().unwrap();
            let psig = sign(&secnonce, &sk, &session).unwrap();
            assert_eq!(hex::encode_upper(psig), expected, "tweak case {:?}", ti);
        }

        // Tweak >= n is rejected.
        let session = SessionContext {
            aggnonce: hx(T_AGGNONCE).try_into().unwrap(),
            pks,
            tweaks: vec![Tweak { t: hx(T_TWEAKS[4]).try_into().unwrap(), is_xonly: false }],
            msg: hx(T_MSG),
        };
        assert!(sign(&hx(T_SECNONCE).try_into().unwrap(), &sk, &session).is_err());
    }

    #[test]
    fn three_devices_jointly_sign_and_verify() {
        let secp = Secp256k1::new();

        // Three devices, deterministic secrets (stand-ins for three Primes).
        let secrets = [secret(0x31), secret(0x32), secret(0x33)];
        let pks: Vec<[u8; 33]> = secrets
            .iter()
            .map(|d| PublicKey::from_secret_key(&secp, d).serialize())
            .collect();
        let agg = key_agg_sorted(&pks).unwrap();
        let agg_xonly = agg.agg_xonly;

        // A 32-byte message (e.g. a BIP341 sighash).
        let msg: [u8; 32] =
            sha256::Hash::hash(b"DOJO SIGNER MULTISIG VAULT SPEND").to_byte_array();

        // Round 1: every device generates a pubnonce.
        let mut secnonces = Vec::new();
        let mut pubnonces = Vec::new();
        for (i, d) in secrets.iter().enumerate() {
            let mut rand = [0u8; 32];
            rand[0] = i as u8 + 1;
            let pk = PublicKey::from_secret_key(&secp, d).serialize();
            let (sn, pn) = nonce_gen(rand, Some(d), &pk, Some(agg_xonly), Some(&msg), &[]).unwrap();
            secnonces.push(sn);
            pubnonces.push(pn);
        }
        let aggnonce = nonce_agg(&pubnonces).unwrap();
        // The session MUST use the SAME (sorted) key list as the vault
        // identity (key_agg is order-dependent per BIP-327: L and the
        // coefficients depend on the order). Using the raw array order here
        // would sign under a different aggregate key than the vault key.
        let session = SessionContext {
            aggnonce,
            pks: key_sort(&pks),
            tweaks: vec![],
            msg: msg.to_vec(),
        };

        // Round 2: every device signs.
        let psigs: Vec<[u8; 32]> = (0..3)
            .map(|i| sign(&secnonces[i], &secrets[i], &session).unwrap())
            .collect();

        // Every partial signature verifies; a tampered one does not.
        for i in 0..3 {
            partial_sig_verify(&psigs[i], &pubnonces[i], &pks[i], &session).unwrap();
        }
        let mut bad = psigs[0];
        bad[0] ^= 1;
        assert!(partial_sig_verify(&bad, &pubnonces[0], &pks[0], &session).is_err());

        // Aggregate and check the final BIP340 signature against the
        // aggregate x-only public key.
        let sig = partial_sig_agg(&psigs, &session).unwrap();
        let m = Message::from_digest_slice(&msg).unwrap();
        let s = schnorr::Signature::from_slice(&sig).unwrap();
        let xonly = XOnlyPublicKey::from_slice(&agg_xonly).unwrap();
        assert!(secp.verify_schnorr(&s, &m, &xonly).is_ok());
    }

    #[test]
    fn three_devices_sign_for_child_key_of_aggregate_payment_code() {
        // The real BIP47 integration: the vault spends a payment received to
        // a CHILD key of the aggregate payment code. Child pubkey B = X + IL·G
        // (IL = BIP32 child tweak, exposed by bip47::PaymentCode::child_il).
        // Signing for B is a PLAIN tweak on the aggregate key — proving the
        // three devices can spend BIP47-derived child addresses.
        let secp = Secp256k1::new();
        let secrets = [secret(0x41), secret(0x42), secret(0x43)];
        let pks: Vec<[u8; 33]> = secrets
            .iter()
            .map(|d| PublicKey::from_secret_key(&secp, d).serialize())
            .collect();
        let chaincodes: Vec<[u8; 32]> = (0..3)
            .map(|i| {
                let mut cc = [0u8; 32];
                cc[0] = i + 1;
                cc
            })
            .collect();
        let agg_pc = aggregate_payment_code(&pks, &chaincodes).unwrap();

        // Child index 1 tweak (IL) of the aggregate payment code.
        let il: [u8; 32] = agg_pc.payment_code.child_il(1).unwrap().to_be_bytes();
        let agg = key_agg_sorted(&pks).unwrap();
        let agg_xonly = agg.agg_xonly;

        let msg: [u8; 32] = sha256::Hash::hash(b"VAULT CHILD ADDRESS SPEND").to_byte_array();

        let mut secnonces = Vec::new();
        let mut pubnonces = Vec::new();
        for (i, d) in secrets.iter().enumerate() {
            let mut rand = [0u8; 32];
            rand[0] = 0x50 + i as u8;
            let pk = PublicKey::from_secret_key(&secp, d).serialize();
            let (sn, pn) = nonce_gen(rand, Some(d), &pk, Some(agg_xonly), Some(&msg), &[]).unwrap();
            secnonces.push(sn);
            pubnonces.push(pn);
        }
        let aggnonce = nonce_agg(&pubnonces).unwrap();
        // Sorted participant list, matching the aggregate payment code's
        // canonical key order (BIP-327 KeySort). key_agg is order-dependent,
        // so the session MUST aggregate the same sorted list as the vault key.
        let session = SessionContext {
            aggnonce,
            pks: key_sort(&pks),
            tweaks: vec![Tweak { t: il, is_xonly: false }],
            msg: msg.to_vec(),
        };

        let psigs: Vec<[u8; 32]> = (0..3)
            .map(|i| sign(&secnonces[i], &secrets[i], &session).unwrap())
            .collect();
        let sig = partial_sig_agg(&psigs, &session).unwrap();

        // The signature must verify against the CHILD (tweaked) x-only key
        // xonly(X + IL·G), and must NOT verify against the untweaked key.
        let tweaked = agg
            .agg_pubkey
            .add_exp_tweak(&secp, &Scalar::from_be_bytes(il).unwrap())
            .unwrap();
        let child_xonly = tweaked.x_only_public_key().0;
        let m = Message::from_digest_slice(&msg).unwrap();
        let s = schnorr::Signature::from_slice(&sig).unwrap();
        assert!(secp.verify_schnorr(&s, &m, &child_xonly).is_ok());

        let xonly = XOnlyPublicKey::from_slice(&agg_xonly).unwrap();
        assert!(secp.verify_schnorr(&s, &m, &xonly).is_err());
    }

    // ---- Official BIP-327 nonce generation vectors ----
    // Source: bitcoin/bips bip-0327/vectors/nonce_gen_vectors.json
    // These validate the exact NonceGen byte serialization (aux XOR, prefixed
    // message, counter-at-end) against the reference implementation.
    const NG_PK: &str =
        "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766";
    const NG_PK2: &str =
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9";

    #[test]
    fn nonce_gen_matches_official_bip327_vectors() {
        let rand = [0x0f; 32];
        let sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let pk: [u8; 33] = hx(NG_PK).try_into().unwrap();
        let aggpk: [u8; 32] = [0x07; 32];
        let extra: Vec<u8> = vec![0x08; 32];

        // Case 0: 32-byte message.
        let msg: Vec<u8> = vec![0x01; 32];
        let (sn, pn) = nonce_gen(rand, Some(&sk), &pk, Some(aggpk), Some(&msg), &extra).unwrap();
        assert_eq!(
            hex::encode_upper(sn),
            "B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB64\
             95B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2\
             024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766"
                .replace(' ', "")
        );
        assert_eq!(
            hex::encode_upper(pn),
            "02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF\
             02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A"
                .replace(' ', "")
        );

        // Case 1: empty message.
        let (sn, pn) = nonce_gen(rand, Some(&sk), &pk, Some(aggpk), Some(&[]), &extra).unwrap();
        assert_eq!(
            hex::encode_upper(sn),
            "E862B068500320088138468D47E0E6F147E01B6024244AE45EAC40ACE5929B9F\
             0789E051170B9E705D0B9EB49049A323BBBBB206D8E05C19F46C6228742AA7A9\
             024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766"
                .replace(' ', "")
        );
        assert_eq!(
            hex::encode_upper(pn),
            "023034FA5E2679F01EE66E12225882A7A48CC66719B1B9D3B6C4DBD743EFEDA2C5\
             03F3FD6F01EB3A8E9CB315D73F1F3D287CAFBB44AB321153C6287F407600205109"
                .replace(' ', "")
        );

        // Case 2: 38-byte message (exercises the u64 length prefix).
        let msg: Vec<u8> = vec![0x26; 38];
        let (sn, pn) = nonce_gen(rand, Some(&sk), &pk, Some(aggpk), Some(&msg), &extra).unwrap();
        assert_eq!(
            hex::encode_upper(sn),
            "3221975ACBDEA6820EABF02A02B7F27D3A8EF68EE42787B88CBEFD9AA06AF363\
             2EE85B1A61D8EF31126D4663A00DD96E9D1D4959E72D70FE5EBB6E7696EBA66F\
             024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766"
                .replace(' ', "")
        );
        assert_eq!(
            hex::encode_upper(pn),
            "02E5BBC21C69270F59BD634FCBFA281BE9D76601295345112C58954625BF23793A\
             021307511C79F95D38ACACFF1B4DA98228B77E65AA216AD075E9673286EFB4EAF3"
                .replace(' ', "")
        );

        // Case 3: no secret key, no aggpk, no message, no extra input.
        let pk3: [u8; 33] = hx(NG_PK2).try_into().unwrap();
        let (sn, pn) = nonce_gen(rand, None, &pk3, None, None, &[]).unwrap();
        assert_eq!(
            hex::encode_upper(sn),
            "89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D\
             0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD2897\
             02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
                .replace(' ', "")
        );
        assert_eq!(
            hex::encode_upper(pn),
            "02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C00\
             0299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786"
                .replace(' ', "")
        );
    }

    // ---- Official BIP-327 nonce aggregation vectors ----
    // Source: bitcoin/bips bip-0327/vectors/nonce_agg_vectors.json
    const NA_PNONCES: [&str; 7] = [
        "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
        "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
    ];

    fn np(i: usize) -> [u8; 66] {
        hx(NA_PNONCES[i]).try_into().unwrap()
    }

    #[test]
    fn nonce_agg_matches_official_bip327_vectors() {
        // Valid: two ordinary pubnonces.
        let agg = nonce_agg(&[np(0), np(1)]).unwrap();
        assert_eq!(
            hex::encode_upper(agg),
            "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B\
             024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8"
                .replace(' ', "")
        );

        // Valid: second halves cancel to the point at infinity (33 zero bytes).
        let agg = nonce_agg(&[np(2), np(3)]).unwrap();
        assert_eq!(
            hex::encode_upper(agg),
            "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B\
             000000000000000000000000000000000000000000000000000000000000000000"
                .replace(' ', "")
        );

        // Error cases: wrong tag 0x04, x not on curve, x exceeds field size.
        assert!(nonce_agg(&[np(0), np(4)]).is_err());
        assert!(nonce_agg(&[np(5), np(1)]).is_err());
        assert!(nonce_agg(&[np(6), np(1)]).is_err());
    }
}
