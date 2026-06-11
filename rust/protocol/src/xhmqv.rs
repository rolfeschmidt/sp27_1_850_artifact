//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! XHMQV key agreement using Ristretto255.
//!
//! This module implements the XHMQV protocol as described in the SPQXDH specification,
//! using Ristretto255 as the underlying group. Ristretto255 is used instead of X25519
//! because XHMQV requires group operations (point addition, scalar multiplication)
//! that X25519 does not expose.
//!
//! The XHMQV protocol provides implicit key authentication by combining multiple
//! DH keys into aggregated points before performing the key agreement.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256, Sha512};
use curve25519_dalek::traits::VartimeMultiscalarMul;
use subtle::ConstantTimeEq;

use crate::{Result, SignalProtocolError};

/// Length of a compressed Ristretto255 point in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// Length of a Ristretto255 scalar in bytes.
pub const PRIVATE_KEY_LENGTH: usize = 32;
/// Length of a shared secret in bytes.
pub const SHARED_SECRET_LENGTH: usize = 32;

/// A Ristretto255 public key for use in XHMQV.
#[derive(Clone, Copy, Debug, Eq)]
pub struct RistrettoPublicKey {
    point: RistrettoPoint,
    compressed: CompressedRistretto,
}

impl RistrettoPublicKey {
    /// Create a public key from a Ristretto point.
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self {
            point,
            compressed: point.compress(),
        }
    }

    /// Deserialize a public key from bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SignalProtocolError::InvalidArgument(format!(
                "invalid public key length: expected {}, got {}",
                PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }
        let compressed = CompressedRistretto::from_slice(bytes)
            .map_err(|_| SignalProtocolError::InvalidArgument("invalid compressed point".into()))?;
        let point = compressed
            .decompress()
            .ok_or_else(|| SignalProtocolError::InvalidArgument("invalid Ristretto point".into()))?;
        Ok(Self { point, compressed })
    }

    /// Serialize the public key to bytes.
    pub fn serialize(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.compressed.to_bytes()
    }

    /// Get the underlying Ristretto point.
    pub fn point(&self) -> &RistrettoPoint {
        &self.point
    }
}

impl PartialEq for RistrettoPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.compressed.ct_eq(&other.compressed).into()
    }
}

impl std::ops::Add for RistrettoPublicKey {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::from_point(self.point + rhs.point)
    }
}

impl std::ops::Add<&RistrettoPublicKey> for RistrettoPublicKey {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self::from_point(self.point + rhs.point)
    }
}

impl std::ops::Mul<&Scalar> for &RistrettoPublicKey {
    type Output = RistrettoPublicKey;

    fn mul(self, scalar: &Scalar) -> Self::Output {
        RistrettoPublicKey::from_point(self.point * scalar)
    }
}

/// A Ristretto255 private key for use in XHMQV.
#[derive(Clone)]
pub struct RistrettoPrivateKey {
    scalar: Scalar,
}

impl RistrettoPrivateKey {
    /// Generate a new random private key.
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Self {
            scalar: Scalar::from_bytes_mod_order_wide(&bytes),
        }
    }

    /// Create a private key from a scalar.
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { scalar }
    }

    /// Deserialize a private key from bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PRIVATE_KEY_LENGTH {
            return Err(SignalProtocolError::InvalidArgument(format!(
                "invalid private key length: expected {}, got {}",
                PRIVATE_KEY_LENGTH,
                bytes.len()
            )));
        }
        let bytes_array: [u8; 32] = bytes.try_into().unwrap();
        // Use from_bytes_mod_order to accept any 32 bytes
        let scalar = Scalar::from_bytes_mod_order(bytes_array);
        Ok(Self { scalar })
    }

    /// Serialize the private key to bytes.
    pub fn serialize(&self) -> [u8; PRIVATE_KEY_LENGTH] {
        self.scalar.to_bytes()
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> RistrettoPublicKey {
        let point = &self.scalar * RISTRETTO_BASEPOINT_TABLE;
        RistrettoPublicKey::from_point(point)
    }

    /// Get the underlying scalar.
    pub fn scalar(&self) -> &Scalar {
        &self.scalar
    }

    /// Perform a Diffie-Hellman agreement with a public key.
    pub fn agree(&self, their_public: &RistrettoPublicKey) -> [u8; SHARED_SECRET_LENGTH] {
        let shared_point = self.scalar * their_public.point;
        shared_point.compress().to_bytes()
    }

    /// Multiply this scalar by another scalar.
    pub fn mul_scalar(&self, other: &Scalar) -> Self {
        Self {
            scalar: self.scalar * other,
        }
    }
}

impl std::ops::Add for &RistrettoPrivateKey {
    type Output = RistrettoPrivateKey;

    fn add(self, rhs: Self) -> Self::Output {
        RistrettoPrivateKey {
            scalar: self.scalar + rhs.scalar,
        }
    }
}

impl std::ops::Mul<&Scalar> for &RistrettoPrivateKey {
    type Output = RistrettoPrivateKey;

    fn mul(self, scalar: &Scalar) -> Self::Output {
        RistrettoPrivateKey {
            scalar: self.scalar * scalar,
        }
    }
}

/// A Ristretto255 key pair for use in XHMQV.
#[derive(Clone)]
pub struct RistrettoKeyPair {
    pub public_key: RistrettoPublicKey,
    pub private_key: RistrettoPrivateKey,
}

impl RistrettoKeyPair {
    /// Generate a new random key pair.
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let private_key = RistrettoPrivateKey::generate(rng);
        let public_key = private_key.public_key();
        Self {
            public_key,
            private_key,
        }
    }

    /// Create a key pair from a private key.
    pub fn from_private(private_key: RistrettoPrivateKey) -> Self {
        let public_key = private_key.public_key();
        Self {
            public_key,
            private_key,
        }
    }
}

/// Domain separation labels for XHMQV hash functions.
const XHMQV_E1_LABEL: &[u8] = b"Signal_XHMQV_e1_20260101";
const XHMQV_E2_LABEL: &[u8] = b"Signal_XHMQV_e2_20260101";
const XHMQV_D_LABEL: &[u8] = b"Signal_XHMQV_d_20260101";
const XHMQV_SEALING_LABEL: &[u8] = b"Signal_XHMQV_Sealing_20260101";
const XHMQV_FINAL_KEYS_LABEL: &[u8] = b"Signal_XHMQV_Final_20260101";

/// Hash public keys to produce scalar e1.
fn hash_e1(
    identity_key: &RistrettoPublicKey,
    signed_prekey: &RistrettoPublicKey,
    one_time_prekey: Option<&RistrettoPublicKey>,
) -> Scalar {
    // 128-bit hash reduced to scalar to match Ristretto255 security level
    let mut h = Sha256::new();
    h.update(XHMQV_E1_LABEL);
    h.update(identity_key.serialize());
    h.update(signed_prekey.serialize());
    if let Some(opk) = one_time_prekey { h.update(opk.serialize()); }
    let digest = h.finalize();
    let mut wide = [0u8; 32];
    wide[..16].copy_from_slice(&digest[..16]);
    Scalar::from_bytes_mod_order(wide)
}

/// Hash public keys to produce scalar e2.
fn hash_e2(
    identity_key: &RistrettoPublicKey,
    signed_prekey: &RistrettoPublicKey,
    one_time_prekey: Option<&RistrettoPublicKey>,
) -> Scalar {
    let mut h = Sha256::new();
    h.update(XHMQV_E2_LABEL);
    h.update(identity_key.serialize());
    h.update(signed_prekey.serialize());
    if let Some(opk) = one_time_prekey { h.update(opk.serialize()); }
    let digest = h.finalize();
    let mut wide = [0u8; 32];
    wide[..16].copy_from_slice(&digest[..16]);
    Scalar::from_bytes_mod_order(wide)
}

/// Hash sender's identity and ephemeral keys to produce scalar d.
fn hash_d(
    sender_identity: &RistrettoPublicKey,
    sender_ephemeral: &RistrettoPublicKey,
) -> Scalar {
    let mut h = Sha256::new();
    h.update(XHMQV_D_LABEL);
    h.update(sender_identity.serialize());
    h.update(sender_ephemeral.serialize());
    let digest = h.finalize();
    let mut wide = [0u8; 32];
    wide[..16].copy_from_slice(&digest[..16]);
    Scalar::from_bytes_mod_order(wide)
}

/// Compute the aggregated receiver public key B.
///
/// B = OPK_r + [e1]*IK_r + [e2]*SPK_r (when OPK is present)
/// B = [e1]*IK_r + [e2]*SPK_r (when OPK is absent)
fn compute_aggregated_receiver_key(
    receiver_identity: &RistrettoPublicKey,
    receiver_signed_prekey: &RistrettoPublicKey,
    receiver_one_time_prekey: Option<&RistrettoPublicKey>,
    e1: &Scalar,
    e2: &Scalar,
) -> RistrettoPublicKey {
    match receiver_one_time_prekey {
        Some(opk) => {
            let scalars = vec![*e1, *e2, Scalar::ONE];
            let points = vec![*receiver_identity.point(), *receiver_signed_prekey.point(), *opk.point()];
            RistrettoPublicKey::from_point(RistrettoPoint::vartime_multiscalar_mul(scalars, points))
        }
        None => {
            let scalars = vec![*e1, *e2];
            let points = vec![*receiver_identity.point(), *receiver_signed_prekey.point()];
            RistrettoPublicKey::from_point(RistrettoPoint::vartime_multiscalar_mul(scalars, points))
        }
    }
}

/// Compute the aggregated receiver secret key.
///
/// b = opk_sk + e1*ik_sk + e2*spk_sk (when OPK is present)
/// b = e1*ik_sk + e2*spk_sk (when OPK is absent)
fn compute_aggregated_receiver_secret(
    receiver_identity_sk: &RistrettoPrivateKey,
    receiver_signed_prekey_sk: &RistrettoPrivateKey,
    receiver_one_time_prekey_sk: Option<&RistrettoPrivateKey>,
    e1: &Scalar,
    e2: &Scalar,
) -> RistrettoPrivateKey {
    let ik_term = receiver_identity_sk * e1;
    let spk_term = receiver_signed_prekey_sk * e2;

    let combined = match receiver_one_time_prekey_sk {
        Some(opk_sk) => opk_sk.scalar + ik_term.scalar + spk_term.scalar,
        None => ik_term.scalar + spk_term.scalar,
    };

    RistrettoPrivateKey::from_scalar(combined)
}

/// Result of an XHMQV key agreement from the sender's perspective.
#[derive(Clone)]
pub struct XhmqvSendResult {
    /// The ephemeral public key to send to the receiver.
    pub ephemeral_public: RistrettoPublicKey,
    /// The first shared secret (from ephemeral key).
    pub shared_secret_1: [u8; SHARED_SECRET_LENGTH],
    /// The second shared secret (from identity key).
    pub shared_secret_2: [u8; SHARED_SECRET_LENGTH],
}

/// Perform XHMQV key agreement from the sender's perspective.
///
/// This computes:
/// - e1 = hash1(IK_r, SPK_r, OPK_r)
/// - e2 = hash2(IK_r, SPK_r, OPK_r)
/// - B = OPK_r + [e1]*IK_r + [e2]*SPK_r
/// - ss_1 = [ek_s.sk] * B
/// - d = hash3(IK_s, EK_s)
/// - ss_2 = [d * ik_s.sk] * B
pub fn xhmqv_send<R: Rng + CryptoRng>(
    sender_identity: &RistrettoKeyPair,
    receiver_identity: &RistrettoPublicKey,
    receiver_signed_prekey: &RistrettoPublicKey,
    receiver_one_time_prekey: Option<&RistrettoPublicKey>,
    rng: &mut R,
) -> XhmqvSendResult {
    // Generate ephemeral key pair
    let ephemeral = RistrettoKeyPair::generate(rng);

    // Compute e1, e2
    let e1 = hash_e1(receiver_identity, receiver_signed_prekey, receiver_one_time_prekey);
    let e2 = hash_e2(receiver_identity, receiver_signed_prekey, receiver_one_time_prekey);

    // Compute aggregated receiver key B
    let b = compute_aggregated_receiver_key(
        receiver_identity,
        receiver_signed_prekey,
        receiver_one_time_prekey,
        &e1,
        &e2,
    );

    // Compute first shared secret: ss_1 = [ek_s.sk] * B
    let shared_secret_1 = ephemeral.private_key.agree(&b);

    // Compute d = hash(IK_s, EK_s)
    let d = hash_d(&sender_identity.public_key, &ephemeral.public_key);

    // Compute second shared secret: ss_2 = [d * ik_s.sk] * B
    let d_times_ik = sender_identity.private_key.mul_scalar(&d);
    let shared_secret_2 = d_times_ik.agree(&b);

    XhmqvSendResult {
        ephemeral_public: ephemeral.public_key,
        shared_secret_1,
        shared_secret_2,
    }
}

/// Result of an XHMQV key agreement from the receiver's perspective.
#[derive(Clone)]
pub struct XhmqvRecv1Result {
    /// The aggregated receiver secret needed in next round
    pub b_secret: RistrettoPrivateKey,
    /// The first shared secret (from ephemeral key).
    pub shared_secret_1: [u8; SHARED_SECRET_LENGTH],
}

/// Result of an XHMQV key agreement from the receiver's perspective.
#[derive(Clone)]
pub struct XhmqvRecv2Result {
    /// The second shared secret (from identity key).
    pub shared_secret_2: [u8; SHARED_SECRET_LENGTH],
}

/// Perform XHMQV key agreement from the receiver's perspective.
///
/// This computes:
/// - e1 = hash1(IK_r, SPK_r, OPK_r)
/// - e2 = hash2(IK_r, SPK_r, OPK_r)
/// - b = opk_sk + e1*ik_sk + e2*spk_sk (combined receiver secret)
/// - ss_1 = [b] * EK_s
/// - d = hash3(IK_s, EK_s)
/// - ss_2 = [b * d] * IK_s
pub fn xhmqv_recv1(
    receiver_identity: &RistrettoKeyPair,
    receiver_signed_prekey: &RistrettoKeyPair,
    receiver_one_time_prekey: Option<&RistrettoKeyPair>,
    sender_ephemeral: &RistrettoPublicKey,
) -> XhmqvRecv1Result {
    // Compute e1, e2
    let e1 = hash_e1(
        &receiver_identity.public_key,
        &receiver_signed_prekey.public_key,
        receiver_one_time_prekey.as_ref().map(|kp| &kp.public_key),
    );
    let e2 = hash_e2(
        &receiver_identity.public_key,
        &receiver_signed_prekey.public_key,
        receiver_one_time_prekey.as_ref().map(|kp| &kp.public_key),
    );

    // Compute aggregated receiver secret key b
    let b_secret = compute_aggregated_receiver_secret(
        &receiver_identity.private_key,
        &receiver_signed_prekey.private_key,
        receiver_one_time_prekey.as_ref().map(|kp| &kp.private_key),
        &e1,
        &e2,
    );

    // Compute first shared secret: ss_1 = [b] * EK_s
    let shared_secret_1 = b_secret.agree(sender_ephemeral);


    XhmqvRecv1Result {
        b_secret,
        shared_secret_1,
    }
}



/// Perform XHMQV key agreement from the receiver's perspective.
///
/// This computes:
/// - e1 = hash1(IK_r, SPK_r, OPK_r)
/// - e2 = hash2(IK_r, SPK_r, OPK_r)
/// - b = opk_sk + e1*ik_sk + e2*spk_sk (combined receiver secret)
/// - ss_1 = [b] * EK_s
/// - d = hash3(IK_s, EK_s)
/// - ss_2 = [b * d] * IK_s
pub fn xhmqv_recv2(
    b_secret: &RistrettoPrivateKey,
    sender_identity: &RistrettoPublicKey,
    sender_ephemeral: &RistrettoPublicKey,
) -> XhmqvRecv2Result {

    // Compute d = hash(IK_s, EK_s)
    let d = hash_d(sender_identity, sender_ephemeral);

    // Compute second shared secret: ss_2 = [b * d] * IK_s
    // This matches sender's [d * IK_s.sk] * B because:
    //   sender:   [d * IK_s.sk] * B = [d * IK_s.sk * b] * G
    //   receiver: [b * d] * IK_s = [b * d * IK_s.sk] * G
    let b_times_d = b_secret.mul_scalar(&d);
    let shared_secret_2 = b_times_d.agree(sender_identity);

    XhmqvRecv2Result {
        shared_secret_2,
    }
}

#[derive(Clone)]
pub struct XhmqvRecvResult {
    pub shared_secret_1: [u8; SHARED_SECRET_LENGTH],
    pub shared_secret_2: [u8; SHARED_SECRET_LENGTH],
}

// Intentionally no combined xhmqv_recv: for sealed/anonymous variants,
// the receiver must perform recv1, then unseal inner to learn IKs, then recv2.

// ---------------- Top-level XHMQV message (2-phase) ----------------

#[derive(Clone, Debug)]
pub struct XhmqvMessage {
    pub version: u8,
    pub ephemeral: [u8; PUBLIC_KEY_LENGTH],
    pub signed_prekey_id: u32,
    pub one_time_prekey_id: Option<u32>,
    pub inner_ct: Vec<u8>, // AES-CTR over inner payload
}

#[derive(Clone, Debug)]
pub struct XhmqvSendMessageResult {
    pub message: XhmqvMessage,
    pub session_key: [u8; 32],
    pub sealing_key: [u8; 32],
}

fn derive_kseal(
    ss1: &[u8],
    receiver_identity: &RistrettoPublicKey,
    receiver_signed_prekey: &RistrettoPublicKey,
    receiver_one_time_prekey: Option<&RistrettoPublicKey>,
    sender_ephemeral: &RistrettoPublicKey,
) -> [u8; 32] {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(ss1);
    transcript.extend_from_slice(&receiver_identity.serialize());
    transcript.extend_from_slice(&receiver_signed_prekey.serialize());
    if let Some(opk) = receiver_one_time_prekey {
        transcript.extend_from_slice(&opk.serialize());
    }
    transcript.extend_from_slice(&sender_ephemeral.serialize());
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &transcript)
        .expand(XHMQV_SEALING_LABEL, &mut out)
        .expect("valid length");
    out
}

fn derive_session_key(
    ss1: &[u8],
    ss2: &[u8],
    sender_identity: &RistrettoPublicKey,
    sender_ephemeral: &RistrettoPublicKey,
) -> [u8; 32] {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(ss1);
    transcript.extend_from_slice(ss2);
    transcript.extend_from_slice(&sender_identity.serialize());
    transcript.extend_from_slice(&sender_ephemeral.serialize());
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &transcript)
        .expand(XHMQV_FINAL_KEYS_LABEL, &mut out)
        .expect("valid length");
    out
}

pub fn message_send<R: Rng + CryptoRng>(
    sender_identity: &RistrettoKeyPair,
    receiver_identity: (&RistrettoPublicKey, u32),
    receiver_signed_prekey: (&RistrettoPublicKey, u32),
    receiver_one_time_prekey: Option<(&RistrettoPublicKey, u32)>,
    rng: &mut R,
) -> XhmqvSendMessageResult {
    let rcv_id = receiver_identity.0;
    let rcv_spk = receiver_signed_prekey.0;
    let rcv_opk = receiver_one_time_prekey.map(|(k, _)| k);

    let send = xhmqv_send(sender_identity, rcv_id, rcv_spk, rcv_opk, rng);
    let kseal = derive_kseal(
        &send.shared_secret_1,
        rcv_id,
        rcv_spk,
        rcv_opk,
        &send.ephemeral_public,
    );
    // Inner contains only sender IKs for this module
    let mut inner = Vec::with_capacity(32);
    inner.extend_from_slice(&sender_identity.public_key.serialize());
    let inner_ct = crate::spqxdh::aes_256_ctr_encrypt(&inner, &kseal).expect("encrypt");

    let msg = XhmqvMessage {
        version: 1,
        ephemeral: send.ephemeral_public.serialize(),
        signed_prekey_id: receiver_signed_prekey.1,
        one_time_prekey_id: receiver_one_time_prekey.map(|(_, id)| id),
        inner_ct,
    };

    let session_key = derive_session_key(
        &send.shared_secret_1,
        &send.shared_secret_2,
        &sender_identity.public_key,
        &send.ephemeral_public,
    );

    XhmqvSendMessageResult { message: msg, session_key, sealing_key: kseal }
}

pub fn message_receive(
    msg: &XhmqvMessage,
    receiver_identity: &RistrettoKeyPair,
    receiver_signed_prekey: &RistrettoKeyPair,
    receiver_one_time_prekey: Option<&RistrettoKeyPair>,
) -> Result<([u8; 32], RistrettoPublicKey)> {
    let eph = RistrettoPublicKey::deserialize(&msg.ephemeral)?;
    let rec1 = xhmqv_recv1(
        receiver_identity,
        receiver_signed_prekey,
        receiver_one_time_prekey,
        &eph,
    );
    let kseal = derive_kseal(
        &rec1.shared_secret_1,
        &receiver_identity.public_key,
        &receiver_signed_prekey.public_key,
        receiver_one_time_prekey.as_ref().map(|kp| &kp.public_key),
        &eph,
    );
    let inner = crate::spqxdh::aes_256_ctr_decrypt(&msg.inner_ct, &kseal)?;
    if inner.len() != 32 {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "inner length invalid".into(),
        ));
    }
    let sender_iks = RistrettoPublicKey::deserialize(&inner)?;

    let rec2 = xhmqv_recv2(&rec1.b_secret, &sender_iks, &eph);
    let session_key = derive_session_key(&rec1.shared_secret_1, &rec2.shared_secret_2, &sender_iks, &eph);
    Ok((session_key, sender_iks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    #[test]
    fn test_key_generation_and_serialization() {
        let mut rng = OsRng.unwrap_err();
        let keypair = RistrettoKeyPair::generate(&mut rng);

        // Test public key serialization roundtrip
        let serialized = keypair.public_key.serialize();
        let deserialized = RistrettoPublicKey::deserialize(&serialized).unwrap();
        assert_eq!(keypair.public_key, deserialized);

        // Test private key serialization roundtrip
        let private_serialized = keypair.private_key.serialize();
        let private_deserialized = RistrettoPrivateKey::deserialize(&private_serialized).unwrap();
        assert_eq!(
            private_deserialized.public_key(),
            keypair.public_key
        );
    }

    #[test]
    fn test_basic_dh_agreement() {
        let mut rng = OsRng.unwrap_err();

        let alice = RistrettoKeyPair::generate(&mut rng);
        let bob = RistrettoKeyPair::generate(&mut rng);

        let alice_shared = alice.private_key.agree(&bob.public_key);
        let bob_shared = bob.private_key.agree(&alice.public_key);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_xhmqv_with_one_time_prekey() {
        let mut rng = OsRng.unwrap_err();

        // Sender keys
        let sender_identity = RistrettoKeyPair::generate(&mut rng);

        // Receiver keys
        let receiver_identity = RistrettoKeyPair::generate(&mut rng);
        let receiver_signed_prekey = RistrettoKeyPair::generate(&mut rng);
        let receiver_one_time_prekey = RistrettoKeyPair::generate(&mut rng);

        // Sender performs key agreement
        let send_result = xhmqv_send(
            &sender_identity,
            &receiver_identity.public_key,
            &receiver_signed_prekey.public_key,
            Some(&receiver_one_time_prekey.public_key),
            &mut rng,
        );

        // Receiver performs two-phase
        let r1 = xhmqv_recv1(
            &receiver_identity,
            &receiver_signed_prekey,
            Some(&receiver_one_time_prekey),
            &send_result.ephemeral_public,
        );
        let r2 = xhmqv_recv2(&r1.b_secret, &sender_identity.public_key, &send_result.ephemeral_public);

        // Both should derive the same shared secrets
        assert_eq!(send_result.shared_secret_1, r1.shared_secret_1);
        assert_eq!(send_result.shared_secret_2, r2.shared_secret_2);
    }

    #[test]
    fn test_xhmqv_without_one_time_prekey() {
        let mut rng = OsRng.unwrap_err();

        // Sender keys
        let sender_identity = RistrettoKeyPair::generate(&mut rng);

        // Receiver keys
        let receiver_identity = RistrettoKeyPair::generate(&mut rng);
        let receiver_signed_prekey = RistrettoKeyPair::generate(&mut rng);

        // Sender performs key agreement without one-time prekey
        let send_result = xhmqv_send(
            &sender_identity,
            &receiver_identity.public_key,
            &receiver_signed_prekey.public_key,
            None,
            &mut rng,
        );

        // Receiver performs two-phase
        let r1 = xhmqv_recv1(
            &receiver_identity,
            &receiver_signed_prekey,
            None,
            &send_result.ephemeral_public,
        );
        let r2 = xhmqv_recv2(&r1.b_secret, &sender_identity.public_key, &send_result.ephemeral_public);

        // Both should derive the same shared secrets
        assert_eq!(send_result.shared_secret_1, r1.shared_secret_1);
        assert_eq!(send_result.shared_secret_2, r2.shared_secret_2);
    }

    #[test]
    fn test_different_sessions_produce_different_secrets() {
        let mut rng = OsRng.unwrap_err();

        let sender_identity = RistrettoKeyPair::generate(&mut rng);
        let receiver_identity = RistrettoKeyPair::generate(&mut rng);
        let receiver_signed_prekey = RistrettoKeyPair::generate(&mut rng);

        let result1 = xhmqv_send(
            &sender_identity,
            &receiver_identity.public_key,
            &receiver_signed_prekey.public_key,
            None,
            &mut rng,
        );

        let result2 = xhmqv_send(
            &sender_identity,
            &receiver_identity.public_key,
            &receiver_signed_prekey.public_key,
            None,
            &mut rng,
        );

        // Different ephemeral keys should produce different secrets
        assert_ne!(result1.ephemeral_public, result2.ephemeral_public);
        assert_ne!(result1.shared_secret_1, result2.shared_secret_1);
        assert_ne!(result1.shared_secret_2, result2.shared_secret_2);
    }

    #[test]
    fn test_message_roundtrip_with_one_time_prekey() {
        let mut rng = OsRng.unwrap_err();

        // Sender keys
        let sender_identity = RistrettoKeyPair::generate(&mut rng);

        // Receiver keys + ids
        let receiver_identity = RistrettoKeyPair::generate(&mut rng);
        let receiver_signed_prekey = RistrettoKeyPair::generate(&mut rng);
        let receiver_one_time_prekey = RistrettoKeyPair::generate(&mut rng);
        let ik_id: u32 = 11;
        let spk_id: u32 = 22;
        let opk_id: u32 = 33;

        // Sender constructs message
        let send_msg = message_send(
            &sender_identity,
            (&receiver_identity.public_key, ik_id),
            (&receiver_signed_prekey.public_key, spk_id),
            Some((&receiver_one_time_prekey.public_key, opk_id)),
            &mut rng,
        );

        // Receiver processes message
        let (session_key_recv, sender_iks_recv) = message_receive(
            &send_msg.message,
            &receiver_identity,
            &receiver_signed_prekey,
            Some(&receiver_one_time_prekey),
        )
        .expect("receive ok");

        assert_eq!(send_msg.session_key, session_key_recv);
        assert_eq!(sender_identity.public_key, sender_iks_recv);
    }

    #[test]
    fn test_message_roundtrip_without_one_time_prekey() {
        let mut rng = OsRng.unwrap_err();

        // Sender keys
        let sender_identity = RistrettoKeyPair::generate(&mut rng);

        // Receiver keys + ids (no OPK)
        let receiver_identity = RistrettoKeyPair::generate(&mut rng);
        let receiver_signed_prekey = RistrettoKeyPair::generate(&mut rng);
        let ik_id: u32 = 44;
        let spk_id: u32 = 55;

        // Sender constructs message
        let send_msg = message_send(
            &sender_identity,
            (&receiver_identity.public_key, ik_id),
            (&receiver_signed_prekey.public_key, spk_id),
            None,
            &mut rng,
        );

        // Receiver processes message
        let (session_key_recv, sender_iks_recv) = message_receive(
            &send_msg.message,
            &receiver_identity,
            &receiver_signed_prekey,
            None,
        )
        .expect("receive ok");

        assert_eq!(send_msg.session_key, session_key_recv);
        assert_eq!(sender_identity.public_key, sender_iks_recv);
    }
}
