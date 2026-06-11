//
// SPDX-License-Identifier: AGPL-3.0-only
//
use rand::{CryptoRng, Rng};
use core::hint::black_box;
use sha2::Digest as _;

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};

use crate::{
    CiphertextMessageType, ContentHint, Result, SenderCertificate, SignalProtocolError,
    kem, spqxdh, xhmqv,
};
use crate::pure_falcon;

// Sealed RingXKEM-XHMQV: clean split between classical XHMQV (Ristretto255)
// and post-quantum RingXKEM (MLKEM-1024) with Falcon-512 signatures.

type Mac = Vec<u8>;
type SessionKey = Vec<u8>;

const PROTOCOL_VERSION: u8 = 0x54; // arbitrary distinct version byte

const LABEL_SEALING_PHASE: &[u8] = b"Signal_SealedRingXKEMXHMQV_Sealing_20260101";
const LABEL_FINAL_KEYS: &[u8] = b"Signal_SealedRingXKEMXHMQV_Final_20260101";
const SESSION_LABEL: &[u8] = b"Signal_SealedRingXKEMXHMQV_Session_20260101";

#[derive(Clone)]
pub struct ClassicalBundle {
    pub identity_key: xhmqv::RistrettoPublicKey, // IKr
    pub signed_prekey: xhmqv::RistrettoPublicKey, // SPKr
    pub signed_prekey_signature: Vec<u8>,         // Ed25519(sig(SPKr))
    pub one_time_prekey: Option<xhmqv::RistrettoPublicKey>, // OPKr
    pub ed25519_verify_key: Ed25519VerifyingKey,  // classical verifying key
}

#[derive(Clone)]
pub struct PqBundle {
    pub receiver_falcon_vkey: Vec<u8>, // VKr^Q
    pub mlkem_identity_key: kem::PublicKey, // EKr^Q
    pub mlkem_signed_prekey: kem::PublicKey, // EKrhat^Q
    pub mlkem_signed_prekey_signature: Vec<u8>, // sig_VKr^Q( EKrhat^Q )
}

#[derive(Clone)]
pub struct SealedRingXkemXhmqvPreKeyBundle {
    pub classical: ClassicalBundle,
    pub pq: PqBundle,
    pub registration_id: u32,
}

#[derive(Debug)]
pub struct SealedMessage {
    version: u8,
    // Ristretto255 compressed 32B
    ec_ephemeral: [u8; xhmqv::PUBLIC_KEY_LENGTH],
    kem_ciphertext1: Vec<u8>,
    kem_ciphertext2: Vec<u8>,
    inner_msg_ct: Vec<u8>,
}

#[derive(Debug)]
pub struct SealedMessageData {
    msg: SealedMessage,
    mac: Mac,
    sealing_key: Vec<u8>,
}

impl SealedMessageData {
    fn serialize_without_mac_inner(msg: &SealedMessage) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(msg.version);
        out.extend_from_slice(&msg.ec_ephemeral);
        out.extend_from_slice(&(msg.kem_ciphertext1.len() as u32).to_le_bytes());
        out.extend_from_slice(&msg.kem_ciphertext1);
        out.extend_from_slice(&(msg.kem_ciphertext2.len() as u32).to_le_bytes());
        out.extend_from_slice(&msg.kem_ciphertext2);
        out.extend_from_slice(&(msg.inner_msg_ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&msg.inner_msg_ct);
        out
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Self::serialize_without_mac_inner(&self.msg);
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn sealing_key(&self) -> &[u8] {
        &self.sealing_key
    }

    pub fn ec_ephemeral(&self) -> &[u8; xhmqv::PUBLIC_KEY_LENGTH] {
        &self.msg.ec_ephemeral
    }
}

fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    for p in parts {
        h.update(*p);
    }
    h.finalize().into()
}

fn verify_classical_spk_sig(bundle: &ClassicalBundle) -> Result<()> {
    let spk_bytes = bundle.signed_prekey.serialize();
    let sig = Ed25519Signature::from_slice(&bundle.signed_prekey_signature)
        .map_err(|_| SignalProtocolError::InvalidArgument("bad ed25519 sig".into()))?;
    bundle
        .ed25519_verify_key
        .verify_strict(&spk_bytes, &sig)
        .map_err(|_| SignalProtocolError::InvalidSealedSenderMessage("bad SPK signature".into()))
}

fn verify_pq_spk_sig(pq: &PqBundle) -> Result<()> {
    let spk_bytes = pq.mlkem_signed_prekey.serialize();
    let ok = pure_falcon::verify_bytes(&pq.receiver_falcon_vkey, &spk_bytes, &pq.mlkem_signed_prekey_signature);
    if ok { Ok(()) } else { Err(SignalProtocolError::InvalidSealedSenderMessage("bad PQ SPK signature".into())) }
}

pub struct SendParams<'a> {
    pub sender_classical_identity: &'a xhmqv::RistrettoKeyPair, // IKs
    pub sender_falcon_sk: &'a pure_falcon::SecretKey,           // SKs^Q
    pub sender_falcon_vk: &'a [u8],                             // VKs^Q
    pub cert: &'a SenderCertificate,
    pub registration_id: u32,
    pub msg_type: CiphertextMessageType,
    pub content_hint: ContentHint,
}

pub struct RecvParams<'a> {
    // Classical receiver private data
    pub receiver_identity: &'a xhmqv::RistrettoKeyPair,
    pub receiver_signed_prekey: &'a xhmqv::RistrettoKeyPair,
    pub receiver_one_time_prekey: Option<&'a xhmqv::RistrettoKeyPair>,
    // PQ receiver private data
    pub pq_identity_kp: &'a kem::KeyPair,       // secret for EKr^Q
    pub pq_signed_prekey_kp: &'a kem::KeyPair,  // secret for EKrhat^Q
    pub receiver_falcon_vk: &'a [u8],           // VKr^Q
}

#[derive(Debug)]
pub struct RecvResult {
    pub sender_certificate: SenderCertificate,
    pub registration_id: u32,
    pub msg_type: CiphertextMessageType,
    pub content_hint: ContentHint,
    pub session_key: SessionKey,
}

#[derive(Clone, Copy)]
struct CkKseal {
    ck: [u8; 32],
    kseal: [u8; 32],
}

fn derive_ck_kseal(
    ss1: &[u8],
    ss2: &[u8],
    ss_iii: &[u8],
    receiver_identity: &xhmqv::RistrettoPublicKey,
    receiver_signed_prekey: &xhmqv::RistrettoPublicKey,
    receiver_one_time_prekey: Option<&xhmqv::RistrettoPublicKey>,
    eph_bytes: &[u8; xhmqv::PUBLIC_KEY_LENGTH],
    pq_identity_key_bytes: &[u8],
    pq_signed_prekey_bytes: &[u8],
    receiver_falcon_vk: &[u8],
    ct1: &[u8],
    ct2: &[u8],
) -> CkKseal {
    let mut sealing_and_chain_key = [0u8; 64];
    let mut transcript = Vec::new();
    transcript.extend_from_slice(ss1);
    transcript.extend_from_slice(ss2);
    transcript.extend_from_slice(ss_iii);
    transcript.extend_from_slice(&receiver_identity.serialize());
    transcript.extend_from_slice(&receiver_signed_prekey.serialize());
    if let Some(opk) = receiver_one_time_prekey {
        transcript.extend_from_slice(&opk.serialize());
    }
    transcript.extend_from_slice(eph_bytes);
    transcript.extend_from_slice(pq_identity_key_bytes);
    transcript.extend_from_slice(pq_signed_prekey_bytes);
    transcript.extend_from_slice(receiver_falcon_vk);
    transcript.extend_from_slice(ct1);
    transcript.extend_from_slice(ct2);
    hkdf::Hkdf::<sha2::Sha256>::new(None, &transcript)
        .expand(LABEL_SEALING_PHASE, &mut sealing_and_chain_key)
        .expect("valid length");
    let (ck, kseal) = sealing_and_chain_key.split_at(32);
    CkKseal {
        ck: ck.try_into().expect("32"),
        kseal: kseal.try_into().expect("32"),
    }
}

struct ParsedInner {
    registration_id: u32,
    msg_type: CiphertextMessageType,
    content_hint: ContentHint,
    sender_iks: xhmqv::RistrettoPublicKey,
    vks: Vec<u8>,
    sigma: Vec<u8>,
    sender_certificate: SenderCertificate,
}

fn validated_parse_inner(kseal: &[u8], inner_ct: &[u8]) -> Result<ParsedInner> {
    let inner = spqxdh::aes_256_ctr_decrypt(inner_ct, kseal)?;
    if inner.len() < 6 + 32 + 2 + 2 + 4 {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "inner too short".into(),
        ));
    }
    let registration_id = u32::from_le_bytes(inner[0..4].try_into().unwrap());
    let msg_type = CiphertextMessageType::try_from(inner[4])
        .map_err(|_| SignalProtocolError::InvalidSealedSenderMessage("invalid message type".into()))?;
    let content_hint = ContentHint::from(inner[5] as u32);
    let sender_iks = xhmqv::RistrettoPublicKey::deserialize(&inner[6..6 + 32])?;
    let mut o = 6 + 32;
    let vks_len = u16::from_le_bytes(inner[o..o + 2].try_into().unwrap()) as usize;
    o += 2;
    if inner.len() < o + vks_len + 2 {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "inner too short".into(),
        ));
    }
    let vks = inner[o..o + vks_len].to_vec();
    o += vks_len;
    let sig_len = u16::from_le_bytes(inner[o..o + 2].try_into().unwrap()) as usize;
    o += 2;
    if inner.len() < o + sig_len + 4 {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "inner too short".into(),
        ));
    }
    let sigma = inner[o..o + sig_len].to_vec();
    o += sig_len;
    let cert_len = u32::from_le_bytes(inner[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    if inner.len() < o + cert_len {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "inner too short".into(),
        ));
    }
    let sender_certificate = SenderCertificate::deserialize(&inner[o..o + cert_len])?;
    Ok(ParsedInner { registration_id, msg_type, content_hint, sender_iks, vks, sigma, sender_certificate })
}

fn build_inner_message(
    registration_id: u32,
    msg_type: CiphertextMessageType,
    content_hint: ContentHint,
    sender_iks: &xhmqv::RistrettoPublicKey,
    vks: &[u8],
    sigma: &[u8],
    cert_bytes: &[u8],
    kseal: &[u8],
) -> Result<Vec<u8>> {
    let mut inner = Vec::with_capacity(4 + 1 + 1 + 32 + 2 + vks.len() + 2 + sigma.len() + 4 + cert_bytes.len());
    inner.extend_from_slice(&registration_id.to_le_bytes());
    inner.push(msg_type as u8);
    inner.push(content_hint.to_u32() as u8);
    inner.extend_from_slice(&sender_iks.serialize());
    let vks_len: u16 = vks.len().try_into().unwrap();
    inner.extend_from_slice(&vks_len.to_le_bytes());
    inner.extend_from_slice(vks);
    let sig_len: u16 = sigma.len().try_into().unwrap();
    inner.extend_from_slice(&sig_len.to_le_bytes());
    inner.extend_from_slice(sigma);
    inner.extend_from_slice(&(cert_bytes.len() as u32).to_le_bytes());
    inner.extend_from_slice(cert_bytes);
    spqxdh::aes_256_ctr_encrypt(&inner, kseal)
}

fn verified_parse_outer<'a>(
    msg_bytes: &'a [u8],
) -> Result<(
    &'a [u8],               // encoded (without MAC)
    &'a [u8],               // expected_mac
    [u8; xhmqv::PUBLIC_KEY_LENGTH], // eph
    &'a [u8],               // ct1
    &'a [u8],               // ct2
    &'a [u8],               // inner_ct
)> {
    if msg_bytes.len() < 33 {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let (encoded, expected_mac) = msg_bytes.split_at(msg_bytes.len() - 32);
    let version = encoded[0];
    if version != PROTOCOL_VERSION {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let mut idx = 1;
    if encoded.len() < idx + xhmqv::PUBLIC_KEY_LENGTH {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let mut eph = [0u8; xhmqv::PUBLIC_KEY_LENGTH];
    eph.copy_from_slice(&encoded[idx..idx + xhmqv::PUBLIC_KEY_LENGTH]);
    idx += xhmqv::PUBLIC_KEY_LENGTH;
    if encoded.len() < idx + 4 {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let len1 = u32::from_le_bytes(encoded[idx..idx + 4].try_into().unwrap()) as usize;
    idx += 4;
    if encoded.len() < idx + len1 {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let ct1 = &encoded[idx..idx + len1];
    idx += len1;
    if encoded.len() < idx + 4 {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let len2 = u32::from_le_bytes(encoded[idx..idx + 4].try_into().unwrap()) as usize;
    idx += 4;
    if encoded.len() < idx + len2 {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let ct2 = &encoded[idx..idx + len2];
    idx += len2;
    if encoded.len() < idx + 4 {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let inner_len = u32::from_le_bytes(encoded[idx..idx + 4].try_into().unwrap()) as usize;
    idx += 4;
    if encoded.len() < idx + inner_len {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let inner_ct = &encoded[idx..idx + inner_len];
    Ok((encoded, expected_mac, eph, ct1, ct2, inner_ct))
}

fn falcon_transcript_hash(
    vkr_vk: &[u8],
    vks_vk: &[u8],
    ek_id_bytes: &[u8],
    ek_spk_bytes: &[u8],
    ct1: &[u8],
    ct2: &[u8],
) -> [u8; 32] {
    sha256_concat(&[vkr_vk, vks_vk, ek_id_bytes, ek_spk_bytes, ct1, ct2])
}
pub fn send<R: Rng + CryptoRng>(
    bundle: &SealedRingXkemXhmqvPreKeyBundle,
    params: &SendParams,
    rng: &mut R,
) -> Result<(SealedMessageData, SessionKey)> {
    // Verify bundle signatures
    verify_classical_spk_sig(&bundle.classical)?;
    verify_pq_spk_sig(&bundle.pq)?;

    // PQ encapsulations
    let (ss1, ct1) = bundle.pq.mlkem_identity_key.encapsulate(rng)?;
    let (ss2, ct2) = bundle.pq.mlkem_signed_prekey.encapsulate(rng)?;

    // XHMQV (classical)
    let x = xhmqv::xhmqv_send(
        params.sender_classical_identity,
        &bundle.classical.identity_key,
        &bundle.classical.signed_prekey,
        bundle.classical.one_time_prekey.as_ref(),
        rng,
    );

    // Derive CK || Kseal
    let eph_bytes = x.ephemeral_public.serialize();
    let pq_id_bytes = bundle.pq.mlkem_identity_key.serialize();
    let pq_spk_bytes = bundle.pq.mlkem_signed_prekey.serialize();
    let ck_kseal = derive_ck_kseal(
        &ss1,
        &ss2,
        &x.shared_secret_1,
        &bundle.classical.identity_key,
        &bundle.classical.signed_prekey,
        bundle.classical.one_time_prekey.as_ref(),
        &eph_bytes,
        &pq_id_bytes,
        &pq_spk_bytes,
        &bundle.pq.receiver_falcon_vkey,
        &ct1,
        &ct2,
    );

    // Falcon signature over PQ transcript only
    let pq_transcript_hash = falcon_transcript_hash(
        &bundle.pq.receiver_falcon_vkey,
        params.sender_falcon_vk,
        &pq_id_bytes,
        &pq_spk_bytes,
        &ct1,
        &ct2,
    );
    let sigma = pure_falcon::sign(params.sender_falcon_sk, &pq_transcript_hash);
    // Compute a second, unused Falcon signature for benchmarking 2-ring cost.
    // Use black_box to prevent the compiler from optimizing it away.
    let _sigma2 = black_box(pure_falcon::sign(
        black_box(params.sender_falcon_sk),
        black_box(&pq_transcript_hash),
    ));
    let _ = black_box(&_sigma2);

    // XHMQV identity secret (ss_iv) and derive session||mac
    let mut session_and_mac = [0u8; 64];
    let mut final_parts = Vec::new();
    final_parts.extend_from_slice(&ck_kseal.ck);
    final_parts.extend_from_slice(&x.shared_secret_2); // ss_iv
    final_parts.extend_from_slice(&params.sender_classical_identity.public_key.serialize());
    final_parts.extend_from_slice(params.sender_falcon_vk);
    final_parts.extend_from_slice(&sigma);
    hkdf::Hkdf::<sha2::Sha256>::new(None, &final_parts)
        .expand(LABEL_FINAL_KEYS, &mut session_and_mac)
        .expect("valid length");
    let (session_key, mac_key) = session_and_mac.split_at(32);

    // Build inner message to roughly match SPQXDH + our PQ fields
    // Format: reg_id(4) | msg_type(1) | content_hint(1) | IKs_ristretto(32)
    //         | len(VKs^Q)(2) | VKs^Q | len(sig)(2) | sig | len(cert)(4) | cert
    let cert_bytes = params.cert.serialized()?;
    let inner_ct = build_inner_message(
        params.registration_id,
        params.msg_type,
        params.content_hint,
        &params.sender_classical_identity.public_key,
        params.sender_falcon_vk,
        &sigma,
        &cert_bytes,
        &ck_kseal.kseal,
    )?;

    let msg = SealedMessage {
        version: PROTOCOL_VERSION,
        ec_ephemeral: eph_bytes,
        kem_ciphertext1: ct1.to_vec(),
        kem_ciphertext2: ct2.to_vec(),
        inner_msg_ct: inner_ct,
    };
    let encoded_wo_mac = SealedMessageData::serialize_without_mac_inner(&msg);
    let mac = crate::crypto::hmac_sha256(mac_key, &encoded_wo_mac).to_vec();

    Ok((
        SealedMessageData { msg, mac, sealing_key: ck_kseal.kseal.to_vec() },
        session_key.to_vec(),
    ))
}

pub fn recv(
    msg_bytes: &[u8],
    recv_params: &RecvParams,
) -> Result<RecvResult> {
    let (encoded, expected_mac, eph, ct1, ct2, inner_ct) = verified_parse_outer(msg_bytes)?;

    // Decapsulate PQ
    let ss1 = recv_params.pq_identity_kp.secret_key.decapsulate(&ct1.into())?;
    let ss2 = recv_params.pq_signed_prekey_kp.secret_key.decapsulate(&ct2.into())?;

    // XHMQV phase 1 (receiver): compute ss_iii and keep b_secret for phase 2
    let eph_pk = xhmqv::RistrettoPublicKey::deserialize(&eph)?;
    let rec1 = xhmqv::xhmqv_recv1(
        recv_params.receiver_identity,
        recv_params.receiver_signed_prekey,
        recv_params.receiver_one_time_prekey,
        &eph_pk,
    );

    // Derive CK || Kseal
    let ck_kseal = derive_ck_kseal(
        &ss1,
        &ss2,
        &rec1.shared_secret_1,
        &recv_params.receiver_identity.public_key,
        &recv_params.receiver_signed_prekey.public_key,
        recv_params
            .receiver_one_time_prekey
            .as_ref()
            .map(|kp| &kp.public_key),
        &eph,
        &recv_params.pq_identity_kp.public_key.serialize(),
        &recv_params.pq_signed_prekey_kp.public_key.serialize(),
        recv_params.receiver_falcon_vk,
        ct1,
        ct2,
    );

    // Decrypt inner and parse
    let ParsedInner { registration_id, msg_type, content_hint, sender_iks, vks, sigma, sender_certificate } =
        validated_parse_inner(&ck_kseal.kseal, inner_ct)?;

    // XHMQV phase 2 (receiver): compute ss_iv using the parsed IKs and kept b_secret
    let rec2 = xhmqv::xhmqv_recv2(&rec1.b_secret, &sender_iks, &eph_pk);
    let ss_iv = rec2.shared_secret_2;

    // Derive session || mac
    let mut session_and_mac = [0u8; 64];
    let mut final_parts = Vec::new();
    final_parts.extend_from_slice(&ck_kseal.ck);
    final_parts.extend_from_slice(&ss_iv);
    final_parts.extend_from_slice(&sender_iks.serialize());
    final_parts.extend_from_slice(&vks);
    final_parts.extend_from_slice(&sigma);
    hkdf::Hkdf::<sha2::Sha256>::new(None, &final_parts)
        .expand(LABEL_FINAL_KEYS, &mut session_and_mac)
        .expect("valid length");
    let (_session_key, mac_key) = session_and_mac.split_at(32);

    // Verify MAC
    let mac = crate::crypto::hmac_sha256(mac_key, encoded);
    if mac != expected_mac { return Err(SignalProtocolError::BadSealedPQXDHMac); }

    // Verify Falcon signature on PQ transcript
    let pq_transcript_hash = falcon_transcript_hash(
        recv_params.receiver_falcon_vk,
        &vks,
        &recv_params.pq_identity_kp.public_key.serialize(),
        &recv_params.pq_signed_prekey_kp.public_key.serialize(),
        ct1,
        ct2,
    );
    let ok = pure_falcon::verify_bytes(&vks, &pq_transcript_hash, &sigma);
    // Perform a second, unused Falcon verification to model 2-ring verify cost.
    let _ok2 = black_box(pure_falcon::verify_bytes(
        black_box(&vks),
        black_box(&pq_transcript_hash),
        black_box(&sigma),
    ));
    let _ = black_box(&_ok2);
    if !ok { return Err(SignalProtocolError::InvalidSealedSenderMessage("invalid Falcon signature".into())); }

    Ok(RecvResult {
        sender_certificate,
        registration_id,
        msg_type,
        content_hint,
        session_key: session_and_mac[0..32].to_vec(),
    })
}

// Session initialization helpers (derive DR keys from session key)
use crate::ratchet::{ChainKey, RootKey};

fn derive_session_keys(session_key: &[u8]) -> (RootKey, ChainKey, [u8; 32]) {
    let mut secrets = [0u8; 96];
    hkdf::Hkdf::<sha2::Sha256>::new(None, session_key)
        .expand(SESSION_LABEL, &mut secrets)
        .expect("valid length");
    let (rk, ck, pqr) = (&secrets[0..32], &secrets[32..64], &secrets[64..96]);
    (RootKey::new(rk.try_into().unwrap()), ChainKey::new(ck.try_into().unwrap(), 0), pqr.try_into().unwrap())
}

use crate::{identity_key::IdentityKey, protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION, state::SessionState};
use libsignal_core::curve::{KeyPair as X25519KeyPair, PublicKey};

fn spqr_chain_params(self_connection: bool) -> spqr::ChainParams {
    #[allow(clippy::needless_update)]
    spqr::ChainParams {
        max_jump: if self_connection {
            u32::MAX
        } else {
            crate::consts::MAX_FORWARD_JUMPS.try_into().expect("should be <4B")
        },
        max_ooo_keys: crate::consts::MAX_MESSAGE_KEYS.try_into().expect("should be <4B"),
        ..Default::default()
    }
}

pub fn initialize_alice_session<R: Rng + CryptoRng>(
    session_key: &[u8],
    their_ratchet_key: &PublicKey,
    local_identity: &IdentityKey,
    their_identity_key: &IdentityKey,
    our_base_key: &PublicKey,
    local_registration_id: u32,
    remote_registration_id: u32,
    rng: &mut R,
) -> Result<crate::SessionRecord> {
    let (root_key, chain_key, pqr_key) = derive_session_keys(session_key);

    let sending_ratchet_key = X25519KeyPair::generate(rng);
    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        their_ratchet_key,
        &sending_ratchet_key.private_key,
    )?;

    let self_session = local_identity == their_identity_key;
    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::A2B,
        min_version: spqr::Version::V0,
        chain_params: spqr_chain_params(self_session),
    })
    .map_err(|e| {
        SignalProtocolError::InvalidArgument(format!(
            "post-quantum ratchet: error creating initial A2B state: {e}"
        ))
    })?;

    let mut session = SessionState::new(
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
        local_identity,
        their_identity_key,
        &sending_chain_root_key,
        our_base_key,
        pqr_state,
    )
    .with_receiver_chain(their_ratchet_key, &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    session.set_local_registration_id(local_registration_id);
    session.set_remote_registration_id(remote_registration_id);
    Ok(crate::SessionRecord::new(session))
}

pub fn initialize_bob_session(
    session_key: &[u8],
    their_base_key: &PublicKey,
    local_identity: &IdentityKey,
    their_identity_key: &IdentityKey,
    our_ratchet_key_pair: &X25519KeyPair,
    local_registration_id: u32,
    remote_registration_id: u32,
) -> Result<crate::SessionRecord> {
    let (root_key, receiver_chain_key, pqr_key) = derive_session_keys(session_key);

    let self_session = local_identity == their_identity_key;
    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::B2A,
        min_version: spqr::Version::V0,
        chain_params: spqr_chain_params(self_session),
    })
    .map_err(|e| {
        SignalProtocolError::InvalidArgument(format!(
            "post-quantum ratchet: error creating initial B2A state: {e}"
        ))
    })?;

    let mut session = SessionState::new(
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
        local_identity,
        their_identity_key,
        &root_key,
        their_base_key,
        pqr_state,
    )
    .with_sender_chain(our_ratchet_key_pair, &receiver_chain_key);

    session.set_local_registration_id(local_registration_id);
    session.set_remote_registration_id(remote_registration_id);
    Ok(crate::SessionRecord::new(session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    fn make_classical_bundle<R: Rng + CryptoRng>(rng: &mut R) -> (ClassicalBundle, xhmqv::RistrettoKeyPair, xhmqv::RistrettoKeyPair, Option<xhmqv::RistrettoKeyPair>, ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let ik = xhmqv::RistrettoKeyPair::generate(rng);
        let spk = xhmqv::RistrettoKeyPair::generate(rng);
        let opk = Some(xhmqv::RistrettoKeyPair::generate(rng));
        // Generate 32-byte seed and construct key to avoid rand_core version mismatch
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let ed_vk = ed_sk.verifying_key();
        let spk_sig = ed_sk.sign(&spk.public_key.serialize()).to_vec();
        (
            ClassicalBundle {
                identity_key: ik.public_key,
                signed_prekey: spk.public_key,
                signed_prekey_signature: spk_sig,
                one_time_prekey: opk.as_ref().map(|k| k.public_key),
                ed25519_verify_key: ed_vk,
            },
            ik,
            spk,
            opk,
            ed_sk,
        )
    }

    fn make_pq_bundle<R: Rng + CryptoRng>(rng: &mut R) -> (PqBundle, kem::KeyPair, kem::KeyPair, (Vec<u8>, pure_falcon::SecretKey)) {
        let ek_id = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
        let ek_spk = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
        let (vkr_pk, vkr_sk) = pure_falcon::keypair();
        let spk_sig = pure_falcon::sign(&vkr_sk, &ek_spk.public_key.serialize());
        (
            PqBundle {
                receiver_falcon_vkey: vkr_pk.clone(),
                mlkem_identity_key: ek_id.public_key.clone(),
                mlkem_signed_prekey: ek_spk.public_key.clone(),
                mlkem_signed_prekey_signature: spk_sig,
            },
            ek_id,
            ek_spk,
            (vkr_pk, vkr_sk),
        )
    }

    fn make_sender_falcon<R: Rng + CryptoRng>(_rng: &mut R) -> (Vec<u8>, pure_falcon::SecretKey) {
        pure_falcon::keypair()
    }

    use crate::{IdentityKeyPair, Timestamp, KeyPair, DeviceId};

    fn make_sender_cert<R: Rng + CryptoRng>(rng: &mut R) -> SenderCertificate {
        // Reuse SPQXDH helper path: construct a small certificate with a fresh identity key
        // using libsignal's existing flow.
        let trust_root = KeyPair::generate(rng);
        let server_key = KeyPair::generate(rng);
        let server_cert = crate::ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, rng).unwrap();
        let device_id = DeviceId::new(42).unwrap();
        let expires = Timestamp::from_epoch_millis(1605722925);
        let id_pair = IdentityKeyPair::generate(rng);
        crate::SenderCertificate::new(
            "user-aci".to_string(),
            Some("+14150000000".to_string()),
            *id_pair.public_key(),
            device_id,
            expires,
            server_cert,
            &server_key.private_key,
            rng,
        ).unwrap()
    }

    #[test]
    fn test_roundtrip() {
        let mut rng = OsRng.unwrap_err();
        // Receiver bundle
        let (classical_bundle, ik_kp, spk_kp, opk_kp, _ed_sk) = make_classical_bundle(&mut rng);
        let (pq_bundle, pq_id_kp, pq_spk_kp, (vkr_pk, _vkr_sk)) = make_pq_bundle(&mut rng);
        let bundle = SealedRingXkemXhmqvPreKeyBundle { classical: classical_bundle, pq: pq_bundle, registration_id: 7 };

        // Sender materials
        let sender_classical = xhmqv::RistrettoKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(&mut rng);
        let (vks_pk, vks_sk) = make_sender_falcon(&mut rng);

        let params = SendParams {
            sender_classical_identity: &sender_classical,
            sender_falcon_sk: &vks_sk,
            sender_falcon_vk: &vks_pk,
            cert: &sender_cert,
            registration_id: 12345,
            msg_type: CiphertextMessageType::Whisper,
            content_hint: ContentHint::Default,
        };

        let (msg, session_key) = send(&bundle, &params, &mut rng).expect("send");
        let serialized = msg.serialize();

        let recv_params = RecvParams {
            receiver_identity: &ik_kp,
            receiver_signed_prekey: &spk_kp,
            receiver_one_time_prekey: opk_kp.as_ref(),
            pq_identity_kp: &pq_id_kp,
            pq_signed_prekey_kp: &pq_spk_kp,
            receiver_falcon_vk: &vkr_pk,
        };
        let rr = recv(&serialized, &recv_params).expect("recv");

        assert_eq!(rr.registration_id, 12345);
        assert_eq!(rr.msg_type, CiphertextMessageType::Whisper);
        assert_eq!(rr.content_hint, ContentHint::Default);
        assert_eq!(rr.sender_certificate.serialized().unwrap(), sender_cert.serialized().unwrap());
        assert_eq!(rr.session_key, session_key);
    }

    #[test]
    fn test_roundtrip_no_onetime_prekey() {
        let mut rng = OsRng.unwrap_err();
        // Receiver bundle with NO OPK
        let (mut classical_bundle, ik_kp, spk_kp, _opk_kp, _ed_sk) = make_classical_bundle(&mut rng);
        classical_bundle.one_time_prekey = None;
        let (pq_bundle, pq_id_kp, pq_spk_kp, (vkr_pk, _vkr_sk)) = make_pq_bundle(&mut rng);
        let bundle = SealedRingXkemXhmqvPreKeyBundle { classical: classical_bundle, pq: pq_bundle, registration_id: 7 };

        // Sender materials
        let sender_classical = xhmqv::RistrettoKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(&mut rng);
        let (vks_pk, vks_sk) = make_sender_falcon(&mut rng);

        let params = SendParams {
            sender_classical_identity: &sender_classical,
            sender_falcon_sk: &vks_sk,
            sender_falcon_vk: &vks_pk,
            cert: &sender_cert,
            registration_id: 12345,
            msg_type: CiphertextMessageType::Whisper,
            content_hint: ContentHint::Default,
        };

        let (msg, session_key) = send(&bundle, &params, &mut rng).expect("send");
        let serialized = msg.serialize();

        let recv_params = RecvParams {
            receiver_identity: &ik_kp,
            receiver_signed_prekey: &spk_kp,
            receiver_one_time_prekey: None,
            pq_identity_kp: &pq_id_kp,
            pq_signed_prekey_kp: &pq_spk_kp,
            receiver_falcon_vk: &vkr_pk,
        };
        let rr = recv(&serialized, &recv_params).expect("recv");

        assert_eq!(rr.registration_id, 12345);
        assert_eq!(rr.msg_type, CiphertextMessageType::Whisper);
        assert_eq!(rr.content_hint, ContentHint::Default);
        assert_eq!(rr.sender_certificate.serialized().unwrap(), sender_cert.serialized().unwrap());
        assert_eq!(rr.session_key, session_key);
    }

    #[test]
    fn test_mac_tampering_detected() {
        let mut rng = OsRng.unwrap_err();
        let (classical_bundle, ik_kp, spk_kp, opk_kp, _ed_sk) = make_classical_bundle(&mut rng);
        let (pq_bundle, pq_id_kp, pq_spk_kp, (vkr_pk, _vkr_sk)) = make_pq_bundle(&mut rng);
        let bundle = SealedRingXkemXhmqvPreKeyBundle { classical: classical_bundle, pq: pq_bundle, registration_id: 7 };

        let sender_classical = xhmqv::RistrettoKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(&mut rng);
        let (vks_pk, vks_sk) = make_sender_falcon(&mut rng);

        let params = SendParams {
            sender_classical_identity: &sender_classical,
            sender_falcon_sk: &vks_sk,
            sender_falcon_vk: &vks_pk,
            cert: &sender_cert,
            registration_id: 111,
            msg_type: CiphertextMessageType::Whisper,
            content_hint: ContentHint::Default,
        };
        let (msg, _sk) = send(&bundle, &params, &mut rng).expect("send");
        let mut serialized = msg.serialize();
        // Flip a bit in MAC
        let last = serialized.len() - 1;
        serialized[last] ^= 0x01;

        let recv_params = RecvParams {
            receiver_identity: &ik_kp,
            receiver_signed_prekey: &spk_kp,
            receiver_one_time_prekey: opk_kp.as_ref(),
            pq_identity_kp: &pq_id_kp,
            pq_signed_prekey_kp: &pq_spk_kp,
            receiver_falcon_vk: &vkr_pk,
        };
        let err = recv(&serialized, &recv_params).unwrap_err();
        match err {
            SignalProtocolError::BadSealedPQXDHMac => {}
            other => panic!("expected MAC failure, got {:?}", other),
        }
    }

    #[test]
    fn test_inner_tampering_detected() {
        let mut rng = OsRng.unwrap_err();
        let (classical_bundle, ik_kp, spk_kp, opk_kp, _ed_sk) = make_classical_bundle(&mut rng);
        let (pq_bundle, pq_id_kp, pq_spk_kp, (vkr_pk, _vkr_sk)) = make_pq_bundle(&mut rng);
        let bundle = SealedRingXkemXhmqvPreKeyBundle { classical: classical_bundle, pq: pq_bundle, registration_id: 7 };

        let sender_classical = xhmqv::RistrettoKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(&mut rng);
        let (vks_pk, vks_sk) = make_sender_falcon(&mut rng);

        let params = SendParams {
            sender_classical_identity: &sender_classical,
            sender_falcon_sk: &vks_sk,
            sender_falcon_vk: &vks_pk,
            cert: &sender_cert,
            registration_id: 111,
            msg_type: CiphertextMessageType::Whisper,
            content_hint: ContentHint::Default,
        };
        let (msg, _sk) = send(&bundle, &params, &mut rng).expect("send");
        let mut serialized = msg.serialize();
        // Flip a bit in inner ciphertext region
        // version(1) + eph(32) + 4 + ct1 + 4 + ct2 + 4 -> start of inner
        let mut idx = 1 + xhmqv::PUBLIC_KEY_LENGTH;
        let ct1_len = u32::from_le_bytes(serialized[idx..idx+4].try_into().unwrap()) as usize; idx += 4 + ct1_len;
        let ct2_len = u32::from_le_bytes(serialized[idx..idx+4].try_into().unwrap()) as usize; idx += 4 + ct2_len;
        // inner len at idx
        let _inner_len = u32::from_le_bytes(serialized[idx..idx+4].try_into().unwrap()) as usize; idx += 4;
        // flip the first byte of inner ciphertext
        serialized[idx] ^= 0x80;

        let recv_params = RecvParams {
            receiver_identity: &ik_kp,
            receiver_signed_prekey: &spk_kp,
            receiver_one_time_prekey: opk_kp.as_ref(),
            pq_identity_kp: &pq_id_kp,
            pq_signed_prekey_kp: &pq_spk_kp,
            receiver_falcon_vk: &vkr_pk,
        };
        let err = recv(&serialized, &recv_params).unwrap_err();
        match err {
            SignalProtocolError::BadSealedPQXDHMac => {}
            other => panic!("expected MAC failure, got {:?}", other),
        }
    }

    #[test]
    fn test_bad_pq_spk_signature_rejected_in_send() {
        let mut rng = OsRng.unwrap_err();
        let (classical_bundle, _ik_kp, _spk_kp, _opk_kp, _ed_sk) = make_classical_bundle(&mut rng);
        let (mut pq_bundle, _pq_id_kp, _pq_spk_kp, _vkr) = make_pq_bundle(&mut rng);
        // Corrupt the PQ SPK signature
        if !pq_bundle.mlkem_signed_prekey_signature.is_empty() {
            pq_bundle.mlkem_signed_prekey_signature[0] ^= 0x01;
        }
        let bundle = SealedRingXkemXhmqvPreKeyBundle { classical: classical_bundle, pq: pq_bundle, registration_id: 7 };

        let sender_classical = xhmqv::RistrettoKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(&mut rng);
        let (vks_pk, vks_sk) = make_sender_falcon(&mut rng);
        let params = SendParams {
            sender_classical_identity: &sender_classical,
            sender_falcon_sk: &vks_sk,
            sender_falcon_vk: &vks_pk,
            cert: &sender_cert,
            registration_id: 1,
            msg_type: CiphertextMessageType::Whisper,
            content_hint: ContentHint::Default,
        };
        let err = send(&bundle, &params, &mut rng).unwrap_err();
        match err {
            SignalProtocolError::InvalidSealedSenderMessage(s) => assert!(s.contains("PQ SPK")),
            other => panic!("expected invalid PQ SPK signature, got {:?}", other),
        }
    }

    #[test]
    fn test_bad_classical_spk_signature_rejected_in_send() {
        let mut rng = OsRng.unwrap_err();
        let (mut classical_bundle, _ik_kp, _spk_kp, _opk_kp, _ed_sk) = make_classical_bundle(&mut rng);
        // Corrupt the classical SPK signature
        if !classical_bundle.signed_prekey_signature.is_empty() {
            classical_bundle.signed_prekey_signature[0] ^= 0x01;
        }
        let (pq_bundle, _pq_id_kp, _pq_spk_kp, _vkr) = make_pq_bundle(&mut rng);
        let bundle = SealedRingXkemXhmqvPreKeyBundle { classical: classical_bundle, pq: pq_bundle, registration_id: 7 };

        let sender_classical = xhmqv::RistrettoKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(&mut rng);
        let (vks_pk, vks_sk) = make_sender_falcon(&mut rng);
        let params = SendParams {
            sender_classical_identity: &sender_classical,
            sender_falcon_sk: &vks_sk,
            sender_falcon_vk: &vks_pk,
            cert: &sender_cert,
            registration_id: 1,
            msg_type: CiphertextMessageType::Whisper,
            content_hint: ContentHint::Default,
        };
        let err = send(&bundle, &params, &mut rng).unwrap_err();
        match err {
            SignalProtocolError::InvalidSealedSenderMessage(s) => assert!(s.contains("SPK signature")),
            other => panic!("expected invalid SPK signature, got {:?}", other),
        }
    }
    #[test]
    fn test_size_breakdown() {
        let mut rng = OsRng.unwrap_err();
        // Receiver bundle
        let (classical_bundle, _ik_kp, _spk_kp, _opk_kp, _ed_sk) = make_classical_bundle(&mut rng);
        let (pq_bundle, _pq_id_kp, _pq_spk_kp, (_vkr_pk, _vkr_sk)) = make_pq_bundle(&mut rng);
        let bundle = SealedRingXkemXhmqvPreKeyBundle { classical: classical_bundle, pq: pq_bundle, registration_id: 7 };

        // Sender materials
        let sender_classical = xhmqv::RistrettoKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(&mut rng);
        let (vks_pk, vks_sk) = make_sender_falcon(&mut rng);

        let params = SendParams {
            sender_classical_identity: &sender_classical,
            sender_falcon_sk: &vks_sk,
            sender_falcon_vk: &vks_pk,
            cert: &sender_cert,
            registration_id: 12345,
            msg_type: CiphertextMessageType::Whisper,
            content_hint: ContentHint::Default,
        };

        let (msg, _session_key) = send(&bundle, &params, &mut rng).expect("send");
        let serialized = msg.serialize();

        // Parse sizes
        let ephem_len = xhmqv::PUBLIC_KEY_LENGTH;
        // Deserialize easy fields from our format
        let mut idx = 1; // skip version
        idx += ephem_len;
        let ct1_len = u32::from_le_bytes(serialized[idx..idx+4].try_into().unwrap()) as usize; idx += 4;
        idx += ct1_len;
        let ct2_len = u32::from_le_bytes(serialized[idx..idx+4].try_into().unwrap()) as usize; idx += 4;
        idx += ct2_len;
        let inner_len = u32::from_le_bytes(serialized[idx..idx+4].try_into().unwrap()) as usize; idx += 4;
        let inner_ct = &serialized[idx..idx+inner_len];

        // Decrypt inner to extract VKs^Q and sigma lengths
        let inner_pt = spqxdh::aes_256_ctr_decrypt(inner_ct, msg.sealing_key()).expect("inner decrypt");
        // reg(4) + type(1) + hint(1) + IKs(32)
        let mut o = 4 + 1 + 1 + 32;
        let vks_len = u16::from_le_bytes(inner_pt[o..o+2].try_into().unwrap()) as usize; o += 2;
        o += vks_len;
        let sigma_len = u16::from_le_bytes(inner_pt[o..o+2].try_into().unwrap()) as usize; o += 2;
        o += sigma_len;
        let cert_len = u32::from_le_bytes(inner_pt[o..o+4].try_into().unwrap()) as usize;

        let mac_len = 32;
        let total = serialized.len();

        println!("SealedRingXKEMXHMQV size breakdown:");
        println!("  Ephemeral (ristretto): {}", ephem_len);
        println!("  KEM ct1: {}", ct1_len);
        println!("  KEM ct2: {}", ct2_len);
        println!("  Inner total: {} (IKs: 32, VKs: {}, sigma: {}, cert: {})", inner_len, vks_len, sigma_len, cert_len);
        println!("  MAC: {}", mac_len);
        println!("  TOTAL: {}", total);
    }
}
