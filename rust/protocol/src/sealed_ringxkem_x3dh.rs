//
// SPDX-License-Identifier: AGPL-3.0-only
//
use rand::{CryptoRng, Rng};
use core::hint::black_box;

use sha2::Digest as _;

use crate::{
    CiphertextMessageType, ContentHint, IdentityKey, IdentityKeyPair, PreKeyBundle, Result,
    SenderCertificate, SignalProtocolError, kem, spqxdh,
};
use crate::pure_falcon;

use libsignal_core::curve::{KeyPair as X25519KeyPair, PublicKey};

type Mac = Vec<u8>;
type SessionKey = Vec<u8>;

const PROTOCOL_VERSION: u8 = 0x55; // distinct version for RingXKEM+X3DH

const LABEL_SEALING_PHASE: &[u8] = b"Signal_SealedRingXKEMX3DH_Sealing_20260101";
const LABEL_FINAL_KEYS: &[u8] = b"Signal_SealedRingXKEMX3DH_LocalIdentity_Mixin_20260101";
const SESSION_LABEL: &[u8] = b"Signal_SealedRingXKEMX3DH_Session_20260101";

fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    for p in parts {
        h.update(*p);
    }
    h.finalize().into()
}

#[derive(Clone)]
pub struct PqBundle {
    pub receiver_falcon_vkey: Vec<u8>,        // VKr^Q
    pub mlkem_identity_key: kem::PublicKey,   // EKr^Q
    pub mlkem_signed_prekey: kem::PublicKey,  // EKrhat^Q
    pub mlkem_signed_prekey_signature: Vec<u8>, // sig_VKr^Q(EKrhat^Q)
}

#[derive(Clone)]
pub struct SealedRingXkemX3dhPreKeyBundle {
    pub classical: PreKeyBundle, // X25519-based classical bundle
    pub pq: PqBundle,
    pub registration_id: u32,
}

#[derive(Debug)]
pub struct SealedMessage {
    version: u8,
    // X25519 Montgomery public key (33 bytes serialized)
    ec_ephemeral: [u8; 33],
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

    pub fn ec_ephemeral(&self) -> &[u8; 33] {
        &self.msg.ec_ephemeral
    }
}

fn verified_parse_outer<'a>(
    msg_bytes: &'a [u8],
) -> Result<(
    &'a [u8], // encoded without MAC
    &'a [u8], // expected_mac
    [u8; 33], // eph
    &'a [u8], // ct1
    &'a [u8], // ct2
    &'a [u8], // inner_ct
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
    if encoded.len() < idx + 33 {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let mut eph = [0u8; 33];
    eph.copy_from_slice(&encoded[idx..idx + 33]);
    idx += 33;
    if encoded.len() < idx + 4 { return Err(SignalProtocolError::InvalidProtobufEncoding); }
    let len1 = u32::from_le_bytes(encoded[idx..idx+4].try_into().unwrap()) as usize; idx += 4;
    if encoded.len() < idx + len1 { return Err(SignalProtocolError::InvalidProtobufEncoding); }
    let ct1 = &encoded[idx..idx+len1]; idx += len1;
    if encoded.len() < idx + 4 { return Err(SignalProtocolError::InvalidProtobufEncoding); }
    let len2 = u32::from_le_bytes(encoded[idx..idx+4].try_into().unwrap()) as usize; idx += 4;
    if encoded.len() < idx + len2 { return Err(SignalProtocolError::InvalidProtobufEncoding); }
    let ct2 = &encoded[idx..idx+len2]; idx += len2;
    if encoded.len() < idx + 4 { return Err(SignalProtocolError::InvalidProtobufEncoding); }
    let inner_len = u32::from_le_bytes(encoded[idx..idx+4].try_into().unwrap()) as usize; idx += 4;
    if encoded.len() < idx + inner_len { return Err(SignalProtocolError::InvalidProtobufEncoding); }
    let inner_ct = &encoded[idx..idx+inner_len];
    Ok((encoded, expected_mac, eph, ct1, ct2, inner_ct))
}

fn verified_classical_spk_sig(bundle: &PreKeyBundle) -> Result<()> {
    let ik = bundle.identity_key()?;
    if !ik
        .public_key()
        .verify_signature(&bundle.signed_pre_key_public()?.serialize(), bundle.signed_pre_key_signature()?)
    {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "bad classical SPK signature".into(),
        ));
    }
    Ok(())
}

fn verified_pq_spk_sig(pq: &PqBundle) -> Result<()> {
    let spk_bytes = pq.mlkem_signed_prekey.serialize();
    let ok = pure_falcon::verify_bytes(&pq.receiver_falcon_vkey, &spk_bytes, &pq.mlkem_signed_prekey_signature);
    if ok { Ok(()) } else { Err(SignalProtocolError::InvalidSealedSenderMessage("bad PQ SPK signature".into())) }
}

// Build CK || Kseal using transcript: includes PQ secrets, classical ephemeral ECDHs, and context.
fn derive_ck_kseal(
    ss1: &[u8],
    ss2: &[u8],
    ecdh_eph_ikr: &[u8],
    ecdh_eph_spkr: &[u8],
    ecdh_eph_opkr: Option<&[u8]>,
    receiver_identity: &PublicKey,
    receiver_signed_prekey: &PublicKey,
    receiver_one_time_prekey: Option<&PublicKey>,
    eph_bytes: &[u8; 33],
    pq_identity_key_bytes: &[u8],
    pq_signed_prekey_bytes: &[u8],
    receiver_falcon_vk: &[u8],
    ct1: &[u8],
    ct2: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let mut sealing_and_chain_key = [0u8; 64];
    let mut transcript = Vec::new();
    transcript.extend_from_slice(ss1);
    transcript.extend_from_slice(ss2);
    transcript.extend_from_slice(ecdh_eph_ikr);
    transcript.extend_from_slice(ecdh_eph_spkr);
    if let Some(opk) = ecdh_eph_opkr { transcript.extend_from_slice(opk); }
    transcript.extend_from_slice(&receiver_identity.serialize());
    transcript.extend_from_slice(&receiver_signed_prekey.serialize());
    if let Some(opk) = receiver_one_time_prekey { transcript.extend_from_slice(&opk.serialize()); }
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
    (
        ck.try_into().expect("32"),
        kseal.try_into().expect("32"),
    )
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

struct ParsedInner {
    registration_id: u32,
    msg_type: CiphertextMessageType,
    content_hint: ContentHint,
    sender_iks: PublicKey, // 33 bytes
    vks: Vec<u8>,
    sigma: Vec<u8>,
    sender_certificate: SenderCertificate,
}

fn validated_parse_inner(kseal: &[u8], inner_ct: &[u8]) -> Result<ParsedInner> {
    let inner = spqxdh::aes_256_ctr_decrypt(inner_ct, kseal)?;
    if inner.len() < 6 + 33 + 2 + 2 + 4 {
        return Err(SignalProtocolError::InvalidSealedSenderMessage("inner too short".into()));
    }
    let registration_id = u32::from_le_bytes(inner[0..4].try_into().unwrap());
    let msg_type = CiphertextMessageType::try_from(inner[4])
        .map_err(|_| SignalProtocolError::InvalidSealedSenderMessage("invalid message type".into()))?;
    let content_hint = ContentHint::from(inner[5] as u32);
    let sender_iks = PublicKey::deserialize(&inner[6..6 + 33])
        .map_err(|_| SignalProtocolError::InvalidSealedSenderMessage("bad IKs".into()))?;
    let mut o = 6 + 33;
    let vks_len = u16::from_le_bytes(inner[o..o + 2].try_into().unwrap()) as usize; o += 2;
    if inner.len() < o + vks_len + 2 { return Err(SignalProtocolError::InvalidSealedSenderMessage("inner too short".into())); }
    let vks = inner[o..o + vks_len].to_vec(); o += vks_len;
    let sig_len = u16::from_le_bytes(inner[o..o + 2].try_into().unwrap()) as usize; o += 2;
    if inner.len() < o + sig_len + 4 { return Err(SignalProtocolError::InvalidSealedSenderMessage("inner too short".into())); }
    let sigma = inner[o..o + sig_len].to_vec(); o += sig_len;
    let cert_len = u32::from_le_bytes(inner[o..o + 4].try_into().unwrap()) as usize; o += 4;
    if inner.len() < o + cert_len { return Err(SignalProtocolError::InvalidSealedSenderMessage("inner too short".into())); }
    let sender_certificate = SenderCertificate::deserialize(&inner[o..o + cert_len])?;
    Ok(ParsedInner { registration_id, msg_type, content_hint, sender_iks, vks, sigma, sender_certificate })
}

fn build_inner_message(
    registration_id: u32,
    msg_type: CiphertextMessageType,
    content_hint: ContentHint,
    sender_iks: &PublicKey,
    vks: &[u8],
    sigma: &[u8],
    cert_bytes: &[u8],
    kseal: &[u8],
) -> Result<Vec<u8>> {
    let mut inner = Vec::with_capacity(4 + 1 + 1 + 33 + 2 + vks.len() + 2 + sigma.len() + 4 + cert_bytes.len());
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

pub struct SendParams<'a> {
    pub sender_identity: &'a IdentityKeyPair,      // IKs
    pub sender_falcon_sk: &'a pure_falcon::SecretKey, // SKs^Q
    pub sender_falcon_vk: &'a [u8],               // VKs^Q
    pub cert: &'a SenderCertificate,
    pub registration_id: u32,
    pub msg_type: CiphertextMessageType,
    pub content_hint: ContentHint,
}

pub struct RecvParams<'a> {
    pub receiver_signed_prekey_kp: &'a X25519KeyPair, // SPKr private
    pub receiver_one_time_prekey_kp: Option<&'a X25519KeyPair>, // OPKr private
    pub receiver_identity_kp: &'a IdentityKeyPair, // IKr private
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

pub fn send<R: Rng + CryptoRng>(
    bundle: &SealedRingXkemX3dhPreKeyBundle,
    params: &SendParams,
    rng: &mut R,
) -> Result<(SealedMessageData, SessionKey)> {
    // Verify bundle signatures
    verified_classical_spk_sig(&bundle.classical)?;
    verified_pq_spk_sig(&bundle.pq)?;

    // PQ encapsulations
    let (ss1, ct1) = bundle.pq.mlkem_identity_key.encapsulate(rng)?;
    let (ss2, ct2) = bundle.pq.mlkem_signed_prekey.encapsulate(rng)?;

    // X3DH: ephemeral agreements with receiver identity, signed prekey, optional one-time prekey
    let eph = X25519KeyPair::generate(rng);
    let ecdh_eph_ikr = eph
        .private_key
        .calculate_agreement(bundle.classical.identity_key()?.public_key())?;
    let ecdh_eph_spkr = eph
        .private_key
        .calculate_agreement(&bundle.classical.signed_pre_key_public()?)?;
    let ecdh_eph_opkr = if let Some(opk) = bundle.classical.pre_key_public()? {
        Some(eph.private_key.calculate_agreement(&opk)?)
    } else { None };
    let eph_bytes: [u8; 33] = eph.public_key.serialize().as_ref().try_into().expect("33 bytes");

    // Derive CK || Kseal from transcript
    let pq_id_bytes = bundle.pq.mlkem_identity_key.serialize();
    let pq_spk_bytes = bundle.pq.mlkem_signed_prekey.serialize();
    let (ck, kseal) = derive_ck_kseal(
        &ss1,
        &ss2,
        &ecdh_eph_ikr,
        &ecdh_eph_spkr,
        ecdh_eph_opkr.as_deref(),
        bundle.classical.identity_key()?.public_key(),
        &bundle.classical.signed_pre_key_public()?,
        bundle.classical.pre_key_public()?.as_ref(),
        &eph_bytes,
        &pq_id_bytes,
        &pq_spk_bytes,
        &bundle.pq.receiver_falcon_vkey,
        &ct1,
        &ct2,
    );

    // Falcon signature over PQ transcript
    let pq_transcript_hash = falcon_transcript_hash(
        &bundle.pq.receiver_falcon_vkey,
        params.sender_falcon_vk,
        &pq_id_bytes,
        &pq_spk_bytes,
        &ct1,
        &ct2,
    );
    let sigma = pure_falcon::sign(params.sender_falcon_sk, &pq_transcript_hash);
    // Compute a second, unused Falcon signature to upper bound computation
    // for benchmarking a 2-ring signature. Wrap inputs and result in black_box
    // to prevent the compiler from optimizing this work away without
    // affecting serialized message sizes or contents.
    let _sigma2 = black_box(pure_falcon::sign(
        black_box(params.sender_falcon_sk),
        black_box(&pq_transcript_hash),
    ));
    let _ = black_box(&_sigma2);

    // Final session || mac via spqxdh-style identity mixin: ck + (IKs × SPKr)
    let ss_id = params
        .sender_identity
        .private_key()
        .calculate_agreement(&bundle.classical.signed_pre_key_public()?)?;
    let mut session_and_mac = [0u8; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &[&ck, ss_id.as_ref()].concat())
        .expand(LABEL_FINAL_KEYS, &mut session_and_mac)
        .expect("valid len");
    let (session_key, mac_key) = session_and_mac.split_at(32);

    // Build inner message and encrypt with kseal
    let cert_bytes = params.cert.serialized()?;
    let inner_ct = build_inner_message(
        params.registration_id,
        params.msg_type,
        params.content_hint,
        params.sender_identity.public_key(),
        params.sender_falcon_vk,
        &sigma,
        &cert_bytes,
        &kseal,
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
        SealedMessageData { msg, mac, sealing_key: kseal.to_vec() },
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

    // Classical agreements using sender ephemeral
    let eph_pk = PublicKey::deserialize(&eph)
        .map_err(|_| SignalProtocolError::InvalidSealedSenderMessage("bad eph".into()))?;
    let ecdh_eph_ikr = recv_params
        .receiver_identity_kp
        .private_key()
        .calculate_agreement(&eph_pk)?;
    let ecdh_eph_spkr = recv_params
        .receiver_signed_prekey_kp
        .private_key
        .calculate_agreement(&eph_pk)?;
    let ecdh_eph_opkr = if let Some(opk) = recv_params.receiver_one_time_prekey_kp {
        Some(opk.private_key.calculate_agreement(&eph_pk)?)
    } else { None };

    let pq_id_bytes = recv_params.pq_identity_kp.public_key.serialize();
    let pq_spk_bytes = recv_params.pq_signed_prekey_kp.public_key.serialize();
    let (ck, kseal) = derive_ck_kseal(
        &ss1,
        &ss2,
        &ecdh_eph_ikr,
        &ecdh_eph_spkr,
        ecdh_eph_opkr.as_deref(),
        recv_params.receiver_identity_kp.public_key(),
        &recv_params.receiver_signed_prekey_kp.public_key,
        recv_params
            .receiver_one_time_prekey_kp
            .as_ref()
            .map(|kp| &kp.public_key),
        &eph,
        &pq_id_bytes,
        &pq_spk_bytes,
        recv_params.receiver_falcon_vk,
        ct1,
        ct2,
    );

    // Decrypt inner and parse
    let ParsedInner { registration_id, msg_type, content_hint, sender_iks: _sender_iks, vks, sigma, sender_certificate } =
        validated_parse_inner(&kseal, inner_ct)?;

    // Final session || mac via spqxdh-style identity mixin: ck + (IKs × SPKr)
    let their_id_key = sender_certificate.key()?;
    let ss_id = recv_params
        .receiver_signed_prekey_kp
        .private_key
        .calculate_agreement(&their_id_key)?;
    let mut session_and_mac = [0u8; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &[&ck, ss_id.as_ref()].concat())
        .expand(LABEL_FINAL_KEYS, &mut session_and_mac)
        .expect("valid len");
    let (session_key, mac_key) = session_and_mac.split_at(32);

    // Verify MAC
    let mac = crate::crypto::hmac_sha256(mac_key, encoded);
    if mac != expected_mac { return Err(SignalProtocolError::BadSealedPQXDHMac); }

    // Verify Falcon signature on PQ transcript
    let pq_transcript_hash = falcon_transcript_hash(
        recv_params.receiver_falcon_vk,
        &vks,
        &pq_id_bytes,
        &pq_spk_bytes,
        ct1,
        ct2,
    );
    let ok = pure_falcon::verify_bytes(&vks, &pq_transcript_hash, &sigma);
    // Perform a second, unused Falcon verification to model a 2-ring
    // signature verify cost for benchmarks. Use black_box to prevent
    // optimization while not changing any observable outputs.
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
        session_key: session_key.to_vec(),
    })
}

// Session initialization helpers (derive DR keys from session key)
use crate::ratchet::{ChainKey, RootKey};
use crate::{protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION, state::SessionState, SessionRecord};

fn derive_session_keys(session_key: &[u8]) -> (RootKey, ChainKey, [u8; 32]) {
    let mut secrets = [0u8; 96];
    hkdf::Hkdf::<sha2::Sha256>::new(None, session_key)
        .expand(SESSION_LABEL, &mut secrets)
        .expect("valid length");
    let (rk, ck, pqr) = (&secrets[0..32], &secrets[32..64], &secrets[64..96]);
    (
        RootKey::new(rk.try_into().unwrap()),
        ChainKey::new(ck.try_into().unwrap(), 0),
        pqr.try_into().unwrap(),
    )
}

fn spqr_chain_params(self_connection: bool) -> spqr::ChainParams {
    #[allow(clippy::needless_update)]
    spqr::ChainParams {
        max_jump: if self_connection { u32::MAX } else { crate::consts::MAX_FORWARD_JUMPS.try_into().expect("<4B") },
        max_ooo_keys: crate::consts::MAX_MESSAGE_KEYS.try_into().expect("<4B"),
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
) -> Result<SessionRecord> {
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
    .map_err(|e| SignalProtocolError::InvalidArgument(format!(
        "post-quantum ratchet: error creating initial A2B state: {e}"
    )))?;

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
    Ok(SessionRecord::new(session))
}

pub fn initialize_bob_session(
    session_key: &[u8],
    their_base_key: &PublicKey,
    local_identity: &IdentityKey,
    their_identity_key: &IdentityKey,
    our_ratchet_key_pair: &X25519KeyPair,
    local_registration_id: u32,
    remote_registration_id: u32,
) -> Result<SessionRecord> {
    let (root_key, receiver_chain_key, pqr_key) = derive_session_keys(session_key);

    let self_session = local_identity == their_identity_key;
    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::B2A,
        min_version: spqr::Version::V0,
        chain_params: spqr_chain_params(self_session),
    })
    .map_err(|e| SignalProtocolError::InvalidArgument(format!(
        "post-quantum ratchet: error creating initial B2A state: {e}"
    )))?;

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
    Ok(SessionRecord::new(session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;
    use futures_util::FutureExt;
    use crate::InMemSignalProtocolStore;
    use crate::{IdentityKeyStore as _, PreKeyStore as _, SignedPreKeyStore as _, KyberPreKeyStore as _, ProtocolStore as _};
    use crate::state::GenericSignedPreKey as _;

    fn make_sender_cert(identity_key: PublicKey, rng: &mut rand_core::UnwrapErr<OsRng>) -> SenderCertificate {
        let trust_root = X25519KeyPair::generate(rng);
        let server_key = X25519KeyPair::generate(rng);
        let server_cert = crate::sealed_sender::ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, rng).unwrap();
        let device_id = crate::DeviceId::new(42).unwrap();
        let expires = crate::Timestamp::from_epoch_millis(1605722925);
        SenderCertificate::new(
            "user-aci".to_string(),
            Some("+14150000000".to_string()),
            identity_key,
            device_id,
            expires,
            server_cert,
            &server_key.private_key,
            rng,
        )
        .unwrap()
    }

    fn make_pq_bundle<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> (PqBundle, kem::KeyPair, kem::KeyPair, (Vec<u8>, crate::pure_falcon::SecretKey)) {
        let ek_id = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
        let ek_spk = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
        let (vkr_pk, vkr_sk) = crate::pure_falcon::keypair();
        let spk_sig = crate::pure_falcon::sign(&vkr_sk, &ek_spk.public_key.serialize());
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

    fn create_pre_key_bundle(
        store: &mut InMemSignalProtocolStore,
        rng: &mut rand_core::UnwrapErr<OsRng>,
    ) -> PreKeyBundle {
        // Generate classical and kyber prekeys
        let pre_key_pair = X25519KeyPair::generate(rng);
        let signed_pre_key_pair = X25519KeyPair::generate(rng);
        let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);

        // Sign SPK and Kyber prekey with identity
        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
        let id_pair = store.get_identity_key_pair().now_or_never().unwrap().unwrap();
        let spk_sig = id_pair
            .private_key()
            .calculate_signature(&signed_pre_key_public, rng)
            .unwrap();
        let kyber_sig = id_pair
            .private_key()
            .calculate_signature(&kyber_pre_key_public, rng)
            .unwrap();

        // IDs
        let device_id: crate::DeviceId = rng.random();
        let pre_key_id: u32 = rng.random();
        let signed_pre_key_id: u32 = rng.random();
        let kyber_pre_key_id: u32 = rng.random();

        // Build bundle
        let bundle = crate::state::PreKeyBundle::new(
            store.get_local_registration_id().now_or_never().unwrap().unwrap(),
            device_id,
            Some((pre_key_id.into(), pre_key_pair.public_key)),
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key,
            spk_sig.to_vec(),
            kyber_pre_key_id.into(),
            kyber_pre_key_pair.public_key.clone(),
            kyber_sig.to_vec(),
            *id_pair.identity_key(),
        )
        .unwrap();

        // Save to store for later retrieval
        store
            .save_pre_key(pre_key_id.into(), &crate::state::PreKeyRecord::new(pre_key_id.into(), &pre_key_pair))
            .now_or_never()
            .unwrap()
            .unwrap();

        let timestamp = crate::Timestamp::from_epoch_millis(rng.random());
        store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &crate::state::SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    timestamp,
                    &signed_pre_key_pair,
                    &spk_sig,
                ),
            )
            .now_or_never()
            .unwrap()
            .unwrap();

        let timestamp2 = crate::Timestamp::from_epoch_millis(rng.random());
        store
            .save_kyber_pre_key(
                kyber_pre_key_id.into(),
                &crate::state::KyberPreKeyRecord::new(
                    kyber_pre_key_id.into(),
                    timestamp2,
                    &kyber_pre_key_pair,
                    &kyber_sig,
                ),
            )
            .now_or_never()
            .unwrap()
            .unwrap();

        bundle
    }

    #[test]
    fn test_round_trip() {
        let mut rng = OsRng.unwrap_err();

        // Classical bundle via local helper
        let mut store = InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut rng), 123).unwrap();
        let classical = create_pre_key_bundle(&mut store, &mut rng);

        // Keep receiver private keys for recv
        let spk_id = classical.signed_pre_key_id().unwrap();
        let spk_kp = store
            .signed_pre_key_store
            .get_signed_pre_key(spk_id)
            .now_or_never()
            .expect("sync")
            .expect("valid")
            .key_pair()
            .unwrap();
        let opk_kp = classical
            .pre_key_id()
            .unwrap()
            .and_then(|id| store.pre_key_store.get_pre_key(id).now_or_never().unwrap().ok())
            .map(|pkrec| pkrec.key_pair().unwrap());
        let ik_kp = store.get_identity_key_pair().now_or_never().unwrap().unwrap();

        let (pq_bundle, pq_id_kp, pq_spk_kp, (vkr_pk, vkr_sk)) = make_pq_bundle(&mut rng);
        let bundle = SealedRingXkemX3dhPreKeyBundle { classical: classical.clone(), pq: pq_bundle, registration_id: classical.registration_id().unwrap() };

        let sender_identity = IdentityKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(*sender_identity.public_key(), &mut rng);
        let (vks_pk, vks_sk) = crate::pure_falcon::keypair();

        let params = SendParams {
            sender_identity: &sender_identity,
            sender_falcon_sk: &vks_sk,
            sender_falcon_vk: &vks_pk,
            cert: &sender_cert,
            registration_id: 7777,
            msg_type: CiphertextMessageType::Whisper,
            content_hint: ContentHint::Default,
        };

        let (msg, session_key) = send(&bundle, &params, &mut rng).expect("send");
        let serialized = msg.serialize();

        let recv_params = RecvParams {
            receiver_signed_prekey_kp: &spk_kp,
            receiver_one_time_prekey_kp: opk_kp.as_ref(),
            receiver_identity_kp: &ik_kp,
            pq_identity_kp: &pq_id_kp,
            pq_signed_prekey_kp: &pq_spk_kp,
            receiver_falcon_vk: &vkr_pk,
        };
        let rr = recv(&serialized, &recv_params).expect("recv");

        assert_eq!(rr.registration_id, 7777);
        assert_eq!(rr.msg_type, CiphertextMessageType::Whisper);
        assert_eq!(rr.content_hint, ContentHint::Default);
        assert_eq!(rr.sender_certificate.serialized().unwrap(), sender_cert.serialized().unwrap());
        assert_eq!(rr.session_key, session_key);
    }

    #[test]
    fn test_mac_tampering_detected() {
        let mut rng = OsRng.unwrap_err();
        let mut store = InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut rng), 123).unwrap();
        let classical = create_pre_key_bundle(&mut store, &mut rng);
        let (pq_bundle, pq_id_kp, pq_spk_kp, (vkr_pk, _vkr_sk)) = make_pq_bundle(&mut rng);
        let bundle = SealedRingXkemX3dhPreKeyBundle { classical: classical.clone(), pq: pq_bundle, registration_id: classical.registration_id().unwrap() };
        let sender_identity = IdentityKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(*sender_identity.public_key(), &mut rng);
        let (vks_pk, vks_sk) = crate::pure_falcon::keypair();
        let params = SendParams { sender_identity: &sender_identity, sender_falcon_sk: &vks_sk, sender_falcon_vk: &vks_pk, cert: &sender_cert, registration_id: 7, msg_type: CiphertextMessageType::Whisper, content_hint: ContentHint::Default };
        let (msg, _sk) = send(&bundle, &params, &mut rng).unwrap();
        let mut serialized = msg.serialize();
        let last = serialized.len() - 1; serialized[last] ^= 0x01;

        let spk_id = classical.signed_pre_key_id().unwrap();
        let spk_kp = store.signed_pre_key_store.get_signed_pre_key(spk_id).now_or_never().unwrap().unwrap().key_pair().unwrap();
        let opk_kp = classical
            .pre_key_id().unwrap()
            .and_then(|id| store.pre_key_store.get_pre_key(id).now_or_never().unwrap().ok())
            .map(|pkrec| pkrec.key_pair().unwrap());
        let ik_kp = store.get_identity_key_pair().now_or_never().unwrap().unwrap();

        let recv_params = RecvParams { receiver_signed_prekey_kp: &spk_kp, receiver_one_time_prekey_kp: opk_kp.as_ref(), receiver_identity_kp: &ik_kp, pq_identity_kp: &pq_id_kp, pq_signed_prekey_kp: &pq_spk_kp, receiver_falcon_vk: &vkr_pk };
        let err = recv(&serialized, &recv_params).unwrap_err();
        match err { SignalProtocolError::BadSealedPQXDHMac => {}, other => panic!("expected MAC failure, got {:?}", other) }
    }

    #[test]
    fn test_size_breakdown() {
        let mut rng = OsRng.unwrap_err();
        let mut store = InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut rng), 123).unwrap();
        let classical = create_pre_key_bundle(&mut store, &mut rng);
        let (pq_bundle, _pq_id_kp, _pq_spk_kp, (_vkr_pk, _vkr_sk)) = make_pq_bundle(&mut rng);
        let bundle = SealedRingXkemX3dhPreKeyBundle { classical: classical.clone(), pq: pq_bundle, registration_id: classical.registration_id().unwrap() };
        let sender_identity = IdentityKeyPair::generate(&mut rng);
        let sender_cert = make_sender_cert(*sender_identity.public_key(), &mut rng);
        let (vks_pk, vks_sk) = crate::pure_falcon::keypair();
        let params = SendParams { sender_identity: &sender_identity, sender_falcon_sk: &vks_sk, sender_falcon_vk: &vks_pk, cert: &sender_cert, registration_id: 9, msg_type: CiphertextMessageType::Whisper, content_hint: ContentHint::Default };
        let (msg, _sk) = send(&bundle, &params, &mut rng).unwrap();
        let serialized = msg.serialize();

        let mut idx = 1; // skip version
        let ephem_len = 33;
        idx += ephem_len;
        let ct1_len = u32::from_le_bytes(serialized[idx..idx+4].try_into().unwrap()) as usize; idx += 4; idx += ct1_len;
        let ct2_len = u32::from_le_bytes(serialized[idx..idx+4].try_into().unwrap()) as usize; idx += 4; idx += ct2_len;
        let inner_len = u32::from_le_bytes(serialized[idx..idx+4].try_into().unwrap()) as usize; idx += 4;
        let inner_ct = &serialized[idx..idx+inner_len];

        let inner_pt = spqxdh::aes_256_ctr_decrypt(inner_ct, msg.sealing_key()).expect("inner decrypt");
        let mut o = 4 + 1 + 1 + 33;
        let vks_len = u16::from_le_bytes(inner_pt[o..o+2].try_into().unwrap()) as usize; o += 2; o += vks_len;
        let sigma_len = u16::from_le_bytes(inner_pt[o..o+2].try_into().unwrap()) as usize; o += 2; o += sigma_len;
        let cert_len = u32::from_le_bytes(inner_pt[o..o+4].try_into().unwrap()) as usize;

        let mac_len = 32;
        let total = serialized.len();
        println!("SealedRingXKEMX3DH size breakdown:");
        println!("  Ephemeral (x25519): {}", ephem_len);
        println!("  KEM ct1: {}", ct1_len);
        println!("  KEM ct2: {}", ct2_len);
        println!("  Inner total: {} (IKs: 33, VKs: {}, sigma: {}, cert: {})", inner_len, vks_len, sigma_len, cert_len);
        println!("  MAC: {}", mac_len);
        println!("  TOTAL: {}", total);
    }
}
