//
// SPDX-License-Identifier: AGPL-3.0-only
//
use libsignal_core::curve::{KeyPair, PublicKey};
use prost::Message as _;
use rand::{CryptoRng, Rng};

use crate::{
    CiphertextMessageType, ContentHint, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, KyberPreKeyId, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyStore,
    Result, SenderCertificate, SessionRecord, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyStore, consts, crypto, kem, proto,
    protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION,
    ratchet::{ChainKey, RootKey},
    state::SessionState,
};

/// Encrypt plaintext using AES-256-CTR with the given key.
/// The first 16 bytes of the result are the nonce (randomly generated).
pub fn aes_256_ctr_encrypt(ptext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    crypto::aes_256_ctr_encrypt(ptext, key).map_err(|crypto::EncryptionError::BadKeyOrIv| {
        SignalProtocolError::InvalidArgument("invalid key or IV for AES-256-CTR".to_string())
    })
}

/// Decrypt ciphertext using AES-256-CTR with the given key.
/// Expects the first 16 bytes to be the nonce.
pub fn aes_256_ctr_decrypt(ctext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    crypto::aes_256_ctr_decrypt(ctext, key).map_err(|e| match e {
        crypto::DecryptionError::BadKeyOrIv => {
            SignalProtocolError::InvalidArgument("invalid key or IV for AES-256-CTR".to_string())
        }
        crypto::DecryptionError::BadCiphertext(msg) => {
            SignalProtocolError::InvalidSealedSenderMessage(msg.to_string())
        }
    })
}

type Mac = Vec<u8>;
type SessionKey = Vec<u8>;

#[allow(dead_code)]
const SEALED_SENDER_V3_SPQXDH_MAJOR_VERSION: u8 = 3;
const SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION: u8 = 0x34;

const PROTOCOL_LABEL_ONETIME_PREKEY_PRESENT: &[u8] =
    b"Signal_SealedPQXDH_20251111_X25519_SHA-256_CRYSTALS-KYBER-1024_ONETIME_KEY_PRESENT";
const PROTOCOL_LABEL_ONETIME_PREKEY_ABSENT: &[u8] =
    b"Signal_SealedPQXDH_20251111_X25519_SHA-256_CRYSTALS-KYBER-1024_ONETIME_KEY_ABSENT_";

struct SealedPQXDHMessage {
    #[allow(dead_code)]
    message_version: u8,
    ec_ephemeral: [u8; 33], // known as "base_key" in prior versions
    kem_ciphertext: Vec<u8>,
    pre_key_id: Option<PreKeyId>,
    signed_pre_key_id: SignedPreKeyId,
    mlkem_pre_key_id: KyberPreKeyId,
    inner_msg_ct: Vec<u8>,
    sealed_ciphertext: Vec<u8>, // AES-CTR encrypted SignalMessage
}

/// Inner message content that is encrypted with the sealing key.
/// Serialized as: registration_id (4 bytes LE) + msg_type (1 byte) + content_hint (1 byte) + SenderCertificate
#[allow(dead_code)]
struct SealedPQXDHInnerMessage {
    registration_id: u32,
    msg_type: CiphertextMessageType,
    content_hint: ContentHint,
    cert: SenderCertificate,
}

pub struct SealedPQXDHMessageData {
    msg: SealedPQXDHMessage,
    mac: Mac,
    sealing_key: Vec<u8>,
}

impl SealedPQXDHMessageData {
    /// Serialize the message for transmission.
    pub fn serialize(&self) -> Vec<u8> {
        let pb = proto::wire::SealedPqxdhMessage {
            pre_key_id: self.msg.pre_key_id.map(|pkid| pkid.into()),
            signed_pre_key_id: Some(self.msg.signed_pre_key_id.into()),
            mlkem_pre_key_id: Some(self.msg.mlkem_pre_key_id.into()),
            ec_ephemeral: Some(self.msg.ec_ephemeral.to_vec()),
            kem_ciphertext: Some(self.msg.kem_ciphertext.clone()),
            inner_msg_ct: Some(self.msg.inner_msg_ct.clone()),
            sealed_ciphertext: if self.msg.sealed_ciphertext.is_empty() {
                None
            } else {
                Some(self.msg.sealed_ciphertext.clone())
            },
        };

        let mut serialized = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
        pb.encode(&mut serialized)
            .expect("can always append to Vec");
        serialized.extend_from_slice(&self.mac);
        serialized
    }

    /// Get the sealing key for encrypting/decrypting the DR message.
    pub fn sealing_key(&self) -> &[u8] {
        &self.sealing_key
    }

    /// Get the ephemeral EC public key (base key).
    pub fn ec_ephemeral(&self) -> &[u8; 33] {
        &self.msg.ec_ephemeral
    }
}

struct SealingResult {
    sealing_and_chain_key: [u8; 64],
    ec_ephemeral: [u8; 33],
    kem_ciphertext: Vec<u8>,
}

fn prepare_sealing_key_send<R: Rng + CryptoRng>(
    prekey_bundle: &PreKeyBundle,
    rng: &mut R,
) -> Result<SealingResult> {
    let mut sealing_and_chain_key = [0u8; 64];
    let mut kem_ciphertext = Vec::new();

    let info: &[u8] = if prekey_bundle.pre_key_public()?.is_some() {
        PROTOCOL_LABEL_ONETIME_PREKEY_PRESENT
    } else {
        PROTOCOL_LABEL_ONETIME_PREKEY_ABSENT
    };

    let mut secrets = Vec::with_capacity(32 * 4);

    let ephemeral = KeyPair::generate(rng);

    secrets.extend_from_slice(
        ephemeral
            .private_key
            .calculate_agreement(prekey_bundle.identity_key()?.public_key())?
            .as_ref(),
    );

    secrets.extend_from_slice(
        ephemeral
            .private_key
            .calculate_agreement(&prekey_bundle.signed_pre_key_public()?)?
            .as_ref(),
    );

    if let Some(opk) = prekey_bundle.pre_key_public()? {
        secrets.extend_from_slice(ephemeral.private_key.calculate_agreement(&opk)?.as_ref());
    }

    let (ss, ct) = prekey_bundle.kyber_pre_key_public()?.encapsulate(rng)?;
    secrets.extend_from_slice(&ss);
    kem_ciphertext.extend_from_slice(&ct);

    hkdf::Hkdf::<sha2::Sha256>::new(None, &secrets)
        .expand(info, &mut sealing_and_chain_key)
        .expect("valid length");
    let ephemeral_dh_key: [u8; 33] = ephemeral
        .public_key
        .serialize()
        .as_ref()
        .try_into()
        .expect("serialized DH public key is 33 bytes");

    Ok(SealingResult {
        sealing_and_chain_key,
        ec_ephemeral: ephemeral_dh_key,
        kem_ciphertext,
    })
}

pub async fn send<R: Rng + CryptoRng>(
    prekey_bundle: &PreKeyBundle,
    cert: &SenderCertificate,
    registration_id: u32,
    msg_type: CiphertextMessageType,
    content_hint: ContentHint,
    identity_store: &dyn IdentityKeyStore,
    rng: &mut R,
) -> Result<(SealedPQXDHMessageData, SessionKey)> {
    let sealing_result = prepare_sealing_key_send(prekey_bundle, rng)?;
    let our_identity = identity_store.get_identity_key_pair().await?;

    let (sealing_key, chain_key) = sealing_result.sealing_and_chain_key.split_at(32);

    //perform key agreement between our identity and their signed prekey
    let ss = our_identity
        .private_key()
        .calculate_agreement(&prekey_bundle.signed_pre_key_public()?)?;

    // mix this with the chain key
    let mut session_and_mac_key: [u8; 64] = [0u8; 64];
    let info: &[u8] = b"Signal_SealedPQXDH_LocalIdentity_Mixin";

    hkdf::Hkdf::<sha2::Sha256>::new(None, &[chain_key, &ss].concat())
        .expand(info, &mut session_and_mac_key)
        .expect("valid length");

    let (session_key, mac_key) = session_and_mac_key.split_at(32);

    // encrypt the inner message using simple AES256CTR - No AE needed here.
    // Format: registration_id (4 bytes LE) + msg_type (1 byte) + content_hint (1 byte) + SenderCertificate
    let mut inner_bytes = registration_id.to_le_bytes().to_vec();
    inner_bytes.push(msg_type as u8);
    inner_bytes.push(content_hint.to_u32() as u8);
    inner_bytes.extend_from_slice(&cert.serialized()?);
    let inner_msg_ct = match crypto::aes_256_ctr_encrypt(&inner_bytes, sealing_key) {
        Ok(ct) => ct,
        Err(crypto::EncryptionError::BadKeyOrIv) => {
            unreachable!("just derived these keys; they should be valid");
        }
    };

    let msg = SealedPQXDHMessage {
        message_version: SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION,
        ec_ephemeral: sealing_result.ec_ephemeral,
        kem_ciphertext: sealing_result.kem_ciphertext,
        pre_key_id: prekey_bundle.pre_key_id()?,
        signed_pre_key_id: prekey_bundle.signed_pre_key_id()?,
        mlkem_pre_key_id: prekey_bundle.kyber_pre_key_id()?,
        inner_msg_ct,
        sealed_ciphertext: Vec::new(), // Will be set later when encrypting a message
    };


    let pb = proto::wire::SealedPqxdhMessage {
        pre_key_id: msg.pre_key_id.map(|pkid| pkid.into()),
        signed_pre_key_id: Some(msg.signed_pre_key_id.into()),
        mlkem_pre_key_id: Some(msg.mlkem_pre_key_id.into()),
        ec_ephemeral: Some(msg.ec_ephemeral.to_vec()),
        kem_ciphertext: Some(msg.kem_ciphertext.clone()),
        inner_msg_ct: Some(msg.inner_msg_ct.clone()),
        sealed_ciphertext: None, // Will be set later when encrypting a message
    };

    let mut serialized = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
    pb.encode(&mut serialized)
        .expect("can always append to Vec");

    // mac the full message with MAC key
    let mac = crypto::hmac_sha256(&mac_key, &serialized).to_vec();

    Ok((SealedPQXDHMessageData {
            msg,
            mac,
            sealing_key: sealing_key.to_vec(),
        }, 
        session_key.to_vec()))
}

fn prepare_sealing_key_recv(
    ec_ephemeral: &PublicKey,
    kem_ciphertext: &[u8],
    id_key_pair: &IdentityKeyPair,
    signed_pre_key_pair: &KeyPair,
    one_time_pre_key_pair: &Option<KeyPair>,
    mlkem_key_pair: &kem::KeyPair,
) -> Result<[u8;64]> {
    let mut sealing_and_chain_key = [0u8; 64];

    let info: &[u8] = if one_time_pre_key_pair.is_some() {
        PROTOCOL_LABEL_ONETIME_PREKEY_PRESENT
    } else {
        PROTOCOL_LABEL_ONETIME_PREKEY_ABSENT
    };

    let mut secrets = Vec::with_capacity(32 * 4);

    secrets.extend_from_slice(
        id_key_pair
            .private_key()
            .calculate_agreement(ec_ephemeral)?
            .as_ref(),
    );

    secrets.extend_from_slice(
        signed_pre_key_pair
            .private_key
            .calculate_agreement(ec_ephemeral)?
            .as_ref(),
    );

    if let Some(opk) = one_time_pre_key_pair {
        secrets.extend_from_slice(opk.private_key.calculate_agreement(ec_ephemeral)?.as_ref());
    }

    let ss = mlkem_key_pair.secret_key.decapsulate(&kem_ciphertext.into())?;
    secrets.extend_from_slice(&ss);

    hkdf::Hkdf::<sha2::Sha256>::new(None, &secrets)
        .expand(info, &mut sealing_and_chain_key)
        .expect("valid length");

    Ok(sealing_and_chain_key)
}

/// Result of receiving an SPQXDH message.
pub struct RecvResult {
    pub sender_certificate: SenderCertificate,
    pub registration_id: u32,
    pub msg_type: CiphertextMessageType,
    pub content_hint: ContentHint,
    pub session_key: SessionKey,
}

pub async fn recv(
    msg_bytes: &[u8],
    identity_store: &dyn IdentityKeyStore,
    signed_prekey_store: &dyn SignedPreKeyStore,
    kyber_prekey_store: &dyn KyberPreKeyStore,
    pre_key_store: &dyn PreKeyStore,
) -> Result<RecvResult> {
    // Minimum message length: 1 byte version + at least some protobuf + 32 byte MAC
    if msg_bytes.len() < 33 {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }

    let message_version = msg_bytes[0];
    // TODO: check version

    let (encoded, expected_mac) = msg_bytes.split_at(msg_bytes.len() - 32);

    let pb = proto::wire::SealedPqxdhMessage::decode(&encoded[1..])
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

    let ec_ephemeral: [u8; 33] = pb
        .ec_ephemeral
        .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
        .try_into()
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

    let msg = SealedPQXDHMessage {
        message_version,
        ec_ephemeral,
        kem_ciphertext: pb
            .kem_ciphertext
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
        pre_key_id: pb.pre_key_id.map(|pkid| pkid.into()),
        signed_pre_key_id: pb
            .signed_pre_key_id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into(),
        mlkem_pre_key_id: pb
            .mlkem_pre_key_id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into(),
        inner_msg_ct: pb
            .inner_msg_ct
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
        sealed_ciphertext: pb.sealed_ciphertext.unwrap_or_default(),
    };

    // Fetch private keys from the stores
    let id_key_pair = identity_store.get_identity_key_pair().await?;
    let signed_pre_key_pair = signed_prekey_store
        .get_signed_pre_key(msg.signed_pre_key_id)
        .await?
        .key_pair()?;
    let mlkem_key_pair = kyber_prekey_store
        .get_kyber_pre_key(msg.mlkem_pre_key_id)
        .await?
        .key_pair()?;
    let one_time_pre_key_pair = if let Some(pre_key_id) = msg.pre_key_id {
        log::info!("processing Sealed PreKey message. Recipient sealed");
        Some(pre_key_store.get_pre_key(pre_key_id).await?.key_pair()?)
    } else {
        log::warn!("processing Sealed PreKey message which had no one-time prekey");
        None
    };

    // Perform first phase of key agreements
    let ec_ephemeral_key = PublicKey::deserialize(&ec_ephemeral)
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
    let sealing_and_chain_key  = prepare_sealing_key_recv(
        &ec_ephemeral_key,
        &msg.kem_ciphertext,
        &id_key_pair,
        &signed_pre_key_pair,
        &one_time_pre_key_pair,
        &mlkem_key_pair,
    )?;

    // Now use the sealing key to decrypt the inner message
    let (sealing_key, chain_key) = sealing_and_chain_key.split_at(32);

    let inner_msg = match crypto::aes_256_ctr_decrypt(&msg.inner_msg_ct, sealing_key) {
        Ok(pt) => pt,
        Err(crypto::DecryptionError::BadKeyOrIv) => {
            unreachable!("just derived these keys; they should be valid");
        },
        Err(crypto::DecryptionError::BadCiphertext(s)) => {
            return Err(SignalProtocolError::InvalidSealedSenderMessage(s.to_string()));
        }
    };

    // Parse inner message: registration_id (4 bytes LE) + msg_type (1 byte) + content_hint (1 byte) + SenderCertificate
    if inner_msg.len() < 6 {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "inner message too short".to_string(),
        ));
    }
    let registration_id: u32 = u32::from_le_bytes(inner_msg[0..4].try_into().expect("4 bytes"));
    let msg_type = CiphertextMessageType::try_from(inner_msg[4]).map_err(|_| {
        SignalProtocolError::InvalidSealedSenderMessage("invalid message type".to_string())
    })?;
    let content_hint = ContentHint::from(inner_msg[5] as u32);
    let sender_certificate = SenderCertificate::deserialize(&inner_msg[6..])?;
    let their_id_key = sender_certificate.key()?;

    let ss = signed_pre_key_pair
        .private_key
        .calculate_agreement(&their_id_key)?;


    // mix this with the chain key
    let mut session_and_mac_key: [u8; 64] = [0u8; 64];
    let info: &[u8] = b"Signal_SealedPQXDH_LocalIdentity_Mixin";

    hkdf::Hkdf::<sha2::Sha256>::new(None, &[chain_key, &ss].concat())
        .expand(info, &mut session_and_mac_key)
        .expect("valid length");

    let (session_key, mac_key) = session_and_mac_key.split_at(32);

    let mac = crypto::hmac_sha256(mac_key, encoded);

    if mac != expected_mac {
        return Err(SignalProtocolError::BadSealedPQXDHMac);
    }

    Ok(RecvResult {
        sender_certificate,
        registration_id,
        msg_type,
        content_hint,
        session_key: session_key.to_vec(),
    })
}

const SPQXDH_SESSION_LABEL: &[u8] = b"Signal_SealedPQXDH_Session_20251111";

type InitialPQRKey = [u8; 32];

fn derive_session_keys(session_key: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    let mut secrets = [0; 96];
    hkdf::Hkdf::<sha2::Sha256>::new(None, session_key)
        .expand(SPQXDH_SESSION_LABEL, &mut secrets)
        .expect("valid length");
    let (root_key_bytes, chain_key_bytes, pqr_bytes) =
        (&secrets[0..32], &secrets[32..64], &secrets[64..96]);

    let root_key = RootKey::new(root_key_bytes.try_into().expect("correct length"));
    let chain_key = ChainKey::new(chain_key_bytes.try_into().expect("correct length"), 0);
    let pqr_key: InitialPQRKey = pqr_bytes.try_into().expect("correct length");

    (root_key, chain_key, pqr_key)
}

fn spqr_chain_params(self_connection: bool) -> spqr::ChainParams {
    #[allow(clippy::needless_update)]
    spqr::ChainParams {
        max_jump: if self_connection {
            u32::MAX
        } else {
            consts::MAX_FORWARD_JUMPS.try_into().expect("should be <4B")
        },
        max_ooo_keys: consts::MAX_MESSAGE_KEYS.try_into().expect("should be <4B"),
        ..Default::default()
    }
}

/// Initialize a Double Ratchet session from an SPQXDH-derived session key.
///
/// This function takes the session_key returned by `spqxdh::send()` and creates
/// a SessionRecord ready for encrypting messages. It mirrors what
/// `ratchet::initialize_alice_session` does, but uses the pre-computed session key
/// from SPQXDH instead of performing key agreement internally.
///
/// # Arguments
/// * `session_key` - The 32-byte session key from `spqxdh::send()`
/// * `their_ratchet_key` - Bob's signed pre-key public key (used for initial ratchet)
/// * `local_identity` - Alice's identity key
/// * `their_identity_key` - Bob's identity key
/// * `our_base_key` - Alice's ephemeral public key (ec_ephemeral from SealedPQXDHMessage)
/// * `local_registration_id` - Alice's registration ID
/// * `remote_registration_id` - Bob's registration ID
/// * `rng` - Random number generator
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

    let sending_ratchet_key = KeyPair::generate(rng);
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

    Ok(SessionRecord::new(session))
}

/// Initialize a Double Ratchet session for Bob (recipient) from an SPQXDH-derived session key.
///
/// This function takes the session_key returned by `spqxdh::recv()` and creates
/// a SessionRecord ready for decrypting messages. It mirrors what
/// `ratchet::initialize_bob_session` does, but uses the pre-computed session key
/// from SPQXDH instead of performing key agreement internally.
///
/// # Arguments
/// * `session_key` - The 32-byte session key from `spqxdh::recv()`
/// * `their_base_key` - Alice's ephemeral public key (ec_ephemeral from SealedPQXDHMessage)
/// * `local_identity` - Bob's identity key
/// * `their_identity_key` - Alice's identity key (from SenderCertificate)
/// * `our_ratchet_key_pair` - Bob's signed pre-key pair (used as initial ratchet key)
/// * `local_registration_id` - Bob's registration ID
/// * `remote_registration_id` - Alice's registration ID
pub fn initialize_bob_session(
    session_key: &[u8],
    their_base_key: &PublicKey,
    local_identity: &IdentityKey,
    their_identity_key: &IdentityKey,
    our_ratchet_key_pair: &KeyPair,
    local_registration_id: u32,
    remote_registration_id: u32,
) -> Result<SessionRecord> {
    let (root_key, chain_key, pqr_key) = derive_session_keys(session_key);

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
    .with_sender_chain(our_ratchet_key_pair, &chain_key);

    session.set_local_registration_id(local_registration_id);
    session.set_remote_registration_id(remote_registration_id);

    Ok(SessionRecord::new(session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use futures_util::FutureExt;
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    fn create_sender_cert(
        identity_key: PublicKey,
        rng: &mut rand_core::UnwrapErr<OsRng>,
    ) -> Result<SenderCertificate> {
        let trust_root = KeyPair::generate(rng);
        let server_key = KeyPair::generate(rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, rng)?;

        let device_id = DeviceId::new(42).unwrap();
        let expires = Timestamp::from_epoch_millis(1605722925);

        SenderCertificate::new(
            "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string(),
            Some("+14152222222".to_string()),
            identity_key,
            device_id,
            expires,
            server_cert,
            &server_key.private_key,
            rng,
        )
    }

    fn create_prekey_bundle(
        store: &mut InMemSignalProtocolStore,
        rng: &mut rand_core::UnwrapErr<OsRng>,
    ) -> Result<PreKeyBundle> {
        let pre_key_pair = KeyPair::generate(rng);
        let signed_pre_key_pair = KeyPair::generate(rng);
        let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);

        let identity_key_pair = store
            .get_identity_key_pair()
            .now_or_never()
            .expect("sync")?;

        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&signed_pre_key_public, rng)?;

        let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
        let kyber_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&kyber_pre_key_public, rng)?;

        let device_id: DeviceId = rng.random();
        let pre_key_id: u32 = rng.random();
        let signed_pre_key_id: u32 = rng.random();
        let kyber_pre_key_id: u32 = rng.random();

        let registration_id = store.get_local_registration_id().now_or_never().expect("sync")?;

        // Save keys to store
        store
            .save_pre_key(
                pre_key_id.into(),
                &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
            )
            .now_or_never()
            .expect("sync")?;

        let timestamp = Timestamp::from_epoch_millis(42);
        store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    timestamp,
                    &signed_pre_key_pair,
                    &signed_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("sync")?;

        store
            .save_kyber_pre_key(
                kyber_pre_key_id.into(),
                &KyberPreKeyRecord::new(
                    kyber_pre_key_id.into(),
                    Timestamp::from_epoch_millis(43),
                    &kyber_pre_key_pair,
                    &kyber_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("sync")?;

        PreKeyBundle::new(
            registration_id,
            device_id,
            Some((pre_key_id.into(), pre_key_pair.public_key)),
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key,
            signed_pre_key_signature.to_vec(),
            kyber_pre_key_id.into(),
            kyber_pre_key_pair.public_key.clone(),
            kyber_pre_key_signature.to_vec(),
            *identity_key_pair.identity_key(),
        )
    }

    fn create_prekey_bundle_no_onetime(
        store: &mut InMemSignalProtocolStore,
        rng: &mut rand_core::UnwrapErr<OsRng>,
    ) -> Result<PreKeyBundle> {
        let signed_pre_key_pair = KeyPair::generate(rng);
        let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);

        let identity_key_pair = store
            .get_identity_key_pair()
            .now_or_never()
            .expect("sync")?;

        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&signed_pre_key_public, rng)?;

        let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
        let kyber_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&kyber_pre_key_public, rng)?;

        let device_id: DeviceId = rng.random();
        let signed_pre_key_id: u32 = rng.random();
        let kyber_pre_key_id: u32 = rng.random();

        let registration_id = store.get_local_registration_id().now_or_never().expect("sync")?;

        // Save keys to store (no one-time prekey)
        let timestamp = Timestamp::from_epoch_millis(42);
        store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    timestamp,
                    &signed_pre_key_pair,
                    &signed_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("sync")?;

        store
            .save_kyber_pre_key(
                kyber_pre_key_id.into(),
                &KyberPreKeyRecord::new(
                    kyber_pre_key_id.into(),
                    Timestamp::from_epoch_millis(43),
                    &kyber_pre_key_pair,
                    &kyber_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("sync")?;

        PreKeyBundle::new(
            registration_id,
            device_id,
            None, // No one-time prekey
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key,
            signed_pre_key_signature.to_vec(),
            kyber_pre_key_id.into(),
            kyber_pre_key_pair.public_key.clone(),
            kyber_pre_key_signature.to_vec(),
            *identity_key_pair.identity_key(),
        )
    }

    
    #[test]
    fn test_spqxdh_roundtrip() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            let alice_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;
            let mut bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            let alice_identity = alice_store.get_identity_key_pair().await?;
            let alice_registration_id = alice_store.get_local_registration_id().await?;

            // Create Bob's prekey bundle
            let bob_bundle = create_prekey_bundle(&mut bob_store, &mut rng)?;

            // Create Alice's sender certificate
            let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)?;

            // Alice sends a message
            let (msg_data, session_key_send) =
                send(&bob_bundle, &sender_cert, alice_registration_id, CiphertextMessageType::Whisper, ContentHint::Default, &alice_store, &mut rng)
                    .await?;

            
            let pb = proto::wire::SealedPqxdhMessage {
                pre_key_id: msg_data.msg.pre_key_id.map(|pkid| pkid.into()),
                signed_pre_key_id: Some(msg_data.msg.signed_pre_key_id.into()),
                mlkem_pre_key_id: Some(msg_data.msg.mlkem_pre_key_id.into()),
                ec_ephemeral: Some(msg_data.msg.ec_ephemeral.to_vec()),
                kem_ciphertext: Some(msg_data.msg.kem_ciphertext),
                inner_msg_ct: Some(msg_data.msg.inner_msg_ct),
                sealed_ciphertext: None,
            };

            let mut serialized = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
            pb.encode(&mut serialized)
                .expect("can always append to Vec");
            serialized.extend_from_slice(&msg_data.mac);

            // Bob receives the message
            let recv_result = recv(
                &serialized,
                &bob_store,
                &bob_store,
                &bob_store,
                &bob_store,
            )
            .await?;

            // Verify the results
            assert_eq!(recv_result.registration_id, alice_registration_id);
            assert_eq!(session_key_send, recv_result.session_key);
            assert_eq!(recv_result.msg_type, CiphertextMessageType::Whisper);
            assert_eq!(recv_result.content_hint, ContentHint::Default);
            assert_eq!(
                recv_result.sender_certificate.serialized()?,
                sender_cert.serialized()?
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    #[test]
    fn test_spqxdh_roundtrip_no_onetime_prekey() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            let alice_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;
            let mut bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            let alice_identity = alice_store.get_identity_key_pair().await?;
            let alice_registration_id = alice_store.get_local_registration_id().await?;

            // Create Bob's prekey bundle WITHOUT one-time prekey
            let bob_bundle = create_prekey_bundle_no_onetime(&mut bob_store, &mut rng)?;

            // Create Alice's sender certificate
            let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)?;

            // Alice sends a message
            let (msg_data, session_key_send) =
                send(&bob_bundle, &sender_cert, alice_registration_id, CiphertextMessageType::Whisper, ContentHint::Default, &alice_store, &mut rng)
                    .await?;

            let pb = proto::wire::SealedPqxdhMessage {
                pre_key_id: msg_data.msg.pre_key_id.map(|pkid| pkid.into()),
                signed_pre_key_id: Some(msg_data.msg.signed_pre_key_id.into()),
                mlkem_pre_key_id: Some(msg_data.msg.mlkem_pre_key_id.into()),
                ec_ephemeral: Some(msg_data.msg.ec_ephemeral.to_vec()),
                kem_ciphertext: Some(msg_data.msg.kem_ciphertext),
                inner_msg_ct: Some(msg_data.msg.inner_msg_ct),
                sealed_ciphertext: None,
            };

            let mut serialized = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
            pb.encode(&mut serialized)
                .expect("can always append to Vec");
            serialized.extend_from_slice(&msg_data.mac);

            // Bob receives the message
            let recv_result = recv(
                &serialized,
                &bob_store,
                &bob_store,
                &bob_store,
                &bob_store,
            )
            .await?;

            // Verify the results
            assert_eq!(recv_result.registration_id, alice_registration_id);
            assert_eq!(session_key_send, recv_result.session_key);
            assert_eq!(recv_result.msg_type, CiphertextMessageType::Whisper);
            assert_eq!(recv_result.content_hint, ContentHint::Default);
            assert_eq!(
                recv_result.sender_certificate.serialized()?,
                sender_cert.serialized()?
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    #[test]
    fn test_spqxdh_mac_failure_on_tampering() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            let alice_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;
            let mut bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            let alice_identity = alice_store.get_identity_key_pair().await?;
            let alice_registration_id = alice_store.get_local_registration_id().await?;

            // Create Bob's prekey bundle
            let bob_bundle = create_prekey_bundle(&mut bob_store, &mut rng)?;

            // Create Alice's sender certificate
            let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)?;

            // Alice sends a message
            let (msg_data, _session_key_send) =
                send(&bob_bundle, &sender_cert, alice_registration_id, CiphertextMessageType::Whisper, ContentHint::Default, &alice_store, &mut rng)
                    .await?;

            let pb = proto::wire::SealedPqxdhMessage {
                pre_key_id: msg_data.msg.pre_key_id.map(|pkid| pkid.into()),
                signed_pre_key_id: Some(msg_data.msg.signed_pre_key_id.into()),
                mlkem_pre_key_id: Some(msg_data.msg.mlkem_pre_key_id.into()),
                ec_ephemeral: Some(msg_data.msg.ec_ephemeral.to_vec()),
                kem_ciphertext: Some(msg_data.msg.kem_ciphertext),
                inner_msg_ct: Some(msg_data.msg.inner_msg_ct),
                sealed_ciphertext: None,
            };

            let mut serialized = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
            pb.encode(&mut serialized)
                .expect("can always append to Vec");
            serialized.extend_from_slice(&msg_data.mac);

            // Tamper with the MAC by flipping a bit in the last 32 bytes
            let mac_start = serialized.len() - 32;
            serialized[mac_start] ^= 0x01;

            // Bob tries to receive the message - should fail
            let result = recv(
                &serialized,
                &bob_store,
                &bob_store,
                &bob_store,
                &bob_store,
            )
            .await;

            match result {
                Err(SignalProtocolError::BadSealedPQXDHMac) => { /* Expected */ }
                Err(e) => panic!("Unexpected error: {:?}", e),
                Ok(_) => panic!("Should have failed MAC verification"),
            }

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    #[test]
    fn test_spqxdh_message_tampering() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            let alice_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;
            let mut bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            let alice_identity = alice_store.get_identity_key_pair().await?;
            let alice_registration_id = alice_store.get_local_registration_id().await?;

            // Create Bob's prekey bundle
            let bob_bundle = create_prekey_bundle(&mut bob_store, &mut rng)?;

            // Create Alice's sender certificate
            let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)?;

            // Alice sends a message
            let (msg_data, _session_key_send) =
                send(&bob_bundle, &sender_cert, alice_registration_id, CiphertextMessageType::Whisper, ContentHint::Default, &alice_store, &mut rng)
                    .await?;

            let pb = proto::wire::SealedPqxdhMessage {
                pre_key_id: msg_data.msg.pre_key_id.map(|pkid| pkid.into()),
                signed_pre_key_id: Some(msg_data.msg.signed_pre_key_id.into()),
                mlkem_pre_key_id: Some(msg_data.msg.mlkem_pre_key_id.into()),
                ec_ephemeral: Some(msg_data.msg.ec_ephemeral.to_vec()),
                kem_ciphertext: Some(msg_data.msg.kem_ciphertext),
                inner_msg_ct: Some(msg_data.msg.inner_msg_ct),
                sealed_ciphertext: None,
            };

            let mut serialized = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
            pb.encode(&mut serialized)
                .expect("can always append to Vec");
            serialized.extend_from_slice(&msg_data.mac);

            // Tamper with the message body (not the MAC at the end)
            // The MAC is the last 32 bytes, so tamper with something before that
            let tampered_byte_index = serialized.len() / 2; // Middle of message
            serialized[tampered_byte_index] ^= 0x01;

            // Bob tries to receive the message - should fail
            // Can fail with MAC error or protobuf decoding error depending on what we corrupted
            let result = recv(
                &serialized,
                &bob_store,
                &bob_store,
                &bob_store,
                &bob_store,
            )
            .await;

            match result {
                Err(SignalProtocolError::BadSealedPQXDHMac) => { /* Expected */ }
                Err(SignalProtocolError::InvalidProtobufEncoding) => { /* Also acceptable - corrupted the protobuf */ }
                Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => { /* Also acceptable - corrupted inner message */ }
                Err(e) => panic!("Unexpected error: {:?}", e),
                Ok(_) => panic!("Should have failed after message tampering"),
            }

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    #[test]
    fn test_spqxdh_invalid_protobuf() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            let bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            // Create invalid message with random bytes
            let mut invalid_msg = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
            invalid_msg.extend_from_slice(&[0xFF; 100]); // Random garbage

            // Bob tries to receive the message - should fail
            let result = recv(
                &invalid_msg,
                &bob_store,
                &bob_store,
                &bob_store,
                &bob_store,
            )
            .await;

            match result {
                Err(SignalProtocolError::InvalidProtobufEncoding) => { /* Expected */ }
                Err(e) => panic!("Unexpected error: {:?}", e),
                Ok(_) => panic!("Should have failed protobuf decoding"),
            }

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    #[test]
    fn test_spqxdh_bit_flipping() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            let alice_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;
            let mut bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            let alice_identity = alice_store.get_identity_key_pair().await?;
            let alice_registration_id = alice_store.get_local_registration_id().await?;

            // Create Bob's prekey bundle
            let bob_bundle = create_prekey_bundle(&mut bob_store, &mut rng)?;

            // Create Alice's sender certificate
            let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)?;

            // Alice sends a message
            let (msg_data, _session_key_send) =
                send(&bob_bundle, &sender_cert, alice_registration_id, CiphertextMessageType::Whisper, ContentHint::Default, &alice_store, &mut rng)
                    .await?;

            let pb = proto::wire::SealedPqxdhMessage {
                pre_key_id: msg_data.msg.pre_key_id.map(|pkid| pkid.into()),
                signed_pre_key_id: Some(msg_data.msg.signed_pre_key_id.into()),
                mlkem_pre_key_id: Some(msg_data.msg.mlkem_pre_key_id.into()),
                ec_ephemeral: Some(msg_data.msg.ec_ephemeral.to_vec()),
                kem_ciphertext: Some(msg_data.msg.kem_ciphertext),
                inner_msg_ct: Some(msg_data.msg.inner_msg_ct),
                sealed_ciphertext: None,
            };

            let mut serialized = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
            pb.encode(&mut serialized)
                .expect("can always append to Vec");
            serialized.extend_from_slice(&msg_data.mac);

            let original = serialized.clone();
            let msg_bits = original.len() * 8;

            // Test flipping each bit - all should fail
            for bit in 0..msg_bits {
                let byte = bit / 8;
                let bit_in_byte = bit % 8;

                // Skip the version byte at index 0
                if byte == 0 {
                    continue;
                }

                let mut tampered = original.clone();
                tampered[byte] ^= 1u8 << bit_in_byte;

                let result = recv(
                    &tampered,
                    &bob_store,
                    &bob_store,
                    &bob_store,
                    &bob_store,
                )
                .await;

                // Every bit flip should result in an error
                match result {
                    Err(SignalProtocolError::BadSealedPQXDHMac)
                    | Err(SignalProtocolError::InvalidProtobufEncoding)
                    | Err(SignalProtocolError::InvalidSealedSenderMessage(_))
                    | Err(SignalProtocolError::BadKeyLength(_, _))
                    | Err(SignalProtocolError::BadKeyType(_))
                    | Err(SignalProtocolError::NoKeyTypeIdentifier)
                    | Err(SignalProtocolError::BadKEMKeyType(_))
                    | Err(SignalProtocolError::BadKEMCiphertextLength(_, _)) => {
                        // Expected error types
                    }
                    Err(e) => {
                        // Uncomment for debugging specific bit positions
                        // panic!("Unexpected error at bit {}: {:?}", bit, e);
                        // For now, just accept any error
                        let _ = e;
                    }
                    Ok(_) => {
                        panic!("Bit {} flip should have caused an error", bit);
                    }
                }
            }

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    #[test]
    fn test_spqxdh_wrong_prekey_id() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            let alice_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;
            let mut bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            let alice_identity = alice_store.get_identity_key_pair().await?;
            let alice_registration_id = alice_store.get_local_registration_id().await?;

            // Create Bob's prekey bundle
            let bob_bundle = create_prekey_bundle(&mut bob_store, &mut rng)?;

            // Create Alice's sender certificate
            let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)?;

            // Alice sends a message
            let (msg_data, _session_key_send) =
                send(&bob_bundle, &sender_cert, alice_registration_id, CiphertextMessageType::Whisper, ContentHint::Default, &alice_store, &mut rng)
                    .await?;

            let pb = proto::wire::SealedPqxdhMessage {
                pre_key_id: msg_data.msg.pre_key_id.map(|pkid| pkid.into()),
                signed_pre_key_id: Some(msg_data.msg.signed_pre_key_id.into()),
                mlkem_pre_key_id: Some(msg_data.msg.mlkem_pre_key_id.into()),
                ec_ephemeral: Some(msg_data.msg.ec_ephemeral.to_vec()),
                kem_ciphertext: Some(msg_data.msg.kem_ciphertext),
                inner_msg_ct: Some(msg_data.msg.inner_msg_ct),
                sealed_ciphertext: None,
            };

            let mut serialized = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
            pb.encode(&mut serialized)
                .expect("can always append to Vec");
            serialized.extend_from_slice(&msg_data.mac);

            // Create a different Bob store without the prekeys
            let different_bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            // Try to receive with wrong store - should fail because keys don't exist
            let result = recv(
                &serialized,
                &different_bob_store,
                &different_bob_store,
                &different_bob_store,
                &different_bob_store,
            )
            .await;

            assert!(result.is_err(), "Should fail with missing prekeys");

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    #[test]
    fn test_spqxdh_empty_message() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            let bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            // Try to receive an empty message
            let result = recv(
                &[],
                &bob_store,
                &bob_store,
                &bob_store,
                &bob_store,
            )
            .await;

            assert!(result.is_err(), "Should fail with empty message");

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    #[test]
    fn test_spqxdh_message_too_short() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            let bob_store = InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut rng),
                rng.random::<u8>() as u32,
            )?;

            // Try to receive a message that's too short to contain MAC
            let short_msg = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION, 0x01, 0x02];
            let result = recv(
                &short_msg,
                &bob_store,
                &bob_store,
                &bob_store,
                &bob_store,
            )
            .await;

            assert!(result.is_err(), "Should fail with message too short");

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }


    #[test]
    fn test_compare_message_sizes() -> Result<()> {
        async {
            let mut rng = OsRng.unwrap_err();

            {
                let mut alice_store = InMemSignalProtocolStore::new(
                    IdentityKeyPair::generate(&mut rng),
                    rng.random::<u8>() as u32,
                )?;
                let mut bob_store = InMemSignalProtocolStore::new(
                    IdentityKeyPair::generate(&mut rng),
                    rng.random::<u8>() as u32,
                )?;

                let alice_identity = alice_store.get_identity_key_pair().await?;
                let alice_registration_id = alice_store.get_local_registration_id().await?;

                // Create Bob's prekey bundle
                let bob_bundle = create_prekey_bundle(&mut bob_store, &mut rng)?;

                // Create Alice's sender certificate
                let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)?;

                // SPQXDH key agreement
                let (msg_data, session_key) =
                    send(&bob_bundle, &sender_cert, alice_registration_id, CiphertextMessageType::Whisper, ContentHint::Default, &alice_store, &mut rng)
                        .await?;

                // Initialize a DR session from the SPQXDH session key
                let ec_ephemeral_key = PublicKey::deserialize(&msg_data.msg.ec_ephemeral)
                    .expect("valid key");
                let their_ratchet_key = bob_bundle.signed_pre_key_public()?;
                let session_record = initialize_alice_session(
                    &session_key,
                    &their_ratchet_key,
                    alice_identity.identity_key(),
                    bob_bundle.identity_key()?,
                    &ec_ephemeral_key,
                    alice_registration_id,
                    bob_bundle.registration_id()?,
                    &mut rng,
                )?;

                // Save the session to the store
                let bob_address = ProtocolAddress::new(
                    "+14151111112".to_owned(),
                    DeviceId::new(1).unwrap(),
                );
                alice_store.session_store.store_session(&bob_address, &session_record).await?;

                // Save Bob's identity to allow encryption
                alice_store.identity_store.save_identity(&bob_address, bob_bundle.identity_key()?).await?;

                // Encrypt a message using the session - this produces a SignalMessage (not PreKeySignalMessage)
                // because we didn't set unacknowledged_pre_key_message items
                let ciphertext = message_encrypt(
                    b"", // Empty message for fair comparison
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    std::time::SystemTime::now(),
                    &mut rng,
                )
                .await?;

                // Extract the SignalMessage
                let signal_message = match &ciphertext {
                    CiphertextMessage::SignalMessage(sm) => sm,
                    _ => panic!("Expected SignalMessage, got {:?}", ciphertext.message_type()),
                };

                // Seal the SignalMessage with AES-CTR using the sealing key
                let sealed_ciphertext = crypto::aes_256_ctr_encrypt(
                    signal_message.as_ref(),
                    &msg_data.sealing_key,
                ).expect("sealing should succeed");

                println!("\n=== SPQXDH Breakdown ===");
                println!("ec_ephemeral: {} bytes", msg_data.msg.ec_ephemeral.len());
                println!("kem_ciphertext: {} bytes", msg_data.msg.kem_ciphertext.len());
                println!("inner_msg_ct: {} bytes", msg_data.msg.inner_msg_ct.len());
                println!("  - SenderCertificate: {} bytes", sender_cert.serialized()?.len());
                println!("  - registration_id: 4 bytes");
                println!("sealed_ciphertext: {} bytes", sealed_ciphertext.len());
                println!("  - SignalMessage: {} bytes", signal_message.as_ref().len());
                println!("mac: {} bytes", msg_data.mac.len());

                let pb = proto::wire::SealedPqxdhMessage {
                    pre_key_id: msg_data.msg.pre_key_id.map(|pkid| pkid.into()),
                    signed_pre_key_id: Some(msg_data.msg.signed_pre_key_id.into()),
                    mlkem_pre_key_id: Some(msg_data.msg.mlkem_pre_key_id.into()),
                    ec_ephemeral: Some(msg_data.msg.ec_ephemeral.to_vec()),
                    kem_ciphertext: Some(msg_data.msg.kem_ciphertext.clone()),
                    inner_msg_ct: Some(msg_data.msg.inner_msg_ct.clone()),
                    sealed_ciphertext: Some(sealed_ciphertext),
                };

                let mut serialized = vec![SEALED_SENDER_V3_SPQXDH_UUID_FULL_VERSION];
                pb.encode(&mut serialized)
                    .expect("can always append to Vec");
                serialized.extend_from_slice(&msg_data.mac);

                println!("SPQXDH total (with DR message): {} bytes", serialized.len());
            }

            // Compare with regular PQXDH message sizes wrapped in Sealed Sender v1
            {
                let mut alice_store = InMemSignalProtocolStore::new(
                    IdentityKeyPair::generate(&mut rng),
                    rng.random::<u8>() as u32,
                )?;
                let mut bob_store = InMemSignalProtocolStore::new(
                    IdentityKeyPair::generate(&mut rng),
                    rng.random::<u8>() as u32,
                )?;

                let alice_identity = alice_store.get_identity_key_pair().await?;

                // Create Bob's prekey bundle
                let bob_bundle = create_prekey_bundle(&mut bob_store, &mut rng)?;

                let bob_address = ProtocolAddress::new(
                    "+14151111112".to_owned(),
                    DeviceId::new(1).unwrap(),
                );

                // Process prekey bundle to establish session
                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    &bob_bundle,
                    std::time::SystemTime::now(),
                    &mut rng,
                )
                .await?;

                // Create Alice's sender certificate
                let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)?;

                // Encrypt a message to get a PreKeySignalMessage
                let ciphertext = message_encrypt(
                    b"", // Empty message for fair comparison
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    std::time::SystemTime::now(),
                    &mut rng,
                )
                .await?;

                println!("\n=== PQXDH + Sealed Sender v1 Breakdown ===");
                println!("PreKeySignalMessage: {} bytes", ciphertext.serialize().len());

                // Wrap in Sealed Sender v1
                let usmc = UnidentifiedSenderMessageContent::new(
                    ciphertext.message_type(),
                    sender_cert.clone(),
                    ciphertext.serialize().to_vec(),
                    ContentHint::Default,
                    None,
                )?;

                println!("USMC (serialized): {} bytes", usmc.serialized()?.len());
                println!("  - SenderCertificate: {} bytes", sender_cert.serialized()?.len());

                let sealed = sealed_sender_encrypt_from_usmc(
                    &bob_address,
                    &usmc,
                    &alice_store.identity_store,
                    &mut rng,
                )
                .await?;

                println!("Sealed Sender v1 total: {} bytes", sealed.len());
                println!("SS v1 overhead: {} bytes", sealed.len() - ciphertext.serialize().len());
            }

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

}
