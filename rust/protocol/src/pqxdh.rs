use libsignal_core::curve::PublicKey;
use rand::{CryptoRng, Rng};

use crate::{
    IdentityKeyStore, KeyPair, KyberPreKeyId, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyStore, Result, SenderCertificate, SignedPreKeyId, SignedPreKeyStore,
};

type SessionKey = Vec<u8>;

const DST: &[u8] = b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024";

/// Data needed to construct a PreKeySignalMessage for PQXDH.
pub struct PQXDHMessageData {
    pub base_key: PublicKey,
    pub pre_key_id: Option<PreKeyId>,
    pub signed_pre_key_id: SignedPreKeyId,
    pub kyber_pre_key_id: KyberPreKeyId,
    pub kyber_ciphertext: Vec<u8>,
}

pub async fn send<R: Rng + CryptoRng>(
    prekey_bundle: &PreKeyBundle,
    _cert: &SenderCertificate,
    _registration_id: u32,
    identity_store: &dyn IdentityKeyStore,
    rng: &mut R,
) -> Result<(PQXDHMessageData, SessionKey)> {
    let local_identity =  identity_store.get_identity_key_pair().await?;
    
    let mut secrets = Vec::with_capacity(32 * 6);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    let ephemeral = KeyPair::generate(rng);

    let our_base_private_key = ephemeral.private_key;

    secrets.extend_from_slice(
        &local_identity
            .private_key()
            .calculate_agreement(&prekey_bundle.signed_pre_key_public()?)?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(
            &prekey_bundle
                .identity_key()?
                .public_key()
            )?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(&prekey_bundle.signed_pre_key_public()?)?,
    );

    if let Some(their_one_time_prekey) = &prekey_bundle.pre_key_public()? {
        secrets
            .extend_from_slice(&our_base_private_key.calculate_agreement(their_one_time_prekey)?);
    }

    let kyber_ciphertext = {
        let (ss, ct) = prekey_bundle.kyber_pre_key_public()?.encapsulate(rng)?;
        secrets.extend_from_slice(ss.as_ref());
        ct
    };
    let mut sk = [0; 96];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &secrets)
        .expand(DST, &mut sk)
        .expect("valid length");

    let msg_data = PQXDHMessageData {
        base_key: ephemeral.public_key,
        pre_key_id: prekey_bundle.pre_key_id()?,
        signed_pre_key_id: prekey_bundle.signed_pre_key_id()?,
        kyber_pre_key_id: prekey_bundle.kyber_pre_key_id()?,
        kyber_ciphertext: kyber_ciphertext.into_vec(),
    };

    Ok((msg_data, sk.to_vec()))
}


pub async fn recv(
    _msg_bytes: &[u8],
    _identity_store: &dyn IdentityKeyStore,
    _signed_prekey_store: &dyn SignedPreKeyStore,
    _kyber_prekey_store: &dyn KyberPreKeyStore,
    _pre_key_store: &dyn PreKeyStore,
) -> Result<(SenderCertificate, u32, SessionKey)> {
    todo!();
}
