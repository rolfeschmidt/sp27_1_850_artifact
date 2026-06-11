// Benchmarks for SealedRingXKEM+X3DH session establishment.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

#[path = "../tests/support/mod.rs"]
mod support;

fn make_pq_bundle<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> (sealed_ringxkem_x3dh::PqBundle, kem::KeyPair, kem::KeyPair, (Vec<u8>, crate::pure_falcon::SecretKey)) {
    let ek_id = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
    let ek_spk = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
    let (vkr_pk, vkr_sk) = crate::pure_falcon::keypair();
    let spk_sig = crate::pure_falcon::sign(&vkr_sk, &ek_spk.public_key.serialize());
    (
        sealed_ringxkem_x3dh::PqBundle {
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

fn create_sender_cert(identity_key: PublicKey, rng: &mut rand_core::UnwrapErr<OsRng>) -> SenderCertificate {
    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let server_cert = ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, rng).unwrap();
    let device_id = DeviceId::new(42).unwrap();
    let expires = Timestamp::from_epoch_millis(1605722925);
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

pub fn sealed_ringxkem_x3dh_benches(c: &mut Criterion) {
    let mut rng = OsRng.unwrap_err();

    // Receiver classical bundle (PreKeyBundle) + retained private keys
    let mut bob_store = support::test_in_memory_protocol_store().expect("brand new store");
    let classical = support::create_pre_key_bundle(&mut bob_store, &mut rng)
        .now_or_never()
        .expect("sync")
        .expect("valid");

    let spk_id = classical.signed_pre_key_id().expect("valid");
    let spk_kp = bob_store
        .signed_pre_key_store
        .get_signed_pre_key(spk_id)
        .now_or_never()
        .expect("sync")
        .expect("valid")
        .key_pair()
        .expect("keypair");
    let opk_kp = classical
        .pre_key_id()
        .expect("valid")
        .and_then(|id| bob_store.pre_key_store.get_pre_key(id).now_or_never().unwrap().ok())
        .map(|pkrec| pkrec.key_pair().expect("keypair"));
    let ik_kp = bob_store
        .identity_store
        .get_identity_key_pair()
        .now_or_never()
        .expect("sync")
        .expect("valid");

    let (pq_bundle, pq_id_kp, pq_spk_kp, (vkr_pk, vkr_sk)) = make_pq_bundle(&mut rng);
    let bundle = sealed_ringxkem_x3dh::SealedRingXkemX3dhPreKeyBundle { classical: classical.clone(), pq: pq_bundle, registration_id: classical.registration_id().unwrap() };

    let alice_store_template = support::test_in_memory_protocol_store().expect("brand new store");
    let sender_identity = IdentityKeyPair::generate(&mut rng);
    let sender_cert = create_sender_cert(*sender_identity.public_key(), &mut rng);
    let (vks_pk, vks_sk) = crate::pure_falcon::keypair();

    let bob_address = ProtocolAddress::new(
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
        DeviceId::new(1).unwrap(),
    );

    c.bench_function("sealed_ringxkem_x3dh/session_establish_encrypt", |b| {
        b.iter(|| {
            let params = sealed_ringxkem_x3dh::SendParams {
                sender_identity: &sender_identity,
                sender_falcon_sk: &vks_sk,
                sender_falcon_vk: &vks_pk,
                cert: &sender_cert,
                registration_id: 7777,
                msg_type: CiphertextMessageType::Whisper,
                content_hint: ContentHint::Default,
            };
            let (msg_data, session_key) = sealed_ringxkem_x3dh::send(&bundle, &params, &mut rng).expect("send");

            // Initialize a session from derived key for fair comparison
            let mut alice_store = alice_store_template.clone();
            let alice_identity = alice_store
                .get_identity_key_pair()
                .now_or_never()
                .expect("sync")
                .expect("valid");
            let alice_registration_id = alice_store
                .get_local_registration_id()
                .now_or_never()
                .expect("sync")
                .expect("valid");

            let bob_identity = bob_store
                .identity_store
                .get_identity_key_pair()
                .now_or_never()
                .expect("sync")
                .expect("valid");
            let their_ratchet_key = *bob_identity.public_key();
            let our_base_key = PublicKey::try_from(msg_data.ec_ephemeral().as_ref()).expect("base key");
            let session_record = sealed_ringxkem_x3dh::initialize_alice_session(
                &session_key,
                &their_ratchet_key,
                alice_identity.identity_key(),
                &IdentityKey::new(*bob_identity.public_key()),
                &our_base_key,
                alice_registration_id,
                bob_store
                    .identity_store
                    .get_local_registration_id()
                    .now_or_never()
                    .expect("sync")
                    .expect("valid"),
                &mut rng,
            )
            .expect("valid session");

            alice_store
                .session_store
                .store_session(&bob_address, &session_record)
                .now_or_never()
                .expect("sync")
                .expect("valid");

            alice_store
                .identity_store
                .save_identity(&bob_address, &IdentityKey::new(*bob_identity.public_key()))
                .now_or_never()
                .expect("sync")
                .expect("valid");

            // Encrypt a DR message and seal with AES-CTR using kseal
            let ciphertext = message_encrypt(
                b"test message",
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                std::time::SystemTime::now(),
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("valid");
            let signal_message = match &ciphertext { CiphertextMessage::SignalMessage(sm) => sm, _ => panic!("Expected SignalMessage"), };

            black_box(spqxdh::aes_256_ctr_encrypt(signal_message.as_ref(), msg_data.sealing_key()).expect("valid"))
        })
    });

    let params = sealed_ringxkem_x3dh::SendParams { sender_identity: &sender_identity, sender_falcon_sk: &vks_sk, sender_falcon_vk: &vks_pk, cert: &sender_cert, registration_id: 7777, msg_type: CiphertextMessageType::Whisper, content_hint: ContentHint::Default };
    let (msg_data, _session_key) = sealed_ringxkem_x3dh::send(&bundle, &params, &mut rng).expect("send");
    let serialized = msg_data.serialize();
    let recv_params_full = sealed_ringxkem_x3dh::RecvParams { receiver_signed_prekey_kp: &spk_kp, receiver_one_time_prekey_kp: opk_kp.as_ref(), receiver_identity_kp: &ik_kp, pq_identity_kp: &pq_id_kp, pq_signed_prekey_kp: &pq_spk_kp, receiver_falcon_vk: &vkr_pk };

    c.bench_function("sealed_ringxkem_x3dh/session_establish_decrypt", |b| {
        b.iter(|| {
            let recv_result = sealed_ringxkem_x3dh::recv(&serialized, &recv_params_full).expect("recv");

            // Initialize Bob DR from session key
            let bob_identity = bob_store
                .identity_store
                .get_identity_key_pair()
                .now_or_never()
                .expect("sync")
                .expect("valid");
            let bob_registration_id = bob_store
                .identity_store
                .get_local_registration_id()
                .now_or_never()
                .expect("sync")
                .expect("valid");
            let their_base_key = PublicKey::try_from(msg_data.ec_ephemeral().as_ref()).expect("base key");
            let signed_pre_key_pair = KeyPair::try_from(*bob_identity.private_key()).expect("keypair");
            let bob_session_record = sealed_ringxkem_x3dh::initialize_bob_session(
                &recv_result.session_key,
                &their_base_key,
                bob_identity.identity_key(),
                &IdentityKey::new(*bob_identity.public_key()),
                &signed_pre_key_pair,
                bob_registration_id,
                recv_result.registration_id,
            )
            .expect("valid session");

            bob_store
                .session_store
                .store_session(&bob_address, &bob_session_record)
                .now_or_never()
                .expect("sync")
                .expect("valid");

            bob_store
                .identity_store
                .save_identity(&bob_address, &IdentityKey::new(*bob_identity.public_key()))
                .now_or_never()
                .expect("sync")
                .expect("valid");

            black_box(msg_data.sealing_key());
        })
    });
}

criterion_group!(benches, sealed_ringxkem_x3dh_benches);
criterion_main!(benches);
