//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Benchmarks for SealedRingXKEMXHMQV session establishment.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use futures_util::FutureExt;
use ed25519_dalek::Signer as _;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

#[path = "../tests/support/mod.rs"]
mod support;

fn make_classical_bundle<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> sealed_ringxkem_xhmqv::ClassicalBundle {
    // Minimal inline re-creation of helper used in tests
    let ik = xhmqv::RistrettoKeyPair::generate(rng);
    let spk = xhmqv::RistrettoKeyPair::generate(rng);
    let opk = Some(xhmqv::RistrettoKeyPair::generate(rng));
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let ed_vk = ed_sk.verifying_key();
    let spk_sig = ed_sk.sign(&spk.public_key.serialize()).to_vec();
    sealed_ringxkem_xhmqv::ClassicalBundle {
        identity_key: ik.public_key,
        signed_prekey: spk.public_key,
        signed_prekey_signature: spk_sig,
        one_time_prekey: opk.as_ref().map(|k| k.public_key),
        ed25519_verify_key: ed_vk,
    }
}

fn make_pq_bundle<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> (sealed_ringxkem_xhmqv::PqBundle, kem::KeyPair, kem::KeyPair, (Vec<u8>, crate::pure_falcon::SecretKey)) {
    let ek_id = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
    let ek_spk = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
    let (vkr_pk, vkr_sk) = crate::pure_falcon::keypair();
    let spk_sig = crate::pure_falcon::sign(&vkr_sk, &ek_spk.public_key.serialize());
    (
        sealed_ringxkem_xhmqv::PqBundle {
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

fn create_sender_cert(rng: &mut rand_core::UnwrapErr<OsRng>) -> SenderCertificate {
    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let server_cert = ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, rng).unwrap();
    let device_id = DeviceId::new(42).unwrap();
    let expires = Timestamp::from_epoch_millis(1605722925);
    let id_pair = IdentityKeyPair::generate(rng);
    SenderCertificate::new(
        "user-aci".to_string(),
        Some("+14150000000".to_string()),
        *id_pair.public_key(),
        device_id,
        expires,
        server_cert,
        &server_key.private_key,
        rng,
    )
    .unwrap()
}

fn create_full_bundle<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> (
    sealed_ringxkem_xhmqv::SealedRingXkemXhmqvPreKeyBundle,
    xhmqv::RistrettoKeyPair,
    xhmqv::RistrettoKeyPair,
    Option<xhmqv::RistrettoKeyPair>,
    kem::KeyPair,
    kem::KeyPair,
    Vec<u8>,
) {
    // Classical with keypairs retained
    let ik = xhmqv::RistrettoKeyPair::generate(rng);
    let spk = xhmqv::RistrettoKeyPair::generate(rng);
    let opk = Some(xhmqv::RistrettoKeyPair::generate(rng));
    let mut seed = [0u8; 32]; rng.fill_bytes(&mut seed);
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let ed_vk = ed_sk.verifying_key();
    let spk_sig = ed_sk.sign(&spk.public_key.serialize()).to_vec();
    let classical = sealed_ringxkem_xhmqv::ClassicalBundle {
        identity_key: ik.public_key,
        signed_prekey: spk.public_key,
        signed_prekey_signature: spk_sig,
        one_time_prekey: opk.as_ref().map(|k| k.public_key),
        ed25519_verify_key: ed_vk,
    };

    // PQ with keypairs retained
    let ek_id = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
    let ek_spk = kem::KeyPair::generate(kem::KeyType::MLKEM1024, rng);
    let (vkr_pk, vkr_sk) = crate::pure_falcon::keypair();
    let spk_sig_pq = crate::pure_falcon::sign(&vkr_sk, &ek_spk.public_key.serialize());
    let pq = sealed_ringxkem_xhmqv::PqBundle {
        receiver_falcon_vkey: vkr_pk.clone(),
        mlkem_identity_key: ek_id.public_key.clone(),
        mlkem_signed_prekey: ek_spk.public_key.clone(),
        mlkem_signed_prekey_signature: spk_sig_pq,
    };

    let bundle = sealed_ringxkem_xhmqv::SealedRingXkemXhmqvPreKeyBundle { classical, pq, registration_id: 42 };
    (bundle, ik, spk, opk, ek_id, ek_spk, vkr_pk)
}

pub fn sealed_ringxkem_benches(c: &mut Criterion) {
    let mut rng = OsRng.unwrap_err();

    // Static receiver materials + private keys retained
    let (bundle, ik_kp, spk_kp, opk_kp, pq_id_kp, pq_spk_kp, vkr_pk) = create_full_bundle(&mut rng);

    let bob_address = ProtocolAddress::new(
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
        DeviceId::new(1).unwrap(),
    );

    let alice_store_template = support::test_in_memory_protocol_store().expect("brand new store");
    let mut bob_store = support::test_in_memory_protocol_store().expect("brand new store");

    // Sender cert and identities
    let sender_cert = create_sender_cert(&mut rng);
    let sender_classical = xhmqv::RistrettoKeyPair::generate(&mut rng);
    let (vks_pk, vks_sk) = crate::pure_falcon::keypair();

    c.bench_function("sealed_ringxkem_xhmqv/session_establish_encrypt", |b| {
        b.iter(|| {
            let params = sealed_ringxkem_xhmqv::SendParams {
                sender_classical_identity: &sender_classical,
                sender_falcon_sk: &vks_sk,
                sender_falcon_vk: &vks_pk,
                cert: &sender_cert,
                registration_id: 7777,
                msg_type: CiphertextMessageType::Whisper,
                content_hint: ContentHint::Default,
            };
            // SPHASE: protocol send
            let (msg_data, session_key) = sealed_ringxkem_xhmqv::send(&bundle, &params, &mut rng).expect("send");

            // Initialize DR session from derived session key (for fair comparison)
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

            // ratchet key: receiver's identity key (long-term)
            let bob_identity = bob_store
                .identity_store
                .get_identity_key_pair()
                .now_or_never()
                .expect("sync")
                .expect("valid");
            let their_ratchet_key = *bob_identity.public_key();
            // base key: wrap XHMQV ephemeral bits as DJB public key
            let our_base_key = {
                let mut bytes = [0u8; 33];
                bytes[0] = 0x05;
                bytes[1..].copy_from_slice(msg_data.ec_ephemeral());
                PublicKey::try_from(&bytes[..]).expect("valid base key")
            };
            let session_record = sealed_ringxkem_xhmqv::initialize_alice_session(
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

            // Encrypt DR message
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

            // Seal DR content with AES-CTR using protocol sealing key
            let signal_message = match &ciphertext {
                CiphertextMessage::SignalMessage(sm) => sm,
                _ => panic!("Expected SignalMessage"),
            };

            black_box(
                spqxdh::aes_256_ctr_encrypt(signal_message.as_ref(), msg_data.sealing_key())
                    .expect("valid"),
            )
        })
    });

    // Prepare a message for decrypt benchmark
    let params = sealed_ringxkem_xhmqv::SendParams {
        sender_classical_identity: &sender_classical,
        sender_falcon_sk: &vks_sk,
        sender_falcon_vk: &vks_pk,
        cert: &sender_cert,
        registration_id: 7777,
        msg_type: CiphertextMessageType::Whisper,
        content_hint: ContentHint::Default,
    };
    let (msg_data, _session_key) = sealed_ringxkem_xhmqv::send(&bundle, &params, &mut rng).expect("send");
    let serialized = msg_data.serialize();

    let recv_params_full = sealed_ringxkem_xhmqv::RecvParams {
        receiver_identity: &ik_kp,
        receiver_signed_prekey: &spk_kp,
        receiver_one_time_prekey: opk_kp.as_ref(),
        pq_identity_kp: &pq_id_kp,
        pq_signed_prekey_kp: &pq_spk_kp,
        receiver_falcon_vk: &vkr_pk,
    };

    c.bench_function("sealed_ringxkem_xhmqv/session_establish_decrypt", |b| {
        b.iter(|| {
            // Recv protocol
            let recv_result = sealed_ringxkem_xhmqv::recv(&serialized, &recv_params_full).expect("recv");

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
            let their_base_key = {
                let mut bytes = [0u8; 33];
                bytes[0] = 0x05;
                bytes[1..].copy_from_slice(msg_data.ec_ephemeral());
                PublicKey::try_from(&bytes[..]).expect("valid base key")
            };
            let signed_pre_key_pair = KeyPair::try_from(*bob_identity.private_key()).expect("keypair");

            let bob_session_record = sealed_ringxkem_xhmqv::initialize_bob_session(
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

criterion_group!(benches, sealed_ringxkem_benches);
criterion_main!(benches);
