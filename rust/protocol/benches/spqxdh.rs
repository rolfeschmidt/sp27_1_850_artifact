//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Benchmarks comparing SPQXDH vs PQXDH + Sealed Sender v1 for session establishment.
//!
//! Both protocols are measured for the full session establishment flow:
//! - Encrypt: Full key agreement + message encryption + sealing
//! - Decrypt: Unsealing + key agreement + message decryption

use std::hint::black_box;
use std::time::SystemTime;

use criterion::{Criterion, criterion_group, criterion_main};
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

#[path = "../tests/support/mod.rs"]
mod support;

fn create_sender_cert(
    identity_key: PublicKey,
    rng: &mut rand_core::UnwrapErr<OsRng>,
) -> Result<SenderCertificate, SignalProtocolError> {
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

/// Benchmark PQXDH session establishment + Sealed Sender v1 wrapping.
/// This measures the full cost of establishing a new session and sending the first message.
pub fn pqxdh_sealed_sender_v1(c: &mut Criterion) {
    let mut rng = OsRng.unwrap_err();

    let bob_address = ProtocolAddress::new(
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
        DeviceId::new(1).unwrap(),
    );

    // Create a template store for Alice that we'll clone for each iteration
    let alice_store_template = support::test_in_memory_protocol_store().expect("brand new store");
    let alice_identity = alice_store_template
        .get_identity_key_pair()
        .now_or_never()
        .expect("sync")
        .expect("valid");
    let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)
        .expect("valid sender cert");

    // Create Bob's store with prekeys
    let mut bob_store = support::test_in_memory_protocol_store().expect("brand new store");
    let bob_pre_key_bundle = support::create_pre_key_bundle(&mut bob_store, &mut rng)
        .now_or_never()
        .expect("sync")
        .expect("valid");

    // For encrypt benchmark: measure process_prekey_bundle + message_encrypt + sealed_sender_encrypt
    c.bench_function("pqxdh+ss_v1/session_establish_encrypt", |b| {
        b.iter(|| {
            // Fresh store for each iteration to measure full session establishment
            let mut alice_store = alice_store_template.clone();

            // 1. Process prekey bundle (PQXDH key agreement, establishes session)
            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("valid");

            // 2. Encrypt first message (creates PreKeySignalMessage)
            let ciphertext = message_encrypt(
                b"test message",
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                SystemTime::now(),
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("valid");

            // 3. Wrap in Sealed Sender v1
            let usmc = UnidentifiedSenderMessageContent::new(
                ciphertext.message_type(),
                sender_cert.clone(),
                ciphertext.serialize().to_vec(),
                ContentHint::Default,
                None,
            )
            .expect("valid");

            black_box(
                sealed_sender_encrypt_from_usmc(
                    &bob_address,
                    &usmc,
                    &alice_store.identity_store,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("valid"),
            )
        })
    });

    // Create a sealed message for decrypt benchmark
    let mut alice_store_for_msg = alice_store_template.clone();
    process_prekey_bundle(
        &bob_address,
        &mut alice_store_for_msg.session_store,
        &mut alice_store_for_msg.identity_store,
        &bob_pre_key_bundle,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .expect("sync")
    .expect("valid");

    let ciphertext = message_encrypt(
        b"test message",
        &bob_address,
        &mut alice_store_for_msg.session_store,
        &mut alice_store_for_msg.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .expect("sync")
    .expect("valid");

    let usmc = UnidentifiedSenderMessageContent::new(
        ciphertext.message_type(),
        sender_cert.clone(),
        ciphertext.serialize().to_vec(),
        ContentHint::Default,
        None,
    )
    .expect("valid");

    let sealed_message = sealed_sender_encrypt_from_usmc(
        &bob_address,
        &usmc,
        &alice_store_for_msg.identity_store,
        &mut rng,
    )
    .now_or_never()
    .expect("sync")
    .expect("valid");

    // For decrypt benchmark: measure SS unseal + PreKeySignalMessage processing
    // This includes the full PQXDH key agreement (ML-KEM decapsulation) for fair comparison
    let bob_store_template = bob_store.clone();
    let alice_address = ProtocolAddress::new(
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_owned(),
        DeviceId::new(1).unwrap(),
    );

    c.bench_function("pqxdh+ss_v1/session_establish_decrypt", |b| {
        b.iter(|| {
            // Fresh store for each iteration to measure full session establishment
            let mut bob_store_fresh = bob_store_template.clone();

            // 1. Unseal the message (X25519 DH for SS v1)
            let usmc = sealed_sender_decrypt_to_usmc(&sealed_message, &bob_store_fresh.identity_store)
                .now_or_never()
                .expect("sync")
                .expect("valid");

            // 2. Process the PreKeySignalMessage (PQXDH including ML-KEM decapsulation)
            let prekey_message = PreKeySignalMessage::try_from(usmc.contents().expect("valid"))
                .expect("valid prekey message");

            black_box(
                message_decrypt_prekey(
                    &prekey_message,
                    &alice_address,
                    &mut bob_store_fresh.session_store,
                    &mut bob_store_fresh.identity_store,
                    &mut bob_store_fresh.pre_key_store,
                    &bob_store_fresh.signed_pre_key_store,
                    &mut bob_store_fresh.kyber_pre_key_store,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("valid"),
            )
        })
    });
}

/// Benchmark SPQXDH session establishment.
/// SPQXDH combines key agreement and sealed sender in a single protocol.
pub fn spqxdh_bench(c: &mut Criterion) {
    let mut rng = OsRng.unwrap_err();

    let bob_address = ProtocolAddress::new(
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
        DeviceId::new(1).unwrap(),
    );

    let alice_store_template = support::test_in_memory_protocol_store().expect("brand new store");
    let mut bob_store = support::test_in_memory_protocol_store().expect("brand new store");

    let bob_pre_key_bundle = support::create_pre_key_bundle(&mut bob_store, &mut rng)
        .now_or_never()
        .expect("sync")
        .expect("valid");

    // Get Bob's signed pre-key pair for session initialization
    let bob_signed_pre_key_id = bob_pre_key_bundle.signed_pre_key_id().expect("valid");
    let bob_signed_pre_key_pair = bob_store
        .signed_pre_key_store
        .get_signed_pre_key(bob_signed_pre_key_id)
        .now_or_never()
        .expect("sync")
        .expect("valid")
        .key_pair()
        .expect("valid");

    let alice_identity = alice_store_template
        .get_identity_key_pair()
        .now_or_never()
        .expect("sync")
        .expect("valid");

    let alice_registration_id = alice_store_template
        .get_local_registration_id()
        .now_or_never()
        .expect("sync")
        .expect("valid");

    let sender_cert = create_sender_cert(*alice_identity.public_key(), &mut rng)
        .expect("valid sender cert");

    // Benchmark SPQXDH encrypt (full key agreement + DR message encryption + sealing)
    c.bench_function("spqxdh/session_establish_encrypt", |b| {
        b.iter(|| {
            let mut alice_store = alice_store_template.clone();

            // 1. SPQXDH key agreement
            let (msg_data, session_key) = spqxdh::send(
                &bob_pre_key_bundle,
                &sender_cert,
                alice_registration_id,
                CiphertextMessageType::Whisper,
                ContentHint::Default,
                &alice_store.identity_store,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("valid");

            // 2. Initialize DR session from SPQXDH session key
            let ec_ephemeral_key = PublicKey::deserialize(msg_data.ec_ephemeral())
                .expect("valid key");
            let their_ratchet_key = bob_pre_key_bundle.signed_pre_key_public().expect("valid");
            let session_record = spqxdh::initialize_alice_session(
                &session_key,
                &their_ratchet_key,
                alice_identity.identity_key(),
                bob_pre_key_bundle.identity_key().expect("valid"),
                &ec_ephemeral_key,
                alice_registration_id,
                bob_pre_key_bundle.registration_id().expect("valid"),
                &mut rng,
            )
            .expect("valid session");

            // Save session to store
            alice_store
                .session_store
                .store_session(&bob_address, &session_record)
                .now_or_never()
                .expect("sync")
                .expect("valid");

            // Save Bob's identity
            alice_store
                .identity_store
                .save_identity(&bob_address, bob_pre_key_bundle.identity_key().expect("valid"))
                .now_or_never()
                .expect("sync")
                .expect("valid");

            // 3. Encrypt message with DR session
            let ciphertext = message_encrypt(
                b"test message",
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                SystemTime::now(),
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("valid");

            // 4. Seal the SignalMessage with AES-CTR
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

    // Create a complete SPQXDH message for decrypt benchmark
    let mut alice_store_for_msg = alice_store_template.clone();
    let (spqxdh_msg_data, session_key) = spqxdh::send(
        &bob_pre_key_bundle,
        &sender_cert,
        alice_registration_id,
        CiphertextMessageType::Whisper,
        ContentHint::Default,
        &alice_store_for_msg.identity_store,
        &mut rng,
    )
    .now_or_never()
    .expect("sync")
    .expect("valid");

    // Initialize Alice's session and encrypt a message
    let ec_ephemeral_key = PublicKey::deserialize(spqxdh_msg_data.ec_ephemeral())
        .expect("valid key");
    let their_ratchet_key = bob_pre_key_bundle.signed_pre_key_public().expect("valid");
    let alice_session_record = spqxdh::initialize_alice_session(
        &session_key,
        &their_ratchet_key,
        alice_identity.identity_key(),
        bob_pre_key_bundle.identity_key().expect("valid"),
        &ec_ephemeral_key,
        alice_registration_id,
        bob_pre_key_bundle.registration_id().expect("valid"),
        &mut rng,
    )
    .expect("valid session");

    alice_store_for_msg
        .session_store
        .store_session(&bob_address, &alice_session_record)
        .now_or_never()
        .expect("sync")
        .expect("valid");

    alice_store_for_msg
        .identity_store
        .save_identity(&bob_address, bob_pre_key_bundle.identity_key().expect("valid"))
        .now_or_never()
        .expect("sync")
        .expect("valid");

    let ciphertext = message_encrypt(
        b"test message",
        &bob_address,
        &mut alice_store_for_msg.session_store,
        &mut alice_store_for_msg.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .expect("sync")
    .expect("valid");

    let signal_message = match &ciphertext {
        CiphertextMessage::SignalMessage(sm) => sm,
        _ => panic!("Expected SignalMessage"),
    };

    let sealed_dr_message = spqxdh::aes_256_ctr_encrypt(signal_message.as_ref(), spqxdh_msg_data.sealing_key())
        .expect("valid");

    let spqxdh_serialized = spqxdh_msg_data.serialize();

    let alice_address = ProtocolAddress::new(
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_owned(),
        DeviceId::new(1).unwrap(),
    );

    let bob_store_template = bob_store.clone();

    // Benchmark SPQXDH decrypt (full key agreement + unsealing + DR message decryption)
    c.bench_function("spqxdh/session_establish_decrypt", |b| {
        b.iter(|| {
            let mut bob_store_fresh = bob_store_template.clone();

            // 1. SPQXDH key agreement (receive)
            let recv_result = spqxdh::recv(
                &spqxdh_serialized,
                &bob_store_fresh.identity_store,
                &bob_store_fresh.signed_pre_key_store,
                &bob_store_fresh.kyber_pre_key_store,
                &bob_store_fresh.pre_key_store,
            )
            .now_or_never()
            .expect("sync")
            .expect("valid");

            // 2. Initialize Bob's DR session from SPQXDH session key
            let their_base_key = PublicKey::deserialize(spqxdh_msg_data.ec_ephemeral())
                .expect("valid key");
            let bob_identity = bob_store_fresh
                .identity_store
                .get_identity_key_pair()
                .now_or_never()
                .expect("sync")
                .expect("valid");
            let bob_registration_id = bob_store_fresh
                .identity_store
                .get_local_registration_id()
                .now_or_never()
                .expect("sync")
                .expect("valid");
            let their_identity_key = IdentityKey::new(recv_result.sender_certificate.key().expect("valid"));

            let bob_session_record = spqxdh::initialize_bob_session(
                &recv_result.session_key,
                &their_base_key,
                bob_identity.identity_key(),
                &their_identity_key,
                &bob_signed_pre_key_pair,
                bob_registration_id,
                recv_result.registration_id,
            )
            .expect("valid session");

            bob_store_fresh
                .session_store
                .store_session(&alice_address, &bob_session_record)
                .now_or_never()
                .expect("sync")
                .expect("valid");

            bob_store_fresh
                .identity_store
                .save_identity(&alice_address, &their_identity_key)
                .now_or_never()
                .expect("sync")
                .expect("valid");

            // 3. Unseal the DR message with AES-CTR
            let unsealed_dr_message = spqxdh::aes_256_ctr_decrypt(&sealed_dr_message, spqxdh_msg_data.sealing_key())
                .expect("valid");

            // 4. Decrypt the SignalMessage
            let signal_message = SignalMessage::try_from(&unsealed_dr_message[..])
                .expect("valid signal message");

            black_box(
                message_decrypt_signal(
                    &signal_message,
                    &alice_address,
                    &mut bob_store_fresh.session_store,
                    &mut bob_store_fresh.identity_store,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("valid"),
            )
        })
    });
}

criterion_group!(benches, pqxdh_sealed_sender_v1, spqxdh_bench);

criterion_main!(benches);
