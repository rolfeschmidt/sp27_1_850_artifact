//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Micro-benchmarks for XHMQV aggregated key computation (B).
//! Compares naive repeated scalar-mul + add vs. vartime_multiscalar_mul.

use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use libsignal_protocol::xhmqv;
use rand::rngs::OsRng;
use rand::{RngCore as _, TryRngCore as _};

fn random_scalar(rng: &mut rand_core::UnwrapErr<OsRng>) -> Scalar {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

pub fn bench_multiscalar(c: &mut Criterion) {
    let mut rng = OsRng.unwrap_err();

    // Generate receiver public keys (Ristretto)
    let ik = xhmqv::RistrettoKeyPair::generate(&mut rng);
    let spk = xhmqv::RistrettoKeyPair::generate(&mut rng);
    let opk = xhmqv::RistrettoKeyPair::generate(&mut rng);

    // Random scalars e1,e2
    let e1 = random_scalar(&mut rng);
    let e2 = random_scalar(&mut rng);

    // Pre-extract points
    let ik_pt = *ik.public_key.point();
    let spk_pt = *spk.public_key.point();
    let opk_pt = *opk.public_key.point();

    c.bench_function("xhmqv/agg_key_naive_no_opk", |b| {
        b.iter(|| {
            let p = ik_pt * e1 + spk_pt * e2;
            let _compressed = p.compress();
        })
    });

    c.bench_function("xhmqv/agg_key_multiscalar_no_opk", |b| {
        b.iter(|| {
            let scalars = vec![e1, e2];
            let points = vec![ik_pt, spk_pt];
            let p = RistrettoPoint::vartime_multiscalar_mul(scalars, points);
            let _compressed = p.compress();
        })
    });

    c.bench_function("xhmqv/agg_key_naive_with_opk", |b| {
        b.iter(|| {
            let p = ik_pt * e1 + spk_pt * e2 + opk_pt;
            let _compressed = p.compress();
        })
    });

    c.bench_function("xhmqv/agg_key_multiscalar_with_opk", |b| {
        b.iter(|| {
            let scalars = vec![e1, e2, Scalar::ONE];
            let points = vec![ik_pt, spk_pt, opk_pt];
            let p = RistrettoPoint::vartime_multiscalar_mul(scalars, points);
            let _compressed = p.compress();
        })
    });
}

criterion_group!(benches, bench_multiscalar);
criterion_main!(benches);

