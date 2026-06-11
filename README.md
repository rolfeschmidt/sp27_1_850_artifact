# Signal Protocol PQ + Sealed Sender Evaluation (Standalone)

Standalone Rust project for evaluating:
- spqxdh (Sealed PQXDH)
- sealed_ringxkem_xhmqv
- sealed_ringxkem_x3dh
- baseline sealed sender + PQXDH flows

## Reproducing the Paper's Evaluation

This artifact reproduces the message-size and computation-time results in the
Evaluation section (the two tables) and the symbolic-verification results.

### Expected environment

The numbers in the paper were measured on an **Intel Core i9-14900K**,
**Ubuntu 24.04.3**, **`rustc 1.92.0-nightly`**, with `pqcrypto-falcon 0.4`,
`libcrux-ml-kem 0.0.4`, and `curve25519-dalek 4.1.3` (pinned in `Cargo.lock`).
Absolute timings are hardware-dependent; on different machines the **relative**
results (e.g. Sealed PQXDH's ~34% round-trip reduction, the hybrid's faster
decryption) should reproduce even where the absolute µs differ.

### One command for both tables

```bash
bash rust/protocol/benches/compare_spqxdh.sh
```

This builds the three protocols, runs the size tests and timing benchmarks, and
prints formatted size and timing tables for **SS+PQXDH**, **Sealed PQXDH**, and
the **Sealed RingXKEM-XHMQV** hybrid, plus the **Sealed RingXKEM-X3DH** variant
used to isolate XHMQV's contribution.

### Mapping output to the paper

**Message size (Table: session establishment message sizes).**

| Paper column | Value | Where in output |
|---|---|---|
| SS+PQXDH | 2147 B | `Sealed Sender v1 total` |
| Sealed PQXDH | 2048 B | `SPQXDH total (with DR message)` |
| Hybrid | 5695 B | `Sealed RingXKEM-XHMQV … TOTAL` **+ 625** (see note) |

Sealed PQXDH saves **99 bytes (4.6%)** over SS+PQXDH. 

**Computation time (Table: session establishment time, µs).** Encrypt / Decrypt
/ Round-trip rows map to the `session_establish_encrypt` and
`session_establish_decrypt` benchmark lines for `pqxdh+ss_v1`, `spqxdh`, and
`sealed_ringxkem_xhmqv`; round-trip is their sum. The X3DH isolation result
(hybrid 12% faster overall, decryption 195→148 µs) comes from the
`sealed_ringxkem_x3dh` benchmarks in the same run.

**Symbolic verification.** See the [Formal Models](#formal-models-proverif)
section below.

### Note on the ring signature

The full hybrid protocol specifies a **Falcon ring signature** for sender
anonymity. Lacking a ring-signature implementation, we use a standard Falcon
signature (666 B) and **conservatively estimate** the ring-signature overhead:

- **Size:** the paper adds **625 bytes** to the implemented hybrid message. The
  `test_size_breakdown` output reports the *raw* implemented size (one Falcon
  signature) — **5070 B** — so the paper's **5695 B** = 5070 + 625.
- **Timing:** the benchmarks already perform **two** Falcon
  signatures/verifications per session to model the ring-signature cost (see the
  "second, unused Falcon" steps in `src/sealed_ringxkem_xhmqv.rs` and
  `src/sealed_ringxkem_x3dh.rs`), so the reported timings need no adjustment.

## Building

```bash
cargo build --release -p libsignal-protocol
```

## Comparison Script

```bash
# From the workspace root, generate size and timing tables
bash rust/protocol/benches/compare_spqxdh.sh
```

This script runs:
- spqxdh size test: `test_compare_message_sizes` (includes Sealed Sender v1 totals)
- sealed_ringxkem_xhmqv size test: `sealed_ringxkem_xhmqv::tests::test_size_breakdown`
- sealed_ringxkem_x3dh size test: `sealed_ringxkem_x3dh::tests::test_size_breakdown`
- Benchmarks for `spqxdh`, `sealed_ringxkem_xhmqv`, and `sealed_ringxkem_x3dh`

## Running Benchmarks

```bash
# Run sealed_ringxkem_xhmqv benchmarks
cargo bench -p libsignal-protocol --bench sealed_ringxkem_xhmqv

# Run sealed_ringxkem_x3dh benchmarks
cargo bench -p libsignal-protocol --bench sealed_ringxkem_x3dh

# Run spqxdh and sealed_sender benchmarks (for comparison)
cargo bench -p libsignal-protocol --bench spqxdh
cargo bench -p libsignal-protocol --bench sealed_sender
```


## Formal Models (ProVerif)

The `models/proverif/` directory contains the symbolic-model analysis of
Sealed PQXDH, derived from the PQXDH models of Bhargavan et al.
(USENIX Security 2024). Two properties are verified:

- **Sender anonymity / transcript unlinkability** — a passive (and
  post-quantum) network observer cannot link a transcript to a sender.
- **Secrecy and authentication** — the same key-secrecy and authentication
  guarantees as PQXDH.

Requires [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) and a C
preprocessor (`cpp`) on the PATH. Models are generated from `.cpp.pv` sources
via the C preprocessor; generated `.gen.pv` files are not checked in.

```bash
cd models/proverif

# Secrecy + authentication (main PQXDH results)
make

# Sender anonymity, five threat-model scenarios
make anonymity                          # baseline
make anonymity-broken-kem               # KEM broken anytime (HNDL)
make anonymity-compromise-ik            # identity-key compromise (phase 1)
make anonymity-broken-kem-compromise-ik # both
make anonymity-broken-dh                # DH broken in phase 1 (PQ forward anon.)
```

See `models/proverif/README.md` for the full threat model, scenario list, and
expected results/timings.

## License
This code is based on Signal Messenger's `libsignal`.

Copyright 2020-2026 Signal Messenger, LLC

Licensed under the GNU AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html