This folder contains ProVerif model of the SealedPQXDH protocol. It is derived
from the models of [Bhargavan, et
al.](https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf)



## Sender Anonymity

**File:** `pqxdh-model-anonymity.cpp.pv`

This protocol introduces a modification of PQXDH to provide sender anonymity: the initiator's identity key (IKA) is now encrypted under a seal key (Kseal) derived from SK1, which is computed before including the sender's identity contribution (DH1).

### Property Tested: Transcript Unlinkability

The anonymity model verifies whether a passive network observer can distinguish between different senders (e.g., Alex vs. Blake) sending to the same responder (Charlie) by observing the network transcript.

**Simplification:** To reduce state space complexity, the anonymity model does NOT use optional one-time prekeys (OPK). All handshakes use only SPK and PQPK.

```
(IKA_ct, EKA_p, CT, SPKB_p, PQPKB_p, enc_msg)
```

Where `IKA_ct = senc(Kseal, encodeEC(IKA_p))` is the encrypted sender identity.

### Result

**✓ Diff-equivalence is true**

The protocol achieves sender anonymity:

- A network attacker cannot cryptographically link transcripts to specific sender identities
- The encryption of IKA under Kseal (derived from SK1 without the sender's DH contribution) successfully hides which initiator created the message
- The responder can still decrypt IKA_ct and authenticate the sender, but this knowledge does not leak to network observers

### Modeling Approach

This analysis uses observational equivalence (`diff[alex, blake]`) to model two scenarios where different initiators send to the same responder. The model:

- Uses a single public channel representing the network
- Removes events that would encode sender identity (InitDone, RespondDone) to avoid trivial distinguishers
- Tests whether the network transcript itself reveals sender identity

### Threat Model

**Important:** PQXDH is NOT designed to defend against active quantum attackers who can both break DH and forge prekey bundles in phase 0. DH breaking is tested in phase 1 (after protocol execution) to model post-quantum forward anonymity.

We test sender anonymity under five scenarios:

1. **Baseline**: All cryptography secure (passive network observer)
2. **Broken KEM**: Attacker can break KEM anytime
3. **Compromised IK**: Identity keys compromised in phase 1 (forward anonymity)
4. **Broken KEM + Compromised IK**: Both KEM broken and phase 1 IK compromise
5. **Broken DH**: DH broken in phase 1 (post-quantum forward anonymity)

### Running the Anonymity Analysis

```bash
make anonymity                          # 1. Baseline
make anonymity-broken-kem               # 2. Broken KEM
make anonymity-compromise-ik            # 3. Phase 1 compromised IK
make anonymity-broken-kem-compromise-ik # 4. Broken KEM + phase 1 Compromised IK
make anonymity-broken-dh                # 5. Phase 1 broken DH
```

### Results

All tests run on Intel® Core™ i9-14900K × 32.

**1. Baseline**: ✓ Diff-equivalence is TRUE (~5,200 rules, ~4 sec)

- Sender anonymity achieved with all cryptography secure
- The encryption of IKA under Kseal successfully hides sender identity

**2. Broken KEM**: ✓ Diff-equivalence is TRUE (~5,200 rules, ~4 sec)

- KEM can be broken ANYTIME (harvest-now-decrypt-later quantum threat)
- DH protects sender anonymity: attacker cannot compute DH2/DH3 without breaking DH
- Even with KEM broken, Kseal remains secret

**3. Compromised IK**: ✓ Diff-equivalence is TRUE (~11,000 rules, ~22 sec)

- Identity keys compromised in PHASE 1 (after protocol execution)
- Forward anonymity: past transcripts remain unlinkable even after IK compromise
- Encryption uses ephemeral keys (EKA), not long-term identity keys

**4. Broken KEM + Compromised IK**: ✓ Diff-equivalence is TRUE (~11,200 rules, ~23 sec)

- Both KEM broken (anytime) and IK compromised (phase 1)
- DH contributions (DH2, DH3) still protect Kseal
- Demonstrates defense-in-depth: multiple compromises don't break anonymity

**5. Broken DH** (phase 1): ✓ Diff-equivalence is TRUE (~11,000 rules, ~22 sec)

- DH broken in PHASE 1 only (post-quantum forward anonymity)
- Past transcripts remain unlinkable because KEM protected SS during execution
- Demonstrates: KEM protects sender anonymity even if DH breaks later

**Note:** The simplified model (without optional one-time prekeys) enables fast verification while still capturing the core anonymity properties.

# Secrecy and Authentication

Sealed PQXDH also shares the same secrecy and authentication properties as PQXDH, as modeled in Bhargavan, et al.

We use the cpp preprocessor to generate many possible scenarios from a single modeling file.

One can call `./run.sh tag1 ... tagn` with the list of valid tags to verify the corresponding scenario. In the `Makefile`, we provide a few of the main interesting scenarios.

The main possible tags are:

- Reach - include the reachaility queries
- SecrecyInit - Include the initiator secrecy query
- SecrecyResp - Include the responder secrecy query
- Authentication - Include the authentication query

Some simplifying tags allow to verify simpler scenarios:

- DisableNoOPK - Forces all communications to use an OPK
- UnbreakableDH - Remove the potential arrival of the discrete log algo

With the Makefile:

- `make` sets SecrecyInit, SecrecyResp and Authentication, used to reproduce the main results.
- `make reach` sets Reach, for sanity checks

For each scenario, timings and expected result can be found at the bottom of the file.
