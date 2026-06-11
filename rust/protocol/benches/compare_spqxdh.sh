#!/bin/bash
#
# Compare SPQXDH vs PQXDH + Sealed Sender v1
# Runs size comparison test and timing benchmarks, then outputs formatted tables.
#

set -e

cd "$(dirname "$0")/.."

echo "Running SPQXDH size comparison test..."
SIZE_OUTPUT=$(cargo test -p libsignal-protocol test_compare_message_sizes -- --nocapture 2>&1)

echo "Running SPQXDH timing benchmarks..."
BENCH_OUTPUT=$(cargo bench -p libsignal-protocol --bench spqxdh --offline 2>&1)

echo "Running Sealed RingXKEM-XHMQV size test..."
SR_SIZE_OUTPUT=$(cargo test -p libsignal-protocol sealed_ringxkem_xhmqv::tests::test_size_breakdown -- --nocapture 2>&1)

echo "Running Sealed RingXKEM-XHMQV timing benchmarks..."
SR_BENCH_OUTPUT=$(cargo bench -p libsignal-protocol --bench sealed_ringxkem_xhmqv --offline 2>&1)

echo "Running Sealed RingXKEM-X3DH size test..."
SRX3DH_SIZE_OUTPUT=$(cargo test -p libsignal-protocol sealed_ringxkem_x3dh::tests::test_size_breakdown -- --nocapture 2>&1)

echo "Running Sealed RingXKEM-X3DH timing benchmarks..."
SRX3DH_BENCH_OUTPUT=$(cargo bench -p libsignal-protocol --bench sealed_ringxkem_x3dh --offline 2>&1)

# Extract size data using awk/grep
# "SPQXDH total (with DR message): 2048 bytes" -> field 6
SPQXDH_TOTAL=$(echo "$SIZE_OUTPUT" | awk '/SPQXDH total \(with DR message\):/ {print $6}')
# "Sealed Sender v1 total: 2146 bytes" -> field 5
SS_V1_TOTAL=$(echo "$SIZE_OUTPUT" | awk '/Sealed Sender v1 total:/ {print $5}')
# "ec_ephemeral: 33 bytes" -> field 2
SPQXDH_EC=$(echo "$SIZE_OUTPUT" | awk '/ec_ephemeral:/ {print $2}')
SPQXDH_KEM=$(echo "$SIZE_OUTPUT" | awk '/kem_ciphertext:/ {print $2}')
SPQXDH_INNER=$(echo "$SIZE_OUTPUT" | awk '/inner_msg_ct:/ {print $2}')
SPQXDH_SEALED=$(echo "$SIZE_OUTPUT" | awk '/sealed_ciphertext:/ {print $2}')
SPQXDH_MAC=$(echo "$SIZE_OUTPUT" | awk '/^mac:/ {print $2}')
PKSM_SIZE=$(echo "$SIZE_OUTPUT" | awk '/PreKeySignalMessage:/ {print $2}')
SS_OVERHEAD=$(echo "$SIZE_OUTPUT" | awk '/SS v1 overhead:/ {print $4}')

# Extract timing data (get the first value from the confidence interval)
PQXDH_ENC=$(echo "$BENCH_OUTPUT" | grep -A4 "pqxdh+ss_v1/session_establish_encrypt" | grep "time:" | head -1 | sed 's/.*\[\([0-9.]*\) µs.*/\1/')
PQXDH_DEC=$(echo "$BENCH_OUTPUT" | grep -A4 "pqxdh+ss_v1/session_establish_decrypt" | grep "time:" | head -1 | sed 's/.*\[\([0-9.]*\) µs.*/\1/')
SPQXDH_ENC=$(echo "$BENCH_OUTPUT" | grep -A4 "spqxdh/session_establish_encrypt" | grep "time:" | head -1 | sed 's/.*\[\([0-9.]*\) µs.*/\1/')
SPQXDH_DEC=$(echo "$BENCH_OUTPUT" | grep -A4 "spqxdh/session_establish_decrypt" | grep "time:" | head -1 | sed 's/.*\[\([0-9.]*\) µs.*/\1/')

# Calculate derived values
SIZE_SAVINGS=$((SS_V1_TOTAL - SPQXDH_TOTAL))
SIZE_SAVINGS_PCT=$(awk "BEGIN {printf \"%.1f\", $SIZE_SAVINGS * 100 / $SS_V1_TOTAL}")
SPQXDH_KEY_MATERIAL=$((SPQXDH_EC + SPQXDH_KEM))

PQXDH_TIME_TOTAL=$(echo "$PQXDH_ENC + $PQXDH_DEC" | bc)
SPQXDH_TIME_TOTAL=$(echo "$SPQXDH_ENC + $SPQXDH_DEC" | bc)

# Calculate improvements as percentage faster (use awk for floating point)
ENC_IMPROVEMENT=$(awk "BEGIN {printf \"%.0f\", ($PQXDH_ENC - $SPQXDH_ENC) / $PQXDH_ENC * 100}")
DEC_IMPROVEMENT=$(awk "BEGIN {printf \"%.0f\", ($PQXDH_DEC - $SPQXDH_DEC) / $PQXDH_DEC * 100}")
TOTAL_IMPROVEMENT=$(awk "BEGIN {printf \"%.0f\", ($PQXDH_TIME_TOTAL - $SPQXDH_TIME_TOTAL) / $PQXDH_TIME_TOTAL * 100}")

# Output
echo ""
echo "============================================================"
echo "    SPQXDH vs PQXDH + Sealed Sender v1 Comparison"
echo "============================================================"
echo ""
echo "MESSAGE SIZE"
echo "------------------------------------------------------------"
printf "%-35s %10s %15s\n" "Component" "SPQXDH" "PQXDH + SS v1"
echo "------------------------------------------------------------"
printf "%-35s %10s %15s\n" "Key agreement material" "${SPQXDH_KEY_MATERIAL} bytes" "${PKSM_SIZE} bytes"
printf "%-35s %10s %15s\n" "Sender identity (encrypted)" "${SPQXDH_INNER} bytes" "${SS_OVERHEAD} bytes"
printf "%-35s %10s %15s\n" "DR message (sealed)" "${SPQXDH_SEALED} bytes" "(included)"
printf "%-35s %10s %15s\n" "MAC" "${SPQXDH_MAC} bytes" "(included)"
echo "------------------------------------------------------------"
printf "%-35s %10s %15s\n" "TOTAL" "${SPQXDH_TOTAL} bytes" "${SS_V1_TOTAL} bytes"
echo "------------------------------------------------------------"
echo ""
echo "Savings: ${SIZE_SAVINGS} bytes (${SIZE_SAVINGS_PCT}% smaller)"
echo ""
echo ""
echo "TIMING (Session Establishment + First Message)"
echo "------------------------------------------------------------"
printf "%-20s %12s %12s %12s\n" "Operation" "PQXDH+SS v1" "SPQXDH" "Improvement"
echo "------------------------------------------------------------"
printf "%-20s %12s %12s %10s%% faster\n" "Encrypt" "${PQXDH_ENC} µs" "${SPQXDH_ENC} µs" "${ENC_IMPROVEMENT}"
printf "%-20s %12s %12s %10s%% faster\n" "Decrypt" "${PQXDH_DEC} µs" "${SPQXDH_DEC} µs" "${DEC_IMPROVEMENT}"
echo "------------------------------------------------------------"
printf "%-20s %12s %12s %10s%% faster\n" "Round-trip" "${PQXDH_TIME_TOTAL} µs" "${SPQXDH_TIME_TOTAL} µs" "${TOTAL_IMPROVEMENT}"
echo "------------------------------------------------------------"
echo ""
echo ""

# ------------------------------------------------------------
# Sealed RingXKEM-XHMQV (SRXKEMXHMQV)
# ------------------------------------------------------------

# Parse SR size breakdown
SR_EC=$(echo "$SR_SIZE_OUTPUT" | awk '/Ephemeral \(ristretto\):/ {print $3}')
SR_CT1=$(echo "$SR_SIZE_OUTPUT" | awk '/KEM ct1:/ {print $3}')
SR_CT2=$(echo "$SR_SIZE_OUTPUT" | awk '/KEM ct2:/ {print $3}')
SR_INNER=$(echo "$SR_SIZE_OUTPUT" | awk '/Inner total:/ {print $3}')
SR_MAC=$(echo "$SR_SIZE_OUTPUT" | awk '/MAC:/ {print $2}')
SR_TOTAL=$(echo "$SR_SIZE_OUTPUT" | awk '/TOTAL:/ {print $2}')

# Parse SR bench timings
SR_ENC=$(echo "$SR_BENCH_OUTPUT" | grep -A4 "sealed_ringxkem_xhmqv/session_establish_encrypt" | grep "time:" | head -1 | sed 's/.*\[\([0-9.]*\) µs.*/\1/')
SR_DEC=$(echo "$SR_BENCH_OUTPUT" | grep -A4 "sealed_ringxkem_xhmqv/session_establish_decrypt" | grep "time:" | head -1 | sed 's/.*\[\([0-9.]*\) µs.*/\1/')
SR_TOTAL_TIME=$(echo "$SR_ENC + $SR_DEC" | bc)

echo ""
echo "============================================================"
echo "    Sealed RingXKEM-XHMQV Size and Timing"
echo "============================================================"
echo ""
echo "MESSAGE SIZE"
echo "------------------------------------------------------------"
printf "%-30s %10s\n" "Ephemeral (ristretto)" "${SR_EC} bytes"
printf "%-30s %10s\n" "KEM ct1" "${SR_CT1} bytes"
printf "%-30s %10s\n" "KEM ct2" "${SR_CT2} bytes"
printf "%-30s %10s\n" "Inner total" "${SR_INNER} bytes"
printf "%-30s %10s\n" "MAC" "${SR_MAC} bytes"
echo "------------------------------------------------------------"
printf "%-30s %10s\n" "TOTAL" "${SR_TOTAL} bytes"
echo ""

echo "TIMING (Session Establishment)"
echo "------------------------------------------------------------"
printf "%-20s %12s\n" "Encrypt" "${SR_ENC} µs"
printf "%-20s %12s\n" "Decrypt" "${SR_DEC} µs"
echo "------------------------------------------------------------"
printf "%-20s %12s\n" "Round-trip" "${SR_TOTAL_TIME} µs"
echo ""

# ------------------------------------------------------------
# Sealed RingXKEM-X3DH (SRXKEMX3DH)
# ------------------------------------------------------------

# Parse SRX3DH size breakdown
SRX3DH_EC=$(echo "$SRX3DH_SIZE_OUTPUT" | awk '/Ephemeral \(x25519\):/ {print $3}')
SRX3DH_CT1=$(echo "$SRX3DH_SIZE_OUTPUT" | awk '/KEM ct1:/ {print $3}')
SRX3DH_CT2=$(echo "$SRX3DH_SIZE_OUTPUT" | awk '/KEM ct2:/ {print $3}')
SRX3DH_INNER=$(echo "$SRX3DH_SIZE_OUTPUT" | awk '/Inner total:/ {print $3}')
SRX3DH_MAC=$(echo "$SRX3DH_SIZE_OUTPUT" | awk '/MAC:/ {print $2}')
SRX3DH_TOTAL=$(echo "$SRX3DH_SIZE_OUTPUT" | awk '/TOTAL:/ {print $2}')

# Parse SRX3DH bench timings
SRX3DH_ENC=$(echo "$SRX3DH_BENCH_OUTPUT" | grep -A4 "sealed_ringxkem_x3dh/session_establish_encrypt" | grep "time:" | head -1 | sed 's/.*\[\([0-9.]*\) µs.*/\1/')
SRX3DH_DEC=$(echo "$SRX3DH_BENCH_OUTPUT" | grep -A4 "sealed_ringxkem_x3dh/session_establish_decrypt" | grep "time:" | head -1 | sed 's/.*\[\([0-9.]*\) µs.*/\1/')
SRX3DH_TOTAL_TIME=$(echo "$SRX3DH_ENC + $SRX3DH_DEC" | bc)

echo ""
echo "============================================================"
echo "    Sealed RingXKEM-X3DH Size and Timing"
echo "============================================================"
echo ""
echo "MESSAGE SIZE"
echo "------------------------------------------------------------"
printf "%-30s %10s\n" "Ephemeral (x25519)" "${SRX3DH_EC} bytes"
printf "%-30s %10s\n" "KEM ct1" "${SRX3DH_CT1} bytes"
printf "%-30s %10s\n" "KEM ct2" "${SRX3DH_CT2} bytes"
printf "%-30s %10s\n" "Inner total" "${SRX3DH_INNER} bytes"
printf "%-30s %10s\n" "MAC" "${SRX3DH_MAC} bytes"
echo "------------------------------------------------------------"
printf "%-30s %10s\n" "TOTAL" "${SRX3DH_TOTAL} bytes"
echo ""

echo "TIMING (Session Establishment)"
echo "------------------------------------------------------------"
printf "%-20s %12s\n" "Encrypt" "${SRX3DH_ENC} µs"
printf "%-20s %12s\n" "Decrypt" "${SRX3DH_DEC} µs"
echo "------------------------------------------------------------"
printf "%-20s %12s\n" "Round-trip" "${SRX3DH_TOTAL_TIME} µs"
echo ""

# ------------------------------------------------------------
# Hybrid Comparison: XHMQV vs X3DH
# ------------------------------------------------------------

echo "============================================================"
echo "    RingXKEM Hybrid: XHMQV vs X3DH"
echo "============================================================"
echo ""
echo "MESSAGE SIZE"
echo "------------------------------------------------------------"
printf "%-24s %12s %12s\n" "Component" "XHMQV" "X3DH"
echo "------------------------------------------------------------"
printf "%-24s %12s %12s\n" "Ephemeral" "${SR_EC} bytes" "${SRX3DH_EC} bytes"
printf "%-24s %12s %12s\n" "KEM ct1" "${SR_CT1} bytes" "${SRX3DH_CT1} bytes"
printf "%-24s %12s %12s\n" "KEM ct2" "${SR_CT2} bytes" "${SRX3DH_CT2} bytes"
printf "%-24s %12s %12s\n" "Inner total" "${SR_INNER} bytes" "${SRX3DH_INNER} bytes"
printf "%-24s %12s %12s\n" "MAC" "${SR_MAC} bytes" "${SRX3DH_MAC} bytes"
echo "------------------------------------------------------------"
printf "%-24s %12s %12s\n" "TOTAL" "${SR_TOTAL} bytes" "${SRX3DH_TOTAL} bytes"
echo ""

echo "TIMING (Session Establishment)"
echo "------------------------------------------------------------"
printf "%-24s %12s %12s\n" "Encrypt" "${SR_ENC} µs" "${SRX3DH_ENC} µs"
printf "%-24s %12s %12s\n" "Decrypt" "${SR_DEC} µs" "${SRX3DH_DEC} µs"
echo "------------------------------------------------------------"
printf "%-24s %12s %12s\n" "Round-trip" "${SR_TOTAL_TIME} µs" "${SRX3DH_TOTAL_TIME} µs"
echo ""
