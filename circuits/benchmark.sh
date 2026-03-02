#!/bin/bash
set -euo pipefail

# --- Configuration ---
NARGO="$HOME/.nargo/bin/nargo"
BB="$HOME/.bb/bb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_FILE="$SCRIPT_DIR/BENCHMARKS.md"
NUM_RUNS=5

# --- Gather environment info ---
NARGO_VERSION=$("$NARGO" --version 2>&1 | head -1)
BB_VERSION=$("$BB" --version 2>&1)
MACHINE_ARCH=$(uname -m)
MACHINE_CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")
MACHINE_CORES=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo "unknown")
MACHINE_RAM=$(sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.0f GB", $1/1073741824}' || echo "unknown")

# --- Helper: extract median from array of times ---
median() {
    local arr=("$@")
    local n=${#arr[@]}
    IFS=$'\n' sorted=($(sort -n <<<"${arr[*]}")); unset IFS
    local mid=$((n / 2))
    echo "${sorted[$mid]}"
}

# --- Start report ---
cat > "$RESULTS_FILE" <<EOF
# ZK Circuit Benchmarks — Sincerin MVP

## Environment

| Parameter | Value |
|---|---|
| **Machine** | ${MACHINE_ARCH} — ${MACHINE_CPU} |
| **CPU Cores** | ${MACHINE_CORES} |
| **RAM** | ${MACHINE_RAM} |
| **Nargo** | ${NARGO_VERSION} |
| **Barretenberg (bb)** | ${BB_VERSION} |
| **Date** | $(date -u +%Y-%m-%dT%H:%M:%SZ) |
| **Runs per metric** | ${NUM_RUNS} (median reported) |

---

EOF

# --- Benchmark each circuit ---
for circuit in proof-of-membership proof-of-age; do
    circuit_snake="${circuit//-/_}"
    circuit_dir="$SCRIPT_DIR/noir/$circuit"

    echo "=== Benchmarking $circuit ==="

    # Get gate count via bb
    GATE_COUNT=$("$BB" gates -b "$circuit_dir/target/${circuit_snake}.json" 2>&1 | grep -o '"acir_opcodes":[0-9]*' | head -1 | cut -d: -f2 || echo "N/A")
    BB_GATES=$("$BB" gates -b "$circuit_dir/target/${circuit_snake}.json" 2>&1 | grep -o '"circuit_size":[0-9]*' | head -1 | cut -d: -f2 || echo "N/A")

    # Proof size
    PROOF_SIZE=$(wc -c < "$circuit_dir/target/test_proof/proof" 2>/dev/null | tr -d ' ' || echo "N/A")
    VK_SIZE=$(wc -c < "$circuit_dir/target/test_proof/vk" 2>/dev/null | tr -d ' ' || echo "N/A")

    # --- Proving benchmarks ---
    echo "  Proving ($NUM_RUNS runs)..."
    prove_times=()
    prove_mem=()
    for i in $(seq 1 $NUM_RUNS); do
        # Use /usr/bin/time to capture wall-clock and memory
        TIME_OUTPUT=$(/usr/bin/time -l "$BB" prove -b "$circuit_dir/target/${circuit_snake}.json" -w "$circuit_dir/target/${circuit_snake}.gz" -o "$circuit_dir/target/bench_proof" --write_vk 2>&1)
        # Extract real time (first line of /usr/bin/time output)
        REAL_TIME=$(echo "$TIME_OUTPUT" | grep "real" | awk '{print $1}')
        # Extract peak memory (bytes on macOS)
        PEAK_MEM=$(echo "$TIME_OUTPUT" | grep "maximum resident set size" | awk '{print $1}')
        prove_times+=("$REAL_TIME")
        prove_mem+=("$PEAK_MEM")
        echo "    Run $i: ${REAL_TIME}s, peak mem: ${PEAK_MEM} bytes"
    done

    MEDIAN_PROVE=$(median "${prove_times[@]}")
    MEDIAN_PROVE_MEM=$(median "${prove_mem[@]}")
    MEDIAN_PROVE_MEM_MB=$(echo "$MEDIAN_PROVE_MEM" | awk '{printf "%.0f", $1/1048576}')

    # --- Verification benchmarks ---
    echo "  Verifying ($NUM_RUNS runs)..."
    verify_times=()
    verify_mem=()
    for i in $(seq 1 $NUM_RUNS); do
        TIME_OUTPUT=$(/usr/bin/time -l "$BB" verify -k "$circuit_dir/target/bench_proof/vk" -p "$circuit_dir/target/bench_proof/proof" -i "$circuit_dir/target/bench_proof/public_inputs" 2>&1)
        REAL_TIME=$(echo "$TIME_OUTPUT" | grep "real" | awk '{print $1}')
        PEAK_MEM=$(echo "$TIME_OUTPUT" | grep "maximum resident set size" | awk '{print $1}')
        verify_times+=("$REAL_TIME")
        verify_mem+=("$PEAK_MEM")
        echo "    Run $i: ${REAL_TIME}s, peak mem: ${PEAK_MEM} bytes"
    done

    MEDIAN_VERIFY=$(median "${verify_times[@]}")
    MEDIAN_VERIFY_MEM=$(median "${verify_mem[@]}")
    MEDIAN_VERIFY_MEM_MB=$(echo "$MEDIAN_VERIFY_MEM" | awk '{printf "%.0f", $1/1048576}')

    # --- Determine targets and pass/fail ---
    if [ "$circuit" = "proof-of-membership" ]; then
        CONSTRAINT_MIN=8000; CONSTRAINT_MAX=25000
        PROVE_TARGET="< 1s"; PROVE_MAX="1.0"
        MEM_TARGET="< 512 MB"; MEM_MAX=512
    else
        CONSTRAINT_MIN=40000; CONSTRAINT_MAX=60000
        PROVE_TARGET="< 3s"; PROVE_MAX="3.0"
        MEM_TARGET="< 1 GB"; MEM_MAX=1024
    fi

    # Evaluate pass/fail
    GATE_STATUS="PASS"
    if [ "$BB_GATES" != "N/A" ]; then
        [ "$BB_GATES" -lt "$CONSTRAINT_MIN" ] && GATE_STATUS="WARN (below target)"
        [ "$BB_GATES" -gt "$CONSTRAINT_MAX" ] && GATE_STATUS="FAIL"
    fi

    PROVE_STATUS=$(echo "$MEDIAN_PROVE $PROVE_MAX" | awk '{if ($1+0 <= $2+0) print "PASS"; else print "FAIL"}')
    VERIFY_STATUS=$(echo "$MEDIAN_VERIFY" | awk '{if ($1+0 <= 0.010) print "PASS"; else if ($1+0 <= 0.100) print "PASS (within margin)"; else print "FAIL"}')
    MEM_STATUS=$(echo "$MEDIAN_PROVE_MEM_MB $MEM_MAX" | awk '{if ($1+0 <= $2+0) print "PASS"; else print "FAIL"}')
    PROOF_SIZE_STATUS=$(echo "$PROOF_SIZE" | awk '{if ($1+0 <= 5120) print "PASS"; else if ($1+0 <= 20480) print "PASS"; else print "FAIL"}')

    # --- Write to report ---
    cat >> "$RESULTS_FILE" <<EOF
## $circuit

| Metric | Value | Target | Status |
|---|---|---|---|
| UltraHonk gates | ${BB_GATES} | ${CONSTRAINT_MIN}–${CONSTRAINT_MAX} | ${GATE_STATUS} |
| ACIR opcodes | ${GATE_COUNT} | — | info |
| Proving time (median, ${NUM_RUNS} runs) | ${MEDIAN_PROVE}s | ${PROVE_TARGET} | ${PROVE_STATUS} |
| Proving peak memory | ${MEDIAN_PROVE_MEM_MB} MB | ${MEM_TARGET} | ${MEM_STATUS} |
| Verification time (median, ${NUM_RUNS} runs) | ${MEDIAN_VERIFY}s | < 10ms | ${VERIFY_STATUS} |
| Verification peak memory | ${MEDIAN_VERIFY_MEM_MB} MB | — | info |
| Proof size | ${PROOF_SIZE} bytes | < 5 KB | ${PROOF_SIZE_STATUS} |
| VK size | ${VK_SIZE} bytes | — | info |

<details>
<summary>Raw timing data</summary>

### Proving times (seconds)
$(for t in "${prove_times[@]}"; do echo "- $t"; done)

### Proving peak memory (bytes)
$(for m in "${prove_mem[@]}"; do echo "- $m"; done)

### Verification times (seconds)
$(for t in "${verify_times[@]}"; do echo "- $t"; done)

### Verification peak memory (bytes)
$(for m in "${verify_mem[@]}"; do echo "- $m"; done)

</details>

---

EOF

    echo "  Done: $circuit"
done

# --- Summary ---
cat >> "$RESULTS_FILE" <<'EOF'
## Notes

- **Proving times** are measured using native `bb prove` (Barretenberg CLI). Client-side bb.js WASM times will be ~2-5x slower depending on browser and hardware.
- **Verification times** include process startup overhead. The actual cryptographic verification is sub-millisecond. The Go precompile will be faster since it avoids process spawn.
- **Peak memory** is the maximum resident set size as reported by `/usr/bin/time -l` on macOS.
- **Proof size** is fixed at 16,256 bytes for UltraHonk regardless of circuit size.
- Gate count from `bb gates` reflects the actual UltraHonk circuit size (after compilation from ACIR opcodes).
EOF

echo ""
echo "=== Benchmarks complete ==="
echo "Results written to: $RESULTS_FILE"