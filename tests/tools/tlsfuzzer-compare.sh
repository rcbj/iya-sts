#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/tlsfuzzer-compare.sh
#
# ---------------------------------------------------------------------------
# tlsfuzzer's PLAN AGAINST THE NODE LISTENER AND THE RUST ONE (#444, phase 3).
#
#   tests/tools/tlsfuzzer-compare.sh <tests image> <node host:port> \
#       <rust host:port> [out-dir] [script-substring...]
#
# `tests/protocol/sts_tlsfuzzer.js` needs a compose stack and the management
# API to issue its client certificates, neither of which the Rust runtime
# has yet. This runs the SAME plan (`tests/protocol/tlsfuzzer_kit.js`, by
# hand, the tests image's tlsfuzzer and OpenSSL 3.5) against two listeners
# with the same client certificates — every one self-signed, made here, so
# neither listener can verify one and both are asked the same question —
# and diffs the per-script verdicts, the timing taken out. Run both
# services the way the job runs them: TLS 1.2 on
# (STS_TLS_DISABLE_TLS12=false).
#
# Writes <out-dir>/node.txt, rust.txt and diff.txt (default
# tests/vectors/tlsfuzzer-compare, gitignored); exits 1 when they differ.
# ---------------------------------------------------------------------------
set -euo pipefail

if [ "$#" -lt 3 ]; then
  sed -n '9,11p' "$0" >&2
  exit 2
fi
IMAGE="$1"
NODE="$2"
RUST="$3"
shift 3
cd "$(dirname "$0")/../.."
OUT="${1:-tests/vectors/tlsfuzzer-compare}"
[ "$#" -gt 0 ] && shift
mkdir -p "$OUT"

label="$(docker image inspect --format \
  '{{index .Config.Labels "com.docker.compose.project"}}' "$IMAGE")"
if [ -n "$label" ]; then
  echo "refusing: $IMAGE carries the compose label '$label'" >&2
  exit 2
fi

read -r -d '' RUN <<'EOF' || true
set -u
target="$1"; shift
C=/tmp/certs
mkdir -p "$C"
one() {
  openssl req -x509 -nodes -days 2 -subj "/CN=tlsfuzzer-$1" \
    -keyout "$C/$1.key" -out "$C/$1.crt" "${@:2}" >/dev/null 2>&1
}
one rsa -newkey rsa:2048
one ec -newkey ec -pkeyopt ec_paramgen_curve:P-256
one ed25519 -newkey ed25519
one rsapss -newkey rsa-pss -pkeyopt rsa_keygen_bits:2048
one mldsa -newkey ml-dsa-65
one nonNist -newkey ec -pkeyopt ec_paramgen_curve:brainpoolP256r1
openssl ec -in "$C/nonNist.key" -out "$C/nonNist.key" >/dev/null 2>&1
STS_TLSFUZZER_DIR=/opt/tlsfuzzer STS_TLSFUZZER_CERTS="$C" \
STS_TLSFUZZER_CONCURRENCY="${CONCURRENCY:-4}" \
  node tests/protocol/tlsfuzzer_kit.js main "${target%:*}" "${target##*:}" \
  "$@" 2>/dev/null
EOF

run() {
  docker run --rm --network host --entrypoint bash "$IMAGE" -c "$RUN" \
    fuzz "$@" | sed -E 's/ \([0-9]+ s\)$//' | sort
}

run "$NODE" "$@" > "$OUT/node.txt" || true
run "$RUST" "$@" > "$OUT/rust.txt" || true
if diff -u "$OUT/node.txt" "$OUT/rust.txt" > "$OUT/diff.txt"; then
  echo "identical: $(grep -c '^\[' "$OUT/node.txt") script(s); $(grep -c '^\[FAILED' "$OUT/node.txt") failed on both"
  exit 0
fi
cat "$OUT/diff.txt"
exit 1
