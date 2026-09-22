#!/usr/bin/env bash
#
# File: build-native.sh
#
# THE ONE NATIVE MODULE THIS SERVICE HAS, COMPILED INSIDE AN IMAGE BUILD ONLY
# (#40 phase four, 2026-09-21).
#
# `spiffe/native/peercred.c` reads a Unix socket peer's credentials
# (SO_PEERCRED) and holds a pidfd for it — what SPIFFE workload attestation
# needs and Node cannot do. rcbj's rules: nothing compiled is written to the
# host, so this refuses outside an image build, exactly as build-typescript.sh
# does; and no node-gyp or Python — it is one C file against Node's own
# `node_api.h`, compiled with the system compiler.
#
# A build with no C compiler, or no Node headers, SKIPS rather than failing:
# the service still starts, and the Workload API socket then reports workload
# attestation as unavailable (and, in product mode, is not served at all —
# `spiffe/spiffe_peer.ts`).
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f /.dockerenv ] && [ -z "${STS_IN_IMAGE_BUILD:-}" ]; then
  echo "build-native.sh: this runs inside an image build only (no compiled" \
       "files on the host)." >&2
  exit 1
fi

SRC=spiffe/native/peercred.c
OUT=spiffe/native/peercred.node
CC="${CC:-cc}"
NODE_BIN="$(command -v node)"
INCLUDE="$(dirname "$(dirname "$NODE_BIN")")/include/node"

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "build-native.sh: no C compiler ($CC); $OUT is NOT built, and SPIFFE" \
       "workload attestation will report itself unavailable." >&2
  exit 0
fi
if [ ! -f "$INCLUDE/node_api.h" ]; then
  echo "build-native.sh: no Node headers at $INCLUDE; $OUT is NOT built." >&2
  exit 0
fi

echo "build-native.sh: compiling $SRC against $INCLUDE"
"$CC" -O2 -Wall -Wextra -Werror -fPIC -shared -std=c11 \
      -DNODE_GYP_MODULE_NAME=peercred -I"$INCLUDE" \
      -o "$OUT" "$SRC"
node -e "const m = require('./$OUT'); \
  if (typeof m.peerCred !== 'function') { process.exit(1); } \
  console.log('build-native.sh: $OUT loads:', Object.keys(m).join(', '));"
