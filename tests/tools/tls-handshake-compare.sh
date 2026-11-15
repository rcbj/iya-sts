#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/tls-handshake-compare.sh
#
# ---------------------------------------------------------------------------
# THE NODE LISTENER AND THE RUST LISTENER, HANDSHAKE FOR HANDSHAKE (#444,
# phase 3, rust/DESIGN.md section 10.2).
#
#   tests/tools/tls-handshake-compare.sh <image> <node host:port> \
#       <rust host:port> [out-dir]
#
# Runs the same scripted scan against both listeners with `openssl s_client`
# from <image> (the tests image: OpenSSL 3.5, which speaks the ML-KEM
# groups and ML-DSA; the host's 3.0 does not), on the host's network, and
# diffs what each answered. Every probe prints only what the two SHOULD
# share — the version, suite, group, ALPN, signature scheme, alert, the
# chain's subjects and issuers, the CertificateRequest's CA names and
# signature algorithms, the certificates' extensions with their key
# identifiers and dates left out, the tickets and their lifetime, and
# whether a session resumed — never a key, a serial or a fingerprint, which
# differ between any two starts of the same service.
#
# The probes:
#   * versions: TLS 1.3, 1.2, 1.1, 1.0;
#   * each of the five TLS 1.3 suites alone;
#   * each group alone (the hybrids, pure ML-KEM, the classical curves,
#     finite-field, brainpool), and a client whose first key share is X25519
#     while it also supports a hybrid (whether a HelloRetryRequest moves it);
#   * each signature scheme alone;
#   * ALPN: none, h2, http/1.1, both orders, and a protocol neither offers;
#   * a client certificate presented (RSA and P-256, self-signed);
#   * server names: none, an unknown one;
#   * the session tickets a full handshake gets, and a resumption with one;
#   * with TLS 1.2 on (run both services with STS_TLS_DISABLE_TLS12=false):
#     each of the four BCP 195 suites, a CBC suite, and renegotiation.
#
# Writes <out-dir>/node.txt, rust.txt and diff.txt (default
# tests/vectors/tls-compare, gitignored) and exits 1 when they differ.
# ---------------------------------------------------------------------------
set -euo pipefail

if [ "$#" -lt 3 ]; then
  sed -n '9,12p' "$0" >&2
  exit 2
fi
IMAGE="$1"
NODE="$2"
RUST="$3"
cd "$(dirname "$0")/../.."
OUT="${4:-tests/vectors/tls-compare}"
mkdir -p "$OUT"

label="$(docker image inspect --format \
  '{{index .Config.Labels "com.docker.compose.project"}}' "$IMAGE")"
if [ -n "$label" ]; then
  echo "refusing: $IMAGE carries the compose label '$label'" >&2
  exit 2
fi

# The scan, run inside the image with the target as $1.
read -r -d '' SCAN <<'EOF' || true
set -u
T="$1"
W=/tmp/scan
mkdir -p "$W"
cd "$W"
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=probe-rsa \
  -keyout rsa.key -out rsa.crt -days 2 >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj /CN=probe-ec -keyout ec.key -out ec.crt -days 2 >/dev/null 2>&1

# One connection; stdin held open briefly so the tickets arrive.
connect() {
  (sleep "${HOLD:-0.3}"; printf '') | timeout 15 openssl s_client \
    -connect "$T" -msg "$@" 2>&1 | tr -d '\000'
}

facts() {
  name="$1"; shift
  out="$(connect "$@")"
  cipher="$(printf '%s\n' "$out" | sed -n 's/^\(New\|Reused\), \(.*\), Cipher is \(.*\)$/\2 \3/p' | head -1)"
  if [ -z "$cipher" ] || printf '%s' "$cipher" | grep -q '(NONE)'; then
    alert="$(printf '%s\n' "$out" | grep -o 'alert [a-z_ ]*[a-z]' | head -1)"
    [ -n "$alert" ] || alert="$(printf '%s\n' "$out" | grep -oE 'no protocols available|no ciphers available|wrong version number|unexpected eof|Connection refused|unsupported protocol|no suitable signature algorithm|no shared cipher' | head -1)"
    echo "$name: FAILED ${alert:-closed}"
    return
  fi
  group="$(printf '%s\n' "$out" | sed -n 's/^Negotiated TLS1.3 group: //p; s/^Peer Temp Key: \([^,]*\).*/\1/p' | head -1)"
  alpn="$(printf '%s\n' "$out" | sed -n 's/^ALPN protocol: //p' | head -1)"
  sig="$(printf '%s\n' "$out" | sed -n 's/^Peer signature type: //p' | head -1)"
  hellos="$(printf '%s\n' "$out" | grep -cE "<<< .*, ServerHello$" || true)"
  hrr="no"; [ "$hellos" -gt 1 ] && hrr="HelloRetryRequest"
  reused="$(printf '%s\n' "$out" | grep -oE '^(Reused|New), TLSv[0-9.]+' | head -1)"
  echo "$name: $cipher group=${group:-none} alpn=${alpn:-none} sig=${sig:-none} $hrr $reused"
  if [ -n "${DETAIL:-}" ]; then
    printf '%s\n' "$out" | grep -E '^ *[0-9] s:|^ +i:|^ +a:PKEY' | sed "s/^/$name chain: /"
    # Every certificate's extensions, without the key identifiers, serial
    # numbers, dates and keys that differ between any two starts.
    (sleep 0.3) | timeout 15 openssl s_client -connect "$T" -showcerts \
      2>/dev/null | awk '/BEGIN CERT/{n++} n{print > ("c" n ".pem")} /END CERT/{}'
    for c in c*.pem; do
      openssl x509 -in "$c" -noout -text 2>/dev/null \
        | sed -n '/X509v3 extensions/,/Signature Algorithm/p' \
        | grep -vE '^ +([0-9A-F]{2}:)+[0-9A-F]{2}$|Signature Algorithm' \
        | sed "s/^/$name $c ext: /"
    done
    rm -f c*.pem
    printf '%s\n' "$out" | sed -n '/^Acceptable client certificate CA names/,/^Requested Sig/p' | sed "s/^/$name certreq: /"
    printf '%s\n' "$out" | grep -E '^Shared Requested Signature|^Client Certificate Types' | sed "s/^/$name certreq: /"
    printf '%s\n' "$out" | grep -E 'TLS session ticket lifetime hint|Max Early Data|Extended master secret|Secure Renegotiation' | sort -u | sed "s/^/$name session: /"
    tickets="$(printf '%s\n' "$out" | grep -c 'NewSessionTicket' || true)"
    echo "$name session: NewSessionTicket messages $tickets"
    printf '%s\n' "$out" | grep -oE '<<< TLS 1.3, Handshake \[length [0-9a-f]+\], [A-Za-z]+' | sed 's/\[length [0-9a-f]*\]//' | sed "s/^/$name flight: /"
  fi
}

DETAIL=1 facts default -servername localhost
facts tls1.3 -tls1_3
facts tls1.2 -tls1_2
facts tls1.1 -tls1_1 -cipher 'DEFAULT@SECLEVEL=0'
facts tls1.0 -tls1 -cipher 'DEFAULT@SECLEVEL=0'
for s in TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 \
         TLS_AES_128_GCM_SHA256 TLS_AES_128_CCM_SHA256 TLS_AES_128_CCM_8_SHA256; do
  facts "suite $s" -tls1_3 -ciphersuites "$s"
done
for g in X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024 MLKEM512 \
         MLKEM768 MLKEM1024 X25519 P-256 X448 P-384 P-521 ffdhe2048 \
         ffdhe3072 brainpoolP256r1tls13; do
  facts "group $g" -groups "$g"
done
facts "keyshare X25519 then hybrid" -groups 'X25519:X25519MLKEM768'
facts "keyshare P-256 then X25519" -groups 'P-256:X25519'
for a in rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 \
         rsa_pkcs1_sha256 rsa_pss_pss_sha256 ecdsa_secp256r1_sha256 \
         ed25519 mldsa65; do
  facts "sigalg $a" -sigalgs "$a"
done
facts "alpn none"
facts "alpn h2" -alpn h2
facts "alpn http/1.1" -alpn http/1.1
facts "alpn h2,http/1.1" -alpn h2,http/1.1
facts "alpn http/1.1,h2" -alpn http/1.1,h2
facts "alpn spdy/3" -alpn spdy/3
facts "client cert rsa" -cert rsa.crt -key rsa.key
facts "client cert ec" -cert ec.crt -key ec.key
facts "sni none" -noservername
facts "sni unknown" -servername unknown.example
HOLD=1 connect -sess_out sess.pem >/dev/null
facts "resume with ticket" -sess_in sess.pem
for s in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 \
         ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-SHA; do
  facts "tls1.2 suite $s" -tls1_2 -cipher "$s"
done
DETAIL=1 facts "tls1.2 detail" -tls1_2
HOLD=1 connect -tls1_2 -sess_out sess12.pem >/dev/null
facts "tls1.2 resume" -tls1_2 -sess_in sess12.pem
reneg="$( (printf 'R\n'; sleep 1) | timeout 10 openssl s_client -connect "$T" -tls1_2 2>&1 | grep -oE 'RENEGOTIATING|no renegotiation|alert [a-z_ ]*' | sort -u | tr '\n' ' ')"
echo "tls1.2 renegotiation: ${reneg:-none}"
EOF

scan() {
  docker run --rm --network host --entrypoint bash "$IMAGE" -c "$SCAN" \
    scan "$1"
}

scan "$NODE" > "$OUT/node.txt"
scan "$RUST" > "$OUT/rust.txt"
if diff -u "$OUT/node.txt" "$OUT/rust.txt" > "$OUT/diff.txt"; then
  echo "identical: $(wc -l < "$OUT/node.txt") lines ($OUT/node.txt)"
  exit 0
fi
cat "$OUT/diff.txt"
exit 1
