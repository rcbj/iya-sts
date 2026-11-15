#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/rust-enroll-e2e.sh
#
# ---------------------------------------------------------------------------
# CERTIFICATE ENROLLMENT OVER THE WIRE, RUST BESIDE NODE, ON ONE STORE
# (#444, phase 6, the `enroll` slice; rust/DESIGN.md section 4.7's method).
#
#   tests/tools/rust-enroll-e2e.sh <tests image> <sts-runtime binary> [out]
#
# The family jobs in tests/protocol/ cannot run against the Rust runtime
# yet: every one makes its people, EAB keys, challenges and host names
# through /admin-api, which is the management-API slice's. So the REAL
# CLIENTS the tests image carries are run here, against each runtime in
# turn, on the same directory:
#
#   1. NODE (the tests image's compiled tree, `node server.js`, development,
#      persistence.mode=ldif) seeds its directory, issues alice one EST
#      certificate, and stops: the LDIF holds a Node-written record.
#   2. rust-enroll-e2e-seed.js writes an EAB key, a SCEP challenge and a
#      host name onto alice, in Node's form.
#   3. For RUST, then NODE, each on its own copy of that directory: curl
#      and openssl for EST (cacerts, csrattrs, simpleenroll, serverkeygen,
#      a refused password, /nonce), sscep for SCEP (GetCACaps, GetCACert,
#      PKCSReq with the challenge, the challenge again), and certbot for
#      ACME (register with the EAB key, certonly for the host name, revoke).
#   4. The store both ways: the records each runtime left on alice are
#      counted in the LDIF it wrote, and NODE is started once more on the
#      directory RUST left and issues alice another certificate there.
#
# Nothing here is a compose stack. The Node service and the clients run in
# containers named for the slice on the host's network; the Rust runtime is
# the host binary. Ports 19771-19779. Writes <out> (default
# tests/vectors/rust-enroll-e2e, gitignored).
# ---------------------------------------------------------------------------
set -euo pipefail

IMAGE="$1"
RUST_BIN="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
cd "$(dirname "$0")/../.."
REPO="$PWD"
OUT="${3:-tests/vectors/rust-enroll-e2e}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
TAG="iya-sts-444-p6-enroll"
NODE_PORT=19773
NODE_PKI=19774
RUST_PORT=19771
RUST_PKI=19772
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
FAILED=0
RUST_PID=""

label="$(docker image inspect --format \
  '{{index .Config.Labels "com.docker.compose.project"}}' "$IMAGE")"
if [ -n "$label" ]; then
  echo "refusing: $IMAGE carries the compose label '$label'" >&2
  exit 2
fi

say() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }

cleanup() {
  docker rm -f "$TAG-node" "$TAG-clients" >/dev/null 2>&1 || true
  if [ -n "$RUST_PID" ]; then
    kill "$RUST_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

wait_up() {
  local port="$1"
  for _ in $(seq 1 120); do
    if curl -s -o /dev/null -w '%{http_code}' \
         "http://localhost:$port/healthcheck" 2>/dev/null | grep -q 200; then
      return 0
    fi
    sleep 2
  done
  return 1
}

node_start() {
  local data="$1"
  docker rm -f "$TAG-node" >/dev/null 2>&1 || true
  nice -n 19 docker run -d --name "$TAG-node" --network host \
    -u "$(id -u):$(id -g)" -v "$data:/data" \
    -e STS_PORT=$NODE_PORT -e PKI_HTTP_PORT=$NODE_PKI -e STS_HTTPS=false \
    -e STS_PERSISTENCE_MODE=ldif -e STS_PERSISTENCE_DATA_DIR=/data \
    -e STS_WORKERS_REQUEST_COUNT=0 -e STS_DEBUGGER_ENABLED=off \
    "$IMAGE" node server.js >/dev/null
  wait_up $NODE_PORT
}

node_stop() {
  docker logs "$TAG-node" > "$OUT/node-$1.log" 2>&1 || true
  docker stop -t 30 "$TAG-node" >/dev/null
  docker rm "$TAG-node" >/dev/null
}

rust_start() {
  local data="$1"
  ( cd "$OUT" && STS_PORT=$RUST_PORT PKI_HTTP_PORT=$RUST_PKI \
      STS_HTTPS=false STS_PERSISTENCE_MODE=ldif \
      STS_PERSISTENCE_DATA_DIR="$data" STS_LOG_LEVEL=info \
      exec nice -n 19 "$RUST_BIN" > "$OUT/rust.log" 2>&1 ) &
  RUST_PID=$!
  wait_up $RUST_PORT
}

rust_stop() {
  kill -TERM "$RUST_PID"
  wait "$RUST_PID" 2>/dev/null || true
  RUST_PID=""
}

# How many values of an attribute an entry holds in an LDIF.
count_on() {
  node -e '
    const t = require("fs").readFileSync(process.argv[1], "utf8")
      .replace(/\n /g, "");
    const b = t.split("\n\n").find(function (one) {
      return /^dn: uid=alice,/im.test(one);
    }) || "";
    console.log(b.split("\n").filter(function (l) {
      return l.toLowerCase().startsWith(process.argv[2] + ":");
    }).length);' "$1" "$2"
}

# One EST simpleenroll for alice, as curl sends it; prints the status.
est_enroll() {
  local port="$1" work="$2"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$work/est.key" -subj /CN=alice -outform DER \
    -out "$work/est.csr" 2>/dev/null
  base64 -w0 "$work/est.csr" | curl -s -o "$work/est.p7" \
    -w '%{http_code}' -u alice:x -H 'Content-Type: application/pkcs10' \
    --data-binary @- "http://localhost:$port/.well-known/est/simpleenroll"
}

# The clients, in the tests image, against one runtime.
CLIENTS='
set -u
BASE="$1"; CRED=/work/credentials.json
cd /work
ok() { echo "  PASS  $*"; }
no() { echo "  FAIL  $*"; }
check() { if eval "$1"; then ok "$2"; else no "$2"; fi; }
KID=$(node -p "require(\"$CRED\").kid")
HMAC=$(node -p "require(\"$CRED\").hmacKey")
CHAL=$(node -p "require(\"$CRED\").challenge")
HOST=$(node -p "require(\"$CRED\").host")

echo "-- EST (curl, openssl)"
code=$(curl -s -o cacerts.b64 -w "%{http_code}" "$BASE/.well-known/est/cacerts")
check "[ $code = 200 ] && base64 -d cacerts.b64 | openssl pkcs7 -inform DER -print_certs >/dev/null 2>&1" \
  "cacerts answers a certs-only PKCS#7 openssl reads"
code=$(curl -s -o csrattrs.b64 -w "%{http_code}" "$BASE/.well-known/est/csrattrs")
check "[ $code = 200 ] && base64 -d csrattrs.b64 | openssl asn1parse -inform DER >/dev/null 2>&1" \
  "csrattrs answers a DER sequence"
openssl req -new -newkey rsa:2048 -nodes -keyout est.key -subj /CN=alice \
  -outform DER -out est.csr 2>/dev/null
code=$(base64 -w0 est.csr | curl -s -o est.b64 -w "%{http_code}" -u alice:x \
  -H "Content-Type: application/pkcs10" --data-binary @- \
  "$BASE/.well-known/est/simpleenroll")
check "[ $code = 200 ] && base64 -d est.b64 | openssl pkcs7 -inform DER -print_certs 2>/dev/null | grep -q \"subject=.*CN *= *alice\"" \
  "simpleenroll issues alice a certificate"
code=$(base64 -w0 est.csr | curl -s -o /dev/null -w "%{http_code}" -u alice:invalid \
  -H "Content-Type: application/pkcs10" --data-binary @- \
  "$BASE/.well-known/est/simpleenroll")
check "[ $code = 401 ]" "simpleenroll with the password invalid is 401"
code=$(base64 -w0 est.csr | curl -s -o skg.txt -D skg.h -w "%{http_code}" -u alice:x \
  -H "Content-Type: application/pkcs10" --data-binary @- \
  "$BASE/.well-known/est/serverkeygen")
check "[ $code = 200 ] && grep -qi \"multipart/mixed; boundary=\" skg.h && grep -q application/pkcs8 skg.txt" \
  "serverkeygen answers the key and the certificate as multipart/mixed"
code=$(curl -s -o nonce.json -w "%{http_code}" -u alice:x "$BASE/.well-known/est/nonce")
check "[ $code = 200 ] && node -e \"process.exit(JSON.parse(require(\\\"fs\\\").readFileSync(\\\"nonce.json\\\")).nonce ? 0 : 1)\"" \
  "/nonce answers a freshness nonce"

echo "-- SCEP (sscep)"
caps=$(sscep getcaps -u "$BASE/enroll/scep" 2>&1)
check "echo \"$caps\" | grep -q POSTPKIOperation" "sscep getcaps reads the capabilities"
rm -f ca.crt*
sscep getca -u "$BASE/enroll/scep" -c ca.crt > getca.out 2>&1
check "[ -s ca.crt-0 ] && [ -s ca.crt-1 ]" "sscep getca reads the RA and the SCEP Issuing CA"
cat > req.cnf <<EOF
[req]
prompt = no
distinguished_name = dn
attributes = attrs
[dn]
CN = alice
[attrs]
challengePassword = $CHAL
EOF
openssl req -new -newkey rsa:2048 -nodes -keyout scep.key -config req.cnf \
  -out scep.csr 2>/dev/null
sscep enroll -u "$BASE/enroll/scep" -c ca.crt-0 -e ca.crt-0 -k scep.key \
  -r scep.csr -l scep.pem -S sha256 -E aes > enroll.out 2>&1
check "[ -s scep.pem ] && openssl x509 -in scep.pem -noout -subject | grep -q \"CN *= *alice\"" \
  "sscep enroll with the challenge is issued alice a certificate"
openssl req -new -newkey rsa:2048 -nodes -keyout scep2.key -config req.cnf \
  -out scep2.csr 2>/dev/null
sscep enroll -u "$BASE/enroll/scep" -c ca.crt-0 -e ca.crt-0 -k scep2.key \
  -r scep2.csr -l scep2.pem -S sha256 -E aes > enroll2.out 2>&1
check "[ ! -s scep2.pem ] && grep -qi \"fail\" enroll2.out" \
  "the spent challenge, in a new transaction, is a FAILURE"

echo "-- ACME (certbot)"
CB="--server $BASE/enroll/acme/directory --non-interactive --config-dir cb/config --work-dir cb/work --logs-dir cb/logs"
certbot register $CB --agree-tos -m alice@example.com --eab-kid "$KID" \
  --eab-hmac-key="$HMAC" > register.out 2>&1
check "grep -qi \"account registered\" register.out" "certbot registers with the EAB key"
certbot certonly $CB --standalone --http-01-port 19779 --cert-name e2e \
  -d "$HOST" > certonly.out 2>&1
check "[ -s cb/config/live/e2e/fullchain.pem ] && openssl x509 -in cb/config/live/e2e/cert.pem -noout -ext subjectAltName | grep -q \"$HOST\"" \
  "certbot certonly is issued the registered host name"
certbot revoke $CB --cert-path cb/config/live/e2e/cert.pem --no-delete-after-revoke \
  --reason keycompromise > revoke.out 2>&1
check "grep -qi \"revoked\" revoke.out" "certbot revokes it"
'

run_clients() {
  local what="$1" port="$2"
  local work="$OUT/work-$what"
  rm -rf "$work"
  mkdir -p "$work"
  cp "$OUT/credentials.json" "$work/credentials.json"
  docker rm -f "$TAG-clients" >/dev/null 2>&1 || true
  nice -n 19 docker run --rm --name "$TAG-clients" --network host \
    -u "$(id -u):$(id -g)" -e HOME=/work -v "$work:/work" "$IMAGE" \
    bash -c "$CLIENTS" clients "http://localhost:$port" \
    | tee "$OUT/clients-$what.txt" | tee -a "$SUMMARY"
}

say "== 1. Node writes the store =="
rm -rf "$OUT/data-0" "$OUT/data-rust" "$OUT/data-node"
mkdir -p "$OUT/data-0" "$OUT/scratch"
node_start "$OUT/data-0"
code="$(est_enroll $NODE_PORT "$OUT/scratch")"
say "  Node's EST simpleenroll for alice: $code"
node_stop seed
say "  records on alice: $(count_on "$OUT/data-0/realm-default.ldif" \
  stsenrolledcertificate)"

say "== 2. the credentials, in Node's form =="
node tests/tools/rust-enroll-e2e-seed.js "$OUT/data-0/realm-default.ldif" \
  alice www.alice.test "$OUT/credentials.json"
cp -r "$OUT/data-0" "$OUT/data-rust"
cp -r "$OUT/data-0" "$OUT/data-node"

say "== 3a. the clients against RUST =="
rust_start "$OUT/data-rust"
run_clients rust $RUST_PORT
rust_stop
say "== 3b. the clients against NODE =="
node_start "$OUT/data-node"
run_clients node $NODE_PORT
node_stop clients

say "== 4. the store both ways =="
rust_records="$(count_on "$OUT/data-rust/realm-default.ldif" \
  stsenrolledcertificate)"
node_records="$(count_on "$OUT/data-node/realm-default.ldif" \
  stsenrolledcertificate)"
say "  records on alice after Rust: $rust_records; after Node: $node_records"
node_start "$OUT/data-rust"
code="$(est_enroll $NODE_PORT "$OUT/scratch")"
node_stop after-rust
after="$(count_on "$OUT/data-rust/realm-default.ldif" stsenrolledcertificate)"
if [ "$code" = 200 ] && [ "$after" = "$((rust_records + 1))" ]; then
  say "  PASS  Node, on the directory Rust left, keeps Rust's $rust_records" \
      "records and adds its own ($after)"
else
  say "  FAIL  Node on Rust's directory: $code, $after records"
fi

# "  FAIL  " with its spaces: a check's own words may say FAILURE.
if grep -q "  FAIL  " "$SUMMARY"; then
  FAILED=1
fi
say "== done: $(grep -c "  PASS  " "$SUMMARY") passed," \
  "$(grep -c "  FAIL  " "$SUMMARY" || true) failed =="
exit $FAILED
