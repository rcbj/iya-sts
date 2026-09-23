"use strict";
//
// File: sts_spiffe_broker.js
//
// ---------------------------------------------------------------------------
// THE SPIFFE BROKER API, OVER THE NETWORK, IN A DEVELOPMENT REALM AND A
// PRODUCT REALM (#170, 2026-09-23).
//
// `tests/spiffe_broker.js` holds the endpoint in process; this is the same
// surface as a DEPLOYED service is reached — a gRPC client of this job's own
// (`@grpc/grpc-js` from here, never the service's wrappers —
// `spiffe/CLAUDE.md`'s rule), over mutual TLS, to a realm's Broker endpoint
// at the host the service is reached at.
//
// WHAT IT MAKES, ALL AT RUN TIME (no key material is committed):
//
//   * two realms of its own, one per mode, each with SPIFFE on and its
//     Broker endpoint on a port of its own (STS_SPIFFE_BROKER_PORT_DEV,
//     STS_SPIFFE_BROKER_PORT_PROD; 8193 and 8194), left standing with
//     SPIFFE off afterwards;
//   * a CA of this job's own for a trust domain of its own, pushed into each
//     realm as a FEDERATED bundle (`/admin-api/spiffe/federation-set`) —
//     which is how a broker from another trust domain is verified — and
//     X509-SVIDs under it for a broker, a pod-only broker and a stranger;
//   * the brokers, through `/admin-api/spiffe/brokers/set` (rule 7), and
//     registration entries through `/admin-api/spiffe/entries/create`;
//   * a fake kubelet: an https listener on OUTBOUND_TEST_HOST (or
//     GNAP_PUSH_HOST, the name the service reaches this runner by) answering
//     the pod list. Development reaches it with
//     `spiffe.k8sSkipKubeletVerification`; product only through
//     `spiffe.k8sKubeletCaFile`, the CA this job made, published through the
//     shared directory — and that half is SKIPPED, saying so, where there is
//     none.
//
// WHAT IS ASSERTED, in each realm:
//
//   * REFUSED WITHOUT A BROKER SVID: no `broker.spiffe.io` header is
//     INVALID_ARGUMENT, no client certificate UNAUTHENTICATED, an SVID naming
//     no broker PERMISSION_DENIED; and `/admin-api/spiffe/brokers/set`
//     refuses a broker that is not a SPIFFE ID or names no reference type;
//   * THE REFERENCE: none is INVALID_ARGUMENT with a google.rpc.ErrorInfo
//     (WORKLOAD_REFERENCE_INVALID, spiffe.io) in `grpc-status-details-bin`;
//     a type the broker is not allowed is PERMISSION_DENIED; a pid that does
//     not exist is NOT_FOUND (WORKLOAD_NOT_FOUND);
//   * ANSWERED WITH ONE: FetchJWTSVID and SubscribeToX509SVID for a PROCESS
//     reference — pid 1 in the service's container, attested by the unix
//     attestor as the uid the service runs as (STS_SPIFFE_BROKER_PID_UID,
//     0 by default, since the image runs as root) — and FetchJWTSVID for a
//     POD reference by UID, attested by the k8s attestor over the fake
//     kubelet; a pod no entry selects is PERMISSION_DENIED
//     (WORKLOAD_NOT_ENTITLED);
//   * `GET /admin-api/spiffe/brokers` lists what was set, and a broker
//     removed is refused on its next call.
//
// WHERE THE ENDPOINT CANNOT BE REACHED — a load balancer that forwards only
// the published ports, an AWS target — the gRPC half is SKIPPED with the
// reason, and only when the service ITSELF says the listener is bound; a
// listener the service reports as not bound is a failure.
//
// OWNED HERE (local: true): no counterpart exists in the parent project.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const net = require("net");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");
const testCa = require("./outbound_test_ca.js");
const { declineToRun } = require("./expectation.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_spiffe_broker",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "vendored", "x509.js"));
const keys = require(path.join(REPO, "common", "vendored",
                               "key_material.js"));

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const RUN = "b" + Date.now().toString(36) +
            nodeCrypto.randomBytes(2).toString("hex");
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "localhost";
const BROKER_TD = "broker-" + RUN + ".test";
const POD = "0a0b0c0d-1e1f-4a2b-8c3d-4e5f60718293";
const EMPTY_POD = "1a1b1c1d-2e2f-4a3b-9c4d-5e6f70819203";
const PID_URL = "type.googleapis.com/spiffe.broker.WorkloadPIDReference";
const K8S_URL =
  "type.googleapis.com/spiffe.broker.KubernetesObjectReference";
const PROTO_DIR = path.join(__dirname, "..", "..", "spiffe", "protos");

let checks = 0;
let skipped = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function call(method, url, body) {
  log.debug("Entering call().");
  const r = await fetch(url, { method: method,
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into any assertion message.
    json = null;
  }
  log.debug("Leaving call().");
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200, what + ": " + r.status + " " +
            r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r;
}

function realmBase(id) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + id;
}

// ----- protobuf, this file's own ------------------------------------------

function varint(n) {
  log.debug("Entering varint().");
  const out = [];
  let v = BigInt(n);
  do {
    let b = Number(v & BigInt(0x7f));
    v >>= BigInt(7);
    if (v > BigInt(0)) b |= 0x80;
    out.push(b);
  } while (v > BigInt(0));
  log.debug("Leaving varint().");
  return Buffer.from(out);
}

function field(no, bytes) {
  log.debug("Entering field().");
  const body = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, "utf8");
  log.debug("Leaving field().");
  return Buffer.concat([varint((no << 3) | 2), varint(body.length), body]);
}

function decode(buf) {
  log.debug("Entering decode().");
  const out = [];
  let at = 0;
  const read = function () {
    let v = 0;
    let shift = 0;
    for (;;) {
      const b = buf[at++];
      v += (b & 0x7f) * Math.pow(2, shift);
      shift += 7;
      if (!(b & 0x80)) return v;
    }
  };
  while (at < buf.length) {
    const key = read();
    if ((key & 7) === 0) {
      out.push({ no: key >> 3, int: read() });
    } else {
      const len = read();
      out.push({ no: key >> 3, bytes: buf.subarray(at, at + len) });
      at += len;
    }
  }
  log.debug("Leaving decode().");
  return out;
}

// The google.rpc.ErrorInfo in a refusal's grpc-status-details-bin, or null.
function errorInfo(err) {
  log.debug("Entering errorInfo().");
  const raw = err && err.metadata ? err.metadata.get("grpc-status-details-bin")
                                  : [];
  if (!raw || !raw.length) {
    log.debug("Leaving errorInfo(). None.");
    return null;
  }
  const any = decode(Buffer.from(raw[0])).filter(function (f) {
    return f.no === 3;
  })[0];
  const value = any ? decode(any.bytes).filter(function (f) {
    return f.no === 2;
  })[0] : null;
  const info = value ? decode(value.bytes) : [];
  const text = function (no) {
    const f = info.filter(function (x) { return x.no === no; })[0];
    return f ? Buffer.from(f.bytes).toString("utf8") : "";
  };
  log.debug("Leaving errorInfo().");
  return { reason: text(1), domain: text(2) };
}

function pidRef(pid) {
  log.debug("Entering pidRef().");
  log.debug("Leaving pidRef().");
  return { reference: { type_url: PID_URL,
                        value: Buffer.concat([varint(1 << 3), varint(pid)]) } };
}

function podRef(uid) {
  log.debug("Entering podRef().");
  log.debug("Leaving podRef().");
  return { reference: { type_url: K8S_URL, value: Buffer.concat([
    field(1, Buffer.concat([field(1, "pods"), field(2, "core")])),
    field(3, uid)]) } };
}

// ----- certificates, this job's own ----------------------------------------

// An X509-SVID for `id` under `ca`: `{ key, cert }`.
async function svid(ca, id) {
  log.debug("Entering svid(). " + id);
  const pair = await keys.generateKeyPair("ec-p256");
  const leaf = await x509.issueCertificate({
    subject: [{ name: "O", value: "sts test broker" }],
    subjectPublicKey: pair.publicPem, signatureAlg: "sha256-rsa",
    profile: "tls-client",
    issuer: { certificatePem: ca.certPem, privateKeyPem: ca.privatePem,
              keyAlg: "rsa-2048" },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ["digitalSignature"] },
      extKeyUsage: { present: true, critical: false,
                     usages: ["clientAuth", "serverAuth"] },
      subjectAltName: { present: true, critical: false,
                        names: [{ kind: "uri", value: id }] }
    }
  });
  log.debug("Leaving svid().");
  return { key: pair.privatePem, cert: leaf.pem };
}

// A SPIFFE bundle document holding `ca` as its x509-svid authority.
function bundleOf(ca) {
  log.debug("Entering bundleOf().");
  const jwk = nodeCrypto.createPublicKey(ca.certPem).export({ format: "jwk" });
  const der = new nodeCrypto.X509Certificate(ca.certPem).raw;
  log.debug("Leaving bundleOf().");
  return { keys: [Object.assign(jwk, { use: "x509-svid",
                                       x5c: [der.toString("base64")] })],
           spiffe_sequence: 1, spiffe_refresh_hint: 300 };
}

// ----- the fake kubelet -----------------------------------------------------

async function kubelet(ca) {
  log.debug("Entering kubelet().");
  const credential = await testCa.listenerCertificate(ca, HOST);
  const pods = { items: [
    { metadata: { name: "web-0", namespace: "shop", uid: POD },
      spec: { serviceAccountName: "web", nodeName: "node-1" },
      status: { containerStatuses: [] } },
    { metadata: { name: "idle-0", namespace: "shop", uid: EMPTY_POD },
      spec: { serviceAccountName: "idle", nodeName: "node-1" },
      status: { containerStatuses: [] } }] };
  const server = https.createServer({ key: credential.key,
                                      cert: credential.cert },
                                    function (req, res) {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(req.url === "/pods" ? pods : {}));
  });
  await new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", resolve);
  });
  server.unref();
  log.debug("Leaving kubelet().");
  return server;
}

// Whether a TCP connection to host:port opens.
function reachable(host, port) {
  log.debug("Entering reachable().");
  log.debug("Leaving reachable().");
  return new Promise(function (resolve) {
    const socket = net.connect(port, host);
    const done = function (answer) {
      socket.destroy();
      resolve(answer);
    };
    socket.setTimeout(5000, function () { done(false); });
    socket.on("connect", function () { done(true); });
    socket.on("error", function () { done(false); });
  });
}

// ----- one realm ------------------------------------------------------------

async function oneRealm(o) {
  log.debug("Entering oneRealm(). " + o.id);
  log.info("=== the " + o.mode + " realm " + o.id + " ===");
  const product = o.mode === "product";
  const caFile = product ? testCa.publishCa(o.ca) : null;
  const overrides = {
    "global.mode": o.mode, "spiffe.brokerPort": o.port,
    "spiffe.workloadSocketEnabled": false,
    "spiffe.workloadAttestors": "unix,k8s",
    "spiffe.k8sNodeName": HOST,
    "spiffe.k8sKubeletSecurePort": o.kubeletPort,
    "spiffe.k8sUseAnonymousAuthentication": true,
    "spiffe.k8sMaxPollAttempts": 1
  };
  if (product && caFile) {
    overrides["spiffe.k8sKubeletCaFile"] = caFile;
  }
  if (!product) {
    overrides["spiffe.k8sSkipKubeletVerification"] = true;
  }
  await ok(base + "/admin-api/realms/create",
           { id: o.id, domain: o.id + ".example.net",
             name: "SPIFFE broker (" + o.mode + ")", overrides: overrides },
           "created the " + o.mode + " realm");
  await ok(base + "/admin-api/realms/set",
           { id: o.id, key: "spiffe.enabled", value: true },
           "turned SPIFFE on in it");
  const api = realmBase(o.id) + "/admin-api";
  let r = await call("GET", api + "/spiffe");
  const td = r.json && (r.json.trustDomain || "");
  check(o.mode + ": the realm is its own trust domain", function () {
    assert.ok(td, r.text.slice(0, 300));
  });

  // ---- the broker list, through /admin-api (rule 7) -------------------------
  r = await call("POST", api + "/spiffe/brokers/set",
                 { id: "not-a-spiffe-id", referenceTypes: ["pid"] });
  check(o.mode + ": a broker that is not a SPIFFE ID is refused",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
  });
  r = await call("POST", api + "/spiffe/brokers/set",
                 { id: "spiffe://" + BROKER_TD + "/broker",
                   referenceTypes: [] });
  check(o.mode + ": a broker allowed no reference type is refused",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
  });
  await ok(api + "/spiffe/brokers/set",
           { id: "spiffe://" + BROKER_TD + "/broker",
             referenceTypes: ["pid", "k8s"] }, "authorized the broker");
  await ok(api + "/spiffe/brokers/set",
           { id: "spiffe://" + BROKER_TD + "/pod-broker",
             referenceTypes: ["k8s"] }, "authorized the pod-only broker");
  r = await call("GET", api + "/spiffe/brokers");
  const listed = (r.json && r.json.brokers) || [];
  check(o.mode + ": GET /admin-api/spiffe/brokers lists both, with what " +
        "each may reference", function () {
    assert.ok(listed.some(function (b) {
      return b.id === "spiffe://" + BROKER_TD + "/broker" &&
             b.referenceTypes.join(",") === "pid,k8s";
    }) && listed.some(function (b) {
      return b.id === "spiffe://" + BROKER_TD + "/pod-broker";
    }), r.text.slice(0, 600));
  });
  const listening = ((r.json && r.json.listeners) || []).filter(function (b) {
    return b.listening && /:\d+$/.test(b.address) &&
           b.address.split(":").pop() === String(o.port);
  })[0];
  check(o.mode + ": the realm's Broker endpoint is bound, mutual TLS",
        function () {
    assert.ok(listening && listening.tls, r.text.slice(0, 600));
  });

  await ok(api + "/spiffe/federation-set",
           { trustDomain: BROKER_TD, document: bundleOf(o.ca) },
           "federated with the broker's trust domain");
  const pidEntry = await ok(api + "/spiffe/entries/create",
    { spiffeId: "spiffe://" + td + "/sts-test/broker/" + RUN + "/by-pid",
      selectors: "unix:uid:" + o.uid }, "created the process entry");
  await ok(api + "/spiffe/entries/create",
    { spiffeId: "spiffe://" + td + "/sts-test/broker/" + RUN + "/by-pod",
      selectors: "k8s:pod-uid:" + POD }, "created the pod entry");

  // ---- the endpoint ---------------------------------------------------------
  const url = new URL(base);
  const target = url.hostname + ":" + o.port;
  if (!(await reachable(url.hostname, o.port))) {
    declineToRun(log, "the " + o.mode + " realm's Broker endpoint is bound " +
                 "on port " + o.port + " and this runner cannot reach " +
                 target + " (a balancer forwarding only published ports, or " +
                 "a remote target)");
    skipped += 1;
    log.debug("Leaving oneRealm(). Unreachable.");
    return;
  }
  const anchors = await call("GET", realmBase(o.id) + "/spiffe/bundle");
  const roots = ((anchors.json && anchors.json.keys) || [])
    .filter(function (k) { return k.use === "x509-svid"; })
    .map(function (k) {
      return "-----BEGIN CERTIFICATE-----\n" + k.x5c[0] +
             "\n-----END CERTIFICATE-----\n";
    }).join("");
  const serverId = "spiffe://" + td + "/spire/server";
  const definition = protoLoader.loadSync("brokerapi.proto", {
    keepCase: true, longs: String, enums: String, defaults: true,
    oneofs: true, includeDirs: [PROTO_DIR] });
  const Client = grpc.makeGenericClientConstructor(
    definition["spiffe.broker.API"], "API");
  const connect = function (credential) {
    const verify = { checkServerIdentity: function (host, cert) {
      return String(cert.subjectaltname || "").indexOf("URI:" + serverId) >= 0
        ? undefined : new Error("the server is not " + serverId);
    } };
    return new Client(target, credential
      ? grpc.credentials.createSsl(Buffer.from(roots),
          Buffer.from(credential.key), Buffer.from(credential.cert), verify)
      : grpc.credentials.createSsl(Buffer.from(roots), null, null, verify),
      { "grpc.use_local_subchannel_pool": 1 });
  };
  const header = function () {
    const md = new grpc.Metadata();
    md.set("broker.spiffe.io", "true");
    return md;
  };
  const unary = function (client, request, metadata) {
    return new Promise(function (resolve) {
      client.FetchJWTSVID(request, metadata || header(),
                          { deadline: Date.now() + 30000 },
                          function (err, reply) {
        resolve({ err: err, reply: reply });
      });
    });
  };
  const jwt = function (ref) {
    return { reference: ref, audience: ["https://api.test/" + RUN] };
  };
  const codeOf = function (a) {
    return a.err ? a.err.code : 0;
  };
  const broker = connect(o.broker);
  let a = await unary(broker, jwt(pidRef(1)), new grpc.Metadata());
  check(o.mode + ": no broker.spiffe.io header is INVALID_ARGUMENT",
        function () {
    assert.strictEqual(codeOf(a), grpc.status.INVALID_ARGUMENT,
                       String(a.err && a.err.details));
  });
  const anonymous = connect(null);
  a = await unary(anonymous, jwt(pidRef(1)));
  anonymous.close();
  check(o.mode + ": no client certificate is UNAUTHENTICATED", function () {
    assert.strictEqual(codeOf(a), grpc.status.UNAUTHENTICATED,
                       String(a.err && a.err.details));
  });
  const stranger = connect(o.stranger);
  a = await unary(stranger, jwt(pidRef(1)));
  stranger.close();
  check(o.mode + ": an SVID that verifies and names no broker is " +
        "PERMISSION_DENIED", function () {
    assert.strictEqual(codeOf(a), grpc.status.PERMISSION_DENIED,
                       String(a.err && a.err.details));
  });
  a = await unary(broker, { reference: null, audience: ["a"] });
  let info = errorInfo(a.err);
  check(o.mode + ": no reference is INVALID_ARGUMENT, with a " +
        "google.rpc.ErrorInfo WORKLOAD_REFERENCE_INVALID", function () {
    assert.ok(codeOf(a) === grpc.status.INVALID_ARGUMENT && info &&
              info.reason === "WORKLOAD_REFERENCE_INVALID" &&
              info.domain === "spiffe.io",
              String(a.err && a.err.details) + " " + JSON.stringify(info));
  });
  const podOnly = connect(o.podBroker);
  a = await unary(podOnly, jwt(pidRef(1)));
  check(o.mode + ": a reference type the broker is not allowed is " +
        "PERMISSION_DENIED", function () {
    assert.strictEqual(codeOf(a), grpc.status.PERMISSION_DENIED,
                       String(a.err && a.err.details));
  });
  a = await unary(broker, jwt(pidRef(4194301)));
  info = errorInfo(a.err);
  check(o.mode + ": a pid that does not exist is NOT_FOUND, " +
        "WORKLOAD_NOT_FOUND", function () {
    assert.ok(codeOf(a) === grpc.status.NOT_FOUND && info &&
              info.reason === "WORKLOAD_NOT_FOUND",
              String(a.err && a.err.details) + " " + JSON.stringify(info));
  });
  a = await unary(broker, jwt(pidRef(1)));
  const svids = (a.reply && a.reply.svids) || [];
  check(o.mode + ": a PROCESS reference (pid 1, the service) is attested " +
        "and answered with its entry's JWT-SVID", function () {
    assert.ok(!a.err && svids.length === 1 &&
              /\/by-pid$/.test(svids[0].spiffe_id),
              String(a.err && a.err.details) + " " + JSON.stringify(svids));
    const claims = JSON.parse(Buffer.from(svids[0].svid.split(".")[1],
                                          "base64url").toString("utf8"));
    assert.strictEqual(claims.sub, svids[0].spiffe_id);
  });
  const first = await new Promise(function (resolve) {
    const stream = broker.SubscribeToX509SVID({ reference: pidRef(1) },
                                              header());
    stream.on("data", function (message) {
      resolve({ message: message });
      stream.cancel();
    });
    stream.on("error", function (err) {
      if (err.code !== grpc.status.CANCELLED) resolve({ err: err });
    });
  });
  check(o.mode + ": SubscribeToX509SVID answers the entry's X509-SVID",
        function () {
    const got = (first.message && first.message.svids) || [];
    assert.ok(got.length === 1 && got[0].x509_svid.length > 0 &&
              got[0].x509_svid_key.length > 0,
              String(first.err && first.err.details));
    const leaf = new nodeCrypto.X509Certificate(Buffer.from(got[0].x509_svid));
    assert.ok(String(leaf.subjectAltName).indexOf("/by-pid") >= 0,
              leaf.subjectAltName);
  });
  if (product && !caFile) {
    log.info("  [skip] " + testCa.skipReason());
    skipped += 1;
  } else {
    a = await unary(podOnly, jwt(podRef(POD)));
    check(o.mode + ": a POD reference by UID is attested over the kubelet " +
          "and answered", function () {
      assert.ok(!a.err && a.reply.svids.length === 1 &&
                /\/by-pod$/.test(a.reply.svids[0].spiffe_id),
                String(a.err && a.err.details));
    });
    a = await unary(podOnly, jwt(podRef(EMPTY_POD)));
    info = errorInfo(a.err);
    check(o.mode + ": a pod no entry selects is PERMISSION_DENIED, " +
          "WORKLOAD_NOT_ENTITLED", function () {
      assert.ok(codeOf(a) === grpc.status.PERMISSION_DENIED && info &&
                info.reason === "WORKLOAD_NOT_ENTITLED",
                String(a.err && a.err.details));
    });
  }
  podOnly.close();
  await ok(api + "/spiffe/brokers/remove",
           { id: "spiffe://" + BROKER_TD + "/broker" }, "removed the broker");
  a = await unary(broker, jwt(pidRef(1)));
  broker.close();
  check(o.mode + ": a broker removed is PERMISSION_DENIED on its next call",
        function () {
    assert.strictEqual(codeOf(a), grpc.status.PERMISSION_DENIED,
                       String(a.err && a.err.details));
  });
  await call("POST", api + "/spiffe/entries/delete",
             { entry: pidEntry.json && pidEntry.json.id });
  log.debug("Leaving oneRealm().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the SPIFFE Broker API at " + base + "; the fake kubelet " +
           "is on " + HOST);
  const probe = await call("GET", base + "/admin-api/spiffe/brokers");
  if (probe.status === 404) {
    declineToRun(log, "this environment does not publish " +
                 "/admin-api/spiffe/brokers");
    return;
  }
  const ca = await testCa.makeCa();
  const kube = await kubelet(ca);
  const realmsMade = [];
  const uid = String(process.env.STS_SPIFFE_BROKER_PID_UID || "0");
  const shared = { ca: ca, uid: uid,
                   kubeletPort: kube.address().port,
                   broker: await svid(ca, "spiffe://" + BROKER_TD +
                                          "/broker"),
                   podBroker: await svid(ca, "spiffe://" + BROKER_TD +
                                             "/pod-broker"),
                   stranger: await svid(ca, "spiffe://" + BROKER_TD +
                                            "/stranger") };
  try {
    for (const mode of ["development", "product"]) {
      const id = "brk" + (mode === "product" ? "p" : "d") + RUN.slice(-8);
      realmsMade.push(id);
      await oneRealm(Object.assign({}, shared, {
        id: id, mode: mode,
        port: Number(mode === "product"
          ? process.env.STS_SPIFFE_BROKER_PORT_PROD || 8194
          : process.env.STS_SPIFFE_BROKER_PORT_DEV || 8193) }));
    }
  } finally {
    // The realms stay, SPIFFE off, so their ports are free for the next run.
    for (const id of realmsMade) {
      try {
        await call("POST", base + "/admin-api/realms/set",
                   { id: id, key: "spiffe.enabled", value: false });
      } catch (e) {
        log.debug("Caught in test(): " + ((e && e.message) || e));
        log.warn("The realm " + id + " could not be turned off: " + e.message);
      }
    }
    kube.close();
  }
  // A section skipped for an endpoint this runner cannot reach, or a
  // product kubelet with no shared directory, runs fewer; nothing skipped,
  // every check must have run. BOTH endpoints unreachable is the `cluster`
  // mode, where each realm's Broker socket is a per-node listener the balancer
  // does not forward (tests/cluster/haproxy.cfg): each realm still runs its
  // five setup checks, so ten remain, where a single skip leaves twelve.
  const floor = skipped >= 2 ? 10 : (skipped ? 12 : 30);
  assert.ok(checks >= floor, "only " + checks + " checks ran " +
            "with " + skipped + " section(s) skipped; a section has stopped " +
            "being called.");
  log.info(checks + " check(s) passed, " + skipped + " section(s) skipped.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_spiffe_broker")
  .description("The SPIFFE Broker API over mutual TLS in a development and " +
    "a product realm: refused without a broker SVID, the reference " +
    "refusals, and a process and a pod reference answered.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
