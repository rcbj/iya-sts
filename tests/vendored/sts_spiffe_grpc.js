"use strict";
//
// File: sts_spiffe_grpc.js
//
// ---------------------------------------------------------------------------
// THE SPIFFE WORKLOAD API AND THE SPIRE SERVER API, OVER THE NETWORK, AT THE
// ADDRESS THE SERVICE IS REACHED AT (2026-09-18).
//
// Until this job both gRPC surfaces were covered only IN PROCESS
// (tests/spiffe_*.js): a real client on a realm's Unix socket, the codec both
// ways, the policy table read off the module. None of that says anything about
// a DEPLOYED service — three nodes behind a load balancer that passes TCP
// straight through, each node minting from an authority the cluster agreed on,
// a registry that is a replicated directory, and a join token that must be
// spent once across nodes. So this job is a gRPC CLIENT of its own
// (`@grpc/grpc-js` driven from here, never the service's `spiffe_grpc.ts`
// wrappers — `spiffe/CLAUDE.md`'s instruction: if both ends came from one
// implementation, a shared misunderstanding passes and interoperates with
// nobody) against the default trust realm's two TCP listeners.
//
// WHAT IT CREATES, AND HOW. Nothing is changed about the service: no setting
// is read for any purpose but finding out what the service IS. Every
// registration entry this job needs is created BEFOREHAND through
// `/admin-api/spiffe/entries` and deleted at the end:
//
//   * W, a workload entry whose selectors are the two a TCP Workload API
//     caller is seen by (`transport:tcp`, `endpoint:<grpcHost>:<port>` —
//     `spiffe_auth.ts`'s `workloadSelectors()`), with a DNS name, a hint and
//     short lifetimes of its own so they can be asserted;
//   * A, the same selectors and the `admin` flag — which is how an X509-SVID
//     that may call the SPIRE Server API's admin methods is obtained without
//     touching `spiffe.adminIds`: the Workload API hands it out, and
//     `spiffe_auth.ts`'s `classify()` reads the flag off the registry on
//     every call;
//   * N, selecting `transport:uds` only, which a TCP caller must NOT be given
//     — selector matching DECIDES the answer (`spiffe.attestWorkloads`);
//   * C, created once an agent has attested, with that agent as its parent,
//     which is what `GetAuthorizedEntries` must hand the agent back.
//
// **THE WORKLOAD API AUTHENTICATES NOBODY AND ATTESTS NOTHING, BY DESIGN**
// (`spiffe/CLAUDE.md`): any TCP caller of the port matches W and A while they
// exist. So A is the shortest-lived thing this job makes — its SVIDs live five
// minutes — and it is deleted the moment the admin half is done, which is
// itself asserted: the admin SVID still in this job's hands is REFUSED the
// admin methods once the entry is gone, because the flag is read per call and
// never cached. On testidp the ports admit only the operator's own address.
//
// WHAT IS ASSERTED — positives and, as much, the refusals:
//
//   Workload API (plain gRPC; the specification forbids requiring TLS)
//     1. a call without the `workload.spiffe.io: true` header is
//        INVALID_ARGUMENT (where `spiffe.requireSecurityHeader` is on);
//     2. FetchX509SVID: W's SVID — exactly one URI SAN, W's SPIFFE ID; W's
//        DNS name; not a CA; a lifetime within W's own `x509SvidTtl`; a chain
//        in which each certificate is ISSUED AND SIGNED by the next, ending at
//        an anchor in the bundle it came with; a private key that matches the
//        leaf; the hint; no CRL; N's identity absent; and the stream still
//        OPEN after its first message (a stream that ends puts a real client
//        into a reconnect loop);
//     3. FetchX509Bundles: this trust domain's bundle, byte-identical to the
//        anchors FetchX509SVID sent and to the `x509-svid` keys of the HTTPS
//        bundle endpoint;
//     4. FetchJWTSVID: no audience is INVALID_ARGUMENT, a malformed
//        `spiffe_id` is INVALID_ARGUMENT, an identity the caller is not
//        entitled to (N) is an EMPTY list, and W's token carries W as `sub`,
//        the audience asked for, a lifetime within W's `jwtSvidTtl`, and a
//        signature THIS FILE verifies against FetchJWTBundles' key;
//     5. FetchJWTBundles: the `jwt-svid` keys of the HTTPS bundle, and only
//        those;
//     6. ValidateJWTSVID: W's token validates, with `claims` actually
//        CARRYING sub/aud/exp (the `google.protobuf.Struct` that once
//        serialised to nothing); a wrong audience, a tampered payload, a
//        token this file signed with a key of its own under the service's
//        `kid`, and garbage are each INVALID_ARGUMENT.
//
//   SPIRE Server API (mutual TLS; the server is verified against the bundle
//   and must present `spiffe://<td>/spire/server`)
//     7. anonymous: ListEntries and CreateJoinToken are UNAUTHENTICATED;
//        GetBundle is OPEN and answers this trust domain's anchors and JWT
//        keys;
//     8. W's genuine but ordinary SVID: ListEntries and CreateJoinToken are
//        PERMISSION_DENIED (something presented, not enough — a different
//        instruction from UNAUTHENTICATED); RenewAgent is PERMISSION_DENIED;
//     9. a SELF-SIGNED certificate naming A's admin SPIFFE ID: refused;
//    10. A's admin SVID: CountEntries, ListEntries filtered to W, a
//        BatchCreateEntry and BatchDeleteEntry round trip, CreateJoinToken;
//        Debug.GetInfo is still PERMISSION_DENIED over TCP (SPIRE's own
//        local-only row);
//    11. AttestAgent: no CSR is INVALID_ARGUMENT; a join token never minted
//        is PERMISSION_DENIED; the minted token attests an agent under
//        `/spire/agent/join_token/` whose SVID chains to the bundle; the same
//        token again is PERMISSION_DENIED (single use, across nodes);
//    12. the agent's SVID: GetAuthorizedEntries returns C; ListEntries and
//        CreateJoinToken are PERMISSION_DENIED; RenewAgent renews THE AGENT
//        ON THE CONNECTION (same SPIFFE ID, a new certificate);
//    13. the agent BANNED through `/admin-api`: its SVID is refused
//        GetAuthorizedEntries;
//    14. A's entry DELETED through `/admin-api`: A's admin SVID is refused
//        ListEntries.
//
// A CLUSTER IS A REPLICATED REGISTRY, so every assertion that depends on a
// write made through `/admin-api` (an entry, a join token, an agent, a ban, a
// delete) is asked on a FRESH gRPC connection per attempt until it holds —
// bounded, and a refusal that must hold is asked to hold on several fresh
// connections in a row, not once. A fresh connection is what lets the load
// balancer pick another node: grpc-js shares one subchannel per target across
// clients unless told not to (`grpc.use_local_subchannel_pool`).
//
// ADDRESSES ARE ASKED, NOT ASSUMED: the host is the service URL's, the ports,
// bind address and trust domain are the realm's own settings
// (`GET /admin-api/config`), and STS_SPIFFE_WORKLOAD_URL /
// STS_SPIFFE_SERVER_URL (`host:port`, `tcp://host:port`) override the
// published address where it differs. A Workload API with no TCP port is a
// SKIP with the reason, not a failure.
//
// OWNED HERE (local: true): no counterpart exists in the parent project.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");
const forge = require("node-forge");
const facts = require("./service_facts.js");
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
var log = bunyan.createLogger({ name: "sts_spiffe_grpc",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const API = base + "/admin-api";
// One tag per run, so two runs against one shared service (and a run's
// leftovers, should a cleanup fail) never collide on a SPIFFE ID.
const RUN = "r" + Date.now().toString(36) +
            nodeCrypto.randomBytes(3).toString("hex");
const AUDIENCE = "urn:sts-test:spiffe-grpc:" + RUN;
const SECURITY_HEADER = "workload.spiffe.io";
// Replication across nodes is a change log a node polls; these bound how long
// a write made through /admin-api is waited for before the gRPC answer that
// depends on it is taken as final. Generous, because a failure here costs
// only time and a false failure costs an afternoon.
const ATTEMPTS = 30;
const PAUSE_MS = 1500;
const HOLDS = 3;
const DEADLINE_MS = 20000;

// The protos the SERVICE serves, read from its own tree: in the tests image
// the tree is at /usr/src/sts, and a vendored job sits two levels below it.
// The load options are the service's own (`spiffe_grpc.ts`), because
// `keepCase` decides every field name this file reads.
const PROTO_DIR = path.join(__dirname, "..", "..", "spiffe", "protos");
const LOAD_OPTIONS = { keepCase: true, longs: String, enums: String,
                       defaults: true, oneofs: true,
                       includeDirs: [PROTO_DIR] };
const SERVER_PROTOS = [
  "spire/api/server/entry/v1/entry.proto",
  "spire/api/server/agent/v1/agent.proto",
  "spire/api/server/bundle/v1/bundle.proto",
  "spire/api/server/debug/v1/debug.proto"
];

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// ---------------------------------------------------------------------------
// HTTP: the management API (its token is attached by the runner's preload)
// and the bundle endpoint.
// ---------------------------------------------------------------------------
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

async function createEntry(fields, what) {
  log.debug("Entering createEntry().");
  const r = await call("POST", API + "/spiffe/entries/create", fields);
  assert.ok(r.status === 200 && r.json && r.json.ok && r.json.id,
            what + " could not be created: " + r.status + " " +
            r.text.slice(0, 400));
  log.debug("Leaving createEntry(). " + r.json.id);
  return r.json.id;
}

async function deleteEntry(id) {
  log.debug("Entering deleteEntry().");
  const r = await call("POST", API + "/spiffe/entries/delete", { entry: id });
  log.debug("Leaving deleteEntry(). " + r.status);
  return r;
}

// ---------------------------------------------------------------------------
// CERTIFICATES. The Workload API's `bytes` fields are ASN.1 DER — a chain or a
// bundle is several certificates CONCATENATED, with no separator — and node's
// X509Certificate reads exactly one, so the DER is split here by its own
// SEQUENCE headers.
// ---------------------------------------------------------------------------
function splitDer(buffer) {
  log.debug("Entering splitDer().");
  const out = [];
  let at = 0;
  const der = Buffer.from(buffer || []);
  while (at < der.length) {
    assert.strictEqual(der[at], 0x30,
                       "a DER certificate starts with a SEQUENCE at " + at);
    let length = der[at + 1];
    let header = 2;
    if (length & 0x80) {
      const bytes = length & 0x7f;
      length = 0;
      for (let i = 0; i < bytes; i++) {
        length = (length * 256) + der[at + 2 + i];
      }
      header = 2 + bytes;
    }
    out.push(der.subarray(at, at + header + length));
    at += header + length;
  }
  log.debug("Leaving splitDer(). " + out.length + " certificate(s).");
  return out.map(function (one) {
    return new nodeCrypto.X509Certificate(one);
  });
}

function uriSans(cert) {
  log.debug("Entering uriSans().");
  const names = String(cert.subjectAltName || "").split(/,\s*/);
  log.debug("Leaving uriSans().");
  return names.filter(function (n) { return n.indexOf("URI:") === 0; })
    .map(function (n) { return n.slice(4); });
}

function dnsSans(cert) {
  log.debug("Entering dnsSans().");
  const names = String(cert.subjectAltName || "").split(/,\s*/);
  log.debug("Leaving dnsSans().");
  return names.filter(function (n) { return n.indexOf("DNS:") === 0; })
    .map(function (n) { return n.slice(4); });
}

// Each certificate ISSUED (names) and SIGNED (signature) by the next, and the
// last by one of the anchors. Returns a sentence for an assertion message
// rather than throwing, so the caller's check names what failed.
function chainProblem(chain, anchors) {
  log.debug("Entering chainProblem().");
  for (let i = 0; i + 1 < chain.length; i++) {
    if (!chain[i].checkIssued(chain[i + 1]) ||
        !chain[i].verify(chain[i + 1].publicKey)) {
      log.debug("Leaving chainProblem(). Link " + i + ".");
      return "certificate " + i + " (" + chain[i].subject + ") is not " +
             "issued and signed by certificate " + (i + 1) + " (" +
             chain[i + 1].subject + ")";
    }
  }
  const top = chain[chain.length - 1];
  const anchored = anchors.some(function (anchor) {
    return top.checkIssued(anchor) && top.verify(anchor.publicKey);
  });
  if (!anchored) {
    log.debug("Leaving chainProblem(). No anchor.");
    return "the top of the chain (" + top.subject + ", issued by " +
           top.issuer + ") was signed by no anchor in the bundle";
  }
  log.debug("Leaving chainProblem(). None.");
  return "";
}

function pemOf(certs) {
  log.debug("Entering pemOf().");
  log.debug("Leaving pemOf().");
  return certs.map(function (c) { return c.toString(); }).join("\n");
}

// A fresh RSA key pair and a PKCS#10 request for it, DER. The CSR only
// conveys a public key (agent.proto says so), and forge is what this suite
// already builds CSRs and certificates with; the service reads the key out
// of it with pkijs, which is a second implementation of the same format.
function newKeyAndCsr(commonName) {
  log.debug("Entering newKeyAndCsr().");
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: "commonName", value: commonName }]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  const der = Buffer.from(forge.asn1.toDer(
      forge.pki.certificationRequestToAsn1(csr)).getBytes(), "binary");
  log.debug("Leaving newKeyAndCsr().");
  return { csrDer: der,
           privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey) };
}

// A SELF-SIGNED certificate carrying whatever SPIFFE ID it is told to — the
// forgery the SPIRE Server API must refuse however well it names an admin.
function forgedCertificate(spiffeUri) {
  log.debug("Entering forgedCertificate().");
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  const name = [{ name: "commonName", value: "forged " + RUN }];
  cert.setSubject(name);
  cert.setIssuer(name);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", clientAuth: true },
    { name: "subjectAltName", altNames: [{ type: 6, value: spiffeUri }] }
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  log.debug("Leaving forgedCertificate().");
  return { certPem: forge.pki.certificateToPem(cert),
           privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey) };
}

// ---------------------------------------------------------------------------
// JWT. Verified HERE, against the key FetchJWTBundles published, so a
// ValidateJWTSVID that said yes to everything could not carry the positive
// half of section 4 on its own.
// ---------------------------------------------------------------------------
function decodeJwt(token) {
  log.debug("Entering decodeJwt().");
  const parts = String(token || "").split(".");
  assert.strictEqual(parts.length, 3, "a JWS compact serialisation");
  log.debug("Leaving decodeJwt().");
  return {
    header: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")),
    payload: JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")),
    signingInput: parts[0] + "." + parts[1],
    signature: Buffer.from(parts[2], "base64url")
  };
}

function verifyJws(decoded, jwk) {
  log.debug("Entering verifyJws(). alg=" + decoded.header.alg);
  const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  const alg = String(decoded.header.alg || "");
  const data = Buffer.from(decoded.signingInput, "utf8");
  let ok;
  if (/^ES(256|384|512)$/.test(alg)) {
    ok = nodeCrypto.verify("sha" + alg.slice(2), data,
                           { key: key, dsaEncoding: "ieee-p1363" },
                           decoded.signature);
  } else if (/^RS(256|384|512)$/.test(alg)) {
    ok = nodeCrypto.verify("sha" + alg.slice(2), data, key,
                           decoded.signature);
  } else if (/^PS(256|384|512)$/.test(alg)) {
    ok = nodeCrypto.verify("sha" + alg.slice(2), data,
      { key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: Number(alg.slice(2)) / 8 }, decoded.signature);
  } else if (alg === "EdDSA") {
    ok = nodeCrypto.verify(null, data, key, decoded.signature);
  } else {
    log.debug("Leaving verifyJws(). Unknown alg.");
    throw new Error("this job cannot verify a JWT-SVID signed " + alg +
                    "; teach verifyJws() the algorithm");
  }
  log.debug("Leaving verifyJws(). " + ok);
  return ok;
}

// A JWS signed with a key of THIS FILE's, under the header the service used
// — its alg (ES256 by default; P-256 whatever it says, since a signature this
// file makes only has to be well-formed) and its kid — carrying the genuine
// payload. What ValidateJWTSVID must refuse is exactly this: a token that
// names a key it holds and was signed by one it does not.
function resignedWithForeignKey(decoded) {
  log.debug("Entering resignedWithForeignKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const header = Object.assign({}, decoded.header, { alg: "ES256" });
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
                "." + Buffer.from(JSON.stringify(decoded.payload))
                  .toString("base64url");
  const signature = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving resignedWithForeignKey().");
  return input + "." + signature.toString("base64url");
}

// ---------------------------------------------------------------------------
// gRPC. A client per call, on a subchannel of its own, so that every call is
// a new TCP connection and the load balancer may pick another node.
// ---------------------------------------------------------------------------
const CHANNEL_OPTIONS = { "grpc.use_local_subchannel_pool": 1 };

function loadServices() {
  log.debug("Entering loadServices().");
  const workload = grpc.loadPackageDefinition(
      protoLoader.loadSync("workloadapi.proto", LOAD_OPTIONS));
  const server = grpc.loadPackageDefinition(
      protoLoader.loadSync(SERVER_PROTOS, LOAD_OPTIONS));
  log.debug("Leaving loadServices().");
  return {
    Workload: workload.SpiffeWorkloadAPI,
    Entry: server.spire.api.server.entry.v1.Entry,
    Agent: server.spire.api.server.agent.v1.Agent,
    Bundle: server.spire.api.server.bundle.v1.Bundle,
    Debug: server.spire.api.server.debug.v1.Debug
  };
}

function workloadMetadata(withHeader) {
  log.debug("Entering workloadMetadata().");
  const md = new grpc.Metadata();
  if (withHeader) {
    md.set(SECURITY_HEADER, "true");
  }
  log.debug("Leaving workloadMetadata().");
  return md;
}

// One unary call, resolved with `{ error, value }` and never rejected, so each
// check reads the status it expects. The client is closed either way.
function unary(client, method, request, metadata) {
  log.debug("Entering unary(). " + method);
  return new Promise(function (resolve) {
    client[method](request, metadata || new grpc.Metadata(),
                   { deadline: Date.now() + DEADLINE_MS },
                   function (error, value) {
      client.close();
      if (error) {
        log.debug("unary(): " + method + " answered " + error.code + " " +
                  error.details);
      }
      resolve({ error: error || null, value: value || null });
    });
    log.debug("Leaving unary(). " + method + " sent.");
  });
}

// The FIRST message of a server stream, and whether the stream was still open
// `holdMs` after it: every Workload API stream is a subscription a real client
// holds for the life of the process, and one that ends after its first
// message looks perfect here and puts go-spiffe into a reconnect loop.
function firstMessage(client, method, request, metadata, holdMs) {
  log.debug("Entering firstMessage(). " + method);
  return new Promise(function (resolve) {
    const stream = client[method](request, metadata);
    const state = { message: null, error: null, ended: false, done: false };
    const timer = setTimeout(function () {
      state.error = state.error ||
        { code: -1, details: "no message within " + DEADLINE_MS + " ms" };
      finish();
    }, DEADLINE_MS);
    function finish() {
      log.debug("Entering finish().");
      if (state.done) {
        log.debug("Leaving finish(). Already.");
        return;
      }
      state.done = true;
      clearTimeout(timer);
      stream.cancel();
      client.close();
      resolve({ message: state.message, error: state.error,
                endedEarly: state.ended });
      log.debug("Leaving finish().");
    }
    stream.on("data", function (message) {
      if (state.message) {
        return;
      }
      state.message = message;
      setTimeout(finish, holdMs || 0);
    });
    stream.on("end", function () {
      state.ended = true;
    });
    stream.on("error", function (error) {
      // A cancel of our own arrives here as CANCELLED once finish() has run;
      // anything before it is the call's answer.
      if (!state.done) {
        log.debug("firstMessage(): " + method + " answered " + error.code +
                  " " + error.details);
        state.error = error;
        finish();
      }
    });
    log.debug("Leaving firstMessage(). " + method + " opened.");
  });
}

// ---------------------------------------------------------------------------
// test()
// ---------------------------------------------------------------------------
function parseAddress(text) {
  log.debug("Entering parseAddress().");
  const t = String(text || "").trim().replace(/^[a-z]+:\/\//i, "")
    .replace(/\/.*$/, "");
  log.debug("Leaving parseAddress(). " + t);
  return t;
}

async function test() {
  log.debug("Entering test().");
  const settings = await facts.settings(API);
  const product = await facts.isProduct(API);
  const trustDomain = String(settings["spiffe.trustDomain"] || "");
  const tdId = "spiffe://" + trustDomain;
  const grpcHost = String(settings["spiffe.grpcHost"] || "");
  const workloadPort = Number(settings["spiffe.workloadPort"]);
  const serverPort = Number(settings["spiffe.serverPort"]);
  const serviceHost = new URL(base).hostname;
  log.info("The service is in " + (product ? "PRODUCT" : "development") +
           " mode; trust domain " + trustDomain + ", gRPC bound on " +
           grpcHost + " (Workload API " + workloadPort + ", SPIRE Server " +
           "API " + serverPort + ").");
  assert.ok(trustDomain, "spiffe.trustDomain is set");
  if (settings["spiffe.enabled"] !== true) {
    declineToRun(log, "spiffe.enabled is off in the default realm, so both " +
                      "gRPC surfaces answer Unavailable by design; this job " +
                      "does not turn it on.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  if (!(workloadPort > 0) && !process.env.STS_SPIFFE_WORKLOAD_URL) {
    declineToRun(log, "the default realm's Workload API has no TCP port " +
                      "(spiffe.workloadPort is " + workloadPort + "): it " +
                      "is on the Unix socket " +
                      settings["spiffe.workloadSocket"] + " only, which a " +
                      "network client cannot reach.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  if (!(serverPort > 0) && !process.env.STS_SPIFFE_SERVER_URL) {
    declineToRun(log, "the default realm's SPIRE Server API has no TCP " +
                      "port (spiffe.serverPort is " + serverPort + ").");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const workloadTarget = parseAddress(process.env.STS_SPIFFE_WORKLOAD_URL) ||
                         serviceHost + ":" + workloadPort;
  const serverTarget = parseAddress(process.env.STS_SPIFFE_SERVER_URL) ||
                       serviceHost + ":" + serverPort;
  log.info("Workload API at " + workloadTarget + ", SPIRE Server API at " +
           serverTarget + ".");
  const svc = loadServices();
  const requireHeader = settings["spiffe.requireSecurityHeader"] !== false;
  const narrowing = settings["spiffe.attestWorkloads"] !== false;

  // The selectors a TCP caller of THIS port is seen by — the realm's own bind
  // address and port, not the address this job dialled (which, behind a load
  // balancer, is a different string entirely).
  const tcpSelectors = "transport:tcp, endpoint:" + grpcHost + ":" +
                       workloadPort;
  const W = tdId + "/sts-test/spiffe-grpc/" + RUN + "/workload";
  const A = tdId + "/sts-test/spiffe-grpc/" + RUN + "/admin";
  const N = tdId + "/sts-test/spiffe-grpc/" + RUN + "/unix-only";
  const C = tdId + "/sts-test/spiffe-grpc/" + RUN + "/agent-child";
  const W_DNS = "w-" + RUN + ".sts-test.invalid";
  const W_X509_TTL = 600;
  const W_JWT_TTL = 120;
  const created = {};
  let agentId = "";

  function workload() {
    log.debug("Entering workload().");
    log.debug("Leaving workload().");
    return new svc.Workload(workloadTarget, grpc.credentials.createInsecure(),
                            CHANNEL_OPTIONS);
  }

  let anchorsPem = "";
  // A client of one SPIRE Server API service, over mutual TLS — or TLS with
  // no client certificate when `who` is null. The server is verified against
  // the trust bundle, never the web PKI, and must present THE server's SPIFFE
  // ID: its certificate has no DNS name, so grpc-js's host-name check is
  // replaced by the check a SPIFFE client actually makes.
  function server(Service, who) {
    log.debug("Entering server().");
    const credentials = grpc.credentials.createSsl(
      Buffer.from(anchorsPem, "utf8"),
      who ? Buffer.from(who.privateKeyPem, "utf8") : null,
      who ? Buffer.from(who.certPem, "utf8") : null,
      { checkServerIdentity: function (hostname, cert) {
        const want = "URI:" + tdId + "/spire/server";
        const names = String((cert && cert.subjectaltname) || "")
          .split(/,\s*/);
        return names.indexOf(want) >= 0 ? undefined
          : new Error("the SPIRE Server API presented " +
                      ((cert && cert.subjectaltname) || "no SAN") +
                      ", not " + want);
      } });
    log.debug("Leaving server().");
    return new Service(serverTarget, credentials, CHANNEL_OPTIONS);
  }

  // Ask until `settled(answer)` holds, on a fresh connection each time; then,
  // when `holds` is given, ask that many more times and require every answer
  // to settle too — a refusal that one node gives and another does not is not
  // yet the service's answer.
  async function eventually(what, ask, settled, holds) {
    log.debug("Entering eventually(). " + what);
    let answer = null;
    for (let i = 0; i < ATTEMPTS; i++) {
      answer = await ask();
      if (settled(answer)) {
        for (let j = 0; j < (holds || 0); j++) {
          answer = await ask();
          assert.ok(settled(answer), what + ": settled once and then not on " +
                    "a later connection: " + describe(answer));
        }
        log.debug("Leaving eventually(). After " + (i + 1) + ".");
        return answer;
      }
      await sleep(PAUSE_MS);
    }
    log.debug("Leaving eventually(). Never settled.");
    return answer;
  }

  function describe(answer) {
    log.debug("Entering describe().");
    log.debug("Leaving describe().");
    if (answer && answer.error) {
      return "status " + answer.error.code + ": " + answer.error.details;
    }
    return JSON.stringify(answer && (answer.value || answer.message))
      .slice(0, 600);
  }

  function codeIs(code) {
    log.debug("Entering codeIs().");
    log.debug("Leaving codeIs().");
    return function (answer) {
      return !!(answer && answer.error && answer.error.code === code);
    };
  }

  function succeeded(answer) {
    log.debug("Entering succeeded().");
    log.debug("Leaving succeeded().");
    return !!(answer && !answer.error);
  }

  try {
    // =======================================================================
    // 0. THE REGISTRY, THROUGH /admin-api — including its two refusals.
    // =======================================================================
    log.info("=== 0. registration entries created through /admin-api ===");
    let r = await call("POST", API + "/spiffe/entries/create",
                       { spiffeId: "spiffe://other-domain.invalid/x/" + RUN,
                         selectors: tcpSelectors });
    check("an entry in ANOTHER trust domain is refused", function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    });
    r = await call("POST", API + "/spiffe/entries/create",
                   { spiffeId: tdId + "/spire/sts-test-" + RUN,
                     selectors: tcpSelectors });
    check("an entry under the reserved /spire path is refused", function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    });
    created.W = await createEntry({ spiffeId: W, selectors: tcpSelectors,
                                    dnsNames: W_DNS, hint: "sts-test-" + RUN,
                                    x509SvidTtl: W_X509_TTL,
                                    jwtSvidTtl: W_JWT_TTL }, "W");
    created.A = await createEntry({ spiffeId: A, selectors: tcpSelectors,
                                    x509SvidTtl: 300, jwtSvidTtl: 60 }, "A");
    r = await call("POST", API + "/spiffe/entries/update",
                   { entry: created.A, field: "admin", value: "true" });
    check("A is marked admin through /admin-api", function () {
      assert.ok(r.status === 200 && r.json && r.json.entry &&
                r.json.entry.admin === true, r.text.slice(0, 400));
    });
    created.N = await createEntry({ spiffeId: N,
                                    selectors: "transport:uds" }, "N");

    // =======================================================================
    // 1–2. FetchX509SVID.
    // =======================================================================
    log.info("=== 1-2. Workload API: FetchX509SVID ===");
    let a = await firstMessage(workload(), "FetchX509SVID", {},
                               workloadMetadata(false), 0);
    check("a Workload API call without the " + SECURITY_HEADER + " header " +
          (requireHeader ? "is INVALID_ARGUMENT" : "is answered " +
                           "(spiffe.requireSecurityHeader is off)"),
          function () {
      if (requireHeader) {
        assert.ok(a.error && a.error.code === grpc.status.INVALID_ARGUMENT,
                  describe(a));
        assert.ok(/workload\.spiffe\.io/.test(a.error.details), describe(a));
      } else {
        assert.ok(!a.error, describe(a));
      }
    });
    function svidsOf(answer) {
      log.debug("Entering svidsOf().");
      log.debug("Leaving svidsOf().");
      return (answer && answer.message && answer.message.svids) || [];
    }
    function hasBoth(answer) {
      log.debug("Entering hasBoth().");
      const ids = svidsOf(answer).map(function (s) { return s.spiffe_id; });
      log.debug("Leaving hasBoth().");
      return !answer.error && ids.indexOf(W) >= 0 && ids.indexOf(A) >= 0;
    }
    a = await eventually("FetchX509SVID hands out W and A", function () {
      return firstMessage(workload(), "FetchX509SVID", {},
                          workloadMetadata(true), 2000);
    }, hasBoth, 0);
    check("FetchX509SVID answers W and A, the two entries whose selectors a " +
          "TCP caller matches", function () {
      assert.ok(hasBoth(a), describe(a));
    });
    const wSvid = svidsOf(a).filter(function (s) {
      return s.spiffe_id === W;
    })[0];
    const aSvid = svidsOf(a).filter(function (s) {
      return s.spiffe_id === A;
    })[0];
    check("the stream is still OPEN two seconds after its first message",
          function () {
      assert.strictEqual(a.endedEarly, false);
    });
    check("N (transport:uds) is " + (narrowing ? "NOT " : "") + "handed to " +
          "a TCP caller" + (narrowing ? "" : " (spiffe.attestWorkloads is " +
                                              "off, so nothing narrows)"),
          function () {
      const ids = svidsOf(a).map(function (s) { return s.spiffe_id; });
      assert.strictEqual(ids.indexOf(N) >= 0, !narrowing, ids.join(" "));
    });
    check("no CRL — SPIFFE has none, and empty is the conforming value",
          function () {
      assert.deepStrictEqual(a.message.crl, []);
    });
    const chain = splitDer(wSvid.x509_svid);
    const anchors = splitDer(wSvid.bundle);
    anchorsPem = pemOf(anchors);
    const leaf = chain[0];
    check("W's X509-SVID carries exactly one URI SAN, and it is W",
          function () {
      assert.deepStrictEqual(uriSans(leaf), [W]);
    });
    check("W's X509-SVID carries W's DNS name", function () {
      assert.ok(dnsSans(leaf).indexOf(W_DNS) >= 0, leaf.subjectAltName);
    });
    check("W's X509-SVID is a leaf, not a CA", function () {
      assert.strictEqual(leaf.ca, false);
    });
    check("W's X509-SVID lives no longer than W's own x509SvidTtl (" +
          W_X509_TTL + " s)", function () {
      const life = (Date.parse(leaf.validTo) - Date.parse(leaf.validFrom)) /
                   1000;
      assert.ok(life > 0 && life <= W_X509_TTL + 120, "lifetime " + life);
      assert.ok(Date.parse(leaf.validTo) > Date.now(), leaf.validTo);
    });
    check("W's chain (" + chain.length + " certificates) links, each issued " +
          "and signed by the next, to an anchor in the bundle it came with",
          function () {
      assert.ok(chain.length >= 1 && anchors.length >= 1);
      assert.strictEqual(chainProblem(chain, anchors), "");
    });
    check("W's private key is the key the leaf certifies", function () {
      const key = nodeCrypto.createPrivateKey({ key: wSvid.x509_svid_key,
                                                format: "der",
                                                type: "pkcs8" });
      assert.ok(leaf.checkPrivateKey(key));
    });
    check("W's hint is passed through", function () {
      assert.strictEqual(wSvid.hint, "sts-test-" + RUN);
    });
    const aChain = splitDer(aSvid.x509_svid);
    check("A's X509-SVID names A and chains to the same bundle", function () {
      assert.deepStrictEqual(uriSans(aChain[0]), [A]);
      assert.strictEqual(chainProblem(aChain, anchors), "");
    });
    function identity(svid, theChain) {
      log.debug("Entering identity().");
      const key = nodeCrypto.createPrivateKey({ key: svid.x509_svid_key,
                                                format: "der",
                                                type: "pkcs8" });
      log.debug("Leaving identity().");
      return { certPem: pemOf(theChain),
               privateKeyPem: key.export({ type: "pkcs8", format: "pem" }) };
    }
    const wIdentity = identity(wSvid, chain);
    const aIdentity = identity(aSvid, aChain);

    // =======================================================================
    // 3. FetchX509Bundles, against the HTTPS bundle endpoint.
    // =======================================================================
    log.info("=== 3. Workload API: FetchX509Bundles ===");
    const bundlePath = String(settings["spiffe.bundlePath"] ||
                              "/spiffe/bundle");
    const doc = await call("GET", base + bundlePath);
    check("the HTTPS bundle endpoint answers a JWK Set", function () {
      assert.strictEqual(doc.status, 200, doc.text.slice(0, 300));
      assert.ok(doc.json && Array.isArray(doc.json.keys), doc.text);
    });
    const httpsAnchors = doc.json.keys.filter(function (k) {
      return k.use === "x509-svid";
    }).map(function (k) {
      return new nodeCrypto.X509Certificate(Buffer.from(k.x5c[0], "base64"));
    });
    const httpsJwtKids = doc.json.keys.filter(function (k) {
      return k.use === "jwt-svid";
    }).map(function (k) { return k.kid; }).sort();
    function prints(certs) {
      log.debug("Entering prints().");
      log.debug("Leaving prints().");
      return certs.map(function (c) { return c.fingerprint256; }).sort();
    }
    a = await firstMessage(workload(), "FetchX509Bundles", {},
                           workloadMetadata(true), 1000);
    check("FetchX509Bundles answers this trust domain's bundle under " + tdId +
          ", with no CRL, and stays open", function () {
      assert.ok(!a.error, describe(a));
      assert.ok(a.message.bundles[tdId], Object.keys(a.message.bundles)
        .join(" "));
      assert.deepStrictEqual(a.message.crl, []);
      assert.strictEqual(a.endedEarly, false);
    });
    check("…and it is the bundle FetchX509SVID sent, and the x509-svid keys " +
          "of the HTTPS bundle endpoint", function () {
      const own = splitDer(a.message.bundles[tdId]);
      assert.deepStrictEqual(prints(own), prints(anchors));
      assert.deepStrictEqual(prints(own), prints(httpsAnchors));
    });

    // =======================================================================
    // 4–5. FetchJWTSVID and FetchJWTBundles.
    // =======================================================================
    log.info("=== 4-5. Workload API: FetchJWTSVID, FetchJWTBundles ===");
    a = await unary(workload(), "FetchJWTSVID", { audience: [] },
                    workloadMetadata(true));
    check("FetchJWTSVID with no audience is INVALID_ARGUMENT", function () {
      assert.ok(codeIs(grpc.status.INVALID_ARGUMENT)(a), describe(a));
    });
    a = await unary(workload(), "FetchJWTSVID",
                    { audience: [AUDIENCE], spiffe_id: "not a spiffe id" },
                    workloadMetadata(true));
    check("FetchJWTSVID for a malformed spiffe_id is INVALID_ARGUMENT",
          function () {
      assert.ok(codeIs(grpc.status.INVALID_ARGUMENT)(a), describe(a));
    });
    if (narrowing) {
      a = await unary(workload(), "FetchJWTSVID",
                      { audience: [AUDIENCE], spiffe_id: N },
                      workloadMetadata(true));
      check("FetchJWTSVID for an identity the caller is not entitled to (N) " +
            "is an EMPTY list, not an error", function () {
        assert.ok(!a.error, describe(a));
        assert.deepStrictEqual(a.value.svids, []);
      });
    }
    a = await eventually("FetchJWTSVID for W", function () {
      return unary(workload(), "FetchJWTSVID",
                   { audience: [AUDIENCE], spiffe_id: W },
                   workloadMetadata(true));
    }, function (x) {
      return succeeded(x) && x.value.svids.length === 1;
    }, 0);
    check("FetchJWTSVID for W answers one JWT-SVID, for W", function () {
      assert.ok(!a.error, describe(a));
      assert.strictEqual(a.value.svids.length, 1, describe(a));
      assert.strictEqual(a.value.svids[0].spiffe_id, W);
    });
    const jwtSvid = a.value.svids[0].svid;
    const jwt = decodeJwt(jwtSvid);
    check("its sub is W, its aud the audience asked for, and it lives no " +
          "longer than W's jwtSvidTtl (" + W_JWT_TTL + " s)", function () {
      assert.strictEqual(jwt.payload.sub, W);
      const aud = [].concat(jwt.payload.aud);
      assert.deepStrictEqual(aud, [AUDIENCE]);
      assert.ok(jwt.payload.exp > Date.now() / 1000, "exp " + jwt.payload.exp);
      const life = jwt.payload.exp - (jwt.payload.iat ||
                                      Math.floor(Date.now() / 1000));
      assert.ok(life > 0 && life <= W_JWT_TTL + 1, "lifetime " + life);
      assert.ok(jwt.header.kid, JSON.stringify(jwt.header));
    });
    a = await firstMessage(workload(), "FetchJWTBundles", {},
                           workloadMetadata(true), 1000);
    let jwks = null;
    check("FetchJWTBundles answers a JWK Set under " + tdId + " and stays " +
          "open", function () {
      assert.ok(!a.error, describe(a));
      jwks = JSON.parse(Buffer.from(a.message.bundles[tdId]).toString("utf8"));
      assert.ok(Array.isArray(jwks.keys) && jwks.keys.length > 0,
                JSON.stringify(jwks));
      assert.strictEqual(a.endedEarly, false);
    });
    check("…holding exactly the jwt-svid keys of the HTTPS bundle, and no " +
          "X.509 key", function () {
      assert.deepStrictEqual(jwks.keys.map(function (k) { return k.kid; })
        .sort(), httpsJwtKids);
      jwks.keys.forEach(function (k) {
        assert.ok(!k.x5c && k.use !== "x509-svid", JSON.stringify(k));
      });
    });
    check("W's JWT-SVID verifies, HERE, against the key its kid names in " +
          "that bundle", function () {
      const jwk = jwks.keys.filter(function (k) {
        return k.kid === jwt.header.kid;
      })[0];
      assert.ok(jwk, "kid " + jwt.header.kid + " is in the bundle");
      const bare = Object.assign({}, jwk);
      delete bare.use;
      delete bare.kid;
      assert.ok(verifyJws(jwt, bare), "the signature verifies");
    });

    // =======================================================================
    // 6. ValidateJWTSVID.
    // =======================================================================
    log.info("=== 6. Workload API: ValidateJWTSVID ===");
    a = await eventually("ValidateJWTSVID of W's token", function () {
      return unary(workload(), "ValidateJWTSVID",
                   { audience: AUDIENCE, svid: jwtSvid },
                   workloadMetadata(true));
    }, succeeded, 0);
    check("W's JWT-SVID validates, naming W", function () {
      assert.ok(!a.error, describe(a));
      assert.strictEqual(a.value.spiffe_id, W);
    });
    check("…and its claims ARRIVE — a Struct with sub, aud and exp, not the " +
          "empty one a plain object serialises to", function () {
      const fields = (a.value.claims && a.value.claims.fields) || {};
      assert.ok(fields.sub && fields.sub.stringValue === W,
                JSON.stringify(fields).slice(0, 400));
      assert.ok(fields.exp && Number(fields.exp.numberValue) ===
                Number(jwt.payload.exp), JSON.stringify(fields.exp));
      assert.ok(fields.aud, "aud is in the claims");
      assert.ok(JSON.stringify(fields.aud).indexOf(AUDIENCE) >= 0,
                JSON.stringify(fields.aud));
    });
    const refusals = [
      ["a WRONG audience", { audience: AUDIENCE + ":other", svid: jwtSvid }],
      ["a TAMPERED payload (the sub changed to A, the signature kept)",
       { audience: AUDIENCE,
         svid: jwtSvid.split(".")[0] + "." +
               Buffer.from(JSON.stringify(Object.assign({}, jwt.payload,
                                                        { sub: A })))
                 .toString("base64url") + "." + jwtSvid.split(".")[2] }],
      ["a token signed by a key of this job's under the service's kid",
       { audience: AUDIENCE, svid: resignedWithForeignKey(jwt) }],
      ["something that is not a JWT at all",
       { audience: AUDIENCE, svid: "not.a.jwt-" + RUN }]
    ];
    for (let i = 0; i < refusals.length; i++) {
      a = await unary(workload(), "ValidateJWTSVID", refusals[i][1],
                      workloadMetadata(true));
      check("ValidateJWTSVID refuses " + refusals[i][0] + " (INVALID_ARGUMENT)",
            function () {
        assert.ok(codeIs(grpc.status.INVALID_ARGUMENT)(a), describe(a));
      });
    }

    // =======================================================================
    // 7. THE SPIRE SERVER API, ANONYMOUSLY.
    // =======================================================================
    log.info("=== 7. SPIRE Server API: anonymous ===");
    a = await unary(server(svc.Bundle, null), "GetBundle", {});
    check("GetBundle is OPEN to a caller with no certificate, over TLS the " +
          "caller verified against the bundle as " + tdId + "/spire/server",
          function () {
      assert.ok(!a.error, describe(a));
      assert.strictEqual(a.value.trust_domain, trustDomain);
    });
    check("…and answers this trust domain's anchors and JWT keys",
          function () {
      const got = a.value.x509_authorities.map(function (x) {
        return new nodeCrypto.X509Certificate(x.asn1);
      });
      assert.deepStrictEqual(prints(got), prints(anchors));
      assert.deepStrictEqual(a.value.jwt_authorities.map(function (k) {
        return k.key_id;
      }).sort(), httpsJwtKids);
    });
    a = await unary(server(svc.Entry, null), "ListEntries", {});
    check("ListEntries with no certificate is UNAUTHENTICATED", function () {
      assert.ok(codeIs(grpc.status.UNAUTHENTICATED)(a), describe(a));
    });
    a = await unary(server(svc.Agent, null), "CreateJoinToken", { ttl: 60 });
    check("CreateJoinToken with no certificate is UNAUTHENTICATED",
          function () {
      assert.ok(codeIs(grpc.status.UNAUTHENTICATED)(a), describe(a));
    });

    // =======================================================================
    // 8–9. AN ORDINARY SVID, AND A FORGED ADMIN.
    // =======================================================================
    log.info("=== 8-9. SPIRE Server API: W's SVID, and a forgery ===");
    a = await unary(server(svc.Entry, wIdentity), "ListEntries", {});
    check("ListEntries with W's genuine, non-admin SVID is PERMISSION_DENIED " +
          "(not UNAUTHENTICATED: something WAS presented)", function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });
    a = await unary(server(svc.Agent, wIdentity), "CreateJoinToken",
                    { ttl: 60 });
    check("CreateJoinToken with W's SVID is PERMISSION_DENIED", function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });
    const wCsr = newKeyAndCsr("w-renew-" + RUN);
    a = await unary(server(svc.Agent, wIdentity), "RenewAgent",
                    { params: { csr: wCsr.csrDer } });
    check("RenewAgent with W's SVID is PERMISSION_DENIED — W is no agent",
          function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });
    const forged = forgedCertificate(A);
    a = await unary(server(svc.Entry, forged), "ListEntries", {});
    check("a SELF-SIGNED certificate naming A's admin SPIFFE ID is refused " +
          "ListEntries", function () {
      assert.ok(a.error && (a.error.code === grpc.status.PERMISSION_DENIED ||
                            a.error.code === grpc.status.UNAUTHENTICATED),
                describe(a));
    });

    // =======================================================================
    // 10. THE ADMIN SVID.
    // =======================================================================
    log.info("=== 10. SPIRE Server API: A's admin SVID ===");
    const byW = { filter: { by_spiffe_id: { trust_domain: trustDomain,
                  path: W.slice(tdId.length) } } };
    a = await eventually("ListEntries as A", function () {
      return unary(server(svc.Entry, aIdentity), "ListEntries", byW);
    }, function (x) {
      return succeeded(x) && x.value.entries.length === 1;
    }, 0);
    check("ListEntries as A, filtered by W's SPIFFE ID, answers W's entry",
          function () {
      assert.ok(!a.error, describe(a));
      assert.strictEqual(a.value.entries.length, 1, describe(a));
      assert.strictEqual(a.value.entries[0].id, created.W);
      assert.strictEqual(a.value.entries[0].x509_svid_ttl, W_X509_TTL);
      assert.ok(a.value.entries[0].dns_names.indexOf(W_DNS) >= 0);
    });
    a = await unary(server(svc.Entry, aIdentity), "CountEntries", {});
    check("CountEntries as A answers a count", function () {
      assert.ok(!a.error, describe(a));
      assert.ok(Number(a.value.count) >= 3, describe(a));
    });
    a = await unary(server(svc.Debug, aIdentity), "GetInfo", {});
    check("Debug.GetInfo is PERMISSION_DENIED even to an admin over TCP — " +
          "SPIRE's own local-only row", function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });
    const viaSpire = tdId + "/sts-test/spiffe-grpc/" + RUN + "/via-spire-api";
    a = await unary(server(svc.Entry, aIdentity), "BatchCreateEntry", {
      entries: [{ spiffe_id: { trust_domain: trustDomain,
                               path: viaSpire.slice(tdId.length) },
                  parent_id: { trust_domain: trustDomain,
                               path: "/spire/server" },
                  selectors: [{ type: "transport", value: "uds" },
                              { type: "sts-test", value: RUN }] }] });
    let viaId = "";
    check("BatchCreateEntry as A creates an entry", function () {
      assert.ok(!a.error, describe(a));
      const one = a.value.results[0];
      assert.strictEqual(one.status.code, 0, JSON.stringify(one.status));
      viaId = one.entry.id;
      assert.ok(viaId, describe(a));
      created.via = viaId;
    });
    a = await eventually("BatchDeleteEntry as A", function () {
      return unary(server(svc.Entry, aIdentity), "BatchDeleteEntry",
                   { ids: [viaId] });
    }, function (x) {
      return succeeded(x) && x.value.results[0].status.code === 0;
    }, 0);
    check("…and BatchDeleteEntry as A removes it", function () {
      assert.ok(!a.error, describe(a));
      assert.strictEqual(a.value.results[0].status.code, 0, describe(a));
      delete created.via;
    });
    a = await unary(server(svc.Agent, aIdentity), "CreateJoinToken",
                    { ttl: 300 });
    let joinToken = "";
    check("CreateJoinToken as A answers a token and its expiry", function () {
      assert.ok(!a.error, describe(a));
      joinToken = a.value.value;
      assert.ok(joinToken && joinToken.length >= 16, describe(a));
      assert.ok(Number(a.value.expires_at) > Date.now() / 1000, describe(a));
    });

    // =======================================================================
    // 11. AttestAgent.
    // =======================================================================
    log.info("=== 11. SPIRE Server API: AttestAgent with a join token ===");
    const agentKey = newKeyAndCsr("agent-" + RUN);
    // THE SEND SIDE STAYS OPEN UNTIL THE ANSWER ARRIVES, which is what the
    // SPIRE agent does (Send, then Recv, then CloseSend). The first version of
    // this client half-closed straight after its one message, and the SERVICE
    // (`spiffe_grpc.ts`'s `bidiStream()`) answers a client's half-close with
    // `call.end()` at once — before the asynchronous handler has replied. The
    // attestation then completed on the server, SPENT THE TOKEN and recorded
    // the agent, and the client received an empty stream: every retry was
    // refused as spent. Recorded as a service defect rather than worked around
    // silently; this is the conforming client shape either way.
    function attest(token, csrDer) {
      log.debug("Entering attest().");
      const client = server(svc.Agent, null);
      log.debug("Leaving attest().");
      return new Promise(function (resolve) {
        const stream = client.AttestAgent(
          { deadline: Date.now() + DEADLINE_MS });
        let settledOnce = false;
        function done(error, value) {
          log.debug("Entering done().");
          if (settledOnce) {
            log.debug("Leaving done(). Already.");
            return;
          }
          settledOnce = true;
          try {
            stream.end();
          } catch (e) {
            log.debug("Caught in done(): " + ((e && e.message) || e));
            // A stream the server already failed has nothing to half-close.
          }
          client.close();
          resolve({ error: error, value: value });
          log.debug("Leaving done().");
        }
        stream.on("data", function (message) {
          done(null, message);
        });
        stream.on("error", function (error) {
          done(error, null);
        });
        stream.on("end", function () {
          done({ code: -1, details: "the stream ended with no answer" }, null);
        });
        const params = { data: { type: "join_token",
                                 payload: Buffer.from(token, "utf8") } };
        if (csrDer) {
          params.params = { csr: csrDer };
        }
        stream.write({ params: params });
      });
    }
    a = await attest(joinToken, null);
    check("AttestAgent with no CSR is INVALID_ARGUMENT", function () {
      assert.ok(codeIs(grpc.status.INVALID_ARGUMENT)(a), describe(a));
    });
    a = await attest("never-minted-" + RUN, agentKey.csrDer);
    check("AttestAgent with a join token this server never minted is " +
          "PERMISSION_DENIED", function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });
    // A node that has not yet replicated the token refuses it exactly as it
    // refuses a forgery, and a refused attestation does not spend it — so the
    // positive half is asked until one node accepts it.
    a = await eventually("AttestAgent with the minted token", function () {
      return attest(joinToken, agentKey.csrDer);
    }, succeeded, 0);
    let agentChain = [];
    check("AttestAgent with the minted join token issues an agent SVID " +
          "under /spire/agent/join_token/", function () {
      assert.ok(!a.error, describe(a));
      const svid = a.value.result.svid;
      agentId = tdId + svid.id.path;
      assert.strictEqual(svid.id.trust_domain, trustDomain);
      assert.ok(/^\/spire\/agent\/join_token\//.test(svid.id.path),
                svid.id.path);
      assert.strictEqual(a.value.result.reattestable, false);
      agentChain = svid.cert_chain.map(function (der) {
        return new nodeCrypto.X509Certificate(der);
      });
      assert.deepStrictEqual(uriSans(agentChain[0]), [agentId]);
      assert.strictEqual(chainProblem(agentChain, anchors), "");
    });
    a = await attest(joinToken, agentKey.csrDer);
    check("the same join token a second time is PERMISSION_DENIED — spent " +
          "once, across nodes", function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });

    // =======================================================================
    // 12. THE AGENT.
    // =======================================================================
    log.info("=== 12. SPIRE Server API: the agent's SVID ===");
    const agentIdentity = { certPem: pemOf(agentChain),
                            privateKeyPem: agentKey.privateKeyPem };
    created.C = await createEntry({ spiffeId: C, parentId: agentId,
                                    selectors: "sts-test:" + RUN }, "C");
    a = await eventually("GetAuthorizedEntries as the agent", function () {
      return unary(server(svc.Entry, agentIdentity),
                   "GetAuthorizedEntries", {});
    }, function (x) {
      return succeeded(x) && x.value.entries.some(function (e) {
        return e.id === created.C;
      });
    }, 0);
    check("GetAuthorizedEntries as the agent answers C, the entry beneath it",
          function () {
      assert.ok(!a.error, describe(a));
      const mine = a.value.entries.filter(function (e) {
        return e.id === created.C;
      });
      assert.strictEqual(mine.length, 1, describe(a));
      assert.strictEqual(tdId + mine[0].spiffe_id.path, C);
    });
    check("…and nothing that is not beneath it (W, A)", function () {
      const ids = a.value.entries.map(function (e) { return e.id; });
      assert.ok(ids.indexOf(created.W) < 0 && ids.indexOf(created.A) < 0,
                ids.join(" "));
    });
    a = await unary(server(svc.Entry, agentIdentity), "ListEntries", {});
    check("ListEntries as the agent is PERMISSION_DENIED", function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });
    a = await unary(server(svc.Agent, agentIdentity), "CreateJoinToken",
                    { ttl: 60 });
    check("CreateJoinToken as the agent is PERMISSION_DENIED", function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });
    const renewKey = newKeyAndCsr("agent-renew-" + RUN);
    a = await unary(server(svc.Agent, agentIdentity), "RenewAgent",
                    { params: { csr: renewKey.csrDer } });
    check("RenewAgent renews THE AGENT ON THE CONNECTION: the same SPIFFE " +
          "ID, a new certificate for the new key", function () {
      assert.ok(!a.error, describe(a));
      const renewed = a.value.svid.cert_chain.map(function (der) {
        return new nodeCrypto.X509Certificate(der);
      });
      assert.strictEqual(tdId + a.value.svid.id.path, agentId);
      assert.deepStrictEqual(uriSans(renewed[0]), [agentId]);
      assert.notStrictEqual(renewed[0].serialNumber,
                            agentChain[0].serialNumber);
      assert.ok(renewed[0].checkPrivateKey(
          nodeCrypto.createPrivateKey(renewKey.privateKeyPem)));
      assert.strictEqual(chainProblem(renewed, anchors), "");
    });

    // =======================================================================
    // 13. THE AGENT BANNED.
    // =======================================================================
    log.info("=== 13. the agent banned through /admin-api ===");
    r = await call("POST", API + "/spiffe/agents/ban", { agent: agentId });
    check("the agent is banned through /admin-api", function () {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    });
    a = await eventually("the banned agent refused", function () {
      return unary(server(svc.Entry, agentIdentity),
                   "GetAuthorizedEntries", {});
    }, codeIs(grpc.status.PERMISSION_DENIED), HOLDS);
    check("the banned agent's SVID is PERMISSION_DENIED at " +
          "GetAuthorizedEntries, on " + (HOLDS + 1) + " connections in a row",
          function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });

    // =======================================================================
    // 14. THE ADMIN ENTRY DELETED.
    // =======================================================================
    log.info("=== 14. A's entry deleted: its SVID is no longer an admin ===");
    r = await deleteEntry(created.A);
    check("A's entry is deleted through /admin-api", function () {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    });
    delete created.A;
    a = await eventually("A's SVID refused once A is gone", function () {
      return unary(server(svc.Entry, aIdentity), "ListEntries", byW);
    }, codeIs(grpc.status.PERMISSION_DENIED), HOLDS);
    check("the admin SVID still in hand is PERMISSION_DENIED at ListEntries " +
          "once its entry is gone — the flag is read per call, never cached",
          function () {
      assert.ok(codeIs(grpc.status.PERMISSION_DENIED)(a), describe(a));
    });
  } finally {
    // Everything this job made, whatever happened above. A failure here is
    // logged rather than thrown, so it cannot hide the failure that brought
    // the run here; the next run's entries carry a different RUN anyway.
    const names = Object.keys(created);
    for (let i = 0; i < names.length; i++) {
      try {
        const d = await deleteEntry(created[names[i]]);
        if (d.status !== 200) {
          log.warn("Entry " + names[i] + " (" + created[names[i]] + ") was " +
                   "not deleted: " + d.status + " " + d.text.slice(0, 200));
        }
      } catch (e) {
        log.debug("Caught in test(): " + ((e && e.message) || e));
        log.warn("Entry " + names[i] + " could not be deleted: " + e.message);
      }
    }
    if (agentId) {
      try {
        const d = await call("POST", API + "/spiffe/agents/delete",
                             { agent: agentId });
        if (d.status !== 200) {
          log.warn("The agent " + agentId + " was not deleted: " + d.status +
                   " " + d.text.slice(0, 200));
        }
      } catch (e) {
        log.debug("Caught in test(): " + ((e && e.message) || e));
        log.warn("The agent could not be deleted: " + e.message);
      }
    }
  }

  assert.ok(checks >= 55, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_spiffe_grpc")
  .description("The SPIFFE Workload API and SPIRE Server API over the " +
    "network: X509-SVIDs, bundles, JWT-SVIDs and their validation; the " +
    "Server API's anonymous, ordinary, forged, admin and agent callers; a " +
    "join token spent once; a ban and an admin entry's deletion taking " +
    "effect.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
