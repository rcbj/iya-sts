// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_proxy_protocol.js
//
// ---------------------------------------------------------------------------
// THE PROXY PROTOCOL V2 READER AND A CDN'S EDGES, ASKED OF A RUNNING NODE
// (#46, #1336).
//
// D12 (#444): carries over tests/proxy_protocol.js and tests/edge_secret.js.
// Both need the client address to be one the job chooses, which only a PROXY
// protocol header can do, so the job asks the service which mode it is in
// (`global.proxyProtocol` on `GET /admin-api/config`) and asserts that mode:
//
// WITH `global.proxyProtocol` OFF (every stack but one started for it):
//   * a connection that opens with a PROXY v2 header is not read as one —
//     the bytes reach TLS, and the handshake fails;
//   * the connection's own peer is the address `GET /admin-api/tls-connection`
//     reports;
//   * edge ranges that do not hold the job's own address ask nothing of it.
//
// WITH IT `v2`, and `STS_TEST_PROXY_PROTOCOL_DIRECT` (host:port) naming a
// way to the node that does NOT pass a balancer — the job's own trusted
// proxy is its own socket — every claim below is made on a connection the
// job opens there, writes a header on and runs TLS over:
//   1. THE PARSER: IPv4, IPv6 and LOCAL (the balancer's own address kept);
//      an AWS (0xEA) and an authority TLV read or ignored; a good CRC32C;
//      and each refusal closing the connection with its own code on the
//      default realm's audit — no signature (STS-PROXY-0002), version 1
//      (-0003), a bad version, command, family or transport, a short
//      address block and a TLV past the end (-0004), an oversize length
//      (-0005), a CRC32C that does not match (-0006), a header that never
//      finishes within `global.proxyProtocolTimeoutMs` (-0007), and one
//      closed part way (-0008);
//   3. THE ADDRESS REACHES THE READERS: `GET /admin-api/tls-connection`'s
//      peer and client address and the audit row's `address` are the
//      header's source, IPv6 included;
//   4. MUTUAL TLS IS UNAFFECTED: a client certificate presented in the
//      handshake that follows the header still verifies.
//   EDGE (tests/edge_secret.js; `global.edgeProxies` set here to
//   `198.51.100.0/24, not-a-range` and reset after):
//   * with STS_TEST_EDGE_SECRET unset (a service started with no
//     `global.edgeSecret`): every request from an edge is refused 403
//     (`Forbidden`, no-store, its own CSP), whatever header it carries,
//     an empty one included — a half-made deployment fails closed;
//   * with it set to what the service holds (plain or `sha256:<digest>`):
//     an edge with the secret passes, a wrong one and none are refused, an
//     IPv4-mapped edge too; a peer outside the ranges passes; `not-a-range`
//     is ignored, never widened (198.51.101.8 passes with a wrong secret).
//   * in every mode: no ranges configured asks nothing of anybody.
//
// What stays in process (class (d)): an untrusted address closed
// (STS-PROXY-0001) and a service with nobody trusted refusing to start
// (-0009) — the first needs a second source address, the second a start —
// and the header split at every byte boundary; the plain `net` listener's
// and ldapjs's socket (the KDC's and the bind limiter's readers); that
// `X-Origin-Verify` is gone from the request, which no answer echoes.
// STS-CORE-0165, the edge refusal's code, was marked before the call log and
// reached neither the audit nor the log until 2026-11-14; its row is asserted.
//
// OWNED HERE (local: true): this repository's own listeners and management
// API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const net = require("net");
const tls = require("tls");
const credentials = require("../tools/pep-credential.js");
const serviceTrust = require("../tools/service_trust.js");

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
var log = bunyan.createLogger({ name: "sts_proxy_protocol",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const TARGET = new URL(base);
const DIRECT = String(process.env.STS_TEST_PROXY_PROTOCOL_DIRECT ||
                      TARGET.hostname + ":" + (TARGET.port || 443));
const DIRECT_HOST = DIRECT.replace(/:\d+$/, "");
const DIRECT_PORT = Number((/:(\d+)$/.exec(DIRECT) || [])[1] || 443);
const EDGE_SECRET = process.env.STS_TEST_EDGE_SECRET;
const SIGNATURE = Buffer.from("0d0a0d0a000d0a515549540a", "hex");
const EDGE_RANGES = "198.51.100.0/24, not-a-range";

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
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// CRC32C (Castagnoli), for the 0x03 TLV.
function crc32c(buf) {
  log.debug("Entering crc32c().");
  let crc = 0xffffffff;
  for (const byte of buf) {
    crc ^= byte;
    for (let k = 0; k < 8; k += 1) {
      crc = (crc >>> 1) ^ (0x82f63b78 & -(crc & 1));
    }
  }
  log.debug("Leaving crc32c().");
  return (crc ^ 0xffffffff) >>> 0;
}

function ipv6Bytes(text) {
  log.debug("Entering ipv6Bytes().");
  let parts = String(text);
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(parts);
  if (v4) {
    parts = parts.slice(0, v4.index) +
      ((Number(v4[1]) << 8) | Number(v4[2])).toString(16) + ":" +
      ((Number(v4[3]) << 8) | Number(v4[4])).toString(16);
  }
  const halves = parts.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
  const words = left.concat(new Array(8 - left.length - right.length)
    .fill("0"), right);
  const out = Buffer.alloc(16);
  words.forEach(function (w, i) {
    out.writeUInt16BE(parseInt(w, 16), i * 2);
  });
  log.debug("Leaving ipv6Bytes().");
  return out;
}

// A PROXY V2 HEADER. `o`: command (0x1 PROXY, 0x0 LOCAL), version (2),
// family ('4', '6', 'unspec' or a raw byte), source, tlvs [{type, value}],
// crc ('good', 'bad' or none), length (to lie about the block's length).
function header(o) {
  log.debug("Entering header().");
  const version = o.version === undefined ? 2 : o.version;
  const command = o.command === undefined ? 1 : o.command;
  let fam = 0x11;
  let addr = Buffer.alloc(0);
  if (o.family === "6") {
    fam = 0x21;
    addr = Buffer.concat([ipv6Bytes(o.source || "2001:db8::7"),
                          ipv6Bytes("2001:db8::1"), Buffer.alloc(4)]);
    addr.writeUInt16BE(40000, 32);
    addr.writeUInt16BE(443, 34);
  } else if (o.family === "unspec") {
    fam = 0x00;
  } else if (typeof o.family === "number") {
    fam = o.family;
    addr = Buffer.alloc(12);
  } else {
    addr = Buffer.alloc(12);
    String(o.source || "203.0.113.9").split(".").forEach(function (b, i) {
      addr[i] = Number(b);
    });
    [192, 0, 2, 1].forEach(function (b, i) {
      addr[4 + i] = b;
    });
    addr.writeUInt16BE(40000, 8);
    addr.writeUInt16BE(443, 10);
  }
  const tlvParts = (o.tlvs || []).map(function (t) {
    const v = Buffer.from(t.value);
    const head = Buffer.alloc(3);
    head[0] = t.type;
    head.writeUInt16BE(t.length === undefined ? v.length : t.length, 1);
    return Buffer.concat([head, v]);
  });
  if (o.crc) {
    tlvParts.push(Buffer.from([0x03, 0x00, 0x04, 0, 0, 0, 0]));
  }
  if (o.shortBlock) {
    addr = addr.slice(0, 6);
  }
  let block = Buffer.concat([addr].concat(tlvParts));
  const fixed = Buffer.alloc(4);
  fixed[0] = (version << 4) | command;
  fixed[1] = fam;
  fixed.writeUInt16BE(o.length === undefined ? block.length : o.length, 2);
  let out = Buffer.concat([SIGNATURE, fixed, block]);
  if (o.crc) {
    const value = o.crc === "good" ? crc32c(out) : (crc32c(out) ^ 1) >>> 0;
    out.writeUInt32BE(value, out.length - 4);
  }
  log.debug("Leaving header().");
  return out;
}

// A CONNECTION TO THE NODE THAT BEGINS WITH `prefix`, then TLS, then one
// HTTP/1.1 request. Resolves { status, body, closedEarly, tlsError }.
function overHeader(prefix, request, tlsOptions) {
  log.debug("Entering overHeader().");
  log.debug("Leaving overHeader().");
  return new Promise(function (resolve) {
    const out = { status: 0, body: "", tlsError: null };
    const raw = net.connect({ host: DIRECT_HOST, port: DIRECT_PORT });
    let text = "";
    let done = false;
    const finish = function () {
      if (done) {
        return;
      }
      done = true;
      const m = /^HTTP\/1\.1 (\d{3})/.exec(text);
      out.status = m ? Number(m[1]) : 0;
      out.head = text.split("\r\n\r\n")[0];
      out.body = text.split("\r\n\r\n").slice(1).join("\r\n\r\n");
      resolve(out);
    };
    raw.on("error", function (e) {
      out.tlsError = out.tlsError || String((e && e.message) || e);
    });
    raw.on("connect", function () {
      if (prefix && prefix.length) {
        raw.write(prefix);
      }
      const s = tls.connect(Object.assign({ socket: raw,
        servername: TARGET.hostname, ca: serviceTrust.trustedCa(),
        ALPNProtocols: ["http/1.1"] }, tlsOptions || {}), function () {
        const r = request || {};
        const headers = Object.assign({ Host: TARGET.host,
          Connection: "close", Accept: "application/json" },
          r.headers || {});
        s.write((r.method || "GET") + " " + (r.path ||
          "/.well-known/openid-configuration") + " HTTP/1.1\r\n" +
          Object.keys(headers).map(function (k) {
            return k + ": " + headers[k];
          }).join("\r\n") + "\r\n\r\n");
      });
      s.setTimeout(15000, function () {
        s.destroy();
      });
      s.on("data", function (c) {
        text += c.toString("utf8");
      });
      s.on("error", function (e) {
        out.tlsError = String((e && e.message) || e);
      });
      s.on("close", finish);
    });
    raw.on("close", function () {
      setTimeout(finish, 50);
    });
  });
}

// Bytes on a connection and nothing after: resolves once the node closes it.
function raw(bytes, holdMs) {
  log.debug("Entering raw().");
  log.debug("Leaving raw().");
  return new Promise(function (resolve) {
    const sock = net.connect({ host: DIRECT_HOST, port: DIRECT_PORT });
    const t0 = Date.now();
    let read = 0;
    sock.on("connect", function () {
      sock.write(bytes);
      if (holdMs === "end") {
        sock.end();
      }
    });
    sock.on("data", function (c) {
      read += c.length;
    });
    sock.on("error", function () {});
    sock.setTimeout(20000, function () {
      sock.destroy();
    });
    sock.on("close", function () {
      resolve({ closedAfter: Date.now() - t0, read: read });
    });
  });
}

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const r = await fetch(base + path, {
    method: method,
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload) });
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving api(). " + r.status);
  return { status: r.status, body: body, raw: text };
}

async function setting(key) {
  log.debug("Entering setting(). " + key);
  const r = await api("GET", "/admin-api/config");
  let value;
  ((r.body && r.body.groups) || []).forEach(function (g) {
    (g.settings || []).forEach(function (row) {
      if (row.key === key) {
        value = row.value;
      }
    });
  });
  log.debug("Leaving setting().");
  return value;
}

async function codeRows(code) {
  log.debug("Entering codeRows(). " + code);
  const r = await api("GET", "/admin-api/audit?per=500&code=" +
                      encodeURIComponent(code));
  log.debug("Leaving codeRows().");
  return (r.body && (r.body.events || r.body.rows)) || [];
}

// A row for `code` recorded since `since` (ms). The PROXY refusals are
// audited once per code and address per minute, so a row from a run a few
// seconds earlier also counts: it is this node refusing the same thing.
async function sawRecent(code, since, slackMs) {
  log.debug("Entering sawRecent(). " + code);
  for (let i = 0; i < 30; i += 1) {
    const rows = await codeRows(code);
    if (rows.some(function (row) {
      return Number(row.at) >= since - (slackMs === undefined ? 70000
                                                                : slackMs);
    })) {
      log.debug("Leaving sawRecent(). Seen.");
      return true;
    }
    await sleep(200);
  }
  log.debug("Leaving sawRecent(). Not seen.");
  return false;
}

function tokenHeader() {
  log.debug("Entering tokenHeader().");
  log.debug("Leaving tokenHeader().");
  return { Authorization: "Bearer " + (process.env.STS_ADMIN_API_TOKEN || "") };
}

async function viewThrough(prefix, tlsOptions) {
  log.debug("Entering viewThrough().");
  const r = await overHeader(prefix, { path: "/admin-api/tls-connection",
                                       headers: tokenHeader() }, tlsOptions);
  assert.strictEqual(r.status, 200, "GET /admin-api/tls-connection over a " +
                     "header: " + r.status + " " + (r.tlsError || "") + " " +
                     r.body.slice(0, 200));
  log.debug("Leaving viewThrough().");
  return JSON.parse(r.body);
}

async function offMode() {
  log.debug("Entering offMode().");
  log.info("=== global.proxyProtocol is off ===");
  const tried = await overHeader(header({ source: "203.0.113.9" }));
  check("a connection that opens with a PROXY v2 header is not read as one: " +
        "TLS meets the bytes and the handshake fails", function () {
    assert.strictEqual(tried.status, 0, JSON.stringify(tried));
    assert.ok(tried.tlsError, JSON.stringify(tried));
  });
  const view = await api("GET", "/admin-api/tls-connection");
  check("the connection's own peer is the address reported", function () {
    assert.strictEqual(view.status, 200, view.raw.slice(0, 200));
    assert.ok(view.body.connection.peerAddress, view.raw.slice(0, 300));
    assert.notStrictEqual(view.body.connection.peerAddress, "203.0.113.9");
  });
  log.debug("Leaving offMode().");
}

async function parserClaims() {
  log.debug("Entering parserClaims().");
  log.info("=== 1 and 3. the parser, and the address it carries ===");
  const v4 = await viewThrough(header({ source: "203.0.113.9" }));
  check("IPv4: the header's source is the connection's peer and client " +
        "address", function () {
    assert.strictEqual(v4.connection.peerAddress, "203.0.113.9",
                       JSON.stringify(v4.connection));
    assert.strictEqual(v4.connection.clientAddress, "203.0.113.9",
                       JSON.stringify(v4.connection));
  });
  const v6 = await viewThrough(header({ family: "6",
                                        source: "2001:db8::7" }));
  check("IPv6: the same, for an IPv6 source", function () {
    assert.strictEqual(v6.connection.peerAddress, "2001:db8::7",
                       JSON.stringify(v6.connection));
  });
  const local = await viewThrough(header({ command: 0, family: "unspec" }));
  check("LOCAL (a balancer's health check) keeps the balancer's own " +
        "address", function () {
    assert.ok(local.connection.peerAddress &&
              local.connection.peerAddress !== "203.0.113.9",
              JSON.stringify(local.connection));
  });
  const tlvs = await viewThrough(header({ source: "203.0.113.10",
    tlvs: [{ type: 0xea, value: Buffer.from([0x01]).toString("latin1") +
                                "vpce-0123456789abcdef" },
           { type: 0x02, value: "sts.example.com" }],
    crc: "good" }));
  check("an AWS (0xEA) and an authority (0x02) TLV, and a good CRC32C, are " +
        "read and the request answered", function () {
    assert.strictEqual(tlvs.connection.peerAddress, "203.0.113.10",
                       JSON.stringify(tlvs.connection));
  });
  const since = Date.now();
  const refusals = [
    ["no PROXY signature from a trusted proxy", "STS-PROXY-0002",
     Buffer.from("GET / HTTP/1.1\r\nHost: x\r\n\r\n")],
    ["a version 1 (text) header", "STS-PROXY-0003",
     Buffer.from("PROXY TCP4 203.0.113.9 192.0.2.1 40000 443\r\n")],
    ["a bad version nibble", "STS-PROXY-0004", header({ version: 3 })],
    ["an unknown command", "STS-PROXY-0004", header({ command: 0x0f })],
    ["an unknown family or transport", "STS-PROXY-0004",
     header({ family: 0x31 })],
    ["an address block shorter than its family needs", "STS-PROXY-0004",
     header({ shortBlock: true })],
    ["a TLV running past the declared length", "STS-PROXY-0004",
     header({ tlvs: [{ type: 0x02, value: "abc", length: 40 }] })],
    ["a length over 4096", "STS-PROXY-0005", header({ length: 5000 })],
    ["a CRC32C that does not match", "STS-PROXY-0006",
     header({ crc: "bad" })]
  ];
  for (const one of refusals) {
    const r = await raw(one[2]);
    check(one[0] + " closes the connection before TLS", function () {
      assert.ok(r.closedAfter < 10000, JSON.stringify(r));
      assert.strictEqual(r.read, 0, "the node answered " + r.read +
                         " bytes rather than closing");
    });
  }
  const partial = await raw(header({}).slice(0, 10), "end");
  check("a header closed part way closes the connection", function () {
    assert.strictEqual(partial.read, 0, JSON.stringify(partial));
  });
  const set = await api("POST", "/admin-api/config/set",
                        { key: "global.proxyProtocolTimeoutMs", value: 500 });
  assert.strictEqual(set.status, 200, set.raw.slice(0, 200));
  let slow;
  try {
    slow = await raw(header({}).slice(0, 10));
  } finally {
    await api("POST", "/admin-api/config/reset",
              { key: "global.proxyProtocolTimeoutMs" });
  }
  check("a header that never finishes is closed after " +
        "global.proxyProtocolTimeoutMs", function () {
    assert.ok(slow.closedAfter >= 400 && slow.closedAfter < 10000,
              JSON.stringify(slow));
  });
  const wanted = ["STS-PROXY-0002", "STS-PROXY-0003", "STS-PROXY-0004",
                  "STS-PROXY-0005", "STS-PROXY-0006", "STS-PROXY-0007",
                  "STS-PROXY-0008"];
  for (const code of wanted) {
    const saw = await sawRecent(code, since);
    check("the refusal is on the audit as " + code, function () {
      assert.ok(saw, "no " + code + " row within the minute");
    });
  }
  const tagged = await overHeader(header({ source: "203.0.113.77" }),
    { path: "/no-such-path-proxy-" + since });
  assert.strictEqual(tagged.status, 404, JSON.stringify(tagged));
  let rowAddress = null;
  for (let i = 0; i < 20 && !rowAddress; i += 1) {
    const rows = await codeRows("STS-HTTP-0001");
    const row = rows.filter(function (one) {
      return String(one.target) === "/no-such-path-proxy-" + since;
    })[0];
    rowAddress = row ? row.address : null;
    if (!rowAddress) {
      await sleep(200);
    }
  }
  check("the audit row of a request over a header names the header's " +
        "source as its address", function () {
    assert.strictEqual(rowAddress, "203.0.113.77");
  });
  log.debug("Leaving parserClaims().");
}

async function mutualTls() {
  log.debug("Entering mutualTls().");
  log.info("=== 4. mutual TLS behind a header ===");
  const cred = await credentials.mint({
    subject: "CN=proxy-mtls-" + Date.now() + ",O=iya-sts tests" });
  const added = [];
  try {
    const answer = await credentials.trustRecorded(base, cred.anchorPem,
                                                   added);
    assert.ok(answer.ok, JSON.stringify(answer).slice(0, 300));
    let view = {};
    for (let i = 0; i < 40; i += 1) {
      view = await viewThrough(header({ source: "203.0.113.11" }),
                               { cert: cred.certPem, key: cred.keyPem });
      if (view.clientCertificate && view.clientCertificate.verified) {
        break;
      }
      await sleep(500);
    }
    check("a client certificate in the handshake behind the header still " +
          "verifies, and the address is still the header's", function () {
      assert.strictEqual(view.clientCertificate.presented, true,
                         JSON.stringify(view.clientCertificate));
      assert.strictEqual(view.clientCertificate.verified, true,
                         JSON.stringify(view.clientCertificate));
      assert.strictEqual(view.connection.peerAddress, "203.0.113.11");
    });
  } finally {
    await credentials.removeAnchor(base, cred.anchorPem);
  }
  log.debug("Leaving mutualTls().");
}

async function edgeClaims() {
  log.debug("Entering edgeClaims().");
  log.info("=== the edge (tests/edge_secret.js) ===");
  const from = function (source, secret) {
    const headers = {};
    if (secret !== undefined) {
      headers["X-Origin-Verify"] = secret;
    }
    const family = source.indexOf(":") >= 0 ? "6" : "4";
    return overHeader(header({ family: family, source: source }),
                      { headers: headers });
  };
  const none = await from("198.51.100.7");
  check("no ranges configured: an edge address is asked nothing", function () {
    assert.strictEqual(none.status, 200, JSON.stringify(none));
  });
  const set = await api("POST", "/admin-api/config/set",
                        { key: "global.edgeProxies", value: EDGE_RANGES });
  assert.strictEqual(set.status, 200, set.raw.slice(0, 300));
  try {
    const since = Date.now();
    if (EDGE_SECRET === undefined) {
      const anything = await from("198.51.100.7", "anything");
      const empty = await from("198.51.100.7", "");
      check("ranges and no secret refuse every edge, an empty header " +
            "included: a half-made deployment fails closed (403)",
            function () {
        assert.strictEqual(anything.status, 403, JSON.stringify(anything));
        assert.strictEqual(empty.status, 403, JSON.stringify(empty));
        assert.ok(/Forbidden/.test(anything.body), anything.body);
      });
    } else {
      const good = await from("198.51.100.7", EDGE_SECRET);
      const wrong = await from("198.51.100.7", "wrong");
      const missing = await from("198.51.100.7");
      const mapped = await from("::ffff:198.51.100.7");
      const outside = await from("203.0.113.9");
      const notRange = await from("198.51.100.8", "wrong");
      const notWidened = await from("198.51.101.8", "wrong");
      check("an edge with the secret passes; a wrong one, none, and an " +
            "IPv4-mapped edge without it are refused 403", function () {
        assert.strictEqual(good.status, 200, JSON.stringify(good));
        assert.strictEqual(wrong.status, 403, JSON.stringify(wrong));
        assert.strictEqual(missing.status, 403, JSON.stringify(missing));
        assert.strictEqual(mapped.status, 403, JSON.stringify(mapped));
        assert.ok(/^Forbidden/.test(wrong.body), wrong.body);
        assert.ok(/cache-control: no-store/i.test(wrong.head), wrong.head);
        assert.ok(/frame-ancestors 'none'/i.test(wrong.head), wrong.head);
      });
      check("a peer outside the ranges is not claiming to be an edge, and " +
            "a value that is not a range is ignored, never widened",
            function () {
        assert.strictEqual(outside.status, 200, JSON.stringify(outside));
        assert.strictEqual(notRange.status, 403, JSON.stringify(notRange));
        assert.strictEqual(notWidened.status, 200,
                           JSON.stringify(notWidened));
      });
    }
    // A NODE DEFECT, FIXED (2026-11-14, #444's D12): STS-CORE-0165 was
    // marked above the call log and reached neither the audit nor the log.
    // It writes its own row now, as its siblings do.
    const audited = await sawRecent("STS-CORE-0165", since, 2000);
    check("each refusal is on the audit log as STS-CORE-0165", function () {
      assert.ok(audited, "no STS-CORE-0165 row since " + since);
    });
    log.debug("Edge probes from " + since + " done.");
  } finally {
    await api("POST", "/admin-api/config/reset",
              { key: "global.edgeProxies" });
  }
  log.debug("Leaving edgeClaims().");
}

async function test() {
  log.debug("Entering test().");
  const mode = await setting("global.proxyProtocol");
  log.info("global.proxyProtocol is " + mode + "; the node is dialled " +
           "directly at " + DIRECT);
  if (String(mode) !== "v2") {
    await offMode();
    const set = await api("POST", "/admin-api/config/set",
                          { key: "global.edgeProxies", value: EDGE_RANGES });
    assert.strictEqual(set.status, 200, set.raw.slice(0, 300));
    try {
      const mine = await api("GET", "/.well-known/openid-configuration");
      check("edge ranges that do not hold this job's address ask nothing " +
            "of it", function () {
        assert.strictEqual(mine.status, 200, mine.raw.slice(0, 200));
      });
    } finally {
      await api("POST", "/admin-api/config/reset",
                { key: "global.edgeProxies" });
    }
    log.info("[not exercised] the parser, the address readers and the " +
             "edge: they need global.proxyProtocol=v2 and " +
             "STS_TEST_PROXY_PROTOCOL_DIRECT.");
  } else {
    assert.ok(process.env.STS_TEST_PROXY_PROTOCOL_DIRECT,
              "global.proxyProtocol is v2, so the job needs " +
              "STS_TEST_PROXY_PROTOCOL_DIRECT: a way to the node that does " +
              "not pass the balancer");
    await parserClaims();
    await mutualTls();
    await edgeClaims();
  }
  log.info("sts_proxy_protocol: " + checks + " checks passed.");
  log.debug("Leaving test().");
}

test().then(function () {
  log.info("Test completed successfully.");
}).catch(function (e) {
  log.error("sts_proxy_protocol FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
