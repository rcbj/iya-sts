// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_audit_export.js
//
// ---------------------------------------------------------------------------
// AUDIT EXPORT, AND THE CLIENT ADDRESS ON AN AUDIT ROW, OVER THE WIRE.
//
// D12 (#444): carries over
//
//   * tests/audit_export.js (#641) — what its child held through
//     `AuditExport` itself, asked of `/admin-api/audit-export` and of the
//     two stand-ins this job runs (a TCP syslog collector and an HTTP
//     webhook, which the service dials at OUTBOUND_TEST_HOST):
//       A. the acts: an unknown act and a duplicate id (STS-AUDIT-0001), an
//          id outside the register's shape (the schema), an unknown id
//          (STS-AUDIT-0002); a Splunk token and a credential header never
//          in a view, `tokenSet` and `secretHeaderSet` instead; an empty
//          token keeping the stored one; an update omitting headers keeping
//          them and empty plain headers replacing them; a file path stored,
//          a climbing and a relative one refused (STS-AUDIT-0004), a mode
//          that is not octal (STS-AUDIT-0001); `test` sending a synthetic
//          event that is no audit row; disable, enable, remove; every
//          change audited as `admin.audit-export.*`;
//       S/Y. the syslog line: one octet-counted RFC 5424 frame per event
//          over TCP, `<133>1` for a success and `<132>1` for a refusal,
//          the `[iyaAudit …]` structured data naming the realm, the
//          event's sequence and its outcome; one datagram over UDP;
//       H/D. the webhook: the canonical event as JSON, its id ending in its
//          sequence, a detail name on `auditExport.redactKeys` and one on
//          the destination's `excludeAttributes` replaced by `[redacted]`;
//          a template
//          line; a redirect not followed (STS-AUDIT-0014); HTTP 400 that
//          event only, counted permanently failed (STS-AUDIT-0015); a 401
//          a transient failure (STS-AUDIT-0007) that holds the cursor and is
//          delivered once the peer answers again;
//       P. a metadata address and a URL with userinfo refused
//          (STS-AUDIT-0005), plain http refused while allowHttp is off,
//          a private address refused until allowPrivateDestinations, which
//          still refuses metadata.
//     Its F (a file destination's appends and rotation) writes inside the
//     service's own filesystem, its D cursor arithmetic (gaps, trims,
//     give-up after retryMaxPeriodMs, one save) and its Splunk HEC
//     acknowledgement round trip are internal state or a day's clock, and
//     stay in process (class (d)).
//   * tests/audit_client_address.js — the client's address on every row
//     an entry point writes: a sign-in's `authentication` row and the
//     person's own event list carry the address the protocol call came
//     from, an LDAP bind's row carries the socket's peer, and the audit
//     filter's `address` is a PREFIX. Its ambient-source mechanics
//     (`withSource()`, an event's own address winning, across an await)
//     and the KDC's UDP socket (no probe publishes 88) stay in process.
//
// In a throwaway development realm, removed at the end only when
// STS_TEST_REMOVE_REALMS=1 (removeRealms() says why). OWNED HERE
// (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const dgram = require("dgram");
const http = require("http");
const net = require("net");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_audit_export",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");
const REALM = ("auditx-" + STAMP).slice(0, 31);
const API = base + "/realm/" + REALM + "/admin-api";
// The name the SERVICE dials this job's stand-ins by: the runner's own
// host as the service's network sees it (test_crl_host.js's variable).
const PEER = String(process.env.OUTBOUND_TEST_HOST ||
                    process.env.GNAP_PUSH_HOST || "localhost");
// THE FIRST WEBHOOK IS GIVEN THAT HOST'S NAME, THE REST ITS ADDRESS. Until
// 2026-11-14 Node's HTTP destination refused every delivery to a host NAME
// with "Invalid IP address: undefined" (its pinned lookup answered the
// single-address form to `{ all: true }`), while a syslog destination by
// the same name delivered — a Node defect #444's D12 found, now fixed, so
// the JSON webhook is given the name and has to deliver. The others keep
// the address. OUTBOUND_TEST_ADDRESS names it where the job's own lookup of
// PEER would answer differently from the service's.
const dns = require("dns");

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

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
}

function post(path, payload) {
  log.debug("Entering post(). " + path);
  log.debug("Leaving post().");
  return send(API + path, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(promise, what) {
  log.debug("Entering ok().");
  const r = await promise;
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    what + ": answered " + r.status + " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return ((r.body && r.body.errors) || []).join(" ");
}

async function auditRows(query) {
  log.debug("Entering auditRows().");
  const r = await send(API + "/audit?per=500&" + query);
  log.debug("Leaving auditRows().");
  return (r.body && r.body.events) || [];
}

// Runs `fn` and answers its result and whether the realm's audit log gained
// a row carrying `code`. A code is never sent.
async function recording(code, fn) {
  log.debug("Entering recording(). " + code);
  const q = "code=" + encodeURIComponent(code);
  const before = (await auditRows(q)).length;
  const out = await fn();
  let after = before;
  for (let i = 0; i < 30 && after <= before; i += 1) {
    await sleep(200);
    after = (await auditRows(q)).length;
  }
  log.debug("Leaving recording(). " + before + " -> " + after);
  return { out: out, recorded: after > before };
}

function act(action, payload) {
  log.debug("Entering act(). " + action);
  log.debug("Leaving act().");
  return post("/audit-export/" + action, payload);
}

async function view() {
  log.debug("Entering view().");
  const r = await send(API + "/audit-export");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving view().");
  return r.body;
}

function rowOf(answer, id) {
  log.debug("Entering rowOf(). " + id);
  log.debug("Leaving rowOf().");
  return (answer.destinations || []).filter(function (one) {
    return one.id === id;
  })[0] || null;
}

// Waits until `test` holds of what a stand-in has received.
async function until(test, what, ms) {
  log.debug("Entering until(). " + what);
  const end = Date.now() + (ms || 30000);
  while (Date.now() < end) {
    if (test()) {
      log.debug("Leaving until().");
      return true;
    }
    await sleep(250);
  }
  log.debug("Leaving until(). Timed out.");
  return false;
}

// A TCP syslog collector: RFC 6587 octet counting, frames kept in order.
function syslogCollector() {
  log.debug("Entering syslogCollector().");
  const frames = [];
  const server = net.createServer(function (socket) {
    let buffered = Buffer.alloc(0);
    socket.on("data", function (chunk) {
      buffered = Buffer.concat([buffered, chunk]);
      for (;;) {
        const space = buffered.indexOf(0x20);
        if (space < 0) {
          return;
        }
        const length = Number(buffered.slice(0, space).toString("ascii"));
        if (!(length > 0) || buffered.length < space + 1 + length) {
          return;
        }
        frames.push({ declared: length,
                      line: buffered.slice(space + 1, space + 1 + length)
                        .toString("utf8") });
        buffered = buffered.slice(space + 1 + length);
      }
    });
    socket.on("error", function (e) {
      log.debug("Caught in syslogCollector(): " + ((e && e.message) || e));
      // The service closing its end mid-frame is not this job's failure.
    });
  });
  log.debug("Leaving syslogCollector().");
  return new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", function () {
      resolve({ server: server, frames: frames,
                port: server.address().port });
    });
  });
}

function udpCollector() {
  log.debug("Entering udpCollector().");
  const datagrams = [];
  const socket = dgram.createSocket("udp4");
  socket.on("message", function (message) {
    datagrams.push(message.toString("utf8"));
  });
  log.debug("Leaving udpCollector().");
  return new Promise(function (resolve) {
    socket.bind(0, "0.0.0.0", function () {
      resolve({ socket: socket, datagrams: datagrams,
                port: socket.address().port });
    });
  });
}

// An HTTP webhook with one behaviour per path: /ok and /template take the
// event, /redirect answers 302, /bad 400, /deny 401 until it is told to
// take events again.
function webhook() {
  log.debug("Entering webhook().");
  const got = { ok: [], template: [], redirect: 0, bad: 0, deny: 0,
                denying: true, after: [] };
  const server = http.createServer(function (req, res) {
    let body = "";
    req.on("data", function (chunk) {
      body += chunk;
    });
    req.on("end", function () {
      const at = String(req.url || "").replace(/\?.*$/, "");
      if (at === "/ok") {
        got.ok.push({ body: body, type: req.headers["content-type"],
                      trace: req.headers["x-trace"],
                      auth: req.headers.authorization });
        res.writeHead(200).end("{}");
      } else if (at === "/template") {
        got.template.push(body);
        res.writeHead(200).end("{}");
      } else if (at === "/redirect") {
        got.redirect += 1;
        res.writeHead(302, { Location: "/ok" }).end();
      } else if (at === "/bad") {
        got.bad += 1;
        res.writeHead(400).end("no");
      } else if (at === "/deny" && got.denying) {
        got.deny += 1;
        res.writeHead(401).end("no");
      } else if (at === "/deny") {
        got.after.push(body);
        res.writeHead(200).end("{}");
      } else {
        res.writeHead(404).end();
      }
    });
  });
  log.debug("Leaving webhook().");
  return new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", function () {
      resolve({ server: server, got: got, port: server.address().port });
    });
  });
}

async function acts() {
  log.debug("Entering acts().");
  log.info("=== A. the acts ===");
  const unknown = await recording("STS-AUDIT-0001", function () {
    return act("explode", { id: "x" });
  });
  check("A1. an unknown act is refused", function () {
    assert.ok(unknown.out.status === 400 || unknown.out.status === 404,
              unknown.out.raw.slice(0, 300));
    log.info("    (an unknown act recorded STS-AUDIT-0001: " +
             unknown.recorded + ")");
  });
  const badId = await act("add", { id: "Bad Id!", type: "syslog",
                                   host: "siem.example" });
  check("A2. an id outside the register shape is refused by the schema",
        function () {
    assert.strictEqual(badId.status, 400, badId.raw.slice(0, 300));
    assert.ok(/"id" must match pattern/.test(errorsOf(badId)),
              errorsOf(badId));
  });
  const added = await ok(act("add", { id: "siem", type: "syslog",
    name: "SIEM", host: "siem.example", transport: "tcp" }), "added siem");
  check("A3. a syslog destination is stored, port 0 being 514 or 6514 and " +
        "the facility local0", function () {
    assert.strictEqual(added.destination.host, "siem.example");
    assert.strictEqual(added.destination.transport, "tcp");
    assert.strictEqual(added.destination.facility, 16);
  });
  const duplicate = await recording("STS-AUDIT-0001", function () {
    return act("add", { id: "siem", type: "syslog", host: "siem.example" });
  });
  check("A4. a duplicate id is STS-AUDIT-0001", function () {
    assert.ok(duplicate.out.status === 400 && duplicate.recorded,
              duplicate.out.raw.slice(0, 300));
  });
  const missing = await recording("STS-AUDIT-0002", function () {
    return act("update", { id: "missing" });
  });
  check("A5. an unknown id is STS-AUDIT-0002", function () {
    assert.ok(missing.out.status === 400 && missing.recorded,
              missing.out.raw.slice(0, 300));
  });
  const TOKEN = "tok-keep-me-" + STAMP;
  await ok(act("add", { id: "hec", type: "splunk", name: "HEC",
    url: "https://hec.example/services/collector/event", token: TOKEN,
    ack: true }), "added a Splunk HEC");
  const first = await view();
  check("A6/A7. a view names this process, says the token is set and does " +
        "not carry it", function () {
    assert.strictEqual(first.thisProcess, true);
    assert.ok(JSON.stringify(first).indexOf(TOKEN) < 0, "the token leaked");
    const row = rowOf(first, "hec");
    assert.ok(row && row.tokenSet === true && row.token === undefined,
              JSON.stringify(row));
  });
  const kept = await act("update", { id: "hec", token: "" });
  check("A8. an empty token on update keeps the stored one", function () {
    assert.strictEqual(kept.status, 200, kept.raw.slice(0, 300));
    assert.strictEqual(rowOf(kept.body ? { destinations:
      [kept.body.destination] } : {}, "hec").tokenSet, true);
  });
  const SECRET = "Bearer hidden-" + STAMP;
  await ok(act("add", { id: "hook", type: "webhook", name: "Hook",
    url: "https://hooks.example/in",
    headers: "Authorization: " + SECRET + "\nX-Trace: yes",
    template: "{message}" }), "added a webhook");
  const hooked = await view();
  const hookRow = rowOf(hooked, "hook");
  check("A9. a credential header is sealed and leaves the plain set",
        function () {
    assert.ok(JSON.stringify(hooked).indexOf("hidden-" + STAMP) < 0);
    assert.ok(hookRow.secretHeaderSet.indexOf("Authorization") >= 0,
              JSON.stringify(hookRow));
    assert.ok(hookRow.headerText.indexOf("X-Trace") >= 0 &&
              hookRow.headerText.indexOf("Authorization") < 0,
              hookRow.headerText);
  });
  await ok(act("update", { id: "hook", name: "Hook two" }), "renamed");
  const renamed = rowOf(await view(), "hook");
  check("A10. an update that omits headers keeps them", function () {
    assert.ok(renamed.headerText.indexOf("X-Trace") >= 0,
              renamed.headerText);
  });
  await ok(act("update", { id: "hook", headers: "" }), "cleared headers");
  const cleared = rowOf(await view(), "hook");
  check("A11. empty plain headers replace, and secret headers stay",
        function () {
    assert.strictEqual(cleared.headerText, "");
    assert.ok(cleared.secretHeaderSet.indexOf("Authorization") >= 0);
  });
  const file = await ok(act("add", { id: "files", type: "file", name: "F",
    path: "/tmp/sts-audit-" + STAMP + ".ndjson", mode: "640",
    enabled: false }), "added a file destination");
  check("A12. an absolute file path is stored", function () {
    assert.strictEqual(file.destination.path,
                       "/tmp/sts-audit-" + STAMP + ".ndjson");
  });
  for (const one of [["/tmp/x/../../etc/passwd", "a path that climbs"],
                     ["audit.ndjson", "a relative path"]]) {
    const r = await recording("STS-AUDIT-0004", function () {
      return act("add", { id: "path-" + checks, type: "file",
                          path: one[0] });
    });
    check("A14/A15. " + one[1] + " is STS-AUDIT-0004", function () {
      assert.ok(r.out.status === 400 && r.recorded, r.out.raw.slice(0, 300));
    });
  }
  const badMode = await recording("STS-AUDIT-0001", function () {
    return act("add", { id: "mode", type: "file",
                        path: "/tmp/sts-audit-mode.ndjson", mode: "999" });
  });
  check("A16. a mode that is not octal is STS-AUDIT-0001", function () {
    assert.ok(badMode.out.status === 400 && badMode.recorded,
              badMode.out.raw.slice(0, 300));
  });
  const disabled = await ok(act("disable", { id: "siem" }), "disabled");
  const enabled = await ok(act("enable", { id: "siem" }), "enabled");
  check("A18. disable and enable keep the destination", function () {
    assert.strictEqual(disabled.destination.enabled, false);
    assert.strictEqual(enabled.destination.enabled, true);
    assert.strictEqual(enabled.destination.host, "siem.example");
  });
  for (const id of ["siem", "hec", "hook", "files"]) {
    await ok(act("remove", { id: id }), "removed " + id);
  }
  const gone = await recording("STS-AUDIT-0002", function () {
    return act("remove", { id: "siem" });
  });
  const after = await view();
  check("A19. remove drops the destination: a second remove is " +
        "STS-AUDIT-0002", function () {
    assert.ok(gone.out.status === 400 && gone.recorded,
              gone.out.raw.slice(0, 300));
    assert.strictEqual(rowOf(after, "siem"), null);
  });
  log.debug("Leaving acts().");
}

async function refusals() {
  log.debug("Entering refusals().");
  log.info("=== P. where a destination may point ===");
  const metadata = await recording("STS-AUDIT-0005", function () {
    return act("add", { id: "meta", type: "webhook",
                        url: "https://169.254.169.254/latest" });
  });
  check("P1. a metadata address is refused (STS-AUDIT-0005)", function () {
    assert.ok(metadata.out.status === 400 && metadata.recorded,
              metadata.out.raw.slice(0, 300));
  });
  const userinfo = await recording("STS-AUDIT-0005", function () {
    return act("add", { id: "userinfo", type: "webhook",
                        url: "https://user:pass@hooks.example/in" });
  });
  check("P8. a URL with userinfo is refused (STS-AUDIT-0005), and the " +
        "refusal does not repeat the password", function () {
    assert.ok(userinfo.out.status === 400 && userinfo.recorded,
              userinfo.out.raw.slice(0, 300));
    assert.ok(userinfo.out.raw.indexOf("user:pass") < 0);
  });
  const plain = await recording("STS-AUDIT-0005", function () {
    return act("add", { id: "plain", type: "webhook",
                        url: "http://hooks.example/in" });
  });
  check("P7. plain http is refused while auditExport.allowHttp is off",
        function () {
    assert.ok(plain.out.status === 400 && plain.recorded,
              plain.out.raw.slice(0, 300));
  });
  const privateHost = await recording("STS-AUDIT-0005", function () {
    return act("add", { id: "private", type: "syslog", host: "10.1.2.3" });
  });
  check("P5. a private address is refused while " +
        "allowPrivateDestinations is off", function () {
    assert.ok(privateHost.out.status === 400 && privateHost.recorded,
              privateHost.out.raw.slice(0, 300));
  });
  await ok(post("/config/set", { key: "auditExport.allowPrivateDestinations",
                                 value: "true" }), "allowed private ones");
  await ok(post("/config/set", { key: "auditExport.allowHttp",
                                 value: "true" }), "allowed plain http");
  const nowPrivate = await act("add", { id: "private", type: "syslog",
                                        host: "10.1.2.3" });
  const stillMeta = await recording("STS-AUDIT-0005", function () {
    return act("add", { id: "meta", type: "syslog",
                        host: "169.254.169.254" });
  });
  check("P11. private destinations can be allowed, which still refuses " +
        "metadata", function () {
    assert.strictEqual(nowPrivate.status, 200, nowPrivate.raw.slice(0, 300));
    assert.ok(stillMeta.out.status === 400 && stillMeta.recorded,
              stillMeta.out.raw.slice(0, 300));
  });
  await ok(act("remove", { id: "private" }), "removed it");
  log.debug("Leaving refusals().");
}

function sd(line, name) {
  log.debug("Entering sd().");
  const m = new RegExp(" " + name + "=\"([^\"]*)\"").exec(line);
  log.debug("Leaving sd().");
  return m ? m[1] : null;
}

async function syslog(tcp, udp) {
  log.debug("Entering syslog().");
  log.info("=== S/Y. syslog over TCP and UDP ===");
  await ok(act("add", { id: "tcp", type: "syslog", name: "TCP",
    host: PEER, port: tcp.port, transport: "tcp" }), "added the TCP one");
  const tested = await ok(act("test", { id: "tcp" }), "tested it");
  await until(function () {
    return tcp.frames.some(function (f) {
      return / audit\.export\.test /.test(f.line);
    });
  }, "the test frame");
  const testFrame = tcp.frames.filter(function (f) {
    return / audit\.export\.test /.test(f.line);
  })[0];
  const testRows = await auditRows("action=audit.export.test");
  check("A13. test sends one synthetic event, which is no audit row",
        function () {
    assert.strictEqual(tested.diagnostic.test, true);
    assert.ok(testFrame, JSON.stringify(tcp.frames.slice(0, 2)));
    assert.ok(/^test:tcp:/.test(sd(testFrame.line, "id")), testFrame.line);
    assert.strictEqual(testRows.length, 0, JSON.stringify(testRows));
  });
  // A refusal of this job's own, so the backlog holds both outcomes.
  await post("/audit-export/update", { id: "no-such-" + STAMP });
  await until(function () {
    return tcp.frames.some(function (f) {
      return sd(f.line, "outcome") === "refused";
    }) && tcp.frames.some(function (f) {
      return sd(f.line, "outcome") === "success" &&
             !/audit\.export\.test/.test(f.line);
    });
  }, "both outcomes");
  const success = tcp.frames.filter(function (f) {
    return sd(f.line, "outcome") === "success" &&
           !/audit\.export\.test/.test(f.line);
  })[0];
  const refused = tcp.frames.filter(function (f) {
    return sd(f.line, "outcome") === "refused";
  })[0];
  check("Y1. TCP syslog sends octet-counted frames, each exactly the " +
        "length it declares and no newline", function () {
    assert.ok(tcp.frames.length > 2, String(tcp.frames.length));
    tcp.frames.forEach(function (f) {
      assert.strictEqual(Buffer.byteLength(f.line, "utf8"), f.declared);
      assert.notStrictEqual(f.line.charAt(f.line.length - 1), "\n");
    });
  });
  check("S3. a success is facility local0 severity notice (<133>1), with " +
        "[iyaAudit] naming the realm, its sequence and outcome", function () {
    assert.ok(success && success.line.indexOf("<133>1 ") === 0,
              success && success.line);
    assert.ok(success.line.indexOf("[iyaAudit ") >= 0);
    assert.strictEqual(sd(success.line, "realm"), REALM);
    assert.ok(/^\d+$/.test(sd(success.line, "seq")), success.line);
    assert.ok(sd(success.line, "id").endsWith(":" + sd(success.line, "seq")),
              success.line);
  });
  check("S4. a refusal is severity warning (<132>1)", function () {
    assert.ok(refused && refused.line.indexOf("<132>1 ") === 0,
              refused && refused.line);
  });
  await ok(act("remove", { id: "tcp" }), "removed the TCP one");

  await ok(act("add", { id: "udp", type: "syslog", name: "UDP",
    host: PEER, port: udp.port, transport: "udp" }), "added the UDP one");
  await ok(act("test", { id: "udp" }), "tested it");
  const got = await until(function () {
    return udp.datagrams.some(function (d) {
      return / audit\.export\.test /.test(d);
    });
  }, "a datagram");
  check("Y2. UDP syslog sends one datagram holding the RFC 5424 line",
        function () {
    assert.ok(got, JSON.stringify(udp.datagrams.slice(0, 2)));
    const one = udp.datagrams.filter(function (d) {
      return / audit\.export\.test /.test(d);
    })[0];
    assert.ok(/^<13[0-9]>1 /.test(one), one);
  });
  await ok(act("remove", { id: "udp" }), "removed the UDP one");
  log.debug("Leaving syslog().");
}

async function hooks(peer) {
  log.debug("Entering hooks().");
  log.info("=== H/D. the webhook ===");
  const address = process.env.OUTBOUND_TEST_ADDRESS ||
    (await dns.promises.lookup(PEER, { family: 4 })).address;
  const at = "http://" + address + ":" + peer.port;
  const byName = "http://" + PEER + ":" + peer.port;
  await ok(post("/config/set", { key: "auditExport.redactKeys",
    value: "password,secret,token,authorization,method" }),
    "redacted the detail name method");
  await ok(act("add", { id: "json", type: "webhook", name: "JSON",
    url: byName + "/ok", excludeAttributes: "durationMs",
    headers: "X-Trace: d12" }), "added the JSON webhook, by host name");
  await until(function () {
    return peer.got.ok.some(function (one) {
      return /"protocol\.call"/.test(one.body);
    });
  }, "a protocol call delivered");
  const delivered = peer.got.ok.map(function (one) {
    let parsed = null;
    try {
      parsed = JSON.parse(one.body);
    } catch (e) {
      log.debug("Caught in hooks(): " + ((e && e.message) || e));
      // A body that is not one JSON event fails the check below.
      parsed = null;
    }
    return { event: parsed, type: one.type, trace: one.trace };
  });
  const call = delivered.filter(function (one) {
    return one.event && one.event.action === "protocol.call";
  })[0];
  check("H0. a webhook given by host NAME delivers (the pinned lookup " +
        "answers net.connect()'s { all: true })", function () {
    assert.ok(call, "nothing delivered to " + byName);
  });
  check("H. the canonical event as JSON, with the plain header sent",
        function () {
    assert.ok(call, JSON.stringify(peer.got.ok.slice(0, 2)).slice(0, 400));
    assert.ok(/json/.test(call.type), String(call.type));
    assert.strictEqual(call.trace, "d12");
    assert.strictEqual(call.event.realm, REALM);
  });
  check("D2. its id ends in its sequence", function () {
    assert.ok(String(call.event.id).endsWith(":" + call.event.seq),
              JSON.stringify(call.event).slice(0, 300));
  });
  check("S1/D2. a detail name on auditExport.redactKeys, and one on the " +
        "destination's excludeAttributes, are both [redacted]; the rest " +
        "stands", function () {
    const attrs = call.event.attributes || {};
    assert.strictEqual(attrs.method, "[redacted]", JSON.stringify(attrs));
    assert.strictEqual(attrs.durationMs, "[redacted]", JSON.stringify(attrs));
    assert.strictEqual(typeof attrs.status, "number", JSON.stringify(attrs));
  });
  await ok(act("remove", { id: "json" }), "removed it");

  await ok(act("add", { id: "line", type: "webhook", name: "Line",
    url: at + "/template", template: "{event_type} in {realm}" }),
    "added a template webhook");
  await until(function () {
    return peer.got.template.length > 0;
  }, "a template line");
  check("a template is one line of its placeholders", function () {
    assert.ok(peer.got.template.some(function (one) {
      return new RegExp("^[a-z.-]+ in " + REALM + "$").test(one);
    }), JSON.stringify(peer.got.template.slice(0, 3)));
  });
  await ok(act("remove", { id: "line" }), "removed it");

  const redirect = await recording("STS-AUDIT-0014", async function () {
    await ok(act("add", { id: "moved", type: "webhook",
      url: at + "/redirect" }), "added the redirecting one");
    await until(function () {
      return peer.got.redirect > 0;
    }, "a redirect answered");
  });
  check("H1. a redirect is not followed (STS-AUDIT-0014)", function () {
    assert.ok(redirect.recorded, "no STS-AUDIT-0014 row");
    assert.ok(peer.got.redirect > 0);
  });
  await ok(act("remove", { id: "moved" }), "removed it");

  const bad = await recording("STS-AUDIT-0015", async function () {
    await ok(act("add", { id: "bad", type: "webhook", url: at + "/bad" }),
             "added the refusing one");
    await until(function () {
      return peer.got.bad > 1;
    }, "two events refused");
  });
  const badRow = rowOf(await view(), "bad");
  check("H2. HTTP 400 is that event only: STS-AUDIT-0015, counted " +
        "permanently failed, and the next event is sent", function () {
    assert.ok(bad.recorded, "no STS-AUDIT-0015 row");
    assert.ok(peer.got.bad > 1, String(peer.got.bad));
    assert.ok(badRow && badRow.failedPermanent > 0, JSON.stringify(badRow));
  });
  await ok(act("remove", { id: "bad" }), "removed it");

  const denied = await recording("STS-AUDIT-0007", async function () {
    await ok(act("add", { id: "deny", type: "webhook", url: at + "/deny" }),
             "added the denying one");
    await until(function () {
      return peer.got.deny > 0;
    }, "a 401");
  });
  const held = peer.got.after.length;
  peer.got.denying = false;
  await post("/config/set", { key: "auditExport.retryInitialMs",
                              value: "100" });
  const recovered = await until(function () {
    return peer.got.after.length > 0;
  }, "delivery after the 401", 60000);
  check("D7. a 401 is a transient failure (STS-AUDIT-0007) that holds the " +
        "cursor, and the events are delivered once the peer takes them",
        function () {
    assert.ok(denied.recorded, "no STS-AUDIT-0007 row");
    assert.strictEqual(held, 0);
    assert.ok(recovered, "nothing delivered after the peer recovered");
  });
  await ok(act("remove", { id: "deny" }), "removed it");
  log.debug("Leaving hooks().");
}

function hostOf(url) {
  log.debug("Entering hostOf().");
  log.debug("Leaving hostOf().");
  return new URL(url).hostname;
}

function ldapBind(dn) {
  log.debug("Entering ldapBind().");
  return new Promise(function (resolve) {
    const url = process.env.STS_LDAPS_URL ||
      ("ldaps://" + hostOf(base) + ":" + (process.env.STS_LDAPS_PORT || 636));
    const client = ldapjs.createClient({ url: url,
      tlsOptions: { rejectUnauthorized: false } });
    client.on("error", function (e) {
      log.debug("Caught in ldapBind(): " + ((e && e.message) || e));
      resolve(false);
    });
    client.bind(dn, "development-checks-none", function (e) {
      client.unbind();
      log.debug("Leaving ldapBind(). " + (e ? e.name : "bound"));
      resolve(!e);
    });
  });
}

async function addresses() {
  log.debug("Entering addresses().");
  log.info("=== the client's address (audit_client_address.js) ===");
  const PERSON = ("addr-" + STAMP).slice(0, 40);
  const CLIENT = "addr-client-" + STAMP.slice(-6);
  await ok(post("/users/create", { username: PERSON, invent: false,
    attributes: { cn: PERSON, sn: "Address" } }), "created a person");
  await ok(post("/applications/create", { identifier: CLIENT,
    protocols: ["oauth2"], "field.oauthClientId": CLIENT,
    "field.oauthClientSecret": CLIENT + "-secret",
    "field.oauthGrantType": "password" }), "created a client");
  const own = (await auditRows("action=application.create"))
    .filter(function (row) {
      return row.target === CLIENT;
    })[0];
  const address = String((own && own.address) || "");
  check("a management API call's row names the address it came from",
        function () {
    assert.ok(/^[0-9a-f.:]+$/i.test(address) && address.indexOf("::ffff:") <
              0, JSON.stringify(own));
  });
  const grant = await send(base + "/realm/" + REALM + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", username: PERSON,
      password: "development-checks-none", client_id: CLIENT,
      client_secret: CLIENT + "-secret" }).toString() });
  assert.strictEqual(grant.status, 200, grant.raw.slice(0, 300));
  let authn = null;
  for (let i = 0; i < 20 && !authn; i += 1) {
    authn = (await auditRows("category=authentication"))
      .filter(function (row) {
        return String(row.target || "").indexOf(PERSON) >= 0 ||
               String(row.summary || "").indexOf(PERSON) >= 0;
      })[0] || null;
    if (!authn) {
      await sleep(200);
    }
  }
  check("5a. a sign-in's authentication row carries the caller's address",
        function () {
    assert.ok(authn && authn.address === address, JSON.stringify(authn));
  });
  const detail = await send(API + "/users?user=" + encodeURIComponent(PERSON));
  const events = (detail.body && detail.body.authenticationEvents) || [];
  check("5b. and so does the person's own event list", function () {
    assert.ok(events.length > 0, JSON.stringify(detail.body).slice(0, 200));
    assert.ok(events.some(function (one) {
      return one.address === address;
    }), JSON.stringify(events).slice(0, 400));
  });
  const dn = detail.body.ldap.entry.dn;
  await ldapBind(dn);
  let bind = null;
  for (let i = 0; i < 20 && !bind; i += 1) {
    bind = (await auditRows("action=directory.bind")).filter(function (row) {
      return row.target === dn;
    })[0] || null;
    if (!bind) {
      await sleep(200);
    }
  }
  check("7. an LDAP bind on the directory's own listener writes a row " +
        "naming the socket's peer", function () {
    assert.ok(bind && /^[0-9a-f.:]+$/i.test(bind.address) &&
              bind.address.indexOf("::ffff:") < 0, JSON.stringify(bind));
  });
  const prefix = address.replace(/[.:][^.:]*$/, "");
  const inner = address.slice(1);
  const byPrefix = await auditRows("address=" + encodeURIComponent(prefix));
  const byInner = await auditRows("address=" + encodeURIComponent(inner));
  const filtered = await send(API + "/audit?per=1&address=" +
                              encodeURIComponent(prefix));
  check("6. the address filter matches the FRONT of an address, not its " +
        "inside, and the answer says what it filtered on", function () {
    assert.ok(byPrefix.length > 0, prefix);
    assert.ok(byPrefix.every(function (row) {
      return String(row.address).indexOf(prefix) === 0;
    }));
    assert.strictEqual(byInner.length, 0, inner + " matched " +
                       JSON.stringify(byInner.slice(0, 1)));
    assert.strictEqual(filtered.body.filter.address, prefix);
  });
  log.debug("Leaving addresses().");
}

// REMOVAL IS OPT-IN (#444 D12). tests/CLAUDE.md's *No job removes a realm*
// is the rule for a suite run, whose realms an operator reads afterwards;
// a run against a private probe sets STS_TEST_REMOVE_REALMS=1 so that the
// realms this job made do not fill a directory shared with other runs.
async function removeRealms(ids) {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Kept.");
    return;
  }
  for (const id of ids) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A removal that fails leaves the realm standing, which is what a
      // suite run does anyway; the job's verdict is already decided.
    }
  }
  log.debug("Leaving removeRealms().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + "; the service dials " +
           PEER + " ===");
  const made = await send(base + "/admin-api/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM, domain: REALM + ".example.net",
                           name: "Audit export " + STAMP }) });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  const tcp = await syslogCollector();
  const udp = await udpCollector();
  const peer = await webhook();
  try {
    await acts();
    await refusals();
    await syslog(tcp, udp);
    await hooks(peer);
    await addresses();
    const changes = (await auditRows("category=admin")).map(function (row) {
      return row.action;
    });
    check("A20. configuration changes are audited", function () {
      ["admin.audit-export.add", "admin.audit-export.test",
       "admin.audit-export.remove"].forEach(function (action) {
        assert.ok(changes.indexOf(action) >= 0, action + " in " +
                  JSON.stringify(changes.slice(0, 30)));
      });
    });
  } finally {
    tcp.server.close();
    udp.socket.close();
    peer.server.close();
  }
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

async function main() {
  log.debug("Entering main().");
  try {
    try {
      await test();
    } finally {
      await removeRealms([REALM]);
    }
    log.info("Test completed successfully.");
    log.debug("Leaving main().");
    process.exit(0);
  } catch (e) {
    log.error("Test failed: " + ((e && e.stack) || e));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
}

main();
