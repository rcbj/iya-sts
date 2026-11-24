// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_ssh_client_lab.js
//
// ---------------------------------------------------------------------------
// SSH USER CERTIFICATES AGAINST A REAL sshd (#2060, umbrella #2055). rcbj's
// "realistic tests": the software a person and an administrator really use,
// in the client lab (tests/CLAUDE.md, *THE CLIENT LAB*), against a running
// service. sts_ssh_user_ca.js checks the same certificates with bytes made
// in node; this job hands them to OpenSSH.
//
//   a. OpenSSH's sshd in the lab trusts the realm's SSH user CA:
//      TrustedUserCAKeys is GET /pki/ssh-user-ca/{realm} and RevokedKeys
//      GET /pki/ssh-user-krl/{realm}, both fetched with curl, as a
//      deployment's refresh would (bin/lab-sshd);
//   b. a person's key made by ssh-keygen, held in ssh-agent: the
//      certificate is obtained the way an SSH CLI obtains one, through the
//      RFC 8628 device grant for `ssh:certificate` (the person approves on
//      the portal) and POST /account-api/ssh/certificates with the
//      DPoP-bound token; `ssh-keygen -L` reads it, and `ssh` logs in and
//      runs a command;
//   c. a key GENERATED ON THE VIRTUAL PIV CARD (yubico-piv-tool, slot
//      9a), read through OpenSC's PKCS#11 module (`ssh-keygen -D`),
//      certified the same way, and used with `ssh -I`, the card's PIN
//      asked for and answered;
//   d. both certificates are on the person's entry (stsSshUserCertificate),
//      read with a real `ldapsearch` over LDAPS;
//   d2. in product, the person's OWN ldapmodify of that attribute is
//      refused (insufficientAccessRights): a socket write is authorized;
//   e. an administrator REVOKES the agent's certificate by REMOVING its
//      value from the entry with a real `ldapmodify` over LDAPS (rcbj: the
//      entry is the master, and a removal is a revocation): the audit row
//      names the bound DN; until the KRL is fetched again sshd still
//      accepts it, and after the refresh `ssh` is refused, sshd's log says
//      why and `ssh-keygen -Q` finds it in the KRL;
//   f. the revoked value written back with ldapmodify is taken off again
//      and audited (STS-SSHCA-0009);
//   g. the person's own revoke, the portal's operation
//      (POST /account-api/ssh/certificates/revoke), revokes the card's
//      certificate too, and after a KRL refresh `ssh -I` is refused.
//
// The realm is a PRODUCT realm in every mode, so the LDAP write is
// authorized against the administrator's role, Admin Write on the realm's
// own roster, which the administrator is granted. Until #2092 it ran in the
// stack's mode, because on a store that persists nothing (`memory`) a
// product realm's first KRL was refused (STS-PKI-0290, its cache could not
// be persisted); the first fetch is answered now, and this job's first
// RevokedKeys fetch is what proves it. Every key,
// certificate and account is made in this run; the PIV card is swapped for
// a factory-fresh one first (bin/lab-piv-card). `local: true`, `clientLab:
// true`: SKIPPED by the runner where there is no CLIENT_LAB_URL.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const fs = require("fs");
const names = require("./random_username.js");
const portal = require("./portal_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still
  // loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_ssh_client_lab",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
// THE SERVICE AS THE LAB REACHES IT. The same URL by default: the lab is on
// the stack's network, where the runner's name for the service resolves.
const LAB_BASE = String(process.env.CLIENT_LAB_STS_URL || base)
  .replace(/\/+$/, "");
const LAB_URL = String(process.env.CLIENT_LAB_URL || "")
  .replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "sshlab" + STAMP;
const DOMAIN = REALM + ".example.net";
// A unix account name in the lab, too: lowercase, short, no dot.
const OWNER = ("sl" + STAMP).slice(0, 24);
const ADMIN = ("sla" + STAMP).slice(0, 24);
const CLI = ("slcli" + STAMP).slice(0, 30);
const PASSWORD = "Ssh-Lab-Key9!xQ";
const PIV_PIN = "123456";
const PKCS11 = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so";
const PIV_READER = "Virtual PCD 00 01";
const DIR = "ssh-" + STAMP;
const SRV = DIR + "/srv";
const WORK = "/run/client-lab/work";
const PORT = 22000 + nodeCrypto.randomInt(0, 2000);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send().");
  const response = await fetch(url, Object.assign({ redirect: "manual" },
                                                   options || {}));
  const raw = await response.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON. The caller reads raw.
    body = null;
  }
  log.debug("Leaving send(). " + response.status);
  return { status: response.status, body: body, raw: raw,
           headers: response.headers };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const response = await postJson(url, payload);
  assert.ok(response.status >= 200 && response.status < 300 &&
            response.body && response.body.ok !== false,
            "POST " + url + " should have " + what + "; it answered " +
            response.status + " " + String(response.raw).slice(0, 300));
  log.debug("Leaving ok().");
  return response.body;
}

// ---------------------------------------------------------------------------
// THE LAB'S AGENT (tests/client-lab/lab_agent.js): one program by name, and
// files in and out of its work directory. Nothing here is a shell.
// ---------------------------------------------------------------------------
async function labRun(program, args, extra) {
  log.debug("Entering labRun(). " + program);
  const spec = Object.assign({ program: program, args: args || [] },
                             extra || {});
  const response = await fetch(LAB_URL + "/run", { method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(spec) });
  const answer = await response.json();
  assert.strictEqual(response.status, 200, "the lab would not run " +
                     program + ": " + JSON.stringify(answer).slice(0, 300));
  log.info("  lab$ " + program + " " + (args || []).join(" ") + "  -> " +
           answer.code);
  log.debug("Leaving labRun(). " + answer.code);
  return answer;
}

async function labMust(program, args, extra) {
  log.debug("Entering labMust(). " + program);
  const answer = await labRun(program, args, extra);
  assert.strictEqual(answer.code, 0, program + " " + (args || []).join(" ") +
                     " failed (" + answer.code + "): " +
                     String(answer.stderr).slice(0, 600) +
                     String(answer.stdout).slice(0, 300));
  log.debug("Leaving labMust().");
  return answer;
}

async function labPut(rel, content) {
  log.debug("Entering labPut(). " + rel);
  const response = await fetch(LAB_URL + "/files/" + rel, { method: "PUT",
    body: Buffer.isBuffer(content) ? content : Buffer.from(String(content)) });
  await response.text();
  assert.ok(response.status >= 200 && response.status < 300,
            "PUT /files/" + rel + " answered " + response.status);
  log.debug("Leaving labPut().");
}

async function labGet(rel) {
  log.debug("Entering labGet(). " + rel);
  const response = await fetch(LAB_URL + "/files/" + rel);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.strictEqual(response.status, 200, "GET /files/" + rel +
                     " answered " + response.status);
  log.debug("Leaving labGet().");
  return bytes.toString("utf8");
}

async function labHealthy() {
  log.debug("Entering labHealthy().");
  const until = Date.now() + 180000;
  let last = "";
  while (Date.now() < until) {
    try {
      const r = await fetch(LAB_URL + "/health");
      last = r.status + " " + (await r.text());
      if (r.status === 200) {
        log.debug("Leaving labHealthy().");
        return;
      }
    } catch (e) {
      log.debug("Caught in labHealthy(): " + ((e && e.message) || e));
      // Not up yet: the runner waits for the lab started, not healthy.
      last = String((e && e.message) || e);
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 2000);
    });
  }
  log.debug("Leaving labHealthy(). Never.");
  throw new Error("the client lab at " + LAB_URL + " never became " +
                  "healthy: " + last);
}

// ---------------------------------------------------------------------------
// THE SSH CLI: the RFC 8628 device grant for ssh:certificate with a DPoP
// key, as docs/v1.2.0/pki.md describes a browserless SSH client. The
// person approves on the portal, signed in there.
// ---------------------------------------------------------------------------
function dpopKey() {
  log.debug("Entering dpopKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const publicJwk = { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y };
  log.debug("Leaving dpopKey().");
  return { privateKey: pair.privateKey, jwk: publicJwk };
}

function dpopProof(key, method, url, extra) {
  log.debug("Entering dpopProof(). " + method + " " + url);
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: key.jwk };
  const claims = Object.assign({ jti: nodeCrypto.randomBytes(16)
    .toString("base64url"), htm: method.toUpperCase(), htu: url,
    iat: Math.floor(Date.now() / 1000) }, extra || {});
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." + Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving dpopProof().");
  return input + "." + signature.toString("base64url");
}

async function deviceGrant(rb, person) {
  log.debug("Entering deviceGrant().");
  const key = dpopKey();
  const startUrl = rb + "/oauth2/device_authorization";
  const started = await send(startUrl, { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
               dpop: dpopProof(key, "POST", startUrl) },
    body: new URLSearchParams({ client_id: CLI, scope: "ssh:certificate",
      resource: rb + "/account-api" }).toString() });
  assert.strictEqual(started.status, 200, "device authorization: " +
                     started.raw.slice(0, 300));
  const codes = started.body;
  const approved = await person.act("/portal/device",
    { action: "approve", user_code: codes.user_code });
  assert.strictEqual(approved.status, 200, "the portal's approval: " +
                     String(approved.text).slice(0, 300));
  const tokenUrl = rb + "/oauth2/token";
  const granted = await send(tokenUrl, { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
      dpop: dpopProof(key, "POST", tokenUrl) },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: CLI, device_code: codes.device_code }).toString() });
  assert.strictEqual(granted.status, 200, "the device-code token: " +
                     granted.raw.slice(0, 300));
  const token = String(granted.body.access_token || "");
  log.debug("Leaving deviceGrant().");
  return {
    tokenType: granted.body.token_type,
    scope: granted.body.scope,
    call: function (method, path, payload) {
      const url = rb + path;
      return send(url, { method: method,
        headers: { "content-type": "application/json",
          authorization: "DPoP " + token,
          dpop: dpopProof(key, method, url, {
            ath: nodeCrypto.createHash("sha256").update(token)
              .digest("base64url") }) },
        body: payload ? JSON.stringify(payload) : undefined });
    }
  };
}

// ---------------------------------------------------------------------------
// OpenSSH in the lab.
// ---------------------------------------------------------------------------
const SSH_OPTIONS = ["-p", String(PORT),
  "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
  "-o", "PreferredAuthentications=publickey",
  "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
  "-o", "ConnectTimeout=20", "-o", "LogLevel=VERBOSE"];
const REMOTE = "echo ssh-lab-login $(id -un)";

function sshWithAgent(agentSock) {
  log.debug("Entering sshWithAgent().");
  log.debug("Leaving sshWithAgent().");
  return labRun("ssh", SSH_OPTIONS.concat(["-o", "BatchMode=yes",
    "-o", "IdentityAgent=" + agentSock, OWNER + "@127.0.0.1", REMOTE]),
    { timeoutMs: 60000 });
}

// OpenSC SEES BOTH OF THE LAB'S CARDS, and ssh logs in to every token its
// provider lists, so without this the PIN prompt is the OpenPGP card's
// (the PIN typed there is the OpenPGP card's, and the sign-in then fails).
// The configuration a person with two cards would write: only OpenSC's PIV
// driver binds, as #2059's tests/client-lab/piv/opensc.conf has it.
const OPENSC_CONF = "app default {\n  card_drivers = PIV-II;\n}\n";

function cardEnv() {
  log.debug("Entering cardEnv().");
  log.debug("Leaving cardEnv().");
  return { OPENSC_CONF: WORK + "/" + DIR + "/opensc.conf" };
}

// `-i` NAMES THE CARD'S PUBLIC KEY, as ssh_config(5) says to select one of a
// PKCS11Provider's keys: with IdentitiesOnly and no `-i` the token's key is
// never tried, the certificate is offered alone, and ssh then fails to load
// a private key from the certificate's file ("error in libcrypto").
function sshWithCard() {
  log.debug("Entering sshWithCard().");
  log.debug("Leaving sshWithCard().");
  return labRun("ssh", SSH_OPTIONS.concat(["-I", PKCS11,
    "-i", WORK + "/" + DIR + "/piv-ssh.pub",
    "-o", "CertificateFile=" + WORK + "/" + DIR + "/piv-cert.pub",
    "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    OWNER + "@127.0.0.1", REMOTE]),
    { timeoutMs: 90000,
      env: Object.assign(cardEnv(), {
        SSH_ASKPASS: "/opt/client-lab/bin/lab-askpass",
        SSH_ASKPASS_REQUIRE: "force", DISPLAY: ":0",
        LAB_ASKPASS_ANSWER: PIV_PIN }) });
}

function curlArgs(url, out) {
  log.debug("Entering curlArgs().");
  log.debug("Leaving curlArgs().");
  return ["-fsS", "--create-dirs", "--cacert",
          WORK + "/" + DIR + "/anchor.pem",
          "-o", WORK + "/" + out, url];
}

async function refreshKrl() {
  log.debug("Entering refreshKrl().");
  await labMust("curl", curlArgs(LAB_BASE + "/realm/" + REALM +
    "/pki/ssh-user-krl/" + REALM, SRV + "/revoked.krl"));
  log.debug("Leaving refreshKrl().");
}

function loggedIn(answer) {
  log.debug("Entering loggedIn().");
  const yes = answer.code === 0 &&
    String(answer.stdout).trim() === "ssh-lab-login " + OWNER;
  log.debug("Leaving loggedIn(). " + yes);
  return yes;
}

function refused(answer) {
  log.debug("Entering refused().");
  const yes = answer.code === 255 &&
    /Permission denied \(publickey\)/.test(String(answer.stderr));
  log.debug("Leaving refused(). " + yes);
  return yes;
}

function decimalOf(serialHex) {
  log.debug("Entering decimalOf().");
  log.debug("Leaving decimalOf().");
  return BigInt("0x" + serialHex).toString(10);
}

// ---------------------------------------------------------------------------
// OpenLDAP's clients in the lab, over LDAPS, bound as the administrator.
// ---------------------------------------------------------------------------
function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.CLIENT_LAB_LDAPS_URL ||
    ("ldaps://" + new URL(LAB_BASE).hostname + ":" +
     (process.env.STS_LDAPS_PORT || 636));
}

function ldapEnv() {
  log.debug("Entering ldapEnv().");
  log.debug("Leaving ldapEnv().");
  return { LDAPTLS_CACERT: WORK + "/" + DIR + "/anchor.pem",
           LDAPTLS_REQCERT: "demand" };
}

// The values of stsSshUserCertificate on `dn`, as ldapsearch prints them
// (an LDIF `::` value is base64), each parsed as the JSON it is.
async function entryCertificates(adminDn, dn) {
  log.debug("Entering entryCertificates().");
  const answer = await labMust("ldapsearch", ["-LLL", "-o", "ldif-wrap=no",
    "-H", ldapsUrl(), "-D", adminDn, "-w", PASSWORD, "-b", dn, "-s", "base",
    "(objectClass=*)", "stsSshUserCertificate"], { env: ldapEnv() });
  const values = [];
  String(answer.stdout).split("\n").forEach(function (line) {
    const plain = /^stsSshUserCertificate: (.*)$/i.exec(line);
    const coded = /^stsSshUserCertificate:: (.*)$/i.exec(line);
    if (plain) {
      values.push(plain[1]);
    } else if (coded) {
      values.push(Buffer.from(coded[1], "base64").toString("utf8"));
    }
  });
  log.debug("Leaving entryCertificates(). " + values.length);
  return values.map(function (raw) {
    return { raw: raw, json: JSON.parse(raw) };
  });
}

function valueFor(values, serialHex) {
  log.debug("Entering valueFor().");
  const hit = values.filter(function (one) {
    return String(one.json.serial || one.json.serialHex || "") === serialHex;
  })[0] || null;
  log.debug("Leaving valueFor(). " + !!hit);
  return hit;
}

async function ldapModify(adminDn, dn, op, raw) {
  log.debug("Entering ldapModify(). " + op);
  const ldif = "dn: " + dn + "\nchangetype: modify\n" + op +
    ": stsSshUserCertificate\nstsSshUserCertificate:: " +
    Buffer.from(raw, "utf8").toString("base64") + "\n-\n";
  log.debug("Leaving ldapModify().");
  return labRun("ldapmodify", ["-H", ldapsUrl(), "-D", adminDn,
    "-w", PASSWORD], { env: ldapEnv(), stdin: ldif });
}

async function auditRows(rb, action, serialHex) {
  log.debug("Entering auditRows(). " + action);
  const r = await send(rb + "/admin-api/audit?" + new URLSearchParams({
    action: action, per: "300" }).toString());
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const rows = (r.body.events || []).filter(function (one) {
    return one.detail && String(one.detail.serialHex) === serialHex;
  });
  log.debug("Leaving auditRows(). " + rows.length);
  return rows;
}

async function waitFor(what, fn) {
  log.debug("Entering waitFor(). " + what);
  const until = Date.now() + 30000;
  let last = null;
  while (Date.now() < until) {
    last = await fn();
    if (last.done) {
      log.debug("Leaving waitFor().");
      return last;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 1000);
    });
  }
  log.debug("Leaving waitFor(). Timed out.");
  return last;
}

function userBody(username) {
  log.debug("Entering userBody().");
  log.debug("Leaving userBody().");
  return { username: username, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "Ssh Lab " + username, sn: username,
                  givenName: "Ssh", mail: username + "@" + DOMAIN } };
}

async function setUp() {
  log.debug("Entering setUp().");
  // A product realm requires a second factor of everybody, and an LDAP
  // simple bind cannot ask for one, hence allowOptionalSecondFactor, as
  // sts_ldap_read_authorization.js has it.
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "SSH client lab " + STAMP, overrides: {
      "global.mode": "product",
      "authn.allowOptionalSecondFactor": "true",
      // pki.personSelfServicePerAddress is the default five: since #2093 it
      // counts this realm's issuances only, so the four sts_ssh_user_ca.js
      // spends from the same runner address in its own realm just before
      // this job are not this realm's. This job issues two.
      "risk.assessSignIns": "false",
      "oauth2.deviceAuthorization": "true" } },
    "created the realm " + REALM);
  const rb = base + "/realm/" + REALM;
  const made = {};
  for (const who of [OWNER, ADMIN]) {
    made[who] = String((await ok(rb + "/admin-api/users/create",
      userBody(who), "created " + who)).dn);
  }
  await ok(rb + "/admin-api/rbac/grant", { username: ADMIN, role: "write" },
           "granted " + ADMIN + " Admin Write on the realm's roster");
  // THE SSH CLI's CLIENT: public, the device grant, ssh:certificate only,
  // declared as the delegated permission grant docs/v1.2.0/pki.md names.
  await ok(rb + "/admin-api/applications/create", { identifier: CLI,
    name: "SSH CLI " + STAMP, protocols: ["oauth2"], fields: {
      oauthClientId: [CLI], oauthTokenEndpointAuthMethod: "none",
      oauthGrantType: ["urn:ietf:params:oauth:grant-type:device_code"],
      oauthAllowedScope: ["ssh:certificate"] } },
    "registered the SSH CLI " + CLI);
  await ok(rb + "/admin-api/permissions/grant-permission", { client: CLI,
    permission: "urn:sts:account-api:ssh:certificate" },
    "granted the CLI the person's SSH certificates");
  log.debug("Leaving setUp().");
  return { rb: rb, ownerDn: made[OWNER], adminDn: made[ADMIN] };
}

async function issue(cli, publicKey) {
  log.debug("Entering issue().");
  const issued = await cli.call("POST", "/account-api/ssh/certificates",
    { publicKey: publicKey, principals: [OWNER] });
  assert.strictEqual(issued.status, 200, "issuance: " +
                     issued.raw.slice(0, 300));
  log.debug("Leaving issue(). " + issued.body.serialHex);
  return issued.body;
}

async function test() {
  log.debug("Entering test().");
  log.info("SSH user certificates against a real sshd, realm " + REALM +
           ", lab " + LAB_URL);
  await labHealthy();
  const anchorFile = process.env.NODE_EXTRA_CA_CERTS || "";
  assert.ok(anchorFile && fs.existsSync(anchorFile), "the job needs the " +
            "service's TLS anchor in NODE_EXTRA_CA_CERTS");
  await labPut(DIR + "/anchor.pem", fs.readFileSync(anchorFile));
  const s = await setUp();
  const rb = s.rb;

  log.info("=== a. sshd trusts the realm's SSH user CA ===");
  await labMust("curl", curlArgs(LAB_BASE + "/realm/" + REALM +
    "/pki/ssh-user-ca/" + REALM, SRV + "/trusted_user_ca.pub"));
  await refreshKrl();
  const started = await labMust("lab-sshd", ["start", SRV, String(PORT),
                                             OWNER]);
  const caLine = await labGet(SRV + "/trusted_user_ca.pub");
  check("sshd starts with TrustedUserCAKeys and RevokedKeys from the " +
        "realm, fetched with curl", function () {
    assert.match(String(started.stdout).trim(), /^\d+$/);
    assert.match(caLine,
      /^(ssh-ed25519|ecdsa-sha2-nistp\d+|rsa-sha2-\d+|ssh-rsa) /);
  });

  log.info("=== b. a key in ssh-agent, certified through the device " +
           "grant ===");
  const person = await portal.signInToThePortal(rb, OWNER, log,
                                                { password: PASSWORD });
  const cli = await deviceGrant(rb, person);
  check("the SSH CLI's device grant answers a DPoP token for " +
        "ssh:certificate", function () {
    assert.strictEqual(cli.tokenType, "DPoP");
  });
  await labMust("ssh-keygen", ["-q", "-t", "ed25519", "-N", "",
    "-C", OWNER + "@client-lab", "-f", WORK + "/" + DIR + "/id_ed25519"]);
  const agentKey = (await labGet(DIR + "/id_ed25519.pub")).trim();
  const agentCert = await issue(cli, agentKey);
  await labPut(DIR + "/id_ed25519-cert.pub", agentCert.certificate + "\n");
  const shown = await labMust("ssh-keygen", ["-L", "-f",
    WORK + "/" + DIR + "/id_ed25519-cert.pub"]);
  check("ssh-keygen -L reads the certificate: a user certificate for " +
        "the person, with this serial, signed by the published CA",
        function () {
    const text = String(shown.stdout);
    assert.match(text, /Type: ssh-ed25519-cert-v01@openssh\.com user /);
    assert.match(text, new RegExp("Serial: " + decimalOf(
      agentCert.serialHex) + "\\b"));
    assert.match(text, new RegExp("Principals: \\n\\s+" + OWNER + "\\n"));
    const fingerprint = "SHA256:" + nodeCrypto.createHash("sha256")
      .update(Buffer.from(caLine.trim().split(/\s+/)[1], "base64"))
      .digest("base64").replace(/=+$/, "");
    assert.ok(text.indexOf("Signing CA: ") >= 0 &&
              text.indexOf(fingerprint) >= 0, text + " / " + fingerprint);
  });
  const sock = WORK + "/" + DIR + "/agent.sock";
  const agent = await labMust("ssh-agent", ["-a", sock]);
  const agentPid = (/SSH_AGENT_PID=(\d+)/.exec(String(agent.stdout)) ||
                    [])[1];
  const added = await labMust("ssh-add", [WORK + "/" + DIR + "/id_ed25519"],
    { env: { SSH_AUTH_SOCK: sock } });
  const listed = await labMust("ssh-add", ["-l"],
    { env: { SSH_AUTH_SOCK: sock } });
  const login = await sshWithAgent(sock);
  check("ssh-add loads the key and its certificate into ssh-agent, and " +
        "ssh logs in with the certificate and runs a command", function () {
    assert.match(String(added.stderr), /Certificate added/);
    assert.match(String(listed.stdout), /ED25519-CERT/);
    assert.ok(loggedIn(login), JSON.stringify(login).slice(0, 900));
  });

  log.info("=== c. a key on the virtual PIV card, through PKCS#11 ===");
  await labMust("lab-piv-card", ["yubikey"]);
  await labMust("yubico-piv-tool", ["-r", PIV_READER, "-a", "generate",
    "-s", "9a", "-A", "ECCP256", "-o", "piv-9a.pub"], { cwd: DIR });
  // OpenSC lists a PIV key only beside a certificate in its slot, as a
  // real YubiKey needs `ykman piv certificates generate`: a placeholder
  // over the card's key, signed by a throwaway key (bin/lab-piv-attest's
  // -force_pubkey arrangement).
  await labMust("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt",
    "ec_paramgen_curve:P-256", "-out", "placeholder.key"], { cwd: DIR });
  await labMust("openssl", ["req", "-new", "-key", "placeholder.key",
    "-subj", "/CN=" + OWNER + " ssh 9a", "-out", "placeholder.csr"],
    { cwd: DIR });
  await labMust("openssl", ["x509", "-req", "-in", "placeholder.csr",
    "-force_pubkey", "piv-9a.pub", "-signkey", "placeholder.key",
    "-days", "1", "-out", "placeholder.pem"], { cwd: DIR });
  await labMust("yubico-piv-tool", ["-r", PIV_READER, "-a",
    "import-certificate", "-s", "9a", "-i", "placeholder.pem"],
    { cwd: DIR });
  await labPut(DIR + "/opensc.conf", OPENSC_CONF);
  const fromCard = await labMust("ssh-keygen", ["-D", PKCS11],
                                 { env: cardEnv() });
  const fromPem = await labMust("ssh-keygen", ["-i", "-m", "PKCS8", "-f",
    "piv-9a.pub"], { cwd: DIR });
  const cardKey = String(fromCard.stdout).split("\n").filter(function (l) {
    return /^ecdsa-sha2-nistp256 /.test(l);
  })[0] || "";
  check("ssh-keygen -D reads the card's 9a key through OpenSC, the key " +
        "yubico-piv-tool generated on the card", function () {
    assert.ok(cardKey, String(fromCard.stdout).slice(0, 400));
    assert.strictEqual(cardKey.split(/\s+/)[1],
                       String(fromPem.stdout).trim().split(/\s+/)[1]);
  });
  const cardLine = cardKey.split(/\s+/).slice(0, 2).join(" ");
  await labPut(DIR + "/piv-ssh.pub", cardLine + "\n");
  const cardCert = await issue(cli, cardLine);
  await labPut(DIR + "/piv-cert.pub", cardCert.certificate + "\n");
  const cardLogin = await sshWithCard();
  check("ssh -I with the card's certificate logs in, the card's PIN " +
        "asked for and answered", function () {
    assert.match(cardCert.certificate,
                 /^ecdsa-sha2-nistp256-cert-v01@openssh\.com /);
    assert.ok(loggedIn(cardLogin), JSON.stringify(cardLogin).slice(0, 900));
    assert.match(String(cardLogin.stderr), /lab-askpass: asked: /);
  });
  const sshdLog = await labGet(SRV + "/sshd.log");
  check("sshd's own log names both certificates it accepted, by serial",
        function () {
    for (const one of [agentCert, cardCert]) {
      assert.match(sshdLog, new RegExp("Accepted publickey for " + OWNER +
        " .*serial " + decimalOf(one.serialHex) + "\\b"), sshdLog);
    }
  });

  log.info("=== d. both on the person's entry, read over LDAPS ===");
  const before = await entryCertificates(s.adminDn, s.ownerDn);
  check("ldapsearch over LDAPS reads both certificates in " +
        "stsSshUserCertificate, in OpenSSH text form", function () {
    const a = valueFor(before, agentCert.serialHex);
    const c = valueFor(before, cardCert.serialHex);
    assert.ok(a && c, JSON.stringify(before).slice(0, 600));
    assert.strictEqual(a.json.certificate, agentCert.certificate);
    assert.strictEqual(c.json.certificate, cardCert.certificate);
  });

  log.info("=== d2. the person may not remove it over LDAP ===");
  const modeAnswer = await send(rb + "/admin-api/mode");
  check("the realm is in product mode (#2092: forced in every stack)",
        function () {
    assert.ok(modeAnswer.body && modeAnswer.body.isProduct,
              JSON.stringify(modeAnswer.body).slice(0, 300));
  });
  // Product authorizes a socket write: a person modifies only the
  // attributes ldap.selfWritableAttributes names on their own entry
  // (ldap/CLAUDE.md, *WHO MAY WRITE THIS DIRECTORY OVER THE SOCKET*), and
  // an SSH certificate is not one of them.
  const ownWrite = await ldapModify(s.ownerDn, s.ownerDn, "delete",
    valueFor(before, agentCert.serialHex).raw);
  const kept = await entryCertificates(s.adminDn, s.ownerDn);
  check("in product, the person's own ldapmodify of the attribute is " +
        "refused insufficientAccessRights (50), and nothing is revoked",
        function () {
    assert.strictEqual(ownWrite.code, 50,
                       JSON.stringify(ownWrite).slice(0, 400));
    assert.match(String(ownWrite.stderr), /Insufficient access/i);
    assert.ok(valueFor(kept, agentCert.serialHex));
  });

  log.info("=== e. revoked by REMOVING it from the entry with " +
           "ldapmodify ===");
  const removed = await ldapModify(s.adminDn, s.ownerDn, "delete",
    valueFor(before, agentCert.serialHex).raw);
  const afterRemoval = await entryCertificates(s.adminDn, s.ownerDn);
  const revokeRows = (await waitFor("the revocation's audit row",
    async function () {
      const rows = await auditRows(rb, "ssh-user-ca.revoke",
                                   agentCert.serialHex);
      return { done: rows.length > 0, rows: rows };
    })).rows;
  check("ldapmodify, bound as the administrator, removes the value; the " +
        "revocation is audited with the bound DN", function () {
    assert.strictEqual(removed.code, 0, JSON.stringify(removed));
    assert.ok(!valueFor(afterRemoval, agentCert.serialHex));
    assert.ok(valueFor(afterRemoval, cardCert.serialHex));
    assert.ok(revokeRows.length > 0, "no ssh-user-ca.revoke row");
    assert.strictEqual(revokeRows[0].outcome, "success");
    assert.strictEqual(revokeRows[0].detail.via, "entry");
    // The writer as the observer names an LDAP one: `ldap:` and the bound
    // DN, through the `ldap modify` door.
    assert.strictEqual(String(revokeRows[0].actor).toLowerCase(),
                       "ldap:" + s.adminDn.toLowerCase(),
                       JSON.stringify(revokeRows[0]));
    assert.strictEqual(revokeRows[0].detail.door, "ldap modify");
  });
  const stale = await sshWithAgent(sock);
  check("until the KRL is fetched again, sshd still accepts it (its " +
        "RevokedKeys file is the old KRL)", function () {
    assert.ok(loggedIn(stale), JSON.stringify(stale).slice(0, 900));
  });
  await refreshKrl();
  const query = await labRun("ssh-keygen", ["-Q", "-f",
    WORK + "/" + SRV + "/revoked.krl",
    WORK + "/" + DIR + "/id_ed25519-cert.pub",
    WORK + "/" + DIR + "/piv-cert.pub"]);
  const afterKrl = await sshWithAgent(sock);
  const logAfter = await labGet(SRV + "/sshd.log");
  check("after the KRL refresh ssh is refused; ssh-keygen -Q finds the " +
        "certificate in the KRL and not the card's; sshd's log says it " +
        "was revoked", function () {
    assert.ok(refused(afterKrl), JSON.stringify(afterKrl).slice(0, 900));
    assert.match(String(query.stdout), /id_ed25519-cert\.pub\): REVOKED/);
    assert.match(String(query.stdout), /piv-cert\.pub\): ok/);
    assert.match(logAfter, /revoked by file/i);
  });
  const cardStill = await sshWithCard();
  check("the card's certificate still logs in", function () {
    assert.ok(loggedIn(cardStill), JSON.stringify(cardStill).slice(0, 900));
  });

  log.info("=== f. a revoked certificate written back is taken off ===");
  const writtenBack = await ldapModify(s.adminDn, s.ownerDn, "add",
    valueFor(before, agentCert.serialHex).raw);
  const backOff = await waitFor("the value taken off again",
    async function () {
      const values = await entryCertificates(s.adminDn, s.ownerDn);
      const rows = await auditRows(rb, "ssh-user-ca.entry-refused",
                                   agentCert.serialHex);
      return { done: !valueFor(values, agentCert.serialHex) &&
                     rows.length > 0, values: values, rows: rows };
    });
  const stillRefused = await sshWithAgent(sock);
  check("ldapmodify adds it back; the service takes it off the entry " +
        "again and audits the refusal (STS-SSHCA-0009), and ssh is still " +
        "refused", function () {
    log.info("    the write back answered " + writtenBack.code + " " +
             String(writtenBack.stderr).trim());
    assert.ok(backOff.done, JSON.stringify(backOff).slice(0, 600));
    assert.strictEqual(backOff.rows[0].errorCode, "STS-SSHCA-0009");
    assert.strictEqual(backOff.rows[0].outcome, "refused");
    assert.ok(refused(stillRefused), JSON.stringify(stillRefused)
      .slice(0, 900));
  });

  log.info("=== g. the person's own revoke, the portal's operation ===");
  const own = await person.api("POST", "/account-api/ssh/certificates/revoke",
    { serialHex: cardCert.serialHex });
  await refreshKrl();
  const cardAfter = await sshWithCard();
  const query2 = await labRun("ssh-keygen", ["-Q", "-f",
    WORK + "/" + SRV + "/revoked.krl",
    WORK + "/" + DIR + "/piv-cert.pub"]);
  const finalValues = await entryCertificates(s.adminDn, s.ownerDn);
  check("the person revokes the card's certificate; it is off the entry, " +
        "in the KRL, and ssh -I is refused", function () {
    assert.strictEqual(own.status, 200, String(own.text).slice(0, 300));
    assert.ok(!valueFor(finalValues, cardCert.serialHex));
    assert.match(String(query2.stdout), /piv-cert\.pub\): REVOKED/);
    assert.ok(refused(cardAfter), JSON.stringify(cardAfter).slice(0, 900));
  });

  if (agentPid) {
    await labRun("ssh-agent", ["-k"], { env: { SSH_AGENT_PID: agentPid,
                                               SSH_AUTH_SOCK: sock } });
  }
  log.debug("Leaving test().");
}

async function cleanUp() {
  log.debug("Entering cleanUp().");
  if (LAB_URL) {
    try {
      await labRun("lab-sshd", ["stop", SRV]);
      // A fresh card for whoever comes next; this one holds our 9a key.
      await labRun("lab-piv-card", ["yubikey"]);
    } catch (e) {
      log.debug("Caught in cleanUp(): " + ((e && e.message) || e));
      // The lab's own restart clears it; the verdict is the test's.
      log.info("could not tidy the lab: " + ((e && e.message) || e));
    }
  }
  if (process.env.STS_TEST_REMOVE_REALMS === "1") {
    const response = await postJson(base + "/admin-api/realms/remove",
                                    { id: REALM });
    log.info("removed the realm " + REALM + " (" + response.status + ")");
  }
  log.debug("Leaving cleanUp().");
}

async function main() {
  log.debug("Entering main().");
  if (!LAB_URL) {
    log.info("SKIPPED: no CLIENT_LAB_URL, so there is no client lab " +
             "(an AWS target, or ./run-coverage.sh).");
    log.debug("Leaving main(). No lab.");
    return;
  }
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the lab and the realm are tidied.
    failure = e;
  }
  try {
    await cleanUp();
  } catch (e) {
    log.debug("Caught in main() tidying up: " + ((e && e.message) || e));
    // A tidy-up that fails does not hide the test's own verdict.
    log.info("could not tidy up: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              (failure.stack || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main();
