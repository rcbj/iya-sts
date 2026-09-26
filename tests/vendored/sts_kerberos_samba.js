"use strict";
//
// File: sts_kerberos_samba.js
//
// ---------------------------------------------------------------------------
// SAMBA'S RAW KERBEROS KDC TESTS AGAINST THE PER-REALM KDC (#204, 2026-09-26).
//
// Samba's python/samba/tests/krb5 is the most thorough protocol-level KDC test
// suite there is: RawKerberosTest builds every AS-REQ and TGS-REQ by hand and
// checks every field of every reply and every error — enctype negotiation,
// ETYPE-INFO2, FAST (RFC 6113), S4U, user-to-user, the PAC's buffers and
// signatures. This job runs ALL of it, unchanged, against a throwaway
// DEVELOPMENT trust realm's KDC on TCP 88 (routed by its Kerberos realm name,
// #33), in every local mode — a realm's mode is its own.
//
// Samba is GPL-3.0 and is never vendored: tests/Dockerfile builds a pinned
// release into /opt/samba (tests/kerberos-interop/build-samba.sh), and
// tests/kerberos-interop/samba_krb5_driver.py runs the classes and prints
// every outcome as JSON. That file argues its two adaptations, neither of
// which changes what a test sends or checks:
//
//   * every door to an Active Directory DC (SamDB over LDAP, DRSUAPI, LSA,
//     SAMR, NETLOGON) raises SkipTest naming what the test needed — those
//     tests create or read their accounts in AD, and this KDC is not an AD
//     DC; and
//   * a plain USER account is the development realm's create-on-first-sight
//     principal under a fresh name. A computer, server or managed-service
//     account (a sAMAccountName and SPNs sharing one key, MS-KILE), or a user
//     with any AD attribute set, is skipped naming what it needed.
//
// Everything else the tests read is Samba's own environment contract
// (raw_testcase.py's setUpClass and _get_krb5_creds_from_env): the user,
// client, machine, service, server, DC, admin and krbtgt credentials, and
// the KDC's capabilities — FAST_SUPPORT=1, CLAIMS_SUPPORT=0,
// COMPOUND_ID_SUPPORT=0, EXPECT_PAC=1, STRICT_CHECKING=0 (what Samba's own
// selftest runs its KDCs with). The keys the job hands over are derived here
// from the realm's published salts and development passwords; nothing is
// read out of the service's store.
//
// THREE SERVICE PROFILES, because Samba names "the service" three ways and
// in Active Directory all three are one computer account:
//
//   * HOST — SERVICE_USERNAME `<h>.<domain>$`: the FAST and kdc_base tests ask
//     for `host/<name without its $>`, which this KDC creates on first sight
//     for a host of the realm's own domain;
//   * ACCOUNT — `sambasrv$`, a user-type principal: kdc_tgs_tests and
//     s4u_tests ask for the account name itself, and log in as it;
//   * SPN — `<h>.<domain>`: simple_tests asks for `host/<SERVICE_USERNAME>`.
//
// Each module runs under exactly one. xrealm_tests runs against the DEFAULT
// realm's development trust (krb5.trustedRealm), the one trust this service
// has; where the default realm is in product mode there is none, and the
// module is recorded as not applicable.
//
// WHAT FAILS THIS JOB: any test that FAILS or ERRORS and is not in
// EXCEPTIONS below — each also recorded on #204 with its reason — and fewer
// passes than FLOOR, which is what a harness that stopped running looks like.
// An exception that did not occur is reported.
//
// OWNED HERE (local: true): this repository's KDC and management API.
// tests/CLAUDE.md, *The Kerberos interoperability harnesses*, is the
// provenance.
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const wire = require("./krb5_wire.js");
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
var log = bunyan.createLogger({ name: "sts_kerberos_samba",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

const TAG = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 10);
const RID = "sambak-" + TAG;
const DOMAIN = RID + ".example.net";
const KREALM = DOMAIN.toUpperCase();
const realmApi = base + "/realm/" + RID + "/admin-api";
const HOST = "sambahost." + DOMAIN;
const ACCOUNT = "sambasrv$";

// Where Samba is. tests/Dockerfile builds it and sets this.
const SAMBA_DIR = process.env.STS_SAMBA_DIR || "/opt/samba";
const DRIVER = path.join(__dirname, "..", "kerberos-interop",
                         "samba_krb5_driver.py");
const MARKER = "SAMBA-KRB5-RESULTS ";
const MODULE_PREFIX = "samba.tests.krb5.";

// A module's profile (see the header); everything not named is HOST.
const PROFILE_OF = {
  kdc_tgs_tests: "account",
  s4u_tests: "account",
  simple_tests: "spn",
  xrealm_tests: "trust"
};

// The minimum number of passing tests: well under what a run yields (#204's
// first complete runs: 268 in memory, 267 in single-node), well over what a
// harness that stopped reaching the KDC would.
const FLOOR = 200;

// A whole run of every module is well under a minute (#204: ~10 s); this
// bounds a hung one.
const RUN_TIMEOUT_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// THE DOCUMENTED EXCEPTIONS, each also recorded on #204 with its reason.
// Keyed by the test's id as unittest names it, without the module prefix.
// ---------------------------------------------------------------------------
const MIT_ONLY = "compatability_tests pairs each MIT behaviour with its " +
  "Heimdal/Windows opposite, and Samba's own selftest expects one half of " +
  "each pair to fail against any given KDC; this KDC follows Active " +
  "Directory and Heimdal (EncASRepPart's own tag, the kvno of a long-term " +
  "key in the AS-REP's EncryptedData, no salt for rc4-hmac), which the " +
  "test_heimdal_* halves assert and pass";
const NO_SPN = "the test logs in as the machine account's SPN, which it " +
  "reads from the account SamDB created; environment credentials carry no " +
  "SPN, so the AS-REQ names the account itself and is rightly answered";
const SAM_ACCOUNT_KRBTGT = "Active Directory resolves the single-component " +
  "sname `krbtgt` as the krbtgt account's sAMAccountName; RFC 4120 names " +
  "the ticket-granting service krbtgt/REALM, and this KDC resolves " +
  "principal names, not sAMAccountNames (KDC_ERR_S_PRINCIPAL_UNKNOWN)";
const UNICODE = "the vendored Kerberos codec (kerberos/krb5_asn1.js, the " +
  "parent project's) decodes a KerberosString as Latin-1 and encodes it as " +
  "UTF-8, so a non-ASCII principal name's salt comes back double-encoded; " +
  "the fix is in the codec, which is not edited here — " +
  "rcbj/id-proto-debugger#308";
const ARMOR_NOT_TGT = "an armor ticket that is not a TGT of the realm is " +
  "refused KDC_ERR_PREAUTH_FAILED (STS-KRB-0137), RFC 6113 section 5.4.1's " +
  "code for armor a KDC cannot accept; the test expects Heimdal's " +
  "KDC_ERR_POLICY or KDC_ERR_S_PRINCIPAL_UNKNOWN, and records that Windows " +
  "accepts the ticket";
const TGS_ENC_PA_REP = "RFC 6806 section 11: a KDC MUST include " +
  "PA-REQ-ENC-PA-REP in \"any generated KDC reply\" to a request that " +
  "sent it, the TGS-REP included; the test asserts Windows' behaviour of " +
  "answering it in the AS exchange only (Samba's own Heimdal KDC " +
  "knownfails it the same way)";
const MICROSOFT_COOKIE = "Windows puts a fixed PA-FX-COOKIE \"Microsoft\" " +
  "in an unarmored KDC_ERR_PREAUTH_REQUIRED; RFC 6113 section 5.2 asks " +
  "for a cookie only inside FAST, and this KDC sends none outside it " +
  "because MIT's client retries whenever one is present (kerberos/" +
  "CLAUDE.md); Samba's own Heimdal KDC knownfails it too";
const PAC_HARDENING = "Active Directory's PAC hardening (KB5008380): a " +
  "TGT always carries a PAC whatever PA-PAC-REQUEST asked, and a TGT " +
  "without one is refused KDC_ERR_TGT_REVOKED. This KDC honours " +
  "PA-PAC-REQUEST false by design (kerberos/CLAUDE.md), and RFC 4120 has " +
  "no PAC; Samba's MIT KDC knownfails both";
const S4U_CHECKSUM = "[MS-SFU] 2.2.1 fixes the PA-FOR-USER checksum as " +
  "KERB_CHECKSUM_HMAC_MD5 and this KDC verifies exactly that " +
  "(test_s4u2self_hmac_md5_checksum passes); the test sends the TGT " +
  "session key's own checksum type, which Windows, MIT and Heimdal also " +
  "accept";
const AUTH_LOG = "authentication policies and silos, and Samba's own " +
  "authentication log over its messaging bus: setUpClass reads the Samba " +
  "server's `interfaces` to watch it, and there is no Samba server";
const GMSA = "group managed service accounts, an Active Directory object " +
  "with a key the DC derives (MS-GKDI); the test builds a local SamDB";
const IDMAP = "Samba's winbind NSS mapping on a domain member " +
  "(MAPPED_USERNAME, UNMAPPED_USERNAME, INVALID_USERNAME): a member server " +
  "joined to an AD domain, which this KDC is not";
const EXCEPTIONS = {
  "as_req_tests.AsReqKerberosTests.test_as_req_enc_timestamp_spn": NO_SPN,
  "as_req_tests.AsReqKerberosTests.test_as_req_enc_timestamp_spn_enterprise":
    NO_SPN,
  "as_req_tests.AsReqKerberosTests.test_krbtgt_single_component_krbtgt":
    SAM_ACCOUNT_KRBTGT,
  "as_req_tests.AsReqKerberosTests.test_as_req_unicode": UNICODE,
  "compatability_tests.CompatabilityTests.test_mit_EncASRepPart_tag":
    MIT_ONLY,
  ["compatability_tests.CompatabilityTests." +
    "test_mit_EncASRepPart_FAST_support"]: MIT_ONLY,
  "compatability_tests.CompatabilityTests.test_mit_EncryptedData_kvno":
    MIT_ONLY,
  "compatability_tests.CompatabilityTests.test_mit_arcfour_salt": MIT_ONLY,
  "fast_tests.FAST_Tests.test_fast_invalid_tgt": ARMOR_NOT_TGT,
  "fast_tests.FAST_Tests.test_fast_invalid_checksum_tgt": ARMOR_NOT_TGT,
  "fast_tests.FAST_Tests.test_fast_tgs_enc_pa_rep": TGS_ENC_PA_REP,
  "fast_tests.FAST_Tests.test_simple_tgs_enc_pa_rep": TGS_ENC_PA_REP,
  "fast_tests.FAST_Tests.test_fx_cookie_no_fast": MICROSOFT_COOKIE,
  "kdc_tgs_tests.KdcTgsTests.test_remove_pac": PAC_HARDENING,
  "kdc_tgs_tests.KdcTgsTests.test_request_no_pac": PAC_HARDENING,
  "s4u_tests.S4UKerberosTests.test_s4u2self": S4U_CHECKSUM,
  "setUpClass (authn_policy_tests.AuthnPolicyTests)": AUTH_LOG,
  "setUpClass (conditional_ace_tests.ConditionalAceTests)": AUTH_LOG,
  "setUpClass (conditional_ace_tests.DeviceRestrictionTests)": AUTH_LOG,
  "setUpClass (conditional_ace_tests.SamLogonTests)": AUTH_LOG,
  "setUpClass (conditional_ace_tests.TgsReqServicePolicyTests)": AUTH_LOG,
  "gmsa_tests.GmsaTests.test_gmsa_cannot_be_locked_out_with_gensec_ntlmssp":
    GMSA
};
// Every test of these modules, whatever it reports.
const MODULE_EXCEPTIONS = {
  test_idmap_nss: IDMAP
};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function call(method, url, body) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into any message.
    json = null;
  }
  log.debug("Leaving call(). HTTP " + r.status);
  return { status: r.status, json: json, text: text };
}

// ---------------------------------------------------------------------------
// 0. THE REALM, ITS PRINCIPALS AND THEIR KEYS.
// ---------------------------------------------------------------------------
async function principalRows(prefix) {
  log.debug("Entering principalRows().");
  const r = await call("GET", prefix + "/krb5/principals");
  assert.strictEqual(r.status, 200, "GET /krb5/principals: " + r.status);
  log.debug("Leaving principalRows().");
  return r.json.principals || [];
}

function rowFor(rows, principal) {
  log.debug("Entering rowFor(). " + principal);
  const row = rows.filter(function (one) {
    return one.principal === principal;
  })[0];
  assert.ok(row, principal + " is not in /krb5/principals");
  log.debug("Leaving rowFor().");
  return row;
}

// Samba's `<PREFIX>_{AES256,AES128,RC4}_KEY_HEX` for a password and a salt.
async function keyEnv(prefix, password, salt) {
  log.debug("Entering keyEnv(). " + prefix);
  const out = {};
  const etypes = { AES256: 18, AES128: 17, RC4: 23 };
  for (const name of Object.keys(etypes)) {
    const key = await wire.stringToKey(password, salt, etypes[name]);
    out[prefix + "_" + name + "_KEY_HEX"] = Buffer.from(key).toString("hex");
  }
  log.debug("Leaving keyEnv().");
  return out;
}

async function setUp(k) {
  log.debug("Entering setUp().");
  const made = await call("POST", api + "/realms/create",
    { id: RID, domain: DOMAIN, name: "#204 Samba raw Kerberos tests",
      overrides: { "krb5.enabled": true, "krb5.realm": KREALM,
                   "global.mode": "development" } });
  assert.strictEqual(made.status, 200, "realm: " + made.text.slice(0, 300));
  k.password = String(await facts.setting(realmApi, "krb5.userPassword"));
  k.kvno = Number(await facts.setting(realmApi, "krb5.kvno"));
  k.krbtgtPassword = String(await facts.setting(realmApi,
                                                "krb5.krbtgtPassword"));
  k.servicePassword = String(await facts.setting(realmApi,
                                                 "krb5.autoServicePassword"));
  // The two principals the profiles name are made on first sight: an AS
  // exchange for the account, a TGS exchange for the host.
  const tcp = wire.tcpTransport(k.kdcHost, k.kdcPort);
  const account = await wire.asExchange(tcp, KREALM, ACCOUNT,
                                        { password: k.password });
  check("the development realm " + KREALM + " answers on TCP " +
        k.kdcPort + " and issues " + ACCOUNT + " a TGT", function () {
    assert.ok(account.tgt, JSON.stringify(account.second ||
                                          account.first).slice(0, 300));
  });
  const host = await wire.tgsExchange(tcp, account.tgt,
    { type: wire.msgs.NAME_TYPE.SRV_HST, name: ["host", HOST] });
  check("host/" + HOST + " is issued a ticket, so it exists", function () {
    assert.ok(host.ok, host.error && host.error.toString());
  });
  const rows = await principalRows(base + "/realm/" + RID);
  const krbtgt = rowFor(rows, "krbtgt/" + KREALM + "@" + KREALM);
  const hostRow = rowFor(rows, "host/" + HOST + "@" + KREALM);
  const accountRow = rowFor(rows, ACCOUNT + "@" + KREALM);
  k.krbtgtKeys = await keyEnv("KRBTGT", k.krbtgtPassword, krbtgt.salt);
  k.krbtgtKvno = krbtgt.kvno;
  k.hostKeys = await keyEnv("SERVICE", k.servicePassword, hostRow.salt);
  k.accountKeys = await keyEnv("SERVICE", k.password, accountRow.salt);
  k.accountSalt = accountRow.salt;
  log.debug("Leaving setUp().");
}

// ---------------------------------------------------------------------------
// 1. THE RUNS.
// ---------------------------------------------------------------------------
function sambaPythonPath() {
  log.debug("Entering sambaPythonPath().");
  const lib = path.join(SAMBA_DIR, "lib");
  const py = fs.readdirSync(lib).filter(function (one) {
    return /^python3/.test(one);
  })[0];
  log.debug("Leaving sambaPythonPath().");
  return py ? path.join(lib, py, "site-packages") : "";
}

function smbConf(dir, realm) {
  log.debug("Entering smbConf().");
  const file = path.join(dir, "smb-" + realm.toLowerCase() + ".conf");
  // The client side of Samba's LoadParm and, as SERVERCONFFILE, what the
  // tests read of "the server's" configuration — whose defaults describe
  // this KDC (no implicit-dollar matching is ever asked of it here).
  fs.writeFileSync(file, "[global]\n realm = " + realm + "\n workgroup = " +
                   realm.split(".")[0] + "\n netbios name = STSKRB5TEST\n");
  log.debug("Leaving smbConf().");
  return file;
}

// The environment a profile's run reads (raw_testcase.py's contract).
async function envFor(k, profile, dir) {
  log.debug("Entering envFor(). " + profile);
  const trust = profile === "trust";
  const realm = trust ? k.defaultRealm : KREALM;
  const conf = smbConf(dir, realm);
  const env = {
    PYTHONPATH: sambaPythonPath(),
    SERVER: k.kdcHost, DC_SERVER: k.kdcHost,
    DOMAIN: realm.split(".")[0], REALM: realm,
    SMB_CONF_PATH: conf, SERVERCONFFILE: conf,
    USERNAME: "sambauser", PASSWORD: trust ? k.defaultPassword : k.password,
    CLIENT_USERNAME: "sambaclient", CLIENT_PASSWORD: k.password,
    ADMIN_USERNAME: "sambaadmin", ADMIN_PASSWORD: k.password,
    FOR_USER: "sambauser",
    STRICT_CHECKING: "0", FAST_SUPPORT: "1", CLAIMS_SUPPORT: "0",
    COMPOUND_ID_SUPPORT: "0", EXPECT_PAC: "1", EXPECT_EXTRA_PAC_BUFFERS: "1",
    CHECK_CNAME: "1", CHECK_PADATA: "1", KADMIN_IS_TGS: "0",
    EXPECT_NT_STATUS: "0",
    SAMBA_KRB5_SHARED_PASSWORD: k.password,
    SAMBA_KRB5_SHARED_KVNO: String(k.kvno),
    // Every account here is keyed with AES; see the driver.
    SAMBA_KRB5_DOMAIN_FUNCTIONAL_LEVEL: "7",
    KRBTGT_USERNAME: "krbtgt", KRBTGT_PASSWORD: k.krbtgtPassword,
    KRBTGT_KVNO: String(k.krbtgtKvno)
  };
  Object.assign(env, k.krbtgtKeys);
  // The machine, server and DC credentials are the ACCOUNT principal, which
  // logs in with the shared password (FAST's armor TGT is its).
  ["MAC", "SERVER", "DC"].forEach(function (prefix) {
    env[prefix + "_USERNAME"] = ACCOUNT;
    env[prefix + "_PASSWORD"] = k.password;
    env[prefix + "_KVNO"] = String(k.kvno);
  });
  const accountKeys = await keyEnv("X", k.password, k.accountSalt);
  Object.keys(accountKeys).forEach(function (name) {
    ["MAC", "SERVER", "DC"].forEach(function (prefix) {
      env[name.replace(/^X_/, prefix + "_")] = accountKeys[name];
    });
  });
  if (profile === "account") {
    env.SERVICE_USERNAME = ACCOUNT;
    env.SERVICE_PASSWORD = k.password;
    Object.assign(env, k.accountKeys);
  } else {
    env.SERVICE_USERNAME = profile === "spn" ? HOST : HOST + "$";
    env.SERVICE_PASSWORD = k.servicePassword;
    Object.assign(env, k.hostKeys);
  }
  env.SERVICE_KVNO = String(k.kvno);
  if (trust) {
    env.TRUST_REALM = k.trustedRealm;
  }
  log.debug("Leaving envFor().");
  return env;
}

// One driver run, asynchronously: a synchronous spawn would block the event
// loop for the whole run (enroll_clients_kit.js's lesson).
function runDriver(modules, env, label) {
  log.debug("Entering runDriver(). " + label);
  return new Promise(function (resolve, reject) {
    const child = childProcess.spawn("python3",
      [DRIVER].concat(modules.map(function (m) {
        return MODULE_PREFIX + m;
      })), { env: Object.assign({}, process.env, env) });
    let out = "";
    let err = "";
    const timer = setTimeout(function () {
      child.kill("SIGKILL");
    }, RUN_TIMEOUT_MS);
    child.stdout.on("data", function (b) {
      out += b.toString();
    });
    child.stderr.on("data", function (b) {
      err += b.toString();
    });
    child.on("error", function (e) {
      clearTimeout(timer);
      reject(new Error(label + ": python3 could not be run: " + e.message));
    });
    child.on("close", function (code) {
      clearTimeout(timer);
      const line = out.split("\n").filter(function (one) {
        return one.indexOf(MARKER) === 0;
      }).pop();
      if (!line) {
        reject(new Error(label + ": the driver printed no results (exit " +
                         code + "): " + (err || out).slice(-3000)));
        return;
      }
      if (err) {
        log.debug(label + " stderr: " + err.slice(-4000));
      }
      log.debug("Leaving runDriver(). " + label);
      resolve(JSON.parse(line.slice(MARKER.length)));
    });
  });
}

// Every test module of Samba's krb5 directory — the library modules beside
// them are not tests. Found in the installed tree rather than listed, so a
// module a newer pin adds is run, and reported, without an edit here.
const LIBRARY_MODULES = ["__init__", "raw_testcase", "kdc_base_test",
                         "kcrypto", "rfc4120_constants", "rfc4120_pyasn1",
                         "rfc4120_pyasn1_generated"];

function allModules() {
  log.debug("Entering allModules().");
  const dir = path.join(sambaPythonPath(), "samba", "tests", "krb5");
  const out = fs.readdirSync(dir).filter(function (one) {
    return /\.py$/.test(one) &&
           LIBRARY_MODULES.indexOf(one.replace(/\.py$/, "")) === -1;
  }).map(function (one) {
    return one.replace(/\.py$/, "");
  }).sort();
  log.debug("Leaving allModules(). " + out.length);
  return out;
}

function stripPrefix(id) {
  log.debug("Entering stripPrefix().");
  log.debug("Leaving stripPrefix().");
  return String(id).split(MODULE_PREFIX).join("");
}

async function test() {
  log.debug("Entering test().");
  if (String(process.env.STS_TEST_UNPUBLISHED || "").split(",")
        .indexOf("kerberos") >= 0) {
    declineToRun(log, "this environment does not publish the KDC's TCP 88 " +
                      "(STS_TEST_UNPUBLISHED names kerberos).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  assert.ok(fs.existsSync(path.join(SAMBA_DIR, "SAMBA_VERSION")),
            "Samba is not installed at " + SAMBA_DIR + " (tests/Dockerfile " +
            "builds it; STS_SAMBA_DIR names another)");
  const k = {
    kdcHost: process.env.STS_KDC_HOST || new URL(base).hostname,
    kdcPort: Number(process.env.STS_KDC_PORT ||
                    await facts.setting(api, "krb5.kdcPort") || 88)
  };
  if (k.kdcPort !== 88) {
    // raw_testcase.py dials port 88 and takes no other.
    declineToRun(log, "the KDC is on port " + k.kdcPort + " and Samba's " +
                      "raw tests dial 88 only.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("Samba " + fs.readFileSync(path.join(SAMBA_DIR, "SAMBA_VERSION"),
                                      "utf8").trim() +
           "'s raw Kerberos tests against " + KREALM + " at " + k.kdcHost +
           ":88");
  log.info("=== 0. the realm, its principals and their keys ===");
  await setUp(k);
  k.defaultRealm = String(await facts.setting(api, "krb5.realm") || "");
  k.trustedRealm = String(await facts.setting(api, "krb5.trustedRealm") ||
                          "");
  k.defaultPassword = String(await facts.setting(api, "krb5.userPassword") ||
                             "");
  const product = await facts.isProduct(api);

  const modules = allModules();
  const groups = { host: [], account: [], spn: [], trust: [] };
  modules.forEach(function (m) {
    groups[PROFILE_OF[m] || "host"].push(m);
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "samba-krb5-"));
  const rows = [];
  const loadErrors = [];
  try {
    for (const profile of ["host", "account", "spn", "trust"]) {
      if (!groups[profile].length) {
        continue;
      }
      if (profile === "trust" && (product || !k.trustedRealm)) {
        log.info("=== " + groups[profile].join(", ") + ": NOT APPLICABLE " +
                 "here — the default realm is in product mode, which " +
                 "creates no development trust (kerberos/CLAUDE.md) ===");
        continue;
      }
      log.info("=== 1. " + profile + " profile: " +
               groups[profile].join(", ") + " ===");
      const started = Date.now();
      const result = await runDriver(groups[profile],
                                     await envFor(k, profile, dir), profile);
      result.results.forEach(function (row) {
        rows.push(Object.assign({ profile: profile }, row));
      });
      result.load_errors.forEach(function (one) {
        loadErrors.push(one);
      });
      log.info("  " + result.results.length + " result(s) in " +
               Math.round((Date.now() - started) / 1000) + " s");
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  log.info("=== 2. the outcomes ===");
  const counts = {};
  const skipReasons = {};
  const unexplained = [];
  const excepted = {};
  rows.forEach(function (row) {
    counts[row.outcome] = (counts[row.outcome] || 0) + 1;
    const id = stripPrefix(row.id);
    if (row.outcome === "skip") {
      const reason = String(row.detail).replace(/\(([^)]*)\)/, "(…)")
        .slice(0, 160);
      skipReasons[reason] = (skipReasons[reason] || 0) + 1;
      return;
    }
    if (row.outcome !== "fail" && row.outcome !== "error") {
      return;
    }
    const module = id.split(".")[0].replace(/^setUpClass \(/, "");
    const reason = EXCEPTIONS[id] || MODULE_EXCEPTIONS[module];
    if (reason) {
      excepted[EXCEPTIONS[id] ? id : module] = true;
      log.info("  [exception] " + id + " (" + row.outcome + "): " + reason);
      return;
    }
    const last = String(row.detail).trim().split("\n").pop();
    unexplained.push(id + " [" + row.profile + "] " + row.outcome + ": " +
                     last.slice(0, 300));
  });
  log.info("  outcomes: " + Object.keys(counts).sort().map(function (key) {
    return key + " " + counts[key];
  }).join(", "));
  log.info("  not applicable, by reason:");
  Object.keys(skipReasons).sort().forEach(function (reason) {
    log.info("    " + skipReasons[reason] + " × " + reason);
  });
  Object.keys(EXCEPTIONS).concat(Object.keys(MODULE_EXCEPTIONS))
    .forEach(function (key) {
      if (!excepted[key]) {
        log.info("  [exception not seen] " + key + " — it passed or did not " +
                 "run this time; if that holds, take it off the list.");
      }
    });
  unexplained.forEach(function (line) {
    log.error("  [unexplained] " + line);
  });
  check("every module loaded", function () {
    assert.strictEqual(loadErrors.length, 0, JSON.stringify(loadErrors)
      .slice(0, 2000));
  });
  check("at least " + FLOOR + " of Samba's tests passed against this KDC",
        function () {
    assert.ok((counts.pass || 0) >= FLOOR, "only " + (counts.pass || 0) +
              " passed");
  });
  check("every failure and error is fixed or a documented exception",
        function () {
    assert.strictEqual(unexplained.length, 0, unexplained.length +
      " unexplained:\n" + unexplained.join("\n"));
  });
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_samba")
  .description("#204: Samba's raw Kerberos KDC tests " +
    "(python/samba/tests/krb5) against a development realm's KDC on TCP " +
    "88 — every applicable test run, the AD-only ones skipped by reason, " +
    "every failure fixed or a documented exception.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
