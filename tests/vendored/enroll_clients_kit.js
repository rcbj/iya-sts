"use strict";
//
// File: enroll_clients_kit.js
//
// ===========================================================================
// WHAT THE FIVE REAL-CLIENT ENROLLMENT JOBS SHARE (#207-#211, 2026-09-26).
//
// Not a job. `sts_acme_certbot.js`, `sts_acme_lego.js`, `sts_est_libest.js`,
// `sts_scep_sscep.js` and `sts_scep_micromdm.js` each drive one real client
// — built at a pinned version into the tests image (tests/Dockerfile, *THE
// FIVE CERTIFICATE ENROLLMENT CLIENTS*) — against the running service, and
// they need the same few things around it:
//
//   * the management API (a throwaway realm, its CA, people, host names,
//     settings), through the token the runner's preload presents;
//   * a TRUST BUNDLE FILE the clients can read. Node's jobs are handed
//     NODE_EXTRA_CA_CERTS; a Python, Go or C client reads a file of its own
//     (REQUESTS_CA_BUNDLE, LEGO_CA_CERTIFICATES, EST_OPENSSL_CACERT,
//     SSL_CERT_FILE), so the kit writes one holding the service Root and
//     whatever the runner handed over;
//   * a way to RUN a client that records what it said and never hangs:
//     `run()` is spawnSync with a bound, the arguments logged with every
//     secret masked;
//   * the portal's sign-in, for the one scenario in which the credential is
//     one the PERSON made (#210: a SCEP challenge from /portal/certificates);
//   * a reader for the CRL, to see a client's revocation land.
//
// Nothing from acme/, est/, scep/ or common/cert_enrollment.ts is loaded:
// the service is only ever reached over the wire.
// ===========================================================================

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const nodeCrypto = require("crypto");
const os = require("os");
const path = require("path");
const facts = require("./service_facts.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "enroll_clients_kit",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const asn1js = require(path.join(REPO, "node_modules", "asn1js"));
const pkijs = require(path.join(REPO, "node_modules", "pkijs"));

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

function realmApi(realm) {
  log.debug("Entering realmApi().");
  log.debug("Leaving realmApi().");
  return realm ? base + "/realm/" + realm + "/admin-api"
               : base + "/admin-api";
}

// A counter of checks per job, and the one line each passing check logs.
function checker(logger) {
  log.debug("Entering checker().");
  const self = {
    count: 0,
    check: function (what, fn) {
      logger.debug("Entering check().");
      fn();
      self.count += 1;
      logger.info("  [ok] " + what);
      logger.debug("Leaving check().");
    }
  };
  log.debug("Leaving checker().");
  return self;
}

async function send(url, options) {
  log.debug("Entering send().");
  const r = await fetch(url, options);
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — the raw text says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving send().");
  return { status: r.status, body: parsed, raw: raw, headers: r.headers };
}

async function post(url, body) {
  log.debug("Entering post().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) });
  log.debug("Leaving post().");
  return r;
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await post(url, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + JSON.stringify((r.body && (r.body.errors || r.body.why)) || r.body)
      .slice(0, 500));
  log.debug("Leaving ok().");
  return r.body;
}

async function setting(realm, key, value) {
  log.debug("Entering setting(). key=" + key);
  await ok(realmApi(realm) + "/config/set", { key: key, value: value },
           "set " + key);
  log.debug("Leaving setting().");
}

// A throwaway realm with its certificate authority built, left standing
// (tests/CLAUDE.md, *No job removes a realm*).
async function makeRealm(realm, name) {
  log.debug("Entering makeRealm(). realm=" + realm);
  await ok(realmApi(null) + "/realms/create",
           { id: realm, domain: realm + ".example.net", name: name },
           "created the trust realm " + realm);
  await ok(realmApi(realm) + "/pki/build",
           { organisation: name, country: "US" },
           "built the certificate authority of " + realm);
  log.debug("Leaving makeRealm().");
}

// A person with a GENERATED password, answered once — verified in product
// mode, so the jobs hold for both modes.
async function makePerson(realm, who, mail) {
  log.debug("Entering makePerson(). who=" + who);
  const made = await ok(realmApi(realm) + "/users/create",
    { username: who, invent: false, credential: "generate",
      attributes: { cn: who, sn: who, mail: mail } },
    "created " + who);
  assert.ok(made.password, "users/create answered no generated password");
  log.debug("Leaving makePerson().");
  return made.password;
}

// Whether the realm under test is in product mode — read, not assumed
// (`service_facts.js`); a realm inherits the process's mode.
async function isProduct(realm) {
  log.debug("Entering isProduct().");
  const answer = await facts.isProduct(realmApi(realm));
  log.debug("Leaving isProduct(). " + answer);
  return answer;
}

// ---------------------------------------------------------------------------
// THE TRUST BUNDLE A CLIENT READS.
//
// The service Root (every certificate this service presents chains to it)
// and, after it, whatever the runner handed this job as NODE_EXTRA_CA_CERTS
// — the certificate the main port presents, re-read before each job
// (tests/tools/run-report.js, refreshTrust()). Written once per job.
// ---------------------------------------------------------------------------
async function trustBundle(dir) {
  log.debug("Entering trustBundle().");
  const r = await fetch(base + "/pki/ca/service/root.cer");
  assert.strictEqual(r.status, 200, "the service Root is published");
  const root = new nodeCrypto.X509Certificate(
    Buffer.from(await r.arrayBuffer()));
  let extra = "";
  if (process.env.NODE_EXTRA_CA_CERTS) {
    try {
      extra = fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS, "utf8");
    } catch (e) {
      log.debug("Caught in trustBundle(): " + ((e && e.message) || e));
      // The Root alone is the anchor every presented chain ends at; the
      // extra file only helps a stack whose listener is not issued by it.
      extra = "";
    }
  }
  const file = path.join(dir, "trust-bundle.pem");
  fs.writeFileSync(file, root.toString() + "\n" + extra);
  log.debug("Leaving trustBundle().");
  return { file: file, root: root };
}

function scratch(prefix) {
  log.debug("Entering scratch().");
  log.debug("Leaving scratch().");
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

// ---------------------------------------------------------------------------
// RUN A CLIENT.
//
// A child process with a bound (a client waiting on a prompt must not hold
// the job to the runner's watchdog), stdin given when asked, and the command
// logged with every value in `secrets` masked. Answers the exit status and
// both streams joined, which is what each job reads — estclient exits 0 on
// every failure, so its jobs read what it printed and wrote.
//
// **ASYNCHRONOUS, NOT spawnSync, AND THAT IS A FIX.** The first version
// blocked the event loop for the whole of a client's run; the service
// closed the job's idle keep-alive connection meanwhile (its keep-alive
// timeout is seconds), node never processed the close, and the job's next
// fetch() went out on the dead socket: `fetch failed … other side closed`
// straight after every slow certbot command.
// ---------------------------------------------------------------------------
function run(command, args, options) {
  log.debug("Entering run(). command=" + command);
  const opts = options || {};
  const secrets = (opts.secrets || []).filter(Boolean);
  const mask = function (text) {
    let out = String(text);
    secrets.forEach(function (one) {
      out = out.split(String(one)).join("<secret>");
    });
    return out;
  };
  log.info("  $ " + mask(command + " " + args.join(" ")));
  log.debug("Leaving run(). Started.");
  return new Promise(function (resolve) {
    let stdout = "";
    let stderr = "";
    let failed = null;
    let timer = null;
    const child = childProcess.spawn(command, args, {
      cwd: opts.cwd,
      env: Object.assign({}, process.env, opts.env || {}) });
    const finish = function (status) {
      clearTimeout(timer);
      const output = stdout + stderr;
      if (failed) {
        log.info("    (the process could not be run: " + failed.message +
                 ")");
      }
      log.debug("    exit " + status + ", output: " + mask(output));
      resolve({ status: status, stdout: stdout, stderr: stderr,
                output: output, error: failed,
                shown: mask(output).slice(-3000) });
    };
    timer = setTimeout(function () {
      failed = new Error("still running after " +
                         (opts.timeoutMs || 120000) + " ms; killed");
      child.kill("SIGKILL");
    }, opts.timeoutMs || 120000);
    child.stdout.on("data", function (d) {
      stdout += d;
    });
    child.stderr.on("data", function (d) {
      stderr += d;
    });
    child.on("error", function (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      // A binary that is not there: answered as a failed run, which is
      // what every caller asserts against.
      failed = e;
    });
    child.on("close", function (code) {
      finish(code === null ? -1 : code);
    });
    child.stdin.on("error", function (e) {
      log.debug("Caught in run() writing stdin: " + ((e && e.message) || e));
      // A client that exits before reading its input closes the pipe.
    });
    child.stdin.end(opts.input || "");
  });
}

// The lines of a client's output or log that are warnings or errors, less
// the ones a job has recorded as a documented exception (`allowed`, a list
// of regular expressions, each argued where the job passes it).
function problemLines(text, pattern, allowed) {
  log.debug("Entering problemLines().");
  const lines = String(text).split(/\r?\n/).filter(function (line) {
    return pattern.test(line) && !(allowed || []).some(function (re) {
      return re.test(line);
    });
  });
  log.debug("Leaving problemLines(). count=" + lines.length);
  return lines;
}

// ---------------------------------------------------------------------------
// CERTIFICATES.
// ---------------------------------------------------------------------------
function pemChain(text) {
  log.debug("Entering pemChain().");
  log.debug("Leaving pemChain().");
  return (String(text).match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [])
    .map(function (pem) {
      return new nodeCrypto.X509Certificate(pem);
    });
}

function serialOf(x) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return String(x.serialNumber).toLowerCase().replace(/^(00)+/, "");
}

// The leaf chains, one certificate at a time, to `root`; every link is
// checked by OpenSSL through node's X509Certificate.
function chainsTo(chain, root) {
  log.debug("Entering chainsTo().");
  for (let i = 0; i + 1 < chain.length; i += 1) {
    assert.ok(chain[i].checkIssued(chain[i + 1]) &&
              chain[i].verify(chain[i + 1].publicKey),
              "certificate " + i + " (" + chain[i].subject + ") is not " +
              "signed by the next (" + chain[i + 1].subject + ")");
  }
  const last = chain[chain.length - 1];
  assert.ok(last.checkIssued(root) && last.verify(root.publicKey),
            "the chain's last certificate is not signed by the service Root");
  log.debug("Leaving chainsTo().");
}

async function crlSerials(realm, ca) {
  log.debug("Entering crlSerials(). ca=" + ca);
  const r = await fetch(base + "/pki/crl/" + realm + "/" + ca + ".crl");
  const bytes = Buffer.from(await r.arrayBuffer());
  assert.strictEqual(r.status, 200, "the " + ca + " CRL is published");
  const crl = new pkijs.CertificateRevocationList({ schema: asn1js.fromBER(
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength))
    .result });
  log.debug("Leaving crlSerials().");
  return (crl.revokedCertificates || []).map(function (entry) {
    return Buffer.from(entry.userCertificate.valueBlock.valueHexView)
      .toString("hex").replace(/^(00)+/, "");
  });
}

// A key and a PKCS#10 made with the `openssl` command at run time — the
// tool an operator of these clients makes them with. `subject` is an
// openssl -subj string; `sans` an -addext value or empty; `challenge` the
// challengePassword attribute or empty.
async function opensslRequest(dir, name, spec) {
  log.debug("Entering opensslRequest(). name=" + name);
  const keyFile = path.join(dir, name + ".key");
  const csrFile = path.join(dir, name + ".csr");
  const conf = path.join(dir, name + ".cnf");
  const lines = ["[req]", "prompt=no", "distinguished_name=dn",
                 "attributes=attrs", "[dn]"];
  String(spec.subject || "").split("/").filter(Boolean).forEach(
    function (rdn) {
      lines.push(rdn);
    });
  lines.push("[attrs]");
  if (spec.challenge) {
    lines.push("challengePassword=" + spec.challenge);
  }
  fs.writeFileSync(conf, lines.join("\n") + "\n");
  const args = ["req", "-new", "-newkey", spec.newkey || "rsa:2048", "-nodes",
                "-keyout", keyFile, "-out", csrFile, "-config", conf];
  if (spec.sans) {
    args.push("-addext", "subjectAltName=" + spec.sans);
  }
  const r = await run("openssl", args, { secrets: [spec.challenge] });
  assert.strictEqual(r.status, 0, "openssl req failed: " + r.shown);
  log.debug("Leaving opensslRequest().");
  return { key: keyFile, csr: csrFile };
}

// ---------------------------------------------------------------------------
// THE PORTAL, SIGNED IN AS A PERSON OF A REALM.
//
// `sts_portal_certificates.js`'s browser, under a realm's prefix: the portal
// is an OpenID Connect relying party of the realm's own authorization
// server, so the sign-in is the code flow followed by hand.
// ---------------------------------------------------------------------------
function formBody(o) {
  log.debug("Entering formBody().");
  log.debug("Leaving formBody().");
  return new URLSearchParams(o).toString();
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

function browser() {
  log.debug("Entering browser().");
  const self = {
    jar: {},
    async go(method, where, body) {
      log.debug("Entering go().");
      const headers = {};
      const cookie = Object.keys(self.jar).map(function (k) {
        return k + "=" + self.jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const url = /^https?:\/\//i.test(String(where)) ? String(where)
                                                     : base + String(where);
      const r = await fetch(url, { method: method, redirect: "manual",
                                   headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const key = pair.split("=")[0];
        const value = pair.slice(key.length + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete self.jar[key];
        } else {
          self.jar[key] = value;
        }
      });
      log.debug("Leaving go().");
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text() };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

async function portalSignIn(realm, who, password) {
  log.debug("Entering portalSignIn(). who=" + who);
  const page = "/realm/" + realm + "/portal/certificates";
  const b = browser();
  let r = await b.go("GET", page);
  assert.ok(/\/oauth2\/authorize\?/.test(r.location),
    "an unauthenticated browser should be sent to the authorization " +
    "endpoint; it answered " + r.status + " -> " + r.location);
  for (let hops = 0; hops < 4 && r.location &&
       !/name="authn_id"/.test(r.text); hops += 1) {
    r = await b.go("GET", r.location);
  }
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id.");
  r = await b.go("POST", "/realm/" + realm + "/authn/login",
                 formBody({ authn_id: authnId, username: who,
                            password: password, action: "login",
                            csrf_token: csrfOf(r.text) }));
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in should end in a redirect; got " + r.status + " " +
    r.text.slice(0, 300));
  for (let hops = 0; hops < 6 && r.location; hops += 1) {
    r = await b.go("GET", r.location);
  }
  assert.strictEqual(r.status, 200, "the portal page after sign-in: " +
                     r.status);
  log.debug("Leaving portalSignIn().");
  return {
    async post(fields) {
      log.debug("Entering portal post().");
      const form = await b.go("GET", page);
      const answer = await b.go("POST", page,
        formBody(Object.assign({ csrf_token: csrfOf(form.text) }, fields)));
      log.debug("Leaving portal post().");
      return answer;
    }
  };
}

pkijs.setEngine("node", new pkijs.CryptoEngine({
  name: "node", crypto: nodeCrypto.webcrypto }));

module.exports = {
  base: base,
  realmApi: realmApi,
  checker: checker,
  send: send,
  post: post,
  ok: ok,
  setting: setting,
  makeRealm: makeRealm,
  makePerson: makePerson,
  isProduct: isProduct,
  trustBundle: trustBundle,
  scratch: scratch,
  run: run,
  problemLines: problemLines,
  pemChain: pemChain,
  serialOf: serialOf,
  chainsTo: chainsTo,
  crlSerials: crlSerials,
  opensslRequest: opensslRequest,
  portalSignIn: portalSignIn
};
