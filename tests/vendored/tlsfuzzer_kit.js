"use strict";
//
// File: tlsfuzzer_kit.js
//
// ===========================================================================
// TLSFUZZER AGAINST THIS SERVICE'S THREE TLS LISTENERS (#212, 2026-09-26).
//
// Not a job. `sts_tlsfuzzer.js` (the main port and LDAPS 636 of a running
// stack) and `tests/tlsfuzzer_debugger.js` (the debugger's listener, which no
// test stack binds) run the same PLAN below through this file.
//
// tlsfuzzer (GPL-2.0) and tlslite-ng (LGPL-2.1) are fetched at pinned
// commits into the tests image by tests/tlsfuzzer/build-tlsfuzzer.sh and are
// never vendored; STS_TLSFUZZER_DIR names where they are (/opt/tlsfuzzer).
// Every script runs UNMODIFIED through tests/tlsfuzzer/sts_adapter.py, which
// answers three facts about the far end no script can be told on its command
// line — each argued in its header:
//
//   --client-cert-request  the main port and the debugger ASK for a client
//                          certificate and require none;
//   --ldap                 LDAPS speaks LDAP, so "GET / HTTP/1.0" becomes an
//                          LDAP bind of the same length;
//   --tls12-aead           TLS 1.2 is BCP 195's ECDHE-RSA AES-GCM and nothing
//                          else, so a TLS 1.2 script's default suites (RSA
//                          key exchange, CBC) are swapped for it.
//
// THE PLAN IS EVERY SCRIPT tlsfuzzer SHIPS, EACH ONE OF THREE THINGS:
//
//   * RUN, with the arguments that fit this service (its groups, signature
//     algorithms, ticket count), and every probe that does not pass named
//     with -x (expected to fail, with the alert it must fail with: -X) or -e
//     (not run) and the REASON — `design` (a choice this service made and
//     documents), `openssl` (Node/OpenSSL behaviour this service cannot
//     change) or `tool` (the probe cannot be pointed at this service). A
//     probe marked -x that passes fails the script (XPASS), so a behaviour
//     that changes cannot go unnoticed;
//   * NOT APPLICABLE, with the reason: the script tests a feature this
//     service does not offer at all (CBC, RSA key exchange, finite-field
//     DHE, heartbeat, PSK, an echo server's replies), or it measures TIMING,
//     which needs a quiet dedicated host and a packet capture;
//   * RUN AS A REFUSAL, where the whole script is an attack or a version
//     this service must refuse (SSLv2, export suites, TLS 1.0 and 1.1).
//
// A script passes when it exits 0 with FAIL: 0 and XPASS: 0 in its summary.
// ===========================================================================

const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

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
var log = bunyan.createLogger({ name: "tlsfuzzer_kit",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const TLSFUZZER_DIR = process.env.STS_TLSFUZZER_DIR || "/opt/tlsfuzzer";
const ADAPTER = path.join(__dirname, "..", "tlsfuzzer", "sts_adapter.py");

// What each listener is, to the adapter.
const LISTENERS = {
  main: { flags: ["--client-cert-request"], requestsCertificate: true,
          label: "the main HTTPS port" },
  ldaps: { flags: ["--ldap"], requestsCertificate: false,
           label: "LDAPS 636" },
  debugger: { flags: ["--client-cert-request"], requestsCertificate: true,
              label: "the debugger's listener" }
};

// PLAN_PLACEHOLDER

// ---------------------------------------------------------------------------
// The command line for one script on one listener.
// ---------------------------------------------------------------------------
function argsFor(entry, listener, target) {
  log.debug("Entering argsFor(). " + entry.script + " " + listener);
  const argv = [ADAPTER].concat(LISTENERS[listener].flags);
  if (entry.tls12) {
    argv.push("--tls12-aead");
  }
  argv.push(path.join(TLSFUZZER_DIR, "tlsfuzzer", "scripts", entry.script),
            "-h", target.host, "-p", String(target.port));
  (entry.args || []).forEach(function (one) {
    argv.push(one);
  });
  if (entry.certificate) {
    const pair = target.certificates && target.certificates[entry.certificate];
    if (!pair) {
      log.debug("Leaving argsFor(). No " + entry.certificate + " pair.");
      throw new Error(entry.script + " needs a " + entry.certificate +
                      " client certificate and none was made");
    }
    argv.push("-k", pair.key, "-c", pair.cert);
  }
  exceptionsFor(entry, listener).forEach(function (one) {
    if (one.exclude) {
      argv.push("-e", one.probe);
    } else {
      argv.push("-x", one.probe);
      if (one.alert) {
        argv.push("-X", one.alert);
      }
    }
  });
  log.debug("Leaving argsFor().");
  return argv;
}

// The exceptions that apply on this listener.
function exceptionsFor(entry, listener) {
  log.debug("Entering exceptionsFor().");
  log.debug("Leaving exceptionsFor().");
  return (entry.exceptions || []).filter(function (one) {
    return !one.on || one.on.indexOf(listener) >= 0;
  });
}

// Whether a script runs on this listener at all.
function appliesTo(entry, listener) {
  log.debug("Entering appliesTo().");
  log.debug("Leaving appliesTo().");
  return !entry.skip && (!entry.on || entry.on.indexOf(listener) >= 0);
}

// The summary block every tlsfuzzer script prints last.
function summarise(out) {
  log.debug("Entering summarise().");
  const counts = {};
  ["TOTAL", "SKIP", "PASS", "XFAIL", "FAIL", "XPASS"].forEach(function (k) {
    const m = new RegExp("^" + k + ":\\s*(\\d+)\\s*$", "m").exec(out);
    counts[k.toLowerCase()] = m ? Number(m[1]) : null;
  });
  const failed = /^FAILED:\n((?:\t.*\n?)+)/m.exec(out);
  counts.failed = failed
    ? failed[1].split("\n").map(function (l) {
      return l.trim();
    }).filter(Boolean) : [];
  const xpassed = /^XPASSED:\n((?:\t.*\n?)+)/m.exec(out);
  counts.xpassed = xpassed
    ? xpassed[1].split("\n").map(function (l) {
      return l.trim();
    }).filter(Boolean) : [];
  log.debug("Leaving summarise().");
  return counts;
}

// One script, asynchronously and with a bound: a spawnSync would hold the
// event loop of the in-process file for as long as the script runs.
function runScript(entry, listener, target) {
  log.debug("Entering runScript(). " + entry.script);
  const argv = argsFor(entry, listener, target);
  const python = path.join(TLSFUZZER_DIR, "venv", "bin", "python");
  const env = Object.assign({}, process.env, {
    PYTHONPATH: [path.join(TLSFUZZER_DIR, "tlsfuzzer"),
                 path.join(TLSFUZZER_DIR, "tlslite-ng")].join(path.delimiter),
    PYTHONUNBUFFERED: "1"
  });
  const bound = entry.timeoutMs || 900000;
  log.debug("Leaving runScript().");
  return new Promise(function (resolve) {
    const started = Date.now();
    const child = childProcess.spawn(python, argv,
      { cwd: path.join(TLSFUZZER_DIR, "tlsfuzzer"), env: env,
        stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", function (chunk) {
      out += chunk;
    });
    child.stderr.on("data", function (chunk) {
      out += chunk;
    });
    const timer = setTimeout(function () {
      child.kill("SIGKILL");
    }, bound);
    child.on("error", function (e) {
      log.debug("Caught in runScript(): " + ((e && e.message) || e));
      out += "\n[could not start " + python + ": " + e.message + "]";
    });
    child.on("close", function (code, signal) {
      clearTimeout(timer);
      const counts = summarise(out);
      const ok = code === 0 && counts.fail === 0 && counts.xpass === 0;
      resolve({ script: entry.script, listener: listener, code: code,
                signal: signal, seconds: Math.round((Date.now() - started) /
                                                    1000),
                counts: counts, ok: ok, output: out,
                command: ["python"].concat(argv).join(" ") });
    });
  });
}

// ---------------------------------------------------------------------------
// The whole plan against one listener, `concurrency` scripts at a time.
// `only` narrows it to scripts whose names contain one of its strings.
// ---------------------------------------------------------------------------
async function runPlan(target, listener, options) {
  log.debug("Entering runPlan(). " + listener);
  const opts = options || {};
  const entries = PLAN.filter(function (entry) {
    return appliesTo(entry, listener) &&
      (!entry.certificate || LISTENERS[listener].requestsCertificate) &&
      (!opts.only || !opts.only.length || opts.only.some(function (o) {
        return entry.script.indexOf(o) >= 0;
      }));
  });
  const results = [];
  let next = 0;
  async function worker() {
    log.debug("Entering worker().");
    while (next < entries.length) {
      const entry = entries[next];
      next += 1;
      const r = await runScript(entry, listener, target);
      (opts.onResult || function () {})(r);
      results.push(r);
    }
    log.debug("Leaving worker().");
  }
  const workers = [];
  for (let i = 0; i < (opts.concurrency || 6); i += 1) {
    workers.push(worker());
  }
  await Promise.all(workers);
  log.debug("Leaving runPlan(). " + results.length + " script(s)");
  return results;
}

// The one line a result is reported as.
function line(r) {
  log.debug("Entering line().");
  const c = r.counts;
  log.debug("Leaving line().");
  return (r.ok ? "[ok] " : "[FAILED] ") + r.listener + " " + r.script +
    " — " + (c.total === null ? "no summary" : c.pass + " passed, " +
    c.xfail + " expected failures, " + c.skip + " skipped, " + c.fail +
    " failed, " + c.xpass + " unexpectedly passed") + " (" + r.seconds +
    " s" + (r.code !== 0 ? ", exit " + r.code : "") + ")" +
    (c.failed.length ? " FAILED: " + c.failed.slice(0, 12).join(" | ") : "") +
    (c.xpassed.length ? " XPASSED: " + c.xpassed.slice(0, 12).join(" | ")
                      : "");
}

// What is not run, and why — logged by each job so the record is in its
// output as well as here.
function notApplicable() {
  log.debug("Entering notApplicable().");
  log.debug("Leaving notApplicable().");
  return PLAN.filter(function (entry) {
    return !!entry.skip;
  });
}

module.exports = {
  PLAN: PLAN,
  LISTENERS: LISTENERS,
  TLSFUZZER_DIR: TLSFUZZER_DIR,
  argsFor: argsFor,
  runPlan: runPlan,
  line: line,
  notApplicable: notApplicable,
  summarise: summarise
};

// ---------------------------------------------------------------------------
// BY HAND: node tests/vendored/tlsfuzzer_kit.js <listener> <host> <port>
//   [script-substring...] — with STS_TLSFUZZER_DIR pointing at a tree
// build-tlsfuzzer.sh made, and STS_TLSFUZZER_CERTS at a directory holding
// <kind>.key and <kind>.crt for each client certificate the plan names.
// ---------------------------------------------------------------------------
if (require.main === module) {
  const [listener, host, port, ...only] = process.argv.slice(2);
  const certDir = process.env.STS_TLSFUZZER_CERTS || "";
  const certificates = {};
  if (certDir) {
    fs.readdirSync(certDir).filter(function (f) {
      return /\.key$/.test(f);
    }).forEach(function (f) {
      const kind = f.replace(/\.key$/, "");
      certificates[kind] = { key: path.join(certDir, f),
                             cert: path.join(certDir, kind + ".crt") };
    });
  }
  runPlan({ host: host, port: Number(port), certificates: certificates },
          listener, { only: only, concurrency: Number(process.env
            .STS_TLSFUZZER_CONCURRENCY || 6),
          onResult: function (r) {
            process.stdout.write(line(r) + "\n");
            if (!r.ok && process.env.STS_TLSFUZZER_OUT) {
              fs.writeFileSync(path.join(process.env.STS_TLSFUZZER_OUT,
                listener + "-" + r.script + ".log"), r.command + "\n" +
                r.output);
            }
          } })
    .then(function (results) {
      const bad = results.filter(function (r) {
        return !r.ok;
      });
      process.stdout.write(results.length + " script(s), " + bad.length +
                           " failed\n");
      process.exit(bad.length ? 1 : 0);
    });
  void os;
}
