// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
// File: client_lab.js
// ===========================================================================
// HOW A JOB DRIVES THE CLIENT LAB (#2056): the real clients and the virtual
// smart cards in `tests/client-lab/`, through its agent at CLIENT_LAB_URL.
//
// **THIS IS A HELPER AND NOT A JOB**, and it is OURS (`MANIFEST.js`'s
// LOCAL_HELPERS). tests/CLAUDE.md, *THE CLIENT LAB*, argues the lab.
//
//   available()              CLIENT_LAB_URL is set (a job that needs the lab
//                            carries `clientLab: true`, and the runner skips
//                            it otherwise)
//   ready()                  waits for /health: both cards in their readers
//   run(program, args, o)    one client or bin/ script, to completion:
//                            `{ ok, code, stdout, stdoutBase64, stderr }`;
//                            `o.stdin`, `o.env`, `o.timeoutMs`
//   must(program, args, o)   run(), and an assertion that it exited 0
//   put(path, data)          a file into the lab's work directory
//   get(path)                a file out of it, as a Buffer
//   work(path)               that file's absolute path in the lab
//   newPivCard(variant)      a factory-fresh PIV card, `yubikey` or `stock`
//
// THE LAB HOLDS NOTHING OF THE SERVICE'S: a job hands it the service's TLS
// anchor, a token or a configuration through put().
// ===========================================================================

const assert = require("assert");

const log = require("bunyan").createLogger({ name: "client_lab",
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || "info" });

const WORK = "/run/client-lab/work";
// The readers (tests/client-lab/card-lib.sh).
const OPENPGP_READER = "Virtual PCD 00 00";
const PIV_READER = "Virtual PCD 00 01";
// OpenSC's PKCS#11 module in the lab (Debian's path).
const PKCS11_MODULE = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so";

function url() {
  log.debug("Entering url().");
  log.debug("Leaving url().");
  return String(process.env.CLIENT_LAB_URL || "").replace(/\/+$/, "");
}

/**
 * Whether this run has a client lab.
 *
 * @returns true when CLIENT_LAB_URL is set
 */
function available() {
  log.debug("Entering available().");
  log.debug("Leaving available().");
  return !!url();
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

/**
 * Waits for the lab's agent to answer with both cards in.
 *
 * @param timeoutMs - how long to wait (default two minutes: a JVM per card)
 * @returns the health answer
 */
async function ready(timeoutMs) {
  log.debug("Entering ready().");
  const deadline = Date.now() + (timeoutMs || 120000);
  let last = "";
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url() + "/health");
      const body = await r.text();
      if (r.status === 200) {
        log.debug("Leaving ready().");
        return JSON.parse(body);
      }
      last = r.status + " " + body.slice(0, 200);
    } catch (e) {
      log.debug("Caught in ready(): " + ((e && e.message) || e));
      // Not up yet: the wait is the answer.
      last = String((e && e.message) || e);
    }
    await pause(1000);
  }
  log.debug("Leaving ready(). Timed out.");
  throw new Error("the client lab at " + url() + " did not become ready: " +
                  last);
}

/**
 * Runs one client or bin/ script in the lab, to completion.
 *
 * @param program - its name
 * @param args - its arguments
 * @param o - `stdin` (string or Buffer), `env`, `timeoutMs`
 * @returns `{ ok, code, stdout, stdoutBase64, stderr }`
 */
async function run(program, args, o) {
  log.debug("Entering run(). " + program);
  const opts = o || {};
  const spec = { program: program, args: args || [],
                 env: opts.env || {}, timeoutMs: opts.timeoutMs || 120000 };
  if (Buffer.isBuffer(opts.stdin)) {
    spec.stdinBase64 = opts.stdin.toString("base64");
  } else if (opts.stdin !== undefined) {
    spec.stdin = String(opts.stdin);
  }
  const r = await fetch(url() + "/run", { method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(spec) });
  const text = await r.text();
  assert.strictEqual(r.status, 200, "the lab would not run " + program +
                     ": " + r.status + " " + text.slice(0, 300));
  const answer = JSON.parse(text);
  log.info("lab: " + program + " " + JSON.stringify(spec.args).slice(0, 200) +
           " -> " + answer.code);
  log.debug("Leaving run().");
  return answer;
}

/**
 * run(), asserting the program exited 0.
 *
 * @param program - its name
 * @param args - its arguments
 * @param o - as run()'s
 * @returns run()'s answer
 */
async function must(program, args, o) {
  log.debug("Entering must(). " + program);
  const r = await run(program, args, o);
  assert.strictEqual(r.code, 0, program + " " + JSON.stringify(args || []) +
                     " exited " + r.code + ":\n" + r.stdout.slice(-1500) +
                     "\n" + r.stderr.slice(-1500));
  log.debug("Leaving must().");
  return r;
}

/**
 * Puts a file into the lab's work directory.
 *
 * @param path - relative to the work directory
 * @param data - a string or a Buffer
 * @returns the file's absolute path in the lab
 */
async function put(path, data) {
  log.debug("Entering put(). " + path);
  const r = await fetch(url() + "/files/" + encodeURIComponent(path)
    .replace(/%2F/g, "/"), { method: "PUT",
    headers: { "content-type": "application/octet-stream" },
    body: Buffer.isBuffer(data) ? data : Buffer.from(String(data)) });
  const text = await r.text();
  assert.strictEqual(r.status, 200, "PUT " + path + ": " + r.status + " " +
                     text.slice(0, 200));
  log.debug("Leaving put().");
  return work(path);
}

/**
 * Takes a file out of the lab's work directory.
 *
 * @param path - relative to the work directory
 * @returns its bytes
 */
async function get(path) {
  log.debug("Entering get(). " + path);
  const r = await fetch(url() + "/files/" + encodeURIComponent(path)
    .replace(/%2F/g, "/"));
  const body = Buffer.from(await r.arrayBuffer());
  assert.strictEqual(r.status, 200, "GET " + path + ": " + r.status + " " +
                     body.toString("utf8").slice(0, 200));
  log.debug("Leaving get().");
  return body;
}

/**
 * A file's absolute path in the lab.
 *
 * @param path - relative to the work directory
 * @returns the path
 */
function work(path) {
  log.debug("Entering work().");
  log.debug("Leaving work().");
  return WORK + "/" + String(path).replace(/^\/+/, "");
}

/**
 * Replaces the PIV card with a factory-fresh one.
 *
 * @param variant - `yubikey` (attests as a YubiKey 5) or `stock`
 * @returns the card's serial (yubico-piv-tool -a status)
 */
async function newPivCard(variant) {
  log.debug("Entering newPivCard(). " + variant);
  await must("lab-piv-card", [variant || "yubikey"]);
  const status = await must("yubico-piv-tool", ["-r", PIV_READER, "-a",
                                                "status"]);
  const m = /Serial Number:\s*(-?\d+)/.exec(status.stdout);
  log.debug("Leaving newPivCard().");
  return m ? m[1] : "";
}

module.exports = {
  available: available,
  ready: ready,
  run: run,
  must: must,
  put: put,
  get: get,
  work: work,
  newPivCard: newPivCard,
  OPENPGP_READER: OPENPGP_READER,
  PIV_READER: PIV_READER,
  PKCS11_MODULE: PKCS11_MODULE
};
