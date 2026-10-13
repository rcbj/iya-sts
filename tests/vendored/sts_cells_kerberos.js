// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_cells_kerberos.js
//
// ===========================================================================
// KERBEROS ON PORT 88 AT A CELL THAT DOES NOT HOLD THE PERSON (#98 D2, #588,
// 2026-10-12).
//
// A person's long-term keys, sign-out instant and disabled flag are in their
// home cell. Until #588 a request on a visiting cell's raw TCP 88 was
// answered THERE — KDC_ERR_C_PRINCIPAL_UNKNOWN in product, where every cell
// of this stack runs — while MS-KKDCP was already relayed home. The KDC now
// asks a message router (`kerberos/krb5_home.ts`) before it answers, and a
// message whose client is homed elsewhere travels as the inter-cell
// operation `kdc-message`. For a person homed at cell A, in the default trust
// realm (whose Kerberos is on in every stack), over TCP at cell B's KDC:
//
//   1. an AS exchange with the right password gets a TGT — keyed at home;
//   2. a wrong password is KDC_ERR_PREAUTH_FAILED (24): home answered, and
//      said no — not C_PRINCIPAL_UNKNOWN (6), which is the visiting cell
//      answering for somebody it does not hold;
//   3. the TGT buys a service ticket at cell B (a TGS-REQ is routed by the
//      ticket's client);
//   4. after a sign-out at cell A, the same TGT at cell B is refused
//      KDC_ERR_TGT_REVOKED (20): the instant is the home cell's, and a cell
//      that answered the TGS-REQ itself would never have seen it.
//
// THE CLIENT is `krb5_wire.js` beside this file, over TCP, rather than MIT's
// or Heimdal's kinit: the runner image carries no Kerberos client, and the
// Heimdal job's container (sts_kerberos_heimdal.js) is a stack of its own.
// UDP is not driven here; the visiting cell holds a relayed reply to the
// same size limit as its own, and that is tests/cell_handlers_c.js's.
//
// `local: true`: a stack only this repository's launcher builds. It declines
// to run in every mode but `cells`. The person is left behind, like every
// person a cells job makes.
// ===========================================================================
"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const expectation = require("./expectation.js");
const kit = require("./cells_kit.js");
const wire = require("./krb5_wire.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

const log = require("bunyan").createLogger({ name: "sts_cells_kerberos",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const PERSON = "cells-krb-" + STAMP;
const PASSWORD = "Cells-krb5-" + STAMP + "-Aa1!";
// How long the person's keys and their routing-index row may take to reach
// where cell B's KDC finds them: the keys are derived when the password is
// set (sts_kerberos_spnego.js argues the number), and the row is written when
// cell A's store is flushed (cells_kit.js, homed()).
const READY_WAIT_MS = 30000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function codeOf(result) {
  log.debug("Entering codeOf().");
  const e = result && ((result.second && result.second.error) ||
                       (result.first && result.first.error) ||
                       (!result.ok && result.error));
  log.debug("Leaving codeOf().");
  return e ? e.code : null;
}

// The AS exchange at cell B, waiting out the window in which the person is
// not yet keyed at home or not yet in the routing index. Only the refusals
// that window produces are retried, and the bound is the failure.
async function signIn(tcp, realm, password) {
  log.debug("Entering signIn().");
  const started = Date.now();
  for (;;) {
    const r = await wire.asExchange(tcp, realm, PERSON,
                                    { password: password });
    const e = (r.second && r.second.error) || (r.first && r.first.error);
    if (!(!r.tgt && e && (e.code === 6 ||
          /no Kerberos keys yet|sign in once|nobody by that name/i
            .test(e.eText)) && Date.now() - started < READY_WAIT_MS)) {
      log.debug("Leaving signIn().");
      return r;
    }
    await pause(500);
  }
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "second cell's KDC to ask.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const realm = String(await kit.settingAt(cells.a, "krb5.realm") || "");
  const port = Number(await kit.settingAt(cells.b, "krb5.kdcPort") || 88);
  const spn = String(await kit.settingAt(cells.a, "krb5.servicePrincipal") ||
                     "");
  assert.ok(realm && spn, "the service reports no krb5.realm or " +
            "krb5.servicePrincipal");
  const host = new URL(cells.b).hostname;
  const tcp = wire.tcpTransport(host, port);
  log.info("realm " + realm + "; cell B's KDC at " + host + ":" + port);

  const made = await kit.createPerson(cells.a, PERSON, PASSWORD, "");
  check("the person is created at cell A, homed there", function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  });

  const first = await signIn(tcp, realm, PASSWORD);
  check("an AS exchange at cell B's TCP 88 with the right password gets a " +
        "TGT: the request was answered at home", function () {
          assert.ok(first.tgt, "no TGT: " +
                    JSON.stringify(first.second || first.first)
                      .slice(0, 400));
        });

  const wrong = await wire.asExchange(tcp, realm, PERSON,
                                      { password: PASSWORD + "-wrong" });
  check("a wrong password is KDC_ERR_PREAUTH_FAILED (24) — home answered " +
        "and said no — not C_PRINCIPAL_UNKNOWN (6) from cell B", function () {
          assert.strictEqual(codeOf(wrong), 24,
                             JSON.stringify(wrong.second || wrong.first)
                               .slice(0, 400));
        });

  const service = { type: 3, name: spn.split("/") };
  const before = await wire.tgsExchange(tcp, first.tgt, service);
  check("the TGT buys a ticket for " + spn + " at cell B", function () {
    assert.ok(before.ok, before.error && before.error.toString());
  });

  const out = await kit.api(cells.a, "POST", "/logout/global",
                            { user: PERSON });
  check("a global sign-out at cell A", function () {
    assert.ok(out.status === 200 && out.body && out.body.ok,
              out.status + " " + out.raw.slice(0, 300));
  });
  const refused = await wire.tgsExchange(tcp, first.tgt, service);
  check("the TGT from before it is refused KDC_ERR_TGT_REVOKED (20) at " +
        "cell B: the sign-out instant is the home cell's", function () {
          assert.strictEqual(codeOf(refused), 20,
                             refused.ok ? "it was ACCEPTED"
                                        : refused.error.toString());
        });

  assert.ok(checks >= 6, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_kerberos")
  .description("an AS and a TGS exchange at cell B's TCP 88 for a person " +
      "homed at cell A are answered at home.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
