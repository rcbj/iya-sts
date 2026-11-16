// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_crl_directory_publication.js
//
// ---------------------------------------------------------------------------
// THE DIRECTORY COPY OF A REALM'S CRL, READ AS A RELYING PARTY READS IT,
// OVER THE LDAP SOCKET.
//
// D12 (#444): carries over what a client can see of
// `tests/crl_directory_publication.js`. A throwaway realm's CA is built, the
// `ldap://` distribution point of a certificate its Intermediate issued is
// read out of that certificate, and the directory is asked over the plain
// LDAP port (`STS_LDAP_PORT`) with NO bind:
//
//   1. in development, a base search of the DN the URL names answers one
//      entry carrying a CRL (DER, a SEQUENCE) — in THIS realm's tree;
//   2. in PRODUCT mode the same unbound base read is still answered — the
//      one exemption from product's refusal of unbound reads;
//   3. and an unbound subtree search of the realm's people is refused
//      there: the exemption is a base read of one list, not a way in.
//
// NOT carried, and why: a list published with no realm ambient (the
// start-up pass and the refresh timer, one `publishAll()` at top level),
// STS-PKI-0185 (a CRL number the shared store could not advance) and
// STS-WORKER-0027 (a read-barrier round) are class (d): a deferred
// publication's realm, a store fault and a worker's lag are not something a
// request can cause.
//
// OWNED HERE (local: true): this repository's own directory and CA.
// ---------------------------------------------------------------------------

const assert = require("assert");
const ldapjs = require("ldapjs");
const K = require("./oauth_wire_kit.js").kit("sts_crl_directory_publication");
const log = K.log;

const FLOOR = 3;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// An unbound search; its entries, or the error it ended with.
function search(base, scope, filter) {
  log.debug("Entering search(). " + scope + " " + base);
  const url = "ldap://" + new URL(K.base).hostname + ":" +
              (process.env.STS_LDAP_PORT || "389");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: url });
    const entries = [];
    const finish = function (out) {
      client.unbind();
      log.debug("Leaving search().");
      resolve(out);
    };
    client.on("error", function (e) {
      log.debug("Caught in search(): " + e.message);
      finish({ error: e.message, entries: entries });
    });
    client.search(base, { scope: scope, filter: filter || "(objectClass=*)",
      attributes: ["certificateRevocationList;binary",
                   "certificateRevocationList"] }, function (err, res) {
      if (err) {
        finish({ error: err.message, entries: entries });
        return;
      }
      res.on("searchEntry", function (entry) {
        entries.push(entry);
      });
      res.on("error", function (e) {
        finish({ error: e.message, entries: entries });
      });
      res.on("end", function (result) {
        finish({ status: result && result.status, entries: entries });
      });
    });
  });
}

function crlOf(entry) {
  log.debug("Entering crlOf().");
  const attrs = (entry && (entry.attributes || entry.pojo &&
                 entry.pojo.attributes)) || [];
  const one = attrs.filter(function (a) {
    return /^certificateRevocationList(;binary)?$/i.test(a.type);
  })[0];
  const raw = one && ((one.buffers && one.buffers[0]) ||
                      (one.values && one.values[0]) ||
                      (one._vals && one._vals[0]));
  log.debug("Leaving crlOf().");
  return raw ? Buffer.from(raw) : null;
}

async function ldapPoint(realm) {
  log.debug("Entering ldapPoint().");
  const jwks = await K.send(K.rb(realm) + "/oauth2/jwks");
  const k = ((jwks.json && jwks.json.keys) || []).filter(function (one) {
    return Array.isArray(one.x5c) && one.x5c.length >= 2;
  })[0];
  assert.ok(k, "no key of " + realm + " carries an x5c chain");
  const der = Buffer.from(k.x5c[1], "base64").toString("latin1");
  const m = /ldap:\/\/[\x21-\x7e]+/.exec(der);
  assert.ok(m, "the certificate names no ldap:// distribution point");
  const dn = /^ldap:\/\/[^/]*\/([^?]*)/.exec(m[0]);
  log.debug("Leaving ldapPoint().");
  return decodeURIComponent(dn[1]);
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("crldir");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "CRL" },
             "built the CA");
  const dn = await ldapPoint(realm);
  const suffix = (realm + ".example.net").split(".").map(function (l) {
    return "dc=" + l;
  }).join(",");
  const dev = await search(dn, "base");
  check("1. in development an unbound base search of the ldap:// DN answers " +
        "one entry carrying a CRL, in this realm's tree", function () {
    assert.ok(!dev.error, dev.error);
    assert.strictEqual(dev.entries.length, 1, dn);
    const crl = crlOf(dev.entries[0]);
    assert.ok(crl && crl[0] === 0x30, "no DER CRL on " + dn);
    assert.ok(dn.toLowerCase().indexOf(suffix.toLowerCase()) >= 0, dn);
  });
  await K.set(realm, "global.mode", "product");
  const prod = await search(dn, "base");
  check("2. in product the same unbound base read is still answered",
        function () {
    assert.ok(!prod.error, prod.error);
    assert.strictEqual(prod.entries.length, 1, dn);
    assert.ok(crlOf(prod.entries[0]), "no CRL on " + dn);
  });
  const people = await search("ou=users," + suffix, "sub");
  check("3. and an unbound subtree search of the realm's people is refused " +
        "there", function () {
    assert.ok(people.error || (people.status && people.status !== 0),
              "answered " + people.entries.length + " entries unbound");
    assert.strictEqual(people.entries.length, 0);
  });
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
