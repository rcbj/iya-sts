// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: canonical_digest_proto.js
//
// ===========================================================================
// A `__proto__` MEMBER IS PART OF WHAT IS DIGESTED (2026-11-12).
//
// Three canonicalisers sort an object's members before hashing it:
// `FgaMap.digest()` (a fine-grained type definition's digest, which a policy
// may pin), `FgaPep.detailDigest()` (an RFC 9396 detail's digest on the
// audit row) and `AuthzenSearch.fingerprintOf()` (what ties an AuthZEN page
// token to the request it continues). Each copied the members with
// `out[key] = …` onto a fresh `{}`, and an assignment of `__proto__` there
// sets the copy's prototype and adds no member — so `{"a":1,"__proto__":
// {"b":2}}` hashed as `{"a":1}`. Since #1688 a `__proto__` member is read as
// data, so two inputs that behave differently shared one digest.
//
//   A. each digest tells a `__proto__` member apart from its absence, and
//      from a different `__proto__` value, at the top and nested;
//   B. BACKWARDS COMPATIBILITY: for inputs with no `__proto__` member, each
//      digest is byte-identical to the one the old canonicaliser gives
//      (reproduced here), so no pinned digest, audit row or page token
//      issued before the fix changes;
//   C. member order still does not matter, `__proto__` included.
//
// WHY IN PROCESS: all three are pure functions of their input.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('../common/crypto');
const fgaMap = require('../xacml/fga_map');
const fgaPep = require('../xacml/fga_pep');
const authzenSearch = require('../authzen/authzen_search');

// The canonicaliser as it was before the fix, for B.
function oldCanonical(value) {
  if (Array.isArray(value)) {
    return value.map(oldCanonical);
  }
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).sort().forEach(function (key) {
      out[key] = oldCanonical(value[key]);
    });
    return out;
  }
  return value;
}

const ORDINARY = [
  { type: 'document_access', actions: ['read', 'write'],
    locations: ['https://rs.example.com/'],
    datatypes: { nested: { z: 1, a: [true, null, 'x'] } } },
  { type: 'payment', instructedAmount: { currency: 'EUR', amount: '12.50' },
    creditorName: 'Merchant A', constructor: 'a plain member',
    toString: 'another' },
  { type: 'empty' }
];

module.exports = {
  name: 'canonical_digest_proto',
  describe: 'a __proto__ member is digested by FGA and the AuthZEN page ' +
            'fingerprint, and every other digest is unchanged',
  run: function (t) {
    t.log.debug("Entering run().");
    const search = new authzenSearch.AuthzenSearch({ crypto: crypto });
    const pep = fgaPep.FgaPep.defaultDeps ?
      new fgaPep.FgaPep(fgaPep.FgaPep.defaultDeps()) : null;
    const digests = {
      'FgaMap.digest': function (v) {
        return fgaMap.digest(v);
      },
      'FgaPep.detailDigest': function (v) {
        return pep.detailDigest(v);
      },
      'AuthzenSearch.fingerprintOf': function (v) {
        return search.fingerprintOf('resource', v);
      }
    };
    const oldDigests = {
      'FgaMap.digest': function (v) {
        return crypto.sha256Hex(JSON.stringify(oldCanonical(v)));
      },
      'FgaPep.detailDigest': function (v) {
        return crypto.sha256Hex(JSON.stringify(oldCanonical(v)));
      },
      'AuthzenSearch.fingerprintOf': function (v) {
        return String(crypto.sha256Hex('resource ' +
          JSON.stringify(oldCanonical(JSON.parse(JSON.stringify(v))))))
          .slice(0, 16);
      }
    };
    t.check(!!pep, 'an FgaPep can be built');
    // JSON.parse makes `__proto__` an own member, as every body parser does.
    const plain = JSON.parse('{"type":"t","a":1}');
    const withProto = JSON.parse('{"type":"t","a":1,"__proto__":{"b":2}}');
    const otherProto = JSON.parse('{"type":"t","a":1,"__proto__":{"b":3}}');
    const reordered = JSON.parse('{"__proto__":{"b":2},"a":1,"type":"t"}');
    const nested = JSON.parse('{"type":"t","x":{"__proto__":{"b":2}}}');
    const nestedPlain = JSON.parse('{"type":"t","x":{}}');
    Object.keys(digests).forEach(function (name) {
      const d = digests[name];
      t.check(d(withProto) !== d(plain),
              name + ': a __proto__ member changes the digest');
      t.check(d(withProto) !== d(otherProto),
              name + ': a different __proto__ value changes it');
      t.equal(d(reordered), d(withProto),
              name + ': member order around __proto__ does not');
      t.check(d(nested) !== d(nestedPlain),
              name + ': a nested __proto__ member changes it');
      ORDINARY.forEach(function (value, i) {
        t.equal(d(value), oldDigests[name](value),
                name + ': ordinary input ' + i + ' digests as before');
      });
      t.equal(d(plain), oldDigests[name](plain),
              name + ': the input without __proto__ digests as before');
    });
    // The definition's other spellings still agree with the object.
    t.equal(fgaMap.digest(JSON.stringify(ORDINARY[0])),
            fgaMap.digest(ORDINARY[0]),
            'FgaMap.digest: a definition as text digests as its object');
    t.log.debug("Leaving run().");
  }
};
