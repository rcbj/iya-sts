// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/oauth7-vectors.js
//
// ---------------------------------------------------------------------------
// THE `oauth7` SLICE'S VECTORS (#444, phase 5): what
// `rust/crates/sts-oauth/tests/oauth7_vectors.rs` reads, run by
// `crypto-vectors.js` (`oauth7-node.json`) in a child of its own.
//
//   identities  admin_stats.identityOf(presented): the key the identity
//               funnel files a person under;
//   personas    vc_claims.personaFor(name)'s names and address: what an
//               entry the funnel creates in development is given;
//   claims      oauth2.parseClaimsRequest(raw): OIDC Core 5.5's request as
//               understood, or the sentence refusing it, verified_claims
//               among it (Identity Assurance section 6);
//   matches     identity_assurance.matches() and project() over a request
//               and a recorded verification;
//   accepts     introspection_jwt.wantsJwt(accept): RFC 9701's content
//               negotiation.
//
// And `checkRust()`: the same five, computed by Rust over the same inputs
// (`oauth7-rust.json`), computed again by Node. A builder is a tool, not
// service code, and logs nothing.
// ---------------------------------------------------------------------------

const path = require('path');

const PRESENTED = ['alice', 'alice@EXAMPLE.COM', 'urn:sts:user:bob',
  'cn=Carol,o=Example,emailAddress=carol@example.com',
  'did:jwk:eyJrdHkiOiJFQyJ9', 'urn:uuid:00000000-0000-4000-8000-000000000001',
  '  dave  ', 'a@b@realm.example', ''];

const NAMES = ['alice', 'bob', 'ro-user-123', 'Ünïcødé', 'somebody', '',
  'alice@EXAMPLE.COM', 'oidc-core-1731667200000-dave'];

const CLAIMS = [
  '',
  '{"userinfo":{"email":null,"given_name":{"essential":true}}}',
  '{"id_token":{"acr":{"values":["urn:a","urn:b"]}},"other":{}}',
  '{"userinfo":[1]}',
  '{"userinfo":{"x":"y"}}',
  '{"userinfo":{"x":{"essential":"yes"}}}',
  '{"userinfo":{"x":{"values":[]}}}',
  'not json',
  '[1,2]',
  '{"userinfo":{"verified_claims":{"claims":{"given_name":null}}}}',
  '{"userinfo":{"verified_claims":{"verification":{},' +
    '"claims":{"given_name":null}}}}',
  '{"userinfo":{"verified_claims":{"verification":' +
    '{"trust_framework":null},"claims":{}}}}',
  '{"userinfo":{"verified_claims":{"verification":' +
    '{"trust_framework":{"value":"eidas"},"evidence":[{"type":' +
    '{"value":"document"},"document_details":{"type":null}}]},' +
    '"claims":{"given_name":null,"family_name":null,' +
    '"birthdate":{"purpose":"To check your age"}}}},' +
    '"id_token":{"verified_claims":{"verification":' +
    '{"trust_framework":{"value":"de_aml"}},' +
    '"claims":{"given_name":null}}}}',
  '{"id_token":{"verified_claims":[{"verification":' +
    '{"trust_framework":null},"claims":{"name":{"purpose":"ab"}}}]}}',
  '{"id_token":{"verified_claims":[]}}'
];

const RECORD = { trust_framework: 'eidas', assurance_level: 'high',
  evidence: [{ type: 'document', check_details: [{ check_method: 'vpip' }],
    document_details: { type: 'passport', document_number: 'P1' } }] };

const MATCHES = [
  [{ trust_framework: { value: 'eidas' } }, RECORD],
  [{ trust_framework: { value: 'de_aml' } }, RECORD],
  [{ trust_framework: { values: ['x', 'eidas'] } }, RECORD],
  [{ trust_framework: null, evidence: [{ type: { value: 'document' },
    document_details: { type: null } }] }, RECORD],
  [{ trust_framework: null, evidence: [{ type: { value: 'vouch' } }] },
   RECORD],
  [{ trust_framework: null, assurance_level: null }, RECORD],
  [{ given_name: null, address: { locality: null } },
   { given_name: 'A', address: { locality: 'L', country: 'US' } }]
];

const ACCEPTS = ['', 'application/json',
  'application/token-introspection+jwt',
  'application/token-introspection+jwt, application/json;q=0.5',
  'application/token-introspection+jwt;q=0.4, application/json',
  'application/token-introspection+jwt;q=0', '*/*',
  'application/token-introspection+jwt;q=0.9, */*'];

// `matches()` and `project()` are the class's, not facades.
function assurance(ROOT) {
  const ida = require(path.join(ROOT, 'common', 'identity_assurance'));
  return new ida.IdentityAssurance(ida.IdentityAssurance.defaultDeps());
}

function claimsAnswer(oauth2, raw) {
  const parsed = oauth2.parseClaimsRequest(raw);
  return parsed.error ? { error: parsed.error }
                      : { claims: parsed.claims || null };
}

async function build(ROOT) {
  const out = { problems: [] };
  try {
    // THE COMPOSITION ROOT FIRST: it installs every instance, and a module
    // a facade had already built refuses the second install.
    require(path.join(ROOT, 'common', 'protocol_stack'));
    const stats = require(path.join(ROOT, 'common', 'admin_stats'));
    out.identities = PRESENTED.map(function (one) {
      const id = stats.identityOf(one);
      return { presented: one, key: id.key, realm: id.realm,
               unresolved: !!id.unresolved };
    });
    const vcClaims = require(path.join(ROOT, 'oid4vc', 'vc_claims'));
    out.personas = NAMES.map(function (one) {
      const p = vcClaims.personaFor(one);
      return { name: one, username: p.username, given: p.given,
               family: p.family, display: p.display, email: p.email };
    });
    const ida = assurance(ROOT);
    out.matches = MATCHES.map(function (pair) {
      const projected = ida.project(pair[0], pair[1]);
      return { request: pair[0], actual: pair[1],
               matches: ida.matches(pair[0], pair[1]),
               projected: projected === undefined ? null : projected };
    });
    const introspectionJwt = require(path.join(ROOT, 'oauth-oidc',
                                               'introspection_jwt'));
    out.accepts = ACCEPTS.map(function (one) {
      return { accept: one, jwt: introspectionJwt.wantsJwt(one) };
    });
    const oauth2 = require(path.join(ROOT, 'oauth-oidc', 'oauth2'));
    out.claims = CLAIMS.map(function (raw) {
      return Object.assign({ raw: raw }, claimsAnswer(oauth2, raw));
    });
  } catch (e) {
    out.problems.push(String((e && e.stack) || e));
  }
  return out;
}

// THE OTHER DIRECTION: what Rust computed, computed again here.
function checkRust(ROOT, rows, check) {
  const same = function (a, b) {
    return JSON.stringify(a) === JSON.stringify(b);
  };
  require(path.join(ROOT, 'common', 'protocol_stack'));
  const stats = require(path.join(ROOT, 'common', 'admin_stats'));
  (rows.identities || []).forEach(function (row) {
    const id = stats.identityOf(row.presented);
    check(id.key === row.key && id.realm === row.realm,
          'oauth7: Node folds what Rust folded (' + row.presented + ')',
          id.key + '@' + id.realm + ' vs ' + row.key + '@' + row.realm);
  });
  const vcClaims = require(path.join(ROOT, 'oid4vc', 'vc_claims'));
  (rows.personas || []).forEach(function (row) {
    const p = vcClaims.personaFor(row.name);
    check(p.given === row.given && p.family === row.family &&
          p.email === row.email,
          'oauth7: Node invents the person Rust invented (' + row.name + ')',
          p.display + ' <' + p.email + '> vs ' + row.display + ' <' +
          row.email + '>');
  });
  const ida = assurance(ROOT);
  (rows.matches || []).forEach(function (row) {
    const projected = ida.project(row.request, row.actual);
    check(ida.matches(row.request, row.actual) === row.matches &&
          same(projected === undefined ? null : projected, row.projected),
          'oauth7: Node matches and projects as Rust did',
          JSON.stringify(row.request));
  });
  const introspectionJwt = require(path.join(ROOT, 'oauth-oidc',
                                             'introspection_jwt'));
  (rows.accepts || []).forEach(function (row) {
    check(introspectionJwt.wantsJwt(row.accept) === row.jwt,
          'oauth7: Node negotiates the JWT answer as Rust did (' +
          row.accept + ')', String(row.jwt));
  });
  const oauth2 = require(path.join(ROOT, 'oauth-oidc', 'oauth2'));
  (rows.claims || []).forEach(function (row) {
    const mine = claimsAnswer(oauth2, row.raw);
    const theirs = row.error !== undefined ? { error: row.error }
                                           : { claims: row.claims };
    check(same(mine, theirs),
          'oauth7: Node parses the claims request as Rust did (' +
          String(row.raw).slice(0, 40) + ')',
          JSON.stringify(mine) + ' vs ' + JSON.stringify(theirs));
  });
}

module.exports = { build: build, checkRust: checkRust };
