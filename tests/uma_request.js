// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/uma_request.js
//
// ---------------------------------------------------------------------------
// THE USER-MANAGED ACCESS FACTS (#1168 phase 1, #1190): `uma(facts)` writes
// every fact in its category, forces the action-id by layer, leaves an
// unknown requesting party OUT (never '' — the missing-attribute rule
// stands on it), spells every identifier under urn:sts:xacml:uma:, and
// is mirrored by name in the Rust builder.
//
//   A. the categories: resource, action, subject, environment
//   B. the action-id by layer, and the scope on every layer
//   C. nobody is not a subject called ''
//   D. the gathered claims, under the prefix, and nothing a caller could
//      forge: every identifier is in urn:sts:xacml:, which the AuthZEN and
//      FGA catalogues refuse
//   E. the Rust builder declares every UMA_* identifier VOCABULARY declares
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'uma_request',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const xacmlRequest = require('../xacml/xacml_request');
const model = require('../xacml/xacml_model');
const catalogue = require('../authzen/authzen_catalogue');
const V = xacmlRequest.VOCABULARY;

function categoryOf(request, id) {
  log.debug("Entering categoryOf().");
  log.debug("Leaving categoryOf().");
  return request.categories.filter(function (one) {
    return one.category === id;
  })[0] || null;
}

function valuesOf(request, categoryId, attributeId) {
  log.debug("Entering valuesOf().");
  const category = categoryOf(request, categoryId);
  const found = category ? category.attributes.filter(function (one) {
    return one.attributeId === attributeId;
  })[0] : null;
  log.debug("Leaving valuesOf().");
  return found ? found.values.map(function (v) {
    return v.lexical;
  }) : null;
}

function facts(over) {
  log.debug("Entering facts().");
  log.debug("Leaving facts().");
  return Object.assign({
    realm: 'acme', layer: 'realm', stage: 'assess', scope: 'read',
    resource: { id: 'res-1', type: 'photo', resourceServer: 'photos-rs',
                resourceServerDeclared: true, owner: 'urn:uuid:owner',
                ownerKind: 'user' },
    requestingParty: { id: 'urn:uuid:bob', kind: 'user', known: true,
                       isOwner: false, claimSource: 'session',
                       claimIssuer: '', claimIssuerDeclared: true,
                       acr: 'phr' },
    clientId: 'viewer', clientGrantDeclared: true,
    claims: { email: ['bob@example.com'], groups: ['staff', 'ops'] },
    ticketAgeS: 12.9, rptPresented: false, mode: 'development',
    settings: { 'uma.partialRpt': true, 'uma.rptLifetimeS': 600 }
  }, over || {});
}

function build(over) {
  log.debug("Entering build().");
  log.debug("Leaving build().");
  return new xacmlRequest.AuthorizationRequest({}).uma(facts(over)).build();
}

function theCategories(t) {
  log.debug("Entering theCategories().");
  t.log.info('=== A. the categories ===');
  const S = model.CATEGORY.ACCESS_SUBJECT;
  const R = model.CATEGORY.RESOURCE;
  const A = model.CATEGORY.ACTION;
  const E = model.CATEGORY.ENVIRONMENT;
  const built = build({});
  t.check(valuesOf(built, R, model.ATTRIBUTE.RESOURCE_ID).join() === 'res-1' &&
          valuesOf(built, R, V.UMA_RESOURCE_TYPE).join() === 'photo' &&
          valuesOf(built, R, V.UMA_RESOURCE_SERVER).join() === 'photos-rs' &&
          valuesOf(built, R, V.UMA_RESOURCE_SERVER_DECLARED).join() ===
            'true' &&
          valuesOf(built, R, V.UMA_OWNER).join() === 'urn:uuid:owner' &&
          valuesOf(built, R, V.UMA_OWNER_KIND).join() === 'user',
          'A1. the resource: its id, type, resource server (and whether it ' +
          'is declared), owner and owner kind', JSON.stringify(built));
  t.check(valuesOf(built, S, model.ATTRIBUTE.SUBJECT_ID).join() ===
            'urn:uuid:bob' &&
          valuesOf(built, S, V.SUBJECT_KIND).join() === 'user' &&
          valuesOf(built, S, V.CLIENT_ID).join() === 'viewer' &&
          valuesOf(built, S, V.UMA_REQUESTING_PARTY_KNOWN).join() === 'true' &&
          valuesOf(built, S, V.UMA_REQUESTING_PARTY_IS_OWNER).join() ===
            'false' &&
          valuesOf(built, S, V.UMA_CLAIM_SOURCE).join() === 'session' &&
          valuesOf(built, S, V.UMA_CLAIM_ISSUER_DECLARED).join() === 'true' &&
          valuesOf(built, S, V.UMA_CLIENT_GRANT_DECLARED).join() === 'true' &&
          valuesOf(built, S, V.ACR).join() === 'phr',
          'A2. the requesting party: who, how known, the client, the acr');
  const booleans = categoryOf(built, S).attributes.filter(function (one) {
    return [V.UMA_REQUESTING_PARTY_KNOWN, V.UMA_REQUESTING_PARTY_IS_OWNER,
            V.UMA_CLAIM_ISSUER_DECLARED, V.UMA_CLIENT_GRANT_DECLARED]
      .indexOf(one.attributeId) >= 0;
  });
  t.check(booleans.length === 4 && booleans.every(function (one) {
    return one.values[0].type === model.TYPE.BOOLEAN;
  }), 'A3. the four subject facts are booleans, typed as such');
  t.check(valuesOf(built, E, V.PROTOCOL).join() === 'uma' &&
          valuesOf(built, E, V.GRANT_TYPE).join() ===
            xacmlRequest.UMA_GRANT_TYPE &&
          valuesOf(built, E, V.REALM).join() === 'acme' &&
          valuesOf(built, E, V.UMA_LAYER).join() === 'realm' &&
          valuesOf(built, E, V.UMA_STAGE).join() === 'assess' &&
          valuesOf(built, E, V.UMA_TICKET_AGE).join() === '12' &&
          valuesOf(built, E, V.UMA_RPT_PRESENTED).join() === 'false' &&
          valuesOf(built, E, V.MODE).join() === 'development' &&
          valuesOf(built, E, V.SETTING_PREFIX + 'uma.partialRpt').join() ===
            'true' &&
          valuesOf(built, E, V.SETTING_PREFIX + 'uma.rptLifetimeS').join() ===
            '600',
          'A4. the environment: protocol uma, the UMA grant type, the ' +
          'realm, layer, stage, the ticket age as a whole number of ' +
          'seconds, whether an RPT was presented, the mode and the settings');
  t.check(valuesOf(built, A, V.UMA_SCOPE).join() === 'read',
          'A5. the scope is on the action category under uma:scope');
  log.debug("Leaving theCategories().");
}

function theForcedAction(t) {
  log.debug("Entering theForcedAction().");
  t.log.info('=== B. the action-id by layer ===');
  const A = model.CATEGORY.ACTION;
  const realm = build({ layer: 'realm' });
  const owner = build({ layer: 'owner' });
  const fga = build({ layer: 'fga' });
  const stray = build({ layer: 'anything-else' });
  t.check(valuesOf(realm, A, model.ATTRIBUTE.ACTION_ID).join() ===
            xacmlRequest.UMA_PERMISSION_ACTION &&
          valuesOf(fga, A, model.ATTRIBUTE.ACTION_ID).join() ===
            xacmlRequest.UMA_FGA_ACTION &&
          valuesOf(owner, A, model.ATTRIBUTE.ACTION_ID).join() === 'read',
          'B1. the realm layer asks issue-uma-permission, the FGA layer ' +
          'grant-uma-permission, and the owner layer the scope itself');
  t.check(valuesOf(stray, model.CATEGORY.ENVIRONMENT, V.UMA_LAYER).join() ===
            'realm' &&
          valuesOf(stray, A, model.ATTRIBUTE.ACTION_ID).join() ===
            xacmlRequest.UMA_PERMISSION_ACTION,
          'B2. a layer nobody knows is the realm\'s, whose action is forced');
  [realm, owner, fga].forEach(function (one, i) {
    t.check(valuesOf(one, A, V.UMA_SCOPE).join() === 'read',
            'B3.' + (i + 1) + ' the scope is on every layer under uma:scope');
  });
  t.check(xacmlRequest.UMA_LAYERS.join() === 'realm,owner,fga' &&
          xacmlRequest.UMA_STAGES.join() === 'assess,upgrade,approval' &&
          valuesOf(build({ stage: 'upgrade' }), model.CATEGORY.ENVIRONMENT,
                   V.UMA_STAGE).join() === 'upgrade' &&
          valuesOf(build({ stage: 'nonsense' }), model.CATEGORY.ENVIRONMENT,
                   V.UMA_STAGE).join() === 'assess',
          'B4. the three layers and three stages; an unknown stage is assess');
  log.debug("Leaving theForcedAction().");
}

function nobody(t) {
  log.debug("Entering nobody().");
  t.log.info('=== C. nobody is not a subject called \'\' ===');
  const S = model.CATEGORY.ACCESS_SUBJECT;
  const built = build({ requestingParty: { known: false } });
  const subject = categoryOf(built, S);
  t.check(valuesOf(built, S, model.ATTRIBUTE.SUBJECT_ID) === null &&
          !subject.attributes.some(function (one) {
            return one.attributeId === V.SUBJECT_KIND;
          }) &&
          valuesOf(built, S, V.CLIENT_ID).join() === 'viewer' &&
          valuesOf(built, S, V.UMA_REQUESTING_PARTY_KNOWN).join() === 'false' &&
          valuesOf(built, S, V.UMA_REQUESTING_PARTY_IS_OWNER).join() ===
            'false',
          'C1. with no requesting party there is no subject-id and no ' +
          'subject kind at all; the client and the two booleans stay',
          JSON.stringify(built));
  const empty = build({ requestingParty: { id: '', known: false } });
  t.check(valuesOf(empty, S, model.ATTRIBUTE.SUBJECT_ID) === null,
          'C2. an empty id is nobody too');
  const declared = build({ requestingParty: { known: false,
                                              claimIssuerDeclared: undefined },
                           clientGrantDeclared: undefined });
  t.check(valuesOf(declared, S, V.UMA_CLAIM_ISSUER_DECLARED).join() ===
            'true' &&
          valuesOf(declared, S, V.UMA_CLIENT_GRANT_DECLARED).join() ===
            'false',
          'C3. an unstated claim issuer is declared (no token was pushed); ' +
          'an unstated client declaration is false');
  log.debug("Leaving nobody().");
}

function theClaims(t) {
  log.debug("Entering theClaims().");
  t.log.info('=== D. the gathered claims, and the namespace ===');
  const S = model.CATEGORY.ACCESS_SUBJECT;
  const built = build({});
  t.check(valuesOf(built, S, V.UMA_CLAIM_PREFIX + 'email').join() ===
            'bob@example.com' &&
          valuesOf(built, S, V.UMA_CLAIM_PREFIX + 'groups').join() ===
            'staff,ops',
          'D1. each gathered claim is a subject attribute under the prefix, ' +
          'a bag where it had several values');
  const scalar = build({ claims: { dept: 'ops', skipped: null } });
  t.check(valuesOf(scalar, S, V.UMA_CLAIM_PREFIX + 'dept').join() === 'ops' &&
          (valuesOf(scalar, S, V.UMA_CLAIM_PREFIX + 'skipped') || [])
            .length === 0,
          'D2. a scalar claim is a bag of one; a null value is left out');
  const strangers = Object.keys(V).filter(function (name) {
    return name.indexOf('UMA_') === 0 &&
           V[name].indexOf('urn:sts:xacml:uma:') !== 0;
  });
  t.check(strangers.length === 0 && V.ACR === 'urn:sts:xacml:acr',
          'D3. every UMA identifier is in urn:sts:xacml:uma:, and the acr ' +
          'fact is urn:sts:xacml:acr', strangers.join(', '));
  // THE CATALOGUES REFUSE THE NAMESPACE (#1168's rule): a row an AuthZEN
  // caller or a detail type could write cannot name a UMA fact.
  const refused = [V.UMA_OWNER, V.UMA_REQUESTING_PARTY_IS_OWNER,
                   V.UMA_CLAIM_PREFIX + 'email', V.ACR]
    .map(function (id) {
      const read = catalogue.rowsOf([JSON.stringify({
        object: 'subject', property: 'x', attributeId: id })]);
      return read.rows.length === 0 && read.problems.length === 1;
    });
  t.check(refused.every(Boolean),
          'D4. the AuthZEN catalogue refuses a row naming a UMA fact, so a ' +
          'caller\'s property cannot forge one', JSON.stringify(refused));
  log.debug("Leaving theClaims().");
}

function theRustMirror(t) {
  log.debug("Entering theRustMirror().");
  t.log.info('=== E. the Rust builder spells every UMA identifier ===');
  const builder = fs.readFileSync(
    path.join(ROOT, 'rust/crates/sts-xacml/src/builder.rs'), 'utf8');
  const rust = {};
  const pattern = /pub const ([A-Z_]+): &str =\s*"([^"]+)";/g;
  let found = pattern.exec(builder);
  while (found) {
    rust[found[1]] = found[2];
    found = pattern.exec(builder);
  }
  const missing = Object.keys(V).filter(function (name) {
    return (name.indexOf('UMA_') === 0 || name === 'ACR') &&
           rust[name] !== V[name];
  });
  t.check(missing.length === 0,
          'E1. every UMA_* identifier and ACR is declared in the Rust ' +
          'builder with the same spelling', missing.join(', '));
  log.debug("Leaving theRustMirror().");
}

async function run(t) {
  log.debug("Entering run().");
  theCategories(t);
  theForcedAction(t);
  nobody(t);
  theClaims(t);
  theRustMirror(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'uma_request',
  describe: 'the User-Managed Access facts (#1168 phase 1): every category, ' +
            'the action-id forced by layer, nobody left out rather than ' +
            'named \'\', the gathered claims under their prefix, the ' +
            'namespace the catalogues refuse, and the Rust mirror',
  run: run
};
