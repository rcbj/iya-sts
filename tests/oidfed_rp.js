// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oidfed_rp.js
//
// ===========================================================================
// THIS SERVICE AS A FEDERATED RELYING PARTY: THE OP'S ISSUER (#933,
// 2026-11-13). The first run of the OpenID Foundation's
// `openid-federation-entity-joined-to-test-federation-rp-test-plan` found
// every happy-path module (`openid-federation-client-test`, and the two
// ID Token negatives that need the flow to reach the token endpoint) left
// WAITING until it timed out. The suite's OpenID Provider publishes
// `openid_provider` metadata with no `issuer`, and
// `oidfed_rp.ts`'s `effectiveRecord()` read the absent value as a wrong
// one (STS-FED-0149, "its issuer is undefined, not its Entity
// Identifier"), so the person never left this service.
//
// OpenID Federation for OpenID Connect 1.1 section 5.1.2: the `issuer` in
// `openid_provider` metadata MUST match the Entity Identifier — so that is
// the one value it can have, and an absent one is that value. In process,
// over stub dependencies (the resolution is a stub; `tests/oidfed_*.js`
// cover the chain itself):
//
//   1. no `issuer`: the relationship is usable, its `fedOpIssuer` is the
//      OP's Entity Identifier, and the request object's `aud` is that
//      identifier; the private_key_jwt's `aud` is the OP's TOKEN ENDPOINT
//      URL, one string (Connect Core 9 — the next run of the plan got past
//      the login and every happy-path module failed the suite's
//      ValidateClientAssertionClaims, which never takes the Entity
//      Identifier at the token endpoint);
//   2. an `issuer` naming another entity is still refused (STS-FED-0149);
//   3. an `issuer` equal to the Entity Identifier is used as before.
// ===========================================================================

const OidfedRp = require('../oidfed/oidfed_rp').OidfedRp;

const log = require('bunyan').createLogger({ name: 'oidfed_rp',
  level: process.env.LOG_LEVEL || 'info' });

const PEER = 'https://op.test/test/a/alias';
const ANCHOR = PEER + '/trust-anchor';
const OURS = 'https://sts.test/realm/rp';

// The suite's own openid_provider metadata, as
// AddOpenIDProviderMetadataToEntityConfiguration builds it: no issuer.
function suiteMetadata(extra) {
  log.debug("Entering suiteMetadata().");
  log.debug("Leaving suiteMetadata().");
  return Object.assign({
    authorization_endpoint: PEER + '/authorize',
    pushed_authorization_request_endpoint: PEER + '/par',
    token_endpoint: PEER + '/token',
    jwks_uri: PEER + '/jwks',
    client_registration_types_supported: ['automatic'],
    request_object_signing_alg_values_supported: ['RS256', 'PS256', 'ES256']
  }, extra || {});
}

function rpOver(metadata) {
  log.debug("Entering rpOver().");
  const deps = {
    log: log,
    baseUrlOf: function () {
      log.debug("Entering baseUrlOf().");
      log.debug("Leaving baseUrlOf().");
      return OURS;
    },
    signingKeys: function () {
      log.debug("Entering signingKeys().");
      log.debug("Leaving signingKeys().");
      return [];
    },
    publishedKidFor: function (kid) {
      log.debug("Entering publishedKidFor().");
      log.debug("Leaving publishedKidFor().");
      return kid;
    },
    // Answers the payload, so what would be signed can be read back.
    signJwtAsAsync: async function (payload) {
      log.debug("Entering signJwtAsAsync().");
      log.debug("Leaving signJwtAsAsync().");
      return JSON.stringify(payload);
    },
    oidfed: function () {
      log.debug("Entering oidfed().");
      log.debug("Leaving oidfed().");
      return {
        resolve: async function () {
          log.debug("Entering resolve().");
          log.debug("Leaving resolve().");
          return { ok: true, resolved: { metadata:
            { openid_provider: metadata }, chain: [] } };
        },
        entityId: function () {
          log.debug("Entering entityId().");
          log.debug("Leaving entityId().");
          return OURS;
        }
      };
    },
    federation: function () {
      log.debug("Entering federation().");
      log.debug("Leaving federation().");
      return {};
    },
    federationSp: function () {
      log.debug("Entering federationSp().");
      log.debug("Leaving federationSp().");
      return {};
    },
    fedHttp: function () {
      log.debug("Entering fedHttp().");
      log.debug("Leaving fedHttp().");
      return {};
    },
    now: function () {
      log.debug("Entering now().");
      log.debug("Leaving now().");
      return Date.now();
    }
  };
  log.debug("Leaving rpOver().");
  return new OidfedRp(deps);
}

const RECORD = { fedId: 'suite', fedRole: 'service-provider',
                 fedProtocol: 'oidc', fedPeer: PEER,
                 fedTrustAnchor: ANCHOR };

async function run(t) {
  log.debug("Entering run().");

  t.log.info('=== 1. an openid_provider with no issuer ===');
  const rp = rpOver(suiteMetadata());
  const got = await rp.effectiveRecord({}, RECORD);
  t.check(got.ok && got.record.fedOpIssuer === PEER &&
          got.record.fedClientId === OURS &&
          got.record.fedSsoUrl === PEER + '/authorize',
          '1a. an absent issuer is the Entity Identifier (Connect 1.1, ' +
          '5.1.2): the relationship is usable and fedOpIssuer is the OP',
          JSON.stringify(got.ok ? got.record.fedOpIssuer : got));
  let aud = null;
  let assertionAud = null;
  if (got.ok) {
    const url = await rp.authorizationRequestUrl(got.record,
      new URLSearchParams({ client_id: OURS, response_type: 'code',
                            scope: 'openid' }));
    aud = JSON.parse(new URL(url).searchParams.get('request')).aud;
    assertionAud = JSON.parse(await rp.clientAssertion(got.record)).aud;
  }
  t.check(aud === PEER,
          '1b. the request object is addressed to the OP\'s Entity ' +
          'Identifier alone (Federation 1.0, 12.1.1.1), never to ' +
          '"undefined"', JSON.stringify(aud));
  // The token endpoint's assertion is NOT the request object's audience:
  // Federation 1.0 holds a client assertion to the Entity Identifier only
  // at the PAR endpoint (12.1.1.2), and says nothing of the token endpoint,
  // so Connect Core 9 governs ("SHOULD be the URL of the Authorization
  // Server's Token Endpoint"). The suite's ValidateClientAssertionClaims
  // refused the Entity Identifier there with "aud mismatch".
  t.check(typeof assertionAud === 'string' &&
          assertionAud === PEER + '/token',
          '1c. the private_key_jwt at the token endpoint is addressed to ' +
          'the token endpoint URL, as one string (Connect Core 9, ' +
          'RFC 7523 3), not to the Entity Identifier',
          JSON.stringify(assertionAud));

  t.log.info('=== 2. an issuer naming somebody else ===');
  const wrong = await rpOver(suiteMetadata(
    { issuer: 'https://elsewhere.test' })).effectiveRecord({}, RECORD);
  t.check(!wrong.ok && wrong.code === 'STS-FED-0149' &&
          /https:\/\/elsewhere\.test/.test(wrong.why),
          '2. an issuer that is present and is not the Entity Identifier ' +
          'is still refused (STS-FED-0149)', JSON.stringify(wrong));

  t.log.info('=== 3. an issuer that is the Entity Identifier ===');
  const same = await rpOver(suiteMetadata({ issuer: PEER }))
    .effectiveRecord({}, RECORD);
  t.check(same.ok && same.record.fedOpIssuer === PEER,
          '3. an issuer equal to the Entity Identifier is used as before',
          JSON.stringify(same.ok ? same.record.fedOpIssuer : same));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidfed_rp',
  describe: 'OpenID Federation for OpenID Connect (#933): this service as ' +
            'a federated relying party reads an OP whose openid_provider ' +
            'metadata carries no issuer as issued by its Entity Identifier, ' +
            'and still refuses one naming somebody else, in process',
  run: run
};
