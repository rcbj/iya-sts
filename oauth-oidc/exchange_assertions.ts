// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oauth-oidc/exchange_assertions.ts
//
// ===========================================================================
// AN ASSERTION FROM A DECLARED ISSUER, EXCHANGED (#114, 2026-10-03).
//
// RFC 8693 section 3 names the token types `jwt`, `saml2` and `saml1`, and
// nothing in RFC 7521, 7522 or 7523 limits an assertion to the grant and
// client-authentication uses they define; section 2.1 leaves validation to
// the authorization server. So an RFC 7523 JWT, an RFC 7522 SAML 2.0
// assertion or a SAML 1.1 assertion signed by an issuer this realm DECLARED
// is accepted as a subject_token or an actor_token — verified by the same
// code the assertion grant uses (`assertion_grant.js`, rule 3x;
// `saml_assertion_grant.js`, rule 3z): the declaration, the signature and
// chain, revocation, the person-as-issuer rule, the lifetime ceiling and the
// one-spend history, which is SHARED with the grant (rcbj, #114): one
// assertion is spent once, whichever door spends it, and only when tokens
// are issued.
//
// WHAT THE EXCHANGE DECIDES OTHERWISE, each a stated rule:
//
//   * THE AUDIENCE — `oauth2.tokenExchangeAudience`. `authorization-server`
//     (the default, rcbj's decision) is the grant's rule: the assertion is
//     addressed to this token endpoint or issuer. `any-declared-relying-
//     party` also accepts an audience naming an application registered in
//     this realm — TOKEN FORWARDING, recorded on the act as such.
//   * THE SAML RECIPIENT — the token endpoint, and under forwarding an
//     assertion consumer service registered on the EXCHANGING client (a
//     browser-SSO assertion's Recipient is its ACS).
//   * WHO MAY EXCHANGE IT — #186's delegation policy, as for any subject
//     token, with no rule of this file's (rcbj, #114). What the policy needs
//     is S, the application the subject's token was issued FOR: an assertion
//     addressed to this authorization server was issued for whoever presents
//     it, so S is the exchanging client; a forwarded one was issued for the
//     relying party its audience names.
//
// A LIBRARY with no route and no store. The token endpoint provisions the
// subject and speaks the refusal; this file verifies and says what it found.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import applications = require('../common/applications');
import mode = require('../common/mode');
import assertionGrant = require('./assertion_grant');
import samlAssertionGrant = require('./saml_assertion_grant');

const { log } = helpers;

type Json = any;

// RFC 8693 section 3's three assertion types.
const TYPES = {
  jwt: 'urn:ietf:params:oauth:token-type:jwt',
  saml2: 'urn:ietf:params:oauth:token-type:saml2',
  saml1: 'urn:ietf:params:oauth:token-type:saml1'
};

/**
 * Verifies an assertion presented as an RFC 8693 subject_token or
 * actor_token (#114).
 */
class ExchangeAssertions {
  /**
   * The audience rule in force in the ambient realm.
   *
   * @returns `authorization-server` or `any-declared-relying-party`
   */
  static audienceRule(): string {
    log.debug("Entering ExchangeAssertions.audienceRule().");
    const value = String(config.value('oauth2.tokenExchangeAudience') ||
                         'authorization-server');
    log.debug("Leaving ExchangeAssertions.audienceRule(). " + value);
    return value === 'any-declared-relying-party' ? value
                                                  : 'authorization-server';
  }

  // The application an audience value names, '' for none: as an OAuth
  // audience, a client_id, a WS-Trust AppliesTo or SAML entityID, or an
  // identifier.
  private static applicationNamed(value: string): string {
    log.debug("Entering ExchangeAssertions.applicationNamed().");
    const found = applications.forAudience(value) ||
      applications.forClientId(value) || applications.forAppliesTo(value) ||
      applications.get(value) || null;
    // In product only a REGISTERED one (#496): an entry a development
    // sighting filed is not "an application registered in this realm", the
    // sentence the audience rule states.
    if (found && !mode.issuesToUnregisteredApplications() &&
        !String(found.registeredBy || '')) {
      log.debug("Leaving ExchangeAssertions.applicationNamed(). " +
                found.identifier + " is not registered.");
      return '';
    }
    log.debug("Leaving ExchangeAssertions.applicationNamed().");
    return found ? String(found.identifier) : '';
  }

  // The assertion consumer services registered on the exchanging client.
  private static clientAcs(clientId: string): string[] {
    log.debug("Entering ExchangeAssertions.clientAcs().");
    const row = applications.forClientId(clientId) ||
      applications.get(clientId) || null;
    const raw = row && row.fields
      ? row.fields.samlAssertionConsumerService : undefined;
    const out = [].concat(raw === undefined || raw === null ? [] : raw)
      .map(String).filter(Boolean);
    log.debug("Leaving ExchangeAssertions.clientAcs(). " + out.length);
    return out;
  }

  /**
   * Verifies one assertion presented to the token exchange.
   *
   * @param input - `{ token, type, base, issuer, clientId, clientSecret,
   *   request }`: the token as presented, its declared type, this realm's
   *   base URL and issuer, the exchanging client, its secret (for a JWT
   *   encrypted to it) and the request (so it is spent only if tokens are
   *   issued)
   * @returns a promise of `{ ok, format, issuer, subject, claims, audience,
   *   forwarded, relyingParty, id, issuerKind, application }` or `{ ok:
   *   false, errorCode, error, description }`
   */
  static async verify(input: Json): Promise<Json> {
    log.debug("Entering ExchangeAssertions.verify(). " + input.type);
    const base = String(input.base || '');
    const asServer = [base + '/oauth2/token', String(input.issuer || ''),
                      base].filter(Boolean);
    const rule = ExchangeAssertions.audienceRule();
    const forwarding = rule === 'any-declared-relying-party';
    // THE AUDIENCE RULE: this authorization server always; under
    // forwarding, also an application registered here. Answers the audience
    // it accepted.
    let relyingParty = '';
    const audienceCheck = function (auds: string[]): string {
      log.debug("Entering audienceCheck().");
      const ours = auds.filter(function (one) {
        return asServer.indexOf(one) >= 0;
      })[0];
      if (ours) {
        log.debug("Leaving audienceCheck(). This server.");
        return ours;
      }
      if (forwarding) {
        for (let i = 0; i < auds.length; i++) {
          const app = ExchangeAssertions.applicationNamed(auds[i]);
          if (app) {
            relyingParty = app;
            log.debug("Leaving audienceCheck(). A relying party.");
            return auds[i];
          }
        }
      }
      log.debug("Leaving audienceCheck(). None.");
      return '';
    };
    const audienceRule = forwarding
      ? 'it must name this authorization server (' + asServer.join(' or ') +
        ') or an application registered in this realm'
      : 'it must name this authorization server (' + asServer.join(' or ') +
        '); `any-declared-relying-party` would also accept a registered ' +
        'relying party';
    let checked: Json;
    let format: string;
    if (input.type === TYPES.jwt) {
      format = 'jwt';
      checked = await assertionGrant.verify({
        assertion: String(input.token || ''), use: 'token-exchange',
        audiences: asServer, audienceCheck: audienceCheck,
        audienceRule: audienceRule, clientSecret: input.clientSecret,
        request: input.request, requestingClientId: input.clientId
      });
    } else if (input.type === TYPES.saml2 || input.type === TYPES.saml1) {
      format = input.type === TYPES.saml1 ? 'saml11' : 'saml';
      checked = await samlAssertionGrant.verify({
        assertion: String(input.token || ''), use: 'token-exchange',
        samlVersion: input.type === TYPES.saml1 ? '1.1' : '2.0',
        audiences: asServer, audienceCheck: audienceCheck,
        audienceRule: audienceRule,
        recipients: forwarding
          ? ExchangeAssertions.clientAcs(String(input.clientId || '')) : [],
        request: input.request, requestingClientId: input.clientId
      });
    } else {
      log.debug("Leaving ExchangeAssertions.verify(). Not an assertion.");
      return { ok: false, errorCode: 'STS-OAUTH-0627',
               error: 'invalid_request',
               description: String(input.type) + ' is not an assertion ' +
                            'type.' };
    }
    if (!checked || !checked.ok) {
      log.debug("Leaving ExchangeAssertions.verify(). Refused: " +
                (checked && checked.errorCode));
      // RFC 8693 section 2.2.2: an invalid subject_token or actor_token is
      // invalid_request, whatever the grant would have called it.
      return Object.assign({}, checked || {}, { ok: false,
                                                error: 'invalid_request' });
    }
    // The audience accepted: the SAML verifier answers it; for a JWT it is
    // the rule asked again of the verified `aud`.
    const audience = String(checked.matchedAudience ||
      audienceCheck([].concat(checked.claims && checked.claims.aud !==
        undefined ? checked.claims.aud : []).map(String)) || '');
    const out = {
      ok: true, format: format,
      issuer: String(checked.issuer || ''),
      subject: String(checked.subject || ''),
      claims: checked.claims || {},
      audience: audience,
      // TOKEN FORWARDING: the assertion was addressed to a relying party
      // registered here rather than to this server — recorded on the act.
      forwarded: !!relyingParty && asServer.indexOf(audience) < 0,
      relyingParty: relyingParty,
      id: String(checked.id || (checked.claims && checked.claims.jti) || ''),
      issuerKind: String(checked.issuerKind || ''),
      application: String(checked.application || '')
    };
    log.debug("Leaving ExchangeAssertions.verify(). " + format + " from " +
              out.issuer + " about " + out.subject);
    return out;
  }

  /**
   * Whether a declared token type is one of the three assertion types.
   *
   * @param type - the declared token type
   * @returns true for jwt, saml2 and saml1
   */
  static isAssertionType(type: string): boolean {
    log.debug("Entering ExchangeAssertions.isAssertionType().");
    const out = type === TYPES.jwt || type === TYPES.saml2 ||
                type === TYPES.saml1;
    log.debug("Leaving ExchangeAssertions.isAssertionType(). " + out);
    return out;
  }
}

/**
 * Assertions from declared issuers as RFC 8693 subject and actor tokens.
 * @namespace
 */
export = {
  ExchangeAssertions: ExchangeAssertions,
  TYPES: TYPES,
  audienceRule: ExchangeAssertions.audienceRule,
  verify: ExchangeAssertions.verify,
  isAssertionType: ExchangeAssertions.isAssertionType
};
