// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scim_client_rules.ts
//
// ---------------------------------------------------------------------------
// THE OUTBOUND SCIM CLIENT'S CLOSED VOCABULARIES AND ITS ADDRESS RULES (#552).
//
// A LEAF, and a static utility class, so `common/applications.js` can offer
// the closed sets on a client's entry (`ATTRIBUTE_CHOICES`, lazily) without
// loading the client — which requires the directory, the queue and the
// scheduler — and so the register, the console's view and the sender judge an
// address by ONE rule. It requires nothing of this service but the logger.
//
// THE ADDRESS RULES ARE RFC 7644's: TLS (section 7.2: "the service provider
// and client MUST require TLS"), no user information in the URI (section
// 7.1: credentials go in the Authorization header and never in a URI), and a
// base URI with no query or fragment (section 1.3: the client appends the
// path and the query). Plain http is admitted only where the caller says
// development allows it (`scimClient.allowHttp`, development mode).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');

/**
 * The closed vocabularies of an outbound SCIM client, and the rule its two
 * addresses are held to.
 *
 * A static utility class; it holds no state and requires nothing but the
 * logger.
 */
class ScimClientRules {
  /**
   * How a request to the service provider is authenticated: HTTP Basic, an
   * OAuth 2.0 bearer token, or only the TLS client certificate.
   */
  static readonly AUTH_METHODS = Object.freeze(['basic', 'oauth2', 'none']);

  /**
   * How the client authenticates at the token endpoint (RFC 6749 section
   * 2.3.1).
   */
  static readonly OAUTH_CLIENT_AUTH = Object.freeze(['client_secret_basic',
                                                     'client_secret_post']);

  /**
   * Where the TLS client certificate comes from.
   */
  static readonly TLS_SOURCES = Object.freeze(['none', 'issued', 'uploaded']);

  /**
   * Who is pushed: every person, the members of chosen groups, or the people
   * an LDAP filter matches.
   */
  static readonly SCOPE_MODES = Object.freeze(['all', 'groups', 'filter']);

  /**
   * Which groups are pushed.
   */
  static readonly GROUP_MODES = Object.freeze(['none', 'selected',
                                               'member-groups', 'all']);

  /**
   * What a deprovisioned person becomes there.
   */
  static readonly DEPROVISION = Object.freeze(['deactivate', 'delete']);

  /**
   * Says what is wrong with a base URI or a token endpoint, or '' when
   * nothing is.
   *
   * @param value - the URL
   * @param what - what it is, for the sentence
   * @param httpAllowed - true where development admits plain http
   * @param base - true for the SCIM base URI, which carries no query
   * @returns the sentence, or ''
   */
  static urlProblem(value: unknown, what: string, httpAllowed: boolean,
                    base: boolean): string {
    helpers.log.debug("Entering ScimClientRules.urlProblem(). " + what);
    const text = String(value == null ? '' : value).trim();
    if (!text) {
      helpers.log.debug("Leaving ScimClientRules.urlProblem(). Empty.");
      return 'No ' + what + ' is set.';
    }
    let parsed: URL;
    try {
      parsed = new URL(text);
    } catch (e) {
      helpers.log.debug("Caught in ScimClientRules.urlProblem(): " +
                        ((e && (e as Error).message) || e));
      helpers.log.debug("Leaving ScimClientRules.urlProblem(). Not a URL.");
      return 'The ' + what + ' "' + text + '" is not an absolute URL.';
    }
    if (parsed.protocol !== 'https:' &&
        !(parsed.protocol === 'http:' && httpAllowed)) {
      helpers.log.debug("Leaving ScimClientRules.urlProblem(). Scheme.");
      return 'The ' + what + ' must be https (RFC 7644 section 7.2 requires ' +
             'TLS); plain http is admitted only in development mode with ' +
             'scimClient.allowHttp on.';
    }
    if (parsed.username || parsed.password) {
      helpers.log.debug("Leaving ScimClientRules.urlProblem(). Userinfo.");
      return 'The ' + what + ' may not carry a user name or password (RFC ' +
             '7644 section 7.1): set the credential instead.';
    }
    if (parsed.hash || (base && parsed.search)) {
      helpers.log.debug("Leaving ScimClientRules.urlProblem(). Query.");
      return 'The ' + what + ' may not carry ' +
             (base ? 'a query or ' : '') + 'a fragment (RFC 7644 section 1.3).';
    }
    helpers.log.debug("Leaving ScimClientRules.urlProblem(). Usable.");
    return '';
  }

  /**
   * Builds an RFC 7644 section 3.4.2.2 equality filter, the value as a JSON
   * string literal so a quote or a backslash in it cannot end the literal.
   *
   * @param attribute - the attribute path
   * @param value - the value
   * @returns the filter
   */
  static eqFilter(attribute: string, value: unknown): string {
    helpers.log.debug("Entering ScimClientRules.eqFilter(). " + attribute);
    helpers.log.debug("Leaving ScimClientRules.eqFilter().");
    return attribute + ' eq ' + JSON.stringify(String(value == null ? ''
                                                                   : value));
  }

  /**
   * Whether an HTTP status is worth another attempt: 429 and the transient
   * server errors. 501 Not Implemented is a fact about the service provider,
   * and 4xx a fact about the request; neither changes on a second try.
   *
   * @param status - the status
   * @returns true for 408, 429, 500, 502, 503 and 504
   */
  static retryable(status: number): boolean {
    helpers.log.debug("Entering ScimClientRules.retryable(). " + status);
    const answer = [408, 429, 500, 502, 503, 504].indexOf(Number(status)) >= 0;
    helpers.log.debug("Leaving ScimClientRules.retryable(). " + answer);
    return answer;
  }
}

export = ScimClientRules;
