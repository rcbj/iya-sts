// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_placement.ts
//
// ---------------------------------------------------------------------------
// WHICH CELL SERVES A REQUEST (#98 D9, D10, 2026-09-28).
//
// Every cell answers on the same public name, so a request arrives at the cell
// DNS chose — and it belongs to the cell that holds what it is about. This
// module decides which that is and hands the request to `cell_channel.ts` to
// relay when it is not this one. It decides in two places:
//
//   * **AT THE EDGE** (`middleware()`, installed in `app.js` just above the
//     request pool, in the front process, before any body is read): from
//     what the request carries without reading its body — the AFFINITY
//     cookie a browser was pinned with, an artifact in the query string or
//     the path, a bearer token's `jti`, or a `?cell=` an administrator named.
//   * **IN A HANDLER** (`relayIfElsewhere()`, `relayToHome()`), for what only
//     the body says: a code at the token endpoint, a login name at the sign-in
//     screen, a SAML artifact in a SOAP envelope. The handler has the parsed
//     body and the relay re-serialises it.
//
// **THE PLACEMENT TABLE (`ROWS`) HAS A ROW FOR EVERY ROUTE**, the strategy
// named and the reason beside it, and `tests/cell_placement.js` fails on a
// registered route no row covers and on a `handler` row whose module never
// asks — so a new endpoint cannot arrive without somebody deciding where it
// is served, and a decision cannot be written down without being made.
//
// **THE AFFINITY COOKIE** (`sts_cell`) is how a BROWSER is pinned: to its
// home cell when the sign-in screen finds the person homed elsewhere (D9's
// restart), to the cell that holds its session when one is minted or
// exported there. Its value is `<realm>:<tag>` per realm, the tag
// `cell_locator.ts`'s keyed tag — nothing a reader can map to a cell — and a
// cookie naming no cell this service has is ignored.
//
// **A RELAYED REQUEST IS NEVER PLACED AGAIN**: the cell that received it from
// another cell serves it. One hop.
//
// **SINGLE-CELL MODE PLACES NOTHING**: the middleware calls next() and every
// helper answers "here".
//
// A LIBRARY that registers no route; `app.js` installs its middleware.
// Everything beyond the leaves is required lazily.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('./config');
import cells = require('./cells');
import cellLocator = require('./cell_locator');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-cell-placement' });

// The affinity cookie's name.
const AFFINITY_COOKIE = 'sts_cell';
// The default realm's id in the cookie, which cannot be empty there.
const DEFAULT_REALM_TOKEN = '-';

type Strategy = 'local' | 'affinity' | 'selector' | 'artifact' | 'bearer' |
  'handler';

/**
 * One row of the placement table: every route whose path starts with
 * `prefix` (an exact path when `exact`) is placed by `strategy`.
 */
interface Row {
  prefix: string;
  exact?: boolean;
  strategy: Strategy;
  // For `artifact`: the query parameters, and the path segment index (after
  // the realm prefix is stripped) that may carry a stamped artifact.
  query?: string[];
  segment?: number;
  // For `handler`: the module that decides, which `tests/cell_placement.js`
  // holds to calling this module.
  handler?: string;
  // A browser row: the affinity cookie is honoured before the strategy.
  browser?: boolean;
  why: string;
}

// ---------------------------------------------------------------------------
// THE TABLE. Longest prefix wins. `local` is what every cell answers the same
// way — configuration, metadata, keys, static scripts — or what is minted
// where it is asked for. `browser: true` honours the affinity cookie first.
// ---------------------------------------------------------------------------
const ROWS: Row[] = [
  // --- served where it arrives: the same answer in every cell ---
  { prefix: '/', exact: true, strategy: 'local',
    why: 'the front door is the same page in every cell' },
  { prefix: '/healthcheck', strategy: 'local',
    why: 'each cell answers for itself; a balancer health check must' },
  { prefix: '/.well-known', strategy: 'local',
    why: 'discovery documents and key sets are the global tier\'s, the ' +
         'same in every cell' },
  { prefix: '/.well-known/hoba', strategy: 'handler', browser: true,
    handler: 'scim/scim_cells.ts',
    why: 'a HOBA key goes on its person\'s entry, where they are homed; a ' +
         'pinned browser first, because outside development only the ' +
         'owner\'s own session may register one' },
  { prefix: '/.well-known/est', strategy: 'handler',
    handler: 'est/est.ts',
    why: 'an EST enrollment is for an entry, served where it is homed' },
  { prefix: '/pki', strategy: 'local',
    why: 'the certificate authority is the global tier\'s' },
  { prefix: '/crypto', strategy: 'local',
    why: 'the signer generations are the global tier\'s' },
  { prefix: '/docs', strategy: 'local', why: 'static documentation' },
  { prefix: '/logo.png', strategy: 'local', why: 'a static image' },
  { prefix: '/tos', strategy: 'local', why: 'a static page' },
  { prefix: '/policy', strategy: 'local', why: 'a static page' },
  { prefix: '/did.json', strategy: 'local',
    why: 'the realm\'s DID document is the global tier\'s' },
  { prefix: '/did', strategy: 'local',
    why: 'the realm\'s DID documents are the global tier\'s' },
  { prefix: '/issuer', strategy: 'local',
    why: 'issuer metadata is the global tier\'s' },
  { prefix: '/bbs', strategy: 'local',
    why: 'the realm\'s BBS key is the global tier\'s' },
  { prefix: '/FederationMetadata', strategy: 'local',
    why: 'WS-Federation metadata is the global tier\'s' },
  { prefix: '/oidfed', strategy: 'local',
    why: 'OpenID Federation statements and registers are the global tier\'s' },
  { prefix: '/realms', strategy: 'local',
    why: 'the realm registry is the global tier\'s' },
  { prefix: '/dpop', strategy: 'local',
    why: 'a nonce is valid where it was issued, and asked for there' },
  { prefix: '/spiffe', strategy: 'local',
    why: 'a workload attests to the cell it runs beside' },
  { prefix: '/vc-api', strategy: 'local',
    why: 'a development-only test control over global configuration' },
  { prefix: '/krb5', strategy: 'local',
    why: 'the Kerberos views read global configuration' },
  { prefix: '/KdcProxy', strategy: 'handler',
    handler: 'kerberos/krb5_home.ts',
    why: 'an AS-REQ names its client, and a TGS-REQ\'s ticket does; both ' +
         'are answered where the client is homed (the raw port 88 is not ' +
         'placed: kerberos/CLAUDE.md)' },
  { prefix: '/spnego', strategy: 'affinity', browser: true,
    why: 'a browser flow, served where the browser is pinned' },
  // --- the sign-in service and the browser flows ---
  { prefix: '/authn', strategy: 'affinity', browser: true,
    why: 'the sign-in screen is where D9\'s restart at home happens; a ' +
         'pinned browser is served where it is pinned' },
  { prefix: '/authn/login', strategy: 'handler', browser: true,
    handler: 'authn/authn.ts',
    why: 'the login name decides the home cell (D9)' },
  { prefix: '/authn/webauthn.js', strategy: 'local', why: 'a static script' },
  { prefix: '/authn/wallet.js', strategy: 'local', why: 'a static script' },
  { prefix: '/authn/fingerprint.js', strategy: 'local',
    why: 'a static script' },
  { prefix: '/logout', strategy: 'affinity', browser: true,
    why: 'the session to end is where the browser is pinned' },
  { prefix: '/portal', strategy: 'handler', browser: true,
    handler: 'portal/portal.ts',
    why: 'the portal manages a person\'s own entry, which only their home ' +
         'cell holds; a projected session is sent home' },
  { prefix: '/admin', strategy: 'selector', browser: true,
    why: 'the console acts on the global tier and on the serving cell\'s ' +
         'residents; ?cell= names another cell (D11)' },
  { prefix: '/admin-api', strategy: 'selector',
    why: 'the management API acts on the global tier and on the serving ' +
         'cell\'s residents; ?cell= names another cell (D11)' },
  { prefix: '/devices', strategy: 'bearer',
    why: 'a device registration is for the token\'s subject' },
  // --- OAuth 2.0 and OpenID Connect ---
  { prefix: '/oauth2', strategy: 'affinity', browser: true,
    why: 'a browser endpoint of the authorization server' },
  { prefix: '/oauth2/authorize', strategy: 'artifact', browser: true,
    query: ['request_uri'],
    why: 'a pushed request is found where it was pushed (D10); otherwise ' +
         'where the browser is pinned' },
  { prefix: '/oauth2/jwks', strategy: 'local',
    why: 'the realm keys are the global tier\'s' },
  { prefix: '/oauth2/check_session', strategy: 'local',
    why: 'the OP iframe answers from the browser state it is given' },
  { prefix: '/oauth2/autopost.js', strategy: 'local', why: 'a static script' },
  { prefix: '/oauth2/rfc9700', strategy: 'local', why: 'an information page' },
  { prefix: '/oauth2/fapi', strategy: 'local', why: 'an information page' },
  { prefix: '/oauth2/oauth21', strategy: 'local', why: 'an information page' },
  { prefix: '/oauth2/register', strategy: 'local',
    why: 'a client registration is global configuration' },
  { prefix: '/oauth2/par', strategy: 'local',
    why: 'the pushed request is minted here and stamped (D10)' },
  { prefix: '/oauth2/device_authorization', strategy: 'local',
    why: 'the device code is minted here and stamped (D10)' },
  { prefix: '/oauth2/challenge', strategy: 'local',
    why: 'an attestation challenge is valid where it is issued' },
  { prefix: '/oauth2/commands/mock-rp', strategy: 'local',
    why: 'a test relying party with no state of anybody\'s' },
  { prefix: '/oauth2/commands/callback', strategy: 'local',
    why: 'a Command callback token is global configuration' },
  { prefix: '/oauth2/token', strategy: 'handler',
    handler: 'oauth-oidc/oauth2.ts',
    why: 'the grant in the body names what the owning cell holds' },
  { prefix: '/oauth2/introspect', strategy: 'handler',
    handler: 'oauth-oidc/oauth2.ts',
    why: 'the token in the body names the cell that minted it' },
  { prefix: '/oauth2/revoke', strategy: 'handler',
    handler: 'oauth-oidc/oauth2.ts',
    why: 'the token in the body names the cell that minted it' },
  { prefix: '/oauth2/bc-authorize', strategy: 'handler',
    handler: 'oauth-oidc/oauth2.ts',
    why: 'a CIBA request names its person, whose home runs it' },
  { prefix: '/oauth2/userinfo', strategy: 'bearer',
    why: 'answered by the cell that minted the access token' },
  { prefix: '/oauth2/grants', strategy: 'bearer',
    why: 'the grant is held by the cell that minted the access token' },
  { prefix: '/oauth2/step-up/resource', strategy: 'bearer',
    why: 'the stand-in resource checks a token its minting cell holds' },
  // --- SAML, WS-Federation, WS-Trust ---
  { prefix: '/saml2', strategy: 'affinity', browser: true,
    why: 'a browser profile, served where the browser is pinned' },
  { prefix: '/saml2/metadata', strategy: 'local',
    why: 'metadata is the global tier\'s' },
  { prefix: '/saml2/autopost.js', strategy: 'local', why: 'a static script' },
  { prefix: '/saml2/ars', strategy: 'handler',
    handler: 'saml/saml2_sso.ts',
    why: 'an artifact is resolved by the cell that minted it (D10)' },
  { prefix: '/saml2/aa', strategy: 'handler', handler: 'saml/saml2_sso.ts',
    why: 'an attribute query names its subject, answered at home' },
  { prefix: '/saml11', strategy: 'affinity', browser: true,
    why: 'a browser profile, served where the browser is pinned' },
  { prefix: '/saml11/metadata', strategy: 'local',
    why: 'metadata is the global tier\'s' },
  { prefix: '/saml11/autopost.js', strategy: 'local', why: 'a static script' },
  { prefix: '/saml11/responder', strategy: 'handler',
    handler: 'saml/saml11_sso.ts',
    why: 'an artifact or attribute query is answered where it belongs' },
  { prefix: '/wsfed', strategy: 'affinity', browser: true,
    why: 'a browser profile, served where the browser is pinned' },
  { prefix: '/wsfed/autopost.js', strategy: 'local', why: 'a static script' },
  { prefix: '/sts', strategy: 'handler', handler: 'ws-trust/wstrust.ts',
    why: 'a UsernameToken names its person, verified at home' },
  { prefix: '/federation', strategy: 'affinity', browser: true,
    why: 'a partner\'s browser flow, served where the browser is pinned' },
  { prefix: '/federation/metadata', strategy: 'local',
    why: 'a relationship\'s metadata is the global tier\'s' },
  { prefix: '/federation/jwks', strategy: 'local',
    why: 'a relationship\'s keys are the global tier\'s' },
  { prefix: '/federation/link', strategy: 'artifact', browser: true,
    segment: 3, why: 'a link handle is found where it was minted (D10)' },
  { prefix: '/federation/backchannel-logout', strategy: 'handler',
    handler: 'federation/federation_slo.ts',
    why: 'a partner\'s sign-out may end sessions in every cell' },
  // --- SCIM, SSF, XACML ---
  { prefix: '/scim', strategy: 'handler', handler: 'scim/scim_cells.ts',
    why: 'a resource is written where its person is homed; a list answers ' +
         'the serving cell\'s residents (D11); a Group write or a Bulk ' +
         'spanning cells is refused whole' },
  { prefix: '/scim/v2/ServiceProviderConfig', strategy: 'local',
    why: 'the same configuration in every cell' },
  { prefix: '/scim/v2/ResourceTypes', strategy: 'local',
    why: 'the same configuration in every cell' },
  { prefix: '/scim/v2/Schemas', strategy: 'local',
    why: 'the same configuration in every cell' },
  { prefix: '/scim/v2/Me', strategy: 'bearer',
    why: 'the token\'s own subject, where the token was minted' },
  { prefix: '/ssf', strategy: 'local',
    why: 'streams are global configuration; events reach every cell\'s ' +
         'transmitter' },
  { prefix: '/xacml', strategy: 'local',
    why: 'policy and the decision point are the global tier\'s' },
  { prefix: '/xacml/pip', strategy: 'handler', handler: 'xacml/xacml.ts',
    why: 'a subject\'s attributes are answered at home' },
  // --- TLS ---
  { prefix: '/tls', strategy: 'local',
    why: 'certificate views and test controls over global configuration' },
  { prefix: '/tls/sign-in', strategy: 'handler', browser: true,
    handler: 'tls/tls_server.js',
    why: 'a client certificate names its person, signed in at home; a ' +
         'pinned browser first, because a browser already holding a ' +
         'session is not given a second one' },
  // --- OpenID4VC ---
  { prefix: '/oid4vci', strategy: 'local',
    why: 'nonces and status lists: minted here, or the global tier\'s' },
  { prefix: '/oid4vci/credential', strategy: 'bearer',
    why: 'issued by the cell that minted the access token' },
  { prefix: '/oid4vci/deferred_credential', strategy: 'bearer',
    why: 'held by the cell that minted the access token' },
  { prefix: '/oid4vci/notification', strategy: 'bearer',
    why: 'held by the cell that minted the access token' },
  { prefix: '/oid4vci/credential-offer', strategy: 'artifact', segment: 3,
    why: 'an offer is found where it was minted (D10)' },
  { prefix: '/oid4vp', strategy: 'affinity', browser: true,
    why: 'the verifier\'s browser pages, where the browser is pinned' },
  { prefix: '/oid4vp/verifier', strategy: 'local',
    why: 'verifier metadata is the global tier\'s' },
  { prefix: '/oid4vp/verifier-certificate', strategy: 'local',
    why: 'verifier metadata is the global tier\'s' },
  { prefix: '/oid4vp/request', strategy: 'artifact', segment: 3,
    why: 'a wallet fetches a request where it was minted (D10)' },
  { prefix: '/oid4vp/result', strategy: 'artifact', browser: true,
    segment: 3, why: 'a result is found where it was minted (D10)' },
  { prefix: '/oid4vp/response', strategy: 'handler',
    handler: 'oid4vc/vc_verifier.ts',
    why: 'a wallet\'s direct_post names its transaction in the body' },
  // --- GNAP ---
  { prefix: '/gnap', strategy: 'handler', handler: 'gnap/gnap.ts',
    why: 'a grant request may name its subject; everything after it is ' +
         'found by its handle' },
  { prefix: '/gnap/keys', strategy: 'local',
    why: 'the key set is the global tier\'s' },
  { prefix: '/gnap/continue', strategy: 'artifact', segment: 3,
    why: 'a continuation is found where it was minted (D10)' },
  { prefix: '/gnap/token', strategy: 'artifact', segment: 3,
    why: 'a token handle is found where it was minted (D10)' },
  { prefix: '/gnap/interact', strategy: 'artifact', browser: true,
    segment: 3, why: 'an interaction is found where it was minted (D10)' },
  { prefix: '/gnap/app', strategy: 'artifact', browser: true, segment: 3,
    why: 'an interaction is found where it was minted (D10)' },
  { prefix: '/gnap/approve', strategy: 'artifact', browser: true,
    segment: 3, why: 'an interaction is found where it was minted (D10)' },
  { prefix: '/gnap/resource', strategy: 'bearer',
    why: 'the resource checks a token its minting cell holds' },
  { prefix: '/gnap/rs', strategy: 'bearer',
    why: 'the resource checks a token its minting cell holds' },
  // --- certificate enrollment ---
  { prefix: '/enroll', strategy: 'handler', handler: 'acme/acme.ts',
    why: 'an enrollment is for an entry, served where it is homed' },
  { prefix: '/enroll/acme/directory', strategy: 'local',
    why: 'the same directory in every cell' },
  { prefix: '/enroll/acme/new-nonce', strategy: 'local',
    why: 'a nonce is valid where it is issued' },
  { prefix: '/enroll/acme/account', strategy: 'artifact', segment: 4,
    why: 'an account is found where it was created (D10)' },
  { prefix: '/enroll/acme/order', strategy: 'artifact', segment: 4,
    why: 'an order is found where it was created (D10)' },
  { prefix: '/enroll/acme/authz', strategy: 'artifact', segment: 4,
    why: 'an authorization is found where it was created (D10)' },
  { prefix: '/enroll/acme/challenge', strategy: 'artifact', segment: 4,
    why: 'a challenge is found where it was created (D10)' },
  { prefix: '/enroll/acme/cert', strategy: 'artifact', segment: 4,
    why: 'a certificate is found where it was issued (D10)' },
  { prefix: '/enroll/acme/renewal-info', strategy: 'local',
    why: 'renewal information is computed from the certificate itself' },
  { prefix: '/enroll/scep', strategy: 'handler', handler: 'scep/scep.ts',
    why: 'a SCEP challenge names the entry it was issued for' }
];

// The rows, longest prefix first, so the first match is the most specific.
const ORDERED = ROWS.slice().sort(function (a, b) {
  return b.prefix.length - a.prefix.length;
});

/**
 * Where requests are served in a service deployed as cells: the placement
 * table, the affinity cookie, the edge middleware and the handler helpers.
 */
class CellPlacement {
  private relayed = 0;
  private placedHere = 0;

  /**
   * Builds the placement. It holds nothing but its counters.
   */
  constructor() {
    log.debug("Entering CellPlacement.constructor().");
    log.debug("Leaving CellPlacement.constructor().");
  }

  // A named authorization server lives under `/{id}/oauth2/…` and
  // `/{id}/gnap…`; it is placed as the default one is.
  static canonicalPath(path: string): string {
    log.debug("Entering CellPlacement.canonicalPath().");
    const text = String(path || '/');
    const m = /^\/[^/]+(\/(?:oauth2|gnap)(?:\/.*)?)$/.exec(text);
    log.debug("Leaving CellPlacement.canonicalPath().");
    return m && text.indexOf('/oauth2') !== 0 && text.indexOf('/gnap') !== 0
      ? m[1] : text;
  }

  /**
   * Finds the placement row of a path (the realm prefix already stripped).
   *
   * @param path - the request path
   * @returns the row, or null when none covers it
   */
  static rowFor(path: string): Row | null {
    log.debug("Entering CellPlacement.rowFor().");
    const p = CellPlacement.canonicalPath(path);
    const found = ORDERED.filter(function (row) {
      if (row.exact) {
        return p === row.prefix;
      }
      return p === row.prefix || p.indexOf(row.prefix.replace(/\/$/, '') +
                                           '/') === 0 ||
             (row.prefix.indexOf('.') > 0 && p.indexOf(row.prefix) === 0);
    })[0] || null;
    log.debug("Leaving CellPlacement.rowFor(). " +
              (found ? found.prefix : 'none'));
    return found;
  }

  // -------------------------------------------------------------------------
  // THE AFFINITY COOKIE.
  // -------------------------------------------------------------------------
  private static realmToken(realmId: string): string {
    log.debug("Entering CellPlacement.realmToken().");
    log.debug("Leaving CellPlacement.realmToken().");
    return realmId ? String(realmId) : DEFAULT_REALM_TOKEN;
  }

  // The cookie's entries: realm token -> tag.
  private static affinityEntries(req: any): Record<string, string> {
    log.debug("Entering CellPlacement.affinityEntries().");
    const out: Record<string, string> = {};
    const header = String((req && req.headers && req.headers.cookie) || '');
    header.split(';').forEach(function (part) {
      const at = part.indexOf('=');
      if (at < 0 || part.slice(0, at).trim() !== AFFINITY_COOKIE) {
        return;
      }
      part.slice(at + 1).trim().split('~').forEach(function (entry) {
        const colon = entry.indexOf(':');
        if (colon > 0) {
          out[entry.slice(0, colon)] = entry.slice(colon + 1);
        }
      });
    });
    log.debug("Leaving CellPlacement.affinityEntries().");
    return out;
  }

  /**
   * The cell a browser is pinned to in a realm, by its affinity cookie.
   *
   * @param req - the request
   * @param realmId - the realm
   * @returns the cell id, or '' when the cookie names none this service has
   */
  affinityOf(req: any, realmId: string): string {
    log.debug("Entering CellPlacement.affinityOf().");
    if (!cells.isMulti()) {
      log.debug("Leaving CellPlacement.affinityOf(). Single-cell.");
      return '';
    }
    const tag = CellPlacement.affinityEntries(req)[
      CellPlacement.realmToken(realmId)] || '';
    if (!tag) {
      log.debug("Leaving CellPlacement.affinityOf(). None.");
      return '';
    }
    const found = cells.all().filter(function (one) {
      return cellLocator.tagOf(one.id) === tag;
    })[0];
    log.debug("Leaving CellPlacement.affinityOf(). " +
              (found ? found.id : 'unknown tag'));
    return found ? found.id : '';
  }

  /**
   * Pins a browser to a cell in a realm, keeping its pins in other realms.
   *
   * @param req - the request (its cookie carries the other realms' pins)
   * @param res - the response the cookie is set on
   * @param realmId - the realm
   * @param cellId - the cell, or '' to remove the realm's pin
   */
  setAffinity(req: any, res: any, realmId: string, cellId: string): void {
    log.debug("Entering CellPlacement.setAffinity().");
    if (!cells.isMulti()) {
      log.debug("Leaving CellPlacement.setAffinity(). Single-cell.");
      return;
    }
    const entries = CellPlacement.affinityEntries(req);
    const token = CellPlacement.realmToken(realmId);
    const tag = cellId ? cellLocator.tagOf(cellId) : '';
    if (tag) {
      entries[token] = tag;
    } else {
      delete entries[token];
    }
    const value = Object.keys(entries).map(function (k) {
      return k + ':' + entries[k];
    }).join('~');
    const https = !!config.value('global.https');
    const lifetime = Math.max(60,
                              Number(config.value('authn.sessionLifetimeS')) ||
                              28800);
    const cookie = AFFINITY_COOKIE + '=' + value + '; Path=/; HttpOnly' +
      (https ? '; Secure; SameSite=None' : '; SameSite=Lax') +
      (value ? '; Max-Age=' + lifetime : '; Max-Age=0');
    if (typeof res.append === 'function') {
      res.append('Set-Cookie', cookie);
    } else if (typeof res.setHeader === 'function') {
      const had = res.getHeader('Set-Cookie');
      res.setHeader('Set-Cookie', [].concat(had || [], cookie));
    }
    log.debug("Leaving CellPlacement.setAffinity().");
  }

  // -------------------------------------------------------------------------
  // THE EDGE. In the front process, above the request pool, before any body
  // is read — so a relay pipes the request untouched.
  // -------------------------------------------------------------------------
  // A bearer token's minting cell: the `jti` of a JWT (stamped when it was
  // minted), or the opaque token itself. Read, never verified: this decides
  // only WHERE the token is checked, and the cell it names checks it.
  private static bearerCell(req: any): string {
    log.debug("Entering CellPlacement.bearerCell().");
    const auth = String((req.headers && req.headers.authorization) || '');
    const m = /^(?:Bearer|DPoP|GNAP)\s+(\S+)$/i.exec(auth.trim());
    if (!m) {
      log.debug("Leaving CellPlacement.bearerCell(). No token.");
      return '';
    }
    const token = m[1];
    const parts = token.split('.');
    if (parts.length === 3) {
      try {
        const claims = JSON.parse(Buffer.from(parts[1], 'base64url')
          .toString('utf8'));
        log.debug("Leaving CellPlacement.bearerCell(). A JWT.");
        return cellLocator.elsewhere(String((claims && claims.jti) || ''));
      } catch (e) {
        log.debug("Caught in CellPlacement.bearerCell(): " +
                  ((e && e.message) || e));
        return '';
      }
    }
    log.debug("Leaving CellPlacement.bearerCell(). Opaque.");
    return cellLocator.elsewhere(token);
  }

  // An artifact the row names, in the query or the path.
  private static artifactCell(req: any, row: Row): string {
    log.debug("Entering CellPlacement.artifactCell().");
    let found = '';
    (row.query || []).forEach(function (name) {
      if (found) {
        return;
      }
      const raw = req.query ? req.query[name] : undefined;
      const value = String(Array.isArray(raw) ? raw[0] || '' : raw || '');
      // A request_uri is `urn:ietf:params:oauth:request_uri:<value>`.
      found = cellLocator.elsewhere(value.split(':').pop() || '');
    });
    if (!found && typeof row.segment === 'number') {
      const path = CellPlacement.canonicalPath(String(req.path || ''));
      const segment = path.split('/')[row.segment] || '';
      found = cellLocator.elsewhere(decodeURIComponent(segment));
    }
    log.debug("Leaving CellPlacement.artifactCell(). " + (found || 'here'));
    return found;
  }

  /**
   * Decides, from what a request carries without its body, which OTHER cell
   * serves it.
   *
   * @param req - the request, inside its realm
   * @param realmId - the realm
   * @returns `{ cell, reason }` naming another cell, or null to serve here
   */
  decide(req: any, realmId: string): { cell: string; reason: string } | null {
    log.debug("Entering CellPlacement.decide().");
    const row = CellPlacement.rowFor(String(req.path || '/'));
    const here = cells.id();
    const other = (cell: string, reason: string) =>
      cell && cell !== here && cells.get(cell) ? { cell: cell, reason: reason }
                                               : null;
    if (!row || row.strategy === 'local') {
      log.debug("Leaving CellPlacement.decide(). Local.");
      return null;
    }
    // A PINNED BROWSER IS SERVED WHERE IT IS PINNED, before anything else a
    // browser route carries is read — a request_uri or a handle minted in
    // another cell included. A flow that restarted at home (D9) was handed
    // what it needs there, and following the artifact's tag instead would
    // send the browser straight back to the cell that sent it home.
    if (row.browser) {
      const pinned = this.affinityOf(req, realmId);
      if (pinned) {
        log.debug("Leaving CellPlacement.decide(). Pinned.");
        return other(pinned, 'affinity');
      }
    }
    if (row.strategy === 'selector') {
      const raw = req.query ? req.query.cell : undefined;
      const named = String(Array.isArray(raw) ? raw[0] || '' : raw || '');
      if (named) {
        log.debug("Leaving CellPlacement.decide(). Selected.");
        return other(named, 'selected');
      }
    }
    if (row.strategy === 'artifact') {
      const minted = CellPlacement.artifactCell(req, row);
      if (minted) {
        log.debug("Leaving CellPlacement.decide(). An artifact.");
        return other(minted, 'artifact');
      }
    }
    if (row.strategy === 'bearer') {
      const minted = CellPlacement.bearerCell(req);
      log.debug("Leaving CellPlacement.decide(). A bearer token.");
      return other(minted, 'bearer');
    }
    if (row.strategy === 'affinity' && !row.browser) {
      const pinned = this.affinityOf(req, realmId);
      log.debug("Leaving CellPlacement.decide(). Affinity.");
      return other(pinned, 'affinity');
    }
    log.debug("Leaving CellPlacement.decide(). The handler decides.");
    return null;
  }

  /**
   * The edge middleware `app.js` installs above the request pool.
   *
   * @returns an express middleware; next() for everything in single-cell mode
   */
  middleware(): (req: any, res: any, next: () => void) => void {
    log.debug("Entering CellPlacement.middleware().");
    const self = this;
    log.debug("Leaving CellPlacement.middleware().");
    return function cellPlacementEdge(req: any, res: any, next: () => void) {
      // A HOT PATH: every request passes, so the Entering/Leaving pair is on
      // the branch that does something rather than on every request.
      if (!cells.isMulti() || req.stsCellRelay) {
        next();
        return;
      }
      log.debug("Entering cellPlacementEdge().");
      const realms = require('./realms');
      const decision = self.decide(req, realms.currentId());
      if (!decision) {
        self.placedHere += 1;
        log.debug("Leaving cellPlacementEdge(). Here.");
        next();
        return;
      }
      self.relayed += 1;
      log.debug("Leaving cellPlacementEdge(). Relayed.");
      require('./cell_channel').relay(req, res, decision.cell,
                                      { reason: decision.reason });
    };
  }

  // -------------------------------------------------------------------------
  // THE HANDLER HELPERS, for what only the body says. A handler that has
  // parsed the body calls one of these before it looks anything up; `true`
  // means the request was relayed and the handler must stop.
  // -------------------------------------------------------------------------
  /**
   * Re-serialises a parsed request body the way it arrived.
   *
   * @param req - the request, its body parsed
   * @returns the body as a Buffer
   */
  static serialisedBody(req: any): Buffer {
    log.debug("Entering CellPlacement.serialisedBody().");
    const body = req.body;
    const type = String((req.headers && req.headers['content-type']) || '')
      .toLowerCase();
    let out: Buffer;
    if (Buffer.isBuffer(body)) {
      out = body;
    } else if (typeof body === 'string') {
      out = Buffer.from(body, 'utf8');
    } else if (body && typeof body === 'object' &&
               type.indexOf('application/x-www-form-urlencoded') >= 0) {
      const params = new URLSearchParams();
      Object.keys(body).forEach(function (k) {
        const v = body[k];
        (Array.isArray(v) ? v : [v]).forEach(function (one) {
          params.append(k, one === undefined || one === null ? ''
                                                             : String(one));
        });
      });
      out = Buffer.from(params.toString(), 'utf8');
    } else if (body && typeof body === 'object') {
      out = Buffer.from(JSON.stringify(body), 'utf8');
    } else {
      out = Buffer.alloc(0);
    }
    log.debug("Leaving CellPlacement.serialisedBody(). " + out.length);
    return out;
  }

  /**
   * Relays a request whose body names an artifact another cell minted.
   *
   * @param req - the request, its body parsed
   * @param res - the response
   * @param value - the artifact (a code, a token, a handle)
   * @param reason - what it is, for the log
   * @returns true when the request was relayed (the handler must stop)
   */
  relayIfElsewhere(req: any, res: any, value: string,
                   reason: string): boolean {
    log.debug("Entering CellPlacement.relayIfElsewhere().");
    if (!cells.isMulti() || req.stsCellRelay) {
      log.debug("Leaving CellPlacement.relayIfElsewhere(). Here.");
      return false;
    }
    const minted = cellLocator.elsewhere(String(value || ''));
    if (!minted || !cells.get(minted)) {
      log.debug("Leaving CellPlacement.relayIfElsewhere(). Here.");
      return false;
    }
    this.relayed += 1;
    require('./cell_channel').relay(req, res, minted, {
      reason: reason, body: CellPlacement.serialisedBody(req) });
    log.debug("Leaving CellPlacement.relayIfElsewhere(). Relayed.");
    return true;
  }

  /**
   * Relays a request about a person to their home cell when that is another
   * cell.
   *
   * @param req - the request, its body parsed
   * @param res - the response
   * @param realmId - the realm
   * @param kind - 'name' or 'uuid'
   * @param value - the login name or the entryUUID
   * @param reason - what it is, for the log
   * @returns a promise of true when the request was relayed
   */
  relayToHome(req: any, res: any, realmId: string, kind: string,
              value: string, reason: string): Promise<boolean> {
    log.debug("Entering CellPlacement.relayToHome().");
    if (!cells.isMulti() || req.stsCellRelay || !value) {
      log.debug("Leaving CellPlacement.relayToHome(). Here.");
      return Promise.resolve(false);
    }
    const self = this;
    log.debug("Leaving CellPlacement.relayToHome().");
    return require('./cell_routing').homeOf(realmId, kind, value)
      .then(function (home: string) {
        if (!home || home === cells.id() || !cells.get(home)) {
          return false;
        }
        self.relayed += 1;
        return require('./cell_channel').relay(req, res, home, {
          reason: reason, body: CellPlacement.serialisedBody(req)
        }).then(function () {
          return true;
        });
      });
  }

  /**
   * What `/admin/cells` shows about placement in this process.
   *
   * @returns the counters and the table's size
   */
  status(): Record<string, any> {
    log.debug("Entering CellPlacement.status().");
    log.debug("Leaving CellPlacement.status().");
    return { relayed: this.relayed, placedHere: this.placedHere,
             rows: ROWS.length };
  }
}

const placement = new CellPlacement();

/**
 * Which cell serves a request (#98 D9, D10): the placement table, the
 * affinity cookie, the edge middleware and the helpers a handler calls.
 * A library: no route.
 * @namespace
 */
export = {
  CellPlacement: CellPlacement,
  ROWS: ROWS,
  AFFINITY_COOKIE: AFFINITY_COOKIE,
  rowFor: CellPlacement.rowFor,
  canonicalPath: CellPlacement.canonicalPath,
  serialisedBody: CellPlacement.serialisedBody,
  middleware: () => placement.middleware(),
  decide: (req: any, realmId: string) => placement.decide(req, realmId),
  affinityOf: (req: any, realmId: string): string =>
    placement.affinityOf(req, realmId),
  setAffinity: (req: any, res: any, realmId: string, cellId: string): void =>
    placement.setAffinity(req, res, realmId, cellId),
  relayIfElsewhere: (req: any, res: any, value: string,
                     reason: string): boolean =>
    placement.relayIfElsewhere(req, res, value, reason),
  relayToHome: (req: any, res: any, realmId: string, kind: string,
                value: string, reason: string): Promise<boolean> =>
    placement.relayToHome(req, res, realmId, kind, value, reason),
  status: () => placement.status()
};
