// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/launch_links.ts
//
// ---------------------------------------------------------------------------
// WHERE AN IDENTITY-PROVIDER-INITIATED SIGN-IN STARTS (#426, #713).
//
// One link per application, `{realm base}/launch/{app}[?protocol=…]`, is the
// same URL in three places: the user portal's Sign in link, the top of each
// protocol sub-tab of the application in the console (and the management
// API's view of it), and anywhere an operator pastes it — a bookmark, an
// intranet page, an email. `launch/launch.ts` answers it; this library is
// what all three of those readers and that route share, so the URL the
// console shows and the URL the door answers cannot drift apart.
//
// **A LIBRARY, NOT A ROUTE MODULE.** It registers nothing and requires only
// `applications`, `config` and `realms`, so the account API (8a-acct) and
// the management API (19) may require it although the door itself is
// registered near the end of the stack (23a-launch): a require of it moves
// no route and closes no cycle.
//
// FOUR PROTOCOLS, and each has its own endpoint the door hands the browser
// to — the door decides WHICH and checks the switch, the endpoint does the
// sign-in exactly as it does for a link that names it directly, so the
// session, its risk, the issuance policy, `session-presented` and the record
// of the relying party on the session are the protocol's own:
//
//   saml2   /saml2/unsolicited/{sp}                       (#711)
//   saml11  /saml11/sso/{rp}?providerId=…[&TARGET=…]      (#711)
//   wsfed   /wsfed/initiate/{rp}[?wctx=…]                 (#712)
//   oidc    the client's initiate_login_uri, OpenID Connect Core section 4
//
// OPENID CONNECT IS THE ONE WITH NO ENDPOINT HERE: section 4 hands the
// browser to the CLIENT, which starts an ordinary authorization request. So
// the door records the launch on the session (`noteLaunch()`), and a client
// whose own start is turned off (`oauth2.spInitiatedSso`) is answered at
// /oauth2/authorize only within `oauth2.launchWindowS` of one
// (`launchIsFresh()`, `takeLaunch()`).
// ---------------------------------------------------------------------------

import applications = require('./applications');
import config = require('./config');
import helpers = require('./helpers');

type Json = any;

// THE FOUR PROTOCOLS, each with the families an entry must be declared or
// recorded for, the setting (and so, through settingFor(), the attribute)
// that turns identity-provider-initiated sign-in on, and the attribute whose
// absence makes a link that cannot work.
const PROTOCOLS: Json[] = [
  { id: 'saml2', label: 'SAML 2.0', families: ['saml2'],
    setting: 'saml2.idpInitiatedSso', attribute: 'saml2IdpInitiatedSso',
    needs: 'samlAssertionConsumerService' },
  { id: 'saml11', label: 'SAML 1.1', families: ['saml11'],
    setting: 'saml11.idpInitiatedSso', attribute: 'saml11IdpInitiatedSso',
    needs: 'samlAssertionConsumerService' },
  { id: 'wsfed', label: 'WS-Federation', families: ['wsfed'],
    setting: 'wsfed.idpInitiatedSso', attribute: 'wsfedIdpInitiatedSso',
    needs: 'wsfedReplyUrl' },
  { id: 'oidc', label: 'OpenID Connect', families: ['oidc', 'oauth2'],
    setting: 'oauth2.thirdPartyInitiatedLogin',
    attribute: 'oauthThirdPartyInitiatedLogin',
    needs: 'oauthInitiateLoginUri' }
];

/**
 * Identity-provider-initiated sign-in links: which protocols an application
 * can be launched in, the one URL per protocol, where the door sends the
 * browser, and the launch record OpenID Connect's half needs.
 *
 * A static utility class; it holds no state.
 */
class LaunchLinks {
  /**
   * The four protocols a launch can start, in drawing order.
   *
   * @returns a copy of the table
   */
  static protocols(): Json[] {
    helpers.log.debug("Entering LaunchLinks.protocols().");
    helpers.log.debug("Leaving LaunchLinks.protocols().");
    return PROTOCOLS.map(function (row) {
      return Object.assign({}, row);
    });
  }

  /**
   * One protocol's row, or null.
   *
   * @param id - `saml2`, `saml11`, `wsfed` or `oidc`
   * @returns the row
   */
  static protocol(id: string): Json {
    helpers.log.debug("Entering LaunchLinks.protocol(). " + id);
    const row = PROTOCOLS.filter(function (one) {
      return one.id === id;
    })[0] || null;
    helpers.log.debug("Leaving LaunchLinks.protocol().");
    return row;
  }

  // AN ENTRY IS LAUNCHABLE IN A PROTOCOL IT IS DECLARED OR RECORDED FOR —
  // the two lists the portal already counts a sign-in destination by. An
  // OAuth 2.0 client that never asked for OpenID Connect counts for `oidc`
  // only once it has an initiate_login_uri: a resource server or a machine
  // client is an OAuth client too, and a launch it can never answer would
  // be a dead link on every one of their sub-tabs.
  /**
   * The protocols an application can be launched in.
   *
   * @param view - an `applications.get()` view
   * @returns the protocol rows
   */
  static protocolsOf(view: Json): Json[] {
    helpers.log.debug("Entering LaunchLinks.protocolsOf().");
    const holder = view || {};
    const families = (holder.allowedProtocols || [])
      .concat(holder.recordedProtocols || []);
    const found = PROTOCOLS.filter(function (row) {
      if (row.id === 'oidc' && families.indexOf('oidc') < 0) {
        return families.indexOf('oauth2') >= 0 &&
               !!applications.initiateLoginUriOf(holder);
      }
      return row.families.some(function (family: string) {
        return families.indexOf(family) >= 0;
      });
    });
    helpers.log.debug("Leaving LaunchLinks.protocolsOf(). " + found.length);
    return found;
  }

  /**
   * Whether identity-provider-initiated sign-in is on for an application in a
   * protocol: its entry's attribute, else the realm's setting.
   *
   * @param identifier - the application's registry identifier
   * @param protocol - the protocol id
   * @returns true when it is on
   */
  static enabled(identifier: string, protocol: string): boolean {
    helpers.log.debug("Entering LaunchLinks.enabled(). " + protocol);
    const row = LaunchLinks.protocol(protocol);
    const on = !!row &&
      applications.settingFor(identifier, row.setting, config) === true;
    helpers.log.debug("Leaving LaunchLinks.enabled(). " + on);
    return on;
  }

  // WHAT A LINK CANNOT WORK WITHOUT: somewhere to send the answer. Asked of
  // the REGISTERED addresses (returnAddressesOf()), because in product an
  // address a development request merely recorded is refused at the
  // endpoint; SAML 2.0 consumed metadata counts as registering an assertion
  // consumer service, which the endpoint reads first.
  /**
   * The attributes a launch in a protocol is missing, or an empty list.
   *
   * @param view - an `applications.get()` view
   * @param protocol - the protocol id
   * @returns the attribute names
   */
  static missingOf(view: Json, protocol: string): string[] {
    helpers.log.debug("Entering LaunchLinks.missingOf(). " + protocol);
    const row = LaunchLinks.protocol(protocol);
    const fields = (view && view.fields) || {};
    let missing: string[] = [];
    if (!row) {
      missing = [];
    } else if (protocol === 'oidc') {
      missing = applications.initiateLoginUriOf(view) ? [] : [row.needs];
    } else {
      const known = applications.returnAddressesOf(fields, row.needs)
        .registered;
      const metadata = protocol !== 'wsfed' &&
        (!!fields.samlSpMetadata || !!fields.samlSpMetadataUrl);
      missing = known.length || metadata ? [] : [row.needs];
    }
    helpers.log.debug("Leaving LaunchLinks.missingOf(). " + missing.length);
    return missing;
  }

  /**
   * The one launch URL for an application in a protocol.
   *
   * @param base - this realm's base URL (`helpers.baseUrlOf()`)
   * @param identifier - the application's registry identifier
   * @param protocol - the protocol id, or '' for the door to choose
   * @returns the URL
   */
  static launchUrl(base: string, identifier: string,
                   protocol: string): string {
    helpers.log.debug("Entering LaunchLinks.launchUrl().");
    const url = String(base || '') + '/launch/' +
      encodeURIComponent(String(identifier || '')) +
      (protocol ? '?protocol=' + encodeURIComponent(protocol) : '');
    helpers.log.debug("Leaving LaunchLinks.launchUrl().");
    return url;
  }

  // WHERE THE DOOR SENDS THE BROWSER for the three protocols that have an
  // endpoint here. `target` is each protocol's own word for "where to land
  // afterwards": RelayState, TARGET, wctx — passed byte for byte, as each
  // endpoint passes it on.
  /**
   * The protocol endpoint an identity-provider-initiated sign-in starts at,
   * or '' for OpenID Connect, whose start is at the client.
   *
   * @param base - this realm's base URL
   * @param view - an `applications.get()` view
   * @param protocol - the protocol id
   * @param target - where to land afterwards, or ''
   * @returns the URL
   */
  static endpointUrl(base: string, view: Json, protocol: string,
                     target: string): string {
    helpers.log.debug("Entering LaunchLinks.endpointUrl(). " + protocol);
    const fields = (view && view.fields) || {};
    const identifier = String((view && view.identifier) || '');
    // A field is a value or a list of them; the first is the identifier.
    const first = function (name: string): string {
      const value = fields[name];
      return String((Array.isArray(value) ? value[0] : value) || '');
    };
    const there = String(target || '');
    let url = '';
    if (protocol === 'saml2') {
      const sp = first('samlEntityId') || identifier;
      url = base + '/saml2/unsolicited/' + encodeURIComponent(sp) +
        (there ? '?target=' + encodeURIComponent(there) : '');
    } else if (protocol === 'saml11') {
      const rp = first('samlEntityId') || identifier;
      url = base + '/saml11/sso/' + encodeURIComponent(rp) +
        '?providerId=' + encodeURIComponent(rp) +
        (there ? '&TARGET=' + encodeURIComponent(there) : '');
    } else if (protocol === 'wsfed') {
      const realm = first('wsfedRealm') || identifier;
      url = base + '/wsfed/initiate/' + encodeURIComponent(realm) +
        (there ? '?wctx=' + encodeURIComponent(there) : '');
    }
    helpers.log.debug("Leaving LaunchLinks.endpointUrl().");
    return url;
  }

  // OPENID CONNECT CORE SECTION 4: a GET at the client's initiate_login_uri
  // with `iss` (this realm's issuer), `login_hint` (the person, who chose to
  // click) and `target_link_uri` (https only — section 4 says the client
  // MUST verify it, and an http one is a link nobody should be sent on), and
  // OpenID Connect Enterprise Extensions section 4's `tenant` and
  // `domain_hint` (#148). It was the portal's own until #426.
  /**
   * The section 4 address for a client, or ''.
   *
   * @param initiate - the client's initiate_login_uri
   * @param o - `{ issuer, username, tenant, domain, target }`
   * @returns the URL, or '' when there is no initiate_login_uri or issuer
   */
  static thirdPartyLoginUrl(initiate: string, o: Json): string {
    helpers.log.debug("Entering LaunchLinks.thirdPartyLoginUrl().");
    const given = o || {};
    if (!initiate || !given.issuer) {
      helpers.log.debug("Leaving LaunchLinks.thirdPartyLoginUrl(). None.");
      return '';
    }
    const url = new URL(initiate);
    url.searchParams.set('iss', String(given.issuer));
    if (given.username) {
      url.searchParams.set('login_hint', String(given.username));
    }
    if (given.tenant) {
      url.searchParams.set('tenant', String(given.tenant));
    }
    if (given.domain) {
      url.searchParams.set('domain_hint', String(given.domain));
    }
    if (/^https:\/\//i.test(String(given.target || ''))) {
      url.searchParams.set('target_link_uri', String(given.target));
    }
    helpers.log.debug("Leaving LaunchLinks.thirdPartyLoginUrl().");
    return url.toString();
  }

  /**
   * Every protocol an application can be launched in, with its URL, whether
   * it is on, what it is missing and the protocol's own endpoint: what the
   * console's sub-tabs and the management API's view draw.
   *
   * @param view - an `applications.get()` view
   * @param base - this realm's base URL
   * @returns `{ <protocol>: { protocol, label, url, enabled, missing,
   *   endpoint } }`
   */
  static linksFor(view: Json, base: string): Json {
    helpers.log.debug("Entering LaunchLinks.linksFor().");
    const out: Json = {};
    if (!view) {
      helpers.log.debug("Leaving LaunchLinks.linksFor(). No application.");
      return out;
    }
    LaunchLinks.protocolsOf(view).forEach(function (row) {
      out[row.id] = {
        protocol: row.id,
        label: row.label,
        url: LaunchLinks.launchUrl(base, view.identifier, row.id),
        enabled: LaunchLinks.enabled(view.identifier, row.id),
        setting: row.setting,
        attribute: row.attribute,
        missing: LaunchLinks.missingOf(view, row.id),
        endpoint: row.id === 'oidc'
          ? applications.initiateLoginUriOf(view)
          : LaunchLinks.endpointUrl(base, view, row.id, '')
      };
    });
    helpers.log.debug("Leaving LaunchLinks.linksFor(). " +
                      Object.keys(out).length);
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE LAUNCH RECORD, OPENID CONNECT'S HALF. On the SESSION, because it is
  // a fact about this browser's sign-on — the session store replicates it
  // to every process with the rest of the session (the caller calls
  // `noteSessionChanged()`), and it ends with the session. Seconds since the
  // epoch, per client_id. A record is TAKEN when the authorization response
  // goes out, not when the request is checked, because a request that sends
  // the person to sign in first comes round a second time and must still
  // count.
  // ---------------------------------------------------------------------------
  /**
   * Records on a session that a client was launched now.
   *
   * @param session - the sign-on session
   * @param clientId - the client launched
   * @param nowS - now, in seconds since the epoch
   */
  static noteLaunch(session: Json, clientId: string, nowS: number): void {
    helpers.log.debug("Entering LaunchLinks.noteLaunch().");
    if (!session || !clientId) {
      helpers.log.debug("Leaving LaunchLinks.noteLaunch(). Nothing to note.");
      return;
    }
    session.launches = Object.assign({}, session.launches || {});
    session.launches[clientId] = Math.floor(Number(nowS) || 0);
    helpers.log.debug("Leaving LaunchLinks.noteLaunch().");
  }

  /**
   * Whether a session carries a launch of a client no older than the window.
   *
   * @param session - the sign-on session, or null
   * @param clientId - the client
   * @param nowS - now, in seconds since the epoch
   * @param windowS - how old a launch may be
   * @returns true when there is one
   */
  static launchIsFresh(session: Json, clientId: string, nowS: number,
                       windowS: number): boolean {
    helpers.log.debug("Entering LaunchLinks.launchIsFresh().");
    const at = Number(session && session.launches &&
                      session.launches[clientId]);
    const fresh = isFinite(at) && at > 0 && nowS - at >= 0 &&
                  nowS - at <= Number(windowS);
    helpers.log.debug("Leaving LaunchLinks.launchIsFresh(). " + fresh);
    return fresh;
  }

  /**
   * Removes a client's launch from a session.
   *
   * @param session - the sign-on session
   * @param clientId - the client
   * @returns true when there was one to remove
   */
  static takeLaunch(session: Json, clientId: string): boolean {
    helpers.log.debug("Entering LaunchLinks.takeLaunch().");
    if (!session || !session.launches ||
        !Object.prototype.hasOwnProperty.call(session.launches, clientId)) {
      helpers.log.debug("Leaving LaunchLinks.takeLaunch(). None.");
      return false;
    }
    const kept = Object.assign({}, session.launches);
    delete kept[clientId];
    session.launches = kept;
    helpers.log.debug("Leaving LaunchLinks.takeLaunch(). Taken.");
    return true;
  }
}

export = LaunchLinks;
