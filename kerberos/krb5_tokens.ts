// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kerberos/krb5_tokens.ts
//
// ===========================================================================
// A KERBEROS TICKET AS A SECURITY TOKEN, OUTSIDE SPNEGO (#658, 2026-11-02).
//
// WS-Trust carries a Kerberos token in a `wsse:BinarySecurityToken` whose
// ValueType is one of the Web Services Security Kerberos Token Profile 1.1's
// six (section 3.1): an RFC 4120 AP-REQ, bare or in the RFC 4121 / RFC 1964
// GSS InitialContextToken, each with or without a claim to RFC 1510 or
// RFC 4120. RFC 8693's token exchange carries the same token as a
// `subject_token` / `actor_token` / `requested_token_type` named by the same
// URIs (rcbj's decision D1 on #658: one vocabulary across the two). This
// library is both directions for both callers; neither protocol module holds
// any Kerberos code of its own.
//
// ACCEPTING ONE IS THE ACCEPTOR'S JOB, AND ONLY THE ACCEPTOR'S.
// `krb5_service.js`'s `accept()` is the one place this service accepts an
// AP-REQ on any transport — the decryption under its own key, the
// Authenticator, the clock, the replay cache and its cluster-wide claim, the
// kvno and the kept versions, product's RC4 refusal, the authentication
// indicators — and a token here goes through it unchanged. So a Kerberos
// token is accepted only when it is FOR THIS SERVICE'S OWN SPN: the
// acceptor's rule that "a ticket for one service proves nothing to another"
// holds here too, which is the whole of why a delegated Kerberos token is
// read in Kerberos's OWN delegation syntax rather than as the user's ticket
// to the middle tier:
//
//   * a ticket the middle tier obtained by S4U2Proxy to this service's SPN
//     carries the services it was delegated through in its PAC
//     (S4U_DELEGATION_INFO, [MS-PAC] 2.9), the last of them the middle tier;
//   * a ticket bought with a TGT the user FORWARDED to the middle tier
//     carries the FORWARDED flag (RFC 4120 section 2.6), which is
//     unconstrained delegation;
//   * a ticket with neither is one the subject asked for and handed over,
//     and is refused inside OnBehalfOf / ActAs in every mode (rcbj, D2).
//
// What the ticket says is read and reported; WHO MAY ACT FOR WHOM is still
// the one delegation policy's (rule 3az), asked by the caller.
//
// ISSUING ONE IS THE KDC'S JOB. The STS and the KDC are one process, so the
// ticket in an issued token is sealed by `krb5_kdc.js`'s `mintTicket()` with
// the keys and the PAC builder every ticket of this realm goes through, and
// this library adds what a CLIENT adds: the Authenticator (the subject's
// name, a fresh subkey, the RFC 4121 0x8003 checksum in the GSS forms) and
// the AP-REQ around it. For a target in ANOTHER Kerberos realm (rcbj, D8)
// the STS walks the trust itself, as a client would: it mints the subject's
// referral TGT toward the next hop and sends a real TGS-REQ to that realm's
// KDC through `handleMessage()`, so the trust's path checks, SID filtering
// and TGT-delegation bits (#430) apply exactly as they do to anybody's
// ticket. Only a realm a trust realm of THIS PROCESS serves can be reached:
// a partner whose KDC is elsewhere has no address recorded on its trust, and
// is refused rather than dialled (`STS-KRB-0252`).
//
// A FORWARDED TGT IN THE ISSUED TOKEN (rcbj, D7): where the target is
// trusted for unconstrained delegation (`krb5TrustedForDelegation`) and the
// caller asks for it, the Authenticator's 0x8003 checksum carries
// GSS_C_DELEG_FLAG and a KRB-CRED holding a forwarded TGT for the subject,
// sealed under the Authenticator's subkey at key usage 14 — what a GSS
// initiator sends when it delegates (RFC 4121 section 4.1.1.1).
//
// EVERY MODULE OF THIS DIRECTORY IS REACHED LAZILY. `krb5_kdc.js` registers
// its routes when it is required, and WS-Trust (7) and the token endpoint (9)
// are required long before it (15); a require here at load would drag the
// KDC's routes ahead of `oauth2` (the root `CLAUDE.md`, rule 1). So this file
// requires only `common/` libraries at load, and the Kerberos modules inside
// the functions that need them, by which time every one is loaded.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import crypto = require('../common/crypto');

const { log } = helpers;

type Json = any;

// The profile's namespace and its six ValueTypes (section 3.1), and the
// KeyIdentifier ValueType that names a token (section 3.2).
const PROFILE = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-kerberos-token-profile-1.1';
const VALUE_TYPES = Object.freeze({
  AP_REQ: PROFILE + '#Kerberosv5_AP_REQ',
  GSS_AP_REQ: PROFILE + '#GSS_Kerberosv5_AP_REQ',
  AP_REQ_1510: PROFILE + '#Kerberosv5_AP_REQ1510',
  GSS_AP_REQ_1510: PROFILE + '#GSS_Kerberosv5_AP_REQ1510',
  AP_REQ_4120: PROFILE + '#Kerberosv5_AP_REQ4120',
  GSS_AP_REQ_4120: PROFILE + '#GSS_Kerberosv5_AP_REQ4120'
});
const ALL_TYPES = Object.keys(VALUE_TYPES).map(function (k) {
  return VALUE_TYPES[k];
});
const KEY_IDENTIFIER = PROFILE + '#Kerberosv5APREQSHA1';
// SAML 2.0's authentication context class for a Kerberos authentication
// (SAML 2.0 Authentication Context section 3.4.5).
const AUTHN_CONTEXT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos';
// The base64 encoding WS-Security names for a BinarySecurityToken.
const BASE64_ENCODING = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-soap-message-security-1.0#Base64Binary';
// The enctypes an issued ticket is offered in, most preferred first; the
// KDC keeps those the service holds and the realm's mode permits.
const ISSUE_ETYPES = [18, 17, 20, 19];
// Key usage 14: a KRB-CRED's enc-part (RFC 4120 section 7.5.1).
const KRB_CRED_ENCPART = 14;

/**
 * A Kerberos ticket as a security token: the Web Services Security Kerberos
 * Token Profile 1.1's AP-REQ, accepted through the acceptor and issued through
 * the KDC, for WS-Trust and the RFC 8693 token exchange (#658).
 */
class Krb5Tokens {
  static readonly VALUE_TYPES = VALUE_TYPES;
  static readonly KEY_IDENTIFIER = KEY_IDENTIFIER;
  static readonly AUTHN_CONTEXT = AUTHN_CONTEXT;
  static readonly BASE64_ENCODING = BASE64_ENCODING;

  /**
   * Says whether a URI is one of the profile's six Kerberos token types.
   *
   * @param uri - a ValueType, TokenType or RFC 8693 token type
   * @returns true for a Kerberos token type
   */
  static isType(uri: string): boolean {
    log.debug("Entering Krb5Tokens.isType().");
    const out = ALL_TYPES.indexOf(String(uri || '').trim()) !== -1;
    log.debug("Leaving Krb5Tokens.isType(). " + out);
    return out;
  }

  /**
   * Says whether a Kerberos token type is one of the three GSS forms.
   *
   * @param uri - a Kerberos token type
   * @returns true for a GSS-wrapped AP-REQ
   */
  static isGssType(uri: string): boolean {
    log.debug("Entering Krb5Tokens.isGssType().");
    const out = /#GSS_Kerberosv5_AP_REQ/.test(String(uri || ''));
    log.debug("Leaving Krb5Tokens.isGssType(). " + out);
    return out;
  }

  /**
   * The profile's key identifier of a token: the base64 SHA-1 of its bytes as
   * carried (section 3.2), which is also how the delegation register names
   * it.
   *
   * @param bytes - the token's bytes
   * @returns the base64 identifier
   */
  static keyIdentifierOf(bytes: Uint8Array): string {
    log.debug("Entering Krb5Tokens.keyIdentifierOf().");
    const out = crypto.kerberosTokenKeyIdentifier(bytes);
    log.debug("Leaving Krb5Tokens.keyIdentifierOf().");
    return out;
  }

  /**
   * Whether a boolean setting is on in the ambient realm.
   *
   * @param key - the setting
   * @returns true when on
   */
  static settingOn(key: string): boolean {
    log.debug("Entering Krb5Tokens.settingOn(). " + key);
    const value = config.value(key);
    const out = value === true || String(value).toLowerCase() === 'true';
    log.debug("Leaving Krb5Tokens.settingOn(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // `amr` AND `acr` FROM A TICKET'S OWN FLAGS AND INDICATORS — the one copy.
  //
  // Moved here from `spnego_authn.ts` (#658), which now asks this, because a
  // Kerberos token presented to WS-Trust or the token exchange says what the
  // KDC checked exactly as a SPNEGO ticket does, and two copies of the rule
  // would one day disagree. The argument is the SPNEGO sign-in's: `pwd` only
  // for `pre-authent` (a password-derived key was proven to the KDC), `hwk`
  // for `hw-authent`, `otp` for the RFC 8129 indicator of this realm, `swk`
  // for a PKINIT certificate not marked hardware-bound, NEVER `pwd` for a
  // PKINIT ticket, and `acr "mfa"` only for two of them.
  // -------------------------------------------------------------------------
  /**
   * Derives `amr` and `acr` from a ticket's flags and authentication
   * indicators.
   *
   * @param ticketFlags - the ticket's flag names
   * @param indicators - the ticket's authentication indicators
   * @param ownRealm - false for a ticket from a foreign realm, whose indicators
   *   count for nothing
   * @param via - how the ticket arrived, for the method sentence
   * @returns `{ amr, acr, method, password, hardware, otp, pkinit }`
   */
  static factorsFor(ticketFlags: string[], indicators?: string[],
                    ownRealm?: boolean, via?: string): Json {
    log.debug('Entering Krb5Tokens.factorsFor(). flags=' +
              (ticketFlags || []).join(',') + ' indicators=' +
              (indicators || []).join(','));
    const flags = ticketFlags || [];
    const own = ownRealm !== false ? (indicators || []) : [];
    const pkinit = own.indexOf('pkinit') !== -1;
    const password = flags.indexOf('pre-authent') !== -1 && !pkinit;
    const hardware = flags.indexOf('hw-authent') !== -1;
    const otp = own.indexOf('otp') !== -1;
    const amr = [];
    if (password) {
      amr.push('pwd');
    }
    if (hardware) {
      amr.push('hwk');
    } else if (pkinit) {
      amr.push('swk');
    }
    if (otp) {
      amr.push('otp');
    }
    const acr = (password && (hardware || otp)) ? 'mfa'
      : (amr.length ? '1' : '0');
    const method = (via || 'Kerberos ticket over SPNEGO') +
      (pkinit
         ? ' (the KDC checked a certificate with PKINIT' +
           (hardware ? ', a smart-card logon certificate whose key this ' +
                       'service never held' : '') + ')'
         : password && otp
         ? ' (the KDC checked the password and an authenticator app code, ' +
           'with FAST and OTP pre-authentication)'
         : password && hardware
         ? ' (the KDC required pre-authentication AND hardware)'
         : password
           ? ' (the KDC required pre-authentication, so a long-term key ' +
             'derived from a password was proven to it)'
           : hardware
             ? ' (the KDC required hardware for the initial authentication)'
             : ' (the ticket claims no pre-authentication at all, so nothing ' +
               'here knows what the KDC checked)');
    log.debug('Leaving Krb5Tokens.factorsFor(). amr=' + amr.join(',') +
              ', acr=' + acr);
    return { amr: amr, acr: acr, method: method, password: password,
             hardware: hardware, otp: otp, pkinit: pkinit };
  }

  // -------------------------------------------------------------------------
  // THE BYTES, AND WHETHER THEY ARE WHAT THE TYPE SAYS.
  //
  // The bare forms carry the AP-REQ itself; the GSS forms the
  // InitialContextToken around it. The acceptor reads a GSS token only — a
  // real GSS acceptor refuses a bare AP-REQ, and it says so — so a bare token
  // is wrapped here before it is handed over, which changes nothing the
  // acceptor checks: the wrapping is two fixed fields and the AP-REQ inside
  // is the one that was sent. A token whose bytes are the OTHER form than its
  // type names is refused (`STS-KRB-0249`): a caller that labels one as the
  // other has a bug that would bite the first relying party that believed the
  // label.
  // -------------------------------------------------------------------------
  /**
   * Reads a Kerberos token's bytes against its declared type.
   *
   * @param token - the token: bytes, or base64 / base64url text
   * @param valueType - its declared Kerberos token type
   * @returns `{ ok, bytes, gss, apReq }`, or `{ ok: false, errorCode, reason }`
   */
  static decode(token: Json, valueType: string): Json {
    log.debug("Entering Krb5Tokens.decode().");
    const gss = require('./krb5_gss.js');
    const msgs = require('./krb5_messages.js');
    let bytes: Uint8Array;
    if (token instanceof Uint8Array) {
      bytes = token;
    } else {
      const text = String(token || '').replace(/\s+/g, '')
        .replace(/-/g, '+').replace(/_/g, '/');
      bytes = new Uint8Array(Buffer.from(text, 'base64'));
    }
    if (!bytes.length) {
      log.debug("Leaving Krb5Tokens.decode(). Empty.");
      return { ok: false, errorCode: 'STS-KRB-0249',
               reason: 'the Kerberos token is empty' };
    }
    const wantGss = Krb5Tokens.isGssType(valueType);
    if (wantGss) {
      let inner = null;
      try {
        const read = gss.decodeInitialContextToken(bytes);
        inner = read.tokIdName === 'AP_REQ' ? read.inner : null;
      } catch (e) {
        log.debug("Caught in Krb5Tokens.decode(): " + ((e && e.message) || e));
        inner = null;
      }
      if (!inner) {
        log.debug("Leaving Krb5Tokens.decode(). Not a GSS AP-REQ.");
        return { ok: false, errorCode: 'STS-KRB-0249',
                 reason: 'the token is declared ' + valueType + ' and is not ' +
                         'a GSS InitialContextToken carrying an AP-REQ ' +
                         '(RFC 4121 section 4.1)' };
      }
      log.debug("Leaving Krb5Tokens.decode(). A GSS AP-REQ.");
      return { ok: true, bytes: bytes, gss: bytes,
               apReq: new Uint8Array(inner) };
    }
    try {
      msgs.readApReq(bytes);
    } catch (e) {
      log.debug("Caught in Krb5Tokens.decode(): " + ((e && e.message) || e));
      log.debug("Leaving Krb5Tokens.decode(). Not an AP-REQ.");
      return { ok: false, errorCode: 'STS-KRB-0249',
               reason: 'the token is declared ' + valueType + ' and is not ' +
                       'an RFC 4120 AP-REQ (' + ((e && e.message) || e) + ')' };
    }
    log.debug("Leaving Krb5Tokens.decode(). A bare AP-REQ.");
    return { ok: true, bytes: bytes, apReq: bytes,
             gss: gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, bytes) };
  }

  // -------------------------------------------------------------------------
  // ACCEPTING A TOKEN, AND READING WHAT ITS TICKET SAYS.
  //
  // `opts.via` is the sentence the acceptor's checks are filed under. The
  // acceptor RECORDS NOTHING (`record: false`): the caller records the
  // authentication once, as the SPNEGO sign-in does, so one token is one row.
  //
  // The verdict names the principal three ways — `principal` whole
  // (`alice@EXAMPLE.COM`), `name` as this service files it (the local realm
  // stripped from a person, as the SPNEGO sign-in strips it; a service, and
  // anybody of another realm, kept whole as `SPN@REALM` / `name@REALM`) —
  // and says what the ticket carries about delegation:
  //
  //   `shape: 's4u2proxy'` — S4U_DELEGATION_INFO, its transited services in
  //     the order they acted (`transited`), the last the party that asked;
  //   `shape: 'forwarded'` — the FORWARDED flag, a ticket bought with a
  //     forwarded TGT, whose forwarder the ticket does not name;
  //   `shape: 'none'` — neither.
  //
  // The PAC is not re-verified: the ticket decrypted under this service's
  // own key, which only this process holds, so nobody but this KDC could have
  // written it (the CVE-2020-17049 concern is a SERVICE forging a ticket
  // sealed in its own key, and the service here is the STS).
  // -------------------------------------------------------------------------
  /**
   * Accepts a Kerberos token through the acceptor and reads its ticket.
   *
   * @param token - the token: bytes, or base64 text
   * @param valueType - its declared Kerberos token type
   * @param opts - `{ via }`
   * @returns the verdict
   */
  static async accept(token: Json, valueType: string, opts?: Json):
      Promise<Json> {
    log.debug("Entering Krb5Tokens.accept(). " + valueType);
    const options = opts || {};
    const decoded = Krb5Tokens.decode(token, valueType);
    if (!decoded.ok) {
      log.debug("Leaving Krb5Tokens.accept(). Undecodable.");
      return decoded;
    }
    const keyIdentifier = Krb5Tokens.keyIdentifierOf(decoded.bytes);
    const service = require('./krb5_service.js');
    const principals = require('./krb5_principals.js');
    const kpac = require('./krb5_pac.js');
    let result: Json;
    try {
      result = await service.accept(decoded.gss, {
        record: false, via: String(options.via || 'a Kerberos token') });
    } catch (e) {
      log.debug("Caught in Krb5Tokens.accept(): " + ((e && e.message) || e));
      result = { ok: false, errorCode: 'STS-KRB-0250',
                 checks: [{ name: 'the acceptor', ok: false,
                            detail: String((e && e.message) || e) }] };
    }
    if (!result || !result.ok) {
      const failed = ((result && result.checks) || []).filter(
        function (c: Json): boolean { return !c.ok; });
      const last = failed.length ? failed[failed.length - 1] : null;
      log.info('krb5-tokens: a Kerberos token (' + valueType + ') was ' +
               'refused by the acceptor: ' +
               (last ? last.name + ' — ' + last.detail : 'no reason'));
      log.debug("Leaving Krb5Tokens.accept(). Refused.");
      return { ok: false, keyIdentifier: keyIdentifier,
               errorCode: String((result && result.errorCode) ||
                                 'STS-KRB-0250'),
               reason: 'The Kerberos token was refused: ' +
                       (last ? last.name + ' failed' +
                               (last.detail ? ' (' + last.detail + ')' : '')
                             : 'the acceptor did not accept it') + '.' };
    }
    const ticket = result.ticket || {};
    const components = ((ticket.cname && ticket.cname.name) || [])
      .map(String);
    const crealm = String(ticket.crealm || '');
    const localRealm = String(principals.REALM || '');
    const isService = components.length > 1;
    const ownRealm = crealm === localRealm;
    const whole = components.join('/') + '@' + crealm;
    const name = !isService && ownRealm ? components.join('/') : whole;
    // What the PAC says about delegation.
    let transited: string[] = [];
    let target = '';
    let hasDelegationInfo = false;
    let pacBytes: Uint8Array = null;
    try {
      const pacs = kpac.findPacs(ticket.authorizationData || []);
      if (pacs.length) {
        pacBytes = pacs[0].bytes;
        const entry = kpac.bufferOfType(kpac.parsePac(pacBytes),
                                        kpac.TYPE.DELEGATION_INFO);
        if (entry && entry.parsed) {
          hasDelegationInfo = true;
          transited = (entry.parsed.transitedServices || []).map(String);
          target = String(entry.parsed.s4u2proxyTarget || '');
        }
      }
    } catch (e) {
      // A PAC this service cannot parse is no delegation record; the ticket
      // was still accepted, and nothing is read off what could not be read.
      log.debug("Caught in Krb5Tokens.accept(): " + ((e && e.message) || e));
    }
    const flags = (ticket.flags || []).map(String);
    const shape = hasDelegationInfo ? 's4u2proxy'
      : (flags.indexOf('forwarded') !== -1 ? 'forwarded' : 'none');
    const factors = Krb5Tokens.factorsFor(flags, result.authIndicators || [],
      ownRealm, 'a Kerberos token (' + String(options.via ||
                                              'Kerberos Token Profile') + ')');
    const skew = Number(config.value('krb5.clockSkew')) || 300;
    log.info('krb5-tokens: ACCEPTED a Kerberos token for ' + whole +
             ' (' + shape + (transited.length ? ', transited ' +
                             transited.join(' → ') : '') + ')');
    log.debug("Leaving Krb5Tokens.accept(). " + whole);
    return {
      ok: true,
      keyIdentifier: keyIdentifier,
      principal: whole,
      components: components,
      realm: crealm,
      name: name,
      isService: isService,
      ownRealm: ownRealm,
      flags: flags,
      indicators: result.authIndicators || [],
      amr: factors.amr,
      acr: factors.acr,
      method: factors.method,
      authtime: ticket.authtime || null,
      endtime: ticket.endtime || null,
      // The Authenticator's own window: a Kerberos token is good once, within
      // the clock skew of when it was made.
      expires: ticket.ctime
        ? new Date(new Date(ticket.ctime).getTime() + skew * 1000) : null,
      serviceName: ((ticket.sname && ticket.sname.name) || []).join('/') +
                   '@' + String(ticket.realm || ''),
      shape: shape,
      transited: transited,
      target: target,
      pac: pacBytes,
      sessionKey: { etype: result.sessionKeyEtype, key: result.sessionKey },
      subkey: result.initiatorSubkey || null,
      gss: result.gss || null
    };
  }

  // -------------------------------------------------------------------------
  // A PARTY OF A DELEGATION CHAIN, BY NAME. `S4U_DELEGATION_INFO` names a
  // service `SPN@REALM` (#489); an application with no SPN is named by its
  // identifier (rcbj, D4). The registry is the one place either resolves,
  // so this answers the APPLICATION's identifier where it holds one, and the
  // name as written otherwise.
  // -------------------------------------------------------------------------
  /**
   * The application identifier a transited service names, or the name as it
   * was written.
   *
   * @param transited - an `S4U_DELEGATION_INFO` entry
   * @returns the application's identifier, or the entry
   */
  static applicationOfTransited(transited: string): string {
    log.debug("Entering Krb5Tokens.applicationOfTransited().");
    const applications = require('../common/applications');
    const entry = String(transited || '');
    const found = entry ? applications.get(entry) : null;
    const out = found && found.identifier ? String(found.identifier) : entry;
    log.debug("Leaving Krb5Tokens.applicationOfTransited(). " + out);
    return out;
  }

  /**
   * The SPN an application is a Kerberos service under, and its realm: its
   * identifier when that is `SPN@REALM`, else its `krb5ServicePrincipalName`.
   *
   * @param application - the application entry, or null
   * @returns `{ spn, realm }`, or null for an application that is no Kerberos
   *   service
   */
  static servicePrincipalOf(application: Json): Json {
    log.debug("Entering Krb5Tokens.servicePrincipalOf().");
    if (!application) {
      log.debug("Leaving Krb5Tokens.servicePrincipalOf(). No application.");
      return null;
    }
    const field = application.fields &&
      application.fields.krb5ServicePrincipalName;
    const candidates = [String(application.identifier || '')].concat(
      [].concat(field || []).map(String));
    for (const one of candidates) {
      const m = /^([^@\s]+\/[^@\s]+)@([^@\s]+)$/.exec(one);
      if (m) {
        log.debug("Leaving Krb5Tokens.servicePrincipalOf(). " + one);
        return { spn: m[1], realm: m[2] };
      }
    }
    log.debug("Leaving Krb5Tokens.servicePrincipalOf(). None.");
    return null;
  }

  /**
   * Says whether an application is trusted for UNCONSTRAINED delegation
   * (`krb5TrustedForDelegation` on its entry, off by default) — the one fact
   * that lets a party receive a forwarded TGT, in the KDC and here.
   *
   * @param application - the application entry, or null
   * @returns true when trusted
   */
  static trustedForDelegation(application: Json): boolean {
    log.debug("Entering Krb5Tokens.trustedForDelegation().");
    const raw = application && application.fields
      ? application.fields.krb5TrustedForDelegation : undefined;
    const first = Array.isArray(raw) ? raw[0] : raw;
    const out = String(first === undefined || first === null ? '' : first)
      .toUpperCase() === 'TRUE';
    log.debug("Leaving Krb5Tokens.trustedForDelegation(). " + out);
    return out;
  }

  /**
   * Says whether a person may not be delegated (a protected user: [MS-SFU]
   * 3.2.1's DelegationNotAllowed, `stsNotDelegated`), as the KDC asks it.
   *
   * @param name - the person's name components
   * @param realm - their Kerberos realm
   * @returns true when protected
   */
  static isProtected(name: string[], realm: string): boolean {
    log.debug("Entering Krb5Tokens.isProtected().");
    let out = false;
    try {
      out = !!require('./krb5_delegation').isProtected(name, realm);
    } catch (e) {
      // No delegation register in this process: nobody is known to be
      // protected, which is the answer the KDC itself gives without one.
      log.debug("Caught in Krb5Tokens.isProtected(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving Krb5Tokens.isProtected(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // ISSUING A TOKEN.
  //
  // `spec`: { valueType, subject: { name, realm }, target: { spn, realm },
  //   delegationInfo: { s4u2proxyTarget, transitedServices } | null,
  //   forwardable, forwardTgt, carriedPac, lifetimeSeconds }.
  //
  // Answers `{ ok, token (base64), bytes, keyIdentifier, sessionKey, subkey,
  // ticketEndtime, expires, flags, servicePrincipal }`, or a refusal with the
  // KDC's code. `sessionKey` is the key a relying party and the holder share
  // once the AP-REQ is accepted — the subkey where the Authenticator carries
  // one, which this one always does (RFC 4121 section 4.1.1: the initiator's
  // subkey keys what follows) — and is what the caller delivers as the proof
  // token.
  // -------------------------------------------------------------------------
  /**
   * Issues a Kerberos token for a subject to a target service.
   *
   * @param spec - what to issue
   * @returns the token, or a refusal
   */
  static async issue(spec: Json): Promise<Json> {
    log.debug("Entering Krb5Tokens.issue(). " +
              (spec && spec.subject && spec.subject.name) + " to " +
              (spec && spec.target && spec.target.spn));
    const principals = require('./krb5_principals.js');
    const localRealm = String(principals.REALM || '');
    const subjectName = String(spec.subject.name || '');
    const subjectRealm = String(spec.subject.realm || localRealm);
    const subjectComponents = subjectName.split('/');
    const targetRealm = String(spec.target.realm || localRealm);
    const targetSpn = String(spec.target.spn || '');
    let ticket: Json;
    if (targetRealm === localRealm) {
      const kdc = require('./krb5_kdc.js');
      ticket = await kdc.mintTicket({
        client: { name: subjectComponents, realm: subjectRealm },
        service: { name: targetSpn.split('/') },
        forwardable: !!spec.forwardable,
        delegationInfo: spec.delegationInfo || null,
        carriedPac: spec.carriedPac || null,
        lifetimeSeconds: spec.lifetimeSeconds,
        etypes: ISSUE_ETYPES
      });
    } else {
      ticket = await Krb5Tokens.acrossTrusts(spec, subjectComponents,
                                             subjectRealm, localRealm);
    }
    if (!ticket.ok) {
      log.debug("Leaving Krb5Tokens.issue(). No ticket.");
      return ticket;
    }
    let delegated: Uint8Array = null;
    const subkeyProfile = require('./krb5_crypto.js').etypeById(
      ticket.sessionKey.etype);
    const subkey = { etype: ticket.sessionKey.etype,
                     key: require('./krb5_crypto.js').randomBytes(
                       subkeyProfile.keyBytes) };
    if (spec.forwardTgt) {
      const forwarded = await Krb5Tokens.forwardedCredential(
        subjectComponents, subjectRealm, subkey);
      if (!forwarded.ok) {
        log.debug("Leaving Krb5Tokens.issue(). No forwarded TGT.");
        return forwarded;
      }
      delegated = forwarded.krbCred;
    }
    const built = await Krb5Tokens.apRequest(ticket, subkey, spec.valueType,
                                             delegated);
    const skew = Number(config.value('krb5.clockSkew')) || 300;
    log.debug("Leaving Krb5Tokens.issue(). " + built.bytes.length +
              " bytes.");
    return {
      ok: true,
      valueType: spec.valueType,
      token: Buffer.from(built.bytes).toString('base64'),
      bytes: built.bytes,
      keyIdentifier: Krb5Tokens.keyIdentifierOf(built.bytes),
      sessionKey: subkey,
      ticketSessionKey: ticket.sessionKey,
      subkey: subkey,
      flags: ticket.flags || [],
      ticketEndtime: ticket.endtime,
      created: built.ctime,
      expires: new Date(built.ctime.getTime() + skew * 1000),
      forwardedTgt: !!delegated,
      servicePrincipal: targetSpn + '@' + targetRealm
    };
  }

  /**
   * Builds the AP-REQ: the subject's Authenticator under the ticket's session
   * key, with the 0x8003 checksum in the GSS forms (carrying a KRB-CRED when
   * one is delegated), wrapped as the type asks.
   *
   * @param ticket - what `mintTicket()` or the walk answered
   * @param subkey - the Authenticator's subkey
   * @param valueType - the Kerberos token type asked for
   * @param delegated - a KRB-CRED to carry, or null
   * @returns `{ bytes, ctime }`
   */
  static async apRequest(ticket: Json, subkey: Json, valueType: string,
                         delegated: Uint8Array): Promise<Json> {
    log.debug("Entering Krb5Tokens.apRequest().");
    const msgs = require('./krb5_messages.js');
    const gss = require('./krb5_gss.js');
    const kcrypto = require('./krb5_crypto.js');
    const profile = kcrypto.etypeById(ticket.sessionKey.etype);
    const gssForm = Krb5Tokens.isGssType(valueType);
    const at = new Date();
    const ctime = new Date(Math.floor(at.getTime() / 1000) * 1000);
    const flags = [gss.GSS_FLAG.INTEG, gss.GSS_FLAG.CONF];
    if (delegated) {
      flags.push(gss.GSS_FLAG.DELEG);
    }
    const cksum = gssForm || delegated
      ? { type: gss.CHECKSUM_TYPE_GSS,
          checksum: gss.buildGssChecksum({ flags: flags,
                                           channelBindings: null,
                                           delegation: delegated || null }) }
      : null;
    const seq = kcrypto.randomBytes(4);
    const authenticator = msgs.encAuthenticator({
      crealm: ticket.crealm,
      cname: ticket.cname,
      cksum: cksum,
      cusec: (at.getMilliseconds() * 1000) % 1000000,
      ctime: ctime,
      subkey: subkey,
      seqNumber: ((seq[0] & 0x7f) << 24) | (seq[1] << 16) | (seq[2] << 8) |
                 seq[3]
    });
    const apReq = msgs.encApReq({
      apOptions: [],
      ticket: ticket.ticket,
      authenticator: {
        etype: ticket.sessionKey.etype,
        cipher: await profile.encrypt(ticket.sessionKey.key,
                                      kcrypto.KEY_USAGE.AP_REQ_AUTH,
                                      authenticator)
      }
    });
    const bytes = gssForm
      ? gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq) : apReq;
    log.debug("Leaving Krb5Tokens.apRequest().");
    return { bytes: new Uint8Array(bytes), ctime: ctime };
  }

  // -------------------------------------------------------------------------
  // A FORWARDED TGT FOR THE SUBJECT, AS A KRB-CRED (rcbj, D7). RFC 4120
  // section 5.8: the TGT in `tickets`, its session key in the encrypted
  // `ticket-info`, sealed under the Authenticator's subkey at key usage 14,
  // so only the service the token is for can open it. The TGT is minted by
  // the KDC with FORWARDED and FORWARDABLE (the subject's protection is the
  // KDC's to apply); whether the TARGET may receive one is the caller's
  // decision, made before this is asked.
  // -------------------------------------------------------------------------
  /**
   * Mints a forwarded TGT for the subject and wraps it in a KRB-CRED.
   *
   * @param components - the subject's name components
   * @param realm - the subject's realm
   * @param subkey - the Authenticator's subkey, which seals the KRB-CRED
   * @returns `{ ok, krbCred }`, or a refusal
   */
  static async forwardedCredential(components: string[], realm: string,
                                   subkey: Json): Promise<Json> {
    log.debug("Entering Krb5Tokens.forwardedCredential().");
    const kdc = require('./krb5_kdc.js');
    const msgs = require('./krb5_messages.js');
    const kcrypto = require('./krb5_crypto.js');
    const principals = require('./krb5_principals.js');
    const localRealm = String(principals.REALM || '');
    const tgt = await kdc.mintTicket({
      client: { name: components, realm: realm },
      service: { name: ['krbtgt', localRealm] },
      forwardable: true, forwarded: true, etypes: ISSUE_ETYPES
    });
    if (!tgt.ok) {
      log.debug("Leaving Krb5Tokens.forwardedCredential(). Refused.");
      return tgt;
    }
    const encPart = msgs.encEncKrbCredPart({
      ticketInfo: [{
        key: tgt.sessionKey,
        prealm: tgt.crealm,
        pname: tgt.cname,
        flags: tgt.flagBits,
        authtime: tgt.authtime,
        starttime: tgt.starttime,
        endtime: tgt.endtime,
        srealm: tgt.realm,
        sname: tgt.sname
      }],
      timestamp: new Date(Math.floor(Date.now() / 1000) * 1000),
      usec: 0
    });
    const profile = kcrypto.etypeById(subkey.etype);
    const krbCred = msgs.encKrbCred({
      tickets: [tgt.ticket],
      encPart: { etype: subkey.etype,
                 cipher: await profile.encrypt(subkey.key, KRB_CRED_ENCPART,
                                               encPart) }
    });
    log.debug("Leaving Krb5Tokens.forwardedCredential().");
    return { ok: true, krbCred: new Uint8Array(krbCred) };
  }

  // -------------------------------------------------------------------------
  // A TARGET IN ANOTHER KERBEROS REALM (rcbj, D8 on #658).
  //
  // The STS walks the trust path as a client walks it (RFC 4120 section
  // 1.2): a referral TGT for the subject toward the next hop, minted by this
  // realm's KDC (`mintTicket()` seals `krbtgt/<hop>@<us>` with the trust's
  // outgoing key and signs its PAC with that key, as `issueReferral()` does),
  // then a TGS-REQ to the next hop's KDC presenting it; a reply naming
  // `krbtgt/<further>@<hop>` is another referral and the walk goes on, at
  // most `krb5.maxReferralHops` times. Every hop's KDC applies its own trust
  // record — the path, SID filtering, the TGT-delegation bits, the roles a
  // foreign principal may hold — because this is an ordinary TGS-REQ to it.
  // `S4U_DELEGATION_INFO` rides in the referral's PAC, which each hop
  // re-signs and keeps (`resignPac()` keeps every content buffer).
  //
  // A hop is sent to `handleMessage()`, which answers it in the trust realm
  // of THIS PROCESS that serves that Kerberos realm; a realm no trust realm
  // here serves is refused (`STS-KRB-0252`), because no trust record carries
  // a KDC's address and this service dials none a request could choose.
  // -------------------------------------------------------------------------
  /**
   * Obtains a ticket for a service in another Kerberos realm by walking the
   * trusts.
   *
   * @param spec - what `issue()` was asked
   * @param components - the subject's name components
   * @param subjectRealm - the subject's realm
   * @param localRealm - this KDC's realm
   * @returns the ticket, as `mintTicket()` answers one, or a refusal
   */
  static async acrossTrusts(spec: Json, components: string[],
                            subjectRealm: string, localRealm: string):
      Promise<Json> {
    log.debug("Entering Krb5Tokens.acrossTrusts(). to " + spec.target.realm);
    const kdc = require('./krb5_kdc.js');
    const msgs = require('./krb5_messages.js');
    const kcrypto = require('./krb5_crypto.js');
    const principals = require('./krb5_principals.js');
    const targetRealm = String(spec.target.realm);
    const register = principals.trustRegister();
    const firstHop = register ? register.nextHopForRealm(targetRealm) : '';
    if (!firstHop) {
      log.debug("Leaving Krb5Tokens.acrossTrusts(). No route.");
      return { ok: false, errorCode: 'STS-KRB-0251',
               reason: 'no trust of ' + localRealm + ' routes to the ' +
                       'Kerberos realm ' + targetRealm };
    }
    let current: Json = await kdc.mintTicket({
      client: { name: components, realm: subjectRealm },
      service: { name: ['krbtgt', firstHop] },
      forwardable: !!spec.forwardable,
      delegationInfo: spec.delegationInfo || null,
      carriedPac: spec.carriedPac || null,
      lifetimeSeconds: spec.lifetimeSeconds,
      etypes: ISSUE_ETYPES
    });
    if (!current.ok) {
      log.debug("Leaving Krb5Tokens.acrossTrusts(). No referral.");
      return current;
    }
    let hop = firstHop;
    const maxHops = Math.max(1, Number(config.value('krb5.maxReferralHops')) ||
                                1);
    const sname = { type: msgs.NAME_TYPE.SRV_INST,
                    name: String(spec.target.spn).split('/') };
    for (let crossings = 0; crossings < maxHops; crossings++) {
      if (!principals.trustRealmFor(hop)) {
        log.debug("Leaving Krb5Tokens.acrossTrusts(). Not served here.");
        return { ok: false, errorCode: 'STS-KRB-0252',
                 reason: 'the Kerberos realm ' + hop + ' is served by no ' +
                         'trust realm of this service, and no trust record ' +
                         'carries the address of its KDC' };
      }
      const exchange = await Krb5Tokens.tgsExchange(kdc, msgs, kcrypto,
                                                    current, sname, hop);
      if (!exchange.ok) {
        log.debug("Leaving Krb5Tokens.acrossTrusts(). Refused at " + hop);
        return exchange;
      }
      const issued = exchange.ticket;
      const named = (issued.sname.name || []).map(String);
      if (named[0] === 'krbtgt' && named[1] !== hop) {
        hop = named[1];
        current = issued;
        continue;
      }
      log.debug("Leaving Krb5Tokens.acrossTrusts(). A ticket from " + hop);
      return issued;
    }
    log.debug("Leaving Krb5Tokens.acrossTrusts(). Too many hops.");
    return { ok: false, errorCode: 'STS-KRB-0254',
             reason: 'reaching ' + targetRealm + ' took more than ' +
                     'krb5.maxReferralHops (' + maxHops + ') crossings' };
  }

  /**
   * Sends one TGS-REQ for a service, presenting a ticket-granting ticket the
   * STS holds the session key of, to the KDC of `realm` in this process.
   *
   * @param kdc - `krb5_kdc.js`
   * @param msgs - the codec's messages
   * @param kcrypto - the codec's crypto
   * @param tgt - the presented TGT, as `mintTicket()` answers one
   * @param sname - the service asked for
   * @param realm - the realm the request names
   * @returns `{ ok, ticket }`, the ticket shaped as `mintTicket()` answers
   *   one, or a refusal
   */
  static async tgsExchange(kdc: Json, msgs: Json, kcrypto: Json, tgt: Json,
                           sname: Json, realm: string): Promise<Json> {
    log.debug("Entering Krb5Tokens.tgsExchange(). " +
              sname.name.join('/') + '@' + realm);
    const profile = kcrypto.etypeById(tgt.sessionKey.etype);
    const nonceBytes = kcrypto.randomBytes(4);
    const nonce = ((nonceBytes[0] & 0x7f) << 24) | (nonceBytes[1] << 16) |
                  (nonceBytes[2] << 8) | nonceBytes[3];
    const body = msgs.encKdcReqBody({
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.CANONICALIZE]
        .filter(function (one: Json): boolean { return one !== undefined; }),
      realm: realm,
      sname: sname,
      till: tgt.endtime,
      nonce: nonce,
      etypes: ISSUE_ETYPES
    });
    const checksum = await profile.checksum(tgt.sessionKey.key,
      kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM, body);
    const now = new Date();
    const authenticator = msgs.encAuthenticator({
      crealm: tgt.crealm,
      cname: tgt.cname,
      cksum: { type: profile.checksumType, checksum: checksum },
      cusec: (now.getMilliseconds() * 1000) % 1000000,
      ctime: new Date(Math.floor(now.getTime() / 1000) * 1000)
    });
    const apReq = msgs.encApReq({
      apOptions: [],
      ticket: tgt.ticket,
      authenticator: {
        etype: tgt.sessionKey.etype,
        cipher: await profile.encrypt(tgt.sessionKey.key,
                                      kcrypto.KEY_USAGE.TGS_REQ_AUTH,
                                      authenticator)
      }
    });
    const request = msgs.encKdcReq({
      msgType: msgs.MSG_TYPE.TGS_REQ,
      padata: [{ type: msgs.PA_TYPE.TGS_REQ, value: apReq }],
      reqBody: { raw: body }
    });
    const replyBytes = await kdc.handleMessage(request);
    const reply = msgs.readKdcResponse(replyBytes);
    if (reply.kind === 'KRB-ERROR') {
      const refusal = kdc.refusalOf(replyBytes);
      const error = reply.error || {};
      log.debug("Leaving Krb5Tokens.tgsExchange(). Refused.");
      return { ok: false,
               errorCode: refusal ? refusal.code : 'STS-KRB-0253',
               reason: 'the KDC of ' + realm + ' refused the ticket for ' +
                       sname.name.join('/') + ': ' +
                       msgs.describeError(error.errorCode).name +
                       (error.eText ? ' — ' + error.eText : '') };
    }
    const rep = reply.rep;
    const part = msgs.readEncKdcRepPart(
      await kcrypto.etypeById(rep.encPart.etype).decrypt(
        tgt.sessionKey.key, kcrypto.KEY_USAGE.TGS_REP_ENCPART_SESSKEY,
        rep.encPart.cipher));
    log.debug("Leaving Krb5Tokens.tgsExchange(). " +
              (part.sname.name || []).join('/') + '@' + part.srealm);
    return {
      ok: true,
      ticket: {
        ok: true,
        ticket: rep.ticket,
        sessionKey: part.key,
        flags: msgs.ticketFlagNames(part.flags),
        flagBits: part.flags,
        authtime: part.authtime,
        starttime: part.starttime || null,
        endtime: part.endtime,
        crealm: rep.crealm,
        cname: rep.cname,
        sname: part.sname,
        realm: part.srealm
      }
    };
  }
}

export = {
  Krb5Tokens: Krb5Tokens,
  VALUE_TYPES: VALUE_TYPES,
  KEY_IDENTIFIER: KEY_IDENTIFIER,
  AUTHN_CONTEXT: AUTHN_CONTEXT,
  BASE64_ENCODING: BASE64_ENCODING,
  isType: Krb5Tokens.isType,
  isGssType: Krb5Tokens.isGssType,
  keyIdentifierOf: Krb5Tokens.keyIdentifierOf,
  settingOn: Krb5Tokens.settingOn,
  factorsFor: Krb5Tokens.factorsFor,
  decode: Krb5Tokens.decode,
  accept: Krb5Tokens.accept,
  issue: Krb5Tokens.issue,
  applicationOfTransited: Krb5Tokens.applicationOfTransited,
  servicePrincipalOf: Krb5Tokens.servicePrincipalOf,
  trustedForDelegation: Krb5Tokens.trustedForDelegation,
  isProtected: Krb5Tokens.isProtected
};
