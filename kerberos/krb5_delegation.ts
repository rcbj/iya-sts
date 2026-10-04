// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kerberos/krb5_delegation.ts
//
// ===========================================================================
// WHO MAY ACT FOR WHOM AT THE KDC (#186, 2026-10-03).
//
// Kerberos delegation was decided by the KDC from msDS-* fields on its own
// principal table. #186 made it the SAME decision WS-Trust's OnBehalfOf /
// ActAs and the RFC 8693 token exchange make: the common controls on the
// directory's entries (`common/delegation_policy.ts`, rule 3az), asked of
// the issuance policy. rcbj's decisions on #186:
//
//   * S4U2Self is IMPERSONATION, and its actor is the service, which is R as
//     well; S4U2Proxy (classic or resource-based) is DELEGATION, and its
//     actor is the front end, which is S.
//   * ENTRIES ONLY. A Kerberos service is the application entry whose
//     identifier is its `SPN@REALM`; a person is their entry. The
//     development fixtures' rules are SEEDS for those entries
//     (`krb5_principals.js`'s `delegationSeeds()`), written here the first
//     time a realm is asked, filling only what an entry does not hold.
//   * THE KDC ENFORCES IN BOTH MODES, as it always has: the fixtures make
//     every refusal reachable in development, and a KDC that issued a
//     refused S4U2Proxy would change what goes on the wire.
//   * Unconstrained delegation is `krb5TrustedForDelegation` on the service,
//     off by default: its tickets carry ok-as-delegate.
//   * PA-S4U-X509-USER, Protected Users and a Bronze Bit check are added.
//
// THIS FILE DECIDES NOTHING. It names the parties, asks
// `delegation_policy.ts`, and holds the two pieces of Kerberos machinery
// that are not policy: the PAC check on an evidence ticket (CVE-2020-17049,
// and the forged-evidence case behind it) and PA-S4U-X509-USER's encoding.
// `krb5_kdc.js` requires it LAZILY, so a process that never sees an S4U
// request never loads it (and the parent project's COPY closure, which
// `kerberos/CLAUDE.md` tracks, is owed it only when it bumps past #186).
//
// A LIBRARY with no route and no store.
// ===========================================================================

import helpers = require('../common/helpers');
import applications = require('../common/applications');
import delegationPolicy = require('../common/delegation_policy');
import realms = require('../common/realms');
import principals = require('./krb5_principals');
import asn1 = require('./krb5_asn1');
import msgs = require('./krb5_messages');
import kcrypto = require('./krb5_crypto');
import kpac = require('./krb5_pac');
import prim = require('./krb5_primitives');

const { log } = helpers;

type Json = any;

// [MS-SFU] 2.2.2: PA-S4U-X509-USER's checksum is key usage 26, and 27 in a
// reply when the request set KERB_S4U_OPTIONS_use_reply_key_usage.
const S4U_X509_USER_CKSUM = 26;
const S4U_X509_USER_REPLY_CKSUM = 27;
// The options are a BIT STRING counted from the most significant bit:
// 0x20000000 is bit 2.
const OPTION_USE_REPLY_KEY_USAGE = 2;

/**
 * The Kerberos side of the delegation policy (#186): the parties of an S4U
 * request as the policy names them, the development seeds, the evidence
 * ticket's PAC check and PA-S4U-X509-USER.
 */
class Krb5Delegation {
  // The realms whose fixture seeds have been written in this process.
  private seeded: Set<string> = new Set();

  /**
   * The application identifier of a Kerberos service: `SPN@REALM`.
   *
   * @param name - the principal's name components
   * @param realm - its realm
   * @returns the identifier
   */
  static identifierOf(name: string[], realm: string): string {
    log.debug("Entering Krb5Delegation.identifierOf().");
    log.debug("Leaving Krb5Delegation.identifierOf().");
    return (name || []).join('/') + '@' + String(realm || '');
  }

  // The values of one attribute on an application row.
  private static valuesOf(row: Json, attribute: string): string[] {
    log.debug("Entering Krb5Delegation.valuesOf().");
    const raw = row && row.fields ? row.fields[attribute] : undefined;
    log.debug("Leaving Krb5Delegation.valuesOf().");
    return (Array.isArray(raw) ? raw : (raw === undefined || raw === null ||
      raw === '' ? [] : [raw])).map(String).filter(Boolean);
  }

  // -------------------------------------------------------------------------
  // THE SEEDS. The fixtures exist only in development; their rules are
  // written onto the services' entries the first time this realm is asked,
  // and only where the entry does not already hold a value, so an operator's
  // edit is never undone. Nothing is marked done while there is no registry
  // to write into: a process without the directory has no entries at all.
  // -------------------------------------------------------------------------
  /**
   * Writes the development fixtures' delegation rules onto the services'
   * application entries in the ambient realm, once per process.
   */
  ensureSeeded(): void {
    log.debug("Entering Krb5Delegation.ensureSeeded().");
    const realmId = realms.currentId();
    if (this.seeded.has(realmId)) {
      log.debug("Leaving Krb5Delegation.ensureSeeded(). Done before.");
      return;
    }
    const seeds = principals.delegationSeeds();
    if (!seeds.length) {
      this.seeded.add(realmId);
      log.debug("Leaving Krb5Delegation.ensureSeeded(). Nothing to seed.");
      return;
    }
    if (!applications.registryAvailable()) {
      log.debug("Leaving Krb5Delegation.ensureSeeded(). No registry.");
      return;
    }
    seeds.forEach(function (seed: Json) {
      const row = applications.get(seed.identifier);
      if (!row) {
        const made = applications.createApplication({
          identifier: seed.identifier, kind: 'kerberos-service',
          protocols: ['krb5'],
          fields: Object.assign({ krb5ServicePrincipalName:
                                    [seed.identifier] }, seed.fields),
          actor: 'the Kerberos fixtures (development)'
        });
        if (!made || !made.ok) {
          log.warn('krb5: the fixture service ' + seed.identifier +
                   ' could not be given an entry: ' +
                   ((made && made.errors) || []).join(' '));
        }
        return;
      }
      Object.keys(seed.fields).forEach(function (attribute) {
        if (Krb5Delegation.valuesOf(row, attribute).length) {
          return;
        }
        // A list is added value by value; a single value is set.
        const many = Array.isArray(seed.fields[attribute]);
        [].concat(seed.fields[attribute]).forEach(function (value: string) {
          applications.updateApplication(seed.identifier, {
            attribute: attribute, mode: many ? 'add' : 'set', value: value,
            actor: 'the Kerberos fixtures (development)'
          });
        });
      });
    });
    this.seeded.add(realmId);
    log.debug("Leaving Krb5Delegation.ensureSeeded(). " + seeds.length +
              " seed(s).");
  }

  // How the policy names a principal: a service by the identifier of its
  // application entry, a person by their username. A principal of another
  // realm is named whole — cross-realm delegation is #430's.
  private partyName(name: string[], realm: string): string {
    log.debug("Entering Krb5Delegation.partyName().");
    const id = Krb5Delegation.identifierOf(name, realm);
    if (applications.get(id)) {
      log.debug("Leaving Krb5Delegation.partyName(). An application.");
      return id;
    }
    const ours = principals.kerberosRealmOf(realms.currentId()).kerberosRealm;
    const out = realm === ours ? (name || []).join('/') : id;
    log.debug("Leaving Krb5Delegation.partyName(). " + out);
    return out;
  }

  /**
   * Says whether nobody may act for this principal — its entry's own flag,
   * or a protected group (Active Directory's NOT_DELEGATED and Protected
   * Users). The KDC then gives it no forwardable ticket.
   *
   * @param name - the principal's name components
   * @param realm - its realm
   * @returns true when protected
   */
  isProtected(name: string[], realm: string): boolean {
    log.debug("Entering Krb5Delegation.isProtected().");
    this.ensureSeeded();
    const out = !!delegationPolicy.subjectProtected(this.partyName(name,
                                                                   realm));
    log.debug("Leaving Krb5Delegation.isProtected(). " + out);
    return out;
  }

  /**
   * Says whether a service is trusted for UNCONSTRAINED delegation
   * (`krb5TrustedForDelegation`), which puts ok-as-delegate on its tickets.
   *
   * @param name - the service's name components
   * @param realm - its realm
   * @returns true when trusted
   */
  trustedForDelegation(name: string[], realm: string): boolean {
    log.debug("Entering Krb5Delegation.trustedForDelegation().");
    this.ensureSeeded();
    const row = applications.get(Krb5Delegation.identifierOf(name, realm));
    const out = (Krb5Delegation.valuesOf(row, 'krb5TrustedForDelegation')[0] ||
                 '').toUpperCase() === 'TRUE';
    log.debug("Leaving Krb5Delegation.trustedForDelegation(). " + out);
    return out;
  }

  /**
   * Which of the two constrained mechanisms the entries configure between a
   * front end and a back end: classic (the front end's
   * appAllowedToDelegateTo) and resource-based (the back end's
   * appAllowedToActOnBehalfOf).
   *
   * @param front - the front end's name components
   * @param back - the back end's name components
   * @param realm - their realm
   * @returns `{ classic, rbcd, delegatesTo, accepts }`
   */
  relationship(front: string[], back: string[], realm: string): Json {
    log.debug("Entering Krb5Delegation.relationship().");
    this.ensureSeeded();
    const frontId = Krb5Delegation.identifierOf(front, realm);
    const backId = Krb5Delegation.identifierOf(back, realm);
    const frontFacts = delegationPolicy.partyFacts(frontId) || {};
    const backFacts = delegationPolicy.partyFacts(backId) || {};
    const delegatesTo: string[] = frontFacts.delegatesTo || [];
    const accepts: string[] = backFacts.accepts || [];
    const out = {
      classic: delegatesTo.indexOf(backId) >= 0,
      rbcd: accepts.indexOf(frontId) >= 0,
      delegatesTo: Krb5Delegation.valuesOf(applications.get(frontId),
                                           'appAllowedToDelegateTo'),
      accepts: Krb5Delegation.valuesOf(applications.get(backId),
                                       'appAllowedToActOnBehalfOf')
    };
    log.debug("Leaving Krb5Delegation.relationship(). classic=" +
              out.classic + " rbcd=" + out.rbcd);
    return out;
  }

  /**
   * Asks the issuance policy about an S4U request: S4U2Self as an
   * impersonation by the service of itself, S4U2Proxy as a delegation by
   * the front end to the back end.
   *
   * @param question - `{ mechanism: 'self' | 'proxy', requester, subject,
   *   subjectRealm, target, realm }`, names as components
   * @returns `delegation_policy.decide()`'s decision
   */
  decide(question: Json): Json {
    log.debug("Entering Krb5Delegation.decide(). " + question.mechanism);
    this.ensureSeeded();
    const requesterId = Krb5Delegation.identifierOf(question.requester,
                                                    question.realm);
    const targetId = Krb5Delegation.identifierOf(question.target,
                                                 question.realm);
    const decision = delegationPolicy.decide({
      protocol: 'Kerberos',
      requested: question.mechanism === 'self' ? 'impersonation'
                                               : 'delegation',
      actor: requesterId,
      subject: this.partyName(question.subject,
                              question.subjectRealm || question.realm),
      source: question.mechanism === 'self' ? [] : [requesterId],
      targets: [targetId],
      targetKind: 'audience'
    });
    log.debug("Leaving Krb5Delegation.decide(). " + decision.allowed);
    return decision;
  }

  // -------------------------------------------------------------------------
  // THE EVIDENCE TICKET'S PAC, CHECKED (#186: "a Bronze Bit check").
  //
  // An evidence ticket is encrypted in the FRONT END's own key, so the front
  // end can read it and write it: CVE-2020-17049 set the forwardable flag on
  // a non-forwardable S4U2Self ticket and presented it, and the same key
  // forges a whole evidence ticket for anybody. The KDC's answer is its own
  // signatures in the PAC: the TICKET signature, which covers the encrypted
  // part with the PAC's ad-data replaced by one zero byte — the flags
  // included — and the KDC signature, both in the krbtgt key, which the front
  // end does not hold. Until #186 this KDC re-signed a carried PAC without
  // checking it. An evidence ticket with no PAC, or one whose signatures do
  // not verify, is refused.
  // -------------------------------------------------------------------------
  /**
   * Verifies an evidence ticket's PAC: its ticket signature (binding the
   * flags) and its KDC signature, with the krbtgt key.
   *
   * @param evidencePart - the decrypted EncTicketPart
   * @param kdcKey - `{ etype, key }`, the krbtgt key
   * @returns `{ ok, why }`
   */
  async verifyEvidence(evidencePart: Json, kdcKey: Json): Promise<Json> {
    log.debug("Entering Krb5Delegation.verifyEvidence().");
    const ad = evidencePart.authorizationData || [];
    const pacs = kpac.findPacs(ad);
    if (!pacs.length) {
      log.debug("Leaving Krb5Delegation.verifyEvidence(). No PAC.");
      return { ok: false, why: 'the evidence ticket carries no PAC, so ' +
               'nothing signed by this KDC says who it is about or that its ' +
               'flags are the ones it was issued with' };
    }
    // The ticket as the signature covered it: the ad-data element holding
    // the PAC replaced by the one-byte placeholder the KDC signed over.
    const placeholder = kpac.wrapPacAsAuthorizationData(new Uint8Array([0]));
    const replaced = ad.map(function (entry: Json) {
      return kpac.findPacs([entry]).length ? placeholder[0] : entry;
    });
    let results: Json[] = [];
    try {
      const ticketBytes = msgs.encEncTicketPart(Object.assign({},
        evidencePart, { authorizationData: replaced }));
      results = await kpac.verifySignatures(kpac.parsePac(pacs[0].bytes),
        { kdcKey: kdcKey, ticketBytes: ticketBytes });
    } catch (e) {
      log.debug("Caught in Krb5Delegation.verifyEvidence(): " +
                ((e && e.message) || e));
      log.debug("Leaving Krb5Delegation.verifyEvidence(). Unreadable.");
      return { ok: false, why: 'the evidence ticket\'s PAC could not be ' +
               'read or checked: ' + ((e && e.message) || e) };
    }
    const named = function (type: number): Json {
      log.debug("Entering named().");
      log.debug("Leaving named().");
      return results.filter(function (one: Json) {
        return one.type === type;
      })[0] || null;
    };
    const ticket = named(kpac.TYPE.TICKET_CHECKSUM);
    const kdc = named(kpac.TYPE.KDC_CHECKSUM);
    if (!ticket || ticket.verified !== true) {
      log.debug("Leaving Krb5Delegation.verifyEvidence(). Ticket signature.");
      return { ok: false, why: ticket
        ? 'the evidence ticket\'s PAC ticket signature does not verify with ' +
          'this KDC\'s key, so the ticket was altered after it was issued ' +
          '— its flags among what is covered (CVE-2020-17049)'
        : 'the evidence ticket\'s PAC has no ticket signature, so nothing ' +
          'binds its flags to what this KDC issued' };
    }
    if (!kdc || kdc.verified !== true) {
      log.debug("Leaving Krb5Delegation.verifyEvidence(). KDC signature.");
      return { ok: false, why: 'the evidence ticket\'s PAC KDC signature ' +
               'does not verify with this KDC\'s key, so this KDC did not ' +
               'issue the authorization data it carries' };
    }
    log.debug("Leaving Krb5Delegation.verifyEvidence(). Verified.");
    return { ok: true, why: '' };
  }

  // -------------------------------------------------------------------------
  // PA-S4U-X509-USER ([MS-SFU] 2.2.2): S4U2Self naming the user by name and
  // realm, or by CERTIFICATE. A request may carry it instead of PA-FOR-USER.
  // -------------------------------------------------------------------------
  /**
   * Reads a PA-S4U-X509-USER padata value.
   *
   * @param bytes - the padata value
   * @returns `{ userIdRaw, nonce, cname, crealm, certificate, options,
   *   cksum }`
   */
  static readS4uX509User(bytes: Uint8Array): Json {
    log.debug("Entering Krb5Delegation.readS4uX509User().");
    const outer = asn1.readTaggedSequence(asn1.readTlv(bytes, 0).value);
    if (!outer[0] || !outer[1]) {
      throw new Error('PA-S4U-X509-USER needs user-id [0] and checksum [1]');
    }
    const userId = asn1.readTaggedSequence(outer[0].value);
    if (!userId[0] || !userId[2]) {
      throw new Error('S4UUserID needs nonce [0] and crealm [2]');
    }
    const out = {
      userIdRaw: outer[0].raw,
      nonce: asn1.decInteger(userId[0]),
      cname: userId[1] ? msgs.readPrincipalName(userId[1]) : null,
      crealm: asn1.decGeneralString(userId[2]),
      certificate: userId[3] ? asn1.decOctetString(userId[3]) : null,
      options: userId[4] ? asn1.bitsFromFlags(asn1.decFlags(userId[4])) : [],
      cksum: msgs.readChecksum(outer[1])
    };
    log.debug("Leaving Krb5Delegation.readS4uX509User().");
    return out;
  }

  /**
   * The person a PA-S4U-X509-USER certificate names: the certificate this
   * realm's TLS client or enrollment Issuing CA issued, signed by it and not
   * revoked, carrying clientAuth and one `urn:sts:person:` name — the same
   * gate `GET /tls/sign-in` puts a presented certificate through
   * (`common/tls_client_certificates.js`'s `identityOf()`).
   *
   * @param der - the certificate's DER
   * @returns `{ ok, username, why }`
   */
  static userFromCertificate(der: Uint8Array): Json {
    log.debug("Entering Krb5Delegation.userFromCertificate().");
    let identity: Json = null;
    try {
      // LAZILY, for the reason this module is required lazily: only an
      // S4U2Self that names its user by certificate needs it.
      identity = require('../common/tls_client_certificates')
        .identityOf({ leaf: Buffer.from(der), chain: [], verified: true });
    } catch (e) {
      log.debug("Caught in Krb5Delegation.userFromCertificate(): " +
                ((e && e.message) || e));
      identity = null;
    }
    if (!identity || !identity.accepted || identity.kind === 'application' ||
        !identity.username) {
      log.debug("Leaving Krb5Delegation.userFromCertificate(). Refused.");
      return { ok: false, username: '',
               why: (identity && identity.why) || 'the certificate was not ' +
                    'issued to a person by this realm\'s certificate ' +
                    'authority' };
    }
    if (identity.realm && identity.realm !== realms.currentId()) {
      log.debug("Leaving Krb5Delegation.userFromCertificate(). Other realm.");
      return { ok: false, username: '',
               why: 'the certificate names a person of another trust realm' };
    }
    log.debug("Leaving Krb5Delegation.userFromCertificate(). " +
              identity.username);
    return { ok: true, username: String(identity.username), why: '' };
  }

  /**
   * Verifies PA-S4U-X509-USER's checksum: the TGT session key's required
   * checksum (HMAC-MD5 for RC4) over the S4UUserID's DER, key usage 26.
   *
   * @param parsed - what readS4uX509User() returned
   * @param sessionKey - `{ etype, key }`, the TGT's session key
   * @returns true when it verifies
   */
  static async verifyS4uX509User(parsed: Json,
                                 sessionKey: Json): Promise<boolean> {
    log.debug("Entering Krb5Delegation.verifyS4uX509User().");
    const profile = kcrypto.etypeById(sessionKey.etype);
    const expected = await profile.checksum(sessionKey.key,
      S4U_X509_USER_CKSUM, parsed.userIdRaw);
    const out = prim.equalConstantTime(expected, parsed.cksum.checksum);
    log.debug("Leaving Krb5Delegation.verifyS4uX509User(). " + out);
    return out;
  }

  /**
   * The PA-S4U-X509-USER the reply carries: the request's S4UUserID with
   * its checksum, under the TGT session key — key usage 27 when the request
   * asked for it (and said so in the options it echoes), 26 otherwise.
   *
   * @param parsed - what readS4uX509User() returned
   * @param sessionKey - `{ etype, key }`, the TGT's session key
   * @returns the padata entry `{ type, value }`
   */
  static async replyS4uX509User(parsed: Json,
                                sessionKey: Json): Promise<Json> {
    log.debug("Entering Krb5Delegation.replyS4uX509User().");
    const profile = kcrypto.etypeById(sessionKey.etype);
    const usage = parsed.options.indexOf(OPTION_USE_REPLY_KEY_USAGE) >= 0
      ? S4U_X509_USER_REPLY_CKSUM : S4U_X509_USER_CKSUM;
    const checksum = await profile.checksum(sessionKey.key, usage,
                                            parsed.userIdRaw);
    // The S4UUserID goes back as the request sent it, byte for byte: the
    // client compares it and the checksum covers exactly those bytes.
    const encoded = asn1.encTaggedSequence([
      { tag: 0, value: parsed.userIdRaw },
      { tag: 1, value: msgs.encChecksum({ type: profile.checksumType,
                                          checksum: checksum }) }]);
    log.debug("Leaving Krb5Delegation.replyS4uX509User(). usage " + usage);
    return { type: msgs.PA_TYPE.S4U_X509_USER, value: encoded };
  }
}

const instance = new Krb5Delegation();

/**
 * The Kerberos side of who may act for whom (#186).
 * @namespace
 */
export = {
  Krb5Delegation: Krb5Delegation,
  identifierOf: Krb5Delegation.identifierOf,
  readS4uX509User: Krb5Delegation.readS4uX509User,
  userFromCertificate: Krb5Delegation.userFromCertificate,
  verifyS4uX509User: Krb5Delegation.verifyS4uX509User,
  replyS4uX509User: Krb5Delegation.replyS4uX509User,
  ensureSeeded: (): void => instance.ensureSeeded(),
  isProtected: (name: string[], realm: string): boolean =>
    instance.isProtected(name, realm),
  trustedForDelegation: (name: string[], realm: string): boolean =>
    instance.trustedForDelegation(name, realm),
  relationship: (front: string[], back: string[], realm: string): Json =>
    instance.relationship(front, back, realm),
  decide: (question: Json): Json => instance.decide(question),
  verifyEvidence: (evidencePart: Json, kdcKey: Json): Promise<Json> =>
    instance.verifyEvidence(evidencePart, kdcKey)
};
