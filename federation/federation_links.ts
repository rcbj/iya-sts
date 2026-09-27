'use strict';
//
// File: federation_links.ts
//
// ===========================================================================
// THE LINK BETWEEN A PARTNER'S SUBJECT AND A LOCAL PERSON (#109, 2026-09-22).
//
// A service-provider-side relationship used to sign in whichever local entry
// had the NAME the partner asserted — `alice` from a partner landed on the
// local `alice`, and so did `admin`. OpenID Connect Core 1.0 section 5.7 says
// why that is wrong in one sentence: "The sub (subject) and iss (issuer)
// Claims, used together, are the only Claims that an RP can rely upon as a
// stable identifier for the End-User", and `email` and `preferred_username`
// MUST NOT be used as unique identifiers. SAML 2.0 Core section 8.3.7 says the
// same of a persistent NameID: it is scoped to one identity provider (its
// `NameQualifier`, the IdP's entity ID when omitted) and is meant to be LINKED
// to a local account, not matched against one. WS-Federation and plain OAuth
// 2.0 identify a person the same way, by an issuer and a subject.
//
// So a person carries a LINK: one `federationLink` value per partner subject,
//
//     <relationship id> <issuer> <subject>
//
// the issuer being the partner this relationship names (`fedPeer`, which
// every protocol branch has already verified the response came from) and the
// subject taking the REST of the value, because a NameID may contain a space
// and an entity ID or an `iss` may not. The relationship id is in it so that a
// link made through one relationship is a statement about THAT relationship:
// deleting it, or pointing its `fedPeer` at somebody else, and the links stop
// matching rather than following the id.
//
// This file owns the FORMAT and the one CONSEQUENCE of removing a link. What
// a relationship's policy decides is `federation_sp.ts`'s `subjectDecision()`;
// where a link is stored, and the refusal of one person's link on another,
// are `ldap/ldap_server.js`'s, reached through `federation.js`'s directory
// slot.
//
// ---------------------------------------------------------------------------
// A STATIC UTILITY CLASS (#50): it holds no state, so there is nothing for the
// composition root to build. It requires only libraries — helpers, the
// register, the error codes, the audit log and the realms — none of which
// requires it back, and it reaches `authn/authn.ts` LAZILY, at the moment a
// link is removed, because the directory calls it and the directory is
// loaded long after the sign-in service it would otherwise drag forward.
// ===========================================================================

import helpers = require('../common/helpers');
import federation = require('./federation');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import realms = require('../common/realms');

// SAML 2.0 Core section 8.3.8: "transient" — an identifier "used only for the
// duration of" one exchange. There is nothing stable to link.
const SAML2_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

// The longest value written: a URL issuer and a long NameID fit comfortably,
// and a value this service would refuse to MATCH is refused before it is
// stored.
const LINK_MAX = 2048;

// What a namespaced entry's name is built with: `<relationship>~<name>`. A
// character no ordinary username carries, legal in an RDN and in a URL path,
// so a person reading `/admin/users` sees at once which partner made the
// entry and that it is nobody local.
const NAMESPACE_SEPARATOR = '~';

type Json = any;

export = class FederationLinks {
  static readonly SAML2_TRANSIENT = SAML2_TRANSIENT;
  static readonly LINK_MAX = LINK_MAX;
  static readonly NAMESPACE_SEPARATOR = NAMESPACE_SEPARATOR;
  static readonly ATTRIBUTE = 'federationLink';

  // -------------------------------------------------------------------------
  // WHY A LINK CANNOT BE WRITTEN, or ''. Whitespace in the id or the issuer
  // would move the boundary the parse reads, and a line break anywhere would
  // be two values in an LDIF export.
  // -------------------------------------------------------------------------
  static linkProblem(fedId: unknown, issuer: unknown,
                     subject: unknown): string {
    const { log } = helpers;
    log.debug("Entering FederationLinks.linkProblem().");
    const id = String(fedId == null ? '' : fedId);
    const iss = String(issuer == null ? '' : issuer);
    const sub = String(subject == null ? '' : subject);
    let problem = '';
    if (!id || /\s/.test(id)) {
      problem = 'the relationship id is empty or contains white space';
    } else if (!iss || /\s/.test(iss)) {
      problem = 'the issuer is empty or contains white space — it is the ' +
                'partner\'s entity ID or `iss`, which never does';
    } else if (!sub.trim()) {
      problem = 'the subject is empty';
    } else if (/[\r\n]/.test(sub)) {
      problem = 'the subject contains a line break';
    } else if ((id + ' ' + iss + ' ' + sub).length > LINK_MAX) {
      problem = 'the link would be longer than ' + LINK_MAX + ' characters';
    }
    log.debug("Leaving FederationLinks.linkProblem(). " +
              (problem || 'Usable.'));
    return problem;
  }

  // The value, or '' where linkProblem() has something to say.
  static linkValue(fedId: unknown, issuer: unknown, subject: unknown): string {
    const { log } = helpers;
    log.debug("Entering FederationLinks.linkValue().");
    if (FederationLinks.linkProblem(fedId, issuer, subject)) {
      log.debug("Leaving FederationLinks.linkValue(). Not writable.");
      return '';
    }
    log.debug("Leaving FederationLinks.linkValue().");
    return String(fedId) + ' ' + String(issuer) + ' ' + String(subject);
  }

  // One value, read back. null for a value that is not three parts — which
  // only an `ldapmodify` can have written, and which matches nothing.
  static parse(value: unknown): Json {
    const { log } = helpers;
    log.debug("Entering FederationLinks.parse().");
    const text = String(value == null ? '' : value);
    const first = text.indexOf(' ');
    const second = first < 0 ? -1 : text.indexOf(' ', first + 1);
    if (first <= 0 || second <= first + 1 || second === text.length - 1) {
      log.debug("Leaving FederationLinks.parse(). Not a link.");
      return null;
    }
    log.debug("Leaving FederationLinks.parse().");
    return { relationship: text.slice(0, first),
             issuer: text.slice(first + 1, second),
             subject: text.slice(second + 1),
             value: text };
  }

  // -------------------------------------------------------------------------
  // THE STABLE SUBJECT A VERIFIED SIGN-IN CARRIES, as `{ ok, issuer,
  // subject, value, why }`.
  //
  // `result.issuer` is what the protocol branch VERIFIED — the SAML Issuer
  // compared with `fedPeer`, the ID Token's `iss` checked against it — and
  // `fedPeer` otherwise, which is the same string by the time a response gets
  // here. A SAML 2.0 persistent NameID with a `NameQualifier` is qualified by
  // it (section 8.3.7), which is the identity provider's entity ID unless an
  // affiliation says otherwise; a transient one is refused, because nothing
  // about it outlives the exchange.
  // -------------------------------------------------------------------------
  static stableSubjectOf(record: Json, result: Json): Json {
    const { log } = helpers;
    log.debug("Entering FederationLinks.stableSubjectOf().");
    const r = result || {};
    const subject = String(r.subject == null ? '' : r.subject).trim();
    const format = String(r.nameFormat || '');
    const issuer = String(r.nameQualifier || r.issuer ||
                          (record && record.fedPeer) || '').trim();
    if (format === SAML2_TRANSIENT) {
      log.debug("Leaving FederationLinks.stableSubjectOf(). Transient.");
      return { ok: false, issuer: issuer, subject: subject, value: '',
               why: 'the partner identified the person by a TRANSIENT ' +
                    'NameID (SAML 2.0 Core section 8.3.8), which names them ' +
                    'for this one exchange only, so there is nothing to ' +
                    'link. Configure the partner to send a persistent ' +
                    'NameID for this service provider' };
    }
    const problem = FederationLinks.linkProblem(record && record.fedId,
                                                issuer, subject);
    if (problem) {
      log.debug("Leaving FederationLinks.stableSubjectOf(). " + problem);
      return { ok: false, issuer: issuer, subject: subject, value: '',
               why: 'the partner\'s identifier for the person cannot be a ' +
                    'link: ' + problem };
    }
    log.debug("Leaving FederationLinks.stableSubjectOf().");
    return { ok: true, issuer: issuer, subject: subject,
             value: FederationLinks.linkValue(record.fedId, issuer, subject),
             why: '' };
  }

  // `<relationship>~<name>`, the name of an entry `jit-namespaced` creates.
  static namespacedName(fedId: unknown, username: unknown): string {
    const { log } = helpers;
    log.debug("Entering FederationLinks.namespacedName().");
    log.debug("Leaving FederationLinks.namespacedName().");
    return String(fedId || '') + NAMESPACE_SEPARATOR + String(username || '');
  }

  // -------------------------------------------------------------------------
  // A LINK AN ADMINISTRATOR ASKED FOR — the console, `/admin-api` and SCIM
  // all come through here, so the three cannot come to accept different
  // things. `issuer` may be omitted and is then the relationship's `fedPeer`;
  // one that is given must BE it, because a link naming an issuer the
  // relationship does not verify could never match. Answers `{ ok, value }`
  // or `{ ok: false, code, why }`.
  // -------------------------------------------------------------------------
  static resolveRequest(asked: Json): Json {
    const { log } = helpers;
    log.debug("Entering FederationLinks.resolveRequest().");
    const a = asked || {};
    const id = String(a.relationship || '').trim();
    const record = id ? federation.get(id) : null;
    if (!record || record.fedRole !== 'service-provider') {
      log.debug("Leaving FederationLinks.resolveRequest(). No relationship.");
      return errorCodes.mark({ ok: false, code: 'STS-FED-0105',
        why: id
          ? 'There is no service-provider-side relationship called "' + id +
            '" in this realm; a link is to a partner this service consumes ' +
            'from.'
          : 'Name the relationship the link is through.' }, 'STS-FED-0105');
    }
    const peer = String(record.fedPeer || '').trim();
    const issuer = String(a.issuer == null || a.issuer === '' ? peer
                                                                : a.issuer)
      .trim();
    if (peer && issuer !== peer) {
      log.debug("Leaving FederationLinks.resolveRequest(). Wrong issuer.");
      return errorCodes.mark({ ok: false, code: 'STS-FED-0106',
        why: 'The relationship "' + id + '" verifies responses from "' +
             peer + '", so a link through it names that issuer; "' + issuer +
             '" could never match.' }, 'STS-FED-0106');
    }
    const subject = String(a.subject == null ? '' : a.subject).trim();
    const problem = FederationLinks.linkProblem(id, issuer, subject);
    if (problem) {
      log.debug("Leaving FederationLinks.resolveRequest(). " + problem);
      return errorCodes.mark({ ok: false, code: 'STS-FED-0106',
        why: 'That link cannot be written: ' + problem + '.' },
        'STS-FED-0106');
    }
    log.debug("Leaving FederationLinks.resolveRequest().");
    return { ok: true, record: record,
             value: FederationLinks.linkValue(id, issuer, subject),
             relationship: id, issuer: issuer, subject: subject };
  }

  // -------------------------------------------------------------------------
  // A LINK WAS REMOVED — by the console, `/admin-api`, SCIM or an
  // `ldapmodify`; the directory hands every removal here, so the consequence
  // does not depend on the door (`common/account_state.ts`'s arrangement for
  // a lock). Two things follow, and the first needs nothing: the next sign-in
  // through that relationship no longer finds the link. The second is this
  // function: every live sign-on session that partner signed the person in
  // to is ENDED — each through `authn.endSessionById()`, so each is an audit
  // row, a CAEP session-revoked and the back-channel Logout Tokens of its
  // relying parties — AFTER the write has been answered, in the entry's realm.
  // A session the person made some other way is not touched: the partner lost
  // the right to assert them, and nothing else changed.
  // -------------------------------------------------------------------------
  static linksRemoved(change: Json): void {
    const { log } = helpers;
    log.debug("Entering FederationLinks.linksRemoved().");
    const c = change || {};
    const username = String(c.username || '');
    const removed = (Array.isArray(c.removed) ? c.removed : [])
      .map(FederationLinks.parse).filter(Boolean);
    if (!username || !removed.length) {
      log.debug("Leaving FederationLinks.linksRemoved(). Nothing to end.");
      return;
    }
    const realm = realms.get(String(c.realm || '')) || realms.current();
    setImmediate(function (): void {
      realms.run(realm, function (): void {
        FederationLinks.endPartnerSessions(username, removed, {
          kind: String(c.kind || 'a directory write') });
      });
    });
    log.debug("Leaving FederationLinks.linksRemoved(). Scheduled.");
  }

  // The synchronous half of the above: ends the sessions and answers how
  // many. `links` are parsed values.
  static endPartnerSessions(username: string, links: Json[],
                            opts?: Json): number {
    const { log } = helpers;
    log.debug("Entering FederationLinks.endPartnerSessions(). " + username);
    let ended = 0;
    try {
      // Lazily, and never at load: see the header.
      const authn = require('../authn/authn');
      const sessions = (authn.sessionsOf(username) || []) as Json[];
      sessions.forEach(function (session: Json): void {
        const events = Array.isArray(session.events) ? session.events : [];
        const through = links.some(function (link: Json): boolean {
          return events.some(function (event: Json): boolean {
            const authority = (event && event.authority) || {};
            return authority.kind === 'federation' &&
                   String(authority.id || '') === link.relationship &&
                   (!authority.subject ||
                    String(authority.subject) === link.subject);
          });
        });
        // An administrator's act — the console, the API or an LDAP write is
        // what removes a link (#242).
        if (through && authn.endSessionById(session.id,
                                            'federation link removed',
                                            'admin')) {
          ended += 1;
        }
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-FED-0110') + 'federation: ' + username +
                '\'s link was removed and the sessions the partner signed ' +
                'them in to could not be ended; the unlink stands: ' +
                ((e && e.message) || e));
      log.debug("Leaving FederationLinks.endPartnerSessions(). Threw.");
      return ended;
    }
    audit.audit({
      action: 'federation.unlink', actor: '', channel: 'internal',
      protocol: 'Federation', target: username,
      summary: username + '\'s federation link' +
               (links.length === 1 ? '' : 's') + ' through ' +
               links.map(function (link: Json): string {
                 return link.relationship;
               }).join(', ') + ' ' + (links.length === 1 ? 'was' : 'were') +
               ' removed (' + String((opts && opts.kind) || 'a write') +
               '); ' + ended + ' session(s) that partner signed them in to ' +
               'were ended',
      detail: { username: username, ended: String(ended),
                relationships: links.map(function (link: Json): string {
                  return link.relationship;
                }).join(', ') }
    });
    log.info('federation: ' + username + ' was unlinked from ' +
             links.map(function (link: Json): string {
               return link.relationship;
             }).join(', ') + '; ' + ended + ' session(s) ended.');
    log.debug("Leaving FederationLinks.endPartnerSessions(). " + ended);
    return ended;
  }
};
