// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: enrollment_profiles.js
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE PROFILES AN ENROLLMENT PROTOCOL NAMES, AS DATA AND NOTHING
// ELSE (2026-09-26, #251).
//
// The nine profiles ACME, EST and SCEP issue and the five they never do were
// constants in `common/cert_enrollment.ts`, which is where they are DECIDED
// and still are (rule 3ag: `checkProfile()`, `namesFor()`, every `why`). They
// moved here because a second reader needs the NAMES and cannot require that
// module: `common/realms.js`, since an EST label and a trust realm now share a
// path position — `/.well-known/est/<label>/…` names a profile, and
// `/.well-known/est/<realm>/…` a realm (#251) — and the realm registry has to
// refuse a realm called by a label's name and must never read a label as a
// realm. realms.js is loaded before almost everything and requires only
// `config` and the error-code table; `cert_enrollment.ts` requires realms.js
// and twenty modules besides. So the list is a LEAF that both require.
//
// **IT REQUIRES NOTHING, AND IT MUST NOT.** realms.js is in the parent
// project's in-process Kerberos COPY closure (`kerberos/CLAUDE.md`), so this
// file is too — one COPY line owed, and a require here would owe more. It is
// data only, so it has no function to log the entry of: no logger, which is
// what lets it require nothing.
//
// **AND IT IS JAVASCRIPT, NOT TYPESCRIPT, BECAUSE OF THAT CLOSURE (2026-10-13,
// #300).** It was written as `enrollment_profiles.ts`, which exists as `.js`
// only after `tsc` runs inside an image build — so no COPY from a checkout
// could supply it, and the parent's tests image had to take the compiled file
// out of a built service image (`COPY --from=mocksts`), the one place it
// reached into one. A module realms.js requires AT LOAD must be loadable from
// the checkout, which is the same reason `krb5_kdc.js`, `krb5_service.js` and
// `spnego.js` are kept JavaScript. A lazy require in realms.js would not have
// done: `matchPath()` asks `isEstLabel()` on every request's realm middleware,
// so the closure reaches it anyway. `// @ts-check` keeps it typed.
// ---------------------------------------------------------------------------

/**
 * A profile an enrollment protocol never issues, and why.
 *
 * @typedef {Object} RefusedProfile
 * @property {string} id - the profile's id, as `/admin/pki` names it
 * @property {string} why - the reason, drawn on every protocol page and
 *   returned by every refusal
 */

// ---------------------------------------------------------------------------
// **NINE ARE ISSUED AND FIVE ARE NOT, AND THE FIVE ARE A DECISION rcbj MADE
// RATHER THAN A GAP.** /admin/pki offers fourteen because an OPERATOR sitting
// at that page is the authority; an enrollment protocol hands a certificate
// to whoever holds a credential, and for five profiles holding the
// certificate is holding a power over everybody else in the realm. The `why`
// of each is drawn on every protocol page and returned by every refusal.
// ---------------------------------------------------------------------------
/**
 * The nine certificate profiles an enrollment protocol may issue.
 *
 * @type {string[]}
 */
const PROFILE_IDS = [
  'tls-server', 'tls-client', 'tls-server-client', 'digital-signature',
  'key-encipherment', 'code-signing', 'email', 'timestamping',
  'smartcard-logon'];

/**
 * The five profiles an enrollment protocol never issues, each with the
 * reason drawn on every protocol page and returned by every refusal.
 *
 * @type {RefusedProfile[]}
 */
const REFUSED_PROFILES = [
  { id: 'root-ca',
    why: 'A Root CA is a trust anchor. Its holder could issue a ' +
         'certificate for anybody and be believed by everything that ' +
         'trusts this service\'s Root — and it is self-signed, so it ' +
         'would not even chain to this authority.' },
  { id: 'intermediate-ca',
    why: 'An Intermediate CA may sign further CAs. Its holder could build ' +
         'a branch of this hierarchy nobody operates.' },
  { id: 'issuing-ca',
    why: 'An Issuing CA signs certificates. Its holder could issue a ' +
         'certificate naming any person or application in the realm, ' +
         'which is exactly the rule this whole module exists to enforce.' },
  { id: 'ocsp-responder',
    why: 'An OCSP Responder certificate issued by this realm\'s CA is a ' +
         'DELEGATED responder (RFC 6960 section 4.2.2.2): its holder could ' +
         'sign "good" about a certificate this service revoked, and a ' +
         'relying party would believe it.' },
  { id: 'kdc',
    why: 'A Kerberos KDC certificate lets its holder answer PKINIT as the ' +
         'realm\'s KDC and impersonate it to every client that trusts ' +
         'this authority.' }
];

// Every name `est/est.ts` reads as a LABEL — an issued profile, or a refused
// one it answers 403 for rather than 404. A trust realm may not be called
// any of these (`realms.validateId()`, STS-CORE-0107), and a realm that was
// is never reached through the label position: the label reading wins.
/**
 * Every name EST reads as a label: the issued profiles and the refused
 * ones. A trust realm may not be called any of these.
 *
 * @type {string[]}
 */
const EST_LABELS = PROFILE_IDS.concat(REFUSED_PROFILES.map(function (one) {
  return one.id;
}));

module.exports = {
  PROFILE_IDS: PROFILE_IDS,
  REFUSED_PROFILES: REFUSED_PROFILES,
  EST_LABELS: EST_LABELS
};
