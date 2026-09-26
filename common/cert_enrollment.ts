'use strict';
//
// File: cert_enrollment.ts
//
// ---------------------------------------------------------------------------
// WHO MAY BE ISSUED A CERTIFICATE FOR WHOM, AND WHAT GOES IN IT (2026-09-13).
//
// ACME (RFC 8555), EST (RFC 7030) and SCEP (RFC 8894) are three wire formats
// for one act: a client proves who it is, presents a public key, and is handed
// a certificate from this realm's certificate authority. Everything about that
// act that is NOT a wire format lives here, once, and the three protocol
// modules (`acme/`, `est/`, `scep/`) are forbidden from deciding any of it for
// themselves:
//
//   * the IDENTITY RULE — a person may be issued a certificate for their own
//     directory entry and nobody else's, an application for its own entry,
//     and a holder of Admin Write for any person or application in the realm
//     (`authorizeTarget()`);
//   * the PROFILES — the nine leaf profiles of /admin/pki, and the five that
//     are never issued over an enrollment protocol and why (`PROFILES`,
//     `REFUSED_PROFILES`);
//   * the PROOF OF POSSESSION — a PKCS#10 request's signature verified with
//     its own public key, classical and post-quantum (`parseCsr()`);
//   * the CONTENT — subject and subjectAltName are built from the DIRECTORY
//     ENTRY, and a name the request asks for that the entry does not own
//     refuses the request rather than being quietly dropped (`namesFor()`);
//   * WHERE IT IS KEPT — every certificate is written onto the entry it names,
//     and a private key only when this service generated it (`issue()`);
//   * the two protocol CREDENTIALS that are bound to an entry rather than
//     being a password — an ACME External Account Binding key and a SCEP
//     challenge password (`createEab()`, `createScepChallenge()`).
//
// rcbj's four decisions (2026-09-13) are the spine of this file, and each is
// argued where it is applied: keys are kept only when generated here; each
// protocol authenticates in its own native way; the CA, OCSP and KDC profiles
// are refused; and a host name is issued only when it is REGISTERED on the
// entry, so nothing here ever dials an address somebody supplied.
//
// **A LIBRARY, AND IT MUST STAY ONE (rule 3).** It registers no route and it
// reaches the directory through `setDirectory()`, which `ldap/ldap_server.js`
// fills — a require in that direction would drag every `/ldap` route to the
// front of the router. Beyond `common/`'s leaves (helpers, config, audit,
// error_codes, keystore, mode, realms and the two vendored PKI modules) it
// requires `common/pki.js`, `common/credentials.ts`,
// `common/applications.js`, `admin-ui/admin_rbac.ts`, `oauth-oidc/mtls.js`
// and `cluster/cluster_claims.js` / `cluster_capabilities.js`, all
// libraries.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16).
//
//   * **`CertEnrollment` TAKES ITS DEPENDENCIES THROUGH ITS CONSTRUCTOR**
//     (`CertEnrollmentDeps`), the modules above among them, so the
//     composition root can build one and a test can build one with stubs.
//     `pki_revocation.js` and `websecurity.ts` were required lazily, inside
//     the function that needed them, and still are: the deps carry a loader
//     for each rather than the module.
//   * **THE DIRECTORY SLOT IS A FIELD OF THE INSTANCE**, filled by
//     `setDirectory()` exactly as the module variable was.
//   * **THE MODULE STILL EXPORTS EVERY NAME IT DID**: the functions, and
//     the tables from the class's static members. Since #50's R2 the
//     composition root builds the instance (`CertEnrollment.defaultDeps()`) and
//     installs it; the module's old export names are FACADES that forward to
//     it, for the JavaScript callers, and a process without the root builds a
//     default when this module finishes loading. `CertEnrollment` is exported
//     beside them for that root.
//   * **THE CAPABILITY ROW IS STILL DECLARED AT REQUIRE TIME**, by `wire()`'s
//     call to `provideCapability()`, which runs when the root installs the
//     instance as it loads the stack (or, without the root, when this module
//     finishes loading).
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import net = require('net');
import asn1js = require('asn1js');
import pkijs = require('pkijs');

import helpers = require('./helpers');
const { log } = helpers;
import applications = require('./applications');
import audit = require('./audit');
import config = require('./config');
import credentials = require('./credentials');
import enrollmentProfiles = require('./enrollment_profiles');
import errorCodes = require('./error_codes');
import keyMaterial = require('./vendored/key_material');
import keystore = require('./keystore');
import mode = require('./mode');
import pki = require('./pki');
import realms = require('./realms');
import x509 = require('./vendored/x509');
import adminRbac = require('../admin-ui/admin_rbac');
import mtls = require('../oauth-oidc/mtls');
// SEVERAL NODES AGAINST ONE STORE (2026-09-14, #46 section 2): the atomic
// "once" the two entry-bound credentials below are spent through, and the
// capability table this file declares its row in. Both LIBRARIES that reach
// `persistence.js` lazily, so neither can close a cycle from here.
import claims = require('../cluster/cluster_claims');
// CAEP credential-change for a person's certificate issued or revoked (#145).
// A library that sends nothing where Shared Signals is not loaded; it
// requires `helpers` and `crypto` and nothing of this file's.
import accountSignals = require('../ssf/account_signals');
import capabilities = require('../cluster/cluster_capabilities');
import InstanceSlot = require('./instance_slot');

const FAMILIES = ['acme', 'est', 'scep'];

const FAMILY_LABELS = { acme: 'ACME', est: 'EST', scep: 'SCEP' };

// ---------------------------------------------------------------------------
// THE PROFILES.
//
// **NINE ARE ISSUED AND FIVE ARE NOT, AND THE FIVE ARE A DECISION rcbj MADE
// RATHER THAN A GAP** — the argument is beside the lists, which live in the
// leaf `./enrollment_profiles` since 2026-09-26 (#251): `common/realms.js`
// needs the names to keep an EST label and a trust realm apart, and cannot
// require this module. They are DECIDED here, as before.
// ---------------------------------------------------------------------------
const PROFILE_IDS = enrollmentProfiles.PROFILE_IDS;

const REFUSED_PROFILES = enrollmentProfiles.REFUSED_PROFILES;

// What each issued profile REQUIRES of the request or the entry, beyond the
// identity rule. Drawn on the pages from this table.
const PROFILE_NEEDS = {
  'tls-server': 'at least one dNSName or iPAddress registered on the entry',
  'tls-server-client': 'at least one dNSName or iPAddress registered on ' +
                       'the entry',
  'email': 'a person entry with a mail attribute (the rfc822Name)',
  'smartcard-logon': 'a person entry with userPrincipalName or mail ' +
                     '(the UPN otherName)'
};

// Attribute names, canonical spelling. The directory lower-cases a name when it
// stores it; `ldap/ldap_server.js`'s slot translates back.
const ATTRIBUTES = {
  person: {
    certificate: 'stsEnrolledCertificate',
    privateKey: 'stsEnrolledPrivateKey',
    eab: 'stsAcmeEabKey',
    challenge: 'stsScepChallenge',
    hostName: 'stsCertificateHostName'
  },
  application: {
    certificate: 'appEnrolledCertificate',
    privateKey: 'appEnrolledPrivateKey',
    eab: 'appAcmeEabKey',
    challenge: 'appScepChallenge',
    hostName: 'appCertificateHostName'
  }
};

// The attributes a reader of the socket must never see, for
// `ldap/ldap_server.js`'s SECRET_ATTRIBUTES. The certificates and host names
// are public; the private keys and the two credentials are not — an EAB MAC
// key or a SCEP challenge is a working credential, and the challenge record
// holds only a digest but is still an offline guessing target.
const SECRET_ATTRIBUTES = ['stsEnrolledPrivateKey', 'appEnrolledPrivateKey',
                           'stsAcmeEabKey', 'appAcmeEabKey',
                           'stsScepChallenge', 'appScepChallenge'];

// What `read()` is asked for, per kind.
const READ_NAMES = {
  person: ['mail', 'userPrincipalName', 'x509subject'].concat(
    Object.keys(ATTRIBUTES.person).map(function (k) {
      return ATTRIBUTES.person[k];
    })),
  application: ['appIdentifier', 'oauthClientId'].concat(
    Object.keys(ATTRIBUTES.application).map(function (k) {
      return ATTRIBUTES.application[k];
    }))
};

const URN_PREFIX = { person: 'urn:sts:person:',
                     application: 'urn:sts:application:' };

// A single-use credential per entry is plenty; a list somebody can grow without
// bound is a list somebody will.
const MAX_CREDENTIALS_PER_ENTRY = 10;

// The OID of Microsoft's UPN otherName, which is what the smartcard-logon
// profile's subjectAltName carries.
const UPN_OID = '1.3.6.1.4.1.311.20.2.3';


// How long an EAB key's claim is held — see `bindEabOnce()`.
const EAB_CLAIM_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// What `CertEnrollment` needs from the rest of the service: the modules this
// file used to reach for itself, passed in so that the composition root can
// build one and a test can build one with stubs.
interface CertEnrollmentDeps {
  nodeCrypto: typeof nodeCrypto;
  net: typeof net;
  asn1js: typeof asn1js;
  pkijs: typeof pkijs;
  log: typeof log;
  helpers: typeof helpers;
  applications: typeof applications;
  audit: typeof audit;
  config: typeof config;
  credentials: typeof credentials;
  errorCodes: typeof errorCodes;
  keyMaterial: typeof keyMaterial;
  keystore: typeof keystore;
  mode: typeof mode;
  pki: typeof pki;
  realms: typeof realms;
  x509: typeof x509;
  adminRbac: typeof adminRbac;
  mtls: typeof mtls;
  claims: typeof claims;
  capabilities: typeof capabilities;
  // Required when first called, as the JavaScript did: `pki_revocation.js`
  // by `revokeEnrolled()`, and `websecurity.ts` by the throttles
  // (`websecurityModule()`).
  loadRevocation(): typeof import('./pki_revocation');
  loadWebsecurity(): typeof import('./websecurity');
}

class CertEnrollment {
  static readonly FAMILIES = FAMILIES;
  static readonly FAMILY_LABELS = FAMILY_LABELS;
  static readonly PROFILE_IDS = PROFILE_IDS;
  static readonly REFUSED_PROFILES = REFUSED_PROFILES;
  static readonly PROFILE_NEEDS = PROFILE_NEEDS;
  static readonly ATTRIBUTES = ATTRIBUTES;
  static readonly SECRET_ATTRIBUTES = SECRET_ATTRIBUTES;
  static readonly URN_PREFIX = URN_PREFIX;
  static readonly MAX_CREDENTIALS_PER_ENTRY = MAX_CREDENTIALS_PER_ENTRY;

  // THE DIRECTORY SLOT — see `setDirectory()`.
  private directory = null;

  constructor(private readonly deps: CertEnrollmentDeps) {
    deps.log.debug("Entering CertEnrollment.constructor().");
    deps.log.debug("Leaving CertEnrollment.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): CertEnrollmentDeps {
    log.debug("Entering CertEnrollment.defaultDeps().");
    log.debug("Leaving CertEnrollment.defaultDeps().");
    return {
      nodeCrypto: nodeCrypto,
      net: net,
      asn1js: asn1js,
      pkijs: pkijs,
      log: log,
      helpers: helpers,
      applications: applications,
      audit: audit,
      config: config,
      credentials: credentials,
      errorCodes: errorCodes,
      keyMaterial: keyMaterial,
      keystore: keystore,
      mode: mode,
      pki: pki,
      realms: realms,
      x509: x509,
      adminRbac: adminRbac,
      mtls: mtls,
      claims: claims,
      capabilities: capabilities,
      loadRevocation: function () {
        return require('./pki_revocation');
      },
      loadWebsecurity: function () {
        return require('./websecurity');
      }
    };
  }

  // What loading this module did with its instance before R2, run once
  // for whichever instance is installed (#50, R2).
  static wire(instance: CertEnrollment): void {
    log.debug("Entering CertEnrollment.wire().");
    instance.provideCapability();
    log.debug("Leaving CertEnrollment.wire().");
  }

  // ---------------------------------------------------------------------------
  // A REFUSAL. Every one carries the HTTP status a protocol module should send
  // and an STS code; the sentence is for an operator reading a console reply or
  // a problem document's `detail`, and never contains a secret.
  // ---------------------------------------------------------------------------
  refuse(code, status, sentence) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering CertEnrollment.refuse(). code=" + code);
    log.debug("Leaving CertEnrollment.refuse().");
    return errorCodes.mark({ ok: false, status: status, errors: [sentence],
                             why: sentence }, code);
  }

  // ---------------------------------------------------------------------------
  // THE DIRECTORY SLOT (filled by ldap/ldap_server.js at require time).
  //
  //   read(kind, id, names)          -> { dn, attributes: { Name: [values] } }
  //                                     | null. The ambient realm's entry.
  //   write(kind, id, name, values)  -> true | false. `values` replaces the
  //                                     attribute; an empty array removes it.
  //   holders(kind, name)            -> [id] of entries carrying `name`.
  //
  // Validated whole, for `setLogoutReader()`'s reason: half a store is a
  // register that can issue a credential it cannot find again.
  // ---------------------------------------------------------------------------
  setDirectory(store) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.setDirectory().");
    const given = store || {};
    const missing = ['read', 'write', 'holders'].filter(function (name) {
      return typeof given[name] !== 'function';
    });
    if (missing.length) {
      log.debug("Leaving CertEnrollment.setDirectory(). Incomplete.");
      throw new Error('cert_enrollment.setDirectory() needs read, write and ' +
                      'holders; missing ' + missing.join(', ') + '.');
    }
    self.directory = given;
    log.debug("Leaving CertEnrollment.setDirectory().");
  }

  hasDirectory() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.hasDirectory().");
    log.debug("Leaving CertEnrollment.hasDirectory().");
    return !!self.directory;
  }

  // ---------------------------------------------------------------------------
  // SHAPES.
  // ---------------------------------------------------------------------------
  isFamily(family) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.isFamily().");
    log.debug("Leaving CertEnrollment.isFamily().");
    return FAMILIES.indexOf(String(family)) >= 0;
  }

  isKind(kind) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.isKind().");
    log.debug("Leaving CertEnrollment.isKind().");
    return kind === 'person' || kind === 'application';
  }

  // An identifier as a directory holds one: printable, bounded, no control
  // characters. The same bar `common/validation.js` sets on a name, applied
  // here as well because this module is also reached from credential kids that
  // were decoded from base64url and never passed a schema.
  wellFormedId(id) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.wellFormedId().");
    const text = String(id == null ? '' : id);
    log.debug("Leaving CertEnrollment.wellFormedId().");
    return text.length >= 1 && text.length <= 256 &&
           !/[\u0000-\u001f\u007f]/.test(text);
  }

  entryUri(entry) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.entryUri().");
    log.debug("Leaving CertEnrollment.entryUri().");
    return URN_PREFIX[entry.kind] + entry.id;
  }

  entryFromUri(uri) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.entryFromUri().");
    const text = String(uri || '');
    let found = null;
    Object.keys(URN_PREFIX).forEach(function (kind) {
      if (!found && text.indexOf(URN_PREFIX[kind]) === 0) {
        const id = text.slice(URN_PREFIX[kind].length);
        if (self.wellFormedId(id)) {
          found = { kind: kind, id: id };
        }
      }
    });
    log.debug("Leaving CertEnrollment.entryFromUri().");
    return found;
  }

  entryLabel(entry) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.entryLabel().");
    log.debug("Leaving CertEnrollment.entryLabel().");
    return (entry.kind === 'person' ? 'person' : 'application') + ' "' +
           entry.id + '"';
  }

  sameEntry(a, b) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.sameEntry().");
    log.debug("Leaving CertEnrollment.sameEntry().");
    return !!(a && b && a.kind === b.kind && String(a.id) === String(b.id));
  }

  // ---------------------------------------------------------------------------
  // THE ENTRY.
  // ---------------------------------------------------------------------------
  resolveEntry(kind, id) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.resolveEntry(). kind=" + kind + " id=" +
              id);
    if (!self.isKind(kind) || !self.wellFormedId(id)) {
      log.debug("Leaving CertEnrollment.resolveEntry(). Malformed.");
      return self.refuse('STS-ENROLL-0010', 400, 'A certificate is issued ' +
                         'for a person or an application, named by a ' +
                         'printable identifier of at most 256 characters.');
    }
    if (!self.directory) {
      log.debug("Leaving CertEnrollment.resolveEntry(). No directory.");
      return self.refuse('STS-ENROLL-0011', 503, 'No directory is loaded in ' +
                         'this process, so there is no entry a certificate ' +
                         'could be issued for or kept on.');
    }
    let found = null;
    try {
      found = self.directory.read(kind, String(id), READ_NAMES[kind]);
    } catch (e) {
      log.debug("Caught in CertEnrollment.resolveEntry(): " +
                ((e && e.message) || e));
      found = null;
    }
    if (!found) {
      log.debug("Leaving CertEnrollment.resolveEntry(). No such entry.");
      return self.refuse('STS-ENROLL-0012', 404, 'There is no ' +
                         self.entryLabel({ kind: kind, id: id }) + ' in this ' +
                         'realm. A certificate issued over an enrollment ' +
                         'protocol always names an entry that exists, and is ' +
                         'kept on it.');
    }
    const attrs = found.attributes || {};
    const first = function (name) {
      return (attrs[name] && attrs[name].length) ? String(attrs[name][0]) : '';
    };
    const names = ATTRIBUTES[kind];
    log.debug("Leaving CertEnrollment.resolveEntry(). " + found.dn);
    return {
      ok: true,
      entry: { kind: kind, id: String(id) },
      dn: found.dn,
      mail: kind === 'person' ? first('mail') : '',
      upn: kind === 'person' ? first('userPrincipalName') : '',
      hostNames: (attrs[names.hostName] || []).map(function (one) {
        return self.normalHostName(one);
      }).filter(function (one) { return !!one; }),
      attributes: attrs
    };
  }

  normalHostName(value) {
    const { net, log } = this.deps;
    log.debug("Entering CertEnrollment.normalHostName().");
    let text = String(value == null ? '' : value).trim().toLowerCase();
    if (net.isIP(text)) {
      log.debug("Leaving CertEnrollment.normalHostName(). An address.");
      return text;
    }
    if (text.endsWith('.')) {
      text = text.slice(0, -1);
    }
    // RFC 1123 labels, with one leading wildcard label allowed as a literal the
    // operator registered — a wildcard is only ever issued if it is written on
    // the entry exactly so.
    const ok = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
      .test(text) && text.length <= 253;
    log.debug("Leaving CertEnrollment.normalHostName().");
    return ok ? text : '';
  }

  // ---------------------------------------------------------------------------
  // AUTHENTICATION. Each answers { ok, principal } where a principal is
  //   { kind, id, admin, via, realm }
  // and `admin` is true only for a person holding Admin Write — in the DEFAULT
  // realm's roster, or in the ambient realm's own (see `adminFor()`).
  // ---------------------------------------------------------------------------

  // **ADMIN IS DECIDED IN THE REALM WHOSE ROSTER GRANTS IT, WITH THE CREDENTIAL
  // CHECKED THERE.** Two rosters can make somebody an administrator here: the
  // DEFAULT realm's, which administers every realm, and since 2026-09-14 (#32)
  // the ambient realm's own, which administers that realm only — and an
  // enrollment in a realm can only name targets in that realm. What NAMES alone
  // would get wrong is a realm with a person of the same name as an
  // administrator elsewhere, so each roster is consulted only after the
  // password verified against the entry in THAT roster's realm. An empty roster
  // (`open`) grants nothing here, as it grants nothing on the LDAP socket:
  // "everybody is an administrator because nobody is" is a bootstrap for the
  // console and not a reason to issue certificates in anybody's name.
  async adminFor(username, password, via?) {
    const { log, credentials, realms, adminRbac } = this.deps;
    log.debug("Entering CertEnrollment.adminFor(). username=" + username);
    const name = String(username || '');
    if (!name) {
      log.debug("Leaving CertEnrollment.adminFor(). No name.");
      return false;
    }
    let verified: any = false;
    try {
      verified = await realms.run(realms.get(realms.DEFAULT_ID), function () {
        return credentials.verifyAsync(name, String(password || ''),
                                       { via: via, door: 'est' });
      });
    } catch (e) {
      log.debug("Caught in CertEnrollment.adminFor(): " +
                ((e && e.message) || e));
      verified = false;
    }
    let roles = null;
    if (verified && verified.ok) {
      try {
        roles = adminRbac.rolesOf(name, realms.DEFAULT_ID);
      } catch (e) {
        log.debug("Caught in CertEnrollment.adminFor(): " +
                  ((e && e.message) || e));
        roles = null;
      }
    }
    if (roles && roles.write === true && roles.open !== true) {
      log.debug("Leaving CertEnrollment.adminFor(). A service administrator.");
      return true;
    }
    // A REALM'S OWN ADMINISTRATOR (2026-09-14, #32): the same two questions
    // asked of the AMBIENT realm — the password against that realm's entry,
    // then that realm's roster. Its authority is that realm's, and so is every
    // target an enrollment here can name.
    const here = realms.currentId();
    if (here === realms.DEFAULT_ID) {
      log.debug("Leaving CertEnrollment.adminFor(). Not an administrator.");
      return false;
    }
    let local = null;
    try {
      local = await credentials.verifyAsync(name, String(password || ''),
                                            { via: via, door: 'est' });
    } catch (e) {
      log.debug("Caught in CertEnrollment.adminFor(): " +
                ((e && e.message) || e));
      local = null;
    }
    let realmRoles = null;
    if (local && local.ok) {
      try {
        realmRoles = adminRbac.rolesOf(name, here);
      } catch (e) {
        log.debug("Caught in CertEnrollment.adminFor(): " +
                  ((e && e.message) || e));
        realmRoles = null;
      }
    }
    const admin = !!(realmRoles && realmRoles.write === true &&
                     realmRoles.open !== true);
    log.debug("Leaving CertEnrollment.adminFor(). realm admin=" + admin);
    return admin;
  }

  // The same roster question for a principal a console or portal session has
  // ALREADY authenticated — the console gate verified the sign-in, so asking
  // for the password again would be asking for something the caller does not
  // have.
  //
  // **THE ROSTER IS THE AMBIENT REALM'S** (2026-09-14, #32): a portal session
  // is the person of the realm it was signed in through, so it is that realm's
  // roster that says whether they administer it — the default realm's in the
  // default realm, a realm's own anywhere else. Asking the default realm's by
  // name from inside a realm was the collision `adminFor()` describes.
  sessionIsAdmin(username) {
    const { log, realms, adminRbac } = this.deps;
    log.debug("Entering CertEnrollment.sessionIsAdmin().");
    let roles = null;
    try {
      roles = adminRbac.rolesOf(String(username || ''), realms.currentId());
    } catch (e) {
      log.debug("Caught in CertEnrollment.sessionIsAdmin(): " +
                ((e && e.message) || e));
      roles = null;
    }
    log.debug("Leaving CertEnrollment.sessionIsAdmin().");
    // NOR THE BOOTSTRAP ACCOUNT BEFORE ITS CLAIM, IN PRODUCT (#103): a portal
    // session may have been made by a federation partner or a certificate
    // naming it, and until it has claimed the console with its password its
    // roles open the console alone. `adminFor()` above verifies the password
    // itself, so it IS a password sign-in and asks no such question.
    return !!(roles && roles.write === true && roles.open !== true &&
              roles.claimPending !== true);
  }

  async authenticatePerson(username, password, via?) {
    const { log, credentials, realms } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.authenticatePerson(). username=" +
              username);
    const name = String(username || '');
    if (!self.wellFormedId(name)) {
      log.debug("Leaving CertEnrollment.authenticatePerson(). Malformed.");
      return self.refuse('STS-ENROLL-0013', 401, 'A username is required.');
    }
    const local = self.resolveEntry('person', name);
    let verified = null;
    if (local.ok) {
      try {
        verified = await credentials.verifyAsync(name, String(password || ''),
                                                 { via: via, door: 'est' });
      } catch (e) {
        log.debug("Caught in CertEnrollment.authenticatePerson(): " +
                  ((e && e.message) || e));
        verified = null;
      }
    }
    // `door: 'est'` on all three verifications (#101): EST Basic is a
    // password-only door, so in product a person with a second factor is
    // refused their own password here — an administrator included, whose way
    // to enroll on somebody's behalf is then a realm-issued client
    // certificate — and an app password scoped to `est` is accepted instead.
    // An app password is ONE factor and the principal says it was one.
    const admin = await self.adminFor(name, password, via);
    if (local.ok && verified && verified.ok) {
      log.debug("Leaving CertEnrollment.authenticatePerson(). Verified here.");
      return { ok: true, principal: { kind: 'person', id: name, admin: admin,
                                      via: via, realm: realms.currentId(),
                                      hasEntry: true,
                                      appPassword: verified.appPassword
                                        ? verified.appPassword.name
                                        : undefined } };
    }
    if (admin) {
      // An administrator of the SERVICE with no entry of this name in this
      // realm, or whose entry here has a different password. They may issue for
      // an entry the request names and for nobody as themselves.
      log.debug("Leaving CertEnrollment.authenticatePerson(). An " +
                "administrator only.");
      return { ok: true, principal: { kind: 'person', id: name, admin: true,
                                      via: via, realm: realms.currentId(),
                                      hasEntry: false } };
    }
    log.debug("Leaving CertEnrollment.authenticatePerson(). Refused.");
    return self.refuse(local.ok ? 'STS-ENROLL-0014' : 'STS-ENROLL-0015', 401,
                       local.ok
                         ? 'The password was not accepted.'
                         : 'The password was not accepted.');
  }

  secretsEqual(presented, expected) {
    const { nodeCrypto, log } = this.deps;
    log.debug("Entering CertEnrollment.secretsEqual().");
    const a = nodeCrypto.createHash('sha256').update(String(presented || ''))
      .digest();
    const b = nodeCrypto.createHash('sha256').update(String(expected || ''))
      .digest();
    log.debug("Leaving CertEnrollment.secretsEqual().");
    return nodeCrypto.timingSafeEqual(a, b) && !!expected;
  }

  async authenticateApplication(clientId, secret, via?) {
    const { log, applications, mode, realms } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.authenticateApplication(). clientId=" +
              clientId);
    const id = String(clientId || '');
    if (!self.wellFormedId(id)) {
      log.debug("Leaving CertEnrollment.authenticateApplication(). Malformed.");
      return self.refuse('STS-ENROLL-0013', 401, 'A client_id is required.');
    }
    let view = null;
    try {
      view = applications.forClientId(id) || applications.get(id);
    } catch (e) {
      log.debug("Caught in CertEnrollment.authenticateApplication(): " +
                ((e && e.message) || e));
      view = null;
    }
    if (!view || !view.identifier) {
      log.debug("Leaving CertEnrollment.authenticateApplication(). Unknown.");
      return self.refuse('STS-ENROLL-0016', 401, 'The client credentials ' +
                         'were not accepted.');
    }
    const cfg: any = applications.clientConfigOf(view.identifier) || {};
    const expected = String(cfg.client_secret || '');
    if (mode.requiresConfidentialClientAuthentication()) {
      if (!expected || !self.secretsEqual(secret, expected)) {
        log.debug("Leaving CertEnrollment.authenticateApplication(). Secret " +
                  "refused.");
        return self.refuse('STS-ENROLL-0016', 401, 'The client credentials ' +
                           'were not accepted.');
      }
    }
    const entry = self.resolveEntry('application', view.identifier);
    if (!entry.ok) {
      log.debug("Leaving CertEnrollment.authenticateApplication(). No entry.");
      return entry;
    }
    log.debug("Leaving CertEnrollment.authenticateApplication(). Accepted.");
    return { ok: true, principal: { kind: 'application',
                                    id: String(view.identifier), admin: false,
                                    via: via, realm: realms.currentId(),
                                    hasEntry: true } };
  }

  // ---------------------------------------------------------------------------
  // A TLS CLIENT CERTIFICATE AS THE CREDENTIAL (EST re-enrollment).
  //
  // Three checks, and all three are real in both modes:
  //   1. the certificate verifies to THIS REALM's Intermediate and the
  //      service Root, with revocation consulted (`pki.verifyLeaf()`), so a
  //      certificate from another realm — perfectly valid there — is refused
  //      here;
  //   2. it certifies `clientAuth`;
  //   3. its urn:sts: subjectAltName names an entry that exists AND carries
  //      this certificate's serial among its enrolled certificates,
  //      unrevoked. That last clause is what "every certificate maps to an
  //      entry" buys: a certificate the entry does not list is not that
  //      entry's credential.
  // ---------------------------------------------------------------------------
  async authenticateCertificate(req, via?) {
    const { log, mtls } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.authenticateCertificate().");
    const presented = mtls.peerCertificate(req);
    if (!presented || !presented.raw) {
      log.debug("Leaving CertEnrollment.authenticateCertificate(). None " +
                "presented.");
      return self.refuse('STS-ENROLL-0017', 401, 'No TLS client certificate ' +
                         'was presented.');
    }
    const pem = '-----BEGIN CERTIFICATE-----\n' +
      Buffer.from(presented.raw).toString('base64').replace(/(.{64})/g, '$1\n')
        .replace(/\n$/, '') +
      '\n-----END CERTIFICATE-----\n';
    const answer = await self.authenticatePresentedCertificate(
      pem, via, { clientAuth: true });
    log.debug("Leaving CertEnrollment.authenticateCertificate(). ok=" +
              !!answer.ok);
    return answer;
  }

  // ---------------------------------------------------------------------------
  // THE SAME THREE CHECKS, ON A CERTIFICATE THAT DID NOT ARRIVE ON A TLS
  // CONNECTION (2026-09-13).
  //
  // SCEP's RenewalReq, GetCert and GetCRL are SIGNED by an existing certificate
  // carried inside the CMS SignedData (RFC 8894 section 3.3.1.2): the socket
  // knows nothing about it. It is held to exactly what a TLS client certificate
  // is held to — this realm's path, revocation, an entry that lists it — with
  // one difference, and the caller says when: `clientAuth` is required only
  // where the certificate is being used AS a TLS client credential. A SCEP
  // renewal of an S/MIME certificate is signed by that certificate, which
  // certifies `emailProtection` and has never been a TLS credential.
  // ---------------------------------------------------------------------------
  async authenticatePresentedCertificate(pem, via?, options?) {
    const { nodeCrypto, log, pki, realms, x509 } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.authenticatePresentedCertificate().");
    const opts = options || {};
    const verified = await pki.verifyLeaf(realms.currentId(), pem, []);
    if (!verified.ok) {
      log.debug("Leaving CertEnrollment.authenticatePresentedCertificate(). " +
                "Path refused.");
      return self.refuse('STS-ENROLL-0018', 401, 'The client certificate ' +
                         'does not verify to this realm\'s certificate ' +
                         'authority: ' + verified.why);
    }
    let cert = null;
    try {
      cert = new nodeCrypto.X509Certificate(pem);
    } catch (e) {
      log.debug("Caught in " +
                "CertEnrollment.authenticatePresentedCertificate(): " +
                ((e && e.message) || e));
      cert = null;
    }
    const ekus = (cert && cert.keyUsage) || [];
    if (opts.clientAuth !== false &&
        ekus.indexOf(x509.EKU_OIDS.clientAuth) < 0) {
      log.debug("Leaving CertEnrollment.authenticatePresentedCertificate(). " +
                "No clientAuth.");
      return self.refuse('STS-ENROLL-0019', 401, 'The client certificate ' +
                         'does not certify TLS client authentication ' +
                         '(clientAuth).');
    }
    const uris = String((cert && cert.subjectAltName) || '').split(/,\s*/)
      .filter(function (one) { return one.indexOf('URI:') === 0; })
      .map(function (one) { return one.slice(4); });
    const named = uris.map(function (uri) {
      return self.entryFromUri(uri);
    }).filter(function (one) {
      return !!one;
    });
    if (named.length !== 1) {
      log.debug("Leaving CertEnrollment.authenticatePresentedCertificate(). " +
                "No entry.");
      return self.refuse('STS-ENROLL-0019', 401, 'The client certificate ' +
                         'names no single person or application of this ' +
                         'realm.');
    }
    const serialHex = self.normalSerial(cert.serialNumber);
    const held = self.enrolledOf(named[0]).filter(function (one) {
      return self.normalSerial(one.serialHex) === serialHex;
    })[0];
    if (!held || held.revoked) {
      log.debug("Leaving CertEnrollment.authenticatePresentedCertificate(). " +
                "Not held.");
      return self.refuse('STS-ENROLL-0019', 401, 'The client certificate is ' +
                         'not one the ' + self.entryLabel(named[0]) + ' ' +
                         'holds.');
    }
    log.debug("Leaving CertEnrollment.authenticatePresentedCertificate(). " +
              self.entryLabel(named[0]));
    return { ok: true,
             principal: { kind: named[0].kind, id: named[0].id, admin: false,
                          via: via, realm: realms.currentId(), hasEntry: true,
                          certificateSerial: serialHex,
                          certificateFamily: held.family } };
  }

  // ---------------------------------------------------------------------------
  // THE IDENTITY RULE. The one sentence of rcbj's this file most exists to
  // keep: "Any of the users can only issue key pairs that map to their
  // authenticated user identity", and "an admin user can request one that maps
  // to any user object in the current realm".
  // ---------------------------------------------------------------------------
  authorizeTarget(principal, target) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.authorizeTarget().");
    if (!principal || !self.isKind(principal.kind) || !target ||
        !self.isKind(target.kind)) {
      log.debug("Leaving CertEnrollment.authorizeTarget(). Malformed.");
      return self.refuse('STS-ENROLL-0020', 403, 'Nobody authenticated, or ' +
                         'nobody was named.');
    }
    if (self.sameEntry(principal, target) && principal.hasEntry !== false) {
      log.debug("Leaving CertEnrollment.authorizeTarget(). Self.");
      return { ok: true, self: true };
    }
    if (principal.kind === 'person' && principal.admin === true) {
      log.debug("Leaving CertEnrollment.authorizeTarget(). An administrator.");
      return { ok: true, self: false, admin: true };
    }
    log.debug("Leaving CertEnrollment.authorizeTarget(). Refused.");
    return self.refuse('STS-ENROLL-0021', 403, 'A certificate may be issued ' +
                       'only for the entry that authenticated — the ' +
                       self.entryLabel(principal) + ' — and this request is ' +
                       'for the ' + self.entryLabel(target) + '. Only a ' +
                       'holder of Admin Write may request a certificate for ' +
                       'somebody else.');
  }

  // ---------------------------------------------------------------------------
  // PROFILES AGAINST SETTINGS.
  // ---------------------------------------------------------------------------
  allowedProfiles(family) {
    const { log, config } = this.deps;
    log.debug("Entering CertEnrollment.allowedProfiles(). family=" + family);
    const raw = config.value(family + '.allowedProfiles');
    const listed = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one) { return String(one).trim(); })
      .filter(function (one) { return PROFILE_IDS.indexOf(one) >= 0; });
    log.debug("Leaving CertEnrollment.allowedProfiles().");
    return PROFILE_IDS.filter(function (one) {
      return listed.indexOf(one) >= 0;
    });
  }

  checkProfile(family, profileId) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.checkProfile(). profile=" + profileId);
    const id = String(profileId || '');
    const refused = REFUSED_PROFILES.filter(function (one) {
      return one.id === id;
    })[0];
    if (refused) {
      log.debug("Leaving CertEnrollment.checkProfile(). Refused by design.");
      return self.refuse('STS-ENROLL-0002', 403, 'The "' + id + '" profile ' +
                         'is never issued over an enrollment protocol. ' +
                         refused.why);
    }
    if (PROFILE_IDS.indexOf(id) < 0) {
      log.debug("Leaving CertEnrollment.checkProfile(). Unknown.");
      return self.refuse('STS-ENROLL-0001', 400, '"' + id + '" is not a ' +
                         'certificate profile. The ' + PROFILE_IDS.length +
                         ' issued over ' + FAMILY_LABELS[family] + ' are: ' +
                         PROFILE_IDS.join(', ') + '.');
    }
    if (self.allowedProfiles(family).indexOf(id) < 0) {
      log.debug("Leaving CertEnrollment.checkProfile(). Not allowed here.");
      return self.refuse('STS-ENROLL-0003', 403, 'The "' + id + '" profile ' +
                         'is not in ' + family + '.allowedProfiles in this ' +
                         'realm.');
    }
    log.debug("Leaving CertEnrollment.checkProfile(). Allowed.");
    return { ok: true, profile: id };
  }

  defaultProfile(family) {
    const { log, config } = this.deps;
    log.debug("Entering CertEnrollment.defaultProfile().");
    log.debug("Leaving CertEnrollment.defaultProfile().");
    return String(config.value(family + '.defaultProfile') || 'tls-client');
  }

  // ---------------------------------------------------------------------------
  // THE PROFILE OF A REQUEST THAT NAMES NONE, FROM WHAT IT ASKS FOR (#252,
  // rcbj's decision on #207, 2026-09-26).
  //
  // `family.defaultProfile` is `tls-client`, and until this was written a bare
  // `certbot certonly -d www.example.test` was issued a clientAuth-only
  // certificate — a certificate for a web server that no TLS client will accept
  // from one. A request whose identifiers are ALL host names (`dns`, and `ip`,
  // which RFC 8738 makes the same kind of name) is asking for a server
  // certificate whatever it forgot to say, so it gets `tls-server`.
  //
  // THE RULE, WRITTEN DOWN:
  //   * every identifier `dns` or `ip` (and at least one) → `tls-server`, when
  //     `family.allowedProfiles` holds it;
  //   * anything else — a person or application by `permanent-identifier`, an
  //     `email`, or a MIX of host names and those — → `family.defaultProfile`,
  //     as before: a mixed order names an entry as well as a host, and which of
  //     the two it is for is exactly what it did not say;
  //   * a realm whose `allowedProfiles` leaves `tls-server` out has decided it
  //     issues no server certificate, so a host-only order there keeps the
  //     realm default too — the default does not reach past the allowed list;
  //   * a NAMED profile is never replaced: the caller checks it with
  //     `checkProfile()` and uses it, and this is not asked.
  //
  // Only ACME knows the identifiers before it chooses (an EST or SCEP profile
  // is chosen by the path or the realm before a CSR is read), so ACME is the
  // one caller; the rule is here because the profiles are.
  // ---------------------------------------------------------------------------
  profileForIdentifiers(family, types) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.profileForIdentifiers().");
    const list = Array.isArray(types) ? types.map(String) : [];
    const hostsOnly = list.length > 0 && list.every(function (one) {
      return one === 'dns' || one === 'ip';
    });
    if (hostsOnly && this.allowedProfiles(family).indexOf('tls-server') >= 0) {
      log.debug("Leaving CertEnrollment.profileForIdentifiers(). tls-server.");
      return 'tls-server';
    }
    log.debug("Leaving CertEnrollment.profileForIdentifiers(). The realm " +
              "default.");
    return this.defaultProfile(family);
  }

  // ---------------------------------------------------------------------------
  // PKCS#10.
  //
  // **THE PROOF OF POSSESSION IS VERIFIED, WHICH IS MORE THAN THIS SERVICE HAS
  // DONE WITH A CSR BEFORE.** SPIFFE's `signCsr()` reads only the SPKI, and
  // says so, because SPIRE's own server does the same. An enrollment protocol
  // is different: the CSR is the ONLY thing binding the key to the request, and
  // an unverified one lets somebody enroll a public key they do not hold — then
  // present somebody else's certificate as their own. So the signature is
  // checked with the request's own key, for every algorithm the vendored
  // encoder can make: RSA and ECDSA through pkijs, Ed25519 through Web Crypto
  // (pkijs cannot read an Ed25519 SPKI), and the post-quantum and composite
  // families through `x509.verifyBytes()`.
  //
  // A KEY-ENCAPSULATION key cannot sign, so it cannot make that proof at all —
  // RFC 9935 section 7 says the same — and is refused unless the caller says
  // the CSR is only a TEMPLATE (EST /serverkeygen, where the key is this
  // service's).
  // ---------------------------------------------------------------------------
  derToPem(der, label?) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.derToPem().");
    log.debug("Leaving CertEnrollment.derToPem().");
    return '-----BEGIN ' + label + '-----\n' +
      Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n')
        .replace(/\n$/, '') +
      '\n-----END ' + label + '-----\n';
  }

  asArrayBuffer(bytes) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.asArrayBuffer().");
    const buf = Buffer.from(bytes);
    log.debug("Leaving CertEnrollment.asArrayBuffer().");
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }

  stringOfAsn1(value) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.stringOfAsn1().");
    if (!value || !value.valueBlock) {
      log.debug("Leaving CertEnrollment.stringOfAsn1().");
      return '';
    }
    log.debug("Leaving CertEnrollment.stringOfAsn1().");
    return String(value.valueBlock.value !== undefined
      ? value.valueBlock.value : '');
  }

  async parseCsr(bytes, options?) {
    const { asn1js, pkijs, log, keyMaterial } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.parseCsr().");
    const opts = options || {};
    const der = Buffer.from(bytes || []);
    if (!der.length) {
      log.debug("Leaving CertEnrollment.parseCsr(). Empty.");
      return self.refuse('STS-ENROLL-0030', 400, 'The certificate request is ' +
                         'empty.');
    }
    let csr = null;
    try {
      const asn1 = asn1js.fromBER(self.asArrayBuffer(der));
      if (asn1.offset === -1 || asn1.offset !== der.length) {
        throw new Error('not one complete DER value');
      }
      csr = new pkijs.CertificationRequest({ schema: asn1.result });
    } catch (e) {
      log.debug("Caught in CertEnrollment.parseCsr(): " +
                ((e && e.message) || e));
      log.debug("Leaving CertEnrollment.parseCsr(). Unreadable.");
      return self.refuse('STS-ENROLL-0030', 400, 'The certificate request is ' +
                         'not a readable PKCS#10 CertificationRequest.');
    }
    let spkiPem = '';
    let desc = null;
    try {
      spkiPem = self.derToPem(
        csr.subjectPublicKeyInfo.toSchema().toBER(false), 'PUBLIC KEY');
      desc = await keyMaterial.describePublicPem(spkiPem);
    } catch (e) {
      log.debug("Caught in CertEnrollment.parseCsr(): " +
                ((e && e.message) || e));
      desc = null;
    }
    if (!desc) {
      log.debug("Leaving CertEnrollment.parseCsr(). Unsupported key.");
      return self.refuse('STS-ENROLL-0031', 400, 'The public key in the ' +
                         'request is not one this certificate authority can ' +
                         'certify.');
    }
    const kem = desc.kind === 'pqc' && desc.use && desc.use !== 'sig';
    if (kem && !opts.template) {
      log.debug("Leaving CertEnrollment.parseCsr(). A KEM key.");
      return self.refuse('STS-ENROLL-0032', 400, 'The request carries a ' +
                         String(desc.pqc || 'key-encapsulation') + ' key, ' +
                         'which cannot sign and so cannot prove possession ' +
                         '(RFC 9935 section 7). Ask EST /serverkeygen for ' +
                         'one instead.');
    }
    if (!kem) {
      const proven = await self.proofOfPossession(csr, spkiPem, desc);
      if (!proven) {
        log.debug("Leaving CertEnrollment.parseCsr(). The signature does not " +
                  "verify.");
        return self.refuse('STS-ENROLL-0033', 400, 'The certificate ' +
                           'request\'s signature does not verify with the ' +
                           'public key it carries, so it does not prove ' +
                           'possession of that key.');
      }
    }
    const out = {
      ok: true,
      der: der,
      publicKeyPem: spkiPem,
      keyAlg: self.keyAlgName(desc),
      keyKind: desc.kind,
      subject: '',
      commonName: '',
      challengePassword: '',
      // The TYPE of every attribute the request carries, and nothing of their
      // values (2026-09-13, for EST). RFC 7030 section 4.4.1.2 lets a
      // /serverkeygen template ask for the private key to be encrypted by
      // naming a DecryptKeyIdentifier or AsymmetricDecryptKeyIdentifier
      // attribute, and a server that does not do that MUST refuse the request
      // rather than hand the key back in the clear. Only the types are needed
      // to decide, and exposing them here keeps EST from reading the CSR
      // itself.
      attributeTypes: [],
      requested: { uris: [], dns: [], ips: [], emails: [], upns: [] }
    };
    try {
      out.subject = csr.subject.typesAndValues.map(function (tv) {
        return tv.type + '=' + self.stringOfAsn1(tv.value);
      }).join(',');
      csr.subject.typesAndValues.forEach(function (tv) {
        if (tv.type === '2.5.4.3' && !out.commonName) {
          out.commonName = self.stringOfAsn1(tv.value);
        }
      });
      (csr.attributes || []).forEach(function (attribute) {
        out.attributeTypes.push(String(attribute.type));
        if (attribute.type === '1.2.840.113549.1.9.7') {
          out.challengePassword =
            self.stringOfAsn1((attribute.values || [])[0]);
        }
        if (attribute.type === '1.2.840.113549.1.9.14') {
          const extensions = new pkijs.Extensions({
            schema: (attribute.values || [])[0] });
          (extensions.extensions || []).forEach(function (extension) {
            if (extension.extnID !== '2.5.29.17') {
              return;
            }
            const alt = extension.parsedValue ||
              new pkijs.AltName({ schema: asn1js.fromBER(
                extension.extnValue.valueBlock.valueHexView.slice().buffer)
                .result });
            (alt.altNames || []).forEach(function (name) {
              self.readGeneralName(name, out.requested);
            });
          });
        }
      });
    } catch (e) {
      log.debug("Caught in CertEnrollment.parseCsr(): " +
                ((e && e.message) || e));
      log.debug("Leaving CertEnrollment.parseCsr(). Unreadable attributes.");
      return self.refuse('STS-ENROLL-0034', 400, 'The certificate request\'s ' +
                         'subject or requested extensions could not be read.');
    }
    log.debug("Leaving CertEnrollment.parseCsr(). key=" + out.keyAlg);
    return out;
  }

  // A key described by `describePublicPem()` in the vocabulary /admin/pki and
  // `keyMaterial.KEY_ALGS` use — `rsa-2048`, `ec-p256`, `ed25519`, `ml-dsa-44`.
  keyAlgName(desc) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.keyAlgName().");
    if (desc.id) {
      log.debug("Leaving CertEnrollment.keyAlgName(). Named.");
      return String(desc.id);
    }
    if (desc.kind === 'rsa') {
      log.debug("Leaving CertEnrollment.keyAlgName(). RSA.");
      return 'rsa-' + (desc.bits || 2048);
    }
    if (desc.kind === 'ec') {
      log.debug("Leaving CertEnrollment.keyAlgName(). EC.");
      return 'ec-' +
        String(desc.curve || 'P-256').replace('-', '').toLowerCase();
    }
    log.debug("Leaving CertEnrollment.keyAlgName().");
    return desc.kind === 'okp' ? String(desc.name || 'Ed25519').toLowerCase()
                               : String(desc.kind);
  }

  readGeneralName(name, requested) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.readGeneralName(). type=" +
              (name && name.type));
    if (!name) {
      log.debug("Leaving CertEnrollment.readGeneralName().");
      return;
    }
    if (name.type === 1) {
      requested.emails.push(String(name.value));
    } else if (name.type === 2) {
      requested.dns.push(String(name.value));
    } else if (name.type === 6) {
      requested.uris.push(String(name.value));
    } else if (name.type === 7) {
      const raw = Buffer.from(name.value.valueBlock.valueHexView);
      requested.ips.push(self.ipText(raw));
    } else if (name.type === 0) {
      const other = name.value || {};
      const id = other.type || (other.valueBlock && other.valueBlock.value &&
        other.valueBlock.value[0] && other.valueBlock.value[0].valueBlock &&
        other.valueBlock.value[0].valueBlock.toString());
      const inner = other.value ||
        (other.valueBlock && other.valueBlock.value &&
         other.valueBlock.value[1]);
      if (String(id) === UPN_OID) {
        const text = inner && inner.valueBlock && inner.valueBlock.value &&
          inner.valueBlock.value[0]
          ? self.stringOfAsn1(inner.valueBlock.value[0])
          : self.stringOfAsn1(inner);
        requested.upns.push(text);
      } else {
        // An otherName this authority does not issue. Recorded as a URI the
        // entry can never own, so it refuses the request by name.
        requested.uris.push('otherName:' + String(id || 'unknown'));
      }
    } else {
      requested.uris.push('generalName:' + String(name.type));
    }
    log.debug("Leaving CertEnrollment.readGeneralName().");
  }

  ipText(raw) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.ipText().");
    if (raw.length === 4) {
      log.debug("Leaving CertEnrollment.ipText(). IPv4.");
      return Array.from(raw).join('.');
    }
    if (raw.length === 16) {
      const groups = [];
      for (let i = 0; i < 16; i += 2) {
        groups.push(raw.readUInt16BE(i).toString(16));
      }
      log.debug("Leaving CertEnrollment.ipText(). IPv6.");
      return self.normalHostName(
        groups.join(':').replace(/(^|:)0(:0)+(:|$)/, '::'));
    }
    log.debug("Leaving CertEnrollment.ipText(). Neither.");
    return 'invalid-address';
  }

  async proofOfPossession(csr, spkiPem, desc) {
    const { nodeCrypto, log, x509 } = this.deps;
    log.debug("Entering CertEnrollment.proofOfPossession(). kind=" + desc.kind);
    try {
      const tbs = csr.tbsView ? Buffer.from(csr.tbsView)
        : Buffer.from(csr.encodeTBS().toBER(false));
      const signature = Buffer.from(csr.signatureValue.valueBlock.valueHexView);
      const sig = x509.sigAlgForOid(csr.signatureAlgorithm.algorithmId);
      if (sig && sig.kind === 'pqc') {
        const ok = await x509.verifyBytes(sig, spkiPem, signature, tbs);
        log.debug("Leaving CertEnrollment.proofOfPossession(). pqc=" + ok);
        return !!ok;
      }
      if (desc.kind === 'okp') {
        const key = nodeCrypto.createPublicKey(spkiPem);
        const ok = nodeCrypto.verify(null, tbs, key, signature);
        log.debug("Leaving CertEnrollment.proofOfPossession(). Ed25519=" + ok);
        return !!ok;
      }
      const ok = await csr.verify();
      log.debug("Leaving CertEnrollment.proofOfPossession(). pkijs=" + ok);
      return !!ok;
    } catch (e) {
      log.debug("Caught in CertEnrollment.proofOfPossession(): " +
                ((e && e.message) || e));
      log.debug("Leaving CertEnrollment.proofOfPossession(). Threw, so not " +
                "proven.");
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // WHICH ENTRY A REQUEST IS FOR.
  //
  // A urn:sts: subjectAltName names it exactly. With none, a principal is
  // asking for itself — except that an ADMINISTRATOR with no URN may name a
  // person or application by the request's common name, which is what an EST
  // client configured with a subject and nothing else sends. More than one URN
  // naming different entries is refused: one certificate maps to one entry.
  // ---------------------------------------------------------------------------
  targetFromRequest(requested, commonName, principal) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.targetFromRequest().");
    const named = [];
    ((requested && requested.uris) || []).forEach(function (uri) {
      const entry = self.entryFromUri(uri);
      if (entry && !named.some(function (one) {
        return self.sameEntry(one, entry);
      })) {
        named.push(entry);
      }
    });
    if (named.length > 1) {
      log.debug("Leaving CertEnrollment.targetFromRequest(). Several.");
      return self.refuse('STS-ENROLL-0022', 400, 'The request names ' +
                         named.length + ' different entries. One certificate ' +
                         'maps to one person or application.');
    }
    if (named.length === 1) {
      log.debug("Leaving CertEnrollment.targetFromRequest(). Named by URN.");
      return { ok: true, target: named[0], by: 'urn' };
    }
    if (principal && principal.admin && commonName &&
        !(principal.kind === 'person' && commonName === principal.id)) {
      const person = self.resolveEntry('person', commonName);
      if (person.ok) {
        log.debug("Leaving CertEnrollment.targetFromRequest(). A person by " +
                  "CN.");
        return { ok: true, target: person.entry, by: 'common-name' };
      }
      const application = self.resolveEntry('application', commonName);
      if (application.ok) {
        log.debug("Leaving CertEnrollment.targetFromRequest(). An " +
                  "application by CN.");
        return { ok: true, target: application.entry, by: 'common-name' };
      }
    }
    if (principal && principal.hasEntry === false) {
      log.debug("Leaving CertEnrollment.targetFromRequest(). An " +
                "administrator named nobody.");
      return self.refuse('STS-ENROLL-0023', 400, 'An administrator with no ' +
                         'entry of their own in this realm must name the ' +
                         'entry the certificate is for, in a urn:sts:person: ' +
                         'or urn:sts:application: subjectAltName or as the ' +
                         'common name.');
    }
    log.debug("Leaving CertEnrollment.targetFromRequest(). Self.");
    return { ok: true,
             target: principal ? { kind: principal.kind, id: principal.id }
                               : null,
             by: 'principal' };
  }

  // ---------------------------------------------------------------------------
  // WHAT GOES IN THE CERTIFICATE.
  //
  // Built from the entry. Every name the request asked for must be OWNED by the
  // entry or the request is refused — silently dropping a name would issue a
  // certificate that does not do what its requester configured, and they would
  // find out at a TLS handshake a week later.
  // ---------------------------------------------------------------------------
  namesFor(resolved, profileId, requested) {
    const { net, log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.namesFor(). profile=" + profileId);
    const entry = resolved.entry;
    const want = requested || {};
    const names = [{ kind: 'uri', value: self.entryUri(entry) }];
    const seen = {};
    const add = function (kind, value) {
      const key = kind + ':' + value;
      if (!seen[key]) {
        seen[key] = true;
        names.push({ kind: kind, value: value });
      }
    };
    seen['uri:' + self.entryUri(entry)] = true;
    const uris = want.uris || [];
    for (let i = 0; i < uris.length; i++) {
      if (uris[i] !== self.entryUri(entry)) {
        log.debug("Leaving CertEnrollment.namesFor(). A foreign URI.");
        return self.refuse('STS-ENROLL-0050', 403, 'The request asks for the ' +
                           'name "' + String(uris[i]).slice(0, 200) + '", ' +
                           'which the ' + self.entryLabel(entry) + ' does ' +
                           'not own. Only its own urn:sts: name may be ' +
                           'requested.');
      }
    }
    let hosts = 0;
    const dns = want.dns || [];
    for (let i = 0; i < dns.length; i++) {
      const host = self.normalHostName(dns[i]);
      if (!host || net.isIP(host) || resolved.hostNames.indexOf(host) < 0) {
        log.debug("Leaving CertEnrollment.namesFor(). An unregistered host " +
                  "name.");
        return self.refuse('STS-ENROLL-0051', 403, 'The host name "' +
                           String(dns[i]).slice(0, 253) + '" is not ' +
                           'registered on the ' + self.entryLabel(entry) +
                           '. A host name is issued only when an ' +
                           'administrator has registered it on the entry; ' +
                           'this service never proves control of a name by ' +
                           'dialling it.');
      }
      add('dns', host);
      hosts++;
    }
    const ips = want.ips || [];
    for (let i = 0; i < ips.length; i++) {
      const address = self.normalHostName(ips[i]);
      if (!net.isIP(address) || resolved.hostNames.indexOf(address) < 0) {
        log.debug("Leaving CertEnrollment.namesFor(). An unregistered " +
                  "address.");
        return self.refuse('STS-ENROLL-0051', 403, 'The address "' +
                           String(ips[i]).slice(0, 64) + '" is not ' +
                           'registered on the ' + self.entryLabel(entry) + '.');
      }
      add('ip', address);
      hosts++;
    }
    const emails = want.emails || [];
    for (let i = 0; i < emails.length; i++) {
      if (!resolved.mail ||
          String(emails[i]).toLowerCase() !== resolved.mail.toLowerCase()) {
        log.debug("Leaving CertEnrollment.namesFor(). An address the entry " +
                  "does not hold.");
        return self.refuse('STS-ENROLL-0052', 403, 'The email address "' +
                           String(emails[i]).slice(0, 254) + '" is not the ' +
                           'mail attribute of the ' + self.entryLabel(entry) +
                           '.');
      }
      add('email', resolved.mail);
    }
    const upns = want.upns || [];
    for (let i = 0; i < upns.length; i++) {
      const owned = [resolved.upn, resolved.mail].filter(function (one) {
        return !!one;
      }).map(function (one) { return one.toLowerCase(); });
      if (owned.indexOf(String(upns[i]).toLowerCase()) < 0) {
        log.debug("Leaving CertEnrollment.namesFor(). A UPN the entry does " +
                  "not hold.");
        return self.refuse('STS-ENROLL-0053', 403, 'The user principal name "' +
                           String(upns[i]).slice(0, 254) + '" is neither the ' +
                           'userPrincipalName nor the mail of the ' +
                           self.entryLabel(entry) + '.');
      }
      add('upn', String(upns[i]));
    }
    if ((profileId === 'tls-server' || profileId === 'tls-server-client') &&
        !hosts) {
      log.debug("Leaving CertEnrollment.namesFor(). A server certificate " +
                "naming no host.");
      return self.refuse('STS-ENROLL-0054', 400,
                         'A ' + profileId + ' certificate names at least ' +
                         'one host, and the request names none. ' +
                         (resolved.hostNames.length
                           ? 'The ' + self.entryLabel(entry) + ' has ' +
                             resolved.hostNames.length + ' registered.'
                           : 'The ' + self.entryLabel(entry) +
                             ' has none registered.'));
    }
    if (profileId === 'email' && !emails.length) {
      if (!resolved.mail) {
        log.debug("Leaving CertEnrollment.namesFor(). S/MIME with no mail.");
        return self.refuse('STS-ENROLL-0055', 400, 'An S/MIME certificate ' +
                           'carries the holder\'s email address, and the ' +
                           self.entryLabel(entry) + ' has no mail attribute.');
      }
      add('email', resolved.mail);
    }
    if (profileId === 'smartcard-logon' && !upns.length) {
      const upn = resolved.upn || resolved.mail;
      if (!upn) {
        log.debug("Leaving CertEnrollment.namesFor(). Smartcard logon with " +
                  "no UPN.");
        return self.refuse('STS-ENROLL-0056', 400, 'A smartcard logon ' +
                           'certificate carries a user principal name, and ' +
                           'the ' + self.entryLabel(entry) + ' has neither ' +
                           'userPrincipalName nor mail.');
      }
      add('upn', upn);
    }
    log.debug("Leaving CertEnrollment.namesFor(). " + names.length + " " +
              "name(s).");
    return { ok: true, names: names };
  }

  organisationOf() {
    const { log, config, pki, realms } = this.deps;
    log.debug("Entering CertEnrollment.organisationOf().");
    let row = null;
    try {
      row = pki.rawRowFor(realms.currentId());
    } catch (e) {
      log.debug("Caught in CertEnrollment.organisationOf(): " +
                ((e && e.message) || e));
      row = null;
    }
    log.debug("Leaving CertEnrollment.organisationOf().");
    return {
      organisation: String((row && row.organisation) ||
                           config.value('pki.organisation') || 'mock-sts'),
      country: String((row && row.country) || '')
    };
  }

  // ---------------------------------------------------------------------------
  // THE RECORDS ON AN ENTRY.
  // ---------------------------------------------------------------------------
  parseJsonValues(values) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.parseJsonValues().");
    const out = [];
    (values || []).forEach(function (value) {
      try {
        const parsed = JSON.parse(String(value));
        if (parsed && typeof parsed === 'object') {
          out.push(parsed);
        }
      } catch (e) {
        log.debug("Caught in CertEnrollment.parseJsonValues(): " +
                  ((e && e.message) || e));
        // A value somebody wrote over LDAP by hand that is not a record. It is
        // left on the entry and not read, rather than failing every reader.
      }
    });
    log.debug("Leaving CertEnrollment.parseJsonValues(). " + out.length + " " +
              "record(s).");
    return out;
  }

  readAttribute(entry, key) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.readAttribute(). key=" + key);
    const resolved = self.resolveEntry(entry.kind, entry.id);
    if (!resolved.ok) {
      log.debug("Leaving CertEnrollment.readAttribute(). No entry.");
      return null;
    }
    log.debug("Leaving CertEnrollment.readAttribute().");
    return (resolved.attributes[ATTRIBUTES[entry.kind][key]] || []).slice();
  }

  writeAttribute(entry, key, values) {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.writeAttribute(). key=" + key);
    if (!self.directory) {
      log.debug("Leaving CertEnrollment.writeAttribute(). No directory.");
      return false;
    }
    let written = false;
    try {
      written = self.directory.write(entry.kind, entry.id,
                                     ATTRIBUTES[entry.kind][key], values);
    } catch (e) {
      log.error(errorCodes.tag('STS-ENROLL-0041') + 'enrollment: could not ' +
                'write ' + ATTRIBUTES[entry.kind][key] + ' on the ' +
                self.entryLabel(entry) + ': ' + ((e && e.message) || e));
      written = false;
    }
    log.debug("Leaving CertEnrollment.writeAttribute(). written=" + written);
    return !!written;
  }

  sealText(plain, label?) {
    const { log, keystore } = this.deps;
    log.debug("Entering CertEnrollment.sealText().");
    if (!keystore.persists()) {
      log.debug("Leaving CertEnrollment.sealText(). Nothing outlives the " +
                "process to seal for.");
      return { ok: true, value: String(plain) };
    }
    let sealed = null;
    try {
      sealed = keystore.seal(String(plain), label);
    } catch (e) {
      log.debug("Caught in CertEnrollment.sealText(): " +
                ((e && e.message) || e));
      sealed = null;
    }
    if (!sealed) {
      log.debug("Leaving CertEnrollment.sealText(). Could not seal.");
      return { ok: false };
    }
    log.debug("Leaving CertEnrollment.sealText().");
    return { ok: true, value: sealed };
  }

  openText(value, label?) {
    const { log, keystore } = this.deps;
    log.debug("Entering CertEnrollment.openText().");
    const text = String(value || '');
    if (text.indexOf('$aesgcm$') !== 0) {
      log.debug("Leaving CertEnrollment.openText(). Not sealed.");
      return text;
    }
    let opened = null;
    try {
      opened = keystore.open(text, label);
    } catch (e) {
      log.debug("Caught in CertEnrollment.openText(): " +
                ((e && e.message) || e));
      opened = null;
    }
    log.debug("Leaving CertEnrollment.openText().");
    return opened === null || opened === undefined ? null : String(opened);
  }

  normalSerial(serial) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.normalSerial().");
    log.debug("Leaving CertEnrollment.normalSerial().");
    return String(serial || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase()
      .replace(/^0+(?=.)/, '');
  }

  publicRecord(one) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.publicRecord().");
    const out = Object.assign({}, one);
    delete out.privateKeyPem;
    out.expired = new Date(out.notAfter).getTime() < Date.now();
    out.status = out.revoked ? 'revoked' : (out.expired ? 'expired' : 'valid');
    log.debug("Leaving CertEnrollment.publicRecord().");
    return out;
  }

  // The certificates on an entry, newest first, with no key material.
  enrolledOf(entry) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.enrolledOf().");
    const values = self.readAttribute(entry, 'certificate');
    if (!values) {
      log.debug("Leaving CertEnrollment.enrolledOf(). No entry.");
      return [];
    }
    log.debug("Leaving CertEnrollment.enrolledOf().");
    return self.parseJsonValues(values).map(function (one) {
      return self.publicRecord(one);
    }).sort(function (a, b) {
      return String(b.issuedAt).localeCompare(String(a.issuedAt));
    });
  }

  // ---------------------------------------------------------------------------
  // THE SUBJECT'S NAMING ATTRIBUTES, from the entry and the names it owns.
  //
  // **A CERTIFICATE THAT NAMES A HOST HAS THAT HOST AS ITS COMMON NAME, AND
  // THE ENTRY'S IDENTIFIER AS ITS UID (#207, #208, 2026-09-24).** Until then
  // every certificate was `CN=<entry id>`, and a server certificate for
  // `www.example.test` said `CN=alice`. certbot and lego both read a
  // certificate's names back as its CN plus its dNSNames when they renew —
  // so every renewal asked for an order naming `alice`, a host nobody
  // registered, and was refused `rejectedIdentifier`: neither client could
  // renew a single certificate this service had issued it. The CA/Browser
  // Forum's rule is the same one (Baseline Requirements 7.1.4.3: a common
  // name, where present, is one of the subjectAltName values).
  //
  // **THE UID IS WHAT KEEPS THE DN NAMING EXACTLY ONE ENTRY.** A host name
  // may be registered on two entries, and a person's subject DN is written
  // to `x509subject`, which `ldap/ldap_server.js`'s `locateEntry()` reads to
  // turn a certificate's DN into an entry. `CN=www.example.test, O=…` alone
  // would name whichever of the two it met first; with `UID=<entry id>` it
  // names the one it was issued to. A certificate naming no host keeps
  // `CN=<entry id>` as before.
  // ---------------------------------------------------------------------------
  subjectFor(entry, names) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.subjectFor().");
    const host = (names || []).filter(function (one) {
      return one.kind === 'dns';
    }).concat((names || []).filter(function (one) {
      return one.kind === 'ip';
    }))[0];
    if (!host) {
      log.debug("Leaving CertEnrollment.subjectFor(). No host.");
      return [{ name: 'CN', value: entry.id }];
    }
    log.debug("Leaving CertEnrollment.subjectFor(). A host.");
    return [{ name: 'CN', value: host.value },
            { name: 'UID', value: entry.id }];
  }

  // ---------------------------------------------------------------------------
  // ISSUE.
  //
  //   spec.family       'acme' | 'est' | 'scep'
  //   spec.profile      one of PROFILE_IDS
  //   spec.principal    from an authenticate*() call, or a console/portal
  //                     principal built by `sessionPrincipal()`
  //   spec.target       { kind, id }
  //   spec.publicKeyPem the subject's key
  //   spec.requested    { uris, dns, ips, emails, upns }
  //   spec.keySource    'client' | 'server'
  //   spec.privateKeyPem only when keySource === 'server'
  //   spec.via          what to call the door on audit rows
  //   spec.replaces     a serial this certificate supersedes (re-enrollment)
  // ---------------------------------------------------------------------------
  async issue(spec?) {
    const { nodeCrypto, log, helpers, audit, config, errorCodes, pki,
            realms } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.issue().");
    const asked = spec || {};
    const family = String(asked.family || '');
    if (!self.isFamily(family)) {
      log.debug("Leaving CertEnrollment.issue(). Unknown family.");
      return self.refuse('STS-ENROLL-0004', 500, 'Not an enrollment family: ' +
                         family);
    }
    const auditRefusal = function (refusal) {
      audit.record({
        category: 'protocol', action: 'enrollment.issue.refused',
        protocol: FAMILY_LABELS[family], outcome: 'failure',
        errorCode: errorCodes.codeOf(refusal) || 'STS-ENROLL-0004',
        actor: asked.principal ? String(asked.principal.id) : '',
        target: asked.target ? self.entryUri(asked.target) : '',
        summary: 'a certificate was not issued over ' + FAMILY_LABELS[family] +
                 ': ' + String((refusal.errors || [])[0] || '').slice(0, 300),
        detail: { profile: String(asked.profile || ''),
                  via: String(asked.via || family) }
      });
      return refusal;
    };
    const profile = self.checkProfile(family, asked.profile);
    if (!profile.ok) {
      log.debug("Leaving CertEnrollment.issue(). Profile refused.");
      return auditRefusal(profile);
    }
    const target = asked.target;
    const resolved = self.resolveEntry(target && target.kind,
                                       target && target.id);
    if (!resolved.ok) {
      log.debug("Leaving CertEnrollment.issue(). No entry.");
      return auditRefusal(resolved);
    }
    const allowed = self.authorizeTarget(asked.principal, resolved.entry);
    if (!allowed.ok) {
      log.debug("Leaving CertEnrollment.issue(). Not authorized.");
      return auditRefusal(allowed);
    }
    const names = self.namesFor(resolved, profile.profile, asked.requested);
    if (!names.ok) {
      log.debug("Leaving CertEnrollment.issue(). A name was refused.");
      return auditRefusal(names);
    }
    const nowMs = Date.now();
    const existing = self.parseJsonValues(resolved.attributes[
      ATTRIBUTES[resolved.entry.kind].certificate]);
    const live = existing.filter(function (one) {
      return new Date(one.notAfter).getTime() > nowMs;
    });
    const cap = Number(config.value('pki.enrollmentMaxCertificatesPerEntry'));
    const replacing = asked.replaces ? self.normalSerial(asked.replaces) : '';
    const counted = live.filter(function (one) {
      return self.normalSerial(one.serialHex) !== replacing;
    });
    if (counted.length >= cap) {
      log.debug("Leaving CertEnrollment.issue(). The entry is full.");
      return auditRefusal(self.refuse('STS-ENROLL-0040', 409, 'The ' +
        self.entryLabel(resolved.entry) + ' already holds ' + counted.length +
        ' unexpired enrolled certificate(s), the most ' +
        'pki.enrollmentMaxCertificatesPerEntry allows. Revoke one first.'));
    }
    const org = self.organisationOf();
    const subject = self.subjectFor(resolved.entry, names.names)
      .concat([{ name: 'O', value: org.organisation }])
      .concat(org.country ? [{ name: 'C', value: org.country }] : []);
    const days = Number(config.value(family + '.certificateLifetimeDays'));
    const issued = await pki.issueEnrolled(realms.currentId(), family, {
      subject: subject,
      publicKeyPem: asked.publicKeyPem,
      profile: profile.profile,
      subjectAltName: names.names,
      days: days,
      identifier: resolved.entry.id,
      subjectKind: resolved.entry.kind,
      holderSubject: resolved.entry.kind === 'person'
        ? helpers.subjectForName(resolved.entry.id) : ''
    });
    if (!issued.ok) {
      log.debug("Leaving CertEnrollment.issue(). The authority refused.");
      return auditRefusal(self.refuse(
        errorCodes.codeOf(issued) || 'STS-ENROLL-0042', 503,
        'The ' + FAMILY_LABELS[family] + ' Issuing CA could not issue: ' +
        String((issued.errors || [])[0] || 'unknown reason')));
    }
    let thumbprint = '';
    let subjectDn = '';
    try {
      const cert = new nodeCrypto.X509Certificate(issued.certificatePem);
      thumbprint = cert.fingerprint256.replace(/:/g, '').toLowerCase();
      subjectDn = helpers.dnRfc4514(cert.subject);
    } catch (e) {
      log.debug("Caught in CertEnrollment.issue(): " + ((e && e.message) || e));
    }
    const record = {
      serialHex: self.normalSerial(issued.serialHex),
      family: family,
      profile: profile.profile,
      subject: subjectDn || String(issued.subject || ''),
      names: names.names.map(function (one) {
        return one.kind + ':' + one.value;
      }),
      thumbprint: thumbprint,
      keyAlg: String(asked.keyAlg || ''),
      notBefore: issued.notBefore,
      notAfter: issued.notAfter,
      issuedAt: new Date(nowMs).toISOString(),
      requestedBy: asked.principal
        ? { kind: asked.principal.kind, id: String(asked.principal.id),
            admin: !!asked.principal.admin }
        : null,
      via: String(asked.via || family),
      keySource: asked.keySource === 'server' ? 'server' : 'client',
      replaces: replacing || null,
      certificatePem: issued.certificatePem,
      chainPem: (issued.issuerChainPem || []).slice()
    };
    // The private key FIRST, for `person_assertions.write()`'s reason: a
    // certificate on the entry with no key behind it, when this service made
    // the key, is a credential that was issued and lost.
    const kind = resolved.entry.kind;
    if (record.keySource === 'server') {
      const sealed = self.sealText(asked.privateKeyPem, kind === 'person'
        ? 'person-private-key' : 'application-private-key');
      if (!sealed.ok) {
        log.debug("Leaving CertEnrollment.issue(). The key could not be " +
                  "sealed.");
        return auditRefusal(self.refuse('STS-ENROLL-0043', 503, 'The ' +
                                        'generated private key could not be ' +
                                        'sealed for storage, so the ' +
                                        'certificate was not recorded.'));
      }
      const keys = (resolved.attributes[ATTRIBUTES[kind].privateKey] || [])
        .filter(function (one) {
          return String(one).indexOf(record.serialHex + ':') !== 0;
        }).concat([record.serialHex + ':' + sealed.value]);
      if (!self.writeAttribute(resolved.entry, 'privateKey', keys)) {
        log.debug("Leaving CertEnrollment.issue(). The key was not written.");
        return auditRefusal(self.refuse('STS-ENROLL-0041', 503, 'The ' +
                                        'generated private key could not be ' +
                                        'written onto the ' +
                                        self.entryLabel(resolved.entry) + '.'));
      }
    }
    const kept = existing.filter(function (one) {
      return new Date(one.notAfter).getTime() > nowMs ||
             one.revoked;
    }).map(function (one) {
      return JSON.stringify(one);
    }).concat([JSON.stringify(record)]);
    if (!self.writeAttribute(resolved.entry, 'certificate', kept)) {
      log.debug("Leaving CertEnrollment.issue(). The certificate was not " +
                "written.");
      return auditRefusal(self.refuse('STS-ENROLL-0041', 503, 'The ' +
                                      'certificate was issued but could not ' +
                                      'be written onto the ' +
                                      self.entryLabel(resolved.entry) + '.'));
    }
    // A person's subject DN goes into x509subject as well, which is the
    // attribute every certificate-to-entry lookup here already reads.
    if (kind === 'person' && subjectDn && self.directory) {
      const subjects = (resolved.attributes.x509subject || []).slice();
      if (subjects.indexOf(subjectDn) < 0) {
        try {
          self.directory.write('person', resolved.entry.id, 'x509subject',
                               subjects.concat([subjectDn]));
        } catch (e) {
          log.debug("Caught in CertEnrollment.issue(): " +
                    ((e && e.message) || e));
        }
      }
    }
    audit.record({
      category: 'protocol', action: 'enrollment.issue',
      protocol: FAMILY_LABELS[family], outcome: 'success',
      actor: asked.principal ? String(asked.principal.id) : '',
      target: self.entryUri(resolved.entry),
      summary: 'a ' + profile.profile + ' certificate was issued over ' +
               FAMILY_LABELS[family] + ' for the ' +
               self.entryLabel(resolved.entry) +
               (allowed.admin ? ' by an administrator' : ''),
      detail: { serialHex: record.serialHex, profile: record.profile,
                keySource: record.keySource, via: record.via,
                notAfter: record.notAfter }
    });
    // A PERSON's certificate is one of their credentials, and CAEP says so
    // with its issuer and serial (#145). An application's is not a person's
    // and has no CAEP subject here.
    if (kind === 'person') {
      accountSignals.certificateChanged({ username: resolved.entry.id,
        pem: issued.certificatePem, changeType: 'create',
        friendlyName: profile.profile + ' certificate',
        initiatingEntity: allowed.admin ? 'admin' : 'user',
        via: FAMILY_LABELS[family],
        reasonAdmin: 'A ' + profile.profile + ' certificate was issued to ' +
                     resolved.entry.id + ' over ' + FAMILY_LABELS[family] +
                     '.',
        reasonUser: 'A certificate was issued to you.' });
    }
    if (replacing) {
      await self.revokeEnrolled(replacing, 'superseded',
                                asked.principal ? String(asked.principal.id)
                                                : '',
                                { quiet: true });
    }
    log.debug("Leaving CertEnrollment.issue(). serial=" + record.serialHex);
    return { ok: true, record: self.publicRecord(record),
             target: resolved.entry, admin: !!allowed.admin };
  }

  // A key pair generated HERE and certified in one act — EST /serverkeygen and
  // the console's "issue with a server-generated key". The private key is
  // returned ONCE and kept, sealed, on the entry.
  async issueWithServerKey(spec?) {
    const { log, keyMaterial } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.issueWithServerKey().");
    const asked = spec || {};
    const keyAlg = String(asked.keyAlg || 'ec-p256');
    if ((keyMaterial.keyAlgIds() || []).indexOf(keyAlg) < 0) {
      log.debug("Leaving CertEnrollment.issueWithServerKey(). Unknown " +
                "algorithm.");
      return self.refuse('STS-ENROLL-0035', 400, '"' + keyAlg + '" is not a ' +
                         'key algorithm this service generates. They are ' +
                         keyMaterial.keyAlgIds().join(', ') + '.');
    }
    let pair = null;
    try {
      pair = await keyMaterial.generateKeyPair(keyAlg);
    } catch (e) {
      log.debug("Caught in CertEnrollment.issueWithServerKey(): " +
                ((e && e.message) || e));
      pair = null;
    }
    if (!pair) {
      log.debug("Leaving CertEnrollment.issueWithServerKey(). Generation " +
                "failed.");
      return self.refuse('STS-ENROLL-0035', 400, 'A ' + keyAlg + ' key pair ' +
                         'could not be generated.');
    }
    const issued = await self.issue(Object.assign({}, asked, {
      publicKeyPem: pair.publicPem,
      keySource: 'server',
      privateKeyPem: pair.privatePem,
      keyAlg: keyAlg
    }));
    if (!issued.ok) {
      log.debug("Leaving CertEnrollment.issueWithServerKey(). Refused.");
      return issued;
    }
    log.debug("Leaving CertEnrollment.issueWithServerKey().");
    return Object.assign({}, issued, { privateKeyPem: pair.privatePem,
                                       keyAlg: keyAlg });
  }

  // ---------------------------------------------------------------------------
  // FIND AND REVOKE.
  // ---------------------------------------------------------------------------
  findEnrolled(serialHex, family) {
    const { log, helpers, pki, realms } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.findEnrolled(). serial=" + serialHex);
    const wanted = self.normalSerial(serialHex);
    if (!wanted) {
      log.debug("Leaving CertEnrollment.findEnrolled(). No serial.");
      return null;
    }
    const families = family ? [String(family)] : FAMILIES;
    for (let f = 0; f < families.length; f++) {
      let issued = [];
      try {
        issued = pki.issuedKeyPairsFor(realms.currentId(), families[f]);
      } catch (e) {
        log.debug("Caught in CertEnrollment.findEnrolled(): " +
                  ((e && e.message) || e));
        issued = [];
      }
      const hit = issued.filter(function (one) {
        return self.normalSerial(one.serialHex) === wanted;
      })[0];
      if (hit && self.isKind(hit.subjectKind)) {
        // THE ENTRY IT WAS ISSUED TO, by its subject where one was recorded, so
        // a rename finds the renamed entry and a name deleted and re-created
        // finds nobody (2026-09-14).
        const renamed = hit.holderSubject
          ? helpers.nameForSubject(hit.holderSubject) : hit.identifier;
        if (!renamed) {
          log.debug("Leaving CertEnrollment.findEnrolled(). Its holder is " +
                    "gone.");
          return null;
        }
        const entry = { kind: hit.subjectKind, id: renamed };
        const record = self.enrolledOf(entry).filter(function (one) {
          return self.normalSerial(one.serialHex) === wanted;
        })[0];
        if (record) {
          log.debug("Leaving CertEnrollment.findEnrolled(). Found.");
          return { entry: entry, record: record, family: families[f] };
        }
      }
    }
    log.debug("Leaving CertEnrollment.findEnrolled(). Not found.");
    return null;
  }

  async revokeEnrolled(serialHex, reason, by?, options?) {
    const { log, audit, errorCodes, realms, loadRevocation } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.revokeEnrolled(). serial=" + serialHex);
    const opts = options || {};
    const found = self.findEnrolled(serialHex, opts.family);
    if (!found) {
      log.debug("Leaving CertEnrollment.revokeEnrolled(). Not found.");
      return self.refuse('STS-ENROLL-0070', 404,
                         'No certificate with that serial was issued over ' +
                         (opts.family ? FAMILY_LABELS[opts.family]
                                      : 'an enrollment protocol') +
                         ' in this realm.');
    }
    if (opts.entry && !self.sameEntry(opts.entry, found.entry)) {
      log.debug("Leaving CertEnrollment.revokeEnrolled(). Not that entry's.");
      return self.refuse('STS-ENROLL-0071', 403, 'That certificate does not ' +
                         'belong to the ' + self.entryLabel(opts.entry) + '.');
    }
    const revocation = loadRevocation();
    const done = revocation.revoke(realms.currentId(), found.family, {
      serialHex: found.record.serialHex,
      reason: reason || 'unspecified',
      subject: found.record.subject,
      note: 'enrolled over ' + FAMILY_LABELS[found.family] + ' for ' +
            self.entryUri(found.entry) + (by ? '; revoked by ' + by : '')
    });
    if (!done || done.ok === false) {
      log.debug("Leaving CertEnrollment.revokeEnrolled(). The CA refused.");
      return self.refuse(errorCodes.codeOf(done) || 'STS-ENROLL-0072', 400,
                         String(((done && done.errors) || [])[0] ||
                                'The revocation was refused.'));
    }
    const values = self.readAttribute(found.entry, 'certificate') || [];
    const at = new Date().toISOString();
    const rewritten = self.parseJsonValues(values).map(function (one) {
      if (self.normalSerial(one.serialHex) ===
            self.normalSerial(found.record.serialHex) &&
          !one.revoked) {
        one.revoked = { at: at, reason: reason || 'unspecified',
                        by: String(by || '') };
      }
      return JSON.stringify(one);
    });
    self.writeAttribute(found.entry, 'certificate', rewritten);
    // Revoked, told to a person's receivers whether or not the audit row is
    // quiet (#145): a certificate superseded by its renewal is still one the
    // person no longer holds, and that act is the system's.
    if (found.entry && found.entry.kind === 'person') {
      accountSignals.certificateChanged({ username: found.entry.id,
        pem: found.record.certificatePem, changeType: 'revoke',
        friendlyName: String(found.record.profile || '') + ' certificate',
        initiatingEntity: reason === 'superseded' ? 'system'
          : String(by || '') === String(found.entry.id) ? 'user' : 'admin',
        via: FAMILY_LABELS[found.family],
        reasonAdmin: 'A certificate of ' + found.entry.id + ' issued over ' +
                     FAMILY_LABELS[found.family] + ' was revoked (' +
                     (reason || 'unspecified') + ').',
        reasonUser: 'A certificate of yours was revoked.' });
    }
    if (!opts.quiet) {
      audit.record({
        category: 'protocol', action: 'enrollment.revoke',
        protocol: FAMILY_LABELS[found.family], outcome: 'success',
        actor: String(by || ''), target: self.entryUri(found.entry),
        summary: 'an enrolled certificate was revoked (' +
                 (reason || 'unspecified') + ')',
        detail: { serialHex: found.record.serialHex, family: found.family }
      });
    }
    log.debug("Leaving CertEnrollment.revokeEnrolled().");
    return { ok: true, serialHex: found.record.serialHex, entry: found.entry,
             family: found.family, reason: reason || 'unspecified' };
  }

  // A server-generated private key held on an entry, opened. For the entry's
  // own holder through the portal and never through a view.
  serverKeyOf(entry, serialHex) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.serverKeyOf().");
    const values = self.readAttribute(entry, 'privateKey') || [];
    const prefix = self.normalSerial(serialHex) + ':';
    const hit = values.filter(function (one) {
      return String(one).indexOf(prefix) === 0;
    })[0];
    log.debug("Leaving CertEnrollment.serverKeyOf().");
    return hit
      ? self.openText(String(hit).slice(prefix.length),
                      entry.kind === 'person' ? 'person-private-key'
                                              : 'application-private-key')
      : null;
  }

  // ---------------------------------------------------------------------------
  // CREDENTIALS BOUND TO AN ENTRY: THE EAB KEY AND THE SCEP CHALLENGE.
  //
  // **THE IDENTIFIER NAMES THE ENTRY**, so neither needs a register of its own
  // and neither needs a scan to find: `eab-p-<base64url(alice)>-<16 hex>`. That
  // prefix is not a secret and knowing it gains nothing — the MAC key or the
  // challenge secret is what authenticates, compared in constant time. A
  // credential is created FOR an entry by somebody entitled to (the person on
  // the portal, an administrator on the console or the API), shown once, and
  // spent once.
  // ---------------------------------------------------------------------------
  credentialId(prefix, entry) {
    const { nodeCrypto, log } = this.deps;
    log.debug("Entering CertEnrollment.credentialId().");
    log.debug("Leaving CertEnrollment.credentialId().");
    return prefix + '-' + (entry.kind === 'person' ? 'p' : 'a') + '-' +
           Buffer.from(entry.id, 'utf8').toString('base64url') + '-' +
           nodeCrypto.randomBytes(8).toString('hex');
  }

  entryOfCredentialId(prefix, id) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.entryOfCredentialId().");
    const match = new RegExp('^' + prefix + '-([pa])-([A-Za-z0-9_-]{1,400})-' +
                             '([0-9a-f]{16})$').exec(String(id || ''));
    if (!match) {
      log.debug("Leaving CertEnrollment.entryOfCredentialId(). Malformed.");
      return null;
    }
    let decoded = '';
    try {
      decoded = Buffer.from(match[2], 'base64url').toString('utf8');
    } catch (e) {
      log.debug("Caught in CertEnrollment.entryOfCredentialId(): " +
                ((e && e.message) || e));
      decoded = '';
    }
    if (!self.wellFormedId(decoded) ||
        Buffer.from(decoded, 'utf8').toString('base64url') !== match[2]) {
      log.debug("Leaving CertEnrollment.entryOfCredentialId(). Not canonical.");
      return null;
    }
    log.debug("Leaving CertEnrollment.entryOfCredentialId().");
    return { kind: match[1] === 'p' ? 'person' : 'application', id: decoded };
  }

  lifetimeOf(asked, setting) {
    const { log, config } = this.deps;
    log.debug("Entering CertEnrollment.lifetimeOf().");
    const configured = Number(config.value(setting));
    const wanted = Number(asked);
    log.debug("Leaving CertEnrollment.lifetimeOf().");
    return (Number.isInteger(wanted) && wanted >= 60 && wanted <= configured)
      ? wanted : configured;
  }

  liveCredentials(values, nowMs?) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.liveCredentials().");
    log.debug("Leaving CertEnrollment.liveCredentials().");
    return self.parseJsonValues(values).filter(function (one) {
      return new Date(one.expiresAt).getTime() > nowMs && !one.usedAt;
    });
  }

  createEab(spec?) {
    const { nodeCrypto, log, audit } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.createEab().");
    const asked = spec || {};
    const resolved = self.resolveEntry(asked.target && asked.target.kind,
                                       asked.target && asked.target.id);
    if (!resolved.ok) {
      log.debug("Leaving CertEnrollment.createEab(). No entry.");
      return resolved;
    }
    const nowMs = Date.now();
    const values = resolved.attributes[ATTRIBUTES[resolved.entry.kind].eab] ||
                   [];
    // Expired keys are dropped as a new one is made; a key already used to bind
    // an account is kept, because that account's binding is described by it.
    const kept = self.parseJsonValues(values).filter(function (one) {
      return one.boundAccount || new Date(one.expiresAt).getTime() > nowMs;
    });
    if (kept.filter(function (one) { return !one.boundAccount; }).length >=
        MAX_CREDENTIALS_PER_ENTRY) {
      log.debug("Leaving CertEnrollment.createEab(). Too many.");
      return self.refuse('STS-ENROLL-0044', 409, 'The ' +
                         self.entryLabel(resolved.entry) + ' already has ' +
                         MAX_CREDENTIALS_PER_ENTRY + ' unused EAB keys. ' +
                         'Delete one first.');
    }
    const kid = self.credentialId('eab', resolved.entry);
    const hmacKey = nodeCrypto.randomBytes(32).toString('base64url');
    const sealed = self.sealText(hmacKey, 'acme-eab-key');
    if (!sealed.ok) {
      log.debug("Leaving CertEnrollment.createEab(). Could not seal.");
      return self.refuse('STS-ENROLL-0043', 503, 'The EAB key could not be ' +
                         'sealed for storage.');
    }
    const lifetimeS = self.lifetimeOf(asked.lifetimeS, 'acme.eabLifetimeS');
    const record = {
      kid: kid,
      hmacKey: sealed.value,
      createdAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + lifetimeS * 1000).toISOString(),
      createdBy: String(asked.createdBy || ''),
      boundAccount: null,
      boundAt: null
    };
    if (!self.writeAttribute(resolved.entry, 'eab',
                             kept.concat([record]).map(function (one) {
                               return JSON.stringify(one);
                             }))) {
      log.debug("Leaving CertEnrollment.createEab(). Not written.");
      return self.refuse('STS-ENROLL-0041', 503, 'The EAB key could not be ' +
                         'written onto the ' + self.entryLabel(resolved.entry) +
                         '.');
    }
    audit.record({
      category: 'configuration', action: 'enrollment.eab.create',
      protocol: 'ACME', outcome: 'success', actor: record.createdBy,
      target: self.entryUri(resolved.entry),
      summary: 'an ACME External Account Binding key was created for the ' +
               self.entryLabel(resolved.entry),
      detail: { kid: kid, expiresAt: record.expiresAt }
    });
    log.debug("Leaving CertEnrollment.createEab().");
    return { ok: true, kid: kid, hmacKey: hmacKey, alg: 'HS256',
             expiresAt: record.expiresAt, target: resolved.entry };
  }

  findEab(kid) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.findEab().");
    const entry = self.entryOfCredentialId('eab', kid);
    if (!entry) {
      log.debug("Leaving CertEnrollment.findEab(). Malformed.");
      return null;
    }
    const values = self.readAttribute(entry, 'eab');
    if (!values) {
      log.debug("Leaving CertEnrollment.findEab(). No entry.");
      return null;
    }
    const record = self.parseJsonValues(values).filter(function (one) {
      return one.kid === String(kid);
    })[0];
    if (!record) {
      log.debug("Leaving CertEnrollment.findEab(). No such key.");
      return null;
    }
    const opened = self.openText(record.hmacKey, 'acme-eab-key');
    if (opened === null) {
      log.debug("Leaving CertEnrollment.findEab(). Could not open.");
      return null;
    }
    log.debug("Leaving CertEnrollment.findEab().");
    return {
      entry: entry,
      kid: record.kid,
      hmacKey: Buffer.from(opened, 'base64url'),
      expired: new Date(record.expiresAt).getTime() <= Date.now(),
      boundAccount: record.boundAccount || null,
      expiresAt: record.expiresAt
    };
  }

  // Spend the key on one account. A second account presenting the same key is
  // refused; the SAME account re-presenting it (a client retrying newAccount)
  // is the idempotent case RFC 8555 section 7.3.1 describes and is answered as
  // such.
  bindEab(kid, accountThumbprint) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.bindEab().");
    const entry = self.entryOfCredentialId('eab', kid);
    const values = entry ? self.readAttribute(entry, 'eab') : null;
    if (!values) {
      log.debug("Leaving CertEnrollment.bindEab(). No such key.");
      return self.refuse('STS-ENROLL-0080', 401, 'The External Account ' +
                         'Binding key is not known in this realm.');
    }
    let result = null;
    const rewritten = self.parseJsonValues(values).map(function (one) {
      if (one.kid !== String(kid)) {
        return one;
      }
      if (one.boundAccount && one.boundAccount !== accountThumbprint) {
        result = self.refuse('STS-ENROLL-0081', 401, 'That External Account ' +
                             'Binding key has already bound another account.');
        return one;
      }
      if (new Date(one.expiresAt).getTime() <= Date.now() &&
          !one.boundAccount) {
        result = self.refuse('STS-ENROLL-0082', 401, 'That External Account ' +
                             'Binding key has expired.');
        return one;
      }
      if (!one.boundAccount) {
        one.boundAccount = String(accountThumbprint);
        one.boundAt = new Date().toISOString();
      }
      result = { ok: true, entry: entry };
      return one;
    });
    if (!result) {
      log.debug("Leaving CertEnrollment.bindEab(). No such key.");
      return self.refuse('STS-ENROLL-0080', 401, 'The External Account ' +
                         'Binding key is not known in this realm.');
    }
    if (result.ok) {
      self.writeAttribute(entry, 'eab', rewritten.map(function (one) {
        return JSON.stringify(one);
      }));
    }
    log.debug("Leaving CertEnrollment.bindEab(). ok=" + !!result.ok);
    return result;
  }

  // ---------------------------------------------------------------------------
  // BINDING AN EAB KEY ONCE ACROSS THE CLUSTER (2026-09-14, #46 section 2).
  //
  // `bindEab()` reads the key's record off the entry, sees
  // `boundAccount: null`, and writes the account in. Two ACME newAccount
  // requests signed by two DIFFERENT account keys, with one EAB key, arriving
  // at two nodes at once both read null — and RFC 8555 section 7.3.4's "bound
  // to one account" became two accounts, each issued certificates for the
  // entry the key names. The entry is last writer wins, so it even ends up
  // naming only one of them.
  //
  // **THE KEY ID IS CLAIMED BEFORE THE BINDING IS WRITTEN.** The claim lives as
  // long as a claim can (thirty days): its job is the window before every node
  // holds the entry that says the key is bound, and after that the entry's own
  // `boundAccount` refuses a second account as it always did. A bind that is
  // refused after the claim (the key expired under it) gives the claim back.
  //
  // **WHAT IT COSTS**: the SAME account retrying newAccount at a second node
  // before the first node's binding has reached it is refused as a second
  // account (`STS-ENROLL-0081`) rather than answered idempotently — the claim
  // cannot say which account holds it. The client's retry once the entry has
  // replicated finds its account (section 7.3.1) and is answered. A key bound
  // twice is a certificate for somebody else's entry; a retry refused once is a
  // retry.
  // ---------------------------------------------------------------------------
  bindEabOnce(kid, accountThumbprint) {
    const { log, errorCodes, claims } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.bindEabOnce().");
    const known = self.findEab(kid);
    if (known && known.boundAccount === String(accountThumbprint)) {
      log.debug("Leaving CertEnrollment.bindEabOnce(). Already this " +
                "account's.");
      return Promise.resolve(self.bindEab(kid, accountThumbprint));
    }
    log.debug("Leaving CertEnrollment.bindEabOnce(). Claiming.");
    return claims.claim({ scope: 'acme.eab-bind', value: String(kid),
                          ttlMs: EAB_CLAIM_TTL_MS })
      .then(function (claimed) {
        if (!claimed.ok && claimed.reason === 'used' && known &&
            known.boundAccount) {
          // The binding has already reached this node: the refusal it always
          // was, under the code it always had.
          log.debug("Leaving CertEnrollment.bindEabOnce(). Bound, on the " +
                    "entry.");
          return self.bindEab(kid, accountThumbprint);
        }
        if (!claimed.ok && claimed.reason === 'used') {
          log.warn('cert_enrollment: an External Account Binding key was ' +
                   'presented for a new account while it is being or has ' +
                   'been bound to another, on this node or another. Refused.');
          return self.refuse('STS-ENROLL-0081', 401, 'That External Account ' +
                             'Binding key has already bound another account.');
        }
        if (!claimed.ok) {
          log.error(errorCodes.tag('STS-ENROLL-0091') + 'cert_enrollment: an ' +
                    'External Account Binding key could not be proved ' +
                    'unbound (' + (claimed.why || claimed.reason) + '), so ' +
                    'it was refused.');
          return self.refuse('STS-ENROLL-0091', 503, 'The External Account ' +
                             'Binding key could not be checked just now. Try ' +
                             'again.');
        }
        const bound = self.bindEab(kid, accountThumbprint);
        if (!bound.ok) {
          claims.release(claimed.handle);
        }
        return bound;
      });
  }

  deleteEab(kid, by?) {
    const { log, audit } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.deleteEab().");
    const entry = self.entryOfCredentialId('eab', kid);
    const values = entry ? self.readAttribute(entry, 'eab') : null;
    const records = values ? self.parseJsonValues(values) : [];
    const left = records.filter(function (one) {
      return one.kid !== String(kid);
    });
    if (!entry || left.length === records.length) {
      log.debug("Leaving CertEnrollment.deleteEab(). No such key.");
      return self.refuse('STS-ENROLL-0080', 404, 'There is no such External ' +
                         'Account Binding key in this realm.');
    }
    self.writeAttribute(entry, 'eab', left.map(function (one) {
      return JSON.stringify(one);
    }));
    audit.record({
      category: 'configuration', action: 'enrollment.eab.delete',
      protocol: 'ACME', outcome: 'success', actor: String(by || ''),
      target: self.entryUri(entry),
      summary: 'an ACME External Account Binding key was deleted',
      detail: { kid: String(kid) }
    });
    log.debug("Leaving CertEnrollment.deleteEab().");
    return { ok: true, kid: String(kid), entry: entry };
  }

  eabsOf(entry) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.eabsOf().");
    const values = self.readAttribute(entry, 'eab') || [];
    const nowMs = Date.now();
    log.debug("Leaving CertEnrollment.eabsOf().");
    return self.parseJsonValues(values).map(function (one) {
      return { kid: one.kid, createdAt: one.createdAt,
               expiresAt: one.expiresAt, createdBy: one.createdBy,
               boundAccount: one.boundAccount || null, boundAt: one.boundAt,
               status: one.boundAccount ? 'bound'
                 : (new Date(one.expiresAt).getTime() <= nowMs ? 'expired'
                                                                 : 'unused') };
    });
  }

  createScepChallenge(spec?) {
    const { nodeCrypto, log, audit } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.createScepChallenge().");
    const asked = spec || {};
    const profile = self.checkProfile('scep', asked.profile ||
                                      self.defaultProfile('scep'));
    if (!profile.ok) {
      log.debug("Leaving CertEnrollment.createScepChallenge(). Profile " +
                "refused.");
      return profile;
    }
    const resolved = self.resolveEntry(asked.target && asked.target.kind,
                                       asked.target && asked.target.id);
    if (!resolved.ok) {
      log.debug("Leaving CertEnrollment.createScepChallenge(). No entry.");
      return resolved;
    }
    const nowMs = Date.now();
    const values = resolved.attributes[
      ATTRIBUTES[resolved.entry.kind].challenge] || [];
    const kept = self.liveCredentials(values, nowMs);
    if (kept.length >= MAX_CREDENTIALS_PER_ENTRY) {
      log.debug("Leaving CertEnrollment.createScepChallenge(). Too many.");
      return self.refuse('STS-ENROLL-0044', 409, 'The ' +
                         self.entryLabel(resolved.entry) + ' already has ' +
                         MAX_CREDENTIALS_PER_ENTRY + ' unused SCEP ' +
                         'challenges. Delete one first.');
    }
    const id = self.credentialId('scep', resolved.entry);
    const secret = nodeCrypto.randomBytes(24).toString('base64url');
    const lifetimeS = self.lifetimeOf(asked.lifetimeS,
                                      'scep.challengeLifetimeS');
    const record = {
      id: id,
      sha256: nodeCrypto.createHash('sha256').update(secret).digest('hex'),
      profile: profile.profile,
      createdAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + lifetimeS * 1000).toISOString(),
      createdBy: String(asked.createdBy || ''),
      usedAt: null
    };
    if (!self.writeAttribute(resolved.entry, 'challenge',
                             kept.concat([record]).map(function (one) {
                               return JSON.stringify(one);
                             }))) {
      log.debug("Leaving CertEnrollment.createScepChallenge(). Not written.");
      return self.refuse('STS-ENROLL-0041', 503, 'The challenge could not be ' +
                         'written onto the ' + self.entryLabel(resolved.entry) +
                         '.');
    }
    audit.record({
      category: 'configuration', action: 'enrollment.challenge.create',
      protocol: 'SCEP', outcome: 'success', actor: record.createdBy,
      target: self.entryUri(resolved.entry),
      summary: 'a SCEP challenge password was created for the ' +
               self.entryLabel(resolved.entry) + ' (' + profile.profile + ')',
      detail: { id: id, profile: profile.profile, expiresAt: record.expiresAt }
    });
    log.debug("Leaving CertEnrollment.createScepChallenge().");
    return { ok: true, id: id, challenge: id + '.' + secret,
             profile: profile.profile, expiresAt: record.expiresAt,
             target: resolved.entry };
  }

  // Redeem a challenge password. `peek` checks without spending — SCEP answers
  // a retried PKIOperation for a transaction it already completed, and the
  // protocol module decides whether a retry is that case.
  redeemScepChallenge(challenge, options?) {
    const { nodeCrypto, log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.redeemScepChallenge().");
    const opts = options || {};
    const text = String(challenge || '');
    const dot = text.lastIndexOf('.');
    const id = dot > 0 ? text.slice(0, dot) : '';
    const secret = dot > 0 ? text.slice(dot + 1) : '';
    const entry = self.entryOfCredentialId('scep', id);
    const values = entry ? self.readAttribute(entry, 'challenge') : null;
    const generic = self.refuse('STS-ENROLL-0083', 401, 'The challenge ' +
                                'password was not accepted.');
    if (!values || !secret || secret.length > 128) {
      log.debug("Leaving CertEnrollment.redeemScepChallenge(). Unknown.");
      return generic;
    }
    const records = self.parseJsonValues(values);
    const record = records.filter(function (one) { return one.id === id; })[0];
    if (!record) {
      log.debug("Leaving CertEnrollment.redeemScepChallenge(). No such " +
                "challenge.");
      return generic;
    }
    const presented = nodeCrypto.createHash('sha256').update(secret).digest();
    const expected = Buffer.from(String(record.sha256 || ''), 'hex');
    if (expected.length !== presented.length ||
        !nodeCrypto.timingSafeEqual(presented, expected)) {
      log.debug("Leaving CertEnrollment.redeemScepChallenge(). Wrong secret.");
      return generic;
    }
    if (record.usedAt) {
      log.debug("Leaving CertEnrollment.redeemScepChallenge(). Spent.");
      return self.refuse('STS-ENROLL-0084', 401, 'That challenge password ' +
                         'has already been used.');
    }
    if (new Date(record.expiresAt).getTime() <= Date.now()) {
      log.debug("Leaving CertEnrollment.redeemScepChallenge(). Expired.");
      return self.refuse('STS-ENROLL-0085', 401, 'That challenge password ' +
                         'has expired.');
    }
    if (!opts.peek) {
      record.usedAt = new Date().toISOString();
      self.writeAttribute(entry, 'challenge', records.map(function (one) {
        return JSON.stringify(one);
      }));
    }
    log.debug("Leaving CertEnrollment.redeemScepChallenge(). Accepted.");
    return { ok: true, id: id, entry: entry, profile: record.profile };
  }

  // ---------------------------------------------------------------------------
  // A SCEP CHALLENGE, SPENT ONCE ACROSS THE CLUSTER (2026-09-14, #46
  // section 2).
  //
  // `redeemScepChallenge()` is "read `usedAt: null` off the entry, write the
  // time in", and two PKCSReq messages carrying one challenge password — two
  // transactionIDs, so `scep.js`'s transaction guard does not join them — at
  // two nodes both read null and both issued. The challenge is CLAIMED between
  // the look that proves it is right and the write that spends it; the claim
  // lives as long as the challenge could still verify, plus a minute of skew.
  // The synchronous `redeemScepChallenge()` is unchanged and is still what
  // marks the entry, which every page reads.
  // ---------------------------------------------------------------------------
  async redeemScepChallengeOnce(challenge) {
    const { log, errorCodes, claims } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.redeemScepChallengeOnce().");
    const peek = self.redeemScepChallenge(challenge, { peek: true });
    if (!peek.ok) {
      log.debug("Leaving CertEnrollment.redeemScepChallengeOnce(). Refused " +
                "on the entry.");
      return peek;
    }
    const record = self.parseJsonValues(
      self.readAttribute(peek.entry, 'challenge') || [])
      .filter(function (one) { return one.id === peek.id; })[0] || {};
    const remaining = new Date(record.expiresAt).getTime() - Date.now();
    const claimed = await claims.claim({
      scope: 'scep.challenge', value: peek.id,
      ttlMs: Math.max(60 * 1000, (remaining || 0) + 60 * 1000)
    });
    if (!claimed.ok && claimed.reason === 'used') {
      log.warn('cert_enrollment: a SCEP challenge password was presented ' +
               'while another request is spending it or has spent it, on ' +
               'this node or another. Refused.');
      log.debug("Leaving CertEnrollment.redeemScepChallengeOnce(). Claimed " +
                "elsewhere.");
      return self.refuse('STS-ENROLL-0084', 401, 'That challenge password ' +
                         'has already been used.');
    }
    if (!claimed.ok) {
      log.error(errorCodes.tag('STS-ENROLL-0091') + 'cert_enrollment: a SCEP ' +
                'challenge password could not be proved unspent (' +
                (claimed.why || claimed.reason) + '), so it was refused.');
      log.debug("Leaving CertEnrollment.redeemScepChallengeOnce(). The store.");
      return self.refuse('STS-ENROLL-0091', 503, 'The challenge password ' +
                         'could not be checked just now. Try again.');
    }
    const spent = self.redeemScepChallenge(challenge);
    if (!spent.ok) {
      claims.release(claimed.handle);
    }
    log.debug("Leaving CertEnrollment.redeemScepChallengeOnce(). ok=" +
              !!spent.ok);
    return spent;
  }

  deleteScepChallenge(id, by?) {
    const { log, audit } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.deleteScepChallenge().");
    const entry = self.entryOfCredentialId('scep', id);
    const values = entry ? self.readAttribute(entry, 'challenge') : null;
    const records = values ? self.parseJsonValues(values) : [];
    const left = records.filter(function (one) {
      return one.id !== String(id);
    });
    if (!entry || left.length === records.length) {
      log.debug("Leaving CertEnrollment.deleteScepChallenge(). No such " +
                "challenge.");
      return self.refuse('STS-ENROLL-0083', 404, 'There is no such SCEP ' +
                         'challenge in this realm.');
    }
    self.writeAttribute(entry, 'challenge', left.map(function (one) {
      return JSON.stringify(one);
    }));
    audit.record({
      category: 'configuration', action: 'enrollment.challenge.delete',
      protocol: 'SCEP', outcome: 'success', actor: String(by || ''),
      target: self.entryUri(entry),
      summary: 'a SCEP challenge password was deleted',
      detail: { id: String(id) }
    });
    log.debug("Leaving CertEnrollment.deleteScepChallenge().");
    return { ok: true, id: String(id), entry: entry };
  }

  scepChallengesOf(entry) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.scepChallengesOf().");
    const values = self.readAttribute(entry, 'challenge') || [];
    const nowMs = Date.now();
    log.debug("Leaving CertEnrollment.scepChallengesOf().");
    return self.parseJsonValues(values).map(function (one) {
      return { id: one.id, profile: one.profile, createdAt: one.createdAt,
               expiresAt: one.expiresAt, createdBy: one.createdBy,
               usedAt: one.usedAt || null,
               status: one.usedAt ? 'used'
                 : (new Date(one.expiresAt).getTime() <= nowMs ? 'expired'
                                                                 : 'unused') };
    });
  }

  // ---------------------------------------------------------------------------
  // HOST NAMES (an administrator's act).
  // ---------------------------------------------------------------------------
  hostNamesOf(entry) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.hostNamesOf().");
    const resolved = self.resolveEntry(entry.kind, entry.id);
    log.debug("Leaving CertEnrollment.hostNamesOf().");
    return resolved.ok ? resolved.hostNames.slice() : [];
  }

  changeHostName(entry, name, add?, by?) {
    const { log, audit } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.changeHostName(). add=" + add);
    const resolved = self.resolveEntry(entry && entry.kind, entry && entry.id);
    if (!resolved.ok) {
      log.debug("Leaving CertEnrollment.changeHostName(). No entry.");
      return resolved;
    }
    const host = self.normalHostName(name);
    if (!host) {
      log.debug("Leaving CertEnrollment.changeHostName(). Malformed.");
      return self.refuse('STS-ENROLL-0057', 400, '"' +
                         String(name).slice(0, 253) + '" is not a DNS name ' +
                         'or an IP address.');
    }
    const current = resolved.hostNames.slice();
    const has = current.indexOf(host) >= 0;
    if (add && has) {
      log.debug("Leaving CertEnrollment.changeHostName(). Already there.");
      return { ok: true, unchanged: true, hostNames: current };
    }
    if (!add && !has) {
      log.debug("Leaving CertEnrollment.changeHostName(). Not there.");
      return self.refuse('STS-ENROLL-0058', 404, '"' + host + '" is not ' +
                         'registered on the ' +
                         self.entryLabel(resolved.entry) + '.');
    }
    const next = add ? current.concat([host])
                     : current.filter(function (one) { return one !== host; });
    if (!self.writeAttribute(resolved.entry, 'hostName', next)) {
      log.debug("Leaving CertEnrollment.changeHostName(). Not written.");
      return self.refuse('STS-ENROLL-0041', 503, 'The host name could not be ' +
                         'written.');
    }
    audit.record({
      category: 'configuration',
      action: add ? 'enrollment.hostname.add' : 'enrollment.hostname.remove',
      outcome: 'success', actor: String(by || ''),
      target: self.entryUri(resolved.entry),
      summary: 'the host name ' + host + ' was ' +
               (add ? 'registered on' : 'removed from') + ' the ' +
               self.entryLabel(resolved.entry),
      detail: { hostName: host }
    });
    log.debug("Leaving CertEnrollment.changeHostName().");
    return { ok: true, hostNames: next, entry: resolved.entry };
  }

  // ---------------------------------------------------------------------------
  // LISTINGS ACROSS THE REALM, for the console pages and /admin-api.
  // ---------------------------------------------------------------------------
  holdersOf(key) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.holdersOf(). key=" + key);
    const out = [];
    if (!self.directory) {
      log.debug("Leaving CertEnrollment.holdersOf(). No directory.");
      return out;
    }
    ['person', 'application'].forEach(function (kind) {
      let ids = [];
      try {
        ids = self.directory.holders(kind, ATTRIBUTES[kind][key]) || [];
      } catch (e) {
        log.debug("Caught in CertEnrollment.holdersOf(): " +
                  ((e && e.message) || e));
        ids = [];
      }
      ids.forEach(function (id) {
        out.push({ kind: kind, id: String(id) });
      });
    });
    log.debug("Leaving CertEnrollment.holdersOf(). " + out.length + " " +
              "holder(s).");
    return out;
  }

  certificatesInRealm(family) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.certificatesInRealm(). family=" +
              family);
    const out = [];
    self.holdersOf('certificate').forEach(function (entry) {
      self.enrolledOf(entry).forEach(function (record) {
        if (!family || record.family === family) {
          out.push(Object.assign({ entry: entry,
                                   entryUri: self.entryUri(entry) },
                                 record));
        }
      });
    });
    log.debug("Leaving CertEnrollment.certificatesInRealm(). " + out.length +
              ".");
    return out.sort(function (a, b) {
      return String(b.issuedAt).localeCompare(String(a.issuedAt));
    });
  }

  eabsInRealm() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.eabsInRealm().");
    const out = [];
    self.holdersOf('eab').forEach(function (entry) {
      self.eabsOf(entry).forEach(function (one) {
        out.push(Object.assign({ entry: entry, entryUri: self.entryUri(entry) },
                               one));
      });
    });
    log.debug("Leaving CertEnrollment.eabsInRealm().");
    return out.sort(function (a, b) {
      return String(b.createdAt).localeCompare(String(a.createdAt));
    });
  }

  challengesInRealm() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.challengesInRealm().");
    const out = [];
    self.holdersOf('challenge').forEach(function (entry) {
      self.scepChallengesOf(entry).forEach(function (one) {
        out.push(Object.assign({ entry: entry, entryUri: self.entryUri(entry) },
                               one));
      });
    });
    log.debug("Leaving CertEnrollment.challengesInRealm().");
    return out.sort(function (a, b) {
      return String(b.createdAt).localeCompare(String(a.createdAt));
    });
  }

  hostNamesInRealm() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.hostNamesInRealm().");
    const out = [];
    self.holdersOf('hostName').forEach(function (entry) {
      const names = self.hostNamesOf(entry);
      if (names.length) {
        out.push({ entry: entry, entryUri: self.entryUri(entry),
                   hostNames: names });
      }
    });
    log.debug("Leaving CertEnrollment.hostNamesInRealm().");
    return out;
  }

  // The family's Issuing CA in this realm (and nothing private).
  authorityOf(family) {
    const { log, pki, realms } = this.deps;
    log.debug("Entering CertEnrollment.authorityOf(). family=" + family);
    let described = null;
    try {
      described = pki.describeIssuer(realms.currentId(), family);
    } catch (e) {
      log.debug("Caught in CertEnrollment.authorityOf(): " +
                ((e && e.message) || e));
      described = null;
    }
    log.debug("Leaving CertEnrollment.authorityOf().");
    return described;
  }

  // The CA certificates a client installs: the family Issuing CA, the realm
  // Intermediate and the service Root, leaf-most first. What EST /cacerts and
  // SCEP GetCACert serve and what ACME appends to a certificate chain (without
  // the Root).
  caChainOf(family) {
    const { log, pki, realms } = this.deps;
    log.debug("Entering CertEnrollment.caChainOf(). family=" + family);
    const row = pki.rawRowFor(realms.currentId());
    const issuing = row && row.issuing ? row.issuing[family] : null;
    const roots = pki.trustAnchorsFor(realms.currentId()) || [];
    if (!issuing || !row.intermediate) {
      log.debug("Leaving CertEnrollment.caChainOf(). No CA yet.");
      return { ok: false, issuingPem: '', intermediatePem: '', rootPem: '',
               chainPem: [] };
    }
    log.debug("Leaving CertEnrollment.caChainOf().");
    return { ok: true, issuingPem: issuing.certificatePem,
             intermediatePem: row.intermediate.certificatePem,
             rootPem: roots[0] || '',
             chainPem: [issuing.certificatePem, row.intermediate.certificatePem]
               .concat(roots[0] ? [roots[0]] : []) };
  }

  // Make sure the family CA exists in this realm, topping a branch up that was
  // built before the enrollment use cases did. Answers what `caChainOf()` does.
  async ensureAuthority(family) {
    const { log, pki, realms } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.ensureAuthority(). family=" + family);
    let chain = self.caChainOf(family);
    if (chain.ok) {
      log.debug("Leaving CertEnrollment.ensureAuthority(). Present.");
      return chain;
    }
    if (!pki.hasRoot()) {
      log.debug("Leaving CertEnrollment.ensureAuthority(). No Root.");
      return chain;
    }
    try {
      await pki.ensureScope(realms.currentId());
    } catch (e) {
      log.debug("Caught in CertEnrollment.ensureAuthority(): " +
                ((e && e.message) || e));
    }
    chain = self.caChainOf(family);
    log.debug("Leaving CertEnrollment.ensureAuthority(). ok=" + chain.ok);
    return chain;
  }

  // A principal for a console, API or portal session that authenticated
  // elsewhere: the console gate, the /admin-api token gate, or the portal's
  // own sign-in. `admin` asks the roster of the realm the session is in — the
  // default realm's for a session there, the realm's own otherwise.
  sessionPrincipal(username, via?, opts?) {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.sessionPrincipal().");
    const options = opts || {};
    const name = String(username || '');
    const local = name ? self.resolveEntry('person', name) : { ok: false };
    log.debug("Leaving CertEnrollment.sessionPrincipal().");
    return { kind: 'person', id: name,
             admin: options.admin === true ||
                    (options.admin !== false && self.sessionIsAdmin(name)),
             via: via, realm: realms.currentId(), hasEntry: !!local.ok };
  }

  // ---------------------------------------------------------------------------
  // WHAT A DIRECTORY DUMP OR A SEARCH SHOWS OF THE THREE SECRET ATTRIBUTE
  // FAMILIES — in EVERY mode, which is one step further than a person's signing
  // key goes. A server-generated private key, an EAB MAC key and a challenge
  // digest are read back by THIS module through the directory slot and by
  // nothing else, so withholding them from every page and every search spoils
  // no reader's view — `kerberos/krb5_person_keys.ts`'s argument for
  // `stsKrb5Keys`, made again. In development mode a private key is stored
  // UNSEALED (there is no key-encryption key that outlives the process), and a
  // dump that printed it would hand the key to anybody holding Admin Read.
  // `ldap/ldap_server.js` calls this with the LOWER-CASED names the store uses.
  // ---------------------------------------------------------------------------
  withheldValues(attribute, values) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.withheldValues().");
    const lower = String(attribute || '').toLowerCase();
    const secret = SECRET_ATTRIBUTES.some(function (one) {
      return one.toLowerCase() === lower;
    });
    if (!secret) {
      log.debug("Leaving CertEnrollment.withheldValues(). Not withheld.");
      return values;
    }
    log.debug("Leaving CertEnrollment.withheldValues().");
    return (values || []).map(function (value) {
      return '(withheld: certificate-enrollment credential, ' +
             String(value || '').length + ' characters, never shown)';
    });
  }

  // ---------------------------------------------------------------------------
  // THE TWO OWASP CONTROLS EVERY ENROLLMENT ENDPOINT SHARES.
  //
  // `transportRefusal()` — RFC 8555 section 6.1 requires HTTPS for ACME and RFC
  // 7030 section 3.2 puts EST on TLS. Product refuses a request that reached a
  // plain HTTP listener (`mode.requiresEnrollmentTls()`); development answers
  // and logs. SCEP never asks, because its messages are CMS-protected by
  // design.
  //
  // `throttled()` — the web-security window over a family's two limits, counted
  // only for a FAILURE (`websecurity.blocked()` answers without counting, and
  // `attempt()` is called after a refusal): a device fleet enrolling
  // legitimately from one NAT must not be locked out by its own successes.
  // ---------------------------------------------------------------------------
  transportRefusal(req, family) {
    const { log, mode } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.transportRefusal(). family=" + family);
    // `req.protocol` rather than a header: express computes it from the socket,
    // and honours X-Forwarded-Proto only where a proxy is TRUSTED — the request
    // worker trusts the front process (common/request_worker.ts argues why),
    // which writes the header from its OWN `req.protocol`; the main listener
    // sets no `trust proxy` at all, so there it is the socket's scheme whatever
    // `global.trustProxy` says. A header read directly would let any client
    // claim TLS.
    const encrypted = !!(req && req.socket && req.socket.encrypted) ||
      !!(req && req.protocol === 'https');
    if (encrypted) {
      log.debug("Leaving CertEnrollment.transportRefusal(). Over TLS.");
      return null;
    }
    if (!mode.requiresEnrollmentTls()) {
      log.info('enrollment: a ' + FAMILY_LABELS[family] + ' request arrived ' +
               'over plain HTTP; development mode answers it (product mode ' +
               'would refuse it, STS-ENROLL-0060).');
      log.debug("Leaving CertEnrollment.transportRefusal(). Development.");
      return null;
    }
    log.debug("Leaving CertEnrollment.transportRefusal(). Refused.");
    return self.refuse('STS-ENROLL-0060', 403, FAMILY_LABELS[family] + ' is ' +
                       'served over TLS only (RFC 8555 section 6.1, RFC 7030 ' +
                       'section 3.2), and this request did not arrive over ' +
                       'TLS.');
  }

  websecurityModule() {
    const { log, loadWebsecurity } = this.deps;
    log.debug("Entering CertEnrollment.websecurityModule().");
    log.debug("Leaving CertEnrollment.websecurityModule().");
    return loadWebsecurity();
  }

  limitsOf(family) {
    const { log, config } = this.deps;
    log.debug("Entering CertEnrollment.limitsOf().");
    log.debug("Leaving CertEnrollment.limitsOf().");
    return { identity: Number(config.value(family + '.attemptsPerIdentity')),
             address: Number(config.value(family + '.attemptsPerAddress')) };
  }

  // Is this caller over a limit right now? Counts nothing.
  throttled(family, req, identity?) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.throttled(). family=" + family);
    const ws = self.websecurityModule();
    let blocked = null;
    try {
      blocked = typeof ws.blocked === 'function'
        ? ws.blocked('enroll-' + family, req, identity || '',
                     self.limitsOf(family))
        : null;
    } catch (e) {
      log.debug("Caught in CertEnrollment.throttled(): " +
                ((e && e.message) || e));
      blocked = null;
    }
    if (blocked && blocked.ok === false) {
      log.debug("Leaving CertEnrollment.throttled(). Blocked.");
      return self.refuse('STS-ENROLL-0061', 429, 'Too many refused ' +
                         FAMILY_LABELS[family] + ' requests. Wait ' +
                         (blocked.retryAfterS || 60) + ' seconds and try ' +
                         'again.');
    }
    log.debug("Leaving CertEnrollment.throttled().");
    return null;
  }

  // The same question against ONE BUDGET FOR THE CLUSTER (2026-09-14, #46):
  // `websecurity.blockedShared()`, which is `blocked()` where no store is
  // shared. Every door in the three families asks this one; `throttled()` stays
  // for a caller that cannot wait.
  throttledShared(family, req, identity?) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.throttledShared(). family=" + family);
    const ws = self.websecurityModule();
    if (typeof ws.blockedShared !== 'function') {
      log.debug("Leaving CertEnrollment.throttledShared(). No shared limiter.");
      return Promise.resolve(self.throttled(family, req, identity));
    }
    log.debug("Leaving CertEnrollment.throttledShared().");
    return ws.blockedShared('enroll-' + family, req, identity || '',
                            self.limitsOf(family)).then(function (blocked) {
      if (blocked && blocked.ok === false) {
        return self.refuse('STS-ENROLL-0061', 429, 'Too many refused ' +
                           FAMILY_LABELS[family] + ' requests. Wait ' +
                           (blocked.retryAfterS || 60) + ' seconds and try ' +
                           'again.');
      }
      return null;
    }, function (e) {
      log.debug("Caught in CertEnrollment.throttledShared(): " +
                ((e && e.message) || e));
      return self.throttled(family, req, identity);
    });
  }

  // Count one refused request against the caller.
  //
  // **IN THE CLUSTER'S WINDOW WHEN ONE IS SHARED (#46), AND NOT AWAITED.**
  // Every caller is a refusal writer that has already decided and is sending;
  // the count is not a decision, `throttledShared()` on the NEXT request is.
  // The count is one statement and lands well before a client can come back.
  countFailure(family, req, identity?) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.countFailure(). family=" + family);
    try {
      const ws = self.websecurityModule();
      const counting = typeof ws.attemptShared === 'function'
        ? ws.attemptShared('enroll-' + family, req, identity || '',
                           self.limitsOf(family))
        : ws.attempt('enroll-' + family, req, identity || '',
                     self.limitsOf(family));
      Promise.resolve(counting).catch(function (e) {
        log.debug("Caught in CertEnrollment.countFailure(): " +
                  ((e && e.message) || e));
      });
    } catch (e) {
      log.debug("Caught in CertEnrollment.countFailure(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving CertEnrollment.countFailure().");
  }

  // ---------------------------------------------------------------------------
  // COUNT A REFUSAL AND DECIDE WHETHER IT IS STILL ANSWERED AS ONE (2026-09-14,
  // #46 follow-up). `countFailure()` above counts after the answer has been
  // chosen, and `throttledShared()` on the next request reads the count — so a
  // burst of concurrent wrong passwords, challenge passwords or bindings all
  // read a count under the limit and were all answered as refusals of the
  // credential. Where the count is SHARED (`websecurity.sharesLimits()`) a
  // refusal writer asks this instead and waits: the one atomic increment's
  // answer is the same on every node, and an increment past the limit is
  // answered with the throttle's 429 rather than with what the credential got
  // wrong — `websecurity.failedShared()` argues it. Resolves to that refusal,
  // or null. Where nothing is shared, `sharesLimits()` is false and the writers
  // keep `countFailure()`, synchronously, exactly as before.
  // ---------------------------------------------------------------------------
  countFailureShared(family, req, identity?) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.countFailureShared(). family=" + family);
    const ws = self.websecurityModule();
    if (typeof ws.failedShared !== 'function') {
      self.countFailure(family, req, identity);
      log.debug("Leaving CertEnrollment.countFailureShared(). No shared " +
                "limiter.");
      return Promise.resolve(null);
    }
    log.debug("Leaving CertEnrollment.countFailureShared().");
    return ws.failedShared('enroll-' + family, req, identity || '',
                           self.limitsOf(family)).then(function (overLimit) {
      if (!overLimit) {
        return null;
      }
      return self.refuse('STS-ENROLL-0061', 429, 'Too many refused ' +
                         FAMILY_LABELS[family] + ' requests. Wait ' +
                         (overLimit.retryAfterS || 60) + ' seconds and try ' +
                         'again.');
    }, function (e) {
      log.debug("Caught in CertEnrollment.countFailureShared(): " +
                ((e && e.message) || e));
      return null;
    });
  }

  // Whether a refusal writer should wait for `countFailureShared()`.
  sharesThrottle() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertEnrollment.sharesThrottle().");
    const ws = self.websecurityModule();
    log.debug("Leaving CertEnrollment.sharesThrottle().");
    return typeof ws.sharesLimits === 'function' && !!ws.sharesLimits();
  }

  // The retry-after of a throttled refusal, for a Retry-After header.
  retryAfterOf(refusal) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.retryAfterOf().");
    const match = /Wait (\d+) seconds/.exec(String((refusal && refusal.why) ||
                                                   ''));
    log.debug("Leaving CertEnrollment.retryAfterOf().");
    return match ? Number(match[1]) : 60;
  }

  // The two halves of `changeHostName()` the pages and the API call by name.
  addHostName(entry, name, by?) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.addHostName().");
    log.debug("Leaving CertEnrollment.addHostName().");
    return this.changeHostName(entry, name, true, by);
  }

  removeHostName(entry, name, by?) {
    const { log } = this.deps;
    log.debug("Entering CertEnrollment.removeHostName().");
    log.debug("Leaving CertEnrollment.removeHostName().");
    return this.changeHostName(entry, name, false, by);
  }

  // DECLARED AT REQUIRE TIME, for `cluster/cluster.js`'s reason. The row is
  // four fixes and this file holds two of them; the other two are the ACME
  // Replay-Nonce and finalize claims in `acme/acme.ts` (through
  // `acme/acme_store.ts`) and the SPIFFE join token claim in
  // `spiffe/spiffe_api.ts`. The row names this file because the capability is
  // "an enrollment credential is spent once", and this is where they live.
  provideCapability(): void {
    const { log, capabilities } = this.deps;
    log.debug("Entering CertEnrollment.provideCapability().");
    capabilities.provide('enrollment.credentials-once');
    log.debug("Leaving CertEnrollment.provideCapability().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<CertEnrollment>(
  'common/cert_enrollment',
  () => new CertEnrollment(CertEnrollment.defaultDeps()),
  CertEnrollment.wire,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  CertEnrollment: CertEnrollment,
  installInstance: (instance: CertEnrollment): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  FAMILIES: CertEnrollment.FAMILIES,
  withheldValues: slot.forward('withheldValues'),
  transportRefusal: slot.forward('transportRefusal'),
  throttled: slot.forward('throttled'),
  throttledShared: slot.forward('throttledShared'),
  countFailure: slot.forward('countFailure'),
  countFailureShared: slot.forward('countFailureShared'),
  sharesThrottle: slot.forward('sharesThrottle'),
  retryAfterOf: slot.forward('retryAfterOf'),
  keyAlgName: slot.forward('keyAlgName'),
  FAMILY_LABELS: CertEnrollment.FAMILY_LABELS,
  PROFILE_IDS: CertEnrollment.PROFILE_IDS,
  REFUSED_PROFILES: CertEnrollment.REFUSED_PROFILES,
  PROFILE_NEEDS: CertEnrollment.PROFILE_NEEDS,
  ATTRIBUTES: CertEnrollment.ATTRIBUTES,
  SECRET_ATTRIBUTES: CertEnrollment.SECRET_ATTRIBUTES,
  URN_PREFIX: CertEnrollment.URN_PREFIX,
  MAX_CREDENTIALS_PER_ENTRY: CertEnrollment.MAX_CREDENTIALS_PER_ENTRY,
  setDirectory: slot.forward('setDirectory'),
  hasDirectory: slot.forward('hasDirectory'),
  refuse: slot.forward('refuse'),
  isFamily: slot.forward('isFamily'),
  isKind: slot.forward('isKind'),
  wellFormedId: slot.forward('wellFormedId'),
  entryUri: slot.forward('entryUri'),
  organisationOf: slot.forward('organisationOf'),
  entryFromUri: slot.forward('entryFromUri'),
  entryLabel: slot.forward('entryLabel'),
  resolveEntry: slot.forward('resolveEntry'),
  normalHostName: slot.forward('normalHostName'),
  normalSerial: slot.forward('normalSerial'),
  adminFor: slot.forward('adminFor'),
  sessionIsAdmin: slot.forward('sessionIsAdmin'),
  sessionPrincipal: slot.forward('sessionPrincipal'),
  authenticatePerson: slot.forward('authenticatePerson'),
  authenticateApplication: slot.forward('authenticateApplication'),
  authenticateCertificate: slot.forward('authenticateCertificate'),
  authenticatePresentedCertificate:
    slot.forward('authenticatePresentedCertificate'),
  authorizeTarget: slot.forward('authorizeTarget'),
  allowedProfiles: slot.forward('allowedProfiles'),
  checkProfile: slot.forward('checkProfile'),
  defaultProfile: slot.forward('defaultProfile'),
  profileForIdentifiers: slot.forward('profileForIdentifiers'),
  parseCsr: slot.forward('parseCsr'),
  targetFromRequest: slot.forward('targetFromRequest'),
  namesFor: slot.forward('namesFor'),
  issue: slot.forward('issue'),
  issueWithServerKey: slot.forward('issueWithServerKey'),
  enrolledOf: slot.forward('enrolledOf'),
  findEnrolled: slot.forward('findEnrolled'),
  revokeEnrolled: slot.forward('revokeEnrolled'),
  serverKeyOf: slot.forward('serverKeyOf'),
  createEab: slot.forward('createEab'),
  findEab: slot.forward('findEab'),
  bindEab: slot.forward('bindEab'),
  bindEabOnce: slot.forward('bindEabOnce'),
  deleteEab: slot.forward('deleteEab'),
  eabsOf: slot.forward('eabsOf'),
  createScepChallenge: slot.forward('createScepChallenge'),
  redeemScepChallenge: slot.forward('redeemScepChallenge'),
  redeemScepChallengeOnce: slot.forward('redeemScepChallengeOnce'),
  deleteScepChallenge: slot.forward('deleteScepChallenge'),
  scepChallengesOf: slot.forward('scepChallengesOf'),
  hostNamesOf: slot.forward('hostNamesOf'),
  addHostName: slot.forward('addHostName'),
  removeHostName: slot.forward('removeHostName'),
  certificatesInRealm: slot.forward('certificatesInRealm'),
  eabsInRealm: slot.forward('eabsInRealm'),
  challengesInRealm: slot.forward('challengesInRealm'),
  hostNamesInRealm: slot.forward('hostNamesInRealm'),
  authorityOf: slot.forward('authorityOf'),
  caChainOf: slot.forward('caChainOf'),
  ensureAuthority: slot.forward('ensureAuthority'),
  derToPem: slot.forward('derToPem')
};
