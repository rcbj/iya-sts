// @ts-check
'use strict';
//
// common/cert_enrollment.js — WHO MAY BE ISSUED A CERTIFICATE FOR WHOM, AND
// WHAT GOES IN IT (2026-09-13).
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
// requires `common/pki.js`, `common/credentials.js`,
// `common/applications.js`, `admin-ui/admin_rbac.js`, `oauth-oidc/mtls.js`
// and `cluster/cluster_claims.js` / `cluster_capabilities.js`, all
// libraries.

const nodeCrypto = require('crypto');
const net = require('net');
const asn1js = require('asn1js');
const pkijs = require('pkijs');

const { log } = require('./helpers');
const helpers = require('./helpers');
const applications = require('./applications');
const audit = require('./audit');
const config = require('./config');
const credentials = require('./credentials');
const errorCodes = require('./error_codes');
const keyMaterial = require('./vendored/key_material');
const keystore = require('./keystore');
const mode = require('./mode');
const pki = require('./pki');
const realms = require('./realms');
const x509 = require('./vendored/x509');
const adminRbac = require('../admin-ui/admin_rbac');
const mtls = require('../oauth-oidc/mtls');
// SEVERAL NODES AGAINST ONE STORE (2026-09-14, #46 section 2): the atomic
// "once" the two entry-bound credentials below are spent through, and the
// capability table this file declares its row in. Both LIBRARIES that reach
// `persistence.js` lazily, so neither can close a cycle from here.
const claims = require('../cluster/cluster_claims');
const capabilities = require('../cluster/cluster_capabilities');

const FAMILIES = ['acme', 'est', 'scep'];

const FAMILY_LABELS = { acme: 'ACME', est: 'EST', scep: 'SCEP' };

// ---------------------------------------------------------------------------
// THE PROFILES.
//
// **NINE ARE ISSUED AND FIVE ARE NOT, AND THE FIVE ARE A DECISION rcbj MADE
// RATHER THAN A GAP.** /admin/pki offers fourteen because an OPERATOR sitting
// at that page is the authority; an enrollment protocol hands a certificate to
// whoever holds a credential, and for five profiles holding the certificate is
// holding a power over everybody else in the realm. The `why` of each is drawn
// on every protocol page and returned by every refusal.
// ---------------------------------------------------------------------------
const PROFILE_IDS = ['tls-server', 'tls-client', 'tls-server-client',
                     'digital-signature', 'key-encipherment', 'code-signing',
                     'email', 'timestamping', 'smartcard-logon'];

const REFUSED_PROFILES = [
  { id: 'root-ca',
    why: 'A Root CA is a trust anchor. Its holder could issue a certificate ' +
         'for anybody and be believed by everything that trusts this ' +
         'service\'s Root — and it is self-signed, so it would not even ' +
         'chain to this authority.' },
  { id: 'intermediate-ca',
    why: 'An Intermediate CA may sign further CAs. Its holder could build a ' +
         'branch of this hierarchy nobody operates.' },
  { id: 'issuing-ca',
    why: 'An Issuing CA signs certificates. Its holder could issue a ' +
         'certificate naming any person or application in the realm, which ' +
         'is exactly the rule this whole module exists to enforce.' },
  { id: 'ocsp-responder',
    why: 'An OCSP Responder certificate issued by this realm\'s CA is a ' +
         'DELEGATED responder (RFC 6960 section 4.2.2.2): its holder could ' +
         'sign "good" about a certificate this service revoked, and a ' +
         'relying party would believe it.' },
  { id: 'kdc',
    why: 'A Kerberos KDC certificate lets its holder answer PKINIT as the ' +
         'realm\'s KDC and impersonate it to every client that trusts this ' +
         'authority.' }
];

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

let directory = null;

// ---------------------------------------------------------------------------
// A REFUSAL. Every one carries the HTTP status a protocol module should send
// and an STS code; the sentence is for an operator reading a console reply or a
// problem document's `detail`, and never contains a secret.
// ---------------------------------------------------------------------------
function refuse(code, status, sentence) {
  log.debug("Entering refuse(). code=" + code);
  log.debug("Leaving refuse().");
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
// Validated whole, for `setLogoutReader()`'s reason: half a store is a register
// that can issue a credential it cannot find again.
// ---------------------------------------------------------------------------
function setDirectory(store) {
  log.debug("Entering setDirectory().");
  const given = store || {};
  const missing = ['read', 'write', 'holders'].filter(function (name) {
    return typeof given[name] !== 'function';
  });
  if (missing.length) {
    log.debug("Leaving setDirectory(). Incomplete.");
    throw new Error('cert_enrollment.setDirectory() needs read, write and ' +
                    'holders; missing ' + missing.join(', ') + '.');
  }
  directory = given;
  log.debug("Leaving setDirectory().");
}

function hasDirectory() {
  log.debug("Entering hasDirectory().");
  log.debug("Leaving hasDirectory().");
  return !!directory;
}

// ---------------------------------------------------------------------------
// SHAPES.
// ---------------------------------------------------------------------------
function isFamily(family) {
  log.debug("Entering isFamily().");
  log.debug("Leaving isFamily().");
  return FAMILIES.indexOf(String(family)) >= 0;
}

function isKind(kind) {
  log.debug("Entering isKind().");
  log.debug("Leaving isKind().");
  return kind === 'person' || kind === 'application';
}

// An identifier as a directory holds one: printable, bounded, no control
// characters. The same bar `common/validation.js` sets on a name, applied here
// as well because this module is also reached from credential kids that were
// decoded from base64url and never passed a schema.
function wellFormedId(id) {
  log.debug("Entering wellFormedId().");
  const text = String(id == null ? '' : id);
  log.debug("Leaving wellFormedId().");
  return text.length >= 1 && text.length <= 256 &&
         !/[\u0000-\u001f\u007f]/.test(text);
}

function entryUri(entry) {
  log.debug("Entering entryUri().");
  log.debug("Leaving entryUri().");
  return URN_PREFIX[entry.kind] + entry.id;
}

function entryFromUri(uri) {
  log.debug("Entering entryFromUri().");
  const text = String(uri || '');
  let found = null;
  Object.keys(URN_PREFIX).forEach(function (kind) {
    if (!found && text.indexOf(URN_PREFIX[kind]) === 0) {
      const id = text.slice(URN_PREFIX[kind].length);
      if (wellFormedId(id)) {
        found = { kind: kind, id: id };
      }
    }
  });
  log.debug("Leaving entryFromUri().");
  return found;
}

function entryLabel(entry) {
  log.debug("Entering entryLabel().");
  log.debug("Leaving entryLabel().");
  return (entry.kind === 'person' ? 'person' : 'application') + ' "' +
         entry.id + '"';
}

function sameEntry(a, b) {
  log.debug("Entering sameEntry().");
  log.debug("Leaving sameEntry().");
  return !!(a && b && a.kind === b.kind && String(a.id) === String(b.id));
}

// ---------------------------------------------------------------------------
// THE ENTRY.
// ---------------------------------------------------------------------------
function resolveEntry(kind, id) {
  log.debug("Entering resolveEntry(). kind=" + kind + " id=" + id);
  if (!isKind(kind) || !wellFormedId(id)) {
    log.debug("Leaving resolveEntry(). Malformed.");
    return refuse('STS-ENROLL-0010', 400, 'A certificate is issued for a ' +
                  'person or an application, named by a printable ' +
                  'identifier of at most 256 characters.');
  }
  if (!directory) {
    log.debug("Leaving resolveEntry(). No directory.");
    return refuse('STS-ENROLL-0011', 503, 'No directory is loaded in this ' +
                  'process, so there is no entry a certificate could be ' +
                  'issued for or kept on.');
  }
  let found = null;
  try {
    found = directory.read(kind, String(id), READ_NAMES[kind]);
  } catch (e) {
    log.debug("Caught in resolveEntry(): " + ((e && e.message) || e));
    found = null;
  }
  if (!found) {
    log.debug("Leaving resolveEntry(). No such entry.");
    return refuse('STS-ENROLL-0012', 404, 'There is no ' +
                  entryLabel({ kind: kind, id: id }) + ' in this realm. A ' +
                  'certificate issued over an enrollment protocol always ' +
                  'names an entry that exists, and is kept on it.');
  }
  const attrs = found.attributes || {};
  const first = function (name) {
    return (attrs[name] && attrs[name].length) ? String(attrs[name][0]) : '';
  };
  const names = ATTRIBUTES[kind];
  log.debug("Leaving resolveEntry(). " + found.dn);
  return {
    ok: true,
    entry: { kind: kind, id: String(id) },
    dn: found.dn,
    mail: kind === 'person' ? first('mail') : '',
    upn: kind === 'person' ? first('userPrincipalName') : '',
    hostNames: (attrs[names.hostName] || []).map(function (one) {
      return normalHostName(one);
    }).filter(function (one) { return !!one; }),
    attributes: attrs
  };
}

function normalHostName(value) {
  log.debug("Entering normalHostName().");
  let text = String(value == null ? '' : value).trim().toLowerCase();
  if (net.isIP(text)) {
    log.debug("Leaving normalHostName(). An address.");
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
  log.debug("Leaving normalHostName().");
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
// administrator elsewhere, so each roster is consulted only after the password
// verified against the entry in THAT roster's realm. An empty roster (`open`)
// grants nothing here, as it grants nothing on the LDAP socket: "everybody is
// an administrator because nobody is" is a bootstrap for the console and not a
// reason to issue certificates in anybody's name.
async function adminFor(username, password, via) {
  log.debug("Entering adminFor(). username=" + username);
  const name = String(username || '');
  if (!name) {
    log.debug("Leaving adminFor(). No name.");
    return false;
  }
  /** @type {any} */
  let verified = false;
  try {
    verified = await realms.run(realms.get(realms.DEFAULT_ID), function () {
      return credentials.verifyAsync(name, String(password || ''),
                                     { via: via });
    });
  } catch (e) {
    log.debug("Caught in adminFor(): " + ((e && e.message) || e));
    verified = false;
  }
  let roles = null;
  if (verified && verified.ok) {
    try {
      roles = adminRbac.rolesOf(name, realms.DEFAULT_ID);
    } catch (e) {
      log.debug("Caught in adminFor(): " + ((e && e.message) || e));
      roles = null;
    }
  }
  if (roles && roles.write === true && roles.open !== true) {
    log.debug("Leaving adminFor(). A service administrator.");
    return true;
  }
  // A REALM'S OWN ADMINISTRATOR (2026-09-14, #32): the same two questions
  // asked of the AMBIENT realm — the password against that realm's entry, then
  // that realm's roster. Its authority is that realm's, and so is every target
  // an enrollment here can name.
  const here = realms.currentId();
  if (here === realms.DEFAULT_ID) {
    log.debug("Leaving adminFor(). Not an administrator.");
    return false;
  }
  let local = null;
  try {
    local = await credentials.verifyAsync(name, String(password || ''),
                                          { via: via });
  } catch (e) {
    log.debug("Caught in adminFor(): " + ((e && e.message) || e));
    local = null;
  }
  let realmRoles = null;
  if (local && local.ok) {
    try {
      realmRoles = adminRbac.rolesOf(name, here);
    } catch (e) {
      log.debug("Caught in adminFor(): " + ((e && e.message) || e));
      realmRoles = null;
    }
  }
  const admin = !!(realmRoles && realmRoles.write === true &&
                   realmRoles.open !== true);
  log.debug("Leaving adminFor(). realm admin=" + admin);
  return admin;
}

// The same roster question for a principal a console or portal session has
// ALREADY authenticated — the console gate verified the sign-in, so asking for
// the password again would be asking for something the caller does not have.
//
// **THE ROSTER IS THE AMBIENT REALM'S** (2026-09-14, #32): a portal session is
// the person of the realm it was signed in through, so it is that realm's
// roster that says whether they administer it — the default realm's in the
// default realm, a realm's own anywhere else. Asking the default realm's by
// name from inside a realm was the collision `adminFor()` describes.
function sessionIsAdmin(username) {
  log.debug("Entering sessionIsAdmin().");
  let roles = null;
  try {
    roles = adminRbac.rolesOf(String(username || ''), realms.currentId());
  } catch (e) {
    log.debug("Caught in sessionIsAdmin(): " + ((e && e.message) || e));
    roles = null;
  }
  log.debug("Leaving sessionIsAdmin().");
  return !!(roles && roles.write === true && roles.open !== true);
}

async function authenticatePerson(username, password, via) {
  log.debug("Entering authenticatePerson(). username=" + username);
  const name = String(username || '');
  if (!wellFormedId(name)) {
    log.debug("Leaving authenticatePerson(). Malformed.");
    return refuse('STS-ENROLL-0013', 401, 'A username is required.');
  }
  const local = resolveEntry('person', name);
  let verified = null;
  if (local.ok) {
    try {
      verified = await credentials.verifyAsync(name, String(password || ''),
                                               { via: via });
    } catch (e) {
      log.debug("Caught in authenticatePerson(): " + ((e && e.message) || e));
      verified = null;
    }
  }
  const admin = await adminFor(name, password, via);
  if (local.ok && verified && verified.ok) {
    log.debug("Leaving authenticatePerson(). Verified here.");
    return { ok: true, principal: { kind: 'person', id: name, admin: admin,
                                    via: via, realm: realms.currentId(),
                                    hasEntry: true } };
  }
  if (admin) {
    // An administrator of the SERVICE with no entry of this name in this
    // realm, or whose entry here has a different password. They may issue for
    // an entry the request names and for nobody as themselves.
    log.debug("Leaving authenticatePerson(). An administrator only.");
    return { ok: true, principal: { kind: 'person', id: name, admin: true,
                                    via: via, realm: realms.currentId(),
                                    hasEntry: false } };
  }
  log.debug("Leaving authenticatePerson(). Refused.");
  return refuse(local.ok ? 'STS-ENROLL-0014' : 'STS-ENROLL-0015', 401,
                local.ok
                  ? 'The password was not accepted.'
                  : 'The password was not accepted.');
}

function secretsEqual(presented, expected) {
  log.debug("Entering secretsEqual().");
  const a = nodeCrypto.createHash('sha256').update(String(presented || ''))
    .digest();
  const b = nodeCrypto.createHash('sha256').update(String(expected || ''))
    .digest();
  log.debug("Leaving secretsEqual().");
  return nodeCrypto.timingSafeEqual(a, b) && !!expected;
}

async function authenticateApplication(clientId, secret, via) {
  log.debug("Entering authenticateApplication(). clientId=" + clientId);
  const id = String(clientId || '');
  if (!wellFormedId(id)) {
    log.debug("Leaving authenticateApplication(). Malformed.");
    return refuse('STS-ENROLL-0013', 401, 'A client_id is required.');
  }
  let view = null;
  try {
    view = applications.forClientId(id) || applications.get(id);
  } catch (e) {
    log.debug("Caught in authenticateApplication(): " +
              ((e && e.message) || e));
    view = null;
  }
  if (!view || !view.identifier) {
    log.debug("Leaving authenticateApplication(). Unknown.");
    return refuse('STS-ENROLL-0016', 401, 'The client credentials were not ' +
                  'accepted.');
  }
  const cfg = /** @type {any} */ (
    applications.clientConfigOf(view.identifier) || {});
  const expected = String(cfg.client_secret || '');
  if (mode.requiresClientSecret()) {
    if (!expected || !secretsEqual(secret, expected)) {
      log.debug("Leaving authenticateApplication(). Secret refused.");
      return refuse('STS-ENROLL-0016', 401, 'The client credentials were ' +
                    'not accepted.');
    }
  }
  const entry = resolveEntry('application', view.identifier);
  if (!entry.ok) {
    log.debug("Leaving authenticateApplication(). No entry.");
    return entry;
  }
  log.debug("Leaving authenticateApplication(). Accepted.");
  return { ok: true, principal: { kind: 'application',
                                  id: String(view.identifier), admin: false,
                                  via: via, realm: realms.currentId(),
                                  hasEntry: true } };
}

// ---------------------------------------------------------------------------
// A TLS CLIENT CERTIFICATE AS THE CREDENTIAL (EST re-enrollment).
//
// Three checks, and all three are real in both modes:
//   1. the certificate verifies to THIS REALM's Intermediate and the service
//      Root, with revocation consulted (`pki.verifyLeaf()`), so a certificate
//      from another realm — perfectly valid there — is refused here;
//   2. it certifies `clientAuth`;
//   3. its urn:sts: subjectAltName names an entry that exists AND carries this
//      certificate's serial among its enrolled certificates, unrevoked. That
//      last clause is what "every certificate maps to an entry" buys: a
//      certificate the entry does not list is not that entry's credential.
// ---------------------------------------------------------------------------
async function authenticateCertificate(req, via) {
  log.debug("Entering authenticateCertificate().");
  const presented = mtls.peerCertificate(req);
  if (!presented || !presented.raw) {
    log.debug("Leaving authenticateCertificate(). None presented.");
    return refuse('STS-ENROLL-0017', 401, 'No TLS client certificate was ' +
                  'presented.');
  }
  const pem = '-----BEGIN CERTIFICATE-----\n' +
    Buffer.from(presented.raw).toString('base64').replace(/(.{64})/g, '$1\n')
      .replace(/\n$/, '') +
    '\n-----END CERTIFICATE-----\n';
  const answer = await authenticatePresentedCertificate(pem, via,
                                                        { clientAuth: true });
  log.debug("Leaving authenticateCertificate(). ok=" + !!answer.ok);
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
async function authenticatePresentedCertificate(pem, via, options) {
  log.debug("Entering authenticatePresentedCertificate().");
  const opts = options || {};
  const verified = await pki.verifyLeaf(realms.currentId(), pem, []);
  if (!verified.ok) {
    log.debug("Leaving authenticatePresentedCertificate(). Path refused.");
    return refuse('STS-ENROLL-0018', 401, 'The client certificate does not ' +
                  'verify to this realm\'s certificate authority: ' +
                  verified.why);
  }
  let cert = null;
  try {
    cert = new nodeCrypto.X509Certificate(pem);
  } catch (e) {
    log.debug("Caught in authenticatePresentedCertificate(): " +
              ((e && e.message) || e));
    cert = null;
  }
  const ekus = (cert && cert.keyUsage) || [];
  if (opts.clientAuth !== false &&
      ekus.indexOf(x509.EKU_OIDS.clientAuth) < 0) {
    log.debug("Leaving authenticatePresentedCertificate(). No clientAuth.");
    return refuse('STS-ENROLL-0019', 401, 'The client certificate does not ' +
                  'certify TLS client authentication (clientAuth).');
  }
  const uris = String((cert && cert.subjectAltName) || '').split(/,\s*/)
    .filter(function (one) { return one.indexOf('URI:') === 0; })
    .map(function (one) { return one.slice(4); });
  const named = uris.map(entryFromUri).filter(function (one) {
    return !!one;
  });
  if (named.length !== 1) {
    log.debug("Leaving authenticatePresentedCertificate(). No entry.");
    return refuse('STS-ENROLL-0019', 401, 'The client certificate names no ' +
                  'single person or application of this realm.');
  }
  const serialHex = normalSerial(cert.serialNumber);
  const held = enrolledOf(named[0]).filter(function (one) {
    return normalSerial(one.serialHex) === serialHex;
  })[0];
  if (!held || held.revoked) {
    log.debug("Leaving authenticatePresentedCertificate(). Not held.");
    return refuse('STS-ENROLL-0019', 401, 'The client certificate is not ' +
                  'one the ' + entryLabel(named[0]) + ' holds.');
  }
  log.debug("Leaving authenticatePresentedCertificate(). " +
            entryLabel(named[0]));
  return { ok: true,
           principal: { kind: named[0].kind, id: named[0].id, admin: false,
                        via: via, realm: realms.currentId(), hasEntry: true,
                        certificateSerial: serialHex,
                        certificateFamily: held.family } };
}

// ---------------------------------------------------------------------------
// THE IDENTITY RULE. The one sentence of rcbj's this file most exists to keep:
// "Any of the users can only issue key pairs that map to their authenticated
// user identity", and "an admin user can request one that maps to any user
// object in the current realm".
// ---------------------------------------------------------------------------
function authorizeTarget(principal, target) {
  log.debug("Entering authorizeTarget().");
  if (!principal || !isKind(principal.kind) || !target ||
      !isKind(target.kind)) {
    log.debug("Leaving authorizeTarget(). Malformed.");
    return refuse('STS-ENROLL-0020', 403, 'Nobody authenticated, or nobody ' +
                  'was named.');
  }
  if (sameEntry(principal, target) && principal.hasEntry !== false) {
    log.debug("Leaving authorizeTarget(). Self.");
    return { ok: true, self: true };
  }
  if (principal.kind === 'person' && principal.admin === true) {
    log.debug("Leaving authorizeTarget(). An administrator.");
    return { ok: true, self: false, admin: true };
  }
  log.debug("Leaving authorizeTarget(). Refused.");
  return refuse('STS-ENROLL-0021', 403, 'A certificate may be issued only ' +
                'for the entry that authenticated — the ' +
                entryLabel(principal) + ' — and this request is for the ' +
                entryLabel(target) + '. Only a holder of Admin Write may ' +
                'request a certificate for somebody else.');
}

// ---------------------------------------------------------------------------
// PROFILES AGAINST SETTINGS.
// ---------------------------------------------------------------------------
function allowedProfiles(family) {
  log.debug("Entering allowedProfiles(). family=" + family);
  const raw = config.value(family + '.allowedProfiles');
  const listed = (Array.isArray(raw) ? raw : String(raw || '').split(','))
    .map(function (one) { return String(one).trim(); })
    .filter(function (one) { return PROFILE_IDS.indexOf(one) >= 0; });
  log.debug("Leaving allowedProfiles().");
  return PROFILE_IDS.filter(function (one) {
    return listed.indexOf(one) >= 0;
  });
}

function checkProfile(family, profileId) {
  log.debug("Entering checkProfile(). profile=" + profileId);
  const id = String(profileId || '');
  const refused = REFUSED_PROFILES.filter(function (one) {
    return one.id === id;
  })[0];
  if (refused) {
    log.debug("Leaving checkProfile(). Refused by design.");
    return refuse('STS-ENROLL-0002', 403, 'The "' + id + '" profile is ' +
                  'never issued over an enrollment protocol. ' + refused.why);
  }
  if (PROFILE_IDS.indexOf(id) < 0) {
    log.debug("Leaving checkProfile(). Unknown.");
    return refuse('STS-ENROLL-0001', 400, '"' + id + '" is not a ' +
                  'certificate profile. The ' + PROFILE_IDS.length + ' ' +
                  'issued over ' + FAMILY_LABELS[family] + ' are: ' +
                  PROFILE_IDS.join(', ') + '.');
  }
  if (allowedProfiles(family).indexOf(id) < 0) {
    log.debug("Leaving checkProfile(). Not allowed here.");
    return refuse('STS-ENROLL-0003', 403, 'The "' + id + '" profile is not ' +
                  'in ' + family + '.allowedProfiles in this realm.');
  }
  log.debug("Leaving checkProfile(). Allowed.");
  return { ok: true, profile: id };
}

function defaultProfile(family) {
  log.debug("Entering defaultProfile().");
  log.debug("Leaving defaultProfile().");
  return String(config.value(family + '.defaultProfile') || 'tls-client');
}

// ---------------------------------------------------------------------------
// PKCS#10.
//
// **THE PROOF OF POSSESSION IS VERIFIED, WHICH IS MORE THAN THIS SERVICE HAS
// DONE WITH A CSR BEFORE.** SPIFFE's `signCsr()` reads only the SPKI, and says
// so, because SPIRE's own server does the same. An enrollment protocol is
// different: the CSR is the ONLY thing binding the key to the request, and an
// unverified one lets somebody enroll a public key they do not hold — then
// present somebody else's certificate as their own. So the signature is
// checked with the request's own key, for every algorithm the vendored encoder
// can make: RSA and ECDSA through pkijs, Ed25519 through Web Crypto (pkijs
// cannot read an Ed25519 SPKI), and the post-quantum and composite families
// through `x509.verifyBytes()`.
//
// A KEY-ENCAPSULATION key cannot sign, so it cannot make that proof at all —
// RFC 9935 section 7 says the same — and is refused unless the caller says the
// CSR is only a TEMPLATE (EST /serverkeygen, where the key is this service's).
// ---------------------------------------------------------------------------
function derToPem(der, label) {
  log.debug("Entering derToPem().");
  log.debug("Leaving derToPem().");
  return '-----BEGIN ' + label + '-----\n' +
    Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n')
      .replace(/\n$/, '') +
    '\n-----END ' + label + '-----\n';
}

function asArrayBuffer(bytes) {
  log.debug("Entering asArrayBuffer().");
  const buf = Buffer.from(bytes);
  log.debug("Leaving asArrayBuffer().");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function stringOfAsn1(value) {
  log.debug("Entering stringOfAsn1().");
  if (!value || !value.valueBlock) {
    log.debug("Leaving stringOfAsn1().");
    return '';
  }
  log.debug("Leaving stringOfAsn1().");
  return String(value.valueBlock.value !== undefined
    ? value.valueBlock.value : '');
}

async function parseCsr(bytes, options) {
  log.debug("Entering parseCsr().");
  const opts = options || {};
  const der = Buffer.from(bytes || []);
  if (!der.length) {
    log.debug("Leaving parseCsr(). Empty.");
    return refuse('STS-ENROLL-0030', 400, 'The certificate request is empty.');
  }
  let csr = null;
  try {
    const asn1 = asn1js.fromBER(asArrayBuffer(der));
    if (asn1.offset === -1 || asn1.offset !== der.length) {
      throw new Error('not one complete DER value');
    }
    csr = new pkijs.CertificationRequest({ schema: asn1.result });
  } catch (e) {
    log.debug("Caught in parseCsr(): " + ((e && e.message) || e));
    log.debug("Leaving parseCsr(). Unreadable.");
    return refuse('STS-ENROLL-0030', 400, 'The certificate request is not a ' +
                  'readable PKCS#10 CertificationRequest.');
  }
  let spkiPem = '';
  let desc = null;
  try {
    spkiPem = derToPem(csr.subjectPublicKeyInfo.toSchema().toBER(false),
                       'PUBLIC KEY');
    desc = await keyMaterial.describePublicPem(spkiPem);
  } catch (e) {
    log.debug("Caught in parseCsr(): " + ((e && e.message) || e));
    desc = null;
  }
  if (!desc) {
    log.debug("Leaving parseCsr(). Unsupported key.");
    return refuse('STS-ENROLL-0031', 400, 'The public key in the request is ' +
                  'not one this certificate authority can certify.');
  }
  const kem = desc.kind === 'pqc' && desc.use && desc.use !== 'sig';
  if (kem && !opts.template) {
    log.debug("Leaving parseCsr(). A KEM key.");
    return refuse('STS-ENROLL-0032', 400, 'The request carries a ' +
                  String(desc.pqc || 'key-encapsulation') + ' key, which ' +
                  'cannot sign and so cannot prove possession (RFC 9935 ' +
                  'section 7). Ask EST /serverkeygen for one instead.');
  }
  if (!kem) {
    const proven = await proofOfPossession(csr, spkiPem, desc);
    if (!proven) {
      log.debug("Leaving parseCsr(). The signature does not verify.");
      return refuse('STS-ENROLL-0033', 400, 'The certificate request\'s ' +
                    'signature does not verify with the public key it ' +
                    'carries, so it does not prove possession of that key.');
    }
  }
  const out = {
    ok: true,
    der: der,
    publicKeyPem: spkiPem,
    keyAlg: keyAlgName(desc),
    keyKind: desc.kind,
    subject: '',
    commonName: '',
    challengePassword: '',
    // The TYPE of every attribute the request carries, and nothing of their
    // values (2026-09-13, for EST). RFC 7030 section 4.4.1.2 lets a
    // /serverkeygen template ask for the private key to be encrypted by
    // naming a DecryptKeyIdentifier or AsymmetricDecryptKeyIdentifier
    // attribute, and a server that does not do that MUST refuse the request
    // rather than hand the key back in the clear. Only the types are needed to
    // decide, and exposing them here keeps EST from reading the CSR itself.
    attributeTypes: [],
    requested: { uris: [], dns: [], ips: [], emails: [], upns: [] }
  };
  try {
    out.subject = csr.subject.typesAndValues.map(function (tv) {
      return tv.type + '=' + stringOfAsn1(tv.value);
    }).join(',');
    csr.subject.typesAndValues.forEach(function (tv) {
      if (tv.type === '2.5.4.3' && !out.commonName) {
        out.commonName = stringOfAsn1(tv.value);
      }
    });
    (csr.attributes || []).forEach(function (attribute) {
      out.attributeTypes.push(String(attribute.type));
      if (attribute.type === '1.2.840.113549.1.9.7') {
        out.challengePassword = stringOfAsn1((attribute.values || [])[0]);
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
            readGeneralName(name, out.requested);
          });
        });
      }
    });
  } catch (e) {
    log.debug("Caught in parseCsr(): " + ((e && e.message) || e));
    log.debug("Leaving parseCsr(). Unreadable attributes.");
    return refuse('STS-ENROLL-0034', 400, 'The certificate request\'s ' +
                  'subject or requested extensions could not be read.');
  }
  log.debug("Leaving parseCsr(). key=" + out.keyAlg);
  return out;
}

// A key described by `describePublicPem()` in the vocabulary /admin/pki and
// `keyMaterial.KEY_ALGS` use — `rsa-2048`, `ec-p256`, `ed25519`, `ml-dsa-44`.
function keyAlgName(desc) {
  log.debug("Entering keyAlgName().");
  if (desc.id) {
    log.debug("Leaving keyAlgName(). Named.");
    return String(desc.id);
  }
  if (desc.kind === 'rsa') {
    log.debug("Leaving keyAlgName(). RSA.");
    return 'rsa-' + (desc.bits || 2048);
  }
  if (desc.kind === 'ec') {
    log.debug("Leaving keyAlgName(). EC.");
    return 'ec-' + String(desc.curve || 'P-256').replace('-', '').toLowerCase();
  }
  log.debug("Leaving keyAlgName().");
  return desc.kind === 'okp' ? String(desc.name || 'Ed25519').toLowerCase()
                             : String(desc.kind);
}

function readGeneralName(name, requested) {
  log.debug("Entering readGeneralName(). type=" + (name && name.type));
  if (!name) {
    log.debug("Leaving readGeneralName().");
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
    requested.ips.push(ipText(raw));
  } else if (name.type === 0) {
    const other = name.value || {};
    const id = other.type || (other.valueBlock && other.valueBlock.value &&
      other.valueBlock.value[0] && other.valueBlock.value[0].valueBlock &&
      other.valueBlock.value[0].valueBlock.toString());
    const inner = other.value || (other.valueBlock && other.valueBlock.value &&
      other.valueBlock.value[1]);
    if (String(id) === UPN_OID) {
      const text = inner && inner.valueBlock && inner.valueBlock.value &&
        inner.valueBlock.value[0] ? stringOfAsn1(inner.valueBlock.value[0])
        : stringOfAsn1(inner);
      requested.upns.push(text);
    } else {
      // An otherName this authority does not issue. Recorded as a URI the
      // entry can never own, so it refuses the request by name.
      requested.uris.push('otherName:' + String(id || 'unknown'));
    }
  } else {
    requested.uris.push('generalName:' + String(name.type));
  }
  log.debug("Leaving readGeneralName().");
}

function ipText(raw) {
  log.debug("Entering ipText().");
  if (raw.length === 4) {
    log.debug("Leaving ipText(). IPv4.");
    return Array.from(raw).join('.');
  }
  if (raw.length === 16) {
    const groups = [];
    for (let i = 0; i < 16; i += 2) {
      groups.push(raw.readUInt16BE(i).toString(16));
    }
    log.debug("Leaving ipText(). IPv6.");
    return normalHostName(groups.join(':').replace(/(^|:)0(:0)+(:|$)/,
                                                   '::'));
  }
  log.debug("Leaving ipText(). Neither.");
  return 'invalid-address';
}

async function proofOfPossession(csr, spkiPem, desc) {
  log.debug("Entering proofOfPossession(). kind=" + desc.kind);
  try {
    const tbs = csr.tbsView ? Buffer.from(csr.tbsView)
      : Buffer.from(csr.encodeTBS().toBER(false));
    const signature = Buffer.from(csr.signatureValue.valueBlock.valueHexView);
    const sig = x509.sigAlgForOid(csr.signatureAlgorithm.algorithmId);
    if (sig && sig.kind === 'pqc') {
      const ok = await x509.verifyBytes(sig, spkiPem, signature, tbs);
      log.debug("Leaving proofOfPossession(). pqc=" + ok);
      return !!ok;
    }
    if (desc.kind === 'okp') {
      const key = nodeCrypto.createPublicKey(spkiPem);
      const ok = nodeCrypto.verify(null, tbs, key, signature);
      log.debug("Leaving proofOfPossession(). Ed25519=" + ok);
      return !!ok;
    }
    const ok = await csr.verify();
    log.debug("Leaving proofOfPossession(). pkijs=" + ok);
    return !!ok;
  } catch (e) {
    log.debug("Caught in proofOfPossession(): " + ((e && e.message) || e));
    log.debug("Leaving proofOfPossession(). Threw, so not proven.");
    return false;
  }
}

// ---------------------------------------------------------------------------
// WHICH ENTRY A REQUEST IS FOR.
//
// A urn:sts: subjectAltName names it exactly. With none, a principal is asking
// for itself — except that an ADMINISTRATOR with no URN may name a person or
// application by the request's common name, which is what an EST client
// configured with a subject and nothing else sends. More than one URN naming
// different entries is refused: one certificate maps to one entry.
// ---------------------------------------------------------------------------
function targetFromRequest(requested, commonName, principal) {
  log.debug("Entering targetFromRequest().");
  const named = [];
  ((requested && requested.uris) || []).forEach(function (uri) {
    const entry = entryFromUri(uri);
    if (entry && !named.some(function (one) {
      return sameEntry(one, entry);
    })) {
      named.push(entry);
    }
  });
  if (named.length > 1) {
    log.debug("Leaving targetFromRequest(). Several.");
    return refuse('STS-ENROLL-0022', 400, 'The request names ' +
                  named.length + ' different entries. One certificate maps ' +
                  'to one person or application.');
  }
  if (named.length === 1) {
    log.debug("Leaving targetFromRequest(). Named by URN.");
    return { ok: true, target: named[0], by: 'urn' };
  }
  if (principal && principal.admin && commonName &&
      !(principal.kind === 'person' && commonName === principal.id)) {
    const person = resolveEntry('person', commonName);
    if (person.ok) {
      log.debug("Leaving targetFromRequest(). A person by CN.");
      return { ok: true, target: person.entry, by: 'common-name' };
    }
    const application = resolveEntry('application', commonName);
    if (application.ok) {
      log.debug("Leaving targetFromRequest(). An application by CN.");
      return { ok: true, target: application.entry, by: 'common-name' };
    }
  }
  if (principal && principal.hasEntry === false) {
    log.debug("Leaving targetFromRequest(). An administrator named nobody.");
    return refuse('STS-ENROLL-0023', 400, 'An administrator with no entry ' +
                  'of their own in this realm must name the entry the ' +
                  'certificate is for, in a urn:sts:person: or ' +
                  'urn:sts:application: subjectAltName or as the common ' +
                  'name.');
  }
  log.debug("Leaving targetFromRequest(). Self.");
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
function namesFor(resolved, profileId, requested) {
  log.debug("Entering namesFor(). profile=" + profileId);
  const entry = resolved.entry;
  const want = requested || {};
  const names = [{ kind: 'uri', value: entryUri(entry) }];
  const seen = {};
  const add = function (kind, value) {
    const key = kind + ':' + value;
    if (!seen[key]) {
      seen[key] = true;
      names.push({ kind: kind, value: value });
    }
  };
  seen['uri:' + entryUri(entry)] = true;
  const uris = want.uris || [];
  for (let i = 0; i < uris.length; i++) {
    if (uris[i] !== entryUri(entry)) {
      log.debug("Leaving namesFor(). A foreign URI.");
      return refuse('STS-ENROLL-0050', 403, 'The request asks for the name "' +
                    String(uris[i]).slice(0, 200) + '", which the ' +
                    entryLabel(entry) + ' does not own. Only its own ' +
                    'urn:sts: name may be requested.');
    }
  }
  let hosts = 0;
  const dns = want.dns || [];
  for (let i = 0; i < dns.length; i++) {
    const host = normalHostName(dns[i]);
    if (!host || net.isIP(host) || resolved.hostNames.indexOf(host) < 0) {
      log.debug("Leaving namesFor(). An unregistered host name.");
      return refuse('STS-ENROLL-0051', 403, 'The host name "' +
                    String(dns[i]).slice(0, 253) + '" is not registered on ' +
                    'the ' + entryLabel(entry) + '. A host name is issued ' +
                    'only when an administrator has registered it on the ' +
                    'entry; this service never proves control of a name by ' +
                    'dialling it.');
    }
    add('dns', host);
    hosts++;
  }
  const ips = want.ips || [];
  for (let i = 0; i < ips.length; i++) {
    const address = normalHostName(ips[i]);
    if (!net.isIP(address) || resolved.hostNames.indexOf(address) < 0) {
      log.debug("Leaving namesFor(). An unregistered address.");
      return refuse('STS-ENROLL-0051', 403, 'The address "' +
                    String(ips[i]).slice(0, 64) + '" is not registered on ' +
                    'the ' + entryLabel(entry) + '.');
    }
    add('ip', address);
    hosts++;
  }
  const emails = want.emails || [];
  for (let i = 0; i < emails.length; i++) {
    if (!resolved.mail ||
        String(emails[i]).toLowerCase() !== resolved.mail.toLowerCase()) {
      log.debug("Leaving namesFor(). An address the entry does not hold.");
      return refuse('STS-ENROLL-0052', 403, 'The email address "' +
                    String(emails[i]).slice(0, 254) + '" is not the mail ' +
                    'attribute of the ' + entryLabel(entry) + '.');
    }
    add('email', resolved.mail);
  }
  const upns = want.upns || [];
  for (let i = 0; i < upns.length; i++) {
    const owned = [resolved.upn, resolved.mail].filter(function (one) {
      return !!one;
    }).map(function (one) { return one.toLowerCase(); });
    if (owned.indexOf(String(upns[i]).toLowerCase()) < 0) {
      log.debug("Leaving namesFor(). A UPN the entry does not hold.");
      return refuse('STS-ENROLL-0053', 403, 'The user principal name "' +
                    String(upns[i]).slice(0, 254) + '" is neither the ' +
                    'userPrincipalName nor the mail of the ' +
                    entryLabel(entry) + '.');
    }
    add('upn', String(upns[i]));
  }
  if ((profileId === 'tls-server' || profileId === 'tls-server-client') &&
      !hosts) {
    log.debug("Leaving namesFor(). A server certificate naming no host.");
    return refuse('STS-ENROLL-0054', 400, 'A ' + profileId + ' certificate ' +
                  'names at least one host, and the request names none. ' +
                  (resolved.hostNames.length
                    ? 'The ' + entryLabel(entry) + ' has ' +
                      resolved.hostNames.length + ' registered.'
                    : 'The ' + entryLabel(entry) + ' has none registered.'));
  }
  if (profileId === 'email' && !emails.length) {
    if (!resolved.mail) {
      log.debug("Leaving namesFor(). S/MIME with no mail.");
      return refuse('STS-ENROLL-0055', 400, 'An S/MIME certificate carries ' +
                    'the holder\'s email address, and the ' +
                    entryLabel(entry) + ' has no mail attribute.');
    }
    add('email', resolved.mail);
  }
  if (profileId === 'smartcard-logon' && !upns.length) {
    const upn = resolved.upn || resolved.mail;
    if (!upn) {
      log.debug("Leaving namesFor(). Smartcard logon with no UPN.");
      return refuse('STS-ENROLL-0056', 400, 'A smartcard logon certificate ' +
                    'carries a user principal name, and the ' +
                    entryLabel(entry) + ' has neither userPrincipalName nor ' +
                    'mail.');
    }
    add('upn', upn);
  }
  log.debug("Leaving namesFor(). " + names.length + " name(s).");
  return { ok: true, names: names };
}

function organisationOf() {
  log.debug("Entering organisationOf().");
  let row = null;
  try {
    row = pki.rawRowFor(realms.currentId());
  } catch (e) {
    log.debug("Caught in organisationOf(): " + ((e && e.message) || e));
    row = null;
  }
  log.debug("Leaving organisationOf().");
  return {
    organisation: String((row && row.organisation) ||
                         config.value('pki.organisation') || 'mock-sts'),
    country: String((row && row.country) || '')
  };
}

// ---------------------------------------------------------------------------
// THE RECORDS ON AN ENTRY.
// ---------------------------------------------------------------------------
function parseJsonValues(values) {
  log.debug("Entering parseJsonValues().");
  const out = [];
  (values || []).forEach(function (value) {
    try {
      const parsed = JSON.parse(String(value));
      if (parsed && typeof parsed === 'object') {
        out.push(parsed);
      }
    } catch (e) {
      log.debug("Caught in parseJsonValues(): " + ((e && e.message) || e));
      // A value somebody wrote over LDAP by hand that is not a record. It is
      // left on the entry and not read, rather than failing every reader.
    }
  });
  log.debug("Leaving parseJsonValues(). " + out.length + " record(s).");
  return out;
}

function readAttribute(entry, key) {
  log.debug("Entering readAttribute(). key=" + key);
  const resolved = resolveEntry(entry.kind, entry.id);
  if (!resolved.ok) {
    log.debug("Leaving readAttribute(). No entry.");
    return null;
  }
  log.debug("Leaving readAttribute().");
  return (resolved.attributes[ATTRIBUTES[entry.kind][key]] || []).slice();
}

function writeAttribute(entry, key, values) {
  log.debug("Entering writeAttribute(). key=" + key);
  if (!directory) {
    log.debug("Leaving writeAttribute(). No directory.");
    return false;
  }
  let written = false;
  try {
    written = directory.write(entry.kind, entry.id,
                              ATTRIBUTES[entry.kind][key], values);
  } catch (e) {
    log.error(errorCodes.tag('STS-ENROLL-0041') + 'enrollment: could not ' +
              'write ' + ATTRIBUTES[entry.kind][key] + ' on the ' +
              entryLabel(entry) + ': ' + ((e && e.message) || e));
    written = false;
  }
  log.debug("Leaving writeAttribute(). written=" + written);
  return !!written;
}

function sealText(plain, label) {
  log.debug("Entering sealText().");
  if (!keystore.persists()) {
    log.debug("Leaving sealText(). Nothing outlives the process to seal for.");
    return { ok: true, value: String(plain) };
  }
  let sealed = null;
  try {
    sealed = keystore.seal(String(plain), label);
  } catch (e) {
    log.debug("Caught in sealText(): " + ((e && e.message) || e));
    sealed = null;
  }
  if (!sealed) {
    log.debug("Leaving sealText(). Could not seal.");
    return { ok: false };
  }
  log.debug("Leaving sealText().");
  return { ok: true, value: sealed };
}

function openText(value, label) {
  log.debug("Entering openText().");
  const text = String(value || '');
  if (text.indexOf('$aesgcm$') !== 0) {
    log.debug("Leaving openText(). Not sealed.");
    return text;
  }
  let opened = null;
  try {
    opened = keystore.open(text, label);
  } catch (e) {
    log.debug("Caught in openText(): " + ((e && e.message) || e));
    opened = null;
  }
  log.debug("Leaving openText().");
  return opened === null || opened === undefined ? null : String(opened);
}

function normalSerial(serial) {
  log.debug("Entering normalSerial().");
  log.debug("Leaving normalSerial().");
  return String(serial || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase()
    .replace(/^0+(?=.)/, '');
}

function publicRecord(one) {
  log.debug("Entering publicRecord().");
  const out = Object.assign({}, one);
  delete out.privateKeyPem;
  out.expired = new Date(out.notAfter).getTime() < Date.now();
  out.status = out.revoked ? 'revoked' : (out.expired ? 'expired' : 'valid');
  log.debug("Leaving publicRecord().");
  return out;
}

// The certificates on an entry, newest first, with no key material.
function enrolledOf(entry) {
  log.debug("Entering enrolledOf().");
  const values = readAttribute(entry, 'certificate');
  if (!values) {
    log.debug("Leaving enrolledOf(). No entry.");
    return [];
  }
  log.debug("Leaving enrolledOf().");
  return parseJsonValues(values).map(publicRecord).sort(function (a, b) {
    return String(b.issuedAt).localeCompare(String(a.issuedAt));
  });
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
async function issue(spec) {
  log.debug("Entering issue().");
  const asked = spec || {};
  const family = String(asked.family || '');
  if (!isFamily(family)) {
    log.debug("Leaving issue(). Unknown family.");
    return refuse('STS-ENROLL-0004', 500, 'Not an enrollment family: ' +
                  family);
  }
  const auditRefusal = function (refusal) {
    audit.record({
      category: 'protocol', action: 'enrollment.issue.refused',
      protocol: FAMILY_LABELS[family], outcome: 'failure',
      errorCode: errorCodes.codeOf(refusal) || 'STS-ENROLL-0004',
      actor: asked.principal ? String(asked.principal.id) : '',
      target: asked.target ? entryUri(asked.target) : '',
      summary: 'a certificate was not issued over ' + FAMILY_LABELS[family] +
               ': ' + String((refusal.errors || [])[0] || '').slice(0, 300),
      detail: { profile: String(asked.profile || ''),
                via: String(asked.via || family) }
    });
    return refusal;
  };
  const profile = checkProfile(family, asked.profile);
  if (!profile.ok) {
    log.debug("Leaving issue(). Profile refused.");
    return auditRefusal(profile);
  }
  const target = asked.target;
  const resolved = resolveEntry(target && target.kind, target && target.id);
  if (!resolved.ok) {
    log.debug("Leaving issue(). No entry.");
    return auditRefusal(resolved);
  }
  const allowed = authorizeTarget(asked.principal, resolved.entry);
  if (!allowed.ok) {
    log.debug("Leaving issue(). Not authorized.");
    return auditRefusal(allowed);
  }
  const names = namesFor(resolved, profile.profile, asked.requested);
  if (!names.ok) {
    log.debug("Leaving issue(). A name was refused.");
    return auditRefusal(names);
  }
  const nowMs = Date.now();
  const existing = parseJsonValues(resolved.attributes[
    ATTRIBUTES[resolved.entry.kind].certificate]);
  const live = existing.filter(function (one) {
    return new Date(one.notAfter).getTime() > nowMs;
  });
  const cap = Number(config.value('pki.enrollmentMaxCertificatesPerEntry'));
  const replacing = asked.replaces ? normalSerial(asked.replaces) : '';
  const counted = live.filter(function (one) {
    return normalSerial(one.serialHex) !== replacing;
  });
  if (counted.length >= cap) {
    log.debug("Leaving issue(). The entry is full.");
    return auditRefusal(refuse('STS-ENROLL-0040', 409, 'The ' +
      entryLabel(resolved.entry) + ' already holds ' + counted.length +
      ' unexpired enrolled certificate(s), the most ' +
      'pki.enrollmentMaxCertificatesPerEntry allows. Revoke one first.'));
  }
  const org = organisationOf();
  const subject = [{ name: 'CN', value: resolved.entry.id },
                   { name: 'O', value: org.organisation }]
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
    log.debug("Leaving issue(). The authority refused.");
    return auditRefusal(refuse(errorCodes.codeOf(issued) || 'STS-ENROLL-0042',
      503, 'The ' + FAMILY_LABELS[family] + ' Issuing CA could not issue: ' +
      String((issued.errors || [])[0] || 'unknown reason')));
  }
  let thumbprint = '';
  let subjectDn = '';
  try {
    const cert = new nodeCrypto.X509Certificate(issued.certificatePem);
    thumbprint = cert.fingerprint256.replace(/:/g, '').toLowerCase();
    subjectDn = helpers.dnRfc4514(cert.subject);
  } catch (e) {
    log.debug("Caught in issue(): " + ((e && e.message) || e));
  }
  const record = {
    serialHex: normalSerial(issued.serialHex),
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
  // certificate on the entry with no key behind it, when this service made the
  // key, is a credential that was issued and lost.
  const kind = resolved.entry.kind;
  if (record.keySource === 'server') {
    const sealed = sealText(asked.privateKeyPem, kind === 'person'
      ? 'person-private-key' : 'application-private-key');
    if (!sealed.ok) {
      log.debug("Leaving issue(). The key could not be sealed.");
      return auditRefusal(refuse('STS-ENROLL-0043', 503, 'The generated ' +
        'private key could not be sealed for storage, so the certificate ' +
        'was not recorded.'));
    }
    const keys = (resolved.attributes[ATTRIBUTES[kind].privateKey] || [])
      .filter(function (one) {
        return String(one).indexOf(record.serialHex + ':') !== 0;
      }).concat([record.serialHex + ':' + sealed.value]);
    if (!writeAttribute(resolved.entry, 'privateKey', keys)) {
      log.debug("Leaving issue(). The key was not written.");
      return auditRefusal(refuse('STS-ENROLL-0041', 503, 'The generated ' +
        'private key could not be written onto the ' +
        entryLabel(resolved.entry) + '.'));
    }
  }
  const kept = existing.filter(function (one) {
    return new Date(one.notAfter).getTime() > nowMs ||
           one.revoked;
  }).map(function (one) {
    return JSON.stringify(one);
  }).concat([JSON.stringify(record)]);
  if (!writeAttribute(resolved.entry, 'certificate', kept)) {
    log.debug("Leaving issue(). The certificate was not written.");
    return auditRefusal(refuse('STS-ENROLL-0041', 503, 'The certificate was ' +
      'issued but could not be written onto the ' +
      entryLabel(resolved.entry) + '.'));
  }
  // A person's subject DN goes into x509subject as well, which is the
  // attribute every certificate-to-entry lookup here already reads.
  if (kind === 'person' && subjectDn && directory) {
    const subjects = (resolved.attributes.x509subject || []).slice();
    if (subjects.indexOf(subjectDn) < 0) {
      try {
        directory.write('person', resolved.entry.id, 'x509subject',
                        subjects.concat([subjectDn]));
      } catch (e) {
        log.debug("Caught in issue(): " + ((e && e.message) || e));
      }
    }
  }
  audit.record({
    category: 'protocol', action: 'enrollment.issue',
    protocol: FAMILY_LABELS[family], outcome: 'success',
    actor: asked.principal ? String(asked.principal.id) : '',
    target: entryUri(resolved.entry),
    summary: 'a ' + profile.profile + ' certificate was issued over ' +
             FAMILY_LABELS[family] + ' for the ' +
             entryLabel(resolved.entry) +
             (allowed.admin ? ' by an administrator' : ''),
    detail: { serialHex: record.serialHex, profile: record.profile,
              keySource: record.keySource, via: record.via,
              notAfter: record.notAfter }
  });
  if (replacing) {
    await revokeEnrolled(replacing, 'superseded',
                         asked.principal ? String(asked.principal.id) : '',
                         { quiet: true });
  }
  log.debug("Leaving issue(). serial=" + record.serialHex);
  return { ok: true, record: publicRecord(record),
           target: resolved.entry, admin: !!allowed.admin };
}

// A key pair generated HERE and certified in one act — EST /serverkeygen and
// the console's "issue with a server-generated key". The private key is
// returned ONCE and kept, sealed, on the entry.
async function issueWithServerKey(spec) {
  log.debug("Entering issueWithServerKey().");
  const asked = spec || {};
  const keyAlg = String(asked.keyAlg || 'ec-p256');
  if ((keyMaterial.keyAlgIds() || []).indexOf(keyAlg) < 0) {
    log.debug("Leaving issueWithServerKey(). Unknown algorithm.");
    return refuse('STS-ENROLL-0035', 400, '"' + keyAlg + '" is not a key ' +
                  'algorithm this service generates. They are ' +
                  keyMaterial.keyAlgIds().join(', ') + '.');
  }
  let pair = null;
  try {
    pair = await keyMaterial.generateKeyPair(keyAlg);
  } catch (e) {
    log.debug("Caught in issueWithServerKey(): " + ((e && e.message) || e));
    pair = null;
  }
  if (!pair) {
    log.debug("Leaving issueWithServerKey(). Generation failed.");
    return refuse('STS-ENROLL-0035', 400, 'A ' + keyAlg + ' key pair could ' +
                  'not be generated.');
  }
  const issued = await issue(Object.assign({}, asked, {
    publicKeyPem: pair.publicPem,
    keySource: 'server',
    privateKeyPem: pair.privatePem,
    keyAlg: keyAlg
  }));
  if (!issued.ok) {
    log.debug("Leaving issueWithServerKey(). Refused.");
    return issued;
  }
  log.debug("Leaving issueWithServerKey().");
  return Object.assign({}, issued, { privateKeyPem: pair.privatePem,
                                     keyAlg: keyAlg });
}

// ---------------------------------------------------------------------------
// FIND AND REVOKE.
// ---------------------------------------------------------------------------
function findEnrolled(serialHex, family) {
  log.debug("Entering findEnrolled(). serial=" + serialHex);
  const wanted = normalSerial(serialHex);
  if (!wanted) {
    log.debug("Leaving findEnrolled(). No serial.");
    return null;
  }
  const families = family ? [String(family)] : FAMILIES;
  for (let f = 0; f < families.length; f++) {
    let issued = [];
    try {
      issued = pki.issuedKeyPairsFor(realms.currentId(), families[f]);
    } catch (e) {
      log.debug("Caught in findEnrolled(): " + ((e && e.message) || e));
      issued = [];
    }
    const hit = issued.filter(function (one) {
      return normalSerial(one.serialHex) === wanted;
    })[0];
    if (hit && isKind(hit.subjectKind)) {
      // THE ENTRY IT WAS ISSUED TO, by its subject where one was recorded, so
      // a rename finds the renamed entry and a name deleted and re-created
      // finds nobody (2026-09-14).
      const renamed = hit.holderSubject
        ? helpers.nameForSubject(hit.holderSubject) : hit.identifier;
      if (!renamed) {
        log.debug("Leaving findEnrolled(). Its holder is gone.");
        return null;
      }
      const entry = { kind: hit.subjectKind, id: renamed };
      const record = enrolledOf(entry).filter(function (one) {
        return normalSerial(one.serialHex) === wanted;
      })[0];
      if (record) {
        log.debug("Leaving findEnrolled(). Found.");
        return { entry: entry, record: record, family: families[f] };
      }
    }
  }
  log.debug("Leaving findEnrolled(). Not found.");
  return null;
}

async function revokeEnrolled(serialHex, reason, by, options) {
  log.debug("Entering revokeEnrolled(). serial=" + serialHex);
  const opts = options || {};
  const found = findEnrolled(serialHex, opts.family);
  if (!found) {
    log.debug("Leaving revokeEnrolled(). Not found.");
    return refuse('STS-ENROLL-0070', 404, 'No certificate with that serial ' +
                  'was issued over ' +
                  (opts.family ? FAMILY_LABELS[opts.family] : 'an enrollment ' +
                                 'protocol') + ' in this realm.');
  }
  if (opts.entry && !sameEntry(opts.entry, found.entry)) {
    log.debug("Leaving revokeEnrolled(). Not that entry's.");
    return refuse('STS-ENROLL-0071', 403, 'That certificate does not belong ' +
                  'to the ' + entryLabel(opts.entry) + '.');
  }
  const revocation = require('./pki_revocation');
  const done = revocation.revoke(realms.currentId(), found.family, {
    serialHex: found.record.serialHex,
    reason: reason || 'unspecified',
    subject: found.record.subject,
    note: 'enrolled over ' + FAMILY_LABELS[found.family] + ' for ' +
          entryUri(found.entry) + (by ? '; revoked by ' + by : '')
  });
  if (!done || done.ok === false) {
    log.debug("Leaving revokeEnrolled(). The CA refused.");
    return refuse(errorCodes.codeOf(done) || 'STS-ENROLL-0072', 400,
                  String(((done && done.errors) || [])[0] ||
                         'The revocation was refused.'));
  }
  const values = readAttribute(found.entry, 'certificate') || [];
  const at = new Date().toISOString();
  const rewritten = parseJsonValues(values).map(function (one) {
    if (normalSerial(one.serialHex) === normalSerial(found.record.serialHex) &&
        !one.revoked) {
      one.revoked = { at: at, reason: reason || 'unspecified',
                      by: String(by || '') };
    }
    return JSON.stringify(one);
  });
  writeAttribute(found.entry, 'certificate', rewritten);
  if (!opts.quiet) {
    audit.record({
      category: 'protocol', action: 'enrollment.revoke',
      protocol: FAMILY_LABELS[found.family], outcome: 'success',
      actor: String(by || ''), target: entryUri(found.entry),
      summary: 'an enrolled certificate was revoked (' +
               (reason || 'unspecified') + ')',
      detail: { serialHex: found.record.serialHex, family: found.family }
    });
  }
  log.debug("Leaving revokeEnrolled().");
  return { ok: true, serialHex: found.record.serialHex, entry: found.entry,
           family: found.family, reason: reason || 'unspecified' };
}

// A server-generated private key held on an entry, opened. For the entry's own
// holder through the portal and never through a view.
function serverKeyOf(entry, serialHex) {
  log.debug("Entering serverKeyOf().");
  const values = readAttribute(entry, 'privateKey') || [];
  const prefix = normalSerial(serialHex) + ':';
  const hit = values.filter(function (one) {
    return String(one).indexOf(prefix) === 0;
  })[0];
  log.debug("Leaving serverKeyOf().");
  return hit ? openText(String(hit).slice(prefix.length),
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
// credential is created FOR an entry by somebody entitled to (the person on the
// portal, an administrator on the console or the API), shown once, and spent
// once.
// ---------------------------------------------------------------------------
function credentialId(prefix, entry) {
  log.debug("Entering credentialId().");
  log.debug("Leaving credentialId().");
  return prefix + '-' + (entry.kind === 'person' ? 'p' : 'a') + '-' +
         Buffer.from(entry.id, 'utf8').toString('base64url') + '-' +
         nodeCrypto.randomBytes(8).toString('hex');
}

function entryOfCredentialId(prefix, id) {
  log.debug("Entering entryOfCredentialId().");
  const match = new RegExp('^' + prefix + '-([pa])-([A-Za-z0-9_-]{1,400})-' +
                           '([0-9a-f]{16})$').exec(String(id || ''));
  if (!match) {
    log.debug("Leaving entryOfCredentialId(). Malformed.");
    return null;
  }
  let decoded = '';
  try {
    decoded = Buffer.from(match[2], 'base64url').toString('utf8');
  } catch (e) {
    log.debug("Caught in entryOfCredentialId(): " + ((e && e.message) || e));
    decoded = '';
  }
  if (!wellFormedId(decoded) ||
      Buffer.from(decoded, 'utf8').toString('base64url') !== match[2]) {
    log.debug("Leaving entryOfCredentialId(). Not canonical.");
    return null;
  }
  log.debug("Leaving entryOfCredentialId().");
  return { kind: match[1] === 'p' ? 'person' : 'application', id: decoded };
}

function lifetimeOf(asked, setting) {
  log.debug("Entering lifetimeOf().");
  const configured = Number(config.value(setting));
  const wanted = Number(asked);
  log.debug("Leaving lifetimeOf().");
  return (Number.isInteger(wanted) && wanted >= 60 && wanted <= configured)
    ? wanted : configured;
}

function liveCredentials(values, nowMs) {
  log.debug("Entering liveCredentials().");
  log.debug("Leaving liveCredentials().");
  return parseJsonValues(values).filter(function (one) {
    return new Date(one.expiresAt).getTime() > nowMs && !one.usedAt;
  });
}

function createEab(spec) {
  log.debug("Entering createEab().");
  const asked = spec || {};
  const resolved = resolveEntry(asked.target && asked.target.kind,
                                asked.target && asked.target.id);
  if (!resolved.ok) {
    log.debug("Leaving createEab(). No entry.");
    return resolved;
  }
  const nowMs = Date.now();
  const values = resolved.attributes[ATTRIBUTES[resolved.entry.kind].eab] ||
                 [];
  // Expired keys are dropped as a new one is made; a key already used to bind
  // an account is kept, because that account's binding is described by it.
  const kept = parseJsonValues(values).filter(function (one) {
    return one.boundAccount || new Date(one.expiresAt).getTime() > nowMs;
  });
  if (kept.filter(function (one) { return !one.boundAccount; }).length >=
      MAX_CREDENTIALS_PER_ENTRY) {
    log.debug("Leaving createEab(). Too many.");
    return refuse('STS-ENROLL-0044', 409, 'The ' +
                  entryLabel(resolved.entry) + ' already has ' +
                  MAX_CREDENTIALS_PER_ENTRY + ' unused EAB keys. Delete one ' +
                  'first.');
  }
  const kid = credentialId('eab', resolved.entry);
  const hmacKey = nodeCrypto.randomBytes(32).toString('base64url');
  const sealed = sealText(hmacKey, 'acme-eab-key');
  if (!sealed.ok) {
    log.debug("Leaving createEab(). Could not seal.");
    return refuse('STS-ENROLL-0043', 503, 'The EAB key could not be sealed ' +
                  'for storage.');
  }
  const lifetimeS = lifetimeOf(asked.lifetimeS, 'acme.eabLifetimeS');
  const record = {
    kid: kid,
    hmacKey: sealed.value,
    createdAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + lifetimeS * 1000).toISOString(),
    createdBy: String(asked.createdBy || ''),
    boundAccount: null,
    boundAt: null
  };
  if (!writeAttribute(resolved.entry, 'eab',
                      kept.concat([record]).map(function (one) {
                        return JSON.stringify(one);
                      }))) {
    log.debug("Leaving createEab(). Not written.");
    return refuse('STS-ENROLL-0041', 503, 'The EAB key could not be written ' +
                  'onto the ' + entryLabel(resolved.entry) + '.');
  }
  audit.record({
    category: 'configuration', action: 'enrollment.eab.create',
    protocol: 'ACME', outcome: 'success', actor: record.createdBy,
    target: entryUri(resolved.entry),
    summary: 'an ACME External Account Binding key was created for the ' +
             entryLabel(resolved.entry),
    detail: { kid: kid, expiresAt: record.expiresAt }
  });
  log.debug("Leaving createEab().");
  return { ok: true, kid: kid, hmacKey: hmacKey, alg: 'HS256',
           expiresAt: record.expiresAt, target: resolved.entry };
}

function findEab(kid) {
  log.debug("Entering findEab().");
  const entry = entryOfCredentialId('eab', kid);
  if (!entry) {
    log.debug("Leaving findEab(). Malformed.");
    return null;
  }
  const values = readAttribute(entry, 'eab');
  if (!values) {
    log.debug("Leaving findEab(). No entry.");
    return null;
  }
  const record = parseJsonValues(values).filter(function (one) {
    return one.kid === String(kid);
  })[0];
  if (!record) {
    log.debug("Leaving findEab(). No such key.");
    return null;
  }
  const opened = openText(record.hmacKey, 'acme-eab-key');
  if (opened === null) {
    log.debug("Leaving findEab(). Could not open.");
    return null;
  }
  log.debug("Leaving findEab().");
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
// refused; the SAME account re-presenting it (a client retrying newAccount) is
// the idempotent case RFC 8555 section 7.3.1 describes and is answered as such.
function bindEab(kid, accountThumbprint) {
  log.debug("Entering bindEab().");
  const entry = entryOfCredentialId('eab', kid);
  const values = entry ? readAttribute(entry, 'eab') : null;
  if (!values) {
    log.debug("Leaving bindEab(). No such key.");
    return refuse('STS-ENROLL-0080', 401, 'The External Account Binding key ' +
                  'is not known in this realm.');
  }
  let result = null;
  const rewritten = parseJsonValues(values).map(function (one) {
    if (one.kid !== String(kid)) {
      return one;
    }
    if (one.boundAccount && one.boundAccount !== accountThumbprint) {
      result = refuse('STS-ENROLL-0081', 401, 'That External Account ' +
                      'Binding key has already bound another account.');
      return one;
    }
    if (new Date(one.expiresAt).getTime() <= Date.now() && !one.boundAccount) {
      result = refuse('STS-ENROLL-0082', 401, 'That External Account ' +
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
    log.debug("Leaving bindEab(). No such key.");
    return refuse('STS-ENROLL-0080', 401, 'The External Account Binding key ' +
                  'is not known in this realm.');
  }
  if (result.ok) {
    writeAttribute(entry, 'eab', rewritten.map(function (one) {
      return JSON.stringify(one);
    }));
  }
  log.debug("Leaving bindEab(). ok=" + !!result.ok);
  return result;
}

// ---------------------------------------------------------------------------
// BINDING AN EAB KEY ONCE ACROSS THE CLUSTER (2026-09-14, #46 section 2).
//
// `bindEab()` reads the key's record off the entry, sees `boundAccount: null`,
// and writes the account in. Two ACME newAccount requests signed by two
// DIFFERENT account keys, with one EAB key, arriving at two nodes at once both
// read null — and RFC 8555 section 7.3.4's "bound to one account" became two
// accounts, each issued certificates for the entry the key names. The entry
// is last writer wins, so it even ends up naming only one of them.
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
const EAB_CLAIM_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function bindEabOnce(kid, accountThumbprint) {
  log.debug("Entering bindEabOnce().");
  const known = findEab(kid);
  if (known && known.boundAccount === String(accountThumbprint)) {
    log.debug("Leaving bindEabOnce(). Already this account's.");
    return Promise.resolve(bindEab(kid, accountThumbprint));
  }
  log.debug("Leaving bindEabOnce(). Claiming.");
  return claims.claim({ scope: 'acme.eab-bind', value: String(kid),
                        ttlMs: EAB_CLAIM_TTL_MS })
    .then(function (claimed) {
      if (!claimed.ok && claimed.reason === 'used' && known &&
          known.boundAccount) {
        // The binding has already reached this node: the refusal it always
        // was, under the code it always had.
        log.debug("Leaving bindEabOnce(). Bound, on the entry.");
        return bindEab(kid, accountThumbprint);
      }
      if (!claimed.ok && claimed.reason === 'used') {
        log.warn('cert_enrollment: an External Account Binding key was ' +
                 'presented for a new account while it is being or has ' +
                 'been bound to another, on this node or another. Refused.');
        return refuse('STS-ENROLL-0081', 401, 'That External Account ' +
                      'Binding key has already bound another account.');
      }
      if (!claimed.ok) {
        log.error(errorCodes.tag('STS-ENROLL-0091') + 'cert_enrollment: an ' +
                  'External Account Binding key could not be proved unbound (' +
                  (claimed.why || claimed.reason) + '), so it was refused.');
        return refuse('STS-ENROLL-0091', 503, 'The External Account Binding ' +
                      'key could not be checked just now. Try again.');
      }
      const bound = bindEab(kid, accountThumbprint);
      if (!bound.ok) {
        claims.release(claimed.handle);
      }
      return bound;
    });
}

function deleteEab(kid, by) {
  log.debug("Entering deleteEab().");
  const entry = entryOfCredentialId('eab', kid);
  const values = entry ? readAttribute(entry, 'eab') : null;
  const records = values ? parseJsonValues(values) : [];
  const left = records.filter(function (one) {
    return one.kid !== String(kid);
  });
  if (!entry || left.length === records.length) {
    log.debug("Leaving deleteEab(). No such key.");
    return refuse('STS-ENROLL-0080', 404, 'There is no such External Account ' +
                  'Binding key in this realm.');
  }
  writeAttribute(entry, 'eab', left.map(function (one) {
    return JSON.stringify(one);
  }));
  audit.record({
    category: 'configuration', action: 'enrollment.eab.delete',
    protocol: 'ACME', outcome: 'success', actor: String(by || ''),
    target: entryUri(entry),
    summary: 'an ACME External Account Binding key was deleted',
    detail: { kid: String(kid) }
  });
  log.debug("Leaving deleteEab().");
  return { ok: true, kid: String(kid), entry: entry };
}

function eabsOf(entry) {
  log.debug("Entering eabsOf().");
  const values = readAttribute(entry, 'eab') || [];
  const nowMs = Date.now();
  log.debug("Leaving eabsOf().");
  return parseJsonValues(values).map(function (one) {
    return { kid: one.kid, createdAt: one.createdAt,
             expiresAt: one.expiresAt, createdBy: one.createdBy,
             boundAccount: one.boundAccount || null, boundAt: one.boundAt,
             status: one.boundAccount ? 'bound'
               : (new Date(one.expiresAt).getTime() <= nowMs ? 'expired'
                                                               : 'unused') };
  });
}

function createScepChallenge(spec) {
  log.debug("Entering createScepChallenge().");
  const asked = spec || {};
  const profile = checkProfile('scep', asked.profile || defaultProfile('scep'));
  if (!profile.ok) {
    log.debug("Leaving createScepChallenge(). Profile refused.");
    return profile;
  }
  const resolved = resolveEntry(asked.target && asked.target.kind,
                                asked.target && asked.target.id);
  if (!resolved.ok) {
    log.debug("Leaving createScepChallenge(). No entry.");
    return resolved;
  }
  const nowMs = Date.now();
  const values = resolved.attributes[
    ATTRIBUTES[resolved.entry.kind].challenge] || [];
  const kept = liveCredentials(values, nowMs);
  if (kept.length >= MAX_CREDENTIALS_PER_ENTRY) {
    log.debug("Leaving createScepChallenge(). Too many.");
    return refuse('STS-ENROLL-0044', 409, 'The ' +
                  entryLabel(resolved.entry) + ' already has ' +
                  MAX_CREDENTIALS_PER_ENTRY + ' unused SCEP challenges. ' +
                  'Delete one first.');
  }
  const id = credentialId('scep', resolved.entry);
  const secret = nodeCrypto.randomBytes(24).toString('base64url');
  const lifetimeS = lifetimeOf(asked.lifetimeS, 'scep.challengeLifetimeS');
  const record = {
    id: id,
    sha256: nodeCrypto.createHash('sha256').update(secret).digest('hex'),
    profile: profile.profile,
    createdAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + lifetimeS * 1000).toISOString(),
    createdBy: String(asked.createdBy || ''),
    usedAt: null
  };
  if (!writeAttribute(resolved.entry, 'challenge',
                      kept.concat([record]).map(function (one) {
                        return JSON.stringify(one);
                      }))) {
    log.debug("Leaving createScepChallenge(). Not written.");
    return refuse('STS-ENROLL-0041', 503, 'The challenge could not be ' +
                  'written onto the ' + entryLabel(resolved.entry) + '.');
  }
  audit.record({
    category: 'configuration', action: 'enrollment.challenge.create',
    protocol: 'SCEP', outcome: 'success', actor: record.createdBy,
    target: entryUri(resolved.entry),
    summary: 'a SCEP challenge password was created for the ' +
             entryLabel(resolved.entry) + ' (' + profile.profile + ')',
    detail: { id: id, profile: profile.profile, expiresAt: record.expiresAt }
  });
  log.debug("Leaving createScepChallenge().");
  return { ok: true, id: id, challenge: id + '.' + secret,
           profile: profile.profile, expiresAt: record.expiresAt,
           target: resolved.entry };
}

// Redeem a challenge password. `peek` checks without spending — SCEP answers a
// retried PKIOperation for a transaction it already completed, and the
// protocol module decides whether a retry is that case.
function redeemScepChallenge(challenge, options) {
  log.debug("Entering redeemScepChallenge().");
  const opts = options || {};
  const text = String(challenge || '');
  const dot = text.lastIndexOf('.');
  const id = dot > 0 ? text.slice(0, dot) : '';
  const secret = dot > 0 ? text.slice(dot + 1) : '';
  const entry = entryOfCredentialId('scep', id);
  const values = entry ? readAttribute(entry, 'challenge') : null;
  const generic = refuse('STS-ENROLL-0083', 401, 'The challenge password was ' +
                         'not accepted.');
  if (!values || !secret || secret.length > 128) {
    log.debug("Leaving redeemScepChallenge(). Unknown.");
    return generic;
  }
  const records = parseJsonValues(values);
  const record = records.filter(function (one) { return one.id === id; })[0];
  if (!record) {
    log.debug("Leaving redeemScepChallenge(). No such challenge.");
    return generic;
  }
  const presented = nodeCrypto.createHash('sha256').update(secret).digest();
  const expected = Buffer.from(String(record.sha256 || ''), 'hex');
  if (expected.length !== presented.length ||
      !nodeCrypto.timingSafeEqual(presented, expected)) {
    log.debug("Leaving redeemScepChallenge(). Wrong secret.");
    return generic;
  }
  if (record.usedAt) {
    log.debug("Leaving redeemScepChallenge(). Spent.");
    return refuse('STS-ENROLL-0084', 401, 'That challenge password has ' +
                  'already been used.');
  }
  if (new Date(record.expiresAt).getTime() <= Date.now()) {
    log.debug("Leaving redeemScepChallenge(). Expired.");
    return refuse('STS-ENROLL-0085', 401, 'That challenge password has ' +
                  'expired.');
  }
  if (!opts.peek) {
    record.usedAt = new Date().toISOString();
    writeAttribute(entry, 'challenge', records.map(function (one) {
      return JSON.stringify(one);
    }));
  }
  log.debug("Leaving redeemScepChallenge(). Accepted.");
  return { ok: true, id: id, entry: entry, profile: record.profile };
}

// ---------------------------------------------------------------------------
// A SCEP CHALLENGE, SPENT ONCE ACROSS THE CLUSTER (2026-09-14, #46 section 2).
//
// `redeemScepChallenge()` is "read `usedAt: null` off the entry, write the
// time in", and two PKCSReq messages carrying one challenge password — two
// transactionIDs, so `scep.js`'s transaction guard does not join them — at two
// nodes both read null and both issued. The challenge is CLAIMED between the
// look that proves it is right and the write that spends it; the claim lives
// as long as the challenge could still verify, plus a minute of skew. The
// synchronous `redeemScepChallenge()` is unchanged and is still what marks the
// entry, which every page reads.
// ---------------------------------------------------------------------------
async function redeemScepChallengeOnce(challenge) {
  log.debug("Entering redeemScepChallengeOnce().");
  const peek = redeemScepChallenge(challenge, { peek: true });
  if (!peek.ok) {
    log.debug("Leaving redeemScepChallengeOnce(). Refused on the entry.");
    return peek;
  }
  const record = parseJsonValues(readAttribute(peek.entry, 'challenge') || [])
    .filter(function (one) { return one.id === peek.id; })[0] || {};
  const remaining = new Date(record.expiresAt).getTime() - Date.now();
  const claimed = await claims.claim({
    scope: 'scep.challenge', value: peek.id,
    ttlMs: Math.max(60 * 1000, (remaining || 0) + 60 * 1000)
  });
  if (!claimed.ok && claimed.reason === 'used') {
    log.warn('cert_enrollment: a SCEP challenge password was presented ' +
             'while another request is spending it or has spent it, on this ' +
             'node or another. Refused.');
    log.debug("Leaving redeemScepChallengeOnce(). Claimed elsewhere.");
    return refuse('STS-ENROLL-0084', 401, 'That challenge password has ' +
                  'already been used.');
  }
  if (!claimed.ok) {
    log.error(errorCodes.tag('STS-ENROLL-0091') + 'cert_enrollment: a SCEP ' +
              'challenge password could not be proved unspent (' +
              (claimed.why || claimed.reason) + '), so it was refused.');
    log.debug("Leaving redeemScepChallengeOnce(). The store.");
    return refuse('STS-ENROLL-0091', 503, 'The challenge password could not ' +
                  'be checked just now. Try again.');
  }
  const spent = redeemScepChallenge(challenge);
  if (!spent.ok) {
    claims.release(claimed.handle);
  }
  log.debug("Leaving redeemScepChallengeOnce(). ok=" + !!spent.ok);
  return spent;
}

function deleteScepChallenge(id, by) {
  log.debug("Entering deleteScepChallenge().");
  const entry = entryOfCredentialId('scep', id);
  const values = entry ? readAttribute(entry, 'challenge') : null;
  const records = values ? parseJsonValues(values) : [];
  const left = records.filter(function (one) {
    return one.id !== String(id);
  });
  if (!entry || left.length === records.length) {
    log.debug("Leaving deleteScepChallenge(). No such challenge.");
    return refuse('STS-ENROLL-0083', 404, 'There is no such SCEP challenge ' +
                  'in this realm.');
  }
  writeAttribute(entry, 'challenge', left.map(function (one) {
    return JSON.stringify(one);
  }));
  audit.record({
    category: 'configuration', action: 'enrollment.challenge.delete',
    protocol: 'SCEP', outcome: 'success', actor: String(by || ''),
    target: entryUri(entry),
    summary: 'a SCEP challenge password was deleted',
    detail: { id: String(id) }
  });
  log.debug("Leaving deleteScepChallenge().");
  return { ok: true, id: String(id), entry: entry };
}

function scepChallengesOf(entry) {
  log.debug("Entering scepChallengesOf().");
  const values = readAttribute(entry, 'challenge') || [];
  const nowMs = Date.now();
  log.debug("Leaving scepChallengesOf().");
  return parseJsonValues(values).map(function (one) {
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
function hostNamesOf(entry) {
  log.debug("Entering hostNamesOf().");
  const resolved = resolveEntry(entry.kind, entry.id);
  log.debug("Leaving hostNamesOf().");
  return resolved.ok ? resolved.hostNames.slice() : [];
}

function changeHostName(entry, name, add, by) {
  log.debug("Entering changeHostName(). add=" + add);
  const resolved = resolveEntry(entry && entry.kind, entry && entry.id);
  if (!resolved.ok) {
    log.debug("Leaving changeHostName(). No entry.");
    return resolved;
  }
  const host = normalHostName(name);
  if (!host) {
    log.debug("Leaving changeHostName(). Malformed.");
    return refuse('STS-ENROLL-0057', 400, '"' + String(name).slice(0, 253) +
                  '" is not a DNS name or an IP address.');
  }
  const current = resolved.hostNames.slice();
  const has = current.indexOf(host) >= 0;
  if (add && has) {
    log.debug("Leaving changeHostName(). Already there.");
    return { ok: true, unchanged: true, hostNames: current };
  }
  if (!add && !has) {
    log.debug("Leaving changeHostName(). Not there.");
    return refuse('STS-ENROLL-0058', 404, '"' + host + '" is not registered ' +
                  'on the ' + entryLabel(resolved.entry) + '.');
  }
  const next = add ? current.concat([host])
                   : current.filter(function (one) { return one !== host; });
  if (!writeAttribute(resolved.entry, 'hostName', next)) {
    log.debug("Leaving changeHostName(). Not written.");
    return refuse('STS-ENROLL-0041', 503, 'The host name could not be ' +
                  'written.');
  }
  audit.record({
    category: 'configuration',
    action: add ? 'enrollment.hostname.add' : 'enrollment.hostname.remove',
    outcome: 'success', actor: String(by || ''),
    target: entryUri(resolved.entry),
    summary: 'the host name ' + host + ' was ' +
             (add ? 'registered on' : 'removed from') + ' the ' +
             entryLabel(resolved.entry),
    detail: { hostName: host }
  });
  log.debug("Leaving changeHostName().");
  return { ok: true, hostNames: next, entry: resolved.entry };
}

// ---------------------------------------------------------------------------
// LISTINGS ACROSS THE REALM, for the console pages and /admin-api.
// ---------------------------------------------------------------------------
function holdersOf(key) {
  log.debug("Entering holdersOf(). key=" + key);
  const out = [];
  if (!directory) {
    log.debug("Leaving holdersOf(). No directory.");
    return out;
  }
  ['person', 'application'].forEach(function (kind) {
    let ids = [];
    try {
      ids = directory.holders(kind, ATTRIBUTES[kind][key]) || [];
    } catch (e) {
      log.debug("Caught in holdersOf(): " + ((e && e.message) || e));
      ids = [];
    }
    ids.forEach(function (id) {
      out.push({ kind: kind, id: String(id) });
    });
  });
  log.debug("Leaving holdersOf(). " + out.length + " holder(s).");
  return out;
}

function certificatesInRealm(family) {
  log.debug("Entering certificatesInRealm(). family=" + family);
  const out = [];
  holdersOf('certificate').forEach(function (entry) {
    enrolledOf(entry).forEach(function (record) {
      if (!family || record.family === family) {
        out.push(Object.assign({ entry: entry, entryUri: entryUri(entry) },
                               record));
      }
    });
  });
  log.debug("Leaving certificatesInRealm(). " + out.length + ".");
  return out.sort(function (a, b) {
    return String(b.issuedAt).localeCompare(String(a.issuedAt));
  });
}

function eabsInRealm() {
  log.debug("Entering eabsInRealm().");
  const out = [];
  holdersOf('eab').forEach(function (entry) {
    eabsOf(entry).forEach(function (one) {
      out.push(Object.assign({ entry: entry, entryUri: entryUri(entry) },
                             one));
    });
  });
  log.debug("Leaving eabsInRealm().");
  return out.sort(function (a, b) {
    return String(b.createdAt).localeCompare(String(a.createdAt));
  });
}

function challengesInRealm() {
  log.debug("Entering challengesInRealm().");
  const out = [];
  holdersOf('challenge').forEach(function (entry) {
    scepChallengesOf(entry).forEach(function (one) {
      out.push(Object.assign({ entry: entry, entryUri: entryUri(entry) },
                             one));
    });
  });
  log.debug("Leaving challengesInRealm().");
  return out.sort(function (a, b) {
    return String(b.createdAt).localeCompare(String(a.createdAt));
  });
}

function hostNamesInRealm() {
  log.debug("Entering hostNamesInRealm().");
  const out = [];
  holdersOf('hostName').forEach(function (entry) {
    const names = hostNamesOf(entry);
    if (names.length) {
      out.push({ entry: entry, entryUri: entryUri(entry), hostNames: names });
    }
  });
  log.debug("Leaving hostNamesInRealm().");
  return out;
}

// The family's Issuing CA in this realm (and nothing private).
function authorityOf(family) {
  log.debug("Entering authorityOf(). family=" + family);
  let described = null;
  try {
    described = pki.describeIssuer(realms.currentId(), family);
  } catch (e) {
    log.debug("Caught in authorityOf(): " + ((e && e.message) || e));
    described = null;
  }
  log.debug("Leaving authorityOf().");
  return described;
}

// The CA certificates a client installs: the family Issuing CA, the realm
// Intermediate and the service Root, leaf-most first. What EST /cacerts and
// SCEP GetCACert serve and what ACME appends to a certificate chain (without
// the Root).
function caChainOf(family) {
  log.debug("Entering caChainOf(). family=" + family);
  const row = pki.rawRowFor(realms.currentId());
  const issuing = row && row.issuing ? row.issuing[family] : null;
  const roots = pki.trustAnchorsFor(realms.currentId()) || [];
  if (!issuing || !row.intermediate) {
    log.debug("Leaving caChainOf(). No CA yet.");
    return { ok: false, issuingPem: '', intermediatePem: '', rootPem: '',
             chainPem: [] };
  }
  log.debug("Leaving caChainOf().");
  return { ok: true, issuingPem: issuing.certificatePem,
           intermediatePem: row.intermediate.certificatePem,
           rootPem: roots[0] || '',
           chainPem: [issuing.certificatePem, row.intermediate.certificatePem]
             .concat(roots[0] ? [roots[0]] : []) };
}

// Make sure the family CA exists in this realm, topping a branch up that was
// built before the enrollment use cases did. Answers what `caChainOf()` does.
async function ensureAuthority(family) {
  log.debug("Entering ensureAuthority(). family=" + family);
  let chain = caChainOf(family);
  if (chain.ok) {
    log.debug("Leaving ensureAuthority(). Present.");
    return chain;
  }
  if (!pki.hasRoot()) {
    log.debug("Leaving ensureAuthority(). No Root.");
    return chain;
  }
  try {
    await pki.ensureScope(realms.currentId());
  } catch (e) {
    log.debug("Caught in ensureAuthority(): " + ((e && e.message) || e));
  }
  chain = caChainOf(family);
  log.debug("Leaving ensureAuthority(). ok=" + chain.ok);
  return chain;
}

// A principal for a console, API or portal session that authenticated
// elsewhere: the console gate, the /admin-api token gate, or the portal's
// own sign-in. `admin` asks the roster of the realm the session is in — the
// default realm's for a session there, the realm's own otherwise.
function sessionPrincipal(username, via, opts) {
  log.debug("Entering sessionPrincipal().");
  const options = opts || {};
  const name = String(username || '');
  const local = name ? resolveEntry('person', name) : { ok: false };
  log.debug("Leaving sessionPrincipal().");
  return { kind: 'person', id: name,
           admin: options.admin === true ||
                  (options.admin !== false && sessionIsAdmin(name)),
           via: via, realm: realms.currentId(), hasEntry: !!local.ok };
}

// ---------------------------------------------------------------------------
// WHAT A DIRECTORY DUMP OR A SEARCH SHOWS OF THE THREE SECRET ATTRIBUTE
// FAMILIES — in EVERY mode, which is one step further than a person's signing
// key goes. A server-generated private key, an EAB MAC key and a challenge
// digest are read back by THIS module through the directory slot and by nothing
// else, so withholding them from every page and every search spoils no reader's
// view — `kerberos/krb5_person_keys.js`'s argument for `stsKrb5Keys`, made
// again. In development mode a private key is stored UNSEALED (there is no
// key-encryption key that outlives the process), and a dump that printed it
// would hand the key to anybody holding Admin Read. `ldap/ldap_server.js` calls
// this with the LOWER-CASED names the store uses.
// ---------------------------------------------------------------------------
function withheldValues(attribute, values) {
  log.debug("Entering withheldValues().");
  const lower = String(attribute || '').toLowerCase();
  const secret = SECRET_ATTRIBUTES.some(function (one) {
    return one.toLowerCase() === lower;
  });
  if (!secret) {
    log.debug("Leaving withheldValues(). Not withheld.");
    return values;
  }
  log.debug("Leaving withheldValues().");
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
// plain HTTP listener (`mode.requiresEnrollmentTls()`); development answers and
// logs. SCEP never asks, because its messages are CMS-protected by design.
//
// `throttled()` — the web-security window over a family's two limits, counted
// only for a FAILURE (`websecurity.blocked()` answers without counting, and
// `attempt()` is called after a refusal): a device fleet enrolling legitimately
// from one NAT must not be locked out by its own successes.
// ---------------------------------------------------------------------------
function transportRefusal(req, family) {
  log.debug("Entering transportRefusal(). family=" + family);
  // `req.protocol` rather than a header: express computes it from the socket,
  // and honours X-Forwarded-Proto only where a proxy is TRUSTED — the request
  // worker trusts the front process (common/request_worker.js argues why),
  // which writes the header from its OWN `req.protocol`; the main listener
  // sets no `trust proxy` at all, so there it is the socket's scheme whatever
  // `global.trustProxy` says. A header read directly would let any client
  // claim TLS.
  const encrypted = !!(req && req.socket && req.socket.encrypted) ||
    !!(req && req.protocol === 'https');
  if (encrypted) {
    log.debug("Leaving transportRefusal(). Over TLS.");
    return null;
  }
  if (!mode.requiresEnrollmentTls()) {
    log.info('enrollment: a ' + FAMILY_LABELS[family] + ' request arrived ' +
             'over plain HTTP; development mode answers it (product mode ' +
             'would refuse it, STS-ENROLL-0060).');
    log.debug("Leaving transportRefusal(). Development.");
    return null;
  }
  log.debug("Leaving transportRefusal(). Refused.");
  return refuse('STS-ENROLL-0060', 403, FAMILY_LABELS[family] + ' is served ' +
                'over TLS only (RFC 8555 section 6.1, RFC 7030 section 3.2), ' +
                'and this request did not arrive over TLS.');
}

function websecurityModule() {
  log.debug("Entering websecurityModule().");
  log.debug("Leaving websecurityModule().");
  return require('./websecurity');
}

function limitsOf(family) {
  log.debug("Entering limitsOf().");
  log.debug("Leaving limitsOf().");
  return { identity: Number(config.value(family + '.attemptsPerIdentity')),
           address: Number(config.value(family + '.attemptsPerAddress')) };
}

// Is this caller over a limit right now? Counts nothing.
function throttled(family, req, identity) {
  log.debug("Entering throttled(). family=" + family);
  const ws = websecurityModule();
  let blocked = null;
  try {
    blocked = typeof ws.blocked === 'function'
      ? ws.blocked('enroll-' + family, req, identity || '', limitsOf(family))
      : null;
  } catch (e) {
    log.debug("Caught in throttled(): " + ((e && e.message) || e));
    blocked = null;
  }
  if (blocked && blocked.ok === false) {
    log.debug("Leaving throttled(). Blocked.");
    return refuse('STS-ENROLL-0061', 429, 'Too many refused ' +
                  FAMILY_LABELS[family] + ' requests. Wait ' +
                  (blocked.retryAfterS || 60) + ' seconds and try again.');
  }
  log.debug("Leaving throttled().");
  return null;
}

// The same question against ONE BUDGET FOR THE CLUSTER (2026-09-14, #46):
// `websecurity.blockedShared()`, which is `blocked()` where no store is
// shared. Every door in the three families asks this one; `throttled()` stays
// for a caller that cannot wait.
function throttledShared(family, req, identity) {
  log.debug("Entering throttledShared(). family=" + family);
  const ws = websecurityModule();
  if (typeof ws.blockedShared !== 'function') {
    log.debug("Leaving throttledShared(). No shared limiter.");
    return Promise.resolve(throttled(family, req, identity));
  }
  log.debug("Leaving throttledShared().");
  return ws.blockedShared('enroll-' + family, req, identity || '',
                          limitsOf(family)).then(function (blocked) {
    if (blocked && blocked.ok === false) {
      return refuse('STS-ENROLL-0061', 429, 'Too many refused ' +
                    FAMILY_LABELS[family] + ' requests. Wait ' +
                    (blocked.retryAfterS || 60) + ' seconds and try again.');
    }
    return null;
  }, function (e) {
    log.debug("Caught in throttledShared(): " + ((e && e.message) || e));
    return throttled(family, req, identity);
  });
}

// Count one refused request against the caller.
//
// **IN THE CLUSTER'S WINDOW WHEN ONE IS SHARED (#46), AND NOT AWAITED.** Every
// caller is a refusal writer that has already decided and is sending; the
// count is not a decision, `throttledShared()` on the NEXT request is. The
// count is one statement and lands well before a client can come back.
function countFailure(family, req, identity) {
  log.debug("Entering countFailure(). family=" + family);
  try {
    const ws = websecurityModule();
    const counting = typeof ws.attemptShared === 'function'
      ? ws.attemptShared('enroll-' + family, req, identity || '',
                         limitsOf(family))
      : ws.attempt('enroll-' + family, req, identity || '', limitsOf(family));
    Promise.resolve(counting).catch(function (e) {
      log.debug("Caught in countFailure(): " + ((e && e.message) || e));
    });
  } catch (e) {
    log.debug("Caught in countFailure(): " + ((e && e.message) || e));
  }
  log.debug("Leaving countFailure().");
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
// wrong — `websecurity.failedShared()` argues it. Resolves to that refusal, or
// null. Where nothing is shared, `sharesLimits()` is false and the writers keep
// `countFailure()`, synchronously, exactly as before.
// ---------------------------------------------------------------------------
function countFailureShared(family, req, identity) {
  log.debug("Entering countFailureShared(). family=" + family);
  const ws = websecurityModule();
  if (typeof ws.failedShared !== 'function') {
    countFailure(family, req, identity);
    log.debug("Leaving countFailureShared(). No shared limiter.");
    return Promise.resolve(null);
  }
  log.debug("Leaving countFailureShared().");
  return ws.failedShared('enroll-' + family, req, identity || '',
                         limitsOf(family)).then(function (overLimit) {
    if (!overLimit) {
      return null;
    }
    return refuse('STS-ENROLL-0061', 429, 'Too many refused ' +
                  FAMILY_LABELS[family] + ' requests. Wait ' +
                  (overLimit.retryAfterS || 60) + ' seconds and try again.');
  }, function (e) {
    log.debug("Caught in countFailureShared(): " + ((e && e.message) || e));
    return null;
  });
}

// Whether a refusal writer should wait for `countFailureShared()`.
function sharesThrottle() {
  log.debug("Entering sharesThrottle().");
  const ws = websecurityModule();
  log.debug("Leaving sharesThrottle().");
  return typeof ws.sharesLimits === 'function' && !!ws.sharesLimits();
}

// The retry-after of a throttled refusal, for a Retry-After header.
function retryAfterOf(refusal) {
  log.debug("Entering retryAfterOf().");
  const match = /Wait (\d+) seconds/.exec(String((refusal && refusal.why) ||
                                                 ''));
  log.debug("Leaving retryAfterOf().");
  return match ? Number(match[1]) : 60;
}

// DECLARED AT REQUIRE TIME, for `cluster/cluster.js`'s reason. The row is
// four fixes and this file holds two of them; the other two are the ACME
// Replay-Nonce and finalize claims in `acme/acme.js` (through
// `acme/acme_store.js`) and the SPIFFE join token claim in
// `spiffe/spiffe_api.js`. The row names this file because the capability is
// "an enrollment credential is spent once", and this is where they live.
capabilities.provide('enrollment.credentials-once');

module.exports = {
  FAMILIES: FAMILIES,
  withheldValues: withheldValues,
  transportRefusal: transportRefusal,
  throttled: throttled,
  throttledShared: throttledShared,
  countFailure: countFailure,
  countFailureShared: countFailureShared,
  sharesThrottle: sharesThrottle,
  retryAfterOf: retryAfterOf,
  keyAlgName: keyAlgName,
  FAMILY_LABELS: FAMILY_LABELS,
  PROFILE_IDS: PROFILE_IDS,
  REFUSED_PROFILES: REFUSED_PROFILES,
  PROFILE_NEEDS: PROFILE_NEEDS,
  ATTRIBUTES: ATTRIBUTES,
  SECRET_ATTRIBUTES: SECRET_ATTRIBUTES,
  URN_PREFIX: URN_PREFIX,
  MAX_CREDENTIALS_PER_ENTRY: MAX_CREDENTIALS_PER_ENTRY,
  setDirectory: setDirectory,
  hasDirectory: hasDirectory,
  refuse: refuse,
  isFamily: isFamily,
  isKind: isKind,
  wellFormedId: wellFormedId,
  entryUri: entryUri,
  entryFromUri: entryFromUri,
  entryLabel: entryLabel,
  resolveEntry: resolveEntry,
  normalHostName: normalHostName,
  normalSerial: normalSerial,
  adminFor: adminFor,
  sessionIsAdmin: sessionIsAdmin,
  sessionPrincipal: sessionPrincipal,
  authenticatePerson: authenticatePerson,
  authenticateApplication: authenticateApplication,
  authenticateCertificate: authenticateCertificate,
  authenticatePresentedCertificate: authenticatePresentedCertificate,
  authorizeTarget: authorizeTarget,
  allowedProfiles: allowedProfiles,
  checkProfile: checkProfile,
  defaultProfile: defaultProfile,
  parseCsr: parseCsr,
  targetFromRequest: targetFromRequest,
  namesFor: namesFor,
  issue: issue,
  issueWithServerKey: issueWithServerKey,
  enrolledOf: enrolledOf,
  findEnrolled: findEnrolled,
  revokeEnrolled: revokeEnrolled,
  serverKeyOf: serverKeyOf,
  createEab: createEab,
  findEab: findEab,
  bindEab: bindEab,
  bindEabOnce: bindEabOnce,
  deleteEab: deleteEab,
  eabsOf: eabsOf,
  createScepChallenge: createScepChallenge,
  redeemScepChallenge: redeemScepChallenge,
  redeemScepChallengeOnce: redeemScepChallengeOnce,
  deleteScepChallenge: deleteScepChallenge,
  scepChallengesOf: scepChallengesOf,
  hostNamesOf: hostNamesOf,
  addHostName: function addHostName(entry, name, by) {
    log.debug("Entering addHostName().");
    log.debug("Leaving addHostName().");
    return changeHostName(entry, name, true, by);
  },
  removeHostName: function removeHostName(entry, name, by) {
    log.debug("Entering removeHostName().");
    log.debug("Leaving removeHostName().");
    return changeHostName(entry, name, false, by);
  },
  certificatesInRealm: certificatesInRealm,
  eabsInRealm: eabsInRealm,
  challengesInRealm: challengesInRealm,
  hostNamesInRealm: hostNamesInRealm,
  authorityOf: authorityOf,
  caChainOf: caChainOf,
  ensureAuthority: ensureAuthority,
  derToPem: derToPem
};
