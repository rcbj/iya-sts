// @ts-check
'use strict';
//
// common/tls_client_certificates.js — A PERSON'S TLS CLIENT CERTIFICATE, ISSUED
// BY THE PERSON (2026-09-13).
//
// `/portal/signing-key` hands a signed-in person an RFC 7523 and an RFC 7522
// key pair already. This is the third thing on that page and the first whose
// use is a HANDSHAKE rather than a document: a key pair and an X.509
// certificate carrying `clientAuth`, which the person installs in a browser
// and presents on this service's main port, where `GET /tls/sign-in` signs
// them in. (It was the 8443 and 9443 listeners until they were deleted on
// 2026-09-16.)
//
// THREE HALVES, AND THEY ARE ONE MODULE BECAUSE THEY ARE ONE RULE READ THREE
// WAYS:
//
//   1. ISSUE — from the realm's `tls-client` Issuing CA, through
//      `pki.certify()`, so the certificate is in the register (OCSP answers
//      `good`, the revocation pane on /admin/pki offers it, a rebuilt branch
//      supersedes it) and names that authority's CRL and responder. The
//      private key is handed back ONCE and this module keeps no copy.
//   2. PACKAGE — a password-protected PKCS#12 and a PEM key and chain, through
//      `common/vendored/key_material.js`'s `exportKeyPair()`, which is the
//      exporter `/admin/keys` and the Certificate & Key Configuration pane
//      already use. One exporter, so a `.p12` from here imports exactly as one
//      from those pages does.
//   3. RECOGNISE — `identityOf()`, the gate every door that turns a verified
//      client certificate into an identity asks.
//
// ---------------------------------------------------------------------------
// WHY THE GATE EXISTS AT ALL, AND IT IS THE SECURITY POINT OF THE FEATURE.
//
// A certificate this service issues is useless at a listener unless the
// listener trusts its chain, and the client truststore every listener shares
// (`tls/tls_server.js`) was EMPTY by default — anchors arrived only through
// /tls/trust. So since this module it trusts the SERVICE ROOT as well
// (`trustAnchorPem()`, behind `tls.trustIssuedClientCertificates`), which
// reaches the main port. OpenSSL will not end a path at an
// Intermediate or an Issuing CA without a partial-chain flag node does not
// expose, so the anchor HAS to be the Root.
//
// **AND THE ROOT VOUCHES FOR EVERY KEY PAIR THIS SERVICE HAS EVER ISSUED.** An
// application's RFC 7523 key pair carries no extended key usage, which OpenSSL
// reads as "any purpose"; its CN is a client_id. An X509-SVID carries
// `clientAuth`. With the Root trusted and nothing else changed, every one of
// them would complete a handshake as a VERIFIED client certificate, start a
// sign-on session for its common name, and resolve to a directory entry at the
// XACML and SCIM doors. That is the widening this gate refuses.
//
// SO A CHAIN THROUGH A HELD AUTHORITY IS AN IDENTITY ONLY WHEN ALL OF THIS IS
// TRUE, and otherwise it is reported as `issuedHere` and `accepted: false`:
//
//   * the leaf was signed by a realm Issuing CA in `IDENTITY_USE_CASES` (below)
//     — found by NAME AND SIGNATURE through `revocation_status.js`'s walk,
//     because two authorities here share a subject and only the key tells
//     them apart;
//   * it carries `clientAuth` in its extended key usage;
//   * its subjectAltName names exactly ONE `urn:sts:person:` or
//     `urn:sts:application:` entry, which is the identity;
//   * for this module's own `tls-client` authority, that name is also the CN
//     — `issue()` writes both from one name, so a leaf whose CN and SAN
//     disagree is somebody else's construction and is refused rather than
//     believed on its CN.
//
// A chain through NO authority this process holds is not this module's
// business and is answered `issuedHere: false`: that is an anchor somebody
// installed through /tls/trust, and every door treats it exactly as before.
//
// ---------------------------------------------------------------------------
// THE REALM IS THE ISSUING CA'S.
//
// A socket is shared by every realm and has no path to put a realm in. A
// certificate from `acme`'s `tls-client` Issuing CA therefore names its realm
// by WHO SIGNED IT, and `identityOf()` answers `realm`. `GET /tls/sign-in`
// starts the session in that realm; the doors that read a certificate under an
// ambient realm refuse a certificate from another realm's authority
// (`checkSocket()`), for the reason `pki.verifyLeaf()` requires this realm's
// own Intermediate on an assertion's path.
// ===========================================================================

const nodeCrypto = require('crypto');
const { log } = require('./helpers');
const config = require('./config');
const realms = require('./realms');
const errorCodes = require('./error_codes');
const pki = require('./pki');
const keyMaterial = require('./vendored/key_material');

const USE_CASE = 'tls-client';

// What a browser and every TLS stack worth talking to will present: RSA and the
// two NIST curves every client library signs a CertificateVerify with. The
// Edwards and post-quantum keys `pki.js` can generate are not in any browser's
// client-certificate support, and a certificate that installs and is then never
// offered is the worst version of this feature. RSA 2048 is the default because
// it is the one every certificate store on every operating system imports.
const KEY_ALGS = ['rsa-2048', 'rsa-3072', 'ec-p256', 'ec-p384'];
const DEFAULT_KEY_ALG = 'rsa-2048';

// The two RFC 5280 reasons a person can honestly give about their own
// certificate. `cessationOfOperation` is "I stopped using it"; `keyCompromise`
// is "somebody else may have the key". The others are an authority's to state.
const REVOCATION_REASONS = ['cessationOfOperation', 'keyCompromise'];

// ---------------------------------------------------------------------------
// THE AUTHORITIES WHOSE clientAuth LEAVES ARE IDENTITIES, AND ONLY THESE.
//
// `tls-client` is this module's own. `acme`, `est` and `scep` are the three
// enrollment protocols' (`common/cert_enrollment.ts`, the same day), whose
// leaves are issued to a directory entry and name it in a `urn:sts:person:` or
// `urn:sts:application:` subjectAltName — a certificate somebody enrolled for a
// TLS client is exactly as much an identity as one issued on the portal. What
// stays OUT is every authority that issues keys for a purpose that is not
// "this is who is connecting": JOSE and XML signing, the assertion key pairs,
// SPIFFE (whose identities are SPIFFE IDs at the SPIRE Server API, not people
// at a sign-in), this service's own TLS server certificates (`tls`) and a
// remote PEP's.
// ---------------------------------------------------------------------------
const IDENTITY_USE_CASES = ['tls-client', 'acme', 'est', 'scep'];

const CLIENT_AUTH_OID = '1.3.6.1.5.5.7.3.2';
const PERSON_URN = 'urn:sts:person:';
const APPLICATION_URN = 'urn:sts:application:';
const PKCS12_PASSWORD_MIN = 8;

// ---------------------------------------------------------------------------
// TWO KINDS OF HOLDER SINCE 2026-09-13, AND THE SLOT SAYS WHICH.
//
// A person holds one to sign in from a browser; an APPLICATION holds one to
// authenticate at the token endpoint under RFC 8705 section 2.1 and to bind
// its access tokens under section 3. Issued from the same `tls-client` Issuing
// CA, with the same clientAuth, because they are the same kind of credential
// — what differs is the urn: the subjectAltName carries, and that is what
// every door reads. `KINDS` is the one table of the two spellings.
// ---------------------------------------------------------------------------
const KINDS = {
  person: { slot: 'person:', urn: PERSON_URN,
            setting: 'pki.personTlsClientCertificateMax',
            capCode: 'STS-PKI-0170', notHeldCode: 'STS-PKI-0171' },
  application: { slot: 'application:', urn: APPLICATION_URN,
                 setting: 'pki.applicationTlsClientCertificateMax',
                 capCode: 'STS-PKI-0180', notHeldCode: 'STS-PKI-0181' }
};

// ---------------------------------------------------------------------------
// THE SLOT NAMES THE HOLDER, AND THAT IS WHERE "WHOSE CERTIFICATE" LIVES.
//
// `pki.certify()` records a certificate under `<use case>:<slot>`, so a slot of
// `person:<username>:<random>` is one record per certificate, several per
// person, and a holder that can be read back without a second store. A second
// store — an attribute on the person's entry — would be a second answer to
// "which certificates does alice hold" that a rebuilt branch, a revocation on
// /admin/pki and a realm purge would each have to remember to update.
// ---------------------------------------------------------------------------
function kindOf(kind) {
  log.debug("Entering kindOf().");
  const id = kind === undefined || kind === null || kind === ''
    ? 'person' : String(kind);
  log.debug("Leaving kindOf().");
  return KINDS[id] ? id : null;
}

function slotFor(holder, kind) {
  log.debug("Entering slotFor().");
  const k = kindOf(kind) || 'person';
  log.debug("Leaving slotFor().");
  return KINDS[k].slot + String(holder) + ':' +
    nodeCrypto.randomBytes(6).toString('hex');
}

// `{ kind, id }` for a slot this module wrote, or null.
function slotHolder(slot) {
  log.debug("Entering slotHolder().");
  const text = String(slot || '');
  const found = /^(person|application):(.+):[0-9a-f]{12}$/.exec(text);
  log.debug("Leaving slotHolder().");
  return found ? { kind: found[1], id: found[2] } : null;
}

// The PERSON a slot names, or null — what every caller before applications
// could hold one asked, and still asks.
function holderOfSlot(slot) {
  log.debug("Entering holderOfSlot().");
  const holder = slotHolder(slot);
  log.debug("Leaving holderOfSlot().");
  return holder && holder.kind === 'person' ? holder.id : null;
}

function scopeOf(realmId) {
  log.debug("Entering scopeOf().");
  const id = realmId ? String(realmId) : realms.currentId();
  log.debug("Leaving scopeOf().");
  return id;
}

function maxPerPerson() {
  log.debug("Entering maxPerPerson().");
  log.debug("Leaving maxPerPerson().");
  return Number(config.value('pki.personTlsClientCertificateMax'));
}

function maxPerHolder(kind) {
  log.debug("Entering maxPerHolder().");
  const k = kindOf(kind) || 'person';
  log.debug("Leaving maxPerHolder().");
  return Number(config.value(KINDS[k].setting));
}

// Revocation is `pki_revocation.js`'s, required lazily for the reason `pki.js`
// requires it lazily: that module requires `pki.js`, and this one is loaded by
// modules `pki.js`'s callers load.
function revocation() {
  log.debug("Entering revocation().");
  log.debug("Leaving revocation().");
  return require('./pki_revocation');
}

// ---------------------------------------------------------------------------
// WHAT ONE PERSON HOLDS, newest first, each with the state a person needs to
// read: valid, expired, or revoked with its reason. `superseded` is a
// revocation like any other — it is what a rebuilt branch writes — and it is reported as
// what it is rather than folded into "revoked".
// ---------------------------------------------------------------------------
function listFor(realmId, username, kind) {
  log.debug("Entering listFor().");
  const scope = scopeOf(realmId);
  const wanted = String(username || '');
  const wantedKind = kindOf(kind) || 'person';
  const now = Date.now();
  const rows = pki.certificatesFor(scope, USE_CASE).filter(function (one) {
    const holder = slotHolder(one.slot);
    return !!holder && holder.kind === wantedKind && holder.id === wanted;
  }).map(function (one) {
    let revoked = null;
    try {
      revoked = revocation().isRevoked(scope, USE_CASE, one.serialHex);
    } catch (e) {
      // No revocation register in this process. The certificate is reported
      // on its validity alone, which is all such a process could check.
      log.debug("Caught in listFor(): " + ((e && e.message) || e));
      revoked = null;
    }
    const expired = new Date(one.notAfter).getTime() < now;
    return {
      slot: one.slot,
      label: one.label,
      serialHex: one.serialHex,
      subject: one.subject,
      keyAlg: one.keyAlg,
      notBefore: one.notBefore,
      notAfter: one.notAfter,
      thumbprint: one.thumbprint,
      createdAt: one.createdAt,
      state: revoked ? (revoked.reason === 'superseded' ? 'superseded'
                                                       : 'revoked')
                     : (expired ? 'expired' : 'valid'),
      revokedAt: revoked ? revoked.revokedAt : null,
      reason: revoked ? revoked.reason : null,
      certificatePem: one.certificatePem
    };
  });
  log.debug("Leaving listFor(). " + rows.length + " held.");
  return rows;
}

function activeFor(realmId, username, kind) {
  log.debug("Entering activeFor().");
  log.debug("Leaving activeFor().");
  return listFor(realmId, username, kind).filter(function (one) {
    return one.state === 'valid';
  });
}

// A label is what a person calls the device — "work laptop" — and it lands in
// the certificate register and on this person's own page. Letters, digits,
// spaces and a little punctuation, because it is also the friendly name inside
// the PKCS#12, which several certificate stores draw verbatim.
function labelProblem(label) {
  log.debug("Entering labelProblem().");
  const text = String(label || '');
  log.debug("Leaving labelProblem().");
  return text.length <= 40 && /^[A-Za-z0-9 ._()-]*$/.test(text)
    ? ''
    : 'A name for the certificate is at most 40 letters, digits, spaces, ' +
      'dots, dashes, underscores and brackets.';
}

// ---------------------------------------------------------------------------
// ISSUE ONE.
//
// **THE CALLER HAS ALREADY DECIDED WHO.** `username` is the signed-in person's
// — `/portal/signing-key` reads it from the session and has no parameter for
// it — and this function has no opinion about sessions. What it does decide:
// the key algorithm is one a browser presents, the cap is not reached, and the
// realm's `tls-client` Issuing CA exists (built, or topped up under the
// existing Intermediate by `ensureScope()`, which never rebuilds a branch that
// only lacks this use case).
//
// **`certify()` AND NOT `issueUnder()`**, for `issueTlsServerKeyPair()`'s
// reason: a certificate a person keeps for a year names its issuer's CRL and
// OCSP responder, and a responder with no record of the serial answers
// `unknown` about a certificate that sends a relying party there to ask.
// ---------------------------------------------------------------------------
async function issue(realmId, spec) {
  log.debug("Entering issue().");
  const scope = scopeOf(realmId);
  const s = spec || {};
  // WHO. A person by `username` (what every caller before 2026-09-13 passes),
  // or an application by `application` with `kind: 'application'` — the
  // application's identifier in the registry, which is what the
  // urn:sts:application: name carries and what RFC 8705's implicit mapping at
  // the token endpoint resolves back to the entry.
  const kind = kindOf(s.kind);
  if (!kind) {
    log.debug("Leaving issue(). Unknown kind of holder.");
    return errorCodes.mark({ ok: false,
             errors: ['A TLS client certificate is issued to a person or to ' +
                      'an application.'] }, 'STS-PKI-0168');
  }
  const username = String((kind === 'application' ? s.application
                                                   : s.username) || '');
  if (!username) {
    log.debug("Leaving issue(). No holder.");
    return errorCodes.mark({ ok: false,
             errors: ['A TLS client certificate is issued TO somebody.'] },
                           'STS-PKI-0168');
  }
  if (username.length > 256 || /[ -]/.test(username)) {
    log.debug("Leaving issue(). Holder name refused.");
    return errorCodes.mark({ ok: false,
             errors: ['The holder is named by a printable identifier of at ' +
                      'most 256 characters.'] }, 'STS-PKI-0168');
  }
  const keyAlgId = String(s.keyAlg || DEFAULT_KEY_ALG);
  const keyDesc = keyMaterial.keyAlg(keyAlgId);
  if (!keyDesc || KEY_ALGS.indexOf(keyAlgId) < 0) {
    log.debug("Leaving issue(). Key algorithm refused.");
    return errorCodes.mark({ ok: false,
             errors: ['"' + keyAlgId + '" is not a key algorithm a TLS ' +
                      'client certificate is issued with here. It may be ' +
                      KEY_ALGS.join(', ') + '.'] }, 'STS-PKI-0169');
  }
  const labelSaid = labelProblem(s.label);
  if (labelSaid) {
    log.debug("Leaving issue(). Label refused.");
    return errorCodes.mark({ ok: false, errors: [labelSaid] }, 'STS-PKI-0169');
  }
  // THE CAP COUNTS WHAT STILL WORKS. A revoked or expired certificate cannot
  // sign anybody in, so it is not one of the "five devices" the number means;
  // counting it would make revoking an old laptop's certificate unable to make
  // room for the new laptop's.
  const active = activeFor(scope, username, kind);
  if (active.length >= maxPerHolder(kind)) {
    log.debug("Leaving issue(). The cap is reached.");
    return errorCodes.mark({ ok: false,
             errors: [kind === 'application'
               ? 'The application "' + username + '" already holds ' +
                 active.length + ' TLS client certificate(s) that are still ' +
                 'valid, which is ' + KINDS.application.setting + '. Revoke ' +
                 'one it no longer uses and issue again.'
               : 'You already hold ' + active.length + ' TLS client ' +
                 'certificate(s) that are still valid, which is the ' +
                 'most this service issues to one person. Revoke one ' +
                 'you no longer use and generate again.'] },
                           KINDS[kind].capCode);
  }
  const branch = await pki.ensureScope(scope);
  if (!branch || !branch.ok) {
    log.debug("Leaving issue(). No branch.");
    return branch || errorCodes.mark({ ok: false,
             errors: ['This realm has no certificate authority.'] },
                                     'STS-PKI-0009');
  }

  // EXPIRED RECORDS OF THIS PERSON'S ARE FORGOTTEN BEFORE ONE IS ADDED — RFC
  // 5280 section 3.3 lets a list forget an expired certificate, and a register
  // that kept every certificate a person ever held would grow for as long as
  // they kept replacing laptops. A REVOKED one that has not expired stays: its
  // record is what lets this person's page say it was revoked.
  const now = Date.now();
  pki.certificatesFor(scope, USE_CASE).forEach(function (one) {
    const holder = slotHolder(one.slot);
    if (holder && holder.kind === kind && holder.id === username &&
        new Date(one.notAfter).getTime() < now) {
      pki.forgetCertificate(scope, USE_CASE, one.slot);
    }
  });

  const pair = await keyMaterial.generateKeyPair(keyAlgId);
  const names = [{ kind: 'uri', value: KINDS[kind].urn + username }];
  const email = kind === 'person' ? String(s.email || '').trim() : '';
  if (email && /^[^\s@]+@[^\s@]+$/.test(email)) {
    // RFC 5280 section 4.2.1.6's rfc822Name. It is what several browsers and
    // most operating system certificate pickers show beside the common name,
    // and it is taken from the person's own directory entry rather than typed.
    names.push({ kind: 'email', value: email });
  }
  const slot = slotFor(username, kind);
  const made = await pki.certify(scope, USE_CASE, {
    slot: slot,
    holderSubject: kind === 'person' && realms.get(scope)
      ? realms.run(realms.get(scope), function () {
        return require('./helpers').subjectForName(username);
      }) : '',
    label: String(s.label || '') || 'TLS client certificate',
    commonName: username,
    keyAlg: keyAlgId,
    publicKeyPem: pair.publicPem,
    profile: 'tls-client',
    days: s.days,
    // keyEncipherment only where the key can do it — `issueTlsServerKeyPair()`
    // says why a KeyUsage naming a use the key cannot perform is refused by a
    // strict peer.
    keyUsage: keyDesc.kind === 'rsa' ? ['digitalSignature', 'keyEncipherment']
                                     : ['digitalSignature'],
    extensions: {
      extKeyUsage: { present: true, critical: false, usages: ['clientAuth'] },
      subjectAltName: { present: true, critical: false, names: names }
    }
  });
  if (!made.ok) {
    log.debug("Leaving issue(). certify() refused.");
    return made;
  }
  const root = pki.serviceRoot();
  log.info('tls-client: a ' + keyDesc.label + ' TLS client certificate was ' +
           'issued to the ' + kind + ' ' + username + ' in "' + scope +
           '", serial ' +
           made.record.serialHex + ', expires ' + made.record.notAfter +
           '. The private key was handed to the caller and is not kept.');
  log.debug("Leaving issue().");
  return {
    ok: true,
    issued: {
      scope: scope,
      slot: slot,
      label: made.record.label,
      kind: kind,
      username: username,
      keyAlg: keyAlgId,
      keyDesc: keyDesc,
      serialHex: made.record.serialHex,
      subject: made.record.subject,
      notBefore: made.record.notBefore,
      notAfter: made.record.notAfter,
      thumbprint: made.record.thumbprint,
      certificatePem: made.record.certificatePem,
      chainPem: (made.record.chainPem || []).slice(),
      publicKeyPem: pair.publicPem,
      privateKeyPem: pair.privatePem,
      rootPem: root ? root.certificatePem : ''
    }
  };
}

// ---------------------------------------------------------------------------
// PACKAGE WHAT `issue()` HANDED BACK.
//
// Three files, all protected by the one password the person chose:
//
//   * `<name>.p12` — the key, the leaf and the chain above it (Issuing CA and
//     Intermediate; the Root is an anchor and is not shipped, which is what a
//     browser's certificate store expects). PBES2 with AES-256-CBC, PBKDF2 and
//     an HMAC-SHA-256 MAC, which is what the vendored exporter writes;
//   * `<name>-key.pem` — the same key as an ENCRYPTED PKCS#8 block, for curl
//     and openssl (`--key … --pass …`);
//   * `<name>-chain.pem` — the leaf then its issuers, public.
//
// **THE PASSWORD IS NEVER STORED, LOGGED OR AUDITED**, and it is not this
// service's credential for anything: it protects a file on somebody's disk.
// ---------------------------------------------------------------------------
function pkcs12PasswordProblem(password, confirm) {
  log.debug("Entering pkcs12PasswordProblem().");
  const text = String(password || '');
  if (text.length < PKCS12_PASSWORD_MIN || text.length > 256) {
    log.debug("Leaving pkcs12PasswordProblem(). Length.");
    return 'The file password is between ' + PKCS12_PASSWORD_MIN + ' and 256 ' +
      'characters. It protects the private key while the file is on your ' +
      'disk, and a browser asks for it once, when you import the file.';
  }
  if (confirm !== undefined && String(confirm) !== text) {
    log.debug("Leaving pkcs12PasswordProblem(). Mismatch.");
    return 'The two file passwords you typed are not the same.';
  }
  log.debug("Leaving pkcs12PasswordProblem().");
  return '';
}

function fileStem(issued) {
  log.debug("Entering fileStem().");
  const base = (String(issued.username) + (issued.label &&
    issued.label !== 'TLS client certificate' ? '-' + issued.label : ''))
    .replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  log.debug("Leaving fileStem().");
  return (base || 'client') + '-tls-client';
}

async function bundle(issued, password) {
  log.debug("Entering bundle().");
  const stem = fileStem(issued);
  const certs = [issued.certificatePem].concat(issued.chainPem || []);
  const friendly = String(issued.username) + ' (' + issued.label + ')';
  const p12 = await keyMaterial.exportKeyPair({
    format: 'pkcs12', password: String(password),
    privatePem: issued.privateKeyPem, publicPem: issued.publicKeyPem,
    desc: issued.keyDesc, certs: certs, baseName: stem,
    friendlyName: friendly
  });
  const pem = await keyMaterial.exportKeyPair({
    format: 'pem', password: String(password),
    privatePem: issued.privateKeyPem, publicPem: issued.publicKeyPem,
    desc: issued.keyDesc, certs: [], baseName: stem + '-key'
  });
  const p12File = p12.files[0];
  const pemFile = pem.files[0];
  log.debug("Leaving bundle().");
  return {
    pkcs12: { name: stem + '.p12', mime: 'application/x-pkcs12',
              base64: Buffer.from(p12File.data).toString('base64') },
    key: { name: stem + '-key.pem', mime: 'application/x-pem-file',
           text: typeof pemFile.data === 'string'
             ? pemFile.data : Buffer.from(pemFile.data).toString('utf8') },
    chain: { name: stem + '-chain.pem', mime: 'application/x-pem-file',
             text: certs.map(function (one) {
               return String(one).trim() + '\n';
             }).join('') }
  };
}

// ---------------------------------------------------------------------------
// REVOKE ONE OF YOUR OWN.
//
// **THE SERIAL IS LOOKED UP AMONG THIS PERSON'S CERTIFICATES** and nowhere
// else, which is `credentials.removeKey()`'s rule: a serial belonging to
// somebody else matches nothing, so the route taking one from a form body
// cannot be used to revoke another person's certificate.
// ---------------------------------------------------------------------------
function revoke(realmId, username, serialHex, reasonId, kind) {
  log.debug("Entering revoke().");
  const scope = scopeOf(realmId);
  const holderKind = kindOf(kind) || 'person';
  const reason = REVOCATION_REASONS.indexOf(String(reasonId)) >= 0
    ? String(reasonId) : 'cessationOfOperation';
  let normal;
  try {
    normal = revocation().normalSerial(serialHex);
  } catch (e) {
    log.debug("Caught in revoke(): " + ((e && e.message) || e));
    normal = String(serialHex || '').toLowerCase();
  }
  const mine = listFor(scope, username, holderKind).filter(function (one) {
    return revocation().normalSerial(one.serialHex) === normal;
  })[0];
  if (!mine) {
    log.debug("Leaving revoke(). Not one of theirs.");
    return errorCodes.mark({ ok: false,
             errors: [holderKind === 'application'
               ? 'The application "' + username + '" holds no TLS client ' +
                 'certificate with that serial number.'
               : 'You hold no TLS client certificate with that serial ' +
                 'number.'] }, KINDS[holderKind].notHeldCode);
  }
  const done = revocation().revoke(scope, USE_CASE, {
    serialHex: mine.serialHex,
    reason: reason,
    subject: mine.subject,
    note: holderKind === 'application'
      ? 'revoked for the application ' + username + ' by an administrator'
      : 'revoked by ' + username + ' on the user portal'
  });
  log.debug("Leaving revoke(). ok=" + !!done.ok);
  return Object.assign({ certificate: mine, reason: reason }, done);
}

// ---------------------------------------------------------------------------
// THE ANCHOR THE CLIENT TRUSTSTORE ADDS, or '' when it adds none.
//
// Read per call, so a Root rebuilt on /admin/pki is what the next
// `applyAnchors()` hands OpenSSL — `tls_server.js` re-applies its context when
// the listener is re-certified under the new Root, which is exactly the moment
// this answer changes.
// ---------------------------------------------------------------------------
function trustAnchorPem() {
  log.debug("Entering trustAnchorPem().");
  if (config.value('tls.trustIssuedClientCertificates') === false) {
    log.debug("Leaving trustAnchorPem(). Off.");
    return '';
  }
  let root = null;
  try {
    root = pki.serviceRoot();
  } catch (e) {
    // A process with no hierarchy — `npm test`, a supplied certificate with
    // no PKI started. Nothing to trust.
    log.debug("Caught in trustAnchorPem(): " + ((e && e.message) || e));
    root = null;
  }
  log.debug("Leaving trustAnchorPem().");
  return (root && root.certificatePem) || '';
}

// ---------------------------------------------------------------------------
// RECOGNISE.
//
// `input` is `revocation_status.fromSocket()`'s shape — `{ leaf, chain,
// verified }` — which is what makes one function serve a real socket on the
// main port and a request worker's shim for a dispatched request.
//
// The walk is memoised by the leaf's digest AND by which authorities are held:
// a replaced Issuing CA is a different authority, and a memo that outlived it
// would recognise a certificate its successor never issued.
// ---------------------------------------------------------------------------
const memo = new Map();
const MEMO_ENTRIES = 256;

function subjectCnOf(x509) {
  log.debug("Entering subjectCnOf().");
  const found = /(?:^|\n)CN=([^\n]*)/
    .exec(String((x509 && x509.subject) || ''));
  log.debug("Leaving subjectCnOf().");
  return found ? found[1] : '';
}

// ---------------------------------------------------------------------------
// WHO HOLDS AN ACCEPTED PERSON'S CERTIFICATE NOW (2026-09-14).
//
// A certificate names a person as they were CALLED when it was issued — the
// CN, the `urn:sts:person:` SAN and the register's slot all carry that name.
// A rename leaves the certificate naming nobody, and a name deleted and
// re-created would hand it to a different person: the account-recycling hole
// a stable subject exists to close. So where the issuing record carries the
// holder's `urn:uuid:` subject, the directory says who that is today, and a
// subject naming nobody refuses the certificate. A record written before the
// subject was recorded is answered by its name, as before.
//
// Asked per call and never memoised, because the answer is the directory's.
// ---------------------------------------------------------------------------
function currentHolderOf(answer) {
  log.debug("Entering currentHolderOf().");
  if (!answer || !answer.accepted || answer.kind !== 'person' ||
      !answer.authority) {
    log.debug("Leaving currentHolderOf(). Nothing to resolve.");
    return answer;
  }
  let normal = function (serial) {
    return String(serial || '').toLowerCase().replace(/^0+/, '');
  };
  try {
    normal = revocation().normalSerial;
  } catch (e) {
    log.debug("Caught in currentHolderOf(): " + ((e && e.message) || e));
  }
  const serial = normal(answer.serialHex);
  const ca = String(answer.authority.ca);
  const records = ca === USE_CASE
    ? pki.certificatesFor(answer.realm, USE_CASE)
    : pki.issuedKeyPairsFor(answer.realm, ca);
  const record = records.filter(function (one) {
    return one && normal(one.serialHex) === serial;
  })[0];
  const subject = record && record.holderSubject;
  if (!subject) {
    log.debug("Leaving currentHolderOf(). No subject recorded.");
    return answer;
  }
  const realm = realms.get(answer.realm);
  const named = realm ? realms.run(realm, function () {
    return require('./helpers').nameForSubject(subject);
  }) : '';
  if (!named) {
    log.debug("Leaving currentHolderOf(). The holder is gone.");
    return { issuedHere: true, accepted: false, error: 'HOLDER_GONE',
             why: 'the certificate was issued to the person "' +
                  answer.username + '", whose directory entry is gone; a ' +
                  'person created since under that name is somebody else',
             authority: answer.authority, serialHex: answer.serialHex };
  }
  log.debug("Leaving currentHolderOf(). " + named);
  return named === answer.username ? answer
    : Object.assign({}, answer, { username: named,
                                  certifiedName: answer.username });
}

function identityOf(input) {
  log.debug("Entering identityOf().");
  if (!input || !input.leaf || input.verified !== true) {
    log.debug("Leaving identityOf(). Nothing verified.");
    return { issuedHere: false, accepted: false };
  }
  let status;
  try {
    status = require('./revocation_status');
  } catch (e) {
    log.debug("Caught in identityOf(): " + ((e && e.message) || e));
    log.debug("Leaving identityOf(). No revocation walk in this process.");
    return { issuedHere: false, accepted: false };
  }
  const leafBytes = Buffer.isBuffer(input.leaf) ? input.leaf
                                                : Buffer.from(input.leaf);
  const heldKey = (typeof status.heldAuthorityKey === 'function')
    ? status.heldAuthorityKey() : '';
  const key = nodeCrypto.createHash('sha256').update(leafBytes)
    .digest('hex') + '|' + heldKey;
  if (memo.has(key)) {
    log.debug("Leaving identityOf(). Memoised.");
    return currentHolderOf(memo.get(key));
  }
  const walked = status.walk(input);
  const links = (walked && walked.links) || [];
  const held = links.filter(function (one) {
    return one.source === 'register';
  });
  let answer;
  if (!held.length) {
    answer = { issuedHere: false, accepted: false };
  } else {
    const first = links[0];
    const leaf = new nodeCrypto.X509Certificate(leafBytes);
    const commonName = subjectCnOf(leaf);
    const eku = Array.isArray(leaf.keyUsage) ? leaf.keyUsage : [];
    const uris = String(leaf.subjectAltName || '').split(/,\s*/)
      .filter(function (one) { return one.indexOf('URI:') === 0; })
      .map(function (one) { return one.slice(4); });
    const named = function (prefix) {
      log.debug("Entering named().");
      const all = uris.filter(function (one) {
        return one.indexOf(prefix) === 0 && one.length > prefix.length;
      }).map(function (one) { return one.slice(prefix.length); });
      log.debug("Leaving named().");
      return all;
    };
    const people = named(PERSON_URN);
    const applications = named(APPLICATION_URN);
    const authority = first && first.authority ? first.authority : null;
    const scope = authority ? String(authority.scope) : '';
    const isRealmScope = !!authority && scope !== pki.SERVICE_SCOPE &&
                         scope !== pki.PROCESS_SCOPE;
    let why = '';
    let error = '';
    let kind = 'person';
    let name = '';
    if (!(first && first.source === 'register' && authority &&
          IDENTITY_USE_CASES.indexOf(authority.ca) >= 0 && isRealmScope)) {
      error = 'NOT_A_TLS_CLIENT_CERTIFICATE';
      why = 'the certificate chains to this service\'s own Root, but it was ' +
            'not issued by a realm\'s TLS client or enrollment Issuing CA' +
            (authority ? ' (it was signed by the "' + authority.ca + '" ' +
                         'authority)' : '') + '. Every key pair this service ' +
            'issues chains to that Root, so the Root alone vouches for ' +
            'nothing: only a TLS client certificate issued on the user ' +
            'portal, or one enrolled over ACME, EST or SCEP, is an identity ' +
            'here';
    } else if (eku.indexOf(CLIENT_AUTH_OID) < 0) {
      error = 'NOT_A_TLS_CLIENT_CERTIFICATE';
      why = 'the certificate was issued by the "' + authority.ca + '" ' +
            'authority and does not carry clientAuth in its extended key usage';
    } else if (people.length + applications.length !== 1) {
      error = 'NOT_A_TLS_CLIENT_CERTIFICATE';
      why = 'the certificate does not name exactly one person or application ' +
            'in a urn:sts:person: or urn:sts:application: subjectAltName, ' +
            'so there is no one entry it could be the identity of';
    } else if (authority.ca === USE_CASE &&
               (people.length ? people[0] : applications[0]) !== commonName) {
      // `issue()` writes the CN and the SAN from one name — a username, or
      // since 2026-09-13 an application's identifier. A TLS client leaf where
      // they differ was not built by it, and it is refused rather than
      // believed on whichever of the two a door would read.
      error = 'NOT_A_TLS_CLIENT_CERTIFICATE';
      why = 'the certificate\'s common name and its ' +
            (people.length ? 'urn:sts:person:' : 'urn:sts:application:') +
            ' subjectAltName do not name the same ' +
            (people.length ? 'person' : 'application');
    } else if (!realms.get(scope)) {
      error = 'REALM_GONE';
      why = 'the certificate was issued in the "' + scope + '" realm, which ' +
            'no longer exists';
    } else {
      kind = people.length ? 'person' : 'application';
      name = people.length ? people[0] : applications[0];
    }
    answer = error
      ? { issuedHere: true, accepted: false, error: error, why: why,
          authority: authority, serialHex: first ? first.serialHex : '' }
      : { issuedHere: true, accepted: true, realm: scope, kind: kind,
          username: name, subject: leaf.subject,
          serialHex: first.serialHex, authority: authority,
          why: 'issued to the ' + kind + ' ' + name + ' by the "' + scope +
               '" realm\'s "' + authority.ca + '" Issuing CA' };
  }
  if (memo.size >= MEMO_ENTRIES) {
    memo.clear();
  }
  memo.set(key, answer);
  log.debug("Leaving identityOf(). issuedHere=" + answer.issuedHere +
            " accepted=" + answer.accepted);
  return currentHolderOf(answer);
}

// ---------------------------------------------------------------------------
// DOES THE ENTRY A CERTIFICATE NAMES STILL LIST IT (2026-09-13).
//
// `identityOf()` answers who a certificate was ISSUED to, from the certificate
// alone. RFC 8705's implicit mapping at the token endpoint needs one more
// fact, which is `cert_enrollment.js`'s rule for EST re-enrollment read again:
// a certificate the holder's record no longer lists is not that holder's
// credential, however well it verifies. For this module's own authority that
// record is the `pki.certify()` register under the holder's slot; for the
// three enrollment authorities it is the certificate on the entry, found
// through `cert_enrollment.findEnrolled()` in the certificate's realm.
//
// Revocation is NOT asked here: the door's revocation verdict
// (`req.certificateRevocation`, `revocation_status.js`'s annotation) already
// refused a revoked certificate before this is reached, and a second answer to
// "is it revoked" is the one that disagrees with the first.
// ---------------------------------------------------------------------------
function stillHeld(identity) {
  log.debug("Entering stillHeld().");
  if (!identity || !identity.accepted || !identity.authority) {
    log.debug("Leaving stillHeld(). Not an accepted identity.");
    return false;
  }
  const scope = String(identity.realm);
  const ca = String(identity.authority.ca);
  let normal = null;
  try {
    normal = revocation().normalSerial;
  } catch (e) {
    log.debug("Caught in stillHeld(): " + ((e && e.message) || e));
    normal = function (serial) {
      return String(serial || '').toLowerCase().replace(/^0+/, '');
    };
  }
  const serial = normal(identity.serialHex);
  if (ca === USE_CASE) {
    const held = pki.certificatesFor(scope, USE_CASE).some(function (one) {
      const holder = slotHolder(one.slot);
      return !!holder && holder.kind === identity.kind &&
             holder.id === (identity.certifiedName || identity.username) &&
             normal(one.serialHex) === serial;
    });
    log.debug("Leaving stillHeld(). tls-client register: " + held);
    return held;
  }
  const realm = realms.get(scope);
  if (!realm) {
    log.debug("Leaving stillHeld(). The realm is gone.");
    return false;
  }
  let found = null;
  try {
    found = realms.run(realm, function () {
      return require('./cert_enrollment').findEnrolled(identity.serialHex, ca);
    });
  } catch (e) {
    log.debug("Caught in stillHeld(): " + ((e && e.message) || e));
    found = null;
  }
  const held = !!(found && found.entry && found.entry.kind === identity.kind &&
                  String(found.entry.id) === identity.username);
  log.debug("Leaving stillHeld(). Enrolled record: " + held);
  return held;
}

// ---------------------------------------------------------------------------
// THE DOORS ON THE MAIN PORT, which have an ambient realm.
//
// `{ ok: true }` for a certificate this module has no opinion about (none,
// unverified, or from an anchor somebody installed) and for a TLS client
// certificate from THIS realm's authority; `{ ok: false, error, why }` for a
// certificate this service issued for something else, or one from another
// realm's authority.
// ---------------------------------------------------------------------------
function checkSocket(socket) {
  log.debug("Entering checkSocket().");
  let input = null;
  try {
    input = require('./revocation_status').fromSocket(socket);
  } catch (e) {
    log.debug("Caught in checkSocket(): " + ((e && e.message) || e));
    input = null;
  }
  const identity = identityOf(input);
  if (!identity.issuedHere) {
    log.debug("Leaving checkSocket(). Not ours.");
    return { ok: true, identity: identity };
  }
  if (!identity.accepted) {
    log.debug("Leaving checkSocket(). Refused.");
    return { ok: false, identity: identity, error: identity.error,
             why: identity.why };
  }
  const ambient = realms.currentId();
  if (identity.realm !== ambient) {
    log.debug("Leaving checkSocket(). Another realm's.");
    return { ok: false, identity: identity, error: 'OTHER_REALM',
             why: 'the certificate is a TLS client certificate issued in the ' +
                  '"' + identity.realm + '" realm and this request is in "' +
                  ambient + '"; a realm\'s authority vouches for that ' +
                  'realm\'s ' +
                  'people and nobody else\'s' };
  }
  log.debug("Leaving checkSocket(). Accepted.");
  return { ok: true, identity: identity };
}

// What `/tls` and the portal page say about this arrangement.
function report() {
  log.debug("Entering report().");
  const on = config.value('tls.trustIssuedClientCertificates') !== false;
  const anchor = trustAnchorPem();
  let rootSubject = '';
  try {
    const root = pki.serviceRoot();
    rootSubject = root ? root.subject : '';
  } catch (e) {
    log.debug("Caught in report(): " + ((e && e.message) || e));
    rootSubject = '';
  }
  log.debug("Leaving report().");
  return {
    enabled: on,
    trusted: !!anchor,
    rootSubject: rootSubject,
    useCase: USE_CASE,
    keyAlgorithms: KEY_ALGS.slice(),
    defaultKeyAlg: DEFAULT_KEY_ALG,
    maxPerPerson: maxPerPerson(),
    note: !on
      ? 'tls.trustIssuedClientCertificates is off, so the TLS listeners do ' +
        'not trust this service\'s Root and a certificate issued on the user ' +
        'portal verifies only where somebody added that Root at /tls/trust.'
      : (anchor
        ? 'The TLS listeners trust this service\'s Root for client ' +
          'certificates, and a chain through it is an identity only when the ' +
          'leaf came from a realm\'s TLS client Issuing CA with clientAuth; ' +
          'every other key pair this service issued is refused as one.'
        : 'This process has no Root CA yet, so there is nothing to trust.')
  };
}

module.exports = {
  USE_CASE: USE_CASE,
  IDENTITY_USE_CASES: IDENTITY_USE_CASES,
  APPLICATION_URN: APPLICATION_URN,
  KEY_ALGS: KEY_ALGS,
  DEFAULT_KEY_ALG: DEFAULT_KEY_ALG,
  REVOCATION_REASONS: REVOCATION_REASONS,
  PKCS12_PASSWORD_MIN: PKCS12_PASSWORD_MIN,
  holderOfSlot: holderOfSlot,
  slotHolder: slotHolder,
  maxPerHolder: maxPerHolder,
  stillHeld: stillHeld,
  listFor: listFor,
  activeFor: activeFor,
  labelProblem: labelProblem,
  issue: issue,
  pkcs12PasswordProblem: pkcs12PasswordProblem,
  bundle: bundle,
  revoke: revoke,
  trustAnchorPem: trustAnchorPem,
  identityOf: identityOf,
  checkSocket: checkSocket,
  report: report
};
