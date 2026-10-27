// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_client_certificate.js
//
// ===========================================================================
// A SHARED SIGNALS RECEIVER AUTHENTICATED BY ITS TLS CLIENT CERTIFICATE
// (#1049, part of #520).
//
// `ssf/ssf_auth.ts`'s fourth scheme, every branch of it, in process. The
// certificate-to-entry mapping is `common/tls_client_certificates.js`'s, and
// `tests/tls_client_certificates.js` holds that; here its two answers
// (`checkSocket()`, `stillHeld()`) are given per request, so each outcome of
// the gate can be put to the door. The scope half is REAL: real
// applications, real SSF_READ and SSF_MANAGE membership, and
// `role_permissions.ts`'s `narrowScope()` under the built-in policy. The wire
// half — certificates this realm issues, presented on the main port — is
// `tests/protocol/sts_ssf_client_certificate.js`.
//
//   1. `authorization_schemes` carries urn:ietf:rfc:8705 while
//      `ssf.authClientCert` is on, and not while it is off — and off, an
//      application's certificate is not taken.
//   2. An application certificate is the application: principal its
//      identifier, owner kind `application`. Declaring `ssf.manage` and in
//      SSF_MANAGE, it reads and writes; declaring `ssf.read` and in SSF_READ
//      it reads and is refused a write (STS-SSF-0149, 403); declaring nothing,
//      or declaring `ssf.manage` with no role, it is refused even a read;
//      declaring both and holding SSF_MANAGE only, it reads.
//   3. An Authorization header decides instead of the certificate; an
//      unverified connection, or a chain to an anchor somebody installed,
//      is not this credential.
//   4. A person's certificate, and one the gate refuses (another realm's),
//      are STS-SSF-0147; one the application no longer holds is 0148; one
//      refused on revocation is 0150, with the certificate's own code
//      audited. None of them is refused on an endpoint that needs nothing.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const applications = require('../common/applications');
// Fills the directory slots the application register and the roles write
// through.
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const ssfAuthModule = require('../ssf/ssf_auth');

const log = require('bunyan').createLogger({ name: 'ssf_client_certificate',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const MANAGE = 'ssfcc-manage-' + RUN;
const READ = 'ssfcc-read-' + RUN;
const NOTHING = 'ssfcc-nothing-' + RUN;
const NOROLE = 'ssfcc-norole-' + RUN;
const BOTH = 'ssfcc-both-' + RUN;
const RFC8705 = 'urn:ietf:rfc:8705';

// What the certificate gate answers, per request: the fake socket carries it.
const audited = [];
const fakeGate = {
  checkSocket: function (socket) {
    log.debug("Entering fakeGate.checkSocket().");
    log.debug("Leaving fakeGate.checkSocket().");
    return socket.gate;
  },
  stillHeld: function (identity) {
    log.debug("Entering fakeGate.stillHeld().");
    log.debug("Leaving fakeGate.stillHeld().");
    return identity.held !== false;
  }
};

const deps = Object.assign(ssfAuthModule.SsfAuth.defaultDeps(), {
  loadTlsClientCertificates: function () {
    return fakeGate;
  },
  loadAudit: function () {
    return {
      failure: function (code) {
        audited.push(code);
      }
    };
  }
});
const gate = new ssfAuthModule.SsfAuth(deps);

function application(name) {
  log.debug("Entering application().");
  log.debug("Leaving application().");
  return { ok: true,
           identity: { issuedHere: true, accepted: true, kind: 'application',
                       username: name, realm: '', serialHex: '0a' + RUN,
                       why: 'issued to the application ' + name } };
}

function request(gateAnswer, extra) {
  log.debug("Entering request().");
  const more = extra || {};
  log.debug("Leaving request().");
  return Object.assign({
    headers: more.headers || {},
    url: '/ssf/stream', originalUrl: '/ssf/stream',
    socket: { authorized: more.authorized !== false,
              getPeerCertificate: function () {
                return {};
              },
              gate: gateAnswer }
  }, more.revocation ? { certificateRevocation: more.revocation } : {});
}

function setUp(t) {
  log.debug("Entering setUp().");
  const rows = [[MANAGE, ['ssf.manage']], [READ, ['ssf.read']],
                [NOTHING, ['openid']], [NOROLE, ['ssf.manage']],
                [BOTH, ['ssf.read', 'ssf.manage']]];
  const made = rows.map(function (row) {
    return applications.createApplication({ identifier: row[0],
      protocols: ['oauth2', 'ssf'],
      fields: { oauthClientId: row[0], oauthAllowedScope: row[1] } });
  });
  t.check(made.every(function (one) {
    return one && one.ok;
  }), 'precondition: the five applications were created',
          JSON.stringify(made));
  const members = [['SSF_MANAGE', MANAGE], ['SSF_READ', READ],
                   ['SSF_MANAGE', BOTH]];
  t.check(members.every(function (row) {
    return adminActions.rolesAction({ action: 'add-member', role: row[0],
      kind: 'application', member: row[1] },
    { actor: 'test', via: 'test' }).ok;
  }), 'precondition: the three applications were added to their roles');
  log.debug("Leaving setUp().");
}

function metadata(t) {
  log.debug("Entering metadata().");
  t.log.info('=== 1. the published scheme and its setting ===');
  t.check(gate.schemesForMetadata().some(function (row) {
    return row.spec_urn === RFC8705;
  }), '1a. authorization_schemes carries urn:ietf:rfc:8705 by default');
  t.check(gate.describe().schemes.some(function (row) {
    return row.id === 'clientcert' && row.offered === true;
  }), '1b. the description the console and /admin-api draw says it is ' +
      'offered');
  config.setOverride('ssf.authClientCert', false);
  try {
    t.check(gate.schemesForMetadata().every(function (row) {
      return row.spec_urn !== RFC8705;
    }), '1c. with ssf.authClientCert off it is not published');
    const off = gate.authenticate(request(application(MANAGE)), 'write');
    t.check(off.scheme !== 'clientcert',
            '1d. and an application\'s certificate is not taken',
            JSON.stringify(off));
  } finally {
    config.clearOverride('ssf.authClientCert');
  }
  log.debug("Leaving metadata().");
}

function accepted(t) {
  log.debug("Entering accepted().");
  t.log.info('=== 2. the application, and what it holds ===');
  const write = gate.authenticate(request(application(MANAGE)), 'write');
  t.check(write.ok && write.scheme === 'clientcert' &&
          write.principal === MANAGE && write.owner &&
          write.owner.kind === 'application',
          '2a. a manage application\'s certificate writes, as the ' +
          'application', JSON.stringify(write));
  t.check(gate.authenticate(request(application(MANAGE)), 'read').ok,
          '2b. and reads, because write includes read');
  t.check(gate.authenticate(request(application(READ)), 'read').ok,
          '2c. a read application reads');
  const readWrite = gate.authenticate(request(application(READ)), 'write');
  t.check(!readWrite.ok && readWrite.status === 403 &&
          readWrite.errorCode === 'STS-SSF-0149' &&
          /ssf\.manage/.test(readWrite.description),
          '2d. and is refused a write, 403 STS-SSF-0149 naming ssf.manage',
          JSON.stringify(readWrite));
  const nothing = gate.authenticate(request(application(NOTHING)), 'read');
  t.check(!nothing.ok && nothing.errorCode === 'STS-SSF-0149' &&
          /declares no Shared Signals scope/.test(nothing.description),
          '2e. an application declaring no SSF scope is refused a read',
          JSON.stringify(nothing));
  const noRole = gate.authenticate(request(application(NOROLE)), 'read');
  t.check(!noRole.ok && noRole.errorCode === 'STS-SSF-0149',
          '2f. one declaring ssf.manage and in no role is refused too',
          JSON.stringify(noRole));
  const both = gate.authenticate(request(application(BOTH)), 'read');
  t.check(both.ok && both.scopes === 'ssf.manage',
          '2g. declaring both and holding SSF_MANAGE alone, it holds ' +
          'ssf.manage and reads', JSON.stringify(both));
  log.debug("Leaving accepted().");
}

function notThisCredential(t) {
  log.debug("Entering notThisCredential().");
  t.log.info('=== 3. not this credential ===');
  const basic = gate.authenticate(request(application(MANAGE), {
    headers: { authorization: 'Basic ' +
      Buffer.from('somebody:x').toString('base64') } }), 'write');
  t.check(basic.scheme === 'basic',
          '3a. an Authorization header decides, not the certificate',
          JSON.stringify(basic));
  const unverified = gate.authenticate(
    request(application(MANAGE), { authorized: false }), 'write');
  t.check(unverified.scheme !== 'clientcert',
          '3b. a certificate that did not verify is not taken',
          JSON.stringify(unverified));
  const foreign = gate.authenticate(
    request({ ok: true, identity: { issuedHere: false, accepted: false } }),
    'write');
  t.check(foreign.scheme !== 'clientcert' &&
          foreign.errorCode !== 'STS-SSF-0147',
          '3c. a chain to an installed anchor names nobody here, and is ' +
          'neither taken nor refused', JSON.stringify(foreign));
  log.debug("Leaving notThisCredential().");
}

function refused(t) {
  log.debug("Entering refused().");
  t.log.info('=== 4. refused ===');
  const person = { ok: true, identity: { issuedHere: true, accepted: true,
    kind: 'person', username: 'somebody', serialHex: '01' } };
  const asPerson = gate.authenticate(request(person), 'read');
  t.check(!asPerson.ok && asPerson.status === 401 &&
          asPerson.errorCode === 'STS-SSF-0147' &&
          /person "somebody"/.test(asPerson.description),
          '4a. a person\'s certificate is STS-SSF-0147',
          JSON.stringify(asPerson));
  const other = { ok: false, error: 'OTHER_REALM',
    why: 'the certificate is a TLS client certificate issued in the "acme" ' +
         'realm', identity: { issuedHere: true, accepted: true,
                              kind: 'application', username: MANAGE } };
  const asOther = gate.authenticate(request(other), 'read');
  t.check(!asOther.ok && asOther.errorCode === 'STS-SSF-0147' &&
          /"acme" realm/.test(asOther.description),
          '4b. another realm\'s certificate is STS-SSF-0147, saying why',
          JSON.stringify(asOther));
  const gone = application(MANAGE);
  gone.identity.held = false;
  const asGone = gate.authenticate(request(gone), 'read');
  t.check(!asGone.ok && asGone.errorCode === 'STS-SSF-0148',
          '4c. one the application no longer holds is STS-SSF-0148',
          JSON.stringify(asGone));
  audited.length = 0;
  const asRevoked = gate.authenticate(request(application(MANAGE), {
    revocation: { refused: true, why: 'revoked (keyCompromise)' } }),
  'read');
  t.check(!asRevoked.ok && asRevoked.errorCode === 'STS-SSF-0150' &&
          audited.indexOf('STS-PKI-0118') >= 0,
          '4d. one refused on revocation is STS-SSF-0150, and the ' +
          'certificate\'s own code is audited', JSON.stringify(asRevoked));
  t.check(gate.authenticate(request(person), 'none').ok &&
          gate.authenticate(request(other), 'none').ok &&
          gate.authenticate(request(gone), 'none').ok,
          '4e. none of them is refused on an endpoint that needs nothing');
  log.debug("Leaving refused().");
}

function run(t) {
  log.debug("Entering run().");
  setUp(t);
  metadata(t);
  accepted(t);
  notThisCredential(t);
  refused(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_client_certificate',
  describe: 'Shared Signals: a receiver authenticated by its TLS client ' +
            'certificate, as its application, held to its declared scopes ' +
            'and SSF roles (#1049)',
  run: run
};
