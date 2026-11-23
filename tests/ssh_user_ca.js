// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssh_user_ca.js
//
// THE ISSUE DECISION (#1955 P3): the caller's entry supplies the only
// candidate principals, XACML is asked once per principal, and a denied
// principal prevents issuance. The account API's serial ownership check is
// exercised through the issuer's revocation call.
//
// AND WHAT THE #1955 REVIEW CHANGED: a group is a principal only where
// `pki.sshGroupPrincipals` names it, never when it is named like a person
// or a system account; the lifetimes are settings; an `sk-` key with no
// attestation gets the short lifetime and one with an attestation but no
// challenge is refused; the ML-DSA certificate is returned; an
// administrator lists and revokes a person's; the plain-HTTP listener
// serves neither the CA key nor the KRL; and the register keeps issued
// certificates in a store of their own.

const bunyan = require('bunyan');
const sshUserCa = require('../common/ssh_user_ca');
const errorCodes = require('../common/error_codes');
const pkiService = require('../pki/pki_service');

const log = bunyan.createLogger({
  name: 'ssh_user_ca',
  level: process.env.LOG_LEVEL || 'info'
});

function issuerWith(policy, opts) {
  log.debug('Entering issuerWith().');
  const o = opts || {};
  const calls = { decisions: [], kinds: [], issues: [], revocations: [],
                  recorded: [] };
  const key = Object.assign({
    type: 'ssh-ed25519', certType: null, sk: false,
    blob: Buffer.from('public-key-blob')
  }, o.key || {});
  const settings = o.settings || {};
  const issuer = new sshUserCa.SshUserCa({
    log: log,
    pki: {
      parseSshAuthorizedKey: function () {
        return key;
      },
      sshFingerprint: function () {
        return 'SHA256:fingerprint';
      },
      issueSshUserCertificateAsync: async function (realm, spec) {
        calls.issues.push({ realm: realm, spec: spec });
        return Object.assign({ ok: true, line: 'ssh-ed25519-cert AAAA',
                               serialHex: 'a1', validAfter: 10,
                               validBefore: 310 }, o.issued || {});
      },
      revokeSshUserCertificateAsync: async function (realm, serial, owner) {
        calls.revocations.push({ realm: realm, serial: serial, owner: owner });
        return { ok: true };
      },
      sshUserCertificatesOfAsync: async function (realm, owner) {
        return owner === 'urn:uuid:alice'
          ? [{ serialHex: 'a1', keyType: 'ssh-ed25519',
               keyFingerprint: 'SHA256:fingerprint', principals: ['alice'],
               issuedAt: '2026-11-23T00:00:00Z',
               notAfter: '2026-11-23T00:05:00Z', hardwareBound: false,
               caMember: 'sshUserCa' }] : [];
      }
    },
    crypto: {},
    accessGate: {
      RESOURCE: { SSH_USER_CA: 'ssh-user-ca' },
      ACTION: { ISSUE_SSH_PRINCIPAL: 'issue-ssh-principal' },
      check: function (request) {
        calls.decisions.push(request.sshPrincipal);
        calls.kinds.push(request.sshPrincipalKind);
        return policy(request);
      }
    },
    config: { value: function (name) {
      return settings[name];
    } },
    hardwareTokens: {
      recordAttested: function (spec) {
        calls.recorded.push(spec);
        return { ok: true };
      }
    },
    errorCodes: errorCodes,
    audit: { record: function () {} },
    directory: function () {
      return {
        existingUserEntry: function (name) {
          if (name === 'alice') {
            return { dn: 'uid=alice', attributes: { uid: ['alice'] } };
          }
          return name === 'bob' ? { dn: 'uid=bob',
                                    attributes: { uid: ['bob'] } } : null;
        },
        groupsOfUser: function () {
          return { entryFound: true, groups: [{ cn: 'developers' },
                                               { cn: 'bob' },
                                               { cn: 'root' }] };
        },
        storedCertificatesOf: function () {
          return { certificates: [] };
        }
      };
    },
    webauthn: function () {
      return {};
    },
    subjectFor: function (username) {
      return username === 'alice' ? 'urn:uuid:alice' : '';
    }
  });
  log.debug('Leaving issuerWith().');
  return { issuer: issuer, calls: calls };
}

function responseStub() {
  log.debug('Entering responseStub().');
  const response = {
    statusCode: 0, headers: {}, body: null,
    status: function (code) {
      response.statusCode = code;
      return response;
    },
    type: function (value) {
      response.headers['Content-Type'] = value;
      return response;
    },
    set: function (name, value) {
      response.headers[name] = value;
      return response;
    },
    send: function (body) {
      response.body = body;
      return response;
    },
    setHeader: function (name, value) {
      response.headers[name] = value;
    },
    end: function (body) {
      response.body = body;
    }
  };
  log.debug('Leaving responseStub().');
  return response;
}

function always() {
  log.debug('Entering always().');
  log.debug('Leaving always().');
  return { allowed: true };
}

function issueFor(principals, extra) {
  log.debug('Entering issueFor().');
  log.debug('Leaving issueFor().');
  return Object.assign({
    username: 'alice', subject: 'urn:uuid:alice', realm: 'realm-a',
    publicKey: 'ssh-ed25519 AAAA alice', principals: principals,
    lifetimeS: 300 }, extra || {});
}

async function checkPrincipals(t) {
  log.debug('Entering checkPrincipals().');
  const offered = { 'pki.sshGroupPrincipals': 'developers,bob,root' };
  const allowed = issuerWith(always, { settings: offered });
  const answer = await allowed.issuer.issue(issueFor(['alice',
                                                      'developers']));
  t.check(answer.ok, '1a. a permitted key gets a certificate');
  t.equal(allowed.calls.decisions.join(','), 'alice,developers',
          '1b. the policy is asked separately for each principal');
  t.equal(allowed.calls.kinds.join(','), 'uid,group',
          '1b-ii. and told whether each is the uid or a group');
  t.equal(allowed.calls.issues.length, 1,
          '1c. the signed certificate is recorded once');
  const plain = issuerWith(always);
  t.equal(errorCodes.codeOf(await plain.issuer.issue(issueFor(
    ['alice', 'developers']))), 'STS-PKI-0294',
          '1d. A GROUP IS NO PRINCIPAL BY DEFAULT (pki.sshGroupPrincipals ' +
          'empty): a group grants nothing by being a group');
  t.equal(plain.calls.issues.length, 0, '1e. and nothing is issued');
  for (const name of ['bob', 'root']) {
    const reserved = issuerWith(always, { settings: offered });
    t.equal(errorCodes.codeOf(await reserved.issuer.issue(issueFor(
      ['alice', name]))), 'STS-SSHCA-0002', '1f. a group named like ' +
            (name === 'bob' ? 'a person\'s uid' : 'a system account') +
            ' (' + name + ') is refused even where it is offered');
  }
  const denied = issuerWith(function (request) {
    return { allowed: request.sshPrincipal !== 'developers',
             why: 'test refusal' };
  }, { settings: offered });
  t.equal(errorCodes.codeOf(await denied.issuer.issue(issueFor(
    ['alice', 'developers']))), 'STS-PKI-0294',
          '2a. a denied principal is refused');
  t.equal(denied.calls.issues.length, 0,
          '2b. no certificate is issued after a denial');
  const options = issuerWith(always);
  t.equal(errorCodes.codeOf(await options.issuer.issue(issueFor(['alice'],
    { publicKey: 'command="id" ssh-ed25519 AAAA alice' }))), 'STS-PKI-0289',
          '3a. authorized-key options cannot be silently discarded');
  t.equal(options.calls.issues.length, 0,
          '3b. an invalid key line never reaches the CA');
  log.debug('Leaving checkPrincipals().');
}

async function checkLifetimesAndKeys(t) {
  log.debug('Entering checkLifetimesAndKeys().');
  const longer = issuerWith(always,
    { settings: { 'pki.sshSoftwareLifetimeSeconds': 900 } });
  t.check((await longer.issuer.issue(issueFor(['alice'],
    { lifetimeS: 900 }))).ok,
          '4a. the software lifetime is pki.sshSoftwareLifetimeSeconds');
  const short = issuerWith(always);
  t.equal(errorCodes.codeOf(await short.issuer.issue(issueFor(['alice'],
    { lifetimeS: 900 }))), 'STS-PKI-0289',
          '4b. and 300 seconds by default, as before');
  const sk = { type: 'sk-ssh-ed25519@openssh.com', sk: true,
               application: 'ssh:' };
  const skLine = 'sk-ssh-ed25519@openssh.com AAAA alice';
  const unattested = issuerWith(always, { key: sk });
  const bare = await unattested.issuer.issue(issueFor(['alice'],
    { publicKey: skLine }));
  t.check(bare.ok && bare.hardwareBound === false,
          '4c. AN sk- KEY WITH NO ATTESTATION IS ISSUED, with the short ' +
          'lifetime and no hardware claim', JSON.stringify(bare.errors));
  const noChallenge = issuerWith(always, { key: sk });
  t.equal(errorCodes.codeOf(await noChallenge.issuer.issue(issueFor(
    ['alice'], { publicKey: skLine, attestation: 'AAAA' }))),
          'STS-SSHCA-0003', '4d. an attestation without the challenge ' +
          'ssh-keygen signed is refused');
  t.equal(noChallenge.calls.issues.length, 0, '4e. and nothing is issued');
  log.debug('Leaving checkLifetimesAndKeys().');
}

async function checkPqcAndRevocation(t) {
  log.debug('Entering checkPqcAndRevocation().');
  const beside = issuerWith(always, { issued: {
    pqcLine: 'ssh-mldsa-65-cert BBBB', pqcSerialHex: 'b2' } });
  const both = await beside.issuer.issue(issueFor(['alice']));
  t.check(both.ok && both.pqcCertificate === 'ssh-mldsa-65-cert BBBB' &&
          both.pqcSerialHex === 'b2',
          '5a. THE ML-DSA CERTIFICATE issued beside the classical one is ' +
          'returned', JSON.stringify(both));
  const allowed = issuerWith(always);
  await allowed.issuer.revoke('realm-a', 'urn:uuid:alice', 'a1');
  t.equal(allowed.calls.revocations[0].owner, 'urn:uuid:alice',
          '6a. revocation is bound to the caller token subject');
  const listed = await allowed.issuer.certificatesOf('realm-a',
                                                     'urn:uuid:alice');
  t.check(listed.length === 1 && listed[0].serialHex === 'a1' &&
          listed[0].authority === 'classical' && listed[0].revoked === false,
          '6b. a person\'s certificates are listed, never a key',
          JSON.stringify(listed));
  const admin = await allowed.issuer.adminRevoke({ realm: 'realm-a',
    username: 'alice', serialHex: 'A1', actor: 'root-admin', via: 'api' });
  t.check(admin.ok && allowed.calls.revocations[1].owner ===
          'urn:uuid:alice',
          '6c. an administrator revokes a person\'s certificate, bound to ' +
          'that person', JSON.stringify(admin));
  t.equal(errorCodes.codeOf(await allowed.issuer.adminRevoke({
    realm: 'realm-a', username: 'nobody', serialHex: 'a1' })),
          'STS-SSHCA-0004', '6d. and is refused for nobody of that name');
  log.debug('Leaving checkPqcAndRevocation().');
}

async function checkPublication(t) {
  log.debug('Entering checkPublication().');
  let fetched = 0;
  let handed = 0;
  const marks = [];
  const publicService = new pkiService.PkiService({
    http: {}, stsCrypto: {},
    app: function () {
      handed += 1;
    },
    log: log, config: {},
    pki: {
      SERVICE_SCOPE: 'service', PROCESS_SCOPE: 'process',
      sshUserCaPublicKeyAsync: async function () {
        fetched += 1;
        return { ok: true, publicLine: 'ssh-ed25519 AAAA ca' };
      },
      buildSshUserKrlAsync: async function () {
        return { ok: true, bytes: Buffer.from('KRL') };
      }
    },
    realms: { get: function (id) {
      return id === 'missing' ? null : { id: id };
    } },
    revocation: { scopeFromSegment: function (id) {
      return id === 'default' ? '' : id;
    } },
    certificateHeader: {},
    errorCodes: { mark: function (res, code) {
      marks.push(code);
    } },
    proxyProtocol: {}
  });
  const unknownScope = responseStub();
  await publicService.sshUserCaFor(unknownScope, 'missing');
  t.equal(unknownScope.statusCode, 404,
          '7a. an unknown realm cannot trigger CA creation');
  t.equal(fetched, 0,
          '7b. the public CA endpoint validates the realm before reading PKI');
  const publicKey = responseStub();
  await publicService.sshUserCaFor(publicKey, 'realm-a');
  t.equal(publicKey.headers['Cache-Control'], 'no-store',
          '7c. the public CA key is not cached');
  const publicKrl = responseStub();
  await publicService.sshUserKrlFor(publicKrl, 'realm-a');
  t.equal(publicKrl.headers['Cache-Control'], 'no-store',
          '7d. the public KRL is not cached');
  for (const path of ['/pki/ssh-user-ca/default', '/pki/ssh-user-krl/a']) {
    const plain = responseStub();
    publicService.revocationOnly({ url: path }, plain);
    t.check(plain.statusCode === 404 && handed === 0 &&
            marks.indexOf('STS-SSHCA-0001') >= 0,
            '7e. THE PLAIN-HTTP LISTENER DOES NOT SERVE ' + path +
            ': an unsigned trust anchor over HTTP is anybody\'s');
  }
  publicService.revocationOnly({ url: '/pki/crl/default/root.crl' },
                               responseStub());
  t.equal(handed, 1, '7f. while a CRL is still handed to the app there');
  log.debug('Leaving checkPublication().');
}

function handleIsPerRealm() {
  log.debug('Entering handleIsPerRealm().');
  const handle = require('../common/realms')
    .handleFor('ssh_user_ca.issued');
  log.debug('Leaving handleIsPerRealm().');
  return !!handle && handle.scope === 'realm';
}

async function checkRegister(t) {
  log.debug('Entering checkRegister().');
  const register = require('../common/ssh_issued');
  const realms = require('../common/realms');
  const realm = realms.currentId();
  const now = Date.now();
  const rows = [
    { serialHex: '00ab', keyFingerprint: 'SHA256:k1',
      ownerSubject: 'urn:uuid:reg-a', issuedAt: new Date(now).toISOString(),
      notAfter: new Date(now + 60000).toISOString() },
    { serialHex: 'cd', keyFingerprint: 'SHA256:k1',
      ownerSubject: 'urn:uuid:reg-a',
      issuedAt: new Date(now + 1).toISOString(),
      notAfter: new Date(now - 1000).toISOString() }
  ];
  t.check(await register.record(realm, rows),
          '8a. issued certificates are recorded in a store of their own');
  const mine = await register.ofOwner(realm, 'urn:uuid:reg-a', now);
  t.check(mine.length === 1 && mine[0].serialHex === 'ab',
          '8b. a person\'s live certificates, by the owner index, the ' +
          'expired one left out and the serial normalised',
          JSON.stringify(mine));
  const marked = await register.markRevoked(realm, 'AB',
                                            new Date(now).toISOString());
  const revoked = await register.revoked(realm, now);
  t.check(marked.ok && marked.changed && revoked.some(function (one) {
    return one.serialHex === 'ab';
  }), '8c. a revocation rewrites one row, and the KRL\'s question finds it',
          JSON.stringify(revoked));
  t.equal((await register.ofKey(realm, 'SHA256:k1', now)).length, 1,
          '8d. a key\'s live certificates, by the key index');
  t.check(handleIsPerRealm(), '8e. the register is declared per realm');
  register.forgetForTests();
  log.debug('Leaving checkRegister().');
}

async function run(t) {
  log.debug('Entering run().');
  await checkPrincipals(t);
  await checkLifetimesAndKeys(t);
  await checkPqcAndRevocation(t);
  await checkPublication(t);
  await checkRegister(t);
  log.debug('Leaving run().');
}

module.exports = {
  name: 'ssh_user_ca',
  describe: 'SSH user CA principal policy, lifetimes, security-key ' +
            'attestation, owner-bound revocation, the issued register and ' +
            'where the CA is published',
  run: run
};
