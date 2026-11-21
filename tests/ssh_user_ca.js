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

const bunyan = require('bunyan');
const sshUserCa = require('../common/ssh_user_ca');
const errorCodes = require('../common/error_codes');
const pkiService = require('../pki/pki_service');

const log = bunyan.createLogger({
  name: 'ssh_user_ca',
  level: process.env.LOG_LEVEL || 'info'
});

function issuerWith(policy) {
  log.debug('Entering issuerWith().');
  const calls = { decisions: [], issues: [], revocations: [] };
  const key = {
    type: 'ssh-ed25519', certType: null, sk: false,
    blob: Buffer.from('public-key-blob')
  };
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
        return { ok: true, line: 'ssh-ed25519-cert AAAA', serialHex: 'a1',
                 validAfter: 10, validBefore: 310 };
      },
      revokeSshUserCertificateAsync: async function (realm, serial, owner) {
        calls.revocations.push({ realm: realm, serial: serial, owner: owner });
        return { ok: true };
      }
    },
    crypto: {},
    accessGate: {
      RESOURCE: { SSH_USER_CA: 'ssh-user-ca' },
      ACTION: { ISSUE_SSH_PRINCIPAL: 'issue-ssh-principal' },
      check: function (request) {
        calls.decisions.push(request.sshPrincipal);
        return policy(request);
      }
    },
    config: {},
    hardwareTokens: {},
    errorCodes: errorCodes,
    audit: { record: function () {} },
    directory: function () {
      return {
        existingUserEntry: function () {
          return { dn: 'uid=alice', attributes: { uid: ['alice'] } };
        },
        groupsOfUser: function () {
          return { entryFound: true, groups: [{ cn: 'developers' }] };
        },
        storedCertificatesOf: function () {
          return { certificates: [] };
        }
      };
    },
    webauthn: function () {
      return {};
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
    }
  };
  log.debug('Leaving responseStub().');
  return response;
}

async function run(t) {
  log.debug('Entering run().');
  const allowed = issuerWith(function () {
    return { allowed: true };
  });
  const answer = await allowed.issuer.issue({
    username: 'alice', subject: 'urn:uuid:alice', realm: 'realm-a',
    publicKey: 'ssh-ed25519 AAAA alice',
    principals: ['alice', 'developers'], lifetimeS: 300
  });
  t.check(answer.ok, '1a. a permitted key gets a certificate');
  t.equal(allowed.calls.decisions.join(','), 'alice,developers',
          '1b. the policy is asked separately for each principal');
  t.equal(allowed.calls.issues.length, 1,
          '1c. the signed certificate is recorded once');

  const denied = issuerWith(function (request) {
    return { allowed: request.sshPrincipal !== 'developers',
             why: 'test refusal' };
  });
  const refused = await denied.issuer.issue({
    username: 'alice', subject: 'urn:uuid:alice', realm: 'realm-a',
    publicKey: 'ssh-ed25519 AAAA alice',
    principals: ['alice', 'developers'], lifetimeS: 300
  });
  t.equal(errorCodes.codeOf(refused), 'STS-PKI-0294',
          '2a. a denied principal is refused');
  t.equal(denied.calls.issues.length, 0,
          '2b. no certificate is issued after a denial');

  const options = issuerWith(function () {
    return { allowed: true };
  });
  const withOptions = await options.issuer.issue({
    username: 'alice', subject: 'urn:uuid:alice', realm: 'realm-a',
    publicKey: 'command="id" ssh-ed25519 AAAA alice',
    principals: ['alice'], lifetimeS: 300
  });
  t.equal(errorCodes.codeOf(withOptions), 'STS-PKI-0289',
          '3a. authorized-key options cannot be silently discarded');
  t.equal(options.calls.issues.length, 0,
          '3b. an invalid key line never reaches the CA');

  await allowed.issuer.revoke('realm-a', 'urn:uuid:alice', 'a1');
  t.equal(allowed.calls.revocations[0].owner, 'urn:uuid:alice',
          '4. revocation is bound to the caller token subject');

  let fetched = 0;
  const publicService = new pkiService.PkiService({
    http: {}, stsCrypto: {}, app: {}, log: log, config: {},
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
    certificateHeader: {}, errorCodes: { mark: function () {} },
    proxyProtocol: {}
  });
  const unknownScope = responseStub();
  await publicService.sshUserCaFor(unknownScope, 'missing');
  t.equal(unknownScope.statusCode, 404,
          '5a. an unknown realm cannot trigger CA creation');
  t.equal(fetched, 0,
          '5b. the public CA endpoint validates the realm before reading PKI');
  const publicKey = responseStub();
  await publicService.sshUserCaFor(publicKey, 'realm-a');
  t.equal(publicKey.headers['Cache-Control'], 'no-store',
          '5c. the public CA key is not cached');
  const publicKrl = responseStub();
  await publicService.sshUserKrlFor(publicKrl, 'realm-a');
  t.equal(publicKrl.headers['Cache-Control'], 'no-store',
          '5d. the public KRL is not cached');
  log.debug('Leaving run().');
}

module.exports = {
  name: 'ssh_user_ca',
  describe: 'SSH user CA principal policy and owner-bound revocation',
  run: run
};
