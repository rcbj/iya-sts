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
//
// AND (#2050) EACH PERSON'S LIVE CERTIFICATES ON THEIR ENTRY: written at
// issuance, taken off at revocation and expiry, reconciled with the
// register by its job, and the older certificates backfilled once.

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

// A DIRECTORY OF ONE PERSON (#2050): the slot's two functions over a Map.
function fakeDirectory(people) {
  log.debug('Entering fakeDirectory().');
  const writes = [];
  const out = {
    writes: writes,
    locate: async function locate(subject) {
      log.debug('Entering locate().');
      const p = people.get(String(subject));
      log.debug('Leaving locate().');
      return p ? { dn: p.dn, values: p.values.slice() } : null;
    },
    write: function write(dn, values) {
      log.debug('Entering write().');
      writes.push(dn);
      for (const [, p] of people) {
        if (p.dn === dn) {
          p.values = values.slice();
          log.debug('Leaving write(). Written.');
          return true;
        }
      }
      log.debug('Leaving write(). Nobody.');
      return false;
    }
  };
  log.debug('Leaving fakeDirectory().');
  return out;
}

function serialsOn(person) {
  log.debug('Entering serialsOn().');
  const register = require('../common/ssh_issued');
  const out = person.values.map(function (one) {
    const read = register.readEntryValue(one);
    return read ? read.serialHex : '?';
  }).sort().join(',');
  log.debug('Leaving serialsOn().');
  return out;
}

// THE CERTIFICATES ON THEIR HOLDER'S ENTRY (#2050): issuance writes one,
// revocation takes it off and leaves it on the KRL, the entries job takes
// an expired one off, writes back one the entry lost and drops a value the
// register does not hold, and the backfill copies the PKI row's onto their
// holders once. S/MIME is read through the concept.
async function checkEntries(t) {
  log.debug('Entering checkEntries().');
  const register = require('../common/ssh_issued');
  const realms = require('../common/realms');
  const realm = realms.currentId();
  const before = register.installedDirectory();
  const ana = { dn: 'uid=ana,ou=users,dc=example', values: [] };
  const people = new Map([['urn:uuid:ent-ana', ana]]);
  const dir = fakeDirectory(people);
  t.check(!register.setDirectory({ locate: dir.locate }),
          '9a. a directory offering half the slot is refused whole');
  t.check(register.setDirectory(dir), '9b. and the whole slot installed');
  const now = Date.now();
  const row = function (serial, lifeMs, extra) {
    log.debug('Entering row().');
    log.debug('Leaving row().');
    return Object.assign({ serialHex: serial, keyType: 'ssh-ed25519',
      keyFingerprint: 'SHA256:ana', ownerSubject: 'urn:uuid:ent-ana',
      principals: ['ana'], issuedAt: new Date(now).toISOString(),
      notAfter: new Date(now + lifeMs).toISOString(), caMember: 'sshUserCa',
      certificate: 'ssh-ed25519-cert-v01@openssh.com AAAA' + serial },
      extra || {});
  };
  t.check(await register.record(realm, [row('e1', 600000),
                                        row('e2', 2000)]),
          '9c. two certificates issued');
  t.equal(serialsOn(ana), 'e1,e2',
          '9d. both are on the holder\'s entry, the master, written ' +
          'before the index');
  const first = register.readEntryValue(ana.values[0]);
  t.check(/^ssh-ed25519-cert-v01@openssh\.com /.test(first.certificate) &&
          first.principals[0] === 'ana' && first.authority === 'classical',
          '9e. each value carries the certificate in OpenSSH text form',
          JSON.stringify(first));
  await register.markRevoked(realm, 'e1', new Date(now).toISOString());
  t.equal(serialsOn(ana), 'e2', '9f. a revoked certificate leaves the entry');
  t.check((await register.revoked(realm, now)).some(function (one) {
    return one.serialHex === 'e1';
  }), '9g. and stays on the KRL\'s question until it expires');
  const swept = await register.reconcileEntries(realm, now + 5000);
  t.check(swept.ok && serialsOn(ana) === '',
          '9h. the entries job takes the expired one off',
          JSON.stringify(swept));
  t.check(await register.record(realm, [row('e3', 600000)]),
          '9i. another issued');
  // A FOREIGN WRITE: the entry is the master, so a value REMOVED by another
  // door (an ldapmodify, say) is a revocation, which the KRL lists.
  const e3 = ana.values.filter(function (one) {
    return register.readEntryValue(one).serialHex === 'e3';
  })[0];
  ana.values = ana.values.filter(function (one) {
    return one !== e3;
  });
  const removal = await register.entryChanged({ realm: realm,
    subject: 'urn:uuid:ent-ana', username: 'ana', dn: ana.dn,
    actor: 'ldap:cn=admin', door: 'ldap modify', before: [e3], after: [] });
  const gone = await register.get(realm, 'e3');
  t.check(removal && removal.revoked === 1 && gone && !!gone.revokedAt &&
          (await register.revoked(realm, now)).some(function (one) {
            return one.serialHex === 'e3';
          }), '9j. a certificate removed from the entry is revoked, and ' +
          'is on the KRL\'s question', JSON.stringify(removal));
  // A REVOCATION IS PERMANENT: written back, it is refused and taken off.
  ana.values = ana.values.concat([e3]);
  const back = await register.entryChanged({ realm: realm,
    subject: 'urn:uuid:ent-ana', username: 'ana', dn: ana.dn,
    actor: 'ldap:cn=admin', door: 'ldap modify', before: [], after: [e3] });
  t.check(back && back.refused === 1 && serialsOn(ana) === '' &&
          !!(await register.get(realm, 'e3')).revokedAt,
          '9k. a revoked certificate written back onto the entry is ' +
          'refused, and stays revoked', JSON.stringify(back));
  // ONLY THE CA ISSUES: an invented serial is refused the same way.
  const invented = JSON.stringify({ serialHex: 'ff99', keyType: 'ssh-ed25519',
    keyFingerprint: 'SHA256:x', principals: ['root'], issuedAt: '',
    notAfter: new Date(now + 600000).toISOString(), authority: 'classical' });
  ana.values = [invented];
  const made = await register.entryChanged({ realm: realm,
    subject: 'urn:uuid:ent-ana', username: 'ana', dn: ana.dn,
    actor: 'ldap:cn=admin', door: 'ldap modify', before: [],
    after: [invented] });
  t.check(made && made.refused === 1 && serialsOn(ana) === '' &&
          !(await register.get(realm, 'ff99')),
          '9l. a certificate the CA never issued, written onto the entry, ' +
          'is refused and makes no index row', JSON.stringify(made));
  // AND THE ONE OBSERVER HANDS IT OVER: the handler is registered for the
  // attribute, with S/MIME's beside it.
  require('../common/openpgp_keys');
  const observer = require('../common/entry_observer');
  t.check(observer.registered().indexOf('stsSshUserCertificate') >= 0 &&
          observer.registered().indexOf('userSMIMECertificate') >= 0 &&
          observer.entryChanged({ kind: 'updated', dn: ana.dn,
            realm: realm, subject: 'urn:uuid:ent-ana',
            before: { stssshusercertificate: [] },
            after: { stssshusercertificate: [] } }).length === 0,
          '9m. the entry observer holds both handlers, and tells nobody of ' +
          'a write that moved neither', JSON.stringify(observer.registered()));
  // THE BACKFILL: the PKI row's certificates from before the #1955 review,
  // through an instance whose legacy reader is a stub.
  const legacy = [row('f1', 600000), row('f2', 600000,
    { revokedAt: new Date(now).toISOString() }), row('f3', -1000)];
  const old = new register.SshIssued(Object.assign(
    register.SshIssued.defaultDeps(), {
      legacyRows: async function legacyRows() {
        log.debug('Entering legacyRows().');
        log.debug('Leaving legacyRows().');
        return legacy;
      }
    }));
  old.setDirectory(dir);
  const filled = await old.reconcileEntries(realm, now);
  t.check(filled.ok && filled.copied === 2 && serialsOn(ana) === 'f1',
          '9n. the backfill copies the live PKI-row certificates into the ' +
          'register and the unrevoked one onto its holder',
          JSON.stringify(filled) + ' ' + serialsOn(ana));
  t.check((await register.revoked(realm, now)).some(function (one) {
    return one.serialHex === 'f2';
  }), '9o. a copied revocation is still on the KRL\'s question');
  const writes = dir.writes.length;
  const again = new register.SshIssued(Object.assign(
    register.SshIssued.defaultDeps(), {
      legacyRows: async function legacyRows() {
        log.debug('Entering legacyRows().');
        log.debug('Leaving legacyRows().');
        return legacy;
      }
    }));
  again.setDirectory(dir);
  const twice = await again.reconcileEntries(realm, now);
  t.check(twice.ok && twice.copied === 0 && twice.marked === 0 &&
          dir.writes.length === writes && serialsOn(ana) === 'f1',
          '9p. a second backfill copies nothing and writes no entry',
          JSON.stringify(twice));
  const DomainMap = require('../common/domain_map');
  t.equal((DomainMap.fieldOf('Credential', 'smimeCertificate', {
    'userSMIMECertificate;binary': ['A'], userSMIMECertificate: ['B']
  }) || []).join(','), 'A,B', '9q. S/MIME certificates are read through ' +
          'the concept, under both RFC 4522 spellings');
  register.setDirectory(before);
  register.forgetForTests();
  log.debug('Leaving checkEntries().');
}

// Gives the promise jobs a handler started time to finish.
async function settled(test) {
  log.debug('Entering settled().');
  for (let i = 0; i < 200; i++) {
    if (await test()) {
      log.debug('Leaving settled(). Held.');
      return true;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 10);
    });
  }
  log.debug('Leaving settled(). Never held.');
  return false;
}

// THROUGH THE REAL DIRECTORY (#2050): a write of the person's entry by
// another door — `writePerson()`, the console's and SCIM's replace, which
// reaches `noteAccountChange()` as an LDAP modify does — is handed to the
// register by the entry observer: removing the certificate revokes it, and
// writing it back is refused.
async function checkDirectoryWrites(t) {
  log.debug('Entering checkDirectoryWrites().');
  const ldap = require('../ldap/ldap_server');
  const register = require('../common/ssh_issued');
  const realm = require('../common/realms').currentId();
  const name = 'ssh-obs-' + Date.now().toString(36);
  ldap.createUser(name, { invent: false, attributes: {} });
  const entry = ldap.existingUserEntry(name);
  const uuid = String(((entry && entry.attributes.entryuuid) || [])[0] || '');
  const serial = (0x7a000000 + (Date.now() % 0xffffff)).toString(16);
  const now = Date.now();
  t.check(!!uuid && await register.record(realm, [{ serialHex: serial,
    keyType: 'ssh-ed25519', keyFingerprint: 'SHA256:obs',
    ownerSubject: 'urn:uuid:' + uuid, principals: [name],
    issuedAt: new Date(now).toISOString(),
    notAfter: new Date(now + 600000).toISOString(), caMember: 'sshUserCa',
    certificate: 'ssh-ed25519-cert-v01@openssh.com AAAAobs' }]),
    'precondition: a certificate issued to a person of the directory');
  const held = (ldap.existingUserEntry(name).attributes
    .stssshusercertificate || []).slice();
  t.equal(held.length, 1, '10a. it is on their entry in the directory');
  const view = ldap.objectFor(name);
  const without = Object.assign({}, view.entry.attributes || view.entry);
  Object.keys(without).forEach(function (key) {
    if (key.toLowerCase() === 'stssshusercertificate') {
      delete without[key];
    }
  });
  const wrote = ldap.writePerson(view.dn, without);
  t.check(wrote && wrote.ok !== false && await settled(async function () {
    const row = await register.get(realm, serial);
    return !!(row && row.revokedAt);
  }), '10b. a directory write that removes it revokes it', JSON.stringify(
    await register.get(realm, serial)));
  const back = Object.assign({}, without, { stsSshUserCertificate: held });
  ldap.writePerson(view.dn, back);
  t.check(await settled(async function () {
    return !(ldap.existingUserEntry(name).attributes
      .stssshusercertificate || []).length;
  }), '10c. written back by a directory write, it is refused and taken ' +
      'off again: a revocation is permanent');
  // WHO DID IT, FOR EVERY DOOR: the revocation's audit row names the
  // ambient request's actor — the management API's token subject (what
  // the console's calls carry too), the SCIM client — and a job's name.
  const doors = [
    { what: '10d. /admin-api', actor: 'api-admin-' + name,
      source: { req: { headers: {}, socket: {},
        res: { locals: { apiCaller: { name: 'api-admin-' + name } } } } } },
    { what: '10e. SCIM', actor: 'scim-client-' + name,
      source: { req: { headers: {}, socket: {},
        scimAuth: { principal: 'scim-client-' + name },
        res: { locals: {} } } } },
    { what: '10f. a scheduler job', actor: 'job:test.revoke',
      source: { actor: 'job:test.revoke' } }
  ];
  const audit = require('../common/audit');
  for (let i = 0; i < doors.length; i++) {
    const door = doors[i];
    const one = (0x7b000000 + i + (Date.now() % 0xffff)).toString(16);
    await register.record(realm, [{ serialHex: one,
      keyType: 'ssh-ed25519', keyFingerprint: 'SHA256:door' + i,
      ownerSubject: 'urn:uuid:' + uuid, principals: [name],
      issuedAt: new Date().toISOString(),
      notAfter: new Date(Date.now() + 600000).toISOString(),
      caMember: 'sshUserCa', certificate: 'ssh-ed25519-cert-v01 x' + i }]);
    const current = ldap.objectFor(name);
    const kept = Object.assign({}, current.entry.attributes || current.entry);
    Object.keys(kept).forEach(function (key) {
      if (key.toLowerCase() === 'stssshusercertificate') {
        delete kept[key];
      }
    });
    audit.withSource(door.source, function () {
      return ldap.writePerson(current.dn, kept);
    });
    let row = null;
    await settled(async function () {
      row = audit.list().filter(function (e) {
        return e.action === 'ssh-user-ca.revoke' && e.detail &&
          e.detail.serialHex === one;
      })[0] || null;
      return !!row;
    });
    t.equal(row && row.actor, door.actor, door.what + ': a removal through ' +
            'it is revoked, and the audit row names who did it');
  }
  log.debug('Leaving checkDirectoryWrites().');
}

async function run(t) {
  log.debug('Entering run().');
  await checkPrincipals(t);
  await checkLifetimesAndKeys(t);
  await checkPqcAndRevocation(t);
  await checkPublication(t);
  await checkRegister(t);
  await checkEntries(t);
  await checkDirectoryWrites(t);
  log.debug('Leaving run().');
}

module.exports = {
  name: 'ssh_user_ca',
  describe: 'SSH user CA principal policy, lifetimes, security-key ' +
            'attestation, owner-bound revocation, the issued register and ' +
            'where the CA is published',
  run: run
};
