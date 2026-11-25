// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/truststores.js — NAMED TRUSTSTORES AND THEIR USE CASES (#2118).
//
// The catalogue (every row resolvable, every default naming something that
// exists); a named truststore's life (the name rule, admission, the caps,
// removal refused while assigned); assignment (the scope rule, the kind rule,
// clearing back to the default); resolution (views, settings, fallback, node's
// store); and the slot validated whole. The directory is a double here except
// in the last section, which holds the real directory to the same eight
// functions in a child, because requiring `ldap/ldap_server` registers its
// routes on the shared app.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const realms = require('../common/realms');
const config = require('../common/config');
const truststores = require('../common/truststores');
const UseCases = require('../common/truststore_use_cases');
const kit = require('./tools/trust_kit');
const stsCrypto = require('../common/crypto');

const log = require('bunyan').createLogger({ name: 'truststores_test',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD = 'STS_TRUSTSTORES_CHILD';

// Whether a PEM list holds a certificate, by fingerprint: a store may hand a
// block back with its line ends normalised.
function holds(list, pem) {
  log.debug("Entering holds().");
  const wanted = stsCrypto.parseCertificate(pem).fingerprint256;
  log.debug("Leaving holds().");
  return list.some(function (one) {
    return stsCrypto.parseCertificate(one).fingerprint256 === wanted;
  });
}

// The registry's directory: a Map of stores, certificates and assignments per
// realm, with the slot's own eight functions.
function double() {
  log.debug("Entering double().");
  const realmsSeen = new Map();
  const of = function (realmId) {
    log.debug("Entering of().");
    if (!realmsSeen.has(realmId)) {
      realmsSeen.set(realmId, { stores: new Map(), assignments: {} });
    }
    log.debug("Leaving of().");
    return realmsSeen.get(realmId);
  };
  log.debug("Leaving double().");
  return {
    listStores: function (realmId) {
      return Array.from(of(realmId).stores.values()).map(function (one) {
        return one.row;
      });
    },
    putStore: function (realmId, row) {
      of(realmId).stores.set(row.name, { row: row, certs: new Map() });
      return true;
    },
    removeStore: function (realmId, name) {
      return of(realmId).stores.delete(name);
    },
    listCerts: function (realmId, name) {
      const held = of(realmId).stores.get(name);
      return held ? Array.from(held.certs.values()) : [];
    },
    putCert: function (realmId, name, row) {
      const held = of(realmId).stores.get(name);
      if (!held) {
        return false;
      }
      held.certs.set(row.fingerprint, row);
      return true;
    },
    removeCert: function (realmId, name, fingerprint) {
      const held = of(realmId).stores.get(name);
      return held ? held.certs.delete(fingerprint) : false;
    },
    readAssignments: function (realmId) {
      return Object.assign({}, of(realmId).assignments);
    },
    writeAssignments: function (realmId, map) {
      of(realmId).assignments = Object.assign({}, map);
      return true;
    }
  };
}

async function directoryChild() {
  log.debug("Entering directoryChild().");
  require('../ldap/ldap_server');
  const root = await kit.mint({ cn: 'directory root', ca: true });
  const id = 'sts-ts-directory-' + process.pid;
  realms.create({ id: id, name: id, domain: id + '.example.net' });
  const made = truststores.create(id, { name: 'partners',
                                        description: 'our partners',
                                        addedBy: 'alice' });
  const added = await truststores.addCertificates(id, 'partners', root.pem,
                                                  { addedBy: 'alice' });
  const assigned = truststores.assign(id, 'saml-signer', ['partners',
                                                          'signers']);
  const resolved = truststores.resolve('saml-signer', { realmId: id });
  const otherRealm = truststores.namesFor('saml-signer', 'default');
  const inUse = truststores.remove(id, 'partners');
  const cleared = truststores.assign(id, 'saml-signer', []);
  const removed = truststores.remove(id, 'partners');
  // A key set (#2149), through the real directory: its three attributes.
  const keyMade = truststores.create(id, { name: 'acme-keys', kind: 'jwks',
    party: 'client:acme', jwksUri: 'https://keys.example.net/jwks' });
  const keyRow = truststores.stores(id).filter(function (one) {
    return one.name === 'acme-keys';
  })[0] || {};
  const keyGone = truststores.remove(id, 'acme-keys');
  process.stdout.write('DIRECTORY ' + JSON.stringify({
    keyMade: keyMade.ok, keyParty: keyRow.party, keyUri: keyRow.jwksUri,
    keyKind: keyRow.storeKind, keyGone: keyGone.ok,
    made: made.ok, added: added.added.length, assigned: assigned.ok,
    names: resolved.names, anchors: resolved.anchors.length,
    otherRealm: otherRealm.names, inUse: inUse.code, cleared: cleared.ok,
    removed: removed.ok,
    after: truststores.stores(id).filter(function (one) {
      return one.kind === 'named';
    }).length
  }) + '\n');
  log.debug("Leaving directoryChild().");
}

if (process.env[CHILD]) {
  directoryChild().then(function () {
    process.exit(0);
  }, function (e) {
    process.stderr.write(String(e && e.stack) + '\n');
    process.exit(2);
  });
}

module.exports = {
  name: 'truststores',
  describe: 'named truststores: the catalogue, a truststore\'s life, ' +
            'assignment and its rules, resolution, and the slot',
  run: async function (t) {
    const previous = truststores.installedDirectory();
    truststores.setDirectory(double());
    const stamp = Date.now();
    const realmA = 'sts-ts-a-' + stamp;
    const overrides = [];
    const setOverride = function (key, value) {
      overrides.push(key);
      const out = config.setOverride(key, value);
      t.check(!out || out.ok !== false, 'the override ' + key + ' is taken');
    };
    try {
      // A. THE CATALOGUE.
      t.log.info('A. the catalogue');
      const ids = UseCases.ROWS.map(function (row) {
        return row.id;
      });
      t.check(ids.length === new Set(ids).size, 'every use case id is unique');
      UseCases.ROWS.forEach(function (row) {
        if (!UseCases.assignable(row)) {
          return;
        }
        t.check(row.defaults.length > 0, row.id + ' has a default list');
        const concrete = row.defaults.filter(function (one) {
          return one !== 'spiffe:*';
        });
        const problem = truststores.assignmentProblem(row.id,
          concrete.length ? concrete : ['spiffe:example.org'], 'default');
        t.check(!problem, row.id + '\'s default list is one it could be ' +
                'assigned' + (problem ? ': ' + problem.why : ''));
      });
      t.check(truststores.namesFor('outbound-federation').names
        .join(',') === 'system,setting:federation.outboundCaFile',
              'an unassigned use case trusts its default');

      // B. A NAMED TRUSTSTORE'S LIFE.
      t.log.info('B. a named truststore');
      const root = await kit.mint({ cn: 'ts root', ca: true });
      const issuing = await kit.mint({ cn: 'ts issuing', ca: true,
                                       pathLen: 0, issuer: root });
      const leaf = await kit.mint({ cn: 'ts leaf', issuer: root });
      ['Bad', '', '-x', 'system', 'signers', 'a'.repeat(64)]
        .forEach(function (name) {
          const out = truststores.create(realmA, { name: name });
          t.check(out.ok === false && out.code === 'STS-PKI-0305',
                  'the name "' + name + '" is refused (STS-PKI-0305)');
        });
      t.check(truststores.create(realmA, { name: 'partners',
                                           description: 'ours' }).ok,
              'a truststore is created');
      t.check(truststores.create(realmA, { name: 'partners' }).code ===
              'STS-PKI-0305', 'a second of the same name is refused');
      const added = await truststores.addCertificates(realmA, 'partners',
        leaf.pem + root.pem + issuing.pem, { addedBy: 'alice' });
      t.check(added.added.length === 2, 'the anchor and the intermediate ' +
              'are admitted (' + added.added.length + ')');
      t.check(added.refused.length === 1, 'the leaf is refused');
      const again = await truststores.addCertificates(realmA, 'partners',
                                                      root.pem);
      t.check(again.duplicates === 1, 'a certificate held is a duplicate');
      const nowhere = await truststores.addCertificates(realmA, 'nowhere',
                                                        root.pem);
      t.check(nowhere.refused[0].code === 'STS-PKI-0301',
              'a truststore that does not exist takes nothing');
      const described = truststores.store(realmA, 'partners');
      t.check(described && described.certificates.length === 2 &&
              described.kind === 'named' && described.scope === 'realm',
              'the truststore describes what it holds');

      // C. ASSIGNMENT AND ITS RULES.
      t.log.info('C. assignment');
      t.check(truststores.assign(realmA, 'saml-signer', ['partners']).ok,
              'a realm use case is assigned a realm truststore');
      t.check(truststores.namesFor('saml-signer', realmA).assigned,
              'the assignment is what the use case trusts');
      t.check(!truststores.namesFor('saml-signer', 'default').assigned,
              'another realm is not changed by it');
      t.check(truststores.assign(realmA, 'tls-client', ['partners'])
        .code === 'STS-PKI-0301', 'a service-wide inbound use case cannot ' +
              'name a realm\'s truststore (it resolves in the default realm)');
      t.check(truststores.create('default', { name: 'shared' }).ok,
              'a default-realm truststore is created');
      t.check(truststores.assignmentProblem('outbound-smtp', ['shared'],
                                            realmA) === null,
              'a service-wide use case may name a default-realm truststore');
      t.check(truststores.assignmentProblem('saml-signer', ['shared'],
                                            realmA) === null,
              'a realm use case may name a service-wide truststore');
      t.check(truststores.assign(realmA, 'spiffe-svid', ['partners']).code ===
              'STS-PKI-0304', 'a SPIFFE use case names bundles only');
      t.check(truststores.assign(realmA, 'saml-signer',
                                 ['spiffe:example.org']).code ===
              'STS-PKI-0304', 'a bundle is named by SPIFFE use cases only');
      t.check(truststores.assign(realmA, 'cell-peer', ['shared']).code ===
              'STS-PKI-0303', 'a fixed use case is not assigned');
      t.check(truststores.assign(realmA, 'nope', ['shared']).code ===
              'STS-PKI-0303', 'an unknown use case is refused');
      t.check(truststores.assign(realmA, 'saml-signer', ['ghost']).code ===
              'STS-PKI-0301', 'an unknown truststore is refused');
      const inUse = truststores.remove(realmA, 'partners');
      t.check(inUse.code === 'STS-PKI-0307', 'a truststore a use case ' +
              'trusts is not deleted');

      // D. RESOLUTION.
      t.log.info('D. resolution');
      const resolved = truststores.resolve('saml-signer', { realmId: realmA });
      t.check(resolved.anchors.length === 1 &&
              resolved.intermediates.length === 1,
              'resolution gives the anchors and the intermediates');
      setOverride('webauthn.attestationTrustAnchors', root.pem);
      const viaSetting = truststores.resolve('webauthn-attestation');
      t.check(holds(viaSetting.anchors, root.pem),
              'a setting view reads the legacy setting');
      const dynamic = truststores.resolve('webauthn-attestation',
        { context: { fidoMdsRoots: [issuing.pem] } });
      t.check(holds(dynamic.intermediates, issuing.pem),
              'a dynamic built-in reads what the caller hands it');
      const fallback = truststores.resolve('piv-attestation');
      t.check(fallback.fallback && fallback.names[0] === 'yubico-piv',
              'an empty default falls back to what ships');
      setOverride('piv.attestationAnchors', root.pem);
      const configured = truststores.resolve('piv-attestation');
      t.check(!configured.fallback && configured.anchors.length === 1,
              'a configured setting replaces what ships, as before');
      const system = truststores.caFor('outbound-cloud-sdk');
      t.check(system.ca === undefined, '`system` alone leaves node\'s store');
      t.check(truststores.assign('default', 'outbound-smtp',
                                 ['system', 'shared']).ok,
              'an outbound use case is assigned node\'s store and a ' +
              'truststore');
      await truststores.addCertificates('default', 'shared', root.pem);
      const smtp = truststores.caFor('outbound-smtp');
      t.check(Array.isArray(smtp.ca) &&
              smtp.ca.length ===
                truststores.Truststores.systemPems().length + 1,
              'node\'s store and the truststore are both in `ca`');
      setOverride('mail.smtpCaFile', '/nonexistent/ca.pem');
      t.check(truststores.assign('default', 'outbound-smtp', []).ok,
              'clearing returns a use case to its default');
      const unreadable = truststores.caFor('outbound-smtp');
      t.check(unreadable.problems.length === 1 &&
              unreadable.problems[0].code === 'STS-CORE-0104',
              'an unreadable legacy file is a problem, named');

      // E. THE STORES LIST.
      t.log.info('E. the list');
      const listed = truststores.stores(realmA);
      ['system', 'service-root', 'signers', 'client-certificates',
       'setting:federation.outboundCaFile', 'partners', 'shared']
        .forEach(function (name) {
          t.check(listed.some(function (one) {
            return one.name === name;
          }), name + ' is listed');
        });
      t.check(listed.filter(function (one) {
        return one.name === 'shared';
      })[0].readOnly === true, 'a service-wide truststore is read-only ' +
              'from another realm');
      t.check(truststores.usedBy(realmA, 'partners')
        .indexOf('saml-signer') >= 0, 'usedBy names the assignment');
      t.check(truststores.assign(realmA, 'saml-signer', []).ok &&
              truststores.remove(realmA, 'partners').ok,
              'unassigned, a truststore is deleted');

      // E2. THE PUBLIC PAGE names every use case, so the table there cannot
      // quietly fall behind the catalogue.
      const page = require('fs').readFileSync(require('path').join(__dirname,
        '..', 'docs', 'v1.2.0', 'truststores.md'), 'utf8');
      UseCases.ROWS.forEach(function (row) {
        t.check(page.indexOf('| `' + row.id + '` |') >= 0,
                'docs/v1.2.0/truststores.md lists ' + row.id);
      });

      // E3. A REALM'S OVERRIDE OF AN OUTBOUND USE CASE (#2148).
      t.log.info('E3. per-realm overrides');
      t.check(truststores.create(realmA, { name: 'realm-relay' }).ok,
              'a realm\'s own truststore is created');
      const before = truststores.namesFor('outbound-smtp', realmA);
      t.check(before.names.join(',') ===
              truststores.namesFor('outbound-smtp', 'default').names.join(','),
              'a realm with no override inherits the default realm\'s list');
      t.check(truststores.assign(realmA, 'outbound-smtp',
                                 ['system', 'realm-relay', 'shared']).ok,
              'a realm overrides an outbound use case with its own and a ' +
              'service-wide truststore');
      t.check(truststores.namesFor('outbound-smtp', realmA).names.join(',') ===
              'system,realm-relay,shared',
              'the realm\'s own dials trust its override');
      t.check(truststores.namesFor('outbound-smtp', 'default').names
        .indexOf('realm-relay') === -1,
              'the default realm, and every other realm, is not changed by it');
      const overRow = truststores.useCases(realmA).filter(function (one) {
        return one.id === 'outbound-smtp';
      })[0];
      t.check(overRow.overridable && overRow.realmOverride,
              'the use case says it is overridable and overridden here');
      t.check(!truststores.useCases(realmA).filter(function (one) {
        return one.id === 'tls-client';
      })[0].overridable, 'a handshake (tls-client) is not overridable');
      const otherRealm = 'sts-ts-other-' + stamp;
      t.check(truststores.assignmentProblem('outbound-smtp', ['realm-relay'],
                                            otherRealm).code ===
              'STS-PKI-0301', 'another realm cannot name this realm\'s ' +
              'truststore');
      t.check(truststores.assign(realmA, 'outbound-smtp', []).ok &&
              !truststores.namesFor('outbound-smtp', realmA).assigned,
              'clearing the override returns the realm to the default ' +
              'realm\'s list');
      t.check(truststores.remove(realmA, 'realm-relay').ok,
              'the realm\'s truststore is deleted once unassigned');

      // E4. KEY SETS, BOUND TO ONE PARTY (#2149).
      t.log.info('E4. key sets');
      const pair = require('crypto').generateKeyPairSync('ec',
        { namedCurve: 'P-256' });
      const pub = Object.assign({ kid: 'bound-' + stamp, alg: 'ES256' },
        pair.publicKey.export({ format: 'jwk' }));
      const priv = pair.privateKey.export({ format: 'jwk' });
      const setOf = function (keys) {
        return JSON.stringify({ keys: keys });
      };
      const acme = 'ks-acme-' + stamp;
      const bound = 'ks-bound-' + stamp;
      const certs = 'ks-certs-' + stamp;
      const refusedWith = function (spec) {
        return truststores.create('default', Object.assign({ name: 'ks-bad',
          kind: 'jwks' }, spec)).code;
      };
      t.check(refusedWith({ party: 'person:alice', jwks: setOf([pub]) }) ===
              'STS-PKI-0308', 'a key set names a client, a federation ' +
              'relationship or a claims provider');
      t.check(refusedWith({ party: 'client:' + acme,
                            jwks: setOf([priv]) }) === 'STS-PKI-0308',
              'a private key is never stored');
      t.check(refusedWith({ party: 'client:' + acme, jwks: setOf([pub]),
                            jwksUri: 'https://keys.example.net/jwks' }) ===
              'STS-PKI-0308', 'pasted keys or a jwks_uri, not both');
      t.check(refusedWith({ party: 'client:' + acme, jwks: '{"keys":[]}' }) ===
              'STS-PKI-0308', 'an empty key set is refused');
      t.check(refusedWith({ party: 'client:' + acme,
                            jwksUri: 'ftp://keys.example.net/' }) ===
              'STS-PKI-0308', 'a jwks_uri is an https URL');
      t.check(truststores.create('default', { name: bound, kind: 'jwks',
        party: 'client:' + acme, jwks: setOf([pub]) }).ok,
              'a key set bound to one client is created');
      t.check(truststores.create('default', { name: certs }).ok,
              'a certificate truststore beside it');
      const boundRow = truststores.stores('default').filter(function (one) {
        return one.name === bound;
      })[0];
      t.check(boundRow && boundRow.storeKind === 'jwks' &&
              boundRow.party === 'client:' + acme && boundRow.keys === 1,
              'the list says what it is, whose, and how many keys',
              JSON.stringify(boundRow || {}));
      const toKeySet = await truststores.addCertificates('default', bound,
        '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----');
      t.check(toKeySet.refused.length === 1 &&
              toKeySet.refused[0].code === 'STS-PKI-0309',
              'a certificate is not added to a key set');
      t.check(truststores.setKeys('default', certs,
                                  { jwks: setOf([pub]) }).code ===
              'STS-PKI-0309', 'keys are not set on a certificate truststore');
      t.check(truststores.assign('default', 'saml-signer', [bound]).code ===
              'STS-PKI-0309', 'a certificate use case does not name a key set');
      t.check(truststores.assign('default', 'client-jws', [certs]).code ===
              'STS-PKI-0309', 'a key-set use case does not name a ' +
              'certificate truststore');
      t.check(truststores.assign('default', 'client-jws',
                                 ['registered-keys', bound]).ok,
              'client-jws names the registration and the bound key set');
      const forAcme = truststores.keySources('client-jws',
        { kind: 'client', id: acme }, 'default');
      const forOther = truststores.keySources('client-jws',
        { kind: 'client', id: acme + '-other' }, 'default');
      t.check(forAcme.registered && forAcme.sets.length === 1 &&
              forAcme.sets[0].keys.length === 1,
              'the bound client gets its registration and the key set');
      t.check(forOther.registered && forOther.sets.length === 0,
              'ANY OTHER CLIENT gets nothing from it: a key set is never a ' +
              'pool');
      const grant = require('../oauth-oidc/assertion_grant');
      const read = grant.keysForParty({ oauthClientId: acme }, 'application');
      const readOther = grant.keysForParty(
        { oauthClientId: acme + '-other' }, 'application');
      t.check(read.keys.some(function (one) {
        return one.source === 'truststore:' + bound;
      }) && !readOther.keys.length,
              'keysForParty() finds the bound key for that client only',
              JSON.stringify(read.keys.map(function (one) {
                return one.source;
              })));
      t.check(truststores.assign('default', 'client-jws', [bound]).ok &&
              !truststores.keySources('client-jws',
                { kind: 'client', id: acme }, 'default').registered,
              'a list without registered-keys leaves the registration out');
      t.check(truststores.setKeys('default', bound,
        { jwksUri: 'https://keys.example.net/jwks' }).ok &&
              truststores.keySources('client-jws',
                { kind: 'client', id: acme }, 'default').sets[0].uri ===
              'https://keys.example.net/jwks',
              'the keys are replaced by a jwks_uri; the party stays');
      t.check(truststores.assign('default', 'client-jws', []).ok &&
              truststores.remove('default', bound).ok &&
              truststores.remove('default', certs).ok,
              'unassigned, both are deleted');
      t.check(truststores.keySources('client-jws',
        { kind: 'client', id: acme }, 'default').registered,
              'unassigned, client-jws is the registration again');

      // E5. SSH CA KEYS (#2151): they pool, and no other kind stands in.
      t.log.info('E5. SSH CA keys');
      const sshString = function (buf) {
        const len = Buffer.alloc(4);
        len.writeUInt32BE(buf.length, 0);
        return Buffer.concat([len, buf]);
      };
      const edRaw = require('crypto').generateKeyPairSync('ed25519')
        .publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
      const sshLine = 'ssh-ed25519 ' + Buffer.concat([
        sshString(Buffer.from('ssh-ed25519')), sshString(edRaw)])
        .toString('base64') + ' ca@example.net';
      const sshName = 'ks-ssh-' + stamp;
      t.check(truststores.create('default', { name: sshName + '-bad',
        kind: 'ssh', sshKeys: 'ssh-ed25519 not-base64' }).code ===
              'STS-PKI-0308', 'a line that is not an SSH key is refused');
      t.check(truststores.create('default', { name: sshName, kind: 'ssh',
        sshKeys: sshLine }).ok, 'an SSH CA truststore is created');
      t.check(truststores.create('default', { name: certs + '-2' }).ok,
              'a certificate truststore beside it');
      t.check(truststores.assign('default', 'spiffe-sshpop',
                                 [certs + '-2']).code === 'STS-PKI-0309' &&
              truststores.assign('default', 'saml-signer',
                                 [sshName]).code === 'STS-PKI-0309',
              'SSH CA keys and certificates never stand in for each other');
      t.check(truststores.assign('default', 'spiffe-sshpop',
        ['setting:spiffe.sshpopCertAuthorities', sshName]).ok &&
              truststores.sshAuthorities('spiffe-sshpop', 'default')
                .keys.indexOf(sshLine) >= 0,
              'spiffe-sshpop trusts the setting and the truststore');
      t.check(truststores.setKeys('default', sshName,
                                  { sshKeys: sshLine + '\n' + sshLine })
        .ok && truststores.stores('default').filter(function (one) {
        return one.name === sshName;
      })[0].keys === 2, 'its keys are replaced and counted');
      t.check(truststores.assign('default', 'spiffe-sshpop', []).ok &&
              truststores.remove('default', sshName).ok &&
              truststores.remove('default', certs + '-2').ok,
              'unassigned, both are deleted');

      // F. THE SLOT.
      t.log.info('F. the slot');
      t.check(truststores.setDirectory({ listStores: function () {
        return [];
      } }) === false, 'a partial directory is refused');

      // G. THE REAL DIRECTORY, in a child.
      t.log.info('G. the directory');
      const out = childProcess.spawnSync(process.execPath, [__filename], {
        env: Object.assign({}, process.env, { [CHILD]: 'directory',
                                              LOG_LEVEL: 'fatal' }),
        encoding: 'utf8', timeout: 120000 });
      const line = String(out.stdout || '').split('\n').filter(function (one) {
        return one.indexOf('DIRECTORY ') === 0;
      })[0];
      t.check(!!line, 'the directory child answered' +
              (line ? '' : ': ' + String(out.stderr || '').slice(-400)));
      if (line) {
        const got = JSON.parse(line.slice(10));
        t.check(got.made && got.added === 1 && got.assigned,
                'the directory creates, admits and assigns');
        t.check(got.names.join(',') === 'partners,signers' &&
                got.anchors === 1, 'the directory resolves the assignment');
        t.check(got.otherRealm.join(',') === 'signers',
                'the default realm keeps its default');
        t.check(got.inUse === 'STS-PKI-0307' && got.cleared && got.removed &&
                got.after === 0, 'the directory clears and deletes');
        t.check(got.keyMade && got.keyParty === 'client:acme' &&
                got.keyUri === 'https://keys.example.net/jwks' &&
                got.keyKind === 'jwks' && got.keyGone,
                'the directory keeps a key set\'s party and jwks_uri (#2149)',
                JSON.stringify(got));
      }
    } finally {
      overrides.forEach(function (key) {
        config.clearOverride(key);
      });
      if (previous) {
        truststores.setDirectory(previous);
      }
    }
  }
};
