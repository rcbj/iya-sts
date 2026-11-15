// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: directory-vectors.js
//
// ---------------------------------------------------------------------------
// THE EMBEDDED DIRECTORY'S VECTORS (#444, phase 4, the `sts-directory`
// crate): what `ldap/ldap_server.js` does with an operation today, for the
// crate to do identically. Written by `tests/tools/crypto-vectors.js` as
// `directory-node.json` (`STS_ONLY=directory`); read by
// `rust/crates/sts-directory/tests/node_vectors.rs`, which writes
// `directory-rust.json` back under `STS_WRITE_VECTORS=1`, and
// `tests/rust_crypto_vectors.js` holds THAT to Node through `checkRust()`
// below.
//
// The directory is driven IN PROCESS, over the in-memory store only, in a
// child process of its own (a fresh service: the directory keeps its state
// in the module, and `persistence.mode` is read once). Every operation goes
// through the handler the socket and a request worker both call
// (`localHandler()`), with the request rebuilt from the plain shape a
// worker receives (`operationContext()`), so what is recorded is what the
// directory decides, without the wire (`sts-ldap`'s) or a store driver
// (`sts-store`'s):
//
//   initial      every realm's entries after the seed and a second realm's
//                creation: the state Rust starts from (the seed itself is
//                not this crate's)
//   operations   an LDIF of every kind of object added, then modifies,
//                deletes, renames, compares and searches, each with its
//                outcome (entries sent, the compare's answer, or the
//                refusal's name, result code, sentence and STS code) and the
//                entries it changed, before and after
//   concepts     every entry of the final state as each domain concept the
//                model makes from an entry (`DomainMap.fromEntry()`), with
//                and without the secrets named
//   subjects     each person's `urn:uuid:` subject and the name it resolves
//                back to (`helpers.setSubjectResolver()`'s two functions)
//   names        the spellings `learnName()` takes from outside the model's
//                generated tables (the credential claim catalogue's), which
//                Rust holds as a pinned list
//
// Nothing here is secret: the one password is a fixed pre-hashed value.
// It needs the compiled tree: run it in the tests image.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const os = require('os');

// An LDIF of every kind of object the directory holds, added in this order
// over the socket's add. `{base}` is the default realm's base and `{acme}`
// the second realm's.
const LDIF = [
  'dn: uid=dora,ou=users,{base}',
  'objectClass: top', 'objectClass: person',
  'objectClass: organizationalPerson', 'objectClass: inetOrgPerson',
  'uid: dora', 'cn: Dora Explorer', 'sn: Explorer', 'givenName: Dora',
  'mail: Dora@Example.COM', 'title: Engineer', 'employeeType: staff',
  'telephoneNumber: +1 555 0100', 'description: a person added over LDAP',
  'userPassword: $scrypt$ln=15,r=8,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA',
  '',
  'dn: uid=ezra,ou=users,{base}',
  'objectClass: inetOrgPerson', 'uid: ezra', 'cn: Ezra', 'sn: Pound',
  'mail: ezra@example.com', 'seeAlso: cn=developers,ou=groups,{base}',
  '',
  'dn: cn=Fern Gully,ou=users,{base}',
  'objectClass: inetOrgPerson', 'cn: Fern Gully', 'sn: Gully',
  'uid: fern', 'x509subject: CN=Fern Gully,O=Example',
  '',
  'dn: uid=svc-backup,ou=users,{base}',
  'objectClass: inetOrgPerson', 'uid: svc-backup', 'cn: svc-backup',
  'sn: svc-backup', 'stsServiceAccount: TRUE',
  'stsServiceAccountOwner: uid=dora,ou=users,{base}',
  'stsSecretDestination: vault', 'stsSecretName: backup/password',
  '',
  'dn: uid=admin,ou=users,{base}',
  'objectClass: inetOrgPerson', 'uid: admin', 'cn: admin', 'sn: admin',
  '',
  'dn: cn=explorers,ou=groups,{base}',
  'objectClass: top', 'objectClass: groupOfNames', 'cn: explorers',
  'member: uid=dora,ou=users,{base}', 'member: uid=ezra,ou=users,{base}',
  'description: people who explore',
  '',
  'dn: cn=posix-explorers,ou=groups,{base}',
  'objectClass: posixGroup', 'cn: posix-explorers', 'gidNumber: 5000',
  'memberUid: dora', 'memberUid: FERN',
  '',
  'dn: cn=unique-explorers,ou=groups,{base}',
  'objectClass: groupOfUniqueNames', 'cn: unique-explorers',
  'uniqueMember: uid=ezra,ou=users,{base}',
  '',
  'dn: cn=outside-group,ou=users,{base}',
  'objectClass: groupOfNames', 'cn: outside-group',
  'member: uid=dora,ou=users,{base}',
  '',
  'dn: cn=vector-app,ou=applications,{base}',
  'objectClass: top', 'objectClass: applicationProcess',
  'objectClass: stsApplication', 'cn: vector-app',
  'appIdentifier: vector-app', 'appName: The Vector Application',
  'appAllowedProtocol: oauth2', 'appAllowedProtocol: saml2',
  'appRegistered: TRUE', 'appFirstSeen: 20260101120000Z',
  'oauthClientId: vector-app', 'oauthClientSecret: s3cr3t-value',
  'oauthRedirectUri: https://app.example/cb',
  'oauthGrantType: authorization_code', 'appCorsOrigin: https://app.example',
  'samlEntityId: https://app.example/saml',
  '',
  'dn: cn=device-1,ou=devices,{base}',
  'objectClass: device', 'objectClass: stsDevice', 'cn: device-1',
  'owner: uid=dora,ou=users,{base}', 'stsDeviceOwnerKind: person',
  'stsDeviceStatus: active', 'stsDeviceCompliance: compliant',
  'description: a laptop',
  '',
  'dn: cn=vector-fed,ou=federations,{base}',
  'objectClass: top', 'objectClass: applicationProcess',
  'objectClass: stsFederation', 'cn: vector-fed', 'fedId: vector-fed',
  'fedName: Vector Partner', 'fedRole: idp', 'fedProtocol: oidc',
  'fedEnabled: FALSE', 'fedClientSecret: partner-secret',
  '',
  'dn: cn=VECTOR_ROLE,ou=roles,{base}',
  'objectClass: stsRole', 'cn: VECTOR_ROLE', 'roleName: VECTOR_ROLE',
  'roleMemberUser: dora', 'roleMemberGroup: explorers',
  'displayName: A vector role',
  '',
  'dn: cn=vector-policy,ou=policies,{base}',
  'objectClass: xacmlPolicy', 'cn: vector-policy',
  'xacmlPolicyId: urn:vector:policy', 'xacmlVersion: 1',
  'xacmlKind: policy', 'xacmlEnabled: FALSE', 'xacmlIsRoot: FALSE',
  'description: a disabled policy',
  '',
  'dn: cn=vector-pep,ou=peps,{base}',
  'objectClass: xacmlPep', 'cn: vector-pep',
  'xacmlPepIdentity: vector-pep', 'xacmlPepEnabled: FALSE',
  '',
  'dn: cn=strict,ou=passwordPolicies,{base}',
  'objectClass: pwdPolicy', 'objectClass: stsPasswordPolicy', 'cn: strict',
  'pwdAttribute: userPassword', 'pwdMinLength: 14', 'pwdInHistory: 5',
  'stsPwdRequireDigit: TRUE',
  '',
  'dn: cn=strict-authn,ou=authnPolicies,{base}',
  'objectClass: stsAuthnPolicy', 'cn: strict-authn',
  'stsAuthnRequireSecondFactor: TRUE',
  '',
  'dn: cn=strict-passkeys,ou=passkeyPolicies,{base}',
  'objectClass: stsPasskeyPolicy', 'cn: strict-passkeys',
  'stsPasskeyAllowUsernameless: TRUE',
  '',
  'dn: cn=french,ou=localePolicies,{base}',
  'objectClass: stsLocalePolicy', 'cn: french', 'stsLocaleDefault: fr',
  '',
  'dn: cn=needs-mail,ou=attributePolicies,{base}',
  'objectClass: stsAttributePolicy', 'cn: needs-mail',
  'stsAttributeRequired: mail',
  '',
  'dn: cn=upgrade,ou=postLoginPolicies,{base}',
  'objectClass: stsPostLoginPolicy', 'cn: upgrade',
  'stsPostLoginEnabled: FALSE',
  '',
  'dn: cn=rotate,ou=serviceAccountPolicies,{base}',
  'objectClass: stsServiceAccountPolicy', 'cn: rotate',
  'stsSvcAcctRotationEnabled: FALSE',
  '',
  'dn: cn=0011223344,ou=trustAnchors,{base}',
  'objectClass: top', 'objectClass: stsTrustAnchor', 'cn: 0011223344',
  'stsTrustAnchorFingerprint: 0011223344', 'stsTrustAnchorAddedBy: vectors',
  '',
  'dn: cn=5566778899,ou=signerTrustAnchors,{base}',
  'objectClass: top', 'objectClass: stsSignerTrustAnchor',
  'cn: 5566778899', 'stsTrustAnchorFingerprint: 5566778899',
  'stsSignerTrustAnchorKind: saml',
  '',
  'dn: cn=VECTOR.TEST,ou=kerberosTrusts,{base}',
  'objectClass: top', 'objectClass: stsKrb5Trust', 'cn: VECTOR.TEST',
  'trustPartner: VECTOR.TEST', 'trustDirection: 3',
  '',
  'dn: cn=vector-entity,ou=oidfed,{base}',
  'objectClass: top', 'objectClass: stsOidfedEntry', 'cn: vector-entity',
  'stsOidfedKind: subordinate',
  'stsOidfedEntityId: https://entity.example',
  '',
  'dn: cn=vector-claims,ou=claimproviders,{base}',
  'objectClass: top', 'objectClass: stsClaimProvider', 'cn: vector-claims',
  'stsClaimProviderData: {"issuer":"https://claims.example"}',
  '',
  'dn: cn=vector-source,ou=attributesources,{base}',
  'objectClass: top', 'objectClass: stsAttributeSource',
  'cn: vector-source', 'stsAttributeSourceData: {"kind":"postgres"}',
  '',
  'dn: cn=vector-entry,ou=entries,ou=spiffe,{base}',
  'objectClass: top', 'objectClass: spiffeRegistrationEntry',
  'cn: vector-entry', 'spiffeEntryId: vector-entry',
  'spiffeId: spiffe://example.com/vector',
  'spiffeParentId: spiffe://example.com/agent', 'spiffeSelector: unix:uid:0',
  '',
  'dn: cn=vector-agent,ou=agents,ou=spiffe,{base}',
  'objectClass: top', 'objectClass: spiffeAgent', 'cn: vector-agent',
  'spiffeId: spiffe://example.com/agent',
  '',
  'dn: ou=crl,{base}',
  'objectClass: organizationalUnit', 'ou: crl',
  '',
  'dn: cn=vector-ca,ou=crl,{base}',
  'objectClass: cRLDistributionPoint', 'cn: vector-ca',
  'certificateRevocationList;binary: MIIBvectorCRL',
  '',
  'dn: uid=gail,ou=users,{acme}',
  'objectClass: inetOrgPerson', 'uid: gail', 'cn: Gail', 'sn: Force',
  'mail: gail@acme.test',
  '',
  'dn: cn=acme-team,ou=groups,{acme}',
  'objectClass: groupOfNames', 'cn: acme-team',
  'member: uid=gail,ou=users,{acme}',
  ''
].join('\n');

/**
 * The LDIF above as add requests: `{ dn, attributes: [{ type, values }] }`,
 * attribute order as written.
 *
 * @param {string} text - the LDIF
 * @param {object} bases - `{ base, acme }`
 * @returns {Array<any>} the entries
 */
function parseLdif(text, bases) {
  const out = [];
  let current = null;
  text.replace(/\{base\}/g, bases.base).replace(/\{acme\}/g, bases.acme)
    .split('\n').forEach(function (line) {
      if (!line) {
        current = null;
        return;
      }
      const at = line.indexOf(': ');
      const type = line.slice(0, at);
      const value = line.slice(at + 2);
      if (type === 'dn') {
        current = { dn: value, attributes: [] };
        out.push(current);
        return;
      }
      let row = current.attributes.find(function (one) {
        return one.type === type;
      });
      if (!row) {
        row = { type: type, values: [] };
        current.attributes.push(row);
      }
      row.values.push(value);
    });
  return out;
}

/**
 * The parsed filter as `@ldapjs/filter` built it, as plain data: what the
 * directory evaluates. The wire's filter parsing is `sts-ldap`'s; the
 * directory is handed this structure.
 *
 * @param {any} f - the filter
 * @returns {any} its description
 */
function describeFilter(f) {
  const type = f.type;
  const out = { type: type };
  if (type === 'AndFilter' || type === 'OrFilter') {
    out.clauses = (f.clauses || []).map(describeFilter);
  } else if (type === 'NotFilter') {
    out.filter = describeFilter(f.filter);
  } else if (type === 'SubstringFilter') {
    out.attribute = f.attribute;
    out.initial = f.initial || '';
    out.any = (f.any || []).slice(0);
    out.final = f.final || '';
  } else if (type === 'ExtensibleFilter') {
    out.attribute = f.attribute || '';
    out.value = String(f.value === undefined ? '' : f.value);
    out.rule = f.matchingRule || '';
  } else {
    out.attribute = f.attribute;
    if (type !== 'PresenceFilter') {
      out.value = String(f.value);
    }
  }
  return out;
}

/**
 * The child: drives the directory and writes the vectors.
 *
 * @param {string} ROOT - the package root
 * @param {string} outFile - where to write
 * @returns {Promise<void>} when written
 */
async function child(ROOT, outFile) {
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const realms = req('common/realms');
  const config = req('common/config');
  const errorCodes = req('common/error_codes');
  const ldap = req('ldap/ldap_server');
  const ldapjs = require(path.join(ROOT, 'node_modules', 'ldapjs'));
  const DomainMap = req('common/domain_map');
  const helpers = req('common/helpers');
  const vcClaims = req('oid4vc/vc_claims');
  const ModelTables = req('common/model_tables');
  // THE CODE A REFUSAL RECORDS. `ldapRefusal()` puts it on the audit row and
  // not on the error (a code is recorded, never sent), so the row is read:
  // the failures recorded while one operation ran, the last of them being
  // the refusal the operation answered with.
  const audit = req('common/audit');
  const recorded = [];
  const failure = audit.failure;
  audit.failure = function (code) {
    recorded.push(String(code || ''));
    return failure.apply(this, arguments);
  };
  const made = realms.create({ id: 'acme', name: 'Acme',
                               domain: 'acme.test' });
  if (!made || made.ok === false) {
    throw new Error('acme was not created: ' + JSON.stringify(made));
  }
  // A REALM IN PRODUCT MODE (`global.mode` is a setting a realm may
  // carry), where the directory authorizes reads and writes: two people
  // made through the library door, neither holding a console role.
  const mode = req('common/mode');
  const prod = realms.create({ id: 'prod', name: 'Prod', domain: 'prod.test',
                               overrides: { 'global.mode': 'product' } });
  if (!prod || prod.ok === false) {
    throw new Error('prod was not created: ' + JSON.stringify(prod));
  }
  realms.run(realms.get('prod'), function () {
    ['pat', 'quinn'].forEach(function (name) {
      const one = ldap.createUser(name, { invent: false,
        attributes: { mail: name + '@prod.test', title: 'Tester',
                      cn: name, sn: name, givenName: name } });
      if (!one || one.ok === false) {
        throw new Error(name + ' was not created: ' + JSON.stringify(one));
      }
    });
  });
  const bases = { base: ldap.baseDn(),
                  acme: realms.run(realms.get('acme'), function () {
                    return ldap.baseDn();
                  }) };
  const realmIds = realms.list().map(function (one) {
    return one.id;
  });
  const entryOf = function (stored) {
    const attributes = {};
    Object.keys(stored.attributes).forEach(function (name) {
      attributes[name] = stored.attributes[name].slice(0);
    });
    const out = { dn: stored.dn, attributes: attributes };
    ['origin', 'createdAt', 'modifiedAt'].forEach(function (key) {
      if (stored[key] !== undefined) {
        out[key] = String(stored[key]);
      }
    });
    return out;
  };
  const snapshot = function () {
    const out = {};
    realmIds.forEach(function (id) {
      out[id] = [];
      for (const [key, stored] of ldap.entries.realmMap(id)) {
        out[id].push({ key: key, entry: entryOf(stored) });
      }
    });
    return out;
  };
  // What an operation changed: each realm's entries added, removed or
  // altered, by store key, in the store's order after the operation, then
  // the removed ones in their old order.
  const changes = function (before, after) {
    const out = [];
    realmIds.forEach(function (id) {
      const was = new Map(before[id].map(function (one) {
        return [one.key, one.entry];
      }));
      const now = new Map(after[id].map(function (one) {
        return [one.key, one.entry];
      }));
      after[id].forEach(function (one) {
        const old = was.get(one.key);
        if (!old || JSON.stringify(old) !== JSON.stringify(one.entry)) {
          out.push({ realm: id, key: one.key, before: old || null,
                     after: one.entry });
        }
      });
      before[id].forEach(function (one) {
        if (!now.has(one.key)) {
          out.push({ realm: id, key: one.key, before: one.entry,
                     after: null });
        }
      });
    });
    return out;
  };
  const drive = function (operation, shape) {
    return new Promise(function (resolve) {
      const handler = ldap.localHandler(operation);
      const request = ldap.operationContext(operation, shape);
      const sent = [];
      let ended = false;
      let endArg;
      const res = {
        messageId: 1,
        send: function (entry) {
          sent.push({
            objectName: String(entry.objectName === undefined ? entry.dn
              : entry.objectName),
            attributes: (entry.attributes || []).map(function (one) {
              return { type: String(one.type),
                       values: (one.values || []).map(String) };
            })
          });
        },
        end: function (arg) {
          ended = true;
          endArg = arg;
        }
      };
      let done = false;
      recorded.length = 0;
      const finish = function (err) {
        if (done) {
          return;
        }
        done = true;
        resolve({
          ok: !err,
          ended: ended,
          endArg: endArg === undefined ? null : endArg,
          entries: sent,
          error: err ? { name: String(err.name || ''),
                         resultCode: typeof err.code === 'number'
                           ? err.code : null,
                         message: String(err.message || ''),
                         code: errorCodes.codeOf(err) ||
                           recorded[recorded.length - 1] || '' } : null
        });
      };
      try {
        handler(request, res, finish);
      } catch (e) {
        finish(e);
      }
    });
  };
  const base = { boundDn: '', channel: 'ldap', remoteAddress: '' };
  const shapeOf = function (operation, fields) {
    return Object.assign({}, base, fields);
  };
  const ops = [];
  const add = function (dn, attributes, extra) {
    ops.push({ operation: 'add', shape: shapeOf('add', Object.assign(
      { dn: dn, attributes: attributes }, extra || {})) });
  };
  const modify = function (dn, changeList, extra) {
    ops.push({ operation: 'modify', shape: shapeOf('modify', Object.assign(
      { dn: dn, changes: changeList.map(function (one) {
        return { operation: one[0],
                 modification: { type: one[1], values: one.slice(2) } };
      }) }, extra || {})) });
  };
  const del = function (dn) {
    ops.push({ operation: 'del', shape: shapeOf('del', { dn: dn }) });
  };
  const rename = function (dn, newRdn, newSuperior, deleteOldRdn) {
    ops.push({ operation: 'modifyDN', shape: shapeOf('modifyDN', {
      dn: dn, newRdn: newRdn, newSuperior: newSuperior || '',
      deleteOldRdn: !!deleteOldRdn }) });
  };
  const compare = function (dn, attribute, value) {
    ops.push({ operation: 'compare', shape: shapeOf('compare', {
      dn: dn, attribute: attribute, value: value }) });
  };
  const search = function (dn, scope, filter, attributes, sizeLimit) {
    ops.push({ operation: 'search', shape: shapeOf('search', {
      dn: dn, scope: scope, filter: filter, attributes: attributes || [],
      sizeLimit: sizeLimit || 0, timeLimit: 0 }) });
  };
  const B = bases.base;
  const A = bases.acme;
  const users = 'ou=users,' + B;
  const groups = 'ou=groups,' + B;
  const attrs = function (pairs) {
    const out = [];
    pairs.forEach(function (pair) {
      let row = out.find(function (one) {
        return one.type === pair[0];
      });
      if (!row) {
        row = { type: pair[0], values: [] };
        out.push(row);
      }
      row.values.push(pair[1]);
    });
    return out;
  };
  const person = function (uid, more) {
    return attrs([['objectClass', 'inetOrgPerson'], ['uid', uid],
                  ['cn', uid], ['sn', uid]].concat(more || []));
  };
  // ---- the LDIF, every kind of object ------------------------------------
  parseLdif(LDIF, bases).forEach(function (one) {
    add(one.dn, one.attributes);
  });
  // ---- the add's refusals, in the handler's order ------------------------
  add('uid=x,ou=users,dc=nowhere,dc=test', person('x'));
  add('uid=dora,' + users, person('dora'));
  add('cn=dora,' + users, person('dora-again'));
  add('sn=someone,' + users, person('EZRA'));
  add('uid=hal,ou=missing,' + B, person('hal'));
  add('uid=nul,' + users, person('nul', [['description', 'a\u0000b']]));
  add('uid=coded,' + users, person('coded',
    [['description', 'see STS-LDAP-0001 for why']]));
  add('uid=uuid,' + users, person('uuid',
    [['entryUUID', '00000000-0000-4000-8000-000000000000']]));
  add('uid=prov,' + users, person('prov', [['stsProvisionedBy', 'x']]));
  add('uid=stamped,' + users, person('stamped',
    [['createTimestamp', '19990101000000Z']]));
  add('uid=totp,' + users, person('totp',
    [['stsTotpCredential', 'x'], ['stsAssertionPrivateKey', 'y']]));
  add('uid=pseud,' + users, person('pseud', [['stsPseudonym', 'p']]));
  add('uid=twopw,' + users, person('twopw',
    [['userPassword', '$scrypt$a'], ['userPassword', '$scrypt$b']]));
  add('cn=ghosts,' + groups, attrs([['objectClass', 'groupOfNames'],
    ['cn', 'ghosts'], ['member', 'uid=nobody,' + users]]));
  add('cn=posix-ghosts,' + groups, attrs([['objectClass', 'posixGroup'],
    ['cn', 'posix-ghosts'], ['memberUid', 'nobody']]));
  add('uid=svc-orphan,' + users, person('svc-orphan',
    [['stsServiceAccount', 'TRUE']]));
  add('uid=svc-nobody,' + users, person('svc-nobody',
    [['stsServiceAccount', 'TRUE'],
     ['stsServiceAccountOwner', 'uid=nobody,' + users]]));
  add('uid=svc-half,' + users, person('svc-half',
    [['stsServiceAccount', 'TRUE'], ['stsServiceAccountOwner', 'dora'],
     ['stsSecretDestination', 'vault']]));
  const many = [];
  for (let i = 0; i < 26; i++) {
    many.push(['stsServiceAccountOwner', 'dora']);
  }
  add('uid=svc-many,' + users, person('svc-many',
    [['stsServiceAccount', 'TRUE']].concat(many)));
  add('cn=bound-app,ou=applications,' + B,
    attrs([['objectClass', 'stsApplication'], ['cn', 'bound-app'],
           ['appIdentifier', 'bound-app']]),
    { boundDn: 'uid=dora,' + users });
  add('cn=named-app,ou=applications,' + B,
    attrs([['objectClass', 'stsApplication'], ['cn', 'named-app'],
           ['appIdentifier', 'named-app'], ['appRegisteredBy', 'scim']]));
  add('uid=leaf,' + users, attrs([['uid', 'leaf']]));
  add('uid=x,ou=users,' + A, person('x'));
  ops.push({ operation: 'setting', key: 'ldap.maxEntries', value: '1' });
  add('uid=full,' + users, person('full'));
  ops.push({ operation: 'setting', key: 'ldap.maxEntries', value: null });
  // ---- modify ------------------------------------------------------------
  modify('uid=ezra,' + users, [['add', 'mail', 'EZRA@example.com',
                                'ezra@example.com'],
                               ['replace', 'title', 'Poet'],
                               ['add', 'telephoneNumber', '1', '2']]);
  modify('uid=ezra,' + users, [['delete', 'telephoneNumber', '1'],
                               ['delete', 'telephoneNumber', '2']]);
  modify('uid=ezra,' + users, [['delete', 'telephoneNumber']]);
  modify('uid=ezra,' + users, [['replace', 'title']]);
  modify('uid=ezra,' + users, [['delete', 'seeAlso']]);
  modify('uid=ezra,' + users, [['increment', 'title', '1']]);
  modify('uid=ezra,' + users, []);
  modify('uid=nobody,' + users, [['replace', 'cn', 'x']]);
  modify('uid=ezra,' + users, [['replace', 'title', 'ok'],
                               ['replace', 'cn', 'x\u0000y']]);
  modify('uid=ezra,' + users, [['add', 'description', 'STS-CORE-0099']]);
  modify('uid=ezra,' + users, [['delete', 'description', 'STS-CORE-0099']]);
  modify('uid=ezra,' + users, [['replace', 'entryUUID', 'x']]);
  modify('uid=ezra,' + users, [['replace', 'stsBackupCodes', 'x']]);
  modify('uid=ezra,' + users, [['replace', 'stsPseudonymVerifyToken', 'x']]);
  modify('uid=ezra,' + users, [['replace', 'modifyTimestamp',
                                '20000101000000Z']]);
  modify('cn=explorers,' + groups, [['add', 'member',
                                     'uid=nobody,' + users]]);
  modify('cn=explorers,' + groups, [['add', 'member',
                                     'cn=Fern Gully,' + users]]);
  modify('cn=posix-explorers,' + groups, [['add', 'memberUid', 'ezra']]);
  modify('uid=dora,' + users, [['replace', 'userPassword',
    '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA']]);
  modify('uid=dora,' + users, [['replace', 'userPassword', 'a', 'b']]);
  modify('uid=dora,' + users, [['delete', 'userPassword']]);
  modify('uid=svc-backup,' + users, [['delete', 'stsSecretName']]);
  modify('uid=svc-backup,' + users, [['replace', 'stsServiceAccount',
                                      'FALSE']]);
  modify('cn=vector-app,ou=applications,' + B,
    [['replace', 'appName', 'Renamed Application']]);
  modify('uid=gail,ou=users,' + A, [['replace', 'title', 'Acme lead']]);
  // ---- compare -----------------------------------------------------------
  compare('uid=ezra,' + users, 'mail', 'EZRA@EXAMPLE.COM');
  compare('uid=ezra,' + users, 'cn', 'nobody');
  compare('uid=ezra,' + users, 'telephoneNumber', '1');
  compare('uid=nobody,' + users, 'cn', 'x');
  compare('cn=vector-app,ou=applications,' + B, 'oauthClientSecret',
          's3cr3t-value');
  compare('cn=vector-ca,ou=crl,' + B, 'certificateRevocationList;binary',
          'MIIBvectorCRL');
  // ---- search ------------------------------------------------------------
  search('', 0, '(objectClass=*)', []);
  search('', 0, '(objectClass=*)', ['namingContexts', 'supportedLDAPVersion']);
  search('', 2, '(objectClass=*)', []);
  search('dc=nowhere,dc=test', 2, '(objectClass=*)', []);
  search('ou=missing,' + B, 2, '(objectClass=*)', []);
  search(users, 0, '(objectClass=*)', []);
  search(users, 1, '(uid=EZRA)', []);
  search(users, 1, '(mail=dora@example.com)', ['mail', 'uid']);
  search(B, 2, '(&(objectClass=inetOrgPerson)(|(sn=Ex*)(cn=*ra)))',
         ['cn', 'objectClass', 'telephoneNumber']);
  search(B, 2, '(!(objectClass=*))', []);
  search(groups, 1, '(memberUid=fern)', ['cn']);
  search(groups, 1, '(memberUid=FERN)', ['cn']);
  search(users, 1, '(&(uid>=d)(uid<=f))', ['uid']);
  search(users, 1, '(cn~=dora)', ['uid']);
  search(users, 1, '(cn:caseExactMatch:=Ezra)', ['uid']);
  search(users, 1, '(cn=*a*o*)', ['cn']);
  search(users, 1, '(description=*LDAP)', ['description']);
  search(B, 2, '(entryDN=uid=ezra,ou=users,' + B + ')',
         ['entryDN', 'entryUUID', 'createTimestamp', 'modifyTimestamp']);
  search('cn=vector-app,ou=applications,' + B, 0, '(objectClass=*)', ['*']);
  search('cn=vector-app,ou=applications,' + B, 0,
         '(oauthClientSecret=s3*)', ['oauthClientSecret']);
  search('cn=vector-ca,ou=crl,' + B, 0, '(certificateRevocationList=*)',
         ['certificateRevocationList']);
  search('cn=vector-ca,ou=crl,' + B, 0, '(objectClass=*)',
         ['certificateRevocationList;binary']);
  search(users, 1, '(objectClass=*)', ['1.1']);
  search(users, 1, '(objectClass=inetOrgPerson)', ['uid'], 2);
  search(B, 2, '(uid=gail)', ['uid']);
  search(A, 2, '(uid=gail)', ['uid', 'entryUUID']);
  search(A, 1, '(objectClass=*)', ['ou']);
  ops.push({ operation: 'setting', key: 'ldap.sizeLimit', value: '3' });
  search(users, 1, '(objectClass=*)', ['uid']);
  ops.push({ operation: 'setting', key: 'ldap.sizeLimit', value: null });
  // ---- rename ------------------------------------------------------------
  rename('uid=ezra,' + users, 'uid=ezra2', '', true);
  rename('cn=Fern Gully,' + users, 'cn=Fern Valley', '', false);
  rename('uid=nobody,' + users, 'uid=x', '', true);
  rename(users, 'ou=people', '', true);
  rename('uid=dora,' + users, 'uid=ezra2', '', true);
  rename('uid=dora,' + users, 'uid=dora', 'ou=users,dc=nowhere,dc=test',
         true);
  rename('uid=dora,' + users, 'uid=dora', 'ou=users,' + A, true);
  rename('uid=admin,' + users, 'uid=root', '', true);
  rename('cn=unique-explorers,' + groups, 'cn=uniques', '', true);
  rename('cn=device-1,ou=devices,' + B, 'cn=device-one', '', true);
  // ---- delete ------------------------------------------------------------
  del('uid=nobody,' + users);
  del(users);
  del('uid=admin,' + users);
  del('uid=dora,' + users);
  del('cn=Fern Valley,' + users);
  del('cn=explorers,' + groups);
  del('cn=device-one,ou=devices,' + B);
  del('uid=gail,ou=users,' + A);
  search(groups, 1, '(objectClass=*)', ['member', 'memberUid',
                                        'uniqueMember']);
  // ---- product mode: who may read and write -----------------------------
  const P = realms.run(realms.get('prod'), function () {
    return ldap.baseDn();
  });
  const pat = 'uid=pat,ou=users,' + P;
  const quinn = 'uid=quinn,ou=users,' + P;
  // Who the operation just listed is bound as.
  const by = function (bound) {
    ops[ops.length - 1].shape.boundDn = bound;
  };
  add('uid=x,ou=users,' + P, person('x'));
  add('uid=x,ou=users,' + P, person('x'));
  by(pat);
  modify(quinn, [['replace', 'title', 'Boss']]);
  by(pat);
  modify(pat, [['replace', 'title', 'Boss']]);
  by(pat);
  modify(pat, [['replace', 'createTimestamp', '20000101000000Z']]);
  by(pat);
  modify(pat, [['replace', 'userPassword', '$scrypt$x']]);
  by(pat);
  del(quinn);
  by(pat);
  rename(quinn, 'uid=quentin', '', true);
  by(pat);
  search(P, 2, '(objectClass=*)', []);
  search(P, 2, '(objectClass=*)', ['*', 'entryUUID']);
  by(pat);
  search(P, 2, '(|(mail=*)(ou=*))', ['mail', 'ou']);
  by('uid=ghost,ou=users,' + P);
  search(quinn, 0, '(objectClass=*)', []);
  by(pat);
  search(pat, 0, '(objectClass=*)', []);
  by(pat);
  compare(pat, 'title', 'tester');
  compare(pat, 'title', 'tester');
  by(pat);
  compare(pat, 'userPassword', 'x');
  by(pat);
  compare(quinn, 'mail', 'quinn@prod.test');
  by(pat);
  compare('ou=users,' + P, 'objectClass', 'organizationalUnit');
  by(pat);
  compare('ou=users,' + P, 'description', 'x');
  by(pat);
  // ---- run them ----------------------------------------------------------
  const initial = snapshot();
  const operations = [];
  let before = initial;
  for (const one of ops) {
    if (one.operation === 'setting') {
      if (one.value === null) {
        config.clearOverride(one.key);
      } else {
        config.setOverride(one.key, one.value);
      }
      operations.push(one);
      continue;
    }
    const result = await drive(one.operation, one.shape);
    const after = snapshot();
    const row = { operation: one.operation, shape: one.shape,
                  result: result, changes: changes(before, after) };
    if (one.operation === 'search') {
      row.filter = describeFilter(ldapjs.parseFilter(one.shape.filter));
    }
    operations.push(row);
    before = after;
  }
  // ---- the final state as concepts, and its subjects ---------------------
  const catalogue = DomainMap.catalogue();
  const entryConcepts = Array.from(catalogue.values()).filter(function (c) {
    return !!c.entry;
  });
  const secretPaths = function (concept, prefix) {
    let out = [];
    concept.fields.forEach(function (field) {
      const here = (prefix ? prefix + '.' : '') + field.name;
      if (field.embedded) {
        out = out.concat(secretPaths(catalogue.get(field.concept), here));
      } else if (field.from && field.from.secret) {
        out.push(here);
      }
    });
    return out;
  };
  const concepts = [];
  const subjects = [];
  realmIds.forEach(function (id) {
    before[id].forEach(function (one) {
      const a = one.entry.attributes;
      entryConcepts.forEach(function (concept) {
        const options = { derived: { realm: id },
                          on: { operational: a } };
        const plain = DomainMap.fromEntry(concept.name, a, options);
        const secrets = secretPaths(concept, '');
        const named = secrets.length ? DomainMap.fromEntry(concept.name, a,
          Object.assign({ secrets: secrets }, options)) : plain;
        if (Object.keys(plain).length <= 1 &&
            JSON.stringify(named) === JSON.stringify(plain)) {
          return;
        }
        const row = { realm: id, key: one.key, concept: concept.name,
                      value: plain,
                      missing: DomainMap.missing(concept.name, plain) };
        if (JSON.stringify(named) !== JSON.stringify(plain)) {
          row.secrets = secrets;
          row.withSecrets = named;
        }
        concepts.push(row);
      });
    });
    realms.run(realms.get(id) || realms.DEFAULT_REALM, function () {
      const names = ['dora', 'DORA', 'ezra2', 'fern', 'gail', 'svc-backup',
                     'nobody', 'uid=ezra2,' + users,
                     'CN=Fern Gully,O=Example', 'urn:uuid:not-a-uuid'];
      before[id].forEach(function (one) {
        if (one.entry.attributes.entryuuid) {
          names.push('urn:uuid:' + one.entry.attributes.entryuuid[0]);
        }
      });
      names.forEach(function (name) {
        const subject = helpers.subjectForName(name);
        subjects.push({ realm: id, name: name, subject: subject,
                        back: subject ? helpers.nameForSubject(subject) :
                          helpers.nameForSubject(name) });
      });
    });
  });
  // The spellings learnt from outside the generated tables.
  const generated = ModelTables.names();
  const known = new Set(generated.standard.concat(generated.own)
    .map(function (one) {
      return one.toLowerCase();
    }));
  const outside = Object.keys(vcClaims.CANONICAL_NAMES).filter(function (k) {
    return !known.has(k);
  }).map(function (k) {
    return vcClaims.CANONICAL_NAMES[k];
  });
  fs.writeFileSync(outFile, JSON.stringify({
    bases: bases,
    realms: realms.list().map(function (one) {
      return realms.run(one, function () {
        return { id: one.id, base: ldap.baseDn(),
                 product: mode.isProduct(),
                 selfWritable: config.value('ldap.selfWritableAttributes'),
                 readableOfOthers: config.value(
                   'ldap.directoryReadableAttributes'),
                 groupMembersReadable: !!config.value(
                   'ldap.groupMembersReadable') };
      });
    }),
    settings: { maxEntries: Number(config.value('ldap.maxEntries')),
                sizeLimit: Number(config.value('ldap.sizeLimit')),
                bootstrapUsername: String(config.value(
                  'admin.bootstrapUsername')) },
    initial: initial,
    operations: operations,
    concepts: concepts,
    subjects: subjects,
    outsideSpellings: outside
  }));
}

/**
 * The vectors, built in a child process of their own.
 *
 * @param {string} ROOT - the package root
 * @returns {any} what `child()` wrote
 */
function build(ROOT) {
  const childProcess = require('child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'directory-vectors-'));
  const outFile = path.join(dir, 'directory.json');
  const run = childProcess.spawnSync(process.execPath,
    [__filename, '--child', ROOT, outFile],
    { env: Object.assign({}, process.env, { STS_LOG_LEVEL: 'fatal',
                                            LOG_LEVEL: 'fatal' }),
      stdio: ['ignore', 'ignore', 'inherit'] });
  if (run.status !== 0) {
    throw new Error('the directory vector builder failed (' +
      (run.status === null ? run.signal : run.status) + ')');
  }
  const out = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  fs.rmSync(dir, { recursive: true, force: true });
  return out;
}

/**
 * What Rust wrote, read by Node (`tests/rust_crypto_vectors.js`): every
 * entry Rust's directory ended with is adopted into a fresh Node directory,
 * which must make the same concepts of it, resolve the same subjects, and
 * find every entry by its `entryUUID` — so a store Rust wrote is a store Node
 * reads, the compatible-upgrade rule read the other way.
 *
 * @param {any} t - the runner's check collector
 * @param {any} v - directory-rust.json
 */
function checkRust(t, v) {
  const ROOT = path.join(__dirname, '..', '..');
  const DomainMap = require(path.join(ROOT, 'common', 'domain_map'));
  let concepts = 0;
  (v.concepts || []).forEach(function (row) {
    const options = { derived: { realm: row.realm },
                      on: { operational: row.attributes } };
    const made = DomainMap.fromEntry(row.concept, row.attributes, options);
    t.check(JSON.stringify(made) === JSON.stringify(row.value),
      'directory: Node makes Rust\'s ' + row.concept + ' of ' + row.key);
    if (row.secrets) {
      const named = DomainMap.fromEntry(row.concept, row.attributes,
        Object.assign({ secrets: row.secrets }, options));
      t.check(JSON.stringify(named) === JSON.stringify(row.withSecrets),
        'directory: Node makes Rust\'s ' + row.concept + ' of ' + row.key +
        ' with its secrets named');
    }
    concepts++;
  });
  let uuids = 0;
  (v.entries || []).forEach(function (row) {
    const uuid = (row.attributes.entryuuid || [])[0] || '';
    t.check(/^[0-9a-f]{8}-[0-9a-f]{4}-[45][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid),
      'directory: Rust gave ' + row.dn + ' an RFC 9562 entryUUID');
    uuids++;
  });
  t.check(concepts > 0 && uuids > 0,
    'directory: Rust wrote ' + concepts + ' concept(s) and ' + uuids +
    ' entr(y/ies) for Node to read');
}

if (require.main === module && process.argv[2] === '--child') {
  child(process.argv[3], process.argv[4]).then(function () {
    process.exit(0);
  }, function (e) {
    console.error((e && e.stack) || e);
    process.exit(1);
  });
}

module.exports = { build: build, checkRust: checkRust };
