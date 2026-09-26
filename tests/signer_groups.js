'use strict';
//
// File: signer_groups.js
//
// ===========================================================================
// THE SIGNER GROUPS' KEYS AND CERTIFICATES (2026-09-26, #68 phase 2a).
//
// A realm in `keys.signerModel = hybrid-groups` holds, per group, an RSA-3072,
// a P-256 and a P-384 key each certified TOGETHER with an ML-DSA key in one
// hybrid certificate (ITU-T X.509 clause 9.8), and an SLH-DSA key in a plain
// one. This file holds what that is made of, where it is kept and what it is
// certified as — not yet which signature uses it (phase 3).
//
// WHY IN PROCESS: every claim is about material a running service keeps to
// itself — private halves on a residency timer, a sealed blob, a certificate
// register keyed by slot — and the interesting assertion is often an absence
// (an ML-DSA key with a partner has NO certificate of its own), which over
// HTTP is a missing row nobody can tell from a slow one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const log = require('bunyan').createLogger({ name: 'signer_groups',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = 'sgroups-a';

async function waitFor(predicate, ms) {
  log.debug("Entering waitFor().");
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (predicate()) {
      log.debug("Leaving waitFor(). Yes.");
      return true;
    }
    await new Promise(function (resolve) { setTimeout(resolve, 100); });
  }
  log.debug("Leaving waitFor(). Timed out.");
  return predicate();
}

async function run(t) {
  log.debug("Entering run().");
  const realms = require('../common/realms');
  try {
    await inProcess(t);
  } finally {
    // Two later files assert only the default realm is left; a removal
    // purges the realm's stores and certificate register with it.
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }
  }
  log.debug("Leaving run().");
}

async function inProcess(t) {
  log.debug("Entering inProcess().");
  const signerGroups = require('../common/signer_groups');
  const certificateHeader = require('../common/jose_certificate_header');
  const keystore = require('../common/keystore');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const pki = require('../common/pki');
  const x509 = require('../common/vendored/x509');

  t.log.info('=== A. the table: five groups, every JOSE use in one ===');
  t.equal(signerGroups.GROUP_IDS.join(','),
          'tokens,credentials,events,wstrust-gnap,xml',
          'the five groups of rcbj\'s D2');
  const homes = {};
  signerGroups.GROUPS.forEach(function (grp) {
    grp.useCases.forEach(function (uc) {
      homes[uc] = (homes[uc] || []).concat([grp.id]);
    });
  });
  const unhomed = certificateHeader.USE_CASE_IDS.filter(function (uc) {
    return !homes[uc];
  });
  const twice = Object.keys(homes).filter(function (uc) {
    return homes[uc].length > 1;
  });
  t.equal(unhomed.join(','), '',
          'every JOSE certificate-header use case belongs to a group — a ' +
          'new signer added without a group would sign with the ' +
          'per-algorithm key in a hybrid realm and nothing would say so');
  t.equal(twice.join(','), '', 'and none belongs to two');
  t.equal(Object.keys(homes).filter(function (uc) {
            return certificateHeader.USE_CASE_IDS.indexOf(uc) < 0;
          }).join(','), '',
          'and no group names a use case that does not exist');
  t.equal(signerGroups.PAIRS.map(function (pair) {
            return pair.keyAlg + (pair.pq ? '+' + pair.pq.alg : '');
          }).join(' '),
          'rsa-3072+ML-DSA-65 ec-p256+ML-DSA-44 ec-p384+ML-DSA-87 ' +
          'slh-dsa-sha2-128s',
          'the three pairings of rcbj\'s D3 (the composite draft\'s own) and ' +
          'SLH-DSA alone');
  t.check(!signerGroups.isGroupSlot('ES256:P-256') &&
          !signerGroups.isGroupSlot('ML-DSA-65') &&
          signerGroups.isGroupSlot('tokens/ES256'),
          'a group slot can never be mistaken for a per-algorithm one');

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  const set = realms.setOverride(REALM, 'keys.signerModel', 'hybrid-groups');
  t.check(!set || set.ok !== false, 'the realm is switched to hybrid-groups',
          JSON.stringify(set));
  const started = await pki.start({
    realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    }
  });
  t.check(started.ok, 'the hierarchy is built', JSON.stringify(started));

  t.log.info('=== B. a per-algorithm realm makes none ===');
  const none = await helpers.warmSignerGroups('');
  t.equal(none, null, 'the default realm, in the default model, makes no ' +
          'group keys — a realm that never asks holds none');

  t.log.info('=== C. a hybrid-groups realm makes 35 keys ===');
  const keys = helpers.stsKeysFor.of(REALM);
  t.equal(keys.realm, REALM, 'the fixture is a real realm\'s key set');
  const members = await helpers.warmSignerGroups(REALM);
  t.equal((members || []).length, 35,
          'five groups of seven keys: three classical, three ML-DSA, one ' +
          'SLH-DSA — every one a key pair of its own');
  const kids = (members || []).map(function (one) {
    return one.publicJwk.kid;
  });
  t.equal(new Set(kids).size, kids.length, 'every kid is distinct');
  t.check(kids.every(function (kid) { return /^sts-g-/.test(kid); }),
          'and every kid is a group kid, which a per-algorithm kid (sts-es256-…, ' +
          'sts-ml-dsa-65-…) can never be');
  t.check((members || []).every(function (one) {
            return !one.publicJwk.d && !one.publicJwk.priv;
          }), 'no public JWK carries a private member');
  const rsa = (members || []).filter(function (one) {
    return one.slot === 'tokens/RS256';
  })[0];
  t.equal(rsa && Buffer.from(rsa.publicJwk.n, 'base64url').length * 8, 3072,
          'the RSA member is RSA-3072');
  t.equal(keys.signerGroups && keys.signerGroups.length, 35,
          'and the members are ON the realm\'s key set');

  t.log.info('=== D. four certificates per group, three of them hybrid ===');
  const certOf = function (group, slot) {
    log.debug("Entering certOf().");
    const grp = signerGroups.group(group);
    log.debug("Leaving certOf().");
    return pki.certificateFor(REALM, grp.pkiUseCase,
                              signerGroups.slotOf(group, slot));
  };
  const arrived = await waitFor(function () {
    return signerGroups.GROUP_IDS.every(function (group) {
      return signerGroups.PAIRS.every(function (pair) {
        return !!certOf(group, pair.slot);
      });
    });
  }, 60000);
  t.check(arrived, 'every group\'s four certificates are issued with nobody ' +
          'asking');
  const byPartner = {};
  (members || []).forEach(function (one) {
    byPartner[one.slot] = one;
  });
  const wrong = [];
  for (let g = 0; g < signerGroups.GROUPS.length; g++) {
    const grp = signerGroups.GROUPS[g];
    for (let p = 0; p < signerGroups.PAIRS.length; p++) {
      const pair = signerGroups.PAIRS[p];
      const held = certOf(grp.id, pair.slot);
      if (!held) {
        wrong.push(grp.id + '/' + pair.slot + ': none');
        continue;
      }
      const parsed = x509.alternativeParts(require('pkijs').Certificate
        .fromBER(new nodeCrypto.X509Certificate(held.certificatePem).raw));
      if (pair.pq) {
        const partner = byPartner[signerGroups.slotOf(grp.id, pair.pq.slot)];
        const expected = pki.pqSubjectPublicKeyPem(partner.alg,
                                                   partner.publicJwk);
        if (!parsed.altPublicKeyPem ||
            parsed.altPublicKeyPem.replace(/\s/g, '') !==
              expected.replace(/\s/g, '')) {
          wrong.push(grp.id + '/' + pair.slot + ': its alternative key is ' +
                     'not its ML-DSA partner');
        }
        const own = certOf(grp.id, pair.pq.slot);
        if (grp.id !== 'xml' && own) {
          wrong.push(grp.id + '/' + pair.pq.slot + ': has a certificate of ' +
                     'its own');
        }
        // THE XML GROUP'S ML-DSA KEYS DO (rcbj's D7): a plain certificate
        // whose subjectPublicKeyInfo IS the ML-DSA key, for XML KeyInfo.
        if (grp.id === 'xml') {
          const ownParts = own ? x509.alternativeParts(require('pkijs')
            .Certificate.fromBER(new nodeCrypto.X509Certificate(
              own.certificatePem).raw)) : null;
          if (!own || ownParts.altPublicKeyPem ||
              own.subjectPublicKeyPem.replace(/\s/g, '') !==
                expected.replace(/\s/g, '')) {
            wrong.push('xml/' + pair.pq.slot + ': no plain certificate over ' +
                       'its own key');
          }
        }
      } else if (parsed.altPublicKeyPem) {
        wrong.push(grp.id + '/' + pair.slot + ': SLH-DSA carries an ' +
                   'alternative key');
      }
      const verdict = await pki.verifyLeaf(REALM, held.certificatePem,
                                           held.chainPem);
      if (!verdict.ok) {
        wrong.push(grp.id + '/' + pair.slot + ': ' + verdict.why);
      }
    }
  }
  t.equal(wrong.join('; '), '',
          'each classical certificate carries EXACTLY its ML-DSA partner in ' +
          'subjectAltPublicKeyInfo, no partnered JOSE ML-DSA key has a ' +
          'certificate of its own while each XML one has a plain one over ' +
          'itself (D7), the SLH-DSA one is plain, and every one verifies as ' +
          'hybrid under the realm\'s own hierarchy');
  t.equal(certOf('xml', 'RS256') && certOf('xml', 'RS256').useCase, 'xml',
          'the XML group is certified by the XML Signing CA, the JOSE groups ' +
          'by the JOSE one');

  t.log.info('=== E. the set carries the groups through the keystore ===');
  const blob = keystore.serialise(keys);
  t.equal((blob.signerGroups || []).length, 35,
          'serialise() writes every member');
  t.check(blob.signerGroups.every(function (one) {
            return one.kind === 'pq' ? typeof one.privateKey === 'string'
                                     : /BEGIN PRIVATE KEY/
                                         .test(one.privateKeyPem);
          }),
          'a classical private half as PKCS#8 PEM, a post-quantum one as ' +
          'base64 — the encodings extraKeys and pqKeys use');
  const back = keystore.deserialiseSignerGroups(blob.signerGroups, nodeCrypto);
  const rsaBack = back.filter(function (one) {
    return one.slot === 'tokens/RS256';
  })[0];
  const message = Buffer.from('signer groups round trip');
  const signature = nodeCrypto.sign('sha256', message, rsaBack.privateKey);
  t.check(nodeCrypto.verify('sha256', message,
                            nodeCrypto.createPublicKey({
                              key: rsa.publicJwk, format: 'jwk' }),
                            signature),
          'a private key read back signs for the public key it was ' +
          'published with');
  const without = Object.assign({}, blob, { signerGroups: null });
  t.check(keystore.enriches(blob, without) &&
          !keystore.enriches(without, blob),
          'a blob gaining the groups ENRICHES the one without them, and ' +
          'never the reverse — so a sibling process adopts them rather than ' +
          'making its own');

  await whichKeySigns(t, { signerGroups: signerGroups, helpers: helpers,
                           realms: realms, pki: pki });
  log.debug("Leaving inProcess().");
}

// ---------------------------------------------------------------------------
// F. WHICH KEY SIGNS (phase 3) — in the switched realm and the default one.
// ---------------------------------------------------------------------------
async function whichKeySigns(t, m) {
  log.debug("Entering whichKeySigns().");
  const stsCrypto = require('../common/crypto');
  t.log.info('=== F. a group use signs with its group key; nothing else ' +
             'does ===');
  const realm = m.realms.get(REALM);
  const kidOf = function (token) {
    log.debug("Entering kidOf().");
    log.debug("Leaving kidOf().");
    return m.helpers.peekJoseHeader(token).kid;
  };
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return m.realms.run(realm, fn);
  };
  const accessToken = inRealm(function () {
    return m.helpers.signJwt({ sub: 'probe', iss: 'x', aud: 'y' }, null,
                             { certificateHeader: 'access-token' });
  });
  t.check(/^sts-g-tokens-rs256-/.test(kidOf(accessToken)),
          'an RS256 access token signs with the TOKENS group\'s RSA-3072 ' +
          'key', kidOf(accessToken));
  const verified = inRealm(function () {
    return m.helpers.verifyOwnJws(accessToken, { ignoreExpiration: true });
  });
  t.equal(verified && verified.sub, 'probe',
          'and this service verifies its own group-signed token');
  const ps = inRealm(function () {
    return m.helpers.signJwt({ sub: 'probe' }, null,
                             { certificateHeader: 'id-token',
                               algorithm: 'PS256' });
  });
  t.equal(kidOf(ps), kidOf(accessToken),
          'PS256 in the same group signs with the same RSA key — one key per ' +
          'algorithm FAMILY, as the per-algorithm model does');
  const event = inRealm(function () {
    return m.helpers.signJwtAs({ sub: 'probe' }, 'ES384', null,
                               { certificateHeader: 'ssf-set' });
  });
  t.check(/^sts-g-events-es384-/.test(kidOf(event)),
          'an ES384 Security Event Token signs with the EVENTS group\'s ' +
          'P-384 key — a different group, a different key pair',
          kidOf(event));
  const credential = await inRealm(function () {
    return m.helpers.signJwtAsAsync({ sub: 'probe' }, 'ML-DSA-65', null,
                                    { certificateHeader: 'vci-credential' });
  });
  t.check(/^sts-g-credentials-ml-dsa-65-/.test(kidOf(credential)),
          'an ML-DSA-65 credential signs with the CREDENTIALS group\'s ' +
          'ML-DSA-65 key', kidOf(credential));
  const pqJwk = inRealm(function () {
    return m.helpers.publicJwkOfKid(kidOf(credential));
  });
  let pqOk = false;
  try {
    await stsCrypto.verifyCompactJwsAsync(credential, pqJwk,
                                          { algorithms: ['ML-DSA-65'] });
    pqOk = true;
  } catch (e) {
    log.debug("Caught in whichKeySigns(): " + ((e && e.message) || e));
    pqOk = false;
  }
  t.check(pqOk, 'and it verifies under the key publicJwkOfKid() names');
  const es512 = inRealm(function () {
    return m.helpers.signJwtAs({ sub: 'probe' }, 'ES512', null,
                               { certificateHeader: 'access-token' });
  });
  t.check(/^sts-es512-/.test(kidOf(es512)),
          'ES512 is outside the set, so it signs with the PER-ALGORITHM key ' +
          '(D6)', kidOf(es512));
  const ungrouped = inRealm(function () {
    // certificate-header: none — the probe of a signature that names no use.
    return m.helpers.signJwt({ sub: 'probe' }, null, {});
  });
  t.check(!/^sts-g-/.test(kidOf(ungrouped)),
          'a signature naming no use case signs with the per-algorithm key');
  const defaultRealm = m.helpers.signJwt({ sub: 'probe' }, null,
                                         { certificateHeader: 'access-token' });
  t.check(!/^sts-g-/.test(kidOf(defaultRealm)),
          'and the default realm, in the per-algorithm model, is untouched');

  t.log.info('=== G. the JWKS publishes the JOSE groups as D5 says ===');
  const jwks = inRealm(function () {
    return m.helpers.groupPublishedJwks(m.helpers.stsKeysFor.of(REALM));
  });
  t.equal(jwks.length, 28, 'four JOSE groups of seven keys — the XML ' +
          'group\'s keys are not JOSE keys and are not published here');
  const members = m.helpers.stsKeysFor.of(REALM).signerGroups;
  const byKid = {};
  members.forEach(function (one) {
    byKid[one.publicJwk.kid] = one;
  });
  const bad = [];
  jwks.forEach(function (jwk) {
    const member = byKid[jwk.kid];
    const partnered = member.kind === 'pq' && !!member.pairedSlot;
    if (partnered && jwk.x5c) {
      bad.push(jwk.kid + ': a partnered ML-DSA key carries x5c');
    }
    if (!partnered) {
      if (!jwk.x5c) {
        bad.push(jwk.kid + ': no x5c');
        return;
      }
      if (member.kind !== 'pq') {
        const certKey = new nodeCrypto.X509Certificate(
          Buffer.from(jwk.x5c[0], 'base64')).publicKey
          .export({ format: 'jwk' });
        if ((certKey.n || certKey.x) !== (jwk.n || jwk.x)) {
          bad.push(jwk.kid + ': x5c[0] does not hold this key');
        }
      }
    }
  });
  t.equal(bad.join('; '), '',
          'each classical key carries its hybrid certificate in x5c, whose ' +
          'subjectPublicKeyInfo IS that key (RFC 7517 section 4.7); a ' +
          'partnered ML-DSA key is published bare (D5); SLH-DSA carries its ' +
          'own certificate');

  t.log.info('=== H. an x5c header names the hybrid certificate ===');
  m.realms.setOverride(REALM, 'oauth2.accessTokenCertificateHeader', 'x5c');
  const withChain = inRealm(function () {
    return m.helpers.signJwt({ sub: 'probe' }, null,
                             { certificateHeader: 'access-token' });
  });
  const header = m.helpers.peekJoseHeader(withChain);
  const certificate = m.pki.certificateFor(REALM, 'jose', 'tokens/RS256');
  t.check(!!(header.x5c && certificate) &&
          header.x5c[0] === certificate.certificatePem
            .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''),
          'a group-signed token\'s x5c starts with the tokens group\'s ' +
          'hybrid RS256 certificate');
  const pqHeader = m.helpers.peekJoseHeader(await inRealm(function () {
    return m.helpers.signJwtAsAsync({ sub: 'probe' }, 'ML-DSA-65', null,
                                    { certificateHeader: 'access-token' });
  }));
  t.check(!pqHeader.x5c,
          'and an ML-DSA-65 token carries NO x5c: its certificate is its ' +
          'partner\'s, whose first key is not the signing key (RFC 7515 ' +
          'section 4.1.6)');
  m.realms.clearOverride(REALM, 'oauth2.accessTokenCertificateHeader');

  t.log.info('=== I. XML signs with the XML group\'s key (phase 4a) ===');
  const xmlView = inRealm(function () {
    return m.helpers.STS.xml;
  });
  const xmlCert = m.pki.certificateFor(REALM, 'xml', 'xml/RS256');
  t.check(!!xmlCert && xmlView.certPem === xmlCert.certificatePem,
          'STS.xml in a hybrid-groups realm IS the XML group\'s RSA-3072 ' +
          'key, with its hybrid certificate');
  const document = '<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ' +
                   'ID="_probe" Version="2.0" IssueInstant="2026-09-26T00:00:00Z">' +
                   '<Issuer>probe</Issuer></Assertion>';
  const signedXml = inRealm(function () {
    return stsCrypto.signXml(document, {
      privateKeyPem: m.helpers.STS.xml.privateKeyPem,
      certPem: m.helpers.STS.xml.certPem, what: 'a probe assertion' });
  });
  t.check(signedXml.indexOf(stsCrypto.stripPem(xmlCert.certificatePem)) > 0,
          'a signed document carries the hybrid certificate in KeyInfo');
  const xmlVerdict = inRealm(function () {
    return m.helpers.verifyOwnXml(signedXml, { element: 'Assertion' });
  });
  t.check(xmlVerdict && xmlVerdict.ok,
          'and this service verifies it as its own',
          JSON.stringify(xmlVerdict));
  const defaultXml = m.helpers.STS.xml;
  t.check(defaultXml.kid && !/^sts-g-/.test(defaultXml.kid) &&
          defaultXml.certPem !== xmlCert.certificatePem,
          'while the default realm\'s STS.xml is still its per-algorithm key');

  await rotation(t, m, inRealm, kidOf);
  await xmlAlgorithms(t, m, inRealm);
  log.debug("Leaving whichKeySigns().");
}

// ---------------------------------------------------------------------------
// J. A HYBRID PAIR ROTATES AS ONE UNIT (phase 2b).
// ---------------------------------------------------------------------------
async function rotation(t, m, inRealm, kidOf) {
  log.debug("Entering rotation().");
  const keystore = require('../common/keystore');
  const UNIT = 'jose:tokens/RS256';
  t.log.info('=== J. a hybrid pair rotates as ONE unit ===');
  const units = m.helpers.signingUnitsOf(m.helpers.stsKeysFor.of(REALM))
    .filter(function (row) {
      return row.kind === 'group';
    });
  t.equal(units.length, 20,
          'one rotation unit per group CERTIFICATE (5 groups x 4), not per ' +
          'key: a new key in either half is a new certificate');
  const before = m.helpers.stsKeysFor.of(REALM).signerGroups;
  const kidAt = function (members, slot) {
    log.debug("Entering kidAt().");
    log.debug("Leaving kidAt().");
    return (members.filter(function (one) {
      return one.slot === slot;
    })[0] || { publicJwk: {} }).publicJwk.kid;
  };
  const oldRsa = kidAt(before, 'tokens/RS256');
  const oldPq = kidAt(before, 'tokens/ML-DSA-65');
  const oldToken = inRealm(function () {
    return m.helpers.signJwt({ sub: 'before-rotation', iss: 'x', aud: 'y' },
                             null, { certificateHeader: 'access-token' });
  });
  const minted = await m.helpers.ensureNextGenerations(REALM,
                                                       { units: [UNIT] });
  t.check(minted.ok && minted.minted.indexOf(UNIT) >= 0,
          'a next generation is minted for the unit', JSON.stringify(minted));
  const next = m.helpers.standbyOf(m.helpers.stsKeysFor.of(REALM), UNIT)
    .filter(function (one) {
      return one.role === 'next';
    });
  t.equal(next.map(function (one) { return one.slot; }).sort().join(','),
          'tokens/ML-DSA-65,tokens/RS256',
          'and it is TWO keys — the RSA-3072 key and its ML-DSA-65 partner');
  const nextRsa = next.filter(function (one) {
    return one.slot === 'tokens/RS256';
  })[0];
  const nextPq = next.filter(function (one) {
    return one.slot === 'tokens/ML-DSA-65';
  })[0];
  const nextCertified = await waitFor(function () {
    const held = m.pki.certificateFor(REALM, 'jose', 'tokens/RS256',
                                      nextRsa.kid);
    return !!(held && held.kid === nextRsa.kid && held.altPublicKeyPem);
  }, 30000);
  const nextCert = m.pki.certificateFor(REALM, 'jose', 'tokens/RS256',
                                        nextRsa.kid);
  t.check(nextCertified && nextCert.altPublicKeyPem.replace(/\s/g, '') ===
            m.pki.pqSubjectPublicKeyPem(nextPq.alg, nextPq.publicJwk)
              .replace(/\s/g, ''),
          'the next generation has its OWN hybrid certificate, over the next ' +
          'RSA key with the next ML-DSA key beside it — published before it ' +
          'signs');
  const blob = keystore.serialise(m.helpers.stsKeysFor.of(REALM));
  const rows = blob.generations.standby.filter(function (one) {
    return one.unit === UNIT;
  });
  t.check(rows.length === 2 && rows.every(function (one) {
            return one.memberKind === 'pq'
              ? typeof one.privateKey === 'string' && !one.privateKeyPem
              : /BEGIN PRIVATE KEY/.test(one.privateKeyPem);
          }),
          'both standby halves are written down, each in its kind\'s ' +
          'encoding');

  const promoted = await m.helpers.promoteGenerations(REALM,
    { units: [UNIT], graceMs: 3600000 });
  t.check(promoted.ok && promoted.rotated.length === 1,
          'the unit is promoted', JSON.stringify(promoted));
  const after = m.helpers.stsKeysFor.of(REALM).signerGroups;
  t.check(kidAt(after, 'tokens/RS256') === nextRsa.kid &&
          kidAt(after, 'tokens/ML-DSA-65') === nextPq.kid,
          'BOTH halves are now the next generation\'s');
  const retired = m.helpers.standbyOf(m.helpers.stsKeysFor.of(REALM), UNIT)
    .filter(function (one) {
      return one.role === 'retired';
    }).map(function (one) {
      return one.kid;
    });
  t.check(retired.indexOf(oldRsa) >= 0 && retired.indexOf(oldPq) >= 0,
          'and BOTH old halves are retired together, verifying through ' +
          'their grace');
  const newToken = inRealm(function () {
    return m.helpers.signJwt({ sub: 'after-rotation', iss: 'x', aud: 'y' },
                             null, { certificateHeader: 'access-token' });
  });
  t.equal(kidOf(newToken), nextRsa.kid,
          'a token signed now uses the promoted key');
  const stillVerifies = inRealm(function () {
    return m.helpers.verifyOwnJws(oldToken, { ignoreExpiration: true });
  });
  t.equal(stillVerifies && stillVerifies.sub, 'before-rotation',
          'and a token signed BEFORE the rotation still verifies');
  const others = m.helpers.stsKeysFor.of(REALM).signerGroups
    .filter(function (one) {
      return one.group !== 'tokens' || (one.slot !== 'tokens/RS256' &&
                                        one.slot !== 'tokens/ML-DSA-65');
    }).map(function (one) {
      return one.publicJwk.kid;
    });
  const othersBefore = before.filter(function (one) {
    return one.group !== 'tokens' || (one.slot !== 'tokens/RS256' &&
                                      one.slot !== 'tokens/ML-DSA-65');
  }).map(function (one) {
    return one.publicJwk.kid;
  });
  t.equal(others.join(','), othersBefore.join(','),
          'and no other group key moved');
  log.debug("Leaving rotation().");
}

// ---------------------------------------------------------------------------
// K. ECDSA AND POST-QUANTUM XML SIGNATURES (phase 4b).
// ---------------------------------------------------------------------------
async function xmlAlgorithms(t, m, inRealm) {
  log.debug("Entering xmlAlgorithms().");
  const stsCrypto = require('../common/crypto');
  const documentSettings = require('../saml/document_settings');
  t.log.info('=== K. the XML group signs ECDSA and ML-DSA ===');
  const document = '<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ' +
                   'ID="_alg" Version="2.0" IssueInstant="2026-09-26T00:00:00Z">' +
                   '<Issuer>probe</Issuer></Assertion>';
  const cases = [['ecdsa-sha256', 'xml/ES256', 'ecdsa-sha256'],
                 ['ml-dsa-65', 'xml/ML-DSA-65', 'ml-dsa-65']];
  for (let i = 0; i < cases.length; i++) {
    const name = cases[i][0];
    const slot = cases[i][1];
    m.realms.setOverride(REALM, 'saml.signatureAlgorithm', name);
    const how = inRealm(function () {
      return documentSettings.signatureOptions();
    });
    const signer = inRealm(function () {
      return m.helpers.STS.xmlSigner;
    });
    const cert = m.pki.certificateFor(REALM, 'xml', slot);
    t.check(how.sigName === name && how.sigAlg.indexOf(cases[i][2]) > 0 &&
            !!cert && signer.certPem === cert.certificatePem,
            name + ': the SignatureMethod and the key come from ONE ' +
            'decision — the URI names ' + cases[i][2] + ' and the key is ' +
            slot + ' with its own certificate', JSON.stringify(how));
    const signed = inRealm(function () {
      return stsCrypto.signXml(document, {
        privateKeyPem: signer.privateKeyPem, privateKey: signer.privateKey,
        certPem: signer.certPem, sigAlg: how.sigAlg, c14nAlg: how.c14nAlg,
        what: 'a ' + name + ' probe' });
    });
    t.check(signed.indexOf(how.sigAlg) > 0 &&
            signed.indexOf(stsCrypto.stripPem(cert.certificatePem)) > 0,
            name + ': the document carries that SignatureMethod and that ' +
            'certificate in KeyInfo');
    const verdict = inRealm(function () {
      return m.helpers.verifyOwnXml(signed, { element: 'Assertion' });
    });
    t.check(verdict && verdict.ok, name + ': and this service verifies it',
            JSON.stringify(verdict));
    const query = 'SAMLRequest=abc&RelayState=xyz&SigAlg=' +
                  encodeURIComponent(how.sigAlg);
    const querySignature = inRealm(function () {
      return stsCrypto.signQueryString(query, signer.privateKeyPem,
                                       how.sigAlg, signer.privateKey);
    });
    const queryVerdict = stsCrypto.verifyQueryString(query, {
      certPem: cert.certificatePem, sigAlg: how.sigAlg,
      signature: querySignature });
    t.check(queryVerdict && queryVerdict.ok,
            name + ': a Redirect-binding query signature verifies too',
            JSON.stringify(queryVerdict));
  }
  const metadataKeys = inRealm(function () {
    return m.helpers.ownXmlSigningCertificates();
  });
  t.equal(metadataKeys[0] && metadataKeys[0].certPem,
          m.pki.certificateFor(REALM, 'xml', 'xml/ML-DSA-65').certificatePem,
          'the configured signer\'s certificate is FIRST among the ' +
          'metadata\'s signing keys');
  m.realms.clearOverride(REALM, 'saml.signatureAlgorithm');
  m.realms.setOverride('', 'saml.signatureAlgorithm', 'ecdsa-sha256');
  const fallback = documentSettings.signatureOptions();
  m.realms.clearOverride('', 'saml.signatureAlgorithm');
  t.equal(fallback.sigName, 'rsa-sha256',
          'a per-algorithm realm asked for ecdsa-sha256 signs rsa-sha256 — ' +
          'it has no key for it, and a signature under the wrong key would ' +
          'be refused everywhere');
  log.debug("Leaving xmlAlgorithms().");
}

module.exports = {
  name: 'signer_groups',
  describe: 'The signer groups (#68): five groups, every JOSE use in exactly ' +
            'one; a hybrid-groups realm makes 35 key pairs lazily and a ' +
            'per-algorithm one none; each classical key is certified with ' +
            'its ML-DSA partner in subjectAltPublicKeyInfo and SLH-DSA ' +
            'alone, under the group\'s Issuing CA, verifying as hybrid; and ' +
            'the members survive the keystore and enrich a set without them',
  run: run
};
