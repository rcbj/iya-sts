'use strict';
//
// File: gnap_token_formats.js
//
// ===========================================================================
// THE THREE STRUCTURED GNAP TOKEN FORMATS — MACAROON, BISCUIT, ZCAP — AND THE
// ACCESS-RIGHTS MATCHER THEY SHARE (RFC 9767 SECTION 2, RFC 9635 SECTION 8).
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
//   * **A ROUND TRIP IS A PROPERTY OF TWO FUNCTIONS, NOT OF AN ENDPOINT.** Over
//     HTTP a token that loses its `label` or its `nbf` on the way through a
//     format is a token whose introspection response lacks a member — which
//     looks exactly like a model that never had one. Here every field of a
//     fully populated model is compared, per format.
//   * **THE REFUSALS ARE THE POINT, AND THEY ARE NINE-BY-THREE.** Expiry,
//     not-before, audience, binding, access, tamper, wrong key and attenuation,
//     for each of three formats, is a matrix; over HTTP each cell is a grant,
//     a token and a request.
//   * **ATTENUATION HAS NO ENDPOINT AT ALL.** RFC 9767 section 2.2's sub-token
//     is made by a resource server offline; the only way to hold a narrowed
//     macaroon or biscuit is to call the library.
//   * **THE MATCHER IS A TABLE OF CASES.** `accessCovers()` is section 8's
//     cross-product sentence, and its edges (a union covering what no single
//     grant does, an empty dimension that must not be vacuous) are argued in
//     `gnap/gnap_access.js` and pinned here.
//
// Every refusal is asserted by CODE, and the code is asserted to be MARKED on
// the refusal object as well as named on it, because the route module reads
// the mark.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const macaroonLib = require('macaroon');
const errorCodes = require('../common/error_codes');
const gnapAccess = require('../gnap/gnap_access');
const macaroon = require('../gnap/token_macaroon');
const biscuit = require('../gnap/token_biscuit');
const zcap = require('../gnap/token_zcap');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'gnap_token_formats',
  level: process.env.LOG_LEVEL || 'info' });

const NOW = 2000000000;
const JKT = nodeCrypto.createHash('sha256')
                      .update('client key')
                      .digest('base64url');
const X5T = nodeCrypto.createHash('sha256')
                      .update('client certificate')
                      .digest('base64url');

function fullModel(extra) {
  log.debug("Entering fullModel().");
  log.debug("Leaving fullModel().");
  return Object.assign({
    jti: 'tok-"full" 1',
    iss: 'https://as.example/realm/acme/gnap',
    sub: 'alice@example.com',
    aud: ['https://rs1.example/api', 'https://rs2.example/api'],
    instanceId: 'client-instance-7',
    access: [
      { type: 'photo-api', actions: ['read', 'write'],
        locations: ['https://rs1.example/api'],
        datatypes: ['metadata', 'images'], privileges: [
          'admin'], identifier: 'album-9',
        geolocation: [{ lat: -32.364, lng: 153.207 }] },
      'dolphin-metadata',
      { type: 'financial-transaction', actions: ['withdraw'],
        identifier: 'account-14-32-32-3',
        currency: 'USD' }
    ],
    flags: ['durable'],
    cnf: { jkt: JKT },
    iat: NOW - 60,
    nbf: NOW - 30,
    exp: NOW + 3600,
    label: 'photos token'
  }, extra || {});
}

function bearerModel() {
  log.debug("Entering bearerModel().");
  log.debug("Leaving bearerModel().");
  return {
    jti: 'tok-min', iss: 'https://as.example/gnap', sub: null, aud: [],
    instanceId: 'ci-1',
    access: ['read'], flags: ['bearer'], cnf: null, iat: NOW -
        10, nbf: null, exp: NOW + 60,
    label: null
  };
}

const FIELDS = ['jti', 'iss', 'sub', 'aud', 'instanceId', 'access', 'flags',
                'cnf',
                'iat', 'nbf', 'exp', 'label'];

function refused(t, result, code, what) {
  log.debug("Entering refused().");
  const ok = !!result && result.ok === false && result.errorCode === code;
  t.check(ok, what, 'expected ' + code + ', got ' + JSON.stringify(result));
  if (ok) {
    t.equal(errorCodes.codeOf(result), code, what + ' — and the code is ' +
                                                    'MARKED on the refusal');
  }
  log.debug("Leaving refused().");
}

function accepted(t, result, what) {
  log.debug("Entering accepted().");
  log.debug("Leaving accepted().");
  return t.check(!!result && result.ok === true, what, JSON.stringify(result));
}

function sameModel(t, got, want, what) {
  log.debug("Entering sameModel().");
  FIELDS.forEach(function (f) {
    t.equal(gnapAccess.canonicalJson(got && got[f]),
            gnapAccess.canonicalJson(want[f]),
            what + ': ' + f + ' survives the round trip');
  });
  log.debug("Leaving sameModel().");
}

// Flip one base64url character of a value somewhere in its middle.
function flipOne(value) {
  log.debug("Entering flipOne().");
  const bytes = Buffer.from(value, 'base64url');
  bytes[Math.floor(bytes.length / 2)] ^= 0x01;
  log.debug("Leaving flipOne().");
  return bytes.toString('base64url');
}

function accessCases(t) {
  log.debug("Entering accessCases().");
  t.log.info('=== accessCovers(): RFC 9635 section 8 as points ===');
  const cover = gnapAccess.accessCovers;
  t.check(cover(['read', 'write'], ['read']), 'a reference string is covered ' +
                                              'by the identical string');
  t.check(!cover(['read'], ['Read']), 'a reference string is compared by ' +
                                      'exact bytes');
  t.check(!cover([{ type: 'read' }], ['read']), 'an object never covers a ' +
                                                'reference string');
  t.check(!cover(['photo-api'], [{ type: 'photo-api' }]), 'a reference ' +
      'string never covers an object');
  t.check(!cover([{ type: 'photo-api', actions: ['read'] }],
                 [{ type: 'Photo-api', actions: ['read'] }]),
          'a type mismatch is not covered (exact bytes, no normalisation)');
  t.check(cover([{ type: 'p', actions: ['read', 'write'] }],
                [{ type: 'p', actions: ['read'] }]),
          'a subset of actions is covered');
  t.check(!cover([{ type: 'p', actions: ['read'] }],
                 [{ type: 'p', actions: ['read', 'delete'] }]),
          'a superset of actions is not covered');
  t.check(cover([{ type: 'p', actions: ['read'], locations: ['A'] },
                 { type: 'p', actions: ['write'], locations: ['A'] }],
                [{ type: 'p', actions: ['read', 'write'], locations: ['A'] }]),
          'the UNION of two grants covers a cross-product neither covers ' +
          'alone');
  t.check(!cover([{ type: 'p', actions: ['read'], locations: ['A'] },
                  { type: 'p', actions: ['write'], locations: ['B'] }],
                 [{ type: 'p', actions: ['read', 'write'],
                    locations: ['A', 'B'] }]),
          'a cross-product with an uncovered point (write at A) is not ' +
          'covered');
  t.check(cover([{ type: 'p', actions: ['read'],
                   datatypes: ['images', 'metadata'] }],
                [{ type: 'p', actions: ['read'], datatypes: ['images'],
                   locations: ['https://x'] }]),
          'a dimension the grant does not list is unrestricted');
  t.check(cover([{ type: 'p', actions: ['read'], locations: ['A'] }],
                [{ type: 'p', actions: ['read'] }]),
          'a dimension the requirement does not list is not asked about');
  t.check(!cover([{ type: 'p', identifier: 'acct-1' }],
                 [{ type: 'p', identifier: 'acct-2' }]),
          'identifier is compared exactly');
  t.check(cover([{ type: 'f', currency: 'USD' }],
                [{ type: 'f', currency: 'USD', actions: ['withdraw'] }]) &&
          !cover([{ type: 'f', currency: 'USD' }],
                 [{ type: 'f', currency: 'EUR' }]),
          'an API-specific member must be deep-equal when the grant carries ' +
          'it');
  t.check(!cover([{ type: 'other' }], [{ type: 'p', actions: [] }]),
          'an EMPTY dimension in a requirement is not vacuously covered — ' +
          'the type still has to match');
  t.check(cover([{ type: 'p' }], []) && cover([{ type: 'p' }], null),
          'an absent or empty requirement is covered');
  t.check(!cover('read', ['read']) && !cover(['read'], [42]), 'malformed ' +
      'input is not covered');
  const many = [];
  for (let i = 0; i < 40; i++) {
    many.push('v' + i);
  }
  const big = { type: 'p', actions: many, locations: many };
  t.check(cover([{ type: 'p', actions: many, locations: many }], [big]),
          'a requirement past MAX_POINTS falls back to one grant covering it ' +
          'whole — and that grant does');
  t.check(!cover([{ type: 'p', actions: many.slice(0, 20), locations: many },
                  { type: 'p', actions: many.slice(20), locations: many }],
                 [big]),
          'past MAX_POINTS a union of two grants is (conservatively) not ' +
          'enough');

  t.log.info('=== normalise(), dedupe(), intersect(), union() ===');
  refused(t, gnapAccess.normalise('read'), 'STS-GNAP-0300', 'normalise ' +
      'refuses a non-array');
  refused(t, gnapAccess.normalise([]), 'STS-GNAP-0300', 'normalise refuses ' +
                                                        'an empty array');
  refused(t, gnapAccess.normalise([{ actions: ['read'] }]), 'STS-GNAP-0301',
          'normalise refuses an object with no type');
  refused(t, gnapAccess.normalise([{ type: 'p', actions: 'read' }]),
          'STS-GNAP-0302',
          'normalise refuses a dimension that is not an array of strings');
  const n = gnapAccess.normalise([{ type: 'p', actions: ['r'] },
                                  { actions: ['r'], type: 'p' }, 'x', 'x']);
  t.equal(n.ok && n.access.length, 2, 'normalise deduplicates rights that ' +
                                      'differ only in member order');
  t.equal(JSON.stringify(gnapAccess.intersect([{ type: 'p',
                                                 actions: ['read'] }],
                                              [{ type: 'p', actions: ['read'] },
                                               { type: 'p',
                                                 actions: ['write'] }, 'z'])),
          JSON.stringify([{ type: 'p', actions: ['read'] }]),
          'intersect keeps the requested rights the grant covers, whole');
  t.equal(gnapAccess.union(['a', 'b'], ['b', 'c']).join(','), 'a,b,c',
          'union ' +
      'deduplicates');
  refused(t,
          gnapAccess.validateModel(Object.assign(bearerModel(), { flags: [] })),
          'STS-GNAP-0303',
          'a model whose bearer flag and cnf disagree is not a model');
  refused(t,
          gnapAccess.validateModel(Object.assign(fullModel(),
                                                 { flags: ['bearer',
                                                           'durable'] })),
          'STS-GNAP-0303', 'a bound model carrying the bearer flag is not a ' +
                           'model');
  log.debug("Leaving accessCases().");
}

// The matrix every format answers identically.
async function commonCases(t, fmt, keys, wrongKeys, tamper) {
  log.debug("Entering commonCases().");
  const name = fmt.FORMAT;
  t.log.info('=== ' + name + ': round trip, time, audience, binding, access, ' +
                             'tamper, key ===');
  const d = fmt.describe();
  t.check(d.name === name && d.libraries.length > 0 &&
          d.libraries.every(function (l) { return l.version && l.license; }) &&
          d.algorithms.length > 0 && d.carries.length === 12,
          name + ': describe() names the format, its libraries with versions ' +
                 'and licences, and 12 carried fields',
          JSON.stringify(d.libraries));

  const full = fullModel();
  const minted = await fmt.mint(full, keys);
  t.check(minted && typeof minted.value === 'string' &&
          minted.format === name && minted.jti === full.jti,
          name + ': mint() returns a value, the format and the jti');
  t.check(/^[A-Za-z0-9._~+/-]+=*$/.test(minted.value), name + ': the value ' +
      'is token68 (RFC 9110 section 11.2)');
  const ctx = { now: NOW, audience: 'https://rs2.example/api',
                presentedKey: { jkt: JKT },
                requiredAccess: [{ type: 'photo-api', actions: ['read'],
                                   datatypes: ['images'] }] };
  const v = await fmt.verify(minted.value, keys, ctx);
  if (accepted(t, v, name + ': a fully populated bound token verifies')) {
    sameModel(t, v.model, full, name + ' full');
  }

  const min = bearerModel();
  const mintedMin = await fmt.mint(min, keys);
  const vMin = await fmt.verify(mintedMin.value, keys,
                                { now: NOW, audience: 'https://any.rs',
                                  presentedKey: null });
  if (accepted(t, vMin, name + ': a minimal bearer token with no audience ' +
                               'verifies at any RS')) {
    sameModel(t, vMin.model, min, name + ' minimal');
  }
  accepted(t,
           await fmt.verify(mintedMin.value, keys,
                            { now: NOW, audience: null,
                              presentedKey: { jkt: JKT } }),
           name + ': a bearer token presented alongside a key is still ' +
                  'accepted (RFC 9635 section 7.2)');

  refused(t,
          await fmt.mint(Object.assign(fullModel(),
                                       { exp: NOW - 100, iat: NOW }), keys),
          'STS-GNAP-0303', name + ': mint() refuses a model whose exp is ' +
                                  'before its iat');
  refused(t,
          await fmt.verify(minted.value, keys,
                           Object.assign({}, ctx, { now: full.exp })),
          'STS-GNAP-0304', name + ': a token is expired AT exp');
  refused(t,
          await fmt.verify(minted.value, keys,
                           Object.assign({}, ctx, { now: full.nbf - 1 })),
          'STS-GNAP-0305', name + ': a token is not valid a second before nbf');
  accepted(t,
           await fmt.verify(minted.value, keys,
                            Object.assign({}, ctx, { now: full.nbf })),
           name + ': a token is valid AT nbf');
  refused(t,
          await fmt.verify(minted.value, keys,
                           Object.assign({}, ctx,
                                         { audience:
                                             'https://rs3.example/api' })),
          'STS-GNAP-0306', name + ': an RS the audience does not name is ' +
                                  'refused');
  accepted(t,
           await fmt.verify(minted.value, keys,
                            Object.assign({}, ctx, { audience: null })),
           name + ': a verifier that is not an RS (audience null) asks ' +
                  'nothing of the audience');
  refused(t,
          await fmt.verify(minted.value, keys,
                           Object.assign({}, ctx, { presentedKey: null })),
          'STS-GNAP-0307', name + ': a bound token presented with no key is ' +
                                  'refused');
  refused(t,
          await fmt.verify(minted.value, keys,
                           Object.assign({}, ctx,
                                         { presentedKey: { jkt: X5T } })),
          'STS-GNAP-0307', name + ': a bound token presented with another ' +
                                  'key is refused');
  refused(t,
          await fmt.verify(minted.value, keys,
                           Object.assign({}, ctx,
                                         { presentedKey: {
                                           'x5t#S256': JKT } })),
          'STS-GNAP-0307', name + ': the right thumbprint under the wrong ' +
                                  'member is refused');
  const x5tMinted = await fmt.mint(fullModel({ jti: 'x5t-tok',
                                               cnf: { 'x5t#S256': X5T } }),
                                   keys);
  accepted(t,
           await fmt.verify(x5tMinted.value, keys,
                            Object.assign({}, ctx,
                                          { presentedKey: {
                                            'x5t#S256': X5T } })),
           name + ': an x5t#S256-bound token verifies with its certificate ' +
                  'thumbprint');
  const kidMinted = await fmt.mint(fullModel({ jti: 'kid-tok',
                                               cnf: { kid: 'client ' +
      'key/7' } }), keys);
  const kidV = await fmt.verify(kidMinted.value, keys,
                                Object.assign({}, ctx,
                                              { presentedKey: { kid: 'client ' +
      'key/7' } }));
  t.check(kidV.ok && kidV.model.cnf.kid === 'client key/7',
          name + ': a key-reference-bound token verifies and carries the ' +
                 'reference', JSON.stringify(kidV));
  accepted(t, await fmt.verify(minted.value, keys, Object.assign({}, ctx, {
    requiredAccess: ['dolphin-metadata',
                     { type: 'financial-transaction', actions: ['withdraw'],
                       currency: 'USD' }]
  })), name + ': a requirement the access covers is accepted');
  refused(t, await fmt.verify(minted.value, keys, Object.assign({}, ctx, {
    requiredAccess: [{ type: 'photo-api', actions: ['delete'] }]
  })), 'STS-GNAP-0308', name + ': a requirement the access does not cover is ' +
                               'refused');

  const tampered = tamper(minted.value);
  const tv = await fmt.verify(tampered.value, keys, ctx);
  refused(t, tv, tampered.code, name + ': a tampered token is refused as ' +
                                       'tampered');
  const wrong = await fmt.verify(minted.value, wrongKeys, ctx);
  refused(t, wrong, tampered.wrongKeyCode, name + ': a token verified with ' +
                                                  'another AS key is refused');
  refused(t, await fmt.verify('not a token!', keys, ctx), tampered.garbageCode,
          name + ': a value that is not the format at all is refused');
  log.debug("Leaving commonCases().");
  return minted;
}

async function macaroonCases(t) {
  log.debug("Entering macaroonCases().");
  const keys = { rootKey: nodeCrypto.randomBytes(32),
                 location: 'https://as.example/gnap' };
  const wrongKeys = { rootKey: nodeCrypto.randomBytes(32) };
  // A bearer macaroon under the same root key, for the appended-binding case.
  const mintedBearer = await macaroon.mint(bearerModel(), keys);
  const minted = await commonCases(t, macaroon, keys, wrongKeys,
                                   function (value) {
    const text = Buffer.from(value, 'base64url').toString('latin1');
    const swapped = text.replace('gnap:sub=alice@example.com',
                                 'gnap:sub=mallo@example.com');
    return { value: Buffer.from(swapped, 'latin1').toString('base64url'),
             code: 'STS-GNAP-0314',
             wrongKeyCode: 'STS-GNAP-0314', garbageCode: 'STS-GNAP-0311' };
  });
  t.log.info('=== macaroon: the serialiser, the grammar, and attenuation ===');
  const small = macaroonLib.newMacaroon({ identifier: 'gnap:v1:x',
                                          location: 'https://as',
                                          rootKey: new Uint8Array(32) });
  small.addFirstPartyCaveat('gnap:iss=https://as');
  small.addFirstPartyCaveat('gnap:iat=1');
  t.check(Buffer.compare(Buffer.from(small.exportBinary()),
                         macaroon.encodeBinaryV2(small)) === 0,
          'macaroon: encodeBinaryV2() writes the library\'s own v2 bytes ' +
          '(compared where the library can still export)');
  refused(t,
          await macaroon.mint(fullModel(),
                              { rootKey: nodeCrypto.randomBytes(16) }),
          'STS-GNAP-0310',
          'macaroon: a root key shorter than 32 bytes is refused');
  refused(t, await macaroon.mint(fullModel({ aud: ['https://rs one'] }), keys),
          'STS-GNAP-0310',
          'macaroon: an audience the grammar cannot spell (whitespace) is ' +
          'refused at mint');

  const ctx = { now: NOW, audience: 'https://rs1.example/api',
                presentedKey: { jkt: JKT } };
  const narrowed = await macaroon.attenuate(minted.value, [
    { aud: ['https://rs2.example/api'] },
    { access: [{ type: 'photo-api', actions: ['read'] }, 'dolphin-metadata'] },
    'gnap:exp<' + (NOW + 100)
  ]);
  accepted(t, narrowed, 'macaroon: attenuate() adds aud, access and exp ' +
                        'caveats with no key');
  refused(t, await macaroon.verify(narrowed.value, keys, ctx), 'STS-GNAP-0306',
          'macaroon: an attenuating aud caveat narrows — rs1 is in the ' +
          'authority list and not the added one');
  const rs2 = Object.assign({}, ctx, { audience: 'https://rs2.example/api' });
  const nv = await macaroon.verify(narrowed.value, keys, rs2);
  t.check(nv.ok && nv.attenuated === true, 'macaroon: the narrowed token ' +
                                           'verifies at rs2 and says it was ' +
                                           'attenuated',
          JSON.stringify(nv));
  if (nv.ok) {
    sameModel(t, nv.model, fullModel(), 'macaroon attenuated (the model is ' +
                                        'the AUTHORITY\'s)');
  }
  refused(t,
          await macaroon.verify(narrowed.value, keys, Object.assign({}, rs2, {
    requiredAccess: [{ type: 'photo-api', actions: ['write'] }]
  })), 'STS-GNAP-0308', 'macaroon: an attenuating access caveat narrows — ' +
                        'write is in the authority list only');
  refused(t,
          await macaroon.verify(narrowed.value, keys,
                                Object.assign({}, rs2, { now: NOW + 100 })),
          'STS-GNAP-0304', 'macaroon: an attenuating exp caveat narrows — ' +
                           'the earliest exp wins');

  // Removing the last caveat while keeping the signature: the chain must break.
  const imported = macaroonLib.importMacaroon(new Uint8Array(
      Buffer.from(narrowed.value, 'base64url')));
  const cut = { identifier: imported.identifier, location: imported.location,
                caveats: imported.caveats.slice(0, -1),
                signature: imported.signature };
  refused(t,
          await macaroon.verify(macaroon.encodeBinaryV2(cut)
                                        .toString('base64url'), keys, rs2),
          'STS-GNAP-0314', 'macaroon: REMOVING a caveat breaks the HMAC chain');

  function appendRaw(value, caveat) {
    log.debug("Entering appendRaw().");
    const m = macaroonLib.importMacaroon(new Uint8Array(
        Buffer.from(value, 'base64url')));
    m.addFirstPartyCaveat(caveat);
    log.debug("Leaving appendRaw().");
    return macaroon.encodeBinaryV2(m).toString('base64url');
  }
  refused(t,
          await macaroon.verify(appendRaw(minted.value, 'gnap:sub=mallory'),
                                keys, ctx), 'STS-GNAP-0316',
          'macaroon: a subject APPENDED after the authority section is ' +
          'refused, not believed');
  refused(t,
          await macaroon.verify(appendRaw(mintedBearer.value,
                                          'gnap:cnf=jkt:' + JKT), keys,
                                   { now: NOW, presentedKey: { jkt: JKT } }),
          'STS-GNAP-0316', 'macaroon: a binding appended to a bearer token ' +
                           'is refused');
  refused(t,
          await macaroon.verify(appendRaw(minted.value, 'time < 2030'), keys,
                                ctx), 'STS-GNAP-0315',
          'macaroon: a caveat outside the grammar makes verification FAIL ' +
          'rather than being skipped');
  refused(t, await macaroon.attenuate(minted.value, ['gnap:label=mine']),
          'STS-GNAP-0317',
          'macaroon: attenuate() refuses a caveat that is not exp, nbf, aud ' +
          'or access');
  const third = macaroonLib.importMacaroon(new Uint8Array(
      Buffer.from(minted.value, 'base64url')));
  third.addThirdPartyCaveat(nodeCrypto.randomBytes(32), 'discharge-me',
                            'https://third.example');
  refused(t,
          await macaroon.verify(macaroon.encodeBinaryV2(third)
                                        .toString('base64url'), keys, ctx),
          'STS-GNAP-0313', 'macaroon: a third-party caveat is refused before ' +
                           'the chain is walked');
  const wrongId = macaroonLib.newMacaroon({ identifier: 'other:' + 'x',
                                            rootKey: keys.rootKey });
  refused(t,
          await macaroon.verify(macaroon.encodeBinaryV2(wrongId)
                                        .toString('base64url'), keys, ctx),
          'STS-GNAP-0312', 'macaroon: an identifier that is not ' +
                           'gnap:v1:<jti> is refused');
  log.debug("Leaving macaroonCases().");
}

async function biscuitCases(t) {
  log.debug("Entering biscuitCases().");
  const pair = nodeCrypto.generateKeyPairSync('ed25519');
  const other = nodeCrypto.generateKeyPairSync('ed25519');
  const keys = { privateKey: pair.privateKey, publicKey: pair.publicKey };
  const wrongKeys = { publicKey: other.publicKey };
  const minted = await commonCases(t, biscuit, keys, wrongKeys,
                                   function (value) {
    return { value: flipOne(value), code: 'STS-GNAP-0322',
             wrongKeyCode: 'STS-GNAP-0322',
             garbageCode: 'STS-GNAP-0322' };
  });
  t.log.info('=== biscuit: attenuation blocks ===');
  const ctx = { now: NOW, audience: 'https://rs1.example/api',
                presentedKey: { jkt: JKT },
                requiredAccess: [{ type: 'photo-api', actions: ['read'] }] };
  const onlyRs2 = await biscuit.attenuate(minted.value, 'check if rs({rs});',
                                          keys,
                                          { rs: 'https://rs2.example/api' });
  accepted(t, onlyRs2, 'biscuit: attenuate() appends a block of checks');
  refused(t, await biscuit.verify(onlyRs2.value, keys, ctx), 'STS-GNAP-0324',
          'biscuit: an appended block check that fails (rs is rs1, the block ' +
          'wants rs2) makes verification fail');
  const at2 = await biscuit.verify(onlyRs2.value, keys,
                                   Object.assign({}, ctx,
                                                 { audience: 'https://rs2.example/api' }));
  t.check(at2.ok && at2.attenuated === true, 'biscuit: the same token ' +
                                             'verifies at rs2 and says it ' +
                                             'was attenuated',
          JSON.stringify(at2));
  if (at2.ok) {
    sameModel(t, at2.model, fullModel(), 'biscuit attenuated (no block fact ' +
                                         'reaches the model)');
  }
  const readOnly = await biscuit.attenuate(minted.value, 'reject if ' +
      'request_action($i, $a), $a != "read";', keys);
  accepted(t, await biscuit.verify(readOnly.value, keys, ctx), 'biscuit: a ' +
      'read-only block lets a read through');
  refused(t, await biscuit.verify(readOnly.value, keys, Object.assign({}, ctx, {
    requiredAccess: [{ type: 'photo-api', actions: ['write'] }]
  })), 'STS-GNAP-0324', 'biscuit: a read-only block refuses a write the ' +
                        'authority block grants');
  const forged = await biscuit.attenuate(minted.value, 'access(0, ' +
                                                       '"{\\"type\\":\\"everything\\"}' +
                                                       '"); ' +
                                                       'gnap_token("forged");',
                                         keys);
  const fv = await biscuit.verify(forged.value, keys,
                                  Object.assign({}, ctx,
                                                { requiredAccess: [
                                                  { type: 'everything' }] }));
  refused(t, fv, 'STS-GNAP-0308', 'biscuit: access facts in an attenuation ' +
                                  'block never reach the model');
  refused(t, await biscuit.attenuate(minted.value, 'check if ((((', keys),
          'STS-GNAP-0326',
          'biscuit: a block that does not parse is refused');
  refused(t, await biscuit.attenuate(minted.value, 'allow if true;', keys),
          'STS-GNAP-0326',
          'biscuit: a block cannot carry a policy');
  refused(t,
          await biscuit.mint(fullModel(),
                             { privateKey: nodeCrypto.generateKeyPairSync('ec',
                                                                          { namedCurve: 'P-256' }).privateKey }),
          'STS-GNAP-0320', 'biscuit: a key that is not Ed25519 is refused');
  log.debug("Leaving biscuitCases().");
}

async function zcapCases(t) {
  log.debug("Entering zcapCases().");
  const pair = nodeCrypto.generateKeyPairSync('ed25519');
  const other = nodeCrypto.generateKeyPairSync('ed25519');
  const controller = 'https://as.example/realm/acme/gnap/zcap/controller';
  const keys = { privateKey: pair.privateKey, publicKey: pair.publicKey,
                 controller: controller,
                 keyId: controller + '#as-1' };
  const wrongKeys = Object.assign({}, keys, { publicKey: other.publicKey });
  const minted = await commonCases(t, zcap, keys, wrongKeys, function (value) {
    const doc = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
    doc.gnapAccess[0].actions.push('delete');
    return { value: Buffer.from(JSON.stringify(doc), 'utf8')
                          .toString('base64url'), code: 'STS-GNAP-0333',
             wrongKeyCode: 'STS-GNAP-0333', garbageCode: 'STS-GNAP-0332' };
  });
  t.log.info('=== zcap: the capability shape, the pinned context, the ' +
             'controller document ===');
  const doc = JSON.parse(Buffer.from(minted.value, 'base64url')
                               .toString('utf8'));
  t.check(doc.invocationTarget === 'https://rs1.example/api' &&
          doc.parentCapability === 'urn:zcap:root:' +
                                   encodeURIComponent(
                                       'https://rs1.example/api') &&
          doc.controller === 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' +
                             JKT &&
          JSON.stringify(doc.allowedAction) === JSON.stringify(
              ['read', 'write', 'withdraw']) &&
          doc.proof && doc.proof.proofPurpose === 'capabilityDelegation',
          'zcap: target is aud[0], parent is its root, controller is the RFC ' +
          '9278 jkt URN, allowedAction is the union of ' +
          'actions', JSON.stringify(doc).slice(0, 400));
  const swapped = JSON.parse(JSON.stringify(doc));
  swapped['@context'][2].gnapLabel = 'gnap:sub';
  refused(t,
          await zcap.verify(Buffer.from(JSON.stringify(swapped))
                                  .toString('base64url'), keys,
                               { now: NOW, presentedKey: { jkt: JKT } }),
          'STS-GNAP-0332', 'zcap: a capability whose @context is not exactly ' +
                           'the pinned one is refused');
  refused(t,
          await zcap.verify(minted.value, keys,
                            { now: NOW + 3600 + 31536000,
                              presentedKey: { jkt: JKT } }),
          'STS-GNAP-0304', 'zcap: a capability a year past expiry is refused ' +
          '— the ZCAP library checks a PARENT\'s expires and never the ' +
          'verified capability\'s own, so this check is the only one');
  const extra = Object.assign({}, doc, { gnapExtra: 1 });
  refused(t,
          await zcap.verify(Buffer.from(JSON.stringify(extra))
                                  .toString('base64url'), keys,
                               { now: NOW, presentedKey: { jkt: JKT } }),
          'STS-GNAP-0332', 'zcap: a member this format does not write is ' +
                           'refused');
  refused(t,
          await zcap.verify(minted.value,
                               Object.assign({}, keys,
                                             { keyId: controller + '#as-2' }),
                               { now: NOW, presentedKey: { jkt: JKT } }),
          'STS-GNAP-0333', 'zcap: a proof naming a key the offline loader ' +
                           'does not serve is refused');
  const bearer = await zcap.mint(bearerModel(), keys);
  const bdoc = JSON.parse(Buffer.from(bearer.value, 'base64url')
                                .toString('utf8'));
  t.check(bdoc.invocationTarget === 'urn:gnap:as:https://as.example/gnap' &&
          bdoc.controller === 'urn:gnap:bearer' &&
          bdoc.allowedAction === undefined,
          'zcap: with no audience the target is the AS, a bearer controller ' +
          'is urn:gnap:bearer, and no actions means no allowedAction');
  // A resource server's identifier is an application entry's name, which is
  // usually not a URI. Minting refused every such token until 2026-09-12 — the
  // in-process audiences above were all URLs, so only sts_gnap_rs.js saw it.
  const named = await zcap.mint(fullModel({ aud: ['photo-rs'] }), keys);
  const ndoc = named.value ?
               JSON.parse(Buffer.from(named.value, 'base64url')
                                .toString('utf8')) : {};
  t.check(ndoc.invocationTarget === 'urn:gnap:rs:photo-rs',
          'zcap: an audience that is not a URI is carried as ' +
          'urn:gnap:rs:<id> rather than refused',
          JSON.stringify(named).slice(0, 300));
  const namedBack = named.value ?
                    await zcap.verify(named.value, keys,
                                      { now: NOW, presentedKey: { jkt: JKT },
                                                                          audience: 'photo-rs' }) : {};
  t.check(namedBack.ok && namedBack.model.aud[0] === 'photo-rs',
          'zcap: and it verifies back to the same audience',
          JSON.stringify(namedBack).slice(0, 300));
  const cd = await zcap.controllerDocument({ privateKey: pair.privateKey,
                                             controller: controller,
                                             keyId: keys.keyId });
  t.check(cd.id === controller && cd.capabilityDelegation[0] === keys.keyId &&
          cd.verificationMethod[0].type === 'Ed25519VerificationKey2020' &&
          cd.verificationMethod[0].controller === controller,
          'zcap: controllerDocument() publishes the AS key for ' +
          'capabilityDelegation', JSON.stringify(cd));
  refused(t,
          await zcap.mint(fullModel(),
                          Object.assign({}, keys,
                                        { keyId: 'https://elsewhere#k' })),
          'STS-GNAP-0330', 'zcap: a keyId outside the controller document is ' +
                           'refused');
  log.debug("Leaving zcapCases().");
}

// ---------------------------------------------------------------------------
// THE TWO JWT FORMATS, THROUGH THE SAME MATRIX (2026-09-12).
//
// They had no in-process case at all: the three library formats each have a
// module of their own with `mint(model, keys)` / `verify(value, keys, ctx)`,
// and the JWT formats live inside `gnap/gnap_tokens.js`'s dispatcher, keyed by
// the ambient REALM's signing key rather than by a key handed in. So an adapter
// gives them the library shape — `keys.realm` is the realm the token is minted
// and verified in, and "another AS key" is another realm, which is exactly what
// another authorization server's key is here.
// ---------------------------------------------------------------------------
function jwtFormat(format, extra) {
  log.debug("Entering jwtFormat().");
  const realms = require('../common/realms');
  const tokens = require('../gnap/gnap_tokens');
  log.debug("Leaving jwtFormat().");
  return {
    FORMAT: format,
    describe: function () {
      log.debug("Entering describe().");
      log.debug("Leaving describe().");
      return { name: format,
               libraries: [gnapAccess.libraryInfo('jsonwebtoken')],
               algorithms: [['JWS', ['RS256']]].concat(
                   format === 'jwt-encrypted' ? [['JWE', ['dir', 'A256GCM']]] :
                   []),
               carries: FIELDS.slice() };
    },
    mint: async function (model, keys) {
      log.debug("Entering mint().");
      try {
        log.debug("Leaving mint().");
        return await realms.run(keys.realm, function () {
          return tokens.mint(format, model,
                             Object.assign({ base: 'https://as.example' },
                                           extra || {}));
        });
      } catch (e) {
        // A JWT mint REFUSES by throwing (gnap_tokens.js's mintedOrThrow()
        // header); the matrix reads a refusal object, so the code is carried
        // over.
        const code = e.errorCode || errorCodes.codeOf(e) || 'none';
        log.debug("Leaving mint().");
        return errorCodes.mark({ ok: false, errorCode: code, why: e.message },
                               code);
      }
    },
    verify: function (value, keys, ctx) {
      log.debug("Entering verify().");
      log.debug("Leaving verify().");
      return realms.run(keys.realm, function () {
        return tokens.verify(format, value,
                             Object.assign({ base: 'https://as.example' }, ctx,
                                                          keys.rsPrivateKey ?
                                                              { rsPrivateKey: keys.rsPrivateKey } : {}));
      });
    }
  };
}

async function jwtCases(t) {
  log.debug("Entering jwtCases().");
  const realms = require('../common/realms');
  const idA = 'gnapjwt-a-' + Date.now().toString(36);
  const idB = 'gnapjwt-b-' + Date.now().toString(36);
  realms.create({ id: idA });
  realms.create({ id: idB });
  try {
    const keys = { realm: realms.get(idA) };
    const wrongKeys = { realm: realms.get(idB) };
    const signed = await commonCases(t, jwtFormat('jwt-signed'), keys,
                                     wrongKeys, function (value) {
      const parts = value.split('.');
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url')
                                      .toString('utf8'));
      claims.sub = 'mallory@example.com';
      parts[1] = Buffer.from(JSON.stringify(claims)).toString('base64url');
      return { value: parts.join('.'), code: 'STS-GNAP-0342',
               wrongKeyCode: 'STS-GNAP-0342',
               garbageCode: 'STS-GNAP-0342' };
    });
    t.log.info('=== jwt-signed: the header and the claims ===');
    const header = JSON.parse(Buffer.from(signed.value.split('.')[0],
                                          'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(signed.value.split('.')[1],
                                          'base64url').toString('utf8'));
    t.check(header.alg === 'RS256' && claims.typ === 'GNAP' &&
            claims.client_id === 'client-instance-7' &&
            Array.isArray(claims.aud) && claims.cnf.jkt === JKT,
            'jwt-signed: RS256, typ GNAP, client_id is the instance, aud ' +
            'kept as an array, cnf.jkt carried',
            JSON.stringify({ header: header, claims: claims }));
    const oauthLike = await realms.run(keys.realm, function () {
      return require('../common/helpers').signJwt(
          { typ: 'Bearer', sub: 'alice', iss: 'x', exp: NOW + 60 });
    });
    refused(t,
            await jwtFormat('jwt-signed').verify(oauthLike, keys,
                                                 { now: NOW, audience: null,
                                                   presentedKey: null }),
            'STS-GNAP-0343', 'jwt-signed: an OAuth access token signed by ' +
                             'the SAME key is not a GNAP token');

    await commonCases(t, jwtFormat('jwt-encrypted'), keys, wrongKeys,
                      function (value) {
      const parts = value.split('.');
      parts[3] = flipOne(parts[3]);
      return { value: parts.join('.'), code: 'STS-GNAP-0341',
               wrongKeyCode: 'STS-GNAP-0341',
               garbageCode: 'STS-GNAP-0341' };
    });
    t.log.info('=== jwt-encrypted: to a resource server\'s own key ===');
    const rsPair = nodeCrypto.generateKeyPairSync('rsa',
                                                  { modulusLength: 2048 });
    const rsJwk = Object.assign(rsPair.publicKey.export({ format: 'jwk' }),
                                { alg: 'RSA-OAEP-256' });
    const toRs = jwtFormat('jwt-encrypted',
                           { rs: { identity: 'photo-rs', jweKey: rsJwk } });
    const minted = await toRs.mint(fullModel(), keys);
    const jweHeader = JSON.parse(Buffer.from(minted.value.split('.')[0],
                                             'base64url').toString('utf8'));
    t.check(jweHeader.alg === 'RSA-OAEP-256' && jweHeader.enc === 'A256GCM' &&
            jweHeader.cty === 'JWT',
            'jwt-encrypted: a resource server with a gnapJweKey gets ' +
            'RSA-OAEP-256 + A256GCM, cty JWT',
            JSON.stringify(jweHeader));
    const ctx = { now: NOW, audience: 'https://rs1.example/api',
                  presentedKey: { jkt: JKT } };
    refused(t, await toRs.verify(minted.value, keys, ctx), 'STS-GNAP-0340',
            'jwt-encrypted: a token encrypted to a resource server\'s key is ' +
            'opaque to this AS');
    const opened = await toRs.verify(minted.value,
                                     Object.assign({}, keys,
                                                   { rsPrivateKey: rsPair.privateKey }), ctx);
    if (accepted(t, opened, 'jwt-encrypted: the resource server\'s private ' +
                            'key opens it and the JWS inside verifies')) {
      sameModel(t, opened.model, fullModel(), 'jwt-encrypted to an RS');
    }
    const otherRs = nodeCrypto.generateKeyPairSync('rsa',
                                                   { modulusLength: 2048 });
    refused(t,
            await toRs.verify(minted.value,
                              Object.assign({}, keys,
                                            { rsPrivateKey:
                                                otherRs.privateKey }), ctx),
            'STS-GNAP-0341', 'jwt-encrypted: another resource server\'s ' +
                             'private key does not');
  } finally {
    realms.remove(idA);
    realms.remove(idB);
  }
  log.debug("Leaving jwtCases().");
}

async function run(t) {
  log.debug("Entering run().");
  accessCases(t);
  const started = Date.now();
  await macaroonCases(t);
  await biscuitCases(t);
  await zcapCases(t);
  await jwtCases(t);
  t.log.info('five formats in ' + (Date.now() - started) + 'ms');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'gnap_token_formats',
  describe: 'GNAP macaroon, biscuit and zcap token formats round-trip the ' +
            'RFC 9767 model and refuse what they must',
  run: run
};
