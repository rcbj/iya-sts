// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: credentials-webauthn.js
//
// ---------------------------------------------------------------------------
// THE WEBAUTHN HALF OF THE CREDENTIALS' VECTORS (#444 phase 5): registrations
// and assertions made by SOFTWARE AUTHENTICATORS here, at run time, with
// `tests/webauthn_attestation_kit.js` — every key and certificate in memory,
// none in the repository — for every algorithm a passkey may use (ES256,
// ES384, ES512, ES256K, ESP256, EdDSA and Ed25519, RS256, PS256,
// ML-DSA-44/65/87, and RS1 behind its setting) and the attestation formats
// `none`, `packed` (Self and Basic), `tpm` and `fido-u2f`, each also spoiled
// in each of the ways the kit offers; then what `authn/webauthn.js`'s
// `verifyRegistration()` and `verifyAssertion()` answered, and what
// `webauthn_attestation.ts`'s `verifyStatement()` answered over the context
// `assess()` builds. Malformed input — CBOR that is not CTAP2's, short
// authenticator data, client data that is not JSON — is recorded with the
// sentence Node threw.
//
// `checkRust()` is the other direction: Node verifies, with
// `verifyAssertion()`, assertions against the public keys the crate read
// out of registrations.
// ---------------------------------------------------------------------------

const path = require('path');
const nodeCrypto = require('crypto');

function clone(value) {
  return value === undefined ? null : JSON.parse(JSON.stringify(value));
}

async function build(ROOT) {
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const webauthn = req('authn/webauthn');
  const kit = req('tests/webauthn_attestation_kit');
  const attestationModule = req('authn/webauthn_attestation');
  const Attestation = attestationModule.WebauthnAttestation;
  const deps = Attestation.defaultDeps();
  let insecure = false;
  deps.policy = Object.assign(Object.create(deps.policy), {
    insecureAlgorithmsAllowed: function () {
      return insecure;
    }
  });
  // The verifier's clock, recorded on each row: SafetyNet's timestampMs is
  // held to it.
  let nowMs = Date.now();
  deps.now = function () {
    return nowMs;
  };
  const attestation = new Attestation(deps);
  const sha256 = function (data) {
    return nodeCrypto.createHash('sha256').update(data).digest();
  };
  const project = function (r) {
    return { ok: r.ok, checks: r.checks, failed: r.failed, fmt: r.fmt,
             aaguid: r.aaguid, credentialId: r.credentialId,
             publicKeyJwk: r.publicKeyJwk, algorithm: r.algorithm,
             signCount: r.signCount, flags: r.flags,
             attStmt: clone(r.attStmt), coseAlg: r.coseAlg,
             extensions: r.extensions };
  };
  const statementOf = function (s) {
    const out = { ok: s.ok, format: s.format };
    if (s.ok) {
      out.type = s.type;
      out.trustPath = (s.trustPath || []).length;
      if (s.acki) {
        out.acki = s.acki;
      }
    } else {
      out.code = s.code;
      out.why = s.why;
    }
    return out;
  };
  const registrations = [];
  const assertions = [];
  const register = async function (name, input, opts) {
    let answer = null;
    let threw = null;
    let statement = null;
    try {
      const r = webauthn.verifyRegistration(input);
      answer = project(r);
      const ctx = {
        authData: Buffer.from(r.authDataRaw || []),
        clientDataHash: Buffer.from(r.clientDataHash || []),
        cose: r.credentialPublicKeyCose, coseAlg: Number(r.coseAlg),
        credentialJwk: r.publicKeyJwk,
        aaguid: Buffer.from(String(r.aaguid || ''), 'hex'),
        credentialId: Buffer.from(r.credentialIdRaw || []),
        rpIdHash: Buffer.from(r.rpIdHash || []),
        settings: (opts && opts.settings) || {}
      };
      insecure = !!(opts && opts.insecure);
      nowMs = Date.now();
      if ((opts || {}).statement !== false) {
        statement = statementOf(await attestation.verifyStatement(
          r.fmt, r.attStmt, ctx, 0));
      }
      insecure = false;
    } catch (e) {
      threw = String((e && e.message) || e);
    }
    registrations.push({ name: name, input: input, answer: answer,
                         threw: threw, statement: statement,
                         insecure: !!(opts && opts.insecure),
                         settings: (opts && opts.settings) || {},
                         now: nowMs });
    return answer;
  };
  const assert = function (name, input) {
    let answer = null;
    let threw = null;
    try {
      answer = clone(webauthn.verifyAssertion(input));
    } catch (e) {
      threw = String((e && e.message) || e);
    }
    assertions.push({ name: name, input: clone(input), answer: answer,
                      threw: threw });
  };
  // An assertion by the ceremony's credential.
  const assertionInput = function (c, o) {
    const opts = o || {};
    const count = Buffer.alloc(4);
    count.writeUInt32BE(opts.signCount === undefined ? 5 : opts.signCount, 0);
    const authData = Buffer.concat([
      sha256(Buffer.from(opts.signedRpId || c.rpId, 'utf8')),
      Buffer.from([opts.flags === undefined ? 0x05 : opts.flags]), count]);
    const challenge = nodeCrypto.randomBytes(32).toString('base64url');
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: opts.type || 'webauthn.get', challenge: challenge,
      origin: opts.origin || c.origin, crossOrigin: false }));
    let sig = c.credential.sign(Buffer.concat([authData,
                                               sha256(clientDataJSON)]));
    if (opts.tamper) {
      sig = Buffer.from(sig);
      sig[sig.length - 1] ^= 0x01;
    }
    return { authenticatorData: authData.toString('base64url'),
             clientDataJSON: clientDataJSON.toString('base64url'),
             signature: Buffer.from(sig).toString('base64url'),
             expectedChallenge: opts.expectChallenge || challenge,
             expectedOrigin: c.origin, expectedRpId: c.rpId,
             requireUserVerification: !!opts.requireUv,
             previousSignCount: opts.previous,
             allowInsecure: !!opts.allowInsecure };
  };

  // EVERY ALGORITHM: a `none` registration, then assertions.
  const ALGS = [-7, -35, -36, -47, -9, -8, -19, -257, -37, -48, -49, -50];
  const anchors = { vendor: await kit.root('Synthetic Vendor'),
                    tpm: await kit.root('Synthetic TPM Manufacturer', 'rsa'),
                    u2f: await kit.root('Synthetic U2F'),
                    android: await kit.root('Synthetic Android'),
                    google: await kit.root('Synthetic Google'),
                    apple: await kit.root('Synthetic Apple') };
  for (const alg of ALGS) {
    const c = await kit.ceremony({ alg: alg });
    const input = Object.assign(c.input(kit.none()),
                                { expectedAlgorithms: [alg, -7] });
    const reg = await register('none ' + alg, input);
    const jwk = reg && reg.publicKeyJwk;
    assert('assertion ' + alg, Object.assign(assertionInput(c),
                                             { publicKeyJwk: jwk }));
    assert('assertion ' + alg + ', UV required and not given',
           Object.assign(assertionInput(c, { requireUv: true }),
                         { publicKeyJwk: jwk }));
    assert('assertion ' + alg + ', tampered',
           Object.assign(assertionInput(c, { tamper: true }),
                         { publicKeyJwk: jwk }));
  }
  // The checks a registration makes, each failing alone.
  const base = await kit.ceremony({ alg: -7 });
  const good = base.input(kit.none());
  await register('wrong challenge', Object.assign({}, good,
    { expectedChallenge: 'other' }));
  await register('wrong origin', Object.assign({}, good,
    { expectedOrigin: 'https://evil.example' }));
  await register('wrong RP ID', Object.assign({}, good,
    { expectedRpId: 'example.org' }));
  await register('UV required', Object.assign({}, good,
    { requireUserVerification: true }));
  await register('an algorithm not offered', Object.assign({}, good,
    { expectedAlgorithms: [-257, -8] }));
  for (const flags of [0x55, 0x5d, 0x45 | 0x18, 0x44]) {
    const c = await kit.ceremony({ alg: -7, flags: flags });
    await register('flags ' + flags, c.input(kit.none()));
  }
  await register('a get as a create', Object.assign({}, good, {
    clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.get',
      challenge: good.expectedChallenge, origin: good.expectedOrigin }))
      .toString('base64url') }));
  // Malformed input, each with Node's sentence.
  const cbor = kit.cbor;
  [['not CBOR', Buffer.from([0xff])],
   ['a CBOR array', cbor([1, 2])],
   ['an indefinite map', Buffer.from([0xbf, 0xff])],
   ['a tag', Buffer.from([0xc0, 0x01])],
   ['a float', Buffer.from([0xf9, 0x3c, 0x00])],
   ['short bytes', Buffer.from([0x44, 0x01])],
   ['a repeated key', Buffer.concat([Buffer.from([0xa2]), cbor('fmt'),
                                     cbor('none'), cbor('fmt'),
                                     cbor('none')])],
   ['a 64-bit integer', Buffer.from([0x1b, 0xff, 0, 0, 0, 0, 0, 0, 0])],
   ['short authenticator data', cbor(new Map([['fmt', 'none'],
     ['attStmt', new Map()], ['authData', Buffer.alloc(20)]]))],
   ['the AT flag and no room', cbor(new Map([['fmt', 'none'],
     ['attStmt', new Map()],
     ['authData', Buffer.concat([Buffer.alloc(32), Buffer.from([0x41]),
                                 Buffer.alloc(10)])]]))]]
    .forEach(function (row) {
      const input = Object.assign({}, good,
        { attestationObject: row[1].toString('base64url') });
      let threw = null;
      try {
        webauthn.verifyRegistration(input);
      } catch (e) {
        threw = String((e && e.message) || e);
      }
      registrations.push({ name: row[0], input: input, answer: null,
                           threw: threw, statement: null });
    });
  await register('client data that is not JSON', Object.assign({}, good,
    { clientDataJSON: Buffer.from('{nope').toString('base64url') }));

  // THE FORMATS, and each one spoiled.
  const formats = [
    ['packed self', function (c) {
      return kit.packedSelf(c);
    }],
    ['packed self, alg', function (c) {
      return kit.packedSelf(c, 'alg');
    }],
    ['packed self, signature', function (c) {
      return kit.packedSelf(c, 'signature');
    }],
    ['none with members', function () {
      return { fmt: 'none', attStmt: { x: Buffer.alloc(1) } };
    }],
    ['an unknown format', function () {
      return { fmt: 'bogus', attStmt: {} };
    }]
  ];
  [undefined, 'ou', 'ca', 'aaguid-extension', 'signature']
    .forEach(function (spoil) {
      formats.push(['packed ' + (spoil || 'basic'), function (c) {
        return kit.packed(c, anchors.vendor, spoil);
      }]);
    });
  [undefined, 'extra-data', 'name', 'magic', 'signature', 'eku', 'subject',
   'key', 'bare-signature'].forEach(function (spoil) {
    formats.push(['tpm ' + (spoil || 'attca'), function (c) {
      return kit.tpm(c, anchors.tpm, spoil);
    }]);
  });
  [undefined, 'signature', 'two-certificates'].forEach(function (spoil) {
    formats.push(['fido-u2f ' + (spoil || 'basic'), function (c) {
      return kit.fidoU2f(c, anchors.u2f, spoil);
    }]);
  });
  formats.push(['packed, a missing sig', async function (c) {
    const made = await kit.packed(c, anchors.vendor);
    delete made.attStmt.sig;
    return made;
  }]);
  formats.push(['packed, alg a string', async function (c) {
    const made = await kit.packed(c, anchors.vendor);
    made.attStmt.alg = 'ES256';
    return made;
  }]);
  formats.push(['tpm, ver 1.2', async function (c) {
    const made = await kit.tpm(c, anchors.tpm);
    made.attStmt.ver = '1.2';
    return made;
  }]);
  // The four formats the credentials slice left (#444 phase 5, webauthn):
  // android-key, android-safetynet, apple and compound, each spoiled in
  // each way the kit offers.
  [undefined, 'challenge', 'all-applications', 'software-origin', 'purpose',
   'key'].forEach(function (spoil) {
    formats.push(['android-key ' + (spoil || 'basic'), function (c) {
      return kit.androidKey(c, anchors.android, spoil);
    }]);
  });
  formats.push(['android-key software-origin, software keys allowed',
    function (c) {
      return kit.androidKey(c, anchors.android, 'software-origin');
    }, { settings: { androidSoftwareKeys: true } }]);
  formats.push(['android-key, a bare certificate', async function (c) {
    const made = await kit.androidKey(c, anchors.android);
    made.attStmt.x5c = [anchors.android.der];
    return made;
  }]);
  formats.push(['android-key, no KeyDescription', async function (c) {
    const leaf = await kit.certificate({
      subject: [['2.5.4.3', 'Android Keystore Key']],
      publicKey: c.credential.pair.crypto.publicKey, issuer: anchors.android,
      ca: false });
    const made = await kit.androidKey(c, anchors.android);
    made.attStmt.x5c = [leaf.der];
    return made;
  }]);
  [undefined, 'nonce', 'cts', 'stale', 'signature', 'host']
    .forEach(function (spoil) {
      formats.push(['android-safetynet ' + (spoil || 'basic'), function (c) {
        return kit.safetynet(c, anchors.google, spoil);
      }]);
    });
  formats.push(['android-safetynet, not a JWS', function () {
    return { fmt: 'android-safetynet',
             attStmt: { ver: '1', response: Buffer.from('nope') } };
  }]);
  [undefined, 'nonce', 'key'].forEach(function (spoil) {
    formats.push(['apple ' + (spoil || 'anonca'), function (c) {
      return kit.apple(c, anchors.apple, spoil);
    }]);
  });
  formats.push(['apple, no nonce extension', async function (c) {
    const made = await kit.apple(c, anchors.apple);
    made.attStmt.x5c = [anchors.apple.der];
    return made;
  }]);
  const pairOf = function (made) {
    return { fmt: made.fmt, attStmt: made.attStmt };
  };
  formats.push(['compound packed and apple', async function (c) {
    return { fmt: 'compound', attStmt: [
      pairOf(await kit.packed(c, anchors.vendor)),
      pairOf(await kit.apple(c, anchors.apple))] };
  }]);
  formats.push(['compound none and packed self', async function (c) {
    return { fmt: 'compound', attStmt: [pairOf(kit.none()),
                                        pairOf(kit.packedSelf(c))] };
  }]);
  formats.push(['compound, a member spoiled', async function (c) {
    return { fmt: 'compound', attStmt: [
      pairOf(await kit.packed(c, anchors.vendor)),
      pairOf(await kit.apple(c, anchors.apple, 'nonce'))] };
  }]);
  formats.push(['compound, one member', async function (c) {
    return { fmt: 'compound', attStmt: [pairOf(kit.packedSelf(c))] };
  }]);
  formats.push(['compound, a compound member', async function (c) {
    return { fmt: 'compound', attStmt: [pairOf(kit.packedSelf(c)),
      { fmt: 'compound', attStmt: [] }] };
  }]);
  formats.push(['compound, a member with three keys', async function (c) {
    return { fmt: 'compound', attStmt: [pairOf(kit.packedSelf(c)),
      { fmt: 'none', attStmt: {}, x: 1 }] };
  }]);
  formats.push(['compound, a map', async function () {
    return { fmt: 'compound', attStmt: {} };
  }]);
  formats.push(['compound, an unknown member format', async function (c) {
    return { fmt: 'compound', attStmt: [pairOf(kit.packedSelf(c)),
      { fmt: 'bogus', attStmt: {} }] };
  }]);
  for (const row of formats) {
    const c = await kit.ceremony({ alg: -7 });
    const made = await row[1](c);
    await register(row[0], c.input(made), row[2]);
  }
  for (const alg of [-257, -8, -48]) {
    const c = await kit.ceremony({ alg: alg });
    await register('packed self ' + alg, c.input(kit.packedSelf(c)));
  }

  // THE ASSERTION'S CHECKS, each failing alone.
  const c = await kit.ceremony({ alg: -7 });
  const reg = await register('a key for the assertions',
                             c.input(kit.none()));
  const jwk = reg.publicKeyJwk;
  [['as made', {}],
   ['a create as a get', { type: 'webauthn.create' }],
   ['another challenge', { expectChallenge: 'something else' }],
   ['another origin', { origin: 'https://evil.example' }],
   ['another RP ID', { signedRpId: 'example.org' }],
   ['no user presence', { flags: 0x04 }],
   ['UV required and given', { flags: 0x05, requireUv: true }],
   ['the counter advanced', { signCount: 9, previous: 5 }],
   ['the counter did not advance', { signCount: 5, previous: 5 }],
   ['both counters zero', { signCount: 0, previous: 0 }],
   ['the counter went back', { signCount: 0, previous: 3 }]]
    .forEach(function (row) {
      assert(row[0], Object.assign(assertionInput(c, row[1]),
                                   { publicKeyJwk: jwk }));
    });
  assert('a JWK without alg', Object.assign(assertionInput(c),
    { publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } }));
  assert('another key', Object.assign(assertionInput(c),
    { publicKeyJwk: Object.assign({}, jwk, { x: jwk.y }) }));
  assert('short authenticator data', Object.assign(assertionInput(c),
    { authenticatorData: Buffer.alloc(10).toString('base64url'),
      publicKeyJwk: jwk }));
  // RS1, insecure: refused by name unless allowed.
  const rs1 = await kit.ceremony({ alg: -65535 });
  const rs1Reg = await register('RS1', rs1.input(kit.none()));
  const rs1Jwk = rs1Reg && rs1Reg.publicKeyJwk;
  assert('RS1, not allowed', Object.assign(assertionInput(rs1),
    { publicKeyJwk: rs1Jwk }));
  assert('RS1, allowed', Object.assign(assertionInput(rs1,
    { allowInsecure: true }), { publicKeyJwk: rs1Jwk }));
  await register('RS1 packed self, insecure allowed',
                 rs1.input(kit.packedSelf(rs1)), { insecure: true });
  await register('RS1 packed self', rs1.input(kit.packedSelf(rs1)));

  // FOR THE REVERSE DIRECTION: the crate reads each registration's key, and
  // Node verifies the assertion with what it read.
  const reverse = [];
  for (const alg of [-7, -8, -257, -49]) {
    const cc = await kit.ceremony({ alg: alg });
    reverse.push({ alg: alg, registration: cc.input(kit.none()),
                   assertion: assertionInput(cc) });
  }
  return { coseAlgs: webauthn.COSE_ALGS,
           insecure: webauthn.INSECURE_COSE_ALGS,
           registrations: registrations, assertions: assertions,
           reverse: reverse };
}

/**
 * The other direction: for each reverse row, Node verifies the assertion
 * with the JWK the crate read out of the registration.
 *
 * @param {string} ROOT - the repository root
 * @param {any} rust - the crate's `webauthn` answer
 * @param {any} node - the Node vectors' `webauthn`
 * @param {Function} check - the runner's check collector
 */
function checkRust(ROOT, rust, node, check) {
  const webauthn = require(path.join(ROOT, 'authn', 'webauthn'));
  const rows = (rust && rust.reverse) || [];
  const bad = rows.filter(function (row, i) {
    const mine = node.reverse[i];
    if (!mine) {
      return true;
    }
    const answer = webauthn.verifyAssertion(Object.assign({}, mine.assertion,
      { publicKeyJwk: row.publicKeyJwk }));
    return !answer.ok;
  });
  check(rows.length === node.reverse.length && rows.length > 0 &&
          bad.length === 0,
        'credentials: Node verifies an assertion with every public key ' +
        'Rust read out of a registration (' + rows.length + ')',
        bad.map(function (row) {
          return String(row.alg);
        }).join(', '));
}

module.exports = { build: build, checkRust: checkRust };
