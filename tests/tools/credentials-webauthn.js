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
           reverse: reverse,
           trust: await buildTrust(ROOT, kit, anchors) };
}

// ---------------------------------------------------------------------------
// THE TRUST HALF (#444 phase 5, webauthn): `assess()` over a registration,
// its dependencies answered from the case and every question recorded —
// the attestation settings, the clock, the FIDO Metadata Service as rows of
// an MDS3 BLOB SIGNED HERE (`pki.verifyFidoMdsBlob()` against a root made
// here, then `RiskDatasets.mdsRowsOf()`), Google's Android status list as
// `RiskDatasets.androidStatusRowsOf()`'s rows of a list made here, and
// revocation as the case says. The path to the anchors is the real one
// (`CertificateTrust.path()`, the baseline while paranoid PKI mode is off).
// ---------------------------------------------------------------------------
async function buildTrust(ROOT, kit, anchors) {
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const webauthn = req('authn/webauthn');
  const pki = req('common/pki');
  const errorCodes = req('common/error_codes');
  const RiskDatasets = req('risk/risk_datasets').RiskDatasets;
  const Attestation = req('authn/webauthn_attestation').WebauthnAttestation;
  const Revocation = req('common/attestation_revocation')
    .AttestationRevocation;
  const NOW = Date.now();
  let CASE = null;
  let CALLS = null;
  const SETTINGS = {
    configured: 'verify-if-present', policy: 'verify-if-present',
    trustAnchorsPem: '', allowedAaguids: [], minCertificationLevel: 'none',
    requireFips: false, allowSafetynet: false, androidSoftwareKeys: false,
    enterpriseSerialAttribute: '', attestationAlgorithms: [],
    conveyance: 'direct', enterpriseRpIds: [], demandsTrust: false
  };
  const settingsOf = function (over) {
    const out = Object.assign({}, SETTINGS, over || {});
    out.demandsTrust = out.policy === 'require-trusted' ||
      out.allowedAaguids.length > 0 || out.minCertificationLevel !== 'none' ||
      out.requireFips || !!out.enterpriseSerialAttribute ||
      out.attestationAlgorithms.length > 0;
    return out;
  };
  // The MDS BLOB: a root and a signing certificate made here, a payload of
  // entries the cases name.
  const mdsRoot = await kit.root('Synthetic FIDO MDS', 'rsa');
  const signer = await kit.keyPair('rsa');
  const mdsLeaf = await kit.certificate({
    subject: [['2.5.4.3', 'Synthetic MDS Signer']],
    publicKey: signer.crypto.publicKey, issuer: mdsRoot, ca: false });
  const blobOf = function (entries) {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT',
      x5c: [mdsLeaf.der.toString('base64')] })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ legalHeader: 'synthetic',
      no: 42, nextUpdate: '2099-01-01', entries: entries }))
      .toString('base64url');
    const sig = nodeCrypto.sign('sha256', Buffer.from(header + '.' + payload),
                                signer.privateKey).toString('base64url');
    return header + '.' + payload + '.' + sig;
  };
  const metadataOf = async function (spec) {
    const verdict = await pki.verifyFidoMdsBlob(spec.token,
      { anchorsPem: spec.anchorsPem, now: NOW });
    const rows = {};
    if (verdict.ok) {
      (verdict.payload.entries || []).forEach(function (entry) {
        RiskDatasets.mdsRowsOf(entry).forEach(function (row) {
          rows[row.keyKind + '\u0000' + row.key] = row;
        });
      });
    }
    return {
      lookupAuthenticatorBy: async function (kind, key) {
        const wanted = String(key || '').toLowerCase();
        CALLS.push(['metadata', kind, wanted]);
        if (CASE.metadataThrows) {
          throw new Error('the risk store is unreachable');
        }
        if (kind === 'aaguid' && (!wanted || /^[0-]+$/.test(wanted))) {
          return null;
        }
        if (!verdict.ok || ['aaguid', 'aaid', 'acki'].indexOf(kind) < 0) {
          return null;
        }
        const row = rows[kind + '\u0000' + wanted];
        return row ? { model: Object.assign({}, row),
                       version: String(verdict.payload.no) } : null;
      }
    };
  };
  const androidOf = function () {
    return new Revocation(Object.assign(Revocation.defaultDeps(), {
      now: function () {
        return NOW;
      },
      mode: function () {
        return { refusesUncheckedAttestationRevocation: function () {
          return !!CASE.refusesUnchecked;
        } };
      },
      datasets: function () {
        return { lookupAttestationSerials: async function (serials) {
          CALLS.push(['android', serials]);
          const list = CASE.androidList;
          if (list === 'throws') {
            throw new Error('the risk store is unreachable');
          }
          if (!list) {
            return { checked: false, version: '', hits: [],
                     why: 'no Android attestation status list is loaded' };
          }
          const rows = {};
          (RiskDatasets.androidStatusRowsOf(list.list) || [])
            .forEach(function (row) {
              rows[row.key] = row;
            });
          const hits = [];
          (serials || []).forEach(function (one) {
            const key = RiskDatasets.androidSerialKey(one);
            const row = key ? rows[key] : null;
            if (row) {
              const report = (row.statusReports || [])[0] || {};
              hits.push({ serial: key, status: String(row.latestStatus || ''),
                          reason: String(report.reason || ''),
                          compromised: !!row.compromised });
            }
          });
          return { checked: true, version: list.version, hits: hits,
                   why: '' };
        } };
      }
    }));
  };
  const cases = [];
  const assess = async function (name, c, made, spec) {
    const deps = Attestation.defaultDeps();
    deps.now = function () {
      return NOW;
    };
    deps.policy = Object.assign(Object.create(deps.policy), {
      attestationSettings: function () {
        return settingsOf(spec.settings);
      },
      insecureAlgorithmsAllowed: function () {
        return false;
      }
    });
    const metadata = spec.metadata ? await metadataOf(spec.metadata)
                                   : await metadataOf({ token: 'x.y.z',
                                                        anchorsPem: '' });
    deps.metadata = function () {
      return metadata;
    };
    deps.revocation = function () {
      return { verdictFor: async function (s) {
        CALLS.push(['revocation', s.leaf, s.chain]);
        return CASE.revocation || { refused: false, status: 'good' };
      } };
    };
    const android = androidOf();
    deps.androidRevocation = function () {
      return android;
    };
    const attestation = new Attestation(deps);
    const input = c.input(made);
    CASE = spec;
    CALLS = [];
    const verdict = webauthn.verifyRegistration(input);
    const answer = await attestation.assess(verdict);
    cases.push({ name: name, input: input, now: NOW,
                 settings: settingsOf(spec.settings),
                 metadata: spec.metadata || null,
                 androidList: spec.androidList || null,
                 refusesUnchecked: !!spec.refusesUnchecked,
                 metadataThrows: !!spec.metadataThrows,
                 revocation: spec.revocation || null,
                 answer: { value: JSON.parse(JSON.stringify(answer)),
                           code: errorCodes.codeOf(answer) || '' },
                 calls: JSON.parse(JSON.stringify(CALLS)) });
  };
  const ceremony = function (o) {
    return kit.ceremony(Object.assign({ alg: -7 }, o || {}));
  };
  const vendorPem = anchors.vendor.pem;
  // The policy off, and verify-if-present over every kind of statement.
  let c = await ceremony();
  await assess('policy off', c, kit.none(),
               { settings: { configured: 'off', policy: 'off' } });
  c = await ceremony();
  await assess('none, verify-if-present', c, kit.none(), {});
  c = await ceremony();
  await assess('packed self', c, kit.packedSelf(c), {});
  c = await ceremony();
  await assess('packed basic, no anchor', c,
               await kit.packed(c, anchors.vendor), {});
  c = await ceremony();
  await assess('packed basic, the vendor anchored', c,
               await kit.packed(c, anchors.vendor),
               { settings: { trustAnchorsPem: vendorPem } });
  c = await ceremony();
  await assess('packed basic, another anchor', c,
               await kit.packed(c, anchors.vendor),
               { settings: { trustAnchorsPem: anchors.u2f.pem } });
  c = await ceremony();
  await assess('a refused statement', c,
               await kit.packed(c, anchors.vendor, 'signature'), {});
  // require-trusted.
  for (const row of [['none', function () {
    return kit.none();
  }], ['self', function (cc) {
    return kit.packedSelf(cc);
  }], ['basic', function (cc) {
    return kit.packed(cc, anchors.vendor);
  }]]) {
    c = await ceremony();
    await assess('require-trusted, ' + row[0], c, await row[1](c),
                 { settings: { policy: 'require-trusted' } });
  }
  c = await ceremony();
  await assess('require-trusted, anchored', c,
               await kit.packed(c, anchors.vendor),
               { settings: { policy: 'require-trusted',
                             trustAnchorsPem: vendorPem } });
  // The FIDO Metadata Service.
  const mdsEntry = function (aaguid, root, reports, extra) {
    const id = Buffer.from(aaguid).toString('hex');
    return Object.assign({
      aaguid: id.slice(0, 8) + '-' + id.slice(8, 12) + '-' +
              id.slice(12, 16) + '-' + id.slice(16, 20) + '-' + id.slice(20),
      metadataStatement: { description: 'Synthetic Key ' + id.slice(0, 4),
        protocolFamily: 'fido2', icon: 'data:image/png;base64,AAAA',
        attestationRootCertificates: root ? [root.der.toString('base64')]
                                          : [] },
      statusReports: reports }, extra || {});
  };
  const certified = [{ status: 'FIDO_CERTIFIED_L1',
                       effectiveDate: '2023-01-01' },
                     { status: 'FIDO_CERTIFIED_L2',
                       effectiveDate: '2024-06-01' },
                     { status: 'FIPS140_CERTIFIED_L2',
                       effectiveDate: '2024-07-01' }];
  const listed = await ceremony();
  const listedOther = await ceremony();
  const listedBad = await ceremony();
  const listedRevoked = await ceremony();
  const u2f = await ceremony({ aaguid: Buffer.alloc(16) });
  const u2fMade = await kit.fidoU2f(u2f, anchors.u2f);
  const entries = [
    mdsEntry(listed.aaguid, anchors.vendor, certified),
    mdsEntry(listedOther.aaguid, anchors.vendor,
             [{ status: 'NOT_FIDO_CERTIFIED', effectiveDate: '2024-01-01' }]),
    mdsEntry(listedBad.aaguid, anchors.u2f, certified),
    mdsEntry(listedRevoked.aaguid, anchors.vendor,
             [{ status: 'FIDO_CERTIFIED_L1', effectiveDate: '2022-01-01' },
              { status: 'USER_VERIFICATION_BYPASS',
                effectiveDate: '2023-01-01' },
              { status: 'UPDATE_AVAILABLE', effectiveDate: '2024-01-01' }]),
    { attestationCertificateKeyIdentifiers:
        [pki.attestationKeyIdentifier(u2fMade.attStmt.x5c[0])],
      metadataStatement: { description: 'Synthetic U2F Key',
        attestationRootCertificates: [anchors.u2f.der.toString('base64')] },
      statusReports: [{ status: 'FIDO_CERTIFIED',
                        effectiveDate: '2020-01-01T00:00:00Z' }] }];
  const metadata = { token: blobOf(entries), anchorsPem: mdsRoot.pem };
  await assess('MDS lists the model, its roots', listed,
               await kit.packed(listed, anchors.vendor), { metadata: metadata });
  await assess('MDS lists the model, another root', listedBad,
               await kit.packed(listedBad, anchors.vendor),
               { metadata: metadata });
  await assess('MDS reports the model compromised', listedRevoked,
               await kit.packed(listedRevoked, anchors.vendor),
               { metadata: metadata });
  await assess('MDS by key identifier (fido-u2f)', u2f, u2fMade,
               { metadata: metadata });
  await assess('a BLOB that does not verify', listed,
               await kit.packed(listed, anchors.vendor),
               { metadata: { token: metadata.token,
                             anchorsPem: anchors.u2f.pem } });
  await assess('the metadata service throws', listed,
               await kit.packed(listed, anchors.vendor),
               { metadata: metadata, metadataThrows: true });
  // What demands trust: the AAGUID list, the level, FIPS.
  await assess('an AAGUID list naming it', listed,
               await kit.packed(listed, anchors.vendor),
               { metadata: metadata, settings: { allowedAaguids:
                 [Buffer.from(listed.aaguid).toString('hex')] } });
  await assess('an AAGUID list not naming it', listed,
               await kit.packed(listed, anchors.vendor),
               { metadata: metadata,
                 settings: { allowedAaguids: ['00'.repeat(15) + 'ab'] } });
  for (const level of ['L2', 'L3']) {
    await assess('at least ' + level, listed,
                 await kit.packed(listed, anchors.vendor),
                 { metadata: metadata,
                   settings: { minCertificationLevel: level } });
  }
  await assess('a level, the model not certified', listedOther,
               await kit.packed(listedOther, anchors.vendor),
               { metadata: metadata,
                 settings: { minCertificationLevel: 'L1' } });
  c = await ceremony();
  await assess('a level, the model not listed', c,
               await kit.packed(c, anchors.vendor),
               { metadata: metadata,
                 settings: { minCertificationLevel: 'L1',
                             trustAnchorsPem: vendorPem } });
  await assess('FIPS held', listed, await kit.packed(listed, anchors.vendor),
               { metadata: metadata, settings: { requireFips: true } });
  await assess('FIPS not held', listedOther,
               await kit.packed(listedOther, anchors.vendor),
               { metadata: metadata, settings: { requireFips: true } });
  await assess('the U2F key certified at L1', u2f, u2fMade,
               { metadata: metadata,
                 settings: { minCertificationLevel: 'L1' } });
  // Revocation.
  c = await ceremony();
  await assess('a revoked certificate', c,
               await kit.packed(c, anchors.vendor),
               { settings: { trustAnchorsPem: vendorPem },
                 revocation: { refused: true, status: 'revoked',
                               why: 'serial 01 is on the CRL' } });
  c = await ceremony();
  await assess('revocation unknown, no distribution point', c,
               await kit.packed(c, anchors.vendor),
               { settings: { trustAnchorsPem: vendorPem },
                 revocation: { refused: true, status: 'unknown',
                               why: 'no distribution point',
                               unknown: [{ kind: 'no-distribution-point',
                                           refusable: true }] } });
  c = await ceremony();
  await assess('revocation unknown, a list that failed', c,
               await kit.packed(c, anchors.vendor),
               { settings: { trustAnchorsPem: vendorPem },
                 revocation: { refused: true, status: 'unknown',
                               why: 'the CRL could not be fetched',
                               unknown: [{ kind: 'unreachable',
                                           refusable: true }] } });
  // android-key and Google's status list.
  const androidCase = async function (name, spec, settings) {
    const cc = await ceremony();
    const made = await kit.androidKey(cc, anchors.android);
    const serial = pki.certificateSerialHex(made.leaf.der);
    const list = typeof spec.list === 'function' ? spec.list(serial)
                                                 : spec.list;
    await assess(name, cc, made, Object.assign({ androidList: list,
      settings: Object.assign({ trustAnchorsPem: anchors.android.pem },
                              settings || {}) }, spec.extra || {}));
  };
  const listOf = function (entries) {
    return { version: '2026-11-14', list: { entries: entries } };
  };
  await androidCase('android-key, the list says nothing', {
    list: listOf({ 'ff00': { status: 'REVOKED', reason: 'KEY_COMPROMISE' } })
  });
  await androidCase('android-key, the leaf revoked', {
    list: function (serial) {
      const e = {};
      e['0x' + serial.toUpperCase()] = { status: 'REVOKED',
                                          reason: 'KEY_COMPROMISE' };
      return listOf(e);
    } });
  await androidCase('android-key, the leaf suspended', {
    list: function (serial) {
      const e = {};
      e[serial] = { status: 'SUSPENDED', comment: 'held' };
      return listOf(e);
    } });
  await androidCase('android-key, no list', { list: null });
  await androidCase('android-key, no list, unchecked refused', {
    list: null, extra: { refusesUnchecked: true } });
  await androidCase('android-key, the list throws', { list: 'throws' });
  await androidCase('android-key, revoked, require-trusted', {
    list: function (serial) {
      const e = {};
      e[serial] = { status: 'REVOKED' };
      return listOf(e);
    } }, { policy: 'require-trusted' });
  // SafetyNet, Apple, TPM, compound.
  c = await ceremony();
  await assess('android-safetynet, not allowed', c,
               await kit.safetynet(c, anchors.google),
               { settings: { trustAnchorsPem: anchors.google.pem } });
  c = await ceremony();
  await assess('android-safetynet, allowed', c,
               await kit.safetynet(c, anchors.google),
               { settings: { trustAnchorsPem: anchors.google.pem,
                             allowSafetynet: true } });
  c = await ceremony();
  await assess('apple, anchored', c, await kit.apple(c, anchors.apple),
               { settings: { trustAnchorsPem: anchors.apple.pem } });
  c = await ceremony();
  await assess('tpm, anchored', c, await kit.tpm(c, anchors.tpm),
               { settings: { trustAnchorsPem: anchors.tpm.pem } });
  c = await ceremony();
  await assess('compound, the apple member anchored', c,
               { fmt: 'compound', attStmt: [
                 { fmt: 'packed',
                   attStmt: (await kit.packed(c, anchors.vendor)).attStmt },
                 { fmt: 'apple',
                   attStmt: (await kit.apple(c, anchors.apple)).attStmt }] },
               { settings: { trustAnchorsPem: anchors.apple.pem } });
  c = await ceremony();
  await assess('compound, nothing anchored, require-trusted', c,
               { fmt: 'compound', attStmt: [
                 { fmt: 'none', attStmt: {} },
                 { fmt: 'packed', attStmt: kit.packedSelf(c).attStmt }] },
               { settings: { policy: 'require-trusted' } });
  // Enterprise attestation (#1114) and the device serial (#532).
  for (const row of [['subject', { subject: 'SN-0042' }],
                     ['yubico', { yubico: 12345678 }]]) {
    c = await ceremony();
    const rpHash = 'localhost';
    await assess('enterprise, a ' + row[0] + ' serial', c,
                 await kit.packed(c, anchors.vendor, undefined, undefined,
                                  row[1]),
                 { settings: { trustAnchorsPem: vendorPem,
                               conveyance: 'enterprise',
                               enterpriseRpIds: [rpHash],
                               enterpriseSerialAttribute: 'serialNumber' } });
  }
  c = await ceremony();
  await assess('enterprise, the RP ID not listed', c,
               await kit.packed(c, anchors.vendor, undefined, undefined,
                                { subject: 'SN-0042' }),
               { settings: { trustAnchorsPem: vendorPem,
                             conveyance: 'enterprise',
                             enterpriseRpIds: ['example.org'] } });
  c = await ceremony();
  await assess('attestation algorithms demanded', c,
               await kit.packed(c, anchors.vendor),
               { settings: { trustAnchorsPem: vendorPem,
                             attestationAlgorithms: ['ML-DSA-65'] } });
  return { cases: cases, blob: { token: metadata.token,
                                 anchorsPem: metadata.anchorsPem } };
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
