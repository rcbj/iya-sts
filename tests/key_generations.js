'use strict';
//
// File: key_generations.js
//
// ===========================================================================
// SIGNING KEY GENERATIONS AND THE PUBLIC CRYPTO METADATA DOCUMENT (#42, P2,
// 2026-09-22).
//
// Every unit of a realm — (use case, algorithm) — holds a CURRENT key and may
// hold a NEXT one, published before it signs anything, and RETIRED ones that
// go on verifying through their grace (`common/helpers.js`, KEY
// GENERATIONS). The rotation JOBS are P3; what P2 promises, and what this
// file holds it to, is that the generations are real everywhere a key is
// published or checked:
//
//   A. THE SPLIT. XML signing has a key of its own (`STS.xml`), so a SAML
//      assertion verifies against the XML key and NOT the JOSE one, and the
//      one lookup (`verifyOwnXml()`) finds it.
//   B. NEXT. `ensureNextGenerations()` mints a next key for a unit, once, and
//      it is published — the JWKS, the SAML 2.0 metadata (a second signing
//      KeyDescriptor), and `/crypto/metadata` in JSON and XML — before it
//      signs anything; the generation counter moves.
//   C. THE DOCUMENT. `/crypto/metadata` negotiates on Accept, every form is
//      `no-store` and anonymous, the signed JSON verifies as this realm's own
//      JWS and the signed XML as this realm's own XML Signature, the XSD is
//      served, and OIDC discovery and the SAML metadata both link to it. No
//      private key is in any of it.
//   D. PROMOTE. The next key becomes current, the old current is RETIRED with
//      a `retiredUntil`, a fresh next is minted — and a token and an assertion
//      signed BEFORE the promotion still verify, which is the whole point.
//   E. RETIRE. Past its grace a retired key is dropped: it leaves the JWKS
//      and the document, and what it signed stops verifying.
//
// In a child process on an ephemeral loopback port, with the whole stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'key_generations',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.KG_ROOT;
  const OUT = process.env.KG_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const get = function (port, urlPath, headers) {
    return new Promise(function (resolve) {
      http.get({ host: '127.0.0.1', port: port, path: urlPath,
                 headers: headers || {} }, function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers,
                    text: text, json: json });
        });
      });
    });
  };
  const kids = function (jwks) {
    return ((jwks && jwks.keys) || []).map(function (k) { return k.kid; });
  };
  const unitOf = function (doc, name) {
    return ((doc && doc.units) || []).filter(function (u) {
      return u.unit === name;
    })[0] || { keys: [] };
  };
  const stateOf = function (doc, name, kid) {
    const k = unitOf(doc, name).keys.filter(function (one) {
      return one.kid === kid;
    })[0];
    return k ? k.state : '';
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const helpers = require(ROOT + '/common/helpers');
    const realms = require(ROOT + '/common/realms');
    const stsCrypto = require(ROOT + '/common/crypto');
    const saml2 = require(ROOT + '/saml/saml2');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const REALM = realms.DEFAULT_ID;
    const STS = helpers.STS;
    const keysNow = function () {
      return helpers.stsKeysFor.of(REALM);
    };
    const generationNow = function () {
      const g = keysNow().generations;
      return Number(g && g.generation) || 0;
    };

    // --- A. the split -------------------------------------------------------
    const joseKid = STS.kid;
    const xmlKid = STS.xml.kid;
    note(joseKid && xmlKid && joseKid !== xmlKid,
         'A1. XML signing has a key of its own, with a kid of its own',
         joseKid + ' / ' + xmlKid);
    const assertion = saml2.buildSamlAssertion('kg-alice', 'https://sp.test', 5);
    note(stsCrypto.verifyXmlSignature(assertion, { element: 'Assertion',
           certPem: STS.xml.certPem }).ok &&
         !stsCrypto.verifyXmlSignature(assertion, { element: 'Assertion',
           certPem: STS.certPem }).ok,
         'A2. a SAML assertion verifies against the XML key and not against ' +
         'the JOSE key');
    note(helpers.verifyOwnXml(assertion, { element: 'Assertion' }).ok,
         'A3. and the one lookup, verifyOwnXml(), finds it');
    const token = stsCrypto.signJws({ sub: 'kg-alice', aud: 'kg' },
      STS.privateKey, { algorithm: 'RS256', issuer: 'https://kg.test',
                        expiresIn: 3600, keyid: joseKid });
    let tokenOk = false;
    try {
      tokenOk = !!helpers.verifyOwnJws(token);
    } catch (e) {
      tokenOk = false;
    }
    note(tokenOk, 'A4. a JWS signed with the current JOSE key verifies ' +
                  'through verifyOwnJws()');

    // --- B. next --------------------------------------------------------------
    const g0 = generationNow();
    const minted = await helpers.ensureNextGenerations(REALM,
      { units: ['jose:RS256', 'xml:RS256'] });
    note(minted.ok && minted.minted.length === 2 &&
         minted.minted.indexOf('jose:RS256') >= 0 &&
         minted.minted.indexOf('xml:RS256') >= 0,
         'B1. ensureNextGenerations() mints a next key for each unit asked',
         JSON.stringify(minted));
    note(generationNow() > g0, 'B2. and the generation counter moves',
         g0 + ' -> ' + generationNow());
    const again = await helpers.ensureNextGenerations(REALM,
      { units: ['jose:RS256', 'xml:RS256'] });
    note(again.minted.length === 0,
         'B3. a second call mints nothing: a unit with a next is left alone',
         JSON.stringify(again));
    const nextJose = helpers.standbyOf(keysNow(), 'jose:RS256')
      .filter(function (one) { return one.role === 'next'; })[0];
    const nextXml = helpers.standbyOf(keysNow(), 'xml:RS256')
      .filter(function (one) { return one.role === 'next'; })[0];
    note(nextJose && nextXml && nextJose.kid !== joseKid &&
         nextXml.kid !== xmlKid,
         'B4. each next key is a different key from the current one');
    note(STS.kid === joseKid && STS.xml.kid === xmlKid,
         'B5. and the current keys are unchanged: a next key signs nothing');
    const jwks1 = await get(port, '/oauth2/jwks');
    note(kids(jwks1.json).indexOf(joseKid) >= 0 &&
         kids(jwks1.json).indexOf(nextJose && nextJose.kid) >= 0,
         'B6. the JWKS publishes the current AND the next JOSE key',
         JSON.stringify(kids(jwks1.json)));
    const curve = helpers.signingUnitsOf(keysNow()).filter(function (u) {
      return u.kind === 'curve';
    })[0];
    const curveMinted = curve ? await helpers.ensureNextGenerations(REALM,
      { units: [curve.unit] }) : { minted: [] };
    const nextCurve = curve ? helpers.standbyOf(keysNow(), curve.unit)
      .filter(function (one) { return one.role === 'next'; })[0] : null;
    const jwksCurve = await get(port, '/oauth2/jwks');
    note(curve && curveMinted.minted.length === 1 && nextCurve &&
         kids(jwksCurve.json).indexOf(nextCurve.kid) >= 0 &&
         kids(jwksCurve.json).indexOf(curve.kid) >= 0,
         'B6a. a curve unit\'s next key is published beside its current one ' +
         'too', JSON.stringify({ unit: curve && curve.unit,
                                 next: nextCurve && nextCurve.kid }));
    const md1 = await get(port, '/saml2/metadata');
    const signingDescriptors = (md1.text.match(
      /<md:KeyDescriptor use="signing">/g) || []).length;
    note(signingDescriptors >= 2 &&
         md1.text.indexOf(nextXml && nextXml.certB64) >= 0,
         'B7. the SAML 2.0 metadata carries a signing KeyDescriptor for the ' +
         'next XML key', signingDescriptors + ' signing descriptor(s)');

    // --- C. the document -----------------------------------------------------
    const doc = await get(port, '/crypto/metadata.json');
    note(doc.status === 200 && /no-store/.test(doc.headers['cache-control']) &&
         doc.json && doc.json.specVersion === 1,
         'C1. /crypto/metadata.json answers a stranger, no-store',
         doc.status + ' ' + doc.headers['cache-control']);
    note(stateOf(doc.json, 'jose:RS256', joseKid) === 'current' &&
         stateOf(doc.json, 'jose:RS256', nextJose && nextJose.kid) === 'next' &&
         stateOf(doc.json, 'xml:RS256', xmlKid) === 'current' &&
         stateOf(doc.json, 'xml:RS256', nextXml && nextXml.kid) === 'next',
         'C2. it lists each unit\'s current and next key by kid and state',
         JSON.stringify(((doc.json && doc.json.units) || []).map(function (u) {
           return u.unit + ':' + u.keys.map(function (k) {
             return k.state;
           }).join('/');
         })));
    const cert = unitOf(doc.json, 'jose:RS256').keys[0].certificate || {};
    note(cert.x5c && cert.x5c.length >= 1 &&
         /^[0-9a-f]{64}$/.test(cert.sha256Fingerprint || '') &&
         cert.notBefore && cert.notAfter,
         'C3. with a certificate chain, fingerprint and validity per key',
         JSON.stringify(Object.keys(cert)));
    note(!/PRIVATE KEY|"d":|"p":|"q":/.test(doc.text),
         'C4. and no private half of anything');
    const negotiated = await get(port, '/crypto/metadata',
                                 { accept: 'application/xml' });
    const xml = await get(port, '/crypto/metadata.xml');
    note(/^application\/xml/.test(negotiated.headers['content-type']) &&
         /<cm:CryptoMetadata\b/.test(negotiated.text) &&
         /<cm:CryptoMetadata\b/.test(xml.text) &&
         xml.text.indexOf('kid="' + (nextXml && nextXml.kid) + '"') >= 0,
         'C5. Accept: application/xml gets the XML, and the XML lists the ' +
         'same keys', negotiated.headers['content-type']);
    const plain = await get(port, '/crypto/metadata');
    note(/^application\/json/.test(plain.headers['content-type']),
         'C6. with no Accept it is JSON', plain.headers['content-type']);
    const jwt = await get(port, '/crypto/metadata.jwt');
    let signedClaims = null;
    try {
      signedClaims = helpers.verifyOwnJws(jwt.text);
    } catch (e) {
      signedClaims = null;
    }
    note(jwt.status === 200 && signedClaims && signedClaims.units &&
         /no-store/.test(jwt.headers['cache-control']),
         'C7. the signed JSON is a JWS this realm verifies as its own',
         jwt.status + ' ' + jwt.text.slice(0, 80));
    const signedXml = await get(port, '/crypto/metadata.signed.xml');
    note(helpers.verifyOwnXml(signedXml.text,
                              { element: 'CryptoMetadata' }).ok,
         'C8. the signed XML carries an XML Signature this realm verifies ' +
         'with its XML key', signedXml.text.slice(0, 200));
    const xsd = await get(port, '/crypto/metadata.xsd');
    note(xsd.status === 200 &&
         /targetNamespace="urn:iya:sts:crypto-metadata:1"/.test(xsd.text),
         'C9. the schema is served');
    const discovery = await get(port, '/.well-known/openid-configuration');
    note(discovery.json && /\/crypto\/metadata\.json$/.test(
           discovery.json.crypto_metadata_uri || ''),
         'C10. OIDC discovery links to it (crypto_metadata_uri)',
         discovery.json && discovery.json.crypto_metadata_uri);
    note(/<md:Extensions><cm:CryptoMetadataLocation [^>]*>[^<]*\/crypto\/metadata\.xml</
           .test(md1.text),
         'C11. and the SAML 2.0 metadata does, in md:Extensions');

    // --- D. promote -----------------------------------------------------------
    const g1 = generationNow();
    const promoted = await helpers.promoteGenerations(REALM,
      { units: ['jose:RS256', 'xml:RS256'], graceMs: 3600000 });
    note(promoted.ok && promoted.rotated.length === 2,
         'D1. promoteGenerations() rotates both units', JSON.stringify(
           promoted.rotated));
    note(STS.kid === (nextJose && nextJose.kid) &&
         STS.xml.kid === (nextXml && nextXml.kid),
         'D2. the next keys are the current ones now', STS.kid + ' / ' +
         STS.xml.kid);
    note(generationNow() > g1, 'D3. the generation counter moves again');
    const retiredJose = helpers.standbyOf(keysNow(), 'jose:RS256')
      .filter(function (one) { return one.kid === joseKid; })[0];
    note(retiredJose && retiredJose.role === 'retired' &&
         Number(retiredJose.retiredUntil) > Date.now(),
         'D4. the old JOSE key is RETIRED with a retiredUntil in the future',
         JSON.stringify(retiredJose && { role: retiredJose.role,
                                         until: retiredJose.retiredUntil }));
    note(helpers.standbyOf(keysNow(), 'jose:RS256').some(function (one) {
      return one.role === 'next';
    }) && helpers.standbyOf(keysNow(), 'xml:RS256').some(function (one) {
      return one.role === 'next';
    }), 'D5. and a fresh next key is minted for each: one rotation ahead ' +
        'again');
    let oldTokenOk = false;
    try {
      oldTokenOk = !!helpers.verifyOwnJws(token);
    } catch (e) {
      oldTokenOk = false;
    }
    note(oldTokenOk, 'D6. a token signed BEFORE the promotion still verifies');
    note(helpers.verifyOwnXml(assertion, { element: 'Assertion' }).ok,
         'D7. and so does an assertion signed before it');
    const fresh = saml2.buildSamlAssertion('kg-bob', 'https://sp.test', 5);
    note(stsCrypto.verifyXmlSignature(fresh, { element: 'Assertion',
           certPem: STS.xml.certPem }).ok,
         'D8. a new assertion is signed with the promoted key');
    const jwks2 = await get(port, '/oauth2/jwks');
    note(kids(jwks2.json).indexOf(joseKid) >= 0 &&
         kids(jwks2.json).indexOf(STS.kid) >= 0,
         'D9. the JWKS publishes the retired key beside the current one',
         JSON.stringify(kids(jwks2.json)));
    const doc2 = await get(port, '/crypto/metadata.json');
    note(stateOf(doc2.json, 'jose:RS256', joseKid) === 'retired' &&
         stateOf(doc2.json, 'jose:RS256', STS.kid) === 'current',
         'D10. and the document says which is which');

    // --- E. retire --------------------------------------------------------------
    const dropped = helpers.retireExpiredGenerations(REALM,
                                                     Date.now() + 7200000);
    note(dropped.ok && dropped.dropped.some(function (one) {
      return one.kid === joseKid;
    }) && dropped.dropped.some(function (one) {
      return one.kid === xmlKid;
    }), 'E1. past its grace each retired key is dropped',
         JSON.stringify(dropped.dropped));
    let droppedTokenOk = false;
    try {
      droppedTokenOk = !!helpers.verifyOwnJws(token);
    } catch (e) {
      droppedTokenOk = false;
    }
    note(!droppedTokenOk,
         'E2. and what it signed stops verifying');
    note(!helpers.verifyOwnXml(assertion, { element: 'Assertion' }).ok,
         'E3. the old assertion too');
    const jwks3 = await get(port, '/oauth2/jwks');
    const doc3 = await get(port, '/crypto/metadata.json');
    note(kids(jwks3.json).indexOf(joseKid) < 0 &&
         stateOf(doc3.json, 'jose:RS256', joseKid) === '',
         'E4. it leaves the JWKS and the document',
         JSON.stringify(kids(jwks3.json)));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'key-generations-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', KG_ROOT: ROOT, KG_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'key_generations',
  describe: 'signing key generations (#42 P2): the XML key split, a next ' +
            'key published before it signs, promotion with the retired key ' +
            'still verifying, retirement, and the public crypto metadata ' +
            'document in every form',
  run: run
};
