'use strict';
//
// File: mode_weak_settings.js
//
// ===========================================================================
// SIX MORE SETTINGS OF #104'S CLASS, AND THE PAGE THAT SAYS SO (#181).
//
// Product mode honoured six settings that are non-conforming or weak, and
// #181 made each development's through #104's machinery (the `onlyWhile` /
// `onlyWhileValues` markers, `mode.valueInForce()`, STS-CORE-0103 on write
// and STS-CORE-0106 on read):
//
//   * `risc.googleSubjectType` on         — `spoilsOnPurpose()`;
//   * `krb5.clockOffset` not 0             — `spoilsOnPurpose()`;
//   * `saml2.signAssertion`, `saml11.signAssertion`, `saml11.signResponse`
//     off                                  — `issuesUnsignedAssertions()`;
//   * `spiffe.requireSecurityHeader` off   — `servesWithoutSecurityHeader()`;
//   * `saml.signatureAlgorithm` rsa-sha1, `saml2.keyTransportAlgorithm`
//     rsa-1_5, and their siblings `saml.allowSha1Signatures` on and
//     `pki.signatureAlgorithm` sha1-rsa / sha1-ecdsa
//                                          — `usesBrokenAlgorithms()`.
//
// This file holds them to the rule, in a CHILD PROCESS that loads the whole
// protocol stack (so the directory, the SAML identity providers, the KDC and
// the SPIFFE server are nobody else's):
//
//   A. THE WRITE, per setting: refused in product by `setOverride()` and
//      `checkWrite()` (STS-CORE-0103) while `checkOverride()` is not; a
//      stronger value of the same setting accepted; every value accepted in
//      development. An application's override — `saml2SignAssertion`,
//      `saml11SignResponse`, `saml2KeyTransportAlgorithm` — refused in
//      product by `updateApplication()` and `createApplication()`
//      (STS-REG-0193).
//   B. THE READ, at every read site, in development with every weak value
//      stored (each honoured), in product with them STILL stored (each
//      ignored, twice over), and in development again: the RISC subject, the
//      XML SignatureMethod, the SHA-1 verdict, the SAML 2.0 assertion
//      signature service-wide and per application, the key transport
//      service-wide and per application, the SAML 1.1 Response signature, the
//      Workload API's header, the KDC's clock (`GET /krb5/principals`), the
//      CA's signature algorithm — and an rsa-1_5 EncryptedKey unwrapped in
//      development and refused, STS-KEYS-0070, in product. Each ignored
//      setting, and each overriding attribute, logged ONCE (STS-CORE-0106).
//   C. THE REPORT AND ITS TWO ROUTES: `mode.report()` carries the three new
//      requirements and every marked row with its stored and in-force value;
//      `GET /admin-api/mode` answers it; `GET /admin/mode` is registered.
//
// The same over HTTP, against a running service in two throwaway realms, is
// `tests/vendored/sts_mode_weak_settings.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'mode_weak_settings',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Each marked value and, where the setting has one, a stronger value that
// product still accepts.
const MARKED = [
  { key: 'risc.googleSubjectType', weak: true },
  { key: 'krb5.clockOffset', weak: 120 },
  { key: 'saml2.signAssertion', weak: false },
  { key: 'saml11.signAssertion', weak: false },
  { key: 'saml11.signResponse', weak: false },
  { key: 'spiffe.requireSecurityHeader', weak: false },
  { key: 'saml.allowSha1Signatures', weak: true },
  { key: 'saml.signatureAlgorithm', weak: 'rsa-sha1', strong: 'rsa-sha512' },
  { key: 'saml2.keyTransportAlgorithm', weak: 'rsa-1_5' },
  { key: 'pki.signatureAlgorithm', weak: 'sha1-rsa', strong: 'sha384-rsa' },
  { key: 'pki.signatureAlgorithm', weak: 'sha1-ecdsa' }
];

// THE CHILD'S PROGRAM. It runs in the child only, which the code style exempts
// from the Entering/Leaving lines.
function childMain() {
  const ROOT = process.env.MW_ROOT;
  const OUT = process.env.MW_OUT;
  const MARKED = JSON.parse(process.env.MW_MARKED);
  const fs = require('fs');
  const http = require('http');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  const SP = 'urn:mode-weak:sp-181';
  const RP = 'urn:mode-weak:rp-181';

  (async function () {
    try {
      require(ROOT + '/common/protocol_stack');
      const app = require(ROOT + '/common/app');
      const config = require(ROOT + '/common/config');
      const mode = require(ROOT + '/common/mode');
      const errorCodes = require(ROOT + '/common/error_codes');
      const applications = require(ROOT + '/common/applications');
      const stsCrypto = require(ROOT + '/common/crypto');
      const pki = require(ROOT + '/common/pki');
      const risc = require(ROOT + '/ssf/risc');
      const documentSettings = require(ROOT + '/saml/document_settings');
      const saml2sso = require(ROOT + '/saml/saml2_sso');
      const saml11sso = require(ROOT + '/saml/saml11_sso');
      const spiffeGrpc = require(ROOT + '/spiffe/spiffe_grpc');
      const modeAdmin = require(ROOT + '/admin-ui/mode_admin');
      const forge = require('node-forge');

      const server = http.createServer(app);
      await new Promise(function (r) {
        server.listen(0, '127.0.0.1', r);
      });
      const base = 'http://127.0.0.1:' + server.address().port;
      const getJson = async function (p) {
        const r = await fetch(base + p);
        const text = await r.text();
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          json = null;
        }
        return { status: r.status, json: json, text: text };
      };
      const set = function (key, value) {
        const result = config.setOverride(key, value);
        if (!result.ok) {
          throw new Error('setting ' + key + '=' + value + ' was refused: ' +
                          (result.errors || []).join(' '));
        }
      };
      config.setOverride('adminApi.authRequired', false);

      // A key pair and a self-signed certificate, made here, for the rsa-1_5
      // unwrap. Nothing is written anywhere.
      const keys = forge.pki.rsa.generateKeyPair(2048);
      const cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = '0181';
      cert.validity.notBefore = new Date(Date.now() - 60000);
      cert.validity.notAfter = new Date(Date.now() + 3600000);
      cert.setSubject([{ name: 'commonName', value: 'mode-weak-181' }]);
      cert.setIssuer([{ name: 'commonName', value: 'mode-weak-181' }]);
      cert.sign(keys.privateKey, forge.md.sha256.create());
      const certPem = forge.pki.certificateToPem(cert);
      const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
      const sealed15 = stsCrypto.encryptElement(
        '<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
        'mode-weak</saml:NameID>', certPem,
        { keyTransport: 'rsa-1_5', wrapper: 'saml:EncryptedID' });

      // The two applications whose overrides are exercised.
      const madeSp = applications.createApplication({ identifier: SP,
        protocols: ['saml2'], fields: { samlEntityId: SP } });
      const madeRp = applications.createApplication({ identifier: RP,
        protocols: ['saml11'], fields: { samlEntityId: RP } });
      note(madeSp.ok && madeRp.ok, 'set-up: a SAML 2.0 and a SAML 1.1 ' +
           'application', JSON.stringify([madeSp.errors, madeRp.errors]));
      const direct2 = new saml2sso.Saml2Sso(saml2sso.Saml2Sso.defaultDeps());
      const direct11 = new saml11sso.Saml11Sso(
        saml11sso.Saml11Sso.defaultDeps());
      const grpc = new spiffeGrpc.SpiffeGrpc(
        spiffeGrpc.SpiffeGrpc.defaultDeps());

      const observe = async function () {
        const subject = risc.googleSubjectType({ format: 'email',
                                                 email: 'a@mode.test' });
        const verdict = stsCrypto.xmlAlgorithmVerdict(RSA_SHA1, []);
        const opened = stsCrypto.decryptElement(sealed15, keyPem);
        const configured = pki.algorithmsFrom({ keyAlg: 'rsa-2048' });
        const named = pki.algorithmsFrom({ keyAlg: 'rsa-2048',
                                           signatureAlg: 'sha1-rsa' });
        const principals = await getJson('/krb5/principals');
        const spiffe = await getJson('/spiffe?format=json');
        return {
          risc: Object.prototype.hasOwnProperty.call(subject,
                                                      'subject_type')
            ? 'subject_type' : 'format',
          sigName: documentSettings.signatureOptions().sigName,
          sha1: verdict.code || 'accepted',
          unwrap15: opened.ok ? 'opened' : errorCodes.codeOf(opened),
          signs2: direct2.signsAssertionFor(''),
          signs2Sp: direct2.signsAssertionFor(SP),
          transport: direct2.encryptionAlgorithmsFor('').keyTransport,
          transportSp: direct2.encryptionAlgorithmsFor(SP).keyTransport,
          signs11Assertion: !!applications.settingFor(
            RP, 'saml11.signAssertion', config),
          signs11Response: !!direct11.buildResponse(
            { rp: RP, assertion: '' }).signed,
          header: grpc.requireSecurityHeader(),
          headerView: !!(spiffe.json && spiffe.json.workloadApi &&
                         spiffe.json.workloadApi.securityHeaderRequired),
          clockOffset: principals.json ?
            principals.json.clockOffsetSeconds : 'status ' +
            principals.status,
          caConfigured: configured.ok ? configured.signatureAlg : 'refused',
          caNamed: named.ok ? named.signatureAlg : errorCodes.codeOf(named)
        };
      };

      // ---- A. the write ----------------------------------------------------
      set('global.mode', 'product');
      MARKED.forEach(function (row) {
        const refused = config.setOverride(row.key, row.weak);
        note(!refused.ok &&
             errorCodes.codeOf(refused) === 'STS-CORE-0103' &&
             (refused.errors || []).join(' ').indexOf(row.key) >= 0 &&
             /product mode/.test((refused.errors || []).join(' ')),
             'A. product: writing ' + row.key + '=' + row.weak +
             ' is refused, STS-CORE-0103, naming it', JSON.stringify(refused));
        note(config.checkWriteCode(row.key, String(row.weak)) ===
               'STS-CORE-0103' &&
             config.checkOverride(row.key, String(row.weak)) === null,
             'A. product: checkWrite() refuses ' + row.key + '=' + row.weak +
             ' and checkOverride(), the restore door, does not');
        if (row.strong) {
          const strong = config.setOverride(row.key, row.strong);
          note(strong.ok, 'A. product: ' + row.key + '=' + row.strong +
               ', a stronger value, is accepted', JSON.stringify(strong));
          config.clearOverride(row.key);
        }
      });
      const saml2Off = applications.updateApplication(SP,
        { attribute: 'saml2SignAssertion', mode: 'set', value: 'FALSE' });
      const rsa15 = applications.updateApplication(SP,
        { attribute: 'saml2KeyTransportAlgorithm', mode: 'set',
          value: 'rsa-1_5' });
      const saml11Off = applications.updateApplication(RP,
        { attribute: 'saml11SignResponse', mode: 'set', value: 'FALSE' });
      note([saml2Off, rsa15, saml11Off].every(function (r) {
        return !r.ok && errorCodes.codeOf(r) === 'STS-REG-0193' &&
               /product mode/.test((r.errors || []).join(' '));
      }), 'A. product: an application\'s saml2SignAssertion=FALSE, ' +
          'saml2KeyTransportAlgorithm=rsa-1_5 and saml11SignResponse=FALSE ' +
          'are refused, STS-REG-0193',
           JSON.stringify([saml2Off, rsa15, saml11Off].map(function (r) {
             return [r.ok, errorCodes.codeOf(r)];
           })));
      const oaep = applications.updateApplication(SP,
        { attribute: 'saml2KeyTransportAlgorithm', mode: 'set',
          value: 'rsa-oaep-mgf1p' });
      const cleared = applications.updateApplication(SP,
        { attribute: 'saml2KeyTransportAlgorithm', mode: 'set', value: '' });
      note(oaep.ok && cleared.ok, 'A. product: rsa-oaep-mgf1p and a clear ' +
           'are accepted', JSON.stringify([oaep.errors, cleared.errors]));
      const createdWeak = applications.createApplication({
        identifier: 'urn:mode-weak:sp-refused', protocols: ['saml2'],
        fields: { samlEntityId: 'urn:mode-weak:sp-refused',
                  saml2SignAssertion: 'FALSE' } });
      note(!createdWeak.ok &&
           errorCodes.codeOf(createdWeak) === 'STS-REG-0193' &&
           !applications.get('urn:mode-weak:sp-refused'),
           'A. product: a create carrying saml2SignAssertion=FALSE is ' +
           'refused, STS-REG-0193, and nothing is created',
           JSON.stringify(createdWeak));
      set('global.mode', 'development');
      MARKED.forEach(function (row) {
        const r = config.setOverride(row.key, row.weak);
        note(r.ok && config.checkWrite(row.key, String(row.weak)) === null,
             'A. development: writing ' + row.key + '=' + row.weak +
             ' is accepted', JSON.stringify(r));
        config.clearOverride(row.key);
      });

      // ---- B. the read -----------------------------------------------------
      const out = {};
      out.devOff = await observe();
      MARKED.forEach(function (row) {
        // pki.signatureAlgorithm is marked twice; the first value is the one
        // left stored.
        if (row.key !== 'pki.signatureAlgorithm' || row.weak === 'sha1-rsa') {
          set(row.key, row.weak);
        }
      });
      const overrides = [
        applications.updateApplication(SP, { attribute: 'saml2SignAssertion',
          mode: 'set', value: 'FALSE' }),
        applications.updateApplication(SP,
          { attribute: 'saml2KeyTransportAlgorithm', mode: 'set',
            value: 'rsa-1_5' }),
        applications.updateApplication(RP, { attribute: 'saml11SignResponse',
          mode: 'set', value: 'FALSE' }),
        applications.updateApplication(RP,
          { attribute: 'saml11SignAssertion', mode: 'set', value: 'FALSE' })
      ];
      note(overrides.every(function (r) {
        return r.ok;
      }), 'B. development: the four overriding attributes are written',
           JSON.stringify(overrides.map(function (r) {
             return r.errors;
           })));
      // Every service-wide switch back ON, so that what the per-application
      // rows answer is theirs alone.
      set('saml2.signAssertion', true);
      set('saml2.keyTransportAlgorithm', 'rsa-oaep-mgf1p');
      set('saml11.signAssertion', true);
      set('saml11.signResponse', true);
      out.devApps = await observe();
      set('saml2.signAssertion', false);
      set('saml2.keyTransportAlgorithm', 'rsa-1_5');
      set('saml11.signAssertion', false);
      set('saml11.signResponse', false);
      out.devOn = await observe();
      set('global.mode', 'product');
      out.productOn = await observe();
      out.productAgain = await observe();
      const report = mode.report();
      out.ignored = report.developmentOnlySettings.filter(function (row) {
        return row.ignored;
      }).map(function (row) {
        return row.key;
      });
      out.ids = report.requirements.map(function (row) {
        return row.id;
      });
      out.view = modeAdmin.modeView();
      out.routes = [];
      (app._router ? app._router.stack : app.router.stack)
        .forEach(function (layer) {
          if (layer.route && (layer.route.path === '/admin/mode' ||
                              layer.route.path === '/admin-api/mode')) {
            out.routes.push(layer.route.path);
          }
        });
      set('global.mode', 'development');
      out.devAgain = await observe();
      // In DEVELOPMENT, where `adminApi.authRequired` off opens the API: in
      // product the same setting means the console's own sign-in.
      out.api = await getJson('/admin-api/mode');
      out.page = await getJson('/admin/mode?format=json');

      // ---- the verdicts ------------------------------------------------
      const d0 = out.devOff;
      note(d0.risc === 'format' && d0.sigName === 'rsa-sha256' &&
           d0.sha1 === 'STS-KEYS-0062' && d0.unwrap15 === 'opened' &&
           d0.signs2 === true && d0.transport === 'rsa-oaep-mgf1p' &&
           d0.signs11Response === true && d0.header === true &&
           d0.headerView === true && d0.clockOffset === 0 &&
           d0.caNamed === 'sha1-rsa',
           'B. development, nothing set: format, rsa-sha256, SHA-1 refused ' +
           'by default, an rsa-1_5 key UNWRAPPED (development allows it), ' +
           'assertions and Responses signed, the header required, the ' +
           'KDC on the machine\'s clock, and a CA may be asked for SHA-1',
           JSON.stringify(d0));
      const da = out.devApps;
      note(da.signs2 === true && da.signs2Sp === false &&
           da.transport === 'rsa-oaep-mgf1p' && da.transportSp === 'rsa-1_5' &&
           da.signs11Assertion === false && da.signs11Response === false,
           'B. development: each application\'s override is honoured while ' +
           'the service-wide setting is strong', JSON.stringify(da));
      const d1 = out.devOn;
      note(d1.risc === 'subject_type' && d1.sigName === 'rsa-sha1' &&
           d1.sha1 === 'accepted' && d1.signs2 === false &&
           d1.transport === 'rsa-1_5' && d1.signs11Response === false &&
           d1.header === false && d1.headerView === false &&
           d1.clockOffset === 120 && d1.caConfigured === 'sha1-rsa',
           'B. development, every weak value stored: each is honoured',
           JSON.stringify(d1));
      [out.productOn, out.productAgain].forEach(function (p, i) {
        const when = i ? ' (read again)' : '';
        note(p.risc === 'format', 'B. product: the RISC subject says ' +
             '`format`' + when, JSON.stringify(p));
        note(p.sigName === 'rsa-sha256', 'B. product: XML is signed ' +
             'RSA-SHA256, rsa-sha1 still stored' + when, p.sigName);
        note(p.sha1 === 'STS-KEYS-0062', 'B. product: a SHA-1 signature is ' +
             'refused, saml.allowSha1Signatures still on' + when, p.sha1);
        note(p.unwrap15 === 'STS-KEYS-0070', 'B. product: an rsa-1_5 ' +
             'EncryptedKey is refused before it is unwrapped, ' +
             'STS-KEYS-0070' + when, p.unwrap15);
        note(p.signs2 === true && p.signs2Sp === true, 'B. product: the ' +
             'SAML 2.0 assertion is signed, service-wide and for the ' +
             'application whose override says FALSE' + when,
             JSON.stringify([p.signs2, p.signs2Sp]));
        note(p.transport === 'rsa-oaep-mgf1p' &&
             p.transportSp === 'rsa-oaep-mgf1p', 'B. product: keys are ' +
             'wrapped with rsa-oaep-mgf1p, service-wide and per ' +
             'application' + when,
             JSON.stringify([p.transport, p.transportSp]));
        note(p.signs11Assertion === true && p.signs11Response === true,
             'B. product: the SAML 1.1 assertion and Response are signed, ' +
             'the overrides saying FALSE' + when,
             JSON.stringify([p.signs11Assertion, p.signs11Response]));
        note(p.header === true && p.headerView === true, 'B. product: the ' +
             'Workload API requires the header, and GET /spiffe says so' +
             when, JSON.stringify([p.header, p.headerView]));
        note(p.clockOffset === 0, 'B. product: the KDC runs on the ' +
             'machine\'s clock, krb5.clockOffset still 120' + when,
             String(p.clockOffset));
        note(p.caConfigured === 'sha256-rsa' &&
             p.caNamed === 'STS-PKI-0191', 'B. product: a CA build reads ' +
             'the stored sha1-rsa as the key\'s default, and one NAMING ' +
             'sha1-rsa is refused, STS-PKI-0191' + when,
             JSON.stringify([p.caConfigured, p.caNamed]));
      });
      const d2 = out.devAgain;
      note(d2.risc === 'subject_type' && d2.sigName === 'rsa-sha1' &&
           d2.sha1 === 'accepted' && d2.unwrap15 === 'opened' &&
           d2.signs2 === false && d2.header === false &&
           d2.clockOffset === 120 && d2.caNamed === 'sha1-rsa',
           'B. back in development, every weak value is honoured again',
           JSON.stringify(d2));

      // ---- C. the report and the routes --------------------------------
      note(['broken-algorithms', 'signed-assertions',
            'workload-security-header', 'deliberate-defects']
             .every(function (id) {
               return out.ids.indexOf(id) >= 0;
             }), 'C. mode.report() carries the three new requirements, ' +
           'and deliberate-defects', out.ids.join(', '));
      const wanted = ['risc.googleSubjectType', 'krb5.clockOffset',
                      'saml2.signAssertion', 'saml11.signAssertion',
                      'saml11.signResponse', 'spiffe.requireSecurityHeader',
                      'saml.allowSha1Signatures', 'saml.signatureAlgorithm',
                      'saml2.keyTransportAlgorithm', 'pki.signatureAlgorithm'];
      note(wanted.every(function (key) {
        return out.ignored.indexOf(key) >= 0;
      }), 'C. product: report() lists every stored weak value as IGNORED',
           out.ignored.join(', '));
      note(out.view && out.view.mode === 'product' &&
           out.view.developmentOnlySettings.length >= wanted.length,
           'C. modeView() is the report', JSON.stringify(out.view &&
                                                         out.view.mode));
      note(out.api.status === 200 && out.api.json &&
           out.api.json.mode === 'development' &&
           Array.isArray(out.api.json.requirements) &&
           out.api.json.requirements.length === out.ids.length &&
           Array.isArray(out.api.json.developmentOnlySettings),
           'C. GET /admin-api/mode answers the report',
           out.api.status + ' ' + out.api.text.slice(0, 300));
      note(out.routes.indexOf('/admin/mode') >= 0 &&
           out.routes.indexOf('/admin-api/mode') >= 0,
           'C. GET /admin/mode and GET /admin-api/mode are registered',
           out.routes.join(', '));
      note(out.page.status !== 404,
           'C. GET /admin/mode answers (behind the console gate)',
           out.page.status + ' ' + out.page.text.slice(0, 200));
      server.close();
    } catch (e) {
      note(false, 'the child ran every section', (e && e.stack) || e);
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })();
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'mode-weak-' + process.pid + '-' +
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
      env: Object.assign(clean, { LOG_LEVEL: 'warn', STS_LOG_LEVEL: 'warn',
                                  MW_ROOT: ROOT, MW_OUT: out,
                                  MW_MARKED: JSON.stringify(MARKED) }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT,
      maxBuffer: 64 * 1024 * 1024
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
  // Said ONCE per setting, and once per overriding attribute, however often
  // it was read (STS-CORE-0106).
  const stdout = String(result.stdout || '');
  const saidFor = function (subject) {
    log.debug("Entering saidFor(). " + subject);
    log.debug("Leaving saidFor().");
    return stdout.split('\n').filter(function (line) {
      return line.indexOf('STS-CORE-0106') >= 0 &&
             line.indexOf('mode: ' + subject + ' ') >= 0;
    }).length;
  };
  ['risc.googleSubjectType', 'krb5.clockOffset', 'saml2.signAssertion',
   'saml11.signAssertion', 'saml11.signResponse',
   'spiffe.requireSecurityHeader',
   'saml.allowSha1Signatures', 'saml.signatureAlgorithm',
   'saml2.keyTransportAlgorithm', 'pki.signatureAlgorithm']
    .forEach(function (key) {
      t.check(saidFor(key) === 1, 'B. product: ' + key + ' ignored is ' +
              'logged ONCE with STS-CORE-0106', saidFor(key) + ' line(s)');
    });
  ['saml2SignAssertion', 'saml2KeyTransportAlgorithm', 'saml11SignResponse',
   'saml11SignAssertion']
    .forEach(function (attribute) {
      t.check(saidFor(attribute) === 1, 'B. product: the overriding ' +
              attribute + ' ignored is logged ONCE, naming it',
              saidFor(attribute) + ' line(s)');
    });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'mode_weak_settings',
  describe: '#181: risc.googleSubjectType, krb5.clockOffset, the SAML ' +
            'signature switches, spiffe.requireSecurityHeader and the SHA-1 ' +
            'and RSA 1.5 values are honoured in development, ignored where ' +
            'they are read in product (logged once) and refused on write ' +
            'there; /admin/mode and /admin-api/mode publish mode.report()',
  run: run
};
