'use strict';
//
// File: outbound_tls.js
//
// ===========================================================================
// PRODUCT MODE NO LONGER SENDS ANYTHING OVER UNVERIFIED TLS (#171).
//
// Four families make an outbound request to an address somebody else answers
// — GNAP's push finish, SSF push delivery, federation's back channels and the
// XACML PEP nudge — and each had one `…AllowInsecure` switch that allowed
// plain http AND turned certificate verification off, which product mode
// honoured. `common/outbound_tls.ts` is the one policy now, and this file
// holds each family to it by DIALLING real listeners in this process:
//
//   A. a self-signed https listener is REFUSED in product even with the
//      family's `…SkipTlsVerification` stored on — and the stored value is
//      reported as not in force;
//   B. the same kind of listener, certified by a CA the family's `…CaFile`
//      names, is REACHED in product with verification on; a CA file that
//      cannot be read refuses the request (STS-CORE-0104);
//   C. `…SkipTlsVerification` still works in development;
//   D. plain http: allowed in development with `…AllowHttp` on, refused
//      without it; in product refused for SSF, federation and XACML whatever
//      it says (each family's code), and allowed for GNAP to loopback only
//      (STS-GNAP-0103 otherwise);
//   E. a WRITE of `…SkipTlsVerification=true` is refused in product
//      (STS-CORE-0103) through `config.setOverride()` and `config.checkWrite()`
//      — the two things every console and API door writes through — while
//      `false` is accepted, and development accepts both; SPIRE's
//      `spiffe.k8sSkipKubeletVerification` is held to the same rule;
//   F. the removed keys: a stored override naming one is refused with its
//      replacement named, and a process whose environment names one does not
//      start (STS-CORE-0105);
//   G. `mode.report()` lists the requirement, so /admin/mode and the API say
//      what product mode changed.
//
// In process, in this runner's process: every module here is a library that
// builds its own default instance when loaded alone, and nothing needs the
// protocol stack. `global.mode` is set and cleared as a process override, and
// every setting this file touches is cleared in the `finally`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const childProcess = require('child_process');
// The run-time CA the HTTP jobs use, built by the vendored PKI encoder
// (`common/vendored/x509.js`): one certificate encoder, and no key material
// on disk in the repository (#171).
const testCa = require('./vendored/outbound_test_ca');

const log = require('bunyan').createLogger({ name: 'outbound_tls',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// An https listener on 127.0.0.1 answering every request with `status`.
function listen(options, status, seen) {
  log.debug("Entering listen().");
  const server = (options ? https : http).createServer(options || {},
                                                       function (req, res) {
    req.resume();
    req.on('end', function () {
      seen.push(req.url);
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(status === 200 ? '{"ok":true}' : '');
    });
  });
  log.debug("Leaving listen().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

function originOf(server, scheme) {
  log.debug("Entering originOf().");
  log.debug("Leaving originOf().");
  return scheme + '://127.0.0.1:' + server.address().port;
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const mode = require('../common/mode');
  const errorCodes = require('../common/error_codes');
  const outboundTls = require('../common/outbound_tls');
  const gnapHttp = require('../gnap/gnap_http');
  const ssfHttp = require('../ssf/ssf_http');
  const fedHttp = require('../federation/federation_http');
  const pepHttp = require('../xacml/xacml_pep_http');

  // THE PINNED LOOKUP ANSWERS ON A LATER TURN (2026-09-24). Answered in the
  // same tick, node connected inside transport.request() before the
  // ClientRequest listened to its socket, and an address that failed at once
  // (ENETUNREACH) was an unhandled 'error' that ended the process.
  await (async function () {
    let answered = null;
    let single = null;
    const lookup = fedHttp.pinnedLookup({ address: '192.0.2.1', family: 4 });
    lookup('pinned.example', { all: true }, function (e, list) {
      answered = list;
    });
    lookup('pinned.example', {}, function (e, address, family) {
      single = { address: address, family: family };
    });
    t.check(answered === null && single === null,
            'the pinned lookup does not answer in the tick it was asked');
    await new Promise(function (resolve) { setImmediate(resolve); });
    t.check(!!answered && answered.length === 1 &&
            answered[0].address === '192.0.2.1' && answered[0].family === 4,
            'and answers the vetted address on a later turn, as a list when ' +
            'asked for all (' + JSON.stringify(answered) + ')');
    t.check(!!single && single.address === '192.0.2.1' && single.family === 4,
            'and as one address otherwise (' + JSON.stringify(single) + ')');
  })();

  // The certificates, made now: a CA and a leaf it issued, and a self-signed
  // leaf. The CA certificate goes to a temp directory, the only file.
  const ca = await testCa.makeCa();
  const leaf = await testCa.listenerCertificate(ca, '127.0.0.1');
  const self = await testCa.selfSignedCertificate('127.0.0.1');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'outbound-tls-'));
  const caFile = path.join(dir, 'ca.crt');
  fs.writeFileSync(caFile, ca.certPem);
  const emptyFile = path.join(dir, 'empty.crt');
  fs.writeFileSync(emptyFile, 'no certificate here\n');

  const seen = [];
  const trusted = await listen(leaf, 202, seen);
  const untrusted = await listen(self, 202, seen);
  const trustedJson = await listen(leaf, 200, seen);
  const untrustedJson = await listen(self, 200, seen);
  const TRUSTED = originOf(trusted, 'https');
  const UNTRUSTED = originOf(untrusted, 'https');

  const touched = ['global.mode', 'gnap.pushFinish', 'ssf.pushDelivery',
    'federation.outbound', 'xacml.pepNotify'];
  const FAMILIES = [
    { name: 'GNAP', t: gnapHttp.PUSH_TRANSPORT, loopback: true },
    { name: 'SSF', t: ssfHttp.PUSH_TRANSPORT, loopback: false },
    { name: 'federation', t: fedHttp.OUTBOUND_TRANSPORT, loopback: false },
    { name: 'XACML', t: pepHttp.NOTIFY_TRANSPORT, loopback: false }
  ];
  FAMILIES.forEach(function (f) {
    touched.push(f.t.allowHttpKey, f.t.skipTlsKey, f.t.caFileKey);
  });
  touched.push('spiffe.k8sSkipKubeletVerification');
  const set = function (key, value) {
    const result = config.setOverride(key, value);
    if (!result.ok) {
      throw new Error('setting ' + key + ' was refused: ' +
                      result.errors.join(' '));
    }
  };

  // ONE REQUEST PER FAMILY, the same way each family's caller makes it, and
  // an answer reduced to { ok, code, why }.
  const dial = {
    GNAP: async function (origin) {
      const r = await gnapHttp.pushFinish(origin + '/push', { hash: 'h',
        interact_ref: 'r' });
      return { ok: r.ok, code: r.errorCode || '', why: r.why || '' };
    },
    SSF: async function (origin) {
      const r = await ssfHttp.pushSet(origin + '/events', 'e.y.j');
      return { ok: r.ok, code: r.errorCode || '', why: r.why || '' };
    },
    federation: async function (origin) {
      const port = origin === TRUSTED ? trustedJson.address().port
        : origin === UNTRUSTED ? untrustedJson.address().port
          : Number(new URL(origin).port);
      const r = await fedHttp.fetchJson({ fedId: 'test',
        fedJwksUri: origin.replace(/:\d+$/, ':' + port) + '/jwks' },
                                        'fedJwksUri');
      return { ok: r.ok, code: r.errorCode || '', why: r.why || '' };
    },
    XACML: async function (origin) {
      const r = await pepHttp.nudge(origin + '/notify', 'pdp');
      return { ok: r.ok, code: '', why: r.why || '' };
    }
  };

  try {
    set('gnap.pushFinish', true);
    set('ssf.pushDelivery', true);
    set('federation.outbound', true);
    set('xacml.pepNotify', true);

    for (const f of FAMILIES) {
      t.log.info('--- ' + f.name + ' ---');
      // C. DEVELOPMENT: the skip works; without it the self-signed listener
      // is refused.
      set('global.mode', 'development');
      let r = await dial[f.name](UNTRUSTED);
      t.check(!r.ok, f.name + ': in development a self-signed listener is ' +
              'refused while ' + f.t.skipTlsKey + ' is off', r.why);
      set(f.t.skipTlsKey, true);
      r = await dial[f.name](UNTRUSTED);
      t.check(r.ok, f.name + ': in development ' + f.t.skipTlsKey +
              ' still reaches a self-signed listener', r.why);
      t.check(outboundTls.describe(f.t).skipTlsVerification === true,
              f.name + ': and the view reports the skip in force');

      // A. PRODUCT: the stored skip is IGNORED.
      set('global.mode', 'product');
      r = await dial[f.name](UNTRUSTED);
      t.check(!r.ok && /certificate|self.signed|SELF_SIGNED/i.test(r.why),
              f.name + ': in product a self-signed listener is refused even ' +
              'with ' + f.t.skipTlsKey + ' stored on', r.why);
      const view = outboundTls.describe(f.t);
      t.check(view.skipTlsVerificationSet && !view.skipTlsVerification,
              f.name + ': and the view says the stored skip is NOT in force',
              JSON.stringify(view));

      // B. PRODUCT: a CA file reaches a privately certified listener.
      set(f.t.caFileKey, caFile);
      r = await dial[f.name](TRUSTED);
      t.check(r.ok, f.name + ': in product ' + f.t.caFileKey + ' reaches a ' +
              'listener its CA certified, with verification on', r.why);
      r = await dial[f.name](UNTRUSTED);
      t.check(!r.ok, f.name + ': while a listener no CA certified is still ' +
              'refused', r.why);
      set(f.t.caFileKey, path.join(dir, 'missing.crt'));
      r = await dial[f.name](TRUSTED);
      t.check(!r.ok && /could not be read/.test(r.why) &&
              (f.name === 'XACML' || r.code === 'STS-CORE-0104'),
              f.name + ': a CA file that cannot be read refuses the request ' +
              '(STS-CORE-0104)', r.code + ' ' + r.why);
      set(f.t.caFileKey, emptyFile);
      r = await dial[f.name](TRUSTED);
      t.check(!r.ok && /no PEM certificate/.test(r.why),
              f.name + ': and so does one holding no certificate', r.why);
      set(f.t.caFileKey, '');

      // E. THE WRITE, IN PRODUCT.
      const refused = config.setOverride(f.t.skipTlsKey, 'true');
      t.check(!refused.ok && errorCodes.codeOf(refused) === 'STS-CORE-0103',
              f.name + ': in product a write of ' + f.t.skipTlsKey +
              '=true is refused with STS-CORE-0103',
              JSON.stringify(refused) + ' ' + errorCodes.codeOf(refused));
      t.check(!!config.checkWrite(f.t.skipTlsKey, true) &&
              config.checkWriteCode(f.t.skipTlsKey, true) === 'STS-CORE-0103',
              f.name + ': and checkWrite(), which a console section\'s ' +
              'Save asks before writing anything, refuses it too');
      t.check(config.checkOverride(f.t.skipTlsKey, true) === null,
              f.name + ': while checkOverride() — what a STORED value is ' +
              'restored through — does not, so a realm holding one still ' +
              'restores and the value is ignored where it is read');
      t.check(config.setOverride(f.t.skipTlsKey, false).ok,
              f.name + ': writing false is accepted in product');

      // D. PLAIN HTTP.
      set('global.mode', 'development');
      set(f.t.allowHttpKey, false);
      const verdictOf = function (url) {
        return f.name === 'GNAP' ? gnapHttp.urlVerdict(url)
          : f.name === 'SSF' ? ssfHttp.urlVerdict(url)
            : f.name === 'federation' ? fedHttp.urlVerdict(url)
              : pepHttp.urlVerdict(url);
      };
      let v = verdictOf('http://partner.example.com/x');
      t.check(!!v.why && v.why.indexOf(f.t.allowHttpKey) >= 0 && !v.errorCode,
              f.name + ': in development plain http is refused while ' +
              f.t.allowHttpKey + ' is off, naming it', v.why);
      set(f.t.allowHttpKey, true);
      v = verdictOf('http://partner.example.com/x');
      t.check(!v.why, f.name + ': and allowed to any host with it on', v.why);
      set('global.mode', 'product');
      v = verdictOf('http://partner.example.com/x');
      t.check(!!v.why && v.errorCode === f.t.httpRefusedCode,
              f.name + ': in product plain http to a remote host is refused ' +
              'whatever ' + f.t.allowHttpKey + ' says (' +
              f.t.httpRefusedCode + ')', v.errorCode + ' ' + v.why);
      v = verdictOf('http://127.0.0.1:9/x');
      if (f.loopback) {
        t.check(!v.why, f.name + ': but to loopback it is allowed (RFC 9635 ' +
                'section 2.5.2.1)', v.why);
      } else {
        t.check(!!v.why && v.errorCode === f.t.httpRefusedCode,
                f.name + ': and to loopback too — no loopback exception ' +
                'outside GNAP', v.errorCode + ' ' + v.why);
      }
      set(f.t.allowHttpKey, false);
      set('global.mode', 'development');
      set(f.t.skipTlsKey, false);
    }

    // E, for SPIRE's kubelet skip, which is not a family's.
    set('global.mode', 'product');
    const kubelet = config.setOverride('spiffe.k8sSkipKubeletVerification',
                                       true);
    t.check(!kubelet.ok && errorCodes.codeOf(kubelet) === 'STS-CORE-0103',
            'spiffe.k8sSkipKubeletVerification=true is refused in product',
            JSON.stringify(kubelet));
    set('global.mode', 'development');
    set('spiffe.k8sSkipKubeletVerification', true);
    t.check(outboundTls.skipsVerification('spiffe.k8sSkipKubeletVerification',
                                          'STS-SPIFFE-0116', 'a test'),
            'and honoured in development');
    set('global.mode', 'product');
    t.check(!outboundTls.skipsVerification(
      'spiffe.k8sSkipKubeletVerification', 'STS-SPIFFE-0116', 'a test'),
            'and ignored in product when it is stored on');
    set('global.mode', 'development');
    set('spiffe.k8sSkipKubeletVerification', false);

    // F. THE REMOVED KEYS.
    config.REPLACED_SETTINGS.forEach(function (row) {
      const problem = config.checkOverride(row.key, true);
      t.check(!!problem && problem.indexOf(row.now[0]) >= 0,
              row.key + ' is unknown, and the refusal names what replaced it',
              problem);
    });
    const child = childProcess.spawnSync(process.execPath,
      ['-e', "require(" + JSON.stringify(path.join(ROOT, 'common/config')) +
             ")"],
      { env: Object.assign({}, process.env,
                           { STS_SSF_PUSH_ALLOW_INSECURE: 'true' }),
        encoding: 'utf8', timeout: 60000 });
    t.check(child.status === 1 && /STS-CORE-0105/.test(child.stderr) &&
            /STS_SSF_PUSH_ALLOW_HTTP/.test(child.stderr),
            'a process whose environment names a removed key does not ' +
            'start, and says what replaced it (STS-CORE-0105)',
            'exit ' + child.status + ' ' +
            String(child.stderr || '').slice(0, 300));

    // G. /admin/mode.
    const row = mode.report().requirements.filter(function (one) {
      return one.id === 'outbound-tls';
    })[0];
    t.check(!!row && /IGNORED/.test(row.product),
            'mode.report() lists the outbound-tls requirement');
    t.check(typeof mode.skipsOutboundTlsVerification === 'function' &&
            typeof mode.dialsPlainHttpOutbound === 'function',
            'and the two predicates exist');

    // H. EVERY OTHER DIALER (#201): the one helper and the process-wide hook.
    const tlsModule = require('tls');
    const httpsModule = require('https');
    const dialOut = function (options) {
      log.debug("Entering dialOut().");
      log.debug("Leaving dialOut().");
      return new Promise(function (resolve) {
        const req = httpsModule.get(Object.assign({ host: '127.0.0.1',
          port: trusted.address().port, path: '/' }, options),
        function (res) {
          res.resume();
          resolve({ ok: true, status: res.statusCode });
        });
        req.on('error', function (e) {
          resolve({ ok: false, code: e.code || '', message: e.message });
        });
      });
    };
    const opts = outboundTls.verifiedOptions(ca.certPem);
    t.check(opts.rejectUnauthorized === true &&
            opts.checkServerIdentity === outboundTls.checkServerIdentity &&
            Array.isArray(opts.ca) && opts.ca.some(function (one) {
              return one.trim() === ca.certPem.trim();
            }),
            'verifiedOptions() verifies, checks the host as RFC 9525 does, ' +
            'and adds the CA beside node\'s store');
    const viaHelper = await dialOut(Object.assign({}, opts,
                                                  { agent: false }));
    t.check(viaHelper.ok, 'a request with verifiedOptions() reaches a ' +
            'server whose leaf names 127.0.0.1 in its SAN',
            JSON.stringify(viaHelper));
    const wrongName = await dialOut(Object.assign({}, opts, { agent: false,
      servername: 'elsewhere.example',
      checkServerIdentity: function (host, cert) {
        return outboundTls.checkServerIdentity('elsewhere.example', cert);
      } }));
    t.check(!wrongName.ok && wrongName.code === 'ERR_TLS_CERT_ALTNAME_INVALID',
            'and refuses one that does not name the host asked for',
            JSON.stringify(wrongName));
    const cnOnly = outboundTls.hostNameProblem('example.com',
      { subject: { CN: 'example.com' }, subjectaltname: '' });
    t.check(!!cnOnly, 'the host check never falls back to the common name ' +
            '(RFC 9525 section 6.3)', cnOnly);
    t.check(!!outboundTls.hostNameProblem('foo.example.com',
      { subjectaltname: 'DNS:f*.example.com' }) &&
            !outboundTls.hostNameProblem('foo.example.com',
              { subjectaltname: 'DNS:*.example.com' }),
            'and takes a wildcard only as a whole left-most label');
    const before = tlsModule.checkServerIdentity;
    outboundTls.installProcessWide();
    t.check(tlsModule.checkServerIdentity === outboundTls.checkServerIdentity,
            'installProcessWide() puts the check under every TLS client ' +
            'that names none (it was ' + (before === outboundTls
              .checkServerIdentity ? 'already installed' : 'node\'s') + ')');
    const plain = await dialOut({ agent: false, ca: [ca.certPem],
                               servername: 'elsewhere.example' });
    t.check(!plain.ok && plain.code === 'ERR_TLS_CERT_ALTNAME_INVALID',
            'so a plain https.get() naming no check of its own refuses a ' +
            'host its server\'s certificate does not name',
            JSON.stringify(plain));
    const chainOnly = await dialOut({ agent: false, ca: [ca.certPem],
      servername: 'elsewhere.example',
      checkServerIdentity: outboundTls.checkChainOnly });
    t.check(chainOnly.ok, 'while checkChainOnly() — the kubelet with its ' +
            'own CA — holds the chain to the path rules and not the name',
            JSON.stringify(chainOnly));
  } finally {
    touched.forEach(function (key) {
      try {
        config.clearOverride(key);
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
        // A key this run never set; nothing to clear.
      }
    });
    [trusted, untrusted, trustedJson, untrustedJson].forEach(function (s) {
      s.close();
    });
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'outbound_tls',
  describe: '#171: GNAP push, SSF push, federation back channels and XACML ' +
            'nudges verify TLS in product whatever a skip says, reach a ' +
            'private CA through a CA file, refuse plain http in product ' +
            '(GNAP loopback excepted), and refuse a product write of a skip',
  run: run
};
