'use strict';
//
// File: fapi2_message_signing_units.js
//
// ===========================================================================
// FAPI 2.0 MESSAGE SIGNING (#141, 2026-09-22), in process:
//
//   A. `2-message-signing` is the Security Profile and more: fapi2() true,
//      messageSigning() true, its report the 2.0 table plus its own rows.
//   B. A signed request object is required, held to exp, nbf and aud.
//   C. JARM is required: a request without a JWT response mode is refused.
//   D. The metadata: a signed request object required, JARM's modes only,
//      PAR still required.
//   E. The Security Profile alone asks none of B-D.
//
// `tests/vendored/sts_fapi2_message_signing.js` holds it over the wire.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({
  name: 'fapi2_message_signing_units',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

// IN A CHILD PROCESS, for `oidc_core_units.js`'s reason.
function childMain() {
  const ROOT = process.env.FMS_ROOT;
  const OUT = process.env.FMS_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }
  function eq(got, want, what) {
    return note(got === want, what, 'expected ' + JSON.stringify(want) +
                ', got ' + JSON.stringify(got));
  }
  function codeOf(refusal) {
    return refusal ? refusal.errorCode : null;
  }
  const main = async function () {
    require(ROOT + '/common/protocol_stack');
    const fapi = require(ROOT + '/oauth-oidc/fapi');
    const bcp = require(ROOT + '/oauth-oidc/oauth2_bcp');
    const ms = function (fn) {
      return fapi.withProfile('2-message-signing', fn);
    };
    const sp = function (fn) {
      return fapi.withProfile('2-security', fn);
    };

    // --- A ----------------------------------------------------------------
    eq(ms(function () {
      return [fapi.fapi2(), fapi.messageSigning(), fapi.advanced(),
              fapi.v1(), bcp.enabled()].join('/');
    }), 'true/true/false/false/true', 'A. Message Signing is FAPI 2.0 and ' +
       'more, and implies RFC 9700 mode');
    const view = ms(function () {
      return fapi.state();
    });
    const ids = view.requirements.map(function (row) {
      return row.id;
    });
    note(/Message Signing/.test(view.specification) &&
         ids.indexOf('no-rotation') >= 0 &&
         ids.indexOf('jarm-required') >= 0 &&
         ids.indexOf('signed-request-at-par') >= 0,
         'A. its report is the 2.0 table and its own rows',
         JSON.stringify(ids));

    // --- B ----------------------------------------------------------------
    eq(ms(function () {
      return fapi.requiresSignedRequestObject();
    }), true, 'B. a signed request object is required (5.3.2 item 1)');
    const now = Math.floor(Date.now() / 1000);
    const iss = 'https://as.example';
    const obj = function (claims) {
      return ms(function () {
        return codeOf(fapi.requestObjectRefusal(Object.assign({ aud: iss,
          nbf: now, exp: now + 300 }, claims), iss, now));
      });
    };
    eq(obj({}), null, 'B. exp, nbf and aud as asked are accepted');
    eq(obj({ nbf: undefined }), 'STS-OAUTH-0584', 'B. no nbf (item 3)');
    eq(obj({ exp: now + 3700 }), 'STS-OAUTH-0584',
       'B. exp over 60 minutes after nbf (item 4)');
    eq(obj({ aud: 'https://else.example' }), 'STS-OAUTH-0585',
       'B. aud not the issuer (item 2)');

    // --- C ----------------------------------------------------------------
    const good = { redirect_uri: 'https://rp.example/cb',
                   response_type: 'code', scope: 'openid',
                   code_challenge: 'x'.repeat(43),
                   code_challenge_method: 'S256', response_mode: 'jwt' };
    const vet = function (overrides) {
      return ms(function () {
        return codeOf(fapi.authorizationRefusal(Object.assign({}, good,
                                                              overrides),
                                                { pushed: true }));
      });
    };
    eq(vet({}), null, 'C. code with response_mode=jwt is allowed');
    eq(vet({ response_mode: 'form_post.jwt' }), null,
       'C. any JARM mode is');
    eq(vet({ response_mode: undefined }), 'STS-OAUTH-0591',
       'C. no JARM mode is refused (5.4.2 item 1)');
    eq(vet({ response_mode: 'query' }), 'STS-OAUTH-0591',
       'C. and nor is a plain one');
    eq(vet({ response_type: 'code id_token' }), 'STS-OAUTH-0582',
       'C. the Security Profile\'s code-only rule still holds');

    // --- D ----------------------------------------------------------------
    const meta = ms(function () {
      return fapi.applyToMetadata({
        response_modes_supported: ['query', 'fragment', 'form_post', 'jwt',
                                   'query.jwt', 'fragment.jwt',
                                   'form_post.jwt'],
        response_types_supported: ['code'] });
    });
    eq(JSON.stringify(meta.response_modes_supported),
       '["jwt","query.jwt","fragment.jwt","form_post.jwt"]',
       'D. JARM\'s modes only');
    eq(meta.require_signed_request_object, true,
       'D. a signed request object required');
    eq(meta.require_pushed_authorization_requests, true,
       'D. and PAR, as the Security Profile has it');

    // --- E ----------------------------------------------------------------
    eq(sp(function () {
      return fapi.requiresSignedRequestObject() + '/' +
             codeOf(fapi.authorizationRefusal(Object.assign({}, good,
               { response_mode: undefined }), { pushed: true })) + '/' +
             codeOf(fapi.requestObjectRefusal({}, iss, now));
    }), 'false/null/null', 'E. the Security Profile alone asks none of it');
  };
  main().catch(function (e) {
    note(false, 'the test itself threw', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'fapi2-ms-units-' + process.pid +
                        '-' + Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', FMS_ROOT: ROOT, FMS_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'fapi2_message_signing_units',
  describe: 'FAPI 2.0 Message Signing (#141): the profile over the ' +
            'Security Profile, the signed request object, JARM required, ' +
            'and the metadata',
  run: run
};
