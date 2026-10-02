// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/scim_auth_discovery.js
// ===========================================================================
// `scim.authDiscovery`, OFF AND ON (#416, 2026-10-02).
//
// RFC 7644 section 4's three discovery endpoints — /ServiceProviderConfig,
// /ResourceTypes and /Schemas — answer without a credential by default: the
// ServiceProviderConfig is where a client READS which authentication schemes
// exist (`authenticationSchemes`, RFC 7643 section 5), so requiring one to
// fetch it asks a client for the answer to its own question. The setting
// turns that round, and section 4 permits either. Turned on, a client learns
// the schemes from the refusal instead: the 401 carries a WWW-Authenticate
// challenge per scheme offered (RFC 7644 section 2's SHALL). Nothing in
// `tests/` mentioned the setting (#113 item 12).
//
// In a CHILD PROCESS with the whole stack, the default realm, a directory
// person to present over Basic:
//
//   A. OFF (the default), in development and in product: each discovery
//      endpoint answers a request with NO credential, the
//      ServiceProviderConfig's `authenticationSchemes` names exactly the
//      schemes the realm accepts, and no challenge is sent; while /Users, the
//      control, still refuses that request 401 with the challenges;
//   B. ON, in both modes: each discovery endpoint refuses a request with no
//      credential 401 (STS-SCIM-0058), and its WWW-Authenticate challenges
//      publish the schemes the realm accepts — one per scheme that has a
//      challenge, the same set /Users' refusal carries;
//   C. ON, with a credential: the ServiceProviderConfig is answered and
//      publishes the same `authenticationSchemes` as A — the setting decides
//      who may read the document, not what it says.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'scim_auth_discovery',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.SD_ROOT;
  const OUT = process.env.SD_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function get(port, urlPath, headers) {
    return new Promise(function (resolve, reject) {
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: 'GET',
                                 headers: Object.assign(
                                   { accept: 'application/scim+json' },
                                   headers || {}) },
      function (res) {
        let text = '';
        res.on('data', function (d) { text += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          // ONE PER HEADER LINE, from the raw headers: node folds repeated
          // WWW-Authenticate lines into one comma-joined string, and a
          // challenge's own parameters are comma-separated too.
          const challenge = [];
          for (let i = 0; i < res.rawHeaders.length; i += 2) {
            if (res.rawHeaders[i].toLowerCase() === 'www-authenticate') {
              challenge.push(res.rawHeaders[i + 1]);
            }
          }
          resolve({ status: res.statusCode, text: text, json: json,
                    challenge: challenge });
        });
      });
      req.on('error', reject);
      req.end();
    });
  }
  // The auth-scheme of each challenge, lower case and sorted: a Digest
  // challenge carries a fresh nonce, so the challenges themselves differ
  // between two responses and their schemes do not.
  const schemesOf = function (challenge) {
    return challenge.map(function (one) {
      return String(one).trim().split(/\s+/)[0].toLowerCase();
    }).filter(function (one, i, all) {
      return one && all.indexOf(one) === i;
    }).sort().join(',');
  };
  const namesOf = function (spc) {
    return ((spc && spc.authenticationSchemes) || []).map(function (one) {
      return one.name;
    }).sort().join(' | ');
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const audit = require(ROOT_DIR + '/common/audit');
    const scimAuth = require(ROOT_DIR + '/scim/scim_auth');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const PERSON = 'sd-client-' + process.pid;
    ldap.createUser(PERSON, { invent: false });
    const basic = { authorization: 'Basic ' +
      Buffer.from(PERSON + ':anything-at-all').toString('base64') };
    const DISCOVERY = ['/scim/v2/ServiceProviderConfig',
                       '/scim/v2/ResourceTypes', '/scim/v2/Schemas'];
    // What the realm accepts, from the scheme table itself: every scheme
    // that is offered, by name — what the document must publish.
    const accepted = function () {
      return scimAuth.describe().schemes.filter(function (one) {
        return one.enabled;
      }).map(function (one) {
        return one.name;
      }).sort().join(' | ');
    };
    // And the challenge each offered scheme answers with: the four of the
    // seven that have one (a DPoP proof, a cookie and a certificate are not
    // asked for in a WWW-Authenticate header), by the scheme's id, which is
    // its auth-scheme token.
    const challenged = function () {
      return scimAuth.describe().schemes.filter(function (one) {
        return one.enabled &&
               ['bearer', 'basic', 'digest', 'hoba'].indexOf(one.id) >= 0;
      }).map(function (one) {
        return one.id;
      }).sort().join(',');
    };
    const coded = function (target, code) {
      return audit.list().filter(function (event) {
        return event.target === target && event.errorCode === code;
      }).length;
    };

    for (const mode of ['development', 'product']) {
      const label = mode.toUpperCase();
      if (mode === 'product') {
        config.setOverride('global.mode', 'product');
      }
      try {
        // --- A. off --------------------------------------------------------
        config.setOverride('scim.authDiscovery', false);
        const control = await get(port, '/scim/v2/Users');
        note(control.status === 401 && control.challenge.length > 0,
             'A0. ' + label + ', off: /Users still refuses a request with no ' +
             'credential, with challenges (the control)',
             control.status + ' ' + schemesOf(control.challenge));
        for (const urlPath of DISCOVERY) {
          const r = await get(port, urlPath);
          note(r.status === 200 && r.challenge.length === 0,
               'A1. ' + label + ', off: ' + urlPath + ' answers a request ' +
               'with no credential', r.status + ' ' + r.text.slice(0, 160));
        }
        const open = await get(port, '/scim/v2/ServiceProviderConfig');
        note(namesOf(open.json) === accepted() && accepted().length > 0,
             'A2. ' + label + ', off: and its authenticationSchemes names ' +
             'exactly the schemes the realm accepts',
             namesOf(open.json) + ' / ' + accepted());

        // --- B. on, with no credential -----------------------------------
        config.setOverride('scim.authDiscovery', true);
        for (const urlPath of DISCOVERY) {
          const before = coded(urlPath, 'STS-SCIM-0058');
          const r = await get(port, urlPath);
          await new Promise(function (res) { setTimeout(res, 30); });
          note(r.status === 401 && coded(urlPath, 'STS-SCIM-0058') ===
               before + 1,
               'B1. ' + label + ', on: ' + urlPath + ' refuses a request ' +
               'with no credential 401, under STS-SCIM-0058',
               r.status + ' ' + r.text.slice(0, 160));
          note(r.challenge.length > 0 &&
               schemesOf(r.challenge) === challenged() &&
               schemesOf(r.challenge) === schemesOf(control.challenge),
               'B2. ' + label + ', on: and its challenges publish the ' +
               'schemes the realm accepts — the same set /Users\' refusal ' +
               'carries', schemesOf(r.challenge) + ' / ' + challenged() +
               ' / ' + schemesOf(control.challenge));
        }

        // --- C. on, with a credential (development: product checks the
        // password, and what is asked here is about the document) ---------
        if (mode === 'development') {
          const r = await get(port, '/scim/v2/ServiceProviderConfig', basic);
          note(r.status === 200 && namesOf(r.json) === namesOf(open.json),
               'C1. ' + label + ', on: with a credential the ' +
               'ServiceProviderConfig is answered, and publishes the same ' +
               'authenticationSchemes as when it was open',
               r.status + ' ' + namesOf(r.json));
        }
      } finally {
        config.clearOverride('scim.authDiscovery');
        if (mode === 'product') {
          config.clearOverride('global.mode');
        }
      }
    }
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sd-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|SCIM_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  SD_ROOT: ROOT, SD_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scim_auth_discovery',
  describe: 'scim.authDiscovery: off, the discovery endpoints answer with no ' +
            'credential and publish the accepted schemes; on, they refuse ' +
            'it 401 with a challenge per scheme (#416)',
  run: run
};
