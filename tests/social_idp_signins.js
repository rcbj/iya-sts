// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/social_idp_signins.js
//
// ===========================================================================
// ONE SIGN-IN THROUGH EACH NAMED SOCIAL PROVIDER'S DUMMY (#1689).
//
// The catalogue names 39 social providers, plus two generic profiles that
// are not providers. A live sign-in needs an application and an account at
// each, and none is kept. companion/social_idps.js serves a dummy of each
// named one. This file signs in through every one of them.
//
// ONE FILE, because the stack boots once. EACH PROVIDER IS ITS OWN
// ASSERTION: a throw in one is a failed finding and the loop continues, so
// a broken dummy does not hide the others. The two generic profiles stay
// out. The catalogue comparison runs in the child, after the stack is
// loaded: requiring the catalogue here would pull the service into this
// process.
//
// The child writes its findings as it goes, so a timeout still leaves the
// providers that finished.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'social_idp_signins',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const { SocialIdps } = require(path.join(ROOT, 'companion', 'social_idps'));

/**
 * GET /social, as text.
 *
 * @param {number} port - the dummy's port
 * @returns {Promise<object>} `{ status, text }`
 */
function indexText(port) {
  log.debug("Entering indexText().");
  log.debug("Leaving indexText().");
  return new Promise(function (resolve, reject) {
    const req = http.get({ host: '127.0.0.1', port: port, path: '/social' },
                          function (res) {
      let text = '';
      res.on('data', function (chunk) {
        text += chunk;
      });
      res.on('end', function () {
        resolve({ status: res.statusCode, text: text });
      });
    });
    req.on('error', reject);
  });
}

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SOCIAL_ROOT;
  const OUT = process.env.SOCIAL_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];

  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    try {
      fs.writeFileSync(OUT, JSON.stringify(findings));
    } catch (e) {
      console.error('findings write failed: ' + ((e && e.message) || e));
    }
  }

  (async function () {
    delete process.env.CONFIG_FILE;
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const federation = require(ROOT + '/federation/federation');
    const links = require(ROOT + '/federation/federation_links');
    const consumer = require(ROOT + '/federation/consumer_providers');
    const { SocialIdps } = require(ROOT + '/companion/social_idps');

    const server = http.createServer(app);
    await new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const origin = new URL(base).origin;
    const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
               '(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

    const social = new SocialIdps({ publicUrl: 'http://127.0.0.1' });
    const dummy = http.createServer(function (req, res) {
      social.handle(req, res);
    });
    await new Promise(function (resolve) {
      dummy.listen(0, '127.0.0.1', resolve);
    });
    const dport = dummy.address().port;
    social.setPublicUrl('http://127.0.0.1:' + dport);

    const SP = 'socialsp';
    realms.create({ id: SP });
    function inSp(fn) {
      return realms.run(realms.get(SP), fn);
    }
    function entryOf(name) {
      return inSp(function () {
        return ldap.existingUserEntry(name) || null;
      });
    }
    function attr(entry, name) {
      if (!entry) {
        return [];
      }
      return entry.attributes[name.toLowerCase()] || [];
    }
    inSp(function () {
      config.setOverride('federation.consumerProviders', 'true');
    });
    config.setOverride('federation.outboundAllowHttp', 'true');
    config.setOverride('federation.atprotoPlcDirectory',
                       social.blueskyDirectory());

    let jar = {};
    function cookieHeader() {
      return Object.keys(jar).map(function (key) {
        return key + '=' + jar[key];
      }).join('; ');
    }
    function request(method, target, opts) {
      const o = opts || {};
      const url = new URL(target, base);
      const remote = url.origin !== origin;
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign(remote ? {} : {
          cookie: cookieHeader(), 'user-agent': UA
        }, o.headers || {});
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({
          host: url.hostname, port: url.port,
          path: url.pathname + url.search, method: method, headers: headers
        }, function (res) {
          if (!remote) {
            [].concat(res.headers['set-cookie'] || []).forEach(
              function (line) {
                const pair = String(line).split(';')[0];
                const at = pair.indexOf('=');
                if (at > 0) {
                  const value = pair.slice(at + 1).trim();
                  const name = pair.slice(0, at).trim();
                  if (value) {
                    jar[name] = value;
                  } else {
                    delete jar[name];
                  }
                }
              });
          }
          const chunks = [];
          res.on('data', function (chunk) {
            chunks.push(chunk);
          });
          res.on('end', function () {
            resolve({
              status: res.statusCode, headers: res.headers,
              text: Buffer.concat(chunks).toString('utf8'),
              remote: remote, final: url.toString()
            });
          });
        });
        req.setTimeout(20000, function () {
          req.destroy(new Error('timed out'));
        });
        req.on('error', function (e) {
          resolve({
            status: 0, headers: {}, text: String((e && e.message) || e),
            remote: remote, final: url.toString()
          });
        });
        req.end(body);
      });
    }
    function htmlText(value) {
      return String(value).replace(/&quot;/g, '"').replace(/&#39;/g, "'")
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&');
    }
    function postedForm(html) {
      const form = /<form method="post" action="([^"]*)">/.exec(html);
      if (!form) {
        return null;
      }
      const fields = {};
      const input = /<input type="hidden" name="([^"]*)" value="([^"]*)">/g;
      let one = input.exec(html);
      while (one) {
        fields[htmlText(one[1])] = htmlText(one[2]);
        one = input.exec(html);
      }
      return { action: htmlText(form[1]), fields: fields };
    }
    function whereNext(response) {
      const loc = response.headers.location;
      if (Array.isArray(loc)) {
        return String(loc[0] || '');
      }
      return String(loc || '');
    }
    async function signIn(rel) {
      jar = {};
      let response = await request('GET', '/realm/' + SP +
                                   '/federation/login/' + rel);
      for (let hop = 0; hop < 16; hop += 1) {
        const at = whereNext(response);
        if (response.status >= 300 && response.status < 400 && at) {
          response = await request('GET',
                                   new URL(at, response.final).toString());
          continue;
        }
        if (response.remote &&
            response.text.indexOf('<form method="post" action=') >= 0) {
          const form = postedForm(response.text);
          if (form) {
            response = await request('POST',
              new URL(form.action, response.final).toString(),
              { form: form.fields });
            continue;
          }
        }
        return response;
      }
      return response;
    }

    const ids = SocialIdps.ids();
    const catalogue = consumer.ids().filter(function (id) {
      return id !== 'generic-oidc' && id !== 'generic-oauth2';
    });
    note(ids.join('\n') === catalogue.join('\n'),
         'the dummies are the named providers, in catalogue order',
         ids.join(',') + ' vs ' + catalogue.join(','));
    note(consumer.ids().indexOf('generic-oidc') >= 0 &&
         consumer.ids().indexOf('generic-oauth2') >= 0 &&
         ids.indexOf('generic-oidc') < 0 &&
         ids.indexOf('generic-oauth2') < 0,
         'the two generic profiles stay in the catalogue and out of ' +
         'the dummies', consumer.ids().join(','));

    async function oneProvider(id) {
      const rel = 'soc-' + id;
      const made = inSp(function () {
        return federation.create({ fedId: rel, fedProvider: id });
      });
      note(!!made.ok, id + ': the relationship is created from the profile',
           JSON.stringify(made.errors || ''));
      if (!made.ok) {
        return;
      }
      const fields = social.relationshipFields(id);
      const written = inSp(function () {
        const out = [];
        fields.forEach(function (one) {
          out.push(federation.update(rel, one));
        });
        out.push(federation.update(rel, { field: 'fedEnabled',
                                          value: 'TRUE' }));
        return out;
      });
      const bad = written.filter(function (one) {
        return !one.ok;
      });
      note(bad.length === 0,
           id + ': pointed at the dummy and enabled last',
           JSON.stringify(bad.map(function (one) {
             return one.errors;
           })));
      if (bad.length) {
        return;
      }
      const response = await signIn(rel);
      const account = SocialIdps.account(id);
      const name = inSp(function () {
        return links.provisionedName(rel, account.subject);
      });
      const entry = entryOf(name);
      const stopped = response.status + ' ' + response.final + ' ' +
                      String(response.text || '').slice(0, 400);
      note(response.status === 200 && !!entry,
           id + ': signs in ' + account.subject,
           stopped);
      if (!entry) {
        return;
      }
      const expect = account.expect;
      if (expect.cn !== undefined) {
        note(attr(entry, 'cn')[0] === expect.cn,
             id + ': the name is ' + expect.cn,
             JSON.stringify(entry.attributes).slice(0, 500));
      }
      if (expect.givenName !== undefined) {
        note(attr(entry, 'givenName')[0] === expect.givenName,
             id + ': the given name is ' + expect.givenName,
             JSON.stringify(attr(entry, 'givenName')));
      }
      if (expect.sn !== undefined) {
        note(attr(entry, 'sn')[0] === expect.sn,
             id + ': the surname is ' + expect.sn,
             JSON.stringify(attr(entry, 'sn')));
      }
      if (expect.mail !== undefined) {
        note(attr(entry, 'mail')[0] === expect.mail,
             id + ': the address is ' + expect.mail,
             JSON.stringify(attr(entry, 'mail')));
        const verified = attr(entry, 'stsMailVerified');
        if (expect.verified) {
          note(verified[0] === expect.mail,
               id + ': the address is verified',
               JSON.stringify(verified));
        } else {
          note(verified.length === 0,
               id + ': the address is not verified',
               JSON.stringify(verified));
        }
      }
    }

    for (let i = 0; i < ids.length; i += 1) {
      const id = ids[i];
      try {
        await oneProvider(id);
      } catch (e) {
        note(false, id + ' threw', e && e.stack);
      }
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child threw', e && e.stack);
    try {
      fs.writeFileSync(OUT, JSON.stringify(findings));
    } catch (writeError) {
      console.error('findings write failed: ' +
                    ((writeError && writeError.message) || writeError));
    }
    process.exit(0);
  });
}

/**
 * Serves /social, then runs one sign-in per named provider.
 *
 * @param t - the test context
 * @returns {Promise<void>}
 */
async function run(t) {
  log.debug("Entering run().");
  const social = new SocialIdps({ publicUrl: 'http://127.0.0.1' });
  const server = http.createServer(function (req, res) {
    social.handle(req, res);
  });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  social.setPublicUrl('http://127.0.0.1:' + port);
  try {
    const page = await indexText(port);
    const missing = SocialIdps.ids().filter(function (id) {
      return page.text.indexOf('href="/social/' + id + '"') < 0;
    });
    t.check(page.status === 200 && missing.length === 0 &&
            page.text.indexOf('generic-oidc') < 0 &&
            page.text.indexOf('generic-oauth2') < 0 &&
            !/<script/i.test(page.text),
            'the list names every dummy and neither generic, with no script',
            page.status + ' missing ' + missing.join(','));
  } finally {
    server.close();
  }

  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'social-')),
                        'findings.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (key !== 'CONFIG_FILE' &&
        !/^(STS_|OAUTH2_|LDAP_|SAML_|KRB5_|ADMIN_|SCIM_)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const child = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'],
    { env: Object.assign(clean, {
        LOG_LEVEL: 'fatal', SOCIAL_ROOT: ROOT, SOCIAL_OUT: out }),
      encoding: 'utf8', timeout: 420000, maxBuffer: 64 * 1024 * 1024 });
  if (child.error) {
    t.check(false, 'the child finished',
            String(child.error && child.error.message) + ' ' +
            String(child.stderr || '').slice(-2000));
  }
  let findings = [];
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.check(false, 'the child wrote its findings',
            String(child.stderr || '').slice(-2000) + ' ' +
            String(child.stdout || '').slice(-500));
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'social_idp_signins',
  describe: 'a dummy of each of the 39 named social providers (#1689), ' +
            'served by the companion, each signed in through as its own ' +
            'assertion; the two generic profiles stay out',
  run: run
};
