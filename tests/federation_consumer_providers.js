// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_consumer_providers.js
//
// ===========================================================================
// CONSUMER AND SOCIAL PROVIDERS AS FEDERATION RELATIONSHIPS (#565).
//
// The three first profiles — Google (OpenID Connect), Discord (OAuth 2.0 with
// one profile endpoint) and GitHub (OAuth 2.0 with the address on a second
// one) — each driven through a REAL federated sign-in, over HTTP, in one
// process: this service is the relying party in a trust realm of this
// file's own, and a small server in the same child plays the three providers
// — each the SHAPE of its provider, not a copy of it: the authorization
// endpoint answers at once with a code, the token endpoint checks the PKCE
// verifier and the client authentication the profile says the provider
// takes, and the profile endpoints answer what the provider's documentation
// says they answer. No provider is dialled.
//
// What is held, section by section:
//
//   A. the catalogue and the profile written onto the entry at creation —
//      the endpoints, the issuer, the scope, the token authentication, the
//      consumer defaults (jit-namespaced, auto-create on), no encryption key;
//   B. the realm switch, at every door: creation refused, enabling refused,
//      a relationship written while it was on refusing at the login
//      endpoint once it is off — and enterprise relationships untouched;
//   C. the reading of a sign-in, without HTTP: `readPath()`, `extract()`,
//      a named claim authoritative even when it finds nothing, the address
//      unverified unless the provider says so;
//   D. a Discord sign-in: the subject is `id`, a newcomer's entry is
//      `<relationship>~<id>`, `verified` is the address's statement, and
//      client_secret_basic reached the token endpoint;
//   E. a GitHub sign-in: client_secret_post, the address from /user/emails'
//      primary verified one and NOT /user's public one, and the sign-in
//      standing without an address when /user/emails fails;
//   F. a Google sign-in: a signed ID Token verified against the provider's
//      keys, `accounts.google.com` accepted beside `https://…` and nothing
//      else, `email_verified` honoured;
//   G. COLLISION: a provider's person whose name and address are an
//      existing local person's lands on an entry of their own and never on
//      the local one, which is left exactly as it was; any-existing refused
//      on a consumer relationship;
//   H. the provider's MFA claim satisfying nothing, and the credential
//      fingerprint on the risk input being the relationship.
//
// WHY A CHILD PROCESS: it loads the whole protocol stack, serves it on a
// loopback port, creates a realm and flips settings.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'federation_consumer_providers',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.FCP_ROOT;
  const OUT = process.env.FCP_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const jwt = require('jsonwebtoken');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const federation = require(ROOT + '/federation/federation');
    const links = require(ROOT + '/federation/federation_links');
    const consumer = require(ROOT + '/federation/consumer_providers');
    const authn = require(ROOT + '/authn/authn');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    // A browser's User-Agent, so risk scoring sees a person rather than an
    // automated client (a key signal, which would ask for a security key).
    const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, ' +
               'like Gecko) Chrome/130.0.0.0 Safari/537.36';
    const base = 'http://127.0.0.1:' + port;

    // --- THE PROVIDERS ------------------------------------------------------
    // One server, three providers under three path prefixes. `people` is
    // who the next sign-in at each provider is; `seen` is what each token
    // endpoint was sent, for the client-authentication checks.
    const people = {};
    const seen = { discord: [], github: [], google: [], x: [], tiktok: [],
                   twitch: [], apple: [] };
    // Sign in with Apple's developer key (the .p8), which signs the client
    // secret this service mints.
    const appleKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const authorizeSeen = { tiktok: [], twitch: [] };
    const failEmails = { on: false };
    const codes = {};
    const signing = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const googleJwk = Object.assign(signing.publicKey.export({ format: 'jwk' }),
                                    { kid: 'fake-google-1', alg: 'RS256',
                                      use: 'sig' });
    let googleIssuer = '';
    const provider = http.createServer(function (req, res) {
      const url = new URL(req.url, 'http://127.0.0.1');
      const parts = url.pathname.split('/').filter(Boolean);
      const who = parts[0];
      const what = parts.slice(1).join('/');
      let body = '';
      req.on('data', function (c) { body += c; });
      req.on('end', function () {
        const json = function (status, value) {
          res.writeHead(status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(value));
        };
        if (what === 'authorize' && who === 'apple') {
          // FORM POST (Apple requires it for a name or an address): what
          // the browser would POST back, answered as data for the test.
          const code = 'apple-' + crypto.randomBytes(8).toString('hex');
          codes[code] = { who: who,
            challenge: url.searchParams.get('code_challenge'),
            nonce: url.searchParams.get('nonce') || '',
            clientId: url.searchParams.get('client_id'),
            mode: url.searchParams.get('response_mode'),
            person: people[who] };
          json(200, { action: url.searchParams.get('redirect_uri'),
                      mode: url.searchParams.get('response_mode'),
                      fields: { code: code,
                                state: url.searchParams.get('state'),
                                user: people[who].user || '' } });
          return;
        }
        if (what === 'authorize') {
          if (authorizeSeen[who]) {
            authorizeSeen[who].push(Object.fromEntries(
              url.searchParams.entries()));
          }
          const code = who + '-' + crypto.randomBytes(8).toString('hex');
          codes[code] = { who: who,
            challenge: url.searchParams.get('code_challenge'),
            nonce: url.searchParams.get('nonce') || '',
            clientId: url.searchParams.get('client_id') ||
                      url.searchParams.get('client_key'),
            person: people[who] };
          const back = new URL(url.searchParams.get('redirect_uri'));
          back.searchParams.set('code', code);
          back.searchParams.set('state', url.searchParams.get('state'));
          res.writeHead(302, { location: back.toString() });
          res.end();
          return;
        }
        if (what === 'token') {
          const form = new URLSearchParams(body);
          seen[who].push({ authorization: req.headers.authorization || '',
                           form: Object.fromEntries(form.entries()) });
          const grant = codes[form.get('code')];
          delete codes[form.get('code')];
          const verifier = form.get('code_verifier') || '';
          const digest = crypto.createHash('sha256').update(verifier)
            .digest('base64url');
          if (!grant || grant.challenge !== digest) {
            json(400, { error: 'invalid_grant' });
            return;
          }
          const token = 'at-' + crypto.randomBytes(8).toString('hex');
          codes['at:' + token] = grant;
          const answer = { access_token: token, token_type: 'Bearer' };
          if (who === 'tiktok') {
            answer.open_id = grant.person.openId;
          }
          if (who === 'apple') {
            let verified = null;
            try {
              verified = jwt.verify(form.get('client_secret') || '',
                                    appleKey.publicKey,
                                    { algorithms: ['ES256'] });
            } catch (e) {
              verified = null;
            }
            grant.appleSecret = verified;
            if (!verified || verified.iss !== 'TEAM123456' ||
                verified.sub !== grant.clientId ||
                verified.aud !== 'https://appleid.apple.com') {
              json(400, { error: 'invalid_client' });
              return;
            }
            answer.id_token = jwt.sign(Object.assign({
              iss: pbase + '/apple', aud: grant.clientId,
              nonce: grant.nonce }, grant.person.claims),
            signing.privateKey, { algorithm: 'RS256', expiresIn: 300,
                                  keyid: 'fake-google-1' });
          }
          if (who === 'google') {
            answer.id_token = jwt.sign(Object.assign({
              iss: grant.person.iss || googleIssuer, aud: grant.clientId,
              nonce: grant.nonce }, grant.person.claims),
            signing.privateKey, { algorithm: 'RS256', expiresIn: 300,
                                  keyid: 'fake-google-1' });
          }
          json(200, answer);
          return;
        }
        if (what === 'jwks') {
          json(200, { keys: [googleJwk] });
          return;
        }
        const bearer = String(req.headers.authorization || '')
          .replace(/^Bearer /, '');
        const grant = codes['at:' + bearer];
        if (!grant) {
          json(401, { message: 'Bad credentials' });
          return;
        }
        if (what === 'users/@me' || what === 'user' ||
            what === '2/users/me' || what === 'v2/user/info') {
          json(200, grant.person.profile);
          return;
        }
        if (what === 'user/emails') {
          if (failEmails.on) {
            json(500, { message: 'down' });
            return;
          }
          json(200, grant.person.emails);
          return;
        }
        json(404, { message: 'Not Found' });
      });
    });
    await new Promise(function (r) { provider.listen(0, '127.0.0.1', r); });
    const pbase = 'http://127.0.0.1:' + provider.address().port;
    googleIssuer = pbase + '/google';

    // --- a cookie jar, and a request that keeps it --------------------------
    let jar = {};
    function cookieHeader() {
      return Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ');
    }
    function request(method, target, opts) {
      const o = opts || {};
      const url = new URL(target, base);
      const remote = url.origin !== base;
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign(remote ? {} : { cookie: cookieHeader(),
                                                      'user-agent': UA },
                                      o.headers || {});
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: url.hostname, port: url.port,
          path: url.pathname + url.search, method: method, headers: headers },
        function (res) {
          if (!remote) {
            [].concat(res.headers['set-cookie'] || []).forEach(function (l) {
              const pair = String(l).split(';')[0];
              const i = pair.indexOf('=');
              if (i > 0) {
                const value = pair.slice(i + 1).trim();
                if (value) {
                  jar[pair.slice(0, i).trim()] = value;
                } else {
                  delete jar[pair.slice(0, i).trim()];
                }
              }
            });
          }
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, path: url.pathname });
          });
        });
        req.end(body);
      });
    }
    // The whole sign-in, redirect by redirect, to the service provider's
    // answer: its signed-in page or its refusal.
    async function signIn(rel) {
      jar = {};
      let r = await request('GET', '/realm/' + SP + '/federation/login/' +
                                   rel);
      for (let hop = 0; hop < 12; hop += 1) {
        const at = String(r.headers.location || '');
        if (r.status >= 300 && r.status < 400 && at) {
          r = await request('GET', new URL(at, base).toString());
          continue;
        }
        return r;
      }
      return r;
    }

    const SP = 'fcpsp';
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
      return entry ? (entry.attributes[name.toLowerCase()] || []) : [];
    }
    config.setOverride('federation.outboundAllowHttp', 'true');

    // ===== A. THE CATALOGUE AND WHAT CREATION WRITES ========================
    const ids = consumer.ids();
    note(['google', 'discord', 'github'].every(function (one) {
      return ids.indexOf(one) >= 0;
    }), 'A1. the catalogue holds Google, Discord and GitHub', ids.join(', '));
    note(ids.indexOf('discord') >= 0 && ids.indexOf('discord') < 3,
         'A2. Discord is among the first three profiles', ids.join(', '));

    inSp(function () {
      config.setOverride('federation.consumerProviders', 'true');
    });
    const made = inSp(function () {
      return { discord: federation.create({ fedId: 'cp-discord',
                                             fedProvider: 'discord' }),
               github: federation.create({ fedId: 'cp-github',
                                           fedProvider: 'github' }),
               google: federation.create({ fedId: 'cp-google',
                                           fedProvider: 'google' }) };
    });
    const d0 = made.discord.relationship || {};
    note(made.discord.ok && d0.fedRole === 'service-provider' &&
         d0.fedProtocol === 'oauth2' && d0.fedProvider === 'discord',
         'A3. a provider alone says the role and the protocol',
         JSON.stringify(made.discord.errors || [d0.fedRole, d0.fedProtocol]));
    note(d0.fedSsoUrl === 'https://discord.com/oauth2/authorize' &&
         d0.fedTokenUrl === 'https://discord.com/api/oauth2/token' &&
         d0.fedUserinfoUrl === 'https://discord.com/api/users/@me' &&
         d0.fedPeer === 'https://discord.com' &&
         d0.fedScope === 'identify email',
         'A4. the profile\'s endpoints, issuer and scope are ON THE ENTRY',
         [d0.fedSsoUrl, d0.fedTokenUrl, d0.fedUserinfoUrl, d0.fedPeer,
          d0.fedScope].join(' | '));
    const g0 = (made.github.relationship || {});
    note(g0.fedEmailsUrl === 'https://api.github.com/user/emails' &&
         g0.fedTokenAuth === 'client_secret_post',
         'A5. GitHub\'s second endpoint and client_secret_post are written',
         g0.fedEmailsUrl + ' ' + g0.fedTokenAuth);
    note(d0.fedSubjectPolicy === 'jit-namespaced' &&
         federation.boolOf(d0.fedAutocreateUsers, false) &&
         !federation.boolOf(d0.fedEnabled, true),
         'A6. created disabled, jit-namespaced, auto-create on',
         [d0.fedSubjectPolicy, d0.fedAutocreateUsers, d0.fedEnabled]
           .join(' '));
    const go = made.google.relationship || {};
    note(made.google.ok && go.fedProtocol === 'oidc' &&
         !federation.encrypts(go) && !go.fedEncryptionKeyType,
         'A7. a Google relationship is OIDC and is given no encryption key',
         go.fedProtocol + ' ' + go.fedEncryptionKeyType);
    const wrong = inSp(function () {
      return { proto: federation.create({ fedId: 'cp-bad1',
                 fedProvider: 'discord', fedProtocol: 'oidc' }),
               role: federation.create({ fedId: 'cp-bad2',
                 fedProvider: 'discord', fedRole: 'identity-provider' }),
               unknown: federation.create({ fedId: 'cp-bad3',
                 fedProvider: 'myspace' }) };
    });
    note(!wrong.proto.ok && !wrong.role.ok && !wrong.unknown.ok,
         'A8. another protocol, the other role, an unknown provider refused',
         JSON.stringify([wrong.proto.ok, wrong.role.ok, wrong.unknown.ok]));
    note(inSp(function () {
      return federation.categoryOf(federation.get('cp-discord'));
    }) === 'consumer' && consumer.categoryOf({}) === 'enterprise',
         'A9. the category is derived from fedProvider');
    const notReady = inSp(function () {
      return federation.readinessOf(federation.get('cp-discord')).missing;
    });
    note(notReady.indexOf('fedClientId') >= 0 &&
         notReady.indexOf('fedClientSecret') >= 0,
         'A10. a new provider relationship names the client credentials ' +
         'it still needs', notReady.join(', '));

    // ===== C. THE READING, WITHOUT HTTP ====================================
    note(consumer.readPath({ data: { id: '7' } }, 'data.id') === '7' &&
         consumer.readPath([{ email: 'a', primary: false },
                            { email: 'b', primary: true }],
                           '@primary.email') === 'b' &&
         consumer.readPath({}, '__proto__') === undefined &&
         consumer.readPath([1, 2], '1') === 2,
         'C1. readPath(): dotted, @primary, an index, own members only');
    const ghProfile = consumer.profileFor('github');
    const read = consumer.extract(ghProfile, {
      userinfo: { id: 42, login: 'octo', email: 'public@example.com' },
      emails: undefined }, { login: 'octo', email: 'public@example.com',
                             company: 'acme' });
    note(read.subject === '42' && read.bag.preferred_username === 'octo' &&
         read.bag.email === undefined && read.bag.company === 'acme' &&
         read.bag.email_verified === false,
         'C2. a named claim is authoritative when it finds nothing: no ' +
         'public address, the raw member kept, unverified',
         JSON.stringify(read));
    const dc = consumer.extract(consumer.profileFor('discord'),
      { userinfo: { id: '9', email: 'x@example.com', verified: 'yes' } }, {});
    note(dc.bag.email_verified === false,
         'C3. a verification statement that is not true is unverified');
    note(consumer.pathProblem('data.id') === null &&
         !!consumer.pathProblem('a..b') &&
         !!consumer.pathProblem('constructor'),
         'C4. pathProblem() takes a dotted path and refuses prototype names');

    // C5. MICROSOFT, ANY TENANT: the token's tid SELECTS the issuer the
    // signature check demands, only for a tenant the relationship lists.
    const tokenFor = function (tid) {
      return 'e30.' + Buffer.from(JSON.stringify({ tid: tid }))
        .toString('base64url') + '.sig';
    };
    const multi = { fedProvider: 'microsoft-any',
      fedPeer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
      fedAllowedTenants: ['9188040d-6c67-4c5b-b112-36a304b66dad'] };
    note(consumer.issuersFor(multi,
           tokenFor('9188040d-6c67-4c5b-b112-36a304b66dad')) ===
         'https://login.microsoftonline.com/' +
         '9188040d-6c67-4c5b-b112-36a304b66dad/v2.0' &&
         consumer.issuersFor(multi,
           tokenFor('72f988bf-86f1-41af-91ab-2d7cd011db47')) ===
         'urn:sts:federation:tenant-not-allowed' &&
         consumer.issuersFor(multi, 'not.a.token') ===
         'urn:sts:federation:tenant-not-allowed',
         'C5. microsoft-any: the issuer of an allowed tenant, and one no ' +
         'token can carry for any other');

    // Fill in the three relationships against the fake providers.
    const point = function (id, who, extra) {
      return inSp(function () {
        const set = function (field, value) {
          return federation.update(id, { field: field, value: value });
        };
        const out = [];
        out.push(set('fedSsoUrl', pbase + '/' + who + '/authorize'));
        out.push(set('fedTokenUrl', pbase + '/' + who + '/token'));
        out.push(set('fedClientId', 'client-' + who));
        out.push(set('fedClientSecret', 'secret-' + who));
        Object.keys(extra || {}).forEach(function (f) {
          out.push(set(f, extra[f]));
        });
        out.push(set('fedEnabled', 'TRUE'));
        return out;
      });
    };
    const pointed = [
      point('cp-discord', 'discord',
            { fedUserinfoUrl: pbase + '/discord/users/@me' }),
      point('cp-github', 'github',
            { fedUserinfoUrl: pbase + '/github/user',
              fedEmailsUrl: pbase + '/github/user/emails' }),
      point('cp-google', 'google',
            { fedJwksUri: pbase + '/google/jwks', fedPeer: googleIssuer })
    ];
    note(pointed.every(function (list) {
      return list.every(function (one) { return one.ok; });
    }), 'A11. the three relationships configured and enabled',
         JSON.stringify(pointed.map(function (list) {
           return list.filter(function (one) { return !one.ok; })
             .map(function (one) { return one.errors; });
         })));

    // ===== D. DISCORD =======================================================
    people.discord = { profile: { id: '80351110224678912',
      username: 'nelly', global_name: 'Nelly', email: 'nelly@example.com',
      verified: true, locale: 'en-US', mfa_enabled: true } };
    const dr = await signIn('cp-discord');
    const dName = inSp(function () {
      return links.provisionedName('cp-discord', '80351110224678912');
    });
    const dEntry = entryOf(dName);
    note(dr.status === 200 && !!dEntry,
         'D1. a Discord sign-in creates the namespaced entry ' + dName,
         dr.status + ' ' + dr.text.slice(0, 300));
    note(attr(dEntry, 'mail')[0] === 'nelly@example.com' &&
         attr(dEntry, 'cn')[0] === 'Nelly',
         'D2. the profile\'s claims reached the entry',
         JSON.stringify(dEntry && dEntry.attributes));
    const dBasic = (seen.discord[0] || {}).authorization || '';
    note(/^Basic /.test(dBasic) &&
         Buffer.from(dBasic.slice(6), 'base64').toString() ===
           'client-discord:secret-discord' &&
         !(seen.discord[0] || { form: {} }).form.client_secret,
         'D3. client_secret_basic reached Discord\'s token endpoint', dBasic);
    const dLinks = attr(dEntry, 'federationLink');
    note(dLinks.some(function (one) {
      return one === 'cp-discord https://discord.com 80351110224678912';
    }), 'D4. the link is the relationship, the issuer and the id',
         dLinks.join(' | '));

    // ===== E. GITHUB ========================================================
    people.github = { profile: { id: 583231, login: 'octocat',
      name: 'The Octocat', email: 'public-octo@example.com',
      avatar_url: 'https://avatars.example/583231',
      html_url: 'https://github.com/octocat', company: 'GitHub' },
      emails: [{ email: 'old@example.com', primary: false, verified: true },
               { email: 'octo@example.com', primary: true, verified: true }] };
    const gr = await signIn('cp-github');
    const gName = inSp(function () {
      return links.provisionedName('cp-github', '583231');
    });
    const gEntry = entryOf(gName);
    note(gr.status === 200 && attr(gEntry, 'mail')[0] === 'octo@example.com',
         'E1. GitHub: the primary verified address, not /user\'s public one',
         gr.status + ' ' + JSON.stringify(gEntry && gEntry.attributes.mail));
    const gForm = (seen.github[0] || { form: {} }).form;
    note(gForm.client_secret === 'secret-github' &&
         gForm.client_id === 'client-github' &&
         !(seen.github[0] || {}).authorization,
         'E2. client_secret_post: the secret in the body, no Basic header',
         JSON.stringify(Object.keys(gForm)));
    note(!!gForm.code_verifier,
         'E3. PKCE is sent to a plain OAuth 2.0 provider too');
    people.github = { profile: { id: 99, login: 'nomail',
                                 email: 'public-nomail@example.com' },
                      emails: [] };
    failEmails.on = true;
    const gr2 = await signIn('cp-github');
    failEmails.on = false;
    const g2 = entryOf(inSp(function () {
      return links.provisionedName('cp-github', '99');
    }));
    // Development mode invents a persona's address for a person who
    // arrives with none (`mode.inventsClaimValues()`), so what is held is
    // that the PUBLIC address /user carried is never the one written.
    note(gr2.status === 200 && !!g2 &&
         attr(g2, 'mail').indexOf('public-nomail@example.com') < 0,
         'E4. /user/emails failing costs the address, never the sign-in, ' +
         'and /user\'s public address is not used instead',
         gr2.status + ' ' + JSON.stringify(g2 && g2.attributes.mail));
    // The service provider's audit log: a realm's rows are its own.
    const spRows = inSp(function () {
      return audit.list();
    });
    note(spRows.some(function (row) {
      return row.errorCode === 'STS-FED-0176';
    }), 'E5. and the failure is audited STS-FED-0176 in the realm',
         JSON.stringify(spRows.filter(function (row) {
           return String(row.target || '') === 'cp-github';
         }).slice(0, 3)));

    // ===== F. GOOGLE ========================================================
    people.google = { claims: { sub: '110169484474386276334',
      email: 'gina@example.com', email_verified: true, name: 'Gina' } };
    const fr = await signIn('cp-google');
    const fEntry = entryOf(inSp(function () {
      return links.provisionedName('cp-google', '110169484474386276334');
    }));
    note(fr.status === 200 && attr(fEntry, 'mail')[0] === 'gina@example.com',
         'F1. a Google sign-in on a verified ID Token',
         fr.status + ' ' + fr.text.slice(0, 300));
    people.google = { iss: 'accounts.google.com',
      claims: { sub: '2', email: 'b@example.com', email_verified: true } };
    const aliasRefused = await signIn('cp-google');
    note(aliasRefused.status !== 200,
         'F2. the bare-host alias is Google\'s, so it is NOT accepted for a ' +
         'peer that is not accounts.google.com', aliasRefused.status);
    people.google = { iss: 'https://evil.example',
      claims: { sub: '3', email: 'c@example.com' } };
    const evil = await signIn('cp-google');
    note(evil.status === 401,
         'F3. an ID Token naming another issuer is refused', evil.status);
    note(JSON.stringify(consumer.issuersFor({ fedProvider: 'google',
      fedPeer: 'https://accounts.google.com' })) ===
         JSON.stringify(['https://accounts.google.com',
                         'accounts.google.com']),
         'F4. issuersFor(): Google\'s two spellings, and only for Google');

    // ===== J. X AND TIKTOK: A NESTED PROFILE, AND THE TOKEN RESPONSE =======
    const pointedMore = inSp(function () {
      const out = [];
      ['x', 'tiktok'].forEach(function (who) {
        out.push(federation.create({ fedId: 'cp-' + who, fedProvider: who }));
        const set = function (field, value) {
          out.push(federation.update('cp-' + who, { field: field,
                                                    value: value }));
        };
        set('fedSsoUrl', pbase + '/' + who + '/authorize');
        set('fedTokenUrl', pbase + '/' + who + '/token');
        set('fedUserinfoUrl', pbase + '/' + who +
            (who === 'x' ? '/2/users/me' : '/v2/user/info'));
        set('fedClientId', 'client-' + who);
        set('fedClientSecret', 'secret-' + who);
        set('fedEnabled', 'TRUE');
      });
      return out;
    });
    note(pointedMore.every(function (one) { return one.ok; }),
         'J1. X and TikTok relationships made from their profiles',
         JSON.stringify(pointedMore.filter(function (one) {
           return !one.ok;
         }).map(function (one) { return one.errors; })));
    people.x = { profile: { data: { id: '2244994945', username: 'xdev',
                                    name: 'X Dev' } } };
    const xr = await signIn('cp-x');
    const xEntry = entryOf(inSp(function () {
      return links.provisionedName('cp-x', '2244994945');
    }));
    note(xr.status === 200 && attr(xEntry, 'cn')[0] === 'X Dev',
         'J2. X: the subject and the name come out of data.*',
         xr.status + ' ' + JSON.stringify(xEntry && xEntry.attributes.cn));
    people.tiktok = { openId: '-000OQ1lmxtaeNpsWw8MQXpDdSkM',
      profile: { data: { user: { display_name: 'Tik Tok',
                                 open_id: '-000OQ1lmxtaeNpsWw8MQXpDdSkM' } },
                 error: { code: 'ok' } } };
    const tr = await signIn('cp-tiktok');
    const tEntry = entryOf(inSp(function () {
      return links.provisionedName('cp-tiktok',
                                   '-000OQ1lmxtaeNpsWw8MQXpDdSkM');
    }));
    note(tr.status === 200 && !!tEntry,
         'J3. TikTok: the person is the token response\'s open_id',
         tr.status + ' ' + tr.text.slice(0, 200));
    const tAuth = authorizeSeen.tiktok[0] || {};
    const tToken = (seen.tiktok[0] || { form: {} }).form;
    note(tAuth.client_key === 'client-tiktok' && !tAuth.client_id &&
         tToken.client_key === 'client-tiktok' &&
         tToken.client_secret === 'secret-tiktok' && !tToken.client_id,
         'J4. the client-key adapter: client_key in the authorization and ' +
         'token requests, and no client_id', JSON.stringify([tAuth,
                                                              tToken]));
    const twitch = inSp(function () {
      return federation.create({ fedId: 'cp-twitch', fedProvider: 'twitch' });
    });
    note(twitch.ok && JSON.stringify((twitch.relationship || {})
      .fedAuthorizeParams).indexOf('claims=') >= 0,
         'J5. Twitch is given its claims request as an extra authorization ' +
         'parameter', JSON.stringify((twitch.relationship || {})
           .fedAuthorizeParams));
    const reserved = inSp(function () {
      return federation.update('cp-twitch', { field: 'fedAuthorizeParams',
                                              value: 'state=forged',
                                              mode: 'add' });
    });
    note(!reserved.ok, 'J6. fedAuthorizeParams refuses a parameter this ' +
         'service sets itself', JSON.stringify(reserved.errors));

    // ===== G. COLLISION =====================================================
    // A local person named and addressed exactly as the provider's person.
    const local = inSp(function () {
      ldap.createUser('nelly2', { invent: false, attributes: {
        givenName: 'Local', sn: 'Nelly', cn: 'Local Nelly',
        mail: 'nelly2@example.com' } });
      return ldap.existingUserEntry('nelly2');
    });
    if (local) {
      people.discord = { profile: { id: '5555', username: 'nelly2',
        global_name: 'Imposter', email: 'nelly2@example.com',
        verified: true } };
      await signIn('cp-discord');
      const after = entryOf('nelly2');
      note(attr(after, 'cn')[0] === 'Local Nelly' &&
           !attr(after, 'federationLink').length,
           'G1. a provider\'s person matching a local name and address ' +
           'never lands on the local entry',
           JSON.stringify(after && after.attributes));
      note(!!entryOf(inSp(function () {
        return links.provisionedName('cp-discord', '5555');
      })), 'G2. they get an entry of their own');
    } else {
      note(false, 'G1. a local person could be created for the collision ' +
           'case', 'ldap.createUser made nobody');
    }
    const anyExisting = inSp(function () {
      return federation.update('cp-discord', { field: 'fedSubjectPolicy',
                                               value: 'any-existing' });
    });
    note(!anyExisting.ok, 'G3. any-existing refused on a consumer ' +
         'relationship', JSON.stringify(anyExisting.errors));

    // ===== H. MFA AND THE RISK INPUT ========================================
    people.google = { claims: { sub: '4', email: 'm@example.com',
      email_verified: true, amr: ['mfa', 'hwk'], acr: 'mfa' } };
    const assessed = [];
    const started = [];
    const realAssess = authn.assessSignIn;
    const realStart = authn.startSession;
    authn.assessSignIn = function (req, username, via, detail) {
      assessed.push(detail || {});
      return realAssess.apply(this, arguments);
    };
    authn.startSession = function (res, username, amr, acr) {
      started.push({ amr: amr, acr: acr });
      return realStart.apply(this, arguments);
    };
    const hr = await signIn('cp-google');
    authn.assessSignIn = realAssess;
    authn.startSession = realStart;
    const hEntry = entryOf(inSp(function () {
      return links.provisionedName('cp-google', '4');
    }));
    note(hr.status === 200 && !!hEntry, 'H1. a Google sign-in claiming MFA',
         hr.status);
    note(assessed.some(function (one) {
      return one.credential && one.credential.kind === 'federation' &&
             one.credential.id === 'cp-google' &&
             one.credential.relationship === 'cp-google';
    }), 'H2. the risk input names the relationship as the credential',
         JSON.stringify(assessed.map(function (one) {
           return one.credential;
         })));
    const last = started[started.length - 1] || {};
    note(last.acr === '' && JSON.stringify(last.amr) === '["federated"]',
         'H3. the provider\'s amr and acr satisfy nothing: the session is ' +
         'federated, and no more', JSON.stringify(last));
    note(attr(hEntry, 'mail')[0] === 'm@example.com',
         'H4. and the sign-in itself stands');

    // ===== I. RISK: THE SIGNALS AND THE STEP-UP =============================
    // A sign-in through the federation door, following a second-factor step
    // where one is asked for: the step's page opened as the surface opens
    // it, answered with a one-time code, and its redirect followed.
    async function signInStepping(rel, secret) {
      jar = {};
      const trail = { steps: 0 };
      let r = await request('GET', '/realm/' + SP + '/federation/login/' +
                                   rel);
      for (let hop = 0; hop < 16; hop += 1) {
        const at = String(r.headers.location || r.location || '');
        if (/\/authn\/totp\?/.test(at)) {
          trail.steps += 1;
          const opened = await authnScreen.openStep({ port: port, jar: jar,
            userAgent: UA,
            at: new URL(at, base).pathname + new URL(at, base).search });
          if (!secret) {
            return { r: opened, trail: trail };
          }
          r = await authnScreen.stepAct({ port: port, jar: jar,
            userAgent: UA, opened: opened, op: 'totp',
            body: { code: totp.codeAt(secret) } });
          continue;
        }
        if (at && ((r.status >= 300 && r.status < 400) ||
                   r.next === 'redirect')) {
          r = await request('GET', new URL(at, base).toString());
          continue;
        }
        return { r: r, trail: trail };
      }
      return { r: r, trail: trail };
    }
    const assessments = [];
    authn.assessSignIn = function () {
      const p = realAssess.apply(this, arguments);
      return Promise.resolve(p).then(function (one) {
        assessments.push(one);
        return one;
      });
    };
    const signalsOf = function (one) {
      return JSON.stringify(one || {});
    };
    // I1. NETWORK-SIGNUPS: several accounts were created from this loopback
    // network above; a threshold of two puts the signal on the next one.
    inSp(function () {
      config.setOverride('risk.networkSignupThreshold', '2');
    });
    people.discord = { profile: { id: '6001', username: 'six',
      email: 'six@example.com', verified: true } };
    assessments.length = 0;
    await signIn('cp-discord');
    note(assessments.some(function (one) {
      return /network-signups/.test(signalsOf(one));
    }), 'I1. network-signups: the accounts this network created count',
         signalsOf(assessments[0]).slice(0, 600));
    inSp(function () {
      config.setOverride('risk.networkSignupThreshold', '1000000');
    });
    // An existing person linked to two relationships, holding a TOTP here,
    // and one holding nothing.
    const PAT = 'fcp-pat';
    const QUINN = 'fcp-quinn';
    const secret = inSp(function () {
      ldap.createUser(PAT, { invent: false, attributes: {
        givenName: 'Pat', sn: 'Local', mail: 'pat@sp.example' } });
      ldap.createUser(QUINN, { invent: false, attributes: {
        givenName: 'Quinn', sn: 'Local', mail: 'quinn@sp.example' } });
      federation.writeFederationLink(PAT,
        'cp-discord https://discord.com 7001', true, {});
      federation.writeFederationLink(PAT,
        'cp-github https://github.com 7002', true, {});
      federation.writeFederationLink(QUINN,
        'cp-discord https://discord.com 7003', true, {});
      const begun = credentials.beginTotpEnrolment(PAT, {});
      const confirmed = credentials.confirmTotpEnrolment(PAT,
        totp.codeAt(begun.secret, Date.now() - 30000));
      return confirmed && confirmed.ok ? begun.secret : '';
    });
    note(!!secret, 'I2. a linked local person holding a TOTP');
    inSp(function () {
      config.setOverride('risk.minimumHistory', '1');
    });
    people.discord = { profile: { id: '7001', username: 'pat',
      email: 'pat@example.com', verified: true } };
    const patFirst = await signIn('cp-discord');
    people.discord = { profile: { id: '7003', username: 'quinn',
      email: 'quinn@example.com', verified: true } };
    await signIn('cp-discord');
    people.github = { profile: { id: 7002, login: 'pat' },
      emails: [{ email: 'pat@example.com', primary: true, verified: true }] };
    assessments.length = 0;
    const patGithub = await signIn('cp-github');
    note(patFirst.status === 200 && patGithub.status === 200 &&
         assessments.some(function (one) {
           return /new-federated-provider/.test(signalsOf(one));
         }),
         'I3. new-federated-provider: a person\'s first sign-in through a ' +
         'relationship they never used', signalsOf(assessments[0])
           .slice(0, 600));
    // I4. A STEP-UP ON RISK: every scored sign-in MEDIUM, and enforced.
    inSp(function () {
      config.setOverride('risk.enforceInDevelopment', 'true');
      config.setOverride('risk.mediumScorePercent', '1');
      config.setOverride('risk.highScorePercent', '1000000');
    });
    people.discord = { profile: { id: '7001', username: 'pat',
      email: 'pat@example.com', verified: true } };
    started.length = 0;
    authn.startSession = function (res, username, amr, acr) {
      started.push({ username: username, amr: amr, acr: acr });
      return realStart.apply(this, arguments);
    };
    const stepped = await signInStepping('cp-discord', secret);
    const patSession = started.filter(function (one) {
      return one.username === PAT && acrIsMfa(one);
    });
    function acrIsMfa(one) {
      return one.acr === 'mfa';
    }
    note(stepped.trail.steps === 1 && stepped.r.status === 200,
         'I4. a MEDIUM federated sign-in is stepped up with a one-time code ' +
         'held here, and finishes', stepped.trail.steps + ' ' +
         stepped.r.status + ' ' + String(stepped.r.text || '').slice(0, 200));
    note(patSession.some(function (one) {
      return JSON.stringify(one.amr) === '["federated","otp"]';
    }), 'I5. the federated session is federated + otp, acr mfa',
         JSON.stringify(started));
    people.discord = { profile: { id: '7003', username: 'quinn',
      email: 'quinn@example.com', verified: true } };
    const refused = await signInStepping('cp-discord', '');
    note(refused.r.status === 403 && refused.trail.steps === 0,
         'I6. a person holding no second factor here is refused, never ' +
         'offered enrolment or a password', refused.r.status + ' ' +
         refused.trail.steps);
    // I7. A NEWCOMER ON EVIDENCE: with network-signups' threshold met and
    // risk enforced, a sign-in that would CREATE somebody is refused —
    // and nobody is created. A newcomer is assessed under a provisional
    // subject, since there is no entry to assess them as.
    inSp(function () {
      config.setOverride('risk.networkSignupThreshold', '2');
    });
    people.discord = { profile: { id: '8008', username: 'bot',
      email: 'bot@example.com', verified: true } };
    const botTry = await signIn('cp-discord');
    const botName = inSp(function () {
      return links.provisionedName('cp-discord', '8008');
    });
    note(botTry.status === 403 && !entryOf(botName),
         'I7. a newcomer on evidence (network-signups), risk enforced: ' +
         'refused, and nobody created', botTry.status + ' ' +
         JSON.stringify(entryOf(botName) && entryOf(botName).dn));
    authn.startSession = realStart;
    authn.assessSignIn = realAssess;
    inSp(function () {
      ['risk.enforceInDevelopment', 'risk.mediumScorePercent',
       'risk.highScorePercent', 'risk.minimumHistory',
       'risk.networkSignupThreshold'].forEach(function (k) {
        config.clearOverride(k);
      });
    });

    // ===== K. CONNECTED ACCOUNTS, FROM THE PORTAL ===========================
    const portalSignin = require(ROOT + '/tests/vendored/portal_signin');
    const RAE = 'fcp-rae';
    const RAE_PASSWORD = 'Fcp-Rae-' + process.pid + '-Passw0rd!';
    inSp(function () {
      ldap.createUser(RAE, { invent: false, attributes: {
        givenName: 'Rae', sn: 'Local', mail: 'rae@sp.example' } });
      credentials.setPassword(RAE, RAE_PASSWORD);
    });
    const spBase = base + '/realm/' + SP;
    const rae = await portalSignin.signInToThePortal(spBase, RAE, null,
                                                     { password: RAE_PASSWORD });
    note(!!rae.token, 'K1. a local person signs in to the portal');
    // A connect, followed through the provider and back.
    async function connect(id, withCookie) {
      const asked = await rae.api('POST', '/account-api/connected-accounts',
                                  { action: 'connect', id: id });
      const location = asked.json && asked.json.location;
      const set = asked.headers && asked.headers.getSetCookie
        ? asked.headers.getSetCookie() : [];
      jar = {};
      if (withCookie) {
        set.forEach(function (line) {
          const pair = String(line).split(';')[0];
          const at = pair.indexOf('=');
          if (at > 0) {
            jar[pair.slice(0, at)] = pair.slice(at + 1);
          }
        });
      }
      if (!location) {
        return { asked: asked, back: '' };
      }
      let r = await request('GET', location);
      for (let hop = 0; hop < 6; hop += 1) {
        const at = String(r.headers.location || '');
        if (/\/portal\/connected-accounts/.test(at)) {
          return { asked: asked, back: at };
        }
        if (!(r.status >= 300 && r.status < 400 && at)) {
          break;
        }
        r = await request('GET', new URL(at, base).toString());
      }
      return { asked: asked, back: '', last: r };
    }
    people.discord = { profile: { id: '9100', username: 'rae-at-discord',
      email: 'rae@discord.example', verified: true } };
    const linked = await connect('cp-discord', true);
    const raeEntry = entryOf(RAE);
    note(/done=/.test(linked.back) && attr(raeEntry, 'federationLink')
      .indexOf('cp-discord https://discord.com 9100') >= 0,
         'K2. Connect: the provider\'s subject becomes a link on the ' +
         'person\'s own entry, and the portal is told done', linked.back +
         ' ' + JSON.stringify(attr(raeEntry, 'federationLink')) + ' ' +
         JSON.stringify(linked.asked && linked.asked.json));
    note(attr(raeEntry, 'mail')[0] === 'rae@sp.example',
         'K3. connecting writes nothing else onto the entry');
    started.length = 0;
    authn.startSession = function (res, username, amr, acr) {
      started.push({ username: username, amr: amr, acr: acr });
      return realStart.apply(this, arguments);
    };
    await signIn('cp-discord');
    authn.startSession = realStart;
    note(started.some(function (one) {
      return String(one.username).toLowerCase() === RAE;
    }), 'K4. a sign-in through the connected provider is the person',
         JSON.stringify(started));
    const viewed = await rae.api('GET', '/account-api/connected-accounts');
    note(viewed.status === 200 && (viewed.json.providers || []).some(
      function (p) { return p.id === 'cp-discord' && p.connected; }),
         'K5. the page lists the provider as connected',
         JSON.stringify(viewed.json));
    people.discord = { profile: { id: '9200', username: 'rae-other',
      email: 'other@discord.example', verified: true } };
    const csrf = await connect('cp-github', false);
    note(!/done=/.test(csrf.back) &&
         !attr(entryOf(RAE), 'federationLink').some(function (v) {
           return /^cp-github /.test(v);
         }),
         'K6. a connect finished in a browser without its binding cookie ' +
         'links nothing (the account-linking CSRF)', csrf.back);
    people.discord = { profile: { id: '80351110224678912', username: 'n',
      email: 'n@example.com', verified: true } };
    const taken = await connect('cp-discord', true);
    note(/problem=/.test(taken.back),
         'K7. a provider account already connected to somebody else is ' +
         'refused', taken.back);
    const dropped = await rae.api('POST', '/account-api/connected-accounts',
                                  { action: 'disconnect', id: 'cp-discord' });
    note(dropped.status === 200 && !attr(entryOf(RAE), 'federationLink')
      .some(function (v) { return /^cp-discord /.test(v); }),
         'K8. Disconnect removes the connection', dropped.status + ' ' +
         JSON.stringify(attr(entryOf(RAE), 'federationLink')));

    // ===== L. SIGN IN WITH APPLE ============================================
    const appleMade = inSp(function () {
      const out = [federation.create({ fedId: 'cp-apple',
                                       fedProvider: 'apple' })];
      const set = function (field, value) {
        out.push(federation.update('cp-apple', { field: field,
                                                 value: value }));
      };
      set('fedSsoUrl', pbase + '/apple/authorize');
      set('fedTokenUrl', pbase + '/apple/token');
      set('fedJwksUri', pbase + '/apple/jwks');
      set('fedPeer', pbase + '/apple');
      set('fedClientId', 'com.example.web');
      set('fedTeamId', 'TEAM123456');
      set('fedKeyId', 'KEY1234567');
      set('fedClientSigningKey', appleKey.privateKey.export(
        { format: 'pem', type: 'pkcs8' }).toString());
      set('fedEnabled', 'TRUE');
      return { out: out, record: federation.get('cp-apple') };
    });
    note(appleMade.out.every(function (one) { return one.ok; }) &&
         appleMade.record.fedResponseMode === 'form_post',
         'L1. an Apple relationship: form_post, its team id, key id and key',
         JSON.stringify(appleMade.out.filter(function (one) {
           return !one.ok;
         }).map(function (one) { return one.errors; })));
    // The browser's part of form_post: the provider's answer POSTed to the
    // assertion consumer service.
    async function appleSignIn() {
      jar = {};
      let r = await request('GET', '/realm/' + SP +
                                   '/federation/login/cp-apple');
      const at = String(r.headers.location || '');
      const answered = await request('GET', at);
      let posted = null;
      try {
        posted = JSON.parse(answered.text);
      } catch (e) {
        posted = null;
      }
      if (!posted || !posted.action) {
        return { r: answered, posted: posted };
      }
      r = await request('POST', posted.action, { form: posted.fields });
      for (let hop = 0; hop < 6; hop += 1) {
        const next = String(r.headers.location || '');
        if (r.status >= 300 && r.status < 400 && next) {
          r = await request('GET', new URL(next, base).toString());
          continue;
        }
        break;
      }
      return { r: r, posted: posted };
    }
    people.apple = { claims: { sub: '001234.abcdef0123456789.0123',
      email: 'x7q2@privaterelay.appleid.com', email_verified: 'true',
      is_private_email: 'true' },
      user: JSON.stringify({ name: { firstName: 'Ada', lastName: 'Byron' },
                             email: 'x7q2@privaterelay.appleid.com' }) };
    const ar = await appleSignIn();
    const aName = inSp(function () {
      return links.provisionedName('cp-apple',
                                   '001234.abcdef0123456789.0123');
    });
    const aEntry = entryOf(aName);
    note(ar.posted && ar.posted.mode === 'form_post' &&
         ar.r.status === 200 && !!aEntry,
         'L2. Apple: the code by form_post, redeemed with a client secret ' +
         'this service signed', ar.r.status + ' ' +
         JSON.stringify(ar.posted && ar.posted.mode) + ' ' +
         String(ar.r.text || '').slice(0, 200));
    note(attr(aEntry, 'givenName')[0] === 'Ada' &&
         attr(aEntry, 'sn')[0] === 'Byron' &&
         attr(aEntry, 'mail')[0] === 'x7q2@privaterelay.appleid.com',
         'L3. the name from the one-time user field, the relay address from ' +
         'the ID Token', JSON.stringify(aEntry && aEntry.attributes));
    const view = inSp(function () {
      const views = require(ROOT + '/admin-core/admin_views');
      return views.federationJson({ query: { relationship: 'cp-apple' } });
    });
    note(view && view.fields && view.fields.fedClientSigningKey ===
         '(set — not returned)',
         'L4. the signing key is never returned by the console\'s view',
         JSON.stringify(view && view.fields &&
                        view.fields.fedClientSigningKey));
    // The server-to-server notification: consent revoked, then replayed.
    const notice = function (jti, type) {
      return jwt.sign({ iss: pbase + '/apple', aud: 'com.example.web',
        jti: jti, events: JSON.stringify({ type: type,
          sub: '001234.abcdef0123456789.0123',
          event_time: Date.now() }) },
      signing.privateKey, { algorithm: 'RS256', expiresIn: 300,
                            keyid: 'fake-google-1' });
    };
    const revoked = await request('POST', '/realm/' + SP +
      '/federation/notifications/cp-apple',
      { form: { payload: notice('n-1', 'consent-revoked') } });
    note(revoked.status === 200 && !attr(entryOf(aName),
                                         'federationLink').length,
         'L5. consent-revoked removes the subject\'s link, and the entry ' +
         'stays', revoked.status + ' ' + JSON.stringify(entryOf(aName) &&
           entryOf(aName).attributes.federationlink));
    const replayed = await request('POST', '/realm/' + SP +
      '/federation/notifications/cp-apple',
      { form: { payload: notice('n-1', 'consent-revoked') } });
    const forged = await request('POST', '/realm/' + SP +
      '/federation/notifications/cp-apple',
      { form: { payload: jwt.sign({ iss: pbase + '/apple',
        aud: 'com.example.web', jti: 'n-2',
        events: JSON.stringify({ type: 'account-delete', sub: 'x' }) },
      'not-the-key', { algorithm: 'HS256' }) } });
    note(replayed.status === 400 && forged.status === 400,
         'L6. a replayed notification and one not signed by the provider ' +
         'are refused', replayed.status + ' ' + forged.status);

    // ===== M. A NOTIFICATION IN A SERVICE DEPLOYED AS CELLS (#727) =========
    // Two cells, this one `cac1`; the channel to the peer stubbed. The link
    // is put back first: L5 removed it.
    const cellsModule = require(ROOT + '/common/cells');
    const channelModule = require(ROOT + '/common/cell_channel');
    const sp = require(ROOT + '/federation/federation_sp');
    const swap = function (target, replacements) {
      const saved = {};
      Object.keys(replacements).forEach(function (k) {
        saved[k] = target[k];
        target[k] = replacements[k];
      });
      return function () {
        Object.keys(saved).forEach(function (k) {
          target[k] = saved[k];
        });
      };
    };
    const appleValue = 'cp-apple ' + pbase + '/apple ' +
                       '001234.abcdef0123456789.0123';
    const relink = function () {
      return inSp(function () {
        return federation.writeFederationLink(aName, appleValue, true, {});
      });
    };
    const calls = [];
    let peerAnswer = function () {
      return Promise.resolve({ people: 1, unlinked: 1 });
    };
    const restoreCells = swap(cellsModule, {
      isMulti: function () { return true; },
      id: function () { return 'cac1'; },
      peers: function () {
        return [{ id: 'usw2', url: 'https://usw2:8446' }];
      }
    });
    const restoreChannel = swap(channelModule, {
      call: function (cellId, name, body) {
        calls.push({ cellId: cellId, name: name, body: body });
        return peerAnswer();
      }
    });
    const notifyAt = '/realm/' + SP + '/federation/notifications/cp-apple';
    try {
      relink();
      const fanned = await request('POST', notifyAt,
        { form: { payload: notice('n-10', 'consent-revoked') } });
      const asked = calls[0] || {};
      note(fanned.status === 200 &&
           asked.name === 'federation-provider-notification' &&
           asked.cellId === 'usw2' && asked.body &&
           asked.body.realm === SP && asked.body.relationship === 'cp-apple' &&
           asked.body.type === 'consent-revoked' &&
           asked.body.sub === '001234.abcdef0123456789.0123' &&
           !attr(entryOf(aName), 'federationLink').length,
           'M1. a notification is applied here and fanned out to every ' +
           'peer, the relationship and the subject as data',
           fanned.status + ' ' + JSON.stringify(calls));
      relink();
      calls.length = 0;
      peerAnswer = function () {
        return Promise.reject(new Error('unreachable'));
      };
      const partial = await request('POST', notifyAt,
        { form: { payload: notice('n-11', 'consent-revoked') } });
      note(partial.status === 503,
           'M2. a peer that cannot be reached makes the answer 503',
           partial.status);
      relink();
      peerAnswer = function () {
        return Promise.resolve({ people: 0, unlinked: 0 });
      };
      const retried = await request('POST', notifyAt,
        { form: { payload: notice('n-11', 'consent-revoked') } });
      note(retried.status === 200 &&
           !attr(entryOf(aName), 'federationLink').length,
           'M3. and its claim was released: the provider\'s retry is ' +
           'accepted and applied', retried.status);
      const again = await request('POST', notifyAt,
        { form: { payload: notice('n-11', 'consent-revoked') } });
      note(again.status === 400,
           'M4. once accepted, the same notification is refused', again.status);
    } finally {
      restoreChannel();
      restoreCells();
    }
    // The peer's half, as the inter-cell operation calls it.
    relink();
    const peerHalf = sp.notificationForPeer({ realm: SP,
      relationship: 'cp-apple', type: 'account-delete',
      sub: '001234.abcdef0123456789.0123' }, 'usw2');
    note(peerHalf.people === 1 && peerHalf.unlinked === 1 &&
         !attr(entryOf(aName), 'federationLink').length && !!entryOf(aName),
         'M5. a peer removes the link it holds, and never the entry',
         JSON.stringify(peerHalf));
    relink();
    const recorded = sp.notificationForPeer({ realm: SP,
      relationship: 'cp-apple', type: 'email-disabled',
      sub: '001234.abcdef0123456789.0123' }, 'usw2');
    const elsewhere = sp.notificationForPeer({ realm: SP,
      relationship: 'cp-discord', type: 'account-delete',
      sub: '001234.abcdef0123456789.0123' }, 'usw2');
    note(recorded.people === 1 && recorded.unlinked === 0 &&
         elsewhere.people === 0 &&
         attr(entryOf(aName), 'federationLink').indexOf(appleValue) >= 0,
         'M6. email-disabled removes nothing, and a relationship that takes ' +
         'no notifications is not acted on', JSON.stringify([recorded,
                                                            elsewhere]));
    note(channelModule.opNames().indexOf('federation-provider-notification') >=
         0, 'M7. the inter-cell operation is registered');

    // ===== B. THE REALM SWITCH ==============================================
    inSp(function () {
      config.setOverride('federation.consumerProviders', 'false');
    });
    const offCreate = inSp(function () {
      return federation.create({ fedId: 'cp-off', fedProvider: 'google' });
    });
    note(!offCreate.ok, 'B1. off: a provider relationship cannot be created',
         JSON.stringify(offCreate.errors));
    const offLogin = await request('GET', '/realm/' + SP +
                                          '/federation/login/cp-discord');
    note(offLogin.status === 403,
         'B2. off: an existing provider relationship refuses at the login ' +
         'endpoint', offLogin.status);
    const offReady = inSp(function () {
      return federation.readinessOf(federation.get('cp-discord'));
    });
    note(!offReady.ready && offReady.missing.some(function (one) {
      return /federation\.consumerProviders/.test(one);
    }), 'B3. off: readiness names the switch, so every door that asks ' +
         'readiness refuses', offReady.missing.join(', '));
    const offOptions = inSp(function () {
      return federation.signInOptions();
    });
    note(!offOptions.some(function (one) {
      return one.category === 'consumer';
    }), 'B4. off: no consumer provider is offered at the sign-in screen');
    const ent = inSp(function () {
      const c = federation.create({ fedId: 'cp-enterprise',
        fedRole: 'service-provider', fedProtocol: 'oauth2' });
      const e = federation.update('cp-enterprise',
                                  { field: 'fedEnabled', value: 'TRUE' });
      return { c: c, e: e, cat: federation.categoryOf(
        federation.get('cp-enterprise')) };
    });
    note(ent.c.ok && ent.e.ok && ent.cat === 'enterprise',
         'B5. off: an enterprise relationship is created and enabled as ' +
         'always', JSON.stringify([ent.c.errors, ent.e.errors]));
    const offEnable = inSp(function () {
      federation.update('cp-github', { field: 'fedEnabled', value: 'FALSE' });
      return federation.update('cp-github', { field: 'fedEnabled',
                                              value: 'TRUE' });
    });
    note(!offEnable.ok, 'B6. off: a provider relationship cannot be enabled',
         JSON.stringify(offEnable.errors));
    const claimOnOidc = inSp(function () {
      return federation.update('cp-google', { field: 'fedSubjectClaim',
                                              value: 'id' });
    });
    const claimOnEnt = inSp(function () {
      return federation.update('cp-enterprise', { field: 'fedSubjectClaim',
                                                  value: 'data.id' });
    });
    note(!claimOnOidc.ok && claimOnEnt.ok,
         'B7. fedSubjectClaim: a plain OAuth 2.0 enterprise relationship ' +
         'only', JSON.stringify([claimOnOidc.errors, claimOnEnt.errors]));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child threw', e && e.stack);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and checks each of its findings.
 *
 * @param t - the test context
 */
function run(t) {
  log.debug("Entering run().");
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fcp-')),
                        'findings.json');
  const clean = {};
  Object.keys(process.env).forEach(function (k) {
    if (!/^(STS_|OAUTH2_|LDAP_|SAML_|KRB5_|ADMIN_|SCIM_)/.test(k)) {
      clean[k] = process.env[k];
    }
  });
  const child = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'],
    { env: Object.assign(clean, { LOG_LEVEL: 'fatal', FCP_ROOT: ROOT,
                                  FCP_OUT: out }),
      encoding: 'utf8', timeout: 300000, maxBuffer: 64 * 1024 * 1024 });
  let findings = [];
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.check(false, 'the child wrote its findings',
            String(child.stderr || '').slice(-2000));
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'federation_consumer_providers',
  describe: 'consumer and social providers (#565): Google, Discord and ' +
            'GitHub profiles written at creation and read at sign-in, ' +
            'each driven through a real federated sign-in against a ' +
            'provider-shaped server; the realm switch at every door; ' +
            'collisions landing on entries of their own',
  run: run
};
