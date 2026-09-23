'use strict';
//
// File: federation_subject_policy.js
//
// ===========================================================================
// WHICH PEOPLE A FEDERATION PARTNER MAY ASSERT (#109, 2026-09-22).
//
// Until #109 a service-provider-side relationship signed in whichever local
// entry had the NAME the partner asserted, and it wrote the partner's
// attributes onto that entry inside `authn.startSession()` BEFORE anything
// could refuse — so a partner whose signature verified could sign in `admin`
// and overwrite admin's `mail` on the way. OpenID Connect Core section 5.7
// makes `iss` + `sub` the only stable identifier a relying party may rely on,
// and SAML 2.0 Core section 8.3.7 LINKS a persistent NameID to a local account
// rather than matching one. rcbj's decisions on the issue:
//
//   * a person carries `federationLink` values, `<relationship> <issuer>
//     <subject>`, and a linked subject signs in the person it is linked to;
//   * `fedSubjectPolicy` decides what happens to an unlinked subject:
//       link-at-first-sign-in (default) — the person it names signs in HERE
//         first (password, and a second factor where held or required), and
//         only then is the link recorded and the partner's attributes written;
//       pre-linked — refused;
//       jit-namespaced — a NEW entry `<relationship>~<name>`, never an
//         existing person;
//       any-existing — the old name match, development only;
//   * group, domain and DN-pattern rules on top of every policy, and a console
//     administrator refused unless the relationship allows it — a link
//     included;
//   * links set and removed on the console, through /admin-api and through a
//     SCIM extension; an unlink ends the sessions that partner made.
//
// WHAT IS DRIVEN IS A REAL FEDERATED SIGN-IN, twice over — once with the
// service provider's realm in DEVELOPMENT mode and once in PRODUCT mode — in
// one process per mode: the DEFAULT realm is the OpenID Provider, a realm of
// this file's own is the service provider, and an OIDC relationship joins
// them (code flow, PKCE, the back channel, the ID Token verified against the
// partner's published keys, UserInfo). The linking sign-in is the SP realm's
// own sign-in screen, and the second factor is a real RFC 6238 code.
//
// WHY A CHILD PROCESS: it loads the whole protocol stack, serves it on a
// loopback port, creates realms and flips settings.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'federation_subject_policy', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.FSP_ROOT;
  const OUT = process.env.FSP_OUT;
  const MODE = process.env.FSP_MODE;
  const https = require('https');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: '[' + MODE + '] ' + what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const helpers = require(ROOT + '/common/helpers');
    const mode = require(ROOT + '/common/mode');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');
    const rbac = require(ROOT + '/admin-ui/admin_rbac');
    const authn = require(ROOT + '/authn/authn');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const views = require(ROOT + '/admin-core/admin_views');
    const federation = require(ROOT + '/federation/federation');
    const fedSp = require(ROOT + '/federation/federation_sp');

    // HTTPS UNDER A CA OF THIS CHILD'S OWN (#171). The relationship is to
    // this service's own OpenID Provider, and product mode refuses a plain
    // http back channel whatever federation.outboundAllowHttp says — so the
    // listener serves a certificate from a CA this child makes now (the
    // shared run-time CA helper, `tests/vendored/outbound_test_ca.js`), and
    // federation.outboundCaFile names the CA, which is how product reaches a
    // privately certified partner.
    const testCa = require(ROOT + '/tests/vendored/outbound_test_ca');
    const ca = await testCa.makeCa();
    const leaf = await testCa.listenerCertificate(ca, '127.0.0.1');
    const caPem = ca.certPem;
    const caFile = require('path').join(require('os').tmpdir(),
      'fsp-ca-' + process.pid + '.crt');
    require('fs').writeFileSync(caFile, caPem);
    config.setOverride('federation.outboundCaFile', caFile);
    const server = https.createServer({ key: leaf.key, cert: leaf.cert },
                                      app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'https://127.0.0.1:' + port;
    const SP = 'fsp' + (MODE === 'product' ? 'p' : 'd');
    const REL = 'fsp-oidc';
    const PASSWORD = 'Fed-Link-Passw0rd!2026';
    const IDP_PASSWORD = 'x';

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
      return new Promise(function (resolve) {
        const body = o.json !== undefined ? JSON.stringify(o.json)
          : (o.form ? new URLSearchParams(o.form).toString() : '');
        const headers = Object.assign({ cookie: cookieHeader() },
                                      o.headers || {});
        if (method !== 'GET') {
          headers['content-type'] = o.json !== undefined
            ? 'application/scim+json' : 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = https.request({ host: '127.0.0.1', port: port,
          ca: caPem,
          path: url.pathname + url.search, method: method, headers: headers },
        function (res) {
          [].concat(res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = String(line).split(';')[0];
            const i = pair.indexOf('=');
            if (i > 0) {
              const name = pair.slice(0, i).trim();
              const value = pair.slice(i + 1).trim();
              if (value) {
                jar[name] = value;
              } else {
                delete jar[name];
              }
            }
          });
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (e) {
              json = { parseError: e.message };
            }
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, json: json, path: url.pathname });
          });
        });
        req.end(body);
      });
    }
    function inSp(fn) {
      return realms.run(realms.get(SP), fn);
    }
    function entryOf(name) {
      return inSp(function () { return ldap.existingUserEntry(name); });
    }
    function attr(entry, name) {
      return entry ? (entry.attributes[name.toLowerCase()] || []) : [];
    }
    function hidden(text, name) {
      const m = new RegExp('name="' + name + '" value="([^"]*)"').exec(text);
      return m ? m[1] : '';
    }
    function codesSince(mark) {
      return inSp(function () { return audit.list(); })
        .slice(0, Math.max(0, inSp(function () {
          return audit.list();
        }).length - mark))
        .map(function (event) { return event.errorCode; })
        .filter(Boolean);
    }
    function auditCount() {
      return inSp(function () { return audit.list().length; });
    }
    function fedSessionsOf(name) {
      return inSp(function () {
        return authn.sessionsOf(name).filter(function (s) {
          return (s.events || []).some(function (e) {
            return e.authority && e.authority.kind === 'federation' &&
                   e.authority.id === REL;
          });
        });
      });
    }
    function wait(ms) {
      return new Promise(function (r) { setTimeout(r, ms); });
    }

    // THE WHOLE FEDERATED SIGN-IN, hop by hop. `idpUser` is who signs in at
    // the partner. At the SP realm's own sign-in screen — the linking screen —
    // `o.link` decides: 'password' posts `o.password`, 'cancel' cancels,
    // 'stop' returns the screen. A one-time code page is answered with
    // `o.totpSecret` when given. Returns the final answer and what happened.
    async function signIn(idpUser, o) {
      const opts = o || {};
      if (!opts.keepJar) {
        jar = {};
      }
      const trail = { linkScreens: 0, linkScreen: '', totp: 0, setup: 0 };
      let r = await request('GET', '/realm/' + SP + '/federation/login/' +
                                   REL);
      for (let hop = 0; hop < 30; hop += 1) {
        if (r.status >= 300 && r.status < 400 && r.headers.location) {
          r = await request('GET', r.headers.location);
          continue;
        }
        const authnId = hidden(r.text, 'authn_id');
        if (r.status === 200 && authnId &&
            r.path.indexOf('/realm/' + SP + '/') === 0) {
          trail.linkScreens += 1;
          trail.linkScreen = r.text;
          if (opts.link === 'stop' ||
              trail.linkScreens > (opts.linkAttempts || 1)) {
            return { r: r, trail: trail };
          }
          r = await request('POST', '/realm/' + SP + '/authn/login', {
            form: { authn_id: authnId, username: 'somebody-else-typed',
                    password: opts.password || PASSWORD,
                    action: opts.link === 'cancel' ? 'cancel' : 'login' } });
          continue;
        }
        if (r.status === 200 && authnId) {
          r = await request('POST', '/authn/login', { form: {
            authn_id: authnId, username: idpUser, password: IDP_PASSWORD,
            action: 'login' } });
          continue;
        }
        const mfaId = hidden(r.text, 'mfa_id');
        if (r.status === 200 && mfaId && /\/authn\/totp/.test(r.text)) {
          trail.totp += 1;
          if (!opts.totpSecret || trail.totp > 1) {
            return { r: r, trail: trail };
          }
          r = await request('POST', '/realm/' + SP + '/authn/totp', {
            form: { mfa_id: mfaId, code: totp.codeAt(opts.totpSecret) } });
          continue;
        }
        if (r.status === 200 && mfaId) {
          trail.setup += 1;
          return { r: r, trail: trail };
        }
        return { r: r, trail: trail };
      }
      return { r: r, trail: trail };
    }

    function setRel(field, value) {
      return inSp(function () {
        return federation.update(REL, { field: field, value: value });
      });
    }
    function addRel(field, value) {
      return inSp(function () {
        return federation.update(REL, { field: field, value: value,
                                        mode: 'add' });
      });
    }
    function removeRel(field, value) {
      return inSp(function () {
        return federation.update(REL, { field: field, value: value,
                                        mode: 'remove' });
      });
    }
    // A person in the SP realm, with a password that verifies in product.
    function makePerson(name, mail) {
      return inSp(function () {
        const made = ldap.createUser(name, { invent: false });
        const stored = ldap.existingUserEntry(name);
        if (stored && mail) {
          ldap.writePerson(stored.dn, Object.assign({}, stored.attributes,
                                                    { mail: [mail] }));
        }
        credentials.setPassword(name, PASSWORD, {});
        return made;
      });
    }
    // The partner's subject for somebody: the IdP realm's `sub` for them,
    // which is `urn:uuid:` of their entry there. Made on demand.
    function partnerSubjectOf(name) {
      return realms.run(realms.DEFAULT_REALM, function () {
        if (!ldap.existingUserEntry(name)) {
          ldap.createUser(name, { invent: true });
        }
        return helpers.subjectForName(name);
      });
    }
    function linkAs(name, subject, issuer) {
      return inSp(function () {
        return actions.usersAction({ action: 'federation-link', user: name,
                                     relationship: REL, subject: subject,
                                     issuer: issuer },
                                   { via: 'console', actor: 'fsp-test' });
      });
    }
    function unlinkAs(name, link) {
      return inSp(function () {
        return actions.usersAction({ action: 'federation-unlink', user: name,
                                     link: link },
                                   { via: 'api', actor: '' });
      });
    }

    // --- the partner, the realm and the relationship ------------------------
    config.setOverride('oauth2.consentRequired', 'false');
    config.setOverride('security.rateLimitPerAddress', '100000');
    config.setOverride('security.rateLimitPerIdentity', '100000');
    const discovery = await request('GET',
                                    '/.well-known/openid-configuration');
    const ISSUER = discovery.json.issuer;
    realms.create({ id: SP });
    inSp(function () {
      config.setOverride('security.rateLimitPerAddress', '100000');
      config.setOverride('security.rateLimitPerIdentity', '100000');
      if (MODE === 'product') {
        config.setOverride('global.mode', 'product');
      }
    });
    const created = inSp(function () {
      const made = federation.create({ fedId: REL,
        fedRole: 'service-provider', fedProtocol: 'oidc' });
      const set = function (field, value) {
        return federation.update(REL, { field: field, value: value });
      };
      set('fedPeer', ISSUER);
      set('fedSsoUrl', discovery.json.authorization_endpoint);
      set('fedTokenUrl', discovery.json.token_endpoint);
      set('fedUserinfoUrl', discovery.json.userinfo_endpoint);
      set('fedJwksUri', discovery.json.jwks_uri);
      set('fedClientId', 'fsp-client-' + MODE);
      set('fedScope', 'openid profile email');
      set('fedUsernameSource', 'preferred_username');
      const enabled = set('fedEnabled', 'TRUE');
      return { made: made, enabled: enabled, record: federation.get(REL) };
    });
    note(created.made.ok && created.enabled.ok,
         '0a. an OIDC relationship to this service\'s own OpenID Provider',
         JSON.stringify(created.enabled.errors || created.made.errors || []));
    note(created.record.fedSubjectPolicy === 'link-at-first-sign-in' &&
         created.record.fedMayAssertAdministrators === 'FALSE',
         '0b. a new relationship is created link-at-first-sign-in, with ' +
         'administrators refused',
         JSON.stringify({ p: created.record.fedSubjectPolicy,
                          a: created.record.fedMayAssertAdministrators }));
    note(inSp(function () { return mode.matchesFederatedNames(); }) ===
         (MODE !== 'product'),
         '0c. mode.matchesFederatedNames() is ' + (MODE !== 'product') +
         ' in ' + MODE + ' mode');

    // The pattern validator (unit): bounded and anchored.
    note(federation.subjectPatternProblem('uid=[^,]+,ou=users,.*') === '' &&
         /quantifier/.test(federation.subjectPatternProblem('(a+)+')) &&
         /backreference/.test(federation.subjectPatternProblem('(a)\\1')) &&
         /at most/.test(federation.subjectPatternProblem('x'.repeat(300))) &&
         federation.subjectPatternMatches('uid=a.*', 'uid=alice,ou=users') &&
         !federation.subjectPatternMatches('ou=users', 'uid=a,ou=users'),
         '0d. fedSubjectPattern refuses a nested quantifier, a backreference ' +
         'and a long pattern, and matches the WHOLE value');
    note(!setRel('fedSubjectPolicy', 'everybody').ok &&
         !setRel('fedSubjectPattern', '(x+)+').ok,
         '0e. a policy that is not one of the four, and a pattern that could ' +
         'backtrack, are refused at the relationship');

    // =======================================================================
    // 1. LINK AT FIRST SIGN-IN
    // =======================================================================
    const ALICE = 'fsp-alice-' + MODE;
    makePerson(ALICE, 'local-alice@sp.example');
    let mark = auditCount();
    let got = await signIn(ALICE, { link: 'stop' });
    let alice = entryOf(ALICE);
    note(got.trail.linkScreens === 1 && /readonly/.test(got.trail.linkScreen) &&
         got.trail.linkScreen.indexOf('value="' + ALICE + '"') >= 0 &&
         !/webauthn_only/.test(got.trail.linkScreen) &&
         !/kc-anonymous/.test(got.trail.linkScreen),
         '1a. an unlinked subject naming an existing person is sent to the ' +
         'SP realm\'s sign-in screen, the name fixed, no passwordless key ' +
         'and no anonymous session offered',
         got.r.status + ' ' + got.r.path);
    note(attr(alice, 'federationLink').length === 0 &&
         JSON.stringify(attr(alice, 'mail')) ===
           '["local-alice@sp.example"]' &&
         attr(alice, 'federationRelationship').length === 0 &&
         fedSessionsOf(ALICE).length === 0,
         '1b. NOTHING is written onto the entry before linking: no link, ' +
         'the local mail, no relationship recorded, no session',
         JSON.stringify(alice && alice.attributes));

    got = await signIn(ALICE, { link: 'password', password: 'invalid',
                                linkAttempts: 1 });
    alice = entryOf(ALICE);
    note(got.trail.linkScreens === 2 &&
         /Authentication failed/.test(got.r.text) &&
         attr(alice, 'federationLink').length === 0 &&
         JSON.stringify(attr(alice, 'mail')) === '["local-alice@sp.example"]',
         '1c. a WRONG PASSWORD at the linking screen links nothing and ' +
         'writes nothing', got.r.status + ' ' + got.r.text.slice(0, 120));
    if (MODE === 'product') {
      got = await signIn(ALICE, { link: 'password',
                                  password: 'Not-Her-Passw0rd!',
                                  linkAttempts: 1 });
      alice = entryOf(ALICE);
      note(got.trail.linkScreens === 2 &&
           attr(alice, 'federationLink').length === 0,
           '1c-ii. product verifies the password: a plausible wrong one ' +
           'links nothing either');
    }

    got = await signIn(ALICE, { link: 'password' });
    alice = entryOf(ALICE);
    const aliceSub = partnerSubjectOf(ALICE);
    const aliceLink = REL + ' ' + ISSUER + ' ' + aliceSub;
    note(got.r.status === 200 && /Signed in through/.test(got.r.text) &&
         got.trail.linkScreens === 1,
         '1d. the right password at the linking screen signs the person in',
         got.r.status + ' ' + got.r.text.replace(/\s+/g, ' ').slice(0, 200));
    note(JSON.stringify(attr(alice, 'federationLink')) ===
           JSON.stringify([aliceLink]),
         '1e. and records the PAIRED link <relationship> <iss> <sub>',
         JSON.stringify(attr(alice, 'federationLink')) + ' vs ' + aliceLink);
    note((attr(alice, 'mail')[0] || '') !== 'local-alice@sp.example' &&
         attr(alice, 'federationRelationship').indexOf(REL) >= 0 &&
         attr(alice, 'federationSubject').length === 0,
         '1f. only then are the partner\'s attributes written; ' +
         'federationSubject is gone', JSON.stringify(attr(alice, 'mail')));
    note(fedSessionsOf(ALICE).length >= 1,
         '1g. the session is the federated one');
    got = await signIn(ALICE, { link: 'stop' });
    note(got.r.status === 200 && got.trail.linkScreens === 0 &&
         /Signed in through/.test(got.r.text),
         '1h. the next sign-in finds the link and asks for nothing',
         got.r.status + ' screens=' + got.trail.linkScreens);

    // ANOTHER BROWSER: the linking screen's address handed to somebody else.
    // Account-linking CSRF — the victim's own password would link the
    // partner account that started the flow — so the step is bound to the
    // browser the partner's response arrived in.
    const VICTIM = 'fsp-victim-' + MODE;
    makePerson(VICTIM, 'local-victim@sp.example');
    got = await signIn(VICTIM, { link: 'stop' });
    const handedOver = hidden(got.trail.linkScreen, 'authn_id');
    jar = {};
    mark = auditCount();
    let other = await request('POST', '/realm/' + SP + '/authn/login', {
      form: { authn_id: handedOver, username: VICTIM, password: PASSWORD,
              action: 'login' } });
    for (let hop = 0; hop < 5 && other.status >= 300 && other.status < 400;
         hop += 1) {
      other = await request('GET', other.headers.location);
    }
    note(handedOver && other.status === 403 &&
         /different browser/.test(other.text) &&
         codesSince(mark).indexOf('STS-FED-0111') >= 0 &&
         attr(entryOf(VICTIM), 'federationLink').length === 0,
         '1i-0. the linking screen completed in ANOTHER browser is refused ' +
         '(STS-FED-0111) and links nothing', other.status + ' ' +
         JSON.stringify(codesSince(mark)));

    // CANCEL
    const CAROL = 'fsp-carol-' + MODE;
    makePerson(CAROL, 'local-carol@sp.example');
    mark = auditCount();
    got = await signIn(CAROL, { link: 'cancel' });
    const carol = entryOf(CAROL);
    note(got.r.status === 403 && /was not linked/.test(got.r.text) &&
         codesSince(mark).indexOf('STS-FED-0099') >= 0 &&
         attr(carol, 'federationLink').length === 0 &&
         JSON.stringify(attr(carol, 'mail')) === '["local-carol@sp.example"]',
         '1i. Cancel at the linking screen: refused 403 (STS-FED-0099), ' +
         'nothing linked or written',
         got.r.status + ' ' + JSON.stringify(codesSince(mark)));

    // A SECOND FACTOR HELD
    const DAVE = 'fsp-dave-' + MODE;
    makePerson(DAVE, 'local-dave@sp.example');
    const begun = inSp(function () {
      return credentials.beginTotpEnrolment(DAVE, {});
    });
    const confirmed = inSp(function () {
      return credentials.confirmTotpEnrolment(DAVE,
        totp.codeAt(begun.secret, Date.now() - 30000));
    });
    if (!confirmed.ok && MODE === 'product') {
      // A product-mode realm SEALS an authenticator's secret under the
      // key-encryption key, and an in-process stack has none — so the app
      // cannot be stored here. 1l below is the product half of the second
      // factor at the linking screen.
      note(/could not be encrypted/.test((confirmed.errors || []).join(' ')),
           '1j. (an authenticator app cannot be stored in process without a ' +
           'key-encryption key; the required-factor case below covers ' +
           'product)', JSON.stringify(confirmed.errors));
    } else {
      got = await signIn(DAVE, { link: 'password' });
      let dave = entryOf(DAVE);
      note(got.trail.totp === 1 && attr(dave, 'federationLink').length === 0,
           '1j. somebody holding a second factor is asked for it after the ' +
           'password, and nothing is linked while it is outstanding',
           'totp=' + got.trail.totp + ' ' + got.r.status + ' ' +
           JSON.stringify({ begun: begun.ok !== false && !!begun.secret,
                            errors: begun.errors,
                            confirmed: confirmed }).slice(0, 400));
      got = await signIn(DAVE, { link: 'password', totpSecret: begun.secret });
      dave = entryOf(DAVE);
      note(got.r.status === 200 && attr(dave, 'federationLink').length === 1,
           '1k. with the one-time code too, they are linked and signed in',
           got.r.status + ' ' + got.r.text.replace(/\s+/g, ' ').slice(0, 160));
    }

    // A SECOND FACTOR REQUIRED, and none held: the enrolment step.
    const EVE = 'fsp-eve-' + MODE;
    makePerson(EVE, 'local-eve@sp.example');
    inSp(function () {
      return actions.usersAction({ action: 'require-mfa', user: EVE },
                                 { via: 'console', actor: 'fsp-test' });
    });
    got = await signIn(EVE, { link: 'password' });
    note(got.trail.setup === 1 &&
         attr(entryOf(EVE), 'federationLink').length === 0,
         '1l. somebody a second factor is REQUIRED of meets the enrolment ' +
         'step, and nothing is linked', 'setup=' + got.trail.setup);

    // NOBODY OF THAT NAME: a namespaced entry, or nothing in product.
    const NEWBIE = 'fsp-new-' + MODE;
    got = await signIn(NEWBIE, {});
    const namespaced = entryOf(REL + '~' + NEWBIE);
    if (MODE === 'product') {
      note(got.r.status === 403 && /not been provisioned/.test(got.r.text) &&
           !namespaced && !entryOf(NEWBIE),
           '1m. a subject naming nobody: product creates nobody (403)',
           got.r.status);
    } else {
      note(got.r.status === 200 && namespaced && !entryOf(NEWBIE) &&
           attr(namespaced, 'federationLink').length === 1,
           '1m. a subject naming nobody gets a NAMESPACED entry, ' +
           REL + '~' + NEWBIE + ', linked at creation',
           got.r.status + ' ' + !!namespaced);
    }

    // =======================================================================
    // 2. ADMINISTRATORS
    // =======================================================================
    const ADMIN = 'fsp-admin-' + MODE;
    makePerson(ADMIN, 'local-admin@sp.example');
    const granted = rbac.grant(ADMIN, 'write',
                               { realm: SP, via: 'console', actor: 'test' });
    const adminSub = partnerSubjectOf(ADMIN);
    const adminLinked = linkAs(ADMIN, adminSub);
    mark = auditCount();
    got = await signIn(ADMIN, {});
    let admin = entryOf(ADMIN);
    note(granted.ok && adminLinked.ok && got.r.status === 403 &&
         /may not sign in an administrator/.test(got.r.text) &&
         codesSince(mark).indexOf('STS-FED-0093') >= 0 &&
         JSON.stringify(attr(admin, 'mail')) === '["local-admin@sp.example"]',
         '2a. a console administrator is refused (STS-FED-0093) even with a ' +
         'valid link, and their entry is not written',
         JSON.stringify({ g: granted.ok, l: adminLinked.ok, s: got.r.status,
                          c: codesSince(mark) }));
    setRel('fedMayAssertAdministrators', 'TRUE');
    got = await signIn(ADMIN, {});
    admin = entryOf(ADMIN);
    note(got.r.status === 200 &&
         (attr(admin, 'mail')[0] || '') !== 'local-admin@sp.example',
         '2b. with fedMayAssertAdministrators on, the same partner signs ' +
         'them in', got.r.status);
    setRel('fedMayAssertAdministrators', 'FALSE');

    // =======================================================================
    // 3. PRE-LINKED
    // =======================================================================
    setRel('fedSubjectPolicy', 'pre-linked');
    const FRANK = 'fsp-frank-' + MODE;
    makePerson(FRANK, 'local-frank@sp.example');
    mark = auditCount();
    got = await signIn(FRANK, {});
    note(got.r.status === 403 && got.trail.linkScreens === 0 &&
         codesSince(mark).indexOf('STS-FED-0091') >= 0 &&
         JSON.stringify(attr(entryOf(FRANK), 'mail')) ===
           '["local-frank@sp.example"]',
         '3a. pre-linked: an unlinked existing person is refused ' +
         '(STS-FED-0091) and nothing is written', got.r.status);
    const frankLinked = linkAs(FRANK, partnerSubjectOf(FRANK), '');
    got = await signIn(FRANK, {});
    note(frankLinked.ok && got.r.status === 200,
         '3b. linked by an administrator (issuer omitted: the ' +
         'relationship\'s fedPeer), they sign in',
         JSON.stringify(frankLinked.errors || '') + ' ' + got.r.status);
    const refusedLink = linkAs(CAROL, partnerSubjectOf(FRANK), '');
    note(!refusedLink.ok && /already carried by/.test(
           (refusedLink.errors || []).join(' ')),
         '3c. the same link on a SECOND person is refused (STS-FED-0107)',
         JSON.stringify(refusedLink.errors));
    const wrongIssuer = linkAs(CAROL, 'someone', 'https://elsewhere.example');
    note(!wrongIssuer.ok,
         '3d. a link naming an issuer the relationship does not verify is ' +
         'refused', JSON.stringify(wrongIssuer.errors));

    // =======================================================================
    // 4. JIT-NAMESPACED
    // =======================================================================
    setRel('fedSubjectPolicy', 'jit-namespaced');
    const GINA = 'fsp-gina-' + MODE;
    makePerson(GINA, 'local-gina@sp.example');
    got = await signIn(GINA, {});
    const ginaSpace = entryOf(REL + '~' + GINA);
    if (MODE === 'product') {
      note(got.r.status === 403 && !ginaSpace &&
           JSON.stringify(attr(entryOf(GINA), 'mail')) ===
             '["local-gina@sp.example"]',
           '4a. jit-namespaced never reaches the existing person; product ' +
           'creates no entry, so the sign-in is refused', got.r.status);
    } else {
      note(got.r.status === 200 && ginaSpace &&
           JSON.stringify(attr(entryOf(GINA), 'mail')) ===
             '["local-gina@sp.example"]' &&
           attr(entryOf(GINA), 'federationLink').length === 0,
           '4a. jit-namespaced gives the subject a NEW entry and never the ' +
           'existing person of that name', got.r.status);
    }

    // =======================================================================
    // 5. ANY-EXISTING (development only)
    // =======================================================================
    const HANK = 'fsp-hank-' + MODE;
    makePerson(HANK, 'local-hank@sp.example');
    if (MODE === 'product') {
      const refusedSet = setRel('fedSubjectPolicy', 'any-existing');
      note(!refusedSet.ok, '5a. product refuses setting any-existing ' +
           '(STS-FED-0095)', JSON.stringify(refusedSet.errors));
      // An entry written by `ldapmodify` while the realm was in development.
      inSp(function () { config.clearOverride('global.mode'); });
      setRel('fedSubjectPolicy', 'any-existing');
      inSp(function () { config.setOverride('global.mode', 'product'); });
      mark = auditCount();
      got = await signIn(HANK, {});
      note(got.r.status === 403 &&
           codesSince(mark).indexOf('STS-FED-0094') >= 0 &&
           JSON.stringify(attr(entryOf(HANK), 'mail')) ===
             '["local-hank@sp.example"]',
           '5b. and a relationship that carries it anyway is refused at the ' +
           'sign-in (STS-FED-0094), writing nothing', got.r.status);
    } else {
      setRel('fedSubjectPolicy', 'any-existing');
      got = await signIn(HANK, {});
      note(got.r.status === 200 && got.trail.linkScreens === 0 &&
           (attr(entryOf(HANK), 'mail')[0] || '') !==
             'local-hank@sp.example' &&
           attr(entryOf(HANK), 'federationLink').length === 1,
           '5a. any-existing, development only: the name match of old signs ' +
           'the person in directly (and records the link)', got.r.status);
    }

    // =======================================================================
    // 6. THE RULES ON TOP
    // =======================================================================
    setRel('fedSubjectPolicy', '');
    addRel('fedSubjectDomain', 'nowhere.example');
    mark = auditCount();
    got = await signIn(ALICE, {});
    note(got.r.status === 403 &&
         codesSince(mark).indexOf('STS-FED-0092') >= 0,
         '6a. a domain rule refuses even a LINKED person whose partner ' +
         'address is elsewhere (STS-FED-0092)', got.r.status);
    removeRel('fedSubjectDomain', 'nowhere.example');
    setRel('fedSubjectPattern', 'uid=nobody-matches,.*');
    got = await signIn(ALICE, {});
    note(got.r.status === 403 && /fedSubjectPattern/.test(got.r.text),
         '6b. a DN pattern the entry does not match refuses', got.r.status);
    setRel('fedSubjectPattern', 'uid=fsp-alice-[a-z]+,.*');
    got = await signIn(ALICE, {});
    note(got.r.status === 200, '6c. and one it matches admits',
         got.r.status);
    setRel('fedSubjectPattern', '');
    addRel('fedSubjectGroup', 'fsp-partners');
    got = await signIn(ALICE, {});
    note(got.r.status === 403 && /fedSubjectGroup/.test(got.r.text),
         '6d. a group rule refuses somebody outside the group', got.r.status);
    removeRel('fedSubjectGroup', 'fsp-partners');

    // =======================================================================
    // 7. UNLINKING ENDS THE PARTNER'S SESSIONS
    // =======================================================================
    got = await signIn(ALICE, {});
    const before = fedSessionsOf(ALICE).length;
    const unlinked = unlinkAs(ALICE, aliceLink);
    await wait(200);
    const after = fedSessionsOf(ALICE).length;
    note(before >= 1 && unlinked.ok && after === 0 &&
         attr(entryOf(ALICE), 'federationLink').length === 0,
         '7a. an unlink through the API action ends every session that ' +
         'partner signed the person in to', before + ' -> ' + after);
    got = await signIn(ALICE, { link: 'stop' });
    note(got.trail.linkScreens === 1,
         '7b. and the next sign-in is treated as unlinked again');

    // =======================================================================
    // 8. SCIM CARRIES THE LINK
    // =======================================================================
    const SCIMMER = 'fsp-scim-' + MODE;
    makePerson(SCIMMER, '');
    const scimAuth = { authorization: 'Basic ' +
      Buffer.from(SCIMMER + ':' + PASSWORD).toString('base64') };
    const IVY = 'fsp-ivy-' + MODE;
    const ivySub = partnerSubjectOf(IVY);
    const EXT = 'urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User';
    const scimBody = { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User',
                                 EXT],
                       userName: IVY };
    scimBody[EXT] = { federationLinks: [{ relationship: REL,
                                          subject: ivySub }] };
    jar = {};
    let scim = await request('POST', '/realm/' + SP + '/scim/v2/Users', {
      headers: scimAuth, json: scimBody });
    note(scim.status === 201 &&
         JSON.stringify(attr(entryOf(IVY), 'federationLink')) ===
           JSON.stringify([REL + ' ' + ISSUER + ' ' + ivySub]) &&
         JSON.stringify(scim.json[EXT + ':federationLinks'] ||
                        (scim.json[EXT] || {}).federationLinks || []) !==
           '[]',
         '8a. a person created over SCIM with the iya-sts extension carries ' +
         'the link, and the resource returns it',
         scim.status + ' ' + scim.text.slice(0, 300));
    setRel('fedSubjectPolicy', 'pre-linked');
    got = await signIn(IVY, {});
    note(got.r.status === 200, '8b. and a pre-linked relationship signs ' +
         'them in', got.r.status + ' ' + got.r.text.slice(0, 200));
    const bad = { schemas: scimBody.schemas, userName: 'fsp-bad-' + MODE };
    bad[EXT] = { federationLinks: [{ relationship: 'no-such-rel',
                                     subject: 'x' }] };
    jar = {};
    scim = await request('POST', '/realm/' + SP + '/scim/v2/Users', {
      headers: scimAuth, json: bad });
    note(scim.status === 400 && !entryOf('fsp-bad-' + MODE),
         '8c. a link through no relationship is refused 400 and creates ' +
         'nobody', scim.status + ' ' + scim.text.slice(0, 200));
    const ivyId = attr(entryOf(IVY), 'entryUUID')[0];
    const put = { schemas: scimBody.schemas, userName: IVY };
    put[EXT] = { federationLinks: [] };
    const sessionsBefore = fedSessionsOf(IVY).length;
    jar = {};
    scim = await request('PUT', '/realm/' + SP + '/scim/v2/Users/' + ivyId, {
      headers: scimAuth, json: put });
    await wait(200);
    note(scim.status === 200 &&
         attr(entryOf(IVY), 'federationLink').length === 0 &&
         sessionsBefore >= 1 && fedSessionsOf(IVY).length === 0,
         '8d. a SCIM PUT with no links removes the link and ends the ' +
         'partner\'s sessions', scim.status + ' ' + sessionsBefore);
    setRel('fedSubjectPolicy', '');

    // =======================================================================
    // 9. THE VIEWS THE CONSOLE AND /admin-api READ
    // =======================================================================
    const frankView = inSp(function () {
      return views.userDetailJson({ query: {} }, FRANK);
    });
    note(frankView && frankView.json.federationLinks.length === 1 &&
         frankView.json.federationLinks[0].relationship === REL &&
         frankView.json.federationLinksPaging,
         '9a. the person view lists their links, paged',
         JSON.stringify(frankView && frankView.json.federationLinks));
    const relView = inSp(function () {
      return views.federationDetailJson({ query: {}, headers: {},
        protocol: 'http', get: function () { return '127.0.0.1'; } }, REL);
    });
    note(relView.json.links.some(function (one) {
      return one.username === FRANK;
    }) && relView.json.linksPaging,
         '9b. the relationship view lists who is linked through it, paged');
    note(typeof fedSp.subjectDecision === 'function',
         '9c. subjectDecision() is exported for the tests');

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: '[' + MODE + '] the child ran to the ' +
                                     'end', detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function runMode(t, modeName) {
  log.debug("Entering runMode(). " + modeName);
  const out = path.join(os.tmpdir(), 'federation-subject-policy-' +
                        process.pid + '-' + modeName + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  // federation_provisioning.js's reason: the partner's first JWKS is slow
  // under coverage.
  if (process.env.NODE_V8_COVERAGE) {
    clean.STS_FEDERATION_OUTBOUND_TIMEOUT_MS = '60000';
  }
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', FSP_ROOT: ROOT,
                                  FSP_OUT: out, FSP_MODE: modeName }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in runMode(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in runMode(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings), '[' + modeName + '] the child ' +
              'process reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-800))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving runMode().");
}

function run(t) {
  log.debug("Entering run().");
  runMode(t, 'development');
  runMode(t, 'product');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'federation_subject_policy',
  describe: 'which people a federation partner may assert (#109), in ' +
            'development and product: link-at-first-sign-in with a password, ' +
            'a wrong one, a second factor and a cancel, nothing written ' +
            'before the link, pre-linked, jit-namespaced, any-existing ' +
            'refused in product, the rules, the administrator refusal and ' +
            'its override, an unlink ending sessions, and the link set ' +
            'through the admin action and SCIM',
  run: run
};
