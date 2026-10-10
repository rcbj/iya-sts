// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: risk_decisions.js
//
// ===========================================================================
// RISK DECIDED BY THE ISSUANCE POLICY (#62 P3, 2026-09-22).
//
// rcbj's directive that day: every authorization decision is XACML policy.
// The risk of an authentication is a set of FACTS the embedded PEP puts in
// the issuance request, and the built-in `role-issuance` policy decides roles
// and risk in one evaluation. What this holds:
//
//   A. THE POLICY. The built-in document carries the three risk rules and
//      ordered-deny-overrides; `decideRisk: no` builds the roles-only one;
//      the document survives the XML writer and reader and decides the same.
//   B. THE DECISIONS, through `issuance_gate.check()` with the facts named:
//      LOW and UNSCORED permit; HIGH refuses; MEDIUM asks for a second
//      factor, or a security key where a signal is about the device, and
//      permits once the authentication carries it. A refusal tells a client
//      nothing about the level or the signals. No facts decides on roles.
//   C. NO WAY ROUND. The gate's two shortcuts — no application named,
//      `roles.enforceIssuance` off — waive the role question only.
//   D. WHERE THE FACTS COME FROM when a caller names none: the session it
//      hands the gate, else the person's standing held in this process.
//   E. DEVELOPMENT OBSERVES: without `risk.enforceInDevelopment` a risk Deny
//      is recorded as observed and the roles decide.
//   F. THE SIGN-IN SCREEN, over HTTP, from an address on a Tor list (a
//      first sign-in there is MEDIUM): a person holding no second factor is
//      refused (STS-RISK-0018) rather than offered enrolment; a person
//      holding an authenticator app is asked for a code and signed in with
//      two factors, the session carrying its risk and the assessment its
//      decision.
//   G. EVERY TOKEN ON THE SESSION: the authorization endpoint refuses a
//      session at HIGH (access_denied, saying nothing about why) and sends a
//      session at MEDIUM with a device signal back to sign in with a key.
//   H. HIGH AT SIGN-IN (an operator deny list) is refused; in development,
//      observed and signed in.
//   I. THE CONSOLE IS NEVER LOCKED OUT ON RISK (#226): for
//      `sts-admin-console` HIGH is a step-up to the strongest factor the
//      person holds, and a person holding none is PERMITTED with the alarm
//      (STS-RISK-0038). Any other application is refused as before. And
//      the whole sign-in over HTTP: /admin, a password at HIGH, the code,
//      the console's callback — and a crossing into HIGH there ends what
//      the person held BEFORE, never the session it just permitted, with
//      one alarm per sign-in.
//   J. `risk.listsMatchSpecialPurpose` OFF sets a list aside for a
//      loopback address — the one #226 put everybody behind a bridge on —
//      and the assessment says which lists were set aside.
//   K. A KNOWN CONTEXT caps the address evidence at MEDIUM (#226): the same
//      listed address is HIGH for a newcomer and not HIGH for a person who
//      has signed in from it, with this browser, `risk.minimumHistory` times.
//
// In a child process, because it loads the whole stack and changes settings
// the rest of the in-process suite must not see. Every list is synthetic;
// the one address on them is the loopback the test's requests come from.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'risk_decisions',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.RD_ROOT;
  const OUT = process.env.RD_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function browser(port, userAgent) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign({ 'user-agent': userAgent },
                                      o.headers || {});
        if (!o.noCookies && Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
                                   path: String(urlPath).replace(
                                     /^https?:\/\/[^/]+/, ''),
                                   method: method, headers: headers },
                                 function (res) {
          let text = '';
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }
  const hiddenFields = function (html) {
    const form = {};
    (html.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
      }
    });
    return form;
  };

  // A browser's User-Agent: anything `isbot` reads as an automated client is
  // a signal of its own (x10), which would take every sign-in here to HIGH.
  const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const authn = require(ROOT + '/authn/authn');
    const gate = require(ROOT + '/common/issuance_gate');
    const credentials = require(ROOT + '/common/credentials');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const helpers = require(ROOT + '/common/helpers');
    const totp = require(ROOT + '/common/totp');
    const templates = require(ROOT + '/xacml/xacml_templates');
    const xacmlXml = require(ROOT + '/xacml/xacml_xml');
    const pdp = require(ROOT + '/xacml/xacml_pdp');
    const rolePep = require(ROOT + '/xacml/xacml_role_pep');
    const riskEngine = require(ROOT + '/risk/risk_engine');
    const riskDatasets = require(ROOT + '/risk/risk_datasets');
    const riskTerms = require(ROOT + '/risk/risk_terms');
    const RISK = templates.RISK_ATTRIBUTE;

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    config.setOverride('oauth2.consentRequired', false);
    config.setOverride('risk.enforceInDevelopment', true);
    config.setOverride('risk.datasetShrinkLimitPercent', 100);

    const SECRET = 'risk-decisions-secret-0123456789abcdef';
    const REDIRECT = 'https://rp.risk.example/cb';
    const CLIENT = 'rd-client';
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });

    // --- A. the policy ------------------------------------------------------
    const built = templates.build('role-issuance', {},
                                  { name: 'role-issuance' });
    const ruleIds = (built.policy && built.policy.rules || [])
      .map(function (r) { return r.id.split(':rule:')[1]; });
    note(built.ok && ruleIds.join(',') === 'device-compromised,' +
         'device-required,protocol-not-declared,authn-mechanism,' +
         'mfa-mechanism,risk-high,risk-medium-key,' +
         'risk-medium-second-factor,risk-protected-key,' +
         'risk-protected-second-factor,' +
         'native-sso-not-enabled-refused,native-sso-not-enabled-dropped,' +
         'protected-undeclared-refused,protected-undeclared-dropped,' +
         'undeclared-refused,undeclared-dropped,permission-not-granted,' +
         'exchange-widens-scope,exchange-permission-not-delegated,' +
         'scope-not-authorized,consent-outstanding,scope-kept,' +
         'detail-type-not-registered,detail-type-not-published,detail-kept,' +
         // The per-right GNAP rules (#432 phases 3, 5 and 6): today's
         // checks, the catalogue's, ownership, interaction and acr.
         'gnap-bearer-refused,gnap-protected-undeclared,' +
         'gnap-right-not-listed,gnap-reference-unknown,' +
         'gnap-type-not-catalogued,gnap-type-bearer-refused,' +
         'gnap-owner-unresolved,gnap-owner-mismatch,' +
         'gnap-type-interaction-never,gnap-type-interaction-always,' +
         'gnap-type-consent-action,gnap-type-acr,gnap-type-lifetime,' +
         'gnap-right-kept,' +
         'transfer-hold-relayed,transfer-hold-kept,' +
         'transfer-serve-geofenced,transfer-serve-kept,' +
         'transfer-release-withheld,transfer-release-kept,' +
         // The passkey rules (#536): registration, then sign-in, each
         // stage's refusals in order and its allow.
         'passkey-register-backup-eligible,passkey-register-pin-length,' +
         'passkey-register-serial-missing,passkey-register-serial-not-held,' +
         'passkey-register-allowed,' +
         'passkey-use-backup-eligible,passkey-use-pin-length,' +
         'passkey-use-attestation-unchecked,' +
         'passkey-use-attestation-compromised,' +
         'passkey-use-attestation-untrusted,passkey-use-attestation-aaguid,' +
         'passkey-use-attestation-unlisted,passkey-use-attestation-level,' +
         'passkey-use-attestation-fips,passkey-use-allowed,' +
         // The exchange rules (#186): the semantics, the refusals in order,
         // the allows, and the may_act question.
         'exchange-semantics-requested,exchange-semantics-actor-default,' +
         'exchange-semantics-subject-default,' +
         'exchange-semantics-realm-default,exchange-may-act,' +
         'exchange-several-targets,exchange-unregistered-target,' +
         'exchange-no-target,exchange-protected-subject,' +
         'exchange-unknown-actor,exchange-user-actor-role,' +
         'exchange-semantics,exchange-subject-group,exchange-authority,' +
         'exchange-delegation,exchange-impersonation,' +
         'exchange-self-default-audience,exchange-self,exchange-allowed,' +
         'may-act-subject-choice,' +
         'risk-protected-alarm,holds-a-required-role' &&
         /ordered-deny-overrides$/.test(built.policy.combiningAlgId),
         'A1. the built-in issuance policy carries the two device rules ' +
         '(#164), the protocol-declaration rule, the sign-in mechanism ' +
         'rule (#457), the second-factor rule (#475), the three risk ' +
         'rules, the console\'s two step-ups and ' +
         'its alarm ahead of the role rule, under ordered-deny-overrides',
         ruleIds.join(',') + ' ' + (built.policy || {}).combiningAlgId);
    const rolesOnly = templates.build('role-issuance',
      { decideRisk: 'no', decideDevices: 'no', decideProtocols: 'no',
        decideAuthnMechanisms: 'no', decideMfaMechanisms: 'no',
        decideScopes: 'no', decideTransfers: 'no', decideExchanges: 'no',
        decideGnapRights: 'no', decidePasskeys: 'no' },
      { name: 'role-issuance' });
    note(rolesOnly.ok && rolesOnly.policy.rules.length === 1 &&
         /deny-unless-permit$/.test(rolesOnly.policy.combiningAlgId),
         'A2. decideRisk: no (and decideDevices, decideProtocols, ' +
         'decideAuthnMechanisms (#457), decideMfaMechanisms (#475), ' +
         'decideScopes and ' +
         'decideTransfers, decideExchanges, decideGnapRights and ' +
         'decidePasskeys: no, #164, #304, #98, #186, #432 and #536) builds ' +
         'the ' +
         'roles-only document it was');
    const request = rolePep.buildRequest({
      application: CLIENT, kind: 'start-session',
      subject: { kind: 'user', name: 'rd-unit', authenticated: true },
      risk: { level: 'HIGH', score: 20, signals: ['tor-exit'], satisfied: [],
              enforced: true } }, ['EVERYBODY'], [], ['EVERYBODY']);
    let reread = null;
    try {
      reread = xacmlXml.parsePolicy(xacmlXml.writePolicy(built.policy));
    } catch (e) {
      reread = null;
      note(false, 'A3. the document survives the XML writer and reader',
           e.message);
    }
    const direct = pdp.evaluate(built.policy, request, {});
    const viaXml = reread ? pdp.evaluate(reread, request, {}) : {};
    note(reread && direct.decision === 'Deny' && viaXml.decision === 'Deny' &&
         (viaXml.obligations || []).some(function (o) {
           return o.id === RISK.OBLIGATION;
         }),
         'A3. the document survives the XML writer and reader, and decides ' +
         'the same Deny with the same risk obligation',
         direct.decision + ' / ' + viaXml.decision);

    // --- B. the decisions ---------------------------------------------------
    ldap.createUser('rd-unit', { invent: false });
    const ask = function (facts, extra) {
      return gate.check(Object.assign({
        application: CLIENT, kind: gate.ISSUANCE.ACCESS_TOKEN,
        subject: { kind: 'user', name: 'rd-unit', authenticated: true },
        claims: null, risk: facts }, extra || {}));
    };
    const facts = function (level, signals, satisfied, enforced) {
      return { level: level, score: level === 'UNSCORED' ? null : 2,
               signals: signals || [], satisfied: satisfied || [],
               enforced: enforced !== false, assessmentId: 'a-test' };
    };
    note(ask(facts('LOW')).allowed && ask(facts('UNSCORED')).allowed &&
         ask(null).allowed,
         'B1. LOW, UNSCORED and no facts at all are permitted');
    const high = ask(facts('HIGH', ['tor-exit']));
    note(!high.allowed && high.risk && high.risk.action === 'refuse' &&
         high.why === 'Authentication failed.',
         'B2. HIGH is refused — and the sentence a client may see names ' +
         'neither the level nor the signals', JSON.stringify(high));
    const medium = ask(facts('MEDIUM', ['tor-exit']));
    note(!medium.allowed && medium.risk && medium.risk.action === 'step-up' &&
         medium.risk.factor === 'second-factor',
         'B3. MEDIUM asks for a second factor', JSON.stringify(medium.risk));
    note(ask(facts('MEDIUM', ['tor-exit'], ['second-factor'])).allowed,
         'B4. and permits once the authentication carries one');
    const device = ask(facts('MEDIUM', ['automated-client'],
                             ['second-factor']));
    note(!device.allowed && device.risk &&
         device.risk.factor === 'security-key',
         'B5. MEDIUM with a signal about the device asks for a SECURITY ' +
         'KEY, which a one-time code does not answer',
         JSON.stringify(device.risk));
    note(ask(facts('MEDIUM', ['automated-client'],
                   ['security-key', 'second-factor'])).allowed,
         'B6. and permits an authentication that used one');
    note(JSON.stringify(riskEngine.satisfiedBy(['pwd', 'otp'], 'mfa')) ===
           '["second-factor"]' &&
         JSON.stringify(riskEngine.satisfiedBy(['hwk'], '1')) ===
           '["security-key","second-factor"]' &&
         riskEngine.satisfiedBy(['pwd'], '1').length === 0,
         'B7. a code after a password meets a second factor; a key meets ' +
         'both; a password alone meets neither');

    // --- C. no way round ----------------------------------------------------
    note(!ask(facts('HIGH'), { application: '' }).allowed &&
         ask(null, { application: '' }).allowed,
         'C1. a call naming no application is still refused on risk, and ' +
         'still allowed without facts');
    config.setOverride('roles.enforceIssuance', false);
    note(!ask(facts('HIGH')).allowed && ask(facts('LOW')).allowed,
         'C2. roles.enforceIssuance off waives the roles, not the risk');
    config.setOverride('roles.enforceIssuance', true);

    // --- D. where the facts come from ---------------------------------------
    const fromSession = gate.check({
      application: CLIENT, kind: gate.ISSUANCE.ACCESS_TOKEN,
      subject: { kind: 'user', name: 'rd-unit', authenticated: true },
      claims: null,
      session: { risk: { level: 'HIGH', score: 20, signals: [],
                         assessmentId: 'x' }, amr: ['pwd', 'otp'],
                 acr: 'mfa' } });
    note(!fromSession.allowed && fromSession.risk &&
         fromSession.risk.action === 'refuse',
         'D1. a caller that hands the session gets its risk decided: a ' +
         'session at HIGH is issued nothing, whatever factors it holds');
    const unitSub = helpers.subjectForName('rd-unit');
    await riskEngine.assess({ realm: 'default', subject: unitSub,
      username: 'rd-unit', sessionId: '', door: 'a test',
      context: { address: '192.0.2.10', uaFingerprint: 'fp' },
      userAgent: 'curl/8.5.0' });
    const standing = riskEngine.standingOf('default', 'rd-unit');
    const fromStanding = gate.check({
      application: CLIENT, kind: gate.ISSUANCE.KERBEROS_TICKET,
      subject: { kind: 'user', name: 'rd-unit', authenticated: true },
      claims: null });
    note(standing && standing.level === 'HIGH' && !fromStanding.allowed,
         'D2. with no session, the person\'s standing decides: an ' +
         'automated client made them HIGH, and a Kerberos ticket is refused',
         JSON.stringify(standing && standing.level));

    // --- E. development observes --------------------------------------------
    config.setOverride('risk.enforceInDevelopment', false);
    const observed = ask(riskEngine.factsOf({ level: 'HIGH', score: 20,
                                               signals: [] }, [], ''));
    note(observed.allowed && observed.risk && observed.risk.observed,
         'E1. in development a risk Deny is observed and the roles decide',
         JSON.stringify(observed.risk));
    config.setOverride('risk.enforceInDevelopment', true);

    // --- M. WS-Trust and the KDC decide at the door (#499) -----------------
    // The sign-in being made is assessed before anything is issued and the
    // decision is made on THAT assessment, recorded — not on the standing
    // an earlier sign-in left. So a person held at MEDIUM is assessed again
    // on every attempt, and is let through the moment they score lower.
    // The MEDIUM line is moved to make the earlier sign-ins MEDIUM, and back
    // to its default (3) for the one that recovers. Before any list names
    // the loopback these requests come from (F below adds them).
    config.setOverride('risk.minimumHistory', 1);
    const assessedFor = async function (name, door) {
      const v = await riskEngine.view('default',
        { subject: helpers.subjectForName(name), days: 1 });
      return v.assessments.rows.filter(function (a) {
        return String(a.door).indexOf(door) === 0;
      });
    };
    const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
    const soap = function (user) {
      const body = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-' +
        'envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/' +
        'oasis-200401-wss-wssecurity-secext-1.0.xsd"><s:Header>' +
        '<wsse:Security><wsse:UsernameToken><wsse:Username>' + user +
        '</wsse:Username><wsse:Password>any</wsse:Password>' +
        '</wsse:UsernameToken></wsse:Security></s:Header><s:Body>' +
        '<wst:RequestSecurityToken xmlns:wst="' + WST + '">' +
        '<wst:RequestType>' + WST + '/Issue</wst:RequestType>' +
        '</wst:RequestSecurityToken></s:Body></s:Envelope>';
      return new Promise(function (resolve) {
        const req = http.request({ host: '127.0.0.1', port: port,
          path: '/sts', method: 'POST',
          headers: { 'content-type': 'application/soap+xml; charset=utf-8',
                     'content-length': Buffer.byteLength(body),
                     'user-agent': CHROME } }, function (res) {
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, text: text });
          });
        });
        req.end(body);
      });
    };
    ldap.createUser('rd-kim', { invent: false });
    const kimFirst = await soap('rd-kim');
    config.setOverride('risk.mediumScorePercent', 1);
    const kimHeld = await soap('rd-kim');
    const kimHeldAgain = await soap('rd-kim');
    const kimHeldRows = await assessedFor('rd-kim', 'WS-Trust');
    config.clearOverride('risk.mediumScorePercent');
    const kimBack = await soap('rd-kim');
    const kimRows = await assessedFor('rd-kim', 'WS-Trust');
    note(kimFirst.status === 200 && kimHeld.status === 403 &&
         kimHeldAgain.status === 403 && kimHeldRows.length === 3 &&
         kimHeldRows[0].level === 'MEDIUM' &&
         /step-up/.test(String(kimHeldRows[0].decision)),
         'M1. WS-Trust assesses every Issue at the door and decides on it: ' +
         'a MEDIUM sign-in is refused, and the next attempt is ASSESSED ' +
         'AGAIN (three assessments, the last MEDIUM with its step-up ' +
         'decision recorded) rather than refused on the standing',
         JSON.stringify({ statuses: [kimFirst.status, kimHeld.status,
                                     kimHeldAgain.status],
                          rows: kimHeldRows.map(function (a) {
                            return [a.level, a.decision];
                          }) }));
    note(kimBack.status === 200 && kimRows.length === 4 &&
         kimRows[0].level === 'LOW' &&
         riskEngine.standingOf('default', 'rd-kim').level === 'LOW',
         'M2. a person held at MEDIUM recovers at the door the moment their ' +
         'score allows: at the default line the next Issue scores LOW and is ' +
         'issued, and their standing is LOW',
         JSON.stringify({ status: kimBack.status, rows: kimRows.map(
           function (a) {
             return [a.level, a.score, a.decision];
           }) }));

    const kdc = require(ROOT + '/kerberos/krb5_kdc.js');
    const principals = require(ROOT + '/kerberos/krb5_principals.js');
    const wire = require(ROOT + '/tests/vendored/krb5_wire.js');
    const inproc = { label: 'in-process', send: function (bytes) {
      return kdc.handleMessage(bytes);
    } };
    const KPW = String(config.value('krb5.userPassword'));
    const kinit = async function (name) {
      const r = await wire.asExchange(inproc, principals.REALM, name,
                                      { password: KPW });
      const e = (r.second && r.second.error) || (r.first && r.first.error);
      return { tgt: !!r.tgt, code: e ? e.code : null,
               eText: e ? String(e.eText || '') : '' };
    };
    ldap.createUser('rd-kurt', { invent: false });
    const kurtFirst = await kinit('rd-kurt');
    config.setOverride('risk.mediumScorePercent', 1);
    // FROM AN ADDRESS KURT NEVER USED. Since #502 a KDC sign-in from his
    // usual address is so familiar — no User-Agent and that address, both
    // his and both rare in the realm — that it scores under the lowest line
    // the setting can hold (0.01, measured at 0.007): the lookups an absent
    // header and an unmapped address fail are no longer values everybody
    // shares. A new address (×4, unmapped) is what puts it over.
    const kurtHeld = await require(ROOT + '/common/audit').withSource(
      { address: '198.51.100.77' }, function () {
        return kinit('rd-kurt');
      });
    config.clearOverride('risk.mediumScorePercent');
    const kurtBack = await kinit('rd-kurt');
    const kurtRows = await assessedFor('rd-kurt', 'Kerberos');
    note(kurtFirst.tgt && !kurtHeld.tgt && kurtHeld.code === 12 &&
         /stronger authentication/.test(kurtHeld.eText) && kurtBack.tgt &&
         kurtRows.length === 3 && kurtRows[1].level === 'MEDIUM' &&
         kurtRows[0].level === 'LOW',
         'M3. the KDC assesses an AS-REQ at the door once the pre-' +
         'authentication verified: a MEDIUM sign-in gets no ticket ' +
         '(KDC_ERR_POLICY, a stronger authentication), and the next, LOW, ' +
         'gets one — each recorded',
         JSON.stringify({ first: kurtFirst, held: kurtHeld, back: kurtBack,
                          rows: kurtRows.map(function (a) {
                            return [a.level, a.score, a.decision,
                                    a.signals[0].factors];
                          }) }));
    config.clearOverride('risk.minimumHistory');

    // --- F. the sign-in screen ----------------------------------------------
    await riskTerms.accept({ provider: 'tor-project', acceptedBy: 'a test',
                             via: 'upload' });
    await riskDatasets.importVersion({ dataset: 'iplist.tor-exit',
      format: 'ip-list', content: '127.0.0.1\n', version: 'rd-tor-1',
      source: 'upload' });
    const authorize = function (b) {
      return b.go('GET', '/oauth2/authorize?' + new URLSearchParams({
        client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 's', nonce: 'n-' + Date.now() }).toString());
    };
    const signIn = async function (b, username) {
      const start = await authorize(b);
      const screenAt = String(start.headers.location || '');
      const page = await b.go('GET', screenAt);
      return b.go('POST', screenAt.split('?')[0], {
        form: Object.assign(hiddenFields(page.text), {
          username: username, password: 'anything', action: 'login' }) });
    };
    const follow = async function (b, first) {
      let at = first;
      for (let i = 0; i < 4 && at.status >= 300 && at.status < 400 &&
           String(at.headers.location || '').indexOf(REDIRECT) !== 0; i++) {
        at = await b.go('GET', String(at.headers.location));
      }
      return at;
    };
    const assessmentOf = async function (username) {
      const sub = helpers.subjectForName(username);
      const view = await riskEngine.view('default', {});
      return view.assessments.rows.filter(function (a) {
        return a.subject === sub;
      })[0] || null;
    };

    ldap.createUser('rd-bob', { invent: false });
    const bob = browser(port, CHROME);
    const bobAnswer = await signIn(bob, 'rd-bob');
    const bobAssessed = await assessmentOf('rd-bob');
    note(bobAnswer.status === 200 &&
         /Authentication failed for rd-bob/.test(bobAnswer.text) &&
         !authn.sessionsOf('rd-bob').length,
         'F1. from a Tor exit a first sign-in is MEDIUM, and a person ' +
         'holding no second factor is refused rather than offered one',
         bobAnswer.status + ' ' + bobAnswer.text.slice(0, 120));
    note(bobAssessed && bobAssessed.level === 'MEDIUM' &&
         bobAssessed.decision === 'step-up',
         'F2. the assessment records the decision it met',
         JSON.stringify(bobAssessed && { level: bobAssessed.level,
                                         decision: bobAssessed.decision }));

    ldap.createUser('rd-carol', { invent: false });
    const begun = credentials.beginTotpEnrolment('rd-carol', {});
    credentials.confirmTotpEnrolment('rd-carol', totp.codeAt(begun.secret));
    const carol = browser(port, CHROME);
    const asked = await signIn(carol, 'rd-carol');
    const step = hiddenFields(asked.text);
    note(asked.status === 200 && step.mfa_id &&
         /name="code"/.test(asked.text),
         'F3. a person holding an authenticator app is asked for a code',
         asked.status + ' ' + asked.text.slice(0, 120));
    const coded = await carol.go('POST', '/authn/totp', { form: {
      mfa_id: step.mfa_id,
      code: totp.codeAt(begun.secret, Date.now() + 30000) } });
    const landed = await follow(carol, coded);
    const carolSessions = authn.sessionsOf('rd-carol');
    const carolSession = carolSessions.length
      ? authn.sessionById(carolSessions[0].id || carolSessions[0]) : null;
    note(String(landed.headers.location || '').indexOf(REDIRECT) === 0 &&
         carolSession && carolSession.acr === 'mfa' &&
         carolSession.risk && carolSession.risk.level === 'MEDIUM',
         'F4. and signed in with two factors, the session carrying the ' +
         'risk it was decided on',
         String(landed.headers.location || '') + ' ' +
         JSON.stringify(carolSession && { acr: carolSession.acr,
                                          risk: carolSession.risk }));

    // --- G. every token on the session --------------------------------------
    if (carolSession) {
      carolSession.risk = { level: 'HIGH', score: 20, signals: ['tor-exit'],
                            assessmentId: 'rd-g1' };
      const denied = await authorize(carol);
      const deniedAt = String(denied.headers.location || '');
      note(deniedAt.indexOf(REDIRECT) === 0 &&
           /error=access_denied/.test(deniedAt) &&
           !/HIGH|tor/i.test(decodeURIComponent(deniedAt)),
           'G1. a session at HIGH is issued no code, and the client is told ' +
           'nothing about why', deniedAt);
      carolSession.risk = { level: 'MEDIUM', score: 2,
                            signals: ['automated-client'],
                            assessmentId: 'rd-g2' };
      const stepUp = await authorize(carol);
      note(/\/authn\/login\?authn=/.test(String(stepUp.headers.location ||
                                                 '')),
           'G2. a session at MEDIUM with a device signal, holding a code ' +
           'and no key, is sent to sign in again with a security key',
           stepUp.status + ' ' + String(stepUp.headers.location || ''));
    } else {
      note(false, 'G. the session to test issuance on exists');
    }

    // --- H. HIGH at sign-in --------------------------------------------------
    const denied = await riskDatasets.importVersion({
      dataset: 'iplist.operator-deny', realm: 'default', format: 'ip-list',
      content: '127.0.0.1\n', version: 'rd-deny-1', source: 'upload' });
    note(denied && denied.ok, 'H0. the operator deny list is imported',
         JSON.stringify(denied && denied.errors));
    ldap.createUser('rd-dave', { invent: false });
    const dave = browser(port, CHROME);
    const daveAnswer = await signIn(dave, 'rd-dave');
    const daveAssessed = await assessmentOf('rd-dave');
    note(daveAssessed && daveAssessed.level === 'HIGH' &&
         daveAssessed.decision === 'refuse' && daveAnswer.status === 200 &&
         /Authentication failed for rd-dave/.test(daveAnswer.text) &&
         !authn.sessionsOf('rd-dave').length,
         'H1. an address on the operator\'s deny list makes a sign-in ' +
         'HIGH, and it is refused', daveAnswer.status + ' ' +
         JSON.stringify(daveAssessed && { level: daveAssessed.level,
                                          decision: daveAssessed.decision }));
    config.setOverride('risk.enforceInDevelopment', false);
    ldap.createUser('rd-erin', { invent: false });
    const erin = browser(port, CHROME);
    const erinLanded = await follow(erin, await signIn(erin, 'rd-erin'));
    const erinAssessed = await assessmentOf('rd-erin');
    note(String(erinLanded.headers.location || '').indexOf(REDIRECT) === 0 &&
         erinAssessed && erinAssessed.level === 'HIGH' &&
         erinAssessed.decision === 'observe:refuse',
         'H2. in development the same sign-in is observed — recorded as a ' +
         'refusal it would have been — and signed in',
         JSON.stringify(erinAssessed && { level: erinAssessed.level,
                                          decision: erinAssessed.decision }));

    // --- I. the console is never locked out on risk (#226) ----------------
    config.setOverride('risk.enforceInDevelopment', true);
    const audit = require(ROOT + '/common/audit');
    const CONSOLE = 'sts-admin-console';
    // THE CONSOLE'S SIGN-IN STARTS IN THE BROWSER since the cutover (#446):
    // the shell is asked for first (it registers the callback), then the
    // authorize endpoint as the public client with PKCE.
    const consoleAuthorize = '/oauth2/authorize?' + new URLSearchParams({
      client_id: CONSOLE, response_type: 'code',
      redirect_uri: 'http://127.0.0.1:' + port + '/admin/callback',
      scope: 'openid admin:read admin:write', state: 's',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256' }).toString();
    const onConsole = function (name, satisfied) {
      return gate.check({
        application: CONSOLE, kind: gate.ISSUANCE.SESSION,
        subject: { kind: 'user', name: name, authenticated: true },
        claims: null,
        risk: { level: 'HIGH', score: 20, signals: ['operator-deny'],
                satisfied: satisfied || [], enforced: true,
                assessmentId: 'rd-i-' + name } });
    };
    const alarmsBefore = audit.list().filter(function (row) {
      return row.action === 'xacml.issuance.alarm';
    }).length;
    const bare = onConsole('rd-unit');
    const alarms = audit.list().filter(function (row) {
      return row.action === 'xacml.issuance.alarm';
    });
    note(bare.allowed && alarms.length === alarmsBefore + 1 &&
         alarms[alarms.length - 1].errorCode === 'STS-RISK-0038',
         'I1. HIGH at the console, for a person holding no second factor, ' +
         'is PERMITTED — and the alarm is on the audit log (STS-RISK-0038)',
         JSON.stringify({ allowed: bare.allowed, why: bare.why,
                          alarms: alarms.length - alarmsBefore }));
    const withCode = onConsole('rd-carol');
    note(!withCode.allowed && withCode.risk &&
         withCode.risk.action === 'step-up' &&
         withCode.risk.factor === 'second-factor',
         'I2. a person holding an authenticator app is asked for it at the ' +
         'console, not refused', JSON.stringify(withCode.risk));
    note(onConsole('rd-carol', ['second-factor']).allowed,
         'I3. and permitted once the authentication carries it');
    const elsewhere = gate.check({
      application: CLIENT, kind: gate.ISSUANCE.SESSION,
      subject: { kind: 'user', name: 'rd-unit', authenticated: true },
      claims: null,
      risk: { level: 'HIGH', score: 20, signals: ['operator-deny'],
              satisfied: [], enforced: true, assessmentId: 'rd-i-other' } });
    note(!elsewhere.allowed && elsewhere.risk &&
         elsewhere.risk.action === 'refuse',
         'I4. any other application is still refused at HIGH',
         JSON.stringify(elsewhere.risk));
    const unprotectedPolicy = templates.build('role-issuance',
      { neverLockOut: 'none' }, { name: 'role-issuance' });
    const consoleRequest = rolePep.buildRequest({
      application: CONSOLE, kind: 'start-session',
      subject: { kind: 'user', name: 'rd-unit', authenticated: true },
      risk: { level: 'HIGH', score: 20, signals: [], satisfied: [],
              enforced: true } }, ['EVERYBODY'], [], ['EVERYBODY']);
    const plain = pdp.evaluate(unprotectedPolicy.policy, consoleRequest, {});
    note(unprotectedPolicy.ok && plain.decision === 'Deny' &&
         // The three risk rules, the role rule, #164's two device rules,
         // the fifteen scope and detail rules of #304, #305, #186 and
         // #549, the
         // six transfer rules of #98, the protocol-declaration rule, the
         // twenty exchange rules of #186, the fourteen per-right GNAP
         // rules of #432, the sign-in mechanism rule of #457, the
         // second-factor rule of #475, and the fifteen passkey rules of
         // #536.
         unprotectedPolicy.policy.rules.length === 79,
         'I5. neverLockOut none puts the console under the three rules, ' +
         'and HIGH refuses it', plain.decision);

    // THE WHOLE CONSOLE SIGN-IN, OVER HTTP (#226, what rcbj hit on the
    // rebuilt stack): /admin sends the browser to the authorization
    // endpoint, the password on the deny-listed loopback is HIGH, the
    // console's rule asks for the second factor the person holds, and the
    // code is answered — and the SESSION'S decision, made again after the
    // second factor, must still be about the console. It was about "" until
    // the second-factor finishers named the application, and the ordinary
    // HIGH rule refused it.
    ldap.createUser('rd-ivy', { invent: false });
    const ivyTotp = credentials.beginTotpEnrolment('rd-ivy', {});
    credentials.confirmTotpEnrolment('rd-ivy', totp.codeAt(ivyTotp.secret));
    const ivy = browser(port, CHROME);
    const pathOf = function (location) {
      const u = new URL(String(location || ''), 'http://127.0.0.1');
      return u.pathname + u.search;
    };
    await ivy.go('GET', '/admin');
    let ivyAt = await ivy.go('GET', consoleAuthorize);
    for (let i = 0; i < 4 && ivyAt.status >= 300 && ivyAt.status < 400 &&
         !/\/authn\/login\?/.test(String(ivyAt.headers.location || ''));
         i++) {
      ivyAt = await ivy.go('GET', pathOf(ivyAt.headers.location));
    }
    const ivyScreen = pathOf(ivyAt.headers.location);
    const ivyPage = await ivy.go('GET', ivyScreen);
    const ivyAsked = await ivy.go('POST', ivyScreen.split('?')[0], {
      form: Object.assign(hiddenFields(ivyPage.text), {
        username: 'rd-ivy', password: 'anything', action: 'login' }) });
    const ivyStep = hiddenFields(ivyAsked.text);
    let ivyDone = ivyStep.mfa_id ? await ivy.go('POST', '/authn/totp', {
      form: { mfa_id: ivyStep.mfa_id,
              code: totp.codeAt(ivyTotp.secret, Date.now() + 30000) } })
      : ivyAsked;
    for (let i = 0; i < 4 && ivyDone.status >= 300 && ivyDone.status < 400 &&
         !/\/admin\/callback\?/.test(String(ivyDone.headers.location || ''));
         i++) {
      ivyDone = await ivy.go('GET', pathOf(ivyDone.headers.location));
    }
    note(!!ivyStep.mfa_id &&
         /\/admin\/callback\?.*code=/.test(String(ivyDone.headers.location ||
                                                  '')),
         'I6. a HIGH console sign-in is asked for the second factor, and ' +
         'answering it reaches the console\'s callback with a code — the ' +
         'session decided on the console, not on no application at all',
         ivyAsked.status + ' ' + ivyDone.status + ' ' +
         String(ivyDone.headers.location || '') + ' ' +
         String(ivyDone.text || '').slice(0, 160));

    // CROSSING INTO HIGH AT THE CONSOLE ENDS WHAT WAS HELD BEFORE, NOT THE
    // SIGN-IN ITSELF (#226, what the `admin` user hit): a person with no
    // second factor and a session elsewhere signs in to the console, goes
    // from nothing to HIGH, is permitted with the alarm — and the
    // risk-response reaction, taken a moment later, used to end that very
    // session with the rest, so the console's code was gone before the
    // callback redeemed it.
    ldap.createUser('rd-jay', { invent: false });
    config.setOverride('risk.listsMatchSpecialPurpose', false);
    const jayEarlier = browser(port, CHROME);
    await follow(jayEarlier, await signIn(jayEarlier, 'rd-jay'));
    const earlierIds = authn.sessionsOf('rd-jay').map(function (one) {
      return String(one.id || one);
    });
    config.setOverride('risk.listsMatchSpecialPurpose', true);
    const jayAlarmsBefore = audit.list().filter(function (row) {
      return row.action === 'xacml.issuance.alarm' && row.actor === 'rd-jay';
    }).length;
    const jay = browser(port, CHROME);
    await jay.go('GET', '/admin');
    let jayAt = await jay.go('GET', consoleAuthorize);
    for (let i = 0; i < 4 && jayAt.status >= 300 && jayAt.status < 400 &&
         !/\/authn\/login\?/.test(String(jayAt.headers.location || ''));
         i++) {
      jayAt = await jay.go('GET', pathOf(jayAt.headers.location));
    }
    const jayScreen = pathOf(jayAt.headers.location);
    const jayPage = await jay.go('GET', jayScreen);
    let jayDone = await jay.go('POST', jayScreen.split('?')[0], {
      form: Object.assign(hiddenFields(jayPage.text), {
        username: 'rd-jay', password: 'anything', action: 'login' }) });
    for (let i = 0; i < 4 && jayDone.status >= 300 && jayDone.status < 400 &&
         !/\/admin\/callback\?/.test(String(jayDone.headers.location || ''));
         i++) {
      jayDone = await jay.go('GET', pathOf(jayDone.headers.location));
    }
    // The reactions run after the assessment is answered; give them time.
    await new Promise(function (r) { setTimeout(r, 1500); });
    const jayNow = authn.sessionsOf('rd-jay').map(function (one) {
      return String(one.id || one);
    });
    const jayStanding = riskEngine.standingOf('default', 'rd-jay');
    const jayAlarms = audit.list().filter(function (row) {
      return row.action === 'xacml.issuance.alarm' && row.actor === 'rd-jay';
    }).length - jayAlarmsBefore;
    note(earlierIds.length === 1 && jayStanding &&
         jayStanding.level === 'HIGH' &&
         /\/admin\/callback\?.*code=/.test(String(jayDone.headers.location ||
                                                  '')) &&
         jayNow.length === 1 && jayNow[0] !== earlierIds[0],
         'I7. crossing into HIGH at the console ends the session held ' +
         'BEFORE the sign-in and not the one the sign-in was just permitted',
         JSON.stringify({ earlier: earlierIds, now: jayNow,
           level: jayStanding && jayStanding.level,
           at: String(jayDone.headers.location || '').slice(0, 80) }));
    // A token issued on that session — what the console's back channel asks
    // for next — is permitted by the same rule and raises no second alarm.
    const jayToken = gate.check({
      application: CONSOLE, kind: gate.ISSUANCE.ACCESS_TOKEN,
      subject: { kind: 'user', name: 'rd-jay', authenticated: true },
      claims: null,
      risk: { level: 'HIGH', score: 20, signals: ['operator-deny'],
              satisfied: [], enforced: true, assessmentId: 'rd-i8' } });
    const jayAlarmsAfter = audit.list().filter(function (row) {
      return row.action === 'xacml.issuance.alarm' && row.actor === 'rd-jay';
    }).length - jayAlarmsBefore;
    note(jayAlarms === 1 && jayToken.allowed && jayAlarmsAfter === 1,
         'I8. the alarm is raised once for the sign-in, not for every code ' +
         'and token issued on its session',
         jayAlarms + ' then ' + jayAlarmsAfter + ' ' + jayToken.allowed);

    // --- J. lists set aside for a special-purpose address (#226) ---------
    config.setOverride('risk.listsMatchSpecialPurpose', false);
    ldap.createUser('rd-fay', { invent: false });
    const fay = browser(port, CHROME);
    const fayLanded = await follow(fay, await signIn(fay, 'rd-fay'));
    const fayAssessed = await assessmentOf('rd-fay');
    const fayModel = fayAssessed && (fayAssessed.signals || [])
      .filter(function (one) { return one.signal === 'model'; })[0];
    note(String(fayLanded.headers.location || '').indexOf(REDIRECT) === 0 &&
         fayAssessed && fayAssessed.level === 'UNSCORED' &&
         fayModel && (fayModel.listsSetAside || []).sort().join(',') ===
           'operator-deny,tor-exit',
         'J1. with risk.listsMatchSpecialPurpose off, the Tor and deny ' +
         'lists are set aside for a loopback address, the first sign-in is ' +
         'UNSCORED and signed in, and the assessment names both lists',
         JSON.stringify(fayAssessed && { level: fayAssessed.level,
           setAside: fayModel && fayModel.listsSetAside }));
    config.setOverride('risk.listsMatchSpecialPurpose', true);

    // --- K. a known context caps address evidence at MEDIUM (#226) --------
    config.setOverride('risk.minimumHistory', 2);
    const contextOf = function (name) {
      return { realm: 'default', subject: helpers.subjectForName(name),
               username: name, sessionId: '', door: 'a test',
               context: { address: '127.0.0.1', uaFingerprint: 'fp-k-' + name },
               userAgent: CHROME };
    };
    ldap.createUser('rd-gus', { invent: false });
    await riskEngine.assess(contextOf('rd-gus'));
    await riskEngine.assess(contextOf('rd-gus'));
    const known = await riskEngine.assess(contextOf('rd-gus'));
    const knownModel = (known && known.signals || []).filter(function (one) {
      return one.signal === 'model';
    })[0];
    ldap.createUser('rd-hal', { invent: false });
    const newcomer = await riskEngine.assess(contextOf('rd-hal'));
    note(newcomer && newcomer.level === 'HIGH' &&
         known && known.level !== 'HIGH' && knownModel &&
         knownModel.knownContext === true &&
         known.signals.some(function (one) {
           return one.signal === 'operator-deny';
         }),
         'K1. on the same listed address a newcomer is HIGH, and a person ' +
         'with two earlier sign-ins from it in this browser is not: the ' +
         'address evidence still counts, capped at MEDIUM',
         JSON.stringify({ newcomer: newcomer && newcomer.level,
                          known: known && known.level,
                          score: known && known.score,
                          capped: knownModel && knownModel.capped }));
    note(riskEngine.riskOf(known).knownContext === true,
         'K2. the session carries the known context, so the rescore job ' +
         'caps what a list gained later can raise it to');

    // --- L. an allow-listed network is not counted as hostile (#311) -------
    // `network-failures` is refused passwords from anybody behind the
    // address; an operator who allow-listed it declared it trusted.
    const riskStore = require(ROOT + '/risk/risk_store');
    config.setOverride('risk.networkFailureThreshold', 1);
    await riskStore.recordFailure({ realm: 'default', at: Date.now(),
      door: 'a test', subject: '', nameHmac: 'rd-l', addressSealed: '',
      addressPrefix: riskStore.prefixOf('127.0.0.1'),
      asn: 0, errorCode: 'STS-AUTHN-0054' }, false);
    ldap.createUser('rd-ian', { invent: false });
    const before = await riskEngine.assess(contextOf('rd-ian'));
    const allowed = await riskDatasets.importVersion({
      dataset: 'iplist.operator-allow', realm: 'default', format: 'ip-list',
      content: '127.0.0.1\n', version: 'rd-allow-1', source: 'upload' });
    ldap.createUser('rd-jon', { invent: false });
    const after = await riskEngine.assess(contextOf('rd-jon'));
    const named = function (a, id) {
      return !!a && (a.signals || []).some(function (one) {
        return one.signal === id;
      });
    };
    note(named(before, 'network-failures') && allowed && allowed.ok &&
         named(after, 'operator-allow') &&
         !named(after, 'network-failures'),
         'L1. refused passwords from the network count against a newcomer ' +
         'until the operator allow-lists it, and not after',
         JSON.stringify({ before: before && before.signals.map(function (x) {
           return x.signal; }), after: after && after.signals.map(function (x) {
           return x.signal; }), allowed: allowed && allowed.errors }));
    config.clearOverride('risk.networkFailureThreshold');
    config.setOverride('risk.minimumHistory', 5);

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
  const out = path.join(os.tmpdir(), 'risk-decisions-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', RD_ROOT: ROOT, RD_OUT: out }),
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
  name: 'risk_decisions',
  describe: 'risk decided by the issuance policy (#62 P3): the risk rules in ' +
            'the built-in document, HIGH refused and MEDIUM stepped up, no ' +
            'shortcut round them, facts from the session or the standing, ' +
            'development observing, the sign-in screen and the ' +
            'authorization endpoint acting on the decision, the console ' +
            'never locked out, lists set aside for special-purpose ' +
            'addresses, and a known context capping address evidence (#226)',
  run: run
};
