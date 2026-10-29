// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/risk_key_step_up.js — A SECURITY KEY DEMANDED ON RISK CLOSES THE
// CODE DOORS, AND A SET-UP AFTER A WALLET KEEPS THE ASSESSMENT (#926).
//
// #899 and #906 were fixed in #914 without a test. Held here, in a child
// process on wallet_kit.js, with the risk engine and the shipped
// role-issuance document installed once by tests/tools/risk_key_step_up.js.
//
// THE WALLET IS THE FIRST FACTOR DRIVEN, because wallet_kit.js already
// presents one. finishEmailFirstFactor() and
// beginSecondFactorAfterFederation() both call
// beginSecondFactorAfterWallet(), so an emailed-code sign-in or a
// federation sign-in that reached the same required-enrolment branch would
// carry the assessment the same way. Neither is driven here.
//
// THE ENROLMENT IS THAT REQUIRED BRANCH: the person must have a second
// factor, holds none, and the assessment names no risk factor. That is the
// step #906 put `risk: assessment` on. enrolAfterProof() copies step.risk
// too, but only after a factor was proved and the application wants a
// different one; this person holds nothing to prove, so that copy is not
// reached. A password enrolment already stored the assessment before #906
// and would not show the fix.
//
// #899 SENDS curl/8.5.0. A first sign-in scores 1 and an automated client
// multiplies by 10. The helper raises the HIGH line to 15, so that score
// is MEDIUM and risk-medium-key asks for a security key. At the default
// HIGH line of 10, risk-high would refuse the sign-in before a step
// existed. The sign-in names no application, so the console's
// risk-protected-key does not match; both rules are in the document the
// helper installs, and the page that is drawn is what says which answered.
// Somebody who already holds an mfa-role key is asked for a passkey on an
// ordinary second factor too, so the proof is the code doors: both a
// one-time code and a recovery code are enrolled, the page draws neither
// link (a normal step would), and each act refuses STS-AUTHN-0204. The
// request did not set forceKey. The code is recorded and is not in the
// body. A wrong code is also unspent, so the same code is verified
// afterwards.
//
// #906 SENDS A BROWSER. A MEDIUM assessment carrying a key signal, for
// somebody with no mfa-role key, is refused before enrolment; a MEDIUM
// assessment without one asks for a factor they hold. A first sign-in from
// a browser has no evidence signal, so no risk factor is named and the
// set-up step is reached with the assessment on it. The session is not
// required to be LOW. Whatever was assessed is what the session's risk and
// the issuance gate's start-session question must carry, and the gate's
// satisfied list must include second-factor — the check made once the
// authenticator app is confirmed, not the one made when the wallet alone
// had signed in.
//
// IN A CHILD PROCESS because it turns enforcement on, moves the HIGH line,
// writes the issuance policy and creates people the rest of this process
// would see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'risk_key_step_up',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');
  const authnScreen = require(ROOT + '/tests/tools/authn_screen');
  const CODE = 'STS-AUTHN-0204';

  walletKit.boot().then(async function (w) {
    const note = w.note;
    const m = w.m;
    // After the stack: the helper's policy write needs the directory slot
    // ldap_server.js fills, and these are the same modules the stack bound.
    const setup = require(ROOT + '/tests/tools/risk_key_step_up');
    const audit = require(ROOT + '/common/audit');
    const totp = require(ROOT + '/common/totp');
    const helpers = require(ROOT + '/common/helpers');
    const credentials = require(ROOT + '/common/credentials');
    const gate = require(ROOT + '/common/issuance_gate');
    const riskEngine = require(ROOT + '/risk/risk_engine');
    const nodeCrypto = require('crypto');

    function sleep(ms) {
      return new Promise(function (resolve) {
        setTimeout(resolve, ms);
      });
    }

    async function counted(code) {
      await sleep(50);
      return audit.list().filter(function (row) {
        return row.errorCode === code;
      }).length;
    }

    function detailOf(page) {
      const view = page && page.view;
      const answer = (page && page.answer) || page || {};
      const json = (page && page.json) || {};
      const setupView = view && view.setup;
      return JSON.stringify({
        status: page && page.status,
        apiStatus: answer.apiStatus,
        next: answer.next || json.next || '',
        step: answer.step || json.step || '',
        page: view && view.page,
        links: view && view.links,
        setup: setupView ? { state: setupView.state,
                             optional: setupView.optional } : null,
        errors: answer.errors || json.errors || [],
        text: String(answer.text || (page && page.text) || '').slice(0, 500)
      });
    }

    function signalNames(row) {
      return ((row && row.signals) || []).map(function (one) {
        return one && one.signal ? one.signal : one;
      });
    }

    function described(row) {
      if (!row) {
        return 'none';
      }
      return JSON.stringify({ id: row.id, level: row.level,
                              subject: row.subject,
                              signals: signalNames(row) });
    }

    function hasSignal(row, id) {
      return signalNames(row).indexOf(id) >= 0;
    }

    async function assessmentOf(name) {
      const sub = w.inRealm(function () {
        return helpers.subjectForName(name);
      });
      // An empty subject is not "everybody": the view would then be the
      // newest sign-in in the realm, and a later note could pass on
      // somebody else's assessment.
      if (!sub) {
        return null;
      }
      const view = await riskEngine.view(w.DEFAULT.id, { subject: sub });
      const rows = (view && view.assessments &&
                    view.assessments.rows) || [];
      const mine = rows.filter(function (row) {
        return row.subject === sub;
      });
      return mine[0] || null;
    }

    // An mfa-role key, an authenticator app and one recovery code. The key
    // is what lets a security-key step-up ask instead of refusing; the
    // other two are what a normal second-factor step would offer and this
    // one must not. The code spent confirming the app cannot sign in.
    function holdFactors(name) {
      return w.inRealm(function () {
        m.ldap.createUser(name, { invent: false });
        const pair = nodeCrypto.generateKeyPairSync('ec',
          { namedCurve: 'P-256' });
        const jwk = pair.publicKey.export({ format: 'jwk' });
        const added = credentials.addKey(name, {
          credentialId: 'rk-' + name,
          publicKeyJwk: jwk,
          signCount: 0,
          label: 'platform key',
          attachment: 'platform'
        });
        const begun = credentials.beginTotpEnrolment(name,
                                                     { base: w.base });
        let spent = '';
        if (begun.ok && begun.secret) {
          spent = totp.codeAt(begun.secret, Date.now(), begun);
        }
        const confirmed = begun.ok
          ? credentials.confirmTotpEnrolment(name, spent)
          : { ok: false, errors: begun.errors };
        const pending = credentials.beginBackupCodes(name);
        const kept = pending.ok
          ? credentials.confirmBackupCodes(name, pending.handle)
          : { ok: false, errors: pending.errors };
        const backup = (pending.codes && pending.codes[0]) || '';
        return {
          name: name,
          ok: !!(added && added.ok && confirmed && confirmed.ok &&
                 kept && kept.ok && spent && backup),
          why: JSON.stringify({
            key: (added && (added.errors || added.ok)) || added,
            totp: (confirmed && (confirmed.errors || confirmed.ok)) ||
                  confirmed,
            backup: (kept && (kept.errors || kept.ok)) || kept
          }),
          secret: (begun && begun.secret) || '',
          period: (begun && begun.period) || 30,
          digits: begun && begun.digits,
          algorithm: (begun && begun.algorithm) || '',
          spentTotp: spent,
          backup: backup
        };
      });
    }

    // A code the enrolment did not spend. The act's window is 2, so one
    // step later still verifies; posting the enrolment's own code would
    // prove nothing, because that one is already spent.
    function freshTotp(held) {
      if (!held || !held.secret) {
        return '';
      }
      // The same digits and algorithm the enrolment was confirmed with.
      // A code from the defaults is a different code when those differ,
      // and verifying that one would not show the posted code was unspent.
      const opts = { period: held.period, digits: held.digits,
                     algorithm: held.algorithm || undefined };
      let at = Date.now();
      let code = totp.codeAt(held.secret, at, opts);
      let hops = 0;
      while (code === held.spentTotp && hops < 4) {
        at += (held.period || 30) * 1000;
        code = totp.codeAt(held.secret, at, opts);
        hops += 1;
      }
      return code;
    }

    async function passwordStep(name, ua) {
      const id = w.pendingSignIn({});
      const who = w.browser();
      const page = await authnScreen.follow({
        port: w.port, jar: who.cookies, userAgent: ua,
        at: '/authn/login?authn=' + encodeURIComponent(id),
        fields: { action: 'login', username: name,
                  password: 'anything' } });
      return { who: who, page: page };
    }

    // The assessment is made on the browser's status poll (VcSignin.status
    // calls finish, which reads that request's User-Agent). collect()
    // cannot set one, so the poll is posted here.
    async function walletToStep(holder, credential, ua) {
      const who = w.browser();
      const one = await w.start(who, w.pendingSignIn({}));
      if (!one || !one.requestObject || !one.state) {
        return { who: who,
                 page: (one && one.started) || one || {}, one: one };
      }
      const presentation = w.presentSdJwt(credential, holder,
                                          one.requestObject.nonce, aud);
      await w.respond(one, presentation, { format: 'dc+sd-jwt' });
      const raw = await w.request('POST', '/authn-api/wallet/' +
        encodeURIComponent(one.state) + '/status', {
          browser: who,
          json: { authn: one.authn },
          headers: {
            accept: 'application/json',
            origin: w.origin,
            'x-csrf-token': who.csrf || '',
            'user-agent': ua
          }
        });
      const answered = w.formLike(raw);
      const at = String((answered.headers &&
                         answered.headers.location) || '');
      if (answered.status === 303 &&
          /\/authn\/[a-z-]+\?mfa=/.test(at)) {
        const opened = await authnScreen.openStep({
          port: w.port, jar: who.cookies, userAgent: ua, at: at });
        opened.answer = answered;
        return { who: who, page: opened, one: one };
      }
      answered.answer = answered;
      return { who: who, page: answered, one: one };
    }

    async function reopen(who, at, ua) {
      if (!at) {
        return null;
      }
      return authnScreen.openStep({
        port: w.port, jar: who.cookies, userAgent: ua, at: at });
    }

    function refusalOf(posted, before, after) {
      const body = String((posted && posted.text) || '');
      const why = ((posted && posted.errors) || []).join(' ');
      return {
        ok: !!(posted && posted.apiStatus === 400 &&
               posted.next === 'refused' && after === before + 1 &&
               body.indexOf(CODE) < 0 && /demands a passkey/.test(why)),
        why: why,
        apiStatus: posted && posted.apiStatus,
        next: posted && posted.next,
        before: before,
        after: after,
        bodyHasCode: body.indexOf(CODE) >= 0
      };
    }

    // `prove` runs after the refusal and says whether the code is still
    // good. The step is kept on a refusal, so the same id is posted twice;
    // the page is opened again between them because the token is taken
    // from the cookie the last answer set.
    async function codeDoor(refusedWhat, unspentWhat, who, opened, ua, op,
                            code, prove) {
      if (!opened || !opened.id || !code) {
        note(false, refusedWhat,
             !code ? 'no code was enrolled' : detailOf(opened));
        note(false, unspentWhat,
             !code ? 'no code was enrolled' : detailOf(opened));
        return;
      }
      const before = await counted(CODE);
      const posted = await authnScreen.stepAct({
        port: w.port, jar: who.cookies, userAgent: ua, opened: opened,
        op: op, body: { code: code } });
      const after = await counted(CODE);
      const answer = refusalOf(posted, before, after);
      note(answer.ok && !w.sessionOf(who), refusedWhat,
           JSON.stringify(answer));
      const proof = await prove();
      note(proof.ok === true, unspentWhat, JSON.stringify(proof));
    }

    async function totpStillGood(name, code) {
      const verified = await w.inRealm(function () {
        return credentials.verifyTotpAsync(name, code);
      });
      return { ok: !!(verified && verified.ok),
               reason: verified && (verified.reason || verified.errors) };
    }

    async function backupStillGood(name, code, beforeLeft) {
      const afterLeft = w.inRealm(function () {
        return credentials.backupCodeStatus(name).remaining;
      });
      const verified = await w.inRealm(function () {
        return credentials.verifyBackupCodeAsync(name, code);
      });
      const spentLeft = w.inRealm(function () {
        return credentials.backupCodeStatus(name).remaining;
      });
      return {
        ok: afterLeft === beforeLeft && beforeLeft > 0 &&
            !!(verified && verified.ok) && spentLeft === beforeLeft - 1,
        beforeLeft: beforeLeft,
        afterLeft: afterLeft,
        spentLeft: spentLeft,
        verified: !!(verified && verified.ok)
      };
    }

    async function mediumAutomated(name, what) {
      const row = await assessmentOf(name);
      note(!!(row && row.level === 'MEDIUM' &&
              hasSignal(row, 'automated-client')), what, described(row));
    }

    async function keyDemand(who, page, ua, held, totpRefused, totpUnspent,
                             backupRefused, backupUnspent) {
      const view = page && page.view;
      const links = view && view.links;
      const hidden = !!(view && view.page === 'webauthn' && links &&
                        links.totp === false && links.backup === false &&
                        !w.sessionOf(who));
      note(hidden,
           held.name + ' is asked for the passkey, with neither code ' +
           'door drawn, though both are enrolled and the request ' +
           'demanded no key',
           detailOf(page));
      const at = (page && page.at) ||
        (page && page.answer && page.answer.location) || '';
      const totpCode = freshTotp(held);
      await codeDoor(totpRefused, totpUnspent, who, page, ua, 'totp',
                     totpCode, function () {
        return totpStillGood(held.name, totpCode);
      });
      const again = await reopen(who, at, ua);
      const beforeLeft = w.inRealm(function () {
        return credentials.backupCodeStatus(held.name).remaining;
      });
      await codeDoor(backupRefused, backupUnspent, who, again, ua,
                     'backup-code', held.backup, function () {
        return backupStillGood(held.name, held.backup, beforeLeft);
      });
    }

    async function cases() {
      const armed = setup.arm();
      const rules = (armed && armed.rules) || [];
      note(!!(armed && armed.ok === true &&
              rules.indexOf('risk-medium-key') >= 0 &&
              rules.indexOf('risk-protected-key') >= 0),
           '0. the shipped role-issuance document is installed, ' +
           'including risk-medium-key and risk-protected-key',
           armed && armed.ok ? rules.join(',') : (armed && armed.why));
      if (!armed || armed.ok !== true) {
        return;
      }
      const windowed = w.inRealm(function () {
        return w.m.config.setOverride('totp.window', 2);
      });
      note(!!(windowed && windowed.ok === true),
           '0b. totp.window is 2, so a code one step after enrolment ' +
           'still verifies',
           JSON.stringify((windowed && windowed.errors) || windowed));
      w.inRealm(function () {
        w.provision();
      });
      aud = await w.signInAudience();
      const passwordHeld = holdFactors('rk-pw');
      note(passwordHeld.ok,
           '0c. the password sign-in holds an mfa-role key, an ' +
           'authenticator app and a recovery code',
           passwordHeld.why);
      const walletHeld = holdFactors('rk-wallet');
      note(walletHeld.ok,
           '0d. the wallet sign-in holds an mfa-role key, an ' +
           'authenticator app and a recovery code',
           walletHeld.why);

      const pw = await passwordStep('rk-pw', armed.userAgent);
      await mediumAutomated('rk-pw',
        '1. the password sign-in from an automated client is MEDIUM, ' +
        'with automated-client, so risk-medium-key is the rule that ' +
        'can answer');
      await keyDemand(pw.who, pw.page, armed.userAgent, passwordHeld,
        '1c. a valid one-time code posted to the password step is ' +
        'refused STS-AUTHN-0204, recorded and absent from the body',
        '1d. that one-time code was not checked: the same code still ' +
        'verifies',
        '1e. an unspent recovery code posted to the password step is ' +
        'refused STS-AUTHN-0204, recorded and absent from the body',
        '1f. that recovery code was not checked: it was unspent across ' +
        'the refusal and still verifies');

      const walletKey = w.holderKey();
      const walletCred = await w.issue('rk-wallet', walletKey);
      note(!!walletCred.credential,
           '0e. rk-wallet holds a wallet credential',
           walletCred.error || '');
      const wallet = walletCred.credential
        ? await walletToStep(walletKey, walletCred.credential,
                             armed.userAgent)
        : { who: w.browser(),
            page: { text: walletCred.error || 'no credential' } };
      await mediumAutomated('rk-wallet',
        '2. the wallet sign-in from an automated client is MEDIUM, ' +
        'with automated-client — the poll carried the User-Agent');
      await keyDemand(wallet.who, wallet.page, armed.userAgent, walletHeld,
        '2c. a valid one-time code posted to the wallet step is ' +
        'refused STS-AUTHN-0204, recorded and absent from the body',
        '2d. that one-time code was not checked: the same code still ' +
        'verifies',
        '2e. an unspent recovery code posted to the wallet step is ' +
        'refused STS-AUTHN-0204, recorded and absent from the body',
        '2f. that recovery code was not checked: it was unspent across ' +
        'the refusal and still verifies');

      await enrolAfterWallet(armed.browserUserAgent);
    }

    // The required set-up after a wallet. The gate is wrapped only around
    // the confirm, so the check recorded is the session's start and not
    // the one beginSecondFactorAfterWallet made when the wallet alone had
    // signed in (that one satisfies nothing).
    async function enrolAfterWallet(ua) {
      const name = 'rk-enrol';
      w.inRealm(function () {
        m.ldap.createUser(name, { invent: false });
      });
      const required = w.inRealm(function () {
        return credentials.setMfaRequired(name, true);
      });
      const key = w.holderKey();
      const issued = await w.issue(name, key);
      note(!!(required && required.ok && issued.credential),
           '3-pre. somebody who must have a second factor, and holds ' +
           'none, holds a wallet credential',
           (required && required.ok) ? (issued.error || '')
                                     : JSON.stringify(required));
      const missed = 'the set-up step was not reached';
      if (!issued.credential) {
        note(false, '3a. a browser wallet sign-in is the required ' +
                    'set-up step',
             issued.error || missed);
        note(false, '3b. confirming an authenticator app signs in', missed);
        note(false, '3c. the session carries that sign-in\'s assessment',
             missed);
        note(false,
             '3d. the issuance gate is asked with that assessment and ' +
             'second-factor satisfied', missed);
        return;
      }
      const landed = await walletToStep(key, issued.credential, ua);
      const view = landed.page && landed.page.view;
      const choice = view && view.setup;
      const onSetup = !!(view && view.page === 'setup' && choice &&
                         choice.state === 'choose' &&
                         choice.optional === false &&
                         !w.sessionOf(landed.who));
      note(onSetup,
           '3a. a browser wallet sign-in by somebody who must have a ' +
           'second factor and holds none is the required set-up step, ' +
           'and no session exists yet',
           detailOf(landed.page));
      if (!onSetup || !landed.page || !landed.page.id) {
        note(false, '3b. confirming an authenticator app signs in',
             detailOf(landed.page));
        note(false, '3c. the session carries that sign-in\'s assessment',
             detailOf(landed.page));
        note(false,
             '3d. the issuance gate is asked with that assessment and ' +
             'second-factor satisfied', detailOf(landed.page));
        return;
      }
      const begun = await authnScreen.stepAct({
        port: w.port, jar: landed.who.cookies, userAgent: ua,
        opened: landed.page, op: 'setup/totp', body: {} });
      if (begun.next !== 'mfa' || !begun.location) {
        note(false, '3b. confirming an authenticator app signs in',
             JSON.stringify({ next: begun.next, text: begun.text }));
        note(false, '3c. the session carries that sign-in\'s assessment',
             begun.text);
        note(false,
             '3d. the issuance gate is asked with that assessment and ' +
             'second-factor satisfied', begun.text);
        return;
      }
      const enrolling = await authnScreen.openStep({
        port: w.port, jar: landed.who.cookies, userAgent: ua,
        at: begun.location });
      const shown = enrolling.view && enrolling.view.setup &&
                    enrolling.view.setup.totp;
      const uri = shown && shown.uri;
      const secret = uri
        ? (new URL(String(uri)).searchParams.get('secret') || '') : '';
      if (!secret) {
        note(false, '3b. confirming an authenticator app signs in',
             'the set-up view carried no otpauth secret');
        note(false, '3c. the session carries that sign-in\'s assessment',
             detailOf(enrolling));
        note(false,
             '3d. the issuance gate is asked with that assessment and ' +
             'second-factor satisfied', detailOf(enrolling));
        return;
      }
      const code = totp.codeAt(secret, Date.now(), {
        period: (shown && shown.period) || 30,
        digits: shown && shown.digits
      });
      const seen = [];
      const realCheck = gate.check;
      gate.check = function (request) {
        const facts = request && request.risk;
        seen.push({
          kind: request && request.kind,
          level: facts ? facts.level : '',
          assessmentId: facts ? facts.assessmentId : '',
          satisfied: facts && facts.satisfied ? facts.satisfied.slice()
                                              : []
        });
        return realCheck(request);
      };
      let confirmed = null;
      try {
        confirmed = await authnScreen.stepAct({
          port: w.port, jar: landed.who.cookies, userAgent: ua,
          opened: enrolling, op: 'setup/confirm', body: { code: code }
        });
      } finally {
        gate.check = realCheck;
      }
      const session = w.sessionOf(landed.who);
      const risk = session && session.risk;
      const row = await assessmentOf(name);
      const same = !!(session && session.user &&
                      session.user.username === name && risk && row &&
                      String(risk.assessmentId) === String(row.id) &&
                      String(risk.level) === String(row.level));
      note(!!(confirmed && confirmed.next === 'redirect'),
           '3b. confirming the authenticator app signs in',
           confirmed && confirmed.text);
      note(same,
           '3c. the session carries that sign-in\'s assessment',
           JSON.stringify({
             user: session && session.user && session.user.username,
             risk: risk || null,
             row: row ? { id: row.id, level: row.level,
                          signals: signalNames(row) } : null
           }));
      const hit = seen.filter(function (one) {
        return !!risk && one.kind === gate.ISSUANCE.SESSION &&
          String(one.assessmentId) === String(risk.assessmentId) &&
          String(one.level) === String(risk.level) &&
          (one.satisfied || []).indexOf('second-factor') >= 0;
      });
      note(same && hit.length >= 1,
           '3d. the issuance gate\'s start-session question carries ' +
           'that assessment, and second-factor is satisfied',
           JSON.stringify(seen));
    }

    let aud = '';
    try {
      await cases();
    } catch (e) {
      note(false, 'the child ran to the end',
           e && (e.stack || e.message));
    }
    await w.finish(OUT);
    process.exit(0);
  }).catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify([
      { ok: false, what: 'the child booted', detail: e && e.stack }]));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'risk-key-step-up');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risk_key_step_up',
  describe: 'a security key demanded on risk refuses a one-time code and ' +
            'a recovery code before either is checked (STS-AUTHN-0204, ' +
            'recorded, not sent), after a password and after a wallet, ' +
            'and a second-factor set-up after a wallet keeps that ' +
            'sign-in\'s risk assessment on the session and the issuance ' +
            'gate',
  run: run
};
