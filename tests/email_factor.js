'use strict';
//
// File: email_factor.js
//
// ===========================================================================
// THE EMAILED CODE AND THE EMAILED SIGN-IN LINK (#64, 2026-09-23), over HTTP
// against the whole stack in a child process, reading what was mailed from
// the capture transport — development mode's.
//
// `authn/email_factor.ts` and `common/mail_factor.ts` argue the design. What
// is held here:
//
//   1. OFF BY DEFAULT: with the built-in policy the sign-in screen offers no
//      emailed first factor, and a hand-made POST asking for one is refused.
//   2. THE OPT-IN (D8): refused for an unverified address; accepted for a
//      verified one; it makes the person a second-factor holder.
//   3. A CODE AS THE SECOND FACTOR: the password step mails a code and asks
//      for it; the step holds a HASH and never the code; a wrong code keeps
//      the step and counts down; the right one signs in with amr
//      ["pwd","otp"], acr "mfa" and the credential kind email-code; it
//      works once.
//   4. THE STEP ENDS after the policy's number of wrong codes, and a resend
//      sooner than the policy's interval is refused.
//   5. A CODE AS THE FIRST FACTOR: amr ["otp"], acr "1"; and the page for an
//      unknown account, or one with no verified address, is the SAME page
//      and mails nothing.
//   6. A LINK: the GET spends nothing; opened in another browser (no binding
//      cookie) it signs nobody in; in the right one Continue signs in; the
//      waiting page then says the sign-in went on elsewhere.
//   7. THE FAILURE LIMIT (section 3.2.2): at the policy's limit the person's
//      emailed factor is turned off.
//   8. NO MAIL, NO BUTTON: in a realm that cannot send mail, nothing emailed
//      is offered, whatever the policy says.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'email_factor',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.EF_ROOT;
  const OUT = process.env.EF_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, form, cookie) {
    return new Promise(function (resolve) {
      const body = form ? new URLSearchParams(form).toString() : '';
      const headers = {};
      if (cookie) {
        headers.cookie = cookie;
      }
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          resolve({ status: res.statusCode, headers: res.headers,
                    text: text });
        });
      });
      req.end(body);
    });
  }

  function sleep(ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const credentials = require(ROOT + '/common/credentials');
    const ldapServer = require(ROOT + '/ldap/ldap_server');
    const authn = require(ROOT + '/authn/authn');
    const mail = require(ROOT + '/common/mail');
    const mailFactor = require(ROOT + '/common/mail_factor');
    const authnPolicy = require(ROOT + '/common/authn_policy');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    await realms.run(realms.DEFAULT_REALM, async function () {
      config.setOverride('global.publicBaseUrl', 'http://127.0.0.1:' + port);
      // Generous limits for a test that signs in many times from one address.
      config.setOverride('security.rateLimitPerIdentity', '200');
      config.setOverride('security.rateLimitPerAddress', '1000');

      const person = function (name, address, verified) {
        ldapServer.createUser(name, {});
        credentials.setPassword(name, 'Email-Factor-1!');
        mail.directory().writeAddress(name, address,
                                      verified ? 'admin' : '');
      };
      person('ef-amy', 'amy@example.com', true);
      person('ef-bo', 'bo@example.com', true);
      person('ef-cy', 'cy@example.com', true);
      person('ef-dee', 'dee@example.com', false);
      person('ef-eve', 'eve@example.com', true);

      const startSignIn = async function () {
        const got = await request(port, 'GET', '/oauth2/authorize?' +
          new URLSearchParams({ client_id: 'ef-client',
                                response_type: 'code',
                                redirect_uri: 'https://rp.ef.example/cb',
                                scope: 'openid', state: 's' }).toString());
        const location = String(got.headers.location || '');
        return (location.match(/[?&]authn=([^&]+)/) || [])[1] || '';
      };
      const cookieOf = function (res, name) {
        return [].concat(res.headers['set-cookie'] || []).map(function (one) {
          return String(one).split(';')[0];
        }).filter(function (one) {
          return one.indexOf((name || 'sts_session') + '=') === 0 &&
                 one.split('=')[1];
        })[0] || '';
      };
      const mfaIdOf = function (res) {
        return (res.text.match(/name="mfa_id" value="([^"]+)"/) || [])[1] ||
          '';
      };
      // The newest captured message to `who` with `subject` matching.
      const mailed = async function (who, subject, after) {
        for (let i = 0; i < 60; i += 1) {
          const rows = mail.list({ username: who }).filter(function (row) {
            return subject.test(String(row.subject || '')) &&
                   (after || []).indexOf(row.id) < 0;
          });
          if (rows.length) {
            return mail.message(rows[0].id);
          }
          await sleep(25);
        }
        return null;
      };
      const idsFor = function (who) {
        return mail.list({ username: who }).map(function (row) {
          return row.id;
        });
      };
      const codeIn = function (message) {
        return ((message && message.text || '').match(/\b(\d{6})\b/) ||
                [])[1] || '';
      };

      // ==================================================================
      // 1. OFF BY DEFAULT
      // ==================================================================
      let authnId = await startSignIn();
      let r = await request(port, 'GET', '/authn/login?authn=' + authnId);
      note(r.status === 200 && !/kc-email-code/.test(r.text) &&
           !/kc-email-link/.test(r.text),
           '1a. the built-in policy offers no emailed first factor',
           r.status);
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ef-bo', action: 'email-code' });
      note(r.status === 200 && /does not offer an emailed code/.test(r.text) &&
           !cookieOf(r),
           '1b. a hand-made POST asking for one is refused at the door',
           r.status + ' ' + r.text.slice(0, 200));

      const opened = authnPolicy.save('default', Object.assign({},
        authnPolicy.DEFAULTS, { emailCodePrimary: true,
          emailCodeSecondFactor: true, emailLinkPrimary: true,
          emailLinkSecondFactor: true, emailCodeAttempts: 3,
          emailResendS: 15, emailFailureLimit: 5 }));
      note(opened.ok, '1c. the policy turns all four on (mail works here)',
           JSON.stringify(opened.errors));

      // ==================================================================
      // 2. THE OPT-IN
      // ==================================================================
      const refusedOpt = mailFactor.optIn('ef-dee', 'code', 'ef-dee', 'test');
      note(!refusedOpt.ok && /not verified/.test(refusedOpt.errors[0]),
           '2a. an unverified address cannot be opted in',
           JSON.stringify(refusedOpt));
      note(mailFactor.optIn('ef-amy', 'code', 'ef-amy', 'test').ok &&
           credentials.mechanismsFor('ef-amy').mfaRequired &&
           credentials.mechanismsFor('ef-amy').secondFactor === 'email-code',
           '2b. a verified one is, and makes the person a second-factor ' +
           'holder asked for an emailed code');

      // ==================================================================
      // 3. A CODE AS THE SECOND FACTOR
      // ==================================================================
      let before = idsFor('ef-amy');
      authnId = await startSignIn();
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ef-amy',
          password: 'Email-Factor-1!', action: 'login' });
      let mfaId = mfaIdOf(r);
      note(r.status === 200 && /Check your email/.test(r.text) && mfaId &&
           !cookieOf(r),
           '3a. the password step mails a code and asks for it, and starts ' +
           'no session', r.status + ' ' + r.text.slice(0, 160));
      let message = await mailed('ef-amy', /sign-in code/, before);
      let code = codeIn(message);
      const step = authn.mfaStepFor(mfaId);
      note(code && step && step.emailState &&
           step.emailState.hash && step.emailState.hash !== code &&
           JSON.stringify(step).indexOf(code) < 0,
           '3b. the code was mailed, and the step holds a HASH of it and ' +
           'never the code', code);
      note(message && message.to === 'amy@example.com' &&
           /You received this because/.test(message.text),
           '3c. to the verified address, in the standard layout',
           message && message.to);
      const wrong = code === '000000' ? '111111' : '000000';
      r = await request(port, 'POST', '/authn/email-code',
        { mfa_id: mfaId, action: 'verify', code: wrong });
      note(r.status === 200 && /2 more attempt/.test(r.text) && !cookieOf(r),
           '3d. a wrong code keeps the step and counts down', r.status);
      r = await request(port, 'POST', '/authn/email-code',
        { mfa_id: mfaId, action: 'verify',
          code: code.slice(0, 3) + ' ' + code.slice(3) });
      const amySession = authn.sessionsOf('ef-amy')[0];
      const lastEvent = amySession && amySession.events &&
        amySession.events[amySession.events.length - 1];
      note((r.status === 302 || r.status === 303) && !!cookieOf(r) &&
           amySession && JSON.stringify(amySession.amr) === '["pwd","otp"]' &&
           amySession.acr === 'mfa' && lastEvent && lastEvent.context &&
           lastEvent.context.credential &&
           lastEvent.context.credential.kind === 'email-code',
           '3e. the right code (typed with a space) signs in: amr ' +
           '["pwd","otp"], acr "mfa", credential kind email-code',
           r.status + ' ' + JSON.stringify(amySession && {
             amr: amySession.amr, acr: amySession.acr }));
      r = await request(port, 'POST', '/authn/email-code',
        { mfa_id: mfaId, action: 'verify', code: code });
      note(r.status === 400 && !cookieOf(r),
           '3f. and it works once: the step is spent', r.status);

      // ==================================================================
      // 4. THE STEP ENDS, AND A RESEND TOO SOON IS REFUSED
      // ==================================================================
      authnId = await startSignIn();
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ef-amy',
          password: 'Email-Factor-1!', action: 'login' });
      mfaId = mfaIdOf(r);
      r = await request(port, 'POST', '/authn/email-code',
        { mfa_id: mfaId, action: 'send' });
      note(r.status === 200 && /seconds ago/.test(r.text),
           '4a. another code sooner than emailResendS is refused', r.status);
      for (let i = 0; i < 3; i += 1) {
        r = await request(port, 'POST', '/authn/email-code',
          { mfa_id: mfaId, action: 'verify', code: '999999' });
      }
      note(r.status === 400 && /Too many wrong codes/.test(r.text) &&
           !authn.mfaStepFor(mfaId),
           '4b. at emailCodeAttempts wrong codes the step ENDS',
           r.status + ' ' + r.text.slice(0, 120));

      // ==================================================================
      // 5. A CODE AS THE FIRST FACTOR, AND THE DECOY
      // ==================================================================
      before = idsFor('ef-bo');
      authnId = await startSignIn();
      r = await request(port, 'GET', '/authn/login?authn=' + authnId);
      note(/kc-email-code/.test(r.text) && /kc-email-link/.test(r.text),
           '5a. with the policy on, the sign-in screen offers both');
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ef-bo', action: 'email-code' });
      mfaId = mfaIdOf(r);
      const realPage = r.text.replace(/value="[A-Za-z0-9_-]{20,}"/g, 'ID');
      message = await mailed('ef-bo', /sign-in code/, before);
      code = codeIn(message);
      r = await request(port, 'POST', '/authn/email-code',
        { mfa_id: mfaId, action: 'verify', code: code });
      const boSession = authn.sessionsOf('ef-bo')[0];
      note((r.status === 302 || r.status === 303) && boSession &&
           JSON.stringify(boSession.amr) === '["otp"]' &&
           boSession.acr === '1',
           '5b. an emailed code alone signs in with amr ["otp"], acr "1"',
           JSON.stringify(boSession && { amr: boSession.amr,
                                         acr: boSession.acr }));
      const pages = [];
      for (const who of ['ef-nobody-here', 'ef-dee']) {
        const beforeWho = idsFor(who);
        authnId = await startSignIn();
        r = await request(port, 'POST', '/authn/login',
          { authn_id: authnId, username: who, action: 'email-code' });
        pages.push(r.text.replace(/value="[A-Za-z0-9_-]{20,}"/g, 'ID')
          .replace(new RegExp(who, 'g'), 'WHO'));
        await sleep(100);
        note(idsFor(who).length === beforeWho.length,
             '5c. nothing is mailed for ' + who);
      }
      note(pages[0] === pages[1] &&
           pages[0] === realPage.replace(/ef-bo/g, 'WHO'),
           '5d. and the page is the SAME for an unknown account, one with no ' +
           'verified address, and a real one — no enumeration');

      // ==================================================================
      // 6. A LINK
      // ==================================================================
      note(mailFactor.optIn('ef-cy', 'link', 'ef-cy', 'test').ok,
           '6a. ef-cy opts in to a link');
      before = idsFor('ef-cy');
      authnId = await startSignIn();
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ef-cy',
          password: 'Email-Factor-1!', action: 'login' });
      mfaId = mfaIdOf(r);
      const binding = cookieOf(r, 'sts_email_binding');
      note(r.status === 200 && /Open it in this browser/.test(r.text) &&
           /http-equiv="refresh"/.test(r.text) && binding,
           '6b. the waiting page, refreshed by a meta tag, and a binding ' +
           'cookie', r.status);
      message = await mailed('ef-cy', /sign-in link/, before);
      const link = ((message && message.text || '')
        .match(/(http:\/\/127\.0\.0\.1:\d+\S*email-link\/open\S*)/) ||
        [])[1] || '';
      const linkPath = link.replace(/^http:\/\/127\.0\.0\.1:\d+/, '');
      note(link && message.to === 'cy@example.com',
           '6c. the link is mailed on the pinned origin', link);
      r = await request(port, 'GET', linkPath);
      note(r.status === 400 && /where you started/.test(r.text) &&
           !cookieOf(r) && authn.mfaStepFor(mfaId),
           '6d. opened in ANOTHER browser it signs nobody in and spends ' +
           'nothing', r.status);
      r = await request(port, 'GET', linkPath, null, binding);
      const t = (r.text.match(/name="t" value="([^"]+)"/) || [])[1] || '';
      note(r.status === 200 && /Continue/.test(r.text) && t &&
           authn.mfaStepFor(mfaId) && !cookieOf(r),
           '6e. in the right one the GET draws Continue and spends nothing — ' +
           'a mail scanner fetching it signs nobody in', r.status);
      r = await request(port, 'POST', '/authn/email-link/open',
        { mfa_id: mfaId, t: t });
      note(r.status === 400 && !cookieOf(r),
           '6f. a POST without the binding cookie is refused too', r.status);
      r = await request(port, 'POST', '/authn/email-link/open',
        { mfa_id: mfaId, t: t }, binding);
      const cySession = authn.sessionsOf('ef-cy')[0];
      note((r.status === 302 || r.status === 303) && cySession &&
           JSON.stringify(cySession.amr) === '["pwd","otp"]',
           '6g. with it, Continue signs in', r.status);
      r = await request(port, 'GET', '/authn/email-link?mfa=' + mfaId);
      note(/continued in the tab/.test(r.text),
           '6h. and the waiting page says the sign-in went on in the tab ' +
           'the link opened');

      // ==================================================================
      // 7. THE FAILURE LIMIT
      // ==================================================================
      note(mailFactor.optIn('ef-eve', 'code', 'ef-eve', 'test').ok,
           '7a. ef-eve opts in');
      for (let round = 0; round < 2; round += 1) {
        authnId = await startSignIn();
        r = await request(port, 'POST', '/authn/login',
          { authn_id: authnId, username: 'ef-eve',
            password: 'Email-Factor-1!', action: 'login' });
        mfaId = mfaIdOf(r);
        for (let i = 0; i < 3; i += 1) {
          await request(port, 'POST', '/authn/email-code',
            { mfa_id: mfaId, action: 'verify', code: '999999' });
        }
      }
      const eve = mailFactor.status('ef-eve');
      note(!eve.optedIn && !credentials.mechanismsFor('ef-eve').mfaRequired,
           '7b. at emailFailureLimit consecutive failures the person\'s ' +
           'emailed factor is turned OFF (NIST SP 800-63B-4 section 3.2.2)',
           JSON.stringify(eve));

      // ==================================================================
      // 8. NO MAIL, NO BUTTON
      // ==================================================================
      config.setOverride('mail.transport', 'off');
      try {
        authnId = await startSignIn();
        r = await request(port, 'GET', '/authn/login?authn=' + authnId);
        note(!/kc-email-code/.test(r.text) && !/kc-email-link/.test(r.text) &&
             !credentials.mechanismsFor('ef-amy').mailFactor.held,
             '8a. where mail is not working nothing emailed is offered, and ' +
             'nobody holds an emailed factor');
      } finally {
        config.clearOverride('mail.transport');
      }
      authnPolicy.reset('default');
    });
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify(findings.concat([
      { ok: false, what: 'the child ran to the end', detail: e && e.stack }])));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'email-factor-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ADMIN_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', EF_ROOT: ROOT,
                                  EF_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

module.exports = {
  name: 'email factor',
  describe: 'The emailed code and sign-in link (#64): off by default, the ' +
            'opt-in, a code as the second and the first factor, the step ' +
            'limits, the decoy, a link bound to its browser, the failure ' +
            'limit, and nothing offered without mail',
  run: async function (t) {
    log.debug("Entering run().");
    inAChild(t);
    log.debug("Leaving run().");
  }
};
