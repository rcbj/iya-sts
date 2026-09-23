'use strict';
//
// File: risk_response.js
//
// ===========================================================================
// WHAT A CHANGE OF RISK LEADS TO, AND LIVE SESSIONS WATCHED (#62 P4,
// 2026-09-22).
//
// rcbj's directive: every authorization decision is XACML policy. The
// reactions to a person's risk level CHANGING are rules in the built-in
// `risk-response` policy (`xacml/xacml_risk_pep.ts` asks it once per
// reaction), and `risk/risk_engine.ts` takes what it permits. What this
// holds:
//
//   A. THE POLICY: announce, end-sessions and credential-compromise by
//      default, and a disable rule only when `disableFromScore` is given;
//      both shapes survive the XML and ALFA round trips.
//   B. ITS DECISIONS: a first LOW is not announced; a change is; crossing
//      into HIGH ends everything; on evidence about a credential RISC is
//      told too; staying HIGH, nothing; coming down, announced only.
//   C. THE REACTIONS TAKEN, where enforced: crossing into HIGH ends every
//      session the person holds — once per assessment, however many times
//      the change is answered.
//   D. DEVELOPMENT OBSERVES: the same change ends nothing, and says so.
//   E. A REALM'S OWN POLICY decides: an override with a disable rule
//      disables the account; deleting it puts the built-in one back.
//   F. CAEP can emit risk-level-change on its own now.
//   G. CONTINUOUS EVALUATION: a browser that updated itself is the same
//      device and is not assessed again; the cookie presented from another
//      browser on another system is (phase `session`), scores HIGH against
//      a thin history, and — enforced — ends everything the person held.
//   H. THE `risk.rescore` JOB raises a live session whose address has since
//      become a Tor exit, and never lowers one.
//   I. WHAT THE PERSON SAID (#62 P6): "this was me" from the flagged session
//      moves nothing, from another low-risk session lowers the standing;
//      "this wasn't me" puts it at HIGH and ends every session; a sign-in is
//      answered once, and only by its own person.
//
// In a child process, for `risk_decisions.js`'s reason. Every list is
// synthetic; the one address on them is the loopback.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'risk_response',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.RR_ROOT;
  const OUT = process.env.RR_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
  const FIREFOX = 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) ' +
    'Gecko/20100101 Firefox/140.0';

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const authn = require(ROOT + '/authn/authn');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const helpers = require(ROOT + '/common/helpers');
    const accountState = require(ROOT + '/common/account_state');
    const templates = require(ROOT + '/xacml/xacml_templates');
    const xacmlXml = require(ROOT + '/xacml/xacml_xml');
    const alfa = require(ROOT + '/xacml/xacml_alfa');
    const xacmlStore = require(ROOT + '/xacml/xacml_store');
    const riskPep = require(ROOT + '/xacml/xacml_risk_pep');
    const caep = require(ROOT + '/ssf/caep');
    const riskEngine = require(ROOT + '/risk/risk_engine');
    const riskStore = require(ROOT + '/risk/risk_store');
    const riskDatasets = require(ROOT + '/risk/risk_datasets');
    const riskTerms = require(ROOT + '/risk/risk_terms');

    config.setOverride('risk.enforceInDevelopment', true);
    config.setOverride('risk.datasetShrinkLimitPercent', 100);
    // Scored from the second sign-in: G2 re-assesses a live session
    // against a history of one sign-in, which risk.minimumHistory (5 by
    // default) would leave UNSCORED.
    config.setOverride('risk.minimumHistory', 1);

    // A response the sign-in service can set a cookie on, keeping it.
    const response = function () {
      const res = { cookie: '', req: null };
      res.set = function (name, value) {
        if (String(name).toLowerCase() === 'set-cookie') {
          res.cookie = String(Array.isArray(value) ? value[0] : value)
            .split(';')[0];
        }
        return res;
      };
      res.append = res.set;
      res.status = function () { return res; };
      res.type = function () { return res; };
      res.send = function () { return res; };
      return res;
    };
    const request = function (userAgent, cookie) {
      return { headers: { 'user-agent': userAgent, cookie: cookie || '' },
               socket: { remoteAddress: '127.0.0.1' }, ip: '127.0.0.1' };
    };
    // A person signed in, in process, with an assessment of their sign-in.
    const signIn = async function (username, userAgent) {
      const req = request(userAgent);
      const assessment = await audit.withSource({ req: req }, function () {
        return authn.assessSignIn(req, username, 'a test', {});
      });
      const res = response();
      const session = audit.withSource({ req: req }, function () {
        return authn.startSession(res, username, ['pwd'], '1', 'a test',
                                  { request: req, risk: assessment });
      });
      return { session: session, cookie: res.cookie, assessment: assessment };
    };

    // --- A. the policy ------------------------------------------------------
    const ruleSlugs = function (built) {
      return (built.policy ? built.policy.rules : []).map(function (r) {
        return r.id.split(':rule:')[1];
      }).join(',');
    };
    const plain = templates.build('risk-response', {},
                                  { name: 'risk-response' });
    const withDisable = templates.build('risk-response',
      { disableFromScore: '10' }, { name: 'risk-response' });
    note(ruleSlugs(plain) === 'announce,end-sessions,credential-compromise',
         'A1. the built-in policy announces, ends sessions and tells RISC — ' +
         'and has no disable rule', ruleSlugs(plain));
    note(ruleSlugs(withDisable) === 'announce,end-sessions,' +
         'credential-compromise,disable',
         'A2. a disable rule exists only when a score is given',
         ruleSlugs(withDisable));
    let roundTrips = true;
    let roundTripWhy = '';
    [plain, withDisable].forEach(function (built) {
      try {
        xacmlXml.parsePolicy(xacmlXml.writePolicy(built.policy));
        alfa.parse(alfa.write(built.policy));
      } catch (e) {
        roundTrips = false;
        roundTripWhy = e.message;
      }
    });
    note(roundTrips, 'A3. both shapes survive the XML and ALFA round trips',
         roundTripWhy);

    // --- B. its decisions ---------------------------------------------------
    const reactions = function (change) {
      return riskPep.decide(Object.assign({ username: 'rr-nobody',
        score: 2, signals: [] }, change)).reactions.join(',');
    };
    note(reactions({ level: 'LOW', previousLevel: '' }) === '',
         'B1. a person\'s first level, LOW, is not announced');
    note(reactions({ level: 'MEDIUM', previousLevel: 'LOW' }) ===
           'risk-announce',
         'B2. LOW to MEDIUM is announced, and nothing else');
    note(reactions({ level: 'HIGH', previousLevel: 'MEDIUM',
                     signals: ['tor-exit'] }) ===
           'risk-announce,risk-end-sessions',
         'B3. crossing into HIGH ends everything the person holds');
    note(reactions({ level: 'HIGH', previousLevel: 'MEDIUM',
                     signals: ['account-failures'] }) ===
           'risk-announce,risk-end-sessions,risk-credential-compromise',
         'B4. and on evidence about a credential, RISC is told it is ' +
         'compromised');
    note(reactions({ level: 'HIGH', previousLevel: 'HIGH' }) === '' &&
         reactions({ level: 'LOW', previousLevel: 'HIGH' }) ===
           'risk-announce',
         'B5. staying HIGH does nothing; coming down is announced');

    // --- C. the reactions taken ---------------------------------------------
    ldap.createUser('rr-alice', { invent: false });
    const aliceSub = helpers.subjectForName('rr-alice');
    await signIn('rr-alice', CHROME);
    await signIn('rr-alice', CHROME);
    const heldBefore = authn.sessionsOf('rr-alice').length;
    const change = { realm: 'default', subject: aliceSub,
      username: 'rr-alice', level: 'HIGH', previousLevel: 'MEDIUM',
      score: 20, signals: ['account-failures'], assessmentId: 'rr-c1' };
    const first = await riskEngine.respond(change);
    note(heldBefore === 2 && !authn.sessionsOf('rr-alice').length &&
         first.taken.indexOf('risk-end-sessions') >= 0 &&
         first.taken.indexOf('risk-credential-compromise') >= 0,
         'C1. crossing into HIGH ends both sessions the person held, and ' +
         'RISC is told', heldBefore + ' ' + JSON.stringify(first));
    await signIn('rr-alice', CHROME);
    const again = await riskEngine.respond(change);
    note(!again.taken.length && authn.sessionsOf('rr-alice').length === 1,
         'C2. answering the same change again takes nothing — a reaction is ' +
         'claimed once per assessment', JSON.stringify(again));

    // --- D. development observes --------------------------------------------
    config.setOverride('risk.enforceInDevelopment', false);
    const observed = await riskEngine.respond(Object.assign({}, change,
                                              { assessmentId: 'rr-d1' }));
    note(observed.observed.indexOf('risk-end-sessions') >= 0 &&
         authn.sessionsOf('rr-alice').length === 1,
         'D1. in development the same change ends nothing, and is recorded ' +
         'as observed', JSON.stringify(observed));
    config.setOverride('risk.enforceInDevelopment', true);

    // --- E. a realm's own policy --------------------------------------------
    const written = xacmlStore.write('risk-response',
      xacmlXml.writePolicy(withDisable.policy), { enabled: true });
    const disabled = await riskEngine.respond(Object.assign({}, change,
                                              { assessmentId: 'rr-e1' }));
    note(written && written.ok && disabled.taken.indexOf('risk-disable') >= 0 &&
         accountState.isDisabled('rr-alice'),
         'E1. a realm\'s own policy with a disable rule disables the account',
         JSON.stringify([written && written.why, disabled]));
    xacmlStore.remove('risk-response');
    accountState.setDisabled('rr-alice', false, { actor: 'a test' });
    const builtBack = riskPep.responsePolicy();
    note(builtBack.builtIn === true,
         'E2. deleting it puts the built-in policy back');

    // --- F. CAEP --------------------------------------------------------------
    config.setOverride('caep.enabled', true);
    config.setOverride('caep.autoEmit', true);
    note(caep.autoEmitActs().indexOf('risk') >= 0,
         'F1. risk-level-change is an act CAEP emits by itself',
         JSON.stringify(caep.autoEmitActs()));

    // --- G. continuous evaluation -------------------------------------------
    const CHROME_NEXT = CHROME.replace('Chrome/140', 'Chrome/141');
    ldap.createUser('rr-bob', { invent: false });
    const bob = await signIn('rr-bob', CHROME);
    const bobSub = helpers.subjectForName('rr-bob');
    const sessionPhase = async function () {
      const view = await riskEngine.view('default', {});
      return view.assessments.rows.filter(function (a) {
        return a.subject === bobSub && a.phase === 'session';
      });
    };
    const updated = request(CHROME_NEXT, bob.cookie);
    const stillBob = audit.withSource({ req: updated }, function () {
      return authn.sessionOf(updated);
    });
    await new Promise(function (r) { setTimeout(r, 150); });
    note(stillBob && !(await sessionPhase()).length,
         'G1. a browser that updated itself mid-session is the same device: ' +
         'the session is not assessed again');
    const moved = request(FIREFOX, bob.cookie);
    audit.withSource({ req: moved }, function () {
      return authn.sessionOf(moved);
    });
    let reassessed = [];
    for (let i = 0; i < 60 && !reassessed.length; i++) {
      reassessed = await sessionPhase();
      if (!reassessed.length) {
        await new Promise(function (r) { setTimeout(r, 50); });
      }
    }
    await new Promise(function (r) { setTimeout(r, 150); });
    const one = reassessed[0] || {};
    note(reassessed.length === 1 && /device/.test(one.door) &&
         one.level === 'HIGH' && !authn.sessionsOf('rr-bob').length,
         'G2. the same cookie presented from another browser on another ' +
         'system is assessed again — against a history of one sign-in it ' +
         'is HIGH — and, enforced, everything the person held is ended',
         JSON.stringify({ door: one.door, level: one.level }) + ' held ' +
         authn.sessionsOf('rr-bob').length);

    // --- H. the rescore job -------------------------------------------------
    ldap.createUser('rr-carol', { invent: false });
    const carol = await signIn('rr-carol', CHROME);
    await riskTerms.accept({ provider: 'tor-project', acceptedBy: 'a test',
                             via: 'upload' });
    await riskDatasets.importVersion({ dataset: 'iplist.tor-exit',
      format: 'ip-list', content: '127.0.0.1\n', version: 'rr-tor-1',
      source: 'upload' });
    const ran = await riskEngine.rescoreLiveSessions();
    const carolNow = carol.session ? authn.sessionById(carol.session.id)
                                   : null;
    note(ran.raised >= 1 && carolNow && carolNow.risk &&
         carolNow.risk.level === 'MEDIUM' &&
         carolNow.risk.signals.indexOf('tor-exit') >= 0,
         'H1. the job raises a live session whose address has since become ' +
         'a Tor exit (UNSCORED at sign-in, x5: MEDIUM)',
         JSON.stringify(ran) + ' ' + JSON.stringify(carolNow &&
                                                    carolNow.risk));
    const ranAgain = await riskEngine.rescoreLiveSessions();
    note(ranAgain.raised === 0,
         'H2. and a session already carrying the signal is not raised again',
         JSON.stringify(ranAgain));
    const standing = await riskStore.subjectOf('default',
      helpers.subjectForName('rr-carol'), false);
    note(standing && standing.level === 'MEDIUM',
         'H3. the person\'s standing moves with it',
         JSON.stringify(standing));

    // --- I. what the person said (#62 P6) -----------------------------------
    // The loopback off the Tor list again, or every sign-in below is MEDIUM
    // and asked for a second factor this test does not give.
    await riskDatasets.importVersion({ dataset: 'iplist.tor-exit',
      format: 'ip-list', content: '192.0.2.250\n', version: 'rr-tor-2',
      source: 'upload' });
    config.setOverride('risk.enforceInDevelopment', true);
    ldap.createUser('rr-dana', { invent: false });
    const danaSub = helpers.subjectForName('rr-dana');
    const dana = await signIn('rr-dana', CHROME);
    const danaAssessed = dana.assessment;
    const fromItself = await riskEngine.feedback({ realm: 'default',
      subject: danaSub, username: 'rr-dana', assessmentId: danaAssessed.id,
      verdict: 'confirmed', fromSessionId: dana.session.id,
      fromSessionLevel: 'MEDIUM' });
    note(fromItself.ok && fromItself.moved === '',
         'I1. "this was me" said from the flagged session itself is ' +
         'recorded and moves nothing', JSON.stringify(fromItself));
    const again2 = await riskEngine.feedback({ realm: 'default',
      subject: danaSub, username: 'rr-dana', assessmentId: danaAssessed.id,
      verdict: 'denied', fromSessionId: 'x', fromSessionLevel: 'LOW' });
    note(!again2.ok, 'I2. a sign-in is answered once');
    const second = await signIn('rr-dana', FIREFOX);
    await riskStore.upsertSubject({ realm: 'default', subject: danaSub,
      score: 5, level: 'MEDIUM', reason: 'a test',
      lastAssessment: second.assessment.id, updatedAt: Date.now() }, false);
    const vouched = await riskEngine.feedback({ realm: 'default',
      subject: danaSub, username: 'rr-dana',
      assessmentId: second.assessment.id, verdict: 'confirmed',
      fromSessionId: dana.session.id, fromSessionLevel: 'LOW' });
    const lowered = await riskStore.subjectOf('default', danaSub, false);
    note(vouched.ok && vouched.moved === 'LOW' && lowered.level === 'LOW',
         'I3. "this was me" from ANOTHER, low-risk session lowers the ' +
         'person\'s standing to LOW', JSON.stringify(lowered));
    const third = await signIn('rr-dana', CHROME);
    const denied = await riskEngine.feedback({ realm: 'default',
      subject: danaSub, username: 'rr-dana',
      assessmentId: third.assessment.id, verdict: 'denied',
      fromSessionId: third.session.id, fromSessionLevel: 'LOW' });
    await new Promise(function (r) { setTimeout(r, 200); });
    const raised = await riskStore.subjectOf('default', danaSub, false);
    note(denied.ok && denied.moved === 'HIGH' && raised.level === 'HIGH' &&
         !authn.sessionsOf('rr-dana').length,
         'I4. "this wasn\'t me" puts the standing at HIGH, and every ' +
         'session the person held is ended', JSON.stringify(raised) +
         ' held ' + authn.sessionsOf('rr-dana').length);
    const stranger = await riskEngine.feedback({ realm: 'default',
      subject: aliceSub, username: 'rr-alice',
      assessmentId: third.assessment.id, verdict: 'denied',
      fromSessionId: 'x', fromSessionLevel: 'LOW' });
    note(!stranger.ok, 'I5. nobody answers for somebody else\'s sign-in');

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
  const out = path.join(os.tmpdir(), 'risk-response-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RR_ROOT: ROOT, RR_OUT: out }),
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
  name: 'risk_response',
  describe: 'what a change of risk leads to (#62 P4): the risk-response ' +
            'policy\'s reactions and their decisions, sessions ended once ' +
            'per assessment, development observing, a realm override that ' +
            'disables, CAEP risk-level-change, a session presented from ' +
            'another device assessed again, and the rescore job raising a ' +
            'session whose address became a Tor exit',
  run: run
};
