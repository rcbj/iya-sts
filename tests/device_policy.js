'use strict';
//
// File: device_policy.js
//
// ===========================================================================
// #164 PHASE 6 (2026-09-26), in process: the registered device in the
// issuance policy, the compliant-device acr and the `device_id` claim
// (decisions 3 and 8).
//
// In a child process, because it loads the whole protocol stack, and in a
// THROWAWAY REALM, because it writes real devices, clients and sessions.
//
//   A. THE XACML FACTS: the issuance request carries the device attributes
//      and the realm's requirement when the gate asked the device question,
//      and none otherwise; ownership is decided against the subject.
//   B. THE RULES OFF (the default): a not-compliant device, and no device,
//      are issued; a COMPROMISED one is refused (STS-DEVICE-0038, on by
//      default in both modes) and issued once devices.refuseCompromised is
//      off.
//   C. THE RULE ON (devices.requireCompliantDevice): no device, a
//      not-compliant one, somebody else's and a compromised one refused
//      (STS-DEVICE-0037); the person's own compliant one issued; attested
//      required refuses a self-asserted one; the console and the portal are
//      exempt; a waived role question is still refused on the device.
//   D. THE SESSION'S DEVICE, UP TO DATE: a session recognised on a
//      compliant device is refused once the MDM says not-compliant.
//   E. THE SESSION'S START: startSession() refuses with no device while the
//      rule is on, and a gated door is asked the device question alone.
//   F. THE ACR: urn:sts:acr:compliant-device is published, met by a session
//      on the person's own compliant device and nothing else, and neither
//      meets nor is met by mfa.
//   G. THE CLAIM: device_id in the access token and the ID Token, the
//      register's id for a public client; absent
//      with no device and for somebody else's; a sector-derived one for a
//      pairwise client and none for an ephemeral one; the DPoP-bound
//      token's cnf.jkt is the device key's thumbprint, and no second cnf.
//      (`claims_supported` and introspection are held over HTTP by
//      `tests/vendored/sts_devices.js`.)
//   H. SSF: a pairwise stream is told the pairwise device id, an ephemeral
//      one no device.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'device_policy',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

function childMain() {
  const ROOT = process.env.DP_ROOT;
  const OUT = process.env.DP_OUT;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }
  function payloadOf(token) {
    return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url')
      .toString('utf8'));
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const applications = require(ROOT + '/common/applications');
    const devices = require(ROOT + '/common/devices');
    const recognition = require(ROOT + '/common/device_recognition');
    const gate = require(ROOT + '/common/issuance_gate');
    const rolePep = require(ROOT + '/xacml/xacml_role_pep');
    const templates = require(ROOT + '/xacml/xacml_templates');
    const authn = require(ROOT + '/authn/authn');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
    const stepUp = require(ROOT + '/oauth-oidc/step_up');
    const ssf = require(ROOT + '/ssf/ssf');
    const stsCrypto = require(ROOT + '/common/crypto');
    const helpers = require(ROOT + '/common/helpers');
    const DEVICE = templates.DEVICE_ATTRIBUTE;
    const RUN = nodeCrypto.randomBytes(3).toString('hex');
    const realm = realms.create({ id: 'dpol-' + RUN,
                                  name: 'device policy ' + RUN }).realm;
    await realms.run(realm, async function () {
      const ALICE = 'dpol-alice-' + RUN;
      const BOB = 'dpol-bob-' + RUN;
      [ALICE, BOB].forEach(function (name) {
        ldap.createUser(name, { invent: false, attributes: {} });
      });
      const PUBLIC = 'dpol-public-' + RUN;
      const PAIRWISE = 'dpol-pairwise-' + RUN;
      const EPHEMERAL = 'dpol-ephemeral-' + RUN;
      const made = [[PUBLIC, 'public'], [PAIRWISE, 'pairwise'],
                    [EPHEMERAL, 'ephemeral']].map(function (pair) {
        return applications.createApplication({ identifier: pair[0],
          protocols: ['oauth2', 'oidc'], fields: { oauthClientId: pair[0],
            oauthSubjectType: pair[1],
            oauthRedirectUri: 'https://' + pair[0] + '.example/cb' } });
      });
      note(made.every(function (one) {
        return one.ok;
      }) && applications.clientConfigOf(PAIRWISE).subject_type ===
             'pairwise',
           'precondition: a public, a pairwise and an ephemeral client',
           JSON.stringify(made.map(function (one) {
             return one.errors || 'ok';
           })));
      const pub = function () {
        return nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
          .publicKey.export({ format: 'jwk' });
      };
      const aliceJwk = pub();
      const laptop = devices.create({ owner: ALICE, label: 'dpol laptop',
        keys: [{ kind: 'jwk', value: aliceJwk }] }, 'dpol-admin');
      const bobDevice = devices.create({ owner: BOB, label: 'dpol bob',
        keys: [{ kind: 'jwk', value: pub() }] }, 'dpol-admin');
      note(laptop.ok && bobDevice.ok, 'precondition: two people\'s devices',
           JSON.stringify([laptop.errors, bobDevice.errors]));
      const id = laptop.device.id;
      const thumb = stsCrypto.jwkThumbprint(aliceJwk);
      const alicesFact = function () {
        return recognition.recognize({ dpopJkt: thumb, subject: ALICE });
      };
      const bobsFact = recognition.recognize({
        dpopJkt: bobDevice.device.keys[0].thumbprint, subject: ALICE });
      const ask = function (fact, extra) {
        return gate.check(Object.assign({
          application: PUBLIC, kind: gate.ISSUANCE.ACCESS_TOKEN,
          subject: { kind: 'user', name: ALICE, authenticated: true },
          claims: null, risk: null, device: fact }, extra || {}));
      };
      const code = function (answer) {
        return answer && answer.device ? answer.device.refusal : '';
      };

      // --- A. the XACML facts -----------------------------------------------
      devices.setCompliance(id, 'compliant', 'admin', 'dpol-admin');
      const request = rolePep.buildRequest({
        application: PUBLIC, kind: 'issue-access-token',
        subject: { kind: 'user', name: ALICE, authenticated: true },
        risk: null, device: recognition.current(alicesFact()),
        deviceRequirement: gate.deviceRequirementOf() },
        ['EVERYBODY'], [], ['EVERYBODY']);
      const env = request.categories.filter(function (c) {
        return /environment/.test(c.category);
      })[0].attributes;
      const valueOf = function (id) {
        const hit = env.filter(function (a) {
          return a.attributeId === id;
        })[0];
        return hit ? hit.values.map(function (v) {
          return v.lexical;
        }).join(',') : undefined;
      };
      note(valueOf(DEVICE.RECOGNIZED) === 'true' &&
           valueOf(DEVICE.ID) === id && valueOf(DEVICE.VIA) === 'jwk' &&
           valueOf(DEVICE.OWNER_MATCHES) === 'true' &&
           valueOf(DEVICE.OWNER_KIND) === 'person' &&
           valueOf(DEVICE.COMPLIANCE) === 'compliant' &&
           valueOf(DEVICE.ATTESTATION) === 'self-asserted' &&
           valueOf(DEVICE.STATUS) === 'active' &&
           valueOf(DEVICE.REQUIREMENT) === 'not-compromised',
           'A1. the issuance request carries the device: recognised, id, ' +
           'via, owner matches, owner kind, compliance, attestation, ' +
           'status, and the realm\'s requirement',
           JSON.stringify(env.map(function (a) {
             return a.attributeId + '=' + a.values.map(function (v) {
               return v.lexical;
             }).join(',');
           })));
      const noDevice = rolePep.buildRequest({ application: PUBLIC,
        kind: 'issue-access-token',
        subject: { kind: 'user', name: ALICE, authenticated: true },
        device: null, deviceRequirement: [] },
        ['EVERYBODY'], [], ['EVERYBODY']);
      const unasked = rolePep.buildRequest({ application: PUBLIC,
        kind: 'issue-access-token',
        subject: { kind: 'user', name: ALICE, authenticated: true } },
        ['EVERYBODY'], [], ['EVERYBODY']);
      const envOf = function (req) {
        return req.categories.filter(function (c) {
          return /environment/.test(c.category);
        })[0].attributes.map(function (a) {
          return a.attributeId;
        });
      };
      note(envOf(noDevice).indexOf(DEVICE.RECOGNIZED) >= 0 &&
           envOf(noDevice).indexOf(DEVICE.ID) < 0 &&
           envOf(unasked).indexOf(DEVICE.RECOGNIZED) < 0,
           'A2. with no device only "recognized" (false) goes; a question ' +
           'that did not ask about the device carries none',
           JSON.stringify([envOf(noDevice), envOf(unasked)]));
      const bobsRequest = rolePep.buildRequest({ application: PUBLIC,
        kind: 'issue-access-token',
        subject: { kind: 'user', name: ALICE, authenticated: true },
        device: bobsFact, deviceRequirement: [] },
        ['EVERYBODY'], [], ['EVERYBODY']);
      const bobsOwner = bobsRequest.categories.filter(function (c) {
        return /environment/.test(c.category);
      })[0].attributes.filter(function (a) {
        return a.attributeId === DEVICE.OWNER_MATCHES;
      })[0];
      note(bobsOwner && bobsOwner.values[0].lexical === 'false',
           'A3. somebody else\'s device does not match the subject');

      // --- B. the rules off (the default) -----------------------------------
      devices.setCompliance(id, 'not-compliant', 'admin', 'dpol-admin');
      const offNc = ask(alicesFact());
      const offNone = ask(null);
      note(offNc.allowed && offNone.allowed,
           'B1. with the compliant-device rule off (the default), a ' +
           'not-compliant device and no device are issued',
           JSON.stringify([offNc.why, offNone.why]));
      devices.setStatus(id, 'compromised', 'dpol-admin', 'lost',
                        { initiatingEntity: 'admin' });
      const compromisedAnswer = ask(alicesFact());
      note(!compromisedAnswer.allowed &&
           code(compromisedAnswer) === 'compromised' &&
           compromisedAnswer.why === 'Authentication failed.',
           'B2. a COMPROMISED device is refused by default, and the client ' +
           'is told only that authentication failed',
           JSON.stringify(compromisedAnswer));
      config.setOverride('devices.refuseCompromised', false);
      const allowedCompromised = ask(alicesFact());
      config.clearOverride('devices.refuseCompromised');
      note(allowedCompromised.allowed,
           'B3. devices.refuseCompromised off lets it through (a risk ' +
           'signal only)', allowedCompromised.why);
      const noApp = gate.check({ kind: gate.ISSUANCE.ACCESS_TOKEN,
        subject: { kind: 'user', name: ALICE, authenticated: true },
        claims: null, risk: null, device: alicesFact() });
      note(!noApp.allowed && code(noApp) === 'compromised',
           'B4. a compromised device is refused even where no application ' +
           'was named and the role question is waived', noApp.why);
      devices.setStatus(id, 'active', 'dpol-admin', 'found',
                        { initiatingEntity: 'admin' });

      // --- C. the rule on ---------------------------------------------------
      config.setOverride('devices.requireCompliantDevice', true);
      const cNone = ask(null);
      const cNc = ask(alicesFact());
      const cBobs = ask(bobsFact);
      devices.setCompliance(id, 'compliant', 'admin', 'dpol-admin');
      devices.setCompliance(bobDevice.device.id, 'compliant', 'admin',
                            'dpol-admin');
      const cBobsCompliant = ask(recognition.recognize({
        dpopJkt: bobDevice.device.keys[0].thumbprint, subject: ALICE }));
      const cOk = ask(alicesFact());
      note(!cNone.allowed && code(cNone) === 'not-compliant' &&
           !cNc.allowed && code(cNc) === 'not-compliant' &&
           !cBobs.allowed && !cBobsCompliant.allowed &&
           cNone.why === 'A compliant registered device is required.',
           'C1. with devices.requireCompliantDevice on: no device, a ' +
           'not-compliant one and somebody else\'s (even compliant) are ' +
           'refused', JSON.stringify([cNone.why, cNc.why, cBobs.why,
                                      cBobsCompliant.why]));
      note(cOk.allowed, 'C2. and the person\'s own compliant device is ' +
           'issued', cOk.why);
      config.setOverride('devices.compliantDeviceAttested', true);
      const selfAsserted = ask(alicesFact());
      const attestedFact = Object.assign(alicesFact(),
                                         { attestation: 'attested' });
      devices.addKey(id, { kind: 'jwk', value: pub(), proof: 'jwk-proof',
        attestation: { level: 'attested', format: 'android-key-attestation',
                       summary: 'a test' } }, 'dpol-admin');
      const attested = ask(alicesFact());
      config.clearOverride('devices.compliantDeviceAttested');
      note(!selfAsserted.allowed && attested.allowed &&
           devices.byId(id).attestation === 'attested',
           'C3. with devices.compliantDeviceAttested on, a self-asserted ' +
           'device is refused and an attested one issued',
           JSON.stringify([selfAsserted.why, attested.why, attestedFact.id]));
      const console = ask(null, { application: 'sts-admin-console' });
      const portal = ask(null, { application: 'sts-user-portal' });
      note(console.allowed && portal.allowed,
           'C4. the console and the portal (where a device is registered) ' +
           'are exempt', JSON.stringify([console.why, portal.why]));
      const waived = gate.check({ kind: gate.ISSUANCE.ACCESS_TOKEN,
        subject: { kind: 'user', name: ALICE, authenticated: true },
        claims: null, risk: null, device: null });
      note(!waived.allowed && code(waived) === 'not-compliant',
           'C5. a waived role question is still refused on the device',
           waived.why);
      const deferred = ask(null, { deviceDeferred: true });
      note(deferred.allowed,
           'C6. a door that defers the device question is not refused on it',
           deferred.why);

      // --- D. the session's device, up to date -----------------------------
      const session = authn.startSession({ headers: [], set: function () {},
                                           req: null }, ALICE, ['pwd'], '1',
        'Test', { cookie: false, device: undefined });
      note(session === null, 'E1. startSession() refuses a session with no ' +
           'device while the rule is on');
      config.clearOverride('devices.requireCompliantDevice');
      const live = authn.startSession({ headers: [], set: function () {},
                                        req: null }, ALICE, ['pwd'], '1',
                                      'Test', { cookie: false });
      const held = authn.sessions.get(live.id);
      held.events[held.events.length - 1].registeredDevice = alicesFact();
      authn.sessions.set(live.id, held);
      config.setOverride('devices.requireCompliantDevice', true);
      const onSession = gate.check({ application: PUBLIC,
        kind: gate.ISSUANCE.ACCESS_TOKEN,
        subject: { kind: 'user', name: ALICE, authenticated: true },
        claims: null, risk: null, session: authn.sessionById(live.id) });
      devices.setCompliance(id, 'not-compliant', 'mdm', 'dpol-mdm');
      const afterMdm = gate.check({ application: PUBLIC,
        kind: gate.ISSUANCE.ACCESS_TOKEN,
        subject: { kind: 'user', name: ALICE, authenticated: true },
        claims: null, risk: null, session: authn.sessionById(live.id) });
      note(onSession.allowed && !afterMdm.allowed &&
           code(afterMdm) === 'not-compliant',
           'D1. a session recognised on a compliant device is issued, and ' +
           'refused once the MDM says not-compliant — the device is read ' +
           'as it stands now', JSON.stringify([onSession.why,
                                                afterMdm.why]));
      devices.setCompliance(id, 'compliant', 'admin', 'dpol-admin');

      // --- E. a gated door asks the device alone -----------------------------
      const said = { cookie: false, gated: true };
      const gated = authn.startSession({ headers: [], set: function () {},
                                         req: null }, ALICE, ['pwd'], '1',
                                       'Test', said);
      config.clearOverride('devices.requireCompliantDevice');
      note(gated === null && said.refusedWith === 'STS-DEVICE-0037',
           'E2. a gated door (the sign-in screen asked the rest already) ' +
           'is asked the device question alone at the session\'s start',
           JSON.stringify(said));

      // --- F. the acr ------------------------------------------------
      const COMPLIANT = 'urn:sts:acr:compliant-device';
      note(stepUp.SUPPORTED.join(' ') === '0 1 mfa ' + COMPLIANT,
           'F1. urn:sts:acr:compliant-device is what acr_values_supported ' +
           'publishes after the ladder (the discovery documents are held ' +
           'to it over HTTP)', JSON.stringify(stepUp.SUPPORTED));
      const liveSession = authn.sessionById(live.id);
      const met = stepUp.meets(COMPLIANT, liveSession);
      devices.setCompliance(id, 'not-compliant', 'mdm', 'dpol-mdm');
      const unmetNc = stepUp.meets(COMPLIANT, authn.sessionById(live.id));
      devices.setCompliance(id, 'compliant', 'admin', 'dpol-admin');
      const bobsSession = JSON.parse(JSON.stringify(liveSession));
      bobsSession.events[bobsSession.events.length - 1].registeredDevice =
        bobsFact;
      const mfaSession = JSON.parse(JSON.stringify(liveSession));
      mfaSession.acr = 'mfa';
      mfaSession.events[mfaSession.events.length - 1].registeredDevice = null;
      note(met && !unmetNc && !stepUp.meets(COMPLIANT, bobsSession) &&
           !stepUp.meets(COMPLIANT, mfaSession) &&
           !stepUp.meets('mfa', liveSession) &&
           stepUp.meets('1', liveSession),
           'F2. met by a session on the person\'s own compliant device; not ' +
           'once it is not-compliant, not on somebody else\'s, not by an ' +
           'mfa session without one — and it does not meet mfa',
           JSON.stringify([met, unmetNc]));
      const assessed = stepUp.assessSession({ acrValues: [COMPLIANT],
                                              maxAge: null },
                                            mfaSession, { honoured: false });
      const honoured = stepUp.assessSession({ acrValues: [COMPLIANT],
                                              maxAge: null },
                                            mfaSession, { honoured: true });
      const refusal = stepUp.unmetRefusal({ acrValues: [COMPLIANT],
                                            maxAge: null }, honoured);
      note(!assessed.met && assessed.retry === true && !honoured.met &&
           honoured.retry === false &&
           refusal.error === 'unmet_authentication_requirements' &&
           stepUp.satisfiedAcr([COMPLIANT], liveSession) === COMPLIANT,
           'F3. a session without one is sent to sign in again, then ' +
           'refused unmet_authentication_requirements; one with it carries ' +
           'it as its acr', JSON.stringify([assessed, honoured, refusal]));

      // --- G. the claim ----------------------------------------------
      const base = 'https://dpol.example';
      const user = helpers.userFor(ALICE);
      const at = oauth2.accessToken(base, { client_id: PUBLIC,
        username: ALICE, user: user, scope: 'openid', jkt: thumb,
        registered_device: alicesFact() });
      const atClaims = payloadOf(at);
      const idt = payloadOf(await oauth2.idToken(base, { client_id: PUBLIC,
        username: ALICE, user: user, scope: 'openid',
        registered_device: alicesFact() }));
      note(atClaims.device_id === id && idt.device_id === id &&
           atClaims.cnf && atClaims.cnf.jkt === thumb &&
           Object.keys(atClaims.cnf).length === 1,
           'G1. device_id is the register\'s id in the access token and the ' +
           'ID Token, and the DPoP-bound token\'s one cnf names the device ' +
           'key by its thumbprint', JSON.stringify([atClaims.device_id,
                                                    idt.device_id,
                                                    atClaims.cnf]));
      const none = payloadOf(oauth2.accessToken(base, { client_id: PUBLIC,
        username: ALICE, user: user, scope: 'openid',
        registered_device: null }));
      const bobs = payloadOf(oauth2.accessToken(base, { client_id: PUBLIC,
        username: ALICE, user: user, scope: 'openid',
        registered_device: bobsFact }));
      note(none.device_id === undefined && bobs.device_id === undefined,
           'G2. absent with no device, and absent for somebody else\'s');
      const pw1 = payloadOf(oauth2.accessToken(base, { client_id: PAIRWISE,
        username: ALICE, user: user, scope: 'openid',
        registered_device: alicesFact() }));
      const pw2 = payloadOf(await oauth2.idToken(base, {
        client_id: PAIRWISE, username: ALICE, user: user, scope: 'openid',
        registered_device: alicesFact() }));
      const eph = payloadOf(oauth2.accessToken(base, { client_id: EPHEMERAL,
        username: ALICE, user: user, scope: 'openid',
        registered_device: alicesFact() }));
      note(pw1.device_id && pw1.device_id !== id &&
           pw1.device_id === pw2.device_id && eph.device_id === undefined,
           'G3. a pairwise client is told a sector-derived device_id, the ' +
           'same in both tokens and never the register\'s id; an ephemeral ' +
           'client is told none', JSON.stringify([pw1.device_id,
                                                   eph.device_id]));

      // --- H. SSF --------------------------------------------------
      const subject = { format: 'complex',
        user: { format: 'iss_sub', iss: base, sub: user.sub },
        device: { format: 'iss_sub', iss: base, sub: id } };
      const pwTold = ssf.subjectForReceiver({ createdBy: PAIRWISE }, subject);
      const ephTold = ssf.subjectForReceiver({ createdBy: EPHEMERAL },
                                             subject);
      const pubTold = ssf.subjectForReceiver({ createdBy: PUBLIC }, subject);
      note(pwTold.device && pwTold.device.sub === pw1.device_id &&
           ephTold.device === undefined && pubTold.device.sub === id,
           'H1. a pairwise stream is told the device_id its tokens carry, ' +
           'an ephemeral one no device, a public one the register\'s id',
           JSON.stringify([pwTold.device, ephTold.device, pubTold.device]));
    });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'device-policy-' + process.pid + '-' +
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
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', DP_ROOT: ROOT,
                                  DP_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
  if (!findings) {
    t.check(false, 'the child process reported its findings',
            String(result.stderr || result.error || '').slice(-2000));
    log.debug("Leaving run(). No findings.");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'device_policy',
  describe: '#164 phase 6: the registered device in the issuance policy ' +
            '(the XACML facts, the compromised-device rule on by default, ' +
            'the compliant-device rule off by default and each case it ' +
            'refuses, the exempt surfaces, the session\'s device read as ' +
            'it stands now, the gated door\'s device question), the ' +
            'urn:sts:acr:compliant-device acr, and the device_id claim ' +
            'with its pairwise and ephemeral handling, in tokens and SSF',
  run: run
};
