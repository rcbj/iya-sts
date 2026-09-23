'use strict';
//
// File: federation_signout.js
//
// ===========================================================================
// A FEDERATION PARTNER'S SIGN-OUT ENDS THE SESSION IT STARTED (#167), IN
// PROCESS, IN BOTH MODES.
//
// `federation/federation_slo.ts` receives a partner's sign-out — a SAML 2.0
// LogoutRequest or LogoutResponse, an OpenID Connect Back-Channel or
// Front-Channel logout, a WS-Federation cleanup — and tells a partner of a
// sign-out here; `federation_sp.ts` keeps what a sign-in learns about the
// partner's session and its SessionNotOnOrAfter; `logout/logout.ts` ends the
// matched session through its one model. `tests/vendored/
// sts_federation_signout.js` drives all of it over HTTP against a running
// service; this file holds what a running service cannot be made to show on
// demand, and what is cheaper to pin at the function:
//
//   0. the Redirect-binding signature verifier in common/crypto.js, and the
//      mode predicate and the relationship's two new refusals;
//   1. REALM TO REALM, OpenID Connect: a genuine Back-Channel Logout Token,
//      POSTed by this service's own OpenID Provider (the default realm) when
//      the partner's session ends, ends the federated session in a realm of
//      this file's own — and a genuine token replayed is refused;
//   2. every Logout Token refusal of Back-Channel Logout 1.0 section 2.6, and
//      fedAcceptSignout off;
//   3. Front-Channel Logout: iss and sid required, the partner's origin the
//      only frame ancestor, the matched session ended;
//   4. a sign-out HERE offers the partner its own (RP-Initiated Logout with
//      id_token_hint), and the return is matched once;
//   5. a SAML 2.0 partner under this file's own key: the LogoutRequest
//      refusals (unsigned, wrong key, wrong issuer, wrong Destination, stale,
//      replayed), an unknown SessionIndex answered UnknownPrincipal, the
//      match ending only its session, the signed LogoutResponse, and the
//      service-provider-initiated round trip;
//   6. SessionNotOnOrAfter binds the session, and one already passed is
//      refused.
//
// WHY A CHILD PROCESS PER MODE: it loads the whole protocol stack, serves it
// on a loopback port under a CA of its own (product refuses a plain-http
// back channel), creates a realm and puts it in product mode for the second
// run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'federation_signout', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.FSO_ROOT;
  const OUT = process.env.FSO_OUT;
  const MODE = process.env.FSO_MODE;
  const https = require('https');
  const nodeCrypto = require('crypto');
  const zlib = require('zlib');
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
    const errorCodes = require(ROOT + '/common/error_codes');
    const stsCrypto = require(ROOT + '/common/crypto');
    const applications = require(ROOT + '/common/applications');
    const authn = require(ROOT + '/authn/authn');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const federation = require(ROOT + '/federation/federation');
    const fedSp = require(ROOT + '/federation/federation_sp');
    const fedSlo = require(ROOT + '/federation/federation_slo');
    const backchannel = require(ROOT + '/oauth-oidc/backchannel_logout');
    const logout = require(ROOT + '/logout/logout');
    const stats = require(ROOT + '/common/admin_stats');
    const xmldsig = require(ROOT + '/tests/vendored/saml_xmldsig');
    const forge = require('node-forge');

    // EVERY CODE A RESPONSE IS MARKED WITH, in order: the refusals' codes
    // are recorded and never sent, so this is how a test reads them.
    const marks = [];
    const mark = errorCodes.mark;
    errorCodes.mark = function (res, code) {
      marks.push(code);
      return mark.apply(this, arguments);
    };
    function marked(since, code) {
      return marks.slice(since).indexOf(code) >= 0;
    }

    // HTTPS under a CA of this child's own — federation_subject_policy.js's
    // arrangement and reason: product refuses a plain-http back channel.
    const testCa = require(ROOT + '/tests/vendored/outbound_test_ca');
    const ca = await testCa.makeCa();
    const leaf = await testCa.listenerCertificate(ca, '127.0.0.1');
    const caPem = ca.certPem;
    const caFile = path.join(os.tmpdir(), 'fso-ca-' + process.pid + '.crt');
    fs.writeFileSync(caFile, caPem);
    config.setOverride('federation.outboundCaFile', caFile);
    const server = https.createServer({ key: leaf.key, cert: leaf.cert },
                                      app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'https://127.0.0.1:' + port;
    const SP = 'fso' + (MODE === 'product' ? 'p' : 'd');
    const REL = 'fso-oidc';
    const SAML = 'fso-saml';
    const CLIENT = 'fso-client-' + MODE;
    const SECRET = 'fso-secret-' + nodeCrypto.randomBytes(8).toString('hex');
    const PERSON = 'fso-person-' + MODE;
    const PARTNER = 'urn:test:fso-partner:' + MODE;
    const SP_BASE = base + '/realm/' + SP;

    let jar = {};
    function request(method, target, opts) {
      const o = opts || {};
      const url = new URL(target, base);
      return new Promise(function (resolve) {
        const body = o.body !== undefined ? o.body
          : (o.form ? new URLSearchParams(o.form).toString() : '');
        const headers = Object.assign({
          cookie: Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ') }, o.headers || {});
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = https.request({ host: '127.0.0.1', port: port, ca: caPem,
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
              json = null;
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
    function inPartner(fn) {
      return realms.run(realms.get(realms.DEFAULT_ID), fn);
    }
    function wait(ms) {
      return new Promise(function (r) { setTimeout(r, ms); });
    }
    function hidden(text, name) {
      const m = new RegExp('name="' + name + '" value="([^"]*)"').exec(text);
      return m ? m[1] : '';
    }
    function decodeHtml(text) {
      return String(text || '').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    }
    function fedSession(relationship, id) {
      return inSp(function () {
        const out = authn.sessionsOf(PERSON).filter(function (s) {
          return s.fedPartnerSession &&
                 s.fedPartnerSession.relationship === relationship &&
                 !authn.sessionEnded(s) && (!id || s.id === id);
        });
        return out[0] || null;
      });
    }
    async function endedWithin(id, ms) {
      const until = Date.now() + ms;
      while (Date.now() < until) {
        if (!inSp(function () { return authn.sessionById(id); })) {
          return true;
        }
        await wait(200);
      }
      return false;
    }
    function spAuditActions() {
      return inSp(function () { return audit.list(); }).map(function (row) {
        return row.action + ' ' + (row.errorCode || '');
      });
    }
    function selfSigned(keys, cn) {
      const cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = '01' + nodeCrypto.randomBytes(8).toString('hex');
      cert.validity.notBefore = new Date(Date.now() - 60000);
      cert.validity.notAfter = new Date(Date.now() + 3600 * 1000);
      cert.setSubject([{ name: 'commonName', value: cn }]);
      cert.setIssuer([{ name: 'commonName', value: cn }]);
      cert.sign(keys.privateKey, forge.md.sha256.create());
      const pem = forge.pki.certificateToPem(cert);
      return { certPem: pem,
               der: pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''),
               privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey) };
    }
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    // THE SERVICE PROVIDER REALM'S OWN XML SIGNING CERTIFICATE: keys are per
    // realm, so what signs a LogoutRequest or LogoutResponse there is not
    // the default realm's.
    let spXmlCert = '';

    // =======================================================================
    // 0. THE REDIRECT-BINDING SIGNATURE VERIFIER (common/crypto.js), THE
    //    MODE PREDICATE AND THE RELATIONSHIP'S TWO NEW REFUSALS
    // =======================================================================
    const partnerKey = selfSigned(forge.pki.rsa.generateKeyPair(2048),
                                  'fso partner ' + MODE);
    const otherKey = selfSigned(forge.pki.rsa.generateKeyPair(2048),
                                'fso somebody else ' + MODE);
    const octets = 'SAMLRequest=' + encodeURIComponent('abc+/=') +
                   '&RelayState=r1&SigAlg=' + encodeURIComponent(RSA_SHA256);
    const sig = stsCrypto.signQueryString(octets, partnerKey.privateKeyPem,
                                          RSA_SHA256);
    const good = stsCrypto.verifyQueryString(octets, { signature: sig,
      sigAlg: RSA_SHA256, certPem: partnerKey.certPem });
    const tampered = stsCrypto.verifyQueryString(octets + 'x',
      { signature: sig, sigAlg: RSA_SHA256, certPem: partnerKey.certPem });
    const wrongCert = stsCrypto.verifyQueryString(octets, { signature: sig,
      sigAlg: RSA_SHA256, certPem: otherKey.certPem });
    const noCert = stsCrypto.verifyQueryString(octets, { signature: sig,
      sigAlg: RSA_SHA256 });
    const noAlg = stsCrypto.verifyQueryString(octets, { signature: sig,
      sigAlg: 'urn:nothing', certPem: partnerKey.certPem });
    note(good.ok && !tampered.ok && tampered.usable &&
         errorCodes.codeOf(tampered) === 'STS-KEYS-0059' &&
         !wrongCert.ok && wrongCert.usable && !noCert.ok && !noCert.usable &&
         errorCodes.codeOf(noCert) === 'STS-KEYS-0060' && !noAlg.ok &&
         !noAlg.usable,
         '0a. the Redirect-binding verifier: good verifies; altered octets ' +
         'and another certificate are wrong (0059); no certificate and an ' +
         'unknown SigAlg cannot be checked',
         JSON.stringify([good.ok, tampered.ok, wrongCert.ok, noCert.ok,
                         noAlg.ok]));

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
    note(inSp(function () {
      return mode.acceptsUnsignedFederatedLogout();
    }) === (MODE !== 'product'),
         '0b. mode.acceptsUnsignedFederatedLogout() is ' +
         (MODE !== 'product') + ' in ' + MODE + ' mode');

    const setRel = function (id, field, value) {
      return inSp(function () {
        return federation.update(id, { field: field, value: value });
      });
    };
    const made = inSp(function () {
      const one = federation.create({ fedId: REL, fedRole: 'service-provider',
                                      fedProtocol: 'oidc' });
      const two = federation.create({ fedId: SAML,
                                      fedRole: 'service-provider',
                                      fedProtocol: 'saml2' });
      return { one: one, two: two };
    });
    note(made.one.ok && made.two.ok &&
         made.one.relationship.fedAcceptSignout === 'TRUE' &&
         made.one.relationship.fedRequireSignedLogout === 'TRUE' &&
         made.two.relationship.fedSloBinding === 'HTTP-Redirect',
         '0c. a new relationship accepts its partner\'s sign-out, requires ' +
         'it signed, and sends SAML logout on the Redirect binding',
         JSON.stringify(made.one.relationship));
    let since = marks.length;
    const badBinding = setRel(SAML, 'fedSloBinding', 'SOAP');
    const unsigned = setRel(SAML, 'fedRequireSignedLogout', 'FALSE');
    note(!badBinding.ok && (MODE === 'product' ? !unsigned.ok : unsigned.ok),
         '0d. fedSloBinding refuses a binding that is not Redirect or POST; ' +
         'fedRequireSignedLogout off is ' + (MODE === 'product'
           ? 'REFUSED in product' : 'allowed in development'),
         JSON.stringify([badBinding.errors, unsigned.errors]));
    const codes = inSp(function () { return audit.list(); })
      .map(function (row) { return row.errorCode; });
    note(codes.indexOf('STS-FED-0133') >= 0 &&
         (MODE !== 'product' || codes.indexOf('STS-FED-0132') >= 0),
         '0e. both refusals are recorded under their codes (0133' +
         (MODE === 'product' ? ', 0132' : '') + ')');
    setRel(SAML, 'fedRequireSignedLogout', 'TRUE');

    // =======================================================================
    // 1. OPENID CONNECT, REALM TO REALM
    // =======================================================================
    const slo = SP_BASE + '/federation/slo/' + REL;
    const acs = SP_BASE + '/federation/acs/' + REL;
    const bcUri = SP_BASE + '/federation/backchannel-logout/' + REL;
    const fcUri = SP_BASE + '/federation/frontchannel-logout/' + REL;
    ['fedPeer:' + ISSUER,
     'fedSsoUrl:' + discovery.json.authorization_endpoint,
     'fedTokenUrl:' + discovery.json.token_endpoint,
     'fedUserinfoUrl:' + discovery.json.userinfo_endpoint,
     'fedJwksUri:' + discovery.json.jwks_uri,
     'fedEndSessionUrl:' + discovery.json.end_session_endpoint,
     'fedClientId:' + CLIENT, 'fedClientSecret:' + SECRET,
     'fedScope:openid profile email',
     'fedSubjectPolicy:pre-linked', 'fedEnabled:TRUE'].forEach(function (one) {
      const at = one.indexOf(':');
      setRel(REL, one.slice(0, at), one.slice(at + 1));
    });
    const registered = inPartner(function () {
      return applications.createApplication({ identifier: CLIENT,
        protocols: ['oauth2'],
        fields: { oauthClientId: CLIENT, oauthRedirectUri: [acs],
                  oauthClientSecret: SECRET,
                  oauthTokenEndpointAuthMethod: 'client_secret_basic',
                  oauthBackchannelLogoutUri: bcUri,
                  oauthBackchannelLogoutSessionRequired: 'TRUE',
                  oauthFrontchannelLogoutUri: fcUri,
                  oauthFrontchannelLogoutSessionRequired: 'TRUE',
                  oauthPostLogoutRedirectUri: [slo] } });
    });
    note(registered && registered.ok !== false,
         '1a. (the relying party registered at the partner)',
         JSON.stringify(registered).slice(0, 300));
    const partnerSub = inPartner(function () {
      if (!ldap.existingUserEntry(PERSON)) {
        ldap.createUser(PERSON, { invent: true });
      }
      return helpers.subjectForName(PERSON);
    });
    inSp(function () {
      ldap.createUser(PERSON, { invent: false });
    });
    const linked = inSp(function () {
      return actions.usersAction({ action: 'federation-link', user: PERSON,
                                   relationship: REL, subject: partnerSub,
                                   issuer: ISSUER },
                                 { via: 'console', actor: 'fso-test' });
    });
    note(linked && linked.ok, '1b. (the person linked to the partner)',
         JSON.stringify(linked).slice(0, 300));

    // The whole sign-in, and the partner's own cookie kept apart: both realms
    // set `sts_session` at Path=/, so a browser holding both holds one.
    async function oidcSignIn() {
      jar = {};
      let partnerJar = null;
      let r = await request('GET', '/realm/' + SP + '/federation/login/' +
                                   REL);
      for (let hop = 0; hop < 20; hop += 1) {
        if (r.status >= 300 && r.status < 400 && r.headers.location) {
          const next = new URL(r.headers.location, base);
          if (next.pathname.indexOf('/realm/' + SP + '/federation/acs/') ===
              0 && !partnerJar) {
            partnerJar = Object.assign({}, jar);
          }
          r = await request('GET', r.headers.location);
          continue;
        }
        const authnId = hidden(r.text, 'authn_id');
        if (r.status === 200 && authnId) {
          r = await request('POST', '/authn/login', { form: {
            authn_id: authnId, username: PERSON, password: 'x',
            action: 'login' } });
          continue;
        }
        break;
      }
      return { r: r, partnerJar: partnerJar };
    }

    let got = await oidcSignIn();
    let held = fedSession(REL);
    note(held && held.fedPartnerSession.sid &&
         held.fedPartnerSession.sub === partnerSub &&
         held.fedPartnerSession.issuer === ISSUER &&
         !!held.fedPartnerSession.idToken,
         '1c. the federated session keeps the partner\'s sid, sub and ' +
         'issuer, ' +
         'and the ID Token for id_token_hint (fedEndSessionUrl is set)',
         got.r.status + ' ' + JSON.stringify(held && held.fedPartnerSession)
           .slice(0, 300));

    // THE PARTNER ENDS ITS SESSION: its OpenID Provider plans and POSTs a
    // Logout Token to this relying party's backchannel_logout_uri.
    if (held) {
      inPartner(function () {
        authn.endSessionById(held.fedPartnerSession.sid, 'the fso test');
      });
      const ended = await endedWithin(held.id, 15000);
      note(ended,
           '1d. a GENUINE Back-Channel Logout Token from the partner realm ' +
           'ended the federated session here');
      note(spAuditActions().some(function (one) {
        return one.indexOf('federation.signout') === 0;
      }), '1e. the partner\'s sign-out is its own audit row ' +
          '(federation.signout)');
    }

    // A genuine token, signed by the partner, POSTed twice: the second is a
    // replay whatever the first matched.
    const jti = 'fso-jti-' + MODE + '-' + Date.now();
    const genuine = await inPartner(function () {
      return backchannel.logoutToken({ iss: ISSUER, clientId: CLIENT,
                                       sub: partnerSub, sid: 'no-such-sid',
                                       jti: jti });
    });
    since = marks.length;
    let r1 = await request('POST', bcUri, { form: { logout_token: genuine } });
    let r2 = await request('POST', bcUri, { form: { logout_token: genuine } });
    note(r1.status === 200 && marked(since, 'STS-FED-0122') &&
         r2.status === 400 && r2.json && r2.json.error === 'invalid_request' &&
         marked(since, 'STS-FED-0120') &&
         /no-store/.test(String(r2.headers['cache-control'])),
         '1f. a genuine Logout Token matching nothing answers 200 (0122); ' +
         'the same token again is a replay, 400 invalid_request (0120)',
         r1.status + ' ' + r2.status + ' ' + r2.text);

    // =======================================================================
    // 2. EVERY SECTION 2.6 REFUSAL
    // =======================================================================
    async function partnerSigned(claims, header) {
      return inPartner(function () {
        return helpers.signJwtAsAsync(claims, 'RS256', undefined,
                                      { header: header || { typ:
                                                            'logout+jwt' } });
      });
    }
    function claims(extra) {
      const now = Math.floor(Date.now() / 1000);
      const out = { iss: ISSUER, aud: CLIENT, iat: now, exp: now + 120,
                    jti: 'fso-' + nodeCrypto.randomBytes(8).toString('hex'),
                    sid: 'fso-nobody',
                    events: {} };
      out.events['http://schemas.openid.net/event/backchannel-logout'] = {};
      return Object.assign(out, extra || {});
    }
    const rogue = nodeCrypto.generateKeyPairSync('rsa',
                                                 { modulusLength: 2048 });
    const partnerKid = (await request('GET',
      discovery.json.jwks_uri.replace(base, ''))).json.keys[0].kid;
    const b64u = function (v) {
      return Buffer.from(JSON.stringify(v)).toString('base64url');
    };
    const forgedInput = b64u({ alg: 'RS256', typ: 'logout+jwt',
                               kid: partnerKid }) + '.' + b64u(claims());
    const forged = forgedInput + '.' + nodeCrypto.sign('sha256',
      Buffer.from(forgedInput), rogue.privateKey).toString('base64url');
    const cases = [
      ['2a. no logout_token (0127)', {}, 'STS-FED-0127'],
      ['2b. an encrypted (five-part) token (0127)',
       { logout_token: 'a.b.c.d.e' }, 'STS-FED-0127'],
      ['2c. a token signed by a key that is not the partner\'s, under its ' +
       'kid (0128)', { logout_token: forged }, 'STS-FED-0128'],
      ['2d. a token with a nonce (0129)',
       { logout_token: await partnerSigned(claims({ nonce: 'n' })) },
       'STS-FED-0129'],
      ['2e. a token with no events member (0129)',
       { logout_token: await partnerSigned(claims({ events: {} })) },
       'STS-FED-0129'],
      ['2f. a token naming neither sub nor sid (0129)',
       { logout_token: await partnerSigned(claims({ sid: undefined })) },
       'STS-FED-0129'],
      ['2g. a token typed at+jwt (0129)',
       { logout_token: await partnerSigned(claims(), { typ: 'at+jwt' }) },
       'STS-FED-0129'],
      ['2h. a token for another audience (0128)',
       { logout_token: await partnerSigned(claims({ aud: 'somebody' })) },
       'STS-FED-0128'],
      ['2i. a token issued an hour ago (0119)',
       { logout_token: await partnerSigned(claims({
         iat: Math.floor(Date.now() / 1000) - 3600,
         exp: Math.floor(Date.now() / 1000) + 60 })) }, 'STS-FED-0119']
    ];
    for (const one of cases) {
      since = marks.length;
      const r = await request('POST', bcUri, { form: one[1] });
      note(r.status === 400 && marked(since, one[2]), one[0],
           r.status + ' ' + r.text.slice(0, 200) + ' ' +
           JSON.stringify(marks.slice(since)));
    }
    setRel(REL, 'fedAcceptSignout', 'FALSE');
    since = marks.length;
    const refusedOff = await request('POST', bcUri, { form: {
      logout_token: await partnerSigned(claims()) } });
    note(refusedOff.status === 400 && marked(since, 'STS-FED-0123'),
         '2j. fedAcceptSignout off refuses a genuine token (0123)',
         refusedOff.status + ' ' + refusedOff.text);
    setRel(REL, 'fedAcceptSignout', 'TRUE');

    // =======================================================================
    // 3. FRONT-CHANNEL LOGOUT
    // =======================================================================
    got = await oidcSignIn();
    held = fedSession(REL);
    since = marks.length;
    const noSid = await request('GET', fcUri);
    const wrongIss = await request('GET', fcUri + '?iss=' +
      encodeURIComponent('https://elsewhere.example') + '&sid=' +
      encodeURIComponent(held ? held.fedPartnerSession.sid : 'x'));
    note(noSid.status === 400 && wrongIss.status === 400 &&
         marked(since, 'STS-FED-0130') && !!fedSession(REL),
         '3a. no sid, and an iss that is not the partner, are refused 400 ' +
         '(0130) and end nothing', noSid.status + ' ' + wrongIss.status);
    const front = held ? await request('GET', fcUri + '?iss=' +
      encodeURIComponent(ISSUER) + '&sid=' +
      encodeURIComponent(held.fedPartnerSession.sid)) : { status: 0,
                                                          headers: {} };
    const csp = String(front.headers['content-security-policy'] || '');
    note(front.status === 200 && held &&
         !inSp(function () { return authn.sessionById(held.id); }) &&
         csp.indexOf('frame-ancestors ' + base) >= 0 &&
         !/frame-ancestors 'none'/.test(csp) &&
         !/script-src 'self'/.test(csp) &&
         !front.headers['x-frame-options'],
         '3b. iss and sid end the matched session; the page may be framed ' +
         'by the partner\'s origin and nobody else, and runs no script',
         front.status + ' ' + csp);

    // =======================================================================
    // 4. A SIGN-OUT HERE OFFERS THE PARTNER ITS OWN
    // =======================================================================
    got = await oidcSignIn();
    held = fedSession(REL);
    const inventory = inSp(function () {
      return logout.inventoryFor(held ? stats.holderKeyOf(
        held.user.username, held.user.sub) : PERSON, ISSUER);
    });
    const partnerRows = [].concat.apply([], inventory.families.map(
      function (f) { return f.id === 'federation-partner' ? f.rows : []; }));
    note(partnerRows.length >= 1 && partnerRows.every(function (row) {
      return !row.terminable && /own sign-out/.test(row.why);
    }), '4a. with no browser (/admin/logout, the API) the partner row is ' +
        'listed and cannot be ended', JSON.stringify(partnerRows));
    const out = await request('POST', '/realm/' + SP + '/logout',
                              { form: { scope: 'global' } });
    const link = decodeHtml((/href="([^"]*end_session[^"]*|[^"]*oauth2\/logout[^"]*)"/
      .exec(out.text) || [])[1] || '');
    const asked = link ? new URL(link) : null;
    note(out.status === 200 && asked &&
         asked.searchParams.get('client_id') === CLIENT &&
         asked.searchParams.get('post_logout_redirect_uri') === slo &&
         !!asked.searchParams.get('id_token_hint') &&
         /^fed-/.test(asked.searchParams.get('state') || '') &&
         held && !inSp(function () { return authn.sessionById(held.id); }),
         '4b. /logout ends the session and offers RP-Initiated Logout at the ' +
         'partner: id_token_hint, client_id, post_logout_redirect_uri and ' +
         'state', out.status + ' ' + link);
    if (asked) {
      since = marks.length;
      const back = await request('GET', '/realm/' + SP + '/federation/slo/' +
        REL + '?state=' + encodeURIComponent(asked.searchParams.get('state')));
      const again = await request('GET', '/realm/' + SP + '/federation/slo/' +
        REL + '?state=' + encodeURIComponent(asked.searchParams.get('state')));
      note(back.status === 200 && /Signed out/.test(back.text) &&
           again.status === 400 && marked(since, 'STS-FED-0134'),
           '4c. the return from the partner is matched once; the same state ' +
           'again is refused (0134)', back.status + ' ' + again.status);
    }

    // =======================================================================
    // 5. A SAML 2.0 PARTNER UNDER THIS FILE'S OWN KEY
    // =======================================================================
    const samlAcs = SP_BASE + '/federation/acs/' + SAML;
    const samlSlo = SP_BASE + '/federation/slo/' + SAML;
    const PARTNER_SLO = 'https://partner.invalid/slo';
    ['fedPeer:' + PARTNER, 'fedSsoUrl:https://partner.invalid/sso',
     'fedSigningCertificate:' + partnerKey.der, 'fedAllowUnsolicited:TRUE',
     'fedSloUrl:' + PARTNER_SLO, 'fedSubjectPolicy:pre-linked',
     'fedEnabled:TRUE'].forEach(function (one) {
      const at = one.indexOf(':');
      setRel(SAML, one.slice(0, at), one.slice(at + 1));
    });
    const NAMEID = 'fso-saml-subject-' + MODE;
    inSp(function () {
      return actions.usersAction({ action: 'federation-link', user: PERSON,
                                   relationship: SAML, subject: NAMEID,
                                   issuer: PARTNER },
                                 { via: 'console', actor: 'fso-test' });
    });
    spXmlCert = inSp(function () { return helpers.STS.xml.certPem; });
    const metadata = await request('GET', '/realm/' + SP +
                                   '/federation/metadata/' + SAML);
    note(metadata.status === 200 &&
         metadata.text.indexOf('<md:SingleLogoutService Binding="' +
           'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="' +
           samlSlo + '"/>') >= 0 &&
         /SingleLogoutService Binding="[^"]*HTTP-POST"/.test(metadata.text),
         '5a. the relationship\'s metadata publishes SingleLogoutService on ' +
         'the Redirect and POST bindings', metadata.text.slice(0, 400));

    // A Response carrying a signed assertion with a SessionIndex.
    async function samlSignIn(sessionIndex, notOnOrAfter) {
      jar = {};
      const built = xmldsig.buildAssertion({
        issuer: PARTNER, subject: NAMEID, audience: samlAcs,
        recipient: samlAcs,
        nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        authnStatement: true, sessionIndex: sessionIndex,
        sessionNotOnOrAfter: notOnOrAfter });
      const signed = xmldsig.sign(built, partnerKey.privateKeyPem, '');
      const response = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:' +
        'SAML:2.0:protocol" ID="_r' + nodeCrypto.randomBytes(8)
          .toString('hex') + '" Version="2.0" IssueInstant="' +
        new Date().toISOString() + '" Destination="' + samlAcs + '">' +
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:' +
        '2.0:status:Success"/></samlp:Status>' + signed + '</samlp:Response>';
      return request('POST', samlAcs, { form: {
        SAMLResponse: Buffer.from(response).toString('base64') } });
    }
    // A LogoutRequest on the Redirect binding, signed (or not) by `key`.
    function logoutRequestUrl(o) {
      const id = o.id || '_lr' + nodeCrypto.randomBytes(8).toString('hex');
      const xml = '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:' +
        'SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
        'assertion" ID="' + id + '" Version="2.0" IssueInstant="' +
        (o.issueInstant || new Date().toISOString()) + '" Destination="' +
        (o.destination || samlSlo) + '"><saml:Issuer>' +
        (o.issuer || PARTNER) + '</saml:Issuer><saml:NameID Format="urn:' +
        'oasis:names:tc:SAML:2.0:nameid-format:persistent">' + NAMEID +
        '</saml:NameID>' + (o.sessionIndex ? '<samlp:SessionIndex>' +
        o.sessionIndex + '</samlp:SessionIndex>' : '') +
        '</samlp:LogoutRequest>';
      let qs = 'SAMLRequest=' + encodeURIComponent(
        zlib.deflateRawSync(Buffer.from(xml)).toString('base64')) +
        '&RelayState=fso-relay';
      if (o.key) {
        qs += '&SigAlg=' + encodeURIComponent(RSA_SHA256);
        qs += '&Signature=' + encodeURIComponent(nodeCrypto.sign('sha256',
          Buffer.from(qs), o.key.privateKeyPem).toString('base64'));
      }
      return { id: id, url: samlSlo + '?' + qs };
    }
    // What a LogoutResponse in a Location says, its signature checked with
    // this service's own certificate over the octets as sent.
    function responseIn(location) {
      const url = new URL(location);
      const raw = url.search.slice(1);
      const pick = function (name) {
        const m = new RegExp('(?:^|&)' + name + '=([^&]*)').exec(raw);
        return m ? m[1] : '';
      };
      const octets = 'SAMLResponse=' + pick('SAMLResponse') +
        (pick('RelayState') ? '&RelayState=' + pick('RelayState') : '') +
        '&SigAlg=' + pick('SigAlg');
      const verdict = stsCrypto.verifyQueryString(octets, {
        signature: decodeURIComponent(pick('Signature')),
        sigAlg: decodeURIComponent(pick('SigAlg')),
        certPem: spXmlCert });
      const xml = zlib.inflateRawSync(Buffer.from(decodeURIComponent(
        pick('SAMLResponse')), 'base64')).toString('utf8');
      const codesIn = [...xml.matchAll(/StatusCode Value="([^"]+)"/g)]
        .map(function (m) { return m[1].split(':').pop(); });
      return { verified: verdict.ok, xml: xml, codes: codesIn,
               relay: decodeURIComponent(pick('RelayState')),
               to: url.origin + url.pathname };
    }

    const signedIn = await samlSignIn('idx-one-' + MODE, '');
    held = fedSession(SAML);
    note((signedIn.status === 200 || signedIn.status === 303) && held &&
         held.fedPartnerSession.sessionIndex === 'idx-one-' + MODE &&
         held.fedPartnerSession.nameId === NAMEID,
         '5b. a SAML sign-in keeps the partner\'s NameID and SessionIndex',
         signedIn.status + ' ' + signedIn.text.slice(0, 200));
    const refusals = [
      ['5c. an UNSIGNED LogoutRequest is refused 403 (0115)',
       logoutRequestUrl({ sessionIndex: 'idx-one-' + MODE }), 403,
       'STS-FED-0115'],
      ['5d. one signed by a key the relationship does not name, 403 (0116)',
       logoutRequestUrl({ sessionIndex: 'idx-one-' + MODE, key: otherKey }),
       403, 'STS-FED-0116'],
      ['5e. one issued by somebody else, 403 (0117)',
       logoutRequestUrl({ sessionIndex: 'idx-one-' + MODE, key: partnerKey,
                          issuer: 'urn:somebody:else' }), 403, 'STS-FED-0117'],
      ['5f. one addressed to another endpoint, 403 (0118)',
       logoutRequestUrl({ sessionIndex: 'idx-one-' + MODE, key: partnerKey,
                          destination: 'https://elsewhere.example/slo' }),
       403, 'STS-FED-0118'],
      ['5g. one issued an hour ago, 403 (0119)',
       logoutRequestUrl({ sessionIndex: 'idx-one-' + MODE, key: partnerKey,
                          issueInstant: new Date(Date.now() - 3600000)
                            .toISOString() }), 403, 'STS-FED-0119']
    ];
    for (const one of refusals) {
      since = marks.length;
      const r = await request('GET', one[1].url.replace(base, ''));
      note(r.status === one[2] && marked(since, one[3]) && !!fedSession(SAML),
           one[0] + ', and ends nothing', r.status + ' ' +
           JSON.stringify(marks.slice(since)));
    }
    since = marks.length;
    const unknown = await request('GET', logoutRequestUrl({
      sessionIndex: 'idx-nobody', key: partnerKey }).url.replace(base, ''));
    const unknownAnswer = unknown.headers.location
      ? responseIn(unknown.headers.location) : null;
    note(unknown.status === 303 && unknownAnswer &&
         unknownAnswer.verified && unknownAnswer.to === PARTNER_SLO &&
         unknownAnswer.codes.indexOf('Requester') >= 0 &&
         unknownAnswer.codes.indexOf('UnknownPrincipal') >= 0 &&
         unknownAnswer.relay === 'fso-relay' &&
         marked(since, 'STS-FED-0122') && !!fedSession(SAML),
         '5h. an unknown SessionIndex is answered with a SIGNED ' +
         'LogoutResponse, Requester/UnknownPrincipal, RelayState returned, ' +
         'and ends nothing (0122)', unknown.status + ' ' +
         JSON.stringify(unknownAnswer && unknownAnswer.codes));
    const valid = logoutRequestUrl({ sessionIndex: 'idx-one-' + MODE,
                                     key: partnerKey });
    const heldBefore = held;
    const accepted = await request('GET', valid.url.replace(base, ''));
    const answer = accepted.headers.location
      ? responseIn(accepted.headers.location) : null;
    note(accepted.status === 303 && answer && answer.verified &&
         answer.codes[0] === 'Success' &&
         new RegExp('InResponseTo="' + valid.id + '"').test(answer.xml) &&
         heldBefore &&
         !inSp(function () { return authn.sessionById(heldBefore.id); }),
         '5i. a signed LogoutRequest naming the session ends it and is ' +
         'answered with a signed Success LogoutResponse',
         accepted.status + ' ' + JSON.stringify(answer && answer.codes));
    since = marks.length;
    const replayed = await request('GET', valid.url.replace(base, ''));
    note(replayed.status === 403 && marked(since, 'STS-FED-0120'),
         '5j. the same LogoutRequest again is a replay, 403 (0120)',
         replayed.status);

    // THE SERVICE-PROVIDER-INITIATED ROUND TRIP: /logout sends the partner a
    // signed LogoutRequest; its LogoutResponse is matched once.
    await samlSignIn('idx-two-' + MODE, '');
    held = fedSession(SAML);
    const bye = await request('POST', '/realm/' + SP + '/logout',
                              { form: { scope: 'global' } });
    const outLink = decodeHtml((/href="(https:\/\/partner\.invalid\/slo[^"]*)"/
      .exec(bye.text) || [])[1] || '');
    let sent = null;
    if (outLink) {
      const url = new URL(outLink);
      const raw = url.search.slice(1);
      const pick = function (name) {
        const m = new RegExp('(?:^|&)' + name + '=([^&]*)').exec(raw);
        return m ? m[1] : '';
      };
      const signedOctets = 'SAMLRequest=' + pick('SAMLRequest') +
        '&RelayState=' + pick('RelayState') + '&SigAlg=' + pick('SigAlg');
      sent = {
        verified: stsCrypto.verifyQueryString(signedOctets, {
          signature: decodeURIComponent(pick('Signature')),
          sigAlg: decodeURIComponent(pick('SigAlg')),
          certPem: spXmlCert }).ok,
        xml: zlib.inflateRawSync(Buffer.from(decodeURIComponent(
          pick('SAMLRequest')), 'base64')).toString('utf8'),
        relay: decodeURIComponent(pick('RelayState'))
      };
    }
    note(sent && sent.verified &&
         sent.xml.indexOf('<saml:NameID Format="urn:oasis:names:tc:SAML:' +
           '2.0:nameid-format:persistent">' + NAMEID + '</saml:NameID>') >=
           0 && sent.xml.indexOf('<samlp:SessionIndex>idx-two-' + MODE) >=
           0 && held &&
         !inSp(function () { return authn.sessionById(held.id); }),
         '5k. /logout ends the session and offers the partner a SIGNED ' +
         'LogoutRequest naming the NameID and SessionIndex',
         bye.status + ' ' + outLink.slice(0, 200));
    if (sent) {
      const requestId = (/ID="([^"]+)"/.exec(sent.xml) || [])[1];
      const lrXml = '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:' +
        'SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
        'assertion" ID="_lresp' + nodeCrypto.randomBytes(6).toString('hex') +
        '" Version="2.0" IssueInstant="' + new Date().toISOString() +
        '" Destination="' + samlSlo + '" InResponseTo="' + requestId +
        '"><saml:Issuer>' + PARTNER + '</saml:Issuer><samlp:Status>' +
        '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:' +
        'Success"/></samlp:Status></samlp:LogoutResponse>';
      let qs = 'SAMLResponse=' + encodeURIComponent(zlib.deflateRawSync(
        Buffer.from(lrXml)).toString('base64')) + '&RelayState=' +
        encodeURIComponent(sent.relay) + '&SigAlg=' +
        encodeURIComponent(RSA_SHA256);
      qs += '&Signature=' + encodeURIComponent(nodeCrypto.sign('sha256',
        Buffer.from(qs), partnerKey.privateKeyPem).toString('base64'));
      since = marks.length;
      const confirmed = await request('GET', '/realm/' + SP +
                                      '/federation/slo/' + SAML + '?' + qs);
      const twice = await request('GET', '/realm/' + SP +
                                  '/federation/slo/' + SAML + '?' + qs);
      note(confirmed.status === 200 && /confirmed/.test(confirmed.text) &&
           twice.status === 400 && marked(since, 'STS-FED-0124'),
           '5l. the partner\'s signed LogoutResponse is matched by ' +
           'InResponseTo and RelayState once; again it is refused (0124)',
           confirmed.status + ' ' + twice.status);
    }

    // =======================================================================
    // 6. SessionNotOnOrAfter
    // =======================================================================
    const past = fedSp.sessionBoundOf({ sessionNotOnOrAfter:
      new Date(Date.now() - 3600000).toISOString() });
    const unreadable = fedSp.sessionBoundOf({ sessionNotOnOrAfter: 'soon' });
    const future = fedSp.sessionBoundOf({ sessionNotOnOrAfter:
      new Date(Date.now() + 3600000).toISOString() });
    note(past.refused && unreadable.refused && !future.refused &&
         future.at > Date.now() + 3500000,
         '6a. a SessionNotOnOrAfter that has passed, or cannot be read, ' +
         'refuses; a future one is the bound');
    since = marks.length;
    const late = await samlSignIn('idx-late-' + MODE,
      new Date(Date.now() - 3600000).toISOString().replace(/\.\d{3}Z$/, 'Z'));
    note(late.status === 401 && marked(since, 'STS-FED-0131'),
         '6b. an assertion whose SessionNotOnOrAfter has passed starts no ' +
         'session (401, 0131)', late.status);
    inSp(function () {
      config.setOverride('oauth2.clockSkewS', '0');
    });
    await samlSignIn('idx-short-' + MODE,
      new Date(Date.now() + 2000).toISOString());
    held = fedSession(SAML);
    note(held && held.expires <= Date.now() + 2500 &&
         held.expiresBoundBy === 'SessionNotOnOrAfter',
         '6c. the partner\'s SessionNotOnOrAfter is the session\'s expiry',
         JSON.stringify(held && [held.expires - Date.now(),
                                 held.expiresBoundBy]));
    await wait(3000);
    note(held && inSp(function () {
      return authn.sessionEnded(authn.sessionById(held.id));
    }) === 'expired',
         '6d. and it has ended when that instant passes');
    inSp(function () {
      config.clearOverride('oauth2.clockSkewS');
    });

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: '[' + MODE + '] the child ran to the ' +
                                     'end', detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function runMode(t, modeName) {
  log.debug("Entering runMode(). " + modeName);
  const out = path.join(os.tmpdir(), 'federation-signout-' + process.pid +
                        '-' + modeName + '-' +
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
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', FSO_ROOT: ROOT,
                                  FSO_OUT: out, FSO_MODE: modeName }),
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
  name: 'federation_signout',
  describe: 'a federation partner\'s sign-out (#167), in development and ' +
            'product: the Redirect-binding verifier; a genuine Back-Channel ' +
            'Logout Token from another realm ending the federated session, ' +
            'and every section 2.6 refusal; Front-Channel Logout framed by ' +
            'the partner only; RP-Initiated Logout offered from /logout; a ' +
            'SAML partner\'s LogoutRequest refusals, UnknownPrincipal, the ' +
            'signed LogoutResponse and the SP-initiated round trip; and ' +
            'SessionNotOnOrAfter bounding the session',
  run: run
};
