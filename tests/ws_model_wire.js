// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/ws_model_wire.js
//
// ---------------------------------------------------------------------------
// WHAT WS-TRUST AND WS-FEDERATION ANSWER, HELD BYTE FOR BYTE (#1579 item 6).
//
// The trust namespaces, request types, token types, key types, fault codes
// and actions WS-Trust 1.0-1.4 answers with, the SOAP envelopes and faults
// of both SOAP versions, the WS-Security references it writes, and
// WS-Federation 1.2's parameters, its sign-in response and its role in the
// metadata come from `models/ws/*.tsp` since #1579. Before the switch they
// were written by hand in `ws-trust/wstrust.ts` and
// `ws-federation/wsfed.ts`, and the switch was to change NOTHING a client
// sees: the model describes and validates the wire, it does not reshape
// it. So this records what the hand-written version answered, in
// `tests/ws_model_wire.snapshot.json`, and holds every later build to it: a
// scripted conversation over HTTP — GET /sts and its certificate, an Issue
// of each token type in each trust version on both SOAP versions, a
// Renew, a Validate of a token and of nothing, a Cancel in 1.3 and in
// 2004/04, a requested Lifetime clamped, and the refusals (not XML, a wrong
// password, no credential, both delegation elements, an AppliesTo nobody
// registered, none at all, a Kerberos token asked for with issuing off); and
// WS-Federation's description page, both metadata paths and one relying
// party's, a sign-in with and without a session, each token type and trust
// version, wreq, wctx echoed, and the refusals (wreqptr, no wtrealm, an
// unknown wauth, a token type not offered, a wreply nobody registered,
// wattr1.0, an unknown wa, an unregistered wtrealm, the initiation link
// off), and both sign-outs — in a development realm and a product realm.
//
// What is recorded of each answer: the status, every header but the ones
// that are about the connection, and the body. The `wresult` a sign-in
// response posts is DECODED beside it, so the record is the XML a relying
// party parses.
//
// Values that differ from run to run are replaced by a placeholder: every
// ID this service mints (numbered within a step), an instant, a port, a
// signature's and a digest's value, a certificate, a cipher value, a key
// identifier, a JWT, a cookie, a handle and any long random run — matched
// by where it is, not by whether it happens to hold a digit or a capital.
// The comparison is of everything else, exactly.
//
// `WS_WIRE_PRINT=1 node tests/ws_model_wire.js` prints the snapshot
// instead of comparing it; that is how the file was written, from the image
// of the tree before the switch, and how it is rewritten when the wire is
// MEANT to change.
//
// A CHILD PROCESS, as tests/saml_model_wire.js runs one: the protocol stack
// and a listener are loaded once, fresh, and nothing leaks into the runner.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'ws_model_wire',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'ws_model_wire.snapshot.json');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WW_ROOT;
  const OUT = process.env.WW_OUT;
  const http = require('http');
  const record = { wire: [], problems: [] };
  const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
             '(KHTML, like Gecko) Chrome/124.0 Safari/537.36';
  const SKIPPED_HEADERS = ['date', 'connection', 'keep-alive',
                           'content-length', 'etag', 'transfer-encoding'];
  const SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/';
  const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
  const WST13 = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
  const WST2005 = 'http://schemas.xmlsoap.org/ws/2005/02/trust';
  const WST2004 = 'http://schemas.xmlsoap.org/ws/2004/04/trust';
  const WST14 = 'http://docs.oasis-open.org/ws-sx/ws-trust/200802';
  const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
               'wssecurity-secext-1.0.xsd';
  const WSP = 'http://schemas.xmlsoap.org/ws/2004/09/policy';
  const WSA = 'http://www.w3.org/2005/08/addressing';
  const SAML2_TT = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-' +
                   'profile-1.1#SAMLV2.0';
  const SAML11_TT = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-' +
                    'profile-1.1#SAMLV1.1';
  const JWT_TT = 'urn:ietf:params:oauth:token-type:jwt';
  const KERBEROS_TT = 'http://docs.oasis-open.org/wss/oasis-wss-kerberos-' +
                      'token-profile-1.1#GSS_Kerberosv5_AP_REQ';

  function unescapeHtml(text) {
    return String(text).replace(/&#x2B;|&#43;/g, '+')
      .replace(/&#x2F;|&#47;/g, '/').replace(/&#x3D;|&#61;/g, '=')
      .replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  }

  // What an answer carries, decoded: a form's fields (the wresult is XML),
  // and a Location's path and parameters.
  function decoded(res) {
    const out = {};
    const location = String(res.headers.location || '');
    if (location) {
      try {
        const url = new URL(location, 'http://127.0.0.1');
        url.searchParams.forEach(function (value, name) {
          out['location.param.' + name] = value;
        });
        out['location.path'] = url.origin + url.pathname;
      } catch (e) {
        out['location.unparsed'] = location;
      }
    }
    const body = String(res.body || '');
    const form = /<form[^>]*action="([^"]*)"/.exec(body);
    if (form) {
      out['form.action'] = unescapeHtml(form[1]);
      const inputs = /<input[^>]*>/g;
      let m;
      while ((m = inputs.exec(body)) !== null) {
        const name = /name="([^"]*)"/.exec(m[0]);
        const value = /value="([^"]*)"/.exec(m[0]);
        if (name) {
          out['form.' + name[1]] = value ? unescapeHtml(value[1]) : '';
        }
      }
    }
    return out;
  }

  function request(port, method, target, cookie, body, contentType) {
    const url = new URL(target, 'http://127.0.0.1:' + port);
    return new Promise(function (resolve) {
      const headers = { 'user-agent': UA };
      if (cookie) {
        headers.cookie = cookie;
      }
      const text = body === undefined ? '' : String(body);
      if (method === 'POST') {
        headers['content-type'] = contentType ||
          'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
        path: url.pathname + url.search, method: method, headers: headers,
        agent: false },
      function (res) {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
          raw += chunk;
        });
        res.on('end', function () {
          const kept = {};
          Object.keys(res.headers).sort().forEach(function (name) {
            if (SKIPPED_HEADERS.indexOf(name) < 0) {
              kept[name] = res.headers[name];
            }
          });
          resolve({ status: res.statusCode, headers: kept, body: raw });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, headers: {}, body: String(e && e.message) });
      });
      req.end(text);
    });
  }

  // An RST: `o.soap11`, `o.trustNs`, `o.op`, `o.security`, `o.tokenType`,
  // `o.appliesTo`, `o.body` (more of the RST), `o.header` (more headers).
  function rst(o) {
    const ns = o.trustNs || WST13;
    return '<s:Envelope xmlns:s="' + (o.soap11 ? SOAP11 : SOAP12) +
      '" xmlns:wsse="' + WSSE + '" xmlns:wsa="' + WSA + '"><s:Header>' +
      '<wsa:Action>' + ns + '/RST/' + (o.op || 'Issue') + '</wsa:Action>' +
      (o.header || '') +
      (o.security ? '<wsse:Security>' + o.security + '</wsse:Security>'
                  : '') +
      '</s:Header><s:Body><wst:RequestSecurityToken xmlns:wst="' + ns +
      '"><wst:RequestType>' + ns + '/' + (o.op || 'Issue') +
      '</wst:RequestType>' + (o.tokenType ? '<wst:TokenType>' +
        o.tokenType + '</wst:TokenType>' : '') + (o.appliesTo
        ? '<wsp:AppliesTo xmlns:wsp="' + WSP + '"><wsa:EndpointReference>' +
          '<wsa:Address>' + o.appliesTo + '</wsa:Address>' +
          '</wsa:EndpointReference></wsp:AppliesTo>' : '') +
      (o.body || '') +
      '</wst:RequestSecurityToken></s:Body></s:Envelope>';
  }

  function usernameToken(user, pass) {
    return '<wsse:UsernameToken><wsse:Username>' + user +
      '</wsse:Username>' + (pass === null ? '' : '<wsse:Password>' + pass +
      '</wsse:Password>') + '</wsse:UsernameToken>';
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const keystore = require(ROOT + '/common/keystore');
    const pki = require(ROOT + '/common/pki');
    const helpers = require(ROOT + '/common/helpers');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const errorCodes = require(ROOT + '/common/error_codes');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const authn = require(ROOT + '/authn/authn');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const kit = require(ROOT + '/tests/tools/saml_signing_kit');
    const consent = require(ROOT + '/common/consent');

    const MODES = [
      { name: 'development', id: 'wswire', product: false },
      { name: 'product', id: 'wswirep', product: true }
    ];
    await keystore.start();
    MODES.forEach(function (mode) {
      if (!realms.get(mode.id)) {
        const made = realms.create({ id: mode.id, name: mode.id,
                                     description: 'ws_model_wire.js' });
        if (!made.ok) {
          record.problems.push(mode.name + ': ' + JSON.stringify(made));
        }
      }
    });
    await pki.start({ realmIds: [''].concat(MODES.map(function (m) {
      return m.id;
    })),
    keySetFor: function (id) {
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      return false;
    } });

    let lastCode = '';
    const server = http.createServer(function (req, res) {
      res.on('finish', function () {
        lastCode = errorCodes.codeOf(res);
      });
      app(req, res);
    });
    await new Promise(function (ok) {
      server.listen(0, '127.0.0.1', ok);
    });
    const port = server.address().port;

    const BACK = 'https://back.wswire.test/service';
    const RP = 'https://rp.wswire.test/app';
    const RP_REPLY = 'https://rp.wswire.test/reply';
    const PERSON = 'wswalice';
    const PASSWORD = 'Wire-Password-7a!Kq2';

    MODES.forEach(function (mode) {
      realms.run(realms.get(mode.id), function () {
        const made = ldap.createUser(PERSON, { invent: false, attributes: {
          givenName: 'Wire', sn: 'Alice', mail: PERSON + '@wire.test' } });
        if (made && made.ok === false) {
          record.problems.push(mode.name + ': person ' +
                               JSON.stringify(made));
        }
        const pw = credentials.setPassword(PERSON, PASSWORD);
        if (pw && pw.ok === false) {
          record.problems.push(mode.name + ': password ' +
                               JSON.stringify(pw));
        }
        const back = applications.createApplication({ identifier: 'wsback',
          protocols: ['wstrust'],
          fields: { oauthClientId: 'wsback', wstrustAppliesTo: [BACK] } });
        if (!back.ok) {
          record.problems.push('back: ' + JSON.stringify(back));
        }
        const rp = applications.createApplication({ identifier: RP,
          protocols: ['wsfed'], fields: { wsfedReplyUrl: [RP_REPLY] } });
        if (!rp.ok) {
          record.problems.push('rp: ' + JSON.stringify(rp));
        }
        consent.record(PERSON, RP, [consent.SSO_SIGN_IN_SCOPE]);
        if (mode.product) {
          // Scoring is turned off for the sign-in, as
          // tests/wsfed_initiation.js's product pass does: this child's
          // connections have no history to score, and a risk denial is not
          // what this records.
          const unscored = config.setOverride('risk.assessSignIns', false);
          if (unscored && unscored.ok === false) {
            record.problems.push('risk: ' + JSON.stringify(unscored));
          }
          const moded = config.setOverride('global.mode', 'product');
          if (moded && moded.ok === false) {
            record.problems.push('product: ' + JSON.stringify(moded));
          }
        }
      });
    });

    for (let m = 0; m < MODES.length; m++) {
      const mode = MODES[m];
      const P = '/realm/' + mode.id;
      const inRealm = function (fn) {
        return realms.run(realms.get(mode.id), fn);
      };
      const signIn = function () {
        return inRealm(function () {
          const res = kit.fakeRes();
          // Product requires a second factor of every person (ASVS 5.0.0
          // 6.3.3), so its session carries two.
          authn.startSession(res, PERSON, mode.product ? ['pwd', 'otp']
                                                       : ['pwd'],
                             mode.product ? 'mfa' : '1', 'ws_model_wire', {});
          return [].concat(res.headers['set-cookie'] || [])
            .map(function (line) {
              return String(line).split(';')[0];
            }).filter(function (pair) {
              return /^sts_session=/.test(pair);
            })[0] || '';
        });
      };
      const step = async function (name, method, target, cookie, body,
                                   contentType) {
        const r = await request(port, method, target, cookie, body,
                                contentType);
        record.wire.push({ mode: mode.name, step: name, method: method,
                           path: target, status: r.status, code: lastCode,
                           headers: r.headers, decoded: decoded(r),
                           body: r.body });
        return r;
      };
      const sts = function (name, xml, soap11) {
        return step(name, 'POST', P + '/sts', '', xml,
                    soap11 ? 'text/xml; charset=utf-8'
                           : 'application/soap+xml; charset=utf-8');
      };
      // Product refuses a second-factor person's own password at /sts and
      // takes an app password scoped to it (#101).
      const secret = mode.product ? inRealm(function () {
        const made = credentials.createAppPassword(PERSON, {
          name: 'ws_model_wire', doors: ['wstrust'], createdBy: PERSON });
        if (!made.ok) {
          record.problems.push('app password: ' + JSON.stringify(made));
        }
        return made.password;
      }) : PASSWORD;
      const ut = usernameToken(PERSON, secret);

      // --- WS-Trust ----------------------------------------------------------
      await step('GET /sts', 'GET', P + '/sts');
      await step('GET /sts/cert', 'GET', P + '/sts/cert');
      const issued = await sts('Issue SAML 2.0, 1.3, SOAP 1.2',
        rst({ security: ut, tokenType: SAML2_TT, appliesTo: BACK }));
      await sts('Issue SAML 2.0, 1.3, SOAP 1.1',
        rst({ soap11: true, security: ut, tokenType: SAML2_TT,
              appliesTo: BACK }), true);
      await sts('Issue SAML 1.1, 1.3', rst({ security: ut,
        tokenType: SAML11_TT, appliesTo: BACK }));
      await sts('Issue SAML 1.1 by its assertion namespace', rst({
        security: ut, tokenType: 'urn:oasis:names:tc:SAML:1.0:assertion',
        appliesTo: BACK }));
      await sts('Issue JWT, 1.3', rst({ security: ut, tokenType: JWT_TT,
                                        appliesTo: BACK }));
      await sts('Issue, no TokenType', rst({ security: ut,
                                             appliesTo: BACK }));
      await sts('Issue, 2005/02', rst({ trustNs: WST2005, security: ut,
        tokenType: SAML2_TT, appliesTo: BACK }));
      await sts('Issue, 2004/04, SOAP 1.1', rst({ soap11: true,
        trustNs: WST2004, security: ut, tokenType: SAML2_TT,
        appliesTo: BACK }), true);
      await sts('Issue, a KeyType and a Lifetime asked for, clamped',
        rst({ security: ut, tokenType: SAML2_TT, appliesTo: BACK,
              body: '<wst:KeyType>' + WST13 + '/SymmetricKey</wst:KeyType>' +
                '<wst:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-' +
                'open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-' +
                '1.0.xsd">2026-01-01T00:00:00Z</wsu:Created><wsu:Expires ' +
                'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-' +
                '200401-wss-wssecurity-utility-1.0.xsd">2027-01-01T00:00:00Z' +
                '</wsu:Expires></wst:Lifetime>' }));
      const assertion = (function () {
        const found = /<saml:Assertion[\s\S]*?<\/saml:Assertion>/
          .exec(String(issued.body));
        return found ? found[0] : '';
      })();
      await sts('Renew the issued assertion', rst({ op: 'Renew',
        security: ut, tokenType: SAML2_TT, appliesTo: BACK,
        body: '<wst:RenewTarget>' + assertion + '</wst:RenewTarget>' }));
      await sts('Validate the issued assertion', rst({ op: 'Validate',
        security: ut, tokenType: WST13 + '/RSTR/Status',
        body: '<wst:ValidateTarget>' + assertion + '</wst:ValidateTarget>' }));
      await sts('Validate nothing', rst({ op: 'Validate', security: ut,
        body: '<wst:ValidateTarget/>' }));
      await sts('Cancel, 1.3', rst({ op: 'Cancel', security: ut,
        body: '<wst:CancelTarget>' + assertion + '</wst:CancelTarget>' }));
      await sts('Cancel, 2004/04: refused', rst({ op: 'Cancel',
        trustNs: WST2004, security: ut }));
      await sts('not XML', 'this is not <xml', false);
      await sts('no credential', rst({ tokenType: SAML2_TT,
                                       appliesTo: BACK }));
      await sts('both OnBehalfOf and ActAs', rst({ security: ut,
        tokenType: SAML2_TT, appliesTo: BACK,
        body: '<wst:OnBehalfOf>' + assertion + '</wst:OnBehalfOf>' +
          '<wst14:ActAs xmlns:wst14="' + WST14 + '">' + assertion +
          '</wst14:ActAs>' }));
      await sts('an AppliesTo nobody registered', rst({ security: ut,
        tokenType: SAML2_TT, appliesTo: 'https://nobody.wswire.test/' }));
      await sts('no AppliesTo', rst({ security: ut, tokenType: SAML2_TT }));
      await sts('a Kerberos token asked for, issuing off', rst({
        security: ut, tokenType: KERBEROS_TT, appliesTo: BACK }));

      // Last of WS-Trust: refused passwords count toward a lockout (#1448).
      await sts('a wrong password, SOAP 1.2', rst({
        security: usernameToken(PERSON, 'invalid'),
        tokenType: SAML2_TT, appliesTo: BACK }));
      await sts('a wrong password, SOAP 1.1', rst({ soap11: true,
        security: usernameToken(PERSON, 'invalid'),
        tokenType: SAML2_TT, appliesTo: BACK }), true);

      // --- WS-Federation -----------------------------------------------------
      const wsfed = function (params) {
        return P + '/wsfed?' + new URLSearchParams(params).toString();
      };
      await step('GET /wsfed', 'GET', P + '/wsfed');
      await step('the federation metadata', 'GET',
                 P + '/FederationMetadata/2007-06/FederationMetadata.xml');
      await step('one relying party\'s metadata', 'GET',
                 P + '/wsfed/metadata/' + encodeURIComponent(RP));
      await step('the metadata of a relying party nobody registered', 'GET',
                 P + '/wsfed/metadata/nobody.wswire.test');
      await step('wsignin1.0, no session', 'GET', wsfed({ wa: 'wsignin1.0',
        wtrealm: RP, wctx: 'ctx-1' }));
      const alice = signIn();
      await step('wsignin1.0, signed in: SAML 1.1', 'GET', wsfed({
        wa: 'wsignin1.0', wtrealm: RP, wctx: 'ctx-2' }), alice);
      await step('wsignin1.0 posted: SAML 2.0 by tokenType', 'POST',
                 P + '/wsfed', alice, new URLSearchParams({ wa: 'wsignin1.0',
                   wtrealm: RP, wreply: RP_REPLY, tokenType: 'saml2' })
                   .toString());
      await step('wsignin1.0: trust 1.3', 'GET', wsfed({ wa: 'wsignin1.0',
        wtrealm: RP, trust: '1.3', tokenType: 'saml2' }), alice);
      await step('wsignin1.0: wreq names the token type', 'GET', wsfed({
        wa: 'wsignin1.0', wtrealm: RP,
        wreq: '<wst:RequestSecurityToken xmlns:wst="' + WST2005 + '">' +
          '<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion' +
          '</wst:TokenType></wst:RequestSecurityToken>' }), alice);
      await step('wsignin1.0: wfresh=0, whr and wct', 'GET', wsfed({
        wa: 'wsignin1.0', wtrealm: RP, wfresh: '0', whr: 'urn:home',
        wct: '2026-01-01T00:00:00Z' }), alice);
      await step('wsignin1.0: a password wauth the session meets', 'GET',
        wsfed({ wa: 'wsignin1.0', wtrealm: RP,
                wauth: 'urn:oasis:names:tc:SAML:1.0:am:password' }), alice);
      await step('wsignin1.0: a multi-factor wauth, a step-up', 'GET',
        wsfed({ wa: 'wsignin1.0', wtrealm: RP,
                wauth: 'http://schemas.microsoft.com/claims/multipleauthn' }),
        alice);
      await step('wsignin1.0: an unknown wauth', 'GET', wsfed({
        wa: 'wsignin1.0', wtrealm: RP, wauth: 'urn:example:retina' }), alice);
      await step('wsignin1.0: wreqptr', 'GET', wsfed({ wa: 'wsignin1.0',
        wtrealm: RP, wreqptr: 'https://evil.wswire.test/rst' }), alice);
      await step('wsignin1.0: no wtrealm', 'GET', wsfed({ wa: 'wsignin1.0' }),
                 alice);
      await step('wsignin1.0: a token type not offered', 'GET', wsfed({
        wa: 'wsignin1.0', wtrealm: RP, tokenType: 'urn:example:token' }),
        alice);
      await step('wsignin1.0: a wreply nobody registered', 'GET', wsfed({
        wa: 'wsignin1.0', wtrealm: RP,
        wreply: 'https://elsewhere.wswire.test/' }), alice);
      await step('wsignin1.0: a wtrealm nobody registered', 'GET', wsfed({
        wa: 'wsignin1.0', wtrealm: 'https://nobody.wswire.test/',
        wreply: 'https://nobody.wswire.test/reply' }), alice);
      await step('wattr1.0', 'GET', wsfed({ wa: 'wattr1.0' }), alice);
      await step('an unknown wa', 'GET', wsfed({ wa: 'wsomething1.0' }),
                 alice);
      await step('the initiation link, off by default', 'GET',
                 P + '/wsfed/initiate/' + encodeURIComponent(RP), alice);
      await step('wsignoutcleanup1.0', 'GET', wsfed({
        wa: 'wsignoutcleanup1.0', wtrealm: RP }), alice);
      const bob = signIn();
      await step('wsignout1.0', 'GET', wsfed({ wa: 'wsignout1.0',
        wtrealm: RP, wreply: RP_REPLY }), bob);
    }
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push('threw: ' + ((e && e.stack) || e));
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

// The attributes whose value this service mints, in any namespace: each
// value is replaced by a placeholder numbered within its step, everywhere
// it appears in that step, so a reference to it still names it. The text
// is a step's JSON, so a quote may be escaped.
const MINTED =
  /\b(ID|AssertionID|ResponseID|Id|InResponseTo|SessionIndex)=\\?"([^"\\]+)\\?"/g;

// The elements whose text is key material, a minted reference or a value
// drawn at random.
const OPAQUE = ['SignatureValue', 'DigestValue', 'X509Certificate',
                'CipherValue', 'KeyIdentifier', 'BinarySecret',
                'BinarySecurityToken', 'AssertionIDReference'];

// One step's text, its minted values numbered.
function numberMinted(text) {
  log.debug("Entering numberMinted().");
  const seen = new Map();
  let match;
  MINTED.lastIndex = 0;
  while ((match = MINTED.exec(text)) !== null) {
    const value = match[2];
    if (value.length >= 8 && !seen.has(value)) {
      seen.set(value, '<id' + (seen.size + 1) + '>');
    }
  }
  let out = text;
  seen.forEach(function (placeholder, value) {
    out = out.split(value).join(placeholder);
  });
  log.debug("Leaving numberMinted().");
  return out;
}

// The run-to-run values, each replaced by a placeholder, so that two runs
// of one tree record the same text.
function normalise(record) {
  log.debug("Entering normalise().");
  const opaque = new RegExp('(<(?:[A-Za-z0-9]+:)?(?:' + OPAQUE.join('|') +
                            ')(?:\\s[^>]*)?>)[^<]*(</)', 'g');
  const PATTERNS = [
    ['pem', /-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----(\\n)?/g],
    ['jwt', /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g],
    ['value', /value=\\"[^"\\]{40,}\\"/g],
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['port', /127\.0\.0\.1(:|%3A|%253A)\d+/g],
    ['epoch', /\b1[789]\d{11}\b/g],
    ['cookie', /\b(sts_[a-z_]+)=[^;"\s]+/g],
    ['incident', /(Incident ID<\/dt><dd><code>)\d+/g],
    ['handle', /\b(authn|rid|fid|sts_signout_account)=[A-Za-z0-9_%-]{12,}/g],
    ['handleParam',
     /("location\.param\.(?:authn|rid|fid|sts_signout_account)": ?")[^"]+/g],
    ['chain', /(<ds:X509Certificate><opaque><\/ds:X509Certificate>)+/g],
    ['hex', /\b[0-9a-f]{24,}\b/g],
    // A run of base64 or base64url of 24 or more characters holding a
    // capital and a digit; every value this service draws at random is
    // placeholdered above by where it stands, so this is the last net. It
    // does not start after a '.' or a ':', which is where a URI's path does
    // — a trust namespace's action or key type is what this records — and
    // it holds no '/', so a path is never one: a base64 value that can hold
    // one is placeholdered by the element or attribute it stands in.
    ['random', /(?<![A-Za-z0-9_+/=.:-])(?=[A-Za-z0-9_+=-]*[A-Z])(?=[A-Za-z0-9_+=-]*[0-9])[A-Za-z0-9_+=-]{24,}/g]
  ];
  const wire = record.wire.map(function (one) {
    let text = numberMinted(JSON.stringify(one));
    text = text.replace(opaque, '$1<opaque>$2');
    PATTERNS.forEach(function (pair) {
      if (pair[0] === 'value') {
        text = text.replace(pair[1], 'value=\\"<value>\\"');
      } else if (pair[0] === 'incident') {
        text = text.replace(pair[1], '$1<incident>');
      } else if (pair[0] === 'handle') {
        text = text.replace(pair[1], '$1=<handle>');
      } else if (pair[0] === 'handleParam') {
        text = text.replace(pair[1], '$1<handle>');
      } else if (pair[0] === 'chain') {
        text = text.replace(pair[1], '<chain>');
      } else if (pair[0] === 'cookie') {
        text = text.replace(pair[1], '$1=<cookie>');
      } else {
        text = text.replace(pair[1], '<' + pair[0] + '>');
      }
    });
    return JSON.parse(text);
  });
  log.debug("Leaving normalise().");
  return { wire: wire, problems: record.problems };
}

// Runs the child and answers its record, normalised, or null.
function capture() {
  log.debug("Entering capture().");
  const out = path.join(os.tmpdir(), 'ws-model-wire-' + process.pid +
                        '-' + Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|SAML|WS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', WW_ROOT: ROOT, WW_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT,
      maxBuffer: 64 * 1024 * 1024
    });
  let record = null;
  try {
    record = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in capture(): " + ((e && e.message) || e));
    log.debug("Leaving capture(). No record: exit " + result.status + " " +
              String(result.stderr || '').slice(-800));
    return null;
  }
  log.debug("Leaving capture().");
  return normalise(record);
}

// The first place two values differ, as a dotted path, or null.
function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + '.' + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  log.debug("Leaving firstDifference().");
  return where + ': ' + JSON.stringify(b).slice(0, 400) + ' where ' +
    JSON.stringify(a).slice(0, 400) + ' was recorded';
}

// The XML documents of every recorded step: each XML body and each posted
// wresult, what tests/model_ws.js holds to the model.
function messages(record) {
  log.debug("Entering messages().");
  const out = [];
  (record ? record.wire : []).forEach(function (one) {
    const decodedOf = one.decoded || {};
    if (typeof decodedOf['form.wresult'] === 'string') {
      out.push({ step: one.mode + ', ' + one.step + ' (wresult)',
                 xml: decodedOf['form.wresult'] });
    }
    if (/xml/.test(String((one.headers || {})['content-type'] || '')) &&
        typeof one.body === 'string') {
      out.push({ step: one.mode + ', ' + one.step + ' (body)',
                 xml: one.body });
    }
  });
  log.debug("Leaving messages().");
  return out;
}

function run(t) {
  log.debug("Entering run().");
  const now = capture();
  if (!t.check(!!now, 'the child process reported')) {
    log.debug("Leaving run().");
    return;
  }
  t.check(now.problems.length === 0, 'the child ran to the end',
          now.problems.join('\n'));
  let recorded = null;
  try {
    recorded = JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    recorded = null;
  }
  if (!t.check(!!recorded, 'the recorded wire is in the tree', SNAPSHOT)) {
    log.debug("Leaving run().");
    return;
  }
  t.check(recorded.wire.length === now.wire.length,
          'the conversation has as many steps as recorded',
          now.wire.length + ' vs ' + recorded.wire.length);
  recorded.wire.forEach(function (one, i) {
    t.check(firstDifference(one, now.wire[i], 'wire') === null,
            one.mode + ', ' + one.step + ' answers as recorded (' +
            one.status + ')', firstDifference(one, now.wire[i], 'wire'));
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env.WS_WIRE_PRINT) {
  process.stdout.write(JSON.stringify(capture(), null, 1) + '\n');
}

module.exports = {
  name: 'ws_model_wire',
  describe: 'what WS-Trust and WS-Federation answer, byte for byte, ' +
            'against the record made before their namespaces, request, ' +
            'token and key types, faults, envelopes, parameters and the ' +
            'order of every element they write came from the model ' +
            '(#1579): each operation in each trust and SOAP version, each ' +
            'refusal, the sign-in response, the metadata and both ' +
            'sign-outs, in development and product realms',
  run: run,
  messages: messages,
  capture: capture,
  normalise: normalise,
  SNAPSHOT: SNAPSHOT
};
