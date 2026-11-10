// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/saml_model_wire.js
//
// ---------------------------------------------------------------------------
// WHAT BOTH SAML IDENTITY PROVIDERS ANSWER, HELD BYTE FOR BYTE (#1579 item 6).
//
// SAML 2.0's and SAML 1.1's vocabularies — the bindings, the status codes,
// the NameID formats, the confirmation methods, the authentication context
// classes — the attributes this service reads off an AuthnRequest and a
// LogoutRequest, and the order of the elements it writes into every message
// and metadata document come from `models/saml/*.tsp` since #1579. Before
// the switch they were written by hand in `saml/saml2_sso.ts`,
// `saml11_sso.ts`, `saml2.ts`, `saml11.ts` and `authn_context.ts`, and the
// switch was to change NOTHING a service provider sees: the model describes
// and validates the wire, it does not reshape it. So this records what the
// hand-written version answered, in `tests/saml_model_wire.snapshot.json`,
// and holds every later build to it: a scripted conversation over HTTP —
// every metadata document, sign-ins on the Redirect, POST and Artifact
// bindings and their resolution, the identity provider's own start, each
// AuthnRequest refusal, the attribute authority, Single Logout in both
// directions, and SAML 1.1's Browser/POST and Browser/Artifact profiles and
// every request its responder answers — in a development realm and a
// product realm, with the family's switches (`saml2.signResponse`,
// `saml2.signAssertion`, `saml2.requireSignedAuthnRequests`,
// `saml2.nameIdFormat`) turned for the steps they change.
//
// What is recorded of each answer: the status, every header but the ones
// that are about the connection, and the body. A SAML message the answer
// carries — a form's SAMLResponse, a Location's SAMLRequest or
// SAMLResponse (inflated), a SOAP body — is DECODED beside it, so the
// record is the XML a service provider parses. An artifact is recorded as
// its type code and length.
//
// Values that differ from run to run are replaced by a placeholder: every
// ID this service mints (numbered within a step, so a reference to one
// still names the same placeholder), an instant, a port, a signature's and
// a digest's value, a certificate, a cipher value, a NameID this service
// draws at random, a cookie and any long random run. The comparison is of
// everything else, exactly.
//
// `SAML_WIRE_PRINT=1 node tests/saml_model_wire.js` prints the snapshot
// instead of comparing it; that is how the file was written, from the image
// of the tree before the switch, and how it is rewritten when the wire is
// MEANT to change.
//
// A CHILD PROCESS, as tests/oauth_model_wire.js runs one: the protocol stack
// and a listener are loaded once, fresh, and nothing leaks into the runner.
// The federation module consumes SAML from partners through its own reader
// (`federation/federation_sp.ts`) and shares nothing here but
// `request_signature.ts` and `document_settings.ts`, which the switch left
// alone; `tests/federation_*.js` hold it.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'saml_model_wire',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'saml_model_wire.snapshot.json');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SW_ROOT;
  const OUT = process.env.SW_OUT;
  const http = require('http');
  const zlib = require('zlib');
  const record = { wire: [], problems: [] };
  const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
             '(KHTML, like Gecko) Chrome/124.0 Safari/537.36';
  const SKIPPED_HEADERS = ['date', 'connection', 'keep-alive',
                           'content-length', 'etag', 'transfer-encoding'];
  const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
  const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
  const NS_SAMLP11 = 'urn:oasis:names:tc:SAML:1.0:protocol';
  const NS_SAML11 = 'urn:oasis:names:tc:SAML:1.0:assertion';
  const NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';

  function soap(inner) {
    return '<soap:Envelope xmlns:soap="' + NS_SOAP + '"><soap:Body>' +
      inner + '</soap:Body></soap:Envelope>';
  }

  // The SAML message a value carries: base64, inflated when it was deflated.
  function decodeMessage(value, deflated) {
    try {
      const bytes = Buffer.from(String(value), 'base64');
      if (deflated) {
        return zlib.inflateRawSync(bytes).toString('utf8');
      }
      return bytes.toString('utf8');
    } catch (e) {
      return '(not decodable: ' + (e && e.message) + ')';
    }
  }

  // An artifact's shape: its type code, endpoint index and length.
  function artifactShape(value) {
    const bytes = Buffer.from(String(value), 'base64');
    return { length: bytes.length,
             typeCode: bytes.length >= 2 ? bytes.readUInt16BE(0) : -1,
             endpointIndex: bytes.length >= 4 ? bytes.readUInt16BE(2) : -1 };
  }

  function unescapeHtml(text) {
    return String(text).replace(/&#x2B;|&#43;/g, '+')
      .replace(/&#x2F;|&#47;/g, '/').replace(/&#x3D;|&#61;/g, '=')
      .replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  }

  // What an answer carries, decoded.
  function decoded(res) {
    const out = {};
    const location = String(res.headers.location || '');
    if (location) {
      try {
        const url = new URL(location, 'http://127.0.0.1');
        ['SAMLRequest', 'SAMLResponse'].forEach(function (name) {
          const value = url.searchParams.get(name);
          if (value) {
            out['location.' + name] = decodeMessage(value, true);
          }
        });
        const art = url.searchParams.get('SAMLart');
        if (art) {
          out['location.SAMLart'] = artifactShape(art);
        }
        url.searchParams.forEach(function (value, name) {
          out['location.param.' + name] =
            ['SAMLRequest', 'SAMLResponse', 'SAMLart', 'Signature']
              .indexOf(name) >= 0 ? '<value>' : value;
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
      const fields = {};
      while ((m = inputs.exec(body)) !== null) {
        const name = /name="([^"]*)"/.exec(m[0]);
        const value = /value="([^"]*)"/.exec(m[0]);
        if (name) {
          fields[name[1]] = value ? unescapeHtml(value[1]) : '';
        }
      }
      Object.keys(fields).forEach(function (name) {
        if (name === 'SAMLResponse' || name === 'SAMLRequest') {
          out['form.' + name] = decodeMessage(fields[name], false);
        } else if (name === 'SAMLart') {
          out['form.SAMLart'] = artifactShape(fields[name]);
        } else {
          out['form.' + name] = fields[name];
        }
      });
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

  function form(fields) {
    return Object.keys(fields).map(function (k) {
      return encodeURIComponent(k) + '=' + encodeURIComponent(fields[k]);
    }).join('&');
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
    const authn = require(ROOT + '/authn/authn');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const saml2Sso = require(ROOT + '/saml/saml2_sso');
    const kit = require(ROOT + '/tests/tools/saml_signing_kit');

    const MODES = [
      { name: 'development', id: 'samlwire', product: false },
      { name: 'product', id: 'samlwirep', product: true }
    ];
    await keystore.start();
    MODES.forEach(function (mode) {
      if (!realms.get(mode.id)) {
        const made = realms.create({ id: mode.id, name: mode.id,
                                     description: 'saml_model_wire.js' });
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

    const SP = 'https://sp.wire.test/sp';
    const SP_ACS = 'https://sp.wire.test/acs';
    const SP_SLO = 'https://sp.wire.test/slo';
    const RP = 'https://rp.wire.test/rp';
    const RP_SHIRE = 'https://rp.wire.test/shire';
    const PERSON = 'wirealice';

    const parties = function () {
      const sp = applications.createApplication({
        identifier: SP, kind: 'saml2-service-provider',
        protocol: 'SAML 2.0', protocols: ['saml2'],
        fields: { samlEntityId: SP, samlAssertionConsumerService: SP_ACS,
                  samlSingleLogoutService: SP_SLO,
                  saml2IdpInitiatedSso: 'TRUE' } });
      if (!sp.ok) {
        record.problems.push('sp: ' + JSON.stringify(sp));
      }
      const rp = applications.createApplication({
        identifier: RP, kind: 'saml11-relying-party',
        protocol: 'SAML 1.1', protocols: ['saml11'],
        fields: { samlEntityId: RP, samlAssertionConsumerService: RP_SHIRE,
                  saml11IdpInitiatedSso: 'TRUE' } });
      if (!rp.ok) {
        record.problems.push('rp: ' + JSON.stringify(rp));
      }
    };

    MODES.forEach(function (mode) {
      realms.run(realms.get(mode.id), function () {
        const made = ldap.createUser(PERSON, { invent: false, attributes: {
          givenName: 'Wire', sn: 'Alice', mail: PERSON + '@wire.test' } });
        if (made && made.ok === false) {
          record.problems.push(mode.name + ': person ' +
                               JSON.stringify(made));
        }
        parties();
        if (mode.product) {
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
      const set = function (key, value) {
        inRealm(function () {
          const done = config.setOverride(key, value);
          if (done && done.ok === false) {
            record.problems.push(mode.name + ': ' + key + ' ' +
                                 JSON.stringify(done));
          }
        });
      };
      const clear = function (key) {
        inRealm(function () {
          config.clearOverride(key);
        });
      };
      // A signed-in session for the person, and its cookie.
      const signIn = function () {
        return inRealm(function () {
          const res = kit.fakeRes();
          const session = authn.startSession(res, PERSON, ['pwd'], '1',
                                             'saml_model_wire', {});
          const cookie = [].concat(res.headers['set-cookie'] || [])
            .map(function (line) {
              return String(line).split(';')[0];
            }).filter(function (pair) {
              return /^sts_session=/.test(pair);
            })[0] || '';
          return { cookie: cookie, session: session };
        });
      };
      const step = async function (name, method, target, cookie, body,
                                   contentType) {
        const r = await request(port, method, target, cookie, body,
                                contentType);
        const code = lastCode;
        const entry = { mode: mode.name, step: name, method: method,
                        path: target.replace(/(SAMLRequest|SAMLResponse|Signature)=[^&]+/g,
                                             '$1=<value>'),
                        status: r.status, code: code, headers: r.headers,
                        decoded: decoded(r), body: r.body };
        record.wire.push(entry);
        return r;
      };
      let n = 0;
      const nextId = function (what) {
        n += 1;
        return '_wire-' + mode.id + '-' + what + '-' + n;
      };
      const authnRequest = function (o) {
        o = o || {};
        const id = o.id || nextId('ar');
        const attrs = [
          'xmlns:samlp="' + NS_SAMLP + '"', 'xmlns:saml="' + NS_SAML + '"',
          'ID="' + id + '"', 'Version="' + (o.version || '2.0') + '"',
          'IssueInstant="' + (o.issueInstant || new Date().toISOString()) +
            '"'
        ];
        if (o.destination) {
          attrs.push('Destination="' + o.destination + '"');
        }
        if (o.acsIndex !== undefined) {
          attrs.push('AssertionConsumerServiceIndex="' + o.acsIndex + '"');
        } else if (o.acs !== '') {
          attrs.push('AssertionConsumerServiceURL="' + (o.acs || SP_ACS) +
                     '"');
        }
        if (o.binding) {
          attrs.push('ProtocolBinding="' + o.binding + '"');
        }
        if (o.forceAuthn) {
          attrs.push('ForceAuthn="true"');
        }
        if (o.isPassive) {
          attrs.push('IsPassive="true"');
        }
        let inner = '<saml:Issuer>' + (o.issuer || SP) + '</saml:Issuer>';
        if (o.subject) {
          inner += '<saml:Subject><saml:NameID>' + o.subject +
            '</saml:NameID></saml:Subject>';
        }
        if (o.nameIdFormat) {
          inner += '<samlp:NameIDPolicy Format="' + o.nameIdFormat +
            '" AllowCreate="true"/>';
        }
        if (o.classRefs) {
          inner += '<samlp:RequestedAuthnContext Comparison="exact">' +
            o.classRefs.map(function (ref) {
              return '<saml:AuthnContextClassRef>' + ref +
                '</saml:AuthnContextClassRef>';
            }).join('') + '</samlp:RequestedAuthnContext>';
        }
        if (o.scoping) {
          inner += '<samlp:Scoping ProxyCount="1"><samlp:RequesterID>' +
            SP + '</samlp:RequesterID></samlp:Scoping>';
        }
        return '<samlp:AuthnRequest ' + attrs.join(' ') + '>' + inner +
          '</samlp:AuthnRequest>';
      };
      const redirect = function (xml, extra) {
        return P + '/saml2/sso?SAMLRequest=' + encodeURIComponent(
          zlib.deflateRawSync(Buffer.from(xml)).toString('base64')) +
          (extra || '');
      };
      const posted = function (xml) {
        return form({ SAMLRequest: Buffer.from(xml).toString('base64'),
                      RelayState: 'rs-post' });
      };

      // --- the metadata ----------------------------------------------------
      await step('SAML 2.0 metadata', 'GET', P + '/saml2/metadata');
      await step('SAML 2.0 metadata for one service provider', 'GET',
                 P + '/saml2/metadata/' + encodeURIComponent(SP));
      await step('SAML 2.0 metadata for a name nobody registered', 'GET',
                 P + '/saml2/metadata/nobody.wire.test');
      await step('SAML 1.1 metadata', 'GET', P + '/saml11/metadata');
      await step('SAML 1.1 metadata for one relying party', 'GET',
                 P + '/saml11/metadata/' + encodeURIComponent(RP));
      await step('the WS-Federation view of the entity', 'GET',
                 P + '/wsfed/metadata');

      // --- SAML 2.0 sign-in --------------------------------------------------
      // Product requires a signed AuthnRequest by default: once refused, the
      // rest of the conversation runs with the requirement off.
      await step('an unsigned AuthnRequest, signatures required by default',
                 'GET', redirect(authnRequest({}), '&RelayState=rs-1'));
      set('saml2.requireSignedAuthnRequests', 'off');
      await step('Redirect, no session: to the sign-in screen', 'GET',
                 redirect(authnRequest({}), '&RelayState=rs-2'));
      const alice = signIn();
      await step('Redirect, signed in: the POST binding answers', 'GET',
                 redirect(authnRequest({ destination: 'http://127.0.0.1:' +
                                         port + P + '/saml2/sso' }),
                          '&RelayState=rs-3'), alice.cookie);
      const heldPost = await step('POST binding: held and sent to a GET',
                                  'POST', P + '/saml2/sso', alice.cookie,
                                  posted(authnRequest({})));
      if (heldPost.headers.location) {
        await step('POST binding: the held request answered', 'GET',
                   heldPost.headers.location, alice.cookie);
      }
      await step('NameIDPolicy persistent', 'GET', redirect(authnRequest({
        nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
      })), alice.cookie);
      await step('NameIDPolicy transient', 'GET', redirect(authnRequest({
        nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
      })), alice.cookie);
      await step('NameIDPolicy emailAddress', 'GET', redirect(authnRequest({
        nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
      })), alice.cookie);
      await step('a Subject hint and Scoping are read and not refused', 'GET',
                 redirect(authnRequest({ subject: PERSON, scoping: true })),
                 alice.cookie);
      await step('ProtocolBinding HTTP-Redirect', 'GET', redirect(
        authnRequest({ binding:
          'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' })),
      alice.cookie);
      await step('ProtocolBinding HTTP-POST-SimpleSign', 'GET', redirect(
        authnRequest({ binding:
          'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign' })),
      alice.cookie);
      const art = await step('ProtocolBinding HTTP-Artifact', 'GET',
        redirect(authnRequest({ binding:
          'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact' }),
        '&RelayState=rs-art'), alice.cookie);
      const artValue = (function () {
        try {
          return new URL(String(art.headers.location || ''))
            .searchParams.get('SAMLart') || '';
        } catch (e) {
          return '';
        }
      })();
      const resolve = function (artifact, id) {
        return soap('<samlp:ArtifactResolve xmlns:samlp="' + NS_SAMLP +
          '" xmlns:saml="' + NS_SAML + '" ID="' + id +
          '" Version="2.0" IssueInstant="' + new Date().toISOString() +
          '"><saml:Issuer>' + SP + '</saml:Issuer><samlp:Artifact>' +
          artifact + '</samlp:Artifact></samlp:ArtifactResolve>');
      };
      await step('ArtifactResolve', 'POST', P + '/saml2/ars', '',
                 resolve(artValue, nextId('resolve')), 'text/xml');
      await step('ArtifactResolve, the same artifact again', 'POST',
                 P + '/saml2/ars', '', resolve(artValue, nextId('resolve')),
                 'text/xml');
      await step('ArtifactResolve, not XML', 'POST', P + '/saml2/ars', '',
                 'not xml', 'text/xml');

      // --- the switches ------------------------------------------------------
      set('saml2.signResponse', false);
      await step('saml2.signResponse off', 'GET', redirect(authnRequest({})),
                 alice.cookie);
      clear('saml2.signResponse');
      set('saml2.signAssertion', false);
      await step('saml2.signAssertion off', 'GET', redirect(authnRequest({})),
                 alice.cookie);
      clear('saml2.signAssertion');
      set('saml2.nameIdFormat',
          'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
      await step('saml2.nameIdFormat emailAddress', 'GET',
                 redirect(authnRequest({})), alice.cookie);
      clear('saml2.nameIdFormat');

      // --- the AuthnRequest's refusals ------------------------------------
      await step('a SAMLRequest that is not a message', 'GET',
                 P + '/saml2/sso?SAMLRequest=bm90IGEgbWVzc2FnZQ%3D%3D',
                 alice.cookie);
      await step('no SAMLRequest at all', 'GET', P + '/saml2/sso',
                 alice.cookie);
      await step('a LogoutRequest at the SSO service', 'GET', redirect(
        '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" ID="' +
        nextId('lr') + '" Version="2.0" IssueInstant="' +
        new Date().toISOString() + '"/>'), alice.cookie);
      await step('Version 1.0', 'GET',
                 redirect(authnRequest({ version: '1.0' })), alice.cookie);
      await step('a Destination elsewhere', 'GET', redirect(authnRequest({
        destination: 'https://elsewhere.wire.test/sso' })), alice.cookie);
      await step('an IssueInstant an hour old', 'GET', redirect(authnRequest({
        issueInstant: new Date(Date.now() - 3600000).toISOString() })),
      alice.cookie);
      const replayed = authnRequest({ id: nextId('replay') });
      await step('an AuthnRequest, the first time', 'GET', redirect(replayed),
                 alice.cookie);
      await step('the same AuthnRequest again', 'GET', redirect(replayed),
                 alice.cookie);
      await step('ProtocolBinding PAOS', 'GET', redirect(authnRequest({
        binding: 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS' })),
      alice.cookie);
      await step('IsPassive with no session', 'GET',
                 redirect(authnRequest({ isPassive: true })));
      await step('ForceAuthn: one trip to the screen', 'GET',
                 redirect(authnRequest({ forceAuthn: true })), alice.cookie);
      await step('RequestedAuthnContext MultiFactor, a password session',
                 'GET', redirect(authnRequest({ classRefs: [
                   'urn:oasis:names:tc:SAML:2.0:ac:classes:' +
                   'MultiFactorAuthnContract'] })), alice.cookie);
      await step('RequestedAuthnContext PasswordProtectedTransport', 'GET',
                 redirect(authnRequest({ classRefs: [
                   'urn:oasis:names:tc:SAML:2.0:ac:classes:' +
                   'PasswordProtectedTransport'] })), alice.cookie);
      await step('an unknown AssertionConsumerServiceIndex', 'GET',
                 redirect(authnRequest({ acsIndex: 7 })), alice.cookie);
      await step('an AssertionConsumerServiceURL nobody registered', 'GET',
                 redirect(authnRequest({ acs: 'https://evil.wire.test/acs' })),
                 alice.cookie);
      await step('an Issuer nobody registered', 'GET', redirect(authnRequest({
        issuer: 'https://stranger.wire.test/sp',
        acs: 'https://stranger.wire.test/acs' })), alice.cookie);

      // --- the identity provider's own start ------------------------------
      await step('an unsolicited Response', 'GET', P +
                 '/saml2/unsolicited?providerId=' + encodeURIComponent(SP) +
                 '&shire=' + encodeURIComponent(SP_ACS) + '&target=rs-u',
                 alice.cookie);
      await step('an unsolicited Response for a stranger', 'GET', P +
                 '/saml2/unsolicited?providerId=' +
                 encodeURIComponent('https://stranger.wire.test/sp'),
                 alice.cookie);

      // --- the attribute authority ----------------------------------------
      const given = inRealm(function () {
        const held = authn.sessionById(alice.session.id);
        const named = held && held.saml2ServiceProviders &&
          held.saml2ServiceProviders[SP];
        return named && named.nameId ? String(named.nameId) : '';
      });
      const query = function (nameId, id) {
        return soap('<samlp:AttributeQuery xmlns:samlp="' + NS_SAMLP +
          '" xmlns:saml="' + NS_SAML + '" ID="' + id +
          '" Version="2.0" IssueInstant="' + new Date().toISOString() +
          '"><saml:Issuer>' + SP + '</saml:Issuer><saml:Subject>' +
          '<saml:NameID>' + nameId + '</saml:NameID></saml:Subject>' +
          '</samlp:AttributeQuery>');
      };
      await step('an AttributeQuery about the session\'s subject', 'POST',
                 P + '/saml2/aa', '', query(given || PERSON, nextId('aq')),
                 'text/xml');
      await step('an AttributeQuery about nobody', 'POST', P + '/saml2/aa',
                 '', query('nobody-at-all', nextId('aq')), 'text/xml');

      // --- Single Logout --------------------------------------------------
      const idpInitiated = inRealm(function () {
        const held = authn.sessionById(alice.session.id);
        return held ? saml2Sso.logoutTargetsFor(held) : [];
      });
      record.wire.push({ mode: mode.name,
        step: 'the LogoutRequests an identity-provider-initiated logout ' +
              'sends', targets: (idpInitiated || []).map(function (one) {
          const url = String((one && (one.url || one.href)) || '');
          let xml = '';
          try {
            const parsed = new URL(url);
            xml = parsed.searchParams.get('SAMLRequest')
              ? decodeMessage(parsed.searchParams.get('SAMLRequest'), true)
              : '';
          } catch (e) {
            xml = '';
          }
          return { party: one && one.entityId, from: one && one.from,
                   url: url.replace(
                     /(SAMLRequest|Signature)=[^&]+/g, '$1=<value>'),
                   decoded: xml };
        }) });
      const logoutResponse = '<samlp:LogoutResponse xmlns:samlp="' +
        NS_SAMLP + '" xmlns:saml="' + NS_SAML + '" ID="' + nextId('lresp') +
        '" Version="2.0" IssueInstant="' + new Date().toISOString() +
        '" InResponseTo="_wire-none"><saml:Issuer>' + SP +
        '</saml:Issuer><samlp:Status><samlp:StatusCode Value="' +
        'urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '</samlp:LogoutResponse>';
      await step('a LogoutResponse from the service provider', 'GET',
                 P + '/saml2/slo?SAMLResponse=' + encodeURIComponent(
                   zlib.deflateRawSync(Buffer.from(logoutResponse))
                     .toString('base64')) + '&RelayState=rs-lr',
                 alice.cookie);
      const logoutRequest = function (nameId, id) {
        return '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP +
          '" xmlns:saml="' + NS_SAML + '" ID="' + id +
          '" Version="2.0" IssueInstant="' + new Date().toISOString() +
          '" Destination="http://127.0.0.1:' + port + P + '/saml2/slo">' +
          '<saml:Issuer>' + SP + '</saml:Issuer><saml:NameID>' + nameId +
          '</saml:NameID></samlp:LogoutRequest>';
      };
      await step('a LogoutRequest that is not XML', 'GET',
                 P + '/saml2/slo?SAMLRequest=bm90IHhtbA%3D%3D', alice.cookie);
      await step('a LogoutRequest from the service provider', 'GET',
                 P + '/saml2/slo?SAMLRequest=' + encodeURIComponent(
                   zlib.deflateRawSync(Buffer.from(logoutRequest(
                     given || PERSON, nextId('slo')))).toString('base64')) +
                 '&RelayState=rs-slo', alice.cookie);
      await step('a LogoutRequest with no session', 'POST', P + '/saml2/slo',
                 '', form({ SAMLRequest: Buffer.from(logoutRequest(
                   'nobody', nextId('slo'))).toString('base64') }));

      // --- SAML 1.1 ---------------------------------------------------------
      const bob = signIn();
      const sso11 = function (extra) {
        return P + '/saml11/sso?' + new URLSearchParams(Object.assign({
          providerId: RP, shire: RP_SHIRE,
          TARGET: 'https://rp.wire.test/app' }, extra || {})).toString();
      };
      await step('Browser/POST, no session: to the sign-in screen', 'GET',
                 sso11());
      await step('Browser/POST', 'GET', sso11(), bob.cookie);
      await step('Browser/POST, a format asked for', 'GET', sso11({
        format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' }),
      bob.cookie);
      const art11 = await step('Browser/Artifact', 'GET',
                               sso11({ profile: 'artifact' }), bob.cookie);
      const art11Value = (function () {
        try {
          return new URL(String(art11.headers.location || ''))
            .searchParams.get('SAMLart') || '';
        } catch (e) {
          return '';
        }
      })();
      const request11 = function (inner, id) {
        return soap('<samlp:Request xmlns:samlp="' + NS_SAMLP11 +
          '" xmlns:saml="' + NS_SAML11 + '" MajorVersion="1" ' +
          'MinorVersion="1" RequestID="' + id + '" IssueInstant="' +
          new Date().toISOString() + '">' + inner + '</samlp:Request>');
      };
      await step('the responder: an AssertionArtifact', 'POST',
                 P + '/saml11/responder', '', request11(
                   '<samlp:AssertionArtifact>' + art11Value +
                   '</samlp:AssertionArtifact>', nextId('r11')), 'text/xml');
      await step('the responder: the same artifact again', 'POST',
                 P + '/saml11/responder', '', request11(
                   '<samlp:AssertionArtifact>' + art11Value +
                   '</samlp:AssertionArtifact>', nextId('r11')), 'text/xml');
      const subject11 = '<saml:Subject><saml:NameIdentifier Format="' +
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">' + PERSON +
        '</saml:NameIdentifier></saml:Subject>';
      await step('the responder: an AttributeQuery', 'POST',
                 P + '/saml11/responder', '', request11(
                   '<samlp:AttributeQuery Resource="' + RP + '">' +
                   subject11 + '</samlp:AttributeQuery>', nextId('r11')),
                 'text/xml');
      await step('the responder: an AuthenticationQuery', 'POST',
                 P + '/saml11/responder', '', request11(
                   '<samlp:AuthenticationQuery>' + subject11 +
                   '</samlp:AuthenticationQuery>', nextId('r11')),
                 'text/xml');
      await step('the responder: an AuthorizationDecisionQuery', 'POST',
                 P + '/saml11/responder', '', request11(
                   '<samlp:AuthorizationDecisionQuery Resource="x">' +
                   subject11 + '<saml:Action>read</saml:Action>' +
                   '</samlp:AuthorizationDecisionQuery>', nextId('r11')),
                 'text/xml');
      await step('the responder: an AssertionIDReference nobody holds',
                 'POST', P + '/saml11/responder', '', request11(
                   '<saml:AssertionIDReference>_nothing' +
                   '</saml:AssertionIDReference>', nextId('r11')),
                 'text/xml');
      await step('the responder: a Request carrying nothing', 'POST',
                 P + '/saml11/responder', '', request11('', nextId('r11')),
                 'text/xml');
      await step('the responder: not XML', 'POST', P + '/saml11/responder',
                 '', 'not xml', 'text/xml');
      await step('no TARGET', 'GET', P + '/saml11/sso?providerId=' +
                 encodeURIComponent(RP) + '&shire=' +
                 encodeURIComponent(RP_SHIRE), bob.cookie);
      await step('a shire nobody registered', 'GET',
                 sso11({ shire: 'https://evil.wire.test/shire' }),
                 bob.cookie);
      await step('a relying party nobody registered', 'GET', sso11({
        providerId: 'https://stranger.wire.test/rp',
        shire: 'https://stranger.wire.test/shire' }), bob.cookie);
      await step('an unknown profile', 'GET', sso11({ profile: 'paos' }),
                 bob.cookie);
      await step('the inter-site transfer service\'s own start', 'GET',
                 P + '/saml11/sso/' + encodeURIComponent(RP) +
                 '?TARGET=' + encodeURIComponent('https://rp.wire.test/x'),
                 bob.cookie);
    }

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push(String(e && e.stack));
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

// The attributes whose values this service draws at random. Each distinct
// value is replaced by a placeholder numbered within its step, everywhere
// it appears in that step, so a reference to it still names it.
const MINTED = /\b(ID|AssertionID|ResponseID|SessionIndex|RequestID|Id)="([^"]+)"/g;

// The elements whose text is key material or a value drawn at random.
const OPAQUE = ['SignatureValue', 'DigestValue', 'X509Certificate',
                'CipherValue', 'MessageHandle', 'AssertionArtifact',
                'Artifact'];

// One step's text, its minted values numbered.
function numberMinted(text) {
  log.debug("Entering numberMinted().");
  const seen = new Map();
  let match;
  MINTED.lastIndex = 0;
  while ((match = MINTED.exec(text)) !== null) {
    const value = match[2];
    if (!/^_wire-/.test(value) && value.length >= 8 && !seen.has(value)) {
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
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['port', /127\.0\.0\.1(:|%3A|%253A)\d+/g],
    ['epoch', /\b1[789]\d{11}\b/g],
    ['cookie', /\b(sts_[a-z_]+)=[^;"\s]+/g],
    ['nameid', /(Format="urn:oasis:names:tc:SAML:2\.0:nameid-format:(?:transient|persistent)"[^>]*>)[^<]+/g],
    ['hex', /\b[0-9a-f]{24,}\b/g],
    ['random', /(?<![A-Za-z0-9_+/=-])(?=[A-Za-z0-9_+/=-]*[A-Z])(?=[A-Za-z0-9_+/=-]*[0-9])[A-Za-z0-9_+/=-]{24,}/g]
  ];
  const wire = record.wire.map(function (one) {
    let text = numberMinted(JSON.stringify(one));
    text = text.replace(opaque, '$1<opaque>$2');
    PATTERNS.forEach(function (pair) {
      if (pair[0] === 'nameid') {
        text = text.replace(pair[1], '$1<nameid>');
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
  const out = path.join(os.tmpdir(), 'saml-model-wire-' + process.pid +
                        '-' + Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|SAML|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SW_ROOT: ROOT, SW_OUT: out }),
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

// The SAML messages of every recorded step, decoded: what
// tests/model_saml.js holds to the model.
function messages(record) {
  log.debug("Entering messages().");
  const out = [];
  (record ? record.wire : []).forEach(function (one) {
    const decodedOf = one.decoded || {};
    Object.keys(decodedOf).forEach(function (key) {
      if (typeof decodedOf[key] === 'string' &&
          /^\s*(<\?xml[^>]*>)?\s*</.test(decodedOf[key])) {
        out.push({ step: one.mode + ', ' + one.step + ' (' + key + ')',
                   xml: decodedOf[key] });
      }
    });
    if (/xml/.test(String((one.headers || {})['content-type'] || '')) &&
        typeof one.body === 'string') {
      out.push({ step: one.mode + ', ' + one.step + ' (body)',
                 xml: one.body });
    }
    (one.targets || []).forEach(function (target) {
      if (target.decoded) {
        out.push({ step: one.mode + ', ' + one.step + ' (target)',
                   xml: target.decoded });
      }
    });
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
            (one.status === undefined ? 'in process' : one.status) + ')',
            firstDifference(one, now.wire[i], 'wire'));
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env.SAML_WIRE_PRINT) {
  process.stdout.write(JSON.stringify(capture(), null, 1) + '\n');
}

module.exports = {
  name: 'saml_model_wire',
  describe: 'what both SAML identity providers answer, byte for byte, ' +
            'against the record made before their vocabularies, the ' +
            'AuthnRequest\'s attributes and the order of every element they ' +
            'write came from the model (#1579): the metadata, sign-in on ' +
            'every binding, artifact resolution, each refusal, the ' +
            'attribute authority, single logout both ways, and SAML 1.1\'s ' +
            'profiles and responder, in development and product realms',
  run: run,
  messages: messages,
  capture: capture,
  SNAPSHOT: SNAPSHOT
};
