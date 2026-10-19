// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_jit.js
//
// ===========================================================================
// A CREATED FEDERATED ENTRY IS `<relationship>~<subject>` (#358), ON THE
// SIGN-IN PROTOCOLS THE OIDC JOBS DO NOT DRIVE.
//
// OpenID Connect's create and its refusal live in
// `tests/federation_provisioning.js` and `tests/federation_subject_policy.js`.
// This file posts a partner's assertion — or, for plain OAuth 2.0, follows
// the authorization-code redirect to a loopback token endpoint — and reads
// the directory:
//
//   * SAML 2.0, SAML 1.1 (unsolicited, which that protocol's create turns
//     on), WS-Federation and OAuth 2.0 each create one entry, and with
//     `fedAutocreateUsers` off refuse the next (`STS-FED-0090`, the page
//     says the person has not been provisioned);
//   * `alice@a.example` and `alice@b.example` become two entries, not one
//     `rel~alice`;
//   * `fedProvisionCap` refuses the next newcomer once the relationship is
//     already at the count, and the linked person still signs in;
//   * `federation.provision-idle` disables a person whose
//     `federationLastSeen` is old and whose only path is that relationship,
//     and leaves a password, a missing timestamp and a second link alone;
//   * a cap that is not a count is `STS-FED-0160`.
//
// A development child. Product stores `fedAutocreateUsers` FALSE; this
// file asserts the development default and then drives the switch itself.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'federation_jit', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.JIT_ROOT;
  const OUT = process.env.JIT_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const federation = require(ROOT + '/federation/federation');
    const errorCodes = require(ROOT + '/common/error_codes');
    const credentials = require(ROOT + '/common/credentials');
    const scheduler = require(ROOT + '/cluster/scheduler');
    const provision = require(ROOT + '/federation/federation_provision');
    const xmldsig = require(ROOT + '/tests/vendored/saml_xmldsig');
    const forge = require('node-forge');

    const marks = [];
    const mark = errorCodes.mark;
    errorCodes.mark = function (res, code) {
      marks.push(code);
      return mark.apply(this, arguments);
    };
    function saw(from, code) {
      return marks.slice(from).indexOf(code) >= 0;
    }

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;

    const SAML2 = 'jit-saml2';
    const SAML11 = 'jit-saml11';
    const WSFED = 'jit-wsfed';
    const OAUTH = 'jit-oauth';
    const ENTITY = 'https://jit.example/sp';
    const ISS2 = 'https://partner.example/jit-saml2';
    const ISS11 = 'https://partner.example/jit-saml11';
    const ISSWS = 'https://partner.example/jit-wsfed';
    const ISSOA = 'https://partner.example/jit-oauth';
    const PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    const OLD = '20200101000000Z';
    let oauthSubject = 'oauth-first';

    const job = scheduler.job('federation.provision-idle');
    note(!!job && job.kind === 'cluster' &&
         job.owner === 'federation/federation_provision.ts' &&
         job.everyMs() === 300000,
         '0. federation.provision-idle is a cluster job, every five minutes',
         job && (job.id + ' ' + job.kind + ' ' + job.owner));

    config.setOverride('federation.outboundAllowHttp', 'true');

    let jar = {};
    function cookieHeader() {
      return Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ');
    }
    function request(method, target, opts) {
      const o = opts || {};
      const url = new URL(target, base);
      const sts = url.hostname === '127.0.0.1' &&
                  String(url.port) === String(port);
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign({}, o.headers || {});
        if (sts && cookieHeader()) headers.cookie = cookieHeader();
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({
          host: url.hostname, port: url.port, method: method,
          path: url.pathname + url.search, headers: headers
        }, function (res) {
          if (sts) {
            [].concat(res.headers['set-cookie'] || [])
              .forEach(function (line) {
                const pair = String(line).split(';')[0];
                const i = pair.indexOf('=');
                if (i > 0) {
                  const name = pair.slice(0, i).trim();
                  const value = pair.slice(i + 1).trim();
                  if (value) jar[name] = value;
                  else delete jar[name];
                }
              });
          }
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.on('error', function (e) {
          resolve({ status: 0, headers: {},
                    text: (e && e.message) || String(e) });
        });
        req.end(body);
      });
    }
    function snippet(r) {
      return r.status + ' ' + String(r.text || '').replace(/\s+/g, ' ')
        .slice(0, 280);
    }

    function person(name) {
      return ldap.existingUserEntry(name);
    }

    function locked(name) {
      const entry = person(name);
      return !!(entry && (entry.attributes.pwdaccountlockedtime || [])
        .length);
    }

    function linksOf(name) {
      const entry = person(name);
      return entry ? (entry.attributes.federationlink || []).slice() : [];
    }

    function uid(rel, subject) {
      return rel + '~' + subject;
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
      return { der: pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''),
               privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey) };
    }
    const partnerKey = selfSigned(
      forge.pki.rsa.generateKeyPair(2048), 'jit-partner');

    function makeRel(id, protocol, fields) {
      const made = federation.create({
        fedId: id, fedRole: 'service-provider', fedProtocol: protocol });
      const problems = [];
      function set(field, value) {
        const out = federation.update(id, { field: field, value: value });
        if (!out.ok) {
          problems.push(field + ' ' + (out.errors || []).join(' '));
        }
        return out;
      }
      Object.keys(fields).forEach(function (field) {
        set(field, fields[field]);
      });
      const enabled = set('fedEnabled', 'TRUE');
      return { made: made, enabled: enabled, problems: problems,
               record: federation.get(id) };
    }

    function xmlFields(issuer, opts) {
      const o = opts || {};
      const fields = {
        fedPeer: issuer,
        fedSsoUrl: issuer + '/sso',
        fedSigningCertificate: partnerKey.der,
        fedLocalEntityId: ENTITY
      };
      // SAML 1.1 has no encryption construct, so the field does not apply.
      if (o.unencrypted !== false) fields.fedAllowUnencrypted = 'TRUE';
      if (o.unsolicited) fields.fedAllowUnsolicited = 'TRUE';
      return fields;
    }

    function sign2(issuer, subject) {
      const built = xmldsig.buildAssertion({
        issuer: issuer, subject: subject, audience: ENTITY,
        nameIdFormat: PERSISTENT, authnStatement: true });
      return xmldsig.sign(built, partnerKey.privateKeyPem, '');
    }

    function saml2Document(signed) {
      const id = '_r' + nodeCrypto.randomBytes(4).toString('hex');
      return '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:' +
        'protocol" ID="' + id + '" Version="2.0" IssueInstant="' +
        new Date().toISOString() + '"><samlp:Status><samlp:StatusCode ' +
        'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>' +
        '</samlp:Status>' + signed + '</samlp:Response>';
    }

    function postSaml(id, xml) {
      return request('POST', '/federation/acs/' + id, { form: {
        SAMLResponse: Buffer.from(xml).toString('base64') } });
    }

    async function created(id, issuer, subject, version) {
      const from = marks.length;
      const name = uid(id, subject);
      let xml;
      if (version === '1.1') {
        const built = xmldsig.buildAssertion11({
          issuer: issuer, subject: subject, audience: ENTITY });
        const signed = xmldsig.sign(built, partnerKey.privateKeyPem, '',
                                     { at: 'end' });
        const rid = '_r' + nodeCrypto.randomBytes(4).toString('hex');
        xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:1.0:' +
          'protocol" ResponseID="' + rid + '" MajorVersion="1" ' +
          'MinorVersion="1" IssueInstant="' + new Date().toISOString() +
          '"><samlp:Status><samlp:StatusCode Value="samlp:Success"/>' +
          '</samlp:Status>' + signed + '</samlp:Response>';
      } else if (version === 'wsfed') {
        const signed = sign2(issuer, subject);
        xml = '<trust:RequestSecurityTokenResponse xmlns:trust=' +
          '"http://schemas.xmlsoap.org/ws/2005/02/trust">' +
          '<trust:RequestedSecurityToken>' + signed +
          '</trust:RequestedSecurityToken>' +
          '</trust:RequestSecurityTokenResponse>';
      } else {
        xml = saml2Document(sign2(issuer, subject));
      }
      const r = version === 'wsfed'
        ? await request('POST', '/federation/acs/' + id, { form: {
          wa: 'wsignin1.0', wresult: xml } })
        : await postSaml(id, xml);
      return { r: r, name: name, entry: person(name),
               marked: saw(from, 'STS-FED-0090'), from: from };
    }

    const saml2 = makeRel(SAML2, 'saml2',
                          xmlFields(ISS2, { unsolicited: true }));
    note(saml2.made.ok && saml2.enabled.ok && saml2.record &&
         saml2.record.fedAutocreateUsers === 'TRUE',
         '0b. a new relationship stores fedAutocreateUsers on, in ' +
         'development',
         (saml2.record && saml2.record.fedAutocreateUsers) + ' ' +
         saml2.problems.join('; '));

    const first = await created(SAML2, ISS2, 'saml2-first', '2.0');
    const firstOld = person(SAML2 + '~saml2');
    note(first.r.status === 200 && first.entry && !firstOld &&
         linksOf(first.name).length === 1,
         '1a. SAML 2.0 creates ' + first.name,
         snippet(first.r) + ' links=' + linksOf(first.name).length);

    const off = federation.update(SAML2, {
      field: 'fedAutocreateUsers', value: 'FALSE' });
    const absent = await created(SAML2, ISS2, 'saml2-second', '2.0');
    note(off.ok && absent.r.status === 403 && absent.marked &&
         /not been provisioned/.test(absent.r.text) && !absent.entry,
         '1b. SAML 2.0 with fedAutocreateUsers off refuses STS-FED-0090 ' +
         'and creates nothing',
         snippet(absent.r) + ' marked=' + absent.marked);
    federation.update(SAML2, {
      field: 'fedAutocreateUsers', value: 'TRUE' });

    // Not `alice@`: the default realm already has alice, and link-at-first
    // confirms that mapped local-part instead of creating. `jit-ada@` maps
    // to nobody, so the two subjects are created whole.
    const aliceA = await created(SAML2, ISS2, 'jit-ada@a.example', '2.0');
    const aliceB = await created(SAML2, ISS2, 'jit-ada@b.example', '2.0');
    const collapsed = person(SAML2 + '~jit-ada');
    function storedUid(entry) {
      return entry ? String((entry.attributes.uid || [])[0] || '') : '';
    }
    note(aliceA.r.status === 200 && aliceB.r.status === 200 &&
         aliceA.entry && aliceB.entry && aliceA.name !== aliceB.name &&
         storedUid(aliceA.entry) === aliceA.name &&
         storedUid(aliceB.entry) === aliceB.name && !collapsed,
         '2. two email subjects that share a local-part are two entries',
         'uidA=' + storedUid(aliceA.entry) + ' uidB=' +
         storedUid(aliceB.entry) + ' collapsed=' +
         (collapsed ? storedUid(collapsed) : '') + ' ' +
         snippet(aliceA.r) + ' || ' + snippet(aliceB.r));

    const count = federation.provisionedCount(SAML2);
    const capSet = federation.update(SAML2, {
      field: 'fedProvisionCap', value: String(count) });
    const capped = await created(SAML2, ISS2, 'saml2-capped', '2.0');
    const again = await created(SAML2, ISS2, 'saml2-first', '2.0');
    note(capSet.ok && count > 0 && capped.r.status === 403 &&
         capped.marked && /not been provisioned/.test(capped.r.text) &&
         !capped.entry && again.r.status === 200 && again.entry,
         '3. fedProvisionCap refuses the next newcomer and the linked ' +
         'person still signs in',
         'count=' + count + ' ' + snippet(capped.r) + ' || ' +
         snippet(again.r));

    const aged = person(first.name);
    const agedAttrs = {};
    Object.keys(aged.attributes).forEach(function (key) {
      const value = aged.attributes[key];
      agedAttrs[key] = Array.isArray(value) ? value.slice() : [String(value)];
    });
    agedAttrs.federationlastseen = [OLD];
    const agedWrite = ldap.writePerson(aged.dn, agedAttrs);
    function plant(name, opts) {
      const made = ldap.createUser(name, { invent: false });
      let password = null;
      if (opts.password) {
        password = credentials.setPassword(name, opts.password);
      }
      const entry = ldap.existingUserEntry(name);
      const attrs = {};
      Object.keys(entry.attributes).forEach(function (key) {
        const value = entry.attributes[key];
        attrs[key] = Array.isArray(value) ? value.slice() : [String(value)];
      });
      attrs.federationlink = opts.links;
      if (opts.lastSeen) attrs.federationlastseen = [opts.lastSeen];
      else delete attrs.federationlastseen;
      const written = ldap.writePerson(entry.dn, attrs);
      return { made: made, password: password, written: written,
               entry: ldap.existingUserEntry(name) };
    }
    const pass = plant('jit-has-password', {
      password: 'Jit-Local-Passw0rd!',
      lastSeen: OLD,
      links: [SAML2 + ' ' + ISS2 + ' jit-has-password']
    });
    const unseen = plant('jit-no-seen', {
      links: [SAML2 + ' ' + ISS2 + ' jit-no-seen']
    });
    const other = plant('jit-two-links', {
      lastSeen: OLD,
      links: [SAML2 + ' ' + ISS2 + ' jit-two-links',
              'jit-other ' + ISS2 + ' jit-two-links']
    });
    const idleSet = federation.update(SAML2, {
      field: 'fedProvisionIdleMinutes', value: '30' });
    const swept = provision.sweepIdle(Date.now());
    const passHash = pass.entry &&
      (pass.entry.attributes.userpassword || []).length;
    note(agedWrite.ok && idleSet.ok && swept.disabled === 1 &&
         locked(first.name) && linksOf(first.name).length === 1 &&
         pass.written.ok && passHash && !locked('jit-has-password') &&
         unseen.written.ok && !locked('jit-no-seen') &&
         other.written.ok && !locked('jit-two-links') &&
         !locked(aliceA.name) && !locked(aliceB.name),
         '4. the idle sweep disables only the person whose last seen is ' +
         'old and whose only path is this relationship',
         'disabled=' + swept.disabled + ' aged=' + agedWrite.ok +
         ' pass=' + !!(pass.password && pass.password.ok) +
         ' hash=' + passHash + ' unseen=' + unseen.written.ok +
         ' other=' + other.written.ok);
    const againSweep = provision.sweepIdle(Date.now());
    note(againSweep.disabled === 0 && locked(first.name),
         '4b. a second sweep disables nobody already locked',
         'disabled=' + againSweep.disabled);

    const saml11 = makeRel(SAML11, 'saml11',
                           xmlFields(ISS11, { unencrypted: false }));
    note(saml11.made.ok && saml11.record &&
         saml11.record.fedAllowUnsolicited === 'TRUE' &&
         saml11.record.fedAutocreateUsers === 'TRUE',
         '5. SAML 1.1 create turns fedAllowUnsolicited on',
         (saml11.record && saml11.record.fedAllowUnsolicited) + ' ' +
         saml11.problems.join('; '));
    const unsolicited = await created(SAML11, ISS11, 'saml11-first', '1.1');
    note(unsolicited.r.status === 200 && unsolicited.entry,
         '5a. an unsolicited SAML 1.1 response creates ' + unsolicited.name,
         snippet(unsolicited.r));
    federation.update(SAML11, {
      field: 'fedAutocreateUsers', value: 'FALSE' });
    const unsolicitedOff = await created(SAML11, ISS11, 'saml11-second',
                                         '1.1');
    note(unsolicitedOff.r.status === 403 && unsolicitedOff.marked &&
         /not been provisioned/.test(unsolicitedOff.r.text) &&
         !unsolicitedOff.entry,
         '5b. SAML 1.1 with the switch off refuses STS-FED-0090',
         snippet(unsolicitedOff.r));

    const wsfed = makeRel(WSFED, 'wsfed',
                          xmlFields(ISSWS, { unsolicited: true }));
    const ws = await created(WSFED, ISSWS, 'wsfed-first', 'wsfed');
    note(wsfed.made.ok && ws.r.status === 200 && ws.entry,
         '6a. WS-Federation creates ' + ws.name,
         snippet(ws.r) + ' ' + wsfed.problems.join('; '));
    federation.update(WSFED, {
      field: 'fedAutocreateUsers', value: 'FALSE' });
    const wsOff = await created(WSFED, ISSWS, 'wsfed-second', 'wsfed');
    note(wsOff.r.status === 403 && wsOff.marked &&
         /not been provisioned/.test(wsOff.r.text) && !wsOff.entry,
         '6b. WS-Federation with the switch off refuses STS-FED-0090',
         snippet(wsOff.r));

    const keys = nodeCrypto.generateKeyPairSync('rsa', {
      modulusLength: 2048 });
    const jwk = keys.publicKey.export({ format: 'jwk' });
    jwk.kid = 'jit-oauth';
    jwk.alg = 'RS256';
    jwk.use = 'sig';
    function accessToken(sub) {
      const header = Buffer.from(JSON.stringify({
        alg: 'RS256', kid: 'jit-oauth' })).toString('base64url');
      const now = Math.floor(Date.now() / 1000);
      const body = Buffer.from(JSON.stringify({
        iss: ISSOA, sub: sub, iat: now, exp: now + 300
      })).toString('base64url');
      const data = header + '.' + body;
      const sig = nodeCrypto.sign('sha256', Buffer.from(data),
                                   keys.privateKey).toString('base64url');
      return data + '.' + sig;
    }
    const mock = http.createServer(function (req, res) {
      const url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname === '/authorize') {
        const back = url.searchParams.get('redirect_uri') + '?code=jit-code' +
          '&state=' + encodeURIComponent(url.searchParams.get('state') || '');
        res.writeHead(302, { Location: back });
        res.end();
        return;
      }
      if (url.pathname === '/token') {
        let dumped = '';
        req.on('data', function (c) { dumped += c; });
        req.on('end', function () {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            access_token: accessToken(oauthSubject), token_type: 'Bearer',
            dumped: dumped.length }));
        });
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise(function (r) { mock.listen(0, '127.0.0.1', r); });
    const mockPort = mock.address().port;
    const oauth = makeRel(OAUTH, 'oauth2', {
      fedPeer: ISSOA,
      fedSsoUrl: 'http://127.0.0.1:' + mockPort + '/authorize',
      fedTokenUrl: 'http://127.0.0.1:' + mockPort + '/token',
      fedClientId: 'jit-oauth-client',
      fedJwks: JSON.stringify({ keys: [jwk] }),
      fedLocalEntityId: ENTITY
    });
    async function oauthSignIn(subject) {
      oauthSubject = subject;
      jar = {};
      const from = marks.length;
      let r = await request('GET', '/federation/login/' + OAUTH);
      for (let hop = 0; hop < 8; hop += 1) {
        const at = r.headers && r.headers.location;
        if (r.status >= 300 && r.status < 400 && at) {
          r = await request('GET', at);
          continue;
        }
        break;
      }
      const name = uid(OAUTH, subject);
      return { r: r, name: name, entry: person(name),
               marked: saw(from, 'STS-FED-0090') };
    }
    const oauthIn = await oauthSignIn('oauth-first');
    note(oauth.made.ok && oauth.enabled.ok && oauthIn.r.status === 200 &&
         oauthIn.entry,
         '7a. plain OAuth 2.0 creates ' + oauthIn.name,
         snippet(oauthIn.r) + ' ' + oauth.problems.join('; '));
    federation.update(OAUTH, {
      field: 'fedAutocreateUsers', value: 'FALSE' });
    const oauthOff = await oauthSignIn('oauth-second');
    note(oauthOff.r.status === 403 && oauthOff.marked &&
         /not been provisioned/.test(oauthOff.r.text) && !oauthOff.entry,
         '7b. OAuth 2.0 with the switch off refuses STS-FED-0090',
         snippet(oauthOff.r));

    const junk = federation.update(SAML2, {
      field: 'fedProvisionCap', value: 'nope' });
    note(!junk.ok && /number of people/.test((junk.errors || []).join(' ')),
         '8. a cap that is not a count is refused (STS-FED-0160)',
         (junk.errors || []).join(' '));

    mock.close();
    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'federation-jit-' + process.pid +
                        '-' + require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  if (process.env.NODE_V8_COVERAGE) {
    clean.STS_FEDERATION_OUTBOUND_TIMEOUT_MS = '60000';
  }
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', JIT_ROOT: ROOT, JIT_OUT: out }),
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
  if (t.check(Array.isArray(findings), 'the child process reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-1200))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'federation_jit',
  describe: 'SAML 2.0, SAML 1.1, WS-Federation and OAuth 2.0 each create a ' +
            'federated entry named <relationship>~<subject>, refuse the ' +
            'next when fedAutocreateUsers is off, keep two email subjects ' +
            'apart, honour fedProvisionCap, and disable an idle federated ' +
            'person whose only path is that relationship',
  run: run
};
