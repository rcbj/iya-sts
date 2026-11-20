// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/ssf_model_wire.js
//
// ---------------------------------------------------------------------------
// WHAT THE SHARED SIGNALS ENDPOINTS ANSWER AND SEND, HELD BYTE FOR BYTE
// (#1579 item 6).
//
// The Security Event Token envelope, every SSF, CAEP, RISC and service event
// type with its members, the RFC 9493 subject identifier formats, the
// transmitter metadata, the stream configuration and the error codes come
// from `models/ssf/ssf.tsp` since #1579. Before the switch they were tables
// written by hand in `ssf/ssf_events.js`, `ssf/ssf_subjects.js` and
// `ssf/ssf_streams.ts`, and the switch was to change NOTHING a receiver
// sees: the model describes and validates the wire, it does not reshape it.
// So this records what the hand-written version answered and sent, in
// `tests/ssf_model_wire.snapshot.json`, and holds every later build to it:
//
//   * a scripted conversation with every endpoint of the transmitter — the
//     metadata in both forms, stream management, status, subjects,
//     verification and poll, each success and its refusals — and the
//     receiver's push endpoints' refusals;
//   * every event type this service knows, transmitted on a poll stream with
//     the payload its row generates and collected by a poll, so each SET's
//     header and claims are held member by member;
//   * the subject grammar's and the event catalogue's verdicts on a battery
//     of right and wrong documents, word for word;
//   * the description document `GET /ssf?format=json`, which carries the
//     catalogue's prose and every format's example;
//
// in four realms: development (the default), product, development with the
// family's switches that change what is sent (`ssf.legacySubClaim`,
// `risc.googleSubjectType`, `ssf.pushDelivery` off), and the family off.
//
// What is recorded of each answer: the status, every header but the ones that
// are about the connection, and the body — parsed when it is JSON. A JWT is
// DECODED and its signature dropped. Values that differ from run to run are
// replaced by a placeholder (an instant, a port, a stream id, a jti, a txn, a
// random credential). The comparison is of everything else, exactly.
//
// `SSF_WIRE_PRINT=1 node tests/ssf_model_wire.js` prints the snapshot instead
// of comparing it; that is how the file was written, from the image of the
// tree before the switch, and how it is rewritten when the wire is MEANT to
// change.
//
// A CHILD PROCESS, as tests/oauth_model_wire.js runs one: the protocol stack
// and a listener are loaded once, fresh, and nothing leaks into the runner.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'ssf_model_wire',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'ssf_model_wire.snapshot.json');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SW_ROOT;
  const OUT = process.env.SW_OUT;
  const http = require('http');
  const record = { wire: [], verdicts: [], problems: [] };

  const SKIPPED_HEADERS = ['date', 'connection', 'keep-alive',
                           'content-length', 'etag', 'transfer-encoding'];

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      let body = '';
      const headers = Object.assign({}, o.headers || {});
      if (o.json !== undefined) {
        body = typeof o.json === 'string' ? o.json : JSON.stringify(o.json);
        headers['content-type'] = o.type || 'application/json';
      }
      if (body) {
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          let parsed;
          const type = String(res.headers['content-type'] || '');
          if (/json/.test(type) && text) {
            try {
              parsed = JSON.parse(text);
            } catch (e) {
              parsed = { unparsed: text };
            }
          } else {
            parsed = text;
          }
          const kept = {};
          Object.keys(res.headers).sort().forEach(function (name) {
            if (SKIPPED_HEADERS.indexOf(name) < 0) {
              kept[name] = res.headers[name];
            }
          });
          resolve({ status: res.statusCode, headers: kept, body: parsed });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, headers: {}, body: String(e && e.message) });
      });
      req.end(body);
    });
  }

  function basic(id, secret) {
    return 'Basic ' + Buffer.from(encodeURIComponent(id) + ':' +
                                  encodeURIComponent(secret))
      .toString('base64');
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const ssf = require(ROOT + '/ssf/ssf');
    const events = require(ROOT + '/ssf/ssf_events');
    const subjects = require(ROOT + '/ssf/ssf_subjects');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;

    // THE GRAMMAR AND THE CATALOGUE, ONCE: their verdicts word for word.
    const subjectCases = [
      ['email', { format: 'email', email: 'alice@example.com' }],
      ['email, an extra member', { format: 'email', email: 'a@b.c', x: 1 }],
      ['email, not an address', { format: 'email', email: 'nobody' }],
      ['no format', { email: 'alice@example.com' }],
      ['an unknown format', { format: 'nope', id: 'x' }],
      ['complex as a member', { format: 'complex', user: { format:
        'complex', user: { format: 'opaque', id: 'x' } } }],
      ['account', { format: 'account', uri: 'acct:alice@example.com' }],
      ['account, not acct', { format: 'account', uri: 'mailto:a@b.c' }],
      ['iss_sub', { format: 'iss_sub', iss: 'https://i.example/', sub: '1' }],
      ['iss_sub, relative iss', { format: 'iss_sub', iss: 'i', sub: '1' }],
      ['iss_sub, missing sub', { format: 'iss_sub', iss: 'https://i/' }],
      ['opaque', { format: 'opaque', id: '1111' }],
      ['opaque, empty', { format: 'opaque', id: '' }],
      ['opaque, a number', { format: 'opaque', id: 7 }],
      ['phone', { format: 'phone_number', phone_number: '+12065550100' }],
      ['phone, spaced', { format: 'phone_number',
                          phone_number: '+1 206 555 0100' }],
      ['did', { format: 'did', url: 'did:example:123' }],
      ['did, not a did', { format: 'did', url: 'https://x' }],
      ['uri', { format: 'uri', uri: 'urn:x:y' }],
      ['uri, relative', { format: 'uri', uri: 'x y' }],
      ['aliases', { format: 'aliases', identifiers: [
        { format: 'email', email: 'a@b.c' },
        { format: 'opaque', id: '1' }] }],
      ['aliases, empty', { format: 'aliases', identifiers: [] }],
      ['aliases, not an array', { format: 'aliases', identifiers: {} }],
      ['aliases, nested', { format: 'aliases', identifiers: [
        { format: 'aliases', identifiers: [] }] }],
      ['aliases, a bad member', { format: 'aliases', identifiers: [
        { format: 'email', email: 'x' }] }],
      ['jwt_id', { format: 'jwt_id', iss: 'https://i/', jti: 'j' }],
      ['jwt_id, relative iss', { format: 'jwt_id', iss: 'i', jti: 'j' }],
      ['saml_assertion_id', { format: 'saml_assertion_id',
        issuer: 'https://i/', assertion_id: '_a' }],
      ['ip-addresses', { format: 'ip-addresses',
        'ip-addresses': ['10.0.0.1', '::1'] }],
      ['ip-addresses, empty', { format: 'ip-addresses', 'ip-addresses': [] }],
      ['ip-addresses, a CIDR', { format: 'ip-addresses',
        'ip-addresses': ['10.0.0.0/8', 7] }],
      ['complex', { format: 'complex', user: { format: 'email',
        email: 'a@b.c' }, session: { format: 'opaque', id: 's' } }],
      ['complex, empty', { format: 'complex' }],
      ['complex, an additional member', { format: 'complex',
        building: { format: 'opaque', id: 'b1' } }],
      ['complex, a bad member name', { format: 'complex',
        '1bad': { format: 'opaque', id: 'b1' } }],
      ['complex, a bad member', { format: 'complex',
        user: { format: 'email', email: 'x', y: 1 } }],
      ['draft complex', { user: { format: 'email', email: 'a@b.c' } }],
      ['not an object', 'alice'],
      ['an array', []]
    ];
    subjectCases.forEach(function (one) {
      record.verdicts.push({ kind: 'subject', name: one[0],
        verdict: subjects.validateSubjectId(one[1], {}) });
    });
    record.verdicts.push({ kind: 'subject', name: 'complex, critical',
      verdict: subjects.validateSubjectId({ format: 'complex',
        user: { format: 'opaque', id: 'u' } },
      { criticalMembers: ['user', 'session'], path: 'subject' }) });
    record.verdicts.push({ kind: 'formats', names: subjects.FORMAT_NAMES,
      person: subjects.PERSON_FORMATS,
      complex: subjects.COMPLEX_MEMBER_NAMES });

    const C = events.CAEP_PREFIX;
    const R = events.RISC_PREFIX;
    const S = events.SSF_PREFIX;
    const eventCases = [
      ['unknown type', 'urn:nope', {}],
      ['not an object', C + 'session-revoked', []],
      ['session-revoked, bare', C + 'session-revoked', {}],
      ['session-revoked, reason as a string', C + 'session-revoked',
       { reason_admin: 'x', event_timestamp: '1757000000' }],
      ['session-revoked, a bad tag', C + 'session-revoked',
       { reason_user: { 'english!': 'x', en: 7 } }],
      ['session-revoked, a bad entity', C + 'session-revoked',
       { initiating_entity: 'robot' }],
      ['session-established, amr a string', C + 'session-established',
       { amr: 'pwd', acr: 1, fp_ua: 'f', ext_id: 'e' }],
      ['token-claims-change, claims an array', C + 'token-claims-change',
       { claims: [] }],
      ['token-claims-change, missing claims', C + 'token-claims-change', {}],
      ['credential-change, a vendor type', C + 'credential-change',
       { credential_type: 'vendor', change_type: 'create' }],
      ['credential-change, a bad change', C + 'credential-change',
       { credential_type: 'password', change_type: 'replace' }],
      ['assurance-level-change', C + 'assurance-level-change',
       { namespace: 'mine', current_level: 'x', change_direction: 'up' }],
      ['device-compliance-change', C + 'device-compliance-change',
       { previous_status: 'noncompliant', current_status: 'compliant' }],
      ['risk-level-change', C + 'risk-level-change',
       { principal: 'ROBOT', current_level: 'low' }],
      ['identifier-changed, the near miss', R + 'identifier-changed',
       { new_value: 'x' }],
      ['sessions-revoked, deprecated', R + 'sessions-revoked', {}],
      ['credential-compromise', R + 'credential-compromise',
       { credential_type: 'password', reason_admin: { en: 'x' } }],
      ['account-disabled, an extension', R + 'account-disabled',
       { reason: 'left', why: 'x' }],
      ['stream-updated, a bad status', S + 'stream-updated',
       { status: 'gone' }],
      ['verification, state a number', S + 'verification', { state: 1 }],
      ['spiffe-authority-rotated', events.SPIFFE_AUTHORITY_ROTATED,
       { realm: 'r', rotated: 'a', reason: 'scheduled',
         bundle_changed: 'yes' }],
      ['kerberos-tickets-invalidated', events.KERBEROS_TICKETS_INVALIDATED,
       { realm: 'r', kerberos_realm: 'R', kvno: '2', reason: 'x' }],
      ['announcement', events.ANNOUNCEMENT,
       { realm: 'r', message: 'm', surfaces: 'admin-console' }]
    ];
    eventCases.forEach(function (one) {
      record.verdicts.push({ kind: 'event', name: one[0],
        verdict: events.validateEvent(one[1], one[2]) });
    });
    events.EVENTS.forEach(function (row) {
      record.verdicts.push({ kind: 'row', uri: row.uri, name: row.name,
        family: row.family, subject: row.subject,
        subjectFormats: row.subjectFormats, deprecated: row.deprecated,
        required: row.required, members: row.members,
        generated: row.generate({}), what: row.what });
    });
    record.verdicts.push({ kind: 'catalogue', statuses: events.STATUSES,
      credentialTypes: events.CREDENTIAL_TYPES,
      caep: events.CAEP_EVENT_URIS, risc: events.RISC_EVENT_URIS,
      caepCommon: events.CAEP_COMMON_MEMBERS,
      riscCommon: events.RISC_COMMON_MEMBERS,
      advice: [
        events.subjectAdvice(R + 'identifier-changed',
                             { format: 'iss_sub', iss: 'https://i/',
                               sub: '1' }),
        events.subjectAdvice(R + 'identifier-changed',
                             { format: 'complex', user: { format: 'email',
                               email: 'a@b.c' } })
      ] });

    const PASS = 'A-long-enough-wire-passphrase-77';
    const MODES = [
      { name: 'development', id: null, overrides: null },
      { name: 'product', id: 'wireprod', product: true,
        overrides: { 'global.mode': 'product',
                     'authn.allowOptionalSecondFactor': true } },
      { name: 'defects', id: 'wiredefect',
        overrides: { 'ssf.legacySubClaim': true,
                     'risc.googleSubjectType': true,
                     'ssf.pushDelivery': false } },
      { name: 'off', id: 'wireoff', off: true,
        overrides: { 'ssf.enabled': false } }
    ];

    for (let m = 0; m < MODES.length; m++) {
      const mode = MODES[m];
      let realm = realms.DEFAULT_REALM;
      if (mode.id) {
        const made = realms.create({ id: mode.id, name: mode.id,
                                     description: 'ssf_model_wire.js',
                                     overrides: mode.overrides });
        if (!made.ok) {
          record.problems.push(mode.name + ': ' +
                               JSON.stringify(made.errors || made));
          continue;
        }
        realm = realms.get(mode.id);
      }
      const P = mode.id ? '/realm/' + mode.id : '';
      const WHO = 'wire-receiver';
      const subjectSub = 'wire-subject';
      let AUTH = { authorization: basic(WHO, PASS) };
      if (mode.product) {
        // PRODUCT: a client's own token. HTTP Basic needs Admin Write there
        // (#1473), and a role cannot be granted on this base (the directory's
        // danglingMember regression), so the receiver is an application.
        const SECRET = 'wire-client-secret-0123456789abcdef0123456789';
        realms.run(realm, function () {
          const applications = require(ROOT + '/common/applications');
          const made = applications.createApplication({
            identifier: 'wire-receiver', protocols: ['oauth2', 'ssf'],
            fields: { oauthClientId: 'wire-receiver',
              oauthClientSecret: SECRET,
              oauthGrantType: ['client_credentials'],
              oauthAllowedScope: ['ssf.read', 'ssf.manage'],
              oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
          if (!made.ok) {
            record.problems.push('product client: ' +
                                 JSON.stringify(made.errors));
          }
          const roles = require(ROOT + '/common/roles');
          ['SSF_READ', 'SSF_MANAGE'].forEach(function (name) {
            const cur = roles.read(name) || {};
            const wrote = roles.write(name, { description: cur.what,
              users: cur.users || [], groups: cur.groups || [],
              applications: (cur.applications || [])
                .concat(['wire-receiver']) });
            if (!wrote.ok) {
              record.problems.push('product role ' + name + ': ' +
                                   JSON.stringify(wrote));
            }
          });
        });
        const token = await request(port, 'POST', P + '/oauth2/token', {
          headers: { authorization: basic('wire-receiver', SECRET),
                     'content-type': 'application/x-www-form-urlencoded' },
          json: 'grant_type=client_credentials&scope=ssf.read%20ssf.manage',
          type: 'application/x-www-form-urlencoded' });
        if (!token.body || !token.body.access_token) {
          record.problems.push('product token: ' +
                               JSON.stringify(token.body).slice(0, 300));
        } else {
          AUTH = { authorization: 'Bearer ' + token.body.access_token };
        }
      }
      const step = async function (name, method, p, opts) {
        const r = await request(port, method, P + p, opts);
        record.wire.push({ mode: mode.name, step: name, method: method,
                           path: p, status: r.status, headers: r.headers,
                           body: r.body });
        return r;
      };
      const withAuth = function (o) {
        return Object.assign({ headers: AUTH }, o || {});
      };

      // DISCOVERY, both forms, and a path no issuer has.
      const meta = await step('metadata', 'GET',
                              '/.well-known/ssf-configuration');
      await step('metadata, the inserted-path form', 'GET',
                 '/.well-known/ssf-configuration' + P);
      if (!mode.id) {
        await step('metadata, no such issuer', 'GET',
                   '/.well-known/ssf-configuration/nope');
      }
      await step('description', 'GET', '/ssf?format=json');
      const issuer = (meta.body && meta.body.issuer) || '';

      // THE GATE.
      await step('stream, no credential', 'GET', '/ssf/stream');
      await step('stream, a bearer token nobody issued', 'GET', '/ssf/stream',
                 { headers: { authorization: 'Bearer not-a-token' } });
      await step('stream, the reserved password', 'GET', '/ssf/stream',
                 { headers: { authorization: basic(WHO, 'invalid') } });

      // STREAM MANAGEMENT.
      await step('create, not JSON', 'POST', '/ssf/stream',
                 withAuth({ json: 'not json', type: 'text/plain' }));
      await step('create, a bad format', 'POST', '/ssf/stream',
                 withAuth({ json: { delivery: { method:
                   'urn:ietf:rfc:8936' }, format: 'ip-addresses' } }));
      await step('create, a bad delivery method', 'POST', '/ssf/stream',
                 withAuth({ json: { delivery: { method: 'urn:nope' } } }));
      await step('create, push with no endpoint', 'POST', '/ssf/stream',
                 withAuth({ json: { delivery: { method:
                   'urn:ietf:rfc:8935' } } }));
      await step('create, push over plain http', 'POST', '/ssf/stream',
                 withAuth({ json: { delivery: { method: 'urn:ietf:rfc:8935',
                   endpoint_url: 'http://rcv.wire.example/push' } } }));
      await step('create, poll with an endpoint', 'POST', '/ssf/stream',
                 withAuth({ json: { delivery: { method: 'urn:ietf:rfc:8936',
                   endpoint_url: 'https://rcv.wire.example/x' } } }));
      await step('create, a foreign aud', 'POST', '/ssf/stream',
                 withAuth({ json: { aud: 'https://somebody.else/',
                   delivery: { method: 'urn:ietf:rfc:8936' } } }));
      await step('create, aud an empty array', 'POST', '/ssf/stream',
                 withAuth({ json: { aud: [],
                   delivery: { method: 'urn:ietf:rfc:8936' } } }));
      await step('create, a short verification interval', 'POST',
                 '/ssf/stream', withAuth({ json: { delivery: { method:
                   'urn:ietf:rfc:8936' }, min_verification_interval: 1 } }));
      const push = await step('create, push', 'POST', '/ssf/stream',
        withAuth({ json: { delivery: { method: 'urn:ietf:rfc:8935',
          endpoint_url: 'https://rcv.wire.example/push',
          authorization_header: 'Bearer wire-push-secret' },
          events_requested: [C + 'session-revoked', 'urn:not:supported'],
          description: 'the push stream' } }));
      const created = await step('create, poll', 'POST', '/ssf/stream',
        withAuth({ json: { delivery: { method: 'urn:ietf:rfc:8936' },
          events_requested: events.EVENT_URIS,
          format: 'email', description: 'the poll stream' } }));
      const id = (created.body && created.body.stream_id) || 'none';
      const pushId = (push.body && push.body.stream_id) || 'none';
      await step('read, every stream', 'GET', '/ssf/stream', withAuth());
      await step('read, one', 'GET', '/ssf/stream?stream_id=' + id,
                 withAuth());
      await step('read, nobody\'s', 'GET', '/ssf/stream?stream_id=nope',
                 withAuth());
      await step('update, not JSON', 'PATCH', '/ssf/stream',
                 withAuth({ json: '[', type: 'text/plain' }));
      await step('update, merge', 'PATCH', '/ssf/stream',
                 withAuth({ json: { stream_id: id,
                   description: 'merged' } }));
      await step('update, a transmitter member changed', 'PATCH',
                 '/ssf/stream', withAuth({ json: { stream_id: id,
                   iss: 'https://other.example/' } }));
      await step('update, replace', 'PUT', '/ssf/stream',
                 withAuth({ json: { stream_id: id,
                   delivery: { method: 'urn:ietf:rfc:8936' },
                   events_requested: events.EVENT_URIS,
                   description: 'replaced' } }));
      await step('update, nobody\'s', 'PATCH', '/ssf/stream',
                 withAuth({ json: { stream_id: 'nope' } }));

      // STATUS.
      await step('status', 'GET', '/ssf/status?stream_id=' + id, withAuth());
      await step('status, nobody\'s', 'GET', '/ssf/status?stream_id=nope',
                 withAuth());
      await step('status, a bad value', 'POST', '/ssf/status',
                 withAuth({ json: { stream_id: id, status: 'gone' } }));
      await step('status, paused', 'POST', '/ssf/status',
                 withAuth({ json: { stream_id: id, status: 'paused',
                   reason: 'wire' } }));
      await step('status, enabled', 'POST', '/ssf/status',
                 withAuth({ json: { stream_id: id, status: 'enabled' } }));

      // SUBJECTS.
      await step('subjects/add, malformed', 'POST', '/ssf/subjects/add',
                 withAuth({ json: { stream_id: id, subject: {
                   format: 'email', email: 'a@b.c', extra: 1 } } }));
      await step('subjects/add', 'POST', '/ssf/subjects/add',
                 withAuth({ json: { stream_id: id, subject: {
                   format: 'iss_sub', iss: issuer, sub: subjectSub } } }));
      await step('subjects/add, somebody else', 'POST', '/ssf/subjects/add',
                 withAuth({ json: { stream_id: id, subject: {
                   format: 'iss_sub', iss: issuer, sub: 'somebody-else' } }
                 }));
      await step('subjects/remove, malformed', 'POST',
                 '/ssf/subjects/remove', withAuth({ json: { stream_id: id,
                   subject: { format: 'nope' } } }));
      await step('subjects/remove', 'POST', '/ssf/subjects/remove',
                 withAuth({ json: { stream_id: id, subject: {
                   format: 'iss_sub', iss: issuer, sub: subjectSub } } }));
      await step('subjects/remove, again', 'POST', '/ssf/subjects/remove',
                 withAuth({ json: { stream_id: id, subject: {
                   format: 'iss_sub', iss: issuer, sub: subjectSub } } }));
      await step('subjects/remove, the other', 'POST',
                 '/ssf/subjects/remove', withAuth({ json: { stream_id: id,
                   subject: { format: 'iss_sub', iss: issuer,
                              sub: 'somebody-else' } } }));

      // VERIFICATION.
      await step('verify', 'POST', '/ssf/verify',
                 withAuth({ json: { stream_id: id, state: 'wire-state' } }));
      await step('verify, not JSON', 'POST', '/ssf/verify',
                 withAuth({ json: 'x', type: 'text/plain' }));
      // The 204 comes before the event is queued (section 8.1.4.2), so the
      // order of the SETs below is held by letting it land first.
      await new Promise(function (r) {
        setTimeout(r, 500);
      });

      // EVERY EVENT TYPE, ON THE POLL STREAM, WITH ITS ROW'S OWN PAYLOAD.
      if (!mode.off) {
        for (let i = 0; i < events.EVENTS.length; i++) {
          const row = events.EVENTS[i];
          let subject = null;
          if (row.subject !== 'none') {
            subject = (row.subjectFormats || []).indexOf('email') >= 0
              ? { format: 'email', email: WHO + '@example.test' }
              : { format: 'iss_sub', iss: issuer, sub: subjectSub };
          }
          const report = await realms.run(realm, function () {
            return ssf.consoleAction('transmit', { stream_id: id,
              type: row.uri, payload: row.generate({}),
              subject: subject ? JSON.stringify(subject) : '',
              txn: 'wire-txn-' + i });
          });
          record.verdicts.push({ kind: 'transmit', mode: mode.name,
            uri: row.uri, ok: report.ok, errors: report.errors });
        }
      }

      // POLL DELIVERY.
      await step('poll, not JSON', 'POST', '/ssf/poll',
                 withAuth({ json: 'x', type: 'text/plain' }));
      await step('poll, a push stream', 'POST', '/ssf/poll',
                 withAuth({ json: { stream_id: pushId } }));
      const polled = await step('poll', 'POST', '/ssf/poll',
        withAuth({ json: { stream_id: id, maxEvents: 100,
                           returnImmediately: true } }));
      const jtis = Object.keys((polled.body && polled.body.sets) || {});
      const errs = {};
      if (jtis.length) {
        errs[jtis[0]] = { err: 'invalid_request', description: 'wire' };
      }
      await step('poll, acknowledging', 'POST', '/ssf/poll',
                 withAuth({ json: { stream_id: id, ack: jtis.slice(1),
                   setErrs: errs, maxEvents: 0 } }));

      // THE RECEIVERS' PUSH ENDPOINTS.
      await step('admin receive, no credential', 'POST',
                 '/admin/signals/receive', { json: 'x.y.z',
                   type: 'application/secevent+jwt' });
      await step('portal receive, no credential', 'POST',
                 '/portal/signals/receive', { json: 'x.y.z',
                   type: 'application/secevent+jwt' });
      await step('report receive, no credential', 'POST',
                 '/report/signals/receive', { json: 'x.y.z',
                   type: 'application/secevent+jwt' });
      await step('federation receive, no relationship', 'POST',
                 '/federation/signals/nope', { json: 'x.y.z',
                   type: 'application/secevent+jwt' });

      // DELETE LAST.
      await step('delete', 'DELETE', '/ssf/stream?stream_id=' + id,
                 withAuth());
      await step('delete, again', 'DELETE', '/ssf/stream?stream_id=' + id,
                 withAuth());
      await step('delete, the push stream', 'DELETE', '/ssf/stream',
                 withAuth({ json: { stream_id: pushId } }));
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

// The member names whose values this service draws at random, each replaced
// by its name. A JWT among them is decoded rather than replaced.
const VOLATILE_MEMBERS = ['jti', 'iat', 'kid', 'n', 'e', 'x', 'y', 'x5c',
  'stream_id', 'authorization_header', 'createdAt', 'updatedAt',
  'lastActivityAt', 'lastPushAt', 'toe', 'event_timestamp', 'txn',
  'tokenDigest'];

const JWT = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/;

// A compact JWS, decoded: its header and claims, its signature dropped.
function decodeJwt(text) {
  log.debug("Entering decodeJwt().");
  const parts = text.split('.');
  try {
    const out = { jwt: {
      header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')),
      claims: JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')),
      signed: parts[2].length > 0 } };
    log.debug("Leaving decodeJwt().");
    return out;
  } catch (e) {
    log.debug("Caught in decodeJwt(): " + ((e && e.message) || e));
    log.debug("Leaving decodeJwt(). Not a JWT.");
    return text;
  }
}

// Walks a value: a JWT anywhere is decoded, a volatile member's value is
// replaced by its name, and a poll's `sets` — keyed by jti — becomes the list
// of its values in the order they were answered.
function scrub(value, name) {
  log.debug("Entering scrub().");
  if (Array.isArray(value)) {
    const list = value.map(function (one) {
      return scrub(one, name);
    });
    log.debug("Leaving scrub().");
    return list;
  }
  if (name === 'sets' && value && typeof value === 'object') {
    const list = Object.keys(value).map(function (key) {
      return scrub(value[key], 'set');
    });
    log.debug("Leaving scrub(). A poll's SETs.");
    return list;
  }
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach(function (key) {
      out[key] = scrub(value[key], key);
    });
    log.debug("Leaving scrub().");
    return out;
  }
  if (typeof value === 'string' && JWT.test(value)) {
    const decoded = decodeJwt(value);
    if (decoded !== value) {
      log.debug("Leaving scrub(). A JWT.");
      return scrub(decoded, name);
    }
  }
  if (typeof value === 'number' && value >= 1.7e9 && value < 2.2e9) {
    log.debug("Leaving scrub(). An instant.");
    return '<epoch>';
  }
  if (name && VOLATILE_MEMBERS.indexOf(name) >= 0 && value !== undefined &&
      value !== null && value !== '' && typeof value !== 'object') {
    log.debug("Leaving scrub(). A volatile member.");
    return '<' + name + '>';
  }
  log.debug("Leaving scrub().");
  return value;
}

// The run-to-run values, each replaced by a placeholder, so that two runs of
// one tree record the same text.
function normalise(record) {
  log.debug("Entering normalise().");
  const PATTERNS = [
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['httpdate', /[A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT/g],
    ['port', /127\.0\.0\.1(:|%3A)\d+/g],
    ['port', /localhost(:|%3A)\d+/g],
    ['epoch', /\b1[789]\d{8}\b/g],
    ['stream', /(?<![A-Za-z0-9_-])ssf-[A-Za-z0-9_-]{16}(?![A-Za-z0-9_-])/g],
    ['uptime', /up \d+ second\(s\)/g],
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}/g]
  ];
  let out = JSON.stringify(scrub(record), null, 1);
  PATTERNS.forEach(function (pair) {
    out = out.replace(pair[1], '<' + pair[0] + '>');
  });
  log.debug("Leaving normalise().");
  return JSON.parse(out);
}

// Runs the child and answers its record, normalised, or null.
function capture() {
  log.debug("Entering capture().");
  const out = path.join(os.tmpdir(), 'ssf-model-wire-' + process.pid +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|SSF_|CAEP_|RISC_|LDAP_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SW_ROOT: ROOT, SW_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
  return where + ': ' + JSON.stringify(b).slice(0, 300) + ' where ' +
    JSON.stringify(a).slice(0, 300) + ' was recorded';
}

// Every recorded entry of one list against the same entry now.
function compareList(t, recorded, now, label) {
  log.debug("Entering compareList(). " + label);
  t.check(recorded.length === now.length,
          'the ' + label + ' has as many entries as recorded',
          now.length + ' vs ' + recorded.length);
  recorded.forEach(function (one, i) {
    const name = label === 'wire'
      ? one.mode + ', ' + one.step + ': ' + one.method +
        ' answers as recorded (' + one.status + ')'
      : one.kind + ' ' + (one.mode ? one.mode + ' ' : '') +
        (one.name || one.uri || '') + ' is as recorded';
    t.check(firstDifference(one, now[i], label) === null, name,
            firstDifference(one, now[i], label));
  });
  log.debug("Leaving compareList().");
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
  compareList(t, recorded.wire, now.wire, 'wire');
  compareList(t, recorded.verdicts, now.verdicts, 'verdicts');
  log.debug("Leaving run().");
}

if (require.main === module && process.env.SSF_WIRE_PRINT) {
  process.stdout.write(JSON.stringify(capture(), null, 1) + '\n');
}

module.exports = {
  name: 'ssf_model_wire',
  describe: 'what the Shared Signals endpoints answer and send, byte for ' +
            'byte, against the record made before the SET envelope, the ' +
            'event types, the subject formats, the metadata and the stream ' +
            'configuration came from the model (#1579): discovery, stream ' +
            'management, status, subjects, verification, poll, every event ' +
            'type\'s SET and the receivers\' refusals, in development, ' +
            'product, with the defects on and with the family off',
  run: run
};
