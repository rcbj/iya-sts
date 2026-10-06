// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_signals.js
//
// ===========================================================================
// SHARED SIGNALS FOR NON-HUMAN IDENTITIES (#221 P5, 2026-10-06), in process.
//
// What each row of rcbj's 2026-09-27 table now sends, read back at the one
// place every event passes on its way to a stream: `ssf_streams.ts`'s
// `listStreams()`, `deliversEvent()` and `streamCoversSubject()` are replaced
// on the loaded module by a recorder that offers one stream, takes every
// type, notes the event's type and SUBJECT, and covers nothing — so the real
// emitters in `ssf/ssf.ts` build each event exactly as they would for a
// receiver and send it nowhere. `caep.buildPayload()` is wrapped to read the
// CAEP payload beside it. What this holds:
//
//   A. THE SUBJECT: `ssf_subjects.js`'s application subject is SSF 1.0's
//      complex subject with an `opaque` `application` member, validates, and
//      a real stream that ADDED it (complex, or the bare opaque member)
//      covers an event about the application and not one about a person.
//   B. CREDENTIALS: a client secret added (create), regenerated (update) and
//      removed (revoke), with `urn:iya:sts:credential-type:client-secret`;
//      a registered jwks set, replaced and cleared (create / update /
//      revoke, `...:jwk`); an RFC 7523 key pair issued and stored as SEVEN
//      attribute writes told as ONE `x509` create; a TLS client certificate
//      issued (x509 create) and revoked for keyCompromise (x509 revoke and
//      RISC credential-compromise) — every one under the application.
//   C. CLAIMS: an application's own client_credentials token is a holder of
//      its own (`liveClaimBearers()`), and a fan-out tells the APPLICATION;
//      a role given to it is a token-claims-change naming the roles claim.
//   D. A GRANT: the client_credentials grant revoked is session-revoked
//      about the application with `oauth-grant:<id>` as the session.
//   E. RISC: an application entry deleted is account-purged under the
//      application, its register row an application's, and the opt-out
//      gate SAYS it does not apply; a service account (stsServiceAccount)
//      likewise; a person's still applies.
//   F. SESSIONS: a SPIFFE ID is a workload and an application identifier is
//      the application (`principalOfSession()`), and a CAEP session row for
//      one is named by the application member, never a `user`.
//   G. SPIFFE: a registration entry removed is credential-change about the
//      workload — `update` while another entry names it, `delete` for the
//      last — with a plain `uri` subject.
//
// In a child process, because it loads the protocol stack.
// `tests/vendored/sts_application_signals.js` holds a rotation over the wire.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'application_signals',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// THE CHILD. Serialised with toString() and run with `node -e`.
// ---------------------------------------------------------------------------
/* eslint-disable no-undef */
function childMain() {
  const ROOT = process.env.AS_ROOT;
  const OUT = process.env.AS_OUT;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }
  const settle = function () {
    return new Promise(function (resolve) {
      setTimeout(resolve, 60);
    });
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const helpers = require(ROOT + '/common/helpers');
    const stats = require(ROOT + '/common/admin_stats');
    const applications = require(ROOT + '/common/applications');
    const roles = require(ROOT + '/common/roles');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const ssf = require(ROOT + '/ssf/ssf');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const subjects = require(ROOT + '/ssf/ssf_subjects');
    const caep = require(ROOT + '/ssf/caep');
    const risc = require(ROOT + '/ssf/risc');
    const signals = require(ROOT + '/ssf/account_signals');

    await realms.run(realms.DEFAULT_REALM, async function () {
      const keystore = require(ROOT + '/common/keystore');
      const pki = require(ROOT + '/common/pki');
      await keystore.start();
      await pki.start({ realmIds: [''],
        keySetFor: function (id) {
          return helpers.stsKeysFor.of(id);
        },
        keySetHeldFor: function () {
          return false;
        } });
      await pki.ensureScope(realms.currentId());
      const tlsClient = require(ROOT + '/common/tls_client_certificates');

      const APP = 'as-app';
      const appSubject = subjects.applicationSubject(APP, '');

      // ================================================================
      // A. THE SUBJECT, against a real stream.
      // ================================================================
      note(JSON.stringify(appSubject) === JSON.stringify({
        format: 'complex', application: { format: 'opaque', id: APP } }),
           'A1. an application is complex, application: opaque client_id',
           JSON.stringify(appSubject));
      note(subjects.validateSubjectId(appSubject, {}).ok,
           'A2. the application subject validates as an SSF sub_id');
      const made = streams.createStream(
        { delivery: { method: 'urn:ietf:rfc:8936' } },
        { issuer: 'https://sts.test', principal: 'as-receiver',
          audience: 'https://receiver.test/as' });
      note(made.ok, 'A3. a relying party\'s stream is made',
           JSON.stringify(made.errors));
      if (made.ok) {
        const id = made.stream.stream_id;
        const added = streams.addSubject(id, appSubject, true, {});
        note(added.ok, 'A4. Add Subject takes the application subject',
             JSON.stringify(added.errors));
        const record = streams.getStream(id);
        const person = { format: 'complex', user: { format: 'iss_sub',
          iss: 'https://sts.test', sub: 'urn:uuid:nobody' } };
        note(streams.streamCoversSubject(record, appSubject) === true &&
             streams.streamCoversSubject(record,
               subjects.applicationSubject(APP, 'oauth-grant:x')) === true &&
             streams.streamCoversSubject(record, person) === false,
             'A5. the stream covers the application (with or without a ' +
             'session) and not a person');
        const bare = streams.createStream(
          { delivery: { method: 'urn:ietf:rfc:8936' } },
          { issuer: 'https://sts.test', principal: 'as-receiver-2',
            audience: 'https://receiver.test/as2' });
        streams.addSubject(bare.stream.stream_id,
                           { format: 'opaque', id: APP }, true, {});
        note(streams.streamCoversSubject(
          streams.getStream(bare.stream.stream_id), appSubject) === true,
             'A6. a stream that added the bare opaque member covers it too');
        streams.removeStream(id);
        streams.removeStream(bare.stream.stream_id);
      }

      // ================================================================
      // THE RECORDER.
      // ================================================================
      const seen = [];
      let lastUri = '';
      let lastPayload = null;
      streams.listStreams = function () {
        return [{ stream_id: 'as-recorder', subjects: [], createdBy: '' }];
      };
      streams.deliversEvent = function (record, uri) {
        lastUri = String(uri || '');
        return true;
      };
      streams.streamCoversSubject = function (record, subject) {
        seen.push({ uri: lastUri, subject: subject, payload: lastPayload });
        return false;
      };
      const realBuild = caep.buildPayload;
      caep.buildPayload = function (uri, values, options) {
        lastPayload = realBuild(uri, values, options);
        return lastPayload;
      };
      const mark = function () {
        return seen.length;
      };
      const about = function (from, type, application) {
        return seen.slice(from).filter(function (one) {
          return one.uri.slice(-type.length - 1) === '/' + type &&
                 subjects.applicationIdOf(one.subject) === application;
        });
      };
      const brief = function (list) {
        return JSON.stringify(list.map(function (one) {
          return { uri: one.uri.split('/').pop(), s: one.subject,
                   t: one.payload && one.payload.credential_type,
                   c: one.payload && one.payload.change_type,
                   i: one.payload && one.payload.initiating_entity };
        }));
      };

      // ================================================================
      // B. CREDENTIALS.
      // ================================================================
      const created = applications.createApplication({ identifier: APP,
        protocols: ['oauth2'], fields: { oauthClientId: APP } });
      note(created.ok, 'B0. the application is created',
           JSON.stringify(created.errors));
      await settle();
      let from = mark();
      const added = applications.addClientSecret(APP, { actor: 'as-admin' });
      await settle();
      let got = about(from, 'credential-change', APP);
      note(added.ok && got.length === 1 &&
           got[0].payload.credential_type ===
             'urn:iya:sts:credential-type:client-secret' &&
           got[0].payload.change_type === 'create' &&
           got[0].payload.initiating_entity === 'admin',
           'B1. a client secret added is client-secret create, by admin, ' +
           'under the application', brief(got));
      from = mark();
      const regenerated = applications.regenerateClientSecret(APP,
        { actor: 'as-admin' });
      await settle();
      got = about(from, 'credential-change', APP);
      note(got.length === 1 && got[0].payload.change_type === 'update',
           'B2. regenerated is update', brief(got));
      from = mark();
      const removed = applications.removeClientSecret(APP,
        { actor: 'as-admin', id: String(regenerated.secretId || '') });
      await settle();
      got = about(from, 'credential-change', APP);
      note(removed.ok && got.length === 1 &&
           got[0].payload.change_type === 'revoke',
           'B3. removed is revoke', brief(got) + ' ' +
           JSON.stringify(removed.errors || []));

      const pair = nodeCrypto.generateKeyPairSync('ec',
                                                  { namedCurve: 'P-256' });
      const jwk = pair.publicKey.export({ format: 'jwk' });
      const jwks = function (kid) {
        return JSON.stringify({ keys: [Object.assign({ kid: kid,
                                                       use: 'sig' }, jwk)] });
      };
      from = mark();
      applications.updateApplication(APP, { attribute: 'oauthJwks',
        mode: 'set', value: jwks('k1'), actor: 'as-admin' });
      await settle();
      applications.updateApplication(APP, { attribute: 'oauthJwks',
        mode: 'set', value: jwks('k2'), actor: 'as-admin' });
      await settle();
      applications.updateApplication(APP, { attribute: 'oauthJwks',
        mode: 'set', value: '', actor: 'as-admin' });
      await settle();
      got = about(from, 'credential-change', APP);
      note(got.length === 3 && got.every(function (one) {
        return one.payload.credential_type ===
               'urn:iya:sts:credential-type:jwk';
      }) && got.map(function (one) {
        return one.payload.change_type;
      }).join(',') === 'create,update,revoke',
           'B4. a registered jwks set, replaced and cleared is jwk create, ' +
           'update, revoke', brief(got));

      const issued = await pki.issueSigningKeyPair(undefined, {
        identifier: APP, purpose: 'jwt', commonName: APP });
      from = mark();
      const stored = issued.ok
        ? applications.storeIssuedJwtKeyPair(APP, issued.issued)
        : { ok: false };
      await settle();
      got = about(from, 'credential-change', APP);
      note(stored.ok && got.length === 1 &&
           got[0].payload.credential_type === 'x509' &&
           got[0].payload.change_type === 'create' &&
           !!got[0].payload.x509_serial,
           'B5. an RFC 7523 key pair stored as seven writes is ONE x509 ' +
           'create, with its serial', brief(got) + ' ' +
           JSON.stringify(issued.errors || []));

      from = mark();
      const tls = await tlsClient.issue(undefined, { kind: 'application',
        application: APP, label: 'as-svc', keyAlg: 'ec-p256' });
      got = about(from, 'credential-change', APP);
      note(tls.ok && got.length === 1 &&
           got[0].payload.credential_type === 'x509' &&
           got[0].payload.change_type === 'create',
           'B6. an application\'s TLS client certificate issued is x509 ' +
           'create under the application', brief(got) + ' ' +
           JSON.stringify(tls.errors || []));
      from = mark();
      if (tls.ok) {
        tlsClient.revoke(undefined, APP, tls.issued.serialHex,
                         'keyCompromise', 'application');
      }
      await settle();
      got = about(from, 'credential-change', APP);
      const compromised = about(from, 'credential-compromise', APP);
      note(got.length === 1 && got[0].payload.change_type === 'revoke' &&
           compromised.length === 1,
           'B7. revoked for keyCompromise is x509 revoke AND RISC ' +
           'credential-compromise, both under the application',
           brief(got) + ' ' + brief(compromised));

      // ================================================================
      // C. CLAIMS.
      // ================================================================
      const now = helpers.nowSec();
      helpers.signJwt({ iss: 'https://sts.test', sub: APP,
        aud: 'https://as-api.test/', typ: 'Bearer', jti: 'as-cc-1',
        client_id: APP, scope: 'as:read as:write', iat: now,
        exp: now + 300 }, { grant: 'client_credentials', grantId: 'as-g1',
                            grantRefresh: false });
      const bearers = stats.liveClaimBearers(function (token) {
        return token.client_id === APP;
      });
      note(bearers.length === 1 && bearers[0].application === APP &&
           !bearers[0].username,
           'C1. a client_credentials token is listed as the application\'s ' +
           'own, with no person', JSON.stringify(bearers.map(function (b) {
             return [b.application, b.username];
           })));
      note(!stats.holdsLiveIssuance(APP, ''),
           'C2. and is no person\'s live issuance of the same name');
      from = mark();
      signals.claimsFanOut({ protocol: 'Applications',
        initiatingEntity: 'admin', reasonAdmin: 'as:write withdrawn',
        match: function (token) {
          return token.client_id === APP;
        },
        claimsFor: function (bearer) {
          return { scope: String(bearer.record.scope).split(' ')
            .filter(function (one) {
              return one !== 'as:write';
            }).join(' ') };
        } });
      await settle();
      got = about(from, 'token-claims-change', APP);
      note(got.length === 1 && !got[0].subject.user &&
           JSON.stringify(got[0].payload.claims) ===
             JSON.stringify({ scope: 'as:read' }),
           'C3. the fan-out tells the APPLICATION, with its token\'s claims',
           brief(got) + ' ' + JSON.stringify(got[0] && got[0].payload));
      from = mark();
      const wrote = roles.write('as-role', { applications: [APP] });
      await settle();
      got = about(from, 'token-claims-change', APP);
      note(wrote.ok !== false && got.length === 1 &&
           JSON.stringify(got[0].payload.claims.roles) ===
             JSON.stringify(['as-role']),
           'C4. a role given to the application is a token-claims-change ' +
           'naming the roles claim', brief(got) + ' ' +
           JSON.stringify(got[0] && got[0].payload));
      roles.remove('as-role');
      await settle();

      // ================================================================
      // D. A GRANT.
      // ================================================================
      from = mark();
      stats.revoke('as-cc-1', 'the RFC 7009 revocation endpoint',
                   { initiatingEntity: 'user' });
      await settle();
      got = about(from, 'session-revoked', APP);
      note(got.length === 1 && got[0].subject.session &&
           got[0].subject.session.id === 'oauth-grant:as-g1' &&
           !got[0].subject.user,
           'D1. the client_credentials grant revoked is session-revoked ' +
           'about the application, the grant as the session', brief(got));

      // ================================================================
      // E. RISC.
      // ================================================================
      applications.createApplication({ identifier: 'as-gone',
        protocols: ['oauth2'], fields: { oauthClientId: 'as-gone' } });
      await settle();
      from = mark();
      const deleted = applications.deleteApplication('as-gone',
                                                     { actor: 'as-admin' });
      got = about(from, 'account-purged', 'as-gone');
      note(deleted.ok && got.length === 1,
           'E1. an application deleted is RISC account-purged under the ' +
           'application', brief(got));
      const row = risc.get(risc.applicationAccountId('as-gone')) || {};
      note(row.kind === 'application' && row.lifecycle === 'purged' &&
           (row.notes || []).some(function (one) {
             return /APPLICATION/.test(one) && /does not apply/.test(one);
           }),
           'E2. its register row is an application\'s, purged, and SAYS the ' +
           'opt-out gate does not apply', JSON.stringify(row.notes));
      const appView = risc.optOutOf(risc.applicationAccountId('as-gone'));
      note(appView.applies === false && appView.moves.length === 0,
           'E3. an application is offered no opt-out move',
           JSON.stringify(appView));
      risc.observe({ kind: 'added', username: 'as-svc',
        after: { uid: ['as-svc'], stsserviceaccount: ['TRUE'] } });
      risc.observe({ kind: 'added', username: 'as-human',
        after: { uid: ['as-human'] } });
      const svc = risc.gate(risc.get('as-svc'),
        'https://schemas.openid.net/secevent/risc/event-type/' +
        'account-disabled');
      note(svc.send === true && /SERVICE ACCOUNT/.test(svc.notApplicable ||
                                                       ''),
           'E4. the gate STATES it does not apply to a service account',
           JSON.stringify(svc));
      note(risc.optOutOf('as-svc').applies === false &&
           risc.optOutOf('as-human').applies === true &&
           risc.optOutOf('as-human').moves.length === 1,
           'E5. a service account has no opt-out move; a person still has ' +
           'one');

      // ================================================================
      // F. SESSIONS.
      // ================================================================
      note(JSON.stringify(ssf.principalOfSession('spiffe://as.test/w', '')) ===
             JSON.stringify({ workload: 'spiffe://as.test/w' }) &&
           JSON.stringify(ssf.principalOfSession(APP, '')) ===
             JSON.stringify({ application: APP }) &&
           ssf.principalOfSession('as-human', 'urn:uuid:x') === null,
           'F1. a SPIFFE ID is a workload, an application identifier the ' +
           'application, a person a person');
      const due = caep.observe({ kind: 'established',
        session: { id: 'as-session-1', user: { username: APP, sub: '' },
                   acr: '1', amr: ['pwd'] },
        issuer: 'https://sts.test',
        classifyPrincipal: function (name, sub) {
          return ssf.principalOfSession(name, sub);
        } });
      note(due && !due.subject.user && due.subject.application &&
           due.subject.application.id === APP &&
           due.subject.session.id === 'as-session-1',
           'F2. a session an application authenticated is named by the ' +
           'application member and the session',
           JSON.stringify(due && due.subject));

      // ================================================================
      // G. SPIFFE.
      // ================================================================
      const registry = require(ROOT + '/spiffe/spiffe_registry');
      const ca = require(ROOT + '/spiffe/spiffe_ca');
      const td = ca.trustDomain();
      const spiffeId = 'spiffe://' + td + '/as-workload';
      const one = registry.createEntry({ spiffeId: spiffeId,
        parentId: 'spiffe://' + td + '/spire/server',
        selectors: [{ type: 'unix', value: 'uid:221' }] }, 'test', td,
        'test');
      const two = registry.createEntry({ spiffeId: spiffeId,
        parentId: 'spiffe://' + td + '/spire/server',
        selectors: [{ type: 'unix', value: 'uid:222' }] }, 'test', td,
        'test');
      const workload = function (list) {
        return list.filter(function (entry) {
          return entry.subject && entry.subject.format === 'uri' &&
                 entry.subject.uri === spiffeId;
        });
      };
      from = mark();
      registry.deleteEntry(one.id, 'as-admin');
      registry.deleteEntry(two.id, 'as-admin');
      got = workload(seen.slice(from));
      note(one.ok && two.ok && got.length === 2 &&
           got[0].payload.credential_type ===
             'urn:iya:sts:credential-type:spiffe-registration' &&
           got[0].payload.change_type === 'update' &&
           got[1].payload.change_type === 'delete',
           'G1. a registration entry removed is credential-change about ' +
           'the workload: update while another names it, delete for the last',
           brief(got) + ' ' + JSON.stringify([one.errors, two.errors]));
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
/* eslint-enable no-undef */

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'application-signals-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', AS_ROOT: ROOT,
                                  AS_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1500))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application_signals',
  describe: 'Shared Signals for non-human identities (#221 P5): the ' +
            'application subject, an application\'s credentials, own ' +
            'tokens, roles, grant, deletion, sessions, the RISC opt-out ' +
            'gate stated for applications and service accounts, and a ' +
            'SPIFFE registration removed',
  run: run
};
