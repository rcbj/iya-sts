// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_ssh_issue_yubiotp_list.js
//
// ===========================================================================
// AN ADMINISTRATOR ISSUES A PERSON'S SSH USER CERTIFICATE, AND THE YUBIKEY
// OTP INVENTORY IS LISTED (#2071).
//
//   A. `common/ssh_user_ca.ts`'s `adminIssue()`: the person's own core —
//      their subject on the certificate, their uid the default principal,
//      the policy asked about THEM on the management API's path — and the
//      audit row naming the administrator (given, or the ambient source's
//      `audit.currentActor()`); nobody of that name is STS-SSHCA-0004 and
//      issues nothing; a principal the policy refuses issues nothing and is
//      audited as refused.
//   B. `POST /admin-api/hardware-tokens/issue-ssh` through the route
//      table's handler: the answer, the console's comma-separated principals
//      and text lifetime read, each refusal's status and code, a throw a 500
//      with STS-SSHCA-0011; the unknown-action sentence names `issue-ssh`;
//      `GET /admin-api/hardware-tokens/yubiotp` answers the store's page
//      with the console's paging, and a throw is STS-YUBIOTP-0035.
//   C. `common/yubiotp_store.ts`'s `list()` over the real store: an import
//      listed unassigned and never with its key, a serial searched exactly,
//      `status` through the index, and a person's tokens read off THEIR
//      ENTRY (`stsYubiOtpToken`, the master copy) — a value on the entry
//      with no inventory row is listed for them.
//   D. The console: the YubiKey OTP tab (filters, import form, Assign and
//      Remove), the SSH Issue form on the central tab and fixed to the
//      person on their sub-tab, the person's YubiKey OTP list, none of the
//      forms for a reader who may not write, and the issued certificate
//      drawn once.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({
  name: 'admin_ssh_issue_yubiotp_list',
  level: process.env.LOG_LEVEL || 'info' });

const errorCodes = require('../common/error_codes');
const sshUserCa = require('../common/ssh_user_ca');

const RUN = Date.now().toString(36);

// AN ISSUER OVER STUBS, as tests/ssh_user_ca.js builds one: alice exists,
// with uid alice; the policy is `policy`; the audit records into `rows`.
function issuerWith(policy, ambientActor) {
  log.debug("Entering issuerWith().");
  const calls = { issues: [], decisions: [], rows: [] };
  const issuer = new sshUserCa.SshUserCa({
    log: log,
    pki: {
      parseSshAuthorizedKey: function () {
        return { type: 'ssh-ed25519', certType: null, sk: false,
                 blob: Buffer.from('public-key-blob') };
      },
      sshFingerprint: function () {
        return 'SHA256:fingerprint';
      },
      issueSshUserCertificateAsync: async function (realm, spec) {
        calls.issues.push({ realm: realm, spec: spec });
        return { ok: true, line: 'ssh-ed25519-cert AAAA', serialHex: 'c3',
                 validAfter: 10, validBefore: 310 };
      },
      revokeSshUserCertificateAsync: async function () {
        return { ok: true };
      }
    },
    crypto: {},
    accessGate: {
      RESOURCE: { SSH_USER_CA: 'ssh-user-ca' },
      ACTION: { ISSUE_SSH_PRINCIPAL: 'issue-ssh-principal' },
      check: function (request) {
        calls.decisions.push(request);
        return policy(request);
      }
    },
    config: { value: function () {
      return undefined;
    } },
    hardwareTokens: { recordAttested: function () {
      return { ok: true };
    } },
    errorCodes: errorCodes,
    audit: {
      record: function (row) {
        calls.rows.push(row);
      },
      currentActor: function () {
        return ambientActor || '';
      }
    },
    directory: function () {
      return {
        existingUserEntry: function (name) {
          return name === 'alice'
            ? { dn: 'uid=alice', attributes: { uid: ['alice'] } } : null;
        },
        groupsOfUser: function () {
          return { entryFound: true, groups: [] };
        },
        storedCertificatesOf: function () {
          return { certificates: [] };
        }
      };
    },
    webauthn: function () {
      return {};
    },
    subjectFor: function (username) {
      return username === 'alice' ? 'urn:uuid:alice' : '';
    }
  });
  log.debug("Leaving issuerWith().");
  return { issuer: issuer, calls: calls };
}

async function checkCore(t) {
  log.debug("Entering checkCore().");
  const allow = issuerWith(function () {
    return { allowed: true };
  }, 'ambient-admin');
  const issued = await allow.issuer.adminIssue({ realm: 'r', username: 'alice',
    publicKey: 'ssh-ed25519 AAAA alice', actor: 'root-admin', via: 'api' });
  const decision = allow.calls.decisions[0] || {};
  const row = allow.calls.rows[0] || {};
  t.check(issued.ok && issued.certificate === 'ssh-ed25519-cert AAAA' &&
          allow.calls.issues.length === 1 &&
          allow.calls.issues[0].spec.ownerSubject === 'urn:uuid:alice' &&
          allow.calls.issues[0].spec.principals.join(',') === 'alice',
          'A1. an administrator issues for the person: their subject, ' +
          'their uid the default principal', JSON.stringify(allow.calls));
  t.check(decision.subject && decision.subject.name === 'alice' &&
          decision.owner === 'alice' && decision.sshPrincipalKind === 'uid' &&
          decision.context.path === '/admin-api/hardware-tokens/issue-ssh',
          'A2. the policy is asked about the PERSON, on the management ' +
          'API\'s path', JSON.stringify(decision));
  t.check(row.action === 'ssh-user-ca.issue' && row.actor === 'root-admin' &&
          row.target === 'alice' && row.outcome === 'success' &&
          /administrator/i.test(row.summary) && row.detail.via === 'api',
          'A3. the audit row names the administrator and the person',
          JSON.stringify(row));
  const ambient = issuerWith(function () {
    return { allowed: true };
  }, 'ambient-admin');
  await ambient.issuer.adminIssue({ realm: 'r', username: 'alice',
    publicKey: 'ssh-ed25519 AAAA alice', via: 'api' });
  t.equal(ambient.calls.rows[0] && ambient.calls.rows[0].actor,
          'ambient-admin', 'A4. with no actor given, the ambient source\'s ' +
          '(audit.currentActor()) is named');
  const nobody = await allow.issuer.adminIssue({ realm: 'r',
    username: 'nobody', publicKey: 'ssh-ed25519 AAAA x', actor: 'root-admin' });
  t.check(errorCodes.codeOf(nobody) === 'STS-SSHCA-0004' &&
          allow.calls.issues.length === 1 &&
          allow.calls.rows[1].outcome === 'refused' &&
          allow.calls.rows[1].errorCode === 'STS-SSHCA-0004',
          'A5. nobody of that name is STS-SSHCA-0004, issues nothing and ' +
          'is audited', JSON.stringify(nobody));
  const deny = issuerWith(function () {
    return { allowed: false, why: 'no' };
  }, '');
  const refused = await deny.issuer.adminIssue({ realm: 'r',
    username: 'alice', publicKey: 'ssh-ed25519 AAAA alice',
    principals: ['alice'], actor: 'root-admin' });
  t.check(errorCodes.codeOf(refused) === 'STS-PKI-0294' &&
          !deny.calls.issues.length && deny.calls.rows.length === 1 &&
          deny.calls.rows[0].outcome === 'refused' &&
          deny.calls.rows[0].actor === 'root-admin',
          'A6. a principal the policy refuses issues nothing, audited as ' +
          'refused', JSON.stringify(deny.calls.rows));
  log.debug("Leaving checkCore().");
}

function responseStub() {
  log.debug("Entering responseStub().");
  const res = {
    statusCode: 0, body: null, headers: {},
    locals: { apiCaller: { kind: 'person', name: 'root-admin' } },
    status: function (code) {
      res.statusCode = code;
      return res;
    },
    type: function () {
      return res;
    },
    set: function (name, value) {
      res.headers[name] = value;
      return res;
    },
    send: function (text) {
      res.body = JSON.parse(text);
      if (res.done) {
        res.done();
      }
      return res;
    }
  };
  log.debug("Leaving responseStub().");
  return res;
}

// One call of a route's handler, answered when it sends.
function drive(handler, req) {
  log.debug("Entering drive().");
  return new Promise(function (resolve) {
    const res = responseStub();
    res.done = function () {
      resolve(res);
    };
    handler(req, res);
    log.debug("Leaving drive().");
  });
}

async function checkApi(t) {
  log.debug("Entering checkApi().");
  const Api = require('../mgmt-api/hardware_tokens_api').HardwareTokensApi;
  const seen = { issue: [] };
  let answerOf = null;
  const api = new Api(Object.assign(Api.defaultDeps(), {
    loadSshUserCa: function () {
      return { adminIssue: async function (spec) {
        seen.issue.push(spec);
        return answerOf(spec);
      } };
    },
    loadYubi: function () {
      return { list: async function (opts) {
        seen.list = opts;
        if (opts.q === 'boom') {
          throw new Error('the store threw');
        }
        return { ok: true, total: 3, capped: false,
                 tokens: [{ serial: '1', publicId: 'cccc',
                            status: 'unassigned', holder: '',
                            importedAt: 'x', assignedAt: '',
                            retiredAt: '' }] };
      } };
    }
  }));
  const routes = api.buildRoutes();
  const acts = routes.filter(function (r) {
    return /:action$/.test(String(r.route || r.path || ''));
  })[0];
  const yubi = routes.filter(function (r) {
    return r.path === '/admin-api/hardware-tokens/yubiotp';
  })[0];
  const post = function (body) {
    return drive(acts.handler, { params: { action: 'issue-ssh' },
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body) });
  };
  answerOf = function () {
    return { ok: true, certificate: 'ssh-ed25519-cert AAAA', serialHex: 'c3',
             validAfter: 10, validBefore: 310, hardwareBound: false };
  };
  const ok = await post({ username: 'alice', publicKey: 'ssh-ed25519 AAAA',
                          principals: 'alice, ops', lifetimeS: '600' });
  t.check(ok.statusCode === 200 && ok.body.username === 'alice' &&
          ok.body.certificate === 'ssh-ed25519-cert AAAA' &&
          ok.body.serialHex === 'c3' && !('pqcCertificate' in ok.body) &&
          seen.issue[0].principals.join('|') === 'alice|ops' &&
          seen.issue[0].lifetimeS === 600 &&
          seen.issue[0].actor === 'root-admin' && seen.issue[0].via === 'api',
          'B1. issue-ssh answers the certificate, reading the console\'s ' +
          'comma-separated principals and text lifetime, the actor the ' +
          'token\'s subject', JSON.stringify({ body: ok.body,
                                               spec: seen.issue[0] }));
  const statuses = [['STS-SSHCA-0004', 404], ['STS-PKI-0294', 403],
                    ['STS-SSHCA-0002', 403], ['STS-PKI-0289', 400],
                    ['STS-PKI-0290', 503]];
  for (const pair of statuses) {
    answerOf = function () {
      return errorCodes.mark({ ok: false, errors: ['refused'] }, pair[0]);
    };
    const refused = await post({ username: 'x', publicKey: 'y' });
    t.check(refused.statusCode === pair[1] &&
            errorCodes.codeOf(refused) === pair[0] &&
            JSON.stringify(refused.body).indexOf('STS-') < 0,
            'B2. ' + pair[0] + ' is ' + pair[1] + ', marked and not sent',
            refused.statusCode + ' ' + JSON.stringify(refused.body));
  }
  answerOf = function () {
    throw new Error('the core threw');
  };
  const threw = await post({ username: 'x', publicKey: 'y' });
  t.check(threw.statusCode === 500 &&
          errorCodes.codeOf(threw) === 'STS-SSHCA-0011',
          'B3. a throw is a 500 marked STS-SSHCA-0011');
  const unknown = await drive(acts.handler, { params: { action: 'nope' },
    headers: { 'content-type': 'application/json' }, body: '{}' });
  t.check(unknown.statusCode === 400 &&
          /issue-ssh/.test(unknown.body.errors[0]) &&
          /revoke-ssh/.test(unknown.body.errors[0]),
          'B4. the unknown-action sentence names issue-ssh',
          JSON.stringify(unknown.body));
  t.check(acts.actions.some(function (a) {
    return a.action === 'issue-ssh' &&
      a.operationId === 'issueUserSshCertificate';
  }), 'B5. issue-ssh is its own operation, issueUserSshCertificate');
  const listed = await drive(yubi.handler, { query: { q: '', status:
    'unassigned', page: '1', per: '2' } });
  t.check(listed.statusCode === 200 && listed.body.tokens.length === 1 &&
          listed.body.paging.total === 3 && listed.body.paging.perPage === 2 &&
          listed.body.status === 'unassigned' &&
          seen.list.limit === 2 && seen.list.offset === 0 &&
          yubi.operationId === 'getYubiOtpTokens' &&
          yubi.mirrors === 'GET /admin/hardware-tokens',
          'B6. GET .../yubiotp answers the store\'s page with the paging the ' +
          'console reads', JSON.stringify(listed.body));
  const broke = await drive(yubi.handler, { query: { q: 'boom' } });
  t.check(broke.statusCode === 500 &&
          errorCodes.codeOf(broke) === 'STS-YUBIOTP-0035',
          'B7. a store that throws is a 500 marked STS-YUBIOTP-0035');
  log.debug("Leaving checkApi().");
}

async function checkStore(t) {
  log.debug("Entering checkStore().");
  const ldap = require('../ldap/ldap_server');
  const entries = require('../common/token_entries');
  const yubi = require('../common/yubiotp_store');
  const person = 'yl-' + RUN;
  ldap.createUser(person, { invent: false, attributes: {} });
  const serials = ['71' + RUN.slice(-6), '72' + RUN.slice(-6)];
  const csv = 'serial,public id,private id,aes key\n' +
    serials[0] + ',ccccccbcdefg,0102030405a6,' +
    '00112233445566778899aabbccddeeff\n' +
    serials[1] + ',ccccccbcdefh,0102030405a7,' +
    'ffeeddccbbaa99887766554433221100';
  const imported = yubi.importCsv({ csv: csv, actor: 'test', via: 'test' });
  t.check(imported.ok && imported.imported.length === 2,
          'precondition: two YubiKey OTPs are imported',
          JSON.stringify(imported));
  const all = await yubi.list({ limit: 500 });
  const mine = all.tokens.filter(function (r) {
    return serials.indexOf(r.serial) >= 0;
  });
  const text = JSON.stringify(all);
  t.check(mine.length === 2 && mine.every(function (r) {
    return r.status === 'unassigned' && r.holder === '' && r.publicId;
  }) && text.indexOf('00112233445566778899aabbccddeeff') < 0 &&
          text.indexOf('secret') < 0,
          'C1. the imports are listed unassigned, never with a key',
          JSON.stringify(mine));
  const one = await yubi.list({ q: serials[1] });
  t.check(one.tokens.length === 1 && one.tokens[0].serial === serials[1] &&
          one.total === 1, 'C2. a serial is matched exactly',
          JSON.stringify(one));
  const unassigned = await yubi.list({ status: 'unassigned', limit: 500 });
  const assignedNone = await yubi.list({ status: 'assigned', limit: 500 });
  t.check(unassigned.tokens.filter(function (r) {
    return serials.indexOf(r.serial) >= 0;
  }).length === 2 && !assignedNone.tokens.some(function (r) {
    return serials.indexOf(r.serial) >= 0;
  }), 'C3. status filters through the index');
  // THE PERSON'S ENTRY IS THE MASTER: a value on it is listed for them,
  // whether or not this process holds an inventory row for that serial.
  const onEntry = '73' + RUN.slice(-6);
  const state = entries.project(person, entries.ATTRIBUTES.yubiotp, onEntry,
    { serial: onEntry, publicId: 'ccccccbcdefj', credentialId: 'c1',
      status: 'assigned', importedAt: '2026-11-24T00:00:00Z',
      assignedAt: '2026-11-24T00:01:00Z', retiredAt: '' });
  const theirs = await yubi.list({ q: person });
  t.check(state !== 'failed' && theirs.tokens.length === 1 &&
          theirs.tokens[0].serial === onEntry &&
          theirs.tokens[0].holder === person &&
          theirs.tokens[0].status === 'assigned',
          'C4. a person\'s tokens are read off their entry (stsYubiOtpToken)',
          JSON.stringify({ state: state, theirs: theirs }));
  const paged = await yubi.list({ limit: 1, offset: 1 });
  t.check(paged.tokens.length === 1 && paged.total >= 2,
          'C5. the list is paged by offset and limit', JSON.stringify(paged));
  for (const serial of serials) {
    yubi.remove({ serial: serial, actor: 'test' });
  }
  log.debug("Leaving checkStore().");
}

function checkConsole(t) {
  log.debug("Entering checkConsole().");
  const WebKit = require('../admin-ui/web_kit');
  const Page = require('../admin-ui/web_hardware_tokens');
  const WebAnswers = require('../admin-ui/web_answers');
  const writer = WebKit.context({}, true);
  const reader = WebKit.context({}, false);
  const yubiotp = { tokens: [
    { serial: '901', publicId: 'ccccccbcdefg', status: 'unassigned',
      holder: '', importedAt: 'a', assignedAt: '', retiredAt: '' },
    { serial: '902', publicId: 'ccccccbcdefh', status: 'assigned',
      holder: 'erin', importedAt: 'a', assignedAt: 'b', retiredAt: '' }],
    paging: { pages: 1 }, q: '', status: '' };
  const view = { tokens: [], paging: { pages: 1 }, yubiotp: yubiotp };
  const html = Page.render(view, writer);
  const tab = html.slice(html.indexOf('data-tab="yubiotp"'),
                         html.indexOf('data-tab="enrol"'));
  t.check(tab.length > 0 && tab.indexOf('name="yq"') >= 0 &&
          tab.indexOf('value="import-yubiotp"') >= 0 &&
          tab.indexOf('name="csv"') >= 0 &&
          (tab.match(/value="assign-yubiotp"/g) || []).length === 1 &&
          (tab.match(/value="remove-yubiotp"/g) || []).length === 1 &&
          tab.indexOf('#hardware-tokens-tab-yubiotp') >= 0,
          'D1. the YubiKey OTP tab: filters, the import form, Assign on the ' +
          'unassigned token and Remove on the one not assigned', tab);
  const ssh = html.slice(html.indexOf('data-tab="ssh"'));
  t.check(ssh.indexOf('value="issue-ssh"') >= 0 &&
          ssh.indexOf('name="username"') >= 0 &&
          ssh.indexOf('name="publicKey"') >= 0 &&
          ssh.indexOf('name="principals"') >= 0 &&
          ssh.indexOf('action="/admin/hardware-tokens"') >= 0,
          'D2. the SSH tab carries the Issue form, posting to the central ' +
          'page', ssh.slice(0, 800));
  const read = Page.render(view, reader);
  t.check(read.indexOf('value="import-yubiotp"') < 0 &&
          read.indexOf('value="assign-yubiotp"') < 0 &&
          read.indexOf('value="issue-ssh"') < 0,
          'D3. a reader who may not write gets none of the forms');
  const personSsh = Page.personSsh(writer.t, { tokens: [], q: 'erin' },
                                   writer, 'erin');
  t.check(personSsh.indexOf('value="issue-ssh"') >= 0 &&
          personSsh.indexOf('<input type="hidden" name="username" ' +
                            'value="erin">') >= 0 &&
          personSsh.indexOf('id="hwt-ssh-user"') < 0,
          'D4. the person\'s SSH sub-tab issues with the person fixed',
          personSsh);
  const personYubi = Page.personYubi(writer.t, yubiotp, writer, 'erin', '');
  t.check(personYubi.indexOf('<code>902</code>') >= 0 &&
          personYubi.indexOf('<code>901</code>') < 0 &&
          personYubi.indexOf('value="assign-yubiotp"') >= 0,
          'D5. the person\'s YubiKey OTP sub-tab lists their tokens and ' +
          'assigns by serial', personYubi);
  const once = WebAnswers.once('/admin/hardware-tokens', 'issue-ssh',
    { username: 'erin' }, { ok: true, username: 'erin',
      certificate: 'ssh-ed25519-cert-v01@openssh.com AAAA erin',
      serialHex: 'c3', message: 'issued' },
    { back: '/admin/users?user=erin' });
  t.check(once && /SSH/.test(once.title) &&
          once.html.indexOf('ssh-ed25519-cert-v01@openssh.com AAAA erin') >=
            0 && once.up && once.up.via && once.up.via[0].label === 'erin',
          'D6. the issued certificate is drawn once, the trail through the ' +
          'person', JSON.stringify(once));
  log.debug("Leaving checkConsole().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkCore(t);
  await checkApi(t);
  await checkStore(t);
  checkConsole(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_ssh_issue_yubiotp_list',
  describe: 'an administrator issues a person\'s SSH user certificate ' +
            'through the person\'s own core, and the YubiKey OTP inventory ' +
            'is listed, a person\'s off their entry (#2071)',
  run: run
};
