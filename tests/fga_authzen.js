// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/fga_authzen.js
//
// ---------------------------------------------------------------------------
// AUTHZEN DECIDES AGAINST AN APPLICATION'S OWN FINE-GRAINED POLICY (#564,
// phase P4; rcbj's decision 4, which amends #563's decision 7).
//
// `tests/authzen_evaluation.js`'s arrangement: the whole stack in a child
// process, a listener with the main port's posture over the client
// truststore, the certificate door, and a throwaway realm whose ROOT policy
// this file wrote. The root permits `read` and `delete` and says nothing
// about `archive`. Three applications are in the caller's scope:
// `fgaz-plain` (FGA never enabled), `fgaz-docs` (FGA enforced), and none of
// `fgaz-secret` (FGA enforced, out of scope). What it holds:
//
//   R. ROUTING. An application without FGA is decided by the root, as
//      before (read and delete true, archive false). With FGA enforced and
//      its DEFAULT policy, archive — NotApplicable at the root — is true:
//      the application's policy decided, not the root. A custom policy that
//      denies delete answers false while the root would permit it, and its
//      read is true only because the request carries AuthZEN's
//      `protocol = authzen` and the two FGA facts (application, stage
//      `access`) its target reads.
//   A. THE AUDIT ROW names the fine-grained policy, its PolicyId and
//      version, and the monitor counts the decision once, on `authzen` and
//      not on `fga`.
//   E. ERRORS, NEVER FALSE: a disabled policy and an unparseable one are
//      500 (STS-AUTHZEN-0040), the audit row carrying the STS-FGA code that
//      says why (0006, 0007); in a batch, that item's context.error.
//   S. SCOPE: a caller scoped away from an enforcing application cannot
//      reach its policy by naming it (403, STS-AUTHZEN-0025).
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const https = require('https');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_FGA_AUTHZEN_CHILD';
const MARK = 'FGA-AUTHZEN-CHILD ';
const REALM = 'fgazen';
const PREFIX = '/realm/' + REALM;

const CA_PEM = { value: '' };

const log = require('bunyan').createLogger({ name: 'fga_authzen',
  level: process.env.LOG_LEVEL || 'info' });

// THE REALM'S ROOT: AuthZEN questions may read and delete; nothing else is
// decided (archive is NotApplicable, so false).
const ROOT_POLICY = [
  'namespace fgazen {',
  '    attribute act { category = actionCat',
  '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '        type = string }',
  '    attribute protocol { category = environmentCat',
  '        id = "urn:sts:xacml:protocol" type = string }',
  '    policy fgazenRoot {',
  '        id = "urn:test:fgazen-root"',
  '        apply firstApplicable',
  '        target clause protocol == "authzen"',
  '        rule readOrDelete {',
  '            permit',
  '            target clause act == "read" or act == "delete"',
  '        }',
  '    }',
  '}'
].join('\n');

// THE APPLICATION'S OWN POLICY: only an AuthZEN question, about THIS
// application, at stage `access` is in its target — so a Permit proves the
// request carried all three facts — and delete is denied.
const NO_DELETE = [
  'namespace fgazendocs {',
  '    attribute act { category = actionCat',
  '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '        type = string }',
  '    attribute protocol { category = environmentCat',
  '        id = "urn:sts:xacml:protocol" type = string }',
  '    attribute stage { category = environmentCat',
  '        id = "urn:sts:xacml:fga:stage" type = string }',
  '    attribute owner { category = resourceCat',
  '        id = "urn:sts:xacml:fga:application" type = string }',
  '    policy fgazenDocs {',
  '        id = "urn:test:fgazen-docs"',
  '        apply firstApplicable',
  '        target clause protocol == "authzen"',
  '        target clause stage == "access"',
  '        target clause owner == "fgaz-docs"',
  '        rule noDelete {',
  '            deny',
  '            target clause act == "delete"',
  '        }',
  '        rule everythingElse {',
  '            permit',
  '        }',
  '    }',
  '}'
].join('\n');

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function request(port, method, urlPath, cred, body) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const text = body === undefined ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const req = https.request({ host: '127.0.0.1', port: port,
      path: urlPath, method: method,
      headers: { 'content-type': 'application/json',
                 'content-length': Buffer.byteLength(text) },
      ca: CA_PEM.value, cert: cred ? cred.certPem : undefined,
      key: cred ? cred.keyPem : undefined, agent: false }, function (res) {
      let raw = '';
      res.on('data', function (chunk) {
        raw += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in request(): " + e.message);
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: raw,
                  json: json });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in request(): " + e.message);
      resolve({ status: 0, headers: {}, text: '', json: null,
                error: e.message });
    });
    req.end(text);
  });
}

// One evaluation about `application`, asking `action`.
function evaluation(application, action) {
  log.debug("Entering evaluation().");
  log.debug("Leaving evaluation().");
  return { subject: { type: 'user', id: 'fgazalice' },
           action: { name: action },
           resource: { type: 'document', id: 'doc-1' },
           context: { application: application } };
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const applications = require(ROOT + '/common/applications');
  const errorCodes = require(ROOT + '/common/error_codes');
  const audit = require(ROOT + '/common/audit');
  const tls = require(ROOT + '/tls/tls_server');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const store = require(ROOT + '/xacml/xacml_store');
  const xml = require(ROOT + '/xacml/xacml_xml');
  const alfa = require(ROOT + '/xacml/xacml_alfa');
  const fga = require(ROOT + '/xacml/fga_policies');
  const monitor = require(ROOT + '/xacml/xacml_monitor');
  const testCa = require('./protocol/outbound_test_ca');
  const outsideCa = require('./tools/pep-credential.js');

  const marks = [];
  const mark = errorCodes.mark;
  errorCodes.mark = function (res, code) {
    marks.push(code);
    return mark.apply(this, arguments);
  };
  const markedSince = function (since, code) {
    log.debug("Entering markedSince().");
    log.debug("Leaving markedSince().");
    return marks.slice(since).indexOf(code) >= 0;
  };

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };

  // THE CALLER, the applications and the root.
  const pepCred = await outsideCa.mint({ subject: 'CN=fgazpep,O=Outside',
                                         crlBase: '' });
  const added = tls.addAnchors(pepCred.anchorPem);
  t.check(added && added.added === 1,
          'setup: the outside Root CA is in the client truststore',
          JSON.stringify(added));
  const group = String(config.value('roles.authzenPepGroup'));
  const made = inRealm(function () {
    ['fgazalice', 'fgazpep'].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    ldap.changeStoredCertificate('person', 'fgazpep',
      { add: new nodeCrypto.X509Certificate(pepCred.leaf.pem).raw });
    adminActions.groupsAction({ action: 'add-member', group: group,
                                member: 'fgazpep' });
    ldap.locateEntry('fgazpep').stored.attributes.stsauthzenapplication =
      ['fgaz-plain', 'fgaz-docs'];
    store.write('fgazen-root', xml.writePolicy(alfa.parse(ROOT_POLICY)),
                { enabled: true, isRoot: true });
    return ['fgaz-plain', 'fgaz-docs', 'fgaz-secret'].map(function (id) {
      return applications.createApplication({ identifier: id,
        protocols: ['oauth2'], fields: { oauthClientId: id } });
    });
  });
  t.check(made.every(function (one) {
    return one && one.ok !== false;
  }), 'setup: three applications, each with its default policy',
          JSON.stringify(made));
  const enabled = inRealm(function () {
    return [fga.enable('fgaz-docs', { actor: 'test' }),
            fga.enable('fgaz-secret', { actor: 'test' })];
  });
  t.check(enabled.every(function (one) {
    return one && one.ok && one.enforced === true;
  }), 'setup: FGA is enforced on fgaz-docs and fgaz-secret',
          JSON.stringify(enabled));
  const docsPolicy = inRealm(function () {
    return applications.fgaStateOf('fgaz-docs').policy;
  });

  // THE LISTENER, with the main port's posture over the client truststore.
  const serverCa = await testCa.makeCa();
  const serverLeaf = await testCa.listenerCertificate(serverCa, '127.0.0.1');
  CA_PEM.value = serverCa.certPem;
  const listener = https.createServer(Object.assign({
    cert: serverLeaf.cert, key: serverLeaf.key,
    ca: tls.clientTruststoreOptions().ca,
    requestCert: true, rejectUnauthorized: false
  }, tls.protocolOptions()), app);
  tls.trustClientCertificatesOn(listener, 'the fga_authzen listener',
    function () {
      log.debug("Entering the listener's certificateOf().");
      log.debug("Leaving the listener's certificateOf().");
      return { key: serverLeaf.key, cert: serverLeaf.cert };
    });
  await new Promise(function (ok) {
    listener.listen(0, '127.0.0.1', ok);
  });
  const port = listener.address().port;
  const URL = PREFIX + '/access/v1/evaluation';
  const BATCH = PREFIX + '/access/v1/evaluations';
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return r.status + ' ' + String(r.text || '').slice(0, 300);
  };
  const ask = function (application, action) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return request(port, 'POST', URL, pepCred,
                   evaluation(application, action));
  };
  const decided = function (r, expected) {
    log.debug("Entering decided().");
    log.debug("Leaving decided().");
    return r.status === 200 && r.json && r.json.decision === expected;
  };
  const countOf = function (id) {
    log.debug("Entering countOf().");
    log.debug("Leaving countOf().");
    return inRealm(function () {
      return (monitor.snapshot().rows.filter(function (row) {
        return row.id === id;
      })[0] || {}).decisions || 0;
    });
  };
  const authzenRows = function () {
    log.debug("Entering authzenRows().");
    log.debug("Leaving authzenRows().");
    return inRealm(function () {
      return audit.list();
    }).filter(function (row) {
      return row && row.action === 'authzen.decision';
    });
  };

  // -------------------------------------------------------------------------
  // R. ROUTING
  // -------------------------------------------------------------------------
  let r = await ask('fgaz-plain', 'read');
  const plainDelete = await ask('fgaz-plain', 'delete');
  const plainArchive = await ask('fgaz-plain', 'archive');
  t.check(decided(r, true) && decided(plainDelete, true) &&
          decided(plainArchive, false),
          'R1. an application without FGA is decided by the realm root, ' +
          'unchanged: read and delete true, archive (NotApplicable) false',
          [brief(r), brief(plainDelete), brief(plainArchive)].join(' / '));
  r = await ask('fgaz-docs', 'archive');
  t.check(decided(r, true),
          'R2. with FGA enforced and its DEFAULT policy, archive is true — ' +
          'the application\'s policy decided, not the root', brief(r));
  const written = inRealm(function () {
    return store.write(docsPolicy, xml.writePolicy(alfa.parse(NO_DELETE)),
                       { enabled: true });
  });
  t.check(written && written.ok !== false,
          'setup: fgaz-docs\'s own policy now denies delete',
          JSON.stringify(written));
  const authzenBefore = countOf('authzen');
  const fgaBefore = countOf('fga');
  r = await ask('fgaz-docs', 'delete');
  t.check(decided(r, false) && decided(plainDelete, true),
          'R3. its custom policy denies delete: false, where the root ' +
          'permits it (fgaz-plain\'s true)', brief(r));
  r = await ask('fgaz-docs', 'read');
  t.check(decided(r, true),
          'R4. and read is true, which its target allows only for a ' +
          'request carrying protocol authzen, the FGA application ' +
          'fgaz-docs and stage access', brief(r));

  // -------------------------------------------------------------------------
  // A. THE AUDIT ROW, AND THE MONITOR
  // -------------------------------------------------------------------------
  const named = authzenRows().filter(function (row) {
    // The row's own text, not its JSON: a quote inside it is escaped there.
    const text = String(row.summary || '') + ' ' +
                 String(typeof row.detail === 'string' ? row.detail : '');
    return text.indexOf('"' + docsPolicy + '"') >= 0 &&
           text.indexOf('PolicyId urn:test:fgazen-docs') >= 0 &&
           /, version [^,)]+\)/.test(text) &&
           /fine-grained authorization policy/.test(text);
  });
  t.check(named.length >= 2,
          'A1. the authzen.decision row names the fine-grained policy, ' +
          'its PolicyId and version', named.length + ' row(s): ' +
          JSON.stringify(named[0] || authzenRows().slice(-1)[0] || null)
            .slice(0, 600));
  const rootRow = authzenRows().filter(function (row) {
    return /fgaz-plain/.test(JSON.stringify(row));
  })[0];
  t.check(!!rootRow && !/fine-grained/.test(JSON.stringify(rootRow)),
          'A2. a row the root decided names no fine-grained policy',
          JSON.stringify(rootRow || null).slice(0, 300));
  t.check(countOf('authzen') === authzenBefore + 2 &&
          countOf('fga') === fgaBefore,
          'A3. each decision is counted once, on the authzen row and not ' +
          'on fga', 'authzen ' + authzenBefore + ' -> ' + countOf('authzen') +
          ', fga ' + fgaBefore + ' -> ' + countOf('fga'));

  // -------------------------------------------------------------------------
  // E. A POLICY THAT CANNOT BE USED IS AN ERROR, NEVER FALSE
  // -------------------------------------------------------------------------
  inRealm(function () {
    return store.write(docsPolicy, xml.writePolicy(alfa.parse(NO_DELETE)),
                       { enabled: false });
  });
  let since = marks.length;
  r = await ask('fgaz-docs', 'read');
  t.check(r.status === 500 && markedSince(since, 'STS-AUTHZEN-0040') &&
          !(r.json && r.json.decision === false),
          'E1. a DISABLED policy is 500 (STS-AUTHZEN-0040), never false ' +
          'and never the root instead', brief(r));
  r = await request(port, 'POST', BATCH, pepCred, {
    subject: { type: 'user', id: 'fgazalice' },
    resource: { type: 'document', id: 'doc-1' },
    evaluations: [{ action: { name: 'read' },
                    context: { application: 'fgaz-plain' } },
                  { action: { name: 'read' },
                    context: { application: 'fgaz-docs' } }] });
  const items = (r.json && r.json.evaluations) || [];
  t.check(r.status === 200 && items.length === 2 &&
          items[0].decision === true && items[1].decision === false &&
          items[1].context && items[1].context.error &&
          items[1].context.error.status === 500,
          'E2. in a batch it is that item\'s context.error (500), the ' +
          'other item decided by the root as before', brief(r));
  inRealm(function () {
    store.directoryInstalled().writePolicy('fgaz-broken', {
      objectClass: ['top', 'xacmlPolicy'], xacmlPolicyId: 'urn:x:broken',
      xacmlPolicyDocument: '<Policy', xacmlEnabled: 'TRUE',
      xacmlApplication: 'fgaz-docs' });
    applications.setFgaState('fgaz-docs', { policy: 'fgaz-broken' },
                             { actor: 'test' });
  });
  since = marks.length;
  r = await ask('fgaz-docs', 'read');
  t.check(r.status === 500 && markedSince(since, 'STS-AUTHZEN-0040'),
          'E3. an UNPARSEABLE policy is 500 (STS-AUTHZEN-0040)', brief(r));
  const codes = authzenRows().map(function (row) {
    return row.errorCode;
  });
  t.check(codes.indexOf('STS-FGA-0006') >= 0 &&
          codes.indexOf('STS-FGA-0007') >= 0,
          'E4. the audit rows carry the STS-FGA code that says why ' +
          '(0006 disabled, 0007 unparseable)', codes.join(' '));
  inRealm(function () {
    applications.setFgaState('fgaz-docs', { policy: docsPolicy },
                             { actor: 'test' });
    store.remove('fgaz-broken');
    store.write(docsPolicy, xml.writePolicy(alfa.parse(NO_DELETE)),
                { enabled: true });
  });
  r = await ask('fgaz-docs', 'read');
  t.check(decided(r, true), 'E5. and with its policy back it decides ' +
          'again', brief(r));

  // -------------------------------------------------------------------------
  // S. SCOPE
  // -------------------------------------------------------------------------
  since = marks.length;
  r = await ask('fgaz-secret', 'read');
  t.check(r.status === 403 && markedSince(since, 'STS-AUTHZEN-0025'),
          'S1. a caller scoped away from an enforcing application cannot ' +
          'reach its policy by naming it (403, STS-AUTHZEN-0025)', brief(r));

  await new Promise(function (ok) {
    listener.close(ok);
  });
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== AuthZEN against an application\'s FGA policy (#564) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'fga_authzen',
  describe: 'AuthZEN decides against an application\'s own fine-grained ' +
            'policy when it enforces FGA (#564 P4): routing, the audit row, ' +
            'the monitor, errors never false, and the caller\'s scope',
  run: run
};
