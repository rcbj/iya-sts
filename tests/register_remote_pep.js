// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/register_remote_pep.js
// ===========================================================================
// THE OPERATOR'S TOOL, utilities/register-remote-pep.js, RUN AGAINST THE
// WHOLE STACK (rcbj 2026-11-16: "I need a utility script, command, or
// documented process to register a new remote pep").
//
// In a CHILD PROCESS with the stack on an ephemeral plain-HTTP loopback port,
// as `pep_assertion_credential.js` runs; the tool itself is a grandchild,
// started asynchronously so the stack keeps answering it, with nothing but a
// management API token minted for `sts-api-client` in its environment:
//
//   U. what it refuses before it calls anything: plain http:// to a host
//      that is not loopback, NODE_TLS_REJECT_UNAUTHORIZED=0 without
//      --insecure, and --pep-app without --cluster (exit 2).
//   T. a token the service did not issue: step "Checking the token and the
//      realm" fails with the service's own words, and nothing is written.
//   O. a realm with no Admin Write group (a bare process has none): the
//      entry is made and joins remote-peps, the service cannot make it a
//      service account, and the tool stops at step 3 naming
//      STS-SVCACCT-0051 and --owner. Run again with --owner, the first two
//      steps are skipped and it finishes.
//   D. --dry-run with --cluster --create-cluster: exit 0, and no entry, no
//      cluster and no --out directory.
//   R. a fresh name, end to end: the entry (a service account owned by the
//      Admin Write group, in remote-peps), ONE valid RFC 7523 key whose
//      serial is the certificate's in --out, the key file 0600 and never
//      printed, the environment and compose files, the cluster membership,
//      and the listener step waiting for a registration. The cluster
//      compose is the members plus one load balancer on 127.0.0.1, with
//      no TCP forwarder and no published decision API.
//   C. a second member beside the first shares that balancer. A member
//      whose PEP_PDP_URL host is localhost also gets the reach script;
//      a PDP URL of https://sts:8081 does not.
//   I. the same command again: every step skipped, still one key, the key
//      file unchanged.
//   K. the key in --out signs the PEP's own grant, and the PEP registers on
//      the token; a third run then issues the HTTPS listener pair, and a
//      fourth skips it.
//   P. --pep-app on its own cluster: the application and role already
//      exist from the cluster run above. This cluster gets the same
//      session path, the secret is not printed again, and a second run
//      skips.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'register_remote_pep',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.RRP_ROOT;
  const OUT = process.env.RRP_OUT;
  const http = require('http');
  const fsc = require('fs');
  const osc = require('os');
  const pathc = require('path');
  const cp = require('child_process');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, where, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body ? JSON.stringify(body) : '';
      const req = http.request({ host: '127.0.0.1', port: port, path: where,
        method: method, headers: Object.assign({
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(text) },
          token ? { authorization: 'Bearer ' + token } : {}) },
      function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: raw, json: json });
        });
      });
      req.on('error', reject);
      req.end(text);
    });
  }
  const TOOL = pathc.join(ROOT_DIR, 'utilities', 'register-remote-pep.js');
  // The tool, asynchronously: this process is the service it calls.
  function tool(args, env) {
    return new Promise(function (resolve) {
      cp.execFile(process.execPath, [TOOL].concat(args), {
        env: Object.assign({ PATH: process.env.PATH }, env || {}),
        timeout: 120000, cwd: ROOT_DIR
      }, function (error, stdout, stderr) {
        resolve({ code: error ? (typeof error.code === 'number'
                                   ? error.code : 99) : 0,
                  out: String(stdout || ''), err: String(stderr || '') });
      });
    });
  }
  const said = function (r) {
    return 'exit ' + r.code + '\n' + (r.out + '\n' + r.err).slice(-1500);
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const pki = require(ROOT_DIR + '/common/pki');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const credentials = require(ROOT_DIR + '/tests/tools/pep-credential.js');

    if (!pki.hasChain()) {
      await pki.start({});
    }
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const token = await realms.run(realms.DEFAULT_REALM, function () {
      return oauth2.accessTokenAsync(BASE, { audience: BASE + '/admin-api',
        scope: 'admin:read admin:write', client_id: 'sts-api-client',
        sub: 'sts-api-client' });
    });
    // The tests image has no Docker daemon. A real run starts the containers.
    const ENV = { STS_ADMIN_API_TOKEN: token,
                  REGISTER_PEP_NO_START: '1' };
    const get = function (where) {
      return call(port, 'GET', '/admin-api' + where, token);
    };
    const entryOf = async function (name) {
      const r = await get('/users?user=' + encodeURIComponent(name));
      const body = r.json || {};
      const pairs = (body.credentials && body.credentials.keyPairs) || [];
      const jwt = pairs.filter(function (one) {
        return one.purpose === 'jwt';
      })[0];
      return { found: !!(body.known && body.ldap && body.ldap.found),
               serviceAccount: body.serviceAccount || null,
               keys: (jwt && jwt.keys) || [] };
    };
    const memberOf = async function (group, name) {
      const r = await get('/groups?q=' + encodeURIComponent(group));
      const row = ((r.json && r.json.groups) || []).filter(function (one) {
        return one.cn === group;
      })[0];
      if (!row) {
        return false;
      }
      const one = await get('/groups?group=' + encodeURIComponent(row.dn));
      return JSON.stringify((one.json && one.json.group) || one.json || {})
        .indexOf('uid=' + name + ',') >= 0;
    };
    const stamp = Date.now().toString(36);
    const dirs = [];
    const outDir = function (label) {
      const dir = pathc.join(fsc.mkdtempSync(pathc.join(osc.tmpdir(),
        'rrp-' + label + '-')), 'out');
      dirs.push(pathc.dirname(dir));
      return dir;
    };
    const common = function (name, out) {
      return ['--url=' + BASE, '--name=' + name, '--out=' + out];
    };

    // ---------------------------------------------------------------------
    // U. THE REFUSALS BEFORE ANYTHING IS CALLED.
    // ---------------------------------------------------------------------
    const offLoopback = await tool(['--url=http://sts.example.test:8081',
      '--name=rrp-u-' + stamp, '--out=' + outDir('u')], ENV);
    note(offLoopback.code === 2 && /plain http/.test(offLoopback.err),
         'U1. plain http:// to a host that is not loopback is refused',
         said(offLoopback));
    const quietOff = await tool(['--url=https://127.0.0.1:' + port,
      '--name=rrp-u-' + stamp, '--out=' + outDir('u2')],
      Object.assign({ NODE_TLS_REJECT_UNAUTHORIZED: '0' }, ENV));
    note(quietOff.code === 2 &&
         /NODE_TLS_REJECT_UNAUTHORIZED=0/.test(quietOff.err),
         'U2. verification turned off by the environment is refused, not ' +
         'obeyed silently', said(quietOff));
    const noCluster = await tool(['--url=http://127.0.0.1:' + port,
      '--name=rrp-u-' + stamp, '--out=' + outDir('u3'), '--pep-app'], ENV);
    note(noCluster.code === 2 && /--pep-app/.test(noCluster.err) &&
         /--cluster/.test(noCluster.err) &&
         !(await entryOf('rrp-u-' + stamp)).found,
         'U3. --pep-app without --cluster is refused before anything is ' +
         'written', said(noCluster));

    // ---------------------------------------------------------------------
    // T. A TOKEN THE SERVICE DID NOT ISSUE.
    // ---------------------------------------------------------------------
    const tName = 'rrp-t-' + stamp;
    const tOut = outDir('t');
    const badToken = await tool(common(tName, tOut),
                                { STS_ADMIN_API_TOKEN: 'not-a-token' });
    note(badToken.code === 1 &&
         /FAILED at Checking the token and the realm/.test(badToken.err) &&
         /HTTP 401/.test(badToken.err) && /What to do:/.test(badToken.err),
         'T1. a bad token fails at the first step, with the service\'s ' +
         'refusal and what to do', said(badToken));
    note(!fsc.existsSync(tOut) && !(await entryOf(tName)).found,
         'T2. and nothing was written, here or there');

    // ---------------------------------------------------------------------
    // O. NOBODY TO OWN IT.
    // ---------------------------------------------------------------------
    const oName = 'rrp-o-' + stamp;
    const oOut = outDir('o');
    const noOwner = await tool(common(oName, oOut), ENV);
    note(noOwner.code === 1 &&
         /FAILED at 3\. Service account/.test(noOwner.err) &&
         /STS-SVCACCT-0051/.test(noOwner.err) &&
         /--owner/.test(noOwner.err),
         'O1. with no Admin Write group the tool stops at the service ' +
         'account, naming STS-SVCACCT-0051 and --owner', said(noOwner));
    const oEntry = await entryOf(oName);
    note(oEntry.found && !oEntry.serviceAccount &&
         await memberOf('remote-peps', oName) && oEntry.keys.length === 0,
         'O2. the entry and its membership stand; no key was certified',
         JSON.stringify(oEntry));
    const OWNER = 'rrp-owner-' + stamp;
    ldap.createUser(OWNER, { invent: false });
    const owned = await tool(common(oName, oOut).concat(['--owner=' + OWNER]),
                             ENV);
    const oAfter = await entryOf(oName);
    note(owned.code === 0 && /1\. The entry [^:]*: exists; skipped/
           .test(owned.out) &&
         /2\. Membership of remote-peps: already a member; skipped/
           .test(owned.out) &&
         /3\. Service account: made one, owned by /.test(owned.out) &&
         !!oAfter.serviceAccount && oAfter.keys.length === 1,
         'O3. run again with --owner: the first two steps are skipped, it ' +
         'is made a service account and its key certified', said(owned));

    // The realm's Admin Write group, which a deployment has.
    const made = await call(port, 'POST', '/admin-api/groups/create', token,
                            { group: 'admin-write' });
    note(made.status === 200, 'precondition: the admin-write group exists',
         made.status + ' ' + made.text.slice(0, 200));

    // ---------------------------------------------------------------------
    // D. --dry-run CHANGES NOTHING.
    // ---------------------------------------------------------------------
    const NAME = 'rrp-pep-' + stamp;
    const CLUSTER = 'rrp-c-' + stamp;
    const OUTDIR = outDir('r');
    const full = common(NAME, OUTDIR).concat(['--cluster=' + CLUSTER,
      '--create-cluster', '--pdp-url=https://sts:8081']);
    const dry = await tool(full.concat(['--dry-run']), ENV);
    const clustersAfterDry = await get('/xacml/pep-clusters');
    const dryParent = pathc.dirname(OUTDIR);
    note(dry.code === 0 && /DRY RUN/.test(dry.out) &&
         /would be created/.test(dry.out) &&
         !(await entryOf(NAME)).found && !fsc.existsSync(OUTDIR) &&
         !fsc.existsSync(pathc.join(dryParent,
           'pep-cluster-' + CLUSTER + '.json')) &&
         !fsc.existsSync(pathc.join(dryParent,
           'docker-compose.pep-cluster.yml')) &&
         !((clustersAfterDry.json && clustersAfterDry.json.clusters) || [])
           .some(function (one) { return one.name === CLUSTER; }),
         'D1. --dry-run says what it would do and creates no entry, no ' +
         'cluster and no files', said(dry));

    // ---------------------------------------------------------------------
    // R. A FRESH NAME, END TO END.
    // ---------------------------------------------------------------------
    const first = await tool(full, ENV);
    const entry = await entryOf(NAME);
    note(first.code === 0, 'R1. a fresh name registers end to end',
         said(first));
    note(entry.found && !!entry.serviceAccount &&
         (entry.serviceAccount.owners || []).some(function (one) {
           return one.name === 'admin-write';
         }) && await memberOf('remote-peps', NAME),
         'R2. the entry is a service account owned by admin-write, in ' +
         'remote-peps', JSON.stringify(entry.serviceAccount));
    const keyFile = pathc.join(OUTDIR, 'pep-assertion.key');
    const crtFile = pathc.join(OUTDIR, 'pep-assertion.crt');
    const keyPem = fsc.existsSync(keyFile)
      ? fsc.readFileSync(keyFile, 'utf8') : '';
    let serial = '';
    try {
      serial = new (require('crypto').X509Certificate)(
        fsc.readFileSync(crtFile, 'utf8')).serialNumber;
    } catch (e) {
      // No certificate in --out: R3 reports the empty serial.
      serial = '';
    }
    const plainSerial = function (s) {
      return String(s || '').toLowerCase().replace(/^0+/, '');
    };
    const valid = entry.keys.filter(function (one) {
      return one.state === 'valid';
    });
    note(valid.length === 1 &&
         plainSerial(valid[0].serialHex) === plainSerial(serial),
         'R3. one valid RFC 7523 key is on the entry, the certificate in ' +
         '--out', JSON.stringify(entry.keys.map(function (one) {
           return [one.serialHex, one.state];
         })) + ' crt ' + serial);
    note(!!keyPem && (fsc.statSync(keyFile).mode & 0o777) === 0o600,
         'R4. the private key is written 0600',
         keyPem ? (fsc.statSync(keyFile).mode & 0o777).toString(8) : 'none');
    const keyBody = keyPem.split('\n').filter(function (line) {
      return line && line.indexOf('-----') !== 0;
    }).join('');
    note(!!keyBody && (first.out + first.err).indexOf(keyBody.slice(0, 40))
           < 0 && !/PRIVATE KEY/.test(first.out + first.err),
         'R5. and never printed');
    const envText = fsc.existsSync(pathc.join(OUTDIR, 'pep.env'))
      ? fsc.readFileSync(pathc.join(OUTDIR, 'pep.env'), 'utf8') : '';
    note(/^PEP_NAME=rrp-pep-/m.test(envText) &&
         /^PEP_PDP_URL=https:\/\/sts:8081$/m.test(envText) &&
         /^PEP_CLIENT_ID=sts-remote-pep$/m.test(envText) &&
         /^PEP_ASSERTION_KEY=\/certs\/pep-assertion\.key$/m.test(envText) &&
         /^PEP_HTTPS_CERT=\/certs\/server\/pep-server\.crt$/m.test(envText) &&
         fsc.existsSync(pathc.join(OUTDIR, 'docker-compose.pep.yml')) &&
         /PEP_ASSERTION_KEY=/.test(first.out),
         'R6. the environment and the compose service are written, and ' +
         'the environment printed', envText);
    const parent = pathc.dirname(OUTDIR);
    const clusterYml = pathc.join(parent, 'docker-compose.pep-cluster.yml');
    const haproxyFile = pathc.join(parent, 'pep-cluster-haproxy.cfg');
    const reachFile = pathc.join(parent, 'pep-cluster-reach-sts.sh');
    const planFile = pathc.join(parent, 'pep-cluster-' + CLUSTER + '.json');
    const memberCompose = fsc.existsSync(
      pathc.join(OUTDIR, 'docker-compose.pep.yml'))
      ? fsc.readFileSync(pathc.join(OUTDIR, 'docker-compose.pep.yml'), 'utf8')
      : '';
    const sharedCompose = fsc.existsSync(clusterYml)
      ? fsc.readFileSync(clusterYml, 'utf8') : '';
    const haproxy = fsc.existsSync(haproxyFile)
      ? fsc.readFileSync(haproxyFile, 'utf8') : '';
    let plan = {};
    try {
      plan = JSON.parse(fsc.readFileSync(planFile, 'utf8'));
    } catch (e) {
      // R6b reports the empty plan.
      plan = {};
    }
    note(/pep-lb:/.test(memberCompose) &&
         /127\.0\.0\.1:\d+:9543/.test(memberCompose) &&
         /"\.:\/certs:ro"/.test(memberCompose) &&
         !/9444:9443/.test(memberCompose) &&
         !/network_mode/.test(memberCompose) &&
         !/^  sts:/m.test(memberCompose) &&
         /external: true/.test(sharedCompose) &&
         /"\.\/[^"]+:\/certs:ro"/.test(sharedCompose) &&
         /iya-sts_default/.test(sharedCompose) &&
         /haproxy:3\.2\.23-alpine/.test(sharedCompose) &&
         /\n  companion:\n/.test(sharedCompose) &&
         /iya-sts-companion/.test(sharedCompose) &&
         // #1972: the companion publishes no host port (its route trusts
         // identity headers) and never turns TLS verification off; with a
         // CA the anchor is mounted beside the variable that names it.
         !/COMPANION_HOST_PORT|:9700:9700/.test(sharedCompose) &&
         !/COMPANION_STS_TLS_INSECURE/.test(sharedCompose) &&
         (!/COMPANION_STS_CA_FILE/.test(sharedCompose) ||
          /pep-cluster-service-ca\.pem:\/certs\/service-ca\.pem:ro/
            .test(sharedCompose)) &&
         /COMPANION_KRB5_SERVICE_PORT: "off"/.test(sharedCompose) &&
         !/^  sts:/m.test(sharedCompose) &&
         /balance source/.test(haproxy) &&
         /bind :9443/.test(haproxy) &&
         haproxy.indexOf('server ' + NAME + ' ' + NAME + ':9543') >= 0 &&
         plan.hostPort > 0 && plan.members &&
         plan.members[NAME] === pathc.resolve(OUTDIR) &&
         !fsc.existsSync(reachFile) &&
         /docker compose -f /.test(first.out) &&
         first.out.indexOf('docker-compose.pep-cluster.yml') >= 0 &&
         first.out.indexOf('-p 9444:9443') < 0 &&
         /9\. The containers: not started/.test(first.out) &&
         /8\. The \/pep-app path:/.test(first.out),
         'R6b. the cluster compose is the members, one load balancer on ' +
         '127.0.0.1 and the companion, and /pep-app is registered',
         memberCompose + '\n' + sharedCompose + '\n' + haproxy);
    const clusters = await get('/xacml/pep-clusters');
    const cluster = ((clusters.json && clusters.json.clusters) || [])
      .filter(function (one) { return one.name === CLUSTER; })[0];
    note(!!cluster && (cluster.members || []).some(function (one) {
      return one.pep === NAME;
    }), 'R7. the cluster was created and it is a member',
         JSON.stringify(cluster && cluster.members));
    note(/6\. The HTTPS listener pair: WAITING/.test(first.out),
         'R8. the listener pair waits for the PEP to register', said(first));

    // ---------------------------------------------------------------------
    // I. THE SAME COMMAND AGAIN.
    // ---------------------------------------------------------------------
    const again = await tool(full, ENV);
    const entryAgain = await entryOf(NAME);
    note(again.code === 0 &&
         /1\. The entry [^:]*: exists; skipped/.test(again.out) &&
         /2\. Membership of remote-peps: already a member; skipped/
           .test(again.out) &&
         /3\. Service account: yes/.test(again.out) &&
         /4\. The assertion key: .*registered and valid .*skipped/
           .test(again.out) &&
         /5\. Cluster [^:]*: already a member; skipped/.test(again.out),
         'I1. a second run skips every step', said(again));
    note(entryAgain.keys.length === entry.keys.length &&
         fsc.readFileSync(keyFile, 'utf8') === keyPem,
         'I2. and certifies nothing more: the same key, on file and on ' +
         'the entry', entryAgain.keys.length + ' key(s)');

    // ---------------------------------------------------------------------
    // K. THE KEY WORKS, AND THE LISTENER PAIR FOLLOWS A REGISTRATION.
    // ---------------------------------------------------------------------
    const pepToken = await credentials.pepAccessToken(BASE, NAME, keyPem,
                                                      'xacml:pep',
                                                      '/xacml/pep');
    note(pepToken.status === 200 && !!pepToken.token,
         'K1. the key in --out signs the PEP\'s grant for xacml:pep',
         pepToken.status + ' ' + String(pepToken.text).slice(0, 300));
    const registerUrl = BASE + '/xacml/pep/register';
    const registered = await fetch(registerUrl, { method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' },
        credentials.dpopHeaders(keyPem, 'POST', registerUrl,
                                pepToken.token)),
      body: JSON.stringify({ name: NAME, version: 'test' }) });
    note(registered.status === 200 || registered.status === 201,
         'K2. the PEP registers on that token', String(registered.status));
    const third = await tool(full.concat(['--https-dns=pep.example.test']),
                             ENV);
    const serverCrt = pathc.join(OUTDIR, 'server', 'pep-server.crt');
    const serverKey = pathc.join(OUTDIR, 'server', 'pep-server.key');
    let names = '';
    try {
      names = new (require('crypto').X509Certificate)(
        fsc.readFileSync(serverCrt, 'utf8')).subjectAltName;
    } catch (e) {
      // No pair in --out: K3 reports the empty names.
      names = '';
    }
    note(third.code === 0 &&
         /6\. The HTTPS listener pair: issued/.test(third.out) &&
         /pep\.example\.test/.test(names) &&
         (fsc.statSync(serverKey).mode & 0o777) === 0o600,
         'K3. once it has registered, a run issues the listener pair ' +
         'naming --https-dns, its key 0600', said(third) + ' ' + names);
    const fourth = await tool(full, ENV);
    note(fourth.code === 0 &&
         /6\. The HTTPS listener pair: already in/.test(fourth.out),
         'K4. and the next run skips it', said(fourth));

    // ---------------------------------------------------------------------
    // C. A SECOND MEMBER, AND A LOCALHOST PDP URL.
    // ---------------------------------------------------------------------
    const OUT2 = pathc.join(parent, 'out2');
    const NAME2 = 'rrp-pep2-' + stamp;
    const second = await tool(common(NAME2, OUT2).concat([
      '--cluster=' + CLUSTER, '--pdp-url=https://sts:8081']), ENV);
    const haproxy2 = fsc.existsSync(haproxyFile)
      ? fsc.readFileSync(haproxyFile, 'utf8') : '';
    const secondCompose = fsc.existsSync(
      pathc.join(OUT2, 'docker-compose.pep.yml'))
      ? fsc.readFileSync(pathc.join(OUT2, 'docker-compose.pep.yml'), 'utf8')
      : '';
    let plan2 = {};
    try {
      plan2 = JSON.parse(fsc.readFileSync(planFile, 'utf8'));
    } catch (e) {
      // C1 reports the empty plan.
      plan2 = {};
    }
    note(second.code === 0 &&
         haproxy2.indexOf('server ' + NAME + ' ' + NAME + ':9543') >= 0 &&
         haproxy2.indexOf('server ' + NAME2 + ' ' + NAME2 + ':9543') >= 0 &&
         plan2.members && !!plan2.members[NAME2] &&
         /127\.0\.0\.1:/.test(secondCompose) &&
         !/9444:9443/.test(secondCompose) &&
         !fsc.existsSync(reachFile),
         'C1. a second member joins the same load balancer, and a sts ' +
         'PDP URL writes no reach script', said(second));
    const OUT3 = pathc.join(parent, 'out3');
    const NAME3 = 'rrp-loc-' + stamp;
    const local = await tool(common(NAME3, OUT3).concat([
      '--cluster=' + CLUSTER, '--pdp-url=https://localhost:8081']), ENV);
    const reach = fsc.existsSync(reachFile)
      ? fsc.readFileSync(reachFile, 'utf8') : '';
    const composed = fsc.existsSync(clusterYml)
      ? fsc.readFileSync(clusterYml, 'utf8') : '';
    const reachHits = (composed.match(/pep-reach-sts\.sh/g) || []).length;
    note(local.code === 0 &&
         /getent ahostsv4 sts/.test(reach) &&
         /grep -v localhost/.test(reach) &&
         /exec xacml-pep/.test(reach) &&
         reachHits === 2 &&
         composed.indexOf('network_mode') < 0 &&
         /points that name at the sts container/.test(local.out) &&
         local.out.indexOf('Pass --pdp-url') < 0,
         'C2. a localhost PDP URL points that name at the sts container',
         reach + '\n' + said(local));

    // ---------------------------------------------------------------------
    // P. ONE PATH ON THE CLUSTER, PROTECTED BY ONE ROLE.
    // ---------------------------------------------------------------------
    const fieldValues = function (entry, attribute) {
      const fields = (entry && (entry.attributes || entry.fields)) || {};
      const held = fields[attribute];
      if (held === undefined || held === null || held === '') {
        return [];
      }
      return Array.isArray(held) ? held.map(String) : [String(held)];
    };
    const P_APP = 'pep-app';
    const P_ROLE = 'pep-app';
    const P_BASE = 'https://localhost:9543';
    const P_CALLBACK = P_BASE + '/.iya-pep/callback';
    const pName = 'rrp-p-' + stamp;
    const pCluster = 'rrp-pc-' + stamp;
    const pOut = outDir('p');
    const pArgs = common(pName, pOut).concat(['--cluster=' + pCluster,
      '--create-cluster', '--pep-app']);
    const pDry = await tool(pArgs.concat(['--dry-run']), ENV);
    note(pDry.code === 0 && /8\. The \/pep-app path:/.test(pDry.out) &&
         !fsc.existsSync(pOut),
         'P1. --dry-run --pep-app writes no files', said(pDry));
    const pFirst = await tool(pArgs, ENV);
    const secret = ((first.out.match(/shown once\): (\S+)/) || [])[1]) || '';
    note(pFirst.code === 0 &&
         /8\. The \/pep-app path:/.test(pFirst.out) &&
         pFirst.out.indexOf('shown once') < 0 &&
         secret.length >= 16 &&
         (pFirst.out + pFirst.err).indexOf('PRIVATE KEY') < 0 &&
         (pFirst.out + pFirst.err).indexOf(secret) < 0,
         'P2. this cluster gets /pep-app, and the secret is not printed ' +
         'again', said(pFirst));
    const application = await get('/applications?application=' + P_APP);
    const redirects = fieldValues(application.json, 'oauthRedirectUri');
    const grants = fieldValues(application.json, 'oauthGrantType');
    const methods = fieldValues(application.json,
                                'oauthTokenEndpointAuthMethod');
    note(application.json && application.json.found &&
         redirects.indexOf(P_CALLBACK) >= 0 &&
         grants.indexOf('authorization_code') >= 0 &&
         methods.indexOf('client_secret_basic') >= 0 &&
         methods.indexOf('client_secret_post') >= 0,
         'P3. the application is a confidential client of the proxy callback',
         JSON.stringify({ redirects: redirects, grants: grants,
                          methods: methods }));
    const role = await get('/roles?role=' + encodeURIComponent(P_ROLE));
    note(role.json && role.json.role && role.json.role.found === true &&
         role.json.role.name === P_ROLE,
         'P4. the one role exists',
         JSON.stringify(role.json && role.json.role));
    const held = await get('/xacml/pep-clusters?cluster=' +
                           encodeURIComponent(pCluster));
    const pClusterRow = ((held.json && held.json.clusters) || [])
      .filter(function (one) { return one.name === pCluster; })[0];
    const pRoute = pClusterRow && pClusterRow.proxy &&
      (pClusterRow.proxy.routes || []).filter(function (one) {
        return one.path === '/pep-app';
      })[0];
    const pRoles = pRoute && pRoute.authorization &&
      pRoute.authorization.roles;
    note(!!pRoute && pRoute.application === P_APP &&
         (pRoute.mechanisms || []).indexOf('session') >= 0 &&
         (pRoute.methods || []).indexOf('POST') >= 0 &&
         pRoles && pRoles.read && pRoles.read.length === 1 &&
         pRoles.read[0] === P_ROLE &&
         pRoles.write && pRoles.write.length === 1 &&
         pRoles.write[0] === P_ROLE &&
         pClusterRow.proxy.publicBaseUrl === P_BASE &&
         pClusterRow.proxy.upstream === 'http://companion:9700',
         'P5. one prefix, one role on read and write',
         JSON.stringify(pRoute && {
           path: pRoute.path, application: pRoute.application,
           methods: pRoute.methods, roles: pRoles,
           base: pClusterRow.proxy.publicBaseUrl,
           upstream: pClusterRow.proxy.upstream }));
    const pAgain = await tool(pArgs, ENV);
    note(pAgain.code === 0 &&
         /8\. The \/pep-app path:.*skipped/.test(pAgain.out) &&
         pAgain.out.indexOf('shown once') < 0 &&
         pAgain.out.indexOf(secret) < 0,
         'P6. a second run skips the path and does not print the secret',
         said(pAgain));
    const pComposePath = pathc.join(pOut, 'docker-compose.pep.yml');
    const pCompose = fsc.existsSync(pComposePath)
      ? fsc.readFileSync(pComposePath, 'utf8') : '';
    note(/127\.0\.0\.1:9543:9543/.test(pCompose) &&
         !/9444:9443/.test(pCompose) &&
         !/network_mode/.test(pCompose) &&
         !fsc.existsSync(pathc.join(pathc.dirname(pOut),
           'pep-cluster-reach-sts.sh')) &&
         /inside a container is the container itself/.test(pFirst.out),
         'P7. --pep-app on a free 9543 publishes only that load balancer, ' +
         'and 127.0.0.1 is not rewritten', pCompose);

    dirs.forEach(function (dir) {
      fsc.rmSync(dir, { recursive: true, force: true });
    });
    server.close();
    fsc.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'rrp-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  RRP_ROOT: ROOT, RRP_OUT: out }),
      encoding: 'utf8', timeout: 600000, cwd: ROOT
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
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'register_remote_pep',
  describe: 'utilities/register-remote-pep.js registers a new remote PEP ' +
            'end to end (entry, remote-peps, service account, a key ' +
            'certified from its own request, cluster, listener pair, the ' +
            'environment; a cluster compose is the members plus one load ' +
            'balancer on 127.0.0.1), and with --pep-app one session path ' +
            'protected by a single role, idempotently; it refuses a bad ' +
            'token and a realm with no owner clearly, and --dry-run ' +
            'changes nothing',
  run: run
};
