'use strict';
//
// File: deploy/aws/reset-environment.js
//
// ---------------------------------------------------------------------------
// PUTS A REUSED AWS ENVIRONMENT BACK BEFORE A SUITE RUN (issue #51): removes
// every trust realm but the default one, and clears every runtime override in
// the default realm.
//
//   STS_ADMIN_API_TOKEN=… node deploy/aws/reset-environment.js https://<nlb>
//
// Called by deploy/aws/runner/run-in-task.sh and deploy/aws/run-suite.sh, so an
// AWS environment can be REUSED run after run — creating one takes most of half
// an hour. The suite leaves every realm it creates standing on purpose
// (tests/CLAUDE.md, *No job removes a realm*): a realm is the record a person
// reads when a run went red. That is right for one run and wrong for the next
// on a long-lived cluster, where the previous run's realms are state the new
// run did not make — a fixed realm id such as the remote PEP's meets "already
// defined", and every realm is more for each node to replicate and hold keys
// for. So the record is kept until the next run starts, and cleared then.
//
// THE DEFAULT REALM'S RUNTIME OVERRIDES GO TOO, through `/admin-api/config/reset`.
// tests/vendored/admin_api.js requires none to be in force when it starts, and
// the store keeps them across a restart: the first reuse of the dev cluster
// found `groups.claim` from an interrupted run and `ldap.maxEntries`, which the
// bulk-load jobs raise and leave raised on purpose (tests/vendored/bulk_load.js).
// Resetting that one is safe HERE only because the nodes are started with
// LDAP_MAX_ENTRIES well above what the bulk loads leave in the directory
// (environment/ecs.tf), so the reset lands on the environment's value rather
// than the 2000 default that would refuse every later create.
//
// What it does NOT clear is the default realm's own CONTENTS (people,
// applications a run wrote there): a job that writes into the default realm
// names what it writes for the run, and `POST /admin-api/realms/remove` refuses
// the default realm by design. `STS_SUITE_KEEP_REALMS=1` skips all of this.
//
// Through `/admin-api/realms` and `/admin-api/realms/remove` with the run's
// admin token (admin:write), one realm at a time: a removal purges every store
// the realm holds and replicates to every node, and a cluster asked for three
// dozen at once answers slower than one asked in turn. TLS is not verified:
// the cluster's Root is issued by the cluster, and this asks the service to
// act, it trusts nothing the service says.
//
// Its `log` is console-backed and bunyan-shaped, the arrangement the root
// CLAUDE.md names for a tool outside the service.
// ---------------------------------------------------------------------------
const https = require('https');

const log = {
  debug: function (message) {
    if (process.env.LOG_LEVEL === 'debug') {
      process.stderr.write(message + '\n');
    }
  }
};

function request(method, url, token, body) {
  log.debug('Entering request(). ' + method + ' ' + url);
  const payload = body ? JSON.stringify(body) : null;
  log.debug('Leaving request().');
  return new Promise(function (resolve, reject) {
    const req = https.request(url, {
      method: method,
      rejectUnauthorized: false,
      timeout: 120000,
      headers: Object.assign({ Authorization: 'Bearer ' + token },
        payload ? { 'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(payload) } : {})
    }, function (res) {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', function (chunk) { text += chunk; });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug('Caught in request(): ' + ((e && e.message) || e));
        }
        resolve({ status: res.statusCode, json: json, text: text });
      });
    });
    req.on('timeout', function () {
      req.destroy(new Error('timed out after 120s'));
    });
    req.on('error', reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

async function main() {
  log.debug('Entering main().');
  const base = String(process.argv[2] || '').replace(/\/+$/, '');
  const token = process.env.STS_ADMIN_API_TOKEN || '';
  if (!base || !token) {
    log.debug('Leaving main().');
    throw new Error('usage: STS_ADMIN_API_TOKEN=… reset-environment.js <url>');
  }
  if (process.env.STS_SUITE_KEEP_REALMS === '1') {
    process.stdout.write('reset-environment: STS_SUITE_KEEP_REALMS=1, ' +
                         'leaving every realm in place.\n');
    log.debug('Leaving main(). Kept.');
    return;
  }
  const list = await request('GET', base + '/admin-api/realms', token);
  if (list.status !== 200 || !list.json || !Array.isArray(list.json.realms)) {
    log.debug('Leaving main().');
    throw new Error('GET /admin-api/realms answered ' + list.status + ': ' +
                    list.text.slice(0, 300));
  }
  const ids = list.json.realms
    .map(function (r) { return r.id; })
    .filter(function (id) { return id && id !== 'default'; });
  process.stdout.write('reset-environment: ' + ids.length + ' realm(s) besides ' +
                       'the default one.\n');
  let removed = 0;
  const failed = [];
  for (const id of ids) {
    const r = await request('POST', base + '/admin-api/realms/remove', token,
                            { id: id });
    if (r.status === 200) {
      removed += 1;
    } else {
      failed.push(id + ' (' + r.status + ': ' +
                  r.text.replace(/\s+/g, ' ').slice(0, 160) + ')');
    }
  }
  process.stdout.write('reset-environment: removed ' + removed + ' of ' +
                       ids.length + '.\n');
  const config = await request('GET', base + '/admin-api/config', token);
  if (config.status !== 200 || !config.json ||
      !Array.isArray(config.json.overridden)) {
    log.debug('Leaving main().');
    throw new Error('GET /admin-api/config answered ' + config.status + ': ' +
                    config.text.slice(0, 300));
  }
  const keys = config.json.overridden;
  let reset = 0;
  for (const key of keys) {
    const r = await request('POST', base + '/admin-api/config/reset', token,
                            { key: key });
    if (r.status === 200) {
      reset += 1;
    } else {
      failed.push(key + ' (' + r.status + ': ' +
                  r.text.replace(/\s+/g, ' ').slice(0, 160) + ')');
    }
  }
  process.stdout.write('reset-environment: reset ' + reset + ' of ' +
                       keys.length + ' runtime override(s)' +
                       (keys.length ? ' (' + keys.join(', ') + ')' : '') +
                       '.\n');
  if (failed.length) {
    process.stderr.write('reset-environment: not reset: ' + failed.join('; ') +
                         '\n');
    log.debug('Leaving main().');
    throw new Error(failed.length + ' realm(s) or setting(s) could not be ' +
                    'reset');
  }
  log.debug('Leaving main().');
}

main().catch(function (e) {
  process.stderr.write('reset-environment: ' + ((e && e.message) || e) + '\n');
  process.exit(1);
});
