// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: deploy/aws/reset-environment.js
//
// ---------------------------------------------------------------------------
// PUTS A REUSED AWS ENVIRONMENT BACK BEFORE A SUITE RUN (issue #51, #344):
// removes every trust realm but the default one, removes what earlier suite
// runs left in the default realm — the bulk-load people and groups and the
// applications the jobs registered — and clears every runtime override in the
// default realm.
//
//   STS_ADMIN_API_TOKEN=… STS_ADMIN_API_CLIENT_SECRET=… \
//     node deploy/aws/reset-environment.js [--dry-run] https://<nlb>
//
// `--dry-run` lists what would go and changes nothing.
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
// THE DEFAULT REALM'S LEFTOVERS GO TOO SINCE 2026-09-29 (#344). Every node
// process holds the whole directory and the application registry in memory,
// so what a run leaves there is resident until the environment is destroyed:
// about 15,000 bulk-load entries a run, and a few hundred applications. On
// testidp that held the idle floor at 76–87 % of 8 GiB and took a restart
// past the task's memory limit (#339). The run is removed by NAME, and only
// by the suite's own names:
//
//   * people and groups whose name is a bulk-load job's — `bulk-<door>-…`,
//     `<door>` one of the four `tests/vendored/bulk_load.js`'s `stampFor()` is
//     given (`scim`, `ldap`, `ldap50k`, `api`). Found and deleted through SCIM
//     (`/scim/v2`), which is this service's door for deleting a person or a
//     group: `/admin-api` has none. The token is the seeded
//     `sts-management-api` client's with `scim:read scim:write`, minted the
//     way the SCIM bulk-load job mints it (tests/tools/admin-api-token.js).
//     Groups first, so no deleted person is left dangling in a group that is
//     about to go anyway. In SCIM Bulk requests of the service's advertised
//     `bulk.maxOperations`, a bounded number at a time
//     (`STS_RESET_CONCURRENCY`, default 2, at most 8), with progress on
//     stdout.
//   * applications `isSuiteApplication()` recognises, through
//     `POST /admin-api/applications/forget`. Never one this service seeded
//     (`registeredBy: startup`), never one that merely turned up.
//
// Nothing an operator made goes, because an operator does not name a person
// `bulk-scim-<run>-000001` — and the default realm itself, its bootstrap
// administrator (not a bulk name) and its seeded applications are never
// candidates. `--dry-run` is how to check that before trusting it.
//
// THE DEFAULT REALM'S RUNTIME OVERRIDES GO LAST, through
// `/admin-api/config/reset`. tests/vendored/admin_api.js requires none to be
// in force when it starts, and the store keeps them across a restart: the
// first reuse of the dev cluster found `groups.claim` from an interrupted run
// and `ldap.maxEntries`, which the bulk-load jobs raise and leave raised on
// purpose (tests/vendored/bulk_load.js). Resetting that one lands on the
// nodes' LDAP_MAX_ENTRIES (`ldap_max_entries`, environment/ecs.tf), and is
// done AFTER the bulk entries are gone so the directory is back under it.
//
// `STS_SUITE_KEEP_REALMS=1` skips all of this.
//
// Through `/admin-api/realms` and `/admin-api/realms/remove` with the run's
// admin token (admin:write), one realm at a time: a removal purges every store
// the realm holds and replicates to every node, and a cluster asked for three
// dozen at once answers slower than one asked in turn. TLS is not verified:
// the cluster's Root is issued by the cluster, and this asks the service to
// act, it trusts nothing the service says.
//
// Its `log` is console-backed and bunyan-shaped, the arrangement the root
// CLAUDE.md names for a tool outside the service. Required as a module it runs
// nothing and exports the name tests `tests/reset_environment.js` holds.
// ---------------------------------------------------------------------------
const https = require('https');

const log = {
  debug: function (message) {
    if (process.env.LOG_LEVEL === 'debug') {
      process.stderr.write(message + '\n');
    }
  }
};

// The doors `tests/vendored/bulk_load.js`'s `stampFor()` is called with —
// `ldap50k` is `sts_directory_bulk_load_ldap_50k.js`'s BULK_DOOR. A door added
// there has to be added here, or its entries accumulate again.
const BULK_DOORS = ['scim', 'ldap', 'ldap50k', 'api'];

// `bulk-<door>-<run>-NNNNNN` for a person, `bulk-<door>-binder-<run>` for the
// LDAP job's bind identity; `bulk-<door>-<run>-grp-NNN` for a group. The run
// stamp is lower-case alphanumerics (random_username.js's `runStamp()`, or a
// pinned RANDOM_USERNAME_STAMP folded the same way).
const PERSON_PATTERN = new RegExp('^bulk-(' + BULK_DOORS.join('|') +
                                  ')-[a-z0-9][a-z0-9-]*$');
const GROUP_PATTERN = new RegExp('^bulk-(' + BULK_DOORS.join('|') +
                                 ')-[a-z0-9-]+-grp-[0-9]+$');

/**
 * Tells whether a person's user name is one a bulk-load job made.
 *
 * @param {string} userName - the SCIM userName (the entry's uid)
 * @returns {boolean} true for a suite bulk-load person
 */
function isSuitePerson(userName) {
  log.debug('Entering isSuitePerson().');
  const answer = PERSON_PATTERN.test(String(userName || '')) &&
                 !GROUP_PATTERN.test(String(userName || ''));
  log.debug('Leaving isSuitePerson().');
  return answer;
}

/**
 * Tells whether a group's name is one a bulk-load job made.
 *
 * @param {string} displayName - the SCIM displayName (the entry's cn)
 * @returns {boolean} true for a suite bulk-load group
 */
function isSuiteGroup(displayName) {
  log.debug('Entering isSuiteGroup().');
  const answer = GROUP_PATTERN.test(String(displayName || ''));
  log.debug('Leaving isSuiteGroup().');
  return answer;
}

// APPLICATIONS THE SUITE REGISTERS IN THE DEFAULT REALM. A job registering
// into a realm it created is not here: that application goes with the realm.
const APPLICATION_PATTERNS = [];

/**
 * Tells whether an application row from `GET /admin-api/applications` is one
 * a suite run registered in the default realm.
 *
 * @param {object} row - the row: `identifier`, `registeredBy`, `name`
 * @returns {boolean} true for a suite application
 */
function isSuiteApplication(row) {
  log.debug('Entering isSuiteApplication().');
  const identifier = String((row && row.identifier) || '');
  const by = String((row && row.registeredBy) || '');
  // Seeded by this service at startup, or never registered at all (it turned
  // up in development mode): neither is the suite's to remove.
  if (!identifier || by === 'startup' || !by) {
    log.debug('Leaving isSuiteApplication(). Not a registration.');
    return false;
  }
  const answer = APPLICATION_PATTERNS.some(function (pattern) {
    return pattern.test(identifier);
  });
  log.debug('Leaving isSuiteApplication(). ' + answer);
  return answer;
}

function request(method, url, token, body, contentType) {
  log.debug('Entering request(). ' + method + ' ' + url);
  const payload = body ? JSON.stringify(body) : null;
  log.debug('Leaving request().');
  return new Promise(function (resolve, reject) {
    const req = https.request(url, {
      method: method,
      rejectUnauthorized: false,
      timeout: 120000,
      headers: Object.assign({ Authorization: 'Bearer ' + token },
        payload ? { 'Content-Type': contentType || 'application/json',
                    'Content-Length': Buffer.byteLength(payload) } : {})
    }, function (res) {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', function (chunk) {
        text += chunk;
      });
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

function say(line) {
  log.debug('Entering say().');
  process.stdout.write('reset-environment: ' + line + '\n');
  log.debug('Leaving say().');
}

function brief(r) {
  log.debug('Entering brief().');
  log.debug('Leaving brief().');
  return r.status + ': ' + String(r.text || '').replace(/\s+/g, ' ')
    .slice(0, 160);
}

// Runs `work` over `items` with at most `limit` in flight, in order of start.
async function eachBounded(items, limit, work) {
  log.debug('Entering eachBounded(). ' + items.length + ' item(s).');
  let next = 0;
  async function lane() {
    log.debug('Entering lane().');
    while (next < items.length) {
      const index = next;
      next += 1;
      await work(items[index], index);
    }
    log.debug('Leaving lane().');
  }
  const lanes = [];
  for (let i = 0; i < Math.max(1, Math.min(limit, items.length)); i += 1) {
    lanes.push(lane());
  }
  await Promise.all(lanes);
  log.debug('Leaving eachBounded().');
}

function concurrency() {
  log.debug('Entering concurrency().');
  const asked = parseInt(String(process.env.STS_RESET_CONCURRENCY || ''), 10);
  log.debug('Leaving concurrency().');
  return isFinite(asked) && asked > 0 ? Math.min(asked, 8) : 2;
}

// ---------------------------------------------------------------------------
// THE REALMS.
// ---------------------------------------------------------------------------
async function resetRealms(base, token, dryRun, failed) {
  log.debug('Entering resetRealms().');
  const list = await request('GET', base + '/admin-api/realms', token);
  if (list.status !== 200 || !list.json || !Array.isArray(list.json.realms)) {
    log.debug('Leaving resetRealms().');
    throw new Error('GET /admin-api/realms answered ' + list.status + ': ' +
                    list.text.slice(0, 300));
  }
  const ids = list.json.realms
    .map(function (r) {
      return r.id;
    })
    .filter(function (id) {
      return id && id !== 'default';
    });
  say(ids.length + ' realm(s) besides the default one' +
      (dryRun && ids.length ? ': ' + ids.join(', ') : '') + '.');
  if (dryRun) {
    log.debug('Leaving resetRealms(). Dry run.');
    return;
  }
  let removed = 0;
  for (const id of ids) {
    const r = await request('POST', base + '/admin-api/realms/remove', token,
                            { id: id });
    if (r.status === 200) {
      removed += 1;
    } else {
      failed.push('realm ' + id + ' (' + brief(r) + ')');
    }
  }
  say('removed ' + removed + ' of ' + ids.length + ' realm(s).');
  log.debug('Leaving resetRealms().');
}

// ---------------------------------------------------------------------------
// THE BULK-LOAD PEOPLE AND GROUPS, THROUGH SCIM.
// ---------------------------------------------------------------------------

// A token for /scim/v2: the seeded client, with the two SCIM scopes declared
// on it first (idempotent, and what the SCIM bulk-load job does every run) —
// except in a dry run, which writes nothing and relies on an earlier run
// having declared them.
async function scimToken(base, token, dryRun) {
  log.debug('Entering scimToken().');
  if (!dryRun) {
    for (const scope of ['scim:read', 'scim:write']) {
      const r = await request('POST', base + '/admin-api/applications/add',
                              token, { application: 'sts-management-api',
                                       attribute: 'oauthAllowedScope',
                                       value: scope });
      if (r.status !== 200 && !/already/i.test(r.text)) {
        log.debug('Leaving scimToken().');
        throw new Error('declaring ' + scope + ' on sts-management-api ' +
                        'answered ' + brief(r));
      }
    }
  }
  // Loaded here rather than at the top: it needs the tests' bunyan, which a
  // caller requiring this file only for its name tests may not have.
  const minted = require('../../tests/tools/admin-api-token.js');
  const scim = await minted.tokenFor(base, {
    scope: 'scim:read scim:write',
    audience: base + '/resource'
  });
  log.debug('Leaving scimToken().');
  return scim;
}

// Every resource of `type` whose `attribute` starts `bulk-`, as
// `{ id, name }`, paged at the service's own maximum (`scim.maxResults`
// clamps the count asked for). The filter narrows what comes back; `wanted`
// decides.
async function scimList(base, scim, type, attribute, wanted) {
  log.debug('Entering scimList(). ' + type);
  const found = [];
  let start = 1;
  let total = Infinity;
  let pages = 0;
  while (start <= total) {
    const url = base + '/scim/v2/' + type + '?filter=' +
      encodeURIComponent(attribute + ' sw "bulk-"') +
      '&attributes=' + attribute + '&count=1000&startIndex=' + start;
    const r = await request('GET', url, scim);
    if (r.status !== 200 || !r.json || !Array.isArray(r.json.Resources)) {
      log.debug('Leaving scimList().');
      throw new Error('GET /scim/v2/' + type + ' answered ' + brief(r));
    }
    total = Number(r.json.totalResults) || 0;
    const rows = r.json.Resources;
    if (!rows.length) {
      break;
    }
    rows.forEach(function (row) {
      const name = String(row[attribute] || '');
      if (row.id && wanted(name)) {
        found.push({ id: String(row.id), name: name });
      }
    });
    start += rows.length;
    pages += 1;
    if (pages % 20 === 0) {
      say('listed ' + (start - 1) + ' of ' + total + ' ' + type + '...');
    }
  }
  log.debug('Leaving scimList(). ' + found.length + ' found.');
  return found;
}

// The advertised Bulk limit, so a batch is never refused for its size; 0 when
// the service offers no Bulk, and each resource is then deleted on its own.
async function bulkLimit(base, scim) {
  log.debug('Entering bulkLimit().');
  const r = await request('GET', base + '/scim/v2/ServiceProviderConfig', scim);
  const bulk = (r.json && r.json.bulk) || {};
  const most = Number(bulk.maxOperations) || 0;
  if (r.status !== 200 || !bulk.supported || most < 1) {
    log.debug('Leaving bulkLimit(). No bulk.');
    return 0;
  }
  log.debug('Leaving bulkLimit(). ' + most);
  return Math.min(most, 1000);
}

// Deletes `rows` of `type`, in Bulk requests when the service offers them and
// one DELETE at a time otherwise. A 404 is somebody else having got there
// first, which is the outcome wanted.
async function scimDelete(base, scim, type, rows, perBatch, failed) {
  log.debug('Entering scimDelete(). ' + rows.length + ' ' + type + '.');
  const batches = [];
  const size = perBatch || 1;
  for (let i = 0; i < rows.length; i += size) {
    batches.push(rows.slice(i, i + size));
  }
  let done = 0;
  let deleted = 0;
  let lastReport = 0;
  await eachBounded(batches, concurrency(), async function (batch) {
    log.debug('Entering the ' + type + ' delete batch.');
    if (perBatch) {
      const body = {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
        Operations: batch.map(function (row) {
          return { method: 'DELETE', path: '/' + type + '/' + row.id };
        })
      };
      const r = await request('POST', base + '/scim/v2/Bulk', scim, body,
                              'application/scim+json');
      if (r.status !== 200 || !r.json || !Array.isArray(r.json.Operations)) {
        failed.push(type + ' bulk of ' + batch.length + ' (' + brief(r) + ')');
      } else {
        r.json.Operations.forEach(function (op, index) {
          const status = parseInt(String(op.status || ''), 10);
          if (status === 204 || status === 200 || status === 404) {
            deleted += 1;
          } else {
            failed.push(type + ' ' + (batch[index] || {}).name + ' (' +
                        status + ': ' + JSON.stringify(op.response || '')
                          .slice(0, 160) + ')');
          }
        });
      }
    } else {
      for (const row of batch) {
        const r = await request('DELETE', base + '/scim/v2/' + type + '/' +
                                encodeURIComponent(row.id), scim);
        if (r.status === 204 || r.status === 200 || r.status === 404) {
          deleted += 1;
        } else {
          failed.push(type + ' ' + row.name + ' (' + brief(r) + ')');
        }
      }
    }
    done += batch.length;
    if (done - lastReport >= 1000 || done === rows.length) {
      lastReport = done;
      say('deleted ' + deleted + ' of ' + rows.length + ' ' + type +
          ' (' + done + ' asked).');
    }
    log.debug('Leaving the ' + type + ' delete batch.');
  });
  log.debug('Leaving scimDelete(). ' + deleted + ' deleted.');
  return deleted;
}

async function resetDirectory(base, token, dryRun, failed) {
  log.debug('Entering resetDirectory().');
  const scim = await scimToken(base, token, dryRun);
  const groups = await scimList(base, scim, 'Groups', 'displayName',
                                isSuiteGroup);
  const people = await scimList(base, scim, 'Users', 'userName',
                                isSuitePerson);
  say(groups.length + ' bulk-load group(s) and ' + people.length +
      ' bulk-load person/people in the default realm.');
  if (dryRun) {
    const sample = function (rows) {
      return rows.slice(0, 5).map(function (row) {
        return row.name;
      }).join(', ') + (rows.length > 5 ? ', …' : '');
    };
    if (groups.length) {
      say('  groups, e.g. ' + sample(groups));
    }
    if (people.length) {
      say('  people, e.g. ' + sample(people));
    }
    log.debug('Leaving resetDirectory(). Dry run.');
    return;
  }
  const perBatch = await bulkLimit(base, scim);
  const started = Date.now();
  await scimDelete(base, scim, 'Groups', groups, perBatch, failed);
  await scimDelete(base, scim, 'Users', people, perBatch, failed);
  say('the directory took ' + Math.round((Date.now() - started) / 1000) +
      's.');
  log.debug('Leaving resetDirectory().');
}

// ---------------------------------------------------------------------------
// THE APPLICATIONS.
// ---------------------------------------------------------------------------
async function resetApplications(base, token, dryRun, failed) {
  log.debug('Entering resetApplications().');
  const found = [];
  let page = 1;
  let pages = 1;
  while (page <= pages) {
    const r = await request('GET', base + '/admin-api/applications?per=300' +
                            '&page=' + page, token);
    if (r.status !== 200 || !r.json || !Array.isArray(r.json.applications)) {
      log.debug('Leaving resetApplications().');
      throw new Error('GET /admin-api/applications answered ' + brief(r));
    }
    pages = Number(r.json.pages) || 1;
    r.json.applications.forEach(function (row) {
      if (isSuiteApplication(row)) {
        found.push(String(row.identifier));
      }
    });
    page += 1;
  }
  say(found.length + ' suite application(s) in the default realm' +
      (dryRun && found.length ? ': ' + found.slice(0, 20).join(', ') +
       (found.length > 20 ? ', …' : '') : '') + '.');
  if (dryRun) {
    log.debug('Leaving resetApplications(). Dry run.');
    return;
  }
  let removed = 0;
  await eachBounded(found, concurrency(), async function (identifier) {
    log.debug('Entering the application delete.');
    const r = await request('POST', base + '/admin-api/applications/forget',
                            token, { identifier: identifier });
    if (r.status === 200) {
      removed += 1;
    } else if (!/no application called/i.test(r.text)) {
      failed.push('application ' + identifier + ' (' + brief(r) + ')');
    }
    log.debug('Leaving the application delete.');
  });
  say('removed ' + removed + ' of ' + found.length + ' application(s).');
  log.debug('Leaving resetApplications().');
}

// ---------------------------------------------------------------------------
// THE RUNTIME OVERRIDES.
// ---------------------------------------------------------------------------
async function resetOverrides(base, token, dryRun, failed) {
  log.debug('Entering resetOverrides().');
  const config = await request('GET', base + '/admin-api/config', token);
  if (config.status !== 200 || !config.json ||
      !Array.isArray(config.json.overridden)) {
    log.debug('Leaving resetOverrides().');
    throw new Error('GET /admin-api/config answered ' + config.status + ': ' +
                    config.text.slice(0, 300));
  }
  const keys = config.json.overridden;
  if (dryRun) {
    say(keys.length + ' runtime override(s)' +
        (keys.length ? ' (' + keys.join(', ') + ')' : '') + '.');
    log.debug('Leaving resetOverrides(). Dry run.');
    return;
  }
  let reset = 0;
  for (const key of keys) {
    const r = await request('POST', base + '/admin-api/config/reset', token,
                            { key: key });
    if (r.status === 200) {
      reset += 1;
    } else {
      failed.push('setting ' + key + ' (' + brief(r) + ')');
    }
  }
  say('reset ' + reset + ' of ' + keys.length + ' runtime override(s)' +
      (keys.length ? ' (' + keys.join(', ') + ')' : '') + '.');
  log.debug('Leaving resetOverrides().');
}

async function main(argv) {
  log.debug('Entering main().');
  const args = argv.slice(2);
  const dryRun = args.indexOf('--dry-run') >= 0;
  const base = String(args.filter(function (a) {
    return a.indexOf('--') !== 0;
  })[0] || '').replace(/\/+$/, '');
  const token = process.env.STS_ADMIN_API_TOKEN || '';
  if (!base || !token) {
    log.debug('Leaving main().');
    throw new Error('usage: STS_ADMIN_API_TOKEN=… ' +
                    'STS_ADMIN_API_CLIENT_SECRET=… ' +
                    'reset-environment.js [--dry-run] <url>');
  }
  if (process.env.STS_SUITE_KEEP_REALMS === '1') {
    say('STS_SUITE_KEEP_REALMS=1, leaving every realm in place.');
    log.debug('Leaving main(). Kept.');
    return;
  }
  if (dryRun) {
    say('DRY RUN: listing what would be removed; nothing is changed.');
  }
  const failed = [];
  await resetRealms(base, token, dryRun, failed);
  await resetDirectory(base, token, dryRun, failed);
  await resetApplications(base, token, dryRun, failed);
  await resetOverrides(base, token, dryRun, failed);
  if (failed.length) {
    process.stderr.write('reset-environment: not reset: ' +
                         failed.slice(0, 50).join('; ') +
                         (failed.length > 50 ? '; and ' +
                          (failed.length - 50) + ' more' : '') + '\n');
    log.debug('Leaving main().');
    throw new Error(failed.length + ' realm(s), entries, application(s) or ' +
                    'setting(s) could not be reset');
  }
  log.debug('Leaving main().');
}

module.exports = {
  isSuitePerson: isSuitePerson,
  isSuiteGroup: isSuiteGroup,
  isSuiteApplication: isSuiteApplication,
  BULK_DOORS: BULK_DOORS
};

if (require.main === module) {
  main(process.argv).catch(function (e) {
    process.stderr.write('reset-environment: ' + ((e && e.message) || e) +
                         '\n');
    process.exit(1);
  });
}
