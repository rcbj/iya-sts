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
//   * applications `isSuiteApplication()` recognises — the identifiers the
//     jobs name per run in the default realm, and sts_userinfo_protected.js's
//     RFC 7591 registrations — through `POST /admin-api/applications/forget`.
//     Never one this service seeded (`registeredBy: startup`).
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

// APPLICATIONS THE SUITE REGISTERS IN THE DEFAULT REALM AND NAMES FOR THE RUN
// (surveyed 2026-09-29, #344). A job registering into a realm it created is
// not here: that application goes with the realm. Nor is one registered under
// a FIXED identifier (`admin-api-test`, `sts-endpoint-test-client`,
// `dpop-test-client`, `abcapp1`…): the next run finds it again, so it does not
// accumulate, and removing it would only make that run re-create it. Each
// pattern names the job that makes it; `<stamp>` is random_username.js's
// `runStamp()`. A job that starts naming a default-realm application per run
// belongs here too.
const STAMP = '[a-z0-9-]+';
const APPLICATION_PATTERNS = [
  // sts_saml11.js: `urn:test:saml11:<stamp>`
  new RegExp('^urn:test:saml11:' + STAMP + '$'),
  // sts_oauth2_monitor.js: `parmon-a-<stamp>`, `parmon-b-<stamp>`
  new RegExp('^parmon-[ab]-' + STAMP + '$'),
  // sts_portal_sessions.js: `portal-probe-{open,narrowed,nowhere,ssf}-<stamp>`
  new RegExp('^portal-probe-(open|narrowed|nowhere|ssf)-' + STAMP + '$'),
  // sts_oauth21.js (product only): `oauth21-control-c-<stamp>`
  new RegExp('^oauth21-control-c-' + STAMP + '$'),
  // sts_global_logout.js: `gl-all-<stamp>`, `gl-<protocol>-<stamp>`
  new RegExp('^gl-(all|oauth2|oidc|saml2|saml11|wsfed|wstrust|krb5|ldap|' +
             'mtls)-' + STAMP + '$'),
  // sts_saml_encryption.js: `https://enc-{gcm,cbc,nokey,logout}-<stamp>.
  // example.com`
  new RegExp('^https://enc-(gcm|cbc|nokey|logout)-' + STAMP +
             '\\.example\\.com$'),
  // sts_scope_policy.js: `sp-admin-scopepol-<stamp>` (it forgets its own, and
  // an interrupted run leaves it)
  new RegExp('^sp-admin-scopepol-' + STAMP + '$'),
  // sts_admin_closed_sets.js: `closed-sets-<scope>-<Date.now() in base 36>`
  new RegExp('^closed-sets-' + STAMP + '$'),
  // sts_consent.js: `consent-{resource,client,other-client}-<8 digits>`
  /^consent-(resource|client|other-client)-[0-9]{8}$/,
  // sts_saml11.js's unregistered relying party, where a sighting is recorded:
  // `urn:test:not:registered:<pid>`
  /^urn:test:not:registered:[0-9]+$/
];

// sts_userinfo_protected.js registers about fourteen clients a run through
// RFC 7591 and deletes none. Their client_id is the service's
// (`oauth2.registeredClientIdPrefix`, `sts-client-` unless set), so they are
// told apart by all three of: registered through RFC 7591, that prefix, and
// the job's one redirect URI and nothing else. The other jobs registering the
// same way (oauth2_sts_endpoints.js) delete theirs through RFC 7592.
const SUITE_REGISTRATION_REDIRECT = 'http://localhost:9999/callback';

// The values of `name` in an entry's attributes, whatever case the directory
// hands the attribute name back in.
function attributeValues(attributes, name) {
  log.debug('Entering attributeValues().');
  const wanted = name.toLowerCase();
  const key = Object.keys(attributes || {}).filter(function (one) {
    return one.toLowerCase() === wanted;
  })[0];
  const values = key === undefined ? [] : [].concat(attributes[key]);
  log.debug('Leaving attributeValues().');
  return values.map(String);
}

function isSuiteRegistration(row) {
  log.debug('Entering isSuiteRegistration().');
  const redirects = attributeValues(row.attributes, 'oauthRedirectUri');
  const answer = String(row.registeredBy) === 'rfc7591' &&
                 /^sts-client-/.test(String(row.identifier)) &&
                 redirects.length === 1 &&
                 redirects[0] === SUITE_REGISTRATION_REDIRECT;
  log.debug('Leaving isSuiteRegistration(). ' + answer);
  return answer;
}

/**
 * Tells whether an application row from `GET /admin-api/applications` is one
 * a suite run registered in the default realm.
 *
 * @param {object} row - the row: `identifier`, `registeredBy`, `attributes`
 * @returns {boolean} true for a suite application
 */
function isSuiteApplication(row) {
  log.debug('Entering isSuiteApplication().');
  const identifier = String((row && row.identifier) || '');
  const by = String((row && row.registeredBy) || '');
  // Seeded by this service at startup: never the suite's to remove, whatever
  // it is called. A sighting (an application that turned up, registered by
  // nobody) is removed when its NAME is the suite's — sts_saml11.js presents
  // an unregistered one on purpose.
  if (!identifier || by === 'startup') {
    log.debug('Leaving isSuiteApplication(). Seeded, or no identifier.');
    return false;
  }
  const answer = isSuiteRegistration(row) ||
                 APPLICATION_PATTERNS.some(function (pattern) {
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
        resolve({ status: res.statusCode, json: json, text: text,
                  retryAfter: res.headers['retry-after'] || '' });
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

// A REQUEST THAT FAILED ON THE WAY IS ASKED AGAIN (#311). Every request this
// script makes may be repeated — a GET, and a DELETE (in a Bulk or alone),
// whose 404 is the outcome wanted — and on testidp's first reset of 29,600
// leftovers one page out of a 37-minute listing failed with `read ETIMEDOUT`
// and threw the whole listing away. So is a 503: since #351 a write the
// service could not commit is answered 503 with a Retry-After rather than a
// 204 it might lose, and a 502 is a request worker that went away without
// answering. Any other answer is the service speaking, and the caller judges
// it.
async function requestRetrying(method, url, token, body, contentType) {
  log.debug('Entering requestRetrying(). ' + method + ' ' + url);
  let last = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const answer = await request(method, url, token, body, contentType);
      if ((answer.status === 503 || answer.status === 502) && attempt < 3) {
        const after = parseInt(String(answer.retryAfter || ''), 10);
        const waitS = isFinite(after) && after > 0 ? Math.min(after, 60) :
          5 * attempt;
        say(method + ' answered ' + answer.status + ', attempt ' + attempt +
            ' of 3; asking again in ' + waitS + 's.');
        await new Promise(function (resolve) {
          setTimeout(resolve, waitS * 1000);
        });
        continue;
      }
      log.debug('Leaving requestRetrying().');
      return answer;
    } catch (e) {
      log.debug('Caught in requestRetrying(): ' + ((e && e.message) || e));
      last = e;
      say(method + ' failed (' + ((e && e.message) || e) + '), attempt ' +
          attempt + ' of 3.');
      await new Promise(function (resolve) {
        setTimeout(resolve, 5000 * attempt);
      });
    }
  }
  log.debug('Leaving requestRetrying(). Gave up.');
  throw last;
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
    const r = await requestRetrying('GET', url, scim);
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
  return Math.min(most, bulkBatchSize());
}

// HOW MANY DELETES ONE BULK REQUEST CARRIES (#311). A person's delete ends
// everything they held (common/CLAUDE.md, *A deleted person ends the same
// way*), so a Bulk of 1,000 people ran past this script's 120 s request
// timeout on testidp's first reset of 29,600 leftovers and the run stopped
// before its first job. 100 is well inside it; STS_RESET_BULK_SIZE moves it,
// never past the service's own advertised bulk.maxOperations.
function bulkBatchSize() {
  log.debug('Entering bulkBatchSize().');
  const asked = parseInt(String(process.env.STS_RESET_BULK_SIZE || ''), 10);
  log.debug('Leaving bulkBatchSize().');
  return isFinite(asked) && asked > 0 ? Math.min(asked, 1000) : 100;
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
      const r = await requestRetrying('POST', base + '/scim/v2/Bulk', scim,
                                      body, 'application/scim+json');
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
        const r = await requestRetrying('DELETE', base + '/scim/v2/' + type +
                                        '/' + encodeURIComponent(row.id),
                                        scim);
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

// THE PEOPLE ARE DELETED A PAGE AT A TIME, AS THEY ARE LISTED (#311). A
// filtered SCIM page costs the service ~15 s at testidp's size, so listing
// 29,600 leftovers before deleting any took 37 minutes and deleted nothing
// when the run stopped. Here each page is deleted before the next is asked
// for, and the next is asked for from the front again — what was deleted is
// no longer there — skipping only the rows kept (a `bulk-` name
// `isSuitePerson()` does not recognise) and rows already tried, which a node
// that has not yet heard of the delete may still list. Progress survives a
// stop, and the next reset starts where this one ended.
async function scimSweep(base, scim, type, attribute, wanted, perBatch,
                         failed) {
  log.debug('Entering scimSweep(). ' + type);
  const tried = new Set();
  let skipped = 0;
  let deleted = 0;
  let total = 0;
  for (;;) {
    const url = base + '/scim/v2/' + type + '?filter=' +
      encodeURIComponent(attribute + ' sw "bulk-"') +
      '&attributes=' + attribute + '&count=1000&startIndex=' + (skipped + 1);
    const r = await requestRetrying('GET', url, scim);
    if (r.status !== 200 || !r.json || !Array.isArray(r.json.Resources)) {
      log.debug('Leaving scimSweep().');
      throw new Error('GET /scim/v2/' + type + ' answered ' + brief(r));
    }
    total = Number(r.json.totalResults) || 0;
    const rows = r.json.Resources;
    // Past the last result there is nothing left to look at. testidp's SCIM
    // answers a startIndex beyond totalResults with the last rows again
    // rather than the empty page RFC 7644 section 3.4.2.4 describes, so an
    // empty page alone never came: run 8's reset skipped the same four kept
    // rows for good, silently. This stops on the count whatever comes back.
    if (!rows.length || skipped >= total) {
      break;
    }
    const batch = [];
    rows.forEach(function (row) {
      const name = String(row[attribute] || '');
      if (!row.id || !wanted(name) || tried.has(String(row.id))) {
        skipped += 1;
      } else {
        tried.add(String(row.id));
        batch.push({ id: String(row.id), name: name });
      }
    });
    if (batch.length) {
      const before = failed.length;
      await scimDelete(base, scim, type, batch, perBatch, failed);
      deleted += batch.length - (failed.length - before);
      say('deleted ' + deleted + ' ' + type + ' so far; ' +
          Math.max(0, total - skipped - batch.length) + ' left to look at.');
    }
  }
  say('deleted ' + deleted + ' ' + type + ' (' + skipped + ' kept or ' +
      'already tried).');
  log.debug('Leaving scimSweep(). ' + deleted + ' deleted.');
  return deleted;
}

async function resetDirectory(base, token, dryRun, failed) {
  log.debug('Entering resetDirectory().');
  const scim = await scimToken(base, token, dryRun);
  const groups = await scimList(base, scim, 'Groups', 'displayName',
                                isSuiteGroup);
  if (!dryRun) {
    const perBatch = await bulkLimit(base, scim);
    const started = Date.now();
    say(groups.length + ' bulk-load group(s) in the default realm.');
    await scimDelete(base, scim, 'Groups', groups, perBatch, failed);
    await scimSweep(base, scim, 'Users', 'userName', isSuitePerson, perBatch,
                    failed);
    say('the directory took ' + Math.round((Date.now() - started) / 1000) +
        's.');
    log.debug('Leaving resetDirectory().');
    return;
  }
  const people = await scimList(base, scim, 'Users', 'userName',
                                isSuitePerson);
  say(groups.length + ' bulk-load group(s) and ' + people.length +
      ' bulk-load person/people in the default realm.');
  const sample = function (rows) {
    log.debug('Entering sample().');
    log.debug('Leaving sample().');
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
}

// ---------------------------------------------------------------------------
// THE RISK DATASETS (#311).
// ---------------------------------------------------------------------------
// sts_admin_risk and sts_admin_risk_upload import versions of the operator
// lists into the default realm and leave the last one ACTIVE. On testidp that
// replaced rcbj's own deny list, and the next run's sts_admin_risk was then
// refused by the shrink guard against a 2,500-row suite version. The jobs now
// put back what they found; this is the backstop for a job that was killed.
//
// A version is the SUITE'S when
//   * its name has a suite job's prefix (`run-`, `two-`, `bomb-`), or
//   * it was loaded within SUITE_NEIGHBOUR_MS of such a version (the upload
//     job's own versions are named by their SHA-256 on purpose, and always
//     land seconds after sts_admin_risk's), or
//   * it was loaded within SUITE_WINDOW_MS after a run's start, which the
//     launcher marks by uploading `suite-<run>` to iplist.operator-allow.
// `suite-<run>` itself is the launcher's allow list for THIS run and is
// never displaced. For every other dataset whose active version is the
// suite's, the newest version that is not, and that loaded (not refused,
// not deleted), is made active again. A dataset with no such version is
// left alone and reported.
const SUITE_VERSION_PREFIX = /^(run|two|bomb)-/;
const SUITE_NEIGHBOUR_MS = 60 * 1000;
const SUITE_WINDOW_MS = 12 * 60 * 60 * 1000;

function suiteVersionTest(datasets) {
  log.debug('Entering suiteVersionTest().');
  const named = [];
  const windows = [];
  datasets.forEach(function (d) {
    (d.versions || []).forEach(function (v) {
      const at = Number(v.loadedAt) || 0;
      if (SUITE_VERSION_PREFIX.test(String(v.version))) {
        named.push(at);
      }
      if (/^suite-/.test(String(v.version))) {
        windows.push(at);
      }
    });
  });
  log.debug('Leaving suiteVersionTest().');
  return function (v) {
    const name = String(v.version || '');
    const at = Number(v.loadedAt) || 0;
    if (SUITE_VERSION_PREFIX.test(name) || /^suite-/.test(name)) {
      return true;
    }
    return named.some(function (t) {
      return Math.abs(at - t) <= SUITE_NEIGHBOUR_MS;
    }) || windows.some(function (t) {
      return at >= t && at - t <= SUITE_WINDOW_MS;
    });
  };
}

async function resetRiskDatasets(base, token, dryRun, failed) {
  log.debug('Entering resetRiskDatasets().');
  const r = await requestRetrying('GET', base + '/admin-api/risk', token);
  if (r.status !== 200 || !r.json || !Array.isArray(r.json.datasets)) {
    log.debug('Leaving resetRiskDatasets().');
    throw new Error('GET /admin-api/risk answered ' + brief(r));
  }
  const datasets = r.json.datasets;
  const isSuite = suiteVersionTest(datasets);
  let restored = 0;
  for (const d of datasets) {
    const active = String(d.activeVersion || '');
    if (!active || /^suite-/.test(active)) {
      continue;
    }
    const current = (d.versions || []).filter(function (v) {
      return String(v.version) === active;
    })[0] || { version: active, loadedAt: 0 };
    if (!isSuite(current)) {
      continue;
    }
    const operator = (d.versions || []).filter(function (v) {
      return !isSuite(v) &&
        ['superseded', 'ready', 'active'].indexOf(String(v.state)) >= 0;
    }).sort(function (a, b) {
      return (Number(b.loadedAt) || 0) - (Number(a.loadedAt) || 0);
    })[0];
    if (!operator) {
      say(d.dataset + ': the suite\'s ' + active + ' is active and no ' +
          'operator version is held; left as it is.');
      continue;
    }
    if (dryRun) {
      say(d.dataset + ': would make ' + operator.version + ' active again ' +
          'in place of the suite\'s ' + active + '.');
      continue;
    }
    const a = await requestRetrying('POST',
                                    base + '/admin-api/risk/activate', token,
                                    { dataset: d.dataset,
                                      version: operator.version,
                                      // The versions are held per realm, and
                                      // an activate naming none looked in
                                      // realm '' and answered "not recorded"
                                      // for rcbj's own list (run 9).
                                      realm: String(operator.realm ||
                                                    d.realm || 'default') });
    if (a.status === 200) {
      restored += 1;
      say(d.dataset + ': ' + operator.version + ' is active again in place ' +
          'of the suite\'s ' + active + '.');
    } else {
      failed.push('risk dataset ' + d.dataset + ' (' + brief(a) + ')');
    }
  }
  say('restored ' + restored + ' risk dataset(s) to the operator\'s version.');
  log.debug('Leaving resetRiskDatasets().');
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
    // The operation's member is `application` (mgmt-api/admin_api.ts,
    // deleteApplication), and its schema refuses any other since #86: run 8's
    // reset was answered 400 for all 418 when this sent `identifier`.
    const r = await requestRetrying('POST',
                                    base + '/admin-api/applications/forget',
                                    token, { application: identifier });
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
  await resetRiskDatasets(base, token, dryRun, failed);
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
  suiteVersionTest: suiteVersionTest,
  BULK_DOORS: BULK_DOORS
};

if (require.main === module) {
  main(process.argv).catch(function (e) {
    process.stderr.write('reset-environment: ' + ((e && e.message) || e) +
                         '\n');
    process.exit(1);
  });
}
