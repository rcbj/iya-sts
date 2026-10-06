// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: delivered_secrets.ts
//
// ---------------------------------------------------------------------------
// A SECRET DELIVERED AS A FILE, READ ONCE AND DELETED (#254, 2026-10-06).
//
// A handful of settings are secrets that only a deployment can supply and
// that this service needs before it has loaded anything else: the management
// API client's secret is written onto the seeded `sts-management-api` entry
// at REQUIRE time (`ldap/ldap_server.js` seeds the internal applications as
// it loads), so it cannot wait for an asynchronous read from a secret store
// the way the key-encryption key and the database password do.
//
// Until #254 they arrived as environment variables, and an environment
// variable is the most readable place a secret can be: `docker inspect` shows
// it without a shell, `/proc/<pid>/environ` shows it to the process's own
// user, and every child the process spawns inherits it. So each may instead
// be named by `<ENV>_FILE` — `ADMIN_API_CLIENT_SECRET_FILE` for
// `ADMIN_API_CLIENT_SECRET` — and this module, called by `server.js` once the
// heap-limit re-exec is behind it and before the protocol stack loads:
//
//   * reads the file, trimmed, and refuses an empty one or one it cannot
//     read (STS-CORE-0150, 0151) — the service was told where its secret is,
//     and starting without it would mint a different one;
//   * DELETES it, so that what was handed over is gone once it has been
//     taken (STS-CORE-0152 when the deletion fails, and the service starts);
//   * holds the value at config.js's environment layer
//     (`config.setDelivered()`), never in `process.env`;
//   * forgets `<ENV>_FILE` itself, which names a file that no longer exists.
//
// **THE REQUEST WORKERS ARE HANDED THE VALUES** as variables of their own
// thread's environment (`workerEnvironment()`, read by `request_pool.js`'s
// `startThread()`). A worker thread's `process.env` is a copy inside this
// process, so it shows in no `/proc/<pid>/environ` and no child inherits it
// from here; the debugger api child's environment is built, not inherited
// (`debugger/debugger_api_process.ts`).
//
// **AFTER THE RE-EXEC AND NOT BEFORE IT**: `process_memory.ts` may replace
// this process with `process.execve()`, and the file is read once. Read
// before that, the value would be gone from the process that serves.
//
// WHO WRITES THE FILE is the deployment's business. The compose stacks'
// start-up helper, `openbao/startup-secrets.js`, writes them on a tmpfs from
// what a single-use, response-wrapped OpenBao token can read
// (`openbao/CLAUDE.md`).
//
// A LEAF: config, error_codes and node's own `fs`.
// ---------------------------------------------------------------------------

import fs = require('fs');
import bunyan = require('bunyan');
import config = require('./config');
import errorCodes = require('./error_codes');

let logLevelProblem: any = null;
const log = bunyan.createLogger({
  name: 'delivered_secrets',
  level: (function (): any {
    try {
      return config.value('global.logLevel') || 'info';
    } catch (e) {
      logLevelProblem = e;
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('No log level could be read, so info: ' +
            ((logLevelProblem && logLevelProblem.message) || logLevelProblem));
}

// THE SETTINGS THAT MAY BE DELIVERED THIS WAY. A list, and not "every row
// marked secret": the two Kerberos passwords are not drawn as secrets (in
// development the krbtgt one is published on purpose, so a reader can open a
// ticket), and they are still secrets a product launcher hands over.
const KEYS: string[] = [
  'adminApi.clientSecret',
  'krb5.krbtgtPassword',
  'krb5.servicePassword'
];

// What load() delivered, by environment variable: the workers' share.
const handed: Record<string, string> = {};

class DeliveredSecrets {
  /**
   * The settings that may be delivered as a file.
   *
   * @returns their keys
   */
  static keys(): string[] {
    log.debug("Entering DeliveredSecrets.keys().");
    log.debug("Leaving DeliveredSecrets.keys().");
    return KEYS.slice();
  }

  /**
   * Reads every `<ENV>_FILE` named for a deliverable setting, deletes the
   * file and holds the value at config.js's environment layer. Called once by
   * `server.js` before the protocol stack loads.
   *
   * @param env - optional; the environment to read, for tests
   * @returns the keys delivered
   * @throws an Error carrying STS-CORE-0150 or STS-CORE-0151 when a named
   *   file cannot be read or is empty
   */
  static load(env?: Record<string, string | undefined>): string[] {
    log.debug("Entering DeliveredSecrets.load().");
    const from = env || process.env;
    const out: string[] = [];
    KEYS.forEach(function (key) {
      const row: any = config.SETTINGS.filter(function (one: any) {
        return one.key === key;
      })[0];
      const variable = row && row.env ? String(row.env) : '';
      if (!variable) {
        return;
      }
      const fileVariable = variable + '_FILE';
      const where = String(from[fileVariable] || '').trim();
      if (!where) {
        return;
      }
      let value = '';
      try {
        value = fs.readFileSync(where, 'utf8').trim();
      } catch (e) {
        log.debug("Caught in DeliveredSecrets.load(): " +
                  ((e && e.message) || e));
        log.debug("Leaving DeliveredSecrets.load(). Unreadable.");
        throw errorCodes.mark(new Error(errorCodes.tag('STS-CORE-0150') +
          fileVariable + ' names ' + where + ', which could not be read (' +
          ((e && e.message) || e) + '). The service does not start without ' +
          'the secret it was told is there.'), 'STS-CORE-0150');
      }
      if (!value) {
        log.debug("Leaving DeliveredSecrets.load(). Empty.");
        throw errorCodes.mark(new Error(errorCodes.tag('STS-CORE-0151') +
          fileVariable + ' names ' + where + ', which is empty.'),
          'STS-CORE-0151');
      }
      try {
        fs.unlinkSync(where);
      } catch (e) {
        log.debug("Caught in DeliveredSecrets.load(): " +
                  ((e && e.message) || e));
        // STARTED ANYWAY: the value is good, and a file left behind is a
        // weaker posture rather than a wrong answer. Said, with its code.
        log.warn(errorCodes.tag('STS-CORE-0152') + fileVariable + ' named ' +
                 where + ', which was read and could not be deleted (' +
                 ((e && e.message) || e) + '); it is still readable there.');
      }
      delete from[fileVariable];
      config.setDelivered(key, value);
      handed[variable] = value;
      out.push(key);
    });
    if (out.length) {
      // WHICH, AND NEVER WHAT.
      log.info('delivered_secrets: read ' + out.join(', ') + ' from the ' +
               'file' + (out.length === 1 ? '' : 's') + ' named by its ' +
               '<ENV>_FILE, and deleted ' +
               (out.length === 1 ? 'it' : 'them') + '.');
    }
    log.debug("Leaving DeliveredSecrets.load(). " + out.length);
    return out;
  }

  /**
   * The delivered values as environment variables, for a request worker's
   * thread (#254).
   *
   * @returns `{ <ENV>: value }` for each setting load() delivered
   */
  static workerEnvironment(): Record<string, string> {
    log.debug("Entering DeliveredSecrets.workerEnvironment().");
    log.debug("Leaving DeliveredSecrets.workerEnvironment().");
    return Object.assign({}, handed);
  }
}

export = DeliveredSecrets;
