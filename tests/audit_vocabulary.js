'use strict';
//
// File: tests/audit_vocabulary.js
//
// ---------------------------------------------------------------------------
// EVERY AUDIT ACTION THE SERVICE RECORDS IS IN THE VOCABULARY (2026-09-26).
//
// `common/audit.js`'s ACTIONS is the table the console's filter and the
// `/admin-api/audit` `action` enum are built from, and since #86 that enum
// is HELD: `GET /admin-api/audit?action=<x>` is refused 400 for an action
// the table does not name. Seventy-four actions were recorded by their
// modules and never listed, so a query for any of them was refused —
// `sts_portal_backup_codes` found it asking for
// `admin.mfa.backup-codes.cleared`.
//
// What is held here, by reading the source:
//
//   1. Every literal `action: '<a>.<b>'` in a service directory is a row of
//      ACTIONS (the audit rows are the only dotted `action:` literals here).
//   2. The four actions built by concatenation are listed with their
//      suffixes, so a new suffix fails here rather than at the filter.
//   3. Every row names a category CATEGORIES declares.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'audit_vocabulary',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DIRS = ['common', 'admin-core', 'admin-ui', 'authn', 'portal',
  'oauth-oidc', 'saml', 'ws-trust', 'ws-federation', 'federation',
  'kerberos', 'ldap', 'scim', 'ssf', 'spiffe', 'xacml', 'gnap', 'acme',
  'est', 'scep', 'risk', 'oid4vc', 'oidfed', 'pki', 'mgmt-api', 'logout',
  'cluster', 'persistence', 'tls', 'debugger', 'home'];

// The actions a module builds by concatenation: the prefix, and every suffix
// the module can append. A literal scan cannot see these.
const BUILT = {
  'portal.risc.': ['optOutInitiated', 'optOutCancelled', 'optIn'],
  'admin.krb5.service.': ['created', 'rotated', 'deleted'],
  'oauth2.claims-providers.': ['add-provider', 'update-provider',
                               'remove-provider', 'revoke-link'],
  'xacml.pep.': ['enable', 'disable']
};

function sources() {
  log.debug("Entering sources().");
  const out = [];
  DIRS.forEach(function (dir) {
    const full = path.join(ROOT, dir);
    if (!fs.existsSync(full)) {
      return;
    }
    fs.readdirSync(full).forEach(function (name) {
      if (/\.(ts|js)$/.test(name) && !/\.d\.ts$/.test(name)) {
        // A compiled .js beside its .ts is the same source twice.
        if (/\.js$/.test(name) &&
            fs.existsSync(path.join(full, name.replace(/\.js$/, '.ts')))) {
          return;
        }
        out.push(path.join(full, name));
      }
    });
  });
  log.debug("Leaving sources(). " + out.length + " file(s).");
  return out;
}

module.exports = {
  name: 'audit_vocabulary',
  describe: 'every audit action the service records is a row of ' +
            'audit.ACTIONS, so the filter can name it',
  run: function run(t) {
    log.debug("Entering run().");
    const audit = require('../common/audit');
    const have = new Set(audit.ACTIONS.map(function (row) {
      return row.action;
    }));
    const categories = new Set(audit.CATEGORIES.map(function (row) {
      return row.category;
    }));

    const missing = [];
    let seen = 0;
    sources().forEach(function (file) {
      const text = fs.readFileSync(file, 'utf8');
      const re = /action:\s*'([a-z][a-z0-9-]*(?:\.[a-zA-Z0-9-]+)+)'(?!\s*\+)/g;
      let m;
      while ((m = re.exec(text)) !== null) {
        seen += 1;
        if (!have.has(m[1])) {
          missing.push(m[1] + ' (' + path.relative(ROOT, file) + ')');
        }
      }
    });
    t.check(seen > 150, 'the scan found the audit rows it reads',
            seen + ' literal action(s) read');
    t.check(missing.length === 0,
            'every literal audit action is a row of audit.ACTIONS',
            missing.join(', '));

    Object.keys(BUILT).forEach(function (prefix) {
      BUILT[prefix].forEach(function (suffix) {
        t.check(have.has(prefix + suffix),
                'the built action ' + prefix + suffix + ' is a row');
      });
    });

    const badCategory = audit.ACTIONS.filter(function (row) {
      return !categories.has(row.category);
    }).map(function (row) {
      return row.action + ':' + row.category;
    });
    t.check(badCategory.length === 0,
            'every row names a declared category', badCategory.join(', '));
    log.debug("Leaving run().");
  }
};
