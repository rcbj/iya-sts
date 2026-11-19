// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// AND THE ACTIONS BUILT AT RUN TIME (2026-11-16). Until then this read only
// the literal `action: '<a>.<b>'`, and a hand-kept table of six prefixes.
// Everything else escaped it: a name assembled from a prefix and a suffix
// (`owner.audit + '.listener.' + verb` wrote `xacml.pep.cluster.listener.set`
// and others with no row), a name handed through a helper's parameter
// (`recordAudit('device.risk', …)` had none either), a ternary
// (`c ? 'a.b' : 'a.c'`), and a name read from a table (`auditAction:`).
//
// What is held here, by reading the source of every service directory:
//
//   1. Every `action:` (and `auditAction:`) whose value is a literal, or a
//      ternary whose every branch is one, is read, and each dotted name is a
//      row of ACTIONS — wherever it is written, because a row object is
//      often built before it reaches `audit.audit()`.
//   2. Every `action:` handed to an audit writer — a callee with `audit` in
//      its name, directly or through `Object.assign()` — whose value is NOT
//      such a literal is a BUILT site, and must be declared in BUILT below,
//      keyed by its file and its expression, with every value it can take:
//      listed, or read from the calls of the helper that passes it. An
//      undeclared site fails, so a new built name cannot go unseen.
//   3. A value with `+` or a template literal holding a dotted fragment is a
//      built site wherever it is written, writer or not.
//   4. Every BUILT entry still names a site (a renamed expression leaves a
//      stale entry, and the site it replaced undeclared), and every value it
//      enumerates is a row.
//   5. Every row names a category CATEGORIES declares.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'audit_vocabulary',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Every top-level directory is read except these, which hold no service code
// (or, for `node-ldapjs`, code that writes no audit row of this service's).
// A list of what is LEFT OUT rather than of what is read, so that a new
// service directory is read without anybody remembering to add it: `uma/`,
// `report/`, `account-api/` and `launch/` were missing from the old list.
const NOT_SERVICE = ['tests', 'node-ldapjs', 'rust', 'deploy', 'docs',
  'companion', 'xacml-pep', 'utilities', 'types', 'LICENSES', 'env',
  'models', 'mariadb', 'postgres', 'openbao', 'icap-clamav', 'node_modules'];

const DOTTED = /^[a-z][a-z0-9-]*(?:\.[a-zA-Z0-9-]+)+$/;

// ---------------------------------------------------------------------------
// THE BUILT SITES: `<file>|<expression>`, the expression with its whitespace
// collapsed to one space, mapped to what it can write. One of:
//
//   values: [...]          every action, enumerated by reading the code
//   via: {                 the action is (built from) an argument of a helper
//     call: 'name',        the helper, as it is called in that same file
//     arg: n,              which argument (from 0)
//     prefix, suffix       what the site adds around it
//   }                      every call's argument must be a literal (or a
//                          ternary of literals); one that is not fails,
//                          unless its expression is in `except` and what it
//                          can be is in `values`
//   fromKey: 'auditAction' every literal `auditAction:` in the service, which
//                          rule 1 reads as rows already
//   passThrough: 'why'     the value is an `action:` its caller wrote, which
//                          this scan reads where the caller wrote it
//
// `via` may be a list, for one expression several helpers share (each
// `action: action` of ldap_server.js), and `call` and `prefix` may each be a
// list: every call name is read, and every prefix applied.
// ---------------------------------------------------------------------------
const XACML_OWNERS = ['xacml.pep', 'xacml.pep.cluster'];

/**
 * Every owner's prefix with every suffix: `xacml_admin.ts` builds a remote
 * PEP's actions from `owner.audit`, which is `xacml.pep` for a PEP and
 * `xacml.pep.cluster` for a cluster (`pepOwner()`, `clusterOwner()`).
 *
 * @param {string[]} suffixes - what each site appends
 * @returns {string[]} the actions
 */
function xacmlOwners(suffixes) {
  log.debug("Entering xacmlOwners().");
  const out = [];
  XACML_OWNERS.forEach(function (owner) {
    suffixes.forEach(function (suffix) {
      out.push(owner + suffix);
    });
  });
  log.debug("Leaving xacmlOwners().");
  return out;
}

const BUILT = {
  // ---- admin-core
  // The local `audited(name, …)` of credentialAdminAction() and the local
  // `audit(name, …)` of the passkey upgrade.
  'admin-core/admin_actions.ts|name': {
    via: [{ call: 'audited', arg: 0 }, { call: 'audit', arg: 0 }] },
  // policy_kinds.ts' tables; each literal `auditAction:` is read by rule 1.
  'admin-core/admin_actions.ts|found.extra.auditAction': {
    fromKey: 'auditAction' },
  'admin-core/admin_actions.ts|kind.auditAction': { fromKey: 'auditAction' },
  // KERBEROS_TRUST_ACTIONS, every one of which reaches the row.
  "admin-core/admin_actions.ts|'krb5.trust.' + action": {
    values: ['krb5.trust.add', 'krb5.trust.update', 'krb5.trust.enable',
             'krb5.trust.disable', 'krb5.trust.rotate-key',
             'krb5.trust.remove', 'krb5.trust.pair'] },
  // ---- attribute-sources
  "attribute-sources/attribute_sources.ts|'attribute-sources.' + what": {
    via: { call: 'note', arg: 0, prefix: 'attribute-sources.' } },
  // ---- authn
  "authn/device_bound_sessions.ts|'authn.session.' + action + '.refused'": {
    via: { call: 'this.refuse', arg: 5, prefix: 'authn.session.',
           suffix: '.refused' } },
  // ---- authzen: `finish()` is handed a task's final status.
  "authzen/authzen_access_request.ts|'authzen.access-request.' + status": {
    via: { call: 'self.finish', arg: 1, prefix: 'authzen.access-request.' } },
  // ---- common
  // recordHttp(): httpActionFor()'s five answers.
  'common/audit.js|action': {
    values: ['api.change', 'api.read', 'admin.change', 'admin.view',
             'protocol.call'] },
  'common/audit.js|info.action': {
    passThrough: 'recordDirectory() writes the action its caller named' },
  'common/audit_export.ts|action': {
    via: { call: 'this.changed', arg: 0 } },
  'common/devices.ts|action': { via: { call: 'this.recordAudit', arg: 0 } },
  'common/service_account_rotation.ts|action': {
    via: { call: 'this.record', arg: 0 } },
  // ---- federation
  'federation/federation.js|action': { via: { call: 'recordChange', arg: 0 } },
  // ---- gnap: `revokeGrantBy()`'s `ctx.action` is `gnap_revocation.ts`'s
  // `EndHow.action`, which no caller sets today.
  "gnap/gnap_grants.ts|String(ctx.action || 'gnap.grant.revoke')": {
    values: ['gnap.grant.revoke'] },
  // ---- kerberos
  "kerberos/krb5_person_keys.ts|'admin.krb5.service.' + act": {
    via: { call: 'this.mintServiceKeys', arg: 2,
           prefix: 'admin.krb5.service.' } },
  ["kerberos/krb5_person_keys.ts|(manual ? 'admin.' : '') + 'krb5.krbtgt.' + " +
  "act"]: {
    via: { call: 'this.writeKrbtgt', arg: 2,
           prefix: ['krb5.krbtgt.', 'admin.krb5.krbtgt.'] },
    except: ["invalidate ? 'invalidated' : 'rotated'"],
    values: ['krb5.krbtgt.invalidated', 'krb5.krbtgt.rotated',
             'admin.krb5.krbtgt.invalidated', 'admin.krb5.krbtgt.rotated'] },
  // ---- ldap: directoryActionFor() is objectKindOf() (`user`, `group`,
  // `entry`) and the operation.
  ["ldap/ldap_server.js|audit.directoryActionFor('create', dn, { users: " +
  "usersDn(), groups: groupsDn() })"]: {
    values: ['user.create', 'group.create', 'entry.create'] },
  ["ldap/ldap_server.js|audit.directoryActionFor('delete', dn, { users: " +
  "usersDn(), groups: groupsDn() })"]: {
    values: ['user.delete', 'group.delete', 'entry.delete'] },
  ["ldap/ldap_server.js|audit.directoryActionFor('update', dn, { users: " +
  "usersDn(), groups: groupsDn() })"]: {
    values: ['user.update', 'group.update', 'entry.update'] },
  ["ldap/ldap_server.js|audit.directoryActionFor('rename', target, { users: " +
  "usersDn(), groups: groupsDn() })"]: {
    values: ['user.rename', 'group.rename', 'entry.rename'] },
  'ldap/ldap_server.js|action': {
    via: [{ call: 'auditDirectory', arg: 0 },
          { call: 'auditPolicyDirectory', arg: 0 },
          { call: 'auditFederationDirectory', arg: 0 },
          { call: 'spiffeAuditDirectory', arg: 0 },
          { call: 'writeGroupOwners', arg: 3 }] },
  // ---- oauth-oidc
  "oauth-oidc/claims_providers.ts|'oauth2.claims-providers.' + action": {
    values: ['oauth2.claims-providers.add-provider',
             'oauth2.claims-providers.update-provider',
             'oauth2.claims-providers.remove-provider',
             'oauth2.claims-providers.revoke-link'] },
  // ---- oid4vc
  // `deactivate()` hands its own `action`: an administrator's or the
  // person's.
  'oid4vc/person_did.ts|action': {
    via: { call: 'this.audited', arg: 0 }, except: ['action'],
    values: ['admin.did.deactivated', 'did.person.deactivated'] },
  // ---- oidfed
  'oidfed/federation_keys.ts|event': { via: { call: 'this.record', arg: 0 } },
  // `act()` hands `'oidfed.' + action` for its two removals.
  'oidfed/oidfed.ts|action': {
    via: { call: 'this.audited', arg: 1 }, except: ["'oidfed.' + action"],
    values: ['oidfed.remove-mark-type', 'oidfed.remove-mark-policy'] },
  'oidfed/oidfed_registration.ts|action': {
    via: { call: 'this.audited', arg: 0 } },
  // ---- portal
  // AccountOverview.moveParticipation(): RISC's three moves.
  "portal/account_overview.ts|'portal.risc.' + move": {
    values: ['portal.risc.optOutInitiated', 'portal.risc.optOutCancelled',
             'portal.risc.optIn'] },
  "portal/portal_devices.ts|'portal.device.' + action": {
    via: { call: 'this.audited', arg: 2, prefix: 'portal.device.' } },
  // PortalShared.act()'s four `kind = '…'`.
  'portal/portal_shared.ts|kind': {
    values: ['uma.share.add', 'uma.share.remove', 'uma.approval.answer',
             'uma.policy.alfa'] },
  'portal/portal_wallet.ts|action': {
    via: { call: ['this.refuseDisagreement', 'self.refuseDisagreement'],
           arg: 3 } },
  // ---- risk
  'risk/risk_datasets.ts|action': { via: { call: 'this.auditRow', arg: 0 } },
  // ---- scim
  'scim/scim.ts|action': { via: { call: 'this.auditScim', arg: 0 } },
  // ---- spiffe
  'spiffe/spiffe_registry.ts|action': {
    via: { call: 'this.auditEntry', arg: 0 } },
  // ---- ssf
  // `streamAct()` hands `'ssf.signals.' + action` for each act it performs.
  'ssf/ssf_transmitters.ts|action': {
    via: { call: 'this.audited', arg: 0 },
    except: ["'ssf.signals.' + action"],
    values: ['ssf.signals.read-stream', 'ssf.signals.update-stream',
             'ssf.signals.replace-stream', 'ssf.signals.read-status',
             'ssf.signals.delete-stream', 'ssf.signals.set-status',
             'ssf.signals.add-subject', 'ssf.signals.remove-subject',
             'ssf.signals.verify'] },
  // ---- uma
  'uma/uma.ts|action': { via: { call: 'self.record', arg: 0 } },
  // The owner's own acts on the console hand `kind`, one of three.
  'uma/uma_console.ts|action': {
    via: { call: 'self.record', arg: 0 }, except: ['kind'],
    values: ['uma.share.add', 'uma.share.remove', 'uma.approval.answer'] },
  // ---- ws-trust: an application's decryption key pair (#1668), each act
  // naming its action at the call.
  'ws-trust/ws_decryption_key.ts|action': {
    via: { call: 'WsDecryptionKey.audited', arg: 0 } },
  // ---- xacml
  "xacml/xacml_admin.ts|'xacml.pep.' + (on ? 'enable' : 'disable')": {
    values: ['xacml.pep.enable', 'xacml.pep.disable'] },
  "xacml/xacml_admin.ts|owner.audit + '.listener.environment'": {
    values: xacmlOwners(['.listener.environment']) },
  "xacml/xacml_admin.ts|owner.audit + '.listener.' + verb": {
    values: xacmlOwners(['.listener.set', '.listener.remove',
                         '.listener.renew']) },
  ["xacml/xacml_admin.ts|owner.audit + '.settings.' + (keys.length ? 'set' " +
  ": 'clear')"]: {
    values: xacmlOwners(['.settings.set', '.settings.clear']) },
  "xacml/xacml_admin.ts|owner.audit + '.proxy.clear'": {
    values: xacmlOwners(['.proxy.clear']) },
  "xacml/xacml_admin.ts|owner.audit + '.proxy.set'": {
    values: xacmlOwners(['.proxy.set']) }
};

/**
 * Blanks out comments and the bodies of string and template literals,
 * keeping every offset, so the structure can be walked without a quote or a
 * brace inside a string misleading it.
 *
 * @param {string} text - the source
 * @returns {string} the masked source, the same length
 */
// No Entering/Leaving pair: called once per character class of every service
// file and every expression, and the lines would drown the log.
function mask(text) {
  const out = text.split('');
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    const d = text[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && text[i] !== '\n') {
        out[i] = ' ';
        i += 1;
      }
      continue;
    }
    if (c === '/' && d === '*') {
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) {
        if (text[i] !== '\n') {
          out[i] = ' ';
        }
        i += 1;
      }
      out[i] = ' ';
      out[i + 1] = ' ';
      i += 2;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      i += 1;
      while (i < n && text[i] !== c) {
        if (text[i] === '\\') {
          out[i] = '_';
          i += 1;
        }
        if (text[i] !== '\n') {
          out[i] = '_';
        }
        i += 1;
      }
      i += 1;
      continue;
    }
    i += 1;
  }
  return out.join('');
}

/**
 * Finds where an expression starting at `from` ends: the first `,` or `;`,
 * or closing bracket, at depth 0.
 *
 * @param {string} masked - the masked source
 * @param {number} from - where the expression starts
 * @returns {number} the offset just past it
 */
// No Entering/Leaving pair: a hot path, once per site and argument.
function expressionEnd(masked, from) {
  let depth = 0;
  let j = from;
  while (j < masked.length) {
    const c = masked[j];
    if (c === '(' || c === '[' || c === '{') {
      depth += 1;
    } else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) {
        break;
      }
      depth -= 1;
    } else if ((c === ',' || c === ';') && depth === 0) {
      break;
    }
    j += 1;
  }
  return j;
}

/**
 * Finds the unmatched opening bracket before `at`.
 *
 * @param {string} masked - the masked source
 * @param {number} at - where to start looking, going backwards
 * @returns {number} its offset, or -1
 */
// No Entering/Leaving pair: a hot path, once per site.
function openingBefore(masked, at) {
  let depth = 0;
  let k = at;
  while (k >= 0) {
    const c = masked[k];
    if (c === ')' || c === ']' || c === '}') {
      depth += 1;
    } else if (c === '(' || c === '[' || c === '{') {
      if (depth === 0) {
        break;
      }
      depth -= 1;
    }
    k -= 1;
  }
  return k;
}

/**
 * The callee of the call an object literal at `brace` is an argument of:
 * `audit.audit` for `audit.audit({ … })`, and the callee of the enclosing
 * call for `audit.recordDirectory(Object.assign({ … }, …))`.
 *
 * @param {string} masked - the masked source
 * @param {number} brace - the offset of the object's `{`
 * @returns {string} the callee, or '' when the object is not an argument
 */
// No Entering/Leaving pair: a hot path, once per site.
function calleeOf(masked, brace) {
  let p = brace - 1;
  while (p >= 0 && /\s/.test(masked[p])) {
    p -= 1;
  }
  let open = -1;
  if (masked[p] === '(') {
    open = p;
  } else if (masked[p] === ',') {
    open = openingBefore(masked, p - 1);
  }
  if (open < 0 || masked[open] !== '(') {
    return '';
  }
  let b = open - 1;
  while (b >= 0 && /[\w.$()]/.test(masked[b])) {
    b -= 1;
  }
  // `audit().record(` keeps its brackets; a leading one belongs to
  // something before the name.
  const callee = masked.slice(b + 1, open).replace(/^[()]+/, '');
  if (callee === 'Object.assign') {
    return calleeOf(masked, open - 'Object.assign'.length);
  }
  return callee;
}

/**
 * Whether a callee writes an audit row: its name has `audit` in it
 * (`audit.audit`, `auditLog.record`, `this.deps.audit().record`,
 * `ctx.audit.record`, `auditLdap`, `reportAudit`, `this.recordAudit`), or
 * it is `recordDirectory` or `reportRecord`.
 *
 * @param {string} callee - the callee
 * @returns {boolean} whether it writes one
 */
// No Entering/Leaving pair: a hot path, once per site.
function isWriter(callee) {
  return /audit/i.test(callee) || /(^|\.)recordDirectory$/.test(callee) ||
         callee === 'reportRecord';
}

/**
 * The names an expression can take when it is a literal, or a ternary
 * (nested to any depth) whose every result is one.
 *
 * @param {string} text - the expression, unmasked
 * @returns {string[] | null} the names, or null when it is not one
 */
// No Entering/Leaving pair: a hot path, once per site and argument.
function literalValues(text) {
  let expr = text.trim();
  let masked = mask(expr);
  while (expr[0] === '(' && expressionEnd(masked, 1) === expr.length - 1) {
    expr = expr.slice(1, -1).trim();
    masked = mask(expr);
  }
  const one = /^'([^'\\]*)'$/.exec(expr) || /^"([^"\\]*)"$/.exec(expr);
  if (one) {
    return [one[1]];
  }
  // The ternary's `?` and its `:` at depth 0; a nested ternary in the first
  // branch is skipped over by counting.
  let depth = 0;
  let question = -1;
  let colon = -1;
  let pending = 0;
  for (let i = 0; i < masked.length && colon < 0; i += 1) {
    const c = masked[i];
    if (c === '(' || c === '[' || c === '{') {
      depth += 1;
    } else if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
    } else if (depth === 0 && c === '?' && masked[i + 1] !== '.' &&
               masked[i + 1] !== '?' && masked[i - 1] !== '?') {
      if (question < 0) {
        question = i;
      } else {
        pending += 1;
      }
    } else if (depth === 0 && c === ':' && question >= 0) {
      if (pending === 0) {
        colon = i;
      } else {
        pending -= 1;
      }
    }
  }
  if (question < 0 || colon < 0) {
    return null;
  }
  const yes = literalValues(expr.slice(question + 1, colon));
  const no = literalValues(expr.slice(colon + 1));
  return yes && no ? yes.concat(no) : null;
}

/**
 * The arguments of every call of `name(` in a source, unmasked.
 *
 * @param {string} text - the source
 * @param {string} masked - the same, masked
 * @param {string} name - the callee as written, `this.recordAudit`
 * @returns {string[][]} each call's arguments
 */
function callsOf(text, masked, name) {
  log.debug("Entering callsOf().");
  const escaped = name.replace(/[.$()]/g, '\\$&');
  const re = new RegExp('(^|[^\\w$.])' + escaped + '\\(', 'g');
  const out = [];
  let m;
  while ((m = re.exec(masked)) !== null) {
    // A declaration (`function name(`, `private name(`) is not a call.
    const before = masked.slice(Math.max(0, m.index - 16),
                                m.index + m[1].length);
    if (/\b(function|private|public|protected|static|async)\s*$/
          .test(before)) {
      continue;
    }
    const args = [];
    let at = m.index + m[0].length;
    for (;;) {
      const end = expressionEnd(masked, at);
      args.push(text.slice(at, end).trim().replace(/\s+/g, ' '));
      if (masked[end] !== ',') {
        break;
      }
      at = end + 1;
    }
    out.push(args);
  }
  log.debug("Leaving callsOf(). " + out.length + " call(s).");
  return out;
}

/**
 * Every service source file, read once.
 *
 * @returns {Array<{ file: string, text: string, masked: string }>} each one
 */
function sources() {
  log.debug("Entering sources().");
  const out = [];
  const take = function (dir, name) {
    if (/\.(ts|js)$/.test(name) && !/\.d\.ts$/.test(name)) {
      // A compiled .js beside its .ts is the same source twice.
      if (/\.js$/.test(name) &&
          fs.existsSync(path.join(dir, name.replace(/\.js$/, '.ts')))) {
        return;
      }
      const text = fs.readFileSync(path.join(dir, name), 'utf8');
      out.push({ file: path.relative(ROOT, path.join(dir, name)),
                 text: text, masked: mask(text) });
    }
  };
  fs.readdirSync(ROOT).forEach(function (name) {
    const full = path.join(ROOT, name);
    if (name[0] === '.' || NOT_SERVICE.indexOf(name) >= 0) {
      return;
    }
    if (fs.statSync(full).isDirectory()) {
      fs.readdirSync(full).forEach(function (inner) {
        take(full, inner);
      });
    } else {
      take(ROOT, name);
    }
  });
  log.debug("Leaving sources(). " + out.length + " file(s).");
  return out;
}

/**
 * Reads every `action:` and `auditAction:` in the service sources.
 *
 * @param {Array<object>} files - from `sources()`
 * @returns {Array<object>} each site: its file, expression, whether an
 *   audit writer is handed it, and the file's text
 */
function sites(files) {
  log.debug("Entering sites().");
  const out = [];
  files.forEach(function (one) {
    const re = /(^|[^\w$.])(action|auditAction)\s*:/g;
    let m;
    while ((m = re.exec(one.masked)) !== null) {
      const start = m.index + m[0].length;
      const end = expressionEnd(one.masked, start);
      const raw = one.text.slice(start, end);
      // A type (`action: string;`) is not a value.
      if (/^\s*(string|boolean|number|any|Json|true|false)\b/.test(raw)) {
        continue;
      }
      const brace = openingBefore(one.masked, m.index);
      const callee = brace >= 0 && one.masked[brace] === '{'
        ? calleeOf(one.masked, brace) : '';
      out.push({ file: one.file, key: m[2],
                 expr: raw.trim().replace(/\s+/g, ' '),
                 writer: isWriter(callee), source: one });
    }
  });
  log.debug("Leaving sites(). " + out.length + " site(s).");
  return out;
}

/**
 * Every action a BUILT entry can write, read from the code where the entry
 * says so.
 *
 * @param {object} entry - the entry
 * @param {object} site - the site it names
 * @param {string[]} problems - where a call that cannot be read goes
 * @returns {string[]} the actions
 */
function builtValues(entry, site, problems) {
  log.debug("Entering builtValues().");
  const out = (entry.values || []).slice();
  const except = entry.except || [];
  [].concat(entry.via || []).forEach(function (via) {
    const names = [].concat(via.call);
    const prefixes = [].concat(via.prefix || '');
    let calls = [];
    names.forEach(function (name) {
      calls = calls.concat(callsOf(site.source.text, site.source.masked,
                                   name));
    });
    if (!calls.length) {
      problems.push(site.file + ': no call of ' + names.join(' or ') +
                    '(…) to read');
    }
    calls.forEach(function (args) {
      const given = args[via.arg || 0] || '';
      if (except.indexOf(given) >= 0) {
        return;
      }
      const values = literalValues(given);
      if (!values) {
        problems.push(site.file + ': ' + names[0] + '(…) is handed `' +
                      given + '`, which this cannot read; list what it ' +
                      'can be in `values` and the expression in `except`');
        return;
      }
      values.forEach(function (one) {
        prefixes.forEach(function (prefix) {
          out.push(prefix + one + (via.suffix || ''));
        });
      });
    });
  });
  log.debug("Leaving builtValues(). " + out.length + " value(s).");
  return out;
}

module.exports = {
  name: 'audit_vocabulary',
  describe: 'every audit action the service records, literal or built, is ' +
            'a row of audit.ACTIONS, so the filter can name it',
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
    const undeclared = [];
    const problems = [];
    const used = new Set();
    let seen = 0;
    const note = function (name, where) {
      if (!DOTTED.test(name)) {
        return;
      }
      seen += 1;
      if (!have.has(name) && missing.indexOf(name + ' (' + where + ')') < 0) {
        missing.push(name + ' (' + where + ')');
      }
    };

    const files = sources();
    sites(files).forEach(function (site) {
      const key = site.file + '|' + site.expr;
      const values = literalValues(site.expr);
      if (values) {
        values.forEach(function (one) {
          note(one, site.file);
        });
        return;
      }
      // Rule 3: concatenation or a template, with a dotted fragment.
      const built = /\+|`/.test(mask(site.expr).replace(/_/g, '')) &&
                    /'[^']*\.[^']*'|"[^"]*\.[^"]*"|`[^`]*\.[^`]*`/
                      .test(site.expr);
      if (!site.writer && !built) {
        return;
      }
      const entry = BUILT[key];
      if (!entry) {
        undeclared.push(key);
        return;
      }
      used.add(key);
      if (entry.passThrough || entry.fromKey) {
        return;
      }
      builtValues(entry, site, problems).forEach(function (one) {
        note(one, site.file + ', built');
      });
    });

    // THE HELPERS EVERY FILE CALLS BY ONE NAME (2026-10-06): admin_actions.ts'
    // and ssf_transmitters.ts' `audited(name, …)` and the private
    // `this.record(name, …)` of service_account_rotation.ts and
    // federation_keys.ts each write `action: name`. Their sites are BUILT
    // entries above, read from their own file; this reads the same calls in
    // EVERY file, so a new helper of one of these names is held too.
    files.forEach(function (one) {
      ['audited', 'this.audited', 'this.record', 'self.record']
        .forEach(function (name) {
        callsOf(one.text, one.masked, name).forEach(function (args) {
          (literalValues(args[0] || '') || []).forEach(function (value) {
            note(value, one.file);
          });
        });
      });
    });

    t.check(seen > 400, 'the scan found the audit actions it reads',
            seen + ' action(s) read');
    t.check(missing.length === 0,
            'every audit action, literal or built, is a row of ' +
            'audit.ACTIONS', missing.join(', '));
    t.check(undeclared.length === 0,
            'every action built at run time is declared in BUILT with ' +
            'every value it can take', undeclared.join('; '));
    t.check(problems.length === 0,
            'every call of a helper that names an action hands it a ' +
            'literal, or is listed', problems.join('; '));
    const stale = Object.keys(BUILT).filter(function (key) {
      return !used.has(key);
    });
    t.check(stale.length === 0,
            'every BUILT entry names a site the source still has',
            stale.join('; '));

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
