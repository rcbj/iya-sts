// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/pseudonym_index.js — A LIVE stsPseudonym IS A USERNAME (#644).
//
// In a child, for person_attribute_editor.js's reason: requiring the
// directory loads the protocol stack. The claims:
//
//   1. An administrator's name is stored at once and existingUserEntry of
//      that name is the owner. name_keys holds the uid and the alias.
//   2. A self-service email is pending. It is not a name key and
//      existingUserEntry of it is not the owner. Two copies of one alias
//      are one name key.
//   3. The person's own uid is refused and not stored.
//   4. userFor of a live alias, and of a live email, is the filing name.
//      identityKeyOf stays a pure fold.
//   5. Removing the alias drops it from the index.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'pseudonym_index',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.PSEUD_ROOT;
  const OUT = process.env.PSEUD_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const helpers = require(ROOT + '/common/helpers');
    const stats = require(ROOT + '/common/admin_stats');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const codec = require(ROOT + '/persistence/directory_codec');

    await realms.run(realms.DEFAULT_REALM, async function () {
      const who = 'p644-index';
      const made = ldap.createUser(who, {});
      note(made && made.ok, 'created the person',
           JSON.stringify(made && made.ok ? { ok: true } : made));
      if (!made || !made.ok) {
        return;
      }
      const alias = 'P644.Other';
      const added = await ldap.writePseudonyms(who, {
        op: 'add', value: alias, source: 'admin'
      });
      const live = (added && added.pseudonyms || []).some(function (one) {
        return String(one).toLowerCase() === 'p644.other';
      });
      note(added && added.ok === true && live,
           'an administrator\'s name is live at once',
           JSON.stringify(added));
      const owner = ldap.existingUserEntry(who);
      const found = ldap.existingUserEntry('p644.other');
      note(!!(found && owner && found.dn === owner.dn),
           'existingUserEntry of the alias is the owner',
           found && found.dn);
      const indexed = codec.indexOf(owner && owner.attributes);
      const aliasKey = codec.lookupOf('name', 'p644.other');
      const uidKey = codec.lookupOf('name', who);
      note(indexed.nameKeys.indexOf(aliasKey) >= 0 &&
           indexed.nameKeys.indexOf(uidKey) >= 0,
           'name_keys holds the uid and the live alias',
           JSON.stringify(indexed.nameKeys));
      const pendingAddress = 'pend644@example.com';
      const pending = await ldap.writePseudonyms(who, {
        op: 'add', value: pendingAddress, source: 'self'
      });
      const notLive = (pending && pending.pseudonyms || [])
        .every(function (one) {
          return String(one).toLowerCase() !== pendingAddress;
        });
      const shown = Object.assign({}, pending || {}, { token: 'held' });
      note(pending && pending.ok === true && pending.pending === true &&
           !!pending.token && notLive,
           'a self-service email is pending and not a live name',
           JSON.stringify(shown));
      const after = ldap.existingUserEntry(who);
      const keys = codec.indexOf(after && after.attributes);
      const pendingKey = codec.lookupOf('name', pendingAddress);
      note(keys.nameKeys.indexOf(pendingKey) < 0,
           'the pending address is not a name key',
           JSON.stringify(keys.nameKeys));
      const pendingHit = ldap.existingUserEntry(pendingAddress);
      note(!pendingHit || pendingHit.dn !== owner.dn,
           'existingUserEntry of the pending address is not the owner',
           pendingHit && pendingHit.dn);
      const doubled = codec.indexOf({
        uid: [who],
        stspseudonym: ['Same', 'same'],
        stspseudonymverifyaddress: [pendingAddress]
      });
      const sameKey = codec.lookupOf('name', 'same');
      const once = doubled.nameKeys.filter(function (one) {
        return one === sameKey;
      }).length === 1;
      note(once && doubled.nameKeys.indexOf(pendingKey) < 0,
           'two identical aliases are one name key, and a pending ' +
           'address is not', JSON.stringify(doubled.nameKeys));
      const own = await ldap.writePseudonyms(who, {
        op: 'add', value: who, source: 'admin'
      });
      note(own && own.ok === false && own.code === 'STS-LDAP-0201',
           'the person\'s own uid is refused', JSON.stringify(own));
      const still = ldap.existingUserEntry(who);
      const held = (still.attributes.stspseudonym || []).map(function (v) {
        return String(v).toLowerCase();
      });
      note(held.indexOf(who) < 0, 'the refused uid was not stored',
           held.join(','));
      const claims = helpers.userFor('p644.other');
      note(claims.username === who &&
           claims.preferred_username === who &&
           String(claims.sub).indexOf('urn:uuid:') === 0,
           'userFor of the alias is the filing name',
           JSON.stringify({ username: claims.username,
                            preferred_username: claims.preferred_username,
                            sub: claims.sub }));
      const folded = stats.identityKeyOf('P644.Other@example.com');
      note(folded === 'P644.Other', 'identityKeyOf stays a fold', folded);
      const email = who + '@alias.example';
      const liveMail = await ldap.writePseudonyms(who, {
        op: 'add', value: email, source: 'admin'
      });
      note(liveMail && liveMail.ok === true,
           'an administrator\'s email is live', JSON.stringify(liveMail));
      note(stats.identityKeyOf(email) === who,
           'identityKeyOf of that email is still the local part',
           stats.identityKeyOf(email));
      const byMail = helpers.userFor(email);
      note(byMail.username === who && byMail.sub === claims.sub,
           'userFor of the live email is the filing person',
           JSON.stringify({ username: byMail.username, sub: byMail.sub }));
      const removed = await ldap.writePseudonyms(who, {
        op: 'remove', value: alias, source: 'admin'
      });
      note(removed && removed.ok === true, 'removed the alias',
           JSON.stringify(removed));
      const gone = ldap.existingUserEntry('p644.other');
      note(!gone || gone.dn !== owner.dn,
           'the alias is no longer the owner', gone && gone.dn);
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

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'pseudonym-index-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ADMIN_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', PSEUD_ROOT: ROOT,
                                  PSEUD_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pseudonym index',
  describe: 'a live stsPseudonym is a username in the index and in ' +
            'userFor, a pending email is not, and the person\'s own uid ' +
            'is refused',
  run: run
};
