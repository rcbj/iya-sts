// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/webauthn_enterprise_attestation.js
//
// ===========================================================================
// ENTERPRISE ATTESTATION, ASKED FOR ONLY BY RP ID (#1114).
//
//   A. With `webauthn.attestation` `enterprise`, a registration asks for
//      `enterprise` only at an RP ID `webauthn.attestationEnterpriseRpIds`
//      lists (case aside), and for `direct` anywhere else, which
//      `attestationConveyance()` reports as `downgraded`; a conveyance
//      other than `enterprise` is never downgraded, and a policy that
//      demands trust still asks for `direct`.
//   B. The write rule (STS-AUTHN-0500): `enterprise` with the list empty
//      is refused, and emptying the list while `enterprise` is chosen; the
//      pair posted together is judged by both new values
//      (`config.withWriteBatch()`), and a console section's Save
//      (`set-many`) takes both in one post, refuses `enterprise` alone and
//      takes the way back to `direct` with the list emptied.
//   C. The device serial (#532) is read only from a statement an
//      enterprise request produced: a trusted packed attestation naming a
//      serial records it under `enterprise` at a listed RP ID, and does
//      not under `direct` nor at an unlisted RP ID — where the record says
//      `conveyance: direct` and `enterpriseDowngraded: true`.
//   D. The ceremony row's `attestation` detail leads with the downgrade,
//      and says nothing of it for an enterprise request — and is stored at
//      all: since #1108 it is the third part of the folded `authenticator`
//      (read back with `unfold()`), so the row is within `audit.js`'s
//      twelve fields (it was thirteen, and the cap dropped `attestation`),
//      with `client` the plain client and `capabilities` its own field.
//
// The certificates are made at run time by `webauthn_attestation_kit.js`;
// no key material is in this repository.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const audit = require('../common/audit');
const errorCodes = require('../common/error_codes');
const webauthn = require('../authn/webauthn');
const webauthnPolicy = require('../authn/webauthn_policy');
const attestation = require('../authn/webauthn_attestation');
const ceremonies = require('../authn/webauthn_ceremonies');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({
  name: 'webauthn_enterprise_attestation',
  level: process.env.LOG_LEVEL || 'info' });

const CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ' +
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.54 ' +
  'Safari/537.36';

const CONVEYANCE = 'webauthn.attestation';
const RP_IDS = 'webauthn.attestationEnterpriseRpIds';

// Sets the pair as one write, as the console's section does.
function setPair(conveyance, rpIds) {
  log.debug('Entering setPair().');
  const batch = {};
  batch[CONVEYANCE] = conveyance;
  batch[RP_IDS] = rpIds;
  const out = config.withWriteBatch(batch, function () {
    return [config.setOverride(RP_IDS, rpIds),
            config.setOverride(CONVEYANCE, conveyance)];
  });
  log.debug('Leaving setPair().');
  return out;
}

function clearPair() {
  log.debug('Entering clearPair().');
  config.clearOverride(CONVEYANCE);
  config.clearOverride(RP_IDS);
  log.debug('Leaving clearPair().');
}

function byRpId(t) {
  log.debug('Entering byRpId().');
  try {
    setPair('enterprise', ' Sts.Example.COM , localhost');
    const listed = webauthnPolicy.creationOptions('localhost');
    const cased = webauthnPolicy.creationOptions('sts.example.com');
    const other = webauthnPolicy.creationOptions('other.example.org');
    const told = webauthnPolicy.attestationConveyance('other.example.org');
    t.check(listed.attestation === 'enterprise' &&
            cased.attestation === 'enterprise' &&
            other.attestation === 'direct' &&
            told.configured === 'enterprise' &&
            told.requested === 'direct' && told.downgraded === true &&
            webauthnPolicy.attestationConveyance('localhost').downgraded ===
              false,
            'A. enterprise is asked for only at a listed RP ID (case ' +
            'aside); anywhere else direct, reported as downgraded',
            JSON.stringify([listed.attestation, cased.attestation,
                            other.attestation, told]));
    setPair('none', 'localhost');
    const none = webauthnPolicy.attestationConveyance('other.example.org');
    config.setOverride('webauthn.attestationAllowedAaguids',
                       '00000000000000000000000000000001');
    const trust = webauthnPolicy.attestationConveyance('other.example.org');
    t.check(none.requested === 'none' && none.downgraded === false &&
            trust.requested === 'direct' && trust.downgraded === false,
            'A2. another conveyance is never downgraded, and a policy that ' +
            'demands trust still asks for direct',
            JSON.stringify([none, trust]));
  } finally {
    config.clearOverride('webauthn.attestationAllowedAaguids');
    clearPair();
  }
  log.debug('Leaving byRpId().');
}

function writeRule(t) {
  log.debug('Entering writeRule().');
  const adminActions = require('../admin-core/admin_actions');
  try {
    const alone = config.checkWriteCode(CONVEYANCE, 'enterprise');
    const direct = config.checkWriteCode(CONVEYANCE, 'direct');
    setPair('enterprise', 'localhost');
    const emptied = config.checkWriteCode(RP_IDS, '');
    const replaced = config.checkWriteCode(RP_IDS, 'sts.example.com');
    t.check(alone === 'STS-AUTHN-0500' && direct === '' &&
            emptied === 'STS-AUTHN-0500' && replaced === '' &&
            /cannot be enterprise while/.test(
              config.checkWrite(RP_IDS, '') || ''),
            'B. enterprise with no RP ID listed is refused at the write, ' +
            'either way round (STS-AUTHN-0500)',
            [alone, direct, emptied, replaced].join(' '));
    clearPair();
    const together = config.withWriteBatch(
      { 'webauthn.attestation': 'enterprise',
        'webauthn.attestationEnterpriseRpIds': 'localhost' },
      function () {
        return [config.checkWriteCode(CONVEYANCE, 'enterprise'),
                config.checkWriteCode(RP_IDS, 'localhost')];
      });
    t.check(together.join('') === '',
            'B2. the pair posted together is judged by both new values',
            JSON.stringify(together));
    const both = adminActions.configAction({ action: 'set-many',
      'webauthn.attestation': 'enterprise',
      'webauthn.attestationEnterpriseRpIds': 'localhost' });
    const bothHeld = config.value(CONVEYANCE) === 'enterprise' &&
      JSON.stringify(config.value(RP_IDS)) === '["localhost"]';
    const back = adminActions.configAction({ action: 'set-many',
      'webauthn.attestation': 'direct',
      'webauthn.attestationEnterpriseRpIds': '' });
    const backHeld = config.value(CONVEYANCE) === 'direct';
    const lone = adminActions.configAction({ action: 'set-many',
      'webauthn.attestation': 'enterprise' });
    t.check(both && both.ok === true && bothHeld &&
            back && back.ok === true && backHeld &&
            lone && lone.ok === false &&
            errorCodes.codeOf(lone) === 'STS-AUTHN-0500' &&
            config.value(CONVEYANCE) === 'direct',
            'B3. a section\'s Save takes enterprise with its list in one ' +
            'post and the way back to direct with the list emptied, and ' +
            'refuses enterprise alone',
            JSON.stringify([both, back, lone]));
  } finally {
    clearPair();
  }
  log.debug('Leaving writeRule().');
}

async function serial(t) {
  log.debug('Entering serial().');
  const root = await kit.root('Enterprise Vendor');
  config.setOverride('webauthn.attestationPolicy', 'verify-if-present');
  config.setOverride('webauthn.attestationTrustAnchors', root.pem);
  const assessed = async function () {
    log.debug('Entering serial() assessed().');
    const ctx = await kit.ceremony({ rpId: 'localhost' });
    const made = await kit.packed(ctx, root, null, null,
                                  { subject: 'SN-1114' });
    const out = await attestation.assess(
      webauthn.verifyRegistration(ctx.input(made)));
    log.debug('Leaving serial() assessed().');
    return out;
  };
  const out = {};
  try {
    const plain = await assessed();
    setPair('enterprise', 'localhost');
    const asked = await assessed();
    setPair('enterprise', 'sts.example.com');
    const unlisted = await assessed();
    const p = plain.attestation || {};
    const a = asked.attestation || {};
    const u = unlisted.attestation || {};
    t.check(plain.ok && p.trusted === true && p.conveyance === 'direct' &&
            p.enterpriseDowngraded === false && p.deviceSerial === undefined,
            'C. a direct request\'s statement records no device serial, ' +
            'though its certificate names one', JSON.stringify(p));
    t.check(asked.ok && a.conveyance === 'enterprise' &&
            a.enterpriseDowngraded === false && a.deviceSerial === 'SN-1114',
            'C2. an enterprise request at a listed RP ID records the serial',
            JSON.stringify(a));
    t.check(unlisted.ok && u.conveyance === 'direct' &&
            u.enterpriseDowngraded === true && u.deviceSerial === undefined,
            'C3. at an RP ID the list does not name, the request was ' +
            'direct, the record says it was downgraded, and no serial is ' +
            'read', JSON.stringify(u));
    out.asked = a;
    out.unlisted = u;
  } finally {
    clearPair();
    config.clearOverride('webauthn.attestationPolicy');
    config.clearOverride('webauthn.attestationTrustAnchors');
  }
  log.debug('Leaving serial().');
  return out;
}

function row(t, recorded) {
  log.debug('Entering row().');
  const who = 'wea-' + require('crypto').randomBytes(3).toString('hex');
  ['unlisted', 'asked'].forEach(function (which) {
    ceremonies.record({ ceremony: 'registration', door: 'portal',
                        username: who, role: 'mfa', lane: 'classical',
                        outcome: 'success', offered: [-7],
                        algorithm: 'ES256',
                        req: { headers: { 'user-agent': CHROME } },
                        posted: { capabilities: { hybridTransport: true,
                                                  conditionalGet: true } },
                        attestation: recorded[which] || null });
  });
  const stored = audit.list().filter(function (one) {
    return one.action === 'webauthn.ceremony' && one.actor === who;
  });
  const first = (stored[0] || {}).detail || {};
  const rows = audit.list().filter(function (one) {
    return one.action === 'webauthn.ceremony' && one.actor === who;
  }).map(function (one) {
    return String(ceremonies.unfold(one.detail || {}).attestation || '');
  });
  const downgraded = rows.filter(function (text) {
    return /^enterprise not listed, asked direct; ES256/.test(text);
  });
  const plain = rows.filter(function (text) {
    return /^ES256/.test(text) && text.indexOf('enterprise') < 0;
  });
  t.check(rows.length === 2 && downgraded.length === 1 && plain.length === 1 &&
          Object.keys(first).length <= 12 && !first['(more)'] &&
          first.client === 'Chrome 141 on macOS 10' &&
          first.capabilities === 'conditionalGet,hybridTransport' &&
          /^\|\|enterprise not listed, asked direct; ES256|^\|\|ES256/
            .test(String(first.authenticator || '')),
          'D. the ceremony row\'s attestation detail leads with the ' +
          'downgrade, and an enterprise request\'s says nothing of it',
          JSON.stringify([rows, first]));
  log.debug('Leaving row().');
}

module.exports = {
  name: 'webauthn_enterprise_attestation',
  describe: 'enterprise attestation asked for only at the RP IDs a realm ' +
            'lists, the write refused with none, and the device serial read ' +
            'only from an enterprise request (#1114)',
  run: async function (t) {
    log.debug('Entering run().');
    byRpId(t);
    writeRule(t);
    const recorded = await serial(t);
    row(t, recorded);
    log.debug('Leaving run().');
  }
};
