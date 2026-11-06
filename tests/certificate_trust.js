// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/certificate_trust.js — THE VALIDATION DOOR (#1360).
//
// Every interesting input here is a certificate nobody would deploy, and every
// verdict's `checks` is asserted and not only its `ok`: the door's whole claim
// is that it says WHICH check refused, with the code an operator looks up. The
// master is forced on, so what development answers by default is `baseline`'s
// section and `tests/paranoid_settings.js`'s.
//
// A: the matrix, for each purpose that can reach a caller's anchors or the
//    signer truststore. B: the checks a purpose's own row decides. C: self-signed
//    where it is allowed and where it is not. D: a chain completed from the
//    signer truststore, and purposes restricting an entry. E: revocation, off a
//    real CRL, under each policy. F: name constraints, a critical extension.
//    G: sigstore's notBefore rule. H: the baselines. I: the counters and the
//    audit row. J: the synchronous door. K: expected names.
//
// MUTATION RECORD, each applied to a scratch build, seen red and put back:
//   * `fieldChecks()` not marking a failure                  — 53 red
//   * `compose()` letting `not-asked` pass under paranoid    — 2 red (E, J)
//   * the `pinned` condition accepting any self-signed leaf  — 1 red (C)
//   * `anchorsFor()` ignoring `purposes`                     — 1 red (D)
//   * `ruleOf()` ignoring the variant                        — 4 red (B, E, G)
MUT// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const audit = require('../common/audit');
const trust = require('../common/certificate_trust');
const signers = require('../common/signer_truststore');
const kit = require('./tools/trust_kit');

const log = require('bunyan').createLogger({ name: 'certificate_trust_test',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = 'default';

// Nests, which is the point: a setting put back is put back to what an outer
// call set, never cleared out from under it.
const held = {};

function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const before = Object.assign({}, held);
  Object.keys(pairs).forEach(function (key) {
    const out = config.setOverride(key, pairs[key]);
    if (!out.ok) {
      throw new Error('could not set ' + key + ': ' + out.errors.join(' '));
    }
    held[key] = pairs[key];
  });
  const restore = function () {
    log.debug("Entering restore().");
    Object.keys(pairs).forEach(function (key) {
      if (Object.prototype.hasOwnProperty.call(before, key)) {
        config.setOverride(key, before[key]);
        held[key] = before[key];
      } else {
        config.clearOverride(key);
        delete held[key];
      }
    });
    log.debug("Leaving restore().");
  };
  log.debug("Leaving withSettings().");
  return Promise.resolve().then(fn).then(function (value) {
    restore();
    return value;
  }, function (e) {
    restore();
    throw e;
  });
}

// Every purpose the matrix can drive with a CA the file holds in hand.
function reachable(purpose) {
  log.debug("Entering reachable().");
  log.debug("Leaving reachable().");
  return purpose.anchors.indexOf('caller') !== -1 &&
         purpose.id !== 'anchor-admission';
}

module.exports = {
  name: 'certificate_trust',
  describe: 'the one validation door: every check named, every code the ' +
            'operator looks up, the pin rule, revocation and the baselines',
  run: async function (t) {
    const previous = signers.installedDirectory();
    const double = kit.signerStoreDouble();
    signers.setDirectory(double);
    const crls = await kit.crlServer();
    try {
      await withSettings({ 'pki.paranoid': 'on',
                           'pki.revocationCheck': 'soft-fail' }, async () => {
        await run(t, double, crls);
      });
    } finally {
      await crls.close();
      if (previous) {
        signers.setDirectory(previous);
      }
    }
  }
};

async function run(t, double, crls) {
  log.debug("Entering run().");
  const now = Date.now();
  const root = await kit.mint({ cn: 'door root', ca: true });
  const ekuFor = function (purpose) {
    log.debug("Entering ekuFor().");
    const rule = purpose.leaf.eku;
    const stsCrypto = require('../common/crypto');
    const name = rule && Object.keys(stsCrypto.EKU).filter(function (key) {
      return stsCrypto.EKU[key] === rule.oids[0];
    })[0];
    log.debug("Leaving ekuFor().");
    return rule ? [{ serverAuth: 'serverAuth', clientAuth: 'clientAuth',
                     codeSigning: 'codeSigning', ocspSigning: 'ocspSigning',
                     pkinitClientAuth: 'pkinitClientAuth' }[name]] : undefined;
  };

  // A. THE MATRIX: one certificate that breaks one thing, per purpose.
  t.log.info('A. the matrix');
  const purposes = trust.PURPOSES.filter(reachable);
  t.check(purposes.length >= 9, 'A. the matrix drives most of the table',
          purposes.map(function (p) {
            return p.id;
          }).join(' '));
  for (const purpose of purposes) {
    const usage = purpose.leaf.keyUsage.slice(0, 1);
    const eku = ekuFor(purpose);
    const opts = { anchors: [root.pem], anchorSources: ['caller'] };
    const good = await kit.mint({ cn: purpose.id + ' good', issuer: root,
                                  usages: usage, eku: eku });
    const verdict = await trust.assess(purpose.id, { leaf: good.pem,
                                                     chain: [] }, opts);
    t.check(verdict.ok && verdict.inForce && verdict.anchor === 'caller' &&
            verdict.code === '', 'A. ' + purpose.id + ': a good leaf holds',
            verdict.why + ' ' + JSON.stringify(verdict.checks));
    t.equal(verdict.checks.path, 'passed', 'A. ' + purpose.id + ': path');
    t.equal(verdict.path.length, 2, 'A. ' + purpose.id + ': the path walked');

    const expired = await kit.mint({ cn: purpose.id + ' expired', issuer: root,
      usages: usage, eku: eku, notBefore: now - 3 * kit.DAY,
      notAfter: now - kit.DAY });
    const late = await trust.assess(purpose.id, { leaf: expired.pem }, opts);
    if (purpose.validity === 'now') {
      t.check(!late.ok && late.checks.validity === 'failed' &&
              late.code === 'STS-KEYS-0168',
              'A. ' + purpose.id + ': expired, under its own code',
              late.code + ' ' + late.why);
    }

    const future = await kit.mint({ cn: purpose.id + ' future', issuer: root,
      usages: usage, eku: eku, notBefore: now + kit.DAY,
      notAfter: now + 3 * kit.DAY });
    const early = await trust.assess(purpose.id, { leaf: future.pem }, opts);
    t.check(!early.ok && early.checks.validity === 'failed' &&
            early.code === 'STS-KEYS-0169',
            'A. ' + purpose.id + ': not yet valid, under its own code',
            early.code);

    const wrongUsage = await kit.mint({ cn: purpose.id + ' usage', issuer: root,
      usages: ['nonRepudiation'], eku: eku });
    const usageVerdict = await trust.assess(purpose.id,
      { leaf: wrongUsage.pem }, opts);
    t.check(!usageVerdict.ok && usageVerdict.checks['key-usage'] === 'failed' &&
            usageVerdict.code === 'STS-KEYS-0171',
            'A. ' + purpose.id + ': the wrong keyUsage', usageVerdict.code);

    if (!purpose.leaf.mayBeCa) {
      const isCa = await kit.mint({ cn: purpose.id + ' ca', issuer: root,
        ca: true, pathLen: 0, usages: usage.concat(['keyCertSign']), eku: eku });
      const caVerdict = await trust.assess(purpose.id, { leaf: isCa.pem }, opts);
      t.check(!caVerdict.ok && caVerdict.checks['basic-constraints'] ===
              'failed' && caVerdict.code === 'STS-KEYS-0170',
              'A. ' + purpose.id + ': a CA as a leaf', caVerdict.code);
    }
    if (purpose.leaf.eku) {
      const wrongEku = await kit.mint({ cn: purpose.id + ' eku', issuer: root,
        usages: usage, eku: ['emailProtection'] });
      const ekuVerdict = await trust.assess(purpose.id, { leaf: wrongEku.pem },
                                            opts);
      t.check(!ekuVerdict.ok &&
              ekuVerdict.checks['extended-key-usage'] === 'failed' &&
              ekuVerdict.code === 'STS-KEYS-0172',
              'A. ' + purpose.id + ': an EKU that names something else',
              ekuVerdict.code);
    }
  }

  // B. WHAT A ROW DECIDES: required, or only if present.
  t.log.info('B. required and optional');
  const noEku = await kit.mint({ cn: 'no eku', issuer: root });
  const required = await trust.assess('pkinit', { leaf: noEku.pem },
    { anchors: [root.pem] });
  t.check(!required.ok && required.checks['extended-key-usage'] === 'failed',
          'B. pkinit requires its EKU to be present', required.why);
  const optional = await trust.assess('spiffe-attestation', { leaf: noEku.pem },
    { anchors: [root.pem], anchorSources: ['caller'] });
  t.check(optional.ok, 'B. a purpose that asks no EKU passes it',
          optional.why);
  t.equal(optional.checks['extended-key-usage'], 'passed',
          'B. and says so, rather than not-asked');
  const tpm = await trust.assess('device-attestation', { leaf: noEku.pem },
    { anchors: [root.pem], anchorSources: ['caller'], variant: 'tpm' });
  t.check(!tpm.ok && tpm.checks['extended-key-usage'] === 'failed',
          'B. a variant asks more: the TPM AIK EKU', tpm.why);
  const noUsage = await kit.mint({ cn: 'no ku', issuer: root,
                                   noKeyUsage: true });
  const absent = await trust.assess('jose-signer', { leaf: noUsage.pem },
    { anchors: [root.pem], anchorSources: ['caller'] });
  t.equal(absent.checks['key-usage'], 'passed',
          'B. a keyUsage absent permits everything (RFC 5280 4.2.1.3)');

  // C. SELF-SIGNED.
  t.log.info('C. self-signed');
  const self = await kit.mint({ cn: 'self signed leaf', usages:
                                ['digitalSignature', 'keyEncipherment'] });
  const refused = await trust.assess('client-attestation', { leaf: self.pem },
    { anchors: [root.pem] });
  t.check(!refused.ok && refused.checks['self-signed-allowed'] === 'failed' &&
          refused.code === 'STS-PKI-0249',
          'C. refused where the table says refuse, under the purpose\'s code',
          refused.code);
  const stranger = await trust.assess('saml-signer', { leaf: self.pem });
  t.check(!stranger.ok && stranger.checks['self-signed-allowed'] === 'failed',
          'C. allowed by spec, but a stranger\'s is not a pin', stranger.why);
  const pin = await trust.assess('saml-signer',
    { leaf: self.pem, registered: { chain: [] } });
  t.check(pin.ok && pin.anchor === 'pinned', 'C. the registered one is',
          pin.why);
  t.equal(pin.checks.path, 'exempt-by-spec', 'C. no chain is asked of it');
  const stale = await kit.mint({ cn: 'stale pin', notBefore: now - 3 * kit.DAY,
                                 notAfter: now - kit.DAY });
  const pinnedLate = await trust.assess('saml-signer',
    { leaf: stale.pem, registered: { chain: [] } });
  t.check(!pinnedLate.ok && pinnedLate.checks.validity === 'failed' &&
          pinnedLate.code === 'STS-KEYS-0168',
          'C. validity is exempt nowhere: an expired pin is refused',
          pinnedLate.code);
  const rfc8705 = await trust.assess('tls-client-self-signed',
    { leaf: stale.pem, pinned: true });
  t.check(!rfc8705.ok && rfc8705.checks.validity === 'failed',
          'C. RFC 8705 equality does not exempt validity', rfc8705.why);
  const opensslStyle = await kit.mint({ cn: 'openssl req -x509', ca: true,
    usages: ['digitalSignature', 'keyCertSign'] });
  const accepted = await trust.assess('tls-client-self-signed',
    { leaf: opensslStyle.pem, pinned: true });
  t.check(accepted.ok, 'C. a pinned self-signed leaf may carry cA=TRUE',
          accepted.why);
  const garbage = await trust.assess('jose-signer', { leaf: 'not a cert' });
  t.check(!garbage.ok && garbage.code === 'STS-PKI-0238',
          'C. what is not a certificate says so', garbage.code);

  // D. THE SIGNER TRUSTSTORE.
  t.log.info('D. the signer truststore');
  const partner = await kit.mint({ cn: 'partner root', ca: true, pathLen: 1 });
  const partnerIssuing = await kit.mint({ cn: 'partner issuing', ca: true,
                                          pathLen: 0, issuer: partner });
  const partnerLeaf = await kit.mint({ cn: 'partner leaf',
                                       issuer: partnerIssuing });
  const before = await trust.assess('jose-signer', { leaf: partnerLeaf.pem });
  t.check(!before.ok && before.checks.path === 'failed' &&
          before.code === 'STS-PKI-0243',
          'D. a chain that reaches nothing is refused, under the purpose\'s ' +
          'code', before.code + ' ' + before.why);
  const addRoot = await signers.add(REALM, partner.pem, {});
  t.equal(addRoot.added.length, 1, 'D. the partner\'s Root is admitted');
  const noIntermediate = await trust.assess('jose-signer',
    { leaf: partnerLeaf.pem });
  t.check(!noIntermediate.ok, 'D. the intermediate is still missing',
          noIntermediate.why);
  await signers.add(REALM, partnerIssuing.pem, {});
  const completed = await trust.assess('jose-signer', { leaf: partnerLeaf.pem });
  t.check(completed.ok && completed.anchor === 'signer-truststore',
          'D. an incomplete chain is completed from the store', completed.why);
  t.equal(completed.path.length, 3, 'D. leaf, intermediate, Root');
  const fingerprint = addRoot.added[0].fingerprint256;
  signers.remove(REALM, fingerprint);
  await signers.add(REALM, partner.pem, { purposes: ['saml-signer'] });
  const restricted = await trust.assess('jose-signer',
    { leaf: partnerLeaf.pem });
  t.check(!restricted.ok,
          'D. an entry restricted to another use case serves not this one',
          restricted.why);
  const allowed = await trust.assess('saml-signer', { leaf: partnerLeaf.pem });
  t.check(allowed.ok, 'D. and does serve the one it names', allowed.why);
  double.rows(REALM).clear();

  // E. REVOCATION, off a real CRL.
  t.log.info('E. revocation');
  const revoker = await kit.mint({ cn: 'revoking root', ca: true });
  const listed = await kit.mint({ cn: 'revoked leaf', issuer: revoker,
                                  crls: [crls.base + '/one.crl'] });
  const clean = await kit.mint({ cn: 'clean leaf', issuer: revoker,
                                 crls: [crls.base + '/one.crl'] });
  crls.routes['/one.crl'] = await kit.crlOf(revoker, [listed.serialHex]);
  const options = { anchors: [revoker.pem], anchorSources: ['caller'] };
  const gone = await trust.assess('client-attestation', { leaf: listed.pem },
                                  options);
  t.check(!gone.ok && gone.checks.revocation === 'failed' &&
          gone.code === 'STS-PKI-0118',
          'E. a revoked leaf is refused under the revocation code',
          gone.code + ' ' + gone.why);
  const fine = await trust.assess('client-attestation', { leaf: clean.pem },
                                  options);
  t.check(fine.ok && fine.checks.revocation === 'passed' &&
          fine.revocation.status === 'good',
          'E. one the list does not name holds', fine.why);
  const unreachable = await kit.mint({ cn: 'unreachable', issuer: revoker,
    crls: [crls.base + '/none.crl'] });
  const soft = await trust.assess('client-attestation',
    { leaf: unreachable.pem }, options);
  t.check(soft.ok && soft.revocation.status === 'unknown',
          'E. unknown holds under soft-fail', soft.why);
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async () => {
    const hard = await trust.assess('client-attestation',
      { leaf: unreachable.pem }, options);
    t.check(!hard.ok && hard.checks.revocation === 'failed',
            'E. unknown is refused under hard-fail', hard.why);
  });
  await withSettings({ 'pki.revocationCheck': 'off' }, async () => {
    const off = await trust.assess('client-attestation', { leaf: clean.pem },
                                   options);
    t.check(!off.ok && off.checks.revocation === 'not-asked' &&
            off.code === 'STS-PKI-0249',
            'E. revocation off: a check nobody made is a refusal under ' +
            'paranoid, under the purpose\'s code', off.code + ' ' + off.why);
  });
  const exempt = await trust.assess('spiffe-svid',
    { leaf: await kit.mint({ cn: 'svid', issuer: revoker,
                             eku: ['clientAuth'] }).then(function (one) {
      return one.pem;
    }) },
    { anchors: [revoker.pem], anchorSources: ['caller'],
      variant: 'federated' });
  t.equal(exempt.checks.revocation, 'exempt-by-spec',
          'E. a federated SVID\'s revocation is exempt by spec');

  // F. WHAT THE PATH RULES REFUSE.
  t.log.info('F. the path rules');
  const constrained = await kit.mint({ cn: 'constrained root', ca: true,
                                       permittedDns: ['good.example'] });
  const outside = await kit.mint({ cn: 'outside', issuer: constrained,
                                   san: ['DNS:bad.example'] });
  const nc = await trust.assess('client-attestation', { leaf: outside.pem },
    { anchors: [constrained.pem], anchorSources: ['caller'] });
  t.check(!nc.ok && nc.checks['name-constraints'] === 'failed' &&
          nc.code === 'STS-PKI-0194',
          'F. a name-constraint violation, under its code',
          nc.code + ' ' + nc.why);
  const criticalLeaf = await kit.mint({ cn: 'critical', issuer: root,
                                        critical: '1.3.6.1.4.1.55555.7.2' });
  const crit = await trust.assess('client-attestation',
    { leaf: criticalLeaf.pem }, { anchors: [root.pem],
                                  anchorSources: ['caller'] });
  t.check(!crit.ok && crit.checks['critical-extensions'] === 'failed',
          'F. a critical extension nothing reads', crit.code + ' ' + crit.why);
  t.check(crit.code === 'STS-KEYS-0175', 'F. under the field\'s code',
          crit.code);

  // G. SIGSTORE'S RULE.
  t.log.info('G. sigstore');
  const fulcio = await kit.mint({ cn: 'fulcio', ca: true });
  const shortLived = await kit.mint({ cn: 'short lived', issuer: fulcio,
    eku: ['codeSigning'], notBefore: now - 2 * 3600000,
    notAfter: now - 3600000 });
  const sigstore = await trust.assess('spiffe-attestation',
    { leaf: shortLived.pem },
    { anchors: [fulcio.pem], anchorSources: ['caller'], variant: 'sigstore',
      now: now - 90 * 60000 });
  t.equal(sigstore.checks.validity, 'exempt-by-spec',
          'G. sigstore evaluates validity at notBefore, and says it is ' +
          'exempt');
  const elsewhere = await trust.assess('spiffe-attestation',
    { leaf: shortLived.pem },
    { anchors: [fulcio.pem], anchorSources: ['caller'] });
  t.equal(elsewhere.checks.validity, 'failed',
          'G. and only that variant: any other attestor refuses it');

  // H. THE BASELINES: not in force, what the site did before.
  t.log.info('H. the baselines');
  await withSettings({ 'pki.paranoid': 'off' }, async () => {
    const none = await trust.assess('saml-signer', { leaf: stale.pem });
    t.check(none.ok && !none.inForce && none.checks.validity === 'not-asked',
            'H. saml-signer: an expired signer passes, as it always did',
            none.why);
    const path = await trust.assess('client-attestation', { leaf: listed.pem },
                                    options);
    t.check(path.ok && path.checks.path === 'passed' &&
            path.checks.revocation === 'not-asked',
            'H. client-attestation: the path and no revocation', path.why);
    const pathBad = await trust.assess('client-attestation', { leaf: self.pem },
      { anchors: [root.pem] });
    t.check(!pathBad.ok && pathBad.checks.path === 'failed',
            'H. a baseline refuses what it refused before', pathBad.why);
    const direct = await trust.assess('vc-key-attestation', { leaf: good(root) },
      { anchors: [root.pem] });
    t.check(typeof direct.ok === 'boolean', 'H. vc-key-attestation answers',
            direct.why);
  });
  await withSettings({ 'pki.paranoidJoseSigner': false }, async () => {
    t.check(!trust.applies('jose-signer'), 'H. a row off does not apply', '');
    t.check(trust.applies('saml-signer'), 'H. and no other row moves', '');
  });

  // I. COUNTED, AND AUDITED WHEN IT REFUSES UNDER PARANOID.
  t.log.info('I. counters and the audit row');
  const beforeCount = trust.counters()['client-attestation'];
  const assessedThen = beforeCount.assessed;
  const refusedThen = beforeCount.refused;
  const counted = await trust.assess('client-attestation', { leaf: self.pem },
    { anchors: [root.pem] });
  const afterCount = trust.counters()['client-attestation'];
  t.equal(afterCount.assessed, assessedThen + 1, 'I. assessed counts');
  t.equal(afterCount.refused, refusedThen + 1, 'I. refused counts');
  t.equal(afterCount.lastRefusal.code, counted.code,
          'I. the last refusal is what the verdict said');
  const row = audit.list().filter(function (one) {
    return one.errorCode === counted.code;
  })[0];
  t.check(!!row, 'I. the refusal is on an audit row, under its code', '');
  t.check(row && row.detail &&
          row.detail['self-signed-allowed'] === 'failed',
          'I. carrying the checks', JSON.stringify(row && row.detail));
  const forced = trust.counters()['client-attestation'].assessed;
  await trust.assess('client-attestation', { leaf: self.pem },
    { anchors: [root.pem], force: true });
  t.equal(trust.counters()['client-attestation'].assessed, forced,
          'I. the inventory\'s forced read is not counted');

  // J. THE SYNCHRONOUS DOOR.
  t.log.info('J. the synchronous door');
  const inRealm = await kit.mint({ cn: 'sync foreign', issuer: root,
                                   crls: [crls.base + '/one.crl'],
                                   eku: ['clientAuth'] });
  const sync = trust.assessSync('spiffe-svid', { leaf: inRealm.pem },
                                { anchors: [{ raw: pemDer(root.pem) }] });
  t.check(!sync.ok && sync.checks.path === 'passed' &&
          sync.checks.revocation === 'not-asked' && sync.code === 'STS-PKI-0252',
          'J. a revocation it cannot fetch is not-asked, so refused',
          sync.code + ' ' + sync.why + JSON.stringify(sync.checks));
  const syncExempt = trust.assessSync('spiffe-svid', { leaf: inRealm.pem },
    { anchors: [{ raw: pemDer(root.pem) }], variant: 'federated' });
  t.check(syncExempt.ok, 'J. exempt by spec it holds', syncExempt.why);

  // K. A NAME THE CALLER EXPECTED.
  t.log.info('K. expected names');
  const named = await kit.mint({ cn: 'host', issuer: root,
                                 san: ['DNS:host.example'] });
  const yes = await trust.assess('client-attestation', { leaf: named.pem },
    { anchors: [root.pem], anchorSources: ['caller'],
      expectName: { dns: 'host.example' } });
  t.equal(yes.checks['name-match'], 'passed', 'K. the name it carries');
  const no = await trust.assess('client-attestation', { leaf: named.pem },
    { anchors: [root.pem], anchorSources: ['caller'],
      expectName: { dns: 'other.example' } });
  t.check(!no.ok && no.checks['name-match'] === 'failed',
          'K. a name it does not carry', no.why);
  const dn = await trust.assess('client-attestation', { leaf: named.pem },
    { anchors: [root.pem], anchorSources: ['caller'],
      expectName: { dn: 'cn=HOST' } });
  t.equal(dn.checks['name-match'], 'passed', 'K. a DN, by the one comparison');
  const unasked = await trust.assess('client-attestation', { leaf: named.pem },
    { anchors: [root.pem], anchorSources: ['caller'] });
  t.check(unasked.ok && unasked.checks['name-match'] === 'not-asked',
          'K. no name expected is the one not-asked that passes', unasked.why);
  // L. THE DOORS SIGNERS CALL (Phase 3).
  t.log.info('L. signers');
  const expiredSelf = await kit.mint({ cn: 'expired sp',
    notBefore: now - 3 * kit.DAY, notAfter: now - kit.DAY });
  const goodSelf = await kit.mint({ cn: 'good sp' });
  const pinned = trust.pinnedSync('saml-signer', goodSelf.pem);
  t.check(pinned.ok, 'L. a self-signed SP certificate is accepted by spec',
          pinned.why);
  const pinnedOld = trust.pinnedSync('saml-signer', expiredSelf.pem);
  t.check(!pinnedOld.ok && pinnedOld.code === 'STS-KEYS-0168',
          'L. and held to its validity', pinnedOld.code);
  const wssSelf = trust.pinnedSync('wss-x509-token', goodSelf.pem);
  t.check(!wssSelf.ok && wssSelf.code === 'STS-PKI-0246',
          'L. a use case that refuses self-signed refuses it', wssSelf.code);
  const stranger2 = await kit.mint({ cn: 'stranger issued', issuer: root });
  const unheld = trust.pinnedSync('saml-signer', stranger2.pem);
  t.check(!unheld.ok && unheld.code === 'STS-PKI-0244',
          'L. a CA-issued signer reaching nothing held is refused',
          unheld.code + ' ' + unheld.why);
  await signers.add(REALM, root.pem, {});
  const nowHeld = trust.pinnedSync('saml-signer', stranger2.pem);
  t.check(nowHeld.ok, 'L. and accepted once its CA is in the store',
          nowHeld.why);
  const listedPin = await kit.mint({ cn: 'listed pin', issuer: root,
                                     crls: [crls.base + '/pin.crl'] });
  crls.routes['/pin.crl'] = await kit.crlOf(root, [listedPin.serialHex]);
  const firstAsk = trust.pinnedSync('saml-signer', listedPin.pem);
  t.check(!firstAsk.ok, 'L. a list not yet read is a check nobody made',
          firstAsk.why);
  await new Promise(function (resolve) {
    setTimeout(resolve, 800);
  });
  const secondAsk = trust.pinnedSync('saml-signer', listedPin.pem);
  t.check(!secondAsk.ok && secondAsk.code === 'STS-PKI-0118',
          'L. and once read, it is revoked', secondAsk.code);
  const bareOk = trust.bareKey({ kty: 'EC' });
  t.check(bareOk.ok, 'L. a bare JWK is left alone (OpenID Federation 1.1)', '');
  const carried = trust.bareKey({ kty: 'EC', x5c: [pemDer(expiredSelf.pem)
    .toString('base64')] });
  t.check(!carried.ok, 'L. a JWK carrying an x5c is held to it', carried.why);
  t.check(trust.registrationProblem('saml-signer', expiredSelf.pem) !== null,
          'L. the registration door asks the fields', '');
  t.equal(trust.registrationProblem('saml-signer', goodSelf.pem), null,
          'L. and takes a good certificate');
  const chainOf = await trust.signerChain('jose-signer',
    { certificate: pemDer(goodSelf.pem).toString('base64'), chain: [] });
  t.check(!chainOf.ok && /self-signed/.test(chainOf.why),
          'L. a self-signed x5c[0] is refused for a JOSE signer', chainOf.why);
  const inStore = await kit.mint({ cn: 'jose leaf', issuer: root });
  const viaStore = await trust.signerChain('jose-signer',
    { certificate: inStore.pem, chain: [] });
  t.check(viaStore.ok && viaStore.anchor === 'signer-truststore',
          'L. a chain with no registered root completes from the store',
          viaStore.why);
  await withSettings({ 'pki.paranoid': 'off' }, async () => {
    t.check(trust.pinnedSync('saml-signer', expiredSelf.pem).ok,
            'L. out of force, nothing is asked', '');
    const baseline = await trust.signerChain('jose-signer',
      { certificate: pemDer(goodSelf.pem).toString('base64'), chain: [] });
    t.check(baseline.ok && baseline.anchor === 'pinned',
            'L. and a self-signed x5c[0] is the pin it was', baseline.why);
  });
  double.rows(REALM).clear();
  log.debug("Leaving run().");
}

function pemDer(pem) {
  log.debug("Entering pemDer().");
  log.debug("Leaving pemDer().");
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
}

function good(root) {
  log.debug("Entering good().");
  log.debug("Leaving good().");
  return root.pem;
}
