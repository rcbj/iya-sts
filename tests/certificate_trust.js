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
//    audit row. J: the synchronous door. K: expected names. L: signers.
//    M: encryption recipients. N: the path helpers of Phase 5.
//
// MUTATION RECORD, each applied to a scratch build, seen red and put back:
//   * `readable()` not asked at either door                  — red each
//   * `endingAtAnchor()` not asked (real hosts: STS-PKI-0119) — 1 red
//   * an anchor matched on its subject alone                  — 1 red
//   * the certificates below the anchor dropped from the walk — 1 red
//   * a server accepted without being named                   — 2 red
//   * a truststore anchor counting as a dialer's pin          — 1 red
//   * paranoid not lifting the distribution-point requirement — 1 red
//   * a link with no issuer refused though it names nothing   — 1 red
//   * every link with no issuer passing, naming or not        — 2 red
//   * a pin asking only its own extensions, not the path      — 2 red (L)
//   * `named` ignored at the path, or at the self-signed rule — 1 red (L)
//   * a pin always asking, naming or not                     — 2 red (L)
//   * `fieldChecks()` not marking a failure                  — 53 red
//   * `compose()` letting `not-asked` pass under paranoid    — 2 red (E, J)
//   * the `pinned` condition accepting any self-signed leaf  — 1 red (C)
//   * `anchorsFor()` ignoring `purposes`                     — 1 red (D)
//   * `ruleOf()` ignoring the variant                        — 4 red (B, E, G)
//   * a self-signed x5c[0] left the pin it was under paranoid — 1 red (L)
//   * a chain not completed from the signer truststore       — 1 red (L)
//   * the pinned certificate's fetched verdict never read    — 1 red (L)
//   * a JWK's x5c not held                                   — 1 red (L)
//   * `path()` always the baseline                           — 9 red (N)
//   * a site's anchor entries not read as DER                — 11 red (N)
//   * SCEP's variant asking for clientAuth again             — 2 red (N)
//   * `siteAsksRevocation` ignored                           — 1 red (N)
//   * and honoured with the check switched off               — 1 red (N)
//   * `direct()` assessing an authority that signed nothing  — 1 red (N)
//   * `direct()` skipping the door                           — 2 red (N)
//   * `realmLeaf()` asking no fields                         — 1 red (N)
//   * `fields()` ignoring `only`                             — 1 red (N)
//   * `fields()` ignoring `fieldRole`                        — 1 red (N)
//   * a certificate naming no list still `not-asked`         — 1 red (N)
//   * a CRL's signer not held                                — 1 red (N)
//   * the path's own word for a refusal lost                 — 2 red (N)
//   * `anchorsAvailable()` ignoring the signer truststore    — 1 red (N)
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const audit = require('../common/audit');
const trust = require('../common/certificate_trust');
const stsCrypto = require('../common/crypto');
const cryptoForDoor = require('../common/crypto');
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
  // Nothing is looked up for a pin naming nothing, unless a CA above it does.
  const crossKeysForPins = require('../common/crypto_impl/key_material');
  const quietCa = await kit.mint({ cn: 'pin ca naming nothing', ca: true,
    issuer: root, pair: await crossKeysForPins.generateKeyPair('rsa-2048') });
  const quietPin = await kit.mint({ cn: 'pin naming nothing', issuer: quietCa });
  await signers.add(REALM, quietCa.pem, {});
  const noSource = trust.pinnedSync('saml-signer', quietPin.pem);
  t.check(noSource.ok,
          'L. a pin whose path names no source has no check to perform',
          noSource.why);
  const loudCa = await kit.mint({ cn: 'pin ca naming a list', ca: true,
    issuer: root, crls: [crls.base + '/pin-ca.crl'],
    pair: await crossKeysForPins.generateKeyPair('rsa-2048') });
  crls.routes['/pin-ca.crl'] = await kit.crlOf(root, [loudCa.serialHex]);
  const underLoud = await kit.mint({ cn: 'pin under it', issuer: loudCa });
  await signers.add(REALM, loudCa.pem, {});
  t.check(!trust.pinnedSync('saml-signer', underLoud.pem).ok,
          'L. a CA above the pin naming one is asked', '');
  await new Promise(function (resolve) {
    setTimeout(resolve, 800);
  });
  const caAnswered = trust.pinnedSync('saml-signer', underLoud.pem);
  t.check(!caAnswered.ok && caAnswered.code === 'STS-PKI-0118',
          'L. and its answer about that CA holds', caAnswered.code);
  // NAMED: an administrator's act stored it, so it needs no path (rcbj).
  const namedPin = await kit.mint({ cn: 'named pin', issuer: await kit.mint(
    { cn: 'a ca nobody holds', ca: true,
      pair: await crossKeysForPins.generateKeyPair('rsa-2048') }) });
  t.check(!trust.pinnedSync('saml-signer', namedPin.pem).ok &&
          trust.pinnedSync('saml-signer', namedPin.pem, { named: true }).ok,
          'L. a certificate named by an administrator needs no path', '');
  t.check(trust.pinnedSync('wss-x509-token', goodSelf.pem,
                           { named: true }).ok,
          'L. nor is a self-signed one refused for being that', '');
  t.check(!trust.pinnedSync('saml-signer', expiredSelf.pem,
                            { named: true }).ok,
          'L. and its validity still counts', '');
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
  // M. AN ENCRYPTION RECIPIENT (Phase 4).
  t.log.info('M. encryption recipients');
  const signsOnly = await kit.mint({ cn: 'cannot encipher', usages:
                                     ['digitalSignature'] });
  const enciphers = await kit.mint({ cn: 'enciphers', usages:
                                     ['keyEncipherment'] });
  const noEnc = trust.pinnedSync('encryption-recipient', signsOnly.pem);
  t.check(!noEnc.ok && noEnc.code === 'STS-KEYS-0171',
          'M. a certificate that may not encipher is refused', noEnc.code);
  t.check(trust.pinnedSync('encryption-recipient', enciphers.pem).ok,
          'M. one that may is accepted, self-signed by spec', '');
  const encOld = await kit.mint({ cn: 'old recipient', usages:
    ['keyEncipherment'], notBefore: now - 3 * kit.DAY,
    notAfter: now - kit.DAY });
  t.check(!trust.pinnedSync('encryption-recipient', encOld.pem).ok,
          'M. an expired one is refused', '');
  t.check(trust.registrationProblem('encryption-recipient',
                                    signsOnly.pem) !== null,
          'M. and at the door', '');
  // N. THE PATH HELPERS (Phase 5): a site's shape kept, the checks added.
  t.log.info('N. attestation, enrollment and credential paths');
  const pki = require('../common/pki');
  const nRoot = await kit.mint({ cn: 'n root', ca: true });
  const nMiddle = await kit.mint({ cn: 'n middle', ca: true, issuer: nRoot });
  const nLeaf = await kit.mint({ cn: 'n leaf', issuer: nMiddle });
  const nDer = function (one) {
    log.debug("Entering nDer().");
    log.debug("Leaving nDer().");
    return pemDer(one.pem);
  };
  const nPath = function (id, leaf, intermediates, options) {
    log.debug("Entering nPath().");
    log.debug("Leaving nPath().");
    return trust.path(id, nDer(leaf), intermediates.map(nDer),
                      [pki.certificateFromDer(nDer(nRoot))], options);
  };
  const nAnchored = await nPath('device-attestation', nLeaf, [nMiddle]);
  t.check(nAnchored.ok && nAnchored.anchor === 'caller' &&
          !!nAnchored.chain[0].x509,
          'N. a good path answers the shape a site reads', nAnchored.reason);
  const encipherer = await kit.mint({ cn: 'n encipherer', issuer: nRoot,
                                      usages: ['keyEncipherment'] });
  const fieldBad = await nPath('device-attestation', encipherer, []);
  t.check(!fieldBad.ok && fieldBad.code === 'STS-KEYS-0171' &&
          fieldBad.check === 'paranoid',
          'N. a leaf whose field fails is refused by name', fieldBad.reason);
  const unrelated = await kit.mint({ cn: 'n stranger',
                                     issuer: await kit.mint({ cn: 'n other',
                                                              ca: true }) });
  const noPath = await nPath('device-attestation', unrelated, []);
  t.check(!noPath.ok && noPath.check === 'no-path',
          'N. a rule the path broke keeps that function\'s word for it',
          noPath.check);
  const nKeys = require('../common/crypto_impl/key_material');
  const forgedCa = await kit.mint({ cn: 'n root', ca: true,
    pair: await nKeys.generateKeyPair('rsa-2048') });
  const forged = await kit.mint({ cn: 'n forged', issuer: forgedCa });
  const badSignature = await nPath('pkinit', forged, []);
  const badOff = await withSettings({ 'pki.paranoid': 'off' }, function () {
    return nPath('pkinit', forged, []);
  });
  t.equal(badSignature.check, badOff.check,
          'N. in force and out, PKINIT reads the same refusal off a forged ' +
          'link');
  const noAik = await nPath('webauthn-attestation', nLeaf, [nMiddle],
                            { variant: 'tpm' });
  t.check(!noAik.ok && noAik.code === 'STS-KEYS-0172',
          'N. a TPM attestation needs the AIK extendedKeyUsage', noAik.code);
  const aik = await kit.mint({ cn: 'n aik', issuer: nRoot,
                               eku: [stsCrypto.EKU.tcgAik] });
  t.check((await nPath('webauthn-attestation', aik, [],
                       { variant: 'tpm' })).ok, 'N. and passes with it', '');
  t.check((await nPath('webauthn-attestation', nLeaf, [nMiddle])).ok,
          'N. another format is not asked for it', '');
  const notDs = await nPath('vc-issuer', nLeaf, [nMiddle], { variant: 'mdoc' });
  t.check(!notDs.ok && notDs.code === 'STS-KEYS-0172',
          'N. an mdoc signer needs the document-signer EKU', notDs.code);
  const ds = await kit.mint({ cn: 'n ds', issuer: nRoot,
                              eku: [stsCrypto.EKU.mdocDs] });
  t.check((await nPath('vc-issuer', ds, [], { variant: 'mdoc' })).ok,
          'N. and passes with it', '');
  t.check(!(await nPath('spiffe-attestation', encipherer, [])).ok &&
          (await nPath('spiffe-attestation', encipherer, [],
                       { variant: 'tpm-ek' })).ok,
          'N. an endorsement key enciphers, and only that variant says so', '');
  const nFulcio = await kit.mint({ cn: 'n fulcio', ca: true,
                                  notBefore: now - 10 * kit.DAY });
  const lapsed = await kit.mint({ cn: 'n lapsed', issuer: nFulcio,
    eku: [stsCrypto.EKU.codeSigning], notBefore: now - 3 * kit.DAY,
    notAfter: now - kit.DAY });
  const sigstorePath = await trust.path('spiffe-attestation', nDer(lapsed), [],
    [pki.certificateFromDer(nDer(nFulcio))],
    { variant: 'sigstore', now: now - 2 * kit.DAY });
  t.check(sigstorePath.ok, 'N. sigstore reads a certificate at its notBefore',
          sigstorePath.reason);
  const selfLeaf = await kit.mint({ cn: 'n self leaf' });
  const selfAnchored = await trust.path('client-attestation', nDer(selfLeaf),
    [], [pki.certificateFromDer(nDer(selfLeaf))]);
  t.check(!selfAnchored.ok && selfAnchored.code === 'STS-PKI-0249',
          'N. a self-signed leaf is not its own anchor', selfAnchored.reason);
  const nStoreRoot = await kit.mint({ cn: 'n store root', ca: true });
  const nStoreLeaf = await kit.mint({ cn: 'n store leaf', issuer: nStoreRoot });
  await signers.add(REALM, nStoreRoot.pem, {});
  const nViaStore = await nPath('webauthn-attestation', nStoreLeaf, []);
  t.check(nViaStore.ok && nViaStore.anchor === 'signer-truststore',
          'N. a use case that reaches the signer truststore finds it there',
          nViaStore.reason);
  t.check(!(await nPath('pkinit', nStoreLeaf, [])).ok,
          'N. and one that does not, does not', '');
  t.check(trust.anchorsAvailable('webauthn-attestation', []) &&
          !trust.anchorsAvailable('pkinit', []),
          'N. so with no configured anchors the store is still something to ' +
          'reach, for the use case that may', '');
  await withSettings({ 'pki.paranoid': 'off' }, async () => {
    t.check(!trust.anchorsAvailable('webauthn-attestation', []),
            'N. and out of force it is not', '');
  });
  const listedLeaf = await kit.mint({ cn: 'n listed', issuer: nRoot,
                                      crls: [crls.base + '/n.crl'] });
  crls.routes['/n.crl'] = await kit.crlOf(nRoot, [listedLeaf.serialHex]);
  const nRevoked = await nPath('device-attestation', listedLeaf, []);
  t.check(!nRevoked.ok && nRevoked.code === 'STS-PKI-0118',
          'N. revocation is asked', nRevoked.code + ' ' + nRevoked.reason);
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async () => {
    const noneNamed = await nPath('device-attestation', nLeaf, [nMiddle]);
    t.check(noneNamed.ok, 'N. under hard-fail, a hardware chain naming ' +
            'nothing is not refused for it', noneNamed.reason);
    t.check((await nPath('client-attestation', nLeaf, [nMiddle])).ok &&
            (await nPath('vc-key-attestation', nLeaf, [nMiddle])).ok &&
            (await nPath('vc-issuer', nLeaf, [nMiddle])).ok,
            'N. and no use case is treated differently', '');
  });
  await withSettings({ 'pki.revocationCheck': 'hard-fail',
                       'pki.revocationRequireDistributionPoint': 'on' },
                     async () => {
    t.check(!(await nPath('device-attestation', nLeaf, [nMiddle])).ok &&
            !(await nPath('vc-issuer', nLeaf, [nMiddle])).ok,
            'N. an operator who set the requirement `on` refuses it everywhere',
            '');
  });
  const asksItself = await nPath('device-attestation', listedLeaf, [],
                                 { siteAsksRevocation: true });
  t.check(asksItself.ok, 'N. and a site that asks for itself is left to it',
          asksItself.reason);
  await withSettings({ 'pki.revocationCheck': 'off' }, async () => {
    const nobody = await nPath('device-attestation', listedLeaf, [],
                               { siteAsksRevocation: true });
    t.check(!nobody.ok, 'N. unless the check is off, when nobody asked',
            nobody.reason);
  });
  await withSettings({ 'pki.paranoid': 'off' }, async () => {
    t.check((await nPath('device-attestation', listedLeaf, [])).ok &&
            (await nPath('device-attestation', encipherer, [])).ok,
            'N. out of force the path is all that is asked', '');
  });
  // The one-hop door.
  const nAuthority = [{ raw: nDer(nRoot) }];
  const svid = await kit.mint({ cn: 'n svid', issuer: nRoot,
    eku: [stsCrypto.EKU.clientAuth] });
  const svidOk = trust.direct('spiffe-svid', nDer(svid), nAuthority);
  t.check(svidOk.ok && !!svidOk.chain,
          'N. an SVID naming no list passes the door that cannot wait',
          svidOk.reason);
  const noEkuSvid = trust.direct('spiffe-svid', nDer(nLeaf),
                                 [{ raw: nDer(nMiddle) }]);
  t.check(!noEkuSvid.ok && noEkuSvid.code === 'STS-KEYS-0172',
          'N. an SVID needs the extendedKeyUsage', noEkuSvid.code);
  const nAssessed = function () {
    log.debug("Entering nAssessed().");
    log.debug("Leaving nAssessed().");
    return (trust.counters(REALM)['spiffe-svid'] || {}).assessed || 0;
  };
  const assessedBefore = nAssessed();
  t.equal(trust.direct('spiffe-svid', nDer(unrelated), nAuthority).check,
          'no-path', 'N. another authority\'s is left for the next authority');
  t.equal(nAssessed(), assessedBefore, 'N. and nothing is counted for trying');
  const svidListed = await kit.mint({ cn: 'n svid listed', issuer: nRoot,
    eku: [stsCrypto.EKU.clientAuth], crls: [crls.base + '/none.crl'] });
  const cannotWait = trust.direct('spiffe-svid', nDer(svidListed), nAuthority);
  t.check(!cannotWait.ok, 'N. one naming a list is a check nobody made',
          cannotWait.reason);
  t.check(trust.direct('spiffe-svid', nDer(svidListed), nAuthority,
                       { variant: 'federated' }).ok,
          'N. except a federated one, whose authority publishes nothing here',
          '');
  // The realm's own leaf: `verifyLeaf()` is a double here, since what is under
  // test is what the door adds to its answer. `tests/pki.js` holds the rest.
  const realLeaf = pki.verifyLeaf;
  pki.verifyLeaf = async function () {
    return { ok: true, revocation: { status: 'good' } };
  };
  try {
    const held = await trust.realmLeaf('enrollment-credential', REALM,
                                       nLeaf.pem, []);
    t.check(!held.ok && /extended/i.test(held.why),
            'N. the realm\'s own leaf is held to the fields as well', held.why);
    t.check((await trust.realmLeaf('enrollment-credential', REALM, svid.pem,
                                   [])).ok, 'N. and passes them', '');
    // SCEP's renewal: signed by the certificate being renewed, whatever its EKU.
    const serverCert = await kit.mint({ cn: 'n scep server', issuer: nRoot,
      eku: [stsCrypto.EKU.serverAuth] });
    t.check(!(await trust.realmLeaf('enrollment-credential', REALM,
                                    serverCert.pem, [])).ok,
            'N. a server certificate is no EST client', '');
    const scepHeld = await trust.realmLeaf('enrollment-credential', REALM,
      serverCert.pem, [], { variant: 'scep' });
    t.check(scepHeld.ok, 'N. and may renew itself over SCEP', scepHeld.why);
    const scepSigner = trust.assessSync('enrollment-credential',
      { leaf: serverCert.pem, pinned: true }, { variant: 'scep' });
    t.check(scepSigner.ok, 'N. at the signature as well', scepSigner.why);
    await withSettings({ 'pki.paranoid': 'off' }, async () => {
      t.check((await trust.realmLeaf('enrollment-credential', REALM, nLeaf.pem,
                                     [])).ok,
              'N. out of force, it is that function\'s answer', '');
    });
  } finally {
    pki.verifyLeaf = realLeaf;
  }
  // Fields alone.
  const aged = await kit.mint({ cn: 'n aged', notBefore: now - 3 * kit.DAY,
                                notAfter: now - kit.DAY });
  const weakKu = await kit.mint({ cn: 'n ku', usages: ['keyEncipherment'] });
  t.check(trust.fields('spiffe-attestation', weakKu.pem,
                       { variant: 'aws', only: ['validity'] }).ok &&
          !trust.fields('spiffe-attestation', aged.pem,
                        { variant: 'aws', only: ['validity'] }).ok,
          'N. a pin is asked its window and nothing else', '');
  t.check(!trust.fields('spiffe-attestation', weakKu.pem, {}).ok,
          'N. while no `only` asks everything', '');
  const signsCertsOnly = await kit.mint({ cn: 'n not a ca', issuer: nRoot,
                                          usages: ['keyCertSign'] });
  t.check(!trust.fields('spiffe-svid', signsCertsOnly.pem,
                        { variant: 'federated-authority',
                          fieldRole: 'anchor' }).ok &&
          trust.fields('spiffe-svid', nRoot.pem,
                       { variant: 'federated-authority',
                         fieldRole: 'anchor' }).ok,
          'N. a federated authority must be a certificate authority', '');
  const responder = await kit.mint({ cn: 'n responder', issuer: nRoot,
    eku: [stsCrypto.EKU.ocspSigning] });
  t.check(trust.fields('revocation-signer', responder.pem).ok &&
          !trust.fields('revocation-signer', nLeaf.pem).ok,
          'N. a responder needs id-kp-OCSPSigning', '');
  // A list signed by an authority whose own window has closed.
  const agedCa = await kit.mint({ cn: 'n aged ca', ca: true,
    notBefore: now - 3 * kit.DAY, notAfter: now - kit.DAY });
  const underAged = await kit.mint({ cn: 'n under aged', issuer: agedCa,
    notBefore: now - 2 * kit.DAY, notAfter: now + kit.DAY,
    crls: [crls.base + '/aged.crl'] });
  crls.routes['/aged.crl'] = await kit.crlOf(agedCa, []);
  const revocationStatus = require('../common/revocation_status');
  const agedVerdict = await revocationStatus.verdictFor(
    { leaf: nDer(underAged), chain: [nDer(agedCa)], verified: true }, {});
  t.check(agedVerdict.status !== 'good' &&
          /its signer is refused/.test(JSON.stringify(agedVerdict)),
          'N. a CRL\'s signer is held to the fields too',
          JSON.stringify(agedVerdict).slice(0, 300));
  // A second list: what the first answered is remembered by its address.
  const underAgedToo = await kit.mint({ cn: 'n under aged too', issuer: agedCa,
    notBefore: now - 2 * kit.DAY, notAfter: now + kit.DAY,
    crls: [crls.base + '/aged-too.crl'] });
  crls.routes['/aged-too.crl'] = await kit.crlOf(agedCa, []);
  const stillGood = await withSettings({ 'pki.paranoid': 'off' }, function () {
    return revocationStatus.verdictFor(
      { leaf: nDer(underAgedToo), chain: [nDer(agedCa)], verified: true }, {});
  });
  t.check(!/its signer is refused/.test(JSON.stringify(stillGood)),
          'N. and only in force', JSON.stringify(stillGood).slice(0, 300));
  double.rows(REALM).clear();
  // A CHAIN ENDING IN A CROSS-SIGNED ROOT (the shape of every Google endpoint):
  // a root the store holds, sent as a copy another root signed, whose issuer is
  // not sent. Hard-fail refused it for having no issuer until the walk stopped
  // at the anchor. Generated here: nothing in the suite depends on a real host.
  t.log.info('a chain ending in a cross-signed root');
  const crossKeys = require('../common/crypto_impl/key_material');
  const crossPair = await crossKeys.generateKeyPair('rsa-2048');
  const crossRoot = await kit.mint({ cn: 'cross root', ca: true,
                                     pair: crossPair });
  const olderRoot = await kit.mint({ cn: 'older root', ca: true,
    pair: await crossKeys.generateKeyPair('rsa-2048') });
  // It names a list, as GTS Root R4 does, or there would be nothing to ask.
  const crossCopy = await kit.mint({ cn: 'cross root', ca: true,
                                     issuer: olderRoot, pair: crossPair,
                                     crls: ['http://127.0.0.1:1/older.crl'] });
  const crossCrls = await kit.crlServer();
  const crossLeaf = await kit.mint({ cn: 'cross leaf', issuer: crossRoot,
    usages: ['digitalSignature', 'keyEncipherment'], eku: ['serverAuth'],
    crls: [crossCrls.base + '/cross.crl'] });
  crossCrls.routes['/cross.crl'] = await kit.crlOf(crossRoot, []);
  const peerOf = function (one, above) {
    log.debug("Entering peerOf().");
    log.debug("Leaving peerOf().");
    return { raw: pemDer(one.pem), issuerCertificate: above };
  };
  const crossPeer = peerOf(crossLeaf, peerOf(crossCopy));
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async () => {
    const unheld = await trust.assessPeer('tls-server-outbound', crossPeer,
                                          { realmId: REALM });
    t.check(!unheld.ok && unheld.code === 'STS-PKI-0119',
            'with no anchor held, what is above it has no issuer to ask',
            String(unheld.code) + ' ' + unheld.why);
    await signers.add(REALM, crossRoot.pem, {});
    const heldRoot = await trust.assessPeer('tls-server-outbound', crossPeer,
                                            { realmId: REALM });
    t.check(heldRoot.ok,
            'with the root held, the path ends at it and the peer passes',
            String(heldRoot.why));
    const revokedPeer = await kit.mint({ cn: 'cross revoked', issuer: crossRoot,
      usages: ['digitalSignature', 'keyEncipherment'], eku: ['serverAuth'],
      crls: [crossCrls.base + '/crossr.crl'] });
    crossCrls.routes['/crossr.crl'] = await kit.crlOf(crossRoot,
                                                     [revokedPeer.serialHex]);
    const stillAsked = await trust.assessPeer('tls-server-outbound',
      peerOf(revokedPeer, peerOf(crossCopy)), { realmId: REALM });
    t.check(!stillAsked.ok && stillAsked.code === 'STS-PKI-0118',
            'and a leaf below that anchor is still asked about revocation',
            stillAsked.code + ' ' + stillAsked.why);
    // An intermediate below the anchor is walked too.
    const crossMiddle = await kit.mint({ cn: 'cross middle', ca: true,
      issuer: crossRoot, crls: [crossCrls.base + '/crossm.crl'],
      pair: await crossKeys.generateKeyPair('rsa-2048') });
    const underMiddle = await kit.mint({ cn: 'under middle',
      issuer: crossMiddle, usages: ['digitalSignature', 'keyEncipherment'],
      eku: ['serverAuth'], crls: [crossCrls.base + '/under.crl'] });
    crossCrls.routes['/under.crl'] = await kit.crlOf(crossMiddle, []);
    crossCrls.routes['/crossm.crl'] = await kit.crlOf(crossRoot,
                                                     [crossMiddle.serialHex]);
    const revokedMiddle = await trust.assessPeer('tls-server-outbound',
      peerOf(underMiddle, peerOf(crossMiddle, peerOf(crossCopy))),
      { realmId: REALM });
    t.check(!revokedMiddle.ok && revokedMiddle.code === 'STS-PKI-0118',
            'a revoked intermediate below the anchor is refused',
            revokedMiddle.code + ' ' + revokedMiddle.why);
    // The anchor's subject under another key is not the anchor, so the walk
    // does not stop there, and this one still has no issuer to ask.
    const sameName = await kit.mint({ cn: 'cross root', ca: true,
      issuer: olderRoot, crls: [crossCrls.base + '/samename.crl'],
      pair: await crossKeys.generateKeyPair('rsa-2048') });
    const underName = await kit.mint({ cn: 'under the same name',
      issuer: sameName, usages: ['digitalSignature', 'keyEncipherment'],
      eku: ['serverAuth'], crls: [crossCrls.base + '/name.crl'] });
    crossCrls.routes['/name.crl'] = await kit.crlOf(sameName, []);
    const named = await trust.assessPeer('tls-server-outbound',
      peerOf(underName, peerOf(sameName)), { realmId: REALM });
    t.check(!named.ok && /neither held here nor in the chain/.test(named.why),
            'the anchor\'s subject under another key does not stop the walk',
            named.code + ' ' + named.why);
    // And a good path through that same-named CA is not cut short at it.
    // Stopped there, the leaf would be asked against a key that never signed it.
    await signers.add(REALM, olderRoot.pem, {});
    crossCrls.routes['/samename.crl'] = await kit.crlOf(olderRoot, []);
    const through = await trust.assessPeer('tls-server-outbound',
      peerOf(underName, peerOf(sameName, peerOf(olderRoot))),
      { realmId: REALM });
    t.check(through.ok, 'and a good path through it goes on to its real anchor',
            String(through.why));
  });
  await crossCrls.close();
  // ONE CERTIFICATE ACCEPTED BY NAME (rcbj): the door's half. The gate's is
  // `tests/outbound_gate.js` section I, over real handshakes.
  t.log.info('a server certificate accepted case by case');
  const appliance = await kit.mint({ cn: 'an appliance', eku: ['serverAuth'],
    usages: ['digitalSignature', 'keyEncipherment'] });
  const appliancePeer = peerOf(appliance);
  const asAppliance = function (options) {
    log.debug("Entering asAppliance().");
    log.debug("Leaving asAppliance().");
    return trust.assessPeer('tls-server-outbound', appliancePeer,
                            Object.assign({ realmId: REALM }, options || {}));
  };
  const notNamed = await asAppliance();
  t.check(!notNamed.ok && /self-signed/.test(notNamed.why),
          'a self-signed server nobody named is refused', notNamed.why);
  const offered = await signers.add(REALM, appliance.pem, { kind: 'accepted' });
  t.check(offered.added.length === 1 && offered.added[0].kind === 'accepted' &&
          offered.added[0].purposes[0] === 'tls-server-outbound',
          'accepted by name, for outbound TLS alone',
          JSON.stringify(offered.refused));
  const nowNamed = await asAppliance();
  t.check(nowNamed.ok, 'and the same server then passes', nowNamed.why);
  t.check(!signers.anchorsFor(REALM).anchors.concat(
    signers.anchorsFor(REALM).intermediates).some(function (der) {
    return der.equals(pemDer(appliance.pem));
  }), 'it is no step on anybody\'s path', '');
  // NO SOURCE NAMED, NO CHECK TO PERFORM (rcbj). A private CA's leaf naming no
  // list passes under hard-fail; one naming a list that says revoked, or that
  // cannot be reached, does not; and a CA's own source is asked.
  const privateCa = await kit.mint({ cn: 'a private ca', ca: true,
    pair: await crossKeys.generateKeyPair('rsa-2048') });
  const serverLeaf = { usages: ['digitalSignature', 'keyEncipherment'],
                       eku: ['serverAuth'] };
  const privateLeaf = await kit.mint(Object.assign({ cn: 'a partner on it',
                                                     issuer: privateCa },
                                                   serverLeaf));
  await signers.add(REALM, privateCa.pem, {});
  const lists = await kit.crlServer();
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async () => {
    const silent = await trust.assessPeer('tls-server-outbound',
      peerOf(privateLeaf, peerOf(privateCa)), { realmId: REALM });
    t.check(silent.ok, 'no source named anywhere: no check, and it passes',
            String(silent.why));
    const noIssuer = await trust.assessPeer('tls-server-outbound',
      peerOf(privateLeaf), { realmId: REALM });
    t.check(noIssuer.ok, 'and with its issuer not presented either',
            String(noIssuer.why));
    const revokedOne = await kit.mint(Object.assign({ cn: 'names and revoked',
      issuer: privateCa, crls: [lists.base + '/nr.crl'] }, serverLeaf));
    lists.routes['/nr.crl'] = await kit.crlOf(privateCa,
                                              [revokedOne.serialHex]);
    const namedRevoked = await trust.assessPeer('tls-server-outbound',
      peerOf(revokedOne, peerOf(privateCa)), { realmId: REALM });
    t.check(!namedRevoked.ok && namedRevoked.code === 'STS-PKI-0118',
            'a source named that says revoked is refused',
            namedRevoked.code + ' ' + namedRevoked.why);
    const deadOne = await kit.mint(Object.assign({ cn: 'names a dead list',
      issuer: privateCa, crls: ['http://127.0.0.1:1/dead.crl'] }, serverLeaf));
    const namedDead = await trust.assessPeer('tls-server-outbound',
      peerOf(deadOne, peerOf(privateCa)), { realmId: REALM });
    t.check(!namedDead.ok && namedDead.checks.revocation === 'failed',
            'a source named that cannot be reached is refused under hard-fail',
            String(namedDead.why));
    // A CA naming a source is asked, and the leaf naming none gets no lookup.
    const middle = await kit.mint({ cn: 'a ca naming a list', ca: true,
      issuer: privateCa, crls: [lists.base + '/mid.crl'],
      pair: await crossKeys.generateKeyPair('rsa-2048') });
    const under = await kit.mint(Object.assign({ cn: 'names nothing itself',
                                                 issuer: middle }, serverLeaf));
    lists.routes['/mid.crl'] = await kit.crlOf(privateCa, []);
    const fine = await trust.assessPeer('tls-server-outbound',
      peerOf(under, peerOf(middle, peerOf(privateCa))), { realmId: REALM });
    t.check(fine.ok,
            'a leaf naming nothing under a CA whose list clears it passes',
            String(fine.why));
    const middleRevoked = await kit.mint({ cn: 'a ca that is revoked', ca: true,
      issuer: privateCa, crls: [lists.base + '/mid3.crl'],
      pair: await crossKeys.generateKeyPair('rsa-2048') });
    lists.routes['/mid3.crl'] = await kit.crlOf(privateCa,
                                                [middleRevoked.serialHex]);
    const underRevoked = await kit.mint(Object.assign({ cn: 'under it',
      issuer: middleRevoked }, serverLeaf));
    const caRevoked = await trust.assessPeer('tls-server-outbound',
      peerOf(underRevoked, peerOf(middleRevoked, peerOf(privateCa))),
      { realmId: REALM });
    t.check(!caRevoked.ok && caRevoked.code === 'STS-PKI-0118',
            'and is refused when that CA is revoked',
            caRevoked.code + ' ' + caRevoked.why);
  });
  await withSettings({ 'pki.revocationCheck': 'hard-fail',
                       'pki.revocationRequireDistributionPoint': 'on' },
    async () => {
      t.check(!(await trust.assessPeer('tls-server-outbound',
        peerOf(privateLeaf, peerOf(privateCa)), { realmId: REALM })).ok,
        'an operator who set the requirement `on` still gets it', '');
    });
  // Development mode never asks for a distribution point, so the requirement
  // being lifted is visible only in product: `auto` asks for one there unless
  // paranoid is in force, which has a sharper rule of its own.
  const requires = async function (pairs) {
    return await withSettings(
      Object.assign({ 'global.mode': 'product' }, pairs),
      async () => require('../common/revocation_status')
        .policy().requireDistributionPoint);
  };
  t.equal(await requires({ 'pki.paranoid': 'on' }), false,
          'in product, paranoid in force lifts `auto`\'s requirement');
  t.equal(await requires({ 'pki.paranoid': 'off' }), true,
          'in product without it, `auto` still asks for a source');
  await lists.close();
  const acceptedRoot = await signers.add(REALM,
    (await kit.mint({ cn: 'a ca offered by name', ca: true })).pem,
    { kind: 'accepted' });
  t.check(!acceptedRoot.added.length &&
          acceptedRoot.refused[0].code === 'STS-PKI-0267',
          'a CA cannot be accepted by name: it would vouch for what it signs',
          JSON.stringify(acceptedRoot.refused));
  const lapsedOffer = await signers.add(REALM,
    (await kit.mint({ cn: 'lapsed appliance', notBefore: now - 3 * kit.DAY,
                      notAfter: now - kit.DAY })).pem, { kind: 'accepted' });
  t.check(!lapsedOffer.added.length,
          'nor can one that is out of date', '');
  signers.remove(REALM, offered.added[0].fingerprint256);
  t.check(!(await asAppliance()).ok, 'removing the row takes it back', '');
  const pinnedOk = await asAppliance({ pinnedTo: ['x', appliance.pem] });
  t.check(pinnedOk.ok, 'a dialer configured with it has named it',
          pinnedOk.why);
  // Fit for a server in every field, so only the rule can refuse it.
  const anchorAsServer = await kit.mint({ cn: 'an anchor as a server', ca: true,
    usages: ['digitalSignature', 'keyEncipherment', 'keyCertSign'],
    eku: ['serverAuth'] });
  const heldAnchor = await signers.add(REALM, anchorAsServer.pem, {});
  t.equal(heldAnchor.added.length, 1, 'an anchor is held');
  const asAnchor = await trust.assessPeer('tls-server-outbound',
    peerOf(anchorAsServer), { realmId: REALM, pinnedTo: anchorAsServer.pem });
  t.check(!asAnchor.ok, 'a truststore anchor in a dialer\'s `ca` names no server',
          String(asAnchor.why));

  // UNREADABLE (x509-limbo found one): node reads it and the field checks cannot.
  // The second parser is a double, since what is under test is that the door
  // answers a verdict; which bytes split the two parsers is not this file's.
  t.log.info('unreadable by the field checks');
  const unreadableRoot = await kit.mint({ cn: 'unreadable root', ca: true });
  const unreadableLeaf = await kit.mint({ cn: 'unreadable',
                                          issuer: unreadableRoot });
  const realFacts = cryptoForDoor.certificateFacts;
  cryptoForDoor.certificateFacts = function () {
    throw new Error('a double: the second parser refuses it');
  };
  try {
    const asked = await trust.assess('device-attestation',
      { leaf: unreadableLeaf.pem }, { anchors: [unreadableRoot.pem] });
    t.check(!asked.ok && asked.code === 'STS-PKI-0238',
            'a certificate the field checks cannot read is a verdict, not a ' +
            'throw', asked.code);
    const askedSync = trust.assessSync('spiffe-svid',
      { leaf: unreadableLeaf.pem },
      { anchors: [{ raw: pemDer(unreadableRoot.pem) }] });
    t.check(!askedSync.ok && askedSync.code === 'STS-PKI-0238',
            'and the same at the door that cannot wait', askedSync.code);
  } finally {
    cryptoForDoor.certificateFacts = realFacts;
  }
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
