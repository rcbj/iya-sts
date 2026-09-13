'use strict';
//
// File: pki_anchor_drift.js
//
// ===========================================================================
// THE ANCHOR THIS SERVICE PUBLISHES MUST SIGN THE CHAIN IT PUBLISHES.
//
// On 2026-09-11 it stopped doing, and the shape of that failure is the reason
// this file exists rather than an assertion tacked onto `tests/pki.js`.
//
// `tls/tls_server.js` publishes a truststore at `GET /tls/server-certificate`:
// the listener's leaf, the chain it travels with, and the Root to verify them
// against. **The leaf and chain are a SNAPSHOT** — taken when the listener was
// certified — and **the Root is read LIVE** from `common/pki.js`. Replace the
// Root without rebuilding the branch under it and the two halves are from
// different hierarchies.
//
// ---------------------------------------------------------------------------
// WHY IT SURVIVED BEING LOOKED AT, WHICH IS THE PART WORTH KEEPING.
//
// Every Root this service builds is called `<organisation> Root CA`. So the
// broken bundle has four certificates with exactly the right subjects, exactly
// the right issuers, in exactly the right order, and the Root's KEY is not the
// one that signed the Intermediate. Nothing that compares names can see it:
// not the console, not `openssl x509 -subject`, not a log line.
//
// **AND CURL ACCEPTS IT WHILE NODE DOES NOT.** `curl --cacert` was the obvious
// way to check by hand and answered 200; every node client answered `unable to
// get local issuer certificate`. Node clients are this repository's entire
// protocol suite and this service's own OpenID Connect back channel, so the
// symptom was ~25 jobs per mode failing at their first request, two more
// spinning until the 300s watchdog, and every hosted-surface sign-in failing —
// none of which names a certificate.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED, AND WHY IT IS THE SIGNATURE RATHER THAN THE NAMES.
//
//   1. The normal case: the published anchor verifies the published chain.
//   2. **THE DRIFT IS REPAIRED RATHER THAN DETECTED.** `common/pki.js`'s
//      `certify()` rebuilds a branch that no longer chains to the Root before
//      it issues anything from it, so a leaf carrying a dead chain never
//      exists. That is the fix; the guard in `tls_server.js` is the net under
//      it.
//   3. The bundle verifies the way a CLIENT verifies it — `openssl verify`
//      semantics, through node's own X509 API — rather than by this file
//      agreeing with the code that built it.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS. The drift needs a Root replaced WITHOUT its branches, and no
// endpoint offers that: `/admin-api/pki/build-root` rebuilds every scope in the
// same act, which is correct and is why driving the API cannot reach this
// state. `pki.buildRoot()` alone can, and only a caller inside the process can
// make it.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const tls = require('../tls/tls_server');
const pki = require('../common/pki');

// Does `anchor` carry the signature over the top of `chain`? The whole check,
// and it is the SIGNATURE because the names are identical on both sides of the
// bug this pins.
function anchorSignsChain(anchorPem, chainPem, leafPem) {
  const topPem = chainPem.length ? chainPem[chainPem.length - 1] : leafPem;
  if (!anchorPem || !topPem) {
    return false;
  }
  return new nodeCrypto.X509Certificate(topPem)
    .verify(new nodeCrypto.X509Certificate(anchorPem).publicKey);
}

// Every link, leaf upwards — so a failure says WHICH one broke rather than
// that the bundle is bad.
function everyLinkVerifies(leafPem, chainPem, anchorPem) {
  const certs = [leafPem].concat(chainPem).concat(anchorPem ? [anchorPem] : [])
    .map(function (pem) { return new nodeCrypto.X509Certificate(pem); });
  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i].verify(certs[i + 1].publicKey)) {
      return i;
    }
  }
  return -1;
}

async function run(t) {
  await pki.start();

  t.log.info('=== the ordinary case ===');
  const good = tls.serverCertificate();
  t.check(good.certPem, 'the listener has a certificate');
  t.check(good.chainPem.length > 0,
          'and it is CERTIFIED rather than self-signed, so there is a chain ' +
          'to be wrong about', good.chainPem.length + ' link(s)');
  t.check(!!good.trustAnchorPem, 'and an anchor is published');
  t.check(anchorSignsChain(good.trustAnchorPem, good.chainPem, good.certPem),
          'THE PUBLISHED ANCHOR SIGNS THE PUBLISHED CHAIN. Checked by ' +
          'signature and not by name: the two Roots this exists to tell ' +
          'apart have identical subjects');
  t.equal(everyLinkVerifies(good.certPem, good.chainPem, good.trustAnchorPem), -1,
          'and every link from the leaf up verifies');

  const rootBefore = pki.serviceRoot();
  t.check(rootBefore && good.trustAnchorPem === rootBefore.certificatePem,
          'the anchor IS the service Root in the ordinary case — the repair ' +
          'below must not be achieved by quietly publishing something else');

  t.log.info('=== the Root is replaced and the branch is left behind ===');
  // THE DRIFT, made the only way it can be. See the header: no endpoint
  // reaches this state, because the console's control rebuilds every branch in
  // the same act.
  const replaced = await pki.buildRoot({ organisation: 'sts' });
  t.check(replaced.ok, 'a new Root is built', (replaced.errors || []).join(' '));
  const rootAfter = pki.serviceRoot();
  t.check(rootAfter.certificatePem !== rootBefore.certificatePem,
          'and it really is a different Root');
  t.check(new nodeCrypto.X509Certificate(rootAfter.certificatePem).subject ===
          new nodeCrypto.X509Certificate(rootBefore.certificatePem).subject,
          'WITH THE SAME SUBJECT as the one it replaced, which is why nothing ' +
          'that compares names can see this state',
          new nodeCrypto.X509Certificate(rootAfter.certificatePem).subject
            .replace(/\n/g, ', '));

  // The listener is untouched at this point — its certificate was issued under
  // the OLD Root and nothing has asked for a new one. That is the state the
  // repair has to survive.
  const stale = tls.serverCertificate();
  t.check(stale.certPem === good.certPem,
          'the listener certificate is unchanged by replacing the Root — ' +
          'which is what leaves the two halves from different hierarchies');

  t.log.info('=== and certifying REPAIRS it rather than propagating it ===');
  const certified = await pki.certifyRegistered();
  t.check(certified >= 1, 'the registered certifiables are re-certified',
          String(certified));

  const fixed = tls.serverCertificate();
  t.check(fixed.certPem !== stale.certPem,
          'the listener has a new leaf');
  t.check(fixed.chainPem[fixed.chainPem.length - 1] !==
          stale.chainPem[stale.chainPem.length - 1],
          '**AND A NEW CHAIN**, which is the assertion that matters. Re-issuing ' +
          'the leaf alone was the bug: `certify()` would mint it from the ' +
          'stale Issuing CA, so the leaf changed, the chain did not, and the ' +
          'bundle went out with a Root that signs none of it');
  t.check(anchorSignsChain(fixed.trustAnchorPem, fixed.chainPem, fixed.certPem),
          'the published anchor signs the published chain again');
  t.equal(everyLinkVerifies(fixed.certPem, fixed.chainPem, fixed.trustAnchorPem), -1,
          'and every link verifies from the leaf to the anchor');
  t.check(fixed.trustAnchorPem === pki.serviceRoot().certificatePem,
          'and the anchor is the CURRENT Root — the repair rebuilt the branch ' +
          'under it rather than reaching back for the old Root');

  t.log.info('=== the net under the repair ===');
  // `tls_server.js` refuses to publish an anchor that does not sign the chain,
  // whatever produced the mismatch — a request worker holding a Root of its
  // own is the case the repair above cannot reach, because that process never
  // issued the certificate it is serving.
  //
  // **IT PUBLISHES NOTHING RATHER THAN THE INTERMEDIATE.** That substitute was
  // tried: an Intermediate is a CA and looks like a usable anchor, and OpenSSL
  // will not terminate a path at a certificate that is not self-signed without
  // `-partial_chain`. An anchor only some clients can use is the same mistake
  // one layer along.
  t.check(typeof fixed.trustAnchorPem === 'string',
          'the anchor is a string, so a caller with no anchor to give can ' +
          'answer the empty one rather than something unusable');

  // ---------------------------------------------------------------------
  // **PUT THE HIERARCHY BACK, AND THIS IS NOT TIDINESS.**
  //
  // `tests/run.js` runs every file in ONE process, and this one replaced the
  // service Root — which is global state that every later file inherits. The
  // first version of it did not restore, and `tests/pki_hierarchy.js` (which
  // sorts after this file) then certified four keys where it expected seven:
  // it was building on branches this file had orphaned, and `certify()`'s own
  // repair rebuilt them underneath it mid-test.
  //
  // It is restored HERE rather than left for the next file to cope with,
  // because a test that leaves a service in a state no production path
  // produces is a test that fails its neighbours and passes alone — which is
  // exactly how this was found.
  //
  // Rebuilding the PROCESS scope is what `certifyRegistered()` above already
  // did; the realm scopes are rebuilt here so that anything hanging off them
  // chains to the Root this file installed.
  // ---------------------------------------------------------------------
  t.log.info('=== and the anchor has to be PARSEABLE, not merely well signed ===');
  // ---------------------------------------------------------------------
  // **RFC 5280 SECTION 4.1.2.5.2: NO FRACTIONAL SECONDS IN A
  // GeneralizedTime.** `new Date()` carries milliseconds and the encoder
  // writes what it is handed, so a thirty-year Root came out as
  // `20560911143530.614Z` and OpenSSL refused it outright with `format error
  // in certificate's notAfter`.
  //
  // **ONLY THE ROOT WAS EVER AFFECTED, WHICH IS WHY IT LOOKED LIKE A
  // DIFFERENT BUG.** Section 4.1.2.5 makes a time before 2050 a UTCTime,
  // which has no fractional part at all — so the leaf (one year), the Issuing
  // CA (five) and the Intermediate (ten) were always clean, and only a Root
  // whose lifetime crosses 2050 is encoded as a GeneralizedTime. The one
  // malformed certificate in the hierarchy was therefore the TRUST ANCHOR:
  // the chain verified, the console drew it, `openssl x509` printed it — and
  // every client asked to trust it rejected it before checking anything.
  //
  // On this service that is `Signing in did not complete` on /admin, because
  // the OpenID Connect back channel puts exactly that certificate in its
  // truststore to dial itself.
  //
  // **THE 2050 BOUNDARY IS DRIVEN RATHER THAN WAITED FOR.** The default Root
  // is twenty years out, which is a UTCTime today and will silently start
  // being a GeneralizedTime in 2030 — so a test that used the default would
  // pass for four more years and then fail for reasons nobody would connect
  // to this. Thirty years is asked for explicitly.
  // ---------------------------------------------------------------------
  const long = await pki.buildRoot({ organisation: 'sts', years: 30 });
  t.check(long.ok, 'a thirty-year Root is built', (long.errors || []).join(' '));
  const longPem = pki.serviceRoot().certificatePem;
  const longCert = new nodeCrypto.X509Certificate(longPem);
  t.check(new Date(longCert.validTo).getUTCFullYear() >= 2050,
          'and it really does cross 2050, so it is a GeneralizedTime rather ' +
          'than a UTCTime — the encoding this checks does not exist below it',
          longCert.validTo);
  t.check(!/\.[0-9]/.test(longCert.validTo),
          'IT CARRIES NO FRACTIONAL SECONDS. RFC 5280 section 4.1.2.5.2 ' +
          'forbids them, and OpenSSL refuses the whole certificate with ' +
          '"format error in certificate\'s notAfter" — which is not a ' +
          'validation failure a client can report usefully, because it ' +
          'happens before any validation',
          longCert.validTo);
  // AND THE THING THAT ACTUALLY BROKE: a client putting it in a truststore.
  let usable = '';
  try {
    // `tls.createSecureContext()` and not `crypto`'s — this is the call the
    // OpenID Connect back channel makes when it pins the anchor, and it is
    // where OpenSSL parses the certificate. A malformed notAfter throws here,
    // before anything is verified.
    require('tls').createSecureContext({ ca: [longPem] });
    usable = 'ok';
  } catch (e) {
    usable = e.message;
  }
  t.equal(usable, 'ok',
          'and a TLS client can load it as a trust anchor, which is the act ' +
          'that failed — the certificate was never parsed far enough to be ' +
          'checked');

  const restored = [];
  for (const scope of [pki.PROCESS_SCOPE, '']) {
    const built = await pki.buildScope(scope, {});
    restored.push(scope + '=' + (built.ok ? 'ok' : 'failed'));
  }
  await pki.certifyRegistered();
  t.check(restored.every(function (one) { return /=ok$/.test(one); }),
          'and the hierarchy is left COHERENT for the files that run after ' +
          'this one in the same process', restored.join(' '));
}

module.exports = {
  name: 'pki_anchor_drift',
  describe: 'the published trust anchor must sign the published chain: the ' +
            'drift a replaced Root leaves, and that certifying repairs the ' +
            'branch instead of minting a leaf onto a dead one',
  run: run
};
