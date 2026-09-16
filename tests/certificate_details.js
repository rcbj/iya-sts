'use strict';
//
// File: certificate_details.js
//
// ===========================================================================
// THE CERTIFICATE DETAILS DIALOG: THE MODEL, THE CATALOGUE, THE RENDERER
// (2026-09-13).
//
// `/admin/pki` and `/admin/crypto-metadata` open a certificate's every X.509
// field and its trust chain in a dialog over the page. Three modules make it —
// `common/certificate_details.js` (the model),
// `admin-core/certificate_views.ts` (which certificates may be opened) and
// `admin-ui/certificate_dialog.js` (the one renderer) — and
// `tests/vendored/sts_admin_api_operations.js` drives the same answer over
// HTTP. What is here is what a request cannot choose:
//
//   A. THE FIELDS AGAINST OPENSSL. The model is built on pkijs; node's
//      X509Certificate and the `openssl` binary are a second reading, so a
//      serial, a fingerprint, a date or a key identifier that pkijs read
//      differently fails here rather than on a page nobody compares.
//   B. THE CHAIN IS BUILT BY SIGNATURE, NOT BY NAME. An impostor carrying the
//      Root's exact subject is a certificate no request can make this service
//      hold, and it is the case that separates the two: a walk by name alone
//      draws a complete chain to it.
//   C. THE CATALOGUE: a fingerprint in either spelling, a refusal for anything
//      not held, a PEM never accepted as a handle, and the realm boundary — a
//      realm's own Issuing CA opens inside that realm and is refused outside.
//   D. THE RENDERER, in a CHILD PROCESS because requiring it requires the
//      console, which registers every `/admin` route on the shared app: no
//      script, no new tab, an X and a real Close button that both return to
//      the page, the section kept, and a hostile subject escaped.
// ===========================================================================

// Deleted rather than set, for the reason `config_realm_layer.js` gives.
delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const CHILD_FLAG = 'STS_CERTIFICATE_DETAILS_CHILD';
const REALM = 'certview-a';

const log = require('bunyan').createLogger({ name: 'certificate_details',
  level: process.env.LOG_LEVEL || 'info' });

// A self-signed EC certificate with the subject given, made with the vendored
// encoder — an IMPOSTOR when the subject is somebody else's.
async function selfSigned(subject) {
  log.debug("Entering selfSigned().");
  const x509 = require('../common/vendored/x509');
  const pair = nodeCrypto.generateKeyPairSync('ec',
                                              { namedCurve: 'prime256v1' });
  const issued = await x509.issueCertificate({
    subject: subject,
    subjectPublicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    signatureAlg: 'sha256-ecdsa',
    issuerPrivateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    profile: 'root-ca'
  });
  log.debug("Leaving selfSigned().");
  return issued.pem;
}

function openSslText(pem) {
  log.debug("Entering openSslText().");
  try {
    const out = childProcess.execFileSync('openssl',
      ['x509', '-noout', '-text'], { input: pem, encoding: 'utf8',
                                     stdio: ['pipe', 'pipe', 'pipe'] });
    log.debug("Leaving openSslText().");
    return out;
  } catch (e) {
    log.debug("Caught in openSslText(): " + ((e && e.message) || e));
    log.debug("Leaving openSslText(). No openssl.");
    return null;
  }
}

async function inProcess(t) {
  log.debug("Entering inProcess().");
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const details = require('../common/certificate_details');
  const views = require('../admin-core/certificate_views');
  const errorCodes = require('../common/error_codes');

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  await pki.ensureScope(REALM);
  const rootPem = pki.serviceRoot().certificatePem;
  const scope = pki.describeScope('');
  const joseCa = scope.issuing.filter(function (one) {
    return one.id === 'jose';
  })[0].ca;

  // -------------------------------------------------------------------------
  t.log.info('=== A. every field, against node and openssl ===');
  // -------------------------------------------------------------------------
  const described = await details.describe(joseCa.certificatePem);
  const node = new nodeCrypto.X509Certificate(joseCa.certificatePem);
  const tbs = described.fields.tbsCertificate;
  t.equal(described.fingerprints.sha256, node.fingerprint256,
          'the SHA-256 fingerprint is OpenSSL\'s');
  t.equal(described.fingerprints.sha1, node.fingerprint,
          'and so is the SHA-1 one');
  t.equal(tbs.serialNumber.hex.replace(/^0+/, '').toUpperCase(),
          node.serialNumber.replace(/^0+/, '').toUpperCase(),
          'the serial number is the one OpenSSL reads');
  t.equal(new Date(tbs.validity.notAfter.iso).getTime(),
          new Date(node.validTo).getTime(),
          'notAfter is the date OpenSSL reads');
  t.equal(tbs.subjectPublicKeyInfo.key.modulusBits,
          node.publicKey.asymmetricKeyDetails.modulusLength,
          'the RSA modulus size is the one OpenSSL reads');
  t.check(tbs.version.value === 3 && tbs.version.encoded === 2,
          'a v3 certificate, encoded as the integer 2');
  t.check(tbs.subject.attributes.some(function (one) {
    return one.oid === '2.5.4.3' && one.short === 'CN' &&
           /JOSE Signing CA/.test(one.value);
  }), 'the subject is described RDN by RDN, with each attribute\'s OID');
  t.check(described.fields.signatureAlgorithmsAgree &&
          tbs.signature.oid === described.fields.signatureAlgorithm.oid,
          'the signature algorithm inside tbsCertificate and outside it are ' +
          'both reported, and agree');
  t.check(described.fields.signatureValue.octets === 256 &&
          described.fields.signatureValue.hex.length === 512,
          'the signature value is carried whole — 256 octets for RSA-2048');
  t.check(tbs.validity.notBefore.type === 'UTCTime',
          'each validity bound says which ASN.1 time type it is written in');
  const ski = tbs.extensions.filter(function (one) {
    return one.name === 'subjectKeyIdentifier';
  })[0];
  const text = openSslText(joseCa.certificatePem);
  if (text) {
    const skiLine = (text.split('\n').map(function (l) { return l.trim(); })
      .filter(function (l) { return /^([0-9A-F]{2}:){19}[0-9A-F]{2}$/.test(l); })
      )[0] || '';
    t.equal(skiLine.replace(/:/g, '').toLowerCase(), ski && ski.value,
            'the Subject Key Identifier is the one `openssl x509 -text` ' +
            'prints');
    t.check(/X509v3 Basic Constraints: critical/.test(text) &&
            tbs.extensions.some(function (one) {
              return one.name === 'basicConstraints' && one.critical &&
                     one.value.ca === true && one.value.pathLen === 0;
            }),
            'basicConstraints is critical, cA and pathLen 0, as openssl says');
    // The extensions openssl lists, by the heading each gets; one it cannot
    // name it prints as a dotted OID, which counts too.
    const openSslCount = text.split('\n').filter(function (line) {
      return /^ {12}(X509v3 |Authority Information Access|[0-9]+(\.[0-9]+)+)/
        .test(line) && /:/.test(line);
    }).length;
    t.equal(tbs.extensions.length, openSslCount,
            'every extension openssl lists is described, and no other');
  } else {
    t.check(true, 'no openssl binary on this machine; the node comparisons ' +
            'above stand alone');
  }
  t.check(tbs.extensions.every(function (one) {
    return one.label && one.oid && one.text !== undefined;
  }), 'every extension carries a readable label, its OID and a value');

  // A COMPOSITE KEY IS NAMED AS ONE. The inspector's summary imports the key
  // and a composite's classical half is what imports, so an ML-DSA-44 +
  // Ed25519 key was summarised as "Ed25519" — found on the page, in the first
  // screenshot of the dialog.
  const pqJose = require('../common/pq_jose');
  const composite = pqJose.generate('ML-DSA-44-Ed25519');
  // In this file's own realm: the default realm's slot is shared by every
  // file `run.js` runs in this process.
  await pki.certifyPqKeys(REALM, [{ alg: 'ML-DSA-44-Ed25519',
    publicJwk: pqJose.akpPublicJwk('ML-DSA-44-Ed25519', composite.pub,
                                   'certview') }]);
  const compositeCert = pki.certificateFor(REALM, 'jose',
                                           'ML-DSA-44-Ed25519');
  const compositeView = await details.describe(compositeCert.certificatePem);
  t.check(/MLDSA44-Ed25519/.test(compositeView.summary.publicKey) &&
          /composite/.test(compositeView.fields.tbsCertificate
            .subjectPublicKeyInfo.description),
          'a composite ML-DSA key is named as the composite, not as its ' +
          'classical half', compositeView.summary.publicKey);

  // -------------------------------------------------------------------------
  t.log.info('=== B. the chain is built by signature, not by name ===');
  // -------------------------------------------------------------------------
  const intermediatePem = scope.intermediate.certificatePem;
  const anchors = {};
  anchors[details.fingerprintOf(rootPem)] = 'this service\'s Root CA';
  const good = await details.detailsFor(joseCa.certificatePem,
                                        [intermediatePem, rootPem],
                                        { anchors: anchors });
  t.check(good.chainStatus === 'complete' && good.chainTrusted &&
          good.chain.length === 3 &&
          good.chain.every(function (link) {
            return link.signatureValid === true &&
                   link.issuerMayCertify === true;
          }) && good.chain[2].anchor === 'this service\'s Root CA',
          'the JOSE Issuing CA builds a trusted three-link chain to the Root',
          JSON.stringify(good.chain.map(function (l) {
            return [l.role, l.signatureValid, l.issuerMayCertify];
          })));
  const impostor = await selfSigned(pki.serviceRoot().subject);
  const fooled = await details.detailsFor(intermediatePem, [impostor],
                                          { anchors: anchors });
  t.check(fooled.chainStatus === 'unverified' && !fooled.chainTrusted &&
          fooled.chain.length === 1,
          'an IMPOSTOR carrying the Root\'s exact subject is not taken as ' +
          'the issuer — a walk by name alone would draw a complete chain to it',
          fooled.chainStatus + ': ' + fooled.chainReason);
  const both = await details.detailsFor(intermediatePem, [impostor, rootPem],
                                        { anchors: anchors });
  t.check(both.chainStatus === 'complete' && both.chainTrusted &&
          both.chain[1].fingerprint === details.fingerprintOf(rootPem),
          'and with the real Root held beside it, the walk takes the one ' +
          'whose key verifies');
  const orphan = await details.detailsFor(joseCa.certificatePem, [],
                                          { anchors: anchors });
  t.check(orphan.chainStatus === 'incomplete' && !orphan.chainTrusted &&
          /Intermediate CA/.test(orphan.chainReason),
          'a certificate whose issuer is not held stops, naming the issuer',
          orphan.chainReason);
  const loner = await details.detailsFor(impostor, [], { anchors: anchors });
  t.check(loner.chainStatus === 'complete' && !loner.chainTrusted &&
          loner.chain[0].anchor === null,
          'a self-signed certificate nobody here installed is a complete ' +
          'path and NOT a trusted one');

  // -------------------------------------------------------------------------
  t.log.info('=== C. the catalogue and the realm boundary ===');
  // -------------------------------------------------------------------------
  const rootFp = details.fingerprintOf(rootPem);
  const rootView = await views.detailsView(null, rootFp);
  t.check(rootView.ok && rootView.chainTrusted &&
          rootView.appearances.some(function (one) {
            return one.label === 'Service Root CA';
          }),
          'the service Root opens by fingerprint and says where it appears');
  const colons = rootFp.toUpperCase().match(/.{2}/g).join(':');
  t.check((await views.detailsView(null, colons)).ok,
          'the colon-separated upper-case spelling opens the same certificate');
  const unknown = await views.detailsView(null, '0'.repeat(64));
  t.check(!unknown.ok && errorCodes.codeOf(unknown) === 'STS-ADMIN-0641' &&
          JSON.stringify(unknown).indexOf('STS-ADMIN') < 0,
          'a fingerprint nothing here holds is refused, with a code that ' +
          'is RECORDED and not serialised into the reply');
  const asPem = await views.detailsView(null, rootPem);
  t.check(!asPem.ok && errorCodes.codeOf(asPem) === 'STS-ADMIN-0640',
          'a PEM is NOT a handle: the view looks certificates up and never ' +
          'describes one it was sent');
  const realmScope = pki.describeScope(REALM);
  const realmCa = realmScope.issuing.filter(function (one) {
    return one.id === 'jose';
  })[0].ca;
  const realmCaFp = details.fingerprintOf(realmCa.certificatePem);
  const outside = await views.detailsView(null, realmCaFp);
  t.check(!outside.ok && errorCodes.codeOf(outside) === 'STS-ADMIN-0641',
          'THE REALM BOUNDARY: ' + REALM + '\'s JOSE Issuing CA is refused ' +
          'in the default realm, whose catalogue does not hold another realm\'s ' +
          'branch');
  const inside = await realms.run(realms.get(REALM), function () {
    log.debug("Entering the realm-scoped lookup.");
    log.debug("Leaving the realm-scoped lookup.");
    return views.detailsView(null, realmCaFp);
  });
  t.check(inside.ok && inside.chainTrusted && inside.chain.length === 3 &&
          inside.realm === REALM,
          'and opens inside ' + REALM + ', with a trusted chain through that ' +
          'realm\'s own Intermediate');
  const list = views.listView({ query: { per: '500' } });
  const fps = list.certificates.map(function (one) { return one.fingerprint; });
  t.check(fps.indexOf(rootFp) >= 0 && fps.indexOf(realmCaFp) < 0 &&
          new Set(fps).size === fps.length,
          'the list holds the Root, not another realm\'s branch, and each ' +
          'certificate once however many places it appears');
  t.check(JSON.stringify(list).indexOf('PRIVATE KEY') < 0 &&
          JSON.stringify(rootView).indexOf('PRIVATE KEY') < 0,
          'no private key is anywhere in the list or the details');
  log.debug("Leaving inProcess().");
}

// ---------------------------------------------------------------------------
// D. THE RENDERER, in a child process.
// ---------------------------------------------------------------------------
async function childBody() {
  log.debug("Entering childBody().");
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const details = require('../common/certificate_details');
  const views = require('../admin-core/certificate_views');
  const dialog = require('../admin-ui/certificate_dialog');
  await keystore.start();
  await pki.start({ realmIds: [''] });
  const rootFp = details.fingerprintOf(pki.serviceRoot().certificatePem);
  const view = await views.detailsView(null, rootFp);
  const hostile = await selfSigned([{ name: 'CN',
    value: '<script>alert(1)</script>' }]);
  const hostileModel = Object.assign({ ok: true, realm: 'default',
    appearances: [{ label: '<img src=x onerror=alert(1)>', where: 'pki' }] },
    await details.detailsFor(hostile, []));
  process.stdout.write('CERTDLG ' + JSON.stringify({
    html: dialog.dialog('/admin/pki', view, 'pki-tree'),
    refused: dialog.dialog('/admin/crypto-metadata',
                           { ok: false, errors: ['Not held here.'] },
                           'javascript:alert(1)'),
    hostile: dialog.dialog('/admin/pki', hostileModel, ''),
    link: dialog.link('/admin/pki', rootFp, 'pki-tree'),
    badLink: dialog.link('/admin/pki', 'nope', 'pki-tree'),
    rootFp: rootFp
  }) + '\n');
  log.debug("Leaving childBody().");
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: path.resolve(__dirname, '..'), env: clean, encoding: 'utf8',
    timeout: 180000, maxBuffer: 64 * 1024 * 1024 });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('CERTDLG ') === 0;
  })[0];
  log.debug("Leaving spawnChild().");
  return line ? JSON.parse(line.slice('CERTDLG '.length))
    : { error: 'the child produced no result (exit ' + result.status + '): ' +
               String(result.stderr || '').slice(-1200) };
}

function theRenderer(t, got) {
  log.debug("Entering theRenderer().");
  t.log.info('=== D. the dialog: no script, same tab, X and Close ===');
  if (got.error) {
    t.bad('the renderer child did not run', got.error);
    log.debug("Leaving theRenderer().");
    return;
  }
  const html = got.html;
  t.check(/role="dialog"/.test(html) && /aria-modal="true"/.test(html),
          'it is a modal dialog to assistive technology');
  t.check(/<a class="certdlg-x" href="\/admin\/pki#pki-tree" aria-label="[^"]+"/
            .test(html),
          'the X is a labelled link back to the SAME page, to the section ' +
          'the dialog was opened from');
  t.check(/<form method="get" action="\/admin\/pki#pki-tree"><button type="submit"[^>]*>Close<\/button><\/form>/
            .test(html),
          'the Close button is a real <button> going to the same place');
  t.check(!/<script/i.test(html) && !/\bon[a-z]+=/i.test(html) &&
          !/target=/i.test(html),
          'no script, no event handler, and no target: it stays in the tab ' +
          'on a page that is script-src \'none\'');
  t.check(/Trust chain/.test(html) && /Every X\.509 field/.test(html) &&
          /Subject Key Identifier/.test(html) &&
          /Signature \(inside tbsCertificate\)/.test(html) &&
          /Subject unique ID/.test(html) && /BEGIN CERTIFICATE/.test(html),
          'the trust chain, the tbsCertificate fields, the extensions and ' +
          'the PEM are all in it');
  t.check(/href="\/admin\/pki\?certificate=[0-9a-f]{64}&amp;from=pki-tree"/
            .test(got.link) && got.badLink === '',
          'the opening link carries the fingerprint and the section, and a ' +
          'value that is not a fingerprint draws no link at all');
  t.check(/Certificate not available/.test(got.refused) &&
          /Not held here\./.test(got.refused) &&
          /href="\/admin\/crypto-metadata"/.test(got.refused) &&
          got.refused.indexOf('javascript:') < 0,
          'a refusal still opens the dialog and says why, and a `from` that ' +
          'is not an element id is dropped rather than written into an href');
  t.check(got.hostile.indexOf('<script>alert(1)</script>') < 0 &&
          got.hostile.indexOf('&lt;script&gt;') >= 0 &&
          got.hostile.indexOf('<img src=x') < 0,
          'a hostile subject and a hostile label are escaped wherever they ' +
          'are drawn');
  log.debug("Leaving theRenderer().");
}

// ---------------------------------------------------------------------------
// THE CERTIFICATE AUTHORITY THIS FILE FINDS IS THE ONE IT LEAVES. `run.js`
// runs every file in ONE process, and `pki.start()` here builds a service Root
// and the default realm's branch — which `tests/pki.js` then meets when it asks
// for a Root of its own, so its "the Root carries the organisation it was
// asked for" failed in the suite and passed alone. Whatever was absent on the
// way in is removed on the way out; what was already there is left exactly as
// it was. The same pair `tests/person_credentials.js` and
// `tests/application_credentials.js` carry.
// ---------------------------------------------------------------------------
function heldAuthority(pki, keystore) {
  log.debug("Entering heldAuthority().");
  log.debug("Leaving heldAuthority().");
  return { root: !!keystore.pkiFor(pki.SERVICE_SCOPE),
           chain: pki.hasChain() };
}

function restoreAuthority(pki, keystore, before) {
  log.debug("Entering restoreAuthority().");
  if (!before.chain && pki.hasChain()) {
    pki.clearChain(undefined);
  }
  if (!before.root && keystore.pkiFor(pki.SERVICE_SCOPE)) {
    keystore.attachPki(pki.SERVICE_SCOPE, null);
  }
  log.debug("Leaving restoreAuthority().");
}

async function run(t) {
  log.debug("Entering run().");
  const pki = require('../common/pki');
  const keystore = require('../common/keystore');
  const before = heldAuthority(pki, keystore);
  try {
    await inProcess(t);
  } finally {
    // `realm_isolation.js` asserts only the default realm is left.
    const realms = require('../common/realms');
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }
    restoreAuthority(pki, keystore, before);
  }
  theRenderer(t, spawnChild());
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function () {
    process.exit(0);
  }, function (e) {
    process.stderr.write(String((e && e.stack) || e) + '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'certificate_details',
  describe: 'The certificate details dialog on /admin/pki and ' +
            '/admin/crypto-metadata: every field against node and openssl, ' +
            'a chain built by signature rather than name, the catalogue and ' +
            'its realm boundary, and a no-script dialog that stays in the tab',
  run: run
};
