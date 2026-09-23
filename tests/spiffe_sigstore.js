'use strict';
//
// File: spiffe_sigstore.js
//
// ===========================================================================
// COSIGN IMAGE SIGNATURES AND THE SIGSTORE TUF TRUST ROOT (#170, 2026-09-23).
//
// **EVERY KEY, CERTIFICATE, SIGNATURE AND LOG ENTRY IS MADE HERE, AT RUN
// TIME.** No key material is committed: a cosign key pair, a Fulcio-like
// root and intermediate, a keyless signing certificate carrying Fulcio's
// OIDC-issuer extension and an EMBEDDED SCT from a CT log key made here, a
// Rekor log key and the signed entry timestamps it gives, and a TUF
// repository (root v1, a root v2 rotation, timestamp, snapshot, targets and
// the trusted_root.json target) — all in memory, served by a fake registry
// and a fake TUF mirror handed to the verifier as its `fetch`.
//
// Written from cosign's and TUF's documents rather than from the verifier:
// the canonical JSON here is this file's own, and the certificates are pkijs
// through `webauthn_attestation_kit.js`, not the service's encoder.
//
//   1. KEYED signatures: a good one (image-signature:verified and the log
//      selectors); a WRONG KEY; a signature with NO Rekor bundle (refused);
//      the same with spiffe.dockerSigstoreSkipTlog (verified, no log
//      selectors); a bundle whose SET does not verify; a payload for
//      another digest (the claim check beyond SPIRE); a post-quantum
//      ML-DSA-65 key; an attestation required and missing, then present.
//   2. KEYLESS: a Fulcio certificate that verifies, with SPIRE's subject and
//      issuer selectors; an identity not allowed; an empty allow list
//      (refused, stricter than SPIRE); a certificate with no SCT (refused)
//      and with spiffe.dockerSigstoreIgnoreSct (verified).
//   3. THE REGISTRY: a Bearer challenge answered from an allowed realm; a
//      registry not allowed; a realm not allowed.
//   4. TUF: a refresh that walks a root rotation and verifies every role;
//      then a timestamp with a bad signature, a rollback, expired targets and
//      a target whose hash does not match — each refused, and the last good
//      trust root kept every time; and the verifier using that root.
//   5. The docker attestor with sigstore on: a failed verification fails the
//      attestation (the connection is refused), never a missing selector.
// ===========================================================================

const os = require('os');
const path = require('path');
const fs = require('fs');
const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');

const config = require('../common/config');
const kit = require('./webauthn_attestation_kit');
const pqx = require('../common/vendored/pqc_x509');
const sigstore = require('../spiffe/spiffe_sigstore');
const tufModule = require('../spiffe/spiffe_sigstore_tuf');
const dockerAttestor = require('../spiffe/spiffe_workload_attestor_docker');

const log = require('bunyan').createLogger({
  name: 'spiffe_sigstore', level: process.env.LOG_LEVEL || 'info' });

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-sigstore-'));
const REGISTRY = 'reg.test';
const REPO = 'team/app';
const DIGEST = 'sha256:' + 'd'.repeat(64);
const REPO_DIGEST = REGISTRY + '/' + REPO + '@' + DIGEST;
const ISSUER = 'https://issuer.test';
const SIGNER = 'builder@example.com';

const SETTINGS = [
  'spiffe.dockerSigstorePublicKeyFiles', 'spiffe.dockerSigstoreTrustedRootFile',
  'spiffe.dockerSigstoreAllowedIdentities',
  'spiffe.dockerSigstoreAllowedRegistries', 'spiffe.dockerSigstoreSkipTlog',
  'spiffe.dockerSigstoreIgnoreSct', 'spiffe.dockerSigstoreIgnoreAttestations',
  'spiffe.dockerSigstoreTufRootFile', 'spiffe.dockerSigstoreTufUrl',
  'spiffe.dockerSigstoreSkippedImages', 'spiffe.dockerSigstoreEnabled'];

function show(value) {
  log.debug("Entering show().");
  log.debug("Leaving show().");
  return JSON.stringify(value);
}

// ----- canonical JSON, this file's own --------------------------------------

// RFC 8785 for the Rekor SET, over the only shapes this file canonicalizes
// (strings, integers, objects). Recursive, so no Entering/Leaving pair —
// it would drown the log.
function jcs(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  return '{' + Object.keys(value).sort().map(function (k) {
    return JSON.stringify(k) + ':' + jcs(value[k]);
  }).join(',') + '}';
}

// securesystemslib's canonical form for TUF (only `\` and `"` escaped).
// Recursive, so no Entering/Leaving pair — it would drown the log.
function olpc(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') {
    return String(value);
  }
  if (typeof value === 'string') {
    return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }
  if (Array.isArray(value)) return '[' + value.map(olpc).join(',') + ']';
  return '{' + Object.keys(value).sort().map(function (k) {
    return olpc(k) + ':' + olpc(value[k]);
  }).join(',') + '}';
}

function sha256(bytes) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nodeCrypto.createHash('sha256').update(bytes).digest('hex');
}

// ----- keys ------------------------------------------------------------------

function ecKey() {
  log.debug("Entering ecKey().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = pair.publicKey.export({ type: 'spki', format: 'der' });
  log.debug("Leaving ecKey().");
  return { privateKey: pair.privateKey, publicKey: pair.publicKey,
           spki: spki,
           pem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
           sign: function (data) {
             return nodeCrypto.sign('sha256', data, pair.privateKey);
           } };
}

async function mldsaKey() {
  log.debug("Entering mldsaKey().");
  const pair = await pqx.generateKeyPair('ML-DSA-65');
  const pem = pqx.publicPem('ML-DSA-65', pair.pub);
  const spki = Buffer.from(pem.replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
  log.debug("Leaving mldsaKey().");
  return { spki: spki, pem: pem,
           sign: async function (data) {
             return Buffer.from(await pqx.sign('ML-DSA-65',
                                               new Uint8Array(data),
                                               pair.priv));
           } };
}

function pemOf(der, label) {
  log.debug("Entering pemOf().");
  log.debug("Leaving pemOf().");
  return '-----BEGIN ' + label + '-----\n' +
         der.toString('base64').replace(/(.{64})/g, '$1\n') +
         '\n-----END ' + label + '-----\n';
}

// ----- Fulcio, with an embedded SCT ------------------------------------------

function extension(oid, critical, der) {
  log.debug("Entering extension().");
  log.debug("Leaving extension().");
  return new pkijs.Extension({ extnID: oid, critical: !!critical,
    extnValue: new Uint8Array(Buffer.from(der)).buffer });
}

// A Fulcio root and intermediate: `{ root, intermediate }`, kit shapes.
async function fulcio() {
  log.debug("Entering fulcio().");
  const root = await kit.root('fulcio-test');
  const pair = await kit.keyPair('ec');
  const intermediate = await kit.certificate({
    subject: [['2.5.4.3', 'fulcio-test intermediate']],
    publicKey: pair.crypto.publicKey, issuer: root, ca: true,
    extensions: [extension('2.5.29.37', false, new pkijs.ExtKeyUsage({
      keyPurposes: ['1.3.6.1.5.5.7.3.3'] }).toSchema().toBER(false))] });
  intermediate.signingKey = pair.crypto.privateKey;
  log.debug("Leaving fulcio().");
  return { root: root, intermediate: intermediate };
}

// A keyless signing certificate for `subject` from `issuer`, with Fulcio's
// extensions, and — unless `noSct` — an embedded SCT signed by `ct`.
// Answers `{ der, pem, key }`.
async function signingCertificate(ca, ct, subject, issuerUrl, noSct) {
  log.debug("Entering signingCertificate().");
  const pair = await kit.keyPair('ec');
  const extensions = [
    extension('2.5.29.17', true, new pkijs.AltName({ altNames: [
      new pkijs.GeneralName({ type: 1, value: subject })] })
      .toSchema().toBER(false)),
    extension('2.5.29.37', false, new pkijs.ExtKeyUsage({
      keyPurposes: ['1.3.6.1.5.5.7.3.3'] }).toSchema().toBER(false)),
    extension('1.3.6.1.4.1.57264.1.1', false, Buffer.from(issuerUrl, 'utf8')),
    extension('1.3.6.1.4.1.57264.1.8', false,
              new asn1js.Utf8String({ value: issuerUrl }).toBER(false))
  ];
  const made = await kit.certificate({ subject: [],
                                      publicKey: pair.crypto.publicKey,
                                      issuer: ca.intermediate,
                                      extensions: extensions });
  if (!noSct) {
    // RFC 6962 section 3.2: the SCT signs the TBS WITHOUT the list, and the
    // issuer's key hash; then the list goes in and the certificate is
    // signed again.
    const tbs = Buffer.from(made.pkijs.encodeTBS().toBER(false));
    const issuerSpki = Buffer.from(ca.intermediate.pkijs.subjectPublicKeyInfo
      .toSchema().toBER(false));
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(BigInt(Date.now() - 60000));
    const tbsLen = Buffer.alloc(3);
    tbsLen.writeUIntBE(tbs.length, 0, 3);
    const signed = Buffer.concat([Buffer.from([0, 0]), ts, Buffer.from([0, 1]),
      nodeCrypto.createHash('sha256').update(issuerSpki).digest(), tbsLen,
      tbs, Buffer.from([0, 0])]);
    const sig = ct.sign(signed);
    const sigLen = Buffer.alloc(2);
    sigLen.writeUInt16BE(sig.length);
    const sct = Buffer.concat([Buffer.from([0]),
      nodeCrypto.createHash('sha256').update(ct.spki).digest(), ts,
      Buffer.from([0, 0]), Buffer.from([4, 3]), sigLen, sig]);
    const one = Buffer.alloc(2);
    one.writeUInt16BE(sct.length);
    const listBody = Buffer.concat([one, sct]);
    const total = Buffer.alloc(2);
    total.writeUInt16BE(listBody.length);
    made.pkijs.extensions.push(extension('1.3.6.1.4.1.11129.2.4.2', false,
      new asn1js.OctetString({ valueHex: new Uint8Array(
        Buffer.concat([total, listBody])).buffer }).toBER(false)));
    await made.pkijs.sign(ca.intermediate.signingKey, 'SHA-256');
  }
  const der = Buffer.from(made.pkijs.toSchema(true).toBER(false));
  log.debug("Leaving signingCertificate().");
  return { der: der, pem: pemOf(der, 'CERTIFICATE'),
           sign: function (data) {
             return nodeCrypto.sign('sha256', data,
               nodeCrypto.KeyObject.from(pair.crypto.privateKey));
           } };
}

// A sigstore trusted_root.json naming `ca`, the Rekor key and the CT key.
function trustedRoot(ca, rekor, ct) {
  log.debug("Entering trustedRoot().");
  const logEntry = function (key) {
    return { baseUrl: 'https://log.test', hashAlgorithm: 'SHA2_256',
             publicKey: { rawBytes: key.spki.toString('base64'),
                          keyDetails: 'PKIX_ECDSA_P256_SHA_256',
                          validFor: { start: '2020-01-01T00:00:00Z' } },
             logId: { keyId: nodeCrypto.createHash('sha256').update(key.spki)
                        .digest('base64') } };
  };
  log.debug("Leaving trustedRoot().");
  return {
    mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
    tlogs: [logEntry(rekor)],
    certificateAuthorities: [{
      subject: { organization: 'test', commonName: 'fulcio-test' },
      uri: 'https://fulcio.test',
      certChain: { certificates: [
        { rawBytes: ca.intermediate.der.toString('base64') },
        { rawBytes: ca.root.der.toString('base64') }] },
      validFor: { start: '2020-01-01T00:00:00Z' } }],
    ctlogs: [logEntry(ct)]
  };
}

// ----- cosign objects ------------------------------------------------------

function simpleSigning(digest) {
  log.debug("Entering simpleSigning().");
  log.debug("Leaving simpleSigning().");
  return Buffer.from(JSON.stringify({ critical: {
    identity: { 'docker-reference': REGISTRY + '/' + REPO },
    image: { 'docker-manifest-digest': digest },
    type: 'cosign container image signature' }, optional: null }), 'utf8');
}

// A Rekor bundle for `body` (the entry object), signed by `rekor`.
function bundle(rekor, entry, spoilSet) {
  log.debug("Entering bundle().");
  const payload = {
    body: Buffer.from(JSON.stringify(entry)).toString('base64'),
    integratedTime: Math.floor(Date.now() / 1000) - 30,
    logIndex: 1234,
    logID: sha256(rekor.spki) };
  let set = rekor.sign(Buffer.from(jcs(payload), 'utf8'));
  if (spoilSet) {
    set = rekor.sign(Buffer.from('something else', 'utf8'));
  }
  log.debug("Leaving bundle().");
  return JSON.stringify({ SignedEntryTimestamp: set.toString('base64'),
                          Payload: payload });
}

// One cosign signature layer: `{ payload, annotations }`. `o.key` is the
// signer (`sign`, `pem`), `o.cert` a certificate PEM when keyless.
async function signatureLayer(o) {
  log.debug("Entering signatureLayer().");
  const payload = o.payload || simpleSigning(DIGEST);
  const sig = Buffer.from(await o.key.sign(payload)).toString('base64');
  const annotations = { 'dev.cosignproject.cosign/signature': sig };
  if (o.cert) {
    annotations['dev.sigstore.cosign/certificate'] = o.cert;
  }
  if (o.rekor) {
    annotations['dev.sigstore.cosign/bundle'] = bundle(o.rekor, {
      apiVersion: '0.0.1', kind: 'hashedrekord',
      spec: { data: { hash: { algorithm: 'sha256', value: sha256(payload) } },
              signature: { content: sig, publicKey: { content:
                Buffer.from(o.cert || o.key.pem).toString('base64') } } } },
      o.spoilSet);
  }
  log.debug("Leaving signatureLayer().");
  return { payload: payload, annotations: annotations };
}

// One in-toto attestation layer, a DSSE envelope over a statement about
// `digest`.
async function attestationLayer(o) {
  log.debug("Entering attestationLayer().");
  const statement = Buffer.from(JSON.stringify({
    _type: 'https://in-toto.io/Statement/v0.1',
    predicateType: 'https://slsa.dev/provenance/v0.2',
    subject: [{ name: REGISTRY + '/' + REPO,
                digest: { sha256: o.digest.replace(/^sha256:/, '') } }],
    predicate: {} }));
  const type = 'application/vnd.in-toto+json';
  const pae = Buffer.concat([Buffer.from('DSSEv1 ' + type.length + ' ' + type +
                                         ' ' + statement.length + ' '),
                             statement]);
  const sig = Buffer.from(await o.key.sign(pae)).toString('base64');
  const envelope = Buffer.from(JSON.stringify({
    payloadType: type, payload: statement.toString('base64'),
    signatures: [{ keyid: '', sig: sig }] }));
  const annotations = {};
  if (o.rekor) {
    annotations['dev.sigstore.cosign/bundle'] = bundle(o.rekor, {
      apiVersion: '0.0.2', kind: 'intoto',
      spec: { content: {
        envelope: { payloadType: type, signatures: [{ sig: sig,
          publicKey: Buffer.from(o.key.pem).toString('base64') }] },
        hash: { algorithm: 'sha256', value: sha256(envelope) } } } });
  }
  log.debug("Leaving attestationLayer().");
  return { payload: envelope, annotations: annotations };
}

// ----- a fake registry -----------------------------------------------------

// `images` maps a tag to its layers. Every manifest request is first
// challenged for a Bearer token from `auth.test`.
function registry(images, asked) {
  log.debug("Entering registry().");
  const blobs = {};
  const manifests = {};
  Object.keys(images).forEach(function (tag) {
    manifests[tag] = JSON.stringify({ schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      layers: images[tag].map(function (layer) {
        const digest = 'sha256:' + sha256(layer.payload);
        blobs[digest] = layer.payload;
        return { mediaType: 'application/vnd.dev.cosign.simplesigning.v1+json',
                 digest: digest, size: layer.payload.length,
                 annotations: layer.annotations };
      }) });
  });
  log.debug("Leaving registry().");
  return function (url, options) {
    asked.push(url);
    const headers = (options && options.headers) || {};
    const reply = function (status, body, extra) {
      return Promise.resolve({ ok: status >= 200 && status < 300,
                               status: status, headers: extra || {},
                               body: Buffer.from(body || ''),
                               why: 'HTTP ' + status });
    };
    if (url.indexOf('https://auth.test/token') === 0) {
      return reply(200, JSON.stringify({ token: 'pull-token' }));
    }
    const base = 'https://' + REGISTRY + '/v2/' + REPO + '/';
    if (url.indexOf(base) !== 0) {
      return reply(404, '');
    }
    if (headers.Authorization !== 'Bearer pull-token') {
      return reply(401, '', { 'www-authenticate': 'Bearer realm=' +
        '"https://auth.test/token",service="reg.test",scope="x"' });
    }
    const rest = url.slice(base.length);
    if (rest.indexOf('manifests/') === 0) {
      const tag = rest.slice('manifests/'.length);
      return manifests[tag] ? reply(200, manifests[tag]) : reply(404, '');
    }
    if (rest.indexOf('blobs/') === 0) {
      const blob = blobs[rest.slice('blobs/'.length)];
      return blob ? reply(200, blob) : reply(404, '');
    }
    return reply(404, '');
  };
}

function verifier(fetch, tufRoot) {
  log.debug("Entering verifier().");
  log.debug("Leaving verifier().");
  return new sigstore.SigstoreVerifier(Object.assign(
    sigstore.SigstoreVerifier.defaultDeps(), {
      fetch: fetch,
      tufTrustedRoot: function () {
        return tufRoot || null;
      } }));
}

async function outcome(v, digest) {
  log.debug("Entering outcome().");
  try {
    const selectors = await v.verify(digest || REPO_DIGEST);
    log.debug("Leaving outcome(). Verified.");
    return { ok: true, selectors: selectors };
  } catch (e) {
    log.debug("Caught in outcome(): " + ((e && e.message) || e));
    log.debug("Leaving outcome(). Refused.");
    return { ok: false, why: String(e.message), code: e.stsCode };
  }
}

const HEX = DIGEST.replace(/^sha256:/, '');
const SIG_TAG = 'sha256-' + HEX + '.sig';
const ATT_TAG = 'sha256-' + HEX + '.att';

async function keyed(t, m) {
  log.debug("Entering keyed().");
  t.log.info('=== cosign signatures under a configured key ===');
  const keyFile = path.join(WORK, 'cosign.pub');
  fs.writeFileSync(keyFile, m.cosign.pem);
  config.setOverride('spiffe.dockerSigstorePublicKeyFiles', keyFile);
  config.setOverride('spiffe.dockerSigstoreTrustedRootFile', m.rootFile);
  config.setOverride('spiffe.dockerSigstoreAllowedRegistries',
                     REGISTRY + ',auth.test');
  config.setOverride('spiffe.dockerSigstoreIgnoreAttestations', true);
  const asked = [];
  const good = await signatureLayer({ key: m.cosign, rekor: m.rekor });
  let got = await outcome(verifier(registry({ [SIG_TAG]: [good] }, asked)));
  t.check(got.ok && got.selectors[0] === 'image-signature:verified' &&
          got.selectors.indexOf('image-signature-log-index:1234') >= 0 &&
          got.selectors.indexOf('image-signature-log-id:' +
                                sha256(m.rekor.spki)) >= 0 &&
          got.selectors.some(function (s) {
            return /^image-signature-value:/.test(s);
          }) &&
          got.selectors.some(function (s) {
            return /^image-signature-integrated-time:\d+$/.test(s);
          }) &&
          got.selectors.some(function (s) {
            return /^image-signature-signed-entry-timestamp:/.test(s);
          }) &&
          !got.selectors.some(function (s) {
            return /^image-signature-subject:/.test(s);
          }),
          'a keyed signature with its Rekor bundle verifies, with SPIRE\'s ' +
          'image-signature selectors (no subject or issuer: no certificate)',
          show(got));
  t.check(asked.some(function (u) {
            return u.indexOf('https://auth.test/token?') === 0 &&
                   u.indexOf('scope=repository%3Ateam%2Fapp%3Apull') >= 0;
          }),
          'the registry\'s Bearer challenge was answered with a pull token ' +
          'from its realm', show(asked));

  const other = ecKey();
  const wrong = await signatureLayer({ key: other, rekor: m.rekor });
  got = await outcome(verifier(registry({ [SIG_TAG]: [wrong] }, [])));
  t.check(!got.ok && /names another key/.test(got.why),
          'a signature under another key is refused: its log entry names a ' +
          'key that is not the configured one', show(got));
  config.setOverride('spiffe.dockerSigstoreSkipTlog', true);
  got = await outcome(verifier(registry({ [SIG_TAG]: [wrong] }, [])));
  t.check(!got.ok && got.code === 'STS-SPIFFE-0128' &&
          /does not verify under the configured key/.test(got.why),
          'and with the log skipped, its signature does not verify under ' +
          'the configured key (STS-SPIFFE-0128)', show(got));
  config.clearOverride('spiffe.dockerSigstoreSkipTlog');

  const unlogged = await signatureLayer({ key: m.cosign });
  got = await outcome(verifier(registry({ [SIG_TAG]: [unlogged] }, [])));
  t.check(!got.ok && /no Rekor bundle/.test(got.why),
          'a signature with no Rekor bundle is refused while the log is ' +
          'required', show(got));
  config.setOverride('spiffe.dockerSigstoreSkipTlog', true);
  got = await outcome(verifier(registry({ [SIG_TAG]: [unlogged] }, [])));
  t.check(got.ok && show(got.selectors).indexOf('log-index') < 0,
          'with spiffe.dockerSigstoreSkipTlog it verifies, and no log ' +
          'selector is emitted', show(got));
  config.clearOverride('spiffe.dockerSigstoreSkipTlog');

  const badSet = await signatureLayer({ key: m.cosign, rekor: m.rekor,
                                        spoilSet: true });
  got = await outcome(verifier(registry({ [SIG_TAG]: [badSet] }, [])));
  t.check(!got.ok && /unable to verify SET/.test(got.why),
          'a bundle whose signed entry timestamp does not verify under the ' +
          'Rekor key is refused', show(got));

  const elsewhere = await signatureLayer({
    key: m.cosign, rekor: m.rekor,
    payload: simpleSigning('sha256:' + 'e'.repeat(64)) });
  got = await outcome(verifier(registry({ [SIG_TAG]: [elsewhere] }, [])));
  t.check(!got.ok && /signed payload is for sha256:e/.test(got.why),
          'a genuine signature of ANOTHER image under this image\'s .sig tag ' +
          'is refused — the claim check SPIRE does not make', show(got));

  got = await outcome(verifier(registry({}, [])));
  t.check(!got.ok && /no signatures found/.test(got.why),
          'an image with no signature is refused', show(got));

  t.log.info('=== a post-quantum key ===');
  const pq = await mldsaKey();
  const pqFile = path.join(WORK, 'cosign-mldsa.pub');
  fs.writeFileSync(pqFile, pq.pem);
  config.setOverride('spiffe.dockerSigstorePublicKeyFiles', pqFile);
  const pqLayer = await signatureLayer({ key: pq, rekor: m.rekor });
  got = await outcome(verifier(registry({ [SIG_TAG]: [pqLayer] }, [])));
  t.check(got.ok, 'an ML-DSA-65 signature verifies under an ML-DSA key file',
          show(got));
  config.setOverride('spiffe.dockerSigstorePublicKeyFiles', keyFile);

  t.log.info('=== attestations ===');
  config.clearOverride('spiffe.dockerSigstoreIgnoreAttestations');
  got = await outcome(verifier(registry({ [SIG_TAG]: [good] }, [])));
  t.check(!got.ok && got.code === 'STS-SPIFFE-0130' &&
          /no matching attestations/.test(got.why),
          'with attestations required (SPIRE\'s default), an image with none ' +
          'is refused (STS-SPIFFE-0130)', show(got));
  const att = await attestationLayer({ key: m.cosign, rekor: m.rekor,
                                       digest: DIGEST });
  got = await outcome(verifier(registry({ [SIG_TAG]: [good],
                                          [ATT_TAG]: [att] }, [])));
  t.check(got.ok && got.selectors[1] === 'image-attestations:verified',
          'an in-toto attestation for this digest verifies, and adds ' +
          'image-attestations:verified', show(got));
  const attElsewhere = await attestationLayer({
    key: m.cosign, rekor: m.rekor, digest: 'sha256:' + 'f'.repeat(64) });
  got = await outcome(verifier(registry({ [SIG_TAG]: [good],
                                          [ATT_TAG]: [attElsewhere] }, [])));
  t.check(!got.ok && /subject is not/.test(got.why),
          'an attestation whose statement is about another image is refused',
          show(got));
  config.setOverride('spiffe.dockerSigstoreIgnoreAttestations', true);

  t.log.info('=== the registry is the workload\'s choice ===');
  config.setOverride('spiffe.dockerSigstoreAllowedRegistries', 'auth.test');
  got = await outcome(verifier(registry({ [SIG_TAG]: [good] }, [])));
  t.check(!got.ok && got.code === 'STS-SPIFFE-0127' &&
          /not in spiffe.dockerSigstoreAllowedRegistries/.test(got.why),
          'a registry not allowed is not dialled (STS-SPIFFE-0127)', show(got));
  config.setOverride('spiffe.dockerSigstoreAllowedRegistries', REGISTRY);
  got = await outcome(verifier(registry({ [SIG_TAG]: [good] }, [])));
  t.check(!got.ok && /asks for a token from https:\/\/auth.test/.test(got.why),
          'nor is a token realm that is not allowed', show(got));
  config.setOverride('spiffe.dockerSigstoreAllowedRegistries',
                     REGISTRY + ',auth.test');
  config.setOverride('spiffe.dockerSigstoreSkippedImages', REPO_DIGEST);
  got = await outcome(verifier(registry({}, [])));
  t.check(got.ok && got.selectors.length === 0,
          'a skipped image is attested without verification and without ' +
          'selectors', show(got));
  config.clearOverride('spiffe.dockerSigstoreSkippedImages');
  log.debug("Leaving keyed().");
}

async function keyless(t, m) {
  log.debug("Entering keyless().");
  t.log.info('=== keyless: a Fulcio certificate ===');
  config.clearOverride('spiffe.dockerSigstorePublicKeyFiles');
  config.setOverride('spiffe.dockerSigstoreAllowedIdentities',
                     ISSUER + '=' + SIGNER);
  const cert = await signingCertificate(m.ca, m.ct, SIGNER, ISSUER, false);
  const layer = await signatureLayer({ key: cert, cert: cert.pem,
                                       rekor: m.rekor });
  let got = await outcome(verifier(registry({ [SIG_TAG]: [layer] }, [])));
  t.check(got.ok && got.selectors.indexOf('image-signature-subject:' +
                                          SIGNER) >= 0 &&
          got.selectors.indexOf('image-signature-issuer:' + ISSUER) >= 0,
          'a keyless signature whose certificate chains to the Fulcio root, ' +
          'carries a verifying SCT and names an allowed signer verifies, ' +
          'with the subject and issuer selectors', show(got));

  config.setOverride('spiffe.dockerSigstoreAllowedIdentities',
                     ISSUER + '=someone-else@example.com');
  got = await outcome(verifier(registry({ [SIG_TAG]: [layer] }, [])));
  t.check(!got.ok && /none of the expected identities/.test(got.why),
          'a signer not allowed is refused', show(got));
  config.setOverride('spiffe.dockerSigstoreAllowedIdentities',
                     '^https://issuer\\.test$=^.*@example\\.com$');
  got = await outcome(verifier(registry({ [SIG_TAG]: [layer] }, [])));
  t.check(got.ok, 'a regular expression pair matches as SPIRE\'s does',
          show(got));
  config.setOverride('spiffe.dockerSigstoreAllowedIdentities', '');
  got = await outcome(verifier(registry({ [SIG_TAG]: [layer] }, [])));
  t.check(!got.ok && /admits no keyless signer/.test(got.why),
          'an empty allow list admits no keyless signer — stricter than ' +
          'SPIRE', show(got));
  config.setOverride('spiffe.dockerSigstoreAllowedIdentities',
                     ISSUER + '=' + SIGNER);

  const noSct = await signingCertificate(m.ca, m.ct, SIGNER, ISSUER, true);
  const noSctLayer = await signatureLayer({ key: noSct, cert: noSct.pem,
                                            rekor: m.rekor });
  got = await outcome(verifier(registry({ [SIG_TAG]: [noSctLayer] }, [])));
  t.check(!got.ok && /embedded SCT/.test(got.why),
          'a certificate without an embedded SCT is refused', show(got));
  config.setOverride('spiffe.dockerSigstoreIgnoreSct', true);
  got = await outcome(verifier(registry({ [SIG_TAG]: [noSctLayer] }, [])));
  t.check(got.ok, 'and verifies with spiffe.dockerSigstoreIgnoreSct',
          show(got));
  config.clearOverride('spiffe.dockerSigstoreIgnoreSct');

  const otherLog = ecKey();
  const unknownLog = await signingCertificate(m.ca, otherLog, SIGNER, ISSUER,
                                              false);
  const unknownLogLayer = await signatureLayer({ key: unknownLog,
                                                 cert: unknownLog.pem,
                                                 rekor: m.rekor });
  got = await outcome(verifier(registry({ [SIG_TAG]: [unknownLogLayer] },
                                        [])));
  t.check(!got.ok && /CT log not in the trust root/.test(got.why),
          'an SCT from a CT log the trust root does not name is refused',
          show(got));

  const stranger = await fulcio();
  const foreign = await signingCertificate(stranger, m.ct, SIGNER, ISSUER,
                                           false);
  const foreignLayer = await signatureLayer({ key: foreign, cert: foreign.pem,
                                              rekor: m.rekor });
  got = await outcome(verifier(registry({ [SIG_TAG]: [foreignLayer] }, [])));
  t.check(!got.ok && /cert verification failed/.test(got.why),
          'a certificate from a CA the trust root does not name is refused',
          show(got));
  log.debug("Leaving keyless().");
}

// ----- TUF -----------------------------------------------------------------

function tufKey() {
  log.debug("Entering tufKey().");
  const key = ecKey();
  const doc = { keytype: 'ecdsa', scheme: 'ecdsa-sha2-nistp256',
                keyval: { public: key.pem } };
  log.debug("Leaving tufKey().");
  return { key: key, doc: doc, id: sha256(Buffer.from(olpc(doc))) };
}

function tufSign(signed, keys) {
  log.debug("Entering tufSign().");
  const bytes = Buffer.from(olpc(signed), 'utf8');
  log.debug("Leaving tufSign().");
  return { signed: signed, signatures: keys.map(function (k) {
    return { keyid: k.id, sig: k.key.sign(bytes).toString('hex') };
  }) };
}

function future(days) {
  log.debug("Entering future().");
  log.debug("Leaving future().");
  return new Date(Date.now() + days * 86400000).toISOString()
    .replace(/\.\d+Z$/, 'Z');
}

// A TUF repository: root v1 and a v2 that rotates the root key, and the
// three other roles over `target` (the trusted_root.json bytes).
function tufRepository(target) {
  log.debug("Entering tufRepository().");
  const k = { root1: tufKey(), root2: tufKey(), timestamp: tufKey(),
              snapshot: tufKey(), targets: tufKey() };
  const keys = {};
  Object.keys(k).forEach(function (name) {
    keys[k[name].id] = k[name].doc;
  });
  const roles = function (rootKey) {
    return { root: { keyids: [rootKey.id], threshold: 1 },
             timestamp: { keyids: [k.timestamp.id], threshold: 1 },
             snapshot: { keyids: [k.snapshot.id], threshold: 1 },
             targets: { keyids: [k.targets.id], threshold: 1 } };
  };
  const root1 = tufSign({ _type: 'root', spec_version: '1.0.31', version: 1,
                          expires: future(365), consistent_snapshot: true,
                          keys: keys, roles: roles(k.root1) }, [k.root1]);
  const root2 = tufSign({ _type: 'root', spec_version: '1.0.31', version: 2,
                          expires: future(365), consistent_snapshot: true,
                          keys: keys, roles: roles(k.root2) },
                        [k.root1, k.root2]);
  const repo = { k: k, files: {}, target: target };
  repo.files['2.root.json'] = JSON.stringify(root2);
  repo.publish = function (versions, spoil) {
    const v = versions || {};
    const targets = tufSign({ _type: 'targets', spec_version: '1.0.31',
      version: v.targets || 1, expires: spoil === 'expired-targets'
        ? '2020-01-01T00:00:00Z' : future(30),
      targets: { 'trusted_root.json': { length: target.length,
        hashes: { sha256: sha256(target), sha512: nodeCrypto
          .createHash('sha512').update(target).digest('hex') } } } },
      [k.targets]);
    const targetsBytes = Buffer.from(JSON.stringify(targets));
    const snapshot = tufSign({ _type: 'snapshot', spec_version: '1.0.31',
      version: v.snapshot || 1, expires: future(30),
      meta: { 'targets.json': { version: v.targets || 1 } } }, [k.snapshot]);
    const snapshotBytes = Buffer.from(JSON.stringify(snapshot));
    const timestamp = tufSign({ _type: 'timestamp', spec_version: '1.0.31',
      version: v.timestamp || 1, expires: future(1),
      meta: { 'snapshot.json': { version: v.snapshot || 1,
        length: snapshotBytes.length,
        hashes: { sha256: sha256(snapshotBytes) } } } },
      [spoil === 'bad-timestamp' ? k.snapshot : k.timestamp]);
    repo.files['timestamp.json'] = JSON.stringify(timestamp);
    repo.files[(v.snapshot || 1) + '.snapshot.json'] = snapshotBytes;
    repo.files[(v.targets || 1) + '.targets.json'] = targetsBytes;
    repo.files['targets/' + sha256(target) + '.trusted_root.json'] =
      spoil === 'bad-target' ? Buffer.concat([target, Buffer.from(' ')])
                             : target;
  };
  log.debug("Leaving tufRepository().");
  return { repo: repo, root1: root1 };
}

async function tuf(t, m) {
  log.debug("Entering tuf().");
  t.log.info('=== TUF ===');
  const target = Buffer.from(JSON.stringify(m.trusted));
  const made = tufRepository(target);
  const repo = made.repo;
  const rootFile = path.join(WORK, 'tuf-root.json');
  fs.writeFileSync(rootFile, JSON.stringify(made.root1));
  config.setOverride('spiffe.dockerSigstoreTufRootFile', rootFile);
  config.setOverride('spiffe.dockerSigstoreTufUrl', 'https://tuf.test/');
  const store = new Map();
  const fetched = [];
  const client = new tufModule.SigstoreTuf(Object.assign(
    tufModule.SigstoreTuf.defaultDeps(), {
      store: store,
      fetch: function (url) {
        fetched.push(url);
        const name = url.replace('https://tuf.test/', '');
        const body = repo.files[name];
        return Promise.resolve(body === undefined
          ? { ok: false, status: 404, body: Buffer.alloc(0), why: 'HTTP 404' }
          : { ok: true, status: 200, body: Buffer.from(body), why: '' });
      } }));
  repo.publish({ timestamp: 5, snapshot: 5, targets: 5 });
  let got = await client.refresh();
  const first = client.state();
  t.check(got.ok && first.verified && first.rootVersion === 2 &&
          first.targetsVersion === 5 &&
          show(client.trustedRoot()) === show(m.trusted),
          'a refresh walks the root rotation (v1 to v2, signed by both), ' +
          'verifies timestamp, snapshot and targets, and keeps the ' +
          'trusted_root.json whose length and hashes the targets name',
          show(got) + ' ' + show(first));
  t.check(fetched.indexOf('https://tuf.test/3.root.json') >= 0 &&
          fetched.indexOf('https://tuf.test/5.snapshot.json') >= 0 &&
          fetched.indexOf('https://tuf.test/targets/' + sha256(target) +
                          '.trusted_root.json') >= 0,
          'with consistent snapshots, by version and by hash', show(fetched));

  const refused = async function (label, versions, spoil) {
    log.debug("Entering refused(). " + label);
    repo.publish(versions, spoil);
    const outcome = await client.refresh();
    const state = client.state();
    t.check(!outcome.ok && state.verified && state.targetsVersion === 5 &&
            show(client.trustedRoot()) === show(m.trusted) &&
            !!state.lastError,
            label + ': refused, and the last good trust root is kept',
            show(outcome) + ' ' + show(state));
    log.debug("Leaving refused().");
    return outcome.summary;
  };
  let why = await refused('a timestamp signed by the wrong key',
                          { timestamp: 6, snapshot: 6, targets: 6 },
                          'bad-timestamp');
  t.check(/valid signature/.test(why), 'the threshold is named', why);
  why = await refused('a timestamp older than the one held',
                      { timestamp: 4, snapshot: 5, targets: 5 });
  t.check(/went back/.test(why), 'a rollback is named', why);
  why = await refused('expired targets metadata',
                      { timestamp: 7, snapshot: 7, targets: 7 },
                      'expired-targets');
  t.check(/expired/.test(why), 'the expiry is named', why);
  why = await refused('a target whose hash does not match',
                      { timestamp: 8, snapshot: 8, targets: 8 }, 'bad-target');
  t.check(/does not match|bytes and its metadata/.test(why),
          'the mismatch is named', why);
  repo.publish({ timestamp: 9, snapshot: 9, targets: 9 });
  got = await client.refresh();
  t.check(got.ok && client.state().targetsVersion === 9 &&
          !client.state().lastError,
          'and a good refresh after them moves on', show(client.state()));

  t.log.info('=== the verifier on the TUF root ===');
  config.clearOverride('spiffe.dockerSigstoreTrustedRootFile');
  const cert = await signingCertificate(m.ca, m.ct, SIGNER, ISSUER, false);
  const layer = await signatureLayer({ key: cert, cert: cert.pem,
                                       rekor: m.rekor });
  got = await outcome(verifier(registry({ [SIG_TAG]: [layer] }, []),
                               client.trustedRoot()));
  t.check(got.ok, 'a keyless signature verifies against the trust root TUF ' +
          'delivered', show(got));
  got = await outcome(verifier(registry({ [SIG_TAG]: [layer] }, []), null));
  t.check(!got.ok && got.code === 'STS-SPIFFE-0126' &&
          /no refresh has completed/.test(got.why),
          'and with TUF configured and nothing verified yet, the attestation ' +
          'is refused, naming the job (STS-SPIFFE-0126)', show(got));
  config.clearOverride('spiffe.dockerSigstoreTufRootFile');
  config.clearOverride('spiffe.dockerSigstoreTufUrl');
  log.debug("Leaving tuf().");
}

async function attestor(t, m) {
  log.debug("Entering attestor().");
  t.log.info('=== the docker attestor with sigstore on ===');
  config.setOverride('spiffe.dockerSigstoreTrustedRootFile', m.rootFile);
  config.setOverride('spiffe.dockerSigstoreEnabled', true);
  const container = 'a'.repeat(64);
  const procRoot = path.join(WORK, 'proc');
  fs.mkdirSync(path.join(procRoot, '9'), { recursive: true });
  fs.writeFileSync(path.join(procRoot, '9', 'cgroup'),
                   '0::/system.slice/docker-' + container + '.scope\n');
  const engine = {
    requestLocalSocket: function (socketPath, requestPath) {
      if (requestPath.indexOf('/containers/') >= 0) {
        return Promise.resolve({ ok: true, status: 200, body: Buffer.from(
          JSON.stringify({ Config: { Labels: {}, Env: [],
                                     Image: REGISTRY + '/' + REPO } })) });
      }
      return Promise.resolve({ ok: true, status: 200, body: Buffer.from(
        JSON.stringify({ Id: 'sha256:' + 'b'.repeat(64),
                         RepoDigests: [REPO_DIGEST] })) });
    }
  };
  const build = function (fetch) {
    log.debug("Entering build().");
    const table = require('../spiffe/spiffe_workload_attestation');
    const workload = new table.WorkloadAttestation(
      table.WorkloadAttestation.defaultDeps());
    log.debug("Leaving build().");
    return new dockerAttestor.DockerWorkloadAttestor(Object.assign(
      dockerAttestor.DockerWorkloadAttestor.defaultDeps(
        workload.containerInfo.bind(workload),
        workload.cgroupPaths.bind(workload), verifier(fetch)),
      { outbound: engine }));
  };
  const keyFile = path.join(WORK, 'cosign.pub');
  config.setOverride('spiffe.dockerSigstorePublicKeyFiles', keyFile);
  const good = await signatureLayer({ key: m.cosign, rekor: m.rekor });
  const facts = { tag: 't', visible: true, pid: 9, procRoot: procRoot };
  const got = await build(registry({ [SIG_TAG]: [good] }, [])).attest(facts);
  t.check(got.indexOf('image_id:' + REGISTRY + '/' + REPO) >= 0 &&
          got.indexOf('image-signature:verified') >= 0,
          'a verified image adds SPIRE\'s signature selectors to the docker ' +
          'ones', show(got));
  let failed = '';
  try {
    await build(registry({}, [])).attest(facts);
  } catch (e) {
    log.debug("Caught in attestor(): " + ((e && e.message) || e));
    failed = String(e.message);
  }
  t.check(/sigstore signature verification failed for image/.test(failed),
          'an image whose signature does not verify FAILS the attestation — ' +
          'the connection is refused, never merely short of a selector',
          failed);
  log.debug("Leaving attestor().");
}

async function run(t) {
  log.debug("Entering run().");
  const m = { cosign: ecKey(), rekor: ecKey(), ct: ecKey(),
              ca: await fulcio() };
  m.trusted = trustedRoot(m.ca, m.rekor, m.ct);
  m.rootFile = path.join(WORK, 'trusted_root.json');
  fs.writeFileSync(m.rootFile, JSON.stringify(m.trusted));
  try {
    await keyed(t, m);
    await keyless(t, m);
    await tuf(t, m);
    await attestor(t, m);
  } finally {
    SETTINGS.forEach(function (key) {
      config.clearOverride(key);
    });
    try {
      fs.rmSync(WORK, { recursive: true, force: true });
    } catch (e) {
      // A temporary directory left behind is not a failure of anything
      // under test.
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_sigstore',
  describe: 'cosign image signatures (keyed, keyless with an SCT, Rekor ' +
            'bundles, attestations, post-quantum) and the sigstore TUF ' +
            'trust root, every key made at run time',
  run: run
};
