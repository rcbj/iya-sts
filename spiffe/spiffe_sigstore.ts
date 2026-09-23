'use strict';
//
// File: spiffe_sigstore.ts
//
// ---------------------------------------------------------------------------
// COSIGN IMAGE SIGNATURES FOR THE `docker` WORKLOAD ATTESTOR (#170,
// 2026-09-23).
//
// SPIRE's `pkg/agent/common/sigstore`: before a docker workload is given
// selectors, the image it runs must carry a cosign signature that verifies,
// and SPIRE's `image-signature…` selectors describe that signature. SPIRE
// hands the whole of it to cosign's Go library; this is the same flow, read
// from cosign's `pkg/cosign/verify.go` (v3), with every signature and
// certificate check in `common/crypto.js` and `common/pki.js` — the standing
// rule — and only the flow, the registry client and the selectors here.
//
// FOR ONE REPOSITORY DIGEST (`repo@sha256:…`, from the Engine's RepoDigests):
//
//   1. `spiffe.dockerSigstoreSkippedImages` names it: verified by nobody,
//      no selectors (SPIRE's skipped_images).
//   2. The trust material: the cosign public key FILES
//      (`spiffe.dockerSigstorePublicKeyFiles`) and the sigstore trust root —
//      the one TUF last verified (`spiffe_sigstore_tuf.ts`) or, with TUF off,
//      the pinned `spiffe.dockerSigstoreTrustedRootFile`. Neither: refused
//      (STS-SPIFFE-0126).
//   3. The signature image, `<repo>:sha256-<hex>.sig`, fetched from the
//      registry over the OCI distribution API — ONLY from a registry in
//      `spiffe.dockerSigstoreAllowedRegistries`, because the registry is
//      named by the image, which is the WORKLOAD'S choice (STS-SPIFFE-0127).
//      Every blob is checked against its digest before a byte is read.
//   4. Each layer is a signature: the payload blob, the
//      `dev.cosignproject.cosign/signature` annotation, and optionally the
//      certificate, the chain and the Rekor bundle annotations. It verifies
//      when, as in cosign's `verifyInternal()`:
//        a. the Rekor bundle (unless `spiffe.dockerSigstoreSkipTlog`) names
//           this signature, this key and the SHA-256 of this payload, and
//           its signed entry timestamp verifies under a trusted Rekor key
//           valid at that time (`crypto.verifyRekorSet()`) — a signature
//           WITHOUT a bundle is refused, because this service verifies the
//           log entry offline and never looks one up (STS-SPIFFE-0129);
//        b. the key is a configured key (a certificate, if attached, must
//           hold the same key), or — keyless — the certificate chains to a
//           Fulcio root at its own notBefore (`pki.verifyPathToAnchors()`,
//           cosign's `TrustedCert()`), is for code signing, carries an
//           embedded SCT from a trusted CT log (`pki.verifyEmbeddedScts()`,
//           unless `spiffe.dockerSigstoreIgnoreSct`), and names an allowed
//           issuer and subject;
//        c. the signature verifies over the payload
//           (`crypto.verifyWithPublicKey()`), post-quantum keys included;
//        d. the certificate and its chain were valid at the log's
//           integrated time — or now, with the log skipped;
//        e. BEYOND SPIRE, which passes no claim verifier to cosign: the
//           payload is a cosign simple-signing document for THIS manifest
//           digest, so a genuine signature of another image copied under
//           this image's `.sig` tag does not verify here.
//      At least one must verify (STS-SPIFFE-0128).
//   5. Unless `spiffe.dockerSigstoreIgnoreAttestations`, the `.att` image's
//      DSSE envelopes the same way (PAE, an in-toto statement whose subject
//      is this digest — the subject check again beyond SPIRE); at least one
//      must verify (STS-SPIFFE-0130), which with SPIRE's default refuses an
//      image that has none.
//   6. The selectors, SPIRE's `detailsToSelectors()`:
//      `image-signature:verified`, `image-attestations:verified`, and per
//      verified signature `image-signature-subject:`, `-issuer:`, `-value:`,
//      `-log-id:`, `-log-index:`, `-integrated-time:`,
//      `-signed-entry-timestamp:` — the subject and issuer only for a
//      keyless signature, which is where they come from.
//
// **EVERY FAILURE THROWS, AND A THROW FAILS THE ATTESTATION** — the docker
// attestor's caller refuses the connection UNAVAILABLE. That is SPIRE's
// behaviour and the issue's: a signature that does not verify is never
// merely a missing selector.
//
// NOT DONE, AND SAID: the online Rekor lookup cosign falls back on when a
// signature has no bundle; the new sigstore bundle format (OCI 1.1
// referrers) cosign v3 can write; RFC 3161 timestamps; SPIRE's per-image
// verification cache (every connection verifies again).
// ---------------------------------------------------------------------------

import fs = require('fs');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import pki = require('../common/pki');
import outbound = require('../federation/federation_http');
import tuf = require('./spiffe_sigstore_tuf');

// cosign's annotation keys and media types (`pkg/oci/static`,
// `pkg/types`).
const ANNOTATION_SIGNATURE = 'dev.cosignproject.cosign/signature';
const ANNOTATION_CERTIFICATE = 'dev.sigstore.cosign/certificate';
const ANNOTATION_CHAIN = 'dev.sigstore.cosign/chain';
const ANNOTATION_BUNDLE = 'dev.sigstore.cosign/bundle';
const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const MANIFEST_ACCEPT = 'application/vnd.oci.image.manifest.v1+json, ' +
  'application/vnd.docker.distribution.manifest.v2+json';

// Docker Hub, as go-containerregistry names it.
const DOCKER_HUB = 'index.docker.io';

// One sigstore trust root, as the verifier uses it.
interface TrustLog { logIdHex: string; spki: Buffer; startMs: number;
                     endMs: number }
interface TrustCa { anchors: any[]; intermediates: Buffer[]; startMs: number;
                    endMs: number }
interface TrustMaterial { keys: Buffer[]; fulcio: TrustCa[];
                          rekor: TrustLog[]; ct: TrustLog[];
                          source: string }

interface SigstoreDeps {
  log: typeof log;
  fs: typeof fs;
  config: typeof config;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  pki: typeof pki;
  // GET one URL: `{ ok, status, body, headers, why }` as
  // `federation_http.requestConfigured()`.
  fetch(url: string, options?: { headers?: Record<string, string> }):
    Promise<{ ok: boolean; status: number; body: Buffer; headers: any;
              why: string }>;
  // The trust root TUF last verified, or null.
  tufTrustedRoot(): any;
  nowMs(): number;
}

class SigstoreVerifier {
  // A failure carrying the code it is recorded under (`verify()` tags it).
  static failure(code: string, message: string): Error {
    helpers.log.debug("Entering SigstoreVerifier.failure(). " + code);
    const err: any = new Error(message);
    err.stsCode = code;
    helpers.log.debug("Leaving SigstoreVerifier.failure().");
    // error-code: none — the constructor; the code travels on the error
    return err;
  }

  constructor(private readonly deps: SigstoreDeps) {
    deps.log.debug("Entering SigstoreVerifier.constructor().");
    deps.log.debug("Leaving SigstoreVerifier.constructor().");
  }

  // `failure()`, as the methods below throw it.
  fail(code: string, message: string): Error {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.fail(). " + code);
    log.debug("Leaving SigstoreVerifier.fail().");
    // error-code: none — the constructor; the code travels on the error
    return SigstoreVerifier.failure(code, message);
  }

  static defaultDeps(): SigstoreDeps {
    helpers.log.debug("Entering SigstoreVerifier.defaultDeps().");
    helpers.log.debug("Leaving SigstoreVerifier.defaultDeps().");
    return {
      log: log, fs: fs, config: config, errorCodes: errorCodes,
      stsCrypto: stsCrypto, pki: pki,
      fetch: function (url, options) {
        return outbound.requestConfigured(url, options);
      },
      tufTrustedRoot: function () {
        return tuf.trustedRoot();
      },
      nowMs: function () {
        return Date.now();
      }
    };
  }

  // A csv setting's elements.
  list(key: string): string[] {
    const { log, config } = this.deps;
    log.debug("Entering SigstoreVerifier.list(). " + key);
    const raw = config.value(key);
    log.debug("Leaving SigstoreVerifier.list().");
    return (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
  }

  // One validity window of a trusted root entry, as milliseconds; 0 for an
  // open end.
  windowOf(validFor: any): { startMs: number; endMs: number } {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.windowOf().");
    const start = Date.parse(String((validFor || {}).start || ''));
    const end = Date.parse(String((validFor || {}).end || ''));
    log.debug("Leaving SigstoreVerifier.windowOf().");
    return { startMs: Number.isFinite(start) ? start : 0,
             endMs: Number.isFinite(end) ? end : 0 };
  }

  // A sigstore trusted_root.json (protobuf-specs' TrustedRoot, JSON form)
  // as the verifier's lists. Throws on a document that is not one.
  parseTrustedRoot(doc: any): { fulcio: TrustCa[]; rekor: TrustLog[];
                                ct: TrustLog[] } {
    const { log, pki } = this.deps;
    const self = this;
    log.debug("Entering SigstoreVerifier.parseTrustedRoot().");
    if (!doc || !Array.isArray(doc.certificateAuthorities)) {
      log.debug("Leaving SigstoreVerifier.parseTrustedRoot(). Not one.");
      // error-code: none — refused under STS-SPIFFE-0126 by the caller
      throw new Error('the trust root is not a sigstore trusted_root.json');
    }
    const logs = function (list: any[]): TrustLog[] {
      log.debug("Entering logs().");
      log.debug("Leaving logs().");
      return (list || []).map(function (one) {
        const spki = Buffer.from(String(((one || {}).publicKey || {})
          .rawBytes || ''), 'base64');
        const window = self.windowOf((one.publicKey || {}).validFor);
        return { logIdHex: Buffer.from(String(((one || {}).logId || {})
                   .keyId || ''), 'base64').toString('hex'),
                 spki: spki, startMs: window.startMs, endMs: window.endMs };
      }).filter(function (one) {
        return one.spki.length && one.logIdHex;
      });
    };
    const fulcio = doc.certificateAuthorities.map(function (ca) {
      const ders = (((ca || {}).certChain || {}).certificates || [])
        .map(function (c) {
          return Buffer.from(String((c || {}).rawBytes || ''), 'base64');
        }).filter(function (der) {
          return der.length;
        });
      const window = self.windowOf(ca.validFor);
      const root = ders.length ? pki.certificateFromDer(ders[ders.length - 1])
                               : null;
      return { anchors: root ? [root] : [],
               intermediates: ders.slice(0, -1),
               startMs: window.startMs, endMs: window.endMs };
    }).filter(function (ca) {
      return ca.anchors.length;
    });
    log.debug("Leaving SigstoreVerifier.parseTrustedRoot().");
    return { fulcio: fulcio, rekor: logs(doc.tlogs), ct: logs(doc.ctlogs) };
  }

  // THE TRUST MATERIAL (step 2); throws STS-SPIFFE-0126.
  trustMaterial(): TrustMaterial {
    const { log, fs, config, stsCrypto, tufTrustedRoot } = this.deps;
    log.debug("Entering SigstoreVerifier.trustMaterial().");
    const keys: Buffer[] = [];
    const files = this.list('spiffe.dockerSigstorePublicKeyFiles');
    for (let i = 0; i < files.length; i++) {
      let spki = null;
      try {
        spki = stsCrypto.spkiFromPublicKeyPem(fs.readFileSync(files[i],
                                                              'utf8'));
      } catch (e) {
        log.debug("Caught in SigstoreVerifier.trustMaterial(): " +
                  ((e && e.message) || e));
      }
      if (!spki) {
        log.debug("Leaving SigstoreVerifier.trustMaterial(). A bad key.");
        throw this.fail('STS-SPIFFE-0126', 'the cosign public key file ' +
                      files[i] + ' could not be read as a PEM public key');
      }
      keys.push(spki);
    }
    let root = null;
    let source = '';
    const tufOn = !!String(config.value('spiffe.dockerSigstoreTufRootFile') ||
                           '');
    if (tufOn) {
      root = tufTrustedRoot();
      source = 'TUF';
      if (!root && !keys.length) {
        log.debug("Leaving SigstoreVerifier.trustMaterial(). TUF has " +
                  "nothing yet.");
        throw this.fail('STS-SPIFFE-0126', 'the sigstore trust root comes ' +
                      'from TUF and no refresh has completed yet — run ' +
                      'spiffe.sigstore-tuf-refresh on /admin/scheduler and ' +
                      'read its outcome');
      }
    } else {
      const pinned = String(config.value(
        'spiffe.dockerSigstoreTrustedRootFile') || '');
      if (pinned) {
        try {
          root = JSON.parse(fs.readFileSync(pinned, 'utf8'));
          source = pinned;
        } catch (e) {
          log.debug("Caught in SigstoreVerifier.trustMaterial(): " +
                    ((e && e.message) || e));
          log.debug("Leaving SigstoreVerifier.trustMaterial(). Unreadable.");
          throw this.fail('STS-SPIFFE-0126', 'the pinned trust root ' + pinned +
                        ' could not be read: ' + ((e && e.message) || e));
        }
      }
    }
    let parsed = { fulcio: [], rekor: [], ct: [] };
    if (root) {
      try {
        parsed = this.parseTrustedRoot(root);
      } catch (e) {
        log.debug("Caught in SigstoreVerifier.trustMaterial(): " +
                  ((e && e.message) || e));
        log.debug("Leaving SigstoreVerifier.trustMaterial(). Not a root.");
        throw this.fail('STS-SPIFFE-0126', String((e && e.message) || e));
      }
    }
    if (!keys.length && !parsed.fulcio.length) {
      log.debug("Leaving SigstoreVerifier.trustMaterial(). Nothing.");
      throw this.fail('STS-SPIFFE-0126', 'nothing is configured to verify an ' +
                    'image signature with: no cosign public key file ' +
                    '(spiffe.dockerSigstorePublicKeyFiles), no TUF trust ' +
                    'root and no pinned trusted_root.json');
    }
    log.debug("Leaving SigstoreVerifier.trustMaterial().");
    return { keys: keys, fulcio: parsed.fulcio, rekor: parsed.rekor,
             ct: parsed.ct, source: source || 'keys' };
  }

  // `repo@sha256:hex` as go-containerregistry reads it: the registry (Docker
  // Hub is `index.docker.io`, and a one-component name there is under
  // `library/`), the repository and the digest. Throws.
  parseReference(repoDigest: string): { registry: string; repository: string;
                                        digest: string } {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.parseReference(). " + repoDigest);
    const at = repoDigest.lastIndexOf('@');
    const name = at > 0 ? repoDigest.slice(0, at) : '';
    const digest = at > 0 ? repoDigest.slice(at + 1) : '';
    if (!name || !/^sha256:[0-9a-f]{64}$/.test(digest)) {
      log.debug("Leaving SigstoreVerifier.parseReference(). Not a digest.");
      throw this.fail('STS-SPIFFE-0127', 'failed to parse image reference ' +
                    '"' + repoDigest + '": it is not repository@sha256:<hex>');
    }
    const parts = name.split('/');
    let registry = DOCKER_HUB;
    if (parts.length > 1 && (/[.:]/.test(parts[0]) || parts[0] ===
                             'localhost')) {
      registry = parts.shift();
    }
    if (registry === 'docker.io' || registry === 'registry-1.docker.io') {
      registry = DOCKER_HUB;
    }
    let repository = parts.join('/');
    if (registry === DOCKER_HUB && parts.length === 1) {
      repository = 'library/' + repository;
    }
    if (!/^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/.test(repository)) {
      log.debug("Leaving SigstoreVerifier.parseReference(). Bad repo.");
      throw this.fail('STS-SPIFFE-0127', 'failed to parse image reference ' +
                    '"' + repoDigest + '": the repository name is invalid');
    }
    log.debug("Leaving SigstoreVerifier.parseReference(). " + registry + "/" +
              repository);
    return { registry: registry, repository: repository, digest: digest };
  }

  // Whether this service may dial `host` (`host` or `host:port`) for
  // signatures (step 3).
  registryAllowed(host: string): boolean {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.registryAllowed(). " + host);
    const wanted = String(host || '').toLowerCase();
    log.debug("Leaving SigstoreVerifier.registryAllowed().");
    return this.list('spiffe.dockerSigstoreAllowedRegistries')
      .some(function (one) {
        return one.toLowerCase() === wanted;
      });
  }

  // The Basic credentials a Docker config.json names for `registry`, or ''.
  registryBasic(registry: string): string {
    const { log, fs, config } = this.deps;
    log.debug("Entering SigstoreVerifier.registryBasic().");
    const file = String(config.value('spiffe.dockerSigstoreRegistryAuthFile') ||
                        '');
    if (!file) {
      log.debug("Leaving SigstoreVerifier.registryBasic(). Anonymous.");
      return '';
    }
    try {
      const auths = (JSON.parse(fs.readFileSync(file, 'utf8')) || {}).auths ||
                    {};
      const names = registry === DOCKER_HUB
        ? [DOCKER_HUB, 'https://index.docker.io/v1/', 'docker.io']
        : [registry, 'https://' + registry];
      for (let i = 0; i < names.length; i++) {
        const one = auths[names[i]];
        if (one && one.auth) {
          log.debug("Leaving SigstoreVerifier.registryBasic(). Found.");
          return String(one.auth);
        }
      }
    } catch (e) {
      log.debug("Caught in SigstoreVerifier.registryBasic(): " +
                ((e && e.message) || e));
      log.debug("Leaving SigstoreVerifier.registryBasic(). Unreadable.");
      throw this.fail('STS-SPIFFE-0127', 'the registry credentials file ' +
                    file + ' could not be read: ' + ((e && e.message) || e));
    }
    log.debug("Leaving SigstoreVerifier.registryBasic(). None.");
    return '';
  }

  // A registry's Bearer challenge answered: a token for pulling
  // `repository`, from the realm the challenge names — which must itself be
  // an allowed https host. Throws.
  async bearerToken(challenge: string, registry: string,
                    repository: string): Promise<string> {
    const { log, fetch } = this.deps;
    log.debug("Entering SigstoreVerifier.bearerToken().");
    const params: Record<string, string> = {};
    String(challenge || '').replace(/^Bearer\s+/i, '')
      .replace(/(\w+)="([^"]*)"/g, function (all, k, v) {
        params[k.toLowerCase()] = v;
        return all;
      });
    let realm = null;
    try {
      realm = new URL(String(params.realm || ''));
    } catch (e) {
      log.debug("Caught in SigstoreVerifier.bearerToken(): " +
                ((e && e.message) || e));
    }
    if (!realm || realm.protocol !== 'https:' ||
        !this.registryAllowed(realm.host)) {
      log.debug("Leaving SigstoreVerifier.bearerToken(). Realm refused.");
      throw this.fail('STS-SPIFFE-0127', 'the registry ' + registry + ' asks ' +
                    'for a token from ' + (params.realm || 'nowhere') +
                    ', which is not an https host in ' +
                    'spiffe.dockerSigstoreAllowedRegistries');
    }
    realm.searchParams.set('scope', 'repository:' + repository + ':pull');
    if (params.service) realm.searchParams.set('service', params.service);
    const basic = this.registryBasic(registry);
    const answer = await fetch(realm.toString(), {
      headers: basic ? { 'Authorization': 'Basic ' + basic } : {} });
    let token = '';
    try {
      const doc = JSON.parse(answer.body.toString('utf8'));
      token = String(doc.token || doc.access_token || '');
    } catch (e) {
      log.debug("Caught in SigstoreVerifier.bearerToken(): " +
                ((e && e.message) || e));
    }
    if (!answer.ok || !token) {
      log.debug("Leaving SigstoreVerifier.bearerToken(). No token.");
      throw this.fail('STS-SPIFFE-0127', 'the registry ' + registry +
                    '\'s token service did not issue a pull token: ' +
                    (answer.why || 'no token in the answer'));
    }
    log.debug("Leaving SigstoreVerifier.bearerToken().");
    return token;
  }

  // One registry GET under `/v2/<repository>/`, answering a Bearer
  // challenge once. Resolves the body, or null on 404. Throws.
  async registryGet(ref: any, path: string, accept: string,
                    auth: { token: string }): Promise<Buffer | null> {
    const { log, fetch } = this.deps;
    log.debug("Entering SigstoreVerifier.registryGet(). " + path);
    const url = 'https://' + ref.registry + '/v2/' + ref.repository + '/' +
                path;
    for (let attempt = 0; attempt < 2; attempt++) {
      const headers: Record<string, string> = { 'Accept': accept };
      if (auth.token) {
        headers['Authorization'] = 'Bearer ' + auth.token;
      } else {
        const basic = this.registryBasic(ref.registry);
        if (basic) headers['Authorization'] = 'Basic ' + basic;
      }
      const answer = await fetch(url, { headers: headers });
      if (answer.status === 404) {
        log.debug("Leaving SigstoreVerifier.registryGet(). 404.");
        return null;
      }
      const challenge = String((answer.headers || {})['www-authenticate'] ||
                               '');
      if (answer.status === 401 && attempt === 0 &&
          /^Bearer\s/i.test(challenge)) {
        auth.token = await this.bearerToken(challenge, ref.registry,
                                            ref.repository);
        continue;
      }
      if (answer.status >= 300 && answer.status < 400 &&
          (answer.headers || {}).location) {
        const moved = await this.redirected(String(answer.headers.location),
                                            url);
        log.debug("Leaving SigstoreVerifier.registryGet(). Redirected.");
        return moved;
      }
      if (!answer.ok) {
        log.debug("Leaving SigstoreVerifier.registryGet(). Failed.");
        throw this.fail('STS-SPIFFE-0127', 'the registry answered ' + path +
                      ': ' + answer.why);
      }
      log.debug("Leaving SigstoreVerifier.registryGet().");
      return answer.body;
    }
    log.debug("Leaving SigstoreVerifier.registryGet(). Unauthorized.");
    throw this.fail('STS-SPIFFE-0127', 'the registry refused ' + path +
                  ' with the token it issued');
  }

  // ONE redirect of a blob GET, to an allowed https host, with no
  // credential — the bytes are checked against their digest afterwards, so
  // nothing unverified comes back from it. Throws.
  async redirected(location: string, from: string): Promise<Buffer> {
    const { log, fetch } = this.deps;
    log.debug("Entering SigstoreVerifier.redirected().");
    let target = null;
    try {
      target = new URL(location, from);
    } catch (e) {
      log.debug("Caught in SigstoreVerifier.redirected(): " +
                ((e && e.message) || e));
    }
    if (!target || target.protocol !== 'https:' ||
        !this.registryAllowed(target.host)) {
      log.debug("Leaving SigstoreVerifier.redirected(). Refused.");
      throw this.fail('STS-SPIFFE-0127', 'the registry redirected to ' +
                    location + ', which is not an https host in ' +
                    'spiffe.dockerSigstoreAllowedRegistries');
    }
    const answer = await fetch(target.toString(), { headers: {} });
    if (!answer.ok) {
      log.debug("Leaving SigstoreVerifier.redirected(). Failed.");
      throw this.fail('STS-SPIFFE-0127', 'the redirected blob could not be ' +
                    'fetched: ' + answer.why);
    }
    log.debug("Leaving SigstoreVerifier.redirected().");
    return answer.body;
  }

  // The layers of a cosign signature or attestation image, each with its
  // blob, or null when the tag does not exist. Throws.
  async layers(ref: any, tag: string, auth: { token: string }):
      Promise<Array<{ payload: Buffer; annotations: any;
                      mediaType: string }> | null> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering SigstoreVerifier.layers(). " + tag);
    const body = await this.registryGet(ref, 'manifests/' + tag,
                                        MANIFEST_ACCEPT, auth);
    if (!body) {
      log.debug("Leaving SigstoreVerifier.layers(). No such tag.");
      return null;
    }
    let manifest = null;
    try {
      manifest = JSON.parse(body.toString('utf8'));
    } catch (e) {
      log.debug("Caught in SigstoreVerifier.layers(): " +
                ((e && e.message) || e));
    }
    if (!manifest || !Array.isArray(manifest.layers)) {
      log.debug("Leaving SigstoreVerifier.layers(). Not a manifest.");
      throw this.fail('STS-SPIFFE-0127', tag + ' is not an image manifest');
    }
    const out = [];
    for (let i = 0; i < manifest.layers.length; i++) {
      const layer = manifest.layers[i] || {};
      const digest = String(layer.digest || '');
      if (!/^sha256:[0-9a-f]{64}$/.test(digest)) {
        log.debug("Leaving SigstoreVerifier.layers(). A bad digest.");
        throw this.fail('STS-SPIFFE-0127', 'a layer of ' + tag + ' names no ' +
                      'sha256 digest');
      }
      const blob = await this.registryGet(ref, 'blobs/' + digest, '*/*',
                                          auth);
      if (!blob || 'sha256:' + stsCrypto.sha256Hex(blob) !== digest) {
        log.debug("Leaving SigstoreVerifier.layers(). A blob mismatch.");
        throw this.fail('STS-SPIFFE-0127', 'the blob ' + digest + ' of ' + tag +
                      ' is missing or does not match its digest');
      }
      out.push({ payload: blob, annotations: layer.annotations || {},
                 mediaType: String(layer.mediaType || '') });
    }
    log.debug("Leaving SigstoreVerifier.layers(). " + out.length);
    return out;
  }

  // The PEM certificates of an annotation, as DER.
  pemDers(text: string): Buffer[] {
    const { log, pki } = this.deps;
    log.debug("Entering SigstoreVerifier.pemDers().");
    const read = pki.certificateBundle(String(text || ''));
    log.debug("Leaving SigstoreVerifier.pemDers().");
    return read.certificates.map(function (one) {
      return one.der;
    });
  }

  // An identity pair of `spiffe.dockerSigstoreAllowedIdentities`
  // (`issuer=subject`) against a certificate's issuer and subject: exact, or
  // a regular expression where the text holds one of SPIRE's regex
  // characters (`containsRegexChars()`), matched as cosign matches it —
  // UNANCHORED, so a pattern that must match the whole value says ^…$.
  identityAllowed(issuer: string, subject: string): boolean {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.identityAllowed().");
    const matches = function (pattern: string, value: string): boolean {
      log.debug("Entering matches().");
      if (!/[*+?^${}[\]|()]/.test(pattern)) {
        log.debug("Leaving matches(). Exact.");
        return pattern === value;
      }
      try {
        log.debug("Leaving matches(). Regex.");
        return new RegExp(pattern).test(value);
      } catch (e) {
        log.debug("Caught in matches(): " + ((e && e.message) || e));
        log.debug("Leaving matches(). A bad pattern.");
        return false;
      }
    };
    const pairs = this.list('spiffe.dockerSigstoreAllowedIdentities');
    log.debug("Leaving SigstoreVerifier.identityAllowed().");
    return pairs.some(function (pair) {
      const cut = pair.indexOf('=');
      return cut > 0 && matches(pair.slice(0, cut), issuer) &&
             matches(pair.slice(cut + 1), subject);
    });
  }

  // The Rekor entry in a bundle's body: `{ kind, signature, publicKeyPem,
  // hashAlg, hashValue }`, from a hashedrekord, rekord, intoto (v0.0.2) or
  // dsse entry — cosign's `bundleSig()`, `bundleKey()` and `bundleHash()`.
  // Throws.
  rekorEntry(body: string): any {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.rekorEntry().");
    let entry = null;
    try {
      entry = JSON.parse(Buffer.from(String(body || ''), 'base64')
        .toString('utf8'));
    } catch (e) {
      log.debug("Caught in SigstoreVerifier.rekorEntry(): " +
                ((e && e.message) || e));
    }
    const spec = (entry && entry.spec) || {};
    const kind = String((entry && entry.kind) || '');
    const decode = function (b64: any): string {
      return Buffer.from(String(b64 || ''), 'base64').toString('utf8');
    };
    let out = null;
    if (kind === 'hashedrekord' || kind === 'rekord') {
      out = { kind: kind,
              signature: String(((spec.signature || {}).content) || ''),
              publicKeyPem: decode((((spec.signature || {}).publicKey) ||
                                    {}).content),
              hashAlg: String((((spec.data || {}).hash) || {}).algorithm ||
                              ''),
              hashValue: String((((spec.data || {}).hash) || {}).value || '') };
    } else if (kind === 'intoto') {
      const envelope = ((spec.content || {}).envelope) || {};
      const first = (envelope.signatures || [])[0] || {};
      out = { kind: kind, signature: '',
              publicKeyPem: decode(first.publicKey),
              hashAlg: String((((spec.content || {}).hash) || {}).algorithm ||
                              ''),
              hashValue: String((((spec.content || {}).hash) || {}).value ||
                                '') };
    } else if (kind === 'dsse') {
      const first = (spec.signatures || [])[0] || {};
      out = { kind: kind, signature: '', publicKeyPem: decode(first.verifier),
              hashAlg: String((spec.envelopeHash || {}).algorithm || ''),
              hashValue: String((spec.envelopeHash || {}).value || '') };
    }
    if (!out) {
      log.debug("Leaving SigstoreVerifier.rekorEntry(). Unsupported.");
      throw this.fail('STS-SPIFFE-0129', 'the Rekor bundle\'s entry is not a ' +
                    'hashedrekord, rekord, intoto or dsse entry');
    }
    log.debug("Leaving SigstoreVerifier.rekorEntry(). " + kind);
    return out;
  }

  // Step 4a: the bundle, offline (cosign's VerifyBundle()). `expect` is
  // what the entry must name: the attached certificate's DER, or one of the
  // candidate keys' SPKIs. Resolves the integrated time in milliseconds, the
  // bundle's payload and the key the entry named. Throws.
  async verifyBundle(bundleText: string, payload: Buffer, signatureB64: string,
                     expect: { certDer: Buffer | null; keys: Buffer[] },
                     material: TrustMaterial): Promise<any> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering SigstoreVerifier.verifyBundle().");
    if (!bundleText) {
      log.debug("Leaving SigstoreVerifier.verifyBundle(). None.");
      throw this.fail('STS-SPIFFE-0129', 'the signature carries no Rekor ' +
                    'bundle, and this service verifies the transparency log ' +
                    'entry offline and never looks one up ' +
                    '(spiffe.dockerSigstoreSkipTlog skips the log)');
    }
    let bundle = null;
    try {
      bundle = JSON.parse(bundleText);
    } catch (e) {
      log.debug("Caught in SigstoreVerifier.verifyBundle(): " +
                ((e && e.message) || e));
    }
    const p = (bundle && bundle.Payload) || null;
    if (!p || typeof p.body !== 'string' || !bundle.SignedEntryTimestamp) {
      log.debug("Leaving SigstoreVerifier.verifyBundle(). Malformed.");
      throw this.fail('STS-SPIFFE-0129', 'the Rekor bundle is malformed');
    }
    const entry = this.rekorEntry(p.body);
    if (signatureB64 && entry.signature && entry.signature !== signatureB64) {
      log.debug("Leaving SigstoreVerifier.verifyBundle(). Signature.");
      throw this.fail('STS-SPIFFE-0129', 'signature in bundle does not match ' +
                    'signature being verified');
    }
    // comparePublicKey(): the DER under the entry's PEM against the
    // certificate's, or against one of the keys'.
    let key: Buffer = null;
    if (expect.certDer) {
      const named = this.pemDers(entry.publicKeyPem)[0];
      key = named && named.equals(expect.certDer) ? expect.certDer : null;
    } else {
      const named = stsCrypto.spkiFromPublicKeyPem(entry.publicKeyPem);
      key = named ? expect.keys.filter(function (one) {
        return one.equals(named);
      })[0] || null : null;
    }
    if (!key) {
      log.debug("Leaving SigstoreVerifier.verifyBundle(). Key.");
      throw this.fail('STS-SPIFFE-0129', 'comparing public key PEMs: the ' +
                    'Rekor entry names another key or certificate');
    }
    if (entry.hashAlg !== 'sha256' ||
        entry.hashValue.toLowerCase() !== stsCrypto.sha256Hex(payload)) {
      log.debug("Leaving SigstoreVerifier.verifyBundle(). Payload.");
      throw this.fail('STS-SPIFFE-0129', 'matching bundle to payload: the ' +
                    'Rekor entry is for other bytes');
    }
    const integratedMs = Number(p.integratedTime) * 1000;
    const logs = material.rekor.filter(function (one) {
      return (!one.startMs || integratedMs >= one.startMs) &&
             (!one.endMs || integratedMs <= one.endMs);
    });
    const why = await stsCrypto.verifyRekorSet(p, Buffer.from(String(
      bundle.SignedEntryTimestamp), 'base64'), logs);
    if (why) {
      log.debug("Leaving SigstoreVerifier.verifyBundle(). SET.");
      throw this.fail('STS-SPIFFE-0129', 'verifying bundle: ' + why);
    }
    log.debug("Leaving SigstoreVerifier.verifyBundle().");
    return { integratedMs: integratedMs, payload: p, key: key,
             set: String(bundle.SignedEntryTimestamp) };
  }

  // Step 4b, keyless: the certificate chains to a Fulcio root, is for code
  // signing, carries a verifying SCT and names an allowed identity. Resolves
  // `{ facts, chain }`. Throws.
  async verifyCertificate(leafDer: Buffer, chainDers: Buffer[],
                          material: TrustMaterial): Promise<any> {
    const { log, pki, config } = this.deps;
    log.debug("Entering SigstoreVerifier.verifyCertificate().");
    const facts = pki.sigstoreSignerFacts(leafDer);
    if (!facts || !facts.spki) {
      log.debug("Leaving SigstoreVerifier.verifyCertificate(). Unreadable.");
      throw this.fail('STS-SPIFFE-0128', 'invalid certificate found on ' +
                    'signature');
    }
    let path = null;
    const reasons = [];
    for (let i = 0; i < material.fulcio.length && !path; i++) {
      const ca = material.fulcio[i];
      if ((ca.startMs && facts.notBefore < ca.startMs) ||
          (ca.endMs && facts.notBefore > ca.endMs)) {
        reasons.push('a Fulcio CA outside its validity then');
        continue;
      }
      const verdict = await pki.verifyPathToAnchors(
        leafDer, chainDers.concat(ca.intermediates), ca.anchors,
        { now: facts.notBefore });
      if (verdict.ok) {
        path = verdict.chain;
      } else {
        reasons.push(verdict.reason);
      }
    }
    if (!path) {
      log.debug("Leaving SigstoreVerifier.verifyCertificate(). No path.");
      throw this.fail('STS-SPIFFE-0128', 'cert verification failed: ' +
                    (reasons.join('; ') || 'no Fulcio root is trusted'));
    }
    if (!facts.codeSigning) {
      log.debug("Leaving SigstoreVerifier.verifyCertificate(). EKU.");
      throw this.fail('STS-SPIFFE-0128', 'cert verification failed: the ' +
                    'certificate is not for code signing');
    }
    if (!config.value('spiffe.dockerSigstoreIgnoreSct')) {
      if (path.length < 2) {
        log.debug("Leaving SigstoreVerifier.verifyCertificate(). No issuer.");
        throw this.fail('STS-SPIFFE-0128', 'certificate chain must contain at ' +
                      'least a certificate and its issuer');
      }
      const sct = await pki.verifyEmbeddedScts(leafDer, path[1].der,
                                               material.ct);
      if (!sct.ok) {
        log.debug("Leaving SigstoreVerifier.verifyCertificate(). SCT.");
        throw this.fail('STS-SPIFFE-0128', sct.why);
      }
    }
    if (!this.identityAllowed(facts.issuer, facts.subject)) {
      log.debug("Leaving SigstoreVerifier.verifyCertificate(). Identity.");
      throw this.fail('STS-SPIFFE-0128', 'none of the expected identities ' +
                    'matched what was in the certificate (issuer "' +
                    facts.issuer + '", subject "' + facts.subject + '")' +
                    (this.list('spiffe.dockerSigstoreAllowedIdentities')
                      .length ? '' : '; spiffe.dockerSigstoreAllowed' +
                      'Identities is empty, which admits no keyless signer'));
    }
    log.debug("Leaving SigstoreVerifier.verifyCertificate().");
    return { facts: facts, chain: path };
  }

  // Step 4d: the certificate and its chain valid at `atMs` (CheckExpiry()).
  checkExpiry(chain: any[], atMs: number): string {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.checkExpiry().");
    for (let i = 0; i < chain.length - 1; i++) {
      const from = Date.parse(chain[i].x509.validFrom);
      const to = Date.parse(chain[i].x509.validTo);
      if (to < atMs || from > atMs) {
        log.debug("Leaving SigstoreVerifier.checkExpiry(). Outside.");
        return (i === 0 ? 'certificate' : 'issuing CA certificate') +
               ' was not valid at ' + new Date(atMs).toISOString();
      }
    }
    log.debug("Leaving SigstoreVerifier.checkExpiry().");
    return '';
  }

  // Step 4e and 5's subject check: the signed content is about THIS
  // manifest digest.
  claimProblem(kind: string, payload: Buffer, digest: string): string {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.claimProblem(). " + kind);
    let doc = null;
    try {
      doc = JSON.parse(payload.toString('utf8'));
    } catch (e) {
      log.debug("Caught in SigstoreVerifier.claimProblem(): " +
                ((e && e.message) || e));
    }
    if (kind === 'signature') {
      const critical = (doc && doc.critical) || {};
      const named = String((critical.image || {})['docker-manifest-digest'] ||
                           '');
      log.debug("Leaving SigstoreVerifier.claimProblem().");
      return named === digest ? ''
        : 'the signed payload is for ' + (named || 'no image') + ', not ' +
          digest;
    }
    const hex = digest.replace(/^sha256:/, '');
    const subjects = (doc && doc.subject) || [];
    const found = subjects.some(function (one) {
      return String(((one || {}).digest || {}).sha256 || '') === hex;
    });
    log.debug("Leaving SigstoreVerifier.claimProblem().");
    return found ? '' : 'the in-toto statement\'s subject is not ' + digest;
  }

  // ONE SIGNATURE OR ATTESTATION LAYER (step 4, or 5 for `attestation`).
  // Resolves SPIRE's signatureDetails. Throws.
  async verifyLayer(kind: string, layer: any, digest: string,
                    material: TrustMaterial): Promise<any> {
    const { log, stsCrypto, config, nowMs } = this.deps;
    log.debug("Entering SigstoreVerifier.verifyLayer(). " + kind);
    const code = kind === 'signature' ? 'STS-SPIFFE-0128' : 'STS-SPIFFE-0130';
    const notes = layer.annotations || {};
    const certDers = this.pemDers(notes[ANNOTATION_CERTIFICATE] || '');
    const chainDers = this.pemDers(notes[ANNOTATION_CHAIN] || '');
    const signatureB64 = kind === 'signature'
      ? String(notes[ANNOTATION_SIGNATURE] || '') : '';
    if (kind === 'signature' && !signatureB64) {
      log.debug("Leaving SigstoreVerifier.verifyLayer(). No signature.");
      throw this.fail(code, 'a signature layer carries no ' +
                    ANNOTATION_SIGNATURE + ' annotation');
    }
    // THE KEY (4b). A certificate holding a configured key is that key
    // (cosign with --key checks the two are equal); a certificate holding
    // another key is keyless, verified against the Fulcio roots; with no
    // certificate, the configured keys are the candidates.
    let certificate = null;
    let candidates: Buffer[] = [];
    if (certDers.length) {
      const certSpki = (this.deps.pki.sigstoreSignerFacts(certDers[0]) ||
                        {}).spki || null;
      candidates = material.keys.filter(function (one) {
        return certSpki && one.equals(certSpki);
      });
      if (!candidates.length) {
        if (!material.fulcio.length) {
          log.debug("Leaving SigstoreVerifier.verifyLayer(). Key mismatch.");
          throw this.fail(code, 'both public key and certificate were ' +
                        'provided but did not match, and no Fulcio root is ' +
                        'trusted to verify the certificate on its own');
        }
        certificate = await this.verifyCertificate(certDers[0], chainDers,
                                                   material);
        candidates = [certificate.facts.spki];
      }
    } else if (material.keys.length) {
      candidates = material.keys.slice(0);
    } else {
      log.debug("Leaving SigstoreVerifier.verifyLayer(). No key.");
      throw this.fail(code, 'no certificate found on signature, and no ' +
                    'configured key to verify it with');
    }
    // THE LOG (4a), which also says which key when there were several.
    let logged = null;
    if (!config.value('spiffe.dockerSigstoreSkipTlog')) {
      logged = await this.verifyBundle(String(notes[ANNOTATION_BUNDLE] || ''),
        layer.payload, signatureB64,
        { certDer: certDers.length ? certDers[0] : null, keys: candidates },
        material);
      if (!certDers.length) {
        candidates = [logged.key];
      }
    }
    // THE SIGNATURE (4c).
    let signed = false;
    if (kind === 'signature') {
      for (let i = 0; i < candidates.length && !signed; i++) {
        signed = await stsCrypto.verifyWithPublicKey(candidates[i],
          layer.payload, Buffer.from(signatureB64, 'base64'));
      }
    } else {
      let envelope = null;
      try {
        envelope = JSON.parse(layer.payload.toString('utf8'));
      } catch (e) {
        log.debug("Caught in SigstoreVerifier.verifyLayer(): " +
                  ((e && e.message) || e));
      }
      if (!envelope || envelope.payloadType !== INTOTO_PAYLOAD_TYPE) {
        log.debug("Leaving SigstoreVerifier.verifyLayer(). Envelope.");
        throw this.fail(code, 'invalid payloadType ' +
                      ((envelope && envelope.payloadType) || 'none') +
                      ' on envelope. Expected ' + INTOTO_PAYLOAD_TYPE);
      }
      const body = Buffer.from(String(envelope.payload || ''), 'base64');
      const pae = stsCrypto.dssePae(envelope.payloadType, body);
      const sigs = Array.isArray(envelope.signatures) ? envelope.signatures
                                                      : [];
      for (let i = 0; i < sigs.length && !signed; i++) {
        for (let k = 0; k < candidates.length && !signed; k++) {
          signed = await stsCrypto.verifyWithPublicKey(candidates[k], pae,
            Buffer.from(String((sigs[i] || {}).sig || ''), 'base64'));
        }
      }
      layer = Object.assign({}, layer, { statement: body });
    }
    if (!signed) {
      log.debug("Leaving SigstoreVerifier.verifyLayer(). Signature.");
      throw this.fail(code, 'the ' + kind + ' does not verify under ' +
                    (certificate ? 'its certificate\'s key' :
                                   'the configured key'));
    }
    // THE WINDOW (4d).
    if (certificate) {
      const at = logged ? logged.integratedMs : nowMs();
      const expired = this.checkExpiry(certificate.chain, at);
      if (expired) {
        log.debug("Leaving SigstoreVerifier.verifyLayer(). Expired.");
        throw this.fail(code, 'checking expiry on certificate: ' + expired +
                      (logged ? ', the time the log integrated it'
                              : ' — with the log skipped, now; a keyless ' +
                                'certificate lives ten minutes'));
      }
    }
    // THE CLAIM (4e / 5).
    const claim = this.claimProblem(kind, kind === 'signature'
                                      ? layer.payload : layer.statement,
                                    digest);
    if (claim) {
      log.debug("Leaving SigstoreVerifier.verifyLayer(). Claim.");
      throw this.fail(code, claim);
    }
    log.debug("Leaving SigstoreVerifier.verifyLayer().");
    return {
      subject: certificate ? certificate.facts.subject : '',
      issuer: certificate ? certificate.facts.issuer : '',
      signature: signatureB64,
      logId: logged ? String(logged.payload.logID) : '',
      logIndex: logged ? String(logged.payload.logIndex) : '',
      integratedTime: logged ? String(logged.payload.integratedTime) : '',
      signedEntryTimestamp: logged ? logged.set : ''
    };
  }

  // Every layer of `tag`; resolves the details of those that verified and
  // the reasons the others did not. Throws when the tag cannot be read.
  async verifyAll(kind: string, ref: any, tag: string, material: TrustMaterial,
                  auth: { token: string }):
      Promise<{ verified: any[]; problems: string[]; found: boolean }> {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.verifyAll(). " + kind);
    const layers = await this.layers(ref, tag, auth);
    const verified = [];
    const problems = [];
    for (let i = 0; layers && i < layers.length; i++) {
      try {
        verified.push(await this.verifyLayer(kind, layers[i], ref.digest,
                                             material));
      } catch (e) {
        log.debug("Caught in SigstoreVerifier.verifyAll(): " +
                  ((e && e.message) || e));
        problems.push(String((e && e.message) || e));
      }
    }
    log.debug("Leaving SigstoreVerifier.verifyAll(). " + verified.length);
    return { verified: verified, problems: problems,
             found: !!(layers && layers.length) };
  }

  // SPIRE's detailsToSelectors().
  selectorsOf(details: any): string[] {
    const { log } = this.deps;
    log.debug("Entering SigstoreVerifier.selectorsOf().");
    const out = [];
    const add = function (name: string, value: string) {
      if (value) out.push(name + ':' + value);
    };
    add('image-signature-subject', details.subject);
    add('image-signature-issuer', details.issuer);
    add('image-signature-value', details.signature);
    add('image-signature-log-id', details.logId);
    add('image-signature-log-index', details.logIndex);
    add('image-signature-integrated-time', details.integratedTime);
    add('image-signature-signed-entry-timestamp',
        details.signedEntryTimestamp);
    log.debug("Leaving SigstoreVerifier.selectorsOf().");
    return out;
  }

  // THE ENTRY POINT: SPIRE's ImageVerifier.Verify() for one repository
  // digest. Resolves the selectors; throws with the failure's code tagged on
  // a log line.
  async verify(repoDigest: string): Promise<string[]> {
    const { log, config, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering SigstoreVerifier.verify(). " + repoDigest);
    if (this.list('spiffe.dockerSigstoreSkippedImages')
          .indexOf(repoDigest) >= 0) {
      log.debug("Leaving SigstoreVerifier.verify(). Skipped.");
      return [];
    }
    try {
      const material = this.trustMaterial();
      const ref = this.parseReference(repoDigest);
      if (!this.registryAllowed(ref.registry)) {
        throw this.fail('STS-SPIFFE-0127', 'the registry ' + ref.registry +
                      ' is not in spiffe.dockerSigstoreAllowedRegistries, so ' +
                      'its signatures are not fetched');
      }
      const auth = { token: '' };
      const hex = ref.digest.replace(/^sha256:/, '');
      const signatures = await this.verifyAll('signature', ref,
                                              'sha256-' + hex + '.sig',
                                              material, auth);
      if (!signatures.verified.length) {
        throw this.fail('STS-SPIFFE-0128', signatures.found
          ? 'no matching signatures: ' + signatures.problems.join('; ')
          : 'no signatures found');
      }
      const out = ['image-signature:verified'];
      if (!config.value('spiffe.dockerSigstoreIgnoreAttestations')) {
        const attestations = await this.verifyAll('attestation', ref,
                                                  'sha256-' + hex + '.att',
                                                  material, auth);
        if (!attestations.verified.length) {
          throw this.fail('STS-SPIFFE-0130', 'no matching attestations' +
            (attestations.problems.length
              ? ': ' + attestations.problems.join('; ')
              : ' (the image has none; spiffe.dockerSigstoreIgnore' +
                'Attestations accepts that)'));
        }
        out.push('image-attestations:verified');
      }
      signatures.verified.forEach(function (details) {
        self.selectorsOf(details).forEach(function (one) {
          out.push(one);
        });
      });
      log.debug("Leaving SigstoreVerifier.verify(). " + out.length);
      return out;
    } catch (e) {
      log.debug("Caught in SigstoreVerifier.verify(): " +
                ((e && e.message) || e));
      const code = String((e && e.stsCode) || 'STS-SPIFFE-0128');
      log.info(errorCodes.tag(code) + 'spiffe: the sigstore signature of ' +
               repoDigest + ' did not verify: ' + ((e && e.message) || e));
      log.debug("Leaving SigstoreVerifier.verify(). Refused.");
      throw e;
    }
  }
}

const shared = new SigstoreVerifier(SigstoreVerifier.defaultDeps());

export = {
  SigstoreVerifier: SigstoreVerifier,
  shared: shared,
  verify: (repoDigest: string): Promise<string[]> =>
    shared.verify(repoDigest)
};
