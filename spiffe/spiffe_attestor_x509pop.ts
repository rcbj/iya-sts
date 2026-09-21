'use strict';
//
// File: spiffe_attestor_x509pop.ts
//
// ---------------------------------------------------------------------------
// THE `x509pop` NODE ATTESTOR — X.509 PROOF OF POSSESSION (#40, 2026-09-21).
//
// SPIRE's `pkg/server/plugin/nodeattestor/x509pop` and
// `pkg/common/plugin/x509pop`, step for step, because a real `spire-agent`
// is the client and every byte of the exchange is its:
//
//   1. The payload is `{"certificates": [<DER, base64>, …]}`, leaf first.
//      More intermediates than `spiffe.x509popMaxIntermediates`, or an RSA
//      key above `spiffe.x509popMaxRsaKeySize` on any of them, is refused
//      before anything is verified.
//   2. The leaf must chain to the realm's anchors — `spiffe.x509popCaBundle`
//      (external_pki mode) or this realm's own SPIFFE trust bundle (spiffe
//      mode) — `spiffe_x509_path.ts` builds and checks the path.
//   3. `spiffe.x509popVerifyClientIp`: the agent's address must be one of
//      the leaf's IP subjectAltNames.
//   4. THE CHALLENGE. The leaf's keyUsage must allow digitalSignature. The
//      server sends 32 random bytes as
//      `{"rsa_signature":{"nonce":…},"ecdsa_signature":null}` (or the ECDSA
//      member); the agent answers with its own 32-byte nonce and a signature
//      over SHA-256(server nonce ‖ agent nonce) — RSA-PSS with SHA-256, or
//      ECDSA as big-endian r and s. It is the possession half of the name:
//      a certificate alone is public.
//   5. spiffe mode: the leaf's first spiffe:// URI must start with
//      `spiffe.x509popSpiffePrefix`; what follows is `SVIDPathTrimmed`.
//   6. The agent's id is `spiffe.x509popAgentPathTemplate` (SPIRE's default
//      per mode when empty) under `/spire/agent`, and its selectors are
//      `subject:cn:`, `ca:fingerprint:` for every certificate above the leaf,
//      `serialnumber:`, `san:<k>:<v>` from `x509pop://<trust domain>/<k>/<v>`
//      URIs, and `group:` when `spiffe.x509popGroupTemplate` renders one of
//      `spiffe.x509popAllowedGroups`. Re-attestable.
//
// **POST-QUANTUM, BEYOND SPIRE.** SPIRE's challenge has an RSA and an ECDSA
// member and refuses any other key. A leaf carrying an ML-DSA, SLH-DSA or
// composite key is challenged here with a third member, `pqc_signature`
// (`{"nonce", "algorithm"}` — the key's algorithm, as the vendored engine
// names it), answered with `{"nonce", "signature"}` over the same 32-byte
// digest. A stock SPIRE agent never sees one — it never holds such a key —
// so nothing about the RSA and ECDSA exchange changes; an agent that does
// hold one can prove possession of it here, and the path to it is checked by
// the same engine, which reads post-quantum signatures.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import spiffeId = require('./spiffe_id');
import rpc = require('./spiffe_grpc');
import ca = require('./spiffe_ca');
import x509Path = require('./spiffe_x509_path');
import agentPath = require('./spiffe_agent_path');

type NodeAttestationContext =
  import('../types/spiffe-attestation').NodeAttestationContext;
type NodeAttestationResult =
  import('../types/spiffe-attestation').NodeAttestationResult;

const NONCE_LENGTH = 32;
const DEFAULT_TEMPLATE_CN = '/{{ .PluginName }}/{{ .Fingerprint }}';
const DEFAULT_TEMPLATE_SVID = '/{{ .PluginName }}/{{ .SVIDPathTrimmed }}';
// ECDSA's r and s are each this many bytes on the curves SPIRE's agents use.
const CURVE_BYTES = { 'prime256v1': 32, 'secp384r1': 48, 'secp521r1': 66 };

interface X509popDeps {
  log: typeof log;
  crypto: typeof nodeCrypto;
  config: typeof config;
  errorCodes: typeof errorCodes;
  spiffeId: typeof spiffeId;
  rpc: typeof rpc;
  ca: typeof ca;
  path: typeof x509Path;
  agentPath: typeof agentPath;
  loadX509(): any;
  loadPqc(): any;
}

class X509popAttestor {
  readonly type = 'x509pop';
  readonly verifies = 'An X.509 certificate chaining to the realm\'s ' +
    'x509pop anchors (or its own SPIFFE bundle, in spiffe mode), and a ' +
    'signature over a fresh challenge with its key — RSA, ECDSA or a ' +
    'post-quantum key.';

  constructor(private readonly deps: X509popDeps) {
    deps.log.debug("Entering X509popAttestor.constructor().");
    deps.log.debug("Leaving X509popAttestor.constructor().");
  }

  static defaultDeps(): X509popDeps {
    helpers.log.debug("Entering X509popAttestor.defaultDeps().");
    helpers.log.debug("Leaving X509popAttestor.defaultDeps().");
    return {
      log: log, crypto: nodeCrypto, config: config, errorCodes: errorCodes,
      spiffeId: spiffeId, rpc: rpc, ca: ca, path: x509Path,
      agentPath: agentPath,
      loadX509: function () {
        return require('../common/vendored/x509');
      },
      loadPqc: function () {
        return require('../common/vendored/pqc_x509');
      }
    };
  }

  // A JSON document from bytes, or null.
  json(bytes: Buffer): any {
    const { log } = this.deps;
    log.debug("Entering X509popAttestor.json().");
    try {
      const parsed = JSON.parse(Buffer.from(bytes || []).toString('utf8'));
      log.debug("Leaving X509popAttestor.json().");
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (e) {
      log.debug("Caught in X509popAttestor.json(): " +
                ((e && e.message) || e));
      log.debug("Leaving X509popAttestor.json(). Not JSON.");
      return null;
    }
  }

  // A Go `[]byte` as JSON carries it: standard base64.
  bytesOf(value: any): Buffer | null {
    const { log } = this.deps;
    log.debug("Entering X509popAttestor.bytesOf().");
    if (typeof value !== 'string') {
      log.debug("Leaving X509popAttestor.bytesOf(). Not a string.");
      return null;
    }
    log.debug("Leaving X509popAttestor.bytesOf().");
    return Buffer.from(value, 'base64');
  }

  // The address the agent connected from, without its port, or ''.
  clientIp(context: NodeAttestationContext): string {
    const { log } = this.deps;
    log.debug("Entering X509popAttestor.clientIp().");
    log.debug("Leaving X509popAttestor.clientIp().");
    return String(context.clientIp || '');
  }

  // A pkix.Name as Go's template sees it, from node's "K=V\n" subject.
  pkixName(text: string): Record<string, any> {
    const { log } = this.deps;
    log.debug("Entering X509popAttestor.pkixName().");
    const out: Record<string, any> = {
      Country: [], Organization: [], OrganizationalUnit: [], Locality: [],
      Province: [], StreetAddress: [], PostalCode: [], SerialNumber: '',
      CommonName: ''
    };
    const lists = { C: 'Country', O: 'Organization', OU: 'OrganizationalUnit',
                    L: 'Locality', ST: 'Province', street: 'StreetAddress',
                    postalCode: 'PostalCode' };
    String(text || '').split('\n').forEach(function (line) {
      const at = line.indexOf('=');
      if (at < 0) return;
      const key = line.slice(0, at);
      const value = line.slice(at + 1);
      if (key === 'CN') {
        out.CommonName = value;
      } else if (key === 'serialNumber') {
        out.SerialNumber = value;
      } else if (lists[key]) {
        out[lists[key]].push(value);
      }
    });
    log.debug("Leaving X509popAttestor.pkixName().");
    return out;
  }

  // The subjectAltName entries of one kind, from node's rendering.
  sans(x509: nodeCrypto.X509Certificate, kind: string): string[] {
    const { log } = this.deps;
    log.debug("Entering X509popAttestor.sans(). kind=" + kind);
    const text = String(x509.subjectAltName || '');
    const out = [];
    const pattern = /(DNS|URI|IP Address|email):("(?:[^"\\]|\\.)*"|[^,]*)/g;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      if (match[1] !== kind) continue;
      const raw = match[2].trim();
      out.push(raw.charAt(0) === '"' ? JSON.parse(raw) : raw);
    }
    log.debug("Leaving X509popAttestor.sans(). " + out.length + ".");
    return out;
  }

  // SPIRE's SerialNumberHex: lowercase, an even number of digits.
  serialHex(x509: nodeCrypto.X509Certificate): string {
    const { log } = this.deps;
    log.debug("Entering X509popAttestor.serialHex().");
    let hex = String(x509.serialNumber || '').toLowerCase()
      .replace(/^0+(?=.)/, '');
    if (hex.length % 2) hex = '0' + hex;
    log.debug("Leaving X509popAttestor.serialHex().");
    return hex;
  }

  // What the three kinds of key sign with, or '' for a key this attestor
  // does not challenge.
  keyKind(x509: nodeCrypto.X509Certificate): { kind: string; alg: string } {
    const { log } = this.deps;
    log.debug("Entering X509popAttestor.keyKind().");
    let kind = '';
    try {
      kind = String((x509.publicKey as any).asymmetricKeyType || '');
    } catch (e) {
      log.debug("Caught in X509popAttestor.keyKind(): " +
                ((e && e.message) || e));
      // A key node cannot read: perhaps post-quantum, asked below.
    }
    if (kind === 'rsa' || kind === 'rsa-pss') {
      log.debug("Leaving X509popAttestor.keyKind(). RSA.");
      return { kind: 'rsa', alg: '' };
    }
    if (kind === 'ec') {
      log.debug("Leaving X509popAttestor.keyKind(). ECDSA.");
      return { kind: 'ecdsa', alg: '' };
    }
    const spki = this.spkiDer(x509);
    const read = spki ? this.deps.loadPqc().decodeSpki(new Uint8Array(spki))
                      : null;
    if (read && read.alg) {
      log.debug("Leaving X509popAttestor.keyKind(). Post-quantum.");
      return { kind: 'pqc', alg: String(read.alg.id || read.alg) };
    }
    log.debug("Leaving X509popAttestor.keyKind(). Unsupported.");
    return { kind: '', alg: kind };
  }

  // The leaf's SubjectPublicKeyInfo, read with the vendored engine so that a
  // key node does not know is still there.
  spkiDer(x509: nodeCrypto.X509Certificate): Buffer | null {
    const { log } = this.deps;
    log.debug("Entering X509popAttestor.spkiDer().");
    try {
      const der = (x509.publicKey as any).export({ type: 'spki',
                                                   format: 'der' });
      log.debug("Leaving X509popAttestor.spkiDer(). From node.");
      return Buffer.from(der);
    } catch (e) {
      log.debug("Caught in X509popAttestor.spkiDer(): " +
                ((e && e.message) || e));
    }
    try {
      const pkijs = require('pkijs');
      const cert = pkijs.Certificate.fromBER(new Uint8Array(x509.raw));
      const der = Buffer.from(cert.subjectPublicKeyInfo.toSchema()
        .toBER(false));
      log.debug("Leaving X509popAttestor.spkiDer(). From the engine.");
      return der;
    } catch (e) {
      log.debug("Caught in X509popAttestor.spkiDer(): " +
                ((e && e.message) || e));
      log.debug("Leaving X509popAttestor.spkiDer(). Unreadable.");
      return null;
    }
  }

  // The digest both nonces are signed as.
  combined(challenge: Buffer, response: Buffer): Buffer | null {
    const { log, crypto } = this.deps;
    log.debug("Entering X509popAttestor.combined().");
    if (!challenge || challenge.length !== NONCE_LENGTH || !response ||
        response.length !== NONCE_LENGTH) {
      log.debug("Leaving X509popAttestor.combined(). A nonce is not 32 " +
                "bytes.");
      return null;
    }
    log.debug("Leaving X509popAttestor.combined().");
    return crypto.createHash('sha256').update(challenge).update(response)
      .digest();
  }

  // Does `response` answer `challenge` for this leaf's key?
  async verifyResponse(leaf: nodeCrypto.X509Certificate,
                       key: { kind: string; alg: string },
                       nonce: Buffer, response: any): Promise<boolean> {
    const { log, crypto } = this.deps;
    log.debug("Entering X509popAttestor.verifyResponse(). " + key.kind);
    const member = response && response[key.kind === 'rsa' ? 'rsa_signature'
      : key.kind === 'ecdsa' ? 'ecdsa_signature' : 'pqc_signature'];
    if (!member || typeof member !== 'object') {
      log.debug("Leaving X509popAttestor.verifyResponse(). No member.");
      return false;
    }
    const theirs = this.bytesOf(member.nonce);
    const digestInput = theirs ? Buffer.concat([nonce, theirs]) : null;
    if (!this.combined(nonce, theirs)) {
      log.debug("Leaving X509popAttestor.verifyResponse(). Bad nonce.");
      return false;
    }
    try {
      if (key.kind === 'rsa') {
        // rsa.SignPSS over the digest with SHA-256 and the salt length
        // detected on verify — node hashes `digestInput` to that same digest.
        const ok = crypto.verify('sha256', digestInput, {
          key: leaf.publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO
        }, this.bytesOf(member.signature) || Buffer.alloc(0));
        log.debug("Leaving X509popAttestor.verifyResponse(). RSA " + ok);
        return ok;
      }
      if (key.kind === 'ecdsa') {
        const curve = String(((leaf.publicKey as any).asymmetricKeyDetails ||
                              {}).namedCurve || '');
        const size = CURVE_BYTES[curve];
        const r = this.bytesOf(member.r);
        const s = this.bytesOf(member.s);
        if (!size || !r || !s || r.length > size || s.length > size) {
          log.debug("Leaving X509popAttestor.verifyResponse(). Bad r/s.");
          return false;
        }
        // big.Int.Bytes() drops leading zeroes; IEEE P1363 wants each half
        // at the curve's full width.
        const raw = Buffer.concat([Buffer.alloc(size - r.length), r,
                                   Buffer.alloc(size - s.length), s]);
        // ecdsa.Sign(key, digest): node's 'sha256' over `digestInput` is
        // that digest.
        const ok = crypto.verify('sha256', digestInput, {
          key: leaf.publicKey, dsaEncoding: 'ieee-p1363'
        }, raw);
        log.debug("Leaving X509popAttestor.verifyResponse(). ECDSA " + ok);
        return ok;
      }
      // Post-quantum: over the 32-byte digest itself, which is the message.
      const x509 = this.deps.loadX509();
      const sig = x509.sigAlg(key.alg.toLowerCase());
      const spki = this.spkiDer(leaf);
      if (!sig || !spki) {
        log.debug("Leaving X509popAttestor.verifyResponse(). No algorithm.");
        return false;
      }
      const spkiPem = '-----BEGIN PUBLIC KEY-----\n' +
        spki.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '') +
        '\n-----END PUBLIC KEY-----\n';
      const ok = await x509.verifyBytes(sig, spkiPem,
        this.bytesOf(member.signature) || Buffer.alloc(0),
        this.combined(nonce, theirs));
      log.debug("Leaving X509popAttestor.verifyResponse(). " + key.alg + " " +
                ok);
      return !!ok;
    } catch (e) {
      log.debug("Caught in X509popAttestor.verifyResponse(): " +
                ((e && e.message) || e));
      log.debug("Leaving X509popAttestor.verifyResponse(). Threw.");
      return false;
    }
  }

  async attest(context: NodeAttestationContext):
      Promise<NodeAttestationResult> {
    const { log, crypto, config, errorCodes, spiffeId, rpc, ca, path,
            agentPath } = this.deps;
    const self = this;
    log.debug("Entering X509popAttestor.attest().");
    const call = context.call;
    const status = rpc.grpc.status;
    // THE CONFIGURATION, checked as SPIRE checks it at Configure.
    const mode = String(config.value('spiffe.x509popMode') || 'external_pki');
    const bundleText = String(config.value('spiffe.x509popCaBundle') || '');
    const groupText = String(config.value('spiffe.x509popGroupTemplate') ||
                             '');
    const allowedRaw = config.value('spiffe.x509popAllowedGroups');
    const allowed = (Array.isArray(allowedRaw) ? allowedRaw
      : String(allowedRaw || '').split(',')).map(function (g) {
        return String(g).trim();
      }).filter(Boolean);
    let problem = '';
    if (mode === 'spiffe' && bundleText.trim()) {
      problem = 'spiffe.x509popCaBundle cannot be used in spiffe mode';
    } else if (groupText && !allowed.length) {
      problem = 'spiffe.x509popAllowedGroups must be set when ' +
                'spiffe.x509popGroupTemplate is';
    } else if (!groupText && allowed.length) {
      problem = 'spiffe.x509popGroupTemplate must be set when ' +
                'spiffe.x509popAllowedGroups is';
    }
    let roots = [];
    if (!problem && mode === 'external_pki') {
      roots = path.bundle(bundleText).certificates;
      if (!roots.length) {
        problem = 'spiffe.x509popCaBundle holds no certificate';
      }
    } else if (!problem) {
      // The ambient realm's — the realm of the socket the agent reached.
      roots = (ca.trustAnchors(null) || []).map(function (anchor) {
        return path.certificate(anchor.certificateDer);
      }).filter(Boolean);
    }
    let template = null;
    let groupTemplate = null;
    if (!problem) {
      try {
        template = new agentPath.AgentPathTemplate(
          String(config.value('spiffe.x509popAgentPathTemplate') || '') ||
          (mode === 'spiffe' ? DEFAULT_TEMPLATE_SVID : DEFAULT_TEMPLATE_CN));
        groupTemplate = groupText
          ? new agentPath.AgentPathTemplate(groupText) : null;
      } catch (e) {
        log.debug("Caught in X509popAttestor.attest(): " +
                  ((e && e.message) || e));
        problem = 'a template does not parse: ' + e.message;
      }
    }
    if (problem) {
      log.debug("Leaving X509popAttestor.attest(). Not configured.");
      errorCodes.mark(call, 'STS-SPIFFE-0085');
      throw rpc.statusError(status.FAILED_PRECONDITION,
                            'x509pop is not configured in this realm: ' +
                            problem + '.');
    }
    // 1. THE PAYLOAD.
    const data = this.json(context.payload);
    const certificates = data && Array.isArray(data.certificates)
      ? data.certificates.map(function (c) {
        return self.bytesOf(c);
      }) : null;
    if (!certificates || certificates.some(function (c) {
      return !c;
    })) {
      log.debug("Leaving X509popAttestor.attest(). Unreadable payload.");
      errorCodes.mark(call, 'STS-SPIFFE-0086');
      throw rpc.invalidArgument('failed to unmarshal data: an x509pop ' +
                                'payload is {"certificates": [<base64 ' +
                                'DER>, …]}, leaf first');
    }
    if (!certificates.length) {
      log.debug("Leaving X509popAttestor.attest(). No certificate.");
      errorCodes.mark(call, 'STS-SPIFFE-0086');
      throw rpc.invalidArgument('no certificate to attest');
    }
    if (certificates.length - 1 >
        Number(config.value('spiffe.x509popMaxIntermediates'))) {
      log.debug("Leaving X509popAttestor.attest(). Too many.");
      errorCodes.mark(call, 'STS-SPIFFE-0087');
      throw rpc.invalidArgument('too many intermediate certificates');
    }
    const maxRsa = Number(config.value('spiffe.x509popMaxRsaKeySize'));
    for (let i = 0; i < certificates.length; i++) {
      const one = path.certificate(certificates[i]);
      if (!one) {
        log.debug("Leaving X509popAttestor.attest(). Unparseable.");
        errorCodes.mark(call, 'STS-SPIFFE-0086');
        throw rpc.invalidArgument(i === 0 ? 'unable to parse leaf certificate'
          : 'unable to parse intermediate certificate ' + (i - 1));
      }
      if (path.rsaBits(one) > maxRsa) {
        log.debug("Leaving X509popAttestor.attest(). RSA too large.");
        errorCodes.mark(call, 'STS-SPIFFE-0088');
        throw rpc.invalidArgument(i === 0
          ? 'leaf certificate key size too large'
          : 'intermediate certificate ' + (i - 1) + ' key size too large');
      }
    }
    // 2. THE PATH.
    const verified = await path.verify(certificates[0],
                                       certificates.slice(1), roots);
    if (!verified.ok) {
      log.debug("Leaving X509popAttestor.attest(). No path.");
      errorCodes.mark(call, 'STS-SPIFFE-0089');
      throw rpc.permissionDenied('certificate verification failed: ' +
                                 verified.reason);
    }
    const leaf = verified.chain[0];
    // 3. THE ADDRESS.
    if (config.value('spiffe.x509popVerifyClientIp')) {
      const ip = this.clientIp(context);
      if (!ip) {
        log.debug("Leaving X509popAttestor.attest(). No address.");
        errorCodes.mark(call, 'STS-SPIFFE-0091');
        throw rpc.statusError(status.INTERNAL,
                              'client IP not available for verification');
      }
      if (this.sans(leaf.x509, 'IP Address').indexOf(ip) < 0) {
        log.debug("Leaving X509popAttestor.attest(). Address not allowed.");
        errorCodes.mark(call, 'STS-SPIFFE-0090');
        throw rpc.permissionDenied('client IP ' + ip + ' does not match ' +
                                   'any certificate IP SAN');
      }
    }
    // 4. THE CHALLENGE.
    const described = await this.deps.loadX509().describeCertificate(leaf.pem);
    const keyUsage = ((described && described.extensions) || [])
      .filter(function (ext) {
        return ext.name === 'keyUsage';
      })[0];
    if (!keyUsage || !Array.isArray(keyUsage.value) ||
        keyUsage.value.indexOf('digitalSignature') < 0) {
      log.debug("Leaving X509popAttestor.attest(). Not for signatures.");
      errorCodes.mark(call, 'STS-SPIFFE-0092');
      throw rpc.statusError(status.INTERNAL, 'unable to generate ' +
        'challenge: certificate not intended for digital signature use');
    }
    const key = this.keyKind(leaf.x509);
    if (!key.kind) {
      log.debug("Leaving X509popAttestor.attest(). Unsupported key.");
      errorCodes.mark(call, 'STS-SPIFFE-0092');
      throw rpc.statusError(status.INTERNAL, 'unable to generate ' +
        'challenge: unsupported public key type ' + (key.alg || 'unknown'));
    }
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const challenge = key.kind === 'rsa'
      ? { rsa_signature: { nonce: nonce.toString('base64') },
          ecdsa_signature: null }
      : key.kind === 'ecdsa'
        ? { rsa_signature: null,
            ecdsa_signature: { nonce: nonce.toString('base64') } }
        : { rsa_signature: null, ecdsa_signature: null,
            pqc_signature: { nonce: nonce.toString('base64'),
                             algorithm: key.alg } };
    const answer = await context.challenge(
      Buffer.from(JSON.stringify(challenge), 'utf8'));
    const response = this.json(answer);
    if (!response) {
      log.debug("Leaving X509popAttestor.attest(). Unreadable response.");
      errorCodes.mark(call, 'STS-SPIFFE-0086');
      throw rpc.invalidArgument('unable to unmarshal challenge response');
    }
    if (!(await this.verifyResponse(leaf.x509, key, nonce, response))) {
      log.debug("Leaving X509popAttestor.attest(). Response refused.");
      errorCodes.mark(call, 'STS-SPIFFE-0093');
      throw rpc.permissionDenied('challenge response verification failed: ' +
        (key.kind === 'rsa' ? 'RSA' : key.kind === 'ecdsa' ? 'ECDSA'
                                                           : key.alg) +
        ' signature verify failed');
    }
    // 5. spiffe MODE.
    let svidPath = '';
    if (mode === 'spiffe') {
      const uris = this.sans(leaf.x509, 'URI').filter(function (uri) {
        return uri.indexOf('spiffe://') === 0;
      });
      if (!uris.length) {
        log.debug("Leaving X509popAttestor.attest(). No SVID.");
        errorCodes.mark(call, 'STS-SPIFFE-0094');
        throw rpc.permissionDenied('valid SVID x509 cert not found');
      }
      let prefix = String(config.value('spiffe.x509popSpiffePrefix') || '');
      if (prefix.slice(-1) !== '/') prefix += '/';
      svidPath = new URL(uris[0]).pathname;
      if (svidPath.indexOf(prefix) !== 0) {
        log.debug("Leaving X509popAttestor.attest(). Outside the prefix.");
        errorCodes.mark(call, 'STS-SPIFFE-0094');
        throw rpc.permissionDenied('x509 cert doesnt match SVID prefix');
      }
      svidPath = svidPath.slice(prefix.length);
    }
    // 6. THE AGENT AND ITS SELECTORS.
    const sanSelectors: Record<string, string> = {};
    const sanPrefix = 'x509pop://' + context.trustDomain + '/';
    this.sans(leaf.x509, 'URI').forEach(function (uri) {
      if (uri.indexOf(sanPrefix) !== 0) return;
      const segments = new URL(uri).pathname.replace(/^\/+|\/+$/g, '')
        .split('/');
      if (segments.length < 2) {
        log.warn('spiffe: cannot extract x509pop san selectors from ' + uri);
        return;
      }
      sanSelectors[segments[0]] = segments.slice(1).join('/');
    });
    const templateData = {
      PluginName: this.type,
      TrustDomain: context.trustDomain,
      Fingerprint: leaf.sha1,
      SerialNumberHex: this.serialHex(leaf.x509),
      SVIDPathTrimmed: svidPath,
      URISanSelectors: sanSelectors,
      Subject: this.pkixName(leaf.x509.subject),
      Issuer: this.pkixName(leaf.x509.issuer),
      SerialNumber: BigInt('0x' + (leaf.x509.serialNumber || '0')).toString(),
      DNSNames: this.sans(leaf.x509, 'DNS'),
      EmailAddresses: this.sans(leaf.x509, 'email'),
      IPAddresses: this.sans(leaf.x509, 'IP Address'),
      URIs: this.sans(leaf.x509, 'URI')
    };
    let agentId = '';
    try {
      agentId = spiffeId.make(context.trustDomain,
                              '/spire/agent' + template.execute(templateData));
    } catch (e) {
      log.debug("Caught in X509popAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!agentId || !spiffeId.parse(agentId).ok) {
      log.debug("Leaving X509popAttestor.attest(). No agent id.");
      errorCodes.mark(call, 'STS-SPIFFE-0095');
      throw rpc.statusError(status.INTERNAL, 'failed to make spiffe id from ' +
                            'the agent path template');
    }
    const selectors = [];
    if (templateData.Subject.CommonName) {
      selectors.push('subject:cn:' + templateData.Subject.CommonName);
    }
    verified.chain.slice(1).forEach(function (one) {
      selectors.push('ca:fingerprint:' + one.sha1);
    });
    selectors.push('serialnumber:' + templateData.SerialNumberHex);
    Object.keys(sanSelectors).forEach(function (k) {
      selectors.push('san:' + k + ':' + sanSelectors[k]);
    });
    if (groupTemplate) {
      try {
        const group = groupTemplate.execute(templateData).trim();
        if (group && allowed.indexOf(group) >= 0) {
          selectors.push('group:' + group);
        } else {
          log.debug('spiffe: x509pop group "' + group + '" is not in ' +
                    'spiffe.x509popAllowedGroups.');
        }
      } catch (e) {
        // SPIRE logs a group template that fails at debug and attests
        // without the selector; so does this.
        log.debug("Caught in X509popAttestor.attest(): " +
                  ((e && e.message) || e));
      }
    }
    log.debug("Leaving X509popAttestor.attest(). " + agentId);
    return {
      agentId: agentId,
      selectors: selectors.map(function (value) {
        return { type: 'x509pop', value: value };
      }),
      canReattest: true,
      method: 'agent attestation (x509pop, ' +
              (key.kind === 'pqc' ? key.alg : key.kind.toUpperCase()) + ')',
      note: 'attested by proof of possession of the key in a certificate ' +
            'chaining to ' + (mode === 'spiffe' ? 'this realm\'s SPIFFE bundle'
                                                : 'spiffe.x509popCaBundle'),
      // Nothing is claimed: the evidence is a signature over a nonce this
      // server chose, which cannot be presented twice.
      commit: function () {
        log.debug("Entering commit(). Nothing to spend.");
        log.debug("Leaving commit().");
      },
      release: function () {
        log.debug("Entering release(). Nothing to give back.");
        log.debug("Leaving release().");
      }
    };
  }
}

export = {
  X509popAttestor: X509popAttestor
};
