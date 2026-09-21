'use strict';
//
// File: spiffe_ssh.ts
//
// ---------------------------------------------------------------------------
// OPENSSH CERTIFICATES AND SIGNATURES, FOR THE `sshpop` NODE ATTESTOR (#40,
// 2026-09-21).
//
// `sshpop` proves a node holds the private half of an SSH HOST certificate
// signed by an authority the operator trusts. SPIRE does it with
// `golang.org/x/crypto/ssh`; this is the part of that package the attestor
// needs, written against the wire format of RFC 4251 (strings, mpints,
// uint32/64) and OpenSSH's PROTOCOL.certkeys:
//
//   * `parsePublicKey()` reads a key or a certificate blob — ssh-rsa,
//     ecdsa-sha2-nistp256/384/521, ssh-ed25519, and their -cert-v01
//     versions — into node key material;
//   * `parseAuthorizedKey()` reads one authorized_keys line, options and
//     comment allowed, which is what SPIRE's `cert_authorities` holds;
//   * `checkHostCertificate()` is `CertChecker.CheckHostKey()`: a HOST
//     certificate, signed by a configured authority, inside its validity
//     window, naming the principal, carrying no critical option but
//     `source-address`;
//   * `verify()` is `PublicKey.Verify()` for the signature formats Go
//     accepts for each key type — `ssh-rsa` (SHA-1), `rsa-sha2-256` and
//     `rsa-sha2-512` for RSA; the curve's own hash for ECDSA; Ed25519.
//
// The security-key types (`sk-…@openssh.com`) and DSA are refused: Go's
// CertChecker would accept an sk host certificate, but a HOST key held on a
// FIDO token is not a thing sshd supports, so nothing is lost. OpenSSH
// defines no post-quantum signature, so there is none here to support.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
const { log } = helpers;

const CERT_SUFFIX = '-cert-v01@openssh.com';
// SSH_CERT_TYPE_HOST (PROTOCOL.certkeys).
const HOST_CERT = 2;
// Go's CertTimeInfinity.
const FOREVER = BigInt('0xffffffffffffffff');
const CURVES = {
  'nistp256': { crv: 'P-256', hash: 'sha256', bytes: 32 },
  'nistp384': { crv: 'P-384', hash: 'sha384', bytes: 48 },
  'nistp521': { crv: 'P-521', hash: 'sha512', bytes: 66 }
};

// A reader over RFC 4251's types. Every read throws on a short buffer, and
// the caller turns that into its refusal.
class Wire {
  private at = 0;

  constructor(private readonly bytes: Buffer) {
    log.debug("Entering Wire.constructor().");
    log.debug("Leaving Wire.constructor().");
  }

  take(n: number): Buffer {
    log.debug("Entering Wire.take().");
    if (n < 0 || this.at + n > this.bytes.length) {
      log.debug("Leaving Wire.take(). Short.");
      // error-code: none — a parse failure, refused by the attestor under
      // its own code
      throw new Error('the SSH structure is truncated');
    }
    const out = this.bytes.subarray(this.at, this.at + n);
    this.at += n;
    log.debug("Leaving Wire.take().");
    return out;
  }

  uint32(): number {
    log.debug("Entering Wire.uint32().");
    log.debug("Leaving Wire.uint32().");
    return this.take(4).readUInt32BE(0);
  }

  uint64(): bigint {
    log.debug("Entering Wire.uint64().");
    log.debug("Leaving Wire.uint64().");
    return this.take(8).readBigUInt64BE(0);
  }

  string(): Buffer {
    log.debug("Entering Wire.string().");
    log.debug("Leaving Wire.string().");
    return this.take(this.uint32());
  }

  text(): string {
    log.debug("Entering Wire.text().");
    log.debug("Leaving Wire.text().");
    return this.string().toString('utf8');
  }

  // An mpint's magnitude, without the sign byte OpenSSH adds.
  mpint(): Buffer {
    log.debug("Entering Wire.mpint().");
    const raw = this.string();
    let start = 0;
    while (start < raw.length - 1 && raw[start] === 0) start++;
    log.debug("Leaving Wire.mpint().");
    return raw.subarray(start);
  }

  position(): number {
    log.debug("Entering Wire.position().");
    log.debug("Leaving Wire.position().");
    return this.at;
  }

  // Whatever is left, consumed.
  remaining(): Buffer {
    log.debug("Entering Wire.remaining().");
    log.debug("Leaving Wire.remaining().");
    return this.take(this.bytes.length - this.at);
  }

  done(): boolean {
    log.debug("Entering Wire.done().");
    log.debug("Leaving Wire.done().");
    return this.at === this.bytes.length;
  }
}

interface SshKey {
  // The key's own type: ssh-rsa, ecdsa-sha2-nistp256, ssh-ed25519.
  type: string;
  key: nodeCrypto.KeyObject;
  // The public key blob, as it is marshalled — what fingerprints hash.
  blob: Buffer;
  curve?: string;
}

interface SshCertificate extends SshKey {
  certType: string;
  nonce: Buffer;
  serial: bigint;
  kind: number;
  keyId: string;
  principals: string[];
  validAfter: bigint;
  validBefore: bigint;
  criticalOptions: Record<string, string>;
  extensions: Record<string, string>;
  signatureKey: SshKey;
  signature: { format: string; blob: Buffer; rest: Buffer };
  // The bytes the authority signed: everything before the signature.
  signed: Buffer;
}

interface SshDeps {
  log: typeof log;
  crypto: typeof nodeCrypto;
}

class Ssh {
  constructor(private readonly deps: SshDeps) {
    deps.log.debug("Entering Ssh.constructor().");
    deps.log.debug("Leaving Ssh.constructor().");
  }

  static defaultDeps(): SshDeps {
    helpers.log.debug("Entering Ssh.defaultDeps().");
    helpers.log.debug("Leaving Ssh.defaultDeps().");
    return { log: log, crypto: nodeCrypto };
  }

  b64url(bytes: Buffer): string {
    const { log } = this.deps;
    log.debug("Entering Ssh.b64url().");
    log.debug("Leaving Ssh.b64url().");
    return Buffer.from(bytes).toString('base64url');
  }

  // The public fields of one key type, read from `wire`, as node key
  // material.
  keyFields(type: string, wire: Wire): { key: nodeCrypto.KeyObject;
                                          curve?: string } {
    const { log, crypto } = this.deps;
    log.debug("Entering Ssh.keyFields(). type=" + type);
    if (type === 'ssh-rsa') {
      const e = wire.mpint();
      const n = wire.mpint();
      log.debug("Leaving Ssh.keyFields(). RSA.");
      return { key: crypto.createPublicKey({ format: 'jwk', key: {
        kty: 'RSA', n: this.b64url(n), e: this.b64url(e) } as any }) };
    }
    const ecdsa = /^ecdsa-sha2-(nistp256|nistp384|nistp521)$/.exec(type);
    if (ecdsa) {
      const curve = wire.text();
      const q = wire.string();
      const spec = CURVES[ecdsa[1]];
      if (curve !== ecdsa[1] || q[0] !== 4 ||
          q.length !== 1 + 2 * spec.bytes) {
        log.debug("Leaving Ssh.keyFields(). A bad point.");
        // error-code: none — see Wire.take()
        throw new Error('the ECDSA key is not an uncompressed ' + curve +
                        ' point');
      }
      log.debug("Leaving Ssh.keyFields(). ECDSA.");
      return { curve: ecdsa[1], key: crypto.createPublicKey({ format: 'jwk',
        key: { kty: 'EC', crv: spec.crv,
               x: this.b64url(q.subarray(1, 1 + spec.bytes)),
               y: this.b64url(q.subarray(1 + spec.bytes)) } as any }) };
    }
    if (type === 'ssh-ed25519') {
      const pk = wire.string();
      if (pk.length !== 32) {
        log.debug("Leaving Ssh.keyFields(). A bad Ed25519 key.");
        // error-code: none — see Wire.take()
        throw new Error('an Ed25519 key is 32 bytes');
      }
      log.debug("Leaving Ssh.keyFields(). Ed25519.");
      return { key: crypto.createPublicKey({ format: 'jwk', key: {
        kty: 'OKP', crv: 'Ed25519', x: this.b64url(pk) } as any }) };
    }
    log.debug("Leaving Ssh.keyFields(). Unsupported.");
    // error-code: none — see Wire.take()
    throw new Error('the SSH key type ' + type + ' is not supported ' +
                    '(ssh-rsa, ecdsa-sha2-nistp256/384/521 and ssh-ed25519 ' +
                    'are)');
  }

  // A packed list of name-value pairs (critical options, extensions).
  options(bytes: Buffer): Record<string, string> {
    const { log } = this.deps;
    log.debug("Entering Ssh.options().");
    const wire = new Wire(bytes);
    const out: Record<string, string> = {};
    while (!wire.done()) {
      const name = wire.text();
      const data = wire.string();
      // The value is itself a string inside the data, or empty.
      out[name] = data.length ? new Wire(data).text() : '';
    }
    log.debug("Leaving Ssh.options().");
    return out;
  }

  // A public key blob, or a certificate blob, as `ssh.ParsePublicKey()`.
  parsePublicKey(blob: Buffer): SshKey | SshCertificate {
    const { log } = this.deps;
    log.debug("Entering Ssh.parsePublicKey().");
    const wire = new Wire(Buffer.from(blob));
    const type = wire.text();
    if (type.slice(-CERT_SUFFIX.length) !== CERT_SUFFIX) {
      const fields = this.keyFields(type, wire);
      if (!wire.done()) {
        log.debug("Leaving Ssh.parsePublicKey(). Trailing bytes.");
        // error-code: none — see Wire.take()
        throw new Error('trailing bytes after the SSH public key');
      }
      log.debug("Leaving Ssh.parsePublicKey(). A key.");
      return { type: type, key: fields.key, curve: fields.curve,
               blob: Buffer.from(blob) };
    }
    const keyType = type.slice(0, -CERT_SUFFIX.length);
    const nonce = wire.string();
    const fields = this.keyFields(keyType, wire);
    const serial = wire.uint64();
    const kind = wire.uint32();
    const keyId = wire.text();
    const principalWire = new Wire(wire.string());
    const principals = [];
    while (!principalWire.done()) principals.push(principalWire.text());
    const validAfter = wire.uint64();
    const validBefore = wire.uint64();
    const criticalOptions = this.options(wire.string());
    const extensions = this.options(wire.string());
    wire.string();
    const signatureKeyBlob = wire.string();
    const signedLength = wire.position();
    const signatureWire = new Wire(wire.string());
    if (!wire.done()) {
      log.debug("Leaving Ssh.parsePublicKey(). Trailing bytes.");
      // error-code: none — see Wire.take()
      throw new Error('trailing bytes after the SSH certificate');
    }
    const signatureKey = this.parsePublicKey(signatureKeyBlob);
    if ((signatureKey as SshCertificate).certType) {
      log.debug("Leaving Ssh.parsePublicKey(). A certificate signed a " +
                "certificate.");
      // error-code: none — see Wire.take()
      throw new Error('a certificate\'s signature key cannot itself be a ' +
                      'certificate');
    }
    const format = signatureWire.text();
    const signatureBlob = signatureWire.string();
    const rest = signatureWire.remaining();
    log.debug("Leaving Ssh.parsePublicKey(). A certificate.");
    return {
      type: keyType, certType: type, key: fields.key, curve: fields.curve,
      blob: Buffer.from(blob), nonce: nonce, serial: serial, kind: kind,
      keyId: keyId, principals: principals, validAfter: validAfter,
      validBefore: validBefore, criticalOptions: criticalOptions,
      extensions: extensions, signatureKey: signatureKey,
      signature: { format: format, blob: signatureBlob, rest: rest },
      signed: Buffer.from(blob).subarray(0, signedLength)
    };
  }

  // One authorized_keys line: `[options] type base64 [comment]`, or null for
  // a line that is not a key.
  parseAuthorizedKey(line: string): SshKey | null {
    const { log } = this.deps;
    log.debug("Entering Ssh.parseAuthorizedKey().");
    const text = String(line || '').trim();
    if (!text || text.charAt(0) === '#') {
      log.debug("Leaving Ssh.parseAuthorizedKey(). Not a key.");
      return null;
    }
    // Options may hold quoted spaces; the key is the first field that names
    // a key type and is followed by base64.
    const fields = text.match(/"(?:[^"\\]|\\.)*"|\S+/g) || [];
    for (let i = 0; i < fields.length - 1; i++) {
      if (!/^(ssh-|ecdsa-|sk-)/.test(fields[i]) &&
          fields[i].indexOf('@openssh.com') < 0) {
        continue;
      }
      try {
        const key = this.parsePublicKey(Buffer.from(fields[i + 1], 'base64'));
        if (key.type === fields[i] ||
            (key as SshCertificate).certType === fields[i]) {
          log.debug("Leaving Ssh.parseAuthorizedKey().");
          return key;
        }
      } catch (e) {
        log.debug("Caught in Ssh.parseAuthorizedKey(): " +
                  ((e && e.message) || e));
      }
    }
    log.debug("Leaving Ssh.parseAuthorizedKey(). Unreadable.");
    return null;
  }

  // `ssh.FingerprintSHA256()` without its prefix: unpadded base64 of the
  // SHA-256 of the key blob.
  fingerprint(key: SshKey): string {
    const { log, crypto } = this.deps;
    log.debug("Entering Ssh.fingerprint().");
    log.debug("Leaving Ssh.fingerprint().");
    return crypto.createHash('sha256').update(key.blob).digest('base64')
      .replace(/=+$/, '');
  }

  // Does `signature` over `data` verify under `key`? The formats Go's
  // `Verify()` accepts for each key type, and no others.
  verify(key: SshKey, data: Buffer,
         signature: { format: string; blob: Buffer }): boolean {
    const { log, crypto } = this.deps;
    log.debug("Entering Ssh.verify(). " + key.type + " / " +
              (signature && signature.format));
    if (!signature || !signature.blob) {
      log.debug("Leaving Ssh.verify(). No signature.");
      return false;
    }
    try {
      if (key.type === 'ssh-rsa') {
        const hash = { 'ssh-rsa': 'sha1', 'rsa-sha2-256': 'sha256',
                       'rsa-sha2-512': 'sha512' }[signature.format];
        const ok = !!hash && crypto.verify(hash, data, key.key,
                                           signature.blob);
        log.debug("Leaving Ssh.verify(). RSA " + ok);
        return ok;
      }
      if (key.curve) {
        if (signature.format !== key.type) {
          log.debug("Leaving Ssh.verify(). Wrong format for the curve.");
          return false;
        }
        const spec = CURVES[key.curve];
        const inner = new Wire(signature.blob);
        const r = inner.mpint();
        const s = inner.mpint();
        if (r.length > spec.bytes || s.length > spec.bytes) {
          log.debug("Leaving Ssh.verify(). r or s too long.");
          return false;
        }
        const raw = Buffer.concat([Buffer.alloc(spec.bytes - r.length), r,
                                   Buffer.alloc(spec.bytes - s.length), s]);
        const ok = crypto.verify(spec.hash, data,
                                 { key: key.key, dsaEncoding: 'ieee-p1363' },
                                 raw);
        log.debug("Leaving Ssh.verify(). ECDSA " + ok);
        return ok;
      }
      if (key.type === 'ssh-ed25519' && signature.format === 'ssh-ed25519') {
        const ok = crypto.verify(null, data, key.key, signature.blob);
        log.debug("Leaving Ssh.verify(). Ed25519 " + ok);
        return ok;
      }
    } catch (e) {
      log.debug("Caught in Ssh.verify(): " + ((e && e.message) || e));
    }
    log.debug("Leaving Ssh.verify(). Refused.");
    return false;
  }

  // `CertChecker.CheckHostKey(principal + ':22', …)`: '' when the host
  // certificate is acceptable, otherwise why not.
  checkHostCertificate(cert: SshCertificate, principal: string,
                       authorities: SshKey[], nowSeconds: number): string {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Ssh.checkHostCertificate().");
    if (cert.kind !== HOST_CERT) {
      log.debug("Leaving Ssh.checkHostCertificate(). Not a host cert.");
      return 'ssh: certificate presented as a host key has type ' + cert.kind;
    }
    const authority = self.fingerprint(cert.signatureKey);
    if (!authorities.some(function (one) {
      return self.fingerprint(one) === authority;
    })) {
      log.debug("Leaving Ssh.checkHostCertificate(). Unknown authority.");
      return 'ssh: no authorities for hostname: ' + principal;
    }
    const options = Object.keys(cert.criticalOptions).filter(function (name) {
      return name !== 'source-address';
    });
    if (options.length) {
      log.debug("Leaving Ssh.checkHostCertificate(). Critical option.");
      return 'ssh: unsupported critical option "' + options[0] +
             '" in certificate';
    }
    if (cert.principals.length && cert.principals.indexOf(principal) < 0) {
      log.debug("Leaving Ssh.checkHostCertificate(). Principal.");
      return 'ssh: principal "' + principal + '" not in the set of valid ' +
             'principals for given certificate';
    }
    const now = BigInt(Math.floor(nowSeconds));
    if (cert.validAfter > BigInt('0x7fffffffffffffff') ||
        now < cert.validAfter) {
      log.debug("Leaving Ssh.checkHostCertificate(). Not yet valid.");
      return 'ssh: cert is not yet valid';
    }
    if (cert.validBefore !== FOREVER &&
        (cert.validBefore > BigInt('0x7fffffffffffffff') ||
         now >= cert.validBefore)) {
      log.debug("Leaving Ssh.checkHostCertificate(). Expired.");
      return 'ssh: cert has expired';
    }
    if (!this.verify(cert.signatureKey, cert.signed, cert.signature)) {
      log.debug("Leaving Ssh.checkHostCertificate(). Signature.");
      return 'ssh: certificate signature does not verify';
    }
    log.debug("Leaving Ssh.checkHostCertificate(). Accepted.");
    return '';
  }
}

const shared = new Ssh(Ssh.defaultDeps());

export = {
  Ssh: Ssh,
  HOST_CERT: HOST_CERT,
  parsePublicKey: (blob: Buffer) => shared.parsePublicKey(blob),
  parseAuthorizedKey: (line: string) => shared.parseAuthorizedKey(line),
  fingerprint: (key: any) => shared.fingerprint(key),
  verify: (key: any, data: Buffer, sig: any) => shared.verify(key, data, sig),
  checkHostCertificate: (cert: any, principal: string, authorities: any[],
                         now: number) =>
    shared.checkHostCertificate(cert, principal, authorities, now)
};
