'use strict';
//
// File: spiffe_x509_path.ts
//
// ---------------------------------------------------------------------------
// A CERTIFICATE PATH TO AN OPERATOR'S TRUST ANCHORS, FOR THE NODE ATTESTORS
// THAT PRESENT ONE (#40, 2026-09-21).
//
// `x509pop` and `tpm_devid` both receive a leaf and some intermediates from
// the agent and must answer what Go's `x509.Certificate.Verify()` answers for
// SPIRE: is there a path from this leaf, through these intermediates, to one
// of the roots the operator configured — and which chains, because the
// selectors name every certificate above the leaf (`ca:fingerprint:`).
//
// Node has no verifier that takes caller-supplied roots, so the path is BUILT
// here and its signatures checked by the vendored `x509.verifyChain()`, which
// checks ML-DSA, SLH-DSA and composite signatures as well as RSA, ECDSA and
// Ed25519 — the post-quantum half being why this is not built on
// `X509Certificate.verify()` alone (it cannot read a post-quantum key).
//
// What is checked, as Go checks it with `KeyUsages: ExtKeyUsageAny`:
//   * every certificate is inside its validity window;
//   * every certificate above the leaf is a CA (basicConstraints cA) and,
//     where it states one, its pathLenConstraint allows the CAs below it;
//   * every certificate above the leaf that states a keyUsage permits
//     keyCertSign;
//   * every signature on the path verifies under the key above it;
//   * the path ends at a certificate in the operator's roots — which need
//     not be self-signed (Go's roots are a pool, not a list of self-signed
//     anchors), so a root's own signature is never required.
// The extended key usage is not constrained, which is `ExtKeyUsageAny`.
//
// **TWO THINGS FAIL CLOSED WHERE GO WOULD EVALUATE THEM.** A critical
// extension this module does not understand is refused on any certificate —
// Go refuses those too — except the ones a caller names (`tpm_devid` names
// subjectAltName, which EK certificates mark critical in directoryName form,
// exactly as SPIRE strips it). And a CA carrying nameConstraints is refused,
// because the constraints are not evaluated here: a path accepted without
// checking what its CA was limited to would be accepted wrongly, and one
// refused says so and can be taken up when an operator needs it.
//
// The builder is greedy: at each step it takes a root that issued the current
// certificate if there is one, and otherwise the first unused intermediate
// that did. A set of intermediates offering two different paths is unusual
// enough that an agent meeting it is better told why than walked through
// every alternative.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
const { log } = helpers;

// A certificate on the path, as the caller wants it.
interface PathCertificate {
  der: Buffer;
  pem: string;
  x509: nodeCrypto.X509Certificate;
  // SPIRE's `x509pop.Fingerprint()`: SHA-1 of the DER, lowercase hex.
  sha1: string;
}

interface PathResult {
  ok: boolean;
  // Why not, in a sentence an agent's operator can act on.
  reason?: string;
  // Leaf first, the root last.
  chain?: PathCertificate[];
}

interface X509PathDeps {
  log: typeof log;
  crypto: typeof nodeCrypto;
  // Loaded when first used, as every caller of the vendored engine does.
  loadX509(): any;
}

class X509Path {
  constructor(private readonly deps: X509PathDeps) {
    deps.log.debug("Entering X509Path.constructor().");
    deps.log.debug("Leaving X509Path.constructor().");
  }

  static defaultDeps(): X509PathDeps {
    helpers.log.debug("Entering X509Path.defaultDeps().");
    helpers.log.debug("Leaving X509Path.defaultDeps().");
    return {
      log: log,
      crypto: nodeCrypto,
      loadX509: function () {
        return require('../common/vendored/x509');
      }
    };
  }

  // One certificate from DER, or null when it is not one.
  certificate(der: Buffer): PathCertificate | null {
    const { log, crypto } = this.deps;
    log.debug("Entering X509Path.certificate().");
    try {
      const x509 = new crypto.X509Certificate(der);
      log.debug("Leaving X509Path.certificate().");
      return {
        der: Buffer.from(x509.raw), pem: x509.toString(), x509: x509,
        sha1: crypto.createHash('sha1').update(x509.raw).digest('hex')
      };
    } catch (e) {
      log.debug("Caught in X509Path.certificate(): " +
                ((e && e.message) || e));
      log.debug("Leaving X509Path.certificate(). Not a certificate.");
      return null;
    }
  }

  // Every certificate in a PEM bundle; a block that does not parse is
  // skipped and counted, never fatal, so one bad paste does not take the
  // rest of an operator's anchors with it.
  bundle(pemText: string): { certificates: PathCertificate[];
                             unreadable: number } {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering X509Path.bundle().");
    const blocks = String(pemText || '').match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    const certificates = [];
    let unreadable = 0;
    blocks.forEach(function (block) {
      const body = block.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      const one = self.certificate(Buffer.from(body, 'base64'));
      if (one) {
        certificates.push(one);
      } else {
        unreadable++;
      }
    });
    log.debug("Leaving X509Path.bundle(). " + certificates.length +
              " certificate(s), " + unreadable + " unreadable.");
    return { certificates: certificates, unreadable: unreadable };
  }

  // The RSA modulus size of a certificate's key in bits, or 0 for any other
  // kind of key. SPIRE refuses an RSA key above `max_rsa_key_size` before it
  // does anything else with it, because verifying with a huge one is the
  // expensive half of the protocol and costs the agent nothing to ask for.
  rsaBits(one: PathCertificate): number {
    const { log } = this.deps;
    log.debug("Entering X509Path.rsaBits().");
    const key: any = one.x509.publicKey;
    const details = key && key.asymmetricKeyType === 'rsa'
      ? key.asymmetricKeyDetails || {} : {};
    log.debug("Leaving X509Path.rsaBits().");
    return Number(details.modulusLength || 0);
  }

  // Did `issuer` issue `subject`? Names and key identifiers only — the
  // signature is checked once the path is chosen, by the engine that can
  // check every algorithm.
  issued(subject: PathCertificate, issuer: PathCertificate): boolean {
    const { log } = this.deps;
    log.debug("Entering X509Path.issued().");
    let answer = false;
    const namesMatch = subject.x509.issuer === issuer.x509.subject;
    try {
      answer = subject.x509.checkIssued(issuer.x509);
      if (!answer && namesMatch) {
        // node's check compares key identifiers too, and cannot for a key
        // it does not read (a post-quantum one); there the names decide and
        // the signature check below is what refuses a wrong choice.
        const kind = String((issuer.x509.publicKey as any)
          .asymmetricKeyType || '');
        answer = ['rsa', 'rsa-pss', 'ec', 'ed25519', 'ed448']
          .indexOf(kind) < 0;
      }
    } catch (e) {
      log.debug("Caught in X509Path.issued(): " + ((e && e.message) || e));
      // A key node cannot read: fall back to the names.
      answer = namesMatch;
    }
    log.debug("Leaving X509Path.issued(). " + answer);
    return answer;
  }

  // Build and verify. `now` is milliseconds, for a caller that wants its own
  // clock; skew is not allowed, as Go allows none.
  async verify(leafDer: Buffer, intermediateDers: Buffer[],
               roots: PathCertificate[], now?: number,
               allowCritical?: string[]): Promise<PathResult> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering X509Path.verify().");
    const leaf = this.certificate(leafDer);
    if (!leaf) {
      log.debug("Leaving X509Path.verify(). No leaf.");
      return { ok: false, reason: 'the leaf is not an X.509 certificate' };
    }
    const intermediates = [];
    for (let i = 0; i < intermediateDers.length; i++) {
      const one = this.certificate(intermediateDers[i]);
      if (!one) {
        log.debug("Leaving X509Path.verify(). A bad intermediate.");
        return { ok: false, reason: 'intermediate certificate ' + i +
                 ' is not an X.509 certificate' };
      }
      intermediates.push(one);
    }
    if (!roots.length) {
      log.debug("Leaving X509Path.verify(). No roots.");
      return { ok: false, reason: 'no trust anchor is configured' };
    }
    const path = [leaf];
    const used = new Set();
    let current = leaf;
    // A leaf that IS one of the roots verifies as itself, as in Go.
    let anchored = roots.some(function (root) {
      return root.der.equals(leaf.der);
    });
    while (!anchored) {
      const root = roots.filter(function (candidate) {
        return self.issued(current, candidate);
      })[0];
      if (root) {
        path.push(root);
        anchored = true;
        break;
      }
      const next = intermediates.filter(function (candidate, index) {
        return !used.has(index) && self.issued(current, candidate);
      })[0];
      if (!next) {
        log.debug("Leaving X509Path.verify(). No path.");
        return { ok: false, reason: 'no path from "' + current.x509.subject
                 .replace(/\n/g, ', ') + '" to a configured trust anchor' };
      }
      used.add(intermediates.indexOf(next));
      path.push(next);
      current = next;
    }
    // THE SIGNATURES, by the engine that reads every algorithm. The last
    // link is the root, whose own signature is not the question.
    const x509 = this.deps.loadX509();
    let links = [];
    try {
      links = await x509.verifyChain(path.map(function (one) {
        return one.pem;
      }));
    } catch (e) {
      log.debug("Caught in X509Path.verify(): " + ((e && e.message) || e));
      log.debug("Leaving X509Path.verify(). The engine could not read it.");
      return { ok: false, reason: 'the path could not be read: ' +
               ((e && e.message) || e) };
    }
    const at = now === undefined ? Date.now() : now;
    for (let i = 0; i < path.length; i++) {
      const one = path[i];
      if (Date.parse(one.x509.validFrom) > at ||
          Date.parse(one.x509.validTo) < at) {
        log.debug("Leaving X509Path.verify(). Outside validity.");
        return { ok: false, reason: '"' + one.x509.subject
                 .replace(/\n/g, ', ') + '" is outside its validity window ' +
                 '(' + one.x509.validFrom + ' to ' + one.x509.validTo + ')' };
      }
      if (i < path.length - 1 && !(links[i] && links[i].signatureValid)) {
        log.debug("Leaving X509Path.verify(). A bad signature.");
        return { ok: false, reason: 'the signature on "' + one.x509.subject
                 .replace(/\n/g, ', ') + '" does not verify under the key ' +
                 'of the certificate above it' +
                 (links[i] && links[i].error ? ' (' + links[i].error + ')'
                                             : '') };
      }
      const critical = await this.criticalProblem(one, i > 0,
                                                  allowCritical || []);
      if (critical) {
        log.debug("Leaving X509Path.verify(). An extension.");
        return { ok: false, reason: critical };
      }
      if (i > 0) {
        const problem = await this.caProblem(one, i - 1);
        if (problem) {
          log.debug("Leaving X509Path.verify(). Not a usable CA.");
          return { ok: false, reason: problem };
        }
      }
    }
    log.debug("Leaving X509Path.verify(). " + path.length + " certificate(s).");
    return { ok: true, chain: path };
  }

  // A critical extension nothing here evaluates, or a CA's nameConstraints —
  // see the header — or '' when neither.
  async criticalProblem(one: PathCertificate, isCa: boolean,
                        allowed: string[]): Promise<string> {
    const { log } = this.deps;
    log.debug("Entering X509Path.criticalProblem().");
    const understood = ['basicConstraints', 'keyUsage', 'extKeyUsage',
                        'subjectAltName', 'authorityKeyIdentifier',
                        'subjectKeyIdentifier'];
    const described = await this.deps.loadX509().describeCertificate(one.pem);
    const extensions = (described && described.extensions) || [];
    const name = '"' + one.x509.subject.replace(/\n/g, ', ') + '"';
    for (let i = 0; i < extensions.length; i++) {
      const ext = extensions[i];
      if (isCa && ext.name === 'nameConstraints') {
        log.debug("Leaving X509Path.criticalProblem(). nameConstraints.");
        return name + ' carries nameConstraints, which this server does not ' +
               'evaluate, so a path through it is refused';
      }
      if (ext.critical && understood.indexOf(ext.name) < 0 &&
          allowed.indexOf(ext.name) < 0) {
        log.debug("Leaving X509Path.criticalProblem(). Unhandled.");
        return name + ' carries an unhandled critical extension (' +
               ext.name + ')';
      }
    }
    log.debug("Leaving X509Path.criticalProblem().");
    return '';
  }

  // What stops `one` signing a path with `below` CA certificates beneath it,
  // or '' when nothing does.
  async caProblem(one: PathCertificate, below: number): Promise<string> {
    const { log } = this.deps;
    log.debug("Entering X509Path.caProblem().");
    const name = '"' + one.x509.subject.replace(/\n/g, ', ') + '"';
    if (!one.x509.ca) {
      log.debug("Leaving X509Path.caProblem(). Not a CA.");
      return name + ' issued a certificate and is not a CA ' +
             '(basicConstraints cA is not set)';
    }
    const described = await this.deps.loadX509().describeCertificate(one.pem);
    const extensions = (described && described.extensions) || [];
    const bc = extensions.filter(function (ext) {
      return ext.name === 'basicConstraints';
    })[0];
    const pathLen = bc && bc.value ? bc.value.pathLen : null;
    if (pathLen !== null && pathLen !== undefined && below > pathLen) {
      log.debug("Leaving X509Path.caProblem(). pathLen.");
      return name + ' allows ' + pathLen + ' CA certificate(s) below it ' +
             '(pathLenConstraint) and the path has ' + below;
    }
    const ku = extensions.filter(function (ext) {
      return ext.name === 'keyUsage';
    })[0];
    if (ku && Array.isArray(ku.value) && ku.value.indexOf('keyCertSign') < 0) {
      log.debug("Leaving X509Path.caProblem(). keyUsage.");
      return name + '\'s keyUsage does not permit keyCertSign';
    }
    log.debug("Leaving X509Path.caProblem().");
    return '';
  }
}

const shared = new X509Path(X509Path.defaultDeps());

export = {
  X509Path: X509Path,
  certificate: (der: Buffer) => shared.certificate(der),
  bundle: (pem: string) => shared.bundle(pem),
  rsaBits: (one: PathCertificate) => shared.rsaBits(one),
  verify: (leaf: Buffer, intermediates: Buffer[], roots: PathCertificate[],
           now?: number, allowCritical?: string[]) =>
    shared.verify(leaf, intermediates, roots, now, allowCritical)
};
