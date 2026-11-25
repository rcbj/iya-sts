// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/truststores.ts
//
// ===========================================================================
// NAMED TRUSTSTORES, AND WHICH ONES EACH USE CASE TRUSTS (#2118, 2026-11-24).
//
// rcbj's design on #2118 combined the signer truststore
// (`common/signer_truststore.ts`, Protocols → PKI trust) and the
// client-certificate truststore (`tls/tls_server.js`, /admin/tls/trust) into
// ONE concept: a truststore has a NAME, and every place this service
// validates a signature or dials a TLS server trusts the truststores its use
// case is ASSIGNED, or `system`. The use cases are
// `common/truststore_use_cases.ts`. This module answers three questions and
// nothing else:
//
//   * which truststores exist in a realm — `stores()`, `store()`;
//   * which a use case trusts there — `assignments()`, `namesFor()`;
//   * what they hold — `resolve()` (PEM anchors and intermediates, for a path
//     builder) and `caFor()` (a TLS dialer's `ca`).
//
// **FOUR KINDS OF TRUSTSTORE, ONE NAMESPACE.**
//
//   * BUILT-IN: read-only, shipped or derived. `system` (node's root store),
//     `service-root` (this service's Root), `fido-mds` (the attestation roots
//     the caller's FIDO MDS3 entry lists), `fido-mds-signer` (GlobalSign Root
//     CA - R3 from node's store), `yubico-piv`, `device-vendors`,
//     `cloud-attestation`, `k8s-in-cluster`, `mdoc-own-iaca`.
//   * VIEW: one of the two stores that existed before #2118, read where it is
//     kept — `signers` (`ou=signerTrustAnchors` and its file, per realm) and
//     `client-certificates` (`ou=trustAnchors` and `tls.trustAnchorsFile`,
//     service-wide). Their pages and APIs still write them.
//   * SETTING: `setting:<key>`, one per legacy anchor or CA setting, read in
//     that setting's own format each time it is asked. **NOTHING IS COPIED**:
//     an upgrade changes nothing a deployment trusts, because each use case's
//     default list names the views of what it read before.
//   * NAMED: what an administrator creates, kept in the directory at
//     `ou=truststores,<realm base>` through the slot `ldap/ldap_server.js`
//     fills (rule 3e, the signer truststore's reason: a require of that
//     JavaScript module would move its routes).
//   * SPIFFE: `spiffe:<trust domain>`, a bundle truststore (D5) holding both
//     halves of a trust domain's bundle, read from the bundle storage
//     `spiffe/spiffe_ca.ts` already keeps — which writes both halves in one
//     act, so a bundle truststore cannot hold one half new and the other old.
//
// **SCOPE (D2).** A truststore NAMED in the default realm is service-wide.
// A `service` use case resolves in the default realm and may name only those,
// the built-ins and the views; a `realm` use case resolves in its realm, and a
// name there is looked for in that realm first and in the default realm
// after. `assign()` refuses a list that breaks the rule (STS-PKI-0302).
//
// **EVERY MODE (D4).** Nothing here asks `global.mode` or paranoid PKI mode:
// what a use case is assigned is what it trusts. Paranoid mode decides what
// is CHECKED on the path (`certificate_trust.ts`), never whether a store is
// consulted.
//
// A LIBRARY (rule 3): no route, no listener, no timer. It requires `pki` and
// the settings; every module it reads a view from is required LAZILY, at the
// call, because each is loaded later in the require order.
// ===========================================================================

import fs = require('fs');
import tls = require('tls');
import helpers = require('./helpers');
import config = require('./config');
import realms = require('./realms');
import stsCrypto = require('./crypto');
import pki = require('./pki');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
import UseCases = require('./truststore_use_cases');

type Json = any;

const NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;
const MAX_STORES = 64;
const MAX_ANCHORS = 32;
const MAX_INTERMEDIATES = 64;
const IN_CLUSTER_CA = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt';
const CERTIFICATE =
  /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

const BUILT_INS: Json = {
  system: 'Node\'s own root store, with NODE_EXTRA_CA_CERTS.',
  'service-root': 'This service\'s Root CA.',
  'fido-mds': 'The attestation roots the FIDO MDS3 entry of the ' +
    'authenticator being checked lists.',
  'fido-mds-signer': 'GlobalSign Root CA - R3, from node\'s root store: the ' +
    'anchor of the FIDO MDS3 BLOB.',
  'yubico-piv': 'Yubico\'s PIV attestation roots and intermediates, shipped ' +
    'and pinned by SHA-256.',
  'device-vendors': 'Google\'s Android Key Attestation and Apple\'s App ' +
    'Attest roots, shipped and pinned by SHA-256.',
  'cloud-attestation': 'The Azure roots SPIRE embeds for its IMDS attestor, ' +
    'shipped and pinned.',
  'k8s-in-cluster': 'The Kubernetes service account CA at ' + IN_CLUSTER_CA +
    ', where the service runs in a cluster.',
  'mdoc-own-iaca': 'This realm\'s own mdoc Issuing Authority CA.'
};

const VIEWS: Json = {
  signers: 'The signer truststore: Protocols → PKI trust, ' +
    'ou=signerTrustAnchors and pki.signerTrustAnchorsFile.',
  'client-certificates': 'The client-certificate truststore: ' +
    '/admin/tls/trust, ou=trustAnchors and tls.trustAnchorsFile.'
};

// How each legacy setting holds its certificates, where that is not "PEM text
// or the path of a PEM file".
// KEY SETS (#2149, rcbj 2026-11-25). `registered-keys` is what every key-set
// use case read before: each party's own registered `jwks` / `jwks_uri`. A
// named key-set truststore is BOUND TO ONE PARTY, `<kind>:<id>`, because a
// JWK names no owner and a pool would let one party's key sign as another.
const KEYSET_VIEWS: Json = {
  'registered-keys': 'Each party\'s own registered key set: a client\'s ' +
    'jwks or jwks_uri, a federation relationship\'s fedJwks or fedJwksUri, ' +
    'a claims provider\'s jwksUri. Changed where each party is registered.'
};
// `oidfed-anchor` (#2150): an OpenID Federation Trust Anchor, by its Entity
// Identifier.
const PARTY =
  /^(client|federation|claims-provider|oidfed-anchor):[^\s]{1,255}$/;
const MAX_KEYS = 32;
// A JWK member that makes it a private or a symmetric key.
const SECRET_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

// SSH CERTIFICATE AUTHORITIES (#2151): authorized_keys lines. An SSH CA
// vouches for many hosts and its certificate names the principals, so these
// pool like X.509 anchors; no party binding.
const MAX_SSH_KEYS = 32;
// DOCUMENTS (#2152): the Sigstore trust material, each held as text. cosign
// public keys pool; trusted roots are unioned; a TUF root is ONE document.
const DOCUMENT_KINDS = ['cosign', 'sigstore-root', 'tuf-root'];
const MAX_DOCUMENT = 256 * 1024;
const MAX_COSIGN_KEYS = 32;
// Every kind that is not certificates, for the kind check.
const NOT_X509 = ['jwks', 'ssh'].concat(DOCUMENT_KINDS);
const PUBLIC_KEY =
  /-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/g;

const SETTING_FORMATS: Json = {
  'spiffe.sshpopCertAuthorities': 'ssh-lines',
  // #2152: files of the Sigstore trust material, `files:` a list.
  'spiffe.dockerSigstorePublicKeyFiles': 'files:cosign',
  'spiffe.dockerSigstoreTrustedRootFile': 'file:sigstore-root',
  'spiffe.dockerSigstoreTufRootFile': 'file:tuf-root',
  'saml2.metadataTrustAnchors': 'der-csv',
  'tls.trustIssuedClientCertificates': 'service-root-when-true'
};

interface TruststoresDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  crypto: typeof stsCrypto;
  pki: typeof pki;
  errorCodes: typeof errorCodes;
  readFile: (file: string) => string;
  readCaFile: (file: string) => string[] | string;
  // A file a setting names, held to `security.fileRoots` (#2152).
  readNamedFile: (file: string) => string;
}

interface Resolution {
  useCase: string;
  realmId: string;
  names: string[];
  assigned: boolean;
  fallback: boolean;
  system: boolean;
  anchors: string[];
  intermediates: string[];
  problems: Json[];
}

/**
 * Named truststores and the use cases that trust them. A library: no route.
 */
class Truststores {
  static readonly MAX_STORES = MAX_STORES;
  static readonly MAX_ANCHORS = MAX_ANCHORS;
  static readonly MAX_INTERMEDIATES = MAX_INTERMEDIATES;
  private directory: Json = null;

  /**
   * Creates the registry.
   *
   * @param deps - its dependencies
   */
  constructor(private readonly deps: TruststoresDeps) {
    deps.log.debug("Entering Truststores.constructor().");
    deps.log.debug("Leaving Truststores.constructor().");
  }

  /**
   * The module's own dependencies.
   *
   * @returns the deps a default instance is built from
   */
  static defaultDeps(): TruststoresDeps {
    helpers.log.debug("Entering Truststores.defaultDeps().");
    helpers.log.debug("Leaving Truststores.defaultDeps().");
    return {
      log: helpers.log, config: config, realms: realms, crypto: stsCrypto,
      pki: pki, errorCodes: errorCodes,
      readFile: function (file: string): string {
        return fs.readFileSync(file, 'utf8');
      },
      readCaFile: function (file: string): string[] | string {
        return require('./outbound_tls').caFilePems(file);
      },
      readNamedFile: function (file: string): string {
        require('./outbound_tls').assertNamedFile(file);
        return fs.readFileSync(file, 'utf8');
      }
    };
  }

  /**
   * Installs the directory's half, validated whole (rule 3e): a filler that
   * installed the stores and not the assignments would leave a page that
   * lists truststores nothing can be pointed at.
   *
   * @param directory - `{ listStores, putStore, removeStore, listCerts,
   *   putCert, removeCert, readAssignments, writeAssignments }`, each taking
   *   the realm id first
   * @returns true when installed; false (and logged) for a partial object
   */
  setDirectory(directory: Json): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Truststores.setDirectory().");
    const missing = ['listStores', 'putStore', 'removeStore', 'listCerts',
      'putCert', 'removeCert', 'readAssignments', 'writeAssignments']
      .filter(function (name) {
        return !directory || typeof directory[name] !== 'function';
      });
    if (missing.length) {
      log.error(errorCodes.tag('STS-PKI-0300') + 'truststores: the ' +
                'directory offered no ' + missing.join(', ') + ', so ' +
                'nothing was installed; named truststores and assignments ' +
                'hold nothing until it is.');
      log.debug("Leaving Truststores.setDirectory(). Partial.");
      return false;
    }
    this.directory = directory;
    log.debug("Leaving Truststores.setDirectory().");
    return true;
  }

  /**
   * Names the directory installed, so a test can put it back.
   *
   * @returns the directory, or null
   */
  installedDirectory(): Json {
    this.deps.log.debug("Entering Truststores.installedDirectory().");
    this.deps.log.debug("Leaving Truststores.installedDirectory().");
    return this.directory;
  }

  // A realm id as this module stores it: the ambient realm where none is named.
  private realmIdOf(realmId?: string): string {
    this.deps.log.debug("Entering Truststores.realmIdOf().");
    this.deps.log.debug("Leaving Truststores.realmIdOf().");
    return realmId || this.deps.realms.currentId();
  }

  // The PEM blocks in some text, in order.
  private blocksOf(text: string): string[] {
    this.deps.log.debug("Entering Truststores.blocksOf().");
    const blocks = String(text || '').match(CERTIFICATE) || [];
    this.deps.log.debug("Leaving Truststores.blocksOf(). " + blocks.length);
    return blocks;
  }

  // DER as PEM: an encoding, not a cryptographic operation.
  private pemOfDer(der: Buffer): string {
    this.deps.log.debug("Entering Truststores.pemOfDer().");
    const body = Buffer.from(der).toString('base64').replace(/.{64}/g,
                                                             '$&\n');
    this.deps.log.debug("Leaving Truststores.pemOfDer().");
    return '-----BEGIN CERTIFICATE-----\n' + body.replace(/\n$/, '') +
           '\n-----END CERTIFICATE-----\n';
  }

  // Whether a PEM certificate is self-issued: an anchor rather than a step.
  private selfIssued(pem: string): boolean {
    const { log, crypto } = this.deps;
    log.debug("Entering Truststores.selfIssued().");
    let answer = false;
    try {
      const parsed = crypto.parseCertificate(pem);
      answer = parsed.subject === parsed.issuer;
    } catch (e) {
      log.debug("Caught in Truststores.selfIssued(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving Truststores.selfIssued(). " + answer);
    return answer;
  }

  // Upper hex with no colons, the spelling both older stores use.
  private fingerprintOf(pem: string): string {
    this.deps.log.debug("Entering Truststores.fingerprintOf().");
    this.deps.log.debug("Leaving Truststores.fingerprintOf().");
    return String(this.deps.crypto.parseCertificate(pem).fingerprint256)
      .replace(/:/g, '').toUpperCase();
  }

  // NODE'S DEFAULT STORE as a TLS client would use it: the bundled roots
  // AND what NODE_EXTRA_CA_CERTS adds (`tls.getCACertificates('default')`,
  // node 22.15 and later). `tls.rootCertificates` is the bundled list alone,
  // and a `ca` built from it drops the extra certificates, so it is the
  // fallback only where the newer call is missing.
  static systemPems(): string[] {
    helpers.log.debug("Entering Truststores.systemPems().");
    const api: Json = tls;
    const pems: string[] = typeof api.getCACertificates === 'function' ?
      api.getCACertificates('default').slice() :
      tls.rootCertificates.slice();
    helpers.log.debug("Leaving Truststores.systemPems(). " + pems.length);
    return pems;
  }

  // ----- What a store holds ------------------------------------------------

  // A legacy setting's certificates, read in its own format in a realm.
  private settingPems(realmId: string, key: string): Json {
    const { log, config, realms } = this.deps;
    log.debug("Entering Truststores.settingPems(). " + key);
    const self = this;
    const raw = realms.run(realmId, function () {
      return config.value(key);
    });
    const format = SETTING_FORMATS[key] || 'pem-or-file';
    if (format === 'ssh-lines' || /^files?:/.test(format)) {
      log.debug("Leaving Truststores.settingPems(). Keys or documents, no " +
                "certificate.");
      return { pems: [], problem: null };
    }
    if (format === 'service-root-when-true') {
      const on = raw === true || String(raw) === 'true';
      log.debug("Leaving Truststores.settingPems(). Flag " + on + ".");
      return { pems: on ? this.builtInPems(realmId, 'service-root', {}).pems :
               [], problem: null };
    }
    if (format === 'der-csv') {
      const values = Array.isArray(raw) ? raw :
        String(raw || '').split(',');
      const pems = values.map(function (one: Json) {
        return String(one || '').replace(/\s+/g, '');
      }).filter(Boolean).map(function (b64: string) {
        return self.pemOfDer(Buffer.from(b64, 'base64'));
      });
      log.debug("Leaving Truststores.settingPems(). " + pems.length + ".");
      return { pems: pems, problem: null };
    }
    const text = String(raw || '').trim();
    if (!text) {
      log.debug("Leaving Truststores.settingPems(). Unset.");
      return { pems: [], problem: null };
    }
    if (text.indexOf('-----BEGIN') >= 0) {
      log.debug("Leaving Truststores.settingPems(). Text.");
      return { pems: this.blocksOf(text), problem: null };
    }
    // A PATH, read through the one reader every CA file setting goes
    // through: only in a directory `security.fileRoots` lists, and the same
    // sentence for a file that cannot be used. Required lazily: it is a
    // sibling library, and requiring it at load would order the two for no
    // reason.
    const read = this.deps.readCaFile(text);
    if (typeof read === 'string') {
      log.debug("Leaving Truststores.settingPems(). Unusable file.");
      return { pems: [], problem: { code: 'STS-CORE-0104', store:
        'setting:' + key, why: key + ' names "' + text + '", and ' + read } };
    }
    log.debug("Leaving Truststores.settingPems(). File, " + read.length +
              ".");
    return { pems: read, problem: null };
  }

  // A built-in store's certificates.
  private builtInPems(realmId: string, name: string, context: Json): Json {
    const { log, pki } = this.deps;
    log.debug("Entering Truststores.builtInPems(). " + name);
    const self = this;
    const ders = function (rows: Json[]): string[] {
      return (rows || []).map(function (one: Json) {
        return self.pemOfDer(one.der);
      });
    };
    let pems: string[] = [];
    let intermediates: string[] = [];
    if (name === 'system') {
      pems = Truststores.systemPems();
    } else if (name === 'service-root') {
      pems = pki.trustAnchorsFor(realmId);
      if (!pems.length) {
        const root = pki.serviceRoot();
        pems = root && root.certificatePem ? [root.certificatePem] : [];
      }
    } else if (name === 'fido-mds') {
      pems = (context && context.fidoMdsRoots) || [];
    } else if (name === 'fido-mds-signer') {
      pems = ders(pki.fidoMdsRoots(''));
    } else if (name === 'yubico-piv') {
      const piv = pki.pivAttestationAnchors('');
      pems = ders(piv.anchors);
      intermediates = ders(piv.intermediates);
    } else if (name === 'device-vendors') {
      pems = ders(pki.deviceAttestationAnchors('androidKeyAttestation', '')
        .anchors).concat(ders(pki.deviceAttestationAnchors('appleAppAttest',
          '').anchors));
    } else if (name === 'cloud-attestation') {
      pems = ders(pki.azureImdsRoots());
    } else if (name === 'k8s-in-cluster') {
      try {
        pems = this.blocksOf(this.deps.readFile(IN_CLUSTER_CA));
      } catch (e) {
        log.debug("Caught in Truststores.builtInPems(): " +
                  ((e && e.message) || e));
      }
    } else if (name === 'mdoc-own-iaca') {
      pems = (context && context.ownIaca) || [];
    }
    log.debug("Leaving Truststores.builtInPems(). " + pems.length + ".");
    return { pems: pems, intermediates: intermediates };
  }

  // A view's certificates: the two stores that existed before #2118.
  private viewPems(realmId: string, name: string, context?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.viewPems(). " + name);
    let pems: string[] = [];
    if (name === 'signers') {
      // Anchors and intermediates; a certificate accepted by name vouches
      // for itself only and is no step on anybody's path.
      const self = this;
      const signerTruststore = require('./signer_truststore');
      // A row narrowed to some purposes serves only those (#1360).
      const held = signerTruststore.anchorsFor(realmId,
        (context && context.purpose) || undefined);
      pems = (held.anchors || []).concat(held.intermediates || [])
        .map(function (der: Buffer) {
          return self.pemOfDer(der);
        });
    } else if (name === 'client-certificates') {
      const tlsServer = require.cache[require.resolve('../tls/tls_server')];
      const listed = tlsServer && tlsServer.exports &&
        typeof tlsServer.exports.listAnchors === 'function' ?
        tlsServer.exports.listAnchors() : [];
      pems = ((listed && listed.anchors) || []).map(function (one: Json) {
        return String(one.pem || '');
      }).filter(Boolean);
    }
    log.debug("Leaving Truststores.viewPems(). " + pems.length + ".");
    return { pems: pems };
  }

  // A SPIFFE bundle truststore's X.509 half, and its JWT keys.
  private spiffeBundle(realmId: string, trustDomain: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.spiffeBundle(). " + trustDomain);
    const self = this;
    let ca: Json = null;
    try {
      ca = require('../spiffe/spiffe_ca');
    } catch (e) {
      log.debug("Caught in Truststores.spiffeBundle(): " +
                ((e && e.message) || e));
    }
    const out: Json = { trustDomain: trustDomain, own: false, pems: [],
                        jwtKeys: [] };
    if (!ca) {
      log.debug("Leaving Truststores.spiffeBundle(). No SPIFFE.");
      return out;
    }
    const own = this.deps.realms.run(realmId, function () {
      return typeof ca.trustDomain === 'function' ? ca.trustDomain() : '';
    });
    if (trustDomain === own) {
      const state = this.deps.realms.run(realmId, function () {
        return typeof ca.state === 'function' ? ca.state() : {};
      }) || {};
      out.own = true;
      out.pems = (state.x509Authorities || []).map(function (one: Json) {
        return String(one.certificatePem || '');
      }).filter(Boolean);
      out.jwtKeys = (state.jwtAuthorities || []).slice();
      log.debug("Leaving Truststores.spiffeBundle(). Own.");
      return out;
    }
    const entry = typeof ca.federatedBundle === 'function' ?
      ca.federatedBundle(trustDomain, realmId) : null;
    ((entry && entry.document && entry.document.keys) || [])
      .forEach(function (key: Json) {
        if (key.use === 'x509-svid') {
          (key.x5c || []).forEach(function (b64: string) {
            out.pems.push(self.pemOfDer(Buffer.from(String(b64), 'base64')));
          });
        } else if (key.use === 'jwt-svid') {
          out.jwtKeys.push(key);
        }
      });
    log.debug("Leaving Truststores.spiffeBundle(). " + out.pems.length +
              " X.509, " + out.jwtKeys.length + " JWT.");
    return out;
  }

  // The SPIFFE trust domains a realm has a bundle truststore for.
  private spiffeDomains(realmId: string): string[] {
    const { log } = this.deps;
    log.debug("Entering Truststores.spiffeDomains().");
    let ca: Json = null;
    try {
      ca = require('../spiffe/spiffe_ca');
    } catch (e) {
      log.debug("Caught in Truststores.spiffeDomains(): " +
                ((e && e.message) || e));
    }
    if (!ca) {
      log.debug("Leaving Truststores.spiffeDomains(). No SPIFFE.");
      return [];
    }
    const own = this.deps.realms.run(realmId, function () {
      return typeof ca.trustDomain === 'function' ? ca.trustDomain() : '';
    });
    const federated = (typeof ca.federatedBundles === 'function' ?
      ca.federatedBundles(realmId) : []).map(function (one: Json) {
      return String(one.trustDomain || '');
    });
    const out = (own ? [own] : []).concat(federated).filter(Boolean);
    log.debug("Leaving Truststores.spiffeDomains(). " + out.length + ".");
    return out;
  }

  // A named store's rows, in the realm that holds it.
  private namedRows(realmId: string, name: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering Truststores.namedRows(). " + name);
    const rows = this.directory ?
      (this.directory.listCerts(realmId, name) || []) : [];
    log.debug("Leaving Truststores.namedRows(). " + rows.length + ".");
    return rows;
  }

  // The named stores a realm holds itself.
  private namedStores(realmId: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering Truststores.namedStores().");
    const rows = this.directory ?
      (this.directory.listStores(realmId) || []) : [];
    log.debug("Leaving Truststores.namedStores(). " + rows.length + ".");
    return rows;
  }

  // Whether a key is a setting this service has, and one a default list names:
  // `setting:` views exist for the legacy anchor and CA settings only.
  private settingKnown(key: string): boolean {
    this.deps.log.debug("Entering Truststores.settingKnown(). " + key);
    const known = UseCases.legacySettings().indexOf(key) >= 0 &&
      (this.deps.config.SETTINGS as Json[]).some(function (row: Json) {
        return row && row.key === key;
      });
    this.deps.log.debug("Leaving Truststores.settingKnown(). " + known);
    return known;
  }

  // Where a name resolves from a realm: which kind, in which realm.
  private locate(realmId: string, name: string): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Truststores.locate(). " + name);
    let found: Json = null;
    if (Object.prototype.hasOwnProperty.call(BUILT_INS, name)) {
      found = { kind: 'built-in', realmId: realmId };
    } else if (Object.prototype.hasOwnProperty.call(VIEWS, name)) {
      found = { kind: 'view', realmId: name === 'client-certificates' ?
        realms.DEFAULT_ID : realmId };
    } else if (name.indexOf('setting:') === 0) {
      found = this.settingKnown(name.slice(8)) ?
        { kind: 'setting', realmId: realmId,
          storeKind: Truststores.settingKind(name.slice(8)) } : null;
    } else if (name.indexOf('spiffe:') === 0) {
      found = { kind: 'spiffe', realmId: realmId };
    } else if (Object.prototype.hasOwnProperty.call(KEYSET_VIEWS, name)) {
      found = { kind: 'keyset-view', realmId: realmId, storeKind: 'jwks' };
    } else {
      const byName = function (row: Json): boolean {
        return row.name === name;
      };
      const here = this.namedStores(realmId).filter(byName)[0];
      const shared = !here && realmId !== realms.DEFAULT_ID ?
        this.namedStores(realms.DEFAULT_ID).filter(byName)[0] : null;
      const row = here || shared;
      found = row ? { kind: 'named', realmId: here ? realmId :
        realms.DEFAULT_ID, storeKind: row.kind || 'x509', row: row } : null;
    }
    log.debug("Leaving Truststores.locate(). " +
              (found ? found.kind : 'none'));
    return found;
  }

  // What one store holds, as `{ anchors, intermediates, problem }`.
  private holdings(realmId: string, name: string, context: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.holdings(). " + name);
    const self = this;
    const where = this.locate(realmId, name);
    const out: Json = { anchors: [], intermediates: [], problem: null,
                        jwtKeys: [] };
    if (!where) {
      out.problem = { code: 'STS-PKI-0301', store: name, why: 'no ' +
        'truststore is named "' + name + '"' };
      log.debug("Leaving Truststores.holdings(). Unknown.");
      return out;
    }
    let pems: string[] = [];
    if (NOT_X509.indexOf(where.storeKind) >= 0) {
      // A key set holds no certificate (#2149), nor SSH CA keys (#2151);
      // `keySources()` and `sshAuthorities()` read them.
      log.debug("Leaving Truststores.holdings(). A key set.");
      return out;
    }
    if (where.kind === 'built-in') {
      const built = this.builtInPems(where.realmId, name, context);
      pems = built.pems;
      out.intermediates = built.intermediates;
    } else if (where.kind === 'view') {
      pems = this.viewPems(where.realmId, name, context).pems;
    } else if (where.kind === 'setting') {
      const read = this.settingPems(where.realmId, name.slice(8));
      pems = read.pems;
      out.problem = read.problem;
    } else if (where.kind === 'spiffe') {
      const domain = name.slice(7) === '*' ?
        String((context && context.trustDomain) || '') : name.slice(7);
      const bundle = domain ? this.spiffeBundle(where.realmId, domain) :
        { pems: [], jwtKeys: [] };
      pems = bundle.pems;
      out.jwtKeys = bundle.jwtKeys;
    } else {
      this.namedRows(where.realmId, name).forEach(function (row: Json) {
        (row.kind === 'intermediate' ? out.intermediates : out.anchors)
          .push(row.pem);
      });
      log.debug("Leaving Truststores.holdings(). Named.");
      return out;
    }
    // A built-in, a view, a setting and a bundle hold certificates without
    // saying which are anchors: a self-issued one is, anything else is a step
    // a path may take.
    pems.forEach(function (pem: string) {
      (self.selfIssued(pem) || where.kind === 'spiffe' ? out.anchors :
        out.intermediates).push(pem);
    });
    log.debug("Leaving Truststores.holdings(). " + out.anchors.length +
              " anchor(s), " + out.intermediates.length + " step(s).");
    return out;
  }

  // ----- Assignments -------------------------------------------------------

  // The realm a use case resolves in.
  // A service-wide use case resolves in the default realm, EXCEPT an outbound
  // one a realm has given a list of its own (#2148): that realm's dials use
  // its override. A realm with none inherits the default realm's list.
  private resolvingRealm(useCase: Json, realmId?: string): string {
    this.deps.log.debug("Entering Truststores.resolvingRealm().");
    const here = this.realmIdOf(realmId);
    const DEFAULT = this.deps.realms.DEFAULT_ID;
    if (!useCase || useCase.scope !== 'service') {
      this.deps.log.debug("Leaving Truststores.resolvingRealm(). Realm.");
      return here;
    }
    const overrides = here !== DEFAULT && UseCases.overridable(useCase) &&
      ((this.assignments(here)[useCase.id] || []).length > 0);
    this.deps.log.debug("Leaving Truststores.resolvingRealm(). " +
                        (overrides ? 'The realm\'s override.' :
                                     'The default realm.'));
    return overrides ? here : DEFAULT;
  }

  // Where an assignment for a use case is WRITTEN from a realm (#2148): an
  // overridable use case assigned from a realm is that realm's override;
  // every other service-wide one is the default realm's.
  private assigningRealm(useCase: Json, realmId?: string): string {
    this.deps.log.debug("Entering Truststores.assigningRealm().");
    const here = this.realmIdOf(realmId);
    this.deps.log.debug("Leaving Truststores.assigningRealm().");
    return useCase && useCase.scope === 'service' &&
      !UseCases.overridable(useCase) ? this.deps.realms.DEFAULT_ID : here;
  }

  /**
   * Every assignment a realm has made, by use case.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @returns `{ <use case>: [names] }`, only for use cases assigned there
   */
  assignments(realmId?: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.assignments().");
    const held = this.directory ?
      (this.directory.readAssignments(this.realmIdOf(realmId)) || {}) : {};
    log.debug("Leaving Truststores.assignments().");
    return held;
  }

  /**
   * The list a use case trusts: its assignment where it has one, its
   * default otherwise.
   *
   * @param useCaseId - the use case
   * @param realmId - the realm; the ambient one where omitted
   * @returns `{ names, assigned }`
   */
  namesFor(useCaseId: string, realmId?: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.namesFor(). " + useCaseId);
    const useCase = UseCases.get(useCaseId);
    if (!useCase) {
      log.debug("Leaving Truststores.namesFor(). Unknown.");
      return { names: [], assigned: false };
    }
    const id = this.resolvingRealm(useCase, realmId);
    const held = UseCases.assignable(useCase) ?
      this.assignments(id)[useCaseId] : null;
    log.debug("Leaving Truststores.namesFor().");
    return held && held.length ?
      { names: held.slice(), assigned: true } :
      { names: useCase.defaults.slice(), assigned: false };
  }

  /**
   * What a use case trusts, resolved to certificates.
   *
   * @param useCaseId - the use case
   * @param options - `{ realmId, context, expandSystem }`; `context` carries
   *   what a dynamic built-in needs (`fidoMdsRoots`, `ownIaca`,
   *   `trustDomain`, `purpose`); `expandSystem` lists node's roots among the
   *   anchors where `system` is named, for a path builder
   * @returns the resolution: the names, whether node's store is among them,
   *   the anchors and intermediates as PEM, and every problem a store had
   */
  resolve(useCaseId: string, options?: Json): Resolution {
    const { log } = this.deps;
    log.debug("Entering Truststores.resolve(). " + useCaseId);
    const self = this;
    const opts = options || {};
    const useCase = UseCases.get(useCaseId);
    const realmId = this.resolvingRealm(useCase, opts.realmId);
    const chosen = this.namesFor(useCaseId, realmId);
    const gather = function (names: string[]): Json {
      const acc: Json = { system: false, anchors: [], intermediates: [],
                          problems: [], jwtKeys: [] };
      names.forEach(function (name: string) {
        // NODE'S STORE IS A FLAG, NOT A LIST, unless a path builder asks for
        // it as one: a TLS dialer given `system` alone keeps node's own store
        // untouched (`caFor()`), and a dialer given more gets node's roots
        // and the rest in one `ca`.
        if (name === 'system') {
          acc.system = true;
          if (!opts.expandSystem) {
            return;
          }
        }
        const held = self.holdings(realmId, name, opts.context);
        held.anchors.forEach(function (pem: string) {
          if (acc.anchors.indexOf(pem) === -1) {
            acc.anchors.push(pem);
          }
        });
        held.intermediates.forEach(function (pem: string) {
          if (acc.intermediates.indexOf(pem) === -1) {
            acc.intermediates.push(pem);
          }
        });
        acc.jwtKeys = acc.jwtKeys.concat(held.jwtKeys || []);
        if (held.problem) {
          acc.problems.push(held.problem);
        }
      });
      return acc;
    };
    let names = chosen.names;
    let got = gather(names);
    let fallback = false;
    if (!chosen.assigned && useCase && useCase.fallback &&
        !got.anchors.length && !got.system) {
      names = useCase.fallback.slice();
      const second = gather(names);
      second.problems = got.problems.concat(second.problems);
      got = second;
      fallback = true;
    }
    const out: Resolution = {
      useCase: useCaseId, realmId: realmId, names: names,
      assigned: chosen.assigned, fallback: fallback, system: got.system,
      anchors: got.anchors, intermediates: got.intermediates,
      problems: got.problems
    };
    (out as Json).jwtKeys = got.jwtKeys;
    log.debug("Leaving Truststores.resolve(). " + names.join(',') + ": " +
              got.anchors.length + " anchor(s), " + got.intermediates.length +
              " intermediate(s)" + (got.system ? ', system' : '') + ".");
    return out;
  }

  /**
   * Whether a use case has anything an administrator configured for it: an
   * assignment that resolves to an anchor, or, unassigned, an anchor in one
   * of its own legacy settings. The signer truststore and the built-ins are
   * not counted unassigned, so a page or a metadata document that used to
   * ask "is the setting set?" keeps its answer (#2118 is compatible).
   *
   * @param useCaseId - the use case
   * @param realmId - the realm; the ambient one where omitted
   * @returns the anchors and intermediates counted, as PEM
   */
  configuredPems(useCaseId: string, realmId?: string): string[] {
    const { log } = this.deps;
    log.debug("Entering Truststores.configuredPems(). " + useCaseId);
    const useCase = UseCases.get(useCaseId);
    const id = this.resolvingRealm(useCase, realmId);
    const chosen = this.namesFor(useCaseId, id);
    const self = this;
    let out: string[] = [];
    if (chosen.assigned) {
      const resolved = this.resolve(useCaseId, { realmId: id });
      out = resolved.anchors.concat(resolved.intermediates);
    } else {
      chosen.names.filter(function (name: string) {
        return name.indexOf('setting:') === 0;
      }).forEach(function (name: string) {
        const held = self.holdings(id, name, {});
        out = out.concat(held.anchors, held.intermediates);
      });
    }
    log.debug("Leaving Truststores.configuredPems(). " + out.length + ".");
    return out;
  }

  /**
   * Whether a SPIFFE use case trusts a federated trust domain. Unassigned,
   * or assigned `spiffe:*`, every federated bundle the realm holds is
   * trusted, as before #2118; assigned a list, only those named. A realm's
   * own trust domain is not asked here: it is this service's own authority.
   *
   * @param useCaseId - `spiffe-svid` or `spiffe-jwt-svid`
   * @param trustDomain - the federated trust domain
   * @param realmId - the realm; the ambient one where omitted
   * @returns whether the trust domain is trusted for that use case
   */
  trustsSpiffeDomain(useCaseId: string, trustDomain: string,
                     realmId?: string): boolean {
    const { log } = this.deps;
    log.debug("Entering Truststores.trustsSpiffeDomain(). " + trustDomain);
    const chosen = this.namesFor(useCaseId, realmId);
    const trusted = !chosen.assigned ||
      chosen.names.indexOf('spiffe:*') >= 0 ||
      chosen.names.indexOf('spiffe:' + trustDomain) >= 0;
    log.debug("Leaving Truststores.trustsSpiffeDomain(). " + trusted);
    return trusted;
  }

  /**
   * What a TLS dialer for an outbound use case hands node as `ca`.
   *
   * @param useCaseId - the outbound use case
   * @param options - `{ realmId, extraPems }`; `extraPems` are an entry's own
   *   CAs (a SCIM client, a secret destination, an attribute source), added
   * @returns `{ ca, names, problems }`; `ca` undefined means node's own store
   *   unchanged (the list is `system` alone)
   */
  caFor(useCaseId: string, options?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.caFor(). " + useCaseId);
    const opts = options || {};
    const resolved = this.resolve(useCaseId, opts);
    const own = resolved.anchors.concat(resolved.intermediates)
      .concat(opts.extraPems || []);
    let ca: string[] | undefined;
    if (resolved.system && !own.length) {
      ca = undefined;
    } else {
      ca = (resolved.system ? Truststores.systemPems() : []).concat(own);
    }
    log.debug("Leaving Truststores.caFor(). " +
              (ca ? ca.length + ' certificate(s)' : 'node\'s store'));
    return { ca: ca, names: resolved.names, problems: resolved.problems };
  }

  /**
   * Checks a list for a use case, without writing it.
   *
   * @param useCaseId - the use case
   * @param names - the truststores
   * @param realmId - the realm; the ambient one where omitted
   * @returns null, or `{ code, why }`
   */
  assignmentProblem(useCaseId: string, names: Json,
                    realmId?: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.assignmentProblem(). " + useCaseId);
    const self = this;
    const useCase = UseCases.get(useCaseId);
    if (!useCase) {
      log.debug("Leaving Truststores.assignmentProblem(). Unknown.");
      return { code: 'STS-PKI-0303', why: 'there is no use case "' +
               useCaseId + '"' };
    }
    if (!UseCases.assignable(useCase)) {
      log.debug("Leaving Truststores.assignmentProblem(). Fixed.");
      return { code: 'STS-PKI-0303', why: '"' + useCaseId + '" is ' +
               (useCase.kind === 'pins' ? 'trusted through the certificate ' +
                 'registered on each entry' : useCase.kind === 'admission' ?
                 'an admission rule, not a trust decision' :
                 'this service\'s own hierarchy by definition') +
               ', so it is not assigned truststores' };
    }
    if (!Array.isArray(names) || !names.length) {
      log.debug("Leaving Truststores.assignmentProblem(). Empty.");
      return { code: 'STS-PKI-0303', why: 'a use case is assigned at least ' +
               'one truststore; to return it to its default, clear its ' +
               'assignment' };
    }
    const realmId2 = this.assigningRealm(useCase, realmId);
    for (let i = 0; i < names.length; i++) {
      const name = String(names[i] || '');
      const where = this.locate(realmId2, name);
      if (!where) {
        log.debug("Leaving Truststores.assignmentProblem(). No such store.");
        return { code: 'STS-PKI-0301', why: 'no truststore is named "' +
                 name + '"' };
      }
      const isSpiffe = where.kind === 'spiffe';
      if ((useCase.kind === 'spiffe') !== isSpiffe) {
        log.debug("Leaving Truststores.assignmentProblem(). Kind.");
        return { code: 'STS-PKI-0304', why: useCase.kind === 'spiffe' ?
          '"' + useCaseId + '" is a SPIFFE use case and may name only ' +
          'SPIFFE bundle truststores (spiffe:<trust domain>)' :
          '"' + name + '" is a SPIFFE bundle truststore, which only a ' +
          'SPIFFE use case may name' };
      }
      // A key-set use case names key sets only, and nothing else names one
      // (#2149): a certificate is not a key, nor a key a certificate.
      // And an SSH CA use case names SSH CA keys only (#2151).
      // And a document use case names its own kind of document (#2152).
      const wants = NOT_X509.indexOf(useCase.kind) >= 0 ? useCase.kind :
        'x509';
      const holds = NOT_X509.indexOf(where.storeKind) >= 0 ?
        where.storeKind : 'x509';
      if (wants !== holds) {
        log.debug("Leaving Truststores.assignmentProblem(). Kind.");
        return { code: 'STS-PKI-0309', why: wants === 'jwks' ?
          '"' + useCaseId + '" verifies a JSON Web Signature and may name ' +
          'only key sets (registered-keys, or a key-set truststore)' :
          wants !== 'x509' ? '"' + useCaseId + '" may name only ' + wants +
          ' truststores, and "' + name + '" holds ' + holds :
          '"' + name + '" holds ' + holds + ', which only a use case of ' +
          'that kind may name' };
      }
      if (useCase.scope === 'service' && where.kind === 'named' &&
          where.realmId !== self.deps.realms.DEFAULT_ID &&
          !(UseCases.overridable(useCase) && where.realmId === realmId2)) {
        log.debug("Leaving Truststores.assignmentProblem(). Scope.");
        return { code: 'STS-PKI-0302', why: '"' + useCaseId + '" is decided ' +
                 'with no realm in hand, so it may name only truststores ' +
                 'defined in the default realm' };
      }
    }
    log.debug("Leaving Truststores.assignmentProblem(). None.");
    return null;
  }

  /**
   * Assigns a use case its truststores, or clears its assignment.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param useCaseId - the use case
   * @param names - the truststores, in order; empty or null clears the
   *   assignment, returning the use case to its default
   * @returns `{ ok, code, why }`
   */
  assign(realmId: string | undefined, useCaseId: string,
         names: Json): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Truststores.assign(). " + useCaseId);
    if (!this.directory) {
      log.debug("Leaving Truststores.assign(). No directory.");
      return errorCodes.mark({ ok: false, code: 'STS-PKI-0300',
        why: 'the directory is not installed in this process' },
        'STS-PKI-0300');
    }
    const useCase = UseCases.get(useCaseId);
    const id = this.assigningRealm(useCase, realmId);
    const held = Object.assign({}, this.assignments(id));
    if (!names || (Array.isArray(names) && !names.length)) {
      if (!useCase) {
        log.debug("Leaving Truststores.assign(). Unknown.");
        return errorCodes.mark({ ok: false, code: 'STS-PKI-0303',
          why: 'there is no use case "' + useCaseId + '"' }, 'STS-PKI-0303');
      }
      delete held[useCaseId];
    } else {
      const list = (Array.isArray(names) ? names : [names]).map(String);
      const problem = this.assignmentProblem(useCaseId, list, id);
      if (problem) {
        log.debug("Leaving Truststores.assign(). Refused.");
        return errorCodes.mark({ ok: false, code: problem.code,
                                 why: problem.why }, problem.code);
      }
      held[useCaseId] = list.filter(function (one, i) {
        return list.indexOf(one) === i;
      });
    }
    const written = this.directory.writeAssignments(id, held) !== false;
    log.debug("Leaving Truststores.assign(). " + written);
    return written ? { ok: true, code: '', why: '' } :
      errorCodes.mark({ ok: false, code: 'STS-PKI-0306',
        why: 'the directory is full' }, 'STS-PKI-0306');
  }

  // ----- The stores --------------------------------------------------------

  /**
   * Every truststore a realm can name, of every kind.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @returns rows `{ name, kind, scope, readOnly, description, anchors,
   *   intermediates }`
   */
  stores(realmId?: string): Json[] {
    const { log, realms } = this.deps;
    log.debug("Entering Truststores.stores().");
    const self = this;
    const id = this.realmIdOf(realmId);
    const out: Json[] = [];
    const count = function (name: string): Json {
      const held = self.holdings(id, name, {});
      return { anchors: held.anchors.length,
               intermediates: held.intermediates.length,
               problem: held.problem ? held.problem.why : '' };
    };
    Object.keys(BUILT_INS).forEach(function (name) {
      out.push(Object.assign({ name: name, kind: 'built-in',
        scope: 'service', readOnly: true, description: BUILT_INS[name] },
      name === 'system' ? { anchors: Truststores.systemPems().length,
        intermediates: 0, problem: '' } : count(name)));
    });
    Object.keys(VIEWS).forEach(function (name) {
      out.push(Object.assign({ name: name, kind: 'view',
        scope: name === 'client-certificates' ? 'service' : 'realm',
        readOnly: true, description: VIEWS[name] }, count(name)));
    });
    Object.keys(KEYSET_VIEWS).forEach(function (name) {
      out.push({ name: name, kind: 'view', storeKind: 'jwks', scope: 'realm',
        readOnly: true, description: KEYSET_VIEWS[name], anchors: 0,
        intermediates: 0, problem: '' });
    });
    UseCases.legacySettings().forEach(function (key) {
      const name = 'setting:' + key;
      if (DOCUMENT_KINDS.indexOf(Truststores.settingKind(key)) >= 0) {
        const read = self.settingDocuments(id, key);
        out.push({ name: name, kind: 'setting',
          storeKind: Truststores.settingKind(key), scope: 'realm',
          readOnly: true, description: 'The file(s) the setting ' + key +
            ' names. Change them with the setting.',
          keys: read.documents.length, anchors: 0, intermediates: 0,
          problem: read.problems.length ? read.problems[0].why : '' });
        return;
      }
      if (SETTING_FORMATS[key] === 'ssh-lines') {
        out.push({ name: name, kind: 'setting', storeKind: 'ssh',
          scope: 'realm', readOnly: true, description: 'The SSH CA keys the ' +
            'setting ' + key + ' holds. Change them with the setting.',
          keys: self.sshSettingKeys(id, key).length, anchors: 0,
          intermediates: 0, problem: '' });
        return;
      }
      out.push(Object.assign({ name: name, kind: 'setting', scope: 'realm',
        readOnly: true, description: 'What the setting ' + key + ' names, ' +
          'read where it is kept. Change it with the setting.' },
      count(name)));
    });
    this.spiffeDomains(id).forEach(function (domain) {
      const bundle = self.spiffeBundle(id, domain);
      out.push({ name: 'spiffe:' + domain, kind: 'spiffe', scope: 'realm',
        readOnly: bundle.own, trustDomain: domain,
        description: bundle.own ? 'This realm\'s own SPIFFE trust domain.' :
          'A federated SPIFFE trust domain\'s bundle.',
        anchors: bundle.pems.length, intermediates: 0,
        jwtKeys: bundle.jwtKeys.length, problem: '' });
    });
    const named = this.namedStores(id).map(function (row: Json) {
      return Object.assign({ realmId: id }, row);
    });
    if (id !== realms.DEFAULT_ID) {
      this.namedStores(realms.DEFAULT_ID).forEach(function (row: Json) {
        if (!named.some(function (one: Json) {
          return one.name === row.name;
        })) {
          named.push(Object.assign({ realmId: realms.DEFAULT_ID }, row));
        }
      });
    }
    named.forEach(function (row: Json) {
      if (DOCUMENT_KINDS.indexOf(row.kind) >= 0) {
        const why = Truststores.documentProblem(row.kind,
                                                String(row.document || ''));
        out.push({ name: row.name, kind: 'named', storeKind: row.kind,
          scope: row.realmId === realms.DEFAULT_ID ? 'service' : 'realm',
          readOnly: row.realmId !== id, description: row.description || '',
          addedBy: row.addedBy || '', keys: why ? 0 : 1,
          anchors: 0, intermediates: 0, problem: why });
        return;
      }
      if (row.kind === 'ssh') {
        const read = Truststores.sshKeysOfText(String(row.sshKeys || ''));
        out.push({ name: row.name, kind: 'named', storeKind: 'ssh',
          scope: row.realmId === realms.DEFAULT_ID ? 'service' : 'realm',
          readOnly: row.realmId !== id, description: row.description || '',
          addedBy: row.addedBy || '', keys: read.keys.length,
          anchors: 0, intermediates: 0, problem: read.why });
        return;
      }
      if (row.kind === 'jwks') {
        const read = Truststores.keysOfText(String(row.jwks || ''));
        out.push({ name: row.name, kind: 'named', storeKind: 'jwks',
          scope: row.realmId === realms.DEFAULT_ID ? 'service' : 'realm',
          readOnly: row.realmId !== id, description: row.description || '',
          addedBy: row.addedBy || '', party: row.party || '',
          keys: read.keys.length, jwksUri: row.jwksUri || '',
          anchors: 0, intermediates: 0, problem: read.why });
        return;
      }
      const rows = self.namedRows(row.realmId, row.name);
      out.push({ name: row.name, kind: 'named',
        scope: row.realmId === realms.DEFAULT_ID ? 'service' : 'realm',
        readOnly: row.realmId !== id, description: row.description || '',
        addedBy: row.addedBy || '',
        anchors: rows.filter(function (one: Json) {
          return one.kind !== 'intermediate';
        }).length,
        intermediates: rows.filter(function (one: Json) {
          return one.kind === 'intermediate';
        }).length, problem: '' });
    });
    log.debug("Leaving Truststores.stores(). " + out.length + ".");
    return out;
  }

  // One certificate as a page reads it.
  private describe(pem: string, kind: string, extra?: Json): Json {
    const { log, crypto } = this.deps;
    log.debug("Entering Truststores.describe().");
    const row: Json = Object.assign({ pem: pem, kind: kind, subject: '',
      issuer: '', notBefore: 0, notAfter: 0, fingerprint256: '' },
    extra || {});
    try {
      const facts = crypto.certificateFacts(pem);
      row.subject = facts.subject;
      row.issuer = facts.issuer;
      row.notBefore = facts.notBefore;
      row.notAfter = facts.notAfter;
      row.fingerprint256 = this.fingerprintOf(pem);
    } catch (e) {
      log.debug("Caught in Truststores.describe(): " +
                ((e && e.message) || e));
      row.unadmittable = 'this is not an X.509 certificate';
    }
    log.debug("Leaving Truststores.describe().");
    return row;
  }

  /**
   * One truststore, with what it holds.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param name - the truststore
   * @returns the row with `certificates`, or null
   */
  store(realmId: string | undefined, name: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.store(). " + name);
    const self = this;
    const id = this.realmIdOf(realmId);
    const row = this.stores(id).filter(function (one: Json) {
      return one.name === name;
    })[0];
    if (!row) {
      log.debug("Leaving Truststores.store(). None.");
      return null;
    }
    const held = this.holdings(id, name, {});
    const out = Object.assign({}, row, {
      certificates: held.anchors.map(function (pem: string) {
        return self.describe(pem, 'anchor');
      }).concat(held.intermediates.map(function (pem: string) {
        return self.describe(pem, 'intermediate');
      })),
      jwtKeys: held.jwtKeys || []
    });
    log.debug("Leaving Truststores.store().");
    return out;
  }

  /**
   * What one truststore holds, each certificate described, WITHOUT the row
   * `store()` builds from every store's counts: for a page that lists the
   * certificates of several truststores, or of node's default store, where
   * `store()` would count every truststore again for each (#2118 phase 4).
   * Read-only.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param name - the truststore
   * @returns the certificates, anchors first; empty for a name nothing holds
   */
  certificatesOf(realmId: string | undefined, name: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering Truststores.certificatesOf(). " + name);
    const self = this;
    const held = this.holdings(this.realmIdOf(realmId), name, {});
    const out = held.anchors.map(function (pem: string) {
      return self.describe(pem, 'anchor');
    }).concat(held.intermediates.map(function (pem: string) {
      return self.describe(pem, 'intermediate');
    }));
    log.debug("Leaving Truststores.certificatesOf(). " + out.length + ".");
    return out;
  }

  /**
   * Which use cases name a truststore, in a realm, by assignment or default.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param name - the truststore
   * @returns the use case ids
   */
  usedBy(realmId: string | undefined, name: string): string[] {
    const { log } = this.deps;
    log.debug("Entering Truststores.usedBy(). " + name);
    const self = this;
    const id = this.realmIdOf(realmId);
    const out = UseCases.ROWS.filter(function (row) {
      return UseCases.assignable(row) &&
        self.namesFor(row.id, id).names.indexOf(name) >= 0;
    }).map(function (row) {
      return row.id;
    });
    log.debug("Leaving Truststores.usedBy(). " + out.length + ".");
    return out;
  }

  // A refusal, marked.
  private refused(code: string, why: string): Json {
    this.deps.log.debug("Entering Truststores.refused(). " + code);
    this.deps.log.debug("Leaving Truststores.refused().");
    return this.deps.errorCodes.mark({ ok: false, code: code, why: why },
                                     code);
  }

  /**
   * Creates an empty named truststore.
   *
   * @param realmId - the realm; the ambient one where omitted. The default
   *   realm's are service-wide.
   * @param spec - `{ name, description, addedBy }`
   * @returns `{ ok, code, why }`
   */
  create(realmId: string | undefined, spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.create().");
    const id = this.realmIdOf(realmId);
    const name = String((spec && spec.name) || '').trim();
    if (!this.directory) {
      log.debug("Leaving Truststores.create(). No directory.");
      return this.refused('STS-PKI-0300', 'the directory is not installed ' +
                          'in this process');
    }
    if (!NAME.test(name) || Object.prototype.hasOwnProperty.call(BUILT_INS,
          name) || Object.prototype.hasOwnProperty.call(VIEWS, name) ||
        Object.prototype.hasOwnProperty.call(KEYSET_VIEWS, name)) {
      log.debug("Leaving Truststores.create(). Name.");
      return this.refused('STS-PKI-0305', 'a truststore name is 1 to 63 ' +
        'lower-case letters, digits and hyphens, starting with a letter or ' +
        'digit, and is not one of the built-in names');
    }
    const stores = this.namedStores(id);
    if (stores.some(function (row: Json) {
      return row.name === name;
    })) {
      log.debug("Leaving Truststores.create(). Exists.");
      return this.refused('STS-PKI-0305', 'this realm already has a ' +
                          'truststore named "' + name + '"');
    }
    if (stores.length >= MAX_STORES) {
      log.debug("Leaving Truststores.create(). Full.");
      return this.refused('STS-PKI-0306', 'this realm already holds ' +
                          MAX_STORES + ' named truststores');
    }
    const kind = String((spec && spec.kind) || 'x509');
    const keySet: Json = { party: '', jwks: '', jwksUri: '', sshKeys: '',
                           document: '' };
    if (DOCUMENT_KINDS.indexOf(kind) >= 0) {
      const text = String(spec.document || '').trim();
      const why = Truststores.documentProblem(kind, text);
      if (why) {
        log.debug("Leaving Truststores.create(). Document.");
        return this.refused('STS-PKI-0308', why);
      }
      keySet.document = text;
    } else if (kind === 'ssh') {
      const read = Truststores.sshKeysOfText(String(spec.sshKeys || ''));
      if (read.why) {
        log.debug("Leaving Truststores.create(). SSH keys.");
        return this.refused('STS-PKI-0308', read.why);
      }
      keySet.sshKeys = read.keys.join('\n');
    } else if (kind === 'jwks') {
      const problem = Truststores.keySetProblem(spec, true);
      if (problem) {
        log.debug("Leaving Truststores.create(). Key set.");
        return this.refused('STS-PKI-0308', problem);
      }
      keySet.party = String(spec.party).trim();
      keySet.jwks = String(spec.jwks || '').trim();
      keySet.jwksUri = String(spec.jwksUri || '').trim();
    } else if (kind !== 'x509') {
      log.debug("Leaving Truststores.create(). Kind.");
      return this.refused('STS-PKI-0308', 'a truststore holds x509 ' +
                          'certificates, a jwks key set, ssh CA keys, or a ' +
                          'cosign, sigstore-root or tuf-root document');
    }
    const written = this.directory.putStore(id, Object.assign({
      name: name, kind: kind,
      description: String((spec && spec.description) || ''),
      addedBy: String((spec && spec.addedBy) || '')
    }, keySet)) !== false;
    log.debug("Leaving Truststores.create(). " + written);
    return written ? { ok: true, code: '', why: '' } :
      this.refused('STS-PKI-0306', 'the directory is full');
  }

  /**
   * Deletes a named truststore and what it holds. Refused while any use
   * case in the realm names it.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param name - the truststore
   * @returns `{ ok, code, why }`
   */
  remove(realmId: string | undefined, name: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.remove(). " + name);
    const id = this.realmIdOf(realmId);
    if (!this.directory) {
      log.debug("Leaving Truststores.remove(). No directory.");
      return this.refused('STS-PKI-0300', 'the directory is not installed ' +
                          'in this process');
    }
    if (!this.namedStores(id).some(function (row: Json) {
      return row.name === name;
    })) {
      log.debug("Leaving Truststores.remove(). None.");
      return this.refused('STS-PKI-0301', 'this realm holds no named ' +
                          'truststore "' + name + '"');
    }
    const users = this.usedBy(id, name);
    if (users.length) {
      log.debug("Leaving Truststores.remove(). In use.");
      return this.refused('STS-PKI-0307', '"' + name + '" is assigned to ' +
        users.join(', ') + '; assign those use cases something else first');
    }
    const self = this;
    this.namedRows(id, name).forEach(function (row: Json) {
      self.directory.removeCert(id, name, row.fingerprint);
    });
    const gone = this.directory.removeStore(id, name) !== false;
    log.debug("Leaving Truststores.remove(). " + gone);
    return { ok: gone, code: '', why: gone ? '' : 'nothing was removed' };
  }

  /**
   * Adds certificates to a named truststore, each through the admission
   * rule. A bundle's refusals are named one by one and do not stop its
   * other blocks. A leaf is never admitted.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param name - the truststore
   * @param text - one or more PEM blocks
   * @param options - `{ addedBy }`
   * @returns a promise of `{ added, duplicates, refused }`
   */
  async addCertificates(realmId: string | undefined, name: string,
                        text: string, options?: Json): Promise<Json> {
    const { log, pki, errorCodes, crypto } = this.deps;
    log.debug("Entering Truststores.addCertificates(). " + name);
    const id = this.realmIdOf(realmId);
    const out: Json = { added: [], duplicates: 0, refused: [] };
    const refuse = function (pem: string, code: string, why: string): void {
      log.debug("Entering refuse(). " + code);
      let subject = '';
      try {
        subject = crypto.certificateFacts(pem).subject;
      } catch (e) {
        log.debug("Caught in refuse(): " + ((e && e.message) || e));
      }
      out.refused.push({ subject: subject, code: code, why: why });
      log.debug("Leaving refuse().");
    };
    if (!this.directory) {
      out.refused.push({ subject: '', code: 'STS-PKI-0300',
                         why: 'the directory is not installed in this ' +
                              'process' });
      log.debug("Leaving Truststores.addCertificates(). No directory.");
      return errorCodes.mark(out, 'STS-PKI-0300');
    }
    if (!this.namedStores(id).some(function (row: Json) {
      return row.name === name;
    })) {
      out.refused.push({ subject: '', code: 'STS-PKI-0301',
                         why: 'this realm holds no named truststore "' +
                              name + '"; a built-in, a view or a setting ' +
                              'is changed where it is kept' });
      log.debug("Leaving Truststores.addCertificates(). No store.");
      return errorCodes.mark(out, 'STS-PKI-0301');
    }
    if (this.namedStores(id).some(function (row: Json) {
      return row.name === name && row.kind === 'jwks';
    })) {
      out.refused.push({ subject: '', code: 'STS-PKI-0309',
                         why: '"' + name + '" is a key set: its keys are ' +
                              'changed with set-keys, and it holds no ' +
                              'certificate' });
      log.debug("Leaving Truststores.addCertificates(). A key set.");
      return errorCodes.mark(out, 'STS-PKI-0309');
    }
    const self = this;
    // Self-issued first, so an intermediate in the same bundle as its anchor
    // finds it held.
    const blocks = this.blocksOf(text).sort(function (a, b) {
      return (self.selfIssued(a) ? 0 : 1) - (self.selfIssued(b) ? 0 : 1);
    });
    if (!blocks.length) {
      out.refused.push({ subject: '', code: 'STS-PKI-0238',
                         why: 'no PEM certificate was given' });
    }
    for (let i = 0; i < blocks.length; i++) {
      const held = this.namedRows(id, name);
      let fingerprint = '';
      try {
        fingerprint = this.fingerprintOf(blocks[i]);
      } catch (e) {
        log.debug("Caught in Truststores.addCertificates(): " +
                  ((e && e.message) || e));
        refuse(blocks[i], 'STS-PKI-0238', 'this is not an X.509 certificate');
        continue;
      }
      if (held.some(function (row: Json) {
        return row.fingerprint === fingerprint;
      })) {
        out.duplicates += 1;
        continue;
      }
      const problem = await pki.anchorProblem(blocks[i], {
        heldAnchors: held.filter(function (row: Json) {
          return row.kind !== 'intermediate';
        }).map(function (row: Json) {
          return row.pem;
        }),
        heldIntermediates: held.filter(function (row: Json) {
          return row.kind === 'intermediate';
        }).map(function (row: Json) {
          return pki.pemToDer(row.pem);
        })
      });
      if (problem) {
        refuse(blocks[i], problem.code, problem.why);
        continue;
      }
      const kind = this.selfIssued(blocks[i]) ? 'anchor' : 'intermediate';
      const sameKind = held.filter(function (row: Json) {
        return (row.kind === 'intermediate') === (kind === 'intermediate');
      }).length;
      const cap = kind === 'intermediate' ? MAX_INTERMEDIATES : MAX_ANCHORS;
      if (sameKind >= cap) {
        refuse(blocks[i], 'STS-PKI-0306', 'this truststore already holds ' +
               cap + ' ' + kind + 's');
        continue;
      }
      const row = { fingerprint: fingerprint, pem: blocks[i], kind: kind,
                    addedBy: String((options && options.addedBy) || '') };
      if (this.directory.putCert(id, name, row) === false) {
        refuse(blocks[i], 'STS-PKI-0306', 'the directory is full');
        continue;
      }
      out.added.push(this.describe(blocks[i], kind));
    }
    if (out.refused.length) {
      errorCodes.mark(out, out.refused[0].code);
    }
    log.debug("Leaving Truststores.addCertificates(). " + out.added.length +
              " added, " + out.refused.length + " refused.");
    return out;
  }

  /**
   * Removes one certificate from a named truststore, under either spelling
   * of its fingerprint.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param name - the truststore
   * @param fingerprint - the SHA-256 fingerprint
   * @returns `{ ok, code, why }`
   */
  removeCertificate(realmId: string | undefined, name: string,
                    fingerprint: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.removeCertificate(). " + name);
    const id = this.realmIdOf(realmId);
    const wanted = String(fingerprint || '').replace(/[^0-9a-fA-F]/g, '')
      .toUpperCase();
    if (!this.directory) {
      log.debug("Leaving Truststores.removeCertificate(). No directory.");
      return this.refused('STS-PKI-0300', 'the directory is not installed ' +
                          'in this process');
    }
    if (!this.namedRows(id, name).some(function (row: Json) {
      return row.fingerprint === wanted;
    })) {
      log.debug("Leaving Truststores.removeCertificate(). Not held.");
      return this.refused('STS-PKI-0301', 'the truststore "' + name + '" ' +
                          'holds no certificate with that fingerprint');
    }
    const gone = this.directory.removeCert(id, name, wanted) !== false;
    log.debug("Leaving Truststores.removeCertificate(). " + gone);
    return { ok: gone, code: '', why: gone ? '' : 'nothing was removed' };
  }

  /**
   * Every use case with what it trusts in a realm, for the page and the API.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @returns rows `{ id, title, scope, kind, direction, names, defaults,
   *   assigned, assignable, overridable, realmOverride, sites }`
   */
  useCases(realmId?: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering Truststores.useCases().");
    const self = this;
    const out = UseCases.ROWS.map(function (row) {
      const chosen = self.namesFor(row.id, realmId);
      return { id: row.id, title: row.title, scope: row.scope,
               kind: row.kind, direction: row.direction,
               names: chosen.names, defaults: row.defaults.slice(),
               fallback: (row.fallback || []).slice(),
               assigned: chosen.assigned,
               assignable: UseCases.assignable(row),
               // #2148: whether a realm may give it a list of its own, and
               // whether the realm asked about has.
               overridable: UseCases.overridable(row),
               realmOverride: UseCases.overridable(row) &&
                 self.realmIdOf(realmId) !== self.deps.realms.DEFAULT_ID &&
                 (self.assignments(realmId)[row.id] || []).length > 0,
               sites: row.sites.slice() };
    });
    log.debug("Leaving Truststores.useCases(). " + out.length + ".");
    return out;
  }

  // ----- Key sets (#2149) ------------------------------------------------

  /**
   * A JSON Web Key Set's public keys, or why there are none: at most
   * MAX_KEYS, each with a `kty`, none private or symmetric.
   *
   * @param text - the key set as JSON
   * @returns `{ keys, why }`; `why` is '' when the set is usable
   */
  static keysOfText(text: string): Json {
    helpers.log.debug("Entering Truststores.keysOfText().");
    if (!text) {
      helpers.log.debug("Leaving Truststores.keysOfText(). Empty.");
      return { keys: [], why: '' };
    }
    let parsed: Json = null;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      helpers.log.debug("Caught in Truststores.keysOfText(): " +
                        ((e && (e as Json).message) || e));
      helpers.log.debug("Leaving Truststores.keysOfText(). Not JSON.");
      return { keys: [], why: 'the key set is not JSON' };
    }
    const keys = parsed && Array.isArray(parsed.keys) ? parsed.keys : null;
    let why = '';
    if (!keys || !keys.length) {
      why = 'a key set is a JSON object whose "keys" array holds at least ' +
        'one key';
    } else if (keys.length > MAX_KEYS) {
      why = 'a key set holds at most ' + MAX_KEYS + ' keys';
    } else if (keys.some(function (one: Json) {
      return !one || typeof one !== 'object' || !one.kty;
    })) {
      why = 'every key names its kty';
    } else if (keys.some(function (one: Json) {
      return SECRET_MEMBERS.some(function (member) {
        return Object.prototype.hasOwnProperty.call(one, member);
      });
    })) {
      why = 'a key set holds public keys only: a private or a symmetric ' +
        'key is never stored here';
    }
    helpers.log.debug("Leaving Truststores.keysOfText(). " + (why || 'ok'));
    return { keys: why ? [] : keys, why: why };
  }

  /**
   * What is wrong with a key set's party and contents, or ''. Exactly one of
   * a pasted `jwks` and a `jwksUri` (an http or https URL, fetched under the
   * outbound policy, which decides whether http may be dialled).
   *
   * @param spec - `{ party, jwks, jwksUri }`
   * @param withParty - whether the party is checked (only at creation)
   * @returns the reason, or ''
   */
  static keySetProblem(spec: Json, withParty: boolean): string {
    helpers.log.debug("Entering Truststores.keySetProblem().");
    const party = String((spec && spec.party) || '').trim();
    const jwks = String((spec && spec.jwks) || '').trim();
    const uri = String((spec && spec.jwksUri) || '').trim();
    let why = '';
    if (withParty && !PARTY.test(party)) {
      why = 'a key set names the one party it speaks for: client:<client_id>' +
        ', federation:<relationship id>, claims-provider:<provider id> or ' +
        'oidfed-anchor:<entity id>';
    } else if (!!jwks === !!uri) {
      why = 'a key set is either pasted keys or a jwks_uri, not both and ' +
        'not neither';
    } else if (jwks) {
      why = Truststores.keysOfText(jwks).why;
    } else if (/^oidfed-anchor:/.test(String((spec && spec.boundTo) ||
                                            party))) {
      // A Trust Anchor's keys are trusted out of band (OpenID Federation
      // 1.1, 10.2), and `Oidfed.anchors()` reads them synchronously (#2150).
      why = 'a Trust Anchor\'s key set is pasted keys: its keys are trusted ' +
        'out of band, never fetched';
    } else {
      let url: URL | null = null;
      try {
        url = new URL(uri);
      } catch (e) {
        helpers.log.debug("Caught in Truststores.keySetProblem(): " +
                          ((e && (e as Json).message) || e));
        url = null;
      }
      if (!url || (url.protocol !== 'https:' && url.protocol !== 'http:')) {
        why = 'a jwks_uri is an https URL';
      }
    }
    helpers.log.debug("Leaving Truststores.keySetProblem(). " +
                      (why || 'none'));
    return why;
  }

  /**
   * Replaces a key-set truststore's keys: a pasted set or a jwks_uri. Its
   * party is fixed when it is created and never changes.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param name - the key-set truststore
   * @param spec - `{ jwks }` or `{ jwksUri }`
   * @returns `{ ok, code, why }`
   */
  setKeys(realmId: string | undefined, name: string, spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.setKeys(). " + name);
    const id = this.realmIdOf(realmId);
    if (!this.directory) {
      log.debug("Leaving Truststores.setKeys(). No directory.");
      return this.refused('STS-PKI-0300', 'the directory is not installed ' +
                          'in this process');
    }
    const row = this.namedStores(id).filter(function (one: Json) {
      return one.name === name;
    })[0];
    if (!row) {
      log.debug("Leaving Truststores.setKeys(). None.");
      return this.refused('STS-PKI-0301', 'this realm holds no named ' +
                          'truststore "' + name + '"');
    }
    if (DOCUMENT_KINDS.indexOf(row.kind) >= 0) {
      const text = String((spec && spec.document) || '').trim();
      const why = Truststores.documentProblem(row.kind, text);
      if (why) {
        log.debug("Leaving Truststores.setKeys(). Document refused.");
        return this.refused('STS-PKI-0308', why);
      }
      const put = this.directory.putStore(id, {
        name: row.name, kind: row.kind, description: row.description || '',
        addedBy: row.addedBy || '', document: text
      }) !== false;
      log.debug("Leaving Truststores.setKeys(). Document " + put);
      return put ? { ok: true, code: '', why: '' } :
        this.refused('STS-PKI-0306', 'the directory is full');
    }
    if (row.kind === 'ssh') {
      const read = Truststores.sshKeysOfText(String((spec && spec.sshKeys) ||
                                                    ''));
      if (read.why) {
        log.debug("Leaving Truststores.setKeys(). SSH keys refused.");
        return this.refused('STS-PKI-0308', read.why);
      }
      const done = this.directory.putStore(id, {
        name: row.name, kind: 'ssh', description: row.description || '',
        addedBy: row.addedBy || '', sshKeys: read.keys.join('\n')
      }) !== false;
      log.debug("Leaving Truststores.setKeys(). SSH keys " + done);
      return done ? { ok: true, code: '', why: '' } :
        this.refused('STS-PKI-0306', 'the directory is full');
    }
    if (row.kind !== 'jwks') {
      log.debug("Leaving Truststores.setKeys(). Certificates.");
      return this.refused('STS-PKI-0309', '"' + name + '" holds ' +
                          'certificates, not a key set');
    }
    const problem = Truststores.keySetProblem(
      Object.assign({}, spec, { boundTo: row.party }), false);
    if (problem) {
      log.debug("Leaving Truststores.setKeys(). Refused.");
      return this.refused('STS-PKI-0308', problem);
    }
    const written = this.directory.putStore(id, {
      name: row.name, kind: 'jwks', description: row.description || '',
      addedBy: row.addedBy || '', party: row.party,
      jwks: String(spec.jwks || '').trim(),
      jwksUri: String(spec.jwksUri || '').trim()
    }) !== false;
    log.debug("Leaving Truststores.setKeys(). " + written);
    return written ? { ok: true, code: '', why: '' } :
      this.refused('STS-PKI-0306', 'the directory is full');
  }

  /**
   * WHERE A PARTY'S KEYS COME FROM for a key-set use case (#2149): whether
   * its own registration counts (`registered-keys` in the use case's list),
   * and the key-set truststores the list names that are BOUND TO IT. A store
   * bound to anybody else contributes nothing, whatever the list says. The
   * caller reads the registration and fetches a `jwksUri` the way it always
   * has; this answers only which sources are in.
   *
   * @param useCaseId - a `jwks` use case
   * @param party - `{ kind: 'client' | 'federation' | 'claims-provider', id }`
   * @param realmId - the realm; the ambient one where omitted
   * @returns `{ registered, sets: [{ name, keys } | { name, uri }],
   *   names, assigned, problems }`
   */
  keySources(useCaseId: string, party: Json, realmId?: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.keySources(). " + useCaseId);
    const useCase = UseCases.get(useCaseId);
    if (!useCase || useCase.kind !== 'jwks') {
      log.debug("Leaving Truststores.keySources(). Not a key-set use case.");
      return { registered: true, sets: [], names: [], assigned: false,
               problems: [] };
    }
    const self = this;
    const chosen = this.namesFor(useCaseId, realmId);
    const here = this.resolvingRealm(useCase, realmId);
    const wanted = String((party && party.kind) || '') + ':' +
      String((party && party.id) || '');
    const sets: Json[] = [];
    const problems: Json[] = [];
    (chosen.names as string[]).forEach(function (name: string) {
      const where = self.locate(here, name);
      if (!where || where.kind !== 'named' || where.storeKind !== 'jwks' ||
          where.row.party !== wanted) {
        return;
      }
      if (where.row.jwksUri) {
        sets.push({ name: name, uri: String(where.row.jwksUri) });
        return;
      }
      const read = Truststores.keysOfText(String(where.row.jwks || ''));
      if (read.why) {
        problems.push({ code: 'STS-PKI-0308', store: name, why: read.why });
        return;
      }
      sets.push({ name: name, keys: read.keys });
    });
    const registered = chosen.names.indexOf('registered-keys') >= 0;
    log.debug("Leaving Truststores.keySources(). registered=" + registered +
              ", " + sets.length + " bound set(s).");
    return { registered: registered, sets: sets, names: chosen.names,
             assigned: chosen.assigned, problems: problems };
  }

  // The store kind a legacy setting's view holds.
  private static settingKind(key: string): string {
    helpers.log.debug("Entering Truststores.settingKind(). " + key);
    const format = String(SETTING_FORMATS[key] || '');
    const kind = format === 'ssh-lines' ? 'ssh' :
      /^files?:/.test(format) ? format.replace(/^files?:/, '') : 'x509';
    helpers.log.debug("Leaving Truststores.settingKind(). " + kind);
    return kind;
  }

  /**
   * What is wrong with a document of a kind (#2152), or ''. `cosign`: one
   * to 32 PEM public keys; `sigstore-root`: a trusted_root.json, a JSON
   * object with certificateAuthorities or tlogs; `tuf-root`: a TUF root,
   * a JSON object whose signed._type is root. At most 256 KiB.
   *
   * @param kind - the document kind
   * @param text - the document
   * @returns the reason, or ''
   */
  static documentProblem(kind: string, text: string): string {
    helpers.log.debug("Entering Truststores.documentProblem(). " + kind);
    let why = '';
    if (!text) {
      why = 'a ' + kind + ' truststore holds a document; none was given';
    } else if (Buffer.byteLength(text, 'utf8') > MAX_DOCUMENT) {
      why = 'a document is at most 256 KiB';
    } else if (kind === 'cosign') {
      const blocks = text.match(PUBLIC_KEY) || [];
      if (!blocks.length || blocks.length > MAX_COSIGN_KEYS) {
        why = 'a cosign truststore holds 1 to ' + MAX_COSIGN_KEYS + ' PEM ' +
          'public keys';
      } else if (blocks.some(function (one) {
        let spki: Json = null;
        try {
          spki = stsCrypto.spkiFromPublicKeyPem(one);
        } catch (e) {
          helpers.log.debug("Caught in Truststores.documentProblem(): " +
                            ((e && (e as Json).message) || e));
          spki = null;
        }
        return !spki;
      })) {
        why = 'every block is a PEM public key';
      }
    } else {
      let doc: Json = null;
      try {
        doc = JSON.parse(text);
      } catch (e) {
        helpers.log.debug("Caught in Truststores.documentProblem(): " +
                          ((e && (e as Json).message) || e));
        doc = null;
      }
      if (!doc || typeof doc !== 'object') {
        why = 'a ' + kind + ' document is JSON';
      } else if (kind === 'sigstore-root' &&
                 !Array.isArray(doc.certificateAuthorities) &&
                 !Array.isArray(doc.tlogs)) {
        why = 'a Sigstore trusted root names certificateAuthorities or tlogs';
      } else if (kind === 'tuf-root' &&
                 !(doc.signed && doc.signed._type === 'root')) {
        why = 'a TUF root is a signed document whose _type is root';
      }
    }
    helpers.log.debug("Leaving Truststores.documentProblem(). " +
                      (why || 'none'));
    return why;
  }

  // The documents a `file:` or `files:` setting names, read where kept.
  private settingDocuments(realmId: string, key: string): Json {
    const { log, config, realms } = this.deps;
    log.debug("Entering Truststores.settingDocuments(). " + key);
    const self = this;
    const raw = realms.run(realmId, function () {
      return config.value(key);
    });
    const files = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one: Json) {
        return String(one).trim();
      }).filter(Boolean);
    const documents: Json[] = [];
    const problems: Json[] = [];
    files.forEach(function (file: string) {
      try {
        documents.push({ name: 'setting:' + key, file: file,
                         text: self.deps.readNamedFile(file) });
      } catch (e) {
        log.debug("Caught in Truststores.settingDocuments(): " +
                  ((e && (e as Json).message) || e));
        problems.push({ code: 'STS-PKI-0308', store: 'setting:' + key,
          file: file, why: file + ' could not be read: ' +
            ((e && (e as Json).message) || e) });
      }
    });
    log.debug("Leaving Truststores.settingDocuments(). " + documents.length);
    return { documents: documents, problems: problems };
  }

  /**
   * THE DOCUMENTS a document use case trusts (#2152), in its list's order:
   * a setting view's files read under `security.fileRoots`, a truststore's
   * document as stored. A file that cannot be read is a problem, not a
   * document; the caller decides whether that fails it.
   *
   * @param useCaseId - a `cosign`, `sigstore-root` or `tuf-root` use case
   * @param realmId - the realm; the ambient one where omitted
   * @returns `{ documents: [{ name, file?, text }], names, assigned,
   *   problems }`
   */
  documentsFor(useCaseId: string, realmId?: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.documentsFor(). " + useCaseId);
    const useCase = UseCases.get(useCaseId);
    if (!useCase || DOCUMENT_KINDS.indexOf(useCase.kind) < 0) {
      log.debug("Leaving Truststores.documentsFor(). Not a document use " +
                "case.");
      return { documents: [], names: [], assigned: false, problems: [] };
    }
    const self = this;
    const chosen = this.namesFor(useCaseId, realmId);
    const here = this.resolvingRealm(useCase, realmId);
    const documents: Json[] = [];
    const problems: Json[] = [];
    (chosen.names as string[]).forEach(function (name: string) {
      const where = self.locate(here, name);
      if (!where || where.storeKind !== useCase.kind) {
        return;
      }
      if (where.kind === 'setting') {
        const read = self.settingDocuments(where.realmId, name.slice(8));
        read.documents.forEach(function (one: Json) {
          documents.push(one);
        });
        read.problems.forEach(function (one: Json) {
          problems.push(one);
        });
        return;
      }
      documents.push({ name: name, text: String(where.row.document || '') });
    });
    log.debug("Leaving Truststores.documentsFor(). " + documents.length +
              " document(s).");
    return { documents: documents, names: chosen.names,
             assigned: chosen.assigned, problems: problems };
  }

  /**
   * SSH CA public keys in authorized_keys form (#2151): one per line, at
   * most MAX_SSH_KEYS, each one `pki.parseSshAuthorizedKey()` reads; blank
   * lines and comments are dropped.
   *
   * @param text - the lines
   * @returns `{ keys, why }`, `keys` the normalised lines
   */
  static sshKeysOfText(text: string): Json {
    helpers.log.debug("Entering Truststores.sshKeysOfText().");
    const lines = String(text || '').split(/\r?\n/).map(function (one) {
      return one.trim();
    }).filter(function (one) {
      return !!one && one.charAt(0) !== '#';
    });
    let why = '';
    if (!lines.length) {
      why = 'SSH CA keys are at least one public key in authorized_keys form';
    } else if (lines.length > MAX_SSH_KEYS) {
      why = 'a truststore holds at most ' + MAX_SSH_KEYS + ' SSH CA keys';
    } else if (lines.some(function (one) {
      return !pki.parseSshAuthorizedKey(one);
    })) {
      why = 'every line is an SSH public key in authorized_keys form';
    }
    helpers.log.debug("Leaving Truststores.sshKeysOfText(). " +
                      (why || 'ok'));
    return { keys: why ? [] : lines, why: why };
  }

  // The SSH CA keys an `ssh-lines` setting holds in a realm.
  private sshSettingKeys(realmId: string, key: string): string[] {
    const { log, config, realms } = this.deps;
    log.debug("Entering Truststores.sshSettingKeys(). " + key);
    const raw = realms.run(realmId, function () {
      return config.value(key);
    });
    const lines = String(raw || '').split(/\r?\n/).map(function (one) {
      return one.trim();
    }).filter(function (one) {
      return !!one && one.charAt(0) !== '#';
    });
    log.debug("Leaving Truststores.sshSettingKeys(). " + lines.length);
    return lines;
  }

  /**
   * THE SSH CA KEYS an `ssh` use case trusts (#2151), in order: what its
   * list names, each setting view and SSH CA truststore read where kept.
   * Lines that do not parse are left for the caller's parser to drop.
   *
   * @param useCaseId - an `ssh` use case
   * @param realmId - the realm; the ambient one where omitted
   * @returns `{ keys, names, assigned, problems }`
   */
  sshAuthorities(useCaseId: string, realmId?: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.sshAuthorities(). " + useCaseId);
    const useCase = UseCases.get(useCaseId);
    if (!useCase || useCase.kind !== 'ssh') {
      log.debug("Leaving Truststores.sshAuthorities(). Not an SSH use case.");
      return { keys: [], names: [], assigned: false, problems: [] };
    }
    const self = this;
    const chosen = this.namesFor(useCaseId, realmId);
    const here = this.resolvingRealm(useCase, realmId);
    const keys: string[] = [];
    const problems: Json[] = [];
    (chosen.names as string[]).forEach(function (name: string) {
      const where = self.locate(here, name);
      if (!where || where.storeKind !== 'ssh') {
        return;
      }
      if (where.kind === 'setting') {
        self.sshSettingKeys(where.realmId, name.slice(8)).forEach(
          function (one) {
            keys.push(one);
          });
        return;
      }
      const read = Truststores.sshKeysOfText(String(where.row.sshKeys || ''));
      if (read.why) {
        problems.push({ code: 'STS-PKI-0308', store: name, why: read.why });
        return;
      }
      read.keys.forEach(function (one: string) {
        keys.push(one);
      });
    });
    log.debug("Leaving Truststores.sshAuthorities(). " + keys.length + ".");
    return { keys: keys, names: chosen.names, assigned: chosen.assigned,
             problems: problems };
  }

  /**
   * EVERY key set a key-set use case names that is bound to a party OF ONE
   * KIND (#2150), for a reader that enumerates its parties rather than being
   * presented one: `Oidfed.anchors()`, whose anchors ARE the parties. Pasted
   * keys only; a set naming a jwks_uri is skipped.
   *
   * @param useCaseId - a `jwks` use case
   * @param partyKind - e.g. `oidfed-anchor`
   * @param realmId - the realm; the ambient one where omitted
   * @returns `{ registered, sets: [{ name, party, keys }], problems }`
   */
  boundKeySets(useCaseId: string, partyKind: string, realmId?: string): Json {
    const { log } = this.deps;
    log.debug("Entering Truststores.boundKeySets(). " + useCaseId);
    const useCase = UseCases.get(useCaseId);
    if (!useCase || useCase.kind !== 'jwks') {
      log.debug("Leaving Truststores.boundKeySets(). Not a key-set use case.");
      return { registered: true, sets: [], problems: [] };
    }
    const self = this;
    const chosen = this.namesFor(useCaseId, realmId);
    const here = this.resolvingRealm(useCase, realmId);
    const prefix = partyKind + ':';
    const sets: Json[] = [];
    const problems: Json[] = [];
    (chosen.names as string[]).forEach(function (name: string) {
      const where = self.locate(here, name);
      if (!where || where.kind !== 'named' || where.storeKind !== 'jwks' ||
          String(where.row.party || '').indexOf(prefix) !== 0 ||
          where.row.jwksUri) {
        return;
      }
      const read = Truststores.keysOfText(String(where.row.jwks || ''));
      if (read.why) {
        problems.push({ code: 'STS-PKI-0308', store: name, why: read.why });
        return;
      }
      sets.push({ name: name, party: String(where.row.party).slice(
        prefix.length), keys: read.keys });
    });
    const registered = chosen.names.indexOf('registered-keys') >= 0;
    log.debug("Leaving Truststores.boundKeySets(). " + sets.length + ".");
    return { registered: registered, sets: sets, problems: problems };
  }

  /**
   * The store's limits, for the page.
   *
   * @returns `{ maxStores, maxAnchors, maxIntermediates, installed }`
   */
  limits(): Json {
    this.deps.log.debug("Entering Truststores.limits().");
    this.deps.log.debug("Leaving Truststores.limits().");
    return { maxStores: MAX_STORES, maxAnchors: MAX_ANCHORS,
             maxIntermediates: MAX_INTERMEDIATES,
             installed: !!this.directory };
  }
}

const slot = new InstanceSlot<Truststores>(
  'common/truststores',
  () => new Truststores(Truststores.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Named truststores and the use cases that trust them.
 *
 * @namespace
 */
export = {
  Truststores: Truststores,
  MAX_STORES: MAX_STORES,
  installInstance: (instance: Truststores): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  setDirectory: slot.forward('setDirectory'),
  installedDirectory: slot.forward('installedDirectory'),
  assignments: slot.forward('assignments'),
  namesFor: slot.forward('namesFor'),
  resolve: slot.forward('resolve'),
  configuredPems: slot.forward('configuredPems'),
  trustsSpiffeDomain: slot.forward('trustsSpiffeDomain'),
  caFor: slot.forward('caFor'),
  assignmentProblem: slot.forward('assignmentProblem'),
  assign: slot.forward('assign'),
  stores: slot.forward('stores'),
  store: slot.forward('store'),
  certificatesOf: slot.forward('certificatesOf'),
  usedBy: slot.forward('usedBy'),
  create: slot.forward('create'),
  remove: slot.forward('remove'),
  addCertificates: slot.forward('addCertificates'),
  removeCertificate: slot.forward('removeCertificate'),
  useCases: slot.forward('useCases'),
  // Key sets (#2149).
  setKeys: slot.forward('setKeys'),
  keySources: slot.forward('keySources'),
  boundKeySets: slot.forward('boundKeySets'),
  sshAuthorities: slot.forward('sshAuthorities'),
  sshKeysOfText: Truststores.sshKeysOfText,
  documentsFor: slot.forward('documentsFor'),
  documentProblem: Truststores.documentProblem,
  keysOfText: Truststores.keysOfText,
  keySetProblem: Truststores.keySetProblem,
  limits: slot.forward('limits')
};
