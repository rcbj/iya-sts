// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: certificate_views.ts
//
// ===========================================================================
// WHICH CERTIFICATES A DETAILS VIEW MAY SHOW, AND THE VIEW ITSELF (2026-09-13).
//
// `common/certificate_details.ts` describes a certificate it is handed. This
// file decides WHICH certificates it may be handed, and answers the two
// questions both admin surfaces ask of them: *what certificates does this
// realm hold*, and *show me this one, with its chain*. `/admin/pki`,
// `/admin/crypto-metadata` and `GET /admin-api/certificates` all read these two
// functions, so a certificate cannot be viewable on one door and unknown on
// another.
//
// ---------------------------------------------------------------------------
// A CERTIFICATE IS NAMED BY ITS SHA-256 AND LOOKED UP, NEVER SENT.
//
// The obvious implementation takes the PEM in the query string. It is not
// taken, and the reason is not size: a details view that describes whatever it
// is handed is a page that renders an attacker's certificate — with an
// attacker's subject, an attacker's extension values and an attacker's chain
// status — under this console's header, reachable by a link somebody was sent.
// So the handle is the fingerprint, and the only certificates that resolve are
// the ones in the CATALOGUE below: what this service itself holds, in the realm
// the request was reached in and the process branch beside it. A fingerprint
// of anything else is refused, and the refusal says where the catalogue comes
// from.
//
// **THE FINGERPRINT IS THE ONE THESE PAGES ALREADY PRINT** —
// `pki.thumbprintOf()` and `certificate_details.fingerprintOf()` are one
// computation, the SHA-256 of the DER — so a thumbprint copied off either page
// is a handle that works.
//
// ---------------------------------------------------------------------------
// THE CATALOGUE IS PER REALM, AND THAT IS THE REALM BOUNDARY APPLIED TO A VIEW.
//
// It holds the service Root, the PROCESS branch (TLS, which certifies the
// sockets every realm answers on — SPIFFE moved to a realm's branch on
// 2026-09-11) and THIS realm's Intermediate, Issuing CAs
// and what they certified — exactly the tree `/admin/pki` draws — plus this
// realm's signing-key certificates, the certificate authority workbench's
// store, the TLS listener certificates, the SPIFFE authorities, and every
// application's and person's issued key pair. Another realm's Intermediate is
// not in it, so another realm's leaf cannot be opened here and its chain could
// not be completed here if it were: the same boundary `verifyLeaf()` enforces,
// drawn on a page.
//
// ---------------------------------------------------------------------------
// TWO KINDS OF SOURCE, AND THE DIFFERENCE IS COST.
//
// The AUTHORITY sources — the tree, the workbench, the keys, TLS, SPIFFE — are
// a few dozen certificates read from memory, and they are also the CANDIDATES
// a chain is built over, since an issuer is an authority. The HOLDER sources —
// every application and every person with an issued key pair — walk the
// directory, which a bulk-loaded realm holds fifty thousand people in. So a
// lookup asks the authorities first and walks the directory only when the
// fingerprint was not among them, and a chain is never built over the holders:
// a leaf signs nothing.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS, AND WHAT IT REQUIRES LAZILY.
//
// `admin-core/` — both surfaces read it, and neither owns it. It requires
// `common/` libraries in the ordinary direction. **`tls/tls_server.js` and
// `spiffe/spiffe_ca.ts` are required INSIDE the functions that read them**, for
// rule 1: `admin-ui/pki_admin.ts` requires this file at 18a and the TLS module
// registers its routes at 20, so a require at the top would move `/tls*` ahead
// of the management API. (That still holds after #50's R1: `tls_server.js` is
// JavaScript and registers its routes when it is required, where the
// converted modules now leave that to `common/protocol_stack.ts`.
// `spiffe_ca.ts` is a library and is lazy for the load order alone.) A
// request handler runs after every module has loaded,
// so inside a function the require is a cache hit — `request_pool.js`'s
// `reconcileTheListener()` makes the same argument.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `CertificateViews` takes this file's logger, the certificate
// describer, the error codes, `pki`, `realms`, both registries of key pairs,
// `helpers`, the X.509 encoder and `pkijs` through its constructor — and the
// three LAZY requires as loader functions, called where the requires were.
// Since R2 the composition root (`common/protocol_stack.ts`) builds the
// instance; the module still exports `PAGES`, and its three functions are
// FACADES that forward to that instance, for `admin-ui/pki_admin.ts`,
// `admin-ui/crypto_metadata.ts`, `mgmt-api/admin_api.ts` and the test. A
// process without the root builds a default at load. `CertificateViews` is
// exported beside them for the root.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('../common/config');

const log = bunyan.createLogger({
  name: 'certificate_views',
  level: config.value('global.logLevel')
});

import details = require('../common/certificate_details');
import errorCodes = require('../common/error_codes');
import pki = require('../common/pki');
import realms = require('../common/realms');
import applications = require('../common/applications');
import personAssertions = require('../common/person_assertions');
import helpers = require('../common/helpers');
import x509 = require('../common/crypto_impl/x509');
import pkijs = require('pkijs');
import stsCrypto = require('../common/crypto');
import pqcSupport = require('../common/pqc_support');
import cacheRegistry = require('../common/cache_registry');
import InstanceSlot = require('../common/instance_slot');
import certificateBinding = require('../common/certificate_binding');

// WHAT `inspectView()` TAKES AT MOST (#2080): a pasted bundle is an
// administrator's own, but a megabyte of text would hold a request worker
// parsing it. A federal bridge bundle is a few dozen certificates.
const INSPECT_MAX_CHARS = 262144;
const INSPECT_MAX_CERTIFICATES = 64;
const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

// The pages a details view is drawn on. The route that draws one passes its
// own path to the renderer, so this list decides nothing at request time; it
// is what the management API's description and the test read, so a third
// page added without being listed here is a page nothing checks.
/**
 * The console pages a certificate details view is drawn on.
 */
const PAGES = ['/admin/pki', '/admin/crypto-metadata'];

interface CertificateViewsDeps {
  log: typeof log;
  // THE LAZY REQUIRES (see the header), as functions the instance calls
  // when a view is drawn rather than when it is built: each is a cache hit by
  // then, and none of the first three may be loaded from here at 18a. The
  // fourth, the cluster membership, is a library that registers nothing; it
  // is a loader so that a test can hand in another node's leaf.
  loadTlsServer: () => any;
  loadSpiffeCa: () => any;
  loadAdminViews: () => any;
  // The cluster membership (`cluster/cluster.js`): the OTHER nodes' listener
  // certificates, off their heartbeats (see `otherNodesListeners()`).
  loadCluster: () => any;
  details: typeof details;
  errorCodes: typeof errorCodes;
  pki: typeof pki;
  realms: typeof realms;
  applications: typeof applications;
  personAssertions: typeof personAssertions;
  helpers: typeof helpers;
  x509: typeof x509;
  pkijs: typeof pkijs;
  // Which key a certificate carries, for `pqcOf()` (#352).
  pqcSupport: typeof pqcSupport;
}

// ---------------------------------------------------------------------------
// WHAT A LIST SHOWS ABOUT A CERTIFICATE, PARSED ONCE (#352, 2026-09-29).
//
// `listView()` parsed EVERY certificate in the catalogue with pkijs on every
// request — the subject, the issuer and the notAfter of each — and then
// filtered and sliced; `/admin/pki` asked `pqc_support.of()` for every
// holder's certificate, which is another pkijs parse, on every view. A
// realm's holders are the part of the catalogue that grows, and a parse per
// holder per page view is the cost #352 was filed about.
//
// **THE LIST NOW PAGES FIRST AND PARSES THE SLICE**, and what a parse finds
// is kept here so that a filter — which has to read the subject and issuer of
// every certificate it is asked about — pays for each certificate once rather
// than once per request. Two kinds of fact, one map:
//
//   * `fp:<fingerprint>` — `{ subject, issuer, notAfter }`, keyed by the
//     SHA-256 of the DER, which the catalogue computes anyway.
//   * `pqc:<sha-256 of the PEM text>` — `pqc_support.of()`'s answer, keyed by
//     the text it reads (it reads the first block of it), so no parse is
//     needed to find the key.
//
// **CONTENT-KEYED, SO IT IS NEVER WRONG**, in this process or any other: a
// certificate's subject and key do not change, and a reissued certificate is
// a different key. That is also why it needs no version and no invalidation;
// a request worker holding facts about a certificate another process has
// since taken off an entry holds facts nothing asks for, until they are the
// oldest and go. Bounded (4,096, the oldest dropped) and described to
// `/admin/caches` (rule 3ap).
// ---------------------------------------------------------------------------
const FACTS_LIMIT = 4096;
const facts = new Map<string, any>();

const factsCount = cacheRegistry.register({
  name: 'certificates.parsed-facts',
  title: 'Parsed certificate facts',
  description: 'The subject, issuer and notAfter a certificate list shows, ' +
    'and whether a certificate carries a post-quantum key, parsed once per ' +
    'certificate for /admin/pki and GET /admin-api/certificates. Keyed by ' +
    'the certificate\'s own SHA-256.',
  owner: 'admin-core/certificate_views.ts',
  scope: 'process',
  maxEntries: function () {
    return FACTS_LIMIT;
  },
  bound: 'Enforced: 4,096 certificates, the oldest dropped and parsed ' +
    'again when next shown.',
  lifetime: function () {
    return 'No expiry: keyed by the certificate\'s content, whose facts ' +
      'never change. The oldest goes first when full.';
  },
  entries: function () {
    const out = [];
    facts.forEach(function (_value, key) {
      out.push({ key: key.slice(0, 24) + '…', validUntil: null,
                 basis: 'content-keyed' });
    });
    return out;
  }
});

/**
 * Which certificates a details view may show, and the two views both admin
 * surfaces draw: the realm's certificate list and one certificate with its
 * chain.
 *
 * A certificate is named by its SHA-256 and looked up in the catalogue of what
 * this service holds; any other fingerprint is refused.
 */
class CertificateViews {
  /**
   * Builds the views over their dependencies.
   *
   * @param deps - the logger, lazy loaders for the TLS server, the SPIFFE CA
   *   and the admin views, the certificate describer, error codes, and the PKI,
   *   realm, application and person-assertion modules
   */
  constructor(private readonly deps: CertificateViewsDeps) {
    deps.log.debug("Entering CertificateViews.constructor().");
    deps.log.debug("Leaving CertificateViews.constructor().");
  }

  // What the composition root passes, from the real modules, with the three
  // lazy requires as loaders (see the header).
  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): CertificateViewsDeps {
    log.debug("Entering CertificateViews.defaultDeps().");
    log.debug("Leaving CertificateViews.defaultDeps().");
    return {
      log: log,
      loadTlsServer: function () {
        return require('../tls/tls_server');
      },
      loadSpiffeCa: function () {
        return require('../spiffe/spiffe_ca');
      },
      loadAdminViews: function () {
        return require('./admin_views');
      },
      loadCluster: function () {
        return require('../cluster/cluster');
      },
      details: details,
      errorCodes: errorCodes,
      pki: pki,
      realms: realms,
      applications: applications,
      personAssertions: personAssertions,
      helpers: helpers,
      x509: x509,
      pkijs: pkijs,
      pqcSupport: pqcSupport
    };
  }

  private scopeOfRealm() {
    const { log, realms } = this.deps;
    log.debug("Entering CertificateViews.scopeOfRealm().");
    const id = String(realms.currentId ? realms.currentId() : '');
    log.debug("Leaving CertificateViews.scopeOfRealm().");
    return id === realms.DEFAULT_ID ? '' : id;
  }

  // A catalogue under construction: one entry per certificate, however many
  // places hold it — the Root is in the tree and in every SPIFFE bundle, and
  // the RS256 JOSE certificate is on the key set and in the tree — with every
  // place recorded, because *where does this certificate appear here* is half
  // of what a reader opens it to find out.
  private newCatalogue() {
    const { log, details } = this.deps;
    log.debug("Entering CertificateViews.newCatalogue().");
    const byFingerprint: Record<string, any> = {};
    const order = [];
    log.debug("Leaving CertificateViews.newCatalogue().");
    return {
      add: function (pem, label, where, chainHint) {
        log.debug("Entering add(). " + label);
        if (!pem || String(pem).indexOf('BEGIN CERTIFICATE') < 0) {
          log.debug("Leaving add(). Not a certificate.");
          return;
        }
        let fp;
        try {
          fp = details.fingerprintOf(pem);
        } catch (e) {
          log.debug("Caught in add(): " + ((e && e.message) || e));
          log.debug("Leaving add(). Unreadable.");
          return;
        }
        if (!byFingerprint[fp]) {
          byFingerprint[fp] = { fingerprint: fp, pem: String(pem),
                                appearances: [], chainHint: [] };
          order.push(fp);
        }
        const entry = byFingerprint[fp];
        const already = entry.appearances.some(function (one) {
          return one.label === label && one.where === where;
        });
        if (!already) {
          entry.appearances.push({ label: label, where: where });
        }
        (chainHint || []).forEach(function (one) {
          if (one && entry.chainHint.indexOf(one) < 0) {
            entry.chainHint.push(one);
          }
        });
        log.debug("Leaving add().");
      },
      get: function (fp) {
        log.debug("Entering get().");
        log.debug("Leaving get().");
        return byFingerprint[fp] || null;
      },
      entries: function () {
        log.debug("Entering entries().");
        log.debug("Leaving entries().");
        return order.map(function (fp) { return byFingerprint[fp]; });
      }
    };
  }

  // One source, contained: a source that throws costs its own rows and never
  // the catalogue, because a details view that failed for every certificate
  // because SPIFFE was not started would be a page broken by a family it is not
  // about.
  private fromSource(name, fn) {
    const { log } = this.deps;
    log.debug("Entering CertificateViews.fromSource(). " + name);
    try {
      fn();
    } catch (e) {
      log.debug("Caught in fromSource(" + name + "): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving CertificateViews.fromSource().");
  }

  // ---------------------------------------------------------------------------
  // THE AUTHORITY SOURCES. Cheap, in memory, and the candidates a chain is
  // built over.
  // ---------------------------------------------------------------------------
  private addAuthorities(catalogue) {
    const { log, pki, realms, helpers, loadTlsServer,
      loadSpiffeCa } = this.deps;
    log.debug("Entering CertificateViews.addAuthorities().");
    const scope = this.scopeOfRealm();
    const realmName = scope || realms.DEFAULT_ID;

    this.fromSource('pki tree', function () {
      const tree = pki.describeTree([scope]);
      if (tree.root) {
        catalogue.add(tree.root.certificatePem, 'Service Root CA', 'pki');
      }
      (tree.scopes || []).forEach(function (one) {
        const branch = one.kind === 'process' ? 'process'
                                              : 'realm ' + realmName;
        if (one.intermediate) {
          catalogue.add(one.intermediate.certificatePem,
                        'Intermediate CA (' + branch + ')', 'pki');
        }
        (one.issuing || []).forEach(function (uc) {
          if (uc.ca) {
            catalogue.add(uc.ca.certificatePem,
                          uc.label + ' Issuing CA (' + branch + ')', 'pki');
          }
          (uc.certified || []).forEach(function (cert) {
            catalogue.add(cert.certificatePem,
                          cert.label + ' (certified by the ' + uc.label +
                          ' Issuing CA)', 'pki', cert.chainPem || []);
          });
        });
      });
    });

    this.fromSource('workbench store', function () {
      pki.objects(scope).forEach(function (one) {
        catalogue.add(one.certificatePem,
                      'Workbench ' + (one.ca ? 'CA' : 'certificate') + ' — ' +
                      (one.subject || one.id), 'pki');
      });
    });

    this.fromSource('signing keys', function () {
      const keys = helpers.stsKeysFor();
      catalogue.add(keys.certPem, 'Signing key (RS256), published certificate',
                    'keys', keys.certChainPem || []);
      if (keys.selfSignedCertPem && keys.selfSignedCertPem !== keys.certPem) {
        catalogue.add(keys.selfSignedCertPem,
                      'Signing key (RS256), the self-signed certificate it ' +
                      'was generated with', 'keys');
      }
    });

    this.fromSource('tls listeners', function () {
      // LAZILY — see the header.
      const tls = loadTlsServer();
      const chains = typeof tls.serverCertificateChains === 'function'
        ? tls.serverCertificateChains()
        : [{ algorithm: 'rsa', certPem: tls.serverCertificate().certPem,
             chainPem: tls.serverCertificate().chainPem || [] }];
      chains.forEach(function (one) {
        catalogue.add(one.certPem, 'TLS listener certificate (' +
                      one.algorithm + ')', 'tls', one.chainPem || []);
        (one.chainPem || []).forEach(function (pem) {
          catalogue.add(pem, 'TLS listener certificate chain', 'tls');
        });
      });
    });

    this.fromSource('other cluster nodes', () => {
      this.addOtherNodesListeners(catalogue);
    });

    this.fromSource('spiffe', function () {
      // LAZILY — see the header.
      const state = loadSpiffeCa().state();
      (state.x509Authorities || []).forEach(function (one) {
        catalogue.add(one.certificatePem,
                      'SPIFFE X.509 authority' + (one.active ? '' :
                                                  ' (retired)'),
                      'spiffe');
      });
      (state.trustAnchors || []).forEach(function (one) {
        catalogue.add(one.certificatePem, 'SPIFFE trust anchor', 'spiffe');
      });
      if (state.root && state.root.certificatePem) {
        catalogue.add(state.root.certificatePem, 'SPIFFE bundle root',
                      'spiffe');
      }
    });
    log.debug("Leaving CertificateViews.addAuthorities().");
  }

  // ---------------------------------------------------------------------------
  // EVERY OTHER NODE'S LISTENER CERTIFICATE (2026-11-24, GitHub Actions run
  // 45326782254's `cluster` mode, `sts_admin_console`).
  //
  // A cluster node presents a listener leaf of its OWN, over its own key,
  // under the TLS Issuing CA the cluster shares (`tls/CLAUDE.md`), and the
  // source above reads only THIS process's. So `/admin/crypto-metadata`
  // drawn by node A linked A's leaf, the browser's next connection was
  // balanced to node B, and B answered the details view 404, STS-ADMIN-0641
  // — "not held here", of a certificate this service was presenting on its
  // main port at that moment. Not a replication lag: B never holds A's
  // listener row, by decision (the row carries A's private key,
  // `tls_server.js`'s `listenerKeys`), so no wait would have found it.
  //
  // The public half already crosses: each node publishes its leaves on its
  // membership row (#248, for the SAML metadata), and
  // `listenerCertificatesOfLiveNodes()` reads them out of the last state
  // read. They are added here as authorities — a leaf this service presents
  // is what a reader opens a details view to see, and its chain is the one
  // the shared TLS Issuing CA already completes. A node that has left, or
  // whose heartbeat lapsed, presents nothing a balancer sends traffic to and
  // is not listed. Without a cluster the list is empty and nothing changes.
  // ---------------------------------------------------------------------------
  private addOtherNodesListeners(catalogue) {
    const { log, details, loadCluster } = this.deps;
    log.debug("Entering CertificateViews.addOtherNodesListeners().");
    const cluster = loadCluster();
    if (!cluster || typeof cluster.listenerCertificatesOfLiveNodes !==
        'function') {
      log.debug("Leaving CertificateViews.addOtherNodesListeners(). No " +
                "cluster module.");
      return;
    }
    let added = 0;
    (cluster.listenerCertificatesOfLiveNodes() || []).forEach(function (b64) {
      const body = String(b64 || '').replace(/\s+/g, '');
      if (!body) {
        return;
      }
      const pem = '-----BEGIN CERTIFICATE-----\n' +
        (body.match(/.{1,64}/g) || []).join('\n') +
        '\n-----END CERTIFICATE-----\n';
      let fp = '';
      try {
        fp = details.fingerprintOf(pem);
      } catch (e) {
        log.debug("Caught in CertificateViews.addOtherNodesListeners(): " +
                  ((e && e.message) || e));
        return;
      }
      // THIS NODE'S OWN LEAF IS ON THE LIST TOO, once its row has been read,
      // and the source above has already said where it appears.
      if (catalogue.get(fp)) {
        return;
      }
      catalogue.add(pem, 'TLS listener certificate (another cluster node)',
                    'tls');
      added += 1;
    });
    log.debug("Leaving CertificateViews.addOtherNodesListeners(). " + added +
              ".");
  }

  // ---------------------------------------------------------------------------
  // A MISS READS THE MEMBERSHIP AGAIN BEFORE IT IS A 404 (2026-11-24). The
  // list above is the last membership state THIS process read, which a
  // request worker may not have read at all yet, or read before the other
  // node re-issued its leaf (a Root rebuilt, `tls/CLAUDE.md`). So a
  // fingerprint nothing here holds waits for one read of the membership
  // rows, through to the store — `cluster.refreshState()`, the read
  // `snapshot()` starts by itself — and is looked up once more. A keyed,
  // bounded read on the refusal path only; no cluster, no read.
  // ---------------------------------------------------------------------------
  private async refreshedMembership(): Promise<boolean> {
    const { log, loadCluster } = this.deps;
    log.debug("Entering CertificateViews.refreshedMembership().");
    let cluster = null;
    try {
      cluster = loadCluster();
    } catch (e) {
      log.debug("Caught in CertificateViews.refreshedMembership(): " +
                ((e && e.message) || e));
      cluster = null;
    }
    if (!cluster || typeof cluster.enabled !== 'function' ||
        !cluster.enabled() || typeof cluster.refreshState !== 'function') {
      log.debug("Leaving CertificateViews.refreshedMembership(). No " +
                "cluster.");
      return false;
    }
    try {
      await cluster.refreshState();
    } catch (e) {
      // `refreshState()` resolves the last state on a failed read; a throw
      // here leaves the refusal as it was, which is what it would have been.
      log.debug("Caught in CertificateViews.refreshedMembership(): " +
                ((e && e.message) || e));
      log.debug("Leaving CertificateViews.refreshedMembership(). Unread.");
      return false;
    }
    log.debug("Leaving CertificateViews.refreshedMembership(). Read.");
    return true;
  }

  // ---------------------------------------------------------------------------
  // THE HOLDER SOURCES. They walk the directory, so they are read only when a
  // fingerprint was not an authority's, or for the full list.
  // ---------------------------------------------------------------------------
  private addHolders(catalogue) {
    const { log, details, applications, personAssertions } = this.deps;
    log.debug("Entering CertificateViews.addHolders().");
    this.fromSource('applications', function () {
      const kinds = applications.KEY_PAIR_ATTRIBUTES || {};
      applications.list().forEach(function (one) {
        const fields = one.fields || {};
        Object.keys(kinds).forEach(function (purpose) {
          const attrs = kinds[purpose];
          const pem = fields[attrs.certificate];
          if (!pem) {
            return;
          }
          catalogue.add(String(pem), 'Application "' + one.identifier + '", ' +
                        (purpose === 'saml' ? 'RFC 7522' : 'RFC 7523') +
                        ' key pair', 'applications',
                        details.splitPem(fields[attrs.chain]));
        });
      });
    });
    this.fromSource('persons', function () {
      // EVERY KEY PAIR A PERSON HOLDS, per profile (#1290): several each,
      // revoked and expired ones included — a certificate this service
      // issued is in the catalogue whatever became of it.
      personAssertions.holders().forEach(function (one) {
        [['jwt', 'RFC 7523'], ['saml', 'RFC 7522']].forEach(function (p) {
          ((one[p[0]] || {}).keys || []).forEach(function (key) {
            if (!key.certificatePem) {
              return;
            }
            catalogue.add(key.certificatePem, 'Person "' + one.username +
                          '", ' + p[1] + ' key pair' +
                          (key.label ? ' "' + key.label + '"' : ''),
                          'persons', details.splitPem(key.chainPem));
          });
        });
      });
    });
    log.debug("Leaving CertificateViews.addHolders().");
  }

  // What a self-signed certificate at the top of a chain IS to this service.
  private anchorsOf(catalogue) {
    const { log, details, pki } = this.deps;
    log.debug("Entering CertificateViews.anchorsOf().");
    const out: Record<string, any> = {};
    const root = pki.serviceRoot ? pki.serviceRoot() : null;
    if (root && root.certificatePem) {
      out[details.fingerprintOf(root.certificatePem)] =
        'this service\'s Root CA';
    }
    catalogue.entries().forEach(function (entry) {
      if (out[entry.fingerprint]) {
        return;
      }
      const spiffe = entry.appearances.some(function (one) {
        return one.where === 'spiffe' && /anchor|root/i.test(one.label);
      });
      if (spiffe) {
        out[entry.fingerprint] = 'a SPIFFE trust anchor this service publishes';
      }
    });
    log.debug("Leaving CertificateViews.anchorsOf().");
    return out;
  }

  // A fingerprint as a person may type or copy it: colons and spaces allowed,
  // case ignored. Anything else is not a SHA-256 and is refused before the
  // catalogue is built.
  /**
   * Normalises a fingerprint as a person may type it: colons and spaces
   * allowed, case ignored.
   *
   * @param text - the fingerprint
   * @returns 64 lower-case hex digits, or '' when it is not a SHA-256
   */
  normalFingerprint(text) {
    const { log } = this.deps;
    log.debug("Entering CertificateViews.normalFingerprint().");
    const hex = String(text || '').replace(/[:\s]/g, '').toLowerCase();
    log.debug("Leaving CertificateViews.normalFingerprint().");
    return /^[0-9a-f]{64}$/.test(hex) ? hex : '';
  }

  private refusal(code, sentence) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering CertificateViews.refusal().");
    log.debug("Leaving CertificateViews.refusal().");
    return errorCodes.mark({ ok: false, errors: [sentence] }, code);
  }

  // ---------------------------------------------------------------------------
  // ONE CERTIFICATE, WITH ITS CHAIN. Resolves to the details model, or to a
  // refusal naming why; never throws for anything a request can cause.
  // ---------------------------------------------------------------------------
  /**
   * Describes one certificate from the catalogue, with its chain.
   *
   * @param req - the request, whose `certificate` query names the fingerprint
   * @param fingerprintText - the fingerprint, instead of the query
   * @returns the details model, or a coded refusal naming why; never throws for
   *   anything a request can cause
   */
  async detailsView(req, fingerprintText?) {
    const { log, details, errorCodes, realms } = this.deps;
    log.debug("Entering CertificateViews.detailsView().");
    const asked = fingerprintText !== undefined ? fingerprintText
      : (req && req.query ? req.query.certificate : '');
    const fp = this.normalFingerprint(asked);
    if (!fp) {
      log.debug("Leaving CertificateViews.detailsView(). Not a fingerprint.");
      return this.refusal('STS-ADMIN-0640',
        '"' + String(asked || '').slice(0, 80) + '" is not a SHA-256 ' +
        'certificate fingerprint. It is 64 hexadecimal digits, with or ' +
        'without colons — the value /admin/pki prints in its SHA-256 column.');
    }
    let catalogue = this.newCatalogue();
    this.addAuthorities(catalogue);
    let entry = catalogue.get(fp);
    if (!entry) {
      this.addHolders(catalogue);
      entry = catalogue.get(fp);
    }
    if (!entry && await this.refreshedMembership()) {
      // Another node's listener leaf, read off the membership just read —
      // see `refreshedMembership()`. The catalogue is built again, so the
      // chain below is built over what is current.
      catalogue = this.newCatalogue();
      this.addAuthorities(catalogue);
      entry = catalogue.get(fp);
    }
    if (!entry) {
      log.debug("Leaving CertificateViews.detailsView(). Not held here.");
      return this.refusal('STS-ADMIN-0641',
        'No certificate with the SHA-256 fingerprint ' + fp + ' is held in ' +
        'the "' + (this.scopeOfRealm() || realms.DEFAULT_ID) + '" realm. A ' +
        'details view shows only what this service holds — the certificate ' +
        'authority tree, the signing keys, the TLS listeners, the SPIFFE ' +
        'authorities and ' +
        'the key pairs issued to applications and people in this realm — and ' +
        'a ' +
        'certificate from another realm is opened under that realm\'s ' +
        'prefix. A certificate that was reissued has a new fingerprint.');
    }
    const candidates = catalogue.entries().filter(function (one) {
      return one.appearances.some(function (a) {
        return a.where !== 'applications' && a.where !== 'persons';
      });
    }).map(function (one) {
      return one.pem;
    }).concat(entry.chainHint);
    let model;
    try {
      model = await details.detailsFor(entry.pem, candidates,
                                       { anchors: this.anchorsOf(catalogue) });
    } catch (e) {
      log.error(errorCodes.tag('STS-ADMIN-0642') + 'certificate_views: the ' +
                'certificate ' + fp + ' could not be described: ' + e.message);
      log.debug("Leaving CertificateViews.detailsView(). The description " +
                "failed.");
      return this.refusal('STS-ADMIN-0642',
        'The certificate ' + fp + ' is held here and could not be described: ' +
        e.message);
    }
    log.debug("Leaving CertificateViews.detailsView(). " + model.chain.length +
              " link(s).");
    // The key's post-quantum classification (#446), which the dialog's icon
    // is drawn from: a renderer in a browser parses no certificate.
    return Object.assign({ ok: true,
                           realm: this.scopeOfRealm() || realms.DEFAULT_ID,
                           appearances: entry.appearances.slice(),
                           pqc: this.pqcOf(model.certificate &&
                                           model.certificate.pem) || null },
                         model);
  }

  // ---------------------------------------------------------------------------
  // EVERY CERTIFICATE THIS REALM HOLDS, as a list a caller walks to find the
  // fingerprint it wants. Paged the way every list on `/admin-api` is, and
  // filterable by `q` over the subject, the issuer and where it appears.
  // ---------------------------------------------------------------------------
  /**
   * Lists every certificate this realm holds, paged and filterable by `q` over
   * the subject, the issuer and where it appears.
   *
   * @param req - the request, with the paging and filter query
   * @returns the page of rows and its paging
   */
  listView(req) {
    const { log, realms, loadAdminViews } = this.deps;
    const self = this;
    log.debug("Entering CertificateViews.listView().");
    const query = (req && req.query) || {};
    const catalogue = this.newCatalogue();
    this.addAuthorities(catalogue);
    this.addHolders(catalogue);
    const needle = String(query.q || '').toLowerCase();
    // **PAGE, THEN PARSE (#352).** The catalogue is in the order its sources
    // were read and nothing sorts it, so without `q` the page is a slice of
    // it and only the slice is parsed. With `q` every certificate has to be
    // asked, and it is asked the cheap question first — where it appears,
    // which is text already in hand — and parsed (once per certificate per
    // process, `facts` above) only when that does not match.
    const entries = catalogue.entries().filter(function (entry) {
      if (!needle) {
        return true;
      }
      const labels = entry.appearances.map(function (a) {
        return a.label;
      }).join(' ');
      if (labels.toLowerCase().indexOf(needle) >= 0) {
        return true;
      }
      // The same haystack the list always searched, so a needle spanning the
      // issuer and the first label still matches: the test above is only
      // the part of it that needs no parse.
      const known = self.factsOf(entry);
      return (known.subject + ' ' + known.issuer + ' ' + labels)
        .toLowerCase().indexOf(needle) >= 0;
    });
    // Lazily, for the load-order reason in the header: `admin_views.ts`
    // requires route-registering modules and this file is required at 18a.
    const pg = loadAdminViews().pagingOf(query, entries.length);
    const out = {
      realm: this.scopeOfRealm() || realms.DEFAULT_ID,
      total: catalogue.entries().length,
      matched: entries.length,
      page: pg.page,
      pages: pg.pages,
      perPage: pg.perPage,
      firstRow: pg.firstRow,
      lastRow: pg.lastRow,
      certificates: entries.slice(pg.offset, pg.offset + pg.perPage)
        .map(function (entry) {
          const known = self.factsOf(entry);
          return {
            fingerprint: entry.fingerprint,
            subject: known.subject,
            issuer: known.issuer,
            notAfter: known.notAfter,
            selfIssued: !!known.subject && known.subject === known.issuer,
            appearances: entry.appearances.slice()
          };
        })
    };
    log.debug("Leaving CertificateViews.listView(). " + out.matched +
              " certificate(s).");
    return out;
  }

  // What a list row shows about one catalogue entry, parsed at most once per
  // certificate (`facts` above). A certificate that does not parse shows
  // empty strings, as it always did, and that answer is kept too.
  private factsOf(entry) {
    const { log, x509, pkijs } = this.deps;
    log.debug("Entering CertificateViews.factsOf().");
    const key = 'fp:' + entry.fingerprint;
    const held = facts.get(key);
    if (held) {
      factsCount.hit();
      log.debug("Leaving CertificateViews.factsOf(). Held.");
      return held;
    }
    factsCount.miss();
    const known = { subject: '', issuer: '', notAfter: '' };
    try {
      const der = Buffer.from(entry.pem.replace(/-----[^-]+-----/g, '')
        .replace(/\s+/g, ''), 'base64');
      const cert = pkijs.Certificate.fromBER(new Uint8Array(der));
      known.subject = x509.dnToString(cert.subject);
      known.issuer = x509.dnToString(cert.issuer);
      known.notAfter = cert.notAfter.value.toISOString();
    } catch (e) {
      log.debug("Caught in CertificateViews.factsOf(): " + ((e &&
          e.message) || e));
    }
    CertificateViews.remember(key, known);
    log.debug("Leaving CertificateViews.factsOf(). Parsed.");
    return known;
  }

  // Hot path for a page of holders: no Entering/Leaving pair beyond the
  // parse itself would add anything but two lines per row.
  private static remember(key: string, value: any) {
    cacheRegistry.makeRoom(facts, FACTS_LIMIT, { counter: factsCount });
    facts.set(key, value);
  }

  // -------------------------------------------------------------------------
  // A CERTIFICATE THE ADMINISTRATOR HANDS IN, DESCRIBED (#2080).
  //
  // The console's form helper for certificate sign-in
  // (`POST /admin-api/console/certificates/inspect`): the profile editor's
  // "add an issuer from its certificate", the PEM lists of
  // `piv.externalIssuers` and `piv.attestationAnchors`, and a person's
  // binding editor all need what a certificate SAYS — its subject, its
  // SHA-256, its SubjectPublicKeyInfo's SHA-256, its serial and key
  // identifier — and a browser must not compute a digest of its own
  // (`common/crypto.js` is the one place this service hashes).
  //
  // **THIS IS THE ONE VIEW HERE THAT DESCRIBES WHAT IT IS HANDED**, and the
  // header's reason for looking up rather than parsing does not reach it:
  // that reason is a LINK — a GET anybody can be sent, drawing an attacker's
  // certificate under this console's header. This is a POST with the
  // administrator's own token and their own text, answered as JSON to the
  // page that sent it and drawn nowhere else; it writes nothing and keeps
  // nothing, so what comes back is what they pasted, read.
  //
  // A PERSON'S BINDINGS (`bindings: true`): the values the high-affinity
  // methods of `common/certificate_binding.ts` look the FIRST certificate up
  // by, in `bindingValueOf()`'s grammar — `spki-sha256` from the leaf alone,
  // and `issuer-serial` and `issuer-ski` from its issuer, found among the
  // other certificates handed in or in the client truststore by the one
  // whose key verifies the leaf's signature (`crypto.certificateSignedWith()`,
  // as `signedPath()` links a chain). No issuer found is said, and the two
  // issuer-scoped values are left out rather than guessed.
  // -------------------------------------------------------------------------
  /**
   * Describes the certificates in a PEM text, and optionally the binding
   * values of the first.
   *
   * @param body - `{ pem, bindings }`
   * @returns `{ ok, errors, certificates, issuer, bindings }`, a refusal
   *   marked with its code
   */
  inspectView(body) {
    const { log, loadTlsServer, errorCodes: codes } = this.deps;
    log.debug("Entering CertificateViews.inspectView().");
    const text = String((body && body.pem) || '');
    // The code is MARKED on the answer, never a member of it: it is
    // recorded on the request's row and never sent (root CLAUDE.md).
    const refused = function (code, message) {
      log.debug("Leaving CertificateViews.inspectView(). Refused.");
      return codes.mark({ ok: false, errors: [message], certificates: [],
                          issuer: null, bindings: [] }, code);
    };
    if (text.length > INSPECT_MAX_CHARS) {
      return refused('STS-ADMIN-0953', 'The text is longer than ' +
                     INSPECT_MAX_CHARS + ' characters.');
    }
    const blocks = text.match(PEM_BLOCK) || [];
    if (!blocks.length) {
      return refused('STS-ADMIN-0953', 'The text holds no PEM certificate ' +
                     '(-----BEGIN CERTIFICATE-----).');
    }
    if (blocks.length > INSPECT_MAX_CERTIFICATES) {
      return refused('STS-ADMIN-0953', 'The text holds ' + blocks.length +
                     ' certificates, more than ' + INSPECT_MAX_CERTIFICATES +
                     '.');
    }
    const parsed = [];
    for (let i = 0; i < blocks.length; i++) {
      try {
        const cert = stsCrypto.parseCertificate(blocks[i]);
        parsed.push({ pem: blocks[i], cert: cert,
                      facts: stsCrypto.certificateFacts(cert) });
      } catch (e) {
        log.debug("Caught in CertificateViews.inspectView(): " +
                  ((e && e.message) || e));
        return refused('STS-ADMIN-0954', 'Certificate ' + (i + 1) +
                       ' could not be read: ' + ((e && e.message) || e) +
                       '.');
      }
    }
    const shown = parsed.map(function (one) {
      const f = one.facts;
      const uuids = ((f.san && f.san.uri) || []).filter(function (u) {
        return /^urn:uuid:/i.test(String(u));
      });
      return {
        pem: one.pem,
        subject: String(f.subject || ''),
        issuer: String(f.issuer || ''),
        serialHex: String(f.serialHex || ''),
        notBefore: new Date(f.notBefore).toISOString(),
        notAfter: new Date(f.notAfter).toISOString(),
        ca: !!f.ca,
        selfIssued: !!f.selfIssued,
        fingerprint256: String(f.fingerprint256 || ''),
        sha256: stsCrypto.digest('sha256', one.cert.raw, 'hex'),
        spkiSha256: String(f.spkiSha256 || ''),
        ski: String(f.ski || ''),
        keyUsage: Array.isArray(f.keyUsage) ? f.keyUsage.slice(0) : [],
        extendedKeyUsage: Array.isArray(f.eku) ? f.eku.slice(0) : [],
        cardUuids: uuids.map(String)
      };
    });
    let issuer = null;
    const values = [];
    if (body && body.bindings === true) {
      const leaf = parsed[0];
      const candidates = parsed.slice(1).map(function (one) {
        return { pem: one.pem, from: 'bundle' };
      });
      try {
        const tls = loadTlsServer();
        const anchors = (tls && tls.truststore && tls.truststore.list)
          ? (tls.truststore.list().anchors || []) : [];
        anchors.forEach(function (row) {
          if (row && row.pem) {
            candidates.push({ pem: String(row.pem), from: 'truststore' });
          }
        });
      } catch (e) {
        // No truststore in this process: the bundle's own certificates are
        // the only candidates, and the answer says no issuer was found.
        log.debug("Caught in CertificateViews.inspectView(): " +
                  ((e && e.message) || e));
      }
      for (let i = 0; i < candidates.length && !issuer; i++) {
        try {
          const above = stsCrypto.parseCertificate(candidates[i].pem);
          if (stsCrypto.certificateSignedWith(leaf.cert, above.publicKey) ===
              true) {
            const facts = stsCrypto.certificateFacts(above);
            issuer = { subject: String(facts.subject || ''),
                       spkiSha256: String(facts.spkiSha256 || ''),
                       from: candidates[i].from };
          }
        } catch (e) {
          // A candidate whose key cannot verify this signature is not its
          // issuer; the next one is asked.
          log.debug("Caught in CertificateViews.inspectView(): " +
                    ((e && e.message) || e));
        }
      }
      const add = function (method, raw) {
        const value = certificateBinding.bindingValueOf(raw);
        if (value) {
          values.push({ method: method, value: value });
        }
      };
      const f = leaf.facts;
      if (f.spkiSha256) {
        add('spki-sha256', 'spki-sha256:' + f.spkiSha256);
      }
      if (issuer && issuer.spkiSha256 && f.serialHex) {
        add('issuer-serial', 'issuer-serial:' + issuer.spkiSha256 + ':' +
            f.serialHex);
      }
      if (issuer && issuer.spkiSha256 && f.ski) {
        add('issuer-ski', 'issuer-ski:' + issuer.spkiSha256 + ':' + f.ski);
      }
    }
    log.debug("Leaving CertificateViews.inspectView(). " + shown.length +
              " certificate(s).");
    return { ok: true, errors: [], certificates: shown,
             issuer: issuer, bindings: values };
  }

  // ---------------------------------------------------------------------------
  // WHETHER A CERTIFICATE CARRIES A POST-QUANTUM KEY, `pqc_support.of()`'s
  // answer for `{ certificatePem }`, parsed once per certificate text (#352).
  // `/admin/pki` asks it of every row it DRAWS — and of every row of the
  // whole list when the JSON is asked for, which is where the memo pays.
  // Nothing to read is answered without a lookup, exactly as `of()` would.
  // ---------------------------------------------------------------------------
  /**
   * Describes the key a certificate carries, as `pqc_support.of()` does for
   * `{ certificatePem }`, remembering the answer per certificate.
   *
   * @param pem - a PEM certificate, or nothing
   * @returns the answer, or null for a classical key or no certificate
   */
  pqcOf(pem) {
    const { log, pqcSupport } = this.deps;
    log.debug("Entering CertificateViews.pqcOf().");
    if (!pem) {
      log.debug("Leaving CertificateViews.pqcOf(). No certificate.");
      return pqcSupport.of({ certificatePem: pem });
    }
    const key = 'pqc:' + stsCrypto.digest('sha256', String(pem), 'hex');
    if (facts.has(key)) {
      factsCount.hit();
      log.debug("Leaving CertificateViews.pqcOf(). Held.");
      return facts.get(key);
    }
    factsCount.miss();
    const answer = pqcSupport.of({ certificatePem: pem });
    CertificateViews.remember(key, answer);
    log.debug("Leaving CertificateViews.pqcOf(). Parsed.");
    return answer;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<CertificateViews>(
  'admin-core/certificate_views',
  () => new CertificateViews(CertificateViews.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Which certificates a details view may show, and the views both admin surfaces
 * read (`/admin/pki`, `/admin/crypto-metadata`, `GET /admin-api/certificates`).
 * @namespace
 */
export = {
  CertificateViews: CertificateViews,
  PAGES: PAGES,
  installInstance: (instance: CertificateViews): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  normalFingerprint: slot.forward('normalFingerprint'),
  detailsView: slot.forward('detailsView'),
  listView: slot.forward('listView'),
  pqcOf: slot.forward('pqcOf'),
  inspectView: slot.forward('inspectView'),
  // For the #352 test: how many parsed facts are held, and a way to forget
  // them so a count starts from nothing.
  factsHeld: (): number => facts.size,
  forgetFacts: (): void => facts.clear()
};
