'use strict';
//
// File: certificate_views.ts
//
// ===========================================================================
// WHICH CERTIFICATES A DETAILS VIEW MAY SHOW, AND THE VIEW ITSELF (2026-09-13).
//
// `common/certificate_details.js` describes a certificate it is handed. This
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
// rule 1: `admin-ui/pki_admin.js` requires this file at 18a and the TLS module
// registers its routes at 20, so a require at the top would move `/tls*` ahead
// of the management API. A request handler runs after every module has loaded,
// so inside a function the require is a cache hit — `request_pool.js`'s
// `reconcileTheListener()` makes the same argument.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `CertificateViews` takes this file's logger, the certificate
// describer, the error codes, `pki`, `realms`, both registries of key pairs,
// `helpers`, the X.509 encoder and `pkijs` through its constructor — and the
// three LAZY requires as loader functions, called where the requires were.
// The module still exports `PAGES` and its three functions from a
// TRANSITIONAL instance at the bottom, for `admin-ui/pki_admin.js`,
// `admin-ui/crypto_metadata.js`, `mgmt-api/admin_api.js` and the test;
// `CertificateViews` is exported beside them for the composition root.
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
import x509 = require('../common/vendored/x509');
import pkijs = require('pkijs');

// The pages a details view is drawn on. The route that draws one passes its
// own path to the renderer, so this list decides nothing at request time; it
// is what the management API's description and the test read, so a third
// page added without being listed here is a page nothing checks.
const PAGES = ['/admin/pki', '/admin/crypto-metadata'];

interface CertificateViewsDeps {
  log: typeof log;
  // THE THREE LAZY REQUIRES (see the header), as functions the instance calls
  // when a view is drawn rather than when it is built: each is a cache hit by
  // then, and none of them may be loaded from here at 18a.
  loadTlsServer: () => any;
  loadSpiffeCa: () => any;
  loadAdminViews: () => any;
  details: typeof details;
  errorCodes: typeof errorCodes;
  pki: typeof pki;
  realms: typeof realms;
  applications: typeof applications;
  personAssertions: typeof personAssertions;
  helpers: typeof helpers;
  x509: typeof x509;
  pkijs: typeof pkijs;
}

class CertificateViews {
  constructor(private readonly deps: CertificateViewsDeps) {
    deps.log.debug("Entering CertificateViews.constructor().");
    deps.log.debug("Leaving CertificateViews.constructor().");
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
      personAssertions.holders().forEach(function (one) {
        catalogue.add(one.certificatePem, 'Person "' + one.username +
                      '", RFC 7523 key pair', 'persons');
        // A person's RFC 7522 key pair too, since 2026-09-13.
        if (one.saml && one.saml.certificatePem) {
          catalogue.add(one.saml.certificatePem, 'Person "' + one.username +
                        '", RFC 7522 key pair', 'persons');
        }
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
    const catalogue = this.newCatalogue();
    this.addAuthorities(catalogue);
    let entry = catalogue.get(fp);
    if (!entry) {
      this.addHolders(catalogue);
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
    return Object.assign({ ok: true,
                           realm: this.scopeOfRealm() || realms.DEFAULT_ID,
                           appearances: entry.appearances.slice() }, model);
  }

  // ---------------------------------------------------------------------------
  // EVERY CERTIFICATE THIS REALM HOLDS, as a list a caller walks to find the
  // fingerprint it wants. Paged the way every list on `/admin-api` is, and
  // filterable by `q` over the subject, the issuer and where it appears.
  // ---------------------------------------------------------------------------
  listView(req) {
    const { log, realms, x509, pkijs, loadAdminViews } = this.deps;
    log.debug("Entering CertificateViews.listView().");
    const query = (req && req.query) || {};
    const catalogue = this.newCatalogue();
    this.addAuthorities(catalogue);
    this.addHolders(catalogue);
    const needle = String(query.q || '').toLowerCase();
    const rows = catalogue.entries().map(function (entry) {
      let subject = '';
      let issuer = '';
      let notAfter = '';
      try {
        const der = Buffer.from(entry.pem.replace(/-----[^-]+-----/g, '')
          .replace(/\s+/g, ''), 'base64');
        const cert = pkijs.Certificate.fromBER(new Uint8Array(der));
        subject = x509.dnToString(cert.subject);
        issuer = x509.dnToString(cert.issuer);
        notAfter = cert.notAfter.value.toISOString();
      } catch (e) {
        log.debug("Caught in CertificateViews.listView(): " + ((e &&
            e.message) || e));
      }
      return {
        fingerprint: entry.fingerprint,
        subject: subject,
        issuer: issuer,
        notAfter: notAfter,
        selfIssued: !!subject && subject === issuer,
        appearances: entry.appearances.slice()
      };
    }).filter(function (row) {
      if (!needle) {
        return true;
      }
      const hay = (row.subject + ' ' + row.issuer + ' ' +
                   row.appearances.map(function (a) { return a.label; })
                     .join(' ')).toLowerCase();
      return hay.indexOf(needle) >= 0;
    });
    // Lazily, for the load-order reason in the header: `admin_views.ts`
    // requires route-registering modules and this file is required at 18a.
    const pg = loadAdminViews().pagingOf(query, rows.length);
    const out = {
      realm: this.scopeOfRealm() || realms.DEFAULT_ID,
      total: catalogue.entries().length,
      matched: rows.length,
      page: pg.page,
      pages: pg.pages,
      perPage: pg.perPage,
      firstRow: pg.firstRow,
      lastRow: pg.lastRow,
      certificates: rows.slice(pg.offset, pg.offset + pg.perPage)
    };
    log.debug("Leaving CertificateViews.listView(). " + out.matched +
              " certificate(s).");
    return out;
  }
}

// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules,
// as the composition root will build one.
const views = new CertificateViews({
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
  details: details,
  errorCodes: errorCodes,
  pki: pki,
  realms: realms,
  applications: applications,
  personAssertions: personAssertions,
  helpers: helpers,
  x509: x509,
  pkijs: pkijs
});


export = {
  CertificateViews: CertificateViews,
  PAGES: PAGES,
  normalFingerprint: views.normalFingerprint.bind(views) as
    CertificateViews['normalFingerprint'],
  detailsView: views.detailsView.bind(views) as CertificateViews['detailsView'],
  listView: views.listView.bind(views) as CertificateViews['listView']
};
