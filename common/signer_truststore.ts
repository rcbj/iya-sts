// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/signer_truststore.ts
//
// ===========================================================================
// THE SIGNER TRUSTSTORE (#1360, 2026-11-06): the certificate authorities, and
// the intermediates under them, a THIRD PARTY's certificate may chain to when
// it is relied on for anything but a TLS handshake: under a signature, as an
// encryption recipient, in an attestation.
//
// **IT IS PER REALM, WHERE THE CLIENT TRUSTSTORE IS NOT.** A TLS handshake has
// no realm in it, which is the one reason `tls/tls_server.js`'s anchors are
// the process's. A signature carries a path and a realm, so a partner's CA
// trusted by one realm is not thereby trusted by another, and a realm's store
// does not inherit the default realm's. The two are never merged: one list
// that showed both would say something false about where each applies.
//
// **THE STORE IS THE DIRECTORY**: `ou=signerTrustAnchors,<realm base>`, for the
// reasons `tls/CLAUDE.md` gives for `ou=trustAnchors`: it is the one thing kept
// in every store mode and replicated between processes, so this module holds
// no copy and needs no reload. Every read asks the directory, whose container
// listing is cached until something is written there. `ldap/ldap_server.js`
// fills the slot at 21: it is JavaScript and a require of it from here would
// move its routes, and it requires this module in the natural direction.
//
// **ADMISSION IS `pki.anchorProblem()`, ALWAYS.** Unlike the client truststore
// this store has no behaviour from before #1360 to restore, so no setting
// loosens it: a leaf is never an entry here.
//
// **CONSULTED ONLY THROUGH THE DOOR** (`common/certificate_trust.ts`); no site
// reads this store itself.
//
// **THE FILE LAYER** is `pki.signerTrustAnchorsFile`, into the DEFAULT realm
// only, read once when the stack loads and held in this process. Named and
// unusable it stops the process (STS-PKI-0237), as `tls.trustAnchorsFile` does:
// an operator named a trust anchor, and a service running without it would
// refuse partners later with a message naming neither the file nor the setting.
//
// A LIBRARY (rule 3): no route, no listener, no timer.
// ===========================================================================

import fs = require('fs');
import helpers = require('./helpers');
import config = require('./config');
import realms = require('./realms');
import stsCrypto = require('./crypto');
import pki = require('./pki');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

type Json = any;
type SignerAnchor = import('../types/certificate_trust').SignerAnchor;

// As the client truststore's cap, and twice that for what hangs beneath them.
const MAX_ANCHORS = 32;
const MAX_INTERMEDIATES = 64;
const CERTIFICATE =
  /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

interface SignerTruststoreDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  crypto: typeof stsCrypto;
  pki: typeof pki;
  errorCodes: typeof errorCodes;
  readFile: (file: string) => string;
  exit: (code: number) => void;
}

/**
 * The per-realm store of third parties' certificate authorities: anchors,
 * intermediates, and the use cases each is trusted for.
 *
 * A library: no route. Every read asks the directory, and a certificate enters
 * only through `pki.anchorProblem()`.
 */
class SignerTruststore {
  static readonly MAX_ANCHORS = MAX_ANCHORS;
  static readonly MAX_INTERMEDIATES = MAX_INTERMEDIATES;
  private directory: Json = null;
  // What the file named, read once: `{ pem, kind, fingerprint, addedAt }`.
  private fileRows: Json[] = [];
  private fileName = '';

  /**
   * Creates the store.
   *
   * @param deps - its dependencies
   */
  constructor(private readonly deps: SignerTruststoreDeps) {
    deps.log.debug("Entering SignerTruststore.constructor().");
    deps.log.debug("Leaving SignerTruststore.constructor().");
  }

  /**
   * The module's own dependencies.
   *
   * @returns the deps a default instance is built from
   */
  static defaultDeps(): SignerTruststoreDeps {
    helpers.log.debug("Entering SignerTruststore.defaultDeps().");
    helpers.log.debug("Leaving SignerTruststore.defaultDeps().");
    return {
      log: helpers.log, config: config, realms: realms, crypto: stsCrypto,
      pki: pki, errorCodes: errorCodes,
      readFile: function (file: string): string {
        return fs.readFileSync(file, 'utf8');
      },
      exit: function (code: number): void {
        process.exit(code);
      }
    };
  }

  /**
   * Installs the directory's half, validated whole: a filler that installed
   * the list and not the write would leave a page that shows anchors and
   * refuses every add, with nothing saying why.
   *
   * @param directory - `{ list(realmId), put(realmId, row), remove(realmId,
   *   fingerprint) }`
   * @returns true when installed; false (and logged) for a partial object
   */
  setDirectory(directory: Json): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SignerTruststore.setDirectory().");
    const missing = ['list', 'put', 'remove'].filter(function (name) {
      return !directory || typeof directory[name] !== 'function';
    });
    if (missing.length) {
      log.error(errorCodes.tag('STS-PKI-0235') + 'signer truststore: the ' +
                'directory offered no ' + missing.join(', ') + ', so nothing ' +
                'was installed; the store holds nothing until it is.');
      log.debug("Leaving SignerTruststore.setDirectory(). Partial.");
      return false;
    }
    this.directory = directory;
    log.debug("Leaving SignerTruststore.setDirectory().");
    return true;
  }

  /**
   * Names the directory installed, so a test can put it back.
   *
   * @returns the directory, or null
   */
  installedDirectory(): Json {
    this.deps.log.debug("Entering SignerTruststore.installedDirectory().");
    this.deps.log.debug("Leaving SignerTruststore.installedDirectory().");
    return this.directory;
  }

  // A realm id as this module stores it: the ambient realm where none is named.
  private realmIdOf(realmId?: string): string {
    this.deps.log.debug("Entering SignerTruststore.realmIdOf().");
    this.deps.log.debug("Leaving SignerTruststore.realmIdOf().");
    return realmId || this.deps.realms.currentId();
  }

  // Upper hex with no colons: `ou=trustAnchors`' spelling.
  private fingerprintOf(cert: Json): string {
    this.deps.log.debug("Entering SignerTruststore.fingerprintOf().");
    this.deps.log.debug("Leaving SignerTruststore.fingerprintOf().");
    return String(this.deps.crypto.parseCertificate(cert).fingerprint256)
      .replace(/:/g, '').toUpperCase();
  }

  // The rows this realm holds, cheapest first: what the directory stores and,
  // in the default realm, what the file named. Nothing is parsed here, which
  // is what lets `anchorsFor()` run at every validation.
  private rowsOf(realmId: string): Json[] {
    const { log, realms } = this.deps;
    log.debug("Entering SignerTruststore.rowsOf().");
    const stored = this.directory ?
      this.directory.list(realmId).map(function (row: Json) {
        return Object.assign({ source: row.source || 'runtime' }, row);
      }) : [];
    const rows = realmId === realms.DEFAULT_ID ?
      this.fileRows.filter(function (file: Json) {
        return !stored.some(function (row: Json) {
          return row.fingerprint === file.fingerprint;
        });
      }).concat(stored) : stored;
    log.debug("Leaving SignerTruststore.rowsOf(). " + rows.length + ".");
    return rows;
  }

  // One row as the page and the API read it.
  private describe(row: Json): SignerAnchor {
    const { log, crypto } = this.deps;
    log.debug("Entering SignerTruststore.describe().");
    const described: SignerAnchor = {
      fingerprint256: row.fingerprint, pem: row.pem, kind: row.kind,
      purposes: row.purposes || [], source: row.source,
      addedBy: row.addedBy || '', addedAt: row.addedAt || '',
      subject: '', issuer: '', notBefore: 0, notAfter: 0
    };
    try {
      const facts = crypto.certificateFacts(row.pem);
      described.subject = facts.subject;
      described.issuer = facts.issuer;
      described.notBefore = facts.notBefore;
      described.notAfter = facts.notAfter;
      // WHAT WAS ADMITTED CAN STOP BEING ADMISSIBLE: an anchor expires where
      // it sits. It stays, and the page says so; an operator removes it.
      const field = crypto.certificateFieldProblem(row.pem,
        row.kind === 'accepted' ? { role: 'leaf', keyUsage: [] } :
          { role: row.kind, keyUsage: ['keyCertSign'] });
      if (field) {
        described.unadmittable = field.why;
      }
    } catch (e) {
      log.debug("Caught in SignerTruststore.describe(): " +
                ((e && e.message) || e));
      described.unadmittable = 'this is not an X.509 certificate';
    }
    log.debug("Leaving SignerTruststore.describe().");
    return described;
  }

  /**
   * Lists what a realm holds.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @returns every anchor and intermediate, as the page reads them
   */
  list(realmId?: string): SignerAnchor[] {
    const { log } = this.deps;
    log.debug("Entering SignerTruststore.list().");
    const self = this;
    const rows = this.rowsOf(this.realmIdOf(realmId))
      .map(function (row: Json) {
        return self.describe(row);
      });
    log.debug("Leaving SignerTruststore.list(). " + rows.length + ".");
    return rows;
  }

  /**
   * The certificates a validation of one use case may reach.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param purpose - the use case; a row naming no purposes serves every one
   * @returns `{ anchors, intermediates }`, each a list of DER buffers
   */
  anchorsFor(realmId?: string, purpose?: string): Json {
    const { log, pki } = this.deps;
    log.debug("Entering SignerTruststore.anchorsFor(). " + (purpose || ''));
    const anchors: Buffer[] = [];
    const intermediates: Buffer[] = [];
    this.rowsOf(this.realmIdOf(realmId)).forEach(function (row: Json) {
      const purposes = row.purposes || [];
      // A certificate accepted by name vouches for itself and nothing else, so
      // it is no step on anybody's path.
      if (row.kind === 'accepted' ||
          (purpose && purposes.length && purposes.indexOf(purpose) === -1)) {
        return;
      }
      (row.kind === 'anchor' ? anchors : intermediates)
        .push(pki.pemToDer(row.pem));
    });
    log.debug("Leaving SignerTruststore.anchorsFor(). " + anchors.length +
              " anchor(s), " + intermediates.length + " intermediate(s).");
    return { anchors: anchors, intermediates: intermediates };
  }

  /**
   * Has an operator accepted this one certificate, by name, in this realm?
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param cert - the certificate
   * @returns whether a row of kind `accepted` is this certificate
   */
  accepted(realmId: string | undefined, cert: Json): boolean {
    const { log, crypto } = this.deps;
    log.debug("Entering SignerTruststore.accepted().");
    const fingerprint = this.fingerprintOf(crypto.parseCertificate(cert));
    const found = this.rowsOf(this.realmIdOf(realmId)).some(function (row) {
      return row.kind === 'accepted' && row.fingerprint === fingerprint;
    });
    log.debug("Leaving SignerTruststore.accepted(). " + found);
    return found;
  }

  /**
   * What a TLS client may add to its `ca` for one use case: the anchors and
   * intermediates a realm's store holds, as PEM.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param purpose - the use case
   * @returns the PEM blocks
   */
  pemsFor(realmId?: string, purpose?: string): string[] {
    this.deps.log.debug("Entering SignerTruststore.pemsFor().");
    const out = this.rowsOf(this.realmIdOf(realmId))
      .filter(function (row: Json) {
        const purposes = row.purposes || [];
        return !purpose || !purposes.length ||
               purposes.indexOf(purpose) !== -1;
      }).map(function (row: Json) {
        return row.pem;
      });
    this.deps.log.debug("Leaving SignerTruststore.pemsFor(). " + out.length);
    return out;
  }

  // Self-issued first, so an intermediate in the same bundle as its anchor
  // finds it held.
  private blocksOf(text: string): string[] {
    const { log, crypto } = this.deps;
    log.debug("Entering SignerTruststore.blocksOf().");
    const blocks = String(text || '').match(CERTIFICATE) || [];
    const rank = function (pem: string): number {
      log.debug("Entering rank().");
      let selfIssued = false;
      try {
        const parsed = crypto.parseCertificate(pem);
        selfIssued = parsed.subject === parsed.issuer;
      } catch (e) {
        log.debug("Caught in rank(): " + ((e && e.message) || e));
      }
      log.debug("Leaving rank().");
      return selfIssued ? 0 : 1;
    };
    const ordered = blocks.slice().sort(function (a: string, b: string) {
      return rank(a) - rank(b);
    });
    log.debug("Leaving SignerTruststore.blocksOf(). " + ordered.length + ".");
    return ordered;
  }

  // Admits one block against what is held, and answers its row or its refusal.
  private async admit(pem: string, held: Json[], kind: string): Promise<Json> {
    const { log, crypto, pki } = this.deps;
    log.debug("Entering SignerTruststore.admit().");
    const anchorsHeld = held.filter(function (row: Json) {
      return row.kind === 'anchor';
    }).map(function (row: Json) {
      return row.pem;
    });
    const intermediatesHeld = held.filter(function (row: Json) {
      return row.kind === 'intermediate';
    }).map(function (row: Json) {
      return pki.pemToDer(row.pem);
    });
    // ONE CERTIFICATE, ACCEPTED BY NAME (rcbj, #1360): a self-signed leaf a
    // server presents, such as an appliance's. Only that: a CA is an anchor,
    // because trusting one trusts everything it signs. In date and of a
    // strength this deployment takes, like anything else held.
    if (kind === 'accepted') {
      const read = crypto.parseCertificate(pem);
      const facts = crypto.certificateFacts(read);
      if (!facts.selfIssued || facts.ca) {
        log.debug("Leaving SignerTruststore.admit(). Not a self-signed leaf.");
        return { refused: { code: 'STS-PKI-0267', why: '"' + facts.subject +
          '" is not a self-signed leaf: a certificate authority is added as ' +
          'an anchor, and one a CA issued is trusted through that CA' } };
      }
      const wrong = crypto.certificateFieldProblem(read,
        { role: 'leaf', keyUsage: [] });
      if (wrong) {
        log.debug("Leaving SignerTruststore.admit(). A field.");
        return { refused: { code: wrong.code, why: wrong.why } };
      }
      log.debug("Leaving SignerTruststore.admit(). Accepted by name.");
      return { kind: 'accepted', fingerprint: this.fingerprintOf(read) };
    }
    const problem = await pki.anchorProblem(pem, {
      role: kind || undefined, heldAnchors: anchorsHeld,
      heldIntermediates: intermediatesHeld
    });
    if (problem) {
      log.debug("Leaving SignerTruststore.admit(). Refused.");
      return { refused: { code: problem.code, why: problem.why } };
    }
    const parsed = crypto.parseCertificate(pem);
    log.debug("Leaving SignerTruststore.admit(). Admitted.");
    return { kind: kind || (parsed.subject === parsed.issuer ? 'anchor' :
                            'intermediate'),
             fingerprint: this.fingerprintOf(parsed) };
  }

  /**
   * Adds certificates to a realm's store, each through the admission rule. A
   * bundle's refusals are named one by one and do not stop its other blocks.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param text - one or more PEM blocks
   * @param options - `{ kind, purposes, addedBy }`; `kind` omitted means a
   *   self-issued certificate is an anchor and any other an intermediate
   * @returns a promise of `{ added, duplicates, refused }`; `refused` rows are
   *   `{ subject, code, why }`
   */
  async add(realmId: string, text: string, options?: Json): Promise<Json> {
    const { log, crypto, errorCodes } = this.deps;
    log.debug("Entering SignerTruststore.add().");
    const id = this.realmIdOf(realmId);
    const opts = options || {};
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
      out.refused.push({ subject: '', code: 'STS-PKI-0235',
                         why: 'the directory is not installed in this ' +
                              'process' });
      log.debug("Leaving SignerTruststore.add(). No directory.");
      return errorCodes.mark(out, 'STS-PKI-0235');
    }
    const blocks = this.blocksOf(text);
    if (!blocks.length) {
      out.refused.push({ subject: '', code: 'STS-PKI-0238',
                         why: 'no PEM certificate was given' });
    }
    for (let i = 0; i < blocks.length; i++) {
      const held = this.rowsOf(id);
      const seen = await this.admit(blocks[i], held, opts.kind || '');
      if (seen.refused) {
        refuse(blocks[i], seen.refused.code, seen.refused.why);
        continue;
      }
      if (held.some(function (row: Json) {
        return row.fingerprint === seen.fingerprint;
      })) {
        out.duplicates += 1;
        continue;
      }
      const sameKind = held.filter(function (row: Json) {
        return row.kind === seen.kind;
      }).length;
      const cap = seen.kind === 'intermediate' ? MAX_INTERMEDIATES :
        MAX_ANCHORS;
      if (sameKind >= cap) {
        refuse(blocks[i], 'STS-PKI-0236', 'this realm already holds ' + cap +
               ' signer truststore ' + seen.kind + 's');
        continue;
      }
      const row = { fingerprint: seen.fingerprint, pem: blocks[i],
                    kind: seen.kind,
                    purposes: seen.kind === 'accepted' ?
                      ['tls-server-outbound'] : opts.purposes || [],
                    addedBy: String(opts.addedBy || ''), source: 'runtime' };
      if (this.directory.put(id, row) === false) {
        refuse(blocks[i], 'STS-PKI-0236', 'the directory is full');
        continue;
      }
      out.added.push(this.describe(row));
    }
    if (out.refused.length) {
      errorCodes.mark(out, out.refused[0].code);
    }
    log.debug("Leaving SignerTruststore.add(). " + out.added.length +
              " added, " + out.refused.length + " refused.");
    return out;
  }

  /**
   * Removes one entry from a realm's store, under either spelling of its
   * fingerprint. A row from the file comes back at the next start, and is
   * refused here for that reason.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param fingerprint - the SHA-256 fingerprint
   * @returns `{ removed, why }`
   */
  remove(realmId: string, fingerprint: string): Json {
    const { log } = this.deps;
    log.debug("Entering SignerTruststore.remove().");
    const id = this.realmIdOf(realmId);
    const wanted = String(fingerprint || '').replace(/[^0-9a-fA-F]/g, '')
      .toUpperCase();
    const row = this.rowsOf(id).filter(function (one: Json) {
      return one.fingerprint === wanted;
    })[0];
    if (!row) {
      log.debug("Leaving SignerTruststore.remove(). Not held.");
      return { removed: false, why: 'this realm holds no signer truststore ' +
               'entry with that fingerprint' };
    }
    if (row.source === 'file') {
      log.debug("Leaving SignerTruststore.remove(). From the file.");
      return { removed: false, why: 'that entry comes from ' +
               'pki.signerTrustAnchorsFile; take it out of the file and ' +
               'restart' };
    }
    const removed = this.directory.remove(id, wanted) !== false;
    log.debug("Leaving SignerTruststore.remove(). " + removed);
    return { removed: removed, why: removed ? '' :
             'the directory did not hold that entry' };
  }

  /**
   * Reads `pki.signerTrustAnchorsFile` into the default realm's store. Named
   * and unreadable, or holding no certificate, it stops the process. A block
   * the admission rule refuses is logged by name and left out.
   *
   * @returns a promise of how many entries the file gave
   */
  async loadFile(): Promise<number> {
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering SignerTruststore.loadFile().");
    const file = String(config.processValue('pki.signerTrustAnchorsFile') ||
                        '');
    this.fileName = file;
    this.fileRows = [];
    if (!file) {
      log.debug("Leaving SignerTruststore.loadFile(). None named.");
      return 0;
    }
    let text = '';
    try {
      text = this.deps.readFile(file);
    } catch (e) {
      log.fatal(errorCodes.tag('STS-PKI-0237') + 'pki.signerTrustAnchorsFile ' +
                'names "' + file + '", which could not be read: ' +
                ((e && e.message) || e));
      this.deps.exit(1);
      log.debug("Leaving SignerTruststore.loadFile(). Unreadable.");
      return 0;
    }
    const blocks = this.blocksOf(text);
    if (!blocks.length) {
      log.fatal(errorCodes.tag('STS-PKI-0237') + 'pki.signerTrustAnchorsFile ' +
                'names "' + file + '", which holds no certificate.');
      this.deps.exit(1);
      log.debug("Leaving SignerTruststore.loadFile(). Empty.");
      return 0;
    }
    for (let i = 0; i < blocks.length; i++) {
      const seen = await this.admit(blocks[i], this.fileRows, '');
      if (seen.refused) {
        // error-code: none — the admission rule's own code is on this line
        log.error(errorCodes.tag(seen.refused.code) +
                  'pki.signerTrustAnchorsFile: left out: ' + seen.refused.why);
        continue;
      }
      this.fileRows.push({ fingerprint: seen.fingerprint, pem: blocks[i],
                           kind: seen.kind, purposes: [], source: 'file',
                           addedBy: '', addedAt: '' });
    }
    log.debug("Leaving SignerTruststore.loadFile(). " + this.fileRows.length +
              ".");
    return this.fileRows.length;
  }

  /**
   * The store's limits and its file, for the page.
   *
   * @returns `{ file, loadedFromFile, maxAnchors, maxIntermediates, installed }`
   */
  limits(): Json {
    this.deps.log.debug("Entering SignerTruststore.limits().");
    this.deps.log.debug("Leaving SignerTruststore.limits().");
    return { file: this.fileName, loadedFromFile: this.fileRows.length,
             maxAnchors: MAX_ANCHORS, maxIntermediates: MAX_INTERMEDIATES,
             installed: !!this.directory };
  }
}

const slot = new InstanceSlot<SignerTruststore>(
  'common/signer_truststore',
  () => new SignerTruststore(SignerTruststore.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The signer truststore: per realm, directory-backed, consulted only through
 * the validation door.
 *
 * @namespace
 */
export = {
  SignerTruststore: SignerTruststore,
  MAX_ANCHORS: MAX_ANCHORS,
  MAX_INTERMEDIATES: MAX_INTERMEDIATES,
  installInstance: (instance: SignerTruststore): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  setDirectory: slot.forward('setDirectory'),
  installedDirectory: slot.forward('installedDirectory'),
  list: slot.forward('list'),
  anchorsFor: slot.forward('anchorsFor'),
  pemsFor: slot.forward('pemsFor'),
  accepted: slot.forward('accepted'),
  add: slot.forward('add'),
  remove: slot.forward('remove'),
  loadFile: slot.forward('loadFile'),
  limits: slot.forward('limits')
};
