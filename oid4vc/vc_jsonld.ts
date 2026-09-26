'use strict';
//
// File: vc_jsonld.ts
//
// ---------------------------------------------------------------------------
// JSON-LD FOR THE DATA INTEGRITY CRYPTOSUITES THAT READ A DOCUMENT AS A GRAPH
// (#194-#196, 2026-09-26): a CLOSED document loader, and RDF Dataset
// Canonicalization (RDFC-1.0) over it.
//
// `vc_data_integrity.ts` held only the JCS cryptosuites until #195/#196,
// and its header said why: an RDFC suite canonicalizes the document as an
// RDF dataset, which needs every `@context` it names, and a loader that
// FETCHED a context a caller named would be this service dialling a URL a
// request supplied (the root `CLAUDE.md`'s *Dial a URL a CALLER supplied*).
// That argument still stands and is what this file keeps: **THE LOADER
// FETCHES NOTHING.** It answers from the contexts below, which ship with
// the service, and refuses every other URL — so a document that names a
// context this service does not hold is not verified (and not signed), it
// is refused with the URL named. `vendored/bbs2023.js` made the same choice
// for bbs-2023 and this is the same rule for the other suites.
//
// THE CONTEXTS, each fetched from its canonical URL on 2026-09-26 and kept
// byte for byte (sha256 of the file here):
//
//   https://www.w3.org/ns/credentials/v2
//   https://www.w3.org/2018/credentials/v1
//                        common/vendored/contexts/ — the copies bbs2023.js
//                        reads, so the two loaders cannot disagree
//   https://www.w3.org/ns/credentials/examples/v2
//                        credentials_examples_v2.json   57393fbc…ae8e43de85
//   https://w3id.org/security/data-integrity/v1
//                        data_integrity_v1.json         b5d829bd…ca9418554
//   https://w3id.org/security/data-integrity/v2
//                        data_integrity_v2.json         67f21e6e…d8ae8f4
//   https://w3id.org/security/multikey/v1
//                        multikey_v1.json               ba2c182d…7c58597
//   https://www.w3.org/ns/did/v1
//                        did_v1.json                    4f3eae55…421b88dad
//   https://www.w3.org/ns/cid/v1
//                        cid_v1.json                    ea216ecc…e43de85
//   https://w3id.org/security/v1, …/v2
//                        security_v1.json, security_v2.json
//   https://w3id.org/security/suites/ed25519-2020/v1
//                        ed25519_2020_v1.json           b9e1ab97…f549588
//   https://w3id.org/security/suites/jws-2020/v1
//                        jws_2020_v1.json               d648e05d…8ce22f6b
//   https://w3id.org/vc/status-list/2021/v1
//                        status_list_2021_v1.json       6dd06a52…870e4
//   https://w3id.org/citizenship/v4rc1
//                        citizenship_v4rc1.json         5038c738…cf2279d7c
//   https://idptools.com/contexts/identity/v1
//                        common/vendored/contexts/, this issuer's own
//
// The W3C documents are under the W3C Software and Document Licence; the
// w3id.org ones are the W3C Credentials Community Group's, published under
// the same. **Adding one is a decision**, not a fix for a refusal: a context
// is a vocabulary this service then agrees to sign and verify statements
// in. `tests/vc_jsonld.js` holds every file to its hash.
//
// **CANONICALIZATION IS SAFE MODE, BASE NULL.** `jsonld.canonize()` defaults
// to both for exactly this use, and they are passed explicitly anyway: safe
// mode makes a term no context defines an ERROR rather than a statement
// silently dropped from what is signed (Data Integrity 1.0 section 4.1:
// "implementations MUST ... produce an error when ... lossy"), and a null
// base keeps a relative IRI from being resolved against wherever the
// document happened to be read.
//
// A LIBRARY (rule 3): no route. It requires `jsonld` (a dependency already,
// for bbs2023.js) and `common/` leaves.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import jsonld = require('jsonld');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

interface VcJsonLdDeps {
  log: typeof helpers.log;
  readJson: (file: string) => any;
  readBytes: (file: string) => Buffer;
}

const VENDORED = path.join(__dirname, '..', 'common', 'vendored', 'contexts');
const OWN = path.join(__dirname, 'contexts');

// URL -> [directory, file]. Read once, when first asked for.
const CONTEXT_FILES: Record<string, [string, string]> = {
  'https://www.w3.org/ns/credentials/v2': [VENDORED, 'credentials_v2.json'],
  'https://www.w3.org/2018/credentials/v1': [VENDORED,
                                             'credentials_v1.json'],
  'https://idptools.com/contexts/identity/v1': [VENDORED,
                                                'idptools_identity_v1.json'],
  'https://www.w3.org/ns/credentials/examples/v2': [OWN,
    'credentials_examples_v2.json'],
  'https://w3id.org/security/data-integrity/v1': [OWN,
                                                  'data_integrity_v1.json'],
  'https://w3id.org/security/data-integrity/v2': [OWN,
                                                  'data_integrity_v2.json'],
  'https://w3id.org/security/multikey/v1': [OWN, 'multikey_v1.json'],
  'https://www.w3.org/ns/did/v1': [OWN, 'did_v1.json'],
  'https://www.w3.org/ns/cid/v1': [OWN, 'cid_v1.json'],
  'https://w3id.org/security/v1': [OWN, 'security_v1.json'],
  'https://w3id.org/security/v2': [OWN, 'security_v2.json'],
  'https://w3id.org/security/suites/ed25519-2020/v1': [OWN,
                                                       'ed25519_2020_v1.json'],
  'https://w3id.org/security/suites/jws-2020/v1': [OWN, 'jws_2020_v1.json'],
  'https://w3id.org/vc/status-list/2021/v1': [OWN, 'status_list_2021_v1.json'],
  'https://w3id.org/citizenship/v4rc1': [OWN, 'citizenship_v4rc1.json']
};

class VcJsonLd {
  static readonly CONTEXT_URLS = Object.keys(CONTEXT_FILES);

  private readonly held = new Map<string, any>();

  constructor(private readonly deps: VcJsonLdDeps) {
    deps.log.debug("Entering VcJsonLd.constructor().");
    deps.log.debug("Leaving VcJsonLd.constructor().");
  }

  static defaultDeps(): VcJsonLdDeps {
    helpers.log.debug("Entering VcJsonLd.defaultDeps().");
    helpers.log.debug("Leaving VcJsonLd.defaultDeps().");
    return {
      log: helpers.log,
      readJson: function readJson(file: string): any {
        helpers.log.debug("Entering readJson().");
        helpers.log.debug("Leaving readJson().");
        return JSON.parse(fs.readFileSync(file, 'utf8'));
      },
      readBytes: function readBytes(file: string): Buffer {
        helpers.log.debug("Entering readBytes().");
        helpers.log.debug("Leaving readBytes().");
        return fs.readFileSync(file);
      }
    };
  }

  // Every context URL this service holds.
  knownContexts(): string[] {
    const { log } = this.deps;
    log.debug("Entering VcJsonLd.knownContexts().");
    log.debug("Leaving VcJsonLd.knownContexts().");
    return VcJsonLd.CONTEXT_URLS.slice();
  }

  // The context document for a URL, or null when this service holds none.
  contextFor(url: unknown): any {
    const { log, readJson } = this.deps;
    log.debug("Entering VcJsonLd.contextFor().");
    const key = String(url || '');
    const where = Object.prototype.hasOwnProperty.call(CONTEXT_FILES, key)
      ? CONTEXT_FILES[key] : null;
    if (!where) {
      log.debug("Leaving VcJsonLd.contextFor(). Not held.");
      return null;
    }
    if (!this.held.has(key)) {
      this.held.set(key, readJson(path.join(where[0], where[1])));
    }
    log.debug("Leaving VcJsonLd.contextFor().");
    return this.held.get(key);
  }

  // The BYTES of a held context, as served at its URL — what a
  // `relatedResource` digest is computed over (VCDM 2.0 section 5.3) — or
  // null when this service holds none.
  resourceBytes(url: unknown): Buffer | null {
    const { log, readBytes } = this.deps;
    log.debug("Entering VcJsonLd.resourceBytes().");
    const key = String(url || '');
    const where = Object.prototype.hasOwnProperty.call(CONTEXT_FILES, key)
      ? CONTEXT_FILES[key] : null;
    log.debug("Leaving VcJsonLd.resourceBytes().");
    return where ? readBytes(path.join(where[0], where[1])) : null;
  }

  // THE LOADER jsonld is given. Never fetches: see the header.
  documentLoader(): (url: string) => Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcJsonLd.documentLoader().");
    const self = this;
    // Called by jsonld once per context reference; no Entering/Leaving pair
    // here — the hot-path exception, stated as the style requires.
    const loader = function (url: string): Promise<any> {
      const document = self.contextFor(url);
      if (!document) {
        const e: any = new Error('the JSON-LD context "' + url + '" is not ' +
          'one this service holds, and it fetches none (it holds ' +
          VcJsonLd.CONTEXT_URLS.join(', ') + ')');
        e.name = 'jsonld.LoadDocumentError';
        e.code = 'loading document failed';
        return Promise.reject(e);
      }
      return Promise.resolve({ contextUrl: null, documentUrl: url,
                               document: document });
    };
    log.debug("Leaving VcJsonLd.documentLoader().");
    return loader;
  }

  // ---------------------------------------------------------------------------
  // RDFC-1.0 OF A JSON-LD DOCUMENT, as canonical N-Quads. `canonicalIdMap`,
  // when given, is filled with the blank node relabelling (input label ->
  // canonical label), which ecdsa-sd-2023's label map needs. Throws, with
  // jsonld's reason, for a document that is not safe to sign: an undefined
  // term, a relative IRI, an unknown context.
  // ---------------------------------------------------------------------------
  async canonize(document: any,
                 opts?: { canonicalIdMap?: Map<string, string> }):
    Promise<string> {
    const { log } = this.deps;
    log.debug("Entering VcJsonLd.canonize().");
    const o = opts || {};
    // `rdfDirection: 'i18n-datatype'`: a value with a base direction
    // (VCDM 2.0 section 11.1) becomes a literal of the i18n datatype, as the
    // Data Integrity cryptosuites expect. Without it safe mode refuses the
    // direction as lossy, and a conforming `name` could not be signed.
    const options: any = {
      algorithm: 'RDFC-1.0', format: 'application/n-quads',
      documentLoader: this.documentLoader(), safe: true, base: null,
      rdfDirection: 'i18n-datatype'
    };
    if (o.canonicalIdMap) {
      options.canonicalIdMap = o.canonicalIdMap;
    }
    const out = await (jsonld as any).canonize(document, options);
    log.debug("Leaving VcJsonLd.canonize(). " + String(out).length +
              " character(s).");
    return String(out);
  }

  // RDFC-1.0 of a set of N-Quads (a string, one quad per line).
  async canonizeNQuads(nquads: string,
                       opts?: { canonicalIdMap?: Map<string, string> }):
    Promise<string> {
    const { log } = this.deps;
    log.debug("Entering VcJsonLd.canonizeNQuads().");
    const o = opts || {};
    const options: any = {
      algorithm: 'RDFC-1.0', format: 'application/n-quads',
      inputFormat: 'application/n-quads', safe: true, base: null
    };
    if (o.canonicalIdMap) {
      options.canonicalIdMap = o.canonicalIdMap;
    }
    const out = await (jsonld as any).canonize(nquads, options);
    log.debug("Leaving VcJsonLd.canonizeNQuads().");
    return String(out);
  }

  // The document as N-Quads, NOT canonicalized (blank nodes as jsonld
  // labels them), safe mode.
  async toNQuads(document: any): Promise<string> {
    const { log } = this.deps;
    log.debug("Entering VcJsonLd.toNQuads().");
    const out = await (jsonld as any).toRDF(document, {
      format: 'application/n-quads', documentLoader: this.documentLoader(),
      safe: true, base: null, rdfDirection: 'i18n-datatype' });
    log.debug("Leaving VcJsonLd.toNQuads().");
    return String(out);
  }

  // The document in JSON-LD expanded form, safe mode.
  async expand(document: any): Promise<any[]> {
    const { log } = this.deps;
    log.debug("Entering VcJsonLd.expand().");
    const out = await (jsonld as any).expand(document, {
      documentLoader: this.documentLoader(), safe: true, base: null });
    log.debug("Leaving VcJsonLd.expand().");
    return out;
  }

  // The document compacted to a context, safe mode.
  async compact(document: any, context: any): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcJsonLd.compact().");
    const out = await (jsonld as any).compact(document, context, {
      documentLoader: this.documentLoader(), safe: true, base: null,
      compactToRelative: false });
    log.debug("Leaving VcJsonLd.compact().");
    return out;
  }
}

const slot = new InstanceSlot<VcJsonLd>(
  'oid4vc/vc_jsonld',
  () => new VcJsonLd(VcJsonLd.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  VcJsonLd: VcJsonLd,
  installInstance: (instance: VcJsonLd): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  CONTEXT_URLS: VcJsonLd.CONTEXT_URLS,
  knownContexts: slot.forward('knownContexts'),
  contextFor: slot.forward('contextFor'),
  resourceBytes: slot.forward('resourceBytes'),
  documentLoader: slot.forward('documentLoader'),
  canonize: slot.forward('canonize'),
  canonizeNQuads: slot.forward('canonizeNQuads'),
  toNQuads: slot.forward('toNQuads'),
  expand: slot.forward('expand'),
  compact: slot.forward('compact')
};
