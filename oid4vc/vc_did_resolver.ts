'use strict';
//
// File: vc_did_resolver.ts
//
// ---------------------------------------------------------------------------
// DID RESOLUTION AND DID URL DEREFERENCING, AS W3C DID CORE 1.0 SECTION 7
// DEFINES THEM (#199, 2026-09-26), for the DIDs this service resolves.
//
// The Verifier has resolved `did:jwk` and `did:key` since #38 — to a KEY,
// inside a proof check, which is all a signature needs. DID Core section 7
// defines resolution as returning a DID DOCUMENT with its metadata, in a
// representation, and dereferencing as returning a resource a DID URL
// names. This file is that, for the same methods and no more:
//
//   * did:key — the W3C CCG did:key method: one `Multikey` verification
//     method, the key itself, referenced from authentication,
//     assertionMethod, capabilityInvocation and capabilityDelegation, for
//     the key types `vc_data_integrity.ts` reads (Ed25519, P-256, P-384 and
//     the two post-quantum ones);
//   * did:jwk — the did:jwk method: one `JsonWebKey2020` method `#0`,
//     referenced from the relationships its `use` allows;
//   * did:web — ONLY THIS REALM'S OWN (`vc_did.ts`), built here rather than
//     fetched. Any other did:web is `notFound`: resolving it would be a GET
//     of a URL a caller chose (the root `CLAUDE.md`'s rule), and this
//     resolver makes none.
//
// Every other method is `methodNotSupported`, a DID that is not DID Core
// section 3.1's syntax is `invalidDid`, and a representation other than
// `application/did+json` and `application/did+ld+json` is
// `representationNotSupported`. The JSON representation carries no
// `@context` — it is the JSON-LD representation's entry (section 6.3.1) —
// and the JSON-LD one does.
//
// DEREFERENCING (section 7.2) answers the DID URL without a fragment with
// the document, and a fragment with the verification method it names
// (section 7.2.2's secondary resource); a path or a query this service
// defines nothing for is `notFound`.
//
// A LIBRARY (rule 3): the VC-API adapter (`vc_api.ts`) serves it at
// /vc-api/resolve and /vc-api/dereference, which the W3C DID test suite's
// fixtures are generated from (#199).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import vcDataIntegrity = require('./vc_data_integrity');
import vcDid = require('./vc_did');

interface VcDidResolverDeps {
  log: typeof helpers.log;
  di: typeof vcDataIntegrity;
  ownDid: (req: any) => string;
  ownDocument: (req: any) => Promise<any>;
}

const DID_V1 = 'https://www.w3.org/ns/did/v1';
const MULTIKEY_V1 = 'https://w3id.org/security/multikey/v1';
const JWS_2020_V1 = 'https://w3id.org/security/suites/jws-2020/v1';
const JSON_TYPE = 'application/did+json';
const JSONLD_TYPE = 'application/did+ld+json';

// DID Core section 3.1's ABNF, and section 3.2's DID URL.
const DID = /^did:[a-z0-9]+:(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$/;

class VcDidResolver {
  static readonly JSON_TYPE = JSON_TYPE;
  static readonly JSONLD_TYPE = JSONLD_TYPE;

  constructor(private readonly deps: VcDidResolverDeps) {
    deps.log.debug("Entering VcDidResolver.constructor().");
    deps.log.debug("Leaving VcDidResolver.constructor().");
  }

  static defaultDeps(): VcDidResolverDeps {
    helpers.log.debug("Entering VcDidResolver.defaultDeps().");
    helpers.log.debug("Leaving VcDidResolver.defaultDeps().");
    return {
      log: helpers.log,
      di: vcDataIntegrity,
      ownDid: function ownDid(req: any): string {
        helpers.log.debug("Entering ownDid().");
        helpers.log.debug("Leaving ownDid().");
        return vcDid.stsDid(req);
      },
      ownDocument: function ownDocument(req: any): Promise<any> {
        helpers.log.debug("Entering ownDocument().");
        helpers.log.debug("Leaving ownDocument().");
        return vcDid.stsDidDocument(req);
      }
    };
  }

  // Is this a DID (section 3.1)?
  isDid(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering VcDidResolver.isDid().");
    log.debug("Leaving VcDidResolver.isDid().");
    return typeof value === 'string' && DID.test(value);
  }

  // The did:key document (W3C CCG did:key, the Multikey form).
  private didKeyDocument(did: string): any {
    const { log, di } = this.deps;
    log.debug("Entering VcDidResolver.didKeyDocument().");
    const multikey = did.slice('did:key:'.length);
    di.jwkOfMultikey(multikey);
    const vm = did + '#' + multikey;
    log.debug("Leaving VcDidResolver.didKeyDocument().");
    return {
      '@context': [DID_V1, MULTIKEY_V1],
      id: did,
      verificationMethod: [{ id: vm, type: 'Multikey', controller: did,
                             publicKeyMultibase: multikey }],
      authentication: [vm], assertionMethod: [vm],
      capabilityInvocation: [vm], capabilityDelegation: [vm]
    };
  }

  // The did:jwk document (the did:jwk method specification).
  private didJwkDocument(did: string): any {
    const { log, di } = this.deps;
    log.debug("Entering VcDidResolver.didJwkDocument().");
    const jwk = di.jwkOfDidJwk(did);
    const raw = JSON.parse(Buffer.from(did.slice('did:jwk:'.length),
                                       'base64url').toString('utf8'));
    const vm = did + '#0';
    const doc: any = {
      '@context': [DID_V1, JWS_2020_V1],
      id: did,
      verificationMethod: [{ id: vm, type: 'JsonWebKey2020', controller: did,
                             publicKeyJwk: jwk }]
    };
    if (raw.use !== 'enc') {
      ['assertionMethod', 'authentication', 'capabilityInvocation',
       'capabilityDelegation'].forEach(function (r) {
        doc[r] = [vm];
      });
    }
    // The did:jwk method: `use` "sig" names no key agreement, "enc" only
    // key agreement, and no `use` both.
    if (raw.use !== 'sig') {
      doc.keyAgreement = [vm];
    }
    log.debug("Leaving VcDidResolver.didJwkDocument().");
    return doc;
  }

  // An error result, with every member section 7.1 says an unsuccessful
  // resolution has.
  private failed(error: string, message: string,
                 representation: boolean): any {
    const { log } = this.deps;
    log.debug("Entering VcDidResolver.failed(). " + error);
    const out: any = { didResolutionMetadata: { error: error,
                                                errorMessage: message },
                       didDocumentMetadata: {} };
    if (representation) {
      out.didDocumentStream = '';
    } else {
      out.didDocument = null;
    }
    log.debug("Leaving VcDidResolver.failed().");
    return out;
  }

  // The document, or an error result.
  private async documentOf(did: string, req: any): Promise<any> {
    const { log, ownDid, ownDocument } = this.deps;
    log.debug("Entering VcDidResolver.documentOf().");
    if (!this.isDid(did)) {
      log.debug("Leaving VcDidResolver.documentOf(). Not a DID.");
      return { error: 'invalidDid', message: JSON.stringify(did) + ' is not ' +
               'a DID (DID Core section 3.1).' };
    }
    const method = did.split(':')[1];
    try {
      if (method === 'key') {
        log.debug("Leaving VcDidResolver.documentOf(). did:key.");
        return { document: this.didKeyDocument(did) };
      }
      if (method === 'jwk') {
        log.debug("Leaving VcDidResolver.documentOf(). did:jwk.");
        return { document: this.didJwkDocument(did) };
      }
    } catch (e) {
      log.debug("Caught in VcDidResolver.documentOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcDidResolver.documentOf(). Malformed key.");
      return { error: 'invalidDid', message: String((e && e.message) || e) };
    }
    if (method === 'web') {
      if (did !== ownDid(req)) {
        log.debug("Leaving VcDidResolver.documentOf(). Another did:web.");
        return { error: 'notFound', message: 'this resolver answers this ' +
                 'realm\'s own did:web (' + ownDid(req) + ') and fetches ' +
                 'no other.' };
      }
      log.debug("Leaving VcDidResolver.documentOf(). This realm's did:web.");
      return { document: await ownDocument(req) };
    }
    log.debug("Leaving VcDidResolver.documentOf(). Unsupported method.");
    return { error: 'methodNotSupported', message: 'did:' + method + ' is ' +
             'not a method this resolver supports (key, jwk, and this ' +
             'realm\'s web).' };
  }

  // ---------------------------------------------------------------------------
  // resolve() (section 7.1): the document as a data model.
  // ---------------------------------------------------------------------------
  async resolve(did: string, options: any, req: any): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcDidResolver.resolve().");
    const o = options || {};
    if (o.accept !== undefined) {
      log.debug("Leaving VcDidResolver.resolve(). accept given.");
      return this.failed('invalidOptions', 'accept MUST NOT be used with ' +
                         'resolve (section 7.1.1).', false);
    }
    const got = await this.documentOf(did, req);
    if (got.error) {
      log.debug("Leaving VcDidResolver.resolve(). " + got.error);
      return this.failed(got.error, got.message, false);
    }
    log.debug("Leaving VcDidResolver.resolve().");
    return { didDocument: got.document, didResolutionMetadata: {},
             didDocumentMetadata: {} };
  }

  // resolveRepresentation() (section 7.1): the document as bytes in a
  // representation — JSON, or JSON-LD (the default).
  async resolveRepresentation(did: string, options: any, req: any):
    Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcDidResolver.resolveRepresentation().");
    const o = options || {};
    const accept = o.accept === undefined ? JSONLD_TYPE : String(o.accept);
    if (accept !== JSON_TYPE && accept !== JSONLD_TYPE) {
      log.debug("Leaving VcDidResolver.resolveRepresentation(). " +
                "Unsupported representation.");
      return this.failed('representationNotSupported', accept + ' is not a ' +
                         'representation this resolver produces (' +
                         JSON_TYPE + ', ' + JSONLD_TYPE + ').', true);
    }
    const got = await this.documentOf(did, req);
    if (got.error) {
      log.debug("Leaving VcDidResolver.resolveRepresentation(). " +
                got.error);
      return this.failed(got.error, got.message, true);
    }
    const doc = Object.assign({}, got.document);
    if (accept === JSON_TYPE) {
      delete doc['@context'];
    }
    log.debug("Leaving VcDidResolver.resolveRepresentation().");
    return { didDocumentStream: JSON.stringify(doc),
             didResolutionMetadata: { contentType: accept },
             didDocumentMetadata: {} };
  }

  // ---------------------------------------------------------------------------
  // dereference() (section 7.2).
  // ---------------------------------------------------------------------------
  async dereference(didUrl: string, options: any, req: any): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcDidResolver.dereference().");
    const text = String(didUrl || '');
    const m = /^(did:[^/?#]+)([^?#]*)(\?[^#]*)?(#.*)?$/.exec(text);
    const fail = function (error: string, message: string): any {
      log.debug("Entering fail().");
      log.debug("Leaving fail().");
      return { dereferencingMetadata: { error: error,
                                        errorMessage: message },
               contentStream: '', contentMetadata: {} };
    };
    if (!m || !this.isDid(m[1])) {
      log.debug("Leaving VcDidResolver.dereference(). Not a DID URL.");
      // error-code: none — a DID Core result, not a response; the route
      // that answers it marks STS-VC-0109.
      return fail('invalidDidUrl', JSON.stringify(text) + ' is not a DID ' +
                  'URL (DID Core section 3.2).');
    }
    const got = await this.documentOf(m[1], req);
    if (got.error) {
      log.debug("Leaving VcDidResolver.dereference(). " + got.error);
      // error-code: none — a DID Core result, not a response; the route
      // that answers it marks STS-VC-0109.
      return fail(got.error === 'invalidDid' ? 'invalidDidUrl' : got.error,
                  got.message);
    }
    if (m[2] || m[3]) {
      log.debug("Leaving VcDidResolver.dereference(). Path or query.");
      // error-code: none — a DID Core result, not a response; the route
      // that answers it marks STS-VC-0109.
      return fail('notFound', 'this service defines no resource at a DID ' +
                  'URL path or query (' + (m[2] || '') + (m[3] || '') + ').');
    }
    const doc = got.document;
    const accept = options && options.accept === JSON_TYPE ? JSON_TYPE
                                                           : JSONLD_TYPE;
    if (!m[4]) {
      const primary = Object.assign({}, doc);
      if (accept === JSON_TYPE) {
        delete primary['@context'];
      }
      log.debug("Leaving VcDidResolver.dereference(). The document.");
      return { dereferencingMetadata: { contentType: accept },
               contentStream: JSON.stringify(primary),
               contentMetadata: {} };
    }
    const wanted = m[1] + m[4];
    const found = [].concat(doc.verificationMethod || [],
                            doc.service || []).filter(function (one: any) {
      return one && (one.id === wanted || one.id === m[4]);
    })[0];
    if (!found) {
      log.debug("Leaving VcDidResolver.dereference(). No such fragment.");
      // error-code: none — a DID Core result, not a response; the route
      // that answers it marks STS-VC-0109.
      return fail('notFound', 'the DID document has nothing with the id ' +
                  wanted + '.');
    }
    const secondary = accept === JSONLD_TYPE
      ? Object.assign({ '@context': doc['@context'] }, found) : found;
    log.debug("Leaving VcDidResolver.dereference(). A fragment.");
    return { dereferencingMetadata: { contentType: accept },
             contentStream: JSON.stringify(secondary),
             contentMetadata: {} };
  }
}

const slot = new InstanceSlot<VcDidResolver>(
  'oid4vc/vc_did_resolver',
  () => new VcDidResolver(VcDidResolver.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  VcDidResolver: VcDidResolver,
  installInstance: (instance: VcDidResolver): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  JSON_TYPE: JSON_TYPE,
  JSONLD_TYPE: JSONLD_TYPE,
  isDid: slot.forward('isDid'),
  resolve: slot.forward('resolve'),
  resolveRepresentation: slot.forward('resolveRepresentation'),
  dereference: slot.forward('dereference')
};
