'use strict';
//
// File: vc_data_model.ts
//
// ---------------------------------------------------------------------------
// THE W3C VERIFIABLE CREDENTIALS DATA MODEL'S "MUST"s, CHECKED (#194,
// 2026-09-26): what a conforming issuer refuses to secure and a conforming
// verifier refuses to accept, whatever securing mechanism is on it.
//
// Until #194 this service never received a credential it had not built
// itself except as a PRESENTATION, and the Verifier judged those by what its
// DCQL query asked for. The W3C VC Data Model 2.0 test suite drives an
// issuer and a verifier with documents somebody else wrote, and every one of
// its negative fixtures is a sentence of the Recommendation this file turns
// into a refusal. Each check names the section it enforces; the list:
//
//   4.3  @context — present; an ordered set whose FIRST item is the base
//        context (`https://www.w3.org/ns/credentials/v2`, or the 1.1 one for
//        a 1.1 credential); every later item a URL or an object. A string
//        alone is the one-item set (an enveloped credential is written so).
//   4.4  id — when present, ONE URL.
//   4.5  type — present; includes VerifiableCredential /
//        VerifiablePresentation; and every value maps to a URL (the JSON-LD
//        half, `vc_jsonld.ts`'s safe-mode expansion, is the caller's).
//   4.6  name, description — a string, a language value object, or an array
//        of either.
//   4.7  issuer — a URL, or an object whose `id` is one.
//   4.8  credentialSubject — one or more objects, each making at least one
//        claim; a subject's `id` is one URL.
//   4.9  validFrom, validUntil — XML Schema dateTimeStamp (a time zone is
//        required); validFrom no later than validUntil; and, when verifying,
//        the credential valid now.
//   4.10 credentialStatus — each with a type, and an id that is one URL.
//   4.11 credentialSchema — each with an id (one URL) and a type.
//   4.13 a presentation's holder (a URL or an object with an id) and its
//        verifiableCredential values (objects, never strings or URLs).
//   5.3  relatedResource — objects, each an id unique in the list and a
//        digestSRI or digestMultibase, and the digest MATCHING the resource
//        where this service holds it (the contexts `vc_jsonld.ts` ships). A
//        resource this service does not hold cannot be retrieved — nothing
//        here fetches a URL a caller supplied — and is a warning.
//   5.4  refreshService, 5.5 termsOfUse, 5.6 evidence — each with a type.
//   4.12 an embedded proof has a type.
//
// And the 1.1 model for a credential whose first context is the 1.1 one:
// `issuanceDate` required, `expirationDate` optional, both XML Schema
// dateTimes.
//
// Every check answers `{ ok, problems, warnings }`, where a problem is
// `{ where, message }`; nothing here throws for a malformed document.
//
// A LIBRARY (rule 3): no route. It requires `vc_jsonld.ts` for the held
// resources' bytes and `common/` leaves.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import vcJsonLd = require('./vc_jsonld');

interface VcDataModelDeps {
  log: typeof helpers.log;
  resourceBytes: (url: string) => Buffer | null;
  now: () => number;
}

interface Problem {
  where: string;
  message: string;
}

const V2 = 'https://www.w3.org/ns/credentials/v2';
const V1 = 'https://www.w3.org/2018/credentials/v1';

// XML Schema 1.1 dateTimeStamp: a dateTime WITH a time zone.
const DATE_TIME_STAMP = new RegExp('^-?\\d{4,}-(0[1-9]|1[0-2])-' +
  '(0[1-9]|[12]\\d|3[01])T([01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(\\.\\d+)?' +
  '(Z|[+-]((0\\d|1[0-3]):[0-5]\\d|14:00))$');
// XML Schema dateTime, the 1.1 model's: the time zone optional.
const DATE_TIME = new RegExp('^-?\\d{4,}-(0[1-9]|1[0-2])-' +
  '(0[1-9]|[12]\\d|3[01])T([01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(\\.\\d+)?' +
  '(Z|[+-]((0\\d|1[0-3]):[0-5]\\d|14:00))?$');

// RFC 3986's scheme, then no white space anywhere.
const ABSOLUTE_URL = /^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$/;

class VcDataModel {
  static readonly V2 = V2;
  static readonly V1 = V1;

  constructor(private readonly deps: VcDataModelDeps) {
    deps.log.debug("Entering VcDataModel.constructor().");
    deps.log.debug("Leaving VcDataModel.constructor().");
  }

  static defaultDeps(): VcDataModelDeps {
    helpers.log.debug("Entering VcDataModel.defaultDeps().");
    helpers.log.debug("Leaving VcDataModel.defaultDeps().");
    return {
      log: helpers.log,
      resourceBytes: function resourceBytes(url: string): Buffer | null {
        helpers.log.debug("Entering resourceBytes().");
        helpers.log.debug("Leaving resourceBytes().");
        return vcJsonLd.resourceBytes(url);
      },
      now: function now(): number {
        helpers.log.debug("Entering now().");
        helpers.log.debug("Leaving now().");
        return Date.now();
      }
    };
  }

  // Is this ONE absolute URL (VCDM 2.0 section 4.4's "URL")?
  isUrl(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.isUrl().");
    if (typeof value !== 'string' || !ABSOLUTE_URL.test(value)) {
      log.debug("Leaving VcDataModel.isUrl(). No.");
      return false;
    }
    try {
      new URL(value);
    } catch (e) {
      log.debug("Caught in VcDataModel.isUrl(): " + ((e && e.message) || e));
      log.debug("Leaving VcDataModel.isUrl(). Unparseable.");
      return false;
    }
    log.debug("Leaving VcDataModel.isUrl(). Yes.");
    return true;
  }

  private isMap(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.isMap().");
    log.debug("Leaving VcDataModel.isMap().");
    return !!value && typeof value === 'object' && !Array.isArray(value);
  }

  // The values of a property that may be one value or an array of them.
  private many(value: unknown): unknown[] {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.many().");
    log.debug("Leaving VcDataModel.many().");
    return value === undefined ? [] : [].concat(value);
  }

  // The data model version a document's @context says it is: '2.0', '1.1',
  // or '' when the first item is neither base context.
  versionOf(document: any): string {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.versionOf().");
    const first = document && document['@context'] !== undefined
      ? [].concat(document['@context'])[0] : undefined;
    log.debug("Leaving VcDataModel.versionOf().");
    return first === V2 ? '2.0' : (first === V1 ? '1.1' : '');
  }

  // 4.3.
  private checkContext(doc: any, where: string, out: Problem[]): void {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.checkContext().");
    if (doc['@context'] === undefined) {
      out.push({ where: where + '@context', message: '@context is missing ' +
                 '(VCDM 2.0 section 4.3: it MUST be present).' });
      log.debug("Leaving VcDataModel.checkContext(). Missing.");
      return;
    }
    const items = [].concat(doc['@context']);
    if (!items.length || (items[0] !== V2 && items[0] !== V1)) {
      out.push({ where: where + '@context', message: 'the first item of ' +
                 '@context MUST be ' + V2 + ' (or ' + V1 + ' for a 1.1 ' +
                 'credential); it is ' + JSON.stringify(items[0]) + '.' });
    }
    const self = this;
    items.slice(1).forEach(function (item, i) {
      if (typeof item === 'string' ? !self.isUrl(item) : !self.isMap(item)) {
        out.push({ where: where + '@context[' + (i + 1) + ']',
                   message: 'every later @context item MUST be a URL or ' +
                            'an object; this is ' + JSON.stringify(item) +
                            '.' });
      }
    });
    log.debug("Leaving VcDataModel.checkContext().");
  }

  // 4.4 for a node: `id`, when present, is one URL.
  private checkId(node: any, where: string, out: Problem[]): void {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.checkId().");
    if (node && node.id !== undefined && !this.isUrl(node.id)) {
      out.push({ where: where + 'id', message: 'id MUST be a single URL; ' +
                 'it is ' + JSON.stringify(node.id) + '.' });
    }
    log.debug("Leaving VcDataModel.checkId().");
  }

  // 4.5: type present, strings, including `required`.
  private checkType(node: any, where: string, required: string,
                    out: Problem[]): void {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.checkType(). " + required);
    if (!node || node.type === undefined) {
      out.push({ where: where + 'type', message: 'type is missing (VCDM ' +
                 '2.0 section 4.5: it MUST be present).' });
      log.debug("Leaving VcDataModel.checkType(). Missing.");
      return;
    }
    const types = [].concat(node.type);
    if (!types.length || types.some(function (t) {
      return typeof t !== 'string' || !t;
    })) {
      out.push({ where: where + 'type', message: 'type MUST be one or more ' +
                 'terms or URLs; it is ' + JSON.stringify(node.type) + '.' });
    }
    if (required && types.indexOf(required) < 0) {
      out.push({ where: where + 'type', message: 'type MUST include ' +
                 required + '; it is ' + JSON.stringify(node.type) + '.' });
    }
    log.debug("Leaving VcDataModel.checkType().");
  }

  // A property whose every value MUST carry a type (4.10, 4.11, 5.4-5.6,
  // and an embedded proof).
  private checkTyped(doc: any, property: string, where: string,
                     out: Problem[], needsId: boolean): void {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.checkTyped(). " + property);
    if (doc[property] === undefined) {
      log.debug("Leaving VcDataModel.checkTyped(). Absent.");
      return;
    }
    const values = this.many(doc[property]);
    const self = this;
    if (!values.length) {
      out.push({ where: where + property, message: property + ' is an ' +
                 'empty list; it MUST name at least one value when present.' });
    }
    values.forEach(function (value: any, i) {
      const at = where + property + (values.length > 1 ? '[' + i + ']' : '');
      if (!self.isMap(value)) {
        out.push({ where: at, message: 'each ' + property + ' value MUST ' +
                   'be an object.' });
        return;
      }
      if (value.type === undefined) {
        out.push({ where: at + '.type', message: 'each ' + property +
                   ' value MUST specify its type.' });
      } else if ([].concat(value.type).some(function (t) {
        return typeof t !== 'string' || !t;
      })) {
        out.push({ where: at + '.type', message: 'a type is a term or a ' +
                   'URL; this is ' + JSON.stringify(value.type) + '.' });
      }
      if (needsId && value.id === undefined) {
        out.push({ where: at + '.id', message: 'each ' + property +
                   ' value MUST have an id.' });
      }
      self.checkId(value, at + '.', out);
    });
    log.debug("Leaving VcDataModel.checkTyped().");
  }

  // 4.6: name and description.
  private checkLanguageValues(doc: any, where: string,
                              out: Problem[]): void {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.checkLanguageValues().");
    const self = this;
    ['name', 'description'].forEach(function (property) {
      if (doc[property] === undefined) {
        return;
      }
      self.many(doc[property]).forEach(function (value: any) {
        const ok = typeof value === 'string' || (self.isMap(value) &&
          typeof value['@value'] === 'string' &&
          (value['@language'] === undefined ||
           typeof value['@language'] === 'string') &&
          (value['@direction'] === undefined ||
           value['@direction'] === 'ltr' || value['@direction'] === 'rtl') &&
          Object.keys(value).every(function (k) {
            return ['@value', '@language', '@direction'].indexOf(k) >= 0;
          }));
        if (!ok) {
          out.push({ where: where + property, message: property + ' MUST ' +
                     'be a string or a language value object; it is ' +
                     JSON.stringify(value) + '.' });
        }
      });
    });
    log.debug("Leaving VcDataModel.checkLanguageValues().");
  }

  // 4.9 (and the 1.1 dates): format and order; when `atTime` is given, that
  // the credential is valid then.
  private checkValidity(vc: any, version: string, atTime: number,
                        out: Problem[]): void {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.checkValidity(). " + version);
    const from = version === '1.1' ? 'issuanceDate' : 'validFrom';
    const until = version === '1.1' ? 'expirationDate' : 'validUntil';
    const pattern = version === '1.1' ? DATE_TIME : DATE_TIME_STAMP;
    if (version === '1.1' && vc.issuanceDate === undefined) {
      out.push({ where: 'issuanceDate', message: 'a 1.1 credential MUST ' +
                 'have an issuanceDate.' });
    }
    const times: Record<string, number> = {};
    [from, until].forEach(function (property) {
      if (vc[property] === undefined) {
        return;
      }
      if (typeof vc[property] !== 'string' || !pattern.test(vc[property]) ||
          isNaN(Date.parse(vc[property]))) {
        out.push({ where: property, message: property + ' MUST be an XML ' +
                   'Schema ' + (version === '1.1' ? 'dateTime' :
                   'dateTimeStamp (with a time zone)') + '; it is ' +
                   JSON.stringify(vc[property]) + '.' });
        return;
      }
      times[property] = Date.parse(vc[property]);
    });
    if (times[from] !== undefined && times[until] !== undefined &&
        times[from] > times[until]) {
      out.push({ where: until, message: from + ' (' + vc[from] + ') MUST ' +
                 'be no later than ' + until + ' (' + vc[until] + ').' });
    }
    if (typeof atTime === 'number') {
      if (times[from] !== undefined && times[from] > atTime) {
        out.push({ where: from, message: 'the credential is not valid yet ' +
                   '(' + from + ' ' + vc[from] + ').' });
      }
      if (times[until] !== undefined && times[until] < atTime) {
        out.push({ where: until, message: 'the credential has expired (' +
                   until + ' ' + vc[until] + ').' });
      }
    }
    log.debug("Leaving VcDataModel.checkValidity().");
  }

  // 5.3: relatedResource, digests checked where the resource is held.
  private checkRelatedResources(vc: any, out: Problem[],
                                warnings: string[]): void {
    const { log, resourceBytes } = this.deps;
    log.debug("Entering VcDataModel.checkRelatedResources().");
    if (vc.relatedResource === undefined) {
      log.debug("Leaving VcDataModel.checkRelatedResources(). None.");
      return;
    }
    const seen: string[] = [];
    const self = this;
    this.many(vc.relatedResource).forEach(function (one: any, i) {
      const at = 'relatedResource[' + i + ']';
      if (!self.isMap(one)) {
        out.push({ where: at, message: 'each relatedResource MUST be an ' +
                   'object; this is ' + JSON.stringify(one) + '.' });
        return;
      }
      if (!self.isUrl(one.id)) {
        out.push({ where: at + '.id', message: 'a related resource\'s id ' +
                   'is REQUIRED and is one URL.' });
        return;
      }
      if (seen.indexOf(one.id) >= 0) {
        out.push({ where: at + '.id', message: 'a related resource\'s id ' +
                   'MUST be unique in the list; ' + one.id + ' repeats.' });
      }
      seen.push(one.id);
      if (one.digestSRI === undefined && one.digestMultibase === undefined) {
        out.push({ where: at, message: 'a related resource MUST have a ' +
                   'digestSRI or a digestMultibase.' });
        return;
      }
      const bytes = resourceBytes(one.id);
      if (!bytes) {
        warnings.push(at + ': ' + one.id + ' is not a resource this ' +
                      'service holds, and it fetches none, so its digest ' +
                      'was not checked.');
        return;
      }
      if (one.digestSRI !== undefined) {
        const m = /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/
          .exec(String(one.digestSRI));
        const ok = !!m && crypto.createHash(m[1]).update(bytes)
          .digest('base64') === m[2];
        if (!ok) {
          out.push({ where: at + '.digestSRI', message: 'the digestSRI does ' +
                     'not match ' + one.id + '.' });
        }
      }
      if (one.digestMultibase !== undefined) {
        const text = String(one.digestMultibase);
        const ok = text.charAt(0) === 'u' &&
          crypto.createHash('sha256').update(bytes).digest('base64url') ===
            text.slice(1);
        if (!ok) {
          out.push({ where: at + '.digestMultibase', message: 'the ' +
                     'digestMultibase does not match ' + one.id +
                     ' (a base64url SHA-256, "u"-prefixed).' });
        }
      }
    });
    log.debug("Leaving VcDataModel.checkRelatedResources().");
  }

  // ---------------------------------------------------------------------------
  // A CREDENTIAL. `opts.atTime` (a time in ms) asks for the validity window
  // too, which a verifier does and an issuer does not; `opts.enveloped`
  // accepts an EnvelopedVerifiableCredential (its shape only — the envelope's
  // contents are the securing mechanism's to open).
  // ---------------------------------------------------------------------------
  checkCredential(vc: any, opts?: { atTime?: number; enveloped?: boolean;
                                    where?: string }): any {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.checkCredential().");
    const o = opts || {};
    const where = o.where || '';
    const out: Problem[] = [];
    const warnings: string[] = [];
    if (!this.isMap(vc)) {
      out.push({ where: where || '(document)', message: 'a verifiable ' +
                 'credential is a JSON object.' });
      log.debug("Leaving VcDataModel.checkCredential(). Not a map.");
      return { ok: false, problems: out, warnings: warnings };
    }
    this.checkContext(vc, where, out);
    const types = vc.type === undefined ? [] : [].concat(vc.type);
    if (o.enveloped && types.indexOf('EnvelopedVerifiableCredential') >= 0) {
      this.checkEnvelope(vc, 'EnvelopedVerifiableCredential', where, out);
      log.debug("Leaving VcDataModel.checkCredential(). An envelope.");
      return { ok: !out.length, problems: out, warnings: warnings };
    }
    const version = this.versionOf(vc) || '2.0';
    this.checkId(vc, where, out);
    this.checkType(vc, where, 'VerifiableCredential', out);
    this.checkLanguageValues(vc, where, out);
    if (vc.issuer === undefined) {
      out.push({ where: where + 'issuer', message: 'issuer is missing (VCDM ' +
                 '2.0 section 4.7: it MUST be present).' });
    } else if (typeof vc.issuer === 'string') {
      if (!this.isUrl(vc.issuer)) {
        out.push({ where: where + 'issuer', message: 'issuer MUST be a URL ' +
                   'or an object with an id; it is ' +
                   JSON.stringify(vc.issuer) + '.' });
      }
    } else if (!this.isMap(vc.issuer) || !this.isUrl(vc.issuer.id)) {
      out.push({ where: where + 'issuer', message: 'issuer MUST be a URL or ' +
                 'an object whose id is a URL; it is ' +
                 JSON.stringify(vc.issuer) + '.' });
    } else {
      this.checkLanguageValues(vc.issuer, where + 'issuer.', out);
    }
    if (vc.credentialSubject === undefined) {
      out.push({ where: where + 'credentialSubject', message: 'the ' +
                 'credentialSubject is missing (section 4.8: it MUST be ' +
                 'present).' });
    } else {
      const subjects = this.many(vc.credentialSubject);
      const self = this;
      if (!subjects.length) {
        out.push({ where: where + 'credentialSubject', message: 'the ' +
                   'credentialSubject MUST name one or more subjects.' });
      }
      subjects.forEach(function (subject: any, i) {
        const at = where + 'credentialSubject' +
          (subjects.length > 1 ? '[' + i + ']' : '');
        if (!self.isMap(subject)) {
          out.push({ where: at, message: 'a credentialSubject MUST be an ' +
                     'object.' });
          return;
        }
        if (!Object.keys(subject).length) {
          out.push({ where: at, message: 'a credentialSubject MUST make at ' +
                     'least one claim; this one is empty.' });
        }
        self.checkId(subject, at + '.', out);
      });
    }
    this.checkValidity(vc, version, o.atTime, out);
    this.checkTyped(vc, 'credentialStatus', where, out, false);
    this.checkTyped(vc, 'credentialSchema', where, out, true);
    this.checkTyped(vc, 'refreshService', where, out, false);
    this.checkTyped(vc, 'termsOfUse', where, out, false);
    this.checkTyped(vc, 'evidence', where, out, false);
    this.checkTyped(vc, 'proof', where, out, false);
    this.checkRelatedResources(vc, out, warnings);
    log.debug("Leaving VcDataModel.checkCredential(). " + out.length +
              " problem(s).");
    return { ok: !out.length, problems: out, warnings: warnings };
  }

  // 4.12.1 / 4.12.2: an enveloped credential or presentation — `@context`,
  // the type, and an id that is a data: URL.
  private checkEnvelope(doc: any, type: string, where: string,
                        out: Problem[]): void {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.checkEnvelope(). " + type);
    const types = [].concat(doc.type);
    if (types.length !== 1 || types[0] !== type) {
      out.push({ where: where + 'type', message: 'the type of an ' +
                 'enveloped object MUST be ' + type + '.' });
    }
    if (typeof doc.id !== 'string' || !/^data:[^,]*,/.test(doc.id)) {
      out.push({ where: where + 'id', message: 'the id of an enveloped ' +
                 'object MUST be a data: URL (RFC 2397).' });
    }
    log.debug("Leaving VcDataModel.checkEnvelope().");
  }

  // ---------------------------------------------------------------------------
  // A PRESENTATION, and every credential in it.
  // ---------------------------------------------------------------------------
  checkPresentation(vp: any, opts?: { atTime?: number }): any {
    const { log } = this.deps;
    log.debug("Entering VcDataModel.checkPresentation().");
    const o = opts || {};
    const out: Problem[] = [];
    const warnings: string[] = [];
    if (!this.isMap(vp)) {
      out.push({ where: '(document)', message: 'a verifiable presentation ' +
                 'is a JSON object.' });
      log.debug("Leaving VcDataModel.checkPresentation(). Not a map.");
      return { ok: false, problems: out, warnings: warnings };
    }
    this.checkContext(vp, '', out);
    const types = vp.type === undefined ? [] : [].concat(vp.type);
    if (types.indexOf('EnvelopedVerifiablePresentation') >= 0) {
      this.checkEnvelope(vp, 'EnvelopedVerifiablePresentation', '', out);
      log.debug("Leaving VcDataModel.checkPresentation(). An envelope.");
      return { ok: !out.length, problems: out, warnings: warnings };
    }
    this.checkId(vp, '', out);
    this.checkType(vp, '', 'VerifiablePresentation', out);
    this.checkLanguageValues(vp, '', out);
    if (vp.holder !== undefined) {
      const ok = typeof vp.holder === 'string' ? this.isUrl(vp.holder)
        : (this.isMap(vp.holder) && this.isUrl(vp.holder.id));
      if (!ok) {
        out.push({ where: 'holder', message: 'holder MUST be a URL or an ' +
                   'object with an id that is one; it is ' +
                   JSON.stringify(vp.holder) + '.' });
      }
    }
    const self = this;
    this.many(vp.verifiableCredential).forEach(function (vc: any, i) {
      const at = 'verifiableCredential[' + i + '].';
      if (!self.isMap(vc)) {
        out.push({ where: 'verifiableCredential[' + i + ']', message: 'a ' +
                   'presentation\'s credentials MUST be objects, never a ' +
                   'string, number or URL.' });
        return;
      }
      const checked = self.checkCredential(vc, { atTime: o.atTime,
                                                 enveloped: true, where: at });
      checked.problems.forEach(function (p: Problem) {
        out.push(p);
      });
      checked.warnings.forEach(function (w: string) {
        warnings.push(w);
      });
    });
    this.checkTyped(vp, 'proof', '', out, false);
    log.debug("Leaving VcDataModel.checkPresentation(). " + out.length +
              " problem(s).");
    return { ok: !out.length, problems: out, warnings: warnings };
  }
}

const slot = new InstanceSlot<VcDataModel>(
  'oid4vc/vc_data_model',
  () => new VcDataModel(VcDataModel.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  VcDataModel: VcDataModel,
  installInstance: (instance: VcDataModel): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  V2: V2,
  V1: V1,
  isUrl: slot.forward('isUrl'),
  versionOf: slot.forward('versionOf'),
  checkCredential: slot.forward('checkCredential'),
  checkPresentation: slot.forward('checkPresentation')
};
