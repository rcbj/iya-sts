'use strict';
//
// File: risk/risk_terms.ts
//
// ===========================================================================
// WHOSE DATA A DATASET IS, ON WHAT TERMS — AND WHO ACCEPTED THEM (#62,
// 2026-09-23, the second independent licence review).
//
// **iya-sts DISTRIBUTES NO THIRD-PARTY DATASET.** Every dataset risk scoring
// reads is an ADMINISTRATOR-SUPPLIED input: the deployment obtains it under
// its provider's terms and pulls it into its own database (`risk_install.ts`,
// the dataset directory, or an upload). The first licence review drew that
// line; this file is what the second one asked for on top of it:
//
//   * **AN ACCEPTANCE IS RECORDED, AND AN IMPORT NEEDS ONE.** No provider's
//     data is imported — by the install-time loader, the console, the API or
//     the dataset directory — unless somebody has accepted that provider's
//     CURRENT terms: who, through which door, from which deployment, when,
//     and the terms text itself (`sts_risk_terms_acceptances`, schema 8).
//     The operator's own list is theirs and needs none.
//   * **TERMS THAT CHANGE MUST BE ACCEPTED AGAIN.** An acceptance is of a
//     DIGEST of the terms as this build states them. A later build that
//     restates a provider's terms changes the digest, and imports of that
//     provider stop until somebody accepts the new text. The install-time
//     loader can also fetch the provider's own terms page (`--check-terms`)
//     and warns when it differs from the page seen at the last acceptance.
//   * **CREDIT AS THE LICENCE ASKS.** A result is credited with the
//     provider's attribution, LINKED, with the licence named and linked and
//     the note that it was imported and reformatted here — what CC BY 4.0
//     section 3(a) asks of a re-user (DB-IP), and CC BY-SA the same
//     (IPinfo). `attributionOf()` builds it; every page and answer that shows
//     a result carries it.
//
// A LIBRARY (rule 3): no route. It requires `risk_store` and the digest
// function in `common/crypto.js`.
// ===========================================================================

import bunyan = require('bunyan');
import os = require('os');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import riskStore = require('./risk_store');

const log = bunyan.createLogger({ name: 'sts-risk-terms' });
config.registerLogger(log);

type Json = any;

// ---------------------------------------------------------------------------
// THE PROVIDERS. `terms` is this build's statement of what binds the
// deployment; `licenceUrl` is the licence a credit links to; `termsUrl` is
// the page `--check-terms` fetches. `supported: false` names a provider the
// plan uses later — nothing can be imported from it, and nothing needs
// accepting yet.
// ---------------------------------------------------------------------------
const PROVIDERS: Record<string, Json> = {
  'dbip-lite': { title: 'DB-IP Lite', licence: 'CC-BY-4.0',
    licenceName: 'CC BY 4.0',
    licenceUrl: 'https://creativecommons.org/licenses/by/4.0/',
    attribution: 'IP Geolocation by DB-IP', url: 'https://db-ip.com',
    termsUrl: 'https://db-ip.com/db/lite.php', supported: true,
    terms: 'CC BY 4.0. A web application must link back to DB-IP on the ' +
           'pages that display or use its results; this service draws that ' +
           'link, with the licence, wherever a result is shown. The ' +
           'recommended default for geolocation and ASN: attribution and ' +
           'no ShareAlike.' },
  'ipinfo-lite': { title: 'IPinfo Lite', licence: 'CC-BY-SA-4.0',
    licenceName: 'CC BY-SA 4.0',
    licenceUrl: 'https://creativecommons.org/licenses/by-sa/4.0/',
    attribution: 'IP address data powered by IPinfo',
    url: 'https://ipinfo.io', termsUrl: 'https://ipinfo.io/lite',
    supported: true,
    terms: 'CC BY-SA 4.0 — ShareAlike. IPinfo data must remain isolated in ' +
           'this deployment\'s database; do not bundle it with a software ' +
           'distribution. Nothing IPinfo-derived is distributed with ' +
           'iya-sts, and a deployment that distributes its own populated ' +
           'database has ShareAlike to resolve first. DB-IP Lite covers ' +
           'the same country and ASN data without ShareAlike.' },
  'tor-project': { title: 'Tor Project exit list',
    licence: 'as published by the Tor Project', licenceName: '',
    licenceUrl: '', attribution: 'Tor exit list from the Tor Project',
    url: 'https://check.torproject.org/torbulkexitlist', termsUrl: '',
    supported: true,
    terms: 'Published by the Tor Project; check the terms of the exact list ' +
           'you download. Administrator-supplied, never shipped.' },
  'firehol': { title: 'FireHOL blocklist-ipsets',
    licence: 'per constituent list', licenceName: '', licenceUrl: '',
    attribution: 'FireHOL blocklist-ipsets',
    url: 'https://github.com/firehol/blocklist-ipsets',
    termsUrl: 'https://github.com/firehol/blocklist-ipsets', supported: true,
    terms: 'An AGGREGATE: each constituent list (level 1 carries DShield, ' +
           'Feodo, Fullbogons and Spamhaus DROP, among others) has terms of ' +
           'its own, which the aggregate does not replace. ' +
           'Administrator-supplied and used internally; iya-sts neither ' +
           'ships nor redistributes it.' },
  'operator': { title: 'The operator', licence: 'as supplied by the operator',
    licenceName: '', licenceUrl: '', attribution: '', url: '', termsUrl: '',
    supported: true,
    terms: 'The operator\'s own list, under whatever terms the operator ' +
           'holds it. Nothing to accept.' },
  'maxmind-geolite2': { title: 'MaxMind GeoLite2', licence: 'GeoLite EULA',
    licenceName: 'GeoLite EULA',
    licenceUrl: 'https://www.maxmind.com/en/geolite2/eula',
    attribution: 'GeoLite2 data created by MaxMind',
    url: 'https://www.maxmind.com',
    termsUrl: 'https://www.maxmind.com/en/geolite2/eula', supported: false,
    terms: 'Not supported (decided 2026-09-23): it requires deletion within ' +
           '30 days of a newer release and forbids redistribution, and ' +
           'DB-IP Lite and IPinfo Lite cover what it would add. Never ' +
           'shipped.' },
  'fido-mds3': { title: 'FIDO Metadata Service (MDS3)',
    licence: 'FIDO Alliance metadata terms', licenceName: '',
    licenceUrl: '', attribution: '',
    url: 'https://fidoalliance.org/metadata/',
    termsUrl: 'https://fidoalliance.org/metadata/', supported: true,
    terms: 'Contractual terms, not open data: use is for enabling FIDO ' +
           'authentication, the latest valid BLOB must be used and a ' +
           'statement no longer in it deleted, and copying or ' +
           'redistributing the metadata is restricted. Fetched by the ' +
           'deployment (the install-time loader, or an upload), verified ' +
           'against the FIDO root before anything is kept, and only the ' +
           'latest BLOB kept; never shipped, and tested with a synthetic ' +
           'BLOB.' },
  'hibp-pwned-passwords': { title: 'Pwned Passwords (Have I Been Pwned)',
    licence: 'HIBP Pwned Passwords terms', licenceName: '', licenceUrl: '',
    attribution: '', url: 'https://haveibeenpwned.com/Passwords',
    termsUrl: 'https://haveibeenpwned.com/Passwords', supported: false,
    terms: 'Not CC BY 4.0 (that is HIBP\'s breach and paste data): the ' +
           'Pwned Passwords API carries no licensing or attribution ' +
           'requirement. The downloadable corpus\'s terms are checked — by ' +
           'the install-time loader\'s --check-terms, and by the ' +
           'deployment — before the filter is built from its own download ' +
           '(P6); the filter is never shipped.' }
};

interface RiskTermsDeps {
  log: { debug(m: string): void; info(m: string): void; warn(m: string): void };
  store: typeof riskStore;
  now(): number;
  audit(): Json;
}

class RiskTerms {
  static readonly PROVIDERS = PROVIDERS;

  constructor(private readonly deps: RiskTermsDeps) {
    deps.log.debug("Entering RiskTerms.constructor().");
    deps.log.debug("Leaving RiskTerms.constructor().");
  }

  static defaultDeps(): RiskTermsDeps {
    log.debug("Entering RiskTerms.defaultDeps().");
    log.debug("Leaving RiskTerms.defaultDeps().");
    return {
      log: log,
      store: riskStore,
      now: function (): number {
        return Date.now();
      },
      audit: function (): Json {
        return require('../common/audit');
      }
    };
  }

  // -------------------------------------------------------------------------
  // A provider's terms as this build states them, and their digest: the
  // text an acceptance is OF. Everything a person accepting reads is in the
  // text — licence, links, terms — so a change to any of it is a change of
  // terms.
  // -------------------------------------------------------------------------
  static termsOf(providerId: string): Json | null {
    log.debug("Entering RiskTerms.termsOf(). " + providerId);
    const p = PROVIDERS[providerId];
    if (!p) {
      log.debug("Leaving RiskTerms.termsOf(). Unknown.");
      return null;
    }
    const text = p.title + '\n' + 'Licence: ' + p.licence +
      (p.licenceUrl ? ' (' + p.licenceUrl + ')' : '') + '\n' +
      (p.url ? 'Source: ' + p.url + '\n' : '') + p.terms;
    log.debug("Leaving RiskTerms.termsOf().");
    return { provider: providerId, text: text,
             digest: stsCrypto.truncatedSha256Hex(text, 64) };
  }

  // Whether a provider's data needs an acceptance before it is imported:
  // every supported provider but the operator's own list.
  static needsAcceptance(providerId: string): boolean {
    log.debug("Entering RiskTerms.needsAcceptance(). " + providerId);
    const p = PROVIDERS[providerId];
    log.debug("Leaving RiskTerms.needsAcceptance().");
    return !!p && p.supported && providerId !== 'operator';
  }

  // -------------------------------------------------------------------------
  // A result's credit, as CC BY 4.0 section 3(a) asks of a re-user: the
  // attribution, linked to the source; the licence, named and linked; and
  // that the data was modified (imported and reformatted here). null for a
  // provider with nothing to credit (the operator's own list).
  // -------------------------------------------------------------------------
  static attributionOf(providerId: string): Json | null {
    log.debug("Entering RiskTerms.attributionOf(). " + providerId);
    const p = PROVIDERS[providerId];
    if (!p || !p.attribution) {
      log.debug("Leaving RiskTerms.attributionOf(). Nothing to credit.");
      return null;
    }
    log.debug("Leaving RiskTerms.attributionOf().");
    return { provider: providerId, text: p.attribution, url: p.url,
             licence: p.licenceName || p.licence,
             licenceUrl: p.licenceUrl,
             modified: 'imported into this service\'s database and ' +
                       'reformatted; provided as is, without warranties' };
  }

  // The acceptance that covers a provider's CURRENT terms, or null.
  async currentFor(providerId: string): Promise<Json | null> {
    const { log, store } = this.deps;
    log.debug("Entering RiskTerms.currentFor(). " + providerId);
    const terms = RiskTerms.termsOf(providerId);
    if (!terms) {
      log.debug("Leaving RiskTerms.currentFor(). Unknown provider.");
      return null;
    }
    const rows = await store.listAcceptances();
    const found = rows.filter(function (a: Json): boolean {
      return a.provider === providerId && a.termsDigest === terms.digest;
    })[0] || null;
    log.debug("Leaving RiskTerms.currentFor(). " + (found ? 'Accepted.'
                                                          : 'None.'));
    return found;
  }

  // -------------------------------------------------------------------------
  // ACCEPT a provider's current terms: `{ provider, acceptedBy, via,
  // deployment?, pageDigest? }`. Recorded in the store and on the audit log.
  // Answers { ok, acceptance } or a refusal.
  // -------------------------------------------------------------------------
  async accept(o: Json): Promise<Json> {
    const { log, store, now, audit } = this.deps;
    log.debug("Entering RiskTerms.accept(). " + o.provider);
    const providerId = String(o.provider || '');
    if (!RiskTerms.needsAcceptance(providerId)) {
      log.debug("Leaving RiskTerms.accept(). Nothing to accept.");
      return errorCodes.mark({ ok: false, errors: [PROVIDERS[providerId]
        ? PROVIDERS[providerId].title + ' has no terms to accept here' +
          (PROVIDERS[providerId].supported ? '.' : ': it is not supported.')
        : 'There is no provider "' + providerId + '".'] }, 'STS-RISK-0014');
    }
    const terms = RiskTerms.termsOf(providerId);
    const row = {
      provider: providerId, termsDigest: terms.digest, termsText: terms.text,
      acceptedBy: String(o.acceptedBy || 'unnamed'),
      acceptedVia: String(o.via || 'unstated'),
      deployment: String(o.deployment || os.hostname()),
      pageDigest: String(o.pageDigest || ''), acceptedAt: now() };
    const id = await store.recordAcceptance(row);
    audit().audit({
      action: 'risk.terms.accept', outcome: 'success',
      actor: row.acceptedBy, protocol: 'Risk scoring',
      channel: row.acceptedVia, target: providerId,
      summary: row.acceptedBy + ' accepted the terms of ' +
               PROVIDERS[providerId].title + ' (digest ' +
               terms.digest.slice(0, 12) + ') through ' + row.acceptedVia,
      detail: { deployment: row.deployment, digest: terms.digest,
                pageDigest: row.pageDigest }
    });
    log.info('risk: ' + row.acceptedBy + ' accepted the terms of ' +
             PROVIDERS[providerId].title + ' through ' + row.acceptedVia +
             ' on ' + row.deployment + '.');
    log.debug("Leaving RiskTerms.accept().");
    return { ok: true, acceptance: Object.assign({ id: id }, row),
             message: 'The terms of ' + PROVIDERS[providerId].title +
                      ' are accepted by ' + row.acceptedBy + '.' };
  }

  // -------------------------------------------------------------------------
  // Every provider, its terms, and where acceptance stands: `accepted` (the
  // acceptance of the current terms), `changed` (accepted once, but the
  // terms have changed since), or neither; with every acceptance recorded.
  // -------------------------------------------------------------------------
  async status(): Promise<Json> {
    const { log, store } = this.deps;
    log.debug("Entering RiskTerms.status().");
    const rows = await store.listAcceptances();
    const providers = Object.keys(PROVIDERS).map(function (id: string): Json {
      const terms = RiskTerms.termsOf(id);
      const mine = rows.filter(function (a: Json): boolean {
        return a.provider === id;
      });
      const current = mine.filter(function (a: Json): boolean {
        return a.termsDigest === terms.digest;
      })[0] || null;
      return Object.assign({ provider: id }, PROVIDERS[id], {
        termsDigest: terms.digest,
        needsAcceptance: RiskTerms.needsAcceptance(id),
        accepted: current,
        changed: !current && mine.length > 0,
        attribution: PROVIDERS[id].attribution
      });
    });
    log.debug("Leaving RiskTerms.status().");
    return { providers: providers, acceptances: rows };
  }
}

const slot = new InstanceSlot<RiskTerms>(
  'risk/risk_terms',
  () => new RiskTerms(RiskTerms.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

export = {
  RiskTerms: RiskTerms,
  installInstance: (instance: RiskTerms): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PROVIDERS: RiskTerms.PROVIDERS,
  termsOf: RiskTerms.termsOf,
  needsAcceptance: RiskTerms.needsAcceptance,
  attributionOf: RiskTerms.attributionOf,
  currentFor: slot.forward('currentFor'),
  accept: slot.forward('accept'),
  status: slot.forward('status')
};
