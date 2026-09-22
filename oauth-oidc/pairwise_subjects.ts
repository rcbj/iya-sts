'use strict';
//
// File: pairwise_subjects.ts
//
// ===========================================================================
// PAIRWISE SUBJECT IDENTIFIERS (OpenID Connect Core 1.0 section 8, #118,
// 2026-09-22).
//
// A `public` client is told the same `sub` for a person as every other
// client — `urn:uuid:<entryUUID>`. A `pairwise` client is told one of its own:
// section 8 has the provider compute "a different sub value to each Client, so
// as not to enable Clients to correlate the End-User's activities without
// permission". This file is that computation, and nothing else.
//
// **THE VALUE** is HMAC-SHA256, through `common/crypto.js`'s
// `deriveSharedCredential()`, over the realm, the SECTOR and the person's
// local `sub`, under the `oidc-pairwise` secret `cluster/cluster_secrets.ts`
// holds — which is the same on every node and across restarts in product mode
// (the store keeps it) and set by `STS_OIDC_PAIRWISE_SECRET` where an operator
// wants to pin it. Section 8.1's recipe is `sub = SHA-256 ( sector_identifier
// || local_account_id || salt )`; an HMAC keyed by the salt is the same idea
// without the length-extension property a bare hash over a secret suffix has.
// The realm is in it because two realms are two providers.
//
// **THE SECTOR** is the host of `sector_identifier_uri` when the client has
// one, and otherwise the host every one of its redirect URIs shares (section
// 8.1). A pairwise client with redirect URIs on two hosts and no sector URI is
// refused at registration (`applications.oidcSubjectMetadataProblem()`); one
// that got that way by hand is refused at ISSUANCE rather than given a sector
// chosen here, because a sector this service picked would change the day a
// URI was added.
//
// **WHAT A SECTOR URI SERVES** is checked where it is registered
// (`sectorIdentifierProblem()`, section 8.1: "the OP MUST validate that all the
// redirect_uris are included" in the JSON array it serves). That is an
// OUTBOUND REQUEST to a URL a client registered, argued with the others in
// `federation/CLAUDE.md`: it is fetched through `federation_http.ts`'s
// `fetchPublished()` — the outbound kill switch, https only, internal addresses
// refused in product mode, no redirect, a size cap, a timeout — once, at
// registration, never while issuing.
//
// A LIBRARY (rule 3): it registers no route.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import stsCrypto = require('../common/crypto');
import realms = require('../common/realms');
import applications = require('../common/applications');
import clusterSecrets = require('../cluster/cluster_secrets');
import fedHttp = require('../federation/federation_http');

type Json = any;

interface PairwiseDeps {
  log: typeof helpers.log;
  stsCrypto: typeof stsCrypto;
  realms: typeof realms;
  applications: typeof applications;
  clusterSecrets: typeof clusterSecrets;
  fedHttp: typeof fedHttp;
}

// The label that keeps this derivation apart from every other one made under
// a shared secret (see `deriveSharedCredential()`).
const LABEL = 'oidc-pairwise-sub';

class PairwiseSubjects {
  static readonly SUBJECT_TYPES = ['public', 'pairwise'];

  constructor(private readonly deps: PairwiseDeps) {
    deps.log.debug("Entering PairwiseSubjects.constructor().");
    deps.log.debug("Leaving PairwiseSubjects.constructor().");
  }

  static defaultDeps(): PairwiseDeps {
    helpers.log.debug("Entering PairwiseSubjects.defaultDeps().");
    helpers.log.debug("Leaving PairwiseSubjects.defaultDeps().");
    return { log: helpers.log, stsCrypto: stsCrypto, realms: realms,
             applications: applications, clusterSecrets: clusterSecrets,
             fedHttp: fedHttp };
  }

  // The sector of a client's configuration, or '' when it has none it can be
  // given — a pairwise client whose redirect URIs span hosts and which names
  // no sector URI.
  sectorOf(client: Json): string {
    const { log } = this.deps;
    log.debug("Entering PairwiseSubjects.sectorOf().");
    const cfg = client || {};
    if (cfg.sector_identifier_uri) {
      try {
        const host = new URL(String(cfg.sector_identifier_uri)).host;
        log.debug("Leaving PairwiseSubjects.sectorOf(). The sector URI's.");
        return host;
      } catch (e) {
        log.debug("Caught in PairwiseSubjects.sectorOf(): " +
                  ((e && e.message) || e));
        // Not a URL: no sector, and the caller refuses.
        return '';
      }
    }
    const hosts: string[] = [];
    (cfg.redirect_uris || []).forEach(function (uri: string) {
      try {
        const host = new URL(String(uri)).host;
        if (hosts.indexOf(host) < 0) {
          hosts.push(host);
        }
      } catch (e) {
        log.debug("Caught in PairwiseSubjects.sectorOf(): " +
                  ((e && e.message) || e));
        // A redirect URI that is not a URL names no host.
        hosts.push('');
      }
    });
    log.debug("Leaving PairwiseSubjects.sectorOf(). " + hosts.length +
              " host(s).");
    return hosts.length === 1 ? hosts[0] : '';
  }

  // -------------------------------------------------------------------------
  // THE `sub` THIS CLIENT IS TOLD FOR THIS PERSON. `localSub` is the public
  // one. Throws — with the sentence — for a pairwise client with no sector,
  // which every caller turns into a server_error rather than a public `sub`
  // this client registered not to be given.
  // -------------------------------------------------------------------------
  subjectFor(clientId: Json, localSub: Json): string {
    const { log, stsCrypto, realms, applications, clusterSecrets } = this.deps;
    log.debug("Entering PairwiseSubjects.subjectFor(). client=" + clientId);
    const local = String(localSub || '');
    if (!local || !clientId) {
      log.debug("Leaving PairwiseSubjects.subjectFor(). Nothing to map.");
      return local;
    }
    const cfg = applications.clientConfigOf(String(clientId));
    if (cfg.subject_type !== 'pairwise') {
      log.debug("Leaving PairwiseSubjects.subjectFor(). public.");
      return local;
    }
    const sector = this.sectorOf(cfg);
    if (!sector) {
      log.debug("Leaving PairwiseSubjects.subjectFor(). No sector.");
      throw new Error('client "' + clientId + '" is registered for pairwise ' +
        'subject identifiers and has no sector: its redirect URIs span ' +
        'several hosts and it names no sector_identifier_uri (OIDC Core ' +
        'section 8.1). Give it one on /admin/applications.');
    }
    const derived = stsCrypto.deriveSharedCredential(
      clusterSecrets.text('oidc-pairwise'), LABEL, realms.currentId(), sector,
      local);
    log.debug("Leaving PairwiseSubjects.subjectFor(). pairwise for " +
              sector + ".");
    return derived;
  }

  // -------------------------------------------------------------------------
  // SECTION 8.1's CHECK OF A REGISTERED sector_identifier_uri: fetch it, read
  // a JSON array of URIs, and require every one of the registration's
  // redirect_uris to be in it. Resolves null or `{ errorCode, error,
  // description }`, and never rejects.
  // -------------------------------------------------------------------------
  sectorIdentifierProblem(metadata: Json): Promise<Json> {
    const { log, fedHttp } = this.deps;
    log.debug("Entering PairwiseSubjects.sectorIdentifierProblem().");
    const meta = metadata || {};
    const uri = String(meta.sector_identifier_uri || '').trim();
    if (!uri) {
      log.debug("Leaving PairwiseSubjects.sectorIdentifierProblem(). None.");
      return Promise.resolve(null);
    }
    const refusal = function (description: string): Json {
      log.debug("Entering refusal().");
      log.debug("Leaving refusal().");
      return { errorCode: 'STS-REG-0169', error: 'invalid_client_metadata',
               description: 'sector_identifier_uri: ' + description +
                 ' (OIDC Core section 8.1).' };
    };
    log.debug("Leaving PairwiseSubjects.sectorIdentifierProblem(). " +
              "Fetching.");
    return fedHttp.fetchPublished(uri, { accept: 'application/json' })
      .then(function (fetched: Json) {
        if (!fetched.ok) {
          return refusal('"' + uri + '" could not be fetched: ' +
                         fetched.why);
        }
        let listed: Json = null;
        try {
          listed = JSON.parse(fetched.body.toString('utf8'));
        } catch (e) {
          log.debug("Caught in a callback in sectorIdentifierProblem(): " +
                    ((e && e.message) || e));
          return refusal('"' + uri + '" did not answer with JSON.');
        }
        if (!Array.isArray(listed) || listed.some(function (one) {
          return typeof one !== 'string';
        })) {
          return refusal('"' + uri + '" answered with something other than ' +
                         'a JSON array of URI strings.');
        }
        const missing = (Array.isArray(meta.redirect_uris)
          ? meta.redirect_uris : []).filter(function (one: Json) {
            return listed.indexOf(String(one)) < 0;
          });
        if (missing.length) {
          return refusal('the array "' + uri + '" serves does not list ' +
                         missing.map(function (one: Json) {
                           return '"' + one + '"';
                         }).join(', ') + ', and it must list every ' +
                         'redirect_uri this client registers.');
        }
        return null;
      }).catch(function (e: Json) {
        log.debug("Caught in PairwiseSubjects.sectorIdentifierProblem(): " +
                  ((e && e.message) || e));
        return refusal('"' + uri + '" could not be fetched: ' +
                       ((e && e.message) || e) + '.');
      });
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PairwiseSubjects>(
  'oauth-oidc/pairwise_subjects',
  () => new PairwiseSubjects(PairwiseSubjects.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

export = {
  PairwiseSubjects: PairwiseSubjects,
  installInstance: (instance: PairwiseSubjects): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SUBJECT_TYPES: PairwiseSubjects.SUBJECT_TYPES,
  sectorOf: slot.forward('sectorOf'),
  subjectFor: slot.forward('subjectFor'),
  sectorIdentifierProblem: slot.forward('sectorIdentifierProblem')
};
