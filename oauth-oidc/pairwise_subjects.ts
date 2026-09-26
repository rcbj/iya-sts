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
import config = require('../common/config');
import nodeCrypto = require('crypto');

type Json = any;

interface PairwiseDeps {
  log: typeof helpers.log;
  stsCrypto: typeof stsCrypto;
  realms: typeof realms;
  applications: typeof applications;
  clusterSecrets: typeof clusterSecrets;
  fedHttp: typeof fedHttp;
  config: typeof config;
  scheduler: () => Json;
  now: () => number;
}

// The label that keeps this derivation apart from every other one made under
// a shared secret (see `deriveSharedCredential()`).
const LABEL = 'oidc-pairwise-sub';
const PURGE_JOB = 'oauth2.ephemeral-subjects-purge';

// EPHEMERAL SUBJECTS (#149, the Ephemeral Subject Identifier draft), PER
// REALM and PERSISTED — every node answers the same `sub`, and a refresh or
// a UserInfo call on another node must find it:
//   `s|<session>|<client>` -> the ephemeral `sub` minted for that
//                             authentication at that client (section 4:
//                             the same within one authentication, a new one
//                             for the next);
//   `e|<sub>`              -> { local, client, session, until }: who it is,
//                             for mapping back, and when it may be purged.
// rcbj's answer: kept as long as the longest token or session of that
// authentication, then removed by the `oauth2.ephemeral-subjects-purge` job.
const ephemeral = realms.map({ persist: 'oauth2.ephemeralSubjects' });

class PairwiseSubjects {
  static readonly SUBJECT_TYPES = ['public', 'pairwise', 'ephemeral'];
  static readonly PURGE_JOB = PURGE_JOB;

  constructor(private readonly deps: PairwiseDeps) {
    deps.log.debug("Entering PairwiseSubjects.constructor().");
    deps.log.debug("Leaving PairwiseSubjects.constructor().");
  }

  static defaultDeps(): PairwiseDeps {
    helpers.log.debug("Entering PairwiseSubjects.defaultDeps().");
    helpers.log.debug("Leaving PairwiseSubjects.defaultDeps().");
    return { log: helpers.log, stsCrypto: stsCrypto, realms: realms,
             applications: applications, clusterSecrets: clusterSecrets,
             fedHttp: fedHttp, config: config,
             scheduler: function (): Json {
               return require('../cluster/scheduler');
             },
             now: function (): number {
               return Date.now();
             } };
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
  subjectFor(clientId: Json, localSub: Json, sessionId?: Json): string {
    const { log, stsCrypto, realms, applications, clusterSecrets } = this.deps;
    log.debug("Entering PairwiseSubjects.subjectFor(). client=" + clientId);
    const local = String(localSub || '');
    if (!local || !clientId) {
      log.debug("Leaving PairwiseSubjects.subjectFor(). Nothing to map.");
      return local;
    }
    const cfg = applications.clientConfigOf(String(clientId));
    if (cfg.subject_type === 'ephemeral') {
      const minted = this.ephemeralFor(String(clientId), local,
                                       String(sessionId || ''));
      log.debug("Leaving PairwiseSubjects.subjectFor(). ephemeral.");
      return minted;
    }
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

  // How long an ephemeral mapping outlives its last use: the longest a token
  // or a session of that authentication can last (#149).
  private ephemeralLifetimeMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering PairwiseSubjects.ephemeralLifetimeMs().");
    const seconds = Math.max(Number(config.value('authn.sessionLifetimeS')) ||
                             0,
                             Number(config.value('oauth2.refreshTokenTtlS')) ||
                             0, 3600);
    log.debug("Leaving PairwiseSubjects.ephemeralLifetimeMs().");
    return seconds * 1000;
  }

  // EPHEMERAL SUBJECT IDENTIFIER SECTION 4 (#149): 160 random bits,
  // base64url, never reused — the draft's recommended size. The same `sub`
  // for every artifact of one authentication (the session) at one client,
  // so the ID Token, UserInfo, a refresh and a Logout Token agree; a new
  // authentication gets a new one. With no session to key it (a grant with
  // no browser), each call mints afresh, as the draft allows. Every use
  // extends the mapping's life.
  private ephemeralFor(clientId: string, local: string,
                       sessionId: string): string {
    const { log, now } = this.deps;
    log.debug("Entering PairwiseSubjects.ephemeralFor().");
    const index = sessionId ? 's|' + sessionId + '|' + clientId : '';
    let sub = index ? String(ephemeral.get(index) || '') : '';
    const held = sub ? ephemeral.get('e|' + sub) : null;
    if (!held || held.local !== local) {
      sub = nodeCrypto.randomBytes(20).toString('base64url');
    }
    const until = now() + this.ephemeralLifetimeMs();
    ephemeral.set('e|' + sub, { local: local, client: clientId,
                               session: sessionId, until: until });
    if (index) {
      ephemeral.set(index, sub);
    }
    log.debug("Leaving PairwiseSubjects.ephemeralFor().");
    return sub;
  }

  // The public `sub` behind an ephemeral one, or '' (#149): what a verified
  // id_token_hint names, mapped back to the person.
  localFor(sub: Json): string {
    const { log } = this.deps;
    log.debug("Entering PairwiseSubjects.localFor().");
    const held = ephemeral.get('e|' + String(sub || ''));
    log.debug("Leaving PairwiseSubjects.localFor().");
    return held ? String(held.local || '') : '';
  }

  // The scheduler job (#49): mappings past their life are removed, with
  // their session index.
  purge(): Json {
    const { log, now } = this.deps;
    log.debug("Entering PairwiseSubjects.purge().");
    const gone: string[] = [];
    ephemeral.forEach(function (row: Json, key: string): void {
      if (key.indexOf('e|') === 0 && Number((row || {}).until) < now()) {
        gone.push(key);
        if (row.session) {
          gone.push('s|' + row.session + '|' + row.client);
        }
      }
    });
    gone.forEach(function (key: string): void {
      ephemeral.delete(key);
    });
    log.debug("Leaving PairwiseSubjects.purge(). " + gone.length + ".");
    return { summary: gone.length + ' expired ephemeral subject row(s) ' +
             'removed' };
  }

  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering PairwiseSubjects.scheduleJobs().");
    const s = scheduler();
    if (s.job(PURGE_JOB)) {
      log.debug("Leaving PairwiseSubjects.scheduleJobs(). Registered.");
      return;
    }
    s.register({
      id: PURGE_JOB,
      title: 'Ephemeral subjects: expired mappings',
      describe: 'Removes each ephemeral subject identifier whose tokens and ' +
                'session can no longer be in use (#149).',
      owner: 'oauth-oidc/pairwise_subjects.ts',
      kind: 'cluster', scope: 'realm', everyMs: function (): number {
        return 3600000;
      },
      manual: true,
      run: function (): Json {
        return self.purge();
      }
    });
    log.debug("Leaving PairwiseSubjects.scheduleJobs(). On the scheduler.");
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
  function (instance: PairwiseSubjects): void {
    instance.scheduleJobs();
  },
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
  localFor: slot.forward('localFor'),
  purge: slot.forward('purge'),
  PURGE_JOB: PURGE_JOB,
  sectorIdentifierProblem: slot.forward('sectorIdentifierProblem')
};
