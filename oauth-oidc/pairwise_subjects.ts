// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// The pairwise DEVICE identifier's own label (#164 phase 6): a device id
// derived under the subject's label could collide with a person's `sub`.
const DEVICE_LABEL = 'oidc-pairwise-device-id';
// The GNAP opaque subject identifier's own label (#432 phase 7), for the
// device label's reason: it must never equal an OIDC pairwise `sub`.
const GNAP_OPAQUE_LABEL = 'gnap-opaque-sub';
/**
 * The scheduler job id that removes expired ephemeral subject mappings.
 */
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

/**
 * The `sub` and `device_id` a client is told for a person: public, pairwise per
 * sector (OpenID Connect Core section 8) or ephemeral per authentication
 * (#149).
 */
class PairwiseSubjects {
  /**
   * The subject types a client may register.
   */
  static readonly SUBJECT_TYPES = ['public', 'pairwise', 'ephemeral'];
  /**
   * The scheduler job id that removes expired ephemeral subject mappings.
   */
  static readonly PURGE_JOB = PURGE_JOB;

  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, crypto module, realms, application registry,
   *   cluster secrets, outbound HTTP, settings, scheduler and clock it reads
   */
  constructor(private readonly deps: PairwiseDeps) {
    deps.log.debug("Entering PairwiseSubjects.constructor().");
    deps.log.debug("Leaving PairwiseSubjects.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
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
  /**
   * Returns the sector of a client: the host of its `sector_identifier_uri`, or
   * the one host all its redirect URIs share.
   *
   * @param client - the client's configuration
   * @returns the sector host, or '' when the client has none it can be given
   */
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
  /**
   * Returns the `sub` a client is told for a person.
   *
   * Public clients get the local `sub`; pairwise clients an HMAC over the
   * realm, their sector and the local `sub`; ephemeral clients one minted for
   * this authentication.
   *
   * @param clientId - the client being answered
   * @param localSub - the person's public `sub`
   * @param sessionId - the session, which an ephemeral subject is bound to
   * @returns the client-facing `sub`
   * @throws an Error with the sentence, for a pairwise client with no sector
   */
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

  // -------------------------------------------------------------------------
  // THE `device_id` A CLIENT IS TOLD (#164 decision 8, phase 6), by the
  // same rule as its `sub`, because a device id is a correlation handle
  // exactly as a subject is: two pairwise clients handed the register's
  // UUID for one person's phone could join their records on it, which is
  // what OIDC Core section 8 has the provider prevent.
  //
  //   public     the register's id — the `sub` of the `iss_sub` subject SSF
  //              names the device by, scoped by the same issuer as the
  //              token's `iss`.
  //   pairwise   HMAC over the realm, the client's SECTOR and the id, under
  //              the pairwise secret and a label of its own: stable for the
  //              sector, different for every other one. A client with no
  //              sector is told nothing ('' — omit), rather than refused as
  //              its `sub` is: the claim is an extra, the token is not.
  //   ephemeral  '' — omit. The Ephemeral Subject Identifier exists so that
  //              a client cannot link one authentication to the next, and a
  //              stable device id would link every one made on that device.
  //
  // A device OWNED BY AN APPLICATION is not an End-User's, and section 8's
  // concern is End-Users: its id goes to every client as it is (`person`
  // false).
  // -------------------------------------------------------------------------
  /**
   * Returns the `device_id` a client is told for a registered device, by the
   * same rule as its `sub`.
   *
   * An ephemeral client, and a pairwise client with no sector, are told
   * nothing. A device owned by an application goes to every client as it is.
   *
   * @param clientId - the client being answered
   * @param deviceId - the device register's id
   * @param person - false when an application owns the device
   * @returns the client-facing device id, or '' to omit the claim
   */
  deviceIdFor(clientId: Json, deviceId: Json, person?: boolean): string {
    const { log, stsCrypto, realms, applications, clusterSecrets } = this.deps;
    log.debug("Entering PairwiseSubjects.deviceIdFor(). client=" + clientId);
    const id = String(deviceId || '');
    if (!id || !clientId || person === false) {
      log.debug("Leaving PairwiseSubjects.deviceIdFor(). As it is.");
      return id;
    }
    const cfg = applications.clientConfigOf(String(clientId));
    if (cfg.subject_type === 'ephemeral') {
      log.debug("Leaving PairwiseSubjects.deviceIdFor(). ephemeral: none.");
      return '';
    }
    if (cfg.subject_type !== 'pairwise') {
      log.debug("Leaving PairwiseSubjects.deviceIdFor(). public.");
      return id;
    }
    const sector = this.sectorOf(cfg);
    if (!sector) {
      log.debug("Leaving PairwiseSubjects.deviceIdFor(). No sector: none.");
      return '';
    }
    const derived = stsCrypto.deriveSharedCredential(
      clusterSecrets.text('oidc-pairwise'), DEVICE_LABEL, realms.currentId(),
      sector, id);
    log.debug("Leaving PairwiseSubjects.deviceIdFor(). pairwise.");
    return derived;
  }

  // -------------------------------------------------------------------------
  // THE GNAP OPAQUE SUBJECT IDENTIFIER A CLIENT INSTANCE IS TOLD (#432
  // phase 7, 2026-10-03). RFC 9635 section 3.4's `opaque` format (RFC 9493)
  // was ONE HMAC PER REALM, so every client was handed the same value for a
  // person and two clients could join their records on it — exactly what
  // OIDC Core section 8 has the provider prevent with a pairwise `sub`. It is
  // derived here, by section 8's model, so there is one place that says how
  // this service keeps clients from correlating a person.
  //
  //   * ALWAYS PER CLIENT OR SECTOR, whatever `subject_type` the entry
  //     registers. GNAP has no registration member asking for a public
  //     identifier, and an opaque identifier exists to name a person to ONE
  //     client — a public one is what `iss_sub` is for.
  //   * THE SECTOR is the host of the entry's REGISTERED
  //     `sector_identifier_uri` (section 8.1, checked where it is
  //     registered). With none, the sector is the client's own identifier:
  //     section 8.1's other rule — the one host every redirect URI shares — is
  //     about redirect URIs, which a GNAP client instance does not have, and
  //     inferring a sector from its finish URIs would change the day one was
  //     added.
  //   * Its own label, `gnap-opaque-sub`, so a value can never equal the
  //     client's OIDC pairwise `sub` for the same person, and the `client:`
  //     or `sector:` prefix keeps a client named like a host from sharing a
  //     sector's identifiers.
  //
  // RFC 9635 section 3.4's "SHOULD NOT reuse Subject Identifiers for
  // multiple different ROs" still holds: the input is the person's stable
  // subject, which is never given to a second person (`gnap_subject.ts`).
  // -------------------------------------------------------------------------
  /**
   * Returns the opaque Subject Identifier (RFC 9635 section 3.4) a GNAP
   * client instance is told for a person: an HMAC over the realm, the
   * client's sector — the host of its registered `sector_identifier_uri`, or
   * the client itself — and the person's stable subject.
   *
   * @param clientId - the GNAP client instance's application identifier
   * @param localKey - the person's stable subject (or name, with no entry)
   * @returns `{ id, sector }`: the identifier and the sector it is for
   */
  gnapOpaqueFor(clientId: Json, localKey: Json): { id: string;
                                                    sector: string } {
    const { log, stsCrypto, realms, clusterSecrets } = this.deps;
    log.debug("Entering PairwiseSubjects.gnapOpaqueFor(). client=" +
              clientId);
    const sector = this.gnapSectorOf(clientId);
    const id = stsCrypto.deriveSharedCredential(
      clusterSecrets.text('oidc-pairwise'), GNAP_OPAQUE_LABEL,
      realms.currentId(), sector, String(localKey || ''));
    log.debug("Leaving PairwiseSubjects.gnapOpaqueFor(). " + sector + ".");
    return { id: id, sector: sector };
  }

  /**
   * Returns the sector a GNAP client instance's opaque identifiers are made
   * for: `sector:<host>` of its registered `sector_identifier_uri`, or
   * `client:<identifier>`.
   *
   * @param clientId - the GNAP client instance's application identifier
   * @returns the sector label
   */
  gnapSectorOf(clientId: Json): string {
    const { log, applications } = this.deps;
    log.debug("Entering PairwiseSubjects.gnapSectorOf().");
    const id = String(clientId || '');
    const cfg = id ? applications.clientConfigOf(id) : null;
    let host = '';
    if (cfg && cfg.sector_identifier_uri) {
      try {
        host = new URL(String(cfg.sector_identifier_uri)).host;
      } catch (e) {
        log.debug("Caught in PairwiseSubjects.gnapSectorOf(): " +
                  ((e && e.message) || e));
        // Not a URL: no sector, and the client is its own.
        host = '';
      }
    }
    log.debug("Leaving PairwiseSubjects.gnapSectorOf().");
    return host ? 'sector:' + host : 'client:' + id;
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
      sub = stsCrypto.randomBytes(20).toString('base64url');
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
  /**
   * Maps an ephemeral `sub` back to the person's public one.
   *
   * @param sub - an ephemeral `sub`, as a verified id_token_hint names it
   * @returns the public `sub`, or ''
   */
  localFor(sub: Json): string {
    const { log } = this.deps;
    log.debug("Entering PairwiseSubjects.localFor().");
    const held = ephemeral.get('e|' + String(sub || ''));
    log.debug("Leaving PairwiseSubjects.localFor().");
    return held ? String(held.local || '') : '';
  }

  // The scheduler job (#49): mappings past their life are removed, with
  // their session index.
  /**
   * Removes every ephemeral mapping past its life, with its session index. The
   * scheduler job's body.
   *
   * @returns `{ summary }` for the scheduler
   */
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

  /**
   * Registers the purge job on the scheduler, once.
   */
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
  /**
   * Checks a registered `sector_identifier_uri` (section 8.1): fetches it and
   * requires every redirect URI of the registration to be in the JSON array it
   * serves.
   *
   * @param metadata - the registration metadata
   * @returns a promise of null, or `{ errorCode, error, description }`; it
   *   never rejects
   */
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

/**
 * OpenID Connect pairwise and ephemeral subject identifiers.
 *
 * A library that registers no route. The composition root builds the instance;
 * each function here forwards to it.
 *
 * @namespace
 */
export = {
  PairwiseSubjects: PairwiseSubjects,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   * Refused once an instance is installed or a default built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: PairwiseSubjects): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  SUBJECT_TYPES: PairwiseSubjects.SUBJECT_TYPES,
  sectorOf: slot.forward('sectorOf'),
  subjectFor: slot.forward('subjectFor'),
  deviceIdFor: slot.forward('deviceIdFor'),
  gnapOpaqueFor: slot.forward('gnapOpaqueFor'),
  gnapSectorOf: slot.forward('gnapSectorOf'),
  localFor: slot.forward('localFor'),
  purge: slot.forward('purge'),
  PURGE_JOB: PURGE_JOB,
  sectorIdentifierProblem: slot.forward('sectorIdentifierProblem')
};
