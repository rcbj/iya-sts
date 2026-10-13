// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scim_client.ts
//
// ===========================================================================
// THE OUTBOUND SCIM CLIENT (#552, 2026-10-10): this realm's people and groups,
// pushed to a remote SCIM 2.0 service provider.
//
// `scim/scim.ts` is the other direction — a SERVICE PROVIDER, provisioned
// into. This file is a CLIENT of somebody else's: RFC 7643 resources over RFC
// 7644, created, replaced or patched, deactivated or deleted as the directory
// changes, and reconciled on demand or on a schedule. rcbj's decisions are on
// #552; what follows is how each is met.
//
// **A CLIENT IS AN APPLICATION ENTRY** declared for the `scim-client`
// family (`common/applications.js`): its address, how it authenticates, who
// and which groups it pushes, and what deprovisioning means there. Its three
// credentials — a Basic password, an OAuth client secret, a TLS private key —
// are SEALED and WITHHELD on the entry, opened only for the request that
// uses them (`applications.scimClientCredentialOf()`), never kept.
//
// **A CHANGE IS A ROW, AND THE ROW IS THE RESOURCE.** The directory tells
// every listener of each write to a person's entry and of each membership
// change (`ldap_server.js`'s `addAccountObserver()`); for each enabled client
// of the realm a row is queued per affected RESOURCE — `<client>|User|<uuid>`
// or `<client>|Group|<uuid>` — in `oauth-oidc/outbound_delivery.ts`'s queue
// (claims, fences, retries, dead letters), and the row carries no data: the
// send reads the entry as it is THEN. So changes to one resource are
// delivered in order (one row, one attempt in flight) and coalesce; a change
// that lands while its row is in flight requeues it when the attempt ends
// (`changedAt` against `lastAttemptAt`). Different resources go in parallel,
// up to `scimClient.concurrency`.
//
// **EVERY CLIENT HAS ITS OWN RETRY QUEUE AND DEAD-LETTER QUEUE** — its rows
// of the one store, by `clientId`: queued (never attempted), retrying
// (attempted and due again), dead (a final failure, kept for an operator to
// retry or purge). One store per client cannot be declared — a store is per
// realm at its declaration (root CLAUDE.md) and a client is a runtime entry.
//
// **EVERY SCHEDULE IS A CLUSTER SCHEDULER JOB** (rcbj's directive, and his
// again on #552): `scim-client.deliver` sends what is due — new changes and
// retries alike — and `scim-client.reconcile` runs the scheduled
// reconciliations. The queue's own in-process retry timer is turned off here
// (`later` does nothing), so no delivery is sent by a timer of its own.
//
// **EXPONENTIAL BACKOFF, PER DELIVERY AND PER CLIENT (rcbj, #552)**, so a
// struggling service provider is not swamped:
//   * a delivery's retry waits backoffMs × 2^(n−1), full jitter, capped at
//     scimClient.maxBackoffMs, and longer where a 429 or 503 says Retry-After;
//   * a failure that says the SERVER is struggling — the network, a timeout,
//     429, 500, 502, 503, 504 — PAUSES THE CLIENT: none of its deliveries is
//     attempted until the pause ends (the queue's holdUntil hook), the
//     pause doubles with each consecutive such failure, jittered and capped,
//     and when it ends ONE delivery goes first (the probe); the rest follow
//     only after a success, which ends the pause. The pause is a persisted
//     row (`scimClient.state`), so every node honours it.
//
// RFC 7643 / 7644, as a client is bound by them (the checklist on #552):
//   * TLS, the server identity checked, no credential in a URI, a base URI
//     with no query (7644 sections 7.1, 7.2, 1.3) — `scim_client_rules.ts`;
//   * `application/scim+json` both ways (section 3.8);
//   * discovery before use — /ServiceProviderConfig for patch, filter,
//     maxResults and etag, /ResourceTypes for the endpoints (sections 3.2, 4);
//   * a create never sends `id`, `meta` or a User's `groups`; `externalId` is
//     the entry's entryUUID, which this client owns (7643 section 3.1); a 409
//     `uniqueness` ADOPTS the resource found by externalId, then userName or
//     displayName, rather than retrying (7644 section 3.3);
//   * a replace is a PUT of the whole owned state to a known id; a 404 there
//     re-creates (section 3.5.1); PATCH only where `patch.supported`, else
//     GET then PUT (section 3.5.2);
//   * ETags where `etag.supported`: If-Match on a PUT, a PATCH and a DELETE,
//     and a 412 — or a 400 `invalidVers` — re-reads and tries again a
//     bounded number of times (section 3.14);
//   * a group's `members[].value` is the service provider's id, so a member
//     goes in once that person is there (7643 section 4.2);
//   * a DELETE answered 404 is done (7644 section 3.6);
//   * only a network failure, a timeout, 429, 500, 502, 503 and 504 are
//     retried; every other answer is a dead letter carrying its scimType,
//     read from the Error body whether its `status` is a string or a number
//     (section 3.12). Three scimTypes CHANGE what the client does, and are
//     the only ones that do: `tooMany` narrows the query (section 3.4.2),
//     `uniqueness` on a create adopts (section 3.3; any other 409 is a dead
//     letter), and `invalidVers` re-reads as a 412 does. `mutability` is
//     deliberately a dead letter: the attribute it names is immutable THERE,
//     and a re-read cannot change what this client would send;
//   * a resource sent carries every extension /ResourceTypes marks
//     `required` — the enterprise one, empty if need be, since RFC 7643
//     section 4.3 makes none of its attributes required — and any other
//     required extension, which this client has no values for, is a dead
//     letter naming it (STS-SCIMC-0029);
//   * a resource missing an attribute RFC 7643 requires (`userName`,
//     `displayName`) is not sent (STS-SCIMC-0030), and a replace clears what
//     this client sent before and the entry no longer has — `null`, or `[]`
//     for a multi-valued attribute — rather than leaving the service
//     provider to guess (section 3.5.1);
//   * a list is read page by page from startIndex 1, and when the answer
//     carries no `totalResults` the paging goes on until a page is empty or
//     brings nothing new, rather than stopping after the first;
//   * no credential, token or filter value is ever logged (section 7.5.2).
//
// IN A SERVICE DEPLOYED AS CELLS (#553; scim/CLAUDE.md argues each part):
//   * a person is pushed only from their HOME cell — a projection is not
//     this cell's — and only when the issuance policy releases them to the
//     client's declared jurisdiction (`release-attributes`, purpose
//     `scim-provision`); a refusal is out of scope, never a dead letter;
//   * a person who left this cell is looked up in the routing index first:
//     homed elsewhere is a HANDOVER (nothing sent), gone everywhere a
//     deprovision;
//   * `scimClientCells` limits which cells push at all;
//   * a group's membership changes by PATCH only, each cell adding its own
//     members and removing only ids it linked; any cell may create it (a
//     409 adopts by externalId, unreplaced); ONE OWNER cell renames and
//     deletes it, deleting only when every cell answers
//     `scim-client-group-share` with no member; without PATCH the owner
//     PUTs every cell's share merged, and nothing while a cell is away.
// In a service that is one cell none of it is asked.
// ===========================================================================

import http = require('http');
import https = require('https');
import fs = require('fs');
import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import mode = require('../common/mode');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import stsCrypto = require('../common/crypto');
import OutboundTls = require('../common/outbound_tls');
import InstanceSlot = require('../common/instance_slot');
import Rules = require('./scim_client_rules');
import outbound = require('../oauth-oidc/outbound_delivery');

type Json = any;

const FAMILY = 'scim-client';
const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const ENTERPRISE_SCHEMA =
  'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const LIST_RESPONSE = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const MEDIA_TYPE = 'application/scim+json';
const UUID_SHAPED = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// A response larger than this is not a SCIM answer this client reads.
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
// How long a discovered service provider configuration is believed.
const DISCOVERY_TTL_MS = 10 * 60 * 1000;
// The most pages one reconciliation reads per resource type.
const MAX_PAGES = 10000;

// THE STORES, per realm at their declarations (root CLAUDE.md's rule).
// The deliveries — every client's rows, told apart by `clientId`.
//
// **NOT TOMBSTONED, unlike every other kind of the queue (2026-10-13).** A
// tombstone ends a key for good — the persisted store refuses a later write
// of it — which is right for the others' random ids and wrong here: a row's
// key is `<client>|<type>|<uuid>`, a NAME written again every time that
// resource changes. Tombstoned, a purged dead letter, a row removed by
// retention or a removed client's rows would have ended the key, and the
// next change to that person or group would have been refused at the flush.
// realms.js says it in as many words: never for anything keyed by a name.
// The merge by rank still orders two nodes' copies; and a row written again
// under a key that was deleted starts at a NEW generation (enqueue()).
const deliveries = realms.map({ persist: 'scimClient.deliveries',
                                mergeRow: outbound.mergeRow });
// Which service provider resource each entry is, per client:
// `<client>|<type>|<uuid>` -> { remoteId, etag, dn, name, inactive, at }.
const links = realms.map({ persist: 'scimClient.links' });
// Per client: the pause (`pausedUntil`, `failures`, `probe`) and the last
// reconciliation. In a service deployed as cells the PAUSE is kept in
// `pauses` instead, and this holds the last reconciliation alone.
const states = realms.map({ persist: 'scimClient.state' });
// THE PAUSE SHARED BY EVERY CELL (#553 section 5), per client: `failures`,
// `pausedUntil`, `probe` and `probeAt`. GLOBAL-tier (`persistence/
// tiers.js`): a 429 or a 5xx seen in any cell pauses every cell, and one
// probe goes cluster-wide. Written only on a failure and a recovery, and it
// holds no person's data — a client id, two times, a count and the probe's
// row id. Unused, and empty, in a service that is one cell.
const pauses = realms.map({ persist: 'scimClient.pause' });

// The members of a client's definition, as the act takes them, against the
// attribute each is written to. The three credentials are not here: they are
// written only when given (write-only).
const MEMBERS: Array<[string, string]> = [
  ['baseUrl', 'scimClientBaseUrl'],
  ['authMethod', 'scimClientAuthMethod'],
  ['username', 'scimClientUsername'],
  ['tokenEndpoint', 'scimClientTokenEndpoint'],
  ['oauthClientId', 'scimClientOAuthClientId'],
  ['oauthClientAuth', 'scimClientOAuthClientAuth'],
  ['oauthScope', 'scimClientOAuthScope'],
  ['oauthResource', 'scimClientOAuthResource'],
  ['tlsSource', 'scimClientTlsSource'],
  ['tlsCertificate', 'scimClientTlsCertificate'],
  ['caCertificates', 'scimClientCaCertificates'],
  ['scopeMode', 'scimClientScopeMode'],
  ['scopeFilter', 'scimClientScopeFilter'],
  ['groupMode', 'scimClientGroupMode'],
  ['deprovision', 'scimClientDeprovision'],
  ['reconcileMinutes', 'scimClientReconcileMinutes'],
  // A service deployed as cells (#553).
  ['jurisdiction', 'scimClientJurisdiction']
];
const LIST_MEMBERS: Array<[string, string]> = [
  ['scopeGroups', 'scimClientScopeGroups'],
  ['groups', 'scimClientGroups'],
  ['cells', 'scimClientCells']
];
const CREDENTIALS: Array<[string, string]> = [
  ['password', 'scimClientPassword'],
  ['oauthClientSecret', 'scimClientOAuthClientSecret'],
  ['tlsPrivateKey', 'scimClientTlsPrivateKey']
];
const ACTIONS = ['add-client', 'update-client', 'remove-client',
                 'issue-certificate', 'test-connection', 'reconcile',
                 'retry-delivery', 'retry-dead', 'purge-dead', 'deliver-now'];
// The acts that are a CELL'S (#553 section 7): its own queue, its own
// residents. With a `cell` member they go to that cell; without one, to
// every cell that pushes.
const CELL_ACTIONS = ['retry-delivery', 'retry-dead', 'purge-dead',
                      'reconcile', 'deliver-now'];
// The inter-cell operations this module registers (#553).
const OP_GROUP_SHARE = 'scim-client-group-share';
const OP_SUMMARY = 'scim-client-summary';
const OP_ACT = 'scim-client-act';
// The purpose a person's push is asked of the issuance policy under.
const PURPOSE = 'scim-provision';
// A jurisdiction code, as the cell map spells one.
const JURISDICTION_SHAPED = /^[a-z0-9][a-z0-9-]{0,31}$/;
// A cell id, as `cells.peers` spells one.
const CELL_SHAPED = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
// How long a probe elected in another cell is waited for before a cell
// takes the probe over (#553 section 5): that cell may have gone.
const FOREIGN_PROBE_MS = 120000;

interface ScimClientsDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: Json;
  mode: Json;
  errorCodes: typeof errorCodes;
  audit: Json;
  now: () => number;
  random: () => number;
  // Lazily, each: they are loaded long after this module, or would close a
  // cycle through the directory.
  applications(): Json;
  directory(): Json;
  scimMap(): Json;
  tlsClientCertificates(): Json;
  scheduler(): Json;
  ldapjs(): Json;
  // The HTTP request, replaceable by a test.
  transport?: (options: Json, body: string | null) => Promise<Json>;
  // A SERVICE DEPLOYED AS CELLS (#553), each lazily and each replaceable by
  // a test: the cell map, the channel between cells, the routing index, the
  // transfer question, and whether a person is a PROJECTION here (homed
  // elsewhere, their session held here).
  cells(): Json;
  channel(): Json;
  routing(): Json;
  transfer(): Json;
  projected(realmId: string, uuid: string): boolean;
  // The four stores, for a test that runs two cells in one process; the
  // module's own otherwise.
  stores?: { deliveries: Json; links: Json; states: Json; pauses: Json };
  // Members laid over the delivery queue's own dependencies (a test's
  // claims).
  deliveryDeps?: Json;
}

/**
 * The outbound SCIM 2.0 client (#552): every `scim-client` application entry
 * of a realm, the deliveries of its people's and groups' changes to its
 * service provider, its queues, and its reconciliation.
 */
class ScimClients {
  /**
   * The family a client's application entry is declared for.
   */
  static readonly FAMILY = FAMILY;
  /**
   * The acts the console and `/admin-api/scim/clients/:action` share.
   */
  static readonly ACTIONS = ACTIONS;
  // The queue, built once the instance is.
  readonly delivery: Json;
  // Per process: a client's discovered configuration, and its OAuth token.
  private readonly discovered = new Map<string, Json>();
  private readonly tokens = new Map<string, Json>();
  // Settings whose ignored value has been logged in this process.
  private readonly announced = new Set<string>();
  // The stores this instance reads and writes.
  private readonly deliveries: Json;
  private readonly links: Json;
  private readonly states: Json;
  private readonly pauses: Json;
  // The concurrency budget per client, briefly remembered (#553 section 5).
  private readonly budgets = new Map<string, Json>();

  /**
   * Builds the client from its dependencies, and its delivery queue.
   *
   * @param deps - the logger, settings, realms, mode, error codes, audit, the
   *   clock, and lazy loaders of the registry, the directory, the SCIM
   *   mapping, the certificate issuer, the scheduler and ldapjs
   */
  constructor(private readonly deps: ScimClientsDeps) {
    deps.log.debug("Entering ScimClients.constructor().");
    const self = this;
    const stores = deps.stores || { deliveries: deliveries, links: links,
                                    states: states, pauses: pauses };
    this.deliveries = stores.deliveries;
    this.links = stores.links;
    this.states = stores.states;
    this.pauses = stores.pauses;
    const deliveryDeps = Object.assign(outbound.OutboundDelivery.defaultDeps(),
      { now: deps.now,
        // NO TIMER OF THE QUEUE'S OWN: a retry is sent by the
        // scim-client.deliver sweep, a cluster scheduler job (#552).
        later: function (): void {
          return undefined;
        } }, deps.deliveryDeps || {});
    this.delivery = new outbound.OutboundDelivery({
      label: 'SCIM client delivery',
      store: this.deliveries,
      attemptScope: 'scimClient.delivery',
      attribute: 'scimClientBaseUrl',
      body: 'json',
      settings: { attempts: 'scimClient.attempts',
                  timeoutMs: 'scimClient.timeoutMs',
                  backoffMs: 'scimClient.backoffMs',
                  leaseMs: 'scimClient.leaseMs',
                  retentionS: 'scimClient.retentionS',
                  maxRows: 'scimClient.maxRows',
                  concurrency: 'scimClient.concurrency',
                  summaryS: 'scimClient.summaryS' },
      codes: { outboundOff: 'STS-SCIMC-0001', url: 'STS-SCIMC-0002',
               internal: 'STS-SCIMC-0006', unresolved: 'STS-SCIMC-0006',
               redirect: 'STS-SCIMC-0008', build: 'STS-SCIMC-0004',
               timeout: 'STS-SCIMC-0005', network: 'STS-SCIMC-0006',
               status400: 'STS-SCIMC-0007', status: 'STS-SCIMC-0008',
               deferred: 'STS-SCIMC-0011', stale: 'STS-SCIMC-0012',
               summary: 'STS-SCIMC-0013', sweepFailed: 'STS-SCIMC-0014',
               retry: 'STS-SCIMC-0015' },
      deadLetterHint: 'Protocols → SCIM → Clients lists each client\'s ' +
                      'dead letters.',
      prepare: function (): Promise<Json> {
        return Promise.resolve({ body: null });
      },
      send: function (row: Json): Promise<Json> {
        return self.sendRow(row);
      },
      judge: function (result: Json): Json {
        return result && result.judgement ? result.judgement : null;
      },
      backoff: function (n: number, row: Json): number {
        return self.retryDelay(n, row);
      },
      holdUntil: function (row: Json, at: number): number {
        return self.holdUntil(row, at);
      },
      onFinish: function (row: Json, state: string, code: string,
                         why: string): void {
        self.finished(row, state, code, why);
      },
      viewExtra: function (row: Json): Json {
        return { client: row.clientId, type: row.type, uuid: row.uuid,
                 name: row.name || '', pendingChange: !!row.pendingChange };
      },
      searchText: function (row: Json): string {
        return [row.clientId, row.type, row.uuid, row.name].join(' ');
      },
      sweepJob: { id: 'scim-client.deliver',
                  title: 'Outbound SCIM deliveries',
                  describe: 'Sends every outbound SCIM client\'s due ' +
                            'deliveries — new changes and retries alike — ' +
                            'to its service provider, scimClient.concurrency ' +
                            'at a time, skipping a client while it is ' +
                            'paused by its backoff, and keeps the queues to ' +
                            'their retention (#552).',
                  owner: 'scim/scim_client.ts',
                  everySetting: 'scimClient.sweepS' }
    }, deliveryDeps);
    deps.log.debug("Leaving ScimClients.constructor().");
  }

  /**
   * Returns the real modules.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): ScimClientsDeps {
    helpers.log.debug("Entering ScimClients.defaultDeps().");
    helpers.log.debug("Leaving ScimClients.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      mode: mode,
      errorCodes: errorCodes,
      audit: audit,
      now: function (): number {
        return Date.now();
      },
      random: function (): number {
        return stsCrypto.randomInt(0, 1000000) / 1000000;
      },
      applications: function (): Json {
        return require('../common/applications');
      },
      directory: function (): Json {
        return require('../ldap/ldap_server');
      },
      scimMap: function (): Json {
        return require('./scim_map');
      },
      tlsClientCertificates: function (): Json {
        return require('../common/tls_client_certificates');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      ldapjs: function (): Json {
        return require('ldapjs');
      },
      cells: function (): Json {
        return require('../common/cells');
      },
      channel: function (): Json {
        return require('../common/cell_channel');
      },
      routing: function (): Json {
        return require('../common/cell_routing');
      },
      transfer: function (): Json {
        return require('../common/cell_transfer');
      },
      projected: function (realmId: string, uuid: string): boolean {
        return require('../common/cell_sessions')
          .isProjected(realmId, 'uuid', uuid);
      }
    };
  }

  /**
   * Wires the installed instance: the directory's change observer and the
   * two scheduler jobs.
   *
   * @param instance - the instance installed
   */
  static wire(instance: ScimClients): void {
    helpers.log.debug("Entering ScimClients.wire().");
    instance.install();
    helpers.log.debug("Leaving ScimClients.wire().");
  }

  /**
   * Listens to the directory and registers the two cluster scheduler jobs.
   * Called once, by the composition root.
   */
  install(): void {
    const { log, scheduler, directory } = this.deps;
    const self = this;
    log.debug("Entering ScimClients.install().");
    try {
      directory().addAccountObserver(function (event: Json): void {
        self.observe(event);
      });
    } catch (e) {
      log.debug("Caught in ScimClients.install(): " +
                ((e && e.message) || e));
    }
    this.registerCellOps();
    this.delivery.scheduleSweep();
    const jobs = scheduler();
    if (!jobs.job('scim-client.reconcile')) {
      jobs.register({
        id: 'scim-client.reconcile',
        title: 'Outbound SCIM reconciliations',
        describe: 'Reconciles each outbound SCIM client whose ' +
                  'scimClientReconcileMinutes has come round: every person ' +
                  'and group in its scope is pushed, and what its service ' +
                  'provider holds under an externalId of this realm\'s and ' +
                  'no longer in scope is deprovisioned (#552).',
        owner: 'scim/scim_client.ts',
        everySetting: 'scimClient.reconcileCheckS', everySettingUnit: 's',
        run: function (): Promise<Json> {
          return self.reconcileDue();
        }
      });
    }
    log.debug("Leaving ScimClients.install().");
  }

  /**
   * Registers the inter-cell operations this client answers for other
   * cells (#553): `scim-client-group-share`. Harmless in a service that is
   * one cell, where nobody calls them.
   */
  registerCellOps(): void {
    const { log, channel } = this.deps;
    const self = this;
    log.debug("Entering ScimClients.registerCellOps().");
    try {
      const ch = channel();
      ch.registerOp(OP_GROUP_SHARE, function (body: Json): Promise<Json> {
        return self.answerGroupShare(body);
      });
    } catch (e) {
      log.debug("Caught in ScimClients.registerCellOps(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving ScimClients.registerCellOps().");
  }

  // =========================================================================
  // THE REGISTER: the realm's application entries declared for the family.
  // =========================================================================

  // One value of a view's fields, as text.
  private one(fields: Json, attribute: string): string {
    const { log } = this.deps;
    log.debug("Entering ScimClients.one(). " + attribute);
    const value = fields[attribute];
    log.debug("Leaving ScimClients.one().");
    return String((Array.isArray(value) ? value[0] : value) == null ? ''
      : (Array.isArray(value) ? value[0] : value)).trim();
  }

  // Every value of a view's fields, as text.
  private many(fields: Json, attribute: string): string[] {
    const { log } = this.deps;
    log.debug("Entering ScimClients.many(). " + attribute);
    const value = fields[attribute];
    const out = (Array.isArray(value) ? value : (value ? [value] : []))
      .map(function (one: Json) {
        return String(one).trim();
      }).filter(function (one: string) {
        return !!one;
      });
    log.debug("Leaving ScimClients.many(). " + out.length);
    return out;
  }

  // Whether development admits plain http to a service provider.
  private httpAllowed(): boolean {
    const { log, config, mode } = this.deps;
    log.debug("Entering ScimClients.httpAllowed().");
    const answer = !!config.value('scimClient.allowHttp') &&
      !!mode.dialsPlainHttpOutbound();
    log.debug("Leaving ScimClients.httpAllowed(). " + answer);
    return answer;
  }

  // What stops a client from being used, as sentences.
  private problemsOf(c: Json): string[] {
    const { log } = this.deps;
    log.debug("Entering ScimClients.problemsOf(). " + c.identifier);
    const out: string[] = [];
    const http = this.httpAllowed();
    const base = Rules.urlProblem(c.baseUrl, 'base URI', http, true);
    if (base) {
      out.push(base);
    }
    if (Rules.AUTH_METHODS.indexOf(c.authMethod) < 0) {
      out.push('The authentication method "' + c.authMethod + '" is not ' +
               'one of ' + Rules.AUTH_METHODS.join(', ') + '.');
    }
    if (c.authMethod === 'basic') {
      if (!c.username) {
        out.push('Basic authentication needs a user name.');
      }
      if (!c.passwordSet) {
        out.push('Basic authentication needs a password.');
      }
    }
    if (c.authMethod === 'oauth2') {
      const token = Rules.urlProblem(c.tokenEndpoint, 'token endpoint',
                                     http, false);
      if (token) {
        out.push(token);
      }
      if (!c.oauthClientId) {
        out.push('OAuth 2.0 needs a client_id.');
      }
      if (!c.oauthClientSecretSet) {
        out.push('OAuth 2.0 needs a client secret.');
      }
      if (Rules.OAUTH_CLIENT_AUTH.indexOf(c.oauthClientAuth) < 0) {
        out.push('"' + c.oauthClientAuth + '" is not one of ' +
                 Rules.OAUTH_CLIENT_AUTH.join(', ') + '.');
      }
    }
    if (Rules.TLS_SOURCES.indexOf(c.tlsSource) < 0) {
      out.push('"' + c.tlsSource + '" is not a certificate source.');
    }
    if (c.tlsSource !== 'none' &&
        (!c.tlsCertificate || !c.tlsPrivateKeySet)) {
      out.push(c.tlsSource === 'issued'
        ? 'No client certificate has been issued yet.'
        : 'A client certificate needs its certificate and its private key.');
    }
    if (c.authMethod === 'none' && c.tlsSource === 'none') {
      out.push('A client must authenticate (RFC 7644 section 2): choose ' +
               'basic or oauth2, or a TLS client certificate.');
    }
    if (Rules.SCOPE_MODES.indexOf(c.scopeMode) < 0) {
      out.push('"' + c.scopeMode + '" is not a scope.');
    }
    if (c.scopeMode === 'groups' && !c.scopeGroups.length) {
      out.push('The groups scope names no group.');
    }
    if (c.scopeMode === 'filter') {
      const filter = this.filterProblem(c.scopeFilter);
      if (filter) {
        out.push(filter);
      }
    }
    if (Rules.GROUP_MODES.indexOf(c.groupMode) < 0) {
      out.push('"' + c.groupMode + '" is not a group mode.');
    }
    if (c.groupMode === 'selected' && !c.groups.length) {
      out.push('Selected groups names no group.');
    }
    if (Rules.DEPROVISION.indexOf(c.deprovision) < 0) {
      out.push('"' + c.deprovision + '" is not deactivate or delete.');
    }
    const minutes = Number(c.reconcileMinutes);
    if (!/^\d+$/.test(String(c.reconcileMinutes)) || minutes > 525600) {
      out.push('The reconciliation interval is a whole number of minutes, ' +
               '0 to 525600.');
    }
    this.cellProblems(c).forEach(function (one) {
      out.push(one);
    });
    log.debug("Leaving ScimClients.problemsOf(). " + out.length);
    return out;
  }

  // Whether an LDAP filter can be evaluated here, as a sentence or ''.
  private filterProblem(filter: string): string {
    const { log, ldapjs } = this.deps;
    log.debug("Entering ScimClients.filterProblem().");
    if (!String(filter || '').trim()) {
      log.debug("Leaving ScimClients.filterProblem(). Empty.");
      return 'The filter scope has no filter.';
    }
    try {
      ldapjs().parseFilter(String(filter));
    } catch (e) {
      log.debug("Caught in ScimClients.filterProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving ScimClients.filterProblem(). Unreadable.");
      return 'The scope filter is not an LDAP filter (RFC 4515): ' +
             ((e && e.message) || e);
    }
    log.debug("Leaving ScimClients.filterProblem(). Readable.");
    return '';
  }

  // One application view as a client row. Never a credential: the view
  // carries the withheld sentence, so its presence says one is set.
  private rowOf(view: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ScimClients.rowOf().");
    const fields = view.fields || {};
    const row: Json = { id: view.identifier, identifier: view.identifier,
                        dn: view.dn || '', name: view.name || view.identifier };
    MEMBERS.forEach((pair) => {
      row[pair[0]] = this.one(fields, pair[1]);
    });
    LIST_MEMBERS.forEach((pair) => {
      row[pair[0]] = this.many(fields, pair[1]);
    });
    row.enabled = /^true$/i.test(this.one(fields, 'scimClientEnabled'));
    row.authMethod = row.authMethod || 'basic';
    row.oauthClientAuth = row.oauthClientAuth || 'client_secret_basic';
    row.tlsSource = row.tlsSource || 'none';
    row.scopeMode = row.scopeMode || 'all';
    row.groupMode = row.groupMode || 'none';
    row.deprovision = row.deprovision || 'deactivate';
    row.reconcileMinutes = row.reconcileMinutes || '0';
    row.jurisdiction = String(row.jurisdiction || '').toLowerCase();
    row.passwordSet = !!this.one(fields, 'scimClientPassword');
    row.oauthClientSecretSet = !!this.one(fields,
                                          'scimClientOAuthClientSecret');
    row.tlsPrivateKeySet = !!this.one(fields, 'scimClientTlsPrivateKey');
    row.certificate = this.certificateFacts(row.tlsCertificate);
    row.problems = this.problemsOf(row);
    row.usable = row.problems.length === 0;
    log.debug("Leaving ScimClients.rowOf(). " + row.identifier);
    return row;
  }

  // The subject, issuer and expiry of a client certificate, for a page.
  private certificateFacts(pem: string): Json {
    const { log } = this.deps;
    log.debug("Entering ScimClients.certificateFacts().");
    if (!pem) {
      log.debug("Leaving ScimClients.certificateFacts(). None.");
      return null;
    }
    try {
      const cert = stsCrypto.parseCertificate(pem);
      log.debug("Leaving ScimClients.certificateFacts().");
      return { subject: String(cert.subject || '').replace(/\n/g, ', '),
               issuer: String(cert.issuer || '').replace(/\n/g, ', '),
               notAfter: cert.validTo, serial: cert.serialNumber };
    } catch (e) {
      log.debug("Caught in ScimClients.certificateFacts(): " +
                ((e && e.message) || e));
      log.debug("Leaving ScimClients.certificateFacts(). Unreadable.");
      return { error: 'not a certificate' };
    }
  }

  /**
   * Whether an application view, record or raw entry is an outbound SCIM
   * client.
   *
   * @param entry - a view or record (`fields`), or raw entry attributes
   * @returns true for a client
   */
  isClient(entry: unknown): boolean {
    const { log, applications } = this.deps;
    log.debug("Entering ScimClients.isClient().");
    const e: Json = (entry && typeof entry === 'object') ? entry as Json : {};
    const record = e.fields ? e : { fields: e.attributes || e };
    const answer = applications().declaredFamiliesOf(record)
      .indexOf(FAMILY) >= 0;
    log.debug("Leaving ScimClients.isClient(). " + answer);
    return answer;
  }

  /**
   * The ambient realm's clients, as rows. Never a credential.
   *
   * @returns the rows
   */
  list(): Json[] {
    const { log, applications } = this.deps;
    const self = this;
    log.debug("Entering ScimClients.list().");
    const out = applications().list().filter(function (view: Json) {
      return self.isClient(view);
    }).map(function (view: Json) {
      return self.rowOf(view);
    });
    log.debug("Leaving ScimClients.list(). " + out.length);
    return out;
  }

  /**
   * One client of the ambient realm, by identifier or DN, or null.
   *
   * @param id - the identifier or the entry's DN
   * @returns the row, or null
   */
  get(id: string): Json | null {
    const { log } = this.deps;
    log.debug("Entering ScimClients.get(). " + id);
    const wanted = String(id || '').trim().toLowerCase();
    const found = wanted ? this.list().filter(function (row: Json) {
      return row.identifier.toLowerCase() === wanted ||
             String(row.dn).toLowerCase() === wanted;
    })[0] || null : null;
    log.debug("Leaving ScimClients.get(). " + (found ? 'found' : 'none'));
    return found;
  }

  // =========================================================================
  // A SERVICE DEPLOYED AS CELLS (#553). Every answer here is the single-cell
  // one when the service is one cell, so nothing below changes there.
  // =========================================================================

  /**
   * Whether the service is deployed as cells.
   *
   * @returns true when `cells.id` is set
   */
  multi(): boolean {
    const { log, cells } = this.deps;
    log.debug("Entering ScimClients.multi().");
    let answer = false;
    try {
      answer = !!cells().isMulti();
    } catch (e) {
      log.debug("Caught in ScimClients.multi(): " + ((e && e.message) || e));
      answer = false;
    }
    log.debug("Leaving ScimClients.multi(). " + answer);
    return answer;
  }

  // This cell's id, '' in a service that is one cell.
  private here(): string {
    const { log, cells } = this.deps;
    log.debug("Entering ScimClients.here().");
    const id = this.multi() ? String(cells().id() || '') : '';
    log.debug("Leaving ScimClients.here(). " + id);
    return id;
  }

  // What is wrong with a client's two cell members, as sentences. Their
  // shapes are checked always; that a listed cell EXISTS only where the
  // service is deployed as cells, since one cell has no map to look in.
  private cellProblems(c: Json): string[] {
    const { log, cells } = this.deps;
    log.debug("Entering ScimClients.cellProblems().");
    const out: string[] = [];
    if (c.jurisdiction && !JURISDICTION_SHAPED.test(c.jurisdiction)) {
      out.push('"' + c.jurisdiction + '" is not a jurisdiction code (lower ' +
               'case letters, digits and hyphens, as the cell map spells ' +
               'one).');
    }
    const multi = this.multi();
    (c.cells || []).forEach(function (one: string) {
      if (!CELL_SHAPED.test(one)) {
        out.push('"' + one + '" is not a cell id.');
      } else if (multi && !cells().get(one)) {
        out.push('This service has no cell "' + one + '".');
      }
    });
    log.debug("Leaving ScimClients.cellProblems(). " + out.length);
    return out;
  }

  /**
   * The cells that push to a client (#553 section 2): those its
   * `scimClientCells` lists that the service has, or every cell. Sorted, so
   * every cell computes the same list.
   *
   * @param c - the client row
   * @returns the cell ids; `['']` in a service that is one cell
   */
  pushingCells(c: Json): string[] {
    const { log, cells } = this.deps;
    log.debug("Entering ScimClients.pushingCells().");
    if (!this.multi()) {
      log.debug("Leaving ScimClients.pushingCells(). One cell.");
      return [''];
    }
    const all = (cells().all() || []).map(function (one: Json) {
      return String(one.id);
    });
    const listed = (c.cells || []).filter(function (one: string) {
      return all.indexOf(one) >= 0;
    });
    const out = (listed.length || (c.cells || []).length ? listed : all)
      .slice().sort();
    log.debug("Leaving ScimClients.pushingCells(). " + out.length);
    return out;
  }

  /**
   * Whether this cell pushes to a client at all. Always, in a service that
   * is one cell.
   *
   * @param c - the client row
   * @returns true when this cell sends for it
   */
  pushesHere(c: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering ScimClients.pushesHere().");
    const answer = !this.multi() ||
                   this.pushingCells(c).indexOf(this.here()) >= 0;
    log.debug("Leaving ScimClients.pushesHere(). " + answer);
    return answer;
  }

  /**
   * The cell that owns a group's LIFECYCLE at a client (#553 section 3) —
   * its rename and its deletion, and the merged replace for a service
   * provider without PATCH: the realm's `cells.homeCell` when it pushes to
   * the client, else one chosen by a hash of the group's UUID, the same in
   * every cell.
   *
   * @param c - the client row
   * @param uuid - the group's entryUUID
   * @returns the cell id; '' in a service that is one cell
   */
  ownerCell(c: Json, uuid: string): string {
    const { log, config } = this.deps;
    log.debug("Entering ScimClients.ownerCell().");
    const pushing = this.pushingCells(c);
    if (!this.multi() || !pushing.length) {
      log.debug("Leaving ScimClients.ownerCell(). One cell.");
      return pushing[0] || '';
    }
    const home = String(config.value('cells.homeCell') || '').trim();
    if (home && pushing.indexOf(home) >= 0) {
      log.debug("Leaving ScimClients.ownerCell(). The realm's home cell.");
      return home;
    }
    const digest = stsCrypto.sha256Hex(String(uuid || '').toLowerCase());
    const at = parseInt(digest.slice(0, 8), 16) % pushing.length;
    log.debug("Leaving ScimClients.ownerCell(). " + pushing[at]);
    return pushing[at];
  }

  /**
   * Why the issuance policy refuses to let a person's data go to a client's
   * service provider (#553 section 2), or '' when it lets it — the
   * `release-attributes` question, purpose `scim-provision`, asked by the
   * person's home cell with the client's declared jurisdiction as the
   * serving side. Never asked in a service that is one cell.
   *
   * @param c - the client row
   * @param uuid - the person's entryUUID
   * @returns the refusal's sentence, or ''
   */
  transferRefusal(c: Json, uuid: string): string {
    const { log, realms, transfer } = this.deps;
    log.debug("Entering ScimClients.transferRefusal().");
    if (!this.multi()) {
      log.debug("Leaving ScimClients.transferRefusal(). One cell.");
      return '';
    }
    let answer: Json;
    try {
      answer = transfer().releaseDecision({
        realm: realms.currentId(), homeCell: this.here(), servingCell: '',
        servingJurisdiction: c.jurisdiction || '', purpose: PURPOSE,
        subject: 'urn:uuid:' + uuid });
    } catch (e) {
      // A decision that cannot be made is not a permission: the person is
      // left out, as the strict default would leave them.
      log.debug("Caught in ScimClients.transferRefusal(): " +
                ((e && e.message) || e));
      answer = { allowed: false, why: 'the transfer could not be decided: ' +
                                      ((e && e.message) || e) };
    }
    const why = answer && answer.allowed ? '' : String((answer && answer.why) ||
                                                        'refused');
    log.debug("Leaving ScimClients.transferRefusal(). " +
              (why ? 'refused' : 'allowed'));
    return why;
  }

  // Whether a person in this cell's directory is a PROJECTION — homed in
  // another cell, their session held here (#98 D4) — and so not this
  // cell's to push.
  private projectedHere(uuid: string): boolean {
    const { log, realms, projected } = this.deps;
    log.debug("Entering ScimClients.projectedHere().");
    let answer = false;
    if (this.multi()) {
      try {
        answer = !!projected(realms.currentId(), uuid);
      } catch (e) {
        log.debug("Caught in ScimClients.projectedHere(): " +
                  ((e && e.message) || e));
        answer = false;
      }
    }
    log.debug("Leaving ScimClients.projectedHere(). " + answer);
    return answer;
  }

  // The cell a person this cell does not hold is homed in, when that is
  // ANOTHER cell — asked of the routing index, never of the local directory
  // (#553 section 4). '' when nobody holds them, or they are homed here.
  private async homedElsewhere(uuid: string): Promise<string> {
    const { log, realms, routing } = this.deps;
    log.debug("Entering ScimClients.homedElsewhere().");
    if (!this.multi()) {
      log.debug("Leaving ScimClients.homedElsewhere(). One cell.");
      return '';
    }
    const home = String(await routing().homeOf(realms.currentId(), 'uuid',
                                               uuid) || '');
    const answer = home && home !== this.here() ? home : '';
    log.debug("Leaving ScimClients.homedElsewhere(). " + (answer || 'no'));
    return answer;
  }

  /**
   * Whether a person is PUSHED by a client from this cell: in its scope, and
   * — in a service deployed as cells — homed here and released to its
   * service provider's jurisdiction by the issuance policy.
   *
   * @param c - the client row
   * @param entry - the person's entry object
   * @returns true when the person is pushed
   */
  pushable(c: Json, entry: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering ScimClients.pushable().");
    const uuid = this.uuidOf(entry);
    let answer = this.inScope(c, entry);
    if (answer && this.multi()) {
      answer = !!uuid && !this.projectedHere(uuid) &&
               !this.transferRefusal(c, uuid);
    }
    log.debug("Leaving ScimClients.pushable(). " + answer);
    return answer;
  }

  // =========================================================================
  // WHO IS IN SCOPE, AND WHICH GROUPS GO.
  // =========================================================================

  // An entry's attributes as a filter reads them: lower-cased names, and no
  // credential, so the filter is no oracle for one.
  private matchable(entry: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ScimClients.matchable().");
    const out: Json = {};
    const attributes = (entry && entry.attributes) || {};
    Object.keys(attributes).forEach(function (name) {
      const lower = name.toLowerCase();
      if (/password|secret|privatekey|credential|backupcodes|totp|history|apppassword|activationtoken/.test(lower)) {
        return;
      }
      out[lower] = [].concat(attributes[name]).map(String);
    });
    out.entrydn = [String(entry && entry.dn || '')];
    log.debug("Leaving ScimClients.matchable().");
    return out;
  }

  // Whether a group (by cn or DN) is one of a list of cns or DNs.
  private namesGroup(list: string[], group: Json): boolean {
    const { log, directory } = this.deps;
    log.debug("Entering ScimClients.namesGroup().");
    const dir = directory();
    const dn = dir.normalizeDn(String(group.dn || ''));
    const cn = String(group.cn || '').toLowerCase();
    const answer = list.some(function (one) {
      const text = String(one).trim();
      return text.indexOf('=') >= 0 ? dir.normalizeDn(text) === dn
                                    : text.toLowerCase() === cn;
    });
    log.debug("Leaving ScimClients.namesGroup(). " + answer);
    return answer;
  }

  /**
   * Whether a person's entry is in a client's scope, in the ambient realm.
   *
   * @param c - the client row
   * @param entry - the person's entry object
   * @returns true when the person is pushed
   */
  inScope(c: Json, entry: Json): boolean {
    const { log, directory, ldapjs } = this.deps;
    const self = this;
    log.debug("Entering ScimClients.inScope().");
    if (!entry) {
      log.debug("Leaving ScimClients.inScope(). No entry.");
      return false;
    }
    if (c.scopeMode === 'groups') {
      const found = directory().groupsOfUser(entry.dn).groups || [];
      const answer = found.some(function (group: Json) {
        return self.namesGroup(c.scopeGroups, group);
      });
      log.debug("Leaving ScimClients.inScope(). groups: " + answer);
      return answer;
    }
    if (c.scopeMode === 'filter') {
      let answer = false;
      try {
        answer = !!ldapjs().parseFilter(c.scopeFilter)
          .matches(this.matchable(entry), false);
      } catch (e) {
        log.debug("Caught in ScimClients.inScope(): " +
                  ((e && e.message) || e));
        log.warn(errorCodes.tag('STS-SCIMC-0022') + 'scim client "' +
                 c.identifier + '": its scope filter cannot be evaluated, ' +
                 'so nobody is in its scope.');
        answer = false;
      }
      log.debug("Leaving ScimClients.inScope(). filter: " + answer);
      return answer;
    }
    log.debug("Leaving ScimClients.inScope(). all.");
    return true;
  }

  // The in-scope people among a group's members, as entry objects.
  private membersInScope(c: Json, group: Json): Json[] {
    const { log, directory } = this.deps;
    const self = this;
    log.debug("Entering ScimClients.membersInScope().");
    const dir = directory();
    const out: Json[] = [];
    const seen: Record<string, boolean> = {};
    (group.members || []).forEach(function (member: Json) {
      const dn = dir.normalizeDn(String(member.dn || ''));
      if (!dn || seen[dn]) {
        return;
      }
      seen[dn] = true;
      const person = dir.readPerson(member.dn);
      if (person && self.pushable(c, person)) {
        out.push(person);
      }
    });
    log.debug("Leaving ScimClients.membersInScope(). " + out.length);
    return out;
  }

  /**
   * Whether a group is pushed by a client, in the ambient realm.
   *
   * @param c - the client row
   * @param group - the group's entry object, with its members
   * @returns true when the group is pushed
   */
  groupInScope(c: Json, group: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering ScimClients.groupInScope(). " + c.groupMode);
    let answer = false;
    if (!group || c.groupMode === 'none') {
      answer = false;
    } else if (c.groupMode === 'all') {
      answer = true;
    } else if (c.groupMode === 'selected') {
      answer = this.namesGroup(c.groups, { dn: group.dn,
        cn: this.firstOf(group.attributes, 'cn') });
    } else {
      answer = this.membersInScope(c, group).length > 0;
    }
    log.debug("Leaving ScimClients.groupInScope(). " + answer);
    return answer;
  }

  // The first value of an attribute, by any spelling of its name.
  private firstOf(attributes: Json, name: string): string {
    const { log } = this.deps;
    log.debug("Entering ScimClients.firstOf(). " + name);
    const key = Object.keys(attributes || {}).filter(function (one) {
      return one.toLowerCase() === name.toLowerCase();
    })[0];
    const value = key ? [].concat(attributes[key])[0] : '';
    log.debug("Leaving ScimClients.firstOf().");
    return value == null ? '' : String(value);
  }

  // The entry's UUID, from an entry object.
  private uuidOf(entry: Json): string {
    const { log } = this.deps;
    log.debug("Entering ScimClients.uuidOf().");
    const value = this.firstOf((entry && entry.attributes) || {},
                               'entryUUID').toLowerCase();
    log.debug("Leaving ScimClients.uuidOf().");
    return UUID_SHAPED.test(value) ? value : '';
  }

  // =========================================================================
  // THE QUEUE: a row per (client, resource), its state, and the pause.
  // =========================================================================

  private rowId(clientId: string, type: string, uuid: string): string {
    const { log } = this.deps;
    log.debug("Entering ScimClients.rowId().");
    log.debug("Leaving ScimClients.rowId().");
    return clientId + '|' + type + '|' + uuid;
  }

  // A client's backoff state in a realm, or a fresh one.
  private stateOf(realmId: string, clientId: string): Json {
    const { log } = this.deps;
    log.debug("Entering ScimClients.stateOf(). " + clientId);
    const held = this.states.realmMap(realmId).get(clientId);
    log.debug("Leaving ScimClients.stateOf().");
    return Object.assign({ failures: 0, pausedUntil: 0, probe: '',
                           lastReconcileAt: 0, lastReconcile: null },
                         held || {});
  }

  private writeState(realmId: string, clientId: string, patch: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ScimClients.writeState(). " + clientId);
    const next = Object.assign(this.stateOf(realmId, clientId), patch);
    this.states.realmMap(realmId).set(clientId, next);
    log.debug("Leaving ScimClients.writeState().");
    return next;
  }

  // The exponential backoff, full jitter: a random time up to base × 2^(n−1),
  // capped. Never less than a second.
  private backoffMs(n: number): number {
    const { log, config, random } = this.deps;
    log.debug("Entering ScimClients.backoffMs(). " + n);
    const base = Math.max(1000, Number(config.value('scimClient.backoffMs')));
    const cap = Math.max(base, Number(config.value('scimClient.maxBackoffMs')));
    const ceiling = Math.min(cap, base * Math.pow(2, Math.max(0, n - 1)));
    const answer = Math.max(1000, Math.round(ceiling / 2 +
                                             random() * ceiling / 2));
    log.debug("Leaving ScimClients.backoffMs(). " + answer);
    return answer;
  }

  /**
   * Queues a resource's change for a client, in the ambient realm: a new
   * row; a pending row marked changed; a sent row queued again; a dead row
   * left dead and marked as having a change waiting.
   *
   * @param c - the client row
   * @param type - `User` or `Group`
   * @param uuid - the entry's UUID
   * @param name - what to call it on a page
   * @returns the row as it stands
   */
  enqueue(c: Json, type: string, uuid: string, name?: string): Json {
    const { log, realms, now } = this.deps;
    log.debug("Entering ScimClients.enqueue(). " + type + " " + uuid);
    const realmId = realms.currentId();
    const id = this.rowId(c.identifier, type, uuid);
    const at = now();
    const due = at;
    const held = this.delivery.liveRow(realmId, id);
    let row: Json;
    if (!held) {
      // THE GENERATION IS THE CLOCK, not 1: the queue claims each attempt
      // by (key, generation, attempt), and a key written again after its row
      // was purged, expired or its client removed would otherwise ask for
      // a claim its earlier row already took — and wait out the lease
      // (scimClient.leaseMs) before anything was sent. Found by the audit's
      // test of a change after purge-dead (2026-10-13).
      row = this.delivery.queue({ id: id, realm: realmId,
        clientId: c.identifier, type: type, uuid: uuid,
        name: String(name || ''), changedAt: at, uri: c.baseUrl,
        nextAttemptAt: due, generation: at }).row;
    } else if (held.state === 'pending') {
      row = this.delivery.writeRow(Object.assign(held, {
        changedAt: at, name: String(name || held.name || '') }));
    } else if (held.state === 'sent') {
      row = this.delivery.writeRow(Object.assign(held,
        outbound.freshFields(at), {
          generation: Number(held.generation) + 1, changedAt: at,
          nextAttemptAt: due, name: String(name || held.name || '') }));
    } else {
      // A DEAD LETTER STAYS ON ITS QUEUE until an operator retries it; the
      // retry sends the resource as it is then, this change included.
      row = this.delivery.writeRow(Object.assign(held, {
        pendingChange: true, changedAt: at }));
    }
    log.debug("Leaving ScimClients.enqueue(). " + row.state);
    return row;
  }

  // A finished delivery: its audit row, the client's pause cleared or not,
  // and a change that landed while it was in flight queued again.
  private finished(row: Json, state: string, code: string, why: string): void {
    const { log, audit, realms } = this.deps;
    log.debug("Entering ScimClients.finished(). " + row.id + " " + state);
    audit.audit({ action: 'scim-client.delivery', category: 'admin',
                  protocol: 'SCIM 2.0', channel: 'internal',
                  outcome: state === 'sent' ? 'success' : 'failure',
                  errorCode: state === 'sent' ? undefined : code,
                  target: row.clientId,
                  summary: (state === 'sent' ? 'Delivered ' : 'Dead-lettered ') +
                           row.type + ' ' + (row.name || row.uuid) + ' to ' +
                           'SCIM client ' + row.clientId +
                           (state === 'sent' ? '' : ': ' + why),
                  detail: { client: row.clientId, type: row.type,
                            uuid: row.uuid, attempts: row.attempts } });
    if (state === 'sent' &&
        Number(row.changedAt) > Number(row.lastAttemptAt)) {
      const realm = realms.get(row.realm);
      const c = realm ? realms.run(realm, () => this.get(row.clientId)) : null;
      if (c && realm) {
        realms.run(realm, () => this.enqueue(c, row.type, row.uuid, row.name));
      }
    }
    log.debug("Leaving ScimClients.finished().");
  }

  /**
   * The wait before a delivery's next attempt: the exponential backoff with
   * full jitter, capped at `scimClient.maxBackoffMs`, and never shorter than
   * a Retry-After the service provider sent.
   *
   * @param n - the attempt that failed
   * @param row - the row, with the judgement's `retryAfterMs`
   * @returns milliseconds
   */
  retryDelay(n: number, row: Json): number {
    const { log } = this.deps;
    log.debug("Entering ScimClients.retryDelay(). " + n);
    const answer = Math.max(this.backoffMs(n), Number(row.retryAfterMs) || 0);
    log.debug("Leaving ScimClients.retryDelay(). " + answer);
    return answer;
  }

  /**
   * Holds a paused client's deliveries: while the pause lasts, every one;
   * after it, every one but the PROBE, until a delivery succeeds. A probe
   * that is no longer pending (sent, dead or gone) is replaced by the row
   * asking.
   *
   * @param row - a due row
   * @param at - now
   * @returns a time after `at` to hold it, or 0
   */
  holdUntil(row: Json, at: number): number {
    const { log } = this.deps;
    log.debug("Entering ScimClients.holdUntil(). " + row.id);
    const state = this.stateOf(row.realm, row.clientId);
    if (!Number(state.failures)) {
      log.debug("Leaving ScimClients.holdUntil(). Not paused.");
      return 0;
    }
    if (Number(state.pausedUntil) > at) {
      log.debug("Leaving ScimClients.holdUntil(). Paused.");
      return Number(state.pausedUntil);
    }
    if (state.probe && state.probe !== row.id) {
      const probe = this.delivery.liveRow(row.realm, state.probe);
      if (probe && probe.state === 'pending') {
        log.debug("Leaving ScimClients.holdUntil(). The probe goes first.");
        return at + Math.max(1000, this.backoffMs(1));
      }
    }
    if (state.probe !== row.id) {
      this.writeState(row.realm, row.clientId, { probe: row.id });
    }
    log.debug("Leaving ScimClients.holdUntil(). The probe.");
    return 0;
  }

  // A failure that says the SERVER is struggling pauses the client; a
  // success ends the pause. Answers the delay of the row that failed.
  private notePause(row: Json, struggling: boolean, ok: boolean,
                    retryAfterMs: number): void {
    const { log, now } = this.deps;
    log.debug("Entering ScimClients.notePause(). " + row.clientId);
    const state = this.stateOf(row.realm, row.clientId);
    if (ok) {
      // A SUCCESS ENDS THE PAUSE ONLY WHEN IT IS THE PROBE'S, or the pause has
      // run out: a request that was already in flight when another failed
      // says nothing about whether the service provider has recovered.
      const ends = !Number(state.failures) || state.probe === row.id ||
                   Number(state.pausedUntil) <= now();
      if (ends && (state.failures || state.pausedUntil)) {
        this.writeState(row.realm, row.clientId,
                        { failures: 0, pausedUntil: 0, probe: '' });
      }
      log.debug("Leaving ScimClients.notePause(). Cleared.");
      return;
    }
    if (!struggling) {
      log.debug("Leaving ScimClients.notePause(). Not the server's.");
      return;
    }
    const failures = Number(state.failures || 0) + 1;
    const pause = Math.max(this.backoffMs(failures), retryAfterMs || 0);
    // THE PROBE: the row that ends the pause goes alone.
    this.writeState(row.realm, row.clientId,
                    { failures: failures, pausedUntil: now() + pause,
                      probe: row.id });
    log.warn(errorCodes.tag('STS-SCIMC-0008') + 'scim client "' +
             row.clientId + '" in realm "' + row.realm + '": the service ' +
             'provider is failing (' + failures + ' in a row); its queue is ' +
             'paused for ' + Math.round(pause / 1000) + 's.');
    log.debug("Leaving ScimClients.notePause(). " + pause + "ms.");
  }

  // =========================================================================
  // THE DIRECTORY'S CHANGES.
  // =========================================================================

  /**
   * The directory's observer: queues each affected resource for each enabled
   * client of the realm. Never throws into the write.
   *
   * @param event - `{ kind, dn, username, realm, before, after, group }`
   */
  observe(event: Json): void {
    const { log, realms } = this.deps;
    log.debug("Entering ScimClients.observe(). " +
              (event && event.kind));
    try {
      const realm = realms.get(String((event && event.realm) || ''));
      if (realm) {
        realms.run(realm, () => this.observeInRealm(event));
      }
    } catch (e) {
      log.debug("Caught in ScimClients.observe(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SCIMC-0023') + 'scim client: a ' +
                'directory change could not be queued: ' +
                ((e && e.message) || e));
    }
    log.debug("Leaving ScimClients.observe().");
  }

  private observeInRealm(event: Json): void {
    const { log, directory } = this.deps;
    log.debug("Entering ScimClients.observeInRealm().");
    // A CELL THAT DOES NOT PUSH TO A CLIENT QUEUES NOTHING FOR IT (#553
    // section 2): `scimClientCells` lists the cells that do.
    const clients = this.list().filter((c: Json) => {
      return c.enabled && this.pushesHere(c);
    });
    if (!clients.length) {
      log.debug("Leaving ScimClients.observeInRealm(). No client.");
      return;
    }
    const dir = directory();
    const kind = String(event.kind || '');
    const pick = function (snapshot: Json): string {
      const value = snapshot && (snapshot.entryuuid || snapshot.entryUUID);
      return String((Array.isArray(value) ? value[0] : value) || '')
        .toLowerCase();
    };
    let uuid = pick(event.after) || pick(event.before);
    if (!uuid && kind.indexOf('deleted') !== 0) {
      uuid = String(dir.resourceIdOfDn(event.dn) || '').toLowerCase();
    }
    const name = String(event.username || '');
    // A PROJECTION IS NOT A RESIDENT (#553 section 1): a person whose
    // session this cell holds is pushed by their home cell, never here.
    const projection = UUID_SHAPED.test(uuid) && this.projectedHere(uuid);
    clients.forEach((c: Json) => {
      if (UUID_SHAPED.test(uuid) && !projection &&
          this.wantsDelivery(c, uuid)) {
        this.enqueue(c, 'User', uuid, name);
      }
      if (c.groupMode === 'none') {
        return;
      }
      if (kind === 'membership' && event.group) {
        this.enqueueGroupByDn(c, String(event.group));
      }
      // The person's groups: a person entering or leaving the scope changes
      // who those groups' members are there.
      const groups = (dir.groupsOfUser(event.dn).groups || []);
      groups.forEach((group: Json) => {
        this.enqueueGroupByDn(c, String(group.dn));
      });
    });
    log.debug("Leaving ScimClients.observeInRealm(). " + clients.length +
              " client(s).");
  }

  // Whether a change to a person is a delivery for a client (#553 section
  // 2): always in a service that is one cell; in one deployed as cells, NOT
  // when the issuance policy refuses the person's transfer to the client's
  // jurisdiction and this cell never pushed them — so a refusal is no
  // delivery, and never a dead letter. Pushed before, it is a delivery: the
  // one that deprovisions them.
  private wantsDelivery(c: Json, uuid: string): boolean {
    const { log } = this.deps;
    log.debug("Entering ScimClients.wantsDelivery().");
    if (!this.multi()) {
      log.debug("Leaving ScimClients.wantsDelivery(). One cell.");
      return true;
    }
    const link = this.linkOf(c, 'User', uuid);
    if (link && link.remoteId) {
      log.debug("Leaving ScimClients.wantsDelivery(). Linked.");
      return true;
    }
    const refused = this.transferRefusal(c, uuid);
    if (refused) {
      log.debug(errorCodes.tag('STS-SCIMC-0031') + 'scim client "' +
                c.identifier + '": a person is not pushed; the issuance ' +
                'policy keeps their data out of "' + (c.jurisdiction || '?') +
                '".');
    }
    log.debug("Leaving ScimClients.wantsDelivery(). " + !refused);
    return !refused;
  }

  // A group by its DN: its UUID if it is there, or the link that remembers
  // it if it is gone.
  private enqueueGroupByDn(c: Json, dn: string): void {
    const { log, directory, realms } = this.deps;
    log.debug("Entering ScimClients.enqueueGroupByDn().");
    const dir = directory();
    const group = dir.readGroupEntry(dn);
    let uuid = group ? this.uuidOf(group) : '';
    let name = group ? this.firstOf(group.attributes, 'cn') : '';
    if (!uuid) {
      const wanted = dir.normalizeDn(dn);
      const prefix = c.identifier + '|Group|';
      this.links.realmMap(realms.currentId()).forEach(function (link: Json,
                                                           key: string) {
        if (!uuid && key.indexOf(prefix) === 0 && link &&
            dir.normalizeDn(String(link.dn || '')) === wanted) {
          uuid = key.slice(prefix.length);
          name = String(link.name || '');
        }
      });
    }
    if (uuid) {
      this.enqueue(c, 'Group', uuid, name);
    }
    log.debug("Leaving ScimClients.enqueueGroupByDn(). " +
              (uuid || 'unknown'));
  }

  // =========================================================================
  // THE WIRE: one HTTP request, with the client's TLS and credential.
  // =========================================================================

  // The TLS options for a client: the CA certificates beside the public
  // roots, the host check, and the client certificate. Throws when the TLS
  // material is unusable.
  private tlsOptions(c: Json): Json {
    const { log, config, mode, applications } = this.deps;
    log.debug("Entering ScimClients.tlsOptions(). " + c.identifier);
    const pems: string[] = [];
    const add = function (text: string): void {
      const found = String(text || '').match(
        /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
      (found || []).forEach(function (one) {
        pems.push(one);
      });
    };
    add(c.caCertificates);
    const file = String(config.value('scimClient.caFile') || '').trim();
    if (file) {
      add(fs.readFileSync(file, 'utf8'));
    }
    const out: Json = OutboundTls.verifiedOptions(pems.length ? pems : null);
    if (config.value('scimClient.skipTlsVerification')) {
      if (mode.skipsOutboundTlsVerification()) {
        log.warn('scim client "' + c.identifier + '": the service ' +
                 'provider\'s certificate is NOT verified ' +
                 '(scimClient.skipTlsVerification, development mode).');
        out.rejectUnauthorized = false;
        delete out.checkServerIdentity;
      } else if (!this.announced.has('skip')) {
        this.announced.add('skip');
        log.warn(errorCodes.tag('STS-SCIMC-0027') + 'scim client: ' +
                 'scimClient.skipTlsVerification is ignored in product ' +
                 'mode; certificates are verified.');
      }
    }
    if (c.tlsSource !== 'none') {
      const key = applications().scimClientCredentialOf(
        c.identifier, 'scimClientTlsPrivateKey');
      if (!c.tlsCertificate || !key) {
        throw new Error('the client certificate or its private key is ' +
                        'missing');
      }
      // Both read here, so an unusable pair fails before anything is sent.
      stsCrypto.parseCertificate(c.tlsCertificate);
      stsCrypto.privateKeyFrom(key);
      out.cert = c.tlsCertificate;
      out.key = key;
    }
    log.debug("Leaving ScimClients.tlsOptions().");
    return out;
  }

  // One HTTP exchange. Answers `{ ok, status, kind, why, json, text,
  // headers }` and never rejects; `kind` is the queue's: url, build,
  // timeout, network or status.
  private exchange(target: string, method: string, headers: Json,
                   body: string | null, tls: Json): Promise<Json> {
    const { log, config, transport } = this.deps;
    log.debug("Entering ScimClients.exchange(). " + method);
    let parsed: URL;
    try {
      parsed = new URL(target);
    } catch (e) {
      log.debug("Caught in ScimClients.exchange(): " +
                ((e && e.message) || e));
      log.debug("Leaving ScimClients.exchange(). Not a URL.");
      return Promise.resolve({ ok: false, kind: 'url', status: 0,
                               why: 'not a URL' });
    }
    if (parsed.protocol === 'http:' && !this.httpAllowed()) {
      log.debug("Leaving ScimClients.exchange(). Plain http refused.");
      return Promise.resolve({ ok: false, kind: 'url', status: 0,
                               code: 'STS-SCIMC-0003',
                               why: 'plain http is refused (RFC 7644 ' +
                                    'section 7.2)' });
    }
    const timeout = Number(config.value('scimClient.timeoutMs'));
    const options: Json = Object.assign({}, parsed.protocol === 'https:'
      ? tls : {}, {
        method: method, hostname: parsed.hostname.replace(/^\[|\]$/g, ''),
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        headers: Object.assign({}, headers),
        timeout: timeout, protocol: parsed.protocol,
        servername: parsed.hostname });
    if (body !== null) {
      options.headers['Content-Length'] = Buffer.byteLength(body);
    }
    log.debug("Leaving ScimClients.exchange(). Sending.");
    const send = transport || ScimClients.httpRequest;
    return send(options, body).then(function (answer: Json): Json {
      if (answer.kind) {
        return answer;
      }
      let json: Json = null;
      if (answer.text) {
        try {
          json = JSON.parse(answer.text);
        } catch (e) {
          // Not JSON: an answer that is not SCIM, judged by its status alone.
          log.debug("Caught in ScimClients.exchange(): " +
                    ((e && e.message) || e));
          json = null;
        }
      }
      const status = Number(answer.status) || 0;
      const ok = status >= 200 && status < 300;
      // RFC 7644 section 3.12's Error body, read only on a failure: its
      // `status` may be a string or a number, and its scimType is what three
      // of the client's decisions turn on (tooMany, uniqueness, invalidVers).
      const error = ok ? { status: 0, scimType: '' } : Rules.errorOf(json);
      return { ok: ok, kind: ok ? '' : 'status', status: status,
               headers: answer.headers || {}, text: answer.text || '',
               json: json, scimType: error.scimType,
               errorStatus: error.status,
               why: ok ? '' : 'HTTP ' + status +
                 (error.scimType ? ' (scimType ' + error.scimType + ')'
                                 : '') +
                 (error.status && error.status !== status
                   ? ' (the Error body says ' + error.status + ')' : '') };
    });
  }

  /**
   * One HTTP request over node's http or https module: no redirect followed,
   * the answer capped. Never rejects.
   *
   * @param options - node's request options
   * @param body - the body, or null
   * @returns a promise of `{ status, headers, text }` or a failure
   *   `{ kind, why }`
   */
  static httpRequest(options: Json, body: string | null): Promise<Json> {
    helpers.log.debug("Entering ScimClients.httpRequest().");
    return new Promise(function (resolve): void {
      const lib: Json = options.protocol === 'https:' ? https : http;
      const opts = Object.assign({}, options);
      delete opts.protocol;
      let settled = false;
      const done = function (value: Json): void {
        if (!settled) {
          settled = true;
          resolve(value);
        }
      };
      let req: Json;
      try {
        req = lib.request(opts, function (res: Json): void {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', function (chunk: Buffer): void {
            size += chunk.length;
            if (size > MAX_RESPONSE_BYTES) {
              res.destroy();
              done({ kind: 'network', why: 'the answer is too large' });
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', function (): void {
            done({ status: res.statusCode, headers: res.headers,
                   text: Buffer.concat(chunks).toString('utf8') });
          });
          res.on('error', function (e: Json): void {
            done({ kind: 'network', why: String((e && e.message) || e) });
          });
        });
      } catch (e) {
        helpers.log.debug("Caught in ScimClients.httpRequest(): " +
                          ((e && e.message) || e));
        done({ kind: 'build', why: String((e && e.message) || e) });
        return;
      }
      req.on('timeout', function (): void {
        req.destroy(new Error('timeout'));
        done({ kind: 'timeout', why: 'no answer in ' + options.timeout +
                                     'ms' });
      });
      req.on('error', function (e: Json): void {
        done({ kind: 'network', why: String((e && e.message) || e) });
      });
      if (body !== null) {
        req.write(body);
      }
      req.end();
      helpers.log.debug("Leaving ScimClients.httpRequest().");
    });
  }

  // An OAuth 2.0 access token for a client, cached until a minute before it
  // expires; `fresh` forgets the cached one first.
  private async tokenFor(c: Json, tls: Json, fresh: boolean): Promise<Json> {
    const { log, applications, realms, now } = this.deps;
    log.debug("Entering ScimClients.tokenFor(). " + c.identifier);
    const key = realms.currentId() + '|' + c.identifier;
    const held = this.tokens.get(key);
    if (!fresh && held && held.expiresAt > now() + 60000 &&
        held.endpoint === c.tokenEndpoint && held.clientId === c.oauthClientId) {
      log.debug("Leaving ScimClients.tokenFor(). Cached.");
      return { ok: true, token: held.token };
    }
    this.tokens.delete(key);
    const secret = applications().scimClientCredentialOf(
      c.identifier, 'scimClientOAuthClientSecret');
    const form = new URLSearchParams({ grant_type: 'client_credentials' });
    if (c.oauthScope) {
      form.set('scope', c.oauthScope);
    }
    if (c.oauthResource) {
      form.set('resource', c.oauthResource);
    }
    const headers: Json = { 'Content-Type': 'application/x-www-form-urlencoded',
                            Accept: 'application/json' };
    if (c.oauthClientAuth === 'client_secret_post') {
      form.set('client_id', c.oauthClientId);
      form.set('client_secret', secret);
    } else {
      // RFC 6749 section 2.3.1: each half form-urlencoded before Basic.
      headers.Authorization = 'Basic ' + Buffer.from(
        encodeURIComponent(c.oauthClientId) + ':' +
        encodeURIComponent(secret)).toString('base64');
    }
    const answer = await this.exchange(c.tokenEndpoint, 'POST', headers,
                                       form.toString(), tls);
    const token = answer.json && answer.json.access_token;
    if (!answer.ok || !token) {
      log.debug("Leaving ScimClients.tokenFor(). Refused.");
      return { ok: false, answer: answer,
               why: 'the token request ' + (answer.ok ? 'answered no ' +
                    'access_token' : 'failed: ' + answer.why) };
    }
    const lifetime = Number(answer.json.expires_in) > 0
      ? Number(answer.json.expires_in) * 1000 : 300000;
    this.tokens.set(key, { token: String(token), expiresAt: now() + lifetime,
                           endpoint: c.tokenEndpoint,
                           clientId: c.oauthClientId });
    log.debug("Leaving ScimClients.tokenFor(). Issued.");
    return { ok: true, token: String(token) };
  }

  /**
   * One SCIM request for a client, authenticated as the client says, with
   * one fresh token after a 401 on a cached one.
   *
   * @param c - the client row
   * @param method - the HTTP method
   * @param path - the path under the base URI, its query included
   * @param body - the JSON body, or null
   * @param extra - more headers (If-Match)
   * @returns a promise of the exchange's answer
   */
  async request(c: Json, method: string, path: string, body: Json,
                extra?: Json): Promise<Json> {
    const { log, applications } = this.deps;
    log.debug("Entering ScimClients.request(). " + method);
    let tls: Json;
    try {
      tls = this.tlsOptions(c);
    } catch (e) {
      log.debug("Caught in ScimClients.request(): " + ((e && e.message) || e));
      log.debug("Leaving ScimClients.request(). TLS material.");
      return { ok: false, kind: 'build', status: 0, code: 'STS-SCIMC-0004',
               why: 'the TLS material is unusable: ' +
                    ((e && e.message) || e) };
    }
    const target = c.baseUrl.replace(/\/+$/, '') + path;
    const headers: Json = Object.assign({ Accept: MEDIA_TYPE + ', ' +
                                                  'application/json' },
                                        extra || {});
    const text = body === null || body === undefined ? null
      : JSON.stringify(body);
    if (text !== null) {
      headers['Content-Type'] = MEDIA_TYPE + '; charset=utf-8';
    }
    for (let round = 0; round < 2; round++) {
      if (c.authMethod === 'basic') {
        const password = applications().scimClientCredentialOf(
          c.identifier, 'scimClientPassword');
        headers.Authorization = 'Basic ' + Buffer.from(
          String(c.username) + ':' + password).toString('base64');
      } else if (c.authMethod === 'oauth2') {
        const token = await this.tokenFor(c, tls, round > 0);
        if (!token.ok) {
          log.debug("Leaving ScimClients.request(). No token.");
          const a = token.answer || {};
          return { ok: false, kind: a.kind && a.kind !== 'status'
                     ? a.kind : 'status',
                   status: a.status || 0, code: 'STS-SCIMC-0010',
                   why: token.why };
        }
        headers.Authorization = 'Bearer ' + token.token;
      }
      const answer = await this.exchange(target, method, headers, text, tls);
      if (answer.status === 401 && c.authMethod === 'oauth2' && round === 0) {
        log.debug("ScimClients.request(): 401 on a cached token; once more " +
                  "with a fresh one.");
        continue;
      }
      log.debug("Leaving ScimClients.request(). " + answer.status);
      return answer;
    }
    log.debug("Leaving ScimClients.request(). Unreachable.");
    return { ok: false, kind: 'build', status: 0, why: 'no attempt' };
  }

  // =========================================================================
  // DISCOVERY (RFC 7644 section 4; RFC 7643 sections 5, 6).
  // =========================================================================

  /**
   * What a client's service provider supports, read from its
   * /ServiceProviderConfig and /ResourceTypes and believed for ten minutes;
   * an unreadable one is assumed to support nothing optional.
   *
   * @param c - the client row
   * @param force - true to read it again now
   * @returns a promise of `{ patch, filter, maxResults, etag, endpoints,
   *   ok, why }`
   */
  async discovery(c: Json, force?: boolean): Promise<Json> {
    const { log, realms, now } = this.deps;
    log.debug("Entering ScimClients.discovery(). " + c.identifier);
    const key = realms.currentId() + '|' + c.identifier + '|' + c.baseUrl;
    const held = this.discovered.get(key);
    if (!force && held && now() - held.at < DISCOVERY_TTL_MS) {
      log.debug("Leaving ScimClients.discovery(). Cached.");
      return held;
    }
    const out: Json = { ok: false, at: now(), patch: false, filter: false,
                        maxResults: 0, etag: false, bulk: false,
                        endpoints: { User: '/Users', Group: '/Groups' },
                        requiredExtensions: {}, authenticationSchemes: [],
                        why: '' };
    const spc = await this.request(c, 'GET', '/ServiceProviderConfig', null);
    if (spc.ok && spc.json && typeof spc.json === 'object') {
      const j = spc.json;
      out.ok = true;
      out.patch = !!(j.patch && j.patch.supported);
      out.filter = !!(j.filter && j.filter.supported);
      out.maxResults = Number(j.filter && j.filter.maxResults) || 0;
      out.etag = !!(j.etag && j.etag.supported);
      out.bulk = !!(j.bulk && j.bulk.supported);
      out.authenticationSchemes = (Array.isArray(j.authenticationSchemes)
        ? j.authenticationSchemes : []).map(function (one: Json) {
          return String((one && one.type) || '');
        });
    } else {
      out.why = '/ServiceProviderConfig: ' + (spc.why || 'not a SCIM ' +
                                              'document');
      out.answer = spc;
    }
    const types = await this.request(c, 'GET', '/ResourceTypes', null);
    if (types.ok && types.json) {
      const list = Array.isArray(types.json) ? types.json
        : (types.json.Resources || []);
      list.forEach(function (one: Json) {
        const name = String((one && (one.name || one.id)) || '');
        if ((name === 'User' || name === 'Group') && one.endpoint) {
          const endpoint = String(one.endpoint);
          out.endpoints[name] = endpoint.charAt(0) === '/' ? endpoint
            : '/' + endpoint;
          out.requiredExtensions[name] = (one.schemaExtensions || [])
            .filter(function (ext: Json) {
              return ext && ext.required;
            }).map(function (ext: Json) {
              return String(ext.schema);
            });
        }
      });
    }
    if (!out.ok) {
      log.warn(errorCodes.tag('STS-SCIMC-0019') + 'scim client "' +
               c.identifier + '": ' + out.why + '. Assuming /Users and ' +
               '/Groups, and no PATCH, filter or ETag support.');
    }
    this.discovered.set(key, out);
    log.debug("Leaving ScimClients.discovery(). ok=" + out.ok);
    return out;
  }

  // =========================================================================
  // THE RESOURCES THIS CLIENT SENDS.
  // =========================================================================

  /**
   * A person's entry as the User resource this client sends: the SCIM
   * server's own mapping, with nothing a client may not send (`id`, `meta`,
   * `groups`), no extension but the enterprise one, `externalId` the entry's
   * UUID, and the manager as the service provider's id where that person is
   * there.
   *
   * @param c - the client row
   * @param entry - the person's entry object
   * @returns the resource
   */
  outboundUser(c: Json, entry: Json): Json {
    const { log, scimMap, directory, realms } = this.deps;
    log.debug("Entering ScimClients.outboundUser().");
    const map = scimMap();
    const dir = directory();
    let resource = map.toScimUser(entry, {
      groups: [], rdnName: dir.usernameOfEntry(entry) });
    resource = map.prune(resource);
    delete resource.id;
    delete resource.meta;
    delete resource.groups;
    delete resource.password;
    const out: Json = {};
    const enterprise: Json = {};
    Object.keys(resource).forEach(function (name) {
      const value = resource[name];
      if (name === 'schemas') {
        return;
      }
      if (name.indexOf('urn:') !== 0) {
        out[name] = value;
        return;
      }
      if (name === ENTERPRISE_SCHEMA) {
        Object.assign(enterprise, value || {});
        return;
      }
      if (name.indexOf(ENTERPRISE_SCHEMA + ':') === 0) {
        enterprise[name.slice(ENTERPRISE_SCHEMA.length + 1)] = value;
      }
      // Any other extension — this service's own — is not the service
      // provider's to read.
    });
    if (enterprise.manager && enterprise.manager.value) {
      const managerUuid = String(dir.resourceIdOfDn(enterprise.manager.value)
                                 || '').toLowerCase();
      const link = this.links.realmMap(realms.currentId()).get(
        this.rowId(c.identifier, 'User', managerUuid));
      if (link && link.remoteId) {
        enterprise.manager = { value: link.remoteId };
      } else {
        delete enterprise.manager;
      }
    }
    out.schemas = [USER_SCHEMA];
    if (Object.keys(enterprise).length) {
      out.schemas.push(ENTERPRISE_SCHEMA);
      out[ENTERPRISE_SCHEMA] = enterprise;
    }
    out.externalId = this.uuidOf(entry);
    log.debug("Leaving ScimClients.outboundUser().");
    return out;
  }

  // =========================================================================
  // WHAT A RESOURCE MUST CARRY, AND WHAT A REPLACE CLEARS.
  // =========================================================================

  /**
   * Why a resource may not be sent to a client's service provider, as a
   * failure the queue dead-letters, or null when it may: an attribute RFC
   * 7643 requires is missing (STS-SCIMC-0030), or /ResourceTypes marks an
   * extension `required` that this client has no values for
   * (STS-SCIMC-0029). The enterprise extension is ADDED, empty where the
   * entry has none of it: RFC 7643 section 4.3 makes none of its attributes
   * required, so an empty one is a valid one.
   *
   * @param disc - the discovery
   * @param type - `User` or `Group`
   * @param body - the resource; the enterprise extension is added to it
   * @returns null, or `{ ok: false, code, why }`
   */
  unsendable(disc: Json, type: string, body: Json): Json | null {
    const { log } = this.deps;
    log.debug("Entering ScimClients.unsendable(). " + type);
    const missing = Rules.missingRequired(type, body);
    if (missing.length) {
      log.debug("Leaving ScimClients.unsendable(). Missing an attribute.");
      return { ok: false, code: 'STS-SCIMC-0030',
               why: 'the ' + type + ' has no ' + missing.join(' or ') +
                    ', which RFC 7643 requires; nothing was sent' };
    }
    const required: string[] = (disc.requiredExtensions &&
                                disc.requiredExtensions[type]) || [];
    const unknown: string[] = [];
    required.forEach(function (schema: string) {
      if (body.schemas.indexOf(schema) >= 0) {
        return;
      }
      if (type === 'User' && schema === ENTERPRISE_SCHEMA) {
        body.schemas.push(ENTERPRISE_SCHEMA);
        body[ENTERPRISE_SCHEMA] = body[ENTERPRISE_SCHEMA] || {};
        return;
      }
      unknown.push(schema);
    });
    if (unknown.length) {
      log.debug("Leaving ScimClients.unsendable(). A required extension.");
      return { ok: false, code: 'STS-SCIMC-0029',
               why: 'the service provider\'s ' + type + ' resource type ' +
                    'requires the extension ' + unknown.join(', ') +
                    ', which this client has no values for; nothing was ' +
                    'sent' };
    }
    log.debug("Leaving ScimClients.unsendable(). Sendable.");
    return null;
  }

  /**
   * What a User this client sends OWNS there: each attribute it carries
   * with a value, top-level or of the enterprise extension
   * (`<urn>:<name>`), and whether it is multi-valued (`many`) or not
   * (`one`). Kept on the link, so the next replace can clear what the
   * entry no longer has.
   *
   * @param body - the resource sent
   * @returns `{ name: 'one' | 'many' }`
   */
  static ownedOf(body: Json): Json {
    helpers.log.debug("Entering ScimClients.ownedOf().");
    const out: Json = {};
    const note = function (key: string, value: Json): void {
      if (value === null || value === undefined ||
          (Array.isArray(value) && !value.length)) {
        return;
      }
      out[key] = Array.isArray(value) ? 'many' : 'one';
    };
    Object.keys(body || {}).forEach(function (name) {
      if (name === 'schemas' || name === 'externalId') {
        return;
      }
      if (name === ENTERPRISE_SCHEMA) {
        Object.keys(body[name] || {}).forEach(function (sub) {
          note(ENTERPRISE_SCHEMA + ':' + sub, body[name][sub]);
        });
        return;
      }
      note(name, body[name]);
    });
    helpers.log.debug("Leaving ScimClients.ownedOf().");
    return out;
  }

  /**
   * A replace's body with every attribute this client sent before and the
   * entry no longer has set to `null` — `[]` for a multi-valued one — so
   * the service provider CLEARS it (RFC 7644 section 3.5.1: null and an
   * empty array are how a PUT says "no value") rather than keeping a value
   * this realm withdrew, which section 3.5.1 leaves it free to do for an
   * attribute a PUT merely leaves out.
   *
   * @param body - the resource to send
   * @param owned - the link's `owned`, or nothing
   * @returns a copy of the body with the clears added
   */
  static withClears(body: Json, owned: Json): Json {
    helpers.log.debug("Entering ScimClients.withClears().");
    const out: Json = Object.assign({}, body,
                                    { schemas: body.schemas.slice() });
    Object.keys(owned || {}).forEach(function (key) {
      const empty = owned[key] === 'many' ? [] : null;
      if (key.indexOf(ENTERPRISE_SCHEMA + ':') === 0) {
        const sub = key.slice(ENTERPRISE_SCHEMA.length + 1);
        const ext = Object.assign({}, out[ENTERPRISE_SCHEMA] || {});
        if (!(sub in ext)) {
          ext[sub] = empty;
          out[ENTERPRISE_SCHEMA] = ext;
          if (out.schemas.indexOf(ENTERPRISE_SCHEMA) < 0) {
            out.schemas.push(ENTERPRISE_SCHEMA);
          }
        }
        return;
      }
      if (!(key in out)) {
        out[key] = empty;
      }
    });
    helpers.log.debug("Leaving ScimClients.withClears().");
    return out;
  }

  // =========================================================================
  // ONE DELIVERY.
  // =========================================================================

  // A judged failure for the queue, the pause noted.
  private failure(row: Json, answer: Json, code: string, why: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering ScimClients.failure(). " + code);
    const status = Number(answer && answer.status) || 0;
    const network = answer && ['timeout', 'network'].indexOf(answer.kind) >= 0;
    // ANOTHER CELL NOT ANSWERING (#553 section 3) is worth another attempt
    // and says nothing about the service provider, so it pauses nobody.
    const cell = !!answer && answer.kind === 'cell';
    const retry = network || cell || Rules.retryable(status);
    const struggling = network || status === 429 || status >= 500;
    let retryAfterMs = 0;
    const header = answer && answer.headers && answer.headers['retry-after'];
    if (header) {
      const seconds = Number(header);
      retryAfterMs = Number.isFinite(seconds) ? seconds * 1000
        : Math.max(0, Date.parse(String(header)) - now());
    }
    retryAfterMs = Math.min(retryAfterMs, 86400000);
    this.notePause(row, struggling, false, retryAfterMs);
    log.debug("Leaving ScimClients.failure(). retry=" + retry);
    return { ok: false, status: status, kind: answer ? answer.kind : 'build',
             why: why,
             judgement: { ok: false, retry: retry, code: code, why: why,
                          patch: { retryAfterMs: retryAfterMs } } };
  }

  // The code a failed answer is filed under.
  private codeFor(answer: Json): string {
    const { log } = this.deps;
    log.debug("Entering ScimClients.codeFor().");
    let code = 'STS-SCIMC-0008';
    if (answer.code) {
      code = answer.code;
    } else if (answer.kind === 'timeout') {
      code = 'STS-SCIMC-0005';
    } else if (answer.kind === 'network') {
      code = 'STS-SCIMC-0006';
    } else if (answer.kind === 'url') {
      code = 'STS-SCIMC-0002';
    } else if (answer.kind === 'build') {
      code = 'STS-SCIMC-0004';
    } else if (answer.status === 401 || answer.status === 403) {
      code = 'STS-SCIMC-0009';
    } else if (answer.status >= 400 && answer.status < 500 &&
               !Rules.retryable(answer.status)) {
      code = 'STS-SCIMC-0007';
    }
    log.debug("Leaving ScimClients.codeFor(). " + code);
    return code;
  }

  /**
   * Sends one row: reads the resource as it is now and makes the service
   * provider hold it, or not hold it. Resolves the queue's result; never
   * rejects.
   *
   * @param row - the delivery row
   * @returns a promise of `{ ok, status, kind, why, judgement }`
   */
  async sendRow(row: Json): Promise<Json> {
    const { log, realms } = this.deps;
    log.debug("Entering ScimClients.sendRow(). " + row.id);
    const realm = realms.get(row.realm);
    if (!realm) {
      log.debug("Leaving ScimClients.sendRow(). No realm.");
      return { ok: false, status: 0, kind: 'build', why: 'no such realm',
               judgement: { ok: false, retry: false, code: 'STS-SCIMC-0001',
                            why: 'the realm is gone' } };
    }
    return realms.run(realm, async () => {
      let answer: Json;
      try {
        answer = await this.sendInRealm(row);
      } catch (e) {
        log.debug("Caught in ScimClients.sendRow(): " +
                  ((e && e.message) || e));
        answer = this.failure(row, { kind: 'build', status: 0 },
                              'STS-SCIMC-0004', String((e && e.message) || e));
      }
      log.debug("Leaving ScimClients.sendRow(). ok=" + answer.ok);
      return answer;
    });
  }

  private async sendInRealm(row: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.sendInRealm().");
    const c = this.get(row.clientId);
    if (!c || !c.enabled) {
      log.debug("Leaving ScimClients.sendInRealm(). No client.");
      return { ok: false, status: 0, kind: 'build',
               why: 'the client is gone or disabled',
               judgement: { ok: false, retry: false, code: 'STS-SCIMC-0001',
                            why: 'SCIM client "' + row.clientId + '" is ' +
                                 (c ? 'disabled' : 'gone') } };
    }
    if (c.problems.length) {
      log.debug("Leaving ScimClients.sendInRealm(). Not usable.");
      return { ok: false, status: 0, kind: 'url', why: c.problems[0],
               judgement: { ok: false, retry: false,
                            code: 'STS-SCIMC-0002', why: c.problems[0] } };
    }
    // NOTHING TO SEND, decided before the service provider is asked anything
    // (#553): a cell that no longer pushes to the client, a person handed
    // over to another cell, a person the issuance policy keeps out who was
    // never pushed. Each is done, not failed.
    const idle = await this.nothingToSend(c, row);
    if (idle) {
      log.debug("Leaving ScimClients.sendInRealm(). Nothing to send.");
      return { ok: true, status: 200, kind: '', judgement: { ok: true } };
    }
    const disc = await this.discovery(c);
    if (!disc.ok && disc.answer &&
        (['timeout', 'network'].indexOf(disc.answer.kind) >= 0 ||
         Rules.retryable(disc.answer.status))) {
      // The service provider is not answering at all: its discovery is not
      // to be believed, and the delivery waits like any other failure.
      this.discovered.delete(this.deps.realms.currentId() + '|' +
                             c.identifier + '|' + c.baseUrl);
      log.debug("Leaving ScimClients.sendInRealm(). Unreachable.");
      return this.failure(row, disc.answer, this.codeFor(disc.answer),
                          disc.why);
    }
    const outcome = row.type === 'Group'
      ? await this.syncGroup(c, disc, row)
      : await this.syncUser(c, disc, row);
    if (outcome.ok) {
      this.notePause(row, false, true, 0);
      log.debug("Leaving ScimClients.sendInRealm(). Delivered.");
      return { ok: true, status: outcome.status || 200, kind: '',
               judgement: { ok: true } };
    }
    log.debug("Leaving ScimClients.sendInRealm(). Failed.");
    return this.failure(row, outcome.answer || {},
                        outcome.code || this.codeFor(outcome.answer || {}),
                        outcome.why || (outcome.answer || {}).why ||
                        'it failed');
  }

  // A resource's link, its key and its store.
  private linkOf(c: Json, type: string, uuid: string): Json {
    const { log, realms } = this.deps;
    log.debug("Entering ScimClients.linkOf().");
    const held = this.links.realmMap(realms.currentId())
      .get(this.rowId(c.identifier, type, uuid));
    log.debug("Leaving ScimClients.linkOf().");
    return held ? Object.assign({}, held) : null;
  }

  private writeLink(c: Json, type: string, uuid: string, link: Json | null):
      void {
    const { log, realms, now } = this.deps;
    log.debug("Entering ScimClients.writeLink().");
    const store = this.links.realmMap(realms.currentId());
    const key = this.rowId(c.identifier, type, uuid);
    if (link) {
      store.set(key, Object.assign({}, link, { at: now() }));
    } else {
      store.delete(key);
    }
    log.debug("Leaving ScimClients.writeLink().");
  }

  // The resources a list answer carries (RFC 7644 section 3.4.2: no
  // `Resources` when there are none).
  private static resourcesOf(json: Json): Json[] {
    helpers.log.debug("Entering ScimClients.resourcesOf().");
    const list = json && Array.isArray(json.Resources) ? json.Resources : [];
    helpers.log.debug("Leaving ScimClients.resourcesOf(). " + list.length);
    return list;
  }

  /**
   * Finds the service provider's resource by an attribute's value, where it
   * supports filtering. Answers `{ ok, id, etag }` (`id` '' when there is
   * none), or a failure; more than one match is a failure for an operator.
   *
   * @param c - the client row
   * @param disc - the discovery
   * @param type - `User` or `Group`
   * @param attribute - `externalId`, `userName` or `displayName`
   * @param value - the value
   * @returns a promise of the answer
   */
  async findBy(c: Json, disc: Json, type: string, attribute: string,
               value: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.findBy(). " + type + " " + attribute);
    if (!disc.filter || !value) {
      log.debug("Leaving ScimClients.findBy(). No filtering.");
      return { ok: true, id: '' };
    }
    const query = '?filter=' +
      encodeURIComponent(Rules.eqFilter(attribute, value)) +
      '&attributes=' + encodeURIComponent('id,externalId,meta');
    let answer = await this.request(c, 'GET', disc.endpoints[type] + query,
                                    null);
    if (ScimClients.isTooMany(answer)) {
      // NARROWED (RFC 7644 section 3.4.2: tooMany is "more results than the
      // server is willing to calculate or process"): the filter is already
      // one equality, so what is left to narrow is the page. Two are all
      // this question needs — none, one, or more than one.
      log.debug("ScimClients.findBy(): tooMany; asking for two.");
      answer = await this.request(c, 'GET', disc.endpoints[type] + query +
                                  '&startIndex=1&count=2', null);
      if (ScimClients.isTooMany(answer)) {
        log.debug("Leaving ScimClients.findBy(). tooMany, narrowed.");
        return { ok: false, answer: answer, code: 'STS-SCIMC-0028',
                 why: 'the service provider answered tooMany to an ' +
                      'equality filter on ' + attribute + ', even for a ' +
                      'page of two' };
      }
    }
    if (!answer.ok) {
      log.debug("Leaving ScimClients.findBy(). Failed.");
      return { ok: false, answer: answer };
    }
    const found = ScimClients.resourcesOf(answer.json);
    if (found.length > 1) {
      log.debug("Leaving ScimClients.findBy(). Ambiguous.");
      return { ok: false, answer: answer, code: 'STS-SCIMC-0026',
               why: 'the service provider holds ' + found.length + ' ' + type +
                    ' resources with this ' + attribute };
    }
    const one = found[0] || null;
    log.debug("Leaving ScimClients.findBy(). " + (one ? 'found' : 'none'));
    return { ok: true, id: one && one.id ? String(one.id) : '',
             etag: one && one.meta && one.meta.version
               ? String(one.meta.version) : '' };
  }

  // The ETag of an answer: the header, else meta.version (RFC 7644 section
  // 3.14), verbatim — `W/` included.
  private static etagOf(answer: Json): string {
    helpers.log.debug("Entering ScimClients.etagOf().");
    const header = answer && answer.headers && answer.headers.etag;
    const meta = answer && answer.json && answer.json.meta &&
                 answer.json.meta.version;
    helpers.log.debug("Leaving ScimClients.etagOf().");
    return String(header || meta || '');
  }

  // Whether an answer is RFC 7644 section 3.4.2's tooMany: a 400 whose Error
  // body says so.
  private static isTooMany(answer: Json): boolean {
    helpers.log.debug("Entering ScimClients.isTooMany().");
    const answer2 = !!answer && answer.status === 400 &&
                    answer.scimType === 'tooMany';
    helpers.log.debug("Leaving ScimClients.isTooMany(). " + answer2);
    return answer2;
  }

  // Whether an answer says the version sent is stale: 412 (RFC 7644 section
  // 3.14), or a 400 `invalidVers` (section 3.12), which a service provider
  // answers to an If-Match it no longer holds.
  private static isStale(answer: Json): boolean {
    helpers.log.debug("Entering ScimClients.isStale().");
    const stale = !!answer && (answer.status === 412 ||
      (answer.status === 400 && answer.scimType === 'invalidVers'));
    helpers.log.debug("Leaving ScimClients.isStale(). " + stale);
    return stale;
  }

  // A write to a known resource — PUT, PATCH or DELETE — with If-Match where
  // the service provider keeps ETags; a stale version (412, or 400
  // invalidVers) re-reads it and tries again, bounded. A re-read answered
  // 404 is returned as it is: the caller decides what a resource that is
  // gone means (a DELETE is done; a replace creates).
  private async writeKnown(c: Json, disc: Json, method: string,
                           path: string, body: Json, etag: string):
      Promise<Json> {
    const { log, config } = this.deps;
    log.debug("Entering ScimClients.writeKnown(). " + method);
    let version = etag;
    const rounds = Math.max(0, Number(config.value('scimClient.etagRetries')));
    for (let i = 0; i <= rounds; i++) {
      const extra: Json = {};
      if (disc.etag && version) {
        extra['If-Match'] = version;
      }
      const answer = await this.request(c, method, path, body, extra);
      // Only where ETags are kept: without them no If-Match was sent, and a
      // re-read would send the same request again.
      if (!ScimClients.isStale(answer) || !disc.etag) {
        log.debug("Leaving ScimClients.writeKnown(). " + answer.status);
        return answer;
      }
      const fresh = await this.request(c, 'GET', path, null);
      if (!fresh.ok) {
        log.debug("Leaving ScimClients.writeKnown(). The re-read failed.");
        return fresh;
      }
      version = ScimClients.etagOf(fresh);
    }
    log.debug("Leaving ScimClients.writeKnown(). Stale too often.");
    return { ok: false, status: 412, kind: 'status',
             code: 'STS-SCIMC-0021',
             why: 'the ' + method + ' was refused as stale (HTTP 412 or ' +
                  'invalidVers) ' + (rounds + 1) + ' times' };
  }

  // Deactivates a user there: PATCH active false, or GET then PUT.
  private async deactivate(c: Json, disc: Json, path: string, etag: string):
      Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.deactivate().");
    if (disc.patch) {
      const answer = await this.writeKnown(c, disc, 'PATCH', path,
        { schemas: [PATCH_OP],
          Operations: [{ op: 'replace', path: 'active', value: false }] },
        etag);
      log.debug("Leaving ScimClients.deactivate(). PATCH " + answer.status);
      return answer;
    }
    const current = await this.request(c, 'GET', path, null);
    if (!current.ok || !current.json) {
      log.debug("Leaving ScimClients.deactivate(). The read failed.");
      return current;
    }
    const body = Object.assign({}, current.json, { active: false });
    delete body.id;
    delete body.meta;
    delete body.groups;
    const answer = await this.writeKnown(c, disc, 'PUT', path, body,
                                         ScimClients.etagOf(current));
    log.debug("Leaving ScimClients.deactivate(). PUT " + answer.status);
    return answer;
  }

  // The service provider's id of an entry: the link, else a search by
  // externalId. `{ ok, id, etag }` or a failure.
  private async remoteOf(c: Json, disc: Json, type: string, uuid: string):
      Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.remoteOf(). " + type);
    const link = this.linkOf(c, type, uuid);
    if (link && link.remoteId) {
      log.debug("Leaving ScimClients.remoteOf(). Linked.");
      return { ok: true, id: link.remoteId, etag: link.etag || '',
               link: link };
    }
    const found = await this.findBy(c, disc, type, 'externalId', uuid);
    log.debug("Leaving ScimClients.remoteOf(). Searched.");
    return found;
  }

  // Creates a resource; a 409 uniqueness adopts the one found by externalId,
  // then by `second` (userName or displayName). `{ ok, id, etag, created }`
  // or a failure.
  //
  // `adoptOnly` (#553 section 3, a group in a service deployed as cells):
  // the resource found by EXTERNALID alone is adopted and NOT replaced —
  // another cell made it, and a PUT of this cell's share would overwrite
  // that cell's members; the caller PATCHes this cell's members in.
  private async create(c: Json, disc: Json, type: string, body: Json,
                       second: [string, string],
                       adoptOnly?: boolean): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.create(). " + type);
    const answer = await this.request(c, 'POST', disc.endpoints[type], body);
    if (answer.ok) {
      const id = answer.json && answer.json.id;
      if (!id) {
        log.debug("Leaving ScimClients.create(). No id.");
        return { ok: false, answer: answer, code: 'STS-SCIMC-0025',
                 why: 'the create answered no resource id' };
      }
      log.debug("Leaving ScimClients.create(). Created.");
      return { ok: true, id: String(id), etag: ScimClients.etagOf(answer),
               created: true };
    }
    if (answer.status !== 409 || answer.scimType !== 'uniqueness') {
      // A 409 WITHOUT `uniqueness` is not "it is already there" (RFC 7644
      // section 3.12 gives 409 to uniqueness alone, but a service provider
      // may answer it to a conflict of its own): nothing is adopted on a
      // guess, and it is a dead letter carrying what it said.
      log.debug("Leaving ScimClients.create(). " + answer.status);
      return { ok: false, answer: answer };
    }
    // ADOPT, NOT RETRY (RFC 7644 section 3.3).
    let found = await this.findBy(c, disc, type, 'externalId',
                                  String(body.externalId || ''));
    if (found.ok && !found.id && second[1] && !adoptOnly) {
      found = await this.findBy(c, disc, type, second[0], second[1]);
    }
    if (!found.ok || !found.id) {
      log.debug("Leaving ScimClients.create(). Nothing to adopt.");
      return found.ok ? { ok: false, answer: answer, code: 'STS-SCIMC-0020',
                          why: 'HTTP 409 uniqueness, and nothing to adopt ' +
                               'was found by externalId or ' + second[0] }
                      : found;
    }
    if (adoptOnly) {
      log.debug("Leaving ScimClients.create(). Adopted, not replaced.");
      return { ok: true, id: found.id, etag: found.etag || '',
               adopted: true };
    }
    const path = disc.endpoints[type] + '/' + encodeURIComponent(found.id);
    const replaced = await this.writeKnown(c, disc, 'PUT', path, body,
                                           found.etag || '');
    if (!replaced.ok) {
      log.debug("Leaving ScimClients.create(). The adopt failed.");
      return { ok: false, answer: replaced };
    }
    log.debug("Leaving ScimClients.create(). Adopted.");
    return { ok: true, id: found.id, etag: ScimClients.etagOf(replaced),
             adopted: true };
  }

  // Whether a row needs nothing sent, in a service deployed as cells
  // (#553): the sentence saying why, or ''. Never in one cell.
  private async nothingToSend(c: Json, row: Json): Promise<string> {
    const { log, directory } = this.deps;
    log.debug("Entering ScimClients.nothingToSend().");
    if (!this.multi()) {
      log.debug("Leaving ScimClients.nothingToSend(). One cell.");
      return '';
    }
    if (!this.pushesHere(c)) {
      log.debug("Leaving ScimClients.nothingToSend(). Not pushed from here.");
      return 'this cell does not push to the client';
    }
    if (row.type !== 'User') {
      log.debug("Leaving ScimClients.nothingToSend(). A group.");
      return '';
    }
    const dir = directory();
    const stored = dir.entryByUuid(row.uuid);
    const projection = this.projectedHere(row.uuid);
    const resident = !!stored && dir.isPersonEntry(stored) && !projection;
    if (!resident) {
      // A MOVE IS A HANDOVER, NOT A DEPROVISION (#553 section 4): the routing
      // index says where they are now, and that cell pushes them — adopting
      // the resource by its externalId, the entryUUID a move keeps.
      const elsewhere = projection ? 'a projection here'
                                   : await this.homedElsewhere(row.uuid);
      if (elsewhere) {
        this.handOver(c, row.uuid);
        log.debug("Leaving ScimClients.nothingToSend(). Handed over.");
        return 'homed in another cell';
      }
      log.debug("Leaving ScimClients.nothingToSend(). Gone everywhere.");
      return '';
    }
    const link = this.linkOf(c, 'User', row.uuid);
    if ((!link || !link.remoteId) && this.transferRefusal(c, row.uuid)) {
      log.debug(errorCodes.tag('STS-SCIMC-0031') + 'scim client "' +
                c.identifier + '": a person is not pushed; the issuance ' +
                'policy keeps their data out of "' + (c.jurisdiction || '?') +
                '".');
      log.debug("Leaving ScimClients.nothingToSend(). Kept out.");
      return 'kept out by the issuance policy';
    }
    log.debug("Leaving ScimClients.nothingToSend(). Something to send.");
    return '';
  }

  // A person this cell held is homed in another cell now (#553 section 4):
  // this cell's link to them goes, and so does their id from this cell's
  // share of every group — so this cell never REMOVES them from a group
  // they are still in, which their new home cell keeps them in.
  private handOver(c: Json, uuid: string): void {
    const { log, realms } = this.deps;
    log.debug("Entering ScimClients.handOver().");
    const link = this.linkOf(c, 'User', uuid);
    const remoteId = link && link.remoteId ? String(link.remoteId) : '';
    this.writeLink(c, 'User', uuid, null);
    if (remoteId) {
      const prefix = c.identifier + '|Group|';
      const store = this.links.realmMap(realms.currentId());
      const changed: Array<[string, Json]> = [];
      store.forEach(function (one: Json, key: string) {
        if (key.indexOf(prefix) === 0 && one && Array.isArray(one.members) &&
            one.members.indexOf(remoteId) >= 0) {
          changed.push([key, Object.assign({}, one, {
            members: one.members.filter(function (id: string) {
              return id !== remoteId;
            }) })]);
        }
      });
      changed.forEach(function (pair) {
        store.set(pair[0], pair[1]);
      });
    }
    log.debug("Leaving ScimClients.handOver().");
  }

  // One person.
  private async syncUser(c: Json, disc: Json, row: Json): Promise<Json> {
    const { log, directory } = this.deps;
    log.debug("Entering ScimClients.syncUser(). " + row.uuid);
    const dir = directory();
    const stored = dir.entryByUuid(row.uuid);
    // A PROJECTION IS NOT A RESIDENT (#553 section 1); nothingToSend() has
    // already handed one over, so here it reads as gone.
    const entry = stored && dir.isPersonEntry(stored) &&
                  !this.projectedHere(row.uuid)
      ? dir.readPerson(stored.dn) : null;
    // THE TRANSFER DECISION (#553 section 2): a refusal is OUT OF SCOPE —
    // not pushed, and deprovisioned through its link if it was.
    const keptOut = entry ? this.transferRefusal(c, row.uuid) : '';
    const wanted = !!entry && !keptOut && this.inScope(c, entry);
    if (!wanted) {
      if (keptOut) {
        const held = this.linkOf(c, 'User', row.uuid);
        if (!held || !held.remoteId) {
          log.debug("Leaving ScimClients.syncUser(). Kept out; never sent.");
          return { ok: true };
        }
      }
      const remote = await this.remoteOf(c, disc, 'User', row.uuid);
      if (!remote.ok) {
        log.debug("Leaving ScimClients.syncUser(). The lookup failed.");
        return remote;
      }
      if (!remote.id) {
        this.writeLink(c, 'User', row.uuid, null);
        log.debug("Leaving ScimClients.syncUser(). Nothing there.");
        return { ok: true };
      }
      const path = disc.endpoints.User + '/' + encodeURIComponent(remote.id);
      if (c.deprovision === 'delete') {
        // Through writeKnown(): If-Match, and a stale version re-read.
        const gone = await this.writeKnown(c, disc, 'DELETE', path, null,
                                           remote.etag || '');
        if (!gone.ok && gone.status !== 404) {
          log.debug("Leaving ScimClients.syncUser(). The delete failed.");
          return { ok: false, answer: gone };
        }
        this.writeLink(c, 'User', row.uuid, null);
        log.debug("Leaving ScimClients.syncUser(). Deleted.");
        return { ok: true, status: gone.status };
      }
      const off = await this.deactivate(c, disc, path, remote.etag || '');
      if (!off.ok && off.status !== 404) {
        log.debug("Leaving ScimClients.syncUser(). The deactivate failed.");
        return { ok: false, answer: off };
      }
      this.writeLink(c, 'User', row.uuid, off.status === 404 ? null :
        Object.assign({}, remote.link || {}, { remoteId: remote.id,
          etag: ScimClients.etagOf(off), inactive: true,
          dn: entry ? entry.dn : '', name: row.name || '' }));
      log.debug("Leaving ScimClients.syncUser(). Deactivated.");
      return { ok: true, status: off.status };
    }
    const body = this.outboundUser(c, entry);
    const refused = this.unsendable(disc, 'User', body);
    if (refused) {
      log.debug("Leaving ScimClients.syncUser(). Not sendable.");
      return refused;
    }
    const remote = await this.remoteOf(c, disc, 'User', row.uuid);
    if (!remote.ok) {
      log.debug("Leaving ScimClients.syncUser(). The lookup failed.");
      return remote;
    }
    let result: Json = null;
    if (remote.id) {
      const path = disc.endpoints.User + '/' + encodeURIComponent(remote.id);
      // What was sent before and is gone now is cleared, not left behind.
      const replaced = await this.writeKnown(c, disc, 'PUT', path,
        ScimClients.withClears(body, remote.link && remote.link.owned),
        remote.etag || '');
      if (replaced.ok) {
        result = { ok: true, id: remote.id,
                   etag: ScimClients.etagOf(replaced) };
      } else if (replaced.status !== 404) {
        log.debug("Leaving ScimClients.syncUser(). The replace failed.");
        return { ok: false, answer: replaced };
      }
    }
    if (!result) {
      result = await this.create(c, disc, 'User', body,
                                 ['userName', String(body.userName || '')]);
      if (!result.ok) {
        log.debug("Leaving ScimClients.syncUser(). The create failed.");
        return result;
      }
    }
    this.writeLink(c, 'User', row.uuid, { remoteId: result.id,
      etag: result.etag || '', inactive: body.active === false,
      dn: entry.dn, name: String(body.userName || ''),
      owned: ScimClients.ownedOf(body) });
    // A person deactivated there and active again is a member again: a group
    // leaves out a member whose link says inactive (syncGroup()).
    const reactivated = !!(remote.link && remote.link.inactive) &&
                        body.active !== false;
    // ADOPTED, IN A SERVICE DEPLOYED AS CELLS, IS A PERSON WHO MOVED HERE
    // (#553 section 4): their groups are this cell's to keep them in now.
    // Found by its externalId rather than linked here is the same arrival.
    const arrived = this.multi() &&
                    (!!result.adopted || (!!remote.id && !remote.link));
    if ((result.created || reactivated || arrived) &&
        c.groupMode !== 'none') {
      // NOW A MEMBER CAN BE NAMED (RFC 7643 section 4.2: a member's value
      // is the service provider's id): the person's groups go again.
      (dir.groupsOfUser(entry.dn).groups || []).forEach((group: Json) => {
        this.enqueueGroupByDn(c, String(group.dn));
      });
    }
    log.debug("Leaving ScimClients.syncUser(). Delivered.");
    return { ok: true };
  }

  // One group.
  private async syncGroup(c: Json, disc: Json, row: Json): Promise<Json> {
    const { log, directory } = this.deps;
    log.debug("Entering ScimClients.syncGroup(). " + row.uuid);
    if (this.multi()) {
      // A GROUP ACROSS CELLS (#553 section 3): each cell's share, and one
      // owner cell for its lifecycle.
      const across = await this.syncGroupCells(c, disc, row);
      log.debug("Leaving ScimClients.syncGroup(). Across cells.");
      return across;
    }
    const dir = directory();
    const stored = dir.entryByUuid(row.uuid);
    const group = stored ? dir.readGroupEntry(stored.dn) : null;
    const wanted = !!group && this.groupInScope(c, group);
    const remote = await this.remoteOf(c, disc, 'Group', row.uuid);
    if (!remote.ok) {
      log.debug("Leaving ScimClients.syncGroup(). The lookup failed.");
      return remote;
    }
    if (!wanted) {
      if (remote.id) {
        const path = disc.endpoints.Group + '/' +
          encodeURIComponent(remote.id);
        const gone = await this.writeKnown(c, disc, 'DELETE', path, null,
                                           remote.etag || '');
        if (!gone.ok && gone.status !== 404) {
          log.debug("Leaving ScimClients.syncGroup(). The delete failed.");
          return { ok: false, answer: gone };
        }
      }
      this.writeLink(c, 'Group', row.uuid, null);
      log.debug("Leaving ScimClients.syncGroup(). Not pushed.");
      return { ok: true };
    }
    const displayName = this.firstOf(group.attributes, 'cn') || group.dn;
    const memberIds: string[] = [];
    this.membersInScope(c, group).forEach((person: Json) => {
      const uuid = this.uuidOf(person);
      const link = uuid ? this.linkOf(c, 'User', uuid) : null;
      if (link && link.remoteId && !link.inactive) {
        memberIds.push(String(link.remoteId));
      } else if (uuid) {
        // Not there yet: the person goes first, and this group again once
        // they are (syncUser()).
        this.enqueue(c, 'User', uuid, dir.usernameOfEntry(person));
      }
    });
    const body: Json = {
      schemas: [GROUP_SCHEMA], displayName: displayName,
      externalId: row.uuid,
      members: memberIds.map(function (id) {
        return { value: id, type: 'User' };
      })
    };
    const refused = this.unsendable(disc, 'Group', body);
    if (refused) {
      log.debug("Leaving ScimClients.syncGroup(). Not sendable.");
      return refused;
    }
    let result: Json = null;
    if (remote.id) {
      const path = disc.endpoints.Group + '/' + encodeURIComponent(remote.id);
      const updated = disc.patch
        ? await this.patchGroup(c, disc, path, body, remote.etag || '')
        : await this.writeKnown(c, disc, 'PUT', path, body,
                                remote.etag || '');
      if (updated.ok) {
        result = { ok: true, id: remote.id, etag: ScimClients.etagOf(updated) };
      } else if (updated.status !== 404) {
        log.debug("Leaving ScimClients.syncGroup(). The update failed.");
        return { ok: false, answer: updated };
      }
    }
    if (!result) {
      result = await this.create(c, disc, 'Group', body,
                                 ['displayName', displayName]);
      if (!result.ok) {
        log.debug("Leaving ScimClients.syncGroup(). The create failed.");
        return result;
      }
    }
    this.writeLink(c, 'Group', row.uuid, { remoteId: result.id,
      etag: result.etag || '', dn: group.dn, name: displayName });
    log.debug("Leaving ScimClients.syncGroup(). Delivered.");
    return { ok: true };
  }

  // A group's members and name by PATCH: the members it should have against
  // the members it has, added and removed by value (RFC 7644 section 3.5.2).
  private async patchGroup(c: Json, disc: Json, path: string, body: Json,
                           etag: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.patchGroup().");
    const current = await this.request(c, 'GET', path + '?attributes=' +
      encodeURIComponent('members,displayName'), null);
    if (!current.ok) {
      log.debug("Leaving ScimClients.patchGroup(). The read failed.");
      return current;
    }
    const have = ((current.json && current.json.members) || [])
      .map(function (one: Json) {
        return String((one && one.value) || '');
      });
    const want = body.members.map(function (one: Json) {
      return String(one.value);
    });
    const operations: Json[] = [];
    if (current.json && current.json.displayName !== body.displayName) {
      operations.push({ op: 'replace', path: 'displayName',
                        value: body.displayName });
    }
    const adding = want.filter(function (id: string) {
      return have.indexOf(id) < 0;
    });
    if (adding.length) {
      operations.push({ op: 'add', path: 'members',
                        value: adding.map(function (id: string) {
                          return { value: id };
                        }) });
    }
    have.filter(function (id: string) {
      return id && want.indexOf(id) < 0;
    }).forEach(function (id: string) {
      operations.push({ op: 'remove',
                        path: 'members[' + Rules.eqFilter('value', id) + ']' });
    });
    if (!operations.length) {
      log.debug("Leaving ScimClients.patchGroup(). Nothing to change.");
      return current;
    }
    const answer = await this.writeKnown(c, disc, 'PATCH', path,
      { schemas: [PATCH_OP], Operations: operations },
      ScimClients.etagOf(current) || etag);
    log.debug("Leaving ScimClients.patchGroup(). " + answer.status);
    return answer;
  }

  // =========================================================================
  // A GROUP ACROSS CELLS (#553 section 3). A group's DEFINITION is global and
  // its person membership is split: each cell holds its own residents' share
  // (`persistence/tiers.js`). So no cell ever sends a member list:
  //   * membership changes by PATCH only — a cell adds its own linked
  //     members and removes only ids it linked itself;
  //   * any cell may create the group, and a 409 adopts the one another cell
  //     made, by externalId (the entryUUID, the same in every cell), without
  //     replacing it;
  //   * ONE OWNER CELL (ownerCell()) renames it and deletes it, deleting only
  //     when every pushing cell answers `scim-client-group-share` with no
  //     member — a cell that cannot be reached means not deleted;
  //   * a service provider without PATCH is written by the owner alone: the
  //     shares gathered over the same operation (the provider's opaque ids,
  //     nothing else), merged and PUT — and nothing PUT while a cell cannot
  //     be reached, so a partial membership is never written.
  // =========================================================================

  // Whether a group is in a client's scope by its DEFINITION — the mode and
  // the selection, not who is in it (member-groups asks every cell's share).
  private groupDefined(c: Json, group: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering ScimClients.groupDefined(). " + c.groupMode);
    let answer = false;
    if (!group || c.groupMode === 'none') {
      answer = false;
    } else if (c.groupMode === 'selected') {
      answer = this.namesGroup(c.groups, { dn: group.dn,
        cn: this.firstOf(group.attributes, 'cn') });
    } else {
      answer = true;
    }
    log.debug("Leaving ScimClients.groupDefined(). " + answer);
    return answer;
  }

  /**
   * This cell's SHARE of a group at a client (#553 section 3): the service
   * provider's ids of the group's members homed here who are pushed, linked
   * and active. Only the provider's opaque ids — never an attribute.
   *
   * @param c - the client row
   * @param group - the group's entry object, with this cell's members
   * @param queue - true to queue a member who is not there yet (their
   *   group is queued again once they are)
   * @returns the ids, sorted
   */
  shareOf(c: Json, group: Json, queue: boolean): string[] {
    const { log, directory } = this.deps;
    log.debug("Entering ScimClients.shareOf().");
    const dir = directory();
    const out: string[] = [];
    this.membersInScope(c, group).forEach((person: Json) => {
      const uuid = this.uuidOf(person);
      const link = uuid ? this.linkOf(c, 'User', uuid) : null;
      if (link && link.remoteId && !link.inactive) {
        if (out.indexOf(String(link.remoteId)) < 0) {
          out.push(String(link.remoteId));
        }
      } else if (uuid && queue) {
        this.enqueue(c, 'User', uuid, dir.usernameOfEntry(person));
      }
    });
    log.debug("Leaving ScimClients.shareOf(). " + out.length);
    return out.sort();
  }

  // The provider ids of every person this cell linked for a client: the ids
  // this cell may REMOVE from a group, and no other.
  private linkedUserIds(c: Json): Record<string, boolean> {
    const { log, realms } = this.deps;
    log.debug("Entering ScimClients.linkedUserIds().");
    const prefix = c.identifier + '|User|';
    const out: Record<string, boolean> = {};
    this.links.realmMap(realms.currentId()).forEach(function (link: Json,
                                                             key: string) {
      if (key.indexOf(prefix) === 0 && link && link.remoteId) {
        out[String(link.remoteId)] = true;
      }
    });
    log.debug("Leaving ScimClients.linkedUserIds().");
    return out;
  }

  // A failure because another cell did not answer: retried, pausing nobody.
  private cellFailure(why: string): Json {
    const { log } = this.deps;
    log.debug("Entering ScimClients.cellFailure().");
    log.debug("Leaving ScimClients.cellFailure().");
    return { ok: false, code: 'STS-SCIMC-0032', why: why,
             answer: { kind: 'cell', status: 0, why: why } };
  }

  /**
   * Asks every OTHER cell that pushes to a client for its share of a group,
   * over `scim-client-group-share` (#553 section 3).
   *
   * @param c - the client row
   * @param uuid - the group's entryUUID
   * @returns a promise of `{ shares: { cell: ids }, unreachable: [cells] }`
   */
  async askShares(c: Json, uuid: string): Promise<Json> {
    const { log, realms, channel } = this.deps;
    log.debug("Entering ScimClients.askShares().");
    const here = this.here();
    const out: Json = { shares: {}, unreachable: [] };
    const others = this.pushingCells(c).filter(function (one) {
      return one && one !== here;
    });
    await Promise.all(others.map(function (cell: string) {
      return Promise.resolve().then(function () {
        return channel().call(cell, OP_GROUP_SHARE, {
          realm: realms.currentId(), client: c.identifier, uuid: uuid });
      }).then(function (answer: Json) {
        out.shares[cell] = (answer && Array.isArray(answer.members)
          ? answer.members : []).map(String);
      }, function (e: Json) {
        log.warn(errorCodes.tag('STS-SCIMC-0032') + 'scim client "' +
                 c.identifier + '": cell "' + cell + '" did not answer ' +
                 OP_GROUP_SHARE + ': ' + ((e && e.message) || e));
        out.unreachable.push(cell);
      });
    }));
    log.debug("Leaving ScimClients.askShares(). " +
              out.unreachable.length + " unreachable.");
    return out;
  }

  // Tells a group's owner cell to look at it again (its share here changed,
  // and the owner deletes or merges). True once it is told; the owner is
  // this cell, it is queued here.
  private async tellOwner(c: Json, uuid: string, name: string):
      Promise<boolean> {
    const { log, realms, channel } = this.deps;
    log.debug("Entering ScimClients.tellOwner().");
    const owner = this.ownerCell(c, uuid);
    if (!owner || owner === this.here()) {
      this.enqueue(c, 'Group', uuid, name);
      log.debug("Leaving ScimClients.tellOwner(). Here.");
      return true;
    }
    try {
      await channel().call(owner, OP_GROUP_SHARE, {
        realm: realms.currentId(), client: c.identifier, uuid: uuid,
        recheck: true });
    } catch (e) {
      log.warn(errorCodes.tag('STS-SCIMC-0032') + 'scim client "' +
               c.identifier + '": the owner cell "' + owner + '" of a ' +
               'group could not be told: ' + ((e && e.message) || e));
      log.debug("Leaving ScimClients.tellOwner(). Unreachable.");
      return false;
    }
    log.debug("Leaving ScimClients.tellOwner(). Told.");
    return true;
  }

  /**
   * Answers `scim-client-group-share` for another cell: this cell's share of
   * a group at a client — the provider's ids, nothing else — and, with
   * `recheck`, queues the group here when this cell owns it.
   *
   * @param body - `{ realm, client, uuid, recheck }`
   * @returns a promise of `{ members }`
   */
  async answerGroupShare(body: Json): Promise<Json> {
    const { log, realms, directory } = this.deps;
    log.debug("Entering ScimClients.answerGroupShare().");
    const given = body || {};
    const realm = realms.get(String(given.realm || ''));
    if (!realm) {
      log.debug("Leaving ScimClients.answerGroupShare(). No realm.");
      return { members: [] };
    }
    const answer = realms.run(realm, () => {
      const c = this.get(String(given.client || ''));
      const uuid = String(given.uuid || '').toLowerCase();
      if (!c || !UUID_SHAPED.test(uuid) || !this.pushesHere(c)) {
        return { members: [] };
      }
      const dir = directory();
      const stored = dir.entryByUuid(uuid);
      const group = stored ? dir.readGroupEntry(stored.dn) : null;
      const members = group && this.groupDefined(c, group)
        ? this.shareOf(c, group, false) : [];
      if (given.recheck && this.ownerCell(c, uuid) === this.here()) {
        const link = this.linkOf(c, 'Group', uuid);
        this.enqueue(c, 'Group', uuid, group
          ? this.firstOf(group.attributes, 'cn') : (link && link.name) || '');
        this.deliverSoon();
      }
      return { members: members };
    });
    log.debug("Leaving ScimClients.answerGroupShare().");
    return answer;
  }

  // One group in a service deployed as cells.
  private async syncGroupCells(c: Json, disc: Json, row: Json):
      Promise<Json> {
    const { log, directory } = this.deps;
    log.debug("Entering ScimClients.syncGroupCells(). " + row.uuid);
    const dir = directory();
    const stored = dir.entryByUuid(row.uuid);
    const group = stored ? dir.readGroupEntry(stored.dn) : null;
    const defined = !!group && this.groupDefined(c, group);
    const share = defined ? this.shareOf(c, group, true) : [];
    const link = this.linkOf(c, 'Group', row.uuid);
    const facts: Json = {
      group: group, defined: defined, share: share, link: link,
      owner: this.ownerCell(c, row.uuid) === this.here(),
      before: link && Array.isArray(link.members) ? link.members : [],
      displayName: group ? (this.firstOf(group.attributes, 'cn') || group.dn)
                         : String((link && link.name) || row.name || '')
    };
    const outcome = disc.patch
      ? await this.groupByPatch(c, disc, row, facts)
      : await this.groupByMerge(c, disc, row, facts);
    log.debug("Leaving ScimClients.syncGroupCells(). ok=" + outcome.ok);
    return outcome;
  }

  // The link a cell keeps for a group: the provider's id and THIS cell's
  // share as it last wrote it.
  private keepGroupLink(c: Json, row: Json, facts: Json, id: string,
                        etag: string, members: string[]): void {
    const { log } = this.deps;
    log.debug("Entering ScimClients.keepGroupLink().");
    this.writeLink(c, 'Group', row.uuid, { remoteId: id, etag: etag || '',
      dn: facts.group ? facts.group.dn : ((facts.link && facts.link.dn) || ''),
      name: facts.displayName, members: members.slice() });
    log.debug("Leaving ScimClients.keepGroupLink().");
  }

  // A provider WITH PATCH: this cell's share by PATCH; the owner's
  // lifecycle when this cell has nothing there.
  private async groupByPatch(c: Json, disc: Json, row: Json, facts: Json):
      Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.groupByPatch().");
    const wantedHere = facts.defined &&
      (c.groupMode !== 'member-groups' || facts.share.length > 0);
    for (let round = 0; round < 2; round++) {
      const remote = await this.remoteOf(c, disc, 'Group', row.uuid);
      if (!remote.ok) {
        log.debug("Leaving ScimClients.groupByPatch(). The lookup failed.");
        return remote;
      }
      if (!wantedHere) {
        const out = await this.groupLeft(c, disc, row, facts, remote);
        log.debug("Leaving ScimClients.groupByPatch(). Nothing here.");
        return out;
      }
      let id = String(remote.id || '');
      let etag = String(remote.etag || '');
      if (!id) {
        const body: Json = { schemas: [GROUP_SCHEMA],
          displayName: facts.displayName, externalId: row.uuid,
          members: facts.share.map(function (one: string) {
            return { value: one, type: 'User' };
          }) };
        const refused = this.unsendable(disc, 'Group', body);
        if (refused) {
          log.debug("Leaving ScimClients.groupByPatch(). Not sendable.");
          return refused;
        }
        const made = await this.create(c, disc, 'Group', body,
                                       ['displayName', facts.displayName],
                                       true);
        if (!made.ok) {
          log.debug("Leaving ScimClients.groupByPatch(). Not created.");
          return made;
        }
        if (made.created) {
          this.keepGroupLink(c, row, facts, made.id, made.etag, facts.share);
          log.debug("Leaving ScimClients.groupByPatch(). Created.");
          return { ok: true };
        }
        // Another cell made it: this cell's members go in by PATCH.
        id = made.id;
        etag = made.etag || '';
      }
      const path = disc.endpoints.Group + '/' + encodeURIComponent(id);
      const patched = await this.patchShare(c, disc, path, facts,
        facts.owner ? facts.displayName : '', etag);
      if (patched.ok) {
        this.keepGroupLink(c, row, facts, id, ScimClients.etagOf(patched),
                           facts.share);
        log.debug("Leaving ScimClients.groupByPatch(). Patched.");
        return { ok: true };
      }
      if (patched.status !== 404 || round > 0) {
        log.debug("Leaving ScimClients.groupByPatch(). The PATCH failed.");
        return { ok: false, answer: patched };
      }
      // Gone there: forget the id and find or make it again.
      this.writeLink(c, 'Group', row.uuid, null);
      facts.before = [];
    }
    log.debug("Leaving ScimClients.groupByPatch(). Unreachable.");
    return { ok: false, answer: { kind: 'build', status: 0,
                                  why: 'no attempt' } };
  }

  // This cell's members of a group by PATCH (RFC 7644 section 3.5.2): adds
  // its share's ids the group lacks, removes ids THIS CELL linked that are
  // no longer in its share — never another cell's — and, for the owner, the
  // rename.
  private async patchShare(c: Json, disc: Json, path: string, facts: Json,
                           rename: string, etag: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.patchShare().");
    const current = await this.request(c, 'GET', path + '?attributes=' +
      encodeURIComponent('members,displayName'), null);
    if (!current.ok) {
      log.debug("Leaving ScimClients.patchShare(). The read failed.");
      return current;
    }
    const have = ((current.json && current.json.members) || [])
      .map(function (one: Json) {
        return String((one && one.value) || '');
      });
    const mine = this.linkedUserIds(c);
    (facts.before || []).forEach(function (id: string) {
      mine[id] = true;
    });
    const share: string[] = facts.share;
    const operations: Json[] = [];
    if (rename && current.json && current.json.displayName !== rename) {
      operations.push({ op: 'replace', path: 'displayName', value: rename });
    }
    const adding = share.filter(function (id) {
      return have.indexOf(id) < 0;
    });
    if (adding.length) {
      operations.push({ op: 'add', path: 'members',
                        value: adding.map(function (id) {
                          return { value: id };
                        }) });
    }
    have.filter(function (id: string) {
      return id && mine[id] && share.indexOf(id) < 0;
    }).forEach(function (id: string) {
      operations.push({ op: 'remove',
                        path: 'members[' + Rules.eqFilter('value', id) + ']' });
    });
    if (!operations.length) {
      log.debug("Leaving ScimClients.patchShare(). Nothing to change.");
      return current;
    }
    const answer = await this.writeKnown(c, disc, 'PATCH', path,
      { schemas: [PATCH_OP], Operations: operations },
      ScimClients.etagOf(current) || etag);
    log.debug("Leaving ScimClients.patchShare(). " + answer.status);
    return answer;
  }

  // This cell has nothing in a group (it is gone, out of the client's
  // scope, or — member-groups — none of this cell's people are in it): this
  // cell's members come out, and the OWNER decides whether the group goes.
  private async groupLeft(c: Json, disc: Json, row: Json, facts: Json,
                          remote: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.groupLeft().");
    if (remote.id && facts.before.length) {
      const path = disc.endpoints.Group + '/' + encodeURIComponent(remote.id);
      const out = await this.patchShare(c, disc, path,
        Object.assign({}, facts, { share: [] }), '', remote.etag || '');
      if (!out.ok && out.status !== 404) {
        log.debug("Leaving ScimClients.groupLeft(). The PATCH failed.");
        return { ok: false, answer: out };
      }
    }
    if (facts.owner) {
      const out = await this.ownerLifecycle(c, disc, row, facts, remote);
      log.debug("Leaving ScimClients.groupLeft(). The owner decided.");
      return out;
    }
    if (facts.link && !(await this.tellOwner(c, row.uuid,
                                             facts.displayName))) {
      log.debug("Leaving ScimClients.groupLeft(). The owner was not told.");
      return this.cellFailure('the owner cell of the group could not be ' +
                              'reached; this cell\'s members are out, and ' +
                              'whether the group goes is the owner\'s');
    }
    this.writeLink(c, 'Group', row.uuid, null);
    log.debug("Leaving ScimClients.groupLeft(). Left.");
    return { ok: true };
  }

  // THE OWNER'S LIFECYCLE, when the owner itself has nothing in the group:
  // every other pushing cell is asked for its share; any member anywhere
  // keeps the group (renamed if need be); no member anywhere — and every
  // cell answered — deletes it. A cell that cannot be reached: not deleted,
  // and retried.
  private async ownerLifecycle(c: Json, disc: Json, row: Json, facts: Json,
                               remote: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.ownerLifecycle().");
    const asked = await this.askShares(c, row.uuid);
    if (asked.unreachable.length) {
      log.debug("Leaving ScimClients.ownerLifecycle(). A cell is away.");
      return this.cellFailure('cell(s) ' + asked.unreachable.join(', ') +
                              ' could not be asked whether they still have ' +
                              'members in the group; it is not deleted');
    }
    const elsewhere = Object.keys(asked.shares).some(function (cell) {
      return asked.shares[cell].length > 0;
    });
    if (elsewhere) {
      // Kept: other cells have members. The rename is still the owner's.
      if (remote.id && facts.defined) {
        const path = disc.endpoints.Group + '/' +
          encodeURIComponent(remote.id);
        const renamed = await this.patchShare(c, disc, path,
          Object.assign({}, facts, { share: [], before: [] }),
          facts.displayName, remote.etag || '');
        if (!renamed.ok) {
          log.debug("Leaving ScimClients.ownerLifecycle(). Not renamed.");
          return { ok: false, answer: renamed };
        }
        this.keepGroupLink(c, row, facts, remote.id,
                           ScimClients.etagOf(renamed), []);
      }
      log.debug("Leaving ScimClients.ownerLifecycle(). Kept.");
      return { ok: true };
    }
    if (remote.id) {
      const path = disc.endpoints.Group + '/' + encodeURIComponent(remote.id);
      const gone = await this.writeKnown(c, disc, 'DELETE', path, null,
                                         remote.etag || '');
      if (!gone.ok && gone.status !== 404) {
        log.debug("Leaving ScimClients.ownerLifecycle(). Not deleted.");
        return { ok: false, answer: gone };
      }
    }
    this.writeLink(c, 'Group', row.uuid, null);
    log.debug("Leaving ScimClients.ownerLifecycle(). Deleted.");
    return { ok: true };
  }

  // A provider WITHOUT PATCH (#553 section 3, rcbj's decision 2): only the
  // owner writes, a PUT of every cell's share merged. Another cell tells
  // the owner; the owner PUTs only when every cell answered.
  private async groupByMerge(c: Json, disc: Json, row: Json, facts: Json):
      Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ScimClients.groupByMerge().");
    if (!facts.owner) {
      if (!(await this.tellOwner(c, row.uuid, facts.displayName))) {
        log.debug("Leaving ScimClients.groupByMerge(). Owner not told.");
        return this.cellFailure('the owner cell of the group could not be ' +
                                'reached to replace its members');
      }
      if (facts.defined || facts.link) {
        this.writeLink(c, 'Group', row.uuid, facts.defined
          ? { remoteId: (facts.link && facts.link.remoteId) || '', etag: '',
              dn: facts.group ? facts.group.dn : '',
              name: facts.displayName, members: facts.share.slice() }
          : null);
      }
      log.debug("Leaving ScimClients.groupByMerge(). The owner writes.");
      return { ok: true };
    }
    const asked = await this.askShares(c, row.uuid);
    if (asked.unreachable.length) {
      log.debug("Leaving ScimClients.groupByMerge(). A cell is away.");
      return this.cellFailure('cell(s) ' + asked.unreachable.join(', ') +
                              ' could not be asked for their members; ' +
                              'nothing is replaced until every cell ' +
                              'answers');
    }
    const merged: string[] = facts.share.slice();
    Object.keys(asked.shares).sort().forEach(function (cell) {
      asked.shares[cell].forEach(function (id: string) {
        if (merged.indexOf(id) < 0) {
          merged.push(id);
        }
      });
    });
    const remote = await this.remoteOf(c, disc, 'Group', row.uuid);
    if (!remote.ok) {
      log.debug("Leaving ScimClients.groupByMerge(). The lookup failed.");
      return remote;
    }
    const wanted = facts.defined &&
      (c.groupMode !== 'member-groups' || merged.length > 0);
    if (!wanted) {
      if (remote.id) {
        const path = disc.endpoints.Group + '/' +
          encodeURIComponent(remote.id);
        const gone = await this.writeKnown(c, disc, 'DELETE', path, null,
                                           remote.etag || '');
        if (!gone.ok && gone.status !== 404) {
          log.debug("Leaving ScimClients.groupByMerge(). Not deleted.");
          return { ok: false, answer: gone };
        }
      }
      this.writeLink(c, 'Group', row.uuid, null);
      log.debug("Leaving ScimClients.groupByMerge(). Deleted.");
      return { ok: true };
    }
    const body: Json = { schemas: [GROUP_SCHEMA],
      displayName: facts.displayName, externalId: row.uuid,
      members: merged.map(function (one) {
        return { value: one, type: 'User' };
      }) };
    const refused = this.unsendable(disc, 'Group', body);
    if (refused) {
      log.debug("Leaving ScimClients.groupByMerge(). Not sendable.");
      return refused;
    }
    let result: Json = null;
    if (remote.id) {
      const path = disc.endpoints.Group + '/' + encodeURIComponent(remote.id);
      const replaced = await this.writeKnown(c, disc, 'PUT', path, body,
                                             remote.etag || '');
      if (replaced.ok) {
        result = { ok: true, id: remote.id,
                   etag: ScimClients.etagOf(replaced) };
      } else if (replaced.status !== 404) {
        log.debug("Leaving ScimClients.groupByMerge(). Not replaced.");
        return { ok: false, answer: replaced };
      }
    }
    if (!result) {
      // A 409 here adopts AND replaces: the owner holds every share.
      result = await this.create(c, disc, 'Group', body,
                                 ['displayName', facts.displayName]);
      if (!result.ok) {
        log.debug("Leaving ScimClients.groupByMerge(). Not created.");
        return result;
      }
    }
    this.keepGroupLink(c, row, facts, result.id, result.etag || '',
                       facts.share);
    log.debug("Leaving ScimClients.groupByMerge(). Replaced, merged.");
    return { ok: true };
  }

  // =========================================================================
  // RECONCILIATION.
  // =========================================================================

  // Every resource of a type the service provider holds: `id` and
  // `externalId`, page by page from startIndex 1 (RFC 7644 section
  // 3.4.2.4), TOLERANT OF INCONSISTENT PAGES:
  //   * a page shorter than asked for is not the end — a service provider
  //     may cap a page below `count` — and neither is a missing
  //     `totalResults`: without one the paging goes on until a page is
  //     empty or brings no id not already seen (until the audit of
  //     2026-10-13 it stopped after page one, so a service provider that
  //     omits the total was reconciled one page deep);
  //   * with `totalResults`, it stops once startIndex passes it, or at an
  //     empty page, whichever is first;
  //   * a resource seen twice — the set moved under the paging — counts
  //     once;
  //   * a 400 `tooMany` NARROWS the query (section 3.4.2): the page is
  //     halved and the same page asked again, down to one; then, where the
  //     service provider filters, only resources with an externalId are
  //     asked for (`externalId pr`), which are the only ones a
  //     reconciliation reads. Past that it is a failure (STS-SCIMC-0028).
  private async listRemote(c: Json, disc: Json, type: string):
      Promise<Json> {
    const { log, config } = this.deps;
    log.debug("Entering ScimClients.listRemote(). " + type);
    let count = Math.max(1, Number(config.value('scimClient.pageSize')));
    if (disc.maxResults > 0) {
      count = Math.min(count, disc.maxResults);
    }
    let filter = '';
    const out: Json[] = [];
    const seen: Record<string, boolean> = {};
    let start = 1;
    for (let page = 0; page < MAX_PAGES; page++) {
      const answer = await this.request(c, 'GET', disc.endpoints[type] +
        '?startIndex=' + start + '&count=' + count +
        (filter ? '&filter=' + encodeURIComponent(filter) : '') +
        '&attributes=' + encodeURIComponent('id,externalId'), null);
      if (ScimClients.isTooMany(answer)) {
        if (count > 1) {
          count = Math.max(1, Math.floor(count / 2));
          log.debug("ScimClients.listRemote(): tooMany; " + count +
                    " a page.");
          continue;
        }
        if (!filter && disc.filter) {
          filter = 'externalId pr';
          log.debug("ScimClients.listRemote(): tooMany; externalId pr.");
          continue;
        }
        log.debug("Leaving ScimClients.listRemote(). tooMany, narrowed.");
        return { ok: false, answer: answer, code: 'STS-SCIMC-0028' };
      }
      if (!answer.ok) {
        log.debug("Leaving ScimClients.listRemote(). Failed.");
        return { ok: false, answer: answer };
      }
      const found = ScimClients.resourcesOf(answer.json);
      let fresh = 0;
      found.forEach(function (one: Json) {
        const id = String((one && one.id) || '');
        if (id && seen[id]) {
          return;
        }
        if (id) {
          seen[id] = true;
        }
        fresh++;
        out.push(one);
      });
      const total = answer.json && answer.json.totalResults;
      const hasTotal = total !== undefined && total !== null &&
                       Number.isFinite(Number(total));
      start += found.length;
      if (!found.length || (hasTotal && start > Number(total)) ||
          (!hasTotal && !fresh)) {
        break;
      }
    }
    log.debug("Leaving ScimClients.listRemote(). " + out.length);
    return { ok: true, resources: out };
  }

  /**
   * Reconciles one client in the ambient realm: queues every person and
   * group in its scope, and every resource the service provider holds under
   * an externalId of this realm's that is no longer in scope; then sends.
   *
   * @param c - the client row
   * @param actor - who asked, or the scheduler
   * @returns a promise of `{ ok, users, groups, deprovisioned, why }`
   */
  async reconcile(c: Json, actor: string): Promise<Json> {
    const { log, directory, realms, now, audit } = this.deps;
    log.debug("Entering ScimClients.reconcile(). " + c.identifier);
    const realmId = realms.currentId();
    const dir = directory();
    const result: Json = { ok: true, users: 0, groups: 0, deprovisioned: 0,
                           why: '' };
    if (!this.pushesHere(c)) {
      // A cell `scimClientCells` leaves out has nothing of this client's to
      // reconcile (#553 section 2).
      log.debug("Leaving ScimClients.reconcile(). Not pushed from here.");
      return Object.assign(result, { notPushedHere: true });
    }
    const multi = this.multi();
    try {
      const desired: Record<string, boolean> = {};
      // EACH CELL RECONCILES ITS OWN RESIDENTS (#553 section 6): pushable()
      // leaves out a projection and a person the policy keeps out.
      dir.allPersons().forEach((person: Json) => {
        const uuid = this.uuidOf(person);
        if (uuid && this.pushable(c, person)) {
          desired['User|' + uuid] = true;
          this.enqueue(c, 'User', uuid, dir.usernameOfEntry(person));
          result.users++;
        }
      });
      if (c.groupMode !== 'none') {
        dir.allGroupEntries().forEach((group: Json) => {
          const uuid = this.uuidOf(group);
          if (uuid && this.groupInScope(c, group)) {
            desired['Group|' + uuid] = true;
            this.enqueue(c, 'Group', uuid,
                         this.firstOf(group.attributes, 'cn'));
            result.groups++;
          }
        });
      }
      const disc = await this.discovery(c, true);
      for (const type of ['User', 'Group']) {
        if (type === 'Group' && c.groupMode === 'none' &&
            !this.hasLinks(c, 'Group')) {
          continue;
        }
        const listed = await this.listRemote(c, disc, type);
        if (!listed.ok) {
          result.ok = false;
          result.why = type + ' listing failed: ' +
                       (listed.code === 'STS-SCIMC-0028'
                         ? 'tooMany, even narrowed to one a page'
                         : ((listed.answer && listed.answer.why) ||
                            'unknown'));
          continue;
        }
        listed.resources.forEach((one: Json) => {
          const uuid = String((one && one.externalId) || '').toLowerCase();
          if (!UUID_SHAPED.test(uuid) || desired[type + '|' + uuid]) {
            return;
          }
          const link = this.linkOf(c, type, uuid);
          // OURS: an externalId this client linked, or one that is an entry
          // of this realm. Anything else belongs to somebody else.
          if (!link && !dir.entryByUuid(uuid)) {
            return;
          }
          if (multi && !link && !this.reconcilesUnlinked(c, type, uuid,
                                                         one)) {
            return;
          }
          // Already deactivated there is done — unless deprovisioning now
          // means delete, when it is queued and deleted.
          if (link && link.inactive && c.deprovision !== 'delete') {
            return;
          }
          this.enqueue(c, type, uuid, link ? link.name : '');
          result.deprovisioned++;
        });
      }
    } catch (e) {
      log.debug("Caught in ScimClients.reconcile(): " +
                ((e && e.message) || e));
      result.ok = false;
      result.why = String((e && e.message) || e);
    }
    if (!result.ok) {
      log.warn(errorCodes.tag('STS-SCIMC-0023') + 'scim client "' +
               c.identifier + '": the reconciliation failed part way: ' +
               result.why);
    }
    this.writeState(realmId, c.identifier, { lastReconcileAt: now(),
                                             lastReconcile: result });
    audit.audit({ action: 'scim-client.reconcile', category: 'admin',
                  protocol: 'SCIM 2.0', channel: 'internal',
                  outcome: result.ok ? 'success' : 'failure',
                  errorCode: result.ok ? undefined : 'STS-SCIMC-0023',
                  actor: actor, target: c.identifier,
                  summary: 'SCIM client ' + c.identifier + ' reconciled: ' +
                           result.users + ' user(s) and ' + result.groups +
                           ' group(s) in scope, ' + result.deprovisioned +
                           ' to deprovision' +
                           (result.ok ? '' : '; ' + result.why),
                  detail: result });
    this.deliverSoon();
    log.debug("Leaving ScimClients.reconcile(). ok=" + result.ok);
    return result;
  }

  // In a service deployed as cells, whether a remote resource this cell
  // never linked is this cell's to deprovision (#553 section 6). A person:
  // only a RESIDENT here — a projection is another cell's — and a resident
  // the policy keeps out is linked to the resource found, so it is
  // deprovisioned through that link and never searched for again. A group:
  // only in its OWNER cell, which alone deletes one.
  private reconcilesUnlinked(c: Json, type: string, uuid: string,
                             remote: Json): boolean {
    const { log, directory } = this.deps;
    log.debug("Entering ScimClients.reconcilesUnlinked(). " + type);
    if (type === 'Group') {
      const owner = this.ownerCell(c, uuid) === this.here();
      log.debug("Leaving ScimClients.reconcilesUnlinked(). Owner: " + owner);
      return owner;
    }
    const dir = directory();
    const stored = dir.entryByUuid(uuid);
    if (!stored || !dir.isPersonEntry(stored) || this.projectedHere(uuid)) {
      log.debug("Leaving ScimClients.reconcilesUnlinked(). Not resident.");
      return false;
    }
    if (remote && remote.id && this.transferRefusal(c, uuid)) {
      this.writeLink(c, 'User', uuid, { remoteId: String(remote.id),
                                        etag: '', dn: stored.dn, name: '' });
    }
    log.debug("Leaving ScimClients.reconcilesUnlinked(). Resident.");
    return true;
  }

  // Whether a client has linked any resource of a type.
  private hasLinks(c: Json, type: string): boolean {
    const { log, realms } = this.deps;
    log.debug("Entering ScimClients.hasLinks().");
    const prefix = c.identifier + '|' + type + '|';
    let found = false;
    this.links.realmMap(realms.currentId()).forEach(function (link: Json,
                                                         key: string) {
      if (!found && key.indexOf(prefix) === 0) {
        found = true;
      }
    });
    log.debug("Leaving ScimClients.hasLinks(). " + found);
    return found;
  }

  /**
   * The `scim-client.reconcile` job: every client in every realm whose
   * interval has come round.
   *
   * @returns a promise of `{ reconciled }`
   */
  async reconcileDue(): Promise<Json> {
    const { log, realms, now } = this.deps;
    log.debug("Entering ScimClients.reconcileDue().");
    let reconciled = 0;
    for (const realm of realms.list()) {
      await realms.run(realm, async () => {
        for (const c of this.list()) {
          const minutes = Number(c.reconcileMinutes) || 0;
          const state = this.stateOf(realm.id, c.identifier);
          if (c.enabled && c.usable && minutes > 0 && this.pushesHere(c) &&
              now() - Number(state.lastReconcileAt || 0) >= minutes * 60000) {
            await this.reconcile(c, 'scheduler');
            reconciled++;
          }
        }
      });
    }
    log.debug("Leaving ScimClients.reconcileDue(). " + reconciled);
    return { reconciled: reconciled };
  }

  // Sends what is due now, without waiting: the sweep, once.
  private deliverSoon(): void {
    const { log } = this.deps;
    log.debug("Entering ScimClients.deliverSoon().");
    this.delivery.sweep().catch(function (e: Json) {
      log.debug("Caught in ScimClients.deliverSoon(): " +
                ((e && e.message) || e));
    });
    log.debug("Leaving ScimClients.deliverSoon().");
  }

  // =========================================================================
  // THE VIEW AND THE ACTS (rule 7: the console's and /admin-api's).
  // =========================================================================

  // A client's queues in the ambient realm: queued, retrying, dead, sent.
  private queuesOf(clientId: string, limit: number): Json {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering ScimClients.queuesOf(). " + clientId);
    const out: Json = { queued: [], retrying: [], dead: [],
                        counts: { queued: 0, retrying: 0, dead: 0, sent: 0 } };
    this.deliveries.realmMap(realms.currentId()).forEach(function (row: Json) {
      if (!row || row.clientId !== clientId) {
        return;
      }
      const which = row.state === 'dead' ? 'dead'
        : row.state === 'sent' ? 'sent'
        : Number(row.attempts) > 0 ? 'retrying' : 'queued';
      out.counts[which]++;
      if (which !== 'sent' && out[which].length < limit) {
        out[which].push(self.delivery.view(row));
      }
    });
    ['queued', 'retrying', 'dead'].forEach(function (which) {
      out[which].sort(function (a: Json, b: Json) {
        return String(b.queuedAt || '').localeCompare(String(a.queuedAt || ''));
      });
    });
    log.debug("Leaving ScimClients.queuesOf().");
    return out;
  }

  /**
   * The view Protocols → SCIM → Clients is drawn from: every client of the
   * realm with its queue counts and pause; and, where `query.client` names
   * one, that client's page — its configuration, discovery, queues and
   * links. Never a credential.
   *
   * @param query - the page's query
   * @returns the view
   */
  view(query?: Json): Json {
    const { log, realms, now } = this.deps;
    const self = this;
    log.debug("Entering ScimClients.view().");
    const realmId = realms.currentId();
    const rows = this.list().map(function (c: Json) {
      const state = self.stateOf(realmId, c.identifier);
      return Object.assign({}, c, {
        counts: self.queuesOf(c.identifier, 0).counts,
        pausedUntil: Number(state.pausedUntil) > now()
          ? new Date(Number(state.pausedUntil)).toISOString() : '',
        failures: Number(state.failures) || 0,
        lastReconcileAt: state.lastReconcileAt
          ? new Date(Number(state.lastReconcileAt)).toISOString() : '',
        lastReconcile: state.lastReconcile || null });
    });
    const out: Json = {
      family: FAMILY,
      clients: rows,
      choices: { authMethods: Rules.AUTH_METHODS.slice(),
                 oauthClientAuth: Rules.OAUTH_CLIENT_AUTH.slice(),
                 tlsSources: Rules.TLS_SOURCES.slice(),
                 scopeModes: Rules.SCOPE_MODES.slice(),
                 groupModes: Rules.GROUP_MODES.slice(),
                 deprovision: Rules.DEPROVISION.slice() },
      httpAllowed: this.httpAllowed()
    };
    const wanted = query && query.client ? String(query.client) : '';
    if (wanted) {
      const c = rows.filter(function (one: Json) {
        return one.identifier.toLowerCase() === wanted.toLowerCase();
      })[0] || null;
      if (c) {
        let linked = 0;
        this.links.realmMap(realmId).forEach(function (link: Json,
                                                       key: string) {
          if (key.indexOf(c.identifier + '|') === 0) {
            linked++;
          }
        });
        const disc = this.discovered.get(realmId + '|' + c.identifier + '|' +
                                         c.baseUrl) || null;
        out.client = Object.assign({}, c, {
          queues: this.queuesOf(c.identifier, 200),
          linked: linked,
          discovery: disc ? { ok: disc.ok, patch: disc.patch,
                              filter: disc.filter, maxResults: disc.maxResults,
                              etag: disc.etag, bulk: disc.bulk,
                              endpoints: disc.endpoints,
                              authenticationSchemes:
                                disc.authenticationSchemes,
                              at: new Date(disc.at).toISOString(),
                              why: disc.why } : null });
      } else {
        out.client = null;
        out.missing = wanted;
      }
    }
    log.debug("Leaving ScimClients.view(). " + rows.length + " client(s).");
    return out;
  }

  // A coded refusal.
  private refusal(code: string, errors: string[]): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ScimClients.refusal(). " + code);
    log.debug("Leaving ScimClients.refusal().");
    return errorCodes.mark({ ok: false, errors: errors }, code);
  }

  // A definition from an act's body over the row it changes.
  private definitionFrom(given: Json, before: Json | null): Json {
    const { log } = this.deps;
    log.debug("Entering ScimClients.definitionFrom().");
    const out: Json = {};
    MEMBERS.forEach(function (pair) {
      out[pair[0]] = given[pair[0]] !== undefined
        ? String(given[pair[0]] == null ? '' : given[pair[0]]).trim()
        : (before ? String(before[pair[0]] || '') : '');
    });
    LIST_MEMBERS.forEach(function (pair) {
      const value = given[pair[0]];
      out[pair[0]] = value !== undefined
        ? (Array.isArray(value) ? value : String(value).split(/[\n,]/))
          .map(function (one: Json) {
            return String(one).trim();
          }).filter(function (one: string) {
            return !!one;
          })
        : (before ? before[pair[0]].slice() : []);
    });
    out.enabled = given.enabled !== undefined
      ? /^(true|on|1|yes)$/i.test(String(given.enabled))
      : (before ? before.enabled : false);
    out.authMethod = out.authMethod || 'basic';
    out.oauthClientAuth = out.oauthClientAuth || 'client_secret_basic';
    out.tlsSource = out.tlsSource || 'none';
    out.scopeMode = out.scopeMode || 'all';
    out.groupMode = out.groupMode || 'none';
    out.deprovision = out.deprovision || 'deactivate';
    out.reconcileMinutes = out.reconcileMinutes || '0';
    out.jurisdiction = String(out.jurisdiction || '').toLowerCase();
    out.passwordSet = !!given.password || !!(before && before.passwordSet);
    out.oauthClientSecretSet = !!given.oauthClientSecret ||
      !!(before && before.oauthClientSecretSet);
    out.tlsPrivateKeySet = !!given.tlsPrivateKey ||
      !!(before && before.tlsPrivateKeySet);
    log.debug("Leaving ScimClients.definitionFrom().");
    return out;
  }

  // What a definition may not be at the write: the use problems, less the
  // ones a client only has until its certificate is issued.
  private writeProblems(d: Json, given: Json): string[] {
    const { log } = this.deps;
    log.debug("Entering ScimClients.writeProblems().");
    const out = this.problemsOf(d).filter(function (one) {
      return one !== 'No client certificate has been issued yet.';
    });
    if (given.tlsCertificate) {
      try {
        stsCrypto.parseCertificate(String(given.tlsCertificate));
      } catch (e) {
        log.debug("Caught in ScimClients.writeProblems(): " +
                  ((e && e.message) || e));
        out.push('The client certificate is not a PEM certificate.');
      }
    }
    if (given.tlsPrivateKey) {
      try {
        stsCrypto.privateKeyFrom(String(given.tlsPrivateKey));
      } catch (e) {
        log.debug("Caught in ScimClients.writeProblems(): " +
                  ((e && e.message) || e));
        out.push('The private key is not a PEM private key.');
      }
    }
    if (d.caCertificates) {
      const found = String(d.caCertificates).match(
        /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
      if (!found.length) {
        out.push('The CA certificates hold no PEM certificate.');
      }
      found.forEach(function (pem) {
        try {
          stsCrypto.parseCertificate(pem);
        } catch (e) {
          out.push('A CA certificate does not parse: ' +
                   ((e && e.message) || e));
        }
      });
    }
    log.debug("Leaving ScimClients.writeProblems(). " + out.length);
    return out;
  }

  // Writes a definition onto the entry: each changed member, the two lists,
  // the switch, and each credential given. Answers the registry's refusals.
  private writeDefinition(identifier: string, d: Json, before: Json | null,
                          given: Json, actor: string): string[] {
    const { log, applications } = this.deps;
    log.debug("Entering ScimClients.writeDefinition(). " + identifier);
    const apps = applications();
    const errors: string[] = [];
    const set = function (attribute: string, value: string): void {
      if (errors.length) {
        return;
      }
      const result = apps.updateApplication(identifier, {
        attribute: attribute, mode: 'set', value: value, actor: actor });
      if (!result.ok) {
        errors.push.apply(errors, result.errors || ['refused']);
      }
    };
    MEMBERS.forEach(function (pair) {
      const was = before ? String(before[pair[0]] || '') : '';
      if (d[pair[0]] !== was) {
        set(pair[1], d[pair[0]]);
      }
    });
    LIST_MEMBERS.forEach(function (pair) {
      const was: string[] = before ? before[pair[0]] : [];
      const now: string[] = d[pair[0]];
      was.filter(function (one) {
        return now.indexOf(one) < 0;
      }).forEach(function (one) {
        if (!errors.length) {
          const r = apps.updateApplication(identifier, {
            attribute: pair[1], mode: 'remove', value: one, actor: actor });
          if (!r.ok) {
            errors.push.apply(errors, r.errors || ['refused']);
          }
        }
      });
      now.filter(function (one) {
        return was.indexOf(one) < 0;
      }).forEach(function (one) {
        if (!errors.length) {
          const r = apps.updateApplication(identifier, {
            attribute: pair[1], mode: 'add', value: one, actor: actor });
          if (!r.ok) {
            errors.push.apply(errors, r.errors || ['refused']);
          }
        }
      });
    });
    if (!before || before.enabled !== d.enabled) {
      set('scimClientEnabled', d.enabled ? 'TRUE' : 'FALSE');
    }
    CREDENTIALS.forEach(function (pair) {
      if (given[pair[0]]) {
        set(pair[1], String(given[pair[0]]));
      }
    });
    log.debug("Leaving ScimClients.writeDefinition(). " + errors.length);
    return errors;
  }

  // One audit row for a change to a client's definition: names, never a
  // credential.
  private changed(identifier: string, what: string, actor: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering ScimClients.changed(). " + what);
    audit.audit({ action: 'scim-client.change', category: 'admin',
                  protocol: 'SCIM 2.0', channel: 'internal', actor: actor,
                  target: identifier,
                  summary: 'SCIM client ' + identifier + ' ' + what });
    log.debug("Leaving ScimClients.changed().");
  }

  /**
   * Performs one act, for the console and the API: add-client,
   * update-client, remove-client, issue-certificate, test-connection,
   * reconcile, retry-delivery, retry-dead, purge-dead and deliver-now.
   *
   * @param body - `action` and its members
   * @param context - `actor` and `via`
   * @returns a promise of `{ ok, message, ... }` or a coded refusal
   */
  async act(body: Json, context?: Json): Promise<Json> {
    const { log, applications, errorCodes, realms, audit } = this.deps;
    const given = body || {};
    const ctx = context || {};
    const actor = String(ctx.actor || '');
    const action = String(given.action || '');
    log.debug("Entering ScimClients.act(). " + action);
    if (ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving ScimClients.act(). Unknown action.");
      return this.refusal('STS-SCIMC-0016', ['Unknown action "' + action +
        '". The acts are: ' + ACTIONS.join(', ') + '.']);
    }
    if (action === 'add-client') {
      const identifier = String(given.identifier || '').trim();
      if (!identifier) {
        log.debug("Leaving ScimClients.act(). No identifier.");
        return this.refusal('STS-SCIMC-0017', ['A client needs an ' +
                                               'identifier.']);
      }
      const d = this.definitionFrom(given, null);
      const problems = this.writeProblems(d, given);
      if (problems.length) {
        log.debug("Leaving ScimClients.act(). Refused.");
        return this.refusal('STS-SCIMC-0017', problems);
      }
      const created = applications().createApplication({
        identifier: identifier,
        name: String(given.name || '').trim() || identifier,
        protocols: [FAMILY], fields: {}, actor: actor });
      if (!created.ok) {
        log.debug("Leaving ScimClients.act(). Not created.");
        return this.refusal(errorCodes.codeOf(created) || 'STS-SCIMC-0017',
                            created.errors || []);
      }
      const errors = this.writeDefinition(identifier, d, null, given, actor);
      if (errors.length) {
        applications().deleteApplication(identifier, { actor: actor });
        log.debug("Leaving ScimClients.act(). A write was refused.");
        return this.refusal('STS-SCIMC-0017', errors);
      }
      this.changed(identifier, 'was added', actor);
      const row = this.get(identifier);
      log.debug("Leaving ScimClients.act(). Added.");
      return { ok: true, client: row,
               message: 'SCIM client ' + identifier + ' is added' +
                        (row && !row.usable ? ', and is not usable yet: ' +
                                              row.problems.join(' ') : '.') };
    }
    if (action === 'retry-delivery') {
      const id = String(given.id || '');
      const result = this.delivery.retry(id, actor, 'SCIM');
      if (result.ok) {
        audit.audit({ action: 'scim-client.queue', category: 'admin',
                      protocol: 'SCIM 2.0', channel: 'internal', actor: actor,
                      target: id, summary: 'A SCIM dead letter was retried: ' +
                                           id });
        this.deliverSoon();
      }
      log.debug("Leaving ScimClients.act(). Retried: " + result.ok);
      return result.ok ? { ok: true, message: 'The dead letter is queued ' +
                                              'again.' }
                       : this.refusal(errorCodes.codeOf(result) ||
                                      'STS-SCIMC-0015', [result.message]);
    }
    const id = String(given.id || given.client || '').trim();
    const before = id ? this.get(id) : null;
    if (!before) {
      log.debug("Leaving ScimClients.act(). No such client.");
      return this.refusal('STS-SCIMC-0016', ['There is no SCIM client "' +
                                             id + '" in this realm.']);
    }
    if (action === 'update-client') {
      const d = this.definitionFrom(given, before);
      const problems = this.writeProblems(d, given);
      if (problems.length) {
        log.debug("Leaving ScimClients.act(). Refused.");
        return this.refusal('STS-SCIMC-0017', problems);
      }
      const errors = this.writeDefinition(before.identifier, d, before, given,
                                          actor);
      if (errors.length) {
        log.debug("Leaving ScimClients.act(). A write was refused.");
        return this.refusal('STS-SCIMC-0017', errors);
      }
      if (given.name !== undefined && String(given.name).trim() &&
          String(given.name).trim() !== before.name) {
        applications().updateApplication(before.identifier, {
          attribute: 'appName', mode: 'set', value: String(given.name).trim(),
          actor: actor });
      }
      this.forget(before);
      this.changed(before.identifier, 'was changed', actor);
      const row = this.get(before.identifier);
      log.debug("Leaving ScimClients.act(). Changed.");
      return { ok: true, client: row,
               message: 'SCIM client ' + before.name + ' is changed' +
                        (row && !row.usable ? '. It is not usable: ' +
                                              row.problems.join(' ') : '.') };
    }
    if (action === 'remove-client') {
      const gone = applications().deleteApplication(before.identifier,
                                                    { actor: actor });
      if (!gone.ok) {
        log.debug("Leaving ScimClients.act(). Not removed.");
        return this.refusal(errorCodes.codeOf(gone) || 'STS-SCIMC-0017',
                            gone.errors || []);
      }
      this.purgeClient(before.identifier);
      this.forget(before);
      this.changed(before.identifier, 'was removed', actor);
      log.debug("Leaving ScimClients.act(). Removed.");
      return { ok: true, message: 'SCIM client ' + before.name + ' is ' +
               'removed, with its credentials, queues and links. Nothing at ' +
               'the service provider changed.' };
    }
    if (action === 'issue-certificate') {
      const issued = await this.deps.tlsClientCertificates().issue(
        realms.currentId(), { kind: 'application',
                              application: before.identifier,
                              label: 'SCIM client ' + before.identifier });
      if (!issued.ok) {
        log.debug("Leaving ScimClients.act(). Not issued.");
        return this.refusal('STS-SCIMC-0024', issued.errors ||
                            ['The certificate could not be issued.']);
      }
      const pem = [issued.issued.certificatePem]
        .concat(issued.issued.chainPem || []).join('\n');
      const errors = this.writeDefinition(before.identifier,
        Object.assign(this.definitionFrom({}, before),
                      { tlsSource: 'issued', tlsCertificate: pem }),
        before, { tlsPrivateKey: issued.issued.privateKeyPem }, actor);
      if (errors.length) {
        log.debug("Leaving ScimClients.act(). Not written.");
        return this.refusal('STS-SCIMC-0024', errors);
      }
      this.forget(before);
      this.changed(before.identifier, 'was issued a TLS client certificate ' +
                   '(serial ' + issued.issued.serialHex + ')', actor);
      log.debug("Leaving ScimClients.act(). Issued.");
      return { ok: true, certificate: { subject: issued.issued.subject,
                                        serial: issued.issued.serialHex,
                                        notAfter: issued.issued.notAfter,
                                        rootPem: issued.issued.rootPem },
               message: 'A TLS client certificate was issued to ' +
                        before.identifier + ' by this realm\'s CA. The ' +
                        'service provider must trust the service Root.' };
    }
    if (action === 'test-connection') {
      const disc = await this.discovery(before, true);
      const probe = await this.request(before, 'GET',
        disc.endpoints.User + '?startIndex=1&count=1&attributes=id', null);
      log.debug("Leaving ScimClients.act(). Tested.");
      if (!probe.ok) {
        return this.refusal(this.codeFor(probe), ['The service provider ' +
          'refused or did not answer: ' + probe.why]);
      }
      return { ok: true, discovery: { ok: disc.ok, patch: disc.patch,
                                      filter: disc.filter, etag: disc.etag,
                                      endpoints: disc.endpoints,
                                      why: disc.why },
               totalResults: probe.json ? probe.json.totalResults : null,
               message: 'The service provider answered: ' +
                        (disc.ok ? 'PATCH ' + (disc.patch ? 'yes' : 'no') +
                                   ', filter ' + (disc.filter ? 'yes' : 'no') +
                                   ', ETags ' + (disc.etag ? 'yes' : 'no')
                                 : disc.why) + '.' };
    }
    if (action === 'reconcile') {
      if (!before.usable) {
        log.debug("Leaving ScimClients.act(). Not usable.");
        return this.refusal('STS-SCIMC-0017', before.problems);
      }
      if (!before.enabled) {
        // Every row it queued would be dead-lettered at the send
        // (STS-SCIMC-0001): a disabled client sends nothing.
        log.debug("Leaving ScimClients.act(). Disabled.");
        return this.refusal('STS-SCIMC-0017', ['SCIM client ' +
          before.identifier + ' is disabled; enable it to reconcile.']);
      }
      const result = await this.reconcile(before, actor || 'administrator');
      log.debug("Leaving ScimClients.act(). Reconciled.");
      return Object.assign({ message: 'Reconciled: ' + result.users +
        ' user(s) and ' + result.groups + ' group(s) queued, ' +
        result.deprovisioned + ' to deprovision' +
        (result.ok ? '.' : '; ' + result.why) }, result);
    }
    if (action === 'retry-dead' || action === 'purge-dead') {
      const store = this.deliveries.realmMap(realms.currentId());
      const dead: Json[] = [];
      store.forEach(function (row: Json) {
        if (row && row.clientId === before.identifier && row.state === 'dead') {
          dead.push(row);
        }
      });
      dead.forEach((row) => {
        if (action === 'retry-dead') {
          this.delivery.retry(row.id, actor, 'SCIM');
        } else {
          store.delete(row.id);
        }
      });
      audit.audit({ action: 'scim-client.queue', category: 'admin',
                    protocol: 'SCIM 2.0', channel: 'internal', actor: actor,
                    target: before.identifier,
                    summary: dead.length + ' dead letter(s) of SCIM client ' +
                             before.identifier + ' were ' +
                             (action === 'retry-dead' ? 'retried' : 'purged') });
      if (action === 'retry-dead') {
        this.deliverSoon();
      }
      log.debug("Leaving ScimClients.act(). " + action);
      return { ok: true, count: dead.length,
               message: dead.length + ' dead letter(s) ' +
                        (action === 'retry-dead' ? 'queued again.'
                                                 : 'purged.') };
    }
    // deliver-now
    this.writeState(realms.currentId(), before.identifier,
                    { failures: 0, pausedUntil: 0, probe: '' });
    this.dueNow(before.identifier, realms.currentId());
    this.deliverSoon();
    log.debug("Leaving ScimClients.act(). Delivering now.");
    return { ok: true, message: 'The pause is lifted and ' + before.name +
             '\'s queue is being sent now.' };
  }

  /**
   * Makes every pending row of a client due now (the deliver-now act).
   *
   * @param clientId - the client
   * @param realmId - the realm
   */
  dueNow(clientId: string, realmId: string): void {
    const { log, now } = this.deps;
    log.debug("Entering ScimClients.dueNow(). " + clientId);
    const at = now();
    this.deliveries.realmMap(realmId).forEach((row: Json) => {
      if (row && row.clientId === clientId && row.state === 'pending' &&
          Number(row.nextAttemptAt) > at) {
        this.delivery.writeRow(Object.assign({}, row, { nextAttemptAt: at,
                                                        retryAfterMs: 0 }));
      }
    });
    log.debug("Leaving ScimClients.dueNow().");
  }

  // A client gone: its rows, links and state.
  private purgeClient(clientId: string): void {
    const { log, realms } = this.deps;
    log.debug("Entering ScimClients.purgeClient(). " + clientId);
    const realmId = realms.currentId();
    const prefix = clientId + '|';
    [this.deliveries, this.links].forEach(function (store: Json) {
      const map = store.realmMap(realmId);
      const keys: string[] = [];
      map.forEach(function (value: Json, key: string) {
        if (key.indexOf(prefix) === 0) {
          keys.push(key);
        }
      });
      keys.forEach(function (key) {
        map.delete(key);
      });
    });
    this.states.realmMap(realmId).delete(clientId);
    log.debug("Leaving ScimClients.purgeClient().");
  }

  // What this process remembers about a client: its discovery and its token.
  private forget(c: Json): void {
    const { log, realms } = this.deps;
    log.debug("Entering ScimClients.forget(). " + c.identifier);
    const prefix = realms.currentId() + '|' + c.identifier;
    Array.from(this.discovered.keys()).forEach((key) => {
      if (key.indexOf(prefix + '|') === 0) {
        this.discovered.delete(key);
      }
    });
    this.tokens.delete(prefix);
    log.debug("Leaving ScimClients.forget().");
  }
}

const slot = new InstanceSlot<ScimClients>(
  'scim/scim_client',
  () => new ScimClients(ScimClients.defaultDeps()),
  ScimClients.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The outbound SCIM client (#552): the register of `scim-client` application
 * entries, their deliveries, queues and reconciliation.
 *
 * @namespace
 */
export = {
  ScimClients: ScimClients,
  FAMILY: FAMILY,
  ACTIONS: ACTIONS,
  /**
   * Installs the instance the composition root built, and wires it.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: ScimClients): void => slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  list: slot.forward('list'),
  get: slot.forward('get'),
  view: slot.forward('view'),
  act: slot.forward('act'),
  reconcile: slot.forward('reconcile'),
  reconcileDue: slot.forward('reconcileDue'),
  sendRow: slot.forward('sendRow'),
  observe: slot.forward('observe'),
  enqueue: slot.forward('enqueue'),
  isClient: slot.forward('isClient'),
  /**
   * The installed instance's delivery queue (its sweep, for a test).
   *
   * @returns the queue
   */
  delivery: (): Json => slot.get().delivery
};
