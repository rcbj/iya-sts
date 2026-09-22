'use strict';
//
// File: spiffe_api.ts
//
// ---------------------------------------------------------------------------
// THE SPIRE SERVER API — the third server-side surface, and the largest: six
// gRPC services and forty-two methods, over the same two transports the
// Workload API uses.
//
//   Entry        registration entries: list, get, batch create/update/delete,
//                and the two an agent uses to learn what it may issue
//   Agent        attesting, renewing, listing, banning, join tokens
//   Bundle       this trust domain's bundle, and every federated one
//   SVID         minting on demand, and signing an agent's CSRs
//   TrustDomain  federation relationships
//   Debug        one method, and it is the cheapest health check there is
//
// A LIBRARY: it registers no HTTP route and starts no listener —
// `spiffe_server.ts` mounts these handlers — and everything it requires
// (`helpers.js`, `config.js`, `audit.js`, `admin_stats.js`, `spiffe_id.ts`,
// `spiffe_ca.ts`, `spiffe_registry.ts`, `spiffe_grpc.ts`) is below it.
//
// ---------------------------------------------------------------------------
// THIS IS THE ONE SURFACE IN THE SPIFFE FAMILY THAT AUTHENTICATES ITS CALLER
//
// A real SPIRE server authorizes this API against the caller's own SVID: an
// agent may call `GetAuthorizedEntries` and `BatchNewX509SVID` and nothing
// else, an entry marked `admin` may create entries, a `downstream` entry may
// ask for an intermediate CA, and everybody else is refused. **This service now
// does the same**, and none of it is decided in this file: `spiffe_auth.ts`
// builds the caller from the mutual-TLS X509-SVID and authorizes each method
// against SPIRE's own `policy_data.json`, and `spiffe_grpc.ts`'s wrappers apply
// it before any handler here runs. So there is no authorization check in any of
// the forty-two handlers below, and there must not be one — a check beside the
// funnel is how a method comes to be guarded twice and differently.
//
// Three things follow that are easy to miss:
//
//   * **The `admin` and `downstream` flags on an entry are now READ.** They
//     used to be recorded, reported, and consulted by nothing — this file's
//     header said so. `spiffe_auth.classify()` reads them on every call, so
//     marking an entry `admin` on /admin/spiffe/entries, or with an
//     `ldapmodify`, changes what that identity may do on the NEXT call.
//
//   * **The Unix socket is the `local` entity and needs no credential**, which
//     is how the `spire-server` CLI reaches a real server. Two methods are open
//     to everybody — `AttestAgent`, because an agent has no SVID until that
//     call gives it one, and `GetBundle`, because a trust bundle is public —
//     and both are open in a real SPIRE server too.
//
//   * **THE OLD POSTURE IS NO LONGER REACHABLE.** `spiffe.authRequired` off
//     used to restore it completely — the TCP port bound plain, nothing was
//     verified, and anybody who could reach it could create a registration
//     entry granting any identity in this trust domain and then collect an
//     SVID for it. That setting was removed on 2026-09-06 when `global.mode`
//     took the question over, so the `!authRequired()` arms below are dead
//     code kept against a third mode wanting them.
//
// **WHAT IS STILL NOT ATTESTED IS A WORKLOAD API CALLER OVER TCP.** NODE
// attestation left this sentence on 2026-09-21 (#40): `AttestAgent` below
// verifies every type it accepts through `spiffe_node_attestation.ts`'s table
// and refuses the rest; the Workload API's Unix socket followed the same day
// (`spiffe_workload_attestation.ts`).
//
// ---------------------------------------------------------------------------
// THE BATCH METHODS ANSWER PER ITEM AND DO NOT FAIL AS A WHOLE
//
// `BatchCreateEntry` takes a list and returns a list of `Result`, each with its
// own `Status`. A batch where one entry is bad returns OK at the RPC level with
// one failed result in it — it does not fail the call. Getting that wrong is
// how a client that submits fifty entries loses forty-nine because the
// thirteenth had a typo, and it is the reason `statusFor()` below exists rather
// than each handler throwing.
//
// The status codes are `google.rpc.Code` values, which happen to be the same
// numbers as the gRPC status codes — 0 OK, 3 INVALID_ARGUMENT, 5 NOT_FOUND, 6
// ALREADY_EXISTS, 8 RESOURCE_EXHAUSTED. `spiffe_grpc.ts` re-exports grpc-js's
// table rather than a second copy here.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SpiffeApi` takes the modules it uses through its constructor
// (`SpiffeApiDeps`), and since #50's R2 the composition root builds the
// instance and installs it here. The module still exports its old names as
// FACADES forwarding to it, for the callers that are not converted; a process
// without the root builds a default when this module loads. `SpiffeApi` is
// exported for the root.
//
// **THE TABLES WHOSE ENTRIES CALL THIS MODULE** (`entryHandlers`,
// `agentHandlers`, `bundleHandlers`, `svidHandlers`, `trustDomainHandlers`,
// `debugHandlers`) are built by
// `build…()` methods, called at load where each was declared.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log, nowSec } = helpers;
import config = require('../common/config');
import audit = require('../common/audit');
// THE ERROR CODES. A LEAF. A handler that throws a status marks the CALL with
// the condition on the line before, and `spiffe_grpc.ts`'s wrapper records it
// on the call's one audit row; a per-item refusal inside a batch, which fails
// no call, is recorded by `refusedItem()` below.
import errorCodes = require('../common/error_codes');
import stats = require('../common/admin_stats');
import spiffeId = require('./spiffe_id');
// PER REALM SINCE 2026-09-12 (it was per process) — see the store below.
// Required only for `realms.map()`, and it is a LEAF that registers no route,
// so this cannot move a route or join a cycle.
import realms = require('../common/realms');
import ca = require('./spiffe_ca');
import registry = require('./spiffe_registry');
import rpc = require('./spiffe_grpc');
// For the caller on a call — see the header. This module never authorizes;
// it reads WHO, where a method's answer depends on it.
import auth = require('./spiffe_auth');
// The atomic "once" a join token is spent through across nodes — see
// AttestAgent. A LIBRARY that reaches `persistence.js` lazily.
import claims = require('../cluster/cluster_claims');
// The node attestors (#40): the table, and the one attestor whose store is
// this module's. LIBRARIES; neither registers a route.
import attestation = require('./spiffe_node_attestation');
import joinTokenAttestor = require('./spiffe_attestor_join_token');
// The attestors whose stores are nobody's (#40 phase two): each is
// configured by settings alone and registered as it is built.
import x509popAttestor = require('./spiffe_attestor_x509pop');
import sshpopAttestor = require('./spiffe_attestor_sshpop');
import tpmDevidAttestor = require('./spiffe_attestor_tpm_devid');
// Phase three: the Kubernetes, HTTP and cloud attestors.
import k8sPsatAttestor = require('./spiffe_attestor_k8s_psat');
import httpChallengeAttestor = require('./spiffe_attestor_http_challenge');
import awsIidAttestor = require('./spiffe_attestor_aws_iid');
import gcpIitAttestor = require('./spiffe_attestor_gcp_iit');
import azureImdsAttestor = require('./spiffe_attestor_azure_imds');

const status = rpc.grpc.status;

// What `SpiffeApi` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface SpiffeApiDeps {
  crypto: typeof crypto;
  log: typeof log;
  nowSec: typeof nowSec;
  config: typeof config;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  stats: typeof stats;
  spiffeId: typeof spiffeId;
  ca: typeof ca;
  registry: typeof registry;
  rpc: typeof rpc;
  auth: typeof auth;
  claims: typeof claims;
  attestation: typeof attestation;
  joinTokenAttestor: typeof joinTokenAttestor;
  // Each attestor other than join_token, built with its own defaults.
  attestors: Array<{ build(): any }>;
  status: typeof status;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadPkijs(): typeof import('pkijs');
  loadAsn1js(): typeof import('asn1js');
}

class SpiffeApi {
  // Built by `nodeAttestation()` on first use.
  private attestationTable: any = null;
  private joinTokenAttestorInstance: any = null;

  constructor(private readonly deps: SpiffeApiDeps) {
    deps.log.debug("Entering SpiffeApi.constructor().");
    deps.log.debug("Leaving SpiffeApi.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): SpiffeApiDeps {
    helpers.log.debug("Entering SpiffeApi.defaultDeps().");
    helpers.log.debug("Leaving SpiffeApi.defaultDeps().");
    return {
      crypto: crypto,
      log: log,
      nowSec: nowSec,
      config: config,
      audit: audit,
      errorCodes: errorCodes,
      stats: stats,
      spiffeId: spiffeId,
      ca: ca,
      registry: registry,
      rpc: rpc,
      auth: auth,
      claims: claims,
      attestation: attestation,
      joinTokenAttestor: joinTokenAttestor,
      attestors: [
        { build: function () {
          return new x509popAttestor.X509popAttestor(
            x509popAttestor.X509popAttestor.defaultDeps());
        } },
        { build: function () {
          return new sshpopAttestor.SshpopAttestor(
            sshpopAttestor.SshpopAttestor.defaultDeps());
        } },
        { build: function () {
          return new tpmDevidAttestor.TpmDevidAttestor(
            tpmDevidAttestor.TpmDevidAttestor.defaultDeps());
        } },
        { build: function () {
          return new k8sPsatAttestor.K8sPsatAttestor(
            k8sPsatAttestor.K8sPsatAttestor.defaultDeps());
        } },
        { build: function () {
          return new httpChallengeAttestor.HttpChallengeAttestor(
            httpChallengeAttestor.HttpChallengeAttestor.defaultDeps());
        } },
        { build: function () {
          return new awsIidAttestor.AwsIidAttestor(
            awsIidAttestor.AwsIidAttestor.defaultDeps());
        } },
        { build: function () {
          return new gcpIitAttestor.GcpIitAttestor(
            gcpIitAttestor.GcpIitAttestor.defaultDeps());
        } },
        { build: function () {
          return new azureImdsAttestor.AzureImdsAttestor(
            azureImdsAttestor.AzureImdsAttestor.defaultDeps());
        } }
      ],
      status: status,
      loadPkijs: function () {
        return require('pkijs');
      },
      loadAsn1js: function () {
        return require('asn1js');
      }
    };
  }

  trustDomain() {
    const { log, ca } = this.deps;
    log.debug("Entering SpiffeApi.trustDomain().");
    log.debug("Leaving SpiffeApi.trustDomain().");
    return ca.trustDomain();
  }

  // ---------------------------------------------------------------------------
  // CONVERSIONS.
  //
  // A registration entry as this service holds it, and as
  // `spire.api.types.Entry` describes it. Written once each way so that eight
  // handlers cannot disagree about, for instance, whether `expires_at` is
  // seconds or milliseconds — it is seconds, and a millisecond value there is
  // an entry that expires in the year 56000 and is reported by every tool as
  // valid.
  // ---------------------------------------------------------------------------
  entryToProto(entry, mask) {
    const { log, spiffeId } = this.deps;
    log.debug('Entering SpiffeApi.entryToProto().');
    if (!entry) {
      log.debug('Leaving SpiffeApi.entryToProto().');
      return null;
    }
    const full = {
      id: entry.id,
      spiffe_id: spiffeId.toProto(entry.spiffeId),
      parent_id: spiffeId.toProto(entry.parentId),
      selectors: (entry.selectors || []).map(function (s) {
        return { type: s.type, value: s.value };
      }),
      x509_svid_ttl: entry.x509SvidTtl || 0,
      jwt_svid_ttl: entry.jwtSvidTtl || 0,
      federates_with: (entry.federatesWith || []).slice(0),
      admin: !!entry.admin,
      downstream: !!entry.downstream,
      expires_at: String(entry.expiresAt || 0),
      dns_names: (entry.dnsNames || []).slice(0),
      revision_number: String(entry.revisionNumber || 0),
      store_svid: !!entry.storeSvid,
      hint: entry.hint || '',
      created_at: String(this.secondsFromGeneralizedTime(entry.createdAt))
    };
    log.debug('Leaving SpiffeApi.entryToProto().');
    return this.applyEntryMask(full, mask);
  }

  // An `EntryMask` names which fields the caller wants back. It is honoured
  // rather than ignored, and the reason is not politeness: a client that asked
  // for `id` alone and got a full entry cannot tell whether the server honoured
  // the mask, so the first time it meets a server that DOES honour one, the
  // fields it had been reading silently become empty.
  //
  // `id` is never masked out — it is the handle to everything else, and an
  // entry without one is a result a caller cannot act on.
  applyEntryMask(full, mask) {
    const { log } = this.deps;
    log.debug("Entering SpiffeApi.applyEntryMask().");
    if (!mask || !Object.keys(mask).length) {
      log.debug("Leaving SpiffeApi.applyEntryMask().");
      return full;
    }
    const anySet = Object.keys(mask).some(function (key) { return mask[key]; });
    if (!anySet) {
      log.debug("Leaving SpiffeApi.applyEntryMask().");
      return full;
    }
    const out = { id: full.id };
    Object.keys(mask).forEach(function (key) {
      if (mask[key] && Object.prototype.hasOwnProperty.call(full, key)) {
        out[key] = full[key];
      }
    });
    log.debug("Leaving SpiffeApi.applyEntryMask().");
    return out;
  }

  // The reverse. `parentId` defaults to this server's own SPIFFE ID, which is
  // what SPIRE does for an entry describing a workload rather than a node, and
  // is what makes `spire-server entry create -spiffeID x -selector y` work with
  // no parent given.
  entryFromProto(message) {
    const { log, spiffeId } = this.deps;
    log.debug('Entering SpiffeApi.entryFromProto().');
    const proto = message || {};
    log.debug('Leaving SpiffeApi.entryFromProto().');
    return {
      id: String(proto.id || '').trim(),
      spiffeId: spiffeId.fromProto(proto.spiffe_id),
      parentId: spiffeId.fromProto(proto.parent_id) ||
                spiffeId.serverId(this.trustDomain()),
      selectors: (proto.selectors || []).map(function (s) {
        return { type: String(s.type || ''), value: String(s.value || '') };
      }),
      x509SvidTtl: Number(proto.x509_svid_ttl || 0),
      jwtSvidTtl: Number(proto.jwt_svid_ttl || 0),
      federatesWith: (proto.federates_with || []).map(String),
      admin: !!proto.admin,
      downstream: !!proto.downstream,
      expiresAt: Number(proto.expires_at || 0),
      dnsNames: (proto.dns_names || []).map(String),
      storeSvid: !!proto.store_svid,
      hint: String(proto.hint || '')
    };
  }

  agentToProto(agent, mask) {
    const { log, spiffeId } = this.deps;
    log.debug('Entering SpiffeApi.agentToProto().');
    if (!agent) {
      log.debug('Leaving SpiffeApi.agentToProto().');
      return null;
    }
    const full = {
      id: spiffeId.toProto(agent.id),
      attestation_type: agent.attestationType || '',
      x509svid_serial_number: agent.svidHash || '',
      x509svid_expires_at: String(agent.expiresAt || 0),
      selectors: (agent.selectors || []).map(function (s) {
        return { type: s.type, value: s.value };
      }),
      banned: !!agent.banned,
      can_reattest: !!agent.canReattest,
      agent_version: ''
    };
    if (!mask || !Object.keys(mask).length) {
      log.debug('Leaving SpiffeApi.agentToProto().');
      return full;
    }
    const anySet = Object.keys(mask).some(function (key) { return mask[key]; });
    if (!anySet) {
      log.debug('Leaving SpiffeApi.agentToProto().');
      return full;
    }
    const out = { id: full.id };
    Object.keys(mask).forEach(function (key) {
      if (mask[key] && Object.prototype.hasOwnProperty.call(full, key)) {
        out[key] = full[key];
      }
    });
    log.debug('Leaving SpiffeApi.agentToProto().');
    return out;
  }

  // A GeneralizedTime — which is what the directory stores — as seconds since
  // the epoch, which is what the protobuf carries. Returns 0 rather than NaN on
  // anything unparseable: a `created_at` of NaN serialises as an error naming
  // the field, and 0 at least reads as "unknown".
  secondsFromGeneralizedTime(text) {
    const { log } = this.deps;
    log.debug("Entering SpiffeApi.secondsFromGeneralizedTime().");
    const value = String(text || '');
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value);
    if (!m) {
      const parsed = Date.parse(value);
      log.debug("Leaving SpiffeApi.secondsFromGeneralizedTime().");
      return Number.isFinite(parsed) ? Math.floor(parsed / 1000) : 0;
    }
    log.debug("Leaving SpiffeApi.secondsFromGeneralizedTime().");
    return Math.floor(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) /
                      1000);
  }

  statusFor(code, message) {
    const { log, status } = this.deps;
    log.debug("Entering SpiffeApi.statusFor().");
    log.debug("Leaving SpiffeApi.statusFor().");
    return { code: code, message: message || (code === status.OK ? 'OK' : '') };
  }

  okStatus() {
    const { log, status } = this.deps;
    log.debug("Entering SpiffeApi.okStatus().");
    log.debug("Leaving SpiffeApi.okStatus().");
    return this.statusFor(status.OK, 'OK');
  }

  // ONE ITEM OF A BATCH, REFUSED. The call itself answers OK — see the header —
  // so the wrapper records a success, and without this row the refusal inside
  // it would be recorded nowhere. One row per refused item, carrying the
  // condition; the status handed back is exactly what `statusFor()` builds.
  // `target` is the item (an entry id, a trust domain), which is a name and
  // never a credential.
  refusedItem(code, grpcCode, message, target) {
    const { log, audit } = this.deps;
    log.debug("Entering SpiffeApi.refusedItem().");
    audit.failure(code, {
      protocol: 'SPIRE Server API', channel: 'grpc', target: target || '',
      // No `outcome`: a row carrying a code is a refusal by default.
      summary: 'One item of a SPIRE Server API batch call was refused: ' +
               (message || '')
    });
    log.debug("Leaving SpiffeApi.refusedItem().");
    // error-code: none — the helper's own internals, handed the status as a
    // variable
    return this.statusFor(grpcCode, message);
  }

  // ---------------------------------------------------------------------------
  // PAGING.
  //
  // Every `List*` method takes `page_size` and `page_token` and returns
  // `next_page_token`. It is implemented rather than ignored for the reason the
  // mask is: a client that pages will loop forever against a server that
  // returns everything and an empty token — no, worse, it will loop forever
  // against one that returns everything and a NON-empty token, which is the
  // shape somebody reaches for when they add paging by copying the field names.
  //
  // The token is the INDEX of the next row, as a string. Opaque to a caller,
  // which is what the specification requires, and stable enough for a store
  // this size — the alternative, a cursor keyed on the last id, matters when
  // rows are being inserted underneath a paging client, and a mock's registry
  // is not.
  // ---------------------------------------------------------------------------
  //
  // **THE CAP IS `spiffe.maxPageSize` SINCE 2026-09-12** (1000, the old
  // literal, is its default). It bounds what one call may ask for; a request
  // with no page_size still gets every row, which is what it always got and
  // what a client that does not page expects.
  page(rows, pageSize, pageToken) {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeApi.page().");
    const cap = config.value('spiffe.maxPageSize');
    const size = Number(pageSize) > 0 ? Math.min(Number(pageSize), cap) :
                 rows.length;
    const start = Math.max(0, parseInt(String(pageToken || '0'), 10) || 0);
    const slice = rows.slice(start, start + size);
    const next = (start + size) < rows.length ? String(start + size) : '';
    log.debug("Leaving SpiffeApi.page().");
    return { rows: slice, nextPageToken: next };
  }

  // ---------------------------------------------------------------------------
  // FILTERS.
  //
  // `ListEntries` and `ListAgents` both take one, and both are honoured. The
  // selector match behaviours are the interesting part and there are four of
  // them, each meaning something different:
  //
  //   MATCH_EXACT     the two sets are equal
  //   MATCH_SUBSET    the entry's selectors are a subset of those given
  //   MATCH_SUPERSET  the entry's selectors are a superset of those given
  //   MATCH_ANY       at least one in common
  //
  // Implementing only MATCH_EXACT and treating the rest as it is the mistake
  // that makes `spire-server entry show -selector unix:uid:1000` return nothing
  // on a deployment where it should return everything.
  // ---------------------------------------------------------------------------
  selectorSet(list) {
    const { log, registry } = this.deps;
    log.debug("Entering SpiffeApi.selectorSet().");
    const set = {};
    (list || []).forEach(function (s) {
      const text = registry.selectorText(s);
      if (text) set[text] = true;
    });
    log.debug("Leaving SpiffeApi.selectorSet().");
    return set;
  }

  selectorMatches(entrySelectors, match) {
    const { log } = this.deps;
    log.debug('Entering SpiffeApi.selectorMatches().');
    if (!match) {
      log.debug('Leaving SpiffeApi.selectorMatches().');
      return true;
    }
    const wanted = this.selectorSet(match.selectors);
    const have = this.selectorSet(entrySelectors);
    const wantedKeys = Object.keys(wanted);
    const haveKeys = Object.keys(have);
    if (!wantedKeys.length) {
      log.debug('Leaving SpiffeApi.selectorMatches().');
      return true;
    }
    const behavior = String(match.match || 'MATCH_EXACT');
    if (behavior === 'MATCH_EXACT') {
      log.debug('Leaving SpiffeApi.selectorMatches().');
      return wantedKeys.length === haveKeys.length &&
             wantedKeys.every(function (k) { return have[k]; });
    }
    if (behavior === 'MATCH_SUBSET') {
      log.debug('Leaving SpiffeApi.selectorMatches().');
      return haveKeys.every(function (k) { return wanted[k]; });
    }
    if (behavior === 'MATCH_SUPERSET') {
      log.debug('Leaving SpiffeApi.selectorMatches().');
      return wantedKeys.every(function (k) { return have[k]; });
    }
    if (behavior === 'MATCH_ANY') {
      log.debug('Leaving SpiffeApi.selectorMatches().');
      return wantedKeys.some(function (k) { return have[k]; });
    }
    log.debug('Leaving SpiffeApi.selectorMatches().');
    return true;
  }

  federatesWithMatches(entryFederates, match) {
    const { log } = this.deps;
    log.debug('Entering SpiffeApi.federatesWithMatches().');
    if (!match) {
      log.debug('Leaving SpiffeApi.federatesWithMatches().');
      return true;
    }
    const wanted = (match.trust_domains || []).map(function (t) {
      return String(t).trim().toLowerCase();
    }).filter(Boolean);
    if (!wanted.length) {
      log.debug('Leaving SpiffeApi.federatesWithMatches().');
      return true;
    }
    const have = {};
    (entryFederates ||
     []).forEach(function (t) { have[String(t).toLowerCase()] = true; });
    const haveKeys = Object.keys(have);
    const behavior = String(match.match || 'MATCH_EXACT');
    if (behavior === 'MATCH_EXACT') {
      log.debug('Leaving SpiffeApi.federatesWithMatches().');
      return wanted.length === haveKeys.length &&
             wanted.every(function (t) { return have[t]; });
    }
    if (behavior === 'MATCH_SUBSET') {
      log.debug('Leaving SpiffeApi.federatesWithMatches().');
      return haveKeys.every(function (t) { return wanted.indexOf(t) >= 0; });
    }
    if (behavior === 'MATCH_SUPERSET') {
      log.debug('Leaving SpiffeApi.federatesWithMatches().');
      return wanted.every(function (t) { return have[t]; });
    }
    if (behavior === 'MATCH_ANY') {
      log.debug('Leaving SpiffeApi.federatesWithMatches().');
      return wanted.some(function (t) { return have[t]; });
    }
    log.debug('Leaving SpiffeApi.federatesWithMatches().');
    return true;
  }

  // A `google.protobuf.StringValue` / `BoolValue` wrapper. The whole point of a
  // wrapper type is that "absent" and "empty" are different — `by_hint` unset
  // means "do not filter on hint" and `by_hint: {value: ""}` means "entries
  // whose hint is empty" — so reading `.value` without checking presence turns
  // the first into the second and silently filters everything out.
  wrapped(value) {
    const { log } = this.deps;
    log.debug("Entering SpiffeApi.wrapped().");
    if (value === null || value === undefined) {
      log.debug("Leaving SpiffeApi.wrapped().");
      return undefined;
    }
    if (typeof value === 'object' &&
        Object.prototype.hasOwnProperty.call(value, 'value')) {
      log.debug("Leaving SpiffeApi.wrapped().");
      return value.value;
    }
    log.debug("Leaving SpiffeApi.wrapped().");
    return value;
  }

  filterEntries(rows, filter) {
    const { log, spiffeId } = this.deps;
    const self = this;
    log.debug('Entering SpiffeApi.filterEntries().');
    if (!filter) {
      log.debug('Leaving SpiffeApi.filterEntries().');
      return rows;
    }
    const bySpiffe = spiffeId.fromProto(filter.by_spiffe_id);
    const byParent = spiffeId.fromProto(filter.by_parent_id);
    const byHint = this.wrapped(filter.by_hint);
    const byDownstream = this.wrapped(filter.by_downstream);
    log.debug('Leaving SpiffeApi.filterEntries().');
    return rows.filter(function (entry) {
      if (bySpiffe && entry.spiffeId !== bySpiffe) return false;
      if (byParent && entry.parentId !== byParent) return false;
      if (byHint !== undefined &&
          String(entry.hint || '') !== String(byHint)) return false;
      if (byDownstream !== undefined &&
          !!entry.downstream !== !!byDownstream) return false;
      if (!self.selectorMatches(entry.selectors,
                                filter.by_selectors)) return false;
      if (!self.federatesWithMatches(entry.federatesWith,
                                     filter.by_federates_with)) return false;
      return true;
    });
  }

  filterAgents(rows, filter) {
    const { log } = this.deps;
    const self = this;
    log.debug('Entering SpiffeApi.filterAgents().');
    if (!filter) {
      log.debug('Leaving SpiffeApi.filterAgents().');
      return rows;
    }
    const byType = String(filter.by_attestation_type || '');
    const byBanned = this.wrapped(filter.by_banned);
    const byReattest = this.wrapped(filter.by_can_reattest);
    const before = String(filter.by_expires_before || '');
    const beforeSeconds = before ? Math.floor(Date.parse(before) / 1000) : 0;
    log.debug('Leaving SpiffeApi.filterAgents().');
    return rows.filter(function (agent) {
      if (byType && agent.attestationType !== byType) return false;
      if (byBanned !== undefined && !!agent.banned !== !!byBanned) return false;
      if (byReattest !== undefined &&
          !!agent.canReattest !== !!byReattest) return false;
      if (beforeSeconds &&
          !(agent.expiresAt && agent.expiresAt < beforeSeconds)) return false;
      if (!self.selectorMatches(agent.selectors,
                                filter.by_selector_match)) return false;
      return true;
    });
  }

  // ===========================================================================
  // THE ENTRY SERVICE.
  // ===========================================================================
  // THE WORK LOADING THIS MODULE USED TO DO WITH ITS OWN INSTANCE (#50, R2),
  // run by `common/instance_slot.ts` once for whichever instance is
  // installed: building each service's handlers, in the order loading this
  // module registered them with `spiffe_grpc.ts`, and the table of them.
  static wire(instance: SpiffeApi): void {
    helpers.log.debug("Entering SpiffeApi.wire().");
    const byName = {
      entry: instance.buildEntryHandlers(),
      agent: instance.buildAgentHandlers(),
      bundle: instance.buildBundleHandlers(),
      svid: instance.buildSvidHandlers(),
      trustdomain: instance.buildTrustDomainHandlers(),
      debug: instance.buildDebugHandlers()
    };
    SERVICE_HANDLERS = SERVICE_ROWS.map(function (row) {
      return { name: row.name, label: row.label, handlers: byName[row.name],
               what: row.what };
    });
    helpers.log.debug("Leaving SpiffeApi.wire().");
  }

  buildEntryHandlers() {
    const { log, rpc, registry, errorCodes, status } = this.deps;
    const self = this;
    log.debug("Entering SpiffeApi.buildEntryHandlers().");
    const entryHandlers = {
      CountEntries: rpc.unary('server', 'Entry.CountEntries',
                              async function (call) {
        const rows = self.filterEntries(registry.allEntries(),
                                        (call.request || {}).filter);
        return { count: rows.length };
      }),

      ListEntries: rpc.unary('server', 'Entry.ListEntries',
                             async function (call) {
        const request = call.request || {};
        const rows = self.filterEntries(registry.allEntries(), request.filter);
        const paged = self.page(rows, request.page_size, request.page_token);
        return {
          entries: paged.rows.map(function (entry) {
            return self.entryToProto(entry, request.output_mask);
          }),
          next_page_token: paged.nextPageToken
        };
      }),

      GetEntry: rpc.unary('server', 'Entry.GetEntry', async function (call) {
        const request = call.request || {};
        const entry = registry.entryById(request.id);
        if (!entry) {
          errorCodes.mark(call, 'STS-SPIFFE-0046');
          throw rpc.notFound('No registration entry has the id ' +
                             String(request.id || '(none given)') + '.');
        }
        return self.entryToProto(entry, request.output_mask);
      }),

      BatchCreateEntry: rpc.unary('server', 'Entry.BatchCreateEntry',
                                  async function (call) {
        const request = call.request || {};
        const results = (request.entries || []).map(function (message) {
          const record = self.entryFromProto(message);
          const created = registry.createEntry(record, 'grpc',
                                               self.trustDomain(), '');
          if (!created.ok) {
            // Per item, never the whole call. See the header: a batch of fifty
            // that fails because the thirteenth had a typo is how a client
            // loses forty-nine entries it correctly submitted.
            return { status: self.refusedItem('STS-SPIFFE-0047',
                                              status.INVALID_ARGUMENT,
                                              created.errors.join(' '),
                                              record.id),
                     entry: null };
          }
          return { status: self.okStatus(),
                   entry: self.entryToProto(created.entry,
                                            request.output_mask) };
        });
        return { results: results };
      }),

      BatchUpdateEntry: rpc.unary('server', 'Entry.BatchUpdateEntry',
                                  async function (call) {
        const request = call.request || {};
        const results = (request.entries || []).map(function (message) {
          const id = String(message.id || '').trim();
          if (!id) {
            return { status: self.refusedItem('STS-SPIFFE-0048',
                                              status.INVALID_ARGUMENT,
                                              'An update names the entry by ' +
                                              'its id, and this one has ' +
                                              'none.', ''), entry: null };
          }
          // The INPUT mask says which fields of the submitted entry to apply.
          // It is honoured, and it matters more than the output mask does: a
          // client that sends an entry with only `hint` set and an input mask
          // naming only
          // `hint` expects the selectors to be left alone. Ignoring the mask
          // and applying the whole message wipes every field the client did not
          // fill in, which reads as the server losing data.
          const submitted = self.entryFromProto(message);
          const changes = self.maskedChanges(submitted, request.input_mask);
          const updated = registry.updateEntry(id, changes, self.trustDomain(),
                                               '');
          if (!updated.ok) {
            const missing = /No registration entry has the id/.test(
                updated.errors[0] || '');
            return { status: self.refusedItem(
              missing ? 'STS-SPIFFE-0046' : 'STS-SPIFFE-0049',
              missing ? status.NOT_FOUND : status.INVALID_ARGUMENT,
              updated.errors.join(' '), id), entry: null };
          }
          return { status: self.okStatus(),
                   entry: self.entryToProto(updated.entry,
                                            request.output_mask) };
        });
        return { results: results };
      }),

      BatchDeleteEntry: rpc.unary('server', 'Entry.BatchDeleteEntry',
                                  async function (call) {
        const request = call.request || {};
        const results = (request.ids || []).map(function (id) {
          const deleted = registry.deleteEntry(String(id), '');
          return { status: deleted.ok ? self.okStatus()
                     : self.refusedItem('STS-SPIFFE-0046', status.NOT_FOUND,
                                        deleted.errors.join(' '), String(id)),
                   id: String(id) };
        });
        return { results: results };
      }),

      // What an AGENT calls to learn what it may issue: the entries beneath the
      // caller's own agent SVID, and nothing else. `spiffe_auth.ts`
      // authenticates the caller and its POLICY row lets only an agent call
      // this. Until 2026-09-16 the answer was every entry in the registry; see
      // `registry.entriesAuthorizedFor()`.
      GetAuthorizedEntries: rpc.unary('server', 'Entry.GetAuthorizedEntries',
                                      async function (call) {
        const request = call.request || {};
        return {
          entries: self.authorizedEntriesOf(call).map(function (entry) {
            return self.entryToProto(entry, request.output_mask);
          })
        };
      }),

      // The streaming form of the same question, which an agent uses to keep
      // its cache current: it sends the ids it holds, and the server answers
      // with the revision of each plus the full entries for anything it does
      // not have.
      //
      // Answered in ONE message with `more: false`. That is a conforming answer
      // — the field exists so a large result can be split — and it is the right
      // one for a registry this size. A client that handles `more: true` is
      // untested by this; a client that does not handle it works.
      SyncAuthorizedEntries: rpc.bidiStream('server',
                                            'Entry.SyncAuthorizedEntries',
        async function (request, call) {
          const held = {};
          (request.ids || [])
            .forEach(function (id) { held[String(id)] = true; });
          // The same narrowing as GetAuthorizedEntries: a stream that listed
          // every entry would undo it. `call` is the stream, carrying the
          // caller.
          const rows = self.authorizedEntriesOf(call);
          return {
            entry_revisions: rows.map(function (entry) {
              return { id: entry.id,
                       revision_number: String(entry.revisionNumber || 0),
                       created_at: String(self.secondsFromGeneralizedTime(
                           entry.createdAt)) };
            }),
            entries: rows.filter(function (entry) { return !held[entry.id]; })
              .map(function (entry) {
                return self.entryToProto(entry, request.output_mask);
              }),
            more: false
          };
        })
    };
    log.debug("Leaving SpiffeApi.buildEntryHandlers().");
    return entryHandlers;
  }

  // The entries the authenticated agent on this call is authorized for. No
  // caller, or one with no verified SPIFFE ID, is authorized for nothing — the
  // policy table has already refused such a caller, so this is the second lock
  // rather than the first.
  authorizedEntriesOf(call) {
    const { log, registry } = this.deps;
    log.debug('Entering SpiffeApi.authorizedEntriesOf().');
    const caller = (call && call.spiffeCaller) || null;
    const agent = caller && caller.authenticated ? caller.spiffeId : '';
    const rows = registry.entriesAuthorizedFor(agent, this.trustDomain());
    log.debug('Leaving SpiffeApi.authorizedEntriesOf(). ' + rows.length +
              ' for ' +
              (agent || 'nobody') + '.');
    return rows;
  }

  // Whether the agent on this call may be issued an SVID from `entry`: the same
  // set GetAuthorizedEntries tells it about. Until 2026-09-16 an agent could
  // name ANY entry id to BatchNewX509SVID or NewJWTSVID and be issued that
  // identity, whatever it had been told.
  authorizedFor(call, entry) {
    const { log } = this.deps;
    log.debug('Entering SpiffeApi.authorizedFor(). entry=' +
              (entry && entry.id));
    const ids = this.authorizedEntriesOf(call).map(function (one) {
      return one.id;
    });
    const answer = !!entry && ids.indexOf(entry.id) >= 0;
    log.debug('Leaving SpiffeApi.authorizedFor(). ' + answer);
    return answer;
  }

  notBeneath(call, entry) {
    const { log } = this.deps;
    log.debug('Entering SpiffeApi.notBeneath().');
    const caller = (call && call.spiffeCaller) || {};
    log.debug('Leaving SpiffeApi.notBeneath().');
    return 'Registration entry ' + entry.id + ' (' + entry.spiffeId + ') is ' +
           'not beneath ' + (caller.spiffeId || 'this caller') + ', so this ' +
           'agent may not be issued its identity. GetAuthorizedEntries lists ' +
           'the entries it may.';
  }

  // Which fields of a submitted entry to apply. No mask, or an empty one, means
  // all of them — which is what the specification says and is what
  // `spire-server entry update` relies on.
  maskedChanges(submitted, mask) {
    const { log } = this.deps;
    log.debug('Entering SpiffeApi.maskedChanges().');
    if (!mask) {
      log.debug('Leaving SpiffeApi.maskedChanges().');
      return submitted;
    }
    const anySet = Object.keys(mask).some(function (key) { return mask[key]; });
    if (!anySet) {
      log.debug('Leaving SpiffeApi.maskedChanges().');
      return submitted;
    }
    const FIELD_OF = {
      spiffe_id: 'spiffeId', parent_id: 'parentId', selectors: 'selectors',
      x509_svid_ttl: 'x509SvidTtl', jwt_svid_ttl: 'jwtSvidTtl',
      federates_with: 'federatesWith', admin: 'admin', downstream: 'downstream',
      expires_at: 'expiresAt', dns_names: 'dnsNames', store_svid: 'storeSvid',
      hint: 'hint'
    };
    const changes = {};
    Object.keys(mask).forEach(function (key) {
      if (mask[key] &&
          FIELD_OF[key]) changes[FIELD_OF[key]] = submitted[FIELD_OF[key]];
    });
    log.debug('Leaving SpiffeApi.maskedChanges().');
    return changes;
  }

  joinTokenKey(token) {
    const { log, crypto } = this.deps;
    log.debug("Entering SpiffeApi.joinTokenKey().");
    log.debug("Leaving SpiffeApi.joinTokenKey().");
    return crypto.createHash('sha256').update(String(token || ''), 'utf8')
      .digest('base64url');
  }

  buildAgentHandlers() {
    const { log, rpc, registry, spiffeId, errorCodes, ca, auth, nowSec,
            crypto, stats, status, audit, config } = this.deps;
    const self = this;
    log.debug("Entering SpiffeApi.buildAgentHandlers().");
    const attestation = this.nodeAttestation();
    const agentHandlers = {
      CountAgents: rpc.unary('server', 'Agent.CountAgents',
                             async function (call) {
        const rows = self.filterAgents(registry.allAgents(),
                                       (call.request || {}).filter);
        return { count: rows.length };
      }),

      ListAgents: rpc.unary('server', 'Agent.ListAgents',
                            async function (call) {
        const request = call.request || {};
        const rows = self.filterAgents(registry.allAgents(), request.filter);
        const paged = self.page(rows, request.page_size, request.page_token);
        return {
          agents: paged.rows.map(function (agent) {
            return self.agentToProto(agent, request.output_mask);
          }),
          next_page_token: paged.nextPageToken
        };
      }),

      GetAgent: rpc.unary('server', 'Agent.GetAgent', async function (call) {
        const request = call.request || {};
        const id = spiffeId.fromProto(request.id);
        const agent = id ? registry.agentById(id) : null;
        if (!agent) {
          errorCodes.mark(call, 'STS-SPIFFE-0050');
          throw rpc.notFound('No agent has attested here as ' +
                             (id || '(no id given)') + '.');
        }
        return self.agentToProto(agent, request.output_mask);
      }),

      DeleteAgent: rpc.unary('server', 'Agent.DeleteAgent',
                             async function (call) {
        const id = spiffeId.fromProto((call.request || {}).id);
        const deleted = registry.deleteAgent(id, '');
        if (!deleted.ok) {
          errorCodes.mark(call, 'STS-SPIFFE-0050');
          throw rpc.notFound(deleted.errors.join(' '));
        }
        return {};
      }),

      BanAgent: rpc.unary('server', 'Agent.BanAgent', async function (call) {
        const id = spiffeId.fromProto((call.request || {}).id);
        const banned = registry.setAgentBanned(id, true, '');
        if (!banned.ok) {
          errorCodes.mark(call, 'STS-SPIFFE-0050');
          throw rpc.notFound(banned.errors.join(' '));
        }
        return {};
      }),

      // ATTESTATION (#40, 2026-09-21: every type is VERIFIED or refused).
      //
      // A real server runs the named node attestor against the payload —
      // verifies a join token it minted, an X.509 proof of possession, a
      // Kubernetes projected service account token, an AWS instance identity
      // document — and derives the agent's SPIFFE ID and selectors from what
      // it proved. Some attestors then issue a CHALLENGE and expect a signed
      // response, which is why this is a bidirectional stream and why the
      // attestor is handed `challenge()`.
      //
      // The attestor is `spiffe_node_attestation.ts`'s table, asked for the
      // type the agent named in THIS realm; a type the table cannot verify or
      // the realm has not turned on is FAILED_PRECONDITION, what SPIRE
      // answers for an attestor it has no plugin for. There is no fallback:
      // until 2026-09-21 any other type was accepted with its payload unread
      // and its agent entry marked `unverified:true`, and that branch is gone
      // in every mode. What is still this handler's is the rest of SPIRE's
      // sequence: the ban, the CSR (only its public key is read, so an agent
      // cannot name itself), the one-attestation rule for evidence that is
      // not re-attestable, and spending the evidence only once the SVID
      // exists.
      AttestAgent: rpc.bidiStream('server', 'Agent.AttestAgent',
                                  async function (request, call,
                                                  conversation) {
        await ca.ready();
        // A challenge response arriving when no challenge is outstanding.
        // Refused rather than ignored: a client in that state has misread the
        // protocol, and an empty answer would leave it waiting.
        if (request.challenge_response !== undefined && !request.params) {
          errorCodes.mark(call, 'STS-SPIFFE-0051');
          throw rpc.invalidArgument('No attestation challenge is outstanding ' +
                                    'on this stream, so there is nothing a ' +
                                    'challenge_response can answer. Send the ' +
                                    'params step first.');
        }
        const params = request.params || {};
        const data = params.data || {};
        const attestationType = String(data.type || '').trim();
        if (!attestationType) {
          errorCodes.mark(call, 'STS-SPIFFE-0079');
          throw rpc.invalidArgument('AttestAgent names its attestor in ' +
                                    'params.data.type, and this one is ' +
                                    'empty.');
        }
        const attestor = attestation.attestorFor(attestationType);
        if (!attestor) {
          errorCodes.mark(call, 'STS-SPIFFE-0078');
          throw rpc.statusError(status.FAILED_PRECONDITION,
            'could not find node attestor type "' + attestationType + '": ' +
            'this realm accepts ' +
            (attestation.enabled().join(', ') || 'no node attestor') +
            ' (spiffe.nodeAttestors). An attestation type this server cannot ' +
            'verify is refused rather than taken on trust.');
        }
        const csr = (params.params || {}).csr;
        if (!csr || !csr.length) {
          errorCodes.mark(call, 'STS-SPIFFE-0053');
          throw rpc.invalidArgument('AttestAgent needs a certificate signing ' +
                                    'request in params.params.csr: the agent ' +
                                    'keeps its own private key, so there is ' +
                                    'nothing to issue against without one.');
        }
        // The attestor verifies — and may challenge, and may claim the
        // evidence. Everything it throws is the call's answer; a conversation
        // that broke down (a timeout, the client gone) is named here, because
        // the attestor only asked a question.
        let verified = null;
        try {
          verified = await attestor.attest({
            type: attestationType,
            payload: Buffer.from(data.payload || []),
            trustDomain: self.trustDomain(),
            // `address:port`, or `[v6]:port`; '' on the Unix socket.
            clientIp: String((call.spiffeCaller || {}).peer || '')
              .replace(/:\d+$/, '')
              .replace(/^\[(.*)\]$/, '$1'),
            call: call,
            challenge: function (bytes) {
              log.debug("Entering challenge(). type=" + attestationType);
              log.debug("Leaving challenge().");
              return conversation.challenge({ challenge: bytes },
                                            attestation.challengeTimeoutMs())
                .then(function (next) {
                  log.debug("Entering the challenge answer.");
                  if (!next || next.params ||
                      next.challenge_response === undefined) {
                    const err: any = new Error('The message after an ' +
                      'attestation challenge must carry challenge_response.');
                    err.conversation = 'unexpected';
                    log.debug("Leaving the challenge answer. Not one.");
                    throw err;
                  }
                  log.debug("Leaving the challenge answer.");
                  return Buffer.from(next.challenge_response);
                });
            }
          });
        } catch (e) {
          log.debug("Caught in AttestAgent: " + ((e && e.message) || e));
          const reason = e && e.conversation;
          if (reason === 'timeout') {
            errorCodes.mark(call, 'STS-SPIFFE-0080');
            throw rpc.statusError(status.DEADLINE_EXCEEDED,
              'The ' + attestationType + ' attestor challenged and no ' +
              'response arrived: ' + e.message + ' ' +
              '(spiffe.attestationChallengeTimeout).');
          }
          if (reason === 'unexpected') {
            errorCodes.mark(call, 'STS-SPIFFE-0081');
            throw rpc.invalidArgument(e.message);
          }
          if (reason) {
            errorCodes.mark(call, 'STS-SPIFFE-0082');
            throw rpc.statusError(status.CANCELLED,
              'The attestation stream closed during the ' + attestationType +
              ' challenge: ' + e.message);
          }
          throw e;
        }
        const agentId = verified.agentId;
        const existing = registry.agentById(agentId);
        try {
          if (existing && existing.banned) {
            // One of the few refusals in this service, and it earns its
            // place: a ban that did not refuse would make the button on
            // /admin/spiffe/agents a lie. PERMISSION_DENIED with the reason
            // SPIRE uses.
            errorCodes.mark(call, 'STS-SPIFFE-0052');
            throw rpc.permissionDenied('The agent ' + agentId + ' is banned ' +
                                       'on this server. Unban it from ' +
                                       '/admin/spiffe/agents or with the ' +
                                       'management API.');
          }
          if (existing && !verified.canReattest) {
            // SPIRE's rule for evidence that is not re-attestable (a join
            // token, and the trust-on-first-use cloud documents): it attests
            // an agent ONCE, and presenting it again is somebody else holding
            // a copy. Deleting the agent is how an operator lets it back.
            errorCodes.mark(call, 'STS-SPIFFE-0083');
            throw rpc.permissionDenied('The agent ' + agentId + ' has ' +
              'already attested, and ' + attestationType + ' evidence is not ' +
              're-attestable. Delete the agent from /admin/spiffe/agents to ' +
              'let it attest again.');
          }
          // `spiffe.agentSvidTtl`, where 0 — its default, and the literal
          // this was — means spiffe.svidTtl. See agentSvidTtl().
          const svid = await ca.signCsr(Buffer.from(csr), agentId,
                                        { ttl: self.agentSvidTtl() });
          const recorded = registry.recordAttestation(agentId, {
            attestationType: attestationType,
            selectors: verified.selectors,
            canReattest: verified.canReattest,
            svidHash: crypto.createHash('sha256').update(svid.certificateDer)
              .digest('hex').slice(0, 32),
            expiresAt: svid.expiresAt
          });
          if (recorded && recorded.banned) {
            errorCodes.mark(call, 'STS-SPIFFE-0052');
            throw rpc.permissionDenied('The agent ' + agentId + ' is banned.');
          }
          // The evidence is spent HERE, at the successful attestation, and
          // not when it was verified — the same reasoning that puts
          // oauth2_bcp.js's transaction check at the point the values are
          // spent rather than at the top of the endpoint.
          verified.commit();
          stats.recordSvid('X.509', {
            subject: agentId, entryId: '', serial: svid.serialHex,
            expiresAt: svid.expiresAt,
            // See buildX509Response() in spiffe_workload.ts: the directory
            // files this agent's identity by the certificate it was just
            // given.
            certificate: svid.certificate
          });
          // THE ATTESTED AGENT IS AN IDENTITY, AND IT REACHES THE FUNNEL
          // HERE, below every refusal — a row must mean "a credential was
          // ACCEPTED", the rule `recordAuthentication()` itself follows.
          auth.recordIdentity({
            presented: agentId,
            protocol: 'SPIFFE',
            method: verified.method,
            note: verified.note
          });
          return {
            result: {
              svid: {
                // **THE WHOLE CHAIN, LEAF FIRST, ANCHOR EXCLUDED.**
                // `cert_chain` is a `repeated bytes` in `svid.proto`; since
                // 2026-09-11 this realm's SPIFFE Issuing CA and its
                // Intermediate sit between every SVID and the anchor, and an
                // agent handed only the leaf cannot build a path to the
                // bundle it was given. `spiffe_ca.ts`'s `chainDerOf()` is the
                // one place the order is decided.
                cert_chain: svid.chainCertificatesDer,
                id: spiffeId.toProto(agentId),
                expires_at: String(svid.expiresAt),
                hint: ''
              },
              reattestable: verified.canReattest
            }
          };
        } catch (e) {
          // THE EVIDENCE IS GIVEN BACK: nothing was attested, so nothing is
          // spent. The error is the call's answer, unchanged.
          log.debug("Caught in AttestAgent: " + ((e && e.message) || e));
          verified.release();
          throw e;
        }
      }),

      // ---------------------------------------------------------------------
      // RenewAgent — THE ONE METHOD AUTHENTICATION TURNED FROM A REFUSAL INTO
      // AN ANSWER, and the refusal it replaced is worth keeping in view.
      //
      // It used to be `Unimplemented`, and the message said why in terms: "a
      // real SPIRE server knows which agent is calling from the SVID on the
      // mTLS connection and renews THAT agent. Nothing here authenticates the
      // caller, so answering would mean either guessing which agent to renew or
      // renewing whichever one the caller named — and the second is a way for
      // any caller to obtain any agent's identity."
      //
      // Something here authenticates the caller now. The agent being renewed is
      // the one on the connection — `caller.spiffeId`, off the mutual-TLS SVID,
      // which `spiffe_auth.ts` verified against this trust domain's bundle and
      // classified as an attested, unbanned agent — and it is NEVER read from
      // the request. The policy table already refuses this method to anybody
      // who is not an agent, so by the time this runs the caller is one; the
      // check below is for the OTHER mode, where nothing identifies a caller
      // and the old objection stands word for word. That mode is unreachable
      // since 2026-09-06.
      // ---------------------------------------------------------------------
      RenewAgent: rpc.unary('server', 'Agent.RenewAgent',
                            async function (call) {
        await ca.ready();
        const csr = ((call.request || {}).params || {}).csr;
        if (!csr || !csr.length) {
          errorCodes.mark(call, 'STS-SPIFFE-0053');
          throw rpc.invalidArgument('RenewAgent needs a certificate signing ' +
                                    'request in params.csr.');
        }
        const caller = call.spiffeCaller || {};
        if (!caller.authenticated || !caller.entities.agent) {
          errorCodes.mark(call, 'STS-SPIFFE-0058');
          throw rpc.statusError(status.UNIMPLEMENTED,
            'RenewAgent renews the agent on ' +
            'the CONNECTION, and this connection ' +
            'has no agent on it: ' + auth.describeCaller(caller) + '. With ' +
            'nothing to identify a caller by, answering would mean renewing ' +
            'whichever agent the caller named — a way for anybody to obtain ' +
            'any agent\'s identity. Present the agent\'s X509-SVID, or call ' +
            'AttestAgent again, which is not refused, re-issues, and records ' +
            'the attestation.');
        }
        const agent = registry.agentById(caller.spiffeId);
        if (!agent) {
          // Classified as an agent a moment ago and gone now: somebody deleted
          // it from /admin/spiffe/agents between the handshake and this call.
          // NOT FOUND rather than an invented re-attestation — a renewal is for
          // an agent that exists, and re-attesting one somebody has just
          // removed would undo the delete from the other end.
          errorCodes.mark(call, 'STS-SPIFFE-0050');
          throw rpc.notFound('The agent ' + caller.spiffeId + ' is no longer ' +
                             'recorded on this server — it was deleted ' +
                             'between this connection being made and this ' +
                             'call. Call AttestAgent to come back.');
        }
        if (agent.banned) {
          errorCodes.mark(call, 'STS-SPIFFE-0052');
          throw rpc.permissionDenied('The agent ' + caller.spiffeId + ' is ' +
                                     'banned on this server. Unban it from ' +
                                     '/admin/spiffe/agents or with the ' +
                                     'management API.');
        }
        const svid = await ca.signCsr(Buffer.from(csr), caller.spiffeId,
                                      { ttl: self.agentSvidTtl() });
        // The renewal is recorded as an attestation of the SAME kind the agent
        // already had. It is not a new attestation — nothing was attested here,
        // the agent proved possession of an SVID this server issued — so the
        // attestation type is carried over rather than invented, and the
        // selectors are left exactly as they were.
        registry.recordAttestation(caller.spiffeId, {
          attestationType: agent.attestationType,
          selectors: agent.selectors,
          canReattest: agent.canReattest,
          svidHash: crypto.createHash('sha256').update(svid.certificateDer)
            .digest('hex').slice(0, 32),
          expiresAt: svid.expiresAt
        });
        stats.recordSvid('X.509', {
          subject: caller.spiffeId, entryId: '', serial: svid.serialHex,
          expiresAt: svid.expiresAt, certificate: svid.certificate
        });
        audit.audit({
          action: 'spiffe.agent.attest', actor: caller.spiffeId,
          protocol: 'SPIRE Server API', channel: 'grpc',
          target: caller.spiffeId,
          summary: 'An agent renewed its own SVID',
          detail: { serial: svid.serialHex, expiresAt: svid.expiresAt }
        });
        return {
          svid: {
            cert_chain: svid.chainCertificatesDer,
            id: spiffeId.toProto(caller.spiffeId),
            expires_at: String(svid.expiresAt),
            hint: ''
          }
        };
      }),

      // A join token. Single-use (see `joinTokens`), and with a real TTL,
      // because both properties are what a join token IS — and because a client
      // author testing "my token expired" has nothing to test against
      // otherwise.
      CreateJoinToken: rpc.unary('server', 'Agent.CreateJoinToken',
                                 async function (call) {
        const request = call.request || {};
        // `spiffe.joinTokenTtl` when the request names none (600, the old
        // literal, is its default). A request's own ttl still wins, as it does
        // in SPIRE.
        const ttl = Number(request.ttl) > 0
          ? Number(request.ttl)
          : config.value('spiffe.joinTokenTtl');
        const token = String(request.token || '').trim() ||
                      crypto.randomUUID();
        const expiresAt = nowSec() + ttl;
        const agentId = spiffeId.fromProto(request.agent_id);
        // ---------------------------------------------------------------------
        // **BOUNDED, AND THE BOUND NO LONGER EATS A LIVE TOKEN (2026-09-12).**
        // It was `if (size > 256) delete the oldest` — so the 257th
        // CreateJoinToken silently invalidated a token somebody had already
        // handed to an agent that had not attested yet, and that agent then met
        // "not issued by this server" about a token this server had issued.
        // Now: expired tokens are swept first, because forgetting one costs
        // nothing; a token being REPLACED by the same value does not count
        // against the cap; and if the cap is still reached the NEW request is
        // refused with RESOURCE_EXHAUSTED naming the setting — the caller
        // asking now can see the refusal, where the agent holding an evicted
        // token could not. `spiffe.maxJoinTokens` (256) is per realm, because
        // the store is.
        // ---------------------------------------------------------------------
        const now = nowSec();
        joinTokens.forEach(function (held, key) {
          if (held && held.expiresAt && held.expiresAt <= now) {
            joinTokens.delete(key);
          }
        });
        const cap = config.value('spiffe.maxJoinTokens');
        if (!joinTokens.has(self.joinTokenKey(token)) &&
            joinTokens.size >= cap) {
          errorCodes.mark(call, 'STS-SPIFFE-0059');
          throw rpc.statusError(status.RESOURCE_EXHAUSTED,
            'This realm already holds ' + joinTokens.size + ' unexpired join ' +
            'token(s), which is spiffe.maxJoinTokens. Nothing was evicted — ' +
            'a token already handed to an agent stays good until it is spent ' +
            'or expires. Wait for one to expire, create tokens with a ' +
            'shorter ttl, or raise the setting.');
        }
        // ---------------------------------------------------------------------
        // A NAMED AGENT IS AN ALIAS ENTRY, AS IN SPIRE (#40, 2026-09-21).
        //
        // `agent_id` used to be stored beside the token and compared with the
        // id the attestation produced — which is always
        // `/spire/agent/join_token/<digest>`, so a token created for a named
        // agent could never attest at all (STS-SPIFFE-0057, now retired).
        // SPIRE does not constrain anything with it: it registers an entry
        // naming `agent_id`, parented on the join token's agent and selecting
        // `spiffe_id:<that agent>`, so the agent is ALSO issued the name the
        // operator chose — a node alias. Checked before the token exists, so
        // a refused name mints nothing.
        // ---------------------------------------------------------------------
        let alias = null;
        if (agentId) {
          self.nodeAttestation();
          const tokenAgent = self.joinTokenAttestorInstance
            .agentIdFor(self.trustDomain(), token);
          alias = { spiffeId: agentId, parentId: tokenAgent,
                    selectors: [{ type: 'spiffe_id', value: tokenAgent }] };
          const checked = registry.checkRecord(alias, self.trustDomain());
          if (!checked.ok) {
            errorCodes.mark(call, 'STS-SPIFFE-0084');
            throw rpc.invalidArgument('agent_id cannot name this join ' +
              'token\'s agent: ' + checked.errors.join(' '));
          }
        }
        joinTokens.set(self.joinTokenKey(token), { expiresAt: expiresAt,
                                                   agentId: agentId || '' });
        if (alias) {
          const created = registry.createEntry(alias, 'join token alias',
                                               self.trustDomain(), '');
          if (!created.ok) {
            joinTokens.delete(self.joinTokenKey(token));
            errorCodes.mark(call, 'STS-SPIFFE-0084');
            throw rpc.invalidArgument('agent_id could not be registered as ' +
              'this join token\'s alias, so no token was issued: ' +
              created.errors.join(' '));
          }
        }
        audit.audit({
          action: 'spiffe.agent.create', actor: '',
          protocol: 'SPIRE Server API',
          channel: 'grpc', target: agentId || '',
          summary: 'A join token was created',
          // THE TOKEN ITSELF IS NEVER RECORDED — it is a credential, and
          // audit.js's rule holds here exactly as it does everywhere else.
          detail: { ttl: ttl, agentId: agentId || '' }
        });
        return { value: token, expires_at: String(expiresAt) };
      }),

      // An agent reporting its version and which bundle it holds. Recorded at
      // debug and otherwise ignored, which is all a real server does with it
      // too.
      PostStatus: rpc.unary('server', 'Agent.PostStatus',
                            async function (call) {
        const request = call.request || {};
        log.debug('spiffe: an agent posted its status. version=' +
                  String(request.agent_version || '(unstated)') +
                  ', bundle serial=' +
                  String(request.current_bundle_serial || 0) +
                  '; this server\'s bundle sequence is ' + ca.sequence() + '.');
        return {};
      })
    };
    log.debug("Leaving SpiffeApi.buildAgentHandlers().");
    return agentHandlers;
  }

  // The lifetime of the SVID an agent is issued at AttestAgent and RenewAgent.
  // `spiffe.agentSvidTtl` since 2026-09-12; its default 0 means
  // "spiffe.svidTtl", which is exactly what the `{ ttl: 0 }` literal it
  // replaced meant —
  // `signCsr()` treats a non-positive ttl as the service default. Stated here
  // because 0 is a legal, meaningful value and must never be read as "unset,
  // use something".
  agentSvidTtl() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeApi.agentSvidTtl().");
    log.debug("Leaving SpiffeApi.agentSvidTtl().");
    return config.value('spiffe.agentSvidTtl');
  }

  // THE NODE ATTESTORS THIS SERVER CAN VERIFY (#40), built once, on first
  // use. The table decides nothing about a realm — `attestorFor()` reads the
  // ambient realm's `spiffe.nodeAttestors` on every call — so one table serves
  // every realm's sockets. `join_token` is registered here rather than in the
  // table's own module because its store is this module's: `CreateJoinToken`
  // writes it.
  nodeAttestation() {
    const { log, attestation, joinTokenAttestor, nowSec, crypto, errorCodes,
            spiffeId, rpc, claims } = this.deps;
    const self = this;
    log.debug("Entering SpiffeApi.nodeAttestation().");
    if (!this.attestationTable) {
      const table = new attestation.NodeAttestation(
        attestation.NodeAttestation.defaultDeps());
      this.joinTokenAttestorInstance = new joinTokenAttestor.JoinTokenAttestor({
        log: log, nowSec: nowSec, crypto: crypto, errorCodes: errorCodes,
        spiffeId: spiffeId, rpc: rpc, claims: claims,
        tokens: joinTokens,
        keyOf: function (token) {
          return self.joinTokenKey(token);
        }
      });
      table.register(this.joinTokenAttestorInstance);
      this.deps.attestors.forEach(function (one) {
        table.register(one.build());
      });
      this.attestationTable = table;
    }
    log.debug("Leaving SpiffeApi.nodeAttestation().");
    return this.attestationTable;
  }

  // What `GET /spiffe` and the console draw about node attestation, in the
  // ambient realm.
  nodeAttestationState() {
    const { log } = this.deps;
    log.debug("Entering SpiffeApi.nodeAttestationState().");
    log.debug("Leaving SpiffeApi.nodeAttestationState().");
    return this.nodeAttestation().state();
  }

  // ===========================================================================
  // THE BUNDLE SERVICE.
  // ===========================================================================
  async ownBundleProto(mask) {
    const { log, ca } = this.deps;
    const self = this;
    log.debug('Entering SpiffeApi.ownBundleProto().');
    const state = ca.state();
    const document = await ca.bundle();
    const full = {
      trust_domain: ca.trustDomain(),
      // **THE TRUST ANCHORS, WHICH SINCE 2026-09-11 ARE NOT THE AUTHORITIES.**
      // `x509_authorities` in `bundle.proto` is what a consumer should TRUST,
      // and that is the service Root — the SPIFFE Issuing CA that actually
      // signs travels in each SVID's own chain instead. The two were one list
      // while the authority was self-signed, and publishing the Issuing CA here
      // now would hand every consumer an anchor that is not one.
      x509_authorities: state.trustAnchors.map(function (authority) {
        return {
          asn1: Buffer.from(authority.certificatePem
            .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'),
          // `tainted` marks an authority being rotated out after a compromise.
          // Always false here: this service has no way to be told one was
          // compromised, and reporting a fact it cannot know would be worse
          // than reporting the absence of one.
          tainted: false
        };
      }),
      jwt_authorities: state.jwtAuthorities.map(function (authority) {
        return {
          public_key: self.derFromJwk(authority.jwk),
          key_id: authority.id,
          expires_at: '0',
          tainted: false
        };
      }),
      refresh_hint: String(document.spiffe_refresh_hint || 0),
      sequence_number: String(document.spiffe_sequence || 0),
      wit_authorities: []
    };
    if (!mask || !Object.keys(mask).some(function (k) { return mask[k]; })) {
      log.debug('Leaving SpiffeApi.ownBundleProto().');
      return full;
    }
    const out = { trust_domain: full.trust_domain };
    Object.keys(mask).forEach(function (key) {
      if (mask[key] && Object.prototype.hasOwnProperty.call(full, key)) {
        out[key] = full[key];
      }
    });
    log.debug('Leaving SpiffeApi.ownBundleProto().');
    return out;
  }

  // `JWTKey.public_key` is a DER-encoded SubjectPublicKeyInfo, NOT a JWK and
  // not PEM. The bundle document publishes JWKs and this message publishes DER,
  // so the conversion has to happen somewhere — here, once, rather than in each
  // of the three methods that build a Bundle.
  derFromJwk(jwk) {
    const { log, crypto, errorCodes } = this.deps;
    log.debug('Entering SpiffeApi.derFromJwk().');
    try {
      log.debug('Leaving SpiffeApi.derFromJwk().');
      return crypto.createPublicKey({ key: jwk, format: 'jwk' })
        .export({ type: 'spki', format: 'der' });
    } catch (e) {
      // A key this node cannot import. Empty rather than fatal: the rest of the
      // bundle is still usable, and a caller sees a key with no material rather
      // than no bundle at all.
      log.error(errorCodes.tag('STS-SPIFFE-0068') +
                'spiffe: a JWT authority could not be exported as DER and is ' +
                'being sent empty: ' + e.message);
      log.debug('Leaving SpiffeApi.derFromJwk().');
      return Buffer.alloc(0);
    }
    log.debug('Leaving SpiffeApi.derFromJwk().');
  }

  federatedBundleProto(entry, mask) {
    const { log } = this.deps;
    const self = this;
    log.debug('Entering SpiffeApi.federatedBundleProto().');
    const document = entry.document || {};
    const x509 = [];
    const jwt = [];
    (document.keys || []).forEach(function (key) {
      if (key.use === 'x509-svid') {
        (key.x5c || []).forEach(function (b64) {
          x509.push({ asn1: Buffer.from(String(b64), 'base64'),
                      tainted: false });
        });
      } else if (key.use === 'jwt-svid') {
        jwt.push({ public_key: self.derFromJwk(key), key_id: key.kid || '',
                   expires_at: '0', tainted: false });
      }
    });
    const full = {
      trust_domain: entry.trustDomain,
      x509_authorities: x509,
      jwt_authorities: jwt,
      refresh_hint: String(document.spiffe_refresh_hint || 0),
      sequence_number: String(document.spiffe_sequence || 0),
      wit_authorities: []
    };
    if (!mask || !Object.keys(mask).some(function (k) { return mask[k]; })) {
      log.debug('Leaving SpiffeApi.federatedBundleProto().');
      return full;
    }
    const out = { trust_domain: full.trust_domain };
    Object.keys(mask).forEach(function (key) {
      if (mask[key] && Object.prototype.hasOwnProperty.call(full, key)) {
        out[key] = full[key];
      }
    });
    log.debug('Leaving SpiffeApi.federatedBundleProto().');
    return out;
  }

  // A `spire.api.types.Bundle` back into the JWK Set document this service
  // holds. The reverse of the two functions above, and it is where a federated
  // bundle submitted over gRPC becomes one `/spiffe/bundle` and the Workload
  // API can serve.
  bundleDocumentFromProto(message) {
    const { log, crypto } = this.deps;
    log.debug('Entering SpiffeApi.bundleDocumentFromProto().');
    const proto = message || {};
    const keys = [];
    (proto.x509_authorities || []).forEach(function (authority) {
      const der = Buffer.from(authority.asn1 || []);
      if (!der.length) return;
      let jwk: any = {};
      try {
        const cert = new crypto.X509Certificate(der);
        jwk = cert.publicKey.export({ format: 'jwk' });
        delete jwk.key_ops;
        delete jwk.ext;
      } catch (e) {
        // Not a certificate this node can parse. The x5c is still carried —
        // it is what an X.509 authority IS — with a minimal kty so the JWK is
        // well-formed. A consumer that can parse it will; one that cannot is no
        // worse off than if this were dropped.
        log.warn('spiffe: an x509 authority in a submitted bundle could not ' +
                 'be parsed, and is being carried as x5c alone: ' + e.message);
        jwk = { kty: 'RSA' };
      }
      jwk.use = 'x509-svid';
      jwk.x5c = [der.toString('base64')];
      keys.push(jwk);
    });
    (proto.jwt_authorities || []).forEach(function (authority) {
      const der = Buffer.from(authority.public_key || []);
      if (!der.length) return;
      try {
        const jwk = crypto.createPublicKey({ key: der, format: 'der',
                                             type: 'spki' })
          .export({ format: 'jwk' });
        delete jwk.key_ops;
        delete jwk.ext;
        jwk.use = 'jwt-svid';
        jwk.kid = authority.key_id || '';
        keys.push(jwk);
      } catch (e) {
        // Dropped, and said so. A JWT authority is nothing BUT its key
        // material, so one that cannot be read carries nothing forward.
        log.warn('spiffe: a JWT authority in a submitted bundle could not be ' +
                 'read and was dropped: ' + e.message);
      }
    });
    log.debug('Leaving SpiffeApi.bundleDocumentFromProto().');
    return {
      keys: keys,
      spiffe_sequence: Number(proto.sequence_number || 0),
      spiffe_refresh_hint: Number(proto.refresh_hint || 0)
    };
  }

  buildBundleHandlers() {
    const { log, rpc, ca, errorCodes, status, registry } = this.deps;
    const self = this;
    log.debug("Entering SpiffeApi.buildBundleHandlers().");
    const bundleHandlers = {
      CountBundles: rpc.unary('server', 'Bundle.CountBundles',
                              async function () {
        // The federated ones only, which is what SPIRE counts: this trust
        // domain's own bundle is not one OF them.
        return { count: ca.federatedBundles().length };
      }),

      GetBundle: rpc.unary('server', 'Bundle.GetBundle', async function (call) {
        await ca.ready();
        return await self.ownBundleProto((call.request || {}).output_mask);
      }),

      // Adding an authority to this trust domain's own bundle. REFUSED, and the
      // reason is not squeamishness: an X.509 authority in a bundle is a key
      // that may sign identities in this trust domain, and this service holds
      // no private key for one somebody else appends — so the effect would be
      // to publish an authority nothing here can issue against, which every
      // workload would then trust. Rotation is how a new authority appears, and
      // it is on /admin/spiffe.
      AppendBundle: rpc.unary('server', 'Bundle.AppendBundle',
                              async function (call) {
        errorCodes.mark(call, 'STS-SPIFFE-0060');
        throw rpc.statusError(status.PERMISSION_DENIED,
          'This service will not append an authority to its OWN bundle. An ' +
          'authority in a trust domain\'s bundle is a key permitted to sign ' +
          'identities in that trust domain, and this server holds no private ' +
          'key for one somebody else submits — so appending would publish an ' +
          'authority that can issue nothing here, which every workload in ' +
          'the trust domain would nonetheless trust. To add an authority, ' +
          'rotate: POST /admin-api/spiffe/rotate, or the button on ' +
          '/admin/spiffe. Federated bundles are a different thing and are ' +
          'accepted — see BatchCreateFederatedBundle.');
      }),

      PublishJWTAuthority: rpc.unary('server', 'Bundle.PublishJWTAuthority',
                                     async function (call) {
        errorCodes.mark(call, 'STS-SPIFFE-0060');
        throw rpc.statusError(status.PERMISSION_DENIED,
          'This service will not publish a JWT authority into its own ' +
          'bundle, for the reason AppendBundle gives: it would advertise a ' +
          'signing key nothing here holds. Rotate instead.');
      }),

      PublishWITAuthority: rpc.unary('server', 'Bundle.PublishWITAuthority',
                                     async function (call) {
        errorCodes.mark(call, 'STS-SPIFFE-0029');
        throw rpc.statusError(status.UNIMPLEMENTED,
          'This service issues no WIT-SVIDs and holds no WIT authority. See ' +
          'GET /spiffe for why: the Workload Identity Token\'s format is not ' +
          'settled in a specification this service could implement against, ' +
          'and inventing one would be inventing a credential format.');
      }),

      ListFederatedBundles: rpc.unary('server', 'Bundle.ListFederatedBundles',
                                      async function (call) {
        const request = call.request || {};
        const rows = ca.federatedBundles();
        const paged = self.page(rows, request.page_size, request.page_token);
        return {
          bundles: paged.rows.map(function (entry) {
            return self.federatedBundleProto(entry, request.output_mask);
          }),
          next_page_token: paged.nextPageToken
        };
      }),

      GetFederatedBundle: rpc.unary('server', 'Bundle.GetFederatedBundle',
                                    async function (call) {
        const request = call.request || {};
        const name = String(request.trust_domain || '').trim().toLowerCase();
        const entry = ca.federatedBundle(name);
        if (!entry) {
          errorCodes.mark(call, 'STS-SPIFFE-0061');
          throw rpc.notFound('This service holds no bundle for the trust ' +
                             'domain ' +
                             (name || '(none given)') + '.');
        }
        return self.federatedBundleProto(entry, request.output_mask);
      }),

      BatchCreateFederatedBundle: rpc.unary('server',
        'Bundle.BatchCreateFederatedBundle',
        async function (call) {
          const request = call.request || {};
          return { results: (request.bundle || []).map(function (message) {
            const name = String(message.trust_domain || '').trim()
              .toLowerCase();
            if (ca.federatedBundle(name)) {
              return { status: self.refusedItem('STS-SPIFFE-0062',
                                                status.ALREADY_EXISTS,
                                                'A bundle for ' + name +
                                                ' is already held; use ' +
                                                'BatchUpdateFederatedBundle ' +
                                                'or BatchSetFederatedBundle.',
                                                name),
                       bundle: null };
            }
            return self.setFederated(message, request.output_mask);
          }) };
        }),

      BatchUpdateFederatedBundle: rpc.unary('server',
        'Bundle.BatchUpdateFederatedBundle',
        async function (call) {
          const request = call.request || {};
          return { results: (request.bundle || []).map(function (message) {
            const name = String(message.trust_domain || '').trim()
              .toLowerCase();
            if (!ca.federatedBundle(name)) {
              return { status: self.refusedItem('STS-SPIFFE-0061',
                                                status.NOT_FOUND,
                                                'No bundle for ' + name +
                                                ' is held ' +
                                                    'here.',
                                                name),
                       bundle: null };
            }
            return self.setFederated(message, request.output_mask);
          }) };
        }),

      // Create-or-update. The one a client should reach for, and the one
      // `spire-server bundle set` uses.
      BatchSetFederatedBundle: rpc.unary('server',
                                         'Bundle.BatchSetFederatedBundle',
        async function (call) {
          const request = call.request || {};
          return { results: (request.bundle || []).map(function (message) {
            return self.setFederated(message, request.output_mask);
          }) };
        }),

      BatchDeleteFederatedBundle: rpc.unary('server',
        'Bundle.BatchDeleteFederatedBundle',
        async function (call) {
          const request = call.request || {};
          // The three modes say what to do about registration entries that
          // federate with the trust domain being deleted. RESTRICT refuses
          // while any does, DELETE removes them too, DISSOCIATE keeps them and
          // drops the federation. All three are implemented, because a client
          // that tested only the default would never learn that RESTRICT is the
          // default.
          const mode = String(request.mode || 'RESTRICT');
          return { results: (request.trust_domains || []).map(function (name) {
            const domain = String(name).trim().toLowerCase();
            const dependents = registry.allEntries().filter(function (entry) {
              return (entry.federatesWith || []).indexOf(domain) >= 0;
            });
            if (dependents.length && mode === 'RESTRICT') {
              return { status: self.refusedItem('STS-SPIFFE-0063',
                status.FAILED_PRECONDITION,
                dependents.length +
                ' registration entry/entries federate with ' +
                domain + '. Delete them first, or send mode DELETE to remove ' +
                'them with it, or DISSOCIATE to keep them and drop the ' +
                'federation.',
                domain),
                trust_domain: domain };
            }
            dependents.forEach(function (entry) {
              if (mode === 'DELETE') {
                registry.deleteEntry(entry.id, '');
              } else if (mode === 'DISSOCIATE') {
                registry.updateEntry(entry.id, {
                  federatesWith: (entry.federatesWith || [])
                    .filter(function (t) {
                    return t !== domain;
                  })
                }, self.trustDomain(), '');
              }
            });
            const removed = ca.deleteFederatedBundle(domain);
            if (!removed) {
              return { status: self.refusedItem('STS-SPIFFE-0061',
                                                status.NOT_FOUND,
                                                'No bundle for ' + domain +
                                                ' is held ' +
                                                    'here.',
                                                domain),
                       trust_domain: domain };
            }
            self.auditBundleChange('a federated bundle for ' + domain +
                                   ' was deleted');
            return { status: self.okStatus(), trust_domain: domain };
          }) };
        })
    };
    log.debug("Leaving SpiffeApi.buildBundleHandlers().");
    return bundleHandlers;
  }

  setFederated(message, mask) {
    const { log, ca, status } = this.deps;
    log.debug("Entering SpiffeApi.setFederated().");
    const name = String(message.trust_domain || '').trim().toLowerCase();
    const document = this.bundleDocumentFromProto(message);
    const result = ca.setFederatedBundle(name, document, {});
    if (!result.ok) {
      log.debug("Leaving SpiffeApi.setFederated().");
      return { status: this.refusedItem(result.errorCode || 'STS-SPIFFE-0041',
                                        status.INVALID_ARGUMENT, result.reason,
                                        name),
               bundle: null };
    }
    this.auditBundleChange('a federated bundle for ' + name + ' was set');
    log.debug("Leaving SpiffeApi.setFederated().");
    return { status: this.okStatus(),
             bundle: this.federatedBundleProto(ca.federatedBundle(name),
                                               mask) };
  }

  auditBundleChange(what) {
    const { log, audit, ca } = this.deps;
    log.debug("Entering SpiffeApi.auditBundleChange().");
    audit.audit({
      action: 'spiffe.bundle.change', actor: '', protocol: 'SPIRE Server API',
      channel: 'grpc', target: '', summary: 'The trust bundle changed: ' + what,
      detail: { sequence: ca.sequence() }
    });
    log.debug("Leaving SpiffeApi.auditBundleChange().");
  }

  // ===========================================================================
  // THE SVID SERVICE.
  // ===========================================================================
  buildSvidHandlers() {
    const { log, rpc, ca, errorCodes, stats, spiffeId, status,
            registry } = this.deps;
    const self = this;
    log.debug("Entering SpiffeApi.buildSvidHandlers().");
    const svidHandlers = {
      // Minting outside any registration entry. This is `spire-server x509
      // mint`, and it is deliberately not tied to an entry — an operator asking
      // for a one-off certificate is what it is for.
      MintX509SVID: rpc.unary('server', 'SVID.MintX509SVID',
                              async function (call) {
        await ca.ready();
        const request = call.request || {};
        if (!request.csr || !request.csr.length) {
          errorCodes.mark(call, 'STS-SPIFFE-0053');
          throw rpc.invalidArgument('MintX509SVID takes a certificate ' +
                                    'signing request; the SPIFFE ID is read ' +
                                    'from its URI subjectAltName.');
        }
        // The one place a CSR's OWN subjectAltName is read, and it is safe here
        // for a reason that does not generalise: there is no entry to take the
        // identity from, so the request is the only statement of what is
        // wanted. Everywhere else — AttestAgent, BatchNewX509SVID — the
        // identity comes from the entry and only the public key is read out of
        // the CSR.
        const wanted = self.spiffeIdFromCsr(request.csr);
        if (!wanted) {
          errorCodes.mark(call, 'STS-SPIFFE-0064');
          throw rpc.invalidArgument('That certificate signing request ' +
                                    'carries no SPIFFE ID in a URI ' +
                                    'subjectAltName, so there is nothing to ' +
                                    'mint. This is the one method here that ' +
                                    'reads the identity out of the CSR: ' +
                                    'there is no registration entry to take ' +
                                    'it from.');
        }
        const svid = await ca.signCsr(Buffer.from(request.csr), wanted,
                                      { ttl: Number(request.ttl || 0) });
        stats.recordSvid('X.509', { subject: wanted, serial: svid.serialHex,
                                    expiresAt: svid.expiresAt,
                                    certificate: svid.certificate });
        self.auditSvid('An X509-SVID was minted for ' + wanted, wanted);
        return { svid: { cert_chain: svid.chainCertificatesDer,
                         id: spiffeId.toProto(wanted),
                         expires_at: String(svid.expiresAt), hint: '' } };
      }),

      MintJWTSVID: rpc.unary('server', 'SVID.MintJWTSVID',
                             async function (call) {
        await ca.ready();
        const request = call.request || {};
        const id = spiffeId.fromProto(request.id);
        if (!id) {
          errorCodes.mark(call, 'STS-SPIFFE-0065');
          throw rpc.invalidArgument('MintJWTSVID needs the SPIFFE ID to mint ' +
                                    'for, as a trust_domain and a path.');
        }
        const audiences = (request.audience || []).map(String).filter(Boolean);
        if (!audiences.length) {
          errorCodes.mark(call, 'STS-SPIFFE-0027');
          throw rpc.invalidArgument('MintJWTSVID requires at least one ' +
                                    'audience: a JWT-SVID is a bearer ' +
                                    'credential, and the audience is ' +
                                    'what stops one being replayed ' +
                                    'against a different service.');
        }
        const minted = await ca.mintJwtSvid(id, audiences,
                                            { ttl: Number(request.ttl || 0) });
        stats.recordSvid('JWT', { subject: id, audiences: audiences,
                                  expiresAt: minted.expiresAt });
        self.auditSvid('A JWT-SVID was minted for ' + id, id);
        return { svid: { token: minted.token, id: spiffeId.toProto(id),
                         expires_at: String(minted.expiresAt),
                         issued_at: String(minted.issuedAt), hint: '' } };
      }),

      MintWITSVID: rpc.unary('server', 'SVID.MintWITSVID',
                             async function (call) {
        errorCodes.mark(call, 'STS-SPIFFE-0029');
        throw rpc.statusError(status.UNIMPLEMENTED,
          'This service issues no WIT-SVIDs; see GET /spiffe for why. ' +
          'X509-SVIDs and JWT-SVIDs are fully implemented.');
      }),

      // What an AGENT calls: one CSR per registration entry it is handing an
      // SVID to. The identity comes from the ENTRY, and only the public key is
      // read out of the CSR — which is the check that stops an agent naming
      // itself anything it likes. (This said "even though nothing here
      // authenticates it" until
      // `spiffe_auth.ts` began authenticating the caller; the check stands on
      // its own either way.)
      BatchNewX509SVID: rpc.unary('server', 'SVID.BatchNewX509SVID',
                                  async function (call) {
        await ca.ready();
        const request = call.request || {};
        const results = [];
        for (let i = 0; i < (request.params || []).length; i++) {
          const params = request.params[i];
          const entry = registry.entryById(String(params.entry_id || ''));
          if (!entry) {
            results.push({ status: self.refusedItem('STS-SPIFFE-0046',
                                                    status.NOT_FOUND,
              'No registration entry has the id ' +
              String(params.entry_id || '') +
              '.',
              String(params.entry_id || '')),
              svid: null });
            continue;
          }
          if (!self.authorizedFor(call, entry)) {
            results.push({ status: self.refusedItem('STS-SPIFFE-0077',
              status.PERMISSION_DENIED, self.notBeneath(call, entry), entry.id),
              svid: null });
            continue;
          }
          if (!params.csr || !params.csr.length) {
            results.push({ status: self.refusedItem('STS-SPIFFE-0053',
              status.INVALID_ARGUMENT,
              'Entry ' + entry.id +
              ' was given no certificate signing request.',
              entry.id),
              svid: null });
            continue;
          }
          try {
            const svid = await ca.signCsr(Buffer.from(params.csr),
                                          entry.spiffeId, {
              ttl: entry.x509SvidTtl, dnsNames: entry.dnsNames, hint: entry.hint
            });
            registry.noteSvidIssued(entry.id);
            stats.recordSvid('X.509',
                             { subject: entry.spiffeId, entryId: entry.id,
                                        serial: svid.serialHex,
                                        hint: entry.hint,
                                        expiresAt: svid.expiresAt,
                                        certificate: svid.certificate });
            results.push({ status: self.okStatus(),
                           svid: { cert_chain: svid.chainCertificatesDer,
                                   id: spiffeId.toProto(entry.spiffeId),
                                   expires_at: String(svid.expiresAt),
                                   hint: entry.hint || '' } });
          } catch (e) {
            // Per item, like every other batch here.
            results.push({ status: self.refusedItem('STS-SPIFFE-0066',
                                                    status.INVALID_ARGUMENT,
                                                    e.message, entry.id),
                           svid: null });
          }
        }
        self.auditSvid(results.length + ' X509-SVID(s) were issued from ' +
                                        'registration entries', '');
        return { results: results };
      }),

      NewJWTSVID: rpc.unary('server', 'SVID.NewJWTSVID', async function (call) {
        await ca.ready();
        const request = call.request || {};
        const entry = registry.entryById(String(request.entry_id || ''));
        if (!entry) {
          errorCodes.mark(call, 'STS-SPIFFE-0046');
          throw rpc.notFound('No registration entry has the id ' +
                             String(request.entry_id || '(none given)') + '.');
        }
        if (!self.authorizedFor(call, entry)) {
          errorCodes.mark(call, 'STS-SPIFFE-0077');
          throw rpc.statusError(status.PERMISSION_DENIED,
                                self.notBeneath(call, entry));
        }
        const audiences = (request.audience || []).map(String).filter(Boolean);
        if (!audiences.length) {
          errorCodes.mark(call, 'STS-SPIFFE-0027');
          throw rpc.invalidArgument('NewJWTSVID requires at least one ' +
                                    'audience.');
        }
        const minted = await ca.mintJwtSvid(entry.spiffeId, audiences,
                                            { ttl: entry.jwtSvidTtl,
                                              hint: entry.hint });
        registry.noteSvidIssued(entry.id);
        stats.recordSvid('JWT', { subject: entry.spiffeId, entryId: entry.id,
                                  audiences: audiences, hint: entry.hint,
                                  expiresAt: minted.expiresAt });
        self.auditSvid('A JWT-SVID was issued from entry ' + entry.id,
                       entry.spiffeId);
        return { svid: { token: minted.token,
                         id: spiffeId.toProto(entry.spiffeId),
                         expires_at: String(minted.expiresAt),
                         issued_at: String(minted.issuedAt),
                         hint: entry.hint || '' } };
      }),

      BatchNewWITSVID: rpc.unary('server', 'SVID.BatchNewWITSVID',
                                 async function (call) {
        errorCodes.mark(call, 'STS-SPIFFE-0029');
        throw rpc.statusError(status.UNIMPLEMENTED,
          'This service issues no WIT-SVIDs; see GET /spiffe for why.');
      }),

      // An intermediate CA for a downstream SPIRE server. The caller's
      // `downstream` flag IS checked now — `spiffe_auth.ts`'s POLICY row allows
      // this method to a `downstream` entity only, read off the entry behind
      // the caller's SVID — and none of it is decided in this handler (see the
      // header). It read "NOT checked — nothing here authenticates the caller"
      // until that file existed.
      NewDownstreamX509CA: rpc.unary('server', 'SVID.NewDownstreamX509CA',
                                     async function (call) {
        await ca.ready();
        const request = call.request || {};
        const downstream = await ca.downstreamCa({
          ttl: Number(request.preferred_ttl || 0)
        });
        const state = ca.state();
        self.auditSvid('A downstream X.509 CA was issued', '');
        return {
          ca_cert_chain: downstream.chainDer,
          // The anchors, for `ownBundleProto()`'s reason — this field is what
          // the caller of NewDownstreamX509CA should trust, not what signed its
          // CA.
          x509_authorities: state.trustAnchors.map(function (authority) {
            return Buffer.from(authority.certificatePem
              .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
          })
        };
      })
    };
    log.debug("Leaving SpiffeApi.buildSvidHandlers().");
    return svidHandlers;
  }

  spiffeIdFromCsr(csr) {
    const { log, loadPkijs, loadAsn1js, spiffeId } = this.deps;
    log.debug('Entering SpiffeApi.spiffeIdFromCsr().');
    try {
      // Node's own X509 parser cannot read a CSR, so this uses the same pkijs
      // the CA does — through a require here rather than an export from
      // spiffe_ca.ts, because reading a CSR's SANs is this file's business and
      // minting is that one's.
      const pkijs = loadPkijs();
      const asn1js = loadAsn1js();
      const buf = Buffer.isBuffer(csr) ? csr : Buffer.from(csr);
      const request = pkijs.CertificationRequest.fromBER(
        buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
      let found = '';
      (request.attributes || []).forEach(function (attribute) {
        if (found || attribute.type !== '1.2.840.113549.1.9.14') return;
        (attribute.values || []).forEach(function (value) {
          if (found) return;
          const extensions = new pkijs.Extensions({ schema: value });
          (extensions.extensions || []).forEach(function (extension) {
            if (found || extension.extnID !== '2.5.29.17') return;
            const names = new pkijs.GeneralNames({
              schema:
                asn1js.fromBER(extension.extnValue.valueBlock.valueHexView)
                  .result
            });
            (names.names || []).forEach(function (name) {
              if (found) return;
              if (name.type === 6 &&
                  spiffeId.isValid(name.value)) found = name.value;
            });
          });
        });
      });
      log.debug('Leaving SpiffeApi.spiffeIdFromCsr().');
      return found;
    } catch (e) {
      // Not a readable CSR, or one with no extensions. The caller answers
      // InvalidArgument with a message about the SPIFFE ID, which is the useful
      // thing to say; the parse failure itself is only interesting at debug.
      log.debug('spiffeIdFromCsr(): could not read a SPIFFE ID out of the ' +
                'CSR: ' +
                e.message);
      log.debug('Leaving SpiffeApi.spiffeIdFromCsr().');
      return '';
    }
    log.debug('Leaving SpiffeApi.spiffeIdFromCsr().');
  }

  auditSvid(summary, subject) {
    const { log, audit } = this.deps;
    log.debug("Entering SpiffeApi.auditSvid().");
    audit.audit({
      action: 'spiffe.svid.issue', actor: '', protocol: 'SPIRE Server API',
      channel: 'grpc', target: subject || '', summary: summary,
      // No SVID and no key, exactly as on the Workload API side.
      detail: {}
    });
    log.debug("Leaving SpiffeApi.auditSvid().");
  }

  // ===========================================================================
  // THE TRUST DOMAIN SERVICE — federation relationships.
  //
  // A relationship is the CONFIGURATION of a federation: which trust domain,
  // where its bundle endpoint is, which profile, and optionally the bundle
  // itself. This service holds all of it and FETCHES NOTHING — see
  // `spiffe_ca.setFederatedBundle()` and `RefreshBundle` below.
  // ===========================================================================
  relationshipProto(entry, mask) {
    const { log } = this.deps;
    log.debug('Entering SpiffeApi.relationshipProto().');
    const full: Record<string, any> = {
      trust_domain: entry.trustDomain,
      bundle_endpoint_url: entry.bundleEndpointUrl || '',
      trust_domain_bundle: this.federatedBundleProto(entry, null)
    };
    // The profile is a `oneof`, so exactly one of the two is set. Setting both
    // — which is easy to do by assigning them in sequence — leaves protobuf
    // silently keeping the last, and a relationship that says https_web when
    // the operator configured https_spiffe.
    if (entry.bundleEndpointProfile === 'https_spiffe') {
      full.https_spiffe = { endpoint_spiffe_id: entry.endpointSpiffeId || '' };
    } else {
      full.https_web = {};
    }
    if (!mask || !Object.keys(mask).some(function (k) { return mask[k]; })) {
      log.debug('Leaving SpiffeApi.relationshipProto().');
      return full;
    }
    const out: Record<string, any> = { trust_domain: full.trust_domain };
    if (mask.bundle_endpoint_url) out.bundle_endpoint_url =
        full.bundle_endpoint_url;
    if (mask.bundle_endpoint_profile) {
      if (full.https_spiffe) out.https_spiffe = full.https_spiffe;
      else out.https_web = full.https_web;
    }
    if (mask.trust_domain_bundle) out.trust_domain_bundle =
        full.trust_domain_bundle;
    log.debug('Leaving SpiffeApi.relationshipProto().');
    return out;
  }

  setRelationship(message, mask) {
    const { log, ca, status } = this.deps;
    log.debug('Entering SpiffeApi.setRelationship().');
    const name = String(message.trust_domain || '').trim().toLowerCase();
    const existing = ca.federatedBundle(name);
    const document = message.trust_domain_bundle
      ? this.bundleDocumentFromProto(message.trust_domain_bundle)
      : (existing ? existing.document : { keys: [] });
    const profile = message.https_spiffe ? 'https_spiffe' : 'https_web';
    const result = ca.setFederatedBundle(name, document, {
      bundleEndpointUrl: message.bundle_endpoint_url || '',
      bundleEndpointProfile: profile,
      endpointSpiffeId: (message.https_spiffe || {}).endpoint_spiffe_id || ''
    });
    if (!result.ok) {
      log.debug('Leaving SpiffeApi.setRelationship().');
      return { status: this.refusedItem(result.errorCode || 'STS-SPIFFE-0041',
                                        status.INVALID_ARGUMENT, result.reason,
                                        name),
               federation_relationship: null };
    }
    this.auditBundleChange('a federation relationship with ' + name +
                           ' was set');
    log.debug('Leaving SpiffeApi.setRelationship().');
    return { status: this.okStatus(),
             federation_relationship:
               this.relationshipProto(ca.federatedBundle(name),
                                                             mask) };
  }

  buildTrustDomainHandlers() {
    const { log, rpc, ca, errorCodes, status } = this.deps;
    const self = this;
    log.debug("Entering SpiffeApi.buildTrustDomainHandlers().");
    const trustDomainHandlers = {
      ListFederationRelationships: rpc.unary('server',
        'TrustDomain.ListFederationRelationships',
        async function (call) {
          const request = call.request || {};
          const paged = self.page(ca.federatedBundles(), request.page_size,
                                  request.page_token);
          return {
            federation_relationships: paged.rows.map(function (entry) {
              return self.relationshipProto(entry, request.output_mask);
            }),
            next_page_token: paged.nextPageToken
          };
        }),

      GetFederationRelationship: rpc.unary('server',
        'TrustDomain.GetFederationRelationship',
        async function (call) {
          const request = call.request || {};
          const name = String(request.trust_domain || '').trim().toLowerCase();
          const entry = ca.federatedBundle(name);
          if (!entry) {
            errorCodes.mark(call, 'STS-SPIFFE-0061');
            throw rpc.notFound('No federation relationship with ' +
                               (name || '(none given)') +
                               ' is configured here.');
          }
          return self.relationshipProto(entry, request.output_mask);
        }),

      BatchCreateFederationRelationship: rpc.unary('server',
        'TrustDomain.BatchCreateFederationRelationship', async function (call) {
          const request = call.request || {};
          return { results: (request.federation_relationships || []).map(
              function (message) {
            const name = String(message.trust_domain || '').trim()
              .toLowerCase();
            if (ca.federatedBundle(name)) {
              return { status: self.refusedItem('STS-SPIFFE-0062',
                                                status.ALREADY_EXISTS,
                'A federation relationship with ' + name + ' is already here.',
                name),
                federation_relationship: null };
            }
            return self.setRelationship(message, request.output_mask);
          }) };
        }),

      BatchUpdateFederationRelationship: rpc.unary('server',
        'TrustDomain.BatchUpdateFederationRelationship', async function (call) {
          const request = call.request || {};
          return { results: (request.federation_relationships || []).map(
              function (message) {
            const name = String(message.trust_domain || '').trim()
              .toLowerCase();
            if (!ca.federatedBundle(name)) {
              return { status: self.refusedItem('STS-SPIFFE-0061',
                                                status.NOT_FOUND,
                'No federation relationship with ' + name +
                ' is configured here.',
                name),
                federation_relationship: null };
            }
            return self.setRelationship(message, request.output_mask);
          }) };
        }),

      BatchDeleteFederationRelationship: rpc.unary('server',
        'TrustDomain.BatchDeleteFederationRelationship', async function (call) {
          const request = call.request || {};
          return { results: (request.trust_domains || []).map(function (name) {
            const domain = String(name).trim().toLowerCase();
            const removed = ca.deleteFederatedBundle(domain);
            if (removed) self.auditBundleChange('a federation relationship ' +
                                                'with ' +
                domain + ' ' +
                'was deleted');
            return { status: removed ? self.okStatus()
                       : self.refusedItem('STS-SPIFFE-0061', status.NOT_FOUND,
                                          'No federation relationship with ' +
                                          domain +
                                          '.',
                                          domain),
                     trust_domain: domain };
          }) };
        }),

      // THE ONE METHOD THAT EXISTS TO SAY NO, AND IT IS A POSITION RATHER THAN
      // A GAP.
      //
      // `RefreshBundle` asks the server to go and fetch a federated bundle from
      // the endpoint URL recorded in the relationship. This service will not:
      // fetching a URL that somebody registered, in order to obtain a key it
      // will then use to verify credentials, is a server-side request forgery
      // with a specification citation attached — and on a service that, when
      // this was written, authenticated nobody and accepted any registration,
      // it would have been a blind HTTP client anybody could point anywhere.
      //
      // The same refusal `wsfed.js` gives `wreqptr` and `client_auth.js` gives
      // `jwks_uri`. Holding the position in two files and not in a third would
      // be no position at all.
      RefreshBundle: rpc.unary('server', 'TrustDomain.RefreshBundle',
                               async function (call) {
        const name = String((call.request || {}).trust_domain || '').trim()
          .toLowerCase();
        const entry = ca.federatedBundle(name);
        if (!entry) {
          errorCodes.mark(call, 'STS-SPIFFE-0061');
          throw rpc.notFound('No federation relationship with ' +
                             (name || '(none given)') + ' is configured here.');
        }
        errorCodes.mark(call, 'STS-SPIFFE-0067');
        throw rpc.statusError(status.UNIMPLEMENTED,
          'This service records a bundle endpoint URL and never fetches it. ' +
          'Fetching a URL somebody registered, to obtain a key that will ' +
          'then verify credentials, is a server-side request forgery with a ' +
          'specification citation attached — and nothing here authenticates ' +
          'the caller who registered it. The same refusal this service gives ' +
          'WS-Federation\'s wreqptr and a client\'s jwks_uri. Push the ' +
          'bundle in instead: BatchSetFederatedBundle, POST ' +
          '/admin-api/spiffe/federation-set, or the form on /admin/spiffe. ' +
          'The URL recorded for ' + name + ' is ' +
          (entry.bundleEndpointUrl || '(none)') + '.');
      })
    };
    log.debug("Leaving SpiffeApi.buildTrustDomainHandlers().");
    return trustDomainHandlers;
  }

  // ===========================================================================
  // THE DEBUG SERVICE — one method, and the cheapest health check here.
  // ===========================================================================
  buildDebugHandlers() {
    const { log, rpc, ca, spiffeId, registry } = this.deps;
    const self = this;
    log.debug("Entering SpiffeApi.buildDebugHandlers().");
    const debugHandlers = {
      GetInfo: rpc.unary('server', 'Debug.GetInfo', async function () {
        await ca.ready();
        const state = ca.state();
        const active = state.x509Authorities[0];
        return {
          // A real server reports its own SVID chain. This one has no SVID — it
          // is the CA — so it reports the CA certificate, which is the closest
          // true statement rather than an empty list that reads as a fault.
          svid_chain: active ? [{
            id: spiffeId.toProto(spiffeId.serverId(self.trustDomain())),
            expires_at: String(Math.floor(new Date(active.notAfter).getTime() /
                                          1000)),
            subject: active.subject
          }] : [],
          uptime: Math.floor((Date.now() - (state.startedAt ||
                                            Date.now())) / 1000),
          agents_count: registry.agentCount(),
          federated_bundles_count: ca.federatedBundles().length,
          entries_count: registry.entryCount()
        };
      })
    };
    log.debug("Leaving SpiffeApi.buildDebugHandlers().");
    return debugHandlers;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SpiffeApi>(
  'spiffe/spiffe_api',
  () => new SpiffeApi(SpiffeApi.defaultDeps()),
  SpiffeApi.wire,
  helpers.log);

// ===========================================================================
// THE AGENT SERVICE.
// ===========================================================================

// The join tokens this service has minted. Persisted (below), and
// SINGLE-USE — a token redeemed once is gone, which is the one property a join
// token has that makes it different from a password. Not enforcing that would
// make `CreateJoinToken` a way of issuing a permanent credential, which is
// exactly what it exists not to be.
// -------------------------------------------------------------------------
// PERSISTED, AND **PER REALM SINCE 2026-09-12** — it was `sharedMap()` with
// `scope: 'shared'`, and that was right for exactly as long as there was one
// trust domain.
//
// The old note read: *shared rather than per realm; `scope: 'shared'` is what
// says the store deliberately has no realm in it, which is the discriminator
// `tests/realm_isolation.js` checks against.* True when the four gRPC sockets
// all answered in the default realm, because then there was one agent
// population and one authority for them to join.
//
// **A JOIN TOKEN IS A CREDENTIAL FOR JOINING A TRUST DOMAIN, AND A TRUST
// DOMAIN IS A REALM'S NOW.** A token minted on acme's SPIRE Server API and
// redeemed on the default realm's would attest an agent into a trust domain
// nobody issued it for — and the SVID it then collects is signed by the wrong
// authority, which is the confused deputy this whole boundary exists to
// prevent. rcbj's instruction said it in one clause: *issue join tokens that
// are scoped per realm*.
//
// So it is `realms.map()`, and the discriminator is the realm the call arrived
// in — which, on these sockets, is the realm whose socket it arrived on.
// -------------------------------------------------------------------------
// SINGLE-USE SURVIVES THE RESTART NOW, and that is the point rather than a
// side effect: a join token redeemed before a restart used to become usable
// again after one, which turned the one property that makes it different
// from a password into a property it did not have.
//
// **THE STORE IS KEYED BY A DIGEST OF THE TOKEN, NOT BY THE TOKEN
// (2026-09-12).** It was keyed by the token itself, and a persisted row's KEY
// is not sealed — `persistence_minted.js` seals the body and writes the key as
// it is, into `sts_minted` and `sts_changes` — so every unspent join token sat
// in the database in the clear, one row per token. The body carried a second
// copy. Membership and the three facts about a held token are the only
// questions ever asked of this map, and a SHA-256 answers the first as well as
// the value did: `joinTokenKey()` is the one spelling, and nothing here holds
// the token after CreateJoinToken has returned it. Same argument, same shape,
// as `oid4vc/vc_offers.ts`'s deferred access tokens.
const joinTokens = realms.map({ persist: 'spiffe.joinTokens' });

// ===========================================================================
// WHAT THIS SURFACE IMPLEMENTS, for the pages that describe it.
//
// `implemented: false` is a claim with a reason attached, and there are six of
// them. A table that said forty-two of forty-two would be the most misleading
// thing in this repository — the same rule `sts_metadata.js`'s coverage notes
// follow, and the same rule that makes `oauth2_bcp.js` publish `enforced: 'no'`
// rows rather than omitting them.
// ===========================================================================
// The methods that answer `Unimplemented`, each with the reason it does —
// published on `GET /spiffe` and on the console, because a table reporting
// forty-two of forty-two would be the most misleading thing in this repository.
//
// **`Agent.RenewAgent` USED TO BE IN HERE AND IS NOT ANY MORE.** Its reason was
// that nothing authenticated the caller, so there was no way to know which
// agent to renew; mutual TLS on the SPIRE Server API answered that, and the
// method now renews the agent on the connection. It still refuses, with the
// same argument, where nothing identifies the caller — see the handler.
const NOT_IMPLEMENTED = {
  'Bundle.AppendBundle':
    'It would publish an authority this server holds no key for, which every ' +
    'workload in the trust domain would then trust. Rotate instead.',
  'Bundle.PublishJWTAuthority':
    'The same reason as AppendBundle.',
  'Bundle.PublishWITAuthority':
    'This service issues no WIT-SVIDs.',
  'SVID.MintWITSVID':
    'This service issues no WIT-SVIDs.',
  'SVID.BatchNewWITSVID':
    'This service issues no WIT-SVIDs.',
  'TrustDomain.RefreshBundle':
    'This service records a bundle endpoint URL and never fetches it — the ' +
    'same refusal it gives wreqptr and jwks_uri. Push the bundle in instead.'
};

// The six services, in the order the surface is published. The handlers of
// each are built by `SpiffeApi.wire()` when the instance is installed (#50,
// R2), which joins them into `SERVICE_HANDLERS` with these rows.
const SERVICE_ROWS = [
  { name: 'entry', label: 'Entry',
    what: 'Registration entries: what identity a workload gets, under which ' +
          'parent, matching which selectors. The store is the LDAP directory ' +
          'under ou=entries,ou=spiffe, so an ldapmodify and a ' +
          'BatchUpdateEntry are two doors onto one entry.' },
  { name: 'agent', label: 'Agent',
    what: 'Attesting, listing, banning and join tokens. NODE ATTESTATION IS ' +
          'VERIFIED OR REFUSED: an agent\'s type must be one the realm ' +
          'accepts (spiffe.nodeAttestors) and one an attestor here verifies. ' +
          'The CSR is real, a join token is single-use, evidence that is not ' +
          're-attestable attests once, and a ban is enforced.' },
  { name: 'bundle', label: 'Bundle',
    what: 'This trust domain\'s bundle, and every federated one. Appending ' +
          'to this trust domain\'s own is refused with a reason; federated ' +
          'bundles are accepted from a caller and never fetched.' },
  { name: 'svid', label: 'SVID',
    what: 'Minting on demand and signing an agent\'s CSRs. Only the public ' +
          'key is read out of a CSR except at MintX509SVID, where there is ' +
          'no entry to take the identity from and the CSR is the only ' +
          'statement of what is wanted.' },
  { name: 'trustdomain', label: 'TrustDomain',
    what: 'Federation relationships: which trust domain, which bundle ' +
          'endpoint, which profile. RefreshBundle is refused — see its ' +
          'message.' },
  { name: 'debug', label: 'Debug',
    what: 'GetInfo: uptime, and how many entries, agents and federated ' +
          'bundles this server holds. The cheapest health check here.' }
];

// Every service with its handlers, built by `SpiffeApi.wire()`.
let SERVICE_HANDLERS: Array<{ name: string; label: string; handlers: any;
                              what: string }> | null = null;

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  SpiffeApi: SpiffeApi,
  installInstance: (instance: SpiffeApi): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // Built by `SpiffeApi.wire()`, so read once the instance exists.
  get SERVICE_HANDLERS(): Array<{ name: string; label: string;
                                  handlers: any; what: string }> {
    log.debug("Entering SERVICE_HANDLERS().");
    slot.get();
    log.debug("Leaving SERVICE_HANDLERS().");
    return SERVICE_HANDLERS;
  },
  NOT_IMPLEMENTED: NOT_IMPLEMENTED,
  // Exported so the console can show what a join token is worth without a
  // second store — the one-store rule, applied to something that never reaches
  // the directory because a credential does not belong in one.
  joinTokens: joinTokens,
  entryToProto: slot.forward('entryToProto'),
  entryFromProto: slot.forward('entryFromProto'),
  nodeAttestationState: slot.forward('nodeAttestationState')
};
