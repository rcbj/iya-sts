'use strict';
//
// File: spiffe_broker.ts
//
// ---------------------------------------------------------------------------
// THE SPIFFE BROKER API (#170, 2026-09-23 — decision 1 on the issue).
//
// `spiffe/standards/SPIFFE_Broker_API.md` and `SPIFFE_Broker_Endpoint.md`
// (both "Incubating"), and `brokerapi.proto` (service `spiffe.broker.API`,
// vendored verbatim in `protos/`): a BROKER — a node proxy, a service mesh's
// per-node component — authenticates with its own X509-SVID and asks for the
// SVIDs and bundles of a workload it REFERENCES, which this service attests
// itself. The issue called it `AttestReference`, which is the name of the
// SPIRE workload-attestor plugin call behind it; the RPCs a broker calls are
// the four the current draft defines:
//
//   SubscribeToX509SVID     a stream of the referenced workload's X509-SVIDs
//   SubscribeToX509Bundles  a stream of the X.509 bundles
//   FetchJWTSVID            the workload's JWT-SVIDs for an audience
//   SubscribeToJWTBundles   a stream of the JWT bundles
//
// WHO MAY CALL is `spiffe_grpc.ts`'s `prepareBrokerCall()` — the header, the
// SVID, `spiffe.brokers` — and this file starts with an authorized broker.
//
// A REFERENCE (sections 3.1 and 4.8), in SPIRE's order
// (`pkg/agent/broker/api/service.go`):
//
//   1. no reference, or an empty type URL: INVALID_ARGUMENT,
//      WORKLOAD_REFERENCE_INVALID (STS-SPIFFE-0136) — before the allow list,
//      so a malformed request is not answered PERMISSION_DENIED;
//   2. a type the broker's entry in `spiffe.brokers` does not allow:
//      PERMISSION_DENIED (STS-SPIFFE-0135);
//   3. the reference resolved and ATTESTED HERE (section 3.1.1: "Servers MUST
//      NOT trust reference data provided by the client without independent
//      verification"):
//        * `WorkloadPIDReference` — a positive pid, opened with a pidfd
//          (`spiffe_peer.observePid()`), and run through the SAME workload
//          attestors the Workload API's socket uses (`spiffe.workloadAttestors`
//          — unix, docker, k8s, systemd), which is SPIRE's host falling back
//          to `Attest` for a pid;
//        * `KubernetesObjectReference` to `pods`/`core` — by UID, or by
//          namespace and name (both: the UID must match) — resolved in this
//          node's kubelet pod list by the `k8s` attestor
//          (`attestPodReference()`), SPIRE's `agent_node` scope; any other
//          resource is INVALID_ARGUMENT, because resolving arbitrary objects
//          needs the API server, which is not implemented here;
//        * anything else: INVALID_ARGUMENT (section 3.1.4).
//      A pid or pod that does not exist is NOT_FOUND, WORKLOAD_NOT_FOUND
//      (STS-SPIFFE-0137); one that cannot be attested UNAVAILABLE
//      (STS-SPIFFE-0139);
//   4. the registration entries the attested selectors match — ALWAYS
//      narrowed, never invented, never an admin or downstream entry
//      (`spiffe_workload.ts`'s `entitledEntries()` for a brokered caller) —
//      and none is PERMISSION_DENIED, WORKLOAD_NOT_ENTITLED
//      (STS-SPIFFE-0138). The bundle subscriptions ask only that the
//      reference resolves, as SPIRE's do.
//
// Every refusal of section 4.8 carries a `google.rpc.Status` in
// `grpc-status-details-bin` with a `google.rpc.ErrorInfo` (domain
// `spiffe.io`, the reason above) — encoded here by hand, because the two
// messages are three fields each and protobufjs is not a dependency of this
// service.
//
// A STREAM ENDS WHEN ITS WORKLOAD DOES (section 4.9): before every re-send the
// reference is asked again — the process's pidfd still alive and its start
// time and executable unchanged, the pod still on the node with that UID —
// and a workload that has stopped ends the stream NOT_FOUND
// (STS-SPIFFE-0137), so nothing is sent for it again. A workload that has
// lost every entry ends it PERMISSION_DENIED. The re-sends are the Workload
// API's rotation timer (`pushOnRotation()`), so a stopped workload is noticed
// at the next rotation rather than the instant it stops.
//
// HINTS are unique within a response (sections 5.2.1 and 6.2.1): the first
// SVID with a hint keeps it and a later one with the same hint is dropped,
// SPIRE's `hintsfilter`.
//
// NOT DONE, AND SAID: gRPC server reflection (the Endpoint's SHOULD); SPIRE's
// `cluster` pod-reference scope and its Kubernetes SubjectAccessReview
// impersonation check; references to Kubernetes objects other than pods.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log } = helpers;
import errorCodes = require('../common/error_codes');
import rpc = require('./spiffe_grpc');
import workload = require('./spiffe_workload');
import ca = require('./spiffe_ca');
import spiffeId = require('./spiffe_id');
import peer = require('./spiffe_peer');

const PID_REFERENCE =
  'type.googleapis.com/spiffe.broker.WorkloadPIDReference';
const K8S_REFERENCE =
  'type.googleapis.com/spiffe.broker.KubernetesObjectReference';
const ERROR_INFO = 'type.googleapis.com/google.rpc.ErrorInfo';
// A Kubernetes UID: a UUID string.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// One decoded reference.
interface Reference {
  type: 'pid' | 'k8s';
  typeUrl: string;
  pid?: number;
  pod?: { uid: string; namespace: string; name: string };
}

// What a resolved reference is: its selectors, a question asked before each
// re-send, and what to give back when the stream ends.
interface Resolved {
  selectors: Array<{ type: string; value: string }>;
  gone(): Promise<string>;
  release(): void;
  describe: string;
}

interface BrokerDeps {
  log: typeof log;
  errorCodes: typeof errorCodes;
  rpc: typeof rpc;
  workload: typeof workload;
  ca: typeof ca;
  spiffeId: typeof spiffeId;
  peer: typeof peer;
  // The workload attestation table (`spiffe_server.ts` builds it).
  attestation(): any;
}

// ---------------------------------------------------------------------------
// THE PROTOBUF WIRE FORMAT, AS FAR AS THE REFERENCES AND google.rpc NEED IT —
// a static utility class, the code style's shape for small helpers.
// ---------------------------------------------------------------------------
class ProtoWire {
  // A varint at `at`: `{ value: bigint, next }`; throws on a truncated one.
  static varint(buf: Buffer, at: number): { value: bigint; next: number } {
    helpers.log.debug("Entering ProtoWire.varint().");
    let value = BigInt(0);
    let shift = BigInt(0);
    for (let i = at; i < buf.length && i < at + 10; i++) {
      value |= BigInt(buf[i] & 0x7f) << shift;
      shift += BigInt(7);
      if (!(buf[i] & 0x80)) {
        helpers.log.debug("Leaving ProtoWire.varint().");
        return { value: value, next: i + 1 };
      }
    }
    helpers.log.debug("Leaving ProtoWire.varint(). Truncated.");
    // error-code: none — a parse failure, refused by the caller as 0136
    throw new Error('a truncated varint');
  }

  // Every field of a message: `[{ no, wire, int?, bytes? }]`; throws.
  static fields(buf: Buffer): Array<{ no: number; wire: number;
                                      int?: bigint; bytes?: Buffer }> {
    helpers.log.debug("Entering ProtoWire.fields().");
    const out = [];
    let at = 0;
    while (at < buf.length) {
      const key = ProtoWire.varint(buf, at);
      at = key.next;
      const no = Number(key.value >> BigInt(3));
      const wire = Number(key.value & BigInt(7));
      if (wire === 0) {
        const v = ProtoWire.varint(buf, at);
        at = v.next;
        out.push({ no: no, wire: wire, int: v.value });
      } else if (wire === 2) {
        const len = ProtoWire.varint(buf, at);
        const end = len.next + Number(len.value);
        if (end > buf.length) {
          helpers.log.debug("Leaving ProtoWire.fields(). Truncated.");
          // error-code: none — a parse failure, refused by the caller
          throw new Error('a truncated length-delimited field');
        }
        out.push({ no: no, wire: wire, bytes: buf.subarray(len.next, end) });
        at = end;
      } else if (wire === 1 || wire === 5) {
        at += wire === 1 ? 8 : 4;
        if (at > buf.length) {
          helpers.log.debug("Leaving ProtoWire.fields(). Truncated.");
          // error-code: none — a parse failure, refused by the caller
          throw new Error('a truncated fixed-width field');
        }
      } else {
        helpers.log.debug("Leaving ProtoWire.fields(). Wire type.");
        // error-code: none — a parse failure, refused by the caller
        throw new Error('an unsupported wire type ' + wire);
      }
    }
    helpers.log.debug("Leaving ProtoWire.fields(). " + out.length);
    return out;
  }

  // The last value of string field `no`, as proto3 reads a repeated scalar
  // it expected once; '' when absent.
  static text(fields: any[], no: number): string {
    helpers.log.debug("Entering ProtoWire.text(). " + no);
    const found = fields.filter(function (f) {
      return f.no === no && f.wire === 2;
    }).pop();
    helpers.log.debug("Leaving ProtoWire.text().");
    return found ? Buffer.from(found.bytes).toString('utf8') : '';
  }

  // A sub-message field, or null.
  static message(fields: any[], no: number): Buffer | null {
    helpers.log.debug("Entering ProtoWire.message(). " + no);
    const found = fields.filter(function (f) {
      return f.no === no && f.wire === 2;
    }).pop();
    helpers.log.debug("Leaving ProtoWire.message().");
    return found ? Buffer.from(found.bytes) : null;
  }

  // Encoders: a varint, a tagged varint, a tagged length-delimited field.
  static encodeVarint(n: number): Buffer {
    helpers.log.debug("Entering ProtoWire.encodeVarint().");
    const out = [];
    let v = BigInt.asUintN(64, BigInt(n));
    do {
      let byte = Number(v & BigInt(0x7f));
      v >>= BigInt(7);
      if (v > BigInt(0)) byte |= 0x80;
      out.push(byte);
    } while (v > BigInt(0));
    helpers.log.debug("Leaving ProtoWire.encodeVarint().");
    return Buffer.from(out);
  }

  static intField(no: number, n: number): Buffer {
    helpers.log.debug("Entering ProtoWire.intField().");
    helpers.log.debug("Leaving ProtoWire.intField().");
    return Buffer.concat([ProtoWire.encodeVarint(no << 3),
                          ProtoWire.encodeVarint(n)]);
  }

  static bytesField(no: number, bytes: Buffer | string): Buffer {
    helpers.log.debug("Entering ProtoWire.bytesField().");
    const body = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8');
    helpers.log.debug("Leaving ProtoWire.bytesField().");
    return Buffer.concat([ProtoWire.encodeVarint((no << 3) | 2),
                          ProtoWire.encodeVarint(body.length), body]);
  }
}

class SpiffeBroker {
  constructor(private readonly deps: BrokerDeps) {
    deps.log.debug("Entering SpiffeBroker.constructor().");
    deps.log.debug("Leaving SpiffeBroker.constructor().");
  }

  static defaultDeps(attestation: () => any): BrokerDeps {
    helpers.log.debug("Entering SpiffeBroker.defaultDeps().");
    helpers.log.debug("Leaving SpiffeBroker.defaultDeps().");
    return { log: log, errorCodes: errorCodes, rpc: rpc, workload: workload,
             ca: ca, spiffeId: spiffeId, peer: peer,
             attestation: attestation };
  }

  // A status error carrying section 4.8's google.rpc.ErrorInfo. `call` is
  // marked with the code the audit row records.
  refusal(call: any, code: string, status: number, message: string,
          reason: string, metadata?: Record<string, string>): Error {
    const { log, errorCodes, rpc } = this.deps;
    log.debug("Entering SpiffeBroker.refusal(). " + code);
    errorCodes.mark(call, code);
    // error-code: none — marked on the line above with the caller's code
    const err: any = rpc.statusError(status, message);
    if (reason) {
      const meta = metadata || {};
      const info = Buffer.concat([
        ProtoWire.bytesField(1, reason), ProtoWire.bytesField(2, 'spiffe.io')
      ].concat(Object.keys(meta).map(function (key) {
        return ProtoWire.bytesField(3, Buffer.concat([
          ProtoWire.bytesField(1, key), ProtoWire.bytesField(2, meta[key])]));
      })));
      const any = Buffer.concat([ProtoWire.bytesField(1, ERROR_INFO),
                                 ProtoWire.bytesField(2, info)]);
      const statusBytes = Buffer.concat([ProtoWire.intField(1, status),
                                         ProtoWire.bytesField(2, message),
                                         ProtoWire.bytesField(3, any)]);
      const md = new rpc.grpc.Metadata();
      md.set('grpc-status-details-bin', statusBytes);
      err.metadata = md;
    }
    log.debug("Leaving SpiffeBroker.refusal().");
    // error-code: none — the constructor; the code is marked on the call
    return err;
  }

  // STEPS 1 AND 3's parsing: the request's `reference` as a Reference, or a
  // thrown INVALID_ARGUMENT.
  decodeReference(call: any): Reference {
    const { log, rpc } = this.deps;
    const self = this;
    log.debug("Entering SpiffeBroker.decodeReference().");
    const wrapper = ((call.request || {}).reference) || null;
    const any = wrapper ? wrapper.reference : null;
    const typeUrl = String((any && any.type_url) || '');
    const invalid = function (why: string): Error {
      log.debug("Entering invalid().");
      log.debug("Leaving invalid().");
      return self.refusal(call, 'STS-SPIFFE-0136',
                          rpc.grpc.status.INVALID_ARGUMENT, why,
                          'WORKLOAD_REFERENCE_INVALID');
    };
    if (!typeUrl) {
      log.debug("Leaving SpiffeBroker.decodeReference(). None.");
      throw invalid('workload reference must be provided');
    }
    const value = Buffer.from((any && any.value) || []);
    let fields = null;
    try {
      fields = ProtoWire.fields(value);
    } catch (e) {
      log.debug("Caught in SpiffeBroker.decodeReference(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpiffeBroker.decodeReference(). Unreadable.");
      throw invalid('unable to unmarshal the reference: ' +
                    ((e && e.message) || e));
    }
    if (typeUrl === PID_REFERENCE) {
      const pidField = fields.filter(function (f) {
        return f.no === 1 && f.wire === 0;
      }).pop();
      const pid = pidField ? Number(BigInt.asIntN(32, pidField.int)) : 0;
      if (!(pid > 0)) {
        log.debug("Leaving SpiffeBroker.decodeReference(). A bad pid.");
        throw invalid('the process id of a WorkloadPIDReference MUST be a ' +
                      'positive integer');
      }
      log.debug("Leaving SpiffeBroker.decodeReference(). pid " + pid);
      return { type: 'pid', typeUrl: typeUrl, pid: pid };
    }
    if (typeUrl === K8S_REFERENCE) {
      const typeMessage = ProtoWire.message(fields, 1);
      const keyMessage = ProtoWire.message(fields, 2);
      let type = null;
      let key = null;
      try {
        type = typeMessage ? ProtoWire.fields(typeMessage) : null;
        key = keyMessage ? ProtoWire.fields(keyMessage) : null;
      } catch (e) {
        log.debug("Caught in SpiffeBroker.decodeReference(): " +
                  ((e && e.message) || e));
        throw invalid('unable to unmarshal object reference');
      }
      const uid = ProtoWire.text(fields, 3);
      // SPIRE's validateKubernetesObjectReference().
      if (!type) {
        throw invalid('object reference is missing type');
      }
      const plural = ProtoWire.text(type, 1);
      const group = ProtoWire.text(type, 2);
      if (!plural) {
        throw invalid('object reference type is missing plural');
      }
      if (!group) {
        throw invalid('object reference type is missing group');
      }
      if (!key && !uid) {
        throw invalid('object reference is missing key and UID');
      }
      const name = key ? ProtoWire.text(key, 2) : '';
      const namespace = key ? ProtoWire.text(key, 1) : '';
      if (key && !name) {
        throw invalid('object reference key is missing name');
      }
      if (plural !== 'pods' || group !== 'core') {
        throw invalid('only pods (plural "pods", group "core") are ' +
                      'resolved here; ' + plural + '.' + group + ' needs ' +
                      'the Kubernetes API server, which this service does ' +
                      'not ask');
      }
      if (name && !namespace) {
        throw invalid('namespace is required when name is set for a ' +
                      'namespaced resource');
      }
      if (uid && !UUID.test(uid)) {
        throw invalid('the uid MUST be a valid UUID string as assigned by ' +
                      'Kubernetes');
      }
      log.debug("Leaving SpiffeBroker.decodeReference(). A pod.");
      return { type: 'k8s', typeUrl: typeUrl,
               pod: { uid: uid, namespace: namespace, name: name } };
    }
    log.debug("Leaving SpiffeBroker.decodeReference(). Unknown type.");
    throw invalid('unsupported reference type: ' + typeUrl);
  }

  // STEP 2: may this broker use this kind of reference? Throws.
  authorizeType(call: any, typeUrl: string, type: string): void {
    const { log, rpc } = this.deps;
    log.debug("Entering SpiffeBroker.authorizeType(). " + type);
    const broker = (call.spiffeCaller || {}).broker || { id: '', types: [] };
    if (broker.types.indexOf('*') >= 0 ||
        (type && broker.types.indexOf(type) >= 0)) {
      log.debug("Leaving SpiffeBroker.authorizeType().");
      return;
    }
    log.debug("Leaving SpiffeBroker.authorizeType(). Refused.");
    throw this.refusal(call, 'STS-SPIFFE-0135',
                       rpc.grpc.status.PERMISSION_DENIED,
                       'broker "' + broker.id + '" is not allowed to use ' +
                       'reference type "' + typeUrl + '"', '');
  }

  // STEP 3: the reference attested. Throws NOT_FOUND or UNAVAILABLE.
  async resolve(call: any, ref: Reference): Promise<Resolved> {
    const { log, rpc, peer, attestation } = this.deps;
    const self = this;
    log.debug("Entering SpiffeBroker.resolve(). " + ref.type);
    const table = attestation();
    const notAttested = function (why: string): Error {
      log.debug("Entering notAttested().");
      log.debug("Leaving notAttested().");
      return self.refusal(call, 'STS-SPIFFE-0139',
                          rpc.grpc.status.UNAVAILABLE,
                          'workload attestation failed: ' + why, '');
    };
    if (ref.type === 'pid') {
      const facts = peer.observePid(ref.pid);
      if ((facts as any).missing) {
        log.debug("Leaving SpiffeBroker.resolve(). No such process.");
        throw this.refusal(call, 'STS-SPIFFE-0137',
                           rpc.grpc.status.NOT_FOUND,
                           'the referenced process ' + ref.pid + ' does not ' +
                           'exist', 'WORKLOAD_NOT_FOUND',
                           { pid: String(ref.pid) });
      }
      if (facts.error) {
        peer.release(facts);
        log.debug("Leaving SpiffeBroker.resolve(). Not attestable.");
        throw notAttested(facts.error);
      }
      let selectors = [];
      try {
        selectors = await table.attest(facts);
      } catch (e) {
        log.debug("Caught in SpiffeBroker.resolve(): " +
                  ((e && e.message) || e));
        peer.release(facts);
        log.debug("Leaving SpiffeBroker.resolve(). An attestor failed.");
        throw notAttested(String((e && e.message) || e));
      }
      // Still the process the pid named when it was opened.
      const changed = peer.stillValid(facts);
      if (changed) {
        peer.release(facts);
        log.debug("Leaving SpiffeBroker.resolve(). It changed.");
        throw this.refusal(call, 'STS-SPIFFE-0137',
                           rpc.grpc.status.NOT_FOUND,
                           'the referenced process ' + ref.pid + ' is gone: ' +
                           changed, 'WORKLOAD_NOT_FOUND',
                           { pid: String(ref.pid) });
      }
      log.debug("Leaving SpiffeBroker.resolve(). pid " + ref.pid);
      return {
        selectors: selectors, describe: 'pid ' + ref.pid,
        gone: function () {
          log.debug("Entering gone().");
          log.debug("Leaving gone().");
          return Promise.resolve(peer.stillValid(facts));
        },
        release: function () {
          log.debug("Entering release().");
          peer.release(facts);
          log.debug("Leaving release().");
        }
      };
    }
    const k8s = table.attestor('k8s');
    if (!k8s || table.enabled().indexOf('k8s') < 0) {
      log.debug("Leaving SpiffeBroker.resolve(). No k8s attestor.");
      throw notAttested('a pod reference is attested by the k8s workload ' +
                        'attestor, which spiffe.workloadAttestors does not ' +
                        'name');
    }
    let found = null;
    try {
      found = await k8s.attestPodReference(ref.pod);
    } catch (e) {
      log.debug("Caught in SpiffeBroker.resolve(): " + ((e && e.message) || e));
      log.debug("Leaving SpiffeBroker.resolve(). The kubelet failed.");
      throw notAttested(String((e && e.message) || e));
    }
    if (!found.found) {
      log.debug("Leaving SpiffeBroker.resolve(). No such pod.");
      throw this.refusal(call, 'STS-SPIFFE-0137', rpc.grpc.status.NOT_FOUND,
                         found.why, 'WORKLOAD_NOT_FOUND',
                         ref.pod.uid ? { uid: ref.pod.uid } : {});
    }
    const uid = String((found.pod.metadata || {}).uid || '');
    log.debug("Leaving SpiffeBroker.resolve(). pod " + uid);
    return {
      selectors: found.values.map(function (value) {
        return { type: 'k8s', value: value };
      }),
      describe: 'pod ' + uid,
      gone: function () {
        log.debug("Entering gone().");
        log.debug("Leaving gone().");
        return k8s.attestPodReference({ uid: uid, namespace: '', name: '' })
          .then(function (again) {
            return again.found ? '' : again.why;
          }, function (e) {
            // A kubelet that cannot be read is not proof the pod has gone:
            // the next rotation asks again.
            log.debug("Caught in gone(): " + ((e && e.message) || e));
            return '';
          });
      },
      release: function () {
        log.debug("Entering release().");
        log.debug("Leaving release().");
      }
    };
  }

  // Steps 1–3 for one call, with the caller the entitlement is asked for.
  // The allow list is asked of the TYPE URL before the reference's value is
  // read, as SPIRE's `authorizeReferenceType()` is: a broker allowed neither
  // kind is refused PERMISSION_DENIED for a malformed pid too, and a type
  // nobody knows is refused by the allow list unless the broker has `*`.
  async referenced(call: any): Promise<{ resolved: Resolved; caller: any }> {
    const { log, rpc } = this.deps;
    log.debug("Entering SpiffeBroker.referenced().");
    const wrapper = ((call.request || {}).reference) || null;
    const typeUrl = String(((wrapper && wrapper.reference) || {}).type_url ||
                           '');
    if (!typeUrl) {
      log.debug("Leaving SpiffeBroker.referenced(). No reference.");
      throw this.refusal(call, 'STS-SPIFFE-0136',
                         rpc.grpc.status.INVALID_ARGUMENT,
                         'workload reference must be provided',
                         'WORKLOAD_REFERENCE_INVALID');
    }
    this.authorizeType(call, typeUrl, typeUrl === PID_REFERENCE ? 'pid'
      : typeUrl === K8S_REFERENCE ? 'k8s' : '');
    const ref = this.decodeReference(call);
    const resolved = await this.resolve(call, ref);
    const broker = (call.spiffeCaller || {}).broker || {};
    log.debug("Leaving SpiffeBroker.referenced(). " + resolved.describe);
    return { resolved: resolved,
             caller: { brokered: true, brokerId: broker.id || '',
                       selectors: resolved.selectors } };
  }

  // SPIRE's hintsfilter: the first of each non-empty hint.
  uniqueHints(svids: any[]): any[] {
    const { log } = this.deps;
    log.debug("Entering SpiffeBroker.uniqueHints().");
    const seen = {};
    const out = svids.filter(function (one) {
      const hint = String((one && one.hint) || '');
      if (!hint) return true;
      if (seen[hint]) return false;
      seen[hint] = true;
      return true;
    });
    log.debug("Leaving SpiffeBroker.uniqueHints().");
    return out;
  }

  notEntitled(call: any, resolved: Resolved): Error {
    const { log, rpc } = this.deps;
    log.debug("Entering SpiffeBroker.notEntitled().");
    log.debug("Leaving SpiffeBroker.notEntitled().");
    return this.refusal(call, 'STS-SPIFFE-0138',
                        rpc.grpc.status.PERMISSION_DENIED,
                        'no identity issued: the referenced ' +
                        resolved.describe + ' is not entitled to an SVID',
                        'WORKLOAD_NOT_ENTITLED');
  }

  // A stream's end when the call closes, whichever way, once.
  releaseOnClose(call: any, resolved: Resolved): void {
    const { log } = this.deps;
    log.debug("Entering SpiffeBroker.releaseOnClose().");
    let done = false;
    const once = function () {
      if (done) return;
      done = true;
      resolved.release();
    };
    ['cancelled', 'error', 'finish', 'close'].forEach(function (event) {
      call.on(event, once);
    });
    log.debug("Leaving SpiffeBroker.releaseOnClose().");
  }

  // THE RE-SEND for a stream: `build()` unless the workload has stopped,
  // which ends the stream (section 4.9) and answers null so the rotation
  // timer stops.
  resend(call: any, resolved: Resolved, end: (err: Error) => void,
         build: () => Promise<any>): () => Promise<any> {
    const { log, rpc } = this.deps;
    const self = this;
    log.debug("Entering SpiffeBroker.resend().");
    log.debug("Leaving SpiffeBroker.resend().");
    return function () {
      log.debug("Entering resend().");
      return resolved.gone().then(function (why) {
        if (why) {
          end(self.refusal(call, 'STS-SPIFFE-0137',
                           rpc.grpc.status.NOT_FOUND,
                           'the referenced ' + resolved.describe +
                           ' has stopped: ' + why, 'WORKLOAD_NOT_FOUND'));
          log.debug("Leaving resend(). The workload stopped.");
          return null;
        }
        log.debug("Leaving resend().");
        return build();
      });
    };
  }

  // The four handlers, wrapped by `spiffe_grpc.ts` for the `broker` surface.
  handlers(): Record<string, any> {
    const { log, rpc, workload, ca, spiffeId, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering SpiffeBroker.handlers().");
    const subscribeX509Svid = rpc.serverStream('broker', 'SubscribeToX509SVID',
      async function (call, push, end) {
        await ca.ready();
        const ref = await self.referenced(call);
        const observed = { shortest: 0 };
        const build = async function () {
          log.debug("Entering build().");
          const answer = await workload.buildX509Response(ref.caller,
                                                          observed);
          answer.svids = self.uniqueHints(answer.svids);
          if (!answer.svids.length) {
            end(self.notEntitled(call, ref.resolved));
            log.debug("Leaving build(). Not entitled.");
            return null;
          }
          log.debug("Leaving build().");
          return answer;
        };
        let first = null;
        try {
          first = await workload.buildX509Response(ref.caller, observed);
        } catch (e) {
          log.debug("Caught in SubscribeToX509SVID: " +
                    ((e && e.message) || e));
          ref.resolved.release();
          throw e;
        }
        first.svids = self.uniqueHints(first.svids);
        if (!first.svids.length) {
          ref.resolved.release();
          throw self.notEntitled(call, ref.resolved);
        }
        self.releaseOnClose(call, ref.resolved);
        workload.pushOnRotation(push, self.resend(call, ref.resolved, end,
                                                  build),
                                'SubscribeToX509SVID',
                                function () { return observed.shortest; });
        return first;
      });
    const subscribeX509Bundles = rpc.serverStream('broker',
      'SubscribeToX509Bundles', async function (call, push, end) {
        await ca.ready();
        const ref = await self.referenced(call);
        self.releaseOnClose(call, ref.resolved);
        workload.pushOnRotation(push, self.resend(call, ref.resolved, end,
          function () {
            return workload.buildX509BundlesResponse();
          }), 'SubscribeToX509Bundles');
        return await workload.buildX509BundlesResponse();
      });
    const fetchJwtSvid = rpc.unary('broker', 'FetchJWTSVID',
      async function (call) {
        await ca.ready();
        const request = call.request || {};
        const audiences = (request.audience || []).map(function (a) {
          return String(a || '').trim();
        }).filter(Boolean);
        if (!audiences.length) {
          errorCodes.mark(call, 'STS-SPIFFE-0027');
          throw rpc.invalidArgument('audience must be specified');
        }
        const wanted = String(request.spiffe_id || '').trim();
        let parsed = null;
        if (wanted) {
          parsed = spiffeId.parse(wanted);
          if (!parsed.ok) {
            errorCodes.mark(call, 'STS-SPIFFE-0028');
            throw rpc.invalidArgument('invalid requested SPIFFE ID: ' +
                                      parsed.reason);
          }
        }
        const ref = await self.referenced(call);
        try {
          let entries = workload.entitledEntries(ref.caller);
          if (parsed) {
            entries = entries.filter(function (entry) {
              return entry.spiffeId === parsed.id;
            });
          }
          if (!entries.length) {
            throw self.notEntitled(call, ref.resolved);
          }
          const svids = await workload.issueJwtSvids(entries, audiences,
                                                     ref.caller);
          return { svids: self.uniqueHints(svids) };
        } finally {
          ref.resolved.release();
        }
      });
    const subscribeJwtBundles = rpc.serverStream('broker',
      'SubscribeToJWTBundles', async function (call, push, end) {
        await ca.ready();
        const ref = await self.referenced(call);
        self.releaseOnClose(call, ref.resolved);
        workload.pushOnRotation(push, self.resend(call, ref.resolved, end,
          function () {
            return workload.buildJwtBundlesResponse();
          }), 'SubscribeToJWTBundles');
        return await workload.buildJwtBundlesResponse();
      });
    log.debug("Leaving SpiffeBroker.handlers().");
    return {
      SubscribeToX509SVID: subscribeX509Svid,
      SubscribeToX509Bundles: subscribeX509Bundles,
      FetchJWTSVID: fetchJwtSvid,
      SubscribeToJWTBundles: subscribeJwtBundles
    };
  }
}

export = {
  SpiffeBroker: SpiffeBroker,
  ProtoWire: ProtoWire,
  PID_REFERENCE: PID_REFERENCE,
  K8S_REFERENCE: K8S_REFERENCE
};
