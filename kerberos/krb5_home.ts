// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: krb5_home.ts
//
// ---------------------------------------------------------------------------
// A KERBEROS REQUEST OVER MS-KKDCP IS ANSWERED IN ITS CLIENT'S HOME CELL (#98
// D2, D10, 2026-09-28).
//
// A person is homed in one cell (`common/cells.ts`), and everything a KDC
// consults about them is there: their long-term keys (sealed on their entry,
// `krb5_person_keys.ts`), whether the account is disabled, their second
// factor, the PAC's facts, and the sign-out instant a TGS-REQ is refused on
// (`signedOutAt`, a field of the CELL-tier `krb5.principals` row —
// `persistence/tiers.js`). So a request whose client is homed elsewhere is
// sent there WHOLE, over the inter-cell channel, and that cell's KDC answers
// it; the reply is piped back untouched. This is §5's "Kerberos AS-REQ …
// forwarded the same way" — the request travels, the person's data does not.
//
// **`krb5_kdc.js` IS IN THE PARENT'S COPY SET** (this repository's own, but
// the parent's tests image copies it and its requires; `kerberos/CLAUDE.md`),
// so rather than grow its closure this is a route of its own, registered on
// `POST /KdcProxy` JUST BEFORE the KDC's (`common/protocol_stack.ts`), that
// decodes just enough to find the client and either relays the request or
// calls `next()` — after which the KDC's own handler runs exactly as it
// always did. It REQUIRES the vendored codec
// (`krb5_messages`, `krb5_asn1`, `krb5_primitives`, `krb5_crypto`) and the
// principal database; it edits none of them, and none of them requires it, so
// the parent project's COPY closure does not move.
//
// **WHO THE CLIENT IS, PER MESSAGE:**
//
//   * **AS-REQ** — the `cname` in the request body, in the Kerberos realm the
//     body names. A FAST-armored AS-REQ is routed by its OUTER body: the inner
//     one cannot be read before the armor key is, and every client this KDC
//     is tested against copies the body into the armor (RFC 6113 section
//     5.4.2 lets the outer body be anything; a client that sends a different
//     cname outside is answered by the cell the outer name is homed in).
//   * **TGS-REQ** — the client of the TICKET, which is inside its encrypted
//     part. The krbtgt key is on an APPLICATION entry (`krbtgt/<REALM>`,
//     #169), which is the global tier, so every cell can open a TGT and read
//     its `cname` — and does, here, only to route. It is served AT HOME and
//     not wherever it arrives, although every cell could decrypt it, because
//     what a TGS exchange decides on is the home cell's: the sign-out instant
//     (a TGT stamped signed out at home would be honoured by a cell that
//     never heard of the stamp), the disabled account, and the person the PAC
//     describes. An S4U2Self request (PA-FOR-USER) is routed by the USER it
//     names rather than by the service asking, for the same reason.
//   * Anything else — a cross-realm ticket, a service's own ticket, a name
//     with more than one component, a message that does not decode — is
//     answered where it arrived, by the KDC, in its own words.
//
// **AND THE RAW SOCKETS ON TCP AND UDP 88 (#588, 2026-10-12).** Until this
// date they were not placed: `krb5_kdc.js` handed each message straight to
// its own answer, so a traveller whose `krb5.conf` names port 88 and whose
// packets reached a visiting cell was answered THERE — an unknown principal in
// product, a freshly made one in development. The KDC now asks a MESSAGE
// ROUTER before it answers (`setMessageRouter()`), and `install()` below
// fills it with `routeMessage()`, which makes the SAME decision this route
// makes — `clientOf()`, then the routing index — so the two doors cannot
// disagree about where a person is answered. A request for somebody homed
// elsewhere is the inter-cell operation `kdc-message`: its bytes, the
// transport and the client's address as this cell saw it, answered at home by
// `answerRelayed()` through the KDC's `answerMessage()` — the code its own
// sockets run — and the reply's bytes and refusal sent back. This cell's
// socket then writes it exactly as one it made: the TCP length prefix, and on
// UDP RFC 4120 section 7.2.1's size limit, so an oversized relayed reply is
// KRB_ERR_RESPONSE_TOO_BIG and the client retries over TCP (rcbj's decision
// on #588). The KDC is handed in (`install(kdc)`, from
// `common/protocol_stack.ts` just after it is required) rather than required
// here, because requiring the JavaScript KDC from this module would register
// its `/KdcProxy` before this one's; and the KDC requires nothing new, so the
// parent project's COPY closure does not move.
//
// **A HOME THAT CANNOT BE REACHED IS FAIL-CLOSED**, as a relayed MS-KKDCP
// request is answered 503 (`cell_channel.ts`'s `relay()`, #98 D6): the client
// is told KDC_ERR_SVC_UNAVAILABLE (29, STS-KRB-0207), which MIT and Heimdal
// read as "try the next KDC". Answering it here instead would be the
// exception this closed. A realm's hard geofence (`cells.hardGeofence`)
// refuses with KDC_ERR_POLICY (12), the serve policy's own code.
//
// **SINGLE-CELL MODE DOES NOT DECODE ANYTHING**: the handler calls `next()`
// before it reads the body, and `install()` sets no router on the KDC
// (`cells.id` is restart-only), so port 88 is answered byte for byte as it
// was.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import cells = require('../common/cells');
import cellPlacement = require('../common/cell_placement');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import asn1Module = require('./krb5_asn1');
import msgsModule = require('./krb5_messages');
import primModule = require('./krb5_primitives');
import kcryptoModule = require('./krb5_crypto');

// `any` for the checker: the vendored codec is untyped JavaScript and is not
// this repository's to annotate.
const asn1: any = asn1Module;
const msgs: any = msgsModule;
const prim: any = primModule;
const kcrypto: any = kcryptoModule;

const log = bunyan.createLogger({ name: 'sts-krb5-home' });

// The inter-cell operation a port-88 message travels home as.
const KDC_MESSAGE_OP = 'kdc-message';
// KDC_ERR_SVC_UNAVAILABLE and KDC_ERR_POLICY (RFC 4120 section 7.5.9).
const SVC_UNAVAILABLE = 29;
const POLICY = 12;

/**
 * Who a Kerberos request is about, as the routing index keys them.
 */
interface Client {
  realmId: string;
  name: string;
}

/**
 * The placement of a KDC request: the MS-KKDCP route registered ahead of the
 * KDC's own, the router the KDC's port-88 sockets ask, the operation a home
 * cell answers a relayed message with, and the decoding that finds the
 * client.
 */
class Krb5Home {
  // The KDC, handed in by install(); null until then.
  private kdc: any = null;

  /**
   * Builds it. It holds nothing until install().
   */
  constructor() {
    log.debug("Entering Krb5Home.constructor().");
    log.debug("Leaving Krb5Home.constructor().");
  }

  /**
   * The Kerberos message a KDC-PROXY-MESSAGE carries, unframed — the same
   * reading the KDC's own `/KdcProxy` makes.
   *
   * @param body - the request body (a Buffer; `application/kerberos` is
   *   parsed raw)
   * @returns the message, or null when the body is not one
   */
  static messageOf(body: unknown): Uint8Array | null {
    log.debug("Entering Krb5Home.messageOf().");
    if (!body || !(body as any).length || typeof body === 'string') {
      log.debug("Leaving Krb5Home.messageOf(). No body.");
      return null;
    }
    try {
      // KDC-PROXY-MESSAGE ::= SEQUENCE { kerb-message [0] OCTET STRING, ... }
      const outer = asn1.readTlv(prim.toBytes(body), 0);
      const fields = asn1.readTaggedSequence(outer.value);
      const framed = asn1.decOctetString(fields[0]);
      if (!framed || framed.length < 4) {
        log.debug("Leaving Krb5Home.messageOf(). Too short.");
        return null;
      }
      const declared = (framed[0] << 24 | framed[1] << 16 | framed[2] << 8 |
                        framed[3]) >>> 0;
      log.debug("Leaving Krb5Home.messageOf().");
      return framed.subarray(4, 4 + declared);
    } catch (e) {
      log.debug("Caught in Krb5Home.messageOf(): " + ((e && e.message) || e));
      return null;
    }
  }

  // A one-component name in the realm's own Kerberos realm, which is what a
  // directory person's principal is; '' for anything else.
  private static personName(principals: any, principal: any,
                            realm: string): string {
    log.debug("Entering Krb5Home.personName().");
    const parts = (principal && principal.name) || [];
    const ours = String(principals.REALM || '');
    log.debug("Leaving Krb5Home.personName().");
    return parts.length === 1 && parts[0] && String(realm) === ours
      ? String(parts[0]) : '';
  }

  // The client of a ticket-granting ticket, read by opening it under this
  // realm's krbtgt key (the current version, or a previous one still kept —
  // the KDC's own `ticketKeyFor()` rule). Null when it will not open here.
  private static async ticketClient(principals: any,
                                    apReq: any): Promise<string> {
    log.debug("Entering Krb5Home.ticketClient().");
    const ticket = apReq.ticket;
    const service = principals.find(ticket.sname.name, ticket.realm);
    if (!service) {
      log.debug("Leaving Krb5Home.ticketClient(). No such service here.");
      return '';
    }
    const enc = ticket.encPart;
    let key: any = null;
    if (!service.directoryKeys || enc.kvno === null ||
        enc.kvno === undefined || enc.kvno === service.kvno) {
      key = await principals.longTermKey(service, enc.etype);
    } else {
      const kept = principals.retainedKeyFor(service, enc.etype, enc.kvno);
      key = kept ? kept.key : null;
    }
    if (!key) {
      log.debug("Leaving Krb5Home.ticketClient(). No key.");
      return '';
    }
    const part = msgs.readEncTicketPart(await kcrypto.etypeById(enc.etype)
      .decrypt(key, kcrypto.KEY_USAGE.KDC_REP_TICKET, enc.cipher));
    log.debug("Leaving Krb5Home.ticketClient().");
    return Krb5Home.personName(principals, part.cname, part.crealm);
  }

  /**
   * Finds the person a KDC request is about, in the trust realm the KDC
   * would answer it in.
   *
   * @param message - the Kerberos message
   * @param pinned - the trust realm a realm-prefixed `/KdcProxy` names, or
   *   null for the bare path, which routes by the Kerberos realm's name
   * @returns a promise of `{ realmId, name }`, or null when the request
   *   names no person this could route by
   */
  static async clientOf(message: Uint8Array,
                        pinned: any): Promise<Client | null> {
    log.debug("Entering Krb5Home.clientOf().");
    const identified = msgs.identify(message);
    const AS = msgs.APPLICATION.AS_REQ;
    const TGS = msgs.APPLICATION.TGS_REQ;
    if (!identified || (identified.applicationNumber !== AS &&
                        identified.applicationNumber !== TGS)) {
      log.debug("Leaving Krb5Home.clientOf(). Not a KDC request.");
      return null;
    }
    // The principal database, lazily: it is the KDC's, loaded with it, and
    // this route is registered just before the KDC is required.
    const principals: any = require('./krb5_principals');
    const request = msgs.readKdcReq(message);
    const body = request.reqBody || {};
    const padata: any[] = request.padata || [];
    const paOf = function (type: number) {
      log.debug("Entering paOf().");
      log.debug("Leaving paOf().");
      return padata.filter(function (pa) {
        return pa.type === type;
      })[0];
    };
    const paTgs = identified.applicationNumber === TGS
      ? paOf(msgs.PA_TYPE.TGS_REQ) : null;
    const apReq = paTgs ? msgs.readApReq(paTgs.value) : null;
    // The KDC's own routing (`krb5_kdc.js`'s routeOf()): a realm-prefixed
    // path is pinned; otherwise the realm is the one answering to the name —
    // the ticket's for a TGS-REQ, whose outer body may say anything under
    // FAST.
    const asked = String((apReq && apReq.ticket.realm) || body.realm || '');
    const realm = pinned || principals.trustRealmFor(asked) ||
                  realms.DEFAULT_REALM;
    const name: string = await realms.run(realm, async function () {
      if (identified.applicationNumber === AS) {
        return Krb5Home.personName(principals, body.cname, body.realm);
      }
      const forUser = paOf(msgs.PA_TYPE.FOR_USER);
      if (forUser) {
        const read = msgs.readPaForUser(forUser.value);
        return Krb5Home.personName(principals, read.userName, read.userRealm);
      }
      return apReq ? Krb5Home.ticketClient(principals, apReq) : '';
    });
    log.debug("Leaving Krb5Home.clientOf(). " + (name ? 'A person.' :
                                                  'Nobody to route by.'));
    return name ? { realmId: String(realm.id), name: name } : null;
  }

  /**
   * The route: relays a request whose client is homed in another cell, and
   * hands every other one to the KDC's own handler.
   *
   * @param req - the request
   * @param res - the response
   * @param next - the KDC's `/KdcProxy`
   */
  handle(req: any, res: any, next: () => void): void {
    log.debug("Entering Krb5Home.handle().");
    if (!cells.isMulti() || req.stsCellRelay) {
      log.debug("Leaving Krb5Home.handle(). Here.");
      next();
      return;
    }
    const message = Krb5Home.messageOf(req.body);
    if (!message) {
      log.debug("Leaving Krb5Home.handle(). The KDC refuses it.");
      next();
      return;
    }
    Krb5Home.clientOf(message, req.realm || null)
      .then(function (client) {
        return client
          ? cellPlacement.relayToHome(req, res, client.realmId, 'name',
                                      client.name, 'kdc-proxy')
          : false;
      })
      .then(function (relayed: boolean) {
        if (!relayed) {
          next();
        }
      }, function (e: any) {
        // A request this could not read, or a lookup that failed, is the
        // KDC's to answer — in its own words, where it arrived.
        log.debug("Caught in Krb5Home.handle(): " + ((e && e.message) || e));
        if (!res.headersSent) {
          next();
        }
      });
    log.debug("Leaving Krb5Home.handle(). Placing it.");
  }

  /**
   * Installs the port-88 half: the `kdc-message` operation another cell
   * calls, and — in a service deployed as cells only — the KDC's message
   * router. Called by `common/protocol_stack.ts` just after `krb5_kdc.js` is
   * required, with that module, so this one never requires it.
   *
   * @param kdc - the KDC module (`kerberos/krb5_kdc.js`)
   * @returns whether a router was set
   */
  install(kdc: any): boolean {
    log.debug("Entering Krb5Home.install().");
    const self = this;
    if (!kdc || typeof kdc.setMessageRouter !== 'function' ||
        typeof kdc.answerMessage !== 'function') {
      log.debug("Leaving Krb5Home.install(). No seam on that KDC.");
      return false;
    }
    this.kdc = kdc;
    // The operation is registered in every mode, as every other module's
    // is: it is reachable only over the inter-cell listener, which a single
    // cell never binds.
    require('../common/cell_channel').registerOp(KDC_MESSAGE_OP,
      function (body: any, ctx: any) {
        return self.answerRelayed(body, ctx);
      });
    if (!cells.isMulti()) {
      log.debug("Leaving Krb5Home.install(). Single-cell: no router.");
      return false;
    }
    kdc.setMessageRouter(function (bytes: Uint8Array, ctx: any) {
      return self.routeMessage(bytes, ctx);
    });
    log.debug("Leaving Krb5Home.install(). The router is set.");
    return true;
  }

  // A KRB-ERROR made by the KDC in the client's trust realm, so its realm
  // and the default sname are that realm's Kerberos name.
  private refuse(realmId: string, code: number, errorCode: string,
                 eText: string): any {
    log.debug("Entering Krb5Home.refuse().");
    const kdc = this.kdc;
    const realm = realms.get(realmId) || realms.DEFAULT_REALM;
    log.debug("Leaving Krb5Home.refuse().");
    return realms.run(realm, function () {
      // error-code: none — the code is the caller's, passed in as errorCode
      return kdc.errorReply(code, { errorCode: errorCode, eText: eText });
    });
  }

  /**
   * The KDC's message router: a port-88 message whose client is homed in
   * another cell is answered there, and every other one is left to this
   * cell's KDC (null). The same decision `handle()` makes for MS-KKDCP.
   *
   * @param bytes - the complete Kerberos message, unframed
   * @param ctx - `{ transport, peer: { address, port } }` from the socket
   * @returns a promise of `{ reply, refusal }`, a KRB-ERROR's bytes, or null
   */
  async routeMessage(bytes: Uint8Array, ctx: any): Promise<any> {
    log.debug("Entering Krb5Home.routeMessage().");
    if (!cells.isMulti()) {
      log.debug("Leaving Krb5Home.routeMessage(). Single-cell.");
      return null;
    }
    let client: Client | null = null;
    try {
      client = await Krb5Home.clientOf(bytes, null);
    } catch (e) {
      // A message that does not decode, or a ticket that will not open here,
      // is the KDC's to refuse in its own words, where it arrived.
      log.debug("Caught in Krb5Home.routeMessage(): " +
                ((e && e.message) || e));
      client = null;
    }
    if (!client) {
      log.debug("Leaving Krb5Home.routeMessage(). Nobody to route by.");
      return null;
    }
    const home: string = await require('../common/cell_routing')
      .homeOf(client.realmId, 'name', client.name);
    if (!home || home === cells.id() || !cells.get(home)) {
      log.debug("Leaving Krb5Home.routeMessage(). Homed here.");
      return null;
    }
    // THE HARD GEOFENCE (#98 D4), the question `relayToHome()` asks for
    // MS-KKDCP: a realm whose law forbids even carrying the traffic is
    // refused here rather than relayed. The policy decides.
    let decision: any = { allowed: false };
    try {
      decision = require('../common/cell_transfer').serveDecision({
        realm: client.realmId, subject: '', homeCell: home,
        servingCell: cells.id() });
    } catch (e) {
      log.debug("Caught in Krb5Home.routeMessage(): " +
                ((e && e.message) || e));
      decision = { allowed: false };
    }
    if (!decision || !decision.allowed) {
      log.debug("Leaving Krb5Home.routeMessage(). Refused by the serve " +
                "policy.");
      return this.refuse(client.realmId, POLICY,
                         errorCodes.codeOf(decision) || 'STS-CELL-0183',
                         'this account cannot be served from here');
    }
    const t = ctx || {};
    const peer = t.peer || {};
    const transport = t.transport === 'udp' ? 'udp' : 'tcp';
    try {
      const answer = await require('../common/cell_channel').call(home,
        KDC_MESSAGE_OP, {
          message: Buffer.from(bytes).toString('base64'),
          transport: transport,
          address: String(peer.address || ''),
          port: Number(peer.port) || 0
        });
      const reply = Buffer.from(String((answer && answer.reply) || ''),
                                'base64');
      if (!reply.length) {
        throw new Error('cell "' + home + '" answered no reply');
      }
      log.debug("Leaving Krb5Home.routeMessage(). Answered at " + home + ".");
      return { reply: reply, refusal: (answer && answer.refusal) || null };
    } catch (e) {
      log.error(errorCodes.tag('STS-KRB-0207') + 'krb5: a ' + transport +
                ' message for a person homed in cell "' + home + '" could ' +
                'not be answered there: ' +
                String((e && e.message) || e).replace(/\.$/, '') + '. The ' +
                'client is told KDC_ERR_SVC_UNAVAILABLE, fail-closed.');
      log.debug("Leaving Krb5Home.routeMessage(). The home failed.");
      return this.refuse(client.realmId, SVC_UNAVAILABLE, 'STS-KRB-0207',
                         'the KDC could not complete this request; try again');
    }
  }

  /**
   * The `kdc-message` operation, at home: a message another cell received
   * on port 88, answered by this cell's KDC as its own socket would answer
   * it — and never routed again (one hop).
   *
   * @param body - `{ message, transport, address, port }`, the message base64
   * @param ctx - `{ peer }`, the calling cell
   * @returns a promise of `{ reply, refusal }`, the reply base64
   */
  async answerRelayed(body: any, ctx: any): Promise<any> {
    log.debug("Entering Krb5Home.answerRelayed().");
    const b = body || {};
    const bytes = Buffer.from(String(b.message || ''), 'base64');
    if (!bytes.length || !this.kdc) {
      log.debug("Leaving Krb5Home.answerRelayed(). Nothing to answer.");
      throw new Error(errorCodes.tag('STS-KRB-0208') + 'krb5: cell "' +
                      String((ctx && ctx.peer) || '?') + '" relayed ' +
                      (this.kdc ? 'no Kerberos message' : 'a Kerberos ' +
                       'message to a process with no KDC') + '.');
    }
    const reply = await this.kdc.answerMessage(bytes,
      b.transport === 'udp' ? 'udp' : 'tcp',
      { address: String(b.address || ''), port: Number(b.port) || 0 });
    log.debug("Leaving Krb5Home.answerRelayed().");
    return {
      reply: Buffer.from(reply).toString('base64'),
      refusal: this.kdc.refusalOf(reply) || null
    };
  }

  /**
   * Registers `POST /KdcProxy` ahead of the KDC's own. Called by
   * `common/protocol_stack.ts`, just before `krb5_kdc.js` is required.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: any): void {
    log.debug("Entering Krb5Home.registerRoutes().");
    const self = this;
    app.post('/KdcProxy', function (req: any, res: any, next: () => void) {
      self.handle(req, res, next);
    });
    log.debug("Leaving Krb5Home.registerRoutes().");
  }
}

const home = new Krb5Home();

/**
 * Where a Kerberos request over MS-KKDCP or TCP and UDP 88 is answered in a
 * service deployed as cells (#98, #588): its client's home cell. One route,
 * registered ahead of the KDC's, and the KDC's message router, installed
 * from outside, so the KDC's require closure is unchanged.
 * @namespace
 */
export = {
  Krb5Home: Krb5Home,
  messageOf: Krb5Home.messageOf,
  clientOf: Krb5Home.clientOf,
  KDC_MESSAGE_OP: KDC_MESSAGE_OP,
  registerRoutes: (app: any): void => home.registerRoutes(app),
  install: (kdc: any): boolean => home.install(kdc),
  routeMessage: (bytes: Uint8Array, ctx: any): Promise<any> =>
    home.routeMessage(bytes, ctx),
  answerRelayed: (body: any, ctx: any): Promise<any> =>
    home.answerRelayed(body, ctx)
};
