// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
// **`krb5_kdc.js` IS LOCKED** (the parent project's copy set, `CLAUDE.md`,
// *The parent project loads these modules in-process*), so this is a route of
// its own, registered on `POST /KdcProxy` JUST BEFORE the KDC's
// (`common/protocol_stack.ts`), that decodes just enough to find the client
// and either relays the request or calls `next()` — after which the KDC's own
// handler runs exactly as it always did. It REQUIRES the vendored codec
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
// **THE RAW SOCKETS ON TCP AND UDP 88 ARE NOT PLACED**, and cannot be from
// here: `krb5_kdc.js` starts them in `listen()` and hands each message to its
// own module-private `handleMessage()`, with no hook between the socket and
// the answer. A traveller's AS-REQ over port 88 at a visiting cell is
// therefore answered THERE — which, for a person that cell does not hold, is
// an unknown principal in product and a fresh one in development. The
// exception, and what the parent project would have to add to close it, is in
// `CLAUDE.md`, *Cells: a Kerberos request is answered at home*.
//
// **SINGLE-CELL MODE DOES NOT DECODE ANYTHING**: the handler calls `next()`
// before it reads the body.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import cells = require('../common/cells');
import cellPlacement = require('../common/cell_placement');
import realms = require('../common/realms');
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

/**
 * Who a Kerberos request is about, as the routing index keys them.
 */
interface Client {
  realmId: string;
  name: string;
}

/**
 * The placement of a KDC request relayed over MS-KKDCP: the route registered
 * ahead of the KDC's own, and the decoding that finds the client.
 */
class Krb5Home {
  /**
   * Builds it. It holds nothing.
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
 * Where a Kerberos request relayed over MS-KKDCP is answered in a service
 * deployed as cells (#98): its client's home cell. One route, registered
 * ahead of the KDC's; the KDC itself is locked and unchanged.
 * @namespace
 */
export = {
  Krb5Home: Krb5Home,
  messageOf: Krb5Home.messageOf,
  clientOf: Krb5Home.clientOf,
  registerRoutes: (app: any): void => home.registerRoutes(app)
};
