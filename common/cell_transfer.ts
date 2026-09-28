// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_transfer.ts
//
// ---------------------------------------------------------------------------
// MAY A PERSON'S DATA GO WHERE THEY ARE? THE TRANSFER DECISION AS POLICY
// (#98 D4, and the design's section 6: "geofencing is policy, not code").
//
// When the service is deployed as CELLS (`cells.ts`), a person is homed in
// one jurisdiction and may turn up at a cell in another. Three questions
// follow, and this module is where every caller asks them:
//
//   * `holdDecision()` — may a SESSION of that person, and the
//     credential-free projection of their entry it stands on, be HELD in the
//     serving cell (#98 D9's handoff)? No is not a refusal: the session stays
//     at home and the serving cell relays each request there — slower, and
//     lawful. That is D4's "strict, with relay".
//   * `serveDecision()` — may a request about that person be served from the
//     serving cell AT ALL, even by relaying it? No is a refusal, the hard
//     geofence a realm asks for (`cells.hardGeofence`) when its law forbids
//     even carrying the traffic. Yes says whether it must be relayed.
//   * `releaseDecision()` — may personal data of the people homed in one
//     cell's jurisdiction be RELEASED to a reader at a cell in another
//     (#98 D11)? An administrator listing another cell's residents from the
//     console, a management-API call relayed with `?cell=`. Asked by the
//     cell that HOLDS the people, before it answers; no withholds them. The
//     built-in rule is `holdDecision()`'s, on the same list.
//
// **NOTHING HERE DECIDES.** rcbj's rule is that every authorization decision is
// a rule of the issuance policy and code supplies facts: this gathers them —
// the home and serving jurisdictions (`cells.jurisdictionOf()`), the client's
// country when a caller knows it, whether the realm LISTS the transfer
// (`cells.transferListed()`, the realm's stated loosening of the strict
// default) and `cells.hardGeofence` — and puts them to the policy through
// `issuance_gate.checkTransfer()`, action-ids `hold-session`, `serve-request`
// and `release-attributes`. The built-in `role-issuance` document holds the
// strict default (`xacml/xacml_templates.ts`, the transfer rules); a realm's
// own issuance policy may say anything else, for example that `eu` subjects may
// hold sessions in `us`, and is honoured. Where no XACML family is loaded the
// gate evaluates the built-in document itself, so the default holds in every
// process.
//
// **SINGLE-CELL MODE ASKS NOTHING.** With `cells.id` empty there is one cell
// and no transfer, and all three answer "allowed" without reaching the policy —
// the rest of the service behaves exactly as it did before cells.
//
// **A HOME CELL NOT RECORDED IS THE SERVING CELL**, as `cells.isHere('')`
// reads it: a person with no home written down is resident where they are
// (single-cell data carried into a cell deployment), and there is no
// transfer to decide. An UNKNOWN home cell — one the service does not have —
// is different: its jurisdiction is '' and no rule reads '' as home, so the
// strict default applies.
//
// **SYNCHRONOUS, like `issuance_gate.check()`**, because its callers sit on
// the edge of every request a cell relays, and an authorization question that
// could make them asynchronous would be a change to every one of them.
//
// A LIBRARY: no route, no slot, no load-time effect beyond building its one
// instance. `issuance_gate.js` is a leaf; the XACML engine is reached through
// it, lazily.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import cells = require('./cells');
import config = require('./config');
import errorCodes = require('./error_codes');
import gate = require('./issuance_gate');
import realms = require('./realms');

const log = bunyan.createLogger({ name: 'sts-cell-transfer' });

/**
 * What a caller knows about the transfer it asks about.
 */
interface TransferOptions {
  // The trust realm the subject belongs to; the ambient one when empty.
  realm: string;
  // The subject, `urn:uuid:<entryUUID>`.
  subject: string;
  // The cell the subject is homed in ('' — not recorded — is the serving
  // cell) and the cell asking.
  homeCell: string;
  servingCell: string;
  // The client's country (ISO 3166-1 alpha-2), when the caller knows it.
  clientCountry?: string;
}

// What a caller knows about a release (#98 D11): no subject — it is about a
// cell's residents — and a purpose instead of a client's country.
interface ReleaseOptions {
  realm: string;
  // The cell that holds the people, and the cell the reader is at.
  homeCell: string;
  servingCell: string;
  // `directory-list` or `api`.
  purpose: string;
}

// The facts the policy is asked on, as `issuance_gate.checkTransfer()` takes
// them.
interface TransferFacts {
  action: string;
  subject: string;
  home: string;
  serving: string;
  clientCountry: string;
  listed: boolean;
  hardGeofence: boolean;
  category: string;
  realm: string;
  purpose: string;
}

// What the module reads; a test supplies its own cell map and settings.
interface CellTransferDeps {
  cells: { isMulti(): boolean; jurisdictionOf(cellId: string): string;
           transferListed(home: string, serving: string): boolean };
  value(key: string): unknown;
  gate: { checkTransfer(request: TransferFacts):
            { verdict: string; decidedBy: string; why: string };
          TRANSFER: { HOLD_SESSION: string; SERVE_REQUEST: string;
                      RELEASE_ATTRIBUTES: string } };
  realms: { currentId(): string; get(id: string): any;
            run<T>(realm: any, fn: () => T): T };
  log: { debug(message: string): void };
}

/**
 * The three transfer questions a cell asks the issuance policy (#98 D4,
 * D11).
 */
class CellTransfer {
  /**
   * Builds the asker over a cell map, a settings reader, the issuance gate
   * and the realm registry.
   *
   * @param deps - what the questions read
   */
  constructor(private readonly deps: CellTransferDeps) {
    deps.log.debug("Entering CellTransfer.constructor().");
    deps.log.debug("Leaving CellTransfer.constructor().");
  }

  /**
   * Returns the dependencies of the module's own instance.
   *
   * @returns the real cell map, settings, gate and realms
   */
  static defaultDeps(): CellTransferDeps {
    log.debug("Entering CellTransfer.defaultDeps().");
    log.debug("Leaving CellTransfer.defaultDeps().");
    return {
      cells: cells,
      value: (key: string) => config.value(key),
      gate: gate,
      realms: realms,
      log: log
    };
  }

  /**
   * May a session of a subject homed in `homeCell`'s jurisdiction — and the
   * credential-free projection of their entry — be held in `servingCell`'s?
   *
   * @param opts - the realm, the subject, the two cells and, when known,
   *   the client's country
   * @returns `{ allowed, why }`; not allowed means the session stays at home
   *   and the serving cell relays
   */
  holdDecision(opts: TransferOptions): { allowed: boolean; why: string } {
    const { log } = this.deps;
    log.debug("Entering CellTransfer.holdDecision().");
    if (!this.deps.cells.isMulti()) {
      log.debug("Leaving CellTransfer.holdDecision(). Single-cell.");
      return { allowed: true, why: 'This service is one cell; there is no ' +
                                   'transfer to decide.' };
    }
    const answer = this.ask(this.deps.gate.TRANSFER.HOLD_SESSION, 'session',
                            opts);
    if (answer.unknownRealm) {
      log.debug("Leaving CellTransfer.holdDecision(). Unknown realm.");
      return errorCodes.mark({ allowed: false, why: answer.why },
                             'STS-CELL-0182');
    }
    const allowed = answer.verdict === 'hold';
    log.debug("Leaving CellTransfer.holdDecision(). " + answer.verdict);
    return { allowed: allowed,
             why: (allowed
               ? 'The session may be held here (' + answer.route + '). '
               : 'The session is held at home and every request relayed ' +
                 'there (' + answer.route + '). ') + answer.why };
  }

  /**
   * May a request about the subject be served from `servingCell` at all, and
   * must it be relayed to `homeCell` to be?
   *
   * @param opts - the realm, the subject, the two cells and, when known,
   *   the client's country
   * @returns `{ allowed, relay, why }`; not allowed is a refusal
   *   (STS-CELL-0183, marked on the answer for the caller's response)
   */
  serveDecision(opts: TransferOptions)
    : { allowed: boolean; relay: boolean; why: string } {
    const { log } = this.deps;
    log.debug("Entering CellTransfer.serveDecision().");
    if (!this.deps.cells.isMulti()) {
      log.debug("Leaving CellTransfer.serveDecision(). Single-cell.");
      return { allowed: true, relay: false,
               why: 'This service is one cell; there is nothing to relay.' };
    }
    const answer = this.ask(this.deps.gate.TRANSFER.SERVE_REQUEST, 'request',
                            opts);
    if (answer.unknownRealm) {
      log.debug("Leaving CellTransfer.serveDecision(). Unknown realm.");
      return errorCodes.mark({ allowed: false, relay: false,
                               why: answer.why }, 'STS-CELL-0182');
    }
    if (answer.verdict === 'refuse') {
      log.debug(errorCodes.tag('STS-CELL-0183') + 'cell_transfer: a ' +
                'request is refused under the hard geofence (' +
                answer.route + ').');
      log.debug("Leaving CellTransfer.serveDecision(). Refused.");
      return errorCodes.mark({
        allowed: false, relay: false,
        why: 'This service cannot be used from here for a person homed in ' +
             'another jurisdiction (' + answer.route + '): the realm ' +
             'refuses rather than relays. ' + answer.why
      }, 'STS-CELL-0183');
    }
    const home = this.homeOf(opts);
    const relay = String(opts.servingCell || '') !== home;
    log.debug("Leaving CellTransfer.serveDecision(). " +
              (relay ? 'Relay.' : 'Serve here.'));
    return { allowed: true, relay: relay,
             why: (relay ? 'Served by relaying to the home cell (' +
                           answer.route + '). '
                         : 'Served here (' + answer.route + '). ') +
                  answer.why };
  }

  /**
   * May personal data of the people homed in `homeCell`'s jurisdiction be
   * released to a reader at `servingCell` (#98 D11)? Asked by the cell that
   * holds them, before it answers.
   *
   * @param opts - the realm, the cell holding the people, the reader's cell
   *   and the purpose (`directory-list` or `api`)
   * @returns `{ allowed, why }`; not allowed withholds them
   *   (STS-CELL-0184, marked on the answer for the caller's response)
   */
  releaseDecision(opts: ReleaseOptions): { allowed: boolean; why: string } {
    const { log } = this.deps;
    log.debug("Entering CellTransfer.releaseDecision().");
    if (!this.deps.cells.isMulti()) {
      log.debug("Leaving CellTransfer.releaseDecision(). Single-cell.");
      return { allowed: true, why: 'This service is one cell; there is no ' +
                                   'transfer to decide.' };
    }
    const given = opts || ({} as ReleaseOptions);
    const answer = this.ask(this.deps.gate.TRANSFER.RELEASE_ATTRIBUTES,
                            'attributes',
                            { realm: given.realm, subject: '',
                              homeCell: given.homeCell,
                              servingCell: given.servingCell },
                            String(given.purpose || '').trim());
    if (answer.unknownRealm) {
      log.debug("Leaving CellTransfer.releaseDecision(). Unknown realm.");
      return errorCodes.mark({ allowed: false, why: answer.why },
                             'STS-CELL-0182');
    }
    if (answer.verdict !== 'release') {
      log.debug(errorCodes.tag('STS-CELL-0184') + 'cell_transfer: ' +
                'residents are withheld from a reader at another cell (' +
                answer.route + ').');
      log.debug("Leaving CellTransfer.releaseDecision(). Withheld.");
      return errorCodes.mark({
        allowed: false,
        why: 'The people homed in this cell are not released to a reader ' +
             'in another jurisdiction (' + answer.route + '): the realm ' +
             'does not list the transfer. ' + answer.why
      }, 'STS-CELL-0184');
    }
    log.debug("Leaving CellTransfer.releaseDecision(). Released.");
    return { allowed: true, why: 'Released (' + answer.route + '). ' +
                                 answer.why };
  }

  // The home cell, with '' (not recorded) read as the serving cell — see
  // the header.
  private homeOf(opts: TransferOptions): string {
    this.deps.log.debug("Entering CellTransfer.homeOf().");
    const home = String((opts && opts.homeCell) || '').trim();
    this.deps.log.debug("Leaving CellTransfer.homeOf().");
    return home || String((opts && opts.servingCell) || '').trim();
  }

  // ONE QUESTION: the facts gathered IN THE SUBJECT'S REALM — the list of
  // permitted transfers and the hard geofence are realm settings, so they
  // are read with that realm ambient — and put to the issuance policy.
  private ask(action: string, category: string, opts: TransferOptions,
              purpose?: string)
    : { verdict: string; why: string; route: string; unknownRealm?: boolean } {
    const { log } = this.deps;
    log.debug("Entering CellTransfer.ask(). " + action);
    const given = opts || ({} as TransferOptions);
    const realmId = String(given.realm || '').trim() ||
      this.deps.realms.currentId();
    const self = this;
    const decideHere = function (): { verdict: string; why: string;
                                      route: string } {
      log.debug("Entering decideHere().");
      const homeCell = self.homeOf(given);
      const servingCell = String(given.servingCell || '').trim();
      const home = self.deps.cells.jurisdictionOf(homeCell);
      const serving = self.deps.cells.jurisdictionOf(servingCell);
      // An unknown jurisdiction on either side is never "listed": `*>us`
      // loosens the default for every KNOWN home, and a cell the service
      // does not have is not one.
      const listed = !!home && !!serving &&
        self.deps.cells.transferListed(home, serving);
      const facts: TransferFacts = {
        action: action,
        subject: String(given.subject || ''),
        home: home,
        serving: serving,
        clientCountry: String(given.clientCountry || '').trim().toLowerCase(),
        listed: listed,
        hardGeofence: self.deps.value('cells.hardGeofence') === true,
        category: category,
        realm: realmId,
        purpose: purpose || ''
      };
      const found = self.deps.gate.checkTransfer(facts);
      log.debug("Leaving decideHere(). " + found.verdict);
      return { verdict: found.verdict, why: found.why || '',
               route: (home || '?') + '>' + (serving || '?') +
                      (listed && home !== serving ? ', listed' : '') +
                      ', decided by ' + (found.decidedBy || 'none') };
    };
    if (realmId === this.deps.realms.currentId()) {
      log.debug("Leaving CellTransfer.ask(). In the ambient realm.");
      return decideHere();
    }
    const realm = this.deps.realms.get(realmId);
    if (!realm) {
      // A caller naming a realm this service does not have is a defect in
      // the caller, and the answer is the strict one — hold nothing, serve
      // nothing — rather than a guess at which realm's rules were meant.
      log.debug("Leaving CellTransfer.ask(). No realm " + realmId + ".");
      return { verdict: '', route: '', unknownRealm: true,
               why: 'This service has no realm "' + realmId + '", so the ' +
                    'transfer was not decided and is refused.' };
    }
    log.debug("Leaving CellTransfer.ask(). In realm " + realmId + ".");
    return this.deps.realms.run(realm, decideHere);
  }
}

// The module's own instance, over the real settings. A LIBRARY with no
// load-time effect beyond this, so there is nothing for the composition root
// to install.
const transfer = new CellTransfer(CellTransfer.defaultDeps());

/**
 * The three transfer questions a cell asks the issuance policy (#98 D4,
 * D11): `holdDecision()`, `serveDecision()` and `releaseDecision()`.
 * Single-cell mode answers all three "allowed" without asking.
 * @namespace
 */
export = {
  CellTransfer: CellTransfer,
  holdDecision: (opts: TransferOptions): { allowed: boolean; why: string } =>
    transfer.holdDecision(opts),
  serveDecision: (opts: TransferOptions)
    : { allowed: boolean; relay: boolean; why: string } =>
    transfer.serveDecision(opts),
  releaseDecision: (opts: ReleaseOptions): { allowed: boolean; why: string } =>
    transfer.releaseDecision(opts)
};
