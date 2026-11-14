// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma_gate.ts
//
// ---------------------------------------------------------------------------
// THE UMA 2.0 GRANT AT THE AUTHORIZATION SERVER'S DOORS (#1168 phase 4,
// #1193): the one place `oauth-oidc/oauth2.ts` hands the
// `urn:ietf:params:oauth:grant-type:uma-ticket` grant, an introspection
// presented with a protection API token, and the revocation of a persisted
// claims token to the UMA family — and the reason it is an empty shell.
//
// WHY A SLOT, rule 3e's test both ways round, as `fga_gate.ts` argues it:
//
//   * `oauth2.ts` is at 9 and the UMA family at 23d-ii. A require from the
//     authorization server to `uma/` would load the family's stores, its PEP
//     and, through the PEP, the XACML surface, whose `xacml_admin.ts` requires
//     the console, which requires `oauth2.ts`: a cycle — and every
//     `InstanceSlot` of the family reached long before the composition root
//     builds it.
//   * The other way, the UMA family reaching into `oauth2.ts`, would have it
//     know the token endpoint's closures (`issue()`, the respond and refusal
//     wrappers) that only the endpoint holds.
//
// So this file requires `helpers`, the error-code table and `InstanceSlot`,
// and nothing else — a LEAF — and `uma/uma_grant.ts` fills it at 23d-ii.
//
// **AN EMPTY SLOT MEANS THE GRANT IS NOT OFFERED**, which is neither
// `issuance_gate.js`'s "allow" nor `fga_gate.ts`'s "refuse": nobody asked
// for UMA in a process without the family, so the grant is simply not
// performed — `offered()` answers false, the metadata does not list it, and
// the token endpoint answers `unsupported_grant_type` as for any grant it
// does not know. An introspection carrying a Bearer token and a revocation
// of an unknown handle go on as they always did.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

type Json = any;

/** What the UMA family installs. */
interface UmaHandler {
  // Whether the grant is performed in the ambient realm now.
  offered(): boolean;
  // The grant: answers `{ body }` for a token response, or `{ status,
  // error, description, code, extra }` for a refusal.
  grant(ctx: Json): Promise<Json>;
  // An introspection presented with a PAT: `undefined` when the request is
  // not one (the endpoint goes on as before); `null` when a refusal was
  // written; else the answer to send.
  introspect(ctx: Json): Json;
  // A PCT's revocation: `{ found: false }` when the token is no PCT.
  revokePct(token: string, clientId: string, identified: boolean): Json;
  // An RPT's permissions for the resource server it was issued for, when
  // that resource server introspects it with its OWN client credentials
  // (#1196): null for anything else.
  permissionsFor(answer: Json, clientId: string): Json;
}

interface UmaGateDeps {
  log: { debug(message: string): void; error(message: string): void };
  errorCodes: { tag(code: string): string };
}

// The grant's identifier, as the token endpoint compares it.
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:uma-ticket';

/**
 * The UMA family's doors at the authorization server.
 */
class UmaGate {
  static readonly GRANT_TYPE = GRANT_TYPE;

  private handler: UmaHandler | null = null;

  /**
   * Builds a gate with nothing installed.
   *
   * @param deps - the logger and the error-code table
   */
  constructor(private readonly deps: UmaGateDeps) {
    deps.log.debug("Entering UmaGate.constructor().");
    deps.log.debug("Leaving UmaGate.constructor().");
  }

  /**
   * The dependencies the default instance is built from.
   *
   * @returns the logger and the error-code table
   */
  static defaultDeps(): UmaGateDeps {
    helpers.log.debug("Entering UmaGate.defaultDeps().");
    helpers.log.debug("Leaving UmaGate.defaultDeps().");
    return { log: helpers.log, errorCodes: errorCodes };
  }

  /**
   * Installs, replaces or clears the handler. Anything else is refused and
   * logged, which leaves the slot as it was.
   *
   * @param handler - the handler, or null to clear it
   * @returns true when installed or cleared
   */
  setHandler(handler: UmaHandler | null): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering UmaGate.setHandler().");
    if (handler !== null && (!handler ||
        typeof handler.offered !== 'function' ||
        typeof handler.grant !== 'function' ||
        typeof handler.introspect !== 'function' ||
        typeof handler.revokePct !== 'function' ||
        typeof handler.permissionsFor !== 'function')) {
      log.error(errorCodes.tag('STS-UMA-0200') + 'uma_gate: setHandler() ' +
                'was given something that is not a whole handler, so it ' +
                'was refused; the UMA grant is not offered.');
      log.debug("Leaving UmaGate.setHandler(). Refused.");
      return false;
    }
    this.handler = handler;
    log.debug("Leaving UmaGate.setHandler(). " +
              (handler ? 'Installed.' : 'Cleared.'));
    return true;
  }

  /**
   * Whether a handler is installed.
   *
   * @returns true when one is
   */
  installed(): boolean {
    const { log } = this.deps;
    log.debug("Entering UmaGate.installed().");
    log.debug("Leaving UmaGate.installed().");
    return !!this.handler;
  }

  /**
   * Whether the grant is performed in the ambient realm: a handler, and the
   * handler's own answer (`uma.enabled`). Never throws.
   *
   * @returns true when it is
   */
  offered(): boolean {
    const { log } = this.deps;
    log.debug("Entering UmaGate.offered().");
    let out = false;
    try {
      out = !!this.handler && this.handler.offered() === true;
    } catch (e) {
      log.debug("Caught in UmaGate.offered(): " + ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving UmaGate.offered(). " + out);
    return out;
  }

  /**
   * Performs the grant, or answers the refusal of a grant not offered.
   *
   * @param ctx - what the token endpoint hands over
   * @returns the answer
   */
  grant(ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering UmaGate.grant().");
    if (!this.offered()) {
      log.debug("Leaving UmaGate.grant(). Not offered.");
      return Promise.resolve({ status: 400, code: 'STS-UMA-0200',
        error: 'unsupported_grant_type',
        description: 'The UMA grant is not performed in this realm.' });
    }
    log.debug("Leaving UmaGate.grant().");
    return (this.handler as UmaHandler).grant(ctx);
  }

  /**
   * An introspection with a PAT, or `undefined` for any other.
   *
   * @param ctx - the request, the response, the token and the
   *   endpoint's own `introspectionOf`
   * @returns the answer, null when a refusal was written, or undefined
   */
  introspect(ctx: Json): Json {
    const { log } = this.deps;
    log.debug("Entering UmaGate.introspect().");
    if (!this.offered()) {
      log.debug("Leaving UmaGate.introspect(). Not offered.");
      return undefined;
    }
    log.debug("Leaving UmaGate.introspect().");
    return (this.handler as UmaHandler).introspect(ctx);
  }

  /**
   * A PCT's revocation, or `{ found: false }`.
   *
   * @param token - the token presented
   * @param clientId - the caller
   * @param identified - whether the caller authenticated
   * @returns the outcome
   */
  revokePct(token: string, clientId: string, identified: boolean): Json {
    const { log } = this.deps;
    log.debug("Entering UmaGate.revokePct().");
    if (!this.handler) {
      log.debug("Leaving UmaGate.revokePct(). Nothing installed.");
      return { found: false };
    }
    log.debug("Leaving UmaGate.revokePct().");
    return this.handler.revokePct(token, clientId, identified);
  }

  /**
   * An RPT's permissions, for the resource server it was issued for when
   * that resource server introspects it authenticated as its own client —
   * keycloak-authz-client's way (rcbj, 2026-10-30, #1196) — or null.
   *
   * @param answer - the endpoint's introspection answer, active
   * @param clientId - the client that authenticated
   * @returns the permissions, or null
   */
  permissionsFor(answer: Json, clientId: string): Json {
    const { log } = this.deps;
    log.debug("Entering UmaGate.permissionsFor().");
    if (!this.offered()) {
      log.debug("Leaving UmaGate.permissionsFor(). Not offered.");
      return null;
    }
    log.debug("Leaving UmaGate.permissionsFor().");
    return (this.handler as UmaHandler).permissionsFor(answer, clientId);
  }
}

const slot = new InstanceSlot<UmaGate>(
  'common/uma_gate',
  () => new UmaGate(UmaGate.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The UMA 2.0 grant's slot at the authorization server (#1168).
 * @namespace
 */
export = {
  UmaGate: UmaGate,
  installInstance: (instance: UmaGate): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  GRANT_TYPE: GRANT_TYPE,
  setHandler: slot.forward('setHandler'),
  installed: slot.forward('installed'),
  offered: slot.forward('offered'),
  grant: slot.forward('grant'),
  introspect: slot.forward('introspect'),
  revokePct: slot.forward('revokePct'),
  permissionsFor: slot.forward('permissionsFor')
};
