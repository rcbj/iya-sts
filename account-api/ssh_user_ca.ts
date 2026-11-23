// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssh_user_ca.ts
//
// ---------------------------------------------------------------------------
// THE ACCOUNT API'S SSH USER CERTIFICATE OPERATIONS (#1955 P3). The token's
// subject is the only identity this provider passes to the issuer. Its
// certificates are returned in the no-store account API response, and its
// serials can be revoked only by that same subject.
//
// Since the #1955 review: the subject's own certificates are LISTED
// (`GET /account-api/ssh/certificates`), and the three operations take
// `ssh:certificate` as well as `account:manage`, so an SSH command line on
// the device grant holds nothing else of the person's account.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import ModelZod = require('../common/model_zod');
import sshUserCa = require('../common/ssh_user_ca');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const ISSUE_FORM = ModelZod.body('account', 'issueSshCertificate');
const REVOKE_FORM = ModelZod.body('account', 'revokeSshCertificate');

// The narrower scope these operations take beside `account:manage`.
const SSH_SCOPES = ['ssh:certificate'];

interface AccountSshUserCaDeps {
  log: typeof helpers.log;
  sshUserCa: typeof sshUserCa;
}

/**
 * The Account API's SSH user certificate operations.
 */
class AccountSshUserCa {
  /**
   * Builds the provider over its dependencies.
   *
   * @param deps - the issuer
   */
  constructor(private readonly deps: AccountSshUserCaDeps) {
    deps.log.debug("Entering AccountSshUserCa.constructor().");
    deps.log.debug("Leaving AccountSshUserCa.constructor().");
  }

  /**
   * Returns the production dependency set.
   *
   * @returns the dependencies
   */
  static defaultDeps(): AccountSshUserCaDeps {
    helpers.log.debug("Entering AccountSshUserCa.defaultDeps().");
    helpers.log.debug("Leaving AccountSshUserCa.defaultDeps().");
    return { log: helpers.log, sshUserCa: sshUserCa };
  }

  private statusOf(ctx: AccountContext, answer: Json,
                   fallback: string): number {
    const { log } = this.deps;
    log.debug("Entering AccountSshUserCa.statusOf().");
    const code = String(ctx.errorCodes.codeOf(answer) || fallback);
    if (code === 'STS-PKI-0290' || code === 'STS-PKI-0297') {
      log.debug("Leaving AccountSshUserCa.statusOf(). 503.");
      return 503;
    }
    if (code === 'STS-PKI-0291') {
      log.debug("Leaving AccountSshUserCa.statusOf(). 404.");
      return 404;
    }
    if (code === 'STS-PKI-0293' || code === 'STS-PKI-0294' ||
        code === 'STS-SSHCA-0002') {
      log.debug("Leaving AccountSshUserCa.statusOf(). 403.");
      return 403;
    }
    log.debug("Leaving AccountSshUserCa.statusOf(). 400.");
    return 400;
  }

  private async issue(ctx: AccountContext, req: Json, res: Json,
                      caller: AccountCaller, body: Json): Promise<unknown> {
    const { log, sshUserCa: issuer } = this.deps;
    log.debug("Entering AccountSshUserCa.issue().");
    if (ctx.config.value('pki.personSelfService') === false) {
      log.debug("Leaving AccountSshUserCa.issue(). Self-service disabled.");
      return ctx.refuse(res, 403, 'STS-PKI-0293',
                        'Self-service SSH certificate issuance is disabled.');
    }
    const allowed = await ctx.websecurity.attemptShared(
      'portal-ssh-user-ca', req, caller.username, {
        identity: ctx.config.value('pki.personSelfServicePerIdentity'),
        address: ctx.config.value('pki.personSelfServicePerAddress')
      });
    if (!allowed || !allowed.ok) {
      log.debug("Leaving AccountSshUserCa.issue(). Rate limited.");
      return ctx.refuse(res, 429,
        String(ctx.errorCodes.codeOf(allowed) || 'STS-PKI-0295'),
        String(allowed.detail || 'Too many SSH certificate requests.'));
    }
    const answer = await issuer.issue({
      username: caller.username, subject: caller.sub, realm: caller.realm,
      publicKey: body.publicKey, principals: body.principals,
      lifetimeS: body.lifetimeS, attestation: body.attestation,
      attestationChallenge: body.attestationChallenge
    });
    if (!answer || !answer.ok) {
      const code = String(ctx.errorCodes.codeOf(answer) || 'STS-PKI-0290');
      log.debug("Leaving AccountSshUserCa.issue(). Refused.");
      return ctx.refuse(res, this.statusOf(ctx, answer, code), code,
        (answer && answer.errors) || 'The SSH certificate could not be issued.');
    }
    log.debug("Leaving AccountSshUserCa.issue(). Issued.");
    return ctx.json(res, 200, answer);
  }

  private async revoke(ctx: AccountContext, req: Json, res: Json,
                       caller: AccountCaller,
                       body: Json): Promise<unknown> {
    const { log, sshUserCa: issuer } = this.deps;
    log.debug("Entering AccountSshUserCa.revoke().");
    const serialHex = String(body.serialHex || '');
    if (!/^[0-9a-fA-F]{1,16}$/.test(serialHex) ||
        !serialHex.replace(/^0+/, '')) {
      log.debug("Leaving AccountSshUserCa.revoke(). Invalid serial.");
      return ctx.refuse(res, 400, 'STS-PKI-0291',
                        'The SSH certificate serial is not valid.');
    }
    const answer = await issuer.revoke(caller.realm, caller.sub,
                                       serialHex);
    if (!answer || !answer.ok) {
      const code = String(ctx.errorCodes.codeOf(answer) || 'STS-PKI-0290');
      log.debug("Leaving AccountSshUserCa.revoke(). Refused.");
      return ctx.refuse(res, this.statusOf(ctx, answer, code), code,
        (answer && answer.errors) || 'The SSH certificate could not be revoked.');
    }
    ctx.audit.record({
      category: 'authentication', action: 'ssh-user-ca.revoke',
      actor: caller.username, target: caller.username, outcome: 'success',
      summary: caller.username + ' revoked an SSH user certificate',
      detail: { serialHex: serialHex }
    });
    log.debug("Leaving AccountSshUserCa.revoke(). Revoked.");
    return ctx.json(res, 200, { ok: true, revoked: true });
  }

  private async list(ctx: AccountContext, res: Json,
                     caller: AccountCaller): Promise<unknown> {
    const { log, sshUserCa: issuer } = this.deps;
    log.debug("Entering AccountSshUserCa.list().");
    let rows: Json[] = [];
    try {
      rows = await issuer.certificatesOf(caller.realm, caller.sub);
    } catch (e) {
      log.error(ctx.errorCodes.tag('STS-SSHCA-0005') + 'account-api: the ' +
                'SSH certificates of ' + caller.username + ' could not be ' +
                'read: ' + ((e && e.message) || e));
      log.debug("Leaving AccountSshUserCa.list(). Threw.");
      return ctx.refuse(res, 503, 'STS-SSHCA-0005',
                        'Your SSH certificates could not be read just now.');
    }
    const limits = issuer.lifetimes();
    log.debug("Leaving AccountSshUserCa.list(). " + rows.length);
    return ctx.json(res, 200, { certificates: rows,
                                lifetimes: { softwareSeconds: limits.software,
                                             hardwareSeconds:
                                               limits.hardware } });
  }

  /**
   * The Account API operations.
   *
   * @param ctx - the API's shared helpers
   * @returns the operations
   */
  accountOperations(ctx: AccountContext): AccountOperation[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AccountSshUserCa.accountOperations().");
    const rows: AccountOperation[] = [
      {
        method: 'GET', path: ctx.BASE + '/ssh/certificates',
        operationId: 'listSshCertificates', access: 'person',
        scopes: SSH_SCOPES,
        handler: function (req, res, caller: AccountCaller):
            Promise<unknown> {
          return self.list(ctx, res, caller);
        }
      },
      {
        method: 'POST', path: ctx.BASE + '/ssh/certificates',
        operationId: 'issueSshCertificate', access: 'person',
        recentAuth: true, body: ISSUE_FORM, scopes: SSH_SCOPES,
        handler: function (req, res, caller: AccountCaller,
                           input): Promise<unknown> {
          return self.issue(ctx, req, res, caller, input.body);
        }
      },
      {
        method: 'POST', path: ctx.BASE + '/ssh/certificates/revoke',
        operationId: 'revokeSshCertificate', access: 'person',
        recentAuth: true, body: REVOKE_FORM, scopes: SSH_SCOPES,
        handler: function (req, res, caller: AccountCaller,
                           input): Promise<unknown> {
          return self.revoke(ctx, req, res, caller, input.body);
        }
      }
    ];
    log.debug("Leaving AccountSshUserCa.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountSshUserCa>(
  'account-api/ssh_user_ca',
  () => new AccountSshUserCa(AccountSshUserCa.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The Account API's SSH user certificate operations (#1955 P3).
 * @namespace
 */
export = {
  AccountSshUserCa: AccountSshUserCa,
  installInstance: (instance: AccountSshUserCa): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
