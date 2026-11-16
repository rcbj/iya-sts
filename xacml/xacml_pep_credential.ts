// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_credential.ts
//
// ===========================================================================
// A REMOTE PEP'S ASSERTION KEY, CERTIFIED FROM ITS OWN REQUEST (#1827's
// follow-up, phase 3 of the rcbj-approved plan, 2026-11-16).
//
// Phases 1 and 2 made a remote PEP reach the service on a DPoP-bound access
// token from the RFC 7523 self-assertion grant through `sts-remote-pep`,
// signed with ONE key (`PEP_ASSERTION_KEY`). The grant accepts that key only
// where it is REGISTERED on the PEP's entry as a purpose=jwt key
// (`stsAssertionKeyPair`), and this is the act that registers it:
// `issue-pep-credential`, on the remote PEP's console page and on
// `POST /admin-api/xacml/issue-pep-credential` (rule 7).
//
// **rcbj's two decisions shape it.** DECISION 4: the PEP's certificate is
// ISSUED BY THE REALM'S INTERNAL CA — never self-signed, never an outside
// authority. And (2026-11-16): **THE SERVICE NEVER HOLDS THE PEP'S PRIVATE
// KEY.** The PEP, or the tool provisioning it (`tests/tools/pep-credential.js
// --assertion`), generates the key pair and sends a PKCS #10 request; the
// realm's Issuing CA certifies the public key in it
// (`person_assertions.certifyRequest()` over `pki.certifySigningRequest()`),
// and the leaf is registered as the entry's RFC 7523 key with no private
// half anywhere. `POST /admin-api/pki/issue target=person purpose=jwt`, which
// generates a key and keeps a sealed copy, is unchanged and is not the route
// for a PEP.
//
// ---------------------------------------------------------------------------
// WHO A KEY IS CERTIFIED FOR: THE ENTRY A PEP DOOR WOULD ADMIT, AND NOBODY
// ELSE. The name is a username under this realm's `ou=users`, and the entry
// must be
//
//   1. THERE (STS-XACML-0298) — a key is certified for an entry that exists,
//      never one invented to hold it;
//   2. A SERVICE ACCOUNT (STS-XACML-0299) — a remote PEP's identity is one
//      (#1760's `designateRemotePep()`), and its leaf names it
//      `urn:sts:sa:<name>`, decided at issue from the entry;
//   3. A HOLDER OF REMOTE_PEPS (STS-XACML-0301) — in the group
//      `roles.remotePepGroup` names. A key for an entry the PEP doors refuse
//      would be a credential that authenticates and is then refused at every
//      call, which reads as a broken PEP rather than a missing membership.
//
// **NO REGISTERED `ou=peps` ROW IS ASKED FOR**, which is where this differs
// from `issue-pep-certificate`: that certificate is the PEP's front door and
// its names come from the row; this key is how the PEP reaches the service at
// all, so it is provisioned BEFORE the PEP has ever registered.
//
// ---------------------------------------------------------------------------
// ROTATION: A NEW KEY IS ADDED, AND `revokePrevious` IS ASKED FOR.
//
// A person's key pairs are ADDED, several per profile up to
// `pki.personSigningKeyMax`, each revoked on its own (#1290) — so a key on a
// laptop and a key in a CI job do not break each other. A PEP's rotation is
// the same shape: the new key is registered, the PEP is restarted (or its
// file replaced; `credential.rs` re-reads it) onto it, and the old key is
// revoked. Revoking the old one IN THE SAME ACT would cut off a running PEP
// before it holds the new key, so it is not the default: `revokePrevious:
// true` revokes every OTHER valid RFC 7523 key of the entry
// (`cessationOfOperation`, onto its authority's CRL), AFTER the new one is
// written — or, where the entry is at the cap, BEFORE, since there is no
// room for the new one otherwise. A revocation that fails leaves the new key
// working and is reported (STS-XACML-0302).
//
// ---------------------------------------------------------------------------
// WHAT THE ANSWER CARRIES: the leaf, its chain and the chain through the
// Root, the `kid`, the urn, the validity — public material only — and the
// environment the PEP is started with: `PEP_NAME` (the username, which is
// the `iss` and `sub` of its self-assertion), `PEP_CLIENT_ID`
// (`sts-remote-pep`) and `PEP_ASSERTION_KEY` (the path of the key file the
// CALLER kept; this service never saw it). The act is audited with the
// name, the kid and the serial, never the certificate.
//
// A LIBRARY: it registers no route. `xacml_admin.ts` answers the action for
// the console and `/admin-api`.
// ===========================================================================

import helpers = require('../common/helpers');
import audit = require('../common/audit');
import errorCodes = require('../common/error_codes');

type Json = any;

/**
 * The client a remote PEP's token is issued through, which the answer's
 * environment names.
 */
const PEP_CLIENT_ID = 'sts-remote-pep';

/**
 * The built-in role a remote PEP's entry holds through its group.
 */
const REMOTE_PEP_ROLE = 'REMOTE_PEPS';

// What `issue()` answers. A refusal carries its code under a Symbol
// (`errorCodes.mark()`).
interface CredentialResult {
  ok: boolean;
  why?: string;
  [member: string]: unknown;
}

interface PepCredentialDeps {
  log: typeof helpers.log;
  audit: { audit(row: object): unknown };
  errorCodes: {
    mark<T>(result: T, code: string): T;
    codeOf(result: unknown): string | null | undefined;
  };
  // `common/person_assertions.js`: the entry, the one CSR door, the keys
  // held and their revocation.
  personAssertions: {
    entryExists(username: string): boolean;
    atCap(username: string, purpose: string): boolean;
    listFor(username: string, purpose: string): Json[];
    certifyRequest(username: string, csr: string, opts: object): Promise<Json>;
    revoke(username: string, purpose: string, handle: string,
           reason: string, opts: object): Json;
  };
  // `common/service_accounts.ts`'s `of()`: null where the entry is not a
  // service account.
  serviceAccountOf(username: string): { dn: string; username: string } | null;
  // `common/roles.js`'s `rolesOf()`.
  rolesOf(who: object): string[];
  // The leaf followed by its chain through the Root (`pki.chainThroughRoot`).
  chainThroughRoot(certificatePem: string, chainPem: string[]): string[];
  // The ambient realm's id.
  realmId(): string;
  // `roles.remotePepGroup`, for the refusal's sentence.
  remotePepGroup(): string;
}

/**
 * Certifies and registers a remote PEP's RFC 7523 assertion key from the
 * PEP's own certificate request (#1827's follow-up, phase 3). The service
 * never holds the private key.
 */
class PepCredential {
  /**
   * The client the PEP's token is issued through.
   */
  static readonly PEP_CLIENT_ID = PEP_CLIENT_ID;

  /**
   * Builds the act over its dependencies.
   *
   * @param deps - the logger, audit log, error codes, person key register,
   *   service accounts, roles, chain builder and realm
   */
  constructor(private readonly deps: PepCredentialDeps) {
    deps.log.debug("Entering PepCredential.constructor().");
    deps.log.debug("Leaving PepCredential.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules. Every module is
   * reached LAZILY: `person_assertions.js` and `roles.js` are on `app.js`'s
   * chain and `service_accounts.ts` and `pki.js` are libraries, all loaded
   * long before an administrator issues anything.
   *
   * @returns the dependencies
   */
  static defaultDeps(): PepCredentialDeps {
    helpers.log.debug("Entering PepCredential.defaultDeps().");
    helpers.log.debug("Leaving PepCredential.defaultDeps().");
    return {
      log: helpers.log,
      audit: audit,
      errorCodes: errorCodes,
      personAssertions: {
        entryExists: function (username: string): boolean {
          helpers.log.debug("Entering entryExists().");
          helpers.log.debug("Leaving entryExists().");
          return require('../common/person_assertions')
            .entryExists(username);
        },
        atCap: function (username: string, purpose: string): boolean {
          helpers.log.debug("Entering atCap().");
          helpers.log.debug("Leaving atCap().");
          return require('../common/person_assertions')
            .atCap(username, purpose);
        },
        listFor: function (username: string, purpose: string): Json[] {
          helpers.log.debug("Entering listFor().");
          helpers.log.debug("Leaving listFor().");
          return require('../common/person_assertions')
            .listFor(username, purpose);
        },
        certifyRequest: function (username: string, csr: string,
                                  opts: object): Promise<Json> {
          helpers.log.debug("Entering certifyRequest().");
          helpers.log.debug("Leaving certifyRequest().");
          return require('../common/person_assertions')
            .certifyRequest(username, csr, opts);
        },
        revoke: function (username: string, purpose: string, handle: string,
                          reason: string, opts: object): Json {
          helpers.log.debug("Entering revoke().");
          helpers.log.debug("Leaving revoke().");
          return require('../common/person_assertions')
            .revoke(username, purpose, handle, reason, opts);
        }
      },
      serviceAccountOf: function (username: string): any {
        helpers.log.debug("Entering serviceAccountOf().");
        helpers.log.debug("Leaving serviceAccountOf().");
        return require('../common/service_accounts').of(username);
      },
      rolesOf: function (who: object): string[] {
        helpers.log.debug("Entering rolesOf().");
        helpers.log.debug("Leaving rolesOf().");
        return require('../common/roles').rolesOf(who);
      },
      chainThroughRoot: function (certificatePem: string,
                                  chainPem: string[]): string[] {
        helpers.log.debug("Entering chainThroughRoot().");
        helpers.log.debug("Leaving chainThroughRoot().");
        return require('../common/pki').chainThroughRoot(certificatePem,
                                                         chainPem);
      },
      realmId: function (): string {
        helpers.log.debug("Entering realmId().");
        let id = '';
        try {
          id = String(require('../common/realms').currentId() || '');
        } catch (e) {
          // No realm module in a bare test process: the default realm.
          helpers.log.debug("Caught in realmId(): " +
                            ((e && e.message) || e));
          id = '';
        }
        helpers.log.debug("Leaving realmId().");
        return id;
      },
      remotePepGroup: function (): string {
        helpers.log.debug("Entering remotePepGroup().");
        helpers.log.debug("Leaving remotePepGroup().");
        return String(require('../common/config')
          .value('roles.remotePepGroup') || '');
      }
    };
  }

  // A refusal in the shape `xacml_admin.ts` answers: `why`, and the code.
  private refuse(code: string, why: string): CredentialResult {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PepCredential.refuse(). code=" + code);
    log.debug("Leaving PepCredential.refuse().");
    return errorCodes.mark({ ok: false, why: why }, code);
  }

  /**
   * Certifies the key in a remote PEP's own PKCS #10 request from the
   * realm's Issuing CA and registers it as the PEP entry's RFC 7523 key.
   *
   * The entry must exist (STS-XACML-0298), be a service account
   * (STS-XACML-0299) and hold REMOTE_PEPS (STS-XACML-0301). The request's
   * names are ignored; the leaf names `urn:sts:sa:<name>`. Audited, with no
   * key material.
   *
   * @param body - `name` (or `pep`): the PEP's username; `csr`: the request
   *   (PEM or base64 DER); optionally `label`, `days` and `revokePrevious`
   * @returns a promise of the result: the certificate, its chain, `kid`,
   *   `urn`, and the PEP's `environment`; or a refusal with its code
   */
  async issue(body?: Json): Promise<CredentialResult> {
    const { log, audit, errorCodes, personAssertions } = this.deps;
    const self = this;
    log.debug('Entering PepCredential.issue(). name=' + (body || {}).name);
    const b = body || {};
    const name = String(b.name || '').trim();
    if (!name) {
      log.debug('Leaving PepCredential.issue(). No name.');
      return self.refuse('STS-XACML-0298', 'Which remote PEP? Send `name` ' +
                         '(or `pep`): the username of its entry under this ' +
                         'realm\'s ou=users.');
    }
    if (!personAssertions.entryExists(name)) {
      log.debug('Leaving PepCredential.issue(). No entry.');
      return self.refuse('STS-XACML-0298', 'There is nobody called "' +
                         name + '" in this realm\'s ou=users. A remote ' +
                         'PEP\'s key is certified for the entry it ' +
                         'authenticates as: create it (a service account ' +
                         'in the remote PEPs group) first.');
    }
    const account = self.deps.serviceAccountOf(name);
    if (!account) {
      log.debug('Leaving PepCredential.issue(). Not a service account.');
      return self.refuse('STS-XACML-0299', '"' + name + '" is not a ' +
                         'service account. A remote PEP\'s identity is one, ' +
                         'and its key names it urn:sts:sa:' + name + '. ' +
                         'Putting the entry in the remote PEPs group makes ' +
                         'it one; so does /admin/users\' Service account ' +
                         'tab.');
    }
    const held = self.deps.rolesOf({ kind: 'user', name: account.dn,
                                     authenticated: true });
    if (held.indexOf(REMOTE_PEP_ROLE) < 0) {
      log.debug('Leaving PepCredential.issue(). No REMOTE_PEPS.');
      return self.refuse('STS-XACML-0301', '"' + name + '" does not hold ' +
                         REMOTE_PEP_ROLE + ': it is not a member of the ' +
                         'group roles.remotePepGroup names ("' +
                         self.deps.remotePepGroup() + '"). A key for it ' +
                         'would authenticate an entry every PEP door ' +
                         'refuses. Add it to the group first.');
    }
    const revokePrevious = b.revokePrevious === true ||
                           String(b.revokePrevious) === 'true' ||
                           String(b.revokePrevious) === 'on';
    // THE OTHER KEYS, READ BEFORE THE NEW ONE IS WRITTEN, so the new one is
    // never among those revoked.
    const others = revokePrevious
      ? personAssertions.listFor(name, 'jwt').filter(function (one: Json) {
        return one.state === 'valid';
      })
      : [];
    const revoked: string[] = [];
    const failed: string[] = [];
    const revokeOthers = function (): void {
      log.debug('Entering revokeOthers(). ' + others.length);
      others.forEach(function (one: Json) {
        const done = personAssertions.revoke(name, 'jwt', String(one.id),
          'cessationOfOperation',
          { initiatingEntity: 'admin', via: 'issue-pep-credential' });
        if (done && done.ok) {
          revoked.push(String(one.id));
        } else {
          failed.push(String(one.id));
        }
      });
      log.debug('Leaving revokeOthers(). ' + revoked.length + ' revoked.');
    };
    // AT THE CAP, THE ROOM IS MADE FIRST — see the header.
    const roomFirst = revokePrevious &&
                      personAssertions.atCap(name, 'jwt');
    if (roomFirst) {
      revokeOthers();
    }
    const label = String(b.label || '').trim() || 'remote PEP';
    const days = Number(b.days);
    const made = await personAssertions.certifyRequest(name,
      typeof b.csr === 'string' ? b.csr : '', {
        serviceAccount: true,
        label: label,
        days: isFinite(days) && days > 0 ? Math.floor(days) : undefined,
        initiatingEntity: 'admin',
        via: 'issue-pep-credential'
      });
    if (!made.ok) {
      log.debug('Leaving PepCredential.issue(). Not certified.');
      return errorCodes.mark({ ok: false,
               why: (made.errors || []).join(' ') ||
                    'The key could not be certified.',
               revoked: revoked },
               made.errorCode || errorCodes.codeOf(made) || 'STS-PKI-0278');
    }
    if (revokePrevious && !roomFirst) {
      revokeOthers();
    }
    const issued = made.issued;
    const chainPem: string[] = (issued.chainPem || []).slice();
    const fullChainPem = self.deps.chainThroughRoot(issued.certificatePem,
                                                    chainPem)
      .map(function (one: string) {
        return String(one).replace(/\s*$/, '\n');
      }).join('');
    audit.audit({ action: 'xacml.pep.credential', actor: '',
                  protocol: 'XACML',
                  detail: 'Certified the ' + issued.keyAlg + ' key in remote ' +
                          'PEP "' + name + '"\'s own certificate request as ' +
                          'its RFC 7523 assertion key (' + issued.subjectUri +
                          ', kid ' + issued.kid + ', serial ' +
                          issued.serialHex + ', expires ' + issued.notAfter +
                          '). The private key was never here.' +
                          (revoked.length
                            ? ' Revoked its other key(s): ' +
                              revoked.join(', ') + '.'
                            : '') +
                          (failed.length
                            ? ' Could not revoke: ' + failed.join(', ') + '.'
                            : '') });
    const environment = {
      PEP_NAME: name,
      PEP_CLIENT_ID: PEP_CLIENT_ID,
      PEP_ASSERTION_KEY: '<the path of the private key you generated the ' +
                         'request with>'
    };
    const what = 'Certified the ' + issued.keyAlg + ' key in "' + name +
      '"\'s certificate request from this realm\'s Issuing CA as ' +
      issued.subjectUri + ' and registered it as its RFC 7523 assertion ' +
      'key (kid ' + issued.kid + ', valid until ' + issued.notAfter + '). ' +
      'THIS SERVICE NEVER HAD THE PRIVATE KEY: start the PEP with ' +
      'PEP_ASSERTION_KEY naming the key file you made the request with, ' +
      'PEP_NAME=' + name + ' and PEP_CLIENT_ID=' + PEP_CLIENT_ID + '.' +
      (revoked.length
        ? ' Its ' + revoked.length + ' other key(s) are revoked.'
        : (revokePrevious ? '' : ' Any key it held before still works; ' +
                                 'revoke it once the PEP runs on this one.'));
    if (failed.length) {
      log.debug('Leaving PepCredential.issue(). A revocation failed.');
      return errorCodes.mark({ ok: false,
               why: what + ' Revoking its other key(s) ' + failed.join(', ') +
                    ' failed, so they still work: revoke them on ' +
                    '/admin/users.',
               pep: name, kid: issued.kid, revoked: revoked },
               'STS-XACML-0302');
    }
    log.debug('Leaving PepCredential.issue(). kid=' + issued.kid);
    return {
      ok: true,
      what: what,
      pep: name,
      realm: self.deps.realmId(),
      urn: issued.subjectUri,
      kid: issued.kid,
      keyAlg: issued.keyAlg,
      jwsAlg: issued.jwsAlg,
      serialHex: issued.serialHex,
      subject: issued.subject,
      notBefore: issued.notBefore,
      notAfter: issued.notAfter,
      certificatePem: issued.certificatePem,
      chainPem: chainPem,
      fullChainPem: fullChainPem,
      environment: environment,
      revoked: revoked
    };
  }
}

export = PepCredential;
