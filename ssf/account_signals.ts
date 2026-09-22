'use strict';
// ---------------------------------------------------------------------------
// ssf/account_signals.ts — WHAT A CREDENTIAL CHANGE SAYS OVER SHARED SIGNALS,
// FOR THE DOORS THAT MAKE ONE (2026-09-13).
//
// The administrator's controls on a person's /admin/users page (and the same
// actions on /admin-api/users) reset passwords, issue reset links, and take
// security keys, authenticator apps and recovery codes off an entry; the user
// portal's /portal/reset-password sets the password a link was for. Each of
// those is a CAEP `credential-change`, and a password reset or a cleared set of
// recovery codes is also a RISC event. `ssf/ssf.ts` is what turns them into
// Security Event Tokens — `emitCredentialChange()` and `emitRiscAccountAct()`.
//
// **THIS FILE EXISTS BECAUSE THOSE DOORS CANNOT REQUIRE `ssf/ssf.ts`.** The
// console's actions are at 18 in the require order, the portal just after
// `authn` (8), and SSF at 23b: a require from either would have registered
// every `/ssf` route ahead of theirs (rule 1) and would close a cycle through
// `admin-ui/admin.ts`. Since #50's R1 the first half is gone — requiring
// `ssf.ts` registers nothing, and `common/protocol_stack.ts` registers its
// routes at 23b — but the cycle, and SSF's load-time effects moving to 8,
// are not. So this is a LIBRARY that requires nothing but the
// logger, and it reads `ssf.ts` out of `require.cache` at the moment an event
// is due — which, in a running service, is always after the whole stack has
// loaded. A process that never loaded SSF (an in-process test, the parent
// project's Kerberos jobs) gets a no-op, and is told so in the answer rather
// than by a thrown `Cannot find module`.
//
// **NOT A SLOT, AND RULE 3e'S TEST SAYS WHY.** A slot is the price of a require
// that would close a cycle or move a route; there is no require here at all,
// only a cache lookup, which is the arrangement
// `admin-core/protocol_endpoints.ts` uses for route-registering modules it
// must never load.
//
// **NOTHING HERE WAITS AND NOTHING HERE THROWS.** Every function returns a
// promise that resolves, and callers do not await it: a receiver's endpoint
// being slow must not hold up a page, and a failure must not undo a credential
// change that has already been written.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AccountSignals` takes the logger and the way to find a loaded
// `ssf.ts` through its constructor, and the module still exports the old
// names from a TRANSITIONAL instance for `admin-core/admin_actions.ts` and
// `portal/portal.ts`, which are not converted.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// The certificate's issuer and serial for `x509` changes (#145). A LEAF
// library, loaded by `helpers.js` long before this file: the require moves
// nothing and closes no cycle.
import stsCrypto = require('../common/crypto');

// What a delivery answers. `sent` and `streams` are `ssf.ts`'s own counts
// when it ran; `why` is set when nothing was sent.
interface Delivery {
  sent: number;
  streams: number;
  why?: string;
  [member: string]: unknown;
}

// The two `ssf.ts` emitters this module calls, and nothing else of it.
interface SsfEmitters {
  emitCredentialChange?(notice: object): Delivery | Promise<Delivery>;
  emitRiscAccountAct?(notice: object): Delivery | Promise<Delivery>;
}

type EmitterName = 'emitCredentialChange' | 'emitRiscAccountAct';

interface AccountSignalsDeps {
  log: { debug(m: string): void; warn(m: string): void };
  // `ssf.ts`'s exports when that module is loaded in this process, else null.
  // Never a require: see the header.
  findSsf(): SsfEmitters | null;
}

// A CAEP credential-change, as the doors describe it.
interface CredentialChange {
  username?: string;
  credentialType?: string;
  changeType?: string;
  friendlyName?: string;
  initiatingEntity?: string;
  reasonAdmin?: string;
  reasonUser?: string;
  via?: string;
  // CAEP's three identifying members (#145): the certificate a change is
  // about, and the security key's AAGUID, where the door knows them.
  x509Issuer?: string;
  x509Serial?: string;
  fido2Aaguid?: string;
}

class AccountSignals {
  // A security key, in CAEP's credential-type vocabulary. Since #145
  // (2026-09-22) a key's record keeps the authenticator attachment the
  // browser reported at enrolment, and keyCredentialType() reads it:
  // `platform` is `fido2-platform`, anything else `fido2-roaming`. A key
  // enrolled before that date has no attachment recorded and stays
  // `fido2-roaming`, the reading that is true of every key this service's
  // ceremony enrolled by default.
  static readonly KEY_CREDENTIAL_TYPE = 'fido2-roaming';
  static readonly PLATFORM_KEY_CREDENTIAL_TYPE = 'fido2-platform';
  // An authenticator app, in the same vocabulary: CAEP's `app`.
  static readonly TOTP_CREDENTIAL_TYPE = 'app';

  constructor(private readonly deps: AccountSignalsDeps) {
    deps.log.debug('Entering AccountSignals.constructor().');
    deps.log.debug('Leaving AccountSignals.constructor().');
  }

  // What the composition root passes: the service logger, and the
  // `require.cache` lookup below as the way to find a loaded `ssf.js`.
  static defaultDeps(): AccountSignalsDeps {
    helpers.log.debug('Entering AccountSignals.defaultDeps().');
    helpers.log.debug('Leaving AccountSignals.defaultDeps().');
    return { log: helpers.log, findSsf: AccountSignals.loadedSsf };
  }

  // `ssf.ts` as it is loaded in THIS process, found in `require.cache`, or
  // null. The default `findSsf` for the transitional instance below.
  static loadedSsf(): SsfEmitters | null {
    const { log } = helpers;
    log.debug('Entering AccountSignals.loadedSsf().');
    let id = '';
    try {
      id = require.resolve('./ssf');
    } catch (e) {
      log.debug('Caught in AccountSignals.loadedSsf(): ' +
                ((e && e.message) || e));
      log.debug('Leaving AccountSignals.loadedSsf(). Not resolvable.');
      return null;
    }
    const cached = require.cache[id];
    log.debug('Leaving AccountSignals.loadedSsf(). ' +
              (cached ? 'Loaded.' : 'Not loaded.'));
    return cached && cached.exports ? cached.exports as SsfEmitters : null;
  }

  // Hand one call to ssf.ts, swallowing everything, so a caller can fire and
  // forget. `what` names the call for the log.
  private deliver(what: string, name: EmitterName,
                  notice: object): Promise<Delivery> {
    const { log, findSsf } = this.deps;
    log.debug('Entering AccountSignals.deliver(). ' + what);
    const ssf = findSsf();
    const emit = ssf ? ssf[name] : undefined;
    if (!ssf || typeof emit !== 'function') {
      log.debug('Leaving AccountSignals.deliver(). Shared Signals is not ' +
                'loaded in this process, so nothing is sent.');
      return Promise.resolve({ sent: 0, streams: 0, why: 'ssf not loaded' });
    }
    let answer: Promise<Delivery>;
    try {
      answer = Promise.resolve(emit.call(ssf, notice));
    } catch (e) {
      log.warn('account signals: ' + what + ' threw and nothing was sent: ' +
               ((e && e.message) || e));
      log.debug('Leaving AccountSignals.deliver(). Threw.');
      return Promise.resolve({ sent: 0, streams: 0,
                               why: String(e && e.message) });
    }
    log.debug('Leaving AccountSignals.deliver(). Handed over.');
    return answer.catch(function (e): Delivery {
      log.warn('account signals: ' + what + ' failed and nothing more is ' +
               'sent: ' + ((e && e.message) || e));
      return { sent: 0, streams: 0, why: String((e && e.message) || e) };
    });
  }

  // A key record's CAEP credential type, from its recorded attachment.
  static keyCredentialType(record?: { attachment?: string } | null): string {
    helpers.log.debug('Entering AccountSignals.keyCredentialType().');
    helpers.log.debug('Leaving AccountSignals.keyCredentialType().');
    return record && record.attachment === 'platform'
      ? AccountSignals.PLATFORM_KEY_CREDENTIAL_TYPE
      : AccountSignals.KEY_CREDENTIAL_TYPE;
  }

  // CAEP credential-change.
  credentialChanged(change?: CredentialChange): Promise<Delivery> {
    const { log } = this.deps;
    log.debug('Entering AccountSignals.credentialChanged().');
    log.debug('Leaving AccountSignals.credentialChanged().');
    return this.deliver('a CAEP credential-change', 'emitCredentialChange',
                        change || {});
  }

  // CAEP credential-change about an X.509 certificate (#145): `pem` is the
  // certificate, and its issuer and serial go out as `x509_issuer` and
  // `x509_serial` — a serial names a certificate only beside its issuer.
  certificateChanged(change?: CredentialChange & { pem?: string }):
      Promise<Delivery> {
    const { log } = this.deps;
    log.debug('Entering AccountSignals.certificateChanged().');
    const asked = change || {};
    const ids = stsCrypto.certificateIdentifiers(asked.pem || '');
    const notice: CredentialChange = Object.assign({}, asked, {
      credentialType: 'x509',
      x509Issuer: asked.x509Issuer || ids.issuer,
      x509Serial: asked.x509Serial || ids.serial });
    delete (notice as { pem?: string }).pem;
    log.debug('Leaving AccountSignals.certificateChanged().');
    return this.credentialChanged(notice);
  }

  // RISC account-credential-change-required: a password was reset for
  // somebody or a reset link issued, so what they held is no longer trusted.
  credentialChangeRequired(notice?: object): Promise<Delivery> {
    const { log } = this.deps;
    log.debug('Entering AccountSignals.credentialChangeRequired().');
    log.debug('Leaving AccountSignals.credentialChangeRequired().');
    return this.deliver('a RISC account-credential-change-required',
                        'emitRiscAccountAct',
                        Object.assign({}, notice || {},
                                      { act: 'credentialChangeRequired' }));
  }

  // RISC recovery-information-changed: somebody's recovery codes were
  // cleared.
  recoveryInformationChanged(notice?: object): Promise<Delivery> {
    const { log } = this.deps;
    log.debug('Entering AccountSignals.recoveryInformationChanged().');
    log.debug('Leaving AccountSignals.recoveryInformationChanged().');
    return this.deliver('a RISC recovery-information-changed',
                        'emitRiscAccountAct',
                        Object.assign({}, notice || {},
                                      { act: 'recoveryChanged' }));
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that instance, for
// the JavaScript that still calls this module through `require()`; a process
// that never runs the root gets a default instance, built from
// `defaultDeps()` on first use (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AccountSignals>(
  'ssf/account_signals',
  () => new AccountSignals(AccountSignals.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  AccountSignals: AccountSignals,
  installInstance: (instance: AccountSignals): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  credentialChanged: slot.forward('credentialChanged'),
  certificateChanged: slot.forward('certificateChanged'),
  credentialChangeRequired: slot.forward('credentialChangeRequired'),
  recoveryInformationChanged: slot.forward('recoveryInformationChanged'),
  KEY_CREDENTIAL_TYPE: AccountSignals.KEY_CREDENTIAL_TYPE,
  keyCredentialType: AccountSignals.keyCredentialType,
  TOTP_CREDENTIAL_TYPE: AccountSignals.TOTP_CREDENTIAL_TYPE
};
