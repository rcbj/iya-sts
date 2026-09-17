'use strict';
//
// File: risc.ts
//
// ---------------------------------------------------------------------------
// THE RISC ACCOUNT REGISTER, AND THE SECOND THING IN THIS DIRECTORY THAT IS
// NOT VOCABULARY.
//
// `ssf_events.js` carries RISC's fourteen event types, because that file is
// the VOCABULARY and the whole design of this family says a vocabulary is rows
// in its table. This file is the thing those rows are ABOUT: an ACCOUNT, what
// state RISC believes it is in, and how many events of which type have been
// sent concerning it.
//
// It is `caep.ts`'s sibling and not its generalization, and the reason is the
// one that decided the whole design of both: **a session and an account are
// not the same kind of thing, and merging them would have meant a register
// whose row is sometimes one and sometimes the other.** A session begins, is
// used and ends, and there are many of them per person. An account is the
// person, has no beginning this service can see, and outlives every session on
// it. CAEP says *this session is no longer trustworthy* and RISC says *this
// account is no longer trustworthy*, and the second sentence is the larger one
// by orders of magnitude: a revoked session is one sign-in at one relying
// party, and a purged account is every session that person has anywhere, for
// ever.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). IT REGISTERS NO ROUTE AND IT SENDS NOTHING.
//
// It requires `helpers`, `config`, `realms`, `mode`, `audit`, `ssf_events` and
// `ssf_subjects` and nothing else, so it cannot join a cycle — and in
// particular it does NOT require `ssf.ts`, which requires IT. The division of
// labour is `caep.ts`'s exactly:
//
//   THIS FILE DECIDES WHAT AN EVENT WOULD BE. `observe()` takes a notice about
//   a directory write and ANSWERS with the events that ought to go out.
//
//   `ssf.ts` DECIDES WHERE THEY GO. It holds `transmit()`, the streams and the
//   deliveries.
//
// ---------------------------------------------------------------------------
// FOUR THINGS HERE ARE NOT WHAT `caep.ts` DOES, AND EACH IS THE SPECIFICATION
// RATHER THAN A PREFERENCE.
//
// **`observe()` RETURNS AN ARRAY AND CAEP's RETURNS ONE EVENT.** A session act
// is one act: a sign-in is a sign-in. A directory write is not — one `PUT
// /Users/:id` can set `active` to false AND change a mail address, which is
// two RISC events about one write, and a version of this that returned the
// first would drop the second silently. There is no "unknown event type" error
// in this protocol and there is no missing-event error either.
//
// **THE REGISTER IS KEYED ON THE PERSON AND NOT ON THE SUBJECT.** CAEP's is
// keyed on a session identifier, which is one string that never changes. A
// RISC subject is composed in whichever RFC 9493 format `risc.subjectFormat`
// names — and the two identifier events IGNORE that setting and use `email`,
// because their subject carries the identifier that moved. So one account
// legitimately produces two different `subjectKey()`s, and a register keyed on
// the subject would split one person into two rows **at exactly the moment
// their identifier changed**, which is the one moment the row is worth having.
//
// **THE STATE IS THREE THINGS AND NOT ONE.** A CAEP row has `state`, because a
// session is alive or it is not. An account has a LIFECYCLE (active, disabled,
// purged), an OPT-OUT state (RISC section 2.8's own three), and a CREDENTIAL
// standing — and they move independently. An account can be opted out and
// perfectly healthy, or compromised and still enabled. Folding them into one
// word would have meant choosing which of three questions the page answers.
//
// **AND THERE IS A GATE, WHICH CAEP HAS NO EQUIVALENT OF.** RISC section 2.8
// says an account in the `opt-out` state is NOT participating in event
// exchange, so a conforming transmitter stops sending about it. See gate()
// below for the exception that makes the rule work at all.
//
// ---------------------------------------------------------------------------
// THE REGISTER OUTLIVES THE ACCOUNT, AND MORE STARKLY THAN CAEP'S DOES.
//
// `caep.ts`'s row outlives a session the session store has forgotten. This one
// outlives an account that has been DELETED FROM THE DIRECTORY ENTIRELY — a
// row whose lifecycle is `purged` is the only remaining evidence anywhere that
// this service ever told anybody the account was purged, and *"did anything go
// out when I deleted that person?"* is the entire question
// /admin/risc-accounts answers. `risc.maxAccountsTracked` caps it and the
// oldest goes first.
//
// **IT IS PER TRUST REALM, AND PERSISTED WHERE MINTED STATE IS, SINCE
// 2026-09-12** — `caep.ts`'s register's change, made the same day and for the
// same two reasons. It was one `new Map()` for the process while the directory
// whose writes it observes has been a subtree per realm since 2026-08-25, so
// deleting `alice` in `acme` put a `purged` row on the DEFAULT realm's
// /admin/risc-accounts beside a directory that still held its own `alice`. And
// "in memory like everything else this service mints" stopped being true in
// product mode on 2026-09-06. `touch()` below reports a row edited in place.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `RiscRegister` takes the logger and three readers of `helpers.js`,
// `config`, `mode`, `audit`, the SSF vocabulary and the subject library
// through its constructor. The register itself stays a module-level
// `realms.map()`, declared at load as before, so it is still per realm and
// still persisted. The module still exports its old names — the
// `EVENTS_PER_ACCOUNT` getter among them — as FACADES forwarding to the
// instance the composition root builds (#50, R2), for `ssf/ssf.ts`, the
// console and the tests. A process that loads this module without the root
// builds a default instance when the module loads.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// The partition. A LEAF requiring `config` and the error-code registry and
// nothing else here.
import realms = require('../common/realms');
// For `inventsClaimValues()` in `defaultEmailFor()`. A leaf requiring only
// config.
import mode = require('../common/mode');
import audit = require('../common/audit');
import events = require('./ssf_events');
import subjects = require('./ssf_subjects');

// One register row. See `blankRow()`.
interface RiscRow {
  accountId: string;
  sub: string;
  username: string;
  iss: string;
  dn: string;
  realm: string;
  email: string;
  phone: string;
  subject?: string;
  formerIdentifiers: string[];
  createdAt: string;
  updatedAt: string;
  lifecycle: string;
  optOut: string;
  credentialStanding: string;
  credentialChangeRequired: boolean;
  recoveryActivated: boolean;
  identifierChanges: any[];
  credentials: any[];
  counts: Record<string, number>;
  total: number;
  suppressed: number;
  events: any[];
  streams: string[];
  notes: string[];
  [member: string]: any;
}

// An act, as `actsFor()` and `observeAct()` describe one.
interface RiscAct {
  act: string;
  values?: Record<string, any>;
  subject?: Record<string, any>;
}

// What `observe()` and `observeAct()` answer, one per event due.
interface DueEvent {
  uri: string;
  payload: Record<string, any>;
  subject: Record<string, any> | null;
  row: RiscRow;
  act: string;
}

interface RiscRegisterDeps {
  log: { debug(m: string): void; info(m: string): void;
         warn(m: string): void };
  nowSec(): number;
  iso(): string;
  nameForSubject(subject: string): string;
  config: { value(key: string): any };
  mode: { inventsClaimValues(): boolean };
  audit: { audit(row: object): unknown };
  events: {
    RISC_PREFIX: string;
    RISC_EVENT_URIS: string[];
    RISC_EVENTS: any[];
    EVENT_BY_URI: Record<string, any>;
  };
  subjects: {
    describeSubject(subject: unknown): string;
    subjectForUser(name: string, format: string, iss: string,
                   facts?: Record<string, any>): Record<string, any>;
  };
}

// The four acts this service can actually OBSERVE in its own directory, and
// their event types. Short names, because that is what `risc.autoEmitTypes`
// holds and a setting whose values were 60-character URIs is a setting nobody
// can type.
//
// **THERE IS NO ACT FOR AN ACCOUNT BEING CREATED**, and that is RISC's
// omission rather than this file's: the vocabulary has fourteen event types
// and not one of them says a new account exists. It is worth knowing why —
// RISC is aimed ACROSS providers, and a relying party learns that an account
// exists when somebody signs in with it. What it cannot learn any other way is
// that one has stopped being trustworthy.
const AUTO_ACTS: Record<string, string> = {
  purged: 'account-purged',
  disabled: 'account-disabled',
  enabled: 'account-enabled',
  identifier: 'identifier-changed',
  // TWO ACTS AN ADMINISTRATOR PERFORMS (2026-09-13), on a person's
  // /admin/users page or through /admin-api/users, and they reach this file
  // through `observeAct()` rather than through a directory diff: a password
  // reset or a reset link REQUIRES a credential change, and clearing somebody's
  // recovery codes changes the information they recover their account with.
  // Neither is a write `actsFor()` could read off the attributes — a password
  // hash moving says nothing about who required what.
  credentialChangeRequired: 'account-credential-change-required',
  recoveryChanged: 'recovery-information-changed'
};

// The four events RISC section 2.8 defines as BEING a state rather than as
// reporting one — "the account is in the opt-in state" — which is why emitting
// one from the console moves the register. They are also the four the opt-out
// gate must never suppress; see gate().
const OPT_OUT_EVENTS: Record<string, string> = {
  'opt-in': 'opt-in',
  'opt-out-initiated': 'opt-out-initiated',
  'opt-out-cancelled': 'opt-in',
  'opt-out-effective': 'opt-out'
};

// RISC section 2.8's three states, in the order the specification's own
// diagram walks them.
const OPT_STATES = ['opt-in', 'opt-out-initiated', 'opt-out'];

// The three lifecycle states, and `purged` is TERMINAL. RISC calls it
// "permanently deleted", which is the strongest word in the vocabulary and the
// only one this register enforces anything on — see applyToState().
const LIFECYCLE_STATES = ['active', 'disabled', 'purged'];

// The directory attributes this file reads, LOWER-CASED, because that is how
// `ldap_server.js`'s store keys them. Naming them here rather than inline is
// what keeps `identifierChanges()` from being four copies of one comparison.
//
// `pwdaccountlockedtime` is draft-behera-ldap-password-policy's
// `pwdAccountLockedTime`, and SINCE 2026-09-17 IT IS WHAT A DISABLED ACCOUNT
// IS HERE: an administrator's disable writes it (`common/account_state.ts`),
// SCIM's `active: false` writes it, and every door refuses the account while
// it is set. It replaced `scimActive`, an attribute this service had invented
// and nothing read — so an `account-disabled` sent over RISC used to report a
// deprovisioning that disabled nobody, and now reports one that did. A
// transmitter still only REPORTS; what the receiver does is the receiver's.
const LOCK_ATTRIBUTE = 'pwdaccountlockedtime';
const EMAIL_ATTRIBUTES = ['mail'];
const PHONE_ATTRIBUTES = ['telephonenumber', 'mobile'];

// accountId -> row. Insertion-ordered, which is what makes "the oldest goes"
// one `keys().next()` rather than a sort by a timestamp two rows can share.
//
// PER TRUST REALM. An account is a person in ONE realm's directory — the same
// username in two realms is two people — so the row about it belongs to that
// realm. The realm is the AMBIENT one, and that is right on every door a write
// arrives by: SCIM and the console are inside the request that made them, and
// `ldap_server.js` wraps every socket operation in `realms.run(realmFor(dn))`
// at registration — the directory's own `entries` are read ambiently, so a
// write outside its realm would not have found the entry to observe.
const register = realms.map({ persist: 'risc.register' });

class RiscRegister {
  static readonly AUTO_ACTS = AUTO_ACTS;
  static readonly OPT_OUT_EVENTS = OPT_OUT_EVENTS;
  static readonly OPT_STATES = OPT_STATES;
  static readonly LIFECYCLE_STATES = LIFECYCLE_STATES;

  constructor(private readonly deps: RiscRegisterDeps) {
    deps.log.debug("Entering RiscRegister.constructor().");
    deps.log.debug("Leaving RiscRegister.constructor().");
  }

  // How many events one row remembers. A RING, and the counters are not — see
  // noteTransmitted() — because "how many account-disabled have gone out about
  // this person" and "what were the last few jtis" are two different questions.
  //
  // `risc.eventsPerAccount` since 2026-09-12 (25, the old constant, is its
  // default); read per event. `risc.historyPerAccount` bounds the credential
  // and identifier-change lists below, which were a literal 10 each.
  eventsPerAccount(): number {
    const { log, config } = this.deps;
    log.debug("Entering RiscRegister.eventsPerAccount().");
    log.debug("Leaving RiscRegister.eventsPerAccount().");
    return config.value('risc.eventsPerAccount');
  }

  private historyPerAccount(): number {
    const { log, config } = this.deps;
    log.debug("Entering RiscRegister.historyPerAccount().");
    log.debug("Leaving RiscRegister.historyPerAccount().");
    return config.value('risc.historyPerAccount');
  }

  // A row edited in place, reported to the journal — `caep.ts`'s `touch()`, for
  // its reason. Re-setting the key keeps the row's place in the insertion
  // order, and a row trimmed out or replaced by another process's write is not
  // put back.
  private touch(row: RiscRow | null): void {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.touch().");
    if (!row || !row.accountId) {
      log.debug("Leaving RiscRegister.touch().");
      return;
    }
    if (register.get(row.accountId) === row) {
      register.set(row.accountId, row);
    }
    log.debug("Leaving RiscRegister.touch().");
  }

  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering RiscRegister.enabled().");
    const on = !!config.value('risc.enabled');
    log.debug("Leaving RiscRegister.enabled(). " + on);
    return on;
  }

  // The fourteen URIs, or none at all when the profile is off. `ssf.ts` unions
  // this with SSF's own two and CAEP's eight to decide what a stream may
  // request, so turning RISC off narrows what this transmitter will agree to.
  supportedEventUris(): string[] {
    const { log, events } = this.deps;
    log.debug("Entering RiscRegister.supportedEventUris().");
    if (!this.enabled()) {
      log.debug("Leaving RiscRegister.supportedEventUris(). RISC is off.");
      return [];
    }
    const out = events.RISC_EVENT_URIS.slice();
    log.debug("Leaving RiscRegister.supportedEventUris(). " + out.length +
              ' type(s).');
    return out;
  }

  // Which of the six acts emit on their own. An entry naming an event this
  // service cannot cause is DROPPED WITH A WARNING rather than honoured: there
  // is no code path that would ever fire it, so honouring it would leave a
  // setting that reads as configured and does nothing.
  autoEmitActs(): string[] {
    const { log, config, events } = this.deps;
    log.debug("Entering RiscRegister.autoEmitActs().");
    if (!this.enabled() || !config.value('risc.autoEmit')) {
      log.debug("Leaving RiscRegister.autoEmitActs(). Off.");
      return [];
    }
    const asked = config.value('risc.autoEmitTypes');
    const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
    const names = {};
    Object.keys(AUTO_ACTS).forEach((act) => {
      names[AUTO_ACTS[act]] = act;
    });
    const chosen = [];
    list.map((one) => {
      return String(one).trim();
    }).filter(Boolean).forEach((name) => {
      const short = name.indexOf(events.RISC_PREFIX) === 0
        ? name.slice(events.RISC_PREFIX.length) : name;
      if (!names[short]) {
        log.warn('risc.autoEmitTypes names "' + name + '", which is not one ' +
                 'of the ' + Object.keys(AUTO_ACTS).length + ' acts this ' +
                 'service can observe (' +
                 Object.keys(AUTO_ACTS).map((act) => {
                   return AUTO_ACTS[act];
                 }).join(', ') + '). It is DROPPED — nothing here would ever ' +
                 'fire it, so honouring it would leave a setting that reads ' +
                 'as configured and does nothing. Emit that type by hand ' +
                 'from /admin/risc.');
        return;
      }
      if (chosen.indexOf(names[short]) < 0) {
        chosen.push(names[short]);
      }
    });
    log.debug("Leaving RiscRegister.autoEmitActs(). " + chosen.length +
              ' act(s).');
    return chosen;
  }

  // ---------------------------------------------------------------------------
  // THE SUBJECT, AND WHY IT IS A PLAIN ONE.
  //
  // **CAEP's subject is complex and RISC's is not, and that is the difference
  // between the two profiles said in one line of JSON.** SSF section 4's
  // complex subject exists because a CAEP event is about one SESSION of one
  // person and a subject identifier names the person — so `{user, session,
  // device}` is how "that person, on that device, in that session" is expressed
  // at all. A RISC event is about the ACCOUNT. The person IS the subject, there
  // is nothing to narrow, and a complex subject here would say *this account
  // was disabled, on this device*, which is a sentence with no meaning.
  //
  // **WHICH FORMAT IS A SETTING, AND IT MATTERS MORE THAN ANY OTHER SETTING IN
  // THIS GROUP.** Eleven of the fourteen event types have no payload members at
  // all, so the subject carries the ENTIRE message: `account-purged` says
  // nothing but its own type and who it is about. `risc.subjectFormat` chooses
  // between `iss_sub` (the identifier a receiver already holds, because an ID
  // Token's `iss` and `sub` said it), `email` (what a receiver keying on an
  // address expects) and `opaque`.
  //
  // **AND THE TWO IDENTIFIER EVENTS IGNORE IT.** RISC says the subject of
  // `identifier-changed` and `identifier-recycled` MUST be an email address or
  // a phone number and MUST carry the OLD value — because for those two the
  // identifier IS the message, and the payload's optional `new-value` is the
  // only place the new one appears. A transmitter that honoured the setting
  // there would send an `iss_sub` subject on an event whose whole content is an
  // email address.
  // ---------------------------------------------------------------------------
  subjectFor(row: Partial<RiscRow>,
             uri?: string): Record<string, any> | null {
    const { log, config, events, subjects } = this.deps;
    log.debug("Entering RiscRegister.subjectFor(). " + (uri || ''));
    const catalogue = events.EVENT_BY_URI[String(uri || '')];
    const formats = (catalogue && Array.isArray(catalogue.subjectFormats))
      ? catalogue.subjectFormats : null;
    let subject;
    if (formats && formats.indexOf('email') >= 0) {
      const email = String(row.email || this.defaultEmailFor(row));
      if (email) {
        subject = { format: 'email', email: email };
      } else if (row.phone && formats.indexOf('phone_number') >= 0) {
        // RISC permits either for the two identifier events, and a number the
        // entry really holds is better than an address nobody has.
        subject = { format: 'phone_number', phone_number: String(row.phone) };
      } else {
        // PRODUCT MODE WITH NOTHING REAL TO NAME. RISC says these two events'
        // subject MUST be an address or a number, so the honest answer is no
        // subject at all — `transmit()` refuses a `subject: 'required'` event
        // that carries none, with a sentence, rather than this file inventing
        // an address to satisfy the shape.
        log.debug("Leaving RiscRegister.subjectFor(). No real address or " +
                  'number, and none is invented in product mode.');
        return null;
      }
    } else {
      // THE ROW'S REAL `mail` AND NUMBER GO WITH IT (2026-09-12). This passed
      // the name alone, so `risc.subjectFormat=email` sent `<name>@example.com`
      // for a person whose entry this register had read a real address off.
      subject = subjects.subjectForUser(
        row.sub || row.accountId,
        String(config.value('risc.subjectFormat') || 'iss_sub'),
        String(row.iss || ''),
        { mail: row.email, phone: row.phone, subject: row.subject || '' });
    }
    const out = this.googleSubjectType(subject);
    log.debug("Leaving RiscRegister.subjectFor(). " +
              subjects.describeSubject(subject));
    return out;
  }

  // An address for somebody whose directory entry carries none, so that an
  // identifier event about them is still SHAPED right. It is marked in the
  // value rather than left plausible, for the reason `caep.ts` marks a
  // generated session id: an event naming an address nobody has is well-formed,
  // delivers, and is about nothing at the far end.
  //
  // **DEVELOPMENT ONLY SINCE 2026-09-12** (`mode.inventsClaimValues()`):
  // product answers the empty string for a name that is not itself an address,
  // and `subjectFor()` then sends no subject rather than an invented one.
  private defaultEmailFor(row: Partial<RiscRow>): string {
    const { log, mode } = this.deps;
    log.debug("Entering RiscRegister.defaultEmailFor().");
    const name = String(row.accountId || row.sub || 'unknown');
    const out = name.indexOf('@') > 0 ? name
      : (mode.inventsClaimValues() ? name + '@example.com' : '');
    log.debug("Leaving RiscRegister.defaultEmailFor(). " + out);
    return out;
  }

  // ---------------------------------------------------------------------------
  // RISC 1.0 SECTION 3.1, AND IT IS THE ONLY DELIBERATE DEFECT IN THIS SERVICE
  // THAT A SPECIFICATION ASKS FOR BY NAME.
  //
  // Google's production RISC transmitter spells a subject identifier's
  // discriminator `subject_type` rather than `format`. The specification
  // records this, says the usage is deprecated, says new services MUST NOT use
  // it — and then tells relying parties they need code to work around it
  // anyway, because that transmitter is the one their users' accounts live
  // behind.
  //
  // So a receiver has to handle both and cannot find out whether it does by
  // reading its own source. `risc.googleSubjectType` renames the member on
  // every RISC subject this service sends. It touches nothing else: CAEP and
  // SSF's own events keep `format`, because their specifications never had the
  // problem and a service that renamed everything would be testing a
  // transmitter nobody has.
  // ---------------------------------------------------------------------------
  googleSubjectType(subject: any): any {
    const { log, config } = this.deps;
    log.debug("Entering RiscRegister.googleSubjectType().");
    if (!config.value('risc.googleSubjectType') || !subject ||
        typeof subject !== 'object' ||
        !Object.prototype.hasOwnProperty.call(subject, 'format')) {
      log.debug("Leaving RiscRegister.googleSubjectType(). Unchanged.");
      return subject;
    }
    const out: Record<string, any> = {};
    Object.keys(subject).forEach((name) => {
      if (name === 'format') {
        out.subject_type = subject.format;
        return;
      }
      out[name] = subject[name];
    });
    log.debug("Leaving RiscRegister.googleSubjectType(). Renamed to " +
              'subject_type.');
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHICH ACCOUNT A SUBJECT NAMES, read back off a token this service — or
  // anybody else — composed.
  //
  // It reads every format `subjectFor()` can produce and the Google spelling
  // beside them, because a subject that came back through `noteTransmitted()`
  // went out through whatever the settings said at the time and the settings
  // can have changed since. An unmatched subject legitimately names no row: a
  // debugger pointed at this transmitter is entitled to name whatever subject
  // it likes, and the caller counts the event against the stream instead.
  // ---------------------------------------------------------------------------
  accountIdOf(subject: unknown): string {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.accountIdOf().");
    const body = (subject && typeof subject === 'object' &&
                  !Array.isArray(subject)) ? subject as any : null;
    if (!body) {
      log.debug("Leaving RiscRegister.accountIdOf(). Not an object.");
      return '';
    }
    const format = String(body.format || body.subject_type || '');
    let candidate = '';
    if (format === 'issuer_subject_id') {
      candidate = String(body.sub || '');
    } else if (format === 'email') {
      candidate = String(body.email || '');
    } else if (format === 'opaque') {
      candidate = String(body.id || '');
    } else if (format === 'account') {
      candidate = String(body.uri || '').replace(/^acct:/, '');
    } else if (format === 'uri') {
      candidate = String(body.uri || '').split('/').pop();
    }
    const found = this.matchAccount(candidate);
    log.debug("Leaving RiscRegister.accountIdOf(). " + (found || '(none)'));
    return found;
  }

  // A candidate string against the register, by account id first and then by
  // the addresses a row is known by. The second pass is what makes an
  // `identifier-changed` about alice@example.com count against alice's row
  // rather than opening a second one — which is the register's whole reason for
  // being keyed on the person.
  private matchAccount(candidate: unknown): string {
    const { log, nameForSubject } = this.deps;
    log.debug("Entering RiscRegister.matchAccount().");
    const value = String(candidate || '');
    if (!value) {
      log.debug("Leaving RiscRegister.matchAccount(). Nothing to match.");
      return '';
    }
    if (register.has(value)) {
      log.debug("Leaving RiscRegister.matchAccount(). By account id.");
      return value;
    }
    // A PERSON'S SUBJECT (2026-09-14): an issuer_subject_id carries
    // `urn:uuid:<entryUUID>` now, and the register is keyed on the name. The
    // directory says whose it is; a row that recorded the subject — which is
    // the only way to recognise an account already deleted — is matched below.
    const named = /^urn:uuid:/i.test(value) ? nameForSubject(value) : '';
    if (named && register.has(named)) {
      log.debug("Leaving RiscRegister.matchAccount(). By subject.");
      return named;
    }
    let found = '';
    register.forEach((row, id) => {
      if (found) {
        return;
      }
      if (row.sub === value || row.email === value || row.subject === value ||
          (row.formerIdentifiers || []).indexOf(value) >= 0 ||
          row.phone === value) {
        found = id;
      }
    });
    log.debug("Leaving RiscRegister.matchAccount(). " +
              (found ? 'By identifier.' : 'No.'));
    return found;
  }

  // ---------------------------------------------------------------------------
  // THE ROW.
  //
  // Every state starts at the value that means THIS SERVICE HAS NOT BEEN TOLD,
  // which for the lifecycle is `active` — an account in the directory is active
  // until something says otherwise — and for the credential standing is the
  // empty string. A page that showed `compromised: no` for an account nothing
  // has ever been said about would be inventing the one fact a reader came to
  // look up.
  // ---------------------------------------------------------------------------
  private blankRow(seed?: Record<string, any>): RiscRow {
    const { log, iso } = this.deps;
    log.debug("Entering RiscRegister.blankRow().");
    const asked = seed || {};
    const row = {
      accountId: String(asked.accountId || ''),
      sub: String(asked.sub || asked.accountId || ''),
      username: String(asked.username || asked.accountId || ''),
      iss: String(asked.iss || ''),
      dn: String(asked.dn || ''),
      realm: String(asked.realm || ''),
      email: String(asked.email || ''),
      phone: String(asked.phone || ''),
      // Every address this account has been known by, so that an event naming a
      // superseded one still counts against the right row. It is the register's
      // memory of its own identifier changes and it is what stops
      // `identifier-recycled` — the event that says an address now belongs to
      // SOMEBODY ELSE — from being filed under the person who used to hold it.
      formerIdentifiers: [],
      createdAt: iso(),
      updatedAt: iso(),
      lifecycle: 'active',
      optOut: 'opt-in',
      credentialStanding: '',
      credentialChangeRequired: false,
      recoveryActivated: false,
      identifierChanges: [],
      credentials: [],
      counts: {},
      total: 0,
      suppressed: 0,
      events: [],
      streams: [],
      notes: []
    };
    log.debug("Leaving RiscRegister.blankRow(). " + row.accountId);
    return row;
  }

  private trim(): number {
    const { log, config } = this.deps;
    log.debug("Entering RiscRegister.trim().");
    const cap = Number(config.value('risc.maxAccountsTracked')) || 200;
    let dropped = 0;
    while (register.size > cap) {
      const oldest = register.keys().next();
      if (oldest.done) {
        break;
      }
      register.delete(oldest.value);
      dropped += 1;
    }
    log.debug("Leaving RiscRegister.trim(). " + dropped + ' dropped.');
    return dropped;
  }

  // Find the row, or make one. A RISC event emitted by hand about an account
  // this service never held is legitimate — a debugger pointing at this
  // transmitter is entitled to name whatever subject it likes — so an unknown
  // id gets a row saying where it came from rather than being refused.
  rowFor(accountId: unknown, seed?: Record<string, any>): RiscRow | null {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.rowFor(). " + accountId);
    const id = String(accountId || '');
    if (!id) {
      log.debug("Leaving RiscRegister.rowFor(). No id.");
      return null;
    }
    let row = register.get(id);
    if (!row) {
      row = this.blankRow(Object.assign({ accountId: id }, seed || {}));
      row.notes.push('This row was created by an event rather than by a ' +
          'directory write, so nothing here has ever held this account.');
      register.set(id, row);
      this.trim();
    }
    log.debug("Leaving RiscRegister.rowFor(). " + id);
    return row;
  }

  get(accountId: unknown): RiscRow | null {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.get().");
    const row = register.get(String(accountId || '')) || null;
    log.debug("Leaving RiscRegister.get(). " + (row ? 'found' : 'not found'));
    return row;
  }

  list(): RiscRow[] {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.list().");
    const out = Array.from(register.values()) as RiscRow[];
    log.debug("Leaving RiscRegister.list(). " + out.length + ' row(s).');
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE THREE COMMON CLAIMS, AND THE ONE EVENT THAT GETS THEM.
  //
  // CAEP section 2 gives `event_timestamp`, `initiating_entity`, `reason_admin`
  // and `reason_user` to every one of its eight event types. **RISC gives THREE
  // of them — there is no `initiating_entity` — and gives them to exactly ONE
  // of its fourteen**, `credential-compromise`. A reader porting CAEP's
  // `commonClaims()` across would attach four members to fourteen events and
  // produce thirteen carrying members their specification does not define.
  // Nothing would fail: an unrecognised member is carried and ignored by a
  // conforming receiver, which is exactly why this is guarded here rather than
  // left to whoever calls it.
  //
  // `event_timestamp` means something different here, too. CAEP's is when the
  // thing happened; RISC section 2.7 words it as when the transmitter
  // DISCOVERED the compromise — a credential found in a breach corpus was
  // compromised long before anybody noticed, and a receiver reading it as an
  // occurrence time dates the incident from the wrong end.
  // ---------------------------------------------------------------------------
  commonClaims(uri: string,
               options?: Record<string, any>): Record<string, any> {
    const { log, nowSec, config, events } = this.deps;
    log.debug("Entering RiscRegister.commonClaims(). " + uri);
    const asked = options || {};
    const out: Record<string, any> = {};
    const row = events.EVENT_BY_URI[String(uri || '')];
    const takesThem = !!row && (row.members || []).some((member) => {
      return member.name === 'reason_admin';
    });
    if (!takesThem) {
      log.debug("Leaving RiscRegister.commonClaims(). This type defines none " +
                'of them.');
      return out;
    }
    if (!config.value('risc.omitEventTimestamp')) {
      out.event_timestamp = typeof asked.eventTimestamp === 'number'
        ? asked.eventTimestamp : nowSec();
    }
    const tag = String(config.value('risc.reasonLanguage') || 'en');
    if (config.value('risc.includeReasons')) {
      if (asked.reasonAdmin) {
        out.reason_admin = {};
        out.reason_admin[tag] = String(asked.reasonAdmin);
      }
      if (asked.reasonUser) {
        out.reason_user = {};
        out.reason_user[tag] = String(asked.reasonUser);
      }
    }
    log.debug("Leaving RiscRegister.commonClaims(). " +
              Object.keys(out).length + ' claim(s).');
    return out;
  }

  // A whole payload: the row's own generator, plus whichever of the three above
  // this event type actually defines. ONE function, so the console form, the
  // management API and the automatic emission all produce the SAME shape.
  buildPayload(uri: string, values?: Record<string, any>,
               options?: Record<string, any>): Record<string, any> {
    const { log, events } = this.deps;
    log.debug("Entering RiscRegister.buildPayload(). " + uri);
    const row = events.EVENT_BY_URI[uri];
    if (!row) {
      log.debug("Leaving RiscRegister.buildPayload(). Unknown type.");
      return {};
    }
    const payload = Object.assign({}, row.generate(values || {}),
                                  this.commonClaims(uri, options));
    log.debug("Leaving RiscRegister.buildPayload(). " +
              Object.keys(payload).length + ' member(s).');
    return payload;
  }

  // ---------------------------------------------------------------------------
  // THE OPT-OUT GATE, AND THE EXCEPTION WITHOUT WHICH IT IS A TRAP.
  //
  // RISC section 2.8 gives an account three states and says the last of them
  // means it is NOT participating in RISC event exchange. So a conforming
  // transmitter stops sending about an account that has reached it, and
  // `risc.honourOptOut` is on by default because that is the conforming
  // behaviour.
  //
  // **THE FOUR OPT-OUT EVENTS ARE NEVER SUPPRESSED, AND THE REASON IS THE ONE
  // THING A STATE MACHINE CAN SEE THAT A RULE CANNOT.** `opt-out-effective` is
  // the event that ANNOUNCES the account has reached that state — a transmitter
  // that applied the gate to it would enter the silent state without telling
  // anybody it had, so a receiver would see the signals simply stop, which is
  // indistinguishable from a transmitter that has gone down. And `opt-in` is
  // sent FROM the opt-out state by definition: it is the only way a receiver
  // ever learns the account came back, and gating it would make the opt-out
  // permanent for every receiver in the world.
  //
  // The middle state, `opt-out-initiated`, exchanges everything. That delay is
  // deliberate in the specification: it exists to stop a hijacker from opting
  // out the moment they take an account over and silencing the very events that
  // would report them.
  // ---------------------------------------------------------------------------
  gate(row: RiscRow, uri: string): { send: boolean; why: string } {
    const { log, config } = this.deps;
    log.debug("Entering RiscRegister.gate(). " + uri);
    const short = this.shortNameOf(uri);
    if (OPT_OUT_EVENTS[short]) {
      log.debug("Leaving RiscRegister.gate(). An opt-out event is never " +
                'suppressed.');
      return { send: true, why: '' };
    }
    if (!config.value('risc.honourOptOut')) {
      log.debug("Leaving RiscRegister.gate(). risc.honourOptOut is off.");
      return { send: true, why: '' };
    }
    if (row.optOut !== 'opt-out') {
      log.debug("Leaving RiscRegister.gate(). " + row.optOut + ' exchanges.');
      return { send: true, why: '' };
    }
    const why = 'This account is in the RISC opt-out state, so nothing but ' +
      'an opt-out event is sent about it (risc.honourOptOut). RISC section ' +
      '2.8 says an opted-out account is not participating in event exchange. ' +
      'Turn that setting off to send anyway, which is how a receiver that ' +
      'ignores an opt-out gets to be shown doing it.';
    log.debug("Leaving RiscRegister.gate(). Suppressed.");
    return { send: false, why: why };
  }

  private shortNameOf(uri: unknown): string {
    const { log, events } = this.deps;
    log.debug("Entering RiscRegister.shortNameOf().");
    const text = String(uri || '');
    log.debug("Leaving RiscRegister.shortNameOf().");
    return text.indexOf(events.RISC_PREFIX) === 0
      ? text.slice(events.RISC_PREFIX.length) : '';
  }

  // ---------------------------------------------------------------------------
  // THE STATE MACHINE.
  //
  // What each event type does to a row, and the ONE place it says NO. Collected
  // findings rather than a boolean, for the reason `ssf_subjects.js` gives
  // about a form: an event built by hand is usually wrong in more than one way.
  //
  // **THE ONE HARD REFUSAL IS `account-enabled` ON A PURGED ACCOUNT**, and it
  // is the exact analogue of `caep.ts`'s refusal of a `session-presented` on a
  // revoked session. That sentence says an account this transmitter has
  // declared PERMANENTLY DELETED is usable again — either a transmitter
  // contradicting itself, or a receiver about to be told to restore access to
  // something that does not exist. Everything else that looks wrong is a
  // WARNING, because this is a mock and refusing to carry an odd-looking event
  // would remove the ability to reproduce one.
  //
  // **THE OPT-OUT TRANSITIONS ARE THE SPECIFICATION'S OWN DIAGRAM AND ARE STILL
  // ONLY WARNINGS.** RISC section 2.8's figure allows exactly four moves;
  // anything else is a transmitter that has lost track of its own state, which
  // is worth SEEING rather than being unable to produce.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // WHAT THIS REGISTER REFUSES OUTRIGHT, ASKED WITHOUT CHANGING ANYTHING.
  //
  // `applyToState()` below answers the same question and MUTATES, because it is
  // what runs when an event has actually been transmitted. This is the same
  // rule asked in advance, and it is a second function rather than a `dryRun`
  // flag on the first for the reason that flag would produce: a state machine
  // with a branch that sometimes writes is one where the next rule added writes
  // in both modes by accident, and the symptom would be a register following an
  // event that was refused.
  //
  // **IT EXISTS BECAUSE A REFUSAL AFTER SIGNING IS NOT A REFUSAL.**
  // `riscEmit()` transmits and the register is updated on the way back through
  // `noteTransmitted()`, so a rule enforced only there would fire on an event
  // that has already been signed, queued and delivered — the receiver would
  // have acted on it, and this service would report the refusal to nobody. So
  // the one hard rule is asked here, before anything is built.
  // ---------------------------------------------------------------------------
  refusals(row: RiscRow | null, uri: string): string[] {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.refusals(). " + uri);
    const errors = [];
    const short = this.shortNameOf(uri);
    if (row && row.lifecycle === 'purged' && short === 'account-enabled') {
      errors.push('This account is PURGED, which RISC defines as permanently ' +
                  'deleted, so it cannot be enabled. That sentence is either ' +
                  'a transmitter contradicting itself or a receiver about to ' +
                  'be told to restore access to something that does not ' +
                  'exist, and it is the one thing this register refuses ' +
                  'outright. Reset the account to send it.');
    }
    log.debug("Leaving RiscRegister.refusals(). " + errors.length +
              ' refusal(s).');
    return errors;
  }

  applyToState(row: RiscRow, uri: string,
               payload?: any): Record<string, any> {
    const { log, iso } = this.deps;
    log.debug("Entering RiscRegister.applyToState(). " + uri);
    const body = (payload && typeof payload === 'object') ? payload : {};
    const errors = [];
    const warnings = [];
    const short = this.shortNameOf(uri);

    if (!short) {
      log.debug("Leaving RiscRegister.applyToState(). Not a RISC event.");
      return { ok: true, errors: errors, warnings: warnings };
    }

    if (row.lifecycle === 'purged' && short !== 'account-purged') {
      // THE ONE HARD RULE IS refusals()'s AND NOT A SECOND COPY OF IT. Two
      // spellings of one refusal is two chances for the pre-flight check and
      // the applied one to disagree, and the disagreement would be invisible:
      // the emit path asks the first and the register writes from the second.
      const hard = this.refusals(row, uri);
      if (hard.length) {
        hard.forEach((one) => {
          errors.push(one);
        });
      } else {
        warnings.push('This account is PURGED and something is still being ' +
            'said about it. That is not forbidden — a compromise can be ' +
            'discovered after a deletion — and a receiver that has already ' +
            'removed the account has nothing left to apply it to, which is ' +
            'what makes it worth noticing.');
      }
    }

    if (short === 'account-disabled') {
      if (row.lifecycle === 'disabled') {
        warnings.push('This account was already disabled. A second disable ' +
                      'is harmless and a receiver should be idempotent about ' +
                      'it, which is exactly the thing worth testing.');
      }
      if (row.lifecycle !== 'purged') {
        row.lifecycle = 'disabled';
      }
      if (typeof body.reason === 'string' && body.reason) {
        row.notes.push('Disabled, reason "' + body.reason + '".');
      }
    } else if (short === 'account-enabled') {
      if (row.lifecycle === 'active') {
        warnings.push('This account was not disabled, so there was nothing ' +
                      'to enable. A receiver acting on the pair will have ' +
                      'nothing to undo — which is harmless here and is the ' +
                      'shape of a transmitter that sends the whole state on ' +
                      'every write rather than the change.');
      }
      if (row.lifecycle !== 'purged') {
        row.lifecycle = 'active';
      }
    } else if (short === 'account-purged') {
      if (row.lifecycle === 'purged') {
        warnings.push('This account was already purged.');
      }
      row.lifecycle = 'purged';
    } else if (short === 'account-credential-change-required') {
      row.credentialChangeRequired = true;
      warnings.push('This says a credential change was REQUIRED and not that ' +
          'one happened. Nothing here says the person complied, and they may ' +
          'never; what a receiver learns is that this provider no longer ' +
          'trusts what it currently holds.');
    } else if (short === 'credential-compromise') {
      row.credentialStanding = 'compromised';
      row.credentials.unshift({ at: iso(),
        credentialType: String(body.credential_type || ''),
        discoveredAt: typeof body.event_timestamp === 'number'
          ? body.event_timestamp : 0 });
      row.credentials = row.credentials.slice(0, this.historyPerAccount());
    } else if (short === 'identifier-changed') {
      // THE SUBJECT CARRIED THE OLD VALUE and the payload carries the new one,
      // which is the reverse of every other event here. The old address goes on
      // `formerIdentifiers` so that a later event naming it still finds this
      // row — see matchAccount().
      const now = String(body['new-value'] || '');
      if (!now) {
        warnings.push('There is no `new-value`, so this says an identifier ' +
                      'the receiver holds is stale without saying what to ' +
                      'hold instead. That is legal — the member is optional ' +
                      '— and it is nearly useless. Note the HYPHEN: ' +
                      '`new_value` is not the member RISC defines and is ' +
                      'silently ignored.');
      }
      if (row.email && row.formerIdentifiers.indexOf(row.email) < 0) {
        row.formerIdentifiers.push(row.email);
      }
      row.identifierChanges.unshift({ at: iso(), from: row.email, to: now });
      row.identifierChanges =
        row.identifierChanges.slice(0, this.historyPerAccount());
      if (now) {
        row.email = now;
      }
    } else if (short === 'identifier-recycled') {
      warnings.push('THIS IDENTIFIER NOW BELONGS TO SOMEBODY ELSE. A ' +
                    'receiver keyed on an email address rather than on an ' +
                    'iss_sub pair will let the new owner into the old ' +
                    'owner\'s account and nothing anywhere was compromised — ' +
                    'which is the whole argument for not keying on an ' +
                    'address, and the reason this event type exists.');
      if (row.email && row.formerIdentifiers.indexOf(row.email) < 0) {
        row.formerIdentifiers.push(row.email);
      }
    } else if (short === 'recovery-activated') {
      row.recoveryActivated = true;
      warnings.push('A recovery flow is how a legitimate owner gets back in ' +
          'AND how an attacker who controls the recovery channel takes over, ' +
          'and this transmitter cannot tell which. A receiver is expected to ' +
          'weigh it rather than act on it.');
    } else if (short === 'recovery-information-changed') {
      row.notes.push('Recovery information changed.');
    } else if (short === 'sessions-revoked') {
      warnings.push('This is the PLURAL event: every session this account ' +
                    'has, everywhere, which is a far larger instruction than ' +
                    'CAEP\'s session-revoked whose subject names ONE of ' +
                    'them. The two names differ by one letter.');
    } else if (OPT_OUT_EVENTS[short]) {
      this.applyOptOut(row, short, warnings);
    }

    row.notes = row.notes.slice(-5);
    row.updatedAt = iso();
    this.touch(row);
    log.debug("Leaving RiscRegister.applyToState(). " + errors.length +
              ' error(s), ' + warnings.length + ' warning(s).');
    return { ok: errors.length === 0, errors: errors, warnings: warnings,
      lifecycle: row.lifecycle, optOut: row.optOut };
  }

  // RISC section 2.8's figure, written out. Four moves are legal and everything
  // else is a transmitter that has lost track of its own state — warned about
  // and then APPLIED, because the state the event declares is the state the
  // receiver will believe, and a register that refused to follow would be
  // reporting something the far end does not think.
  private applyOptOut(row: RiscRow, short: string,
                      warnings: string[]): void {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.applyOptOut(). " + short);
    const from = row.optOut;
    const legal = {
      'opt-out-initiated': ['opt-in'],
      'opt-out-cancelled': ['opt-out-initiated'],
      'opt-out-effective': ['opt-out-initiated'],
      'opt-in': ['opt-out', 'opt-out-initiated']
    };
    if ((legal[short] || []).indexOf(from) < 0) {
      warnings.push('RISC section 2.8\'s state diagram has no ' + short + ' ' +
          'out of the "' + from + '" state — it allows one only from ' +
          (legal[short] || []).join(' or ') + '. It is applied anyway, ' +
          'because the state this event DECLARES is the state the receiver ' +
          'will believe, and a register that refused to follow would be ' +
          'reporting something the far end does not think.');
    }
    if (short === 'opt-out-effective' && from === 'opt-in') {
      warnings.push('This skipped opt-out-initiated, which is the state that ' +
          'exists to stop a hijacker opting out the moment they take an ' +
          'account over and silencing the events that would report them.');
    }
    row.optOut = OPT_OUT_EVENTS[short];
    log.debug("Leaving RiscRegister.applyOptOut(). " + from + ' -> ' +
              row.optOut);
  }

  // ---------------------------------------------------------------------------
  // COUNTING WHAT WENT OUT.
  //
  // Called from `ssf.ts`'s `transmit()` after the SET has been built, so the
  // counters are of things actually MINTED rather than of things somebody meant
  // to send. It reads the account out of the token's own `sub_id`, which is
  // what keeps `transmit()` from having to know anything about this register.
  //
  // **THE COUNT IS NOT THE LIST.** `counts` never forgets and `events` is a
  // ring of the last few.
  // ---------------------------------------------------------------------------
  noteTransmitted(record: any, claims: any): RiscRow | null {
    const { log, iso, events } = this.deps;
    log.debug("Entering RiscRegister.noteTransmitted().");
    if (!this.enabled()) {
      log.debug("Leaving RiscRegister.noteTransmitted(). RISC is off.");
      return null;
    }
    const uris = Object.keys((claims && claims.events) || {});
    const uri = uris[0] || '';
    if (uri.indexOf(events.RISC_PREFIX) !== 0) {
      log.debug("Leaving RiscRegister.noteTransmitted(). Not a RISC event.");
      return null;
    }
    const accountId = this.accountIdOf(claims && claims.sub_id);
    if (!accountId) {
      log.debug("Leaving RiscRegister.noteTransmitted(). No account in the " +
                'subject.');
      return null;
    }
    const row = this.rowFor(accountId,
                            { iss: String((claims && claims.iss) || '') });
    const verdict = this.applyToState(row, uri, (claims.events || {})[uri]);
    row.counts[uri] = (row.counts[uri] || 0) + 1;
    row.total += 1;
    row.events.unshift({
      jti: String((claims && claims.jti) || ''),
      uri: uri,
      name: (events.EVENT_BY_URI[uri] || {}).name || uri,
      at: iso(),
      streamId: String((record && record.stream_id) || ''),
      warnings: verdict.warnings
    });
    row.events = row.events.slice(0, this.eventsPerAccount());
    const streamId = String((record && record.stream_id) || '');
    if (streamId && row.streams.indexOf(streamId) < 0) {
      row.streams.push(streamId);
    }
    this.touch(row);
    log.debug("Leaving RiscRegister.noteTransmitted(). " + row.total +
              ' event(s) on ' + row.accountId + '.');
    return row;
  }

  // ---------------------------------------------------------------------------
  // A DIRECTORY WRITE HAPPENED, AND WHAT — IF ANYTHING — SHOULD GO OUT.
  //
  // `ssf.ts` installs this as `ldap_server.setAccountObserver()`'s function and
  // sends what comes back. It updates the register EVEN WHEN NOTHING WILL BE
  // SENT, which is deliberate: a service with no streams agreed still has
  // accounts, and /admin/risc-accounts showing them with a count of zero is how
  // somebody finds out that the reason no event arrived is that nobody asked
  // for one.
  //
  // **IT ANSWERS WITH A LIST, AND THAT IS THE DIFFERENCE FROM CAEP.** One
  // directory write can be two RISC events — `active` going false AND a mail
  // address moving — and there is no ordering rule between them in the
  // specification, so both go out. A version that returned the first would drop
  // the second with nothing anywhere saying so.
  // ---------------------------------------------------------------------------
  observe(notice?: Record<string, any> | null): DueEvent[] {
    const { log, iso } = this.deps;
    log.debug("Entering RiscRegister.observe().");
    const asked = notice || {};
    const kind = String(asked.kind || '');
    const deleted = kind.indexOf('deleted:') === 0;
    const before = asked.before || {};
    const after = asked.after || {};
    const accountId = deleted ? kind.slice('deleted:'.length)
      : String(asked.username || '');
    if (!this.enabled() || !accountId) {
      log.debug("Leaving RiscRegister.observe(). Off, or nothing named.");
      return [];
    }
    let row = register.get(accountId);
    // A RENAMED ACCOUNT KEEPS ITS ROW (2026-09-14). The register is keyed by
    // the name, and a rename arrives here as an update naming the NEW one; the
    // entry's subject is what says it is the row already held under the old
    // name. Its counts and state move with it, and the old name is kept among
    // its former identifiers so an event naming it is still matched.
    const renamedUuid = ((deleted ? before : after).entryuuid || [])[0];
    if (!row && renamedUuid) {
      const wantedSubject = 'urn:uuid:' + String(renamedUuid).toLowerCase();
      let formerId = '';
      register.forEach((held, id) => {
        if (!formerId && held.subject === wantedSubject) {
          formerId = id;
        }
      });
      if (formerId) {
        row = register.get(formerId);
        register.delete(formerId);
        row.formerIdentifiers = (row.formerIdentifiers || [])
          .filter((one) => {
            return one !== formerId;
          }).concat([formerId]);
        row.accountId = accountId;
        row.username = accountId;
        row.sub = accountId;
        register.set(accountId, row);
      }
    }
    if (!row) {
      row = this.blankRow({
        accountId: accountId,
        sub: accountId,
        username: accountId,
        iss: String(asked.issuer || ''),
        dn: String(asked.dn || ''),
        realm: String(asked.realm || ''),
        email: this.firstOf(deleted ? before : after, EMAIL_ATTRIBUTES),
        phone: this.firstOf(deleted ? before : after, PHONE_ATTRIBUTES)
      });
      register.set(accountId, row);
      this.trim();
    }
    if (asked.issuer && !row.iss) {
      row.iss = String(asked.issuer);
    }
    if (asked.dn) {
      row.dn = String(asked.dn);
    }
    // THE ENTRY'S SUBJECT, off whichever snapshot has the entry in it
    // (2026-09-14). It is kept on the row because the one event where it
    // matters most — an account PURGED — is about an entry that is gone, and
    // the directory can no longer be asked whose `urn:uuid:` it was.
    const snapshotUuid = ((deleted ? before : after).entryuuid || [])[0];
    if (snapshotUuid) {
      row.subject = 'urn:uuid:' + String(snapshotUuid).toLowerCase();
    }
    row.updatedAt = iso();

    // A DESCRIPTOR AND NOT A BARE NAME, because everything below reads
    // `act.act` — a list of strings here made `AUTO_ACTS[act.act]` undefined
    // for every deletion, which produced no event, no note and no state change,
    // and looked exactly like a service where nobody had been deleted.
    const acts = deleted ? [{ act: 'purged', values: {} }]
      : this.actsFor(before, after);
    if (!acts.length) {
      this.touch(row);
      log.debug("Leaving RiscRegister.observe(). Nothing RISC has a word for.");
      return [];
    }
    const due = this.dueForActs(row, acts, asked);
    // ONE REPORT FOR EVERYTHING ABOVE — the seed's `iss` and `dn`, the notes
    // and the suppressed count — rather than one per branch, which would be the
    // branch somebody adds next forgetting it.
    this.touch(row);
    log.debug("Leaving RiscRegister.observe(). " + due.length + ' event(s) ' +
              'due.');
    return due;
  }

  // ---------------------------------------------------------------------------
  // WHAT IS DUE FOR A LIST OF ACTS ON ONE ROW. Split out of `observe()` on
  // 2026-09-13 so that `observeAct()` — an act an administrator performed, with
  // no directory diff behind it — goes through the SAME emission switch,
  // opt-out gate and audit row as a directory write. Two copies of that loop
  // would be two answers to "was this suppressed".
  // ---------------------------------------------------------------------------
  private dueForActs(row: RiscRow, acts: RiscAct[],
                     asked: Record<string, any>): DueEvent[] {
    const { log, audit, events } = this.deps;
    log.debug("Entering RiscRegister.dueForActs(). " + acts.length +
              ' act(s).');
    const accountId = row.accountId;
    const allowed = this.autoEmitActs();
    const due = [];
    acts.forEach((act) => {
      const short = AUTO_ACTS[act.act];
      if (allowed.indexOf(act.act) < 0) {
        // The register still follows the ACT rather than the event, so a reader
        // sees the account change even with emission off.
        this.applyActLocally(row, act);
        row.notes.push('A ' + short + ' was NOT emitted for this write: ' +
            'risc.autoEmit or risc.autoEmitTypes excludes it.');
        row.notes = row.notes.slice(-5);
        return;
      }
      const uri = events.RISC_PREFIX + short;
      const allowedOut = this.gate(row, uri);
      if (!allowedOut.send) {
        this.applyActLocally(row, act);
        row.suppressed += 1;
        row.notes.push('A ' + short + ' was SUPPRESSED: ' + allowedOut.why);
        row.notes = row.notes.slice(-5);
        log.info('risc: a ' + short + ' for ' + accountId + ' was suppressed ' +
                 'because the account is opted out (risc.honourOptOut).');
        return;
      }
      // THE SUBJECT IS COMPOSED FROM THE ROW AS IT WAS BEFORE THIS ACT, which
      // matters for exactly one of the six: an identifier-changed names the
      // OLD address, and applying the act first would name the new one — an
      // event that is well-formed, delivers, and tells the receiver that an
      // address it has never heard of has become the one it already holds.
      const subject = act.act === 'identifier'
        ? this.googleSubjectType(act.subject) : this.subjectFor(row, uri);
      const payload = this.buildPayload(uri, act.values || {}, {
        reasonAdmin: this.reasonFor(act, asked),
        reasonUser: this.reasonForUser(act)
      });
      audit.audit({ action: 'risc.event.auto', category: 'signals',
        protocol: 'RISC', channel: 'http', target: accountId,
        summary: 'A RISC ' + short + ' is due for account ' + accountId,
        detail: { type: uri, dn: String(asked.dn || '') } });
      due.push({ uri: uri, payload: payload, subject: subject, row: row,
        act: act.act });
    });
    log.debug("Leaving RiscRegister.dueForActs(). " + due.length + ' due.');
    return due;
  }

  // ---------------------------------------------------------------------------
  // AN ACT AN ADMINISTRATOR PERFORMED ON AN ACCOUNT (2026-09-13).
  //
  // `observe()` above reads a directory write and decides what it means. These
  // acts carry their meaning already — the console or `/admin-api` knows it
  // reset a password — so the notice names the act and this answers what is
  // due, through the same switch, gate and register `observe()` uses.
  //
  // The notice: `{ username, act, issuer, dn, realm, email, phone, reasonAdmin,
  // reasonUser }`, `act` one of AUTO_ACTS' keys that a directory diff cannot
  // produce.
  // ---------------------------------------------------------------------------
  observeAct(notice?: Record<string, any> | null): DueEvent[] {
    const { log, iso } = this.deps;
    log.debug("Entering RiscRegister.observeAct().");
    const asked = notice || {};
    const accountId = String(asked.username || '');
    const act = String(asked.act || '');
    if (!this.enabled() || !accountId || !AUTO_ACTS[act]) {
      log.debug("Leaving RiscRegister.observeAct(). Off, nothing named, or " +
                'not an act.');
      return [];
    }
    let row = register.get(accountId);
    if (!row) {
      row = this.blankRow({
        accountId: accountId, sub: accountId, username: accountId,
        iss: String(asked.issuer || ''), dn: String(asked.dn || ''),
        realm: String(asked.realm || ''),
        email: String(asked.email || ''), phone: String(asked.phone || '')
      });
      register.set(accountId, row);
      this.trim();
    }
    if (asked.issuer && !row.iss) {
      row.iss = String(asked.issuer);
    }
    row.updatedAt = iso();
    const due = this.dueForActs(row, [{ act: act, values: {} }], asked);
    this.touch(row);
    log.debug("Leaving RiscRegister.observeAct(). " + due.length +
              ' event(s) due.');
    return due;
  }

  // ---------------------------------------------------------------------------
  // THE REGISTER FOLLOWS THE ACT EVEN WHEN NOTHING GOES OUT.
  //
  // **THIS IS THE HALF THAT IS EASY TO LEAVE OUT, AND LEAVING IT OUT IS
  // INVISIBLE.** When an event IS transmitted the state is applied on the way
  // back through `noteTransmitted()`, which reads the token's own subject — so
  // the ordinary path needs nothing here. The three paths that need it are the
  // ones where no token is built: emission turned off, the opt-out gate, and
  // **no stream that both delivers the type and covers the subject**, which is
  // the commonest of the three by a long way and is the whole reason
  // /admin/risc-accounts exists.
  //
  // Without it, deleting a person from a service with no RISC stream agreed
  // leaves a register saying the account is still `active`. Nothing fails: the
  // deletion happened, the page is simply wrong about it, and the wrongness
  // looks exactly like a service where nothing has been deleted.
  //
  // `applyDue()` is the same thing addressed by the descriptor `observe()`
  // returned, so `ssf.ts` can call it without knowing what an act is.
  // ---------------------------------------------------------------------------
  applyDue(due?: Partial<DueEvent> | null): void {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.applyDue().");
    if (due && due.row && due.act) {
      this.applyActLocally(due.row, { act: due.act, values: due.payload });
    }
    log.debug("Leaving RiscRegister.applyDue().");
  }

  private applyActLocally(row: RiscRow, act: RiscAct): void {
    const { log, iso } = this.deps;
    log.debug("Entering RiscRegister.applyActLocally(). " + act.act);
    if (act.act === 'purged') {
      row.lifecycle = 'purged';
    } else if (act.act === 'disabled') {
      row.lifecycle = 'disabled';
    } else if (act.act === 'enabled') {
      row.lifecycle = 'active';
    } else if (act.act === 'identifier' && act.values &&
               act.values['new-value']) {
      if (row.email && row.formerIdentifiers.indexOf(row.email) < 0) {
        row.formerIdentifiers.push(row.email);
      }
      row.email = String(act.values['new-value']);
    } else if (act.act === 'credentialChangeRequired') {
      row.credentialChangeRequired = true;
    } else if (act.act === 'recoveryChanged') {
      row.notes.push('Recovery information changed.');
      row.notes = row.notes.slice(-5);
    }
    row.updatedAt = iso();
    this.touch(row);
    log.debug("Leaving RiscRegister.applyActLocally().");
  }

  // ---------------------------------------------------------------------------
  // WHAT CHANGED, IN RISC'S WORDS.
  //
  // **THIS IS THE READING, AND IT IS HERE RATHER THAN IN `ldap_server.js` ON
  // PURPOSE.** That file knows what a write is; it does not know that
  // a lock appearing is an `account-disabled`, and a version of it that
  // did would be the vocabulary leaking into the store — which is the mistake
  // `ssf_events.js`'s header spends a paragraph warning about, and the third
  // vocabulary would have had to undo it.
  // ---------------------------------------------------------------------------
  actsFor(before?: Record<string, any>,
          after?: Record<string, any>): RiscAct[] {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.actsFor().");
    const out = [];
    const was = this.activeIn(before);
    const now = this.activeIn(after);
    // An entry CREATED locked is a disabled account a receiver may already
    // know by another door; one created unlocked is nothing to report — an
    // `account-enabled` for every person ever created would be noise that
    // teaches a receiver to ignore the event.
    if (was !== now && now === false) {
      out.push({ act: 'disabled', values: { reason: 'hijacking' } });
    }
    if (was === false && now === true) {
      out.push({ act: 'enabled', values: {} });
    }
    // AN IDENTIFIER MOVED. The event's subject names the OLD value, so it is
    // built here where both are in hand rather than by subjectFor(), which only
    // ever sees the row.
    this.identifierMoves(before, after).forEach((move) => {
      out.push({ act: 'identifier',
        values: { 'new-value': move.to },
        subject: move.format === 'email'
          ? { format: 'email', email: move.from }
          : { format: 'phone_number', phone_number: move.from } });
    });
    log.debug("Leaving RiscRegister.actsFor(). " + out.length + ' act(s).');
    return out;
  }

  // Whether the account is ACTIVE, read from the lock: no
  // `pwdAccountLockedTime` is active, any value is disabled. An entry that is
  // not there at all — the `before` of a create, the `after` of a delete —
  // answers null and not either, because "there was no account" is neither
  // state, and reading it as active would make every delete of a disabled
  // account look like an `account-enabled`.
  private activeIn(attributes?: Record<string, any>): boolean | null {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.activeIn().");
    const attrs = attributes || {};
    if (!Object.keys(attrs).length) {
      log.debug("Leaving RiscRegister.activeIn(). No entry.");
      return null;
    }
    const values = attrs[LOCK_ATTRIBUTE];
    const out = !(Array.isArray(values) && values.length);
    log.debug("Leaving RiscRegister.activeIn(). " + out);
    return out;
  }

  private firstOf(attributes: Record<string, any> | undefined,
                  names: string[]): string {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.firstOf().");
    let found = '';
    names.forEach((name) => {
      if (found) {
        return;
      }
      const values = (attributes || {})[name];
      if (Array.isArray(values) && values.length) {
        found = String(values[0]);
      }
    });
    log.debug("Leaving RiscRegister.firstOf(). " + (found || '(none)'));
    return found;
  }

  // Every address or number that moved, as {from, to, format}. An identifier
  // that was ADDED where there was none is not a change and produces nothing:
  // `identifier-changed`'s subject has to carry the OLD value, and there is
  // none, so the event could not be composed. A provider that wanted to
  // announce the addition would send recovery-information-changed, which is
  // what that event is for.
  private identifierMoves(before?: Record<string, any>,
                          after?: Record<string, any>): Array<{
    from: string; to: string; format: string;
  }> {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.identifierMoves().");
    const out = [];
    const wasMail = this.firstOf(before, EMAIL_ATTRIBUTES);
    const nowMail = this.firstOf(after, EMAIL_ATTRIBUTES);
    if (wasMail && nowMail && wasMail !== nowMail) {
      out.push({ from: wasMail, to: nowMail, format: 'email' });
    }
    const wasPhone = this.firstOf(before, PHONE_ATTRIBUTES);
    const nowPhone = this.firstOf(after, PHONE_ATTRIBUTES);
    if (wasPhone && nowPhone && wasPhone !== nowPhone) {
      out.push({ from: wasPhone, to: nowPhone, format: 'phone_number' });
    }
    log.debug("Leaving RiscRegister.identifierMoves(). " + out.length +
              ' move(s).');
    return out;
  }

  // The administrative sentence, for a person reading a log at the far end. It
  // says WHAT HAPPENED HERE rather than what the receiver should do, which is
  // the division RISC draws as sharply as CAEP does.
  //
  // It reaches the wire for one event type only — credential-compromise is the
  // only one of the fourteen with a reason member — so for every act observed
  // here it is composed and dropped by commonClaims(). That is deliberate
  // rather than wasteful: the alternative is a caller that has to know which
  // types take reasons, which is the catalogue's business and not the
  // observer's.
  private reasonFor(act: RiscAct, notice?: Record<string, any>): string {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.reasonFor(). " + act.act);
    const where = String((notice || {}).dn || 'this directory');
    let text = '';
    if (act.act === 'purged') {
      text = 'The entry ' + where + ' was deleted from this directory.';
    } else if (act.act === 'disabled') {
      text = 'The account at ' + where + ' was marked inactive.';
    } else if (act.act === 'enabled') {
      text = 'The account at ' + where + ' was marked active again.';
    } else if (act.act === 'credentialChangeRequired') {
      text = String((notice || {}).reasonAdmin || '') ||
             'An administrator reset the password of ' + where + '.';
    } else if (act.act === 'recoveryChanged') {
      text = String((notice || {}).reasonAdmin || '') ||
             'The recovery codes of ' + where + ' were cleared.';
    } else {
      text = 'An identifier on ' + where + ' was changed.';
    }
    log.debug("Leaving RiscRegister.reasonFor().");
    return text;
  }

  private reasonForUser(act: RiscAct): string {
    const { log } = this.deps;
    log.debug("Entering RiscRegister.reasonForUser(). " + act.act);
    const text = act.act === 'purged'
      ? 'Your account was deleted.'
      : (act.act === 'disabled' ? 'Your account has been disabled.'
        : (act.act === 'enabled' ? 'Your account has been enabled.'
          : (act.act === 'credentialChangeRequired'
            ? 'Your password was reset and must be changed.'
            : (act.act === 'recoveryChanged'
              ? 'Your recovery codes were cleared.'
              : 'One of your contact details was changed.'))));
    log.debug("Leaving RiscRegister.reasonForUser().");
    return text;
  }

  // Put one row back to where a fresh account starts, keeping the row. It is a
  // RESET rather than a delete because the identity is still true — what is
  // being thrown away is what RISC has said about it — and a delete would take
  // the row off the page, which reads as the account having gone, which is
  // exactly what `account-purged` means and must not be faked.
  reset(accountId: unknown): RiscRow | null {
    const { log, iso, audit } = this.deps;
    log.debug("Entering RiscRegister.reset(). " + accountId);
    const row = register.get(String(accountId || ''));
    if (!row) {
      log.debug("Leaving RiscRegister.reset(). No such row.");
      return null;
    }
    row.lifecycle = 'active';
    row.optOut = 'opt-in';
    row.credentialStanding = '';
    row.credentialChangeRequired = false;
    row.recoveryActivated = false;
    row.identifierChanges = [];
    row.credentials = [];
    row.counts = {};
    row.total = 0;
    row.suppressed = 0;
    row.events = [];
    row.streams = [];
    row.notes = ['Reset from the console; the directory entry is untouched.'];
    row.updatedAt = iso();
    this.touch(row);
    audit.audit({ action: 'risc.account.reset', category: 'signals',
      protocol: 'RISC', channel: 'http', target: row.accountId,
      summary: 'The RISC state of account ' + row.accountId + ' was reset' });
    log.debug("Leaving RiscRegister.reset(). Done.");
    return row;
  }

  clear(): number {
    const { log, audit } = this.deps;
    log.debug("Entering RiscRegister.clear().");
    const gone = register.size;
    register.clear();
    audit.audit({ action: 'risc.account.clear', category: 'signals',
      protocol: 'RISC', channel: 'http', target: 'risc',
      summary: gone + ' RISC account row(s) were dropped' });
    log.debug("Leaving RiscRegister.clear(). " + gone + ' dropped.');
    return gone;
  }

  // ---------------------------------------------------------------------------
  // THE REPORT, drawn by /admin/risc-accounts and answered by GET
  // /admin-api/risc. ONE function, so the page and the API cannot come to
  // disagree about what this transmitter has said — which is rule 7's whole
  // subject.
  // ---------------------------------------------------------------------------
  report(): Record<string, any> {
    const { log, config, events, subjects } = this.deps;
    log.debug("Entering RiscRegister.report().");
    const types = events.RISC_EVENTS.map((row) => {
      return { uri: row.uri, name: row.name,
        short: row.uri.slice(events.RISC_PREFIX.length),
        deprecated: String(row.deprecated || '') };
    });
    const totals = {};
    types.forEach((type) => {
      totals[type.uri] = 0;
    });
    const accounts = this.list().map((row) => {
      Object.keys(row.counts).forEach((uri) => {
        totals[uri] = (totals[uri] || 0) + row.counts[uri];
      });
      return {
        accountId: row.accountId,
        sub: row.sub,
        username: row.username,
        iss: row.iss,
        dn: row.dn,
        realm: row.realm,
        email: row.email,
        phone: row.phone,
        formerIdentifiers: row.formerIdentifiers.slice(),
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
        lifecycle: row.lifecycle,
        optOut: row.optOut,
        credentialStanding: row.credentialStanding,
        credentialChangeRequired: row.credentialChangeRequired,
        recoveryActivated: row.recoveryActivated,
        identifierChanges: row.identifierChanges.slice(),
        credentials: row.credentials.slice(),
        counts: Object.assign({}, row.counts),
        total: row.total,
        suppressed: row.suppressed,
        events: row.events.slice(),
        streams: row.streams.slice(),
        notes: row.notes.slice(),
        subject: subjects.describeSubject(
          this.subjectFor(row, events.RISC_PREFIX + 'account-disabled'))
      };
    }).reverse();
    const out = {
      enabled: this.enabled(),
      autoEmit: !!config.value('risc.autoEmit'),
      autoEmitActs: this.autoEmitActs().map((act) => {
        return AUTO_ACTS[act];
      }),
      honourOptOut: !!config.value('risc.honourOptOut'),
      googleSubjectType: !!config.value('risc.googleSubjectType'),
      subjectFormat: String(config.value('risc.subjectFormat') || 'iss_sub'),
      omitEventTimestamp: !!config.value('risc.omitEventTimestamp'),
      eventTypes: types,
      optStates: OPT_STATES.slice(),
      lifecycleStates: LIFECYCLE_STATES.slice(),
      totals: totals,
      accounts: accounts,
      tracked: accounts.length,
      cap: Number(config.value('risc.maxAccountsTracked')) || 200
    };
    log.debug("Leaving RiscRegister.report(). " + out.tracked + ' account(s).');
    return out;
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): RiscRegisterDeps {
    helpers.log.debug("Entering RiscRegister.defaultDeps().");
    helpers.log.debug("Leaving RiscRegister.defaultDeps().");
    return {
      log: helpers.log,
      nowSec: helpers.nowSec,
      iso: helpers.iso,
      nameForSubject: helpers.nameForSubject,
      config: config,
      mode: mode,
      audit: audit,
      events: events,
      subjects: subjects
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<RiscRegister>(
  'ssf/risc',
  () => new RiscRegister(RiscRegister.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  RiscRegister: RiscRegister,
  installInstance: (instance: RiscRegister): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  AUTO_ACTS: RiscRegister.AUTO_ACTS,
  OPT_OUT_EVENTS: RiscRegister.OPT_OUT_EVENTS,
  OPT_STATES: RiscRegister.OPT_STATES,
  LIFECYCLE_STATES: RiscRegister.LIFECYCLE_STATES,
  // A GETTER: `tests/risc_register.js` reads this to know how long the ring
  // is, and the answer is the setting now rather than a constant.
  get EVENTS_PER_ACCOUNT(): number {
    helpers.log.debug("Entering EVENTS_PER_ACCOUNT().");
    helpers.log.debug("Leaving EVENTS_PER_ACCOUNT().");
    return slot.get().eventsPerAccount();
  },
  enabled: slot.forward('enabled'),
  supportedEventUris: slot.forward('supportedEventUris'),
  autoEmitActs: slot.forward('autoEmitActs'),
  subjectFor: slot.forward('subjectFor'),
  // An act an administrator performed (2026-09-13) — see observeAct().
  observeAct: slot.forward('observeAct'),
  googleSubjectType: slot.forward('googleSubjectType'),
  accountIdOf: slot.forward('accountIdOf'),
  rowFor: slot.forward('rowFor'),
  get: slot.forward('get'),
  list: slot.forward('list'),
  commonClaims: slot.forward('commonClaims'),
  buildPayload: slot.forward('buildPayload'),
  gate: slot.forward('gate'),
  applyToState: slot.forward('applyToState'),
  applyDue: slot.forward('applyDue'),
  refusals: slot.forward('refusals'),
  noteTransmitted: slot.forward('noteTransmitted'),
  observe: slot.forward('observe'),
  actsFor: slot.forward('actsFor'),
  reset: slot.forward('reset'),
  clear: slot.forward('clear'),
  report: slot.forward('report')
};
