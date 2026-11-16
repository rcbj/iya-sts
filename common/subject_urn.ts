// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: subject_urn.ts
//
// ---------------------------------------------------------------------------
// THE NAMES A CERTIFICATE THIS SERVICE ISSUES GIVES ITS HOLDER, DEFINED ONCE
// (#1827, rcbj 2026-11-16).
//
// Every leaf this service issues says WHO it is for in a URI subjectAltName,
// `urn:sts:<kind>:<name>`, and every door that meets one of its own leaves
// reads that name rather than the common name: the TLS client gate
// (`tls_client_certificates.js`'s `identityOf()`), the RFC 7523 / RFC 7522
// assertion's `x5c` (`assertion_grant.js`), an upload registered in place of a
// key pair (`pki.js`'s `registerCertificate()`), a WS-Security signer
// (`wstrust.ts`), the enrollment families and their cell routing
// (`cert_enrollment.ts`), and the inter-cell channel (`cell_channel.ts`).
// Until #1827 each of them spelt the prefixes itself, and rcbj's two
// sentences that day are why this file exists:
//
//   "Instead of urn:sts:person:remote-pep-N use the format urn:sts:sa:blah
//    for service accounts, but underneath, it's a regular user object."
//   "Let's make these references more centrally defined and easy to change."
//
// So the prefixes are HERE, and nowhere else in executable code
// (`tests/subject_urn_literals.js` holds that). A new kind of holder is a row
// in `FORMS`; renaming one is one edit.
//
// ---------------------------------------------------------------------------
// FORMS AND KINDS ARE TWO DIFFERENT QUESTIONS.
//
// The FORM is how the name is spelt: `person`, `sa`, `application`,
// `federation`, `cell`, `device`. The KIND is what sort of entry it names,
// which is what every rule asks: a `sa` name is a PERSON, because a service
// account is a person entry with a flag (#221, `service_accounts.ts`) — "a
// person may assert only about themselves" holds for it word for word, and it
// is never an application. So `parse()` answers both, and a reader asks
// `kind` unless the question is specifically about the spelling.
//
// WHICH SPELLING A PERSON GETS is decided at ISSUE by whoever holds the entry:
// `forPerson(name, serviceAccount)`, the caller having asked
// `service_accounts.isServiceAccountName()`. This module never asks it, so it
// stays a leaf. And BOTH spellings are read for ever: a leaf issued with
// `urn:sts:person:` to an entry that is (or has since become) a service
// account keeps working wherever it worked, which is rcbj's 1.0.0 rule on
// backwards compatibility. What a door must refuse — `urn:sts:sa:` naming an
// entry that is NOT a service account — needs the directory, so the door
// asks; `isServiceAccountForm()` is the question it asks first.
//
// **A LEAF (rule 3)**: it requires `bunyan` and `config` (for the log level,
// as `certificate_details.ts` does) and nothing else of this service, so
// `pki.js`, `crypto.js`'s neighbours, `tls_client_certificates.js` and every
// route module may require it at load with no cycle and no route moved.
// A static utility class: no state, no dependencies to inject.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('./config');

const log = bunyan.createLogger({
  name: 'subject_urn',
  level: config.value('global.logLevel')
});

/**
 * How a holder's name is spelt in a certificate.
 */
type Form = 'person' | 'sa' | 'application' | 'federation' | 'cell' |
            'device';

/**
 * What a parsed name says: its spelling, the kind of entry it names, and the
 * name itself.
 */
interface Parsed {
  form: Form;
  kind: string;
  name: string;
  uri: string;
}

/**
 * The one table: each form's prefix and the kind of entry it names.
 */
const FORMS: Readonly<Record<Form, Readonly<{ prefix: string;
                                               kind: string }>>> =
  Object.freeze({
    person: Object.freeze({ prefix: 'urn:sts:person:', kind: 'person' }),
    // A SERVICE ACCOUNT IS A PERSON (#221): its own spelling, the person's
    // kind (#1827).
    sa: Object.freeze({ prefix: 'urn:sts:sa:', kind: 'person' }),
    application: Object.freeze({ prefix: 'urn:sts:application:',
                                 kind: 'application' }),
    // A federation relationship's encryption certificate (`pki.js`).
    federation: Object.freeze({ prefix: 'urn:sts:federation:',
                                kind: 'federation' }),
    // An inter-cell channel leaf (`cell_channel.ts`).
    cell: Object.freeze({ prefix: 'urn:sts:cell:', kind: 'cell' }),
    // A device entry's enrolled certificate (`cert_enrollment.ts`).
    device: Object.freeze({ prefix: 'urn:sts:device:', kind: 'device' })
  });

// Longest prefix first is not needed — no prefix is a prefix of another —
// but the order is fixed so that `parse()` answers the same way every time.
const FORM_IDS = Object.freeze(Object.keys(FORMS) as Form[]);

/**
 * The subject names this service writes in the certificates it issues: one
 * table of prefixes and the helpers every writer and reader uses.
 */
class SubjectUrn {
  static readonly FORMS = FORMS;
  static readonly FORM_IDS = FORM_IDS;
  static readonly PERSON = FORMS.person.prefix;
  static readonly SERVICE_ACCOUNT = FORMS.sa.prefix;
  static readonly APPLICATION = FORMS.application.prefix;
  static readonly FEDERATION = FORMS.federation.prefix;
  static readonly CELL = FORMS.cell.prefix;
  static readonly DEVICE = FORMS.device.prefix;
  /**
   * The forms that name a person entry: a person, and a service account.
   */
  static readonly PERSON_FORMS: readonly Form[] =
    Object.freeze(['person', 'sa'] as Form[]);

  /**
   * Returns a form's prefix.
   *
   * @param form - the form
   * @returns the prefix, or '' for a form this table does not hold
   */
  static prefixOf(form: string): string {
    log.debug("Entering SubjectUrn.prefixOf().");
    const row = Object.prototype.hasOwnProperty.call(FORMS, form)
      ? FORMS[form as Form] : null;
    log.debug("Leaving SubjectUrn.prefixOf().");
    return row ? row.prefix : '';
  }

  /**
   * Builds a name in one form.
   *
   * @param form - the form
   * @param name - the holder's name or identifier
   * @returns the URI, or '' for a form this table does not hold
   */
  static make(form: string, name: unknown): string {
    log.debug("Entering SubjectUrn.make().");
    const prefix = SubjectUrn.prefixOf(form);
    log.debug("Leaving SubjectUrn.make().");
    return prefix ? prefix + String(name == null ? '' : name) : '';
  }

  /**
   * Builds the name a PERSON entry's certificate carries: `urn:sts:sa:` for a
   * service account, `urn:sts:person:` for anybody else. The caller says
   * which, having asked the directory at issue.
   *
   * @param name - the username
   * @param serviceAccount - whether the entry is a service account now
   * @returns the URI
   */
  static forPerson(name: unknown, serviceAccount: boolean): string {
    log.debug("Entering SubjectUrn.forPerson().");
    log.debug("Leaving SubjectUrn.forPerson(). " +
              (serviceAccount ? 'sa' : 'person'));
    return SubjectUrn.make(serviceAccount ? 'sa' : 'person', name);
  }

  /**
   * Builds the name for a holder of a kind: a person (spelt for a service
   * account where `serviceAccount` says so), an application, or any other
   * form by its id.
   *
   * @param kind - 'person', 'application', or another form
   * @param name - the holder's name or identifier
   * @param serviceAccount - for a person, whether it is a service account
   * @returns the URI, or '' for a kind this table does not hold
   */
  static forHolder(kind: string, name: unknown,
                   serviceAccount?: boolean): string {
    log.debug("Entering SubjectUrn.forHolder().");
    const out = kind === 'person'
      ? SubjectUrn.forPerson(name, serviceAccount === true)
      : SubjectUrn.make(kind, name);
    log.debug("Leaving SubjectUrn.forHolder().");
    return out;
  }

  /**
   * Reads one of this service's subject names, as a bare URI or as a
   * subjectAltName member (`URI:urn:sts:…`).
   *
   * @param value - the URI or member
   * @param forms - optional: only these forms are recognised
   * @returns `{ form, kind, name, uri }`, or null when it is none of ours or
   *   names nobody
   */
  static parse(value: unknown, forms?: readonly string[]): Parsed | null {
    log.debug("Entering SubjectUrn.parse().");
    let text = String(value == null ? '' : value).trim();
    if (text.indexOf('URI:') === 0) {
      text = text.slice(4);
    }
    let out: Parsed | null = null;
    for (let i = 0; i < FORM_IDS.length && !out; i++) {
      const form = FORM_IDS[i];
      if (forms && forms.indexOf(form) < 0) {
        continue;
      }
      const prefix = FORMS[form].prefix;
      if (text.indexOf(prefix) === 0 && text.length > prefix.length) {
        out = { form: form, kind: FORMS[form].kind,
                name: text.slice(prefix.length), uri: text };
      }
    }
    log.debug("Leaving SubjectUrn.parse(). " + (out ? out.form : 'none'));
    return out;
  }

  /**
   * Says whether a value is one of this service's subject names.
   *
   * @param value - the URI or subjectAltName member
   * @returns true when it is
   */
  static isSubjectUrn(value: unknown): boolean {
    log.debug("Entering SubjectUrn.isSubjectUrn().");
    const out = !!SubjectUrn.parse(value);
    log.debug("Leaving SubjectUrn.isSubjectUrn(). " + out);
    return out;
  }

  /**
   * Says whether a value names a person entry: `urn:sts:person:` or
   * `urn:sts:sa:`.
   *
   * @param value - the URI or subjectAltName member
   * @returns true when it does
   */
  static namesPerson(value: unknown): boolean {
    log.debug("Entering SubjectUrn.namesPerson().");
    const out = !!SubjectUrn.parse(value, SubjectUrn.PERSON_FORMS);
    log.debug("Leaving SubjectUrn.namesPerson(). " + out);
    return out;
  }

  /**
   * Says whether a value is spelt as a service account's name,
   * `urn:sts:sa:` — the one form a door must check against the directory.
   *
   * @param value - the URI, subjectAltName member, or a `parse()` answer
   * @returns true when it is
   */
  static isServiceAccountForm(value: unknown): boolean {
    log.debug("Entering SubjectUrn.isServiceAccountForm().");
    const parsed = value && typeof value === 'object' &&
                   typeof (value as Parsed).form === 'string'
      ? value as Parsed : SubjectUrn.parse(value);
    const out = !!parsed && parsed.form === 'sa';
    log.debug("Leaving SubjectUrn.isServiceAccountForm(). " + out);
    return out;
  }

  /**
   * Reads every subject name out of a list of URIs or a node-style
   * subjectAltName string (`DNS:a, URI:urn:sts:…`).
   *
   * @param names - the string, or an array of URIs or members
   * @param forms - optional: only these forms are recognised
   * @returns the parsed names, in order
   */
  static namesIn(names: unknown, forms?: readonly string[]): Parsed[] {
    log.debug("Entering SubjectUrn.namesIn().");
    const list = Array.isArray(names) ? names
      : String(names == null ? '' : names).split(/,\s*/)
        .filter(function (one) {
          return one.trim().indexOf('URI:') === 0;
        });
    const out: Parsed[] = [];
    list.forEach(function (one) {
      const parsed = SubjectUrn.parse(one, forms);
      if (parsed) {
        out.push(parsed);
      }
    });
    log.debug("Leaving SubjectUrn.namesIn(). " + out.length);
    return out;
  }

  /**
   * Says whether two names name the same entry, whatever their spelling:
   * `urn:sts:person:x` and `urn:sts:sa:x` are the same person.
   *
   * @param a - a URI or member
   * @param b - another
   * @returns true when both are ours and name one entry
   */
  static sameHolder(a: unknown, b: unknown): boolean {
    log.debug("Entering SubjectUrn.sameHolder().");
    const one = SubjectUrn.parse(a);
    const two = SubjectUrn.parse(b);
    const out = !!one && !!two && one.kind === two.kind &&
                one.name === two.name;
    log.debug("Leaving SubjectUrn.sameHolder(). " + out);
    return out;
  }
}

export = SubjectUrn;
