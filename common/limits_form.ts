// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: limits_form.ts
//
// ===========================================================================
// A RIGHT'S LIMITS AS A FORM A PERSON CAN LOWER (#432 phase 5).
//
// Three pages ask a person to approve access that may carry limits: GNAP's
// approval page (`gnap/gnap_interact.ts`) for the person at the browser,
// `/portal/ciba` (`portal/portal_ciba.ts`, through `gnap/gnap_approval.ts`)
// for a GNAP resource owner who was not there when the client asked (#432
// phase 6), and OAuth's consent screen (`oauth-oidc/consent_screen.ts`) for
// an RFC 9396 detail. All three must draw a limit the same way and accept
// back only LOWER ones, so the drawing and the reading are here, once — in
// `common/`, because two protocol directories read it (a GNAP right and an
// RFC 9396 detail share the `limits` member and its vocabulary):
//
//   * `controls()` draws each member with a meaning (`common/
//     access_limits.ts`) as a control holding the requested value, under
//     its right; a member this service gives no meaning is shown and not
//     editable; the receiver boxes carry a marker, so a form sent back with
//     every box unticked is told from one that never showed them.
//   * `lowered()` reads the posted values back onto the ticked rights (a
//     GNAP token's `access`, or the one list of a request's details): an
//     unchanged value is kept byte for byte, a changed one must be LOWER
//     (`AccessLimits.raised()`: STS-GNAP-0866) and the lowered limits must
//     still meet the type's limits schema (0867).
//   * `strip()` takes the controls off a posted form before the form's own
//     schema reads it.
//
// A STATIC UTILITY CLASS: no route, no store, no state. With script off
// (there is none on either page) every control is plain markup.
// ===========================================================================

import helpers = require('./helpers');
import AccessLimits = require('./access_limits');

type Json = any;

// What `lowered()` reads a posted form through: one value, and the values of
// a repeated (checkbox) field.
interface PostedForm {
  value(name: string): string | undefined;
  values(name: string): string[];
}

/**
 * A right's limits as a form a person can lower, shared by GNAP's approval
 * page, the portal's absent-owner approvals and OAuth's consent screen (#432
 * phase 5).
 */
class LimitsForm {
  /**
   * The name of one limit control of right `r` of token `t`.
   *
   * @param t - the token's index
   * @param r - the right's index in the token
   * @param member - the limit member
   * @returns the field name
   */
  static field(t: number, r: number, member: string): string {
    helpers.log.debug("Entering LimitsForm.field().");
    helpers.log.debug("Leaving LimitsForm.field().");
    return 'lim_t' + t + 'r' + r + '_' + member;
  }

  /**
   * Draws the controls of one right's limits.
   *
   * @param right - the access right
   * @param t - the token's index
   * @param r - the right's index in the token
   * @param esc - the page's escaper
   * @returns the markup, or '' for a right that carries no limits
   */
  static controls(right: Json, t: number, r: number,
                  esc: (text: string) => string): string {
    const log = helpers.log;
    log.debug("Entering LimitsForm.controls().");
    if (!right || typeof right !== 'object' || !right.limits ||
        typeof right.limits !== 'object') {
      log.debug("Leaving LimitsForm.controls(). None.");
      return '';
    }
    const limits = right.limits;
    const name = function (member: string): string {
      log.debug("Entering name().");
      log.debug("Leaving name().");
      return LimitsForm.field(t, r, member);
    };
    const input = function (member: string, value: string,
                            mode: string): string {
      log.debug("Entering input().");
      log.debug("Leaving input().");
      return '<input name="' + name(member) + '" value="' + esc(value) +
        '" inputmode="' + mode + '" size="24">';
    };
    const rows: string[] = [];
    AccessLimits.rows(limits).forEach(function (row: Json): void {
      const v = limits[row.member];
      let control = '';
      if (row.member === 'amount') {
        control = 'at most ' + input('amount', String(v), 'decimal') + ' ' +
          esc(String(limits.currency || ''));
      } else if (row.member === 'currency') {
        // Drawn beside the amount; a currency never changes.
        return;
      } else if (row.member === 'count') {
        control = 'at most ' + input('count', String(v), 'numeric') +
          ' operations';
      } else if (row.member === 'receiver') {
        control = '<input type="hidden" name="' + name('receiverShown') +
          '" value="1">only to ' + (AccessLimits.receiversOf(limits) || [])
          .map(function (one: string): string {
            return '<label><input type="checkbox" name="' +
              name('receiver') + '" value="' + esc(one) + '" checked> ' +
              esc(one) + '</label>';
          }).join(' ');
      } else if (row.member === 'interval') {
        control = 'resetting on ' + input('interval', String(v), 'text') +
          ' <span class="sub">(ISO 8601: R[n]/start/period; a longer ' +
          'period or fewer repetitions is lower)</span>';
      } else if (row.member === 'window' && v && typeof v === 'object') {
        control = 'not before ' + input('notBefore',
          String(v.notBefore || ''), 'text') + ' and not after ' +
          input('notAfter', String(v.notAfter || ''), 'text');
      } else {
        control = esc(row.label + ' ' + row.value) + ' <span class="sub">' +
          '(the API\'s own; it cannot be changed here)</span>';
      }
      rows.push('<div>' + control + '</div>');
    });
    log.debug("Leaving LimitsForm.controls().");
    return '<div class="limits"><span>Limits — you may lower any of them, ' +
      'never raise one:</span>' + rows.join('') + '</div>';
  }

  /**
   * Takes the limit controls off a posted form.
   *
   * @param body - the parsed form
   * @returns a copy without them
   */
  static strip(body: Json): Json {
    helpers.log.debug("Entering LimitsForm.strip().");
    const out: Json = {};
    Object.keys(body || {}).forEach(function (key: string): void {
      if (!/^lim_t\d+r\d+_/.test(key)) {
        out[key] = body[key];
      }
    });
    helpers.log.debug("Leaving LimitsForm.strip().");
    return out;
  }

  /**
   * Reads the posted limits back onto the ticked rights.
   *
   * @param asked - the grant's requested tokens (the rights' identities)
   * @param tokens - the ticked tokens, each right one of `asked`'s
   * @param posted - how the posted form is read
   * @param conformanceRefusal - `gnap_rights.conformanceRefusal()`
   * @returns `{ ok: true, tokens }`, or `{ ok: false, code, why }`
   */
  static lowered(asked: Json[], tokens: Json[], posted: PostedForm,
                 conformanceRefusal: (tokens: Json[]) => Json): Json {
    const log = helpers.log;
    log.debug("Entering LimitsForm.lowered().");
    const out: Json[] = [];
    for (let t = 0; t < tokens.length; t++) {
      const from = (asked && asked[t]) || { access: [] };
      const access: Json[] = [];
      for (let k = 0; k < tokens[t].access.length; k++) {
        const right = tokens[t].access[k];
        const r = from.access.indexOf(right);
        if (!right || typeof right !== 'object' || !right.limits ||
            typeof right.limits !== 'object' || r < 0) {
          access.push(right);
          continue;
        }
        const was = right.limits;
        const proposed: Json = JSON.parse(JSON.stringify(was));
        const value = function (member: string): string | undefined {
          log.debug("Entering value().");
          const got = posted.value(LimitsForm.field(t, r, member));
          log.debug("Leaving value().");
          return typeof got === 'string' ? got.trim() : undefined;
        };
        if (was.amount !== undefined && value('amount') !== undefined &&
            value('amount') !== String(was.amount)) {
          // The spelling the request used: a number stays a number, so the
          // type's schema reads the lowered value as it read the asked.
          proposed.amount = typeof was.amount === 'number' &&
            /^\d{1,15}(\.\d{1,6})?$/.test(value('amount'))
            ? Number(value('amount')) : value('amount');
        }
        if (was.count !== undefined && value('count') !== undefined &&
            value('count') !== String(was.count)) {
          proposed.count = /^\d{1,15}$/.test(value('count'))
            ? Number(value('count')) : value('count');
        }
        if (was.receiver !== undefined && value('receiverShown') === '1') {
          const kept = posted.values(LimitsForm.field(t, r, 'receiver'));
          const before = AccessLimits.receiversOf(was) || [];
          if (kept.length !== before.length ||
              kept.some(function (one: string): boolean {
                return before.indexOf(one) < 0;
              })) {
            if (!kept.length) {
              log.debug("Leaving LimitsForm.lowered(). No receiver.");
              return { ok: false, code: 'STS-GNAP-0866', why: 'Every ' +
                'receiver of "' + right.type + '" was unticked; untick the ' +
                'right itself to leave it out.' };
            }
            proposed.receiver = typeof was.receiver === 'string' &&
              kept.length === 1 ? kept[0] : kept;
          }
        }
        if (typeof was.interval === 'string' &&
            value('interval') !== undefined &&
            value('interval') !== was.interval) {
          proposed.interval = value('interval');
        }
        if (was.window && typeof was.window === 'object') {
          ['notBefore', 'notAfter'].forEach(function (end: string): void {
            const got = value(end);
            if (got !== undefined && got !== String(was.window[end] || '')) {
              proposed.window = Object.assign({}, proposed.window);
              if (got) {
                proposed.window[end] = got;
              } else {
                delete proposed.window[end];
              }
            }
          });
        }
        const raised = AccessLimits.raised(was, proposed);
        if (raised) {
          log.debug("Leaving LimitsForm.lowered(). Raised.");
          return { ok: false, code: 'STS-GNAP-0866', why: 'The limits of "' +
            right.type + '" may only be lowered here: ' + raised + '.' };
        }
        const next = Object.assign({}, right, { limits: proposed });
        const malformed = conformanceRefusal([{ access: [next] }]);
        if (malformed) {
          log.debug("Leaving LimitsForm.lowered(). The schema.");
          return { ok: false, code: 'STS-GNAP-0867', why: malformed.why };
        }
        access.push(next);
      }
      out.push(Object.assign({}, tokens[t], { access: access }));
    }
    log.debug("Leaving LimitsForm.lowered().");
    return { ok: true, tokens: out };
  }
}

/**
 * A right's limits as a form a person can lower (#432 phase 5). A static
 * utility class.
 */
export = LimitsForm;
