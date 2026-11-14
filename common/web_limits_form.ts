// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_limits_form.ts
//
// ---------------------------------------------------------------------------
// A RIGHT'S LIMITS AS CONTROLS, DRAWN WHERE THE PAGE IS (#576, 2026-10-12).
//
// `common/limits_form.ts` drew a right's limits as controls a person may
// lower (#432 phase 5) for three server-drawn pages: GNAP's approval page,
// the portal's absent-owner approvals and OAuth's consent screen. The consent
// screen is a page of the sign-in surface since #576, drawn in the browser,
// so the DRAWING moved here, to a `web_` module both halves load: the server
// (`LimitsForm.controls()`, which hands its work to `controls()` below with
// the rows `AccessLimits.rows()` made) and the browser (the consent screen's
// renderer, from the rows its view carries). One copy of the markup, so a
// detail's limits look the same on every page that asks about them, and
// `lowered()` — which stayed in `limits_form.ts`, on the server — reads back
// the field names drawn here.
//
// THE WORDS ARE ENGLISH, as they were: the controls' labels are the same
// sentence on every page that draws them, and none of those pages translated
// them before this one moved.
//
// A `web_` MODULE: it requires nothing and logs nothing.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * A right's limits as controls a person may lower. A static utility class.
 */
class WebLimitsForm {
  /**
   * The name of one limit control of right `r` of token `t`.
   *
   * @param t - the token's index
   * @param r - the right's index in the token
   * @param member - the limit member
   * @returns the field name
   */
  static field(t: number, r: number, member: string): string {
    return 'lim_t' + t + 'r' + r + '_' + member;
  }

  /**
   * The receivers a `limits` object names, as strings, or null.
   *
   * @param limits - the limits member
   * @returns the receivers
   */
  static receiversOf(limits: Json): string[] | null {
    const value = limits ? limits.receiver : undefined;
    if (value === undefined) {
      return null;
    }
    return (Array.isArray(value) ? value : [value]).map(String);
  }

  /**
   * Draws the controls of one right's limits.
   *
   * @param limits - the right's `limits` member
   * @param rows - `AccessLimits.rows(limits)`: `{ member, label, value }`
   *   in the order they are drawn
   * @param t - the token's index
   * @param r - the right's index in the token
   * @param esc - the page's escaper
   * @returns the markup, or '' where there are no limits
   */
  static controls(limits: Json, rows: Json[], t: number, r: number,
                  esc: (text: string) => string): string {
    if (!limits || typeof limits !== 'object') {
      return '';
    }
    const name = function (member: string): string {
      return WebLimitsForm.field(t, r, member);
    };
    const input = function (member: string, value: string,
                            mode: string): string {
      return '<input name="' + name(member) + '" value="' + esc(value) +
        '" inputmode="' + mode + '" size="24">';
    };
    const out: string[] = [];
    (rows || []).forEach(function (row: Json): void {
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
          '" value="1">only to ' + (WebLimitsForm.receiversOf(limits) || [])
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
      out.push('<div>' + control + '</div>');
    });
    return '<div class="limits"><span>Limits — you may lower any of them, ' +
      'never raise one:</span>' + out.join('') + '</div>';
  }
}

export = WebLimitsForm;
