// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_page_state.ts
//
// ---------------------------------------------------------------------------
// WHAT A PAGE HELD, KEPT ACROSS A SIGN-IN THAT HAS TO LEAVE IT (#508, #2220).
//
// The console has kept its forms' choices in `sessionStorage` across a
// sign-in that leaves the page since #508, and put them back when the page
// is drawn again. A second authorization for a write (#2168) normally
// happens in a window of its own and leaves nothing to keep; only where a
// browser has no `window.open` or no `BroadcastChannel` does the page
// leave for the authorization page. The portal and the reports application
// lost the page's state there as well as the pending change (ASVS 5.0.0
// 3.1.1, #2220). So the console's three functions are here, one copy, with
// `save()` and `take()` around them for any surface:
//
//   * `keepsField()` decides what is kept: CHOICES only — a checkbox, a
//     radio, a select — never a password, a file, a hidden field, a button,
//     anything typed (names and mail are personal data, ASVS 5.0.0 14.3.3)
//     or a control named or marked for a secret;
//   * `save()` writes the forms' choices under a key, with the realm, the
//     page and the person, and never throws;
//   * `take()` reads them once, removes them, and puts them back only for
//     the same realm, page and person within `MAX_AGE_MS`, saying which.
//
// Nothing that was waiting is sent: the page says so, and the person makes
// the change again.
//
// A `web_` MODULE: it requires nothing and logs nothing. It runs in a
// browser; a test drives it with stand-ins.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * A page's forms' choices across a redirect. A static utility class.
 */
class WebPageState {
  /**
   * How long what was kept may be put back, in milliseconds.
   */
  static readonly MAX_AGE_MS = 30 * 60 * 1000;

  /**
   * Whether a form control's value may be kept across a sign-in: never a
   * password, a file, a hidden field, a button, or a control named or
   * marked for a secret.
   *
   * @param el - the control
   * @returns true when it is kept
   */
  static keepsField(el: Json): boolean {
    const name = String((el && el.name) || '');
    const type = String((el && el.type) || '').toLowerCase();
    if (!name || el.disabled) {
      return false;
    }
    if (['password', 'file', 'hidden', 'submit', 'button', 'reset',
         'image'].indexOf(type) >= 0) {
      return false;
    }
    // WHAT PEOPLE TYPE STAYS OUT OF STORAGE (ASVS 5.0.0 14.3.3): names and mail
    // are personal data, and this survives until the page returns. Choices
    // carry none of it.
    if (['checkbox', 'radio', 'select-one', 'select-multiple']
      .indexOf(type) < 0) {
      return false;
    }
    const auto = el.getAttribute
      ? String(el.getAttribute('autocomplete') || '') : '';
    if (/new-password|current-password|one-time-code/.test(auto) ||
        (el.getAttribute && el.getAttribute('data-sensitive') !== null &&
         el.getAttribute('data-sensitive') !== undefined)) {
      return false;
    }
    return !/secret|passw|private|credential|token|otp/i.test(name);
  }

  /**
   * What one form holds, as kept across a sign-in.
   *
   * @param form - the form
   * @param pending - whether it is the form being sent
   * @returns `{ action, pending, fields }`
   */
  static formSnapshot(form: Json, pending: boolean): Json {
    const fields: Json[] = [];
    const els = (form && form.elements) || [];
    for (let i = 0; i < els.length; i++) {
      const el = els[i];
      if (!WebPageState.keepsField(el)) {
        continue;
      }
      const type = String(el.type || '').toLowerCase();
      if (type === 'checkbox' || type === 'radio') {
        fields.push({ name: el.name, value: String(el.value),
                      checked: !!el.checked });
      } else if (el.multiple && el.options) {
        const values: string[] = [];
        for (let j = 0; j < el.options.length; j++) {
          if (el.options[j].selected) {
            values.push(String(el.options[j].value));
          }
        }
        fields.push({ name: el.name, values: values });
      } else {
        fields.push({ name: el.name, value: String(el.value || '') });
      }
    }
    return { action: String((form.getAttribute &&
                             form.getAttribute('action')) || ''),
             pending: !!pending, fields: fields };
  }

  /**
   * Puts kept values back into the forms drawn: the same form by its place
   * and its address, the same control by its name and order.
   *
   * @param forms - the forms drawn, in document order
   * @param saved - `formSnapshot()`'s answers, in the same order
   * @returns `{ restored, unplaced }`, counts of values
   */
  static restoreForms(forms: Json[], saved: Json[]): Json {
    let restored = 0;
    let unplaced = 0;
    (saved || []).forEach(function (kept, i) {
      const form = forms[i];
      const action = form && form.getAttribute
        ? String(form.getAttribute('action') || '') : '';
      if (!form || action !== String(kept.action || '')) {
        unplaced += (kept.fields || []).length;
        return;
      }
      const byName: Json = {};
      const els = form.elements || [];
      for (let j = 0; j < els.length; j++) {
        if (WebPageState.keepsField(els[j])) {
          (byName[els[j].name] = byName[els[j].name] || []).push(els[j]);
        }
      }
      const used: Json = {};
      (kept.fields || []).forEach(function (field) {
        const named = byName[field.name] || [];
        if (field.checked !== undefined) {
          const box = named.filter(function (el) {
            return String(el.value) === String(field.value);
          })[0];
          if (!box) {
            unplaced++;
            return;
          }
          box.checked = !!field.checked;
          restored++;
          return;
        }
        const at = used[field.name] || 0;
        used[field.name] = at + 1;
        const el = named[at];
        if (!el) {
          unplaced++;
          return;
        }
        if (field.values && el.options) {
          for (let k = 0; k < el.options.length; k++) {
            el.options[k].selected =
              field.values.indexOf(String(el.options[k].value)) >= 0;
          }
        } else {
          el.value = String(field.value || '');
        }
        restored++;
      });
    });
    return { restored: restored, unplaced: unplaced };
  }

  /**
   * Keeps the forms' choices in `sessionStorage`, for after a redirect.
   * Storage refused or full keeps nothing, and the redirect still goes.
   *
   * @param env - the browser's objects: `document`, `sessionStorage`, and
   *   `now` where a test gives one
   * @param key - the storage key
   * @param facts - `{ prefix, path, subject, submitting }`: the realm, the
   *   page, the person, and the form being sent, if any
   * @returns whether anything was kept
   */
  static save(env: Json, key: string, facts: Json): boolean {
    const doc = env && env.document;
    if (!facts || !facts.subject || !doc || !doc.querySelectorAll) {
      return false;
    }
    const forms = doc.querySelectorAll('form');
    const kept: Json[] = [];
    for (let i = 0; i < forms.length; i++) {
      kept.push(WebPageState.formSnapshot(forms[i],
                                          forms[i] === facts.submitting));
    }
    try {
      env.sessionStorage.setItem(key, JSON.stringify({
        prefix: facts.prefix, path: facts.path, subject: facts.subject,
        at: env.now ? env.now() : Date.now(), forms: kept }));
    } catch (e) {
      // NO ROOM, or storage refused: the page comes back without what it
      // held, as it did before.
      return false;
    }
    return true;
  }

  /**
   * After a sign-in that left the page: reads what was kept once, removes
   * it, and puts it back for the same realm, page and person.
   *
   * @param env - the browser's objects: `document`, `sessionStorage`, `now`
   * @param key - the storage key
   * @param facts - `{ prefix, path, subject }` of the page now drawn
   * @returns `{ state, restored, unplaced }`: `state` is `none` (nothing
   *   for this page), `other` (another person signed in) or `restored`
   */
  static take(env: Json, key: string, facts: Json): Json {
    const none = { state: 'none', restored: 0, unplaced: 0 };
    let saved: Json = null;
    try {
      saved = JSON.parse(env.sessionStorage.getItem(key) || 'null');
      env.sessionStorage.removeItem(key);
    } catch (e) {
      // Not JSON, or storage refused: nothing this page kept.
      saved = null;
    }
    const now = env && env.now ? env.now() : Date.now();
    if (!saved || !facts || saved.prefix !== facts.prefix ||
        saved.path !== facts.path ||
        now - Number(saved.at || 0) > WebPageState.MAX_AGE_MS) {
      return none;
    }
    if (!saved.subject || saved.subject !== facts.subject) {
      return { state: 'other', restored: 0, unplaced: 0 };
    }
    const doc = env.document;
    const forms = doc && doc.querySelectorAll ? doc.querySelectorAll('form')
                                              : [];
    const list: Json[] = [];
    for (let i = 0; i < forms.length; i++) {
      list.push(forms[i]);
    }
    const done = WebPageState.restoreForms(list, saved.forms);
    return { state: done.restored ? 'restored' : 'none',
             restored: done.restored, unplaced: done.unplaced };
  }
}

export = WebPageState;
