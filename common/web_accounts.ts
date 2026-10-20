// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_accounts.ts
//
// ---------------------------------------------------------------------------
// A BROWSER'S ACCOUNTS, AS EVERY STATIC SURFACE READS THEM (#561, delivery
// steps 5 and 6).
//
// With `authn.multipleAccounts` on, one browser may hold several signed-in
// accounts at once (`authn/CLAUDE.md`, *Several signed-in accounts in one
// browser*), and the list of them is `GET /authn-api/accounts` — keys,
// subjects, names, states and times, never a sid or a token. Three kinds of
// page draw it, and this is what they share:
//
//   * THE LIST (`fetchList()`): that operation, asked of THIS page's own
//     origin with the cookie (`credentials: 'same-origin'`). Never of another
//     listener's: `common/cors.js` sends no `Access-Control-Allow-Credentials`
//     to anybody, so a cross-origin read of a cookie-bound answer cannot be
//     made here, and a page whose origin does not answer `/authn-api` draws
//     no list. Anything but a 200 with `enabled: true` is read as OFF — the
//     setting off, a realm without it, an older service, a network failure —
//     and a page that reads OFF draws exactly what it drew before #561.
//   * THE CHANGE SIGNAL (`openChannel()`): `BroadcastChannel('sts-accounts')`
//     carries that the list CHANGED (an account added, signed out or
//     forgotten) and nothing else — no account, no key, no selection. A tab
//     that hears it fetches the list again for its menu and changes nothing
//     else: a message never changes which account another tab is (the
//     plan's decision 8). Order cannot matter, because every message is
//     answered by asking the server, which is authoritative; a message that
//     never arrives costs a stale menu until the next fetch. A page posts
//     only what its OWN act or navigation changed (`changed()`), never in
//     answer to a message, so two tabs cannot echo each other.
//   * THE CONTROL a public surface draws (`controlHtml()`): the live accounts
//     and *Sign in with another account*, which goes to the user portal with
//     `accounts=another` — the portal's runtime turns that into its own
//     authorization request with `prompt=login` (`/authn/login` is not a
//     destination: it needs a pending sign-in). The console and the portal
//     draw their own menus from the same list (`admin-ui/web_shell.ts`,
//     `portal/web_portal_shell.ts`).
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires nothing,
// logs nothing (code that runs in a browser is exempt from the Entering /
// Leaving rule), and reaches the browser only through the `env` it is handed.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * A browser's accounts: reading the list, the change signal, the control.
 * A static utility class; it holds no state.
 */
class WebAccounts {
  // The channel a change to the list is announced on.
  static readonly CHANNEL = 'sts-accounts';
  // The list's operation, under the realm's prefix.
  static readonly PATH = '/authn-api/accounts';
  // What a link to the portal carries to ask for a sign-in as another
  // account; the portal's runtime reads it (`PortalRuntime.route()`).
  static readonly ANOTHER_PARAM = 'accounts';
  static readonly ANOTHER_VALUE = 'another';
  // THE MESSAGE'S TYPE, so a message of anything else on the channel's name
  // is not mistaken for one.
  static readonly MESSAGE = 'accounts-changed';

  /**
   * The list as OFF: what every page that could not read it draws from.
   *
   * @returns `{ enabled: false, accounts: [] }`
   */
  static off(): Json {
    return { enabled: false, accounts: [], max: 0 };
  }

  /**
   * Fetches the browser's accounts from this page's own origin.
   *
   * @param env - the browser's objects: `fetch`, `location`
   * @param prefix - the realm's path prefix
   * @returns the list, or OFF where it could not be read or is off
   */
  static async fetchList(env: Json, prefix: string): Promise<Json> {
    if (!env || typeof env.fetch !== 'function' || !env.location) {
      return WebAccounts.off();
    }
    try {
      const res = await env.fetch(String(env.location.origin || '') +
        String(prefix || '') + WebAccounts.PATH, {
        method: 'GET', credentials: 'same-origin',
        headers: { 'Accept': 'application/json' } });
      if (!res || res.status !== 200) {
        return WebAccounts.off();
      }
      const json = await res.json();
      if (!json || json.enabled !== true || !Array.isArray(json.accounts)) {
        return WebAccounts.off();
      }
      return json;
    } catch (e) {
      // Unreachable, or not JSON: OFF, which draws today's page.
      return WebAccounts.off();
    }
  }

  /**
   * The signed-in accounts of a list.
   *
   * @param list - the list
   * @returns the accounts whose state is `signed-in`
   */
  static live(list: Json): Json[] {
    return ((list && list.accounts) || []).filter(function (one: Json) {
      return one && one.state === 'signed-in';
    });
  }

  /**
   * The live account a subject is, in a list.
   *
   * @param list - the list
   * @param sub - the subject
   * @returns the account, or null
   */
  static bySubject(list: Json, sub: string): Json {
    if (!sub) {
      return null;
    }
    return WebAccounts.live(list).filter(function (one: Json) {
      return String(one.sub || '') === sub;
    })[0] || null;
  }

  /**
   * The live account a key is, in a list.
   *
   * @param list - the list
   * @param key - the account's key
   * @returns the account, or null
   */
  static byKey(list: Json, key: string): Json {
    return WebAccounts.live(list).filter(function (one: Json) {
      return String(one.key || '') === String(key || '');
    })[0] || null;
  }

  /**
   * What a list says, as one string: two lists with the same accounts in the
   * same states are the same, whatever order they came in.
   *
   * @param list - the list
   * @returns its fingerprint
   */
  static fingerprint(list: Json): string {
    if (!list || !list.enabled) {
      return 'off';
    }
    return (list.accounts || []).map(function (one: Json) {
      return String(one.key || '') + '=' + String(one.state || '');
    }).sort().join('|');
  }

  /**
   * Whether two lists say different things.
   *
   * @param before - the list in hand, or null
   * @param after - the list just read
   * @returns whether they differ (never, where there was none before)
   */
  static changed(before: Json, after: Json): boolean {
    return !!before && WebAccounts.fingerprint(before) !==
                       WebAccounts.fingerprint(after);
  }

  /**
   * Opens the change signal: `onChange` is called for every message of
   * this kind, and `post()` announces a change.
   *
   * @param env - the browser's objects: `window.BroadcastChannel`
   * @param onChange - what a message makes this page do
   * @returns `{ post(change), close() }`; both do nothing where the
   *   browser has no channel
   */
  static openChannel(env: Json, onChange: () => void): Json {
    const win = env && env.window;
    const BC = win && win.BroadcastChannel;
    if (typeof BC !== 'function') {
      return { post: function () { return false; },
               close: function () { return false; } };
    }
    const channel = new BC(WebAccounts.CHANNEL);
    channel.onmessage = function (event: Json) {
      const data = event && event.data;
      if (data && data.type === WebAccounts.MESSAGE) {
        onChange();
      }
    };
    return {
      post: function (change: string): boolean {
        // WHAT KIND OF CHANGE, and nothing about whose: a listener asks the
        // server either way.
        channel.postMessage({ type: WebAccounts.MESSAGE,
                              change: String(change || 'changed') });
        return true;
      },
      close: function (): boolean {
        channel.close();
        return true;
      }
    };
  }

  /**
   * The address a sign-in as another account starts from: the user portal,
   * asked to sign in again.
   *
   * @param list - the list, whose `anotherAccount` is the portal's address
   *   where the service named it (another listener, #472)
   * @returns the address; root-relative where the list named none, so the
   *   page's realm rewrite prefixes it
   */
  static anotherHref(list: Json): string {
    const named = list && typeof list.anotherAccount === 'string'
      ? list.anotherAccount : '';
    if (/^https?:\/\//.test(named)) {
      return named;
    }
    return '/portal?' + WebAccounts.ANOTHER_PARAM + '=' +
      WebAccounts.ANOTHER_VALUE;
  }

  /**
   * The name to show for an account.
   *
   * @param one - the account
   * @returns its display name, its username, or its subject
   */
  static nameOf(one: Json): string {
    return String((one && (one.displayName || one.username || one.sub)) ||
                  '');
  }

  /**
   * Draws the control a public surface carries: the signed-in accounts and
   * Sign in with another account. Nothing where the list is off or holds no
   * signed-in account.
   *
   * @param list - the list
   * @param t - the page's translator (the `accounts` namespace loaded)
   * @returns the control's markup, or ''
   */
  static controlHtml(list: Json, t: Json): string {
    const live = WebAccounts.live(list);
    if (!list || !list.enabled || !live.length) {
      return '';
    }
    const say = function (key: string, english: string): string {
      return t && t.has && t.has(key) ? t.html(key) : WebAccounts.esc(english);
    };
    const sayText = function (key: string, english: string): string {
      return t && t.has && t.has(key) ? t.text(key) : english;
    };
    return '<details class="sts-accounts" id="sts-accounts">' +
      '<summary title="' + WebAccounts.esc(sayText('accounts.title',
        'The accounts signed in in this browser')) + '">' +
      say('accounts.summary', 'Accounts') + '</summary>' +
      '<div class="sts-accounts-panel"><p>' +
      say('accounts.listLabel', 'Signed in in this browser') + '</p><ul>' +
      live.map(function (one: Json): string {
        const name = WebAccounts.nameOf(one);
        const user = String(one.username || '');
        return '<li><strong>' + WebAccounts.esc(name) + '</strong>' +
          (user && user !== name ? ' <span>' + WebAccounts.esc(user) +
                                   '</span>' : '') + '</li>';
      }).join('') + '</ul>' +
      '<a class="sts-accounts-another" href="' +
      WebAccounts.esc(WebAccounts.anotherHref(list)) + '" title="' +
      WebAccounts.esc(sayText('accounts.anotherTitle',
        'Opens the user portal and asks you to sign in, adding an account ' +
        'to this browser. The accounts already signed in stay signed in.')) +
      '">' + say('accounts.another', 'Sign in with another account') +
      '</a></div></details>';
  }

  /**
   * The account action a click is on: a control carrying
   * `data-account-action`, the target or one of its parents.
   *
   * @param target - the click's target
   * @returns `{ action, key }`, or null
   */
  static actionOf(target: Json): Json {
    let el = target;
    for (let i = 0; el && i < 6; i++) {
      const action = el.getAttribute ? el.getAttribute('data-account-action')
                                     : null;
      if (action) {
        return { action: String(action),
                 key: String(el.getAttribute('data-account-key') || '') };
      }
      el = el.parentElement;
    }
    return null;
  }

  /**
   * Escapes text for HTML.
   *
   * @param value - anything
   * @returns the escaped text
   */
  static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

export = WebAccounts;
