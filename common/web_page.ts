// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_page.ts
//
// ---------------------------------------------------------------------------
// WHAT EVERY STATIC SURFACE'S RUNTIME STANDS ON (#570, 2026-10-12).
//
// The admin console (#446) and the user portal (#568) were the first two
// static applications here; #569 converts every other human-facing page
// this service draws — the sign-in screen, consent, the sign-out, GNAP's
// interaction, the front door, the demonstration pages — into the same
// shape, one bundle per surface (rcbj's decision 2 on #570). The console and
// the portal are OAuth clients of this service and hold tokens
// (`web_spa_client.ts`); those surfaces are NOT — the sign-on session is the
// `sts_session` cookie and their APIs are unauthenticated or bound to it
// (#569's decision 3). So what a runtime needs whether or not it is a client
// lives HERE, under the client half:
//
//   * WHERE THINGS ARE: the realm's path prefix (`prefixAt()`), and the bases
//     of the applications on other listeners (#472), read off the shell's
//     `data-sts-*` attributes (`ShellDocument` draws them) — `url()` builds
//     the address of a path from both.
//   * THE QUERY of an address as an object (`queryOf()`).
//   * FETCH WITH JSON ERRORS: `publicJson()` calls an operation that takes no
//     token and answers `{ status, json, res }`, with `json` null where the
//     body was not JSON, so a caller says what went wrong in its own words
//     rather than throwing on a gateway's HTML.
//   * A PAGE IN A REALM LINKS INTO IT: `realmLinks()`, the browser's half of
//     `common/app.js`'s `withRealmLinks()` (the same pattern, on purpose).
//   * FORMS AS API CALLS: `formFields()` reads a submitted form into the JSON
//     an operation takes — a repeated name an array, the pressed button's
//     name and value included, the server-drawn CSRF field left out.
//   * A FRAGMENT AFTER A DRAW: `targetFragment()` navigates to the address's
//     fragment again, since `:target` is set only by a navigation.
//   * A FILE AN ANSWER CARRIED: `saveBase64()`.
//
// Each was written twice, once in `admin-ui/web_runtime.ts` and once in
// `portal/web_portal_runtime.ts`, and moved here verbatim when #570 made a
// third surface certain; the console and the portal now inherit them, through
// `SpaClient`, so the copies cannot drift.
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires nothing,
// logs nothing (code that runs in a browser is exempt from the Entering /
// Leaving rule), and is bundled for a browser by `build-typescript.sh`.
// Everything it touches in the browser arrives in `env`, so a test drives it
// in node with stand-ins.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * The base of every static surface's runtime: where things are, fetch,
 * forms and links.
 */
class WebPage {
  protected env: Json;
  protected prefix: string;
  // WHERE THE OTHER APPLICATIONS ARE when they are not on this page's own
  // listener (#472): their bases, the realm prefix included, from the
  // shell's `data-sts-*` attributes, keyed by the first path segment each
  // stands for; '' where they are here, which is every service without a
  // custom listener.
  protected elsewhere: Json;

  /**
   * Makes the page's runtime base.
   *
   * @param env - the browser's objects: `fetch`, `location`, `history`,
   *   `document`, and whatever the subclass reads; for a test, `formDataOf`
   * @param prefix - the realm's path prefix, '' in the default realm
   * @param elsewhere - the shell's attributes by the first path segment each
   *   stands for: `{ '/oauth2': 'data-sts-oauth', ... }`
   */
  constructor(env: Json, prefix: string, elsewhere?: Record<string, string>) {
    this.env = env;
    this.prefix = prefix;
    this.elsewhere = WebPage.basesOf(env, elsewhere || {});
  }

  /**
   * Reads the shell's `data-sts-*` attributes into bases by path segment.
   *
   * @param env - the browser's objects; its `document` is read
   * @param attributes - the attribute for each first path segment
   * @returns the bases, without a trailing slash, '' where absent
   */
  static basesOf(env: Json, attributes: Record<string, string>): Json {
    const out: Json = {};
    Object.keys(attributes || {}).forEach(function (first) {
      out[first] = WebPage.attribute(env, attributes[first])
        .replace(/\/+$/, '');
    });
    return out;
  }

  /**
   * One attribute of the shell's `<html>` element.
   *
   * @param env - the browser's objects
   * @param name - the attribute, `data-sts-version`
   * @returns its value, or '' where it is absent
   */
  static attribute(env: Json, name: string): string {
    const root = env && env.document && env.document.documentElement;
    return root && typeof root.getAttribute === 'function'
      ? String(root.getAttribute(name) || '') : '';
  }

  /**
   * Splits a path at a surface's base: the realm prefix before it.
   *
   * @param pathname - a path, `/realm/acme/portal/keys` or `/portal`
   * @param base - the surface's first path, `/portal`
   * @returns the prefix, '' in the default realm and where the path is not
   *   under the base
   */
  static prefixAt(pathname: string, base: string): string {
    const quoted = String(base).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const m = new RegExp('^(.*?)' + quoted + '(?:/.*)?$')
      .exec(String(pathname || ''));
    return m ? m[1] : '';
  }

  /**
   * Parses a query string into an object, the last value of a repeated
   * name winning as express's own parser does for a single value.
   *
   * @param search - `?a=1&b=2` or ''
   * @returns the query
   */
  static queryOf(search: string): Json {
    const out = {};
    new URLSearchParams(String(search || '').replace(/^\?/, ''))
      .forEach(function (value, name) {
        out[name] = value;
      });
    return out;
  }

  /**
   * This realm's address for one of its paths: on this origin, or on the
   * listener that answers the path where the shell named one.
   *
   * @param path - `/oauth2/token`, `/web/locales/catalogs.json`
   * @returns the absolute URL
   */
  url(path: string): string {
    const elsewhere = this.elsewhere || {};
    const first = '/' + String(path || '').split(/[/?#]/)[1];
    if (elsewhere[first]) {
      return elsewhere[first] + path;
    }
    return this.env.location.origin + this.prefix + path;
  }

  /**
   * Calls an operation that takes no token, sending an object as JSON, and
   * reads its JSON.
   *
   * @param method - GET or POST
   * @param path - the path under the realm
   * @param body - for a POST, an object
   * @returns `{ status, json, res }`, `json` null where the body was not
   *   JSON
   */
  async publicJson(method: string, path: string, body?: Json): Promise<Json> {
    const res = await this.env.fetch(this.url(path), {
      method: method,
      headers: Object.assign({ 'Accept': 'application/json' },
        body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      body: body !== undefined ? JSON.stringify(body) : undefined });
    const json = await res.json().catch(function () {
      return null;
    });
    return { status: res.status, json: json, res: res };
  }

  // A PAGE UNDER A REALM'S PREFIX LINKS INTO THAT REALM: the renderers draw
  // root-relative addresses, and a server-rendered page had every one
  // prefixed on the way out (`common/app.js`'s `withRealmLinks()`, whose
  // pattern this is); in a static surface the runtime does it.
  /**
   * Prefixes every root-relative `href`, `action`, `formaction` and `src`.
   *
   * @param html - the page
   * @param prefix - the realm's path prefix, or '' for the default realm
   * @returns the page with its links in the realm
   */
  static realmLinks(html: string, prefix: string): string {
    if (!prefix) {
      return html;
    }
    return String(html).replace(/\b(href|action|formaction|src)="\/(?!\/)/g,
                                '$1="' + prefix + '/');
  }

  /**
   * A form's fields as an object: a repeated name is an array, the pressed
   * button's name and value are included, and the CSRF field a form drawn
   * by the server carried is left out (an API call is not a form post).
   *
   * @param form - the form element
   * @param submitter - the button pressed, if any
   * @returns the fields
   */
  formFields(form: Json, submitter: Json): Json {
    const data = this.env.formDataOf ? this.env.formDataOf(form)
                                     : new FormData(form);
    if (submitter && submitter.name) {
      data.delete(submitter.name);
      data.append(submitter.name, submitter.value);
    }
    const out: Json = {};
    data.forEach(function (value: Json, name: string) {
      if (name === 'csrf_token' || typeof value !== 'string') {
        return;
      }
      if (Object.prototype.hasOwnProperty.call(out, name)) {
        out[name] = [].concat(out[name], value);
      } else {
        out[name] = value;
      }
    });
    return out;
  }

  // A TAB OR A SECTION IS A FRAGMENT, and `:target` is set only by a
  // navigation, so after a page is drawn the fragment is navigated to again.
  /**
   * Makes the address's fragment the `:target` of the page just drawn.
   *
   * @returns nothing
   */
  targetFragment(): void {
    const loc = this.env.location;
    const hash = String(loc.hash || '');
    if (!hash || !this.env.history || !loc.replace) {
      return;
    }
    this.env.history.replaceState(null, '', loc.pathname + loc.search);
    loc.replace(loc.pathname + loc.search + hash);
  }

  /**
   * Saves a file an answer carried as base64.
   *
   * @param name - its file name
   * @param mime - its media type
   * @param base64 - its bytes
   * @returns nothing
   */
  saveBase64(name: string, mime: string, base64: string): void {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const href = URL.createObjectURL(new Blob([bytes], { type: mime }));
    const a = this.env.document.createElement('a');
    a.href = href;
    a.download = name.replace(/[\/\\]/g, '_');
    this.env.document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(href);
  }
}

export = WebPage;
