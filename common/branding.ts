// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: branding.ts
//
// ===========================================================================
// A REALM'S SIGN-IN APPEARANCE: ITS COLOURS, LAYOUT AND LOGO (#717).
//
// rcbj's ticket asked for colour, layout and a company logo on the sign-in
// screen, set per realm; his decisions on it (D1–D6) are what this file is:
//
//   * COLOURS are four settings (`branding.accentColor`, `pageColor`,
//     `cardColor`, `textColor`, of `config.js`'s `color` type), set per
//     realm like any setting. They reach a page in ONE way: a stylesheet of
//     this origin, `/web/theme.css`, answering the ambient realm's CSS
//     custom properties. The sign-in pages are sent with `style-src 'self'`,
//     so no inline style and no `style=""` could carry them, and the
//     stylesheet is built only from values the `color` type has already
//     held to six hex digits — nothing an administrator types reaches CSS
//     text. `/web/card.css` reads every colour through `var(--sts-…, <the
//     old literal>)` (`web_card_css.ts`), so a realm that sets nothing —
//     and every shell drawn before this existed — looks exactly as it did.
//   * THE QUIETER TONES ARE DERIVED, never set: the text on a button (black
//     or white, whichever reads better on the accent), the muted and faint
//     text (mixed from the text and the card, never below WCAG 2.2 AA), the
//     borders and rules. A realm whose text and card are the defaults keeps
//     the old literals exactly.
//   * CONTRAST BELOW AA IS REFUSED (D3): a write rule (`config.addWriteRule()`,
//     so every door — the console, the API, a restored value) refuses a
//     text or accent colour below 4.5:1 against the card (STS-AUTHN-0544).
//   * THE LAYOUT is a closed set (`centered`, `split`, `banner`), drawn by
//     CSS keyed on `<html data-sts-layout>` and one header the static
//     runtime draws before the card (`web_surface.ts`). The form is never
//     touched: every element id and its order are what they were.
//   * THE LOGO (D1, D2) is UPLOADED — PNG, JPEG or WebP, decided by its
//     bytes — kept in the realm's own persisted store (`branding.assets`),
//     and served from this origin at `/web/branding/logo`, so the sign-in
//     page's `img-src 'self'` already admits it and no third party learns
//     who is signing in. It needs alternative text (`branding.logoAlt`).
//
// **THE SHELL CARRIES THE FACTS, THE RUNTIME DRAWS THEM.** `shellAttributes()`
// is what `shell_document.ts` puts on `<html>` — the layout, the name, the
// logo's address, its alternative text and link — and `WebSurface.put()`
// draws the header from them, escaped, on every page it draws (the runtime
// replaces the body's markup on each page, so a header the server drew
// would be gone at the first). A realm that has set nothing gets no
// attribute and no extra stylesheet: its shells are the bytes they were.
//
// A LIBRARY THAT ALSO REGISTERS THREE ROUTES, none colliding with anything:
// `GET /web/theme.css`, `GET /web/branding/logo` and `GET /web/branding/preview`
// (D5: the console opens it in a new tab with pending values, to see them
// before saving). It requires `config`, `realms`, `crypto`, `error_codes`
// and `helpers` for the logger, and `audit` lazily, at an upload.
// ===========================================================================

import helpers = require('./helpers');
import config = require('./config');
import realms = require('./realms');
import stsCrypto = require('./crypto');
import errorCodes = require('./error_codes');
import ShellDocument = require('./shell_document');

const { log } = helpers;

type Json = any;

/** The layouts a realm may choose (`branding.layout`). */
const LAYOUTS = ['centered', 'split', 'banner'];

/** The colours a realm sets, by setting key, and their defaults. */
const COLOUR_KEYS = {
  accent: 'branding.accentColor',
  page: 'branding.pageColor',
  card: 'branding.cardColor',
  text: 'branding.textColor'
};

/**
 * The defaults: the look the service always had, which `web_card_css.ts`
 * also carries as each `var()`'s fallback.
 */
const DEFAULTS = Object.freeze({
  accent: '#12107c', page: '#f4f4f7', card: '#ffffff', text: '#222222',
  // The derived tones' literals, used where the text and card are the
  // defaults, so such a realm keeps them exactly.
  onAccent: '#ffffff', muted: '#666666', faint: '#777777', dim: '#555555',
  border: '#d5d5dd', rule: '#eeeeee', tint: '#fafafd', tint2: '#f0f0f5',
  bad: '#b00020', good: '#0b6b4f'
});

// The custom properties as a realm that set nothing would have them: what
// `theme()` leaves out of a realm's stylesheet, so that a property the realm
// did not change keeps each page's OWN fallback — the portal's blue accent,
// a table head's own grey (#717's review: a realm that only uploaded a logo
// must not repaint the portal).
const DEFAULT_PROPERTIES: Record<string, string> = {
  accent: DEFAULTS.accent, 'on-accent': DEFAULTS.onAccent,
  page: DEFAULTS.page, card: DEFAULTS.card, text: DEFAULTS.text,
  muted: DEFAULTS.muted, faint: DEFAULTS.faint, dim: DEFAULTS.dim,
  border: DEFAULTS.border, rule: DEFAULTS.rule, tint: DEFAULTS.tint,
  'tint-2': DEFAULTS.tint2, bad: DEFAULTS.bad, good: DEFAULTS.good
};

/** WCAG 2.2 AA's contrast for normal text (success criterion 1.4.3). */
const AA_CONTRAST = 4.5;

/** The logo's bounds in pixels, each side (STS-AUTHN-0547). */
const LOGO_MIN_SIDE = 16;
const LOGO_MAX_SIDE = 2048;

/** The paths this module answers. */
const PATHS = Object.freeze({
  theme: '/web/theme.css',
  logo: '/web/branding/logo',
  preview: '/web/branding/preview'
});

// THE REALM'S LOGO, keyed `logo`: `{ type, data (base64), sha256, width,
// height, bytes, updatedAt, updatedBy }`. Declared per realm here, at the
// declaration (root CLAUDE.md, trust realms 2), and persisted, so it
// replicates to every process and node through the change log and goes with
// its realm. A global store in cells (`persistence/tiers.js`). Not sealed: a
// logo is public by definition.
const assets = realms.map({ persist: 'branding.assets' });

// An image needs nothing, and is sandboxed if it is ever opened as a document.
// Through `app.contentSecurityPolicy()` (root CLAUDE.md, #1337): until then this
// was a literal with no `frame-ancestors`, which `app.js` replaces with the base
// policy as the response is sent, so `sandbox` never reached a client, and a
// test over a mock response could not see that.
const LOGO_POLICY = Object.freeze({ 'style-src': null, 'img-src': null,
                                    sandbox: '' });

/**
 * A realm's appearance as the shell and the stylesheet need it.
 */
interface Theme {
  // Whether anything differs from the service's own look; a realm that has
  // set nothing is drawn exactly as before.
  active: boolean;
  layout: string;
  colours: Record<string, string>;
  displayName: string;
  logo: { url: string, alt: string, link: string } | null;
  // The stylesheet's text, and a digest of it for the address.
  css: string;
  digest: string;
}

/**
 * A realm's sign-in appearance. A static utility class; its one store is
 * declared above.
 */
class Branding {
  static readonly LAYOUTS = LAYOUTS;
  static readonly DEFAULTS = DEFAULTS;
  static readonly PATHS = PATHS;
  static readonly AA_CONTRAST = AA_CONTRAST;

  // -------------------------------------------------------------------------
  // COLOUR ARITHMETIC (WCAG 2.2, "relative luminance" and "contrast ratio").
  // -------------------------------------------------------------------------
  /**
   * A `#rrggbb` colour's channels, 0–255.
   *
   * @param hex - the colour
   * @returns `[r, g, b]`, or null when it is not one
   */
  static channels(hex: string): number[] | null {
    log.debug("Entering Branding.channels().");
    const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(
      String(hex || ''));
    log.debug("Leaving Branding.channels().");
    return m ? [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)]
             : null;
  }

  /**
   * A colour's relative luminance.
   *
   * @param hex - `#rrggbb`
   * @returns 0 (black) to 1 (white)
   */
  static luminance(hex: string): number {
    log.debug("Entering Branding.luminance().");
    const c = Branding.channels(hex) || [0, 0, 0];
    const lin = c.map(function (v: number): number {
      const s = v / 255;
      return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    });
    log.debug("Leaving Branding.luminance().");
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2];
  }

  /**
   * The contrast ratio of two colours.
   *
   * @param a - `#rrggbb`
   * @param b - `#rrggbb`
   * @returns 1 to 21
   */
  static contrast(a: string, b: string): number {
    log.debug("Entering Branding.contrast().");
    const la = Branding.luminance(a);
    const lb = Branding.luminance(b);
    log.debug("Leaving Branding.contrast().");
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
  }

  /**
   * Two colours mixed: `t` of the way from `a` to `b`.
   *
   * @param a - `#rrggbb`
   * @param b - `#rrggbb`
   * @param t - 0 (all `a`) to 1 (all `b`)
   * @returns `#rrggbb`
   */
  static mix(a: string, b: string, t: number): string {
    log.debug("Entering Branding.mix().");
    const x = Branding.channels(a) || [0, 0, 0];
    const y = Branding.channels(b) || [0, 0, 0];
    const out = '#' + [0, 1, 2].map(function (i: number): string {
      const v = Math.round(x[i] + (y[i] - x[i]) * t);
      return (v < 16 ? '0' : '') + v.toString(16);
    }).join('');
    log.debug("Leaving Branding.mix().");
    return out;
  }

  /**
   * The text colour mixed toward the card as far as `t` goes while it keeps
   * AA contrast against the card — a quieter tone that is still readable.
   *
   * @param text - the text colour
   * @param card - the card colour
   * @param t - how far toward the card it would like to go
   * @returns `#rrggbb`
   */
  static quieter(text: string, card: string, t: number): string {
    log.debug("Entering Branding.quieter().");
    let at = t;
    let out = Branding.mix(text, card, at);
    while (at > 0 && Branding.contrast(out, card) < AA_CONTRAST) {
      at = Math.max(0, at - 0.02);
      out = Branding.mix(text, card, at);
    }
    log.debug("Leaving Branding.quieter().");
    return out;
  }

  /**
   * Every colour a page reads, the four set and the ten derived.
   *
   * @param set - `accent`, `page`, `card` and `text`
   * @returns the fourteen, by custom property name without its `--sts-` prefix
   */
  static palette(set: Record<string, string>): Record<string, string> {
    log.debug("Entering Branding.palette().");
    const accent = set.accent;
    const card = set.card;
    const text = set.text;
    const onAccent = Branding.contrast('#ffffff', accent) >=
      Branding.contrast('#000000', accent) ? '#ffffff' : '#000000';
    // The old literals where the text and card are the defaults, so a realm
    // that changed only its accent or its page keeps every other tone.
    const asBefore = text === DEFAULTS.text && card === DEFAULTS.card;
    const out = {
      accent: accent, 'on-accent': onAccent, page: set.page, card: card,
      text: text,
      muted: asBefore ? DEFAULTS.muted : Branding.quieter(text, card, 0.31),
      faint: asBefore ? DEFAULTS.faint : Branding.quieter(text, card, 0.38),
      dim: asBefore ? DEFAULTS.dim : Branding.quieter(text, card, 0.24),
      border: asBefore ? DEFAULTS.border : Branding.mix(text, card, 0.81),
      rule: asBefore ? DEFAULTS.rule : Branding.mix(text, card, 0.93),
      // The pale boxes, a little toward the text from the card.
      tint: asBefore ? DEFAULTS.tint : Branding.mix(card, text, 0.03),
      'tint-2': asBefore ? DEFAULTS.tint2 : Branding.mix(card, text, 0.07),
      // A failed and a passed check's word: the old colour where it reads on
      // this card, a light one where the card is dark.
      bad: asBefore ? DEFAULTS.bad
        : Branding.readable(['#b00020', '#ff8a80'], card),
      good: asBefore ? DEFAULTS.good
        : Branding.readable(['#0b6b4f', '#69f0ae'], card)
    };
    log.debug("Leaving Branding.palette().");
    return out;
  }

  /**
   * Of several colours, the first with AA contrast against a background, or
   * the one with the most where none has it.
   *
   * @param choices - `#rrggbb` colours, preferred first
   * @param background - the background
   * @returns the chosen colour
   */
  static readable(choices: string[], background: string): string {
    log.debug("Entering Branding.readable().");
    let best = choices[0];
    for (const one of choices) {
      if (Branding.contrast(one, background) >= AA_CONTRAST) {
        log.debug("Leaving Branding.readable().");
        return one;
      }
      if (Branding.contrast(one, background) >
          Branding.contrast(best, background)) {
        best = one;
      }
    }
    log.debug("Leaving Branding.readable(). None reaches AA.");
    return best;
  }

  /**
   * What is wrong with a set of colours under AA (D3), each a sentence; none
   * when it passes.
   *
   * @param set - `accent`, `card` and `text`
   * @returns the problems
   */
  static contrastProblems(set: Record<string, string>): string[] {
    log.debug("Entering Branding.contrastProblems().");
    const out: string[] = [];
    const pairs: Array<[string, string, string]> = [
      ['text', 'branding.textColor', 'the text'],
      ['accent', 'branding.accentColor', 'the links and the accent']
    ];
    pairs.forEach(function (one: [string, string, string]): void {
      const ratio = Branding.contrast(set[one[0]], set.card);
      if (ratio < AA_CONTRAST) {
        out.push(one[2] + ' (' + one[1] + ' ' + set[one[0]] + ') has a ' +
                 'contrast of ' + ratio.toFixed(2) + ':1 against the card ' +
                 '(branding.cardColor ' + set.card + '); WCAG 2.2 AA asks ' +
                 'at least ' + AA_CONTRAST + ':1');
      }
    });
    log.debug("Leaving Branding.contrastProblems(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE WRITE RULES, asked of every door that writes a setting.
  // -------------------------------------------------------------------------
  /**
   * Refuses a colour that would leave the text or the accent below AA
   * against the card (STS-AUTHN-0544), a logo's alternative text emptied
   * while a logo is held (STS-AUTHN-0548), and a logo link that is not an
   * absolute https URL (STS-AUTHN-0551).
   *
   * @param key - the setting being written
   * @param parsed - its parsed value
   * @param inRealm - unused; the rules hold in a realm as in the process
   * @param beside - another setting's value as this write leaves it
   * @returns `{ problem, code }`, or null
   */
  static writeRule(key: string, parsed: unknown, inRealm?: boolean,
                   beside?: (key: string) => unknown): Json {
    log.debug("Entering Branding.writeRule(). " + key);
    const read = typeof beside === 'function' ? beside
      : function (other: string): unknown {
        return config.value(other);
      };
    if (key === 'branding.textColor' || key === 'branding.accentColor' ||
        key === 'branding.cardColor') {
      const set: Record<string, string> = {};
      Object.keys(COLOUR_KEYS).forEach(function (name: string): void {
        const k = COLOUR_KEYS[name];
        set[name] = String(k === key ? parsed : read(k));
      });
      const problems = Branding.contrastProblems(set);
      log.debug("Leaving Branding.writeRule(). Contrast.");
      return problems.length
        ? { code: 'STS-AUTHN-0544',
            problem: 'The sign-in appearance was not changed: ' +
                     problems.join('; ') + '.' }
        : null;
    }
    if (key === 'branding.logoAlt' && !String(parsed || '').trim() &&
        Branding.logoRecord()) {
      log.debug("Leaving Branding.writeRule(). The logo needs its text.");
      return { code: 'STS-AUTHN-0548',
               problem: '"branding.logoAlt" cannot be emptied while this ' +
                        'realm has a sign-in logo: a screen reader reads it ' +
                        'in the logo\'s place. Remove the logo first.' };
    }
    if (key === 'branding.logoLinkUrl' && String(parsed || '').trim() &&
        !Branding.httpsUrl(String(parsed))) {
      log.debug("Leaving Branding.writeRule(). Not https.");
      return { code: 'STS-AUTHN-0551',
               problem: '"branding.logoLinkUrl" must be an absolute https ' +
                        'URL, or empty for a logo that is not a link.' };
    }
    log.debug("Leaving Branding.writeRule().");
    return null;
  }

  /**
   * Whether a text is an absolute https URL.
   *
   * @param text - the text
   * @returns true when it is
   */
  static httpsUrl(text: string): boolean {
    log.debug("Entering Branding.httpsUrl().");
    let ok = false;
    try {
      const url = new URL(String(text).trim());
      ok = url.protocol === 'https:' && !!url.hostname;
    } catch (e) {
      log.debug("Caught in Branding.httpsUrl(): " +
                ((e && (e as Error).message) || e));
      ok = false;
    }
    log.debug("Leaving Branding.httpsUrl(). " + ok);
    return ok;
  }

  // -------------------------------------------------------------------------
  // THE AMBIENT REALM'S THEME.
  // -------------------------------------------------------------------------
  /**
   * The ambient realm's appearance, or the one given by `pending` (a
   * preview's values, already checked) over it.
   *
   * @param pending - colours and a layout to use in place of the realm's
   * @returns the theme
   */
  static theme(pending?: Record<string, string>): Theme {
    log.debug("Entering Branding.theme().");
    const asked = pending || {};
    const set: Record<string, string> = {};
    Object.keys(COLOUR_KEYS).forEach(function (name: string): void {
      set[name] = String(asked[name] ||
                         Branding.setting(COLOUR_KEYS[name], DEFAULTS[name]));
    });
    const layout = LAYOUTS.indexOf(asked.layout) >= 0 ? asked.layout
      : String(Branding.setting('branding.layout', 'centered'));
    const displayName = String(Branding.setting('branding.displayName', ''))
      .trim();
    const record = Branding.logoRecord();
    const alt = String(Branding.setting('branding.logoAlt', '')).trim();
    const link = String(Branding.setting('branding.logoLinkUrl', '')).trim();
    const logo = record ? {
      url: PATHS.logo + '?v=' + String(record.sha256).slice(0, 16),
      alt: alt, link: Branding.httpsUrl(link) ? link : '' } : null;
    const palette = Branding.palette(set);
    // Only what differs from a realm that set nothing (DEFAULT_PROPERTIES):
    // every other property keeps the page's own fallback.
    const css = ':root{' + Object.keys(palette).filter(function (k: string) {
      return palette[k] !== DEFAULT_PROPERTIES[k];
    }).map(function (k: string) {
      return '--sts-' + k + ':' + palette[k];
    }).join(';') + '}';
    const active = layout !== 'centered' || !!displayName || !!logo ||
      !!pending || Object.keys(COLOUR_KEYS).some(function (name: string) {
        return set[name] !== DEFAULTS[name];
      });
    const out = {
      active: active, layout: layout, colours: palette,
      displayName: displayName, logo: logo, css: css,
      digest: stsCrypto.digest('sha256', css, 'hex').slice(0, 16)
    };
    log.debug("Leaving Branding.theme(). " +
              (active ? 'Customised.' : 'As the service always looked.'));
    return out;
  }

  /**
   * A setting's value in the ambient realm, or `fallback` where it cannot be
   * read (a process loading this file before the rows exist).
   *
   * @param key - the setting
   * @param fallback - what to answer instead
   * @returns the value
   */
  static setting(key: string, fallback: unknown): unknown {
    log.debug("Entering Branding.setting(). " + key);
    let out = fallback;
    try {
      out = config.value(key);
    } catch (e) {
      // A setting that cannot be read is its default: the service's own look.
      log.debug("Caught in Branding.setting(): " +
                ((e && (e as Error).message) || e));
      out = fallback;
    }
    log.debug("Leaving Branding.setting().");
    return out === undefined || out === null ? fallback : out;
  }

  /**
   * The `<html>` attributes a shell carries for the ambient realm's
   * appearance, and the stylesheet it links after the card's: nothing at all
   * for a realm that has set nothing, so its shell is the one it always was.
   *
   * @returns `{ attributes, stylesheet }`
   */
  static shellParts(): { attributes: Array<[string, string]>,
                         stylesheet: string } {
    log.debug("Entering Branding.shellParts().");
    let theme: Theme | null = null;
    try {
      theme = Branding.theme();
    } catch (e) {
      // A theme that cannot be read draws the page as it always looked:
      // a sign-in screen must never fail over its colours.
      log.debug("Caught in Branding.shellParts(): " +
                ((e && (e as Error).message) || e));
      theme = null;
    }
    if (!theme || !theme.active) {
      log.debug("Leaving Branding.shellParts(). Nothing to add.");
      return { attributes: [], stylesheet: '' };
    }
    const attributes: Array<[string, string]> = [
      ['data-sts-layout', theme.layout],
      ['data-sts-brand-name', theme.displayName],
      ['data-sts-brand-logo', theme.logo ? theme.logo.url : ''],
      ['data-sts-brand-alt', theme.logo ? theme.logo.alt : ''],
      ['data-sts-brand-link', theme.logo ? theme.logo.link : '']
    ];
    log.debug("Leaving Branding.shellParts().");
    return { attributes: attributes,
             stylesheet: PATHS.theme + '?v=' + theme.digest };
  }

  // -------------------------------------------------------------------------
  // THE LOGO (D1, D2).
  // -------------------------------------------------------------------------
  /**
   * The ambient realm's stored logo, or null.
   *
   * @returns the record
   */
  static logoRecord(): Json {
    log.debug("Entering Branding.logoRecord().");
    let out: Json = null;
    try {
      out = assets.get('logo') || null;
    } catch (e) {
      // A store that cannot be read holds no logo for this answer; the page
      // is drawn without one.
      log.debug("Caught in Branding.logoRecord(): " +
                ((e && (e as Error).message) || e));
      out = null;
    }
    log.debug("Leaving Branding.logoRecord(). " + (out ? 'Held.' : 'None.'));
    return out && out.data ? out : null;
  }

  /**
   * What an image's bytes are and how large it draws: PNG, JPEG or WebP,
   * read from the bytes alone, whatever was declared.
   *
   * @param bytes - the image
   * @returns `{ type, width, height }`; `type` empty when it is none of the
   *   three, the sides 0 when they could not be read
   */
  static sniff(bytes: Buffer): { type: string, width: number,
                                 height: number } {
    log.debug("Entering Branding.sniff().");
    const b = Buffer.isBuffer(bytes) ? bytes : Buffer.alloc(0);
    const out = { type: '', width: 0, height: 0 };
    if (b.length >= 24 && b.slice(0, 8).equals(Buffer.from(
      [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) &&
        b.toString('latin1', 12, 16) === 'IHDR') {
      out.type = 'image/png';
      out.width = b.readUInt32BE(16);
      out.height = b.readUInt32BE(20);
    } else if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8 &&
               b[2] === 0xff) {
      out.type = 'image/jpeg';
      const sides = Branding.jpegSides(b);
      out.width = sides[0];
      out.height = sides[1];
    } else if (b.length >= 30 && b.toString('latin1', 0, 4) === 'RIFF' &&
               b.toString('latin1', 8, 12) === 'WEBP') {
      out.type = 'image/webp';
      const chunk = b.toString('latin1', 12, 16);
      if (chunk === 'VP8 ' && b[23] === 0x9d && b[24] === 0x01 &&
          b[25] === 0x2a) {
        out.width = b.readUInt16LE(26) & 0x3fff;
        out.height = b.readUInt16LE(28) & 0x3fff;
      } else if (chunk === 'VP8L' && b[20] === 0x2f) {
        const bits = b.readUInt32LE(21);
        out.width = (bits & 0x3fff) + 1;
        out.height = ((bits >>> 14) & 0x3fff) + 1;
      } else if (chunk === 'VP8X') {
        out.width = b.readUIntLE(24, 3) + 1;
        out.height = b.readUIntLE(27, 3) + 1;
      }
    }
    log.debug("Leaving Branding.sniff(). " + (out.type || 'none') + " " +
              out.width + "x" + out.height);
    return out;
  }

  /**
   * A JPEG's width and height, from its first start-of-frame segment.
   *
   * @param b - the bytes, starting with the SOI marker
   * @returns `[width, height]`, `[0, 0]` where none was found
   */
  static jpegSides(b: Buffer): number[] {
    log.debug("Entering Branding.jpegSides().");
    let i = 2;
    while (i + 9 < b.length) {
      if (b[i] !== 0xff) {
        break;
      }
      const marker = b[i + 1];
      if (marker === 0xff) {
        i += 1;
        continue;
      }
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
        i += 2;
        continue;
      }
      // SOF0–SOF15 except DHT (C4), JPG (C8) and DAC (CC).
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 &&
          marker !== 0xc8 && marker !== 0xcc) {
        log.debug("Leaving Branding.jpegSides(). Found.");
        return [b.readUInt16BE(i + 7), b.readUInt16BE(i + 5)];
      }
      if (marker === 0xda || marker === 0xd9) {
        break;
      }
      i += 2 + b.readUInt16BE(i + 2);
    }
    log.debug("Leaving Branding.jpegSides(). None.");
    return [0, 0];
  }

  /**
   * Checks and stores the ambient realm's logo, and its alternative text
   * when one is given.
   *
   * @param bytes - the image
   * @param options - `alt` (written to `branding.logoAlt` when given) and
   *   `actor`, for the audit row
   * @returns `{ ok, errors, status, logo }`, a refusal marked with its code
   */
  static setLogo(bytes: Buffer, options?: Json): Json {
    log.debug("Entering Branding.setLogo().");
    const o = options || {};
    const b = Buffer.isBuffer(bytes) ? bytes : Buffer.alloc(0);
    const max = Number(Branding.setting('branding.logoMaxBytes', 262144));
    const refuse = function (code: string, status: number,
                             why: string): Json {
      log.debug("Entering refuse(). " + code);
      log.debug("Leaving refuse().");
      return errorCodes.mark({ ok: false, status: status, errors: [why] },
                             code);
    };
    if (!b.length || b.length > max) {
      log.debug("Leaving Branding.setLogo(). Size.");
      return refuse('STS-AUTHN-0546', b.length ? 413 : 400,
                    b.length ? 'The logo is ' + b.length + ' bytes; this ' +
                               'service takes at most ' + max +
                               ' (branding.logoMaxBytes).'
                             : 'No image was sent.');
    }
    const seen = Branding.sniff(b);
    if (!seen.type) {
      log.debug("Leaving Branding.setLogo(). Not an image.");
      return refuse('STS-AUTHN-0545', 415,
                    'The file is not a PNG, a JPEG or a WebP image. Only ' +
                    'those three are accepted, and the bytes decide, not ' +
                    'the type the upload declared.');
    }
    if (!(seen.width >= LOGO_MIN_SIDE && seen.width <= LOGO_MAX_SIDE &&
          seen.height >= LOGO_MIN_SIDE && seen.height <= LOGO_MAX_SIDE)) {
      log.debug("Leaving Branding.setLogo(). Sides.");
      return refuse('STS-AUTHN-0547', 400,
                    'The image\'s width and height ' +
                    (seen.width ? 'are ' + seen.width + 'x' + seen.height +
                                  ' pixels; each must be '
                                : 'could not be read; each must be ') +
                    LOGO_MIN_SIDE + ' to ' + LOGO_MAX_SIDE + ' pixels.');
    }
    const alt = o.alt === undefined || o.alt === null ? null
      : String(o.alt).trim();
    const heldAlt = String(Branding.setting('branding.logoAlt', '')).trim();
    if (!(alt || heldAlt)) {
      log.debug("Leaving Branding.setLogo(). No alternative text.");
      return refuse('STS-AUTHN-0548', 400,
                    'A logo needs alternative text (branding.logoAlt), ' +
                    'which a screen reader reads in its place. Send it with ' +
                    'the image, or set it first.');
    }
    if (alt && alt !== heldAlt) {
      const written = Branding.writeSetting('branding.logoAlt', alt);
      if (!written.ok) {
        log.debug("Leaving Branding.setLogo(). The text was refused.");
        return Object.assign(written, { status: 400 });
      }
    }
    const record = {
      type: seen.type, data: b.toString('base64'),
      sha256: stsCrypto.digest('sha256', b, 'hex'),
      width: seen.width, height: seen.height, bytes: b.length,
      updatedAt: Date.now(), updatedBy: String(o.actor || '')
    };
    assets.set('logo', record);
    Branding.audited('a ' + seen.type + ' logo of ' + seen.width + 'x' +
                     seen.height + ' pixels and ' + b.length + ' bytes was ' +
                     'uploaded (sha256 ' + record.sha256.slice(0, 16) + ')',
                     o.actor);
    log.debug("Leaving Branding.setLogo(). Stored.");
    return { ok: true, errors: [], logo: Branding.describeLogo(record) };
  }

  /**
   * Removes the ambient realm's logo. Its alternative text stays, so a logo
   * uploaded again needs none sent.
   *
   * @param actor - who removed it, for the audit row
   * @returns `{ ok, removed }`
   */
  static removeLogo(actor?: string): Json {
    log.debug("Entering Branding.removeLogo().");
    const held = !!Branding.logoRecord();
    if (held) {
      assets.delete('logo');
      Branding.audited('the logo was removed', actor);
    }
    log.debug("Leaving Branding.removeLogo(). " + held);
    return { ok: true, errors: [], removed: held };
  }

  /**
   * A stored logo as an answer shows it: never the bytes.
   *
   * @param record - the stored record
   * @returns its type, sides, size, digest, address and when it was set
   */
  static describeLogo(record: Json): Json {
    log.debug("Entering Branding.describeLogo().");
    log.debug("Leaving Branding.describeLogo().");
    return record ? {
      type: record.type, width: record.width, height: record.height,
      bytes: record.bytes, sha256: record.sha256,
      url: PATHS.logo + '?v=' + String(record.sha256).slice(0, 16),
      updatedAt: new Date(Number(record.updatedAt) || 0).toISOString(),
      updatedBy: record.updatedBy || ''
    } : null;
  }

  /**
   * The ambient realm's appearance as the console and `GET
   * /admin-api/branding` show it: the settings, the derived tones, the
   * contrast results and the logo.
   *
   * @returns the description
   */
  static describe(): Json {
    log.debug("Entering Branding.describe().");
    const theme = Branding.theme();
    const c = theme.colours;
    const out = {
      layout: theme.layout,
      layouts: LAYOUTS.slice(),
      colours: { accent: c.accent, page: c.page, card: c.card, text: c.text },
      derived: { onAccent: c['on-accent'], muted: c.muted, faint: c.faint,
                 dim: c.dim, border: c.border, rule: c.rule },
      contrast: {
        text: Number(Branding.contrast(c.text, c.card).toFixed(2)),
        accent: Number(Branding.contrast(c.accent, c.card).toFixed(2)),
        buttonText: Number(Branding.contrast(c['on-accent'], c.accent)
          .toFixed(2)),
        required: AA_CONTRAST
      },
      displayName: theme.displayName,
      logoAlt: String(Branding.setting('branding.logoAlt', '')),
      logoLinkUrl: String(Branding.setting('branding.logoLinkUrl', '')),
      logoMaxBytes: Number(Branding.setting('branding.logoMaxBytes', 262144)),
      logo: Branding.describeLogo(Branding.logoRecord()),
      customised: theme.active,
      preview: PATHS.preview
    };
    log.debug("Leaving Branding.describe().");
    return out;
  }

  /**
   * Writes one setting in the ambient realm: the process's override in the
   * default realm, the realm's own elsewhere — the choice every console
   * page that writes a setting makes.
   *
   * @param key - the setting
   * @param raw - its value as text
   * @returns `{ ok, errors }`, a refusal marked with its code
   */
  static writeSetting(key: string, raw: string): Json {
    log.debug("Entering Branding.writeSetting(). " + key);
    const realm = realms.current();
    const out = !realm || realms.isDefault(realm)
      ? config.setOverride(key, raw)
      : realms.setOverride(realm.id, key, raw);
    log.debug("Leaving Branding.writeSetting(). " + !!(out && out.ok));
    return out;
  }

  /**
   * Sets several appearance settings at once, judged together so that a
   * pair of colours that is legal only together is (`withWriteBatch()`).
   * Only `branding.*` keys are taken.
   *
   * @param values - raw values by setting key
   * @returns `{ ok, errors }`; nothing is written when any is refused
   */
  static saveSettings(values: Json): Json {
    log.debug("Entering Branding.saveSettings().");
    const asked = values && typeof values === 'object' ? values : {};
    const keys = Object.keys(asked).filter(function (k: string): boolean {
      return /^branding\.[A-Za-z]+$/.test(k) && k !== 'branding.logoMaxBytes';
    });
    const unknown = Object.keys(asked).filter(function (k: string) {
      return keys.indexOf(k) < 0;
    });
    if (unknown.length) {
      log.debug("Leaving Branding.saveSettings(). Not appearance settings.");
      return errorCodes.mark({ ok: false, errors: ['Only the sign-in ' +
        'appearance settings are set here, not: ' + unknown.join(', ') +
        '.'] }, 'STS-CORE-0004');
    }
    const raw: Json = {};
    keys.forEach(function (k: string): void {
      raw[k] = String(asked[k] === null || asked[k] === undefined ? ''
                                                                 : asked[k]);
    });
    const realm = realms.current();
    const inRealm = !!realm && !realms.isDefault(realm);
    const out = config.withWriteBatch(raw, function (): Json {
      const errors: string[] = [];
      let code = '';
      keys.forEach(function (k: string): void {
        const problem = config.checkWrite(k, raw[k], inRealm);
        if (problem) {
          errors.push(problem);
          code = code || config.checkWriteCode(k, raw[k], inRealm);
        }
      });
      if (errors.length) {
        return errorCodes.mark({ ok: false, errors: errors },
                               code || 'STS-CORE-0006');
      }
      for (const k of keys) {
        const written = Branding.writeSetting(k, raw[k]);
        if (!written.ok) {
          return written;
        }
      }
      return { ok: true, errors: [], saved: keys };
    });
    log.debug("Leaving Branding.saveSettings(). " + out.ok);
    return out;
  }

  /**
   * Checks a preview's values as the settings would, without writing them.
   *
   * @param query - `accent`, `page`, `card`, `text` and `layout`, each
   *   optional
   * @returns `{ ok, errors, pending }`
   */
  static previewValues(query: Json): Json {
    log.debug("Entering Branding.previewValues().");
    const q = query || {};
    const pending: Record<string, string> = {};
    const errors: string[] = [];
    Object.keys(COLOUR_KEYS).forEach(function (name: string): void {
      if (q[name] === undefined || q[name] === '') {
        return;
      }
      const parsed = config.parseAs(COLOUR_KEYS[name], String(q[name]));
      if (!parsed.ok) {
        errors.push(String(parsed.problem));
      } else {
        pending[name] = String(parsed.value);
      }
    });
    if (q.layout !== undefined && q.layout !== '') {
      if (LAYOUTS.indexOf(String(q.layout)) < 0) {
        errors.push('layout must be one of ' + LAYOUTS.join(', '));
      } else {
        pending.layout = String(q.layout);
      }
    }
    if (!errors.length) {
      const set: Record<string, string> = {};
      Object.keys(COLOUR_KEYS).forEach(function (name: string): void {
        set[name] = pending[name] ||
          String(Branding.setting(COLOUR_KEYS[name], DEFAULTS[name]));
      });
      Branding.contrastProblems(set).forEach(function (p: string): void {
        errors.push(p);
      });
    }
    log.debug("Leaving Branding.previewValues(). " + errors.length);
    return { ok: !errors.length, errors: errors, pending: pending };
  }

  /**
   * The audit row of a logo's upload or removal.
   *
   * @param summary - what happened
   * @param actor - who did it
   */
  static audited(summary: string, actor?: string): void {
    log.debug("Entering Branding.audited().");
    try {
      // LAZILY: `audit.js` is a large module, and this file is reached from
      // `shell_document.ts`, which every surface loads.
      require('./audit').audit({ action: 'branding.logo',
        actor: String(actor || ''), target: realms.currentId() || 'default',
        protocol: 'console', channel: 'http',
        summary: 'Sign-in appearance: ' + summary });
    } catch (e) {
      // An audit row that cannot be written does not undo the change; the
      // log says so.
      log.debug("Caught in Branding.audited(): " +
                ((e && (e as Error).message) || e));
      log.warn(errorCodes.tag('STS-CORE-0006') + 'branding: the audit row ' +
               'of a logo change could not be written: ' +
               ((e && (e as Error).message) || e));
    }
    log.debug("Leaving Branding.audited().");
  }

  // -------------------------------------------------------------------------
  // THE PREVIEW (D5): a page of this origin, opened in a new tab, that draws
  // a sample of the sign-in card with pending colours and a layout over the
  // realm's own name and logo. It is never a sign-in: its form has no
  // action and its fields are disabled, and it carries no script — so it is
  // drawn here, on the server, rather than by the runtime, and the brand
  // header is drawn here too, from the same facts `shellParts()` gives.
  // -------------------------------------------------------------------------
  /**
   * The preview page's markup.
   *
   * @param pending - the checked pending values
   * @returns the document
   */
  static previewDocument(pending: Record<string, string>): string {
    log.debug("Entering Branding.previewDocument().");
    const esc = ShellDocument.esc;
    const theme = Branding.theme(pending);
    const query = Object.keys(pending).map(function (k: string): string {
      return encodeURIComponent(k) + '=' + encodeURIComponent(pending[k]);
    }).join('&');
    const header = Branding.headerMarkup({
      name: theme.displayName,
      logo: theme.logo ? theme.logo.url : '',
      alt: theme.logo ? theme.logo.alt : '',
      link: ''
    });
    const html = '<!DOCTYPE html>\n<html lang="en" data-sts-layout="' +
      esc(theme.layout) + '"><head><meta charset="utf-8"><meta ' +
      'name="viewport" content="width=device-width, initial-scale=1">' +
      '<title>Preview — ' + esc(theme.displayName || 'Sign in') +
      '</title><link rel="stylesheet" href="/web/card.css">' +
      '<link rel="stylesheet" href="' + esc(PATHS.theme + '?preview=1' +
      (query ? '&' + query : '')) + '"></head><body>' + header +
      '<div class="card"><h1>Sign in</h1><p class="sub">A preview of this ' +
      'realm\'s sign-in appearance. Nothing here signs anybody in.</p>' +
      // A PICTURE OF A FORM, NOT ONE (Qualys QIDs 153006 and 150112,
      // 2026-11-10): `method="post"` and `autocomplete="off"` so that a
      // scanner reading the markup sees no password that could travel in a
      // query string or be remembered. Its fields are disabled and its
      // buttons are not submit buttons, so nothing is ever sent.
      '<form action="#" method="post" autocomplete="off">' +
      '<label for="pv-user">Username</label><input type="text" ' +
      'id="pv-user" autocomplete="off" disabled>' +
      '<label for="pv-pass">Password</label><input type="password" ' +
      'id="pv-pass" autocomplete="off" disabled><div class="row">' +
      '<button type="button" ' +
      'class="secondary" disabled>Cancel</button><button type="button" ' +
      'disabled>Sign in</button></div></form><p class="note"><a ' +
      'href="#">A link</a> in the accent colour.</p><div class="meta">' +
      '<div>Quieter text, mixed from the text and the card.</div></div>' +
      '</div></body></html>\n';
    log.debug("Leaving Branding.previewDocument().");
    return html;
  }

  /**
   * The brand header's markup: the logo (a link where one is set) and the
   * name, each escaped; empty where there is neither. The runtime draws the
   * same markup from the shell's attributes (`web_surface.ts`).
   *
   * @param facts - `name`, `logo` (an address), `alt` and `link`
   * @returns the markup
   */
  static headerMarkup(facts: Json): string {
    log.debug("Entering Branding.headerMarkup().");
    const esc = ShellDocument.esc;
    const f = facts || {};
    if (!f.name && !f.logo) {
      log.debug("Leaving Branding.headerMarkup(). Nothing to draw.");
      return '';
    }
    const image = f.logo ? '<img class="sts-brand-logo" src="' +
      esc(f.logo) + '" alt="' + esc(f.alt) + '">' : '';
    const linked = image && f.link ? '<a class="sts-brand-link" href="' +
      esc(f.link) + '" rel="noopener noreferrer">' + image + '</a>' : image;
    const out = '<header class="sts-brand" id="sts-brand">' + linked +
      (f.name ? '<span class="sts-brand-name">' + esc(f.name) + '</span>'
              : '') + '</header>';
    log.debug("Leaving Branding.headerMarkup().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE ROUTES.
  // -------------------------------------------------------------------------
  /**
   * Registers `GET /web/theme.css`, `GET /web/branding/logo` and `GET
   * /web/branding/preview`; `common/protocol_stack.ts` calls it.
   *
   * @param app - the shared express app
   */
  static registerRoutes(app: Json): void {
    log.debug("Entering Branding.registerRoutes().");
    app.get(PATHS.theme, function (req: Json, res: Json): void {
      log.debug("Entering GET " + PATHS.theme + ".");
      const q = req.query || {};
      let pending: Record<string, string> | undefined;
      if (q.preview !== undefined) {
        const checked = Branding.previewValues(q);
        if (!checked.ok) {
          errorCodes.mark(res, 'STS-AUTHN-0550');
          res.status(400).type('text/plain').set('Cache-Control', 'no-store')
             .send(checked.errors.join('\n'));
          log.debug("Leaving GET " + PATHS.theme + ". Refused preview.");
          return;
        }
        pending = checked.pending;
      }
      const theme = Branding.theme(pending);
      // Cached for good where the address names this exact stylesheet, as
      // `/web/card.css` is with its build id; revalidated otherwise.
      const forGood = !pending && typeof q.v === 'string' &&
        q.v === theme.digest;
      res.status(200).type('text/css')
         .set('Cache-Control', pending ? 'no-store' : (forGood
           ? 'public, max-age=31536000, immutable' : 'no-cache'));
      ShellDocument.sendCompressed(req, res, theme.css, null, null);
      log.debug("Leaving GET " + PATHS.theme + ".");
    });
    app.get(PATHS.logo, function (req: Json, res: Json): void {
      log.debug("Entering GET " + PATHS.logo + ".");
      const record = Branding.logoRecord();
      if (!record) {
        errorCodes.mark(res, 'STS-AUTHN-0549');
        res.status(404).type('text/plain').set('Cache-Control', 'no-store')
           .send('This realm has no sign-in logo.');
        log.debug("Leaving GET " + PATHS.logo + ". None.");
        return;
      }
      const etag = '"' + String(record.sha256).slice(0, 32) + '"';
      const asked = req.query && typeof req.query.v === 'string'
        ? req.query.v : '';
      res.set('ETag', etag)
         .set('X-Content-Type-Options', 'nosniff')
         .set('Content-Security-Policy',
              app.contentSecurityPolicy(LOGO_POLICY))
         .set('Cache-Control', asked && asked ===
           String(record.sha256).slice(0, 16)
           ? 'public, max-age=31536000, immutable' : 'no-cache');
      if (req.headers && req.headers['if-none-match'] === etag) {
        res.status(304).end();
        log.debug("Leaving GET " + PATHS.logo + ". Not modified.");
        return;
      }
      res.status(200).type(record.type)
         .set('Content-Disposition', 'inline; filename="logo"')
         .send(Buffer.from(String(record.data), 'base64'));
      log.debug("Leaving GET " + PATHS.logo + ".");
    });
    app.get(PATHS.preview, function (req: Json, res: Json): void {
      log.debug("Entering GET " + PATHS.preview + ".");
      const checked = Branding.previewValues(req.query || {});
      if (!checked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0550');
        res.status(400).type('text/plain').set('Cache-Control', 'no-store')
           .send('This preview cannot be drawn: ' + checked.errors.join('; ') +
                 '.');
        log.debug("Leaving GET " + PATHS.preview + ". Refused.");
        return;
      }
      res.set('Content-Security-Policy', app.contentSecurityPolicy({
        'style-src': "'self'" }));
      res.status(200).type('text/html').set('Cache-Control', 'no-store')
         .send(Branding.previewDocument(checked.pending));
      log.debug("Leaving GET " + PATHS.preview + ".");
    });
    log.debug("Leaving Branding.registerRoutes().");
  }
}

// THE WRITE RULES, added once at load: every door that writes a setting
// asks them (`config.js`'s `checkOverride()`).
config.addWriteRule(Branding.writeRule);

export = Branding;
