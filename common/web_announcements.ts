// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: web_announcements.ts
//
// ---------------------------------------------------------------------------
// AN ADMINISTRATOR'S ANNOUNCEMENT, IN EVERY OPEN TAB (#1086).
//
// An administrator broadcasts from Server configuration → Broadcast
// Announcement; this service sends it as its own `announcement` Security
// Event Token on the receiver streams of the admin console, the user portal
// and the reports application (`ssf/ssf_receivers.ts`), each surface's
// receiver collects it over `/ssf/poll` and keeps it for a short time, and
// THIS is the last hop: each open tab asks its own API for what its receiver
// kept — `/admin-api/announcements`, `/account-api/announcements`,
// `/report-api/announcements` — every `everyMs`, and draws each one it has
// not drawn as a banner at the top of the screen.
//
// One class for the three runtimes, so the three cannot draw or time it
// differently. What differs is handed in: how the runtime asks its API
// (with its own token), and the two words in the reader's language.
//
// * THE FIRST ASK FIXES THE TAB'S START. It sends no `since` and is answered
//   `now` and nothing else; every later ask sends THAT `now`, never a newer
//   one, so an announcement a lagging replica had not applied when one ask
//   was answered is still found by the next. The ids drawn are remembered,
//   so nothing is drawn twice. A tab opened after a broadcast never shows it.
// * THE BANNER is the floating `flash` the console's refusals use (#1066):
//   fixed at the top, above the page, so it is seen whatever is scrolled.
//   It closes itself after `closeAfterMs` (10 s) and has an × to close it
//   sooner. Its styles are set through the CSSOM, never a `style`
//   attribute, so no surface's policy has to allow inline styles.
// * THE MESSAGE IS TEXT: it goes in as `textContent`, never as markup.
// * A HIDDEN TAB DOES NOT ASK; it asks again when it is next looked at, and
//   the fixed start means nothing that arrived meanwhile is lost (while the
//   receiver still keeps it, `ssf.announcementKeepS`).
//
// It runs in a BROWSER: the timer is the tab's own, re-armed by each answer
// and stopped with `stop()` — not this service's work, so no scheduler job
// (`tests/no_periodic_timers.js` names `tick()` among its permanent
// exceptions, beside the wallet QR page's poll). A `web_` module: it requires
// nothing, logs nothing, and touches the browser only through `env`, so a
// test drives it in node.
// ---------------------------------------------------------------------------
type Json = any;

/**
 * What a runtime hands the banner: how to ask its API, and its words.
 */
interface AnnouncementOptions {
  // Asks the surface's own announcements operation; `since` is 0 for the
  // first ask. Resolves the JSON answer, or null when there was none.
  ask: (since: number) => Promise<Json>;
  // The banner's heading and the × button's label, in the reader's language.
  heading: string;
  closeLabel: string;
  // How long a banner stays (default 10 s), and the wait before asking again
  // when an answer names none (default 5 s).
  closeAfterMs?: number;
  everyMs?: number;
}

/**
 * Polls a surface's announcements and draws each new one as a banner.
 */
class WebAnnouncements {
  // The id of the container every banner is drawn into.
  static readonly CONTAINER_ID = 'sts-announcements';

  // How long a banner stays unless closed sooner (#1086: ten seconds).
  static readonly CLOSE_AFTER_MS = 10000;

  private readonly env: Json;
  private readonly options: AnnouncementOptions;
  // The `now` of the first answer: every later ask sends it.
  private since = 0;
  // The ids already drawn in this tab.
  private readonly shown = new Set<string>();
  private timer: Json = null;
  private running = false;
  private everyMs: number;

  /**
   * Builds the poller.
   *
   * @param env - the browser: `document`, `window`
   * @param options - how to ask, and the words
   */
  constructor(env: Json, options: AnnouncementOptions) {
    this.env = env || {};
    this.options = options;
    this.everyMs = Number(options.everyMs) || 5000;
  }

  /**
   * Starts asking, once; a second call does nothing.
   *
   * @returns nothing
   */
  start(): void {
    if (this.running) {
      return;
    }
    this.running = true;
    this.tick();
  }

  /**
   * Stops asking, and closes every banner (a sign-out).
   *
   * @returns nothing
   */
  stop(): void {
    this.running = false;
    const win = this.env.window;
    if (this.timer !== null && win && win.clearTimeout) {
      win.clearTimeout(this.timer);
    }
    this.timer = null;
    const doc = this.env.document;
    const box = doc && doc.getElementById &&
      doc.getElementById(WebAnnouncements.CONTAINER_ID);
    if (box && box.parentNode) {
      box.parentNode.removeChild(box);
    }
  }

  // One ask, then this re-armed for the next — the chain
  // `tests/no_periodic_timers.js` names, a browser's and not this service's.
  // A failed ask is not an announcement; it waits the usual interval and
  // asks again. A hidden tab skips the ask and keeps the chain.
  private tick(): void {
    if (!this.running) {
      return;
    }
    const self = this;
    const win = this.env.window;
    const doc = this.env.document;
    const asking = doc && doc.hidden && this.since
      ? Promise.resolve(null)
      : Promise.resolve().then(function () {
        return self.options.ask(self.since);
      });
    asking.then(function (answer: Json) {
      if (answer) {
        self.take(answer);
      }
    }, function () {
      // Nothing to draw; the next ask is armed below.
      return null;
    }).then(function () {
      if (!self.running || !win || !win.setTimeout) {
        return;
      }
      self.timer = win.setTimeout(function () {
        self.timer = null;
        self.tick();
      }, self.everyMs);
    });
  }

  /**
   * Takes one answer: fixes the start on the first, and draws what is new.
   *
   * @param answer - `{ now, everyMs, announcements }`
   * @returns the announcements drawn
   */
  take(answer: Json): Json[] {
    const a = answer || {};
    if (Number(a.everyMs) >= 1000) {
      this.everyMs = Number(a.everyMs);
    }
    if (!this.since) {
      this.since = Number(a.now) || 0;
      return [];
    }
    const drawn: Json[] = [];
    (Array.isArray(a.announcements) ? a.announcements : [])
      .forEach((one: Json) => {
        const id = String((one && one.id) || '');
        if (!id || this.shown.has(id)) {
          return;
        }
        this.shown.add(id);
        this.show(String(one.message || ''));
        drawn.push(one);
      });
    return drawn;
  }

  // The container, made once at the top of the body.
  private container(): Json {
    const doc = this.env.document;
    let box = doc.getElementById(WebAnnouncements.CONTAINER_ID);
    if (box) {
      return box;
    }
    box = doc.createElement('div');
    box.id = WebAnnouncements.CONTAINER_ID;
    box.setAttribute('aria-live', 'polite');
    const s = box.style;
    s.position = 'fixed';
    s.top = '12px';
    s.left = '50%';
    s.transform = 'translateX(-50%)';
    s.zIndex = '10000';
    s.width = 'min(640px, calc(100% - 32px))';
    s.display = 'flex';
    s.flexDirection = 'column';
    s.gap = '8px';
    doc.body.appendChild(box);
    return box;
  }

  /**
   * Draws one banner, closed by its × or after `closeAfterMs`.
   *
   * @param message - the announcement, as text
   * @returns the banner element, or null with no document
   */
  show(message: string): Json {
    const doc = this.env.document;
    if (!doc || !doc.createElement || !doc.body) {
      return null;
    }
    const banner = doc.createElement('div');
    banner.className = 'flash sts-announcement';
    banner.setAttribute('role', 'status');
    const b = banner.style;
    b.display = 'flex';
    b.alignItems = 'flex-start';
    b.gap = '12px';
    b.padding = '12px 14px';
    b.borderRadius = '8px';
    b.background = '#e8f0fe';
    b.color = '#174ea6';
    b.border = '1px solid #aecbfa';
    b.boxShadow = '0 4px 14px rgba(0,0,0,.18)';
    b.font = 'inherit';
    const text = doc.createElement('div');
    text.style.flex = '1';
    const heading = doc.createElement('strong');
    heading.textContent = this.options.heading;
    heading.style.display = 'block';
    const body = doc.createElement('span');
    body.className = 'sts-announcement-text';
    body.textContent = message;
    body.style.whiteSpace = 'pre-wrap';
    text.appendChild(heading);
    text.appendChild(body);
    const close = doc.createElement('button');
    close.type = 'button';
    close.className = 'sts-announcement-close';
    close.setAttribute('aria-label', this.options.closeLabel);
    close.title = this.options.closeLabel;
    close.textContent = '×';
    const c = close.style;
    c.border = '0';
    c.background = 'transparent';
    c.color = 'inherit';
    c.fontSize = '1.4em';
    c.lineHeight = '1';
    c.cursor = 'pointer';
    c.padding = '0 4px';
    banner.appendChild(text);
    banner.appendChild(close);
    this.container().appendChild(banner);
    const win = this.env.window;
    let timer: Json = null;
    const remove = function (): void {
      if (timer !== null && win && win.clearTimeout) {
        win.clearTimeout(timer);
      }
      timer = null;
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    };
    close.addEventListener('click', remove);
    if (win && win.setTimeout) {
      timer = win.setTimeout(remove, Number(this.options.closeAfterMs) ||
                                     WebAnnouncements.CLOSE_AFTER_MS);
    }
    return banner;
  }
}

export = WebAnnouncements;
