// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: certificate_dialog.ts
//
// ===========================================================================
// THE CERTIFICATE DETAILS POPUP, DRAWN BY THE SERVER, AND THE ONE RENDERER
// BOTH PAGES USE (2026-09-13).
//
// `/admin/pki` and `/admin/crypto-metadata` open a certificate's details in a
// dialog over the page, in the same tab, with an X at the top and a Close
// button at the foot. This file draws that dialog and the link that opens it,
// and nothing else draws either: the model is
// `common/certificate_details.ts`'s and which certificates may be opened is
// `admin-core/certificate_views.ts`'s, so a certificate described on one page
// is described on the other by the same function in the same words.
//
// ---------------------------------------------------------------------------
// A POPUP WITH NO SCRIPT, AND WHY THAT IS NOT A CONSTRAINT WORKED AROUND.
//
// Both pages are `script-src 'none'`, like every page of this console but the
// API explorer, and the root CLAUDE.md's rule for a scripted page is that it
// CANNOT work without one. This one can. Opening a certificate is a link that
// adds `?certificate=<SHA-256>` to the page it is on; the server draws the page
// with the dialog over it; the X and the Close button go back to the same page
// without the parameter. So:
//
//   * **it stays in the tab** — every control is a same-document navigation,
//     and there is no `target` anywhere in this file for a reason;
//   * **the URL IS the open dialog** — it can be bookmarked, sent to somebody,
//     reloaded, and the Back button closes it, which a script-opened dialog
//     does none of;
//   * **only the certificate asked for is described.** The alternative with
//     no script — every dialog rendered hidden and shown by CSS `:target` —
//     would parse and describe every certificate on the page on every render,
//     and `/admin/pki` holds dozens.
//
// What it costs is a round trip per open, which is the cost every other control
// in this console already pays, and it is said here rather than discovered.
//
// **THE CLOSE BUTTON IS A REAL `<button>` IN A GET FORM**, not a link dressed
// as one, because a person asked for a button and a button is what a keyboard
// and a screen reader announce as one. The X is a link, labelled for a screen
// reader, because a close glyph in a corner is a link in every design system
// that has one. Both go to the same address.
//
// **WHERE THE READER WAS IS KEPT.** A link that opens a dialog carries a `from`
// naming the page section it was pressed in, and closing returns to that
// fragment, so closing a certificate forty rows down a tree does not land at
// the top of the page. `from` is an element id and is refused unless it looks
// like one: it is written into an `href`.
//
// A LIBRARY: it registers no route. It requires `admin-ui/admin.ts` for the
// escaper and `admin-ui/pqc_badge.ts` for the post-quantum icon, and nothing
// requires it but the two pages (and `tests/certificate_details.js`).
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `CertificateDialog` takes the logger, the console's escaper and the
// post-quantum icon through its constructor, and every helper that was a
// free function is a private method.
//
// R2 (#50): the composition root (`common/protocol_stack.ts`) builds the
// instance and installs it; this module builds none of its own. It still
// exports `PARAM`, `FROM`, and its four functions as FACADES that forward to
// that instance, for the two pages and `tests/certificate_details.js`. A
// process without the root builds a default instance at load, as loading this
// module always did.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('../common/config');

const log = bunyan.createLogger({
  name: 'certificate_dialog',
  level: config.value('global.logLevel')
});

import admin = require('./admin');
// The post-quantum icon beside the key, the same one the two pages draw.
import pqcBadge = require('./pqc_badge');
import InstanceSlot = require('../common/instance_slot');
import CertificateDialogView = require('./web_certificate_dialog');

type Json = any;

interface CertificateDialogDeps {
  log: { debug(message: string): void };
  // The console's HTML escaper, `admin.esc`.
  esc: (value: any) => string;
  pqcBadge: { badgeFor(options: any): string };
}

// The query parameters, the style and the chain words are the renderer's
// since #446 (`web_certificate_dialog.ts`).
const PARAM = CertificateDialogView.PARAM;
const FROM = CertificateDialogView.FROM;

/**
 * The certificate details dialog, drawn by the server over the page it was
 * opened on with no script, and the link that opens it.
 */
class CertificateDialog {
  /**
   * See the module's `PARAM`.
   */
  static readonly PARAM = PARAM;
  /**
   * See the module's `FROM`.
   */
  static readonly FROM = FROM;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the HTML escaper and the post-quantum badge
   */
  constructor(private readonly deps: CertificateDialogDeps) {
    deps.log.debug("Entering CertificateDialog.constructor().");
    deps.log.debug("Leaving CertificateDialog.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): CertificateDialogDeps {
    log.debug("Entering CertificateDialog.defaultDeps().");
    log.debug("Leaving CertificateDialog.defaultDeps().");
    return {
      log: log,
      esc: admin.esc,
      pqcBadge: pqcBadge
    };
  }

  // Is a dialog being asked for on this request?
  /**
   * Answers whether a dialog is asked for on this request.
   *
   * @param req - the request
   * @returns true when the query carries the certificate parameter
   */
  requested(req: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering CertificateDialog.requested().");
    log.debug("Leaving CertificateDialog.requested().");
    return !!(req && req.query &&
              String(req.query[PARAM] || '').trim());
  }

  // Drawn by `web_certificate_dialog.ts` (#446).
  /**
   * Draws the link that opens a certificate's dialog over the page it is on.
   *
   * @param pagePath - the page the link is drawn on
   * @param fingerprint - the certificate's SHA-256 fingerprint
   * @param from - the id of the section the link sits in
   * @param text - the link's text; "View details" when absent
   * @returns the link's HTML, or an empty string without a usable fingerprint
   */
  link(pagePath: string, fingerprint: Json, from?: Json,
       text?: string): string {
    const { log } = this.deps;
    log.debug("Entering CertificateDialog.link().");
    log.debug("Leaving CertificateDialog.link().");
    return CertificateDialogView.link(pagePath, fingerprint, from, text);
  }

  // Drawn by `web_certificate_dialog.ts` (#446).
  /**
   * Draws every field of a described certificate in the order RFC 5280 section
   * 4.1 writes them; used for the opened certificate and each member of its
   * chain.
   *
   * @param described - `common/certificate_details.ts`'s model of a certificate
   * @returns the fields as HTML
   */
  fieldsHtml(described: Json): string {
    const { log } = this.deps;
    log.debug("Entering CertificateDialog.fieldsHtml().");
    log.debug("Leaving CertificateDialog.fieldsHtml().");
    return CertificateDialogView.fieldsHtml(described);
  }

  // Drawn by `web_certificate_dialog.ts` (#446).
  /**
   * Draws the dialog over a page, with its style: the certificate's fields and
   * its chain, or, for a refusal, why it cannot be opened.
   *
   * @param pagePath - the page the dialog is drawn over, which the close
   * controls return to
   * @param view - `certificate_views.detailsView()`'s answer
   * @param from - the id of the section to return to
   * @returns the dialog's HTML
   */
  dialog(pagePath: string, view: Json, from?: Json): string {
    const { log } = this.deps;
    log.debug("Entering CertificateDialog.dialog().");
    log.debug("Leaving CertificateDialog.dialog().");
    return CertificateDialogView.dialog(pagePath, view, from);
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<CertificateDialog>(
  'admin-ui/certificate_dialog',
  () => new CertificateDialog(CertificateDialog.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The certificate details dialog both `/admin/pki` and `/admin/crypto-metadata`
 * draw, and the one renderer of a certificate's fields, drawn by the server
 * with no script.
 * @namespace
 */
export = {
  CertificateDialog: CertificateDialog,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: CertificateDialog): void =>
    slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PARAM: PARAM,
  FROM: FROM,
  requested: slot.forward('requested'),
  link: slot.forward('link'),
  dialog: slot.forward('dialog'),
  fieldsHtml: slot.forward('fieldsHtml')
};
