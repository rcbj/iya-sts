// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pqc_badge.ts
//
// ===========================================================================
// THE POST-QUANTUM ICON, DRAWN ONE WAY ON EVERY PAGE (2026-09-13).
//
// `/admin/pki` and `/admin/keys` mark each key pair that uses a post-quantum
// algorithm. WHETHER a key does is `common/pqc_support.ts`'s answer; this file
// is how that answer LOOKS, and nothing else draws it — so the icon on a
// Root CA row and the icon on an ML-DSA signing key are one element with one
// meaning, and the certificate details dialog shows the same one.
//
// **THE ICON IS A LATTICE** — nine points joined in a grid — because ML-DSA and
// ML-KEM are lattice constructions and the picture should say "a different
// kind of mathematics" rather than "secure", which a padlock or a shield would
// claim and a key pair's algorithm does not. SLH-DSA is hash-based and gets
// the same mark: the icon says post-quantum, the tooltip says which.
//
// **FOUR KINDS, FOUR WORDS BESIDE THE ICON**, because they are four claims:
// `PQC` for a post-quantum key, `PQC+` for a composite (a post-quantum half and
// a classical half), `PQC KEM` for a key-establishment key that signs nothing,
// and `PQC alt` — dashed — for a CLASSICAL key whose certificate carries an
// alternative post-quantum key. A reader who sees only the icon on a hybrid row
// and concludes the key is post-quantum has been told something false, so the
// hybrid is drawn visibly weaker.
//
// **NO SCRIPT, NO STYLESHEET, NO IMAGE REQUEST.** An inline SVG is markup, so
// `script-src 'none'` and `img-src` are both untouched; the style is on the
// element because this file does not own either page's `<style>`, and a badge
// that depended on a stylesheet one page forgot to include would be unstyled
// there with nothing failing. The sentence is in `title` for a pointer and in
// `aria-label` for a screen reader, which reads the element as one image.
//
// A LIBRARY: it registers no route. It requires `admin-ui/admin.ts` for the
// escaper and `common/pqc_support.ts` for the sentence.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `PqcBadge` takes the logger, the console's escaper and note drawer,
// and `pqc_support` through its constructor.
//
// R2 (#50): the composition root (`common/protocol_stack.ts`) builds the
// instance and installs it; this module builds none of its own. It still
// exports `WORDS`, and its three functions as FACADES that forward to that
// instance, for `admin-ui/certificate_dialog.ts`,
// `admin-ui/crypto_metadata.ts`, `admin-ui/pki_admin.ts` and the test. A
// process without the root builds a default instance at load, as loading this
// module always did.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('../common/config');

const log = bunyan.createLogger({
  name: 'pqc_badge',
  level: config.value('global.logLevel')
});

import admin = require('./admin');
import pqcSupport = require('../common/pqc_support');
import InstanceSlot = require('../common/instance_slot');
import PqcBadgeView = require('./web_pqc_badge');

type PqcKind = 'pq' | 'composite' | 'kem' | 'hybrid';

// What `badge()` reads of a classification: `pqc_support.of()`'s answer, or
// a hand-built one for the legend.
interface PqcInfo {
  kind?: string;
  label?: string;
  standard?: string;
  [key: string]: any;
}

interface PqcBadgeDeps {
  log: { debug(message: string): void };
  // The console's HTML escaper, `admin.esc`.
  esc: (value: any) => string;
  // The console's collapsible note, `admin.note`.
  note: (html: string, summary?: string) => string;
  pqcSupport: {
    sentence(info: any): string;
    of(options: any): any;
  };
}

// The words, the lattice and the styles are the renderer's since #446
// (`web_pqc_badge.ts`), which is what draws the icon.
const WORDS = PqcBadgeView.WORDS;

/**
 * The post-quantum icon, a lattice drawn as inline SVG with its word, one way
 * on every page that marks a key pair.
 */
class PqcBadge {
  /**
   * See the module's `WORDS`.
   */
  static readonly WORDS = WORDS;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the console's escaper and note, and
   * `common/pqc_support.ts`
   */
  constructor(private readonly deps: PqcBadgeDeps) {
    deps.log.debug("Entering PqcBadge.constructor().");
    deps.log.debug("Leaving PqcBadge.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): PqcBadgeDeps {
    log.debug("Entering PqcBadge.defaultDeps().");
    log.debug("Leaving PqcBadge.defaultDeps().");
    return {
      log: log,
      esc: admin.esc,
      note: admin.note,
      pqcSupport: pqcSupport
    };
  }

  // The icon for a classification, or '' where there is none — so a caller
  // can concatenate it after every row's algorithm without asking first.
  /**
   * Draws the icon for a classification.
   *
   * @param info - `pqcSupport`'s classification of a key
   * @returns the badge's markup, or '' where there is none
   */
  badge(info: PqcInfo | null | undefined): string {
    const { log } = this.deps;
    log.debug("Entering PqcBadge.badge().");
    log.debug("Leaving PqcBadge.badge().");
    return PqcBadgeView.badge(info);
  }


  // The icon for a key given in any of its spellings — `pqcSupport.of()`'s
  // arguments — which is what a row usually has to hand.
  /**
   * Draws the icon for a key given in any of the spellings `pqcSupport.of()`
   * takes.
   *
   * @param options - the key's algorithm, in any of its spellings
   * @returns the badge's markup, or '' where there is none
   */
  badgeFor(options: any): string {
    const { log, pqcSupport } = this.deps;
    log.debug("Entering PqcBadge.badgeFor().");
    log.debug("Leaving PqcBadge.badgeFor().");
    return this.badge(pqcSupport.of(options));
  }

  // The key a page draws once, above its tables: what each of the four marks
  // means, drawn with the marks themselves so the legend cannot drift from
  // them.
  /**
   * Draws the key a page shows once above its tables: what each of the four
   * marks means, drawn with the marks themselves.
   *
   * @returns the legend's markup
   */
  legend(): string {
    const { log } = this.deps;
    log.debug("Entering PqcBadge.legend().");
    log.debug("Leaving PqcBadge.legend().");
    return PqcBadgeView.legend();
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
const slot = new InstanceSlot<PqcBadge>(
  'admin-ui/pqc_badge',
  () => new PqcBadge(PqcBadge.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The post-quantum icon, drawn one way on every page: `/admin/pki`,
 * `/admin/keys` and the certificate details dialog.
 * @namespace
 */
export = {
  PqcBadge: PqcBadge,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: PqcBadge): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  WORDS: WORDS,
  badge: slot.forward('badge'),
  badgeFor: slot.forward('badgeFor'),
  legend: slot.forward('legend')
};
