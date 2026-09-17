'use strict';
//
// File: html.ts
//
// ---------------------------------------------------------------------------
// ESCAPING TEXT FOR HTML, AS A STATIC UTILITY CLASS (#50, 2026-09-16).
//
// The first shared helper of the TypeScript conversion. Most modules that draw
// a page carry their own `esc()`; this is the one the converted modules use,
// and the others move to it as they are converted rather than in one sweep.
//
// **A STATIC UTILITY CLASS, NOT A MODULE OF FUNCTIONS** — rcbj's rule for the
// small helpers (issue #50): no free functions in converted code. It holds no
// state and takes no dependencies, so there is nothing for the composition
// root to build.
// ---------------------------------------------------------------------------

export = class Html {
  // The five characters that change meaning in element content and in a
  // quoted attribute value. `null` and `undefined` escape to the empty string,
  // which is what every caller drawing an optional value wants.
  //
  // Called once per value while a page is drawn, so no Entering/Leaving pair —
  // the hot-path exception the code style allows, stated here as it requires.
  static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
};
