// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: csv_cell.ts
//
// ---------------------------------------------------------------------------
// ONE CSV CELL, SAFE TO OPEN IN A SPREADSHEET (#2138, ASVS 5.0.0 1.2.10).
//
// Every CSV this service writes goes through `CsvCell.of()`: the report
// formats (`report/formats.ts`) and the passkey report's export
// (`common/passkey_report.ts`). Until #2138 each had its own escape; the
// report's quoted per RFC 4180 and did nothing about formulas, and the
// passkey report's neutralised formulas but missed a leading NUL.
//
// **A CELL A SPREADSHEET WOULD READ AS A FORMULA GETS A SINGLE QUOTE IN
// FRONT** — OWASP's CSV injection guidance: a first character of `=`, `+`,
// `-`, `@`, a tab (0x09), a carriage return (0x0D) or NUL (0x00). The
// quote is what Excel, LibreOffice and Google Sheets take as "this is
// text", and it is visible in the cell, which is the honest cost: a
// reader sees `'=SUM(A1)` rather than a value that silently ran. RFC 4180
// quoting is applied after the prefix, so a prefixed cell holding a comma,
// a quotation mark, CR or LF is quoted as before.
//
// **A JAVASCRIPT NUMBER IS LEFT ALONE, NEGATIVE OR NOT.** `-5` from a
// numeric column is a number nobody typed, not a formula, and a quote would
// turn it into text a spreadsheet no longer sums. The decision is made on
// the TYPE of the value, never on its text: the STRING `-5` (a person's
// display name, say) is prefixed like any other string, because whoever
// set it chose it. A bigint is treated as a number.
//
// A static utility class (rcbj's rule on #50): no state, no dependencies.
// ---------------------------------------------------------------------------

/**
 * One CSV cell: the formula neutralisation OWASP describes, then RFC 4180
 * quoting.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
export = class CsvCell {
  // The first characters a spreadsheet reads as the start of a formula, or
  // that a spreadsheet strips before reading one (tab, CR, NUL).
  static readonly FORMULA_LEAD = /^[=+\-@\t\r\0]/;

  // Called once per cell of every row exported, so no Entering/Leaving
  // pair — the hot-path exception the code style allows, stated here as it
  // requires.
  /**
   * Writes one value as a CSV cell.
   *
   * `null` and `undefined` are the empty cell; a boolean is `true` or
   * `false`; anything else is converted with `String()`. A string whose
   * first character is `=`, `+`, `-`, `@`, a tab, CR or NUL gets a single
   * quote in front; a number or bigint never does. The result is quoted
   * per RFC 4180 when it holds a comma, a quotation mark, CR or LF.
   *
   * @param value - the value of the cell
   * @returns the cell's text, ready to be joined with commas
   */
  static of(value: unknown): string {
    const text = value == null ? '' : String(value);
    const numeric = typeof value === 'number' || typeof value === 'bigint';
    const safe = !numeric && CsvCell.FORMULA_LEAD.test(text)
      ? '\'' + text : text;
    return /[",\r\n]/.test(safe)
      ? '"' + safe.replace(/"/g, '""') + '"' : safe;
  }
};
