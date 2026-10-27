// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: formats.ts
//
// ---------------------------------------------------------------------------
// JSON, CSV AND PDF (#956).
//
// JSON keeps the catalog types and names the fields by their catalog ids.
// CSV is UTF-8, quotes the way RFC 4180 quotes, and uses the same ids as
// its header. A null is an empty field. An empty result is the header and
// nothing else. PDF is a real PDF 1.4 file in Helvetica with WinAnsi, a
// table of the same ids, and a header that names the report, the realm, the
// language and the time. The chrome words exist in English, Spanish,
// French, German, Filipino and Swedish, which are the languages Helvetica
// WinAnsi can draw. Chinese is not among them: a zh-Hans or zh-Hant report
// is drawn in English and the page says which language was asked for. The
// numbers are the table. There is no chart, and there is no new dependency
// to draw one.
//
// A CELL WRAPS WITHIN ITS COLUMN (#993). Until then a cell was clipped to
// the column's width and the rest of the value was never drawn, which a
// reader could not tell from a short value. Now a value is laid out on as
// many lines as the column needs, up to CELL_BYTES of WinAnsi text (one
// byte per character), after which it is cut and ends in `...`. A row is
// as tall as its tallest cell; a page holds LINES_PER_PAGE lines of data
// (forty single-line rows, as before); a row that fits on a page is never
// split across two; a row taller than a whole page continues on the next
// rather than losing its tail. The page cap is applied to the pages the
// layout actually needs, so a wrapped report can be refused where a
// clipped one was not — the alternative is a page count that lies.
//
// EACH FORMAT IS ALSO A STREAM OF PIECES (#1045): `jsonParts()`,
// `csvParts()` and `pdfParts()` yield the document a row, a line or a PDF
// object at a time, so a job's report is written into its staging file
// without the whole body in memory (`executor.finishToFile()`). The Buffer
// methods are those pieces joined, byte for byte.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-report-formats' });

const PAGE_W = 612;
const PAGE_H = 792;
const MARGIN = 36;
const ROW_H = 14;
// Lines of table data on a page: forty single-line rows, as before #993.
const LINES_PER_PAGE = 40;
// The most WinAnsi bytes a cell draws (#993); past this it is cut.
const CELL_BYTES = 256;
// Helvetica's average advance, as a fraction of the size. The layout is
// a character count, not a measurement: the file carries no font metrics.
const AVERAGE_ADVANCE = 0.5;

interface Chrome {
  title: string;
  realm: string;
  language: string;
  generated: string;
  page: string;
}

// Accented letters are written as escapes so the source stays in the
// ASCII the style scan expects to count, and WinAnsi still receives them.
const CHROME: Record<string, Chrome> = {
  en: { title: 'Report', realm: 'Realm', language: 'Language',
        generated: 'Generated', page: 'Page' },
  es: { title: 'Informe', realm: '\u00c1mbito', language: 'Idioma',
        generated: 'Generado', page: 'P\u00e1gina' },
  fr: { title: 'Rapport', realm: 'Domaine', language: 'Langue',
        generated: 'G\u00e9n\u00e9r\u00e9', page: 'Page' },
  de: { title: 'Bericht', realm: 'Bereich', language: 'Sprache',
        generated: 'Erstellt', page: 'Seite' },
  fil: { title: 'Ulat', realm: 'Saklaw', language: 'Wika',
         generated: 'Nilikha', page: 'Pahina' },
  sv: { title: 'Rapport', realm: 'Omr\u00e5de', language: 'Spr\u00e5k',
        generated: 'Skapad', page: 'Sida' }
};

interface PlanLike {
  source: string;
  fields: string[];
  locale: string | null;
}

type Row = Record<string, unknown>;

interface PdfMeta {
  realm: string;
  when: string;
}

// One drawn line of the table: a string per column, '' where that column
// has nothing on this line.
type Line = string[];

function cellText(value: unknown): string {
  log.debug("Entering cellText().");
  let text = '';
  if (value == null) {
    text = '';
  } else if (typeof value === 'boolean') {
    text = value ? 'true' : 'false';
  } else if (typeof value === 'number') {
    text = String(value);
  } else {
    text = String(value);
  }
  log.debug("Leaving cellText().");
  return text;
}

function csvCell(value: unknown): string {
  log.debug("Entering csvCell().");
  const text = cellText(value);
  let quoted = text;
  if (/[",\r\n]/.test(text)) {
    quoted = '"' + text.replace(/"/g, '""') + '"';
  }
  log.debug("Leaving csvCell().");
  return quoted;
}

function primary(locale: string | null): string {
  log.debug("Entering primary().");
  const tag = String(locale || '').split('-')[0].toLowerCase();
  log.debug("Leaving primary().");
  return tag;
}

function chromeFor(locale: string | null): { labels: Chrome;
    requested: string } {
  log.debug("Entering chromeFor().");
  const tag = primary(locale);
  if (CHROME[tag]) {
    log.debug("Leaving chromeFor(). Drawn in that language.");
    return { labels: CHROME[tag], requested: '' };
  }
  const asked = locale ? String(locale) : '';
  log.debug("Leaving chromeFor(). English.");
  return { labels: CHROME.en, requested: asked };
}

function winAnsi(text: string): number[] {
  log.debug("Entering winAnsi().");
  const out: number[] = [];
  const chars = Array.from(String(text));
  for (let i = 0; i < chars.length; i++) {
    const cp = chars[i].codePointAt(0) || 0x3f;
    if (cp >= 0x20 && cp <= 0x7e) {
      out.push(cp);
    } else if (cp >= 0xa0 && cp <= 0xff) {
      out.push(cp);
    } else {
      out.push(0x3f);
    }
  }
  log.debug("Leaving winAnsi().");
  return out;
}

function pdfString(text: string): string {
  log.debug("Entering pdfString().");
  const bytes = winAnsi(text);
  let out = '(';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x28 || b === 0x29 || b === 0x5c) {
      out += '\\' + String.fromCharCode(b);
    } else if (b < 0x20 || b > 0x7e) {
      let oct = b.toString(8);
      while (oct.length < 3) {
        oct = '0' + oct;
      }
      out += '\\' + oct;
    } else {
      out += String.fromCharCode(b);
    }
  }
  out += ')';
  log.debug("Leaving pdfString().");
  return out;
}

// How many characters a column of `width` points holds at `size`.
function charsPerLine(width: number, size: number): number {
  log.debug("Entering charsPerLine().");
  const n = Math.max(1, Math.floor(width / (size * AVERAGE_ADVANCE)) - 1);
  log.debug("Leaving charsPerLine().");
  return n;
}

// A cell's value cut to CELL_BYTES (#993). WinAnsi is one byte per code
// point, so the count is in code points; a cut value ends in `...` inside
// the cap, so a reader can tell a cut from a short value.
function capped(text: string): string[] {
  log.debug("Entering capped().");
  let chars = Array.from(text);
  if (chars.length > CELL_BYTES) {
    chars = chars.slice(0, CELL_BYTES - 3).concat(['.', '.', '.']);
  }
  log.debug("Leaving capped().");
  return chars;
}

// The lines a cell's value takes in a column of `width` at `size` (#993):
// broken at a space where one falls within the line, a word longer than
// the line broken where the line ends, a CR or LF in the value a break of
// its own. Never empty: a blank cell is one blank line.
function wrapCell(text: string, width: number, size: number): string[] {
  log.debug("Entering wrapCell().");
  const perLine = charsPerLine(width, size);
  const lines: string[] = [];
  const paragraphs = capped(text).join('').split(/\r\n|\r|\n/);
  for (let p = 0; p < paragraphs.length; p++) {
    const words = paragraphs[p].split(' ');
    let line: string[] = [];
    for (let w = 0; w < words.length; w++) {
      let word = Array.from(words[w]);
      while (word.length > perLine) {
        if (line.length) {
          lines.push(line.join(''));
          line = [];
        }
        lines.push(word.slice(0, perLine).join(''));
        word = word.slice(perLine);
      }
      const candidate = line.length ? line.concat([' ']).concat(word)
                                    : word;
      if (candidate.length <= perLine) {
        line = candidate;
      } else {
        lines.push(line.join(''));
        line = word;
      }
    }
    lines.push(line.join(''));
  }
  log.debug("Leaving wrapCell().");
  return lines;
}

// The lines of one table row: as many as its tallest cell (#993).
function rowLines(cells: string[][]): Line[] {
  log.debug("Entering rowLines().");
  let height = 1;
  for (let c = 0; c < cells.length; c++) {
    height = Math.max(height, cells[c].length);
  }
  const lines: Line[] = [];
  for (let i = 0; i < height; i++) {
    lines.push(cells.map(function (cell: string[]): string {
      return cell[i] || '';
    }));
  }
  log.debug("Leaving rowLines().");
  return lines;
}

// The pages the rows need (#993): each a list of lines, at most `budget`
// long. A row that fits in what is left of a page goes there; one that
// does not starts the next page; one taller than a whole page is drawn
// across as many as it takes, because a row cut at the page's foot is
// the clipping this change removes, seen from below.
function paginate(rows: Row[], fields: string[], width: number,
                  budget: number): Line[][] {
  log.debug("Entering paginate().");
  const pages: Line[][] = [];
  let current: Line[] = [];
  for (let r = 0; r < rows.length; r++) {
    let pending = rowLines(fields.map(function (field: string): string[] {
      return wrapCell(cellText(rows[r][field]), width, 8);
    }));
    while (pending.length) {
      const room = budget - current.length;
      if (pending.length <= room) {
        current = current.concat(pending);
        pending = [];
      } else if (current.length === 0) {
        current = pending.slice(0, budget);
        pending = pending.slice(budget);
        pages.push(current);
        current = [];
      } else {
        pages.push(current);
        current = [];
      }
    }
  }
  if (current.length || !pages.length) {
    pages.push(current);
  }
  log.debug("Leaving paginate().");
  return pages;
}

function textAt(x: number, y: number, size: number, text: string): string {
  log.debug("Entering textAt().");
  const line = 'BT /F1 ' + size + ' Tf 1 0 0 1 ' + x + ' ' + y +
    ' Tm ' + pdfString(text) + ' Tj ET\n';
  log.debug("Leaving textAt().");
  return line;
}

/**
 * Renders a plan's rows. PDF refuses, rather than clipping the table,
 * when the rows would pass the page cap.
 */
class Formats {
  /**
   * @param plan - the plan
   * @param rows - the output rows
   * @returns the JSON document, UTF-8
   */
  static json(plan: PlanLike, rows: Row[]): Buffer {
    log.debug("Entering Formats.json().");
    const body = Formats.joined(Formats.jsonParts(plan, rows));
    log.debug("Leaving Formats.json().");
    return body;
  }

  /**
   * The JSON document a piece at a time (#1045): the same bytes
   * `JSON.stringify` makes of the whole, a row per piece, so a report is
   * written to its staging file without the whole body in memory.
   *
   * @param plan - the plan
   * @param rows - the output rows
   * @returns the pieces, in order
   */
  static *jsonParts(plan: PlanLike, rows: Row[]): Generator<string> {
    log.debug("Entering Formats.jsonParts().");
    // The head as `JSON.stringify` writes it, less its closing brace, so a
    // missing source is left out exactly as the whole document leaves it.
    const head = JSON.stringify({ source: plan.source,
      fields: plan.fields });
    const open = head.length > 2 ? head.slice(0, -1) + ',' : '{';
    yield open + '"rows":[';
    for (let i = 0; i < rows.length; i++) {
      const row = JSON.stringify(rows[i]);
      yield (i ? ',' : '') + (row === undefined ? 'null' : row);
    }
    yield '],"truncated":false}';
    log.debug("Leaving Formats.jsonParts().");
  }

  /**
   * @param plan - the plan
   * @param rows - the output rows
   * @returns the CSV document, UTF-8, CRLF, RFC 4180 quoting
   */
  static csv(plan: PlanLike, rows: Row[]): Buffer {
    log.debug("Entering Formats.csv().");
    const body = Formats.joined(Formats.csvParts(plan, rows));
    log.debug("Leaving Formats.csv().");
    return body;
  }

  /**
   * The CSV document a line at a time (#1045).
   *
   * @param plan - the plan
   * @param rows - the output rows
   * @returns the lines, each ending CRLF
   */
  static *csvParts(plan: PlanLike, rows: Row[]): Generator<string> {
    log.debug("Entering Formats.csvParts().");
    const fields = plan.fields || [];
    yield fields.map(csvCell).join(',') + '\r\n';
    for (let i = 0; i < rows.length; i++) {
      const cells: string[] = [];
      for (let c = 0; c < fields.length; c++) {
        cells.push(csvCell(rows[i][fields[c]]));
      }
      yield cells.join(',') + '\r\n';
    }
    log.debug("Leaving Formats.csvParts().");
  }

  /**
   * @param plan - the plan, including its locale
   * @param rows - the output rows
   * @param meta - the realm name and the generation time
   * @param maxPages - report.pdfMaxPages
   * @returns the PDF, or a refusal naming which cap broke
   */
  static pdf(plan: PlanLike, rows: Row[], meta: PdfMeta,
             maxPages: number):
      { ok: true; body: Buffer } | { ok: false; reason: string } {
    log.debug("Entering Formats.pdf().");
    const laid = Formats.pdfParts(plan, rows, meta, maxPages);
    if (!('parts' in laid)) {
      log.debug("Leaving Formats.pdf(). Too many pages.");
      return laid;
    }
    const body = Formats.joined(laid.parts);
    log.debug("Leaving Formats.pdf().");
    return { ok: true, body: body };
  }

  /**
   * The PDF a piece at a time (#1045). The layout is decided first, so a
   * report past the page cap is refused before a byte is produced; the
   * pages are then drawn one at a time as the pieces are asked for.
   *
   * @param plan - the plan, including its locale
   * @param rows - the output rows
   * @param meta - the realm name and the generation time
   * @param maxPages - report.pdfMaxPages
   * @returns the pieces, or a refusal naming which cap broke
   */
  static pdfParts(plan: PlanLike, rows: Row[], meta: PdfMeta,
                  maxPages: number):
      { ok: true; parts: Iterable<string> } |
      { ok: false; reason: string } {
    log.debug("Entering Formats.pdfParts().");
    const cap = maxPages > 0 ? maxPages : 1;
    const fields = plan.fields.length ? plan.fields : ['count'];
    const width = (PAGE_W - MARGIN * 2) / fields.length;
    // The header wraps too (#993); a header taller than one line takes its
    // extra lines out of every page's data budget, so the table never
    // runs into the page number.
    const header = rowLines(fields.map(function (field: string): string[] {
      return wrapCell(field, width, 9);
    }));
    const budget = Math.max(1, LINES_PER_PAGE - (header.length - 1));
    const pages = paginate(rows, fields, width, budget);
    if (pages.length > cap) {
      log.debug("Leaving Formats.pdfParts(). Too many pages.");
      return { ok: false, reason: 'pages' };
    }
    const chosen = chromeFor(plan.locale);
    const given = meta || { realm: '', when: '' };
    const streamOf = function (p: number): string {
      return Formats.pageStream(plan, given, chosen, fields, width,
        header, pages[p], p, pages.length);
    };
    log.debug("Leaving Formats.pdfParts().");
    return { ok: true, parts: Formats.wrapParts(pages.length, streamOf) };
  }

  // The pieces of a document, as one UTF-8 buffer.
  private static joined(parts: Iterable<string>): Buffer {
    log.debug("Entering Formats.joined().");
    const out: string[] = [];
    for (const part of parts) {
      out.push(part);
    }
    log.debug("Leaving Formats.joined().");
    return Buffer.from(out.join(''), 'utf8');
  }

  /**
   * How many lines of table data one page carries: forty single-line
   * rows (#993). The executor uses it only as a comment's companion; the
   * cap is applied inside `pdf`.
   *
   * @returns the line count
   */
  static rowsPerPage(): number {
    log.debug("Entering Formats.rowsPerPage().");
    log.debug("Leaving Formats.rowsPerPage().");
    return LINES_PER_PAGE;
  }

  /**
   * The most WinAnsi bytes a cell draws before it is cut (#993).
   *
   * @returns the byte count
   */
  static cellBytes(): number {
    log.debug("Entering Formats.cellBytes().");
    log.debug("Leaving Formats.cellBytes().");
    return CELL_BYTES;
  }

  // One line of the table at `y`: every column that has text on it.
  private static lineAt(y: number, size: number, width: number,
                        line: Line): string {
    log.debug("Entering Formats.lineAt().");
    let out = '';
    for (let c = 0; c < line.length; c++) {
      if (line[c]) {
        out += textAt(MARGIN + c * width, y, size, line[c]);
      }
    }
    log.debug("Leaving Formats.lineAt().");
    return out;
  }

  private static pageStream(plan: PlanLike, meta: PdfMeta,
      chosen: { labels: Chrome; requested: string }, fields: string[],
      width: number, header: Line[], lines: Line[], pageIndex: number,
      pages: number): string {
    log.debug("Entering Formats.pageStream().");
    const labels = chosen.labels;
    const parts: string[] = [];
    let y = PAGE_H - MARGIN;
    parts.push(textAt(MARGIN, y, 14,
      labels.title + ' ' + (plan.source || '')));
    y -= 16;
    parts.push(textAt(MARGIN, y, 10,
      labels.realm + ': ' + (meta.realm || '')));
    y -= 14;
    parts.push(textAt(MARGIN, y, 10,
      labels.language + ': ' + (plan.locale || 'en')));
    y -= 14;
    parts.push(textAt(MARGIN, y, 10,
      labels.generated + ': ' + (meta.when || '')));
    if (chosen.requested) {
      y -= 14;
      parts.push(textAt(MARGIN, y, 10,
        'Requested language: ' + chosen.requested));
    }
    y -= 20;
    for (let h = 0; h < header.length; h++) {
      parts.push(Formats.lineAt(y, 9, width, header[h]));
      y -= ROW_H;
    }
    for (let l = 0; l < lines.length; l++) {
      parts.push(Formats.lineAt(y, 8, width, lines[l]));
      y -= ROW_H;
    }
    parts.push(textAt(MARGIN, MARGIN, 9,
      labels.page + ' ' + (pageIndex + 1) + '/' + pages));
    log.debug("Leaving Formats.pageStream().");
    return parts.join('');
  }

  // The file around the page streams, a piece at a time: each object as
  // it is made, its offset counted from the bytes already produced, then
  // the cross-reference table. Only the offsets are kept.
  private static *wrapParts(n: number,
      streamOf: (page: number) => string): Generator<string> {
    log.debug("Entering Formats.wrapParts().");
    const kids: string[] = [];
    for (let i = 0; i < n; i++) {
      kids.push((4 + i * 2) + ' 0 R');
    }
    const fixed = [
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [' + kids.join(' ') + '] /Count ' + n + ' >>',
      '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica ' +
        '/Encoding /WinAnsiEncoding >>'
    ];
    const header = '%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n';
    let at = Buffer.byteLength(header, 'utf8');
    yield header;
    const offsets: number[] = [0];
    let number = 0;
    const object = function (body: string): string {
      number += 1;
      offsets.push(at);
      const text = number + ' 0 obj\n' + body + '\nendobj\n';
      at += Buffer.byteLength(text, 'utf8');
      return text;
    };
    for (let i = 0; i < fixed.length; i++) {
      yield object(fixed[i]);
    }
    for (let i = 0; i < n; i++) {
      const contentNum = 4 + i * 2 + 1;
      yield object('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' +
        PAGE_W + ' ' + PAGE_H + '] /Contents ' + contentNum +
        ' 0 R /Resources << /Font << /F1 3 0 R >> >> >>');
      const stream = streamOf(i);
      const length = Buffer.byteLength(stream, 'utf8');
      yield object('<< /Length ' + length + ' >>\nstream\n' + stream +
        'endstream');
    }
    const startxref = at;
    let xref = 'xref\n0 ' + (number + 1) + '\n';
    xref += '0000000000 65535 f \n';
    for (let i = 1; i < offsets.length; i++) {
      let off = String(offsets[i]);
      while (off.length < 10) {
        off = '0' + off;
      }
      xref += off + ' 00000 n \n';
    }
    yield xref + 'trailer\n<< /Size ' + (number + 1) +
      ' /Root 1 0 R >>\nstartxref\n' + startxref + '\n%%EOF\n';
    log.debug("Leaving Formats.wrapParts().");
  }
}

export = Formats;
