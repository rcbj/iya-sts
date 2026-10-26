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
// language and the time. The chrome words exist in English, Spanish, French
// and German, which are the languages Helvetica can draw. Any other
// language is drawn in English and the page says which language was asked
// for. The numbers are the table. There is no chart, and there is no new
// dependency to draw one.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-report-formats' });

const PAGE_W = 612;
const PAGE_H = 792;
const MARGIN = 36;
const ROW_H = 14;
const ROWS_PER_PAGE = 40;

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
        generated: 'Erstellt', page: 'Seite' }
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

function clip(text: string, width: number, size: number): string {
  log.debug("Entering clip().");
  const max = Math.max(1, Math.floor(width / (size * 0.5)));
  let out = text;
  if (text.length > max) {
    out = text.slice(0, Math.max(1, max - 1));
  }
  log.debug("Leaving clip().");
  return out;
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
    const body = JSON.stringify({
      source: plan.source,
      fields: plan.fields,
      rows: rows,
      truncated: false
    });
    log.debug("Leaving Formats.json().");
    return Buffer.from(body, 'utf8');
  }

  /**
   * @param plan - the plan
   * @param rows - the output rows
   * @returns the CSV document, UTF-8, CRLF, RFC 4180 quoting
   */
  static csv(plan: PlanLike, rows: Row[]): Buffer {
    log.debug("Entering Formats.csv().");
    const fields = plan.fields || [];
    const lines = [fields.map(csvCell).join(',')];
    for (let i = 0; i < rows.length; i++) {
      const cells: string[] = [];
      for (let c = 0; c < fields.length; c++) {
        cells.push(csvCell(rows[i][fields[c]]));
      }
      lines.push(cells.join(','));
    }
    log.debug("Leaving Formats.csv().");
    return Buffer.from(lines.join('\r\n') + '\r\n', 'utf8');
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
    const cap = maxPages > 0 ? maxPages : 1;
    const pages = Math.max(1, Math.ceil(rows.length / ROWS_PER_PAGE));
    if (pages > cap) {
      log.debug("Leaving Formats.pdf(). Too many pages.");
      return { ok: false, reason: 'pages' };
    }
    const body = Formats.assemble(plan, rows, meta || { realm: '',
      when: '' });
    log.debug("Leaving Formats.pdf().");
    return { ok: true, body: body };
  }

  /**
   * How many data rows one page carries. The executor uses it only as a
   * comment's companion; the cap is applied inside `pdf`.
   *
   * @returns the row count
   */
  static rowsPerPage(): number {
    log.debug("Entering Formats.rowsPerPage().");
    log.debug("Leaving Formats.rowsPerPage().");
    return ROWS_PER_PAGE;
  }

  private static assemble(plan: PlanLike, rows: Row[],
                          meta: PdfMeta): Buffer {
    log.debug("Entering Formats.assemble().");
    const chosen = chromeFor(plan.locale);
    const fields = plan.fields.length ? plan.fields : ['count'];
    const pages = Math.max(1, Math.ceil(rows.length / ROWS_PER_PAGE) || 1);
    const streams: string[] = [];
    for (let p = 0; p < pages; p++) {
      streams.push(Formats.pageStream(plan, rows, meta, chosen, fields,
        p, pages));
    }
    const built = Formats.wrap(streams);
    log.debug("Leaving Formats.assemble().");
    return built;
  }

  private static pageStream(plan: PlanLike, rows: Row[], meta: PdfMeta,
      chosen: { labels: Chrome; requested: string }, fields: string[],
      pageIndex: number, pages: number): string {
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
    const width = (PAGE_W - MARGIN * 2) / fields.length;
    for (let c = 0; c < fields.length; c++) {
      parts.push(textAt(MARGIN + c * width, y, 9,
        clip(fields[c], width, 9)));
    }
    y -= ROW_H;
    const start = pageIndex * ROWS_PER_PAGE;
    const slice = rows.slice(start, start + ROWS_PER_PAGE);
    for (let r = 0; r < slice.length; r++) {
      for (let c = 0; c < fields.length; c++) {
        parts.push(textAt(MARGIN + c * width, y, 8,
          clip(cellText(slice[r][fields[c]]), width, 8)));
      }
      y -= ROW_H;
    }
    parts.push(textAt(MARGIN, MARGIN, 9,
      labels.page + ' ' + (pageIndex + 1) + '/' + pages));
    log.debug("Leaving Formats.pageStream().");
    return parts.join('');
  }

  private static wrap(streams: string[]): Buffer {
    log.debug("Entering Formats.wrap().");
    const n = streams.length;
    const objects: string[] = [];
    objects.push('<< /Type /Catalog /Pages 2 0 R >>');
    const kids: string[] = [];
    for (let i = 0; i < n; i++) {
      kids.push((4 + i * 2) + ' 0 R');
    }
    objects.push('<< /Type /Pages /Kids [' + kids.join(' ') +
      '] /Count ' + n + ' >>');
    objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica ' +
      '/Encoding /WinAnsiEncoding >>');
    for (let i = 0; i < n; i++) {
      const pageNum = 4 + i * 2;
      const contentNum = pageNum + 1;
      objects.push('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' +
        PAGE_W + ' ' + PAGE_H + '] /Contents ' + contentNum +
        ' 0 R /Resources << /Font << /F1 3 0 R >> >> >>');
      const stream = streams[i];
      const length = Buffer.byteLength(stream, 'utf8');
      objects.push('<< /Length ' + length + ' >>\nstream\n' + stream +
        'endstream');
    }
    const header = '%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n';
    let body = header;
    const offsets: number[] = [0];
    for (let i = 0; i < objects.length; i++) {
      offsets.push(Buffer.byteLength(body, 'utf8'));
      body += (i + 1) + ' 0 obj\n' + objects[i] + '\nendobj\n';
    }
    const startxref = Buffer.byteLength(body, 'utf8');
    let xref = 'xref\n0 ' + (objects.length + 1) + '\n';
    xref += '0000000000 65535 f \n';
    for (let i = 1; i < offsets.length; i++) {
      let off = String(offsets[i]);
      while (off.length < 10) {
        off = '0' + off;
      }
      xref += off + ' 00000 n \n';
    }
    body += xref;
    body += 'trailer\n<< /Size ' + (objects.length + 1) +
      ' /Root 1 0 R >>\nstartxref\n' + startxref + '\n%%EOF\n';
    log.debug("Leaving Formats.wrap().");
    return Buffer.from(body, 'utf8');
  }
}

export = Formats;
