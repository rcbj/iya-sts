// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xml_format.ts
//
// ---------------------------------------------------------------------------
// A DOCUMENT THIS SERVICE WROTE, INDENTED FOR A PERSON (rcbj, 2026-11-13).
//
// `GET /sts/metadata` answered its WSDL on one line of several thousand
// characters, which nobody can read in a browser or a terminal. rcbj: always
// return the WSDL as formatted text. `indent()` puts each element on a line of
// its own, two spaces deeper than its parent; an element holding only text
// keeps it on its own line, and the text itself is never touched, so no value
// changes and no parser reads a different document (whitespace between
// elements is ignorable in WSDL 1.1 and XML Schema content).
//
// **IT IS FOR DOCUMENTS THIS SERVICE BUILT, NOT FOR A CALLER'S.** It reads
// the text as tags and text with one regular expression, which is exact for a
// document whose attribute values and text are escaped by `Html.esc()` (no raw
// `<` or `>` in either), holding no comment, CDATA section or mixed content.
// A caller's XML is none of those things; parse it with xmldom instead.
//
// A static utility class, like `Html`: no state, no dependencies but the
// logger its caller hands it.
// ---------------------------------------------------------------------------

/**
 * Indents an XML document this service built, one element per line.
 *
 * A static utility class; it holds no state.
 */
export = class XmlFormat {
  /**
   * The document with each element on its own line, two spaces deeper than
   * its parent. An element holding only text keeps the text on its line; the
   * XML declaration stays first. Ends with one newline.
   *
   * @param xml - a document this service built (see the file's header)
   * @param log - the caller's logger, for the Entering/Leaving lines
   * @returns the indented document
   */
  static indent(xml: string, log: { debug: (msg: string) => void }): string {
    log.debug("Entering XmlFormat.indent().");
    const tokens = String(xml).split(/(<[^>]*>)/)
      .filter(function (one) {
        return one.trim() !== '';
      });
    const lines: string[] = [];
    let depth = 0;
    const pad = function (): string {
      return '  '.repeat(Math.max(depth, 0));
    };
    const isTag = function (one: string | undefined): boolean {
      return !!one && one.charAt(0) === '<';
    };
    const isClose = function (one: string | undefined): boolean {
      return !!one && one.indexOf('</') === 0;
    };
    for (let i = 0; i < tokens.length; i++) {
      const one = tokens[i];
      if (!isTag(one)) {
        // Text that is not an element's only content: kept, on its own line.
        lines.push(pad() + one.trim());
      } else if (one.indexOf('<?') === 0 || one.indexOf('<!') === 0) {
        lines.push(pad() + one);
      } else if (isClose(one)) {
        depth--;
        lines.push(pad() + one);
      } else if (/\/>$/.test(one)) {
        lines.push(pad() + one);
      } else if (!isTag(tokens[i + 1]) && isClose(tokens[i + 2])) {
        // An element holding only text: one line, the text exactly as built.
        lines.push(pad() + one + tokens[i + 1] + tokens[i + 2]);
        i += 2;
      } else if (isClose(tokens[i + 1])) {
        lines.push(pad() + one + tokens[i + 1]);
        i += 1;
      } else {
        lines.push(pad() + one);
        depth++;
      }
    }
    log.debug("Leaving XmlFormat.indent(). " + lines.length + " lines.");
    return lines.join('\n') + '\n';
  }
};
