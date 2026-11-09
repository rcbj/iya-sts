// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_spellings.ts
//
// ---------------------------------------------------------------------------
// THE CANONICAL SPELLINGS, READ AS TEXT (#1390).
//
// The lists are written in `models/directory/names.tsp`. The comment above a
// group there is the
// citation the provenance rule uses. No OID is parsed out of it, because
// the list is spellings and the comments are not a schema.
//
// `scim/scim_map.ts` has a second `OWN_NAMES`. The directory folds those
// spellings in at runtime. They are read here the same way, as text.
//
// A LIBRARY. No route.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'sts-directory-spellings',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

/**
 * One spelling and the comment group it was under.
 */
interface SpelledName {
  name: string;
  citation: string;
}

/**
 * A contiguous run of own names under one comment.
 */
interface SpellingGroup {
  citation: string;
  names: string[];
}

/**
 * Both lists, plus the own-name groups a gap report walks.
 */
interface SpellingLists {
  standard: SpelledName[];
  own: SpelledName[];
  ownGroups: SpellingGroup[];
  secret: string[];
}

/**
 * Reads the two spelling lists without loading the directory.
 */
class DirectorySpellings {
  /**
   * Reads both lists from the tree `root` points at.
   *
   * @param root - the package root
   * @returns the spellings
   */
  static read(root: string): SpellingLists {
    log.debug("Entering DirectorySpellings.read().");
    const namesPath = path.join(root, 'models', 'directory', 'names.tsp');
    const scimPath = path.join(root, 'scim', 'scim_map.ts');
    const names = fs.readFileSync(namesPath, 'utf8');
    const standard = DirectorySpellings.arrayOf(names, 'standard: #[');
    const own = DirectorySpellings.arrayOf(names, 'own: #[');
    const scim = fs.readFileSync(scimPath, 'utf8');
    const scimOwn = DirectorySpellings.arrayOf(scim, 'const OWN_NAMES = [');
    scimOwn.forEach(function (one) {
      own.push(one);
    });
    const lists = {
      standard: standard,
      own: own,
      ownGroups: DirectorySpellings.groups(own),
      secret: DirectorySpellings.arrayOf(names, 'secret: #[').map(
        function (one) {
          return one.name;
        })
    };
    log.debug("Leaving DirectorySpellings.read().");
    return lists;
  }

  /**
   * The string literals of the array after `marker`, each with the comment
   * block that precedes it.
   *
   * @param source - the file text
   * @param marker - the text that ends with the array's `[`
   * @returns the spellings, in source order
   */
  static arrayOf(source: string, marker: string): SpelledName[] {
    log.debug("Entering DirectorySpellings.arrayOf().");
    const at = source.indexOf(marker);
    if (at < 0) {
      log.debug("Leaving DirectorySpellings.arrayOf(). Missing.");
      throw new Error('No ' + marker + ' in the spelling source.');
    }
    const body = DirectorySpellings.bracketBody(source, at + marker.length -
      1);
    const names = DirectorySpellings.namesIn(body);
    log.debug("Leaving DirectorySpellings.arrayOf().");
    return names;
  }

  /**
   * The text inside the `[` at `openAt`, respecting strings and comments
   * so a `]` in either cannot end the array.
   *
   * @param source - the file text
   * @param openAt - the index of `[`
   * @returns the inside, without the brackets
   */
  static bracketBody(source: string, openAt: number): string {
    log.debug("Entering DirectorySpellings.bracketBody().");
    let depth = 0;
    let i = openAt;
    let quote = '';
    while (i < source.length) {
      const ch = source.charAt(i);
      if (quote) {
        if (ch === '\\') {
          i += 2;
          continue;
        }
        if (ch === quote) {
          quote = '';
        }
        i += 1;
        continue;
      }
      if (ch === "'" || ch === '"') {
        quote = ch;
        i += 1;
        continue;
      }
      if (ch === '/' && source.charAt(i + 1) === '/') {
        i = source.indexOf('\n', i);
        if (i < 0) {
          break;
        }
        continue;
      }
      if (ch === '[') {
        depth += 1;
      } else if (ch === ']') {
        depth -= 1;
        if (depth === 0) {
          const body = source.slice(openAt + 1, i);
          log.debug("Leaving DirectorySpellings.bracketBody().");
          return body;
        }
      }
      i += 1;
    }
    log.debug("Leaving DirectorySpellings.bracketBody(). Unclosed.");
    throw new Error('Unclosed spelling array.');
  }

  /**
   * Spellings in an array body. A run of comment lines is the citation
   * of the names that follow it. A later comment replaces it.
   *
   * @param body - the inside of the array
   * @returns the names
   */
  static namesIn(body: string): SpelledName[] {
    log.debug("Entering DirectorySpellings.namesIn().");
    const out: SpelledName[] = [];
    let citation = '';
    let inComment = false;
    body.split('\n').forEach(function (line) {
      if (/^\s*$/.test(line)) {
        inComment = false;
        return;
      }
      if (/^\s*\/\//.test(line)) {
        if (!inComment) {
          citation = '';
        }
        inComment = true;
        citation = (citation + ' ' + line.replace(/^\s*\/\/\s?/, '')).trim();
        return;
      }
      inComment = false;
      const found = line.match(/['"]([^'"\\]+)['"]/g) || [];
      found.forEach(function (token) {
        out.push({
          name: token.slice(1, -1),
          citation: citation
        });
      });
    });
    log.debug("Leaving DirectorySpellings.namesIn().");
    return out;
  }

  /**
   * Contiguous own names that share one citation.
   *
   * @param names - own spellings in source order
   * @returns one group per citation change
   */
  static groups(names: SpelledName[]): SpellingGroup[] {
    log.debug("Entering DirectorySpellings.groups().");
    const groups: SpellingGroup[] = [];
    names.forEach(function (one) {
      const last = groups[groups.length - 1];
      if (!last || last.citation !== one.citation) {
        groups.push({ citation: one.citation, names: [one.name] });
        return;
      }
      last.names.push(one.name);
    });
    log.debug("Leaving DirectorySpellings.groups().");
    return groups;
  }
}

export = DirectorySpellings;
