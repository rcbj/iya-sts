'use strict';
//
// File: gnap_sf.ts
//
// ---------------------------------------------------------------------------
// RFC 8941 STRUCTURED FIELD VALUES FOR HTTP, PARSED AND SERIALIZED EXACTLY AS
// SECTION 4 WRITES THE ALGORITHMS DOWN.
//
// GNAP's key proofing (RFC 9635 section 7.3.1) is HTTP Message Signatures
// (RFC 9421), and every byte of an RFC 9421 signature base that is not a raw
// header value is a Structured Field serialization: the component identifiers
// are sf-strings with parameters, `@signature-params` is an Inner List, the
// Signature-Input and Signature fields are Dictionaries, `;sf` and `;key=`
// re-serialize a field value, `;bs` wraps one in Byte Sequences, and the
// Content-Digest field (RFC 9530) is a Dictionary of Byte Sequences. So this
// module is not a convenience beside the signature code — it IS most of the
// signature code, and a parser that is lenient in one place is a signature
// base that differs from the signer's in that place.
//
// ---------------------------------------------------------------------------
// WHY STRICT, WHICH IS THE SPECIFICATION'S WORD AND NOT THIS FILE'S.
//
// RFC 8941 section 1.1 is titled *Intentionally Strict Processing* and section
// 4.2 says a field that fails to parse MUST be ignored whole, and that
// specifications referencing it "are not allowed to loosen this requirement".
// The failure mode strictness prevents is the one that matters here: two
// parsers that each accept a malformed value, and each recover from it
// differently, produce two different re-serializations of one header — and a
// signature base built from one of them verifies against a signature made over
// the other. So every "fail parsing" in section 4.2 is a `throw` below, in the
// order the algorithm reaches it, and nothing is repaired.
//
// The places RFC 8941 itself asks for leniency are honoured and no others:
// a Byte Sequence with its `=` padding omitted is decoded (section 4.2.7 says
// parsers SHOULD NOT fail on that), and duplicate Dictionary and Parameter
// keys are LAST-WINS in the position of the first occurrence (sections 4.2.2
// step 4 and 4.2.3.2 step 7 — "overwrite its value", in an ordered map). What
// is NOT honoured is over-padding: `abc==` where one `=` belongs is not
// base64 at all (RFC 4648 section 3.2), and section 4.2.7 step 7 says a
// decoding failure is a parsing failure. RFC 9530's own Appendix B.5 carries
// such a value, which is recorded in `tests/gnap_httpsig.js`.
//
// ---------------------------------------------------------------------------
// THE DATA MODEL, WHICH IS CHOSEN SO THAT A ROUND TRIP IS AN IDENTITY.
//
//   bare item    { type: 'token'|'string'|'integer'|'decimal'|'boolean'|'bytes',
//                  value }                       bytes: a Buffer
//   item         the same, with `params`
//   inner list   { type: 'innerList', value: [item, ...], params }
//   parameters   [[key, bareItem], ...]          ORDERED, which is the point
//   list         [item | innerList, ...]
//   dictionary   [[key, item | innerList], ...]  ORDERED
//
// A TOKEN AND A STRING ARE DIFFERENT TYPES WITH THE SAME JAVASCRIPT VALUE, and
// that is why a bare item carries its type rather than being a plain string:
// `a=b` and `a="b"` are two different fields, and RFC 9421's component names
// are sf-strings — a parser that returned `"@method"` and `@method` as the same
// value would let an identifier through that no signer serialized.
//
// Parameters and Dictionaries are arrays of pairs rather than objects because
// ORDER IS SIGNED: RFC 9421 section 2.3 says the order of the signature
// parameters "cannot be changed" once chosen, and a JavaScript object would
// reorder a key that looks like an integer.
//
// Integers and Decimals are JavaScript numbers. Fifteen digits is inside the
// 2^53 range, which is why RFC 8941 chose fifteen; a Decimal's integer part is
// at most twelve digits and its fraction at most three, so the serializer's
// rounding (section 4.1.5, half to even) is done on the value scaled by a
// thousand, where every legal value is an exact integer.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route and requires `helpers.js` for
// the logger and nothing else in this repository, so it cannot join a cycle and
// a test can drive it with strings. A parse failure THROWS an Error whose
// message is a sentence naming the rule that was broken; callers catch it and
// map it to an error code of their own, because the same malformed value is a
// different failure in a Content-Digest check than in a Signature-Input check.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapSf` takes the logger through its constructor, and every helper
// of the parser and the serializer is one of its private methods. The module
// still exports the thirteen old names as FACADES forwarding to the instance
// the composition root builds (#50, R2), for `gnap_httpsig.ts` and the tests,
// which require it by those names. A process that loads this module without
// the root builds a default instance when the module loads.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

// A parsed value, in the data model the header describes.
type SfValue = any;

// The cursor section 4.2's algorithms consume.
interface Cursor {
  s: string;
  i: number;
}

interface ParseOptions {
  onDuplicate?(key: string): void;
}

interface GnapSfDeps {
  log: { debug(message: string): void };
}

// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA        (RFC 9110 5.6.2)
const TCHAR_PUNCT = "!#$%&'*+-.^_`|~";

class GnapSf {
  constructor(private readonly deps: GnapSfDeps) {
    deps.log.debug("Entering GnapSf.constructor().");
    deps.log.debug("Leaving GnapSf.constructor().");
  }

  // ---------------------------------------------------------------------------
  // CHARACTER CLASSES, from the ABNF of RFC 8941 section 3 and RFC 9110's
  // tchar.
  // ---------------------------------------------------------------------------
  private isDigit(c: string): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapSf.isDigit().");
    log.debug("Leaving GnapSf.isDigit().");
    return c >= '0' && c <= '9';
  }

  private isLcalpha(c: string): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapSf.isLcalpha().");
    log.debug("Leaving GnapSf.isLcalpha().");
    return c >= 'a' && c <= 'z';
  }

  private isAlpha(c: string): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapSf.isAlpha().");
    log.debug("Leaving GnapSf.isAlpha().");
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  }

  private isTchar(c: string): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapSf.isTchar().");
    log.debug("Leaving GnapSf.isTchar().");
    return this.isAlpha(c) || this.isDigit(c) ||
           (c.length === 1 && TCHAR_PUNCT.indexOf(c) >= 0);
  }

  private isKeyChar(c: string): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapSf.isKeyChar().");
    log.debug("Leaving GnapSf.isKeyChar().");
    return this.isLcalpha(c) || this.isDigit(c) || c === '_' || c === '-' ||
           c === '.' || c === '*';
  }

  // ---------------------------------------------------------------------------
  // THE INPUT CURSOR. Section 4.2 is written as consuming characters from the
  // front of `input_string`; an index over an immutable string is the same
  // algorithm without copying the remainder on every character.
  // ---------------------------------------------------------------------------
  private cursor(text: string): Cursor {
    const { log } = this.deps;
    log.debug("Entering GnapSf.cursor().");
    log.debug("Leaving GnapSf.cursor().");
    return { s: text, i: 0 };
  }

  private peek(cur: Cursor): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.peek().");
    log.debug("Leaving GnapSf.peek().");
    return cur.i < cur.s.length ? cur.s[cur.i] : '';
  }

  private empty(cur: Cursor): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapSf.empty().");
    log.debug("Leaving GnapSf.empty().");
    return cur.i >= cur.s.length;
  }

  private discardSP(cur: Cursor): void {
    const { log } = this.deps;
    log.debug("Entering GnapSf.discardSP().");
    while (!this.empty(cur) && this.peek(cur) === ' ') {
      cur.i++;
    }
    log.debug("Leaving GnapSf.discardSP().");
  }

  // OWS = *( SP / HTAB ), RFC 9110 5.6.3. Lists and Dictionaries allow a tab
  // between members because some implementations combine field lines with one.
  private discardOWS(cur: Cursor): void {
    const { log } = this.deps;
    log.debug("Entering GnapSf.discardOWS().");
    while (!this.empty(cur) && (this.peek(cur) === ' ' ||
                                this.peek(cur) === '\t')) {
      cur.i++;
    }
    log.debug("Leaving GnapSf.discardOWS().");
  }

  private fail(sentence: string): never {
    const { log } = this.deps;
    log.debug("Entering GnapSf.fail().");
    log.debug("Leaving GnapSf.fail().");
    throw new Error('RFC 8941: ' + sentence);
  }

  // ---------------------------------------------------------------------------
  // SECTION 4.2, the top of the parser, and its one step people leave out:
  // step 1 CONVERTS TO ASCII AND FAILS if it cannot. A field value carrying an
  // octet above 0x7F outside a Byte Sequence is not a Structured Field, and
  // accepting it would put a non-ASCII byte into an RFC 9421 signature base,
  // which section 2.5 step 4 of that document forbids.
  // ---------------------------------------------------------------------------
  private parseTop(input: unknown, fieldType: string,
                   options?: ParseOptions): SfValue {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseTop(). " + fieldType);
    if (typeof input !== 'string') {
      log.debug("Leaving GnapSf.parseTop(). Not a string.");
      this.fail('the field value to parse is not a string.');
    }
    for (let k = 0; k < input.length; k++) {
      const code = input.charCodeAt(k);
      if (code > 0x7f) {
        log.debug("Leaving GnapSf.parseTop(). Non-ASCII.");
        this.fail('the field value contains a character outside ASCII at ' +
                  'offset ' + k + ' (section 4.2 step 1).');
      }
    }
    const cur = this.cursor(input);
    this.discardSP(cur);
    let output;
    if (fieldType === 'list') {
      output = this.parseListAt(cur);
    } else if (fieldType === 'dictionary') {
      output = this.parseDictionaryAt(cur, options || {});
    } else if (fieldType === 'item') {
      output = this.parseItemAt(cur);
    } else {
      log.debug("Leaving GnapSf.parseTop(). Unknown field type.");
      this.fail('"' + fieldType +
                '" is not a Structured Field type; it must be list, ' +
                'dictionary or item.');
    }
    this.discardSP(cur);
    if (!this.empty(cur)) {
      log.debug("Leaving GnapSf.parseTop(). Trailing characters.");
      this.fail('unexpected "' + this.peek(cur) + '" at offset ' + cur.i +
                ' after the ' + fieldType + ' ended (section 4.2 step 7).');
    }
    log.debug("Leaving GnapSf.parseTop().");
    return output;
  }

  // Section 4.2.1.
  private parseListAt(cur: Cursor): SfValue[] {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseListAt().");
    const members = [];
    while (!this.empty(cur)) {
      members.push(this.parseItemOrInnerListAt(cur));
      this.discardOWS(cur);
      if (this.empty(cur)) {
        log.debug("Leaving GnapSf.parseListAt(). " + members.length +
                  " member(s).");
        return members;
      }
      if (this.peek(cur) !== ',') {
        log.debug("Leaving GnapSf.parseListAt(). Expected a comma.");
        this.fail('expected "," between List members at offset ' + cur.i +
                  ', found "' + this.peek(cur) + '" (section 4.2.1 step 2.4).');
      }
      cur.i++;
      this.discardOWS(cur);
      if (this.empty(cur)) {
        log.debug("Leaving GnapSf.parseListAt(). Trailing comma.");
        this.fail('the List ends with a trailing comma (section 4.2.1 step ' +
                  '2.6).');
      }
    }
    log.debug("Leaving GnapSf.parseListAt(). Empty.");
    return members;
  }

  // Section 4.2.1.1.
  private parseItemOrInnerListAt(cur: Cursor): SfValue {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseItemOrInnerListAt().");
    if (this.peek(cur) === '(') {
      log.debug("Leaving GnapSf.parseItemOrInnerListAt().");
      return this.parseInnerListAt(cur);
    }
    log.debug("Leaving GnapSf.parseItemOrInnerListAt().");
    return this.parseItemAt(cur);
  }

  // Section 4.2.1.2.
  private parseInnerListAt(cur: Cursor): SfValue {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseInnerListAt().");
    if (this.peek(cur) !== '(') {
      log.debug("Leaving GnapSf.parseInnerListAt(). No parenthesis.");
      this.fail('an Inner List must begin with "(" (section 4.2.1.2 step 1).');
    }
    cur.i++;
    const innerList = [];
    while (!this.empty(cur)) {
      this.discardSP(cur);
      if (this.peek(cur) === ')') {
        cur.i++;
        const params = this.parseParametersAt(cur);
        log.debug("Leaving GnapSf.parseInnerListAt(). " + innerList.length +
                  " item(s).");
        return { type: 'innerList', value: innerList, params: params };
      }
      innerList.push(this.parseItemAt(cur));
      const next = this.peek(cur);
      if (next !== ' ' && next !== ')') {
        log.debug("Leaving GnapSf.parseInnerListAt(). Bad separator.");
        this.fail('Inner List items must be separated by a space; found "' +
                  next +
                  '" at offset ' + cur.i + ' (section 4.2.1.2 step 3.5).');
      }
    }
    log.debug("Leaving GnapSf.parseInnerListAt(). Unterminated.");
    this.fail('the Inner List is not closed with ")" (section 4.2.1.2 step ' +
              '4).');
    log.debug("Leaving GnapSf.parseInnerListAt().");
    return null;
  }

  // Section 4.2.2. Duplicate keys overwrite the value IN PLACE — "overwrite its
  // value with member" in an ordered map keeps the first position. The note
  // under the algorithm says all but the last instance are ignored, and it is
  // the VALUE that is ignored, not the slot.
  private parseDictionaryAt(cur: Cursor, options: ParseOptions): SfValue[] {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseDictionaryAt().");
    const dictionary = [];
    while (!this.empty(cur)) {
      const thisKey = this.parseKeyAt(cur);
      let member;
      if (this.peek(cur) === '=') {
        cur.i++;
        member = this.parseItemOrInnerListAt(cur);
      } else {
        const params = this.parseParametersAt(cur);
        member = { type: 'boolean', value: true, params: params };
      }
      const at = this.indexOfKey(dictionary, thisKey);
      if (at >= 0) {
        if (typeof options.onDuplicate === 'function') {
          options.onDuplicate(thisKey);
        }
        dictionary[at][1] = member;
      } else {
        dictionary.push([thisKey, member]);
      }
      this.discardOWS(cur);
      if (this.empty(cur)) {
        log.debug("Leaving GnapSf.parseDictionaryAt(). " + dictionary.length +
                  " member(s).");
        return dictionary;
      }
      if (this.peek(cur) !== ',') {
        log.debug("Leaving GnapSf.parseDictionaryAt(). Expected a comma.");
        this.fail('expected "," between Dictionary members at offset ' + cur.i +
                  ', found "' + this.peek(cur) + '" (section 4.2.2 step 2.8).');
      }
      cur.i++;
      this.discardOWS(cur);
      if (this.empty(cur)) {
        log.debug("Leaving GnapSf.parseDictionaryAt(). Trailing comma.");
        this.fail('the Dictionary ends with a trailing comma (section 4.2.2 ' +
                  'step 2.10).');
      }
    }
    log.debug("Leaving GnapSf.parseDictionaryAt(). Empty.");
    return dictionary;
  }

  private indexOfKey(pairs: SfValue[], key: string): number {
    const { log } = this.deps;
    log.debug("Entering GnapSf.indexOfKey().");
    for (let k = 0; k < pairs.length; k++) {
      if (pairs[k][0] === key) {
        log.debug("Leaving GnapSf.indexOfKey().");
        return k;
      }
    }
    log.debug("Leaving GnapSf.indexOfKey().");
    return -1;
  }

  // Section 4.2.3.
  private parseItemAt(cur: Cursor): SfValue {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseItemAt().");
    const bare = this.parseBareItemAt(cur);
    bare.params = this.parseParametersAt(cur);
    log.debug("Leaving GnapSf.parseItemAt().");
    return bare;
  }

  // Section 4.2.3.1.
  private parseBareItemAt(cur: Cursor): SfValue {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseBareItemAt().");
    const c = this.peek(cur);
    let result;
    if (c === '-' || this.isDigit(c)) {
      result = this.parseNumberAt(cur);
    } else if (c === '"') {
      result = { type: 'string', value: this.parseStringAt(cur) };
    } else if (this.isAlpha(c) || c === '*') {
      result = { type: 'token', value: this.parseTokenAt(cur) };
    } else if (c === ':') {
      result = { type: 'bytes', value: this.parseBytesAt(cur) };
    } else if (c === '?') {
      result = { type: 'boolean', value: this.parseBooleanAt(cur) };
    } else {
      log.debug("Leaving GnapSf.parseBareItemAt(). Unrecognised.");
      this.fail((c === '' ? 'the value ended where an Item was expected'
                          : 'no Item type begins with "' + c + '"') +
                ' at offset ' + cur.i + ' (section 4.2.3.1 step 6).');
    }
    log.debug("Leaving GnapSf.parseBareItemAt(). " + result.type);
    return result;
  }

  // Section 4.2.3.2.
  private parseParametersAt(cur: Cursor): SfValue[] {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseParametersAt().");
    const params = [];
    while (!this.empty(cur)) {
      if (this.peek(cur) !== ';') {
        break;
      }
      cur.i++;
      this.discardSP(cur);
      const key = this.parseKeyAt(cur);
      let value = { type: 'boolean', value: true };
      if (this.peek(cur) === '=') {
        cur.i++;
        value = this.parseBareItemAt(cur);
      }
      const at = this.indexOfKey(params, key);
      if (at >= 0) {
        params[at][1] = value;
      } else {
        params.push([key, value]);
      }
    }
    log.debug("Leaving GnapSf.parseParametersAt(). " + params.length +
              " parameter(s).");
    return params;
  }

  // Section 4.2.3.3.
  private parseKeyAt(cur: Cursor): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseKeyAt().");
    const first = this.peek(cur);
    if (!(this.isLcalpha(first) || first === '*')) {
      log.debug("Leaving GnapSf.parseKeyAt(). Bad first character.");
      this.fail('a key must begin with a lowercase letter or "*"; found "' +
                first + '" at offset ' + cur.i + ' (section 4.2.3.3 step 1).');
    }
    const start = cur.i;
    while (!this.empty(cur) && this.isKeyChar(this.peek(cur))) {
      cur.i++;
    }
    log.debug("Leaving GnapSf.parseKeyAt().");
    return cur.s.slice(start, cur.i);
  }

  // Section 4.2.4. The two length rules are checked INSIDE the loop, as the
  // algorithm has them, so a sixteen-digit integer fails at its sixteenth digit
  // rather than being read whole and rejected afterwards — which matters only
  // for the error message, and the error message is the whole of what a caller
  // debugging a client has to go on.
  private parseNumberAt(cur: Cursor): SfValue {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseNumberAt().");
    let type = 'integer';
    let sign = 1;
    let inputNumber = '';
    if (this.peek(cur) === '-') {
      cur.i++;
      sign = -1;
    }
    if (this.empty(cur)) {
      log.debug("Leaving GnapSf.parseNumberAt(). Empty.");
      this.fail('a "-" with no digits after it is not a number (section ' +
                '4.2.4 step 5).');
    }
    if (!this.isDigit(this.peek(cur))) {
      log.debug("Leaving GnapSf.parseNumberAt(). Not a digit.");
      this.fail('a number must begin with a digit; found "' + this.peek(cur) +
                '" at offset ' + cur.i + ' (section 4.2.4 step 6).');
    }
    while (!this.empty(cur)) {
      const c = this.peek(cur);
      if (this.isDigit(c)) {
        inputNumber += c;
        cur.i++;
      } else if (type === 'integer' && c === '.') {
        if (inputNumber.length > 12) {
          log.debug("Leaving GnapSf.parseNumberAt(). Decimal integer part " +
                    "too long.");
          this.fail('a Decimal has at most 12 digits before "." (section ' +
                    '4.2.4 step 7.3.1).');
        }
        inputNumber += c;
        type = 'decimal';
        cur.i++;
      } else {
        break;
      }
      if (type === 'integer' && inputNumber.length > 15) {
        log.debug("Leaving GnapSf.parseNumberAt(). Integer too long.");
        this.fail('an Integer has at most 15 digits (section 4.2.4 step 7.5).');
      }
      if (type === 'decimal' && inputNumber.length > 16) {
        log.debug("Leaving GnapSf.parseNumberAt(). Decimal too long.");
        this.fail('a Decimal has at most 16 characters (section 4.2.4 step ' +
                  '7.6).');
      }
    }
    if (type === 'integer') {
      log.debug("Leaving GnapSf.parseNumberAt(). integer");
      return { type: 'integer', value: sign * parseInt(inputNumber, 10) };
    }
    if (inputNumber[inputNumber.length - 1] === '.') {
      log.debug("Leaving GnapSf.parseNumberAt(). Ends in a point.");
      this.fail('a Decimal may not end with "." (section 4.2.4 step 9.1).');
    }
    if (inputNumber.length - inputNumber.indexOf('.') - 1 > 3) {
      log.debug("Leaving GnapSf.parseNumberAt(). Fraction too long.");
      this.fail('a Decimal has at most 3 digits after "." (section 4.2.4 ' +
                'step 9.2).');
    }
    log.debug("Leaving GnapSf.parseNumberAt(). decimal");
    return { type: 'decimal', value: sign * parseFloat(inputNumber) };
  }

  // Section 4.2.5.
  private parseStringAt(cur: Cursor): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseStringAt().");
    let output = '';
    if (this.peek(cur) !== '"') {
      log.debug("Leaving GnapSf.parseStringAt(). No quote.");
      this.fail('a String must begin with DQUOTE (section 4.2.5 step 2).');
    }
    cur.i++;
    while (!this.empty(cur)) {
      const c = cur.s[cur.i++];
      if (c === '\\') {
        if (this.empty(cur)) {
          log.debug("Leaving GnapSf.parseStringAt(). Dangling escape.");
          this.fail('a String ends with a lone backslash (section 4.2.5 step ' +
                    '4.2.1).');
        }
        const next = cur.s[cur.i++];
        if (next !== '"' && next !== '\\') {
          log.debug("Leaving GnapSf.parseStringAt(). Bad escape.");
          this.fail('only DQUOTE and "\\" may be escaped in a String; found ' +
                    '"\\' + next + '" (section 4.2.5 step 4.2.3).');
        }
        output += next;
      } else if (c === '"') {
        log.debug("Leaving GnapSf.parseStringAt().");
        return output;
      } else {
        const code = c.charCodeAt(0);
        if (code <= 0x1f || code >= 0x7f) {
          log.debug("Leaving GnapSf.parseStringAt(). Control character.");
          this.fail('a String may contain only printable ASCII; found ' +
                    'character 0x' +
                    code.toString(16) + ' (section 4.2.5 step 4.4).');
        }
        output += c;
      }
    }
    log.debug("Leaving GnapSf.parseStringAt(). Unterminated.");
    this.fail('a String is not closed with DQUOTE (section 4.2.5 step 5).');
    log.debug("Leaving GnapSf.parseStringAt().");
    return null;
  }

  // Section 4.2.6.
  private parseTokenAt(cur: Cursor): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseTokenAt().");
    const first = this.peek(cur);
    if (!(this.isAlpha(first) || first === '*')) {
      log.debug("Leaving GnapSf.parseTokenAt(). Bad first character.");
      this.fail('a Token must begin with a letter or "*" (section 4.2.6 step ' +
                '1).');
    }
    const start = cur.i;
    while (!this.empty(cur)) {
      const c = this.peek(cur);
      if (!(this.isTchar(c) || c === ':' || c === '/')) {
        break;
      }
      cur.i++;
    }
    log.debug("Leaving GnapSf.parseTokenAt().");
    return cur.s.slice(start, cur.i);
  }

  // Section 4.2.7. The alphabet check comes BEFORE decoding and node's decoder
  // is never trusted to refuse anything: `Buffer.from(x, 'base64')` silently
  // skips characters it does not like, which is exactly the leniency step 6 and
  // the last paragraph of the section forbid.
  private parseBytesAt(cur: Cursor): Buffer {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseBytesAt().");
    if (this.peek(cur) !== ':') {
      log.debug("Leaving GnapSf.parseBytesAt(). No colon.");
      this.fail('a Byte Sequence must begin with ":" (section 4.2.7 step 1).');
    }
    cur.i++;
    const end = cur.s.indexOf(':', cur.i);
    if (end < 0) {
      log.debug("Leaving GnapSf.parseBytesAt(). Unterminated.");
      this.fail('a Byte Sequence is not closed with ":" (section 4.2.7 step ' +
                '3).');
    }
    const b64 = cur.s.slice(cur.i, end);
    cur.i = end + 1;
    const decoded = this.decodeBase64Strict(b64);
    log.debug("Leaving GnapSf.parseBytesAt(). " + decoded.length +
              " octet(s).");
    return decoded;
  }

  // RFC 4648 section 4, with the two recipient leniencies RFC 8941 section
  // 4.2.7 asks for (missing padding, non-zero pad bits) and none it does not.
  // Padding, where present, must be the padding that belongs: one or two `=` at
  // the end, and the whole a multiple of four.
  private decodeBase64Strict(b64: string): Buffer {
    const { log } = this.deps;
    log.debug("Entering GnapSf.decodeBase64Strict().");
    if (!/^[A-Za-z0-9+/=]*$/.test(b64)) {
      log.debug("Leaving GnapSf.decodeBase64Strict(). Alphabet.");
      this.fail('a Byte Sequence contains a character outside the base64 ' +
                'alphabet (section 4.2.7 step 6).');
    }
    const firstPad = b64.indexOf('=');
    const body = firstPad < 0 ? b64 : b64.slice(0, firstPad);
    const pad = firstPad < 0 ? '' : b64.slice(firstPad);
    if (!/^={0,2}$/.test(pad)) {
      log.debug("Leaving GnapSf.decodeBase64Strict(). Padding placement.");
      this.fail('base64 padding may only be one or two "=" at the end (RFC ' +
                '4648 section 3.2; RFC 8941 section 4.2.7 step 7).');
    }
    if (body.length % 4 === 1) {
      log.debug("Leaving GnapSf.decodeBase64Strict(). Impossible length.");
      this.fail('a base64 value of ' + body.length +
                ' characters before padding cannot be decoded (RFC 8941 ' +
                'section 4.2.7 step 7).');
    }
    if (pad.length > 0 && b64.length % 4 !== 0) {
      log.debug("Leaving GnapSf.decodeBase64Strict(). Wrong padding.");
      this.fail('base64 padding does not complete a four-character group: "' +
                pad + '" after ' + body.length +
                ' characters (RFC 4648 section 3.2).');
    }
    log.debug("Leaving GnapSf.decodeBase64Strict().");
    return Buffer.from(body, 'base64');
  }

  // Section 4.2.8.
  private parseBooleanAt(cur: Cursor): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseBooleanAt().");
    if (this.peek(cur) !== '?') {
      log.debug("Leaving GnapSf.parseBooleanAt(). No question mark.");
      this.fail('a Boolean must begin with "?" (section 4.2.8 step 1).');
    }
    cur.i++;
    const c = this.peek(cur);
    if (c === '1') {
      cur.i++;
      log.debug("Leaving GnapSf.parseBooleanAt(). true");
      return true;
    }
    if (c === '0') {
      cur.i++;
      log.debug("Leaving GnapSf.parseBooleanAt(). false");
      return false;
    }
    log.debug("Leaving GnapSf.parseBooleanAt(). Neither.");
    this.fail('a Boolean is "?1" or "?0"; found "?' + c +
              '" (section 4.2.8 step 5).');
    log.debug("Leaving GnapSf.parseBooleanAt().");
    return null;
  }

  // ---------------------------------------------------------------------------
  // THE THREE ENTRY POINTS. Each takes the COMBINED field value — every field
  // line of that name joined with ", " — because section 4.2 says the parser is
  // handed that and not the lines one at a time.
  // ---------------------------------------------------------------------------
  parseList(input: unknown): SfValue[] {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseList().");
    log.debug("Leaving GnapSf.parseList().");
    return this.parseTop(input, 'list');
  }

  // `options.onDuplicate(key)` is told about a key that appeared twice. The
  // parse still follows section 4.2.2 (the last value wins); the hook exists
  // for a caller whose OWN specification forbids the repetition — RFC 9421
  // section 4 says a signature label MUST be unique, and last-wins there would
  // let a second member silently replace the signature a verifier was about to
  // check.
  parseDictionary(input: unknown, options?: ParseOptions): SfValue[] {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseDictionary().");
    log.debug("Leaving GnapSf.parseDictionary().");
    return this.parseTop(input, 'dictionary', options);
  }

  parseItem(input: unknown): SfValue {
    const { log } = this.deps;
    log.debug("Entering GnapSf.parseItem().");
    log.debug("Leaving GnapSf.parseItem().");
    return this.parseTop(input, 'item');
  }

  // ===========================================================================
  // SERIALIZATION, SECTION 4.1. Every "fail serialization" is a throw, for the
  // same reason as above plus one: a signer that serialized a value this module
  // would refuse to parse has made a signature no conforming verifier can
  // check.
  // ===========================================================================

  // Section 4.1.1.
  serializeList(list: SfValue[]): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeList().");
    if (!Array.isArray(list)) {
      log.debug("Leaving GnapSf.serializeList(). Not an array.");
      this.fail('a List to serialize must be an array of members.');
    }
    const out = list.map((member) => {
      return member && member.type === 'innerList'
        ? this.serializeInnerList(member)
        : this.serializeItem(member);
    }).join(', ');
    log.debug("Leaving GnapSf.serializeList().");
    return out;
  }

  // Section 4.1.1.1.
  serializeInnerList(innerList: SfValue): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeInnerList().");
    if (!innerList || !Array.isArray(innerList.value)) {
      log.debug("Leaving GnapSf.serializeInnerList(). Not an inner list.");
      this.fail('an Inner List to serialize must carry an array of items as ' +
                '`value`.');
    }
    const out = '(' +
      innerList.value.map((item) => this.serializeItem(item)).join(' ') +
      ')' + this.serializeParams(innerList.params);
    log.debug("Leaving GnapSf.serializeInnerList().");
    return out;
  }

  // Section 4.1.1.2. A Boolean-true parameter is written as its key alone —
  // "MUST omit that value when serialized" (section 3.1.2).
  serializeParams(params: SfValue[] | null | undefined): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeParams().");
    if (params === undefined || params === null) {
      log.debug("Leaving GnapSf.serializeParams(). None.");
      return '';
    }
    if (!Array.isArray(params)) {
      log.debug("Leaving GnapSf.serializeParams(). Not an array.");
      this.fail('Parameters to serialize must be an ordered array of [key, ' +
                'bareItem] pairs.');
    }
    let out = '';
    params.forEach((pair) => {
      if (!Array.isArray(pair) || pair.length !== 2) {
        this.fail('each Parameter must be a [key, bareItem] pair.');
      }
      out += ';' + this.serializeKey(pair[0]);
      const value = pair[1];
      if (!(value && value.type === 'boolean' && value.value === true)) {
        out += '=' + this.serializeBareItem(value);
      }
    });
    log.debug("Leaving GnapSf.serializeParams().");
    return out;
  }

  // Section 4.1.1.3.
  serializeKey(key: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeKey().");
    if (typeof key !== 'string' || key.length === 0) {
      log.debug("Leaving GnapSf.serializeKey(). Empty.");
      this.fail('a key must be a non-empty string.');
    }
    if (!(this.isLcalpha(key[0]) || key[0] === '*')) {
      log.debug("Leaving GnapSf.serializeKey(). Bad first character.");
      this.fail('the key "' + key +
                '" must begin with a lowercase letter or "*" (section ' +
                '4.1.1.3 step 3).');
    }
    for (let k = 1; k < key.length; k++) {
      if (!this.isKeyChar(key[k])) {
        log.debug("Leaving GnapSf.serializeKey(). Bad character.");
        this.fail('the key "' + key + '" contains "' + key[k] +
                  '", which a key may not (section 4.1.1.3 step 2).');
      }
    }
    log.debug("Leaving GnapSf.serializeKey().");
    return key;
  }

  // Section 4.1.2. A member whose value is Boolean true is written as its key
  // and its parameters, with no "=?1".
  serializeDictionary(dictionary: SfValue[]): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeDictionary().");
    if (!Array.isArray(dictionary)) {
      log.debug("Leaving GnapSf.serializeDictionary(). Not an array.");
      this.fail('a Dictionary to serialize must be an ordered array of [key, ' +
                'member] pairs.');
    }
    const out = dictionary.map((pair) => {
      if (!Array.isArray(pair) || pair.length !== 2) {
        this.fail('each Dictionary member must be a [key, member] pair.');
      }
      const member = pair[1];
      let text = this.serializeKey(pair[0]);
      if (member && member.type === 'boolean' && member.value === true) {
        text += this.serializeParams(member.params);
      } else if (member && member.type === 'innerList') {
        text += '=' + this.serializeInnerList(member);
      } else {
        text += '=' + this.serializeItem(member);
      }
      return text;
    }).join(', ');
    log.debug("Leaving GnapSf.serializeDictionary().");
    return out;
  }

  // Section 4.1.3.
  serializeItem(item: SfValue): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeItem().");
    if (!item || typeof item !== 'object') {
      this.fail('an Item to serialize must be an object with a type and a ' +
                'value.');
    }
    log.debug("Leaving GnapSf.serializeItem().");
    return this.serializeBareItem(item) + this.serializeParams(item.params);
  }

  // Section 4.1.3.1 and the six type serializers it dispatches to.
  serializeBareItem(item: SfValue): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeBareItem().");
    if (!item || typeof item !== 'object') {
      log.debug("Leaving GnapSf.serializeBareItem(). Not an object.");
      this.fail('a bare Item to serialize must be an object with a type and ' +
                'a value.');
    }
    let out;
    switch (item.type) {
      case 'integer':
        out = this.serializeInteger(item.value);
        break;
      case 'decimal':
        out = this.serializeDecimal(item.value);
        break;
      case 'string':
        out = this.serializeString(item.value);
        break;
      case 'token':
        out = this.serializeToken(item.value);
        break;
      case 'bytes':
        out = this.serializeBytes(item.value);
        break;
      case 'boolean':
        out = this.serializeBoolean(item.value);
        break;
      default:
        log.debug("Leaving GnapSf.serializeBareItem(). Unknown type.");
        this.fail('"' + item.type +
                  '" is not a bare Item type (section 4.1.3.1 step 7).');
    }
    log.debug("Leaving GnapSf.serializeBareItem(). " + item.type);
    return out;
  }

  // Section 4.1.4.
  private serializeInteger(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeInteger().");
    if (typeof value !== 'number' || !Number.isInteger(value) ||
        value < -999999999999999 || value > 999999999999999) {
      this.fail('an Integer must be a whole number of at most 15 digits; got ' +
                String(value) + ' (section 4.1.4 step 1).');
    }
    log.debug("Leaving GnapSf.serializeInteger().");
    return (value < 0 ? '-' : '') + String(Math.abs(value));
  }

  // Section 4.1.5. Rounded to three places, half to even, on the value scaled
  // by a thousand. The half test is a tolerance rather than an equality because
  // a double such as 0.0005 * 1000 is 0.49999999999999994 — a value whose
  // author wrote exactly one half, and for whom "half to even" was the rule
  // promised.
  private serializeDecimal(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeDecimal().");
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      log.debug("Leaving GnapSf.serializeDecimal(). Not a number.");
      this.fail('a Decimal must be a finite number; got ' + String(value) +
                ' (section 4.1.5 step 1).');
    }
    const scaled = Math.abs(value) * 1000;
    const floor = Math.floor(scaled);
    const remainder = scaled - floor;
    let thousandths;
    if (Math.abs(remainder - 0.5) < 1e-7) {
      thousandths = floor % 2 === 0 ? floor : floor + 1;
    } else {
      thousandths = Math.round(scaled);
    }
    const integerPart = Math.floor(thousandths / 1000);
    const fraction = thousandths % 1000;
    if (String(integerPart).length > 12) {
      log.debug("Leaving GnapSf.serializeDecimal(). Too large.");
      this.fail('a Decimal has at most 12 digits before "."; got ' +
                String(value) + ' (section 4.1.5 step 3).');
    }
    let fractionText = '0';
    if (fraction !== 0) {
      fractionText = String(fraction).padStart(3, '0').replace(/0+$/, '');
    }
    const negative = value < 0 && thousandths !== 0;
    log.debug("Leaving GnapSf.serializeDecimal().");
    return (negative ? '-' : '') + String(integerPart) + '.' + fractionText;
  }

  // Section 4.1.6.
  private serializeString(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeString().");
    if (typeof value !== 'string') {
      log.debug("Leaving GnapSf.serializeString(). Not a string.");
      this.fail('a String must be a string; got ' + typeof value +
                ' (section 4.1.6 step 1).');
    }
    let out = '"';
    for (let k = 0; k < value.length; k++) {
      const c = value[k];
      const code = value.charCodeAt(k);
      if (code <= 0x1f || code >= 0x7f) {
        log.debug("Leaving GnapSf.serializeString(). Not printable.");
        this.fail('a String may contain only printable ASCII; character 0x' +
                  code.toString(16) + ' at offset ' + k +
                  ' (section 4.1.6 step 2).');
      }
      out += (c === '\\' || c === '"') ? '\\' + c : c;
    }
    log.debug("Leaving GnapSf.serializeString().");
    return out + '"';
  }

  // Section 4.1.7.
  private serializeToken(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeToken().");
    if (typeof value !== 'string' || value.length === 0 ||
        !(this.isAlpha(value[0]) || value[0] === '*')) {
      log.debug("Leaving GnapSf.serializeToken(). Bad first character.");
      this.fail('a Token must be a string beginning with a letter or "*"; ' +
                'got ' + JSON.stringify(value) + ' (section 4.1.7 step 2).');
    }
    for (let k = 1; k < value.length; k++) {
      const c = value[k];
      if (!(this.isTchar(c) || c === ':' || c === '/')) {
        log.debug("Leaving GnapSf.serializeToken(). Bad character.");
        this.fail('the Token ' + JSON.stringify(value) + ' contains "' + c +
                  '", which a Token may not (section 4.1.7 step 2).');
      }
    }
    log.debug("Leaving GnapSf.serializeToken().");
    return value;
  }

  // Section 4.1.8. Padded, as the section requires; node's encoder pads.
  private serializeBytes(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeBytes().");
    if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
      this.fail('a Byte Sequence must be a Buffer (section 4.1.8 step 1).');
    }
    log.debug("Leaving GnapSf.serializeBytes().");
    return ':' + Buffer.from(value).toString('base64') + ':';
  }

  // Section 4.1.9.
  private serializeBoolean(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapSf.serializeBoolean().");
    if (typeof value !== 'boolean') {
      this.fail('a Boolean must be true or false; got ' +
                JSON.stringify(value) + ' (section 4.1.9 step 1).');
    }
    log.debug("Leaving GnapSf.serializeBoolean().");
    return value ? '?1' : '?0';
  }

  // ---------------------------------------------------------------------------
  // TWO SMALL READERS every caller wants and would otherwise write four times.
  // `paramValue` answers the bare item's VALUE for a key, or undefined; `param`
  // answers the bare item itself, for a caller that has to know the type.
  // ---------------------------------------------------------------------------
  param(params: SfValue, key: string): SfValue {
    const { log } = this.deps;
    log.debug("Entering GnapSf.param().");
    if (!Array.isArray(params)) {
      log.debug("Leaving GnapSf.param().");
      return undefined;
    }
    const at = this.indexOfKey(params, key);
    log.debug("Leaving GnapSf.param().");
    return at < 0 ? undefined : params[at][1];
  }

  paramValue(params: SfValue, key: string): any {
    const { log } = this.deps;
    log.debug("Entering GnapSf.paramValue().");
    const bare = this.param(params, key);
    log.debug("Leaving GnapSf.paramValue().");
    return bare === undefined ? undefined : bare.value;
  }

  member(dictionary: SfValue, key: string): SfValue {
    const { log } = this.deps;
    log.debug("Entering GnapSf.member().");
    if (!Array.isArray(dictionary)) {
      log.debug("Leaving GnapSf.member().");
      return undefined;
    }
    const at = this.indexOfKey(dictionary, key);
    log.debug("Leaving GnapSf.member().");
    return at < 0 ? undefined : dictionary[at][1];
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): GnapSfDeps {
    helpers.log.debug("Entering GnapSf.defaultDeps().");
    helpers.log.debug("Leaving GnapSf.defaultDeps().");
    return {
      log: helpers.log
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapSf>(
  'gnap/gnap_sf',
  () => new GnapSf(GnapSf.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  GnapSf: GnapSf,
  installInstance: (instance: GnapSf): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  parseList: slot.forward('parseList'),
  parseDictionary: slot.forward('parseDictionary'),
  parseItem: slot.forward('parseItem'),
  serializeList: slot.forward('serializeList'),
  serializeDictionary: slot.forward('serializeDictionary'),
  serializeItem: slot.forward('serializeItem'),
  serializeInnerList: slot.forward('serializeInnerList'),
  serializeParams: slot.forward('serializeParams'),
  serializeBareItem: slot.forward('serializeBareItem'),
  serializeKey: slot.forward('serializeKey'),
  param: slot.forward('param'),
  paramValue: slot.forward('paramValue'),
  member: slot.forward('member')
};
