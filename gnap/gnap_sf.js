'use strict';
//
// File: gnap_sf.js
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

const { log } = require('../common/helpers');

// ---------------------------------------------------------------------------
// CHARACTER CLASSES, from the ABNF of RFC 8941 section 3 and RFC 9110's tchar.
// ---------------------------------------------------------------------------
function isDigit(c) {
  log.debug("Entering isDigit().");
  log.debug("Leaving isDigit().");
  return c >= '0' && c <= '9';
}

function isLcalpha(c) {
  log.debug("Entering isLcalpha().");
  log.debug("Leaving isLcalpha().");
  return c >= 'a' && c <= 'z';
}

function isAlpha(c) {
  log.debug("Entering isAlpha().");
  log.debug("Leaving isAlpha().");
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA        (RFC 9110 5.6.2)
const TCHAR_PUNCT = "!#$%&'*+-.^_`|~";
function isTchar(c) {
  log.debug("Entering isTchar().");
  log.debug("Leaving isTchar().");
  return isAlpha(c) || isDigit(c) ||
         (c.length === 1 && TCHAR_PUNCT.indexOf(c) >= 0);
}

function isKeyChar(c) {
  log.debug("Entering isKeyChar().");
  log.debug("Leaving isKeyChar().");
  return isLcalpha(c) || isDigit(c) || c === '_' || c === '-' || c === '.' ||
         c === '*';
}

// ---------------------------------------------------------------------------
// THE INPUT CURSOR. Section 4.2 is written as consuming characters from the
// front of `input_string`; an index over an immutable string is the same
// algorithm without copying the remainder on every character.
// ---------------------------------------------------------------------------
function cursor(text) {
  log.debug("Entering cursor().");
  log.debug("Leaving cursor().");
  return { s: text, i: 0 };
}

function peek(cur) {
  log.debug("Entering peek().");
  log.debug("Leaving peek().");
  return cur.i < cur.s.length ? cur.s[cur.i] : '';
}

function empty(cur) {
  log.debug("Entering empty().");
  log.debug("Leaving empty().");
  return cur.i >= cur.s.length;
}

function discardSP(cur) {
  log.debug("Entering discardSP().");
  while (!empty(cur) && peek(cur) === ' ') {
    cur.i++;
  }
  log.debug("Leaving discardSP().");
}

// OWS = *( SP / HTAB ), RFC 9110 5.6.3. Lists and Dictionaries allow a tab
// between members because some implementations combine field lines with one.
function discardOWS(cur) {
  log.debug("Entering discardOWS().");
  while (!empty(cur) && (peek(cur) === ' ' || peek(cur) === '\t')) {
    cur.i++;
  }
  log.debug("Leaving discardOWS().");
}

function fail(sentence) {
  log.debug("Entering fail().");
  log.debug("Leaving fail().");
  throw new Error('RFC 8941: ' + sentence);
}

// ---------------------------------------------------------------------------
// SECTION 4.2, the top of the parser, and its one step people leave out:
// step 1 CONVERTS TO ASCII AND FAILS if it cannot. A field value carrying an
// octet above 0x7F outside a Byte Sequence is not a Structured Field, and
// accepting it would put a non-ASCII byte into an RFC 9421 signature base,
// which section 2.5 step 4 of that document forbids.
// ---------------------------------------------------------------------------
function parseTop(input, fieldType, options) {
  log.debug("Entering parseTop(). " + fieldType);
  if (typeof input !== 'string') {
    log.debug("Leaving parseTop(). Not a string.");
    fail('the field value to parse is not a string.');
  }
  for (let k = 0; k < input.length; k++) {
    const code = input.charCodeAt(k);
    if (code > 0x7f) {
      log.debug("Leaving parseTop(). Non-ASCII.");
      fail('the field value contains a character outside ASCII at offset ' + k +
           ' (section 4.2 step 1).');
    }
  }
  const cur = cursor(input);
  discardSP(cur);
  let output;
  if (fieldType === 'list') {
    output = parseListAt(cur);
  } else if (fieldType === 'dictionary') {
    output = parseDictionaryAt(cur, options || {});
  } else if (fieldType === 'item') {
    output = parseItemAt(cur);
  } else {
    log.debug("Leaving parseTop(). Unknown field type.");
    fail('"' + fieldType + '" is not a Structured Field type; it must be ' +
         'list, dictionary or item.');
  }
  discardSP(cur);
  if (!empty(cur)) {
    log.debug("Leaving parseTop(). Trailing characters.");
    fail('unexpected "' + peek(cur) + '" at offset ' + cur.i + ' after the ' +
         fieldType + ' ended (section 4.2 step 7).');
  }
  log.debug("Leaving parseTop().");
  return output;
}

// Section 4.2.1.
function parseListAt(cur) {
  log.debug("Entering parseListAt().");
  const members = [];
  while (!empty(cur)) {
    members.push(parseItemOrInnerListAt(cur));
    discardOWS(cur);
    if (empty(cur)) {
      log.debug("Leaving parseListAt(). " + members.length + " member(s).");
      return members;
    }
    if (peek(cur) !== ',') {
      log.debug("Leaving parseListAt(). Expected a comma.");
      fail('expected "," between List members at offset ' + cur.i +
           ', found "' +
           peek(cur) + '" (section 4.2.1 step 2.4).');
    }
    cur.i++;
    discardOWS(cur);
    if (empty(cur)) {
      log.debug("Leaving parseListAt(). Trailing comma.");
      fail('the List ends with a trailing comma (section 4.2.1 step 2.6).');
    }
  }
  log.debug("Leaving parseListAt(). Empty.");
  return members;
}

// Section 4.2.1.1.
function parseItemOrInnerListAt(cur) {
  log.debug("Entering parseItemOrInnerListAt().");
  if (peek(cur) === '(') {
    log.debug("Leaving parseItemOrInnerListAt().");
    return parseInnerListAt(cur);
  }
  log.debug("Leaving parseItemOrInnerListAt().");
  return parseItemAt(cur);
}

// Section 4.2.1.2.
function parseInnerListAt(cur) {
  log.debug("Entering parseInnerListAt().");
  if (peek(cur) !== '(') {
    log.debug("Leaving parseInnerListAt(). No parenthesis.");
    fail('an Inner List must begin with "(" (section 4.2.1.2 step 1).');
  }
  cur.i++;
  const innerList = [];
  while (!empty(cur)) {
    discardSP(cur);
    if (peek(cur) === ')') {
      cur.i++;
      const params = parseParametersAt(cur);
      log.debug("Leaving parseInnerListAt(). " + innerList.length +
                " item(s).");
      return { type: 'innerList', value: innerList, params: params };
    }
    innerList.push(parseItemAt(cur));
    const next = peek(cur);
    if (next !== ' ' && next !== ')') {
      log.debug("Leaving parseInnerListAt(). Bad separator.");
      fail('Inner List items must be separated by a space; found "' + next +
           '" at offset ' + cur.i + ' (section 4.2.1.2 step 3.5).');
    }
  }
  log.debug("Leaving parseInnerListAt(). Unterminated.");
  fail('the Inner List is not closed with ")" (section 4.2.1.2 step 4).');
  log.debug("Leaving parseInnerListAt().");
  return null;
}

// Section 4.2.2. Duplicate keys overwrite the value IN PLACE — "overwrite its
// value with member" in an ordered map keeps the first position. The note under
// the algorithm says all but the last instance are ignored, and it is the VALUE
// that is ignored, not the slot.
function parseDictionaryAt(cur, options) {
  log.debug("Entering parseDictionaryAt().");
  const dictionary = [];
  while (!empty(cur)) {
    const thisKey = parseKeyAt(cur);
    let member;
    if (peek(cur) === '=') {
      cur.i++;
      member = parseItemOrInnerListAt(cur);
    } else {
      const params = parseParametersAt(cur);
      member = { type: 'boolean', value: true, params: params };
    }
    const at = indexOfKey(dictionary, thisKey);
    if (at >= 0) {
      if (typeof options.onDuplicate === 'function') {
        options.onDuplicate(thisKey);
      }
      dictionary[at][1] = member;
    } else {
      dictionary.push([thisKey, member]);
    }
    discardOWS(cur);
    if (empty(cur)) {
      log.debug("Leaving parseDictionaryAt(). " + dictionary.length + " " +
          "member(s).");
      return dictionary;
    }
    if (peek(cur) !== ',') {
      log.debug("Leaving parseDictionaryAt(). Expected a comma.");
      fail('expected "," between Dictionary members at offset ' + cur.i +
           ', found "' + peek(cur) + '" (section 4.2.2 step 2.8).');
    }
    cur.i++;
    discardOWS(cur);
    if (empty(cur)) {
      log.debug("Leaving parseDictionaryAt(). Trailing comma.");
      fail('the Dictionary ends with a trailing comma (section 4.2.2 step ' +
           '2.10).');
    }
  }
  log.debug("Leaving parseDictionaryAt(). Empty.");
  return dictionary;
}

function indexOfKey(pairs, key) {
  log.debug("Entering indexOfKey().");
  for (let k = 0; k < pairs.length; k++) {
    if (pairs[k][0] === key) {
      log.debug("Leaving indexOfKey().");
      return k;
    }
  }
  log.debug("Leaving indexOfKey().");
  return -1;
}

// Section 4.2.3.
function parseItemAt(cur) {
  log.debug("Entering parseItemAt().");
  const bare = parseBareItemAt(cur);
  bare.params = parseParametersAt(cur);
  log.debug("Leaving parseItemAt().");
  return bare;
}

// Section 4.2.3.1.
function parseBareItemAt(cur) {
  log.debug("Entering parseBareItemAt().");
  const c = peek(cur);
  let result;
  if (c === '-' || isDigit(c)) {
    result = parseNumberAt(cur);
  } else if (c === '"') {
    result = { type: 'string', value: parseStringAt(cur) };
  } else if (isAlpha(c) || c === '*') {
    result = { type: 'token', value: parseTokenAt(cur) };
  } else if (c === ':') {
    result = { type: 'bytes', value: parseBytesAt(cur) };
  } else if (c === '?') {
    result = { type: 'boolean', value: parseBooleanAt(cur) };
  } else {
    log.debug("Leaving parseBareItemAt(). Unrecognised.");
    fail((c === '' ? 'the value ended where an Item was expected'
                   : 'no Item type begins with "' + c + '"') +
         ' at offset ' + cur.i + ' (section 4.2.3.1 step 6).');
  }
  log.debug("Leaving parseBareItemAt(). " + result.type);
  return result;
}

// Section 4.2.3.2.
function parseParametersAt(cur) {
  log.debug("Entering parseParametersAt().");
  const params = [];
  while (!empty(cur)) {
    if (peek(cur) !== ';') {
      break;
    }
    cur.i++;
    discardSP(cur);
    const key = parseKeyAt(cur);
    let value = { type: 'boolean', value: true };
    if (peek(cur) === '=') {
      cur.i++;
      value = parseBareItemAt(cur);
    }
    const at = indexOfKey(params, key);
    if (at >= 0) {
      params[at][1] = value;
    } else {
      params.push([key, value]);
    }
  }
  log.debug("Leaving parseParametersAt(). " + params.length + " parameter(s).");
  return params;
}

// Section 4.2.3.3.
function parseKeyAt(cur) {
  log.debug("Entering parseKeyAt().");
  const first = peek(cur);
  if (!(isLcalpha(first) || first === '*')) {
    log.debug("Leaving parseKeyAt(). Bad first character.");
    fail('a key must begin with a lowercase letter or "*"; found "' + first +
         '" at offset ' + cur.i + ' (section 4.2.3.3 step 1).');
  }
  const start = cur.i;
  while (!empty(cur) && isKeyChar(peek(cur))) {
    cur.i++;
  }
  log.debug("Leaving parseKeyAt().");
  return cur.s.slice(start, cur.i);
}

// Section 4.2.4. The two length rules are checked INSIDE the loop, as the
// algorithm has them, so a sixteen-digit integer fails at its sixteenth digit
// rather than being read whole and rejected afterwards — which matters only
// for the error message, and the error message is the whole of what a caller
// debugging a client has to go on.
function parseNumberAt(cur) {
  log.debug("Entering parseNumberAt().");
  let type = 'integer';
  let sign = 1;
  let inputNumber = '';
  if (peek(cur) === '-') {
    cur.i++;
    sign = -1;
  }
  if (empty(cur)) {
    log.debug("Leaving parseNumberAt(). Empty.");
    fail('a "-" with no digits after it is not a number (section 4.2.4 step ' +
         '5).');
  }
  if (!isDigit(peek(cur))) {
    log.debug("Leaving parseNumberAt(). Not a digit.");
    fail('a number must begin with a digit; found "' + peek(cur) + '" at ' +
        'offset ' +
         cur.i + ' (section 4.2.4 step 6).');
  }
  while (!empty(cur)) {
    const c = peek(cur);
    if (isDigit(c)) {
      inputNumber += c;
      cur.i++;
    } else if (type === 'integer' && c === '.') {
      if (inputNumber.length > 12) {
        log.debug("Leaving parseNumberAt(). Decimal integer part too long.");
        fail('a Decimal has at most 12 digits before "." (section 4.2.4 step ' +
             '7.3.1).');
      }
      inputNumber += c;
      type = 'decimal';
      cur.i++;
    } else {
      break;
    }
    if (type === 'integer' && inputNumber.length > 15) {
      log.debug("Leaving parseNumberAt(). Integer too long.");
      fail('an Integer has at most 15 digits (section 4.2.4 step 7.5).');
    }
    if (type === 'decimal' && inputNumber.length > 16) {
      log.debug("Leaving parseNumberAt(). Decimal too long.");
      fail('a Decimal has at most 16 characters (section 4.2.4 step 7.6).');
    }
  }
  if (type === 'integer') {
    log.debug("Leaving parseNumberAt(). integer");
    return { type: 'integer', value: sign * parseInt(inputNumber, 10) };
  }
  if (inputNumber[inputNumber.length - 1] === '.') {
    log.debug("Leaving parseNumberAt(). Ends in a point.");
    fail('a Decimal may not end with "." (section 4.2.4 step 9.1).');
  }
  if (inputNumber.length - inputNumber.indexOf('.') - 1 > 3) {
    log.debug("Leaving parseNumberAt(). Fraction too long.");
    fail('a Decimal has at most 3 digits after "." (section 4.2.4 step 9.2).');
  }
  log.debug("Leaving parseNumberAt(). decimal");
  return { type: 'decimal', value: sign * parseFloat(inputNumber) };
}

// Section 4.2.5.
function parseStringAt(cur) {
  log.debug("Entering parseStringAt().");
  let output = '';
  if (peek(cur) !== '"') {
    log.debug("Leaving parseStringAt(). No quote.");
    fail('a String must begin with DQUOTE (section 4.2.5 step 2).');
  }
  cur.i++;
  while (!empty(cur)) {
    const c = cur.s[cur.i++];
    if (c === '\\') {
      if (empty(cur)) {
        log.debug("Leaving parseStringAt(). Dangling escape.");
        fail('a String ends with a lone backslash (section 4.2.5 step 4.2.1).');
      }
      const next = cur.s[cur.i++];
      if (next !== '"' && next !== '\\') {
        log.debug("Leaving parseStringAt(). Bad escape.");
        fail('only DQUOTE and "\\" may be escaped in a String; found "\\' +
             next +
             '" (section 4.2.5 step 4.2.3).');
      }
      output += next;
    } else if (c === '"') {
      log.debug("Leaving parseStringAt().");
      return output;
    } else {
      const code = c.charCodeAt(0);
      if (code <= 0x1f || code >= 0x7f) {
        log.debug("Leaving parseStringAt(). Control character.");
        fail('a String may contain only printable ASCII; found character 0x' +
             code.toString(16) + ' (section 4.2.5 step 4.4).');
      }
      output += c;
    }
  }
  log.debug("Leaving parseStringAt(). Unterminated.");
  fail('a String is not closed with DQUOTE (section 4.2.5 step 5).');
  log.debug("Leaving parseStringAt().");
  return null;
}

// Section 4.2.6.
function parseTokenAt(cur) {
  log.debug("Entering parseTokenAt().");
  const first = peek(cur);
  if (!(isAlpha(first) || first === '*')) {
    log.debug("Leaving parseTokenAt(). Bad first character.");
    fail('a Token must begin with a letter or "*" (section 4.2.6 step 1).');
  }
  const start = cur.i;
  while (!empty(cur)) {
    const c = peek(cur);
    if (!(isTchar(c) || c === ':' || c === '/')) {
      break;
    }
    cur.i++;
  }
  log.debug("Leaving parseTokenAt().");
  return cur.s.slice(start, cur.i);
}

// Section 4.2.7. The alphabet check comes BEFORE decoding and node's decoder is
// never trusted to refuse anything: `Buffer.from(x, 'base64')` silently skips
// characters it does not like, which is exactly the leniency step 6 and the
// last paragraph of the section forbid.
function parseBytesAt(cur) {
  log.debug("Entering parseBytesAt().");
  if (peek(cur) !== ':') {
    log.debug("Leaving parseBytesAt(). No colon.");
    fail('a Byte Sequence must begin with ":" (section 4.2.7 step 1).');
  }
  cur.i++;
  const end = cur.s.indexOf(':', cur.i);
  if (end < 0) {
    log.debug("Leaving parseBytesAt(). Unterminated.");
    fail('a Byte Sequence is not closed with ":" (section 4.2.7 step 3).');
  }
  const b64 = cur.s.slice(cur.i, end);
  cur.i = end + 1;
  const decoded = decodeBase64Strict(b64);
  log.debug("Leaving parseBytesAt(). " + decoded.length + " octet(s).");
  return decoded;
}

// RFC 4648 section 4, with the two recipient leniencies RFC 8941 section 4.2.7
// asks for (missing padding, non-zero pad bits) and none it does not. Padding,
// where present, must be the padding that belongs: one or two `=` at the end,
// and the whole a multiple of four.
function decodeBase64Strict(b64) {
  log.debug("Entering decodeBase64Strict().");
  if (!/^[A-Za-z0-9+/=]*$/.test(b64)) {
    log.debug("Leaving decodeBase64Strict(). Alphabet.");
    fail('a Byte Sequence contains a character outside the base64 alphabet ' +
         '(section 4.2.7 step 6).');
  }
  const firstPad = b64.indexOf('=');
  const body = firstPad < 0 ? b64 : b64.slice(0, firstPad);
  const pad = firstPad < 0 ? '' : b64.slice(firstPad);
  if (!/^={0,2}$/.test(pad)) {
    log.debug("Leaving decodeBase64Strict(). Padding placement.");
    fail('base64 padding may only be one or two "=" at the end (RFC 4648 ' +
         'section 3.2; RFC 8941 section 4.2.7 step 7).');
  }
  if (body.length % 4 === 1) {
    log.debug("Leaving decodeBase64Strict(). Impossible length.");
    fail('a base64 value of ' + body.length + ' characters before padding ' +
         'cannot be decoded (RFC 8941 section 4.2.7 step 7).');
  }
  if (pad.length > 0 && b64.length % 4 !== 0) {
    log.debug("Leaving decodeBase64Strict(). Wrong padding.");
    fail('base64 padding does not complete a four-character group: "' + pad +
         '" after ' + body.length + ' characters (RFC 4648 section 3.2).');
  }
  log.debug("Leaving decodeBase64Strict().");
  return Buffer.from(body, 'base64');
}

// Section 4.2.8.
function parseBooleanAt(cur) {
  log.debug("Entering parseBooleanAt().");
  if (peek(cur) !== '?') {
    log.debug("Leaving parseBooleanAt(). No question mark.");
    fail('a Boolean must begin with "?" (section 4.2.8 step 1).');
  }
  cur.i++;
  const c = peek(cur);
  if (c === '1') {
    cur.i++;
    log.debug("Leaving parseBooleanAt(). true");
    return true;
  }
  if (c === '0') {
    cur.i++;
    log.debug("Leaving parseBooleanAt(). false");
    return false;
  }
  log.debug("Leaving parseBooleanAt(). Neither.");
  fail('a Boolean is "?1" or "?0"; found "?' + c + '" (section 4.2.8 step 5).');
  log.debug("Leaving parseBooleanAt().");
  return null;
}

// ---------------------------------------------------------------------------
// THE THREE ENTRY POINTS. Each takes the COMBINED field value — every field
// line of that name joined with ", " — because section 4.2 says the parser is
// handed that and not the lines one at a time.
// ---------------------------------------------------------------------------
function parseList(input) {
  log.debug("Entering parseList().");
  log.debug("Leaving parseList().");
  return parseTop(input, 'list');
}

// `options.onDuplicate(key)` is told about a key that appeared twice. The
// parse still follows section 4.2.2 (the last value wins); the hook exists for
// a caller whose OWN specification forbids the repetition — RFC 9421 section 4
// says a signature label MUST be unique, and last-wins there would let a second
// member silently replace the signature a verifier was about to check.
function parseDictionary(input, options) {
  log.debug("Entering parseDictionary().");
  log.debug("Leaving parseDictionary().");
  return parseTop(input, 'dictionary', options);
}

function parseItem(input) {
  log.debug("Entering parseItem().");
  log.debug("Leaving parseItem().");
  return parseTop(input, 'item');
}

// ===========================================================================
// SERIALIZATION, SECTION 4.1. Every "fail serialization" is a throw, for the
// same reason as above plus one: a signer that serialized a value this module
// would refuse to parse has made a signature no conforming verifier can check.
// ===========================================================================

// Section 4.1.1.
function serializeList(list) {
  log.debug("Entering serializeList().");
  if (!Array.isArray(list)) {
    log.debug("Leaving serializeList(). Not an array.");
    fail('a List to serialize must be an array of members.');
  }
  const out = list.map(function (member) {
    return member && member.type === 'innerList' ? serializeInnerList(member)
                                                 : serializeItem(member);
  }).join(', ');
  log.debug("Leaving serializeList().");
  return out;
}

// Section 4.1.1.1.
function serializeInnerList(innerList) {
  log.debug("Entering serializeInnerList().");
  if (!innerList || !Array.isArray(innerList.value)) {
    log.debug("Leaving serializeInnerList(). Not an inner list.");
    fail('an Inner List to serialize must carry an array of items as `value`.');
  }
  const out = '(' + innerList.value.map(serializeItem).join(' ') + ')' +
              serializeParams(innerList.params);
  log.debug("Leaving serializeInnerList().");
  return out;
}

// Section 4.1.1.2. A Boolean-true parameter is written as its key alone —
// "MUST omit that value when serialized" (section 3.1.2).
function serializeParams(params) {
  log.debug("Entering serializeParams().");
  if (params === undefined || params === null) {
    log.debug("Leaving serializeParams(). None.");
    return '';
  }
  if (!Array.isArray(params)) {
    log.debug("Leaving serializeParams(). Not an array.");
    fail('Parameters to serialize must be an ordered array of [key, ' +
         'bareItem] pairs.');
  }
  let out = '';
  params.forEach(function (pair) {
    if (!Array.isArray(pair) || pair.length !== 2) {
      fail('each Parameter must be a [key, bareItem] pair.');
    }
    out += ';' + serializeKey(pair[0]);
    const value = pair[1];
    if (!(value && value.type === 'boolean' && value.value === true)) {
      out += '=' + serializeBareItem(value);
    }
  });
  log.debug("Leaving serializeParams().");
  return out;
}

// Section 4.1.1.3.
function serializeKey(key) {
  log.debug("Entering serializeKey().");
  if (typeof key !== 'string' || key.length === 0) {
    log.debug("Leaving serializeKey(). Empty.");
    fail('a key must be a non-empty string.');
  }
  if (!(isLcalpha(key[0]) || key[0] === '*')) {
    log.debug("Leaving serializeKey(). Bad first character.");
    fail('the key "' + key + '" must begin with a lowercase letter or "*" ' +
         '(section 4.1.1.3 step 3).');
  }
  for (let k = 1; k < key.length; k++) {
    if (!isKeyChar(key[k])) {
      log.debug("Leaving serializeKey(). Bad character.");
      fail('the key "' + key + '" contains "' + key[k] + '", which a key may ' +
           'not (section 4.1.1.3 step 2).');
    }
  }
  log.debug("Leaving serializeKey().");
  return key;
}

// Section 4.1.2. A member whose value is Boolean true is written as its key
// and its parameters, with no "=?1".
function serializeDictionary(dictionary) {
  log.debug("Entering serializeDictionary().");
  if (!Array.isArray(dictionary)) {
    log.debug("Leaving serializeDictionary(). Not an array.");
    fail('a Dictionary to serialize must be an ordered array of [key, ' +
         'member] pairs.');
  }
  const out = dictionary.map(function (pair) {
    if (!Array.isArray(pair) || pair.length !== 2) {
      fail('each Dictionary member must be a [key, member] pair.');
    }
    const member = pair[1];
    let text = serializeKey(pair[0]);
    if (member && member.type === 'boolean' && member.value === true) {
      text += serializeParams(member.params);
    } else if (member && member.type === 'innerList') {
      text += '=' + serializeInnerList(member);
    } else {
      text += '=' + serializeItem(member);
    }
    return text;
  }).join(', ');
  log.debug("Leaving serializeDictionary().");
  return out;
}

// Section 4.1.3.
function serializeItem(item) {
  log.debug("Entering serializeItem().");
  if (!item || typeof item !== 'object') {
    fail('an Item to serialize must be an object with a type and a value.');
  }
  log.debug("Leaving serializeItem().");
  return serializeBareItem(item) + serializeParams(item.params);
}

// Section 4.1.3.1 and the six type serializers it dispatches to.
function serializeBareItem(item) {
  log.debug("Entering serializeBareItem().");
  if (!item || typeof item !== 'object') {
    log.debug("Leaving serializeBareItem(). Not an object.");
    fail('a bare Item to serialize must be an object with a type and a value.');
  }
  let out;
  switch (item.type) {
    case 'integer':
      out = serializeInteger(item.value);
      break;
    case 'decimal':
      out = serializeDecimal(item.value);
      break;
    case 'string':
      out = serializeString(item.value);
      break;
    case 'token':
      out = serializeToken(item.value);
      break;
    case 'bytes':
      out = serializeBytes(item.value);
      break;
    case 'boolean':
      out = serializeBoolean(item.value);
      break;
    default:
      log.debug("Leaving serializeBareItem(). Unknown type.");
      fail('"' + item.type + '" is not a bare Item type (section 4.1.3.1 ' +
                             'step 7).');
  }
  log.debug("Leaving serializeBareItem(). " + item.type);
  return out;
}

// Section 4.1.4.
function serializeInteger(value) {
  log.debug("Entering serializeInteger().");
  if (typeof value !== 'number' || !Number.isInteger(value) ||
      value < -999999999999999 || value > 999999999999999) {
    fail('an Integer must be a whole number of at most 15 digits; got ' +
         String(value) + ' (section 4.1.4 step 1).');
  }
  log.debug("Leaving serializeInteger().");
  return (value < 0 ? '-' : '') + String(Math.abs(value));
}

// Section 4.1.5. Rounded to three places, half to even, on the value scaled by
// a thousand. The half test is a tolerance rather than an equality because a
// double such as 0.0005 * 1000 is 0.49999999999999994 — a value whose author
// wrote exactly one half, and for whom "half to even" was the rule promised.
function serializeDecimal(value) {
  log.debug("Entering serializeDecimal().");
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    log.debug("Leaving serializeDecimal(). Not a number.");
    fail('a Decimal must be a finite number; got ' + String(value) +
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
    log.debug("Leaving serializeDecimal(). Too large.");
    fail('a Decimal has at most 12 digits before "."; got ' + String(value) +
         ' (section 4.1.5 step 3).');
  }
  let fractionText = '0';
  if (fraction !== 0) {
    fractionText = String(fraction).padStart(3, '0').replace(/0+$/, '');
  }
  const negative = value < 0 && thousandths !== 0;
  log.debug("Leaving serializeDecimal().");
  return (negative ? '-' : '') + String(integerPart) + '.' + fractionText;
}

// Section 4.1.6.
function serializeString(value) {
  log.debug("Entering serializeString().");
  if (typeof value !== 'string') {
    log.debug("Leaving serializeString(). Not a string.");
    fail('a String must be a string; got ' + typeof value + ' (section 4.1.6 ' +
        'step 1).');
  }
  let out = '"';
  for (let k = 0; k < value.length; k++) {
    const c = value[k];
    const code = value.charCodeAt(k);
    if (code <= 0x1f || code >= 0x7f) {
      log.debug("Leaving serializeString(). Not printable.");
      fail('a String may contain only printable ASCII; character 0x' +
           code.toString(16) + ' at offset ' + k + ' (section 4.1.6 step 2).');
    }
    out += (c === '\\' || c === '"') ? '\\' + c : c;
  }
  log.debug("Leaving serializeString().");
  return out + '"';
}

// Section 4.1.7.
function serializeToken(value) {
  log.debug("Entering serializeToken().");
  if (typeof value !== 'string' || value.length === 0 ||
      !(isAlpha(value[0]) || value[0] === '*')) {
    log.debug("Leaving serializeToken(). Bad first character.");
    fail('a Token must be a string beginning with a letter or "*"; got ' +
         JSON.stringify(value) + ' (section 4.1.7 step 2).');
  }
  for (let k = 1; k < value.length; k++) {
    const c = value[k];
    if (!(isTchar(c) || c === ':' || c === '/')) {
      log.debug("Leaving serializeToken(). Bad character.");
      fail('the Token ' + JSON.stringify(value) + ' contains "' + c +
           '", which a Token may not (section 4.1.7 step 2).');
    }
  }
  log.debug("Leaving serializeToken().");
  return value;
}

// Section 4.1.8. Padded, as the section requires; node's encoder pads.
function serializeBytes(value) {
  log.debug("Entering serializeBytes().");
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    fail('a Byte Sequence must be a Buffer (section 4.1.8 step 1).');
  }
  log.debug("Leaving serializeBytes().");
  return ':' + Buffer.from(value).toString('base64') + ':';
}

// Section 4.1.9.
function serializeBoolean(value) {
  log.debug("Entering serializeBoolean().");
  if (typeof value !== 'boolean') {
    fail('a Boolean must be true or false; got ' + JSON.stringify(value) +
         ' (section 4.1.9 step 1).');
  }
  log.debug("Leaving serializeBoolean().");
  return value ? '?1' : '?0';
}

// ---------------------------------------------------------------------------
// TWO SMALL READERS every caller wants and would otherwise write four times.
// `paramValue` answers the bare item's VALUE for a key, or undefined; `param`
// answers the bare item itself, for a caller that has to know the type.
// ---------------------------------------------------------------------------
function param(params, key) {
  log.debug("Entering param().");
  if (!Array.isArray(params)) {
    log.debug("Leaving param().");
    return undefined;
  }
  const at = indexOfKey(params, key);
  log.debug("Leaving param().");
  return at < 0 ? undefined : params[at][1];
}

function paramValue(params, key) {
  log.debug("Entering paramValue().");
  const bare = param(params, key);
  log.debug("Leaving paramValue().");
  return bare === undefined ? undefined : bare.value;
}

function member(dictionary, key) {
  log.debug("Entering member().");
  if (!Array.isArray(dictionary)) {
    log.debug("Leaving member().");
    return undefined;
  }
  const at = indexOfKey(dictionary, key);
  log.debug("Leaving member().");
  return at < 0 ? undefined : dictionary[at][1];
}

module.exports = {
  parseList: parseList,
  parseDictionary: parseDictionary,
  parseItem: parseItem,
  serializeList: serializeList,
  serializeDictionary: serializeDictionary,
  serializeItem: serializeItem,
  serializeInnerList: serializeInnerList,
  serializeParams: serializeParams,
  serializeBareItem: serializeBareItem,
  serializeKey: serializeKey,
  param: param,
  paramValue: paramValue,
  member: member
};
