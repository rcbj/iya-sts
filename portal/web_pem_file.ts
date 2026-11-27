// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_pem_file.ts
//
// ===========================================================================
// A PEM FILE CHOSEN FOR A TEXT BOX, READ AND CHECKED IN THE BROWSER (#2294).
//
// The portal's PIV enrolment (`web_tokens.ts`) takes three PEM texts: the
// certificate request and the two attestation certificates `ykman` writes.
// Each box gains a file chooser. The file is read in the browser, never
// uploaded as a file, and put in the box only when it is what the box
// takes:
//
//   * PEM armour, with exactly one block of the label the box takes
//     (`CERTIFICATE`, or `CERTIFICATE REQUEST` / `NEW CERTIFICATE REQUEST`);
//   * base64 holding nothing but the base64 alphabet, padded where needed;
//   * DER that is the structure that label names: a Certificate's
//     SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } with
//     the tbsCertificate's serial, issuer, validity, subject and key
//     (RFC 5280 section 4.1), or a CertificationRequest's SEQUENCE {
//     certificationRequestInfo, signatureAlgorithm, signature } with its
//     version 0, subject, key and attributes (RFC 2986 section 4). Every
//     length is read and must end exactly where its parent does.
//
// What goes in the box is the block alone, re-wrapped at 64 columns, so
// text around it in the file (`openssl -text` output, a bag attribute) is
// not sent. This is a check of SHAPE, made so a wrong file is named at once:
// the signature, the key and what the certificate says are the server's
// questions, and it asks them whatever the box holds (`cert_enrollment.ts`,
// `piv_attestation.ts`). A static utility class requiring nothing, so the
// portal's bundle carries it.
// ===========================================================================

type Json = any;

/** What a check found. */
interface PemCheck {
  ok: boolean;
  pem: string;
  why: string;
}

/** One DER element: its tag, where its value starts and ends. */
interface DerElement {
  tag: number;
  start: number;
  end: number;
}

class PemFile {
  /** The largest file read, in bytes: a certificate is a few kilobytes. */
  static readonly MAX_BYTES = 64 * 1024;

  /** The labels each kind of box takes. */
  static readonly LABELS: { [kind: string]: string[] } = {
    certificate: ['CERTIFICATE'],
    request: ['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST']
  };

  /**
   * Checks a file's text as the PEM a box of `kind` takes.
   *
   * @param text - the file's text
   * @param kind - `certificate` or `request`
   * @returns the block to put in the box, or why it is refused
   */
  static check(text: string, kind: string): PemCheck {
    const labels = PemFile.LABELS[kind] || [];
    const body = String(text || '');
    if (body.length > PemFile.MAX_BYTES) {
      return PemFile.refused('the file is larger than 64 KiB');
    }
    const blocks: { label: string; base64: string }[] = [];
    const pattern = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END ([A-Z0-9 ]+)-----/g;
    let found = pattern.exec(body);
    while (found) {
      if (found[1] !== found[3]) {
        return PemFile.refused('a BEGIN ' + found[1] + ' line ends with ' +
                               'END ' + found[3]);
      }
      blocks.push({ label: found[1], base64: found[2] });
      found = pattern.exec(body);
    }
    if (!blocks.length) {
      return PemFile.refused('it holds no PEM block (-----BEGIN ' +
                             labels[0] + '-----)');
    }
    const wanted = blocks.filter(function (one) {
      return labels.indexOf(one.label) >= 0;
    });
    if (!wanted.length) {
      return PemFile.refused('it holds ' + blocks.map(function (one) {
        return one.label;
      }).join(', ') + ', not ' + labels[0]);
    }
    if (blocks.length > 1) {
      return PemFile.refused('it holds ' + blocks.length + ' PEM blocks; ' +
                             'choose a file holding one ' + labels[0]);
    }
    const der = PemFile.base64Bytes(wanted[0].base64);
    if (!der) {
      return PemFile.refused('its base64 is not valid');
    }
    const problem = kind === 'request' ? PemFile.requestProblem(der)
                                       : PemFile.certificateProblem(der);
    if (problem) {
      return PemFile.refused(problem);
    }
    return { ok: true, why: '',
             pem: PemFile.pem(wanted[0].label, wanted[0].base64) };
  }

  /**
   * A refusal.
   *
   * @param why - the reason, in English
   * @returns the check's answer
   */
  static refused(why: string): PemCheck {
    return { ok: false, pem: '', why: why };
  }

  /**
   * The bytes base64 text holds, or null where it is not base64.
   *
   * @param text - the text between the armour lines
   * @returns the bytes, or null
   */
  static base64Bytes(text: string): Uint8Array | null {
    const compact = String(text).replace(/[\r\n\t ]/g, '');
    if (!compact || compact.length % 4 !== 0 ||
        !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) {
      return null;
    }
    let binary = '';
    try {
      binary = (globalThis as Json).atob(compact);
    } catch (e) {
      return null;
    }
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }

  /**
   * The block re-armoured at 64 columns.
   *
   * @param label - the block's label
   * @param base64 - its base64
   * @returns the PEM
   */
  static pem(label: string, base64: string): string {
    const compact = String(base64).replace(/[\r\n\t ]/g, '');
    const lines = compact.match(/.{1,64}/g) || [];
    return '-----BEGIN ' + label + '-----\n' + lines.join('\n') +
      '\n-----END ' + label + '-----\n';
  }

  /**
   * One DER element at `at`, or null where it does not fit in `limit`.
   *
   * @param der - the bytes
   * @param at - where the element starts
   * @param limit - where its parent ends
   * @returns the element
   */
  static element(der: Uint8Array, at: number,
                 limit: number): DerElement | null {
    if (at + 2 > limit) {
      return null;
    }
    const tag = der[at];
    if ((tag & 0x1f) === 0x1f) {
      return null;
    }
    let length = der[at + 1];
    let start = at + 2;
    if (length & 0x80) {
      const octets = length & 0x7f;
      if (octets < 1 || octets > 4 || start + octets > limit) {
        return null;
      }
      length = 0;
      for (let i = 0; i < octets; i++) {
        length = length * 256 + der[start + i];
      }
      start += octets;
      if (length < 128) {
        return null;
      }
    }
    if (start + length > limit) {
      return null;
    }
    return { tag: tag, start: start, end: start + length };
  }

  /**
   * The children of a constructed element, or null where they do not fill
   * it exactly.
   *
   * @param der - the bytes
   * @param parent - the element
   * @returns the children
   */
  static children(der: Uint8Array, parent: DerElement): DerElement[] | null {
    const out: DerElement[] = [];
    let at = parent.start;
    while (at < parent.end) {
      const one = PemFile.element(der, at, parent.end);
      if (!one) {
        return null;
      }
      out.push(one);
      at = one.end;
    }
    return at === parent.end ? out : null;
  }

  /**
   * The outer SEQUENCE of three a signed object is, or why it is not.
   *
   * @param der - the bytes
   * @param what - what it should be, for the reason
   * @returns its three parts, or a reason
   */
  static signed(der: Uint8Array, what: string): DerElement[] | string {
    const outer = PemFile.element(der, 0, der.length);
    if (!outer || outer.tag !== 0x30 || outer.end !== der.length) {
      return 'its contents are not a DER ' + what;
    }
    const parts = PemFile.children(der, outer);
    if (!parts || parts.length !== 3 || parts[0].tag !== 0x30 ||
        parts[1].tag !== 0x30 || parts[2].tag !== 0x03) {
      return 'its contents are not a signed ' + what;
    }
    return parts;
  }

  /**
   * Why DER is not an X.509 certificate, or '' where it is one in shape.
   *
   * @param der - the bytes
   * @returns the reason, or ''
   */
  static certificateProblem(der: Uint8Array): string {
    const parts = PemFile.signed(der, 'X.509 certificate');
    if (typeof parts === 'string') {
      return parts;
    }
    const tbs = PemFile.children(der, parts[0]);
    if (!tbs) {
      return 'its tbsCertificate is malformed';
    }
    const fields = tbs.length && tbs[0].tag === 0xa0 ? tbs.slice(1) : tbs;
    // serial, signature, issuer, validity, subject, subjectPublicKeyInfo.
    if (fields.length < 6 || fields[0].tag !== 0x02 ||
        fields[1].tag !== 0x30 || fields[2].tag !== 0x30 ||
        fields[3].tag !== 0x30 || fields[4].tag !== 0x30 ||
        fields[5].tag !== 0x30) {
      return 'it is not an X.509 certificate (RFC 5280 section 4.1)';
    }
    const validity = PemFile.children(der, fields[3]);
    if (!validity || validity.length !== 2 ||
        !validity.every(function (one) {
          return one.tag === 0x17 || one.tag === 0x18;
        })) {
      return 'its validity is not two times';
    }
    return '';
  }

  /**
   * Why DER is not a PKCS #10 request, or '' where it is one in shape.
   *
   * @param der - the bytes
   * @returns the reason, or ''
   */
  static requestProblem(der: Uint8Array): string {
    const parts = PemFile.signed(der, 'certificate request');
    if (typeof parts === 'string') {
      return parts;
    }
    const info = PemFile.children(der, parts[0]);
    // version, subject, subjectPKInfo, attributes [0].
    if (!info || info.length !== 4 || info[0].tag !== 0x02 ||
        info[0].end - info[0].start !== 1 || der[info[0].start] !== 0 ||
        info[1].tag !== 0x30 || info[2].tag !== 0x30 ||
        info[3].tag !== 0xa0) {
      return 'it is not a PKCS #10 certificate request (RFC 2986 ' +
        'section 4)';
    }
    return '';
  }

  /**
   * Wires every `input[data-pem-file]` in the document: a chosen file is
   * read, checked as its `data-pem-kind`, and put in the box its
   * `data-pem-file` names, or refused in the note `data-pem-note` names.
   *
   * @param doc - the document
   * @param t - the page's translator
   * @returns nothing
   */
  static wire(doc: Json, t: Json): void {
    const inputs = doc && doc.querySelectorAll
      ? doc.querySelectorAll('input[data-pem-file]') : [];
    for (let i = 0; i < inputs.length; i++) {
      const input = inputs[i];
      input.addEventListener('change', function (): void {
        PemFile.read(doc, input, t);
      });
    }
  }

  /**
   * Reads one chosen file into its box.
   *
   * @param doc - the document
   * @param input - the file input
   * @param t - the page's translator
   * @returns a promise that settles once the box or the note is written
   */
  static read(doc: Json, input: Json, t: Json): Promise<void> {
    const file = input && input.files && input.files[0];
    const box = doc.getElementById(String(input.getAttribute('data-pem-file')));
    const note = doc.getElementById(String(input.getAttribute('data-pem-note')));
    const kind = String(input.getAttribute('data-pem-kind') || 'certificate');
    const say = function (key: string, values: Json, bad: boolean): void {
      if (note) {
        note.textContent = t.text(key, values);
        note.className = bad ? 'note bad' : 'note';
      }
    };
    if (!file || !box) {
      return Promise.resolve();
    }
    const name = String(file.name || '');
    if (Number(file.size) > PemFile.MAX_BYTES) {
      say('portalTokens.piv.fileRefused',
          { name: name, why: 'the file is larger than 64 KiB' }, true);
      input.value = '';
      return Promise.resolve();
    }
    return Promise.resolve(file.text()).then(function (text: string) {
      const checked = PemFile.check(text, kind);
      if (checked.ok) {
        box.value = checked.pem;
        say('portalTokens.piv.fileRead', { name: name }, false);
      } else {
        say('portalTokens.piv.fileRefused',
            { name: name, why: checked.why }, true);
      }
      input.value = '';
    }, function (e: Json) {
      say('portalTokens.piv.fileRefused',
          { name: name, why: String((e && e.message) || e) }, true);
      input.value = '';
    });
  }
}

export = PemFile;
