// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_photo.ts
//
// ---------------------------------------------------------------------------
// CHOOSING A PROFILE PHOTO IN THE BROWSER (#719), on the Overview's card.
//
// A chosen file is checked, read, cropped to a centred square, scaled down and
// encoded again as a JPEG on a canvas, and what comes out is both the preview
// and what Save sends. So a person saves exactly what they looked at, a phone's
// 5 MB photograph arrives as a small one, and its metadata never leaves the
// browser. The server judges the bytes again (`common/profile_photo.ts`): this
// is for the person, and it is not what enforces anything.
//
// **EVERYTHING GOES THROUGH `data:` URLS**, because the portal's `img-src` is
// `'self' data:` and a `blob:` URL would need the policy widened. A transparent
// PNG is painted on white first, because JPEG has no transparency and would
// otherwise turn it black.
//
// Requires nothing but the portal kit's kind of thing: this runs in a browser
// (root CLAUDE.md, *One static runtime per surface*).
// ---------------------------------------------------------------------------

type Json = any;

// The sides of what is sent: a menu draws it small, and a relying party has
// no use for more.
const LARGEST_SIDE = 720;

// Tried in order until the result fits what the realm keeps.
const QUALITIES = [0.9, 0.8, 0.65, 0.5];

/**
 * The photo card's behaviour. A static utility class.
 */
class PhotoPicker {
  /**
   * Draws an image's centred square onto a canvas of at most `LARGEST_SIDE`.
   *
   * @param doc - the document
   * @param image - the loaded image
   * @returns the canvas
   */
  static squared(doc: Json, image: Json): Json {
    const shorter = Math.min(image.naturalWidth, image.naturalHeight);
    const side = Math.min(shorter, LARGEST_SIDE);
    const canvas = doc.createElement('canvas');
    canvas.width = side;
    canvas.height = side;
    const paint = canvas.getContext('2d');
    paint.fillStyle = '#ffffff';
    paint.fillRect(0, 0, side, side);
    paint.drawImage(image, (image.naturalWidth - shorter) / 2,
                    (image.naturalHeight - shorter) / 2, shorter, shorter,
                    0, 0, side, side);
    return canvas;
  }

  /**
   * Encodes a canvas as the largest quality the realm will keep.
   *
   * @param canvas - the canvas
   * @param maxBytes - what the realm keeps
   * @returns the `data:` URL, or '' when none fits
   */
  static encoded(canvas: Json, maxBytes: number): string {
    for (let i = 0; i < QUALITIES.length; i += 1) {
      const url = String(canvas.toDataURL('image/jpeg', QUALITIES[i]));
      const base64 = url.slice(url.indexOf(',') + 1);
      if (Math.floor(base64.length * 3 / 4) <= maxBytes) {
        return url;
      }
    }
    return '';
  }

  /**
   * Wires the photo card, where the page carries one.
   *
   * @param doc - the document
   * @param win - the window, for `FileReader` and `Image`
   * @param t - the translator
   */
  static wire(doc: Json, win: Json, t: Json): void {
    const input = doc && doc.getElementById
      ? doc.getElementById('portal-photo-file') : null;
    if (!input) {
      return;
    }
    const problem = doc.getElementById('portal-photo-problem');
    const preview = doc.getElementById('portal-photo-preview');
    const shown = doc.getElementById('portal-photo-new');
    const field = doc.getElementById('portal-photo-image');
    const save = doc.getElementById('portal-photo-save');
    const reset = function (message: string): void {
      problem.textContent = message;
      problem.hidden = !message;
      preview.hidden = true;
      field.value = '';
      save.disabled = true;
    };
    input.addEventListener('change', function (): void {
      const file = input.files && input.files[0];
      reset('');
      if (!file) {
        return;
      }
      const maxFile = Number(input.getAttribute('data-max-file'));
      const maxStored = Number(input.getAttribute('data-max-stored'));
      const minPixels = Number(input.getAttribute('data-min-pixels'));
      if (file.type !== 'image/jpeg' && file.type !== 'image/png') {
        reset(t.text('portal.photo.errType'));
        return;
      }
      if (file.size > maxFile) {
        reset(t.text('portal.photo.errBig',
                     { max: Math.floor(maxFile / 1048576) }));
        return;
      }
      const reader = new win.FileReader();
      reader.onerror = function (): void {
        reset(t.text('portal.photo.errRead'));
      };
      reader.onload = function (): void {
        const image = new win.Image();
        image.onerror = function (): void {
          reset(t.text('portal.photo.errRead'));
        };
        image.onload = function (): void {
          if (Math.min(image.naturalWidth, image.naturalHeight) < minPixels) {
            reset(t.text('portal.photo.errSmall', {
              width: image.naturalWidth, height: image.naturalHeight,
              min: minPixels }));
            return;
          }
          const url = PhotoPicker.encoded(PhotoPicker.squared(doc, image),
                                          maxStored);
          if (!url) {
            reset(t.text('portal.photo.errRead'));
            return;
          }
          shown.src = url;
          field.value = url.slice(url.indexOf(',') + 1);
          preview.hidden = false;
          save.disabled = false;
        };
        image.src = String(reader.result);
      };
      reader.readAsDataURL(file);
    });
  }
}

export = PhotoPicker;
