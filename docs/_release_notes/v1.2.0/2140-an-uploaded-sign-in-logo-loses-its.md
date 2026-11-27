---
title: "an uploaded sign-in logo loses its metadata"
kind: behaviour-change
issue: 2140
---

A realm's sign-in logo is shown to everybody who opens a sign-in page, so
it is now cleaned before it is kept, as profile photos already were: a
JPEG's EXIF (a GPS position, a camera, a date), XMP and comments, a PNG's
text chunks and animation frames, a WebP's EXIF and XMP chunks, and
anything after the end of the image are removed (ASVS 5.0.0 14.2.8). The
pixels are not changed. The digest, size and sides the console and `GET
/admin-api/branding` show describe the cleaned file. A file that cannot be
read to the end of its image is refused with `STS-AUTHN-0624`.

Profile photos use the same code, and two things changed for them: a JPEG
now ends at its first end-of-image marker, so a second image a phone
appends after it (a Multi-Picture Format depth or gain map, which carries
its own EXIF) is no longer kept, and an APP2 segment is kept only when it
is an ICC colour profile.

**Upgrading.** Nothing to run. A logo uploaded before 1.2.0 is served as it
was stored, metadata included, until it is uploaded again; upload it again
to clean it. See [Sign-in appearance](sign-in-appearance.md#the-logo).
