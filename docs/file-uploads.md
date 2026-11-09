---
title: File uploads
nav_order: 15
---

# File uploads

This page lists every place iya-sts accepts a file: which types and extensions,
the largest size, and what happens to it.

## The uploads

| Upload | Who | Permitted type and extension | Largest size | What happens to the file |
|---|---|---|---|---|
| **Profile photo**, on the portal | The person | JPEG or PNG, decided by the bytes. The name is not used | `profilePhoto.maxFileBytes` (5 MiB) to choose; the browser crops it, and `profilePhoto.maxStoredBytes` (1 MiB, at most 3 MiB) is what the service keeps. Pixels: `profilePhoto.minPixels` (250) to `profilePhoto.maxPixels` (4096) | Its metadata is removed before it is kept. Served with `X-Content-Type-Options: nosniff` under a sandboxing policy |
| **Partner's profile photo** | A federation partner | JPEG or PNG, decided by the bytes | `profilePhoto.maxStoredBytes` | The same. Dropped if it is not an image |
| **Sign-in logo**, console or `POST /admin-api/branding/logo` | Admin Write | PNG, JPEG or WebP, decided by the bytes | `branding.logoMaxBytes` (256 KiB, at most 2 MiB). Sides from a fixed minimum to 2048 pixels | Stored as uploaded. Served with `nosniff` under a sandboxing policy |
| **Risk dataset** | Admin Write | The format chosen for the dataset; a format that fixes an extension must have it (optionally with `.gz` or `.zip`). gzip, and zip holding exactly one file, are detected from the bytes | `risk.uploadMaxBytes` (2 GiB) as sent. Expanded: `risk.expandedMaxBytes` (8 GiB) and `risk.expansionMaxRatio` (100) | Streamed to `risk.uploadDirectory`, read into the database as data, and deleted when the import ends |
| **Application LDIF import** | Admin Write | `.ldif`, `text/plain` or `text/x-ldif`. Exactly one application record | The 5 MB request body limit | Read as text and written as one application. A record carrying anything an import does not take is refused. The file is not kept |
| **RFC 9728 resource metadata** | Admin Write | `.json`, `application/json` | `federation.maxResponseBytes` | Read as JSON and used to fill in the application. The file is not kept |
| **SAML metadata for a service provider** | Admin Write | `.xml`, `application/samlmetadata+xml` | `saml2.spMetadataMaxBytes` (512 KiB) | Parsed with no document type or external entities, checked, and written onto the application's entry |
| **FIDO and Android datasets** | Scheduled jobs | The publisher's format, after signature or hash checks | `risk.mdsMaxBytes`, and each job's own cap | Stored as data |

An operator can also place a risk dataset in `risk.datasetsDirectory`, and run a
[bulk directory import](bulk-import.md) from the command line. Neither is an
upload.

## When a file is malicious

With [malware scanning](malware-scanning.md) on, profile photos, logos, partner
photos and uploaded risk datasets go to the antivirus service before they are
kept. A flagged file is refused and nothing is stored. A file the scanner cannot
answer for is refused too.

LDIF, RFC 9728 and SAML metadata files are not scanned. They are never served to
anybody. Each is parsed as data and either becomes configuration or is refused.

A risk dataset is read as rows and is never executed or served.

## How a file is made safe to download

Images are the only uploaded files the service serves to others. Each is served
with its checked type, `X-Content-Type-Options: nosniff`, and a sandboxing Content
Security Policy, so a browser cannot run one as a page.

Files the service generates for an administrator (exports, reports, the LDIF
export) are sent as named downloads.

## Related

* [Malware scanning](malware-scanning.md)
* [Sign-in appearance](sign-in-appearance.md)
* [Risk scoring](risk-scoring.md#uploading-a-file)
