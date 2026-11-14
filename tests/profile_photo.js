// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: profile_photo.js
//
// ---------------------------------------------------------------------------
// A PERSON'S PROFILE PHOTO (#719), `common/profile_photo.ts`, for what cannot
// be asked over HTTP from outside: what is inside the bytes it keeps, a
// partner's image host on a port this process owns, and the attribute and row
// directly. `tests/protocol/sts_profile_photo.js` asks the rest of a stack.
//
//   A. THE BYTES: a JPEG loses its EXIF and comment and whatever follows its
//      end, and keeps its image; a PNG loses its text chunks and whatever
//      follows IEND; an SVG, a WebP and garbage are refused.
//   B. THE CLAIM AND THE ASSERTION: `pictureUrl` names the hosted address, the
//      `picture` claim carries it, a SAML set releases it when a row asks, and
//      `stsProfilePhoto` is released by neither.
//   C. A PARTNER'S PHOTO: copied after the sign-in with the claim moved to the
//      copy, the partner's address not written back by a later sign-in, not
//      dialled again within the week, and left in place when the copy fails.
//   D. WHO WINS: the person's own photo outranks a partner's, removing a copy
//      stays removed, and setting one's own afterwards clears that.
//   E. THE SETTINGS: `selfService` and `cacheFederated` off.
//   F. THE ROW FOLLOWS THE PERSON: a disabled account's address answers
//      nothing until it is enabled, and a deleted person's row is gone.
//   G. PRODUCT MODE: no pinned base, no address.
//
// A child process for `admin_api_me.js`'s reason: the stack is built once.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'profile_photo',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// A PNG chunk. The checksum is not checked by what is under test, and a real
// one would only add lines: nothing here decodes the image.
function chunk(name, data) {
  log.debug('Entering chunk(). ' + name);
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(name, 4, 'latin1');
  log.debug('Leaving chunk().');
  return Buffer.concat([head, data, Buffer.alloc(4)]);
}

function png(width, height, extra) {
  log.debug('Entering png().');
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  log.debug('Leaving png().');
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), extra || Buffer.alloc(0),
    chunk('IDAT', Buffer.from('the-image')), chunk('IEND', Buffer.alloc(0))]);
}

function jpegSegment(marker, data) {
  log.debug('Entering jpegSegment().');
  const head = Buffer.from([0xff, marker, 0, 0]);
  head.writeUInt16BE(data.length + 2, 2);
  log.debug('Leaving jpegSegment().');
  return Buffer.concat([head, data]);
}

function jpeg(width, height, segments) {
  log.debug('Entering jpeg().');
  const sof = Buffer.alloc(15);
  sof[0] = 8;
  sof.writeUInt16BE(height, 1);
  sof.writeUInt16BE(width, 3);
  log.debug('Leaving jpeg().');
  return Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    jpegSegment(0xe0, Buffer.from('JFIF\0')),
    segments || Buffer.alloc(0),
    jpegSegment(0xc0, sof),
    jpegSegment(0xda, Buffer.from([1, 1, 0, 0, 63, 0])),
    Buffer.from('the-scan'), Buffer.from([0xff, 0xd9])]);
}

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.PP_ROOT;
  const OUT = process.env.PP_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const http = require('http');
    const config = require(ROOT_DIR + '/common/config');
    const mode = require(ROOT_DIR + '/common/mode');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const claims = require(ROOT_DIR + '/common/claim_attributes');
    const stats = require(ROOT_DIR + '/common/admin_stats');
    const actions = require(ROOT_DIR + '/admin-core/admin_actions');
    const accountState = require(ROOT_DIR + '/common/account_state');
    const photo = require(ROOT_DIR + '/common/profile_photo');
    const sourced = require(ROOT_DIR + '/common/sourced_attributes');

    const stamp = String(process.pid);
    const req = { headers: { host: 'sts.example' }, protocol: 'https',
                  socket: {} };
    const person = function (name) {
      const who = 'pp-' + name + '-' + stamp;
      ldap.createUser(who, { invent: false });
      return who;
    };
    const attribute = function (who, name) {
      const entry = ldap.existingUserEntry(who);
      return ((entry && entry.attributes[name]) || [])[0];
    };
    const claim = function (who) {
      return ((claims.requestedClaimsFor(who, ['picture']) || {}).claims ||
              {}).picture;
    };
    const ridOf = function (path) {
      return String(path || '').split('/').pop();
    };

    // --- A. the bytes -------------------------------------------------------
    const secret = Buffer.from('GPS-52.3676N-4.9041E');
    const dirty = Buffer.concat([
      jpeg(300, 300, Buffer.concat([jpegSegment(0xe1, secret),
                                    jpegSegment(0xfe, secret)])),
      secret]);
    const cleaned = photo.checked(dirty, 250);
    note(cleaned.ok && cleaned.type === 'image/jpeg' && cleaned.width === 300,
         'A1. a JPEG is kept, its type and sides read from its bytes',
         JSON.stringify(cleaned));
    note(cleaned.ok && cleaned.bytes.indexOf(secret) < 0,
         'A2. its EXIF, its comment and what follows its end are gone');
    note(cleaned.ok && cleaned.bytes.indexOf(Buffer.from('the-scan')) > 0 &&
         cleaned.bytes.indexOf(Buffer.from('JFIF')) > 0,
         'A3. its image and its JFIF header are not');
    const dirtyPng = Buffer.concat([
      png(300, 300, Buffer.concat([chunk('tEXt', secret),
                                   chunk('eXIf', secret)])), secret]);
    const cleanedPng = photo.checked(dirtyPng, 250);
    note(cleanedPng.ok && cleanedPng.bytes.indexOf(secret) < 0 &&
         cleanedPng.bytes.indexOf(Buffer.from('the-image')) > 0,
         'A4. a PNG loses its text, its EXIF and what follows IEND, and ' +
         'keeps its image');
    const svg = photo.checked(Buffer.from(
      '<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>'), 16);
    note(!svg.ok && svg.code === 'STS-PORTAL-0630', 'A5. an SVG is refused',
         svg.code);
    const webp = Buffer.alloc(40);
    webp.write('RIFF', 0, 'latin1');
    webp.write('WEBP', 8, 'latin1');
    webp.write('VP8X', 12, 'latin1');
    webp.writeUIntLE(299, 24, 3);
    webp.writeUIntLE(299, 27, 3);
    note(photo.checked(webp, 16).code === 'STS-PORTAL-0630',
         'A6. so is a WebP, which there is no writer to clean');
    note(photo.checked(Buffer.concat([png(300, 300).slice(0, 40)]), 16).code ===
         'STS-PORTAL-0630', 'A7. and a PNG that stops before IEND');
    note(photo.checked(png(100, 300), 250).code === 'STS-PORTAL-0632' &&
         photo.checked(png(5000, 300), 250).code === 'STS-PORTAL-0632',
         'A8. a side too short or too long is refused');
    note(photo.checked(Buffer.alloc(2 * 1048576), 16).code ===
         'STS-PORTAL-0631', 'A9. and so is more than the realm keeps');

    // --- B. the claim and the assertion --------------------------------------
    const ann = person('ann');
    const set = photo.setOwn(req, ann, png(300, 300));
    const annPath = set.path;
    const annUrl = attribute(ann, 'pictureurl');
    note(set.ok && /\/web\/photo\/[A-Za-z0-9_-]{22}/.test(annUrl),
         'B1. a photo set puts a random hosted address on pictureUrl',
         JSON.stringify(set) + ' ' + annUrl);
    note(annUrl.indexOf(ann) < 0, 'B2. and the address does not name them');
    note(claim(ann) === annUrl, 'B3. the picture claim carries it',
         claim(ann));
    note(sourced.releaseRefusal('pictureUrl') === '' &&
         sourced.releaseRefusal('stsProfilePhoto') !== '' &&
         sourced.refusal('stsProfilePhoto') !== '',
         'B4. a claim may release pictureUrl and never the record, and no ' +
         'outside source may write the record');
    const added = actions.claimsAction({ action: 'add-attribute-claim',
      set: 'saml2', name: 'photo', attribute: 'pictureUrl' }, [],
    stats.SAML_CLAIM_SET_IDS);
    const saml = stats.samlAttributes('saml2', { subject: ann });
    const released = saml.filter(function (a) { return a.name === 'photo'; })[0];
    note(added.ok && released && (released.values || [])[0] === annUrl,
         'B5. a SAML set releases it as a custom attribute when a row asks',
         JSON.stringify(released));

    // --- C. a partner's photo -----------------------------------------------
    let dials = 0;
    let answer = jpeg(96, 96);
    const host = http.createServer(function (q, s) {
      dials += 1;
      s.statusCode = q.url === '/missing' ? 404 : 200;
      s.end(answer);
    });
    await new Promise(function (r) { host.listen(0, '127.0.0.1', r); });
    config.setOverride('federation.outboundAllowHttp', true);
    const partner = 'http://127.0.0.1:' + host.address().port;
    const signIn = async function (who, source) {
      ldap.autoCreateUser({ key: who, federation: {
        id: 'pp-partner', peer: 'https://partner.example', create: true,
        updateAttributes: true, attributes: { pictureUrl: [source] } } });
      return photo.noteFederated(req, who, source, 'pp-partner');
    };
    const bob = person('bob');
    const copied = await signIn(bob, partner + '/bob.jpg');
    const bobUrl = attribute(bob, 'pictureurl');
    note(copied.copied && bobUrl.indexOf('/web/photo/') > 0,
         'C1. a partner\'s photo smaller than a person\'s minimum is copied, ' +
         'and the claim names the copy', JSON.stringify(copied) + ' ' + bobUrl);
    note(photo.viewFor(bob).origin === 'federation',
         'C2. and the portal is told whose it was');
    const again = await signIn(bob, partner + '/bob.jpg');
    note(dials === 1 && !again.copied,
         'C3. the same address is not dialled again within the week',
         dials + ' ' + JSON.stringify(again));
    note(attribute(bob, 'pictureurl') === bobUrl,
         'C4. and the sign-in did not put the partner\'s address back',
         attribute(bob, 'pictureurl'));
    const carol = person('carol');
    const failed = await signIn(carol, partner + '/missing');
    note(!failed.copied && attribute(carol, 'pictureurl') ===
         partner + '/missing',
         'C5. where the copy fails the partner\'s address stays on the claim',
         JSON.stringify(failed));
    answer = Buffer.from('<svg></svg>');
    const dan = person('dan');
    const notImage = await signIn(dan, partner + '/dan.svg');
    note(notImage.why === 'STS-PORTAL-0630',
         'C6. and a partner\'s answer that is not an image is not kept',
         JSON.stringify(notImage));
    answer = jpeg(96, 96);

    // --- D. who wins --------------------------------------------------------
    const erin = person('erin');
    photo.setOwn(req, erin, png(300, 300));
    const erinUrl = attribute(erin, 'pictureurl');
    const before = dials;
    const overruled = await signIn(erin, partner + '/erin.jpg');
    note(!overruled.copied && dials === before &&
         attribute(erin, 'pictureurl') === erinUrl,
         'D1. a person\'s own photo outranks a partner\'s, with no dial',
         JSON.stringify(overruled));
    const copiedPath = photo.pathFor(bob);
    photo.removeOwn(bob);
    note(!attribute(bob, 'pictureurl') && !photo.pathFor(bob) &&
         !photo.servable(ridOf(copiedPath)),
         'D2. removing a copy removes the image and the claim\'s address');
    const after = await signIn(bob, partner + '/bob.jpg');
    note(!after.copied && !attribute(bob, 'pictureurl'),
         'D3. and the next sign-in does not bring it back',
         JSON.stringify(after) + ' ' + attribute(bob, 'pictureurl'));
    const own = photo.setOwn(req, bob, png(300, 300));
    note(own.ok && attribute(bob, 'stsprofilephoto').indexOf('declined') < 0,
         'D4. setting one of their own clears that');
    const firstRid = ridOf(photo.pathFor(bob));
    photo.setOwn(req, bob, png(320, 320));
    note(!photo.servable(firstRid) && ridOf(photo.pathFor(bob)) !== firstRid,
         'D5. a new photo is a new address, and the old one answers nothing');

    // --- E. the settings ----------------------------------------------------
    config.setOverride('profilePhoto.selfService', false);
    const off = photo.setOwn(req, person('fay'), png(300, 300));
    note(off.code === 'STS-PORTAL-0634', 'E1. selfService off refuses',
         off.code);
    config.setOverride('profilePhoto.selfService', true);
    config.setOverride('profilePhoto.cacheFederated', false);
    const dialsBefore = dials;
    const notCopied = await signIn(person('gus'), partner + '/gus.jpg');
    note(!notCopied.copied && dials === dialsBefore,
         'E2. cacheFederated off dials nothing');
    config.setOverride('profilePhoto.cacheFederated', true);

    // --- F. the row follows the person --------------------------------------
    const rid = ridOf(annPath);
    note(!!photo.servable(rid), 'F1. an active person\'s address answers');
    accountState.setDisabled(ann, true, { actor: 'test' });
    note(!photo.servable(rid), 'F2. a disabled person\'s answers nothing');
    accountState.setDisabled(ann, false, { actor: 'test' });
    note(!!photo.servable(rid), 'F3. and enabling them restores it');
    const entry = ldap.existingUserEntry(ann);
    photo.forgetEntry(entry.attributes.stsprofilephoto);
    note(!photo.servable(rid), 'F4. a deleted person\'s row is gone');

    // --- G. product mode ----------------------------------------------------
    const wasProduct = mode.mintsPhotoAddressesOnRequestAddress;
    mode.mintsPhotoAddressesOnRequestAddress = function () { return false; };
    const pinned = photo.setOwn(req, person('hal'), png(300, 300));
    mode.mintsPhotoAddressesOnRequestAddress = wasProduct;
    note(pinned.code === 'STS-PORTAL-0635',
         'G1. with no pinned base and no leave to use the request\'s, a photo ' +
         'is refused', pinned.code);

    host.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  }()).catch(function (e) {
    fs.writeFileSync(OUT, JSON.stringify(findings.concat([{
      ok: false, what: 'the child died', detail: String((e && e.stack) || e)
    }])));
    process.exit(1);
  });
}

async function run(t) {
  log.debug('Entering run().');
  const out = path.join(os.tmpdir(), 'pp-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                PP_CHILD: '1', PP_ROOT: ROOT, PP_OUT: out }),
    encoding: 'utf8', timeout: 300000, cwd: ROOT
  });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug('Caught in run(): ' + ((e && e.message) || e));
    findings = null;
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug('Leaving run().');
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug('Leaving run().');
}

// The file is its own child, because the helpers above are shared with it.
if (process.env.PP_CHILD && require.main === module) {
  childMain();
}

module.exports = {
  name: 'profile_photo',
  describe: 'a person\'s profile photo: the bytes kept, the claim, a ' +
            'partner\'s copy, who outranks whom, and the row following the ' +
            'person (#719)',
  run: run
};
