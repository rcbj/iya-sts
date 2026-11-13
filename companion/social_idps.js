#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: companion/social_idps.js
//
// ===========================================================================
// DUMMY SOCIAL IDENTITY PROVIDERS (#1689).
//
// The catalogue in federation/consumer_providers.ts names 39 social
// providers, plus two generic profiles that are not providers. A live
// sign-in needs an application and an account at each, and none is kept.
// This module is a dummy of each named one, served by the development
// companion at /social/{id}, speaking the flow that profile asks for: the
// code grant (basic, body, TikTok's client_key, or Apple's signed secret),
// Steam's OpenID 2.0 check, DiscourseConnect, and Bluesky's DPoP push.
//
// It is a dummy. It signs one fixed person in, checks the client
// authentication and PKCE the profile requires, and refuses a wrong
// secret. It is not that provider, and it does not dial one.
//
// THE SERVICE POSTS HERE, NOT A BROWSER. The token request, Steam's
// check_authentication and Bluesky's pushed authorization request carry
// no session cookie, so companion.js dispatches /social before its CSRF
// check. companion/CLAUDE.md argues that exemption. This module reads
// those bodies itself.
//
// An OAuth redirect is a 302. companion_util.redirect() is 303, which is
// the companion's own form-then-GET, so the redirects here are written
// with sendFound().
//
// No timer. The code, token, push and Steam-nonce maps are capped on
// insert. Nothing is swept.
// ===========================================================================

const crypto = require("crypto");
const zlib = require("zlib");
const util = require("./companion_util.js");

const log = util.logger("iya-sts-companion-social");

const SECRET = "companion-secret";
const TEAM_ID = "COMPANION1";
const APPLE_KEY_ID = "COMPKEY001";
const APPLE_CLIENT = "companion-apple";
const APPLE_AUD = "https://appleid.apple.com";
const MS_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";
const MS_ISS = "https://login.microsoftonline.com/" + MS_TENANT + "/v2.0";
const STEAM_ID = "76561198000000001";
const STEAM_CLAIMED = "https://steamcommunity.com/openid/id/" + STEAM_ID;
const OPENID2_NS = "http://specs.openid.net/auth/2.0";
const BLUESKY_DID = "did:plc:abcdefghijklmnopqrstuvwx";
const DPOP_NONCE = "companion-dpop-nonce";
const MAP_CAP = 2000;
const PICTURE = "https://example.com/a.png";

/**
 * One catalogue row, with the defaults a code-flow provider shares.
 *
 * @param {object} spec - what differs
 * @returns {object} the row
 */
function provider(spec) {
  log.debug("Entering provider().");
  const out = {
    id: spec.id,
    label: spec.label,
    protocol: spec.protocol,
    auth: spec.auth,
    kind: spec.kind || "code",
    alg: spec.alg || "RS256",
    userinfo: spec.userinfo || "none",
    emails: spec.emails || "",
    query: spec.query || "",
    peer: spec.peer || "set",
    subject: spec.subject,
    idClaims: spec.idClaims || null,
    profile: spec.profile || null,
    emailsBody: spec.emailsBody || null,
    tokenExtra: spec.tokenExtra || null,
    formUser: spec.formUser || null,
    expect: spec.expect || {},
    notes: spec.notes || []
  };
  log.debug("Leaving provider().");
  return out;
}

/**
 * An address this dummy says it verified.
 *
 * @param {string} id - the provider id
 * @returns {string} the address
 */
function adaMail(id) {
  log.debug("Entering adaMail().");
  log.debug("Leaving adaMail().");
  return "ada." + id + "@example.com";
}

// The 39 named profiles, in catalogue order. The two generics are absent
// on purpose: they are not providers. tests/social_idp_signins.js fails
// when this list and ConsumerProviders.ids() disagree.
const ROWS = [
  provider({
    id: "google", label: "Google", protocol: "oidc", auth: "basic",
    userinfo: "none", subject: "google-ada",
    idClaims: {
      email: adaMail("google"), email_verified: true,
      name: "Ada Google", given_name: "Ada", family_name: "Byron"
    },
    expect: {
      cn: "Ada Google", givenName: "Ada", sn: "Byron",
      mail: adaMail("google"), verified: true
    }
  }),
  provider({
    id: "discord", label: "Discord", protocol: "oauth2", auth: "basic",
    userinfo: "body", subject: "discord-ada",
    profile: {
      id: "discord-ada", username: "adadiscord",
      global_name: "Ada Discord", email: adaMail("discord"),
      verified: true
    },
    expect: {
      cn: "Ada Discord", mail: adaMail("discord"), verified: true
    }
  }),
  provider({
    id: "github", label: "GitHub", protocol: "oauth2", auth: "post",
    userinfo: "body", emails: "github", subject: "910000001",
    profile: {
      id: 910000001, login: "ada-github", name: "Ada GitHub",
      email: "public-ada@example.com", avatar_url: PICTURE,
      html_url: "https://github.com/ada-github"
    },
    emailsBody: [
      { email: "other.github@example.com", primary: false, verified: true },
      { email: adaMail("github"), primary: true, verified: true }
    ],
    expect: { cn: "Ada GitHub", mail: adaMail("github"), verified: true }
  }),
  provider({
    id: "microsoft", label: "Microsoft (personal accounts)",
    protocol: "oidc", auth: "post", userinfo: "none",
    subject: "ms-ada-personal",
    idClaims: {
      email: adaMail("microsoft"), name: "Ada Microsoft",
      preferred_username: "ada.microsoft"
    },
    expect: {
      cn: "Ada Microsoft", mail: adaMail("microsoft"), verified: false
    }
  }),
  provider({
    id: "microsoft-any", label: "Microsoft (allowed tenants)",
    protocol: "oidc", auth: "post", userinfo: "none", peer: "keep",
    subject: "ms-ada-any",
    idClaims: {
      email: adaMail("microsoft-any"), name: "Ada Microsoft Any",
      preferred_username: "ada.microsoft.any"
    },
    expect: {
      cn: "Ada Microsoft Any", mail: adaMail("microsoft-any"),
      verified: false
    },
    notes: [
      "Leave fedPeer as the profile wrote it. This dummy signs the " +
      "personal-account tenant's issuer and puts that tenant in tid."
    ]
  }),
  provider({
    id: "linkedin", label: "LinkedIn", protocol: "oidc", auth: "post",
    userinfo: "sub", subject: "linkedin-ada",
    idClaims: {
      email: adaMail("linkedin"), email_verified: true,
      name: "Ada LinkedIn", given_name: "Ada", family_name: "Byron"
    },
    expect: {
      cn: "Ada LinkedIn", givenName: "Ada", sn: "Byron",
      mail: adaMail("linkedin"), verified: true
    }
  }),
  provider({
    id: "yahoo", label: "Yahoo", protocol: "oidc", auth: "basic",
    userinfo: "sub", subject: "yahoo-ada",
    idClaims: {
      email: adaMail("yahoo"), email_verified: true, name: "Ada Yahoo",
      given_name: "Ada", family_name: "Byron"
    },
    expect: {
      cn: "Ada Yahoo", givenName: "Ada", sn: "Byron",
      mail: adaMail("yahoo"), verified: true
    }
  }),
  provider({
    id: "slack", label: "Slack", protocol: "oidc", auth: "post",
    userinfo: "sub", subject: "slack-ada",
    idClaims: {
      email: adaMail("slack"), email_verified: true, name: "Ada Slack",
      given_name: "Ada", family_name: "Byron"
    },
    expect: {
      cn: "Ada Slack", givenName: "Ada", sn: "Byron",
      mail: adaMail("slack"), verified: true
    }
  }),
  provider({
    id: "twitch", label: "Twitch", protocol: "oidc", auth: "post",
    userinfo: "sub", subject: "twitch-ada",
    idClaims: {
      email: adaMail("twitch"), email_verified: true,
      preferred_username: "adatwitch", picture: PICTURE
    },
    expect: { mail: adaMail("twitch"), verified: true }
  }),
  provider({
    id: "salesforce", label: "Salesforce", protocol: "oidc", auth: "post",
    userinfo: "sub",
    subject: "https://login.salesforce.com/id/" +
             "00D000000000001EAA/005000000000001AAA",
    idClaims: {
      email: adaMail("salesforce"), email_verified: true,
      name: "Ada Salesforce", given_name: "Ada", family_name: "Byron",
      preferred_username: "ada.salesforce"
    },
    expect: {
      cn: "Ada Salesforce", givenName: "Ada", sn: "Byron",
      mail: adaMail("salesforce"), verified: true
    }
  }),
  provider({
    id: "facebook", label: "Facebook", protocol: "oauth2", auth: "post",
    userinfo: "body", subject: "facebook-ada",
    profile: {
      id: "facebook-ada", email: adaMail("facebook"),
      name: "Ada Facebook", first_name: "Ada", last_name: "Byron"
    },
    expect: {
      cn: "Ada Facebook", givenName: "Ada", sn: "Byron",
      mail: adaMail("facebook"), verified: false
    }
  }),
  provider({
    id: "amazon", label: "Amazon", protocol: "oauth2", auth: "post",
    userinfo: "body", subject: "amazon-ada",
    profile: {
      user_id: "amazon-ada", email: adaMail("amazon"), name: "Ada Amazon"
    },
    expect: {
      cn: "Ada Amazon", mail: adaMail("amazon"), verified: false
    }
  }),
  provider({
    id: "spotify", label: "Spotify", protocol: "oauth2", auth: "basic",
    userinfo: "body", subject: "spotify-ada",
    profile: {
      id: "spotify-ada", email: adaMail("spotify"),
      display_name: "Ada Spotify"
    },
    expect: {
      cn: "Ada Spotify", mail: adaMail("spotify"), verified: false
    }
  }),
  provider({
    id: "x", label: "X", protocol: "oauth2", auth: "basic",
    userinfo: "body", subject: "2244994945",
    profile: {
      data: { id: "2244994945", username: "ada_x", name: "Ada X" }
    },
    expect: { cn: "Ada X" }
  }),
  provider({
    id: "tiktok", label: "TikTok", protocol: "oauth2", auth: "tiktok",
    userinfo: "body", subject: "tiktok-open-ada",
    tokenExtra: { open_id: "tiktok-open-ada" },
    profile: {
      data: { user: { display_name: "Ada TikTok", avatar_url: PICTURE } }
    },
    expect: { cn: "Ada TikTok" }
  }),
  provider({
    id: "apple", label: "Apple", protocol: "oidc", auth: "apple",
    kind: "apple", alg: "ES256", userinfo: "none",
    subject: "001234.abcdef0123456789.0421",
    idClaims: {
      email: adaMail("apple"), email_verified: "true"
    },
    formUser: {
      name: { firstName: "Ada", lastName: "Byron" },
      email: adaMail("apple")
    },
    expect: {
      givenName: "Ada", sn: "Byron", mail: adaMail("apple"),
      verified: true
    },
    notes: [
      "The signing key below is a dummy this companion generated. Paste " +
      "it into fedClientSigningKey. It is not an Apple key."
    ]
  }),
  provider({
    id: "gitlab", label: "GitLab.com", protocol: "oidc", auth: "basic",
    userinfo: "body", subject: "gitlab-ada",
    profile: {
      name: "Ada GitLab", preferred_username: "adagitlab",
      email: adaMail("gitlab"), email_verified: true
    },
    expect: { cn: "Ada GitLab", mail: adaMail("gitlab"), verified: true }
  }),
  provider({
    id: "gitlab-self-managed", label: "GitLab (self-managed)",
    protocol: "oidc", auth: "basic", userinfo: "body",
    subject: "gitlab-self-ada",
    profile: {
      name: "Ada GitLab Self", preferred_username: "adagitlabself",
      email: adaMail("gitlab-self-managed"), email_verified: true
    },
    expect: {
      cn: "Ada GitLab Self", mail: adaMail("gitlab-self-managed"),
      verified: true
    }
  }),
  provider({
    id: "bitbucket", label: "Bitbucket", protocol: "oauth2",
    auth: "basic", userinfo: "body", emails: "bitbucket",
    subject: "ada-bitbucket-uuid",
    profile: {
      uuid: "ada-bitbucket-uuid", display_name: "Ada Bitbucket",
      nickname: "adabb",
      links: { avatar: { href: PICTURE } }
    },
    emailsBody: {
      values: [
        {
          email: "other.bitbucket@example.com",
          is_primary: false, is_confirmed: true
        },
        {
          email: adaMail("bitbucket"),
          is_primary: true, is_confirmed: true
        }
      ]
    },
    expect: {
      cn: "Ada Bitbucket", mail: adaMail("bitbucket"), verified: true
    }
  }),
  provider({
    id: "patreon", label: "Patreon", protocol: "oauth2", auth: "post",
    userinfo: "body", subject: "patreon-ada",
    profile: {
      data: {
        id: "patreon-ada",
        attributes: {
          full_name: "Ada Patreon", first_name: "Ada", last_name: "Byron",
          vanity: "adapatreon", image_url: PICTURE,
          url: "https://www.patreon.com/adapatreon",
          email: adaMail("patreon"), is_email_verified: true
        }
      }
    },
    expect: {
      cn: "Ada Patreon", givenName: "Ada", sn: "Byron",
      mail: adaMail("patreon"), verified: true
    }
  }),
  provider({
    id: "roblox", label: "Roblox", protocol: "oidc", auth: "basic",
    alg: "ES256", userinfo: "none", subject: "roblox-ada",
    idClaims: {
      name: "Ada Roblox", nickname: "adaroblox",
      preferred_username: "adaroblox", picture: PICTURE,
      profile: "https://www.roblox.com/users/ada/profile"
    },
    expect: { cn: "Ada Roblox" }
  }),
  provider({
    id: "battlenet", label: "Battle.net", protocol: "oidc", auth: "basic",
    userinfo: "body", subject: "battlenet-ada",
    profile: { battletag: "Ada-0001" },
    expect: {}
  }),
  provider({
    id: "epic", label: "Epic Games", protocol: "oidc", auth: "basic",
    userinfo: "body", subject: "epic-ada",
    profile: { preferred_username: "adaepic" },
    expect: {}
  }),
  provider({
    id: "paypal", label: "PayPal", protocol: "oauth2", auth: "basic",
    userinfo: "body", subject: "paypal-ada",
    profile: {
      sub: "paypal-ada", name: "Ada PayPal", given_name: "Ada",
      family_name: "Byron", email: adaMail("paypal"),
      email_verified: true, picture: PICTURE
    },
    expect: {
      cn: "Ada PayPal", givenName: "Ada", sn: "Byron",
      mail: adaMail("paypal"), verified: true
    }
  }),
  provider({
    id: "dropbox", label: "Dropbox", protocol: "oidc", auth: "basic",
    userinfo: "none", subject: "dbid:ada-dropbox",
    idClaims: {
      given_name: "Ada", family_name: "Byron",
      email: adaMail("dropbox"), email_verified: true
    },
    expect: {
      givenName: "Ada", sn: "Byron", mail: adaMail("dropbox"),
      verified: true
    }
  }),
  provider({
    id: "box", label: "Box", protocol: "oauth2", auth: "post",
    userinfo: "body", subject: "box-ada",
    profile: {
      id: "box-ada", name: "Ada Box", avatar_url: PICTURE,
      login: adaMail("box")
    },
    expect: { cn: "Ada Box", mail: adaMail("box"), verified: false }
  }),
  provider({
    id: "steam", label: "Steam", protocol: "oauth2", auth: "none",
    kind: "steam", subject: STEAM_ID,
    expect: { cn: "Ada Steam" },
    notes: [
      "Leave fedPeer and fedClientId as the profile wrote them. The " +
      "sign-in address and the check address are the same URL. The " +
      "secret is a Web API key, which this dummy checks."
    ]
  }),
  provider({
    id: "codeberg", label: "Codeberg", protocol: "oidc", auth: "post",
    userinfo: "body", subject: "codeberg-ada",
    profile: {
      name: "Ada Codeberg", preferred_username: "adacodeberg",
      email: adaMail("codeberg"), email_verified: true
    },
    expect: {
      cn: "Ada Codeberg", mail: adaMail("codeberg"), verified: true
    }
  }),
  provider({
    id: "gitea", label: "Gitea or Forgejo instance", protocol: "oidc",
    auth: "post", userinfo: "body", subject: "gitea-ada",
    profile: {
      name: "Ada Gitea", preferred_username: "adagitea",
      email: adaMail("gitea"), email_verified: true
    },
    expect: { cn: "Ada Gitea", mail: adaMail("gitea"), verified: true }
  }),
  provider({
    id: "huggingface", label: "Hugging Face", protocol: "oidc",
    auth: "basic", userinfo: "body", subject: "huggingface-ada",
    profile: {
      name: "Ada Hugging Face", preferred_username: "adahf",
      email: adaMail("huggingface"), email_verified: true
    },
    expect: {
      cn: "Ada Hugging Face", mail: adaMail("huggingface"),
      verified: true
    }
  }),
  provider({
    id: "asana", label: "Asana", protocol: "oidc", auth: "post",
    userinfo: "body", subject: "asana-ada",
    profile: {
      name: "Ada Asana", email: adaMail("asana"), picture: PICTURE
    },
    expect: { cn: "Ada Asana", mail: adaMail("asana"), verified: false }
  }),
  provider({
    id: "atlassian", label: "Atlassian", protocol: "oauth2", auth: "post",
    userinfo: "body", subject: "atlassian-ada",
    profile: {
      account_id: "atlassian-ada", name: "Ada Atlassian",
      nickname: "adaatlassian", picture: PICTURE,
      email: adaMail("atlassian"), email_verified: true
    },
    expect: {
      cn: "Ada Atlassian", mail: adaMail("atlassian"), verified: true
    }
  }),
  provider({
    id: "replit", label: "Replit", protocol: "oidc", auth: "basic",
    userinfo: "body", subject: "replit-ada",
    profile: {
      name: "Ada Replit", preferred_username: "adareplit",
      email: adaMail("replit"), email_verified: true
    },
    expect: { cn: "Ada Replit", mail: adaMail("replit"), verified: true }
  }),
  provider({
    id: "mastodon", label: "Mastodon instance", protocol: "oauth2",
    auth: "post", userinfo: "body",
    subject: "https://mastodon.companion.test/users/ada",
    profile: {
      sub: "https://mastodon.companion.test/users/ada",
      name: "Ada Mastodon", preferred_username: "ada",
      picture: PICTURE,
      profile: "https://mastodon.companion.test/@ada"
    },
    expect: { cn: "Ada Mastodon" }
  }),
  provider({
    id: "sourceforge", label: "SourceForge", protocol: "oauth2",
    auth: "post", userinfo: "body", subject: "adaforge",
    profile: {
      username: "adaforge", name: "Ada Forge", avatar_url: PICTURE
    },
    expect: { cn: "Ada Forge" }
  }),
  provider({
    id: "stackoverflow", label: "Stack Overflow", protocol: "oauth2",
    auth: "post", userinfo: "body", query: "gzip", subject: "424242",
    profile: {
      items: [{
        account_id: 424242, display_name: "Ada Stack",
        profile_image: PICTURE,
        link: "https://stackoverflow.com/users/424242"
      }]
    },
    expect: { cn: "Ada Stack" }
  }),
  provider({
    id: "oschina", label: "OSChina", protocol: "oauth2", auth: "post",
    userinfo: "body", query: "json", subject: "oschina-ada",
    profile: {
      id: "oschina-ada", name: "Ada OSChina", avatar: PICTURE,
      url: "https://my.oschina.net/ada", email: adaMail("oschina")
    },
    expect: {
      cn: "Ada OSChina", mail: adaMail("oschina"), verified: false
    }
  }),
  provider({
    id: "discourse", label: "Discourse instance", protocol: "oauth2",
    auth: "none", kind: "discourse", subject: "321",
    expect: {
      cn: "Ada Discourse", mail: adaMail("discourse"), verified: false
    },
    notes: [
      "Leave fedClientId as the profile wrote it. There is no token " +
      "endpoint. The secret is the DiscourseConnect shared secret."
    ]
  }),
  provider({
    id: "bluesky", label: "Bluesky", protocol: "oauth2", auth: "none",
    kind: "bluesky", subject: BLUESKY_DID,
    expect: { cn: "Ada Bluesky" },
    notes: [
      "Leave fedClientId as the profile wrote it. Point " +
      "federation.atprotoPlcDirectory at the directory address on this " +
      "page. The client id is the document this service publishes."
    ]
  })
];

const BY_ID = new Map();
ROWS.forEach(function (one) {
  BY_ID.set(one.id, one);
});

/**
 * Canonical base64url, which is what a JWT's signing input is.
 *
 * @param {Buffer|string} value - the bytes
 * @returns {string} unpadded base64url
 */
function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(value).toString("base64url");
}

/**
 * Signs a JWT with node crypto. ES256 is JOSE raw r||s, which is what
 * this service's signJws() emits for that algorithm.
 *
 * @param {object} header - the header
 * @param {object} payload - the claims
 * @param {object} key - the private key
 * @param {string} alg - RS256 or ES256
 * @returns {string} the token
 */
function signJwt(header, payload, key, alg) {
  log.debug("Entering signJwt().");
  const input = b64u(JSON.stringify(header)) + "." +
                b64u(JSON.stringify(payload));
  const sig = alg === "ES256"
    ? crypto.sign("sha256", Buffer.from(input),
                  { key: key, dsaEncoding: "ieee-p1363" })
    : crypto.sign("sha256", Buffer.from(input), key);
  log.debug("Leaving signJwt().");
  return input + "." + b64u(sig);
}

/**
 * Verifies an ES256 JWT and returns its header and payload.
 *
 * jsonwebtoken's ES256 signature is raw r||s. A DER signature is tried
 * second, so a token this service signed still verifies if the encoding
 * differs.
 *
 * @param {string} token - the JWT
 * @param {object} publicKey - the key
 * @returns {object|null} `{ header, payload }`, or null
 */
function verifyEs256(token, publicKey) {
  log.debug("Entering verifyEs256().");
  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    log.debug("Leaving verifyEs256(). Shape.");
    return null;
  }
  let header = null;
  let payload = null;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url")
      .toString("utf8"));
  } catch (e) {
    log.debug("Caught in verifyEs256(): " + ((e && e.message) || e));
    log.debug("Leaving verifyEs256(). Parse.");
    return null;
  }
  const input = Buffer.from(parts[0] + "." + parts[1]);
  const sig = Buffer.from(parts[2], "base64url");
  let ok = false;
  try {
    ok = crypto.verify("sha256", input,
      { key: publicKey, dsaEncoding: "ieee-p1363" }, sig);
    if (!ok) {
      ok = crypto.verify("sha256", input,
        { key: publicKey, dsaEncoding: "der" }, sig);
    }
  } catch (e) {
    log.debug("Caught in verifyEs256(): " + ((e && e.message) || e));
    ok = false;
  }
  log.debug("Leaving verifyEs256(). " + ok);
  return ok ? { header: header, payload: payload } : null;
}

/**
 * Decodes one application/x-www-form-urlencoded component.
 *
 * @param {string} value - the component
 * @returns {string} the text
 */
function formDecode(value) {
  log.debug("Entering formDecode().");
  let out = String(value || "");
  try {
    out = decodeURIComponent(out.replace(/\+/g, " "));
  } catch (e) {
    log.debug("Caught in formDecode(): " + ((e && e.message) || e));
  }
  log.debug("Leaving formDecode().");
  return out;
}

/**
 * The user and secret of an HTTP Basic header, form-decoded.
 *
 * @param {string} header - the Authorization header
 * @returns {object|null} `{ user, pass }`, or null
 */
function basicPair(header) {
  log.debug("Entering basicPair().");
  const text = String(header || "");
  if (text.indexOf("Basic ") !== 0) {
    log.debug("Leaving basicPair(). None.");
    return null;
  }
  let decoded = "";
  try {
    decoded = Buffer.from(text.slice(6).trim(), "base64").toString("utf8");
  } catch (e) {
    log.debug("Caught in basicPair(): " + ((e && e.message) || e));
    log.debug("Leaving basicPair(). Undecodable.");
    return null;
  }
  const at = decoded.indexOf(":");
  if (at < 0) {
    log.debug("Leaving basicPair(). No colon.");
    return null;
  }
  log.debug("Leaving basicPair().");
  return {
    user: formDecode(decoded.slice(0, at)),
    pass: formDecode(decoded.slice(at + 1))
  };
}

/**
 * The bearer token a profile request presented, or ''.
 *
 * @param {object} req - the request
 * @returns {string} the token
 */
function bearerToken(req) {
  log.debug("Entering bearerToken().");
  const header = String(req.headers.authorization || "");
  const token = header.indexOf("Bearer ") === 0 ? header.slice(7) : "";
  log.debug("Leaving bearerToken().");
  return token;
}

/**
 * Whether the verifier matches the stored S256 challenge.
 *
 * @param {object} grant - the stored grant
 * @param {string} verifier - the verifier
 * @returns {boolean} whether it matches
 */
function pkceOk(grant, verifier) {
  log.debug("Entering pkceOk().");
  if (grant.method && grant.method !== "S256") {
    log.debug("Leaving pkceOk(). Method.");
    return false;
  }
  if (!grant.challenge) {
    log.debug("Leaving pkceOk(). No challenge.");
    return true;
  }
  if (!verifier) {
    log.debug("Leaving pkceOk(). No verifier.");
    return false;
  }
  const hash = crypto.createHash("sha256").update(String(verifier))
    .digest("base64url");
  const ok = hash === grant.challenge;
  log.debug("Leaving pkceOk(). " + ok);
  return ok;
}

/**
 * Whether a token request names the `redirect_uri` its code was issued to,
 * compared whole (RFC 6749 section 4.1.3: required, and identical, when the
 * authorization request carried one; every dummy's did).
 *
 * @param {object} grant - the code's record
 * @param {object} form - the token request's body
 * @returns {boolean} true when they are the same string
 */
function redirectMatches(grant, form) {
  log.debug("Entering redirectMatches().");
  const asked = String((form || {}).redirect_uri || "");
  const ok = !!grant.redirect && asked === String(grant.redirect);
  log.debug("Leaving redirectMatches(). " + ok);
  return ok;
}

/**
 * A 302. util.redirect() is 303, for the companion's own forms.
 *
 * @param {object} res - the response
 * @param {string} location - where to
 */
function sendFound(res, location) {
  log.debug("Entering sendFound().");
  res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  res.end();
  log.debug("Leaving sendFound().");
}

/**
 * Adds query parameters to an absolute URL without dropping its own.
 *
 * @param {string} target - the URL
 * @param {URLSearchParams} params - the parameters
 * @returns {string} the URL
 */
function withQuery(target, params) {
  log.debug("Entering withQuery().");
  const url = new URL(target);
  params.forEach(function (value, name) {
    url.searchParams.set(name, value);
  });
  log.debug("Leaving withQuery().");
  return url.toString();
}

/**
 * An OAuth error, JSON, with no HTML page around it.
 *
 * @param {object} res - the response
 * @param {number} status - the status
 * @param {string} error - the error code
 */
function oauthError(res, status, error) {
  log.debug("Entering oauthError(). " + error);
  util.sendJson(res, status, { error: error });
  log.debug("Leaving oauthError().");
}

/**
 * The dummy of each named social provider.
 */
class SocialIdps {
  /**
   * @param {object} [options] - `publicUrl`, the companion's public address
   */
  constructor(options) {
    log.debug("Entering SocialIdps.constructor().");
    const opts = options || {};
    this.publicUrl = util.stripTrailingSlashes(opts.publicUrl ||
      "http://localhost:9700");
    // Codes, access tokens, pushed requests and Steam nonces. Capped on
    // insert. A code is single-use, and so is a nonce: one that checks is
    // deleted, so a replayed assertion is refused. One whose check fails
    // is kept, so a retry of the same assertion can still be confirmed.
    this.codes = new Map();
    this.tokens = new Map();
    this.pars = new Map();
    this.nonces = new Map();
    this.rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    this.ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    log.debug("Leaving SocialIdps.constructor().");
  }

  /**
   * What the start page and /healthz list.
   *
   * @returns {object} `{ id, title, links }`
   */
  describe() {
    log.debug("Entering SocialIdps.describe().");
    log.debug("Leaving SocialIdps.describe().");
    return {
      id: "social",
      title: "Dummy social identity providers",
      links: [{ href: "/social",
                text: "A dummy of each named social provider" }]
    };
  }

  /**
   * Mounts nothing. The shell dispatches the /social prefix itself,
   * because those POSTs have no CSRF cookie. The call stays so this is
   * installed the way the other demonstrations are.
   *
   * @param {object} router - the shell's router, unused
   */
  mount(router) {
    log.debug("Entering SocialIdps.mount().");
    if (!router) {
      log.debug("Leaving SocialIdps.mount(). No router.");
      return;
    }
    log.debug("Leaving SocialIdps.mount().");
  }

  /**
   * The address issuers and redirects are built from, after listen(0).
   *
   * @param {string} url - the public URL, with no path
   */
  setPublicUrl(url) {
    log.debug("Entering SocialIdps.setPublicUrl().");
    this.publicUrl = util.stripTrailingSlashes(url);
    log.debug("Leaving SocialIdps.setPublicUrl().");
  }

  /**
   * The provider ids, in catalogue order. Generates no keys.
   *
   * @returns {string[]} the ids
   */
  static ids() {
    log.debug("Entering SocialIdps.ids().");
    log.debug("Leaving SocialIdps.ids().");
    return ROWS.map(function (one) {
      return one.id;
    });
  }

  /**
   * The fixed person a provider signs in, and the directory claims a
   * sign-in through that person should land. Generates no keys.
   *
   * @param {string} id - the provider id
   * @returns {object|null} `{ subject, expect }`, or null
   */
  static account(id) {
    log.debug("Entering SocialIdps.account().");
    const row = BY_ID.get(id) || null;
    log.debug("Leaving SocialIdps.account().");
    if (!row) {
      return null;
    }
    return { subject: row.subject, expect: Object.assign({}, row.expect) };
  }

  /**
   * Remembers one row, evicting the oldest when the map is at its cap.
   *
   * @param {Map} map - the map
   * @param {string} key - the key
   * @param {*} value - the value
   */
  remember(map, key, value) {
    log.debug("Entering SocialIdps.remember().");
    if (map.size >= MAP_CAP) {
      map.delete(map.keys().next().value);
    }
    map.set(key, value);
    log.debug("Leaving SocialIdps.remember().");
  }

  /**
   * Percent-decodes a path. A DID's colons survive either way.
   *
   * @param {string} pathname - the path
   * @returns {string} the path
   */
  decodePath(pathname) {
    log.debug("Entering SocialIdps.decodePath().");
    let out = String(pathname || "");
    try {
      out = decodeURIComponent(out);
    } catch (e) {
      log.debug("Caught in SocialIdps.decodePath(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving SocialIdps.decodePath().");
    return out;
  }

  /**
   * The issuer a token is signed as. Roblox's has a trailing slash.
   * microsoft-any signs the personal-account tenant, which is not this
   * companion's address.
   *
   * @param {string} id - the provider id
   * @returns {string} the issuer
   */
  issuer(id) {
    log.debug("Entering SocialIdps.issuer().");
    if (id === "microsoft-any") {
      log.debug("Leaving SocialIdps.issuer(). Microsoft.");
      return MS_ISS;
    }
    const base = this.publicUrl + "/social/" + id;
    const out = id === "roblox" ? base + "/" : base;
    log.debug("Leaving SocialIdps.issuer().");
    return out;
  }

  /**
   * The client id a code-flow provider expects. Apple's is the same
   * string the pattern would build; it is named because the secret's
   * sub is that id.
   *
   * @param {object} row - the provider
   * @returns {string} the client id
   */
  clientId(row) {
    log.debug("Entering SocialIdps.clientId().");
    const id = row.id === "apple" ? APPLE_CLIENT : "companion-" + row.id;
    log.debug("Leaving SocialIdps.clientId().");
    return id;
  }

  /**
   * The PKCS#8 PEM of the dummy P-256 key Apple's client secret is
   * signed with. It is a dummy. An operator pastes it; the test reads it.
   *
   * @returns {string} the PEM
   */
  appleKeyPem() {
    log.debug("Entering SocialIdps.appleKeyPem().");
    const pem = this.ec.privateKey.export({ type: "pkcs8", format: "pem" });
    log.debug("Leaving SocialIdps.appleKeyPem().");
    return pem;
  }

  /**
   * Where a Bluesky relationship's PLC directory setting should point.
   *
   * @returns {string} the directory address
   */
  blueskyDirectory() {
    log.debug("Entering SocialIdps.blueskyDirectory().");
    log.debug("Leaving SocialIdps.blueskyDirectory().");
    return this.publicUrl + "/social/bluesky/plc";
  }

  /**
   * The relationship fields that point a provider at this dummy, without
   * fedEnabled. Enable last.
   *
   * @param {string} id - the provider id
   * @returns {Array<object>} `{ field, value }` in the order to write them
   */
  relationshipFields(id) {
    log.debug("Entering SocialIdps.relationshipFields().");
    const row = BY_ID.get(id) || null;
    const fields = [];
    const push = function (field, value) {
      fields.push({ field: field, value: value });
    };
    if (!row) {
      log.debug("Leaving SocialIdps.relationshipFields(). Unknown.");
      return fields;
    }
    const base = this.publicUrl + "/social/" + id;
    if (row.kind === "steam") {
      push("fedSsoUrl", base + "/login");
      push("fedTokenUrl", base + "/login");
      push("fedUserinfoUrl", base + "/summary");
      push("fedClientSecret", SECRET);
      log.debug("Leaving SocialIdps.relationshipFields(). Steam.");
      return fields;
    }
    if (row.kind === "discourse") {
      push("fedSsoUrl", base + "/session/sso_provider");
      push("fedPeer", base);
      push("fedClientSecret", SECRET);
      log.debug("Leaving SocialIdps.relationshipFields(). Discourse.");
      return fields;
    }
    if (row.kind === "bluesky") {
      push("fedPeer", base);
      push("fedUserinfoUrl", base + "/userinfo");
      push("fedSsoUrl", base + "/authorize");
      push("fedTokenUrl", base + "/token");
      log.debug("Leaving SocialIdps.relationshipFields(). Bluesky.");
      return fields;
    }
    push("fedSsoUrl", base + "/authorize");
    push("fedTokenUrl", base + "/token");
    if (row.kind === "apple") {
      push("fedClientId", APPLE_CLIENT);
    } else {
      push("fedClientId", this.clientId(row));
      push("fedClientSecret", SECRET);
    }
    if (row.peer !== "keep") {
      push("fedPeer", this.issuer(id));
    }
    if (row.protocol === "oidc") {
      push("fedJwksUri", base + "/jwks");
    }
    if (row.userinfo === "sub" || row.userinfo === "body") {
      push("fedUserinfoUrl", base + "/userinfo");
    }
    if (row.emails) {
      push("fedEmailsUrl", base + "/emails");
    }
    if (row.kind === "apple") {
      push("fedTeamId", TEAM_ID);
      push("fedKeyId", APPLE_KEY_ID);
      push("fedClientSigningKey", this.appleKeyPem());
    }
    log.debug("Leaving SocialIdps.relationshipFields().");
    return fields;
  }

  /**
   * Answers one request under /social. The body, when there is one, is
   * the caller's: two requests can be in flight, so it is not stored.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   * @returns {Promise<void>}
   */
  async handle(req, res) {
    log.debug("Entering SocialIdps.handle(). " + req.method + " " +
              util.stripQuery(req.url));
    try {
      const url = new URL(req.url, "http://companion.invalid");
      let form = null;
      if (req.method === "POST") {
        form = util.formOf(await util.readBody(req));
      }
      await this.dispatch(req, res, url, form);
    } catch (e) {
      log.debug("Caught in SocialIdps.handle(): " +
                ((e && e.message) || e));
      log.error("companion social: " + req.method + " " + req.url +
                " failed: " + ((e && e.stack) || e));
      if (!res.headersSent) {
        util.sendError(res, 500, "The dummy failed",
                       String((e && e.message) || e));
      }
    }
    log.debug("Leaving SocialIdps.handle().");
  }

  /**
   * Routes one decoded /social path.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   * @param {URL} url - the parsed URL
   * @param {object|null} form - the POST body
   * @returns {Promise<void>}
   */
  async dispatch(req, res, url, form) {
    log.debug("Entering SocialIdps.dispatch().");
    const pathname = this.decodePath(url.pathname);
    if (pathname === "/social" || pathname === "/social/") {
      this.indexPage(res);
      log.debug("Leaving SocialIdps.dispatch(). Index.");
      return;
    }
    if (pathname.indexOf("/social/") !== 0) {
      util.sendError(res, 404, "Not here",
                     "No dummy lives at " + pathname + ".");
      log.debug("Leaving SocialIdps.dispatch(). Outside.");
      return;
    }
    const rest = pathname.slice("/social/".length);
    const slash = rest.indexOf("/");
    const id = slash < 0 ? rest : rest.slice(0, slash);
    const what = slash < 0 ? "" : rest.slice(slash + 1);
    const row = BY_ID.get(id) || null;
    if (!row) {
      util.sendError(res, 404, "No such provider",
        "The companion has no dummy for " + id + ".");
      log.debug("Leaving SocialIdps.dispatch(). Unknown.");
      return;
    }
    if (what === "" || what === "/") {
      this.providerPage(res, row);
      log.debug("Leaving SocialIdps.dispatch(). Page.");
      return;
    }
    await this.route(req, res, url, form, row, what);
    log.debug("Leaving SocialIdps.dispatch().");
  }

  /**
   * One provider's protocol address.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   * @param {URL} url - the parsed URL
   * @param {object|null} form - the POST body
   * @param {object} row - the provider
   * @param {string} what - the path after the id
   * @returns {Promise<void>}
   */
  async route(req, res, url, form, row, what) {
    log.debug("Entering SocialIdps.route(). " + what);
    if (what === "authorize") {
      if (req.method !== "GET") {
        this.refuseMethod(res);
      } else if (row.kind === "bluesky") {
        this.blueskyAuthorize(res, url);
      } else {
        this.authorize(res, url, row);
      }
    } else if (what === "token") {
      if (req.method !== "POST") {
        this.refuseMethod(res);
      } else if (row.kind === "bluesky") {
        this.blueskyToken(req, res, url, form);
      } else {
        this.token(req, res, form, row);
      }
    } else if (what === "jwks") {
      if (req.method !== "GET") {
        this.refuseMethod(res);
      } else {
        this.jwks(res);
      }
    } else if (what === "userinfo") {
      if (req.method !== "GET") {
        this.refuseMethod(res);
      } else {
        this.userinfo(req, res, url, row);
      }
    } else if (what === "emails") {
      if (req.method !== "GET") {
        this.refuseMethod(res);
      } else {
        this.emails(req, res, row);
      }
    } else if (what === "developer-key") {
      if (req.method !== "GET" || row.kind !== "apple") {
        this.refuseMethod(res);
      } else {
        this.developerKey(res);
      }
    } else if (what === "login") {
      this.steamLogin(req, res, url, form, row);
    } else if (what === "summary") {
      if (req.method !== "GET" || row.kind !== "steam") {
        this.refuseMethod(res);
      } else {
        this.steamSummary(res, url);
      }
    } else if (what === "session/sso_provider") {
      if (req.method !== "GET" || row.kind !== "discourse") {
        this.refuseMethod(res);
      } else {
        this.discourse(res, url);
      }
    } else if (what === ".well-known/oauth-authorization-server") {
      if (req.method !== "GET" || row.kind !== "bluesky") {
        this.refuseMethod(res);
      } else {
        this.blueskyMetadata(res);
      }
    } else if (what === "par") {
      if (req.method !== "POST" || row.kind !== "bluesky") {
        this.refuseMethod(res);
      } else {
        this.blueskyPar(req, res, url, form);
      }
    } else if (what === "pds/.well-known/oauth-protected-resource") {
      if (req.method !== "GET" || row.kind !== "bluesky") {
        this.refuseMethod(res);
      } else {
        this.blueskyResource(res);
      }
    } else if (what.indexOf("plc/") === 0) {
      if (req.method !== "GET" || row.kind !== "bluesky") {
        this.refuseMethod(res);
      } else {
        this.blueskyPlc(res, what.slice(4));
      }
    } else {
      util.sendError(res, 404, "Not here",
        "This dummy has no address at " + what + ".");
    }
    log.debug("Leaving SocialIdps.route().");
  }

  /**
   * A method this address does not take.
   *
   * @param {object} res - the response
   */
  refuseMethod(res) {
    log.debug("Entering SocialIdps.refuseMethod().");
    util.sendError(res, 405, "Wrong method",
      "This dummy address does not take that method.");
    log.debug("Leaving SocialIdps.refuseMethod().");
  }

  /**
   * The list of dummies.
   *
   * @param {object} res - the response
   */
  indexPage(res) {
    log.debug("Entering SocialIdps.indexPage().");
    const items = ROWS.map(function (one) {
      return "<li><a href=\"/social/" + util.esc(one.id) + "\">" +
             util.esc(one.label) + "</a> <code>" + util.esc(one.id) +
             "</code></li>";
    }).join("");
    util.sendHtml(res, 200, util.page("Dummy social providers",
      "<div class=\"card\"><h1>Dummy social providers</h1>" +
      "<p>These are dummies, not the providers. Each signs in one fixed " +
      "person so a development stack can be tried without an account. " +
      "The two generic profiles are not here.</p>" +
      "<p>The addresses on each page use this companion's public URL. A " +
      "service in another container dials the companion by that address, " +
      "not localhost.</p><ul>" + items + "</ul></div>"));
    log.debug("Leaving SocialIdps.indexPage().");
  }

  /**
   * One provider's paste sheet.
   *
   * @param {object} res - the response
   * @param {object} row - the provider
   */
  providerPage(res, row) {
    log.debug("Entering SocialIdps.providerPage().");
    const fields = this.relationshipFields(row.id).map(function (one) {
      return "<tr><th>" + util.esc(one.field) + "</th><td><code>" +
             util.esc(one.value) + "</code></td></tr>";
    }).join("");
    const notes = row.notes.map(function (one) {
      return "<p>" + util.esc(one) + "</p>";
    }).join("");
    let extra = "";
    if (row.kind === "apple") {
      extra = "<p><a href=\"/social/apple/developer-key\">The dummy " +
              "key, as text</a></p>";
    }
    if (row.kind === "bluesky") {
      extra = "<p>Set <code>federation.atprotoPlcDirectory</code> to " +
              "<code>" + util.esc(this.blueskyDirectory()) + "</code>.</p>";
    }
    const who = SocialIdps.account(row.id);
    util.sendHtml(res, 200, util.page(row.label + " dummy",
      "<div class=\"card\"><h1>" + util.esc(row.label) + "</h1>" +
      "<p>This is a dummy, not " + util.esc(row.label) + ". It signs in " +
      "one fixed person (<code>" + util.esc(who.subject) + "</code>).</p>" +
      notes + extra +
      "<p>Write these, then enable the relationship last. The addresses " +
      "use this companion's public URL. A service in another container " +
      "dials the companion by that address, not localhost.</p>" +
      "<table><tbody>" + fields + "</tbody></table>" +
      "<p><a href=\"/social\">All dummies</a></p></div>"));
    log.debug("Leaving SocialIdps.providerPage().");
  }

  /**
   * The public JWKs. Both, so a token's kid selects one. The private
   * halves are not published.
   *
   * @param {object} res - the response
   */
  jwks(res) {
    log.debug("Entering SocialIdps.jwks().");
    const rsa = this.rsa.publicKey.export({ format: "jwk" });
    const ec = this.ec.publicKey.export({ format: "jwk" });
    util.sendJson(res, 200, { keys: [
      { kty: "RSA", n: rsa.n, e: rsa.e, kid: "companion-rsa",
        use: "sig", alg: "RS256" },
      { kty: "EC", crv: ec.crv, x: ec.x, y: ec.y, kid: "companion-ec",
        use: "sig", alg: "ES256" }
    ] });
    log.debug("Leaving SocialIdps.jwks().");
  }

  /**
   * The dummy Apple key, as text, with a line saying it is a dummy.
   *
   * @param {object} res - the response
   */
  developerKey(res) {
    log.debug("Entering SocialIdps.developerKey().");
    const body = "This key is a dummy generated by the companion. " +
                 "It is not an Apple key.\n" + this.appleKeyPem();
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    });
    res.end(body);
    log.debug("Leaving SocialIdps.developerKey().");
  }

  /**
   * Issues a code, or Apple's form. A missing return address is a page,
   * not a crash.
   *
   * @param {object} res - the response
   * @param {URL} url - the request
   * @param {object} row - the provider
   */
  authorize(res, url, row) {
    log.debug("Entering SocialIdps.authorize().");
    const query = url.searchParams;
    const redirect = query.get("redirect_uri") || "";
    const presented = row.auth === "tiktok"
      ? (query.get("client_key") || "")
      : (query.get("client_id") || "");
    const type = query.get("response_type") || "";
    const challenge = query.get("code_challenge") || "";
    const method = query.get("code_challenge_method") || "";
    let redirectOk = false;
    try {
      redirectOk = !!(redirect && new URL(redirect).href);
    } catch (e) {
      log.debug("Caught in SocialIdps.authorize(): " +
                ((e && e.message) || e));
      redirectOk = false;
    }
    if (!redirectOk || presented !== this.clientId(row) ||
        type.split(" ").indexOf("code") < 0 || !challenge ||
        method !== "S256") {
      util.sendError(res, 400, "The authorization was refused",
        "This dummy expected its own client, a code, and S256 PKCE.");
      log.debug("Leaving SocialIdps.authorize(). Refused.");
      return;
    }
    const code = crypto.randomBytes(24).toString("base64url");
    const state = query.get("state") || "";
    this.remember(this.codes, code, {
      id: row.id, clientId: presented, redirect: redirect,
      challenge: challenge, method: method,
      nonce: query.get("nonce") || "", state: state
    });
    if (row.kind === "apple") {
      this.appleForm(res, redirect, code, state, row);
      log.debug("Leaving SocialIdps.authorize(). Form.");
      return;
    }
    const params = new URLSearchParams();
    params.set("code", code);
    params.set("state", state);
    sendFound(res, withQuery(redirect, params));
    log.debug("Leaving SocialIdps.authorize().");
  }

  /**
   * Apple's form_post answer. No script: a submit button is the whole
   * mechanism, and the companion's policy allows none.
   *
   * @param {object} res - the response
   * @param {string} redirect - the assertion consumer
   * @param {string} code - the code
   * @param {string} state - the state
   * @param {object} row - the provider
   */
  appleForm(res, redirect, code, state, row) {
    log.debug("Entering SocialIdps.appleForm().");
    const user = JSON.stringify(row.formUser || {});
    const form = "<form method=\"post\" action=\"" + util.esc(redirect) +
      "\">" +
      "<input type=\"hidden\" name=\"code\" value=\"" + util.esc(code) +
      "\">" +
      "<input type=\"hidden\" name=\"state\" value=\"" + util.esc(state) +
      "\">" +
      "<input type=\"hidden\" name=\"user\" value=\"" + util.esc(user) +
      "\">" +
      "<button type=\"submit\">Continue</button></form>";
    util.sendHtml(res, 200, util.page("Continue to the service",
      "<div class=\"card\"><h1>Continue</h1>" +
      "<p>This dummy posts the code back, the way Sign in with Apple " +
      "does. It is not Apple.</p>" + form + "</div>"));
    log.debug("Leaving SocialIdps.appleForm().");
  }

  /**
   * Whether the token request authenticated the way the profile says.
   * Checked only after a real code is found, so a missing code is
   * invalid_grant and not a client error.
   *
   * @param {object} row - the provider
   * @param {object} form - the body
   * @param {object} headers - the headers
   * @returns {boolean} whether it authenticated
   */
  clientOk(row, form, headers) {
    log.debug("Entering SocialIdps.clientOk().");
    const authorization = String(headers.authorization || "");
    let ok = false;
    if (row.auth === "tiktok") {
      ok = !authorization && form.client_key === this.clientId(row) &&
           form.client_secret === SECRET;
    } else if (row.auth === "apple") {
      ok = !authorization && form.client_id === APPLE_CLIENT &&
           this.appleSecretOk(form.client_secret, form.client_id);
    } else if (row.auth === "post") {
      ok = !authorization && form.client_id === this.clientId(row) &&
           form.client_secret === SECRET;
    } else if (row.auth === "basic") {
      const pair = basicPair(authorization);
      ok = !!pair && pair.user === this.clientId(row) &&
           pair.pass === SECRET;
    } else {
      ok = true;
    }
    log.debug("Leaving SocialIdps.clientOk(). " + ok);
    return ok;
  }

  /**
   * Whether the body secret is the ES256 client secret this service
   * signs for Apple: team id, client id, Apple's audience, this dummy's
   * key id.
   *
   * @param {string} token - the client_secret
   * @param {string} clientId - the client_id
   * @returns {boolean} whether it verifies
   */
  appleSecretOk(token, clientId) {
    log.debug("Entering SocialIdps.appleSecretOk().");
    const opened = verifyEs256(token, this.ec.publicKey);
    const now = Math.floor(Date.now() / 1000);
    const payload = opened ? opened.payload : null;
    const header = opened ? opened.header : null;
    const ok = !!opened && header.alg === "ES256" &&
               header.kid === APPLE_KEY_ID && payload.iss === TEAM_ID &&
               payload.sub === clientId && payload.aud === APPLE_AUD &&
               typeof payload.iat === "number" &&
               typeof payload.exp === "number" && payload.exp > now - 60;
    log.debug("Leaving SocialIdps.appleSecretOk(). " + ok);
    return ok;
  }

  /**
   * Redeems a code. An unknown code is invalid_grant before any client
   * check (a probe with no session posts one). A wrong secret leaves the
   * code in place. A `redirect_uri` that is not the one the authorization
   * request named (RFC 6749 section 4.1.3), or a wrong verifier, spends it
   * (#1689's review: a negative fixture must refuse what a provider
   * would).
   *
   * @param {object} req - the request
   * @param {object} res - the response
   * @param {object} form - the body
   * @param {object} row - the provider
   */
  token(req, res, form, row) {
    log.debug("Entering SocialIdps.token().");
    if (row.kind === "steam" || row.kind === "discourse" ||
        row.kind === "bluesky") {
      util.sendError(res, 404, "No token endpoint",
        "This dummy does not take a token request.");
      log.debug("Leaving SocialIdps.token(). None.");
      return;
    }
    const code = String(form.code || "");
    const grant = this.codes.get(code) || null;
    if (!grant || grant.id !== row.id) {
      oauthError(res, 400, "invalid_grant");
      log.debug("Leaving SocialIdps.token(). No code.");
      return;
    }
    if (!this.clientOk(row, form, req.headers)) {
      oauthError(res, 401, "invalid_client");
      log.debug("Leaving SocialIdps.token(). Client.");
      return;
    }
    if (!redirectMatches(grant, form)) {
      this.codes.delete(code);
      oauthError(res, 400, "invalid_grant");
      log.debug("Leaving SocialIdps.token(). Redirect.");
      return;
    }
    if (!pkceOk(grant, form.code_verifier || "")) {
      this.codes.delete(code);
      oauthError(res, 400, "invalid_grant");
      log.debug("Leaving SocialIdps.token(). PKCE.");
      return;
    }
    this.codes.delete(code);
    const access = "at-" + crypto.randomBytes(16).toString("hex");
    this.remember(this.tokens, access, { id: row.id });
    const body = {
      access_token: access, token_type: "Bearer", expires_in: 300
    };
    if (row.tokenExtra) {
      Object.keys(row.tokenExtra).forEach(function (name) {
        body[name] = row.tokenExtra[name];
      });
    }
    if (row.protocol === "oidc") {
      body.id_token = this.idToken(row, grant);
    }
    util.sendJson(res, 200, body);
    log.debug("Leaving SocialIdps.token().");
  }

  /**
   * The ID token for one code. sub is a string. iat and exp are numbers.
   * microsoft-any also carries tid, which is how its issuer is chosen.
   *
   * @param {object} row - the provider
   * @param {object} grant - the code's grant
   * @returns {string} the token
   */
  idToken(row, grant) {
    log.debug("Entering SocialIdps.idToken().");
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: this.issuer(row.id), sub: row.subject, aud: grant.clientId,
      iat: now, exp: now + 600, nonce: grant.nonce
    };
    if (row.id === "microsoft-any") {
      payload.tid = MS_TENANT;
    }
    Object.keys(row.idClaims || {}).forEach(function (name) {
      payload[name] = row.idClaims[name];
    });
    const alg = row.alg;
    const kid = alg === "ES256" ? "companion-ec" : "companion-rsa";
    const key = alg === "ES256" ? this.ec.privateKey : this.rsa.privateKey;
    const token = signJwt({ alg: alg, typ: "JWT", kid: kid }, payload,
                           key, alg);
    log.debug("Leaving SocialIdps.idToken().");
    return token;
  }

  /**
   * The profile document. An OIDC userinfo that only exists so its sub
   * matches the ID token returns that sub and nothing else, which keeps
   * the ID token's claims. A full document forces sub on OIDC, because
   * a mismatch refuses the sign-in.
   *
   * @param {object} row - the provider
   * @returns {object} the document
   */
  profileBody(row) {
    log.debug("Entering SocialIdps.profileBody().");
    if (row.userinfo === "sub") {
      log.debug("Leaving SocialIdps.profileBody(). Subject.");
      return { sub: row.subject };
    }
    const body = JSON.parse(JSON.stringify(row.profile || {}));
    if (row.protocol === "oidc") {
      body.sub = row.subject;
    }
    log.debug("Leaving SocialIdps.profileBody().");
    return body;
  }

  /**
   * UserInfo, or the query-token profile, or Bluesky's public profile.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   * @param {URL} url - the request
   * @param {object} row - the provider
   */
  userinfo(req, res, url, row) {
    log.debug("Entering SocialIdps.userinfo().");
    if (row.kind === "bluesky") {
      this.blueskyProfile(res, url);
      log.debug("Leaving SocialIdps.userinfo(). Bluesky.");
      return;
    }
    if (row.query) {
      this.queryProfile(res, row, url.searchParams.get("access_token") ||
                        "");
      log.debug("Leaving SocialIdps.userinfo(). Query.");
      return;
    }
    const held = this.tokens.get(bearerToken(req)) || null;
    if (!held || held.id !== row.id || row.userinfo === "none") {
      oauthError(res, 401, "invalid_token");
      log.debug("Leaving SocialIdps.userinfo(). Refused.");
      return;
    }
    util.sendJson(res, 200, this.profileBody(row));
    log.debug("Leaving SocialIdps.userinfo().");
  }

  /**
   * A profile that takes the access token on the query. Stack Exchange's
   * body is gzip, with no content-encoding, which is how that API answers.
   *
   * @param {object} res - the response
   * @param {object} row - the provider
   * @param {string} token - the query token
   */
  queryProfile(res, row, token) {
    log.debug("Entering SocialIdps.queryProfile().");
    const held = this.tokens.get(token) || null;
    if (!held || held.id !== row.id) {
      oauthError(res, 401, "invalid_token");
      log.debug("Leaving SocialIdps.queryProfile(). Unknown.");
      return;
    }
    const body = this.profileBody(row);
    if (row.query === "gzip") {
      const gz = zlib.gzipSync(Buffer.from(JSON.stringify(body), "utf8"));
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Content-Length": gz.length
      });
      res.end(gz);
      log.debug("Leaving SocialIdps.queryProfile(). Gzip.");
      return;
    }
    util.sendJson(res, 200, body);
    log.debug("Leaving SocialIdps.queryProfile().");
  }

  /**
   * GitHub's or Bitbucket's second address, the one the email comes from.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   * @param {object} row - the provider
   */
  emails(req, res, row) {
    log.debug("Entering SocialIdps.emails().");
    const held = this.tokens.get(bearerToken(req)) || null;
    if (!row.emails || !held || held.id !== row.id) {
      oauthError(res, 401, "invalid_token");
      log.debug("Leaving SocialIdps.emails(). Refused.");
      return;
    }
    util.sendJson(res, 200, row.emailsBody);
    log.debug("Leaving SocialIdps.emails().");
  }

  /**
   * Steam's OpenID 2.0 endpoint: a browser GET becomes an assertion, and
   * the service's POST is check_authentication.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   * @param {URL} url - the request
   * @param {object|null} form - the POST body
   * @param {object} row - the provider
   */
  steamLogin(req, res, url, form, row) {
    log.debug("Entering SocialIdps.steamLogin().");
    if (row.kind !== "steam") {
      util.sendError(res, 404, "Not here", "This dummy has no login.");
      log.debug("Leaving SocialIdps.steamLogin(). Not Steam.");
      return;
    }
    if (req.method === "POST") {
      this.steamCheck(res, form);
      log.debug("Leaving SocialIdps.steamLogin(). Check.");
      return;
    }
    if (req.method !== "GET") {
      this.refuseMethod(res);
      log.debug("Leaving SocialIdps.steamLogin(). Method.");
      return;
    }
    const returnTo = url.searchParams.get("openid.return_to") || "";
    if (url.searchParams.get("openid.mode") !== "checkid_setup" ||
        !returnTo) {
      util.sendError(res, 400, "Not a Steam sign-in",
        "This dummy expected checkid_setup and a return address.");
      log.debug("Leaving SocialIdps.steamLogin(). Refused.");
      return;
    }
    const nonce = Date.now() + "-" + crypto.randomBytes(8).toString("hex");
    this.remember(this.nonces, nonce, true);
    const endpoint = this.publicUrl + "/social/steam/login";
    const params = new URLSearchParams();
    params.set("openid.ns", OPENID2_NS);
    params.set("openid.mode", "id_res");
    params.set("openid.op_endpoint", endpoint);
    params.set("openid.claimed_id", STEAM_CLAIMED);
    params.set("openid.identity", STEAM_CLAIMED);
    params.set("openid.return_to", returnTo);
    params.set("openid.response_nonce", nonce);
    params.set("openid.assoc_handle", "companion");
    params.set("openid.signed",
      "op_endpoint,return_to,response_nonce,assoc_handle," +
      "claimed_id,identity");
    params.set("openid.sig", "companion-unsigned");
    sendFound(res, withQuery(returnTo, params));
    log.debug("Leaving SocialIdps.steamLogin().");
  }

  /**
   * check_authentication. Confirms a nonce this process issued, ONCE: a
   * nonce that checked is forgotten, so a replayed assertion is not valid
   * (OpenID 2.0 section 11.4.2.1, #1689's review). A failed check does not
   * forget it.
   *
   * @param {object} res - the response
   * @param {object} form - the body
   */
  steamCheck(res, form) {
    log.debug("Entering SocialIdps.steamCheck().");
    const nonce = String((form || {})["openid.response_nonce"] || "");
    const claimed = String((form || {})["openid.claimed_id"] || "");
    const endpoint = this.publicUrl + "/social/steam/login";
    const ok = this.nonces.has(nonce) && claimed === STEAM_CLAIMED &&
               String((form || {})["openid.op_endpoint"] || "") === endpoint;
    if (ok) {
      this.nonces.delete(nonce);
    }
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    });
    res.end("ns:" + OPENID2_NS + "\nis_valid:" + (ok ? "true" : "false") +
            "\n");
    log.debug("Leaving SocialIdps.steamCheck(). " + ok);
  }

  /**
   * The Web API summary. A wrong key answers no players, so the sign-in
   * still stands and the name does not.
   *
   * @param {object} res - the response
   * @param {URL} url - the request
   */
  steamSummary(res, url) {
    log.debug("Entering SocialIdps.steamSummary().");
    const key = url.searchParams.get("key") || "";
    const ids = url.searchParams.get("steamids") || "";
    const players = key === SECRET && ids === STEAM_ID ? [{
      steamid: STEAM_ID, personaname: "Ada Steam", avatarfull: PICTURE,
      profileurl: "https://steamcommunity.com/id/ada"
    }] : [];
    util.sendJson(res, 200, { response: { players: players } });
    log.debug("Leaving SocialIdps.steamSummary().");
  }

  /**
   * DiscourseConnect. The signature is the hex HMAC of the raw base64
   * payload, and a bad one is not redirected.
   *
   * @param {object} res - the response
   * @param {URL} url - the request
   */
  discourse(res, url) {
    log.debug("Entering SocialIdps.discourse().");
    const payload = url.searchParams.get("sso") || "";
    const presented = String(url.searchParams.get("sig") || "")
      .toLowerCase();
    const expected = crypto.createHmac("sha256", SECRET)
      .update(Buffer.from(payload, "utf8")).digest("hex");
    const presentedBuf = Buffer.from(presented);
    const expectedBuf = Buffer.from(expected);
    let signed = false;
    if (payload && presentedBuf.length === expectedBuf.length) {
      try {
        signed = crypto.timingSafeEqual(presentedBuf, expectedBuf);
      } catch (e) {
        log.debug("Caught in SocialIdps.discourse(): " +
                  ((e && e.message) || e));
        signed = false;
      }
    }
    let said = null;
    if (signed) {
      try {
        said = new URLSearchParams(Buffer.from(payload, "base64")
          .toString("utf8"));
      } catch (e) {
        log.debug("Caught in SocialIdps.discourse(): " +
                  ((e && e.message) || e));
        said = null;
      }
    }
    const nonce = said ? (said.get("nonce") || "") : "";
    const back = said ? (said.get("return_sso_url") || "") : "";
    if (!signed || !nonce || !back) {
      res.writeHead(400, {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store"
      });
      res.end("bad signature");
      log.debug("Leaving SocialIdps.discourse(). Refused.");
      return;
    }
    const answer = Buffer.from(new URLSearchParams({
      nonce: nonce, external_id: "321", name: "Ada Discourse",
      username: "adadiscourse", email: adaMail("discourse")
    }).toString(), "utf8").toString("base64");
    const sig = crypto.createHmac("sha256", SECRET)
      .update(Buffer.from(answer, "utf8")).digest("hex");
    const dest = new URL(back);
    dest.searchParams.set("sso", answer);
    dest.searchParams.set("sig", sig);
    sendFound(res, dest.toString());
    log.debug("Leaving SocialIdps.discourse().");
  }

  /**
   * Bluesky's authorization-server metadata. issuer has no trailing slash
   * and equals the relationship's fedPeer.
   *
   * @param {object} res - the response
   */
  blueskyMetadata(res) {
    log.debug("Entering SocialIdps.blueskyMetadata().");
    const issuer = this.issuer("bluesky");
    util.sendJson(res, 200, {
      issuer: issuer,
      pushed_authorization_request_endpoint: issuer + "/par",
      authorization_endpoint: issuer + "/authorize",
      token_endpoint: issuer + "/token"
    });
    log.debug("Leaving SocialIdps.blueskyMetadata().");
  }

  /**
   * A DPoP proof for this request. A bad signature is refused with no
   * nonce, so the client does not retry it. A good proof with the wrong
   * nonce is the one retry, and stores nothing.
   *
   * @param {object} req - the request
   * @param {string} pathname - the path the proof's htu must name
   * @returns {object} `{ ok, nonce }`
   */
  dpopVerdict(req, pathname) {
    log.debug("Entering SocialIdps.dpopVerdict().");
    const proof = String(req.headers.dpop || "");
    const parts = proof.split(".");
    let header = null;
    if (parts.length === 3) {
      try {
        header = JSON.parse(Buffer.from(parts[0], "base64url")
          .toString("utf8"));
      } catch (e) {
        log.debug("Caught in SocialIdps.dpopVerdict(): " +
                  ((e && e.message) || e));
        header = null;
      }
    }
    let key = null;
    if (header && header.jwk) {
      try {
        key = crypto.createPublicKey({ key: header.jwk, format: "jwk" });
      } catch (e) {
        log.debug("Caught in SocialIdps.dpopVerdict(): " +
                  ((e && e.message) || e));
        key = null;
      }
    }
    const opened = key ? verifyEs256(proof, key) : null;
    const payload = opened ? opened.payload : null;
    const htu = this.publicUrl + pathname;
    if (!opened || header.typ !== "dpop+jwt" || header.alg !== "ES256" ||
        !payload || payload.htm !== "POST" || payload.htu !== htu) {
      log.debug("Leaving SocialIdps.dpopVerdict(). Proof.");
      return { ok: false, nonce: false };
    }
    if (payload.nonce !== DPOP_NONCE) {
      log.debug("Leaving SocialIdps.dpopVerdict(). Nonce.");
      return { ok: false, nonce: true };
    }
    log.debug("Leaving SocialIdps.dpopVerdict().");
    return { ok: true, nonce: false };
  }

  /**
   * Answers a DPoP refusal. The nonce header is set only for the retry.
   *
   * @param {object} res - the response
   * @param {object} verdict - what dpopVerdict() returned
   * @returns {boolean} whether the proof was refused
   */
  dpopRefused(res, verdict) {
    log.debug("Entering SocialIdps.dpopRefused().");
    if (verdict.ok) {
      log.debug("Leaving SocialIdps.dpopRefused(). Accepted.");
      return false;
    }
    if (verdict.nonce) {
      res.setHeader("dpop-nonce", DPOP_NONCE);
      oauthError(res, 400, "use_dpop_nonce");
      log.debug("Leaving SocialIdps.dpopRefused(). Nonce.");
      return true;
    }
    oauthError(res, 401, "invalid_dpop_proof");
    log.debug("Leaving SocialIdps.dpopRefused(). Proof.");
    return true;
  }

  /**
   * The pushed authorization request. Stored only after DPoP succeeds.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   * @param {URL} url - the request
   * @param {object} form - the body
   */
  blueskyPar(req, res, url, form) {
    log.debug("Entering SocialIdps.blueskyPar().");
    if (this.dpopRefused(res, this.dpopVerdict(req, url.pathname))) {
      log.debug("Leaving SocialIdps.blueskyPar(). DPoP.");
      return;
    }
    const redirect = String(form.redirect_uri || "");
    const challenge = String(form.code_challenge || "");
    if (form.response_type !== "code" || !redirect || !challenge ||
        form.code_challenge_method !== "S256") {
      oauthError(res, 400, "invalid_request");
      log.debug("Leaving SocialIdps.blueskyPar(). Request.");
      return;
    }
    const uri = "urn:companion:bluesky:" +
                crypto.randomBytes(16).toString("base64url");
    this.remember(this.pars, uri, {
      redirect: redirect, challenge: challenge, method: "S256",
      state: String(form.state || "")
    });
    util.sendJson(res, 201, { request_uri: uri, expires_in: 300 });
    log.debug("Leaving SocialIdps.blueskyPar().");
  }

  /**
   * The browser's authorization, from a stored push.
   *
   * @param {object} res - the response
   * @param {URL} url - the request
   */
  blueskyAuthorize(res, url) {
    log.debug("Entering SocialIdps.blueskyAuthorize().");
    const held = this.pars.get(url.searchParams.get("request_uri") || "") ||
                 null;
    if (!held) {
      util.sendError(res, 400, "No such request",
        "This dummy has no pushed authorization under that uri.");
      log.debug("Leaving SocialIdps.blueskyAuthorize(). None.");
      return;
    }
    const code = crypto.randomBytes(24).toString("base64url");
    this.remember(this.codes, code, {
      id: "bluesky", clientId: "", redirect: held.redirect,
      challenge: held.challenge, method: held.method, nonce: "",
      state: held.state
    });
    const params = new URLSearchParams();
    params.set("code", code);
    params.set("state", held.state);
    params.set("iss", this.issuer("bluesky"));
    sendFound(res, withQuery(held.redirect, params));
    log.debug("Leaving SocialIdps.blueskyAuthorize().");
  }

  /**
   * The token request. DPoP is checked before the code is spent, so the
   * nonce retry still has the code. A `redirect_uri` that is not the
   * pushed request's spends it, as a wrong verifier does.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   * @param {URL} url - the request
   * @param {object} form - the body
   */
  blueskyToken(req, res, url, form) {
    log.debug("Entering SocialIdps.blueskyToken().");
    if (this.dpopRefused(res, this.dpopVerdict(req, url.pathname))) {
      log.debug("Leaving SocialIdps.blueskyToken(). DPoP.");
      return;
    }
    const code = String(form.code || "");
    const grant = this.codes.get(code) || null;
    if (!grant || grant.id !== "bluesky") {
      oauthError(res, 400, "invalid_grant");
      log.debug("Leaving SocialIdps.blueskyToken(). No code.");
      return;
    }
    if (!redirectMatches(grant, form)) {
      this.codes.delete(code);
      oauthError(res, 400, "invalid_grant");
      log.debug("Leaving SocialIdps.blueskyToken(). Redirect.");
      return;
    }
    if (!pkceOk(grant, form.code_verifier || "")) {
      this.codes.delete(code);
      oauthError(res, 400, "invalid_grant");
      log.debug("Leaving SocialIdps.blueskyToken(). PKCE.");
      return;
    }
    this.codes.delete(code);
    const access = "at-" + crypto.randomBytes(16).toString("hex");
    util.sendJson(res, 200, {
      access_token: access, token_type: "DPoP", expires_in: 300,
      scope: "atproto", sub: BLUESKY_DID
    });
    log.debug("Leaving SocialIdps.blueskyToken().");
  }

  /**
   * The PLC document for this dummy's one DID.
   *
   * @param {object} res - the response
   * @param {string} did - the path's DID
   */
  blueskyPlc(res, did) {
    log.debug("Entering SocialIdps.blueskyPlc().");
    if (did !== BLUESKY_DID) {
      util.sendError(res, 404, "No such DID",
        "This dummy's directory has one DID.");
      log.debug("Leaving SocialIdps.blueskyPlc(). None.");
      return;
    }
    util.sendJson(res, 200, {
      id: BLUESKY_DID,
      service: [{
        id: "#atproto_pds",
        type: "AtprotoPersonalDataServer",
        serviceEndpoint: this.publicUrl + "/social/bluesky/pds"
      }]
    });
    log.debug("Leaving SocialIdps.blueskyPlc().");
  }

  /**
   * The data server's protected-resource document, naming this issuer.
   *
   * @param {object} res - the response
   */
  blueskyResource(res) {
    log.debug("Entering SocialIdps.blueskyResource().");
    util.sendJson(res, 200, {
      authorization_servers: [this.issuer("bluesky")]
    });
    log.debug("Leaving SocialIdps.blueskyResource().");
  }

  /**
   * The public profile. A different actor is an empty document, which
   * costs the name and not the sign-in.
   *
   * @param {object} res - the response
   * @param {URL} url - the request
   */
  blueskyProfile(res, url) {
    log.debug("Entering SocialIdps.blueskyProfile().");
    const actor = url.searchParams.get("actor") || "";
    const body = actor === BLUESKY_DID ? {
      did: BLUESKY_DID, handle: "ada.bsky.social",
      displayName: "Ada Bluesky", avatar: PICTURE
    } : {};
    util.sendJson(res, 200, body);
    log.debug("Leaving SocialIdps.blueskyProfile().");
  }
}

module.exports = { SocialIdps: SocialIdps };
