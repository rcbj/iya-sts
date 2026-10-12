// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_portal_pages.ts
//
// ---------------------------------------------------------------------------
// EVERY PAGE OF THE USER PORTAL, AS THE BROWSER DRAWS IT (#568).
//
// One row per page: the path the browser shows, the `/account-api`
// operation whose GET answers its view, and the renderer that draws the view
// (`types/account-api.d.ts`, `PortalPage`). Each family of pages lists its
// own rows in its own `web_` module, beside the renderers; this file only
// gathers them, in the order the column lists the pages — the console's
// `web_pages.ts`, for the portal.
//
// It is also the bundle `tests/portal_web_bundle.js` loads: the renderers
// under one global, `StsPortal`, so a test draws every page from the answer
// its operation gives in process.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import OverviewPages = require('./web_overview');
import SignInsPages = require('./web_sign_ins');
import ConsentsPages = require('./web_consents');
import GnapPages = require('./web_gnap');
import MailPages = require('./web_mail');
import PasswordPages = require('./web_password');
import KeysPages = require('./web_keys');
import MfaPages = require('./web_mfa');
import SigningKeyPages = require('./web_signing_key');
import CertificatesPages = require('./web_certificates');
import AppPasswordsPages = require('./web_app_passwords');
import KerberosPages = require('./web_kerberos');
import DelegatePages = require('./web_delegate');
import SelfIssuedPages = require('./web_self_issued');
import WalletPages = require('./web_wallet');
import DevicesPages = require('./web_devices');
import CibaPages = require('./web_ciba');
import DevicePages = require('./web_device');
import ClaimSourcesPages = require('./web_claim_sources');
import ActivationPages = require('./web_activation');
import ResetPages = require('./web_reset');

import WebMessages = require('../common/web_messages');
import PortalShell = require('./web_portal_shell');
import PortalKit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PAGES: PortalPage[] = [].concat(
  OverviewPages.PAGES,
  SignInsPages.PAGES,
  ConsentsPages.PAGES,
  GnapPages.PAGES,
  MailPages.PAGES,
  PasswordPages.PAGES,
  KeysPages.PAGES,
  MfaPages.PAGES,
  SigningKeyPages.PAGES,
  CertificatesPages.PAGES,
  AppPasswordsPages.PAGES,
  KerberosPages.PAGES,
  DelegatePages.PAGES,
  SelfIssuedPages.PAGES,
  WalletPages.PAGES,
  DevicesPages.PAGES,
  CibaPages.PAGES,
  DevicePages.PAGES,
  ClaimSourcesPages.PAGES,
  ActivationPages.PAGES,
  ResetPages.PAGES);

/**
 * The portal's pages. A static utility class.
 */
class PortalPages {
  /**
   * Every page.
   */
  static readonly PAGES = PAGES;
  /**
   * The message formatter and translator, so a test that loads the bundle
   * builds the reader's translator as the runtime does.
   */
  static readonly messages = WebMessages;
  /**
   * The frame and the kit, so a test draws a whole page — the column, its
   * `aria-current`, Refresh and Sign out — as the runtime does.
   */
  static readonly shell = PortalShell;
  static readonly kit = PortalKit;

  /**
   * The page a path names, or null.
   *
   * @param path - the path under the realm, \`/portal/...\`
   * @returns the row, or null
   */
  static find(path: string): PortalPage | null {
    return PAGES.filter(function (row: PortalPage): boolean {
      return row.path === path;
    })[0] || null;
  }

  /**
   * Draws a page's body from its view.
   *
   * @param path - the page's path
   * @param view - its operation's answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(path: string, view: Json, ctx: Json): string {
    const row = PortalPages.find(path);
    return row ? row.render(view, ctx) : '';
  }
}

export = PortalPages;
