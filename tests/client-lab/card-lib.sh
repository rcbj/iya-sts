# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/client-lab/card-lib.sh
#
# ---------------------------------------------------------------------------
# HOW THE CLIENT LAB PLUGS A CARD IN (#2056), sourced by lab-start.sh and
# bin/lab-piv-card. A card is a jcardsim VSmartCard process holding one
# applet, connected to its vpcd slot; once it is in the reader the applet is
# installed with jcardsim's own CREATE APPLET command, because jcardsim's
# configuration file only LOADS an applet (Simulator's constructor) and an
# APDU is how one is installed.
#
#   slot 0  127.0.0.1:35963  OpenPGP (SmartPGP)            "Virtual PCD 00 00"
#   slot 1  127.0.0.1:35964  PIV (PivApplet, yubikey|stock) "Virtual PCD 00 01"
#
# Every start of a card is a factory-fresh card: jcardsim keeps an applet's
# state in memory only.
# ---------------------------------------------------------------------------

LAB=/opt/client-lab
CARDS=/opt/cards
RUN=/run/client-lab
PGP_READER='Virtual PCD 00 00'
PIV_READER='Virtual PCD 00 01'
PIV_AID='A000000308000010000100'
# THE ATRs. jcardsim's default, 3B80800101, is in OpenSC 0.23's table as a
# PIVKey card (card-piv.c's piv_atrs), and OpenSC turns EC off for every
# PIVKey (CI_NO_EC): a P-256 key on the card then has no signing mechanism
# at all (CKR_MECHANISM_INVALID). So each card answers an ATR of its own:
#   * the yubikey PIV card a YubiKey 5 NFC's, whose historical bytes carry
#     "YubiKey" in compact-TLV tag 5 (developers.yubico.com/PIV/
#     Introduction/Yubico_extensions.html), which OpenSC reads as a
#     YubiKey 5 — as it would the real one;
#   * the stock PIV card a generic one no table names (historical bytes
#     "LabPIV01", T=1, its check byte computed);
#   * the OpenPGP card jcardsim's default, which only scdaemon reads.
ATR_DEFAULT='3B80800101'
ATR_YUBIKEY5='3BFD1300008131FE158073C021C057597562694B657940'
ATR_GENERIC_PIV='3B8880014C6162504956303108'

say() {
  echo "client-lab: $*"
}

# One jcardsim configuration per card (VSmartCard reads a properties file).
card_config() {
  local aid="$1" class="$2" port="$3" reloader="$4" atr="$5"
  cat <<EOF
com.licel.jcardsim.card.applet.0.AID=${aid}
com.licel.jcardsim.card.applet.0.Class=${class}
com.licel.jcardsim.card.ATR=${atr}
com.licel.jcardsim.vsmartcard.host=127.0.0.1
com.licel.jcardsim.vsmartcard.port=${port}
com.licel.jcardsim.vsmartcard.reloader.port=${reloader}
EOF
}

# A card's CREATE APPLET command, jcardsim's own (CardManager: 80 B8 00 00,
# then the AID's length, the AID, and an empty parameter block).
create_apdu() {
  local aid="$1"
  local len=$(( ${#aid} / 2 ))
  local body
  body="$(printf '%02X' "${len}")${aid}00"
  printf '80B80000%02X%s' $(( ${#body} / 2 )) "${body}"
}

# opensc-tool takes an APDU as colon-separated bytes.
colons() {
  echo "$1" | sed 's/../&:/g; s/:$//'
}

# Whether a card is in a reader, as pcscd sees it.
card_present() {
  opensc-tool -l 2>/dev/null | grep -q "Yes.*$1"
}

# Takes a card out: its jcardsim process stopped, and the reader empty.
stop_card() {
  local name="$1" reader="$2"
  if [ -f "${RUN}/${name}.pid" ]; then
    kill "$(cat "${RUN}/${name}.pid")" 2>/dev/null || true
    rm -f "${RUN}/${name}.pid" "${RUN}/${name}.install"
  fi
  local i
  for i in $(seq 1 40); do
    if ! card_present "${reader}"; then
      return 0
    fi
    sleep 0.25
  done
  say "the ${name} card is still in ${reader}"
  return 1
}

start_card() {
  local name="$1" aid="$2" class="$3" classes="$4" port="$5" reloader="$6"
  local reader="$7" atr="${8:-${ATR_DEFAULT}}"
  card_config "${aid}" "${class}" "${port}" "${reloader}" "${atr}" \
    > "${RUN}/${name}.cfg"
  say "starting the ${name} card (${classes}) on ${reader} (port ${port})"
  java -cp "${CARDS}/${classes}:${CARDS}/jcardsim.jar" \
    com.licel.jcardsim.remote.VSmartCard "${RUN}/${name}.cfg" \
    > "${RUN}/${name}.log" 2>&1 &
  echo $! > "${RUN}/${name}.pid"
  local i
  for i in $(seq 1 60); do
    if card_present "${reader}"; then
      break
    fi
    sleep 0.5
  done
  if ! card_present "${reader}"; then
    say "the ${name} card did not appear in ${reader}"
    cat "${RUN}/${name}.log"
    return 1
  fi
  local apdu
  apdu="$(create_apdu "${aid}")"
  say "installing ${class} as ${aid}"
  opensc-tool -r "${reader}" -s "$(colons "${apdu}")" \
    > "${RUN}/${name}.install.out" 2>&1 || true
  if ! grep -q "SW1=0x90, SW2=0x00" "${RUN}/${name}.install.out"; then
    say "the ${name} applet did not install"
    cat "${RUN}/${name}.install.out" "${RUN}/${name}.log"
    return 1
  fi
  mv "${RUN}/${name}.install.out" "${RUN}/${name}.install"
}

# The OpenPGP card. Its AID carries the card's serial (OpenPGP card 3.4
# section 4.2.1), made here, so every start is a card of its own.
start_openpgp_card() {
  local serial
  serial="$(openssl rand -hex 4 | tr 'a-f' 'A-F')"
  echo "${serial}" > "${RUN}/openpgp-serial"
  start_card openpgp "D276000124010304AFAF${serial}0000" \
    fr.anssi.smartpgp.SmartPGPApplet smartpgp 35963 8099 "${PGP_READER}"
}

# The PIV card: `yubikey` (PivApplet patched to attest as a YubiKey 5, the
# default) or `stock` (PivApplet as published, whose attestation the
# service refuses).
start_piv_card() {
  local variant="${1:-yubikey}"
  case "${variant}" in
    yubikey|stock)
      ;;
    *)
      say "a PIV card is yubikey or stock, not ${variant}"
      return 1
      ;;
  esac
  local atr="${ATR_YUBIKEY5}"
  if [ "${variant}" = "stock" ]; then
    atr="${ATR_GENERIC_PIV}"
  fi
  start_card piv "${PIV_AID}" net.cooperi.pivapplet.PivApplet \
    "pivapplet-${variant}" 35964 8098 "${PIV_READER}" "${atr}"
  echo "${variant}" > "${RUN}/piv-variant"
}
