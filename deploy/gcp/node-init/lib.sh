# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/gcp/node-init/lib.sh
#
# Secret Manager over REST, with the VM's own credentials — what both
# commands in this image share. Sourced, never run.

METADATA="http://metadata.google.internal/computeMetadata/v1"
SECRETS_API="https://secretmanager.googleapis.com/v1"

# The VM service account's access token, from the metadata server. Fetched
# per call: a token lasts an hour and these commands take seconds, except an
# ACME issuance, which is why it is not cached.
sts_token() {
  curl -fsS -H 'Metadata-Flavor: Google' \
    "${METADATA}/instance/service-accounts/default/token" | jq -r .access_token
}

# The payload of `<secret>/versions/latest`, decoded, on stdout. Exit 3 when
# the secret has no enabled version (a 404 or a FAILED_PRECONDITION), any
# other failure non-zero — the caller tells "not issued yet" from "broken".
sts_secret_read() {
  local secret="$1" out code
  out="$(mktemp)"
  code="$(curl -sS -o "${out}" -w '%{http_code}' \
    -H "Authorization: Bearer $(sts_token)" \
    "${SECRETS_API}/${secret}/versions/latest:access")" || {
      rm -f "${out}"
      return 1
    }
  case "${code}" in
    200)
      jq -r .payload.data "${out}" | base64 -d
      rm -f "${out}"
      return 0
      ;;
    404|400)
      rm -f "${out}"
      return 3
      ;;
    *)
      echo "sts-init: reading ${secret} answered HTTP ${code}:" >&2
      cat "${out}" >&2
      rm -f "${out}"
      return 1
      ;;
  esac
}

# A new version of <secret> holding the file <path>; prints the new
# version's resource name.
sts_secret_add() {
  local secret="$1" path="$2"
  jq -n --arg d "$(base64 -w0 < "${path}")" '{ payload: { data: $d } }' |
    curl -fsS -X POST \
      -H "Authorization: Bearer $(sts_token)" \
      -H 'Content-Type: application/json' \
      --data @- \
      "${SECRETS_API}/${secret}:addVersion" | jq -r .name
}

# Every ENABLED version of <secret> except <keep> is disabled: the old key
# can no longer be read, and a disabled version costs nothing.
sts_secret_disable_others() {
  local secret="$1" keep="$2" v
  for v in $(curl -fsS -H "Authorization: Bearer $(sts_token)" \
               "${SECRETS_API}/${secret}/versions?filter=state:ENABLED" |
             jq -r '.versions[]?.name');
  do
    [ "${v}" = "${keep}" ] && continue
    curl -fsS -X POST -H "Authorization: Bearer $(sts_token)" \
      -H 'Content-Type: application/json' --data '{}' \
      "${SECRETS_API}/${v}:disable" > /dev/null
    echo "sts-cert: disabled ${v}."
  done
}
