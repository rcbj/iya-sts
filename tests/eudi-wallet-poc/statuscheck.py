# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

# Reads a Token Status List (draft-ietf-oauth-status-list) and prints the
# status of each index given: python3 -I statuscheck.py <url> idx...
import sys, ssl, json, base64, zlib, urllib.request
url, idxs = sys.argv[1], [int(i) for i in sys.argv[2:]]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request(url, headers={'Accept': 'application/statuslist+jwt'})
with urllib.request.urlopen(req, context=ctx) as r:
    ctype, body = r.headers.get('Content-Type'), r.read().decode()
seg = lambda s: json.loads(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)))
h, p = seg(body.split('.')[0]), seg(body.split('.')[1])
sl = p['status_list']; bits = sl['bits']
lst = zlib.decompress(base64.urlsafe_b64decode(sl['lst'] + '=' * (-len(sl['lst']) % 4)))
names = {0: 'VALID', 1: 'INVALID', 2: 'SUSPENDED'}
print(f"{ctype}  typ={h.get('typ')} alg={h.get('alg')} sub={p.get('sub')} iat={p.get('iat')} exp={p.get('exp')} ttl={p.get('ttl')} bits={bits} entries={len(lst)*8//bits}")
for i in idxs:
    per = 8 // bits; v = (lst[i // per] >> ((i % per) * bits)) & ((1 << bits) - 1)
    print(f"  idx {i}: {v} {names.get(v, '?')}")
