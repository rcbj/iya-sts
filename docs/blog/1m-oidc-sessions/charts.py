# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# Generates the post's charts from the sessions-1m load log:
#   python3 charts.py <sessions.log> <output dir>
import re, sys, os, datetime as dt, statistics as st
LOG = sys.argv[1]; OUT = sys.argv[2]
os.makedirs(OUT, exist_ok=True)
rx = re.compile(r'^(\S+ \S+) last 60 s: ([\d.]+) sign-ins/s, ([\d.]+) refreshes/s \| signed in (\d+)/.*?logins \d+ \(([\d.]+)/s, p95 (\d+) ms\).*?refreshes \d+ \(([\d.]+)/s, p95 (\d+) ms\)')
rows = []
for l in open(LOG):
    m = rx.match(l)
    if m:
        t = dt.datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
        rows.append((t, float(m.group(2)), float(m.group(3)), int(m.group(4)),
                     int(m.group(6)), int(m.group(8))))
# 15-minute buckets
B = {}
for r in rows:
    k = r[0].replace(minute=r[0].minute // 15 * 15, second=0)
    B.setdefault(k, []).append(r)
pts = []
for k in sorted(B):
    v = B[k]
    pts.append((k, st.mean(x[1] for x in v), st.mean(x[2] for x in v),
                max(x[3] for x in v), st.median(x[4] for x in v),
                st.median(x[5] for x in v)))
T0 = dt.datetime(2026, 10, 20, 22, 0); T1 = dt.datetime(2026, 10, 22, 18, 0)
INK = '#1f2933'; GRID = '#e4e7eb'; MUTED = '#616e7c'
C1 = '#2f6fb0'; C2 = '#d4691f'; C3 = '#3c8d4f'
EVENTS = [(dt.datetime(2026,10,21,16,32), 'on-demand stores'),
          (dt.datetime(2026,10,22,4,50), 'status list full'),
          (dt.datetime(2026,10,22,6,22), 'final build'),
          (dt.datetime(2026,10,22,11,30), '1M signed in')]
def svg_line(name, title, series, ymax, yfmt, ylabel, log=False, events=True):
    W, H, L, R, T, Bm = 900, 340, 70, 20, 40, 50
    pw, ph = W - L - R, H - T - Bm
    sx = lambda t: L + (t - T0).total_seconds() / (T1 - T0).total_seconds() * pw
    sy = lambda v: T + ph - min(v, ymax) / ymax * ph
    o = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" font-family="Helvetica, Arial, sans-serif" font-size="12">' % (W, H),
         '<!-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC -->',
         '<!-- SPDX-License-Identifier: BUSL-1.1 -->',
         '<rect width="%d" height="%d" fill="#ffffff"/>' % (W, H),
         '<text x="%d" y="22" font-size="15" font-weight="bold" fill="%s">%s</text>' % (L, INK, title)]
    for i in range(5):
        v = ymax * i / 4; y = sy(v)
        o.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="%s"/>' % (L, W - R, y, y, GRID))
        o.append('<text x="%d" y="%.1f" text-anchor="end" fill="%s">%s</text>' % (L - 6, y + 4, MUTED, yfmt(v)))
    t = T0
    while t <= T1:
        x = sx(t)
        o.append('<line x1="%.1f" x2="%.1f" y1="%d" y2="%d" stroke="%s"/>' % (x, x, T + ph, T + ph + 4, MUTED))
        o.append('<text x="%.1f" y="%d" text-anchor="middle" fill="%s">%s</text>' % (x, T + ph + 18, MUTED, t.strftime('%b %d %H:%M')))
        t += dt.timedelta(hours=6)
    o.append('<text x="%d" y="%d" text-anchor="middle" fill="%s">time (UTC); gaps are restarts and pauses</text>' % (L + pw / 2, H - 8, MUTED))
    o.append('<text transform="translate(16 %d) rotate(-90)" text-anchor="middle" fill="%s">%s</text>' % (T + ph / 2, MUTED, ylabel))
    if events:
        for ei, (when, label) in enumerate(EVENTS):
            x = sx(when)
            o.append('<line x1="%.1f" x2="%.1f" y1="%d" y2="%d" stroke="%s" stroke-dasharray="3 3"/>' % (x, x, T, T + ph, MUTED))
            o.append('<text x="%.1f" y="%d" fill="%s" font-size="11">%s</text>' % (x + 3, T + 12 + (ei % 2) * 14, MUTED, label))
    lx = W - R - 10 - 200 * (len(series) - 1)
    for idx, (label, color, vals) in enumerate(series):
        segs = []; cur = []; prev = None
        for t, v in vals:
            if prev and (t - prev).total_seconds() > 1800:
                segs.append(cur); cur = []
            cur.append('%.1f,%.1f' % (sx(t), sy(v))); prev = t
        segs.append(cur)
        for s in segs:
            if len(s) > 1:
                o.append('<polyline fill="none" stroke="%s" stroke-width="2" points="%s"/>' % (color, ' '.join(s)))
            elif s:
                x, y = s[0].split(',')
                o.append('<circle cx="%s" cy="%s" r="2" fill="%s"/>' % (x, y, color))
        o.append('<rect x="%d" y="%d" width="12" height="3" fill="%s"/>' % (lx - 150 + idx * 200, 16, color))
        o.append('<text x="%d" y="%d" fill="%s">%s</text>' % (lx - 134 + idx * 200, 21, INK, label))
    o.append('</svg>')
    open(os.path.join(OUT, name), 'w').write('\n'.join(o) + '\n')
svg_line('signed-in.svg', 'People signed in (sessions held)',
         [('signed in', C1, [(p[0], p[3]) for p in pts])], 1000000,
         lambda v: '%dk' % (v / 1000), 'people')
svg_line('rates.svg', 'Sign-ins and refreshes per second (15-minute mean)',
         [('sign-ins / s', C1, [(p[0], p[1]) for p in pts]),
          ('refreshes / s', C2, [(p[0], p[2]) for p in pts])], 50,
         lambda v: '%d' % v, 'per second')
svg_line('latency.svg', 'Client-measured p95: a whole sign-in, and a refresh',
         [('sign-in p95 (5 requests)', C1, [(p[0], p[4]) for p in pts]),
          ('refresh p95', C2, [(p[0], p[5]) for p in pts])], 6000,
         lambda v: '%.1f s' % (v / 1000), 'seconds')
# Stacked bars: the five requests, before and after
before = [('GET /oauth2/authorize', 17, 7, 16, 66, 129), ('GET /authn-api/pending', 6, 3, 2, 32, 51),
          ('POST /authn-api/pending', 6, 4, 214, 54, 299), ('GET /oauth2/authorize', 17, 7, 16, 66, 129),
          ('POST /oauth2/token', 26, 8, 66, 59, 181)]
after = [('GET /oauth2/authorize', 7, 5, 11, 39, 85), ('GET /authn-api/pending', 0, 4, 2, 31, 49),
         ('POST /authn-api/pending', 0, 4, 154, 28, 201), ('GET /oauth2/authorize', 7, 5, 11, 39, 85),
         ('POST /oauth2/token', 37, 7, 56, 47, 175)]
PH = [('read-your-write wait', '#8e6bbf'), ('queue', '#9aa5b1'), ('handler', C1), ('commit wait', C2)]
W, H = 900, 500; L = 230; scale = 0.9
o = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" font-family="Helvetica, Arial, sans-serif" font-size="12">' % (W, H),
     '<!-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC -->',
     '<!-- SPDX-License-Identifier: BUSL-1.1 -->',
     '<rect width="%d" height="%d" fill="#ffffff"/>' % (W, H),
     '<text x="20" y="24" font-size="15" font-weight="bold" fill="%s">The five requests of one sign-in, p50 ms by phase</text>' % INK]
y = 50
for heading, data in (('Before (2026-10-22 03:00 UTC, ~16 sign-ins/s)', before), ('After (06:40 UTC, ~21 sign-ins/s)', after)):
    o.append('<text x="20" y="%d" font-weight="bold" fill="%s">%s</text>' % (y + 12, INK, heading)); y += 22
    tot = 0
    for i, (route, *vals) in enumerate(data):
        measured = vals.pop()
        o.append('<text x="%d" y="%d" text-anchor="end" fill="%s">%d. %s</text>' % (L - 8, y + 13, INK, i + 1, route))
        x = L
        for (lab, col), v in zip(PH, vals):
            w = v * scale
            o.append('<rect x="%.1f" y="%d" width="%.1f" height="18" fill="%s"/>' % (x, y, w, col)); x += w
        tot += measured
        o.append('<text x="%.1f" y="%d" fill="%s">total p50 %d ms</text>' % (x + 6, y + 13, INK, measured)); y += 24
    o.append('<text x="%d" y="%d" text-anchor="end" font-weight="bold" fill="%s">one sign-in</text>' % (L - 8, y + 13, INK))
    o.append('<text x="%d" y="%d" font-weight="bold" fill="%s">~%d ms (sum of the totals)</text>' % (L, y + 13, INK, tot)); y += 34
lx = L
for lab, col in PH:
    o.append('<rect x="%d" y="%d" width="12" height="12" fill="%s"/>' % (lx, y, col))
    o.append('<text x="%d" y="%d" fill="%s">%s</text>' % (lx + 16, y + 10, INK, lab)); lx += 170
o.append('<text x="20" y="%d" fill="%s" font-size="11">Bars are each phase&#8217;s p50; a request&#8217;s total p50 also covers time outside these phases, and p50s do not add exactly.</text>' % (y + 34, MUTED))
o.append('</svg>')
open(os.path.join(OUT, 'signin-breakdown.svg'), 'w').write('\n'.join(o) + '\n')
# Database
def bars(name, title, items, unit, note):
    W = 900; H = 70 + 30 * len(items) + 30; L = 230; mx = max(v for _, v in items)
    o = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" font-family="Helvetica, Arial, sans-serif" font-size="12">' % (W, H),
         '<!-- SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC -->',
         '<!-- SPDX-License-Identifier: BUSL-1.1 -->',
         '<rect width="%d" height="%d" fill="#ffffff"/>' % (W, H),
         '<text x="20" y="24" font-size="15" font-weight="bold" fill="%s">%s</text>' % (INK, title)]
    y = 46
    for lab, v in items:
        w = v / mx * 560
        o.append('<text x="%d" y="%d" text-anchor="end" fill="%s">%s</text>' % (L - 8, y + 14, INK, lab))
        o.append('<rect x="%d" y="%d" width="%.1f" height="20" fill="%s"/>' % (L, y, w, C1))
        o.append('<text x="%.1f" y="%d" fill="%s">%s %s</text>' % (L + w + 6, y + 14, INK, ('%g' % v), unit)); y += 30
    o.append('<text x="20" y="%d" fill="%s" font-size="11">%s</text>' % (y + 16, MUTED, note))
    o.append('</svg>')
    open(os.path.join(OUT, name), 'w').write('\n'.join(o) + '\n')
bars('db-growth.svg', 'Database size as the population grew',
     [('Oct 14: 1M directory entries', 1.2), ('Oct 14: 10M entries', 7.7), ('Oct 15: 50M entries', 37),
      ('Oct 22: 50M entries + 1M sessions', 168)], 'GB',
     'The first three are compressed backups (pg_dump) taken at each milestone; the last is the live database on disk (pg_database_size), indexes included.')
bars('db-tables.svg', 'Where the 168 GB is (Oct 22, after the soak)',
     [('directory entries (50.2M)', 116), ('minted state (19.3M)', 26), ('minted index (39.2M)', 16),
      ('risk counters (9.6M)', 2.8), ('risk assessments (1.0M)', 1.8), ('geolocation ranges (7.8M)', 1.6),
      ('everything else', 3.8)], 'GB', 'Total size of each table with its indexes and TOAST; row counts are postgres estimates.')
print(len(rows), 'minute lines,', len(pts), 'buckets')
