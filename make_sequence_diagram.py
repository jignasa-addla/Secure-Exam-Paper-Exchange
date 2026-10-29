#!/usr/bin/env python3
"""make_sequence_diagram.py -- renders sequence_diagram.svg (sequence of events)."""

from html import escape
from pathlib import Path

W = 1360
X = {"S": 230, "C": 680, "R": 1130}          # lifeline x positions
NAMES = {"S": ("Faculty / Sender", "(sender app)"),
         "C": ("Untrusted channel", "(attacker may read / modify / replace)"),
         "R": ("Exam Coordinator / Recipient", "(recipient app)")}
BOX_W = 400
ROW = 54

INK, MUTED, LINE = "#1f2933", "#52606d", "#9aa5b1"
BLUE, GREEN, RED, AMBER = "#1d4ed8", "#15803d", "#b91c1c", "#b45309"

# event = (kind, ...)
EVENTS = [
    ("phase", "PHASE 0 - Setup (once)  -  public keys exchanged over a TRUSTED channel"),
    ("self", "S", ["Generate RSA-4096 key pair (S_priv, S_pub)", "S_priv stored encrypted (PKCS#8, 0600)"]),
    ("self", "R", ["Generate RSA-4096 key pair (R_priv, R_pub)", "R_priv stored encrypted (PKCS#8, 0600)"]),
    ("trust", "S", "R", "S_pub  (trusted channel, fingerprint checked)"),
    ("trust", "R", "S", "R_pub  (trusted channel, fingerprint checked)"),

    ("phase", "PHASE 1 - Sender protects the examination paper"),
    ("self", "S", ["1. Read exam paper P"]),
    ("self", "S", ["2. Generate FRESH AES-256 session key K", "and FRESH 96-bit nonce N"]),
    ("self", "S", ["3. AES-256-GCM encrypt P with (K, N),", "AAD = metadata  ->  ciphertext C + tag T"]),
    ("self", "S", ["4. Wrap K with R_pub: RSA-OAEP (SHA-256)", "->  EK"]),
    ("self", "S", ["5. Assemble package", "{ metadata, EK, N, C, T }"]),
    ("self", "S", ["6. Sign the COMPLETE package with S_priv:", "RSA-PSS (SHA-256)  ->  SIG"]),

    ("phase", "PHASE 2 - Transfer over the untrusted channel"),
    ("msg", "S", "C", "package.exampkg  { metadata, EK, N, C, T, SIG }"),
    ("self", "C", ["Attacker can READ (sees only ciphertext),", "MODIFY, REPLACE or REPLAY the package"]),
    ("msg", "C", "R", "package.exampkg  (genuine or tampered)"),

    ("phase", "PHASE 3 - Recipient verifies FIRST, decrypts only if every check passes"),
    ("self", "R", ["7. Parse package, check format / version"], "malformed -> REJECT"),
    ("self", "R", ["8. Verify SIG with TRUSTED S_pub", "(RSA-PSS, SHA-256)"], "invalid -> REJECT"),
    ("self", "R", ["9. Replay check (package_id ledger)"], "seen before -> REJECT"),
    ("self", "R", ["10. Unwrap K with R_priv", "(RSA-OAEP, SHA-256)"], "wrong key -> REJECT"),
    ("self", "R", ["11. AES-256-GCM decrypt with (K, N, AAD)", "verify tag T"], "tag bad -> REJECT"),
    ("final", "R", ["12. ALL checks passed: release plaintext P", "to the coordinator (write to disk)"]),
]


def layout():
    y, out = 150, []
    for ev in EVENTS:
        kind = ev[0]
        h = {"phase": 34, "self": ROW, "msg": ROW - 6, "trust": ROW - 6, "final": ROW}[kind]
        out.append((ev, y, h))
        y += h + (10 if kind != "phase" else 8)
    return out, y + 20


def text_lines(x, y, lines, size=13, weight="normal", fill=INK, anchor="middle"):
    n = len(lines)
    start = y - (n - 1) * (size + 3) / 2 + size * 0.35
    parts = []
    for i, ln in enumerate(lines):
        parts.append(f'<text x="{x}" y="{start + i * (size + 3):.1f}" font-size="{size}" '
                     f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{escape(ln)}</text>')
    return "\n".join(parts)


def build():
    items, H = layout()
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
         f'font-family="Helvetica, Arial, sans-serif">',
         '<defs>'
         f'<marker id="aB" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{BLUE}"/></marker>'
         f'<marker id="aG" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{GREEN}"/></marker>'
         f'<marker id="aR" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{RED}"/></marker>'
         '</defs>',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
         f'<text x="{W/2}" y="34" font-size="22" font-weight="bold" fill="{INK}" text-anchor="middle">'
         'Secure Examination-Paper Exchange - Sequence of Events</text>',
         f'<text x="{W/2}" y="58" font-size="13" fill="{MUTED}" text-anchor="middle">'
         'AES-256-GCM (confidentiality + integrity)   |   RSA-OAEP / SHA-256 (session-key protection)   |   '
         'RSA-PSS / SHA-256 (sender authentication)</text>']

    # lifelines + headers
    for k, x in X.items():
        s.append(f'<line x1="{x}" y1="132" x2="{x}" y2="{H - 14}" stroke="{LINE}" stroke-width="2" stroke-dasharray="6 5"/>')
        fill = "#fee2e2" if k == "C" else ("#dbeafe" if k == "S" else "#dcfce7")
        edge = RED if k == "C" else (BLUE if k == "S" else GREEN)
        s.append(f'<rect x="{x - 150}" y="76" width="300" height="54" rx="8" fill="{fill}" stroke="{edge}" stroke-width="2"/>')
        s.append(text_lines(x, 96, [NAMES[k][0]], 15, "bold"))
        s.append(text_lines(x, 117, [NAMES[k][1]], 12, "normal", MUTED))

    for ev, y, h in items:
        kind = ev[0]
        if kind == "phase":
            s.append(f'<rect x="20" y="{y}" width="{W - 40}" height="{h}" rx="5" fill="#eef2f7" stroke="#cbd2d9"/>')
            s.append(text_lines(34, y + h / 2, [ev[1]], 13, "bold", INK, "start"))
        elif kind in ("self", "final"):
            k, lines = ev[1], ev[2]
            cx = X[k]
            col = GREEN if kind == "final" else (RED if k == "C" else (BLUE if k == "S" else INK))
            fill = "#dcfce7" if kind == "final" else ("#fee2e2" if k == "C" else "#ffffff")
            s.append(f'<rect x="{cx - BOX_W/2}" y="{y}" width="{BOX_W}" height="{h}" rx="7" fill="{fill}" '
                     f'stroke="{col}" stroke-width="1.6"/>')
            s.append(text_lines(cx, y + h / 2, lines, 13, "bold" if kind == "final" else "normal"))
            if len(ev) > 3:  # failure branch to the left of the recipient box
                x1, x2 = cx - BOX_W / 2, cx - BOX_W / 2 - 170
                s.append(f'<line x1="{x1}" y1="{y + h/2}" x2="{x2}" y2="{y + h/2}" stroke="{RED}" '
                         f'stroke-width="1.8" stroke-dasharray="5 3" marker-end="url(#aR)"/>')
                s.append(f'<rect x="{x2 - 168}" y="{y + h/2 - 15}" width="164" height="30" rx="6" fill="#fee2e2" stroke="{RED}"/>')
                s.append(text_lines(x2 - 86, y + h / 2, [ev[3]], 12, "bold", RED))
        elif kind in ("msg", "trust"):
            a, b, label = ev[1], ev[2], ev[3]
            col, mk, dash = (AMBER, "aG", ' stroke-dasharray="8 4"') if kind == "trust" else (BLUE, "aB", "")
            if kind == "trust":
                mk, col = "aG", GREEN
            y_line = y + h - 12
            x1 = X[a] + (6 if X[b] > X[a] else -6)
            x2 = X[b] + (-6 if X[b] > X[a] else 6)
            s.append(f'<line x1="{x1}" y1="{y_line}" x2="{x2}" y2="{y_line}" stroke="{col}" stroke-width="2.4"{dash} marker-end="url(#{mk})"/>')
            mid = (x1 + x2) / 2
            s.append(f'<rect x="{mid - 6.4 * len(label) / 2 - 8:.0f}" y="{y_line - 28}" width="{6.4 * len(label) + 16:.0f}" height="20" rx="4" fill="#ffffff"/>')
            s.append(text_lines(mid, y_line - 17, [label], 13, "bold" if kind == "msg" else "normal", col))
    s.append("</svg>")
    return "\n".join(s)


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "sequence_diagram.svg"
    out.write_text(build(), encoding="utf-8")
    print(f"wrote {out}")
