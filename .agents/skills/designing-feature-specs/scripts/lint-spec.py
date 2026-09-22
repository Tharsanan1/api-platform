#!/usr/bin/env python3
"""
lint-spec.py — structural and cross-reference lint for a feature spec.

Belongs to the `designing-feature-specs` skill.

Usage:
  python3 lint-spec.py <spec.md> [--ids D,S,O,N,G,A,Q] [--allow-marker <substring>]... [--quiet]

Checks
  * code fences balanced
  * `##` sections numbered 1..n in order; `###` and `####` consecutive under their parent
  * no duplicate headings
  * every table: separator row present, consistent pipe count per row (pipes inside backticks
    ignored), blank line before the table
  * `---` separators and headings surrounded by blank lines; no doubled separators
  * every §x / §x.y / §x.y.z reference resolves to a heading
  * every identifier reference (default D, S, O, N, G, A, Q) resolves to a definition
  * relative markdown links resolve on disk
  * residual provisional markers: (proposed), '— verify', '(verify)', 'verify in/before/during X',
    UNVERIFIED, TODO, FIXME — listed (lines containing an --allow-marker substring are ignored,
    for rules that quote the words or spike items deliberately left open)

Identifier definitions are recognised in these shapes:
  D/S/O   a table row starting `| D3 |`
  N/G     a list item starting `- N2.` / `- G1.`
  A       a heading `### A.4 `
  Q       bold `**Q-B` at the start of an open-question entry
Exit code 1 if any issue is found.
"""
import argparse, os, re, sys
from collections import defaultdict

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("spec")
    ap.add_argument("--ids", default="D,S,O,N,G,A,Q")
    ap.add_argument("--allow-marker", action="append", default=[])
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    s = open(a.spec, encoding="utf-8").read()
    L = s.split("\n")
    issues = []
    base = os.path.dirname(os.path.abspath(a.spec))

    # ---- fences
    in_fence = [False] * len(L)
    fence = False
    fence_start = None
    for i, l in enumerate(L):
        if l.startswith("```"):
            fence = not fence
            fence_start = i + 1 if fence else None
            in_fence[i] = True
            continue
        in_fence[i] = fence
    if fence:
        issues.append(f"unclosed code fence opened at line {fence_start}")

    def outside(i):
        return not in_fence[i]

    # ---- headings
    h2, h3, h4, allh = [], [], [], []
    for i, l in enumerate(L):
        if not outside(i):
            continue
        if re.match(r"^#{2,4} ", l):
            allh.append((l, i + 1))
        m = re.match(r"^## (\d+)\. ", l)
        if m: h2.append(int(m.group(1)))
        m = re.match(r"^### (\d+)\.(\d+) ", l)
        if m: h3.append((int(m.group(1)), int(m.group(2))))
        m = re.match(r"^#### (\d+)\.(\d+)\.(\d+) ", l)
        if m: h4.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))
    if h2 != list(range(1, len(h2) + 1)):
        issues.append(f"'##' numbering not 1..n in order: {h2}")
    per = defaultdict(list)
    for x, y in h3: per[x].append(y)
    for x, ys in per.items():
        if ys != list(range(1, len(ys) + 1)):
            issues.append(f"'###' under §{x} not consecutive: {ys}")
    per4 = defaultdict(list)
    for x, y, z in h4: per4[(x, y)].append(z)
    for (x, y), zs in per4.items():
        if zs != list(range(1, len(zs) + 1)):
            issues.append(f"'####' under §{x}.{y} not consecutive: {zs}")
    texts = [h for h, _ in allh]
    for h in sorted(set(t for t in texts if texts.count(t) > 1)):
        issues.append(f"duplicate heading: {h}")

    # ---- tables
    i = 0
    while i < len(L):
        if outside(i) and L[i].startswith("|"):
            start = i
            rows = []
            while i < len(L) and L[i].startswith("|"):
                rows.append(L[i]); i += 1
            if len(rows) < 2 or not re.match(r"^\|[\s:|-]+\|$", rows[1]):
                issues.append(f"table at line {start+1}: missing header separator row")
                continue
            def pipes(r): return len(re.findall(r"\|", re.sub(r"`[^`]*`", "", r)))
            n = pipes(rows[0])
            for k, r in enumerate(rows):
                c = pipes(r)
                if c != n:
                    issues.append(f"table at line {start+1}, row {k+1} (line {start+k+1}): {c} pipes vs header {n}")
            if start > 0 and L[start-1].strip() != "":
                issues.append(f"table at line {start+1}: no blank line before it")
            continue
        i += 1

    # ---- separators and heading spacing
    for i, l in enumerate(L):
        if not outside(i):
            continue
        if l.strip() == "---" and i > 8:
            if L[i-1].strip() != "" or (i + 1 < len(L) and L[i+1].strip() != ""):
                issues.append(f"'---' at line {i+1} not surrounded by blank lines")
            if i + 2 < len(L) and L[i+2].strip() == "---":
                issues.append(f"doubled '---' at line {i+1}")
        if re.match(r"^#{2,4} ", l):
            if i > 0 and L[i-1].strip() != "":
                issues.append(f"heading at line {i+1} lacks blank line before: {l[:60]}")
            if i + 1 < len(L) and L[i+1].strip() != "":
                issues.append(f"heading at line {i+1} lacks blank line after: {l[:60]}")

    # ---- § cross-references (refs inside code fences count too: comments cite sections)
    h2n = set(str(x) for x in h2)
    h3n = set(f"{x}.{y}" for x, y in h3) | set(re.findall(r"^### (A\.\d+) ", s, re.M))
    h4n = set(f"{x}.{y}.{z}" for x, y, z in h4)
    for r in sorted(set(re.findall(r"§(\d+(?:\.\d+){0,2})\b", s))):
        parts = r.split(".")
        ok = (len(parts) == 1 and r in h2n) or (len(parts) == 2 and r in h3n) or (len(parts) == 3 and r in h4n)
        if not ok:
            issues.append(f"dangling reference §{r}")

    # ---- identifier references
    defpat = {
        "D": r"^\| D(\d+) \|", "S": r"^\| S(\d+[a-z]?) \|", "O": r"^\| O(\d+[a-z]?) \|",
        "N": r"^- N(\d+)\.", "G": r"^- G(\d+)\.", "A": r"^### A\.(\d+) ", "Q": r"\*\*Q-([A-Z])",
    }
    refpat = {
        "D": r"\bD(\d+)\b", "S": r"\bS(\d+[a-z]?)\b", "O": r"\bO(\d+[a-z]?)\b",
        "N": r"\bN(\d+)\b", "G": r"\bG(\d+)\b", "A": r"\bA\.(\d+)\b", "Q": r"\bQ-([A-Z])\b",
    }
    for tag in [t.strip() for t in a.ids.split(",") if t.strip()]:
        if tag not in defpat:
            issues.append(f"unknown id class '{tag}' (known: {','.join(defpat)})"); continue
        d = set(re.findall(defpat[tag], s, re.M))
        r = set(re.findall(refpat[tag], s))
        # ignore large pure-digit ids (e.g. 'S256' in 'x5t#S256') as false positives
        bad = sorted(x for x in r - d if not (x.isdigit() and int(x) > 100))
        if bad:
            issues.append(f"{tag} references without definition: {bad}")

    # ---- relative links
    for m in re.finditer(r"\]\((\./[^)#]+|[^:)#/][^)#]*\.md)\)", s):
        target = m.group(1)
        if not os.path.exists(os.path.join(base, target)):
            issues.append(f"broken relative link: {target}")

    # ---- provisional markers
    markers = [r"\(proposed\)", r"—\s*verify\b", r"\(verify\)", r"\bverify (?:in|before|during) \w+",
               r"UNVERIFIED", r"\bTODO\b", r"\bFIXME\b"]
    found = []
    for i, l in enumerate(L):
        if any(am in l for am in a.allow_marker):
            continue
        for pat in markers:
            if re.search(pat, l):
                found.append(f"line {i+1}: {l.strip()[:90]}")
                break
    if found:
        issues.append(f"{len(found)} provisional marker(s):")
        issues.extend("   " + f for f in found)

    # ---- report
    if issues:
        print("\n".join(issues))
        print(f"\n{len([x for x in issues if not x.startswith('   ')])} issue(s); {len(allh)} headings; {len(L)} lines")
        sys.exit(1)
    if not a.quiet:
        print(f"lint: no issues — {len(allh)} headings, {len(L)} lines")

if __name__ == "__main__":
    main()
