#!/usr/bin/env python3
"""
skill-sec-bench — evaluate an AI-skill / MCP security scanner against a labeled corpus.

The corpus lives in ../corpus/{malicious,benign}/<sample>/ where each sample has
a SKILL.md (the definition a scanner inspects) and a meta.json (ground truth).
The parent folder is the label. The positive class is "malicious": a scanner is
expected to FLAG malicious samples and leave benign ones alone.

Examples
--------
  # built-in naive baseline scanner (stdlib only, good for a demo / CI):
  python3 harness/run_benchmark.py

  # evaluate your own scanner. {path} is replaced with the SKILL.md path.
  # A sample is FLAGGED if the command exits non-zero OR prints --flag-regex.
  python3 harness/run_benchmark.py --scanner "my-scanner --file {path}"

  # validate corpus integrity only (used by CI):
  python3 harness/run_benchmark.py --self-test
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
LABELS = ("malicious", "benign")
REQUIRED_META = ("id", "label", "category", "technique", "severity", "description")

# --- built-in baseline -----------------------------------------------------
# Deliberately NAIVE keyword/regex matching. It exists so the harness runs out
# of the box and so the benchmark has a floor to beat. It is NOT a good scanner.
SUSPICIOUS_PATTERNS = [
    r"ignore\s+(all|your|the|any)?\s*(previous|prior|above)\s+instructions",
    r"disregard\s+(the|all|any|previous)",
    r"do\s+not\s+(tell|inform|notify|mention)\s+the\s+user",
    r"~/\.ssh|id_rsa|id_ed25519|\.pem\b|\.aws/credentials",
    r"env(ironment)?\s+variable|printenv|process\.env|os\.environ|\benv\b\s*>",
    r"curl\s+-|wget\s+http|requests\.post|fetch\(",
    r"<important>|<!--.*?(system|instruction|ignore).*?-->",
]
_COMPILED = [re.compile(p, re.I | re.S) for p in SUSPICIOUS_PATTERNS]


def baseline_flags(text: str) -> bool:
    """Return True if the baseline scanner considers the text malicious."""
    return any(p.search(text) for p in _COMPILED)


# --- corpus loading ---------------------------------------------------------
def load_samples() -> list[dict]:
    samples = []
    for label in LABELS:
        base = CORPUS / label
        if not base.is_dir():
            continue
        for d in sorted(p for p in base.iterdir() if p.is_dir()):
            samples.append({"dir": d, "label": label, "skill": d / "SKILL.md"})
    return samples


def validate(samples: list[dict]) -> list[str]:
    """Return a list of integrity problems (empty means the corpus is valid)."""
    problems, seen_ids = [], {}
    if not samples:
        problems.append("no samples found under corpus/")
    for s in samples:
        rel = s["dir"].relative_to(ROOT)
        if not s["skill"].is_file():
            problems.append(f"{rel}: missing SKILL.md")
        meta_path = s["dir"] / "meta.json"
        if not meta_path.is_file():
            problems.append(f"{rel}: missing meta.json")
            continue
        try:
            meta = json.loads(meta_path.read_text())
        except json.JSONDecodeError as e:
            problems.append(f"{rel}: meta.json is not valid JSON ({e})")
            continue
        for key in REQUIRED_META:
            if key not in meta:
                problems.append(f"{rel}: meta.json missing '{key}'")
        if meta.get("label") != s["label"]:
            problems.append(
                f"{rel}: meta label '{meta.get('label')}' != folder '{s['label']}'"
            )
        sid = meta.get("id")
        if sid in seen_ids:
            problems.append(f"{rel}: duplicate id '{sid}' (also {seen_ids[sid]})")
        else:
            seen_ids[sid] = rel
    return problems


# --- scanners ----------------------------------------------------------------
def external_flags(cmd_template: str, path: Path, flag_regex: re.Pattern) -> bool:
    cmd = cmd_template.replace("{path}", str(path))
    try:
        proc = subprocess.run(
            shlex.split(cmd), capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"  ! scanner failed on {path}: {e}", file=sys.stderr)
        return False
    if proc.returncode != 0:
        return True
    return bool(flag_regex.search(proc.stdout + proc.stderr))


# --- scoring -----------------------------------------------------------------
def score(rows: list[dict]) -> dict:
    tp = sum(r["flagged"] and r["label"] == "malicious" for r in rows)
    fp = sum(r["flagged"] and r["label"] == "benign" for r in rows)
    fn = sum(not r["flagged"] and r["label"] == "malicious" for r in rows)
    tn = sum(not r["flagged"] and r["label"] == "benign" for r in rows)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn,
                precision=precision, recall=recall, f1=f1, accuracy=accuracy)


def print_report(rows: list[dict], m: dict) -> None:
    print(f"{'sample':44} {'label':10} {'flagged':8} result")
    print("-" * 78)
    for r in sorted(rows, key=lambda r: r["name"]):
        correct = r["flagged"] == (r["label"] == "malicious")
        mark = "ok" if correct else "MISS"
        print(f"{r['name']:44} {r['label']:10} {str(r['flagged']):8} {mark}")
    print("-" * 78)
    print(f"samples={len(rows)}  TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}")
    print(f"precision={m['precision']:.3f}  recall={m['recall']:.3f}  "
          f"f1={m['f1']:.3f}  accuracy={m['accuracy']:.3f}")


# --- main --------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scanner", help="command to evaluate; {path} -> SKILL.md path. "
                                       "Default: built-in naive baseline.")
    ap.add_argument("--flag-regex", default="MALICIOUS",
                    help="external scanner counts as 'flagged' if stdout/stderr "
                         "matches this (case-insensitive). Default: MALICIOUS")
    ap.add_argument("--self-test", action="store_true",
                    help="validate corpus integrity, then run the baseline")
    ap.add_argument("--json", action="store_true", help="print metrics as JSON")
    args = ap.parse_args(argv)

    samples = load_samples()
    problems = validate(samples)
    if problems:
        print("corpus integrity problems:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    if args.self_test:
        print(f"corpus OK: {len(samples)} samples, 0 problems")

    flag_regex = re.compile(args.flag_regex, re.I)
    rows = []
    for s in samples:
        text = s["skill"].read_text()
        flagged = (external_flags(args.scanner, s["skill"], flag_regex)
                   if args.scanner else baseline_flags(text))
        rows.append({"name": s["dir"].name, "label": s["label"], "flagged": flagged})

    m = score(rows)
    if args.json:
        print(json.dumps(m, indent=2))
    else:
        scanner_name = args.scanner or "built-in baseline"
        print(f"\nscanner: {scanner_name}\n")
        print_report(rows, m)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
