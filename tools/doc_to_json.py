"""
tools/doc_to_json.py

Deterministic converter: Policy_as_Code_for_Kubernetes.docx -> policies.json

No LLM involved by design (see HLD "Key Design Decision"). The source
document has a consistent structure (POL-XXX heading, then Rule / Applies
to / Condition / Action / Rationale paragraphs), so a regex-based parser
is simpler, cheaper, and 100% reliable for this input.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

LABELS = ["Rule", "Applies to", "Condition", "Action", "Rationale"]
# Accepts both a literal em dash (—, from extract-text) and pandoc's "---"
# ASCII rendering of the same character.
HEADING_RE = re.compile(r"^POL-(\d{3})\s+—\s+(.+)$")
LABEL_RE = re.compile(r"^(" + "|".join(LABELS) + r"):\s*(.*)$")
VALID_ACTIONS = {"deny", "warn"}


def extract_text(docx_path: str) -> str:
    """Converts docx -> markdown. Prefers `extract-text` (available in the
    Claude sandbox); falls back to `pandoc`, which is what CI runners use
    (`apt-get install -y pandoc` or the pandoc-action on GitHub Actions).
    --wrap=none is required — otherwise pandoc hard-wraps at ~80 chars and
    breaks a field's text across multiple lines."""
    import shutil

    if shutil.which("extract-text"):
        result = subprocess.run(
            ["extract-text", docx_path], capture_output=True, text=True, check=True
        )
        return result.stdout

    result = subprocess.run(
        ["pandoc", docx_path, "-t", "markdown", "--wrap=none"],
        capture_output=True,
        text=True,
        check=True,
    )
    return unescape_pandoc_markdown(result.stdout)


def unescape_pandoc_markdown(text: str) -> str:
    """Pandoc backslash-escapes markdown-special characters in its output
    (verified against this document: [ ] * @ ' "), which extract-text does
    not. It also renders em dashes as ASCII '---'. Undo both so the two
    extraction paths produce byte-identical text for the parser below."""
    for ch in ("[", "]", "*", "@", "'", '"'):
        text = text.replace("\\" + ch, ch)
    text = text.replace("---", "—")
    return text


def strip_bold(text: str) -> str:
    """The source doc has inline bold markers (including malformed nested
    ones, e.g. '**POL-004 — ****No :latest**** image tag**') that don't
    matter for parsing — strip all '**' rather than trying to match them."""
    return text.replace("**", "")


def split_policy_blocks(markdown: str) -> list[str]:
    """Splits the document into one chunk per POL-XXX rule, stopping
    before the 'Notes for Rego conversion' section (and anything after
    it, which is prose commentary, not a rule)."""
    lines = markdown.splitlines()
    starts = [i for i, l in enumerate(lines) if HEADING_RE.match(l.strip())]
    stop_idx = next(
        (i for i, l in enumerate(lines) if l.strip().lower().startswith("notes for rego")),
        len(lines),
    )
    blocks = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else stop_idx
        blocks.append("\n".join(lines[start:end]))
    return blocks


def parse_block(block: str) -> dict:
    """Regex-extracts the Rule/Applies to/Condition/Action/Rationale
    fields from a single POL-XXX block, folding bullet-list continuations
    (e.g. POL-005's registry list) back into the field they follow."""
    lines = [l.strip() for l in block.splitlines() if l.strip()]
    heading_match = HEADING_RE.match(lines[0])
    if not heading_match:
        raise ValueError(f"Block does not start with a POL-XXX heading: {lines[0]!r}")

    pol_id = f"POL-{heading_match.group(1)}"
    title = heading_match.group(2).strip()

    fields = {k: "" for k in LABELS}
    current = None

    for line in lines[1:]:
        label_match = LABEL_RE.match(line)
        if label_match:
            current = label_match.group(1)
            fields[current] = label_match.group(2).strip()
        elif line.startswith("- ") and current:
            item = line[2:].strip()
            if fields[current].endswith(":"):
                fields[current] = f"{fields[current]} {item}"
            elif fields[current]:
                fields[current] = f"{fields[current]}, {item}"
            else:
                fields[current] = item
        elif current:
            fields[current] = f"{fields[current]} {line}".strip()

    applies_to = [p.strip() for p in fields["Applies to"].split(",") if p.strip()]

    action_raw = fields["Action"].strip()
    action = action_raw.split()[0].lower().rstrip(".,") if action_raw else "deny"
    if action not in VALID_ACTIONS:
        action = "deny"

    return {
        "id": pol_id,
        "title": title,
        "rule": fields["Rule"],
        "applies_to": applies_to,
        "condition": fields["Condition"],
        "action": action,
        "rationale": fields["Rationale"],
    }


def build_spec(blocks: list[str]) -> dict:
    return {"policies": [parse_block(b) for b in blocks]}


def main(docx_path: str, out_path: str, check_only: bool = False) -> None:
    raw = extract_text(docx_path)
    text = strip_bold(raw)
    blocks = split_policy_blocks(text)
    if not blocks:
        raise ValueError(f"No POL-XXX policy blocks found in {docx_path}")

    spec = build_spec(blocks)
    new_content = json.dumps(spec, indent=2) + "\n"

    if check_only:
        out_file = Path(out_path)
        if not out_file.exists():
            print(f"FAIL: {out_path} does not exist — run without --check to generate it")
            sys.exit(1)
        existing_content = out_file.read_text()
        if existing_content != new_content:
            print(f"FAIL: {out_path} is out of sync with {docx_path}")
            print("Run: python3 tools/doc_to_json.py <docx> <json>  to regenerate it")
            sys.exit(1)
        print(f"OK: {out_path} matches {docx_path} ({len(spec['policies'])} policies)")
        return

    Path(out_path).write_text(new_content)
    print(f"Wrote {len(spec['policies'])} policies to {out_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("docx_path")
    parser.add_argument("out_path")
    parser.add_argument("--check", action="store_true", help="Verify out_path is in sync; don't write")
    args = parser.parse_args()
    main(args.docx_path, args.out_path, check_only=args.check)