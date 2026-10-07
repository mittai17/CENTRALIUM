"""Regenerate the dependency tables of THIRD_PARTY_NOTICES.md from installed package metadata.

Usage: .venv/bin/python scripts/gen_third_party_notices.py > THIRD_PARTY_NOTICES.md
Python licenses come from importlib.metadata of the packages pinned in requirements.txt (as installed
in the active venv); JS licenses from dashboard/frontend/node_modules/<pkg>/package.json (direct deps
only). Anything that cannot be determined is printed as UNKNOWN - never guessed.
"""

from __future__ import annotations

import json
import re
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = (ROOT / "scripts" / "third_party_header.md").read_text(encoding="utf-8")


def py_license(name: str) -> tuple[str, str]:
    try:
        md = metadata.metadata(name)
    except metadata.PackageNotFoundError:
        return "NOT INSTALLED", ""
    version = md.get("Version", "?")
    expr = md.get("License-Expression")
    if expr:
        return version, expr
    lic = (md.get("License") or "").strip()
    if lic and len(lic) < 80 and "\n" not in lic:
        return version, lic
    cls = [c.split("::")[-1].strip() for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
    if cls:
        return version, "; ".join(cls)
    if lic:
        return version, lic.splitlines()[0][:80] + " (from license text; verify)"
    return version, "UNKNOWN"


def main() -> None:
    out = [HEADER.rstrip(), "", "## Python dependencies (requirements.txt; installed metadata)", ""]
    out += ["| Package | Version | License |", "|---|---|---|"]
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==", line.strip())
        if not m:
            continue
        ver, lic = py_license(m.group(1))
        out.append(f"| {m.group(1)} | {ver} | {lic.replace('|', '/')} |")
    extra = py_license("cryptography")
    if extra[0] != "NOT INSTALLED":
        note = "Optional (not in requirements.txt; Ed25519 update verification)"
        out += ["", f"{note}: cryptography {extra[0]} - {extra[1]}"]
    out += ["", "## JavaScript dependencies (dashboard/frontend, direct deps from node_modules metadata)", ""]
    out += ["| Package | Declared range | Installed | License |", "|---|---|---|---|"]
    pj = json.loads((ROOT / "dashboard/frontend/package.json").read_text())
    for sect in ("dependencies", "devDependencies"):
        for name, rng in pj.get(sect, {}).items():
            f = ROOT / "dashboard/frontend/node_modules" / name / "package.json"
            if f.is_file():
                d = json.loads(f.read_text())
                lic = d.get("license") or d.get("licenses") or "UNKNOWN"
                out.append(f"| {name} ({sect[:3]}) | {rng} | {d.get('version', '?')} | {lic} |")
            else:
                out.append(f"| {name} ({sect[:3]}) | {rng} | not installed | UNKNOWN |")
    sys.stdout.write("\n".join(out) + "\n")
    sys.stdout.write((ROOT / "scripts" / "third_party_footer.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
