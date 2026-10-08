#!/usr/bin/env python3
"""Generate a CycloneDX JSON Software Bill of Materials (SBOM) for Centralium.

Includes both Python runtime dependencies and frontend JavaScript dependencies.
Outputs CycloneDX 1.5 JSON.

Usage:
    .venv/bin/python scripts/gen_sbom.py [--output sbom.cyclonedx.json]
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import uuid
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def get_python_metadata(name: str) -> dict[str, str]:
    """Retrieve metadata for an installed Python distribution."""
    try:
        md = metadata.metadata(name)
    except metadata.PackageNotFoundError:
        return {"name": name, "version": "unknown", "license": "UNKNOWN", "description": ""}

    version = md.get("Version", "unknown")
    desc = md.get("Summary", "")

    lic = md.get("License-Expression")
    if not lic:
        lic_field = (md.get("License") or "").strip()
        if lic_field and len(lic_field) < 80 and "\n" not in lic_field:
            lic = lic_field
        else:
            classifiers = [
                c.split("::")[-1].strip()
                for c in md.get_all("Classifier") or []
                if c.startswith("License ::")
            ]
            if classifiers:
                lic = classifiers[0]
            elif lic_field:
                lic = lic_field.splitlines()[0][:60]
            else:
                lic = "UNKNOWN"

    return {
        "name": name,
        "version": version,
        "license": lic,
        "description": desc,
    }


def collect_python_components() -> list[dict]:
    req_file = ROOT / "requirements.txt"
    components: list[dict] = []
    seen = set()

    if req_file.is_file():
        for line in req_file.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-+]+)", line.strip())
            if not m:
                continue
            pkg_name = m.group(1)
            pinned_ver = m.group(2)
            seen.add(pkg_name.lower())
            meta = get_python_metadata(pkg_name)
            ver = meta["version"] if meta["version"] != "unknown" else pinned_ver

            purl = f"pkg:pypi/{pkg_name.lower()}@{ver}"
            comp: dict = {
                "type": "library",
                "bom-ref": purl,
                "name": pkg_name,
                "version": ver,
                "purl": purl,
            }
            if meta["description"]:
                comp["description"] = meta["description"]
            if meta["license"] and meta["license"] != "UNKNOWN":
                comp["licenses"] = [{"license": {"name": meta["license"]}}]
            components.append(comp)

    # Check cryptography (optional security module)
    if "cryptography" not in seen:
        c_meta = get_python_metadata("cryptography")
        if c_meta["version"] != "unknown":
            purl = f"pkg:pypi/cryptography@{c_meta['version']}"
            comp = {
                "type": "library",
                "bom-ref": purl,
                "name": "cryptography",
                "version": c_meta["version"],
                "purl": purl,
            }
            if c_meta["license"] and c_meta["license"] != "UNKNOWN":
                comp["licenses"] = [{"license": {"name": c_meta["license"]}}]
            components.append(comp)

    return components


def collect_npm_components() -> list[dict]:
    frontend_dir = ROOT / "dashboard" / "frontend"
    pkg_json_file = frontend_dir / "package.json"
    if not pkg_json_file.is_file():
        return []

    try:
        pj = json.loads(pkg_json_file.read_text(encoding="utf-8"))
    except Exception:
        return []

    components: list[dict] = []
    deps = {}
    deps.update(pj.get("dependencies", {}))
    deps.update(pj.get("devDependencies", {}))

    for name, req_version in sorted(deps.items()):
        node_pkg_file = frontend_dir / "node_modules" / name / "package.json"
        version = req_version.lstrip("^~")
        lic_name = "UNKNOWN"
        description = ""

        if node_pkg_file.is_file():
            try:
                mod_data = json.loads(node_pkg_file.read_text(encoding="utf-8"))
                version = mod_data.get("version", version)
                raw_lic = mod_data.get("license") or mod_data.get("licenses")
                if isinstance(raw_lic, str):
                    lic_name = raw_lic
                elif isinstance(raw_lic, dict):
                    lic_name = raw_lic.get("type", "UNKNOWN")
                description = mod_data.get("description", "")
            except (json.JSONDecodeError, OSError):
                # Ignore unreadable node_modules package metadata
                pass

        # purl format for npm: pkg:npm/%40scope/name@version
        if name.startswith("@") and "/" in name:
            scope, pkg = name.split("/", 1)
            purl = f"pkg:npm/%40{scope[1:]}/{pkg}@{version}"
        else:
            purl = f"pkg:npm/{name}@{version}"

        comp: dict = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
        }
        if description:
            comp["description"] = description
        if lic_name and lic_name != "UNKNOWN":
            comp["licenses"] = [{"license": {"name": lic_name}}]
        components.append(comp)

    return components


def build_cyclonedx_sbom() -> dict:
    timestamp = datetime.datetime.now(datetime.UTC).isoformat()
    bom_serial = f"urn:uuid:{uuid.uuid4()}"

    root_component = {
        "type": "application",
        "bom-ref": "pkg:pypi/centralium@0.1.0",
        "name": "centralium",
        "version": "0.1.0",
        "description": "Autonomous Endpoint Detection and Response Agent",
        "licenses": [
            {
                "license": {
                    "id": "Apache-2.0",
                }
            }
        ],
        "purl": "pkg:pypi/centralium@0.1.0",
    }

    py_components = collect_python_components()
    npm_components = collect_npm_components()
    all_components = py_components + npm_components

    # Build dependencies graph referencing root
    dependencies = [
        {
            "ref": root_component["bom-ref"],
            "dependsOn": [c["bom-ref"] for c in all_components],
        }
    ]

    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Centralium",
                    "name": "gen_sbom.py",
                    "version": "0.1.0",
                }
            ],
            "component": root_component,
        },
        "components": all_components,
        "dependencies": dependencies,
    }

    return sbom


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate CycloneDX SBOM for Centralium")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=ROOT / "sbom.cyclonedx.json",
        help="Target output path (default: sbom.cyclonedx.json in repo root)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print JSON to stdout instead of writing to file",
    )
    args = parser.parse_args()

    sbom = build_cyclonedx_sbom()
    json_text = json.dumps(sbom, indent=2, ensure_ascii=False) + "\n"

    if args.stdout:
        sys.stdout.write(json_text)
    else:
        args.output.write_text(json_text, encoding="utf-8")
        print(f"[SBOM] Wrote CycloneDX 1.5 SBOM to {args.output} ({len(sbom['components'])} components)")


if __name__ == "__main__":
    main()
