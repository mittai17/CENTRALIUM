#!/usr/bin/env python3
"""Parse docs/ACCEPTANCE.md and regenerate Section 1 (Summary table and counts)

accurately based on the actual criteria items and statuses present in Section 2.
Guarantees drift is impossible.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

VALID_STATUSES = ("PASS", "PARTIAL", "NOT VERIFIED")

ITEM_RE = re.compile(r"^####\s+(\d+)\.\s+\[(PASS|PARTIAL|NOT VERIFIED)\]\s+(.*)$")
SECTION_RE = re.compile(r"^###\s+2\.\d+\s+(.*)$")


@dataclass
class CategoryStats:
    name: str
    items: list[tuple[int, str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.items)

    def count(self, status: str) -> int:
        return sum(1 for _, s, _ in self.items if s == status)


def parse_acceptance_file(path: Path) -> tuple[str, list[CategoryStats]]:
    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()

    categories: list[CategoryStats] = []
    current_category: CategoryStats | None = None
    in_section_2 = False

    for line in lines:
        if line.strip().startswith("## 2. Detailed Verification"):
            in_section_2 = True
            continue

        if not in_section_2:
            continue

        sec_match = SECTION_RE.match(line.strip())
        if sec_match:
            cat_name = sec_match.group(1).strip()
            current_category = CategoryStats(name=cat_name)
            categories.append(current_category)
            continue

        item_match = ITEM_RE.match(line.strip())
        if item_match and current_category is not None:
            num = int(item_match.group(1))
            status = item_match.group(2).strip()
            title = item_match.group(3).strip()
            current_category.items.append((num, status, title))

    return content, categories


def build_summary_markdown(categories: list[CategoryStats]) -> str:
    total_items = sum(cat.total for cat in categories)
    total_pass = sum(cat.count("PASS") for cat in categories)
    total_partial = sum(cat.count("PARTIAL") for cat in categories)
    total_not_verified = sum(cat.count("NOT VERIFIED") for cat in categories)

    lines = [
        "## 1. Summary of Acceptance Criteria",
        "",
        f"Across the **{total_items} core acceptance criteria** defined in the master prompt:",
        f"- **PASS**: {total_pass} items",
        f"- **PARTIAL**: {total_partial} items",
        f"- **NOT VERIFIED**: {total_not_verified} items",
        "",
        "| Category | Total Criteria | PASS | PARTIAL | NOT VERIFIED |",
        "|---|---|---|---|---|",
    ]

    for cat in categories:
        lines.append(
            f"| **{cat.name}** | {cat.total} | {cat.count('PASS')} | "
            f"{cat.count('PARTIAL')} | {cat.count('NOT VERIFIED')} |"
        )

    lines.append(
        f"| **Total** | **{total_items}** | **{total_pass}** | "
        f"**{total_partial}** | **{total_not_verified}** |"
    )

    return "\n".join(lines)


def update_acceptance_file(path: Path, write: bool = False) -> bool:
    content, categories = parse_acceptance_file(path)
    if not categories:
        raise ValueError(f"No categories found in {path}")

    summary_block = build_summary_markdown(categories)

    # Locate Section 1 in content:
    # Starts at "## 1. Summary of Acceptance Criteria" and ends right before "---"
    pattern = re.compile(
        r"(## 1\. Summary of Acceptance Criteria\n\n.*?\n)(---\n\n## 2\. Detailed Verification)",
        re.DOTALL,
    )

    match = pattern.search(content)
    if not match:
        raise ValueError("Could not find Section 1 bounds in ACCEPTANCE.md")

    existing_block = match.group(1).rstrip()
    new_block = summary_block.rstrip()

    is_identical = existing_block == new_block

    if not is_identical and write:
        new_content = pattern.sub(rf"{summary_block}\n\n\2", content, count=1)
        path.write_text(new_content, encoding="utf-8")

    return is_identical


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile and generate summary table in docs/ACCEPTANCE.md")
    parser.add_argument("--file", type=Path, default=Path("docs/ACCEPTANCE.md"), help="Path to ACCEPTANCE.md")
    parser.add_argument("--write", action="store_true", help="Write changes back to file")
    parser.add_argument("--check", action="store_true", help="Check only, exit 1 if drift detected")
    args = parser.parse_args()

    file_path = args.file
    if not file_path.is_file():
        print(f"Error: {file_path} not found", file=sys.stderr)
        return 1

    _content, categories = parse_acceptance_file(file_path)
    total_items = sum(cat.total for cat in categories)
    total_pass = sum(cat.count("PASS") for cat in categories)
    total_partial = sum(cat.count("PARTIAL") for cat in categories)
    total_not_verified = sum(cat.count("NOT VERIFIED") for cat in categories)

    print(f"Parsed {len(categories)} categories, {total_items} total criteria:")
    print(f"  PASS: {total_pass}")
    print(f"  PARTIAL: {total_partial}")
    print(f"  NOT VERIFIED: {total_not_verified}")
    print()

    summary_md = build_summary_markdown(categories)

    if args.write:
        is_synced = update_acceptance_file(file_path, write=True)
        if is_synced:
            print(f"Summary in {file_path} is already up to date.")
        else:
            print(f"Successfully updated {file_path} summary table.")
        return 0

    if args.check:
        is_synced = update_acceptance_file(file_path, write=False)
        if is_synced:
            print(f"Summary in {file_path} is consistent.")
            return 0
        else:
            print(f"DRIFT DETECTED in {file_path}! Run with --write to update.", file=sys.stderr)
            return 1

    # Default output generated markdown
    print(summary_md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
