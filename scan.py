"""
scan.py
-------
Sentinel's single entry point: scan a target, show what was confirmed, and apply
fixes ONLY with your approval (human-in-the-loop -- no file changes without your OK).

Usage:  python scan.py [path-to-target]
"""

import sys
from pathlib import Path

from sentinel.llm import LLMClient
from sentinel.scanner import Scanner


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "targets/vulnerable_app"
    print(f"Scanning {target} ...\n")

    scanner = Scanner(LLMClient(), target)
    report = scanner.scan()

    print(report.summary())
    print()

    for s in report.confirmed:
        f = s.finding
        print(f"  [CONFIRMED] {f.vuln_class}  {f.file}:{f.line}  (severity: {f.severity})")
    print()

    if not report.patches:
        print("No confirmed findings to patch.")
        return

    for patch in report.patches:
        print("=" * 64)
        print(f"Proposed fix for: {patch.finding.file}")
        print("=" * 64)
        print(patch.diff)
        answer = input(f"Apply this fix to {patch.finding.file}? [y/N] ").strip().lower()
        if answer == "y":
            (Path(target) / patch.finding.file).write_text(patch.fixed_code, encoding="utf-8")
            print(f"  Applied - {patch.finding.file} updated.\n")
        else:
            print("  Skipped - no changes made.\n")


if __name__ == "__main__":
    main()