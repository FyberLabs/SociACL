#!/usr/bin/env python3
"""Run python/tests and write target/coverage/python.json.

Uses coverage.py when it is already installed. Otherwise traces with the
stdlib so CI does not need python3-venv / ensurepip.
"""

from __future__ import annotations

import ast
import json
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COV = ROOT / "target" / "coverage"
SRC = (ROOT / "python" / "sociacl" / "__init__.py").resolve()
TESTS = [
    ROOT / "python" / "tests" / "test_check.py",
    ROOT / "python" / "tests" / "test_client.py",
    ROOT / "python" / "tests" / "test_social_light.py",
    ROOT / "python" / "tests" / "test_gun.py",
    ROOT / "python" / "tests" / "test_verbs.py",
    ROOT / "python" / "tests" / "test_network.py",
]


def run_tests() -> None:
    sys.path.insert(0, str(ROOT / "python"))
    for path in TESTS:
        runpy.run_path(str(path), run_name="__main__")


def statement_lines(path: Path) -> set[int]:
    tree = ast.parse(path.read_text(), filename=str(path))
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and getattr(node, "lineno", None):
            lines.add(node.lineno)
    return lines


def write_reports(covered: int, statements: int, missing: list[int]) -> None:
    COV.mkdir(parents=True, exist_ok=True)
    pct = 100.0 * covered / statements if statements else 0.0
    payload = {
        "totals": {
            "covered_lines": covered,
            "num_statements": statements,
            "percent_covered": pct,
            "missing_lines": len(missing),
        }
    }
    (COV / "python.json").write_text(json.dumps(payload))
    miss = ", ".join(str(n) for n in missing[:80])
    extra = "..." if len(missing) > 80 else ""
    (COV / "python-report.txt").write_text(
        "Name                         Stmts   Miss  Cover   Missing\n"
        "----------------------------------------------------------\n"
        f"python/sociacl/__init__.py  {statements:6d} {statements - covered:6d}  {pct:5.1f}%   {miss}{extra}\n"
        "----------------------------------------------------------\n"
        f"TOTAL                       {statements:6d} {statements - covered:6d}  {pct:5.1f}%\n"
    )
    print(f"python coverage {pct:.1f}% ({covered}/{statements})")


def with_coverage_py() -> bool:
    try:
        import coverage  # type: ignore
    except ImportError:
        return False
    cov = coverage.Coverage(source=[str(ROOT / "python" / "sociacl")])
    cov.erase()
    cov.start()
    try:
        run_tests()
    finally:
        cov.stop()
        cov.save()
    cov.json_report(outfile=str(COV / "python.json"))
    with (COV / "python-report.txt").open("w") as fh:
        cov.report(file=fh, show_missing=True)
    return True


def with_stdlib() -> None:
    stmts = statement_lines(SRC)
    hit: set[int] = set()

    def tracer(frame, event, arg):  # noqa: ANN001
        if event == "line":
            try:
                if Path(frame.f_code.co_filename).resolve() == SRC:
                    hit.add(frame.f_lineno)
            except OSError:
                pass
        return tracer

    sys.settrace(tracer)
    try:
        run_tests()
    finally:
        sys.settrace(None)

    covered_lines = sorted(stmts & hit)
    missing = sorted(stmts - hit)
    write_reports(len(covered_lines), len(stmts), missing)


def main() -> None:
    COV.mkdir(parents=True, exist_ok=True)
    if with_coverage_py():
        return
    with_stdlib()


if __name__ == "__main__":
    main()
