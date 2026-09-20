#!/usr/bin/env python3
"""Turn coverage reports into docs/coverage.md and the README snapshot."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COV = ROOT / "target" / "coverage"
README = ROOT / "README.md"
DOCS = ROOT / "docs" / "coverage.md"
START = "<!-- coverage:start -->"
END = "<!-- coverage:end -->"


def rust_line_cover() -> tuple[str, list[tuple[str, str, str]]]:
    lcov = COV / "rust.lcov"
    if lcov.exists():
        return rust_from_lcov(lcov)
    text = (COV / "rust-summary.txt").read_text()
    rows: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        if not line.strip() or set(line.strip()) == {"-"}:
            continue
        if line.startswith("Filename") or line.startswith("----"):
            continue
        parts = line.split()
        if len(parts) < 10:
            continue
        name = parts[0]
        pcts = re.findall(r"(\d+\.\d+)%", line)
        if len(pcts) < 3:
            continue
        lines = parts[7] if len(parts) > 7 else "?"
        rows.append((name, lines, f"{pcts[2]}%"))
    total = next((r for r in rows if r[0] == "TOTAL"), ("TOTAL", "?", "n/a"))
    return total[2], rows


def rust_from_lcov(path: Path) -> tuple[str, list[tuple[str, str, str]]]:
    rows: list[tuple[str, str, str]] = []
    current = ""
    lf = lh = 0
    total_lf = total_lh = 0
    for raw in path.read_text().splitlines():
        if raw.startswith("SF:"):
            current = raw[3:]
            prefix = str(ROOT) + "/"
            if current.startswith(prefix):
                current = current[len(prefix) :]
            if current.startswith("crates/"):
                current = current[len("crates/") :]
            lf = lh = 0
        elif raw.startswith("LF:"):
            lf = int(raw[3:])
        elif raw.startswith("LH:"):
            lh = int(raw[3:])
        elif raw == "end_of_record" and current:
            total_lf += lf
            total_lh += lh
            pct = f"{(100.0 * lh / lf):.2f}%" if lf else "n/a"
            rows.append((current, str(lf), pct))
            current = ""
    total = f"{(100.0 * total_lh / total_lf):.2f}%" if total_lf else "n/a"
    rows.append(("TOTAL", str(total_lf), total))
    return total, rows


def python_line_cover() -> str:
    data = json.loads((COV / "python.json").read_text())
    return f"{data['totals']['percent_covered']:.1f}%"


def typescript_line_cover() -> str:
    text = (COV / "typescript-report.txt").read_text()
    # "all files | line % | branch % | funcs %"
    m = re.search(r"all files\s*\|\s*([0-9.]+)", text)
    return f"{float(m.group(1)):.1f}%" if m else "n/a"


def sociacl_c_cover(rows: list[tuple[str, str, str]]) -> str:
    for name, _lines, cover in rows:
        if name.endswith("sociacl-c/src/lib.rs") or name == "sociacl-c/src/lib.rs":
            return cover
    return "n/a"


def counts() -> dict[str, int]:
    rust = 0
    list_path = COV / "rust-test-list.txt"
    if list_path.exists():
        rust = sum(1 for line in list_path.read_text().splitlines() if line.endswith(": test"))
    py = 0
    for path in (ROOT / "python" / "tests").glob("test_*.py"):
        py += sum(1 for line in path.read_text().splitlines() if re.match(r"def test_", line))
    ts = 0
    for path in (ROOT / "typescript" / "tests").glob("test_*.js"):
        ts += sum(1 for line in path.read_text().splitlines() if re.match(r"test\(", line))
    c_examples = len(list((ROOT / "examples").glob("*.c")))
    rust_examples = len(list((ROOT / "examples").glob("*.rs")))
    c_unit = 0
    if list_path.exists():
        c_unit = sum(
            1
            for line in list_path.read_text().splitlines()
            if line.startswith("tests::ffi_") and line.endswith(": test")
        )
    return {
        "rust": rust,
        "python": py,
        "typescript": ts,
        "c_unit": c_unit,
        "c_examples": c_examples,
        "rust_examples": rust_examples,
    }


def readme_block(day: str, rust: str, py: str, ts: str, c: str, n: dict[str, int]) -> str:
    rust_n = n["rust"] or "?"
    return f"""{START}
Measured **{day}** by `scripts/coverage.sh`. CI publishes the same table on the job summary.

| Surface | Result | Line coverage |
| --- | --- | ---: |
| Rust workspace | {rust_n} tests + {n["rust_examples"]} examples | {rust} |
| C FFI (`sociacl-c`) | {n["c_unit"]} unit + {n["c_examples"]} examples | {c} |
| Python `python/sociacl` | {n["python"]} tests | {py} |
| TypeScript `typescript/src` | {n["typescript"]} tests | {ts} |

C example hits land in `libsociacl`, not in the `.c` files. Full crate table: [docs/coverage.md](docs/coverage.md).
{END}
"""


def docs_md(
    day: str,
    rust: str,
    py: str,
    ts: str,
    c: str,
    rows: list[tuple[str, str, str]],
    n: dict[str, int],
) -> str:
    body = [
        "# Coverage",
        "",
        f"Measured **{day}** by `scripts/coverage.sh`.",
        "",
        "| Surface | Result | Line coverage | Tool |",
        "| --- | --- | ---: | --- |",
        f"| Rust workspace | {n['rust'] or '?'} tests + {n['rust_examples']} examples | {rust} | cargo-llvm-cov |",
        f"| C FFI | {n['c_unit']} unit + {n['c_examples']} examples | {c} (`sociacl-c`) | same llvm-cov |",
        f"| Python | {n['python']} tests | {py} | coverage.py |",
        f"| TypeScript | {n['typescript']} tests | {ts} | node --experimental-test-coverage |",
        "",
        "C examples are smoke tests against `libsociacl`. Their line hits land in the Rust FFI crate.",
        "",
        "## Rust files",
        "",
        "| File | Lines | Cover |",
        "| --- | ---: | ---: |",
    ]
    for name, lines, cover in rows:
        if name == "TOTAL":
            continue
        body.append(f"| `{name}` | {lines} | {cover} |")
    total = next((r for r in rows if r[0] == "TOTAL"), None)
    if total:
        body.append(f"| **TOTAL** | {total[1]} | **{total[2]}** |")
    body.extend(
        [
            "",
            "## How to refresh",
            "",
            "```bash",
            "cargo build --workspace --locked",
            "./scripts/coverage.sh",
            "```",
            "",
            "Raw summaries: `target/coverage/rust-summary.txt`, `target/coverage/python-report.txt`, `target/coverage/typescript-report.txt`.",
            "",
        ]
    )
    return "\n".join(body)


def patch_readme(block: str) -> None:
    text = README.read_text()
    if START in text and END in text:
        text = re.sub(
            re.escape(START) + r".*?" + re.escape(END),
            block.strip(),
            text,
            count=1,
            flags=re.S,
        )
    else:
        needle = "## Build and test"
        if needle not in text:
            raise SystemExit("README.md is missing ## Build and test")
        text = text.replace(needle, "## Tests and coverage\n\n" + block + "\n" + needle, 1)
    README.write_text(text)


def main() -> None:
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rust, rows = rust_line_cover()
    py = python_line_cover()
    ts = typescript_line_cover()
    c = sociacl_c_cover(rows)
    n = counts()
    DOCS.write_text(docs_md(day, rust, py, ts, c, rows, n))
    patch_readme(readme_block(day, rust, py, ts, c, n))
    print(f"wrote {DOCS}")
    print(f"rust={rust} python={py} typescript={ts} sociacl-c={c}")


if __name__ == "__main__":
    main()
