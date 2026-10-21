#!/usr/bin/env python3
"""Lists C++ functions in src/ longer than TigerStyle's 70-line limit.

    python3 scripts/function_lengths.py [--limit N] [--check]

A function runs from its signature's opening brace to the matching close, both
counted. Signatures are recognised by shape, not parsed, which is enough for this
repository's DuckDB formatting: a line ending in ") {" (optionally const, override
or noexcept) that is not a control statement, or a lambda. With --check the exit
status is 1 when any function is over the limit.
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROL = re.compile(r"^\s*(?:\}\s*)?(?:if|for|while|switch|catch|else|do|try)\b")
SIGNATURE = re.compile(r"\)\s*(?:const\s*)?(?:override\s*)?(?:noexcept\s*)?(?:->\s*[\w:<>&*\s]+)?\{\s*$")
NAME = re.compile(r"([~\w:]+)\s*\((?:[^()]|\([^()]*\))*\)?[^()]*$")


def functions(path):
    lines = path.read_text().splitlines()
    for start, line in enumerate(lines):
        if not SIGNATURE.search(line) or CONTROL.match(line) or line.lstrip().startswith(("//", "#")):
            continue
        # A signature may wrap; its name is on the first line of the statement.
        first = start
        while first > 0 and lines[first - 1].rstrip().endswith((",", "(")) and not lines[first - 1].strip() == "":
            first -= 1
        header = " ".join(part.strip() for part in lines[first:start + 1])
        match = NAME.search(header.split("(")[0] + "(")
        name = match.group(1) if match else header[:40]
        depth = 0
        for end in range(start, len(lines)):
            text = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//.*', "", lines[end])
            depth += text.count("{") - text.count("}")
            if depth == 0:
                yield name, first + 1, end - first + 1
                break


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--limit", type=int, default=70)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    over = []
    for path in sorted((ROOT / "src").rglob("*.[ch]pp")):
        for name, line, length in functions(path):
            if length > arguments.limit:
                over.append((length, f"{path.relative_to(ROOT)}:{line}", name))
    for length, where, name in sorted(over, reverse=True):
        print(f"{length:5}  {where:48} {name}")
    print(f"{len(over)} functions over {arguments.limit} lines")
    return 1 if arguments.check and over else 0


if __name__ == "__main__":
    sys.exit(main())
