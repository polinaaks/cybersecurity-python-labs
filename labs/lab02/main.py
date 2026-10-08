"""Точка входу ЛР №2: команди demo (Завдання 1) та analyze (Завдання 2)."""

from __future__ import annotations

import argparse
import logging
import sys

from labs.lab02 import task1, task2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="ЛР №2: ООП та консольна утиліта кібербезпеки (варіант 1).",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="детальне логування (DEBUG)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("demo", help="демонстрація класів Завдання 1")
    analyze_parser = subparsers.add_parser(
        "analyze", help="аналіз access.log (Завдання 2)"
    )
    task2.add_arguments(analyze_parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
        stream=sys.stdout,
    )
    if args.command == "demo":
        task1.run_demo()
        return 0
    return task2.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
