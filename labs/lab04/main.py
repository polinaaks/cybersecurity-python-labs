"""Консольна утиліта: запис про вразливість NVD -> JSON-звіт за правилом варіанта.

Запуск (з кореня репозиторію):
    python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
    python -m labs.lab04.main --cve CVE-2021-44228

Коди завершення: 0 — звіт сформовано; 1 — помилка отримання/читання/перевірки
даних; 2 — неправильні аргументи або номер варіанта.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import requests

from lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

# fullmatch гарантує збіг усього рядка; регістр має значення.
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def cve_id_type(value: str) -> str:
    """Тип аргументу --cve для argparse: перевіряє формат ідентифікатора."""
    if CVE_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "очікується формат CVE-РРРР-NNNN (великі літери, щонайменше 4 цифри)"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Перегляд запису CVE в NVD та формування JSON-звіту.",
    )
    parser.add_argument("--cve", required=True, type=cve_id_type, help="ідентифікатор CVE")
    parser.add_argument(
        "--input",
        help="шлях до локального JSON-файла з відповіддю NVD (без мережі)",
    )
    return parser


def load_response(path: Path) -> Any:
    """Читає UTF-8 JSON-файл. Помилки (OSError, ValueError) обробляє main()."""
    return json.loads(path.read_text(encoding="utf-8"))


def _fail(message: str, code: int = 1) -> int:
    """Друкує повідомлення в stderr (без трасування) і повертає код завершення."""
    print(f"Помилка: {message}", file=sys.stderr)
    return code


def _read_file(path: str) -> tuple[Any, int | None]:
    """Повертає (дані, None) або (None, код помилки), вже надрукувавши причину."""
    try:
        return load_response(Path(path)), None
    except json.JSONDecodeError:
        return None, _fail("файл не містить коректного JSON.")
    except UnicodeDecodeError:
        return None, _fail("файл не є коректним UTF-8.")
    except OSError:
        return None, _fail("не вдалося прочитати файл.")


def _fetch(cve_id: str) -> tuple[Any, int | None]:
    """Мережевий запит. Повідомлення власні: текст винятків requests не друкуємо."""
    try:
        return api_client.fetch_response(cve_id), None
    except requests.exceptions.Timeout:  # ConnectTimeout теж сюди: перевіряємо до ConnectionError
        return None, _fail("перевищено час очікування відповіді NVD.")
    except requests.exceptions.ConnectionError:
        return None, _fail("не вдалося з'єднатися з NVD.")
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "невідомий"
        return None, _fail(f"NVD повернув HTTP-помилку (статус {status}).")
    except api_client.UnexpectedStatusError as exc:
        return None, _fail(f"NVD повернув неочікуваний статус {exc.status_code}.")
    except requests.exceptions.JSONDecodeError:
        return None, _fail("відповідь NVD не є коректним JSON.")
    except requests.exceptions.RequestException:
        return None, _fail("не вдалося виконати HTTP-запит до NVD.")


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входу CLI; повертає код завершення."""
    # 1) Перевірка номера варіанта. Беремо ім'я з глобальної області модуля —
    #    тому в тестах його можна підмінити через monkeypatch.
    if not analysis._is_valid_variant(VARIANT_NUMBER):
        return _fail("shared.student.VARIANT_NUMBER має бути цілим числом від 1 до 15.", 2)

    # 2) Аргументи. При помилці argparse сам друкує в stderr і робить SystemExit(2).
    args = build_parser().parse_args(argv)

    # 3) Отримання даних: з файла (без мережі) або з NVD.
    if args.input is not None:
        payload, error = _read_file(args.input)
    else:
        payload, error = _fetch(args.cve)
    if error is not None:
        return error

    # 4) Перевірка структури та правило варіанта.
    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        return _fail(f"некоректні дані: {exc}.")

    # 5) У stdout — лише один JSON-об'єкт звіту.
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
