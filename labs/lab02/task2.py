from __future__ import \
    annotations  # Дозволяє використовувати сучасні підказки типів (наприклад, dict[str, int]) у старіших версіях Python.

import argparse  # Модуль для парсингу аргументів командного рядка (CLI).
import csv  # Модуль для роботи з файлами формату CSV (запис звіту).
import json  # Модуль для роботи з форматом JSON (запис звіту).
import logging  # Модуль для логування подій (замість звичайного print для системних повідомлень).
import re  # Модуль для роботи з регулярними виразами.
from collections import Counter, defaultdict  # Структури даних для зручного підрахунку та створення словників із значеннями за замовчуванням.
from collections.abc import Iterator  # Тип для анотації генераторів.
from dataclasses import asdict, dataclass, field  # Інструменти для створення класів-структур даних без зайвого boilerplate-коду.
from datetime import datetime  # Клас для роботи з датою та часом.
from pathlib import Path  # Об'єктно-орієнтований підхід до роботи зі шляхами файлової системи.
from urllib.parse import unquote_plus  # Функція для декодування URL-адрес (наприклад, %20 у пробіл).

logger = logging.getLogger(__name__)  # Створюємо логер для поточного модуля.

DATA_DIR = Path( __file__).resolve().parent / "data" / "data_v01"  # Визначаємо шлях до папки з даними відносно поточного скрипта.
DEFAULT_LOG_FILE = DATA_DIR / "access.log"  # Формуємо стандартний шлях до файлу логів.
LOG_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"  # Формат часу, який використовується в Nginx/Apache (напр., 27/Sep/2026:08:00:00 +0000).
USER_TIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")  # Формати часу, які може ввести користувач через CLI.
MAX_PRINTED_ALERTS = 20  # Максимальна кількість алертів про атаки, що виводяться в консоль (щоб не засмічувати екран).

# Регулярний вираз для парсингу формату Nginx/Apache логу.
LOG_PATTERN = re.compile(  # Компілюємо regex для швидкодії.
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "  # Шукаємо IP та час у квадратних дужках.
    r'"(?P<method>[A-Z]+) (?P<uri>.*?)(?: (?P<protocol>HTTP/\d(?:\.\d)?))?" '  # Шукаємо HTTP-метод, URI та протокол.
    r"(?P<status>\d{3}) (?P<size>\d+|-)"  # Шукаємо статус-код (3 цифри) та розмір відповіді (цифри або '-').
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'  # Опціонально шукаємо Referer та User-Agent (необов'язкові поля).
)

ATTACK_SIGNATURES: dict[str, re.Pattern[str]] = {  # Словник із регулярними виразами для пошуку атак.
    "SQLi": re.compile(  # Сигнатури SQL-ін'єкцій.
        r"union\s+(?:all\s+)?select|select\s.+\sfrom|'\s*(?:or|and)\s+'?\d"  # Пошук UNION SELECT, SELECT FROM, ' OR 1=1 тощо.
        r"|\bor\b\s+\d+\s*=\s*\d+|;\s*drop\s+table|information_schema"  # Пошук OR x=x, DROP TABLE, information_schema.
        r"|sleep\s*\(\s*\d+|'\s*--",  # Пошук SLEEP() або коментарів SQL (--).
        re.IGNORECASE,  # Ігноруємо регістр літер.
    ),
    "Directory Traversal": re.compile(  # Сигнатури обходу каталогів.
        r"\.\.[/\\]|/etc/passwd|/etc/shadow|boot\.ini|win\.ini",  # Пошук ../, ..\, та системних файлів Linux/Windows.
        re.IGNORECASE,  # Ігноруємо регістр.
    ),
    "XSS": re.compile(  # Сигнатури міжсайтового скриптингу.
        r"<\s*script|javascript:|\bon(?:error|load|click|mouseover)\s*="  # Пошук тегів script, js-схем, та небезпечних подій (onerror).
        r"|<\s*(?:img|svg|iframe)[^>]*>",  # Пошук небезпечних тегів img, svg, iframe.
        re.IGNORECASE,  # Ігноруємо регістр.
    ),
}


@dataclass(frozen=True)  # Декоратор датакласу. frozen=True робить об'єкт незмінним (immutable).
class LogEntry:  # Клас для зберігання розібраного одного рядка логу.
    """Один розібраний рядок журналу."""
    ip: str  # IP адреса клієнта.
    timestamp: datetime  # Об'єкт часу запиту.
    method: str  # HTTP метод (GET, POST тощо).
    uri: str  # Запитаний ресурс (шлях).
    status: int  # HTTP статус відповіді (200, 404, 500).
    size: int  # Розмір відповіді у байтах.


@dataclass(frozen=True)
class AttackAlert:  # Клас для зберігання знайденої атаки.
    """Виявлена сигнатура атаки."""
    attack_type: str  # Тип атаки (SQLi, XSS і т.д.).
    ip: str  # IP з якого йшла атака.
    timestamp: str  # Час атаки (як рядок).
    request: str  # Рядок запиту, де виявлено атаку.


@dataclass  # Звичайний датаклас (змінний).
class ParseStats:  # Клас для збору статистики парсингу файлу.
    """Лічильники читання файлу."""
    total_lines: int = 0  # Загальна кількість оброблених рядків.
    parsed: int = 0  # Кількість успішно розібраних рядків.
    malformed: int = 0  # Кількість поламаних/некоректних рядків.


@dataclass  # Звичайний датаклас.
class AnalysisResult:  # Клас, що зберігає повний результат аналізу.
    """Підсумок аналізу, який потім потрапляє у звіт."""
    stats: ParseStats  # Вкладений об'єкт зі статистикою парсингу.
    entries_in_range: int = 0  # Кількість записів, що підійшли під часовий фільтр.
    first_time: str | None = None  # Час першого запису в лозі (з тих, що в діапазоні).
    last_time: str | None = None  # Час останнього запису.
    min_status: int = 400  # Поріг помилки за замовчуванням (від 400).
    top_error_ips: list[dict] = field(default_factory=list)  # Список словників з топом IP (ініціалізується порожнім списком).
    attacks: list[AttackAlert] = field(default_factory=list)  # Список виявлених атак.


def parse_line(line: str) -> LogEntry | None:  # Функція приймає рядок і повертає LogEntry або None, якщо помилка.
    """Розбирає рядок логу; для некоректного рядка повертає None."""
    match = LOG_PATTERN.match(line)  # Застосовуємо регулярний вираз до рядка.
    if match is None:  # Якщо рядок не відповідає шаблону логу:
        return None  # Повертаємо None.
    try:  # Блок обробки помилок часу.
        timestamp = datetime.strptime(match["time"], LOG_TIME_FORMAT)  # Перетворюємо текстовий час у об'єкт datetime.
    except ValueError:  # Якщо формат часу не збігається:
        return None  # Повертаємо None.
    size = 0 if match["size"] == "-" else int(match["size"])  # Якщо розмір '-', ставимо 0, інакше конвертуємо в int.
    return LogEntry(  # Створюємо і повертаємо об'єкт LogEntry з розібраними даними.
        ip=match["ip"],  # Передаємо IP.
        timestamp=timestamp,  # Передаємо час.
        method=match["method"],  # Передаємо метод.
        uri=match["uri"],  # Передаємо URI.
        status=int(match["status"]),  # Передаємо статус (конвертуючи в int).
        size=size,  # Передаємо розмір.
    )


def iter_entries(path: Path, stats: ParseStats) -> Iterator[LogEntry]:  # Функція-генератор, повертає об'єкти LogEntry.
    """Генератор: читає файл порядково, не завантажуючи його повністю."""
    with path.open(encoding="utf-8",
                   errors="replace") as handle:  # Відкриваємо файл на читання (замінюючи биті символи).
        for line in handle:  # Читаємо файл рядок за рядком.
            line = line.strip()  # Видаляємо зайві пробіли/переноси на початку і в кінці.
            if not line:  # Якщо рядок порожній:
                continue  # Пропускаємо і йдемо до наступного.
            stats.total_lines += 1  # Збільшуємо лічильник загальної кількості рядків.
            entry = parse_line(line)  # Намагаємось розібрати рядок.
            if entry is None:  # Якщо розбір не вдався:
                stats.malformed += 1  # Збільшуємо лічильник помилок формату.
                logger.debug("Пропущено некоректний рядок: %s",
                             line[:80])  # Записуємо в лог обрізаний рядок для дебагу.
                continue  # Переходимо до наступного рядка.
            stats.parsed += 1  # Збільшуємо лічильник успішних рядків.
            yield entry  # Повертаємо об'єкт як частину генератора (зупиняючи функцію до наступного виклику).


def in_time_range(entry: LogEntry, start: datetime | None,  end: datetime | None) -> bool:  # Функція перевірки часового діапазону.
    """Перевіряє, чи запис потрапляє в інтервал [start, end]."""

    def comparable(bound: datetime) -> datetime:  # Вкладена функція для коректного порівняння часових поясів.
        if bound.tzinfo is None:  # Якщо межа не має часового поясу (наївний час):
            return entry.timestamp.replace(tzinfo=None)  # Прибираємо часовий пояс і з логу для коректного порівняння.
        return entry.timestamp  # Інакше повертаємо час логу як є.

    if start is not None and comparable(start) < start:  # Якщо задано старт і час запису менший за старт:
        return False  # Запис не підходить.
    return not (end is not None and comparable(end) > end)  # Повертає True, якщо час не перевищує кінець, інакше False.


def detect_attacks(entry: LogEntry) -> list[str]:  # Функція перевірки запису на атаки.
    """Повертає типи атак, сигнатури яких знайдено у запиті."""
    decoded = entry.uri  # Беремо початковий URI з запису.
    for _ in range(2):  # Робимо 2 проходи для декодування.
        decoded = unquote_plus(decoded)  # Декодуємо URL  для виявлення прихованих атак.
    return [  # Генератор списку, що повертає знайдені типи атак.
        name for name, pattern in ATTACK_SIGNATURES.items() if pattern.search(decoded)
        # Проходимо по словнику атак і шукаємо збіги.
    ]


def analyze(log_path: Path, min_status: int = 400, top: int = 5, start: datetime | None = None,
            end: datetime | None = None) -> AnalysisResult:  # Головна аналітична функція.
    """Аналізує журнал: топ IP з помилками та пошук сигнатур атак."""
    stats = ParseStats()  # Створюємо об'єкт для збору статистики файлу.
    result = AnalysisResult(stats=stats, min_status=min_status)  # Створюємо об'єкт результатів аналізу.
    error_total: Counter[str] = Counter()  # Ініціалізуємо лічильник для загальної кількості помилок по IP.
    error_by_status: defaultdict[str, Counter[int]] = defaultdict(
        Counter)  # Словник, де ключ - IP, а значення - лічильник статус-кодів.
    first: datetime | None = None  # Змінна для зберігання часу першого запису.
    last: datetime | None = None  # Змінна для зберігання часу останнього запису.

    for entry in iter_entries(log_path, stats):  # Проходимось по кожному запису через генератор.
        if not in_time_range(entry, start, end):  # Якщо запис не потрапляє в часовий діапазон:
            continue  # Пропускаємо його.
        result.entries_in_range += 1  # Збільшуємо лічильник валідних записів.
        stamp = entry.timestamp.replace(tzinfo=None)  # Отримуємо час без прив'язки до зони.
        first = stamp if first is None else min(first, stamp)  # Оновлюємо мінімальний (перший) час.
        last = stamp if last is None else max(last, stamp)  # Оновлюємо максимальний (останній) час.

        if min_status <= entry.status <= 599:  # Якщо статус відповідає статусу помилки (>= min_status і до 599):
            error_total[entry.ip] += 1  # Зараховуємо загальну помилку для цього IP.
            error_by_status[entry.ip][entry.status] += 1  # Зараховуємо конкретний статус-код для цього IP.

        for attack in detect_attacks(entry):  # Шукаємо атаки в записі та перебираємо знайдені.
            result.attacks.append(  # Додаємо новий алерт у список результатів.
                AttackAlert(
                    attack_type=attack,  # Назва атаки.
                    ip=entry.ip,  # IP-зловмисника.
                    timestamp=entry.timestamp.isoformat(),  # Час у форматі ISO.
                    request=f"{entry.method} {entry.uri}",  # Тіло запиту для логування.
                )
            )

    result.first_time = first.isoformat(
        sep=" ") if first else None  # Форматуємо перший знайдений час або залишаємо None.
    result.last_time = last.isoformat(sep=" ") if last else None  # Форматуємо останній знайдений час.
    result.top_error_ips = [  # Формуємо підсумковий топ IP з помилками (у вигляді списку словників).
        {
            "ip": ip,  # IP-адреса.
            "errors": count,  # Загальна кількість помилок.
            "statuses": dict(error_by_status[ip].most_common()),
            # Словник конкретних статус-кодів та їх кількості, відсортований за частотою.
        }
        for ip, count in error_total.most_common(top)  # Беремо тільки `top` IP-адрес із найбільшою кількістю помилок.
    ]
    return result  # Повертаємо сформований об'єкт з результатами.


def print_report(result: AnalysisResult, top: int) -> None:  # Функція для виведення результатів на екран.
    """Виводить підсумок у консоль у форматі з методички"""
    print(f"\n=== Top-{top} IP Addresses with Error Statuses (status >= {result.min_status}) ===")  # Виводимо заголовок топу помилок.
    if not result.top_error_ips:  # Якщо список порожній:
        print("(помилок не знайдено)")  # Повідомляємо про це.
    for item in result.top_error_ips:  # Проходимось по кожному IP з топу:
        details = ", ".join(
            f"{s}: {c}" for s, c in item["statuses"].items())  # Форматуємо деталі статусів (напр. "404: 120, 500: 22").
        # Виправлено помилку синтаксису з оригінального коду, щоб відповідати виводу з методички.
        print(
            f"{item['ip']} - {item['errors']} errors ({details})")  # Виводимо рядок у форматі: IP - Загально помилок (Деталі).

    print("\n=== Detected Attack Signatures ===")
    if not result.attacks:  # Якщо атак немає:
        print("(сигнатур атак не знайдено)")  # Повідомляємо про це.
    for alert in result.attacks[
        :MAX_PRINTED_ALERTS]:  # Проходимось по атаках, обмежуючи вивід до MAX_PRINTED_ALERTS штук.
        print(f'[ALERT] Potential {alert.attack_type} from {alert.ip}: "{alert.request}"')  # Друкуємо сповіщення.
    hidden = len(result.attacks) - MAX_PRINTED_ALERTS  # Рахуємо, чи залишились атаки, які ми не вивели на екран.
    if hidden > 0:  # Якщо є приховані:
        print(f"... та ще {hidden} подій (див. звіт)")  # Повідомляємо, що їх можна знайти у повному файлі звіту.


def write_report(result: AnalysisResult, path: Path, fmt: str) -> None:  # Функція для збереження результатів у файл.
    """Зберігає звіт у JSON або CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)  # Створюємо директорії для шляху, якщо їх ще немає.
    if fmt == "json":  # Якщо обрано формат JSON:
        payload = {  # Формуємо словник для експорту.
            "summary": {  # Блок статистики.
                **asdict(result.stats),  # Розпаковуємо статистику парсингу.
                "entries_in_range": result.entries_in_range,  # Додаємо кількість записів у діапазоні.
                "first_time": result.first_time,  # Додаємо перший час.
                "last_time": result.last_time,  # Додаємо останній час.
                "min_status": result.min_status,  # Вказуємо поріг помилок.
            },
            "top_error_ips": result.top_error_ips,  # Додаємо список топ IP.
            "attacks": [asdict(a) for a in result.attacks],  # Додаємо список атак (конвертуючи датакласи в словники).
        }
        with path.open("w", encoding="utf-8") as handle:  # Відкриваємо файл на запис.
            json.dump(payload, handle, ensure_ascii=False, indent=2)  # Серіалізуємо у JSON з красивими відступами.
        return  # Виходимо з функції.

    # Якщо формат не JSON (значить CSV):
    with path.open("w", encoding="utf-8", newline="") as handle:  # Відкриваємо файл на запис CSV.
        writer = csv.writer(handle)  # Створюємо об'єкт для запису CSV.
        writer.writerow(
            ["record_type", "ip", "timestamp", "attack_type", "count", "details"])  # Пишемо заголовки колонок.
        for item in result.top_error_ips:  # Записуємо інформацію про топ IP.
            details = "; ".join(f"{s}:{c}" for s, c in item["statuses"].items())  # Форматуємо деталі статусів для CSV.
            writer.writerow(["top_error_ip", item["ip"], "", "", item["errors"], details])  # Записуємо рядок у CSV.
        for alert in result.attacks:  # Записуємо інформацію про атаки.
            writer.writerow(
                ["attack", alert.ip, alert.timestamp, alert.attack_type, 1, alert.request])  # Пишемо дані атаки.


# ---------- Валідація аргументів командного рядка ----------

def positive_int(value: str) -> int:  # Функція валідації додатних цілих чисел
    try:  # Пробуємо конвертувати.
        number = int(value)  # Переводимо рядок в int.
    except ValueError:  # Якщо це не число:
        raise argparse.ArgumentTypeError(
            f"{value!r} не є цілим числом") from None  # Викликаємо помилку парсера аргументів.
    if number <= 0:  # Якщо число менше або дорівнює нулю:
        raise argparse.ArgumentTypeError("значення має бути додатним")  # Викликаємо помилку.
    return number  # Повертаємо валідне число.


def status_code(value: str) -> int:  # Функція валідації HTTP-статус коду.
    number = positive_int(value)  # Використовуємо попередню функцію для перевірки що це число > 0.
    if not 100 <= number <= 599:  # Якщо статус не в діапазоні HTTP кодів:
        raise argparse.ArgumentTypeError("статус-код має бути в діапазоні 100-599")  # Помилка валідації.
    return number  # Повертаємо валідний код.


def datetime_arg(value: str) -> datetime:  # Функція парсингу дати з аргументів CLI.
    for fmt in USER_TIME_FORMATS:  # Перебираємо підтримувані формати дати.
        try:  # Спроба парсингу:
            return datetime.strptime(value, fmt)  # Якщо успішно - повертаємо об'єкт datetime.
        except ValueError:  # Якщо формат не підійшов:
            continue  # Пробуємо наступний.
    raise argparse.ArgumentTypeError(
        f"{value!r}: очікується YYYY-MM-DD[ HH:MM:SS]")  # Якщо жоден формат не підійшов — викидаємо помилку.


def add_arguments(parser: argparse.ArgumentParser) -> None:  # Функція налаштування аргументів.
    """Додає аргументи підкоманди analyze."""  # Докстрінг.
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE,
                        help="шлях до access.log")  # Шлях до файлу логів.
    parser.add_argument("--output", type=Path, default=None, help="шлях до звіту")  # Шлях куди зберегти результат.
    parser.add_argument("--min-status", type=status_code, default=400,
                        help="мінімальний статус-код помилки")  # Мінімальний статус для пошуку.
    parser.add_argument("--top", type=positive_int, default=5, help="кількість IP у рейтингу")  # Топ N адрес.
    parser.add_argument("--format", choices=("json", "csv"), default="json",
                        help="формат звіту")  # Вибір формату виводу.
    parser.add_argument("--start", type=datetime_arg, default=None, help="початок інтервалу")  # Початковий час.
    parser.add_argument("--end", type=datetime_arg, default=None, help="кінець інтервалу")  # Кінцевий час.


def run(args: argparse.Namespace) -> int:  # Головна точка входу логіки скрипта (запускає процес).
    """Виконує аналіз; повертає код завершення (0 — успіх)."""
    if args.start and args.end and args.start > args.end:  # Перевірка, що дата початку не більша за дату кінця.
        logger.error("--start не може бути пізніше за --end")  # Виводимо лог з помилкою.
        return 1  # Повертаємо статус помилки.

    log_path: Path = args.log_file  # Зберігаємо шлях до логу в змінну.
    logger.info("Loading access log from %s...",
                log_path)  # Інформаційне повідомлення про старт завантаження (відповідає прикладу).
    try:  # Блок обробки помилок читання файлу.
        result = analyze(log_path, args.min_status, args.top, args.start,
                         args.end)  # Запускаємо головний процес аналізу.
    except FileNotFoundError:  # Якщо файл не знайдено:
        logger.error("Файл не знайдено: %s", log_path)  # Повідомлення.
        return 1  # Помилка.
    except (PermissionError, IsADirectoryError):  # Якщо немає прав доступу або це папка:
        logger.error("Немає доступу до файлу: %s", log_path)  # Повідомлення.
        return 1  # Помилка.
    except OSError as exc:  # Інші системні помилки:
        logger.error("Помилка читання %s: %s", log_path, exc)  # Повідомлення.
        return 1  # Помилка.

    if result.stats.parsed == 0:  # Якщо не вдалося розібрати жоден рядок.
        logger.error("Жодного коректного запису не розібрано (формат логу?)")  # Пишемо в лог.
        return 1  # Помилка.
    if result.stats.malformed:  # Якщо були поламані рядки:
        logger.warning("Пропущено некоректних рядків: %d", result.stats.malformed)  # Попереджаємо користувача.

    logger.info("Processed %d log entries from %s to %s.", result.entries_in_range, result.first_time,
                result.last_time)  # Виводимо інфо про кількість оброблених записів.
    print_report(result, args.top)  # Виводимо результати на екран.

    output = args.output or log_path.parent / f"web_analysis_report.{args.format}"  # Якщо користувач не задав файл виводу, генеруємо стандартне ім'я поряд з логом.
    try:  # Блок запису файлу звіту.
        write_report(result, output, args.format)  # Спроба записати звіт.
    except OSError as exc:  # Якщо помилка запису на диск:
        logger.error("Не вдалося записати звіт %s: %s", output, exc)  # Повідомлення.
        return 1  # Помилка.

    logger.info("Analysis report saved to %s", output)  # Успішне завершення, виводимо шлях до збереженого звіту.
    return 0  # Повертаємо 0 (все ок).