"""Початкове заповнення бази даними з data/seed.json."""  # документація модуля

import json  # читання JSON
import sqlite3  # помилки та з'єднання SQLite
import sys  # код завершення програми
from contextlib import closing  # гарантоване закриття з'єднання
from pathlib import Path  # робота зі шляхами
from typing import Any  # тип довільних значень

from pydantic import ValidationError  # помилка перевірки Pydantic

from .database import get_connection, initialize_database  # робота з базою
from .schemas import CategoryCreate, RecordCreate  # моделі для перевірки даних

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"  # шлях до початкових даних


class SeedError(Exception):  # власна помилка початкових даних
    """Некоректні початкові дані."""  # опис винятку


def load_seed(path: Path = SEED_PATH) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:  # читання і перевірка JSON
    """Прочитати seed.json та перевірити його вміст."""  # опис функції
    try:  # блок читання файлу
        payload = json.loads(path.read_text(encoding="utf-8"))  # читаємо й розбираємо JSON
    except (OSError, json.JSONDecodeError) as error:  # файл відсутній або JSON зламаний
        raise SeedError(f"Не вдалося прочитати {path.name}: {error}") from error  # зрозуміле повідомлення
    if not isinstance(payload, dict):  # корінь має бути об'єктом
        raise SeedError("Корінь JSON має бути об'єктом")  # повідомлення
    categories = payload.get("categories")  # масив категорій
    records = payload.get("records")  # масив записів
    if not isinstance(categories, list) or not isinstance(records, list):  # обидва мають бути масивами
        raise SeedError("Потрібні масиви categories і records")  # повідомлення
    if len(categories) != 3 or len(records) != 8:  # за завданням: 3 категорії та 8 записів
        raise SeedError("Очікується 3 категорії та 8 записів")  # повідомлення
    category_ids: set[int] = set()  # зібрані id категорій
    try:  # блок перевірки через Pydantic
        for category in categories:  # проходимо по категоріях
            if not isinstance(category, dict) or not isinstance(category.get("id"), int) or category["id"] <= 0:  # id додатний
                raise SeedError("Кожна категорія має мати додатний цілий id")  # повідомлення
            CategoryCreate(name=category.get("name"))  # перевіряємо назву
            category_ids.add(category["id"])  # запам'ятовуємо id
        for record in records:  # проходимо по записах
            RecordCreate(**record)  # перевіряємо поля запису (extra="forbid" відхилить зайві)
            if record["category_id"] not in category_ids:  # посилання на невідому категорію
                raise SeedError("Запис посилається на неіснуючу категорію")  # повідомлення
    except (ValidationError, TypeError) as error:  # помилки моделі
        raise SeedError(f"Некоректні дані: {error}") from error  # зрозуміле повідомлення
    if len(category_ids) != len(categories):  # id категорій мають бути унікальні
        raise SeedError("Ідентифікатори категорій повторюються")  # повідомлення
    return categories, records  # повертаємо перевірені дані


def seed_database() -> bool:  # заповнення бази
    """Заповнити порожню базу. Повертає True, якщо дані додано."""  # опис функції
    categories, records = load_seed()  # спершу перевіряємо дані
    initialize_database()  # створюємо таблиці, якщо їх немає
    with closing(get_connection()) as connection, connection:  # з'єднання закриється після commit/rollback транзакції
        connection.execute("BEGIN IMMEDIATE")  # блокуємо запис, щоб перевірка порожнечі була надійною
        total = connection.execute(  # рахуємо наявні рядки
            "SELECT (SELECT COUNT(*) FROM categories) + (SELECT COUNT(*) FROM records)"  # сума по двох таблицях
        ).fetchone()[0]  # перше поле
        if total > 0:  # база вже містить дані
            return False  # нічого не змінюємо
        connection.executemany(  # додаємо категорії з id із JSON
            "INSERT INTO categories (id, name) VALUES (?, ?)",  # два параметри
            [(c["id"], c["name"].strip()) for c in categories],  # значення категорій
        )  # кінець вставки категорій
        connection.executemany(  # додаємо записи (id створює SQLite)
            "INSERT INTO records (code, title, category_id, value, status) "  # поля
            "VALUES (?, ?, ?, ?, ?)",  # п'ять параметрів
            [(r["code"].strip(), r["title"].strip(), r["category_id"], r["value"], r["status"]) for r in records],  # значення
        )  # кінець вставки записів
    return True  # дані додано


def main() -> int:  # точка входу
    """Запустити заповнення та повернути код завершення."""  # опис функції
    try:  # блок із обробкою помилок
        added = seed_database()  # виконуємо заповнення
    except SeedError as error:  # некоректні початкові дані
        print(f"Помилка початкових даних: {error}")  # повідомлення користувачу
        return 1  # код помилки
    except sqlite3.Error as error:  # порушення обмежень або помилка БД
        print(f"Помилка бази даних, зміни скасовано: {error}")  # повідомлення користувачу
        return 1  # код помилки
    if added:  # дані додано
        print("Додано 3 категорії та 8 записів.")  # повідомлення
    else:  # база не порожня
        print("База вже містить дані — заповнення пропущено.")  # повідомлення
    return 0  # успіх


if __name__ == "__main__":  # запуск: python -m labs.lab03.seed
    sys.exit(main())  # завершуємо з кодом результату
