"""Параметризовані SQL-запити. Модуль не залежить від FastAPI."""  # документація модуля

import sqlite3  # модуль SQLite
from contextlib import closing  # гарантоване закриття з'єднання
from typing import Any  # тип для довільних значень

from .database import get_connection  # функція відкриття з'єднання

RecordData = dict[str, Any]  # псевдонім: запис як словник
CategoryData = dict[str, Any]  # псевдонім: категорія як словник

SELECT_RECORD = (  # спільна частина SELECT із JOIN для читання записів
    "SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, "  # поля запису та назва категорії
    "r.value, r.status "  # числове значення та статус
    "FROM records AS r JOIN categories AS c ON c.id = r.category_id"  # з'єднуємо таблиці за category_id
)  # кінець SELECT_RECORD


class RecordNotFoundError(Exception):  # запис не знайдено
    """Запису з таким id не існує."""  # опис винятку


class CategoryNotFoundError(Exception):  # категорію не знайдено
    """Категорії з таким id не існує."""  # опис винятку


class CategoryNotEmptyError(Exception):  # категорія містить записи
    """Категорію не можна видалити, бо вона містить записи."""  # опис винятку


def _open() -> sqlite3.Connection:  # внутрішня функція відкриття з'єднання
    """Відкрити з'єднання з доступом до стовпців за іменами."""  # опис функції
    connection = get_connection()  # відкриваємо з'єднання з увімкненими FK
    connection.row_factory = sqlite3.Row  # рядки доступні як словники
    return connection  # повертаємо з'єднання


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:  # перевірка існування категорії
    """Повернути True, якщо категорія існує."""  # опис функції
    row = connection.execute(  # виконуємо параметризований запит
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)  # значення передаємо окремо від SQL
    ).fetchone()  # беремо перший рядок
    return row is not None  # True, якщо рядок знайдено


def _fetch_record(connection: sqlite3.Connection, record_id: int) -> RecordData | None:  # читання одного запису
    """Прочитати запис за id (з category_name) або повернути None."""  # опис функції
    row = connection.execute(  # виконуємо запит
        SELECT_RECORD + " WHERE r.id = ?", (record_id,)  # додаємо умову за id через параметр
    ).fetchone()  # беремо перший рядок
    return dict(row) if row is not None else None  # перетворюємо рядок у словник


def create_category(name: str) -> CategoryData:  # створення категорії
    """Створити категорію та повернути її."""  # опис функції
    with closing(_open()) as connection, connection:  # з'єднання закриється після commit/rollback транзакції
        cursor = connection.execute(  # вставляємо категорію
            "INSERT INTO categories (name) VALUES (?)", (name,)  # назва — параметр
        )  # кінець INSERT
        return {"id": cursor.lastrowid, "name": name}  # повертаємо створену категорію


def list_categories() -> list[CategoryData]:  # список категорій
    """Повернути категорії за зростанням id."""  # опис функції
    with closing(_open()) as connection:  # відкриваємо і закриваємо з'єднання
        rows = connection.execute(  # виконуємо вибірку
            "SELECT id, name FROM categories ORDER BY id ASC"  # сортуємо за id
        ).fetchall()  # отримуємо всі рядки
        return [dict(row) for row in rows]  # перетворюємо на список словників


def delete_category(category_id: int) -> None:  # видалення порожньої категорії
    """Видалити категорію, якщо вона існує і порожня."""  # опис функції
    with closing(_open()) as connection, connection:  # з'єднання закриється після commit/rollback транзакції
        connection.execute("BEGIN IMMEDIATE")  # одразу блокуємо запис, щоб перевірка й видалення були атомарні
        if not _category_exists(connection, category_id):  # категорії немає
            raise CategoryNotFoundError  # сигналізуємо про 404
        count = connection.execute(  # рахуємо записи категорії
            "SELECT COUNT(*) FROM records WHERE category_id = ?", (category_id,)  # id — параметр
        ).fetchone()[0]  # перше поле першого рядка
        if count > 0:  # у категорії є записи
            raise CategoryNotEmptyError  # сигналізуємо про 409
        connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))  # видаляємо порожню категорію


def create_record(data: RecordData) -> RecordData:  # створення запису
    """Створити запис і повернути його з category_name."""  # опис функції
    with closing(_open()) as connection, connection:  # з'єднання закриється після commit/rollback транзакції
        connection.execute("BEGIN IMMEDIATE")  # починаємо транзакцію з блокуванням запису
        if not _category_exists(connection, data["category_id"]):  # категорія не існує
            raise CategoryNotFoundError  # сигналізуємо про 404
        cursor = connection.execute(  # вставляємо запис
            "INSERT INTO records (code, title, category_id, value, status) "  # поля вставки
            "VALUES (?, ?, ?, ?, ?)",  # п'ять параметрів
            (data["code"], data["title"], data["category_id"], data["value"], data["status"]),  # значення
        )  # кінець INSERT
        record = _fetch_record(connection, cursor.lastrowid)  # читаємо створений запис з JOIN
        return record  # type: ignore[return-value]  # запис гарантовано існує


def get_record(record_id: int) -> RecordData:  # отримання запису за id
    """Повернути запис або викликати RecordNotFoundError."""  # опис функції
    with closing(_open()) as connection:  # відкриваємо і закриваємо з'єднання
        record = _fetch_record(connection, record_id)  # читаємо запис
        if record is None:  # запису немає
            raise RecordNotFoundError  # сигналізуємо про 404
        return record  # повертаємо запис


def list_records(  # список записів із фільтрами та пагінацією
    category_id: int | None,  # фільтр за категорією
    status: str | None,  # фільтр за статусом
    min_value: float | None,  # фільтр за мінімальним значенням
    q: str | None,  # буквальний підрядок у title
    limit: int,  # максимум записів
    offset: int,  # скільки пропустити
) -> list[RecordData]:  # повертає список записів
    """Повернути записи за фільтрами, відсортовані за id."""  # опис функції
    conditions: list[str] = []  # фрагменти WHERE — лише готові рядки з коду
    params: list[Any] = []  # значення для параметрів ?
    if category_id is not None:  # якщо задано category_id
        conditions.append("r.category_id = ?")  # додаємо умову
        params.append(category_id)  # додаємо значення окремо
    if status is not None:  # якщо задано status
        conditions.append("r.status = ?")  # додаємо умову
        params.append(status)  # додаємо значення
    if min_value is not None:  # якщо задано min_value
        conditions.append("r.value >= ?")  # додаємо умову
        params.append(min_value)  # додаємо значення
    if q is not None:  # якщо задано q
        conditions.append("instr(r.title, ?) > 0")  # буквальний пошук підрядка з урахуванням регістру
        params.append(q)  # додаємо значення
    sql = SELECT_RECORD  # починаємо з базового SELECT
    if conditions:  # якщо є фільтри
        sql += " WHERE " + " AND ".join(conditions)  # об'єднуємо умови через AND
    sql += " ORDER BY r.id ASC LIMIT ? OFFSET ?"  # стабільне сортування та пагінація
    params.extend([limit, offset])  # додаємо limit і offset
    with closing(_open()) as connection:  # відкриваємо і закриваємо з'єднання
        rows = connection.execute(sql, params).fetchall()  # виконуємо запит з параметрами
        return [dict(row) for row in rows]  # перетворюємо на список словників


def replace_record(record_id: int, data: RecordData) -> RecordData:  # повна заміна запису
    """Замінити змінювані поля запису; id не змінюється."""  # опис функції
    with closing(_open()) as connection, connection:  # з'єднання закриється після commit/rollback транзакції
        connection.execute("BEGIN IMMEDIATE")  # починаємо транзакцію з блокуванням запису
        if _fetch_record(connection, record_id) is None:  # запису немає
            raise RecordNotFoundError  # сигналізуємо про 404
        if not _category_exists(connection, data["category_id"]):  # нова категорія не існує
            raise CategoryNotFoundError  # сигналізуємо про 404
        connection.execute(  # оновлюємо запис
            "UPDATE records SET code = ?, title = ?, category_id = ?, value = ?, status = ? "  # п'ять полів
            "WHERE id = ?",  # id не змінюємо
            (data["code"], data["title"], data["category_id"], data["value"], data["status"], record_id),  # значення
        )  # кінець UPDATE
        return _fetch_record(connection, record_id)  # type: ignore[return-value]  # читаємо оновлений запис


def delete_record(record_id: int) -> None:  # видалення запису
    """Видалити запис або викликати RecordNotFoundError."""  # опис функції
    with closing(_open()) as connection, connection:  # з'єднання закриється після commit/rollback транзакції
        connection.execute("BEGIN IMMEDIATE")  # починаємо транзакцію з блокуванням запису
        if _fetch_record(connection, record_id) is None:  # явна перевірка існування
            raise RecordNotFoundError  # сигналізуємо про 404
        connection.execute("DELETE FROM records WHERE id = ?", (record_id,))  # видаляємо запис


def create_records_bulk(items: list[RecordData]) -> list[RecordData]:  # пакетне створення
    """Створити всі записи в одній транзакції або жодного."""  # опис функції
    with closing(_open()) as connection, connection:  # з'єднання закриється після commit/rollback транзакції
        connection.execute("BEGIN IMMEDIATE")  # починаємо транзакцію з блокуванням запису
        created_ids: list[int] = []  # id створених записів
        for item in items:  # проходимо по елементах пакета
            if not _category_exists(connection, item["category_id"]):  # категорії немає
                raise CategoryNotFoundError  # відкат усього пакета, 404
            cursor = connection.execute(  # вставляємо елемент
                "INSERT INTO records (code, title, category_id, value, status) "  # поля вставки
                "VALUES (?, ?, ?, ?, ?)",  # п'ять параметрів
                (item["code"], item["title"], item["category_id"], item["value"], item["status"]),  # значення
            )  # дублікат code дасть IntegrityError і відкат пакета
            created_ids.append(cursor.lastrowid)  # type: ignore[arg-type]  # запам'ятовуємо id
        return [_fetch_record(connection, new_id) for new_id in created_ids]  # type: ignore[misc]  # читаємо створені
