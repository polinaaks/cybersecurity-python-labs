import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "D:\rgithub\rcybersecurity-python-labs")
    )
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

print(f"Студентка: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"  # формуємо персональну сіль
MIN_PASSWORD_LENGTH = 12


class ValidationError(Exception):  # створюємо власний виняток для помилок
    pass


def generate_hash(password: str, salt: str = "00000") -> str:  # хешування

    if (
        not password or not salt
    ):  # перевіряємо чи не передані порожні рядки або значення None
        raise ValueError("Пароль або сіль не можуть бути порожніми")

    if (
        len(password) < MIN_PASSWORD_LENGTH
    ):  # перевіряємо чи пароль має мінімальну довжину
        raise ValidationError(
            f"Пароль коротший за мінімальну довжину ({MIN_PASSWORD_LENGTH} символів)"
        )

    data_to_hash = (password + salt).encode(
        "utf-8"
    )  # з'єднуємо пароль і сіль у єдиний рядок, а потім перетворюємо його у байти
    return hashlib.sha3_512(data_to_hash).hexdigest()  # обчислимо хеш за алгоритмом


def create_user(username: str, password: str) -> tuple:
    """Хеш для користувача з сіллю"""

    hash_value = generate_hash(
        password, PERSONAL_SALT
    )  # викликаємо функцію генерації хешу
    return username, hash_value  # повертаємо кортеж


def create_users(users_list: tuple):
    """Створюєму базу даних у CSV"""

    os.makedirs("labs/lab01/data", exist_ok=True)
    filepath = "labs/lab01/data/users.csv"

    with open(
        filepath, mode="w", newline="", encoding="utf-8"
    ) as file:  # відкриваємо файл на запис
        writer = csv.writer(file)
        for user in users_list:
            if not user[0]:
                print("Пропущено запис без логіна")
                continue
            try:
                writer.writerow(
                    create_user(user[0], user[1])
                )  # генеруємо та записуємо хешовані дані
            except ValidationError:
                writer.writerow(
                    (user[0], "[ПОМИЛКА: Пароль занадто короткий для хешування]")
                )
            except ValueError as e:
                writer.writerow((user[0], f"[ПОМИЛКА: {e}]"))


def read_db() -> list:
    """Читаємо CSV і виводимо дані у таблиці"""

    filepath = "labs/lab01/data/users.csv"
    users_db = []

    with open(filepath, mode="r", encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            if row:
                users_db.append(tuple(row))

    print(f"{'Логін':<15} | {'Хеш пароля (sha3_512)'}")
    print("-" * 145)
    for user in users_db:
        print(f"{user[0]:<15} | {user[1]}")

    return users_db


def log_event(func):
    """Декоратор для логування спроб входу у файл JSON"""

    def wrapper(
        username: str, password: str, *args, **kwargs
    ):  # функція перехоплення перед викликом оригінальної функції
        os.makedirs("labs/lab01/data", exist_ok=True)
        log_file = "labs/lab01/data/log.json"

        result_status = "failure"  # за замовчуванням вважаємо спробу невдалою на випадок збою або винятку
        result = False

        try:
            result = func(
                username, password, *args, **kwargs
            )  # викликаємо  (задекоровану) функцію перевірки автентифікації
            if result:  # якщо функція повернула True (пароль підійшов), статус змінюється на "success"
                result_status = "success"
        except (
            ValidationError,
            ValueError,
        ) as e:  # перехоплюємо будь-які винятки (наприклад, ValidationError, якщо пароль закороткий)
            result_status = "failure"  # статус залишається "failure", а опис винятку виводиться в консоль
            print(f"[Помилка валідації/входу для '{username}']: {e}")
            result = False
        finally:  # блок finally гарантовано виконується завжди
            log_entry = {  # формуємо словник із детальною інформацією про подію входу
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            logs = []  # ініціалізуємо порожній список для збереження історії логів
            if os.path.exists(
                log_file
            ):  # перевіряємо, чи вже існує файл логів на диску
                try:
                    with open(log_file, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (
                    OSError,
                    json.JSONDecodeError,
                ):  # якщо файл пошкоджений, порожній або виникла помилка читання — скидаємо список у порожній
                    logs = []

            logs.append(log_entry)  # додаємо новий сформований запис до списку логів

            with open(
                log_file, "w", encoding="utf-8"
            ) as f:  # перезаписуємо файл з урахуванням нового запису
                json.dump(logs, f, indent=4, ensure_ascii=False)

        return result  # повертаємо початковий результат роботи функції

    return wrapper  # повертаємо обгортку, яка заміщує оригінальну функцію


users_db = []  # змінна для імітації бази данних


@log_event  # застосовуємо декоратор @log_event для фіксації кожного виклику функції login у JSON-файл
def login(username: str, password: str) -> bool:
    """Перевіряє чи збігається хеш введеного пароля зі збереженим у БД"""
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми")

    hashed_attempt = generate_hash(
        password, PERSONAL_SALT
    )  # хешуємо введений користувачем пароль разом із персональною сіллю
    # якщо пароль закороткий (< 12 символів), функція generate_hash згенерує ValidationError

    for user in users_db:
        if (
            user[0] == username and user[1] == hashed_attempt
        ):  # Перевіряємо точний збіг як логіна (індекс 0), так і обчисленого хеша (індекс 1)
            print(f"[УСПІХ] Користувач '{username}' успішно увійшов у систему")
            return True
    print(
        f"[НЕУСПІХ] Користувач '{username}': невірний пароль або користувача не існує"
    )
    return False


def main():
    # 10 записів користувачів
    users_to_register = (
        ("admin", "Admin_Secret_2024!"),
        ("student1", "Student_Pass_1234"),
        ("user_test", "Testing_App_123!"),
        ("dev_ops", "DevOps_Master_321"),
        ("manager", "Manager_Pass_007"),
        ("guest_user", "Guest_Password_1"),
        ("support", "Support_Team_999"),
        ("analyst", "Analyst_Data_123"),
        ("sysadmin", "SysAdmin_Root_01"),
        ("hacker_01", "Hacker_Pass_1337"),
        ("", "Hacker_Pass_1337"),
    )

    global users_db

    try:
        print("Створення БД")
        create_users(users_to_register)  # генерація та запис бази даних у CSV
        print("\n")

        print("Зчитування БД")
        users_db = read_db()  # зчитування даних із CSV, форматований вивід таблиці та збереження в змінну users_db
        print("\n")

        print("Тестування автентифікації")

        login("admin", "Admin_Secret_2024!")  # Успішний вхід
        login("admin", "Wrong_Password_123")  # Неуспішний вхід
        login("student1", "short")  # Спровокує ValidationError

    except FileNotFoundError as e:
        print(f"\n[Помилка] Файл не знайдено: {e}")
    except PermissionError as e:
        print(f"\n[Помилка] Немає доступу до файлу: {e}")
    except OSError as e:
        print(f"\n[Помилка] Помилка вводу/виводу: {e}")
    except ValidationError as e:
        print(f"\n[Помилка валідації] {e}")
    except ValueError as e:
        print(f"\n[Помилка значення] {e}")


if __name__ == "__main__":
    main()
