import hashlib
import os
import sys
import csv
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'D:\rgithub\rcybersecurity-python-labs')))
from shared.student import VARIANT_NUMBER

PERSONAL_SALT = f"{VARIANT_NUMBER:05d}" # формуємо персональну сіль
MIN_PASSWORD_LENGTH = 12

class ValidationError(Exception): # створюємо власний виняток для помилок
    pass

def generate_hash(password: str, salt: str = "00000") -> str: # хешування

    if not password or not salt: # перевіряємо чи не передані порожні рядки або значення None
        raise ValueError("Пароль або сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH: # перевіряємо чи пароль має мінімальну довжину
        raise ValidationError(f"Пароль коротший за мінімальну довжину ({MIN_PASSWORD_LENGTH} символів)")

    data_to_hash = (password + salt).encode('utf-8') # з'єднуємо пароль і сіль у єдиний рядок, а потім перетворюємо його у байти
    return hashlib.sha3_512(data_to_hash).hexdigest() # обчислимо хеш за алгоритмом

"""Хеш для користувача з сіллю"""
def create_user(username: str, password: str) -> tuple:

    hash_value = generate_hash(password, PERSONAL_SALT) # викликаємо функцію генерації хешу
    return username, hash_value # повертаємо кортеж

"""Створюєму базу даних у CSV"""
def create_users(users_list: list):

    os.makedirs("labs/lab01/data", exist_ok=True)
    filepath = "labs/lab01/data/users.csv"

    with open(filepath, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        for user in users_list:
            writer.writerow(create_user(user[0], user[1]))

"""Читаємо CSV і виводимо дані у таблиці"""
def read_db() -> list:

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

"""Декоратор для логування спроб входу у файл JSON"""
def log_event(func):

    def wrapper(username: str, password: str, *args, **kwargs): # функція перехоплення перед викликом оригінальної функції
        os.makedirs("labs/lab01/data", exist_ok=True)
        log_file = "labs/lab01/data/log.json"

        result_status = "failure"
        result = False

        try:
            result = func(username, password, *args, **kwargs)
            if result:
                result_status = "success"
        except Exception:
            result_status = "failure"
            raise  # Прокидаємо виняток далі для обробки у main()
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs
            }

            # Читаємо існуючі логи або створюємо новий список
            logs = []
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, IOError):
                    logs = []

            logs.append(log_entry)

            with open(log_file, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

        return result

    return wrapper


users_db = [] # змінна для імітації бази данних

"""Перевіряє чи збігається хеш введеного пароля зі збереженим у БД"""
@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми")

    hashed_attempt = generate_hash(password, PERSONAL_SALT)   # використовуємо generate_hash

    for user in users_db:
        if user[0] == username and user[1] == hashed_attempt:
            return True
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
        ("hacker_01", "Hacker_Pass_1337")
    )

    global users_db

    try:
        print("Створення БД")
        create_users(users_to_register)
        print("\n")

        print("Зчитування БД")
        users_db = read_db()
        print("\n")

        print("Тестування автентифікації")

        login("admin", "Admin_Secret_2024!")  # Успішний вхід
        login("admin", "Wrong_Password_123")  # Неуспішний вхід
        login("student1", "short")  # Спровокує ValidationError

    except FileNotFoundError as e:
        print(f"\n[Помилка] Файл не знайдено: {e}")
    except PermissionError as e:
        print(f"\n[Помилка] Немає доступу до файлу: {e}")
    except IOError as e:
        print(f"\n[Помилка] Помилка вводу/виводу: {e}")
    except ValidationError as e:
        print(f"\n[Помилка валідації] {e}")
    except ValueError as e:
        print(f"\n[Помилка значення] {e}")
    except Exception as e:
        print(f"\n[Невідома помилка] {e}")


if __name__ == "__main__":
    main()