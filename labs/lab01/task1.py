import os
import random
import string
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'D:\rgithub\rcybersecurity-python-labs')))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = ["password123", "Qwerty!2023", "admin", "MyP@ssw0rd", "123456",
"SecurePass!", "test", "P@ssw0rd123", "welcome", "StrongP@ss1"]
criteria = {"min_length": 8, "require_digits": True, "require_upper": True,
"require_special": True}
forbidden_passwords = {"password", "123456", "admin", "test", "welcome",
"qwerty"}
print(f"Студентка: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

"""Повторне використання паролів"""
for i in range(3):
    random_index = random.randint(0, len(passwords) - 1) # Генеруємо випадковий індекс від 0 до останнього елемента
    duplicate_password = passwords[random_index] # Беремо пароль за цим індексом
    passwords.append(duplicate_password)  # Додаємо дублікат у кінець початкового списку
    print(passwords)

"""Оцінка надійності паролів"""

print(f" {'Пароль':<18} | {'Довжина':<7} | {'Статус':<15}")
print("-" * 45)
for password in passwords:
    has_digit = any(c.isdigit() for c in password)  # чи є хоча б одна цифра
    has_upper = any(c.isupper() for c in password)  # чи є велика літера
    has_special = any(c in string.punctuation for c in password)  # чи є спецсимвол
    if password in forbidden_passwords or len(password) < criteria["min_length"] :
        status = "Заборонений"
    elif passwords.count(password) == 1 and len(password) >= (criteria["min_length"] + 4) and has_digit == True and has_upper == True and has_special == True:
        status = "Дуже сильний"
    elif len(password) < (criteria["min_length"] + 4) and has_digit == True and has_upper == True and has_special == True:
        status = "Сильний"
    elif len(password) >= criteria["require_digits"] and (has_digit or has_upper or has_special):
        status = "Середній"
    elif has_digit == True or has_upper == True or has_special == True:
        status = "Слабкий"

    print(f" {password:<18} | {len(password):<7} | {status:<15}")