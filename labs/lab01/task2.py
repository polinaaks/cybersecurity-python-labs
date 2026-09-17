import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'D:\rgithub\rcybersecurity-python-labs')))
users = {
    "admin001": {"role": "administrator", "clearance": 4, "department": "IT",
"active": True},
    "user123": {"role": "analyst", "clearance": 2, "department": "Security",
"active": True},
    "guest789": {"role": "guest", "clearance": 1, "department": "External",
"active": True},
    "manager456": {"role": "manager", "clearance": 3, "department":
"Operations", "active": True},
    "contractor99": {"role": "contractor", "clearance": 1, "department":
"External", "active": False}
}
resources = [("database_backup", 4), ("user_logs", 2), ("public_docs", 1),
("financial_reports", 3), ("system_config", 4), ("training_materials", 1),
("security_policies", 3), ("audit_logs", 4), ("employee_data", 3),
("temp_files", 1)]
security_levels = ("Public", "Internal", "Confidential", "Secret")
blocked_users = {"contractor99", "temp_user", "suspended_acc"}

"""Чичловий рівень ресурсу замінено на текстову назву"""
for res_name, res_lvl in resources:
    level_name = security_levels[res_lvl - 1]
    print(f"Ресурс: {res_name} | Рівень: {level_name}")

"""Алгоритим перевірки доступу кожного користувача"""
users_to_check = list(users.keys())
for user_id in users_to_check:
    for res_name, res_lvl in resources:

        if user_id not in users: # перевірка чи є користувач у системі
            print(f"user={user_id} resource={res_name} -> DENY (User not found)")

        elif user_id in blocked_users:  # перевірка чи є користувач у списку заблокованих
            print(f"user={user_id} resource={res_name} -> DENY (User is blocked)")

        elif not users[user_id]["active"]: # перевірка чи активний обліковий запис
            print(f"user={user_id} resource={res_name} -> DENY (Account inactive)")

        elif users[user_id]["clearance"] >= res_lvl: # перевірка чи достатній рівень допуску
            print(f"user={user_id} resource={res_name} -> ALLOW")

        else:
            print(f"user={user_id} resource={res_name} -> DENY (Insufficient clearance)")

    print("-" * 50)
