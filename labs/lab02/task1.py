from __future__ import \
    annotations  # Дозволяє використовувати назви класів як типи до того, як вони повністю визначені в коді

import hashlib  # Модуль для створення криптографічних хешів (незворотного шифрування)
import hmac  # Модуль для безпечного порівняння криптографічних значень (захищає від таймінг-атак)
import ipaddress  # Модуль для перевірки, чи є рядок коректною IP-адресою
import os  # Модуль для доступу до функцій операційної системи (тут — для генерації випадкових байтів солі)
import re  # Модуль для роботи з регулярними виразами (шаблонами для пошуку/перевірки тексту)
from collections.abc import \
    Iterable  # Базовий клас для об'єктів, які можна перебирати в циклі (наприклад, списки, множини)
from dataclasses import \
    dataclass  # Декоратор, який автоматично пише рутинний код (__init__, __repr__) для класів-контейнерів
from datetime import datetime, timedelta, timezone  # Класи для роботи з часом, різницею в часі та часовими поясами

PBKDF2_ITERATIONS = 200_000  # Встановлюємо 200 тисяч ітерацій хешування, щоб уповільнити процес підбору пароля зловмисником
SALT_SIZE_BYTES = 16  # Задаємо розмір криптографічної "солі" у 16 байтів (рекомендований мінімум для безпеки)
SESSION_TIMEOUT_SEC = 900  # Час неактивності в секундах, після якого сесія автоматично закривається (15 хвилин)

# Створюємо скомпільований регулярний вираз для перевірки формату електронної пошти
# ^ - початок рядка, [A-Za-z] - перша літера латинська, [A-Za-z0-9_]{2,63} - від 2 до 63 символів імені,
# @ - обов'язковий символ, [A-Za-z0-9.-]+\.[A-Za-z0-9.-]+$ - домен із хоча б однією крапкою, $ - кінець рядка.
EMAIL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9.-]+\.[A-Za-z0-9.-]+$")


def _utcnow() -> datetime:
    """Повертає поточний час UTC обов'язково з прив'язкою до часового поясу."""
    # datetime.now(timezone.utc) бере поточний системний час і одразу каже, що це час за Грінвічем (UTC)
    return datetime.now(timezone.utc)


def _derive_key(password: str, salt: bytes) -> bytes:
    """Обчислює криптографічний хеш PBKDF2-HMAC-SHA256 для пароля з додаванням солі."""
    # hashlib.pbkdf2_hmac створює захищений хеш: використовує алгоритм sha256,
    # перетворює текстовий пароль у байти (.encode("utf-8")), додає унікальну сіль і проганяє це 200 000 разів
    return hashlib.pbkdf2_hmac( "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


class User:
    """Клас моделі звичайного користувача."""

    def __init__(
            self,  # Посилання на сам створюваний об'єкт
            username: str,  # Логін користувача (очікується рядок)
            email: str,  # Пошта користувача (очікується рядок)
            password: str,  # Відкритий пароль при реєстрації
            role: str = "user",  # Роль за замовчуванням — звичайний користувач
            active: bool = True,  # Статус облікового запису (активний за замовчуванням)
    ) -> None:
        # Перевіряємо, чи передали рядок і чи він не порожній (після видалення пробілів по краях)
        if not isinstance(username, str) or not username.strip():
            # Якщо логін поганий, зупиняємо програму з помилкою ValueError
            raise ValueError("username має бути непорожнім рядком")

        self.username = username.strip()  # Зберігаємо очищений від зайвих пробілів логін
        self.role = role  # Зберігаємо роль користувача
        self.active = active  # Зберігаємо статус активності

        self.__password_hash = b""  # Створюємо порожнє приватне поле для хешу пароля (в байтах)
        self.__password_salt = b""  # Створюємо порожнє приватне поле для солі (в байтах)

        self._email = ""  # Приватне поле для зберігання перевіреної пошти
        # Звертаємося до властивості (property) email, що викличе метод email.setter для перевірки формату
        self.email = email

        # Викликаємо метод для генерації солі та створення безпечного хешу з введеного відкритого пароля
        self.set_password(password)

    @property
    def email(self) -> str:
        """Геттер для отримання email."""
        # Коли хтось просить user.email, ми просто повертаємо приховане значення _email
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Сеттер з валідацією пошти за регулярним виразом."""
        # Перевіряємо, чи це рядок і чи відповідає він нашому регулярному виразу EMAIL_PATTERN
        if not isinstance(value, str) or EMAIL_PATTERN.fullmatch(value) is None:
            # Якщо перевірка не пройдена — кидаємо помилку з текстом
            raise ValueError(f"Некоректний email: {value!r}")
        # Якщо все добре, зберігаємо значення у внутрішнє поле
        self._email = value

    def set_password(self, password: str) -> None:
        """Генерує випадкову сіль і зберігає лише результат хешування"""
        # Перевіряємо, чи пароль є рядком і чи він не порожній
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль має бути непорожнім рядком")

        # os.urandom створює 16 випадкових байтів для солі
        salt = os.urandom(SALT_SIZE_BYTES)
        # Зберігаємо цю сіль у приватне поле
        self.__password_salt = salt
        # Викликаємо функцію хешування і зберігаємо результат у приватне поле
        self.__password_hash = _derive_key(password, salt)

    def check_password(self, password: str) -> bool:
        """Перевіряє правильність введеного пароля."""
        # Якщо передали не рядок, одразу кажемо, що пароль неправильний
        if not isinstance(password, str):
            return False
        # Хешуємо введений пароль з тією самою сіллю, що лежить у користувача
        candidate = _derive_key(password, self.__password_salt)
        # Порівнюємо отриманий хеш із збереженим безпечним методом, щоб уникнути атак за часом виконання
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        """Деактивація облікового запису користувача."""
        # Просто перемикаємо прапорець active на False
        self.active = False

    def __str__(self) -> str:
        """Рядкове представлення без витоку конфіденційних полів пароля."""
        # Повертаємо красивий рядок із типом класу, іменем, поштою, роллю та статусом (пароля тут немає!)
        return (
            f"{type(self).__name__}(username={self.username}, email={self.email}, "
            f"role={self.role}, active={self.active})"
        )


class Admin(User):
    """Клас адміністратора, що демонструє наслідування."""

    def __init__(
            self,
            username: str,  # Ті самі параметри, що й у звичайного користувача
            email: str,
            password: str,
            role: str = "admin",  # Роль за замовчуванням тепер "admin"
            active: bool = True,
            permissions: Iterable[str] | None = None,
            # Додано новий аргумент: набір початкових прав (може бути порожнім)
    ) -> None:
        # Викликаємо конструктор батьківського класу User, щоб він зберіг ім'я, пароль і пошту
        super().__init__(username, email, password, role, active)

        # Якщо права передали, робимо з них множину (set), інакше створюємо порожню множину
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        """Надання нового права доступу."""
        # Перевіряємо, чи назва права є коректним рядком
        if not isinstance(permission, str) or not permission.strip():
            raise ValueError("Дозвіл має бути непорожнім рядком")
        # Додаємо право у множину прав адміністратора
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Відкликання права доступу."""
        # Метод discard безпечно видаляє елемент з множини (не видасть помилку, якщо такого елемента там і не було)
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевірка наявності права доступу в адміністратора."""
        # Повертає True, якщо передане право є у множині self.permissions, і False, якщо ні
        return permission in self.permissions

    def __str__(self) -> str:
        """Розширене рядкове представлення з відсортованим переліком прав."""
        # Беремо представлення базового класу (super().__str__()) і доклеюємо відсортований список прав
        return f"{super().__str__()}, permissions={sorted(self.permissions)}"


class Session:
    """Сеанс активності користувача."""

    def __init__(self, ip: str, login_time: datetime | None = None) -> None:
        # Валідуємо рядок IP-адреси Якщо IP неправильний, тут програма впаде з ValueError
        ipaddress.ip_address(ip)
        self.ip = ip  # Зберігаємо валідний IP
        # Якщо час логіну не передали, беремо поточний UTC-час через _utcnow()
        self.login_time = login_time or _utcnow()
        # При створенні сесії час останньої активності такий самий, як час створення
        self.last_activity = self.login_time

    def touch(self) -> None:
        """Оновлює мітку останньої активності користувача на поточний час UTC."""
        # Оновлюємо атрибут last_activity поточним часом
        self.last_activity = _utcnow()

    def is_active(self, timeout_sec: int, now: datetime | None = None) -> bool:
        """Перевіряє, чи не минув встановлений ліміт бездіяльності."""
        # Якщо передали від'ємний або нульовий час, це помилка
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        # Якщо поточний час не передали явно для тестів, беремо реальний час зараз
        current = now or _utcnow()
        # Віднімаємо від поточного часу час останньої активності та перевіряємо, чи ця різниця менша за таймаут
        return (current - self.last_activity) < timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
# Декоратор автоматично створює конструктор. frozen=True робить об'єкти незмінними (їх не можна редагувати після створення)
class AuditEntry:
    """Незмінний клас даних (Data Class) для окремого запису в журналі безпеки."""

    timestamp: datetime  # Час події
    username: str  # Логін користувача, з яким пов'язана подія
    action: str  # Опис самої події (наприклад, "login_success")

    def __str__(self) -> str:
        # Форматуємо час у зручний рядок стандарту ISO (тільки до секунд)
        stamp = self.timestamp.isoformat(timespec="seconds")
        # Повертаємо рядок у форматі "Час | Користувач | Подія"
        return f"{stamp} | {self.username} | {self.action}"


class AuditLog:
    """Журнал подій безпеки системи."""

    def __init__(self) -> None:
        # Створюємо порожній список, у якому будуть зберігатися об'єкти AuditEntry
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> list[AuditEntry]:
        """Повертає поверхневу копію списку, щоб зовнішній код не міг очистити оригінал."""
        # Копіюємо список через list(), щоб ніхто випадково не змінив оригінальний приватний список
        return list(self._entries)

    def add_log(self, username: str, action: str) -> AuditEntry:
        """Створює новий запис аудиту."""
        # Створюємо новий об'єкт запису з поточним часом
        entry = AuditEntry(_utcnow(), username, action)
        # Додаємо цей об'єкт до нашого списку подій
        self._entries.append(entry)
        # Повертаємо створений запис (іноді це зручно для подальшого використання в коді)
        return entry

    def show_all(self) -> None:
        """Виводить усі події журналу в консоль."""
        # Якщо список порожній, просто друкуємо повідомлення
        if not self._entries:
            print("(журнал порожній)")
        # Проходимося циклом по всіх записах
        for entry in self._entries:
            # Виводимо запис на екран (тут автоматично спрацює метод __str__ класу AuditEntry)
            print(entry)


class UserAccount:
    """Обліковий запис: реалізує композицію (містить у собі User, Session, AuditLog)."""

    # Словник правил, який вказує, який тип даних може бути записаний у певні ключі
    _KEY_TYPES: dict[str, type | tuple[type, ...]] = {
        "user": User,  # Ключ user має бути об'єктом класу User
        "session": (Session, type(None)),  # Ключ session може бути класом Session або None
        "audit_log": AuditLog,  # Ключ audit_log має бути класом AuditLog
    }

    def __init__(
            self,
            user: User,  # Обов'язково передаємо об'єкт користувача
            session: Session | None = None,  # Сесія спочатку може бути порожньою
            audit_log: AuditLog | None = None,  # Лог аудиту також може бути порожнім
    ) -> None:
        # Прикріплюємо об'єкт користувача
        self.user = user
        # Прикріплюємо об'єкт сесії (якщо передано)
        self.session = session
        # Якщо передали свій аудит — беремо його, якщо ні — створюємо новий порожній журнал
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Спроба входу в систему."""
        # Перевіряємо три умови: чи збігається логін, чи активний акаунт, чи підходить пароль
        ok = (
                username == self.user.username
                and self.user.active
                and self.user.check_password(password)
        )
        if not ok:
            # Якщо хоча б одна умова хибна — записуємо в журнал невдалу спробу
            self.audit_log.add_log(username, "login_failure")
            # Повертаємо False (вхід не вдався)
            return False

        # Якщо пароль правильний — створюємо нову сесію з переданим IP
        self.session = Session(ip)
        # Оновлюємо час останньої активності сесії
        self.session.touch()
        # Записуємо в журнал успішний вхід
        self.audit_log.add_log(username, "login_success")
        # Повертаємо True (вхід вдався)
        return True

    def is_authenticated(self) -> bool:
        """Перевіряє валідність сеансу."""
        # Якщо сесії немає або користувач заблокований, він не автентифікований
        if self.session is None or not self.user.active:
            return False

        # Перевіряємо, чи час бездіяльності не перевищив таймаут
        if not self.session.is_active(SESSION_TIMEOUT_SEC):
            # Якщо час вийшов — записуємо подію таймауту в журнал
            self.audit_log.add_log(self.user.username, "session_timeout")
            # Знищуємо протерміновану сесію
            self.session = None
            # Повертаємо False (треба заходити наново)
            return False
        # Якщо сесія є і вона активна, повертаємо True
        return True

    def logout(self) -> None:
        """Вихід із системи."""
        # Якщо сесії й так немає — нічого не робимо
        if self.session is None:
            return
        # Знищуємо сесію, прирівнюючи її до None
        self.session = None
        # Записуємо подію успішного виходу в журнал
        self.audit_log.add_log(self.user.username, "logout")

    #Спеціальні методи для роботи з об'єктом як зі словником

    def __getitem__(self, key: str) -> object:
        """Дозволяє отримувати об'єкти як у словнику: account['user']."""
        # Якщо запитують ключ, якого немає в дозволеному словнику _KEY_TYPES, кидаємо KeyError
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        # За допомогою getattr дістаємо відповідний атрибут (self.user, self.session тощо)
        return getattr(self, key)

    def __setitem__(self, key: str, value: object) -> None:
        """Дозволяє змінювати поля через account['user'] = ..."""
        # Якщо ключ заборонений — кидаємо KeyError
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        # Перевіряємо, чи тип нового значення збігається з дозволеними типами для цього ключа
        if not isinstance(value, self._KEY_TYPES[key]):
            # Якщо тип неправильний, кидаємо TypeError
            raise TypeError(f"Неправильний тип значення для ключа {key!r}")
        # Записуємо нове значення у відповідний атрибут через setattr
        setattr(self, key, value)


def run_demo() -> None:
    """Сценарій демонстрації: показує роботу всіх компонентів."""
    print("=== 1. Створення об'єктів ===")
    # Створюємо звичайного користувача Алісу
    user = User("alice_01", "alice_01@example.com", "S3cret!pass")
    # Створюємо адміністратора
    admin = Admin("root_admin", "root_admin@corp.ua", "Adm1n!pass")
    # Друкуємо дані створеного користувача (паролі будуть сховані)
    print(user)
    # Друкуємо дані створеного адміна
    print(admin)

    # Збираємо користувача Алісу в контейнер "облікового запису" (UserAccount)
    account = UserAccount(user)

    print("\n=== 2. Невдалий та успішний вхід ===")
    ip = "192.168.1.10"  # Тестова IP адреса
    # Пробуємо зайти з неправильним паролем і друкуємо результат
    print("Спроба з неправильним паролем:", account.login("alice_01", "wrong", ip))
    # Пробуємо зайти з правильним паролем
    print("Спроба з правильним паролем  :", account.login("alice_01", "S3cret!pass", ip))
    # Перевіряємо, чи в системі Аліса зараз (має бути True)
    print("Статус автентифікації       :", account.is_authenticated())

    print("\n=== 3. Зміна email із валідацією  ===")
    # Змінюємо пошту Аліси на валідну
    user.email = "alice_new@example.org"
    print("Новий успішно встановлений email:", user.email)
    # Створюємо кортеж із свідомо некоректних адрес
    for bad in ("1alice@example.com", "al@example.com", "alice@localhost"):
        try:
            # Пробуємо присвоїти неправильну адресу
            user.email = bad
        except ValueError as exc:
            # Перехоплюємо помилку від сеттера і друкуємо текст помилки
            print("Відхилено некоректний email:", exc)

    print("\n=== 4. Права адміністратора (Admin Is-A User) ===")
    # Видаємо адміну право на керування користувачами
    admin.grant_permission("manage_users")
    # Видаємо адміну право на читання логів
    admin.grant_permission("read_logs")
    print(admin)  # Друкуємо адміна, щоб побачити оновлений список прав
    # Перевіряємо, чи право дійсно застосувалося
    print("Чи є право manage_users:", admin.has_permission("manage_users"))
    # Забираємо право назад
    admin.revoke_permission("manage_users")
    # Перевіряємо ще раз, права вже не має бути
    print("Чи є право manage_users після revoke:", admin.has_permission("manage_users"))

    print("\n=== 5. Завершення сеансу за таймаутом ===")
    # Переконуємось, що сесія взагалі існує
    assert account.session is not None
    # Симулюємо неактивність, штучно відмотавши час останньої активності в минуле (понад 15 хвилин тому)
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    # Тепер is_authenticated має виявити таймаут і закрити сесію (поверне False)
    print("is_authenticated після простою:", account.is_authenticated())

    print("\n=== 6. Повторний вхід і вихід (logout) ===")
    # Логінимось заново
    account.login("alice_01", "S3cret!pass", "192.168.1.10")
    print("is_authenticated після входу:", account.is_authenticated())
    # Примусово виходимо з системи
    account.logout()
    # Перевіряємо, що після виходу статус дійсно False
    print("is_authenticated після logout:", account.is_authenticated())

    print("\n=== 7. Доступ через account[...] (__getitem__ / __setitem__) ===")
    # Доступ до користувача як у словнику за ключем 'user'
    print("account['user'] ->", account["user"])
    # Пробуємо отримати заборонені або неіснуючі ключі
    for key in ("password_hash", "unknown"):
        try:
            account[key]
        except KeyError as exc:
            # Наш метод __getitem__ відкине цей запит
            print(f"Перехоплено очікуваний KeyError для '{exc}'")
    # Пробуємо записати замість користувача просто текстовий рядок
    try:
        account["user"] = "not a user"
    except TypeError as exc:
        # Метод __setitem__ перевірить тип і видасть помилку, оскільки рядок — це не об'єкт User
        print("Перехоплено очікуваний TypeError:", exc)

    # Переходимо до кроку 8
    print("\n=== 8. Журнал аудиту (AuditLog) ===")
    # Виводимо на екран всю історію дій, яку охоронець записував у лог
    account.audit_log.show_all()