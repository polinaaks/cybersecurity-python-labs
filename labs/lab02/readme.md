# ЛР №2 — Розробка консольних утиліт для задач кібербезпеки

**Варіант 1:** Аналізатор журналів веб-сервера (Nginx/Apache Access Log).
Перевірте, що `shared/student.py` містить `VARIANT_NUMBER = 1`.

## Встановлення
```bash
# з кореня репозиторію, в активованому .venv з ЛР №1
pip install -r requirements.txt
```

## Структура
```
labs/lab02/
├── main.py      # команди demo та analyze
├── task1.py     # User, Admin, Session, AuditEntry, AuditLog, UserAccount
├── task2.py     # аналізатор access.log
├── README.md
└── data/
    └── data_v01/
        └── access.log   # вхідний файл (з архіву lab2_data.zip)
```
Каталог `data_v01` із архіву `lab2_data.zip` розмістіть у `labs/lab02/data/`
зі збереженням назв файлів. Якщо файл логу називається інакше, передайте
його шлях через `--log-file`.

## Запуск
```bash
python -m labs.lab02.main demo
python -m labs.lab02.main analyze
python -m labs.lab02.main analyze --log-file labs/lab02/data/data_v01/access.log \
    --output labs/lab02/data/data_v01/web_analysis_report.json \
    --min-status 400 --top 3 --format json
python -m labs.lab02.main analyze --format csv --start "2026-09-27 09:00:00" \
    --end "2026-09-27 10:00:00"
python -m labs.lab02.main --verbose 
```

## Параметри `analyze`
| Параметр | Опис | Типово |
|---|---|---|
| `--log-file` | шлях до access.log | `labs/lab02/data/data_v01/access.log` |
| `--output` | шлях до звіту | `web_analysis_report.<format>` поруч із логом |
| `--min-status` | мінімальний статус-код помилки (100–599) | 400 |
| `--top` | кількість IP у рейтингу (>0) | 5 |
| `--format` | `json` або `csv` | `json` |
| `--start`, `--end` | межі інтервалу `YYYY-MM-DD[ HH:MM:SS]` (додатково) | без обмежень |

## Поведінка при помилках
- Файл не знайдено / немає доступу / помилка читання — повідомлення
  `[ERROR]` і код завершення 1.
- Некоректні рядки логу пропускаються (лічильник у `[WARNING]`).
- Жодного коректного запису — `[ERROR]`, код 1.
- Некоректні аргументи (`--top 0`, `--min-status 999`, `--start` пізніше
  за `--end`) відхиляються з поясненням (argparse, код 2, або код 1).

## Перевірка коду
```bash
ruff check .
ruff format --check .
```
