# PostgreSQL Query Plan Analyzer (PGQA)

Репозиторий: [github.com/vitacore-dev/PGQA](https://github.com/vitacore-dev/PGQA).

Desktop-инструмент на PyQt5 для анализа планов выполнения PostgreSQL.

## Возможности

- подключение к PostgreSQL;
- **Вкладка «💾 Резервное копирование»** (слева, после «Настройки PostgreSQL»): локальный `pg_dump`/`pg_restore` (клиент в `PATH` или каталог `bin`) **или** режим **«Узел SSH»** — `pg_dump` на сервере по Paramiko в абсолютный путь из whitelist префиксов; для SSH-режима в профиле должен быть включён SSH;
- выполнение `EXPLAIN (FORMAT JSON)` и загрузка плана из файла (XML или JSON);
- интерактивная визуализация плана (vis-network): масштаб, навигация, подгонка (**«Подогнать»**), экспорт **PNG**, подсказки при наведении, ограничение глубины дерева, **сворачивание ветки двойным кликом** по узлу и кнопка «Все узлы», иерархический режим раскладки;
- поиск дорогих операций, `Seq Scan`, `Nested Loop` и потенциальных проблем;
- анализ активных запросов через `pg_stat_activity`;
- накопленная статистика запросов через `pg_stat_statements` (отдельная вкладка; на сервере нужны `shared_preload_libraries`, перезапуск и `CREATE EXTENSION` в базе — см. `PROJECT_PLAN.md`; при EXPLAIN из приложения в журнал может сохраняться `statement_queryid`);
- гипотетические индексы HypoPG на вкладке «⚡ Оптимизация БД»: DDL из вкладки «Рекомендации» или буфера, `EXPLAIN (FORMAT JSON)` с гипотезами; опционально пара «до/после» в журнале (**«Журнал: базовый план»** → затем HypoPG): общий `hypopg_pair_group_id`, сравнение из журнала, автообновление окна журнала при сохранении пары (подробнее — `PROJECT_PLAN.md`);
- журнал сохранённых планов: источник записи (`plan_origin`: EXPLAIN / файл / HypoPG), группировка версий запроса, сравнение версий и пар HypoPG;
- базовые рекомендации по индексам, статистике и обслуживанию БД; для планов с `Actual Rows` — блок про расхождение оценки и факта по строкам (`EXPLAIN ANALYZE`); при наличии счётчиков буферов — блок про временные блоки и чтение с диска (`EXPLAIN ANALYZE`, `BUFFERS`); в «Критических проблемах» — внешняя сортировка и спилл по `Temp Written Blocks` у узлов Hash / Incremental Sort.

## AI (OpenRouter)

Опционально (вкладка **«Настройки анализатора» → AI / OpenRouter**): доступ к моделям через [OpenRouter](https://openrouter.ai/) — ключ API, базовый URL, модель (редактируемый список с загрузкой каталога `/models`), маскирование литералов в SQL перед отправкой, локальный кеш ответов.

Где используется:

- панель плана — **«AI: объяснить план»** (структурированный JSON: summary, findings, actions);
- вкладка **«Настройки PostgreSQL»** — **«AI: персональные рекомендации»** по профилю сервера (`pg_settings`, `pg_stat_database`, топ `pg_stat_statements`, при наличии — блок **`hardware_via_ssh`**); ответ в формате P1/P2/P3, risks, read-only checks; экспорт последнего отчёта в `.md`;
- та же вкладка — **«Снять профиль железа (SSH)»**: по тем же учётным данным SSH, что и для туннеля к PostgreSQL, read-only сбор RAM/CPU/диска на **SSH-узле** (см. предупреждение `caveat` в данных — при bastion это может быть не хост БД);
- **«Активные запросы»** — **AI triage** (инцидент, блокирующие кандидаты, действия), опционально контекст lock graph / root blocker;
- **«pg_stat_statements»** — AI-приоритизация workload, **AI digest**, сравнение двух моделей (**A/B check**), кнопки обратной связи («полезно / не полезно», события в `pg_query_analyzer/ai_feedback.json`), пересечение workload с **maintenance debt** (если есть снимок обслуживания).

**TLS:** для HTTPS к OpenRouter используется пакет **`certifi`** (указан в `requirements.txt`). На части систем без корректного системного хранилища CA ошибка `CERTIFICATE_VERIFY_FAILED` снимается после `pip install -r requirements.txt` и перезапуска. Крайний обход проверки сертификата (небезопасно): переменная окружения **`PSQLQA_OPENROUTER_SSL_INSECURE=1`**.

Подробная карта модулей и UI — в [`DONE_AND_CHANGES.md`](DONE_AND_CHANGES.md); дорожная карта и контекст этапов — в [`PROJECT_PLAN.md`](PROJECT_PLAN.md).

## SSH к PostgreSQL

В профиле подключения можно включить **SSH-туннель** (`sshtunnel`): локальный порт пробрасывается на `host:port` PostgreSQL через указанный SSH-сервер; пароль SSH хранится отдельно в **keyring**. Для AI-профиля железа используется отдельное SSH-подключение (**Paramiko**) с теми же полями — см. `pg_query_analyzer/db/ssh_tunnel.py` и `pg_query_analyzer/db/ssh_hardware.py`.

## Observed Plan Repository

В PostgreSQL нет постоянного SQL Server-style plan cache, поэтому проект развивает собственный слой наблюдаемых планов. Пакет `pg_query_analyzer/observed_plans/` нормализует существующие записи журнала в `ObservedPlanSnapshot`, вычисляет полный `plan_hash` и `plan_shape_hash`, извлекает компактные метрики плана и даёт структурированный diff двух snapshot-ов.

В окне журнала есть вкладка **«Наблюдаемые планы»**: она группирует snapshot-ы по `queryid`/fingerprint, показывает смену формы плана через `plan_shape_hash`, summary выбранного плана и сравнение двух выбранных snapshot-ов. Выбранный snapshot можно загрузить в основной анализ, открыть как граф плана или отправить в HypoPG: SQL переносится в главное поле запроса, а найденные `CREATE INDEX` из рекомендаций подставляются в HypoPG Lab. Вариант **«В HypoPG + baseline»** сразу сохраняет snapshot как базовый план «до» для пары HypoPG.

Для `pg_stat_statements` добавлен слой `WorkloadCandidate`: он превращает строки workload в список запросов-кандидатов и отмечает, есть ли по ним уже сохранённый plan snapshot. Вкладка **«Наблюдаемые планы»** показывает уже загруженные candidates из вкладки `pg_stat_statements`; двойной клик по строке подставляет SQL в поле запроса, а кнопка **«Снять EXPLAIN для candidate»** запускает существующий `EXPLAIN (FORMAT JSON)` и сохраняет результат в журнал.

Первый источник данных — текущий `query_plans_journal.json`, включая `statement_queryid`, `plan_origin` и HypoPG-пары. Следующие источники по дорожной карте: импорт `auto_explain` JSON logs и внешние observability-хранилища.

Импорт `auto_explain` уже доступен во вкладке **«Наблюдаемые планы»** через кнопку **«Импорт auto_explain log»**. Поддерживаются raw `EXPLAIN (FORMAT JSON)` документы и log-блоки с `duration: ... ms plan:`, `Query Text:` и JSON-планом; найденные планы сохраняются в журнал с `plan_origin = auto_explain`. Повторный импорт дедуплицируется по fingerprint запроса, `plan_hash` и duration.

Для внешнего observability backend добавлен экспорт ClickHouse: `pg_query_analyzer/observed_plans/exporters/clickhouse.py` содержит MergeTree DDL и преобразование snapshot-ов в `JSONEachRow`. Во вкладке **«Наблюдаемые планы»** кнопка **«Экспорт ClickHouse»** сохраняет текущий репозиторий в `.jsonl` для последующей загрузки в ClickHouse/Grafana pipeline.

Для локального устойчивого хранения добавлен SQLite backend: `pg_query_analyzer/observed_plans/storage/sqlite.py` создаёт таблицу `observed_plan_snapshots`, делает upsert по `snapshot_id` и хранит summary/metadata JSON. Кнопка **«Экспорт SQLite»** во вкладке **«Наблюдаемые планы»** синхронизирует текущий JSON-журнал в `.sqlite`.

`ObservedPlanRepository` умеет читать как текущий JSON-журнал (`from_journal`), так и SQLite backend (`from_sqlite`), сохраняя одинаковые группировки по `queryid`/fingerprint и поиск смены `plan_shape_hash`. Во вкладке **«Наблюдаемые планы»** можно выбрать источник **JSON журнал / SQLite файл** и открыть `.sqlite/.db` как рабочий repository backend. Кнопка **«Sync JSON→SQLite»** синхронизирует текущий `query_plans_journal.json` в выбранный SQLite repository.

## Недавний журнал правок

Ниже — **тематическая сводка** последней активности (ориентир — неделя до **2026-05-09**, включая выровненную под код документацию). Полная карта модулей — в [`DONE_AND_CHANGES.md`](DONE_AND_CHANGES.md).

| Направление | Что менялось |
|-------------|----------------|
| **AI / OpenRouter** | Вкладка настроек анализатора (ключ, модель, каталог моделей, маскирование SQL, кеш); клиент в `ai/openrouter_client.py`; AI по плану, по профилю PostgreSQL (структурированный ответ + экспорт `.md`), triage активных запросов, workload (приоритизация, digest, A/B), файл **`pg_query_analyzer/ai_feedback.json`**. |
| **SSH** | Туннель к PostgreSQL (`db/ssh_tunnel.py`, ключ и пароль в keyring); отдельный **Paramiko**-сборщик профиля железа (`db/ssh_hardware.py`) для поля **`hardware_via_ssh`** в AI-профиле. |
| **Обслуживание БД** | Оценка **maintenance debt**, снимок **baseline**, сравнение и экспорт **Before/After** в Markdown; связка workload × debt во вкладке `pg_stat_statements`. |
| **TLS** | Зависимость **`certifi`** в `requirements.txt`; усиленный SSL-контекст для OpenRouter; распознавание **`SSL`** внутри **`URLError`**; аварийно **`PSQLQA_OPENROUTER_SSL_INSECURE=1`**. |
| **Ядро и качество** | Правки в **`analysis/`** (план, отчёты), **`storage/`** (`json_io`, журнал), **`observed_plans/`**, визуализация и UI; **`pyrightconfig.json`** и набор **`tests/`** (в т.ч. **`test_ssh_hardware.py`** для парсинга meminfo). |

Точный diff по датам: **`git log --since='1 week ago'`**.

## Установка

Клонирование:

```bash
git clone https://github.com/vitacore-dev/PGQA.git
cd PGQA
```

Рекомендуется использовать виртуальное окружение:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Локальные файлы (в `.gitignore`, в репозиторий не попадают):** `pg_query_analyzer/pg_connections.json` (профили БД), `pg_query_analyzer/ui/analyzer_settings.json` (в т.ч. ключ OpenRouter), `query_plans_journal.json`, `pg_query_analyzer/ai_feedback.json`. Шаблон подключений: скопируйте [`pg_query_analyzer/pg_connections.example.json`](pg_query_analyzer/pg_connections.example.json) в `pg_query_analyzer/pg_connections.json` и заполните; пароли приложение хранит в **keyring**. Файл настроек анализатора при первом запуске создаётся автоматически, если его ещё нет.

## Запуск

```bash
python PSQLQA.py
```

Или как модуль пакета (то же самое, что и `PSQLQA.py`):

```bash
python -m pg_query_analyzer
```

## Проверки

Установка зависимостей для разработки (pytest, ruff, black, basedpyright):

```bash
pip install -r requirements-dev.txt
```

Полная цепочка качества (**ruff**, **black**, **pytest**, **basedpyright** для ядра и тестов, без большого UI в pyright):

```bash
bash scripts/ci-quality.sh
```

Быстрая проверка синтаксиса ключевых модулей без dev-утилит + полный прогон unit-тестов:

```bash
python3 -m py_compile PSQLQA.py pg_query_analyzer/app.py pg_query_analyzer/__main__.py pg_query_analyzer/analysis/plan_parser.py pg_query_analyzer/visualization/graph_builder.py pg_query_analyzer/storage/connections.py pg_query_analyzer/storage/history.py pg_query_analyzer/storage/settings.py pg_query_analyzer/storage/journal.py pg_query_analyzer/db/scanner.py pg_query_analyzer/db/scanner_filters.py pg_query_analyzer/ui/main_window.py tests/test_plan_parser.py tests/test_connections_storage.py tests/test_history_storage.py tests/test_settings_storage.py tests/test_journal_storage.py tests/test_scanner_filters.py tests/test_html_templates.py tests/test_plan_analyzer.py
python3 -m unittest discover -s tests -v
pytest
```

Файлы с примером вывода PostgreSQL **`EXPLAIN`** (XML/JSON лежит в `tests/fixtures/`). Без dev-зависимостей достаточно `unittest discover`, как раньше.

Конфигурация: `pyproject.toml` (Black + Ruff), `pyrightconfig.json` (**basedpyright** — те же параметры CLI, что и у Pyright).

## Текущий Статус

Интерфейс и оркестрация вынесены в пакет `pg_query_analyzer/`: главное окно в `pg_query_analyzer/ui/main_window.py`, запуск через `pg_query_analyzer/app.py` (скрипт `PSQLQA.py` — тонкая обёртка). Ядро разбора планов, хранилища и сканер БД — в отдельных модулях; подробности в `PROJECT_PLAN.md`.

Выполненные шаги стабилизации и разнесения кода:

- интеграция **OpenRouter AI** (`pg_query_analyzer/ai/openrouter_client.py`), обратная связь (`storage/ai_feedback.json`), опциональный сбор **hardware profile по SSH** (`db/ssh_hardware.py`);
- безопасное хранение паролей подключений через `keyring`;
- исправление основных мест SQL-сборки через параметры и `psycopg2.sql`;
- вынос парсера планов в `pg_query_analyzer/analysis/plan_parser.py`;
- вынос построения graph-data в `pg_query_analyzer/visualization/graph_builder.py`;
- вынос хранения подключений в `pg_query_analyzer/storage/connections.py`;
- вынос истории запросов в `pg_query_analyzer/storage/history.py`;
- вынос настроек анализатора в `pg_query_analyzer/storage/settings.py`;
- вынос журнала планов в `pg_query_analyzer/storage/journal.py`;
- вынос сканера активных запросов в `pg_query_analyzer/db/scanner.py`;
- первые unit-тесты для парсера и storage-слоя;
- главное окно приложения в `pg_query_analyzer/ui/main_window.py`, единая точка запуска GUI в `pg_query_analyzer/app.py`.
