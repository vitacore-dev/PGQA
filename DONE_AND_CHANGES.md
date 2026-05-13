# PostgreSQL Query Plan Analyzer — что сделано и что изменено (полная сводка)

Документ описывает **весь текущий объём** проекта: назначение, структуру кода, возможности интерфейса, файлы данных, интеграции с PostgreSQL и статус по [`PROJECT_PLAN.md`](PROJECT_PLAN.md). Для краткой дорожной карты см. также сам план.

---

## Содержание

1. [О проекте](#о-проекте)
2. [Структура репозитория](#структура-репозитория)
3. [Запуск и зависимости](#запуск-и-зависимости)
4. [Файлы данных на диске](#файлы-данных-на-диске)
5. [Пакет `pg_query_analyzer` по слоям](#пакет-pg_query_analyzer-по-слоям)
6. [Интерфейс: вкладки и возможности](#интерфейс-вкладки-и-возможности)
7. [Анализ плана (`plan_analyzer`)](#анализ-плана-plan_analyzer)
8. [Интеграции](#интеграции-pglast-pg_stat_statements-hypopg)
9. [Визуализация и UX](#визуализация-и-ux)
10. [Безопасность и качество кода](#безопасность-и-качество-кода)
11. [Тестирование](#тестирование)
12. [Статус по этапам плана](#статус-по-этапам-плана)
13. [Эволюция проекта («что изменено» в архитектуре)](#эволюция-проекта-что-изменено-в-архитектуре)
14. [Недавний журнал правок](#недавний-журнал-правок)

---

## Недавний журнал правок

**Ограничение:** в текущей копии каталога **`git log` недоступен** (нет репозитория или нет прав). Ниже — сводка правок **за последние дни** по смыслу и по затронутым файлам (ориентир на состояние кода и документов на **2026-05-09**).

- **OpenRouter AI:** секция **`ai`** в `analyzer_settings.json` / диалог настроек; модуль **`ai/openrouter_client.py`** (валидация, список моделей, маскирование литералов, несколько сценариев completion с разбором JSON); интеграция в **`main_window.py`** (план, PostgreSQL-профиль, экспорт рекомендаций), **`query_analyzer_tab.py`** (triage), **`stat_statements_tab.py`** (приоритизация, digest, A/B, feedback).
- **Обратная связь AI:** **`storage/ai_feedback.py`** → файл **`pg_query_analyzer/ai_feedback.json`**.
- **SSH:** **`db/ssh_tunnel.py`** (туннель psycopg2); **`db/ssh_hardware.py`** (сбор железа для AI); **`connections_dialog.py`** / **`storage/connections.py`** — профиль и пароль SSH в keyring.
- **Обслуживание и workload:** в главном окне — debt/baseline/compare/export Markdown; во вкладке статистики запросов — пересечение с debt и AI-кнопки.
- **TLS для OpenRouter:** **`certifi`** в **`requirements.txt`**; доработки **`_build_ssl_context`**, **`_urlopen_network_message`**, переменная **`PSQLQA_OPENROUTER_SSL_INSECURE`**.
- **Документация:** синхронизированы **`README.md`**, этот файл и **`PROJECT_PLAN.md`** (раздел OpenRouter/AI, п. 11 дорожной карты).
- **Параллельно крутились** (по дереву исходников и датам изменения файлов): пакет **`observed_plans/`**, **`analysis/plan_analyzer.py`**, **`analysis/db_report.py`**, **`journal`**, **`visualizer`**, **`html_templates`**, тесты и **`pyrightconfig.json`** — без отдельной построчной хроники здесь.

Для точной хронологии на машине разработчика используйте **`git log --since="1 week ago"`** и **`git diff`**.

---

## О проекте

**Назначение:** desktop-приложение на **PyQt5** для подключения к **PostgreSQL**, получения и разбора планов **`EXPLAIN`** (XML или JSON), интерактивной визуализации дерева плана, эвристического текстового анализа и рекомендаций, мониторинга активных запросов и статистики **`pg_stat_statements`**, гипотетических индексов (**HypoPG**) и журнала сохранённых планов.

**Точки входа:**

| Способ | Файл |
|--------|------|
| Скрипт в корне | [`PSQLQA.py`](PSQLQA.py) → вызывает `run_gui()` |
| Модуль | [`python -m pg_query_analyzer`](pg_query_analyzer/__main__.py) → [`pg_query_analyzer/app.py`](pg_query_analyzer/app.py) |

Bootstrap GUI: создание **`QApplication`**, тёмная тема Fusion, палитра, показ главного окна **`QueryPlanVisualizer`** ([`ui/main_window.py`](pg_query_analyzer/ui/main_window.py)).

---

## Структура репозитория

```text
PG/
├── PSQLQA.py                 # тонкая обёртка запуска
├── README.md
├── PROJECT_PLAN.md           # дорожная карта и статус этапов
├── DONE_AND_CHANGES.md       # этот документ
├── requirements.txt          # runtime-зависимости
├── requirements-dev.txt       # pytest, ruff (+ повторный импорт requirements.txt)
├── pytest.ini               # конфиг pytest (testpaths = tests)
├── pg_query_analyzer/
│   ├── __main__.py
│   ├── app.py               # QApplication + тема + show главного окна
│   ├── analysis/
│   │   ├── plan_parser.py   # XML / JSON → единое дерево плана
│   │   ├── plan_analyzer.py # эвристический анализ и текст отчёта
│   │   ├── sql_normalize.py # fingerprint журнала (pglast + fallback)
│   │   └── sql_inspect.py   # AST: таблицы, фильтры, JOIN-поля, Sort Key
│   ├── ai/
│   │   └── openrouter_client.py  # OpenRouter: проверка ключа, список моделей, AI-эндпоинты
│   ├── db/
│   │   ├── scanner.py       # активные запросы pg_stat_activity
│   │   ├── scanner_filters.py
│   │   ├── statement_stats.py
│   │   ├── ssh_tunnel.py    # SSH-туннель к PostgreSQL (sshtunnel)
│   │   ├── ssh_hardware.py   # опциональный сбор профиля железа по SSH (paramiko)
│   │   └── hypopg_sql.py
│   ├── storage/
│   │   ├── connections.py   # pg_connections.json + keyring
│   │   ├── history.py
│   │   ├── settings.py      # analyzer_settings.json
│   │   ├── ai_feedback.py   # события «полезно/не полезно» для AI
│   │   └── journal.py       # query_plans_journal.json
│   ├── visualization/
│   │   ├── graph_builder.py
│   │   └── html_templates.py
│   └── ui/
│       ├── main_window.py   # главное окно (крупный модуль)
│       ├── visualizer_window.py
│       ├── query_analyzer_tab.py
│       ├── journal_window.py
│       ├── analyzer_settings_dialog.py
│       ├── connections_dialog.py
│       ├── sql_editor_dialog.py
│       ├── rich_text_widgets.py
│       ├── stat_statements_tab.py
│       └── hypopg_tab.py
└── tests/
    └── test_*.py            # см. раздел «Тестирование»
```

---

## Запуск и зависимости

**Основные зависимости** ([`requirements.txt`](requirements.txt)): `PyQt5`, `PyQtWebEngine`, **`certifi`** (CA bundle для HTTPS к OpenRouter и обход типичных `CERTIFICATE_VERIFY_FAILED` в Python на macOS), `psycopg2-binary`, **`sshtunnel`**, **`paramiko`** (SSH-туннель и опциональный сбор hardware profile), `qtawesome`, `keyring`, `pglast` (диапазон версий указан в файле).

**TLS / OpenRouter:** клиент использует `certifi.where()` при запросах к API. При сохранении ошибки проверки сертификата см. подсказку в исключении и README; крайний режим без проверки — переменная окружения **`PSQLQA_OPENROUTER_SSL_INSECURE=1`** (небезопасно).

**Разработка** ([`requirements-dev.txt`](requirements-dev.txt)): поверх основных — `pytest`, `ruff`.

**Проверки:** см. раздел «Тестирование» и блок «Проверки» в [`README.md`](README.md) (`py_compile`, `unittest discover`, опционально `pytest`).

---

## Файлы данных на диске

| Файл | Назначение |
|------|------------|
| `pg_connections.json` | Список подключений **без** plaintext-паролей (хост, порт, БД, пользователь, имя профиля). Пароли — через **keyring** (`ConnectionSettings.KEYRING_SERVICE`). |
| `analyzer_settings.json` | Настройки анализатора (пороги, визуализация, цвета, журнал и т.д.), загрузка с deep-merge дефолтов. |
| `query_history.json` | История текстов запросов (хранилище истории). |
| `query_plans_journal.json` | Журнал сохранённых планов и метаданных (в т.ч. `plan_origin`, HypoPG-пары, `statement_queryid`). |
| `pg_query_analyzer/ai_feedback.json` | Пользовательская обратная связь по ответам AI (вкладка workload); создаётся при первых голосах. |

Логика чтения/записи — в [`storage/*.py`](pg_query_analyzer/storage/).

---

## Пакет `pg_query_analyzer` по слоям

### `analysis/`

| Модуль | Роль |
|--------|------|
| **`plan_parser.py`** | Разбор **XML** и **JSON** плана PostgreSQL в **единое внутреннее дерево**: узлы с `type`, `cost`, `rows`, `depth`, `properties` (ключи вида `Relation-Name`, `Plan-Rows`, поля из `EXPLAIN ANALYZE`/`BUFFERS`), `children`. Функции: `parse_xml_plan`, `parse_json_plan`, `parse_plan_document`, `looks_like_plan_json`, вспомогательные функции для журнала (`journal_preview_parts_from_plan_doc`, `accumulate_plan_statistics_from_tree`). |
| **`plan_analyzer.py`** | **`analyze_plan_structure(plan_tree, settings, sql_query?)`** — текстовые секции «общий анализ», «оптимизация», «настройки», список **`problems`**; **`identify_problems`** рекурсивно по дереву. Эвристики: высокая стоимость, Seq Scan / Nested Loop / дорогие узлы, индексы, рекомендации индексов из предикатов (совместно с `sql_inspect`), блок **Plan vs Actual rows**, блок **буферов/I-O**, спиллы (`Sort` external + Hash / Incremental по Temp Written). Возвращает **`meta`** (total_cost, expensive_nodes и др.). |
| **`sql_normalize.py`** | **`normalize_query_text`**: при успешном разборе SQL — **`pglast.fingerprint`**, иначе regex-fallback для группировки в журнале. |
| **`sql_inspect.py`** | **`referenced_tables`**, извлечение полей из **Filter**, **Sort Key**, **`join_columns_for_relation`** по текстам условий JOIN из плана (AST + запас regex). |

### `db/`

| Модуль | Роль |
|--------|------|
| **`scanner.py`** | Класс сканера активных запросов (`pg_stat_activity`), периодический опрос, сигналы Qt. |
| **`scanner_filters.py`** | Чистая функция **`apply_scanner_filters`** — фильтры без GUI (удобно для тестов). |
| **`statement_stats.py`** | **`pg_stat_statements`**: проверка расширения, совместимость колонок PG12/PG13+, топ запросов, сортировки, экспорт данных для UI; ошибки через **`StatementStatsError`**. |
| **`hypopg_sql.py`** | Выполнение **`EXPLAIN (FORMAT JSON)`** с гипотетическими индексами в одной сессии; парсинг **`CREATE INDEX …;`** из текста, нормализация оператора для HypoPG, очистка разметки анализатора от DDL. |
| **`ssh_tunnel.py`** | Контекстный менеджер **`open_ssh_tunnel_if_needed`**: при включённом SSH в профиле подключения поднимает **`SSHTunnelForwarder`** к паре `(postgresql_host, postgresql_port)` через bastion/jump. |
| **`ssh_hardware.py`** | **`collect_hardware_via_ssh(connection)`** — второе SSH-подключение (**Paramiko**) с теми же полями; read-only команды на удалённой ОС (Linux/macOS); результат попадает в ключ **`hardware_via_ssh`** AI-профиля PostgreSQL. |

### `ai/`

| Модуль | Роль |
|--------|------|
| **`openrouter_client.py`** | Нормализация base URL, **`validate_openrouter_settings`**, **`list_openrouter_models`**, **`mask_sql_literals`**, генерация ответов: объяснение плана, workload prioritization/digest, triage активных запросов, персональные рекомендации по настройке PostgreSQL (структурированный JSON + парсинг fallback). TLS через **`_build_ssl_context()`** (certifi + опция **`PSQLQA_OPENROUTER_SSL_INSECURE`**). Ошибки **`ssl.SSLError`**, обёрнутые в **`URLError`**, приводятся к понятным сообщениям (**`_urlopen_network_message`**). |

### `storage/`

| Модуль | Роль |
|--------|------|
| **`connections.py`** | **`ConnectionSettings`**: загрузка/сохранение списка подключений, пароли только через **keyring**, миграция от старых plaintext-паролей в JSON (концептуально описано в плане). |
| **`history.py`** | История SQL-запросов с ограничением размера и потокобезопасностью. |
| **`settings.py`** | Чтение/запись **`analyzer_settings.json`** с **`merge`** поверх дефолтов из диалога настроек. |
| **`journal.py`** | Загрузка/сохранение списка записей журнала, trim по лимиту, upsert, удаление; используется главным окном и окном журнала. |
| **`ai_feedback.py`** | **`append_feedback_event`**, **`load_feedback_events`**, **`summarize_feedback`** — JSON-файл **`ai_feedback.json`** в корне пакета `pg_query_analyzer/`. |

### `visualization/`

| Модуль | Роль |
|--------|------|
| **`graph_builder.py`** | **`create_graph_data_from_plan`**: узлы и рёбра для UI и HTML (id узла — строка от **`id(plan_object)`** в дереве парсера). |
| **`html_templates.py`** | HTML/CSS/JS для **vis-network**, приветственные страницы, заглушки; генерация страницы графа с навигацией, «Подогнать», PNG, подсказки, фильтр по глубине, сворачивание поддерева и др. |

### `ui/` (кратко по файлам)

| Файл | Роль |
|------|------|
| **`main_window.py`** | Центральная оркестрация: меню, подключение к БД (в т.ч. через SSH-туннель), выполнение EXPLAIN в фоне, вкладки слева/справа, журнал, HypoPG, статистики, **AI по плану и по PostgreSQL-профилю**, снимок **hardware по SSH**, блок обслуживания БД (**maintenance debt**, baseline/compare, экспорт Before/After `.md`), настройки анализатора, `TextFormatter`, граф плана. Крупный модуль UI. |
| **`visualizer_window.py`** | Окно веб-движка: **`QWebEngineView`**, канал **`QWebChannel`** для связи JS ↔ Python, спинбокс глубины, загрузка HTML из шаблонов. |
| **`query_analyzer_tab.py`** | Вкладка «Сканер запросов»: таблица активных запросов, фильтры, **AI triage** (OpenRouter), lock graph / подсветка PID блокировщиков. |
| **`journal_window.py`** | Окно журнала планов: список записей, группировка/сравнение версий и пар HypoPG. |
| **`stat_statements_tab.py`** | Вкладка `pg_stat_statements`: таблица, экспорт CSV, сброс, подсветка/queryid, **AI приоритизация**, **AI digest**, **A/B check** двух моделей, обратная связь по AI, **Debt intersection** с таблицами из снимка обслуживания главного окна. |
| **`hypopg_tab.py`** | Ввод DDL гипотетических индексов, EXPLAIN с HypoPG, кнопки импорта из рекомендаций/буфера. |
| **`analyzer_settings_dialog.py`** | Многострочный диалог настроек (пороги, визуализация, анализ, цвета, мониторинг, журнал); **вкладка AI / OpenRouter** (включение, URL, модель с загрузкой каталога, ключ, маскирование литералов, кеш, проверка соединения); параметры **EXPLAIN ANALYZE** (строки, буферы, спилл). |
| **`connections_dialog.py`** | CRUD сохранённых подключений; опционально **SSH-туннель** (хост, порт, пользователь, пароль в keyring, путь к ключу). |
| **`sql_editor_dialog.py`** | Редактор SQL с подсветкой. |
| **`rich_text_widgets.py`** | **`ClickableTextBrowser`**, **`TextFormatter`** — маркеры `[section]`, `[link=node://…]` и т.д. |

---

## Интерфейс: вкладки и возможности

### Левая колонка (`left_tabs`)

| Вкладка | Содержание |
|---------|------------|
| **Визуализация плана запроса** | Поле SQL, выполнение **`EXPLAIN (FORMAT JSON)`**, загрузка плана из файла (XML/JSON), построение графа, окно визуализатора; кнопка **«AI: объяснить план»** (OpenRouter, кеш и маскирование литералов по настройкам). |
| **Сканер запросов** | Активные запросы из **`pg_stat_activity`**, фильтры (`scanner_filters`). |
| **pg_stat_statements** | Топ запросов, сортировки, экспорт CSV, сброс, связь с журналом/fingerprint/queryid. |
| **Оптимизация БД** | Подвкладки: **Индексы**, **Статистика**, **Вакуумирование**, **HypoPG**. На **«Статистика»** — показатель **maintenance debt**, снимок **baseline**, сравнение с baseline, экспорт отчёта **Before/After** в Markdown. |

### Правая колонка (`right_tabs`)

| Вкладка | Содержание |
|---------|------------|
| **Общий анализ** | Текст из **`analyze_plan_structure`** (`general`), включая новые блоки EXPLAIN ANALYZE при наличии данных в дереве. |
| **Рекомендации** | Секция **`optimization`** — индексы, Seq Scan, JOIN и пр. |
| **Настройки PostgreSQL** | Таблица ключевых **`pg_settings`**, локальные рекомендации; **AI: персональные рекомендации** (структурированный ответ OpenRouter по профилю БД + опционально **`hardware_via_ssh`**); **Снять профиль железа (SSH)**; **Сохранить AI рекомендации в .md**. |

Отдельные окна: **журнал планов**, **настройки анализатора**, **соединения**, при необходимости редактор SQL.

---

## Анализ плана (`plan_analyzer`)

Итог разбора попадает в словарь **`analysis`** с ключами **`general`**, **`optimization`**, **`settings`**, списком **`problems`**.

Типичное содержание **`general`** (помимо базовых метрик):

- блок **«Объекты в тексте SQL»**, если передан **`sql_query`** и парсинг успешен (`referenced_tables`);
- **«EXPLAIN ANALYZE: оценка vs факт (строки)»** — узлы с большим отношением Plan Rows к Actual Rows (настройки **`rows_estimate_*`**, **`enable_row_estimate_analysis`**);
- **«EXPLAIN ANALYZE: буферы и ввод-вывод»** — временные блоки и узлы с высоким Shared Read (**`buffers_*`**, **`enable_buffers_io_analysis`**);
- дорогие индексные сканирования, Seq Scan по таблицам, Nested Loop, ресурсоёмкие узлы — по порогам из **`analyzer_settings`**;
- секция **«Критические проблемы»** (дублируется из **`problems`** в конце общего текста): Seq Scan/Nested Loop выше порога, внешняя сортировка, спилл Hash/Aggregate/Incremental Sort по **Temp Written Blocks**.

**`optimization`** содержит рекомендации по индексам (в т.ч. из AST/`Filter`/`Sort Key`), блоки JOIN и общие советы по запросам.

**`meta`** возвращает **`total_cost`**, **`expensive_nodes`**, **`most_expensive_node_info`** и используется для подсветки узлов на графе.

---

## Интеграции: pglast, pg_stat_statements, HypoPG

| Интеграция | Где проявляется |
|------------|------------------|
| **pglast** | Fingerprint журнала; список таблиц из SQL; разбор предикатов и JOIN для рекомендаций; fallback при ошибках парсинга. |
| **pg_stat_statements** | Вкладка и модуль **`statement_stats.py`**; сохранение **`statement_queryid`** в журнал после EXPLAIN из приложения при совпадении текста запроса; подсветка строк во вкладке. Требует расширения на сервере и типичную настройку `shared_preload_libraries`. |
| **HypoPG** | Вкладка HypoPG, **`hypopg_sql.py`**; журнал с **`plan_origin`**, пара **`baseline`/`hypopg`** и **`hypopg_pair_group_id`**; сравнение и автообновление журнала. Требует расширение **`hypopg`** в целевой БД. |
| **OpenRouter (AI)** | Настройки в **`analyzer_settings.json`** → секция **`ai`**: `enabled`, `provider`, `base_url`, `model`, `api_key`, **`mask_sql_literals`**, **`cache_enabled`**. Реализация — **`ai/openrouter_client.py`**; длительные запросы — **`CallableWorkerThread`**. Ответы моделей не заменяют проверку на стенде; учитывайте **`caveat`** для SSH-hardware vs хост PostgreSQL. |

---

## Визуализация и UX

- Граф **vis-network** из **`graph_builder`** + **`html_templates`** (единое дерево из XML или JSON).
- Управление масштабом и навигация, **«Подогнать»**, экспорт вида в **PNG**.
- Подсказки узлов (**`title`**), ограничение отображаемой **глубины** дерева.
- **Двойной клик** по узлу — сворачивание поддерева; кнопка **«Все узлы»** — сброс.
- Режим раскладки (по умолчанию / иерархия).
- Подсветка узлов по правилам анализатора (цвета из настроек).

Подробности и статус «дальше» — раздел **pev2** в [`PROJECT_PLAN.md`](PROJECT_PLAN.md).

---

## Безопасность и качество кода

По [`PROJECT_PLAN.md`](PROJECT_PLAN.md) **Этап 1**:

- пароли не хранятся в JSON в открытом виде (**keyring**);
- параметризованные запросы к служебным представлениям где применимо;
- идентификаторы схем/таблиц через **`psycopg2.sql.Identifier`** для операций обслуживания;
- фоновый EXPLAIN не использует то же соединение, что основной поток UI в опасном режиме (отдельное подключение).

---

## Тестирование

Набор модулей **`tests/test_*.py`** (unittest; поддерживается **pytest** через [`pytest.ini`](pytest.ini)):

| Файл | Зона покрытия |
|------|----------------|
| `test_plan_parser.py` | XML/JSON парсер, graph_builder |
| `test_plan_analyzer.py` | Эвристики анализа, EXPLAIN ANALYZE блоки, спиллы |
| `test_sql_normalize.py` | Нормализация/fingerprint |
| `test_sql_inspect.py` | AST и fallback для предикатов/JOIN |
| `test_connections_storage.py` | Подключения и keyring-слой |
| `test_history_storage.py` | История |
| `test_settings_storage.py` | Настройки анализатора и merge |
| `test_journal_storage.py` | Журнал, в т.ч. метаданные HypoPG |
| `test_scanner_filters.py` | Фильтры сканера |
| `test_statement_stats.py` | pg_stat_statements (моки курсора) |
| `test_hypopg_sql.py` | HypoPG DDL и разметка |
| `test_html_templates.py` | HTML шаблоны визуализации |
| `test_smoke.py` | Быстрый импорт и конвейер парсер→анализатор без GUI |
| `test_ssh_hardware.py` | Разбор фрагментов `/proc/meminfo` для SSH-сборщика железа |

Запуск: см. [`README.md`](README.md) (`unittest discover`, опционально **pytest**).

---

## Статус по этапам плана

| Этап | Тема | Сводный статус |
|------|------|----------------|
| **1** | Стабилизация (безопасность, SQL, потоки, вынос модулей) | По плану — основные пункты **выполнены** |
| **2** | Разделение монолита на пакет | Логика вынесена в **`pg_query_analyzer/`**; **`main_window.py`** по-прежнему крупный модуль UI |
| **3** | pglast / pg_stat_statements / HypoPG / pev2 | **Подключены**; у **pev2** и части функций есть пометки «дальше» / «частично» |
| **4** | Улучшить анализ | **Частично**: строки estimated vs actual, буферы/I-O, спиллы; не сделаны полностью: отдельная «плохая статистика», полный missing-index как цель, confidence score, произвольное сравнение двух записей журнала, проверяемые гипотезы для каждой рекомендации |
| **5** | Тесты и качество | **Частично**: есть unittest по основным модулям, pytest/ruff/smoke; black/pyright/pолный набор — по желанию |

Детали и формулировки задач — в [`PROJECT_PLAN.md`](PROJECT_PLAN.md).

---

## Эволюция проекта («что изменено» в архитектуре)

1. **Изначально** проект опирался на один большой **`PSQLQA.py`** (монолит).
2. **Сейчас** исполняемая часть сведена к обёртке; основной код живёт в пакете **`pg_query_analyzer`** с разделением на **`analysis`**, **`db`**, **`storage`**, **`visualization`**, **`ui`**.
3. **Парсинг планов** унифицирован: один формат дерева для анализа и графа независимо от того, пришёл план как XML или JSON.
4. **Подключение расширений PostgreSQL** (`pg_stat_statements`, **HypoPG**) оформлено отдельными модулями и вкладками; ошибки отсутствия расширения по возможности переводятся в понятные сообщения пользователю.
5. **Настройки анализатора** версионируются через JSON с **merge** дефолтов — новые ключи не ломают старые файлы настроек.
6. **Журнал** поддерживает не только сохранение плана, но и сценарии **«до/после HypoPG»** и связку со **`statement_queryid`**.
7. Добавлен слой **OpenRouter AI**: объяснение планов, triage активных запросов, анализ workload и персональные советы по **`postgresql.conf`** с опциональным **hardware profile по SSH**; обратная связь пользователя — **`ai_feedback.json`**.
8. **HTTPS к OpenRouter** опирается на **`certifi`**; для диагностики TLS см. README и **`_ssl_error_hint`** в коде.

---

*Последнее обновление документа: дополнено разделами AI/OpenRouter, SSH hardware, TLS/certifi и расширениями вкладок обслуживания и workload (соответствует текущему коду `pg_query_analyzer/`).*
