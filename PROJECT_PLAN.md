# PostgreSQL Query Plan Analyzer: План Развития

## Цель

Сделать инструмент, который безопасно подключается к PostgreSQL, анализирует реальные планы запросов, дает проверяемые рекомендации по индексам и настройкам, а также остается поддерживаемым при росте кода.

**Журнал времени:** точная история коммитов зависит от вашей копии Git; тематическая сводка недавних правок (AI, SSH hardware, TLS, обслуживание БД, документация) — в [`README.md`](README.md) раздел **«Недавний журнал правок»** и в [`DONE_AND_CHANGES.md`](DONE_AND_CHANGES.md) § **«Недавний журнал правок»**.

Исходная кодовая база была выстроена вокруг одного файла `PSQLQA.py`; сейчас ядро разбора планов, хранилища, диалоги и главное окно вынесены в пакет `pg_query_analyzer/` (см. README и список ниже). Приложение уже умеет подключаться к PostgreSQL, выполнять `EXPLAIN`, парсить XML-планы, визуализировать граф выполнения, анализировать активные запросы, вести журнал планов и давать базовые рекомендации. Основная задача развития — сохранить эту функциональность и по мере возможности дробить оставшиеся крупные модули (например `ui/main_window.py`), чтобы снизить риски монолитной архитектуры.

## Этап 1. Стабилизация

Сначала нужно убрать риски, которые могут мешать дальнейшей работе.

Текущий статус:

- Выполнено: добавлены `README.md` и `requirements.txt`.
- Выполнено: пароли подключений перенесены в системное хранилище через `keyring`; `pg_connections.json` больше не должен хранить plaintext-пароли.
- Выполнено: основные SQL-запросы к служебным таблицам PostgreSQL переведены на параметры `%s`, а динамические идентификаторы - на `psycopg2.sql.Identifier`.
- Выполнено: `VACUUM` и массовый `ANALYZE` теперь проходят по таблицам выбранной схемы безопасно, а не подставляют имя схемы как сырой SQL.
- Выполнено: фоновое выполнение пользовательского `EXPLAIN` использует отдельное соединение и один путь завершения через Qt-сигнал.
- Выполнено: чистый XML-парсер планов и построение graph-data вынесены в `pg_query_analyzer/analysis/plan_parser.py`.
- Выполнено: построение graph-data перенесено в отдельный слой `pg_query_analyzer/visualization/graph_builder.py`.
- Выполнено: добавлены первые unit-тесты парсера в `tests/test_plan_parser.py`.
- Выполнено: хранение подключений вынесено в `pg_query_analyzer/storage/connections.py` (без дублирования логики в корневом скрипте).
- Выполнено: добавлены unit-тесты для удаления plaintext-паролей из JSON и миграции в keyring-слой.
- Выполнено: история запросов вынесена в `pg_query_analyzer/storage/history.py`; при выносе исправлена потенциальная самоблокировка `save_history()` внутри lock.
- Выполнено: добавлены unit-тесты истории запросов, дедупликации активных запросов и очистки истории.
- Выполнено: чтение и запись `analyzer_settings.json` вынесены в `pg_query_analyzer/storage/settings.py`.
- Выполнено: добавлены unit-тесты deep-merge настроек, создания файла по умолчанию и восстановления после поврежденного JSON.
- Выполнено: чтение, запись, добавление, удаление и upsert записей `query_plans_journal.json` вынесены в `pg_query_analyzer/storage/journal.py`.
- Выполнено: добавлены unit-тесты journal storage для поврежденного JSON, trim, delete и дедупликации upsert.
- Выполнено: сканер активных запросов `QueryScanner` вынесен в `pg_query_analyzer/db/scanner.py`; фильтрация вынесена в чистую функцию `apply_scanner_filters` в `pg_query_analyzer/db/scanner_filters.py` для тестов без PyQt5.
- Выполнено: добавлены unit-тесты фильтров сканера в `tests/test_scanner_filters.py`.

### 1. Зафиксировать зависимости

- Создать `requirements.txt` или `pyproject.toml`.
- Добавить явные зависимости: `PyQt5`, `PyQtWebEngine`, `psycopg2-binary`, `qtawesome`.
- Описать запуск приложения в `README.md`.
- Проверить, что чистое окружение может запустить приложение без ручного угадывания зависимостей.

### 2. Убрать критичные проблемы безопасности

- Заменить хранение паролей в `pg_connections.json` на системное хранилище через `keyring`.
- Оставить в JSON только имя подключения, host, port, dbname, user.
- Добавить миграцию старого файла подключений.
- Не логировать пароли и параметры подключения целиком.

### 3. Исправить SQL-сборку

- Значения передавать через параметры `%s`.
- Идентификаторы schema/table/index/database подставлять через `psycopg2.sql.Identifier`.
- Отдельно проверить места с `VACUUM`, `ANALYZE`, `pg_stat_user_indexes`, `pg_stat_user_tables`, `information_schema`.
- Добавить валидацию операций, которые могут создавать нагрузку на БД.

### 4. Починить потоковую модель

- Не использовать одно `self.conn` из фонового Python thread.
- Для фоновых операций открывать отдельное соединение.
- Убрать двойной вызов `_on_query_completed`.
- **Сделано дополнительно:** вместо ручного `threading.Thread` + опроса — `CallableWorkerThread` (`QThread`) в главном окне, вкладках pg_stat_statements / HypoPG / активных запросов; цикл сканера `pg_stat_activity` переведён на `QThread`.

## Этап 2. Разделение Монолита

После стабилизации стоит разнести код на понятные модули. Первым нужно выносить не UI, а чистую логику, чтобы ее можно было тестировать отдельно.

Рекомендуемая структура:

```text
pg_query_analyzer/
  app.py
  main_window.py
  db/
    connection.py
    queries.py
    scanner.py
  analysis/
    plan_parser.py
    plan_analyzer.py
    index_recommender.py
    postgres_settings.py
  storage/
    connections.py
    journal.py
    settings.py
  ui/
    dialogs.py
    query_analyzer_tab.py
    journal_window.py
    visualizer_window.py
  visualization/
    graph_builder.py
    html_templates.py
```

Первый набор функций для выноса:

- `parse_xml_plan` - выполнено;
- `build_plan_tree` - выполнено;
- `create_graph_data_from_plan` - выполнено, находится в `visualization/graph_builder.py`;
- `ConnectionSettings` - выполнено, находится в `storage/connections.py`;
- `QueryHistory` - выполнено, находится в `storage/history.py`;
- чтение и запись настроек - выполнено, находится в `storage/settings.py`;
- чтение и запись журнала - выполнено, находится в `storage/journal.py`;
- `QueryScanner` - выполнено, находится в `db/scanner.py`;
- `analyze_plan_structure`, выявление проблем и эвристики рекомендаций по индексам — выполнено, находится в `analysis/plan_analyzer.py`;
- статические HTML-шаблоны (приветствие, заглушка графика журнала, vis-network, оверлей статуса) — выполнено, находится в `visualization/html_templates.py`;
- окно интерактивной визуализации плана (`PlanVisualizerWindow`, QWebChannel bridge) — выполнено, находится в `ui/visualizer_window.py`;
- диалоги управления сохранёнными подключениями (`ConnectionDialog`, `AddNewConnectionDialog`, `EditConnectionDialog`) — выполнено, находится в `ui/connections_dialog.py`;
- редактор SQL и подсветка синтаксиса (`SQLEditorDialog`, `SQLHighlighter`) — выполнено, находится в `ui/sql_editor_dialog.py`;
- браузер текста анализа с ссылками на узлы и разбор маркеров (`ClickableTextBrowser`, `TextFormatter`) — выполнено, находится в `ui/rich_text_widgets.py`;
- вкладка сканера активных запросов (`QueryAnalyzerTab`) — выполнено, находится в `ui/query_analyzer_tab.py`;
- диалог настроек анализатора (`AnalyzerSettingsDialog`) — выполнено, находится в `ui/analyzer_settings_dialog.py`;
- окно журнала планов и графиков (`QueryPlansJournal`) — выполнено, находится в `ui/journal_window.py`;
- `parse_xml_plan` / `parse_json_plan` / `parse_plan_document` — выполнено, находится в `analysis/plan_parser.py` (единое внутреннее дерево плана для визуализации и анализа);
- нормализация текста SQL для группировки в журнале — выполнено, находится в `analysis/sql_normalize.py` (`pglast.fingerprint`, при ошибке парсинга — прежний regex-вариант);
- разбор SQL для анализа планов — выполнено, находится в `analysis/sql_inspect.py` (отношения из текста запроса, столбцы из `Sort Key` и предикатов `Filter`; при необходимости — прежний regex).
## Этап 3. Подключить Open-Source Идеи

После разбиения модулей можно усиливать функциональность за счет проверенных open-source решений и подходов.

### `pglast`

- Заменить регулярные выражения для разбора SQL в нормализации журнала — выполнено: `analysis/sql_normalize.py` использует `pglast.fingerprint` с запасным regex-путём при ошибке разбора.
- AST для списка отношений и предикатов — выполнено: `analysis/sql_inspect.py` (`referenced_tables`, разбор `Filter` Seq Scan и `Sort Key`, резерв regex если AST не извлёк ни одного столбца).
- Интеграция в отчёт анализа — выполнено: при наличии текста SQL в поле запроса в «Общий анализ» добавляется блок «Объекты в тексте SQL».
- JOIN из текста плана (`Hash Cond`, `Merge Cond`, `Join-Filter`): равенства колонок через AST в `join_columns_for_relation`, запасной regex при ошибке парсинга; учитывается alias Seq Scan при совпадении с квалификатором.
- Дальше: сложные выражения в фильтрах (функции, подзапросы); **расширено:** `IS NULL` / `IS NOT NULL`, операторы `<>` / `!=`, `NOT` для равенства и для `NOT … IS NULL` в разборе `Filter`; опционально заменить regex в других местах.

### `pg_stat_statements`

**На сервере** должно быть выполнено до использования вкладки и расширения в нужной базе:

- в `postgresql.conf` модуль указан в **`shared_preload_libraries`** и после изменения конфигурации выполнен **перезапуск** экземпляра PostgreSQL (без этого сбор статистики через расширение не работает);
- в конкретной БД выполнено **`CREATE EXTENSION IF NOT EXISTS pg_stat_statements;`** (при необходимости под пользователем с правами на создание расширений).

Если расширение не установлено или запрос к представлению недоступен, во вкладке отображается **понятное сообщение в строке статуса** (без падения приложения).

**Уже сделано:**

- модуль `db/statement_stats.py` — топ запросов текущей БД (calls, mean_ms, total_ms, rows), сортировка по total/mean/calls/rows; поддержка PG12 (`total_time`/`mean_time`) и PG13+ (`total_exec_time`/`mean_exec_time`);
- вкладка «📊 pg_stat_statements» — таблица, превью, контекстное меню «В поле запроса» (переключение на визуализацию);
- связка с журналом по fingerprint (**`normalize_query_text`**) и по **`statement_queryid`**: после успешного `EXPLAIN (FORMAT JSON) …` из приложения выполняется поиск строки в `pg_stat_statements` по точному тексту выполненного запроса; при нахождении `queryid` сохраняется в записи журнала (`statement_queryid`); во вкладке строки с совпадающим queryid подсвечиваются, подсказка журнала и поиск по журналу учитывают поле;
- экспорт топа в **CSV** — все строки или только **выделенные** (режим множественного выбора строк);
- сброс накопленной статистики через **`pg_stat_statements_reset()`** из UI (нужны права на сервере; ошибка показывается пользователю).

**Сделано дополнительно:** workload по нормализованному fingerprint запроса (`normalize_query_text`): режим сортировки **«Workload: по fingerprint (суммы топ-N строк)»** подтягивает топ по `total_time`, агрегирует вызовы/время/строки в `aggregate_statements_by_fingerprint` (`statement_stats.py`), подсветка по `statement_queryid` учитывает все объединённые `queryid`; в детальной панели — список исходных `queryid`.

**Дальше (опционально):** аналогичные сводки по другим измерениям (например приложение), если появятся в доступных представлениях или через обёртку.

### `log_statement` (серверный лог)

**Выполнено:** разбор текстов из stderr-лога (`LOG:  statement: …`, многострочные продолжения с табуляцией) и из **csvlog** (заголовок с `log_time` и `message`; предпочтительно поле `query`, иначе извлечение из `message`). Модуль `analysis/log_statement.py`; вкладка **«📜 log_statement»** — вставка/файл, группировка по `normalize_query_text`, столбец таблиц через `referenced_tables`, перенос примера SQL в поле запроса на вкладке «План». Подключение к БД для локального разбора не требуется. **Удалённый лог (вариант A):** `db/remote_log_fetch.py` — по SSH из профиля подключения: проверка пути по белому списку префиксов (как у удалённого `pg_dump`), чтение файла через SFTP или хвост `tail -c` при превышении лимита размера; кнопка подстановки абсолютного `SHOW log_directory` при активном SQL-подключении.

### `HypoPG`

**На сервере:** расширение **`hypopg`** в базе (`CREATE EXTENSION IF NOT EXISTS hypopg;`), права на создание при необходимости.

**Уже сделано:**

- модуль `db/hypopg_sql.py` — `explain_json_with_hypothetical_indexes`; **`extract_hypopg_create_index_ddls`** / **`normalize_statement_for_hypopg`** (разбор `CREATE INDEX … ;` из текста, снятие маркеров `[table]` и пр., удаление **`CONCURRENTLY`** для совместимости с HypoPG);
- вкладка «HypoPG» в «⚡ Оптимизация БД»: текст запроса из главного поля, DDL вручную или кнопки **«Из вкладки „Рекомендации“»** / **«Из буфера обмена»**; EXPLAIN подставляет план в общий анализ;
- журнал планов с источником **`plan_origin`** (`explain` / `file` / `hypopg`) и явная **пара «до/после»**: кнопка **«Журнал: базовый план (до HypoPG)»**, общий **`hypopg_pair_group_id`**, роли **`baseline`** / **`hypopg`**; контекстное меню и кнопка **«Сравнить планы»** (пара HypoPG имеет приоритет над «предыдущая версия»); автообновление открытого окна журнала после сохранения пары;
- unit-тест сохранности метаданных пары в JSON журнала (`tests/test_journal_storage.py`).

**Сделано дополнительно:** локальное сохранение текста гипотетических DDL и **именованных пресетов** на пару `host:dbname` через `QSettings`; фоновое выполнение EXPLAIN — через `CallableWorkerThread` (`qt_workers.py`).

### OpenRouter / AI (опционально)

Интеграция с [OpenRouter](https://openrouter.ai/) как единой точкой доступа к LLM без привязки к одному вендору.

**Уже сделано:**

- модуль **`pg_query_analyzer/ai/openrouter_client.py`** — проверка ключа и модели, загрузка списка моделей (`/models`), маскирование литералов SQL, запросы к `/chat/completions` с разбором структурированного JSON там, где это предусмотрено;
- вкладка **«Настройки анализатора» → AI / OpenRouter**: включение, `base_url`, модель (редактируемый комбобокс), API key, опции **маскирования литералов** и **локального кеша** ответов;
- **Визуализация плана** — кнопка объяснения плана через AI;
- **Настройки PostgreSQL** — сбор профиля (`server`, настройки, `pg_stat_database`, активность, топ `pg_stat_statements`), **AI: персональные рекомендации** (P1/P2/P3, risks, read-only checks), экспорт последнего AI-отчёта в Markdown; опционально **`hardware_via_ssh`** после кнопки **«Снять профиль железа (SSH)»** (`db/ssh_hardware.py`, те же SSH-учётные, что у туннеля);
- **Активные запросы** — AI triage; **pg_stat_statements** — приоритизация, digest, A/B двух моделей, обратная связь (**`storage/ai_feedback.py`** → `ai_feedback.json`), пересечение workload с maintenance debt;
- **TLS:** зависимость **`certifi`** в `requirements.txt`, контекст SSL в клиенте; при проблемах CA — см. README; переменная **`PSQLQA_OPENROUTER_SSL_INSECURE=1`** только как крайний обход (небезопасно).

**Дальше (идеи):** импорт и дайджест логов `auto_explain` через AI; исполнительные summary для отчётов БД; вынесение части вызовов из «монолита» `main_window.py` в отдельные небольшие модули.

### 

PostgreSQL не предоставляет постоянный SQL Server-style plan cache по дизайну, поэтому для анализа деградаций нужен собственный репозиторий **наблюдаемых** планов, а не попытка читать внутренний кэш планировщика.

**Цель:** единая модель plan snapshot поверх ручного `EXPLAIN`, журнала планов, `pg_stat_statements`, HypoPG-пар, будущего импорта `auto_explain` и внешних observability-пайплайнов.

**Уже начато:**

- добавлен пакет `pg_query_analyzer/observed_plans/`;
- модель `ObservedPlanSnapshot` и компактный `PlanSummary` находятся в `observed_plans/models.py`;
- `observed_plans/fingerprints.py` вычисляет `query_fingerprint`, полный `plan_hash` и `plan_shape_hash` (форма плана без cost/time);
- `observed_plans/summaries.py` извлекает top node, cost, rows, actual time/rows, количество узлов, Seq Scan и I/O/temp counters;
- `observed_plans/diff.py` возвращает структурированный diff двух snapshot-ов: смена формы плана, cost/time/Seq Scan/temp deltas, смена корневого узла;
- `observed_plans/sources/journal.py` адаптирует существующий `query_plans_journal.json` без миграции данных, сохраняя `statement_queryid`, `plan_origin`, `hypopg_pair_group_id` и `hypopg_pair_role`;
- `observed_plans/sources/pg_stat_statements.py` превращает строки workload в `WorkloadCandidate` и помечает запросы, для которых ещё нет сохранённого snapshot-а по fingerprint/queryid;
- `observed_plans/repository.py` даёт read-only facade с группировкой по `queryid`/fingerprint и поиском групп, где менялся `plan_shape_hash`;
- в окно журнала добавлена вкладка **«Наблюдаемые планы»**: группы по `queryid`/fingerprint, список snapshot-ов, summary выбранного плана и структурированный diff двух выбранных snapshot-ов;
- для выбранного snapshot-а во вкладке **«Наблюдаемые планы»** добавлены действия **«Загрузить snapshot»** (открывает план в основном анализе) и **«Открыть граф»** (открывает тот же план во вкладке визуализации);
- для выбранного snapshot-а добавлены действия **«В HypoPG»** и **«В HypoPG + baseline»**: SQL подставляется в главный запрос, рекомендации по индексу пересчитываются из плана, `CREATE INDEX` извлекается и переносится в HypoPG Lab; вариант с baseline дополнительно сохраняет snapshot как базовый план «до», чтобы следующий HypoPG EXPLAIN попал в пару «до/после»;
- во вкладке **«Наблюдаемые планы»** добавлена секция **Workload candidates из `pg_stat_statements`**: использует уже загруженные строки из вкладки `pg_stat_statements`, показывает запросы без сохранённого snapshot-а, по двойному клику подставляет SQL в поле запроса, а кнопка **«Снять EXPLAIN для candidate»** запускает существующий путь `EXPLAIN (FORMAT JSON)` с автосохранением в журнал;
- `observed_plans/sources/auto_explain_logs.py` импортирует raw `EXPLAIN (FORMAT JSON)` документы и log-блоки `auto_explain` вида `duration: ... ms plan:` + `Query Text:` + JSON plan;
- во вкладке **«Наблюдаемые планы»** добавлена кнопка **«Импорт auto_explain log»**: найденные планы сохраняются в текущий журнал с `plan_origin = auto_explain`;
- импорт `auto_explain` дедуплицируется по стабильному ключу из query fingerprint, полного `plan_hash` и duration, чтобы повторный импорт того же файла не плодил одинаковые snapshot-ы;
- `observed_plans/exporters/clickhouse.py` содержит MergeTree DDL и экспорт snapshot-ов в ClickHouse `JSONEachRow`; во вкладке **«Наблюдаемые планы»** добавлена кнопка **«Экспорт ClickHouse»** для выгрузки текущего репозитория во внешний observability backend;
- `observed_plans/storage/sqlite.py` добавляет локальное SQLite-хранилище snapshot-ов с upsert по `snapshot_id` и индексами по `queryid`/fingerprint/shape; во вкладке **«Наблюдаемые планы»** добавлена кнопка **«Экспорт SQLite»** для синхронизации текущего JSON-журнала в `.sqlite`;
- `ObservedPlanRepository.from_sqlite(...)` позволяет читать snapshot-ы из SQLite backend с теми же группировками, diff-ready snapshot-ами и workload candidate API, что и read-only адаптер JSON-журнала;
- во вкладке **«Наблюдаемые планы»** добавлен выбор источника **JSON журнал / SQLite файл**; выбранный `.sqlite/.db` файл открывается через `ObservedPlanRepository.from_sqlite(...)` и используется для группировок, diff, summary и HypoPG workflow;
- добавлена кнопка **«Sync JSON→SQLite»**, которая upsert-ит текущий `query_plans_journal.json` в выбранный SQLite repository и переключает вкладку на SQLite источник;
- добавлены unit-тесты в `tests/test_observed_plans.py`.

**Дальше:**

- расширить внешний backend ClickHouse/Loki/Grafana: прямой импорт/запрос ClickHouse вместо файлового `JSONEachRow`;
- позже добавить запись новых snapshot-ов сразу в SQLite backend, а не только экспорт/чтение.

### Резервное копирование: каталог на сервере БД

**Клиентский режим:** `pg_dump` / `pg_restore` на машине пользователя; путь — локальная ФС; при необходимости SSH только пробрасывает TCP к PostgreSQL.

**Пункт 1 (дамп на диск узла по SSH) — сделано для `pg_dump`:** во вкладке «💾 Резервное копирование» режим **«Узел SSH: pg_dump на сервере»** выполняет на узле SSH одну bash-команду (`mkdir` при необходимости + `export PGPASSWORD=…` + `pg_dump -w … -f <абсолютный путь>`). Учётные данные SSH — как в профиле (включённый SSH); host/port/user/db пароля БД — из профиля, как видит этот узел. Путь на сервере ограничивается **редактируемым списком префиксов** (по умолчанию `/var/backups/`, `/tmp/pgqa_backup/`, `/var/lib/postgresql/`). Реализация: `db/remote_pg_dump.py`, `ui/backup_restore_dialog.py` (`RemotePgDumpThread` + Paramiko через `connect_ssh_client`).

**Дальше (не сделано):** `pg_restore` с файла на сервере по SSH; pgBackRest / WAL-G; отдельный выбор «SSH ≠ хост БД» вне текстового caveat.

**Пункты дорожной карты (исторические формулировки):**

2. Одна удалённая команда — реализовано в духе п.1 (exec по SSH).
3. **pgBackRest / WAL-G / объектное хранилище:** вне текущей вкладки — ссылка в README или пост-обработка после локального дампа.

### `pev2`

- Использовать как UX-ориентир для визуализации планов (граф строится из единого дерева плана; источником служит XML или JSON — см. `plan_parser`).
- **Сделано (эта дорожная карта):** интерактивный граф vis-network с выбором раскладки (по умолчанию / иерархия), подсветкой узлов по правилам анализатора; клавиатура и навигация vis-network, кнопка **«Подогнать»**, экспорт текущего вида в **PNG** (учитывает только узлы после ограничения глубины и сворачивания веток), подсказки при наведении (`title`), спинбокс **«Макс. глубина»**, **двойной клик** по узлу сворачивает/разворачивает поддерево, кнопка **«Все узлы»** сбрасывает сворачивание; см. `visualization/html_templates.py`, `plan_vis_network_html`, `ui/visualizer_window.py`.
- **Экспорт в текстовый отчёт:** при экспорте анализа в Markdown добавляется раздел **«Узлы плана на графе (видимые операции)»** — таблица узлов по текущему виду графа (снимок синхронизируется через QWebChannel с визуализацией, учитываются свёрнутые ветки и лимит глубины). Полный текст разделов анализа по-прежнему относится ко всему плану; при необходимости расширить фильтрацию текстовых блоков — отдельная задача.

## Этап 4. Улучшить Анализ

Текущие рекомендации местами слишком общие. Их нужно сделать проверяемыми и более точными.

Статус (этап 4 замкнут функционально по запланированным пунктам):

- сравнение estimated rows vs actual rows (**сделано:** блок «EXPLAIN ANALYZE: оценка vs факт», пороги и лимиты);
- выявление плохой статистики (**сделано:** блок «Сигналы устаревшей или недостаточной статистики» — группировка узлов по отношению, шаги `ANALYZE` / `SET STATISTICS`; выключатель и лимит в настройках: `enable_stale_statistics_analysis`, `max_stale_statistics_relations`);
- анализ `Buffers`, `I/O`, `Temp Read/Write` (**сделано:** блок буферов как ранее + те же пороги);
- missing indexes (**сделано:** Seq Scan и **Bitmap Heap Scan** с разбором `Filter`/`Recheck Cond`; поля JOIN и ORDER BY из плана; **дедупликация** одинакового кандидата по `(таблица, состав столбцов)`, оставляется узел с максимальной стоимостью; формулировки «гипотеза», ожидаемый эффект, цена, проверка);
- предупреждения о сортировках и spills (**как выше**, частично ранее);
- произвольное сравнение двух записей журнала (**сделано:** выделите **две записи** в дереве журнала и нажмите «Сравнить планы» или контекстное меню; порядок сравнения — по времени метки записи);
- confidence score (**сделано:** эвристика 0–100 для гипотез индексов и для блока статистики; общий выключатель `enable_confidence_scores` в настройках анализа).

Эвристики не заменяют проверку на стенде: подписаны как «уверенность (эвристика)».

## Этап 5. Тесты И Качество

Минимальный набор качества:

- unit-тесты для XML/JSON parser;
- тесты нормализации SQL;
- тесты генерации рекомендаций;
- fixtures с реальными `EXPLAIN` планами;
- smoke-тест запуска приложения;
- **`ruff`**, **`black`**, **`basedpyright`** (CLI-совместим с pyright): **выполнено** — `requirements-dev.txt` (`pytest`, `ruff`, `black`, `basedpyright`, stubs Qt для редактора), `pyproject.toml` (Black + Ruff, правило `E,F` на согласованном наборе путей без обязательного прохода всего большого UI), `pyrightconfig.json` (**импорт + каркас** для `analysis/`, `db/`, `storage/`, `visualization/`, `tests`, точка входа; каталог **`pg_query_analyzer/ui` исключён** из обхода, чтобы не блокировать сборку тысячами предупреждений PyQt);
- один проход качества из корня репозитория: **`bash scripts/ci-quality.sh`** (`ruff`, `black --check`, `pytest`, `basedpyright`); опционально **GitHub Actions** — `.github/workflows/quality.yml`;
- образцы XML/JSON планов в **`tests/fixtures/`** (`nested_sample.xml`, `nested_sample.json`), тесты читают их в `tests/test_plan_parser.py`.

## Приоритетная Дорожная Карта

1. Зависимости, README и запуск.
2. Безопасное хранение паролей.
3. Исправление SQL-инъекционных мест.
4. Разделение `analysis/` и `storage/`.
5. Поддержка JSON-планов наряду с XML (выполнено: парсинг JSON в `plan_parser`, загрузка `.json`, `EXPLAIN (FORMAT JSON)` из UI).
6. Подключение `pglast` (журнал: `sql_normalize` + fingerprint; анализ: `sql_inspect` + блок «Объекты в тексте SQL» при введённом запросе; рекомендации по индексам из `Filter`/`Sort Key` через AST с откатом на regex).
7. Интеграция `pg_stat_statements` (вкладка, `statement_stats`, журнал по fingerprint и по `statement_queryid`, CSV, сброс; **workload по fingerprint объединён клиентским агрегатором**, см. выше).
8. Интеграция HypoPG — выполнено (вкладка, DDL из рекомендаций / буфера, пара «до/после» в журнале, сравнение, автообновление журнала).
9. Переработка визуализации по мотивам `pev2` — выполнено (vis-network, UX, экспорт PNG по видимому виду графа, Markdown-раздел с видимыми узлами при экспорте анализа; см. раздел «pev2»).
10. Тесты и упаковка приложения (**тесты и CI — см. этап 5, `scripts/ci-quality.sh`; упаковка — по необходимости**).
11. Интеграция **OpenRouter AI** и опциональный **SSH hardware profile** — выполнено (см. раздел «OpenRouter / AI» выше и `README.md`).

## Принцип Работы

Сначала сделать ядро безопасным и тестируемым, потом добавлять умные возможности. Проект уже функционально богатый, но его нужно разгрузить архитектурно, иначе каждое новое улучшение будет увеличивать хрупкость.
