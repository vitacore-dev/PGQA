# AI: персональные рекомендации PostgreSQL

**Summary:** PostgreSQL 18.1 на мощном сервере (56 CPU, ~2 ТБ RAM), cache hit 99.90% (отлично), ~31 млн коммитов с низким rollback (0.47%). Высокое потребление temp space (350 ГБ, 4800 файлов) указывает на spilling сортировок/хэшей. Топ-запросы: медленные (mean до 49 сек), некоторые CPU-bound (shared_blks_read=0), другие I/O-bound. shared_buffers=1 ГБ маловато для RAM, work_mem=2 ГБ рискованно при 150 connections. Parallelism ограничен (max_parallel_workers=26).

**Confidence:** 92

## P1/P2/P3 рекомендации
- **P1** Увеличить shared_buffers: Текущее значение 1 ГБ (134 МБ * 8kB) на 2 ТБ RAM слишком мало (рекомендуется 20-25% RAM, ~400-500 ГБ). effective_cache_size=1.6 ГБ тоже занижено. Увеличит hit rate и уменьшит I/O.
- **P1** Снизить work_mem и настроить по workload: 2 ГБ на запрос при max_connections=150 и temp_bytes=350 ГБ (spilling) рискует OOM. Установить 64-256 МБ, мониторить pg_stat_activity/sort mem. Проанализировать топ-запросы с высоким exec_time.
- **P2** Увеличить параллелизм: 56 CPU cores, но max_parallel_workers=26, max_parallel_workers_per_gather=1. Установить max_parallel_workers=48-56, max_parallel_workers_per_gather=4-8. parallel_setup_cost=1000 и parallel_tuple_cost=0.1 консервативны — протестировать.
- **P2** Включить мониторинг I/O: track_io_timing=off, track_wal_io_timing=off. Включить для анализа bottleneck в топ-запросах с shared_blks_read >0 (например, queryid -2904841342588955729: 1.2M reads).
- **P3** Настроить autovacuum и WAL: autovacuum_max_workers=12 мало для 56 CPU — до 20-30. max_wal_size=8 ГБ ок, но wal_compression=off — включить для экономии I/O. checkpoint_completion_target=0.9 хорошо.

## Risks
- Высокий риск OOM: work_mem=2 ГБ * 150 conn + maintenance_work_mem=20 МБ * parallel.
- Spilling temp (350 ГБ) замедляет топ-запросы (mean_exec_ms до 49 с).
- Низкий parallel (per_gather=1) на 56 CPU — упущен потенциал.
- JIT thresholds высокие (jit_above_cost=100k) — редко используется, но on ок.

## Safe read-only checks
- SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20; -- для query text.
- SELECT * FROM pg_stat_user_tables WHERE n_dead_tup > 0; -- dead tuples.
- ANALYZE VERBOSE; -- на проблемных таблицах из топа.

## Raw AI output

{"summary": "PostgreSQL 18.1 на мощном сервере (56 CPU, ~2 ТБ RAM), cache hit 99.90% (отлично), ~31 млн коммитов с низким rollback (0.47%). Высокое потребление temp space (350 ГБ, 4800 файлов) указывает на spilling сортировок/хэшей. Топ-запросы: медленные (mean до 49 сек), некоторые CPU-bound (shared_blks_read=0), другие I/O-bound. shared_buffers=1 ГБ маловато для RAM, work_mem=2 ГБ рискованно при 150 connections. Parallelism ограничен (max_parallel_workers=26).", "recommendations": [{"priority": "P1", "title": "Увеличить shared_buffers", "details": "Текущее значение 1 ГБ (134 МБ * 8kB) на 2 ТБ RAM слишком мало (рекомендуется 20-25% RAM, ~400-500 ГБ). effective_cache_size=1.6 ГБ тоже занижено. Увеличит hit rate и уменьшит I/O."}, {"priority": "P1", "title": "Снизить work_mem и настроить по workload", "details": "2 ГБ на запрос при max_connections=150 и temp_bytes=350 ГБ (spilling) рискует OOM. Установить 64-256 МБ, мониторить pg_stat_activity/sort mem. Проанализировать топ-запросы с высоким exec_time."}, {"priority": "P2", "title": "Увеличить параллелизм", "details": "56 CPU cores, но max_parallel_workers=26, max_parallel_workers_per_gather=1. Установить max_parallel_workers=48-56, max_parallel_workers_per_gather=4-8. parallel_setup_cost=1000 и parallel_tuple_cost=0.1 консервативны — протестировать."}, {"priority": "P2", "title": "Включить мониторинг I/O", "details": "track_io_timing=off, track_wal_io_timing=off. Включить для анализа bottleneck в топ-запросах с shared_blks_read >0 (например, queryid -2904841342588955729: 1.2M reads)."}, {"priority": "P3", "title": "Настроить autovacuum и WAL", "details": "autovacuum_max_workers=12 мало для 56 CPU — до 20-30. max_wal_size=8 ГБ ок, но wal_compression=off — включить для экономии I/O. checkpoint_completion_target=0.9 хорошо."}], "risks": ["Высокий риск OOM: work_mem=2 ГБ * 150 conn + maintenance_work_mem=20 МБ * parallel.", "Spilling temp (350 ГБ) замедляет топ-запросы (mean_exec_ms до 49 с).", "Низкий parallel (per_gather=1) на 56 CPU — упущен потенциал.", "JIT thresholds высокие (jit_above_cost=100k) — редко используется, но on ок."], "read_only_checks": ["SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20; -- для query text.", "SELECT * FROM pg_stat_user_tables WHERE n_dead_tup > 0; -- dead tuples.", "ANALYZE VERBOSE; -- на проблемных таблицах из топа."], "confidence": 92}
