"""Background scanner for PostgreSQL active queries via pg_stat_activity."""

import logging
import threading
import time

import psycopg2
from PyQt5.QtCore import QObject, QThread, pyqtSignal

from pg_query_analyzer.db.scanner_filters import apply_scanner_filters


class _ScannerLooper(QThread):
    """Polling loop; runs on QThread subclass instead of threading.Thread."""

    def __init__(self, scanner: "QueryScanner"):
        super().__init__(scanner)
        self._scanner = scanner

    def run(self) -> None:
        self._scanner._scan_queries()


class QueryScanner(QObject):
    queries_updated = pyqtSignal(list)
    connection_error = pyqtSignal(str)
    applications_updated = pyqtSignal(list)
    users_updated = pyqtSignal(list)
    clients_updated = pyqtSignal(list)

    def __init__(self, connection_params, parent=None, analyzer_settings=None):
        super().__init__(parent)
        self.connection_params = connection_params
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        self.current_queries = {}
        self.current_filters = {
            "state": "",
            "query_text": "",
            "application": "",
            "user": "",
            "client": "",
        }
        self.scan_interval = 2
        self.analyzer_settings = analyzer_settings or {}

    def start_scanning(self, interval=None):
        if interval is not None:
            self.scan_interval = interval

        if self.running:
            logging.warning("Сканирование уже запущено, обновляем интервал")
            return

        self.running = True
        logging.info("Запуск сканирования запросов с интервалом %s сек", self.scan_interval)
        self.thread = _ScannerLooper(self)
        self.thread.start()

    def stop_scanning(self):
        if not self.running:
            return

        logging.info("Остановка сканирования запросов")
        self.running = False
        if self.thread:
            self.thread.wait(2000)
            self.thread = None

    def update_filters(self, state=None, query_text=None, application=None, user=None, client=None):
        with self.lock:
            if state is not None:
                self.current_filters["state"] = state
            if query_text is not None:
                self.current_filters["query_text"] = query_text.lower()
            if application is not None:
                self.current_filters["application"] = application
            if user is not None:
                self.current_filters["user"] = user
            if client is not None:
                self.current_filters["client"] = client

    def _scan_queries(self):
        logging.info("Начало сканирования запросов в фоновом потоке")
        while self.running:
            try:
                start_time = time.time()
                new_queries = self._fetch_queries()

                if new_queries != self.current_queries:
                    self.current_queries = new_queries
                    with self.lock:
                        filters_snapshot = dict(self.current_filters)

                    filtered_queries = apply_scanner_filters(
                        list(new_queries.values()), filters_snapshot
                    )

                    max_display = self.analyzer_settings.get("monitoring", {}).get(
                        "max_active_queries_display", 50
                    )
                    if len(filtered_queries) > max_display:
                        filtered_queries = filtered_queries[:max_display]

                    self.queries_updated.emit(filtered_queries)

                elapsed = time.time() - start_time
                sleep_time = max(0, self.scan_interval - elapsed)
                if self.running:
                    time.sleep(sleep_time)

            except Exception as e:
                logging.error(f"Ошибка сканирования запросов: {e}", exc_info=True)
                time.sleep(5)

        logging.info("Завершение сканирования запросов в фоновом потоке")

    def _fetch_queries(self):
        queries = {}
        users = set()
        clients = set()
        applications = set()

        try:
            with psycopg2.connect(**self.connection_params) as conn:
                conn.autocommit = True
                with conn.cursor() as cursor:
                    try:
                        cursor.execute("""
                            SELECT
                                pid, usename, application_name,
                                client_addr, client_port, datname,
                                query_start, query, state,
                                wait_event_type, wait_event,
                                backend_start, xact_start,
                                (now() - query_start) as duration
                            FROM pg_stat_activity
                            WHERE query NOT LIKE '%pg_stat_activity%'
                            AND state IS NOT NULL
                            """)

                        for row in cursor.fetchall():
                            pid = str(row[0])
                            client_info = f"{row[3]}:{row[4]}" if row[3] and row[4] else "N/A"

                            query_data = {
                                "pid": pid,
                                "usename": row[1],
                                "application_name": row[2],
                                "client_addr": row[3],
                                "client_port": row[4],
                                "datname": row[5],
                                "query_start": row[6],
                                "query": row[7],
                                "state": row[8],
                                "wait_event_type": row[9],
                                "wait_event": row[10],
                                "backend_start": row[11],
                                "xact_start": row[12],
                                "duration": row[13],
                                "duration_str": str(row[13]).split(".")[0],
                            }

                            queries[pid] = query_data
                            if row[1]:
                                users.add(row[1])
                            if client_info != "N/A":
                                clients.add(client_info)
                            if row[2]:
                                applications.add(row[2])

                        logging.debug(f"Found users: {users}")
                        logging.debug(f"Found clients: {clients}")
                        logging.debug(f"Found applications: {applications}")

                        self.applications_updated.emit(sorted(applications))
                        self.users_updated.emit(sorted(users))
                        self.clients_updated.emit(sorted(clients))

                    except Exception as e:
                        logging.error(f"Ошибка выполнения SQL запроса: {e}")
                        conn.rollback()
                        self.connection_error.emit(str(e))

        except Exception as e:
            logging.error(f"Ошибка подключения к базе данных: {e}")
            self.connection_error.emit(str(e))

        return queries

    def _apply_filters(self, queries):
        with self.lock:
            filters_snapshot = dict(self.current_filters)
        return apply_scanner_filters(queries, filters_snapshot)
