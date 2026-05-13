"""Main application window (`QueryPlanVisualizer`).

Split from `PSQLQA.py` entry point.
"""

import datetime
import hashlib
import html
import json
import logging
import os
import re
import socket
import sys
import uuid
import functools
from typing import Any, Optional

import psycopg2
from PyQt5.QtCore import QEvent, QPropertyAnimation, QSize, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWebEngineWidgets import QWebEnginePage, QWebEngineView
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)
from psycopg2 import OperationalError
from psycopg2 import sql
from qtawesome import icon

from pg_query_analyzer.analysis.plan_parser import (
    build_plan_tree as build_explain_plan_tree,
    journal_preview_parts_from_plan_doc,
    parse_plan_document as parse_explain_plan_document,
)
from pg_query_analyzer.analysis.plan_analyzer import (
    analyze_plan_structure as analyze_explain_plan_structure,
)
from pg_query_analyzer.analysis.db_report import (
    build_database_report_markdown,
    collect_database_report_snapshot,
    generate_ai_summary_openai,
)
from pg_query_analyzer.storage.connections import ConnectionSettings as StoredConnectionSettings
from pg_query_analyzer.storage.history import QueryHistory as StoredQueryHistory
from pg_query_analyzer.storage.journal import (
    load_journal_entries,
    upsert_unique_journal_entry,
)
from pg_query_analyzer.storage.settings import (
    load_analyzer_settings as load_stored_analyzer_settings,
    save_analyzer_settings as save_stored_analyzer_settings,
)
from pg_query_analyzer.visualization.graph_builder import (
    create_graph_data_from_plan as create_explain_graph_data,
)
from pg_query_analyzer.visualization.html_templates import (
    animated_status_messages_html,
    welcome_screen_html,
)
from pg_query_analyzer.ui.visualizer_window import PlanVisualizerWindow
from pg_query_analyzer.ui.connections_dialog import ConnectionDialog
from pg_query_analyzer.ui.sql_editor_dialog import SQLEditorDialog
from pg_query_analyzer.ui.rich_text_widgets import ClickableTextBrowser
from pg_query_analyzer.ui.query_analyzer_tab import QueryAnalyzerTab
from pg_query_analyzer.ui.stat_statements_tab import StatStatementsTab
from pg_query_analyzer.ui.hypopg_tab import HypoPGTab
from pg_query_analyzer.ui.analyzer_settings_dialog import AnalyzerSettingsDialog
from pg_query_analyzer.ui.journal_window import QueryPlansJournal, QueryPlansJournalWidget
from pg_query_analyzer.db.scanner import QueryScanner
from pg_query_analyzer.db.explain_sql import explain_format_json_sql
from pg_query_analyzer.db.ssh_hardware import collect_hardware_via_ssh
from pg_query_analyzer.db.statement_stats import lookup_queryid_for_executed_statement
from pg_query_analyzer.ui.qt_workers import CallableWorkerThread
from pg_query_analyzer.ai.openrouter_client import generate_plan_explanation_openrouter
from pg_query_analyzer.ai.openrouter_client import (
    generate_postgres_tuning_recommendations_openrouter,
)

os.environ["QT_QUICK_BACKEND"] = "software"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("application.log"), logging.StreamHandler()],
)


def format_psycopg_connect_error(exc: Exception, _depth: int = 0) -> str:
    """Текст ошибки подключения libpq/psycopg2 (иногда ``str(exc)`` пустой)."""
    if _depth > 6:
        return repr(exc)

    parts: list[str] = []

    raw = str(exc).strip()

    pgerr = getattr(exc, "pgerror", None)
    if pgerr:
        g = str(pgerr).strip()
        if g:
            parts.append(g)

    code = getattr(exc, "pgcode", None)
    if code:
        parts.append(f"SQLSTATE={code}")

    diag = getattr(exc, "diag", None)
    if diag is not None:
        for attr in ("message_primary", "message_detail", "severity"):
            val = getattr(diag, attr, None)
            if val:
                t = str(val).strip()
                if t:
                    parts.append(f"{attr}: {t}")

    for arg in getattr(exc, "args", ()) or ():
        if arg is None:
            continue
        if isinstance(arg, (bytes, bytearray)):
            decoded = bytes(arg).decode("utf-8", errors="replace").strip()
        else:
            decoded = str(arg).strip()
        if decoded:
            parts.append(decoded)

    if raw:
        if raw not in parts:
            parts.insert(0, raw)

    out_parts = []
    seen: set[str] = set()
    for line in parts:
        line_stripped = line.strip()
        if line_stripped and line_stripped not in seen:
            seen.add(line_stripped)
            out_parts.append(line_stripped)

    if out_parts:
        return "\n".join(out_parts)

    cls = exc.__class__
    args_r = getattr(exc, "args", ())
    base = f"{cls.__module__}.{cls.__qualname__} args={args_r!r}"

    cause = getattr(exc, "__cause__", None)
    if isinstance(cause, Exception):
        inner = format_psycopg_connect_error(cause, _depth + 1)
        if inner.strip() and inner.strip() != base.strip():
            return f"{base}\nПричина (__cause__):\n{inner}"
    return base


def tcp_reachability_message(host: str, port: int, timeout: float = 8.0) -> str:
    """Проверка TCP до хоста:порта (без TLS/пароля) — полезно при пустом OperationalError от libpq."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return (
                f"Проверка TCP: соединение с {host}:{port} устанавливается "
                f"(порт открыт; отказ libpq, скорее всего, не из-за сетевой недоступности хоста)."
            )
    except OSError as se:
        return f"Проверка TCP: до {host}:{port} не удалось подключиться: {se}"


def diagnose_empty_operational_error(conn: dict) -> str:
    """Пробует альтернативные SSL-профили и возвращает конкретную подсказку."""
    try:
        base_kw = StoredConnectionSettings.connect_kwargs(conn)
    except Exception as e:
        return f"Диагностика не запущена: не удалось собрать параметры подключения ({e})."

    profiles = (
        ("disable", "disable"),
        ("prefer", "disable"),
        ("require", "disable"),
        ("prefer", "prefer"),
    )
    observed_errors: list[str] = []
    for sslmode, gssencmode in profiles:
        probe_kw = dict(base_kw)
        probe_kw["sslmode"] = sslmode
        probe_kw["gssencmode"] = gssencmode
        probe_kw["connect_timeout"] = min(int(base_kw.get("connect_timeout") or 15), 5)
        try:
            probe_conn = psycopg2.connect(**probe_kw)
            probe_conn.close()
            return (
                "Диагностика libpq: тестовый вход успешен с "
                f"`sslmode={sslmode}`, `gssencmode={gssencmode}`. "
                "Сохраните эти значения в профиле подключения."
            )
        except OperationalError as probe_err:
            text = format_psycopg_connect_error(probe_err).strip()
            if text and "args=()" not in text:
                observed_errors.append(f"sslmode={sslmode}, gssencmode={gssencmode}: {text}")
        except Exception as probe_exc:
            observed_errors.append(
                f"sslmode={sslmode}, gssencmode={gssencmode}: "
                f"{format_psycopg_connect_error(probe_exc)}"
            )

    if observed_errors:
        return "Диагностика libpq/SSL/GSS:\n" + "\n".join(observed_errors)
    return (
        "Диагностика libpq не дала текстовой причины. "
        "Попробуйте явно задать в профиле `sslmode` и `gssencmode` "
        "(обычно `sslmode=disable|require`, `gssencmode=disable`)."
    )


def diagnose_database_name_empty_operational(conn: dict, kw: dict) -> str:
    """Если libpq падает OperationalError без текста, но TCP живой:
    проверяем, существует ли запрошенная `dbname` (через подключение к `postgres`).
    """
    requested_db = (conn.get("dbname") or "").strip()
    if not requested_db or requested_db.lower() == "postgres":
        return ""

    probe_kw = dict(kw)
    probe_kw["dbname"] = "postgres"
    probe_kw["connect_timeout"] = min(int(probe_kw.get("connect_timeout") or 15), 5)

    try:
        temp_conn = psycopg2.connect(**probe_kw)
        cur = temp_conn.cursor()
        cur.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = %s)",
            (requested_db,),
        )
        exists = bool(cur.fetchone()[0])
        if not exists:
            cur.execute(
                "SELECT datname FROM pg_database WHERE datname ILIKE %s ORDER BY datname LIMIT 10",
                (requested_db + "%",),
            )
            suggestions = [r[0] for r in cur.fetchall()]
            cur.close()
            temp_conn.close()
            if suggestions:
                return (
                    f"Проверка базы: база данных `{requested_db}` не существует. "
                    f"Похожие базы на сервере: {', '.join(suggestions)}"
                )
            return f"Проверка базы: база данных `{requested_db}` не существует."

        cur.close()
        temp_conn.close()
    except Exception:
        # Если не смогли подключиться к postgres — не усложняем сообщение.
        return ""

    return ""


class SortableTableWidgetItem(QTableWidgetItem):
    """QTableWidgetItem with explicit sort key (numeric or ranked text)."""

    def __init__(self, text: str, sort_key: Any = None):
        super().__init__(text)
        self._sort_key = sort_key if sort_key is not None else text

    def __lt__(self, other):  # noqa: D401, N802
        if not isinstance(other, QTableWidgetItem):
            return super().__lt__(other)
        if isinstance(other, SortableTableWidgetItem):
            return self._sort_key < other._sort_key
        return self.text() < other.text()


def index_recommendation_rank(value: str) -> int:
    """Sort rank for index recommendation/status column."""
    order = {
        "Требуется индекс": 0,
        "Рекомендуется индекс": 1,
        "Не используется": 2,
        "Редко используется": 3,
        "Активно используется": 4,
        "OK": 5,
    }
    return order.get((value or "").strip(), 99)


def fetch_pg_stat_missing_index_candidates(
    conn_params: dict, min_table_size_mb: float, schema: str
) -> list:
    """Read-only snapshot for «Найти недостающие индексы»; safe to run in a worker thread."""
    query = """
                    SELECT
                        schemaname || '.' || relname AS table_name,
                        seq_scan,
                        seq_tup_read,
                        CASE
                            WHEN seq_scan > 0 THEN seq_tup_read / seq_scan
                            ELSE 0
                        END AS avg_tuples_per_scan,
                        pg_relation_size(relid) / (1024*1024) AS size_mb,
                        CASE
                            WHEN seq_scan > 1000 AND seq_tup_read/seq_scan > 1000
                                 AND pg_relation_size(relid) / (1024*1024) >= %s
                            THEN 'Требуется индекс'
                            WHEN seq_scan > 100
                                 AND pg_relation_size(relid) / (1024*1024) >= %s
                            THEN 'Рекомендуется индекс'
                            ELSE 'OK'
                        END AS recommendation
                    FROM pg_stat_user_tables
                    WHERE schemaname = %s
                    AND seq_scan > 0
                    ORDER BY avg_tuples_per_scan DESC
                    """
    with psycopg2.connect(**conn_params) as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, (min_table_size_mb, min_table_size_mb, schema))
            return list(cursor.fetchall())


class WelcomeNavigationPage(QWebEnginePage):
    """Intercept internal welcome-screen navigation actions."""

    def __init__(self, action_handler, parent=None):
        super().__init__(parent)
        self._action_handler = action_handler

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):  # noqa: N802
        if url.scheme() == "pgqa":
            action = url.host() or url.path().lstrip("/")
            self._action_handler(action)
            return False
        return super().acceptNavigationRequest(url, nav_type, is_main_frame)


class QueryPlanVisualizer(QMainWindow):
    query_finished = pyqtSignal(bool)

    PLAN_TAB_LABEL = "💹 План"
    ACTIVE_QUERIES_TAB_LABEL = "💻 Активные запросы"
    WORKLOAD_TAB_LABEL = "📊 Workload"
    ADMIN_TAB_LABEL = "🛠 Обслуживание БД"
    HISTORY_TAB_LABEL = "🗂 История"
    GENERAL_ANALYSIS_TAB_LABEL = "📕 Проблемы"
    RECOMMENDATIONS_TAB_LABEL = "📗 Что попробовать"
    POSTGRES_SETTINGS_TAB_LABEL = "⚙️ Настройки PostgreSQL"

    def __init__(self):
        super().__init__()
        self.is_loading_from_journal = False

        self.analyzer_settings = self.load_analyzer_settings()
        self.analysis_result = None

        self.current_connection = None
        self.connection_status = False
        self.query_thread = None
        self.update_stats_thread = None
        self.query_result = None
        self.most_expensive_node_info = ""
        self.total_cost = 0
        self.expensive_nodes = []
        self.query_scanner = None
        self.query_plans_journal = []
        self.last_opened_file = None
        self._hypopg_pair_group_id = None

        self._plan_graph_metadata = {}
        self._visible_outline_snapshot = None

        self.tab_data_cache = {
            "visualizer": {"general": "", "optimization": "", "has_data": False},
            "scanner": {"general": "", "optimization": "", "has_data": False},
            "db_optimization": {"general": "", "optimization": "", "has_data": False},
        }

        self._updating_tab_content = False

        self._analyze_highlighters = []
        self._ai_plan_worker = None
        self._ai_postgres_worker = None
        self._last_ai_postgres_structured = None
        self._last_ai_postgres_raw = ""
        self._ai_postgres_recommendations_html = ""
        self._last_postgres_settings_for_recommendations = None
        self._ssh_hardware_profile = None
        self._ssh_hardware_worker = None
        self._missing_indexes_worker = None
        self._missing_indexes_ctx = None
        self.find_missing_indexes_button = None
        self._ai_plan_total_responses = 0
        self._ai_plan_structured_responses = 0
        self._ai_plan_response_cache = {}
        self._ai_pending_cache_key = None

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()
        self.progress_animation = QPropertyAnimation(self.progress_bar, b"value")
        self.progress_animation.setDuration(1000)
        self.progress_animation.setStartValue(0)
        self.progress_animation.setEndValue(100)
        self.progress_animation.setLoopCount(-1)

        self.query_history = StoredQueryHistory()

        self.setWindowTitle("PostgreSQL Query Plan Analyzer")
        self.apply_screen_aware_geometry()

        self.create_main_interface()
        self.create_menu()
        self.create_toolbar()
        self.create_icon_toolbar()

        self.load_connections()
        if self.current_connection:
            self.query_scanner = QueryScanner(self.current_connection, self, self.analyzer_settings)

        try:
            self.initial_content = self._create_welcome_view()
            logging.info("Initial_content успешно инициализирован!")
            if hasattr(self, "visualizer_layout"):
                self.visualizer_layout.addWidget(self.initial_content, 1)
        except Exception as e:
            logging.error(f"Error initializing welcome screen: {e}")
            raise

        self.query_finished.connect(self._on_query_completed)
        self.load_query_plans_journal()

        self.show_visualization_info()

    def apply_screen_aware_geometry(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            self.resize(1200, 760)
            return

        available = screen.availableGeometry()
        margin_x = min(48, max(16, available.width() // 24))
        margin_y = min(48, max(16, available.height() // 24))
        width = min(1400, max(640, available.width() - margin_x * 2))
        height = min(850, max(480, available.height() - margin_y * 2))
        x = available.x() + max(0, (available.width() - width) // 2)
        y = available.y() + max(0, (available.height() - height) // 2)
        self.setGeometry(x, y, width, height)

    def fit_to_available_screen_after_show(self) -> None:
        """Clamp the real shown window after layouts/toolbars compute their minimum size."""
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return

        available = screen.availableGeometry()
        frame = self.frameGeometry()
        too_large = frame.width() > available.width() or frame.height() > available.height()
        compact_screen = available.width() < 1280 or available.height() < 820

        if too_large or compact_screen:
            self.showMaximized()
            return

        self.apply_screen_aware_geometry()

    def load_analyzer_settings(self):
        settings_dir = self.get_settings_directory()
        default_settings = AnalyzerSettingsDialog.get_default_settings(AnalyzerSettingsDialog)
        return load_stored_analyzer_settings(settings_dir, default_settings)

    def save_analyzer_settings(self, settings):
        settings_dir = self.get_settings_directory()

        try:
            save_stored_analyzer_settings(settings_dir, settings)
            self.analyzer_settings = settings

        except Exception as e:
            logging.error(f"Ошибка сохранения настроек анализатора: {e}")
            QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить настройки:\n{str(e)}")

    def show_analyzer_settings(self):
        current_settings_copy = json.loads(json.dumps(self.analyzer_settings))

        dialog = AnalyzerSettingsDialog(self, current_settings_copy)
        dialog.settings_changed.connect(self.on_analyzer_settings_changed)
        dialog.exec_()

    def on_analyzer_settings_changed(self, new_settings):
        self.save_analyzer_settings(new_settings)

        if hasattr(self, "query_analyzer_tab") and self.query_analyzer_tab.query_scanner:
            self.query_analyzer_tab.query_scanner.analyzer_settings = new_settings

            new_interval = new_settings.get("monitoring", {}).get("scan_interval_seconds", 2)
            self.query_analyzer_tab.interval_spin.setValue(new_interval)

            if self.query_analyzer_tab.query_scanner.running:
                self.query_analyzer_tab.query_scanner.stop_scanning()
                self.query_analyzer_tab.query_scanner.start_scanning(new_interval)

        if hasattr(self, "xml_content") and self.xml_content:
            QTimer.singleShot(100, self.reanalyze_current_plan)

        QMessageBox.information(
            self, "Настройки", "Настройки анализатора успешно сохранены и применены"
        )

    def reanalyze_current_plan(self):
        if hasattr(self, "xml_content") and self.xml_content:
            self.analyze_query_plan()

    def fetch_databases(self):
        if not self.connection_status or not hasattr(self, "conn"):
            return []

        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
                databases = [record[0] for record in cursor.fetchall()]
                return databases
        except Exception as e:
            logging.error(f"Ошибка получения списка баз данных: {e}")
            return []

    def fetch_schemas(self, database):
        if not self.connection_status or not hasattr(self, "conn"):
            return []

        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "SELECT schema_name FROM information_schema.schemata WHERE catalog_name = %s;",
                    (database,),
                )
                schemas = [record[0] for record in cursor.fetchall()]
                return schemas
        except Exception as e:
            logging.error(f"Ошибка получения списка схем: {e}")
            return []

    def run_vacuum(self):
        if not self.connection_status or not hasattr(self, "conn"):
            QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
            return

        db_name = self.db_combo.currentText()
        schema_name = self.schema_combo.currentText()

        if not db_name or not schema_name:
            QMessageBox.warning(self, "Ошибка", "Выберите базу данных и схему")
            return

        reply = QMessageBox.question(
            self,
            "Подтверждение выполнения VACUUM",
            f"ВНИМАНИЕ! Вы собираетесь выполнить VACUUM для схемы '{schema_name}'.\n\n"
            "Это действие:\n"
            "• Может создать значительную нагрузку на базу данных\n"
            "• Может временно заблокировать таблицы\n"
            "• Может занять продолжительное время для больших таблиц\n\n"
            "Рекомендуется выполнять в периоды низкой активности.\n\n"
            "Вы уверены, что хотите продолжить?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply != QMessageBox.Yes:
            return

        self.process_output.clear()
        self.process_output.append(
            f"Выполнение VACUUM для базы данных {db_name}, схема {schema_name}..."
        )

        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT tablename
                    FROM pg_tables
                    WHERE schemaname = %s
                    ORDER BY tablename
                    """,
                    (schema_name,),
                )
                tables = [row[0] for row in cursor.fetchall()]

            if not tables:
                QMessageBox.information(
                    self, "VACUUM", f"В схеме '{schema_name}' не найдено таблиц."
                )
                return

            self.conn.rollback()
            previous_autocommit = self.conn.autocommit
            self.conn.autocommit = True
            try:
                with self.conn.cursor() as cursor:
                    for table_name in tables:
                        cursor.execute(
                            sql.SQL("VACUUM (VERBOSE, ANALYZE) {}").format(
                                sql.Identifier(schema_name, table_name)
                            )
                        )
                        self.process_output.append(
                            f"VACUUM выполнен для {schema_name}.{table_name}"
                        )
            finally:
                self.conn.autocommit = previous_autocommit

            self.process_output.append(f"VACUUM успешно выполнен для {len(tables)} таблиц.")
            QMessageBox.information(self, "Успех", "VACUUM успешно выполнен")

        except Exception as e:
            logging.error(f"Ошибка выполнения VACUUM: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось выполнить VACUUM:\n{str(e)}")

    def get_postgresql_server_info(self):
        if not self.connection_status or not hasattr(self, "conn"):
            logging.warning("Нет активного подключения к базе данных.")
            return None

        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT version()")
                version = cursor.fetchone()[0]

                cursor.execute("SELECT pg_postmaster_start_time()")
                start_time = cursor.fetchone()[0]

                if not isinstance(start_time, str):
                    start_time = str(start_time)

                try:
                    start_time_dt = datetime.datetime.fromisoformat(start_time)
                except ValueError:
                    try:
                        start_time_dt = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                        start_time_dt = start_time_dt.replace(tzinfo=datetime.timezone.utc)
                    except ValueError:
                        start_time_dt = datetime.datetime.now(datetime.timezone.utc)
                        logging.warning(f"Не удалось разобрать время сервера: {start_time}")

                now = datetime.datetime.now(datetime.timezone.utc)
                uptime = now - start_time_dt
                uptime_str = str(uptime).split(".")[0]

                config_file = "Недоступно"
                try:
                    cursor.execute("SHOW config_file")
                    config_file = cursor.fetchone()[0]
                except Exception as e:
                    logging.warning(f"Ошибка получения пути к файлу конфигурации: {e}")
                    self.conn.rollback()

                return {
                    "version": version,
                    "uptime": uptime_str,
                    "config_file": config_file,
                    "start_time": start_time_dt.strftime("%Y-%m-%d %H:%M:%S %Z"),
                }

        except Exception as e:
            logging.error(f"Ошибка получения информации о сервере: {e}")
            self.conn.rollback()
            return None

    def load_postgres_settings(self):
        if not self.connection_status or not hasattr(self, "conn"):
            QMessageBox.warning(self, "Ошибка", "Нет подключения к PostgreSQL")
            return

        try:
            server_info = self.get_postgresql_server_info()
            settings_data = self.get_postgresql_settings()

            if server_info and settings_data:
                combined_data = {"server_info": server_info, "settings": settings_data}
                self.update_settings_display(combined_data)
        except Exception as e:
            logging.error(f"Ошибка загрузки настроек: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить настройки:\n{str(e)}")

    def create_postgres_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        toolbar = QToolBar()
        toolbar.setIconSize(QSize(16, 16))

        self.show_all_settings_btn = QPushButton(icon("fa5s.cogs", color="white"), " Все параметры")
        self.show_all_settings_btn.setToolTip("Показать все параметры PostgreSQL")
        self.show_all_settings_btn.clicked.connect(self.show_all_postgres_settings)
        toolbar.addWidget(self.show_all_settings_btn)

        refresh_btn = QPushButton(icon("fa5s.sync", color="white"), " Обновить")
        refresh_btn.setToolTip("Обновить параметры PostgreSQL")
        refresh_btn.clicked.connect(self.load_postgres_settings)
        toolbar.addWidget(refresh_btn)

        ai_tuning_btn = QPushButton(
            icon("fa5s.robot", color="white"), " AI: персональные рекомендации"
        )
        ai_tuning_btn.setToolTip("Сформировать персональные рекомендации по настройке PostgreSQL")
        ai_tuning_btn.clicked.connect(self.generate_ai_postgres_recommendations)
        toolbar.addWidget(ai_tuning_btn)

        save_ai_md_btn = QPushButton(
            icon("fa5s.file-export", color="white"), " Сохранить AI рекомендации в .md"
        )
        save_ai_md_btn.setToolTip("Сохранить последний AI-отчёт по настройке PostgreSQL в Markdown")
        save_ai_md_btn.clicked.connect(self.export_ai_postgres_recommendations_markdown)
        toolbar.addWidget(save_ai_md_btn)

        ssh_hw_btn = QPushButton(icon("fa5s.server", color="white"), " Снять профиль железа (SSH)")
        ssh_hw_btn.setToolTip(
            "По SSH из текущего подключения собрать RAM/CPU/диск (read-only). "
            "Нужен включённый SSH-туннель в профиле и те же учётные данные, что для туннеля."
        )
        ssh_hw_btn.clicked.connect(self.fetch_ssh_hardware_profile)
        toolbar.addWidget(ssh_hw_btn)

        layout.addWidget(toolbar)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: 1px solid #444;
                background-color: #2d2d2d;
            }
            QScrollBar:vertical {
                border: none;
                background: #333;
                width: 10px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #555;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background: none;
            }
        """)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(10)

        self.server_info_group = QGroupBox("Информация о сервере")
        self.server_info_group.setStyleSheet(self.get_groupbox_style())
        server_info_layout = QFormLayout()
        server_info_layout.setVerticalSpacing(5)

        self.server_version_label = QLabel("Не подключено")
        self.server_uptime_label = QLabel("Не подключено")
        self.server_config_label = QLabel("Не подключено")

        server_info_layout.addRow("Версия PostgreSQL:", self.server_version_label)
        server_info_layout.addRow("Время работы:", self.server_uptime_label)
        server_info_layout.addRow("Файл конфигурации:", self.server_config_label)

        self.server_info_group.setLayout(server_info_layout)
        content_layout.addWidget(self.server_info_group)

        self.ssh_hardware_group = QGroupBox("Профиль железа (SSH)")
        self.ssh_hardware_group.setStyleSheet(self.get_groupbox_style())
        ssh_hw_layout = QVBoxLayout()
        self.ssh_hardware_summary_label = QLabel(
            "Снимок не загружали. Нажмите «Снять профиль железа (SSH)» — данные попадут в AI «персональные рекомендации»."
        )
        self.ssh_hardware_summary_label.setWordWrap(True)
        self.ssh_hardware_summary_label.setStyleSheet("color: #b0bec5; font-size: 11px;")
        ssh_hw_layout.addWidget(self.ssh_hardware_summary_label)
        self.ssh_hardware_group.setLayout(ssh_hw_layout)
        content_layout.addWidget(self.ssh_hardware_group)

        self.key_params_group = QGroupBox("Ключевые параметры PostgreSQL")
        self.key_params_group.setStyleSheet(self.get_groupbox_style())
        key_params_layout = QVBoxLayout()
        key_params_layout.setSpacing(5)

        self.settings_table = QTableWidget()
        self.settings_table.setColumnCount(7)
        self.settings_table.setHorizontalHeaderLabels(
            ["Инф", "Параметр", "Текущее", "Рекомендуется", "Диапазон", "Статус", "Описание"]
        )
        self.settings_table.verticalHeader().setVisible(False)
        self.settings_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.settings_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.settings_table.setSelectionMode(QTableWidget.SingleSelection)
        self.settings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.settings_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)

        self.settings_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                gridline-color: #444;
                font-size: 11px;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #e0e0e0;
                padding: 5px;
                border: 1px solid #444;
                font-weight: bold;
                font-size: 11px;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)

        key_params_layout.addWidget(self.settings_table)
        self.key_params_group.setLayout(key_params_layout)
        content_layout.addWidget(self.key_params_group)

        self.recommendations_group = QGroupBox("Рекомендации по настройке")
        self.recommendations_group.setStyleSheet(self.get_groupbox_style())
        recommendations_layout = QVBoxLayout()

        self.recommendations_text = QTextBrowser()
        self.recommendations_text.setOpenExternalLinks(True)
        self.recommendations_text.setMinimumHeight(200)
        self.recommendations_text.setStyleSheet("""
            QTextBrowser {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }
        """)

        recommendations_layout.addWidget(self.recommendations_text)
        self.recommendations_group.setLayout(recommendations_layout)
        content_layout.addWidget(self.recommendations_group)

        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)

        return tab

    def get_groupbox_style(self):
        return """
            QGroupBox {
                font-size: 12px;
                border: 1px solid #555;
                border-radius: 3px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
                color: #81c784;
            }
        """

    def update_settings_display(self, settings_data):
        try:
            server_info = settings_data.get("server_info", {})
            if server_info:
                version = server_info.get("version", "N/A")
                uptime = server_info.get("uptime", "N/A")
                config_file = server_info.get("config_file", "N/A")

                if hasattr(self, "server_version_label"):
                    self.server_version_label.setText(version.split(",")[0].strip())
                if hasattr(self, "server_uptime_label"):
                    self.server_uptime_label.setText(uptime)
                if hasattr(self, "server_config_label"):
                    self.server_config_label.setText(config_file)
            else:
                if hasattr(self, "server_version_label"):
                    self.server_version_label.setText("Не подключено")
                if hasattr(self, "server_uptime_label"):
                    self.server_uptime_label.setText("Не подключено")
                if hasattr(self, "server_config_label"):
                    self.server_config_label.setText("Не подключено")

            if hasattr(self, "settings_table"):
                self.settings_table.setRowCount(0)

                self.settings_table.setColumnCount(7)
                self.settings_table.setHorizontalHeaderLabels(
                    [
                        "Инф",
                        "Параметр",
                        "Текущее",
                        "Рекомендуется",
                        "Диапазон",
                        "Статус",
                        "Описание",
                    ]
                )

                header = self.settings_table.horizontalHeader()
                header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
                header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
                header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
                header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
                header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
                header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
                header.setSectionResizeMode(6, QHeaderView.Stretch)

                for setting in settings_data.get("settings", []):
                    name, value, unit, desc, context, vartype, min_val, max_val, enumvals = setting

                    status, color = self.check_setting_status(name, value, min_val, max_val)

                    row = self.settings_table.rowCount()
                    self.settings_table.insertRow(row)

                    icon_item = QTableWidgetItem()
                    if status == "OK":
                        icon_item.setText("✓")
                        icon_item.setForeground(QColor("#51cf66"))
                    elif status == "Проверьте":
                        icon_item.setText("?")
                        icon_item.setForeground(QColor("#fcc419"))
                    else:
                        icon_item.setText("✗")
                        icon_item.setForeground(QColor("#ff6b6b"))

                    param_item = QTableWidgetItem(name)
                    current_item = QTableWidgetItem(
                        self.convert_units(value, unit, "MB" if "mem" in name else "")
                    )
                    recommended_value = self.get_recommended_value(name, value)
                    recommended_item = QTableWidgetItem(recommended_value)
                    range_value = self.get_param_range(name, min_val, max_val)
                    range_item = QTableWidgetItem(range_value)
                    status_item = QTableWidgetItem(status)
                    status_item.setForeground(QColor(color))
                    desc_item = QTableWidgetItem(desc if desc else "Нет описания")

                    for item in [
                        icon_item,
                        param_item,
                        current_item,
                        recommended_item,
                        range_item,
                        status_item,
                    ]:
                        item.setTextAlignment(Qt.AlignCenter)

                    self.settings_table.setItem(row, 0, icon_item)
                    self.settings_table.setItem(row, 1, param_item)
                    self.settings_table.setItem(row, 2, current_item)
                    self.settings_table.setItem(row, 3, recommended_item)
                    self.settings_table.setItem(row, 4, range_item)
                    self.settings_table.setItem(row, 5, status_item)
                    self.settings_table.setItem(row, 6, desc_item)

            if hasattr(self, "recommendations_text"):
                self._last_postgres_settings_for_recommendations = settings_data
                self.update_recommendations_text(settings_data)

        except Exception as e:
            logging.error(f"Ошибка обновления отображения параметров: {e}")
            QMessageBox.warning(self, "Ошибка", f"Не удалось обновить настройки:\n{str(e)}")

    def _collect_postgres_ai_profile(self):
        if not self.connection_status or not hasattr(self, "conn"):
            raise RuntimeError("Нет подключения к PostgreSQL")
        profile = {"server_info": self.get_postgresql_server_info(), "settings": []}
        rows = self.get_postgresql_settings() or []
        settings_map = {}
        for row in rows:
            if not row or len(row) < 3:
                continue
            settings_map[str(row[0])] = {
                "setting": row[1],
                "unit": row[2],
                "desc": row[3] if len(row) > 3 else "",
            }
        profile["settings"] = settings_map

        with self.conn.cursor() as cursor:
            cursor.execute("""
                SELECT
                    blks_hit, blks_read,
                    CASE WHEN blks_hit + blks_read > 0
                         THEN round(100.0 * blks_hit / NULLIF(blks_hit + blks_read, 0), 2)
                         ELSE NULL END AS cache_hit_pct,
                    xact_commit, xact_rollback, temp_files, temp_bytes, deadlocks
                FROM pg_stat_database
                WHERE datname = current_database()
                """)
            row = cursor.fetchone()
            if row:
                profile["db_stats"] = {
                    "blks_hit": row[0],
                    "blks_read": row[1],
                    "cache_hit_pct": row[2],
                    "xact_commit": row[3],
                    "xact_rollback": row[4],
                    "temp_files": row[5],
                    "temp_bytes": row[6],
                    "deadlocks": row[7],
                }

            cursor.execute("""
                SELECT state, count(*)::int
                FROM pg_stat_activity
                WHERE datname = current_database()
                GROUP BY state
                """)
            profile["activity_states"] = [{"state": r[0], "count": r[1]} for r in cursor.fetchall()]

            cursor.execute("""
                SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='pg_stat_statements')
                """)
            has_statements = bool(cursor.fetchone()[0])
            profile["pg_stat_statements_installed"] = has_statements
            if has_statements:
                cursor.execute("""
                    SELECT queryid, calls, round(total_exec_time::numeric,2), round(mean_exec_time::numeric,2),
                           temp_blks_written, shared_blks_read
                    FROM pg_stat_statements
                    WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                    ORDER BY total_exec_time DESC NULLS LAST
                    LIMIT 20
                    """)
                profile["top_statements"] = [
                    {
                        "queryid": str(r[0]),
                        "calls": r[1],
                        "total_exec_ms": float(r[2]),
                        "mean_exec_ms": float(r[3]),
                        "temp_blks_written": r[4],
                        "shared_blks_read": r[5],
                    }
                    for r in cursor.fetchall()
                ]
        if getattr(self, "_ssh_hardware_profile", None):
            profile["hardware_via_ssh"] = self._ssh_hardware_profile
        return profile

    def _reset_ssh_hardware_snapshot(self):
        self._ssh_hardware_profile = None
        if hasattr(self, "ssh_hardware_summary_label"):
            self.ssh_hardware_summary_label.setText(
                "Снимок не загружали. Нажмите «Снять профиль железа (SSH)» — данные попадут в AI «персональные рекомендации»."
            )

    def _format_ssh_hardware_summary(self, hw: dict) -> str:
        if not isinstance(hw, dict):
            return ""
        lines = []
        mem = hw.get("memory") or {}
        if mem.get("mem_total_gb_rounded") is not None:
            lines.append(f"RAM (оценка): ~{mem['mem_total_gb_rounded']} GiB")
        cpu = hw.get("cpu") or {}
        if cpu.get("cpus_online"):
            lines.append(f"Логических CPU: {cpu['cpus_online']}")
        if cpu.get("model_name"):
            mn = str(cpu["model_name"])
            lines.append(f"CPU: {mn[:120]}{'…' if len(mn) > 120 else ''}")
        st = hw.get("storage") or {}
        if st.get("root_df_line"):
            lines.append(f"Корневая ФС: {st['root_df_line']}")
        cave = (hw.get("caveat") or "").strip()
        if cave:
            lines.append(cave)
        warns = hw.get("warnings") or []
        if warns:
            lines.append("Предупреждения: " + "; ".join(str(w)[:160] for w in warns[:4]))
        ex = hw.get("collected_at_utc")
        if ex:
            lines.append(f"Снято (UTC): {ex}")
        return "\n".join(lines) if lines else "Снимок сохранён (подробности в AI-профиле)."

    def fetch_ssh_hardware_profile(self):
        if self._ssh_hardware_worker is not None:
            QMessageBox.information(self, "SSH профиль", "Сбор профиля уже выполняется.")
            return
        if self._ai_postgres_worker is not None:
            QMessageBox.information(
                self, "SSH профиль", "Дождитесь завершения AI-анализа PostgreSQL."
            )
            return
        if not self.current_connection:
            QMessageBox.warning(self, "SSH профиль", "Выберите сохранённое подключение в списке.")
            return
        ssh_cfg = self.current_connection.get("ssh") or {}
        if not ssh_cfg.get("enabled"):
            QMessageBox.warning(
                self,
                "SSH профиль",
                "В профиле подключения не включён SSH-туннель.\n"
                "Откройте управление подключениями, включите SSH и укажите host/user и ключ или пароль.",
            )
            return

        self.progress_bar.show()
        self.progress_animation.start()
        self._ssh_hardware_worker = CallableWorkerThread(
            functools.partial(collect_hardware_via_ssh, self.current_connection),
            self,
        )
        self._ssh_hardware_worker.completed.connect(self._on_ssh_hardware_done)
        self._ssh_hardware_worker.start()

    def _on_ssh_hardware_done(self, ok: bool, payload: object):
        self.progress_bar.hide()
        self.progress_animation.stop()
        self._ssh_hardware_worker = None
        if not ok:
            QMessageBox.critical(self, "SSH профиль", str(payload))
            return
        if not isinstance(payload, dict):
            QMessageBox.warning(self, "SSH профиль", "Неожиданный ответ сборщика.")
            return
        self._ssh_hardware_profile = payload
        if hasattr(self, "ssh_hardware_summary_label"):
            self.ssh_hardware_summary_label.setText(self._format_ssh_hardware_summary(payload))
        QMessageBox.information(
            self,
            "SSH профиль",
            "Профиль железа сохранён и будет передан в «AI: персональные рекомендации» при следующем запуске.",
        )

    def generate_ai_postgres_recommendations(self):
        if self._ai_postgres_worker is not None:
            QMessageBox.information(self, "AI PostgreSQL", "AI-анализ уже выполняется.")
            return
        if self._ssh_hardware_worker is not None:
            QMessageBox.information(
                self, "AI PostgreSQL", "Дождитесь завершения сбора SSH-профиля железа."
            )
            return
        ai_settings = (self.analyzer_settings or {}).get("ai", {})
        if not ai_settings.get("enabled", False):
            QMessageBox.warning(
                self,
                "AI PostgreSQL",
                "AI-интерпретатор выключен. Включите его в Настройки анализатора -> AI / OpenRouter.",
            )
            return
        provider = (ai_settings.get("provider") or "").strip().lower()
        if provider != "openrouter":
            QMessageBox.warning(
                self, "AI PostgreSQL", "Сейчас поддерживается только provider=openrouter."
            )
            return
        base_url = (ai_settings.get("base_url") or "https://openrouter.ai/api/v1").strip()
        model = (ai_settings.get("model") or "").strip()
        api_key = (ai_settings.get("api_key") or "").strip()
        if not api_key or not model:
            QMessageBox.warning(
                self,
                "AI PostgreSQL",
                "Заполните API key и Модель в Настройки анализатора -> AI / OpenRouter.",
            )
            return

        try:
            profile = self._collect_postgres_ai_profile()
        except Exception as e:
            QMessageBox.warning(
                self, "AI PostgreSQL", f"Не удалось собрать профиль PostgreSQL:\n{e}"
            )
            return

        self.progress_bar.show()
        self.progress_animation.start()
        self._ai_postgres_worker = CallableWorkerThread(
            functools.partial(
                generate_postgres_tuning_recommendations_openrouter,
                base_url=base_url,
                api_key=api_key,
                model=model,
                postgres_profile_payload=profile,
            ),
            self,
        )
        self._ai_postgres_worker.completed.connect(self._on_ai_postgres_done)
        self._ai_postgres_worker.start()

    def _on_ai_postgres_done(self, ok: bool, payload: object):
        self.progress_bar.hide()
        self.progress_animation.stop()
        self._ai_postgres_worker = None
        if not ok:
            QMessageBox.warning(self, "AI PostgreSQL", f"Ошибка AI-анализа:\n{payload}")
            return
        structured = payload.get("structured") if isinstance(payload, dict) else None
        ai_text = (
            str(payload.get("raw_text") or "").strip()
            if isinstance(payload, dict)
            else str(payload or "").strip()
        )
        if not ai_text:
            QMessageBox.warning(self, "AI PostgreSQL", "AI не вернул рекомендации.")
            return
        self._last_ai_postgres_structured = structured if isinstance(structured, dict) else None
        self._last_ai_postgres_raw = ai_text

        if isinstance(structured, dict):
            block = self._render_ai_postgres_structured_html(structured, ai_text)
        else:
            escaped = html.escape(ai_text).replace("\n", "<br>")
            block = (
                "<hr style='border:1px solid #444;margin:12px 0;'>"
                "<h3 style='color:#b3e5fc;margin:0 0 8px 0;'>AI: персональные рекомендации PostgreSQL</h3>"
                "<p style='color:#90a4ae;margin:0 0 8px 0;font-size:11px;'>"
                "Формат ответа не прошёл JSON-валидацию, показан raw-текст."
                "</p>"
                f"<div style='line-height:1.45;'>{escaped}</div>"
            )
        self._ai_postgres_recommendations_html = block
        cached = getattr(self, "_last_postgres_settings_for_recommendations", None)
        if cached is not None:
            try:
                self.update_recommendations_text(cached)
            except Exception as e:
                logging.warning("Не удалось объединить AI-блок с локальными рекомендациями: %s", e)
                self._render_ai_postgres_fallback_html(block)
        else:
            self._render_ai_postgres_fallback_html(block)
        QMessageBox.information(self, "AI PostgreSQL", "AI-рекомендации добавлены в блок настроек.")
        if hasattr(self, "recommendations_text"):
            sb = self.recommendations_text.verticalScrollBar()

            def _scroll_ai_into_view():
                sb.setValue(sb.maximum())

            QTimer.singleShot(0, _scroll_ai_into_view)

    def _render_ai_postgres_fallback_html(self, block: str):
        """Один валидный HTML-документ, если нет кэша настроек для merge или merge упал."""
        if not hasattr(self, "recommendations_text"):
            return
        wrapped = (
            "<html><head><style>"
            "body{color:#e0e0e0;background:transparent;font-size:12px;font-family:'Segoe UI',Arial,sans-serif;}"
            "p,li,div,h3,h4,summary{color:#e0e0e0;}"
            "</style></head><body>" + block + "</body></html>"
        )
        self.recommendations_text.setHtml(wrapped)

    def _render_ai_postgres_structured_html(self, structured: dict, raw_text: str) -> str:
        summary = html.escape(str(structured.get("summary") or "")).replace("\n", "<br>")
        confidence = structured.get("confidence")
        try:
            confidence_value = f"{float(confidence):.2f}"
        except (TypeError, ValueError):
            confidence_value = "n/a"

        rec_items = []
        for rec in structured.get("recommendations", []):
            if not isinstance(rec, dict):
                continue
            priority = html.escape(str(rec.get("priority") or "P3"))
            title = html.escape(str(rec.get("title") or "Без названия"))
            details = html.escape(str(rec.get("details") or ""))
            rec_items.append(
                f"<li><b>{priority}: {title}</b>"
                + (f"<br><span style='color:#b0bec5;'>{details}</span>" if details else "")
                + "</li>"
            )
        if not rec_items:
            rec_items.append("<li>AI не вернул конкретные рекомендации.</li>")

        risk_items = []
        for risk in structured.get("risks", []):
            if isinstance(risk, str):
                risk_items.append(f"<li>{html.escape(risk)}</li>")
        if not risk_items:
            risk_items.append("<li>Явные риски не выделены.</li>")

        check_items = []
        for check in structured.get("read_only_checks", []):
            if isinstance(check, str):
                check_items.append(f"<li>{html.escape(check)}</li>")
        if not check_items:
            check_items.append("<li>Read-only checks не предложены.</li>")

        raw_block = (
            "<details style='margin-top:8px;'>"
            "<summary style='cursor:pointer;color:#90a4ae;'>Raw AI ответ</summary>"
            f"<div style='margin-top:6px;color:#cfd8dc;line-height:1.4;'>{html.escape(raw_text).replace(chr(10), '<br>')}</div>"
            "</details>"
        )
        return (
            "<hr style='border:1px solid #444;margin:12px 0;'>"
            "<h3 style='color:#b3e5fc;margin:0 0 8px 0;'>AI: персональные рекомендации PostgreSQL</h3>"
            f"<p><b>Summary:</b> {summary}</p>"
            f"<p style='color:#90a4ae;'>Confidence: {confidence_value}</p>"
            "<h4 style='color:#81c784;margin:8px 0 4px 0;'>P1/P2/P3 рекомендации</h4>"
            f"<ul>{''.join(rec_items)}</ul>"
            "<h4 style='color:#ffb74d;margin:8px 0 4px 0;'>Risks</h4>"
            f"<ul>{''.join(risk_items)}</ul>"
            "<h4 style='color:#4fc3f7;margin:8px 0 4px 0;'>Safe read-only checks</h4>"
            f"<ul>{''.join(check_items)}</ul>" + raw_block
        )

    def export_ai_postgres_recommendations_markdown(self):
        if not self._last_ai_postgres_raw:
            QMessageBox.information(
                self,
                "Экспорт AI рекомендаций",
                "Нет AI-рекомендаций для экспорта. Сначала выполните AI-анализ.",
            )
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить AI рекомендации",
            "postgres_ai_recommendations.md",
            "Markdown (*.md)",
        )
        if not path:
            return
        lines = ["# AI: персональные рекомендации PostgreSQL", ""]
        structured = self._last_ai_postgres_structured
        if isinstance(structured, dict):
            lines.append(f"**Summary:** {structured.get('summary', '')}")
            lines.append("")
            lines.append(f"**Confidence:** {structured.get('confidence', 'n/a')}")
            lines.append("")
            lines.append("## P1/P2/P3 рекомендации")
            for rec in structured.get("recommendations", []):
                if not isinstance(rec, dict):
                    continue
                lines.append(
                    f"- **{rec.get('priority', 'P3')}** {rec.get('title', '')}: {rec.get('details', '')}"
                )
            lines.append("")
            lines.append("## Risks")
            for risk in structured.get("risks", []):
                if isinstance(risk, str):
                    lines.append(f"- {risk}")
            lines.append("")
            lines.append("## Safe read-only checks")
            for check in structured.get("read_only_checks", []):
                if isinstance(check, str):
                    lines.append(f"- {check}")
            lines.append("")
        lines.append("## Raw AI output")
        lines.append("")
        lines.append(self._last_ai_postgres_raw)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines).strip() + "\n")
        except Exception as e:
            QMessageBox.critical(
                self, "Экспорт AI рекомендаций", f"Не удалось сохранить файл:\n{e}"
            )
            return
        QMessageBox.information(self, "Экспорт AI рекомендаций", f"Сохранено:\n{path}")

    def get_recommended_value(self, param_name, current_value):
        recommendations = {
            "shared_buffers": "25% от RAM",
            "work_mem": "4MB - 64MB",
            "maintenance_work_mem": "5-10% от RAM",
            "effective_cache_size": "50-75% от RAM",
            "random_page_cost": "1.1 для SSD, 4 для HDD",
            "max_connections": "100-500",
            "max_worker_processes": "Ядра CPU × 2",
            "max_parallel_workers_per_gather": "Ядра CPU / 2",
            "checkpoint_completion_target": "0.7-0.9",
            "wal_buffers": "16MB",
            "checkpoint_timeout": "5min - 15min",
            "max_wal_size": "4GB+ (нагрузка-зависимо)",
            "min_wal_size": "1GB+",
            "wal_compression": "on для снижения WAL I/O",
            "effective_io_concurrency": "100-300 для SSD/NVMe",
            "maintenance_io_concurrency": "100-300 для SSD/NVMe",
            "autovacuum_max_workers": "3-10 (нагрузка-зависимо)",
            "autovacuum_naptime": "10s - 1min",
            "autovacuum_vacuum_scale_factor": "0.01-0.1",
            "autovacuum_analyze_scale_factor": "0.02-0.1",
            "default_statistics_target": "100-500",
            "jit": "off для OLTP, on для аналитики",
            "track_io_timing": "on для диагностики I/O",
            "track_wal_io_timing": "on для диагностики WAL I/O",
        }
        return recommendations.get(param_name, "См. документацию")

    def get_param_range(self, name, min_val, max_val):
        ranges = {
            "shared_buffers": "128MB - 8GB",
            "work_mem": "1MB - 1GB",
            "maintenance_work_mem": "64MB - 2GB",
            "effective_cache_size": "1GB - RAM",
            "random_page_cost": "1.0 - 4.0",
            "max_connections": "20 - 1000",
            "max_worker_processes": "1 - 256",
            "max_parallel_workers_per_gather": "0 - 256",
            "checkpoint_completion_target": "0.0 - 1.0",
            "wal_buffers": "32kB - 16MB",
            "checkpoint_timeout": "30s - 24h",
            "max_wal_size": "1GB - 1TB+",
            "min_wal_size": "80MB - max_wal_size",
            "effective_io_concurrency": "0 - 1000",
            "maintenance_io_concurrency": "0 - 1000",
            "autovacuum_max_workers": "1 - 20+",
            "autovacuum_naptime": "1s - 1h",
            "autovacuum_vacuum_scale_factor": "0 - 1",
            "autovacuum_analyze_scale_factor": "0 - 1",
            "default_statistics_target": "1 - 10000",
        }
        if min_val is not None and max_val is not None:
            return f"{min_val} - {max_val}"
        return ranges.get(name, "Зависит от системы")

    def convert_units(self, value, from_unit, to_unit=None):
        try:
            raw = str(value or "").strip()
            if not raw:
                return value if value is not None else ""
            cleaned = re.sub(r"[^\d.]", "", raw)
            if not cleaned:
                return raw
            num_value = float(cleaned)

            if num_value.is_integer():
                return f"{int(num_value)}"

            if from_unit == "kB":
                return f"{num_value / 1024:.2f} MB"
            elif from_unit == "MB":
                return f"{num_value:.2f} MB"
            elif from_unit == "GB":
                return f"{num_value:.2f} GB"
            else:
                return f"{num_value:.2f}"
        except Exception as e:
            logging.error(f"Ошибка конвертации единиц: {e}")
            return value

    def changeEvent(self, event):  # noqa: N802
        """После полноэкранного/максимизированного режима восстанавливаем ширину правой колонки (анализ / рекомендации)."""
        super().changeEvent(event)
        if event.type() != QEvent.WindowStateChange:
            return
        if not getattr(self, "_main_horizontal_splitter", None):
            return
        st = self.windowState()
        if st & (Qt.WindowFullScreen | Qt.WindowMaximized):
            QTimer.singleShot(0, self._ensure_main_splitter_analysis_visible)

    def _ensure_main_splitter_analysis_visible(self):
        """Гарантирует минимальную ширину правой панели (вкладки «Проблемы», «Рекомендации»)."""
        hs = getattr(self, "_main_horizontal_splitter", None)
        if hs is None or hs.width() < 500:
            return
        sizes = hs.sizes()
        if len(sizes) < 2:
            return
        _left_w, right_w = sizes[0], sizes[1]
        min_right = 380
        min_left = 320
        handle = hs.handleWidth()
        total = hs.width()
        if right_w >= min_right:
            return
        avail = total - handle
        if avail < min_left + 200:
            return
        new_right = min(min_right, avail - min_left)
        new_right = max(200, new_right)
        new_left = avail - new_right
        new_left = max(200, new_left)
        hs.setSizes([new_left, new_right])

    def closeEvent(self, event):  # noqa: N802
        """Graceful shutdown: stop background threads before window destruction."""
        try:
            scanners = []
            if hasattr(self, "query_scanner") and self.query_scanner:
                scanners.append(self.query_scanner)
            qa_tab = getattr(self, "query_analyzer_tab", None)
            if qa_tab and getattr(qa_tab, "query_scanner", None):
                scanners.append(qa_tab.query_scanner)

            for scanner in scanners:
                try:
                    scanner.stop_scanning()
                except Exception:
                    logging.debug("Не удалось остановить scanner", exc_info=True)

            for th_name in (
                "query_thread",
                "_db_report_thread",
                "update_stats_thread",
                "_missing_indexes_worker",
            ):
                th = getattr(self, th_name, None)
                if th and getattr(th, "isRunning", lambda: False)():
                    try:
                        th.wait(1500)
                    except Exception:
                        logging.debug("Не удалось дождаться потока %s", th_name, exc_info=True)
        finally:
            super().closeEvent(event)

    def check_setting_status(self, name, value, min_val, max_val):
        try:
            if name in [
                "checkpoint_completion_target",
                "effective_cache_size",
                "maintenance_work_mem",
                "wal_buffers",
                "work_mem",
            ]:
                return "OK", "#51cf66"

            if name == "shared_buffers":
                return "Проверьте", "#fcc419"

            if name == "random_page_cost":
                if float(value) > 2.0:
                    return "OK", "#51cf66"
                else:
                    return "OK", "#51cf66"

            if "max" in name:
                return "OK", "#51cf66"

            if min_val is not None and max_val is not None:
                setting_val = float(value) if value.replace(".", "", 1).isdigit() else None
                if setting_val is not None:
                    min_val_f = float(min_val)
                    max_val_f = float(max_val)

                    if setting_val < min_val_f or setting_val > max_val_f:
                        return "За пределами диапазона", "#ff6b6b"

            return "Неизвестно", "#fcc419"

        except Exception:
            return "Неизвестно", "#fcc419"

    def update_recommendations_text(self, settings_data):
        recommendations = []

        settings_rows = settings_data.get("settings") or []

        dead_tup_threshold = self.analyzer_settings.get("thresholds", {}).get(
            "dead_tup_percent", 20
        )
        mod_warning = self.analyzer_settings.get("thresholds", {}).get(
            "mod_since_analyze_warning", 10000
        )
        mod_critical = self.analyzer_settings.get("thresholds", {}).get(
            "mod_since_analyze_critical", 100000
        )

        shared_buffers = next((s for s in settings_rows if s[0] == "shared_buffers"), None)
        if shared_buffers:
            try:
                value_str = shared_buffers[1].split()[0] if shared_buffers[1] else "0"
                value = float(value_str)
                if value < 128:
                    recommendations.append(
                        "• <b>shared_buffers</b> слишком мал (менее 128MB). Увеличьте до 25% от RAM."
                    )
                elif value > 8192:
                    recommendations.append(
                        "• <b>shared_buffers</b> слишком велик (более 8GB). Уменьшите до 25% от RAM."
                    )
            except (ValueError, IndexError) as e:
                logging.debug(f"Ошибка парсинга shared_buffers: {e}")

        work_mem = next((s for s in settings_rows if s[0] == "work_mem"), None)
        if work_mem:
            try:
                value_str = work_mem[1].split()[0] if work_mem[1] else "0"
                value = float(value_str)
                if value < 4:
                    recommendations.append(
                        "• <b>work_mem</b> слишком мал (менее 4MB). Увеличьте для сложных сортировок."
                    )
                elif value > 64:
                    recommendations.append(
                        "• <b>work_mem</b> слишком велик (более 64MB). Уменьшите для экономии памяти."
                    )
            except (ValueError, IndexError) as e:
                logging.debug(f"Ошибка парсинга work_mem: {e}")

        random_page_cost = next((s for s in settings_rows if s[0] == "random_page_cost"), None)
        if random_page_cost:
            try:
                value = float(random_page_cost[1])
                if value > 2.0:
                    recommendations.append(
                        "• <b>random_page_cost</b> = {:.1f} (рекомендуется 1.1 для SSD)".format(
                            value
                        )
                    )
                else:
                    recommendations.append(
                        "• <b>random_page_cost</b> = {:.1f} (хорошее значение для SSD)".format(
                            value
                        )
                    )
            except (ValueError, IndexError) as e:
                logging.debug(f"Ошибка парсинга random_page_cost: {e}")

        html = """
        <html>
        <head>
            <style>
                body { color: #e0e0e0; font-family: 'Segoe UI', Arial; font-size: 12px; }
                h3 { color: #4fc3f7; margin-top: 5px; margin-bottom: 5px; }
                ul { margin-top: 0; padding-left: 20px; }
                li { margin-bottom: 5px; }
                .ok { color: #51cf66; }
                .warn { color: #fcc419; }
                .error { color: #ff6b6b; }
            </style>
        </head>
        <body>
            <h3>Рекомендации по настройке PostgreSQL</h3>
        """

        if recommendations:
            html += "<ul>"
            for rec in recommendations:
                html += f"<li>{rec}</li>"
            html += "</ul>"
        else:
            html += "<p class='ok'>Ключевые параметры выглядят нормально. Специальные рекомендации не требуются.</p>"

        html += f"""
        <hr style="border-color:#444; margin:10px 0;">
        <p style="font-size:11px; color:#888;">
            📊 Текущие пороги анализа:<br>
            • Мертвые строки для VACUUM: &gt;{dead_tup_threshold}%<br>
            • Изменений после анализа (предупреждение): &gt;{mod_warning}<br>
            • Изменений после анализа (критично): &gt;{mod_critical}
        </p>
        """

        html += "</body></html>"

        ai_frag = getattr(self, "_ai_postgres_recommendations_html", "") or ""
        if ai_frag:
            close = "</body></html>"
            pos = html.rfind(close)
            if pos != -1:
                html = html[:pos] + ai_frag + "\n" + html[pos:]

        if hasattr(self, "recommendations_text"):
            self.recommendations_text.setHtml(html)

    def show_all_postgres_settings(self):
        if not hasattr(self, "conn") or self.conn.closed:
            QMessageBox.warning(self, "Ошибка", "Нет подключения к PostgreSQL")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Все параметры PostgreSQL")
        dialog.resize(1200, 800)
        dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        filter_panel = QWidget()
        filter_layout = QHBoxLayout(filter_panel)
        filter_layout.setContentsMargins(0, 0, 0, 0)

        self.settings_search = QLineEdit()
        self.settings_search.setPlaceholderText("Поиск по параметрам...")
        self.settings_search.textChanged.connect(self.filter_settings_table)
        self.settings_search.setStyleSheet("""
            QLineEdit {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 5px;
                font-size: 12px;
            }
        """)

        self.settings_category = QComboBox()
        self.settings_category.addItem("Все категории", "")
        self.settings_category.addItem("Память", "memory")
        self.settings_category.addItem("Соединения", "connections")
        self.settings_category.addItem("Производительность", "performance")
        self.settings_category.addItem("Журналирование", "wal")
        self.settings_category.addItem("Репликация", "replication")
        self.settings_category.addItem("Параллельные запросы", "parallel")
        self.settings_category.addItem("Статистика", "statistics")
        self.settings_category.currentIndexChanged.connect(self.filter_settings_table)

        reset_button = QPushButton("Сбросить фильтры")
        reset_button.clicked.connect(self.reset_settings_filters)

        filter_layout.addWidget(QLabel("Поиск:"), 0)
        filter_layout.addWidget(self.settings_search, 1)
        filter_layout.addWidget(QLabel("Категория:"), 0)
        filter_layout.addWidget(self.settings_category, 1)
        filter_layout.addWidget(reset_button, 0)

        layout.addWidget(filter_panel)

        self.all_settings_table = QTableWidget()
        self.all_settings_table.setColumnCount(6)
        self.all_settings_table.setHorizontalHeaderLabels(
            ["Статус", "Параметр", "Текущее", "Ед.изм", "Диапазон", "Описание"]
        )
        self.all_settings_table.verticalHeader().setVisible(False)
        self.all_settings_table.setSortingEnabled(True)
        self.all_settings_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.all_settings_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.all_settings_table.setSelectionMode(QTableWidget.SingleSelection)
        self.all_settings_table.setWordWrap(True)

        self.all_settings_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                gridline-color: #444;
                font-size: 11px;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #e0e0e0;
                padding: 5px;
                border: 1px solid #444;
                font-weight: bold;
                font-size: 11px;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)

        header = self.all_settings_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)

        self.all_settings_table.setColumnWidth(0, 80)
        self.all_settings_table.setColumnWidth(1, 180)
        self.all_settings_table.setColumnWidth(2, 120)
        self.all_settings_table.setColumnWidth(3, 60)
        self.all_settings_table.setColumnWidth(4, 120)

        self.all_settings_table.setWordWrap(True)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.all_settings_table)
        scroll.setStyleSheet("""
            QScrollArea {
                border: 1px solid #444;
                background-color: #2d2d2d;
            }
            QScrollBar:vertical {
                border: none;
                background: #333;
                width: 10px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #555;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background: none;
            }
        """)

        layout.addWidget(scroll, 1)

        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)

        fullscreen_button = QPushButton("Развернуть")
        fullscreen_button.clicked.connect(
            lambda: dialog.showMaximized() if not dialog.isMaximized() else dialog.showNormal()
        )
        button_box.addButton(fullscreen_button, QDialogButtonBox.ActionRole)

        layout.addWidget(button_box, 0)

        self.load_all_postgres_settings(dialog)

        dialog.exec_()

    def reset_settings_filters(self):
        self.settings_search.clear()
        self.settings_category.setCurrentIndex(0)
        self.filter_settings_table()

    def filter_settings_table(self, text=None):
        try:
            search_text = self.settings_search.text().lower()
            category = self.settings_category.currentData()

            for row in range(self.all_settings_table.rowCount()):
                status_item = self.all_settings_table.item(row, 0)
                row_category = status_item.data(Qt.UserRole) if status_item else ""

                name_item = self.all_settings_table.item(row, 1)
                desc_item = self.all_settings_table.item(row, 5)

                if not name_item or not desc_item:
                    continue

                name = name_item.text().lower()
                desc = desc_item.text().lower()

                name_match = not search_text or search_text in name
                desc_match = not search_text or search_text in desc
                category_match = not category or row_category == category

                self.all_settings_table.setRowHidden(
                    row, not (name_match and desc_match and category_match)
                )

        except Exception as e:
            logging.error(f"Ошибка фильтрации таблицы параметров: {e}")
            QMessageBox.warning(self, "Ошибка", f"Ошибка при фильтрации:\n{str(e)}")

    def load_all_postgres_settings(self, dialog):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    SELECT name, setting, unit, short_desc, context, vartype, min_val, max_val, enumvals
                    FROM pg_settings
                    ORDER BY name
                """)
                settings = cursor.fetchall()

                categories = {
                    "memory": [
                        "shared_buffers",
                        "work_mem",
                        "maintenance_work_mem",
                        "effective_cache_size",
                        "temp_buffers",
                        "wal_buffers",
                        "huge_pages",
                    ],
                    "connections": [
                        "max_connections",
                        "superuser_reserved_connections",
                        "tcp_keepalives_idle",
                        "tcp_keepalives_interval",
                        "tcp_keepalives_count",
                    ],
                    "performance": [
                        "random_page_cost",
                        "effective_io_concurrency",
                        "max_worker_processes",
                        "max_parallel_workers_per_gather",
                        "parallel_setup_cost",
                        "parallel_tuple_cost",
                    ],
                    "wal": [
                        "wal_level",
                        "synchronous_commit",
                        "wal_compression",
                        "wal_log_hints",
                        "wal_writer_delay",
                        "wal_writer_flush_after",
                    ],
                    "replication": [
                        "max_wal_senders",
                        "hot_standby",
                        "max_replication_slots",
                        "wal_receiver_timeout",
                        "wal_retrieve_retry_interval",
                    ],
                    "parallel": [
                        "max_parallel_workers",
                        "max_parallel_workers_per_gather",
                        "parallel_leader_participation",
                        "parallel_setup_cost",
                    ],
                    "statistics": [
                        "track_activities",
                        "track_counts",
                        "track_io_timing",
                        "track_functions",
                        "stats_temp_directory",
                    ],
                }

                self.all_settings_table.setRowCount(0)
                self.all_settings_table.setSortingEnabled(False)

                for setting in settings:
                    name = setting[0]
                    category = ""
                    for cat, params in categories.items():
                        if name in params:
                            category = cat
                            break

                    self.add_setting_row(setting, category)

                self.all_settings_table.setSortingEnabled(True)
                self.all_settings_table.sortItems(1, Qt.AscendingOrder)

        except Exception as e:
            QMessageBox.critical(dialog, "Ошибка", f"Не удалось загрузить параметры:\n{str(e)}")

    def add_setting_row(self, setting, category):
        name, setting_val, unit, desc, context, vartype, min_val, max_val, enumvals = setting

        status, color = self.get_setting_status(name, setting_val, min_val, max_val)

        row = self.all_settings_table.rowCount()
        self.all_settings_table.insertRow(row)

        status_item = QTableWidgetItem(status)
        status_item.setForeground(QColor(color))
        status_item.setToolTip(status)
        status_item.setData(Qt.UserRole, category)
        self.all_settings_table.setItem(row, 0, status_item)

        param_item = QTableWidgetItem(name)
        param_item.setData(Qt.UserRole, category)
        self.all_settings_table.setItem(row, 1, param_item)

        current_item = QTableWidgetItem(setting_val)
        current_item.setToolTip(setting_val)
        self.all_settings_table.setItem(row, 2, current_item)

        unit_item = QTableWidgetItem(unit if unit else "")
        self.all_settings_table.setItem(row, 3, unit_item)

        range_text = ""
        if min_val is not None and max_val is not None:
            range_text = f"{min_val} - {max_val}"
        elif min_val is not None:
            range_text = f"≥ {min_val}"
        elif max_val is not None:
            range_text = f"≤ {max_val}"
        range_item = QTableWidgetItem(range_text)
        self.all_settings_table.setItem(row, 4, range_item)

        desc_item = QTableWidgetItem(desc if desc else "Нет описания")
        desc_item.setToolTip(desc if desc else "Нет описания")
        self.all_settings_table.setItem(row, 5, desc_item)

    def get_setting_status(self, name, setting, min_val, max_val):
        recommended_values = {
            "shared_buffers": ("25% от RAM", "#51cf66"),
            "work_mem": ("4MB - 64MB", "#51cf66"),
            "maintenance_work_mem": ("5-10% от RAM", "#51cf66"),
            "effective_cache_size": ("50-75% от RAM", "#51cf66"),
            "random_page_cost": ("1.1 для SSD, 4 для HDD", "#51cf66"),
            "max_connections": ("100-500", "#51cf66"),
            "max_worker_processes": ("Ядра CPU * 2", "#51cf66"),
            "max_parallel_workers_per_gather": ("Ядра CPU / 2", "#51cf66"),
            "wal_buffers": ("-1 (авто) или 16MB", "#51cf66"),
        }

        if name in recommended_values:
            return recommended_values[name]

        try:
            if min_val and max_val:
                setting_val = float(setting) if setting.replace(".", "", 1).isdigit() else None
                if setting_val is not None:
                    min_val_f = float(min_val)
                    max_val_f = float(max_val)

                    if setting_val < min_val_f:
                        return ("Слишком мало", "#ff6b6b")
                    elif setting_val > max_val_f:
                        return ("Слишком много", "#ff6b6b")
                    else:
                        return ("OK", "#51cf66")

        except Exception:
            pass

        return ("Неизвестно", "#fcc419")

    def get_postgresql_settings(self):
        if not self.connection_status or not hasattr(self, "conn"):
            return None

        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    SELECT name, setting, unit, short_desc, context, vartype, min_val, max_val, enumvals
                    FROM pg_settings
                    WHERE name IN (
                        'shared_buffers', 'work_mem', 'maintenance_work_mem',
                        'effective_cache_size', 'random_page_cost', 'max_connections',
                        'max_worker_processes', 'max_parallel_workers_per_gather',
                        'checkpoint_completion_target', 'wal_buffers',
                        'checkpoint_timeout', 'max_wal_size', 'min_wal_size',
                        'wal_compression', 'wal_writer_delay',
                        'effective_io_concurrency', 'maintenance_io_concurrency',
                        'autovacuum_max_workers', 'autovacuum_naptime',
                        'autovacuum_vacuum_scale_factor', 'autovacuum_analyze_scale_factor',
                        'default_statistics_target',
                        'jit', 'jit_above_cost', 'jit_inline_above_cost', 'jit_optimize_above_cost',
                        'max_parallel_workers', 'max_parallel_maintenance_workers',
                        'parallel_setup_cost', 'parallel_tuple_cost',
                        'track_io_timing', 'track_wal_io_timing',
                        'cpu_tuple_cost', 'cpu_index_tuple_cost', 'cpu_operator_cost',
                        'seq_page_cost', 'temp_buffers'
                    )
                    ORDER BY name
                """)
                settings = cursor.fetchall()
                return settings

        except Exception as e:
            logging.error(f"Ошибка получения параметров PostgreSQL: {e}")
            self.conn.rollback()
            return None

    def analyze_postgresql_settings(self, settings_data):
        if not settings_data:
            return "[error]Не удалось получить параметры PostgreSQL[/error]"

        analysis = "[title]Текущие настройки PostgreSQL[/title]\n\n"
        analysis += f"[section]Версия PostgreSQL:[/section]\n{settings_data['version']}\n\n"

        important_params = {
            "shared_buffers": ("Общая память (shared_buffers)", "Рекомендуется 25% от RAM"),
            "work_mem": ("Память на операцию (work_mem)", "Увеличить для сложных сортировок"),
            "maintenance_work_mem": (
                "Память для обслуживания (maintenance_work_mem)",
                "Увеличить для создания индексов",
            ),
            "effective_cache_size": (
                "Эффективный размер кэша (effective_cache_size)",
                "Рекомендуется 50-75% от RAM",
            ),
            "random_page_cost": (
                "Стоимость случайного чтения (random_page_cost)",
                "Уменьшить для SSD",
            ),
            "max_connections": (
                "Максимальное число подключений (max_connections)",
                "Оптимизировать в зависимости от нагрузки",
            ),
        }

        analysis += "[section]Ключевые параметры:[/section]\n"
        for row in settings_data["settings"]:
            name, setting, unit, desc, context = row
            if name in important_params:
                param_name, recommendation = important_params[name]
                analysis += f"[hl]{param_name}:[/hl] {setting} {unit if unit else ''}\n"
                analysis += f"[rec]Рекомендация: {recommendation}[/rec]\n"
                analysis += f"[i]Описание: {desc}[/i]\n\n"

        if hasattr(self, "query_plans_journal") and self.query_plans_journal:
            analysis += "[section]Рекомендации на основе анализа запросов:[/section]\n"

            has_seq_scan = any(
                "Seq Scan" in entry.get("query_parts", []) for entry in self.query_plans_journal
            )
            if has_seq_scan:
                analysis += "[warning]Обнаружены Seq Scan операции:[/warning]\n"
                analysis += (
                    "[rec]- Увеличьте work_mem для уменьшения временных файлов сортировки[/rec]\n"
                )
                analysis += "[rec]- Проверьте статистику таблиц: ANALYZE table_name[/rec]\n"
                analysis += "[rec]- Увеличьте maintenance_work_mem для ускорения создания индексов[/rec]\n\n"

            has_expensive_joins = any(
                entry.get("total_cost", 0) > 1000 for entry in self.query_plans_journal
            )
            if has_expensive_joins:
                analysis += "[warning]Обнаружены дорогостоящие соединения:[/warning]\n"
                analysis += "[rec]- Увеличьте work_mem для хеш-соединений[/rec]\n"
                analysis += "[rec]- Включите параллельное выполнение: max_parallel_workers_per_gather[/rec]\n\n"

        analysis += "[section]Общие рекомендации по настройке:[/section]\n"
        analysis += "[rec]- shared_buffers: 25% от оперативной памяти[/rec]\n"
        analysis += "[rec]- effective_cache_size: 50-75% от оперативной памяти[/rec]\n"
        analysis += "[rec]- work_mem: (shared_buffers * 0.25) / max_connections[/rec]\n"
        analysis += "[rec]- maintenance_work_mem: 5-10% от оперативной памяти[/rec]\n"
        analysis += "[rec]- random_page_cost: 1.1 для SSD, 4 для HDD[/rec]\n"
        analysis += "[rec]- max_connections: оптимизировать под нагрузку[/rec]\n"

        return analysis

    def show_query_plans_journal(self):
        if hasattr(self, "embedded_journal"):
            self._switch_left_tab(self.HISTORY_TAB_LABEL)
            self.embedded_journal.load_journal()
            return

        self.journal_window = QueryPlansJournal(self)
        self.journal_window.show()

    def save_to_journal(
        self,
        xml_content,
        query_text="",
        statement_queryid=None,
        plan_origin=None,
        hypopg_pair_group_id=None,
        hypopg_pair_role=None,
    ):
        if hasattr(self, "is_loading_from_journal") and self.is_loading_from_journal:
            return

        if not self.analyzer_settings.get("journal", {}).get("auto_save_plans", True):
            return

        if plan_origin == "hypopg":
            source_type = "hypopg"
            source_name = "HypoPG"
        elif plan_origin == "file" or getattr(self, "last_opened_file", None):
            source_type = "file"
            base = getattr(self, "last_opened_file", None)
            source_name = os.path.basename(base) if base else "Файл"
        else:
            source_type = "manual"
            source_name = "Ручной запрос"

        query_parts = []
        try:
            query_parts = journal_preview_parts_from_plan_doc(xml_content)
        except Exception as e:
            logging.error(f"Ошибка анализа плана для журнала: {e}")

        entry = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "execution_time": datetime.datetime.now().strftime("%H:%M:%S"),
            "source_type": source_type,
            "source_name": source_name,
            "query_parts": query_parts,
            "xml_content": xml_content,
            "query": query_text,
            "custom_name": " | ".join(query_parts) if query_parts else "Новый план запроса",
            "description": "",
            "plan_origin": plan_origin or "explain",
        }
        if statement_queryid:
            entry["statement_queryid"] = statement_queryid
        if hypopg_pair_group_id:
            entry["hypopg_pair_group_id"] = hypopg_pair_group_id
        if hypopg_pair_role:
            entry["hypopg_pair_role"] = hypopg_pair_role

        if not hasattr(self, "query_plans_journal"):
            self.query_plans_journal = []

        existing_entry = next(
            (
                e
                for e in self.query_plans_journal
                if e["timestamp"] == entry["timestamp"] and e["source_name"] == entry["source_name"]
            ),
            None,
        )

        if not existing_entry:
            max_entries = self.analyzer_settings.get("journal", {}).get("max_entries", 1000)
            try:
                self.query_plans_journal, _ = upsert_unique_journal_entry(
                    entry, self.query_plans_journal, max_entries
                )
            except Exception as e:
                logging.error(f"Ошибка сохранения журнала: {e}")

    def _refresh_journal_window_if_open(self):
        jw = getattr(self, "journal_window", None)
        if jw is not None:
            try:
                if jw.isVisible():
                    jw.load_journal()
            except RuntimeError:
                pass

        embedded = getattr(self, "embedded_journal", None)
        if embedded is not None:
            embedded.load_journal()

    def save_hypopg_baseline_for_comparison(self):
        """Сохранить текущий план в журнал как «базовый» для последующей пары с HypoPG."""
        if not self.analyzer_settings.get("journal", {}).get("auto_save_plans", True):
            QMessageBox.warning(
                self,
                "Журнал",
                "Включите автосохранение планов в журнале (настройки анализатора).",
            )
            return False
        xml_content = getattr(self, "xml_content", None)
        if not xml_content:
            QMessageBox.warning(
                self,
                "HypoPG",
                "Нет загруженного плана. Выполните EXPLAIN или откройте файл плана.",
            )
            return False
        gid = uuid.uuid4().hex
        self._hypopg_pair_group_id = gid
        plan_origin = "file" if getattr(self, "last_opened_file", None) else "explain"
        query_text = self.query_input.text() if hasattr(self, "query_input") else ""
        self.save_to_journal(
            xml_content,
            query_text,
            plan_origin=plan_origin,
            hypopg_pair_group_id=gid,
            hypopg_pair_role="baseline",
        )
        self._refresh_journal_window_if_open()
        QMessageBox.information(
            self,
            "HypoPG",
            "Базовый план записан в журнал. Следующий успешный EXPLAIN с HypoPG получит ту же связку «до/после».",
        )
        return True

    def clear_hypopg_comparison_pair(self):
        self._hypopg_pair_group_id = None

    def load_query_plans_journal(self):
        self.query_plans_journal = load_journal_entries()
        logging.info(f"Loaded {len(self.query_plans_journal)} query plans from journal")

    def create_icon_toolbar(self):
        icon_toolbar = QToolBar("Icon Toolbar")
        icon_toolbar.setIconSize(QSize(24, 24))
        icon_toolbar.setOrientation(Qt.Vertical)
        icon_toolbar.setMovable(True)
        icon_toolbar.setAllowedAreas(Qt.LeftToolBarArea | Qt.RightToolBarArea)
        icon_toolbar.setFloatable(True)

        self.icon_toolbar = icon_toolbar

        open_action = QAction(icon("fa5s.folder-open", color="white"), "Открыть план", self)
        open_action.triggered.connect(self.open_and_analyze_plan)
        open_action.setToolTip("Открыть файл плана (XML или JSON)")
        icon_toolbar.addAction(open_action)

        manage_conn_action = QAction(
            icon("fa5s.network-wired", color="white"), "Управление подключениями", self
        )
        manage_conn_action.triggered.connect(self.show_manage_connections_dialog)
        manage_conn_action.setToolTip("Управление сохраненными подключениями")
        icon_toolbar.addAction(manage_conn_action)

        clear_action = QAction(icon("fa5s.eraser", color="white"), "Очистить", self)
        clear_action.triggered.connect(self.clear_workspace)
        clear_action.setToolTip("Очистить рабочую область")
        icon_toolbar.addAction(clear_action)

        home_action = QAction(icon("fa5s.home", color="white"), "Домой", self)
        home_action.triggered.connect(self.show_welcome_screen)
        home_action.setToolTip("Вернуться на начальный экран")
        icon_toolbar.addAction(home_action)

        analyze_action = QAction(icon("fa5s.search", color="white"), "Анализировать", self)
        analyze_action.triggered.connect(self.analyze_query_plan)
        analyze_action.setToolTip("Анализировать текущий план запроса")
        icon_toolbar.addAction(analyze_action)

        ai_explain_action = QAction(icon("fa5s.robot", color="white"), "AI: объяснить план", self)
        ai_explain_action.triggered.connect(self.explain_current_plan_with_ai)
        ai_explain_action.setToolTip("Сформировать AI-интерпретацию текущего плана (OpenRouter)")
        icon_toolbar.addAction(ai_explain_action)

        export_action = QAction(icon("fa5s.file-export", color="white"), "Экспорт", self)
        export_action.triggered.connect(self.export_analysis)
        export_action.setToolTip("Экспортировать результаты анализа")
        icon_toolbar.addAction(export_action)

        db_report_action = QAction(icon("fa5s.file-alt", color="white"), "Отчёт БД", self)
        db_report_action.triggered.connect(self.export_database_report)
        db_report_action.setToolTip("Сформировать отчёт по состоянию PostgreSQL")
        icon_toolbar.addAction(db_report_action)

        settings_action = QAction(icon("fa5s.cog", color="white"), "Настройки", self)
        settings_action.triggered.connect(self.show_settings)
        settings_action.setToolTip("Открыть окно настроек")
        icon_toolbar.addAction(settings_action)

        analyzer_settings_action = QAction(
            icon("fa5s.sliders-h", color="white"), "Настройки анализатора", self
        )
        analyzer_settings_action.triggered.connect(self.show_analyzer_settings)
        analyzer_settings_action.setToolTip("Тонкая настройка анализатора планов запросов")
        icon_toolbar.addAction(analyzer_settings_action)

        help_action = QAction(icon("fa5s.question-circle", color="white"), "Справка", self)
        help_action.triggered.connect(self.show_help)
        help_action.setToolTip("Открыть справочный материал")
        icon_toolbar.addAction(help_action)

        journal_action = QAction(icon("fa5s.book", color="white"), "Журнал планов", self)
        journal_action.triggered.connect(self.show_query_plans_journal)
        journal_action.setToolTip("Открыть журнал планов запросов")
        self.icon_toolbar.addAction(journal_action)

        self.icon_toolbar.setStyleSheet("""
            QToolBar {
                background-color: #2d2d2d;
                border: none;
            }
            QToolBar::separator {
                background: #444;
                width: 1px;
            }
        """)

        self.addToolBar(Qt.LeftToolBarArea, self.icon_toolbar)

    def on_connect_button_clicked(self):
        logging.debug(f"Connection status before action: {self.connection_status}")

        if self.connection_status:
            self.disconnect_from_database()
        else:
            self.connect_to_database()

    def clear_workspace(self):
        self.xml_content = None
        if hasattr(self, "general_analysis_text"):
            self.general_analysis_text.clear()
        if hasattr(self, "optimization_text"):
            self.optimization_text.clear()
        if hasattr(self, "settings_text"):
            self.settings_text.clear()
        if hasattr(self, "node_info_text"):
            self.node_info_text.clear()
        if hasattr(self, "query_input"):
            self.query_input.clear()

        if hasattr(self, "visualizer_window"):
            self.visualizer_layout.removeWidget(self.visualizer_window)
            self.visualizer_window.deleteLater()
            del self.visualizer_window

        self.show_welcome_screen()

    def show_welcome_screen(self):
        self._switch_left_tab(self.PLAN_TAB_LABEL)

        if hasattr(self, "visualizer_window"):
            self.visualizer_window.hide()

        if not hasattr(self, "initial_content"):
            self.initial_content = self._create_welcome_view()
            self.visualizer_layout.addWidget(self.initial_content, 1)
        else:
            self.initial_content.setHtml(self.get_welcome_html())
            self.initial_content.show()

    def show_plan_workspace(self):
        self._switch_left_tab(self.PLAN_TAB_LABEL)

        if hasattr(self, "initial_content"):
            self.initial_content.hide()

        if hasattr(self, "visualizer_window"):
            self.visualizer_window.show()
            return True

        if hasattr(self, "query_input"):
            self.query_input.setFocus()
        return False

    def _on_visible_graph_outline(self, payload_json: str) -> None:
        """Под визуализацию pev2: список id узлов, видимых на графе (двойной клик / глубина)."""
        try:
            self._visible_outline_snapshot = json.loads(payload_json)
        except (json.JSONDecodeError, TypeError, ValueError):
            self._visible_outline_snapshot = None

    def _markdown_visible_plan_fragment(self) -> str:
        """При экспорте анализа: таблица только видимых на графе операций."""
        meta = getattr(self, "_plan_graph_metadata", None) or {}
        if not meta:
            return ""
        snap = getattr(self, "_visible_outline_snapshot", None)
        total_in_tree = len(meta)
        if isinstance(snap, dict) and snap.get("visibleIds") is not None:
            visible_ids = {str(x) for x in snap["visibleIds"]}
            collapsed = list(snap.get("collapsedRootIds") or [])
            total_plan_nodes = snap.get("totalPlanNodes")
            visible_count = snap.get("visibleCount")
            if isinstance(visible_count, int):
                vc_disp = visible_count
            else:
                vc_disp = len(visible_ids)
        else:
            visible_ids = set(meta.keys())
            collapsed = []
            total_plan_nodes = total_in_tree
            vc_disp = len(visible_ids)
        tp = total_plan_nodes if isinstance(total_plan_nodes, int) else total_in_tree

        buf = []
        buf.append("\n### Узлы плана на графе (видимые операции)\n")
        buf.append("")
        buf.append(
            f"Операций в дереве плана: **{tp}**. В текущем виде графа показано: **{vc_disp}** "
        )
        buf.append("(ограничение глубины, сворачивание ветви двойным кликом по узлу).\n")
        if collapsed:
            collapsed_s = ", ".join(f"`{c}`" for c in collapsed[:32])
            if len(collapsed) > 32:
                collapsed_s += " …"
            buf.append("")
            buf.append(f"Идентификаторы узлов со свёрнутыми потомками: {collapsed_s}.\n")
        buf.append("")
        buf.append("| depth | операция | cost | объект / индекс |")
        buf.append("| ---: | --- | ---: | --- |")

        rows: list[tuple[int, float, str, str]] = []
        for nid in sorted(visible_ids, key=lambda x: meta.get(x, {}).get("depth", 0)):
            row = meta.get(nid)
            if not row:
                continue
            depth_i = int(row.get("depth", 0))
            typ_s = str(row.get("type", "?"))
            try:
                cst = float(row.get("cost", 0))
            except (TypeError, ValueError):
                cst = 0.0
            props = row.get("properties") or {}
            if not isinstance(props, dict):
                props = {}
            rel = props.get("Relation-Name") or props.get("Index-Name") or ""
            alias = props.get("Alias") or ""
            obj = ""
            if rel:
                obj = str(rel).replace("|", "\\|").replace("\n", " ")
                if alias and str(alias) != str(rel):
                    obj = f"{obj} ({alias})"
            rows.append((depth_i, -cst, typ_s, obj))
        rows.sort(key=lambda t: (t[0], t[1]))
        for depth_i, _neg_cost, typ_s, obj in rows:
            cst_abs = -_neg_cost
            buf.append(f"| {depth_i} | {typ_s} | {cst_abs:.2f} | {obj} |")
        buf.append("")
        return "\n".join(buf)

    def export_analysis(self):
        if not hasattr(self, "xml_content") or not self.xml_content:
            QMessageBox.warning(self, "Ошибка", "Нет данных для экспорта")
            return

        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт результатов анализа",
            "",
            "MarkDown Files (*.md);;All Files (*)",
            options=options,
        )

        if not fileName:
            return

        try:
            markdown_content = "# Анализ плана запроса PostgreSQL\n\n"
            markdown_content += "## Общий анализ\n\n"
            markdown_content += self.general_analysis_text.toMarkdown()
            markdown_content += "\n\n"
            markdown_content += "## Рекомендации по оптимизации\n\n"
            markdown_content += self.optimization_text.toMarkdown()
            markdown_content += "\n\n"
            markdown_content += "## Рекомендации по настройке PostgreSQL\n\n"
            markdown_content += (
                self.settings_text.toMarkdown() if hasattr(self, "settings_text") else ""
            )

            extra_vis = self._markdown_visible_plan_fragment()
            if extra_vis.strip():
                markdown_content += extra_vis

            with open(fileName, "w", encoding="utf-8") as f:
                f.write(markdown_content)

            QMessageBox.information(self, "Успех", "Результаты анализа успешно экспортированы")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать результаты:\n{str(e)}")

    def _ask_database_report_options(self) -> Optional[dict[str, Any]]:
        dialog = QDialog(self)
        dialog.setWindowTitle("Параметры отчёта БД")
        dialog.setMinimumWidth(480)

        root = QVBoxLayout(dialog)
        form = QFormLayout()

        include_explain = QCheckBox("Выполнить EXPLAIN (ANALYZE, BUFFERS) для одного top-запроса")
        include_explain.setChecked(True)

        include_ai = QCheckBox("Добавить AI-сводку (если задан PGQA_OPENAI_API_KEY)")
        include_ai.setChecked(False)

        top_n_spin = QSpinBox()
        top_n_spin.setRange(3, 50)
        top_n_spin.setValue(10)
        top_n_spin.setToolTip("Сколько top-запросов брать из pg_stat_statements")

        timeout_spin = QSpinBox()
        timeout_spin.setRange(5, 900)
        timeout_spin.setValue(120)
        timeout_spin.setSuffix(" сек")
        timeout_spin.setToolTip("Таймаут только для EXPLAIN ANALYZE")

        form.addRow("Top-N запросов:", top_n_spin)
        form.addRow("Таймаут EXPLAIN:", timeout_spin)
        form.addRow("", include_explain)
        form.addRow("", include_ai)
        root.addLayout(form)

        hint = QLabel(
            "Отчёт собирается в read-only режиме; EXPLAIN ANALYZE может создавать нагрузку."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#bdbdbd; font-size:11px;")
        root.addWidget(hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        root.addWidget(buttons)

        if dialog.exec_() != QDialog.Accepted:
            return None
        return {
            "include_explain": include_explain.isChecked(),
            "include_ai": include_ai.isChecked(),
            "top_n": int(top_n_spin.value()),
            "explain_timeout_ms": int(timeout_spin.value() * 1000),
        }

    def export_database_report(self):
        if not self.connection_status or not hasattr(self, "conn"):
            QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
            return

        options = self._ask_database_report_options()
        if not options:
            return

        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить отчёт БД",
            f"db_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            "MarkDown Files (*.md);;All Files (*)",
        )
        if not file_name:
            return

        if not file_name.lower().endswith(".md"):
            file_name = file_name + ".md"

        selected_name = (
            self.connection_combo.currentText().strip() if hasattr(self, "connection_combo") else ""
        )
        fresh_map = StoredConnectionSettings.load_connections()
        conn_profile = fresh_map.get(selected_name) if selected_name else self.current_connection
        if not conn_profile:
            QMessageBox.warning(
                self, "Ошибка", "Не удалось прочитать параметры подключения для отчёта."
            )
            return

        connection_params = StoredConnectionSettings.connect_kwargs(conn_profile)
        self._db_report_target_path = file_name

        self.progress_bar.show()
        self.progress_animation.start()
        self.execute_button.setEnabled(False)
        self.query_input.setEnabled(False)

        self._db_report_thread = CallableWorkerThread(
            functools.partial(
                self._build_database_report_worker,
                connection_params,
                bool(options.get("include_explain")),
                int(options.get("top_n") or 10),
                int(options.get("explain_timeout_ms") or 120000),
                bool(options.get("include_ai")),
            ),
            self,
        )
        self._db_report_thread.completed.connect(self._on_database_report_done)
        self._db_report_thread.start()

    def _build_database_report_worker(
        self,
        connection_params: dict[str, Any],
        include_explain: bool,
        top_n: int,
        explain_timeout_ms: int,
        include_ai: bool,
    ) -> dict[str, Any]:
        with psycopg2.connect(**connection_params) as report_conn:
            report_conn.autocommit = True
            snapshot = collect_database_report_snapshot(
                report_conn,
                include_explain=include_explain,
                top_n_statements=top_n,
                explain_timeout_ms=explain_timeout_ms,
            )
        ai_summary = ""
        if include_ai:
            try:
                ai_summary = generate_ai_summary_openai(snapshot)
            except Exception as e:
                snapshot.setdefault("warnings", []).append(f"AI-сводка недоступна: {e}")
                ai_summary = ""
        markdown = build_database_report_markdown(snapshot, ai_summary=ai_summary)
        return {"markdown": markdown, "warnings": snapshot.get("warnings") or []}

    def _on_database_report_done(self, ok: bool, payload: Any) -> None:
        self.progress_bar.hide()
        self.progress_animation.stop()
        self.execute_button.setEnabled(True)
        self.query_input.setEnabled(True)

        if not ok:
            QMessageBox.critical(self, "Отчёт БД", f"Не удалось сформировать отчёт:\n{payload}")
            self._db_report_thread = None
            return

        target = getattr(self, "_db_report_target_path", "")
        try:
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(payload.get("markdown") or "")
        except Exception as e:
            QMessageBox.critical(self, "Отчёт БД", f"Не удалось сохранить файл:\n{e}")
            self._db_report_thread = None
            return

        warns = payload.get("warnings") or []
        warn_text = ""
        if warns:
            warn_text = "\n\nПримечания:\n- " + "\n- ".join(str(x) for x in warns[:6])
        QMessageBox.information(
            self,
            "Отчёт БД",
            f"Отчёт успешно сохранён:\n{target}{warn_text}",
        )
        self._db_report_thread = None

    def show_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Настройки программы")
        dialog.setMinimumWidth(400)

        layout = QVBoxLayout()

        appearance_group = QGroupBox("Внешний вид")
        appearance_layout = QFormLayout()

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Темная", "Светлая", "Системная"])
        appearance_layout.addRow("Тема:", self.theme_combo)

        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 20)
        self.font_size_spin.setValue(12)
        appearance_layout.addRow("Размер шрифта:", self.font_size_spin)

        appearance_group.setLayout(appearance_layout)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)

        layout.addWidget(appearance_group)
        layout.addWidget(button_box)

        dialog.setLayout(layout)

        if dialog.exec_() == QDialog.Accepted:
            self.apply_settings()

    def apply_settings(self):
        QMessageBox.information(
            self, "Настройки", "Настройки будут применены при следующем запуске программы"
        )

    def show_help(self):
        help_text = """
        <html>
        <head>
            <style>
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    color: #e0e0e0;
                    background-color: #2d2d2d;
                    margin: 0;
                    padding: 20px;
                    line-height: 1.4;
                }
                h1 {
                    color: #4fc3f7;
                    text-align: center;
                    margin-top: 0;
                    margin-bottom: 20px;
                    font-size: 24px;
                }
                h2 {
                    color: #81c784;
                    margin-top: 20px;
                    margin-bottom: 10px;
                    font-size: 18px;
                    border-bottom: 1px solid #444;
                    padding-bottom: 5px;
                }
                h3 {
                    color: #4fc3f7;
                    margin-top: 15px;
                    margin-bottom: 8px;
                    font-size: 16px;
                }
                p {
                    margin: 8px 0;
                    text-align: justify;
                }
                ul, ol {
                    margin-top: 5px;
                    margin-bottom: 15px;
                    padding-left: 25px;
                }
                li {
                    margin-bottom: 5px;
                }
                .note {
                    background-color: #1e1e1e;
                    padding: 10px;
                    border-left: 3px solid #fcc419;
                    margin: 10px 0;
                }
                .warning {
                    background-color: #1e1e1e;
                    padding: 10px;
                    border-left: 3px solid #ff6b6b;
                    margin: 10px 0;
                }
                .tip {
                    background-color: #1e1e1e;
                    padding: 10px;
                    border-left: 3px solid #51cf66;
                    margin: 10px 0;
                }
                code {
                    font-family: 'Consolas', monospace;
                    background-color: #1e1e1e;
                    padding: 2px 4px;
                    border-radius: 3px;
                    color: #ce9178;
                }
                hr {
                    border-color: #444;
                    margin: 15px 0;
                }
            </style>
        </head>
        <body>
            <h1>PostgreSQL Query Plan Analyzer — Руководство пользователя</h1>

            <h2>1. Введение</h2>
            <p>PostgreSQL Query Plan Analyzer - это профессиональный инструмент для анализа и оптимизации планов выполнения SQL-запросов в базах данных PostgreSQL. Программа предназначена для разработчиков баз данных, администраторов и аналитиков, которые стремятся повысить производительность своих запросов и выявить узкие места в работе базы данных.</p>

            <div class="tip">
                <strong>Основная цель программы:</strong> Предоставить наглядную визуализацию планов запросов и выдать конкретные, практические рекомендации по их оптимизации.
            </div>

            <h2>2. Основные возможности</h2>
            <ul>
                <li><strong>Импорт и анализ планов PostgreSQL</strong> — загрузка выгрузки <code>EXPLAIN</code> из файла (XML или JSON) или получение плана при выполнении запроса через подключение к базе</li>
                <li><strong>Визуализация планов выполнения запросов</strong> - интерактивное графическое представление структуры запроса с возможностью клика по узлам</li>
                <li><strong>Выявление узких мест</strong> - автоматическое обнаружение дорогостоящих операций (Seq Scan, Nested Loop, сортировки на диске)</li>
                <li><strong>Рекомендации по оптимизации</strong> - создание индексов, изменение стратегий объединения, настройка параметров</li>
                <li><strong>Мониторинг активных запросов</strong> - отслеживание выполняющихся запросов в реальном времени</li>
                <li><strong>Журнал планов запросов</strong> - сохранение и сравнение планов для отслеживания изменений производительности</li>
                <li><strong>Анализ настроек PostgreSQL</strong> - проверка ключевых параметров сервера и рекомендации по их оптимизации</li>
                <li><strong>Управление индексами</strong> - поиск недостающих и неиспользуемых индексов</li>
                <li><strong>Работа со статистикой</strong> - проверка актуальности статистики таблиц и её обновление</li>
                <li><strong>Управление VACUUM</strong> - анализ необходимости вакуумирования и его выполнение</li>
                <li><strong>Тонкая настройка анализатора</strong> - гибкая настройка пороговых значений, цветов и параметров анализа</li>
            </ul>

            <h2>3. Начало работы</h2>
            <h3>3.1. Подключение к базе данных</h3>
            <p>Для работы с программой необходимо подключиться к базе данных PostgreSQL:</p>
            <ol>
                <li>Нажмите кнопку "Управление подключениями" на боковой панели или выберите "Файл -> Подключения -> Добавить подключение"</li>
                <li>Заполните параметры подключения: имя подключения, хост, порт, имя базы данных, пользователь, пароль</li>
                <li>Сохраните подключение и выберите его из выпадающего списка в нижней панели</li>
                <li>Нажмите кнопку "Подключиться" для установки соединения</li>
            </ol>

            <h3>3.2. Получение плана запроса</h3>
            <p>Существует несколько способов получить план запроса для анализа:</p>
            <ul>
                <li><strong>Выполнение запроса</strong> — введите SQL в нижней панели и нажмите «Выполнить». Программа выполнит <code>EXPLAIN (FORMAT JSON)</code> для этого запроса</li>
                <li><strong>Загрузка из файла</strong> — нажмите «Открыть план» на боковой панели и выберите файл с результатом <code>EXPLAIN</code> (<code>.xml</code> или <code>.json</code>)</li>
                <li><strong>Из журнала</strong> - откройте "Журнал планов" и дважды кликните по сохраненному плану</li>
                <li><strong>Из сканера запросов</strong> - во вкладке "Сканер запросов" дважды кликните по активному запросу для его анализа</li>
            </ul>

            <h2>4. Интерфейс программы</h2>
            <h3>4.1. Основные области</h3>
            <ul>
                <li><strong>Левая панель (вкладки):</strong>
                    <ul>
                        <li>Визуализация плана запроса - интерактивный граф выполнения запроса</li>
                        <li>Сканер запросов - мониторинг активных запросов в базе данных</li>
                        <li>Обслуживание БД - инструменты для работы с индексами, статистикой и VACUUM</li>
                    </ul>
                </li>
                <li><strong>Правая панель (вкладки):</strong>
                    <ul>
                        <li>Общий анализ - подробный разбор плана запроса с метриками и проблемами</li>
                        <li>Рекомендации - конкретные шаги по оптимизации запроса</li>
                        <li>Настройки PostgreSQL - параметры сервера и рекомендации по их настройке</li>
                    </ul>
                </li>
                <li><strong>Нижняя панель:</strong> выбор подключения, ввод SQL запроса, кнопки выполнения</li>
                <li><strong>Боковая панель (вертикальная):</strong> быстрый доступ к основным функциям</li>
            </ul>

            <h3>4.2. Визуализация плана запроса</h3>
            <p>Графическое представление плана запроса позволяет:</p>
            <ul>
                <li>Кликать по узлам графа для просмотра детальной информации об операции</li>
                <li>Изменять тип визуализации (стандартная или иерархическая)</li>
                <li>Видеть цветовую индикацию проблемных узлов (красный - высокая стоимость, оранжевый - Seq Scan)</li>
                <li>Просматривать стоимость и количество строк на узлах (настраивается)</li>
            </ul>

            <h2>5. Анализ плана запроса</h2>
            <h3>5.1. Основные метрики</h3>
            <p>Программа анализирует следующие ключевые метрики:</p>
            <ul>
                <li><strong>Общая стоимость плана</strong> - чем выше стоимость, тем дольше выполняется запрос</li>
                <li><strong>Стоимость отдельных операций</strong> - выявление самых дорогих операций в плане</li>
                <li><strong>Количество строк</strong> - ожидаемое количество строк на каждом этапе</li>
                <li><strong>Типы операций</strong> - Seq Scan, Index Scan, Nested Loop, Hash Join и другие</li>
            </ul>

            <h3>5.2. Выявляемые проблемы</h3>
            <ul>
                <li><strong>Последовательные сканирования (Seq Scan)</strong> - указывают на отсутствие подходящих индексов</li>
                <li><strong>Дорогостоящие Nested Loop</strong> - неэффективные соединения для больших таблиц</li>
                <li><strong>Внешние сортировки</strong> - нехватка памяти для сортировки (work_mem)</li>
                <li><strong>Высокая стоимость операций</strong> - операции, потребляющие более 15% общей стоимости</li>
            </ul>

            <h3>5.3. Рекомендации по оптимизации</h3>
            <p>На основе анализа программа выдает рекомендации:</p>
            <ul>
                <li><strong>Создание индексов</strong> - какие поля и какого типа индексы рекомендуется создать</li>
                <li><strong>Оптимизация JOIN</strong> - замена Nested Loop на Hash Join или Merge Join</li>
                <li><strong>Настройка параметров</strong> - увеличение work_mem, включение параллельного выполнения</li>
                <li><strong>Реструктуризация запроса</strong> - использование EXISTS вместо JOIN DISTINCT, оптимизация WHERE условий</li>
            </ul>

            <h2>6. Мониторинг активных запросов</h2>
            <h3>6.1. Возможности мониторинга</h3>
            <ul>
                <li><strong>Реальное время</strong> - автоматическое обновление списка активных запросов</li>
                <li><strong>Фильтрация</strong> - по состоянию (активные, ожидающие, заблокированные), пользователю, приложению, тексту запроса</li>
                <li><strong>Детальная информация</strong> - PID, пользователь, приложение, клиент, длительность, состояние, событие ожидания</li>
                <li><strong>Подсветка проблем</strong> - длительные запросы, заблокированные процессы, idle in transaction</li>
            </ul>

            <h3>6.2. Действия с запросами</h3>
            <ul>
                <li><strong>Анализ запроса</strong> - дважды кликните по запросу для получения и анализа его плана</li>
                <li><strong>Завершение процесса</strong> - принудительное завершение выбранного процесса (pg_terminate_backend)</li>
                <li><strong>Копирование запроса</strong> - копирование текста SQL запроса в буфер обмена</li>
            </ul>

            <div class="warning">
                <strong>Внимание:</strong> Завершение процессов может привести к откату транзакций и потере данных. Используйте с осторожностью.
            </div>

            <h2>7. Оптимизация базы данных</h2>
            <h3>7.1. Управление индексами</h3>
            <ul>
                <li><strong>Поиск недостающих индексов</strong> - анализ таблиц с частыми последовательными сканированиями</li>
                <li><strong>Анализ использования индексов</strong> - выявление неиспользуемых и редко используемых индексов</li>
                <li><strong>Рекомендации по индексам</strong> - конкретные предложения по созданию или удалению индексов</li>
            </ul>

            <h3>7.2. Работа со статистикой</h3>
            <ul>
                <li><strong>Проверка устаревшей статистики</strong> - выявление таблиц, требующих обновления статистики</li>
                <li><strong>Обновление статистики (ANALYZE)</strong> - обновление статистики для всех таблиц или выбранной таблицы</li>
            </ul>

            <div class="tip">
                <strong>Совет:</strong> Регулярно обновляйте статистику таблиц, особенно после массовых изменений данных (INSERT/UPDATE/DELETE). Это помогает оптимизатору PostgreSQL строить более точные планы запросов.
            </div>

            <h3>7.3. Вакуумирование (VACUUM)</h3>
            <ul>
                <li><strong>Анализ необходимости VACUUM</strong> - проверка процента мертвых строк в таблицах</li>
                <li><strong>Выполнение VACUUM</strong> - очистка мертвых строк и обновление статистики</li>
            </ul>

            <div class="warning">
                <strong>Предупреждение:</strong> VACUUM создает дополнительную нагрузку на базу данных. Рекомендуется выполнять в периоды низкой активности.
            </div>

            <h2>8. Настройка PostgreSQL</h2>
            <h3>8.1. Ключевые параметры</h3>
            <p>Программа анализирует следующие важные параметры PostgreSQL:</p>
            <ul>
                <li><strong>shared_buffers</strong> - общая память для кэширования данных (рекомендуется 25% от RAM)</li>
                <li><strong>work_mem</strong> - память для сортировок и хеш-таблиц</li>
                <li><strong>maintenance_work_mem</strong> - память для обслуживания (создание индексов, VACUUM)</li>
                <li><strong>effective_cache_size</strong> - оценка размера кэша ОС (рекомендуется 50-75% от RAM)</li>
                <li><strong>random_page_cost</strong> - стоимость случайного чтения (1.1 для SSD, 4 для HDD)</li>
                <li><strong>max_connections</strong> - максимальное количество подключений</li>
                <li><strong>max_parallel_workers_per_gather</strong> - количество параллельных рабочих процессов</li>
            </ul>

            <h3>8.2. Просмотр всех параметров</h3>
            <p>Нажмите кнопку "Все параметры" для просмотра полного списка настроек PostgreSQL с возможностью поиска и фильтрации по категориям.</p>

            <h2>9. Журнал планов запросов</h2>
            <h3>9.1. Сохранение планов</h3>
            <p>Все проанализированные планы автоматически сохраняются в журнал (если включено в настройках). Для каждого плана сохраняется:</p>
            <ul>
                <li>текст плана запроса (XML или JSON)</li>
                <li>Текст SQL запроса</li>
                <li>Временная метка</li>
                <li>Источник (файл или ручной запрос)</li>
                <li>Тип операции и стоимость</li>
            </ul>

            <h3>9.2. Группировка запросов</h3>
            <p>Похожие запросы автоматически группируются (после нормализации). Для групп с несколькими версиями доступны:</p>
            <ul>
                <li><strong>Графики производительности</strong> - визуализация изменения стоимости, количества строк и других метрик во времени</li>
                <li><strong>Сравнение версий</strong> - детальное сравнение двух версий одного запроса</li>
                <li><strong>Тренды</strong> - отображение улучшения или ухудшения производительности</li>
            </ul>

            <h3>9.3. Работа с журналом</h3>
            <ul>
                <li><strong>Поиск</strong> - по названию, описанию или тексту запроса</li>
                <li><strong>Сортировка</strong> - по дате, названию, стоимости, группе</li>
                <li><strong>Редактирование</strong> - изменение названия и описания записи</li>
                <li><strong>Удаление</strong> - удаление отдельных записей или очистка всего журнала</li>
                <li><strong>Добавление заметок</strong> — создание ручных записей с произвольным SQL и текстом плана (XML или JSON)</li>
            </ul>

            <h2>10. Настройка анализатора</h2>
            <p>Для тонкой настройки поведения анализатора нажмите кнопку "Настройки анализатора" на боковой панели. Доступны следующие группы настроек:</p>

            <h3>10.1. Пороговые значения</h3>
            <ul>
                <li>Высокая стоимость (абсолютная и процентная)</li>
                <li>Предупреждение Seq Scan при стоимости выше</li>
                <li>Предупреждение Nested Loop при стоимости выше</li>
                <li>Критическая операция (процент от общей стоимости)</li>
                <li>Долгий запрос (длительность в секундах)</li>
                <li>Мертвые строки для VACUUM (процент)</li>
                <li>Изменения после анализа (предупреждение и критично)</li>
            </ul>

            <h3>10.2. Визуализация</h3>
            <ul>
                <li>Максимум отображаемых узлов</li>
                <li>Множитель размера узла</li>
                <li>Включение анимаций</li>
                <li>Отображение стоимости на узлах</li>
                <li>Отображение количества строк на узлах</li>
                <li>Тип раскладки (стандартная или иерархическая)</li>
            </ul>

            <h3>10.3. Анализ</h3>
            <ul>
                <li>Включение/выключение рекомендаций по индексам, JOIN, VACUUM, параллелизму</li>
                <li>Максимум полей в индексе</li>
                <li>Минимальный размер таблицы для рекомендации индекса (MB)</li>
                <li>Глубина рекурсивного анализа</li>
            </ul>

            <h3>10.4. Цвета</h3>
            <p>Настройка цветовой схемы для различных типов узлов и сообщений (высокая стоимость, Seq Scan, Index Scan, предупреждения, ошибки, рекомендации).</p>

            <h3>10.5. Мониторинг</h3>
            <ul>
                <li>Интервал сканирования активных запросов (секунды)</li>
                <li>Максимум отображаемых запросов</li>
                <li>Автоматическое обновление</li>
                <li>Подсветка заблокированных запросов</li>
            </ul>

            <h3>10.6. Журнал</h3>
            <ul>
                <li>Максимум записей в журнале</li>
                <li>Автоматическое сохранение планов</li>
                <li>Сохранение результатов анализа</li>
                <li>Включение нормализации запросов для группировки</li>
                <li>Подсветка похожих запросов</li>
                <li>Максимум групп запросов</li>
            </ul>

            <h2>11. Экспорт результатов</h2>
            <p>Результаты анализа можно экспортировать в формате Markdown (файл .md). Для этого нажмите кнопку "Экспорт" на боковой панели. Экспортируемый файл содержит:</p>
            <ul>
                <li>Общий анализ плана запроса</li>
                <li>Рекомендации по оптимизации</li>
                <li>Рекомендации по настройке PostgreSQL</li>
            </ul>

            <h2>12. Горячие клавиши</h2>
            <ul>
                <li><strong>Ctrl+O</strong> — открыть файл с планом запроса (XML или JSON)</li>
                <li><strong>Ctrl+E</strong> - Экспорт результатов анализа</li>
                <li><strong>F1</strong> - Открыть справочную документацию</li>
            </ul>

            <h2>13. Устранение неполадок</h2>
            <h3>13.1. Ошибка подключения к базе данных</h3>
            <ul>
                <li>Проверьте правильность введенных параметров подключения (хост, порт, имя БД, пользователь, пароль)</li>
                <li>Убедитесь, что сервер PostgreSQL запущен и доступен по сети</li>
                <li>Проверьте, что в файле pg_hba.conf разрешено подключение с вашего IP-адреса</li>
            </ul>

            <h3>13.2. Ошибка при выполнении EXPLAIN</h3>
            <ul>
                <li>Проверьте синтаксис SQL запроса</li>
                <li>Убедитесь, что у пользователя есть права на выполнение EXPLAIN</li>
                <li>Для запросов, не поддерживающих EXPLAIN (BEGIN, COMMIT), используйте загрузку из файла</li>
            </ul>

            <h3>13.3. Проблемы с визуализацией</h3>
            <ul>
                <li>Убедитесь, что файл содержит корректный вывод <code>EXPLAIN</code> PostgreSQL (XML или JSON)</li>
                <li>При очень больших планах может потребоваться увеличить лимит отображаемых узлов в настройках</li>
                <li>Попробуйте переключить тип визуализации (стандартная/иерархическая)</li>
            </ul>

            <div class="note">
                <strong>Примечание:</strong> Если проблема сохраняется, проверьте файл application.log в директории программы для получения подробной информации об ошибке.
            </div>

            <h2>14. Рекомендации по оптимизации запросов</h2>
            <h3>14.1. Общие принципы</h3>
            <ul>
                <li>Используйте индексы на полях, участвующих в WHERE, JOIN, ORDER BY</li>
                <li>Избегайте функций в WHERE условиях - они отключают использование индексов</li>
                <li>Предпочитайте EXISTS вместо IN для подзапросов</li>
                <li>Используйте LIMIT для ограничения количества возвращаемых строк</li>
                <li>Разбивайте сложные запросы на несколько простых с использованием CTE (WITH)</li>
            </ul>

            <h3>14.2. Оптимизация JOIN</h3>
            <ul>
                <li>Для маленьких таблиц подходит Nested Loop</li>
                <li>Для больших таблиц используйте Hash Join или Merge Join</li>
                <li>Убедитесь, что для полей соединения есть индексы</li>
                <li>Используйте EXPLAIN ANALYZE для проверки реального количества строк</li>
            </ul>

            <h3>14.3. Настройка параметров для конкретных запросов</h3>
            <ul>
                <li><strong>SET work_mem = '64MB'</strong> - для сложных сортировок и хеш-соединений</li>
                <li><strong>SET enable_nestloop = off</strong> - для отключения Nested Loop (временное решение)</li>
                <li><strong>SET max_parallel_workers_per_gather = 4</strong> - для включения параллельного выполнения</li>
            </ul>

            <div class="tip">
                <strong>Финальный совет:</strong> Регулярно анализируйте планы запросов, особенно после изменений в структуре базы данных или обновления версии PostgreSQL. Это поможет своевременно выявлять и устранять проблемы производительности.
            </div>

            <hr>

            <p style="text-align: center; color: #81c784; margin-top: 20px;">
                PostgreSQL Query Plan Analyzer - Версия 0.170<br>
                Инструмент для профессионального анализа и оптимизации запросов PostgreSQL
            </p>
        </body>
        </html>
        """

        help_dialog = QDialog(self)
        help_dialog.setWindowTitle("Справка - PostgreSQL Query Plan Analyzer")
        help_dialog.setMinimumSize(900, 700)

        layout = QVBoxLayout(help_dialog)
        help_browser = QTextBrowser()
        help_browser.setHtml(help_text)
        help_browser.setOpenExternalLinks(True)
        help_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: none;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }
        """)
        layout.addWidget(help_browser)

        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(help_dialog.accept)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #3a7bd5;
                color: white;
                border: 1px solid #2a5ba5;
                border-radius: 4px;
                padding: 8px 20px;
                font-size: 12px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #4a8be5;
            }
        """)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        button_layout.addStretch()

        layout.addLayout(button_layout)
        help_dialog.setLayout(layout)
        help_dialog.exec_()

    def create_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("Файл")

        open_action = QAction("Открыть план...", self)
        open_action.triggered.connect(self.open_xml_file)
        file_menu.addAction(open_action)

        connections_menu = file_menu.addMenu("Подключения")

        add_connection_action = QAction("Добавить подключение...", self)
        add_connection_action.triggered.connect(self.show_add_connection_dialog)
        connections_menu.addAction(add_connection_action)

        manage_connections_action = QAction("Управление подключениями...", self)
        manage_connections_action.triggered.connect(self.show_manage_connections_dialog)
        connections_menu.addAction(manage_connections_action)

        exit_action = QAction("Выход", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        settings_menu = menubar.addMenu("Настройки")
        analyzer_settings_action = QAction("Настройки анализатора...", self)
        analyzer_settings_action.triggered.connect(self.show_analyzer_settings)
        settings_menu.addAction(analyzer_settings_action)

        help_menu = menubar.addMenu("Справка")
        about_action = QAction("О программе", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_toolbar(self):
        bottom_toolbar = QToolBar("Bottom Toolbar")
        bottom_toolbar.setOrientation(Qt.Horizontal)
        bottom_toolbar.setAllowedAreas(Qt.BottomToolBarArea)
        bottom_toolbar.setFloatable(False)

        bottom_toolbar.setFixedHeight(40)

        connection_container = QWidget()
        connection_layout = QHBoxLayout(connection_container)
        connection_layout.setContentsMargins(0, 0, 0, 0)

        self.connection_combo = QComboBox()
        self.connection_combo.setMinimumWidth(150)
        self.connection_combo.setStyleSheet("""
            QComboBox {
                font-size: 12px;
                background-color: #333;
                color: #ccc;
                border: 1px solid #555;
                padding: 5px;
                border-radius: 3px;
            }
        """)
        self.connection_combo.currentIndexChanged.connect(self.on_connection_changed)

        self.connect_button = QPushButton(icon("fa5s.database", color="white"), "Подключиться")
        self.connect_button.clicked.connect(self.on_connect_button_clicked)
        self.connect_button.setStyleSheet("""
            QPushButton {
                font-size: 12px;
                background-color: #3a7bd5;
                color: #fff;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #4a8be5;
            }
        """)

        connection_layout.addWidget(QLabel("Подключение:"))
        connection_layout.addWidget(self.connection_combo)
        connection_layout.addWidget(self.connect_button)

        self.plan_query_container = QWidget()
        self.plan_query_container.setFixedHeight(34)
        self.plan_query_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.plan_query_container.setStyleSheet("""
            QWidget#planQueryContainer {
                background-color: #252525;
                border: 1px solid #444;
                border-radius: 4px;
            }
            QLabel#planQueryTitle {
                color: #b3e5fc;
                font-size: 11px;
                font-weight: bold;
            }
        """)
        self.plan_query_container.setObjectName("planQueryContainer")
        query_layout = QHBoxLayout(self.plan_query_container)
        query_layout.setContentsMargins(6, 3, 6, 3)
        query_layout.setSpacing(6)

        query_title = QLabel("SQL:")
        query_title.setObjectName("planQueryTitle")

        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("Введите SQL запрос...")
        self.query_input.setMinimumWidth(260)
        self.query_input.setFixedHeight(24)
        self.query_input.mouseDoubleClickEvent = self.show_sql_editor
        self.query_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 4px;
                font-size: 12px;
            }
        """)

        self.open_plan_button = QPushButton(icon("fa5s.folder-open", color="white"), "Открыть план")
        self.open_plan_button.setFixedHeight(24)
        self.open_plan_button.clicked.connect(self.open_and_analyze_plan)
        self.open_plan_button.setStyleSheet("""
            QPushButton {
                font-size: 12px;
                background-color: #3a7bd5;
                color: #fff;
                border: none;
                padding: 4px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #4a8be5;
            }
        """)

        self.execute_button = QPushButton(icon("fa5s.play", color="white"), "Выполнить")
        self.execute_button.setFixedHeight(24)
        self.execute_button.clicked.connect(self.execute_query)
        self.execute_button.setStyleSheet("""
            QPushButton {
                font-size: 12px;
                background-color: #4CAF50;
                color: white;
                border: 1px solid #3e8e41;
                border-radius: 3px;
                padding: 4px 12px;
            }
            QPushButton:hover {
                background-color: #5CBF60;
            }
        """)

        self.progress_bar.setFixedWidth(110)
        self.progress_bar.setFixedHeight(18)
        query_layout.addWidget(query_title)
        query_layout.addWidget(self.query_input, 1)
        query_layout.addWidget(self.open_plan_button)
        query_layout.addWidget(self.execute_button)
        query_layout.addWidget(self.progress_bar)

        bottom_toolbar.addWidget(connection_container)

        self.addToolBar(Qt.BottomToolBarArea, bottom_toolbar)

        if hasattr(self, "visualizer_layout"):
            self.visualizer_layout.addWidget(self.plan_query_container, 0)

    def show_sql_editor(self, event):
        dialog = SQLEditorDialog(self, self.query_input.text())
        if dialog.exec_() == QDialog.Accepted:
            self.query_input.setText(dialog.get_sql_text())

    def load_connections(self):
        try:
            connections = StoredConnectionSettings.load_connections()
            self.connection_combo.clear()

            if not connections:
                logging.warning("No connections found in settings")
                return

            valid_connections = 0
            for name, conn in connections.items():
                if not all(k in conn for k in ["host", "port", "dbname", "user", "password"]):
                    logging.warning(f"Skipping invalid connection: {name}")
                    continue

                self.connection_combo.addItem(name, conn)
                valid_connections += 1

            if valid_connections > 0:
                self.connection_combo.setCurrentIndex(0)
                self.current_connection = self.connection_combo.itemData(0)
                logging.info(f"Loaded {valid_connections} connection(s)")
            else:
                logging.warning("No valid connections found")

        except Exception as e:
            logging.error(f"Error loading connections: {e}")
            QMessageBox.warning(
                self,
                "Ошибка",
                "Не удалось загрузить подключения.\n" "Проверьте файл настроек подключений.",
            )

    def show_add_connection_dialog(self):
        dialog = ConnectionDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            conn_data = dialog.get_connection_data()
            if not conn_data["name"]:
                conn_data["name"] = f"Подключение_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            StoredConnectionSettings.add_connection(
                conn_data["name"],
                conn_data["host"],
                conn_data["port"],
                conn_data["dbname"],
                conn_data["user"],
                conn_data["password"],
            )
            self.load_connections()

    def show_manage_connections_dialog(self):
        dialog = ConnectionDialog(self)
        dialog.exec_()

    def on_connection_changed(self, index):
        if index >= 0:
            self.current_connection = self.connection_combo.itemData(index)
            self._reset_ssh_hardware_snapshot()
            if hasattr(self, "query_analyzer_tab") and self.query_analyzer_tab.query_scanner:
                self.query_analyzer_tab.query_scanner.connection_params = (
                    StoredConnectionSettings.connect_kwargs(self.current_connection)
                )
                self.query_analyzer_tab.query_scanner.analyzer_settings = self.analyzer_settings
        else:
            self.current_connection = None
            self._reset_ssh_hardware_snapshot()

    def connect_to_database(self):
        # Обновляем профиль из диска по имени, чтобы не использовать устаревший itemData.
        selected_name = (
            self.connection_combo.currentText().strip() if hasattr(self, "connection_combo") else ""
        )
        if selected_name:
            fresh_map = StoredConnectionSettings.load_connections()
            fresh_conn = fresh_map.get(selected_name)
            if fresh_conn:
                self.current_connection = fresh_conn

        if not self.current_connection:
            QMessageBox.warning(self, "Ошибка", "Не выбрано подключение")
            return

        kw = StoredConnectionSettings.connect_kwargs(self.current_connection)
        tcp_diag = ""
        ssl_diag = ""
        db_diag = ""
        last_err: Optional[OperationalError] = None
        had_empty_args_operational = False

        try:
            self.conn = psycopg2.connect(**kw)
        except OperationalError as e:
            last_err = e
            if not getattr(e, "args", ()):
                had_empty_args_operational = True
                tcp_diag = tcp_reachability_message(str(kw["host"]), int(kw["port"]))
                logging.exception(
                    "Подключение: OperationalError без текста при connect(**kwargs); повтор по libpq URI"
                )
                try:
                    self.conn = psycopg2.connect(
                        StoredConnectionSettings.connection_uri(self.current_connection)
                    )
                    last_err = None
                except OperationalError as e2:
                    last_err = e2
                    ssl_diag = diagnose_empty_operational_error(self.current_connection)
        except Exception as e:
            self.connection_status = False
            detail = format_psycopg_connect_error(e)
            logging.exception("Connection failed (не OperationalError): %s", detail)
            QMessageBox.critical(
                self,
                "Ошибка подключения",
                "Не удалось подключиться (неожиданная ошибка).\n\n"
                f"{detail}\n\n"
                "Если проблема повторяется, пришлите этот текст и фрагмент application.log.",
            )
            return

        if last_err is None:
            self.connection_status = True
            self.connect_button.setText("Отключиться")
            self.connect_button.setStyleSheet("""
                QPushButton {
                    background-color: #ff6b6b;
                    color: white;
                    border: 1px solid #e74c3c;
                    border-radius: 4px;
                    padding: 5px 15px;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background-color: #e74c3c;
                }
            """)

            self.update_databases()
            self.load_postgres_settings()
            return

        self.connection_status = False
        detail = format_psycopg_connect_error(last_err)
        conn_target = (
            f"Профиль: host={kw.get('host')} port={kw.get('port')} "
            f"dbname={kw.get('dbname')} user={kw.get('user')}"
        )
        detail = conn_target + "\n" + detail
        if tcp_diag:
            detail += "\n\n" + tcp_diag
        if ssl_diag:
            detail += "\n\n" + ssl_diag
        if had_empty_args_operational:
            db_diag = diagnose_database_name_empty_operational(self.current_connection, kw)
            if db_diag:
                detail += "\n\n" + db_diag
        logging.error("Connection failed: %s", detail)
        err_low = detail.lower()
        pwd = self.current_connection.get("password") or ""
        hints = ""
        if not str(pwd).strip():
            hints += (
                "\n\nПароль в профиле пустой. Пароли хранятся в системной связке ключей (keyring): "
                "откройте «Подключения» → выберите запись → «Изменить» и снова введите пароль."
            )
        if "authentication failed" in err_low:
            hints += (
                "\n\nПроверьте имя пользователя и пароль на сервере. "
                "Если пароль меняли, введите новый в диалоге изменения подключения."
            )
        if "timed out" in err_low or "timeout" in err_low:
            hints += "\n\nТайм-аут: проверьте сеть/VPN, firewall и что PostgreSQL слушает нужный адрес (listen_addresses / pg_hba)."
        if "ssl" in err_low or "encryption" in err_low:
            hints += (
                '\n\nПопробуйте в профиле подключения в JSON добавить "sslmode": "require" или "disable" '
                'и "gssencmode": "disable" (часто нужно на macOS/libpq).'
            )

        QMessageBox.critical(
            self,
            "Ошибка подключения",
            f"Не удалось подключиться:\n{detail}{hints}",
        )

    def disconnect_from_database(self):
        if hasattr(self, "conn") and self.conn and not self.conn.closed:
            try:
                self.conn.close()
                self.connection_status = False
                logging.info("Отключение от базы данных выполнено.")

                if hasattr(self, "query_scanner") and self.query_scanner:
                    self.query_scanner.stop_scanning()

                self.connect_button.setText("Подключиться")
                self.connect_button.setStyleSheet("""
                    QPushButton {
                        background-color: #3a7bd5;
                        color: white;
                        border: 1px solid #2a5ba5;
                        border-radius: 4px;
                        padding: 5px 15px;
                        font-size: 12px;
                    }
                    QPushButton:hover {
                        background-color: #4a8be5;
                    }
                """)

            except Exception as e:
                logging.error(f"Ошибка при отключении: {e}")
                QMessageBox.critical(self, "Ошибка", f"Не удалось отключиться:\n{str(e)}")

    def execute_query(self):
        if not self.connection_status or not hasattr(self, "conn"):
            QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
            return

        query = self.query_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Ошибка", "Введите SQL запрос")
            return

        self.show_animated_message(["Запрос выполняется. Ожидайте результат..."])

        self.last_opened_file = None
        self._pending_journal_plan_origin = "explain"

        self.progress_bar.show()
        self.progress_animation.start()
        self.execute_button.setEnabled(False)
        self.query_input.setEnabled(False)
        self.execute_button.setText("Выполняется...")
        self.execute_button.setStyleSheet("""
            QPushButton {
                background-color: #FFA500;
                color: white;
                border: 1px solid #E69500;
                border-radius: 4px;
                padding: 5px 15px;
                font-size: 12px;
            }
        """)

        self.clear_analysis_for_new_plan()
        self._pending_journal_queryid = None

        connection_params = StoredConnectionSettings.connect_kwargs(self.current_connection)

        self.query_thread = CallableWorkerThread(
            functools.partial(self._sync_explain_worker, query, connection_params),
            self,
        )
        self.query_thread.completed.connect(self._on_explain_worker_done)
        self.query_thread.start()

    def _sync_explain_worker(
        self, query: str, connection_params: dict
    ) -> tuple[Any, Optional[str]]:
        """Separate connection in QThread-friendly worker callable."""
        with psycopg2.connect(**connection_params) as conn:
            conn.autocommit = True
            with conn.cursor() as cursor:
                explain_query = explain_format_json_sql(query)
                cursor.execute(explain_query)
                result = cursor.fetchone()[0]
                pending_journal_queryid: Optional[str] = None
                try:
                    pending_journal_queryid = lookup_queryid_for_executed_statement(
                        cursor, explain_query
                    )
                except Exception:
                    logging.debug(
                        "Не удалось получить statement_queryid из pg_stat_statements",
                        exc_info=True,
                    )
                    pending_journal_queryid = None
        return result, pending_journal_queryid

    def _on_explain_worker_done(self, ok: bool, payload: Any) -> None:
        """Bridge CallableWorkerThread to existing query_finished / _on_query_completed flow."""
        if ok:
            res, jid = payload
            self.query_result = res
            self._pending_journal_queryid = jid
        else:
            self.query_result = f"Ошибка выполнения запроса: {payload}"
            self._pending_journal_queryid = None
        self.query_finished.emit(True)

    def _on_query_completed(self):
        self.progress_bar.hide()
        self.progress_animation.stop()
        self.execute_button.setEnabled(True)
        self.query_input.setEnabled(True)
        self.execute_button.setText("Выполнить")
        self.execute_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: 1px solid #3e8e41;
                border-radius: 4px;
                padding: 5px 15px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #5CBF60;
            }
            QPushButton:pressed {
                background-color: #3A9F3E;
            }
        """)

        if isinstance(self.query_result, str):
            stripped = self.query_result.strip()
            if stripped.startswith("<?xml") or stripped.startswith("<explain"):
                self.xml_content = self.query_result
                QTimer.singleShot(0, self.analyze_query_plan)
            elif stripped.startswith("[") or stripped.startswith("{"):
                try:
                    json.loads(stripped)
                except json.JSONDecodeError:
                    QMessageBox.warning(
                        self, "Ошибка", "Не удалось получить план выполнения запроса"
                    )
                else:
                    self.xml_content = self.query_result
                    QTimer.singleShot(0, self.analyze_query_plan)
            elif stripped.startswith("Ошибка"):
                QMessageBox.critical(self, "Ошибка", self.query_result)
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось получить план выполнения запроса")

        self.query_thread = None

    def show_about(self):
        about_text = """
        <html>
        <head>
            <style>
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    color: #e0e0e0;
                    background-color: #2d2d2d;
                    margin: 0;
                    padding: 20px;
                    line-height: 1.4;
                    font-size: 13px;
                }
                h1 {
                    color: #4fc3f7;
                    margin-top: 0px;
                    margin-bottom: 5px;
                    font-size: 22px;
                }
                h2 {
                    color: #81c784;
                    margin-top: 15px;
                    margin-bottom: 8px;
                    border-bottom: 1px solid #444;
                    padding-bottom: 3px;
                    font-size: 16px;
                }
                h3 {
                    color: #4fc3f7;
                    margin-top: 10px;
                    margin-bottom: 5px;
                    font-size: 14px;
                }
                ul {
                    margin-top: 5px;
                    margin-bottom: 10px;
                    padding-left: 20px;
                }
                li {
                    margin-bottom: 4px;
                }
                .version {
                    color: #fcc419;
                    font-size: 12px;
                    margin-bottom: 15px;
                }
                .note {
                    color: #888;
                    font-size: 11px;
                    margin-top: 10px;
                    font-style: italic;
                }
                .feature-list {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 5px 15px;
                    margin-top: 5px;
                    margin-bottom: 10px;
                }
                .feature-item {
                    margin-bottom: 3px;
                }
            </style>
        </head>
        <body>
            <h1>VITACORE</h1>
            <h1>PostgreSQL Query Plan Analyzer</h1>
            <div class="version">Версия 0.380</div>

            <h2>Визуализация плана запроса</h2>
            <ul>
                <li>Интерактивный граф выполнения запроса с возможностью клика по узлам</li>
                <li>Цветовая индикация проблемных операций (красный - высокая стоимость, оранжевый - Seq Scan)</li>
                <li>Переключение между стандартной и иерархической раскладкой</li>
                <li>Отображение стоимости и количества строк на узлах (настраивается)</li>
                <li>Масштабирование и перетаскивание узлов мышью</li>
                <li>Подсветка выбранного узла и отображение деталей в правой панели</li>
            </ul>

            <h2>Анализ плана запроса</h2>
            <ul>
                <li>Расчет общей стоимости и процентного соотношения операций</li>
                <li>Выявление операций, потребляющих более 15% общей стоимости</li>
                <li>Обнаружение последовательных сканирований (Seq Scan)</li>
                <li>Поиск дорогостоящих Nested Loop операций</li>
                <li>Анализ использования индексов (Index Scan, Index Only Scan)</li>
                <li>Обнаружение внешних сортировок (Sort-Method: external)</li>
                <li>Выявление таблиц с устаревшей статистикой</li>
                <li>Поиск таблиц с большим количеством мертвых строк</li>
            </ul>

            <h2>Рекомендации по индексам</h2>
            <ul>
                <li>Извлечение полей из условий WHERE (равенство, диапазоны, LIKE, IN, BETWEEN)</li>
                <li>Извлечение полей из JOIN условий</li>
                <li>Учет полей из ORDER BY при формировании индекса</li>
                <li>Определение типа индекса: BTREE для равенства и диапазонов</li>
                <li>Определение типа индекса: GIN с pg_trgm для LIKE '%text%'</li>
                <li>Определение типа индекса: BTREE с varchar_pattern_ops для LIKE 'text%'</li>
                <li>Формирование составных индексов с правильным порядком полей</li>
                <li>Приоритет полей: равенство → JOIN → IN → BETWEEN → диапазоны → LIKE → ORDER BY</li>
                <li>Генерация готового SQL для создания индекса с CONCURRENTLY</li>
                <li>Рекомендация выполнить ANALYZE после создания индекса</li>
            </ul>

            <h2>Мониторинг активных запросов</h2>
            <ul>
                <li>Автоматическое обновление списка активных запросов с настраиваемым интервалом</li>
                <li>Отображение PID, пользователя, приложения, клиента, длительности</li>
                <li>Отображение состояния запроса (active, idle, idle in transaction)</li>
                <li>Отображение событий ожидания (wait_event_type, wait_event)</li>
                <li>Фильтрация по состоянию (активные, ожидающие, заблокированные)</li>
                <li>Фильтрация по тексту запроса</li>
                <li>Фильтрация по приложению, пользователю, клиенту</li>
                <li>Подсветка длительных запросов (более заданного порога)</li>
                <li>Подсветка заблокированных процессов и idle in transaction</li>
                <li>Двойной клик для анализа плана выбранного запроса</li>
                <li>Завершение процесса через pg_terminate_backend</li>
                <li>Копирование текста запроса в буфер обмена</li>
            </ul>

            <h2>Журнал планов запросов</h2>
            <ul>
                <li>Автоматическое сохранение всех проанализированных планов</li>
                <li>Ручное добавление заметок с произвольным SQL и текстом плана (XML или JSON)</li>
                <li>Нормализация запросов для группировки похожих запросов</li>
                <li>Группировка по нормализованному тексту запроса</li>
                <li>Отображение тренда производительности между версиями</li>
                <li>Сравнение двух версий одного запроса (стоимость, строки, операции)</li>
                <li>Графики производительности: стоимость, строки, время, Seq Scan операции</li>
                <li>Типы графиков: линейный, столбчатый, точечный</li>
                <li>Экспорт графиков в PNG</li>
                <li>Поиск по названию, описанию, тексту запроса</li>
                <li>Сортировка по дате, названию, стоимости, группе</li>
                <li>Редактирование названия и описания записи</li>
                <li>Удаление отдельных записей или очистка всего журнала</li>
                <li>Загрузка плана из журнала для повторного анализа</li>
            </ul>

            <h2>Оптимизация базы данных</h2>
            <ul>
                <li>Поиск таблиц с потенциально недостающими индексами</li>
                <li>Анализ использования существующих индексов (pg_stat_user_indexes)</li>
                <li>Выявление неиспользуемых и редко используемых индексов</li>
                <li>Рекомендация по удалению неиспользуемых индексов</li>
                <li>Отображение размера индексов</li>
                <li>Проверка устаревшей статистики таблиц (n_mod_since_analyze)</li>
                <li>Пороги предупреждения: >10000 изменений - рекомендуется ANALYZE</li>
                <li>Пороги критичности: >100000 изменений - срочно требуется ANALYZE</li>
                <li>Выполнение ANALYZE для всех таблиц или выбранной таблицы</li>
                <li>Проверка последнего VACUUM и процента мертвых строк</li>
                <li>Порог для VACUUM: >20% мертвых строк - требуется VACUUM</li>
                <li>Выполнение VACUUM для выбранной схемы</li>
                <li>Выбор базы данных и схемы для анализа</li>
            </ul>

            <h2>Настройки PostgreSQL</h2>
            <ul>
                <li>Отображение информации о сервере (версия, время работы, файл конфигурации)</li>
                <li>Просмотр ключевых параметров: shared_buffers, work_mem, maintenance_work_mem</li>
                <li>Просмотр параметров: effective_cache_size, random_page_cost, max_connections</li>
                <li>Просмотр параметров: max_worker_processes, max_parallel_workers_per_gather, wal_buffers</li>
                <li>Сравнение текущих значений с рекомендуемыми</li>
                <li>Проверка нахождения параметров в допустимом диапазоне</li>
                <li>Просмотр всех параметров PostgreSQL с фильтрацией по категориям</li>
                <li>Категории параметров: память, соединения, производительность, WAL, репликация, параллельные запросы, статистика</li>
                <li>Поиск параметров по имени и описанию</li>
                <li>Отображение единиц измерения, диапазона значений и описания</li>
                <li>Цветовая индикация статуса параметра (OK, проверьте, за пределами диапазона)</li>
            </ul>

            <h2>Управление подключениями</h2>
            <ul>
                <li>Сохранение нескольких подключений к разным серверам</li>
                <li>Хранение параметров: имя, хост, порт, база данных, пользователь, пароль</li>
                <li>Шифрование паролей при сохранении</li>
                <li>Добавление, редактирование, удаление подключений</li>
                <li>Проверка подключения перед использованием</li>
                <li>Автоматическое переподключение при обрыве связи</li>
                <li>Выбор активного подключения из выпадающего списка</li>
            </ul>

            <h2>Настройки анализатора</h2>
            <ul>
                <li>Пороговые значения: высокая стоимость (абсолютная и процентная)</li>
                <li>Порог предупреждения Seq Scan и Nested Loop</li>
                <li>Порог критической операции (процент от общей стоимости)</li>
                <li>Порог длительного запроса в секундах</li>
                <li>Порог мертвых строк для VACUUM (процент)</li>
                <li>Пороги изменений после анализа (предупреждение и критично)</li>
                <li>Настройки визуализации: максимальное количество узлов, размер узлов, анимации</li>
                <li>Отображение стоимости и количества строк на узлах</li>
                <li>Настройка цветов: высокая стоимость, Seq Scan, Index Scan</li>
                <li>Настройка цветов текста: предупреждения, ошибки, рекомендации</li>
                <li>Включение/отключение рекомендаций по индексам, JOIN, VACUUM, параллелизму</li>
                <li>Максимальное количество полей в индексе</li>
                <li>Минимальный размер таблицы для рекомендации индекса (МБ)</li>
                <li>Глубина рекурсивного анализа</li>
                <li>Настройки мониторинга: интервал сканирования, максимальное количество запросов</li>
                <li>Автоматическое обновление и подсветка заблокированных запросов</li>
                <li>Настройки журнала: максимальное количество записей, автосохранение планов</li>
                <li>Включение нормализации запросов для группировки</li>
                <li>Подсветка похожих запросов, максимальное количество групп</li>
            </ul>

            <h2>Экспорт и импорт</h2>
            <ul>
                <li>Экспорт результатов анализа в Markdown (.md)</li>
                <li>Экспорт графиков производительности в PNG</li>
                <li>Открытие файлов с планами запросов (XML или JSON)</li>
                <li>Прямой ввод SQL запроса для выполнения EXPLAIN</li>
            </ul>

            <h2>Интерфейс</h2>
            <ul>
                <li>Темная тема оформления</li>
                <li>Вертикальная панель инструментов с иконками</li>
                <li>Разделяемые панели с возможностью изменения размера</li>
                <li>Вкладки для переключения между режимами работы</li>
                <li>Всплывающие подсказки для всех элементов</li>
                <li>Подсветка синтаксиса SQL в редакторе</li>
                <li>Анимированные индикаторы выполнения операций</li>
                <li>Контекстное меню для таблиц и списков</li>
            </ul>

            <div class="note">
                Требования: PostgreSQL 9.4+, права на чтение pg_stat_activity и выполнение EXPLAIN
            </div>
        </body>
        </html>
        """

        about_dialog = QDialog(self)
        about_dialog.setWindowTitle("О программе")
        about_dialog.resize(750, 700)

        layout = QVBoxLayout(about_dialog)

        browser = QTextBrowser()
        browser.setHtml(about_text)
        browser.setOpenExternalLinks(True)
        layout.addWidget(browser)

        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(about_dialog.accept)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #3a7bd5;
                color: white;
                border: 1px solid #2a5ba5;
                border-radius: 4px;
                padding: 6px 15px;
                font-size: 12px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #4a8be5;
            }
        """)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        button_layout.addStretch()

        layout.addLayout(button_layout)
        about_dialog.setLayout(layout)
        about_dialog.exec_()

    def get_welcome_html(self):
        return welcome_screen_html()

    def _create_welcome_view(self):
        view = QWebEngineView()
        view.setPage(WelcomeNavigationPage(self.handle_welcome_action, view))
        view.setHtml(self.get_welcome_html())
        view.setStyleSheet("""
            background-color: #2d2d2d;
            border: 1px solid #444;
            border-radius: 4px;
        """)
        return view

    def handle_welcome_action(self, action: str) -> None:
        action = (action or "").strip().lower()

        if action == "plan":
            self.show_plan_workspace()
            return

        if action == "file":
            self.show_plan_workspace()
            self.open_and_analyze_plan()
            return

        if action == "active":
            self._switch_left_tab(self.ACTIVE_QUERIES_TAB_LABEL)
            return

        if action == "workload":
            self._switch_left_tab(self.WORKLOAD_TAB_LABEL)
            return

        if action == "hypopg":
            self._switch_left_tab(self.ADMIN_TAB_LABEL)
            self._switch_db_optimization_tab("HypoPG Lab")
            return

        if action == "history":
            self.show_query_plans_journal()
            return

    def _switch_left_tab(self, label: str) -> bool:
        if not hasattr(self, "left_tabs"):
            return False
        for i in range(self.left_tabs.count()):
            if self.left_tabs.tabText(i) == label:
                self.left_tabs.setCurrentIndex(i)
                return True
        return False

    def _switch_db_optimization_tab(self, label: str) -> bool:
        tab_widget = getattr(self, "db_optimization_tab_widget", None)
        if tab_widget is None:
            return False
        for i in range(tab_widget.count()):
            if tab_widget.tabText(i) == label:
                tab_widget.setCurrentIndex(i)
                return True
        return False

    def create_main_interface(self):
        try:
            central_widget = QWidget()
            self.setCentralWidget(central_widget)

            self.main_layout = QVBoxLayout(central_widget)
            self.main_layout.setContentsMargins(5, 5, 5, 5)
            self.main_layout.setSpacing(5)

            horizontal_splitter = QSplitter(Qt.Horizontal)
            self._main_horizontal_splitter = horizontal_splitter

            self.left_tabs = QTabWidget()
            self.left_tabs.setObjectName("left_side")
            self.left_tabs.currentChanged.connect(self.on_left_tab_changed)

            self.visualizer_container = QWidget()
            self.visualizer_layout = QVBoxLayout(self.visualizer_container)
            self.visualizer_layout.setContentsMargins(0, 0, 0, 0)
            self.left_tabs.addTab(self.visualizer_container, self.PLAN_TAB_LABEL)

            self.query_analyzer_tab = QueryAnalyzerTab(self)
            self.left_tabs.addTab(self.query_analyzer_tab, self.ACTIVE_QUERIES_TAB_LABEL)

            self.stat_statements_tab = StatStatementsTab(self)
            self.left_tabs.addTab(self.stat_statements_tab, self.WORKLOAD_TAB_LABEL)

            self.db_optimization_panel = self.create_db_optimization_panel()
            self.left_tabs.addTab(self.db_optimization_panel, self.ADMIN_TAB_LABEL)

            self.embedded_journal = QueryPlansJournalWidget(self)
            self.left_tabs.addTab(self.embedded_journal, self.HISTORY_TAB_LABEL)

            # PostgreSQL settings as a dedicated left tab (after History).
            self.postgres_settings_tab = self.create_postgres_settings_tab()
            self.left_tabs.addTab(self.postgres_settings_tab, self.POSTGRES_SETTINGS_TAB_LABEL)

            self.right_tabs = QTabWidget()
            self.right_tabs.currentChanged.connect(self.on_right_tab_changed)

            general_tab = QWidget()
            general_tab.setStyleSheet("background-color: #2d2d2d;")
            general_layout = QVBoxLayout(general_tab)
            general_layout.setContentsMargins(0, 0, 0, 0)
            self.general_analysis_text = ClickableTextBrowser()
            self.general_analysis_text.setStyleSheet("""
                QTextBrowser {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: none;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    font-size: 12px;
                }
            """)
            general_layout.addWidget(self.general_analysis_text)
            self.right_tabs.addTab(general_tab, self.GENERAL_ANALYSIS_TAB_LABEL)

            optimization_tab = QWidget()
            optimization_tab.setStyleSheet("background-color: #2d2d2d;")
            optimization_layout = QVBoxLayout(optimization_tab)
            optimization_layout.setContentsMargins(0, 0, 0, 0)
            self.optimization_text = QTextBrowser()
            self.optimization_text.setStyleSheet("""
                QTextBrowser {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: none;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    font-size: 12px;
                }
            """)
            optimization_layout.addWidget(self.optimization_text)
            self.right_tabs.addTab(optimization_tab, self.RECOMMENDATIONS_TAB_LABEL)

            # PostgreSQL settings moved to the left tab bar.

            right_side = QSplitter(Qt.Vertical)
            right_side.addWidget(self.right_tabs)

            node_info_container = QWidget()
            node_info_container.setStyleSheet("background-color: #2d2d2d;")
            node_info_layout = QVBoxLayout(node_info_container)
            node_info_layout.setContentsMargins(5, 5, 5, 5)
            node_info_layout.setSpacing(5)

            self.node_info_label = QLabel("📄 Информация о выбранном узле:")
            self.node_info_label.setStyleSheet("""
                QLabel {
                    color: #e0e0e0;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 5px;
                    background-color: #2d2d2d;
                    border-bottom: 1px solid #444;
                }
            """)

            self.node_info_text = QTextBrowser()
            self.node_info_text.setStyleSheet("""
                QTextBrowser {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: none;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    font-size: 12px;
                }
            """)

            node_info_layout.addWidget(self.node_info_label)
            node_info_layout.addWidget(self.node_info_text)
            right_side.addWidget(node_info_container)

            right_side.setSizes([400, 200])

            horizontal_splitter.addWidget(self.left_tabs)
            horizontal_splitter.addWidget(right_side)
            horizontal_splitter.setChildrenCollapsible(False)
            self.left_tabs.setMinimumWidth(360)
            right_side.setMinimumWidth(380)
            horizontal_splitter.setStretchFactor(0, 1)
            horizontal_splitter.setStretchFactor(1, 1)
            horizontal_splitter.setSizes([700, 500])

            self.main_layout.addWidget(horizontal_splitter)

            self.tab_data_cache = {
                "visualizer": {"general": "", "optimization": "", "has_data": False},
                "scanner": {"general": "", "optimization": "", "has_data": False},
                "db_optimization": {"general": "", "optimization": "", "has_data": False},
            }

            self._updating_tab_content = False

        except Exception as e:
            logging.error(f"Error creating main interface: {e}")
            raise RuntimeError(f"Failed to create main interface: {e}")

    def on_left_tab_changed(self, index):
        if not hasattr(self, "left_tabs") or not hasattr(self, "right_tabs"):
            return

        if hasattr(self, "_updating_tab_content") and self._updating_tab_content:
            return

        try:
            self._updating_tab_content = True

            tab_text = self.left_tabs.tabText(index)

            if tab_text == self.PLAN_TAB_LABEL:
                if hasattr(self, "xml_content") and self.xml_content:
                    if hasattr(self, "initial_content"):
                        self.initial_content.hide()
                    if hasattr(self, "visualizer_window"):
                        self.visualizer_window.show()
                    self.restore_tab_data("visualizer")
                else:
                    self.clear_analysis_panels(keep_settings=True)
                    self.show_visualization_info()
            elif tab_text == self.ACTIVE_QUERIES_TAB_LABEL:
                self.clear_analysis_panels(keep_settings=True)
                self.show_scanner_info()
            elif tab_text == self.WORKLOAD_TAB_LABEL:
                self.clear_analysis_panels(keep_settings=True)
                self.show_stat_statements_info()
            elif tab_text == self.ADMIN_TAB_LABEL:
                self.clear_analysis_panels(keep_settings=True)
                self.show_db_optimization_info()
            elif tab_text == self.HISTORY_TAB_LABEL:
                self.clear_analysis_panels(keep_settings=True)
                self.embedded_journal.load_journal()
            elif tab_text == self.POSTGRES_SETTINGS_TAB_LABEL:
                self.clear_analysis_panels(keep_settings=True)
                if self.connection_status and hasattr(self, "conn") and not self.conn.closed:
                    self.load_postgres_settings()
        finally:
            self._updating_tab_content = False

    def on_right_tab_changed(self, _index):
        if not hasattr(self, "right_tabs") or not hasattr(self, "connection_status"):
            return
        # PostgreSQL settings moved to the left tab bar.

    def clear_analysis_panels(self, keep_settings=False):
        if not hasattr(self, "left_tabs") or not hasattr(self, "general_analysis_text"):
            return

        current_tab = self.left_tabs.currentIndex()
        tab_text = self.left_tabs.tabText(current_tab)

        if tab_text == self.PLAN_TAB_LABEL and hasattr(self, "xml_content") and self.xml_content:
            if hasattr(self, "general_analysis_text"):
                self.tab_data_cache["visualizer"]["general"] = self.general_analysis_text.toHtml()
            if hasattr(self, "optimization_text"):
                self.tab_data_cache["visualizer"]["optimization"] = self.optimization_text.toHtml()
            self.tab_data_cache["visualizer"]["has_data"] = bool(
                self.general_analysis_text.toPlainText()
            )

        if not keep_settings:
            if hasattr(self, "general_analysis_text"):
                self.general_analysis_text.clear()
            if hasattr(self, "optimization_text"):
                self.optimization_text.clear()
            if hasattr(self, "node_info_text"):
                self.node_info_text.clear()
            if hasattr(self, "node_info_label"):
                self.node_info_label.setText("📄 Информация о выбранном узле:")

    def restore_tab_data(self, tab_name):
        if not hasattr(self, "tab_data_cache"):
            return

        cached = self.tab_data_cache.get(tab_name, {})

        if cached.get("has_data", False):
            if hasattr(self, "general_analysis_text") and cached.get("general"):
                self.general_analysis_text.setHtml(cached.get("general", ""))
            if hasattr(self, "optimization_text") and cached.get("optimization"):
                self.optimization_text.setHtml(cached.get("optimization", ""))
        else:
            if tab_name == "visualizer":
                if hasattr(self, "general_analysis_text"):
                    self.general_analysis_text.setHtml("""
                    <html>
                    <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
                        <h2 style="color:#4fc3f7;">Разобрать план запроса</h2>
                        <p>Начните с одного источника: SQL, файл EXPLAIN или запись из журнала.</p>
                        <p>Основной поток:</p>
                        <ul>
                            <li>Введите SQL в нижней панели и нажмите «Выполнить»</li>
                            <li>Откройте готовый план XML/JSON кнопкой «Открыть план»</li>
                            <li>Выберите запрос из Workload или сохранённую запись из журнала</li>
                        </ul>
                    </body>
                    </html>
                    """)
                if hasattr(self, "optimization_text"):
                    self.optimization_text.clear()

    def show_scanner_info(self):
        if hasattr(self, "general_analysis_text"):
            self.general_analysis_text.setHtml("""
            <html>
            <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
                <h2 style="color:#4fc3f7;">💻 Активные запросы</h2>
                <p>Найдите запрос, который прямо сейчас влияет на базу, и отправьте его в разбор плана.</p>
                
                <h3 style="color:#81c784;">Возможности:</h3>
                <ul>
                    <li>Просмотр всех активных запросов в реальном времени</li>
                    <li>Фильтрация по состоянию, пользователю, приложению</li>
                    <li>Анализ длительных операций и блокировок</li>
                    <li>Быстрый переход к EXPLAIN для проблемного запроса</li>
                    <li>Завершение проблемных процессов</li>
                </ul>
                
                <h3 style="color:#81c784;">Как использовать:</h3>
                <ol>
                    <li>Подключитесь к базе данных</li>
                    <li>Нажмите "Сканировать запросы" для начала мониторинга</li>
                    <li>Используйте фильтры для поиска нужных запросов</li>
                    <li>Дважды кликните по запросу, чтобы разобрать его план на вкладке «План»</li>
                </ol>
                
                <p style="color:#fcc419;">Совет: Включите автоматическое обновление для непрерывного мониторинга</p>
            </body>
            </html>
            """)
        if hasattr(self, "optimization_text"):
            self.optimization_text.setHtml("""
            <html>
            <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
                <h2 style="color:#4fc3f7;">Что делать с найденным запросом</h2>
                
                <h3 style="color:#81c784;">На что обратить внимание:</h3>
                <ul>
                    <li>Длительные запросы (более 60 секунд)</li>
                    <li>Заблокированные процессы (idle in transaction)</li>
                    <li>Запросы с большим потреблением памяти</li>
                    <li>Часто выполняющиеся запросы</li>
                </ul>
                
                <h3 style="color:#81c784;">Действия при проблемах:</h3>
                <ul>
                    <li>Сначала разберите план проблемного запроса</li>
                    <li>Проверьте недостающие индексы через рекомендации и HypoPG</li>
                    <li>Завершите проблемные процессы при необходимости</li>
                    <li>Оптимизируйте структуру запросов</li>
                </ul>
            </body>
            </html>
            """)

    def show_stat_statements_info(self):
        if hasattr(self, "general_analysis_text"):
            self.general_analysis_text.setHtml("""
            <html>
            <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
                <h2 style="color:#4fc3f7;">📊 Workload</h2>
                <p>Накопленная статистика помогает выбрать запросы, которые дают самый большой вклад в нагрузку.</p>

                <h3 style="color:#81c784;">Что показывает вкладка слева</h3>
                <ul>
                    <li>Топ запросов текущей базы по суммарному или среднему времени, числу вызовов или строкам</li>
                    <li>Сводные поля: calls, mean_ms, total_ms, rows</li>
                    <li>Полный текст запроса — двойной клик или контекстное меню</li>
                    <li>Действие «Вставить в поле запроса» переключает на «План» и подставляет текст для EXPLAIN</li>
                </ul>

                <h3 style="color:#81c784;">Требования на сервере</h3>
                <ul>
                    <li>В <code>postgresql.conf</code>: <code>shared_preload_libraries</code> с модулем, перезапуск кластера</li>
                    <li>В текущей БД: <code>CREATE EXTENSION IF NOT EXISTS pg_stat_statements;</code></li>
                    <li>Иначе во вкладке — сообщение в строке статуса (приложение не падает)</li>
                </ul>

                <h3 style="color:#81c784;">Функции вкладки</h3>
                <ul>
                    <li>Столбец «журнал» — число записей в локальном журнале планов с тем же fingerprint, что и у текста запроса (<code>normalize_query_text</code>)</li>
                    <li>Экспорт CSV и сброс <code>pg_stat_statements_reset()</code></li>
                </ul>

                <p style="color:#fcc419;">Данные относятся только к текущей базе подключения (фильтр по dbid).</p>
            </body>
            </html>
            """)
        if hasattr(self, "optimization_text"):
            self.optimization_text.setHtml("""
            <html>
            <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
                <h2 style="color:#4fc3f7;">Как использовать статистику</h2>
                <ul>
                    <li>Сортировка по total_ms помогает найти запросы с наибольшим суммарным временем CPU</li>
                    <li>Сортировка по mean_ms выявляет дорогие типичные выполнения</li>
                    <li>Сравните с активными запросами, чтобы связать историю и текущую нагрузку</li>
                </ul>
            </body>
            </html>
            """)

    def show_db_optimization_info(self):
        if hasattr(self, "general_analysis_text"):
            self.general_analysis_text.setHtml("""
            <html>
            <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
                <h2 style="color:#4fc3f7;">🛠 Обслуживание БД</h2>
                <p>Инструменты обслуживания и оптимизации: индексы, статистика, VACUUM и HypoPG. Используйте их после того, как выбран конкретный запрос или схема.</p>
                
                <h3 style="color:#81c784;">Доступные функции:</h3>
                <ul>
                    <li><b>Анализ индексов</b> - поиск недостающих и неиспользуемых индексов</li>
                    <li><b>Статистика таблиц</b> - проверка актуальности статистики</li>
                    <li><b>VACUUM</b> - анализ необходимости вакуумирования</li>
                    <li><b>HypoPG</b> — гипотетические индексы и EXPLAIN в одной сессии (расширение <code>hypopg</code>)</li>
                </ul>
                
                <h3 style="color:#81c784;">Рекомендации по использованию:</h3>
                <ol>
                    <li>Выберите базу данных и схему для анализа</li>
                    <li>Проверьте индексы - создайте недостающие, удалите неиспользуемые</li>
                    <li>Обновите статистику для таблиц с большим количеством изменений</li>
                    <li>Выполните VACUUM при высоком проценте мертвых строк</li>
                </ol>
                
                <p style="color:#fcc419;">Внимание: Некоторые операции могут создавать нагрузку на БД.</p>
            </body>
            </html>
            """)
        if hasattr(self, "optimization_text"):
            self.optimization_text.setHtml("""
            <html>
            <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
                <h2 style="color:#4fc3f7;">Рекомендации по оптимизации БД</h2>
                
                <h3 style="color:#81c784;">Индексы:</h3>
                <ul>
                    <li>Создавайте индексы на поля, используемые в WHERE, JOIN, ORDER BY</li>
                    <li>Используйте составные индексы для нескольких условий</li>
                    <li>Удаляйте дублирующиеся и неиспользуемые индексы</li>
                    <li>Регулярно анализируйте использование индексов</li>
                </ul>
                
                <h3 style="color:#81c784;">Статистика:</h3>
                <ul>
                    <li>Выполняйте ANALYZE после массовых изменений данных</li>
                    <li>Увеличьте statistics_target для важных колонок</li>
                    <li>Используйте pg_statistic для проверки качества статистики</li>
                </ul>
                
                <h3 style="color:#81c784;">VACUUM:</h3>
                <ul>
                    <li>Регулярно выполняйте VACUUM для таблиц с частыми UPDATE/DELETE</li>
                    <li>Используйте VACUUM FULL для возврата места ОС (с блокировкой)</li>
                    <li>Отслеживайте процент мертвых строк в pg_stat_user_tables</li>
                </ul>
            </body>
            </html>
            """)

    def create_db_optimization_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        db_schema_widget = QWidget()
        db_schema_layout = QHBoxLayout(db_schema_widget)
        db_schema_layout.setContentsMargins(0, 0, 0, 0)
        db_schema_layout.setSpacing(10)

        self.db_combo = QComboBox()
        self.db_combo.setMinimumWidth(200)
        self.db_combo.setStyleSheet("""
            QComboBox {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #e0e0e0;
                margin-right: 5px;
            }
            QComboBox QAbstractItemView {
                background-color: #333;
                color: #e0e0e0;
                selection-background-color: #4a8be5;
                border: 1px solid #555;
            }
        """)

        self.schema_combo = QComboBox()
        self.schema_combo.setMinimumWidth(200)
        self.schema_combo.setStyleSheet("""
            QComboBox {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #e0e0e0;
                margin-right: 5px;
            }
            QComboBox QAbstractItemView {
                background-color: #333;
                color: #e0e0e0;
                selection-background-color: #4a8be5;
                border: 1px solid #555;
            }
        """)

        db_label = QLabel("База данных:")
        db_label.setStyleSheet("color: #e0e0e0; font-size: 12px;")
        schema_label = QLabel("Схема:")
        schema_label.setStyleSheet("color: #e0e0e0; font-size: 12px;")

        db_schema_layout.addWidget(db_label)
        db_schema_layout.addWidget(self.db_combo)
        db_schema_layout.addWidget(schema_label)
        db_schema_layout.addWidget(self.schema_combo)
        db_schema_layout.addStretch()

        layout.addWidget(db_schema_widget)

        self.update_databases()

        self.db_combo.currentIndexChanged.connect(self.update_schemas)

        self._maintenance_snapshot_current = {}
        self._maintenance_snapshot_baseline = {}
        self._maintenance_last_compare_lines = []

        self.maintenance_debt_label = QLabel("Maintenance debt score: n/a")
        self.maintenance_debt_label.setStyleSheet("""
            QLabel {
                color: #cfd8dc;
                background-color: #263238;
                border-left: 4px solid #4fc3f7;
                padding: 6px 8px;
                font-size: 12px;
            }
        """)
        self.maintenance_debt_label.setWordWrap(True)
        layout.addWidget(self.maintenance_debt_label)

        self.db_optimization_tab_widget = QTabWidget()
        self.db_optimization_tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #444;
                background: #2d2d2d;
            }
            QTabBar::tab {
                background: #3a3a3a;
                color: #e0e0e0;
                padding: 5px 10px;
                border: 1px solid #444;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #4a8be5;
            }
            QTabBar::tab:hover {
                background: #555;
            }
        """)

        indexes_tab = self.create_indexes_tab()
        self.db_optimization_tab_widget.addTab(indexes_tab, "Индексы")

        statistics_tab = self.create_statistics_tab()
        self.db_optimization_tab_widget.addTab(statistics_tab, "Статистика")

        vacuum_tab = self.create_vacuum_tab()
        self.db_optimization_tab_widget.addTab(vacuum_tab, "VACUUM")

        self.hypopg_tab = HypoPGTab(self)
        self.db_optimization_tab_widget.addTab(self.hypopg_tab, "HypoPG Lab")

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.db_optimization_tab_widget)
        self.process_output = QTextEdit()
        self.process_output.setReadOnly(True)
        self.process_output.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #444;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
            }
        """)
        self.process_output.setFixedHeight(100)
        splitter.addWidget(self.process_output)

        layout.addWidget(splitter)

        return panel

    def update_databases(self):
        self.db_combo.clear()
        if self.connection_status and hasattr(self, "conn"):
            try:
                with self.conn.cursor() as cursor:
                    cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
                    databases = [record[0] for record in cursor.fetchall()]
                    self.db_combo.addItems(databases)
                    if databases:
                        self.update_schemas()
            except Exception as e:
                logging.error(f"Ошибка получения списка баз данных: {e}")
                QMessageBox.warning(
                    self, "Ошибка", f"Не удалось получить список баз данных:\n{str(e)}"
                )

    def update_schemas(self):
        self.schema_combo.clear()
        current_db = self.db_combo.currentText()
        if self.connection_status and hasattr(self, "conn") and current_db:
            try:
                conn_params = {
                    **StoredConnectionSettings.connect_kwargs(self.current_connection),
                    "dbname": current_db,
                }

                with psycopg2.connect(**conn_params) as temp_conn:
                    with temp_conn.cursor() as cursor:
                        cursor.execute(
                            "SELECT schema_name FROM information_schema.schemata WHERE catalog_name = current_database();"
                        )
                        schemas = [record[0] for record in cursor.fetchall()]
                        self.schema_combo.addItems(schemas)
            except Exception as e:
                logging.error(f"Ошибка получения списка схем: {e}")
                QMessageBox.warning(self, "Ошибка", f"Не удалось получить список схем:\n{str(e)}")

    def create_indexes_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        toolbar = QToolBar()
        toolbar.setIconSize(QSize(16, 16))
        toolbar.setStyleSheet("""
            QToolBar {
                background-color: #333;
                border: none;
                padding: 2px;
            }
        """)

        find_missing_indexes_button = QPushButton(
            icon("fa5s.search", color="white"), "Найти недостающие индексы"
        )
        find_missing_indexes_button.setToolTip(
            "Поиск таблиц с потенциально недостающими индексами (только чтение)"
        )
        find_missing_indexes_button.clicked.connect(self.find_missing_indexes)
        self.find_missing_indexes_button = find_missing_indexes_button
        find_missing_indexes_button.setStyleSheet("""
            QPushButton {
                background-color: #2d5a8a;
                color: white;
                border: 1px solid #3a7bd5;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #3a6a9a;
            }
        """)
        toolbar.addWidget(find_missing_indexes_button)

        separator = QWidget()
        separator.setFixedWidth(5)
        toolbar.addWidget(separator)

        analyze_indexes_button = QPushButton(
            icon("fa5s.chart-line", color="white"), "Анализ использования индексов"
        )
        analyze_indexes_button.setToolTip(
            "Анализ использования существующих индексов (только чтение)"
        )
        analyze_indexes_button.clicked.connect(self.analyze_indexes)
        analyze_indexes_button.setStyleSheet("""
            QPushButton {
                background-color: #2d5a8a;
                color: white;
                border: 1px solid #3a7bd5;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #3a6a9a;
            }
        """)
        toolbar.addWidget(analyze_indexes_button)

        layout.addWidget(toolbar)

        self.indexes_table = QTableWidget()
        self.indexes_table.setColumnCount(5)
        self.indexes_table.setHorizontalHeaderLabels(
            ["Схема.Таблица", "Индекс/Поле", "Использований", "Размер", "Статус/Рекомендация"]
        )
        self.indexes_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                gridline-color: #444;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #e0e0e0;
                padding: 5px;
                border: 1px solid #444;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)

        header = self.indexes_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)

        self.indexes_table.setSortingEnabled(True)
        self.indexes_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.indexes_table.setSelectionMode(QTableWidget.SingleSelection)
        self.indexes_table.itemSelectionChanged.connect(self.on_index_selected)

        layout.addWidget(self.indexes_table)

        return tab

    def on_index_selected(self):
        selected_rows = self.indexes_table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        table_name = self.indexes_table.item(row, 0).text()
        index_or_field = self.indexes_table.item(row, 1).text()
        status = self.indexes_table.item(row, 4).text()

        data = self.indexes_table.item(row, 0).data(Qt.UserRole + 1)

        if not data:
            return

        if status in ["Требуется индекс", "Рекомендуется индекс"]:
            self.show_index_recommendation(table_name, index_or_field, status, data)
        else:
            self.show_index_details(table_name, index_or_field, status, data)

    def show_index_recommendation(self, table_name, field_info, recommendation_type, data):
        table = table_name.split(".")[-1]
        avg_tuples = data.get("avg_tuples_per_scan", 0)
        seq_scan = data.get("seq_scan", 0)
        seq_tup_read = data.get("seq_tup_read", 0)

        if recommendation_type == "Требуется индекс":
            title_text = "ТРЕБУЕТСЯ СОЗДАНИЕ ИНДЕКСА"
            severity = "Критично"
            severity_color = "#ff6b6b"
        else:
            title_text = "РЕКОМЕНДУЕТСЯ СОЗДАНИЕ ИНДЕКСА"
            severity = "Важно"
            severity_color = "#fcc419"

        improvement_factor = max(10, int(seq_tup_read / max(1, avg_tuples)))

        html = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', 'Consolas', 'Monaco', monospace;
                    color: #e0e0e0;
                    background-color: transparent;
                    margin: 12px;
                    padding: 0;
                    font-size: 12px;
                    line-height: 1.4;
                }}
                .title {{
                    color: {severity_color};
                    font-size: 16px;
                    font-weight: bold;
                    margin: 0 0 12px 0;
                    padding: 0 0 8px 0;
                    border-bottom: 1px solid #555;
                }}
                .section {{
                    margin: 12px 0 8px 0;
                    padding: 0;
                }}
                .section-title {{
                    color: #4fc3f7;
                    font-size: 13px;
                    font-weight: bold;
                    margin: 0 0 6px 0;
                    padding: 0;
                    letter-spacing: 0.5px;
                }}
                .info-row {{
                    margin: 4px 0;
                    padding: 0;
                }}
                .info-label {{
                    color: #888888;
                    display: inline-block;
                    min-width: 180px;
                    font-size: 11px;
                }}
                .info-value {{
                    color: #e0e0e0;
                    font-weight: normal;
                    font-family: 'Consolas', monospace;
                }}
                .severity {{
                    color: {severity_color};
                    font-weight: bold;
                    font-size: 11px;
                }}
                .explanation {{
                    padding: 10px 0;
                    margin: 8px 0;
                    font-size: 11px;
                }}
                .benefits {{
                    margin: 6px 0 6px 20px;
                    padding: 0;
                }}
                .benefits li {{
                    margin: 3px 0;
                }}
                .sql-block {{
                    padding: 10px;
                    margin: 8px 0;
                    font-family: 'Consolas', monospace;
                    font-size: 11px;
                    color: #ce9178;
                    border: 1px solid #3a3a3a;
                    border-radius: 4px;
                    overflow-x: auto;
                    white-space: pre-wrap;
                    word-break: break-all;
                }}
                .warning-note {{
                    padding: 8px 0;
                    margin: 8px 0;
                    font-size: 11px;
                }}
                .recommendation-list {{
                    margin: 6px 0 6px 20px;
                    padding: 0;
                }}
                .recommendation-list li {{
                    margin: 3px 0;
                }}
                hr {{
                    border: none;
                    border-top: 1px solid #3a3a3a;
                    margin: 10px 0;
                }}
                .mono {{
                    font-family: 'Consolas', monospace;
                }}
            </style>
        </head>
        <body>
            <div class="title">{title_text}</div>
            
            <div class="section">
                <div class="info-row">
                    <span class="info-label">Таблица:</span>
                    <span class="info-value mono">{table_name}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Серьезность:</span>
                    <span class="severity">{severity}</span>
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">Статистика использования</div>
                <div class="info-row">
                    <span class="info-label">Количество последовательных сканирований:</span>
                    <span class="info-value">{seq_scan:,}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Всего прочитано строк:</span>
                    <span class="info-value">{seq_tup_read:,}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Среднее строк на сканирование:</span>
                    <span class="info-value">{avg_tuples:,.0f}</span>
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">Почему требуется индекс?</div>
                <div class="explanation">
                    Таблица <span class="mono">{table_name}</span> часто используется в запросах с фильтрацией, но не имеет подходящих индексов.<br>
                    При каждом запросе выполняется полное сканирование таблицы (Seq Scan), что при большом количестве данных приводит к значительным задержкам.
                </div>
                <div>Создание индекса позволит:</div>
                <ul class="benefits">
                    <li>Уменьшить время выполнения запросов в <span class="info-value">{improvement_factor:,}</span> и более раз</li>
                    <li>Снизить нагрузку на ввод-вывод</li>
                    <li>Улучшить общую производительность базы данных</li>
                </ul>
            </div>
            
            <div class="section">
                <div class="section-title">Рекомендация по индексу</div>
                <div class="explanation">
                    Рекомендуется создать индекс на полях, которые часто используются в условиях WHERE, JOIN и ORDER BY.
                </div>
                <div class="sql-block">
    -- Создание индекса (без блокировки записи)
    CREATE INDEX CONCURRENTLY idx_{table[:20]}_optimization ON {table_name} (поле1, поле2);

    -- Обновление статистики после создания индекса
    ANALYZE {table_name};

    -- Проверка использования индекса
    EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM {table_name} WHERE ...;
                </div>
                <div class="warning-note">
                    Важно: Индекс следует создавать с опцией CONCURRENTLY, чтобы не блокировать запись в таблицу.
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">Дополнительные рекомендации</div>
                <ul class="recommendation-list">
                    <li>Перед созданием индекса оцените его размер и влияние на операции вставки/обновления</li>
                    <li>Для больших таблиц используйте CREATE INDEX CONCURRENTLY</li>
                    <li>Регулярно обновляйте статистику: ANALYZE table_name</li>
                    <li>Используйте pg_stat_user_indexes для мониторинга использования индексов</li>
                </ul>
            </div>
        </body>
        </html>
        """

        if hasattr(self, "node_info_text"):
            self.node_info_text.setHtml(html)
            self.node_info_label.setText(f"Рекомендация по индексу: {table_name}")

    def show_index_details(self, table_name, index_name, status, data):
        used_times = data.get("used_times", 0)
        tuples_read = data.get("tuples_read", 0)
        tuples_fetched = data.get("tuples_fetched", 0)
        size_bytes = data.get("size_bytes", 0)

        if size_bytes < 1024:
            size_str = f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            size_str = f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            size_str = f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

        if status == "Не используется":
            status_desc = "Индекс не используется"
            status_color = "#ff6b6b"
        elif status == "Редко используется":
            status_desc = "Индекс используется редко"
            status_color = "#fcc419"
        else:
            status_desc = "Индекс активно используется"
            status_color = "#51cf66"

        html = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', 'Consolas', 'Monaco', monospace;
                    color: #e0e0e0;
                    background-color: transparent;
                    margin: 12px;
                    padding: 0;
                    font-size: 12px;
                    line-height: 1.4;
                }}
                .title {{
                    color: #4fc3f7;
                    font-size: 16px;
                    font-weight: bold;
                    margin: 0 0 12px 0;
                    padding: 0 0 8px 0;
                    border-bottom: 1px solid #555;
                }}
                .section {{
                    margin: 12px 0 8px 0;
                    padding: 0;
                }}
                .section-title {{
                    color: #4fc3f7;
                    font-size: 13px;
                    font-weight: bold;
                    margin: 0 0 6px 0;
                    padding: 0;
                    letter-spacing: 0.5px;
                }}
                .info-row {{
                    margin: 4px 0;
                    padding: 0;
                }}
                .info-label {{
                    color: #888888;
                    display: inline-block;
                    min-width: 140px;
                    font-size: 11px;
                }}
                .info-value {{
                    color: #e0e0e0;
                    font-weight: normal;
                    font-family: 'Consolas', monospace;
                }}
                .status {{
                    color: {status_color};
                    font-weight: bold;
                    font-size: 11px;
                }}
                .info-block {{
                    padding: 8px 0;
                    margin: 8px 0;
                }}
                .sql-block {{
                    padding: 10px;
                    margin: 8px 0;
                    font-family: 'Consolas', monospace;
                    font-size: 11px;
                    color: #ce9178;
                    border: 1px solid #3a3a3a;
                    border-radius: 4px;
                    overflow-x: auto;
                    white-space: pre-wrap;
                    word-break: break-all;
                }}
                hr {{
                    border: none;
                    border-top: 1px solid #3a3a3a;
                    margin: 10px 0;
                }}
                .mono {{
                    font-family: 'Consolas', monospace;
                }}
            </style>
        </head>
        <body>
            <div class="title">Информация об индексе</div>
            
            <div class="section">
                <div class="info-row">
                    <span class="info-label">Таблица:</span>
                    <span class="info-value mono">{table_name}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Индекс:</span>
                    <span class="info-value mono">{index_name}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Статус:</span>
                    <span class="status">{status_desc}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Размер:</span>
                    <span class="info-value">{size_str}</span>
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">Статистика использования</div>
                <div class="info-row">
                    <span class="info-label">Количество использований:</span>
                    <span class="info-value">{used_times:,}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Прочитано строк:</span>
                    <span class="info-value">{tuples_read:,}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Получено строк:</span>
                    <span class="info-value">{tuples_fetched:,}</span>
                </div>
            </div>
        """

        if status == "Не используется":
            html += f"""
            <div class="section">
                <div class="info-block">
                    Внимание: Этот индекс не используется.
                </div>
                <div>Рекомендуется рассмотреть возможность удаления индекса, так как он:</div>
                <ul>
                    <li>Занимает место на диске ({size_str})</li>
                    <li>Замедляет операции вставки/обновления/удаления</li>
                    <li>Не приносит пользы для чтения</li>
                </ul>
                <div class="sql-block">
    -- Удаление индекса
    DROP INDEX CONCURRENTLY {index_name};
                </div>
            </div>
            """
        elif status == "Редко используется":
            html += """
            <div class="section">
                <div class="info-block">
                    Информация: Этот индекс используется редко.
                </div>
                <div>Возможные причины:</div>
                <ul>
                    <li>Индекс не оптимален для текущей нагрузки</li>
                    <li>Существуют более эффективные индексы</li>
                    <li>Статистика таблицы устарела</li>
                </ul>
                <div>Рекомендации:</div>
                <ul>
                    <li>Проверьте планы запросов, которые могли бы использовать этот индекс</li>
                    <li>Рассмотрите возможность создания более подходящего индекса</li>
                    <li>Проанализируйте, не дублирует ли этот индекс функциональность других индексов</li>
                    <li>Выполните ANALYZE для обновления статистики</li>
                </ul>
            </div>
            """
        else:
            html += """
            <div class="section">
                <div class="info-block">
                    Информация: Этот индекс активно используется.
                </div>
                <div>Рекомендуется:</div>
                <ul>
                    <li>Продолжать мониторинг его использования</li>
                    <li>Отслеживать рост размера индекса</li>
                    <li>Периодически проверять фрагментацию</li>
                </ul>
            </div>
            """

        html += f"""
            <div class="section">
                <div class="section-title">Полезные запросы для мониторинга</div>
                <div class="sql-block">
    -- Проверка использования индекса
    SELECT * FROM pg_stat_user_indexes WHERE indexrelname = '{index_name}';

    -- Проверка размера индекса
    SELECT pg_size_pretty(pg_relation_size('{index_name}'));

    -- Проверка фрагментации индекса
    SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
    FROM pg_stat_user_indexes 
    WHERE indexrelname = '{index_name}';
                </div>
            </div>
        </body>
        </html>
        """

        if hasattr(self, "node_info_text"):
            self.node_info_text.setHtml(html)
            self.node_info_label.setText(f"Информация об индексе: {index_name}")

    def find_missing_indexes(self):
        if self._missing_indexes_worker is not None:
            QMessageBox.information(
                self,
                "Индексы",
                "Поиск недостающих индексов уже выполняется. Дождитесь завершения.",
            )
            return

        db = self.db_combo.currentText()
        schema = self.schema_combo.currentText()

        if not db or not schema:
            QMessageBox.warning(self, "Ошибка", "Выберите базу данных и схему")
            return

        try:
            if self.conn.closed:
                self.connect_to_database()
                if not self.connection_status:
                    QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
                    return

            self.conn.rollback()

            conn_params = {
                **StoredConnectionSettings.connect_kwargs(self.current_connection),
                "dbname": db,
            }

            min_table_size_mb = self.analyzer_settings.get("analysis", {}).get(
                "min_table_size_for_index_mb", 10
            )

            self._missing_indexes_ctx = {"db": db, "schema": schema}
            if getattr(self, "find_missing_indexes_button", None):
                self.find_missing_indexes_button.setEnabled(False)
            self.process_output.append(
                "Поиск недостающих индексов выполняется в фоне (интерфейс не должен блокироваться)…"
            )

            self._missing_indexes_worker = CallableWorkerThread(
                functools.partial(
                    fetch_pg_stat_missing_index_candidates,
                    conn_params,
                    min_table_size_mb,
                    schema,
                ),
                self,
            )
            self._missing_indexes_worker.completed.connect(self._on_missing_indexes_worker_done)
            self._missing_indexes_worker.start()

        except Exception as e:
            error_msg = str(e)
            logging.error("Ошибка запуска поиска индексов: %s", error_msg)
            if getattr(self, "find_missing_indexes_button", None):
                self.find_missing_indexes_button.setEnabled(True)
            self._missing_indexes_worker = None
            self._missing_indexes_ctx = None
            try:
                self.conn.rollback()
            except Exception:
                pass
            QMessageBox.critical(self, "Ошибка", f"Не удалось начать поиск индексов:\n{error_msg}")

    def _on_missing_indexes_worker_done(self, ok: bool, payload: object):
        if getattr(self, "find_missing_indexes_button", None):
            self.find_missing_indexes_button.setEnabled(True)
        self._missing_indexes_worker = None
        ctx = getattr(self, "_missing_indexes_ctx", None) or {}
        self._missing_indexes_ctx = None
        db = ctx.get("db", "")
        schema = ctx.get("schema", "")

        if not ok:
            error_msg = str(payload)
            logging.error("Ошибка поиска индексов (фон): %s", error_msg)
            try:
                self.conn.rollback()
            except Exception:
                pass
            QMessageBox.critical(
                self, "Ошибка", f"Не удалось выполнить поиск индексов:\n{error_msg}"
            )
            return

        results = payload
        try:
            self._apply_missing_indexes_table_results(results, db, schema)
            self.process_output.append(f"Найдено {len(results)} таблиц для анализа индексов.")
        except Exception as e:
            logging.error("Ошибка отображения результатов поиска индексов: %s", e, exc_info=True)
            QMessageBox.critical(
                self,
                "Ошибка",
                f"Запрос выполнен, но не удалось заполнить таблицу:\n{e}",
            )

    def _apply_missing_indexes_table_results(self, results, db, schema):
        """GUI thread: fill indexes_table from worker row tuples."""
        self.indexes_table.setSortingEnabled(False)
        self.indexes_table.setUpdatesEnabled(False)
        try:
            self.indexes_table.setRowCount(len(results))

            for row_idx, row in enumerate(results):
                table_name = str(row[0])
                seq_scan = str(row[1])
                _ = str(row[2])
                size_mb = float(row[4] or 0)
                recommendation = str(row[5])

                size_display = f"{size_mb:.1f} MB" if size_mb < 1024 else f"{size_mb/1024:.1f} GB"

                items = [
                    QTableWidgetItem(table_name),
                    QTableWidgetItem("—"),
                    SortableTableWidgetItem(seq_scan, int(row[1] or 0)),
                    SortableTableWidgetItem(size_display, size_mb),
                    SortableTableWidgetItem(
                        recommendation, index_recommendation_rank(recommendation)
                    ),
                ]

                if recommendation == "Требуется индекс":
                    bg_color = QColor("#ff9999")
                    color_name = "critical"
                elif recommendation == "Рекомендуется индекс":
                    bg_color = QColor("#ffff99")
                    color_name = "warning"
                else:
                    bg_color = QColor("#ccffcc")
                    color_name = "ok"

                for col_idx, item in enumerate(items):
                    item.setBackground(bg_color)
                    item.setForeground(QColor("#000000"))
                    item.setData(Qt.UserRole, color_name)
                    self.indexes_table.setItem(row_idx, col_idx, item)

                self.indexes_table.item(row_idx, 0).setData(
                    Qt.UserRole + 1,
                    {
                        "table_name": table_name,
                        "seq_scan": row[1],
                        "seq_tup_read": row[2],
                        "avg_tuples_per_scan": row[3],
                        "size_mb": size_mb,
                        "recommendation": recommendation,
                        "schema": schema,
                        "db": db,
                    },
                )
        finally:
            self.indexes_table.setUpdatesEnabled(True)

        self.indexes_table.setSortingEnabled(True)

        header = self.indexes_table.horizontalHeader()
        for slot in (self.preserve_row_colors, self.preserve_index_analysis_colors):
            try:
                header.sortIndicatorChanged.disconnect(slot)
            except (TypeError, RuntimeError):
                pass
        header.sortIndicatorChanged.connect(self.preserve_row_colors)

    def preserve_row_colors(self):
        try:
            for row in range(self.indexes_table.rowCount()):
                first_item = self.indexes_table.item(row, 0)
                if first_item:
                    color_name = first_item.data(Qt.UserRole)
                    if color_name == "critical":
                        bg_color = QColor("#ff9999")
                    elif color_name == "warning":
                        bg_color = QColor("#ffff99")
                    elif color_name == "ok":
                        bg_color = QColor("#ccffcc")
                    else:
                        continue

                    for col in range(self.indexes_table.columnCount()):
                        item = self.indexes_table.item(row, col)
                        if item:
                            item.setBackground(bg_color)
                            item.setForeground(QColor("#000000"))
        except Exception as e:
            logging.error(f"Ошибка сохранения цветов строк: {e}")

    def ensure_connection(self):
        try:
            if not self.connection_status or not hasattr(self, "conn") or self.conn.closed:
                self.connect_to_database()
            else:
                with self.conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                self.conn.rollback()
        except Exception as e:
            logging.error(f"Ошибка проверки соединения: {e}")
            self.connect_to_database()

    def analyze_indexes(self):
        if not self.connection_status or not hasattr(self, "conn"):
            QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
            return

        db_name = self.db_combo.currentText()
        schema_name = self.schema_combo.currentText()

        if not db_name or not schema_name:
            QMessageBox.warning(self, "Ошибка", "Выберите базу данных и схему")
            return

        self.process_output.clear()
        self.process_output.append(
            f"Анализ использования существующих индексов в базе данных {db_name}, схема {schema_name}..."
        )

        try:
            if self.conn.closed:
                self.connect_to_database()
                if not self.connection_status:
                    QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
                    return

            self.conn.rollback()

            with self.conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        schemaname || '.' || relname AS table_name,
                        indexrelname AS index_name,
                        idx_scan AS used_times,
                        COALESCE(idx_tup_read, 0) AS tuples_read,
                        COALESCE(idx_tup_fetch, 0) AS tuples_fetched,
                        pg_size_pretty(pg_relation_size(indexrelid)) AS size,
                        pg_relation_size(indexrelid) AS size_bytes,
                        CASE 
                            WHEN idx_scan = 0 THEN 'Не используется'
                            WHEN idx_scan < 100 THEN 'Редко используется'
                            ELSE 'Активно используется'
                        END AS status
                    FROM
                        pg_stat_user_indexes
                    WHERE
                        schemaname = %s
                    ORDER BY
                        idx_scan ASC, pg_relation_size(indexrelid) DESC
                """,
                    (schema_name,),
                )
                results = cursor.fetchall()

                self.conn.commit()

                self.indexes_table.setSortingEnabled(False)
                self.indexes_table.setRowCount(len(results))

                for row_idx, row in enumerate(results):
                    (
                        table_name,
                        index_name,
                        used_times,
                        tuples_read,
                        tuples_fetched,
                        size,
                        size_bytes,
                        status,
                    ) = row

                    items = [
                        QTableWidgetItem(table_name),
                        QTableWidgetItem(index_name),
                        SortableTableWidgetItem(str(used_times), int(used_times or 0)),
                        QTableWidgetItem(size),
                        SortableTableWidgetItem(status, index_recommendation_rank(status)),
                    ]

                    if status == "Не используется":
                        bg_color = QColor("#ff9999")
                        color_name = "critical"
                    elif status == "Редко используется":
                        bg_color = QColor("#ffff99")
                        color_name = "warning"
                    else:
                        bg_color = QColor("#ccffcc")
                        color_name = "ok"

                    for col_idx, item in enumerate(items):
                        item.setBackground(bg_color)
                        item.setForeground(QColor("#000000"))
                        item.setData(Qt.UserRole, color_name)
                        self.indexes_table.setItem(row_idx, col_idx, item)

                    self.indexes_table.item(row_idx, 0).setData(
                        Qt.UserRole + 1,
                        {
                            "table_name": table_name,
                            "index_name": index_name,
                            "used_times": used_times,
                            "tuples_read": tuples_read,
                            "tuples_fetched": tuples_fetched,
                            "size_bytes": size_bytes,
                            "status": status,
                            "schema": schema_name,
                            "db": db_name,
                        },
                    )

                self.indexes_table.setSortingEnabled(True)

                header = self.indexes_table.horizontalHeader()
                for slot in (self.preserve_row_colors, self.preserve_index_analysis_colors):
                    try:
                        header.sortIndicatorChanged.disconnect(slot)
                    except (TypeError, RuntimeError):
                        pass
                header.sortIndicatorChanged.connect(self.preserve_index_analysis_colors)

                self.process_output.append(f"Проанализировано {len(results)} индексов.")

        except Exception as e:
            error_msg = str(e)
            logging.error(f"Ошибка анализа индексов: {error_msg}")

            try:
                self.conn.rollback()
            except Exception:
                pass

            QMessageBox.critical(
                self, "Ошибка", f"Не удалось проанализировать индексы:\n{error_msg}"
            )

    def preserve_index_analysis_colors(self):
        try:
            for row in range(self.indexes_table.rowCount()):
                first_item = self.indexes_table.item(row, 0)
                if first_item:
                    color_name = first_item.data(Qt.UserRole)
                    if color_name == "critical":
                        bg_color = QColor("#ff9999")
                    elif color_name == "warning":
                        bg_color = QColor("#ffff99")
                    elif color_name == "ok":
                        bg_color = QColor("#ccffcc")
                    else:
                        continue

                    for col in range(self.indexes_table.columnCount()):
                        item = self.indexes_table.item(row, col)
                        if item:
                            item.setBackground(bg_color)
                            item.setForeground(QColor("#000000"))
        except Exception as e:
            logging.error(f"Ошибка сохранения цветов строк при анализе индексов: {e}")

    def create_statistics_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        toolbar = QToolBar()
        toolbar.setIconSize(QSize(16, 16))
        toolbar.setStyleSheet("""
            QToolBar {
                background-color: #333;
                border: none;
                padding: 2px;
            }
        """)

        check_stats_button = QPushButton(
            icon("fa5s.clock", color="white"), "Проверка устаревшей статистики"
        )
        check_stats_button.setToolTip(
            "Проверить, какие таблицы требуют обновления статистики (только чтение)"
        )
        check_stats_button.clicked.connect(self.check_outdated_statistics)
        check_stats_button.setStyleSheet("""
            QPushButton {
                background-color: #2d5a8a;
                color: white;
                border: 1px solid #3a7bd5;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #3a6a9a;
            }
        """)
        toolbar.addWidget(check_stats_button)

        separator = QWidget()
        separator.setFixedWidth(5)
        toolbar.addWidget(separator)

        update_stats_button = QPushButton(
            icon("fa5s.sync", color="white"), "Обновить статистику (ANALYZE)"
        )
        update_stats_button.setToolTip(
            "ВНИМАНИЕ: Обновляет статистику для всех таблиц. Может создать нагрузку."
        )
        update_stats_button.clicked.connect(self.update_statistics)
        update_stats_button.setStyleSheet("""
            QPushButton {
                background-color: #8a4d2d;
                color: white;
                border: 1px solid #ff8a65;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #9a5d3d;
            }
        """)
        toolbar.addWidget(update_stats_button)

        separator2 = QWidget()
        separator2.setFixedWidth(5)
        toolbar.addWidget(separator2)

        capture_baseline_button = QPushButton(icon("fa5s.camera", color="white"), "Снять baseline")
        capture_baseline_button.setToolTip(
            "Сохранить текущий снимок maintenance-метрик для сравнения before/after."
        )
        capture_baseline_button.clicked.connect(self.capture_maintenance_baseline)
        capture_baseline_button.setStyleSheet("""
            QPushButton {
                background-color: #355c7d;
                color: white;
                border: 1px solid #4a8be5;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #446d90;
            }
        """)
        toolbar.addWidget(capture_baseline_button)

        compare_baseline_button = QPushButton(
            icon("fa5s.balance-scale", color="white"), "Сравнить с baseline"
        )
        compare_baseline_button.setToolTip(
            "Показать эффект обслуживания БД: сравнение текущих метрик и baseline."
        )
        compare_baseline_button.clicked.connect(self.compare_maintenance_with_baseline)
        compare_baseline_button.setStyleSheet("""
            QPushButton {
                background-color: #355c7d;
                color: white;
                border: 1px solid #4a8be5;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #446d90;
            }
        """)
        toolbar.addWidget(compare_baseline_button)

        export_compare_button = QPushButton(
            icon("fa5s.file-export", color="white"), "Экспорт Before/After .md"
        )
        export_compare_button.setToolTip(
            "Экспорт последнего сравнения before/after обслуживания БД в Markdown."
        )
        export_compare_button.clicked.connect(self.export_maintenance_compare_markdown)
        export_compare_button.setStyleSheet("""
            QPushButton {
                background-color: #355c7d;
                color: white;
                border: 1px solid #4a8be5;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #446d90;
            }
        """)
        toolbar.addWidget(export_compare_button)

        layout.addWidget(toolbar)

        self.statistics_table = QTableWidget()
        self.statistics_table.setColumnCount(5)
        self.statistics_table.setHorizontalHeaderLabels(
            [
                "Схема.Таблица",
                "Изменений после анализа",
                "Последний анализ",
                "Размер",
                "Рекомендация",
            ]
        )
        self.statistics_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                gridline-color: #444;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #e0e0e0;
                padding: 5px;
                border: 1px solid #444;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #3a7bd5;
            }
        """)

        header = self.statistics_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)

        self.statistics_table.setSortingEnabled(True)
        layout.addWidget(self.statistics_table)

        self.statistics_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.statistics_table.customContextMenuRequested.connect(self.show_statistics_context_menu)

        return tab

    def check_outdated_statistics(self):
        if not self.connection_status or not hasattr(self, "conn"):
            QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
            return

        db_name = self.db_combo.currentText()
        schema_name = self.schema_combo.currentText()

        if not db_name or not schema_name:
            QMessageBox.warning(self, "Ошибка", "Выберите базу данных и схему")
            return

        self.process_output.clear()
        self.process_output.append(
            f"Проверка состояния статистики в базе данных {db_name}, схема {schema_name}..."
        )

        warning_threshold = self.analyzer_settings.get("thresholds", {}).get(
            "mod_since_analyze_warning", 10000
        )
        critical_threshold = self.analyzer_settings.get("thresholds", {}).get(
            "mod_since_analyze_critical", 100000
        )

        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        schemaname || '.' || relname AS table_name,
                        n_mod_since_analyze AS changes_since_analyze,
                        COALESCE(last_analyze::text, 'Никогда') AS last_analyze,
                        pg_size_pretty(pg_relation_size(relid)) AS size,
                        CASE
                            WHEN n_mod_since_analyze > %s THEN 'Срочно требуется ANALYZE'
                            WHEN n_mod_since_analyze > %s THEN 'Рекомендуется ANALYZE'
                            ELSE 'Статистика актуальна'
                        END AS recommendation
                    FROM
                        pg_stat_user_tables
                    WHERE
                        schemaname = %s
                    ORDER BY
                        n_mod_since_analyze DESC
                """,
                    (critical_threshold, warning_threshold, schema_name),
                )
                results = cursor.fetchall()

                critical_count = 0
                warning_count = 0
                ok_count = 0
                critical_tables = []
                warning_tables = []

                self.statistics_table.setRowCount(len(results))
                for row_idx, row in enumerate(results):
                    table_name, changes, last_analyze, size, recommendation = row

                    if recommendation == "Срочно требуется ANALYZE":
                        critical_count += 1
                        critical_tables.append(table_name)
                        bg_color = QColor("#ff9999")
                        fg_color = QColor("#000000")
                    elif recommendation == "Рекомендуется ANALYZE":
                        warning_count += 1
                        warning_tables.append(table_name)
                        bg_color = QColor("#ffcccc")
                        fg_color = QColor("#000000")
                    else:
                        ok_count += 1
                        bg_color = QColor("#ccffcc")
                        fg_color = QColor("#000000")

                    items = [
                        QTableWidgetItem(table_name),
                        QTableWidgetItem(str(changes)),
                        QTableWidgetItem(last_analyze),
                        QTableWidgetItem(size),
                        QTableWidgetItem(recommendation),
                    ]

                    for col_idx, item in enumerate(items):
                        item.setBackground(bg_color)
                        item.setForeground(fg_color)
                        self.statistics_table.setItem(row_idx, col_idx, item)

                self.process_output.append("")
                self.process_output.append("=" * 60)
                self.process_output.append("РЕЗУЛЬТАТЫ ПРОВЕРКИ СТАТИСТИКИ:")
                self.process_output.append(f"  📊 Всего проверено таблиц: {len(results)}")
                self.process_output.append(f"  🔴 Требуют срочного ANALYZE: {critical_count}")
                self.process_output.append(f"  🟡 Рекомендуется ANALYZE: {warning_count}")
                self.process_output.append(f"  🟢 Статистика актуальна: {ok_count}")
                self.process_output.append("=" * 60)

                if critical_count > 0:
                    self.process_output.append(
                        "⚠️ ВНИМАНИЕ: Некоторые таблицы требуют срочного обновления статистики!"
                    )
                    self.process_output.append(
                        "   Выполните ANALYZE для этих таблиц для улучшения планов запросов."
                    )
                elif warning_count > 0:
                    self.process_output.append(
                        "ℹ️ Рекомендуется выполнить ANALYZE для отмеченных таблиц."
                    )
                else:
                    self.process_output.append("✅ Статистика всех таблиц в хорошем состоянии.")

                self._maintenance_snapshot_current["statistics"] = {
                    "tables_total": len(results),
                    "critical": critical_count,
                    "warning": warning_count,
                    "ok": ok_count,
                    "critical_tables": critical_tables[:30],
                    "warning_tables": warning_tables[:30],
                }
                self._update_maintenance_debt_widget()

        except Exception as e:
            logging.error(f"Ошибка проверки устаревшей статистики: {e}")
            QMessageBox.critical(
                self, "Ошибка", f"Не удалось проверить устаревшую статистику:\n{str(e)}"
            )

    def update_statistics(self):
        if not self.connection_status or not hasattr(self, "conn"):
            QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
            return

        db_name = self.db_combo.currentText()
        schema_name = self.schema_combo.currentText()

        if not db_name or not schema_name:
            QMessageBox.warning(self, "Ошибка", "Выберите базу данных и схему")
            return

        reply = QMessageBox.question(
            self,
            "Подтверждение обновления статистики",
            f"ВНИМАНИЕ! Вы собираетесь обновить статистику для всех таблиц в схеме '{schema_name}'.\n\n"
            "Это действие:\n"
            "• Может создать дополнительную нагрузку на базу данных\n"
            "• Может занять некоторое время\n\n"
            "Обновление статистики улучшает качество планов запросов.\n\n"
            "Вы уверены, что хотите продолжить?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply != QMessageBox.Yes:
            return

        self.process_output.clear()
        self.process_output.append(
            f"Обновление статистики всех таблиц в базе данных {db_name}, схема {schema_name}..."
        )
        # ANALYZE can run long and wait on locks; run off UI thread.
        timeout_ms = int(
            self.analyzer_settings.get("analysis", {}).get("statistics_analyze_timeout_ms", 120000)
        )
        self.process_output.append(
            f"Запущено в фоне. Таймаут на таблицу: {max(1000, timeout_ms)} мс."
        )

        self.execute_button.setEnabled(False)
        self.progress_bar.show()
        self.progress_animation.start()

        conn_params = {
            **StoredConnectionSettings.connect_kwargs(self.current_connection),
            "dbname": db_name,
        }
        self.update_stats_thread = CallableWorkerThread(
            functools.partial(
                self._update_statistics_worker,
                conn_params,
                schema_name,
                max(1000, timeout_ms),
            ),
            self,
        )
        self.update_stats_thread.completed.connect(self._on_update_statistics_done)
        self.update_stats_thread.start()

    def _update_statistics_worker(
        self, connection_params: dict[str, Any], schema_name: str, timeout_ms: int
    ) -> dict[str, Any]:
        analyzed: list[str] = []
        failed: list[dict[str, str]] = []
        with psycopg2.connect(**connection_params) as conn:
            conn.autocommit = True
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT tablename
                    FROM pg_tables
                    WHERE schemaname = %s
                    ORDER BY tablename
                    """,
                    (schema_name,),
                )
                tables = [row[0] for row in cursor.fetchall()]
                if not tables:
                    return {"tables_total": 0, "analyzed": analyzed, "failed": failed}

                for table_name in tables:
                    try:
                        cursor.execute(f"SET statement_timeout = {int(timeout_ms)}")
                        cursor.execute(
                            sql.SQL("ANALYZE {}").format(sql.Identifier(schema_name, table_name))
                        )
                        analyzed.append(table_name)
                    except Exception as e:
                        failed.append({"table": table_name, "error": str(e)})
                        logging.warning(
                            "ANALYZE failed for %s.%s: %s", schema_name, table_name, str(e)
                        )
                        try:
                            conn.rollback()
                        except Exception:
                            pass
        return {"tables_total": len(analyzed) + len(failed), "analyzed": analyzed, "failed": failed}

    def _on_update_statistics_done(self, ok: bool, payload: Any) -> None:
        self.update_stats_thread = None
        self.progress_bar.hide()
        self.progress_animation.stop()
        self.execute_button.setEnabled(True)

        if not ok:
            logging.error(f"Ошибка обновления статистики (worker): {payload}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось обновить статистику:\n{payload}")
            return

        tables_total = int(payload.get("tables_total", 0))
        analyzed = payload.get("analyzed", []) or []
        failed = payload.get("failed", []) or []

        if tables_total == 0:
            QMessageBox.information(
                self, "ANALYZE", "В выбранной схеме не найдено таблиц для ANALYZE."
            )
            return

        for table_name in analyzed:
            self.process_output.append(f"ANALYZE выполнен для таблицы {table_name}")
        if failed:
            self.process_output.append("")
            self.process_output.append("Таблицы с ошибками/таймаутом:")
            for row in failed[:50]:
                self.process_output.append(f"- {row.get('table')}: {row.get('error')}")
            if len(failed) > 50:
                self.process_output.append(f"... и ещё {len(failed) - 50}")

        self.process_output.append("")
        self.process_output.append(
            f"Итог: успешно {len(analyzed)} из {tables_total}, ошибок {len(failed)}."
        )

        self._maintenance_snapshot_current["analyze_run"] = {
            "tables_total": tables_total,
            "analyzed": len(analyzed),
            "failed": len(failed),
        }

        if failed:
            QMessageBox.warning(
                self,
                "ANALYZE завершён частично",
                f"Успешно: {len(analyzed)} / {tables_total}\n"
                f"Ошибок/таймаутов: {len(failed)}\n"
                "Подробности в нижнем логе.",
            )
        else:
            QMessageBox.information(
                self,
                "Успех",
                f"Статистика успешно обновлена для {len(analyzed)} таблиц.",
            )

    def update_statistics_for_table(self, index):
        if not self.connection_status or not hasattr(self, "conn"):
            QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
            return

        table_info = self.statistics_table.item(index.row(), 0).text()
        schema, table = table_info.split(".")

        self.process_output.append(f"Начинается обновление статистики для таблицы {table_info}...")

        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("ANALYZE {}.{}").format(sql.Identifier(schema), sql.Identifier(table))
                )
                self.conn.commit()
                self.process_output.append(
                    f"Успешно обновлена статистика для таблицы {table_info}."
                )
                QMessageBox.information(
                    self, "Успех", f"Статистика для таблицы {table_info} обновлена."
                )
        except Exception as e:
            logging.error(f"Ошибка обновления статистики: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось обновить статистику:\n{str(e)}")

    def show_statistics_context_menu(self, point):
        global_point = self.statistics_table.mapToGlobal(point)
        menu = QMenu()

        index = self.statistics_table.indexAt(point)
        if index.isValid():
            action_update_stats = QAction("Обновить статистику для таблицы", self)
            action_update_stats.triggered.connect(lambda: self.update_statistics_for_table(index))
            menu.addAction(action_update_stats)

        menu.exec(global_point)

    def create_vacuum_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        toolbar = QToolBar()
        toolbar.setIconSize(QSize(16, 16))
        toolbar.setStyleSheet("""
            QToolBar {
                background-color: #333;
                border: none;
                padding: 2px;
            }
        """)

        analyze_vacuum_button = QPushButton(
            icon("fa5s.search", color="white"), "Анализ необходимости VACUUM"
        )
        analyze_vacuum_button.setToolTip("Проверить, какие таблицы требуют VACUUM (только чтение)")
        analyze_vacuum_button.clicked.connect(self.check_last_vacuum)
        analyze_vacuum_button.setStyleSheet("""
            QPushButton {
                background-color: #2d5a8a;
                color: white;
                border: 1px solid #3a7bd5;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #3a6a9a;
            }
        """)
        toolbar.addWidget(analyze_vacuum_button)

        separator = QWidget()
        separator.setFixedWidth(5)
        toolbar.addWidget(separator)

        run_vacuum_button = QPushButton(icon("fa5s.broom", color="white"), "Выполнить VACUUM")
        run_vacuum_button.setToolTip(
            "ВНИМАНИЕ: Выполняет VACUUM для выбранной схемы. Может создать нагрузку и заблокировать таблицы."
        )
        run_vacuum_button.clicked.connect(self.run_vacuum)
        run_vacuum_button.setStyleSheet("""
            QPushButton {
                background-color: #8a4d2d;
                color: white;
                border: 1px solid #ff8a65;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #9a5d3d;
            }
        """)
        toolbar.addWidget(run_vacuum_button)

        layout.addWidget(toolbar)

        self.vacuum_table = QTableWidget()
        self.vacuum_table.setColumnCount(5)
        self.vacuum_table.setHorizontalHeaderLabels(
            ["Схема.Таблица", "Последний VACUUM", "Мертвые строки", "% мертвых строк", "Статус"]
        )
        self.vacuum_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                gridline-color: #444;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #e0e0e0;
                padding: 5px;
                border: 1px solid #444;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)

        header = self.vacuum_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)

        self.vacuum_table.setSortingEnabled(True)
        layout.addWidget(self.vacuum_table)

        return tab

    def check_last_vacuum(self):
        if not self.connection_status or not hasattr(self, "conn"):
            QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
            return

        db_name = self.db_combo.currentText()
        schema_name = self.schema_combo.currentText()

        if not db_name or not schema_name:
            QMessageBox.warning(self, "Ошибка", "Выберите базу данных и схему")
            return

        self.process_output.clear()
        self.process_output.append(
            f"Проверка вакуумирования в базе данных {db_name}, схема {schema_name}..."
        )

        dead_tup_threshold = self.analyzer_settings.get("thresholds", {}).get(
            "dead_tup_percent", 20
        )

        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT 
                        schemaname || '.' || relname AS table_name,
                        COALESCE(last_vacuum::text, 'Никогда') as last_vacuum,
                        n_dead_tup,
                        CASE 
                            WHEN n_live_tup + n_dead_tup > 0 
                            THEN ROUND((n_dead_tup::float / (n_live_tup + n_dead_tup) * 100)::numeric, 1)
                            ELSE 0
                        END as dead_tup_percent,
                        CASE 
                            WHEN n_dead_tup > 0 AND (n_dead_tup::float / NULLIF(n_live_tup + n_dead_tup, 0) * 100) > %s
                            THEN '⚠️ Требуется VACUUM'
                            WHEN last_vacuum IS NULL THEN '⚠️ VACUUM не выполнялся'
                            ELSE '✅ В порядке'
                        END as status
                    FROM pg_stat_user_tables
                    WHERE schemaname = %s
                    ORDER BY dead_tup_percent DESC
                """,
                    (dead_tup_threshold, schema_name),
                )
                results = cursor.fetchall()

                self.vacuum_table.setRowCount(len(results))

                for row_idx, row in enumerate(results):
                    table_name, last_vacuum, n_dead_tup, dead_tup_percent, status = row

                    if status == "⚠️ Требуется VACUUM":
                        bg_color = QColor("#ff9999")
                    elif status == "⚠️ VACUUM не выполнялся":
                        bg_color = QColor("#ffcccc")
                    else:
                        bg_color = QColor("#ccffcc")

                    items = [
                        QTableWidgetItem(table_name),
                        QTableWidgetItem(last_vacuum),
                        QTableWidgetItem(str(n_dead_tup)),
                        QTableWidgetItem(f"{dead_tup_percent}%"),
                        QTableWidgetItem(status),
                    ]

                    for col_idx, item in enumerate(items):
                        item.setBackground(bg_color)
                        item.setForeground(QColor("#000000"))
                        self.vacuum_table.setItem(row_idx, col_idx, item)

                self.process_output.append(f"Проанализировано {len(results)} таблиц.")

                require_vacuum = sum(1 for row in results if str(row[4]) == "⚠️ Требуется VACUUM")
                never_vacuum = sum(1 for row in results if str(row[4]) == "⚠️ VACUUM не выполнялся")
                self._maintenance_snapshot_current["vacuum"] = {
                    "tables_total": len(results),
                    "require_vacuum": require_vacuum,
                    "never_vacuum": never_vacuum,
                    "require_vacuum_tables": [
                        str(row[0]) for row in results if str(row[4]) == "⚠️ Требуется VACUUM"
                    ][:30],
                    "never_vacuum_tables": [
                        str(row[0]) for row in results if str(row[4]) == "⚠️ VACUUM не выполнялся"
                    ][:30],
                }
                self._update_maintenance_debt_widget()

        except Exception as e:
            logging.error(f"Ошибка проверки вакуумирования: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось проверить вакуумирование:\n{str(e)}")

    def _update_maintenance_debt_widget(self):
        stats = self._maintenance_snapshot_current.get("statistics", {}) or {}
        vac = self._maintenance_snapshot_current.get("vacuum", {}) or {}

        critical = int(stats.get("critical", 0))
        warning = int(stats.get("warning", 0))
        require_vacuum = int(vac.get("require_vacuum", 0))
        never_vacuum = int(vac.get("never_vacuum", 0))

        score = min(100, critical * 15 + warning * 6 + require_vacuum * 10 + never_vacuum * 8)
        if score >= 70:
            color = "#e57373"
            level = "HIGH"
        elif score >= 40:
            color = "#ffb74d"
            level = "MEDIUM"
        else:
            color = "#81c784"
            level = "LOW"

        top_issues = []
        if critical:
            top_issues.append(f"critical ANALYZE: {critical}")
        if require_vacuum:
            top_issues.append(f"VACUUM required: {require_vacuum}")
        if never_vacuum:
            top_issues.append(f"never vacuumed: {never_vacuum}")
        if warning:
            top_issues.append(f"warning ANALYZE: {warning}")
        issues_text = ", ".join(top_issues[:4]) if top_issues else "явных долгов не найдено"

        self.maintenance_debt_label.setText(
            "Maintenance debt score: "
            f"<span style='color:{color}; font-weight:bold;'>{score}/100 ({level})</span><br>"
            f"Top debt: {issues_text}"
        )

    def capture_maintenance_baseline(self):
        if not self._maintenance_snapshot_current:
            QMessageBox.information(
                self,
                "Baseline",
                "Нет текущего снимка. Сначала выполните проверку статистики и/или VACUUM.",
            )
            return
        self._maintenance_snapshot_baseline = json.loads(
            json.dumps(self._maintenance_snapshot_current, ensure_ascii=False)
        )
        self.process_output.append("")
        self.process_output.append("[Before/After] Baseline maintenance-снимок сохранён.")
        QMessageBox.information(self, "Baseline", "Baseline для обслуживания БД сохранён.")

    def compare_maintenance_with_baseline(self):
        if not self._maintenance_snapshot_baseline:
            QMessageBox.information(
                self,
                "Before/After",
                "Baseline не сохранён. Нажмите «Снять baseline» после первичной проверки.",
            )
            return
        if not self._maintenance_snapshot_current:
            QMessageBox.information(
                self,
                "Before/After",
                "Нет текущего снимка для сравнения.",
            )
            return

        b_stats = self._maintenance_snapshot_baseline.get("statistics", {}) or {}
        c_stats = self._maintenance_snapshot_current.get("statistics", {}) or {}
        b_vac = self._maintenance_snapshot_baseline.get("vacuum", {}) or {}
        c_vac = self._maintenance_snapshot_current.get("vacuum", {}) or {}

        def delta_line(title: str, before: int, current: int) -> str:
            delta = current - before
            sign = "+" if delta > 0 else ""
            trend = "улучшение" if delta < 0 else "ухудшение" if delta > 0 else "без изменений"
            return f"{title}: {before} -> {current} ({sign}{delta}, {trend})"

        lines = [
            "[Before/After] Эффект обслуживания БД:",
            delta_line(
                "critical ANALYZE", int(b_stats.get("critical", 0)), int(c_stats.get("critical", 0))
            ),
            delta_line(
                "warning ANALYZE", int(b_stats.get("warning", 0)), int(c_stats.get("warning", 0))
            ),
            delta_line(
                "VACUUM required",
                int(b_vac.get("require_vacuum", 0)),
                int(c_vac.get("require_vacuum", 0)),
            ),
            delta_line(
                "never vacuumed",
                int(b_vac.get("never_vacuum", 0)),
                int(c_vac.get("never_vacuum", 0)),
            ),
        ]
        self._maintenance_last_compare_lines = list(lines)
        self.process_output.append("")
        self.process_output.append("=" * 60)
        for line in lines:
            self.process_output.append(line)
        self.process_output.append("=" * 60)

    def export_maintenance_compare_markdown(self):
        if not self._maintenance_last_compare_lines:
            QMessageBox.information(
                self,
                "Экспорт Before/After",
                "Нет данных сравнения. Сначала выполните «Сравнить с baseline».",
            )
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт Before/After",
            "maintenance_before_after.md",
            "Markdown (*.md)",
        )
        if not path:
            return
        lines = ["# Before/After: Обслуживание БД", ""]
        lines.extend(f"- {line}" for line in self._maintenance_last_compare_lines[1:])
        lines.append("")
        lines.append("## Debt Snapshot")
        debt_map = self.get_maintenance_debt_map()
        if debt_map:
            for table_name, tags in sorted(debt_map.items())[:80]:
                lines.append(f"- `{table_name}`: {', '.join(sorted(tags))}")
        else:
            lines.append("- Нет debt-таблиц в текущем снимке.")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception as e:
            QMessageBox.critical(self, "Экспорт Before/After", f"Не удалось сохранить файл:\n{e}")
            return
        QMessageBox.information(self, "Экспорт Before/After", f"Сохранено:\n{path}")

    def get_maintenance_debt_map(self):
        debt = {}
        stats = self._maintenance_snapshot_current.get("statistics", {}) or {}
        vac = self._maintenance_snapshot_current.get("vacuum", {}) or {}
        for table_name in stats.get("critical_tables", []) or []:
            debt.setdefault(str(table_name), set()).add("critical_analyze")
        for table_name in stats.get("warning_tables", []) or []:
            debt.setdefault(str(table_name), set()).add("warning_analyze")
        for table_name in vac.get("require_vacuum_tables", []) or []:
            debt.setdefault(str(table_name), set()).add("require_vacuum")
        for table_name in vac.get("never_vacuum_tables", []) or []:
            debt.setdefault(str(table_name), set()).add("never_vacuum")
        return debt

    def update_node_info(self, info):
        try:
            if isinstance(info, str):
                node_info = json.loads(info)
            else:
                node_info = info

            html_content = self.create_node_info_html(
                node_info.get("type", "Unknown"),
                node_info.get("properties", {}),
                node_info.get("cost", 0),
                self.total_cost,
                node_info.get("rows", 0),
            )

            self.node_info_text.setHtml(html_content)
            self.node_info_label.setText(
                f"Информация о выбранном узле: {node_info.get('type', 'Unknown')}"
            )
        except Exception as e:
            logging.error(f"Ошибка при обновлении информации о узле: {e}")
            self.node_info_text.setPlainText(f"Ошибка: {str(e)}")

    def analyze_query_plan(self):
        try:
            if not hasattr(self, "_analyze_highlighters"):
                self._analyze_highlighters = []
            else:
                self._analyze_highlighters.clear()

            if not hasattr(self, "tab_data_cache"):
                self.tab_data_cache = {
                    "visualizer": {"general": "", "optimization": "", "has_data": False},
                    "scanner": {"general": "", "optimization": "", "has_data": False},
                    "db_optimization": {"general": "", "optimization": "", "has_data": False},
                }

            xml_content = getattr(self, "xml_content", None)
            if not xml_content:
                self._pending_journal_queryid = None
                self._pending_journal_plan_origin = None
                self._pending_hypopg_pair_group_id = None
                self._pending_hypopg_pair_role = None
                QMessageBox.warning(
                    self, "Ошибка", "Пожалуйста, загрузите план запроса (XML или JSON)"
                )
                return

            pending_statement_queryid = getattr(self, "_pending_journal_queryid", None)
            self._pending_journal_queryid = None

            pending_plan_origin = getattr(self, "_pending_journal_plan_origin", None)
            self._pending_journal_plan_origin = None
            if pending_plan_origin is None:
                pending_plan_origin = (
                    "file" if getattr(self, "last_opened_file", None) else "explain"
                )

            pending_pair_gid = getattr(self, "_pending_hypopg_pair_group_id", None)
            pending_pair_role = getattr(self, "_pending_hypopg_pair_role", None)
            self._pending_hypopg_pair_group_id = None
            self._pending_hypopg_pair_role = None

            query_text = self.query_input.text() if hasattr(self, "query_input") else ""
            self.save_to_journal(
                xml_content,
                query_text,
                statement_queryid=pending_statement_queryid,
                plan_origin=pending_plan_origin,
                hypopg_pair_group_id=pending_pair_gid,
                hypopg_pair_role=pending_pair_role,
            )
            if pending_pair_gid and pending_pair_role:
                self._refresh_journal_window_if_open()

            plan_tree = self.parse_xml_plan(xml_content)
            if not plan_tree:
                QMessageBox.warning(self, "Ошибка", "Не удалось разобрать план запроса")
                return

            graph_data = self.create_graph_data_from_plan(plan_tree)
            if not graph_data.get("nodes"):
                QMessageBox.warning(self, "Ошибка", "Нет данных для визуализации")
                return

            analysis = self.analyze_plan_structure(plan_tree)
            self.display_analysis_results(analysis)

            if hasattr(self, "tab_data_cache"):
                if hasattr(self, "general_analysis_text"):
                    self.tab_data_cache["visualizer"][
                        "general"
                    ] = self.general_analysis_text.toHtml()
                if hasattr(self, "optimization_text"):
                    self.tab_data_cache["visualizer"][
                        "optimization"
                    ] = self.optimization_text.toHtml()
                self.tab_data_cache["visualizer"]["has_data"] = True

            if hasattr(self, "initial_content"):
                self.initial_content.hide()

            def remove_circular_refs(obj):
                if isinstance(obj, dict):
                    return {
                        k: remove_circular_refs(v)
                        for k, v in obj.items()
                        if k not in ["parent", "children"]
                    }
                elif isinstance(obj, list):
                    return [remove_circular_refs(item) for item in obj]
                else:
                    return str(obj) if not isinstance(obj, (str, int, float, bool)) else obj

            clean_graph_data = remove_circular_refs(graph_data)
            if not clean_graph_data.get("nodes"):
                raise ValueError("Нет узлов для визуализации")

            self._plan_graph_metadata = {
                str(n.get("id")): n for n in clean_graph_data.get("nodes", [])
            }
            self._visible_outline_snapshot = None

            most_expensive_node_info = (
                self.most_expensive_node_info
                if isinstance(self.most_expensive_node_info, dict)
                else {}
            )
            clean_node_info = remove_circular_refs(most_expensive_node_info)

            if hasattr(self, "visualizer_window"):
                self.visualizer_layout.removeWidget(self.visualizer_window)
                self.visualizer_window.deleteLater()
                del self.visualizer_window

            self.visualizer_window = PlanVisualizerWindow(
                clean_graph_data,
                self.update_node_info,
                None,
                json.dumps(clean_node_info, default=str) if clean_node_info else None,
                self.analyzer_settings,
                self._on_visible_graph_outline,
            )
            self.visualizer_layout.addWidget(self.visualizer_window, 1)
            self.visualizer_window.show()

        except Exception as e:
            logging.error(f"Ошибка при анализе плана запроса: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось обработать план запроса:\n{str(e)}")

    def display_analysis_results(self, analysis):
        if hasattr(self, "general_analysis_text"):
            self.general_analysis_text.setHtml(self.convert_to_html(analysis["general"]))

        if hasattr(self, "optimization_text"):
            self.optimization_text.setHtml(self.convert_to_html(analysis["optimization"]))

        if not hasattr(self, "settings_text"):
            self.settings_text = ClickableTextBrowser()
            self.settings_text.setStyleSheet("""
                QTextBrowser {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: 1px solid #444;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    font-size: 12px;
                }
            """)

        if hasattr(self, "settings_text"):
            self.settings_text.setHtml(self.convert_to_html(analysis["settings"]))

        if hasattr(self, "tab_data_cache"):
            if hasattr(self, "general_analysis_text"):
                self.tab_data_cache["visualizer"]["general"] = self.general_analysis_text.toHtml()
            if hasattr(self, "optimization_text"):
                self.tab_data_cache["visualizer"]["optimization"] = self.optimization_text.toHtml()
            self.tab_data_cache["visualizer"]["has_data"] = True

    def _build_ai_plan_payload(self, plan_tree):
        max_nodes = 24
        nodes = []

        def visit(node, depth=0):
            if not isinstance(node, dict) or len(nodes) >= max_nodes or depth > 4:
                return
            nodes.append(
                {
                    "depth": depth,
                    "node_type": node.get("Node Type"),
                    "relation_name": node.get("Relation Name"),
                    "join_type": node.get("Join Type"),
                    "startup_cost": node.get("Startup Cost"),
                    "total_cost": node.get("Total Cost"),
                    "plan_rows": node.get("Plan Rows"),
                    "actual_rows": node.get("Actual Rows"),
                    "shared_read_blocks": node.get("Shared Read Blocks"),
                    "temp_written_blocks": node.get("Temp Written Blocks"),
                }
            )
            for child in (node.get("Plans") or [])[:6]:
                visit(child, depth + 1)

        visit(plan_tree, 0)
        query_text = self.query_input.text().strip() if hasattr(self, "query_input") else ""
        ai_settings = (self.analyzer_settings or {}).get("ai", {})
        if ai_settings.get("mask_sql_literals", True):
            query_text = self._mask_sql_literals(query_text)
        return {
            "query_text_preview": query_text[:1200],
            "plan_root": {
                "node_type": plan_tree.get("Node Type"),
                "total_cost": plan_tree.get("Total Cost"),
                "plan_rows": plan_tree.get("Plan Rows"),
                "actual_rows": plan_tree.get("Actual Rows"),
            },
            "top_nodes": nodes,
            "rule_based_general_preview": (
                self.general_analysis_text.toPlainText()[:3500]
                if hasattr(self, "general_analysis_text")
                else ""
            ),
            "rule_based_recommendations_preview": (
                self.optimization_text.toPlainText()[:3500]
                if hasattr(self, "optimization_text")
                else ""
            ),
        }

    @staticmethod
    def _mask_sql_literals(sql_text: str) -> str:
        if not sql_text:
            return ""
        # Replace single-quoted strings (including escaped quotes) and standalone numbers.
        masked = re.sub(r"'(?:''|[^'])*'", "'***'", sql_text)
        masked = re.sub(r"\b\d+(?:\.\d+)?\b", "?", masked)
        return masked

    def explain_current_plan_with_ai(self):
        try:
            if self._ai_plan_worker is not None:
                QMessageBox.information(self, "AI", "AI-интерпретация уже выполняется.")
                return

            xml_content = getattr(self, "xml_content", None)
            if not xml_content:
                QMessageBox.warning(
                    self, "AI", "Нет текущего плана. Сначала выполните анализ плана запроса."
                )
                return

            ai_settings = (self.analyzer_settings or {}).get("ai", {})
            if not ai_settings.get("enabled", False):
                QMessageBox.warning(
                    self,
                    "AI",
                    "AI-интерпретатор выключен. Включите его в Настройки анализатора -> AI / OpenRouter.",
                )
                return

            provider = (ai_settings.get("provider") or "").strip().lower()
            if provider != "openrouter":
                QMessageBox.warning(self, "AI", "Сейчас поддерживается только provider=openrouter.")
                return

            base_url = (ai_settings.get("base_url") or "https://openrouter.ai/api/v1").strip()
            model = (ai_settings.get("model") or "").strip()
            api_key = (ai_settings.get("api_key") or "").strip()
            if not api_key or not model:
                QMessageBox.warning(
                    self,
                    "AI",
                    "Заполните поля API key и Модель в Настройки анализатора -> AI / OpenRouter.",
                )
                return

            plan_tree = self.parse_xml_plan(xml_content)
            if not isinstance(plan_tree, dict):
                QMessageBox.warning(self, "AI", "Не удалось подготовить план для AI-интерпретации.")
                return

            payload = self._build_ai_plan_payload(plan_tree)
            cache_enabled = ai_settings.get("cache_enabled", True)
            cache_key = ""
            if cache_enabled:
                cache_blob = json.dumps(
                    {
                        "provider": provider,
                        "base_url": base_url,
                        "model": model,
                        "payload": payload,
                    },
                    sort_keys=True,
                    ensure_ascii=False,
                    default=str,
                )
                cache_key = hashlib.sha256(cache_blob.encode("utf-8")).hexdigest()
                cached_response = self._ai_plan_response_cache.get(cache_key)
                if cached_response is not None:
                    logging.info("AI plan explanation cache hit: %s", cache_key[:12])
                    self._on_ai_plan_explain_completed(True, cached_response)
                    return

            self.progress_bar.show()
            self.progress_animation.start()
            self._ai_pending_cache_key = cache_key or None

            self._ai_plan_worker = CallableWorkerThread(
                functools.partial(
                    generate_plan_explanation_openrouter,
                    base_url=base_url,
                    api_key=api_key,
                    model=model,
                    plan_payload=payload,
                ),
                self,
            )
            self._ai_plan_worker.completed.connect(self._on_ai_plan_explain_completed)
            self._ai_plan_worker.start()
        except Exception as e:
            logging.error("Ошибка запуска AI-интерпретации плана: %s", e)
            QMessageBox.critical(self, "AI", f"Не удалось запустить AI-интерпретацию:\n{str(e)}")

    def _on_ai_plan_explain_completed(self, ok: bool, payload):
        self.progress_bar.hide()
        self.progress_animation.stop()
        self._ai_plan_worker = None
        if ok and self._ai_pending_cache_key:
            self._ai_plan_response_cache[self._ai_pending_cache_key] = payload
        self._ai_pending_cache_key = None

        if not ok:
            QMessageBox.critical(self, "AI", f"Ошибка AI-интерпретации:\n{payload}")
            return

        structured = None
        ai_text = ""
        if isinstance(payload, dict):
            structured = payload.get("structured")
            ai_text = str(payload.get("raw_text") or "").strip()
        else:
            ai_text = str(payload).strip()

        if not ai_text:
            QMessageBox.warning(self, "AI", "AI не вернул содержимое интерпретации.")
            return

        self._ai_plan_total_responses += 1
        is_structured = isinstance(structured, dict)
        if is_structured:
            self._ai_plan_structured_responses += 1
        logging.info(
            "AI plan response quality: structured=%s (%s/%s)",
            "yes" if is_structured else "no",
            self._ai_plan_structured_responses,
            self._ai_plan_total_responses,
        )

        if isinstance(structured, dict):
            block_html = self._render_structured_ai_plan_html(structured, ai_text)
        else:
            escaped_text = html.escape(ai_text).replace("\n", "<br>")
            block_html = (
                "<hr style='border:1px solid #444;margin:12px 0;'>"
                "<h2 style='color:#b3e5fc;margin:0 0 8px 0;'>AI-интерпретация плана (OpenRouter)</h2>"
                f"{self._ai_quality_badge_html()}"
                "<p style='color:#90a4ae;margin:0 0 8px 0;font-size:11px;'>"
                "Формат ответа не прошёл JSON-валидацию, показан raw-текст."
                "</p>"
                f"<div style='line-height:1.45;'>{escaped_text}</div>"
            )
        if hasattr(self, "optimization_text"):
            current_html = self.optimization_text.toHtml() or ""
            self.optimization_text.setHtml(current_html + block_html)
        QMessageBox.information(self, "AI", "AI-интерпретация плана добавлена в блок рекомендаций.")

    def _ai_quality_badge_html(self) -> str:
        total = max(0, int(self._ai_plan_total_responses))
        structured = max(0, int(self._ai_plan_structured_responses))
        ratio = (structured / total * 100.0) if total else 0.0
        color = "#81c784" if ratio >= 80 else "#ffb74d" if ratio >= 50 else "#e57373"
        return (
            "<p style='margin:0 0 8px 0;font-size:11px;color:#b0bec5;'>"
            "Качество AI schema-first: "
            f"<span style='color:{color};font-weight:bold;'>{structured}/{total} ({ratio:.0f}%)</span>"
            "</p>"
        )

    def _render_structured_ai_plan_html(self, structured: dict, raw_text: str) -> str:
        summary = html.escape(str(structured.get("summary") or "")).replace("\n", "<br>")
        confidence = structured.get("confidence")
        try:
            confidence_value = f"{float(confidence):.2f}"
        except (TypeError, ValueError):
            confidence_value = "n/a"

        findings_items = []
        for item in structured.get("key_findings", []):
            if not isinstance(item, dict):
                continue
            severity = html.escape(str(item.get("severity") or "unknown"))
            title = html.escape(str(item.get("title") or "Без названия"))
            evidence = html.escape(str(item.get("evidence") or ""))
            findings_items.append(
                f"<li><b>[{severity}] {title}</b>"
                + (f"<br><span style='color:#b0bec5;'>{evidence}</span>" if evidence else "")
                + "</li>"
            )
        if not findings_items:
            findings_items.append("<li>Нет явных проблем в структурированном ответе.</li>")

        actions_items = []
        for item in structured.get("actions", []):
            if not isinstance(item, dict):
                continue
            priority = html.escape(str(item.get("priority") or "P3"))
            action = html.escape(str(item.get("action") or ""))
            why = html.escape(str(item.get("why") or ""))
            if not action:
                continue
            actions_items.append(
                f"<li><b>{priority}:</b> {action}"
                + (f"<br><span style='color:#b0bec5;'>{why}</span>" if why else "")
                + "</li>"
            )
        if not actions_items:
            actions_items.append("<li>AI не предложил конкретных действий.</li>")

        raw_collapsible = ""
        if raw_text:
            escaped_raw = html.escape(raw_text).replace("\n", "<br>")
            raw_collapsible = (
                "<details style='margin-top:8px;'>"
                "<summary style='cursor:pointer;color:#90a4ae;'>Raw AI ответ</summary>"
                f"<div style='margin-top:6px;color:#cfd8dc;line-height:1.4;'>{escaped_raw}</div>"
                "</details>"
            )

        return (
            "<hr style='border:1px solid #444;margin:12px 0;'>"
            "<h2 style='color:#b3e5fc;margin:0 0 8px 0;'>AI-интерпретация плана (OpenRouter)</h2>"
            f"{self._ai_quality_badge_html()}"
            f"<p style='margin:0 0 8px 0;'><b>Summary:</b> {summary}</p>"
            f"<p style='margin:0 0 8px 0;color:#90a4ae;'>Confidence: {confidence_value}</p>"
            "<h3 style='margin:10px 0 4px 0;color:#81c784;'>Ключевые наблюдения</h3>"
            f"<ul style='margin-top:4px;'>{''.join(findings_items)}</ul>"
            "<h3 style='margin:10px 0 4px 0;color:#4fc3f7;'>Рекомендуемые действия</h3>"
            f"<ul style='margin-top:4px;'>{''.join(actions_items)}</ul>" + raw_collapsible
        )

    def clear_analysis_for_new_plan(self):
        self._plan_graph_metadata = {}
        self._visible_outline_snapshot = None
        if hasattr(self, "general_analysis_text"):
            self.general_analysis_text.clear()
        if hasattr(self, "optimization_text"):
            self.optimization_text.clear()
        if hasattr(self, "node_info_text"):
            self.node_info_text.clear()
        if hasattr(self, "node_info_label"):
            self.node_info_label.setText("Информация о выбранном узле:")

        if hasattr(self, "_analyze_highlighters"):
            self._analyze_highlighters.clear()

        if hasattr(self, "general_analysis_text"):
            self.general_analysis_text.setHtml("""
            <html>
            <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
                <h2 style="color:#4fc3f7;">Загрузка плана запроса</h2>
                <p>Пожалуйста, подождите, идет анализ плана запроса...</p>
                <p>Это может занять некоторое время для сложных запросов.</p>
            </body>
            </html>
            """)
        QApplication.processEvents()

    def convert_to_html(self, text):
        if not text:
            return ""

        text = re.sub(
            r"\[link=([^\]]+)\]([^\[]+)\[/link\]",
            r'<a href="\1" style="color:#4fc3f7;text-decoration:underline;">\2</a>',
            text,
        )

        replacements = {
            "[title]": '<h1 style="color:#ffffff;margin:10px 0 5px 0;padding:0;font-size:16px;">',
            "[/title]": "</h1>",
            "[section]": '<h2 style="color:#4fc3f7;margin:12px 0 8px 0;padding:0;font-size:14px;border-bottom:1px solid #444;">',
            "[/section]": "</h2>",
            "[warning]": f'<h3 style="color:{self.analyzer_settings.get("colors", {}).get("warning_text", "#ff8a65")};margin:8px 0 4px 0;padding:0;font-size:13px;">',
            "[/warning]": "</h3>",
            "[error]": f'<span style="color:{self.analyzer_settings.get("colors", {}).get("error_text", "#ff6b6b")};">',
            "[/error]": "</span>",
            "[rec]": f'<span style="color:{self.analyzer_settings.get("colors", {}).get("recommendation_text", "#b3e5fc")};">',
            "[/rec]": "</span>",
            "[hl]": '<span style="color:#4fc3f7;font-weight:bold;">',
            "[/hl]": "</span>",
            "[seqscan]": f'<span style="color:{self.analyzer_settings.get("colors", {}).get("seq_scan_node", "#ff9e80")};">',
            "[/seqscan]": "</span>",
            "[table]": '<span style="color:#81c784;font-family:Consolas,monospace;">',
            "[/table]": "</span>",
            "[b]": "<b>",
            "[/b]": "</b>",
            "[i]": "<i>",
            "[/i]": "</i>",
            "[u]": "<u>",
            "[/u]": "</u>",
        }

        for marker, html_tag in replacements.items():
            text = text.replace(marker, html_tag)

        lines = text.split("\n")
        formatted_lines = []

        for line in lines:
            if line.strip():
                if line.strip().startswith("•"):
                    formatted_lines.append(
                        f'<div style="margin-left:20px;margin-bottom:4px;">{line}</div>'
                    )
                elif line.strip().startswith("-"):
                    formatted_lines.append(
                        f'<div style="margin-left:20px;margin-bottom:4px;">{line}</div>'
                    )
                elif (
                    line.strip().startswith("1.")
                    or line.strip().startswith("2.")
                    or line.strip().startswith("3.")
                ):
                    formatted_lines.append(
                        f'<div style="margin-left:15px;margin-bottom:4px;">{line}</div>'
                    )
                elif line.strip().startswith("⚠️"):
                    formatted_lines.append(
                        f'<div style="margin:8px 0 4px 0;padding:4px 0 4px 15px;border-left:3px solid {self.analyzer_settings.get("colors", {}).get("error_text", "#ff6b6b")};">{line}</div>'
                    )
                elif line.strip().startswith("✅") or line.strip().startswith("❌"):
                    formatted_lines.append(f'<div style="margin:4px 0;">{line}</div>')
                else:
                    formatted_lines.append(f'<div style="margin-bottom:4px;">{line}</div>')
            else:
                formatted_lines.append('<div style="margin:4px 0;"></div>')

        text = "\n".join(formatted_lines)

        return f'<html><body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;font-size:12px;line-height:1.4;background-color:#2d2d2d;margin:10px;padding:0;">{text}</body></html>'

    def highlight_node_in_graph(self, node_id):
        if hasattr(self, "visualizer_window"):
            js_code = """
                var nodes = network.body.nodes;
                nodes.forEach(function(node) {
                    node.setOptions({ color: node.originalColor });
                });
                var selectedNode = network.body.nodes[nodeId];
                if (selectedNode) {
                    selectedNode.originalColor = selectedNode.options.color;
                    selectedNode.setOptions({ color: '#FF0000' });
                }
            """
            self.visualizer_window.browser.page().runJavaScript(
                js_code, lambda result: print("Node highlighted:", result)
            )

    def parse_xml_plan(self, xml_content):
        try:
            return parse_explain_plan_document(xml_content)
        except ValueError as e:
            logging.error(str(e))
            raise

    def build_plan_tree(self, node, ns, parent=None, depth=0):
        return build_explain_plan_tree(node, ns, parent, depth)

    def create_graph_data_from_plan(self, plan_tree):
        return create_explain_graph_data(plan_tree)

    def analyze_plan_structure(self, plan_tree):
        sql_query = None
        if hasattr(self, "query_input"):
            qt = self.query_input.text().strip()
            if qt:
                sql_query = qt
        analysis, meta = analyze_explain_plan_structure(
            plan_tree, self.analyzer_settings, sql_query=sql_query
        )
        self.total_cost = meta["total_cost"]
        self.expensive_nodes = meta["expensive_nodes"]
        self.most_expensive_node_info = meta["most_expensive_node_info"]
        return analysis

    def open_xml_file(self):
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self,
                "Открыть файл плана",
                "",
                "Plan files (*.xml *.json);;XML (*.xml);;JSON (*.json);;All files (*.*)",
            )
            if not filename:
                return

            self.clear_analysis_for_new_plan()

            with open(filename, "r", encoding="utf-8") as f:
                content = f.read()

            self.xml_content = content
            self.last_opened_file = filename

            self.show_animated_message(
                [f"Файл {os.path.basename(filename)} успешно загружен", "Анализ плана запроса..."]
            )

            self.analyze_query_plan()

        except Exception as e:
            logging.error(f"Ошибка при открытии файла: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть файл:\n{str(e)}")

    def open_and_analyze_plan(self):
        self.open_xml_file()

    def show_animated_message(self, messages, delays=None):
        if delays is None:
            delays = [0.5] * len(messages)

        html = animated_status_messages_html(messages, delays)

        if hasattr(self, "initial_content"):
            self.initial_content.setHtml(html)
        elif hasattr(self, "visualizer_window"):
            self.visualizer_window.browser.setHtml(html)

    def create_node_info_html(self, node_type, properties, cost, total_cost, rows, loop_count=None):
        property_translations = {
            "Relation-Name": "Имя таблицы",
            "Alias": "Псевдоним",
            "Filter": "Условие фильтрации",
            "Index-Name": "Имя индекса",
            "Index-Cond": "Условие индекса",
            "Hash-Cond": "Условие хеширования",
            "Join-Type": "Тип соединения",
            "Merge-Cond": "Условие слияния",
            "Sort-Key": "Ключ сортировки",
            "Strategy": "Стратегия",
            "Partial-Mode": "Частичный режим",
            "Parent-Relationship": "Отношение к родителю",
            "Parallel-Aware": "Параллельное выполнение",
            "Workers-Launched": "Запущено рабочих процессов",
            "Plan-Rows": "Ожидаемое количество строк",
            "Plan-Width": "Ширина плана",
            "Actual-Rows": "Фактическое количество строк",
            "Actual-Loops": "Количество циклов",
            "Total-Cost": "Общая стоимость",
            "Startup-Cost": "Начальная стоимость",
            "Output": "Выводимые поля",
            "Group-Key": "Ключ группировки",
            "Sort-Method": "Метод сортировки",
            "Sort-Space-Used": "Использовано памяти для сортировки",
            "Sort-Space-Type": "Тип памяти для сортировки",
            "Join-Filter": "Условие соединения",
            "Recheck-Cond": "Условие повторной проверки",
            "Heap-Fetches": "Чтений из кучи",
            "Buffers": "Буферы",
            "Shared-Hit-Blocks": "Общие блоки в кэше",
            "Shared-Read-Blocks": "Общие прочитанные блоки",
            "Shared-Dirtied-Blocks": "Общие измененные блоки",
            "Shared-Written-Blocks": "Общие записанные блоки",
            "Local-Hit-Blocks": "Локальные блоки в кэше",
            "Local-Read-Blocks": "Локальные прочитанные блоки",
            "Local-Dirtied-Blocks": "Локальные измененные блоки",
            "Local-Written-Blocks": "Локальные записанные блоки",
            "Temp-Read-Blocks": "Временные прочитанные блоки",
            "Temp-Written-Blocks": "Временные записанные блоки",
            "WAL-Records": "Записи WAL",
            "WAL-FPI": "Полные страницы WAL",
            "WAL-Bytes": "Объем WAL (байты)",
        }

        node_descriptions = {
            "Seq Scan": "Последовательное сканирование таблицы. Чтение данных строка за строкой.",
            "Index Scan": "Сканирование по индексу. Использует индекс для быстрого доступа к данным.",
            "Bitmap Heap Scan": "Сканирование кучи с использованием битмапы. Эффективно для сложных условий.",
            "Hash Join": "Объединение таблиц с использованием хеш-таблицы. Быстрое объединение больших наборов данных.",
            "Nested Loop": "Вложенный цикл для объединения таблиц. Используется для небольших наборов данных.",
            "Merge Join": "Объединение таблиц с использованием сортировки. Эффективно для больших наборов данных.",
            "Sort": "Сортировка данных. Используется для упорядочивания результатов.",
            "Aggregate": "Агрегация данных. Используется для вычисления агрегатных функций (SUM, AVG и т.д.).",
            "Hash": "Хеширование данных. Используется для создания хеш-таблиц.",
            "Limit": "Ограничение количества возвращаемых строк. Используется для пагинации.",
            "Materialize": "Материализация данных. Используется для временного хранения промежуточных результатов.",
            "Result": "Результат выполнения запроса. Конечный узел плана запроса.",
        }

        description = node_descriptions.get(node_type, "Описание недоступно.")
        cost_info = f"Стоимость: {cost}"
        cost_percent = (cost / total_cost) * 100 if total_cost > 0 else 0
        cost_color = (
            self.analyzer_settings.get("colors", {}).get("error_text", "#ff6b6b")
            if cost_percent > 15
            else self.analyzer_settings.get("colors", {}).get("recommendation_text", "#b3e5fc")
        )
        cost_percent_html = f'<span style="color:{cost_color};">{cost_percent:.2f}%</span>'

        rows_info = f"Количество строк: {rows}"
        loop_count_info = (
            f"Количество повторений в цикле: {loop_count}"
            if loop_count is not None
            else "Количество повторений в цикле: Нет данных"
        )

        warning_color = self.analyzer_settings.get("colors", {}).get("warning_text", "#ff8a65")
        error_color = self.analyzer_settings.get("colors", {}).get("error_text", "#ff6b6b")
        recommendation_color = self.analyzer_settings.get("colors", {}).get(
            "recommendation_text", "#b3e5fc"
        )
        seq_scan_color = self.analyzer_settings.get("colors", {}).get("seq_scan_node", "#ff9e80")

        properties_rows = []
        for key, value in properties.items():
            translated_key = property_translations.get(key, key)
            properties_rows.append(
                f'<tr><td style="padding:2px 4px; color:{warning_color}; font-weight:bold; width:40%; vertical-align:top; border:none;">{translated_key}:</td><td style="padding:2px 4px; word-break:break-all; border:none;">{value}</td></tr>'
            )

        properties_html = (
            "".join(properties_rows)
            if properties_rows
            else '<tr><td colspan="2" style="padding:2px 4px; color:#888; border:none;">Нет дополнительных свойств</td></tr>'
        )

        html = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    color: #e0e0e0;
                    background-color: #2d2d2d;
                    margin: 5px;
                    padding: 5px;
                }}
                .info-section {{
                    margin: 0;
                    padding: 0;
                }}
                .info-title {{
                    color: #4fc3f7;
                    margin: 0 0 3px 0;
                    padding: 0;
                    font-size: 14px;
                    font-weight: bold;
                }}
                .info-divider {{
                    border: none;
                    border-top: 1px solid #444;
                    margin: 4px 0;
                }}
                .info-text {{
                    margin: 2px 0;
                    padding: 0;
                    line-height: 1.3;
                }}
                .properties-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 0;
                    padding: 0;
                }}
                .recommendation-text {{
                    color: {recommendation_color};
                    margin: 3px 0;
                    padding: 0;
                }}
                .warning-text {{
                    color: {seq_scan_color};
                    font-weight: bold;
                    margin: 3px 0;
                    padding: 0;
                }}
            </style>
        </head>
        <body>
            <div class="info-section">
                <div class="info-title">{node_type}</div>
                <hr class="info-divider">
                <div class="info-text" style="font-style: italic; color: {recommendation_color};">{description}</div>
                <hr class="info-divider">
                <div class="info-text">{cost_info}</div>
                <div class="info-text">Процент от общей стоимости: {cost_percent_html}</div>
                <div class="info-text">{rows_info}</div>
                <div class="info-text">{loop_count_info}</div>
                <hr class="info-divider">
                <div class="info-title" style="font-size: 12px; color: #81c784;">Свойства:</div>
                <table class="properties-table">
                    {properties_html}
                </table>
        """

        if node_type == "Seq Scan" and "Relation-Name" in properties and "Filter" in properties:
            filter_condition = properties["Filter"]
            fields = set()
            for word in filter_condition.split():
                if (
                    word.isalpha()
                    and len(word) > 2
                    and word not in ["AND", "OR", "NOT", "IS", "NULL"]
                ):
                    fields.add(word)

            if fields:
                html += f"""
                <hr class="info-divider">
                <div class="info-title" style="color: {error_color}; font-size: 12px;">⚠️ Рекомендации по оптимизации:</div>
                <div class="warning-text">→ Эта таблица требует особого внимания!</div>
                <div class="recommendation-text">→ Рассмотрите создание индекса по полям: {', '.join(fields)}</div>
                """

        html += """
            </div>
        </body>
        </html>
        """

        return html

    def get_settings_directory(self):
        if getattr(sys, "frozen", False):
            settings_dir = os.path.dirname(sys.executable)
        else:
            settings_dir = os.path.dirname(os.path.abspath(__file__))

        return settings_dir

    def show_visualization_info(self):
        self.general_analysis_text.setHtml("""
        <html>
        <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
            <h2 style="color:#4fc3f7;">📊 Визуализация плана запроса</h2>
            <p>В этой вкладке отображается графическое представление плана выполнения SQL-запроса в виде интерактивного графа.</p>
            
            <h3 style="color:#81c784;">Что показывает визуализация:</h3>
            <ul>
                <li><b style="color:#4fc3f7;">Узлы графа</b> — отдельные операции в плане запроса (Seq Scan, Index Scan, Join и т.д.)</li>
                <li><b style="color:#4fc3f7;">Связи между узлами</b> — последовательность выполнения операций</li>
                <li><b style="color:#4fc3f7;">Цветовую индикацию</b> — проблемные операции выделяются цветом:</li>
                <ul>
                    <li><span style="color:#ff6b6b;">Красный</span> — операции с высокой стоимостью</li>
                    <li><span style="color:#ff9e80;">Оранжевый</span> — Seq Scan операции (потенциальная проблема)</li>
                    <li><span style="color:#51cf66;">Зеленый</span> — Index Scan операции (эффективно)</li>
                </ul>
                <li><b style="color:#4fc3f7;">Стоимость операций</b> — относительная стоимость каждой операции</li>
                <li><b style="color:#4fc3f7;">Количество строк</b> — ожидаемое количество строк на каждом этапе</li>
            </ul>
            
            <h3 style="color:#81c784;">Как использовать:</h3>
            <ul>
                <li><b>Клик по узлу</b> — отображает детальную информацию об операции в правой панели</li>
                <li><b>Перетаскивание узлов</b> — можно изменять расположение узлов для удобного просмотра</li>
                <li><b>Масштабирование</b> — используйте колесо мыши для приближения/отдаления</li>
                <li><b>Переключение раскладки</b> — выберите тип визуализации в верхней панели:</li>
                <ul>
                    <li>Стандартная — динамическая раскладка с физикой</li>
                    <li>Иерархическая — строгая иерархия сверху вниз</li>
                </ul>
            </ul>
            
            <h3 style="color:#81c784;">Как получить план запроса:</h3>
            <ol>
                <li><b>Из файла</b> — нажмите «Открыть план» и выберите файл с результатом <code>EXPLAIN</code> (форматы XML или JSON)</li>
                <li><b>Из подключения</b> — подключитесь к БД и выполните SQL запрос</li>
                <li><b>Из сканера запросов</b> — дважды кликните по активному запросу</li>
                <li><b>Из журнала</b> — откройте журнал планов и выберите сохраненный план</li>
            </ol>
            
            <h3 style="color:#81c784;">Что означают типы операций:</h3>
            <ul>
                <li><b>Seq Scan</b> — последовательное чтение всей таблицы. <span style="color:#fcc419;">Может быть проблемой для больших таблиц</span></li>
                <li><b>Index Scan</b> — чтение по индексу. <span style="color:#51cf66;">Эффективно для выборочных запросов</span></li>
                <li><b>Index Only Scan</b> — чтение только из индекса. <span style="color:#51cf66;">Самый эффективный вариант</span></li>
                <li><b>Bitmap Heap/Index Scan</b> — комбинированное сканирование. <span style="color:#4fc3f7;">Для сложных условий</span></li>
                <li><b>Hash Join</b> — соединение через хеш-таблицу. <span style="color:#51cf66;">Хорошо для больших таблиц</span></li>
                <li><b>Nested Loop</b> — вложенный цикл. <span style="color:#fcc419;">Может быть неэффективен для больших таблиц</span></li>
                <li><b>Merge Join</b> — соединение через сортировку. <span style="color:#4fc3f7;">Требует сортировки данных</span></li>
            </ul>
            
            <h3 style="color:#81c784;">Настройка визуализации:</h3>
            <p>Вы можете настроить отображение через меню <b>Настройки анализатора → Визуализация</b>:</p>
            <ul>
                <li>Максимальное количество отображаемых узлов</li>
                <li>Размер узлов (множитель)</li>
                <li>Включение/выключение анимаций</li>
                <li>Отображение стоимости и количества строк на узлах</li>
                <li>Выбор цветовой схемы для различных типов узлов</li>
            </ul>
            
            <p style="color:#fcc419; margin-top:15px;"><b>Совет:</b> При работе со сложными запросами используйте иерархическую раскладку — она лучше показывает структуру выполнения.</p>
            
            <hr style="border-color:#444; margin:15px 0;">
            <p style="text-align:center; color:#81c784;">Загрузите план запроса (XML или JSON) или выполните запрос через подключение для начала работы</p>
        </body>
        </html>
        """)

        self.optimization_text.setHtml("""
        <html>
        <body style="color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
            <h2 style="color:#4fc3f7;">Как интерпретировать визуализацию</h2>
            
            <h3 style="color:#81c784;">Анализ стоимости:</h3>
            <ul>
                <li>Узлы с <span style="color:#ff6b6b;">красным</span> цветом — самые дорогие операции (более 15% от общей стоимости)</li>
                <li>Чем крупнее узел — тем выше его стоимость относительно общего плана</li>
                <li>Корневой узел (результат запроса) выделен <span style="color:#ADD8E6;">голубым</span> цветом</li>
            </ul>
            
            <h3 style="color:#81c784;">Типичные проблемы и их признаки:</h3>
            <ul>
                <li><b>Seq Scan на большой таблице</b> — оранжевый узел с высокой стоимостью → нужен индекс</li>
                <li><b>Nested Loop на больших объемах</b> — высокая стоимость, много итераций → заменить на Hash Join</li>
                <li><b>Внешняя сортировка (Sort)</b> — в свойствах узла "Sort-Method: external" → увеличить work_mem</li>
                <li><b>Материализация (Materialize)</b> — временное хранение данных → может потреблять много памяти</li>
            </ul>
            
            <h3 style="color:#81c784;">Понимание структуры:</h3>
            <ul>
                <li>Чтение плана идет <b>снизу вверх</b> и <b>справа налево</b></li>
                <li>Самый глубокий узел выполняется первым</li>
                <li>Результат запроса — самый верхний узел</li>
                <li>Стрелки показывают поток данных между операциями</li>
            </ul>
            
            <h3 style="color:#81c784;">Что искать в первую очередь:</h3>
            <ul>
                <li>Узлы с самой высокой стоимостью</li>
                <li>Операции Seq Scan на таблицах размером > 10 МБ</li>
                <li>Nested Loop, обрабатывающие миллионы строк</li>
                <li>Sort с большим объемом временных файлов</li>
                <li>Materialize на больших наборах данных</li>
            </ul>
            
            <h3 style="color:#81c784;">Быстрые рекомендации:</h3>
            <ul>
                <li><span style="color:#51cf66;"></span> Красный Seq Scan → CREATE INDEX ON table(columns)</li>
                <li><span style="color:#51cf66;"></span> Дорогой Nested Loop → увеличить work_mem для Hash Join</li>
                <li><span style="color:#51cf66;"></span> Внешняя сортировка → SET work_mem = '64MB'</li>
                <li><span style="color:#51cf66;"></span> Несколько Index Scan → рассмотреть составной индекс</li>
            </ul>
            
            <hr style="border-color:#444; margin:15px 0;">
            <p style="text-align:center; color:#81c784;">Кликните на любой узел графа для получения детальной информации</p>
        </body>
        </html>
        """)
