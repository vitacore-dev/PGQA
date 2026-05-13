"""Live query scanner tab (active backends table, filters, EXPLAIN-in-thread)."""

import datetime
import functools
import html
import json
import logging
import time
from collections import Counter

import psycopg2
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QToolBar,
    QVBoxLayout,
    QWidget,
)
from qtawesome import icon

from pg_query_analyzer.db.explain_sql import (
    explain_analyze_format_json_buffers_sql,
    explain_format_json_buffers_sql,
    has_pg_bind_placeholders,
)
from pg_query_analyzer.db.scanner import QueryScanner
from pg_query_analyzer.storage.connections import ConnectionSettings
from pg_query_analyzer.ui.qt_workers import CallableWorkerThread
from pg_query_analyzer.ui.sql_editor_dialog import SQLHighlighter
from pg_query_analyzer.ai.openrouter_client import (
    generate_active_queries_triage_openrouter,
    mask_sql_literals,
)


class QueryAnalyzerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()

        self.query_scanner = QueryScanner(None, self.parent)
        self.query_scanner.queries_updated.connect(self.update_queries_table)
        self.query_scanner.connection_error.connect(self.show_connection_error)
        self.query_scanner.applications_updated.connect(self.update_applications_filter)
        self.query_scanner.users_updated.connect(self.update_users_filter)
        self.query_scanner.clients_updated.connect(self.update_clients_filter)

        self.current_queries = {}
        self._analysis_worker = None
        self._ai_triage_worker = None
        self._ai_triage_cache = {}
        self._ai_triage_cache_key = None
        # Сканер шлёт connection_error на каждом цикле опроса — без throttling модальные окна «замораживают» UI.
        self._scanner_connection_error_last_dialog = 0.0
        self._scanner_connection_error_dialog_interval_sec = 60.0
        self.current_analyze_row = None
        self.setup_queries_table()
        self.queries_table.setObjectName("queries_table")

        self._highlighters = []

    def _get_warning_message(self, query):
        long_duration = self.parent.analyzer_settings.get("thresholds", {}).get(
            "long_duration_seconds", 60
        )
        if query.get("state") == "idle in transaction":
            return """
            <div class="warning">
                ⚠️ Внимание: Этот процесс находится в состоянии "idle in transaction".<br>
                Долгие транзакции могут блокировать другие операции и потреблять ресурсы.
            </div>
            """
        elif query.get("wait_event"):
            return f"""
            <div class="warning">
                ⚠️ Внимание: Этот процесс ожидает ресурс ({query.get('wait_event_type')}: {query.get('wait_event')}).<br>
                Это может указывать на contention (конкуренцию за ресурсы) в системе.
            </div>
            """
        elif (
            query.get("duration")
            and str(query.get("duration"))
            > f"00:{int(long_duration/60):02d}:{int(long_duration%60):02d}"
        ):
            return f"""
            <div class="warning">
                ⚠️ Внимание: Этот запрос выполняется более {long_duration} секунд.<br>
                Рекомендуется проанализировать его план выполнения.
            </div>
            """
        return ""

    def show_connection_error(self, message):
        logging.warning("Сканер активных запросов: %s", message)
        now = time.monotonic()
        interval = self._scanner_connection_error_dialog_interval_sec
        if now - self._scanner_connection_error_last_dialog < interval:
            return
        self._scanner_connection_error_last_dialog = now
        QMessageBox.warning(
            self,
            "Ошибка подключения (сканер)",
            f"{message}\n\nПока сканирование включено, ошибки могут повторяться каждые несколько секунд. "
            f"Следующее такое же модальное окно — не чаще чем раз в {int(interval)} с; остальное — в application.log.",
        )

    def _format_time(self, time_value):
        if not time_value:
            return ""
        try:
            if isinstance(time_value, str):
                time_value = datetime.datetime.fromisoformat(time_value)
            return time_value.strftime("%H:%M:%S")
        except Exception:
            return str(time_value)

    def setup_queries_table(self):
        self.queries_table.setColumnCount(9)
        self.queries_table.setHorizontalHeaderLabels(
            [
                "PID",
                "Пользователь",
                "Приложение",
                "Клиент",
                "Время",
                "Длительность",
                "Запрос",
                "Состояние",
                "Ожидание",
            ]
        )

        header = self.queries_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeToContents)

        self.queries_table.setSortingEnabled(True)
        self.queries_table.sortByColumn(2, Qt.DescendingOrder)

        self.queries_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.queries_table.customContextMenuRequested.connect(self.show_context_menu)

        self.queries_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.queries_table.itemSelectionChanged.connect(self.on_row_selected)
        self.queries_table.itemDoubleClicked.connect(self.on_item_double_clicked)

        self.queries_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                gridline-color: #444;
                font-size: 12px;
                selection-background-color: #3a7bd5;
            }
            QTableWidget::item:selected {
                background-color: #3a7bd5;
            }
            QTableWidget::item:hover {
                background-color: #3a3a3a;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #e0e0e0;
                padding: 5px;
                border: 1px solid #444;
                font-weight: bold;
            }
        """)

    def mousePressEvent(self, event):
        if event.button() == Qt.RightButton:
            pos = event.pos()
            index = self.queries_table.indexAt(self.queries_table.mapFromParent(pos))
            if index.isValid():
                self.queries_table.selectRow(index.row())
            event.accept()
            return
        super().mousePressEvent(event)

    def on_row_selected(self):
        self.update_button_states()
        modifiers = QApplication.keyboardModifiers()

        if modifiers & Qt.AltModifier:
            return

        if hasattr(self, "_suppress_selection"):
            return

        selected_items = self.queries_table.selectedItems()
        if not selected_items:
            return

        first_item = selected_items[0]
        query_data = first_item.data(Qt.UserRole)

        if query_data:
            QTimer.singleShot(100, lambda: self.show_query_details(query_data))

    def show_query_details(self, query):
        try:
            details_html = self._create_query_details_html(query)
            self.query_details_browser.setHtml(details_html)
            self.query_text_edit.setPlainText(query.get("query", ""))
            self.details_tabs.setCurrentIndex(0)

        except Exception as e:
            logging.error(f"Ошибка показа деталей запроса: {e}")
            if hasattr(self, "query_details_browser"):
                self.query_details_browser.setPlainText(f"Ошибка: {str(e)}")

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        toolbar = QToolBar()
        toolbar.setMovable(False)

        self.scan_button = QPushButton(icon("fa5s.search", color="white"), "Сканировать")
        self.scan_button.setCheckable(True)
        self.scan_button.setToolTip("Включить/выключить мониторинг активных запросов")
        self.scan_button.clicked.connect(self.toggle_scanning)
        self.scan_button.setStyleSheet("""
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
            QPushButton:pressed {
                background-color: #2a6bc5;
            }
            QPushButton:checked {
                background-color: #ff6b6b;
            }
        """)

        self.refresh_button = QPushButton(icon("fa5s.sync", color="white"), "Обновить")
        self.refresh_button.setToolTip("Обновить список запросов")
        self.refresh_button.clicked.connect(self.refresh_queries)
        self.refresh_button.setStyleSheet("""
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
            QPushButton:pressed {
                background-color: #2a6bc5;
            }
        """)

        self.clear_history_button = QPushButton(icon("fa5s.trash", color="white"), "Очистить")
        self.clear_history_button.setToolTip("Очистить историю запросов")
        self.clear_history_button.clicked.connect(self.clear_history)
        self.clear_history_button.setStyleSheet("""
            QPushButton {
                background-color: #8a4d2d;
                color: white;
                border: 1px solid #ff8a65;
                border-radius: 4px;
                padding: 5px 15px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #9a5d3d;
            }
            QPushButton:pressed {
                background-color: #7a3d1d;
            }
        """)

        self.kill_button = QPushButton(icon("fa5s.times", color="white"), "Завершить")
        self.kill_button.setToolTip("Завершить выбранный процесс")
        self.kill_button.clicked.connect(self.kill_selected_process)
        self.kill_button.setEnabled(False)
        self.kill_button.setStyleSheet("""
            QPushButton {
                background-color: #8a4d2d;
                color: white;
                border: 1px solid #ff8a65;
                border-radius: 4px;
                padding: 5px 15px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #9a5d3d;
            }
            QPushButton:pressed {
                background-color: #7a3d1d;
            }
            QPushButton:disabled {
                background-color: #555;
                color: #888;
                border: 1px solid #666;
            }
        """)

        self.ai_triage_button = QPushButton(icon("fa5s.robot", color="white"), "AI triage")
        self.ai_triage_button.setToolTip(
            "AI-триаж активных запросов/блокировок: приоритеты P1/P2/P3"
        )
        self.ai_triage_button.clicked.connect(self.ai_triage_active_queries)
        self.ai_triage_button.setStyleSheet("""
            QPushButton {
                background-color: #355c7d;
                color: white;
                border: 1px solid #4a8be5;
                border-radius: 4px;
                padding: 5px 15px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #446d90;
            }
            QPushButton:disabled {
                background-color: #555;
                color: #888;
                border: 1px solid #666;
            }
        """)

        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1, 60)
        scan_interval = 2
        if self.parent and hasattr(self.parent, "analyzer_settings"):
            scan_interval = self.parent.analyzer_settings.get("monitoring", {}).get(
                "scan_interval_seconds", 2
            )
        self.interval_spin.setValue(scan_interval)
        self.interval_spin.setSuffix(" сек")
        self.interval_spin.setToolTip("Интервал обновления (секунды)")
        self.interval_spin.valueChanged.connect(self.update_scan_interval)
        self.interval_spin.setStyleSheet("""
            QSpinBox {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 3px;
                font-size: 12px;
            }
        """)

        toolbar.addWidget(self.scan_button)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.clear_history_button)
        toolbar.addWidget(self.kill_button)
        toolbar.addWidget(self.ai_triage_button)
        toolbar.addSeparator()
        interval_label = QLabel("Интервал:")
        interval_label.setStyleSheet("color: #e0e0e0; font-size: 12px;")
        toolbar.addWidget(interval_label)
        toolbar.addWidget(self.interval_spin)

        self.scan_summary_label = QLabel(
            "Выберите подключение и нажмите «Сканировать», чтобы увидеть активные запросы."
        )
        self.scan_summary_label.setStyleSheet("""
            QLabel {
                color: #b0bec5;
                background-color: #263238;
                border-left: 4px solid #4fc3f7;
                padding: 6px 8px;
                font-size: 12px;
            }
        """)

        filter_container = QWidget()
        filter_layout = QVBoxLayout(filter_container)
        filter_layout.setContentsMargins(0, 0, 0, 0)
        filter_layout.setSpacing(5)

        filter_top_row = QHBoxLayout()
        filter_top_row.setSpacing(6)
        filter_bottom_row = QHBoxLayout()
        filter_bottom_row.setSpacing(6)

        self.state_filter = QComboBox()
        self.state_filter.addItem("Все состояния", "")
        self.state_filter.addItem("Активные", "active")
        self.state_filter.addItem("Ожидающие", "idle")
        self.state_filter.addItem("Заблокированные", "blocked")
        self.state_filter.currentIndexChanged.connect(self.on_state_filter_changed)
        self.state_filter.setStyleSheet("""
            QComboBox {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 3px;
                font-size: 12px;
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
        """)

        self.query_filter = QLineEdit()
        self.query_filter.setPlaceholderText("Фильтр по тексту запроса...")
        self.query_filter.textChanged.connect(self.on_query_filter_changed)
        self.query_filter.setStyleSheet("""
            QLineEdit {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 3px;
                font-size: 12px;
            }
        """)

        self.application_filter = QComboBox()
        self.application_filter.addItem("Все приложения", "")
        self.application_filter.currentIndexChanged.connect(self.on_application_filter_changed)
        self.application_filter.setStyleSheet("""
            QComboBox {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 3px;
                font-size: 12px;
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
        """)

        filter_top_row.addWidget(QLabel("Состояние:"))
        filter_top_row.addWidget(self.state_filter)
        filter_top_row.addWidget(QLabel("Запрос:"))
        filter_top_row.addWidget(self.query_filter, 1)

        filter_bottom_row.addWidget(QLabel("Приложение:"))
        filter_bottom_row.addWidget(self.application_filter)
        filter_bottom_row.addWidget(QLabel("Пользователь:"))
        self.user_filter = QComboBox()
        self.user_filter.addItem("Все пользователи", "")
        self.user_filter.currentIndexChanged.connect(self.on_user_filter_changed)
        self.user_filter.setStyleSheet("""
            QComboBox {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 3px;
                font-size: 12px;
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
        """)
        filter_bottom_row.addWidget(self.user_filter)

        filter_bottom_row.addWidget(QLabel("Клиент:"))
        self.client_filter = QComboBox()
        self.client_filter.addItem("Все клиенты", "")
        self.client_filter.currentIndexChanged.connect(self.on_client_filter_changed)
        self.client_filter.setStyleSheet("""
            QComboBox {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 3px;
                font-size: 12px;
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
        """)
        filter_bottom_row.addWidget(self.client_filter)

        filter_bottom_row.addStretch()
        filter_layout.addLayout(filter_top_row)
        filter_layout.addLayout(filter_bottom_row)

        self.queries_table = QTableWidget()
        self.setup_queries_table()

        self.details_panel = QWidget()
        self.details_panel.setLayout(QVBoxLayout())

        self.details_tabs = QTabWidget()

        self.query_details_browser = QTextBrowser()
        self.query_details_browser.setOpenExternalLinks(True)

        self.query_text_edit = QPlainTextEdit()
        self.query_text_edit.setReadOnly(True)
        self.highlighter = SQLHighlighter(self.query_text_edit.document())
        self.ai_triage_browser = QTextBrowser()
        self.ai_triage_browser.setOpenExternalLinks(False)
        self.ai_triage_browser.setHtml(
            "<p style='color:#9e9e9e;'>AI triage появится после нажатия кнопки «AI triage».</p>"
        )

        self.details_tabs.addTab(self.query_details_browser, "Детали запроса")
        self.details_tabs.addTab(self.query_text_edit, "Текст запроса")
        self.details_tabs.addTab(self.ai_triage_browser, "AI triage")

        self.details_panel.layout().addWidget(self.details_tabs)
        self.details_panel.layout().setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.queries_table)
        splitter.addWidget(self.details_panel)
        splitter.setSizes([400, 200])
        splitter.setHandleWidth(5)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background: #444;
            }
            QSplitter::handle:hover {
                background: #555;
            }
        """)

        layout.addWidget(toolbar)
        layout.addWidget(self.scan_summary_label)
        layout.addWidget(filter_container)
        layout.addWidget(splitter)

        self.setLayout(layout)

        self.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                gridline-color: #444;
                font-size: 12px;
                selection-background-color: #3a7bd5;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #e0e0e0;
                padding: 5px;
                border: 1px solid #444;
                font-weight: bold;
            }
            QPlainTextEdit, QTextBrowser {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }
            QToolBar {
                background-color: #333;
                border: none;
                padding: 2px;
            }
            QLabel {
                color: #e0e0e0;
                font-size: 12px;
            }
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

    def on_state_filter_changed(self, index):
        state = self.state_filter.itemData(index)
        self.query_scanner.update_filters(state=state)

    def on_query_filter_changed(self, text):
        self.query_scanner.update_filters(query_text=text)

    def on_application_filter_changed(self, index):
        app = self.application_filter.itemData(index)
        self.query_scanner.update_filters(application=app)

    def update_applications_filter(self, applications):
        current_app = self.application_filter.currentText()
        self.application_filter.clear()
        self.application_filter.addItem("Все приложения", "")

        for app in applications:
            self.application_filter.addItem(app, app)

        index = self.application_filter.findText(current_app)
        if index >= 0:
            self.application_filter.setCurrentIndex(index)

    def on_user_filter_changed(self, index):
        user = self.user_filter.itemData(index)
        self.query_scanner.update_filters(user=user)

    def on_client_filter_changed(self, index):
        client = self.client_filter.itemData(index)
        self.query_scanner.update_filters(client=client)

    def update_users_filter(self, users):
        current_user = self.user_filter.currentText()
        self.user_filter.clear()
        self.user_filter.addItem("Все пользователи", "")

        logging.debug(f"Updating users filter with: {users}")

        for user in users:
            self.user_filter.addItem(user, user)

        index = self.user_filter.findText(current_user)
        if index >= 0:
            self.user_filter.setCurrentIndex(index)

    def update_clients_filter(self, clients):
        current_client = self.client_filter.currentText()
        self.client_filter.clear()
        self.client_filter.addItem("Все клиенты", "")

        logging.debug(f"Updating clients filter with: {clients}")

        for client in clients:
            self.client_filter.addItem(client, client)

        index = self.client_filter.findText(current_client)
        if index >= 0:
            self.client_filter.setCurrentIndex(index)

    def update_scan_interval(self, interval):
        self.query_scanner.scan_interval = interval
        if self.query_scanner.running:
            self.query_scanner.stop_scanning()
            self.query_scanner.start_scanning()

    def toggle_scanning(self, checked):
        if checked:
            if not self.parent.connection_status:
                QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных")
                self.scan_button.setChecked(False)
                return

            if not self.query_scanner.connection_params:
                if hasattr(self.parent, "current_connection") and self.parent.current_connection:
                    self.query_scanner.connection_params = ConnectionSettings.connect_kwargs(
                        self.parent.current_connection
                    )
                else:
                    QMessageBox.warning(self, "Ошибка", "Параметры подключения не установлены")
                    self.scan_button.setChecked(False)
                    return

            if hasattr(self.parent, "analyzer_settings"):
                self.query_scanner.analyzer_settings = self.parent.analyzer_settings

            self.query_scanner.start_scanning(self.interval_spin.value())
            self.scan_button.setIcon(icon("fa5s.stop", color="white"))
            self.scan_button.setText("Остановить")
            self.scan_button.setStyleSheet("""
                QPushButton {
                    background-color: #ff6b6b;
                    color: white;
                }
                QPushButton:hover {
                    background-color: #e74c3c;
                }
            """)
        else:
            self.query_scanner.stop_scanning()
            self.scan_button.setIcon(icon("fa5s.search", color="white"))
            self.scan_button.setText("Сканировать")
            self.scan_button.setStyleSheet("""
                QPushButton {
                    background-color: #3a7bd5;
                    color: white;
                }
                QPushButton:hover {
                    background-color: #4a8be5;
                }
            """)

    def refresh_queries(self):
        if hasattr(self.parent, "query_history"):
            active_queries = self.parent.query_history.get_active_queries()
            self.update_queries_table(active_queries)

    def update_queries_table(self, new_queries):
        try:
            self.current_queries = {
                str(q.get("pid")): q for q in (new_queries or []) if q.get("pid")
            }
            self.queries_table.setSortingEnabled(False)
            scroll_pos = self.queries_table.verticalScrollBar().value()
            new_queries_map = {str(q["pid"]): q for q in new_queries}

            rows_to_remove = []
            for row in range(self.queries_table.rowCount()):
                pid_item = self.queries_table.item(row, 0)
                if pid_item and pid_item.text() not in new_queries_map:
                    rows_to_remove.append(row)

            for row in reversed(rows_to_remove):
                self.queries_table.removeRow(row)

            existing_pids = set()
            for row in range(self.queries_table.rowCount()):
                pid_item = self.queries_table.item(row, 0)
                if pid_item:
                    pid = pid_item.text()
                    existing_pids.add(pid)
                    if pid in new_queries_map:
                        self._update_existing_row(row, new_queries_map[pid])

            for pid, query in new_queries_map.items():
                if pid not in existing_pids:
                    self._add_new_row(query)

            self.queries_table.verticalScrollBar().setValue(scroll_pos)
            self.update_scan_summary(new_queries)

        except Exception as e:
            logging.error(f"Ошибка обновления таблицы запросов: {e}", exc_info=True)
        finally:
            self.queries_table.setSortingEnabled(True)

    def ai_triage_active_queries(self):
        if self._ai_triage_worker is not None:
            QMessageBox.information(self, "AI triage", "AI triage уже выполняется.")
            return
        queries = list(self.current_queries.values())
        if not queries:
            QMessageBox.information(self, "AI triage", "Нет активных запросов для triage.")
            return

        ai_settings = (getattr(self.parent, "analyzer_settings", None) or {}).get("ai", {})
        if not ai_settings.get("enabled", False):
            QMessageBox.warning(
                self,
                "AI triage",
                "AI-интерпретатор выключен. Включите его в Настройки анализатора -> AI / OpenRouter.",
            )
            return
        provider = (ai_settings.get("provider") or "").strip().lower()
        if provider != "openrouter":
            QMessageBox.warning(
                self, "AI triage", "Сейчас поддерживается только provider=openrouter."
            )
            return
        base_url = (ai_settings.get("base_url") or "https://openrouter.ai/api/v1").strip()
        model = (ai_settings.get("model") or "").strip()
        api_key = (ai_settings.get("api_key") or "").strip()
        if not api_key or not model:
            QMessageBox.warning(
                self,
                "AI triage",
                "Заполните API key и Модель в Настройки анализатора -> AI / OpenRouter.",
            )
            return

        mask_literals = ai_settings.get("mask_sql_literals", True)
        payload_queries = []
        for q in queries[:40]:
            qtxt = (q.get("query") or "").strip()
            if mask_literals:
                qtxt = mask_sql_literals(qtxt)
            payload_queries.append(
                {
                    "pid": str(q.get("pid") or ""),
                    "state": q.get("state"),
                    "wait_event_type": q.get("wait_event_type"),
                    "wait_event": q.get("wait_event"),
                    "duration": q.get("duration_str") or str(q.get("duration") or ""),
                    "query_preview": qtxt[:400],
                    "application_name": q.get("application_name"),
                    "usename": q.get("usename"),
                }
            )
        triage_payload = {
            "summary_counters": {
                "total": len(queries),
                "waiting": sum(1 for q in queries if q.get("wait_event")),
                "active": sum(1 for q in queries if q.get("state") == "active"),
                "idle_in_tx": sum(1 for q in queries if q.get("state") == "idle in transaction"),
            },
            "queries": payload_queries,
        }
        lock_graph = self._fetch_lock_graph_snapshot()
        triage_payload["lock_graph"] = lock_graph

        cache_key = ""
        if ai_settings.get("cache_enabled", True):
            cache_blob = json.dumps(
                {"base_url": base_url, "model": model, "payload": triage_payload},
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            )
            cache_key = cache_blob
            cached = self._ai_triage_cache.get(cache_key)
            if cached is not None:
                self._render_ai_triage(cached)
                return

        self.ai_triage_button.setEnabled(False)
        self.scan_summary_label.setText("AI triage активных запросов выполняется…")

        def triage_sync():
            return generate_active_queries_triage_openrouter(
                base_url=base_url,
                api_key=api_key,
                model=model,
                active_queries_payload=triage_payload,
            )

        self._ai_triage_cache_key = cache_key or None
        self._ai_triage_worker = CallableWorkerThread(triage_sync, self)
        self._ai_triage_worker.completed.connect(self._on_ai_triage_done)
        self._ai_triage_worker.start()

    def _on_ai_triage_done(self, ok: bool, payload: object):
        self.ai_triage_button.setEnabled(True)
        self._ai_triage_worker = None
        if not ok:
            QMessageBox.warning(self, "AI triage", str(payload))
            return
        if getattr(self, "_ai_triage_cache_key", None):
            self._ai_triage_cache[self._ai_triage_cache_key] = payload
        self._ai_triage_cache_key = None
        self._render_ai_triage(payload)

    def _render_ai_triage(self, payload: object):
        structured = payload.get("structured") if isinstance(payload, dict) else None
        raw = (
            str(payload.get("raw_text") or "").strip()
            if isinstance(payload, dict)
            else str(payload)
        )
        lock_graph = self._fetch_lock_graph_snapshot()
        if isinstance(structured, dict):
            summary = html.escape(str(structured.get("summary") or ""))
            level = html.escape(str(structured.get("incident_level") or "unknown"))
            blockers = structured.get("blocking_candidates") or []
            actions = structured.get("actions") or []
            blocker_items = []
            blocker_pids = []
            for b in blockers:
                if not isinstance(b, dict):
                    continue
                pid_text = str(b.get("pid") or "").strip()
                if pid_text:
                    blocker_pids.append(pid_text)
                blocker_items.append(
                    f"<li>PID <b>{html.escape(pid_text)}</b>: "
                    f"{html.escape(str(b.get('reason') or ''))}</li>"
                )
            if not blocker_items:
                blocker_items.append("<li>Явные блокирующие кандидаты не выделены.</li>")
            graph_items = []
            edges = lock_graph.get("edges", []) if isinstance(lock_graph, dict) else []
            roots = lock_graph.get("root_blockers", []) if isinstance(lock_graph, dict) else []
            for edge in edges[:40]:
                if not isinstance(edge, dict):
                    continue
                graph_items.append(
                    "<li>"
                    f"{html.escape(str(edge.get('blocked_pid') or ''))} ← "
                    f"{html.escape(str(edge.get('blocking_pid') or ''))}"
                    "</li>"
                )
            if not graph_items:
                graph_items.append("<li>Граф блокировок пуст или недоступен.</li>")
            root_text = (
                ", ".join(html.escape(str(x)) for x in roots[:12]) if roots else "не определены"
            )
            action_items = []
            for a in actions:
                if not isinstance(a, dict):
                    continue
                action_items.append(
                    f"<li><b>{html.escape(str(a.get('priority') or 'P3'))}</b>: "
                    f"{html.escape(str(a.get('action') or ''))}"
                    f"<br><span style='color:#b0bec5;'>Риск: {html.escape(str(a.get('risk') or ''))}</span></li>"
                )
            if not action_items:
                action_items.append("<li>AI не предложил действия.</li>")
            self.ai_triage_browser.setHtml(
                "<div style='color:#e0e0e0; font-family:Segoe UI,Arial,sans-serif; font-size:12px;'>"
                "<h3 style='color:#b3e5fc;margin:0 0 8px 0;'>AI triage активных запросов</h3>"
                f"<p><b>Incident level:</b> {level}</p>"
                f"<p><b>Summary:</b> {summary}</p>"
                "<h4 style='color:#ffb74d;margin:10px 0 6px 0;'>Кандидаты блокировок</h4>"
                f"<ul>{''.join(blocker_items)}</ul>"
                f"<p><b>Root blocker(s):</b> {root_text}</p>"
                "<h4 style='color:#4fc3f7;margin:10px 0 6px 0;'>Lock graph</h4>"
                f"<ul>{''.join(graph_items)}</ul>"
                "<h4 style='color:#81c784;margin:10px 0 6px 0;'>План действий</h4>"
                f"<ul>{''.join(action_items)}</ul>"
                "</div>"
            )
            self.details_tabs.setCurrentWidget(self.ai_triage_browser)
            if blocker_pids:
                self._highlight_rows_by_pid(blocker_pids)
            return

        self.ai_triage_browser.setHtml(
            "<div style='color:#e0e0e0; font-family:Segoe UI,Arial,sans-serif; font-size:12px;'>"
            "<h3 style='color:#b3e5fc;margin:0 0 8px 0;'>AI triage активных запросов</h3>"
            "<p style='color:#ffb74d;'>JSON-структура не распознана, показан raw ответ:</p>"
            f"<pre style='white-space:pre-wrap;background:#1f1f1f;border:1px solid #444;padding:8px;'>{html.escape(raw)}</pre>"
            "</div>"
        )
        self.details_tabs.setCurrentWidget(self.ai_triage_browser)

    def _fetch_lock_graph_snapshot(self):
        if not self.parent or not getattr(self.parent, "current_connection", None):
            return {"edges": [], "root_blockers": []}
        try:
            conn_params = ConnectionSettings.connect_kwargs(self.parent.current_connection)
            edges = []
            with psycopg2.connect(**conn_params) as conn:
                conn.autocommit = True
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT
                            a.pid::text AS pid,
                            pg_blocking_pids(a.pid) AS blocking_pids
                        FROM pg_stat_activity a
                        WHERE a.datname = current_database()
                          AND a.pid <> pg_backend_pid()
                        """)
                    rows = cursor.fetchall()
            blocking_counter = Counter()
            blocked_set = set()
            for pid, blocking_pids in rows:
                if not blocking_pids:
                    continue
                blocked_set.add(str(pid))
                for bpid in blocking_pids:
                    bp = str(bpid)
                    edges.append({"blocked_pid": str(pid), "blocking_pid": bp})
                    blocking_counter[bp] += 1
            root_blockers = [
                pid for pid, count in blocking_counter.most_common() if pid not in blocked_set
            ]
            if not root_blockers:
                root_blockers = [pid for pid, _ in blocking_counter.most_common()]
            return {"edges": edges, "root_blockers": root_blockers[:10]}
        except Exception as e:
            logging.warning("Не удалось построить lock graph snapshot: %s", e)
            return {"edges": [], "root_blockers": []}

    def _highlight_rows_by_pid(self, pids):
        pid_set = {str(x).strip() for x in (pids or []) if str(x).strip()}
        if not pid_set:
            return
        self.queries_table.clearSelection()
        first_row = None
        for row in range(self.queries_table.rowCount()):
            pid_item = self.queries_table.item(row, 0)
            if not pid_item:
                continue
            pid_text = pid_item.text().strip()
            if pid_text in pid_set:
                self.queries_table.selectRow(row)
                if first_row is None:
                    first_row = row
        if first_row is not None:
            self.queries_table.scrollToItem(self.queries_table.item(first_row, 0))

    def update_scan_summary(self, queries):
        total = len(queries)
        active = sum(1 for q in queries if q.get("state") == "active")
        waiting = sum(1 for q in queries if q.get("wait_event"))
        idle_tx = sum(1 for q in queries if q.get("state") == "idle in transaction")
        if total == 0:
            text = (
                "Активных backend-запросов не найдено. Уточните фильтры или обновите сканирование."
            )
            color = "#4fc3f7"
        else:
            text = (
                f"Найдено: {total} | active: {active} | ожидание: {waiting} | "
                f"idle in transaction: {idle_tx}. Двойной клик по строке снимает EXPLAIN."
            )
            color = "#ff8a65" if waiting or idle_tx else "#81c784"
        self.scan_summary_label.setText(text)
        self.scan_summary_label.setStyleSheet(f"""
            QLabel {{
                color: #e0e0e0;
                background-color: #263238;
                border-left: 4px solid {color};
                padding: 6px 8px;
                font-size: 12px;
            }}
        """)

    def _update_existing_row(self, row, query):
        if "duration_str" in query:
            self.queries_table.item(row, 5).setText(query["duration_str"])
        elif "duration" in query:
            self.queries_table.item(row, 5).setText(str(query["duration"]).split(".")[0])

        state_item = self.queries_table.item(row, 7)
        state_item.setText(query.get("state", ""))

        wait_event = query.get("wait_event", "")
        wait_item = self.queries_table.item(row, 8)
        if wait_event:
            wait_item.setText(f"{query.get('wait_event_type', '')}: {wait_event}")
        else:
            wait_item.setText("Нет")

        for col in range(self.queries_table.columnCount()):
            item = self.queries_table.item(row, col)
            if item:
                item.setData(Qt.UserRole, query)

        if self.parent.analyzer_settings.get("monitoring", {}).get(
            "highlight_blocked_queries", True
        ):
            self.highlight_problematic_queries(row, query)

    def _add_new_row(self, query):
        row = self.queries_table.rowCount()
        self.queries_table.insertRow(row)

        pid_item = QTableWidgetItem(str(query.get("pid", "")))
        self.queries_table.setItem(row, 0, pid_item)

        user_item = QTableWidgetItem(query.get("usename", ""))
        self.queries_table.setItem(row, 1, user_item)

        app_item = QTableWidgetItem(query.get("application_name", ""))
        self.queries_table.setItem(row, 2, app_item)

        client_info = f"{query.get('client_addr', '')}:{query.get('client_port', '')}"
        client_item = QTableWidgetItem(client_info)
        self.queries_table.setItem(row, 3, client_item)

        time_item = QTableWidgetItem(self._format_query_time(query.get("query_start")))
        self.queries_table.setItem(row, 4, time_item)

        duration_item = QTableWidgetItem(self._format_duration(query))
        self.queries_table.setItem(row, 5, duration_item)

        query_item = QTableWidgetItem(self._shorten_query(query.get("query", "")))
        query_item.setToolTip(query.get("query", ""))
        self.queries_table.setItem(row, 6, query_item)

        state_item = QTableWidgetItem(query.get("state", ""))
        self.queries_table.setItem(row, 7, state_item)

        wait_item = QTableWidgetItem(self._format_wait_event(query))
        self.queries_table.setItem(row, 8, wait_item)

        for col in range(self.queries_table.columnCount()):
            item = self.queries_table.item(row, col)
            if item:
                item.setData(Qt.UserRole, query)

        if self.parent.analyzer_settings.get("monitoring", {}).get(
            "highlight_blocked_queries", True
        ):
            self.highlight_problematic_queries(row, query)

    def _format_query_time(self, query_time):
        if not query_time:
            return ""
        try:
            if isinstance(query_time, str):
                query_time = datetime.datetime.fromisoformat(query_time)
            return query_time.strftime("%H:%M:%S")
        except Exception:
            return str(query_time)

    def _format_duration(self, query):
        if "duration_str" in query:
            return query["duration_str"]
        if "duration" in query:
            return str(query["duration"]).split(".")[0]
        return ""

    def _shorten_query(self, query_text):
        if not query_text:
            return ""
        return query_text[:100] + ("..." if len(query_text) > 100 else "")

    def _format_wait_event(self, query):
        wait_event = query.get("wait_event", "")
        if wait_event:
            return f"{query.get('wait_event_type', '')}: {wait_event}"
        return "Нет"

    def highlight_problematic_queries(self, row, query):
        state = query.get("state", "")
        wait_event = query.get("wait_event", "")
        long_duration = self.parent.analyzer_settings.get("thresholds", {}).get(
            "long_duration_seconds", 60
        )

        if state == "idle in transaction":
            color = QColor("#ffcc80")
        elif wait_event:
            color = QColor("#ff8a80")
        elif state == "active" and query.get(
            "duration", datetime.timedelta(0)
        ) > datetime.timedelta(seconds=long_duration):
            color = QColor("#ffcc00")
        else:
            return

        for col in range(self.queries_table.columnCount()):
            item = self.queries_table.item(row, col)
            if item:
                item.setBackground(color)
                text_color = QColor("black") if color.lightness() > 128 else QColor("white")
                item.setForeground(text_color)

    def update_button_states(self):
        selected = len(self.queries_table.selectedItems()) > 0
        self.kill_button.setEnabled(selected)

    def show_context_menu(self, pos):
        index = self.queries_table.indexAt(pos)
        if not index.isValid():
            return

        self.queries_table.selectRow(index.row())

        row = index.row()
        pid_item = self.queries_table.item(row, 0)
        if not pid_item:
            return

        query_data = pid_item.data(Qt.UserRole)
        if not query_data:
            return

        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #3a7bd5;
            }
            QMenu::separator {
                height: 1px;
                background-color: #444;
                margin: 5px 0;
            }
        """)

        kill_action = QAction(icon("fa5s.times", color="white"), "Завершить процесс", menu)
        kill_action.triggered.connect(self.kill_selected_process)
        menu.addAction(kill_action)

        menu.addSeparator()

        explain_action = QAction(
            icon("fa5s.chart-line", color="white"), "Анализировать запрос", menu
        )
        explain_action.triggered.connect(lambda: self.analyze_selected_query(row))
        menu.addAction(explain_action)

        menu.addSeparator()

        copy_action = QAction(icon("fa5s.copy", color="white"), "Копировать запрос", menu)
        copy_action.triggered.connect(self.copy_selected_query)
        menu.addAction(copy_action)

        menu.exec_(self.queries_table.viewport().mapToGlobal(pos))

    def kill_selected_process(self):
        selected_rows = set(index.row() for index in self.queries_table.selectedIndexes())
        if not selected_rows:
            return

        processes = []
        for row in selected_rows:
            pid_item = self.queries_table.item(row, 0)
            if pid_item:
                query_data = pid_item.data(Qt.UserRole)
                if query_data:
                    processes.append(query_data)

        if not processes:
            return

        detailed_info = "<html>"
        for proc in processes:
            detailed_info += f"""<strong>Процесс:</strong> {proc.get('pid', '')}<br>
                            <strong>Пользователь:</strong> {proc.get('usename', '')}<br>
                            <strong>Приложение:</strong> {proc.get('application_name', '')}<br>
                            <strong>Состояние:</strong> {proc.get('state', '')}<br>
                            <strong>Запрос:</strong> {proc.get('query', '')[:100]}...<br><br>"""

        detailed_info += "</html>"

        reply = QMessageBox.question(
            self,
            "Подтверждение",
            f"Выполнить завершение следующих процессов?<br>{detailed_info}",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply == QMessageBox.No:
            return

        success_count = 0
        for proc in processes:
            try:
                connection_params = ConnectionSettings.connect_kwargs(
                    self.parent.current_connection
                )

                with psycopg2.connect(**connection_params) as conn:
                    conn.autocommit = True
                    with conn.cursor() as cursor:
                        cursor.execute("SELECT pg_terminate_backend(%s)", (int(proc["pid"]),))
                        success = cursor.fetchone()[0]
                        if success:
                            success_count += 1
            except Exception as e:
                logging.error(f"Ошибка при завершении процесса {proc['pid']}: {e}")

        if success_count > 0:
            QMessageBox.information(self, "Успех", f"Завершено {success_count} процессов")
            self.refresh_queries()
        else:
            QMessageBox.warning(self, "Ошибка", "Не удалось завершить процессы")

    def copy_selected_query(self):
        selected_rows = set(index.row() for index in self.queries_table.selectedIndexes())
        if not selected_rows:
            return

        queries = []
        for row in selected_rows:
            query_item = self.queries_table.item(row, 6)
            if query_item and query_item.toolTip():
                queries.append(query_item.toolTip())

        if queries:
            QApplication.clipboard().setText("\n\n".join(queries))
            QMessageBox.information(self, "Успех", "Запрос(ы) скопирован(ы) в буфер обмена")

    def show_selected_details(self):
        selected_rows = set(index.row() for index in self.queries_table.selectedIndexes())
        if not selected_rows:
            return

        for row in selected_rows:
            pid_item = self.queries_table.item(row, 0)
            if pid_item:
                query_data = pid_item.data(Qt.UserRole)
                if query_data:
                    self.view_query_details(query_data)
                    break

    def view_query_details(self, query):
        self.show_query_details(query)

    def _create_query_details_html(self, query):
        pid = query.get("pid", "N/A")
        app_name = html.escape(query.get("application_name", "N/A"))
        user = html.escape(query.get("usename", "N/A"))
        client = f"{query.get('client_addr', 'N/A')}:{query.get('client_port', 'N/A')}"
        db_name = html.escape(query.get("datname", "N/A"))
        backend_start = self._format_time(query.get("backend_start"))
        xact_start = self._format_time(query.get("xact_start"))
        query_start = self._format_time(query.get("query_start"))
        duration = self._format_duration(query)
        state = html.escape(query.get("state", "N/A"))
        wait_event = html.escape(
            f"{query.get('wait_event_type', '')}: {query.get('wait_event', 'Нет')}"
        )
        query_text = html.escape(query.get("query", ""))

        return f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    color: #e0e0e0;
                    background-color: #2d2d2d;
                    margin: 10px;
                    padding: 10px;
                }}
                h2 {{
                    color: #4fc3f7;
                    margin-top: 0;
                    border-bottom: 1px solid #444;
                    padding-bottom: 5px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 15px;
                }}
                th {{
                    text-align: left;
                    background-color: #3a3a3a;
                    padding: 5px;
                    border: 1px solid #444;
                }}
                td {{
                    padding: 5px;
                    border: 1px solid #444;
                    word-break: break-all;
                }}
                .query {{
                    background-color: #1e1e1e;
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                    white-space: pre-wrap;
                    font-family: 'Consolas', 'Courier New', monospace;
                }}
                .warning {{
                    color: #ff8a65;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <h2>Детали запроса (PID: {pid})</h2>

            <tr>
                <tr><th>Параметр</th><th>Значение</th></tr>
                <tr><td>Приложение</td><td>{app_name}</td></tr>
                <tr><td>Пользователь</td><td>{user}</td></tr>
                <tr><td>Клиент</td><td>{client}</td></tr>
                <tr><td>База данных</td><td>{db_name}</td></tr>
                <tr><td>Начало подключения</td><td>{backend_start}</td></tr>
                <tr><td>Начало транзакции</td><td>{xact_start}</td></tr>
                <tr><td>Начало запроса</td><td>{query_start}</td></tr>
                <tr><td>Длительность</td><td>{duration}</td></tr>
                <tr><td>Состояние</td><td>{state}</td></tr>
                <tr><td>Ожидание</td><td>{wait_event}</td></tr>
            </table>

            <h3>Текст запроса:</h3>
            <div class="query">{query_text}</div>

            {self._get_warning_message(query)}
        </body>
        </html>
        """

    def on_item_double_clicked(self, item):
        row = item.row()
        self.analyze_selected_query(row)

    def on_table_key_press(self, event):
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            current_row = self.queries_table.currentRow()
            if current_row >= 0:
                self.analyze_selected_query(current_row)
        else:
            QTableWidget.keyPressEvent(self.queries_table, event)

    def analyze_selected_query(self, row=None):
        selected_row = None

        if isinstance(row, bool):
            row = None

        if row is not None:
            if isinstance(row, int):
                selected_row = row
            else:
                try:
                    selected_row = int(row)
                except (ValueError, TypeError):
                    selected_row = None

        if selected_row is None:
            selected_items = self.queries_table.selectedItems()
            if not selected_items:
                QMessageBox.warning(self, "Ошибка", "Пожалуйста, выберите запрос для анализа")
                return
            selected_row = selected_items[0].row()

        if selected_row < 0:
            QMessageBox.warning(self, "Ошибка", "Не удалось определить выбранную строку")
            return

        pid_item = self.queries_table.item(selected_row, 0)
        if not pid_item:
            QMessageBox.warning(self, "Ошибка", "Не удалось получить данные запроса")
            return

        query_data = pid_item.data(Qt.UserRole)
        if not query_data:
            QMessageBox.warning(self, "Ошибка", "Нет данных запроса")
            return

        if "query" not in query_data:
            QMessageBox.warning(self, "Ошибка", "Нет текста запроса")
            return

        query_text = query_data["query"]
        if not query_text or len(query_text.strip()) == 0:
            QMessageBox.warning(self, "Ошибка", "Запрос пуст")
            return

        if not self.parent.connection_status:
            QMessageBox.warning(self, "Ошибка", "Нет подключения к базе данных для анализа запроса")
            return

        self.current_analyze_row = selected_row

        self.parent.progress_bar.show()
        self.parent.progress_animation.start()

        state_item = self.queries_table.item(selected_row, 7)
        if state_item:
            original_state = query_data.get("state", "")
            state_item.setText("Анализируется...")
            state_item.setForeground(QColor("#ffcc00"))
            state_item.setData(Qt.UserRole + 100, original_state)

        self._analysis_worker = CallableWorkerThread(
            functools.partial(self._execute_analysis_sync, query_text),
            self.parent,
        )
        self._analysis_worker.completed.connect(self._on_analysis_worker_completed)
        self._analysis_worker.start()

    def _execute_analysis_sync(self, query_text: str):
        """Run EXPLAIN ANALYZE или plain EXPLAIN; отдельное соединение."""
        # Текст из pg_stat_activity/pg_stat_statements может содержать bind-плейсхолдеры ($1, $2, ...)
        # без исходных параметров. Такой SQL нельзя выполнить через EXPLAIN напрямую.
        if has_pg_bind_placeholders(query_text):
            raise RuntimeError(
                "Ошибка EXPLAIN: запрос содержит параметризованные плейсхолдеры ($1, $2, ...), "
                "но значения параметров недоступны.\n"
                "Скопируйте запрос в редактор и подставьте конкретные значения вместо $N."
            )
        try:
            conn_params = ConnectionSettings.connect_kwargs(self.parent.current_connection)
            with psycopg2.connect(**conn_params) as conn:
                conn.autocommit = True
                with conn.cursor() as cursor:
                    try:
                        explain_query = explain_analyze_format_json_buffers_sql(query_text)
                        cursor.execute(explain_query)
                        return cursor.fetchone()[0]
                    except psycopg2.Error as e:
                        error_msg = str(e)
                        if "cannot be executed" in error_msg or "syntax error" in error_msg:
                            explain_query = explain_format_json_buffers_sql(query_text)
                            cursor.execute(explain_query)
                            return cursor.fetchone()[0]
                        raise RuntimeError(f"Ошибка EXPLAIN: {error_msg}") from e

        except psycopg2.Error as e:
            error_msg = str(e)
            logging.error("Ошибка выполнения EXPLAIN: %s", error_msg)
            raise RuntimeError(f"Ошибка подключения/выполнения: {error_msg}") from e

    def _on_analysis_worker_completed(self, ok: bool, payload):
        self._analysis_worker = None

        self.parent.progress_bar.hide()
        self.parent.progress_animation.stop()

        if hasattr(self, "current_analyze_row") and self.current_analyze_row is not None:
            row = self.current_analyze_row
            state_item = self.queries_table.item(row, 7)
            if state_item:
                original_state = state_item.data(Qt.UserRole + 100)
                if original_state:
                    state_item.setText(original_state)
                else:
                    pid_item = self.queries_table.item(row, 0)
                    if pid_item:
                        query_data = pid_item.data(Qt.UserRole)
                        if query_data:
                            state_item.setText(query_data.get("state", ""))
                state_item.setForeground(QColor("#e0e0e0"))
            self.current_analyze_row = None

        self.parent.analysis_result = None

        if ok:
            self.parent.xml_content = payload
            self.parent.analysis_result = True
        else:
            self.parent.analysis_result = str(payload)

        if hasattr(self.parent, "analysis_result"):
            if self.parent.analysis_result is True:
                left_side = None
                for widget in self.parent.findChildren(QTabWidget):
                    if widget.objectName() == "left_side" or widget.count() > 0:
                        left_side = widget
                        break

                if left_side:
                    left_side.setCurrentIndex(0)

                self.parent.analyze_query_plan()
                QMessageBox.information(
                    self, "Успех", "План запроса успешно получен и проанализирован"
                )
            else:
                QMessageBox.critical(
                    self,
                    "Ошибка",
                    f"Не удалось выполнить EXPLAIN для запроса:\n\n{self.parent.analysis_result}\n\n"
                    "Возможные причины:\n"
                    "• Синтаксическая ошибка в запросе\n"
                    "• Запрос не поддерживает EXPLAIN (например, BEGIN/COMMIT)\n"
                    "• Недостаточно прав для выполнения EXPLAIN ANALYZE\n"
                    "• Таблица или схема не существуют",
                )

        self.parent.analysis_result = None

    def clear_history(self):
        reply = QMessageBox.question(
            self,
            "Очистка истории",
            "Вы уверены, что хотите очистить историю запросов?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.parent.query_history.clear_history()
            self.refresh_queries()
            QMessageBox.information(self, "Успех", "История запросов очищена")
