"""Journal window: saved query plans, performance charts, notes."""

import datetime
import html
import json
import logging
import os
import re
from pg_query_analyzer.analysis.plan_parser import (
    accumulate_plan_statistics_from_tree,
    journal_preview_parts_from_plan_doc,
    parse_plan_document,
)
from pg_query_analyzer.analysis.plan_analyzer import analyze_plan_structure
from pg_query_analyzer.analysis.sql_normalize import normalize_query_text
from pg_query_analyzer.db.explain_sql import (
    ExplainSqlError,
    has_pg_bind_placeholders,
    pg_bind_placeholders,
    substitute_pg_bind_placeholders,
    validate_single_statement_sql,
)
from pg_query_analyzer.db.hypopg_sql import extract_hypopg_create_index_ddls
from pg_query_analyzer.observed_plans.exporters.clickhouse import snapshots_to_json_each_row

from PyQt5.QtCore import QSize, Qt, QTimer
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from PyQt5.QtWebEngineWidgets import QWebEngineView
from qtawesome import icon

from pg_query_analyzer.observed_plans.diff import diff_snapshots
from pg_query_analyzer.observed_plans.repository import ObservedPlanRepository
from pg_query_analyzer.observed_plans.sources.auto_explain_logs import (
    append_auto_explain_entries_deduped,
    journal_entries_from_auto_explain_log,
)
from pg_query_analyzer.observed_plans.storage.sqlite import sync_journal_to_sqlite, upsert_snapshots
from pg_query_analyzer.storage.journal import (
    append_journal_entry,
    delete_journal_entry as delete_stored_journal_entry,
    load_journal_entries,
    save_journal_entries,
    trim_journal_entries,
)
from pg_query_analyzer.ui.sql_editor_dialog import SQLHighlighter
from pg_query_analyzer.visualization.html_templates import empty_performance_graph_html


class QueryPlansJournalWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        self.layout = QVBoxLayout(self)

        self.query_groups = {}
        self.query_colors = {}

        self._dialog_highlighters = []
        self._candidate_placeholder_history = {}

        self.tab_widget = QTabWidget()
        self.layout.addWidget(self.tab_widget)

        self.journal_tab = QWidget()
        self.setup_journal_tab()
        self.tab_widget.addTab(self.journal_tab, "📋 Журнал планов")

        self.performance_tab = QWidget()
        self.setup_performance_tab()
        self.tab_widget.addTab(self.performance_tab, "📊 Графы производительности")

        self.observed_plans_tab = QWidget()
        self.setup_observed_plans_tab()
        self.tab_widget.addTab(self.observed_plans_tab, "🧭 Наблюдаемые планы")

        self.tab_widget.currentChanged.connect(self.on_tab_changed)

        self.load_journal()

    def on_tab_changed(self, index):
        tab_text = self.tab_widget.tabText(index)
        if tab_text == "📊 Графы производительности":
            QTimer.singleShot(50, self.refresh_performance_tab)
        elif tab_text == "🧭 Наблюдаемые планы":
            QTimer.singleShot(50, self.refresh_observed_plans_tab)

    def setup_journal_tab(self):
        layout = QVBoxLayout(self.journal_tab)

        self.setup_toolbar()
        self.setup_search_panel()
        self.setup_journal_tree()

        layout.addWidget(self.toolbar)
        layout.addWidget(self.search_panel)
        layout.addWidget(self.journal_tree)

    def setup_performance_tab(self):
        layout = QVBoxLayout(self.performance_tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        control_panel = QWidget()
        control_panel.setStyleSheet("""
            QWidget {
                background-color: #2d2d2d;
                border-bottom: 1px solid #444;
                padding: 5px;
            }
        """)
        control_layout = QHBoxLayout(control_panel)
        control_layout.setContentsMargins(10, 5, 10, 5)
        control_layout.setSpacing(15)

        control_layout.addWidget(QLabel("📊 Группа запросов:"))
        self.graph_group_combo = QComboBox()
        self.graph_group_combo.setMinimumWidth(400)
        self.graph_group_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.graph_group_combo.setStyleSheet("""
            QComboBox {
                background-color: #3a3a3a;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 5px;
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
            QComboBox QAbstractItemView {
                background-color: #3a3a3a;
                color: #e0e0e0;
                selection-background-color: #4a8be5;
                border: 1px solid #555;
            }
        """)
        self.graph_group_combo.currentIndexChanged.connect(self.on_graph_group_changed)
        control_layout.addWidget(self.graph_group_combo)

        control_layout.addWidget(QLabel("📈 Метрика:"))
        self.metric_combo = QComboBox()
        self.metric_combo.addItems(
            ["Общая стоимость", "Количество строк", "Время выполнения", "Seq Scan операции"]
        )
        self.metric_combo.setStyleSheet("""
            QComboBox {
                background-color: #3a3a3a;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 5px;
                font-size: 12px;
            }
        """)
        self.metric_combo.currentIndexChanged.connect(self.update_performance_graph)
        control_layout.addWidget(self.metric_combo)

        control_layout.addWidget(QLabel("📐 Тип графика:"))
        self.chart_type_combo = QComboBox()
        self.chart_type_combo.addItems(
            ["Линейный график", "Столбчатая диаграмма", "Точечная диаграмма"]
        )
        self.chart_type_combo.setStyleSheet("""
            QComboBox {
                background-color: #3a3a3a;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 5px;
                font-size: 12px;
            }
        """)
        self.chart_type_combo.setCurrentIndex(0)
        self.chart_type_combo.currentIndexChanged.connect(self.update_performance_graph)
        control_layout.addWidget(self.chart_type_combo)

        self.export_graph_button = QPushButton(
            icon("fa5s.download", color="white"), " Экспортировать"
        )
        self.export_graph_button.setToolTip("Сохранить график в PNG")
        self.export_graph_button.setStyleSheet("""
            QPushButton {
                background-color: #3a7bd5;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #4a8be5;
            }
            QPushButton:pressed {
                background-color: #2a6bc5;
            }
        """)
        self.export_graph_button.clicked.connect(self.export_performance_graph)
        control_layout.addWidget(self.export_graph_button)

        self.refresh_graph_button = QPushButton(icon("fa5s.sync", color="white"), " Обновить")
        self.refresh_graph_button.setToolTip("Обновить график")
        self.refresh_graph_button.setStyleSheet("""
            QPushButton {
                background-color: #3a7bd5;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #4a8be5;
            }
        """)
        self.refresh_graph_button.clicked.connect(self.update_performance_graph)
        control_layout.addWidget(self.refresh_graph_button)

        control_layout.addStretch()
        layout.addWidget(control_panel)

        self.performance_splitter = QSplitter(Qt.Horizontal)
        self.performance_splitter.setHandleWidth(3)
        self.performance_splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #444;
            }
            QSplitter::handle:hover {
                background-color: #555;
            }
        """)

        graph_container = QWidget()
        graph_layout = QVBoxLayout(graph_container)
        graph_layout.setContentsMargins(0, 0, 0, 0)

        self.graph_viewer = QWebEngineView()
        self.graph_viewer.setStyleSheet("""
            QWebEngineView {
                background-color: #2d2d2d;
                border: none;
            }
        """)
        graph_layout.addWidget(self.graph_viewer)

        stats_container = QWidget()
        stats_container.setMinimumWidth(300)
        stats_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        stats_layout = QVBoxLayout(stats_container)
        stats_layout.setContentsMargins(5, 5, 5, 5)
        stats_layout.setSpacing(0)

        self.stats_panel = QTextBrowser()
        self.stats_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.stats_panel.setStyleSheet("""
            QTextBrowser {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #333;
                border-radius: 4px;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 11px;
            }
        """)
        stats_layout.addWidget(self.stats_panel)

        self.performance_splitter.addWidget(graph_container)
        self.performance_splitter.addWidget(stats_container)
        self.performance_splitter.setSizes([800, 400])

        layout.addWidget(self.performance_splitter, 1)

    def on_graph_group_changed(self, index):
        if index <= 0:
            self.graph_viewer.setHtml(
                self.get_empty_graph_html("Выберите группу запросов из списка")
            )
            self.stats_panel.clear()
            return

        current_data = self.graph_group_combo.currentData()
        if not current_data:
            self.graph_viewer.setHtml(
                self.get_empty_graph_html("Выберите группу запросов из списка")
            )
            return

        model = self.graph_group_combo.model()
        item = model.item(index, 0)
        if item and not item.isEnabled():
            self.graph_viewer.setHtml(
                self.get_empty_graph_html(
                    "Эта группа имеет только одну версию запроса.\n"
                    "Для построения графика необходимо минимум 2 версии одного запроса.\n"
                    "Выполните запрос несколько раз после изменений в БД."
                )
            )
            self.stats_panel.clear()
            return

        self.update_performance_graph()

    def setup_observed_plans_tab(self):
        layout = QVBoxLayout(self.observed_plans_tab)

        controls = QWidget()
        controls_layout = QVBoxLayout(controls)
        controls_layout.setContentsMargins(0, 5, 0, 5)
        controls_layout.setSpacing(6)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(6)

        self.observed_search_edit = QLineEdit()
        self.observed_search_edit.setPlaceholderText(
            "Поиск по queryid, fingerprint, SQL, источнику или типу узла..."
        )
        self.observed_search_edit.textChanged.connect(self.refresh_observed_plans_tab)
        filter_row.addWidget(self.observed_search_edit, 1)

        filter_row.addWidget(QLabel("Источник:"))
        self.observed_source_combo = QComboBox()
        self.observed_source_combo.addItem("JSON журнал", "journal")
        self.observed_source_combo.addItem("SQLite файл", "sqlite")
        self.observed_source_combo.currentIndexChanged.connect(self.refresh_observed_plans_tab)
        filter_row.addWidget(self.observed_source_combo)

        self.observed_sqlite_button = QPushButton(
            icon("fa5s.folder-open", color="white"), " SQLite…"
        )
        self.observed_sqlite_button.setToolTip("Выбрать SQLite repository observed plans")
        self.observed_sqlite_button.clicked.connect(self.choose_observed_sqlite_source)
        filter_row.addWidget(self.observed_sqlite_button)

        self.observed_sync_sqlite_button = QPushButton(
            icon("fa5s.sync-alt", color="white"),
            " Sync",
        )
        self.observed_sync_sqlite_button.setToolTip("Синхронизировать JSON журнал в SQLite")
        self.observed_sync_sqlite_button.clicked.connect(self.sync_observed_json_to_sqlite)
        filter_row.addWidget(self.observed_sync_sqlite_button)

        observed_refresh_button = QPushButton(icon("fa5s.sync", color="white"), " Обновить")
        observed_refresh_button.clicked.connect(self.refresh_observed_plans_tab)
        filter_row.addWidget(observed_refresh_button)

        controls_layout.addLayout(filter_row)

        snapshot_actions = QHBoxLayout()
        snapshot_actions.setSpacing(6)
        snapshot_actions.addWidget(QLabel("Snapshot:"))

        self.observed_compare_button = QPushButton(
            icon("fa5s.code-branch", color="white"),
            " Сравнить",
        )
        self.observed_compare_button.setToolTip("Сравнить два выбранных observed snapshot-а")
        self.observed_compare_button.setEnabled(False)
        self.observed_compare_button.clicked.connect(self.compare_selected_observed_snapshots)
        snapshot_actions.addWidget(self.observed_compare_button)

        self.observed_load_snapshot_button = QPushButton(
            icon("fa5s.upload", color="white"),
            " Загрузить",
        )
        self.observed_load_snapshot_button.setToolTip(
            "Загрузить выбранный snapshot в основной анализ"
        )
        self.observed_load_snapshot_button.setEnabled(False)
        self.observed_load_snapshot_button.clicked.connect(self.load_selected_observed_snapshot)
        snapshot_actions.addWidget(self.observed_load_snapshot_button)

        self.observed_open_graph_button = QPushButton(
            icon("fa5s.project-diagram", color="white"),
            " Граф",
        )
        self.observed_open_graph_button.setToolTip("Открыть граф выбранного snapshot-а")
        self.observed_open_graph_button.setEnabled(False)
        self.observed_open_graph_button.clicked.connect(self.open_selected_observed_snapshot_graph)
        snapshot_actions.addWidget(self.observed_open_graph_button)

        self.observed_send_hypopg_button = QPushButton(
            icon("fa5s.flask", color="white"),
            " В HypoPG",
        )
        self.observed_send_hypopg_button.setToolTip(
            "Отправить SQL и рекомендации snapshot-а в HypoPG"
        )
        self.observed_send_hypopg_button.setEnabled(False)
        self.observed_send_hypopg_button.clicked.connect(
            self.send_selected_observed_snapshot_to_hypopg
        )
        snapshot_actions.addWidget(self.observed_send_hypopg_button)

        self.observed_send_hypopg_pair_button = QPushButton(
            icon("fa5s.vial", color="white"),
            " HypoPG + baseline",
        )
        self.observed_send_hypopg_pair_button.setToolTip(
            "Сохранить baseline и отправить snapshot в HypoPG для пары до/после"
        )
        self.observed_send_hypopg_pair_button.setEnabled(False)
        self.observed_send_hypopg_pair_button.clicked.connect(
            self.send_selected_observed_snapshot_to_hypopg_with_baseline
        )
        snapshot_actions.addWidget(self.observed_send_hypopg_pair_button)

        snapshot_actions.addStretch()
        controls_layout.addLayout(snapshot_actions)

        workload_actions = QHBoxLayout()
        workload_actions.setSpacing(6)
        workload_actions.addWidget(QLabel("Workload:"))

        self.observed_explain_candidate_button = QPushButton(
            icon("fa5s.play", color="white"),
            " Снять EXPLAIN",
        )
        self.observed_explain_candidate_button.setToolTip(
            "Снять EXPLAIN для выбранного candidate из pg_stat_statements"
        )
        self.observed_explain_candidate_button.setEnabled(False)
        self.observed_explain_candidate_button.clicked.connect(
            self.explain_selected_observed_candidate
        )
        workload_actions.addWidget(self.observed_explain_candidate_button)

        import_auto_explain_button = QPushButton(
            icon("fa5s.file-import", color="white"),
            " Импорт auto_explain",
        )
        import_auto_explain_button.setToolTip("Импортировать auto_explain log или JSON plan dump")
        import_auto_explain_button.clicked.connect(self.import_auto_explain_log)
        workload_actions.addWidget(import_auto_explain_button)

        export_clickhouse_button = QPushButton(
            icon("fa5s.download", color="white"),
            " ClickHouse",
        )
        export_clickhouse_button.setToolTip(
            "Экспортировать observed plans в JSONEachRow для ClickHouse"
        )
        export_clickhouse_button.clicked.connect(self.export_observed_plans_clickhouse_json)
        workload_actions.addWidget(export_clickhouse_button)

        export_sqlite_button = QPushButton(
            icon("fa5s.database", color="white"),
            " SQLite export",
        )
        export_sqlite_button.setToolTip("Экспортировать observed plans в SQLite")
        export_sqlite_button.clicked.connect(self.export_observed_plans_sqlite)
        workload_actions.addWidget(export_sqlite_button)

        workload_actions.addStretch()
        controls_layout.addLayout(workload_actions)

        layout.addWidget(controls)

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        self.observed_group_tree = QTreeWidget()
        self.observed_group_tree.setHeaderLabels(["Группа", "Snapshot-ы", "Формы плана"])
        self.observed_group_tree.setColumnCount(3)
        self.observed_group_tree.itemSelectionChanged.connect(self.on_observed_group_selected)
        self.observed_group_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.observed_group_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.observed_group_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        splitter.addWidget(self.observed_group_tree)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(5, 0, 0, 0)

        self.observed_snapshot_tree = QTreeWidget()
        self.observed_snapshot_tree.setHeaderLabels(
            ["Дата", "Источник", "Root", "Cost", "Seq Scan", "Plan shape"]
        )
        self.observed_snapshot_tree.setColumnCount(6)
        self.observed_snapshot_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.observed_snapshot_tree.itemSelectionChanged.connect(self.on_observed_snapshot_selected)
        self.observed_snapshot_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.observed_snapshot_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.observed_snapshot_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.observed_snapshot_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.observed_snapshot_tree.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.observed_snapshot_tree.header().setSectionResizeMode(5, QHeaderView.Stretch)
        right_layout.addWidget(self.observed_snapshot_tree, 2)

        right_layout.addWidget(QLabel("Workload candidates из pg_stat_statements"))
        self.observed_candidate_tree = QTreeWidget()
        self.observed_candidate_tree.setHeaderLabels(
            ["Нужен план", "queryid", "calls", "total_ms", "mean_ms", "журнал", "preview"]
        )
        self.observed_candidate_tree.setColumnCount(7)
        self.observed_candidate_tree.itemSelectionChanged.connect(
            self.on_observed_candidate_selected
        )
        self.observed_candidate_tree.itemDoubleClicked.connect(
            self.send_selected_observed_candidate_to_query_input
        )
        self.observed_candidate_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.observed_candidate_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.observed_candidate_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.observed_candidate_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.observed_candidate_tree.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.observed_candidate_tree.header().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.observed_candidate_tree.header().setSectionResizeMode(6, QHeaderView.Stretch)
        right_layout.addWidget(self.observed_candidate_tree, 1)

        self.observed_details = QTextBrowser()
        self.observed_details.setOpenExternalLinks(False)
        right_layout.addWidget(self.observed_details, 1)

        splitter.addWidget(right_panel)
        splitter.setSizes([430, 870])

        self._observed_groups = {}
        self._observed_candidates = []
        self._observed_repository = None
        self._observed_sqlite_path = ""

    def refresh_observed_plans_tab(self):
        if not hasattr(self, "observed_group_tree"):
            return

        try:
            self._observed_repository = self._load_observed_repository_from_selected_source()
            groups = self._observed_repository.group_by_query_identity()
            search_text = (self.observed_search_edit.text() or "").strip().lower()

            self.observed_group_tree.clear()
            self.observed_snapshot_tree.clear()
            self.observed_candidate_tree.clear()
            self.observed_details.clear()
            self.observed_explain_candidate_button.setEnabled(False)
            self.observed_load_snapshot_button.setEnabled(False)
            self.observed_open_graph_button.setEnabled(False)
            self.observed_send_hypopg_button.setEnabled(False)
            self.observed_send_hypopg_pair_button.setEnabled(False)
            self._observed_groups = {}
            self._observed_candidates = []

            for identity, snapshots in sorted(
                groups.items(),
                key=lambda item: (len(item[1]), item[0]),
                reverse=True,
            ):
                filtered = [
                    snapshot
                    for snapshot in snapshots
                    if self._observed_snapshot_matches_search(snapshot, identity, search_text)
                ]
                if not filtered:
                    continue

                shape_hashes = {
                    snapshot.plan_shape_hash for snapshot in filtered if snapshot.plan_shape_hash
                }
                display_identity = self._format_observed_identity(identity, filtered[0])
                item = QTreeWidgetItem(
                    [
                        display_identity,
                        str(len(filtered)),
                        str(len(shape_hashes)),
                    ]
                )
                if len(shape_hashes) > 1:
                    item.setForeground(2, QColor("#ffcc80"))
                    item.setToolTip(0, "Форма плана менялась во времени")
                item.setData(0, Qt.UserRole, identity)
                self.observed_group_tree.addTopLevelItem(item)
                self._observed_groups[identity] = filtered

            if self.observed_group_tree.topLevelItemCount() > 0:
                self.observed_group_tree.setCurrentItem(self.observed_group_tree.topLevelItem(0))
            else:
                self.observed_details.setHtml(
                    "<p><b>Нет наблюдаемых планов.</b></p>"
                    "<p>Сохраните EXPLAIN в журнал или измените фильтр поиска.</p>"
                )
            self._refresh_observed_workload_candidates(search_text)
        except Exception as e:
            logging.error(f"Ошибка загрузки наблюдаемых планов: {e}")
            self.observed_details.setHtml(
                f"<p><b>Не удалось загрузить наблюдаемые планы:</b> {html.escape(str(e))}</p>"
            )

    def choose_observed_sqlite_source(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Открыть SQLite repository",
            "",
            "SQLite (*.sqlite *.db);;All files (*)",
        )
        if not path:
            return
        self._observed_sqlite_path = path
        idx = self.observed_source_combo.findData("sqlite")
        if idx >= 0:
            self.observed_source_combo.setCurrentIndex(idx)
        self.refresh_observed_plans_tab()

    def _load_observed_repository_from_selected_source(self):
        source = self.observed_source_combo.currentData()
        if source == "sqlite":
            if not self._observed_sqlite_path:
                raise ValueError("Выберите SQLite файл через кнопку «SQLite…».")
            return ObservedPlanRepository.from_sqlite(self._observed_sqlite_path)
        return ObservedPlanRepository.from_journal()

    def sync_observed_json_to_sqlite(self):
        if not self._observed_sqlite_path:
            path, _ = QFileDialog.getSaveFileName(
                self,
                "Выберите SQLite repository для синхронизации",
                "observed_plan_snapshots.sqlite",
                "SQLite (*.sqlite *.db);;All files (*)",
            )
            if not path:
                return
            self._observed_sqlite_path = path

        try:
            count = sync_journal_to_sqlite("query_plans_journal.json", self._observed_sqlite_path)
            idx = self.observed_source_combo.findData("sqlite")
            if idx >= 0:
                self.observed_source_combo.setCurrentIndex(idx)
            self.refresh_observed_plans_tab()
            QMessageBox.information(
                self,
                "SQLite sync",
                f"Синхронизировано snapshot-ов из JSON-журнала: {count}",
            )
        except Exception as e:
            QMessageBox.warning(
                self,
                "SQLite sync",
                f"Не удалось синхронизировать SQLite:\n{str(e)}",
            )

    def on_observed_group_selected(self):
        selected = self.observed_group_tree.selectedItems()
        self.observed_snapshot_tree.clear()
        self.observed_compare_button.setEnabled(False)
        self.observed_load_snapshot_button.setEnabled(False)
        self.observed_open_graph_button.setEnabled(False)
        self.observed_send_hypopg_button.setEnabled(False)
        self.observed_send_hypopg_pair_button.setEnabled(False)
        if not selected:
            return

        identity = selected[0].data(0, Qt.UserRole)
        snapshots = self._observed_groups.get(identity, [])
        for snapshot in snapshots:
            item = QTreeWidgetItem(
                [
                    snapshot.captured_at,
                    snapshot.source,
                    snapshot.summary.top_node_type,
                    self._format_optional_number(snapshot.summary.total_cost),
                    str(snapshot.summary.seq_scan_count),
                    snapshot.plan_shape_hash[:12],
                ]
            )
            if snapshot.source == "hypopg":
                item.setForeground(1, QColor("#ce93d8"))
            elif snapshot.source == "file":
                item.setForeground(1, QColor("#81c784"))
            item.setData(0, Qt.UserRole, snapshot)
            self.observed_snapshot_tree.addTopLevelItem(item)

        if self.observed_snapshot_tree.topLevelItemCount() > 0:
            self.observed_snapshot_tree.setCurrentItem(self.observed_snapshot_tree.topLevelItem(0))

    def _refresh_observed_workload_candidates(self, search_text):
        if not self._observed_repository:
            return

        rows = self._current_pg_stat_statement_rows()
        if not rows:
            item = QTreeWidgetItem(
                [
                    "-",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "Нет загруженных строк. Обновите вкладку pg_stat_statements.",
                ]
            )
            item.setForeground(6, QColor("#888888"))
            self.observed_candidate_tree.addTopLevelItem(item)
            return

        candidates = self._observed_repository.workload_candidates_from_pg_stat_rows(rows)
        self._observed_candidates = candidates
        for candidate in candidates:
            if not self._observed_candidate_matches_search(candidate, search_text):
                continue
            item = QTreeWidgetItem(
                [
                    "да" if candidate.needs_plan_snapshot else "нет",
                    candidate.queryid or "",
                    str(candidate.calls),
                    self._format_optional_number(candidate.total_ms),
                    self._format_optional_number(candidate.mean_ms),
                    str(candidate.journal_matches),
                    self._preview_text(candidate.query_text, 160),
                ]
            )
            if candidate.needs_plan_snapshot:
                item.setForeground(0, QColor("#ffcc80"))
            else:
                item.setForeground(0, QColor("#a5d6a7"))
            item.setData(0, Qt.UserRole, candidate)
            self.observed_candidate_tree.addTopLevelItem(item)

    def _current_pg_stat_statement_rows(self):
        tab = getattr(self.parent, "stat_statements_tab", None)
        if tab is None:
            return []
        if hasattr(tab, "display_rows"):
            return tab.display_rows()
        return list(getattr(tab, "_display_rows", []) or [])

    def on_observed_snapshot_selected(self):
        selected = self.observed_snapshot_tree.selectedItems()
        self.observed_compare_button.setEnabled(len(selected) == 2)
        self.observed_load_snapshot_button.setEnabled(len(selected) == 1)
        self.observed_open_graph_button.setEnabled(len(selected) == 1)
        self.observed_send_hypopg_button.setEnabled(len(selected) == 1)
        self.observed_send_hypopg_pair_button.setEnabled(len(selected) == 1)
        if not selected:
            self.observed_details.clear()
            return
        snapshot = selected[-1].data(0, Qt.UserRole)
        self.observed_details.setHtml(self._observed_snapshot_html(snapshot))

    def on_observed_candidate_selected(self):
        selected = self.observed_candidate_tree.selectedItems()
        if not selected:
            return
        candidate = selected[-1].data(0, Qt.UserRole)
        if candidate is None:
            self.observed_explain_candidate_button.setEnabled(False)
            return
        self.observed_explain_candidate_button.setEnabled(bool(candidate.query_text))
        self.observed_details.setHtml(self._observed_candidate_html(candidate))

    def send_selected_observed_candidate_to_query_input(self, *_args):
        self._put_selected_observed_candidate_in_query_input(switch_to_visualizer=True)

    def explain_selected_observed_candidate(self):
        candidate = self._selected_observed_candidate()
        query_text = getattr(candidate, "query_text", "")
        if has_pg_bind_placeholders(query_text):
            query_text = self._prompt_candidate_placeholder_values(query_text)
            if not query_text:
                return
            self._put_query_text_in_main_input(query_text, switch_to_visualizer=True)
        elif not self._put_selected_observed_candidate_in_query_input(switch_to_visualizer=True):
            return
        try:
            validate_single_statement_sql(query_text)
        except ExplainSqlError as e:
            QMessageBox.information(
                self,
                "EXPLAIN candidate",
                f"{str(e)}\n\nSQL подставлен в поле запроса без запуска EXPLAIN.",
            )
            return
        mw = self.parent
        if not getattr(mw, "connection_status", False):
            QMessageBox.warning(self, "Нет подключения", "Подключитесь к базе данных.")
            return
        if hasattr(mw, "execute_query"):
            mw.execute_query()

    def _prompt_candidate_placeholder_values(self, query_text):
        placeholders = pg_bind_placeholders(query_text)
        dialog = QDialog(self)
        dialog.setWindowTitle("Значения параметров candidate")
        layout = QVBoxLayout(dialog)
        layout.addWidget(
            QLabel(
                "pg_stat_statements хранит запрос без исходных значений параметров.\n"
                "Введите значения для плейсхолдеров; они будут подставлены как SQL literals.\n"
                "Для SQL NULL введите NULL."
            )
        )
        form = QFormLayout()
        edits = {}
        for placeholder, value in self._last_candidate_placeholder_values(query_text).items():
            if placeholder in placeholders:
                edits.setdefault(placeholder, QLineEdit(value))
        for placeholder in placeholders:
            edit = edits.get(placeholder) or QLineEdit()
            hint = self._placeholder_hint(query_text, placeholder)
            edit.setPlaceholderText(hint)
            edits[placeholder] = edit
            form.addRow(f"{placeholder}:", edit)
        layout.addLayout(form)

        auto_fill_button = QPushButton("Подставить автоматически")
        layout.addWidget(auto_fill_button)

        validation_label = QLabel("")
        layout.addWidget(validation_label)

        source_preview = QPlainTextEdit(query_text)
        source_preview.setReadOnly(True)
        source_preview.setMaximumHeight(90)
        layout.addWidget(QLabel("Исходный SQL:"))
        layout.addWidget(source_preview)

        result_preview = QPlainTextEdit()
        result_preview.setReadOnly(True)
        result_preview.setMaximumHeight(150)
        layout.addWidget(QLabel("SQL после подстановки:"))
        layout.addWidget(result_preview)

        def _render_preview():
            values = {ph: edit.text() for ph, edit in edits.items()}
            try:
                substituted = substitute_pg_bind_placeholders(query_text, values)
                result_preview.setPlainText(substituted)
                validate_single_statement_sql(substituted)
                validation_label.setText("SQL валиден для запуска EXPLAIN")
                validation_label.setStyleSheet("color: #81c784;")
            except ExplainSqlError as err:
                validation_label.setText(str(err))
                validation_label.setStyleSheet("color: #ff8a80;")
                result_preview.setPlainText("")

        def _auto_fill():
            for ph, edit in edits.items():
                if edit.text().strip():
                    continue
                guess = self._auto_guess_placeholder_value(query_text, ph)
                if guess:
                    edit.setText(guess)
            _render_preview()

        for edit in edits.values():
            edit.textChanged.connect(_render_preview)
        auto_fill_button.clicked.connect(_auto_fill)
        _render_preview()

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Подставить и выполнить EXPLAIN")
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec_() != QDialog.Accepted:
            self._put_query_text_in_main_input(query_text, switch_to_visualizer=True)
            return ""

        values = {placeholder: edit.text() for placeholder, edit in edits.items()}
        try:
            substituted = substitute_pg_bind_placeholders(query_text, values)
            validate_single_statement_sql(substituted)
        except ExplainSqlError as e:
            QMessageBox.warning(self, "EXPLAIN candidate", str(e))
            self._put_query_text_in_main_input(query_text, switch_to_visualizer=True)
            return ""
        self._save_candidate_placeholder_values(query_text, values)
        self._put_query_text_in_main_input(substituted, switch_to_visualizer=True)
        return substituted

    def _last_candidate_placeholder_values(self, query_text):
        key = normalize_query_text(query_text or "")
        return dict(self._candidate_placeholder_history.get(key, {}))

    def _save_candidate_placeholder_values(self, query_text, values):
        key = normalize_query_text(query_text or "")
        if not key:
            return
        self._candidate_placeholder_history[key] = {
            placeholder: str(value or "").strip() for placeholder, value in values.items()
        }

    def _placeholder_hint(self, query_text, placeholder):
        suggestion = self._auto_guess_placeholder_value(query_text, placeholder)
        if suggestion:
            return f"например: {suggestion}"
        return "например: postgres или 123 или prod.*"

    def _auto_guess_placeholder_value(self, query_text, placeholder):
        uuid_example = "550e8400-e29b-41d4-a716-446655440000"
        pattern = re.escape(placeholder)
        if re.search(rf"(?is){pattern}\s*::\s*uuid\b", query_text):
            return uuid_example
        if re.search(rf"(?is)\buuid\s*[\)=,]\s*{pattern}\b", query_text):
            return uuid_example
        if re.search(rf"(?is)\blimit\s+{pattern}\b", query_text):
            return "100"
        if re.search(rf"(?is)\boffset\s+{pattern}\b", query_text):
            return "0"
        if re.search(rf"(?is)\b(?:in|not\s+in)\s*\(\s*{pattern}\s*\)", query_text):
            return "1"
        left_context = re.search(rf"(?is)(\w+)\s*=\s*{pattern}", query_text)
        if left_context:
            col_name = left_context.group(1).lower()
            if "uuid" in col_name or col_name.endswith("guid"):
                return uuid_example
            if "id" in col_name and not any(
                token in col_name for token in ("type", "kind", "code", "status")
            ):
                return uuid_example
            if any(token in col_name for token in ("id", "count", "num", "limit", "size")):
                return "1"
            if any(token in col_name for token in ("date", "time")):
                return "2026-01-01"
        return "1"

    def _selected_observed_candidate(self):
        selected = self.observed_candidate_tree.selectedItems()
        if not selected:
            return None
        return selected[-1].data(0, Qt.UserRole)

    def load_selected_observed_snapshot(self):
        snapshot = self._selected_observed_snapshot()
        if snapshot is None:
            return
        self._load_observed_snapshot(snapshot, switch_to_graph=False)

    def open_selected_observed_snapshot_graph(self):
        snapshot = self._selected_observed_snapshot()
        if snapshot is None:
            return
        self._load_observed_snapshot(snapshot, switch_to_graph=True)

    def _selected_observed_snapshot(self):
        selected = self.observed_snapshot_tree.selectedItems()
        if len(selected) != 1:
            return None
        return selected[0].data(0, Qt.UserRole)

    def _load_observed_snapshot(self, snapshot, *, switch_to_graph):
        if not self.parent:
            return
        try:
            self.parent.is_loading_from_journal = True
            self.parent.xml_content = snapshot.plan_document
            if snapshot.query_text and hasattr(self.parent, "query_input"):
                self.parent.query_input.setText(snapshot.query_text)
            self.parent.analyze_query_plan()
            if switch_to_graph and hasattr(self.parent, "left_tabs"):
                for i in range(self.parent.left_tabs.count()):
                    if self.parent.left_tabs.tabText(i).startswith("💹"):
                        self.parent.left_tabs.setCurrentIndex(i)
                        break
            if hasattr(self.parent, "show_plan_workspace"):
                self.parent.show_plan_workspace()
            else:
                self.parent.showMaximized()
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить observed snapshot: {str(e)}")
        finally:
            self.parent.is_loading_from_journal = False

    def send_selected_observed_snapshot_to_hypopg(self):
        self._send_selected_observed_snapshot_to_hypopg(create_baseline_pair=False)

    def send_selected_observed_snapshot_to_hypopg_with_baseline(self):
        self._send_selected_observed_snapshot_to_hypopg(create_baseline_pair=True)

    def _send_selected_observed_snapshot_to_hypopg(self, *, create_baseline_pair):
        snapshot = self._selected_observed_snapshot()
        if snapshot is None:
            return
        mw = self.parent
        if not mw:
            return
        if not snapshot.query_text.strip():
            QMessageBox.information(
                self,
                "HypoPG",
                "У выбранного snapshot-а нет сохранённого SQL текста.",
            )
            return

        ddls = self._hypopg_ddls_for_snapshot(snapshot)
        if create_baseline_pair:
            if not self._prepare_hypopg_baseline_pair(snapshot):
                return
        hypopg_tab = getattr(mw, "hypopg_tab", None)
        if hypopg_tab is None:
            QMessageBox.information(self, "HypoPG", "Вкладка HypoPG недоступна.")
            return

        hypopg_tab.load_from_observed_snapshot(
            query_sql=snapshot.query_text,
            create_index_ddls=ddls,
            source_label=snapshot.source or "observed snapshot",
        )
        self._switch_main_window_to_hypopg()
        if not ddls:
            QMessageBox.information(
                self,
                "HypoPG",
                "SQL отправлен в HypoPG, но CREATE INDEX в рекомендациях для snapshot-а не найден.",
            )

    def _prepare_hypopg_baseline_pair(self, snapshot):
        mw = self.parent
        if not mw:
            return False
        if not hasattr(mw, "save_hypopg_baseline_for_comparison"):
            QMessageBox.information(self, "HypoPG", "Сохранение baseline-пары недоступно.")
            return False
        try:
            mw.xml_content = snapshot.plan_document
            if snapshot.query_text and hasattr(mw, "query_input"):
                mw.query_input.setText(snapshot.query_text)
            return bool(mw.save_hypopg_baseline_for_comparison())
        except Exception as e:
            QMessageBox.warning(
                self,
                "HypoPG",
                f"Не удалось сохранить baseline для HypoPG-пары:\n{str(e)}",
            )
            return False

    def _hypopg_ddls_for_snapshot(self, snapshot):
        try:
            tree = parse_plan_document(snapshot.plan_document)
            settings = getattr(self.parent, "analyzer_settings", {}) if self.parent else {}
            analysis, _meta = analyze_plan_structure(
                tree,
                settings,
                sql_query=snapshot.query_text,
            )
            return extract_hypopg_create_index_ddls(analysis.get("optimization", ""))
        except Exception:
            logging.debug("Не удалось извлечь DDL HypoPG из observed snapshot", exc_info=True)
            return []

    def _switch_main_window_to_hypopg(self):
        mw = self.parent
        if not mw:
            return
        if hasattr(mw, "left_tabs"):
            admin_label = getattr(mw, "ADMIN_TAB_LABEL", "🛠 Обслуживание БД")
            for i in range(mw.left_tabs.count()):
                if mw.left_tabs.tabText(i) == admin_label:
                    mw.left_tabs.setCurrentIndex(i)
                    break
        tab_widget = getattr(mw, "db_optimization_tab_widget", None)
        if tab_widget is not None:
            for i in range(tab_widget.count()):
                if tab_widget.tabText(i) == "HypoPG Lab":
                    tab_widget.setCurrentIndex(i)
                    break

    def import_auto_explain_log(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Импорт auto_explain log",
            "",
            "PostgreSQL logs / JSON (*.log *.json *.txt);;All files (*)",
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            entries = journal_entries_from_auto_explain_log(
                content,
                source_name=os.path.basename(path),
            )
            if not entries:
                QMessageBox.information(
                    self,
                    "Импорт auto_explain",
                    "В файле не найдены JSON-планы auto_explain.",
                )
                return

            max_entries = 1000
            if self.parent and hasattr(self.parent, "analyzer_settings"):
                max_entries = self.parent.analyzer_settings.get("journal", {}).get(
                    "max_entries",
                    1000,
                )
            existing_entries = load_journal_entries()
            updated_entries, added_count = append_auto_explain_entries_deduped(
                existing_entries,
                entries,
            )
            if added_count <= 0:
                QMessageBox.information(
                    self,
                    "Импорт auto_explain",
                    "Новых plan snapshot-ов не найдено: все записи уже есть в журнале.",
                )
                return

            save_journal_entries(trim_journal_entries(updated_entries, max_entries))

            QMessageBox.information(
                self,
                "Импорт auto_explain",
                f"Импортировано новых plan snapshot-ов: {added_count}",
            )
            self.load_journal()
        except Exception as e:
            logging.error("Ошибка импорта auto_explain log", exc_info=True)
            QMessageBox.warning(
                self,
                "Импорт auto_explain",
                f"Не удалось импортировать файл:\n{str(e)}",
            )

    def export_observed_plans_clickhouse_json(self):
        repo = self._observed_repository or ObservedPlanRepository.from_journal()
        snapshots = repo.list_snapshots()
        if not snapshots:
            QMessageBox.information(
                self, "Экспорт ClickHouse", "Нет наблюдаемых планов для экспорта."
            )
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт observed plans для ClickHouse",
            "observed_plan_snapshots.jsonl",
            "JSONEachRow (*.jsonl);;All files (*)",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(snapshots_to_json_each_row(snapshots))
            QMessageBox.information(
                self,
                "Экспорт ClickHouse",
                f"Экспортировано snapshot-ов: {len(snapshots)}",
            )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Экспорт ClickHouse",
                f"Не удалось экспортировать файл:\n{str(e)}",
            )

    def export_observed_plans_sqlite(self):
        repo = self._observed_repository or ObservedPlanRepository.from_journal()
        snapshots = repo.list_snapshots()
        if not snapshots:
            QMessageBox.information(self, "Экспорт SQLite", "Нет наблюдаемых планов для экспорта.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт observed plans в SQLite",
            "observed_plan_snapshots.sqlite",
            "SQLite (*.sqlite *.db);;All files (*)",
        )
        if not path:
            return
        try:
            count = upsert_snapshots(path, snapshots)
            QMessageBox.information(
                self,
                "Экспорт SQLite",
                f"Синхронизировано snapshot-ов: {count}",
            )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Экспорт SQLite",
                f"Не удалось экспортировать SQLite:\n{str(e)}",
            )

    def _put_selected_observed_candidate_in_query_input(self, *, switch_to_visualizer):
        candidate = self._selected_observed_candidate()
        query_text = getattr(candidate, "query_text", "")
        if not query_text:
            return False
        self._put_query_text_in_main_input(
            query_text.strip(), switch_to_visualizer=switch_to_visualizer
        )
        return True

    def _put_query_text_in_main_input(self, query_text, *, switch_to_visualizer):
        mw = self.parent
        if hasattr(mw, "query_input"):
            mw.query_input.setText((query_text or "").strip())
        if switch_to_visualizer and hasattr(mw, "left_tabs"):
            for i in range(mw.left_tabs.count()):
                if mw.left_tabs.tabText(i).startswith("💹"):
                    mw.left_tabs.setCurrentIndex(i)
                    break

    def compare_selected_observed_snapshots(self):
        selected = self.observed_snapshot_tree.selectedItems()
        if len(selected) != 2:
            return

        left = selected[0].data(0, Qt.UserRole)
        right = selected[1].data(0, Qt.UserRole)
        older, newer = sorted([left, right], key=lambda snapshot: snapshot.captured_at)
        diff_items = diff_snapshots(older, newer)

        rows = []
        for item in diff_items:
            color = {
                "success": "#51cf66",
                "warning": "#ff6b6b",
                "info": "#74c0fc",
            }.get(item.severity, "#e0e0e0")
            rows.append(
                "<tr>"
                f"<td style='color:{color}'>{html.escape(item.severity)}</td>"
                f"<td>{html.escape(item.title)}</td>"
                f"<td>{html.escape(str(item.before_value))}</td>"
                f"<td>{html.escape(str(item.after_value))}</td>"
                f"<td>{html.escape(item.details)}</td>"
                "</tr>"
            )

        body = "".join(rows) or "<tr><td colspan='5'>Существенных отличий не найдено</td></tr>"
        self.observed_details.setHtml(
            "<h3>Сравнение наблюдаемых планов</h3>"
            f"<p><b>До:</b> {html.escape(older.captured_at)}<br>"
            f"<b>После:</b> {html.escape(newer.captured_at)}</p>"
            "<table border='1' cellspacing='0' cellpadding='4'>"
            "<tr><th>Severity</th><th>Сигнал</th><th>До</th><th>После</th><th>Детали</th></tr>"
            f"{body}</table>"
        )

    def _observed_snapshot_matches_search(self, snapshot, identity, search_text):
        if not search_text:
            return True
        haystack = " ".join(
            [
                identity,
                snapshot.query_text,
                snapshot.normalized_query,
                snapshot.queryid or "",
                snapshot.source,
                snapshot.source_name,
                snapshot.summary.top_node_type,
                snapshot.plan_hash,
                snapshot.plan_shape_hash,
            ]
        ).lower()
        return search_text in haystack

    def _observed_candidate_matches_search(self, candidate, search_text):
        if not search_text:
            return True
        haystack = " ".join(
            [
                candidate.query_text,
                candidate.query_fingerprint,
                candidate.queryid or "",
                candidate.source,
                " ".join(candidate.merged_queryids),
            ]
        ).lower()
        return search_text in haystack

    def _observed_snapshot_html(self, snapshot):
        summary = snapshot.summary
        sql_preview = html.escape(snapshot.query_text or "SQL не сохранён")
        return (
            "<h3>Observed Plan Snapshot</h3>"
            f"<p><b>Дата:</b> {html.escape(snapshot.captured_at)}<br>"
            f"<b>Источник:</b> {html.escape(snapshot.source)}"
            f" / {html.escape(snapshot.source_name)}<br>"
            f"<b>Query ID:</b> {html.escape(snapshot.queryid or 'нет')}<br>"
            f"<b>Fingerprint:</b> {html.escape(snapshot.query_fingerprint or 'нет')}<br>"
            f"<b>Plan hash:</b> {html.escape(snapshot.plan_hash[:16])}<br>"
            f"<b>Shape hash:</b> {html.escape(snapshot.plan_shape_hash[:16])}</p>"
            "<h4>Summary</h4>"
            f"<p><b>Root:</b> {html.escape(summary.top_node_type)}<br>"
            f"<b>Total cost:</b> {self._format_optional_number(summary.total_cost)}<br>"
            f"<b>Plan rows:</b> {self._format_optional_number(summary.plan_rows)}<br>"
            f"<b>Actual total time:</b> "
            f"{self._format_optional_number(summary.actual_total_time)}<br>"
            f"<b>Actual rows:</b> {self._format_optional_number(summary.actual_rows)}<br>"
            f"<b>Nodes:</b> {summary.node_count}<br>"
            f"<b>Seq Scan:</b> {summary.seq_scan_count}<br>"
            f"<b>Temp written blocks:</b> {summary.temp_written_blocks}<br>"
            f"<b>Shared read/hit blocks:</b> "
            f"{summary.shared_read_blocks} / {summary.shared_hit_blocks}</p>"
            "<h4>SQL</h4>"
            f"<pre>{sql_preview}</pre>"
        )

    def _observed_candidate_html(self, candidate):
        sql_preview = html.escape(candidate.query_text or "SQL не сохранён")
        merged = ", ".join(candidate.merged_queryids) if candidate.merged_queryids else "нет"
        status = (
            "Нужно снять EXPLAIN и сохранить snapshot"
            if candidate.needs_plan_snapshot
            else "В журнале уже есть связанный plan snapshot"
        )
        return (
            "<h3>Workload Candidate</h3>"
            f"<p><b>Статус:</b> {html.escape(status)}<br>"
            f"<b>Источник:</b> {html.escape(candidate.source)}<br>"
            f"<b>Query ID:</b> {html.escape(candidate.queryid or 'нет')}<br>"
            f"<b>Fingerprint:</b> {html.escape(candidate.query_fingerprint or 'нет')}<br>"
            f"<b>Calls:</b> {candidate.calls}<br>"
            f"<b>Total ms:</b> {self._format_optional_number(candidate.total_ms)}<br>"
            f"<b>Mean ms:</b> {self._format_optional_number(candidate.mean_ms)}<br>"
            f"<b>Rows:</b> {candidate.rows_sum}<br>"
            f"<b>Snapshot-ов в журнале:</b> {candidate.journal_matches}<br>"
            f"<b>Совпадение queryid:</b> {'да' if candidate.saved_queryid_match else 'нет'}<br>"
            f"<b>Объединённые queryid:</b> {html.escape(merged)}</p>"
            "<p>Двойной клик по строке подставит SQL в поле запроса для ручного EXPLAIN.</p>"
            "<h4>SQL</h4>"
            f"<pre>{sql_preview}</pre>"
        )

    def _format_observed_identity(self, identity, snapshot):
        if identity.startswith("queryid:"):
            return identity
        if snapshot.normalized_query:
            text = snapshot.normalized_query
            return text if len(text) <= 90 else text[:87] + "..."
        return identity

    def _format_optional_number(self, value):
        if value is None:
            return ""
        if isinstance(value, float):
            return f"{value:.3f}".rstrip("0").rstrip(".")
        return str(value)

    def _preview_text(self, text, max_len):
        preview = (text or "").replace("\n", " ").strip()
        if len(preview) <= max_len:
            return preview
        return preview[: max_len - 1] + "…"

    def setup_toolbar(self):
        self.toolbar = QToolBar()
        self.toolbar.setIconSize(QSize(16, 16))

        self.add_note_button = QPushButton(icon("fa5s.plus", color="white"), " Добавить заметку")
        self.add_note_button.clicked.connect(self.add_custom_note)
        self.toolbar.addWidget(self.add_note_button)

        self.edit_button = QPushButton(icon("fa5s.edit", color="white"), " Редактировать")
        self.edit_button.clicked.connect(self.edit_selected_entry)
        self.edit_button.setEnabled(False)
        self.toolbar.addWidget(self.edit_button)

        self.delete_button = QPushButton(icon("fa5s.trash-alt", color="white"), " Удалить")
        self.delete_button.clicked.connect(self.delete_selected_entry)
        self.delete_button.setEnabled(False)
        self.toolbar.addWidget(self.delete_button)

        self.clear_button = QPushButton(icon("fa5s.broom", color="white"), " Очистить журнал")
        self.clear_button.clicked.connect(self.clear_journal)
        self.toolbar.addWidget(self.clear_button)

        self.refresh_button = QPushButton(icon("fa5s.sync", color="white"), " Обновить")
        self.refresh_button.clicked.connect(self.load_journal)
        self.toolbar.addWidget(self.refresh_button)

        self.view_query_button = QPushButton(icon("fa5s.code", color="white"), " Показать запрос")
        self.view_query_button.clicked.connect(self.view_query_text)
        self.view_query_button.setEnabled(False)
        self.toolbar.addWidget(self.view_query_button)

        self.compare_version_button = QPushButton(
            icon("fa5s.code-branch", color="white"), " Сравнить планы"
        )
        self.compare_version_button.setToolTip(
            "Выделите две любые записи — сравнить их планы; или одну запись: пара HypoPG либо "
            "предыдущая версия того же запроса."
        )
        self.compare_version_button.clicked.connect(self.compare_with_previous_version)
        self.compare_version_button.setEnabled(False)
        self.toolbar.addWidget(self.compare_version_button)

        self.add_to_graph_button = QPushButton(
            icon("fa5s.chart-line", color="white"), " Добавить в график"
        )
        self.add_to_graph_button.clicked.connect(self.add_selected_to_graph)
        self.add_to_graph_button.setEnabled(False)
        self.toolbar.addWidget(self.add_to_graph_button)

    def setup_search_panel(self):
        self.search_panel = QWidget()
        search_layout = QHBoxLayout(self.search_panel)
        search_layout.setContentsMargins(0, 5, 0, 5)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск по названию, описанию или запросу...")
        self.search_edit.textChanged.connect(self.filter_journal)
        search_layout.addWidget(self.search_edit)

        clear_search_button = QPushButton(icon("fa5s.times", color="white"), "")
        clear_search_button.setToolTip("Очистить поиск")
        clear_search_button.clicked.connect(lambda: self.search_edit.clear())
        search_layout.addWidget(clear_search_button)

        self.sort_combo = QComboBox()
        self.sort_combo.addItems(
            [
                "Сортировка: по дате (новые)",
                "Сортировка: по дате (старые)",
                "Сортировка: по названию",
                "Сортировка: по стоимости",
                "Сортировка: по группе запроса",
            ]
        )
        self.sort_combo.currentIndexChanged.connect(self.sort_journal)
        search_layout.addWidget(self.sort_combo)

        self.group_filter = QComboBox()
        self.group_filter.addItem("Все запросы", "")
        self.group_filter.currentIndexChanged.connect(self.filter_by_group)
        search_layout.addWidget(QLabel("Группа:"))
        search_layout.addWidget(self.group_filter)

    def setup_journal_tree(self):
        self.journal_tree = QTreeWidget()
        self.journal_tree.setHeaderLabels(
            ["Название", "Дата", "Источник", "Стоимость", "Тип", "Группа", "Тренд"]
        )
        self.journal_tree.setColumnCount(7)

        header = self.journal_tree.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)

        self.journal_tree.setSortingEnabled(True)
        self.journal_tree.sortByColumn(1, Qt.DescendingOrder)

        self.journal_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                font-size: 12px;
                alternate-background-color: #333333;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:hover {
                background-color: #3a3a3a;
            }
            QTreeWidget::item:selected {
                background-color: #3a7bd5;
            }
        """)

        self.journal_tree.setAlternatingRowColors(True)
        self.journal_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.journal_tree.customContextMenuRequested.connect(self.show_context_menu)
        self.journal_tree.itemDoubleClicked.connect(self.load_plan_from_journal)
        self.journal_tree.itemSelectionChanged.connect(self.update_buttons_state)
        self.journal_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)

    def update_buttons_state(self):
        selected = len(self.journal_tree.selectedItems()) > 0
        self.edit_button.setEnabled(selected)
        self.delete_button.setEnabled(selected)
        self.view_query_button.setEnabled(selected)
        self.add_to_graph_button.setEnabled(selected)

        if selected and len(self.journal_tree.selectedItems()) == 2:
            self.compare_version_button.setEnabled(True)
        elif selected and len(self.journal_tree.selectedItems()) == 1:
            current_item = self.journal_tree.selectedItems()[0]
            entry = current_item.data(0, Qt.UserRole)
            pair_other = self._find_hypopg_pair_entry(entry)
            previous_version = self._find_previous_version(entry)
            self.compare_version_button.setEnabled(
                pair_other is not None or previous_version is not None
            )
        else:
            self.compare_version_button.setEnabled(False)

    def add_selected_to_graph(self):
        selected_items = self.journal_tree.selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        entry = item.data(0, Qt.UserRole)

        group_normalized = entry.get("_group_normalized", "")
        if not group_normalized:
            QMessageBox.information(
                self, "Информация", "Эта запись не принадлежит ни одной группе запросов"
            )
            return

        self.tab_widget.setCurrentIndex(1)

        group_name = self.query_groups.get(group_normalized, {}).get("name", "")
        if group_name:
            index = self.graph_group_combo.findText(group_name)
            if index >= 0:
                self.graph_group_combo.setCurrentIndex(index)
                QMessageBox.information(
                    self, "Успех", f"Запрос добавлен в группу '{group_name}' для анализа"
                )

    def update_performance_graph(self):
        current_data = self.graph_group_combo.currentData()

        if not current_data or current_data == "":
            self.graph_viewer.setHtml(
                self.get_empty_graph_html("Выберите группу запросов из списка")
            )
            self.stats_panel.clear()
            return

        group_data = self.query_groups.get(current_data)

        if not group_data:
            self.graph_viewer.setHtml(
                self.get_empty_graph_html(f"Группа с идентификатором '{current_data}' не найдена")
            )
            self.stats_panel.clear()
            return

        entries = group_data["entries"]

        if len(entries) < 2:
            self.graph_viewer.setHtml(
                self.get_empty_graph_html(
                    f"Для группы '{group_data['name']}' недостаточно данных для построения графика.\n"
                    f"Найдено только {len(entries)} версия (нужно минимум 2)"
                )
            )
            self.stats_panel.clear()
            return

        metric = self.metric_combo.currentText()
        chart_type = self.chart_type_combo.currentText()

        metric_key = {
            "Общая стоимость": "total_cost",
            "Количество строк": "total_rows",
            "Время выполнения": "execution_time",
            "Seq Scan операции": "seq_scans",
        }.get(metric, "total_cost")

        html = self.generate_performance_graph(entries, metric, metric_key, chart_type)
        self.graph_viewer.setHtml(html)

        self.update_stats_panel(entries, metric)

    def generate_performance_graph(self, entries, metric, metric_key, chart_type):
        sorted_entries = sorted(entries, key=lambda x: x.get("timestamp", ""))

        dates = []
        values = []

        for entry in sorted_entries:
            timestamp = entry.get("timestamp", "")
            dates.append(timestamp)

            stats = self._extract_plan_stats(entry.get("xml_content", ""))

            if metric_key == "total_cost":
                value = stats["total_cost"] if stats["total_cost"] is not None else 0
            elif metric_key == "total_rows":
                value = stats["total_rows"] if stats["total_rows"] is not None else 0
            elif metric_key == "execution_time":
                value = (stats["total_cost"] / 100) if stats["total_cost"] else 0
            elif metric_key == "seq_scans":
                value = stats["seq_scans"]
            else:
                value = 0

            values.append(value)

        if all(v == 0 for v in values):
            return self.get_empty_graph_html(
                "Не удалось извлечь данные для построения графика. Убедитесь, что XML планы содержат информацию о стоимости."
            )

        trend_colors = []
        for i in range(len(values)):
            if i == 0:
                trend_colors.append("#4fc3f7")
            else:
                if values[i] < values[i - 1]:
                    trend_colors.append("#51cf66")
                elif values[i] > values[i - 1]:
                    trend_colors.append("#ff6b6b")
                else:
                    trend_colors.append("#fcc419")

        formatted_dates = []
        for date in dates:
            if datetime.datetime.now().strftime("%Y-%m-%d") in date:
                formatted_dates.append(date.split(" ")[1] if " " in date else date)
            else:
                formatted_dates.append(date)

        scatter_data = [{"x": i + 1, "y": v} for i, v in enumerate(values)]

        if chart_type == "Линейный график":
            chart_config = f"""
                type: 'line',
                data: {{
                    labels: {json.dumps(formatted_dates)},
                    datasets: [{{
                        label: '{metric}',
                        data: {json.dumps(values)},
                        borderColor: 'rgb(75, 192, 192)',
                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                        tension: 0.1,
                        fill: true,
                        pointBackgroundColor: {json.dumps(trend_colors)},
                        pointBorderColor: '#ffffff',
                        pointRadius: 6,
                        pointHoverRadius: 8
                    }}]
                }}
            """
        elif chart_type == "Столбчатая диаграмма":
            chart_config = f"""
                type: 'bar',
                data: {{
                    labels: {json.dumps(formatted_dates)},
                    datasets: [{{
                        label: '{metric}',
                        data: {json.dumps(values)},
                        backgroundColor: {json.dumps(trend_colors)},
                        borderColor: 'rgb(75, 192, 192)',
                        borderWidth: 1
                    }}]
                }}
            """
        else:
            chart_config = f"""
                type: 'scatter',
                data: {{
                    datasets: [{{
                        label: '{metric}',
                        data: {json.dumps(scatter_data)},
                        backgroundColor: {json.dumps(trend_colors)},
                        borderColor: 'rgb(75, 192, 192)',
                        pointRadius: 8,
                        pointHoverRadius: 10,
                        showLine: true,
                        lineTension: 0.1
                    }}]
                }}
            """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
            <style>
                body {{
                    margin: 0;
                    padding: 20px;
                    background-color: #2d2d2d;
                    font-family: 'Segoe UI', Arial, sans-serif;
                }}
                canvas {{
                    max-width: 100%;
                    height: auto;
                    max-height: 70vh;
                }}
                .info {{
                    color: #e0e0e0;
                    text-align: center;
                    margin-top: 15px;
                    font-size: 12px;
                }}
                .legend {{
                    display: inline-block;
                    margin: 0 10px;
                }}
                .legend-color {{
                    display: inline-block;
                    width: 12px;
                    height: 12px;
                    border-radius: 2px;
                    margin-right: 5px;
                }}
            </style>
        </head>
        <body>
            <canvas id="performanceChart"></canvas>
            <div class="info">
                <span class="legend"><span class="legend-color" style="background-color: #51cf66;"></span>Улучшение</span>
                <span class="legend"><span class="legend-color" style="background-color: #ff6b6b;"></span>Ухудшение</span>
                <span class="legend"><span class="legend-color" style="background-color: #fcc419;"></span>Без изменений</span>
                <span class="legend"><span class="legend-color" style="background-color: #4fc3f7;"></span>Первая версия</span>
            </div>
            <script>
                const ctx = document.getElementById('performanceChart').getContext('2d');
                
                let config = {{
                    {chart_config},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {{
                            legend: {{
                                labels: {{
                                    color: '#e0e0e0',
                                    font: {{
                                        size: 12
                                    }}
                                }}
                            }},
                            tooltip: {{
                                callbacks: {{
                                    label: function(context) {{
                                        let label = context.dataset.label || '';
                                        if (label) {{
                                            label += ': ';
                                        }}
                                        let value = context.parsed.y !== undefined ? context.parsed.y : context.raw;
                                        if (typeof value === 'number') {{
                                            label += value.toFixed(2);
                                        }} else {{
                                            label += value;
                                        }}
                                        return label;
                                    }}
                                }}
                            }}
                        }},
                        scales: {{
                            x: {{
                                ticks: {{
                                    color: '#e0e0e0',
                                    maxRotation: 45,
                                    minRotation: 45,
                                    autoSkip: true,
                                    maxTicksLimit: 10
                                }},
                                title: {{
                                    display: true,
                                    text: 'Дата и время',
                                    color: '#e0e0e0',
                                    font: {{
                                        size: 12
                                    }}
                                }}
                            }},
                            y: {{
                                ticks: {{
                                    color: '#e0e0e0'
                                }},
                                title: {{
                                    display: true,
                                    text: '{metric}',
                                    color: '#e0e0e0',
                                    font: {{
                                        size: 12
                                    }}
                                }},
                                beginAtZero: true
                            }}
                        }}
                    }}
                }};
                
                new Chart(ctx, config);
            </script>
        </body>
        </html>
        """

        return html

    def update_stats_panel(self, entries, metric):
        if not entries:
            self.stats_panel.clear()
            return

        sorted_entries = sorted(entries, key=lambda x: x.get("timestamp", ""))

        stats_data = []
        for entry in sorted_entries:
            plan_stats = self._extract_plan_stats(entry.get("xml_content", ""))

            if metric == "Общая стоимость":
                value = plan_stats["total_cost"] if plan_stats["total_cost"] is not None else 0
            elif metric == "Количество строк":
                value = plan_stats["total_rows"] if plan_stats["total_rows"] is not None else 0
            elif metric == "Время выполнения":
                value = (plan_stats["total_cost"] / 100) if plan_stats["total_cost"] else 0
            else:
                value = plan_stats["seq_scans"]

            stats_data.append(
                {
                    "timestamp": entry.get("timestamp", ""),
                    "value": value,
                    "total_cost": (
                        plan_stats["total_cost"] if plan_stats["total_cost"] is not None else 0
                    ),
                    "total_rows": (
                        plan_stats["total_rows"] if plan_stats["total_rows"] is not None else 0
                    ),
                    "seq_scans": plan_stats["seq_scans"],
                }
            )

        if len(stats_data) > 1:
            first_value = stats_data[0]["value"]
            last_value = stats_data[-1]["value"]
            change = last_value - first_value
            change_percent = (change / first_value * 100) if first_value != 0 else 0

            if change < 0:
                trend_text = "Улучшение"
            elif change > 0:
                trend_text = "Ухудшение"
            else:
                trend_text = "Без изменений"
        else:
            trend_text = "Недостаточно данных"
            change = 0
            change_percent = 0

        valid_costs = [d for d in stats_data if d["total_cost"] > 0]
        best_plan = min(valid_costs, key=lambda x: x["total_cost"]) if valid_costs else None
        worst_plan = max(valid_costs, key=lambda x: x["total_cost"]) if valid_costs else None

        improvements = 0
        regressions = 0
        for i in range(1, len(stats_data)):
            if stats_data[i]["value"] < stats_data[i - 1]["value"]:
                improvements += 1
            elif stats_data[i]["value"] > stats_data[i - 1]["value"]:
                regressions += 1

        best_cost_str = f"{best_plan['total_cost']:.2f}" if best_plan else "—"
        best_date_str = best_plan["timestamp"][:16] if best_plan else ""
        worst_cost_str = f"{worst_plan['total_cost']:.2f}" if worst_plan else "—"
        worst_date_str = worst_plan["timestamp"][:16] if worst_plan else ""
        first_date_str = stats_data[0]["timestamp"][:16] if stats_data else "—"
        last_date_str = stats_data[-1]["timestamp"][:16] if stats_data else "—"

        avg_cost = sum(d["total_cost"] for d in stats_data) / len(stats_data) if stats_data else 0
        avg_rows = sum(d["total_rows"] for d in stats_data) / len(stats_data) if stats_data else 0
        total_seq_scans = sum(d["seq_scans"] for d in stats_data)
        current_value = stats_data[-1]["value"] if stats_data else 0

        unit_map = {
            "Общая стоимость": "усл. ед.",
            "Количество строк": "строк",
            "Время выполнения": "сек",
            "Seq Scan операции": "опер.",
        }
        unit = unit_map.get(metric, "")

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                body {{
                    margin: 0;
                    padding: 16px;
                    font-family: 'Segoe UI', 'Consolas', 'Monaco', monospace;
                    font-size: 13px;
                    background-color: #1e1e1e;
                    color: #cccccc;
                }}
                
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                
                .section {{
                    margin-bottom: 20px;
                }}
                
                .section-title {{
                    font-size: 11px;
                    font-weight: 600;
                    color: #666666;
                    text-transform: uppercase;
                    letter-spacing: 0.8px;
                    margin-bottom: 10px;
                    padding-bottom: 5px;
                    border-bottom: 1px solid #333333;
                }}
                
                .stat-row {{
                    display: flex;
                    justify-content: space-between;
                    align-items: baseline;
                    padding: 8px 0;
                    border-bottom: 1px solid #2a2a2a;
                }}
                
                .stat-row:last-child {{
                    border-bottom: none;
                }}
                
                .stat-label {{
                    color: #888888;
                    font-size: 13px;
                }}
                
                .stat-value {{
                    color: #e0e0e0;
                    font-weight: 500;
                    font-size: 13px;
                }}
                
                .stat-value-up {{
                    color: #27ae60;
                }}
                
                .stat-value-down {{
                    color: #e74c3c;
                }}
                
                .divider {{
                    height: 1px;
                    background-color: #2a2a2a;
                    margin: 12px 0;
                }}
                
                .indent {{
                    margin-left: 20px;
                }}
                
                .indent .stat-label {{
                    font-size: 12px;
                    color: #777777;
                }}
            </style>
        </head>
        <body>
            <div class="section">
                <div class="section-title">ТРЕНД</div>
                <div class="stat-row">
                    <span class="stat-label">{'▼' if change < 0 else '▲' if change > 0 else '●'}</span>
                    <span class="stat-value {'stat-value-up' if change < 0 else 'stat-value-down' if change > 0 else ''}">{trend_text}</span>
                    <span class="stat-value {'stat-value-up' if change < 0 else 'stat-value-down' if change > 0 else ''}">{change:+.2f} ({change_percent:+.1f}%)</span>
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">{metric.upper()}</div>
                <div class="stat-row">
                    <span class="stat-label">Текущее значение</span>
                    <span class="stat-value">{current_value:.2f} {unit}</span>
                </div>
            </div>
            
            <div class="divider"></div>
            
            <div class="section">
                <div class="section-title">ЭКСТРЕМУМЫ</div>
                <div class="stat-row">
                    <span class="stat-label">Лучший план</span>
                    <span class="stat-value">{best_cost_str}</span>
                </div>
                <div class="stat-row indent">
                    <span class="stat-label">{best_date_str}</span>
                    <span></span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Худший план</span>
                    <span class="stat-value">{worst_cost_str}</span>
                </div>
                <div class="stat-row indent">
                    <span class="stat-label">{worst_date_str}</span>
                    <span></span>
                </div>
            </div>
            
            <div class="divider"></div>
            
            <div class="section">
                <div class="section-title">СТАТИСТИКА</div>
                <div class="stat-row">
                    <span class="stat-label">Всего версий</span>
                    <span class="stat-value">{len(entries)}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Улучшений</span>
                    <span class="stat-value stat-value-up">+{improvements}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Ухудшений</span>
                    <span class="stat-value stat-value-down">-{regressions}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Средняя стоимость</span>
                    <span class="stat-value">{avg_cost:.1f}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Среднее строк</span>
                    <span class="stat-value">{avg_rows:.0f}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Всего Seq Scan</span>
                    <span class="stat-value">{total_seq_scans}</span>
                </div>
            </div>
            
            <div class="divider"></div>
            
            <div class="section">
                <div class="section-title">ПЕРИОД</div>
                <div class="stat-row">
                    <span class="stat-label">С</span>
                    <span class="stat-value">{first_date_str}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">По</span>
                    <span class="stat-value">{last_date_str}</span>
                </div>
            </div>
        </body>
        </html>
        """

        self.stats_panel.setHtml(html)

    def get_empty_graph_html(self, message=""):
        return empty_performance_graph_html(message)

    def export_performance_graph(self):
        if not self.graph_viewer.page():
            QMessageBox.warning(self, "Ошибка", "Нет активного графика для экспорта")
            return

        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Сохранить график", "", "PNG Image (*.png);;All Files (*)", options=options
        )

        if not file_name:
            return

        if not file_name.lower().endswith(".png"):
            file_name += ".png"

        try:
            pixmap = self.graph_viewer.grab()
            if pixmap.save(file_name, "PNG"):
                QMessageBox.information(self, "Успех", f"График сохранен в {file_name}")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось сохранить график")
        except Exception as e:
            logging.error(f"Ошибка экспорта графика: {e}")
            QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить график:\n{str(e)}")

    def load_journal(self):
        self.journal_tree.clear()
        self.query_groups.clear()
        self.query_colors.clear()

        try:
            max_entries = self.parent.analyzer_settings.get("journal", {}).get("max_entries", 1000)
            journal_data = trim_journal_entries(load_journal_entries(), max_entries)

            self._calculate_query_groups(journal_data)

            self.group_filter.clear()
            self.group_filter.addItem("Все запросы", "")

            self.graph_group_combo.clear()
            self.graph_group_combo.addItem("Выберите группу...", "")

            first_active_group = None
            first_active_index = -1

            for normalized, group_data in self.query_groups.items():
                group_name = group_data["name"]
                versions_count = group_data["versions"]

                self.group_filter.addItem(group_name, normalized)

                if versions_count > 1:
                    display_name = f"{group_name} ({versions_count} версий)"
                    self.graph_group_combo.addItem(display_name, normalized)

                    if first_active_group is None:
                        first_active_group = normalized
                        first_active_index = self.graph_group_combo.count() - 1
                else:
                    display_name = f"{group_name} (только 1 версия)"
                    self.graph_group_combo.addItem(display_name, normalized)
                    index = self.graph_group_combo.count() - 1
                    model = self.graph_group_combo.model()
                    item = model.item(index, 0)
                    if item:
                        item.setEnabled(False)
                        item.setToolTip(
                            "Недостаточно данных для построения графика (нужно минимум 2 версии)"
                        )

            for entry in journal_data:
                self.add_journal_entry(entry)

            self.sort_journal()
            self.refresh_observed_plans_tab()

            if first_active_index > 0:
                self.graph_group_combo.setCurrentIndex(first_active_index)
                QTimer.singleShot(100, self.update_performance_graph)
            else:
                self.graph_viewer.setHtml(
                    self.get_empty_graph_html(
                        "Нет групп с несколькими версиями запросов.\n"
                        "Выполните один и тот же запрос несколько раз после изменений в БД."
                    )
                )
                self.stats_panel.clear()

        except Exception as e:
            logging.error(f"Ошибка загрузки журнала: {e}")
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить журнал: {str(e)}")

    def _calculate_query_groups(self, journal_data):
        query_hash_map = {}

        normalize_queries = True
        if self.parent and hasattr(self.parent, "analyzer_settings"):
            normalize_queries = self.parent.analyzer_settings.get("journal", {}).get(
                "query_normalization", True
            )

        for entry in journal_data:
            query_text = entry.get("query", "")

            if not query_text:
                continue

            if normalize_queries:
                normalized = self._normalize_query(query_text)
            else:
                normalized = query_text

            if normalized not in query_hash_map:
                query_hash_map[normalized] = []
            query_hash_map[normalized].append(entry)

        max_query_groups = self.parent.analyzer_settings.get("journal", {}).get(
            "max_query_groups", 50
        )

        group_counter = 1
        for normalized, entries in list(query_hash_map.items())[:max_query_groups]:
            sample_query = entries[0].get("query", "")
            query_preview = sample_query[:50] + "..." if len(sample_query) > 50 else sample_query

            query_preview = query_preview.replace("\n", " ").strip()

            if len(entries) > 1:
                group_name = f"Группа {group_counter}: {query_preview} ({len(entries)} версий)"
                group_counter += 1
            else:
                group_name = f"Группа {group_counter}: {query_preview} (1 версия)"
                group_counter += 1

            self.query_groups[normalized] = {
                "name": group_name,
                "color": self.get_query_group_color(len(self.query_groups)),
                "entries": entries,
                "versions": len(entries),
                "query_preview": query_preview,
            }

            for entry in entries:
                entry["_group_normalized"] = normalized
                entry["_group_name"] = group_name
                entry["_group_color"] = self.query_groups[normalized]["color"]
                entry["_group_versions"] = len(entries)

                if len(entries) > 1:
                    entry["_trend"] = self._calculate_trend_for_entry(entry, entries)
                else:
                    entry["_trend"] = "➖ Единственная версия"

        logging.info(f"Создано {len(self.query_groups)} групп запросов")
        for normalized, data in self.query_groups.items():
            logging.info(f"  - {data['name']}: {data['versions']} версий")

    def _calculate_trend_for_entry(self, entry, all_entries):
        sorted_entries = sorted(all_entries, key=lambda x: x.get("timestamp", ""))
        current_index = next(
            (
                i
                for i, e in enumerate(sorted_entries)
                if e.get("timestamp") == entry.get("timestamp")
            ),
            -1,
        )

        if current_index <= 0:
            return "➖ Первая версия"

        prev_entry = sorted_entries[current_index - 1]

        current_stats = self._extract_plan_stats(entry.get("xml_content", ""))
        prev_stats = self._extract_plan_stats(prev_entry.get("xml_content", ""))

        if current_stats["total_cost"] is None or prev_stats["total_cost"] is None:
            return "❓ Нет данных"

        if current_stats["total_cost"] < prev_stats["total_cost"]:
            improvement = (
                (prev_stats["total_cost"] - current_stats["total_cost"]) / prev_stats["total_cost"]
            ) * 100
            return f"📈 Улучшение на {improvement:.1f}%"
        elif current_stats["total_cost"] > prev_stats["total_cost"]:
            regression = (
                (current_stats["total_cost"] - prev_stats["total_cost"]) / prev_stats["total_cost"]
            ) * 100
            return f"📉 Ухудшение на {regression:.1f}%"
        else:
            return "➖ Без изменений"

    def _journal_source_visuals(self, entry):
        origin = entry.get("plan_origin")
        if origin == "hypopg" or entry.get("source_type") == "hypopg":
            return "⚡", QColor("#ce93d8"), "HypoPG"
        if origin == "file" or entry.get("source_type") == "file":
            return "📄", QColor("#81c784"), f"Файл: {entry.get('source_name', '')}"
        return "✍️", QColor("#ffcc80"), "EXPLAIN (БД)"

    def add_journal_entry(self, entry):
        icon_char, color, source_text = self._journal_source_visuals(entry)

        custom_name = entry.get("custom_name", "")
        if not custom_name:
            if entry.get("query_parts"):
                custom_name = " | ".join(entry["query_parts"])
            else:
                custom_name = "Без названия"

        group_versions = entry.get("_group_versions", 0)
        if group_versions > 1:
            icon_char = "🔄 " + icon_char
            custom_name = f"{custom_name} (v{group_versions})"

        cost, query_type = self._journal_plan_cost_and_type(entry.get("xml_content", ""))
        group_name = entry.get("_group_name", "")
        group_color = entry.get("_group_color", None)
        trend = entry.get("_trend", "")

        item = QTreeWidgetItem(
            [
                f"{icon_char} {custom_name}",
                entry.get("timestamp", ""),
                source_text,
                cost,
                query_type,
                group_name,
                trend,
            ]
        )

        if group_color:
            group_qcolor = QColor(group_color)
            for col in range(7):
                item.setBackground(col, group_qcolor)
                brightness = (
                    group_qcolor.red() * 299
                    + group_qcolor.green() * 587
                    + group_qcolor.blue() * 114
                ) / 1000
                if brightness > 128:
                    item.setForeground(col, QColor("#000000"))
                else:
                    item.setForeground(col, QColor("#ffffff"))
        else:
            item.setForeground(0, color)

        if "Улучшение" in trend:
            item.setForeground(6, QColor("#51cf66"))
        elif "Ухудшение" in trend:
            item.setForeground(6, QColor("#ff6b6b"))
        elif "Без изменений" in trend:
            item.setForeground(6, QColor("#fcc419"))

        item.setData(0, Qt.UserRole, entry)
        item.setToolTip(0, self.create_journal_entry_tooltip(entry))
        self.journal_tree.addTopLevelItem(item)

    def show_context_menu(self, position):
        sel = self.journal_tree.selectedItems()
        if len(sel) == 2:
            menu = QMenu()
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
            """)
            act = QAction(
                icon("fa5s.code-branch", color="white"), "Сравнить две выделенные записи", menu
            )
            act.triggered.connect(self.compare_with_previous_version)
            menu.addAction(act)
            menu.exec_(self.journal_tree.viewport().mapToGlobal(position))
            return

        item = self.journal_tree.itemAt(position)
        if not item:
            return

        entry = item.data(0, Qt.UserRole)
        if not entry:
            return

        menu = QMenu()
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
        """)

        view_query_action = QAction(icon("fa5s.code", color="white"), "Показать запрос", menu)
        view_query_action.triggered.connect(self.view_query_text)
        menu.addAction(view_query_action)

        copy_query_action = QAction(icon("fa5s.copy", color="white"), "Копировать запрос", menu)
        copy_query_action.triggered.connect(self.copy_query_text)
        menu.addAction(copy_query_action)

        menu.addSeparator()

        pair_other = self._find_hypopg_pair_entry(entry)
        if pair_other:
            hyp_compare_action = QAction(
                icon("fa5s.link", color="white"),
                "Сравнить пару HypoPG (до → после)",
                menu,
            )
            hyp_compare_action.triggered.connect(
                lambda checked=False, e=entry, o=pair_other: self._compare_hypopg_pair_entries(e, o)
            )
            menu.addAction(hyp_compare_action)

        previous_version = self._find_previous_version(entry)
        if previous_version:
            compare_action = QAction(
                icon("fa5s.code-branch", color="white"),
                f"Сравнить с предыдущей версией ({previous_version.get('timestamp', '')})",
                menu,
            )
            compare_action.triggered.connect(self.compare_with_previous_version)
            menu.addAction(compare_action)

        menu.addSeparator()

        edit_action = QAction(icon("fa5s.edit", color="white"), "Редактировать", menu)
        edit_action.triggered.connect(self.edit_selected_entry)
        menu.addAction(edit_action)

        delete_action = QAction(icon("fa5s.trash-alt", color="white"), "Удалить", menu)
        delete_action.triggered.connect(self.delete_selected_entry)
        menu.addAction(delete_action)

        menu.exec_(self.journal_tree.viewport().mapToGlobal(position))

    def view_query_text(self):
        selected_items = self.journal_tree.selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        entry = item.data(0, Qt.UserRole)
        query_text = entry.get("query", "")
        custom_name = entry.get("custom_name", "Без названия")

        if not query_text:
            QMessageBox.information(
                self, "Информация", "У этой записи нет сохраненного текста запроса"
            )
            return

        QTimer.singleShot(0, lambda: self._show_query_dialog(query_text, custom_name))

    def _show_query_dialog(self, query_text, custom_name):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"SQL Запрос: {custom_name}")
        dialog.setMinimumSize(800, 600)

        layout = QVBoxLayout(dialog)

        info_label = QLabel(f"<b>Запрос:</b> {custom_name}")
        info_label.setStyleSheet("color: #4fc3f7; padding: 5px;")
        layout.addWidget(info_label)

        query_edit = QPlainTextEdit()
        query_edit.setPlainText(query_text)
        query_edit.setReadOnly(True)
        query_edit.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                selection-background-color: #264F78;
            }
        """)

        if not hasattr(self, "_dialog_highlighters"):
            self._dialog_highlighters = []

        def create_highlighter():
            try:
                highlighter = SQLHighlighter(query_edit.document())
                self._dialog_highlighters.append(highlighter)
            except Exception as e:
                logging.error(f"Ошибка при создании SQLHighlighter в диалоге: {e}")

        QTimer.singleShot(0, create_highlighter)

        layout.addWidget(query_edit)

        button_layout = QHBoxLayout()

        copy_button = QPushButton(icon("fa5s.copy", color="white"), "Копировать в буфер")
        copy_button.clicked.connect(lambda: self._copy_query_to_clipboard(query_text))
        button_layout.addWidget(copy_button)

        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(dialog.accept)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)

        dialog.exec_()

    def _copy_query_to_clipboard(self, query_text):
        clipboard = QApplication.clipboard()
        clipboard.setText(query_text)
        QMessageBox.information(self, "Успех", "Запрос скопирован в буфер обмена")

    def copy_query_text(self):
        selected_items = self.journal_tree.selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        entry = item.data(0, Qt.UserRole)
        query_text = entry.get("query", "")

        if query_text:
            self._copy_query_to_clipboard(query_text)
        else:
            QMessageBox.warning(self, "Ошибка", "Нет текста запроса для копирования")

    def compare_with_previous_version(self):
        selected_items = self.journal_tree.selectedItems()
        if len(selected_items) == 2:
            e_left = selected_items[0].data(0, Qt.UserRole)
            e_right = selected_items[1].data(0, Qt.UserRole)
            older, newer = sorted(
                [e_left, e_right],
                key=lambda e: str(e.get("timestamp", "") or ""),
            )
            ta = older.get("custom_name") or ""
            tb = newer.get("custom_name") or ""
            stamp_o = older.get("timestamp") or ""
            stamp_n = newer.get("timestamp") or ""
            title = f'Сравнение двух записей: {ta[:48] or "?"} ↔ {tb[:48] or "?"}'
            self._show_plan_comparison_dialog(
                older,
                newer,
                title,
                f"<b>Раньше по времени:</b><br>{html.escape(str(stamp_o))}",
                f"<b>Позже по времени:</b><br>{html.escape(str(stamp_n))}",
            )
            return

        if len(selected_items) != 1:
            return

        entry = selected_items[0].data(0, Qt.UserRole)

        pair_other = self._find_hypopg_pair_entry(entry)
        if pair_other:
            self._compare_hypopg_pair_entries(entry, pair_other)
            return

        previous_entry = self._find_previous_version(entry)
        if not previous_entry:
            QMessageBox.information(
                self,
                "Информация",
                "Нет пары HypoPG для этой записи и не найдена предыдущая версия того же запроса.",
            )
            return

        self._show_plan_comparison_dialog(
            previous_entry,
            entry,
            f"Сравнение планов: {entry.get('custom_name', '')}",
            f"<b>Предыдущая версия:</b><br>{previous_entry.get('timestamp', '')}",
            f"<b>Текущая версия:</b><br>{entry.get('timestamp', '')}",
        )

    def _find_hypopg_pair_entry(self, entry):
        gid = entry.get("hypopg_pair_group_id")
        role = entry.get("hypopg_pair_role")
        if not gid or role not in ("baseline", "hypopg"):
            return None
        want = "hypopg" if role == "baseline" else "baseline"
        for i in range(self.journal_tree.topLevelItemCount()):
            e = self.journal_tree.topLevelItem(i).data(0, Qt.UserRole)
            if e.get("hypopg_pair_group_id") == gid and e.get("hypopg_pair_role") == want:
                return e
        return None

    def _show_plan_comparison_dialog(
        self, left_entry, right_entry, window_title, left_caption_html, right_caption_html
    ):
        comparison_html = self._compare_plan_versions(left_entry, right_entry)

        dialog = QDialog(self)
        dialog.setWindowTitle(window_title)
        dialog.setMinimumSize(900, 700)

        layout = QVBoxLayout(dialog)

        info_widget = QWidget()
        info_layout = QHBoxLayout(info_widget)

        old_info = QLabel(left_caption_html)
        old_info.setStyleSheet("color: #ff8a65; padding: 5px;")
        info_layout.addWidget(old_info)

        arrow_label = QLabel("→")
        arrow_label.setStyleSheet("font-size: 20px; color: #4fc3f7;")
        info_layout.addWidget(arrow_label)

        new_info = QLabel(right_caption_html)
        new_info.setStyleSheet("color: #81c784; padding: 5px;")
        info_layout.addWidget(new_info)

        info_layout.addStretch()
        layout.addWidget(info_widget)

        comparison_browser = QTextBrowser()
        comparison_browser.setHtml(comparison_html)
        comparison_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #444;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }
        """)
        layout.addWidget(comparison_browser)

        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button)

        dialog.exec_()

    def _compare_hypopg_pair_entries(self, entry, other):
        if entry.get("hypopg_pair_role") == "baseline":
            left, right = entry, other
        elif other.get("hypopg_pair_role") == "baseline":
            left, right = other, entry
        else:
            ordered = sorted([entry, other], key=lambda x: x.get("timestamp", ""))
            left, right = ordered[0], ordered[1]

        title = f"HypoPG: {left.get('custom_name', '')}"
        self._show_plan_comparison_dialog(
            left,
            right,
            title,
            f"<b>Базовый план:</b><br>{html.escape(left.get('timestamp', '') or '')}",
            f"<b>С HypoPG:</b><br>{html.escape(right.get('timestamp', '') or '')}",
        )

    def _find_previous_version(self, current_entry):
        current_query = current_entry.get("query", "")
        if not current_query:
            return None

        current_normalized = self._normalize_query(current_query)
        current_timestamp = current_entry.get("timestamp", "")

        previous_versions = []
        for i in range(self.journal_tree.topLevelItemCount()):
            item = self.journal_tree.topLevelItem(i)
            entry = item.data(0, Qt.UserRole)

            if entry.get("timestamp") == current_timestamp:
                continue

            entry_query = entry.get("query", "")
            if entry_query:
                entry_normalized = self._normalize_query(entry_query)
                if entry_normalized == current_normalized:
                    previous_versions.append(entry)

        if not previous_versions:
            return None

        previous_versions.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return previous_versions[0]

    def _compare_plan_versions(self, old_entry, new_entry):
        html = """
        <html>
        <head>
            <style>
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    color: #e0e0e0;
                    background-color: #2d2d2d;
                    margin: 10px;
                    padding: 10px;
                }
                h2 {
                    color: #4fc3f7;
                    border-bottom: 2px solid #4fc3f7;
                    padding-bottom: 5px;
                }
                h3 {
                    color: #81c784;
                    margin-top: 15px;
                }
                .improvement {
                    color: #51cf66;
                    font-weight: bold;
                }
                .regression {
                    color: #ff6b6b;
                    font-weight: bold;
                }
                .neutral {
                    color: #fcc419;
                }
                .stat-box {
                    background-color: #1e1e1e;
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                }
                .stat-label {
                    color: #b3e5fc;
                    font-weight: bold;
                }
                .diff-positive {
                    color: #51cf66;
                }
                .diff-negative {
                    color: #ff6b6b;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                }
                td, th {
                    padding: 8px;
                    border-bottom: 1px solid #444;
                    text-align: left;
                }
                th {
                    background-color: #3a3a3a;
                    color: #4fc3f7;
                }
            </style>
        </head>
        <body>
        """

        old_stats = self._extract_plan_stats(old_entry.get("xml_content", ""))
        new_stats = self._extract_plan_stats(new_entry.get("xml_content", ""))

        html += f"""
        <h2>📊 Сравнение планов запроса</h2>
        <div class="stat-box">
            <span class="stat-label">Предыдущая версия:</span> {old_entry.get('timestamp', 'N/A')}<br>
            <span class="stat-label">Текущая версия:</span> {new_entry.get('timestamp', 'N/A')}
        </div>
        """

        if old_stats["total_cost"] is not None and new_stats["total_cost"] is not None:
            cost_diff = new_stats["total_cost"] - old_stats["total_cost"]
            cost_percent = (
                (cost_diff / old_stats["total_cost"]) * 100 if old_stats["total_cost"] > 0 else 0
            )

            cost_class = (
                "improvement" if cost_diff < 0 else "regression" if cost_diff > 0 else "neutral"
            )
            cost_sign = "▼" if cost_diff < 0 else "▲" if cost_diff > 0 else "●"

            html += f"""
            <h3>💰 Изменение стоимости</h3>
            <div class="stat-box">
                <table>
                    <tr>
                        <th>Параметр</th>
                        <th>Предыдущая</th>
                        <th>Текущая</th>
                        <th>Изменение</th>
                    </tr>
                    <tr>
                        <td>Общая стоимость</td>
                        <td>{old_stats['total_cost']:.2f}</td>
                        <td>{new_stats['total_cost']:.2f}</td>
                        <td class="{cost_class}">{cost_sign} {abs(cost_diff):.2f} ({cost_percent:+.1f}%)</td>
                    </tr>
                </table>
            </div>
            """

        if old_stats["total_rows"] is not None and new_stats["total_rows"] is not None:
            rows_diff = new_stats["total_rows"] - old_stats["total_rows"]
            rows_percent = (
                (rows_diff / old_stats["total_rows"]) * 100 if old_stats["total_rows"] > 0 else 0
            )

            rows_class = (
                "improvement" if rows_diff < 0 else "regression" if rows_diff > 0 else "neutral"
            )
            rows_sign = "▼" if rows_diff < 0 else "▲" if rows_diff > 0 else "●"

            html += f"""
            <h3>📈 Изменение количества строк</h3>
            <div class="stat-box">
                <table>
                    <tr>
                        <th>Параметр</th>
                        <th>Предыдущая</th>
                        <th>Текущая</th>
                        <th>Изменение</th>
                    </tr>
                    <tr>
                        <td>Ожидаемое количество строк</td>
                        <td>{old_stats['total_rows']:,}</td>
                        <td>{new_stats['total_rows']:,}</td>
                        <td class="{rows_class}">{rows_sign} {abs(rows_diff):,} ({rows_percent:+.1f}%)</td>
                    </tr>
                </table>
            </div>
            """

        html += """
        <h3>🔧 Изменение операций</h3>
        <div class="stat-box">
            <table>
                <tr>
                    <th>Тип операции</th>
                    <th>Предыдущая</th>
                    <th>Текущая</th>
                    <th>Изменение</th>
                </tr>
        """

        all_ops = set(old_stats["operations"].keys()) | set(new_stats["operations"].keys())
        for op in sorted(all_ops):
            old_count = old_stats["operations"].get(op, 0)
            new_count = new_stats["operations"].get(op, 0)
            diff = new_count - old_count

            if diff > 0:
                change = f"<span class='diff-negative'>+{diff}</span>"
            elif diff < 0:
                change = f"<span class='diff-positive'>{diff}</span>"
            else:
                change = "0"

            html += f"""
                <tr>
                    <td>{op}</td>
                    <td>{old_count}</td>
                    <td>{new_count}</td>
                    <td>{change}</td>
                </tr>
            """

        html += """
            </table>
        </div>
        """

        html += """
        <h3>📋 Общая оценка</h3>
        <div class="stat-box">
        """

        if old_stats["total_cost"] is not None and new_stats["total_cost"] is not None:
            if new_stats["total_cost"] < old_stats["total_cost"]:
                html += "<p class='improvement'>✅ УЛУЧШЕНИЕ! Стоимость запроса снизилась.</p>"
            elif new_stats["total_cost"] > old_stats["total_cost"]:
                html += "<p class='regression'>⚠️ УХУДШЕНИЕ! Стоимость запроса увеличилась.</p>"
            else:
                html += "<p class='neutral'>➖ Стоимость запроса не изменилась.</p>"

        if old_stats["seq_scans"] > 0 and new_stats["seq_scans"] == 0:
            html += "<p class='improvement'>✅ Улучшено! Seq Scan операции заменены на индексные сканирования.</p>"
        elif old_stats["seq_scans"] == 0 and new_stats["seq_scans"] > 0:
            html += "<p class='regression'>⚠️ Ухудшено! Появились Seq Scan операции.</p>"

        html += """
        </div>
        </body>
        </html>
        """

        return html

    def _journal_plan_cost_and_type(self, plan_doc):
        try:
            tree = parse_plan_document(plan_doc)
            return str(tree["cost"]), tree["type"]
        except Exception:
            return "N/A", "Unknown"

    def _extract_plan_stats(self, xml_content):
        stats = {"total_cost": None, "total_rows": None, "operations": {}, "seq_scans": 0}

        try:
            if not xml_content:
                return stats

            tree = parse_plan_document(xml_content)
            filled = accumulate_plan_statistics_from_tree(tree)
            stats["total_cost"] = filled["total_cost"]
            stats["total_rows"] = filled["total_rows"]
            stats["operations"] = filled["operations"]
            stats["seq_scans"] = filled["seq_scans"]
        except Exception as e:
            logging.error(f"Ошибка извлечения статистики: {e}")

        return stats

    def _normalize_query(self, query):
        return normalize_query_text(query)

    def get_query_group_color(self, group_index):
        colors = [
            "#81c784",
            "#4fc3f7",
            "#ffcc80",
            "#ff8a65",
            "#b39ddb",
            "#a5d6a7",
            "#90caf9",
            "#ffab91",
        ]
        return colors[group_index % len(colors)]

    def filter_by_group(self, index):
        group_name = self.group_filter.currentData()

        for i in range(self.journal_tree.topLevelItemCount()):
            item = self.journal_tree.topLevelItem(i)
            entry = item.data(0, Qt.UserRole)

            if not group_name:
                item.setHidden(False)
            else:
                entry_group = entry.get("_group_name", "")
                item.setHidden(entry_group != group_name)

    def create_journal_entry_tooltip(self, entry):
        po = entry.get("plan_origin")
        if po == "hypopg" or entry.get("source_type") == "hypopg":
            src_color = "#ce93d8"
            src_label = html.escape("HypoPG (гипотетические индексы)")
        elif po == "file" or entry.get("source_type") == "file":
            src_color = "#81c784"
            src_label = html.escape("Файл: " + entry.get("source_name", ""))
        else:
            src_color = "#ffcc80"
            src_label = html.escape("EXPLAIN из базы данных")

        tooltip = f"""
        <html>
        <body style="font-family: 'Segoe UI', Arial, sans-serif; color: #e0e0e0; background-color: #2d2d2d;">
            <div style="margin-bottom: 5px;">
                <span style="color: #4fc3f7; font-weight: bold;">Название:</span> {entry.get('custom_name', 'Без названия')}
            </div>
            <div style="margin-bottom: 5px;">
                <span style="color: #4fc3f7; font-weight: bold;">Дата:</span> {entry.get('timestamp', 'N/A')}
            </div>
            <div style="margin-bottom: 5px;">
                <span style="color: #4fc3f7; font-weight: bold;">Источник:</span>
                <span style="color: {src_color};">
                    {src_label}
                </span>
            </div>
        """

        if entry.get("_group_name"):
            tooltip += f"""
            <div style="margin-bottom: 5px;">
                <span style="color: #4fc3f7; font-weight: bold;">Группа:</span> 
                <span style="color: {entry.get('_group_color', '#81c784')};">{entry.get('_group_name', '')}</span>
                <span style="color: #fcc419;"> ({entry.get('_group_versions', 1)} версий)</span>
            </div>
            """

        if entry.get("description"):
            tooltip += f"""
            <div style="margin-bottom: 5px;">
                <span style="color: #4fc3f7; font-weight: bold;">Описание:</span>
                <div style="margin-left: 10px; font-style: italic;">{entry['description']}</div>
            </div>
            """

        if entry.get("query_parts"):
            tooltip += """
            <div style="margin-bottom: 5px;">
                <span style="color: #4fc3f7; font-weight: bold;">Детали:</span>
                <ul style="margin-top: 2px; margin-bottom: 2px;">
            """
            for part in entry["query_parts"]:
                tooltip += f"<li>{part}</li>"
            tooltip += """
                </ul>
            </div>
            """

        if entry.get("query"):
            query_text = html.escape(
                entry["query"][:200] + ("..." if len(entry["query"]) > 200 else "")
            )
            tooltip += f"""
            <div style="margin-bottom: 5px;">
                <span style="color: #4fc3f7; font-weight: bold;">Запрос:</span>
                <div style="background-color: #1e1e1e; padding: 5px; border-radius: 3px; margin-top: 2px; font-family: 'Consolas', monospace;">
                    {query_text}
                </div>
            </div>
            """

        pgid = entry.get("hypopg_pair_group_id")
        prole = entry.get("hypopg_pair_role")
        if pgid and prole:
            role_ru = "базовый" if prole == "baseline" else "HypoPG"
            tooltip += f"""
            <div style="margin-bottom: 5px;">
                <span style="color: #4fc3f7; font-weight: bold;">Пара HypoPG:</span>
                <span style="font-family: 'Consolas', monospace;">{html.escape(str(pgid))}</span>
                <span style="color: #ce93d8;"> ({role_ru})</span>
            </div>
            """

        sqid = entry.get("statement_queryid")
        if sqid:
            tooltip += f"""
            <div style="margin-bottom: 5px;">
                <span style="color: #4fc3f7; font-weight: bold;">pg_stat_statements.queryid:</span>
                <span style="font-family: 'Consolas', monospace;">{html.escape(str(sqid))}</span>
            </div>
            """

        tooltip += """
        </body>
        </html>
        """

        return tooltip

    def filter_journal(self):
        search_text = self.search_edit.text().lower()

        for i in range(self.journal_tree.topLevelItemCount()):
            item = self.journal_tree.topLevelItem(i)
            entry = item.data(0, Qt.UserRole)

            matches = (
                search_text in item.text(0).lower()
                or search_text in item.text(1).lower()
                or search_text in item.text(2).lower()
                or (entry.get("description", "").lower().find(search_text) != -1)
                or (entry.get("query", "").lower().find(search_text) != -1)
                or (entry.get("_group_name", "").lower().find(search_text) != -1)
                or (str(entry.get("statement_queryid") or "").lower().find(search_text) != -1)
                or (entry.get("plan_origin") or "").lower().find(search_text) != -1
                or (str(entry.get("hypopg_pair_group_id") or "").lower().find(search_text) != -1)
            )

            item.setHidden(not matches)

    def sort_journal(self):
        sort_mode = self.sort_combo.currentIndex()

        if sort_mode == 0:
            self.journal_tree.sortByColumn(1, Qt.DescendingOrder)
        elif sort_mode == 1:
            self.journal_tree.sortByColumn(1, Qt.AscendingOrder)
        elif sort_mode == 2:
            self.journal_tree.sortByColumn(0, Qt.AscendingOrder)
        elif sort_mode == 3:
            self.journal_tree.sortByColumn(3, Qt.DescendingOrder)
        elif sort_mode == 4:
            self.journal_tree.sortByColumn(5, Qt.AscendingOrder)

    def add_custom_note(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Добавить заметку")
        dialog.setMinimumWidth(500)

        layout = QVBoxLayout(dialog)

        form_layout = QFormLayout()

        name_edit = QLineEdit()
        name_edit.setPlaceholderText("Введите название заметки")
        form_layout.addRow("Название:", name_edit)

        description_edit = QTextEdit()
        description_edit.setPlaceholderText("Введите описание заметки")
        description_edit.setMaximumHeight(100)
        form_layout.addRow("Описание:", description_edit)

        query_edit = QPlainTextEdit()
        query_edit.setPlaceholderText("Введите SQL запрос (опционально)")
        query_edit.setMaximumHeight(150)
        form_layout.addRow("SQL запрос:", query_edit)

        xml_edit = QPlainTextEdit()
        xml_edit.setPlaceholderText("Вставьте XML план запроса или оставьте пустым")
        form_layout.addRow("XML план:", xml_edit)

        layout.addLayout(form_layout)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        if dialog.exec_() == QDialog.Accepted:
            entry = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "execution_time": datetime.datetime.now().strftime("%H:%M:%S"),
                "source_type": "manual",
                "source_name": "Пользовательская заметка",
                "custom_name": name_edit.text(),
                "description": description_edit.toPlainText(),
                "query": query_edit.toPlainText(),
                "xml_content": (
                    xml_edit.toPlainText() if xml_edit.toPlainText() else "<explain></explain>"
                ),
            }

            self.add_entry_to_journal(entry)

    def add_entry_to_journal(self, entry):
        try:
            max_entries = 1000
            if self.parent and hasattr(self.parent, "analyzer_settings"):
                max_entries = self.parent.analyzer_settings.get("journal", {}).get(
                    "max_entries", 1000
                )
            append_journal_entry(entry, max_entries)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить журнал: {str(e)}")
            return

        self.load_journal()

    def edit_selected_entry(self):
        selected_items = self.journal_tree.selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        entry = item.data(0, Qt.UserRole)

        dialog = QDialog(self)
        dialog.setWindowTitle("Редактировать запись")
        dialog.setMinimumWidth(500)

        layout = QVBoxLayout(dialog)

        form_layout = QFormLayout()

        name_edit = QLineEdit(entry.get("custom_name", ""))
        name_edit.setPlaceholderText("Введите название заметки")
        form_layout.addRow("Название:", name_edit)

        description_edit = QTextEdit(entry.get("description", ""))
        description_edit.setPlaceholderText("Введите описание заметки")
        description_edit.setMaximumHeight(100)
        form_layout.addRow("Описание:", description_edit)

        layout.addLayout(form_layout)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        if dialog.exec_() == QDialog.Accepted:
            entry["custom_name"] = name_edit.text()
            entry["description"] = description_edit.toPlainText()
            self.save_journal_changes()
            self.update_journal_item(item, entry)

    def update_journal_item(self, item, entry):
        icon_char, _, _ = self._journal_source_visuals(entry)
        item.setText(0, f"{icon_char} {entry.get('custom_name', '')}")
        item.setToolTip(0, self.create_journal_entry_tooltip(entry))
        item.setData(0, Qt.UserRole, entry)

    def delete_selected_entry(self):
        selected_items = self.journal_tree.selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        entry = item.data(0, Qt.UserRole)

        reply = QMessageBox.question(
            self,
            "Удаление записи",
            f"Вы уверены, что хотите удалить запись '{entry.get('custom_name', '')}'?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.delete_entry_from_journal(entry)
            self.journal_tree.takeTopLevelItem(self.journal_tree.indexOfTopLevelItem(item))

    def delete_entry_from_journal(self, entry_to_delete):
        try:
            delete_stored_journal_entry(entry_to_delete)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить журнал: {str(e)}")

    def save_journal_changes(self):
        journal_data = []

        for i in range(self.journal_tree.topLevelItemCount()):
            item = self.journal_tree.topLevelItem(i)
            entry = item.data(0, Qt.UserRole)
            entry_copy = {k: v for k, v in entry.items() if not k.startswith("_")}
            journal_data.append(entry_copy)

        try:
            save_journal_entries(journal_data)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить журнал: {str(e)}")

    def load_plan_from_journal(self, item, column):
        entry = item.data(0, Qt.UserRole)
        if entry and self.parent:
            try:
                self.parent.is_loading_from_journal = True
                self.parent.xml_content = entry["xml_content"]
                if entry.get("query"):
                    self.parent.query_input.setText(entry["query"])
                self.parent.analyze_query_plan()
                if hasattr(self.parent, "show_plan_workspace"):
                    self.parent.show_plan_workspace()
                else:
                    self.parent.showMaximized()
                self.parent.is_loading_from_journal = False
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить план: {str(e)}")
                self.parent.is_loading_from_journal = False

    def clear_journal(self):
        reply = QMessageBox.question(
            self,
            "Очистка журнала",
            "Вы уверены, что хотите очистить весь журнал планов запросов?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply == QDialog.Yes:
            try:
                save_journal_entries([])

                if self.parent:
                    self.parent.query_plans_journal = []

                self.journal_tree.clear()

                QMessageBox.information(self, "Успех", "Журнал успешно очищен")
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Не удалось очистить журнал: {str(e)}")

    def add_plan_from_analysis(self, xml_content, query_text=""):
        if hasattr(self.parent, "is_loading_from_journal") and self.parent.is_loading_from_journal:
            return

        if not self.parent.analyzer_settings.get("journal", {}).get("auto_save_plans", True):
            return

        if hasattr(self.parent, "last_opened_file"):
            source_type = "file"
            source_name = os.path.basename(self.parent.last_opened_file)
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
        }

        if not hasattr(self.parent, "query_plans_journal"):
            self.parent.query_plans_journal = []

        existing_entry = next(
            (
                e
                for e in self.parent.query_plans_journal
                if e["timestamp"] == entry["timestamp"] and e["source_name"] == entry["source_name"]
            ),
            None,
        )

        if not existing_entry:
            self.parent.query_plans_journal.append(entry)

            max_entries = self.parent.analyzer_settings.get("journal", {}).get("max_entries", 1000)
            self.parent.query_plans_journal = trim_journal_entries(
                self.parent.query_plans_journal, max_entries
            )

            try:
                save_journal_entries(self.parent.query_plans_journal)
                self.load_journal()
            except Exception as e:
                logging.error(f"Ошибка сохранения журнала: {e}")

    def refresh_performance_tab(self):
        if self.parent and hasattr(self.parent, "query_plans_journal"):
            self.load_journal()

        current_index = self.graph_group_combo.currentIndex()
        if current_index > 0:
            self.update_performance_graph()
        else:
            for i in range(1, self.graph_group_combo.count()):
                model = self.graph_group_combo.model()
                item = model.item(i, 0)
                if item and item.isEnabled():
                    self.graph_group_combo.setCurrentIndex(i)
                    break


class QueryPlansJournal(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("Журнал планов запросов")
        self._apply_screen_aware_geometry()

        self.journal_widget = QueryPlansJournalWidget(parent)
        self.setCentralWidget(self.journal_widget)

    def __getattr__(self, name):
        return getattr(self.journal_widget, name)

    def _apply_screen_aware_geometry(self):
        screen = QApplication.primaryScreen()
        if screen is None:
            self.resize(1200, 760)
            return

        available = screen.availableGeometry()
        margin_x = min(48, max(16, available.width() // 24))
        margin_y = min(48, max(16, available.height() // 24))
        width = min(1400, max(760, available.width() - margin_x * 2))
        height = min(900, max(560, available.height() - margin_y * 2))
        x = available.x() + max(0, (available.width() - width) // 2)
        y = available.y() + max(0, (available.height() - height) // 2)
        self.setGeometry(x, y, width, height)
