"""Workload tab: top queries from pg_stat_statements."""

from __future__ import annotations

import csv
import html
import hashlib
import json
import re
import time
from collections import Counter
from typing import Any, Dict, List, Optional

import psycopg2
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from pg_query_analyzer.analysis.sql_normalize import normalize_query_text
from pg_query_analyzer.db.statement_stats import (
    aggregate_statements_by_fingerprint,
    fetch_top_statements,
    reset_pg_stat_statements,
)
from pg_query_analyzer.storage.journal import load_journal_entries
from pg_query_analyzer.storage.connections import ConnectionSettings
from pg_query_analyzer.ui.qt_workers import CallableWorkerThread
from pg_query_analyzer.ai.openrouter_client import (
    generate_workload_prioritization_openrouter,
    generate_workload_digest_openrouter,
    mask_sql_literals,
)
from pg_query_analyzer.storage.ai_feedback import append_feedback_event
from pg_query_analyzer.storage.ai_feedback import load_feedback_events, summarize_feedback


class StatStatementsTab(QWidget):
    """Shows cumulative stats from pg_stat_statements for the active database."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self._refresh_worker: Optional[CallableWorkerThread] = None
        self._reset_worker: Optional[CallableWorkerThread] = None
        self._pending_rows: Optional[List[Any]] = None
        self._pending_error: Optional[str] = None
        self._reset_error: Optional[str] = None
        self._display_rows: List[Dict[str, Any]] = []
        self._ai_prioritize_worker: Optional[CallableWorkerThread] = None
        self._ai_digest_worker: Optional[CallableWorkerThread] = None
        self._ai_ab_worker: Optional[CallableWorkerThread] = None
        self._ai_workload_cache: Dict[str, Any] = {}
        self._ai_prioritize_cache_key: Optional[str] = None
        self._ai_digest_cache_key: Optional[str] = None
        self._ai_ab_cache_key: Optional[str] = None
        self._last_ai_feedback_context: Optional[Dict[str, Any]] = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        hint = QLabel(
            "Накопленная статистика запросов (расширение pg_stat_statements). "
            "На сервере: shared_preload_libraries + перезапуск, затем CREATE EXTENSION в этой базе. "
            "Связка с локальным журналом — по fingerprint (как группировка планов в журнале)."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #b0bec5; font-size: 11px;")
        layout.addWidget(hint)

        btn_style = """
            QPushButton {
                padding: 6px 12px;
                min-height: 26px;
                font-size: 12px;
            }
        """

        # Строка 1: загрузка и экспорт данных (без ИИ — не сжимается в одну линию с кучей кнопок).
        row_data = QHBoxLayout()
        row_data.setSpacing(10)
        row_data.addWidget(QLabel("Сортировка:"))
        self.sort_combo = QComboBox()
        self.sort_combo.addItem("По суммарному времени (total)", "total_time")
        self.sort_combo.addItem("По среднему времени (mean)", "mean_time")
        self.sort_combo.addItem("По числу вызовов", "calls")
        self.sort_combo.addItem("По строкам (rows)", "rows")
        self.sort_combo.addItem(
            "Workload: по fingerprint (суммы топ-N строк)", "fingerprint_workload"
        )
        self.sort_combo.setMinimumWidth(280)
        self.sort_combo.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        row_data.addWidget(self.sort_combo)

        row_data.addWidget(QLabel("Строк:"))
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(10, 300)
        self.limit_spin.setValue(50)
        row_data.addWidget(self.limit_spin)

        self.refresh_btn = QPushButton("Обновить")
        self.refresh_btn.setStyleSheet(btn_style)
        self.refresh_btn.clicked.connect(self.refresh_data)
        row_data.addWidget(self.refresh_btn)

        self.export_btn = QPushButton("Экспорт в CSV…")
        self.export_btn.setStyleSheet(btn_style)
        self.export_btn.setToolTip(
            "Экспорт текущего топа; если выделены строки — только они (Ctrl/Cmd и Shift)."
        )
        self.export_btn.clicked.connect(self.export_csv)
        row_data.addWidget(self.export_btn)

        self.reset_btn = QPushButton("Сброс статистики…")
        self.reset_btn.setStyleSheet(btn_style)
        self.reset_btn.setToolTip(
            "Выполняется pg_stat_statements_reset() — нужны права на сервере."
        )
        self.reset_btn.clicked.connect(self.reset_stats)
        row_data.addWidget(self.reset_btn)

        row_data.addStretch()
        layout.addLayout(row_data)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Sunken)
        sep.setStyleSheet("color: #555; max-height: 2px; margin-top: 2px; margin-bottom: 2px;")
        layout.addWidget(sep)

        # Строка 2: действия ИИ — отдельная полоса, читаемые подписи на русском.
        row_ai = QHBoxLayout()
        row_ai.setSpacing(8)
        ai_lbl = QLabel("ИИ (OpenRouter):")
        ai_lbl.setStyleSheet("color: #81c784; font-weight: bold; font-size: 12px;")
        ai_lbl.setToolTip("Включите AI в «Настройки анализатора» → вкладка AI / OpenRouter.")
        row_ai.addWidget(ai_lbl)

        self.ai_prioritize_btn = QPushButton("Приоритеты P1–P3")
        self.ai_prioritize_btn.setStyleSheet(btn_style)
        self.ai_prioritize_btn.setToolTip(
            "Отправить текущий топ workload в модель: приоритизация по P1/P2/P3 (структурированный ответ)."
        )
        self.ai_prioritize_btn.clicked.connect(self.ai_prioritize_workload)
        row_ai.addWidget(self.ai_prioritize_btn)

        self.ai_digest_btn = QPushButton("Текстовый дайджест")
        self.ai_digest_btn.setStyleSheet(btn_style)
        self.ai_digest_btn.setToolTip(
            "Сформировать краткий Markdown-дайджест по текущему workload."
        )
        self.ai_digest_btn.clicked.connect(self.ai_generate_digest)
        row_ai.addWidget(self.ai_digest_btn)

        self.ai_feedback_good_btn = QPushButton("Полезно")
        self.ai_feedback_good_btn.setStyleSheet(btn_style)
        self.ai_feedback_good_btn.setEnabled(False)
        self.ai_feedback_good_btn.setToolTip("Оценить последний ответ ИИ по workload (полезно).")
        self.ai_feedback_good_btn.clicked.connect(lambda: self._submit_ai_feedback("useful"))
        row_ai.addWidget(self.ai_feedback_good_btn)

        self.ai_feedback_bad_btn = QPushButton("Не полезно")
        self.ai_feedback_bad_btn.setStyleSheet(btn_style)
        self.ai_feedback_bad_btn.setEnabled(False)
        self.ai_feedback_bad_btn.setToolTip("Оценить последний ответ ИИ по workload (не полезно).")
        self.ai_feedback_bad_btn.clicked.connect(lambda: self._submit_ai_feedback("not_useful"))
        row_ai.addWidget(self.ai_feedback_bad_btn)

        self.ai_ab_btn = QPushButton("Сравнить две модели")
        self.ai_ab_btn.setStyleSheet(btn_style)
        self.ai_ab_btn.setToolTip(
            "A/B: одна и та же выборка workload — текущая модель из настроек и вторая (вводится по запросу)."
        )
        self.ai_ab_btn.clicked.connect(self.run_ai_ab_check)
        row_ai.addWidget(self.ai_ab_btn)

        self.intersection_btn = QPushButton("Запросы × долг обслуживания")
        self.intersection_btn.setStyleSheet(btn_style)
        self.intersection_btn.setToolTip(
            "Показать запросы из топа, которые затрагивают таблицы с maintenance debt "
            "(если в главном окне уже есть снимок обслуживания БД)."
        )
        self.intersection_btn.clicked.connect(self.show_workload_debt_intersection)
        row_ai.addWidget(self.intersection_btn)

        row_ai.addStretch()
        layout.addLayout(row_ai)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(self.status_label)

        self.ai_quality_label = QLabel("")
        self.ai_quality_label.setStyleSheet("""
            QLabel {
                color: #cfd8dc;
                background-color: #263238;
                border-left: 4px solid #4fc3f7;
                padding: 6px 8px;
                font-size: 11px;
            }
        """)
        self.ai_quality_label.setWordWrap(True)
        layout.addWidget(self.ai_quality_label)

        splitter = QSplitter(Qt.Vertical)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["queryid", "calls", "mean_ms", "total_ms", "rows", "журнал", "preview"]
        )
        header = self.table.horizontalHeader()
        for i in range(7):
            header.setSectionResizeMode(
                i, QHeaderView.ResizeToContents if i != 6 else QHeaderView.Stretch
            )
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.itemDoubleClicked.connect(self._on_double_click)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_menu)

        self.detail = QTextBrowser()
        self.detail.setReadOnly(True)
        self.detail.setOpenExternalLinks(False)
        self.detail.setHtml(
            "<p style='color:#9e9e9e;'>"
            "Выберите строку — fingerprint, число совпадений с журналом и полный текст запроса."
            "</p>"
        )
        self.detail.setMinimumHeight(120)

        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setChildrenCollapsible(False)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

        self.table.setStyleSheet("""
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
            """)
        self._refresh_ai_quality_label()

    @staticmethod
    def _journal_fingerprint_counts() -> Counter[str]:
        entries = load_journal_entries()
        c: Counter[str] = Counter()
        for e in entries:
            q = (e.get("query") or "").strip()
            if q:
                c[normalize_query_text(q)] += 1
        return c

    @staticmethod
    def _journal_saved_queryids() -> set[str]:
        ids: set[str] = set()
        for e in load_journal_entries():
            sid = e.get("statement_queryid")
            if sid is not None and str(sid).strip():
                ids.add(str(sid).strip())
        return ids

    def refresh_data(self):
        if not getattr(self.parent, "connection_status", False) or not getattr(
            self.parent, "current_connection", None
        ):
            QMessageBox.warning(self, "Нет подключения", "Подключитесь к базе данных.")
            return

        self.refresh_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.status_label.setText("Загрузка…")

        conn_params = ConnectionSettings.connect_kwargs(self.parent.current_connection)
        limit = self.limit_spin.value()
        sort_key = self.sort_combo.currentData() or "total_time"

        def refresh_sync():
            with psycopg2.connect(**conn_params) as conn:
                with conn.cursor() as cur:
                    conn.autocommit = True
                    if sort_key == "fingerprint_workload":
                        fetch_cap = max(min(400, max(limit * 20, 80)), limit)
                        raw = fetch_top_statements(cur, limit=fetch_cap, sort_key="total_time")
                        agg_list = aggregate_statements_by_fingerprint(raw)
                        agg_list.sort(key=lambda rr: -float(rr.get("total_ms") or 0.0))
                        return agg_list[:limit]

                    rows = fetch_top_statements(cur, limit=limit, sort_key=sort_key)
                    return rows

        self._refresh_worker = CallableWorkerThread(refresh_sync, self)
        self._refresh_worker.completed.connect(self._on_refresh_worker_done)
        self._refresh_worker.start()

    def _on_refresh_worker_done(self, ok: bool, payload: object):
        self._refresh_worker = None
        self.refresh_btn.setEnabled(True)
        self.export_btn.setEnabled(True)

        if not ok:
            self.table.setRowCount(0)
            self._display_rows = []
            self.status_label.setStyleSheet("color: #ffb74d; font-size: 11px;")
            self.status_label.setText(str(payload))
            return

        rows = payload or []
        self.status_label.setStyleSheet("color: #888; font-size: 11px;")
        self.status_label.setText(f"Загружено записей: {len(rows)}")
        self.table.setRowCount(len(rows))

        jcounts = self._journal_fingerprint_counts()
        saved_qids = self._journal_saved_queryids()
        self._display_rows = []

        for r, row in enumerate(rows):
            qid = row.get("queryid") or ""
            calls = row.get("calls")
            mean_ms = row.get("mean_ms")
            total_ms = row.get("total_ms")
            rows_sum = row.get("rows_sum")
            full_q = row.get("query_text") or ""
            fp = row.get("fingerprint") or (normalize_query_text(full_q) if full_q.strip() else "")
            journal_n = jcounts.get(fp, 0) if fp else 0

            disp: Dict[str, Any] = dict(row)
            disp["fingerprint"] = fp
            disp["journal_matches"] = journal_n
            self._display_rows.append(disp)

            preview = full_q.replace("\n", " ").strip()
            if len(preview) > 160:
                preview = preview[:157] + "…"

            vals = [
                str(qid),
                str(calls),
                str(mean_ms),
                str(total_ms),
                str(rows_sum),
                str(journal_n),
                preview,
            ]
            qid_str = str(qid).strip()
            merged_ids = [str(x).strip() for x in (row.get("_merged_queryids") or [])]
            row_highlight = (qid_str and qid_str in saved_qids) or bool(
                merged_ids and any(x in saved_qids for x in merged_ids if x)
            )
            fg = QColor("#a5d6a7") if row_highlight else QColor("#e0e0e0")
            for c, text in enumerate(vals):
                item = QTableWidgetItem(text)
                item.setForeground(fg)
                item.setData(Qt.UserRole, full_q)
                self.table.setItem(r, c, item)

    def _row_query_text(self, row_index: int) -> str:
        if 0 <= row_index < len(self._display_rows):
            return (self._display_rows[row_index].get("query_text") or "").strip()
        return ""

    def display_rows(self) -> List[Dict[str, Any]]:
        """Return the currently loaded workload rows for other UI panels."""

        return list(self._display_rows)

    def _apply_detail_for_row(self, row_index: int) -> None:
        if row_index < 0 or row_index >= len(self._display_rows):
            self.detail.clear()
            return
        d = self._display_rows[row_index]
        fp = d.get("fingerprint") or ""
        jn = d.get("journal_matches", 0)
        q = d.get("query_text") or ""
        qid_raw = str(d.get("queryid") or "").strip()
        saved_ids = self._journal_saved_queryids()

        mq = [str(x).strip() for x in (d.get("_merged_queryids") or [])]
        mq = [x for x in mq if x]
        extra_merge = ""
        if mq:
            shown = mq[:24]
            extra_merge = (
                "\n\nОбъединено несколько строк pg_stat_statements (один fingerprint) — "
                f"исходные queryid: {', '.join(shown)}"
                + ("…" if len(mq) > len(shown) else "")
                + "\n"
            )
            merged_hit = any(x in saved_ids for x in mq)
            if merged_hit:
                extra = (
                    "\nЕсть сохранённые statement_queryid в журнале для хотя бы одной "
                    "из объединённых строк.\n"
                )
            else:
                extra = "\nНи один из объединённых queryid пока не совпадает с журналом планов.\n"
        elif qid_raw:
            extra = (
                "\nСовпадение с сохранённым statement_queryid в журнале планов.\n"
                if qid_raw in saved_ids
                else "\nНет записи журнала с этим statement_queryid.\n"
            )
        else:
            extra = ""

        header_html = (
            "<div style='color:#e0e0e0; font-family:Segoe UI,Arial,sans-serif; font-size:12px;'>"
            "<b>Fingerprint (группа как в журнале планов):</b><br>"
            f"<code>{html.escape(fp)}</code><br><br>"
            f"<b>Планов в локальном журнале с тем же fingerprint:</b> {jn}<br>"
            f"{html.escape(extra).replace(chr(10), '<br>')}"
            f"{html.escape(extra_merge).replace(chr(10), '<br>')}"
            "<br><b>Текст из pg_stat_statements.query</b>"
            "</div>"
        )
        self.detail.setHtml(header_html + self._format_sql_html(q))

    @staticmethod
    def _format_sql_html(sql_text: str) -> str:
        escaped = html.escape(sql_text or "")
        # Soft SQL highlighting for readability in QTextBrowser.
        keyword_re = re.compile(
            r"\b("
            r"SELECT|FROM|WHERE|JOIN|LEFT|RIGHT|FULL|INNER|OUTER|ON|GROUP|BY|ORDER|LIMIT|"
            r"OFFSET|WITH|AS|AND|OR|NOT|IN|EXISTS|CASE|WHEN|THEN|ELSE|END|UNION|ALL|DISTINCT|"
            r"INSERT|UPDATE|DELETE|RETURNING|VALUES|CREATE|ALTER|DROP"
            r")\b",
            re.IGNORECASE,
        )
        highlighted = keyword_re.sub(
            lambda m: f"<span style='color:#81c784; font-weight:bold;'>{m.group(0)}</span>",
            escaped,
        )
        return (
            "<pre style='background:#1f1f1f; color:#e0e0e0; border:1px solid #444; "
            "padding:10px; border-radius:4px; white-space:pre-wrap; "
            "font-family:Consolas,Monaco,monospace; font-size:12px;'>"
            f"{highlighted}"
            "</pre>"
        )

    def _on_selection_changed(self) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        self._apply_detail_for_row(indexes[0].row())

    def _on_double_click(self, item: QTableWidgetItem) -> None:
        self._apply_detail_for_row(item.row())

    def _show_menu(self, pos):
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        row = idx.row()
        self.table.selectRow(row)
        q = self._row_query_text(row)
        if not q:
            return

        menu = QMenu(self)
        act_detail = menu.addAction("Показать в панели ниже")
        act_editor = menu.addAction("Вставить в поле запроса")
        chosen = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if chosen == act_detail:
            self._apply_detail_for_row(row)
        elif chosen == act_editor:
            self._send_to_query_input(q)

    def _send_to_query_input(self, query_text: str):
        mw = self.parent
        if hasattr(mw, "query_input"):
            mw.query_input.setText(query_text.strip())
        if hasattr(mw, "left_tabs"):
            for i in range(mw.left_tabs.count()):
                if mw.left_tabs.tabText(i).startswith("💹"):
                    mw.left_tabs.setCurrentIndex(i)
                    break

    def _rows_for_export(self) -> List[Dict[str, Any]]:
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            return list(self._display_rows)
        indices = sorted({ix.row() for ix in sel})
        out: List[Dict[str, Any]] = []
        for r in indices:
            if 0 <= r < len(self._display_rows):
                out.append(self._display_rows[r])
        return out if out else list(self._display_rows)

    def export_csv(self):
        if not self._display_rows:
            QMessageBox.information(self, "Экспорт", "Нет данных. Нажмите «Обновить».")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт pg_stat_statements", "pg_stat_statements_top.csv", "CSV (*.csv)"
        )
        if not path:
            return
        rows_out = self._rows_for_export()
        sel_n = len(self.table.selectionModel().selectedRows())
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(
                    [
                        "queryid",
                        "calls",
                        "mean_ms",
                        "total_ms",
                        "rows_sum",
                        "journal_matches",
                        "fingerprint",
                        "query_text",
                    ]
                )
                for d in rows_out:
                    w.writerow(
                        [
                            d.get("queryid", ""),
                            d.get("calls", ""),
                            d.get("mean_ms", ""),
                            d.get("total_ms", ""),
                            d.get("rows_sum", ""),
                            d.get("journal_matches", ""),
                            d.get("fingerprint", ""),
                            d.get("query_text", ""),
                        ]
                    )
        except OSError as e:
            QMessageBox.critical(self, "Экспорт", str(e))
            return
        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        suffix = f"{len(rows_out)} строк"
        if sel_n > 0:
            suffix += " (выделено)"
        self.status_label.setText(f"Сохранено: {path} — {suffix}")

    def reset_stats(self):
        if not getattr(self.parent, "connection_status", False) or not getattr(
            self.parent, "current_connection", None
        ):
            QMessageBox.warning(self, "Нет подключения", "Подключитесь к базе данных.")
            return

        reply = QMessageBox.question(
            self,
            "Сброс pg_stat_statements",
            "Выполнить SELECT pg_stat_statements_reset()?\n\n"
            "Статистика выполнения запросов будет обнулена (глобально для кластера). "
            "Обычно нужны права суперпользователя.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        self.refresh_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.reset_btn.setEnabled(False)
        self.status_label.setText("Сброс статистики…")

        conn_params = ConnectionSettings.connect_kwargs(self.parent.current_connection)

        def reset_sync():
            with psycopg2.connect(**conn_params) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    reset_pg_stat_statements(cur)

        self._reset_worker = CallableWorkerThread(reset_sync, self)
        self._reset_worker.completed.connect(self._on_reset_worker_done)
        self._reset_worker.start()

    def ai_prioritize_workload(self):
        if self._ai_prioritize_worker is not None:
            QMessageBox.information(self, "AI Workload", "AI-приоритизация уже выполняется.")
            return
        if not self._display_rows:
            QMessageBox.information(self, "AI Workload", "Нет данных workload. Нажмите «Обновить».")
            return

        ai_settings = (
            (getattr(self.parent, "analyzer_settings", None) or {}).get("ai", {})
            if self.parent
            else {}
        )
        if not ai_settings.get("enabled", False):
            QMessageBox.warning(
                self,
                "AI Workload",
                "AI-интерпретатор выключен. Включите его в Настройки анализатора -> AI / OpenRouter.",
            )
            return

        provider = (ai_settings.get("provider") or "").strip().lower()
        if provider != "openrouter":
            QMessageBox.warning(
                self, "AI Workload", "Сейчас поддерживается только provider=openrouter."
            )
            return

        base_url = (ai_settings.get("base_url") or "https://openrouter.ai/api/v1").strip()
        model = (ai_settings.get("model") or "").strip()
        api_key = (ai_settings.get("api_key") or "").strip()
        if not api_key or not model:
            QMessageBox.warning(
                self,
                "AI Workload",
                "Заполните API key и Модель в Настройки анализатора -> AI / OpenRouter.",
            )
            return

        mask_literals = ai_settings.get("mask_sql_literals", True)
        top_rows = self._display_rows[: min(25, len(self._display_rows))]
        payload_rows = []
        for row in top_rows:
            query_text = (row.get("query_text") or "").strip()
            if mask_literals:
                query_text = mask_sql_literals(query_text)
            payload_rows.append(
                {
                    "queryid": str(row.get("queryid") or ""),
                    "calls": row.get("calls"),
                    "mean_ms": row.get("mean_ms"),
                    "total_ms": row.get("total_ms"),
                    "rows_sum": row.get("rows_sum"),
                    "journal_matches": row.get("journal_matches"),
                    "fingerprint": row.get("fingerprint"),
                    "query_text_preview": query_text[:600],
                }
            )
        workload_payload = {"rows": payload_rows}

        cache_key = ""
        if ai_settings.get("cache_enabled", True):
            cache_blob = json.dumps(
                {
                    "provider": provider,
                    "base_url": base_url,
                    "model": model,
                    "workload_payload": workload_payload,
                },
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            )
            cache_key = hashlib.sha256(cache_blob.encode("utf-8")).hexdigest()
            cached = self._ai_workload_cache.get(cache_key)
            if cached is not None:
                self._render_ai_workload_prioritization(cached)
                self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
                self.status_label.setText("AI приоритизация: ответ из кэша.")
                return

        self.ai_prioritize_btn.setEnabled(False)
        self.status_label.setStyleSheet("color: #90caf9; font-size: 11px;")
        self.status_label.setText("AI приоритизация workload…")

        def prioritize_sync():
            return generate_workload_prioritization_openrouter(
                base_url=base_url,
                api_key=api_key,
                model=model,
                workload_payload=workload_payload,
            )

        self._ai_prioritize_cache_key = cache_key or None
        self._ai_prioritize_worker = CallableWorkerThread(prioritize_sync, self)
        self._ai_prioritize_worker.completed.connect(self._on_ai_prioritize_done)
        self._ai_prioritize_worker.start()

    def _on_ai_prioritize_done(self, ok: bool, payload: object):
        self.ai_prioritize_btn.setEnabled(True)
        self._ai_prioritize_worker = None

        if not ok:
            self.status_label.setStyleSheet("color: #ffb74d; font-size: 11px;")
            self.status_label.setText("AI приоритизация завершилась с ошибкой.")
            QMessageBox.warning(self, "AI Workload", str(payload))
            return

        if getattr(self, "_ai_prioritize_cache_key", None):
            self._ai_workload_cache[self._ai_prioritize_cache_key] = payload  # type: ignore[index]
        self._ai_prioritize_cache_key = None

        self._render_ai_workload_prioritization(payload)
        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        self.status_label.setText("AI приоритизация workload готова.")
        self._set_ai_feedback_context(feature="workload_prioritization")

    def _render_ai_workload_prioritization(self, payload: object):
        structured = payload.get("structured") if isinstance(payload, dict) else None
        raw_text = (
            str(payload.get("raw_text") or "").strip()
            if isinstance(payload, dict)
            else str(payload)
        )

        if isinstance(structured, dict):
            summary = html.escape(str(structured.get("summary") or ""))
            priorities = structured.get("priorities") or []
            quick_wins = structured.get("quick_wins") or []

            pri_items = []
            for p in priorities:
                if not isinstance(p, dict):
                    continue
                pri = html.escape(str(p.get("priority") or "P3"))
                qid = html.escape(str(p.get("queryid") or ""))
                fp = html.escape(str(p.get("fingerprint") or ""))
                reason = html.escape(str(p.get("reason") or ""))
                first_check = html.escape(str(p.get("first_check") or ""))
                pri_items.append(
                    f"<li><b>{pri}</b> · queryid: <code>{qid}</code><br>"
                    f"<span style='color:#cfd8dc;'>{reason}</span><br>"
                    f"<span style='color:#90caf9;'>Первая проверка: {first_check}</span><br>"
                    f"<span style='color:#9e9e9e;font-size:11px;'>fp: {fp}</span></li>"
                )
            if not pri_items:
                pri_items.append("<li>AI не вернул список приоритетов.</li>")

            qw_items = []
            for w in quick_wins:
                if not isinstance(w, str):
                    continue
                qw_items.append(f"<li>{html.escape(w)}</li>")
            if not qw_items:
                qw_items.append("<li>Быстрые шаги не указаны.</li>")

            self.detail.setHtml(
                "<div style='color:#e0e0e0; font-family:Segoe UI,Arial,sans-serif; font-size:12px;'>"
                "<h3 style='color:#b3e5fc; margin:2px 0 8px 0;'>AI Workload Prioritization</h3>"
                f"<p><b>Summary:</b> {summary}</p>"
                "<h4 style='color:#81c784; margin:10px 0 6px 0;'>P1/P2/P3</h4>"
                f"<ul>{''.join(pri_items)}</ul>"
                "<h4 style='color:#4fc3f7; margin:10px 0 6px 0;'>Quick wins</h4>"
                f"<ul>{''.join(qw_items)}</ul>"
                "</div>"
            )
            return

        self.detail.setHtml(
            "<div style='color:#e0e0e0; font-family:Segoe UI,Arial,sans-serif; font-size:12px;'>"
            "<h3 style='color:#b3e5fc; margin:2px 0 8px 0;'>AI Workload Prioritization</h3>"
            "<p style='color:#ffb74d;'>Структурированный JSON не получен. Показан raw ответ.</p>"
            f"<pre style='white-space:pre-wrap;background:#1f1f1f;border:1px solid #444;padding:8px;'>{html.escape(raw_text)}</pre>"
            "</div>"
        )

    def ai_generate_digest(self):
        if self._ai_digest_worker is not None:
            QMessageBox.information(self, "Дайджест ИИ", "Дайджест уже выполняется.")
            return
        if not self._display_rows:
            QMessageBox.information(self, "Дайджест ИИ", "Нет данных workload. Нажмите «Обновить».")
            return

        ai_settings = (
            (getattr(self.parent, "analyzer_settings", None) or {}).get("ai", {})
            if self.parent
            else {}
        )
        if not ai_settings.get("enabled", False):
            QMessageBox.warning(
                self,
                "Дайджест ИИ",
                "AI-интерпретатор выключен. Включите его в Настройки анализатора -> AI / OpenRouter.",
            )
            return
        provider = (ai_settings.get("provider") or "").strip().lower()
        if provider != "openrouter":
            QMessageBox.warning(
                self, "Дайджест ИИ", "Сейчас поддерживается только provider=openrouter."
            )
            return
        base_url = (ai_settings.get("base_url") or "https://openrouter.ai/api/v1").strip()
        model = (ai_settings.get("model") or "").strip()
        api_key = (ai_settings.get("api_key") or "").strip()
        if not api_key or not model:
            QMessageBox.warning(
                self,
                "Дайджест ИИ",
                "Заполните API key и Модель в Настройки анализатора -> AI / OpenRouter.",
            )
            return

        mask_literals = ai_settings.get("mask_sql_literals", True)
        top_rows = self._display_rows[: min(40, len(self._display_rows))]
        payload_rows = []
        for row in top_rows:
            query_text = (row.get("query_text") or "").strip()
            if mask_literals:
                query_text = mask_sql_literals(query_text)
            payload_rows.append(
                {
                    "queryid": str(row.get("queryid") or ""),
                    "calls": row.get("calls"),
                    "mean_ms": row.get("mean_ms"),
                    "total_ms": row.get("total_ms"),
                    "rows_sum": row.get("rows_sum"),
                    "journal_matches": row.get("journal_matches"),
                    "fingerprint": row.get("fingerprint"),
                    "query_text_preview": query_text[:700],
                }
            )
        workload_payload = {"rows": payload_rows}

        cache_key = ""
        if ai_settings.get("cache_enabled", True):
            cache_blob = json.dumps(
                {
                    "provider": provider,
                    "base_url": base_url,
                    "model": model,
                    "digest_payload": workload_payload,
                },
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            )
            cache_key = hashlib.sha256(cache_blob.encode("utf-8")).hexdigest()
            cached = self._ai_workload_cache.get(cache_key)
            if isinstance(cached, dict) and cached.get("digest_markdown"):
                self._render_ai_digest_markdown(str(cached["digest_markdown"]))
                self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
                self.status_label.setText("Дайджест ИИ: ответ из кэша.")
                self._set_ai_feedback_context(feature="workload_digest")
                return

        self.ai_digest_btn.setEnabled(False)
        self.status_label.setStyleSheet("color: #90caf9; font-size: 11px;")
        self.status_label.setText("Дайджест ИИ…")

        def digest_sync():
            return generate_workload_digest_openrouter(
                base_url=base_url,
                api_key=api_key,
                model=model,
                workload_payload=workload_payload,
            )

        self._ai_digest_cache_key = cache_key or None
        self._ai_digest_worker = CallableWorkerThread(digest_sync, self)
        self._ai_digest_worker.completed.connect(self._on_ai_digest_done)
        self._ai_digest_worker.start()

    def _on_ai_digest_done(self, ok: bool, payload: object):
        self.ai_digest_btn.setEnabled(True)
        self._ai_digest_worker = None
        if not ok:
            self.status_label.setStyleSheet("color: #ffb74d; font-size: 11px;")
            self.status_label.setText("Дайджест ИИ завершился с ошибкой.")
            QMessageBox.warning(self, "Дайджест ИИ", str(payload))
            return
        digest_markdown = str(payload or "").strip()
        if not digest_markdown:
            QMessageBox.warning(self, "Дайджест ИИ", "ИИ не вернул текст дайджеста.")
            return
        if getattr(self, "_ai_digest_cache_key", None):
            self._ai_workload_cache[self._ai_digest_cache_key] = {
                "digest_markdown": digest_markdown
            }
        self._ai_digest_cache_key = None
        self._render_ai_digest_markdown(digest_markdown)
        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        self.status_label.setText("Дайджест ИИ готов.")
        self._set_ai_feedback_context(feature="workload_digest")

    def _render_ai_digest_markdown(self, digest_markdown: str):
        escaped = html.escape(digest_markdown)
        escaped = escaped.replace("\n", "<br>")
        self.detail.setHtml(
            "<div style='color:#e0e0e0; font-family:Segoe UI,Arial,sans-serif; font-size:12px;'>"
            "<h3 style='color:#b3e5fc; margin:2px 0 8px 0;'>AI Workload Digest</h3>"
            f"<div style='line-height:1.45'>{escaped}</div>"
            "</div>"
        )

    def _set_ai_feedback_context(self, *, feature: str):
        ai_settings = (
            (getattr(self.parent, "analyzer_settings", None) or {}).get("ai", {})
            if self.parent
            else {}
        )
        self._last_ai_feedback_context = {
            "feature": feature,
            "model": str(ai_settings.get("model") or ""),
            "rows_count": len(self._display_rows),
        }
        self.ai_feedback_good_btn.setEnabled(True)
        self.ai_feedback_bad_btn.setEnabled(True)

    def _submit_ai_feedback(self, rating: str):
        ctx = self._last_ai_feedback_context or {}
        feature = str(ctx.get("feature") or "unknown")
        model = str(ctx.get("model") or "")
        metadata = {"rows_count": ctx.get("rows_count", 0)}
        append_feedback_event(feature=feature, rating=rating, model=model, metadata=metadata)
        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        self.status_label.setText(f"Feedback сохранён: {rating} ({feature}).")
        self._refresh_ai_quality_label()

    def _refresh_ai_quality_label(self):
        summary = summarize_feedback(load_feedback_events())
        total = int(summary.get("total") or 0)
        useful = int(summary.get("useful") or 0)
        not_useful = int(summary.get("not_useful") or 0)
        ratio = float(summary.get("useful_ratio") or 0.0)
        by_feature = summary.get("by_feature") or {}

        if ratio >= 80:
            color = "#81c784"
        elif ratio >= 50:
            color = "#ffb74d"
        else:
            color = "#e57373"

        feature_lines = []
        if isinstance(by_feature, dict):
            for feat, stats in sorted(by_feature.items(), key=lambda x: -int(x[1].get("total", 0)))[
                :5
            ]:
                if not isinstance(stats, dict):
                    continue
                feature_lines.append(
                    f"• {html.escape(str(feat))}: "
                    f"{int(stats.get('useful', 0))}/{int(stats.get('total', 0))} полезно"
                )
        feature_block = "<br>".join(feature_lines) if feature_lines else "Нет данных по фичам."

        self.ai_quality_label.setText(
            "AI качество (feedback): "
            f"<span style='color:{color}; font-weight:bold;'>{useful}/{total} ({ratio:.0f}%)</span> "
            f"| не полезно: {not_useful}<br>"
            f"{feature_block}"
        )

    def run_ai_ab_check(self):
        if self._ai_ab_worker is not None:
            QMessageBox.information(self, "Сравнение моделей", "Сравнение моделей уже выполняется.")
            return
        if not self._display_rows:
            QMessageBox.information(
                self, "Сравнение моделей", "Нет данных workload. Нажмите «Обновить»."
            )
            return
        ai_settings = (
            (getattr(self.parent, "analyzer_settings", None) or {}).get("ai", {})
            if self.parent
            else {}
        )
        if not ai_settings.get("enabled", False):
            QMessageBox.warning(
                self,
                "Сравнение моделей",
                "AI-интерпретатор выключен. Включите его в Настройки анализатора -> AI / OpenRouter.",
            )
            return
        base_url = (ai_settings.get("base_url") or "https://openrouter.ai/api/v1").strip()
        api_key = (ai_settings.get("api_key") or "").strip()
        model_a = (ai_settings.get("model") or "").strip()
        if not api_key or not model_a:
            QMessageBox.warning(
                self,
                "Сравнение моделей",
                "Заполните API key и текущую модель в Настройки анализатора -> AI / OpenRouter.",
            )
            return

        model_b, ok = QInputDialog.getText(
            self,
            "Сравнение двух моделей",
            "Введите вторую модель (модель B):",
            text="x-ai/grok-3-mini",
        )
        if not ok:
            return
        model_b = (model_b or "").strip()
        if not model_b:
            QMessageBox.warning(self, "Сравнение моделей", "Модель B не может быть пустой.")
            return

        mask_literals = ai_settings.get("mask_sql_literals", True)
        top_rows = self._display_rows[: min(20, len(self._display_rows))]
        payload_rows = []
        for row in top_rows:
            query_text = (row.get("query_text") or "").strip()
            if mask_literals:
                query_text = mask_sql_literals(query_text)
            payload_rows.append(
                {
                    "queryid": str(row.get("queryid") or ""),
                    "calls": row.get("calls"),
                    "mean_ms": row.get("mean_ms"),
                    "total_ms": row.get("total_ms"),
                    "rows_sum": row.get("rows_sum"),
                    "fingerprint": row.get("fingerprint"),
                    "query_text_preview": query_text[:500],
                }
            )
        workload_payload = {"rows": payload_rows}

        self.ai_ab_btn.setEnabled(False)
        self.status_label.setStyleSheet("color: #90caf9; font-size: 11px;")
        self.status_label.setText("Сравнение моделей выполняется…")

        def ab_sync():
            def run_one(model_name: str):
                t0 = time.perf_counter()
                result = generate_workload_prioritization_openrouter(
                    base_url=base_url,
                    api_key=api_key,
                    model=model_name,
                    workload_payload=workload_payload,
                )
                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                structured = result.get("structured") if isinstance(result, dict) else None
                raw = str(result.get("raw_text") or "") if isinstance(result, dict) else str(result)
                priorities_count = 0
                if isinstance(structured, dict):
                    priorities = structured.get("priorities") or []
                    if isinstance(priorities, list):
                        priorities_count = len(priorities)
                return {
                    "model": model_name,
                    "elapsed_ms": elapsed_ms,
                    "structured_ok": isinstance(structured, dict),
                    "priorities_count": priorities_count,
                    "raw_preview": raw[:450],
                }

            return {"a": run_one(model_a), "b": run_one(model_b)}

        self._ai_ab_worker = CallableWorkerThread(ab_sync, self)
        self._ai_ab_worker.completed.connect(self._on_ai_ab_done)
        self._ai_ab_worker.start()

    def _on_ai_ab_done(self, ok: bool, payload: object):
        self.ai_ab_btn.setEnabled(True)
        self._ai_ab_worker = None
        if not ok:
            self.status_label.setStyleSheet("color: #ffb74d; font-size: 11px;")
            self.status_label.setText("Сравнение моделей завершилось с ошибкой.")
            QMessageBox.warning(self, "Сравнение моделей", str(payload))
            return
        if not isinstance(payload, dict):
            QMessageBox.warning(
                self, "Сравнение моделей", "Неожиданный формат результата сравнения."
            )
            return
        a = payload.get("a") or {}
        b = payload.get("b") or {}
        a_struct = bool(a.get("structured_ok"))
        b_struct = bool(b.get("structured_ok"))
        if a_struct and not b_struct:
            winner = f"Winner: {html.escape(str(a.get('model') or 'Model A'))} (лучше schema-first)"
        elif b_struct and not a_struct:
            winner = f"Winner: {html.escape(str(b.get('model') or 'Model B'))} (лучше schema-first)"
        else:
            a_time = int(a.get("elapsed_ms") or 0)
            b_time = int(b.get("elapsed_ms") or 0)
            if a_time and b_time:
                winner = "Winner по скорости: " + html.escape(
                    str(a.get("model") if a_time <= b_time else b.get("model"))
                )
            else:
                winner = "Winner: паритет, нужна ручная проверка качества."

        def block(title: str, data: dict):
            return (
                f"<h4 style='color:#81c784;margin:8px 0 4px 0;'>{html.escape(title)}</h4>"
                "<ul>"
                f"<li><b>Model:</b> {html.escape(str(data.get('model') or ''))}</li>"
                f"<li><b>Latency:</b> {int(data.get('elapsed_ms') or 0)} ms</li>"
                f"<li><b>Structured JSON:</b> {'yes' if data.get('structured_ok') else 'no'}</li>"
                f"<li><b>Priorities count:</b> {int(data.get('priorities_count') or 0)}</li>"
                "</ul>"
                "<pre style='white-space:pre-wrap;background:#1f1f1f;border:1px solid #444;padding:8px;'>"
                f"{html.escape(str(data.get('raw_preview') or ''))}</pre>"
            )

        self.detail.setHtml(
            "<div style='color:#e0e0e0; font-family:Segoe UI,Arial,sans-serif; font-size:12px;'>"
            "<h3 style='color:#b3e5fc; margin:2px 0 8px 0;'>Сравнение двух моделей (workload)</h3>"
            f"<p style='color:#90caf9;'><b>{winner}</b></p>"
            f"{block('Model A', a)}"
            f"{block('Model B', b)}"
            "</div>"
        )
        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        self.status_label.setText("Сравнение моделей завершено.")

    def show_workload_debt_intersection(self):
        if not self._display_rows:
            QMessageBox.information(
                self,
                "Запросы и долг обслуживания",
                "Нет workload-данных. Нажмите «Обновить».",
            )
            return
        debt_map = {}
        if self.parent and hasattr(self.parent, "get_maintenance_debt_map"):
            try:
                debt_map = self.parent.get_maintenance_debt_map() or {}
            except Exception:
                debt_map = {}
        if not debt_map:
            QMessageBox.information(
                self,
                "Запросы и долг обслуживания",
                "Нет maintenance debt-данных. Запустите проверку статистики/VACUUM в блоке обслуживания БД.",
            )
            return

        matches = []
        debt_items = []
        for table_name, tags in debt_map.items():
            tn = str(table_name).strip().lower()
            if not tn:
                continue
            short = tn.split(".")[-1]
            debt_items.append((tn, short, set(tags)))

        for row in self._display_rows:
            q = str(row.get("query_text") or "")
            q_lower = q.lower()
            hit_tags = set()
            hit_tables = set()
            for full_name, short_name, tags in debt_items:
                if (
                    full_name in q_lower
                    or f'"{short_name}"' in q_lower
                    or f" {short_name} " in q_lower
                ):
                    hit_tables.add(full_name)
                    hit_tags.update(tags)
            if not hit_tables:
                continue
            score = float(row.get("total_ms") or 0.0)
            if "critical_analyze" in hit_tags:
                score *= 1.5
            if "require_vacuum" in hit_tags:
                score *= 1.3
            matches.append(
                {
                    "queryid": str(row.get("queryid") or ""),
                    "total_ms": float(row.get("total_ms") or 0.0),
                    "calls": row.get("calls"),
                    "score": score,
                    "tables": sorted(hit_tables),
                    "tags": sorted(hit_tags),
                    "preview": (row.get("query_text") or "").replace("\n", " ")[:240],
                }
            )

        if not matches:
            self.detail.setHtml(
                "<p style='color:#9e9e9e;'>Пересечение не найдено: workload сейчас не задевает debt-таблицы.</p>"
            )
            self.status_label.setStyleSheet("color: #888; font-size: 11px;")
            self.status_label.setText("Пересечение с долгом: совпадений нет.")
            return

        matches.sort(key=lambda x: -float(x.get("score", 0.0)))
        top = matches[:20]
        items = []
        for m in top:
            items.append(
                "<li>"
                f"<b>queryid:</b> {html.escape(str(m['queryid']))} | "
                f"<b>score:</b> {m['score']:.1f} | "
                f"<b>total_ms:</b> {m['total_ms']:.1f} | "
                f"<b>calls:</b> {html.escape(str(m['calls']))}<br>"
                f"<b>tables:</b> {html.escape(', '.join(m['tables']))}<br>"
                f"<b>tags:</b> {html.escape(', '.join(m['tags']))}<br>"
                f"<span style='color:#b0bec5;'>{html.escape(m['preview'])}</span>"
                "</li>"
            )

        self.detail.setHtml(
            "<div style='color:#e0e0e0; font-family:Segoe UI,Arial,sans-serif; font-size:12px;'>"
            "<h3 style='color:#b3e5fc; margin:2px 0 8px 0;'>Workload × Maintenance debt</h3>"
            f"<p>Найдено совпадений: <b>{len(matches)}</b> (показано {len(top)}).</p>"
            "<ul>" + "".join(items) + "</ul></div>"
        )
        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        self.status_label.setText(f"Пересечение с долгом: найдено {len(matches)} совпадений.")

    def _on_reset_worker_done(self, ok: bool, payload: object):
        self._reset_worker = None
        self.refresh_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.reset_btn.setEnabled(True)

        if not ok:
            QMessageBox.warning(self, "Сброс статистики", str(payload))
            self.status_label.setStyleSheet("color: #ffb74d; font-size: 11px;")
            self.status_label.setText(str(payload))
            return

        QMessageBox.information(self, "Сброс статистики", "Статистика pg_stat_statements сброшена.")
        self.refresh_data()
