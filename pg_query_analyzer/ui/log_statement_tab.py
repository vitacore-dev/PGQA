"""Tab: import PostgreSQL log lines produced by ``log_statement`` and group by fingerprint."""

from __future__ import annotations

import html
from typing import List, Optional

from PyQt5.QtCore import QSettings, Qt
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QGroupBox,
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
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from pg_query_analyzer.analysis.log_statement import (
    AggregatedLogStatement,
    LogStatementRecord,
    aggregate_log_statements,
    parse_log_statement_records,
)
from pg_query_analyzer.db.remote_log_fetch import (
    fetch_remote_postgresql_log_text,
    parse_log_prefix_whitelist,
    resolve_log_directory_absolute,
)
from pg_query_analyzer.ui.qt_workers import CallableWorkerThread


class LogStatementTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self._records: List[LogStatementRecord] = []
        self._aggregated: List[AggregatedLogStatement] = []
        self._meta: dict = {}
        self._ssh_fetch_worker: Optional[CallableWorkerThread] = None
        self._logdir_worker: Optional[CallableWorkerThread] = None
        self._setup_ui()
        self._load_ssh_settings()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        hint = QLabel(
            "Разбор текстового лога PostgreSQL (stderr) и CSV (logging_collector, log_destination = csvlog). "
            "Ищутся строки вида <code>LOG:  statement: …</code> и колонка <code>query</code> в csvlog. "
            "Группировка — <code>normalize_query_text</code> (как в журнале / Workload). "
            "Локальный файл или вставка — без БД; загрузка по SSH использует профиль подключения с включённым SSH."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #b0bec5; font-size: 11px;")
        layout.addWidget(hint)

        ssh_box = QGroupBox("Удалённый лог по SSH (каталог только из белого списка префиксов)")
        ssh_layout = QVBoxLayout(ssh_box)
        ssh_row1 = QHBoxLayout()
        ssh_row1.addWidget(QLabel("Файл на сервере:"))
        self.remote_path_edit = QLineEdit()
        self.remote_path_edit.setPlaceholderText(
            "/var/lib/postgresql/16/main/log/postgresql-2025-05-13_000000.log"
        )
        ssh_row1.addWidget(self.remote_path_edit, 1)
        self.logdir_btn = QPushButton("Каталог лога из БД…")
        self.logdir_btn.setToolTip(
            "Нужно активное подключение к PostgreSQL. Выполняется SHOW log_directory "
            "(относительный путь разрешается относительно data_directory)."
        )
        self.logdir_btn.clicked.connect(self._fetch_log_directory_from_db)
        ssh_row1.addWidget(self.logdir_btn)
        ssh_layout.addLayout(ssh_row1)

        ssh_row2 = QHBoxLayout()
        ssh_row2.addWidget(QLabel("Префиксы (через запятую):"))
        self.ssh_prefix_edit = QLineEdit()
        self.ssh_prefix_edit.setPlaceholderText(
            "пусто — /var/lib/postgresql/, /var/log/postgresql/, …"
        )
        ssh_row2.addWidget(self.ssh_prefix_edit, 1)
        ssh_row2.addWidget(QLabel("Макс. МБ:"))
        self.ssh_max_mb_spin = QSpinBox()
        self.ssh_max_mb_spin.setRange(1, 512)
        self.ssh_max_mb_spin.setValue(32)
        self.ssh_max_mb_spin.setToolTip(
            "Если файл больше лимита, на сервере выполняется tail -c (хвост файла)."
        )
        ssh_row2.addWidget(self.ssh_max_mb_spin)
        self.ssh_fetch_btn = QPushButton("Загрузить с сервера")
        self.ssh_fetch_btn.clicked.connect(self._ssh_fetch_log)
        ssh_row2.addWidget(self.ssh_fetch_btn)
        ssh_layout.addLayout(ssh_row2)
        layout.addWidget(ssh_box)

        row = QHBoxLayout()
        self.open_btn = QPushButton("Открыть файл…")
        self.open_btn.clicked.connect(self._open_file)
        row.addWidget(self.open_btn)

        self.parse_btn = QPushButton("Разобрать")
        self.parse_btn.clicked.connect(self._parse_buffer)
        row.addWidget(self.parse_btn)

        self.clear_btn = QPushButton("Очистить")
        self.clear_btn.clicked.connect(self._clear_all)
        row.addWidget(self.clear_btn)

        self.hide_tx_chk = QCheckBox("Скрыть BEGIN/COMMIT/ROLLBACK/SAVEPOINT")
        self.hide_tx_chk.setChecked(True)
        self.hide_tx_chk.stateChanged.connect(lambda _: self._reaggregate_only())
        row.addWidget(self.hide_tx_chk)

        row.addStretch()
        layout.addLayout(row)

        self.stats_label = QLabel("Вставьте фрагмент лога или откройте файл.")
        self.stats_label.setStyleSheet("color: #90caf9; font-size: 11px;")
        layout.addWidget(self.stats_label)

        splitter = QSplitter(Qt.Vertical)

        self.raw_edit = QPlainTextEdit()
        self.raw_edit.setPlaceholderText(
            "Вставьте сюда содержимое postgresql-*.log или csvlog…\n\n"
            "Пример:\n2025-01-01 12:00:00 UTC [1]: user=u,db=d LOG:  statement: SELECT 1;"
        )
        self.raw_edit.setMinimumHeight(120)
        splitter.addWidget(self.raw_edit)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["#", "Раз", "Таблицы (пример)", "Fingerprint / превью SQL"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_menu)
        self.table.itemDoubleClicked.connect(lambda *_: self._send_selected_to_query_input())
        self.table.setMinimumHeight(160)
        splitter.addWidget(self.table)

        self.detail = QTextBrowser()
        self.detail.setMinimumHeight(100)
        self.detail.setOpenExternalLinks(False)
        splitter.addWidget(self.detail)

        splitter.setSizes([180, 260, 140])
        layout.addWidget(splitter, 1)

        row2 = QHBoxLayout()
        self.to_query_btn = QPushButton("В поле запроса (вкладка «План»)")
        self.to_query_btn.setToolTip("Подставить полный текст выбранной строки в нижнее поле SQL.")
        self.to_query_btn.clicked.connect(self._send_selected_to_query_input)
        row2.addWidget(self.to_query_btn)
        row2.addStretch()
        layout.addLayout(row2)

    def _clear_all(self):
        self.raw_edit.clear()
        self._records = []
        self._aggregated = []
        self._meta = {}
        self._fill_table()
        self.detail.clear()
        self.stats_label.setText("Очищено.")

    def _open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Лог PostgreSQL",
            "",
            "Log files (*.log *.csv *.txt);;All files (*)",
        )
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                self.raw_edit.setPlainText(f.read())
        except OSError as e:
            QMessageBox.warning(self, "Файл", f"Не удалось прочитать файл:\n{e}")
            return
        self._parse_buffer()

    def _parse_buffer(self):
        text = self.raw_edit.toPlainText()
        if not text.strip():
            QMessageBox.information(self, "Разбор", "Нет текста для разбора.")
            return

        self._records = parse_log_statement_records(text)
        self._reaggregate_only()

        if not self._records:
            self.stats_label.setText(
                "Не найдено ни одной строки «LOG: statement:» и ни одной непустой колонки query в csvlog."
            )
            self.detail.setHtml(
                "<p style='color:#ffab91'>Проверьте, что в логе включён <code>log_statement</code> "
                "и что вы копируете фрагмент с записями уровня LOG.</p>"
            )
            return

    def _reaggregate_only(self):
        hide_tx = self.hide_tx_chk.isChecked()
        self._aggregated, self._meta = aggregate_log_statements(
            self._records,
            hide_transaction_commands=hide_tx,
        )
        self._fill_table()
        m = self._meta
        self.stats_label.setText(
            f"Высказываний в логе: {m.get('raw_statement_count', 0)} · "
            f"уникальных групп: {m.get('unique_fingerprints', 0)} · "
            f"скрыто транзакций: {m.get('skipped_transaction_commands', 0)}"
        )

    def _fill_table(self):
        self.table.setRowCount(0)
        for i, row in enumerate(self._aggregated, start=1):
            r = self.table.rowCount()
            self.table.insertRow(r)

            n_item = QTableWidgetItem(str(i))
            n_item.setFlags(n_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(r, 0, n_item)

            c_item = QTableWidgetItem(str(row.count))
            c_item.setFlags(c_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(r, 1, c_item)

            tables_txt = ", ".join(row.tables) if row.tables else "—"
            t_item = QTableWidgetItem(tables_txt)
            t_item.setFlags(t_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(r, 2, t_item)

            fp_short = row.fingerprint if len(row.fingerprint) <= 72 else row.fingerprint[:69] + "…"
            sql_prev = row.sample_sql.replace("\n", " ")
            if len(sql_prev) > 160:
                sql_prev = sql_prev[:157] + "…"
            combo = f"{fp_short}\n{sql_prev}"
            p_item = QTableWidgetItem(combo)
            p_item.setFlags(p_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(r, 3, p_item)

        self.table.resizeColumnToContents(2)

    def _selected_row_index(self) -> int:
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            return -1
        return int(sel[0].row())

    def _on_table_menu(self, pos):
        row = self._selected_row_index()
        if row < 0 or row >= len(self._aggregated):
            return
        menu = QMenu(self)
        act_q = menu.addAction("Вставить в поле запроса")
        act_d = menu.addAction("Показать полный SQL ниже")
        chosen = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if chosen == act_q:
            self._send_row_to_query_input(row)
        elif chosen == act_d:
            self._show_detail_for_row(row)

    def _show_detail_for_row(self, row: int):
        if row < 0 or row >= len(self._aggregated):
            return
        agg = self._aggregated[row]
        esc = html.escape(agg.sample_sql)
        tbl = html.escape(", ".join(agg.tables) if agg.tables else "—")
        fp = html.escape(agg.fingerprint)
        self.detail.setHtml(
            f"<p style='color:#81c784'><b>Таблицы (pglast):</b> {tbl}</p>"
            f"<p style='color:#b0bec5'><b>Fingerprint:</b> <code>{fp}</code></p>"
            f"<pre style='color:#e0e0e0;white-space:pre-wrap'>{esc}</pre>"
        )

    def _send_selected_to_query_input(self):
        row = self._selected_row_index()
        if row < 0:
            QMessageBox.information(self, "Запрос", "Выберите строку в таблице.")
            return
        self._send_row_to_query_input(row)

    def _send_row_to_query_input(self, row: int):
        if row < 0 or row >= len(self._aggregated):
            return
        sql = self._aggregated[row].sample_sql.strip()
        if not sql:
            return
        mw = self.parent
        if hasattr(mw, "query_input"):
            mw.query_input.setText(sql)
        if hasattr(mw, "_switch_left_tab") and hasattr(mw, "PLAN_TAB_LABEL"):
            mw._switch_left_tab(mw.PLAN_TAB_LABEL)

    def _load_ssh_settings(self):
        s = QSettings("pg_query_analyzer", "LogStatementSSH")
        self.remote_path_edit.setText(str(s.value("last_remote_path", "") or ""))
        self.ssh_prefix_edit.setText(str(s.value("path_prefixes", "") or ""))
        mb = int(s.value("max_mb", 32) or 32)
        self.ssh_max_mb_spin.setValue(max(1, min(512, mb)))

    def _save_ssh_settings(self):
        s = QSettings("pg_query_analyzer", "LogStatementSSH")
        s.setValue("last_remote_path", self.remote_path_edit.text().strip())
        s.setValue("path_prefixes", self.ssh_prefix_edit.text().strip())
        s.setValue("max_mb", int(self.ssh_max_mb_spin.value()))

    def _ssh_profile(self):
        mw = self.parent
        conn = getattr(mw, "current_connection", None)
        if not conn:
            QMessageBox.warning(
                self,
                "SSH",
                "Выберите сохранённое подключение в главном окне (профиль с паролем/keyring).",
            )
            return None
        ssh_cfg = conn.get("ssh") or {}
        if not ssh_cfg.get("enabled"):
            QMessageBox.warning(
                self,
                "SSH",
                "В профиле не включён SSH (как для туннеля / резервного копирования). "
                "Включите SSH в настройках подключения.",
            )
            return None
        return conn

    def _ssh_fetch_log(self):
        conn = self._ssh_profile()
        if not conn:
            return
        path = self.remote_path_edit.text().strip()
        if not path:
            QMessageBox.warning(self, "SSH", "Укажите абсолютный путь к файлу лога на сервере.")
            return

        if self._ssh_fetch_worker and self._ssh_fetch_worker.isRunning():
            QMessageBox.information(self, "SSH", "Загрузка уже выполняется.")
            return

        self._save_ssh_settings()
        prefixes = parse_log_prefix_whitelist(self.ssh_prefix_edit.text())
        max_bytes = int(self.ssh_max_mb_spin.value()) * 1024 * 1024

        def work():
            return fetch_remote_postgresql_log_text(
                conn,
                path,
                prefixes,
                max_bytes=max_bytes,
            )

        self._ssh_fetch_worker = CallableWorkerThread(work, self)
        self._ssh_fetch_worker.completed.connect(self._on_ssh_fetch_completed)
        self.ssh_fetch_btn.setEnabled(False)
        self.stats_label.setText("Загрузка по SSH…")
        self._ssh_fetch_worker.start()

    def _on_ssh_fetch_completed(self, ok: bool, payload: object):
        self.ssh_fetch_btn.setEnabled(True)
        if not ok:
            QMessageBox.warning(self, "SSH", str(payload))
            self.stats_label.setText("Ошибка загрузки по SSH.")
            return
        text, info = payload  # type: ignore[misc]
        self.raw_edit.setPlainText(text)
        self.stats_label.setText(info)
        self._parse_buffer()

    def _fetch_log_directory_from_db(self):
        mw = self.parent
        if not getattr(mw, "connection_status", False):
            QMessageBox.warning(
                self,
                "База",
                "Сначала подключитесь к PostgreSQL (кнопка подключения в главном окне).",
            )
            return
        conn = getattr(mw, "current_connection", None)
        if not conn:
            return

        if self._logdir_worker and self._logdir_worker.isRunning():
            return

        def work():
            return resolve_log_directory_absolute(conn)

        self._logdir_worker = CallableWorkerThread(work, self)
        self._logdir_worker.completed.connect(self._on_logdir_completed)
        self.logdir_btn.setEnabled(False)
        self._logdir_worker.start()

    def _on_logdir_completed(self, ok: bool, payload: object):
        self.logdir_btn.setEnabled(True)
        if not ok:
            QMessageBox.warning(self, "База", str(payload))
            return
        directory = str(payload).rstrip("/") + "/"
        self.remote_path_edit.setText(directory)
        self._save_ssh_settings()
        QMessageBox.information(
            self,
            "Каталог лога",
            f"Подставлен каталог:\n{directory}\nДопишите имя файла лога (например postgresql-…log).",
        )
