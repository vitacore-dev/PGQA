"""GUI for logical backup (pg_dump) and restore (pg_restore) using libpq client tools."""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

from PyQt5.QtCore import QProcess, QProcessEnvironment, QSettings, QThread, pyqtSignal
from PyQt5.QtGui import QShowEvent
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pg_query_analyzer.db.backup_cli import (
    DumpFormat,
    build_pg_dump_command,
    build_pg_restore_command,
    build_pg_restore_list_command,
)
from pg_query_analyzer.db.remote_pg_dump import (
    parse_prefix_whitelist,
    run_remote_pg_dump,
    validate_remote_dump_path,
)
from pg_query_analyzer.db.ssh_tunnel import open_ssh_tunnel_if_needed
from pg_query_analyzer.storage.connections import ConnectionSettings


class RemotePgDumpThread(QThread):
    """Run :func:`run_remote_pg_dump` off the GUI thread; stream log via signal."""

    log_chunk = pyqtSignal(str)
    finished_code = pyqtSignal(int)

    def __init__(
        self,
        connection: dict,
        *,
        remote_path: str,
        fmt: DumpFormat,
        prefixes: tuple[str, ...],
        pg_dump_bin: str,
        schema_only: bool,
        data_only: bool,
        no_owner: bool,
        no_privileges: bool,
        cancel_event: threading.Event,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._connection = connection
        self._remote_path = remote_path
        self._fmt = fmt
        self._prefixes = prefixes
        self._pg_dump_bin = pg_dump_bin
        self._schema_only = schema_only
        self._data_only = data_only
        self._no_owner = no_owner
        self._no_privileges = no_privileges
        self._cancel_event = cancel_event

    def run(self) -> None:
        code = run_remote_pg_dump(
            self._connection,
            remote_path=self._remote_path,
            fmt=self._fmt,
            prefixes=self._prefixes,
            pg_dump_bin=self._pg_dump_bin,
            schema_only=self._schema_only,
            data_only=self._data_only,
            no_owner=self._no_owner,
            no_privileges=self._no_privileges,
            log=lambda s: self.log_chunk.emit(s),
            cancelled=self._cancel_event.is_set,
        )
        self.finished_code.emit(code)


class BackupRestoreWidget(QWidget):
    """Left-tab panel: pg_dump / pg_restore, optional SSH tunnel; call :meth:`shutdown` on app exit."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._settings = QSettings("pg_query_analyzer", "BackupRestore")
        self._tunnel_cm: Any = None
        self._tunnel: Any = None
        self._process: Optional[QProcess] = None
        self._connect_profile: Optional[Dict[str, Any]] = None
        self._remote_thread: Optional[RemotePgDumpThread] = None
        self._remote_cancel = threading.Event()

        self._build_ui()
        self._load_backup_settings()
        self._reload_connections_combo()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        tabs.addTab(self._build_backup_tab(), "Резервная копия")
        tabs.addTab(self._build_restore_tab(), "Восстановление")
        layout.addWidget(tabs, 1)

        log_group = QGroupBox("Журнал")
        log_l = QVBoxLayout()
        self.log_edit = QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumBlockCount(5000)
        log_l.addWidget(self.log_edit)
        log_group.setLayout(log_l)
        layout.addWidget(log_group)

        btn_row = QHBoxLayout()
        self.stop_btn = QPushButton("Остановить")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_process)
        btn_row.addWidget(self.stop_btn)
        refresh_conn_btn = QPushButton("Обновить подключения")
        refresh_conn_btn.clicked.connect(self._reload_connections_combo)
        btn_row.addWidget(refresh_conn_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.setStyleSheet("""
            BackupRestoreWidget, QWidget { background-color: #2b2b2b; color: #e0e0e0; }
            QLabel { color: #e0e0e0; }
            QGroupBox { color: #b3e5fc; font-weight: bold; border: 1px solid #555; margin-top: 8px; }
            QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
                background-color: #333; color: #eee; border: 1px solid #555; border-radius: 3px;
            }
            QPushButton {
                background-color: #3a7bd5; color: #fff; border: none; padding: 6px 12px; border-radius: 4px;
            }
            QPushButton:hover { background-color: #4a8be5; }
            QPushButton:disabled { background-color: #555; color: #aaa; }
            QTabWidget::pane { border: 1px solid #555; }
            QTabBar::tab { background: #333; color: #ccc; padding: 6px 12px; }
            QTabBar::tab:selected { background: #3a7bd5; color: #fff; }
            """)

    def _build_backup_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        self.backup_target_combo = QComboBox()
        self.backup_target_combo.addItem("Клиент: pg_dump на этой машине", "client")
        self.backup_target_combo.addItem(
            "Узел SSH: pg_dump на сервере (путь на диске сервера)", "remote"
        )
        self.backup_target_combo.currentIndexChanged.connect(self._on_backup_target_changed)
        v.addWidget(QLabel("Режим резервной копии:"))
        v.addWidget(self.backup_target_combo)

        self.backup_hint = QLabel()
        self.backup_hint.setWordWrap(True)
        self.backup_hint.setStyleSheet("color: #b0bec5; font-size: 11px;")
        v.addWidget(self.backup_hint)

        self._client_backup_frame = QWidget()
        client_l = QVBoxLayout(self._client_backup_frame)
        client_l.setContentsMargins(0, 0, 0, 0)
        bin_row = QHBoxLayout()
        bin_row.addWidget(QLabel("Каталог bin (pg_dump):"))
        self.bin_dir_edit = QLineEdit()
        self.bin_dir_edit.setPlaceholderText("пусто = PATH")
        bin_row.addWidget(self.bin_dir_edit, 1)
        client_l.addLayout(bin_row)
        v.addWidget(self._client_backup_frame)

        self._remote_backup_frame = QWidget()
        remote_form = QFormLayout(self._remote_backup_frame)
        self.remote_prefix_edit = QLineEdit()
        self.remote_prefix_edit.setPlaceholderText(
            "/var/backups/,/tmp/pgqa_backup/,/var/lib/postgresql/"
        )
        remote_form.addRow("Разрешённые префиксы путей (через запятую):", self.remote_prefix_edit)
        self.remote_pg_dump_bin_edit = QLineEdit()
        self.remote_pg_dump_bin_edit.setPlaceholderText("pg_dump")
        remote_form.addRow("Команда pg_dump на сервере:", self.remote_pg_dump_bin_edit)
        v.addWidget(self._remote_backup_frame)

        form = QFormLayout()
        self.backup_conn_combo = QComboBox()
        form.addRow("Подключение:", self.backup_conn_combo)
        self.backup_format_combo = QComboBox()
        self.backup_format_combo.addItem("Custom (.dump) — рекомендуется", "custom")
        self.backup_format_combo.addItem("Directory (-Fd)", "directory")
        self.backup_format_combo.addItem("Plain SQL (-Fp)", "plain")
        form.addRow("Формат:", self.backup_format_combo)
        path_row = QHBoxLayout()
        self.backup_path_edit = QLineEdit()
        self.backup_browse_btn = QPushButton("Обзор…")
        self.backup_browse_btn.clicked.connect(self._browse_backup_path)
        path_row.addWidget(self.backup_path_edit, 1)
        path_row.addWidget(self.backup_browse_btn)
        pw = QWidget()
        pw.setLayout(path_row)
        self.backup_path_row_label = QLabel("Файл / каталог (на этой машине):")
        form.addRow(self.backup_path_row_label, pw)
        self.backup_schema_only = QCheckBox("Только схема (--schema-only)")
        self.backup_data_only = QCheckBox("Только данные (--data-only)")
        self.backup_no_owner = QCheckBox("Без OWNER (--no-owner)")
        self.backup_no_acl = QCheckBox("Без ACL (--no-acl)")
        form.addRow(self.backup_schema_only)
        form.addRow(self.backup_data_only)
        form.addRow(self.backup_no_owner)
        form.addRow(self.backup_no_acl)
        v.addLayout(form)
        self.backup_start_btn = QPushButton("Запустить pg_dump")
        self.backup_start_btn.clicked.connect(self._start_backup)
        v.addWidget(self.backup_start_btn)
        v.addStretch()
        self._on_backup_target_changed()
        return w

    def _on_backup_target_changed(self, *_args: Any) -> None:
        mode = self.backup_target_combo.currentData() or "client"
        remote = mode == "remote"
        self._client_backup_frame.setVisible(not remote)
        self._remote_backup_frame.setVisible(remote)
        self.backup_browse_btn.setVisible(not remote)
        if remote:
            self.backup_path_row_label.setText("Путь на узле SSH (абсолютный):")
            self.backup_hint.setText(
                "pg_dump выполняется на узле SSH из профиля (те же host/user/ключ, что для туннеля). "
                "Подключение к PostgreSQL — host/port из профиля, как видит этот узел "
                "(если SSH — bastion, а БД на другом хосте, укажите в профиле доступный с bastion адрес БД). "
                "Путь дампа проверяется по списку префиксов."
            )
        else:
            self.backup_path_row_label.setText("Файл / каталог (на этой машине):")
            self.backup_hint.setText(
                "Клиентский pg_dump на этой машине: данные с сервера записываются в локальный файл или каталог. "
                "Нужен pg_dump в PATH или в «Каталог bin»."
            )

    def _build_restore_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        form = QFormLayout()
        self.restore_conn_combo = QComboBox()
        form.addRow("Подключение:", self.restore_conn_combo)
        self.restore_target_db = QLineEdit()
        self.restore_target_db.setPlaceholderText("целевая БД (по умолчанию из профиля)")
        form.addRow("Целевая БД (-d):", self.restore_target_db)
        in_row = QHBoxLayout()
        self.restore_path_edit = QLineEdit()
        rb_file = QPushButton("Файл…")
        rb_file.clicked.connect(self._browse_restore_file)
        rb_dir = QPushButton("Каталог…")
        rb_dir.clicked.connect(self._browse_restore_dir)
        in_row.addWidget(self.restore_path_edit, 1)
        in_row.addWidget(rb_file)
        in_row.addWidget(rb_dir)
        iw = QWidget()
        iw.setLayout(in_row)
        form.addRow("Файл .dump или каталог:", iw)
        self.restore_jobs = QSpinBox()
        self.restore_jobs.setRange(1, 32)
        self.restore_jobs.setValue(1)
        self.restore_jobs.setToolTip("Параллельные задания (только custom/directory)")
        form.addRow("Параллель (-j):", self.restore_jobs)
        self.restore_no_owner = QCheckBox("Без OWNER (--no-owner)")
        self.restore_no_owner.setChecked(True)
        self.restore_no_acl = QCheckBox("Без ACL (--no-acl)")
        self.restore_no_acl.setChecked(True)
        self.restore_clean = QCheckBox("Очистить объекты перед созданием (--clean --if-exists)")
        self.restore_clean.setStyleSheet("color: #ffab91;")
        form.addRow(self.restore_no_owner)
        form.addRow(self.restore_no_acl)
        form.addRow(self.restore_clean)
        v.addLayout(form)
        row = QHBoxLayout()
        self.restore_start_btn = QPushButton("Запустить pg_restore")
        self.restore_start_btn.clicked.connect(self._start_restore)
        self.restore_list_btn = QPushButton("Оглавление дампа (--list)")
        self.restore_list_btn.clicked.connect(self._start_restore_list)
        row.addWidget(self.restore_start_btn)
        row.addWidget(self.restore_list_btn)
        v.addLayout(row)
        v.addStretch()
        return w

    def _load_backup_settings(self) -> None:
        self.bin_dir_edit.setText(self._settings.value("pg_bin_dir", "", str))
        self.remote_prefix_edit.setText(
            self._settings.value(
                "remote_path_prefixes",
                "/var/backups/,/tmp/pgqa_backup/,/var/lib/postgresql/",
                str,
            )
        )
        self.remote_pg_dump_bin_edit.setText(
            self._settings.value("remote_pg_dump_bin", "pg_dump", str)
        )
        mode = self._settings.value("backup_target", "client", str) or "client"
        idx = self.backup_target_combo.findData(mode)
        if idx >= 0:
            self.backup_target_combo.setCurrentIndex(idx)
        self._on_backup_target_changed()

    def _save_backup_settings(self) -> None:
        self._settings.setValue("pg_bin_dir", self.bin_dir_edit.text().strip())
        self._settings.setValue("remote_path_prefixes", self.remote_prefix_edit.text().strip())
        self._settings.setValue("remote_pg_dump_bin", self.remote_pg_dump_bin_edit.text().strip())
        self._settings.setValue("backup_target", self.backup_target_combo.currentData() or "client")

    def _reload_connections_combo(self) -> None:
        conns = ConnectionSettings.load_connections()
        names = sorted(conns.keys())
        self.backup_conn_combo.clear()
        self.restore_conn_combo.clear()
        for n in names:
            self.backup_conn_combo.addItem(n, n)
            self.restore_conn_combo.addItem(n, n)

        preferred = ""
        mw = self.parent()
        if mw and hasattr(mw, "connection_combo"):
            preferred = mw.connection_combo.currentText().strip()
        if preferred:
            idx = self.backup_conn_combo.findText(preferred)
            if idx >= 0:
                self.backup_conn_combo.setCurrentIndex(idx)
                self.restore_conn_combo.setCurrentIndex(idx)
        if self.backup_conn_combo.count() == 0:
            self._append_log("Нет сохранённых подключений. Добавьте профиль в «Подключения».\n")

    def _append_log(self, text: str) -> None:
        self.log_edit.moveCursor(self.log_edit.textCursor().End)
        self.log_edit.insertPlainText(text)
        self.log_edit.moveCursor(self.log_edit.textCursor().End)

    def _bin_dir(self) -> Optional[str]:
        s = self.bin_dir_edit.text().strip()
        return s or None

    def _browse_backup_path(self) -> None:
        if (self.backup_target_combo.currentData() or "client") == "remote":
            return
        fmt = self.backup_format_combo.currentData()
        if fmt == "directory":
            d = QFileDialog.getExistingDirectory(self, "Каталог для pg_dump -Fd")
            if d:
                self.backup_path_edit.setText(d)
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Файл дампа",
            self.backup_path_edit.text() or "backup.dump",
            "Custom dump (*.dump);;SQL (*.sql);;Все (*)",
        )
        if path:
            self.backup_path_edit.setText(path)

    def _browse_restore_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Файл custom dump",
            self.restore_path_edit.text() or "",
            "Custom dump (*.dump);;Все (*)",
        )
        if path:
            self.restore_path_edit.setText(path)

    def _browse_restore_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Каталог directory-format")
        if d:
            self.restore_path_edit.setText(d)

    def showEvent(self, event: QShowEvent) -> None:  # type: ignore[override]
        super().showEvent(event)
        try:
            self._reload_connections_combo()
        except Exception:
            logging.debug("backup tab: reload connections failed", exc_info=True)

    def shutdown(self, interactive: bool = True) -> bool:
        """Stop pg_dump/pg_restore and tunnel. If ``interactive`` and a job runs, ask user."""
        if self._remote_thread is not None and self._remote_thread.isRunning():
            if interactive:
                r = QMessageBox.question(
                    self,
                    "Процесс выполняется",
                    "Остановить удалённый pg_dump?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if r != QMessageBox.Yes:
                    return False
            self._remote_cancel.set()
            self._remote_thread.wait(8000)
            self._remote_thread = None

        if self._process is not None and self._process.state() != QProcess.NotRunning:
            if interactive:
                r = QMessageBox.question(
                    self,
                    "Процесс выполняется",
                    "Остановить pg_dump/pg_restore?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if r != QMessageBox.Yes:
                    return False
            self._stop_process()
        self._save_backup_settings()
        self._close_tunnel_if_any()
        return True

    def _busy(self, busy: bool) -> None:
        remote_running = self._remote_thread is not None and self._remote_thread.isRunning()
        any_busy = busy or remote_running
        self.stop_btn.setEnabled(any_busy)
        self.backup_start_btn.setEnabled(not any_busy)
        self.restore_start_btn.setEnabled(not any_busy)
        self.restore_list_btn.setEnabled(not any_busy)
        self.backup_target_combo.setEnabled(not any_busy)

    def _stop_process(self) -> None:
        self._remote_cancel.set()
        th = self._remote_thread
        if th is not None and th.isRunning():
            self._append_log("\n[остановка удалённого pg_dump…]\n")
            th.wait(8000)
            self._remote_thread = None

        if self._process is None:
            return
        if self._process.state() != QProcess.NotRunning:
            self._append_log("\n[остановка по запросу пользователя]\n")
            self._process.kill()
            self._process.waitForFinished(5000)

    def _close_tunnel_if_any(self) -> None:
        if self._tunnel_cm is not None:
            try:
                self._tunnel_cm.__exit__(None, None, None)
            except Exception:
                pass
            self._tunnel_cm = None
        self._tunnel = None

    def _prepare_profile_and_kwargs(self, conn_name: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
        conns = ConnectionSettings.load_connections()
        if conn_name not in conns:
            raise ValueError(f"Подключение «{conn_name}» не найдено")
        profile = dict(conns[conn_name])
        kw = dict(ConnectionSettings.connect_kwargs(profile))
        return profile, kw

    def _open_tunnel_if_needed(self, profile: Dict[str, Any], kw: Dict[str, Any]) -> Dict[str, Any]:
        """Return connect kwargs (possibly localhost + tunnel port). Starts SSH tunnel if needed."""
        self._close_tunnel_if_any()
        self._tunnel_cm = open_ssh_tunnel_if_needed(profile)
        tunnel = self._tunnel_cm.__enter__()
        self._tunnel = tunnel
        if tunnel is not None:
            out = dict(kw)
            out["host"] = "127.0.0.1"
            out["port"] = int(tunnel.local_bind_port)
            return out
        return kw

    def _start_backup(self) -> None:
        if self._remote_thread is not None and self._remote_thread.isRunning():
            return
        if self._process is not None and self._process.state() != QProcess.NotRunning:
            return
        self._save_backup_settings()
        mode = self.backup_target_combo.currentData() or "client"
        if mode == "remote":
            self._start_backup_remote()
            return

        name = self.backup_conn_combo.currentText().strip()
        if not name:
            QMessageBox.warning(self, "Профиль", "Выберите подключение.")
            return
        path = self.backup_path_edit.text().strip()
        if not path:
            QMessageBox.warning(self, "Путь", "Укажите файл или каталог для дампа.")
            return
        fmt_raw = self.backup_format_combo.currentData()
        fmt: DumpFormat = fmt_raw if fmt_raw in ("custom", "directory", "plain") else "custom"
        try:
            profile, kw = self._prepare_profile_and_kwargs(name)
        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", str(e))
            return

        if self.backup_schema_only.isChecked() and self.backup_data_only.isChecked():
            QMessageBox.warning(
                self, "Параметры", "Нельзя одновременно «только схема» и «только данные»."
            )
            return

        if fmt == "directory":
            os.makedirs(path, exist_ok=True)
        else:
            parent = os.path.dirname(os.path.abspath(path))
            if parent:
                os.makedirs(parent, exist_ok=True)

        self._connect_profile = profile
        try:
            eff_kw = self._open_tunnel_if_needed(profile, kw)
            prog, args, extra = build_pg_dump_command(
                bin_dir=self._bin_dir(),
                connect_kwargs=eff_kw,
                output_path=path,
                fmt=fmt,
                schema_only=self.backup_schema_only.isChecked(),
                data_only=self.backup_data_only.isChecked(),
                no_owner=self.backup_no_owner.isChecked(),
                no_privileges=self.backup_no_acl.isChecked(),
            )
        except Exception as e:
            self._close_tunnel_if_any()
            QMessageBox.critical(self, "Ошибка", str(e))
            return

        self._log_command("pg_dump", prog, args)
        self._spawn_process(prog, args, extra)

    def _start_backup_remote(self) -> None:
        name = self.backup_conn_combo.currentText().strip()
        if not name:
            QMessageBox.warning(self, "Профиль", "Выберите подключение.")
            return
        path = self.backup_path_edit.text().strip()
        if not path:
            QMessageBox.warning(self, "Путь", "Укажите абсолютный путь на узле SSH.")
            return
        fmt_raw = self.backup_format_combo.currentData()
        fmt: DumpFormat = fmt_raw if fmt_raw in ("custom", "directory", "plain") else "custom"
        try:
            profile, _kw = self._prepare_profile_and_kwargs(name)
        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", str(e))
            return

        ssh_cfg = profile.get("ssh") or {}
        if not ssh_cfg.get("enabled"):
            QMessageBox.warning(
                self,
                "SSH",
                "Для дампа на диск сервера включите SSH в профиле подключения "
                "(те же поля, что для туннеля к PostgreSQL).",
            )
            return

        if self.backup_schema_only.isChecked() and self.backup_data_only.isChecked():
            QMessageBox.warning(
                self, "Параметры", "Нельзя одновременно «только схема» и «только данные»."
            )
            return

        prefixes = parse_prefix_whitelist(self.remote_prefix_edit.text())
        try:
            validate_remote_dump_path(path, prefixes)
        except ValueError as e:
            QMessageBox.warning(self, "Путь на сервере", str(e))
            return

        pg_dump_bin = (self.remote_pg_dump_bin_edit.text() or "").strip() or "pg_dump"
        self._remote_cancel = threading.Event()
        self._connect_profile = profile
        th = RemotePgDumpThread(
            profile,
            remote_path=path,
            fmt=fmt,
            prefixes=prefixes,
            pg_dump_bin=pg_dump_bin,
            schema_only=self.backup_schema_only.isChecked(),
            data_only=self.backup_data_only.isChecked(),
            no_owner=self.backup_no_owner.isChecked(),
            no_privileges=self.backup_no_acl.isChecked(),
            cancel_event=self._remote_cancel,
            parent=self,
        )
        th.log_chunk.connect(self._append_log)
        th.finished_code.connect(self._on_remote_dump_finished)
        self._remote_thread = th
        self._busy(True)
        th.start()

    def _on_remote_dump_finished(self, code: int) -> None:
        self._append_log(f"\n--- удалённый pg_dump завершён, код {code} ---\n")
        self._remote_thread = None
        self._busy(False)

    def _start_restore(self) -> None:
        if self._remote_thread is not None and self._remote_thread.isRunning():
            return
        if self._process is not None and self._process.state() != QProcess.NotRunning:
            return
        self._save_backup_settings()
        name = self.restore_conn_combo.currentText().strip()
        if not name:
            QMessageBox.warning(self, "Профиль", "Выберите подключение.")
            return
        in_path = self.restore_path_edit.text().strip()
        if not in_path:
            QMessageBox.warning(self, "Путь", "Укажите файл .dump или каталог directory-format.")
            return
        if not os.path.isfile(in_path) and not os.path.isdir(in_path):
            QMessageBox.warning(self, "Путь", "Файл или каталог не существует.")
            return

        if self.restore_clean.isChecked():
            r = QMessageBox.question(
                self,
                "Подтверждение",
                "Включена опция --clean --if-exists: объекты в целевой БД могут быть удалены. Продолжить?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if r != QMessageBox.Yes:
                return

        try:
            profile, kw = self._prepare_profile_and_kwargs(name)
        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", str(e))
            return

        target_db = self.restore_target_db.text().strip()
        if not target_db:
            target_db = str(kw.get("dbname") or "postgres")

        self._connect_profile = profile
        try:
            eff_kw = self._open_tunnel_if_needed(profile, kw)
            prog, args, extra = build_pg_restore_command(
                bin_dir=self._bin_dir(),
                connect_kwargs=eff_kw,
                input_path=in_path,
                target_db=target_db,
                jobs=int(self.restore_jobs.value()),
                no_owner=self.restore_no_owner.isChecked(),
                no_privileges=self.restore_no_acl.isChecked(),
                clean_if_exists=self.restore_clean.isChecked(),
            )
        except Exception as e:
            self._close_tunnel_if_any()
            QMessageBox.critical(self, "Ошибка", str(e))
            return

        self._log_command("pg_restore", prog, args)
        self._spawn_process(prog, args, extra)

    def _start_restore_list(self) -> None:
        if self._remote_thread is not None and self._remote_thread.isRunning():
            return
        if self._process is not None and self._process.state() != QProcess.NotRunning:
            return
        self._save_backup_settings()
        in_path = self.restore_path_edit.text().strip()
        if not in_path or (not os.path.isfile(in_path) and not os.path.isdir(in_path)):
            QMessageBox.warning(self, "Путь", "Укажите существующий файл .dump или каталог.")
            return
        try:
            prog, args, extra = build_pg_restore_list_command(
                bin_dir=self._bin_dir(), input_path=in_path
            )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))
            return
        self._connect_profile = None
        self._log_command("pg_restore --list", prog, args)
        self._spawn_process(prog, args, extra)

    def _log_command(self, title: str, prog: str, args: list[str]) -> None:
        safe_args: list[str] = []
        for a in args:
            if " " in a or ";" in a:
                safe_args.append(repr(a))
            else:
                safe_args.append(a)
        self._append_log(f"\n--- {title} ---\n{prog} {' '.join(safe_args)}\n\n")

    def _spawn_process(
        self,
        program: str,
        arguments: list[str],
        extra_env: dict[str, str],
    ) -> None:
        proc = QProcess(self)
        self._process = proc
        env = QProcessEnvironment.systemEnvironment()
        for k, v in extra_env.items():
            env.insert(k, v)
        proc.setProcessEnvironment(env)
        proc.setProgram(program)
        proc.setArguments(arguments)
        proc.setProcessChannelMode(QProcess.MergedChannels)
        proc.readyReadStandardOutput.connect(self._drain_stdout)
        proc.finished.connect(self._on_process_finished)
        proc.errorOccurred.connect(self._on_process_error)
        self._busy(True)
        proc.start()
        if not proc.waitForStarted(8000):
            self._append_log(f"Не удалось запустить процесс: {proc.errorString()}\n")
            self._close_tunnel_if_any()
            self._process = None
            self._busy(False)

    def _drain_stdout(self) -> None:
        proc = self._process
        if proc is None:
            return
        data = proc.readAllStandardOutput().data()
        if data:
            try:
                self._append_log(data.decode("utf-8", errors="replace"))
            except Exception:
                self._append_log(str(data))

    def _on_process_error(self, err: QProcess.ProcessError) -> None:
        self._append_log(f"\n[ошибка процесса: {err}]\n")

    def _on_process_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self._append_log(f"\n--- завершено, код выхода {exit_code}, статус {exit_status} ---\n")
        self._process = None
        self._busy(False)
        self._close_tunnel_if_any()
