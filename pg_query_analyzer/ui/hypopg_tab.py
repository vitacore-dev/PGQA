"""HypoPG tab: hypothetical indexes + EXPLAIN in one DB session."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import psycopg2
from PyQt5.QtCore import QSettings
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from pg_query_analyzer.db.hypopg_sql import extract_hypopg_create_index_ddls
from pg_query_analyzer.storage.connections import ConnectionSettings
from pg_query_analyzer.ui.qt_workers import CallableWorkerThread


class HypoPGTab(QWidget):
    """Let planner see hypothetical indexes without creating real indexes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self._worker: Optional[CallableWorkerThread] = None
        self._settings = QSettings("pg_query_analyzer", "HypoPG")
        self._presets_loading = False
        self._setup_ui()
        self._restore_ddl_if_possible()

    def _connection_settings_key_fragment(self) -> Optional[str]:
        mw = self.parent
        if not mw or not getattr(mw, "current_connection", None):
            return None
        c = mw.current_connection
        h = str(c.get("host", "")).strip()
        d = str(c.get("dbname", "")).strip()
        return f"{h}:{d}"

    def _restore_ddl_if_possible(self) -> None:
        frag = self._connection_settings_key_fragment()
        if not frag:
            return
        ddl = self._settings.value(f"ddl_editor/{frag}", "", str)
        if ddl.strip():
            self.ddl_edit.setPlainText(ddl)

    def _persist_ddl(self) -> None:
        frag = self._connection_settings_key_fragment()
        if frag:
            self._settings.setValue(f"ddl_editor/{frag}", self.ddl_edit.toPlainText())

    def _load_presets(self) -> Dict[str, str]:
        frag = self._connection_settings_key_fragment()
        if not frag:
            return {}
        raw = self._settings.value(f"presets/{frag}", "{}")
        try:
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", errors="replace")
            if raw is None or raw == "":
                return {}
            d = json.loads(str(raw))
            return {str(k): str(v) for k, v in d.items()}
        except (json.JSONDecodeError, TypeError, AttributeError):
            return {}

    def _save_presets_dict(self, presets: Dict[str, str]) -> None:
        frag = self._connection_settings_key_fragment()
        if not frag:
            return
        self._settings.setValue(f"presets/{frag}", json.dumps(presets, ensure_ascii=False))

    def refresh_presets_combo(self) -> None:
        presets = self._load_presets()
        self._presets_loading = True
        self.preset_combo.blockSignals(True)
        self.preset_combo.clear()
        self.preset_combo.addItem("(пресеты)", "")
        for name in sorted(presets.keys(), key=lambda s: s.lower()):
            self.preset_combo.addItem(name, name)
        self.preset_combo.blockSignals(False)
        self._presets_loading = False

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_presets_combo()
        self._restore_ddl_if_possible()

    def hideEvent(self, event):
        self._persist_ddl()
        super().hideEvent(event)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        intro = QLabel(
            "HypoPG добавляет индексы только для планировщика в текущей сессии (не на диск). "
            "Берётся SQL из главного поля «Запрос». Нужно расширение hypopg в базе.\n"
            "Укажите по одному CREATE INDEX … на строку или используйте кнопки подстановки из рекомендаций / буфера. "
            "Текст DDL и именованные пресеты сохраняются локально для пары host:dbname."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #b0bec5; font-size: 11px;")
        layout.addWidget(intro)

        ddl_label = QLabel("Гипотетические CREATE INDEX:")
        ddl_label.setStyleSheet("color:#e0e0e0;")
        layout.addWidget(ddl_label)

        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("Пресет:"))
        self.preset_combo = QComboBox()
        self.preset_combo.setMinimumWidth(200)
        self.preset_combo.addItem("(пресеты)", "")
        self.preset_combo.currentIndexChanged.connect(self._on_preset_chosen_idx)
        preset_row.addWidget(self.preset_combo)
        btn_save_preset = QPushButton("Сохранить DDL как пресет…")
        btn_save_preset.setToolTip(
            "Сохранить текущий текст гипотетических CREATE INDEX под именем (локально)."
        )
        btn_save_preset.clicked.connect(self._on_save_preset)
        preset_row.addWidget(btn_save_preset)
        btn_rm_preset = QPushButton("Удалить текущий")
        btn_rm_preset.setToolTip("Удалить имя пресета, выбранное в выпадающем списке")
        btn_rm_preset.clicked.connect(self._on_delete_preset)
        preset_row.addWidget(btn_rm_preset)
        preset_row.addStretch()
        layout.addLayout(preset_row)

        self.ddl_edit = QPlainTextEdit()
        self.ddl_edit.setPlaceholderText(
            "CREATE INDEX ON public.orders USING btree (user_id);\n"
            "CREATE INDEX ON public.orders USING btree (created_at DESC, id);\n"
            "-- строки с -- игнорируются"
        )
        self.ddl_edit.setMinimumHeight(120)
        self.ddl_edit.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #444;
                font-family: Consolas, monospace;
                font-size: 11px;
            }
            """)
        layout.addWidget(self.ddl_edit)

        helpers = QHBoxLayout()
        self.btn_from_rec = QPushButton("Из вкладки «Рекомендации»")
        self.btn_from_rec.setToolTip("Взять CREATE INDEX из текста вкладки «Рекомендации» справа")
        self.btn_from_rec.clicked.connect(self._fill_from_recommendations)
        helpers.addWidget(self.btn_from_rec)
        self.btn_from_clip = QPushButton("Из буфера обмена")
        self.btn_from_clip.setToolTip("Разобрать текст буфера и найти операторы CREATE INDEX … ;")
        self.btn_from_clip.clicked.connect(self._fill_from_clipboard)
        helpers.addWidget(self.btn_from_clip)
        helpers.addStretch()
        layout.addLayout(helpers)

        row = QHBoxLayout()
        self.run_btn = QPushButton("EXPLAIN (FORMAT JSON) с гипотезами")
        self.run_btn.clicked.connect(self._run_hypo_explain)
        row.addWidget(self.run_btn)
        row.addStretch()
        layout.addLayout(row)

        pair_row = QHBoxLayout()
        self.btn_save_baseline = QPushButton("Журнал: базовый план (до HypoPG)")
        self.btn_save_baseline.setToolTip(
            "Сохранить текущий загруженный план в журнал и создать связку «до/после». "
            "Следующий успешный EXPLAIN с HypoPG получит вторую запись с тем же идентификатором пары."
        )
        self.btn_save_baseline.clicked.connect(self._on_save_baseline_clicked)
        pair_row.addWidget(self.btn_save_baseline)
        self.btn_clear_pair = QPushButton("Сбросить связку")
        self.btn_clear_pair.setToolTip(
            "Убрать ожидание пары для следующего HypoPG (записи в журнале не удаляются)."
        )
        self.btn_clear_pair.clicked.connect(self._on_clear_pair_clicked)
        pair_row.addWidget(self.btn_clear_pair)
        pair_row.addStretch()
        layout.addLayout(pair_row)

        self.pair_status = QLabel("")
        self.pair_status.setWordWrap(True)
        self.pair_status.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(self.pair_status)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(self.status_label)

        hint = QTextBrowser()
        hint.setMaximumHeight(72)
        hint.setOpenExternalLinks(False)
        hint.setHtml(
            "<small style='color:#888'>После успешного выполнения план подставится в анализатор "
            "(как после обычного EXPLAIN). Для явного сравнения с гипотезами: «Журнал: базовый план», "
            "затем EXPLAIN с HypoPG — обе записи получат общий идентификатор пары; в журнале можно "
            "открыть контекстное меню «Сравнить пару HypoPG».</small>"
        )
        layout.addWidget(hint)

        self._sync_pair_status_label()

    def _on_preset_chosen_idx(self, index: int) -> None:
        if self._presets_loading or index <= 0:
            return
        name = self.preset_combo.currentData()
        if not isinstance(name, str) or not name.strip():
            return
        presets = self._load_presets()
        text = presets.get(name.strip())
        if text is None:
            return
        self.ddl_edit.setPlainText(text)
        self.status_label.setStyleSheet("color: #90caf9; font-size: 11px;")
        self.status_label.setText(f"Загружен пресет «{name.strip()}».")
        self._persist_ddl()

    def _on_save_preset(self) -> None:
        if not self._connection_settings_key_fragment():
            QMessageBox.warning(
                self, "HypoPG", "Подключитесь к базе — нужен контекст host:dbname для пресетов."
            )
            return
        text = self.ddl_edit.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "HypoPG", "Нет DDL для сохранения.")
            return
        nm, ok = QInputDialog.getText(self, "Новый пресет HypoPG", "Имя пресета:")
        if not ok:
            return
        name = (nm or "").strip()
        if not name:
            return
        presets = self._load_presets()
        presets[name] = self.ddl_edit.toPlainText()
        self._save_presets_dict(presets)
        self.refresh_presets_combo()
        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        self.status_label.setText(f"Пресет «{name}» сохранён.")

    def _on_delete_preset(self) -> None:
        name_raw = self.preset_combo.currentData()
        name = name_raw.strip() if isinstance(name_raw, str) else ""
        if not name:
            QMessageBox.information(self, "HypoPG", "Выберите именованный пресет для удаления.")
            return
        presets = self._load_presets()
        if name in presets:
            del presets[name]
            self._save_presets_dict(presets)
        self.refresh_presets_combo()
        self.status_label.setStyleSheet("color: #ffb74d; font-size: 11px;")
        self.status_label.setText(f"Пресет «{name}» удалён локально.")

    def _sync_pair_status_label(self):
        mw = self.parent
        gid = getattr(mw, "_hypopg_pair_group_id", None) if mw else None
        if gid:
            self.pair_status.setText(
                "Связка «до/после» активна — id: "
                + gid[:14]
                + "… (следующий HypoPG сохранится как вторая запись пары)."
            )
            self.pair_status.setStyleSheet("color: #90caf9; font-size: 11px;")
        else:
            self.pair_status.setText("")
            self.pair_status.setStyleSheet("color: #888; font-size: 11px;")

    def _on_save_baseline_clicked(self):
        mw = self.parent
        if not mw:
            return
        if mw.save_hypopg_baseline_for_comparison():
            self._sync_pair_status_label()

    def _on_clear_pair_clicked(self):
        mw = self.parent
        if mw:
            mw.clear_hypopg_comparison_pair()
        self._sync_pair_status_label()

    def _fill_from_recommendations(self):
        mw = self.parent
        if not hasattr(mw, "optimization_text"):
            QMessageBox.information(self, "HypoPG", "Вкладка «Рекомендации» недоступна.")
            return
        plain = mw.optimization_text.toPlainText()
        ddls = extract_hypopg_create_index_ddls(plain)
        if not ddls:
            QMessageBox.information(
                self,
                "HypoPG",
                "В тексте рекомендаций не найдено ни одного оператора CREATE INDEX … ;",
            )
            return
        self.ddl_edit.setPlainText("\n".join(ddls))
        self._persist_ddl()
        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        self.status_label.setText(f"Подставлено операторов CREATE INDEX: {len(ddls)}")

    def _fill_from_clipboard(self):
        clip = QApplication.clipboard().text() if QApplication.clipboard() else ""
        ddls = extract_hypopg_create_index_ddls(clip)
        if not ddls:
            QMessageBox.information(
                self,
                "HypoPG",
                "В буфере не найдено ни одного оператора CREATE INDEX … ;",
            )
            return
        self.ddl_edit.setPlainText("\n".join(ddls))
        self._persist_ddl()
        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        self.status_label.setText(f"Подставлено операторов CREATE INDEX: {len(ddls)}")

    def load_from_observed_snapshot(
        self,
        *,
        query_sql: str,
        create_index_ddls: list[str],
        source_label: str = "",
    ) -> None:
        """Populate HypoPG Lab from an Observed Plan snapshot."""

        mw = self.parent
        if mw and hasattr(mw, "query_input") and query_sql.strip():
            mw.query_input.setText(query_sql.strip())

        if create_index_ddls:
            self.ddl_edit.setPlainText("\n".join(create_index_ddls))
            self._persist_ddl()
            self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
            suffix = f" из {source_label}" if source_label else ""
            self.status_label.setText(
                f"Подставлено операторов CREATE INDEX{suffix}: {len(create_index_ddls)}"
            )
        else:
            self.status_label.setStyleSheet("color: #ffb74d; font-size: 11px;")
            self.status_label.setText(
                "SQL подставлен, но CREATE INDEX в рекомендациях snapshot-а не найден."
            )

    def _hypo_explain_sync(self, sql: str, conn_params: dict, ddl_lines: list[str]) -> Any:
        from pg_query_analyzer.db.hypopg_sql import explain_json_with_hypothetical_indexes

        with psycopg2.connect(**conn_params) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                return explain_json_with_hypothetical_indexes(
                    cur,
                    query_sql=sql,
                    create_index_ddls=ddl_lines,
                )

    def _run_hypo_explain(self):
        mw = self.parent
        if not getattr(mw, "connection_status", False) or not getattr(
            mw, "current_connection", None
        ):
            QMessageBox.warning(self, "HypoPG", "Подключитесь к базе данных.")
            return

        sql = ""
        if hasattr(mw, "query_input"):
            sql = mw.query_input.text().strip()
        if not sql:
            QMessageBox.warning(self, "HypoPG", "Введите SQL запрос в главном поле.")
            return

        ddl_lines = self.ddl_edit.toPlainText().splitlines()

        conn_params = ConnectionSettings.connect_kwargs(mw.current_connection)

        self._persist_ddl()

        self.run_btn.setEnabled(False)
        self.status_label.setStyleSheet("color: #888; font-size: 11px;")
        self.status_label.setText("Выполнение EXPLAIN с HypoPG…")

        self._worker = CallableWorkerThread(
            lambda sp=sql, cp=conn_params, dl=list(ddl_lines): self._hypo_explain_sync(sp, cp, dl),
            self,
        )
        self._worker.completed.connect(self._on_hypo_worker_done)
        self._worker.start()

    def _on_hypo_worker_done(self, ok: bool, payload: Any) -> None:
        self.run_btn.setEnabled(True)
        self._worker = None

        plan_val = None if not ok else payload
        error_msg = str(payload) if not ok else None

        if error_msg:
            self.status_label.setStyleSheet("color: #ffb74d; font-size: 11px;")
            self.status_label.setText(error_msg)
            QMessageBox.warning(self, "HypoPG", error_msg)
            return

        self.status_label.setStyleSheet("color: #81c784; font-size: 11px;")
        self.status_label.setText("План получен — запуск анализа…")

        mw = self.parent
        if isinstance(plan_val, dict):
            mw.xml_content = json.dumps(plan_val, ensure_ascii=False)
        elif isinstance(plan_val, str):
            mw.xml_content = plan_val.strip()
        else:
            mw.xml_content = (
                json.dumps(plan_val, ensure_ascii=False) if plan_val is not None else ""
            )

        if hasattr(mw, "_pending_journal_queryid"):
            mw._pending_journal_queryid = None

        mw._pending_journal_plan_origin = "hypopg"
        mw.last_opened_file = None

        gid = getattr(mw, "_hypopg_pair_group_id", None)
        if gid:
            mw._pending_hypopg_pair_group_id = gid
            mw._pending_hypopg_pair_role = "hypopg"
        else:
            mw._pending_hypopg_pair_group_id = None
            mw._pending_hypopg_pair_role = None

        self._sync_pair_status_label()
        mw.analyze_query_plan()
