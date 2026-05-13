"""Settings dialog for analyzer thresholds, visualization, colors, monitoring, journal."""

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QCheckBox,
    QColorDialog,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QLineEdit,
    QScrollArea,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pg_query_analyzer.ai.openrouter_client import validate_openrouter_settings
from pg_query_analyzer.ai.openrouter_client import list_openrouter_models


class AnalyzerSettingsDialog(QDialog):
    settings_changed = pyqtSignal(dict)

    def __init__(self, parent=None, current_settings=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки анализатора планов запросов")
        self.setMinimumSize(700, 800)
        self.setModal(False)

        self.settings = current_settings if current_settings else self.get_default_settings()

        self.setup_ui()
        self.load_settings_to_ui()

    def get_default_settings(self):
        return {
            "thresholds": {
                "high_cost_absolute": 10000.0,
                "high_cost_percent": 10.0,
                "seq_scan_warning_cost": 150.0,
                "nested_loop_warning_cost": 500.0,
                "expensive_operation_percent": 15.0,
                "long_duration_seconds": 60.0,
                "dead_tup_percent": 20.0,
                "mod_since_analyze_warning": 10000,
                "mod_since_analyze_critical": 100000,
                "rows_estimate_ratio_warn": 10.0,
                "rows_estimate_min_rows": 1.0,
                "buffers_shared_read_warn_blocks": 64,
                "temp_spill_warning_blocks": 1,
            },
            "visualization": {
                "max_nodes_display": 100,
                "max_plan_depth": 0,
                "node_size_factor": 30,
                "enable_animations": True,
                "default_layout": "default",
                "show_cost_on_nodes": True,
                "show_rows_on_nodes": False,
            },
            "analysis": {
                "enable_index_recommendations": True,
                "enable_join_optimization": True,
                "enable_vacuum_recommendations": True,
                "enable_parallel_recommendations": True,
                "max_index_fields": 5,
                "min_table_size_for_index_mb": 10.0,
                "analyze_deep_level": 5,
                "max_expensive_operations_display": 5,
                "max_expensive_indexes_display": 5,
                "enable_row_estimate_analysis": True,
                "max_row_estimate_mismatch_nodes": 8,
                "enable_buffers_io_analysis": True,
                "max_buffers_io_nodes": 8,
                "enable_spill_problems": True,
                "enable_stale_statistics_analysis": True,
                "enable_confidence_scores": True,
                "max_stale_statistics_relations": 12,
            },
            "colors": {
                "high_cost_node": "#ff6b6b",
                "seq_scan_node": "#ff9e80",
                "index_scan_node": "#51cf66",
                "warning_text": "#ff8a65",
                "error_text": "#ff6b6b",
                "recommendation_text": "#b3e5fc",
            },
            "monitoring": {
                "scan_interval_seconds": 2,
                "max_active_queries_display": 50,
                "enable_auto_refresh": True,
                "highlight_blocked_queries": True,
            },
            "journal": {
                "max_entries": 1000,
                "auto_save_plans": True,
                "save_analysis_results": True,
                "query_normalization": True,
                "highlight_similar_queries": True,
                "max_query_groups": 50,
            },
            "ai": {
                "enabled": False,
                "provider": "openrouter",
                "base_url": "https://openrouter.ai/api/v1",
                "model": "openai/gpt-4o-mini",
                "api_key": "",
                "mask_sql_literals": True,
                "cache_enabled": True,
            },
        }

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)

        self.tab_widget = QTabWidget()

        self.create_thresholds_tab()
        self.create_visualization_tab()
        self.create_analysis_tab()
        self.create_colors_tab()
        self.create_monitoring_tab()
        self.create_journal_tab()
        self.create_ai_tab()

        self.tab_widget.addTab(self.thresholds_tab, "Пороговые значения")
        self.tab_widget.addTab(self.visualization_tab, "Визуализация")
        self.tab_widget.addTab(self.analysis_tab, "Анализ")
        self.tab_widget.addTab(self.colors_tab, "Цвета")
        self.tab_widget.addTab(self.monitoring_tab, "Мониторинг")
        self.tab_widget.addTab(self.journal_tab, "Журнал")
        self.tab_widget.addTab(self.ai_tab, "AI / OpenRouter")

        main_layout.addWidget(self.tab_widget)

        button_layout = QHBoxLayout()

        self.reset_defaults_btn = QPushButton("Сбросить настройки по умолчанию")
        self.reset_defaults_btn.clicked.connect(self.reset_to_defaults)

        self.save_btn = QPushButton("Сохранить")
        self.save_btn.clicked.connect(self.save_settings)

        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.clicked.connect(self.reject)

        button_layout.addWidget(self.reset_defaults_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.cancel_btn)

        main_layout.addLayout(button_layout)

        self.apply_styles()

    def apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #2d2d2d;
            }
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
            QLabel {
                color: #e0e0e0;
                font-size: 12px;
            }
            QLineEdit, QSpinBox, QDoubleSpinBox {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 3px;
            }
            QCheckBox {
                color: #e0e0e0;
            }
            QComboBox {
                background-color: #333;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 3px;
            }
            QPushButton {
                background-color: #3a7bd5;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #4a8be5;
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
        """)

    def create_color_picker_button(self, initial_color, color_name):
        button = QPushButton()
        button.setObjectName(f"color_button_{color_name}")
        button.setMinimumWidth(80)
        button.setMaximumWidth(100)
        button.setMinimumHeight(25)

        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {initial_color};
                border: 1px solid #555;
                border-radius: 3px;
                color: {'#000000' if self.is_light_color(initial_color) else '#ffffff'};
            }}
            QPushButton:hover {{
                border: 2px solid #4a8be5;
            }}
        """)

        button.current_color = initial_color
        button.color_name = color_name

        button.clicked.connect(lambda: self.pick_color(button))

        return button

    def is_light_color(self, color_hex):
        try:
            color_hex = color_hex.lstrip("#")
            r = int(color_hex[0:2], 16)
            g = int(color_hex[2:4], 16)
            b = int(color_hex[4:6], 16)
            brightness = (r * 299 + g * 587 + b * 114) / 1000
            return brightness > 128
        except Exception:
            return False

    def pick_color(self, button):
        current_color = button.current_color
        color = QColorDialog.getColor(
            QColor(current_color), self, f"Выберите цвет для {button.color_name}"
        )

        if color.isValid():
            new_color = color.name()
            button.current_color = new_color

            text_color = "#000000" if self.is_light_color(new_color) else "#ffffff"
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {new_color};
                    border: 1px solid #555;
                    border-radius: 3px;
                    color: {text_color};
                }}
                QPushButton:hover {{
                    border: 2px solid #4a8be5;
                }}
            """)

    def create_thresholds_tab(self):
        self.thresholds_tab = QWidget()
        layout = QVBoxLayout(self.thresholds_tab)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        cost_group = QGroupBox("Пороги стоимости")
        cost_layout = QFormLayout(cost_group)

        self.high_cost_absolute = QDoubleSpinBox()
        self.high_cost_absolute.setRange(0, 1000000)
        self.high_cost_absolute.setSuffix(" (абсолютное)")
        cost_layout.addRow("Высокая стоимость (абсолютная):", self.high_cost_absolute)

        self.high_cost_percent = QDoubleSpinBox()
        self.high_cost_percent.setRange(0, 100)
        self.high_cost_percent.setSuffix(" %")
        cost_layout.addRow("Высокая стоимость (процент от общего):", self.high_cost_percent)

        self.seq_scan_warning_cost = QDoubleSpinBox()
        self.seq_scan_warning_cost.setRange(0, 100000)
        self.seq_scan_warning_cost.setSuffix(" (стоимость)")
        cost_layout.addRow("Предупреждение Seq Scan при стоимости >:", self.seq_scan_warning_cost)

        self.nested_loop_warning_cost = QDoubleSpinBox()
        self.nested_loop_warning_cost.setRange(0, 100000)
        self.nested_loop_warning_cost.setSuffix(" (стоимость)")
        cost_layout.addRow(
            "Предупреждение Nested Loop при стоимости >:", self.nested_loop_warning_cost
        )

        self.expensive_operation_percent = QDoubleSpinBox()
        self.expensive_operation_percent.setRange(0, 100)
        self.expensive_operation_percent.setSuffix(" %")
        cost_layout.addRow(
            "Критическая операция (процент от общего):", self.expensive_operation_percent
        )

        scroll_layout.addWidget(cost_group)

        rows_est_group = QGroupBox("EXPLAIN ANALYZE (оценка строк)")
        rows_est_layout = QFormLayout(rows_est_group)
        self.rows_estimate_ratio_warn = QDoubleSpinBox()
        self.rows_estimate_ratio_warn.setRange(1.0, 10000.0)
        self.rows_estimate_ratio_warn.setDecimals(1)
        self.rows_estimate_ratio_warn.setToolTip(
            "Минимальное отношение Plan Rows к Actual Rows (или обратное), чтобы узел попал в отчёт."
        )
        rows_est_layout.addRow("Порог расхождения строк (×):", self.rows_estimate_ratio_warn)
        self.rows_estimate_min_rows = QDoubleSpinBox()
        self.rows_estimate_min_rows.setRange(0.0, 1e9)
        self.rows_estimate_min_rows.setDecimals(3)
        self.rows_estimate_min_rows.setToolTip(
            "Игнорировать узлы, где и оценка, и факт ниже этого порога (шум)."
        )
        rows_est_layout.addRow("Мин. строк для учёта:", self.rows_estimate_min_rows)
        scroll_layout.addWidget(rows_est_group)

        buffers_thr_group = QGroupBox("EXPLAIN ANALYZE (буферы)")
        buffers_thr_layout = QFormLayout(buffers_thr_group)
        self.buffers_shared_read_warn_blocks = QSpinBox()
        self.buffers_shared_read_warn_blocks.setRange(0, 2000000000)
        self.buffers_shared_read_warn_blocks.setToolTip(
            "Узел попадает в раздел «Чтение shared-буферов с диска», если Shared Read Blocks не ниже этого "
            "порога; 0 трактуется как минимум 1 блок."
        )
        buffers_thr_layout.addRow(
            "Порог Shared Read (блоков):", self.buffers_shared_read_warn_blocks
        )
        self.temp_spill_warning_blocks = QSpinBox()
        self.temp_spill_warning_blocks.setRange(0, 2000000000)
        self.temp_spill_warning_blocks.setToolTip(
            "Если Temp Written Blocks по узлу Hash Join / Hash Aggregate / Incremental Sort не ниже этого "
            "порога — сообщение в разделе «Критические проблемы»."
        )
        buffers_thr_layout.addRow(
            "Мин. Temp Written для предупред. спилла:", self.temp_spill_warning_blocks
        )
        scroll_layout.addWidget(buffers_thr_group)

        time_group = QGroupBox("Временные пороги")
        time_layout = QFormLayout(time_group)

        self.long_duration_seconds = QDoubleSpinBox()
        self.long_duration_seconds.setRange(0, 3600)
        self.long_duration_seconds.setSuffix(" сек")
        time_layout.addRow("Долгий запрос (длительность >):", self.long_duration_seconds)

        scroll_layout.addWidget(time_group)

        stats_group = QGroupBox("Пороги статистики")
        stats_layout = QFormLayout(stats_group)

        self.dead_tup_percent = QDoubleSpinBox()
        self.dead_tup_percent.setRange(0, 100)
        self.dead_tup_percent.setSuffix(" %")
        stats_layout.addRow("Мертвые строки для VACUUM (>):", self.dead_tup_percent)

        self.mod_since_analyze_warning = QSpinBox()
        self.mod_since_analyze_warning.setRange(0, 1000000)
        stats_layout.addRow(
            "Изменений после анализа (предупреждение >):", self.mod_since_analyze_warning
        )

        self.mod_since_analyze_critical = QSpinBox()
        self.mod_since_analyze_critical.setRange(0, 1000000)
        stats_layout.addRow(
            "Изменений после анализа (критично >):", self.mod_since_analyze_critical
        )

        scroll_layout.addWidget(stats_group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

    def create_visualization_tab(self):
        self.visualization_tab = QWidget()
        layout = QVBoxLayout(self.visualization_tab)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        group = QGroupBox("Настройки визуализации")
        form_layout = QFormLayout(group)

        self.max_nodes_display = QSpinBox()
        self.max_nodes_display.setRange(10, 500)
        form_layout.addRow("Максимум отображаемых узлов:", self.max_nodes_display)

        self.max_plan_depth = QSpinBox()
        self.max_plan_depth.setRange(0, 64)
        self.max_plan_depth.setToolTip(
            "Начальное значение для спинбокса «Макс. глубина» на визуализации плана (0 — без ограничения)."
        )
        form_layout.addRow("Макс. глубина дерева плана (по умол.):", self.max_plan_depth)

        self.node_size_factor = QDoubleSpinBox()
        self.node_size_factor.setRange(10, 100)
        self.node_size_factor.setSuffix(" %")
        form_layout.addRow("Множитель размера узла:", self.node_size_factor)

        self.enable_animations = QCheckBox("Включить анимации")
        form_layout.addRow("", self.enable_animations)

        self.show_cost_on_nodes = QCheckBox("Показывать стоимость на узлах")
        form_layout.addRow("", self.show_cost_on_nodes)

        self.show_rows_on_nodes = QCheckBox("Показывать количество строк на узлах")
        form_layout.addRow("", self.show_rows_on_nodes)

        self.default_layout = QComboBox()
        self.default_layout.addItems(["default", "hierarchical"])
        form_layout.addRow("Стандартная раскладка:", self.default_layout)

        scroll_layout.addWidget(group)
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

    def create_analysis_tab(self):
        self.analysis_tab = QWidget()
        layout = QVBoxLayout(self.analysis_tab)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        features_group = QGroupBox("Включенные функции анализа")
        features_layout = QVBoxLayout(features_group)

        self.enable_index_recommendations = QCheckBox("Рекомендации по индексам")
        features_layout.addWidget(self.enable_index_recommendations)

        self.enable_join_optimization = QCheckBox("Оптимизация JOIN операций")
        features_layout.addWidget(self.enable_join_optimization)

        self.enable_vacuum_recommendations = QCheckBox("Рекомендации по VACUUM")
        features_layout.addWidget(self.enable_vacuum_recommendations)

        self.enable_parallel_recommendations = QCheckBox("Рекомендации по параллелизму")
        features_layout.addWidget(self.enable_parallel_recommendations)

        self.enable_row_estimate_analysis = QCheckBox(
            "Анализ расхождения Plan Rows / Actual Rows (EXPLAIN ANALYZE)"
        )
        self.enable_row_estimate_analysis.setToolTip(
            "Раздел «Общий анализ»: узлы с большим отличием оценки строк от факта."
        )
        features_layout.addWidget(self.enable_row_estimate_analysis)

        self.enable_buffers_io_analysis = QCheckBox(
            "Анализ буферов и I/O (EXPLAIN ANALYZE, BUFFERS)"
        )
        self.enable_buffers_io_analysis.setToolTip(
            "Раздел «Общий анализ»: временные блоки (спиллы), высокий Shared Read по узлам."
        )
        features_layout.addWidget(self.enable_buffers_io_analysis)

        self.enable_spill_problems = QCheckBox(
            "Критические предупреждения о спилле Hash / Incremental Sort (Temp Written)"
        )
        self.enable_spill_problems.setToolTip(
            "Раздел «Критические проблемы» для узлов Hash Join, Hash Aggregate, Incremental Sort с Temp Written Blocks."
        )
        features_layout.addWidget(self.enable_spill_problems)

        self.enable_stale_statistics_analysis = QCheckBox(
            "Сводка по устаревшей / недостаточной статистике (Plan vs Actual Rows по отношениям)"
        )
        self.enable_stale_statistics_analysis.setToolTip(
            "Раздел «Общий анализ»: группирует узлы с большим расхождением оценённых и фактических строк по таблицам."
        )
        features_layout.addWidget(self.enable_stale_statistics_analysis)

        self.enable_confidence_scores = QCheckBox(
            "Показывать числовые оценки уверенности (эвристика 0–100)"
        )
        self.enable_confidence_scores.setToolTip(
            "Индексные гипотезы и сигналы статистики: не гарантия, а шкала правдоподобности модели правил анализатора."
        )
        features_layout.addWidget(self.enable_confidence_scores)

        scroll_layout.addWidget(features_group)

        params_group = QGroupBox("Параметры анализа")
        params_layout = QFormLayout(params_group)

        self.max_index_fields = QSpinBox()
        self.max_index_fields.setRange(1, 10)
        params_layout.addRow("Максимум полей в индексе:", self.max_index_fields)

        self.min_table_size_for_index_mb = QDoubleSpinBox()
        self.min_table_size_for_index_mb.setRange(0, 10000)
        self.min_table_size_for_index_mb.setSuffix(" MB")
        params_layout.addRow("Мин. размер таблицы для индекса:", self.min_table_size_for_index_mb)

        self.analyze_deep_level = QSpinBox()
        self.analyze_deep_level.setRange(1, 20)
        params_layout.addRow("Глубина рекурсивного анализа:", self.analyze_deep_level)

        self.max_expensive_operations_display = QSpinBox()
        self.max_expensive_operations_display.setRange(1, 50)
        self.max_expensive_operations_display.setToolTip(
            "Максимальное количество отображаемых ресурсоемких операций"
        )
        params_layout.addRow("Макс. ресурсоемких операций:", self.max_expensive_operations_display)

        self.max_expensive_indexes_display = QSpinBox()
        self.max_expensive_indexes_display.setRange(1, 50)
        self.max_expensive_indexes_display.setToolTip(
            "Максимальное количество отображаемых дорогих индексов"
        )
        params_layout.addRow("Макс. дорогих индексов:", self.max_expensive_indexes_display)

        self.max_row_estimate_mismatch_nodes = QSpinBox()
        self.max_row_estimate_mismatch_nodes.setRange(1, 50)
        self.max_row_estimate_mismatch_nodes.setToolTip(
            "Максимум узлов в разделе «оценка vs факт (строки)»."
        )
        params_layout.addRow("Макс. узлов расхождения строк:", self.max_row_estimate_mismatch_nodes)

        self.max_buffers_io_nodes = QSpinBox()
        self.max_buffers_io_nodes.setRange(1, 50)
        self.max_buffers_io_nodes.setToolTip(
            "Максимум узлов в каждом подразделе буферов (temp и disk)."
        )
        params_layout.addRow("Макс. узлов буферов/I-O:", self.max_buffers_io_nodes)

        self.max_stale_statistics_relations = QSpinBox()
        self.max_stale_statistics_relations.setRange(1, 80)
        self.max_stale_statistics_relations.setToolTip(
            "Максимум отношений в секции про устаревшую статистику (по узлам Plan/Actual Rows)."
        )
        params_layout.addRow(
            "Макс. таблиц в блоке статистики:", self.max_stale_statistics_relations
        )

        scroll_layout.addWidget(params_group)
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

    def create_colors_tab(self):
        self.colors_tab = QWidget()
        layout = QVBoxLayout(self.colors_tab)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        nodes_group = QGroupBox("Цвета узлов")
        nodes_layout = QFormLayout(nodes_group)

        high_cost_container = QWidget()
        high_cost_layout = QHBoxLayout(high_cost_container)
        high_cost_layout.setContentsMargins(0, 0, 0, 0)

        self.high_cost_color_btn = self.create_color_picker_button("#ff6b6b", "high_cost_node")
        high_cost_layout.addWidget(self.high_cost_color_btn)
        high_cost_layout.addWidget(QLabel("Узел с высокой стоимостью"))
        high_cost_layout.addStretch()
        nodes_layout.addRow("", high_cost_container)

        seq_scan_container = QWidget()
        seq_scan_layout = QHBoxLayout(seq_scan_container)
        seq_scan_layout.setContentsMargins(0, 0, 0, 0)

        self.seq_scan_color_btn = self.create_color_picker_button("#ff9e80", "seq_scan_node")
        seq_scan_layout.addWidget(self.seq_scan_color_btn)
        seq_scan_layout.addWidget(QLabel("Узел Seq Scan"))
        seq_scan_layout.addStretch()
        nodes_layout.addRow("", seq_scan_container)

        index_scan_container = QWidget()
        index_scan_layout = QHBoxLayout(index_scan_container)
        index_scan_layout.setContentsMargins(0, 0, 0, 0)

        self.index_scan_color_btn = self.create_color_picker_button("#51cf66", "index_scan_node")
        index_scan_layout.addWidget(self.index_scan_color_btn)
        index_scan_layout.addWidget(QLabel("Узел Index Scan"))
        index_scan_layout.addStretch()
        nodes_layout.addRow("", index_scan_container)

        scroll_layout.addWidget(nodes_group)

        text_group = QGroupBox("Цвета текста")
        text_layout = QFormLayout(text_group)

        warning_container = QWidget()
        warning_layout = QHBoxLayout(warning_container)
        warning_layout.setContentsMargins(0, 0, 0, 0)

        self.warning_color_btn = self.create_color_picker_button("#ff8a65", "warning_text")
        warning_layout.addWidget(self.warning_color_btn)
        warning_layout.addWidget(QLabel("Цвет предупреждения"))
        warning_layout.addStretch()
        text_layout.addRow("", warning_container)

        error_container = QWidget()
        error_layout = QHBoxLayout(error_container)
        error_layout.setContentsMargins(0, 0, 0, 0)

        self.error_color_btn = self.create_color_picker_button("#ff6b6b", "error_text")
        error_layout.addWidget(self.error_color_btn)
        error_layout.addWidget(QLabel("Цвет ошибки"))
        error_layout.addStretch()
        text_layout.addRow("", error_container)

        recommendation_container = QWidget()
        recommendation_layout = QHBoxLayout(recommendation_container)
        recommendation_layout.setContentsMargins(0, 0, 0, 0)

        self.recommendation_color_btn = self.create_color_picker_button(
            "#b3e5fc", "recommendation_text"
        )
        recommendation_layout.addWidget(self.recommendation_color_btn)
        recommendation_layout.addWidget(QLabel("Цвет рекомендации"))
        recommendation_layout.addStretch()
        text_layout.addRow("", recommendation_container)

        scroll_layout.addWidget(text_group)

        info_label = QLabel("Нажмите на цветную кнопку для выбора цвета")
        info_label.setStyleSheet("color: #81c784; font-style: italic; margin-top: 10px;")
        scroll_layout.addWidget(info_label)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

    def create_monitoring_tab(self):
        self.monitoring_tab = QWidget()
        layout = QVBoxLayout(self.monitoring_tab)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        group = QGroupBox("Настройки мониторинга")
        form_layout = QFormLayout(group)

        self.scan_interval_seconds = QSpinBox()
        self.scan_interval_seconds.setRange(1, 60)
        self.scan_interval_seconds.setSuffix(" сек")
        form_layout.addRow("Интервал сканирования:", self.scan_interval_seconds)

        self.max_active_queries_display = QSpinBox()
        self.max_active_queries_display.setRange(10, 500)
        form_layout.addRow("Максимум отображаемых запросов:", self.max_active_queries_display)

        self.enable_auto_refresh = QCheckBox("Автоматическое обновление")
        form_layout.addRow("", self.enable_auto_refresh)

        self.highlight_blocked_queries = QCheckBox("Подсветка заблокированных запросов")
        form_layout.addRow("", self.highlight_blocked_queries)

        scroll_layout.addWidget(group)
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

    def create_journal_tab(self):
        self.journal_tab = QWidget()
        layout = QVBoxLayout(self.journal_tab)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        group = QGroupBox("Настройки журнала")
        form_layout = QFormLayout(group)

        self.max_entries = QSpinBox()
        self.max_entries.setRange(100, 10000)
        form_layout.addRow("Максимум записей в журнале:", self.max_entries)

        self.auto_save_plans = QCheckBox("Автоматическое сохранение планов")
        form_layout.addRow("", self.auto_save_plans)

        self.save_analysis_results = QCheckBox("Сохранять результаты анализа")
        form_layout.addRow("", self.save_analysis_results)

        self.query_normalization = QCheckBox("Включить нормализацию запросов")
        self.query_normalization.setChecked(True)
        form_layout.addRow("", self.query_normalization)

        self.highlight_similar_queries = QCheckBox("Подсветка похожих запросов")
        self.highlight_similar_queries.setChecked(True)
        form_layout.addRow("", self.highlight_similar_queries)

        self.max_query_groups = QSpinBox()
        self.max_query_groups.setRange(10, 200)
        self.max_query_groups.setValue(50)
        form_layout.addRow("Максимум групп запросов:", self.max_query_groups)

        scroll_layout.addWidget(group)
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

    def create_ai_tab(self):
        self.ai_tab = QWidget()
        layout = QVBoxLayout(self.ai_tab)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        group = QGroupBox("Настройки AI-интерпретатора")
        form_layout = QFormLayout(group)

        self.ai_enabled = QCheckBox("Включить AI-интерпретатор")
        self.ai_enabled.setToolTip(
            "Если выключено, AI-анализ не будет вызываться даже при наличии ключа."
        )
        form_layout.addRow("", self.ai_enabled)

        self.ai_provider = QComboBox()
        self.ai_provider.addItems(["openrouter"])
        self.ai_provider.setToolTip("Провайдер LLM API.")
        form_layout.addRow("Провайдер:", self.ai_provider)

        self.ai_base_url = QLineEdit()
        self.ai_base_url.setPlaceholderText("https://openrouter.ai/api/v1")
        self.ai_base_url.setToolTip("Базовый URL API провайдера.")
        form_layout.addRow("Base URL:", self.ai_base_url)

        self.ai_model = QComboBox()
        self.ai_model.setEditable(True)
        self.ai_model.setInsertPolicy(QComboBox.NoInsert)
        self.ai_model.setToolTip("Идентификатор модели на OpenRouter.")
        self.ai_model.addItem("openai/gpt-4o-mini")
        form_layout.addRow("Модель:", self.ai_model)

        self.ai_api_key = QLineEdit()
        self.ai_api_key.setEchoMode(QLineEdit.Password)
        self.ai_api_key.setPlaceholderText("sk-or-...")
        self.ai_api_key.setToolTip("API key OpenRouter.")
        form_layout.addRow("API key:", self.ai_api_key)

        self.ai_show_key = QCheckBox("Показать API key")
        self.ai_show_key.toggled.connect(self.toggle_ai_api_key_visibility)
        form_layout.addRow("", self.ai_show_key)

        self.ai_test_connection_btn = QPushButton("Проверить соединение")
        self.ai_test_connection_btn.clicked.connect(self.test_ai_connection)
        form_layout.addRow("", self.ai_test_connection_btn)

        self.ai_reload_models_btn = QPushButton("Загрузить все модели OpenRouter")
        self.ai_reload_models_btn.clicked.connect(self.reload_openrouter_models)
        form_layout.addRow("", self.ai_reload_models_btn)

        self.ai_mask_literals = QCheckBox("Маскировать SQL-литералы перед отправкой в AI")
        self.ai_mask_literals.setToolTip(
            "Скрывает строки и числа в SQL preview, чтобы уменьшить риск утечки чувствительных данных."
        )
        form_layout.addRow("", self.ai_mask_literals)

        self.ai_cache_enabled = QCheckBox("Кэшировать AI-ответы для одинаковых планов")
        self.ai_cache_enabled.setToolTip(
            "Повторный запрос по тому же плану и модели будет возвращаться из кэша."
        )
        form_layout.addRow("", self.ai_cache_enabled)

        scroll_layout.addWidget(group)
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

    def toggle_ai_api_key_visibility(self, visible):
        self.ai_api_key.setEchoMode(QLineEdit.Normal if visible else QLineEdit.Password)

    def test_ai_connection(self):
        provider = self.ai_provider.currentText().strip()
        base_url = self.ai_base_url.text().strip() or "https://openrouter.ai/api/v1"
        model = self.ai_model.currentText().strip()
        api_key = self.ai_api_key.text().strip()

        if provider != "openrouter":
            QMessageBox.warning(
                self,
                "Проверка AI",
                "Сейчас поддерживается только провайдер openrouter.",
            )
            return

        if not api_key:
            QMessageBox.warning(
                self,
                "Проверка AI",
                "Укажите API key OpenRouter.",
            )
            return

        if not model:
            QMessageBox.warning(
                self,
                "Проверка AI",
                "Укажите модель OpenRouter.",
            )
            return

        self.ai_test_connection_btn.setEnabled(False)
        self.ai_test_connection_btn.setText("Проверяем...")
        try:
            ok, message = validate_openrouter_settings(
                base_url=base_url,
                api_key=api_key,
                model=model,
            )
        finally:
            self.ai_test_connection_btn.setEnabled(True)
            self.ai_test_connection_btn.setText("Проверить соединение")

        if ok:
            QMessageBox.information(self, "Проверка AI", message)
        else:
            QMessageBox.critical(self, "Проверка AI", message)

    def reload_openrouter_models(self):
        provider = self.ai_provider.currentText().strip()
        base_url = self.ai_base_url.text().strip() or "https://openrouter.ai/api/v1"
        api_key = self.ai_api_key.text().strip()

        if provider != "openrouter":
            QMessageBox.warning(
                self,
                "Список моделей",
                "Сейчас поддерживается только провайдер openrouter.",
            )
            return
        if not api_key:
            QMessageBox.warning(
                self,
                "Список моделей",
                "Укажите API key OpenRouter, чтобы загрузить модели.",
            )
            return

        self.ai_reload_models_btn.setEnabled(False)
        self.ai_reload_models_btn.setText("Загрузка...")
        try:
            models = list_openrouter_models(base_url=base_url, api_key=api_key)
        except Exception as exc:
            QMessageBox.critical(self, "Список моделей", str(exc))
            return
        finally:
            self.ai_reload_models_btn.setEnabled(True)
            self.ai_reload_models_btn.setText("Загрузить все модели OpenRouter")

        current = self.ai_model.currentText().strip()
        self.ai_model.clear()
        self.ai_model.addItems(models)
        if current:
            idx = self.ai_model.findText(current)
            if idx >= 0:
                self.ai_model.setCurrentIndex(idx)
            else:
                self.ai_model.setCurrentText(current)

        QMessageBox.information(
            self,
            "Список моделей",
            f"Загружено моделей: {len(models)}",
        )

    def load_settings_to_ui(self):
        self.high_cost_absolute.setValue(self.settings["thresholds"]["high_cost_absolute"])
        self.high_cost_percent.setValue(self.settings["thresholds"]["high_cost_percent"])
        self.seq_scan_warning_cost.setValue(self.settings["thresholds"]["seq_scan_warning_cost"])
        self.nested_loop_warning_cost.setValue(
            self.settings["thresholds"]["nested_loop_warning_cost"]
        )
        self.expensive_operation_percent.setValue(
            self.settings["thresholds"]["expensive_operation_percent"]
        )
        self.long_duration_seconds.setValue(self.settings["thresholds"]["long_duration_seconds"])
        self.dead_tup_percent.setValue(self.settings["thresholds"]["dead_tup_percent"])
        self.mod_since_analyze_warning.setValue(
            self.settings["thresholds"]["mod_since_analyze_warning"]
        )
        self.mod_since_analyze_critical.setValue(
            self.settings["thresholds"]["mod_since_analyze_critical"]
        )
        self.rows_estimate_ratio_warn.setValue(
            self.settings["thresholds"].get("rows_estimate_ratio_warn", 10.0)
        )
        self.rows_estimate_min_rows.setValue(
            self.settings["thresholds"].get("rows_estimate_min_rows", 1.0)
        )
        self.buffers_shared_read_warn_blocks.setValue(
            self.settings["thresholds"].get("buffers_shared_read_warn_blocks", 64)
        )
        self.temp_spill_warning_blocks.setValue(
            self.settings["thresholds"].get("temp_spill_warning_blocks", 1)
        )

        self.max_nodes_display.setValue(self.settings["visualization"]["max_nodes_display"])
        self.max_plan_depth.setValue(self.settings["visualization"].get("max_plan_depth", 0))
        self.node_size_factor.setValue(self.settings["visualization"]["node_size_factor"])
        self.enable_animations.setChecked(self.settings["visualization"]["enable_animations"])
        self.show_cost_on_nodes.setChecked(self.settings["visualization"]["show_cost_on_nodes"])
        self.show_rows_on_nodes.setChecked(self.settings["visualization"]["show_rows_on_nodes"])
        self.default_layout.setCurrentText(self.settings["visualization"]["default_layout"])

        self.enable_index_recommendations.setChecked(
            self.settings["analysis"]["enable_index_recommendations"]
        )
        self.enable_join_optimization.setChecked(
            self.settings["analysis"]["enable_join_optimization"]
        )
        self.enable_vacuum_recommendations.setChecked(
            self.settings["analysis"]["enable_vacuum_recommendations"]
        )
        self.enable_parallel_recommendations.setChecked(
            self.settings["analysis"]["enable_parallel_recommendations"]
        )
        self.enable_row_estimate_analysis.setChecked(
            self.settings["analysis"].get("enable_row_estimate_analysis", True)
        )
        self.enable_buffers_io_analysis.setChecked(
            self.settings["analysis"].get("enable_buffers_io_analysis", True)
        )
        self.enable_spill_problems.setChecked(
            self.settings["analysis"].get("enable_spill_problems", True)
        )
        self.enable_stale_statistics_analysis.setChecked(
            self.settings["analysis"].get("enable_stale_statistics_analysis", True)
        )
        self.enable_confidence_scores.setChecked(
            self.settings["analysis"].get("enable_confidence_scores", True)
        )
        self.max_index_fields.setValue(self.settings["analysis"]["max_index_fields"])
        self.min_table_size_for_index_mb.setValue(
            self.settings["analysis"]["min_table_size_for_index_mb"]
        )
        self.analyze_deep_level.setValue(self.settings["analysis"]["analyze_deep_level"])
        self.max_expensive_operations_display.setValue(
            self.settings["analysis"].get("max_expensive_operations_display", 5)
        )
        self.max_expensive_indexes_display.setValue(
            self.settings["analysis"].get("max_expensive_indexes_display", 5)
        )
        self.max_row_estimate_mismatch_nodes.setValue(
            self.settings["analysis"].get("max_row_estimate_mismatch_nodes", 8)
        )
        self.max_buffers_io_nodes.setValue(self.settings["analysis"].get("max_buffers_io_nodes", 8))
        self.max_stale_statistics_relations.setValue(
            self.settings["analysis"].get("max_stale_statistics_relations", 12)
        )

        self.update_color_button(
            self.high_cost_color_btn, self.settings["colors"]["high_cost_node"], "high_cost_node"
        )
        self.update_color_button(
            self.seq_scan_color_btn, self.settings["colors"]["seq_scan_node"], "seq_scan_node"
        )
        self.update_color_button(
            self.index_scan_color_btn, self.settings["colors"]["index_scan_node"], "index_scan_node"
        )
        self.update_color_button(
            self.warning_color_btn, self.settings["colors"]["warning_text"], "warning_text"
        )
        self.update_color_button(
            self.error_color_btn, self.settings["colors"]["error_text"], "error_text"
        )
        self.update_color_button(
            self.recommendation_color_btn,
            self.settings["colors"]["recommendation_text"],
            "recommendation_text",
        )

        self.scan_interval_seconds.setValue(self.settings["monitoring"]["scan_interval_seconds"])
        self.max_active_queries_display.setValue(
            self.settings["monitoring"]["max_active_queries_display"]
        )
        self.enable_auto_refresh.setChecked(self.settings["monitoring"]["enable_auto_refresh"])
        self.highlight_blocked_queries.setChecked(
            self.settings["monitoring"]["highlight_blocked_queries"]
        )

        self.max_entries.setValue(self.settings["journal"]["max_entries"])
        self.auto_save_plans.setChecked(self.settings["journal"]["auto_save_plans"])
        self.save_analysis_results.setChecked(self.settings["journal"]["save_analysis_results"])

        self.query_normalization.setChecked(
            self.settings["journal"].get("query_normalization", True)
        )
        self.highlight_similar_queries.setChecked(
            self.settings["journal"].get("highlight_similar_queries", True)
        )
        self.max_query_groups.setValue(self.settings["journal"].get("max_query_groups", 50))

        ai_settings = self.settings.get("ai", {})
        self.ai_enabled.setChecked(ai_settings.get("enabled", False))
        self.ai_provider.setCurrentText(ai_settings.get("provider", "openrouter"))
        self.ai_base_url.setText(ai_settings.get("base_url", "https://openrouter.ai/api/v1"))
        self.ai_model.setCurrentText(ai_settings.get("model", "openai/gpt-4o-mini"))
        self.ai_api_key.setText(ai_settings.get("api_key", ""))
        self.ai_mask_literals.setChecked(ai_settings.get("mask_sql_literals", True))
        self.ai_cache_enabled.setChecked(ai_settings.get("cache_enabled", True))
        self.ai_show_key.setChecked(False)
        self.toggle_ai_api_key_visibility(False)

    def update_color_button(self, button, color, color_name):
        if button:
            button.current_color = color
            button.color_name = color_name
            text_color = "#000000" if self.is_light_color(color) else "#ffffff"
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    border: 1px solid #555;
                    border-radius: 3px;
                    color: {text_color};
                }}
                QPushButton:hover {{
                    border: 2px solid #4a8be5;
                }}
            """)

    def get_settings_from_ui(self):
        return {
            "thresholds": {
                "high_cost_absolute": self.high_cost_absolute.value(),
                "high_cost_percent": self.high_cost_percent.value(),
                "seq_scan_warning_cost": self.seq_scan_warning_cost.value(),
                "nested_loop_warning_cost": self.nested_loop_warning_cost.value(),
                "expensive_operation_percent": self.expensive_operation_percent.value(),
                "long_duration_seconds": self.long_duration_seconds.value(),
                "dead_tup_percent": self.dead_tup_percent.value(),
                "mod_since_analyze_warning": self.mod_since_analyze_warning.value(),
                "mod_since_analyze_critical": self.mod_since_analyze_critical.value(),
                "rows_estimate_ratio_warn": self.rows_estimate_ratio_warn.value(),
                "rows_estimate_min_rows": self.rows_estimate_min_rows.value(),
                "buffers_shared_read_warn_blocks": self.buffers_shared_read_warn_blocks.value(),
                "temp_spill_warning_blocks": self.temp_spill_warning_blocks.value(),
            },
            "visualization": {
                "max_nodes_display": self.max_nodes_display.value(),
                "max_plan_depth": self.max_plan_depth.value(),
                "node_size_factor": self.node_size_factor.value(),
                "enable_animations": self.enable_animations.isChecked(),
                "show_cost_on_nodes": self.show_cost_on_nodes.isChecked(),
                "show_rows_on_nodes": self.show_rows_on_nodes.isChecked(),
                "default_layout": self.default_layout.currentText(),
            },
            "analysis": {
                "enable_index_recommendations": self.enable_index_recommendations.isChecked(),
                "enable_join_optimization": self.enable_join_optimization.isChecked(),
                "enable_vacuum_recommendations": self.enable_vacuum_recommendations.isChecked(),
                "enable_parallel_recommendations": self.enable_parallel_recommendations.isChecked(),
                "enable_row_estimate_analysis": self.enable_row_estimate_analysis.isChecked(),
                "enable_buffers_io_analysis": self.enable_buffers_io_analysis.isChecked(),
                "enable_spill_problems": self.enable_spill_problems.isChecked(),
                "enable_stale_statistics_analysis": self.enable_stale_statistics_analysis.isChecked(),
                "enable_confidence_scores": self.enable_confidence_scores.isChecked(),
                "max_index_fields": self.max_index_fields.value(),
                "min_table_size_for_index_mb": self.min_table_size_for_index_mb.value(),
                "analyze_deep_level": self.analyze_deep_level.value(),
                "max_expensive_operations_display": self.max_expensive_operations_display.value(),
                "max_expensive_indexes_display": self.max_expensive_indexes_display.value(),
                "max_row_estimate_mismatch_nodes": self.max_row_estimate_mismatch_nodes.value(),
                "max_buffers_io_nodes": self.max_buffers_io_nodes.value(),
                "max_stale_statistics_relations": self.max_stale_statistics_relations.value(),
            },
            "colors": {
                "high_cost_node": (
                    self.high_cost_color_btn.current_color
                    if hasattr(self, "high_cost_color_btn")
                    else "#ff6b6b"
                ),
                "seq_scan_node": (
                    self.seq_scan_color_btn.current_color
                    if hasattr(self, "seq_scan_color_btn")
                    else "#ff9e80"
                ),
                "index_scan_node": (
                    self.index_scan_color_btn.current_color
                    if hasattr(self, "index_scan_color_btn")
                    else "#51cf66"
                ),
                "warning_text": (
                    self.warning_color_btn.current_color
                    if hasattr(self, "warning_color_btn")
                    else "#ff8a65"
                ),
                "error_text": (
                    self.error_color_btn.current_color
                    if hasattr(self, "error_color_btn")
                    else "#ff6b6b"
                ),
                "recommendation_text": (
                    self.recommendation_color_btn.current_color
                    if hasattr(self, "recommendation_color_btn")
                    else "#b3e5fc"
                ),
            },
            "monitoring": {
                "scan_interval_seconds": self.scan_interval_seconds.value(),
                "max_active_queries_display": self.max_active_queries_display.value(),
                "enable_auto_refresh": self.enable_auto_refresh.isChecked(),
                "highlight_blocked_queries": self.highlight_blocked_queries.isChecked(),
            },
            "journal": {
                "max_entries": self.max_entries.value(),
                "auto_save_plans": self.auto_save_plans.isChecked(),
                "save_analysis_results": self.save_analysis_results.isChecked(),
                "query_normalization": self.query_normalization.isChecked(),
                "highlight_similar_queries": self.highlight_similar_queries.isChecked(),
                "max_query_groups": self.max_query_groups.value(),
            },
            "ai": {
                "enabled": self.ai_enabled.isChecked(),
                "provider": self.ai_provider.currentText().strip() or "openrouter",
                "base_url": self.ai_base_url.text().strip() or "https://openrouter.ai/api/v1",
                "model": self.ai_model.currentText().strip() or "openai/gpt-4o-mini",
                "api_key": self.ai_api_key.text().strip(),
                "mask_sql_literals": self.ai_mask_literals.isChecked(),
                "cache_enabled": self.ai_cache_enabled.isChecked(),
            },
        }

    def reset_to_defaults(self):
        reply = QMessageBox.question(
            self,
            "Сброс настроек",
            "Вы уверены, что хотите сбросить все настройки к значениям по умолчанию?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.settings = self.get_default_settings()
            self.load_settings_to_ui()
            QMessageBox.information(
                self,
                "Настройки",
                "Настройки сброшены к значениям по умолчанию.\nНажмите 'Сохранить' для применения.",
            )

    def save_settings(self):
        self.settings = self.get_settings_from_ui()
        self.settings_changed.emit(self.settings)
        self.accept()
