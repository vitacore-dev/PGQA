"""Interactive query-plan graph (vis-network in QWebEngineView)."""

import logging
import math

from PyQt5.QtCore import QObject, QUrl, pyqtSlot
from PyQt5.QtGui import QColor
from PyQt5.QtWebChannel import QWebChannel
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from pg_query_analyzer.visualization.html_templates import (
    VIS_NETWORK_LAYOUT_OPTIONS,
    plan_vis_network_html,
    simple_visualizer_error_html,
)


class Bridge(QObject):
    def __init__(self, callback, visible_outline_callback=None):
        super().__init__()
        self.callback = callback
        self.visible_outline_callback = visible_outline_callback

    @pyqtSlot(str)
    def updateNodeInfo(self, info):
        self.callback(info)

    @pyqtSlot(str)
    def updateVisibleOutline(self, payload):
        """JSON: visibleIds, collapsedRootIds, visibleCount, totalPlanNodes."""
        if self.visible_outline_callback:
            self.visible_outline_callback(payload)


class PlanVisualizerWindow(QWidget):
    def __init__(
        self,
        graph_data,
        node_info_callback,
        warning_message="",
        most_expensive_node_info=None,
        analyzer_settings=None,
        visible_outline_callback=None,
    ):
        super().__init__()
        if not graph_data:
            raise ValueError("graph_data не может быть пустым")
        self.node_info_callback = node_info_callback
        self.graph_data = graph_data
        self.warning_message = warning_message
        self.most_expensive_node_info = most_expensive_node_info
        self.analyzer_settings = analyzer_settings or {}
        self.current_layout = self.analyzer_settings.get("visualization", {}).get(
            "default_layout", "default"
        )

        self.show_cost_on_nodes = self.analyzer_settings.get("visualization", {}).get(
            "show_cost_on_nodes", True
        )
        self.show_rows_on_nodes = self.analyzer_settings.get("visualization", {}).get(
            "show_rows_on_nodes", False
        )
        self.enable_animations = self.analyzer_settings.get("visualization", {}).get(
            "enable_animations", True
        )
        self.node_size_factor = self.analyzer_settings.get("visualization", {}).get(
            "node_size_factor", 30
        )
        self.visible_outline_callback = visible_outline_callback

        self.init_ui()

    def init_ui(self):
        try:
            self.layout_selector = QComboBox()
            self.layout_selector.addItem("Стандартная визуализация", "default")
            self.layout_selector.addItem("Иерархическая (сверху вниз)", "hierarchical")
            lay_idx = self.layout_selector.findData(self.current_layout)
            self.layout_selector.setCurrentIndex(lay_idx if lay_idx >= 0 else 0)
            self.current_layout = self.layout_selector.currentData()

            self.max_depth_spin = QSpinBox()
            self.max_depth_spin.setRange(0, 64)
            self.max_depth_spin.setValue(
                int(self.analyzer_settings.get("visualization", {}).get("max_plan_depth", 0))
            )
            self.max_depth_spin.setToolTip(
                "Показывать узлы только до указанной глубины в дереве плана (корень = 0).\n"
                "0 — без ограничения. Полезно для упрощения больших планов."
            )

            controls_container = QWidget()
            controls_layout = QHBoxLayout(controls_container)
            controls_layout.setContentsMargins(0, 0, 0, 0)
            controls_layout.addWidget(QLabel("Тип визуализации:"))
            controls_layout.addWidget(self.layout_selector)
            controls_layout.addWidget(QLabel("Макс. глубина:"))
            controls_layout.addWidget(self.max_depth_spin)
            controls_layout.addStretch()

            self.html_content = self.generate_visualization(self.graph_data)
            self.browser = QWebEngineView()

            settings = self.browser.settings()
            settings.setAttribute(settings.WebAttribute.JavascriptEnabled, True)
            settings.setAttribute(settings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
            settings.setAttribute(settings.WebAttribute.LocalStorageEnabled, True)
            settings.setAttribute(settings.WebAttribute.AllowWindowActivationFromJavaScript, True)

            if not self.html_content or len(self.html_content.strip()) == 0:
                raise ValueError("Сгенерированный HTML-контент пуст")

            self.browser.page().setBackgroundColor(QColor("#1e1e1e"))

            self.channel = QWebChannel()
            self.bridge = Bridge(self.node_info_callback, self.visible_outline_callback)
            self.channel.registerObject("bridge", self.bridge)
            self.browser.page().setWebChannel(self.channel)

            layout = QVBoxLayout()
            layout.setContentsMargins(5, 5, 5, 5)
            layout.setSpacing(5)
            layout.addWidget(controls_container)
            layout.addWidget(self.browser, 1)

            self.setLayout(layout)

            self.browser.setHtml(self.html_content, QUrl("about:blank"))
            self.browser.loadFinished.connect(self.on_load_finished)

            self.layout_selector.currentIndexChanged.connect(self._reload_visualization)
            self.max_depth_spin.valueChanged.connect(self._reload_visualization)

            if self.most_expensive_node_info:
                self.node_info_callback(self.most_expensive_node_info)

        except Exception as e:
            logging.error(f"Ошибка инициализации UI: {str(e)}")
            self.show_error_message(str(e))

    def show_error_message(self, message):
        self.browser.setHtml(simple_visualizer_error_html(message))

    def _reload_visualization(self):
        layout_type = self.layout_selector.currentData()
        self.current_layout = layout_type
        self.html_content = self.generate_visualization(self.graph_data)
        self.browser.setHtml(self.html_content, QUrl("about:blank"))

    def generate_visualization(self, graph_data):
        try:

            def clean_data(obj):
                if isinstance(obj, dict):
                    return {
                        k: clean_data(v)
                        for k, v in obj.items()
                        if not k.startswith("_") and k not in ["parent", "children"]
                    }
                elif isinstance(obj, list):
                    return [clean_data(item) for item in obj]
                elif isinstance(obj, (int, float, str, bool)) or obj is None:
                    return obj
                else:
                    return str(obj)

            clean_graph = clean_data(graph_data)

            md_limit = (
                self.max_depth_spin.value()
                if hasattr(self, "max_depth_spin")
                else int(self.analyzer_settings.get("visualization", {}).get("max_plan_depth", 0))
            )
            if md_limit > 0:
                nodes_list = clean_graph.get("nodes") or []
                nodes_f = [n for n in nodes_list if int(n.get("depth", 0)) <= md_limit]
                allowed = {str(n["id"]) for n in nodes_f}
                edges_list = clean_graph.get("edges") or []
                edges_f = [
                    e
                    for e in edges_list
                    if str(e.get("from")) in allowed and str(e.get("to")) in allowed
                ]
                clean_graph = {"nodes": nodes_f, "edges": edges_f}

            if not clean_graph.get("nodes"):
                return simple_visualizer_error_html(
                    "Нет узлов для отображения при текущем ограничении глубины. Увеличьте значение «Макс. глубина» или установите 0."
                )

            max_cost = (
                max(node["cost"] for node in clean_graph["nodes"]) if clean_graph["nodes"] else 1
            )
            high_cost_threshold = self.analyzer_settings.get("thresholds", {}).get(
                "high_cost_absolute", 10000
            )
            high_cost_percent = self.analyzer_settings.get("thresholds", {}).get(
                "expensive_operation_percent", 15
            )

            nodes = []
            edges = []

            for node in clean_graph["nodes"]:
                try:
                    node_type = str(node.get("type", "Unknown"))
                    node_cost = float(node.get("cost", 0))
                    is_seq_scan = node_type == "Seq Scan"
                    is_expensive_seq_scan = is_seq_scan and node_cost > self.analyzer_settings.get(
                        "thresholds", {}
                    ).get("seq_scan_warning_cost", 150)
                    is_high_cost = (
                        node_cost > high_cost_threshold
                        or (node_cost / max_cost * 100) > high_cost_percent
                    )

                    is_root_node = node.get("depth", 0) == 0

                    if is_root_node:
                        node_color = "#ADD8E6"
                    elif is_expensive_seq_scan:
                        node_color = self.analyzer_settings.get("colors", {}).get(
                            "seq_scan_node", "#ff9e80"
                        )
                    elif node_type in ["Index Scan", "Index Only Scan"]:
                        node_color = self.analyzer_settings.get("colors", {}).get(
                            "index_scan_node", "#51cf66"
                        )
                    elif is_high_cost:
                        node_color = self.analyzer_settings.get("colors", {}).get(
                            "high_cost_node", "#ff6b6b"
                        )
                    else:
                        node_color = self.get_node_color(
                            node_type, node_cost, max_cost, node.get("is_main_node", False)
                        )

                    if is_root_node:
                        node_label = "Результат\nзапроса"
                        node_width = 120
                        node_height = 60
                    else:
                        node_label = self.generate_node_label(node_type, node.get("properties", {}))
                        node_width = None
                        node_height = None

                    node_size_factor = self.analyzer_settings.get("visualization", {}).get(
                        "node_size_factor", 30
                    )
                    size = (
                        50
                        if is_root_node
                        else (15 + node_size_factor * math.log1p(node_cost) / math.log1p(max_cost))
                    )

                    depth = node.get("depth", 0)
                    x_pos = node.get("pos_y", 0) * 300

                    node_config = {
                        "id": str(node["id"]),
                        "label": node_label,
                        "type": node_type,
                        "properties": {k: str(v) for k, v in node.get("properties", {}).items()},
                        "cost": node_cost,
                        "rows": int(node.get("rows", 0)),
                        "depth": depth,
                        "pos_y": node.get("pos_y", 0),
                        "is_main_node": is_root_node,
                        "color": node_color,
                        "size": size,
                        "x": x_pos,
                        "y": depth * 120,
                        "borderWidth": 2,
                        "font": {
                            "size": 16 if is_root_node else 14,
                            "color": "#ffffff",
                            "bold": True,
                            "multi": True,
                        },
                        "shadow": {
                            "enabled": self.analyzer_settings.get("visualization", {}).get(
                                "enable_animations", True
                            ),
                            "color": "rgba(0,0,0,0.5)",
                            "size": 10,
                            "x": 5,
                            "y": 5,
                        },
                    }

                    if is_root_node:
                        node_config["shape"] = "box"
                        node_config["widthConstraint"] = {
                            "minimum": node_width,
                            "maximum": node_width,
                        }
                        node_config["heightConstraint"] = {
                            "minimum": node_height,
                            "maximum": node_height,
                        }
                        node_config["margin"] = 10
                    else:
                        node_config["shape"] = "circle"

                    props_raw = node.get("properties") or {}
                    if not isinstance(props_raw, dict):
                        props_raw = {}
                    node_config["title"] = self._node_hover_title(
                        node_type,
                        props_raw,
                        node_cost,
                        int(node.get("rows", 0)),
                        is_root_node,
                    )

                    nodes.append(node_config)

                except Exception as e:
                    logging.error(f"Error processing node: {e}")
                    continue

            for edge in clean_graph.get("edges", []):
                try:
                    edges.append(
                        {
                            "from": str(edge.get("from", "")),
                            "to": str(edge.get("to", "")),
                            "arrows": "to",
                            "width": 2,
                            "smooth": {
                                "enabled": True,
                                "type": "dynamic",
                            },
                        }
                    )
                except Exception as e:
                    logging.error(f"Error processing edge: {e}")
                    continue

            node_ids_with_children = {edge["to"] for edge in edges}
            for node in nodes:
                if node["id"] not in node_ids_with_children:
                    if node.get("is_main_node", False):
                        node["shape"] = "box"
                    else:
                        node["shape"] = "square"
                elif node.get("is_main_node", False):
                    node["shape"] = "box"
                else:
                    if node["shape"] != "box":
                        node["shape"] = "circle"

                if (
                    node["shape"] == "square"
                    and node["cost"]
                    > self.analyzer_settings.get("thresholds", {}).get("seq_scan_warning_cost", 150)
                    and not node.get("is_main_node", False)
                ):
                    node["color"] = self.analyzer_settings.get("colors", {}).get(
                        "high_cost_node", "#ff6b6b"
                    )

                if node.get("is_main_node", False):
                    text_color = "#000000"
                elif node["type"] in ["Index Scan", "Index Only Scan"]:
                    text_color = "#ffffff"
                elif node["type"] in ["Materialize", "Memoize", "Limit", "Aggregate"]:
                    text_color = "#000000"
                else:
                    bg_color = node["color"]
                    if bg_color.lower() in ["#ffff00", "#51cf66", "#fcc419"]:
                        text_color = "#000000"
                    else:
                        text_color = "#ffffff"

                node["font"]["color"] = text_color

            selected_layout = VIS_NETWORK_LAYOUT_OPTIONS.get(
                self.current_layout, VIS_NETWORK_LAYOUT_OPTIONS["default"]
            )

            return plan_vis_network_html(nodes, edges, selected_layout)

        except Exception as e:
            logging.error(f"Visualization error: {str(e)}")
            return simple_visualizer_error_html(str(e))

    def get_node_color(self, node_type, cost, max_cost, is_main_node=False):
        if is_main_node:
            return "#00BFFF"

        cost_threshold = 0.10 * max_cost

        if node_type == "Seq Scan":
            if cost > cost_threshold:
                return self.analyzer_settings.get("colors", {}).get("seq_scan_node", "#ff9e80")
            else:
                return "#800080"
        elif node_type in ["Index Scan", "Index Only Scan"]:
            return self.analyzer_settings.get("colors", {}).get("index_scan_node", "#51cf66")
        elif node_type == "Hash Join":
            return "#339af0"
        elif node_type == "Nested Loop":
            return "#fcc419"
        else:
            intensity = int(255 * (cost / max_cost))
            return f"rgb({intensity}, {255 - intensity}, 0)"

    @staticmethod
    def _node_hover_title(node_type, properties, cost, rows, is_root_node):
        """Plain-text tooltip (vis-network `title`) on node hover."""
        if is_root_node:
            return f"Корень плана\n(cost: {cost:.2f}, rows est.: {rows})"
        lines = [node_type]
        rel = properties.get("Relation-Name")
        idx = properties.get("Index-Name")
        alias = properties.get("Alias")
        if rel:
            t = str(rel)
            if alias and str(alias) != t:
                t = f"{t} AS {alias}"
            lines.append(f"relation: {t}")
        elif idx:
            lines.append(f"index: {idx}")
        filt = properties.get("Filter")
        if filt:
            fs = str(filt).replace("\n", " ")
            if len(fs) > 100:
                fs = fs[:97] + "…"
            lines.append(f"filter: {fs}")
        lines.append(f"cost: {cost:.2f}")
        lines.append(f"rows (est.): {rows}")
        return "\n".join(lines)

    def generate_node_label(self, node_type, properties):
        warning_icon = ""
        cost = float(properties.get("Total-Cost", 0))
        if cost > self.analyzer_settings.get("thresholds", {}).get("seq_scan_warning_cost", 150):
            warning_icon = "⚠️ "

        label = warning_icon + node_type

        if "Relation-Name" in properties:
            table_name = properties["Relation-Name"]
            if "Alias" in properties and properties["Alias"] != table_name:
                table_name = f"{table_name} as {properties['Alias']}"
            label += f"\n({table_name})"
        elif "Index-Name" in properties:
            label += f"\n({properties['Index-Name']})"

        if self.analyzer_settings.get("visualization", {}).get("show_cost_on_nodes", True):
            label += f"\nCost: {cost:.2f}"

        if self.analyzer_settings.get("visualization", {}).get("show_rows_on_nodes", False):
            rows = properties.get("Plan-Rows", "N/A")
            label += f"\nRows: {rows}"

        return label

    def on_load_finished(self, ok):
        if not ok:
            logging.error("Не удалось загрузить HTML-контент")
            self.show_error_message("Не удалось загрузить визуализацию")
