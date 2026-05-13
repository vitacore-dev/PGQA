"""Static HTML snippets for Qt WebEngine views (welcome, graphs, plan network)."""

from __future__ import annotations

import json
from typing import Dict, List, Sequence

# vis-network layout fragments (injected into JS `options` alongside node/edge defaults)
VIS_NETWORK_LAYOUT_OPTIONS: Dict[str, Dict] = {
    "default": {
        "physics": {
            "enabled": True,
            "stabilization": {
                "enabled": True,
                "iterations": 1000,
            },
        }
    },
    "hierarchical": {
        "layout": {
            "hierarchical": {
                "enabled": True,
                "direction": "UD",
                "sortMethod": "directed",
                "nodeSpacing": 200,
                "levelSeparation": 200,
                "parentCentralization": True,
            }
        },
        "physics": {
            "enabled": False,
            "hierarchicalRepulsion": {
                "centralGravity": 0.0,
                "springLength": 100,
                "springConstant": 0.01,
                "nodeDistance": 120,
                "damping": 0.09,
            },
        },
    },
}


def welcome_screen_html() -> str:
    """Splash screen shown before a plan is loaded."""
    return """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>PostgreSQL Query Plan Analyzer</title>
            <style>
                body {
                    background:
                        radial-gradient(circle at top, rgba(79, 195, 247, 0.12), transparent 34%),
                        #2D2D2D;
                    color: #E0E0E0;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 28px;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    box-sizing: border-box;
                }

                .welcome {
                    width: 100%;
                    max-width: 1040px;
                    margin: 0 auto;
                    text-align: center;
                }

                .eyebrow {
                    color: #81c784;
                    font-size: 13px;
                    font-weight: 700;
                    letter-spacing: 0.08em;
                    margin-bottom: 8px;
                    text-transform: uppercase;
                }

                h1 {
                    font-size: 36px;
                    line-height: 1.15;
                    margin: 0 0 10px;
                    color: #B3E5FC;
                }

                .lead {
                    color: #cfd8dc;
                    font-size: 16px;
                    line-height: 1.55;
                    max-width: 720px;
                    margin: 0 auto 24px;
                }

                .primary-actions {
                    display: grid;
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                    gap: 16px;
                    margin: 0 auto 16px;
                }

                .cards {
                    display: grid;
                    grid-template-columns: repeat(4, minmax(0, 1fr));
                    gap: 12px;
                    margin: 0 auto 22px;
                }

                .card {
                    display: block;
                    background: rgba(36, 36, 36, 0.92);
                    border: 1px solid #444;
                    border-radius: 14px;
                    padding: 16px;
                    box-shadow: 0 8px 18px rgba(0, 0, 0, 0.18);
                    text-decoration: none;
                    transition: border-color 0.15s ease, transform 0.15s ease, background 0.15s ease;
                    text-align: left;
                }

                .card:hover {
                    background: #2a3034;
                    border-color: #4fc3f7;
                    transform: translateY(-2px);
                }

                .card.primary {
                    min-height: 138px;
                    padding: 22px;
                    border-color: rgba(79, 195, 247, 0.38);
                    background:
                        linear-gradient(135deg, rgba(79, 195, 247, 0.15), rgba(129, 199, 132, 0.07)),
                        #242424;
                }

                .card.secondary {
                    min-height: 126px;
                }

                .card h2 {
                    color: #e3f2fd;
                    font-size: 17px;
                    line-height: 1.25;
                    margin: 0 0 8px;
                }

                .card.primary h2 {
                    font-size: 22px;
                }

                .card p {
                    color: #b0bec5;
                    font-size: 13px;
                    line-height: 1.5;
                    margin: 0;
                }

                .card .action {
                    color: #81d4fa;
                    display: inline-block;
                    font-size: 12px;
                    font-weight: 700;
                    margin-top: 12px;
                }

                .flow {
                    background: #1f2a30;
                    border-left: 4px solid #4fc3f7;
                    border-radius: 8px;
                    color: #d7eef8;
                    font-size: 14px;
                    line-height: 1.6;
                    margin: 0 auto;
                    max-width: 820px;
                    padding: 14px 16px;
                    text-align: left;
                }

                code {
                    color: #fff59d;
                    background: rgba(255, 255, 255, 0.08);
                    border-radius: 4px;
                    padding: 1px 5px;
                }

                @media (max-width: 980px) {
                    .cards {
                        grid-template-columns: repeat(2, minmax(0, 1fr));
                    }
                }

                @media (max-width: 720px) {
                    body {
                        align-items: flex-start;
                        padding: 20px;
                    }

                    .primary-actions,
                    .cards {
                        grid-template-columns: 1fr;
                    }
                }
            </style>
        </head>
        <body>
            <div class="welcome vitacore-logo">
                <div class="eyebrow">PostgreSQL Query Plan Analyzer</div>
                <h1>С чего начнём анализ?</h1>
                <p class="lead">
                    Выберите рабочий сценарий: ввести SQL, открыть готовый план,
                    найти дорогой запрос, проверить гипотезу индекса или сравнить историю.
                </p>

                <div class="primary-actions">
                    <a class="card primary" href="pgqa://plan">
                        <h2>Ввести SQL</h2>
                        <p>Перейдите к рабочему экрану плана, введите запрос и выполните EXPLAIN через активное подключение.</p>
                        <span class="action">К SQL и плану</span>
                    </a>
                    <a class="card primary" href="pgqa://file">
                        <h2>Открыть план</h2>
                        <p>Загрузите готовый EXPLAIN в JSON/XML, если план уже снят вне приложения или пришёл из логов.</p>
                        <span class="action">Выбрать файл</span>
                    </a>
                </div>

                <div class="cards">
                    <a class="card secondary" href="pgqa://active">
                        <h2>Активные запросы</h2>
                        <p>Посмотрите, что выполняется прямо сейчас, найдите ожидания и долгие операции, затем отправьте SQL в разбор.</p>
                        <span class="action">Открыть активные</span>
                    </a>
                    <a class="card secondary" href="pgqa://workload">
                        <h2>Workload</h2>
                        <p>Найдите запросы с наибольшим вкладом по total time, mean time, calls или rows через pg_stat_statements.</p>
                        <span class="action">Открыть статистику</span>
                    </a>
                    <a class="card secondary" href="pgqa://hypopg">
                        <h2>Проверить индекс</h2>
                        <p>После рекомендаций используйте HypoPG в обслуживании БД, чтобы сравнить план до и после гипотетического индекса.</p>
                        <span class="action">Открыть HypoPG</span>
                    </a>
                    <a class="card secondary" href="pgqa://history">
                        <h2>Сравнить планы</h2>
                        <p>Откройте журнал планов, observed snapshots или импорт auto_explain, чтобы увидеть изменения между версиями.</p>
                        <span class="action">Открыть историю</span>
                    </a>
                </div>

                <div class="flow">
                    Основной поток: найти запрос → получить план → понять проблему → проверить оптимизацию → сохранить результат.
                </div>
            </div>
        </body>
        </html>
        """


def empty_performance_graph_html(message: str = "") -> str:
    """Placeholder when the journal performance chart has nothing to show."""
    if not message:
        message = "Выберите группу запросов из списка для отображения графика"

    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    margin: 0;
                    padding: 20px;
                    background-color: #2d2d2d;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }}
                .message {{
                    color: #e0e0e0;
                    text-align: center;
                    max-width: 500px;
                }}
                .message h2 {{
                    color: #4fc3f7;
                    margin-bottom: 15px;
                    font-size: 18px;
                }}
                .message p {{
                    font-size: 13px;
                    line-height: 1.4;
                    color: #b3e5fc;
                }}
                .hint {{
                    font-size: 11px;
                    color: #fcc419;
                    margin-top: 15px;
                    padding: 8px;
                    background-color: #1e1e1e;
                    border-radius: 4px;
                }}
            </style>
        </head>
        <body>
            <div class="message">
                <h2>📊 График производительности</h2>
                <p>{message}</p>
                <div class="hint">
                    💡 Группы запросов создаются автоматически, когда в журнале есть несколько версий одного запроса
                </div>
            </div>
        </body>
        </html>
        """


def animated_status_messages_html(messages: Sequence[str], delays: Sequence[float]) -> str:
    """Short overlay HTML for status lines (e.g. after opening a file)."""
    msg_list = list(messages)
    delay_list = list(delays)
    if len(delay_list) < len(msg_list):
        delay_list = delay_list + [0.5] * (len(msg_list) - len(delay_list))

    html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                @keyframes fade-in {{
                    from {{ opacity: 0; transform: translateY(20px); }}
                    to {{ opacity: 1; transform: translateY(0); }}
                }}
                .message {{
                    opacity: 0;
                    animation: fade-in 1s ease-out {0}s forwards;
                    text-align: center;
                    font-size: 16px;
                    color: #b3e5fc;
                    margin: 10px 0;
                }}
            </style>
        </head>
        <body style="background-color:#2d2d2d;color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;">
            <div style="text-align:center; margin-top:-250px;">
                {1}
            </div>
        </body>
        </html>
        """

    message_html = ""
    for msg, delay in zip(msg_list, delay_list):
        message_html += f'<div class="message" style="animation-delay:{delay}s">{msg}</div>'

    return html_template.format(delay_list[0] if delay_list else 0, message_html)


def simple_visualizer_error_html(message: str) -> str:
    """Minimal error page for the plan graph web view."""
    return f"""
        <html>
        <body style="background-color:#1e1e1e;color:white;">
            <h2>Ошибка визуализации</h2>
            <p>{message}</p>
        </body>
        </html>
        """


def plan_vis_network_html(nodes: List[dict], edges: List[dict], selected_layout: dict) -> str:
    """Full vis-network document with QWebChannel bridge for node clicks."""
    layout_fragment = json.dumps(selected_layout, indent=4).replace('"', "'")[1:-1]

    return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Query Plan Visualizer</title>
                <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
                <script type="text/javascript" src="qrc:///qtwebchannel/qwebchannel.js"></script>
                <style>
                    body, html {{
                        margin: 0;
                        padding: 0;
                        width: 100%;
                        height: 100%;
                        overflow: hidden;
                        background-color: #1e1e1e;
                    }}
                    #viz-root {{
                        position: relative;
                        width: 100%;
                        height: 100vh;
                    }}
                    #network {{
                        width: 100%;
                        height: 100%;
                    }}
                    #viz-fit-btn:hover, #viz-export-btn:hover, #viz-reset-collapse-btn:hover {{
                        background-color: #3d3d3d !important;
                        border-color: #777 !important;
                    }}
                </style>
            </head>
            <body>
                <div id="viz-root">
                    <div id="viz-toolbar" style="position:absolute;top:10px;right:48px;z-index:20;display:flex;gap:8px;align-items:center;">
                        <button type="button" id="viz-fit-btn" title="Вписать весь граф в область просмотра"
                            style="cursor:pointer;padding:8px 12px;background:#2d2d2d;color:#e0e0e0;border:1px solid #555;border-radius:4px;font-size:12px;font-family:'Segoe UI',sans-serif;">
                            Подогнать
                        </button>
                        <button type="button" id="viz-export-btn" title="PNG: сохранить только узлы текущего вида графа (после сворачивания веток и ограничения глубины)"
                            style="cursor:pointer;padding:8px 12px;background:#2d2d2d;color:#e0e0e0;border:1px solid #555;border-radius:4px;font-size:12px;font-family:'Segoe UI',sans-serif;">
                            PNG
                        </button>
                        <button type="button" id="viz-reset-collapse-btn" title="Показать все узлы после сворачивания веток (двойной клик по узлу)"
                            style="cursor:pointer;padding:8px 12px;background:#2d2d2d;color:#e0e0e0;border:1px solid #555;border-radius:4px;font-size:12px;font-family:'Segoe UI',sans-serif;">
                            Все узлы
                        </button>
                    </div>
                    <div id="network"></div>
                </div>
                <script>
                    new QWebChannel(qt.webChannelTransport, function(channel) {{
                        window.bridge = channel.objects.bridge;
                    }});

                    var nodes = new vis.DataSet({json.dumps(nodes, default=str)});
                    var edges = new vis.DataSet({json.dumps(edges, default=str)});

                    var container = document.getElementById('network');
                    var data = {{ nodes: nodes, edges: edges }};
                    var options = {{
                        interaction: {{
                            hover: true,
                            hoverConnectedEdges: true,
                            navigationButtons: true,
                            keyboard: true,
                            tooltipDelay: 120,
                            zoomView: true
                        }},
                        nodes: {{
                            shapeProperties: {{
                                useBorderWithImage: true
                            }},
                            font: {{ size: 14, color: '#ffffff', multi: true }},
                            borderWidth: 2
                        }},
                        edges: {{
                            arrows: 'to',
                            width: 2,
                            smooth: {{
                                enabled: true,
                                type: 'dynamic'
                            }}
                        }},
                        {layout_fragment}
                    }};

                    var network = new vis.Network(container, data, options);

                    document.getElementById('viz-fit-btn').addEventListener('click', function() {{
                        network.fit({{
                            animation: {{
                                duration: 380,
                                easingFunction: 'easeInOutQuad'
                            }}
                        }});
                    }});

                    document.getElementById('viz-export-btn').addEventListener('click', function() {{
                        try {{
                            var canvas = network.canvas.frame.canvas;
                            var url = canvas.toDataURL('image/png');
                            var a = document.createElement('a');
                            a.href = url;
                            a.download = 'query-plan-graph.png';
                            document.body.appendChild(a);
                            a.click();
                            document.body.removeChild(a);
                        }} catch (err) {{
                            console.error('PNG export failed', err);
                            alert('Не удалось сохранить PNG (см. консоль).');
                        }}
                    }});

                    var planNodesAll = nodes.get();
                    var planEdgesAll = edges.get();

                    var childrenByParent = {{}};
                    planEdgesAll.forEach(function(e) {{
                        var p = String(e.to), c = String(e.from);
                        if (!childrenByParent[p]) childrenByParent[p] = [];
                        childrenByParent[p].push(c);
                    }});

                    var collapsedRoots = {{}};

                    function emitVisibleOutline() {{
                        try {{
                            var cur = nodes.get();
                            var ids = cur.map(function(n) {{ return String(n.id); }});
                            var payload = JSON.stringify({{
                                visibleIds: ids,
                                collapsedRootIds: Object.keys(collapsedRoots),
                                visibleCount: ids.length,
                                totalPlanNodes: planNodesAll.length
                            }});
                            if (window.bridge && window.bridge.updateVisibleOutline) {{
                                window.bridge.updateVisibleOutline(payload);
                            }}
                        }} catch (e) {{ console.warn('emitVisibleOutline', e); }}
                    }}

                    function descendantIdsExceptSelf(rootId) {{
                        var hid = [], st = (childrenByParent[rootId] || []).slice(), seen = {{}};
                        while (st.length) {{
                            var x = st.pop();
                            if (seen[x]) continue;
                            seen[x] = true;
                            hid.push(x);
                            var ch = childrenByParent[x];
                            if (ch) {{
                                for (var i = 0; i < ch.length; i++) st.push(ch[i]);
                            }}
                        }}
                        return hid;
                    }}

                    function refreshOriginalColors(ds) {{
                        ds.forEach(function(node) {{
                            if (node.color) node.originalColor = node.color;
                        }});
                    }}

                    function applyCollapseFilter() {{
                        var hidden = {{}};
                        Object.keys(collapsedRoots).forEach(function(rid) {{
                            descendantIdsExceptSelf(rid).forEach(function(x) {{
                                hidden[x] = true;
                            }});
                        }});
                        var visN = planNodesAll.filter(function(n) {{
                            return !hidden[String(n.id)];
                        }});
                        var visE = planEdgesAll.filter(function(e) {{
                            return !hidden[String(e.from)] && !hidden[String(e.to)];
                        }});
                        nodes.clear();
                        edges.clear();
                        nodes.add(visN);
                        edges.add(visE);
                        refreshOriginalColors(nodes);
                        network.fit({{ animation: {{ duration: 320, easingFunction: 'easeInOutQuad' }} }});
                        emitVisibleOutline();
                    }}

                    document.getElementById('viz-reset-collapse-btn').addEventListener('click', function() {{
                        collapsedRoots = {{}};
                        applyCollapseFilter();
                    }});

                    nodes.forEach(function(node) {{
                        node.originalColor = node.color;
                    }});

                    network.on('doubleClick', function(params) {{
                        if (params.nodes.length === 0) return;
                        var nid = String(params.nodes[0]);
                        if (descendantIdsExceptSelf(nid).length === 0) return;
                        if (collapsedRoots[nid]) {{
                            delete collapsedRoots[nid];
                        }} else {{
                            collapsedRoots[nid] = true;
                        }}
                        applyCollapseFilter();
                    }});

                    network.on('click', function(params) {{
                        if (params.nodes.length > 0) {{
                            var nodeId = params.nodes[0];
                            var node = nodes.get(nodeId);
                            if (node && window.bridge) {{
                                var nodeInfo = {{
                                    id: node.id,
                                    label: node.label,
                                    type: node.type,
                                    properties: node.properties,
                                    cost: node.cost,
                                    rows: node.rows
                                }};
                                window.bridge.updateNodeInfo(JSON.stringify(nodeInfo));
                            }}
                        }}
                    }});

                    function highlightNode(nodeId) {{
                        var nodes = network.body.nodes;
                        nodes.forEach(function(node) {{
                            node.setOptions({{ color: node.originalColor }});
                        }});
                        var selectedNode = network.body.nodes[nodeId];
                        if (selectedNode) {{
                            selectedNode.originalColor = selectedNode.options.color;
                            selectedNode.setOptions({{ color: '#FF0000' }});
                        }}
                    }}

                    window.highlightNode = highlightNode;

                    setTimeout(function() {{ emitVisibleOutline(); }}, 80);
                </script>
            </body>
            </html>
            """
