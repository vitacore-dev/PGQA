"""Application bootstrap: QApplication, theme, main window."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from typing import Optional

from PyQt5.QtGui import QColor
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication

from pg_query_analyzer.ui.main_window import QueryPlanVisualizer


def _configure_qt_webengine_disk_paths() -> None:
    """Ставит профиль WebEngine в каталог по PID, чтобы реже ловить SQLITE_BUSY у cookie DB.

    Сообщения вида ``Cookie sqlite error 5: database is locked`` идут из Chromium; отдельная
    папка на процесс не гарантирует исчезновение, но уменьшает конфликты между экземплярами приложения.
    """

    try:
        from PyQt5.QtWebEngineWidgets import QWebEngineProfile
    except Exception:
        return
    base = os.path.join(tempfile.gettempdir(), f"pg_query_analyzer_qtwebengine_{os.getpid()}")
    try:
        os.makedirs(base, mode=0o700, exist_ok=True)
        profile = QWebEngineProfile.defaultProfile()
        profile.setPersistentStoragePath(os.path.join(base, "persistent"))
        profile.setCachePath(os.path.join(base, "cache"))
    except Exception as e:
        logging.getLogger(__name__).debug("Qt WebEngine disk paths not configured: %s", e)


def run_gui(argv: Optional[list[str]] = None) -> int:
    """Create the Qt application, apply the dark Fusion theme, show the main window, and run the event loop."""
    os.environ["QT_QUICK_BACKEND"] = "software"
    args = argv if argv is not None else sys.argv
    app = QApplication(args)
    app.setStyle("Fusion")

    dark_palette = app.palette()
    dark_palette.setColor(dark_palette.Window, QColor(53, 53, 53))
    dark_palette.setColor(dark_palette.WindowText, QColor(255, 255, 255))
    dark_palette.setColor(dark_palette.Base, QColor(25, 25, 25))
    dark_palette.setColor(dark_palette.AlternateBase, QColor(53, 53, 53))
    dark_palette.setColor(dark_palette.ToolTipBase, QColor(245, 248, 250))
    dark_palette.setColor(dark_palette.ToolTipText, QColor(33, 33, 33))
    dark_palette.setColor(dark_palette.Text, QColor(255, 255, 255))
    dark_palette.setColor(dark_palette.Button, QColor(53, 53, 53))
    dark_palette.setColor(dark_palette.ButtonText, QColor(255, 255, 255))
    dark_palette.setColor(dark_palette.BrightText, QColor(255, 0, 0))
    dark_palette.setColor(dark_palette.Link, QColor(42, 130, 218))
    dark_palette.setColor(dark_palette.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(dark_palette.HighlightedText, QColor(0, 0, 0))
    app.setPalette(dark_palette)

    app.setStyleSheet(
        """
        QTextBrowser, QPlainTextEdit {
            background-color: #2d2d2d;
            color: #e0e0e0;
            border: none;
        }
        QTabWidget::pane {
            background-color: #2d2d2d;
            border: 1px solid #444;
        }
        QTabBar::tab {
            background-color: #3a3a3a;
            color: #e0e0e0;
            padding: 5px 10px;
            border: 1px solid #444;
            border-bottom: none;
        }
        QTabBar::tab:selected {
            background-color: #4a8be5;
        }
        QTabBar::tab:hover {
            background-color: #555;
        }
        QToolTip {
            background-color: #eceff1;
            color: #212121;
            border: 1px solid #78909c;
            padding: 8px 10px;
            font-size: 12px;
        }
    """
    )

    _configure_qt_webengine_disk_paths()

    window = QueryPlanVisualizer()
    window.show()
    QTimer.singleShot(0, window.fit_to_available_screen_after_show)
    return app.exec_()
