"""SQL plain-text editor dialog with lightweight syntax highlighting."""

import re

from PyQt5.QtGui import QColor, QFont, QTextCharFormat, QSyntaxHighlighter
from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout


class SQLHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.highlightingRules = []

        keywords = [
            "SELECT",
            "FROM",
            "WHERE",
            "AND",
            "OR",
            "NOT",
            "IN",
            "LIKE",
            "IS",
            "NULL",
            "INSERT",
            "INTO",
            "VALUES",
            "UPDATE",
            "DELETE",
            "CREATE",
            "ALTER",
            "DROP",
            "TABLE",
            "INDEX",
            "VIEW",
            "SEQUENCE",
            "TRIGGER",
            "FUNCTION",
            "PROCEDURE",
            "EXPLAIN",
            "ANALYZE",
            "WITH",
            "AS",
            "JOIN",
            "LEFT",
            "RIGHT",
            "INNER",
            "OUTER",
            "GROUP BY",
            "ORDER BY",
            "HAVING",
            "LIMIT",
            "OFFSET",
            "UNION",
            "ALL",
            "DISTINCT",
            "EXISTS",
            "BETWEEN",
            "CASE",
            "WHEN",
            "THEN",
            "ELSE",
            "END",
        ]

        keywordFormat = QTextCharFormat()
        keywordFormat.setForeground(QColor("#569CD6"))
        keywordFormat.setFontWeight(QFont.Bold)

        for keyword in keywords:
            pattern = r"\b{}\b".format(keyword)
            self.highlightingRules.append((re.compile(pattern, re.IGNORECASE), keywordFormat))

        stringFormat = QTextCharFormat()
        stringFormat.setForeground(QColor("#CE9178"))
        self.highlightingRules.append((re.compile(r"'.*?'"), stringFormat))
        self.highlightingRules.append((re.compile(r'".*?"'), stringFormat))

        numberFormat = QTextCharFormat()
        numberFormat.setForeground(QColor("#B5CEA8"))
        self.highlightingRules.append((re.compile(r"\b\d+\b"), numberFormat))

        commentFormat = QTextCharFormat()
        commentFormat.setForeground(QColor("#6A9955"))
        self.highlightingRules.append((re.compile(r"--[^\n]*"), commentFormat))
        self.highlightingRules.append((re.compile(r"/\*.*?\*/", re.DOTALL), commentFormat))

        operatorFormat = QTextCharFormat()
        operatorFormat.setForeground(QColor("#D4D4D4"))
        self.highlightingRules.append((re.compile(r"[=<>+\-*/%]"), operatorFormat))

    def highlightBlock(self, text):
        for pattern, format in self.highlightingRules:
            for match in pattern.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, format)


class SQLEditorDialog(QDialog):
    def __init__(self, parent=None, sql_text=""):
        super().__init__(parent)
        self.setWindowTitle("Редактор SQL запроса")
        self.setMinimumSize(1024, 768)

        layout = QVBoxLayout()

        self.editor = QPlainTextEdit()
        self.editor.setPlainText(sql_text)
        self.editor.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                selection-background-color: #264F78;
            }
        """)

        self.highlighter = SQLHighlighter(self.editor.document())

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        layout.addWidget(self.editor)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def get_sql_text(self):
        return self.editor.toPlainText()
