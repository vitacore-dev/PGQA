"""Custom text widgets for formatted analysis output (Qt rich text)."""

from PyQt5.QtGui import QColor, QTextCharFormat
from PyQt5.QtWidgets import QTextBrowser


class ClickableTextBrowser(QTextBrowser):
    """QTextBrowser that delegates node:// links to parent's highlight_node_in_graph."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(False)
        self.anchorClicked.connect(self.handle_link_click)

    def handle_link_click(self, url):
        if url.scheme() == "node":
            node_id = url.path()
            if hasattr(self.parent(), "highlight_node_in_graph"):
                self.parent().highlight_node_in_graph(node_id)

    def setSource(self, url):
        if url.scheme() == "node":
            return
        super().setSource(url)


class TextFormatter:
    STYLE_MARKERS = {
        "title": ("[title]", "[/title]"),
        "section": ("[section]", "[/section]"),
        "warning": ("[warning]", "[/warning]"),
        "error": ("[error]", "[/error]"),
        "recommendation": ("[rec]", "[/rec]"),
        "highlight": ("[hl]", "[/hl]"),
        "seqscan": ("[seqscan]", "[/seqscan]"),
        "table": ("[table]", "[/table]"),
        "bold": ("[b]", "[/b]"),
        "italic": ("[i]", "[/i]"),
        "underline": ("[u]", "[/u]"),
        "color": ("[color=", "[/color]"),
        "font": ("[font=", "[/font]"),
        "size": ("[size=", "[/size]"),
        "link": ("[link=", "[/link]"),
    }

    @classmethod
    def get_formats(cls):
        formats = {
            "title": cls.create_format("#ffffff", 14, 75),
            "section": cls.create_format("#4fc3f7", 12, 75),
            "warning": cls.create_format("#ff8a65", 12, 75),
            "error": cls.create_format("#ff6b6b", 12, 75),
            "recommendation": cls.create_format("#b3e5fc", 10),
            "highlight": cls.create_format("#ffff00", 10),
            "seqscan": cls.create_format("#ff9e80", 10),
            "table": cls.create_format("#81c784", 8, 75),
            "default": cls.create_format("#e0e0e0", 10),
            "link": cls.create_format("#4fc3f7", 10),
        }
        formats["link"].setAnchor(True)
        formats["link"].setAnchorHref("")
        formats["link"].setForeground(QColor("#4fc3f7"))
        formats["link"].setFontUnderline(True)
        return formats

    @staticmethod
    def create_format(foreground_color, font_size, font_weight=50):
        format = QTextCharFormat()
        format.setForeground(QColor(foreground_color))
        format.setFontPointSize(font_size)
        format.setFontWeight(font_weight)
        return format

    @classmethod
    def apply_formatting(cls, text_edit, text):
        cursor = text_edit.textCursor()
        formats = cls.get_formats()
        default_format = formats["default"]

        text_edit.clear()

        buffer = []
        current_format = default_format

        i = 0
        n = len(text)

        while i < n:
            applied = False
            for style, (open_tag, close_tag) in cls.STYLE_MARKERS.items():
                if text.startswith(open_tag, i):
                    if style in ["color", "font", "size", "link"]:
                        param_end = text.find("]", i)
                        if param_end == -1:
                            break
                        param = text[i + len(open_tag) : param_end]
                        i = param_end + 1

                        if style == "color":
                            current_format = cls.create_format(param, 12)
                        elif style == "font":
                            current_format = QTextCharFormat()
                            current_format.setFontFamily(param)
                        elif style == "size":
                            current_format = QTextCharFormat()
                            current_format.setFontPointSize(float(param))
                        elif style == "link":
                            current_format = formats["link"]
                            current_format.setAnchorHref(param)
                    else:
                        i += len(open_tag)

                        if style in formats:
                            current_format = formats[style]
                        elif style == "bold":
                            current_format = QTextCharFormat()
                            current_format.setFontWeight(75)
                        elif style == "italic":
                            current_format = QTextCharFormat()
                            current_format.setFontItalic(True)
                        elif style == "underline":
                            current_format = QTextCharFormat()
                            current_format.setFontUnderline(True)

                    applied = True
                    break

                if text.startswith(close_tag, i):
                    i += len(close_tag)
                    current_format = default_format
                    applied = True
                    break

            if not applied:
                buffer.append((text[i], current_format))
                i += 1

        for char, fmt in buffer:
            cursor.insertText(char, fmt)

        cursor.setPosition(0)
        text_edit.setTextCursor(cursor)
