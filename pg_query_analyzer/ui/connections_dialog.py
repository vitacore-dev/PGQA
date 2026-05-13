"""Dialogs for listing and editing PostgreSQL connection profiles."""

from functools import partial

import psycopg2
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QLineEdit,
)

from pg_query_analyzer.db.ssh_tunnel import open_ssh_tunnel_if_needed
from pg_query_analyzer.storage.connections import ConnectionSettings


class ConnectionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Управление подключениями")
        self.setMinimumSize(750, 500)
        self.setModal(True)

        self.setup_ui()
        self.load_connections()
        self.apply_styles()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["Имя", "Хост", "Порт", "База данных", "Пользователь", ""]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(True)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        header.resizeSection(5, 60)

        layout.addWidget(self.table)

        button_panel = QWidget()
        button_layout = QHBoxLayout(button_panel)
        button_layout.setContentsMargins(0, 8, 0, 0)
        button_layout.setSpacing(8)

        add_button = QPushButton("Добавить")
        add_button.clicked.connect(self.show_add_new_connection_dialog)

        edit_button = QPushButton("Редактировать")
        edit_button.clicked.connect(self.edit_existing_connection)

        delete_button = QPushButton("Удалить")
        delete_button.clicked.connect(self.delete_connection)

        test_button = QPushButton("Проверить")
        test_button.clicked.connect(self.test_connection)

        button_layout.addWidget(add_button)
        button_layout.addWidget(edit_button)
        button_layout.addWidget(delete_button)
        button_layout.addWidget(test_button)
        button_layout.addStretch()

        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(self.reject)
        button_layout.addWidget(close_button)

        layout.addWidget(button_panel)

        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)

    def apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #2d2d2d;
            }
            QTableWidget {
                background-color: #2d2d2d;
                color: #c0c0c0;
                border: 1px solid #3a3a3a;
                gridline-color: #3a3a3a;
                font-size: 12px;
                selection-background-color: #3a3a3a;
            }
            QTableWidget::item:selected {
                background-color: #3a3a3a;
                color: #ffffff;
            }
            QTableWidget::item:hover {
                background-color: #353535;
            }
            QHeaderView::section {
                background-color: #252525;
                color: #a0a0a0;
                padding: 6px;
                border: none;
                border-bottom: 1px solid #3a3a3a;
                font-weight: normal;
                font-size: 11px;
            }
            QPushButton {
                background-color: #353535;
                color: #c0c0c0;
                border: 1px solid #4a4a4a;
                border-radius: 3px;
                padding: 5px 12px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #404040;
                border-color: #5a5a5a;
                color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
            }
        """)

    def load_connections(self):
        connections = ConnectionSettings.load_connections()
        self.table.setRowCount(len(connections))

        for idx, (name, conn) in enumerate(connections.items()):
            self.table.setItem(idx, 0, QTableWidgetItem(name))
            self.table.setItem(idx, 1, QTableWidgetItem(conn["host"]))
            self.table.setItem(idx, 2, QTableWidgetItem(conn["port"]))
            self.table.setItem(idx, 3, QTableWidgetItem(conn["dbname"]))
            self.table.setItem(idx, 4, QTableWidgetItem(conn["user"]))

            edit_btn = QPushButton("...")
            edit_btn.setToolTip("Редактировать")
            edit_btn.setFixedSize(25, 22)
            edit_btn.clicked.connect(partial(self.edit_existing_connection, idx))
            edit_btn.setStyleSheet("""
                QPushButton {
                    background-color: #353535;
                    border: 1px solid #4a4a4a;
                    border-radius: 3px;
                    font-size: 10px;
                    padding: 2px;
                }
                QPushButton:hover {
                    background-color: #404040;
                }
            """)

            container = QWidget()
            container_layout = QHBoxLayout(container)
            container_layout.setContentsMargins(0, 0, 0, 0)
            container_layout.addWidget(edit_btn)
            container_layout.setAlignment(Qt.AlignCenter)
            self.table.setCellWidget(idx, 5, container)

    def show_add_new_connection_dialog(self):
        dialog = AddNewConnectionDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            conn_data = dialog.get_connection_data()
            if conn_data and conn_data.get("name"):
                ConnectionSettings.upsert_connection(conn_data)
                self.load_connections()
                QMessageBox.information(
                    self, "Успех", f"Подключение '{conn_data['name']}' добавлено"
                )

    def edit_existing_connection(self, idx):
        if isinstance(idx, int):
            name = self.table.item(idx, 0).text()
            conn = ConnectionSettings.load_connections()[name]

            dialog = EditConnectionDialog(
                self,
                name,
                conn["host"],
                conn["port"],
                conn["dbname"],
                conn["user"],
                conn["password"],
                conn.get("ssh"),
            )
            if dialog.exec_() == QDialog.Accepted:
                conn_data = dialog.get_connection_data()
                if conn_data and conn_data.get("name"):
                    if conn_data["name"] != name:
                        ConnectionSettings.remove_connection(name)
                    ConnectionSettings.upsert_connection(conn_data)
                    self.load_connections()
                    QMessageBox.information(
                        self, "Успех", f"Подключение '{conn_data['name']}' обновлено"
                    )

    def delete_connection(self):
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            QMessageBox.warning(self, "Внимание", "Выберите подключение для удаления")
            return

        index = indexes[0].row()
        name = self.table.item(index, 0).text()

        reply = QMessageBox.question(
            self,
            "Подтверждение",
            f"Удалить подключение '{name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            ConnectionSettings.remove_connection(name)
            self.load_connections()
            QMessageBox.information(self, "Успех", "Подключение удалено")

    def test_connection(self):
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            QMessageBox.warning(self, "Внимание", "Выберите подключение для проверки")
            return

        index = indexes[0].row()
        name = self.table.item(index, 0).text()
        conn = ConnectionSettings.load_connections()[name]

        try:
            with open_ssh_tunnel_if_needed(conn) as tunnel:
                conn_for_test = dict(conn)
                if tunnel:
                    conn_for_test["host"] = "127.0.0.1"
                    conn_for_test["port"] = str(tunnel.local_bind_port)
                test_conn = psycopg2.connect(**ConnectionSettings.connect_kwargs(conn_for_test))
                test_conn.close()
            QMessageBox.information(self, "Успех", "Подключение установлено")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось подключиться:\n{str(e)}")

    def on_item_double_clicked(self, item):
        row = item.row()
        name = self.table.item(row, 0).text()
        conn = ConnectionSettings.load_connections()[name]
        self.selected_connection = conn
        self.accept()


class AddNewConnectionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Новое подключение")
        self.setMinimumWidth(450)
        self.setModal(True)

        self.setup_ui()
        self.apply_styles()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(15, 15, 15, 15)

        form_widget = QWidget()
        form_layout = QFormLayout(form_widget)
        form_layout.setSpacing(10)
        form_layout.setLabelAlignment(Qt.AlignRight)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("production_db")

        self.host_edit = QLineEdit("localhost")

        self.port_edit = QLineEdit("5432")

        self.dbname_edit = QLineEdit()
        self.dbname_edit.setPlaceholderText("postgres")

        self.user_edit = QLineEdit()

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)

        self.ssh_enabled_check = QCheckBox("Подключаться через SSH-туннель")
        self.ssh_host_edit = QLineEdit()
        self.ssh_host_edit.setPlaceholderText("ssh.example.com")
        self.ssh_port_edit = QLineEdit("22")
        self.ssh_user_edit = QLineEdit()
        self.ssh_password_edit = QLineEdit()
        self.ssh_password_edit.setEchoMode(QLineEdit.Password)
        self.ssh_key_path_edit = QLineEdit()
        self.ssh_key_path_edit.setPlaceholderText("~/.ssh/id_rsa")
        self.ssh_key_path_button = QPushButton("...")
        self.ssh_key_path_button.setFixedWidth(30)
        self.ssh_key_path_button.clicked.connect(self.browse_ssh_key)
        ssh_key_row = QWidget()
        ssh_key_layout = QHBoxLayout(ssh_key_row)
        ssh_key_layout.setContentsMargins(0, 0, 0, 0)
        ssh_key_layout.addWidget(self.ssh_key_path_edit)
        ssh_key_layout.addWidget(self.ssh_key_path_button)

        self.ssh_enabled_check.stateChanged.connect(self._toggle_ssh_fields)

        form_layout.addRow("Имя:", self.name_edit)
        form_layout.addRow("Хост:", self.host_edit)
        form_layout.addRow("Порт:", self.port_edit)
        form_layout.addRow("База:", self.dbname_edit)
        form_layout.addRow("Пользователь:", self.user_edit)
        form_layout.addRow("Пароль:", self.password_edit)
        form_layout.addRow("", self.ssh_enabled_check)
        form_layout.addRow("SSH хост:", self.ssh_host_edit)
        form_layout.addRow("SSH порт:", self.ssh_port_edit)
        form_layout.addRow("SSH пользователь:", self.ssh_user_edit)
        form_layout.addRow("SSH пароль:", self.ssh_password_edit)
        form_layout.addRow("SSH ключ:", ssh_key_row)

        layout.addWidget(form_widget)

        button_box = QDialogButtonBox()
        button_box.setStandardButtons(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        layout.addWidget(button_box)
        self._toggle_ssh_fields()

    def _toggle_ssh_fields(self):
        enabled = self.ssh_enabled_check.isChecked()
        for widget in (
            self.ssh_host_edit,
            self.ssh_port_edit,
            self.ssh_user_edit,
            self.ssh_password_edit,
            self.ssh_key_path_edit,
            self.ssh_key_path_button,
        ):
            widget.setEnabled(enabled)

    def browse_ssh_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите SSH ключ")
        if path:
            self.ssh_key_path_edit.setText(path)

    def apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #2d2d2d;
            }
            QLabel {
                color: #a0a0a0;
                font-size: 11px;
            }
            QLineEdit {
                background-color: #252525;
                color: #c0c0c0;
                border: 1px solid #3a3a3a;
                border-radius: 3px;
                padding: 5px;
                font-size: 11px;
            }
            QLineEdit:focus {
                border-color: #5a5a5a;
            }
            QLineEdit::placeholder {
                color: #606060;
            }
            QPushButton {
                background-color: #353535;
                color: #c0c0c0;
                border: 1px solid #4a4a4a;
                border-radius: 3px;
                padding: 5px 15px;
                font-size: 11px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #404040;
                border-color: #5a5a5a;
                color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
            }
        """)

    def get_connection_data(self):
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Ошибка", "Введите имя подключения")
            return None

        host = self.host_edit.text().strip() or "localhost"
        port = self.port_edit.text().strip() or "5432"
        dbname = self.dbname_edit.text().strip() or "postgres"
        user = self.user_edit.text().strip()

        if not user:
            QMessageBox.warning(self, "Ошибка", "Введите имя пользователя")
            return None
        if self.ssh_enabled_check.isChecked():
            if not self.ssh_host_edit.text().strip():
                QMessageBox.warning(self, "Ошибка", "Введите SSH хост")
                return None
            if not self.ssh_user_edit.text().strip():
                QMessageBox.warning(self, "Ошибка", "Введите SSH пользователя")
                return None

        return {
            "name": name,
            "host": host,
            "port": port,
            "dbname": dbname,
            "user": user,
            "password": self.password_edit.text(),
            "ssh": {
                "enabled": self.ssh_enabled_check.isChecked(),
                "host": self.ssh_host_edit.text().strip(),
                "port": self.ssh_port_edit.text().strip() or "22",
                "user": self.ssh_user_edit.text().strip(),
                "password": self.ssh_password_edit.text(),
                "private_key_path": self.ssh_key_path_edit.text().strip(),
            },
        }


class EditConnectionDialog(QDialog):
    def __init__(
        self,
        parent=None,
        name="",
        host="",
        port="",
        dbname="",
        user="",
        password="",
        ssh=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Редактирование")
        self.setMinimumWidth(450)
        self.setModal(True)

        self.original_name = name

        self.setup_ui(name, host, port, dbname, user, password, ssh or {})
        self.apply_styles()

    def setup_ui(self, name, host, port, dbname, user, password, ssh):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(15, 15, 15, 15)

        form_widget = QWidget()
        form_layout = QFormLayout(form_widget)
        form_layout.setSpacing(10)
        form_layout.setLabelAlignment(Qt.AlignRight)

        self.name_edit = QLineEdit(name)
        self.name_edit.setPlaceholderText("production_db")

        self.host_edit = QLineEdit(host)

        self.port_edit = QLineEdit(port)

        self.dbname_edit = QLineEdit(dbname)

        self.user_edit = QLineEdit(user)

        self.password_edit = QLineEdit(password)
        self.password_edit.setEchoMode(QLineEdit.Password)

        self.ssh_enabled_check = QCheckBox("Подключаться через SSH-туннель")
        self.ssh_enabled_check.setChecked(bool(ssh.get("enabled")))
        self.ssh_host_edit = QLineEdit(ssh.get("host", ""))
        self.ssh_port_edit = QLineEdit(ssh.get("port", "22"))
        self.ssh_user_edit = QLineEdit(ssh.get("user", ""))
        self.ssh_password_edit = QLineEdit(ssh.get("password", ""))
        self.ssh_password_edit.setEchoMode(QLineEdit.Password)
        self.ssh_key_path_edit = QLineEdit(ssh.get("private_key_path", ""))
        self.ssh_key_path_button = QPushButton("...")
        self.ssh_key_path_button.setFixedWidth(30)
        self.ssh_key_path_button.clicked.connect(self.browse_ssh_key)
        ssh_key_row = QWidget()
        ssh_key_layout = QHBoxLayout(ssh_key_row)
        ssh_key_layout.setContentsMargins(0, 0, 0, 0)
        ssh_key_layout.addWidget(self.ssh_key_path_edit)
        ssh_key_layout.addWidget(self.ssh_key_path_button)
        self.ssh_enabled_check.stateChanged.connect(self._toggle_ssh_fields)

        form_layout.addRow("Имя:", self.name_edit)
        form_layout.addRow("Хост:", self.host_edit)
        form_layout.addRow("Порт:", self.port_edit)
        form_layout.addRow("База:", self.dbname_edit)
        form_layout.addRow("Пользователь:", self.user_edit)
        form_layout.addRow("Пароль:", self.password_edit)
        form_layout.addRow("", self.ssh_enabled_check)
        form_layout.addRow("SSH хост:", self.ssh_host_edit)
        form_layout.addRow("SSH порт:", self.ssh_port_edit)
        form_layout.addRow("SSH пользователь:", self.ssh_user_edit)
        form_layout.addRow("SSH пароль:", self.ssh_password_edit)
        form_layout.addRow("SSH ключ:", ssh_key_row)

        layout.addWidget(form_widget)

        button_box = QDialogButtonBox()
        button_box.setStandardButtons(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        layout.addWidget(button_box)
        self._toggle_ssh_fields()

    def _toggle_ssh_fields(self):
        enabled = self.ssh_enabled_check.isChecked()
        for widget in (
            self.ssh_host_edit,
            self.ssh_port_edit,
            self.ssh_user_edit,
            self.ssh_password_edit,
            self.ssh_key_path_edit,
            self.ssh_key_path_button,
        ):
            widget.setEnabled(enabled)

    def browse_ssh_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите SSH ключ")
        if path:
            self.ssh_key_path_edit.setText(path)

    def apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #2d2d2d;
            }
            QLabel {
                color: #a0a0a0;
                font-size: 11px;
            }
            QLineEdit {
                background-color: #252525;
                color: #c0c0c0;
                border: 1px solid #3a3a3a;
                border-radius: 3px;
                padding: 5px;
                font-size: 11px;
            }
            QLineEdit:focus {
                border-color: #5a5a5a;
            }
            QLineEdit::placeholder {
                color: #606060;
            }
            QPushButton {
                background-color: #353535;
                color: #c0c0c0;
                border: 1px solid #4a4a4a;
                border-radius: 3px;
                padding: 5px 15px;
                font-size: 11px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #404040;
                border-color: #5a5a5a;
                color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
            }
        """)

    def get_connection_data(self):
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Ошибка", "Введите имя подключения")
            return None

        host = self.host_edit.text().strip() or "localhost"
        port = self.port_edit.text().strip() or "5432"
        dbname = self.dbname_edit.text().strip() or "postgres"
        user = self.user_edit.text().strip()

        if not user:
            QMessageBox.warning(self, "Ошибка", "Введите имя пользователя")
            return None
        if self.ssh_enabled_check.isChecked():
            if not self.ssh_host_edit.text().strip():
                QMessageBox.warning(self, "Ошибка", "Введите SSH хост")
                return None
            if not self.ssh_user_edit.text().strip():
                QMessageBox.warning(self, "Ошибка", "Введите SSH пользователя")
                return None

        return {
            "name": name,
            "host": host,
            "port": port,
            "dbname": dbname,
            "user": user,
            "password": self.password_edit.text(),
            "ssh": {
                "enabled": self.ssh_enabled_check.isChecked(),
                "host": self.ssh_host_edit.text().strip(),
                "port": self.ssh_port_edit.text().strip() or "22",
                "user": self.ssh_user_edit.text().strip(),
                "password": self.ssh_password_edit.text(),
                "private_key_path": self.ssh_key_path_edit.text().strip(),
            },
        }
