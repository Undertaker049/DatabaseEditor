import os
import re
import pyodbc
import configparser
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, simpledialog

class LoginDialog(tk.Toplevel):

    def __init__(self, parent, last_server):
        super().__init__(parent)
        self.title("Подключение к серверу")
        self.geometry("300x200")
        self.result = None

        ttk.Label(self, text="Сервер:").grid(row=0, column=0, padx=5, pady=5)
        self.server_entry = ttk.Entry(self)
        self.server_entry.insert(0, last_server)
        self.server_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self, text="Логин:").grid(row=1, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(self)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self, text="Пароль:").grid(row=2, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        self.use_windows_auth = tk.BooleanVar()
        ttk.Checkbutton(self, text="Использовать проверку подлинности Windows", variable=self.use_windows_auth).grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        ttk.Button(self, text="Подключиться", command=self.on_login).grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def on_login(self):
        self.result = {
            "server": self.server_entry.get(),
            "username": self.username_entry.get(),
            "password": self.password_entry.get(),
            "use_windows_auth": self.use_windows_auth.get()
        }

        self.destroy()

class ColumnEditorDialog(tk.Toplevel):
    sql_server_data_types = [
        "CHAR", "VARCHAR", "TEXT", "NCHAR", "NVARCHAR", "NTEXT",
        "BIT", "TINYINT", "SMALLINT", "INT", "BIGINT",
        "DECIMAL", "NUMERIC", "FLOAT", "REAL",
        "DATETIME", "SMALLDATETIME", "DATE", "TIME",
        "BINARY", "VARBINARY", "IMAGE",
        "MONEY", "SMALLMONEY",
        "UNIQUEIDENTIFIER"
    ]

    def __init__(self, parent, columns, data_types, primary_key):
        super().__init__(parent)
        self.title("Редактировать столбцы")
        self.geometry("800x400")
        self.columns = columns
        self.data_types = data_types
        self.primary_key = primary_key
        self.result = None
        self.edit_widget = None

        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frame, columns=("name", "type", "length"), show="headings")
        self.tree.heading("name", text="Название столбца")
        self.tree.heading("type", text="Тип данных")
        self.tree.heading("length", text="Длина/Точность")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.tag_configure('primary_key', background='yellow')

        if not self.columns:
            item = self.tree.insert("", "end", values=("ID", "INT", ""))
            self.primary_key = "ID"
            self.tree.item(item, tags=('primary_key',))

        else:

            for col, dtype in zip(self.columns, self.data_types):
                type_info = self.parse_data_type(dtype)
                item = self.tree.insert("", "end", values=(col, type_info['base_type'], type_info['length']))

                if col == self.primary_key:
                    self.tree.item(item, tags=('primary_key',))

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-1>", self.on_click)
        self.tree.bind("<Button-3>", self.show_context_menu)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Принять", command=self.on_accept).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=self.on_cancel).pack(side=tk.LEFT, padx=5)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Добавить столбец", command=self.add_column)
        self.context_menu.add_command(label="Удалить столбец", command=self.delete_column)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Назначить как первичный ключ", command=self.set_primary_key)

    def set_primary_key(self):
        selected_items = self.tree.selection()

        if not selected_items:
            messagebox.showwarning("Предупреждение", "Выберите столбец для установки первичного ключа")
            return

        new_primary_key = self.tree.item(selected_items[0])['values'][0]

        for item in self.tree.get_children():
            self.tree.item(item, tags=())

        self.tree.item(selected_items[0], tags=('primary_key',))
        self.primary_key = new_primary_key

    def parse_data_type(self, data_type):
        match = re.match(r'(\w+)(?:\((\d+)(?:,(\d+))?\))?', data_type)

        if match:
            base_type = match.group(1)
            length = match.group(2)
            scale = match.group(3)

            if scale:
                length = f"{length},{scale}"

            return {'base_type': base_type, 'length': length or ''}

        return {'base_type': data_type, 'length': ''}

    def on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)

        if not item:
            self.add_column()
            return

        if column == '#1':
            self.edit_column_name(item)

        elif column == '#2':
            self.edit_data_type(item, event)

        elif column == '#3':
            self.edit_length(item, event)

    def on_click(self, event):
        
        if self.edit_widget:
            self.save_edit()

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)

        if item:
            self.tree.selection_set(item)

        self.context_menu.post(event.x_root, event.y_root)

    def add_column(self):
        new_column_name = simpledialog.askstring("Добавить столбец", "Введите название нового столбца:")
        if new_column_name:
            self.tree.insert("", "end", values=(new_column_name, "VARCHAR", "255"))

    def delete_column(self):
        selected_item = self.tree.selection()

        if selected_item:
            column_name = self.tree.item(selected_item)['values'][0]

            if column_name == self.primary_key:
                messagebox.showwarning("Предупреждение", "Нельзя удалить столбец первичного ключа")
                return

            self.tree.delete(selected_item)

        else:
            messagebox.showwarning("Предупреждение", "Выберите столбец для удаления")

    def edit_column_name(self, item):
        current_value = self.tree.item(item, 'values')[0]
        new_value = simpledialog.askstring("Изменить название", "Введите новое название столбца:", initialvalue=current_value)

        if new_value:
            values = list(self.tree.item(item, 'values'))
            values[0] = new_value

            if current_value == self.primary_key:
                self.primary_key = new_value

            self.tree.item(item, values=values)

    def edit_data_type(self, item, event):
        column = self.tree.identify_column(event.x)
        x, y, width, _ = self.tree.bbox(item, column)
        current_value = self.tree.item(item, 'values')[1]

        self.edit_widget = ttk.Combobox(self.tree, values=self.sql_server_data_types, state="readonly")
        self.edit_widget.set(current_value)
        self.edit_widget.select_range(0, tk.END)
        self.edit_widget.focus()
        self.edit_widget.bind("<Return>", self.save_edit)
        self.edit_widget.bind("<FocusOut>", self.save_edit)
        self.edit_widget.place(x=x, y=y, width=width)

    def edit_length(self, item, event):
        column = self.tree.identify_column(event.x)
        x, y, width, _ = self.tree.bbox(item, column)
        current_value = self.tree.item(item, 'values')[2]

        self.edit_widget = ttk.Entry(self.tree)
        self.edit_widget.insert(0, current_value)
        self.edit_widget.select_range(0, tk.END)
        self.edit_widget.focus()
        self.edit_widget.bind("<Return>", self.save_edit)
        self.edit_widget.bind("<FocusOut>", self.save_edit)
        self.edit_widget.place(x=x, y=y, width=width)

    def save_edit(self, event=None):

        if self.edit_widget:
            item = self.tree.selection()[0]
            new_value = self.edit_widget.get()
            values = list(self.tree.item(item, 'values'))

            if isinstance(self.edit_widget, ttk.Combobox):
                values[1] = new_value

                if new_value not in ('DATE', 'TIME', 'DATETIME', 'SMALLDATETIME', 'TEXT', 'NTEXT', 'IMAGE'):
                    values[2] = ''
            else:
                values[2] = new_value

            self.tree.item(item, values=values)
            self.edit_widget.destroy()
            self.edit_widget = None

    def on_accept(self):
        self.result = []

        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            column_name = values[0]
            data_type = values[1]
            length = values[2]

            if length:
                data_type = f"{data_type}({length})"

            self.result.append((column_name, data_type))

        if not self.primary_key:
            messagebox.showwarning("Предупреждение", "Установите первичный ключ")
            return

        self.destroy()

    def on_cancel(self):
        self.destroy()

class SQLServerDatabaseEditor:

    def __init__(self, root):
        self.root = root
        self.root.title("DatabaseEditor")
        self.root.geometry("800x600")

        self.conn = None
        self.current_table = None
        self.edit_widget = None
        self.changes_made = False
        self.new_rows = []
        self.original_data = []
        self.key_columns = []
        self.column_types = {}
        self.server = None
        self.database = None
        self.primary_key = None
        self.current_user = None
        self.user_role = None

        self.config = configparser.ConfigParser()
        self.config_file = 'config.ini'
        self.load_config()

        self.create_widgets()
        self.create_context_menu()
        self.create_menu()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def load_config(self):

        if os.path.exists(self.config_file):
            self.config.read(self.config_file)

        else:
            self.config['DEFAULT'] = {'last_server': ''}

    def save_config(self):
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)

    def create_widgets(self):
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        self.connect_button = ttk.Button(top_frame, text="Подключиться к серверу", command=self.connect_to_server)
        self.connect_button.pack(side=tk.LEFT, padx=(0, 10))

        self.table_combobox = ttk.Combobox(top_frame, state="readonly")
        self.table_combobox.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.table_combobox.bind("<<ComboboxSelected>>", self.on_table_select)

        self.tree = ttk.Treeview(self.root)
        self.tree.pack(expand=True, fill="both", padx=10, pady=10)

        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.save_button = ttk.Button(self.root, text="Сохранить изменения", command=self.save_changes)
        self.save_button.pack(pady=10)

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Добавить строку", command=self.add_row)
        self.context_menu.add_command(label="Удалить строку", command=self.delete_row)

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        server_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Сервер", menu=server_menu)
        server_menu.add_command(label="Подключиться к базе данных", command=self.select_database)

        database_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="База данных", menu=database_menu)
        database_menu.add_command(label="Создать таблицу", command=self.create_table)

        table_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Таблица", menu=table_menu)
        table_menu.add_command(label="Редактировать столбцы", command=self.edit_columns)

    def create_table(self):

        if not self.conn:
            messagebox.showwarning("Предупреждение", "Сначала подключитесь к базе данных")
            return

        if self.user_role != "admin":
            messagebox.showwarning("Предупреждение", "У вас нет прав для создания таблиц")
            return

        table_name = simpledialog.askstring("Создать таблицу", "Введите имя новой таблицы:")

        if not table_name:
            return

        cursor = self.conn.cursor()
        cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = ?", (table_name,))

        if cursor.fetchone():
            messagebox.showerror("Ошибка", f"Таблица с именем '{table_name}' уже существует")
            return

        dialog = ColumnEditorDialog(self.root, [], [], None)
        self.root.wait_window(dialog)

        if dialog.result:

            try:
                create_query = f"CREATE TABLE [{table_name}] ("
                column_definitions = []

                for col, dtype in dialog.result:
                    column_def = f"[{col}] {self.convert_sql_server_type(dtype)}"

                    if col == dialog.primary_key:
                        column_def += " PRIMARY KEY"

                    column_definitions.append(column_def)

                create_query += ", ".join(column_definitions)
                create_query += ")"
                cursor.execute(create_query)
                self.conn.commit()
                messagebox.showinfo("Успех", f"Таблица '{table_name}' успешно создана")
                self.load_tables()
                self.table_combobox.set(table_name)
                self.load_table_data(table_name)

            except Exception as e:
                self.conn.rollback()
                messagebox.showerror("Ошибка", f"Не удалось создать таблицу: {str(e)}")

    def edit_columns(self):

        if not self.current_table:
            messagebox.showwarning("Предупреждение", "Таблица не выбрана")
            return

        if self.user_role != "admin":
            messagebox.showwarning("Предупреждение", "У вас нет прав для редактирования структуры таблицы")
            return

        columns = self.tree['columns']
        data_types = [self.column_types.get(col, "VARCHAR(255)") for col in columns]
        dialog = ColumnEditorDialog(self.root, columns, data_types, self.primary_key)
        self.root.wait_window(dialog)

        if dialog.result:
            new_columns = [col for col, _ in dialog.result]
            new_types = [dtype for _, dtype in dialog.result]
            new_primary_key = dialog.primary_key

            if self.update_table_structure(new_columns, new_types, new_primary_key):
                self.primary_key = new_primary_key
                self.load_table_data(self.current_table)
            else:
                messagebox.showerror("Ошибка", "Не удалось обновить структуру таблицы")

    def connect_to_server(self):
        login_dialog = LoginDialog(self.root, self.config['DEFAULT']['last_server'])
        self.root.wait_window(login_dialog)

        if login_dialog.result:
            server = login_dialog.result["server"]

            try:
                if login_dialog.result["use_windows_auth"]:
                    conn_str = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};Trusted_Connection=yes;'

                else:
                    conn_str = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};UID={login_dialog.result["username"]};PWD={login_dialog.result["password"]}'

                self.conn = pyodbc.connect(conn_str)
                self.server = server
                self.current_user = login_dialog.result["username"]
                self.user_role = self.get_user_role()
                self.config['DEFAULT']['last_server'] = server
                self.save_config()
                messagebox.showinfo("Успех", f"Подключено к серверу {server}")
                self.connect_button.config(text=f"Подключено к {server}")

            except pyodbc.Error as e:
                messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу: {str(e)}")

    def get_user_role(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT IS_SRVROLEMEMBER('sysadmin')")
        is_admin = cursor.fetchone()[0]
        return "admin" if is_admin else "user"

    def select_database(self):

        if not self.conn:
            messagebox.showwarning("Предупреждение", "Сначала подключитесь к серверу")
            return

        database = simpledialog.askstring("Выбор базы данных", "Введите имя базы данных:")

        if database:

            try:
                cursor = self.conn.cursor()
                cursor.execute("SELECT database_id FROM sys.databases WHERE name = ?", (database,))

                if cursor.fetchone() is None:
                    messagebox.showerror("Ошибка", f"База данных '{database}' не существует")
                    return

                self.conn.execute(f"USE [{database}]")
                self.database = database
                self.load_tables()
                messagebox.showinfo("Успех", f"Подключено к базе данных {database}")

            except pyodbc.Error as e:
                messagebox.showerror("Ошибка", f"Не удалось подключиться к базе данных: {str(e)}")

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)

        if item:
            self.tree.selection_set(item)

        self.context_menu.post(event.x_root, event.y_root)

    def check_data_compatibility(self, new_columns, new_types):
        cursor = self.conn.cursor()

        for col, new_type in zip(new_columns, new_types):
            query = f"SELECT TOP 1 [{col}] FROM [{self.current_table}] WHERE LEN(CAST([{col}] AS NVARCHAR(MAX))) > ?"
            max_length = self.get_max_length(new_type)

            if max_length is not None:
                cursor.execute(query, max_length)

                if cursor.fetchone():
                    return False, f"Столбец '{col}' содержит значения, которые не помещаются в новый тип данных {new_type}"

        return True, ""

    def get_max_length(self, data_type):
        match = re.search(r'\((\d+)\)', data_type)

        if match:
            return int(match.group(1))

        return None

    def get_primary_key_from_db(self):

        if not self.conn or not self.current_table:
            return None

        cursor = self.conn.cursor()

        try:
            cursor.execute(f"""
                SELECT COLUMN_NAME
                FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
                WHERE OBJECTPROPERTY(OBJECT_ID(CONSTRAINT_SCHEMA + '.' + QUOTENAME(CONSTRAINT_NAME)), 'IsPrimaryKey') = 1
                AND TABLE_NAME = '{self.current_table}'
            """)
            result = cursor.fetchone()
            return result[0] if result else None

        except Exception as e:
            print(f"Ошибка при получении информации о первичном ключе: {str(e)}")
            return None

    def set_primary_key_in_db(self, new_primary_key):

        if not self.conn or not self.current_table:
            return False

        cursor = self.conn.cursor()
        try:
            cursor.execute(f"""
                DECLARE @constraint_name NVARCHAR(128)
                SELECT @constraint_name = CONSTRAINT_NAME
                FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
                WHERE OBJECTPROPERTY(OBJECT_ID(CONSTRAINT_SCHEMA + '.' + QUOTENAME(CONSTRAINT_NAME)), 'IsPrimaryKey') = 1
                AND TABLE_NAME = '{self.current_table}'

                IF @constraint_name IS NOT NULL
                    EXEC('ALTER TABLE [{self.current_table}] DROP CONSTRAINT ' + @constraint_name)
            """)

            cursor.execute(f"""
                ALTER TABLE [{self.current_table}]
                ADD CONSTRAINT PK_{self.current_table}_{new_primary_key} PRIMARY KEY ({new_primary_key})
            """)

            self.conn.commit()
            return True

        except Exception as e:
            print(f"Ошибка при установке первичного ключа: {str(e)}")
            self.conn.rollback()
            return False

    def update_table_structure(self, new_columns, new_types, new_primary_key):

        if not self.conn:
            messagebox.showerror("Ошибка", "Нет подключения к базе данных")
            return False

        cursor = self.conn.cursor()
        temp_table_name = f"#Temp_{self.current_table}"

        try:
            cursor.execute(f"""
                IF OBJECT_ID('tempdb..{temp_table_name}') IS NOT NULL
                    DROP TABLE {temp_table_name}
            """)

            cursor.execute(f"SELECT TOP 0 * FROM [{self.current_table}]")
            current_columns = [column[0] for column in cursor.description]
            create_query = f"CREATE TABLE {temp_table_name} ("
            column_definitions = []

            for col, dtype in zip(new_columns, new_types):
                column_def = f"[{col}] {self.convert_sql_server_type(dtype)}"

                if col == new_primary_key:
                    column_def += " NOT NULL"

                column_definitions.append(column_def)

            create_query += ", ".join(column_definitions)
            create_query += ")"
            cursor.execute(create_query)
            common_columns = list(set(current_columns) & set(new_columns))

            if common_columns:
                columns_to_copy = ", ".join([f"[{col}]" for col in common_columns])
                insert_query = f"INSERT INTO {temp_table_name} ({columns_to_copy}) SELECT {columns_to_copy} FROM [{self.current_table}]"

                try:
                    cursor.execute(insert_query)

                except pyodbc.DataError as e:
                    self.conn.rollback()
                    messagebox.showerror("Ошибка", f"Не удалось скопировать данные: {str(e)}\n"
                                                   f"Новый тип данных не подходит для существующих значений")
                    return False

            cursor.execute(f"DROP TABLE [{self.current_table}]")
            create_query = f"CREATE TABLE [{self.current_table}] ("
            create_query += ", ".join(column_definitions)
            create_query += ")"
            cursor.execute(create_query)

            if common_columns:
                columns_to_copy = ", ".join([f"[{col}]" for col in common_columns])
                insert_query = f"INSERT INTO [{self.current_table}] ({columns_to_copy}) SELECT {columns_to_copy} FROM {temp_table_name}"
                cursor.execute(insert_query)

            cursor.execute(f"DROP TABLE {temp_table_name}")

            if new_primary_key:
                cursor.execute(f"SELECT COUNT(*) FROM [{self.current_table}] WHERE [{new_primary_key}] IS NULL")
                null_count = cursor.fetchone()[0]

                if null_count > 0:

                    raise Exception(f"Столбец '{new_primary_key}' содержит {null_count} NULL значений и не может быть использован как первичный ключ")

                cursor.execute(f"""
                    SELECT COUNT(*) 
                    FROM (
                        SELECT [{new_primary_key}]
                        FROM [{self.current_table}]
                        GROUP BY [{new_primary_key}]
                        HAVING COUNT(*) > 1
                    ) AS duplicates
                """)

                duplicate_count = cursor.fetchone()[0]

                if duplicate_count > 0:

                    raise Exception(f"Столбец '{new_primary_key}' содержит {duplicate_count} дубликатов и не может быть использован как первичный ключ")

                cursor.execute(f"""
                    ALTER TABLE [{self.current_table}]
                    ADD CONSTRAINT PK_{self.current_table}_{new_primary_key} PRIMARY KEY ({new_primary_key})
                """)

            self.conn.commit()
            self.primary_key = new_primary_key
            self.load_table_data(self.current_table)
            messagebox.showinfo("Успех", "Структура таблицы обновлена")
            return True

        except Exception as e:
            self.conn.rollback()
            error_message = f"Не удалось обновить структуру таблицы: {str(e)}"
            messagebox.showerror("Ошибка", error_message)
            print(f"Подробности ошибки: {error_message}")
            return False

        finally:

            try:
                cursor.execute(f"""
                    IF OBJECT_ID('tempdb..{temp_table_name}') IS NOT NULL
                        DROP TABLE {temp_table_name}
                """)

            except:
                pass

    def load_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
        tables = [row.TABLE_NAME for row in cursor.fetchall()]
        self.table_combobox['values'] = tables

        if tables:
            self.table_combobox.set(tables[0])
            self.load_table_data(self.table_combobox.get())

    def on_table_select(self, event):
        selected_table = self.table_combobox.get()

        if self.current_table != selected_table:

            if self.changes_made:
                response = self.ask_save_changes()

                if response == "cancel":
                    self.table_combobox.set(self.current_table)
                    return

                elif response == "no":
                    self.revert_changes()

            self.load_table_data(selected_table)

    def load_table_data(self, table_name):
        self.current_table = table_name
        cursor = self.conn.cursor()
        self.key_columns = self.get_primary_key_columns(cursor, table_name)

        cursor.execute(f"""
            SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, NUMERIC_PRECISION, NUMERIC_SCALE
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_NAME = '{table_name}'
        """)

        column_info = {row.COLUMN_NAME: row for row in cursor.fetchall()}

        order_by_clause = ", ".join([f"[{col}]" for col in self.key_columns])
        query = f"SELECT * FROM [{self.current_table}] ORDER BY {order_by_clause}"
        cursor.execute(query)

        self.tree.delete(*self.tree.get_children())
        columns = [column[0] for column in cursor.description]
        self.column_types = {}

        for column in columns:
            info = column_info[column]
            data_type = info.DATA_TYPE.upper()

            if data_type in ('CHAR', 'VARCHAR', 'NCHAR', 'NVARCHAR'):

                if info.CHARACTER_MAXIMUM_LENGTH == -1:
                    self.column_types[column] = f'{data_type}(MAX)'

                else:
                    self.column_types[column] = f'{data_type}({info.CHARACTER_MAXIMUM_LENGTH})'

            elif data_type in ('DECIMAL', 'NUMERIC'):
                self.column_types[column] = f'{data_type}({info.NUMERIC_PRECISION},{info.NUMERIC_SCALE})'

            else:
                self.column_types[column] = data_type

        print("Column types:", self.column_types)
        self.tree['columns'] = columns
        self.tree.column('#0', width=0, stretch=tk.NO)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)

        self.original_data = []

        for row in cursor.fetchall():
            values = [str(value).strip() if value is not None else '' for value in row]
            self.tree.insert('', 'end', values=values)
            self.original_data.append(values)

        self.changes_made = False
        self.new_rows = []
        self.primary_key = self.get_primary_key_from_db()

    def get_sql_server_type(self, sql_type):
        type_mapping = {
            pyodbc.SQL_CHAR: "CHAR",
            pyodbc.SQL_VARCHAR: "VARCHAR",
            pyodbc.SQL_LONGVARCHAR: "TEXT",
            pyodbc.SQL_WCHAR: "NCHAR",
            pyodbc.SQL_WVARCHAR: "NVARCHAR",
            pyodbc.SQL_WLONGVARCHAR: "NTEXT",
            pyodbc.SQL_DECIMAL: "DECIMAL",
            pyodbc.SQL_NUMERIC: "NUMERIC",
            pyodbc.SQL_SMALLINT: "SMALLINT",
            pyodbc.SQL_INTEGER: "INT",
            pyodbc.SQL_REAL: "REAL",
            pyodbc.SQL_FLOAT: "FLOAT",
            pyodbc.SQL_DOUBLE: "FLOAT",
            pyodbc.SQL_BIT: "BIT",
            pyodbc.SQL_TINYINT: "TINYINT",
            pyodbc.SQL_BIGINT: "BIGINT",
            pyodbc.SQL_BINARY: "BINARY",
            pyodbc.SQL_VARBINARY: "VARBINARY",
            pyodbc.SQL_LONGVARBINARY: "IMAGE",
            pyodbc.SQL_TYPE_DATE: "DATE",
            pyodbc.SQL_TYPE_TIME: "TIME",
            pyodbc.SQL_TYPE_TIMESTAMP: "DATETIME",
            pyodbc.SQL_GUID: "UNIQUEIDENTIFIER"
        }

        return type_mapping.get(sql_type, "VARCHAR")

    def convert_sql_server_type(self, dtype):

        if dtype.startswith(('CHAR', 'VARCHAR', 'NCHAR', 'NVARCHAR')):
            return dtype

        elif dtype == 'TEXT':
            return 'VARCHAR(MAX)'

        elif dtype == 'INT':
            return 'INT'

        elif dtype == 'BIGINT':
            return 'BIGINT'

        elif dtype.startswith('DECIMAL'):
            return dtype

        elif dtype == 'FLOAT':
            return 'FLOAT'

        elif dtype == 'DATE':
            return 'DATE'

        elif dtype == 'DATETIME':
            return 'DATETIME'

        else:
            return 'VARCHAR(255)'

    def get_primary_key_columns(self, cursor, table_name):
        cursor.execute(f"""
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
            WHERE OBJECTPROPERTY(OBJECT_ID(CONSTRAINT_SCHEMA + '.' + CONSTRAINT_NAME), 'IsPrimaryKey') = 1
            AND TABLE_NAME = '{table_name}'
            ORDER BY ORDINAL_POSITION
        """)

        primary_key_columns = [row.COLUMN_NAME for row in cursor.fetchall()]

        if not primary_key_columns:
            cursor.execute(f"SELECT TOP 1 COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}' ORDER BY ORDINAL_POSITION")
            return [cursor.fetchone().COLUMN_NAME]

        return primary_key_columns

    def on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)

        if not item:
            self.add_row()
            return

        if not column:
            return

        column_index = int(column[1:]) - 1
        column_name = self.tree['columns'][column_index]

        if column_name in self.key_columns:
            messagebox.showwarning("Предупреждение", "Нельзя редактировать ключевое поле")
            return

        x, y, width, height = self.tree.bbox(item, column)
        self.edit_widget = ttk.Entry(self.tree)
        self.edit_widget.place(x=x, y=y, width=width, height=height)
        self.edit_widget.insert(0, self.tree.set(item, column))
        self.edit_widget.focus_set()
        self.edit_widget.bind("<Return>", self.on_edit_save)
        self.edit_widget.bind("<FocusOut>", self.on_edit_save)
        self.edit_item = item
        self.edit_column = column

    def on_edit_save(self, event):

        if not self.edit_widget:
            return

        new_value = self.edit_widget.get()
        old_value = self.tree.set(self.edit_item, self.edit_column)
        column_name = self.tree['columns'][int(self.edit_column[1:]) - 1]
        column_type = self.column_types[column_name]

        if self.validate_data_type(new_value, column_type):

            if new_value != old_value:
                self.tree.set(self.edit_item, self.edit_column, new_value)
                self.changes_made = True

        else:
            messagebox.showwarning("Предупреждение", f"Введенное значение не соответствует типу данных {column_type}")

        self.edit_widget.destroy()
        self.edit_widget = None
        self.edit_item = None
        self.edit_column = None

    def validate_data_type(self, value, data_type):

        try:

            if value == '':
                return True

            data_type = data_type.upper()

            if 'CHAR' in data_type or 'TEXT' in data_type:
                length_match = re.search(r'\((\d+)\)', data_type)

                if length_match:
                    max_length = int(length_match.group(1))
                    return len(value) <= max_length

                return True

            elif 'INT' in data_type:
                int(value)

            elif 'FLOAT' in data_type or 'REAL' in data_type:
                float(value)

            elif 'DATE' in data_type:
                datetime.strptime(value, '%Y-%m-%d')

            elif 'TIME' in data_type:
                datetime.strptime(value, '%H:%M:%S')

            elif 'DATETIME' in data_type:
                datetime.strptime(value, '%Y-%m-%d %H:%M:%S')

            elif data_type == 'BIT':
                return value.lower() in ('true', 'false', '1', '0')

            return True

        except ValueError:
            return False

    def on_double_click_empty(self, event):
        item = self.tree.identify_row(event.y)

        if not item:
            self.add_row()

        else:
            self.on_double_click(event)

    def sort_tree(self):
        items = [(self.tree.set(item, self.key_columns[0]), item) for item in self.tree.get_children('')]
        items.sort(key=lambda x: int(x[0]) if x[0].isdigit() else x[0])

        for index, (_, item) in enumerate(items):
            self.tree.move(item, '', index)

    def add_row(self):

        if not self.current_table:
            messagebox.showwarning("Предупреждение", "Таблица не выбрана")
            return

        if not self.primary_key:
            messagebox.showwarning("Предупреждение", "Не удалось определить первичный ключ")
            return

        last_key_value = self.get_last_key_value(self.primary_key)
        new_key_value = last_key_value + 1 if last_key_value is not None else 1

        new_row = [''] * len(self.tree['columns'])
        key_index = self.tree['columns'].index(self.primary_key)
        new_row[key_index] = str(new_key_value)

        item = self.tree.insert('', 'end', values=new_row)
        self.tree.see(item)
        self.tree.selection_set(item)
        self.changes_made = True
        self.new_rows.append(item)

    def get_last_key_value(self, primary_key):

        if not self.conn or not self.current_table:
            return None

        cursor = self.conn.cursor()

        try:
            cursor.execute(f"SELECT MAX([{primary_key}]) FROM [{self.current_table}]")
            result = cursor.fetchone()
            db_max = result[0] if result and result[0] is not None else 0

            tree_max = max((int(self.tree.item(item)['values'][self.tree['columns'].index(primary_key)])
                            for item in self.tree.get_children()
                            if self.tree.item(item)['values'][self.tree['columns'].index(primary_key)]),
                           default=0)

            return max(db_max, tree_max)

        except Exception as e:
            print(f"Ошибка при получении последнего значения первичного ключа: {str(e)}")
            return None

    def delete_row(self):
        selected_items = self.tree.selection()

        if not selected_items:
            messagebox.showwarning("Предупреждение", "Выберите строку для удаления")
            return

        if messagebox.askyesno("Подтверждение", "Вы уверены, что хотите удалить выбранные строки?"):
            for item in selected_items:
                self.tree.delete(item)
            self.changes_made = True

    def ask_save_changes(self):
        response = messagebox.askyesnocancel("Сохранить изменения", "Сохранить внесенные изменения?")

        if response is None:
            return "cancel"

        elif response:
            self.save_changes()
            return "yes"

        else:
            return "no"

    def revert_changes(self):
        self.tree.delete(*self.tree.get_children())

        for row in self.original_data:
            self.tree.insert('', 'end', values=row)

        self.changes_made = False
        self.new_rows = []

    def save_changes(self):

        if not self.conn or not self.current_table:
            messagebox.showerror("Ошибка", "Нет подключения к базе данных или таблица не выбрана")
            return

        if self.user_role != "admin":
            messagebox.showwarning("Предупреждение", "У вас нет прав для сохранения изменений")
            return

        cursor = self.conn.cursor()

        try:
            current_data = self.get_treeview_data()
            deleted_rows, updated_rows, new_rows = self.compare_data(self.original_data, current_data)

            for row in deleted_rows:
                delete_query = f"DELETE FROM [{self.current_table}] WHERE "
                delete_query += " AND ".join([f"[{col}] = ?" for col in self.key_columns])
                delete_values = [row[self.tree['columns'].index(col)] for col in self.key_columns]
                cursor.execute(delete_query, delete_values)

            for row in updated_rows:
                update_query = f"UPDATE [{self.current_table}] SET "
                update_query += ", ".join(
                    [f"[{col}] = ?" for col in self.tree['columns'] if col not in self.key_columns])
                update_query += " WHERE "
                update_query += " AND ".join([f"[{col}] = ?" for col in self.key_columns])

                update_values = [row[self.tree['columns'].index(col)] for col in self.tree['columns'] if
                                 col not in self.key_columns]
                update_values += [row[self.tree['columns'].index(col)] for col in self.key_columns]

                cursor.execute(update_query, update_values)

            for row in new_rows:
                insert_query = f"INSERT INTO [{self.current_table}] ({', '.join([f'[{col}]' for col in self.tree['columns']])}) VALUES ({', '.join(['?' for _ in self.tree['columns']])})"
                cursor.execute(insert_query, row)

            self.conn.commit()
            self.changes_made = False
            self.new_rows = []
            messagebox.showinfo("Успех", "Изменения сохранены")

        except Exception as e:
            self.conn.rollback()
            messagebox.showerror("Ошибка", f"Не удалось сохранить изменения: {str(e)}")

        finally:
            self.load_table_data(self.current_table)

    def get_treeview_data(self):
        data = []

        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            data.append(values)

        return data

    def compare_data(self, original_data, current_data):
        original_set = set(tuple(row) for row in original_data)
        current_set = set(tuple(row) for row in current_data)
        deleted_rows = original_set - current_set
        new_rows = current_set - original_set
        updated_rows = []

        for row in current_set:

            if row not in original_set and row not in new_rows:
                updated_rows.append(row)

        return list(deleted_rows), updated_rows, list(new_rows)

    def convert_values(self, values):
        converted = []

        for value, column in zip(values, self.tree['columns']):
            column_type = self.column_types.get(column, 'TEXT').upper()
            print(f"Converting {column}: {value} (type: {column_type})")

            if value == '':
                converted.append(None)

            elif 'INTEGER' in column_type:
                converted.append(int(value) if value else None)

            elif 'FLOAT' in column_type or 'DOUBLE' in column_type or 'DECIMAL' in column_type:
                converted.append(float(value) if value else None)

            elif 'DATETIME' in column_type:

                try:
                    converted.append(datetime.strptime(value, '%Y-%m-%d %H:%M:%S'))

                except ValueError:
                    converted.append(None)

            else:
                converted.append(value)

        print(f"Converted values: {converted}")
        return converted

    def on_closing(self):

        if self.changes_made:
            response = self.ask_save_changes()

            if response == "cancel":
                return

        self.save_config()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLServerDatabaseEditor(root)
    root.mainloop()