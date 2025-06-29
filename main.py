import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import asyncio
import aiohttp
import asyncpg
import configparser
import os
import threading
import time
import signal
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bybit_downloader.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CryptoManager:
    """Менеджер для шифрования/дешифрования паролей"""
    
    def __init__(self, salt_file='salt.key'):
        self.salt_file = salt_file
        self.salt = self._load_or_generate_salt()
        self.fernet = self._create_fernet()
    
    def _load_or_generate_salt(self) -> bytes:
        """Загрузка существующей соли или генерация новой"""
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            # Генерируем новую соль
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            return salt
    
    def _create_fernet(self) -> Fernet:
        """Создание объекта Fernet для шифрования"""
        # Используем фиксированный пароль для генерации ключа
        # В реальном приложении можно использовать системные переменные или другие методы
        password = b"bybit_downloader_secret_key_2024"
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(key)
    
    def encrypt(self, text: str) -> str:
        """Шифрование текста"""
        if not text:
            return ""
        return self.fernet.encrypt(text.encode()).decode()
    
    def decrypt(self, encrypted_text: str) -> str:
        """Дешифрование текста"""
        if not encrypted_text:
            return ""
        try:
            return self.fernet.decrypt(encrypted_text.encode()).decode()
        except Exception as e:
            logger.warning(f"Не удалось дешифровать пароль: {e}")
            return ""

class ByBitDownloader:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ByBit Downloader")
        self.root.geometry("800x600")
        
        # Обработчик закрытия окна
        self.root.protocol("WM_DELETE_WINDOW", self.exit_program)
        
        # Обработчики сигналов для корректного завершения
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, lambda sig, frame: self.exit_program())
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, lambda sig, frame: self.exit_program())
        
        # Инициализация менеджера шифрования
        self.crypto_manager = CryptoManager()
        
        # Переменные
        self.start_date = tk.StringVar()
        self.end_date = tk.StringVar()
        self.filter_text = tk.StringVar()
        self.status_text = tk.StringVar(value="Готов к работе")
        self.progress_value = tk.DoubleVar()
        
        # Данные
        self.tickers_data = []
        self.marked_tickers = set()
        self.download_thread = None
        self.stop_download = False
        
        # Переменные для корректного завершения
        self.active_tasks = []
        self.loop = None
        
        # Настройки
        self.settings = self.load_settings()
        
        # Восстанавливаем период из настроек
        self.start_date.set(self.settings.get('Period', 'start_date', fallback=datetime.now().strftime("%Y-%m-%d %H:%M")))
        # end_date всегда устанавливаем на текущий момент при открытии программы
        self.end_date.set(datetime.now().strftime("%Y-%m-%d %H:%M"))
        
        self.setup_ui()
        self.load_marked_tickers()
        self.refresh_tickers()
        
    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        # Настройка стилей для таблицы
        style = ttk.Style()
        style.configure("Treeview", background="white", fieldbackground="white")
        style.map("Treeview", background=[("selected", "lightblue")])
        
        # Основной фрейм
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Настройка весов для растяжения
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Выбор периода - центрирование
        period_frame = ttk.LabelFrame(main_frame, text="Период загрузки", padding="10")
        period_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Центрирование периода - создаем внутренний фрейм
        inner_period_frame = ttk.Frame(period_frame)
        inner_period_frame.pack(expand=True)
        
        ttk.Label(inner_period_frame, text="С:").pack(side=tk.LEFT, padx=(0, 5))
        start_entry = ttk.Entry(inner_period_frame, textvariable=self.start_date, width=20)
        start_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(inner_period_frame, text="По:").pack(side=tk.LEFT, padx=(20, 5))
        end_entry = ttk.Entry(inner_period_frame, textvariable=self.end_date, width=20)
        end_entry.pack(side=tk.LEFT, padx=5)
        
        # Кнопка "По сейчас"
        ttk.Button(inner_period_frame, text="По сейчас", command=self.set_end_date_to_now, width=10).pack(side=tk.LEFT, padx=(10, 0))
        
        # Фильтр тикеров
        filter_frame = ttk.Frame(main_frame)
        filter_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        filter_frame.columnconfigure(1, weight=1)
        
        ttk.Label(filter_frame, text="Фильтр тикеров:").grid(row=0, column=0, padx=(0, 5))
        ttk.Entry(filter_frame, textvariable=self.filter_text).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(filter_frame, text="Фильтр", command=self.apply_filter).grid(row=0, column=2, padx=(5, 0))
        
        # Таблица тикеров
        table_frame = ttk.Frame(main_frame)
        table_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        
        # Создание таблицы - убираем лишнюю колонку
        columns = ("ticker", "volume", "turnover", "change")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        # Настройка столбцов
        self.tree.heading("ticker", text="Тикер", command=lambda: self.sort_column("ticker"))
        self.tree.heading("volume", text="Объем", command=lambda: self.sort_column("volume"))
        self.tree.heading("turnover", text="Оборот", command=lambda: self.sort_column("turnover"))
        self.tree.heading("change", text="Изменение", command=lambda: self.sort_column("change"))
        
        self.tree.column("ticker", width=100, anchor=tk.W)
        self.tree.column("volume", width=100, anchor=tk.E)
        self.tree.column("turnover", width=100, anchor=tk.E)
        self.tree.column("change", width=100, anchor=tk.E)
        
        # Скроллбары
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Размещение таблицы и скроллбаров
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Привязка событий
        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<Control-Button-1>", self.on_tree_ctrl_click)
        self.tree.bind("<Shift-Button-1>", self.on_tree_shift_click)
        self.tree.bind("<ButtonRelease-1>", self.on_tree_release)
        
        # Кнопки управления тикерами (справа от таблицы)
        ticker_buttons_frame = ttk.Frame(main_frame)
        ticker_buttons_frame.grid(row=2, column=3, sticky=(tk.N, tk.S), padx=(10, 0))
        
        ttk.Button(ticker_buttons_frame, text="Пометить все", command=self.mark_all, width=20).pack(pady=2)
        ttk.Button(ticker_buttons_frame, text="Снять все", command=self.unmark_all, width=20).pack(pady=2)
        ttk.Button(ticker_buttons_frame, text="Инверсия", command=self.invert_marks, width=20).pack(pady=2)
        
        # Прогресс бар
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_value, maximum=100)
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Кнопки управления
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(buttons_frame, text="Обновить", command=self.refresh_tickers, width=20).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_frame, text="Сохранить тикеры", command=self.save_marked_tickers, width=20).pack(side=tk.LEFT, padx=5)
        
        # Основные кнопки
        main_buttons_frame = ttk.Frame(main_frame)
        main_buttons_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.download_button = ttk.Button(main_buttons_frame, text="Загрузить", command=self.start_download, style="Accent.TButton", width=20)
        self.download_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_button = ttk.Button(main_buttons_frame, text="Прервать", command=self.stop_download_process, state=tk.DISABLED, width=20)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(main_buttons_frame, text="Настройка", command=self.open_settings, width=20).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(main_buttons_frame, text="Выход", command=self.exit_program, width=20).pack(side=tk.LEFT, padx=5)
        
        # Строка состояния
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E))
        status_frame.columnconfigure(0, weight=1)
        
        self.status_label = ttk.Label(status_frame, textvariable=self.status_text, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
    def load_settings(self) -> configparser.ConfigParser:
        """Загрузка настроек из файла"""
        try:
            config = configparser.ConfigParser()
            
            if os.path.exists('settings.ini'):
                config.read('settings.ini', encoding='utf-8')
                logger.info("Настройки загружены из файла")
            else:
                logger.info("Файл настроек не найден, используются значения по умолчанию")
            
            # Установка значений по умолчанию если секции отсутствуют
            if 'Database' not in config:
                config['Database'] = {
                    'host': 'localhost',
                    'port': '5432',
                    'user': 'postgres',
                    'password': '',
                    'database': 'bybit_data',
                    'schema': 'public'
                }
            
            if 'Download' not in config:
                config['Download'] = {
                    'threads': '5'
                }
            
            if 'Period' not in config:
                config['Period'] = {
                    'start_date': datetime.now().strftime("%Y-%m-%d %H:%M"),
                    'end_date': datetime.now().strftime("%Y-%m-%d %H:%M")
                }
            
            return config
        except Exception as e:
            logger.error(f"Ошибка при загрузке настроек: {e}")
            # Возвращаем конфигурацию по умолчанию
            config = configparser.ConfigParser()
            config['Database'] = {
                'host': 'localhost',
                'port': '5432',
                'user': 'postgres',
                'password': '',
                'database': 'bybit_data',
                'schema': 'public'
            }
            config['Download'] = {'threads': '5'}
            config['Period'] = {
                'start_date': datetime.now().strftime("%Y-%m-%d %H:%M"),
                'end_date': datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            return config

    def save_settings(self):
        """Сохранение настроек в файл"""
        try:
            # Обновление периода
            if 'Period' not in self.settings:
                self.settings['Period'] = {}
            self.settings['Period']['start_date'] = self.start_date.get()
            self.settings['Period']['end_date'] = self.end_date.get()
            
            # Шифрование пароля перед сохранением
            if 'Database' in self.settings and 'password' in self.settings['Database']:
                password = self.settings['Database']['password']
                if password and not password.startswith('encrypted:'):
                    encrypted_password = self.crypto_manager.encrypt(password)
                    self.settings['Database']['password'] = f"encrypted:{encrypted_password}"
            
            # Сохранение в файл
            with open('settings.ini', 'w', encoding='utf-8') as f:
                self.settings.write(f)
            
            # Сохранение помеченных тикеров
            self.save_marked_tickers()
            
            logger.info("Настройки сохранены")
        except Exception as e:
            logger.error(f"Ошибка при сохранении настроек: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить настройки: {e}")
    
    def load_marked_tickers(self):
        """Загрузка помеченных тикеров из настроек"""
        try:
            if 'Tickers' in self.settings and 'marked' in self.settings['Tickers']:
                marked_str = self.settings['Tickers']['marked']
                if marked_str:
                    # Загружаем с учетом регистра
                    marked_list = [ticker.strip() for ticker in marked_str.split(',') if ticker.strip()]
                    self.marked_tickers = set(marked_list)
                    logger.info(f"Загружено {len(self.marked_tickers)} помеченных тикеров")
                else:
                    self.marked_tickers = set()
            else:
                self.marked_tickers = set()
        except Exception as e:
            logger.error(f"Ошибка при загрузке помеченных тикеров: {e}")
            self.marked_tickers = set()

    def save_marked_tickers(self):
        """Сохранение помеченных тикеров в настройки"""
        try:
            if 'Tickers' not in self.settings:
                self.settings['Tickers'] = {}
            
            if self.marked_tickers:
                marked_str = ','.join(sorted(self.marked_tickers))
                self.settings['Tickers']['marked'] = marked_str
                logger.info(f"Сохранено {len(self.marked_tickers)} помеченных тикеров")
            else:
                self.settings['Tickers']['marked'] = ''
        except Exception as e:
            logger.error(f"Ошибка при сохранении помеченных тикеров: {e}")
    
    def refresh_tickers(self):
        """Обновление списка тикеров"""
        try:
            self.status_text.set("Обновление списка тикеров...")
            self.root.update()
            
            # Получение тикеров
            tickers = self.get_tickers_from_bybit()
            
            if tickers:
                self.tickers_data = tickers
                self.update_tickers_table()
                self.status_text.set(f"Загружено {len(tickers)} тикеров")
            else:
                self.status_text.set("Не удалось загрузить тикеры")
                logger.warning("Не удалось получить тикеры с ByBit API")
                
        except Exception as e:
            error_msg = f"Ошибка при обновлении тикеров: {e}"
            self.status_text.set(error_msg)
            logger.error(error_msg)
            messagebox.showerror("Ошибка", error_msg)
    
    def get_tickers_from_bybit(self) -> List[Dict]:
        """Получение списка тикеров с ByBit API"""
        try:
            import requests
            
            url = "https://api.bybit.com/v5/market/tickers"
            params = {"category": "spot"}
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("retCode") != 0:
                raise Exception(f"API ошибка: {data.get('retMsg', 'Неизвестная ошибка')}")
            
            result = data.get("result", {})
            instruments = result.get("list", [])
            
            tickers = []
            for instrument in instruments:
                symbol = instrument.get("symbol")
                if symbol:
                    tickers.append({
                        "symbol": symbol,
                        "volume24h": float(instrument.get("volume24h", 0)),
                        "turnover24h": float(instrument.get("turnover24h", 0)),
                        "priceChangePercent": float(instrument.get("price24hPcnt", 0)) * 100
                    })
            
            # Сортировка по объему
            tickers.sort(key=lambda x: x["volume24h"], reverse=True)
            
            logger.info(f"Получено {len(tickers)} тикеров с ByBit API")
            return tickers
            
        except requests.exceptions.Timeout:
            logger.error("Таймаут при получении тикеров с ByBit API")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Ошибка сети при получении тикеров: {e}")
            return []
        except Exception as e:
            logger.error(f"Ошибка при получении тикеров: {e}")
            return []
    
    def update_tickers_table(self):
        """Обновление таблицы тикеров"""
        try:
            # Очистка таблицы
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Добавление данных
            for ticker in self.tickers_data:
                symbol = ticker['symbol']
                volume = f"{int(ticker['volume24h']):,}".replace(",", " ")
                turnover = f"{int(ticker['turnover24h']):,}".replace(",", " ")
                change = f"{ticker['priceChangePercent']:.2f}%"
                
                item = self.tree.insert("", tk.END, values=(symbol, volume, turnover, change))
                
                # Применяем пометки
                if symbol in self.marked_tickers:
                    self.tree.selection_add(item)
            
            # Первичная сортировка по обороту в обратном порядке
            self.sort_column_initial("turnover")
            
            # Обновляем счетчик
            self.update_marked_count_status()
            logger.info(f"Таблица обновлена: {len(self.tickers_data)} тикеров")
        except Exception as e:
            logger.error(f"Ошибка при обновлении таблицы тикеров: {e}")
    
    def apply_filter(self):
        """Применение фильтра к таблице"""
        try:
            filter_text = self.filter_text.get().strip().upper()
            
            # Показываем/скрываем строки
            for item in self.tree.get_children():
                symbol = self.tree.item(item, "values")[0]
                if filter_text in symbol:
                    self.tree.reattach(item, "", "end")
                else:
                    self.tree.detach(item)
            
            # Обновляем счетчик
            self.update_marked_count_status()
        except Exception as e:
            logger.error(f"Ошибка при применении фильтра: {e}")
    
    def sort_column_initial(self, column):
        """Первичная сортировка таблицы по колонке (без учета предыдущего состояния)"""
        try:
            # Получаем текущие данные
            data = []
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                data.append(values)
            
            # Определяем индекс колонки
            column_index = {"ticker": 0, "volume": 1, "turnover": 2, "change": 3}.get(column, 0)
            
            # Первичная сортировка всегда в обратном порядке
            reverse = True
            
            # Специальная обработка для числовых колонок
            if column in ["volume", "turnover"]:
                # Убираем пробелы и конвертируем в числа
                data.sort(key=lambda x: int(x[column_index].replace(" ", "")), reverse=reverse)
            elif column == "change":
                # Убираем % и конвертируем в числа
                data.sort(key=lambda x: float(x[column_index].replace("%", "")), reverse=reverse)
            else:
                # Обычная сортировка строк
                data.sort(key=lambda x: x[column_index], reverse=reverse)
            
            # Обновляем таблицу
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            for row in data:
                item = self.tree.insert("", tk.END, values=row)
                # Восстанавливаем выделение
                if row[0] in self.marked_tickers:
                    self.tree.selection_add(item)
            
            # Инициализируем флаг сортировки
            if not hasattr(self, '_sort_reverse'):
                self._sort_reverse = {}
            self._sort_reverse[column] = reverse
            
            logger.info(f"Первичная сортировка по колонке {column}")
        except Exception as e:
            logger.error(f"Ошибка при первичной сортировке таблицы: {e}")

    def sort_column(self, column):
        """Сортировка таблицы по колонке"""
        try:
            # Получаем текущие данные
            data = []
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                data.append(values)
            
            # Определяем индекс колонки - используем названия колонок из заголовков
            column_index = {"ticker": 0, "volume": 1, "turnover": 2, "change": 3}.get(column, 0)
            
            # Определяем порядок сортировки
            if not hasattr(self, '_sort_reverse'):
                self._sort_reverse = {}
            
            # Если это новая колонка для сортировки, начинаем с обратного порядка
            if column not in self._sort_reverse:
                reverse = True
            else:
                # Если та же колонка, меняем порядок
                reverse = not self._sort_reverse[column]
            
            # Специальная обработка для числовых колонок
            if column in ["volume", "turnover"]:
                # Убираем пробелы и конвертируем в числа
                data.sort(key=lambda x: int(x[column_index].replace(" ", "")), reverse=reverse)
            elif column == "change":
                # Убираем % и конвертируем в числа
                data.sort(key=lambda x: float(x[column_index].replace("%", "")), reverse=reverse)
            else:
                # Обычная сортировка строк
                data.sort(key=lambda x: x[column_index], reverse=reverse)
            
            # Обновляем таблицу
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            for row in data:
                item = self.tree.insert("", tk.END, values=row)
                # Восстанавливаем выделение
                if row[0] in self.marked_tickers:
                    self.tree.selection_add(item)
            
            # Обновляем флаг сортировки
            self._sort_reverse[column] = reverse
            
            logger.info(f"Таблица отсортирована по колонке {column}")
        except Exception as e:
            logger.error(f"Ошибка при сортировке таблицы: {e}")
    
    def on_tree_click(self, event):
        """Обработка клика по таблице"""
        try:
            item = self.tree.identify_row(event.y)
            if item:
                symbol = self.tree.item(item, "values")[0]
                
                # Очищаем все пометки и помечаем только выбранный тикер
                self.marked_tickers.clear()
                self.marked_tickers.add(symbol)
                
                # Обновляем выделение в таблице
                self.tree.selection_set(item)
                
                # Обновляем счетчик
                self.update_marked_count_status()
        except Exception as e:
            logger.error(f"Ошибка при обработке клика по таблице: {e}")

    def on_tree_ctrl_click(self, event):
        """Обработка Ctrl+клика по таблице"""
        try:
            item = self.tree.identify_row(event.y)
            if item:
                symbol = self.tree.item(item, "values")[0]
                
                # Переключаем пометку только для выбранного тикера
                if symbol in self.marked_tickers:
                    self.marked_tickers.remove(symbol)
                    self.tree.selection_remove(item)
                else:
                    self.marked_tickers.add(symbol)
                    self.tree.selection_add(item)
                
                # Обновляем счетчик
                self.update_marked_count_status()
        except Exception as e:
            logger.error(f"Ошибка при обработке Ctrl+клика по таблице: {e}")

    def on_tree_shift_click(self, event):
        """Обработка Shift+клика по таблице"""
        try:
            item = self.tree.identify_row(event.y)
            if item:
                symbol = self.tree.item(item, "values")[0]
                
                # Добавляем тикер к существующим пометкам
                self.marked_tickers.add(symbol)
                self.tree.selection_add(item)
                
                # Обновляем счетчик
                self.update_marked_count_status()
        except Exception as e:
            logger.error(f"Ошибка при обработке Shift+клика по таблице: {e}")

    def on_tree_release(self, event):
        """Обработка отпускания кнопки мыши"""
        try:
            # Синхронизируем выделение с множеством помеченных тикеров
            self.update_table_selection()
        except Exception as e:
            logger.error(f"Ошибка при обработке отпускания кнопки мыши: {e}")
    
    def update_marked_count_status(self):
        """Обновление счетчика помеченных тикеров в статусе"""
        try:
            visible_tickers = self.get_visible_tickers()
            marked_visible = sum(1 for ticker in visible_tickers if ticker in self.marked_tickers)
            total_visible = len(visible_tickers)
            
            status_text = f"Помечено: {marked_visible}/{total_visible} видимых, {len(self.marked_tickers)} всего"
            self.status_text.set(status_text)
        except Exception as e:
            logger.error(f"Ошибка при обновлении счетчика тикеров: {e}")

    def get_visible_tickers(self) -> List[str]:
        """Получение списка видимых (отфильтрованных) тикеров"""
        try:
            visible_tickers = []
            for item in self.tree.get_children():
                symbol = self.tree.item(item, "values")[0]
                visible_tickers.append(symbol)
            return visible_tickers
        except Exception as e:
            logger.error(f"Ошибка при получении видимых тикеров: {e}")
            return []

    def update_table_selection(self):
        """Синхронизация выделения таблицы с множеством помеченных тикеров"""
        try:
            for item in self.tree.get_children():
                symbol = self.tree.item(item, "values")[0]
                if symbol in self.marked_tickers:
                    self.tree.selection_add(item)
                else:
                    self.tree.selection_remove(item)
        except Exception as e:
            logger.error(f"Ошибка при синхронизации выделения таблицы: {e}")
    
    def mark_all(self):
        """Пометка всех видимых тикеров"""
        try:
            visible_tickers = self.get_visible_tickers()
            for ticker in visible_tickers:
                self.marked_tickers.add(ticker)
            
            self.update_table_selection()
            self.update_marked_count_status()
            logger.info(f"Помечено {len(visible_tickers)} тикеров")
        except Exception as e:
            logger.error(f"Ошибка при пометке всех тикеров: {e}")
    
    def unmark_all(self):
        """Снятие пометки со всех видимых тикеров"""
        try:
            visible_tickers = self.get_visible_tickers()
            for ticker in visible_tickers:
                self.marked_tickers.discard(ticker)
            
            self.update_table_selection()
            self.update_marked_count_status()
            logger.info(f"Снята пометка с {len(visible_tickers)} тикеров")
        except Exception as e:
            logger.error(f"Ошибка при снятии пометки со всех тикеров: {e}")
    
    def invert_marks(self):
        """Инвертирование пометок видимых тикеров"""
        try:
            visible_tickers = self.get_visible_tickers()
            for ticker in visible_tickers:
                if ticker in self.marked_tickers:
                    self.marked_tickers.remove(ticker)
                else:
                    self.marked_tickers.add(ticker)
            
            self.update_table_selection()
            self.update_marked_count_status()
            logger.info("Инвертированы пометки тикеров")
        except Exception as e:
            logger.error(f"Ошибка при инвертировании пометок: {e}")
    
    def open_settings(self):
        """Открытие окна настроек"""
        try:
            SettingsWindow(self.root, self.settings, self.save_settings, self.crypto_manager)
        except Exception as e:
            logger.error(f"Ошибка при открытии окна настроек: {e}")
            messagebox.showerror("Ошибка", f"Не удалось открыть окно настроек: {e}")
    
    def start_download(self):
        """Запуск процесса загрузки"""
        try:
            # Проверка выбранных тикеров
            if not self.marked_tickers:
                messagebox.showwarning("Предупреждение", "Не выбрано ни одного тикера для загрузки")
                return
            
            # Парсинг дат
            try:
                start_dt = datetime.strptime(self.start_date.get(), "%Y-%m-%d %H:%M")
                end_dt = datetime.strptime(self.end_date.get(), "%Y-%m-%d %H:%M")
            except ValueError:
                messagebox.showerror("Ошибка", "Неверный формат даты. Используйте формат: YYYY-MM-DD HH:MM")
                return
            
            # Проверка периода
            if start_dt >= end_dt:
                messagebox.showerror("Ошибка", "Начальная дата должна быть меньше конечной")
                return
            
            # Запуск загрузки в отдельном потоке - только помеченные тикеры
            self.stop_download = False
            self.download_thread = threading.Thread(
                target=self.download_process,
                args=(start_dt, end_dt, list(self.marked_tickers))
            )
            self.download_thread.daemon = True
            self.download_thread.start()
            
            # Обновление UI
            self.download_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress_value.set(0)
            self.status_text.set(f"Начало загрузки {len(self.marked_tickers)} помеченных тикеров...")
            
        except Exception as e:
            error_msg = f"Ошибка при запуске загрузки: {e}"
            logger.error(error_msg)
            messagebox.showerror("Ошибка", error_msg)
            self.finish_download()
    
    def stop_download_process(self):
        """Остановка процесса загрузки"""
        try:
            self.stop_download = True
            self.status_text.set("Остановка загрузки...")
            logger.info("Запрошена остановка загрузки")
        except Exception as e:
            logger.error(f"Ошибка при остановке загрузки: {e}")
    
    def download_process(self, start_dt: datetime, end_dt: datetime, tickers: List[str]):
        """Процесс загрузки данных"""
        try:
            # Создание асинхронного цикла
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            # Запуск асинхронной загрузки
            self.loop.run_until_complete(self.async_download(start_dt, end_dt, tickers))
            
        except Exception as e:
            logger.error(f"Ошибка в процессе загрузки: {e}")
            self.root.after(0, lambda: self.status_text.set(f"Ошибка загрузки: {e}"))
        finally:
            # Восстановление UI
            self.root.after(0, self.finish_download)
            # Очищаем ссылку на loop
            self.loop = None
    
    async def async_download(self, start_dt: datetime, end_dt: datetime, tickers: List[str]):
        """Асинхронная загрузка данных"""
        try:
            # Инициализация состояния прогресса
            progress_state = {
                'processed_tickers': 0,
                'processed_minutes': 0,
                'lock': asyncio.Lock()
            }
            
            # Подсчет общего количества минут
            total_minutes = int((end_dt - start_dt).total_seconds() / 60) * len(tickers)
            
            # Создание семафора для ограничения одновременных подключений
            max_connections = int(self.settings.get('Download', 'threads', fallback='5'))
            semaphore = asyncio.Semaphore(max_connections)
            
            # Запуск обновления прогресса
            progress_task = asyncio.create_task(
                self.progress_updater(progress_state, len(tickers), total_minutes)
            )
            
            # Создание задач для каждого тикера
            tasks = []
            for ticker in tickers:
                if self.stop_download:
                    break
                task = asyncio.create_task(
                    self.download_ticker_data(ticker, start_dt, end_dt, semaphore, progress_state)
                )
                tasks.append(task)
            
            # Ожидание завершения всех задач
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            # Отмена задачи обновления прогресса
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass
            
            logger.info("Асинхронная загрузка завершена")
            
        except asyncio.CancelledError:
            logger.info("Асинхронная загрузка отменена")
            raise
        except Exception as e:
            logger.error(f"Ошибка в асинхронной загрузке: {e}")
            raise
    
    async def progress_updater(self, progress_state: dict, total_tickers: int, total_minutes: int):
        """Обновление прогресса в UI"""
        try:
            while not self.stop_download:
                async with progress_state['lock']:
                    processed_tickers = progress_state['processed_tickers']
                    processed_minutes = progress_state['processed_minutes']
                
                # Обновление UI в главном потоке
                self.root.after(0, lambda: self.update_progress(
                    processed_tickers, total_tickers, processed_minutes, total_minutes
                ))
                
                # Проверка завершения
                if processed_tickers >= total_tickers:
                    break
                
                # Пауза между обновлениями
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            logger.info("Обновление прогресса отменено")
            raise
        except Exception as e:
            logger.error(f"Ошибка в обновлении прогресса: {e}")
            raise
    
    async def download_ticker_data(self, ticker: str, start_dt: datetime, end_dt: datetime, 
                                 semaphore: asyncio.Semaphore, progress_state: dict):
        """Загрузка данных для одного тикера"""
        async with semaphore:
            try:
                # Подключение к базе данных
                conn = await asyncpg.connect(
                    host=self.settings.get('Database', 'host'),
                    port=self.settings.get('Database', 'port'),
                    user=self.settings.get('Database', 'user'),
                    password=self.crypto_manager.decrypt(self.settings.get('Database', 'password')),
                    database=self.settings.get('Database', 'database')
                )
                
                try:
                    # Создание таблицы если не существует
                    await self.create_ticker_table(conn, ticker)
                    
                    # Поиск пропусков в данных
                    gaps = await self.find_data_gaps(conn, ticker, start_dt, end_dt)
                    
                    if gaps:
                        logger.info(f"Найдено {len(gaps)} пропусков в данных для {ticker}")
                        for gap_start, gap_end in gaps:
                            if self.stop_download:
                                break
                            await self.download_period_data(conn, ticker, gap_start, gap_end, progress_state)
                    else:
                        logger.info(f"Пропусков в данных для {ticker} не найдено")
                    
                    # Обновляем прогресс по тикерам
                    async with progress_state['lock']:
                        progress_state['processed_tickers'] += 1
                    
                finally:
                    await conn.close()
                    
            except asyncio.CancelledError:
                logger.info(f"Загрузка данных для {ticker} отменена")
                raise
            except Exception as e:
                logger.error(f"Ошибка при загрузке данных для {ticker}: {e}")
                # Обновляем прогресс даже при ошибке
                async with progress_state['lock']:
                    progress_state['processed_tickers'] += 1
    
    async def find_data_gaps(self, conn, ticker: str, start_dt: datetime, end_dt: datetime) -> List[Tuple[datetime, datetime]]:
        """Поиск пропусков в данных"""
        try:
            schema = self.settings.get('Database', 'schema', fallback='public')
            table_name = f"{ticker}_1m"
            
            # Получение существующих временных меток
            query = f"""
                SELECT timestamp 
                FROM {schema}.{table_name} 
                WHERE timestamp >= $1 AND timestamp <= $2 
                ORDER BY timestamp
            """
            
            rows = await conn.fetch(query, start_dt, end_dt)
            existing_timestamps = [row['timestamp'] for row in rows]
            
            if not existing_timestamps:
                # Если данных нет вообще, возвращаем весь период
                return [(start_dt, end_dt)]
            
            gaps = []
            current_time = start_dt
            
            # Проверяем каждый интервал в минуту
            while current_time < end_dt:
                next_time = current_time + timedelta(minutes=1)
                
                # Ищем ближайшую существующую метку времени
                found = False
                for ts in existing_timestamps:
                    if ts >= current_time and ts < next_time:
                        found = True
                        break
                
                if not found:
                    # Найден пропуск
                    gap_start = current_time
                    
                    # Ищем конец пропуска
                    while current_time < end_dt:
                        next_time = current_time + timedelta(minutes=1)
                        found = False
                        for ts in existing_timestamps:
                            if ts >= current_time and ts < next_time:
                                found = True
                                break
                        
                        if found:
                            break
                        current_time = next_time
                    
                    gaps.append((gap_start, current_time))
                else:
                    current_time = next_time
            
            return gaps
        except asyncio.CancelledError:
            logger.info(f"Поиск пропусков для {ticker} отменен")
            raise
        except Exception as e:
            logger.error(f"Ошибка при поиске пропусков для {ticker}: {e}")
            raise
    
    async def create_ticker_table(self, conn, ticker: str):
        """Создание таблицы для тикера если не существует"""
        try:
            schema = self.settings.get('Database', 'schema', fallback='public')
            table_name = f"{ticker}_1m"
            
            # Создание схемы если не существует
            await conn.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
            
            # Создание таблицы
            query = f"""
                CREATE TABLE IF NOT EXISTS {schema}.{table_name} (
                    timestamp TIMESTAMP PRIMARY KEY,
                    open DECIMAL(20, 8),
                    high DECIMAL(20, 8),
                    low DECIMAL(20, 8),
                    close DECIMAL(20, 8),
                    volume DECIMAL(20, 8),
                    turnover DECIMAL(20, 8)
                )
            """
            
            await conn.execute(query)
            logger.info(f"Таблица {schema}.{table_name} готова")
        except asyncio.CancelledError:
            logger.info(f"Создание таблицы для {ticker} отменено")
            raise
        except Exception as e:
            logger.error(f"Ошибка при создании таблицы для {ticker}: {e}")
            raise
    
    async def download_period_data(self, conn, ticker: str, start_dt: datetime, end_dt: datetime, progress_state: dict):
        """Загрузка данных за период"""
        try:
            # Разбиение на блоки по 600 минут
            block_size = timedelta(minutes=600)
            current_start = start_dt
            
            logger.info(f"Начало загрузки данных для {ticker} за период {start_dt} - {end_dt}")
            
            while current_start < end_dt and not self.stop_download:
                current_end = min(current_start + block_size, end_dt)
                
                # Попытки загрузки с повторами
                for attempt in range(3):
                    try:
                        data = await self.fetch_bybit_data(ticker, current_start, current_end)
                        if data:
                            await self.insert_data_to_db(conn, ticker, data)
                            
                            # Обновляем прогресс после записи в базу
                            minutes_processed = int((current_end - current_start).total_seconds() / 60)
                            async with progress_state['lock']:
                                progress_state['processed_minutes'] += minutes_processed
                            
                            logger.info(f"Загружено {len(data)} записей для {ticker} за период {current_start} - {current_end}")
                            break
                        else:
                            raise Exception("Пустой ответ от API")
                            
                    except asyncio.CancelledError:
                        logger.info(f"Загрузка данных для {ticker} отменена")
                        raise
                    except Exception as e:
                        if attempt == 2:  # Последняя попытка
                            logger.error(f"Не удалось загрузить данные для {ticker} за период {current_start}-{current_end}: {e}")
                            raise
                        else:
                            logger.warning(f"Попытка {attempt + 1} для {ticker} за период {current_start}-{current_end}: {e}")
                            await asyncio.sleep(2)  # Пауза перед повтором
                
                current_start = current_end
            
            logger.info(f"Завершена загрузка данных для {ticker} за период {start_dt} - {end_dt}")
        except asyncio.CancelledError:
            logger.info(f"Загрузка периода для {ticker} отменена")
            raise
        except Exception as e:
            logger.error(f"Ошибка при загрузке периода для {ticker}: {e}")
            raise
    
    async def fetch_bybit_data(self, ticker: str, start_dt: datetime, end_dt: datetime) -> List[Dict]:
        """Получение данных с ByBit API"""
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://api.bybit.com/v5/market/kline"
                
                # Конвертация в миллисекунды
                start_ms = int(start_dt.timestamp() * 1000)
                end_ms = int(end_dt.timestamp() * 1000)
                
                params = {
                    "category": "spot",
                    "symbol": ticker,
                    "interval": "1",  # 1 минута
                    "start": start_ms,
                    "end": end_ms,
                    "limit": 1000
                }
                
                async with session.get(url, params=params) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}: {await response.text()}")
                    
                    data = await response.json()
                    
                    if data.get("retCode") != 0:
                        raise Exception(f"API ошибка: {data.get('retMsg', 'Неизвестная ошибка')}")
                    
                    result = data.get("result", {})
                    klines = result.get("list", [])
                    
                    # Преобразование данных
                    formatted_data = []
                    for kline in klines:
                        formatted_data.append({
                            "timestamp": datetime.fromtimestamp(int(kline[0]) / 1000),
                            "open": float(kline[1]),
                            "high": float(kline[2]),
                            "low": float(kline[3]),
                            "close": float(kline[4]),
                            "volume": float(kline[5]),
                            "turnover": float(kline[6])
                        })
                    
                    return formatted_data
        except asyncio.CancelledError:
            logger.info(f"Запрос для {ticker} отменен")
            raise
        except Exception as e:
            logger.error(f"Ошибка при получении данных для {ticker}: {e}")
            raise
    
    async def insert_data_to_db(self, conn, ticker: str, data: List[Dict]):
        """Вставка данных в базу данных"""
        try:
            if not data:
                return
            
            schema = self.settings.get('Database', 'schema', fallback='public')
            table_name = f"{ticker}_1m"
            
            # Подготовка данных для вставки
            values = []
            for row in data:
                values.append((
                    row["timestamp"],
                    row["open"],
                    row["high"],
                    row["low"],
                    row["close"],
                    row["volume"],
                    row["turnover"]
                ))
            
            # Вставка данных
            query = f"""
                INSERT INTO {schema}.{table_name} 
                (timestamp, open, high, low, close, volume, turnover)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (timestamp) DO UPDATE SET
                    open = EXCLUDED.open,
                    high = EXCLUDED.high,
                    low = EXCLUDED.low,
                    close = EXCLUDED.close,
                    volume = EXCLUDED.volume,
                    turnover = EXCLUDED.turnover
            """
            
            await conn.executemany(query, values)
            logger.info(f"Вставлено {len(values)} записей в таблицу {schema}.{table_name}")
        except asyncio.CancelledError:
            logger.info(f"Вставка данных для {ticker} отменена")
            raise
        except Exception as e:
            logger.error(f"Ошибка при вставке данных для {ticker}: {e}")
            raise
    
    def update_progress(self, processed_tickers: int, total_tickers: int, 
                       processed_minutes: int, total_minutes: int):
        """Обновление прогресса"""
        if total_tickers > 0:
            # Прогресс по тикерам
            ticker_progress = (processed_tickers / total_tickers) * 100
            
            # Прогресс по минутам (если есть данные)
            minute_progress = 0
            if total_minutes > 0:
                minute_progress = (processed_minutes / total_minutes) * 100
            
            # Общий прогресс (среднее между тикерами и минутами)
            overall_progress = (ticker_progress + minute_progress) / 2 if total_minutes > 0 else ticker_progress
            
            self.root.after(0, lambda: self.progress_value.set(overall_progress))
            self.root.after(0, lambda: self.status_text.set(
                f"Обработано тикеров: {processed_tickers}/{total_tickers} "
                f"({ticker_progress:.1f}%) | "
                f"Минут: {processed_minutes}/{total_minutes} "
                f"({minute_progress:.1f}%) | "
                f"Общий прогресс: {overall_progress:.1f}%"
            ))
    
    def finish_download(self):
        """Завершение загрузки"""
        try:
            self.download_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress_value.set(0)
            
            if self.stop_download:
                self.status_text.set("Загрузка прервана пользователем")
                logger.info("Загрузка прервана пользователем")
            else:
                self.status_text.set("Загрузка завершена")
                logger.info("Загрузка завершена успешно")
        except Exception as e:
            logger.error(f"Ошибка при завершении загрузки: {e}")
    
    def exit_program(self):
        """Выход из программы"""
        try:
            # Останавливаем загрузку если она идет
            if self.download_thread and self.download_thread.is_alive():
                self.stop_download = True
                logger.info("Остановка загрузки при выходе из программы...")
                
                # Ждем завершения потока загрузки (максимум 5 секунд)
                self.download_thread.join(timeout=5)
                if self.download_thread.is_alive():
                    logger.warning("Поток загрузки не завершился в течение 5 секунд")
            
            # Отменяем все активные асинхронные задачи
            if self.loop and not self.loop.is_closed():
                try:
                    # Отменяем все pending задачи
                    pending_tasks = asyncio.all_tasks(self.loop)
                    for task in pending_tasks:
                        if not task.done():
                            task.cancel()
                    
                    # Даем время на корректное завершение
                    if pending_tasks:
                        self.loop.run_until_complete(asyncio.wait(pending_tasks, timeout=3))
                    
                    # Закрываем loop
                    self.loop.close()
                except Exception as e:
                    logger.warning(f"Ошибка при закрытии event loop: {e}")
            
            # Сохраняем настройки
            self.save_settings()
            
            logger.info("Корректное завершение программы")
            
        except Exception as e:
            logger.error(f"Ошибка при выходе из программы: {e}")
        finally:
            # Принудительно закрываем программу
            self.root.quit()
            self.root.destroy()
    
    def run(self):
        """Запуск приложения"""
        try:
            self.root.mainloop()
        except Exception as e:
            logger.error(f"Ошибка в главном цикле приложения: {e}")
        finally:
            # Обеспечиваем корректное завершение при любых обстоятельствах
            try:
                self.exit_program()
            except:
                pass

    def set_end_date_to_now(self):
        """Установка текущего времени в поле end_date"""
        try:
            self.end_date.set(datetime.now().strftime("%Y-%m-%d %H:%M"))
            logger.info("Установлено текущее время в поле end_date")
        except Exception as e:
            logger.error(f"Ошибка при установке текущего времени: {e}")


class SettingsWindow:
    def __init__(self, parent, settings: configparser.ConfigParser, save_callback, crypto_manager):
        try:
            self.window = tk.Toplevel(parent)
            self.window.title("Настройки")
            self.window.geometry("400x300")
            self.window.resizable(False, False)
            
            self.settings = settings
            self.save_callback = save_callback
            self.crypto_manager = crypto_manager
            
            # Переменные для полей
            self.host_var = tk.StringVar(value=settings.get('Database', 'host', fallback='localhost'))
            self.port_var = tk.StringVar(value=settings.get('Database', 'port', fallback='5432'))
            self.user_var = tk.StringVar(value=settings.get('Database', 'user', fallback='postgres'))
            self.password_var = tk.StringVar(value=settings.get('Database', 'password', fallback=''))
            self.database_var = tk.StringVar(value=settings.get('Database', 'database', fallback='bybit_data'))
            self.schema_var = tk.StringVar(value=settings.get('Database', 'schema', fallback='public'))
            self.threads_var = tk.StringVar(value=settings.get('Download', 'threads', fallback='5'))
            
            self.setup_ui()
            
            # Центрирование окна
            self.window.transient(parent)
            self.window.grab_set()
            parent.wait_window(self.window)
        except Exception as e:
            logger.error(f"Ошибка при создании окна настроек: {e}")
            raise
    
    def setup_ui(self):
        """Настройка интерфейса окна настроек"""
        try:
            main_frame = ttk.Frame(self.window, padding="20")
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Заголовок
            ttk.Label(main_frame, text="Настройки подключения к базе данных", 
                     font=("Arial", 12, "bold")).pack(pady=(0, 20))
            
            # Поля ввода
            fields = [
                ("Host:", self.host_var),
                ("Port:", self.port_var),
                ("User:", self.user_var),
                ("Password:", self.password_var),
                ("Database:", self.database_var),
                ("Schema:", self.schema_var),
                ("Число потоков скачивания:", self.threads_var)
            ]
            
            for i, (label, var) in enumerate(fields):
                frame = ttk.Frame(main_frame)
                frame.pack(fill=tk.X, pady=2)
                
                ttk.Label(frame, text=label, width=20).pack(side=tk.LEFT)
                
                if label == "Password:":
                    entry = ttk.Entry(frame, textvariable=var, show="*")
                else:
                    entry = ttk.Entry(frame, textvariable=var)
                entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
            
            # Кнопки
            buttons_frame = ttk.Frame(main_frame)
            buttons_frame.pack(fill=tk.X, pady=(20, 0))
            
            ttk.Button(buttons_frame, text="Сохранить настройки", 
                      command=self.save_settings, width=20).pack(side=tk.RIGHT, padx=(10, 0))
            ttk.Button(buttons_frame, text="Отмена", 
                      command=self.window.destroy, width=20).pack(side=tk.RIGHT)
        except Exception as e:
            logger.error(f"Ошибка при настройке UI окна настроек: {e}")
            raise
    
    def save_settings(self):
        """Сохранение настроек"""
        try:
            # Валидация
            port = int(self.port_var.get())
            threads = int(self.threads_var.get())
            
            if port <= 0 or port > 65535:
                raise ValueError("Порт должен быть в диапазоне 1-65535")
            
            if threads <= 0 or threads > 50:
                raise ValueError("Число потоков должно быть в диапазоне 1-50")
            
            # Обновление настроек
            if 'Database' not in self.settings:
                self.settings['Database'] = {}
            if 'Download' not in self.settings:
                self.settings['Download'] = {}
            
            self.settings['Database']['host'] = self.host_var.get()
            self.settings['Database']['port'] = self.port_var.get()
            self.settings['Database']['user'] = self.user_var.get()
            self.settings['Database']['password'] = self.password_var.get()
            self.settings['Database']['database'] = self.database_var.get()
            self.settings['Database']['schema'] = self.schema_var.get()
            
            self.settings['Download']['threads'] = self.threads_var.get()
            
            # Сохранение (пароль будет зашифрован в save_callback)
            self.save_callback()
            
            messagebox.showinfo("Сохранение", "Настройки сохранены успешно")
            self.window.destroy()
            
        except ValueError as e:
            messagebox.showerror("Ошибка", str(e))
        except Exception as e:
            logger.error(f"Ошибка при сохранении настроек: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить настройки: {e}")


if __name__ == "__main__":
    app = ByBitDownloader()
    app.run() 