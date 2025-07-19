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
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
import logging
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import psycopg2

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
        self.filter_category = tk.StringVar(value="Все")  # Фильтр по категории
        self.status_text = tk.StringVar(value="Готов к работе")
        self.progress_value = tk.DoubleVar()
        
        # Переменные для корректного завершения
        self.active_tasks = []
        self.loop = None
        
        # Настройки
        self.settings = self.load_settings()
        
        # Восстанавливаем период из настроек
        self.start_date.set(self.settings.get('Period', 'start_date', fallback=datetime.now().strftime("%Y-%m-%d %H:%M")))
        # end_date всегда устанавливаем на текущий момент при открытии программы
        self.end_date.set(datetime.now().strftime("%Y-%m-%d %H:%M"))
        
        # Данные
        self.tickers_data = []
        self.marked_tickers = set()
        self.download_thread = None
        self.stop_download = False
        
        # Состояние выделения
        self.last_active_item = None  # Последний активный (выделенный) тикер
        
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
        
        # Текстовый фильтр
        ttk.Label(filter_frame, text="Фильтр тикеров:").grid(row=0, column=0, padx=(0, 5))
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_text)
        filter_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        filter_entry.bind("<KeyRelease>", lambda e: self.apply_filter())
        
        # Фильтр по категории
        ttk.Label(filter_frame, text="Категория:").grid(row=0, column=2, padx=(10, 5))
        category_combo = ttk.Combobox(filter_frame, textvariable=self.filter_category, 
                                     values=["Все", "Спот", "Линейный", "Обратный"], 
                                     state="readonly", width=10)
        category_combo.grid(row=0, column=3, padx=5)
        category_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())
        
        # Кнопка фильтра
        ttk.Button(filter_frame, text="Фильтр", command=self.apply_filter).grid(row=0, column=4, padx=(5, 0))
        ttk.Button(filter_frame, text="Сбросить", command=self.reset_filters).grid(row=0, column=5, padx=(5, 0))
        
        # Таблица тикеров
        table_frame = ttk.Frame(main_frame)
        table_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        
        # Создание таблицы - добавляем колонку категории
        columns = ("ticker", "category", "volume", "turnover", "change")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        # Настройка столбцов
        self.tree.heading("ticker", text="Тикер", command=lambda: self.sort_column("ticker"))
        self.tree.heading("category", text="Категория", command=lambda: self.sort_column("category"))
        self.tree.heading("volume", text="Объем", command=lambda: self.sort_column("volume"))
        self.tree.heading("turnover", text="Оборот", command=lambda: self.sort_column("turnover"))
        self.tree.heading("change", text="Изменение", command=lambda: self.sort_column("change"))
        
        self.tree.column("ticker", width=100, anchor=tk.W)
        self.tree.column("category", width=80, anchor=tk.CENTER)
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
        
        # Привязка для выделения активной строки
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        
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

        # Перемещаем Combobox уровня логирования сюда
        log_levels = ["INFO", "WARNING", "ERROR", "Не логировать"]
        self.log_level = tk.StringVar()
        saved_level = self.settings.get('Logging', 'level', fallback='INFO')
        if saved_level not in log_levels:
            saved_level = "INFO"
        self.log_level.set(saved_level)
        ttk.Label(buttons_frame, text="Уровень логирования:").pack(side=tk.LEFT, padx=(20, 5))
        log_combo = ttk.Combobox(buttons_frame, textvariable=self.log_level, values=log_levels, state="readonly", width=15)
        log_combo.pack(side=tk.LEFT, padx=5)
        log_combo.bind("<<ComboboxSelected>>", lambda e: self.set_log_level(self.log_level.get()))
        self.set_log_level(self.log_level.get())

        # Основные кнопки
        main_buttons_frame = ttk.Frame(main_frame)
        main_buttons_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.download_button = ttk.Button(main_buttons_frame, text="Загрузить", command=self.start_download, style="Accent.TButton", width=20)
        self.download_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Кнопка "Проверка" между "Загрузить" и "Прервать"
        self.check_button = ttk.Button(main_buttons_frame, text="Проверка", command=self.check_missing_periods, width=20)
        self.check_button.pack(side=tk.LEFT, padx=5)
        
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
        
        # Настройка тега для активной строки
        self.tree.tag_configure("active", background="lightyellow")
    
    def load_settings(self) -> configparser.ConfigParser:
        """Загрузка настроек из файла"""
        try:
            config = configparser.ConfigParser()
            if os.path.exists('settings.ini'):
                config.read('settings.ini', encoding='utf-8')
                logger.info("Настройки загружены из файла")
            else:
                logger.info("Файл настроек не найден, используются значения по умолчанию")
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
                    'threads': '5',
                    'timeout': '10'
                }
            if 'Period' not in config:
                config['Period'] = {
                    'start_date': datetime.now().strftime("%Y-%m-%d %H:%M"),
                    'end_date': datetime.now().strftime("%Y-%m-%d %H:%M")
                }
            if 'Logging' not in config:
                config['Logging'] = {'level': 'INFO'}
            return config
        except Exception as e:
            logger.error(f"Ошибка при загрузке настроек: {e}")
            config = configparser.ConfigParser()
            config['Database'] = {
                'host': 'localhost',
                'port': '5432',
                'user': 'postgres',
                'password': '',
                'database': 'bybit_data',
                'schema': 'public'
            }
            config['Download'] = {'threads': '5', 'timeout': '10'}
            config['Period'] = {
                'start_date': datetime.now().strftime("%Y-%m-%d %H:%M"),
                'end_date': datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            config['Logging'] = {'level': 'INFO'}
            return config

    def save_settings(self):
        """Сохранение настроек в файл"""
        try:
            if 'Period' not in self.settings:
                self.settings['Period'] = {}
            self.settings['Period']['start_date'] = self.start_date.get()
            self.settings['Period']['end_date'] = self.end_date.get()
            if 'Database' in self.settings and 'password' in self.settings['Database']:
                password = self.settings['Database']['password']
                if password and not password.startswith('encrypted:'):
                    encrypted_password = self.crypto_manager.encrypt(password)
                    self.settings['Database']['password'] = f"encrypted:{encrypted_password}"
            # Сохраняем уровень логирования
            if 'Logging' not in self.settings:
                self.settings['Logging'] = {}
            self.settings['Logging']['level'] = self.log_level.get()
            # Сохраняем таймаут
            if 'Download' not in self.settings:
                self.settings['Download'] = {}
            self.settings['Download']['timeout'] = str(getattr(self, 'timeout_var', tk.StringVar(value='10')).get())
            with open('settings.ini', 'w', encoding='utf-8') as f:
                self.settings.write(f)
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
        """Получение списка тикеров с ByBit API (спот + фьючерсы)"""
        try:
            import requests
            
            url = "https://api.bybit.com/v5/market/tickers"
            all_tickers = []
            
            # Категории для загрузки
            categories = ["spot", "linear", "inverse"]
            
            for category in categories:
                try:
                    params = {"category": category}
                    response = requests.get(url, params=params, timeout=30)
                    response.raise_for_status()
                    
                    data = response.json()
                    
                    if data.get("retCode") != 0:
                        logger.warning(f"API ошибка для категории {category}: {data.get('retMsg', 'Неизвестная ошибка')}")
                        continue
                    
                    result = data.get("result", {})
                    instruments = result.get("list", [])
                    
                    for instrument in instruments:
                        symbol = instrument.get("symbol")
                        if symbol:
                            # Добавляем префикс категории для различения
                            if category == "spot":
                                display_symbol = symbol
                            else:
                                display_symbol = f"{symbol}_{category}"
                            
                            all_tickers.append({
                                "symbol": display_symbol,
                                "original_symbol": symbol,
                                "category": category,
                                "volume24h": float(instrument.get("volume24h", 0)),
                                "turnover24h": float(instrument.get("turnover24h", 0)),
                                "priceChangePercent": float(instrument.get("price24hPcnt", 0)) * 100
                            })
                    
                    logger.info(f"Получено {len(instruments)} тикеров категории {category}")
                    
                except requests.exceptions.Timeout:
                    logger.warning(f"Таймаут при получении тикеров категории {category}")
                    continue
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Ошибка сети при получении тикеров категории {category}: {e}")
                    continue
                except Exception as e:
                    logger.warning(f"Ошибка при получении тикеров категории {category}: {e}")
                    continue
            
            # Сортировка по объему
            all_tickers.sort(key=lambda x: x["volume24h"], reverse=True)
            
            logger.info(f"Всего получено {len(all_tickers)} тикеров (спот + фьючерсы)")
            return all_tickers
            
        except Exception as e:
            logger.error(f"Критическая ошибка при получении тикеров: {e}")
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
                category = ticker['category']
                volume = f"{int(ticker['volume24h']):,}".replace(",", " ")
                turnover = f"{int(ticker['turnover24h']):,}".replace(",", " ")
                change = f"{ticker['priceChangePercent']:.2f}%"
                
                # Преобразование категории для отображения
                if category == "spot":
                    display_category = "Спот"
                elif category == "linear":
                    display_category = "Линейный"
                elif category == "inverse":
                    display_category = "Обратный"
                else:
                    display_category = category
                
                item = self.tree.insert("", tk.END, values=(symbol, display_category, volume, turnover, change))
                
                # Применяем пометки
                if symbol in self.marked_tickers:
                    self.tree.selection_add(item)
            
            # Первичная сортировка по обороту в обратном порядке
            self.sort_column_initial("turnover")
            
            # Применяем фильтры если они установлены
            if self.filter_text.get().strip() or self.filter_category.get() != "Все":
                self.apply_filter()
            
            # Обновляем счетчик
            self.update_marked_count_status()
            logger.info(f"Таблица обновлена: {len(self.tickers_data)} тикеров")
        except Exception as e:
            logger.error(f"Ошибка при обновлении таблицы тикеров: {e}")
    
    def apply_filter(self):
        """Применение фильтра к таблице"""
        try:
            filter_text = self.filter_text.get().strip().upper()
            filter_category = self.filter_category.get()
            
            # Показываем/скрываем строки
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                symbol = values[0]
                category = values[1]
                
                # Проверяем текстовый фильтр
                text_match = not filter_text or filter_text in symbol
                
                # Проверяем фильтр по категории
                category_match = filter_category == "Все" or category == filter_category
                
                # Показываем строку только если оба фильтра пройдены
                if text_match and category_match:
                    self.tree.reattach(item, "", "end")
                else:
                    self.tree.detach(item)
            
            # Обновляем счетчик
            self.update_marked_count_status()
            logger.info(f"Применен фильтр: текст='{filter_text}', категория='{filter_category}'")
        except Exception as e:
            logger.error(f"Ошибка при применении фильтра: {e}")
    
    def sort_column_initial(self, column):
        """Первичная сортировка таблицы по колонке (без учета предыдущего состояния)"""
        try:
            # Сбрасываем состояние Shift+выделения
            self.is_shift_selecting = False
            self.shift_click_start = None
            
            # Получаем текущие данные
            data = []
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                data.append(values)
            
            # Определяем индекс колонки
            column_index = {"ticker": 0, "category": 1, "volume": 2, "turnover": 3, "change": 4}.get(column, 0)
            
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
            # Сбрасываем состояние Shift+выделения
            self.is_shift_selecting = False
            self.shift_click_start = None
            
            # Получаем текущие данные
            data = []
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                data.append(values)
            
            # Определяем индекс колонки - используем названия колонок из заголовков
            column_index = {"ticker": 0, "category": 1, "volume": 2, "turnover": 3, "change": 4}.get(column, 0)
            
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
                
                # Обновляем последний активный тикер
                self.last_active_item = item
                
                # Выделяем активную строку
                self.highlight_active_row()
                
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
                else:
                    self.marked_tickers.add(symbol)
                
                # Обновляем последний активный тикер
                self.last_active_item = item
                
                # Синхронизируем визуальное выделение со всеми помеченными тикерами
                self.update_table_selection()
                
                # Выделяем активную строку
                self.highlight_active_row()
                
                # Принудительно обновляем UI
                self.root.update_idletasks()
                
                # Отложенно обновляем визуальное выделение через 10мс
                self.root.after(10, self.update_table_selection)
                
                # Отложенно обновляем счетчик через 20мс
                self.root.after(20, self.update_marked_count_status)
        except Exception as e:
            logger.error(f"Ошибка при обработке Ctrl+клика по таблице: {e}")

    def on_tree_shift_click(self, event):
        """Обработка Shift+клика по таблице"""
        try:
            item = self.tree.identify_row(event.y)
            if item:
                symbol = self.tree.item(item, "values")[0]
                
                # Если есть последний активный тикер и он отличается от текущего, выделяем диапазон
                if self.last_active_item and self.last_active_item != item:
                    self.select_range(self.last_active_item, item)
                else:
                    # Если нет последнего активного тикера или он совпадает с текущим, просто добавляем текущий
                    self.marked_tickers.add(symbol)
                    self.tree.selection_add(item)
                
                # Обновляем последний активный тикер на текущий
                self.last_active_item = item
                
                # Выделяем активную строку
                self.highlight_active_row()
                
                # Предотвращаем стандартную обработку клика
                return "break"
        except Exception as e:
            logger.error(f"Ошибка при обработке Shift+клика по таблице: {e}")
    
    def select_range(self, start_item, end_item):
        """Выделение диапазона от start_item до end_item"""
        try:
            # Получаем все элементы таблицы
            all_items = self.tree.get_children()
            logger.debug(f"select_range: всего элементов в таблице: {len(all_items)}")
            
            # Проверяем, что start_item и end_item действительно существуют в all_items
            if start_item not in all_items:
                logger.error(f"ОШИБКА: start_item {start_item} не найден в all_items")
                return
            if end_item not in all_items:
                logger.error(f"ОШИБКА: end_item {end_item} не найден в all_items")
                return
            
            logger.debug(f"start_item и end_item найдены в all_items")
            
            # Находим индексы начального и конечного элементов
            start_index = -1
            end_index = -1
            
            logger.debug(f"Ищем start_item={start_item}, end_item={end_item}")
            
            for i, item in enumerate(all_items):
                if item == start_item:
                    start_index = i
                    logger.debug(f"Найден start_index={i}")
                if item == end_item:
                    end_index = i
                    logger.debug(f"Найден end_index={i}")
                if start_index != -1 and end_index != -1:
                    break
            
            if start_index == -1 or end_index == -1:
                logger.warning(f"Не найдены индексы: start_index={start_index}, end_index={end_index}")
                logger.warning(f"start_item={start_item}, end_item={end_item}")
                logger.warning(f"Доступные элементы: {all_items[:5]}{'...' if len(all_items) > 5 else ''}")
                return
            
            # Определяем диапазон (от меньшего к большему индексу)
            range_start = min(start_index, end_index)
            range_end = max(start_index, end_index)
            
            # Сохраняем количество помеченных тикеров до выделения
            old_marked_count = len(self.marked_tickers)
            
            # Очищаем предыдущие выделения в таблице, но НЕ очищаем marked_tickers
            self.tree.selection_remove(self.tree.selection())
            
            # Добавляем тикеры из диапазона к уже существующим
            selected_symbols = []
            for i in range(range_start, range_end + 1):
                item = all_items[i]
                symbol = self.tree.item(item, "values")[0]
                self.marked_tickers.add(symbol)  # add() добавляет только если элемента нет
                selected_symbols.append(symbol)
                self.tree.selection_add(item)
            
            # Синхронизируем визуальное выделение со всеми помеченными тикерами
            self.update_table_selection()
            
            new_marked_count = len(self.marked_tickers)
            logger.info(f"Выделен диапазон: {range_end - range_start + 1} тикеров, marked_tickers: {old_marked_count} → {new_marked_count}")
            
            # Проверяем, что все selected_symbols действительно добавлены в marked_tickers
            missing_symbols = [s for s in selected_symbols if s not in self.marked_tickers]
            if missing_symbols:
                logger.error(f"ОШИБКА: Не добавлены в marked_tickers: {missing_symbols}")
            
            # Отложенно обновляем счетчик для обеспечения правильной синхронизации
            self.root.after(10, self.update_marked_count_status)
        except Exception as e:
            logger.error(f"Ошибка при выделении диапазона: {e}")

    def on_tree_release(self, event):
        try:
            # Обновляем счетчик и восстанавливаем активную строку
            self.update_marked_count_status()
            self.root.after(10, self.highlight_active_row)
        except Exception as e:
            logger.error(f"Ошибка при обработке отпускания кнопки мыши: {e}")
    
    def on_tree_select(self, event):
        """Обработка события выбора строки в таблице"""
        try:
            selected_items = self.tree.selection()
            if selected_items:
                new_active_item = selected_items[0]
                if new_active_item != self.last_active_item:
                    self.last_active_item = new_active_item
                    logger.debug(f"Выбор изменен на: {self.tree.item(new_active_item, 'values')[0]}")
                self.highlight_active_row()
                self.update_marked_count_status()
        except Exception as e:
            logger.error(f"Ошибка при обработке события выбора строки: {e}")
    
    def highlight_active_row(self):
        """Выделение активной строки другим цветом"""
        try:
            # Убираем тег "active" со всех строк, но сохраняем другие теги
            for item in self.tree.get_children():
                current_tags = list(self.tree.item(item, "tags"))
                if "active" in current_tags:
                    current_tags.remove("active")
                self.tree.item(item, tags=current_tags)
            
            # Выделяем активную строку, добавляя тег "active" к существующим тегам
            if self.last_active_item:
                current_tags = list(self.tree.item(self.last_active_item, "tags"))
                if "active" not in current_tags:
                    current_tags.append("active")
                self.tree.item(self.last_active_item, tags=current_tags)
                self.tree.see(self.last_active_item)
        except Exception as e:
            logger.error(f"Ошибка при выделении активной строки: {e}")

    def exit_program(self):
        try:
            # Останавливаем загрузку если она идет
            if hasattr(self, 'download_thread') and self.download_thread and self.download_thread.is_alive():
                self.stop_download = True
                logger.info("Остановка загрузки при выходе из программы...")
                self.download_thread.join(timeout=5)
                if self.download_thread.is_alive():
                    logger.warning("Поток загрузки не завершился в течение 5 секунд")
            # Сохраняем настройки
            self.save_settings()
            logger.info("Корректное завершение программы")
        except Exception as e:
            logger.error(f"Ошибка при выходе из программы: {e}")
        finally:
            self.root.quit()
            self.root.destroy()

    def set_end_date_to_now(self):
        try:
            self.end_date.set(datetime.now().strftime("%Y-%m-%d %H:%M"))
            logger.info("Установлено текущее время в поле end_date")
        except Exception as e:
            logger.error(f"Ошибка при установке текущего времени: {e}")

    def reset_filters(self):
        try:
            self.filter_text.set("")
            self.filter_category.set("Все")
            self.apply_filter()
            self.update_marked_count_status()
            logger.info("Фильтры сброшены")
        except Exception as e:
            logger.error(f"Ошибка при сбросе фильтров: {e}")

    def mark_all(self):
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

    def get_visible_tickers(self):
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
        try:
            all_items = self.tree.get_children()
            current_selection = self.tree.selection()
            self.tree.selection_remove(current_selection)
            items_to_select = []
            for item in all_items:
                symbol = self.tree.item(item, "values")[0]
                if symbol in self.marked_tickers:
                    items_to_select.append(item)
            if items_to_select:
                self.tree.selection_set(items_to_select)
                self.tree.see(items_to_select[0])
            self.root.after(5, self.highlight_active_row)
        except Exception as e:
            logger.error(f"Ошибка при синхронизации выделения таблицы: {e}")

    def update_marked_count_status(self):
        try:
            self.root.update_idletasks()
            visible_tickers = self.get_visible_tickers()
            marked_visible = sum(1 for ticker in visible_tickers if ticker in self.marked_tickers)
            total_visible = len(visible_tickers)
            total_marked = len(self.marked_tickers)
            status_text = f"Помечено: {marked_visible}/{total_visible} видимых, {total_marked} всего"
            self.status_text.set(status_text)
        except Exception as e:
            logger.error(f"Ошибка при обновлении счетчика тикеров: {e}")

    def start_download(self):
        try:
            # Создание/обновление функции generate_minute_intervals в базе
            schema = self.settings.get('Database', 'schema', fallback='public')
            query = f"""
                CREATE OR REPLACE FUNCTION {schema}.generate_minute_intervals(start_time timestamp, end_time timestamp)
                RETURNS TABLE (minute_timestamp timestamp) AS $$
                BEGIN
                    RETURN QUERY
                    WITH RECURSIVE time_series AS (
                        SELECT start_time AS minute
                        UNION ALL
                        SELECT minute + interval '1 minute'
                        FROM time_series
                        WHERE minute < end_time
                    )
                    SELECT minute FROM time_series;
                END;
                $$ LANGUAGE plpgsql;
            """
            # Создание таблицы earliest_timestamp
            create_earliest_table = f"""
                CREATE TABLE IF NOT EXISTS {schema}.earliest_timestamp (
                    ticker TEXT PRIMARY KEY,
                    date DATE NOT NULL,
                    earliest_ts TIMESTAMP NOT NULL
                );
            """
            try:
                conn = psycopg2.connect(
                    host=self.settings.get('Database', 'host'),
                    port=self.settings.get('Database', 'port'),
                    user=self.settings.get('Database', 'user'),
                    password=self.crypto_manager.decrypt(self.settings.get('Database', 'password').replace('encrypted:', '')),
                    database=self.settings.get('Database', 'database')
                )
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute(query)
                    cur.execute(create_earliest_table)
                conn.close()
                logger.info("Функции и таблицы успешно созданы/обновлены в базе данных")
            except Exception as e:
                logger.error(f"Ошибка при создании функции или таблицы: {e}")
                messagebox.showerror("Ошибка", f"Ошибка при создании функции или таблицы: {e}")
                return
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

            # Запуск расчета earliest timestamp в отдельном потоке
            threading.Thread(target=self._prepare_and_start_download, args=(start_dt, end_dt), daemon=True).start()
        except Exception as e:
            error_msg = f"Ошибка при запуске загрузки: {e}"
            logger.error(error_msg)
            messagebox.showerror("Ошибка", error_msg)
            self.finish_download()

    def _prepare_and_start_download(self, start_dt, end_dt):
        try:
            import requests
            schema = self.settings.get('Database', 'schema', fallback='public')
            adjusted_periods = []
            total_minutes = 0
            marked_count = len(self.marked_tickers)
            today = datetime.now().date()
            yesterday = today - timedelta(days=1)
            conn = psycopg2.connect(
                host=self.settings.get('Database', 'host'),
                port=self.settings.get('Database', 'port'),
                user=self.settings.get('Database', 'user'),
                password=self.crypto_manager.decrypt(self.settings.get('Database', 'password').replace('encrypted:', '')),
                database=self.settings.get('Database', 'database')
            )
            conn.autocommit = True
            for idx, ticker in enumerate(list(self.marked_tickers), 1):
                if ticker.endswith("_linear"):
                    category = "linear"
                    original_symbol = ticker[:-7]
                elif ticker.endswith("_inverse"):
                    category = "inverse"
                    original_symbol = ticker[:-8]
                else:
                    category = "spot"
                    original_symbol = ticker
                with conn.cursor() as cur:
                    cur.execute(f"SELECT earliest_ts, date FROM {schema}.earliest_timestamp WHERE ticker = %s", (ticker,))
                    row = cur.fetchone()
                    use_db = False
                    if row:
                        db_earliest, db_date = row
                        if db_date >= yesterday:
                            earliest_ts = db_earliest
                            use_db = True
                        else:
                            earliest_ts = None
                    else:
                        earliest_ts = None
                if not use_db:
                    api_earliest = self._get_earliest_timestamp_bybit(original_symbol, category)
                    if api_earliest is None:
                        logger.warning(f"Не удалось получить earliest timestamp для {ticker}, будет использоваться выбранная дата")
                        real_start = start_dt
                    else:
                        earliest_ts = api_earliest
                        with conn.cursor() as cur:
                            cur.execute(f"INSERT INTO {schema}.earliest_timestamp (ticker, date, earliest_ts) VALUES (%s, %s, %s) "
                                        f"ON CONFLICT (ticker) DO UPDATE SET date = EXCLUDED.date, earliest_ts = EXCLUDED.earliest_ts",
                                        (ticker, today, earliest_ts))
                        real_start = max(start_dt, earliest_ts)
                else:
                    real_start = max(start_dt, earliest_ts)
                if real_start >= end_dt:
                    logger.info(f"Для {ticker} нет данных для скачивания в выбранном периоде")
                    continue
                adjusted_periods.append((ticker, real_start, end_dt))
                total_minutes += int((end_dt - real_start).total_seconds() / 60)
                # Обновляем строку состояния из потока
                self.root.after(0, lambda idx=idx, marked_count=marked_count: self.status_text.set(f"Определено первых свечей для {idx} из {marked_count} тикеров..."))
                self.root.after(0, self.root.update_idletasks)
            conn.close()
            # После завершения — явно обновить строку состояния
            self.root.after(0, lambda: self.status_text.set(f"Определено первых свечей для {marked_count} из {marked_count} тикеров."))
            self.root.after(0, self.root.update_idletasks)
            if not adjusted_periods:
                self.root.after(0, lambda: messagebox.showinfo("Нет данных", "Нет тикеров с доступными данными для скачивания в выбранном периоде."))
                return
            # Запуск загрузки в отдельном потоке
            self.stop_download = False
            self.download_thread = threading.Thread(
                target=self.download_process,
                args=(adjusted_periods, total_minutes),
            )
            self.download_thread.daemon = True
            self.download_thread.start()
            # Обновление UI
            self.root.after(0, lambda: self.download_button.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.stop_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.progress_value.set(0))
            self.root.after(0, lambda: self.status_text.set(f"Начало загрузки {len(adjusted_periods)} тикеров..."))
        except Exception as e:
            error_msg = f"Ошибка при подготовке к загрузке: {e}"
            logger.error(error_msg)
            self.root.after(0, lambda: messagebox.showerror("Ошибка", error_msg))
            self.root.after(0, self.finish_download)

    def download_process(self, adjusted_periods, total_minutes):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.async_download(adjusted_periods, total_minutes))
            loop.close()
        except Exception as e:
            logger.error(f"Ошибка в процессе загрузки: {e}")
            self.root.after(0, lambda: self.status_text.set(f"Ошибка загрузки: {e}"))
        finally:
            self.root.after(0, self.finish_download)

    async def async_download(self, adjusted_periods, total_minutes):
        try:
            progress_state = {
                'processed_tickers': 0,
                'processed_minutes': 0,
                'lock': asyncio.Lock()
            }
            max_connections = int(self.settings.get('Download', 'threads', fallback='5'))
            semaphore = asyncio.Semaphore(max_connections)
            progress_task = asyncio.create_task(
                self.progress_updater(progress_state, len(adjusted_periods), total_minutes)
            )
            tasks = []
            for ticker, real_start, real_end in adjusted_periods:
                if self.stop_download:
                    break
                task = asyncio.create_task(
                    self.download_ticker_data(ticker, real_start, real_end, semaphore, progress_state)
                )
                tasks.append(task)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
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

    def stop_download_process(self):
        try:
            self.stop_download = True
            self.status_text.set("Остановка загрузки...")
            logger.info("Запрошена остановка загрузки")
        except Exception as e:
            logger.error(f"Ошибка при остановке загрузки: {e}")

    def open_settings(self):
        try:
            SettingsWindow(self.root, self.settings, self.save_settings, self.crypto_manager)
        except Exception as e:
            logger.error(f"Ошибка при открытии окна настроек: {e}")
            messagebox.showerror("Ошибка", f"Не удалось открыть окно настроек: {e}")

    def run(self):
        try:
            self.root.mainloop()
        except Exception as e:
            logger.error(f"Ошибка в главном цикле приложения: {e}")

    def finish_download(self):
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

    async def progress_updater(self, progress_state, total_tickers, total_minutes):
        try:
            while not self.stop_download:
                async with progress_state['lock']:
                    processed_tickers = progress_state['processed_tickers']
                    processed_minutes = progress_state['processed_minutes']
                self.root.after(0, lambda: self.update_progress(
                    processed_tickers, total_tickers, processed_minutes, total_minutes
                ))
                if processed_tickers >= total_tickers:
                    break
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            logger.info("Обновление прогресса отменено")
            raise
        except Exception as e:
            logger.error(f"Ошибка в обновлении прогресса: {e}")
            raise

    async def download_ticker_data(self, ticker, start_dt, end_dt, semaphore, progress_state):
        async with semaphore:
            try:
                import asyncpg
                conn = await asyncpg.connect(
                    host=self.settings.get('Database', 'host'),
                    port=self.settings.get('Database', 'port'),
                    user=self.settings.get('Database', 'user'),
                    password=self.crypto_manager.decrypt(self.settings.get('Database', 'password').replace('encrypted:', '')),
                    database=self.settings.get('Database', 'database')
                )
                try:
                    await self.create_ticker_table(conn, ticker)
                    # Считаем уже существующие минуты в базе
                    schema = self.settings.get('Database', 'schema', fallback='public')
                    table_name = f"klines_{ticker.lower().replace('-', '_')}"
                    count_query = f"""
                        SELECT COUNT(*) FROM {schema}.{table_name}
                        WHERE timestamp >= $1 AND timestamp < $2
                    """
                    row = await conn.fetchrow(count_query, start_dt, end_dt)
                    existing_minutes = row[0] if row else 0
                    async with progress_state['lock']:
                        progress_state['processed_minutes'] += existing_minutes
                    gaps = await self.find_data_gaps(conn, ticker, start_dt, end_dt)
                    if gaps:
                        logger.info(f"Найдено {len(gaps)} пропусков в данных для {ticker}")
                        for gap_start, gap_end in gaps:
                            if self.stop_download:
                                break
                            await self.download_period_data(conn, ticker, gap_start, gap_end, progress_state)
                    else:
                        logger.info(f"Пропусков в данных для {ticker} не найдено")
                    async with progress_state['lock']:
                        progress_state['processed_tickers'] += 1
                finally:
                    await conn.close()
            except asyncio.CancelledError:
                logger.info(f"Загрузка данных для {ticker} отменена")
                raise
            except Exception as e:
                logger.error(f"Ошибка при загрузке данных для {ticker}: {e}")
                async with progress_state['lock']:
                    progress_state['processed_tickers'] += 1

    async def find_data_gaps(self, conn, ticker, start_dt, end_dt):
        try:
            schema = self.settings.get('Database', 'schema', fallback='public')
            table_name = f"klines_{ticker.lower().replace('-', '_')}"
            query = f"""
                SELECT minute_timestamp as timestamp
                FROM {schema}.generate_minute_intervals($1, $2) as f
                LEFT JOIN {schema}.{table_name} as t ON f.minute_timestamp = t.timestamp
                WHERE t.timestamp IS NULL
                ORDER BY minute_timestamp
            """
            rows = await conn.fetch(query, start_dt, end_dt)
            missing_minutes = [row['timestamp'] for row in rows]
            if not missing_minutes:
                return []
            # Группируем пропущенные минуты в интервалы
            gaps = []
            gap_start = missing_minutes[0]
            prev_minute = missing_minutes[0]
            for minute in missing_minutes[1:]:
                if (minute - prev_minute).total_seconds() > 60:
                    gaps.append((gap_start, prev_minute + timedelta(minutes=1)))
                    gap_start = minute
                prev_minute = minute
            gaps.append((gap_start, prev_minute + timedelta(minutes=1)))
            return gaps
        except asyncio.CancelledError:
            logger.info(f"Поиск пропусков для {ticker} отменен")
            raise
        except Exception as e:
            logger.error(f"Ошибка при поиске пропусков для {ticker}: {e}")
            raise

    async def create_ticker_table(self, conn, ticker):
        try:
            schema = self.settings.get('Database', 'schema', fallback='public')
            table_name = f"klines_{ticker.lower().replace('-', '_')}"
            await conn.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
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

    async def download_period_data(self, conn, ticker, start_dt, end_dt, progress_state):
        try:
            block_size = timedelta(minutes=600)
            current_start = start_dt
            logger.info(f"Начало загрузки данных для {ticker} за период {start_dt} - {end_dt}")
            while current_start < end_dt and not self.stop_download:
                current_end = min(current_start + block_size, end_dt)
                logger.info(f"Пробую загрузить данные для {ticker}: {current_start} - {current_end}")
                for attempt in range(3):
                    try:
                        data = await self.fetch_bybit_data(ticker, current_start, current_end)
                        logger.info(f"fetch_bybit_data вернул {len(data) if data else 0} строк для {ticker} за период {current_start} - {current_end}")
                        if data:
                            await self.insert_data_to_db(conn, ticker, data)
                            minutes_processed = int((current_end - current_start).total_seconds() / 60)
                            async with progress_state['lock']:
                                progress_state['processed_minutes'] += minutes_processed
                            logger.info(f"Загружено {len(data)} записей для {ticker} за период {current_start} - {current_end}")
                            break
                        else:
                            logger.info(f"Пустой ответ от API для {ticker} за период {current_start} - {current_end}")
                            break
                    except asyncio.CancelledError:
                        logger.info(f"Загрузка данных для {ticker} отменена")
                        raise
                    except Exception as e:
                        if attempt == 2:
                            logger.error(f"Не удалось загрузить данные для {ticker} за период {current_start}-{current_end}: {e}")
                            raise
                        else:
                            logger.warning(f"Попытка {attempt + 1} для {ticker} за период {current_start}-{current_end}: {e}")
                            await asyncio.sleep(2)
                logger.info(f"current_start={current_start}, current_end={current_end}, end_dt={end_dt}")
                current_start = current_end
            logger.info(f"Завершена загрузка данных для {ticker} за период {start_dt} - {end_dt}")
        except asyncio.CancelledError:
            logger.info(f"Загрузка периода для {ticker} отменена")
            raise
        except Exception as e:
            logger.error(f"Ошибка при загрузке периода для {ticker}: {e}")
            raise

    async def fetch_bybit_data(self, ticker, start_dt, end_dt):
        import aiohttp
        import logging
        timeout_sec = int(self.settings.get('Download', 'timeout', fallback='10'))
        error_logger = logging.getLogger('bybit_errors')
        if not error_logger.handlers:
            handler = logging.FileHandler('bybit_errors.log', encoding='utf-8')
            handler.setLevel(logging.ERROR)
            error_logger.addHandler(handler)
        url = "https://api.bybit.com/v5/market/kline"
        start_ms = int(start_dt.timestamp() * 1000)
        end_ms = int(end_dt.timestamp() * 1000)
        if ticker.endswith("_linear"):
            category = "linear"
            original_symbol = ticker[:-7]
        elif ticker.endswith("_inverse"):
            category = "inverse"
            original_symbol = ticker[:-8]
        else:
            category = "spot"
            original_symbol = ticker
        params = {
            "category": category,
            "symbol": original_symbol,
            "interval": "1",
            "start": start_ms,
            "end": end_ms,
            "limit": 1000
        }
        for attempt in range(3):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params, timeout=timeout_sec) as response:
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}: {await response.text()}")
                        data = await response.json()
                        if data.get("retCode") != 0:
                            raise Exception(f"API ошибка: {data.get('retMsg', 'Неизвестная ошибка')}")
                        result = data.get("result", {})
                        klines = result.get("list", [])
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
            except asyncio.TimeoutError:
                logger.warning(f"Таймаут при получении данных для {ticker} за {start_dt} (попытка {attempt+1}/3)")
                if attempt == 2:
                    error_logger.error(f"Таймаут для {ticker} на минуте {start_dt}")
            except Exception as e:
                logger.warning(f"Ошибка при получении данных для {ticker} за {start_dt} (попытка {attempt+1}/3): {e}")
                if attempt == 2:
                    error_logger.error(f"Ошибка для {ticker} на минуте {start_dt}: {e}")
            await asyncio.sleep(2)
        # После 3 неудачных попыток
        logger.error(f"Не удалось скачать данные для {ticker} на минуте {start_dt} после 3 попыток")
        return None

    async def insert_data_to_db(self, conn, ticker, data):
        try:
            if not data:
                return
            schema = self.settings.get('Database', 'schema', fallback='public')
            # Replace hyphens with underscores in the table name
            table_name = f"klines_{ticker.lower().replace('-', '_')}"
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

    def update_progress(self, processed_tickers, total_tickers, processed_minutes, total_minutes):
        # Защита от None
        processed_tickers = processed_tickers or 0
        total_tickers = total_tickers or 0
        processed_minutes = processed_minutes or 0
        total_minutes = total_minutes or 0
        if total_tickers > 0:
            ticker_progress = (processed_tickers / total_tickers) * 100
            minute_progress = 0
            if total_minutes > 0:
                minute_progress = (processed_minutes / total_minutes) * 100
            overall_progress = (ticker_progress + minute_progress) / 2 if total_minutes > 0 else ticker_progress
            status = (
                f"Обработано тикеров: {processed_tickers:,} / {total_tickers:,} "
                f"({ticker_progress:.1f}%) | "
                f"Минут: {processed_minutes:,} / {total_minutes:,} "
                f"({minute_progress:.1f}%) | "
                f"Общий прогресс: {overall_progress:.1f}%"
            )
            self.root.after(0, lambda: self.progress_value.set(overall_progress))
            self.root.after(0, lambda: self.status_text.set(status.replace(",", " ")))

    def set_log_level(self, level):
        import logging
        root_logger = logging.getLogger()
        if level == "Не логировать":
            root_logger.disabled = True
        else:
            root_logger.disabled = False
            if level == "INFO":
                root_logger.setLevel(logging.INFO)
            elif level == "WARNING":
                root_logger.setLevel(logging.WARNING)
            elif level == "ERROR":
                root_logger.setLevel(logging.ERROR)

    def check_missing_periods(self):
        """Проверка пропущенных свечей по выделенным тикерам и формирование отчета"""
        try:
            if not self.marked_tickers:
                messagebox.showwarning("Проверка", "Не выбрано ни одного тикера для проверки.")
                return
            # Парсинг дат
            try:
                start_dt = datetime.strptime(self.start_date.get(), "%Y-%m-%d %H:%M")
                end_dt = datetime.strptime(self.end_date.get(), "%Y-%m-%d %H:%M")
            except ValueError:
                messagebox.showerror("Ошибка", "Неверный формат даты. Используйте формат: YYYY-MM-DD HH:MM")
                return
            if start_dt >= end_dt:
                messagebox.showerror("Ошибка", "Начальная дата должна быть меньше конечной")
                return
            # Запуск проверки в отдельном потоке, чтобы не блокировать UI
            threading.Thread(target=self._check_missing_periods_thread, args=(start_dt, end_dt, list(self.marked_tickers)), daemon=True).start()
        except Exception as e:
            logger.error(f"Ошибка при запуске проверки пропущенных свечей: {e}")
            messagebox.showerror("Ошибка", f"Ошибка при запуске проверки: {e}")

    def _check_missing_periods_thread(self, start_dt, end_dt, tickers):
        try:
            self.status_text.set("Проверка пропущенных свечей...")
            self.root.after(0, self.progress_bar.start)
            import requests
            import psycopg2
            from collections import defaultdict
            report = []
            # Подключение к базе
            conn = psycopg2.connect(
                host=self.settings.get('Database', 'host'),
                port=self.settings.get('Database', 'port'),
                user=self.settings.get('Database', 'user'),
                password=self.crypto_manager.decrypt(self.settings.get('Database', 'password').replace('encrypted:', '')),
                database=self.settings.get('Database', 'database')
            )
            schema = self.settings.get('Database', 'schema', fallback='public')
            for ticker in sorted(tickers):
                # Определяем категорию и оригинальный символ
                if ticker.endswith("_linear"):
                    category = "linear"
                    original_symbol = ticker[:-7]
                elif ticker.endswith("_inverse"):
                    category = "inverse"
                    original_symbol = ticker[:-8]
                else:
                    category = "spot"
                    original_symbol = ticker
                # Получаем earliest timestamp через ByBit API
                earliest_ts = self._get_earliest_timestamp_bybit(original_symbol, category)
                if earliest_ts is None:
                    logger.warning(f"Не удалось получить earliest timestamp для {ticker}")
                    continue
                # Если earliest позже выбранного периода, пропускаем
                if earliest_ts > end_dt:
                    continue
                period_start = max(start_dt, earliest_ts)
                # Получаем все минуты периода
                minutes = []
                cur = conn.cursor()
                cur.execute(f"SELECT minute_timestamp FROM {schema}.generate_minute_intervals(%s, %s)", (period_start, end_dt))
                minutes = [row[0] for row in cur.fetchall()]
                # Получаем существующие свечи
                table_name = f"klines_{ticker.lower().replace('-', '_')}"
                cur.execute(f"SELECT timestamp FROM {schema}.{table_name} WHERE timestamp >= %s AND timestamp < %s", (period_start, end_dt))
                existing = set(row[0] for row in cur.fetchall())
                # Пропущенные минуты
                missing = sorted([m for m in minutes if m not in existing])
                # Группируем пропущенные минуты в интервалы
                if missing:
                    interval_start = missing[0]
                    interval_end = missing[0]
                    for m in missing[1:]:
                        if (m - interval_end).total_seconds() == 60:
                            interval_end = m
                        else:
                            report.append((ticker, interval_start, interval_end))
                            interval_start = m
                            interval_end = m
                    report.append((ticker, interval_start, interval_end))
                cur.close()
            conn.close()
            # Сортировка отчета
            report.sort(key=lambda x: (x[0], x[1]))
            # Запись в файл
            report_path = os.path.abspath("bybit_missing_report.txt")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("Тикер\tНачальная свеча\tКонечная свеча\n")
                for ticker, ts_start, ts_end in report:
                    f.write(f"{ticker}\t{ts_start.strftime('%Y-%m-%d %H:%M')}\t{ts_end.strftime('%Y-%m-%d %H:%M')}\n")
            self.status_text.set(f"Проверка завершена. Найдено пропущенных интервалов: {len(report)}")
            logger.info(f"Проверка завершена. Отчет: {report_path}")
            # Открыть файл
            os.startfile(report_path)
        except Exception as e:
            logger.error(f"Ошибка при проверке пропущенных свечей: {e}")
            self.status_text.set(f"Ошибка проверки: {e}")
        finally:
            self.root.after(0, self.progress_bar.stop)

    def _get_earliest_timestamp_bybit(self, symbol, category):
        """Получить самый ранний timestamp для тикера через ByBit API (поиск по месяцам, дням, часам, минутам)"""
        import requests
        from datetime import datetime, timedelta
        import time as time_mod
        url = "https://api.bybit.com/v5/market/kline"
        interval = "1"
        # 1. Поиск earliest месяца
        # Начинаем с 2010-01-01
        t = datetime(2010, 1, 1, tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        found = None
        # Поиск по месяцам
        while t < now:
            params = {
                "category": category,
                "symbol": symbol,
                "interval": interval,
                "from": int(t.timestamp()),
                "limit": 1
            }
            try:
                resp = requests.get(url, params=params, timeout=10)
                data = resp.json()
                if data.get("retCode") != 0:
                    return None
                klines = data.get("result", {}).get("list", [])
                if klines:
                    found = int(klines[-1][0]) // 1000
                    break
            except Exception as e:
                logger.warning(f"Ошибка поиска earliest месяца: {e}")
                return None
            # Следующий месяц
            t = (t.replace(day=1) + timedelta(days=32)).replace(day=1, tzinfo=timezone.utc)
        if not found:
            return None
        # 2. Поиск earliest дня в найденном месяце
        t = datetime.fromtimestamp(found, tz=timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
        while t < now:
            params = {
                "category": category,
                "symbol": symbol,
                "interval": interval,
                "from": int(t.timestamp()),
                "limit": 1
            }
            try:
                resp = requests.get(url, params=params, timeout=10)
                data = resp.json()
                if data.get("retCode") != 0:
                    return None
                klines = data.get("result", {}).get("list", [])
                if klines:
                    found = int(klines[-1][0]) // 1000
                    break
            except Exception as e:
                logger.warning(f"Ошибка поиска earliest дня: {e}")
                return None
            t += timedelta(days=1)
        # 3. Поиск earliest часа в найденном дне
        t = datetime.fromtimestamp(found, tz=timezone.utc).replace(minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
        for h in range(24):
            t_h = t.replace(hour=h)
            if t_h > now:
                break
            params = {
                "category": category,
                "symbol": symbol,
                "interval": interval,
                "from": int(t_h.timestamp()),
                "limit": 1
            }
            try:
                resp = requests.get(url, params=params, timeout=10)
                data = resp.json()
                if data.get("retCode") != 0:
                    return None
                klines = data.get("result", {}).get("list", [])
                if klines:
                    found = int(klines[-1][0]) // 1000
                    break
            except Exception as e:
                logger.warning(f"Ошибка поиска earliest часа: {e}")
                return None
        # 4. Поиск earliest минуты в найденном часе
        t = datetime.fromtimestamp(found, tz=timezone.utc).replace(second=0, microsecond=0, tzinfo=timezone.utc)
        for m in range(60):
            t_m = t.replace(minute=m)
            if t_m > now:
                break
            params = {
                "category": category,
                "symbol": symbol,
                "interval": interval,
                "from": int(t_m.timestamp()),
                "limit": 1
            }
            try:
                resp = requests.get(url, params=params, timeout=10)
                data = resp.json()
                if data.get("retCode") != 0:
                    return None
                klines = data.get("result", {}).get("list", [])
                if klines:
                    found = int(klines[-1][0]) // 1000
                    break
            except Exception as e:
                logger.warning(f"Ошибка поиска earliest минуты: {e}")
                return None
        return datetime.fromtimestamp(found, tz=timezone.utc)


class SettingsWindow:
    def __init__(self, parent, settings: configparser.ConfigParser, save_callback, crypto_manager):
        try:
            self.window = tk.Toplevel(parent)
            self.window.title("Настройки")
            self.window.geometry("400x400")
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
            self.timeout_var = tk.StringVar(value=settings.get('Download', 'timeout', fallback='10'))
            
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
                ("Число потоков скачивания:", self.threads_var),
                ("Таймаут ответа API (сек):", self.timeout_var)
            ]
            
            for i, (label, var) in enumerate(fields):
                frame = ttk.Frame(main_frame)
                frame.pack(fill=tk.X, pady=2)
                
                ttk.Label(frame, text=label, width=25).pack(side=tk.LEFT)
                
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
            port = int(self.port_var.get())
            threads = int(self.threads_var.get())
            timeout = int(self.timeout_var.get())
            if port <= 0 or port > 65535:
                raise ValueError("Порт должен быть в диапазоне 1-65535")
            if threads <= 0 or threads > 50:
                raise ValueError("Число потоков должно быть в диапазоне 1-50")
            if timeout <= 0 or timeout > 120:
                raise ValueError("Таймаут должен быть в диапазоне 1-120 сек")
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
            self.settings['Download']['timeout'] = self.timeout_var.get()
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