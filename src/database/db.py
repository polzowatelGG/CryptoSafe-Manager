import sqlite3
from pathlib import Path

class DatabaseHelper:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.connection = None
        self.cursor = None
        self.connect()
        self.initialize_db()

    def connect(self):
        if not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True)
        self.connection = sqlite3.connect(self.db_path)
        self.cursor = self.connection.cursor()

    def initialize_db(self):                    # Создание таблицы для хранения криптовалютных данных (пример) /// переделать
        pass

    def insert_crypto(self, name: str, symbol: str, price: float):
        self.cursor.execute('''
            INSERT INTO cryptos (name, symbol, price) VALUES (?, ?, ?) 
        ''', (name, symbol, price)) #переделать 
        self.connection.commit()

    def get_all_cryptos(self):
        self.cursor.execute('SELECT * FROM cryptos')
        return self.cursor.fetchall() #переделать 

    def close(self):
        if self.connection:
            self.connection.close() 