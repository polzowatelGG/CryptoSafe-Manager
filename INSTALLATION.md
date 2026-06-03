# Подробная инструкция по установке CryptoSafe-Manager



# Системные требования

## Минимальные требования

- Python 3.12+
- pip
- Git
- virtualenv / venv
- SQLite3



# Установка через Git

## 1. Клонирование проекта

```bash
git clone https://github.com/polzowatelGG/CryptoSafe-Manager/

cd cryptosafe-manager
```



## 2. Создание виртуального окружения

```bash
python -m venv venv
```



## 3. Активация виртуального окружения

### Linux / macOS

```bash
source venv/bin/activate
```

### Windows

```powershell
venv\Scripts\activate
```



## 4. Обновление pip

```bash
python -m pip install --upgrade pip
```



## 5. Установка зависимостей

```bash
pip install -r requirements.txt
```



## 6. Проверка установки

```bash
pytest tests/
```

Если тесты проходят без ошибок —
проект установлен корректно.



## 7. Запуск приложения

```bash
python src/app.py
```



# Ручная установка

## 1. Скачивание проекта

Скачайте ZIP-архив репозитория
и распакуйте его в рабочую директорию.



## 2. Переход в директорию проекта

```bash
cd cryptosafe-manager
```



## 3. Создание виртуального окружения

```bash
python -m venv venv
```



## 4. Активация окружения

### Linux / macOS

```bash
source venv/bin/activate
```

### Windows

```powershell
venv\Scripts\activate
```



## 5. Установка зависимостей

```bash
pip install -r requirements.txt
```



## 6. Запуск проекта

```bash
python src/app.py
```



# Обновление проекта

## Получение последних изменений

```bash
git pull origin main
```



## Обновление зависимостей

```bash
pip install -r requirements.txt --upgrade
```



# Структура проекта

```text
src/
├── core/
├── gui/
├── database/
├── tests/
├── docs/
└── app.py
```



# Возможные ошибки

## Python не найден

Проверьте установлен ли Python:

```bash
python --version
```



## Не активируется venv

### Linux / macOS

```bash
chmod +x venv/bin/activate
```

### Windows PowerShell

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```



## Ошибки зависимостей

Обновите pip:

```bash
python -m pip install --upgrade pip
```

После чего повторите установку:

```bash
pip install -r requirements.txt
```