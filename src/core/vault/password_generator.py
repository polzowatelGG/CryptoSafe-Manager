import secrets

class PasswordGenerator:
    def __init__(self):
        self.history = []

    def _secrets_shuffle(self, lst):

        for i in range(len(lst) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            lst[i], lst[j] = lst[j], lst[i]

    def generate_password(self, length=16, use_upper=True, use_lower=True, use_digits=True, use_special=True, exclude_ambiguous=True):

        # Случайная длина (16–32), если не задана
        if length is None:
            length = secrets.randbelow(length)
        elif length < 16:
            raise ValueError("Password length must be at least 16 characters")

        # Наборы символов
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        special = "!@#$%^&*"

        if exclude_ambiguous:
            lower = lower.replace("l", "")
            upper = upper.replace("I", "").replace("O", "")
            digits = digits.replace("1", "").replace("0", "")

        # Собираем доступные типы
        types = []
        if use_lower:
            types.append(('lower', lower))
        if use_upper:
            types.append(('upper', upper))
        if use_digits:
            types.append(('digits', digits))
        if use_special:
            types.append(('special', special))

        if not types:
            raise ValueError("At least one character set must be selected")

        # Гарантируем минимум один символ от каждого выбранного типа
        mask_chars = []
        for tname, tset in types:
            mask_chars.append(secrets.choice(tset))

        # Оставшиеся позиции заполняем случайными типами (с равномерным распределением)
        remaining = length - len(mask_chars)
        for _ in range(remaining):
            tname, tset = secrets.choice(types)   # secrets.choice для кортежа
            mask_chars.append(secrets.choice(tset))

        # Перемешиваем массив через криптостойкое перемешивание
        self._secrets_shuffle(mask_chars)
        password = ''.join(mask_chars)

        # Проверка на дубликат в истории (последние 20 паролей)
        max_attempts = 100
        for _ in range(max_attempts):
            if password not in self.history[-20:]:
                break
            # Если дубликат – перетасовываем ещё раз (без перегенерации всей строки)
            self._secrets_shuffle(mask_chars)
            password = ''.join(mask_chars)
        else:
            # В крайнем случае всё равно используем последний вариант
            pass

        self.history.append(password)
        if len(self.history) > 20:
            self.history.pop(0)

        return password