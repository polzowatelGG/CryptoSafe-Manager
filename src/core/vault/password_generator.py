import secrets

class PasswordGenerator:
    def __init__(self):
        self.history = []

    def generate_password(self, length=16, use_upper=True, use_lower=True, use_digits=True, use_special=True, exclude_ambiguous=True):
        if length < 8 or length > 64:
            raise ValueError("Password length must be between 8 and 64 characters")

        char_sets = []
        if use_upper:
            char_sets.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        if use_lower:
            char_sets.append("abcdefghijklmnopqrstuvwxyz")
        if use_digits:
            char_sets.append("0123456789")
        if use_special:
            char_sets.append("!@#$%^&*")

        if not char_sets:
            raise ValueError("At least one character set must be selected")

        all_chars = "".join(char_sets)

        if exclude_ambiguous:
            all_chars = all_chars.replace("l", "").replace("I", "").replace("1", "").replace("0", "").replace("O", "")

        while True:
            password = "".join(secrets.choice(all_chars) for _ in range(length))
 
            # проверяем, что пароль соответствует выбранным критериям и не повторяется в последних 20
            if (use_upper and not any(c.isupper() for c in password)) or \
                (use_lower and not any(c.islower() for c in password)) or \
                (use_digits and not any(c.isdigit() for c in password)) or \
                (use_special and not any(c in "!@#$%^&*" for c in password)):
                    continue
            
            elif password in self.history[-20:]:
                continue
            
            self.history.append(password)
            return password
    
