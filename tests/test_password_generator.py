from core.vault.password_generator import PasswordGenerator

def test_password_generator_10000():
    gen = PasswordGenerator()
    passwords = set()
    for _ in range(10000):
        pwd = gen.generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_special=True)
        # проверка на дубликаты (история не даст повторов в последних 20, но за 10000 могут быть)
        assert pwd not in passwords, f"Duplicate password: {pwd}"
        passwords.add(pwd)

        # проверка набора символов
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(c in "!@#$%^&*" for c in pwd)

        # проверка длины
        assert len(pwd) == 16

    # дополнительно: проверить, что история хранит последние 20
    assert len(gen.history) == 20  # так как generate_password обрезает историю до 20