from cryptography.fernet import Fernet
from config import Config


_cipher = Fernet(Config.ENCRYPTION_KEY.encode())


def encrypt_data(plain_text: str) -> str:
    return _cipher.encrypt(plain_text.encode()).decode()


def decrypt_data(cipher_text: str) -> str:
    return _cipher.decrypt(cipher_text.encode()).decode()
