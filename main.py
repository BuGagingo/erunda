import re
import itertools
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Преобразование шестнадцатеричных значений в байтовый массив
def hex_to_bytes(hex_string):
    hex_string = hex_string.replace(' ', '').replace('\n', '')
    return bytes.fromhex(hex_string)

# Расшифровка с использованием AES
def decrypt_aes(byte_array, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted_data = decryptor.update(byte_array) + decryptor.finalize()
        return decrypted_data
    except Exception:
        return None

# Генерация ключей длиной 16 байтов (128 бит)
def generate_keys(charset, length, start_key=None):
    if start_key:
        start_index = 0
        for i, key_tuple in enumerate(itertools.product(charset, repeat=length)):
            if ''.join(key_tuple) == start_key:
                start_index = i
                break
        for key_tuple in itertools.islice(itertools.product(charset, repeat=length), start_index, None):
            yield ''.join(key_tuple).encode()
    else:
        for key_tuple in itertools.product(charset, repeat=length):
            yield ''.join(key_tuple).encode()

# Чтение последнего использованного ключа
def read_last_used_key(last_key_file):
    try:
        with open(last_key_file, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        return None

# Запись последнего использованного ключа
def write_last_used_key(key, last_key_file):
    with open(last_key_file, 'w') as file:
        file.write(key.decode())

# Основная логика
def main():
    hex_string = '''
    92 f1 0f 88 9c 0e 6e dc e1 55 2e 9c ee 07 55 62
    aa 18 b3 30 88 8c 87 d7 c1 78 44 96 99 89 0a da
    f1 5f 78 c3 d1 66 82 25 ac 8d 45 97 10 0d b4 c0
    d8 bc a3 dc 60 98 f1 90 66 fd 35 1c c3 db 4b 96
    7b 0e 8b 10 fe 5e c7 bb d3 96 ca 23 ff 02 27 95
    00 68 7e c3 84 9f 28 49 8c ad 33 54 b1 e0 64
    '''
    used_keys_file = 'used_keys.txt'
    last_key_file = 'last_key.txt'
    
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    key_length = 16

    # Чтение последнего использованного ключа
    last_used_key = read_last_used_key(last_key_file)

    byte_array = hex_to_bytes(hex_string)
    iv = b'\x00' * 16  # Примерный IV (измените на реальный IV, если известен)

    # Перебор ключей
    for key in generate_keys(charset, key_length, last_used_key):
        print(key)
        decrypted_data = decrypt_aes(byte_array, key, iv)
        if decrypted_data:
            print(f"Ключ: {key.decode()}, Расшифрованные данные: {decrypted_data}")
            break
        write_last_used_key(key, last_key_file)

if __name__ == "__main__":
    main()