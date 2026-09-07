import os
import sys
import sqlite3
import uuid
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BUFFER = 100 #100mb buffer

import secrets

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MASTER_KEY_FILE = os.path.join(BASE_DIR, "master.key")
DB_FILE = os.path.join(BASE_DIR, "files.db")

def load_master_key():
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = secrets.token_bytes(32)  # 256-bit AES key
        with open(MASTER_KEY_FILE, "wb") as f:
            f.write(key)
        return key

master_key = load_master_key()

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_name TEXT,
    random_name TEXT,
    filepath TEXT,
    nonce BLOB,
    enc_key BLOB,
    file_hash TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def show_progress(done, total, prefix="Progress", bar_length=50):
    percent = int((done / total) * 100)
    filled_length = int(bar_length * percent // 100)
    bar = "#" * filled_length + "." * (bar_length - filled_length)
    sys.stdout.write(f"\r{prefix}: [{bar}] {percent}%")
    sys.stdout.flush()

def encrypt_file(filepath, buffer_size=BUFFER*1024*1024):
    file_key = secrets.token_bytes(32)  # AES-256 key
    nonce = secrets.token_bytes(12)     # GCM nonce

    cipher = Cipher(algorithms.AES(file_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    file_size = os.path.getsize(filepath)
    random_name = str(uuid.uuid4()) + ".enc"
    enc_path = os.path.join(os.path.dirname(filepath), random_name)

    done = 0
    with open(filepath, "rb") as fin, open(enc_path, "wb") as fout:
        fout.write(nonce)
        while chunk := fin.read(buffer_size):
            ct = encryptor.update(chunk)
            fout.write(ct)
            done += len(chunk)
            show_progress(done, file_size, "Encryption")
        fout.write(encryptor.finalize())
        fout.write(encryptor.tag)

    with open(enc_path, "rb") as f:
        encrypted_data = f.read()
    file_hash = sha256_hash(encrypted_data)

    cursor.execute("INSERT INTO files (original_name, random_name, filepath, nonce, enc_key, file_hash) VALUES (?, ?, ?, ?, ?, ?)",
                   (os.path.basename(filepath), random_name, enc_path, nonce, file_key, file_hash))
    conn.commit()

    os.remove(filepath)
    print(f"\nFile terenkripsi: {enc_path} (original dihapus)")

def decrypt_file(filepath, buffer_size=BUFFER*1024*1024):
    random_name = os.path.basename(filepath)
    cursor.execute("SELECT id, original_name, nonce, enc_key, file_hash FROM files WHERE random_name=?", (random_name,))
    row = cursor.fetchone()
    if not row:
        print("Key tidak ditemukan di database!")
        return

    db_id, original_name, nonce, file_key, stored_hash = row

    file_size = os.path.getsize(filepath)
    with open(filepath, "rb") as fin:
        file_data = fin.read()
    current_hash = sha256_hash(file_data)
    if current_hash != stored_hash:
        print("\nHash tidak cocok, file mungkin rusak atau dimodifikasi!")
        return

    nonce = file_data[:12]
    tag = file_data[-16:]
    ciphertext = file_data[12:-16]

    cipher = Cipher(algorithms.AES(file_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    done = 0
    decrypted_data = b""
    for i in range(0, len(ciphertext), buffer_size):
        chunk = ciphertext[i:i+buffer_size]
        decrypted_data += decryptor.update(chunk)
        done += len(chunk)
        show_progress(done, len(ciphertext), "Decryption")
    decrypted_data += decryptor.finalize()

    orig_path = os.path.join(os.path.dirname(filepath), original_name)
    with open(orig_path, "wb") as fout:
        fout.write(decrypted_data)

    os.remove(filepath)
    cursor.execute("DELETE FROM files WHERE id=?", (db_id,))
    conn.commit()
    print(f"\nFile didekripsi: {orig_path} (file .enc & entry DB dihapus)")
