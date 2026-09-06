import sqlite3
import uuid
import hashlib
import os
from cryptography.fernet import Fernet

MASTER_KEY_FILE = "master.key"

def load_master_key():
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(MASTER_KEY_FILE, "wb") as f:
            f.write(key)
        return key

master_key = load_master_key()
db_cipher = Fernet(master_key)

conn = sqlite3.connect("files.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_name TEXT,
    random_name TEXT,
    filepath TEXT,
    enc_key TEXT,
    file_hash TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def show_progress(done, total, prefix="Progress"):
    percent = int((done / total) * 100)
    print(f"\r{prefix}: {percent}%", end="", flush=True)

def encrypt_file(filepath):
    file_key = Fernet.generate_key()
    cipher = Fernet(file_key)

    file_size = os.path.getsize(filepath)
    random_name = str(uuid.uuid4()) + ".enc"
    enc_path = os.path.join(os.path.dirname(filepath), random_name)

    encrypted_data = b""
    done = 0
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            encrypted_data += cipher.encrypt(chunk)
            done += len(chunk)
            show_progress(done, file_size, "Enkripsi")

    with open(enc_path, "wb") as f:
        f.write(encrypted_data)

    file_hash = sha256_hash(encrypted_data)
    enc_key = db_cipher.encrypt(file_key).decode()

    cursor.execute("INSERT INTO files (original_name, random_name, filepath, enc_key, file_hash) VALUES (?, ?, ?, ?, ?)",
                   (os.path.basename(filepath), random_name, enc_path, enc_key, file_hash))
    conn.commit()

    os.remove(filepath)
    print(f"\nFile terenkripsi: {enc_path} (original dihapus)")

def encrypt_file(filepath):
    file_key = Fernet.generate_key()
    cipher = Fernet(file_key)

    file_size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        data = b""
        done = 0
        while chunk := f.read(4096):
            data += chunk
            done += len(chunk)
            show_progress(done, file_size, "Membaca file untuk enkripsi")

    encrypted = cipher.encrypt(data)

    random_name = str(uuid.uuid4()) + ".enc"
    enc_path = os.path.join(os.path.dirname(filepath), random_name)

    with open(enc_path, "wb") as f:
        f.write(encrypted)

    file_hash = sha256_hash(encrypted)
    enc_key = db_cipher.encrypt(file_key).decode()

    cursor.execute("INSERT INTO files (original_name, random_name, filepath, enc_key, file_hash) VALUES (?, ?, ?, ?, ?)",
                   (os.path.basename(filepath), random_name, enc_path, enc_key, file_hash))
    conn.commit()

    os.remove(filepath)
    print(f"\nFile terenkripsi: {enc_path} (original dihapus)")

def decrypt_file(filepath):
    random_name = os.path.basename(filepath)
    cursor.execute("SELECT id, original_name, enc_key, file_hash FROM files WHERE random_name=?", (random_name,))
    row = cursor.fetchone()
    if row:
        db_id, original_name, enc_key, stored_hash = row
        file_key = db_cipher.decrypt(enc_key.encode())
        cipher = Fernet(file_key)

        file_size = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            encrypted_data = b""
            done = 0
            while chunk := f.read(4096):
                encrypted_data += chunk
                done += len(chunk)
                show_progress(done, file_size, "Membaca file untuk dekripsi")

        current_hash = sha256_hash(encrypted_data)
        if current_hash != stored_hash:
            print("\n⚠️ Hash tidak cocok, file mungkin rusak atau dimodifikasi!")
            return

        decrypted = cipher.decrypt(encrypted_data)

        orig_path = os.path.join(os.path.dirname(filepath), original_name)
        with open(orig_path, "wb") as f:
            f.write(decrypted)

        os.remove(filepath)
        cursor.execute("DELETE FROM files WHERE id=?", (db_id,))
        conn.commit()
        print(f"\nFile didekripsi: {orig_path} (file .enc & entry DB dihapus)")
    else:
        print("Key tidak ditemukan di database!")
