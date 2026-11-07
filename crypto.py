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
cursor.execute("""
CREATE TABLE IF NOT EXISTS directories (
    operation_id TEXT NOT NULL,
    original_path TEXT NOT NULL,
    encrypted_path TEXT NOT NULL,
    original_name TEXT NOT NULL,
    is_root INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (operation_id, original_path)
)
""")
conn.commit()

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


def _absolute_path(path):
    return os.path.abspath(os.path.normpath(path))


def _normalized_path(path):
    return os.path.normcase(_absolute_path(path))


def _raise_walk_error(error):
    raise error


def _folder_contents(folder_path):
    files = []
    directories = []
    for root, _, filenames in os.walk(folder_path, onerror=_raise_walk_error):
        directories.append(_absolute_path(root))
        files.extend(os.path.join(root, name) for name in filenames)
    return directories, files


def _find_folder_operations(folder_path, actual_directories):
    directories_by_name = {}
    for path in actual_directories:
        directories_by_name.setdefault(
            os.path.normcase(os.path.basename(path)), []
        ).append(path)

    cursor.execute(
        "SELECT operation_id, encrypted_path FROM directories WHERE is_root=1"
    )
    operations = []
    for operation_id, stored_root in cursor.fetchall():
        actual_root = next(
            (
                path for path in actual_directories
                if _normalized_path(path) == _normalized_path(stored_root)
            ),
            None,
        )
        if actual_root is None:
            candidates = directories_by_name.get(
                os.path.normcase(os.path.basename(stored_root)), []
            )
            if len(candidates) == 1:
                actual_root = candidates[0]
        if actual_root is not None:
            operations.append((operation_id, stored_root, actual_root))
    return operations


def _recover_folder_operations(folder_path, actual_directories, files):
    tracked_files = []
    for filepath in files:
        if not filepath.endswith(".enc"):
            continue
        cursor.execute(
            "SELECT filepath FROM files WHERE random_name=?",
            (os.path.basename(filepath),),
        )
        row = cursor.fetchone()
        if row:
            tracked_files.append((filepath, row[0]))

    if not tracked_files:
        raise RuntimeError(
            "Metadata nama folder tidak ditemukan. Database tidak memiliki "
            "pemetaan direktori atau file terenkripsi untuk memulihkan nama asli."
        )

    folder_path = _absolute_path(folder_path)
    candidate_roots = []
    nested_roots = set()
    for path in actual_directories:
        if path == folder_path:
            continue
        try:
            uuid.UUID(os.path.basename(path))
            nested_roots.add(_normalized_path(path))
        except ValueError:
            continue

    try:
        selected_is_uuid = bool(uuid.UUID(os.path.basename(folder_path)))
    except ValueError:
        selected_is_uuid = False

    if selected_is_uuid or not nested_roots:
        candidate_roots.append(folder_path)
    else:
        for path in actual_directories:
            if _normalized_path(path) not in nested_roots:
                continue
            parent = os.path.dirname(path)
            has_uuid_ancestor = False
            while parent != folder_path and parent.startswith(folder_path):
                if _normalized_path(parent) in nested_roots:
                    has_uuid_ancestor = True
                    break
                parent = os.path.dirname(parent)
            if not has_uuid_ancestor:
                candidate_roots.append(path)

    recovered_operations = []
    for root in candidate_roots:
        root_key = _normalized_path(root)
        operation_id = str(uuid.uuid4())
        recovered = {}
        for encrypted_file, original_file in tracked_files:
            try:
                relative_dir = os.path.relpath(
                    os.path.dirname(encrypted_file), root
                )
                if relative_dir == os.curdir:
                    depth = 0
                else:
                    depth = len(relative_dir.split(os.sep))
                    if os.path.commonpath((root, encrypted_file)) != root:
                        continue
            except ValueError:
                continue

            source_dir = os.path.dirname(original_file)
            for ancestor_depth in range(depth + 1):
                current_dir = os.path.dirname(encrypted_file)
                for _ in range(depth - ancestor_depth):
                    current_dir = os.path.dirname(current_dir)
                if not os.path.isdir(current_dir):
                    continue
                original_dir = source_dir
                for _ in range(depth - ancestor_depth):
                    original_dir = os.path.dirname(original_dir)
                original_name = os.path.basename(original_dir)
                key = _normalized_path(current_dir)
                value = (current_dir, original_dir, original_name)
                previous = recovered.get(key)
                if previous and previous[2] != original_name:
                    raise RuntimeError(
                        f"Metadata nama folder tidak konsisten: {current_dir}"
                    )
                recovered[key] = value

        if root_key not in recovered:
            continue

        cursor.executemany(
            """INSERT INTO directories
               (operation_id, original_path, encrypted_path, original_name, is_root)
               VALUES (?, ?, ?, ?, ?)""",
            (
                (
                    operation_id,
                    original_dir,
                    current_dir,
                    original_name,
                    int(_normalized_path(current_dir) == root_key),
                )
                for current_dir, original_dir, original_name in recovered.values()
            ),
        )
        recovered_operations.append((operation_id, root, root))

    if not recovered_operations:
        raise RuntimeError(
            "Nama folder asli tidak dapat ditentukan dari database. "
            "Jangan hapus files.db atau master.key; nama asli tidak bisa "
            "ditebak dengan aman tanpa metadata."
        )

    conn.commit()
    return recovered_operations


def is_encrypted_folder(folder_path):
    folder_path = _absolute_path(folder_path)
    if not os.path.isdir(folder_path):
        return False
    actual_directories, files = _folder_contents(folder_path)
    if _find_folder_operations(folder_path, actual_directories):
        return True
    for filepath in files:
        if not filepath.endswith(".enc"):
            continue
        cursor.execute(
            "SELECT 1 FROM files WHERE random_name=?",
            (os.path.basename(filepath),),
        )
        if cursor.fetchone():
            return True
    return False


def encrypt_folder(folder_path):
    folder_path = _absolute_path(folder_path)
    if not os.path.isdir(folder_path):
        raise NotADirectoryError(folder_path)
    if not os.path.basename(folder_path):
        raise ValueError("Folder root tidak dapat diacak namanya.")

    directories = []
    files = []
    for root, _, filenames in os.walk(folder_path, onerror=_raise_walk_error):
        directories.append(_absolute_path(root))
        files.extend(os.path.join(root, name) for name in filenames)

    for filepath in files:
        if filepath.endswith(".enc"):
            decrypt_file(filepath)
        else:
            encrypt_file(filepath)

    operation_id = str(uuid.uuid4())
    random_names = {}
    encrypted_paths = {}
    original_root_parent = os.path.dirname(folder_path)

    for directory in directories:
        while True:
            random_name = str(uuid.uuid4())
            parent = os.path.dirname(directory)
            if not os.path.exists(os.path.join(parent, random_name)):
                break
        random_names[directory] = random_name

    for directory in directories:
        parent = os.path.dirname(directory)
        if directory == folder_path:
            encrypted_parent = original_root_parent
        else:
            encrypted_parent = encrypted_paths[parent]
        encrypted_paths[directory] = os.path.join(encrypted_parent, random_names[directory])

    renamed_directories = []
    try:
        for directory in sorted(directories, key=len, reverse=True):
            current_path = os.path.join(
                os.path.dirname(directory), random_names[directory]
            )
            os.rename(directory, current_path)
            renamed_directories.append(directory)

        cursor.executemany(
            """INSERT INTO directories
               (operation_id, original_path, encrypted_path, original_name, is_root)
               VALUES (?, ?, ?, ?, ?)""",
            (
                (
                    operation_id,
                    directory,
                    encrypted_paths[directory],
                    os.path.basename(directory),
                    int(directory == folder_path),
                )
                for directory in directories
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        for directory in reversed(renamed_directories):
            current_path = os.path.join(
                os.path.dirname(directory), random_names[directory]
            )
            if os.path.exists(current_path):
                os.rename(current_path, directory)
        raise

    print(f"\nFolder terenkripsi: {encrypted_paths[folder_path]}")


def decrypt_folder(folder_path):
    folder_path = _absolute_path(folder_path)
    if not os.path.isdir(folder_path):
        raise NotADirectoryError(folder_path)

    actual_directories, files = _folder_contents(folder_path)
    operations = _find_folder_operations(folder_path, actual_directories)
    if not operations:
        operations = _recover_folder_operations(
            folder_path, actual_directories, files
        )

    for filepath in files:
        if filepath.endswith(".enc"):
            cursor.execute(
                "SELECT 1 FROM files WHERE random_name=?",
                (os.path.basename(filepath),),
            )
            tracked_file = cursor.fetchone() is not None
            if not tracked_file:
                raise RuntimeError(
                    f"Metadata file tidak ditemukan; file dipertahankan: {filepath}"
                )
            decrypted = decrypt_file(filepath)
            if not decrypted:
                raise RuntimeError(
                    f"File belum berhasil didekripsi: {filepath}"
                )

    for operation_id, stored_root, actual_root in operations:
        cursor.execute(
            """SELECT original_path, encrypted_path, original_name, is_root
               FROM directories WHERE operation_id=?""",
            (operation_id,),
        )
        directory_rows = cursor.fetchall()
        rename_pairs = []
        root_original_name = None
        predecessor_operations = set()
        for original_path, encrypted_path, original_name, is_root in directory_rows:
            visited_paths = set()
            while _normalized_path(original_path) not in visited_paths:
                visited_paths.add(_normalized_path(original_path))
                cursor.execute(
                    """SELECT operation_id, original_name, encrypted_path,
                              original_path
                       FROM directories
                       WHERE operation_id!=? ORDER BY rowid DESC""",
                    (operation_id,),
                )
                previous = next(
                    (
                        row for row in cursor.fetchall()
                        if _normalized_path(row[2])
                        == _normalized_path(original_path)
                    ),
                    None,
                )
                if not previous:
                    break
                previous_operation, original_name, _, original_path = previous
                predecessor_operations.add(previous_operation)

            relative_path = os.path.relpath(encrypted_path, stored_root)
            current_path = (
                actual_root
                if relative_path == os.curdir
                else os.path.join(actual_root, relative_path)
            )
            if not os.path.isdir(current_path):
                raise FileNotFoundError(
                    f"Folder terenkripsi tidak ditemukan: {current_path}"
                )
            restored_path = os.path.join(
                os.path.dirname(current_path), original_name
            )
            if os.path.exists(restored_path) and (
                _normalized_path(restored_path) != _normalized_path(current_path)
            ):
                raise FileExistsError(
                    f"Folder tujuan sudah ada: {restored_path}"
                )
            rename_pairs.append((current_path, restored_path))
            if is_root:
                root_original_name = original_name

        if root_original_name is None:
            raise RuntimeError(
                f"Metadata folder root tidak ditemukan untuk operasi {operation_id}"
            )

        renamed_pairs = []
        try:
            for current_path, restored_path in sorted(
                rename_pairs, key=lambda pair: len(pair[0]), reverse=True
            ):
                os.rename(current_path, restored_path)
                renamed_pairs.append((current_path, restored_path))
            cursor.execute(
                "DELETE FROM directories WHERE operation_id=?", (operation_id,)
            )
            for previous_operation in predecessor_operations:
                cursor.execute(
                    "DELETE FROM directories WHERE operation_id=?",
                    (previous_operation,),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            for current_path, restored_path in reversed(renamed_pairs):
                if os.path.isdir(restored_path):
                    os.rename(restored_path, current_path)
            raise

        print(
            f"\nFolder dipulihkan: "
            f"{os.path.join(os.path.dirname(actual_root), root_original_name)}"
        )


def decrypt_file(filepath, buffer_size=BUFFER*1024*1024):
    random_name = os.path.basename(filepath)
    cursor.execute("SELECT id, original_name, nonce, enc_key, file_hash FROM files WHERE random_name=?", (random_name,))
    row = cursor.fetchone()
    if not row:
        print("Key tidak ditemukan di database!")
        return False

    db_id, original_name, nonce, file_key, stored_hash = row

    file_size = os.path.getsize(filepath)
    with open(filepath, "rb") as fin:
        file_data = fin.read()
    current_hash = sha256_hash(file_data)
    if current_hash != stored_hash:
        print("\nHash tidak cocok, file mungkin rusak atau dimodifikasi!")
        return False

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
    return True