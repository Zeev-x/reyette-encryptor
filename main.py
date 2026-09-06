import sys
import os
import crypto as cr

def usage(script_name):
    print(f"Usage:")
    print(f"  {script_name} <file_path> [decrypt]       # Encrypt/Decrypt manual")
    print("Atau drag & drop banyak file/folder ke script ini.")
    sys.exit(1)

def process_file(file_path, force_decrypt=False):
    if not os.path.isfile(file_path):
        return

    if force_decrypt or file_path.endswith(".enc"):
        try:
            cr.decrypt_file(file_path)
        except Exception as e:
            print(f"Error saat dekripsi {file_path}: {e}")
    else:
        try:
            cr.encrypt_file(file_path)
        except Exception as e:
            print(f"Error saat enkripsi {file_path}: {e}")

def process_folder(folder_path, force_decrypt=False):
    for root, _, files in os.walk(folder_path):
        for name in files:
            file_path = os.path.join(root, name)
            process_file(file_path, force_decrypt)

if __name__ == "__main__":
    args = sys.argv[1:]
    script_name = os.path.basename(sys.argv[0])

    if len(args) == 0:
        usage(script_name)

    # cek apakah mode manual decrypt
    force_decrypt = (len(args) > 1 and args[1].lower() == "decrypt")

    # bisa multiple file/folder
    for path in args:
        if not os.path.exists(path):
            print(f"Path tidak ditemukan: {path}")
            continue

        if os.path.isdir(path):
            process_folder(path, force_decrypt)
        else:
            process_file(path, force_decrypt)
