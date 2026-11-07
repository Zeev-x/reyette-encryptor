import sys
import os
import crypto as cr

def usage(script_name):
    print(f"Usage:")
    print(f"  {script_name} <path> [decrypt]")
    print(f"  {script_name} decrypt <path>")
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
    action = "dekripsi" if force_decrypt else "enkripsi"
    try:
        should_decrypt = force_decrypt or cr.is_encrypted_folder(folder_path)
        if should_decrypt:
            action = "dekripsi"
            cr.decrypt_folder(folder_path)
        else:
            cr.encrypt_folder(folder_path)
    except Exception as e:
        print(f"Error saat {action} folder {folder_path}: {e}")

if __name__ == "__main__":
    args = sys.argv[1:]
    script_name = os.path.basename(sys.argv[0])

    if len(args) == 0:
        usage(script_name)

    force_decrypt = False
    if len(args) > 1 and args[0].lower() == "decrypt":
        force_decrypt = True
        args = args[1:]
    elif len(args) > 1 and args[-1].lower() == "decrypt":
        force_decrypt = True
        args = args[:-1]

    if not args:
        usage(script_name)

    # bisa multiple file/folder
    for path in args:
        if not os.path.exists(path):
            print(f"Path tidak ditemukan: {path}")
            continue

        if os.path.isdir(path):
            process_folder(path, force_decrypt)
        else:
            process_file(path, force_decrypt)