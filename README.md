# Reyette Encryptor

 ## Fitur Utama
* Enkripsi & Dekripsi Otomatis

* Mendukung drag & drop file langsung ke aplikasi.

* Deteksi otomatis: file dengan ekstensi ```.enc``` akan didekripsi, file lain akan dienkripsi.

* Multi-file & Folder Support

* Bisa memproses banyak file sekaligus.

* Mendukung drag & drop folder, termasuk subfolder.

## Manajemen Database

* Setiap file terenkripsi memiliki kunci unik yang disimpan di SQLite.

* Kunci file dienkripsi lagi dengan master key untuk keamanan ganda.

* Entry database otomatis dihapus setelah file didekripsi.

## Self-Cleaning System

* File original dihapus setelah enkripsi.

* File ```.enc``` dihapus setelah dekripsi.

* Database tetap rapi tanpa jejak file lama.

## Progress Bar Persentase

* Menampilkan progress enkripsi dan dekripsi dalam bentuk persentase.

* Memberikan feedback real-time saat file diproses.

## Keamanan
* Kunci unik per file → setiap file terenkripsi dengan key berbeda.

* Master key → disimpan secara aman di file master.key.

* Hash SHA256 → memastikan integritas file, mendeteksi modifikasi atau kerusakan.

## Perbaikan & Optimasi
* Perbaikan bug pada proses dekripsi (sekarang bekerja dengan ciphertext penuh).

* Optimasi pembacaan file dalam chunk untuk progress bar tanpa merusak proses enkripsi/dekripsi.

* Penanganan error lebih jelas saat file atau key tidak ditemukan.

## Rencana Pengembangan
* Menambahkan log aktivitas (audit trail) untuk setiap proses.

* Opsi master password agar master key lebih terlindungi.

## Author
* [Reyette](https://github.com/Zeev-x)
