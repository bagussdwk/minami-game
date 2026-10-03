# MINAMI — InfinityFree Deployment

Sumber: branch `account-system`.

Upload ke `htdocs/`:

```
htdocs/
├── index.html
├── joker.html
├── casino-vip-music-classy-lounge-casino-1-469300.mp3
└── api/
    ├── index.php
    └── config.php
```

Catatan:
- `config.php` dibuat/dipertahankan hanya di server InfinityFree karena berisi kredensial database.
- `schema.sql` hanya untuk import database dan tidak wajib berada di `htdocs/api/`.
- `test.html` hanya tester dan tidak diperlukan untuk game produksi.
- `v1.html`, `v2.html`, dan `v3.html` bukan entry utama dan tidak diperlukan untuk deployment produksi.
- `index.html` dan `joker.html` menggunakan API same-origin: `/api/index.php`.
- Gameplay Minami 1, Minami 2, dan JOKER tidak diubah dalam perpindahan hosting ini.

Setelah upload:
1. Buka `https://cardarena.site.je/`.
2. Buka menu Profil → Akun Online.
3. Daftar/login dari halaman tersebut.
4. Jalankan permainan dan cek statistik akun.
