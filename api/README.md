# MINAMI Account API

Folder ini adalah backend akun MINAMI. GitHub Pages hanya menjalankan frontend statis; PHP harus dideploy ke server HTTPS + MySQL terpisah.

## Model data
- `player_global_stats`: statistik yang dipakai bersama untuk gelar.
- `player_mode_stats`: statistik per mode.
- `user_achievements`: achievement tetap bisa dipisah per game/mode.

Jadi kemenangan Game di MINAMI 1, MINAMI 2, atau JOKER masuk ke `game_wins` global yang sama. Rank 1 juga dapat dibuat global. Achievement tidak harus global.

Password disimpan menggunakan `password_hash()`, bukan plaintext.

## Deploy
1. Buat database MySQL.
2. Jalankan `schema.sql`.
3. Salin `config.example.php` menjadi `config.php` dan isi kredensial database.
4. Deploy folder API ke hosting PHP HTTPS.
5. Frontend GitHub Pages kemudian diarahkan ke URL API tersebut.

Jangan commit `config.php` yang berisi password database.