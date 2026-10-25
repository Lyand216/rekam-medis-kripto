# SIM-RM Kripto — Pengamanan Rekam Medis Digital

Web sederhana untuk mengamankan **rekam medis digital** dengan integrasi
**Vigenère Cipher** dan **kriptografi hibrida AES-256-GCM + RSA-2048-OAEP**.

Berjalan 100% di sisi klien (Web Crypto API) — tidak ada data yang dikirim ke server.

## Menjalankan

Cara paling mudah: buka `index.html` langsung di browser modern
(Chrome / Edge / Firefox).

Atau jalankan server lokal (disarankan, agar Web Crypto pasti aktif):

```powershell
# Node.js
npx serve .

# atau Python
python -m http.server 8080
```

Lalu buka `http://localhost:8080` (Python) / alamat yang ditampilkan `serve`.

## Uji otomatis

```powershell
node test/run.mjs
```

Menguji vigenère (termasuk kasus baku `ATTACKATDAWN`) dan round-trip enkripsi–dekripsi
hibrida, penolakan ciphertext yang dimodifikasi, serta penolakan kunci privat yang salah.

## Struktur

```
rekam-medis-kripto/
├─ index.html          Antarmuka (5 tab)
├─ css/styles.css      Tampilan
├─ js/vigenere.js      Vigenère Cipher (case-preserving)
├─ js/hybrid.js        AES-256-GCM + RSA-2048-OAEP + util base64/PEM
├─ js/app.js           Logika UI, alur enkripsi/dekripsi, riwayat
└─ test/run.mjs        Uji round-trip
```

## Alur kriptografi

```
Plaintext (rekam medis)
      │
      ▼  Vigenere(key)                        penyamaran berlapis
Teks tersamarkan
      │
      ▼  AES-256-GCM(keySesi, iv)             enkripsi data + integritas
      │        └── AES-256(keySesi) dibungkus RSA-2048-OAEP(pubKey)
      ▼
Payload { iv, wrappedKey, ciphertext, alg }
```

Dekripsi berjalan terbalik: **RSA** membuka kunci sesi → **AES** membuka data →
**Vigenère** mengembalikan teks asli.

## Fitur

- **Enkripsi** — isi rekam medis + metadata; menampilkan tiap tahap (plaintext,
  hasil Vigenère, ciphertext, wrapped key, IV, payload JSON) beserta contoh
  tabel perhitungan Vigenère.
- **Dekripsi** — tempel payload, kunci privat dibuka RSK, verifikasi integritas GCM.
- **Kunci RSA** — buat pasangan kunci baru, ekspor/impor kunci publik (PEM),
  unduh kunci privat, lihat sidik jari kunci.
- **Riwayat** — disimpan di `localStorage`; hanya ciphertext yang tersimpan.
- **Tentang** — penjelasan lapisan kriptografi dan catatan keamanan.

## Catatan keamanan

- Vigenère adalah kriptografi klasik yang mudah dipatahkan dengan analisis frekuensi.
  Perannya di sini adalah **lapisan tambahan**, bukan pengganti AES/RSA.
- Jika kunci privat hilang, data tidak dapat dipulihkan.
- Untuk produksi: gunakan HSM/Key Vault, audit trail, kendali akses berbasis peran,
  dan patuhi regulasi rekam medis elektronik yang berlaku.
