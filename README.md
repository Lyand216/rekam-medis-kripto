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
node test/run.mjs     # atau: npm test
node test/bench.mjs   # atau: npm run bench
```

- `test/run.mjs` menguji Vigenère (termasuk kasus baku `ATTACKATDAWN`), round-trip
  enkripsi–dekripsi hibrida, penolakan ciphertext yang dimodifikasi (AEAD), penolakan
  kunci privat yang salah, **skema riwayat baru tanpa identitas pasien**, serta **migrasi
  idempoten dari skema lama** dengan jaminan payload ciphertext dipertahankan dan tetap
  dapat didekripsi.
- `test/bench.mjs` mengukur durasi pipeline aktual (lihat bagian benchmark).
  Data uji **sintetis** — tidak memakai data pasien nyata.

## Struktur

```
rekam-medis-kripto/
├─ index.html          Antarmuka (5 tab)
├─ css/styles.css      Tampilan
├─ js/vigenere.js      Vigenère Cipher (case-preserving)
├─ js/hybrid.js        AES-256-GCM + RSA-2048-OAEP + util base64/PEM
├─ js/history.js       Skema riwayat (tanpa identitas pasien) + migrasi idempoten
├─ js/app.js           Logika UI, alur enkripsi/dekripsi, riwayat
├─ test/run.mjs        Uji round-trip, integritas, migrasi riwayat
└─ test/bench.mjs      Benchmark durasi enkripsi & dekripsi
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
- **Dekripsi** — tempel payload, kunci privat membuka kunci sesi, verifikasi integritas GCM.
- **Kunci RSA** — buat pasangan kunci baru, ekspor/impor kunci publik (PEM),
  unduh kunci privat, lihat sidik jari kunci.
- **Riwayat** — disimpan lokal di browser (`localStorage`); entri hanya memuat waktu, algoritma,
  ukuran, tag teknis dari ciphertext, dan payload terenkripsi. **Nama pasien dan ID rekam
  medis tidak ikut tersimpan** (lihat [Catatan keamanan](#catatan-keamanan)).
- **Tentang** — penjelasan lapisan kriptografi dan catatan keamanan.

## Pengukuran durasi (benchmark)

```powershell
node test/bench.mjs     # atau: npm run bench
```

**Metode:**

- Mengukur **pipeline yang benar-benar dipakai aplikasi**, bukan simulasi terpisah:
  enkripsi = `vigenereEncrypt` → `hybridEncrypt` (AES-256-GCM + RSA wrap);
  dekripsi = `hybridDecrypt` (unwrap RSA + AES) → `vigenereDecrypt`.
- Durasi diukur dengan `performance.now()` yang **mengurung `await`**, sehingga operasi
  asinkron Web Crypto dihitung sampai selesai, bukan hanya sampai Promise dimulai.
- Waktu **enkripsi dan dekripsi dilaporkan terpisah**.
- Ukuran data mengikuti format rekam medis aplikasi (`JSON.stringify` objek rekam medis,
  indent 2): **1 KB, 10 KB, 100 KB** berdasarkan panjang UTF-8.
- Data uji **sintetis** — tidak memakai data pasien nyata.
- **Warm-up 3× tanpa pencatatan**, lalu **21 pengukuran** per arah per ukuran.
- Statistik yang dilaporkan: **median, mean (±sd), min, max**.
- `generateRsaKeyPair()` diukur **terpisah** karena tidak berada di jalur per-enkripsi:
  aplikasi hanya memanggilnya sekali saat inisialisasi. Overhead-nya adalah biaya
  pengaturan sekali jalan, bukan biaya perrekam medis.
- Benchmark **tidak mengubah** format ciphertext, algoritma, maupun parameter kriptografi.
- Hasil bergantung pada lingkungan; benchmark ini berjalan di **Node.js (webcrypto)**.
  Angka di browser bisa berbeda.

## Catatan keamanan

- Vigenère adalah kriptografi klasik yang mudah dipatahkan dengan analisis frekuensi.
  Perannya di sini adalah **lapisan tambahan**, bukan pengganti AES/RSA — keamanan nyata
  sistem bertumpu pada AES-256-GCM + RSA-2048-OAEP.
- **Keterbatasan Vigenère** (`js/vigenere.js`): hanya huruf A–Z/a–z yang disandikan.
  **Angka, spasi, tanda baca, dan huruf non-ASCII** (mis. é, ü) **lolos tanpa penyandian**,
  sehingga struktur teks (mis. pengukuran, nomor) tetap dapat dibaca setelah tahap Vigenère.
  Lapisan ini tidak mengganti kebutuhan enkripsi kuat di tahap berikutnya.
- **Privasi metadata riwayat**: identitas pasien **tidak** disimpan di `localStorage` maupun
  ditampilkan di tab Riwayat; yang tersimpan hanya waktu, algoritma, ukuran, tag teknis
  dari ciphertext, dan payload terenkripsi. Migrasi ke skema ini bersifat **irreversibel**
  terhadap metadata identitas lama (dibuang secara sengaja), namun **payload ciphertext
  lama tetap dipertahankan** dan tetap dapat didekripsi via tab Riwayat.
- **Enkripsi bukan berarti aman total**: kunci privat RSA adalah titik kegagalan tunggal —
  kehilangan atau salah menyimpannya berarti data tidak dapat dipulihkan. Taruh kunci privat
  di tempat aman di luar aplikasi.
- Untuk produksi: gunakan HSM/Key Vault, audit trail, kendali akses berbasis peran,
  dan patuhi regulasi rekam medis elektronik yang berlaku.
