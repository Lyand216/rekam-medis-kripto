/**
 * Riwayat enkripsi (localStorage)
 * ------------------------------------------------------------------
 * Skema riwayat sengaja TIDAK menyimpan identitas pasien.
 * Hasil audit (L. app.js sebelumnya): `idRekamMedis` + `namaPasien`
 * tersedia sebagai teks terang di localStorage dan ditampilkan di
 * tabel Riwayat, padahal tidak dibutuhkan untuk dekripsi — payload
 * sudah lengkap dengan iv/wrappedKey/ciphertext.
 *
 * Skema versi 2:
 *   { schemaVersion: 2,
 *     waktu:   ISO 8601,
 *     alg:     nama pipeline,
 *     ukuran:  { plain: number|null, cipher: number },  // null = skema lama
 *     ringkas: hex byte awal ciphertext (tag teknis, bukan identitas),
 *     payload: objek payload utuh -> dipakai tombol "Muat" }
 *
 * Migrasi bersifat idempoten dan TIDAK menyentuh `payload`:
 * hanya metadata identitas (`idRekamMedis`, `namaPasien`) yang dibuang.
 */

import { base64ToBuf, fingerprint } from './hybrid.js';

export const HISTORY_KEY = 'rm-kripto-history';
export const HISTORY_SCHEMA = 2;
export const MAX_HISTORY = 25;

/** Kolom yang boleh ada pada satu entri riwayat — tanpa identitas pasien. */
const ALLOWED_KEYS = new Set(['schemaVersion', 'waktu', 'alg', 'ukuran', 'ringkas', 'payload']);

/** Tag teknis dari byte awal ciphertext (bukan sesuatu yang diambil dari data identitas pasien). */
function cipherTag(ciphertext, cipherBytes) {
  try {
    const bytes = base64ToBuf(ciphertext);
    cipherBytes.value = bytes.length;
    return fingerprint(bytes.subarray(0, 6));
  } catch {
    return ''; // ciphertext tidak valid base64 — tetap disimpan tanpa tag
  }
}

/** Buat entri riwayat versi 2 dari hasil enkripsi aplikasi. */
export function buildEntry({ payload, plainLength, waktu = new Date().toISOString() }) {
  const cipherBytes = { value: 0 };
  const ringkas = payload && payload.ciphertext ? cipherTag(payload.ciphertext, cipherBytes) : '';
  return {
    schemaVersion: HISTORY_SCHEMA,
    waktu,
    alg: (payload && payload.alg) || '—',
    ukuran: { plain: plainLength, cipher: cipherBytes.value },
    ringkas,
    payload,
  };
}

/**
 * Migrasi satu entri ke skema 2. Idempoten.
 * @param {*} raw entri lama (skema 1) atau entri yang sudah dimigrasi
 * @returns entri skema 2, atau null jika tidak ada payload untuk dipertahankan
 */
export function migrateEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;

  // Sudah skema 2 → tidak diubah apa pun (idempoten).
  if (raw.schemaVersion === HISTORY_SCHEMA) return raw;

  // Skema 1 (lama): { idRekamMedis, namaPasien, alg, payload, waktu }
  const payload = raw.payload;
  if (!payload || typeof payload !== 'object' || !payload.ciphertext) {
    // Tanpa payload tidak ada ciphertext untuk dipulihkan → entri tidak dipertahankan.
    // Tidak ada versi aplikasi yang pernah menulis entri tanpa payload.
    return null;
  }

  const cipherBytes = { value: 0 };
  const ringkas = cipherTag(payload.ciphertext, cipherBytes);
  const migrated = {
    schemaVersion: HISTORY_SCHEMA,
    waktu: raw.waktu || new Date().toISOString(),
    alg: payload.alg || raw.alg || '—',
    // Ukuran plaintext tidak konversi dari skema lama.
    ukuran: { plain: null, cipher: cipherBytes.value },
    ringkas,
    payload,
  };

  // Jaminan: identitas pasien tidak terbawa.
  delete migrated.idRekamMedis;
  delete migrated.namaPasien;
  return migrated;
}

/** Buang field di luar daftar yang diperbolehkan (pengaman ekstra). */
export function sanitizeEntry(entry) {
  const out = {};
  for (const key of ALLOWED_KEYS) {
    if (key in entry) out[key] = entry[key];
  }
  return out;
}
