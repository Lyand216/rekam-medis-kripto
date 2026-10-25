/**
 * Vigenere Cipher
 * ------------------------------------------------------------------
 * Lapisan pertama pengamanan rekam medis.
 *
 * Aturan:
 *  - Hanya huruf A-Z / a-z yang dikenai pergeseran.
 *  - Karakter lain (angka, spasi, tanda baca, newline) dibiarkan apa
 *    adanya sehingga isi rekam medis tetap terbaca strukturnya
 *    setelah dekripsi.
 *  - Huruf besar/kecil dipertahankan (case preserving).
 *  - Kunci dinormalisasi menjadi huruf saja (A-Z) dan diulang
 *    sepanjang plaintext.
 */

const A_CODE = 65; // 'A'
const a_CODE = 97; // 'a'

/** Bersihkan kunci Vigenere: ambil hanya huruf, jadikan huruf besar. */
export function normalizeKey(key) {
  const clean = String(key || '').toUpperCase().replace(/[^A-Z]/g, '');
  if (!clean) {
    throw new Error('Kunci Vigenere harus berisi minimal satu huruf (A-Z).');
  }
  return clean;
}

function isUpper(code) {
  return code >= A_CODE && code <= A_CODE + 25;
}

function isLower(code) {
  return code >= a_CODE && code <= a_CODE + 25;
}

/**
 * Geser teks memakai Vigenere.
 * @param {string} text  plaintext atau ciphertext
 * @param {string} key   kunci Vigenere
 * @param {1|-1}   dir   +1 untuk enkripsi, -1 untuk dekripsi
 * @returns {{ result: string, steps: Array }}
 */
export function vigenere(text, key, dir) {
  const normalized = normalizeKey(key);
  const input = String(text ?? '');
  const out = [];
  const steps = [];
  let keyIndex = 0;

  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    const isLetter = isUpper(code) || isLower(code);

    if (!isLetter) {
      // Karakter non-huruf diteruskan tanpa pergeseran.
      out.push(input[i]);
      continue;
    }

    const base = isUpper(code) ? A_CODE : a_CODE;
    const p = code - base;                                  // 0..25
    const k = normalized.charCodeAt(keyIndex % normalized.length) - A_CODE;
    const shifted = (p + dir * k + 26 * 26) % 26;           // selalu positif
    const resultChar = String.fromCharCode(base + shifted);

    // Simpan beberapa langkah pertama sebagai bukti perhitungan (untuk UI).
    if (steps.length < 12) {
      steps.push({
        char: input[i],
        key: normalized[keyIndex % normalized.length],
        plainIndex: p,
        keyIndex: k,
        cipherIndex: shifted,
        out: resultChar,
      });
    }

    out.push(resultChar);
    keyIndex += 1; // kunci hanya maju saat bertemu huruf
  }

  return { result: out.join(''), keyLength: normalized.length, steps };
}

export function vigenereEncrypt(text, key) {
  return vigenere(text, key, 1);
}

export function vigenereDecrypt(text, key) {
  return vigenere(text, key, -1);
}
