/**
 * Benchmark pipeline enkripsi & dekripsi aplikasi.
 * Jalankan: node test/bench.mjs   (atau: npm run bench)
 *
 * Apa yang diukur — persis alur yang dipakai aplikasi, tanpa simulasi tersendiri:
 *   ENKRIPSI : vigenereEncrypt(plaintext, key)              -> js/vigenere.js
 *              hybridEncrypt(vig.result, publicKey, { aad }) -> js/hybrid.js (AES-256-GCM + RSA-2048-OAEP wrap)
 *   DEKRIPSI : hybridDecrypt(payload, privateKey)            -> js/hybrid.js (unwrap RSA + AES decrypt)
 *              vigenereDecrypt(result, key)                  -> js/vigenere.js
 *
 * Metode:
 *   - Durasi diukur dengan performance.now() yang mengurung `await`,
 *     sehingga operasi asinkron dihitung sampai selesai, bukan sampai Promise dimulai.
 *   - Ukuran data mengikuti format rekam medis aplikasi (JSON.stringify record, indent 2),
 *     target 1 KB / 10 KB / 100 KB berdasar panjang UTF-8 (TextEncoder).
 *   - Data uji SINTETIS — tidak ada data pasien nyata.
 *   - Warm-up 3x tanpa pencatatan, lalu 21 pengukuran per arah per ukuran.
 *   - Laporkan median, mean (+sd), min, max. Enkripsi & dekripsi dipisahkan.
 *   - generateRsaKeyPair() diukur terpisah (5x) karena tidak berada di jalur
 *     per-enkripsi: aplikasi memanggilnya sekali saat init / tombol kunci.
 *
 * Tidak mengubah format ciphertext, algoritma, maupun parameter kriptografi.
 */

import { vigenereEncrypt, vigenereDecrypt } from '../js/vigenere.js';
import {
  generateRsaKeyPair,
  hybridEncrypt,
  hybridDecrypt,
} from '../js/hybrid.js';

/* ----------------------------- konfigurasi ----------------------------- */

const AAD = 'REKAM-MEDIS-v1';           // sama dengan app.js:27
const KUNCI_VIGENERE = 'KUNCIUJI';       // sintetis, bukan kunci produksi

const SIZES = [1024, 10240, 102400];      // 1 KB, 10 KB, 100 KB
const WARMUP = 3;
const RUNS = 21;
const KEYGEN_RUNS = 5;

/* ------------------------------ utilitas ------------------------------- */

const enc8 = new TextEncoder();

/** Buat plaintext ukuran ~targetBytes dalam format rekam medis aplikasi (app.js:160). */
function sizedPlaintext(targetBytes) {
  let n = 0;
  const record = (fillerLen) => JSON.stringify(
    {
      idRekamMedis: 'RM-BENCH-0001',
      namaPasien: 'Sampel Uji (sintetis)',
      unitDiagnosis: 'Poli Data Uji',
      isiRekamMedis: 'k'.repeat(fillerLen),
    },
    null,
    2
  );
  while (enc8.encode(record(n)).length < targetBytes) {
    const kurang = targetBytes - enc8.encode(record(n)).length;
    n += Math.max(1, kurang);
  }
  return record(n);
}

const mean = (a) => a.reduce((s, v) => s + v, 0) / a.length;
const median = (a) => {
  const s = [...a].sort((x, y) => x - y);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
};
const sd = (a) => {
  const m = mean(a);
  return Math.sqrt(mean(a.map((v) => (v - m) ** 2)));
};
const ms = (v) => `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ms`;

/* ------------------------------- ukur satu ------------------------------ */

/** Satu putaran pipeline penuh; konsistensi round-trip dijaga. */
async function measureOnce(plaintext, pair) {
  // --- ENKRIPSI (identik app.js:163-166) ---
  const t0 = performance.now();
  const vig = vigenereEncrypt(plaintext, KUNCI_VIGENERE);
  const { payload } = await hybridEncrypt(vig.result, pair.publicKey, { aad: AAD });
  const encMs = performance.now() - t0;

  // --- DEKRIPSI (identik app.js:230-233) ---
  const t1 = performance.now();
  const vigenereCiphertext = await hybridDecrypt(payload, pair.privateKey);
  const restored = vigenereDecrypt(vigenereCiphertext, KUNCI_VIGENERE).result;
  const decMs = performance.now() - t1;

  if (restored !== plaintext) throw new Error('Round-trip tidak cocok — hasil benchmark tidak sah.');
  return { encMs, decMs };
}

async function measureSet(plaintext, pair, runs, withRecord = true) {
  const encTimes = [];
  const decTimes = [];
  for (let i = 0; i < runs; i += 1) {
    const r = await measureOnce(plaintext, pair);
    encTimes.push(r.encMs);
    decTimes.push(r.decMs);
  }
  if (!withRecord) return null; // warm-up
  return { encTimes, decTimes };
}

function stats(list) {
  return {
    min: Math.min(...list),
    max: Math.max(...list),
    median: median(list),
    mean: mean(list),
    sd: sd(list),
  };
}

function statLine(label, s) {
  return `${pad(label)}  median ${ms(s.median).padStart(9)}  mean ${ms(s.mean).padStart(9)}  ±sd ${ms(s.sd).padStart(9)}  min ${ms(s.min).padStart(9)}  max ${ms(s.max).padStart(9)}`;
}
const pad = (s) => s.padEnd(14);

/* --------------------------------- main --------------------------------- */

function mainHeader() {
  console.log('\nPengukuran Durasi Enkripsi & Dekripsi — rekam-medis-kripto');
  console.log('Pipeline: Vigenere -> AES-256-GCM -> RSA-2048-OAEP (wrap)');
  console.log(`Ukuran: ${SIZES.map((b) => (b >= 1024 ? `${b / 1024} KB` : `${b} B`)).join(', ')}`);
  console.log(`Warm-up ${WARMUP}x tanpa pencatatan, ${RUNS} pengulangan per arah per ukuran.`);
  console.log('Statistik: median, mean (+sd), min, max. Enkripsi & dekripsi dipisahkan.\n');
}

async function main() {
  mainHeader();

  // Overhead keygen diukur terpisah — tidak di dalam jalur per-encrypt.
  console.log('Overhead pembangkitan kunci RSA (generateRsaKeyPair, di luar pipeline)');
  const keygen = [];
  for (let i = 0; i < KEYGEN_RUNS; i += 1) {
    const t = performance.now();
    await generateRsaKeyPair();
    keygen.push(performance.now() - t);
  }
  console.log(`  ${statLine('RSA-2048', stats(keygen))}`);
  console.log('');

  const pair = await generateRsaKeyPair();

  for (const sizeBytes of SIZES) {
    const plaintext = sizedPlaintext(sizeBytes);
    const bytes = enc8.encode(plaintext).length;

    // Warm-up tidak dicatat.
    await measureSet(plaintext, pair, WARMUP, false);

    const { encTimes, decTimes } = await measureSet(plaintext, pair, RUNS);
    const label = `${(sizeBytes / 1024).toFixed(0)} KB (${bytes} B plaintext)`;
    console.log(`Ukuran ${label}`);
    console.log(`  ${statLine('ENKRIPSI', stats(encTimes))}`);
    console.log(`  ${statLine('DEKRIPSI', stats(decTimes))}`);
    console.log('');
  }

  console.log('Hasil hanya data yang benar-benar diukur di jalur pipeline ini, tanpa hasil buatan.');
  console.log('Angka bergantung pada lingkungan (Node webcrypto vs browser) — sebutkan lingkungan saat membandingkan.\n');
}

main();
