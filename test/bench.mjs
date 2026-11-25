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
 *   - Setiap tahap (Vigenere, hibrida) diukur dengan penghitung waktunya sendiri;
 *     total enkripsi = Vigenere + hibrida, total dekripsi = hibrida + Vigenere.
 *   - Ukuran data mengikuti format rekam medis aplikasi (JSON.stringify record, indent 2),
 *     target 1 KB / 10 KB / 100 KB berdasar panjang UTF-8 (TextEncoder).
 *   - Data uji SINTETIS — tidak ada data pasien nyata.
 *   - Pemanasan (warm-up) WARMUP putaran tanpa pencatatan, lalu RUNS pengukuran per arah per ukuran.
 *   - Pengukuran dilakukan bergiliran antarukuran (round-robin) agar gangguan sesaat dari
 *     sistem operasi tersebar merata dan tidak menumpuk pada satu ukuran saja.
 *   - Laporkan median, mean (+sd), p95, min, max. Enkripsi & dekripsi dipisahkan.
 *   - Ukuran payload dihitung dari JSON payload (termasuk metadata `vigenere` yang ditambahkan
 *     app.js:174) tanpa indentasi.
 *   - generateRsaKeyPair() diukur terpisah karena tidak berada di jalur per-enkripsi:
 *     aplikasi memanggilnya sekali saat init / tombol kunci.
 *
 * Tidak mengubah format ciphertext, algoritma, maupun parameter kriptografi.
 */

import os from 'node:os';
import { vigenereEncrypt, vigenereDecrypt } from '../js/vigenere.js';
import {
  generateRsaKeyPair,
  hybridEncrypt,
  hybridDecrypt,
  base64ToBuf,
} from '../js/hybrid.js';

/* ----------------------------- konfigurasi ----------------------------- */

const AAD = 'REKAM-MEDIS-v1';           // sama dengan app.js:35
const KUNCI_VIGENERE = 'KUNCIUJI';       // sintetis, bukan kunci produksi

const SIZES = [1024, 10240, 102400];      // 1 KB, 10 KB, 100 KB
const WARMUP = 10;                        // putaran pemanasan (semua ukuran per putaran)
const RUNS = 51;                          // pengukuran per arah per ukuran
const KEYGEN_RUNS = 10;

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
const percentile = (a, p) => {
  const s = [...a].sort((x, y) => x - y);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
};
const ms = (v) => `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ms`;

function stats(list) {
  return {
    min: Math.min(...list),
    max: Math.max(...list),
    median: median(list),
    mean: mean(list),
    sd: sd(list),
    p95: percentile(list, 95),
  };
}

const pad = (s) => s.padEnd(22);
function statLine(label, s) {
  return `${pad(label)}  median ${ms(s.median).padStart(9)}  mean ${ms(s.mean).padStart(9)}  ±sd ${ms(s.sd).padStart(9)}  p95 ${ms(s.p95).padStart(9)}  min ${ms(s.min).padStart(9)}  max ${ms(s.max).padStart(9)}`;
}

/* ------------------------------- ukur satu ------------------------------ */

/** Satu putaran pipeline penuh; konsistensi round-trip dijaga. */
async function measureOnce(plaintext, pair) {
  // --- ENKRIPSI (identik app.js:171-174) ---
  const a0 = performance.now();
  const vig = vigenereEncrypt(plaintext, KUNCI_VIGENERE);
  const a1 = performance.now();
  const { payload } = await hybridEncrypt(vig.result, pair.publicKey, { aad: AAD });
  const a2 = performance.now();
  payload.vigenere = { keyLength: vig.keyLength, algo: 'Vigenere (A-Z, case-preserving)' };

  // --- DEKRIPSI (identik app.js:230-233) ---
  const b0 = performance.now();
  const vigenereCiphertext = await hybridDecrypt(payload, pair.privateKey);
  const b1 = performance.now();
  const restored = vigenereDecrypt(vigenereCiphertext, KUNCI_VIGENERE).result;
  const b2 = performance.now();

  if (restored !== plaintext) throw new Error('Round-trip tidak cocok — hasil benchmark tidak sah.');
  return {
    vigEnc: a1 - a0,
    hybEnc: a2 - a1,
    hybDec: b1 - b0,
    vigDec: b2 - b1,
    payloadBytes: enc8.encode(JSON.stringify(payload)).length,
    cipherBytes: base64ToBuf(payload.ciphertext).length,
  };
}

/* --------------------------------- main --------------------------------- */

function header() {
  const cpus = os.cpus();
  console.log('\nPengukuran Durasi Enkripsi & Dekripsi — rekam-medis-kripto');
  console.log('Pipeline: Vigenere -> AES-256-GCM -> RSA-2048-OAEP (wrap)');
  console.log(`Ukuran: ${SIZES.map((b) => `${b / 1024} KB`).join(', ')}`);
  console.log(`Warm-up ${WARMUP} putaran tanpa pencatatan, ${RUNS} pengulangan per arah per ukuran (round-robin antarukuran).`);
  console.log('Statistik: median, mean (+sd), p95, min, max. Enkripsi & dekripsi dipisahkan, dengan rincian per tahap.\n');
  console.log('Lingkungan pengujian');
  console.log(`  Node.js     : ${process.version} (V8 ${process.versions.v8})`);
  console.log(`  Sistem op.  : ${os.type()} ${os.release()} (${os.arch()})`);
  console.log(`  CPU         : ${cpus[0] ? cpus[0].model.trim() : 'tidak diketahui'} (${cpus.length} thread)`);
  console.log(`  RAM         : ${(os.totalmem() / 1024 ** 3).toFixed(1)} GB`);
  console.log('');
}

async function main() {
  header();

  // Overhead keygen diukur terpisah — tidak di dalam jalur per-encrypt.
  console.log('Overhead pembangkitan kunci RSA (generateRsaKeyPair, di luar pipeline)');
  await generateRsaKeyPair(); // pemanasan, tidak dicatat
  const keygen = [];
  for (let i = 0; i < KEYGEN_RUNS; i += 1) {
    const t = performance.now();
    await generateRsaKeyPair();
    keygen.push(performance.now() - t);
  }
  const keygenStats = stats(keygen);
  console.log(`  ${statLine('RSA-2048', keygenStats)}`);
  console.log('');

  const pair = await generateRsaKeyPair();

  const sets = SIZES.map((sizeBytes) => {
    const plaintext = sizedPlaintext(sizeBytes);
    return {
      sizeBytes,
      plaintext,
      bytes: enc8.encode(plaintext).length,
      vigEnc: [], hybEnc: [], hybDec: [], vigDec: [], enc: [], dec: [],
      payloadBytes: 0,
      cipherBytes: 0,
    };
  });

  // Pemanasan: semua ukuran, tidak dicatat.
  for (let w = 0; w < WARMUP; w += 1) {
    for (const d of sets) await measureOnce(d.plaintext, pair);
  }

  // Pengukuran bergiliran antarukuran.
  for (let r = 0; r < RUNS; r += 1) {
    for (const d of sets) {
      const m = await measureOnce(d.plaintext, pair);
      d.vigEnc.push(m.vigEnc);
      d.hybEnc.push(m.hybEnc);
      d.hybDec.push(m.hybDec);
      d.vigDec.push(m.vigDec);
      d.enc.push(m.vigEnc + m.hybEnc);
      d.dec.push(m.hybDec + m.vigDec);
      d.payloadBytes = m.payloadBytes;
      d.cipherBytes = m.cipherBytes;
    }
  }

  for (const d of sets) {
    console.log(`Ukuran ${(d.sizeBytes / 1024).toFixed(0)} KB (${d.bytes} B plaintext)`);
    console.log(`  ${statLine('ENKRIPSI (total)', stats(d.enc))}`);
    console.log(`  ${statLine('  - Vigenere', stats(d.vigEnc))}`);
    console.log(`  ${statLine('  - AES-GCM + RSA wrap', stats(d.hybEnc))}`);
    console.log(`  ${statLine('DEKRIPSI (total)', stats(d.dec))}`);
    console.log(`  ${statLine('  - RSA unwrap + AES', stats(d.hybDec))}`);
    console.log(`  ${statLine('  - Vigenere', stats(d.vigDec))}`);
    console.log(`  Ukuran payload JSON: ${d.payloadBytes} B (ciphertext+tag: ${d.cipherBytes} B)`);
    console.log('');
  }

  // Ringkasan siap salin ke tabel makalah (median, ms).
  console.log('Ringkasan untuk tabel makalah (median, ms)');
  console.log('| Ukuran plaintext | Enkripsi (ms) | Dekripsi (ms) | Ukuran payload (byte) |');
  console.log('|---|---|---|---|');
  for (const d of sets) {
    console.log(`| ${(d.sizeBytes / 1024).toFixed(0)} KB (${d.bytes} B) | ${median(d.enc).toFixed(2)} | ${median(d.dec).toFixed(2)} | ${d.payloadBytes} |`);
  }
  console.log(`| Pembangkitan kunci RSA-2048 | ${keygenStats.median.toFixed(2)} | - | - |`);
  console.log('');

  console.log('Hasil hanya data yang benar-benar diukur di jalur pipeline ini, tanpa hasil buatan.');
  console.log('Angka bergantung pada lingkungan (Node webcrypto vs browser) — sebutkan lingkungan saat membandingkan.');
  console.log('Jika sd besar: sambungkan laptop ke listrik, tutup aplikasi lain, lalu ulangi 3x dan laporkan median.\n');
}

main();