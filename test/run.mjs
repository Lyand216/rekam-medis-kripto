/**
 * Uji cepat round-trip pipeline (Vigenere + AES + RSA).
 * Jalankan: node test/run.mjs
 */
import { vigenereEncrypt, vigenereDecrypt } from '../js/vigenere.js';
import {
  generateRsaKeyPair,
  hybridEncrypt,
  hybridDecrypt,
} from '../js/hybrid.js';
import { HISTORY_SCHEMA, buildEntry, migrateEntry, sanitizeEntry } from '../js/history.js';

let pass = 0;
let fail = 0;

function check(name, cond) {
  if (cond) { pass += 1; console.log(`  ok   ${name}`); }
  else { fail += 1; console.log(`  FAIL ${name}`); }
}

console.log('\nVigenere Cipher');

const plain = 'Pasien Budi, TD 150/95!';
const enc = vigenereEncrypt(plain, 'RAHASIAMEDIS');
check('ciphertext berbeda dari plaintext', enc.result !== plain);
check('huruf non-alfabet dipertahankan', enc.result.includes('150/95!'));
check('panjang sama persis', enc.result.length === plain.length);
check('dekripsi mengembalikan aslinya', vigenereDecrypt(enc.result, 'RAHASIAMEDIS').result === plain);
check('spasi & tanda baca utuh', vigenereDecrypt(enc.result, 'RAHASIAMEDIS').result === plain);
check('kunci beda -> hasil beda', vigenereDecrypt(enc.result, 'KUNCIBEDA').result !== plain);

// Kunci klasik "ATTACKATDAWN" -> "LEMONLEMONLE"
check('kasus uji baku Vigenere (ATTACKATDAWN/LEMON)',
  vigenereEncrypt('ATTACKATDAWN', 'LEMON').result === 'LXFOPVEFRNHR');

console.log('\nKriptografi Hibrida AES-256-GCM + RSA-2048-OAEP');

const pair = await generateRsaKeyPair();
const record = JSON.stringify({
  idRekamMedis: 'RM-2026-00123',
  namaPasien: 'Budi Santoso',
  isiRekamMedis: 'Hipertensi stadium 1. Terapi Amlodipine 5mg.',
});

const vig = vigenereEncrypt(record, 'RAHASIAMEDIS');
const { payload } = await hybridEncrypt(vig.result, pair.publicKey, { aad: 'REKAM-MEDIS-v1' });

check('payload punya iv, wrappedKey, ciphertext',
  Boolean(payload.iv && payload.wrappedKey && payload.ciphertext));
check('kunci AES terbungkus (bukan mentah)', !payload.ciphertext.includes('CryptoKey'));

const recovered = await hybridDecrypt(payload, pair.privateKey);
check('AES membuka data kembali', recovered === vig.result);
check('Vigenere mengembalikan rekam medis asli',
  vigenereDecrypt(recovered, 'RAHASIAMEDIS').result === record);

// Integritas: ubah 1 karakter ciphertext -> GCM harus menolak.
let tamperRejected = false;
try {
  const tampered = { ...payload, ciphertext: payload.ciphertext.slice(0, -2) + (payload.ciphertext.endsWith('A') ? 'B' : 'A') };
  await hybridDecrypt(tampered, pair.privateKey);
} catch {
  tamperRejected = true;
}
check('ciphertext yang diubah ditolak (AEAD)', tamperRejected);

// Kunci salah -> harus gagal.
const other = await generateRsaKeyPair();
let wrongKeyRejected = false;
try {
  await hybridDecrypt(payload, other.privateKey);
} catch {
  wrongKeyRejected = true;
}
check('kunci privat salah ditolak', wrongKeyRejected);

console.log('\nRiwayat — identitas pasien tidak ikut tersimpan');

// Data pasien di sini SINTETIS, hanya untuk menguji penyaringan metadata.
const LEGACY_NAME = 'Sampel Nama Uji';
const LEGACY_ID = 'RM-UJI-000001';

const recordUji = JSON.stringify({
  idRekamMedis: LEGACY_ID,
  namaPasien: LEGACY_NAME,
  unitDiagnosis: 'Poli Uji',
  isiRekamMedis: 'Catatan uji otomatis.',
}, null, 2);

const pairUji = await generateRsaKeyPair();
const vigUji = vigenereEncrypt(recordUji, 'KUNCIUJI');
const { payload: payloadUji } = await hybridEncrypt(vigUji.result, pairUji.publicKey, { aad: 'REKAM-MEDIS-v1' });

const entryBaru = buildEntry({ payload: payloadUji, plainLength: recordUji.length });
check('entri baru tanpa field identitas',
  !('idRekamMedis' in entryBaru) && !('namaPasien' in entryBaru));
check('entri baru hanya berisi kolom teknis',
  Object.keys(entryBaru).every((k) =>
    ['schemaVersion', 'waktu', 'alg', 'ukuran', 'ringkas', 'payload'].includes(k)));
check('entri baru ditandai schemaVersion 2', entryBaru.schemaVersion === HISTORY_SCHEMA);
check('nama pasien tidak ada di JSON entri baru',
  !JSON.stringify(entryBaru).includes(LEGACY_NAME));
check('ukuran plaintext tercatat', entryBaru.ukuran.plain === recordUji.length);
check('ukuran ciphertext tercatat (byte)', entryBaru.ukuran.cipher > 0);
check('ringkasan adalah tag teknis (hex)', /^[0-9a-f .]+$/.test(entryBaru.ringkas));
check('payload di entri baru utuh', entryBaru.payload.ciphertext === payloadUji.ciphertext);

console.log('\nRiwayat — migrasi skema lama (idempoten, payload dipertahankan)');

// Bentuk entri skema lama persis seperti versi sebelumnya di app.js.
const legacyEntry = {
  idRekamMedis: LEGACY_ID,
  namaPasien: LEGACY_NAME,
  alg: 'VIGENERE+AES-256-GCM+RSA-2048-OAEP',
  payload: payloadUji,
  waktu: '2026-01-02T03:04:05.000Z',
};

const migrated = migrateEntry(legacyEntry);
check('migrasi menghasilkan entri', migrated !== null);
check('migrasi menandai schemaVersion 2', migrated.schemaVersion === HISTORY_SCHEMA);
check('migrasi membuang idRekamMedis', !('idRekamMedis' in migrated));
check('migrasi membuang namaPasien', !('namaPasien' in migrated));
check('payload ciphertext tidak berubah', migrated.payload.ciphertext === legacyEntry.payload.ciphertext);
check('payload wrappedKey tidak berubah', migrated.payload.wrappedKey === legacyEntry.payload.wrappedKey);
check('payload IV tidak berubah', migrated.payload.iv === legacyEntry.payload.iv);
check('waktu asli dipertahankan', migrated.waktu === legacyEntry.waktu);
check('tag ringkasan dibangkitkan dari ciphertext', migrated.ringkas.length > 0);

// Idempoten: migrasi ulang hasil migrasi tidak mengubah apa pun.
const ketikaSudah = migrateEntry(migrated);
check('migrasi idempoten (objek yang sama kembali)',
  ketikaSudah === migrated);

// Payload hasil migrasi benar-benar dapat didekripsi.
const pulihMigrasi = await hybridDecrypt(migrated.payload, pairUji.privateKey);
check('payload hasil migrasi dapat didekripsi', pulihMigrasi === vigUji.result);
check('rekam medis asli kembali dari entri hasil migrasi',
  vigenereDecrypt(pulihMigrasi, 'KUNCIUJI').result === recordUji);

// Entri tanpa payload tidak bisa dipertahankan → null.
check('entri tanpa payload tidak dipertahankan (null)', migrateEntry({ idRekamMedis: 'x' }) === null);

// Ciphertext rusak: entri tetap disimpan, payload tidak dibuang.
const rusak = migrateEntry({ payload: { ciphertext: '@@TIDAKVALID@@', iv: 'x', wrappedKey: 'x' } });
check('ciphertext base64 rusak: entri tetap dipertahankan', rusak !== null && rusak.payload.ciphertext === '@@TIDAKVALID@@');

// Sanitasi: field di luar daftar terbuang.
const tersaring = sanitizeEntry({ ...migrated, idRekamMedis: 'bocor' });
check('sanitize memungkinkan hanya kolom teknis', !('idRekamMedis' in tersaring));

console.log('\nRiwayat — round-trip lewat entri baru (tanpa identitas)');
const pulihBaru = await hybridDecrypt(entryBaru.payload, pairUji.privateKey);
check('payload entri baru dapat didekripsi', pulihBaru === vigUji.result);
check('plaintext identik setelah round-trip',
  vigenereDecrypt(pulihBaru, 'KUNCIUJI').result === recordUji);

console.log(`\n${pass} lulus, ${fail} gagal\n`);
process.exit(fail === 0 ? 0 : 1);
