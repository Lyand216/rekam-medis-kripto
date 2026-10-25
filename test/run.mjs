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

console.log(`\n${pass} lulus, ${fail} gagal\n`);
process.exit(fail === 0 ? 0 : 1);
