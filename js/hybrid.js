/**
 * Kriptografi Hibrida AES-256-GCM + RSA-2048-OAEP
 * ------------------------------------------------------------------
 * Mengapa hibrida?
 *  - AES (simetris) cepat untuk data besar seperti isi rekam medis.
 *  - RSA (asimetris) aman untuk bertukar kunci tanpa saluran rahasia,
 *    tetapi lambat & terbatas ukurannya.
 *  - Solusi: data dienkripsi AES, lalu "kunci AES" dibungkus RSA.
 *    Inilah pola yang dipakai TLS, PGP, dan sistem rekam medis nyata.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

export const RSA_PARAMS = {
  name: 'RSA-OAEP',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: 'SHA-256',
};

export const AES_PARAMS = {
  name: 'AES-GCM',
  length: 256,
  ivBytes: 12,
};

/* ----------------------------- util biner ----------------------------- */

export function bufToBase64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBuf(b64) {
  const binary = atob(String(b64).trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function fingerprint(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  // Kelompokkan agar mudah dibaca.
  return (hex.match(/.{1,4}/g) || []).slice(0, 8).join(' ');
}

/* ------------------------------- kunci -------------------------------- */

export function assertCrypto() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error(
      'Web Crypto API tidak tersedia. Buka halaman melalui http://localhost atau browser modern (Chrome/Edge/Firefox).'
    );
  }
}

/** Bangkitkan pasangan kunci RSA (dipakai sebagai kunci induk / KEK). */
export async function generateRsaKeyPair() {
  assertCrypto();
  return crypto.subtle.generateKey(RSA_PARAMS, true, ['encrypt', 'decrypt']);
}

export async function exportPublicKeyPem(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return toPem(spki, 'PUBLIC KEY');
}

export async function exportPrivateKeyPem(privateKey) {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  return toPem(pkcs8, 'PRIVATE KEY');
}

export async function importPublicKeyPem(pem) {
  const der = fromPem(pem);
  return crypto.subtle.importKey('spki', der, RSA_PARAMS, true, ['encrypt']);
}

export async function importPrivateKeyPem(pem) {
  const der = fromPem(pem);
  return crypto.subtle.importKey('pkcs8', der, RSA_PARAMS, true, ['decrypt']);
}

function toPem(buf, label) {
  const b64 = bufToBase64(buf);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function fromPem(pem) {
  const b64 = String(pem)
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  return base64ToBuf(b64);
}

/* ------------------------------ hibrida ------------------------------- */

/**
 * Enkripsi hibrida.
 * @param {string} plaintext  teks yang sudah (opsional) melewati Vigenere
 * @param {CryptoKey} publicKey  RSA public key
 * @param {{aad?: string}} [opts]  Additional Authenticated Data (metadata)
 * @returns {Promise<{payload: object, aesKey: CryptoKey, rawAesKey: Uint8Array, iv: Uint8Array}>}
 */
export async function hybridEncrypt(plaintext, publicKey, opts = {}) {
  assertCrypto();

  // 1. Kunci sesi AES-256 acak.
  const aesKey = await crypto.subtle.generateKey(AES_PARAMS, true, ['encrypt', 'decrypt']);

  // 2. IV acak (wajib unik per enkripsi pada GCM).
  const iv = crypto.getRandomValues(new Uint8Array(AES_PARAMS.ivBytes));

  // 3. Enkripsi data dengan AES-GCM.
  const cipherBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: opts.aad ? enc.encode(opts.aad) : undefined },
    aesKey,
    enc.encode(plaintext)
  );

  // 4. Bungkus (wrap) kunci AES memakai RSA-OAEP.
  const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
  const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, rawAesKey);

  return {
    payload: {
      v: 1,
      alg: 'VIGENERE+AES-256-GCM+RSA-2048-OAEP',
      iv: bufToBase64(iv),
      aad: opts.aad || null,
      wrappedKey: bufToBase64(wrappedKey),
      ciphertext: bufToBase64(cipherBuf),
      createdAt: new Date().toISOString(),
    },
    aesKey,
    rawAesKey: new Uint8Array(rawAesKey),
    iv,
  };
}

/**
 * Dekripsi hibrida (kebalikan hybridEncrypt).
 * @param {object|string} payload  objek payload atau string JSON
 * @param {CryptoKey} privateKey  RSA private key
 * @returns {Promise<string>}
 */
export async function hybridDecrypt(payload, privateKey) {
  assertCrypto();
  const data = typeof payload === 'string' ? JSON.parse(payload) : payload;

  if (!data || !data.wrappedKey || !data.ciphertext || !data.iv) {
    throw new Error('Payload tidak lengkap (butuh wrappedKey, iv, dan ciphertext).');
  }

  // 1. Buka kunci AES dari wrappedKey.
  const wrappedKey = base64ToBuf(data.wrappedKey);
  const rawAesKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, wrappedKey);

  // 2. Impor kembali sebagai kunci AES.
  const aesKey = await crypto.subtle.importKey('raw', rawAesKey, AES_PARAMS, false, ['decrypt']);

  // 3. Dekripsi data. Jika AAD/diubah, GCM akan gagal (integritas terjaga).
  const iv = base64ToBuf(data.iv);
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: data.aad ? enc.encode(data.aad) : undefined },
    aesKey,
    base64ToBuf(data.ciphertext)
  );

  return dec.decode(plainBuf);
}
