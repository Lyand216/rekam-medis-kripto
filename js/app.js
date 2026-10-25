import {
  vigenereEncrypt,
  vigenereDecrypt,
  normalizeKey,
} from './vigenere.js';
import {
  generateRsaKeyPair,
  exportPublicKeyPem,
  exportPrivateKeyPem,
  importPublicKeyPem,
  importPrivateKeyPem,
  hybridEncrypt,
  hybridDecrypt,
  fingerprint,
  base64ToBuf,
} from './hybrid.js';

/* ============================== state ============================== */

const state = {
  publicKey: null,
  privateKey: null,
  lastPayload: null,
  history: [],
};

const AAD = 'REKAM-MEDIS-v1';
const HISTORY_KEY = 'rm-kripto-history';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

/* ============================== utils ============================== */

function toast(message, type = 'ok') {
  const el = $('#toast');
  el.textContent = message;
  el.dataset.type = type;
  el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), 2600);
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

async function copyText(text, label = 'Teks') {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} disalin ke clipboard.`);
  } catch {
    toast('Gagal menyalin. Salin manual ya.', 'warn');
  }
}

function download(filename, content, mime = 'application/json') {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function switchTab(name) {
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  $$('.panel').forEach((p) => p.classList.toggle('active', p.dataset.panel === name));
}

/* =========================== key management ========================= */

async function generateKeys(silent = false) {
  try {
    const pair = await generateRsaKeyPair();
    state.publicKey = pair.publicKey;
    state.privateKey = pair.privateKey;

    const pubPem = await exportPublicKeyPem(pair.publicKey);
    const privPem = await exportPrivateKeyPem(pair.privateKey);
    $('#pubPem').value = pubPem;
    $('#privPem').value = privPem;

    const spki = base64ToBuf(
      pubPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
    );
    $('#keyStatus').textContent = 'Kunci aktif · RSA-2048-OAEP (SHA-256)';
    $('#keyFingerprint').textContent = fingerprint(spki);
    $('#keyBadge').dataset.state = 'ready';
    $('#keyBadge').textContent = 'Kunci siap';

    if (!silent) toast('Pasangan kunci RSA-2048 berhasil dibuat.');
  } catch (err) {
    $('#keyBadge').dataset.state = 'error';
    $('#keyBadge').textContent = 'Kunci gagal';
    toast(err.message, 'error');
  }
}

/* ============================== enkripsi ============================ */

function collectRecord() {
  const record = {
    idRekamMedis: $('#fId').value.trim() || '(kosong)',
    namaPasien: $('#fNama').value.trim() || '(kosong)',
    unitDiagnosis: $('#fUnit').value.trim() || '(kosong)',
    isiRekamMedis: $('#fIsi').value.trim() || '(kosong)',
  };
  return record;
}

function renderVigenereSteps(steps, container) {
  if (!steps.length) {
    container.innerHTML = '<p class="muted">Tidak ada huruf untuk digeser.</p>';
    return;
  }
  const rows = steps.map((s) => `
    <tr>
      <td class="mono">${escapeHtml(s.char)}</td>
      <td class="mono">${escapeHtml(s.key)}</td>
      <td class="mono">${s.plainIndex}</td>
      <td class="mono">+</td>
      <td class="mono">${s.keyIndex}</td>
      <td class="mono">→</td>
      <td class="mono strong">${escapeHtml(s.out)}</td>
    </tr>`).join('');
  container.innerHTML = `
    <table class="calc-table">
      <thead><tr><th>Plain</th><th>Kunci</th><th>Idx</th><th></th><th>Geser</th><th></th><th>Cipher</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="muted small">Ditampilkan maksimal 12 huruf pertama sebagai contoh perhitungan.</p>`;
}

async function handleEncrypt(event) {
  event.preventDefault();
  if (!state.publicKey) {
    toast('Kunci publik belum siap. Buka tab "Kunci RSA" lalu buat kunci.', 'error');
    switchTab('kunci');
    return;
  }

  const btn = $('#btnEncrypt');
  btn.disabled = true;
  btn.classList.add('loading');
  $('#encSeal').classList.remove('on');

  try {
    const record = collectRecord();
    const keyword = $('#fKey').value;

    if (!keyword.trim()) {
      // Validasi awal kunci Vigenere.
      normalizeKey(keyword);
    }

    const plaintext = JSON.stringify(record, null, 2);

    // Langkah 1 → Vigenere
    const vig = vigenereEncrypt(plaintext, keyword);

    // Langkah 2 & 3 → AES + RSA
    const { payload } = await hybridEncrypt(vig.result, state.publicKey, { aad: AAD });
    payload.vigenere = { keyLength: vig.keyLength, algo: 'Vigenere (A-Z, case-preserving)' };

    state.lastPayload = payload;

    /* ---------------- tampilkan hasil ---------------- */
    $('#encEmpty').hidden = true;
    $('#encResult').hidden = false;

    $('#outPlain').textContent = plaintext;
    $('#outVigenere').textContent = vig.result;
    $('#outCiphertext').value = payload.ciphertext;
    $('#outWrappedKey').value = payload.wrappedKey;
    $('#outIv').value = payload.iv;
    $('#outJson').value = JSON.stringify(payload, null, 2);
    $('#outRmNo').textContent = record.idRekamMedis;
    $('#outState').textContent = 'Terenkripsi';
    $('#encSeal').classList.add('on');
    $('#outMeta').innerHTML = `
      <span class="chip">${escapeHtml(payload.alg)}</span>
      <span class="chip">Panjang plaintext: ${plaintext.length} char</span>
      <span class="chip">Ciphertext: ${payload.ciphertext.length} char (base64)</span>
      <span class="chip">Wrapped key: ${payload.wrappedKey.length} char</span>`;

    renderVigenereSteps(vig.steps, $('#vigenereSteps'));

    saveHistory({
      idRekamMedis: record.idRekamMedis,
      namaPasien: record.namaPasien,
      alg: payload.alg,
      payload,
    });

    toast('Rekam medis berhasil dienkripsi (Vigenere → AES → RSA).');
  } catch (err) {
    toast(err.message || 'Enkripsi gagal.', 'error');
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
  }
}

/* ============================== dekripsi ============================ */

async function handleDecrypt(event) {
  event.preventDefault();
  const btn = $('#btnDecrypt');
  btn.disabled = true;
  $('#decSeal').classList.remove('on');

  try {
    const raw = $('#dPayload').value.trim();
    if (!raw) throw new Error('Tempel payload JSON terlebih dahulu.');

    let privateKey = state.privateKey;
    const pem = $('#dPrivPem').value.trim();
    if (pem) {
      privateKey = await importPrivateKeyPem(pem);
    }
    if (!privateKey) throw new Error('Tidak ada kunci privat. Buat kunci baru atau tempel kunci privat.');

    const keyword = $('#dKey').value;

    // Langkah 1 → buka kunci AES + dekripsi AES
    const vigenereCiphertext = await hybridDecrypt(raw, privateKey);

    // Langkah 2 → dekripsi Vigenere
    const plaintext = vigenereDecrypt(vigenereCiphertext, keyword).result;

    let record;
    try {
      record = JSON.parse(plaintext);
    } catch {
      record = null;
    }

    $('#decEmpty').hidden = true;
    $('#decResult').hidden = false;
    $('#decSeal').classList.add('on');

    if (record) {
      $('#decFields').innerHTML = `
        <div class="field-row"><span>ID Rekam Medis</span><strong>${escapeHtml(record.idRekamMedis)}</strong></div>
        <div class="field-row"><span>Nama Pasien</span><strong>${escapeHtml(record.namaPasien)}</strong></div>
        <div class="field-row"><span>Unit / Diagnosis</span><strong>${escapeHtml(record.unitDiagnosis)}</strong></div>
        <div class="field-row"><span>Isi Rekam Medis</span><strong class="pre">${escapeHtml(record.isiRekamMedis)}</strong></div>`;
      $('#decFields').hidden = false;
      $('#decRawWrap').hidden = true;
    } else {
      $('#decFields').hidden = true;
      $('#decRawWrap').hidden = false;
      $('#decRaw').textContent = plaintext;
    }

    $('#decVigenere').textContent = vigenereCiphertext;
    toast('Rekam medis berhasil didekripsi & diverifikasi.');
  } catch (err) {
    // GCM gagal → data/kunci tidak cocok atau telah dimodifikasi.
    const message = /operation failed|tag|decrypt/i.test(err.message)
      ? 'Dekripsi gagal: kunci privat salah, kata kunci Vigenere salah, atau data telah dimodifikasi.'
      : err.message;
    $('#decEmpty').hidden = true;
    $('#decResult').hidden = false;
    $('#decFields').hidden = true;
    $('#decRawWrap').hidden = false;
    $('#decRaw').textContent = message;
    $('#decVigenere').textContent = '—';
    toast(message, 'error');
  } finally {
    btn.disabled = false;
  }
}

/* ============================== riwayat ============================= */

function loadHistory() {
  try {
    state.history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  } catch {
    state.history = [];
  }
  renderHistory();
}

function saveHistory(entry) {
  state.history.unshift({ ...entry, waktu: new Date().toISOString() });
  state.history = state.history.slice(0, 25);
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history));
  } catch {
    /* localStorage penuh / diblokir → abaikan */
  }
  renderHistory();
}

function renderHistory() {
  const body = $('#historyBody');
  if (!state.history.length) {
    body.innerHTML = `<tr><td colspan="5" class="muted center">Belum ada riwayat enkripsi.</td></tr>`;
    $('#btnClearHistory').disabled = true;
    return;
  }
  $('#btnClearHistory').disabled = false;
  body.innerHTML = state.history.map((h, i) => `
    <tr>
      <td class="mono small" data-label="Waktu">${new Date(h.waktu).toLocaleString('id-ID')}</td>
      <td class="mono" data-label="ID RM">${escapeHtml(h.idRekamMedis)}</td>
      <td data-label="Nama">${escapeHtml(h.namaPasien)}</td>
      <td class="mono small" data-label="Algoritma">${escapeHtml(h.alg)}</td>
      <td class="right ta-r" data-label="Aksi">
        <button class="link" data-load="${i}">Muat</button>
        <button class="link danger" data-del="${i}">Hapus</button>
      </td>
    </tr>`).join('');
}

/* ============================== riwayat evt ========================= */

document.addEventListener('click', (e) => {
  const load = e.target.closest('[data-load]');
  if (load) {
    const item = state.history[Number(load.dataset.load)];
    if (item) {
      $('#dPayload').value = JSON.stringify(item.payload, null, 2);
      switchTab('dekripsi');
      toast('Payload dimuat ke tab Dekripsi.');
    }
  }
  const del = e.target.closest('[data-del]');
  if (del) {
    state.history.splice(Number(del.dataset.del), 1);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history));
    renderHistory();
    toast('Riwayat dihapus.');
  }
});

/* ============================== bootstrap =========================== */

function init() {
  // Tab
  $$('.tab').forEach((tab) => tab.addEventListener('click', () => switchTab(tab.dataset.tab)));
  $$('[data-goto]').forEach((el) => el.addEventListener('click', () => switchTab(el.dataset.goto)));

  // Form
  $('#formEncrypt').addEventListener('submit', handleEncrypt);
  $('#formDecrypt').addEventListener('submit', handleDecrypt);

  // Kunci
  $('#btnGenerate').addEventListener('click', () => generateKeys());
  $('#btnCopyPub').addEventListener('click', () => copyText($('#pubPem').value, 'Kunci publik'));
  $('#btnCopyPriv').addEventListener('click', () => copyText($('#privPem').value, 'Kunci privat'));
  $('#btnDownloadPriv').addEventListener('click', () =>
    download('private-key.pem', $('#privPem').value, 'text/plain'));

  $('#btnImportPub').addEventListener('click', async () => {
    try {
      state.publicKey = await importPublicKeyPem($('#importPub').value);
      const spki = base64ToBuf(
        $('#importPub').value.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
      );
      $('#keyFingerprint').textContent = fingerprint(spki);
      $('#keyStatus').textContent = 'Kunci publik hasil impor · siap untuk enkripsi';
      $('#keyBadge').dataset.state = 'ready';
      $('#keyBadge').textContent = 'Kunci siap';
      toast('Kunci publik berhasil diimpor.');
    } catch {
      toast('Kunci publik tidak valid.', 'error');
    }
  });

  // Hasil enkripsi → aksi
  $('#btnCopyCipher').addEventListener('click', () => copyText($('#outJson').value, 'Payload JSON'));
  $('#btnDownloadCipher').addEventListener('click', () => {
    const id = ($('#fId').value.trim() || 'rekam-medis').replace(/[^\w.-]+/g, '_');
    download(`${id}.enc.json`, $('#outJson').value);
    toast('Payload diunduh.');
  });
  $('#btnSendToDecrypt').addEventListener('click', () => {
    if (!state.lastPayload) return;
    $('#dPayload').value = JSON.stringify(state.lastPayload, null, 2);
    $('#dKey').value = $('#fKey').value;
    switchTab('dekripsi');
    toast('Payload & kata kunci dikirim ke tab Dekripsi.');
  });

  // Riwayat
  $('#btnClearHistory').addEventListener('click', () => {
    state.history = [];
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
    toast('Riwayat dibersihkan.');
  });

  loadHistory();
  generateKeys(true);
}

document.addEventListener('DOMContentLoaded', init);
