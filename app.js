// Crypted · app web del iPhone
// El vídeo se cifra EN EL IPHONE con la llave pública de tu bóveda antes de guardarse o subirse.
// Este teléfono no tiene la llave privada: no puede volver a ver lo que ha grabado.
import { createSealer, createChunker, CHUNK, b64urlToBytes, bytesToB64url } from './crypto.js';
import * as store from './store.js';
import * as lan from './lan.js';

const $ = (s) => document.querySelector(s);
const PAIR_KEY = 'cv.pair';
const fmtSize = (b) => (b < 1048576 ? `${Math.max(1, Math.round(b / 1024))} KB` : b < 1073741824 ? `${(b / 1048576).toFixed(1)} MB` : `${(b / 1073741824).toFixed(2)} GB`);
const pad = (n) => String(n).padStart(2, '0');
const clipName = (d, ext) => `Clip ${pad(d.getHours())}.${pad(d.getMinutes())}.${ext}`;
const newId = () => bytesToB64url(crypto.getRandomValues(new Uint8Array(16)));

let pairing = null;
try { pairing = JSON.parse(localStorage.getItem(PAIR_KEY) || 'null'); } catch { pairing = null; }

// ---------- arranque: vinculación ----------
/** Lee la vinculación del enlace (#pair=…) o de un QR escaneado dentro de la app. */
function readHash(fragment) {
  const fromUrl = fragment === undefined;
  const h = new URLSearchParams(fromUrl ? location.hash.slice(1) : fragment);
  if (!h.get('pair')) return;
  try {
    const p = JSON.parse(new TextDecoder().decode(b64urlToBytes(h.get('pair'))));
    if (p.v !== 2 || b64urlToBytes(p.pk).length !== 65 || !/^[A-Za-z0-9_-]{20,200}$/.test(p.tok) || !Array.isArray(p.hosts) || !p.hosts.length) throw new Error();
    const hosts = p.hosts.filter((x) => /^[a-z0-9.-]+$/i.test(x)).slice(0, 8);
    if (pairing && pairing.pk !== p.pk && !confirm('Este iPhone ya estaba vinculado a otra bóveda. ¿Cambiar a la nueva?')) throw new Error('cancel');
    pairing = {
      pk: p.pk, tok: p.tok, hosts, port: Number(p.port) || lan.PORT,
      prof: /^http:\/\/[a-z0-9.-]+:\d+\/[\w.-]+\.mobileconfig$/i.test(p.prof || '') ? p.prof : '',
      u: String(p.u || '').slice(0, 40), at: new Date().toISOString(),
      ok: !!(pairing && pairing.ok && pairing.pk === p.pk), // si ya funcionaba con este PC, el certificado ya está instalado
    };
    localStorage.setItem(PAIR_KEY, JSON.stringify(pairing));
    pc = null;
    toast('iPhone vinculado a tu bóveda');
  } catch (e) {
    if (e.message !== 'cancel') toast('El enlace de vinculación no es válido', true);
  }
  if (fromUrl) history.replaceState(null, '', location.pathname); // limpiar el enlace (no dejar el token a la vista)
}

// ---------- lector de QR integrado ----------
// En el iPhone, la app añadida a la pantalla de inicio no comparte datos con Safari:
// por eso puede vincularse escaneando el QR del PC desde dentro de la propia app.
let scanStream = null;
let scanning = false;

async function startScan() {
  if (typeof jsQR !== 'function') { toast('No se pudo cargar el lector de QR', true); return; }
  closeCamera();
  $('#scanner').hidden = false;
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } } });
  } catch (e) {
    stopScan();
    toast(e.name === 'NotAllowedError' ? 'Permite el acceso a la cámara para escanear el QR' : e.message, true);
    return;
  }
  const v = $('#scan-video');
  v.srcObject = scanStream;
  await v.play().catch(() => {});
  scanning = true;
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const tick = () => {
    if (!scanning) return;
    if (v.readyState >= 2 && v.videoWidth) {
      const s = Math.min(1, 960 / Math.max(v.videoWidth, v.videoHeight));
      canvas.width = Math.round(v.videoWidth * s);
      canvas.height = Math.round(v.videoHeight * s);
      ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(img.data, canvas.width, canvas.height, { inversionAttempts: 'dontInvert' });
      if (code && code.data) {
        const i = code.data.indexOf('#pair=');
        if (i >= 0) {
          stopScan();
          if (navigator.vibrate) navigator.vibrate(60);
          readHash(code.data.slice(i + 1));
          render();
          pump();
          return;
        }
        if (!tick.warned) { tick.warned = true; toast('Ese QR no es el de Crypted Vault', true); }
      }
    }
    requestAnimationFrame(tick);
  };
  tick();
}

function stopScan() {
  scanning = false;
  if (scanStream) scanStream.getTracks().forEach((t) => t.stop());
  scanStream = null;
  $('#scan-video').srcObject = null;
  $('#scanner').hidden = true;
}

let pc = null;          // { base, name } del PC encontrado en esta sesión
let pcState = 'idle';   // idle | searching | found | missing
async function locatePC() {
  if (pc) return pc;
  pcState = 'searching';
  renderChip();
  pc = await lan.findPC(pairing);
  pcState = pc ? 'found' : 'missing';
  if (pc && !pairing.ok) { pairing.ok = true; localStorage.setItem(PAIR_KEY, JSON.stringify(pairing)); toast(`Conectado con ${pc.name}`); }
  render();
  return pc;
}

// ---------- interfaz ----------
function toast(msg, error = false) {
  const t = document.createElement('div');
  t.className = `toast${error ? ' error' : ''}`;
  t.textContent = msg;
  $('#toasts').append(t);
  setTimeout(() => t.remove(), 3500);
}

function render() {
  $('#view-unpaired').hidden = !!pairing;
  $('#view-main').hidden = !pairing;
  if (!pairing) return;
  $('#vault-user').textContent = pairing.u ? `Bóveda de ${pairing.u}` : 'Tu bóveda';
  // la guía del certificado se muestra hasta la primera conexión correcta con el PC
  $('#setup-banner').hidden = !!pairing.ok;
  $('#install-cert').href = pairing.prof || '#';
  renderChip();
  renderQueue();
}

function renderChip() {
  const chip = $('#pc-chip');
  const t = { idle: 'PC', searching: 'Buscando PC…', found: 'PC conectado', missing: 'PC no encontrado' }[pcState];
  chip.textContent = t;
  chip.classList.toggle('on', pcState === 'found');
}

const STATUS = {
  recording: 'Grabando…',
  encrypting: 'Cifrando…',
  queued: 'En cola para subir',
  uploading: 'Subiendo',
  done: '✓ En tu PC',
  failed: 'Interrumpido',
  waiting: 'Esperando al PC (en casa)',
};

async function renderQueue() {
  const clips = (await store.allClips()).sort((a, b) => b.recordedAt.localeCompare(a.recordedAt));
  const list = $('#queue');
  list.replaceChildren();
  $('#queue-empty').hidden = clips.length > 0;
  for (const c of clips.slice(0, 40)) {
    const li = document.createElement('li');
    li.className = `q-item s-${c.status}`;
    const pct = c.status === 'uploading' && c.total ? ` ${Math.floor((c.offset / c.total) * 100)} %` : '';
    const d = new Date(c.recordedAt);
    li.innerHTML = '<div class="q-ico"></div><div class="q-meta"><strong></strong><span></span></div><div class="q-state"></div>';
    li.querySelector('.q-ico').textContent = c.source === 'gallery' ? '▤' : '●';
    li.querySelector('strong').textContent = c.name;
    li.querySelector('span').textContent = `${d.toLocaleDateString('es', { day: 'numeric', month: 'short' })} · ${fmtSize(c.total || c.bytes || 0)}`;
    li.querySelector('.q-state').textContent = (STATUS[c.status] || c.status) + pct;
    if (c.status === 'uploading' && c.total) {
      const bar = document.createElement('div');
      bar.className = 'q-bar';
      bar.style.width = `${(c.offset / c.total) * 100}%`;
      li.append(bar);
    }
    if (c.status === 'failed' || c.status === 'done') {
      const x = document.createElement('button');
      x.className = 'q-x';
      x.textContent = '×';
      x.title = 'Quitar de la lista';
      x.onclick = async () => { await store.deleteClip(c.id); renderQueue(); };
      li.append(x);
    }
    list.append(li);
  }
}

// ---------- cifrado de un clip (cámara o galería) ----------
async function startClip(meta) {
  const id = newId();
  const sealer = await createSealer(b64urlToBytes(pairing.pk));
  const chunker = createChunker(sealer);
  let seq = 0;
  let total = 0;
  const save = async (rec) => { await store.putPart(id, seq++, rec); total += rec.length; };
  await save(await sealer.sealMeta(meta)); // cabecera + metadatos cifrados
  const clip = { id, name: meta.name, recordedAt: meta.recordedAt, source: meta.source, status: meta.source === 'camera' ? 'recording' : 'encrypting', bytes: 0, total: 0, offset: 0, parts: 0 };
  await store.putClip(clip);
  let chain = Promise.resolve();
  return {
    clip,
    /** Encola datos en claro (solo en memoria); se cifran y se guardan en orden. */
    push(data) {
      // se encadena también la lectura del Blob para que los trozos se cifren SIEMPRE en orden
      chain = chain.then(async () => {
        const bytes = data instanceof Blob ? new Uint8Array(await data.arrayBuffer()) : data;
        for (const r of await chunker.push(bytes)) await save(r);
        clip.bytes += bytes.length;
      });
      return chain;
    },
    async finish() {
      await chain;
      await save(await chunker.finish());
      Object.assign(clip, { status: 'queued', total, parts: seq });
      await store.putClip(clip);
      renderQueue();
      pump();
    },
  };
}

// Fecha real de grabación dentro de un MP4/MOV (caja mvhd), leída antes de cifrar
async function mp4Date(file) {
  const scan = async (start, len) => {
    const buf = new Uint8Array(await file.slice(start, start + len).arrayBuffer());
    for (let i = 0; i + 16 < buf.length; i++) {
      if (buf[i] === 0x6d && buf[i + 1] === 0x76 && buf[i + 2] === 0x68 && buf[i + 3] === 0x64) { // 'mvhd'
        const dv = new DataView(buf.buffer, buf.byteOffset + i + 4);
        const secs = dv.getUint8(0) === 1 ? Number(dv.getBigUint64(4)) : dv.getUint32(4);
        const d = new Date((secs - 2082844800) * 1000);
        return d.getFullYear() >= 2000 && d <= new Date(Date.now() + 86400000) ? d : null;
      }
    }
    return null;
  };
  const W = 8 * 1024 * 1024;
  return (await scan(0, W)) || (file.size > W ? scan(file.size - W, W) : null);
}

// ---------- galería ----------
async function addFromGallery(files) {
  for (const file of files) {
    if (!/^video\//.test(file.type) && !/\.(mp4|mov|m4v|webm)$/i.test(file.name)) { toast(`${file.name}: no es un vídeo`, true); continue; }
    const recorded = (await mp4Date(file).catch(() => null)) || new Date(file.lastModified || Date.now());
    const ext = (file.name.split('.').pop() || 'mp4').toLowerCase();
    const job = await startClip({ name: clipName(recorded, ext), recordedAt: recorded.toISOString(), source: 'gallery', mime: file.type || 'video/mp4' });
    renderQueue();
    for (let off = 0; off < file.size; off += CHUNK) {
      await job.push(new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer()));
    }
    await job.finish();
  }
  toast(files.length === 1 ? 'Vídeo cifrado y en cola' : `${files.length} vídeos cifrados y en cola`);
}

// ---------- cámara ----------
let stream = null;
let recorder = null;
let recJob = null;
let facing = 'environment';
let timerId = null;
let wakeLock = null;

async function openCamera() {
  closeCamera();
  stream = await navigator.mediaDevices.getUserMedia({
    audio: true,
    video: { facingMode: facing, width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30 } },
  });
  const v = $('#preview');
  v.srcObject = stream;
  v.classList.toggle('mirror', facing === 'user');
  await v.play().catch(() => {});
  $('#camera').classList.add('open');
}

function closeCamera() {
  if (recorder && recorder.state !== 'inactive') return;
  if (stream) stream.getTracks().forEach((t) => t.stop());
  stream = null;
  $('#camera').classList.remove('open');
}

async function toggleRecord() {
  if (recorder && recorder.state === 'recording') { recorder.stop(); return; }
  if (!stream) await openCamera();
  const types = ['video/mp4;codecs=avc1', 'video/mp4', 'video/webm;codecs=vp9', 'video/webm'];
  const mimeType = types.find((t) => window.MediaRecorder && MediaRecorder.isTypeSupported(t));
  if (!mimeType) { toast('Este navegador no puede grabar vídeo', true); return; }
  const start = new Date();
  recJob = await startClip({ name: clipName(start, mimeType.includes('mp4') ? 'mp4' : 'webm'), recordedAt: start.toISOString(), source: 'camera', mime: mimeType });
  recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 6_000_000, audioBitsPerSecond: 128_000 });
  const job = recJob;
  recorder.ondataavailable = (e) => { if (e.data && e.data.size) job.push(e.data); };
  recorder.onstop = async () => {
    clearInterval(timerId);
    $('#rec-btn').classList.remove('on');
    $('#rec-time').textContent = '';
    try { await wakeLock?.release(); } catch { /* */ }
    recJob = null;
    try { await job.finish(); toast('Clip cifrado y en cola'); } catch (err) { toast(err.message, true); }
  };
  recorder.start(1000); // trozos de 1 s: se cifran y se guardan mientras grabas
  try { wakeLock = await navigator.wakeLock?.request('screen'); } catch { wakeLock = null; }
  $('#rec-btn').classList.add('on');
  renderQueue();
  timerId = setInterval(() => {
    const s = Math.floor((Date.now() - start) / 1000);
    $('#rec-time').textContent = `${pad(Math.floor(s / 60))}:${pad(s % 60)}`;
  }, 250);
}

// ---------- envío al PC por la Wi-Fi de casa (reanudable) ----------
let pumping = false;
async function pump() {
  if (pumping || !pairing) return;
  pumping = true;
  try {
    for (;;) {
      const clips = (await store.allClips()).filter((c) => c.status === 'queued' || c.status === 'uploading' || c.status === 'waiting')
        .sort((a, b) => a.recordedAt.localeCompare(b.recordedAt));
      if (!clips.length) { if (!pc) await locatePC(); break; }
      const target = await locatePC();
      if (!target) {
        // fuera de casa / PC apagado: los clips esperan cifrados en el iPhone
        for (const c of clips) if (c.status !== 'waiting') { c.status = 'waiting'; await store.putClip(c); }
        break;
      }
      await sendClip(clips[0], target);
    }
  } catch (e) {
    pc = null;
    pcState = 'missing';
    if (e instanceof lan.NotPairedError) { toast(e.message, true); pairing.ok = false; localStorage.setItem(PAIR_KEY, JSON.stringify(pairing)); }
    else toast(`Envío en pausa: ${e.message}`, true);
  } finally {
    pumping = false;
    render();
  }
}

async function sendClip(clip, target) {
  clip.status = 'uploading';
  await store.putClip(clip);
  renderQueue();
  let lastSave = 0;
  await lan.uploadClip({
    base: target.base,
    token: pairing.tok,
    id: clip.id,
    total: clip.total,
    parts: clip.parts,
    getPart: (seq) => store.getPart(clip.id, seq),
    onProgress: async (n) => {
      clip.offset = n;
      if (Date.now() - lastSave > 500) { lastSave = Date.now(); await store.putClip(clip); renderQueue(); }
    },
  });
  await store.deleteParts(clip.id); // ya está en el PC: en el iPhone no queda nada del vídeo
  Object.assign(clip, { status: 'done', offset: clip.total, doneAt: new Date().toISOString() });
  await store.putClip(clip);
}

// Al arrancar: los clips que quedaron a medias de grabar no se pueden cerrar con seguridad
async function recoverInterrupted() {
  for (const c of await store.allClips()) {
    if (c.status === 'recording' || c.status === 'encrypting') { await store.deleteParts(c.id); c.status = 'failed'; await store.putClip(c); }
  }
}

// ---------- inicio ----------
async function init() {
  readHash();
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(() => {});
  try { await navigator.storage?.persist?.(); } catch { /* */ }
  await recoverInterrupted();

  document.querySelectorAll('[data-scan]').forEach((b) => { b.onclick = () => startScan(); });
  $('#scan-close').onclick = stopScan;
  $('#check-pc').onclick = async () => { pc = null; const found = await locatePC(); if (!found) toast('Todavía no encuentro tu PC: revisa los pasos', true); else pump(); };
  $('#pc-chip').onclick = () => { pc = null; pump(); };
  $('#rec-btn').onclick = () => toggleRecord().catch((e) => toast(e.name === 'NotAllowedError' ? 'Permite el acceso a la cámara y al micrófono' : e.message, true));
  $('#open-cam').onclick = () => openCamera().catch((e) => toast(e.name === 'NotAllowedError' ? 'Permite el acceso a la cámara y al micrófono' : e.message, true));
  $('#close-cam').onclick = closeCamera;
  $('#flip').onclick = async () => { if (recorder && recorder.state === 'recording') return; facing = facing === 'user' ? 'environment' : 'user'; await openCamera().catch(() => {}); };
  $('#gallery').onchange = async (e) => {
    const files = [...e.target.files];
    e.target.value = '';
    try { await addFromGallery(files); } catch (err) { toast(err.message, true); renderQueue(); }
  };
  $('#unpair').onclick = () => {
    if (!confirm('¿Desvincular este iPhone de tu bóveda? Los clips que aún no se hayan enviado se perderán.')) return;
    localStorage.removeItem(PAIR_KEY);
    pairing = null;
    pc = null;
    render();
  };
  window.addEventListener('online', () => { pc = null; pump(); });
  // si la app ya estaba abierta y se abre el enlace de vinculación, solo cambia el # (no recarga)
  window.addEventListener('hashchange', () => { readHash(); render(); pump(); });
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') { pc = null; render(); pump(); } });
  // mientras la app está abierta, reintentar cada 30 s (p. ej. al llegar a casa)
  setInterval(() => { if (document.visibilityState === 'visible' && !pumping) { if (pcState !== 'found') pc = null; pump(); } }, 30000);
  render();
  pump();
}

init();
