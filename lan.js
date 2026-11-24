// Envío de clips (ya cifrados) al PC por la Wi-Fi de casa. Sin nube: iPhone -> PC directamente.
export const PORT = 47830;
export const PIECE = 8 * 1024 * 1024;

export class NotPairedError extends Error {}

const withTimeout = (ms) => {
  const c = new AbortController();
  setTimeout(() => c.abort(), ms);
  return c.signal;
};

/** Busca el PC probando a la vez su nombre .local y sus IP. Devuelve { base, name } o null. */
export async function findPC(pairing, timeoutMs = 4000) {
  const tries = (pairing.hosts || []).map(async (host) => {
    const base = `https://${host}:${pairing.port || PORT}`;
    const res = await fetch(`${base}/v1/ping`, { headers: { Authorization: `Bearer ${pairing.tok}` }, signal: withTimeout(timeoutMs), cache: 'no-store' });
    const j = await res.json();
    if (j.app !== 'crypted-vault') throw new Error('no es el PC');
    return { base, name: j.name, paired: j.paired };
  });
  try {
    const pc = await Promise.any(tries);
    if (!pc.paired) throw new NotPairedError('Este iPhone ya no está vinculado con el PC: escanea de nuevo el QR');
    return pc;
  } catch (e) {
    if (e instanceof NotPairedError) throw e;
    return null; // no está en la misma red, apagado, o el certificado aún no está instalado
  }
}

async function call(base, token, id, opts = {}) {
  const res = await fetch(`${base}/v1/clips/${id}`, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${token}` }, cache: 'no-store' });
  if (res.status === 401) throw new NotPairedError('El PC no reconoce este iPhone: escanea de nuevo el QR');
  const j = await res.json().catch(() => ({}));
  return { status: res.status, ...j };
}

/**
 * Sube un clip reanudando desde donde se quedó.
 * getPart(seq) devuelve cada registro cifrado guardado en el iPhone, en orden.
 */
export async function uploadClip({ base, token, id, total, parts, getPart, onProgress = () => {} }) {
  let st = await call(base, token, id);
  if (st.complete) return true;
  let sentTo = st.received || 0;
  onProgress(sentTo);

  let pos = 0;
  let buf = [];
  let bufLen = 0;
  const send = async (final) => {
    while (bufLen >= PIECE || (final && bufLen > 0)) {
      const n = Math.min(bufLen, PIECE);
      const piece = new Uint8Array(n);
      let o = 0;
      while (o < n) {
        const p = buf[0];
        const k = Math.min(p.length, n - o);
        piece.set(p.subarray(0, k), o);
        o += k;
        if (k === p.length) buf.shift(); else buf[0] = p.subarray(k);
      }
      bufLen -= n;
      const r = await call(base, token, id, {
        method: 'PUT',
        headers: { 'Content-Range': `bytes ${sentTo}-${sentTo + n - 1}/${total}`, 'Content-Type': 'application/octet-stream' },
        body: piece,
      });
      if (r.status === 409) throw new Error('El PC tenía otra posición: se reintentará');
      if (r.status !== 200) throw new Error(r.error || `Error del PC (${r.status})`);
      sentTo += n;
      onProgress(sentTo);
      if (r.complete) return true;
    }
    return false;
  };

  for (let seq = 0; seq < parts; seq++) {
    let rec = await getPart(seq);
    if (!rec) throw new Error('Faltan datos del clip en el iPhone');
    rec = new Uint8Array(rec);
    const recStart = pos;
    pos += rec.length;
    if (pos <= sentTo) continue;                                  // ya está en el PC
    if (recStart < sentTo) rec = rec.subarray(sentTo - recStart); // a medias: seguir desde ahí
    buf.push(rec);
    bufLen += rec.length;
    if (await send(false)) return true;
  }
  if (await send(true)) return true;
  throw new Error('El PC no confirmó el clip completo');
}
