// Google Drive desde el iPhone: inicio de sesión por redirección (sin contraseñas en la app)
// y subida reanudable a la carpeta privada de la app (appDataFolder). Solo se suben datos cifrados.
const SCOPE = 'https://www.googleapis.com/auth/drive.appdata';
const TOKEN_KEY = 'cv.token';
const STATE_KEY = 'cv.oauthState';
export const PIECE = 8 * 1024 * 1024; // múltiplo de 256 KB, como exige Google

export const redirectUri = () => location.origin + location.pathname;

export function signIn(clientId, { consent = false } = {}) {
  const state = crypto.getRandomValues(new Uint32Array(4)).join('-');
  localStorage.setItem(STATE_KEY, state);
  const p = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri(),
    response_type: 'token',
    scope: SCOPE,
    include_granted_scopes: 'true',
    state,
    ...(consent ? { prompt: 'consent' } : {}),
  });
  location.assign(`https://accounts.google.com/o/oauth2/v2/auth?${p}`);
}

/** Recoge el token que Google devuelve en el fragmento # tras iniciar sesión. */
export function takeTokenFromUrl(params) {
  if (!params.get('access_token') && !params.get('error')) return null;
  const expected = localStorage.getItem(STATE_KEY);
  localStorage.removeItem(STATE_KEY);
  if (params.get('error')) return { error: params.get('error') };
  if (!expected || params.get('state') !== expected) return { error: 'state' };
  const tok = { access: params.get('access_token'), expires: Date.now() + (Number(params.get('expires_in')) || 3600) * 1000 };
  localStorage.setItem(TOKEN_KEY, JSON.stringify(tok));
  return tok;
}

export function currentToken() {
  try {
    const t = JSON.parse(localStorage.getItem(TOKEN_KEY) || 'null');
    return t && Date.now() < t.expires - 60000 ? t.access : null;
  } catch { return null; }
}
export function signOut() { localStorage.removeItem(TOKEN_KEY); }

export class AuthError extends Error {}

/** Crea una sesión de subida reanudable y devuelve su URL. */
export async function createSession(token, name, total) {
  const res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json; charset=UTF-8',
      'X-Upload-Content-Type': 'application/octet-stream',
      'X-Upload-Content-Length': String(total),
    },
    body: JSON.stringify({ name, parents: ['appDataFolder'] }),
  });
  if (res.status === 401) throw new AuthError('Sesión de Google caducada');
  if (!res.ok) throw new Error(`Google Drive ${res.status}`);
  const loc = res.headers.get('Location');
  if (!loc) throw new Error('Google no devolvió la sesión de subida');
  return loc;
}

/** Cuántos bytes tiene ya Google de esta subida (para reanudar). -1 si ya está completa. */
export async function queryOffset(session, total) {
  const res = await fetch(session, { method: 'PUT', headers: { 'Content-Range': `bytes */${total}` } });
  if (res.status === 200 || res.status === 201) return -1;
  if (res.status === 308) {
    const r = res.headers.get('Range');
    return r ? Number(r.split('-')[1]) + 1 : 0;
  }
  if (res.status === 404 || res.status === 410) return null; // sesión caducada: hay que empezar otra
  throw new Error(`Google Drive ${res.status}`);
}

/** Sube un trozo [start, start+len) de un total. Devuelve true si la subida terminó. */
export async function putPiece(session, bytes, start, total) {
  const end = start + bytes.length - 1;
  const res = await fetch(session, { method: 'PUT', headers: { 'Content-Range': `bytes ${start}-${end}/${total}` }, body: bytes });
  if (res.status === 200 || res.status === 201) return true;
  if (res.status === 308) return false;
  if (res.status === 404 || res.status === 410) { const e = new Error('Sesión de subida caducada'); e.expired = true; throw e; }
  throw new Error(`Google Drive ${res.status}`);
}
