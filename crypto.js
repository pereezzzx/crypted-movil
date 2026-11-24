/**
 * Formato del buzón cifrado (.cvi): el móvil cifra para la bóveda con su LLAVE PÚBLICA.
 * El móvil puede meter clips, pero nunca descifrarlos (no tiene la llave privada).
 *
 *   "CVI1" | pubEfímera(65, P-256 sin comprimir) | sal(16) | tamBloque(u32 LE) | lenMeta(u32 LE)
 *   meta   = IV(12) | AES-GCM(JSON) || TAG(16)             AAD "meta"
 *   bloque = IV(12) | AES-GCM(datos) || TAG(16)            AAD "chunk:<i>:<1 si es el último>"
 *
 * Clave por clip: ECDH(P-256, efímera × pública de la bóveda) -> HKDF-SHA256(sal, "CryptedVault inbox v1") -> AES-256.
 * Funciona en el navegador (iPhone) y en Node (pruebas) con WebCrypto.
 */
export const MAGIC = 'CVI1';
export const CHUNK = 4 * 1024 * 1024;
export const HEADER_LEN = 4 + 65 + 16 + 4 + 4;
const INFO = new TextEncoder().encode('CryptedVault inbox v1');
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

export function b64urlToBytes(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
export function bytesToB64url(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Crea un sellador para un clip nuevo.
 * Devuelve { header, sealMeta(obj), sealChunk(bytes, index, isLast) } — todo en Uint8Array.
 */
export async function createSealer(vaultPublicRaw) {
  const vaultPub = await subtle.importKey('raw', vaultPublicRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ephRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const shared = await subtle.deriveBits({ name: 'ECDH', public: vaultPub }, eph.privateKey, 256);
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const hk = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: INFO }, hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);

  const seal = async (data, aad) => {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad), tagLength: 128 }, key, data));
    const out = new Uint8Array(12 + ct.length);
    out.set(iv, 0);
    out.set(ct, 12);
    return out;
  };

  return {
    async sealMeta(meta) {
      const m = await seal(enc.encode(JSON.stringify(meta)), 'meta');
      const header = new Uint8Array(HEADER_LEN);
      header.set(enc.encode(MAGIC), 0);
      header.set(ephRaw, 4);
      header.set(salt, 69);
      const dv = new DataView(header.buffer);
      dv.setUint32(85, CHUNK, true);
      dv.setUint32(89, m.length, true);
      const out = new Uint8Array(header.length + m.length);
      out.set(header, 0);
      out.set(m, header.length);
      return out; // cabecera + metadatos cifrados
    },
    sealChunk(bytes, index, isLast) {
      if (!isLast && bytes.length !== CHUNK) throw new Error('Bloque intermedio con tamaño incorrecto');
      return seal(bytes, `chunk:${index}:${isLast ? 1 : 0}`);
    },
  };
}

/**
 * Trocea un flujo de bytes en bloques exactos de CHUNK y los cifra a medida que llegan.
 * push(bytes) -> Promise<Uint8Array[]> (registros cifrados listos); finish() -> último registro.
 */
export function createChunker(sealer) {
  let parts = [];
  let len = 0;
  let index = 0;
  const take = (n) => {
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const p = parts[0];
      const k = Math.min(p.length, n - off);
      out.set(p.subarray(0, k), off);
      off += k;
      if (k === p.length) parts.shift(); else parts[0] = p.subarray(k);
    }
    len -= n;
    return out;
  };
  return {
    async push(bytes) {
      parts.push(bytes);
      len += bytes.length;
      const ready = [];
      // siempre queda al menos 1 byte para el bloque final (marcado como último)
      while (len > CHUNK) ready.push(await sealer.sealChunk(take(CHUNK), index++, false));
      return ready;
    },
    async finish() {
      const rest = take(len);
      parts = [];
      return sealer.sealChunk(rest, index++, true);
    },
  };
}
