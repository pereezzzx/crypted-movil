// Cola local en IndexedDB. Solo contiene datos YA CIFRADOS (el iPhone no puede descifrarlos).
const DB_NAME = 'crypted-movil';
let dbp = null;

function db() {
  if (!dbp) {
    dbp = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const d = req.result;
        d.createObjectStore('clips', { keyPath: 'id' });
        d.createObjectStore('parts', { keyPath: ['clip', 'seq'] });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  return dbp;
}

async function tx(stores, mode, fn) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction(stores, mode);
    let out;
    Promise.resolve(fn(t)).then((v) => { out = v; }, reject);
    t.oncomplete = () => resolve(out);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('Transacción abortada'));
  });
}
const wrap = (req) => new Promise((resolve, reject) => { req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error); });

export const putClip = (clip) => tx(['clips'], 'readwrite', (t) => wrap(t.objectStore('clips').put(clip)));
export const getClip = (id) => tx(['clips'], 'readonly', (t) => wrap(t.objectStore('clips').get(id)));
export const allClips = () => tx(['clips'], 'readonly', (t) => wrap(t.objectStore('clips').getAll()));
export const putPart = (clip, seq, data) => tx(['parts'], 'readwrite', (t) => wrap(t.objectStore('parts').put({ clip, seq, data })));
export const getPart = (clip, seq) => tx(['parts'], 'readonly', (t) => wrap(t.objectStore('parts').get([clip, seq]))).then((r) => r && r.data);

export async function deleteParts(clip) {
  await tx(['parts'], 'readwrite', (t) => wrap(t.objectStore('parts').delete(IDBKeyRange.bound([clip, 0], [clip, Infinity]))));
}
export async function deleteClip(id) {
  await deleteParts(id);
  await tx(['clips'], 'readwrite', (t) => wrap(t.objectStore('clips').delete(id)));
}
