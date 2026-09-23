/* 站点访问门 · Service Worker
 * 站内除公开外壳外的所有文件都以 AES-256-GCM 密文存放。
 * 本 Service Worker 用 IndexedDB 里的内容密钥 K（访问门页面输对密码后写入）
 * 在浏览器本地解密，再以原始路径、正确的 Content-Type 交给页面。
 * 没有 K：页面跳转 → 访问门；资源请求 → 401。
 */
'use strict';

const GATE = {"build":"20260923T132535-1e3205","keyId":"385f4799e78eb12a","publicPaths":["/.nojekyll","/favicon.svg","/logo-student.png","/logo.png","/robots.txt","/sw.js"],"publicPrefixes":["/_gate/"]};

const DB_NAME = 'site-gate';
const STORE = 'kv';
const KEY_REC = 'key';
const MAGIC = [0x53, 0x47, 0x54, 0x02]; // "SGT" + 格式版本 2（认证数据绑定发布路径）
const HEAD_LEN = 4 + 8 + 12;            // 魔数+版本 | keyId(8) | IV(12)
const LOCKED = '/_locked';
const GATE_PAGE = '/_gate/index.html';

const TYPES = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8',
  js: 'application/javascript; charset=utf-8', mjs: 'application/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8', json: 'application/json; charset=utf-8', map: 'application/json; charset=utf-8',
  // GitHub Pages 把 .rsc 当作 application/octet-stream；保持一致（前端遇到非 text/x-component 会整页跳转，与原站行为相同）
  rsc: 'application/octet-stream',
  txt: 'text/plain; charset=utf-8', md: 'text/markdown; charset=utf-8', xml: 'application/xml',
  svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', avif: 'image/avif', ico: 'image/x-icon',
  wasm: 'application/wasm', glb: 'model/gltf-binary', gltf: 'model/gltf+json', bin: 'application/octet-stream',
  woff2: 'font/woff2', woff: 'font/woff', ttf: 'font/ttf', otf: 'font/otf',
  mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', mp4: 'video/mp4', webm: 'video/webm',
  pdf: 'application/pdf', csv: 'text/csv; charset=utf-8',
};

// ---------------- IndexedDB ----------------
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB_NAME, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function idbTx(mode, fn) {
  const db = await idb();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, mode);
    const req = fn(tx.objectStore(STORE));
    let out;
    if (req) req.onsuccess = () => { out = req.result; };
    tx.oncomplete = () => { db.close(); res(out); };
    tx.onerror = tx.onabort = () => { db.close(); rej(tx.error); };
  });
}
const idbGet = (k) => idbTx('readonly', (s) => s.get(k));
const idbDel = (k) => idbTx('readwrite', (s) => s.delete(k));

// ---------------- 密钥 ----------------
let keyState = null;   // { keyId, key(CryptoKey), exp }
let keyLoading = null;

async function getKey() {
  if (keyState && keyState.exp > Date.now()) return keyState;
  keyState = null;
  if (!keyLoading) {
    keyLoading = (async () => {
      try {
        const rec = await idbGet(KEY_REC);
        if (rec && rec.key && rec.exp > Date.now()) { keyState = rec; return rec; }
        if (rec) await idbDel(KEY_REC); // 过期
        return null;
      } catch (e) {
        return null;
      } finally {
        keyLoading = null;
      }
    })();
  }
  return keyLoading;
}
async function clearKey() {
  keyState = null;
  try { await idbDel(KEY_REC); } catch (e) {}
}

// 目前线上部署用的 keyId（不走缓存）；拿不到就退回本 sw.js 内置的
async function deployedKeyId() {
  try {
    const r = await fetch('/_gate/config.json', { cache: 'no-store' });
    if (r.ok) { const c = await r.json(); if (c && c.keyId) return c.keyId; }
  } catch (e) {}
  return GATE.keyId;
}

// ---------------- 生命周期 ----------------
self.addEventListener('install', (e) => { e.waitUntil(self.skipWaiting()); });

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    // 新版本上线且换了内容密钥：旧密钥作废，下次打开会看到访问门
    try {
      const rec = await idbGet(KEY_REC);
      if (rec && (rec.keyId !== GATE.keyId || !(rec.exp > Date.now()))) await idbDel(KEY_REC);
    } catch (e) {}
    keyState = null;
    await self.clients.claim();
  })());
});

self.addEventListener('message', (e) => {
  const type = e.data && e.data.type;
  const reply = (v) => { if (e.ports && e.ports[0]) e.ports[0].postMessage(v); };
  if (type === 'refresh') {
    keyState = null;
    e.waitUntil(getKey().then((k) => reply({ ok: !!k, keyId: k ? k.keyId : null, build: GATE.build })));
  } else if (type === 'lock') {
    e.waitUntil(clearKey().then(() => reply({ ok: true })));
  } else if (type === 'ping') {
    reply({ build: GATE.build, keyId: GATE.keyId });
  }
});

// ---------------- 请求处理 ----------------
function isPublic(pathname) {
  if (GATE.publicPaths.indexOf(pathname) >= 0) return true;
  for (const p of GATE.publicPrefixes) if (pathname.indexOf(p) === 0) return true;
  return false;
}

function extOf(pathname) {
  const last = pathname.slice(pathname.lastIndexOf('/') + 1);
  const i = last.lastIndexOf('.');
  return i > 0 ? last.slice(i + 1).toLowerCase() : '';
}

// 页面路由 → 加密后的 HTML 文件（与 GitHub Pages 的解析规则一致）
function lockedDocFor(pathname) {
  if (pathname.endsWith('/')) return LOCKED + pathname + 'index.html';
  if (pathname.endsWith('.html') || pathname.endsWith('.htm')) return LOCKED + pathname;
  return LOCKED + pathname + '.html';
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // 跨域（AI 后端等）不碰
  if (isPublic(url.pathname)) return;               // 公开外壳直接走网络
  e.respondWith(handle(req, url).catch((err) => {
    return new Response('gate error', { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }));
});

function gatePage() {
  return fetch(GATE_PAGE, { cache: 'no-cache' });
}
function locked401() {
  return new Response('locked', { status: 401, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
}

async function handle(req, url) {
  const nav = req.mode === 'navigate';
  if (nav && url.searchParams.has('lock')) {
    await clearKey();
    return gatePage();
  }
  const k = await getKey();
  if (!k) return nav ? gatePage() : locked401();

  const ext = extOf(url.pathname);
  const isDoc = ext === '' || ext === 'html' || ext === 'htm';

  let out;
  if (isDoc) {
    // HTML 永远重新验证（304 很便宜），这样新版本上线后能马上发现密钥已换
    out = await serveFile(k, lockedDocFor(url.pathname), '', 'html', 'no-cache');
    if (out.status === 404 && ext === '' && !url.pathname.endsWith('/')) {
      // 没有扩展名的普通文件（极少见）
      const alt = await serveFile(k, url.pathname, url.search, '', cacheMode(req));
      if (alt.status !== 404) out = alt;
    }
  } else {
    out = await serveFile(k, url.pathname, url.search, ext, cacheMode(req));
  }

  if (out.stale) {
    // 密钥已被新部署替换：清掉本地密钥，回到访问门
    await clearKey();
    return nav ? gatePage() : locked401();
  }
  if (out.status === 404) return notFound(k);
  return out.response;
}

function cacheMode(req) {
  const c = req.cache;
  return c === 'only-if-cached' ? 'default' : (c || 'default');
}

async function notFound(k) {
  const r = await serveFile(k, LOCKED + '/404.html', '', 'html', 'no-cache');
  if (r.response && r.status === 200) {
    return new Response(r.response.body, { status: 404, statusText: 'Not Found', headers: r.response.headers });
  }
  return new Response('Not Found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}

function sameId(buf, keyIdBytes) {
  for (let i = 0; i < 8; i++) if (buf[4 + i] !== keyIdBytes[i]) return false;
  return true;
}
function isBox(buf) {
  if (buf.length < HEAD_LEN + 16) return false;
  for (let i = 0; i < 4; i++) if (buf[i] !== MAGIC[i]) return false;
  return true;
}
function hexToBytes(h) {
  const u = new Uint8Array(h.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16);
  return u;
}

function textResponse(status, text, extra) {
  return new Response(text, { status, headers: Object.assign({ 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {}) });
}
// 受保护路径上拿到的不是密文：绝不原样转交（防止把别处的内容当成本站页面）
const notBox = () => ({ status: 502, response: textResponse(502, 'not an encrypted file') });

// 把路径固定在本站：'//evil.example/x' 这类路径若直接交给 fetch() 会被当成“省略协议的网址”跳到别的站点
function sameOriginUrl(pathname, search) {
  const u = new URL(self.location.origin);
  u.pathname = pathname;
  u.search = search || '';
  return u.origin === self.location.origin ? u : null;
}
function aadFor(buf, pathname) {
  let p = pathname;
  try { p = decodeURIComponent(pathname); } catch (e) {}
  const pb = new TextEncoder().encode(p);
  const a = new Uint8Array(12 + pb.length);
  a.set(buf.subarray(0, 12), 0);
  a.set(pb, 12);
  return a;
}

// 取回密文并解密。返回 { status, response } 或 { stale: true }
async function serveFile(k, pathname, search, ext, cache) {
  const kid = hexToBytes(k.keyId);
  const u = sameOriginUrl(pathname, search);
  if (!u) return { status: 404 };
  const opts = { cache, credentials: 'same-origin', redirect: 'follow', mode: 'same-origin' };
  let res;
  try { res = await fetch(u.href, opts); } catch (e) { return { status: 502, response: textResponse(502, 'fetch failed') }; }
  if (res.status === 404) return { status: 404 };
  if (!res.ok) return { status: res.status, response: textResponse(res.status, 'upstream ' + res.status) };
  let buf = new Uint8Array(await res.arrayBuffer());
  if (!isBox(buf)) return notBox();
  if (!sameId(buf, kid)) {
    // 可能是浏览器缓存里的旧文件：绕过缓存再取一次
    try { res = await fetch(u.href, Object.assign({}, opts, { cache: 'reload' })); } catch (e) { return { status: 502, response: textResponse(502, 'fetch failed') }; }
    if (res.status === 404) return { status: 404 };
    buf = new Uint8Array(await res.arrayBuffer());
    if (!isBox(buf)) return notBox();
    if (!sameId(buf, kid)) {
      // 还是不一致：看线上配置——如果线上用的正是我们手里的密钥，说明是 CDN 上的旧文件，暂不清钥
      const live = await deployedKeyId();
      if (live !== k.keyId) return { stale: true };
      return { status: 503, response: new Response('stale file', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '30' } }) };
    }
  }
  const iv = buf.subarray(12, HEAD_LEN);
  const aad = aadFor(buf, u.pathname);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, k.key, buf.subarray(HEAD_LEN));
  } catch (e) {
    return { status: 500, response: textResponse(500, 'decrypt failed') };
  }
  const t = ext === '' ? 'application/octet-stream' : (TYPES[ext] || 'application/octet-stream');
  const headers = new Headers({ 'Content-Type': t, 'Content-Length': String(plain.byteLength), 'X-Site-Gate': '1' });
  const lm = res.headers.get('Last-Modified');
  if (lm) headers.set('Last-Modified', lm);
  return { status: 200, response: new Response(plain, { status: 200, statusText: 'OK', headers }) };
}
