import express from 'express';
import httpProxy from 'http-proxy';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/* ------------------------------------------------------------------ *
 * 配置
 * ------------------------------------------------------------------ */
const PORT = parseInt(process.env.PORT || '8080', 10);
const TOKEN = process.env.TOKEN || 'changeme';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const INJECT_EXIT = process.env.INJECT_EXIT_BUTTON !== 'false';
// 退出代理时是否「重置目标登录态」：
// 透明代理下浏览器认为所有内容都来自网关这个源，被代理页面自己下发的登录
// Cookie / localStorage 也记在网关域下。若不清，下次代理同一服务会带着旧
// 登录态 → 跳过目标自己的登录页。开启后：退出时按台账逐个过期这些 Cookie
// （含 HttpOnly），并清空该源的 localStorage/sessionStorage/IndexedDB。
const CLEAR_TARGET_ON_EXIT = process.env.CLEAR_TARGET_COOKIES_ON_EXIT !== 'false';
// 出站请求是否清洗「网关来源」头（默认开）。403 排查时可设为 false 做 A/B 对比。
const STRIP_CLIENT_HEADERS = process.env.STRIP_CLIENT_HEADERS !== 'false';
// 打印每个代理请求的上游状态，便于定位 4xx/5xx 来自哪一层
const PROXY_LOG = process.env.PROXY_LOG === 'true';
const SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 小时无操作过期
const COOKIE_NAME = '_gate_sid';
const BASE = '/_gate';
// 判断请求是否为静态资源（用于还原浏览器原生的请求头：静态请求不带 Origin、必带 Sec-Fetch-*）
const STATIC_RE = /\.(?:js|mjs|cjs|css|map|ico|png|jpe?g|gif|svg|webp|bmp|woff2?|ttf|eot|otf|json|txt|wasm)(?:[?#]|$)/i;

/* ---- Token 防爆破 ----
 * 防爆破策略（简单、诚实、可审计）：
 *   错误 token → **显式 401**，并按 IP 计数失败；连续失败达阈值后**指数退避**
 *   （返回 429 + `Retry-After`），把爆破速率压到不可行。
 *   正确 token → 复位计数。
 *   token 用**恒定时间比较**，避免时序侧信道。
 *
 * 说明（重要）：这里**不再使用「诱饵」**。早期版本让错误 token 也返回与成功
 * 完全一致的响应，试图让爆破「无法收敛」。但该机制有一个**无法修补**的缺陷：
 * 一旦登录成功，诱饵会话必须让它「看起来像能正常代理」，否则（恒 502 / 恒跳转）
 * 攻击者只需「代理一个自己控制的可达地址 + 看状态码」即可 100% 判定 token 真假；
 * 而真要做到「看起来一样」，就只能让它**真的代理** —— 那等于给了错 token 一个
 * 可用的开放代理（旁路），比预言机本身更危险。
 * 因此改为显式 401 + 退避：不隐藏、不误导，安全性来自 **Token 熵值** 本身。
 */
const AUTH_MAX_FAILS = parseInt(process.env.AUTH_MAX_FAILS || '5', 10);
const AUTH_LOCK_BASE_MS = parseInt(process.env.AUTH_LOCK_BASE_MS || '1000', 10);
const AUTH_FAIL_WINDOW_MS = parseInt(process.env.AUTH_FAIL_WINDOW_MS || String(15 * 60 * 1000), 10);
// 计数：ip -> { fails, firstAt, lockedUntil }
const authFails = new Map();
function clientIp(req) {
  // 网关前面可能有 CDN（EdgeOne）。仅在显式信任时才采信 X-Forwarded-For，
  // 否则伪造该头即可绕过限速。设 TRUST_PROXY=true 时取最左侧地址。
  if (process.env.TRUST_PROXY === 'true') {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (xff) return xff;
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}
function authRec(ip) {
  const now = Date.now();
  let rec = authFails.get(ip);
  if (!rec || now - rec.firstAt > AUTH_FAIL_WINDOW_MS) rec = { fails: 0, firstAt: now, lockedUntil: 0 };
  return rec;
}
function authLockRemaining(req) {
  const rec = authFails.get(clientIp(req));
  if (!rec) return 0;
  const left = rec.lockedUntil - Date.now();
  return left > 0 ? left : 0;
}
function authNoteFail(req) {
  const ip = clientIp(req);
  const rec = authRec(ip);
  rec.fails++;
  if (rec.fails >= AUTH_MAX_FAILS) {
    // 指数退避（第 N 次超出阈值 → base * 2^(超出次数)，上限 5 分钟）
    const over = rec.fails - AUTH_MAX_FAILS;
    rec.lockedUntil = Date.now() + Math.min(AUTH_LOCK_BASE_MS * Math.pow(2, over), 5 * 60 * 1000);
  }
  authFails.set(ip, rec);
}
function authNoteSuccess(req) { authFails.delete(clientIp(req)); }
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of authFails) {
    if (now - rec.firstAt > AUTH_FAIL_WINDOW_MS && now > rec.lockedUntil) authFails.delete(ip);
  }
}, 60 * 1000).unref?.();

// 是否启用安全响应头（可关，便于 A/B 排查被代理站点异常）
const SECURITY_HEADERS = process.env.SECURITY_HEADERS !== 'false';
// HSTS 仅在有把握全程 HTTPS 时生效（默认开）。内网 HTTP 直连访问不受影响 —— HSTS 只由浏览器在 HTTPS 响应后记录。
const HSTS_MAX_AGE = parseInt(process.env.HSTS_MAX_AGE || '15552000', 10); // 180 天
// 构建标识：优先用环境变量（CI 可注入 commit sha），否则用「自身代码内容」的哈希。
// 用内容哈希的好处：同一次发布内保持不变（不影响浏览器缓存），
// 一旦代码更新就自动变化 → 参与静态资源缓存破坏参数，
// 升级镜像后旧的（可能已损坏的）缓存响应会立即失效。
const BUILD_ID = (() => {
  const fromEnv = String(process.env.BUILD_ID || process.env.GIT_SHA || process.env.VERSION || '').trim();
  if (fromEnv) return fromEnv.slice(0, 16);
  try {
    const self = fs.readFileSync(fileURLToPath(import.meta.url));
    return crypto.createHash('sha256').update(self).digest('hex').slice(0, 10);
  } catch {
    return 'dev';
  }
})();

// 所有网关响应（含代理透传）一律禁止「共享缓存」。
// 真实案例：EdgeOne 按 URL 缓存了网关的「未登录 404」，且缓存键不含 Cookie，
// 于是带会话的浏览器请求 /static/js/*.js 也命中缓存的 404 → 页面空白；
// 同一会话切换目标时还会命中上一个目标的资源（串味）。
// 默认 private + no-store 最强；如需放宽可用 CACHE_CONTROL 覆盖，
// 例如 private, max-age=600（仍禁止 CDN 共享缓存，允许浏览器本地缓存）。
const CACHE_CONTROL = process.env.CACHE_CONTROL || 'private, no-store, max-age=0, must-revalidate';

// 缓存破坏：给被代理 HTML 里的站内资源 URL 追加会话级参数。
/* ------------------------------------------------------------------ *
 * 透明代理模式（nginx 风格）—— 唯一工作模式
 *
 * 与「内容改写式代理」的根本区别：**完全不碰响应体**。
 * 不重写 origin、不改写资源地址、不去 base。只做三件事：
 *   · 把请求原样转给目标（换 Host）；
 *   · 把上游 Set-Cookie 原样回传（不改名/去 Domain/改 Path）；
 *   · 透传状态码与响应头。
 *
 * 为什么这样更不容易白屏：改写 HTML/JS 是「侵入式」的，现代前端
 * （Vite 的动态 import、__vite__mapDeps、内联 worker、根绝对路径资源）
 * 一旦被改错一处就会整页崩。透明转发让目标服务始终认为自己在根路径，
 * 前端拿到的是**一字未改**的原始代码，因此不存在「漏改」。
 *
 * 登录地址里若带子路径（如 192.168.1.10:8080/lucky/），会作为 base 在
 * 出站请求时补上 —— 这属于透明代理自身能力，不需要任何内容改写。
 *
 * HTTPS 说明：网关对外是什么协议就是什么协议，转发时与目标之间按目标
 * 自身的 scheme 建立连接（网关 → 目标 走 http 或 https 均可，可跨协议），
 * 因此不存在「http 页面请求 https 资源」的混合内容问题；目标若用自签
 * 证书，已内置 secure:false 忽略校验。
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ *
 * 数据层（SQLite，零原生依赖）
 * ------------------------------------------------------------------ */
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'gateway.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS sites (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    note         TEXT    NOT NULL DEFAULT '',
    protocol     TEXT    NOT NULL DEFAULT 'http',
    host         TEXT    NOT NULL,
    port         INTEGER,
    base         TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    UNIQUE(protocol, host, port, base)
  );
`);

// 兼容旧库：老版本没有 note / base 列，且唯一键不含 base，平滑升级
{
  const cols = db.prepare('PRAGMA table_info(sites)').all().map((c) => c.name);
  const idx = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='sites'").get();
  const ddl = idx ? String(db.prepare("SELECT sql FROM sqlite_master WHERE name='sites'").get()?.sql || '') : '';
  if (!cols.includes('note') || !cols.includes('base') || !/UNIQUE\s*\(\s*protocol\s*,\s*host\s*,\s*port\s*,\s*base\s*\)/i.test(ddl)) {
    const noteExpr = cols.includes('note') ? 'note' : "''";
    const baseExpr = cols.includes('base') ? 'base' : "''";
    db.exec(`
      ALTER TABLE sites RENAME TO sites_old;
      CREATE TABLE sites (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT    NOT NULL,
        note         TEXT    NOT NULL DEFAULT '',
        protocol     TEXT    NOT NULL DEFAULT 'http',
        host         TEXT    NOT NULL,
        port         INTEGER,
        base         TEXT    NOT NULL DEFAULT '',
        created_at   INTEGER NOT NULL,
        last_used_at INTEGER,
        UNIQUE(protocol, host, port, base)
      );
      INSERT INTO sites (id, name, note, protocol, host, port, base, created_at, last_used_at)
        SELECT id, name, ${noteExpr}, protocol, host, port, ${baseExpr}, created_at, last_used_at FROM sites_old;
      DROP TABLE sites_old;
    `);
  }
}

const stmt = {
  list: db.prepare('SELECT * FROM sites ORDER BY last_used_at DESC, id DESC'),
  get: db.prepare('SELECT * FROM sites WHERE id = ?'),
  upsert: db.prepare(`
    INSERT INTO sites (name, note, protocol, host, port, base, created_at, last_used_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(protocol, host, port, base)
    DO UPDATE SET name = excluded.name, note = excluded.note, last_used_at = excluded.last_used_at
  `),
  touch: db.prepare('UPDATE sites SET last_used_at = ? WHERE id = ?'),
  update: db.prepare('UPDATE sites SET name = ?, note = ?, base = ? WHERE id = ?'),
  del: db.prepare('DELETE FROM sites WHERE id = ?'),
  find: db.prepare('SELECT * FROM sites WHERE protocol = ? AND host = ? AND port = ? AND base = ?'),
};

/* ------------------------------------------------------------------ *
 * 会话层（内存）
 * ------------------------------------------------------------------ */
const sessions = new Map(); // sid -> { authed, target, createdAt, lastSeen }

/* ---- 会话数量上限（防内存 DoS）----
 * 每次无 Cookie 的 POST /auth 都会新建会话；若不设上限，攻击者可无成本刷爆
 * sessions Map（清理任务 60s 一轮、TTL 12h，回收不及）。
 * 策略：超过软上限时**立即淘汰**最久未活跃的会话，且**优先淘汰未认证**的
 * （未完成登录的会话最没有保留价值）。已登录会话尽量保留，避免误伤。
 * 硬上限：连同已认证会话一起淘汰，保证内存绝不越界。*/
const MAX_SESSIONS = Math.max(64, parseInt(process.env.MAX_SESSIONS || '2000', 10) || 2000);
const MAX_PENDING_SESSIONS = Math.max(32, parseInt(process.env.MAX_PENDING_SESSIONS || '500', 10) || 500);

// 溢出淘汰：先清未认证会话中最久未用的，再清全部中最久未用的
function enforceSessionLimits() {
  if (sessions.size <= MAX_SESSIONS) {
    // 仅在「未认证会话」过多时做一次轻量清理
    if (sessions.size <= MAX_PENDING_SESSIONS) return;
    const pend = [];
    for (const [sid, s] of sessions) if (!s.authed) pend.push([sid, s.lastSeen]);
    if (pend.length <= MAX_PENDING_SESSIONS) return;
    pend.sort((a, b) => a[1] - b[1]);
    const drop = pend.length - MAX_PENDING_SESSIONS;
    for (let i = 0; i < drop; i++) {
      sessions.delete(pend[i][0]);
    }
    return;
  }
  // 超过硬上限：先淘汰未认证的，仍不够再按最久未用淘汰全部
  const pending = [], all = [];
  for (const [sid, s] of sessions) {
    all.push([sid, s.lastSeen]);
    if (!s.authed) pending.push([sid, s.lastSeen]);
  }
  pending.sort((a, b) => a[1] - b[1]);
  let need = sessions.size - MAX_SESSIONS;
  for (const [sid] of pending) {
    if (need <= 0) break;
    sessions.delete(sid);
    need--;
  }
  if (need > 0) {
    all.sort((a, b) => a[1] - b[1]);
    for (const [sid] of all) {
      if (need <= 0) break;
      if (!sessions.has(sid)) continue;
      sessions.delete(sid);
      need--;
    }
  }
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function getSession(req, res, create = false) {
  const cookies = parseCookies(req.headers.cookie);
  let sid = cookies[COOKIE_NAME];
  let s = sid && sessions.get(sid);
  if (!s && create) {
    // 先按上限腾位（淘汰最久未活跃 / 优先未认证的），再新建，避免 Map 无界增长
    enforceSessionLimits();
    sid = crypto.randomUUID().replace(/-/g, '');
    s = { sid, authed: false, target: null, tgtCookies: [], createdAt: Date.now(), lastSeen: Date.now() };
    sessions.set(sid, s);
    // HTTPS 时带 Secure；HTTP 直连不带（否则浏览器拒收）
    res.setHeader('Set-Cookie', sessionCookie(req, sid, 43200));
  }
  if (s) s.lastSeen = Date.now();
  return s || null;
}

// 只读 sid（不创建会话）
function readSid(req) {
  const m = /(?:^|;\s*)_gate_sid=([^;]+)/.exec(String(req.headers.cookie || ''));
  return m ? m[1] : null;
}

setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (now - s.lastSeen > SESSION_TTL_MS) {
      sessions.delete(sid);
    }
  }
}, 60 * 1000).unref();

/* ------------------------------------------------------------------ *
 * 目标解析 / 校验
 * ------------------------------------------------------------------ */
function normalizeTarget(input) {
  if (!input) return null;
  let raw = String(input).trim();
  if (!raw) return null;
  if (!/^[a-z]+:\/\//i.test(raw)) raw = 'http://' + raw;

  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

  const host = u.hostname;
  if (!host) return null;
  // 只允许 IP 或内网/域名形式，禁止空格等异常字符
  if (!/^[A-Za-z0-9._:\-]+$/.test(host)) return null;

  let port = u.port ? parseInt(u.port, 10) : u.protocol === 'https:' ? 443 : 80;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;

  // 保留 URL 里的路径作为 base：/wangzhang/ 、/web/ui/ 这类子路径部署
  let base = '';
  try { base = decodeURIComponent(u.pathname || '/'); } catch { return null; }
  if (base.includes('..') || base.includes('\\')) return null;
  base = base.replace(/\/+/g, '/');
  if (!base.startsWith('/')) base = '/' + base;
  // 最后一段看起来是文件名/页面名时当作入口页，只保留目录部分
  if (!base.endsWith('/')) base = base.replace(/\/[^/]*$/, '/');
  if (base === '/' || base === '') base = '';
  if (base && !/^\/[A-Za-z0-9._~%\-/]*$/.test(base)) return null;

  const protocol = u.protocol.replace(':', '');
  return {
    protocol, host, port, base,
    key: `${protocol}//${host}:${port}${base}`,
  };
}

function targetOrigin(t) {
  const isDefault = (t.protocol === 'http' && t.port === 80) || (t.protocol === 'https' && t.port === 443);
  return `${t.protocol}://${t.host}${isDefault ? '' : ':' + t.port}`;
}

/* ---- 网关根路径 <-> 目标 base 的双向映射 ---- */
function splitUrl(url) {
  const i = url.indexOf('?');
  return i < 0
    ? { path: url || '/', query: '' }
    : { path: url.slice(0, i) || '/', query: url.slice(i) };
}

function joinBase(base, path) {
  const b = String(base || '').replace(/\/+$/, '');
  if (!b) return path;
  if (path === b || path === b + '/' || path.startsWith(b + '/')) return path;
  return b + (path.startsWith('/') ? path : '/' + path);
}
/* ------------------------------------------------------------------ *
 * 代理实例
 * ------------------------------------------------------------------ */
const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: false,          // 忽略后端自签 https 证书
  ws: true,
  selfHandleResponse: true,
  // 不注入 x-forwarded-*：这些头会把「网关域名」暴露给目标，
  // 很多内网服务（Lucky/nginx 等）据此做来源校验，直接返回 403。
  xfwd: false,
});

proxy.on('error', (err, req, res) => {
  if (res && !res.headersSent && typeof res.writeHead === 'function') {
    res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(errorPage(err.message));
  } else if (res && typeof res.end === 'function') {
    try { res.end(); } catch {}
  }
});

// 压缩协商：几乎所有「页面能开、JS/CSS 全 404 (len=146)」都是这个原因 ——
// 设备（飞牛 fnOS / 部分 Nginx）静态资源只提供 .js.gz / .css.br 预压缩文件，
// 客户端不声明 gzip/br 就回 404。
//
// 同时必须保证「上游用什么编码，网关都能解开」：
// 现代 Chrome 会发送 `gzip, deflate, br, zstd`，若原样透传，上游可能回 zstd，
// 而我们要改写 JS/CSS 就必须先解码 —— 因此把 zstd 等 Node 不能解的编码剥掉。
function sanitizeAcceptEncoding(clientAE, preferGzip) {
  const parts = String(clientAE || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .map((s) => s.split(';')[0].trim());          // 去掉 q= 权重
  const ok = ['gzip', 'deflate', 'br'];
  const keep = [...new Set(parts.filter((p) => ok.includes(p)))];
  if (keep.length) return keep.join(', ');
  // 客户端只要 identity（或没声明）：若已知该目标依赖压缩协商，则兜底补 gzip
  return preferGzip ? 'gzip, deflate, br' : '';
}

// 统一解码：任何上游返回的压缩体都要能解开（zstd 在 Node 22.15+ 可用）。
// 返回 null 表示「未知编码，调用方必须原样透传」；
// 空 / identity 返回恒等函数（明文，无需解码）。
function makeDecoder(enc) {
  const e = String(enc || '').toLowerCase().trim();
  if (e === '' || e === 'identity') return (b) => b;
  if (e === 'gzip' || e === 'x-gzip') return zlib.gunzipSync;
  if (e === 'deflate') return zlib.inflateSync;
  if (e === 'br') return zlib.brotliDecompressSync;
  if (e === 'zstd' && typeof zlib.zstdDecompressSync === 'function') return zlib.zstdDecompressSync;
  return null;
}

function prepareProxyReq(proxyReq, req, target) {
  // Cookie 处理取决于模式：
  // 透明明代理：Cookie **原样透传**（仅剔除网关自身的会话 cookie）。
  // 目标自己的会话 cookie（如 token=...）必须完整送达，否则目标每次请求都
  // 认为未登录 →「登录已过期」。响应侧 Set-Cookie 也原样回传，因此浏览器里
  // 存的就是目标原生 cookie，直接透传即可闭环。
  {
    const raw = String(req.headers.cookie || '');
    const kept = raw.split(';').map((s) => s.trim()).filter(Boolean)
      .filter((p) => !p.startsWith(COOKIE_NAME + '='));
    proxyReq.removeHeader('Cookie');
    if (kept.length) proxyReq.setHeader('Cookie', kept.join('; '));
  }

  // 页面与资源一律只声明网关能解码的编码（gzip/deflate/br），
  // 既满足「预压缩静态资源」的需求，又保证我们始终能解开并改写。
  const ae = sanitizeAcceptEncoding(req.headers['accept-encoding'], target && target.preferGzip);
  if (ae) proxyReq.setHeader('accept-encoding', ae);
  else proxyReq.removeHeader('accept-encoding');

  // 抹掉会把「网关域名」暴露给目标的头。很多内网服务（Lucky / nginx）
  // 据此做防盗链、Host 白名单或 CSRF 校验，命中即返回 403。
  // STRIP_CLIENT_HEADERS=false 可关闭，用于 A/B 对比定位问题。
  if (STRIP_CLIENT_HEADERS) {
    // 静态资源：尽量还原「浏览器直连目标」时的请求头。
    // 浏览器请求 .js/.css 时不会带 Origin，也一定会带 Sec-Fetch-*；
    // 旧实现无条件注入 Origin、剥掉 Sec-Fetch-*，部分嵌入式设备
    // （iKuai 等）会把它判成跨域接口请求，静态资源直接回 404。
    const isAsset = STATIC_RE.test(String(req.originalUrl || req.url || ''));
    for (const h of Object.keys(proxyReq.getHeaders())) {
      if (/^(x-forwarded-|forwarded$)/i.test(h)) proxyReq.removeHeader(h);
      if (/^sec-fetch-/i.test(h) && !isAsset) proxyReq.removeHeader(h);
    }
    const tOrigin = targetOrigin(target);
    if (isAsset) {
      proxyReq.removeHeader('origin');
      for (const [h, v] of Object.entries(req.headers)) {
        if (/^sec-fetch-/i.test(h) && v !== undefined) proxyReq.setHeader(h, v);
      }
    } else {
      // 比「删除」更稳：把来源伪装成目标自身，兼容要求 Referer 必须同源的防盗链
      proxyReq.setHeader('origin', tOrigin);
    }
    const ref = String(req.headers.referer || '');
    let refPath = '/';
    try { if (ref) refPath = new URL(ref).pathname + new URL(ref).search; } catch {}
    proxyReq.setHeader('referer', tOrigin + refPath);
  }
}

/* ------------------------------------------------------------------ *
 * 代理调度
 * ------------------------------------------------------------------ */
function doProxy(req, res, target) {
  stripGateHeaders(res);    // 移除网关自身的安全头，避免污染被代理内容（见函数注释）
  // 记下「浏览器看到的路径」：Cookie 的默认 Path 要按它推导，
  // 而不是按补了 base 前缀后发往上游的路径（否则过期指令的 Path 会不匹配）。
  req.__gate_visible_path = req.url;
  // 透明代理：不改写响应、不注入内容（仅追加退出按钮）。
  // 但用户显式填写的路径前缀（base）必须保留：否则 /lucky 这类部署会被丢掉，
  // 请求落到上游根路径，表现为「打开的是另一个页面 / 目标服务器默认页」。
  req.__gate_transparent = true;
  if (target.base) {
    const { path, query } = splitUrl(req.url);
    // 已经带该前缀的不重复叠加（浏览器可能直接请求 /lucky/xxx）
    req.url = (path === target.base.replace(/\/$/, '') || path.startsWith(target.base)
      ? path
      : joinBase(target.base, path)) + query;
  }
  req.__gate_out = req.url;
  prepareProxyReqHook(req, target);
  proxy.web(req, res, {
    target: targetOrigin(target),
    changeOrigin: true,
    secure: false,
    selfHandleResponse: true,
    xfwd: false,
    headers: { host: `${target.host}${target.port ? ':' + target.port : ''}` },
  }, (err) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(errorPage(err.message));
    }
  });
}

// 在 proxy.web 之前挂上钩子（每次请求设置）
function prepareProxyReqHook(req, target) {
  req.__gate_target = target;
}
proxy.on('proxyReq', (proxyReq, req) => {
  if (req.__gate_target) prepareProxyReq(proxyReq, req, req.__gate_target);
});
proxy.on('proxyReqWs', (proxyReq, req) => {
  if (req.__gate_target) prepareProxyReq(proxyReq, req, req.__gate_target);
});
// 透明代理的响应统一由下方的直通处理器接管（不做任何改写）

/* ------------------------------------------------------------------ *
 * WebSocket 升级处理
 * ------------------------------------------------------------------ */
function handleUpgrade(req, socket, head) {
  const s = getSession(req);
  if (!s || !s.target) return socket.destroy();
  // 与 HTTP 透明代理保持一致：出站路径补上 base（已带则不重复叠加）。
  if (s.target.base) {
    const { path, query } = splitUrl(req.url);
    req.url = (path === s.target.base.replace(/\/$/, '') || path.startsWith(s.target.base)
      ? path
      : joinBase(s.target.base, path)) + query;
  }
  req.__gate_target = s.target;
  proxy.ws(req, socket, head, {
    target: targetOrigin(s.target),
    changeOrigin: true,
    secure: false,
    headers: { host: `${s.target.host}${s.target.port ? ':' + s.target.port : ''}` },
  });
}

/* ---- 透明代理：原样回传，不做任何改写 ----
 * 这里是「零改写」的关键：状态码、全部响应头、Set-Cookie、Location、
 * Content-Encoding、分块传输…… 一律原封不动交给浏览器。
 * 唯一例外：透明模式下为了能「退出」，会在 HTML 的 </body> 前追加一个
 * 悬浮按钮（只追加、不改写任何既有内容），可通过 INJECT_EXIT_BUTTON=false 关闭。*/
proxy.on('proxyRes', (proxyRes, req, res) => {
  if (!req.__gate_transparent) return;
  if (PROXY_LOG) {
    console.log(`[transparent] ${req.method} ${req.originalUrl} => ${proxyRes.statusCode} (${proxyRes.headers['content-type'] || '-'})`);
  }
  // 透明模式 + 注入开关：对**文本类**响应追加退出按钮，其余原样。
  // 注意：不仅要覆盖 text/html，也要覆盖上游返回的「纯文本错误页」
  // （例如 Lucky 的默认页 "Are you ok?"、Nginx 的 404 文本）。
  // 否则一旦目标报错，用户既看不到内容、也没有退出按钮，彻底卡住。
  if (req.__gate_transparent && INJECT_EXIT) {
    const ctype = String(proxyRes.headers['content-type'] || '');
    const status = proxyRes.statusCode || 200;
    const noBody = status === 204 || status === 304 || (status >= 100 && status < 200);
    const injectable = /text\/html/i.test(ctype) ||
      (/^(?:text\/plain|text\/[a-z0-9.+-]+)/i.test(ctype) && !/text\/css|text\/javascript/i.test(ctype)) ||
      // 上游没给 content-type 时，也按可注入处理（多为文本）
      (!ctype && !noBody);
    if (!noBody && req.method !== 'HEAD' && injectable) {
      return injectOnlyHtml(proxyRes, req, res, req.__gate_target);
    }
  }
  // 防共享缓存：代理响应若被 CDN 按 URL 缓存，会导致切换目标串味 / 旧响应固化。
  // 只覆盖缓存头，其它头保持原样；另修正 Set-Cookie 的 Domain 与绝对 Location。
  const headers = fixPassthroughHeaders({ ...proxyRes.headers }, req.__gate_target);
  // 记录目标下发的 Cookie（供退出时精确过期，含 HttpOnly）
  ledgerAdd(req.__gate_session, headers['set-cookie'], req.__gate_visible_path || req.url);
  delete headers['cache-control'];
  delete headers['expires'];
  delete headers['pragma'];
  delete headers['age'];
  headers['cache-control'] = CACHE_CONTROL;
  const vary = String(headers['vary'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!vary.some((v) => v.toLowerCase() === 'cookie')) vary.push('Cookie');
  headers['vary'] = vary.join(', ');
  res.writeHead(proxyRes.statusCode || 200, headers);
  proxyRes.pipe(res);
});

// 有些站点把 CSP 写在 <meta http-equiv="Content-Security-Policy"> 里，
// 只删响应头不够；若其中未放行 inline script，注入的按钮会被浏览器拦掉。
// 这里移除该 meta 的「脚本相关限制」，其余指令（如 img-src）原样保留。
function stripMetaCsp(html) {
  return String(html).replace(
    /<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi,
    ''
  );
}

/* ---- 透明代理下的「最小必要头部修正」 ----
 * 这两处不改响应体，但**必须**修正，否则会出现「登录已过期」或资源绕过网关：
 *
 * 1) Set-Cookie 里的 Domain：
 *    目标是内网 IP（如 192.168.3.1）时，它会下发 `Domain=192.168.3.1` 的 cookie。
 *    浏览器看到当前站点是网关域名，域不匹配 → **直接拒收该 cookie**
 *    → 目标每次请求都收不到会话 → 表现为「登录已过期」。
 *    做法：剥掉 Domain 属性，使其变为「当前站点」的 host-only cookie。
 *    （同源覆盖场景下这是标准做法；Path/HttpOnly/Secure/SameSite 全部保留。）
 *
 * 2) 绝对地址 Location 且指向目标自身：
 *    目标若 302 到 `http://192.168.3.1/xxx`，浏览器会**直连内网地址**、绕过网关，
 *    在浏览器侧通常表现为连不上 / 混合内容拦截。
 *    做法：把「指向目标自身 origin」的绝对 Location 改成相对路径（其余原样）。
 */
function pfStripCookieDomain(v) {
  return String(v).replace(/;\s*Domain=[^;]*/gi, '');
}

/* ---- 目标登录态「台账」：记录目标下发过的 Cookie（名字 + Path）----
 * 目的：退出代理时能精确把这些 Cookie 过期掉，让下次代理回到「未登录」。
 * 为什么不靠前端删：登录 Cookie 多为 HttpOnly，JS 读不到也删不掉，必须服务端发。
 * 为什么必须记 Path：删除 Cookie 要求 name+path 完全匹配，Path 猜不中就删不掉。 */
function ledgerAdd(session, setCookieValues, reqPath) {
  if (!session || !CLEAR_TARGET_ON_EXIT) return;
  if (!Array.isArray(session.tgtCookies)) session.tgtCookies = [];
  const list = Array.isArray(setCookieValues) ? setCookieValues : [setCookieValues];
  for (const sc of list) {
    const raw = String(sc || '');
    const name = (/^\s*([^=;\s]+)\s*=/.exec(raw) || [])[1];
    if (!name) continue;
    // Path：显式声明优先；否则按浏览器默认规则，取请求路径的目录部分
    let p = (/;\s*Path=([^;]*)/i.exec(raw) || [])[1];
    if (p === undefined) {
      const path = String(reqPath || '/').split('?')[0];
      p = path.slice(0, path.lastIndexOf('/') + 1) || '/';
    }
    p = String(p).trim() || '/';
    // 过期（Max-Age=0 / 过去时间）的 cookie 不必记
    const expired = /;\s*Max-Age\s*=\s*0\b/i.test(raw) ||
      (() => { const m = /;\s*Expires=([^;]+)/i.exec(raw); if (!m) return false; const t = Date.parse(m[1]); return !isNaN(t) && t <= Date.now(); })();
    if (expired) {
      session.tgtCookies = session.tgtCookies.filter((c) => !(c.name === name && c.path === p));
      continue;
    }
    if (!session.tgtCookies.some((c) => c.name === name && c.path === p)) {
      session.tgtCookies.push({ name, path: p });
    }
  }
}

// 生成「清空目标登录态」的一组 Set-Cookie 头（每个记录的 name+path 各一条）
// 注意：删除 Cookie 需要与「原 Cookie 的属性」匹配，因此 HTTPS 下也要带 Secure，
// 否则浏览器可能拒绝这条过期指令、导致旧登录态残留。
function targetClearCookies(session, req) {
  if (!session || !Array.isArray(session.tgtCookies)) return [];
  const secure = req && isHttpsReq(req) ? '; Secure' : '';
  return session.tgtCookies.map((c) =>
    `${c.name}=; Path=${c.path}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax${secure}`
  );
}
function rewriteTargetAbsoluteLocation(loc, target) {
  try {
    const u = new URL(String(loc));
    const sameHost = u.hostname === target.host &&
      (u.port || (u.protocol === 'https:' ? '443' : '80')) === String(target.port);
    if (!sameHost) return loc;                       // 指向别处：原样保留
    // 已是目标自身 → 改为相对路径，强制经网关
    let p = (u.pathname || '/') + (u.search || '') + (u.hash || '');
    // 若目标挂在子路径下，去掉该前缀（浏览器侧路径不含前缀）
    if (target.base && p.startsWith(target.base)) {
      p = '/' + p.slice(target.base.length).replace(/^\/+/, '');
    }
    return p || '/';
  } catch {
    return loc;
  }
}
// 就地修正直通类响应的头部（Set-Cookie / Location）
function fixPassthroughHeaders(headers, target) {
  if (!target) return headers;
  const sc = headers['set-cookie'];
  if (sc) {
    headers['set-cookie'] = Array.isArray(sc)
      ? sc.map(pfStripCookieDomain)
      : pfStripCookieDomain(sc);
  }
  const loc = headers['location'];
  if (loc) {
    headers['location'] = Array.isArray(loc)
      ? loc.map((l) => rewriteTargetAbsoluteLocation(l, target))
      : rewriteTargetAbsoluteLocation(loc, target);
  }
  return headers;
}

// 把一个「非 HTML」的文本响应包成最小合法 HTML，以便挂载退出按钮。
// 仅用于 text/plain、无 content-type 等纯文本场景；HTML 原样传入。
//
// 重要：这里必须**忠实还原浏览器原生渲染纯文本的样子**，否则用户会发现
// 「内容格式和直连不一样」。浏览器对 text/plain 的默认样式是：
//   · 等宽字体（monospace），约 13px；
//   · 默认 8px 页边距，白底、黑字；
//   · 换行/空格原样保留。
// 因此这里用 <pre> + 等价的内联样式，并显式声明页边距与字体，
// 做到「除了右下角多一个退出按钮，其余与直连完全一致」。
function wrapPlainTextAsHtml(text) {
  const esc = String(text)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return '<!doctype html><html lang="zh"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>代理响应</title>' +
    // 复刻浏览器对纯文本的默认样式：仅 body 有 8px 边距、等宽 13px、白底黑字
    '<style>html{margin:0;padding:0}body{margin:8px;padding:0;background:#fff;color:#000}' +
    'pre{margin:0;font-family:monospace;font-size:13px;line-height:1.35;' +
    'white-space:pre-wrap;word-break:break-word}</style></head>' +
    '<body><pre>' + esc + '</pre>' +
    '</body></html>';
}

// 按 content-type 里声明的字符集解码文本（缺省 utf-8）。
// 纯文本页面可能是 gbk 等编码，直接用 utf8 会乱码。
function decodeText(buf, contentType) {
  const m = /charset\s*=\s*["']?([\w-]+)/i.exec(String(contentType || ''));
  const cs = (m ? m[1] : 'utf-8').toLowerCase();
  if (cs === 'utf-8' || cs === 'utf8') return buf.toString('utf8');
  try { return new TextDecoder(cs).decode(buf); } catch { return buf.toString('utf8'); }
}

// 透明模式专用：只注入退出按钮，绝不改写其它内容
function injectOnlyHtml(proxyRes, req, res, target) {
  const headers = fixPassthroughHeaders({ ...proxyRes.headers }, target);
  // 记录目标下发的 Cookie（供退出时精确过期，含 HttpOnly）
  ledgerAdd(req.__gate_session, headers['set-cookie'], req.__gate_visible_path || req.url);
  const enc = String(headers['content-encoding'] || '').toLowerCase();
  const ctype0 = String(headers['content-type'] || '');
  const isHtmlDoc = /text\/html/i.test(ctype0);
  // 我们要「收全 → 注入 → 一次性写回」，因此必须改用 Content-Length。
  // 若保留上游的 transfer-encoding: chunked，会出现
  // 「Content-Length can't be present with Transfer-Encoding」协议错误。
  delete headers['transfer-encoding'];
  // 退出按钮是一段内联脚本；若目标下发了 CSP 且未允许 inline script，
  // 浏览器会直接拦掉它（按钮就不出现）。这里移除 CSP，保证按钮能执行。
  delete headers['content-security-policy'];
  delete headers['content-security-policy-report-only'];
  if (headers['x-frame-options']) delete headers['x-frame-options'];
  const chunks = [];
  proxyRes.on('data', (c) => chunks.push(c));
  proxyRes.on('end', () => {
    const buf = Buffer.concat(chunks);
    const decode = makeDecoder(enc);
    let raw = null;
    if (decode) { try { raw = decode(buf); } catch { raw = null; } }
    // 解不开（未知编码）→ 原样透传，宁可不注入也不破坏
    if (raw === null) {
      headers['content-length'] = buf.length;
      res.writeHead(proxyRes.statusCode || 200, headers);
      res.end(buf);
      return;
    }
    // 按 content-type 声明的字符集解码（纯文本可能是 gbk，用 utf8 会乱码）
    let body = decodeText(raw, ctype0);
    let text = stripMetaCsp(body);
    // 非 HTML（如目标错误页的纯文本 "Are you ok?"）→ 包成 HTML，
    // 否则没有 </body> 可挂，用户既看不到内容也没有退出按钮。
    if (!isHtmlDoc && !/<\/body>/i.test(text)) {
      text = wrapPlainTextAsHtml(text);
      headers['content-type'] = 'text/html; charset=utf-8';
    }
    const out = Buffer.from(injectExitButton(text, target, { mode: 'transparent' }), 'utf8');
    delete headers['content-encoding'];
    delete headers['content-length'];
    headers['content-length'] = out.length;
    res.writeHead(proxyRes.statusCode || 200, headers);
    res.end(out);
  });
  proxyRes.on('error', () => { try { res.end(); } catch {} });
}

/* ------------------------------------------------------------------ *
 * Express 应用
 * ------------------------------------------------------------------ */
const app = express();
app.disable('x-powered-by');

/* --- 防 CDN / 共享缓存：作用于网关自身所有响应（登录页、API、404） --- */
app.use((req, res, next) => {
  res.setHeader('Cache-Control', CACHE_CONTROL);
  res.setHeader('Vary', 'Cookie');
  next();
});

app.use(BASE + '/api', express.json({ limit: '64kb' }));

/* --- 安全响应头（只作用于「网关自身」的响应）---
 * 注意：**绝不**加到被代理的内容上 —— 那会破坏透明代理「零改写」承诺，
 * 且 X-Frame-Options / CSP 可能让被代理应用无法按自身需要内嵌或被内嵌。
 * 这里挂在最前面的中间件上；代理响应走 res.writeHead 时不会继承这些头
 * （因为它们只在 next() 前设置到 res 上，而 writeHead 会以传入对象为准覆盖）。
 * 为稳妥起见，代理写出点用的是显式 headers 对象，天然不带这些头。
 */
app.use((req, res, next) => {
  if (SECURITY_HEADERS) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    // 防点击劫持：Token 输入框在首屏，必须禁止被 iframe 嵌套
    res.setHeader('X-Frame-Options', 'DENY');
    // 仅在 HTTPS 场景下发给浏览器才有效；HTTP 访问时浏览器会忽略
    if (HSTS_MAX_AGE > 0 && isHttpsReq(req)) {
      res.setHeader('Strict-Transport-Security', `max-age=${HSTS_MAX_AGE}; includeSubDomains`);
    }
    // 登录页含内联 <script>/<style>，因此保留 'unsafe-inline'；
    // 其余一律收紧到自身来源，杜绝外链注入与 base 劫持。
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; " +
      "frame-ancestors 'none'; form-action 'self'");
  }
  next();
});

// 判断当前请求是否经 HTTPS（网关前面可能有 CDN/TLS 终止）
function isHttpsReq(req) {
  if (req.socket && req.socket.encrypted) return true;
  if (process.env.TRUST_PROXY === 'true') {
    const xf = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
    if (xf) return xf === 'https';
  }
  return false;
}

// 这些是「网关自身」才该带的安全头。
// ⚠️ Node 的 res.setHeader 会**合并**进后续 res.writeHead()，所以代理响应会
// 意外继承它们 —— 那会破坏透明代理「零改写」，且 CSP/X-Frame-Options 可能
// 让被代理应用无法正常工作。因此在进入代理前必须显式移除。
const GATE_HEADER_NAMES = [
  'X-Content-Type-Options', 'Referrer-Policy', 'X-Frame-Options',
  'Strict-Transport-Security', 'Content-Security-Policy',
];
function stripGateHeaders(res) {
  for (const h of GATE_HEADER_NAMES) {
    try { res.removeHeader(h); } catch {}
  }
}

// 会话 Cookie 的 Secure 策略（COOKIE_SECURE）：
//   auto（默认）：HTTPS 请求才加 Secure，HTTP 直连（内网 192.168.x.x）不加
//                 —— 否则浏览器会**拒收**带 Secure 的 Cookie，直接登录不上。
//   true        ：恒加 Secure。**仅在「只通过 HTTPS 访问」的部署下设**，
//                 若同时保留 HTTP 直连入口，HTTP 下会因拒收而无法登录。
function cookieSecure(req) {
  const mode = String(process.env.COOKIE_SECURE || 'auto').toLowerCase();
  if (mode === 'true' || mode === '1' || mode === 'always') return true;
  if (mode === 'false' || mode === '0' || mode === 'never') return false;
  return isHttpsReq(req);   // auto
}

// 组装会话 Cookie：HTTPS 时附加 Secure（防协议降级被明文携带），
// HTTP 直连（内网 192.168.x.x）时不加，否则浏览器拒收该 Cookie。
function sessionCookie(req, sid, maxAge) {
  return `${COOKIE_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax` +
    (cookieSecure(req) ? '; Secure' : '') +
    `; Max-Age=${maxAge}`;
}

app.use(BASE + '/static', express.static(path.join(__dirname, 'public'), { index: false }));

/* --- Token 校验（恒定时间比较 + 失败指数退避）--- */
app.post(BASE + '/api/auth', async (req, res) => {
  // 退避期内直接 429（避免爆破）
  const left = authLockRemaining(req);
  if (left > 0) {
    res.setHeader('Retry-After', String(Math.ceil(left / 1000)));
    return res.status(429).json({ ok: false, error: `尝试过于频繁，请 ${Math.ceil(left / 1000)} 秒后重试` });
  }
  const token = String((req.body && req.body.token) || '');
  const sha = (v) => crypto.createHash('sha256').update(v).digest();
  const ok = crypto.timingSafeEqual(sha(token), sha(TOKEN));   // 恒定时间比较

  if (!ok) {
    authNoteFail(req);
    return res.status(401).json({ ok: false, error: 'Token 不正确' });
  }
  authNoteSuccess(req);
  const s = getSession(req, res, true);
  s.authed = true;
  res.json({ ok: true });
});

/* --- 当前状态 --- */
app.get(BASE + '/api/me', (req, res) => {
  const s = getSession(req);
  res.json({
    ok: true,
    build: BUILD_ID,
    authed: !!(s && s.authed),
    hasTarget: !!(s && s.target),
    target: s && s.target ? { protocol: s.target.protocol, host: s.target.host, port: s.target.port, base: s.target.base } : null,
  });
});

/* --- 登录目标（仅透明代理）--- */
app.post(BASE + '/api/login', async (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });

  const target = normalizeTarget((req.body && req.body.target) || '');
  if (!target) return res.status(400).json({ ok: false, error: '地址格式不正确，示例：192.168.1.10:8080' });

  s.target = target;
  s.lastSeen = Date.now();

  const now = Date.now();
  if (req.body && req.body.save) {
    const name = String(req.body.name || '').trim() || `${target.host}:${target.port}${target.base}`;
    const note = String(req.body.note || '').trim();
    stmt.upsert.run(name, note, target.protocol, target.host, target.port, target.base, now, now);
  } else {
    const found = stmt.find.get(target.protocol, target.host, target.port, target.base);
    if (found) stmt.touch.run(now, found.id);
  }

  res.json({
    ok: true,
    target: { protocol: target.protocol, host: target.host, port: target.port, base: target.base },
  });
});

/* --- 退出当前代理（回登录页） ---
 * 关键：透明代理下，被代理页面自己的登录 Cookie 也存在于「网关」这个源下。
 * 若不清掉，下次代理同一服务会带着旧登录态 → 跳过目标自己的登录页。
 * 这里按台账把目标下发过的 Cookie 逐个过期（含 HttpOnly，指名道姓 + 原 Path）。
 * 前端脚本还会清 localStorage/sessionStorage/IndexedDB（覆盖非 Cookie 方案）。 */
app.post(BASE + '/api/logout', (req, res) => {
  const s = getSession(req);
  let cleared = [];
  if (s) {
    // 清目标的登录 Cookie（不碰网关自身的 _gate_sid，保留 Token 门禁）
    cleared = targetClearCookies(s, req);
    s.tgtCookies = [];
    s.target = null;
  }
  if (cleared.length) res.setHeader('Set-Cookie', cleared);
  // Clear-Site-Data 是最可靠的「清源」方式：让浏览器丢掉该源的
  // Service Worker 注册与 Cache Storage（PWA 缓存），以及各存储。
  // 注意：**不含 cookies** —— 网关自身与目标的会话 Cookie 由 Set-Cookie 精确处理。
  res.setHeader('Clear-Site-Data', '"cache", "storage"');
  res.json({ ok: true, clearedCookies: cleared.length });
});

/* --- 完全退出（清 Token 会话） --- */
app.post(BASE + '/api/exit', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies[COOKIE_NAME];
  const s = sid && sessions.get(sid);
  let cleared = [];
  if (s) {
    cleared = targetClearCookies(s, req);
  }
  if (sid) sessions.delete(sid);
  const all = [...cleared, sessionCookie(req, '', 0)];
  res.setHeader('Set-Cookie', all);
  res.json({ ok: true, clearedCookies: cleared.length });
});

/* --- 站点列表（全局共享的已保存地址） --- */
app.get(BASE + '/api/sites', (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });
  res.json({ ok: true, sites: stmt.list.all() });
});

app.delete(BASE + '/api/sites/:id', (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });
  stmt.del.run(parseInt(req.params.id, 10));
  res.json({ ok: true });
});

/* --- 编辑已保存站点（名称 / 备注） --- */
app.patch(BASE + '/api/sites/:id', (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });
  const id = parseInt(req.params.id, 10);
  const row = stmt.get.get(id);
  if (!row) return res.status(404).json({ ok: false, error: '记录不存在' });
  const name = req.body && req.body.name !== undefined ? String(req.body.name).trim() : row.name;
  const note = req.body && req.body.note !== undefined ? String(req.body.note).trim() : row.note;
  let base = req.body && req.body.base !== undefined ? String(req.body.base).trim() : (row.base || '');
  if (base && !base.startsWith('/')) base = '/' + base;
  if (base && !base.endsWith('/')) base += '/';
  if (base === '/') base = '';
  if (base && !/^\/[A-Za-z0-9._~\-%/]*$/.test(base)) return res.status(400).json({ ok: false, error: '子路径格式不正确' });
  try {
    stmt.update.run(name || row.name, note, base, id);
  } catch {
    return res.status(409).json({ ok: false, error: '已存在相同地址与子路径的保存项' });
  }
  res.json({ ok: true });
});

/* --- 根路径：有目标则代理，否则给登录页 --- */
const indexPath = path.join(__dirname, 'public', 'index.html');
app.use((req, res, next) => {
  if (req.path.startsWith(BASE + '/')) return next();
  const s = getSession(req);
  if (s && s.target) {
    req.__gate_session = s;       // 供响应侧记录目标 Cookie 台账 / 退出时清理
    return doProxy(req, res, s.target);
  }
  if (req.method === 'GET' && (req.path === '/' || req.path === '/index.html')) {
    // cacheControl:false 避免 Express 覆盖上面设置的 no-store
    return res.sendFile(indexPath, { cacheControl: false });
  }
  res.status(404).type('text/plain; charset=utf-8').send('Not found. 请先通过网关登录。');
});

// 兜底 404：覆盖 /_gate/* 下未匹配的路由，避免落到 Express 默认错误页
// （默认页会回 "Cannot GET /xxx"，暴露后端为 Node/Express）。
app.use((req, res) => {
  res.status(404).type('text/plain; charset=utf-8').send('Not found.');
});

// 兜底错误处理：不让 Express 默认错误页泄露堆栈/技术栈
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const code = err && err.status && err.status >= 400 ? err.status : 500;
  res.status(code).type('text/plain; charset=utf-8').send(code === 400 ? 'Bad request.' : 'Server error.');
});

/* ------------------------------------------------------------------ *
 * 页面
 * ------------------------------------------------------------------ */
function injectExitButton(html, target, opts = {}) {
  if (html.includes('__gate_exit__')) return html;
  const label = target.host + (target.port ? ':' + target.port : '') + (target.base || target.assetPrefix || '');
  const modeTag = opts.mode === 'transparent' ? '透明代理' : '代理中';
  // 说明：不少 SPA（Vite/React/Vue）挂载时会整体替换 <body> 内容，
  // 直接把按钮写进 body 会被「洗掉」。因此这里只注入一段自愈脚本：
  //   · 节点挂到 <html>(documentElement) 上，body 被重建也不受影响；
  //   · 用 MutationObserver 监听，一旦被移除就重新挂上；
  //   · 不依赖任何外部资源，纯内联，零改写原有内容。
  const j = (s) => JSON.stringify(String(s));   // 安全嵌入字符串
  // 样式：默认左上角、收成小圆点（悬停/确认态才展开文字）、可拖动。
  // 用运行时创建的 <style>（只追加、不改写原有内容），这样能用 :hover 伪类，
  // 比内联样式更干净；且 SPA 重建 body 也不影响该 style。
  const CSS =
    '#__gate_exit__{position:fixed;top:10px;left:10px;z-index:2147483647;' +
    'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;' +
    'touch-action:none;user-select:none;-webkit-user-select:none;}' +
    // 折叠态：28×28 正圆、gap 必须为 0 —— 否则文字 span 宽度虽为 0，
    // flex 的 gap 仍占位（8px 点 + 7px 间隙），导致圆点被挤出中心。
    '#__gate_exit_btn__{display:flex;align-items:center;gap:0;box-sizing:border-box;' +
    'width:28px;height:28px;padding:0;justify-content:center;border:0;border-radius:50%;' +
    'background:#111827;color:#fff;font-size:12px;line-height:1;cursor:pointer;' +
    'box-shadow:0 4px 14px rgba(0,0,0,.28);opacity:.92;overflow:hidden;' +
    'transition:width .18s ease,padding .18s ease,gap .18s ease,background .15s ease;}' +
    // 展开态（悬停 / 待确认）：恢复间隙、左对齐
    '#__gate_exit__:hover #__gate_exit_btn__{width:auto;gap:7px;padding:0 12px 0 10px;' +
    'border-radius:999px;justify-content:flex-start;}' +
    '#__gate_exit__.__g_armed #__gate_exit_btn__{width:auto;gap:7px;padding:0 12px 0 10px;' +
    'border-radius:999px;justify-content:flex-start;background:#b42318;}' +
    '#__gate_exit__ .__g_dot{width:8px;height:8px;border-radius:50%;background:#22c55e;' +
    'flex:0 0 auto;display:inline-block;}' +
    '#__gate_exit__.__g_armed .__g_dot{background:#fff;}' +
    '#__gate_exit__ .__g_txt{max-width:0;opacity:0;overflow:hidden;white-space:nowrap;' +
    'transition:max-width .2s ease,opacity .2s ease;}' +
    '#__gate_exit__:hover .__g_txt,#__gate_exit__.__g_armed .__g_txt{max-width:340px;opacity:1;}';
  const script =
    '<script data-gate-exit="1">(function(){' +
    'if(window.__gate_exit_installed__)return;window.__gate_exit_installed__=true;' +
    'var LABEL=' + j(modeTag + ' ' + label) + ';' +
    'var ACT="退出",ARM="再点一次确认退出";' +
    'var POS=null;' +              // 会话内位置（拖动后记住，刷新即回默认；不做持久化）
    'function ensureCss(){' +
    'if(document.getElementById("__gate_exit_style__"))return;' +
    'var s=document.createElement("style");s.id="__gate_exit_style__";' +
    's.textContent=' + j(CSS) + ';' +
    '(document.head||document.documentElement).appendChild(s);}' +
    'function build(){' +
    'var d=document.createElement("div");d.id="__gate_exit__";' +
    'if(POS){d.style.left=POS[0]+"px";d.style.top=POS[1]+"px";}' +
    'd.innerHTML=' + j('<button id="__gate_exit_btn__"><span class="__g_dot"></span><span class="__g_txt"></span></button>') + ';' +
    'var b=d.querySelector("button"),t=d.querySelector(".__g_txt");' +
    't.textContent=LABEL+" | "+ACT;' +
    // 阻止被代理页面（SPA/React）抢走事件。必须用**冒泡阶段**（第 3 参数 false）：
    // 事件先到按钮自身的处理器，再冒泡到容器被拦下、不外泄给宿主页面。
    // 若用捕获阶段（true）会在按钮处理器**之前**就 stopPropagation，反而吃掉自己的点击。
    '["mousedown","mouseup","click","pointerdown","pointerup","touchstart","touchend"].forEach(function(ev){' +
    'd.addEventListener(ev,function(e){e.stopPropagation();},false);});' +
    // 清「目标」留在这个源下的所有痕迹：
    //  · Service Worker：PWA（如 IT-Tools）会注册 SW 并缓存整站；必须**先注销**，
    //    否则退出后跳转 / 会被 SW 用缓存的旧页面顶回来，看着像「没退出」。
    //  · Cache Storage：清掉 SW 的预缓存，使其无法再命中缓存 → 自动回源到网关。
    //  · localStorage/sessionStorage/IndexedDB：覆盖把 token 存前端的服务。
    // 返回 Promise：调用方等它完成后再跳转（关键：不能边清边跳）。
    'function wipe(){' +
    'var jobs=[];' +
    'try{if(navigator.serviceWorker&&navigator.serviceWorker.getRegistrations){' +
    'jobs.push(navigator.serviceWorker.getRegistrations().then(function(rs){' +
    'return Promise.all((rs||[]).map(function(r){return r.unregister().catch(function(){});}));' +
    '}).catch(function(){}));}}catch(e){}' +
    'try{if(window.caches&&caches.keys){' +
    'jobs.push(caches.keys().then(function(ks){' +
    'return Promise.all((ks||[]).map(function(k){return caches.delete(k).catch(function(){});}));' +
    '}).catch(function(){}));}}catch(e){}' +
    'try{localStorage.clear();}catch(e){}' +
    'try{sessionStorage.clear();}catch(e){}' +
    'try{if(indexedDB&&indexedDB.databases){' +
    'jobs.push(indexedDB.databases().then(function(dbs){' +
    '(dbs||[]).forEach(function(db){try{indexedDB.deleteDatabase(db.name);}catch(e){}});' +
    '}).catch(function(){}));}}catch(e){}' +
    'return Promise.all(jobs);' +
    '}' +
    'function leave(){' +
    // replace 而非 href：不留历史记录，避免「后退」又被 SW 缓存顶回代理页
    'location.replace("/?_gate_exit=" + Date.now());' +
    '}' +
    'function doExit(){' +
    // 关键顺序：先让服务端过期目标 Cookie，再清 SW/缓存/存储，**最后**才跳转；
    // 且全程带超时兜底，任何一步卡住都不会让用户点不动。
    'var done=false;function once(){if(done)return;done=true;leave();}' +
    'setTimeout(once,2500);' +
    'var p;' +
    'try{p=fetch("/_gate/api/logout",{method:"POST",cache:"no-store",credentials:"same-origin"});}' +
    'catch(e){p=Promise.resolve();}' +
    'Promise.resolve(p).catch(function(){}).then(function(){' +
    'try{return wipe();}catch(e){return null;}' +
    '}).then(once,once);' +
    '}' +
    'var armTimer=null,armed=false;' +
    // 取消「待确认」态：必须同时复位 DOM 与武装变量 armed，
    // 否则超时/拖动取消后 armed 仍为 true，下一次点击会**直接退出**（漏点一次确认）。
    'function disarm(){armed=false;d.setAttribute("data-armed","0");' +
    'd.className="";t.textContent=LABEL+" | "+ACT;}' +
    // ---- 拖动：Pointer Events + setPointerCapture，鼠标/触摸通用 ----
    // 阈值 4px：小于阈值算点击（避免手抖误判为拖动）；拖动后吞掉随后的 click，
    // 并取消「待确认」态 —— 否则「拖完再点」会误退出。
    //
    // ⚠️ 关键坑：一旦调用 setPointerCapture，浏览器会把后续的 **click 事件
    // 也重定向到「被捕获的元素」**。我们必须捕获在容器 d 上（拖动时指针移出
    // 元素也要能收到 move），因此 click 的 target 会变成 d，而**不是 <button> b**。
    // 若把点击处理绑在 b 上（早期实现），就会「点不动」。
    // 解法：点击判定放在 **pointerup**（捕获元素 d 一定能收到），click 仅作
    // 键盘/无障碍兜底。用 __fromPointer 标记避免一次操作触发两次。
    'var drag=false,mv=false,sx=0,sy=0,ox=0,oy=0,suppress=false,TH=4,fromPtr=false;' +
    'function tap(){' +
    'if(armed){doExit();return;}' +
    'armed=true;d.setAttribute("data-armed","1");d.className="__g_armed";t.textContent=ARM;' +
    'if(armTimer)clearTimeout(armTimer);' +
    'armTimer=setTimeout(disarm,4000);' +
    '}' +
    'd.addEventListener("pointerdown",function(e){' +
    'if(e.button&&e.button!==0)return;' +
    'drag=true;mv=false;fromPtr=false;' +   // 每次按下都复位，防止某次 click 未触发导致后续被误吞
    'sx=e.clientX;sy=e.clientY;' +
    'var r=d.getBoundingClientRect();ox=r.left;oy=r.top;' +
    'try{d.setPointerCapture(e.pointerId);}catch(_){}});' +
    'd.addEventListener("pointermove",function(e){' +
    'if(!drag)return;' +
    'var dx=e.clientX-sx,dy=e.clientY-sy;' +
    'if(!mv&&Math.abs(dx)<=TH&&Math.abs(dy)<=TH)return;' +
    'mv=true;' +
    'var vw=document.documentElement.clientWidth||window.innerWidth||1024;' +
    'var vh=document.documentElement.clientHeight||window.innerHeight||768;' +
    'var nw=d.offsetWidth||28,nh=d.offsetHeight||28;' +
    'var nx=Math.max(0,Math.min(ox+dx,vw-nw));' +
    'var ny=Math.max(0,Math.min(oy+dy,vh-nh));' +
    'd.style.left=nx+"px";d.style.top=ny+"px";' +
    'd.style.right="auto";d.style.bottom="auto";' +
    'POS=[nx,ny];});' +
    'd.addEventListener("pointerup",function(e){' +
    'if(!drag)return;drag=false;' +
    'try{d.releasePointerCapture(e.pointerId);}catch(_){}' +
    'fromPtr=true;' +                      // 标记：本次操作由指针完成，忽略随后的 click
    'var self=(e.target===b||b.contains(e.target));' +  // 点在按钮（或没被重定向到 d）上
    'if(mv){suppress=true;disarm();return;}' +           // 拖动：不算点击
    'if(self||e.target===d||d.contains(e.target)){tap();}' +  // 纯点击（含被捕获重定向到 d 的情况）
    '});' +
    'd.addEventListener("pointercancel",function(){drag=false;});' +
    // 两步确认：不使用浏览器 confirm()（可能被「阻止此页面创建更多对话框」
    // 静默拦掉导致点击毫无反应）。改为自身二次确认，纯 DOM，不依赖弹窗。
    // 这里的 click 只用于「键盘 Enter/Space」等非指针激活；指针点击已在 pointerup 处理。
    'b.addEventListener("click",function(e){' +
    'e.preventDefault();e.stopPropagation();' +
    'if(fromPtr){fromPtr=false;return;}' +   // 指针已处理，避免重复触发
    'if(suppress){suppress=false;return;}' +
    'tap();' +
    '});' +
    'd.addEventListener("click",function(e){' +   // 捕获异常时的兜底：click 落在容器上
    'e.preventDefault();e.stopPropagation();' +
    'if(fromPtr){fromPtr=false;return;}' +
    'if(suppress){suppress=false;return;}' +
    'tap();' +
    '});' +
    'return d;}' +
    'function mount(){' +
    'if(!document.body){return setTimeout(mount,30);}' +
    'ensureCss();' +
    'if(document.getElementById("__gate_exit__"))return;' +
    'var host=document.documentElement||document.body;' +
    'host.appendChild(build());}' +
    'function watch(){' +
    'var obs=new MutationObserver(function(){if(!document.getElementById("__gate_exit__"))mount();});' +
    'obs.observe(document.documentElement,{childList:true,subtree:true});' +
    'var n=0,timer=setInterval(function(){if(!document.getElementById("__gate_exit__"))mount();if(++n>60)clearInterval(timer);},500);}' +
    'if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",function(){mount();watch();});' +
    'else{mount();watch();}' +
    '})();<' + '/script>';
  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, script + '</body>');
  if (/<\/html>/i.test(html)) return html.replace(/<\/html>/i, script + '</html>');
  return html + script;
}

function errorPage(msg) {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>代理失败</title></head>
<body style="font-family:system-ui;padding:48px;background:#f8fafc;color:#0f172a">
<h2 style="margin:0 0 8px">无法连接到目标服务</h2>
<p style="color:#475569;line-height:1.7">${String(msg).replace(/[<>&]/g, '')}</p>
<p><a href="/" style="color:#2563eb">← 返回登录页</a></p>
</body></html>`;
}

/* ------------------------------------------------------------------ *
 * 启动
 * ------------------------------------------------------------------ */
const server = http.createServer(app);
server.on('upgrade', handleUpgrade);
server.listen(PORT, () => {
  console.log(`[intranet-gateway] listening on :${PORT}`);
  console.log(`[intranet-gateway] data dir: ${DATA_DIR}`);
  if (TOKEN === 'changeme') console.warn('[intranet-gateway] ⚠ 正在使用默认 TOKEN=changeme，请通过环境变量修改！');
});
