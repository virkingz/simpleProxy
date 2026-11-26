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
// 出站请求是否清洗「网关来源」头（默认开）。403 排查时可设为 false 做 A/B 对比。
const STRIP_CLIENT_HEADERS = process.env.STRIP_CLIENT_HEADERS !== 'false';
// 打印每个代理请求的上游状态，便于定位 4xx/5xx 来自哪一层
const PROXY_LOG = process.env.PROXY_LOG === 'true';
const SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 小时无操作过期
const COOKIE_NAME = '_gate_sid';
const BASE = '/_gate';
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
// CDN 已缓存的旧 404 不会因源站加 no-store 而消失，但缓存键包含 query，
// 换 URL 即可立刻回源；网关转发前剥离该参数，目标服务完全无感。
// 设 BUST_CDN_CACHE=false 可关闭。
const BUST_CDN_CACHE = process.env.BUST_CDN_CACHE !== 'false';
const BUST_PARAM = '_gw';

/* ------------------------------------------------------------------ *
 * 端口转发模式（PORT_FORWARD）
 *
 * 这是与「路径代理」并存的第二种工作模式，两者取长补短：
 *
 *  · 路径代理（默认）：网关在同一个域名/端口下用路径区分目标，靠改写
 *    HTML/JS 让子资源也走网关。优点是不用额外端口；缺点是要改写内容，
 *    复杂的 SPA（动态 import、内联 worker、绝对 URL、__vite__ 预加载等）
 *    容易出现漏改 → 页面空白。
 *
 *  · 端口转发：登录后网关在宿主机另开一个「专属端口」，把该端口的全部
 *    流量**原样**转给目标（不改写任何 HTML/JS）。浏览器直接访问
 *    http://<网关IP>:<专属端口>/，目标站点看到的自己就是「根路径」，
 *    因此不存在绝对路径错位、也不存在改写遗漏 —— 从根上绕开整类问题。
 *
 * 安全：专属端口同样要求携带网关会话 Cookie，且会话必须已选择目标，
 * 否则返回一个提示页，避免变成开放代理。
 * ------------------------------------------------------------------ */
const PORT_FORWARD = process.env.PORT_FORWARD !== 'false';   // 是否允许端口转发模式
const PF_RANGE_START = Math.max(1, parseInt(process.env.PORT_FORWARD_START || '20000', 10) || 20000);
const PF_RANGE_END = Math.min(65535, parseInt(process.env.PORT_FORWARD_END || '20999', 10) || 20999);
const PF_HOST = process.env.PORT_FORWARD_HOST || '';        // 展示用的网关可达地址（可选）

/* ------------------------------------------------------------------ *
 * 透明代理模式（TRANSPARENT，nginx 风格）—— 推荐默认
 *
 * 与「路径代理 + 内容改写」的根本区别：**完全不碰响应体**。
 * 不注入退出按钮、不重写 origin、不加 _gw、不去 base。只做三件事：
 *   · 把请求原样转给目标（换 Host）；
 *   · 把上游 Set-Cookie 原样回传（不再改名/去 Domain/改 Path）；
 *   · 透传状态码与响应头。
 *
 * 为什么这样更不容易白屏：改写 HTML/JS 是「侵入式」的，现代前端
 * （Vite 的动态 import、__vite__mapDeps、内联 worker、根绝对路径资源）
 * 一旦被改错一处就会整页崩。透明转发让目标服务始终认为自己在根路径，
 * 前端拿到的是**一字未改**的原始代码，因此不存在「漏改」。
 *
 * HTTPS 说明：网关对外是什么协议就是什么协议，转发时与目标之间按目标
 * 自身的 scheme 建立连接（网关 → 目标 走 http 或 https 均可，可跨协议），
 * 因此不存在「http 页面请求 https 资源」的混合内容问题；目标若用自签
 * 证书，已内置 secure:false 忽略校验。
 * ------------------------------------------------------------------ */
const TRANSPARENT = process.env.TRANSPARENT !== 'false';   // 是否提供透明模式

/* ------------------------------------------------------------------ *
 * 通用子路径（base path）代理
 *
 * 很多内网服务不是挂在 / 根，而是挂在 /wangzhang/、/web/、/ui/ 这类
 * 前缀下，或者 HTML 里写死根级 /static/... 而文件其实在别的目录。
 * 旧版 normalizeTarget 直接丢掉了 URL 里的 pathname，导致这类服务
 * 一律 404（且 404 来自上游，不是网关、也不是 CDN）。
 *
 * 两层处理：
 *  ① 显式：登录地址带路径时保留为 base，所有出站请求自动补上
 *     （已经带 base 的路径不会重复叠加）；Location 去掉 base，避免前缀越叠越长。
 *  ② 自动：静态资源在上游 404 时，探测目标真实前缀并即时回源；
 *     命中后只对该会话的「静态资源」请求补前缀，不影响页面/API。
 * ------------------------------------------------------------------ */
const AUTO_SUBPATH = process.env.AUTO_SUBPATH !== 'false';
const PROBE_TIMEOUT_MS = Math.max(200, Math.min(5000, parseInt(process.env.PROBE_TIMEOUT_MS || '1200', 10) || 1200));
const DEFAULT_PREFIXES = ['/web', '/ui', '/www', '/h5', '/admin', '/public', '/dist', '/frontend', '/console', '/manage'];
const STATIC_RE = /\.(?:js|mjs|cjs|css|map|ico|png|jpe?g|gif|svg|webp|bmp|woff2?|ttf|eot|otf|json|txt|wasm)(?:[?#]|$)/i;
// 只对真正的静态文件做 404 探测，避免把 /api/config.json 这类接口也算进去
const PROBE_ASSET_RE = /\.(?:js|mjs|cjs|css|ico|png|jpe?g|gif|svg|webp|bmp|woff2?|ttf|eot|otf|wasm)(?:[?#]|$)/i;
// 这些段不是「部署前缀」，不能当作 base 候选
const SKIP_PREFIX_RE = /^(?:static|assets?|js|css|img|images?|fonts?|media|public|dist|build|login|index\.html?|default\.html?|home|api|favicon\.ico)$/i;

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
    sid = crypto.randomUUID().replace(/-/g, '');
    s = { sid, authed: false, target: null, createdAt: Date.now(), lastSeen: Date.now() };
    sessions.set(sid, s);
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200`);
  }
  if (s) s.lastSeen = Date.now();
  return s || null;
}

// 只读 sid（供端口转发监听器使用，不创建会话）
function readSid(req) {
  const m = /(?:^|;\s*)_gate_sid=([^;]+)/.exec(String(req.headers.cookie || ''));
  return m ? m[1] : null;
}

setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (now - s.lastSeen > SESSION_TTL_MS) {
      if (typeof pfRelease === 'function') pfRelease(s);
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
    mode: 'path',                    // 运行时由登录参数决定：path | transparent
    assetPrefix: '',                 // 自动探测到的静态资源前缀（仅会话内有效）
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

function stripBase(pathname, base) {
  const b = String(base || '').replace(/\/+$/, '');
  if (!b) return pathname;
  if (pathname === b) return '/';
  if (pathname.startsWith(b + '/')) return '/' + pathname.slice(b.length + 1);
  return pathname;
}

// 在 proxy.web 之前把 req.url 改写成目标侧真实路径。
// base 作用于所有请求；assetPrefix 只作用于静态资源（自动探测结果），
// 避免把 /login、/api/... 也带偏。
function mapOutgoingUrl(req, target) {
  const { path, query } = splitUrl(req.url);
  let p = path;
  if (target.base) p = joinBase(target.base, p);
  else if (target.assetPrefix && PROBE_ASSET_RE.test(path)) p = joinBase(target.assetPrefix, p);
  req.url = p + query;
  return req.url;
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

/* ---- 出站请求：cookie 命名空间隔离 + 抹掉网关来源 + 关闭压缩 ---- */
// 直接按原始字符串过滤 cookie，不做 decode/encode 往返：
// 早期实现用 parseCookies 解码后再 encodeURIComponent，会把 token 里的
// `+` `/` `=` 变成 %2B %2F %3D，目标解析失败 → 403。
function forwardCookieHeader(raw, prefix) {
  if (!raw) return null;
  const keep = [];
  for (const part of raw.split(';')) {
    const p = part.trim();
    const i = p.indexOf('=');
    if (i < 0) continue;
    const name = p.slice(0, i);
    if (name.startsWith(prefix)) keep.push(p.slice(prefix.length));
  }
  return keep.length ? keep.join('; ') : null;
}

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
  //  · 透明代理 / 端口转发：**原样透传**。目标自己的会话 cookie（如 token=...）
  //    必须完整送达，否则目标每次请求都认为未登录 →「登录已过期」。
  //    这两种模式下响应侧的 Set-Cookie 也是原样回传的，所以浏览器里存的就是
  //    目标原生的 cookie，直接透传即可闭环。
  //  · 路径代理：多个目标共用同一域名，必须用前缀隔离，避免 cookie 串味。
  if (target.mode === 'transparent' || req.__pf_port) {
    // 只剔除网关自身的会话 cookie（避免泄漏给目标/被目标覆盖），其余原样透传
    const raw = String(req.headers.cookie || '');
    const kept = raw.split(';').map((s) => s.trim()).filter(Boolean)
      .filter((p) => !p.startsWith(COOKIE_NAME + '='));
    proxyReq.removeHeader('Cookie');
    if (kept.length) proxyReq.setHeader('Cookie', kept.join('; '));
  } else {
    const prefix = cookiePrefix(target);
    const cookies = forwardCookieHeader(req.headers.cookie, prefix);
    if (cookies) proxyReq.setHeader('Cookie', cookies);
    else proxyReq.removeHeader('Cookie');
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

/* ---- 响应：cookie 命名空间隔离 + Location 重写 + HTML 注入 ---- */
function handleProxyRes(proxyRes, req, res, target) {
  const prefix = cookiePrefix(target);
  const headers = { ...proxyRes.headers };

  // 我们是「收全 → 改写 → 一次性写回」，必须用 Content-Length，
  // 因此要剔除上游的分块传输头，否则两者冲突会损坏响应。
  delete headers['transfer-encoding'];

  // 代理响应同样禁止共享缓存：同一 URL 在不同会话可能指向不同目标，
  // 被 CDN 缓存会导致 404 固化 / 切换目标串味。覆盖上游的
  // public / s-maxage / immutable / Expires 等缓存指令。
  delete headers['cache-control'];
  delete headers['expires'];
  delete headers['pragma'];
  delete headers['age'];
  headers['cache-control'] = CACHE_CONTROL;
  const vary = String(headers['vary'] || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!vary.some(v => v.toLowerCase() === 'cookie')) vary.push('Cookie');
  headers['vary'] = vary.join(', ');

  // Set-Cookie 改名 + 去掉 Domain，统一挂在网关根路径
  const sc = proxyRes.headers['set-cookie'];
  if (sc) {
    headers['set-cookie'] = sc.map((line) => {
      const m = line.match(/^([^=]+)=/);
      if (!m) return line;
      const name = m[1].trim();
      let rest = line.slice(m[0].length);
      rest = rest.replace(/;\s*Domain=[^;]*/gi, '');
      rest = rest.replace(/;\s*Path=[^;]*/gi, '');
      return `${prefix}${name}=${rest}; Path=/`;
    });
  }

  // Location 重写：指回目标自身的绝对地址 → 相对路径
  const loc = headers['location'];
  if (loc) {
    headers['location'] = rewriteLocation(loc, target);
  }

  const ctype = String(headers['content-type'] || '');
  const enc = String(headers['content-encoding'] || '').toLowerCase();
  const status = proxyRes.statusCode || 200;
  if (PROXY_LOG) {
    const out = String(req.__gate_out || req.url || '');
    const upServer = String(proxyRes.headers.server || '-');
    console.log(`[proxy] ${req.method} ${req.originalUrl} -> ${out} @ ${targetOrigin(target)} => ${status} (server=${upServer}, ${ctype || '-'}, len=${proxyRes.headers['content-length'] ?? 'chunked'})`);
    // 让浏览器 DevTools 里也能一眼看出「请求到底被转发成了什么路径」
    res.setHeader('X-Gate-Outgoing', out);
    res.setHeader('X-Gate-Upstream', String(status));
  }
  // 204/304 及 1xx 无响应体，不能改写、也不能注入
  const noBody = status === 204 || status === 304 || (status >= 100 && status < 200);

  // 目标站点若下发 CSP / frame 限制，会拦住网关下的资源，直接去掉
  delete headers['content-security-policy'];
  delete headers['content-security-policy-report-only'];
  if (headers['x-frame-options']) delete headers['x-frame-options'];

  if (noBody || req.method === 'HEAD') {
    res.writeHead(status, headers);
    return proxyRes.pipe(res);
  }

  // 通用子路径兜底：静态资源被「上游」判 4xx 时，探测目标真实前缀并即时回源。
  // 注意：这里针对的是上游 404（响应里带 Server / X-Arch 等目标自己的头），
  // 不是网关的 38 字节未登录 404，也不是 CDN 缓存的 145 字节 404。
  if (AUTO_SUBPATH && !target.base && !target.assetPrefix && !req.__gate_retried &&
      (target.probeCount || 0) < 3 &&
      status >= 400 && status < 500 &&
      PROBE_ASSET_RE.test(String(req.originalUrl || ''))) {
    req.__gate_retried = true;
    target.probeCount = (target.probeCount || 0) + 1;
    return handleStaticFallback(proxyRes, req, res, target, headers, status);
  }

  const isHtml = /text\/html/i.test(ctype);
  // 文本类响应体才做 origin 重写（JS 里常硬编码自身 origin）
  const isTextLike = /(javascript|ecmascript|text\/css|application\/json|text\/plain)/i.test(ctype);

  if (isHtml && INJECT_EXIT) {
    // 收集 → 解压 → origin 重写 → 注入退出按钮 → 以 identity 回传
    const chunks = [];
    proxyRes.on('data', (c) => chunks.push(c));
    proxyRes.on('end', () => {
      const buf = Buffer.concat(chunks);
      const decode = makeDecoder(enc);
      let body = null;
      if (decode) {
        try { body = decode(buf).toString('utf8'); } catch { body = null; }
      }
      // 解压失败 / 未知编码：原样透传（保留 content-encoding），绝不改写
      if (body === null) {
        headers['content-length'] = buf.length;
        res.writeHead(proxyRes.statusCode || 200, headers);
        res.end(buf);
        return;
      }
      const rewrite = buildOriginRewriters(target, req.headers.host);
      let html = rewrite(body);
      if (BUST_CDN_CACHE) html = bustCacheUrls(html, sessionTag(req));
      const out = Buffer.from(injectExitButton(html, target), 'utf8');
      delete headers['content-encoding'];
      headers['content-length'] = out.length;
      res.writeHead(proxyRes.statusCode || 200, headers);
      res.end(out);
    });
    proxyRes.on('error', () => { try { res.end(); } catch {} });
    return;
  }

  if (isTextLike && req.method !== 'HEAD') {
    const rewrite = buildOriginRewriters(target, req.headers.host);
    const chunks = [];
    proxyRes.on('data', (c) => chunks.push(c));
    proxyRes.on('end', () => {
      const buf = Buffer.concat(chunks);
      const decode = makeDecoder(enc);
      let out = null;
      if (decode) {
        try {
          out = Buffer.from(rewrite(decode(buf).toString('utf8')), 'utf8');
          delete headers['content-encoding'];
        } catch { out = null; }
      }
      // 解压失败 / 未知编码：原样透传，保持 content-encoding 不变
      if (out === null) out = buf;
      headers['content-length'] = out.length;
      res.writeHead(proxyRes.statusCode || 200, headers);
      res.end(out);
    });
    proxyRes.on('error', () => { try { res.end(); } catch {} });
    return;
  }

  res.writeHead(proxyRes.statusCode || 200, headers);
  proxyRes.pipe(res);
}

/* ------------------------------------------------------------------ *
 * 通用子路径：静态资源 404 自动探测
 * ------------------------------------------------------------------ */
function bufferToRes(statusCode, headers, buf) {
  const s = new Readable({
    read() { this.push(buf); this.push(null); },
  });
  s.statusCode = statusCode;
  s.headers = headers;
  return s;
}

// 直接用 node:http(s) 发一次「干净」的 GET 去目标探测路径。
// 不经过网关那套请求头加工，因此也能绕开设备对 Origin / Sec-Fetch 的校验。
// opts.follow: 跟随重定向次数（默认 0，探测入口页时用 3）。
// opts.protocol: 覆盖协议（用于 http/https 交叉探测）。
// opts.headers: 额外/覆盖的请求头。
function rawFetch(target, path, req, opts = {}) {
  const follow = Number.isInteger(opts.follow) ? opts.follow : 0;
  const proto = opts.protocol || target.protocol;

  const once = (p, left) => new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const mod = proto === 'https' ? https : http;
    const base = {
      host: target.host,
      port: target.port,
      path: p,
      method: 'GET',
      rejectUnauthorized: false,
      headers: {
        host: `${target.host}${target.port ? ':' + target.port : ''}`,
        'accept-encoding': 'identity',
        accept: (req && req.headers && req.headers.accept) || '*/*',
        'user-agent': (req && req.headers && req.headers['user-agent']) || 'simpleproxy-probe',
        ...(opts.headers || {}),
      },
    };
    const r = mod.request(base, (up) => {
      const code = up.statusCode || 200;
      const loc = up.headers['location'];
      // 3xx 且有 Location：跟随（仅同源，避免探到外站）
      if (loc && code >= 300 && code < 400 && left > 0) {
        up.resume();
        let np = null;
        try {
          const u = new URL(loc, `${proto}://${target.host}:${target.port}`);
          if (u.hostname === target.host) np = u.pathname + u.search;
        } catch {}
        if (np) return once(np, left - 1).then(done);
        return done({ statusCode: code, headers: up.headers, body: Buffer.alloc(0), path: p, location: loc });
      }
      const chunks = [];
      up.on('data', (c) => chunks.push(c));
      up.on('end', () => {
        const body = Buffer.concat(chunks);
        done({
          statusCode: code,
          headers: up.headers,
          body,
          path: p,
          location: loc,
          stream: bufferToRes(code, up.headers, body),
        });
      });
      up.on('error', () => done(null));
    });
    r.setTimeout(PROBE_TIMEOUT_MS, () => { r.destroy(); done(null); });
    r.on('error', () => done(null));
    r.end();
  });

  return once(path, follow);
}

// 按 content-encoding 解码响应体（用于需要读文本的场景；解不开就原样返回）
function decodeBody(r) {
  const enc = String((r.headers && r.headers['content-encoding']) || '').toLowerCase();
  const decode = makeDecoder(enc);
  if (!decode) return r.body;
  try { return decode(r.body); } catch { return r.body; }
}

/* ---- 自请求：让 diag 能验证「经过网关代理」这条路径本身 ----
 * 之前 diag 只直连上游，因此永远看不到代理层的问题。这里让网关请求自己，
 * 完整走一遍「浏览器 → 网关 → 上游 → 改写 → 回写」，把真实链路暴露出来。
 */
function selfRequest(path, req, ae) {
  return new Promise((resolve) => {
    const r = http.request({
      host: '127.0.0.1', port: PORT, path, method: 'GET',
      headers: {
        cookie: String(req.headers.cookie || ''),
        accept: '*/*',
        'accept-encoding': ae || 'gzip, deflate, br, zstd',
        'user-agent': 'simpleproxy-diag',
      },
    }, (up) => {
      const chunks = [];
      up.on('data', (c) => chunks.push(c));
      up.on('end', () => resolve({ statusCode: up.statusCode, headers: up.headers, body: Buffer.concat(chunks) }));
      up.on('error', () => resolve(null));
    });
    r.setTimeout(8000, () => { r.destroy(); resolve(null); });
    r.on('error', () => resolve(null));
    r.end();
  });
}

// 判断响应体是否「像被当成文本输出的二进制垃圾」（压缩字节被当 utf8 回写）。
// 只对**文本类**资源有意义：图片 / 字体 / ico 等本来就是二进制，
// 不能用这个指标判定异常（否则 favicon 会被误报）。
function isTextualType(ct) {
  return /(javascript|ecmascript|text\/|application\/json|\+json|xml|svg)/i.test(String(ct || ''));
}
function sniffBinary(buf, contentType) {
  const head = buf.slice(0, 120).toString('latin1');
  if (!isTextualType(contentType)) return { binary: false, textual: false, head };
  const n = Math.min(buf.length, 256);
  if (!n) return { binary: false, textual: true, head };
  let non = 0;
  for (let i = 0; i < n; i++) {
    const b = buf[i];
    if (b !== 9 && b !== 10 && b !== 13 && (b < 32 || b > 126)) non++;
  }
  return { binary: non / n > 0.03, textual: true, nonPrintable: non, head };
}

// 从目标根页面推断它真实挂在哪个前缀下（跳转 Location / <base> / 资源 src）
async function rootPrefixes(target) {
  // follow: 3 —— 入口常是 302 → /login，不跟随就拿不到真正引用资源的那个页面
  const r = await rawFetch(target, '/', null, { follow: 3 });
  if (!r) return [];
  const out = [];
  const add = (seg) => {
    if (!seg || SKIP_PREFIX_RE.test(String(seg))) return;
    const p = '/' + String(seg).replace(/^\/+|\/+$/g, '');
    if (p !== '/' && !out.includes(p)) out.push(p);
  };
  if (r.location) {
    try { add(new URL(r.location, targetOrigin(target)).pathname.split('/').filter(Boolean)[0]); } catch {}
  }
  const text = decodeBody(r).toString('utf8');
  const bm = /<base[^>]+href\s*=\s*["']\/?([^"'\/?#]+)\//i.exec(text);
  if (bm) add(bm[1]);
  const re = /(?:src|href)\s*=\s*["']\/?([^"'\/?#]+)\//gi;
  let m;
  while ((m = re.exec(text)) && out.length < 8) add(m[1]);
  return out;
}

async function buildPrefixCandidates(target, req, path) {
  const out = [];
  const add = (seg) => {
    if (!seg || SKIP_PREFIX_RE.test(String(seg))) return;
    const p = '/' + String(seg).replace(/^\/+|\/+$/g, '');
    if (p === '/' || path.startsWith(p + '/') || out.includes(p)) return;
    out.push(p);
  };
  // ① 当前页面所在子路径（Referer=/wangzhang/login -> /wangzhang）
  try {
    const ref = new URL(String(req.headers.referer || ''));
    add(ref.pathname.split('/').filter(Boolean)[0]);
  } catch {}
  // ② 目标根页面自己暴露的前缀
  for (const p of await rootPrefixes(target)) add(p);
  // ③ 常见部署前缀
  DEFAULT_PREFIXES.forEach(add);
  return out.slice(0, 8);
}

async function probeSubPath(target, req) {
  const { path, query } = splitUrl(req.originalUrl || '/');
  const kept = query.replace(/^\?/, '').split('&').filter(p => p && !p.startsWith(BUST_PARAM + '='));
  const suffix = kept.length ? '?' + kept.join('&') : '';
  const candidates = await buildPrefixCandidates(target, req, path);
  const accepts = ['gzip, deflate, br', 'identity'];
  const attempts = [];
  // 前缀候选 × accept-encoding：既找路径前缀，也验证「是否只是压缩协商问题」
  for (const prefix of candidates) {
    for (const ae of accepts) {
      attempts.push({ prefix, full: joinBase(prefix, path) + suffix, ae });
    }
  }
  if (attempts.length === 0) return null;
  const results = await Promise.all(attempts.map(async (a) => {
    const r = await rawFetch(target, a.full, req, { headers: { 'accept-encoding': a.ae } });
    if (!r || r.statusCode < 200 || r.statusCode >= 300) return null;
    // SPA 的 catch-all 常对任意路径回 200 + text/html，那种不是真资源
    if (/text\/html/i.test(String(r.headers['content-type'] || ''))) return null;
    r.prefix = a.prefix;
    r.acceptEncoding = a.ae;
    return r;
  }));
  const hit = results.find(Boolean) || null;
  // 若同一 URL 只有带 gzip 才 200，说明上游依赖压缩协商：记下偏好压缩
  if (hit) target.preferGzip = /gzip|br|deflate/i.test(hit.acceptEncoding);
  return hit;
}

async function handleStaticFallback(proxyRes, req, res, target, headers, status) {
  const chunks = [];
  proxyRes.on('data', (c) => chunks.push(c));
  const collected = new Promise((resolve) => {
    proxyRes.on('end', resolve);
    proxyRes.on('error', resolve);
  });

  let hit = null;
  try { hit = await probeSubPath(target, req); }
  catch (e) { if (PROXY_LOG) console.log('[proxy] subpath probe error:', e.message); }
  await collected;

  if (hit) {
    // 只记住「静态资源」前缀，不影响 /login、/api/... 等页面与接口路径
    target.assetPrefix = hit.prefix;
    req.__gate_out = hit.path;
    if (PROXY_LOG) console.log(`[proxy] subpath discovered ${hit.prefix}: ${req.originalUrl} -> ${hit.path}`);
    return handleProxyRes(hit.stream, req, res, target);
  }

  const buf = Buffer.concat(chunks);
  delete headers['content-length'];
  headers['content-length'] = buf.length;
  res.writeHead(status, headers);
  res.end(buf);
}

function rewriteLocation(loc, target) {
  try {
    if (/^https?:\/\//i.test(loc)) {
      const u = new URL(loc);
      const sameHost = u.hostname === target.host && (u.port ? parseInt(u.port, 10) : u.protocol === 'https:' ? 443 : 80) === target.port;
      if (sameHost) return stripBase(u.pathname, target.base) + u.search + u.hash;
      return loc; // 指向别处则不动
    }
    // 目标站内的根相对跳转：把 base 去掉，浏览器才不会把前缀越叠越长
    if (/^\//.test(loc)) {
      const { path, query } = splitUrl(loc);
      return stripBase(path, target.base) + query;
    }
    return loc;
  } catch {
    return loc;
  }
}

function cookiePrefix(t) {
  const h = crypto.createHash('md5').update(t.key).digest('hex').slice(0, 8);
  return `t_${h}_`;
}

/* ------------------------------------------------------------------ *
 * 代理调度
 * ------------------------------------------------------------------ */
function doProxy(req, res, target) {
  stripBustParam(req);      // 去掉缓存破坏参数后再转发，目标无感
  // 透明模式：不改写响应、不注入内容（仅追加退出按钮）。
  // 但用户显式填写的路径前缀（base）必须保留：否则 /lucky 这类部署会被丢掉，
  // 请求落到上游根路径，表现为「打开的是另一个页面 / 目标服务器默认页」。
  if (target.mode === 'transparent') {
    req.__gate_transparent = true;
    if (target.base) {
      const { path, query } = splitUrl(req.url);
      // 已经带该前缀的不重复叠加（浏览器可能直接请求 /lucky/xxx）
      req.url = (path === target.base.replace(/\/$/, '') || path.startsWith(target.base)
        ? path
        : joinBase(target.base, path)) + query;
    }
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
    return;
  }
  req.__gate_out = mapOutgoingUrl(req, target);   // 通用子路径：补上 base / 探测到的前缀
  prepareProxyReqHook(req, target);
  proxy.web(req, res, {
    target: targetOrigin(target),
    changeOrigin: true,
    secure: false,
    selfHandleResponse: true,
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
proxy.on('proxyRes', (proxyRes, req, res) => {
  if (req.__pf_port || req.__gate_transparent) return;   // 直通类：交给下方处理器
  handleProxyRes(proxyRes, req, res, req.__gate_target);
});

/* ------------------------------------------------------------------ *
 * WebSocket 升级处理
 * ------------------------------------------------------------------ */
function handleUpgrade(req, socket, head) {
  const s = getSession(req);
  if (!s || !s.target) return socket.destroy();
  stripBustParam(req);
  // 透明模式：路径不补前缀，原样转发
  if (s.target.mode !== 'transparent') req.__gate_out = mapOutgoingUrl(req, s.target);
  req.__gate_target = s.target;
  proxy.ws(req, socket, head, {
    target: targetOrigin(s.target),
    changeOrigin: true,
    secure: false,
    headers: { host: `${s.target.host}${s.target.port ? ':' + s.target.port : ''}` },
  });
}

/* ------------------------------------------------------------------ *
 * 端口转发引擎
 *
 * 为每个「已登录且选择了目标」的会话分配一个宿主机端口，该端口上收到的
 * 所有 HTTP/WebSocket 流量**原样**转发给目标，不做任何 HTML/JS 改写。
 * 这样目标服务始终认为自己在根路径，绝对 URL、动态 import、worker、
 * __vite__ 预加载等全部天然正确 —— 彻底绕开「改写漏改」这类问题。
 *
 * 端口按需分配（懒创建），会话退出或超时后回收。
 * ------------------------------------------------------------------ */
const pfServers = new Map();   // port -> { server, sid, target }

function pfGetInfo() {
  // 返回可对外展示的宿主机地址（尽力而为，失败则回退问号）
  return PF_HOST;
}

// 为一个会话启动端口转发监听（幂等）
async function pfEnsure(session) {
  if (!PORT_FORWARD || !session || !session.target) return null;
  // 已分配且目标未变：直接复用
  if (session.pfPort && pfServers.has(session.pfPort)) {
    const cur = pfServers.get(session.pfPort);
    if (cur.target && cur.target.key === session.target.key) return session.pfPort;
    pfRelease(session);
  }
  const taken = new Set(pfServers.keys());
  for (let p = PF_RANGE_START; p <= PF_RANGE_END; p++) {
    if (taken.has(p) || p === PORT) continue;
    const ok = await pfBind(p, session);
    if (ok) return p;
  }
  return null;
}

// 尝试在 port 上监听；成功返回 true，端口被占用返回 false
function pfBind(port, session) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => pfHandleHttp(req, res, port));
    srv.on('upgrade', (req, socket, head) => pfHandleUpgrade(req, socket, head, port));
    srv.on('clientError', (err, socket) => { try { socket.destroy(); } catch {} });

    const onError = () => {
      srv.removeListener('listening', onListening);
      try { srv.close(); } catch {}
      resolve(false);
    };
    const onListening = () => {
      srv.removeListener('error', onError);
      const rec = { server: srv, sid: session.sid, target: session.target, key: session.target.key };
      pfServers.set(port, rec);
      session.pfPort = port;
      if (PROXY_LOG) console.log(`[portfwd] session ${String(session.sid).slice(0, 8)} -> :${port} => ${targetOrigin(session.target)}`);
      resolve(true);
    };
    srv.once('error', onError);
    srv.once('listening', onListening);
    try { srv.listen(port, '0.0.0.0'); } catch { onError(); }
  });
}

function pfRelease(session) {
  if (!session || !session.pfPort) return;
  const rec = pfServers.get(session.pfPort);
  if (rec && rec.sid === session.sid) {
    pfServers.delete(session.pfPort);
    try { rec.server.close(); } catch {}
    if (PROXY_LOG) console.log(`[portfwd] released :${session.pfPort}`);
  }
  session.pfPort = null;
}

// 端口上的会话解析：必须带合法 sid 且已选定目标
function pfResolve(req) {
  const sid = readSid(req);
  const s = sid && sessions.get(sid);
  if (s) s.lastSeen = Date.now();
  return s;
}

function pfDeny(res, reason) {
  res.writeHead(403, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(`<!doctype html><html lang="zh"><meta charset="utf-8"><title>需要登录</title>
<body style="font-family:system-ui;padding:40px;line-height:1.7;color:#0f172a;background:#f8fafc">
<h2 style="margin:0 0 10px">未授权访问该转发端口</h2>
<p style="color:#475569">${reason}</p>
<p>请先在网关登录页完成 Token 校验并选择目标服务，再从本端口访问。</p>
</body></html>`);
}

function pfHandleHttp(req, res, port) {
  const s = pfResolve(req);
  if (!s) return pfDeny(res, '没有有效的网关会话（Cookie 缺失或已过期）。');
  if (!s.target) return pfDeny(res, '当前会话还没有选择目标服务。');
  const rec = pfServers.get(port);
  if (rec) rec.target = s.target;         // 目标切换后即时生效

  // 原样转发：不改写、不注入、不剥离任何东西
  req.url = req.url || '/';
  req.__pf_port = port;                   // 标记：响应侧直通，不做任何改写
  const t = s.target;
  proxy.web(req, res, {
    target: targetOrigin(t),
    changeOrigin: true,
    secure: false,
    selfHandleResponse: true,
    xfwd: false,
    headers: { host: `${t.host}${t.port ? ':' + t.port : ''}` },
  });
}

function pfHandleUpgrade(req, socket, head, port) {
  const s = pfResolve(req);
  if (!s || !s.target) { try { socket.destroy(); } catch {} return; }
  const t = s.target;
  proxy.ws(req, socket, head, {
    target: targetOrigin(t),
    changeOrigin: true,
    secure: false,
    headers: { host: `${t.host}${t.port ? ':' + t.port : ''}` },
  });
}

// 端口转发下的响应：直通，不做 Cookie 改名 / Location 重写 / HTML 注入
/* ---- 直通（端口转发 / 透明代理）：原样回传，不做任何改写 ----
 * 这里是「零改写」的关键：状态码、全部响应头、Set-Cookie、Location、
 * Content-Encoding、分块传输…… 一律原封不动交给浏览器。
 * 唯一例外：透明模式下为了能「退出」，会在 HTML 的 </body> 前追加一个
 * 悬浮按钮（只追加、不改写任何既有内容），可通过 INJECT_EXIT_BUTTON=false 关闭。*/
proxy.on('proxyRes', (proxyRes, req, res) => {
  if (!req.__pf_port && !req.__gate_transparent) return;  // 普通路径代理交给原逻辑
  const tag = req.__pf_port ? 'portfwd' : 'transparent';
  if (PROXY_LOG) {
    console.log(`[${tag}] ${req.method} ${req.originalUrl} => ${proxyRes.statusCode} (${proxyRes.headers['content-type'] || '-'})`);
  }
  // 透明模式 + 注入开关：对**文本类**响应追加退出按钮，其余原样。
  // 注意：不仅要覆盖 text/html，也要覆盖上游返回的「纯文本错误页」
  // （例如 Lucky 的默认页 "Are you ok?"、Nginx 的 404 文本）。
  // 否则一旦目标报错，用户既看不到内容、也没有退出按钮，彻底卡住。
  if (req.__gate_transparent && INJECT_EXIT && !req.__pf_port) {
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
  // 只覆盖缓存头，其它头（Set-Cookie / Location / Content-Encoding）保持原样。
  const headers = { ...proxyRes.headers };
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

// 把一个「非 HTML」的文本响应包成最小合法 HTML，以便挂载退出按钮。
// 仅用于 text/plain、无 content-type 等纯文本场景；HTML 原样传入。
function wrapPlainTextAsHtml(text) {
  const esc = String(text)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return '<!doctype html><html lang="zh"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>代理响应</title></head>' +
    '<body style="margin:0;padding:28px;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;' +
    'color:#0f172a;background:#f8fafc;line-height:1.7">' +
    '<pre style="white-space:pre-wrap;word-break:break-word;margin:0">' + esc + '</pre>' +
    '</body></html>';
}

// 透明模式专用：只注入退出按钮，绝不改写其它内容
function injectOnlyHtml(proxyRes, req, res, target) {
  const headers = { ...proxyRes.headers };
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
    let body = null;
    if (decode) { try { body = decode(buf).toString('utf8'); } catch { body = null; } }
    // 解不开（未知编码）→ 原样透传，宁可不注入也不破坏
    if (body === null) {
      headers['content-length'] = buf.length;
      res.writeHead(proxyRes.statusCode || 200, headers);
      res.end(buf);
      return;
    }
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

app.use(BASE + '/static', express.static(path.join(__dirname, 'public'), { index: false }));

/* --- Token 校验 --- */
app.post(BASE + '/api/auth', (req, res) => {
  const s = getSession(req, res, true);
  const token = String((req.body && req.body.token) || '');
  const sha = (v) => crypto.createHash('sha256').update(v).digest();
  const ok = crypto.timingSafeEqual(sha(token), sha(TOKEN));
  if (!ok) return res.status(401).json({ ok: false, error: 'Token 不正确' });
  s.authed = true;
  res.json({ ok: true });
});

/* --- 当前状态 --- */
app.get(BASE + '/api/me', (req, res) => {
  const s = getSession(req);
  res.json({
    ok: true,
    build: BUILD_ID,
    portForward: PORT_FORWARD,
    transparent: TRANSPARENT,
    pfHost: PF_HOST || null,
    authed: !!(s && s.authed),
    hasTarget: !!(s && s.target),
    pfPort: (s && s.pfPort) || null,
    mode: (s && s.target && s.target.mode) || null,
    target: s && s.target ? { protocol: s.target.protocol, host: s.target.host, port: s.target.port, base: s.target.base } : null,
  });
});

/* --- 登录目标 --- */
app.post(BASE + '/api/login', async (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });

  const target = normalizeTarget((req.body && req.body.target) || '');
  if (!target) return res.status(400).json({ ok: false, error: '地址格式不正确，示例：192.168.1.10:8080' });

  // 代理模式：transparent（nginx 风格、零改写，默认）/ path（路径代理 + 改写）
  const reqMode = String((req.body && req.body.mode) || 'transparent');
  target.mode = reqMode === 'path' ? 'path' : 'transparent';

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

  // 端口转发模式：为会话分配专属端口（可失败，失败则回退路径代理）
  let pfPort = null;
  if (PORT_FORWARD && req.body && req.body.mode === 'port') {
    try { pfPort = await pfEnsure(s); } catch (e) { if (PROXY_LOG) console.log('[portfwd] alloc failed:', e.message); }
    if (!pfPort) target.mode = 'path';   // 分配失败则回退
  } else {
    pfRelease(s);
  }

  res.json({
    ok: true,
    target: { protocol: target.protocol, host: target.host, port: target.port, base: target.base },
    mode: pfPort ? 'port' : target.mode,   // port | transparent | path
    pfPort,
    pfHost: pfPort ? PF_HOST : null,
  });
});

/* --- 退出当前代理（回登录页） --- */
app.post(BASE + '/api/logout', (req, res) => {
  const s = getSession(req);
  if (s) { pfRelease(s); s.target = null; }
  res.json({ ok: true });
});

/* --- 完全退出（清 Token 会话） --- */
app.post(BASE + '/api/exit', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies[COOKIE_NAME];
  const s = sid && sessions.get(sid);
  if (s) pfRelease(s);
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
  res.json({ ok: true });
});

/* --- 诊断：把上游真相一次打出来（需已通过 Token） ---
 * GET /_gate/api/diag[?target=1.2.3.4:443]
 * 返回：入口页真实落点、入口页引用的资源、每个资源在各前缀/协议下的真实状态。
 * 用于定位「上游 404」到底是路径前缀问题、协议问题，还是资源本身不存在。
 */
app.get(BASE + '/api/diag', async (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });
  const t = (req.query.target && normalizeTarget(req.query.target)) || s.target;
  if (!t) return res.status(400).json({ ok: false, error: '未设置目标' });

  const refs = new Set();
  const { path: cur } = splitUrl(String(req.query.path || '/login'));
  const entryPaths = ['/', cur, '/login', '/index.html'];
  const seenEntry = [];

  for (const p of [...new Set(entryPaths)]) {
    const r = await rawFetch(t, p, null, { follow: 3 });
    if (!r) { seenEntry.push({ path: p, error: 'unreachable' }); continue; }
    seenEntry.push({
      path: p, landedOn: r.path, status: r.statusCode,
      server: r.headers.server || null,
      contentType: r.headers['content-type'] || null,
      location: r.location || null,
      bytes: r.body.length,
    });
    if (/text\/html/i.test(String(r.headers['content-type'] || ''))) {
      const html = decodeBody(r).toString('utf8');
      const re = /(?:src|href)\s*=\s*["']([^"']+)["']/gi;
      let m;
      while ((m = re.exec(html))) {
        const u = m[1].trim();
        if (!u || /^(?:data:|javascript:|mailto:|blob:|#)/i.test(u)) continue;
        if (/^https?:\/\//i.test(u)) { try { const x = new URL(u); refs.add(x.pathname + x.search); } catch {} }
        else if (u.startsWith('/')) refs.add(u);
      }
    }
  }

  const rel = [...refs].slice(0, 6);
  const prefixes = ['', ...DEFAULT_PREFIXES.slice(0, 3)];
  const protos = t.protocol === 'https' ? ['https', 'http'] : ['http', 'https'];
  const probes = [];
  outer:
  for (const rp of rel) {
    const { path: rpPath, query: rpQuery } = splitUrl(rp);
    const segs = rpPath.split('/').filter(Boolean);
    const variants = new Set([rpPath]);
    if (segs.length > 1 && ['static', 'assets'].includes(segs[0])) variants.add('/' + segs.slice(1).join('/'));
    for (const v of variants) {
      for (const pf of prefixes) {
        for (const proto of protos) {
          // 第三项刻意带 zstd：用于识别「上游在现代浏览器下会回 zstd」的情况
          for (const ae of ['gzip, deflate, br', 'identity', 'gzip, deflate, br, zstd']) {
            const full = joinBase(pf, v) + rpQuery;
            const key = proto + ' ' + full + ' [' + ae + ']';
            if (probes.some((x) => x.key === key)) continue;
            const r = await rawFetch(t, full, null, { protocol: proto, headers: { 'accept-encoding': ae } });
            probes.push({
              key,
              proto, url: full, acceptEncoding: ae,
              status: r ? r.statusCode : null,
              server: r ? (r.headers.server || null) : null,
              contentType: r ? (r.headers['content-type'] || null) : null,
              contentEncoding: r ? (r.headers['content-encoding'] || null) : null,
              bytes: r ? r.body.length : null,
            });
            if (probes.length >= 48) break outer;
          }
        }
      }
    }
  }

  // ---- 关键：让 diag 请求「网关自己」，验证真实代理链路 ----
  // 之前的 diag 只直连上游，看不到代理层；这里完整走一遍代理，
  // 直接对比「直连上游拿到的资源」与「经网关拿到的资源」是否一致。
  const okProbe = (p) => p.status >= 200 && p.status < 300 && !/text\/html/i.test(String(p.contentType || ''));
  const viaProxy = [];
  for (const rp of rel.slice(0, 4)) {
    const resp = await selfRequest(rp, req, 'gzip, deflate, br, zstd');
    if (!resp) { viaProxy.push({ url: rp, error: 'gateway unreachable' }); continue; }
    const enc = String(resp.headers['content-encoding'] || '').toLowerCase();
    const ct = resp.headers['content-type'] || null;
    const sniff = sniffBinary(resp.body, ct);
    viaProxy.push({
      url: rp,
      status: resp.statusCode,
      contentType: ct,
      contentEncoding: enc || null,
      bytes: resp.body.length,
      bodyLooksBinary: sniff.binary,
      head: sniff.head.slice(0, 80),
    });
  }

  // 找「直连上游 200、但经网关仍失败或（文本资源）变成二进制垃圾」的项 = 代理层 bug
  const proxyBroken = [];
  for (const vp of viaProxy) {
    if (vp.error || !vp.url) continue;
    if (!isTextualType(vp.contentType)) continue;   // 图片/字体等二进制资源跳过
    const direct = probes.find((p) => p.url === vp.url && okProbe(p));
    const proxiedOk = vp.status >= 200 && vp.status < 300;
    if (proxiedOk && !vp.bodyLooksBinary) continue;              // 代理正常
    if (direct) proxyBroken.push({ ...vp, directStatus: direct.status, directBytes: direct.bytes });
    else proxyBroken.push(vp);
  }

  // ---- 结论判定：优先级 代理层 > 压缩协商 > 前缀 > 协议 > 确实不存在 ----
  const firstRef = rel[0] || null;
  let verdict = 'unknown';
  let conclusion = '';
  let fix = null;

  if (!rel.length) {
    verdict = 'no-references';
    conclusion = '入口页没有解析到任何站内资源引用，无法进一步判定。';
  } else if (proxyBroken.length) {
    verdict = 'proxy-path';
    const one = proxyBroken[0];
    conclusion = `上游本身可以取到该资源，但「经过网关」后异常：`
      + `直连 ${one.directStatus ?? '-'}，经网关 ${one.status ?? '-'}`
      + `${one.bodyLooksBinary ? '，且响应体是二进制垃圾（编码未被正确处理）' : ''}。`
      + `说明问题在网关的代理/改写环节，而不是路径或目标服务。`;
    fix = '这是网关自身缺陷，请把完整 JSON 反馈给开发者；临时可设 BUST_CDN_CACHE=false 或 INJECT_EXIT_BUTTON=false 定位是改写还是注入引起。';
  } else {
    // ① 原样路径（无前缀）在各编码下的结果
    const samePath = probes.filter((p) => firstRef && p.url === firstRef);
    const plain = samePath.find((p) => /identity/i.test(p.acceptEncoding));
    const compressible = samePath.filter((p) => /gzip|br|deflate/i.test(p.acceptEncoding));
    const gz = compressible.find((p) => /gzip/i.test(p.acceptEncoding));
    const zst = samePath.find((p) => /zstd/i.test(p.acceptEncoding));
    const prefixHit = probes.find((p) => okProbe(p) && p.url !== firstRef);
    const best = compressible.find(okProbe);

    if (okProbe(gz) && plain && !okProbe(plain)) {
      verdict = 'accept-encoding';
      conclusion = `路径与协议都正确，唯一变量是 Accept-Encoding：同一 URL 带 gzip 返回 ${gz.status}，`
        + `不带（identity）返回 ${plain.status}。目标只提供预压缩静态资源，必须让客户端声明 gzip/br。`;
      fix = zst && zst.contentEncoding === 'zstd'
        ? '目标还会对 zstd 优先响应；网关已剥离 zstd 只请求 gzip/deflate/br，无需修改登录地址。'
        : '网关已自动处理（透传可解码的 Accept-Encoding），无需修改登录地址。拉取最新镜像即可。';
    } else if (okProbe(gz) || okProbe(plain) || best) {
      verdict = 'ok';
      conclusion = '原样路径即可取到资源，无需前缀。若浏览器仍 404，检查是否有其他中间层拦截。';
    } else if (prefixHit) {
      verdict = 'prefix';
      const seg = '/' + prefixHit.url.split('/').filter(Boolean).slice(0, 1).join('/') + '/';
      conclusion = `原样路径取不到，但 ${prefixHit.proto} ${prefixHit.url} [${prefixHit.acceptEncoding}] 返回 ${prefixHit.status}，差一个部署前缀。`;
      fix = `把登录地址改成带路径的形式，例如 <IP>:<端口>${seg}`;
    } else {
      const allOk = probes.filter(okProbe);
      verdict = 'not-found';
      conclusion = '所有前缀 / 协议 / 压缩组合都取不到这些资源，说明该地址下确实没有这些文件（可能换过端口、或需要先登录鉴权后再访问）。';
      fix = `请核对浏览器直连该服务时的完整地址（协议 + IP + 端口）；若曾登录过，先直连登录一次再回到网关。`;
    }
  }

  res.json({
    ok: true,
    target: { protocol: t.protocol, host: t.host, port: t.port, base: t.base },
    entry: seenEntry,
    references: rel,
    verdict,
    conclusion,
    fix,
    viaProxy,
    proxyBroken,
    winner: probes.find(okProbe) || null,
    probes,
  });
});

/* --- 站点列表 --- */
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
  if (s && s.target) return doProxy(req, res, s.target);
  if (req.method === 'GET' && (req.path === '/' || req.path === '/index.html')) {
    // cacheControl:false 避免 Express 覆盖上面设置的 no-store
    return res.sendFile(indexPath, { cacheControl: false });
  }
  res.status(404).send('Not found. 请先通过网关登录。');
});

/* ------------------------------------------------------------------ *
 * CDN 缓存破坏
 * ------------------------------------------------------------------ */
// 同一会话内稳定、不同会话不同的短标识（不含真实 sid）
function sessionTag(req) {
  const m = /(?:^|;\s*)_gate_sid=([^;]+)/.exec(req.headers.cookie || '');
  // 同时混入 BUILD_ID：升级镜像后 tag 必然改变，旧的坏缓存立即失效
  return crypto.createHash('md5').update((m ? m[1] : 'anon') + '|' + BUILD_ID).digest('hex').slice(0, 8);
}

// 只改写「站内」URL（相对路径 / 以 / 开头的绝对路径），外链与伪协议保持原样
function bustCacheUrls(html, tag) {
  return html.replace(/\b(src|href|action|poster)\s*=\s*(["'])([^"']+)\2/gi, (all, attr, q, url) => {
    const u = url.trim();
    if (!u || /^(?:data:|javascript:|mailto:|blob:|#)/i.test(u)) return all;
    if (/^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(u)) return all;   // 外链 / 协议相对
    if (u.includes(BUST_PARAM + '=')) return all;
    const sep = u.includes('?') ? '&' : '?';
    return `${attr}=${q}${u}${sep}${BUST_PARAM}=${tag}${q}`;
  });
}

// 转发给目标前剥离该参数，目标服务看到的 URL 与原来完全一致
function stripBustParam(req) {
  if (!BUST_CDN_CACHE || !req.url) return;
  const i = req.url.indexOf('?');
  if (i < 0) return;
  const kept = req.url.slice(i + 1).split('&').filter(p => !p.startsWith(BUST_PARAM + '='));
  req.url = req.url.slice(0, i) + (kept.length ? '?' + kept.join('&') : '');
}

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
  const script =
    '<script data-gate-exit="1">(function(){' +
    'if(window.__gate_exit_installed__)return;window.__gate_exit_installed__=true;' +
    'var LABEL=' + j(modeTag + ' ' + label) + ';' +
    'function build(){' +
    'var d=document.createElement("div");d.id="__gate_exit__";' +
    'd.setAttribute("style","position:fixed;right:18px;bottom:18px;z-index:2147483647;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;");' +
    'd.innerHTML=' + j('<button id="__gate_exit_btn__" style="display:flex;align-items:center;gap:8px;padding:9px 14px;border:0;border-radius:999px;background:#111827;color:#fff;font-size:13px;cursor:pointer;box-shadow:0 6px 20px rgba(0,0,0,.28);opacity:.92;"><span style="width:7px;height:7px;border-radius:50%;background:#22c55e;display:inline-block;"></span><span></span><span style="opacity:.5">|</span><span style="text-decoration:underline">退出</span></button>') + ';' +
    'var b=d.querySelector("button");var t=b.querySelectorAll("span")[1];if(t)t.textContent=LABEL;' +
    'b.addEventListener("click",function(){if(!confirm("退出代理并返回登录页？"))return;' +
    'fetch("/_gate/api/logout",{method:"POST"}).then(function(){location.href="/"}).catch(function(){location.href="/"});});' +
    'return d;}' +
    'function mount(){' +
    'if(!document.body){return setTimeout(mount,30);}' +
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

/* ------------------------------------------------------------------ *
 * 响应体 origin 重写
 *
 * 很多 Web 应用（尤其 SPA / 前后端分离）会把「自身 origin」硬编码进
 * HTML 或 JS，例如：
 *   <script src="http://192.168.1.10:19980/static/app.js">
 *   const API = "http://192.168.1.10:19980/api";
 * 浏览器会直连这个内网地址（绕过网关），导致资源 404 / 页面空白。
 * 这里把所有指向目标 origin 的引用改写成相对路径，强制走网关。
 * ------------------------------------------------------------------ */
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildOriginRewriters(target, clientHost) {
  const host = target.host;
  const port = target.port;

  // 需要覆盖的 authority 写法
  const authorities = [];
  if (port) authorities.push(host + ':' + port);
  authorities.push(host);
  // 目标写的是本机/容器别名时，同端口下的 127.0.0.1 / localhost 也一并覆盖
  if (port && /^(127\.0\.0\.1|localhost|0\.0\.0\.0|host\.docker\.internal)$/i.test(host)) {
    ['127.0.0.1', 'localhost'].forEach((h) => {
      const a = h + ':' + port;
      if (!authorities.includes(a)) authorities.push(a);
    });
  }

  const alt = authorities.map(escapeRegExp).join('|');
  // 一次匹配：scheme://authority 或 协议相对 //authority
  const re = new RegExp(
    '(https?|wss?):\\/\\/(' + alt + ')(?=[/\\\\\'"\\s)>]|$)|\\/\\/(' + alt + ')(?=[/\\\\\'"\\s)>]|$)',
    'gi'
  );

  const gwHost = clientHost || '';

  return (text) =>
    text.replace(re, (m, scheme) => {
      // http/https → 丢掉 origin，变成相对路径，强制走网关
      if (/^https?$/i.test(scheme)) return '';
      // ws/wss → 指向网关自身（浏览器按当前页协议建立连接）
      if (/^wss?$/i.test(scheme)) return gwHost ? scheme + '://' + gwHost : '';
      // 协议相对 //authority → 指向网关自身
      return gwHost ? '//' + gwHost : '';
    });
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
