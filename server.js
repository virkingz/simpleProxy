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
    s = { authed: false, target: null, createdAt: Date.now(), lastSeen: Date.now() };
    sessions.set(sid, s);
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200`);
  }
  if (s) s.lastSeen = Date.now();
  return s || null;
}

setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (now - s.lastSeen > SESSION_TTL_MS) sessions.delete(sid);
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

function prepareProxyReq(proxyReq, req, target) {
  const prefix = cookiePrefix(target);
  const cookies = forwardCookieHeader(req.headers.cookie, prefix);
  if (cookies) proxyReq.setHeader('Cookie', cookies);
  else proxyReq.removeHeader('Cookie');

  // 需要「解压后注入退出按钮」的只有 HTML；JS/CSS 即使压缩也能解码后重写。
  // 因此只对页面请求强制 identity —— 很多嵌入式设备/精简 Nginx 只提供
  // .js.gz / .css.br 预压缩文件，客户端不声明 gzip/br 时直接回 404（len=146）。
  // 静态资源必须原样透传浏览器的 accept-encoding，否则就是「页面能开、JS 全 404」。
  const isAsset0 = PROBE_ASSET_RE.test(String(req.originalUrl || req.url || ''));
  if (!isAsset0) {
    proxyReq.removeHeader('accept-encoding');
    proxyReq.setHeader('accept-encoding', 'identity');
  } else {
    // 已知该目标需要压缩协商才能取到静态资源时，兜底补上 gzip
    const ae = req.headers['accept-encoding'] || (target && target.preferGzip ? 'gzip, deflate, br' : '');
    if (ae) proxyReq.setHeader('accept-encoding', String(ae));
    else proxyReq.removeHeader('accept-encoding');
  }

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
      const decode = ({ gzip: zlib.gunzipSync, deflate: zlib.inflateSync, br: zlib.brotliDecompressSync }[enc]) || ((b) => b);
      let body;
      try {
        body = decode(buf).toString('utf8');
      } catch {
        // 解压失败：保持原编码原样透传（切勿删 content-encoding）
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
      const decode = ({ gzip: zlib.gunzipSync, deflate: zlib.inflateSync, br: zlib.brotliDecompressSync }[enc]) || ((b) => b);
      let out;
      try {
        out = Buffer.from(rewrite(decode(buf).toString('utf8')), 'utf8');
        delete headers['content-encoding'];
      } catch {
        // 解压失败：保持原编码原样透传
        out = buf;
      }
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
  const text = r.body.toString('utf8');
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
  handleProxyRes(proxyRes, req, res, req.__gate_target);
});

/* ------------------------------------------------------------------ *
 * WebSocket 升级处理
 * ------------------------------------------------------------------ */
function handleUpgrade(req, socket, head) {
  const s = getSession(req);
  if (!s || !s.target) return socket.destroy();
  stripBustParam(req);
  req.__gate_out = mapOutgoingUrl(req, s.target);
  req.__gate_target = s.target;
  proxy.ws(req, socket, head, {
    target: targetOrigin(s.target),
    changeOrigin: true,
    secure: false,
    headers: { host: `${s.target.host}${s.target.port ? ':' + s.target.port : ''}` },
  });
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
    authed: !!(s && s.authed),
    hasTarget: !!(s && s.target),
    target: s && s.target ? { protocol: s.target.protocol, host: s.target.host, port: s.target.port, base: s.target.base } : null,
  });
});

/* --- 登录目标 --- */
app.post(BASE + '/api/login', (req, res) => {
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
  res.json({ ok: true, target: { protocol: target.protocol, host: target.host, port: target.port, base: target.base } });
});

/* --- 退出当前代理（回登录页） --- */
app.post(BASE + '/api/logout', (req, res) => {
  const s = getSession(req);
  if (s) s.target = null;
  res.json({ ok: true });
});

/* --- 完全退出（清 Token 会话） --- */
app.post(BASE + '/api/exit', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies[COOKIE_NAME];
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
      const html = r.body.toString('utf8');
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
          for (const ae of ['gzip, deflate, br', 'identity']) {
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

  const winner = probes.find((p) => p.status >= 200 && p.status < 300 && !/text\/html/i.test(String(p.contentType || '')));
  res.json({
    ok: true,
    target: { protocol: t.protocol, host: t.host, port: t.port, base: t.base },
    entry: seenEntry,
    references: rel,
    probes,
    winner: winner || null,
    hint: winner
      ? `已找到可用组合：${winner.proto} ${winner.url} [accept-encoding: ${winner.acceptEncoding}]。若是前缀差异，把 "${winner.url.split('/').slice(0, 2).join('/')}/" 填进登录地址的路径。`
      : '所有组合都失败：说明这些文件在该地址下确实不存在（可能是另一端口/另一台机器，或需要先登录鉴权）。请核对浏览器直连时的完整地址。',
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
  return crypto.createHash('md5').update(m ? m[1] : 'anon').digest('hex').slice(0, 8);
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
function injectExitButton(html, target) {
  if (html.includes('id="__gate_exit__"')) return html;
  const label = target.host + (target.port ? ':' + target.port : '') + (target.base || target.assetPrefix || '');
  const script =
    '<div id="__gate_exit__" style="position:fixed;right:18px;bottom:18px;z-index:2147483647;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;">' +
    '<button id="__gate_exit_btn__" style="display:flex;align-items:center;gap:8px;padding:9px 14px;border:0;border-radius:999px;background:#111827;color:#fff;font-size:13px;cursor:pointer;box-shadow:0 6px 20px rgba(0,0,0,.28);opacity:.9;">' +
    '<span style="width:7px;height:7px;border-radius:50%;background:#22c55e;display:inline-block;"></span>' +
    '<span>代理中 ' + label + '</span>' +
    '<span style="opacity:.5">|</span>' +
    '<span style="text-decoration:underline">退出</span>' +
    '</button></div>' +
    '<script>(function(){var b=document.getElementById("__gate_exit_btn__");if(!b)return;b.addEventListener("click",function(){if(!confirm("退出代理并返回登录页？"))return;fetch("/_gate/api/logout",{method:"POST"}).then(function(){location.href="/"}).catch(function(){location.href="/"});});})();<' + '/script>';
  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, script + '</body>');
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
