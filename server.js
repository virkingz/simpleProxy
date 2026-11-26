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

/* ---- Token 防爆破（与「诱饵」模式协同）----
 * 诱饵模式下，**绝不能**用 401/429 这类可区分状态来暴露“token 错了” ——
 * 那等于直接告诉攻击者，诱饵也白做。因此这里改为「静默节流」：
 *   某个 IP 在窗口内尝试过于频繁时，只是**把它拖慢**（人为延迟），
 *   响应内容与形状仍与成功完全一致。
 * 关闭诱饵（AUTH_DECOY=false）时，恢复为「失败 → 指数退避 + 429」。
 */
const AUTH_DECOY = process.env.AUTH_DECOY !== 'false';
const AUTH_MAX_FAILS = parseInt(process.env.AUTH_MAX_FAILS || '5', 10);
const AUTH_LOCK_BASE_MS = parseInt(process.env.AUTH_LOCK_BASE_MS || '1000', 10);
const AUTH_FAIL_WINDOW_MS = parseInt(process.env.AUTH_FAIL_WINDOW_MS || String(15 * 60 * 1000), 10);
// 静默节流：窗口内尝试次数超过该值后，每次登录延迟（毫秒），逐渐加长
const AUTH_SILENT_DELAY_MS = parseInt(process.env.AUTH_SILENT_DELAY_MS || '400', 10);
const AUTH_SILENT_MAX_DELAY_MS = parseInt(process.env.AUTH_SILENT_MAX_DELAY_MS || '4000', 10);
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
// 静默节流：返回应等待的毫秒数（不暴露任何「你错了」的信号）
function authThrottleDelay(req) {
  const rec = authFails.get(clientIp(req));
  if (!rec || rec.fails < AUTH_MAX_FAILS) return 0;
  const over = rec.fails - AUTH_MAX_FAILS;
  return Math.min(AUTH_SILENT_DELAY_MS * Math.pow(2, Math.min(over, 6)), AUTH_SILENT_MAX_DELAY_MS);
}
function authNoteFail(req) {
  const ip = clientIp(req);
  const rec = authRec(ip);
  rec.fails++;
  if (!AUTH_DECOY && rec.fails >= AUTH_MAX_FAILS) {
    // 非诱饵模式：指数退避（第 N 次超出阈值 → base * 2^(超出次数)，上限 5 分钟）
    const over = rec.fails - AUTH_MAX_FAILS;
    rec.lockedUntil = Date.now() + Math.min(AUTH_LOCK_BASE_MS * Math.pow(2, over), 5 * 60 * 1000);
  }
  authFails.set(ip, rec);
}
// 诱饵模式专用：记录**每一次尝试**（不论对错），且不因成功而复位。
// 目的是让节流只反映「请求频率」，与 token 是否正确无关 → 杜绝时序/计数侧信道。
function authNoteAttempt(req) {
  const ip = clientIp(req);
  const rec = authRec(ip);
  rec.fails++;
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

// 诱饵专用「影子表」：结构与 sites 完全一致，但彼此隔离。
// 目的：让诱饵会话的保存/列表/PATCH/DELETE 都**真实发生**（耗时、形状与真实一致），
// 又不会污染真实站点数据，也不泄露真实内网地址。
db.exec(`CREATE TABLE IF NOT EXISTS sites_decoy (
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
);`);

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

// 影子表同构语句：诱饵会话统一走这里，行为/耗时与真实一致
const stmtDecoy = {
  list: db.prepare('SELECT * FROM sites_decoy ORDER BY last_used_at DESC, id DESC'),
  get: db.prepare('SELECT * FROM sites_decoy WHERE id = ?'),
  upsert: db.prepare(`
    INSERT INTO sites_decoy (name, note, protocol, host, port, base, created_at, last_used_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(protocol, host, port, base)
    DO UPDATE SET name = excluded.name, note = excluded.note, last_used_at = excluded.last_used_at
  `),
  touch: db.prepare('UPDATE sites_decoy SET last_used_at = ? WHERE id = ?'),
  update: db.prepare('UPDATE sites_decoy SET name = ?, note = ?, base = ? WHERE id = ?'),
  del: db.prepare('DELETE FROM sites_decoy WHERE id = ?'),
  find: db.prepare('SELECT * FROM sites_decoy WHERE protocol = ? AND host = ? AND port = ? AND base = ?'),
};
// 按会话选表：诱饵走影子表，真实走真实表
function stmtFor(s) { return s && s.decoy ? stmtDecoy : stmt; }

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
    s = { sid, authed: false, decoy: false, target: null, tgtCookies: [], createdAt: Date.now(), lastSeen: Date.now() };
    sessions.set(sid, s);
    // HTTPS 时带 Secure；HTTP 直连不带（否则浏览器拒收）
    res.setHeader('Set-Cookie', sessionCookie(req, sid, 43200));
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
  stripGateHeaders(res);    // 移除网关自身的安全头，避免污染被代理内容（见函数注释）
  // 诱饵会话：**绝不真正转发**，但要伪装成「上游不可达」（502 错误页）——
  // 这与真实会话遇到目标下线/端口不通时的表现**完全一致**，
  // 因此无法通过「跳转后看到什么」判断 token 真假。
  if (req.__gate_session && req.__gate_session.decoy) {
    res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(errorPage('connect ECONNREFUSED (upstream unavailable)'));
  }
  // 记下「浏览器看到的路径」：Cookie 的默认 Path 要按它推导，
  // 而不是按补了 base 前缀后发往上游的路径（否则过期指令的 Path 会不匹配）。
  req.__gate_visible_path = req.url;
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
  // 注意：诱饵会话这里**照常返回**（不再返回 null）。
  // 若返回 null，上层会回「未授权访问该转发端口」的 403 页 ——
  // 与真实会话的转发行为明显不同，又成了判据。改由调用方伪装成「上游不可达」。
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
  // 诱饵：伪装成「上游不可达」，与真实会话目标下线时一致（绝不能回 403 异议页）
  if (s.decoy) {
    res.writeHead(502, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    return res.end(errorPage('connect ECONNREFUSED (upstream unavailable)'));
  }
  const rec = pfServers.get(port);
  if (rec) rec.target = s.target;         // 目标切换后即时生效

  // 原样转发：不改写、不注入、不剥离任何东西
  req.url = req.url || '/';
  req.__pf_port = port;                   // 标记：响应侧直通，不做任何改写
  req.__gate_session = s;                 // 供响应侧记录目标 Cookie 台账
  stripGateHeaders(res);                  // 移除网关自身安全头，避免污染被代理内容
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

/* ---- 透明 / 端口转发模式下的「最小必要头部修正」 ----
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

// 组装会话 Cookie：HTTPS 时附加 Secure（防协议降级被明文携带），
// HTTP 直连（内网 192.168.x.x）时不加，否则浏览器拒收该 Cookie。
function sessionCookie(req, sid, maxAge) {
  return `${COOKIE_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax` +
    (isHttpsReq(req) ? '; Secure' : '') +
    `; Max-Age=${maxAge}`;
}

app.use(BASE + '/static', express.static(path.join(__dirname, 'public'), { index: false }));

/* --- Token 校验（含防爆破 / 诱饵）---
 * 诱饵模式（AUTH_DECOY，默认开）：
 *   任何 token 都返回**完全一致**的响应 —— 状态码、body、Cookie 全同（恒定时间）。
 *   正确的 token → 正常会话；错误的 token → 会话带 decoy 标记，
 *   此后所有「真实代理」动作都被静默拒绝（见 doProxy / pfResolve / /api/login）。
 *   目的：让在线爆破无法通过响应差异判断 token 对错，从而无法收敛。
 * 关闭诱饵时：错误 token 返回 401，且失败达阈值后指数退避。
 */
app.post(BASE + '/api/auth', async (req, res) => {
  // 非诱饵模式：退避期内直接 429
  if (!AUTH_DECOY) {
    const left = authLockRemaining(req);
    if (left > 0) {
      res.setHeader('Retry-After', String(Math.ceil(left / 1000)));
      return res.status(429).json({ ok: false, error: `尝试过于频繁，请 ${Math.ceil(left / 1000)} 秒后重试` });
    }
  }
  const token = String((req.body && req.body.token) || '');
  const sha = (v) => crypto.createHash('sha256').update(v).digest();
  const ok = crypto.timingSafeEqual(sha(token), sha(TOKEN));   // 恒定时间比较

  // ⚠️ 顺序与「计数语义」都很关键：
  //  · 先算延迟再记账 —— 否则前一次的正确/错误会影响本次延迟，形成时序预言机。
  //  · 诱饵模式下**统计每一次尝试**（不论对错）、且成功后**不复位**计数 ——
  //    否则攻击者可「先猜 G、再送一个错误 W；若 W 变快 ⇒ G 是对的」反推正确 token。
  //    这样节流状态只取决于「请求频率」，与 token 是否正确**完全无关**。
  const delay = AUTH_DECOY ? authThrottleDelay(req) : 0;
  if (AUTH_DECOY) {
    authNoteAttempt(req);
  } else if (!ok) {
    authNoteFail(req);
  } else {
    authNoteSuccess(req);
  }
  if (delay > 0) await new Promise((r) => setTimeout(r, delay));

  // 非诱饵模式：错误 token 仍返回 401（显式，便于管理员排查）
  if (!AUTH_DECOY && !ok) {
    return res.status(401).json({ ok: false, error: 'Token 不正确' });
  }

  // 到这里：成功 / 或诱饵。二者下发形状完全一致（Cookie 属性、body 均相同）。
  const s = getSession(req, res, true);
  s.authed = true;
  s.decoy = !ok;
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

  // ⚠️ 诱饵会话：**不再靠「没有 target」拒绝** —— 否则 /me 的 hasTarget、
  // localStorage 保存、mode/pfPort 形状都会成为「token 真假」的判据（已被识破）。
  // 现在诱饵走**与真实完全相同的代码路径**：写入 s.target（幻影目标），
  // 一样写库 / 一样尝试分配端口，返回形状逐字段对齐；
  // 真正的差别只在「转发那一层」—— 见 doProxy / pfHandleHttp 里对 s.decoy 的处理，
  // 那里会伪装成「上游不可达」，与真实会话遇到目标下线时的表现一致。
  s.decoy = !!s.decoy;
  if (s.decoy) {
    // 幻影目标：指向一个**必然连不上**的保留地址（RFC 5737 TEST-NET-1），
    // 使「跳转后」的观感 = 目标服务不可达，与真实场景无异。
    target.phantom = true;
    s.target = target;
    s.lastSeen = Date.now();
    // 与真实分支等量工作：诱饵也「写库」，但写入**影子表**（形状/耗时一致，不污染真实数据）
    const ds = stmtFor(s);
    if (req.body && req.body.save) {
      const name = String(req.body.name || '').trim() || `${target.host}:${target.port}${target.base}`;
      const note = String(req.body.note || '').trim();
      try { ds.upsert.run(name, note, target.protocol, target.host, target.port, target.base, Date.now(), Date.now()); } catch {}
    } else {
      const dFound = ds.find.get(target.protocol, target.host, target.port, target.base);
      if (dFound) ds.touch.run(Date.now(), dFound.id);
    }
    // 端口模式：诱饵也真实分配一个端口（监听后只回「不可达」页），保持形状一致
    let dPf = null;
    if (PORT_FORWARD && req.body && req.body.mode === 'port') {
      try { dPf = await pfEnsure(s); } catch {}
      if (!dPf) target.mode = 'path';          // 分配失败同样回退，行为一致
    } else {
      pfRelease(s);
    }
    return res.json({
      ok: true,
      target: { protocol: target.protocol, host: target.host, port: target.port, base: target.base },
      mode: dPf ? 'port' : target.mode,
      pfPort: dPf,
      pfHost: dPf ? PF_HOST : null,
    });
  }

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

/* --- 退出当前代理（回登录页） ---
 * 关键：透明代理下，被代理页面自己的登录 Cookie 也存在于「网关」这个源下。
 * 若不清掉，下次代理同一服务会带着旧登录态 → 跳过目标自己的登录页。
 * 这里按台账把目标下发过的 Cookie 逐个过期（含 HttpOnly，指名道姓 + 原 Path）。
 * 前端脚本还会清 localStorage/sessionStorage/IndexedDB（覆盖非 Cookie 方案）。 */
app.post(BASE + '/api/logout', (req, res) => {
  const s = getSession(req);
  let cleared = [];
  if (s) {
    pfRelease(s);
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
    pfRelease(s);
    cleared = targetClearCookies(s, req);
  }
  if (sid) sessions.delete(sid);
  const all = [...cleared, sessionCookie(req, '', 0)];
  res.setHeader('Set-Cookie', all);
  res.json({ ok: true, clearedCookies: cleared.length });
});

/* --- 诊断：把上游真相一次打出来（需已通过 Token） ---
 * GET /_gate/api/diag[?target=1.2.3.4:443]
 * 返回：入口页真实落点、入口页引用的资源、每个资源在各前缀/协议下的真实状态。
 * 用于定位「上游 404」到底是路径前缀问题、协议问题，还是资源本身不存在。
 */
app.get(BASE + '/api/diag', async (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });
  // 诱饵会话：**照常走完整个 diag 流程**，但把探测目标换成「保证不可达的哨兵地址」
  // （RFC 5737 TEST-NET-1，192.0.2.0/24，不会被路由）。这样：
  //  · 返回形状/状态码与真实一致（不因 400 而暴露身份）；
  //  · 又**无法用它探测内网**（探测对象被强制替换）。
  let diagTarget;
  if (s.decoy) {
    diagTarget = normalizeTarget('192.0.2.1:9');
  } else {
    diagTarget = (req.query.target && normalizeTarget(req.query.target)) || s.target;
  }
  const t = diagTarget;
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

/* --- 站点列表 ---
 * 诱饵会话不能看到**真实**保存列表（那是全局共享的内网地址，泄露即前功尽弃）。
 * 但也不能「恒返回空」—— 否则「空 vs 非空」又成了判据。
 * 解法：诱饵读写**结构完全相同的影子表**（sites_decoy）：诱饵自己保存的项能列出，
 * 耗时/形状/分页语义与真实一致，但看不到真实数据、也污染不到真实数据。 */
app.get(BASE + '/api/sites', (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });
  res.json({ ok: true, sites: stmtFor(s).list.all() });
});

app.delete(BASE + '/api/sites/:id', (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });
  stmtFor(s).del.run(parseInt(req.params.id, 10));
  res.json({ ok: true });
});

/* --- 编辑已保存站点（名称 / 备注） --- */
app.patch(BASE + '/api/sites/:id', (req, res) => {
  const s = getSession(req);
  if (!s || !s.authed) return res.status(401).json({ ok: false, error: '未通过 Token 校验' });
  const ds = stmtFor(s);
  const id = parseInt(req.params.id, 10);
  // 不存在的 id 一律 404 —— 诱饵也走这条，不能用「静默 200」暴露身份
  const row = ds.get.get(id);
  if (!row) return res.status(404).json({ ok: false, error: '记录不存在' });
  const name = req.body && req.body.name !== undefined ? String(req.body.name).trim() : row.name;
  const note = req.body && req.body.note !== undefined ? String(req.body.note).trim() : row.note;
  let base = req.body && req.body.base !== undefined ? String(req.body.base).trim() : (row.base || '');
  if (base && !base.startsWith('/')) base = '/' + base;
  if (base && !base.endsWith('/')) base += '/';
  if (base === '/') base = '';
  if (base && !/^\/[A-Za-z0-9._~\-%/]*$/.test(base)) return res.status(400).json({ ok: false, error: '子路径格式不正确' });
  try {
    ds.update.run(name || row.name, note, base, id);
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
