import express from 'express';
import httpProxy from 'http-proxy';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
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
const SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 小时无操作过期
const COOKIE_NAME = '_gate_sid';
const BASE = '/_gate';

/* ------------------------------------------------------------------ *
 * 数据层（SQLite，零原生依赖）
 * ------------------------------------------------------------------ */
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'gateway.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS sites (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    protocol     TEXT    NOT NULL DEFAULT 'http',
    host         TEXT    NOT NULL,
    port         INTEGER,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    UNIQUE(protocol, host, port)
  );
`);

const stmt = {
  list: db.prepare('SELECT * FROM sites ORDER BY last_used_at DESC, id DESC'),
  get: db.prepare('SELECT * FROM sites WHERE id = ?'),
  upsert: db.prepare(`
    INSERT INTO sites (name, protocol, host, port, created_at, last_used_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(protocol, host, port)
    DO UPDATE SET name = excluded.name, last_used_at = excluded.last_used_at
  `),
  touch: db.prepare('UPDATE sites SET last_used_at = ? WHERE id = ?'),
  del: db.prepare('DELETE FROM sites WHERE id = ?'),
  find: db.prepare('SELECT * FROM sites WHERE protocol = ? AND host = ? AND port = ?'),
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

  const protocol = u.protocol.replace(':', '');
  return { protocol, host, port, key: `${protocol}//${host}:${port}` };
}

function targetOrigin(t) {
  const isDefault = (t.protocol === 'http' && t.port === 80) || (t.protocol === 'https' && t.port === 443);
  return `${t.protocol}://${t.host}${isDefault ? '' : ':' + t.port}`;
}

/* ------------------------------------------------------------------ *
 * 代理实例
 * ------------------------------------------------------------------ */
const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: false,          // 忽略后端自签 https 证书
  ws: true,
  selfHandleResponse: true,
  xfwd: true,
});

proxy.on('error', (err, req, res) => {
  if (res && !res.headersSent && typeof res.writeHead === 'function') {
    res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(errorPage(err.message));
  } else if (res && typeof res.end === 'function') {
    try { res.end(); } catch {}
  }
});

/* ---- 出站请求：cookie 命名空间隔离 + 关闭压缩（便于注入） ---- */
function prepareProxyReq(proxyReq, req, target) {
  const prefix = cookiePrefix(target);
  const cookies = parseCookies(req.headers.cookie);
  const keep = [];
  for (const [k, v] of Object.entries(cookies)) {
    if (k.startsWith(prefix)) keep.push(`${k.slice(prefix.length)}=${encodeURIComponent(v)}`);
  }
  if (keep.length) proxyReq.setHeader('Cookie', keep.join('; '));
  else proxyReq.removeHeader('Cookie');

  // 让上游返回未压缩内容，方便对 HTML 注入退出按钮
  proxyReq.removeHeader('accept-encoding');
  proxyReq.setHeader('accept-encoding', 'identity');
}

/* ---- 响应：cookie 命名空间隔离 + Location 重写 + HTML 注入 ---- */
function handleProxyRes(proxyRes, req, res, target) {
  const prefix = cookiePrefix(target);
  const headers = { ...proxyRes.headers };

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
  const isHtml = /text\/html/i.test(ctype) && req.method !== 'HEAD';
  const enc = String(headers['content-encoding'] || '').toLowerCase();

  if (isHtml && INJECT_EXIT) {
    // 收集 → 解压 → 注入 → 以 identity 回传
    const chunks = [];
    proxyRes.on('data', (c) => chunks.push(c));
    proxyRes.on('end', () => {
      const buf = Buffer.concat(chunks);
      const decode = ({ gzip: zlib.gunzipSync, deflate: zlib.inflateSync, br: zlib.brotliDecompressSync }[enc]) || ((b) => b);
      let body;
      try {
        body = decode(buf).toString('utf8');
      } catch {
        // 解压失败则原样透传
        delete headers['content-encoding'];
        headers['content-length'] = buf.length;
        res.writeHead(proxyRes.statusCode || 200, headers);
        res.end(buf);
        return;
      }
      const out = Buffer.from(injectExitButton(body, target), 'utf8');
      delete headers['content-encoding'];
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

function rewriteLocation(loc, target) {
  try {
    const origin = targetOrigin(target);
    if (/^https?:\/\//i.test(loc)) {
      const u = new URL(loc);
      const sameHost = u.hostname === target.host && (u.port ? parseInt(u.port, 10) : u.protocol === 'https:' ? 443 : 80) === target.port;
      if (sameHost) return u.pathname + u.search + u.hash;
      return loc; // 指向别处则不动
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
    target: s && s.target ? { protocol: s.target.protocol, host: s.target.host, port: s.target.port } : null,
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
    const name = String(req.body.name || '').trim() || `${target.host}:${target.port}`;
    stmt.upsert.run(name, target.protocol, target.host, target.port, now, now);
  } else {
    const found = stmt.find.get(target.protocol, target.host, target.port);
    if (found) stmt.touch.run(now, found.id);
  }
  res.json({ ok: true, target: { protocol: target.protocol, host: target.host, port: target.port } });
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

/* --- 根路径：有目标则代理，否则给登录页 --- */
const indexPath = path.join(__dirname, 'public', 'index.html');
app.use((req, res, next) => {
  if (req.path.startsWith(BASE + '/')) return next();
  const s = getSession(req);
  if (s && s.target) return doProxy(req, res, s.target);
  if (req.method === 'GET' && (req.path === '/' || req.path === '/index.html')) {
    return res.sendFile(indexPath);
  }
  res.status(404).send('Not found. 请先通过网关登录。');
});

/* ------------------------------------------------------------------ *
 * 页面
 * ------------------------------------------------------------------ */
function injectExitButton(html, target) {
  if (html.includes('id="__gate_exit__"')) return html;
  const label = target.host + (target.port ? ':' + target.port : '');
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
