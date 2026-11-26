const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const REPO = 'virkingz/simpleProxy';
const CWD = __dirname;
const TOKEN = execSync('gh auth token', { encoding: 'utf8' }).trim();
function api(method, endpoint, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request({
      host: 'api.github.com', path: `/repos/${REPO}${endpoint}`, method,
      headers: { 'User-Agent': 'simpleproxy-push', Authorization: `Bearer ${TOKEN}`,
        Accept: 'application/vnd.github+json', 'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null; try { json = JSON.parse(text); } catch {}
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(json);
        else reject(new Error(`HTTP ${res.statusCode}: ${text.slice(0, 400)}`));
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}
(async () => {
  let parent = (await api('GET', '/git/ref/heads/main')).object.sha;
  console.log('remote main:', parent.slice(0, 8));
  const SHAS = (process.env.SHAS || '').split(',').map(s => s.trim()).filter(Boolean);
  for (const sha of SHAS) {
    const msg = execSync(`git log -1 --pretty=%B ${sha}`, { cwd: CWD, encoding: 'utf8' }).trim();
    const files = execSync(`git show --name-only --format= ${sha}`, { cwd: CWD, encoding: 'utf8' }).split('\n').map(s => s.trim()).filter(Boolean);
    const baseTree = (await api('GET', `/git/commits/${parent}`)).tree.sha;
    const treeItems = [];
    for (const f of files) {
      const blob = await api('POST', '/git/blobs', { content: fs.readFileSync(path.join(CWD, f)).toString('base64'), encoding: 'base64' });
      treeItems.push({ path: f, mode: '100644', type: 'blob', sha: blob.sha });
    }
    const tree = await api('POST', '/git/trees', { base_tree: baseTree, tree: treeItems });
    const made = await api('POST', '/git/commits', { message: msg, tree: tree.sha, parents: [parent] });
    console.log('created', made.sha.slice(0, 8));
    parent = made.sha;
  }
  await api('PATCH', '/git/refs/heads/main', { sha: parent, force: false });
  console.log('PUSHED OK ->', parent);
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
