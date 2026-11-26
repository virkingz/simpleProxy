# SimpleProxy

[![Build and Push Docker Image](https://github.com/virkingz/simpleProxy/actions/workflows/docker.yml/badge.svg)](https://github.com/virkingz/simpleProxy/actions/workflows/docker.yml)

带 **Token 门禁**的网页版**内网网关**，同时具备「代理」与「导航」两种形态：

- **持有正确 Token**：输入「内网 IP:端口」，网关把该会话的所有请求**原样代理**到目标地址；
  保存过的地址显示在右侧，可一键登录；退出后回到登录页。
- **未持有 / 输入错误 Token**：**同样进入界面**（界面与上面完全一致，不给任何提示），
  输入地址后由浏览器**直接跳转**到该地址（网关不做代理）；跳转记录（时间 / 来源 IP / 目标 URL / UA）写入服务端日志。
  默认**只允许「内网 IP + 端口」**（域名一律拒绝）、每 IP 限流，避免被当作开放重定向/内网探测跳板。

![登录页](docs/login.png)

> 左侧填写「内网 IP:端口」并可选保存；右侧是已保存地址列表，点「登录」即一键进入。

## 功能

- **透明代理（令牌正确）**：nginx 风格，**内容一字不改**原样转发 —— 不改写 HTML/JS/CSS、不加参数、不打乱 Cookie，兼容性最好
- **静默跳转（令牌错误）**：界面完全一致、无任何提示；输入地址后由浏览器直接跳转（仅内网地址，并记录日志）
- **Token 门禁**：令牌正确才启用代理能力，会话保持 12 小时
- **目标登录**：输入 `内网IP:端口`（支持 `http://` / `https://`，省略协议默认 http）
- **Cookie 原样透传**：目标自己的会话 Cookie 完整送达，登录状态不会丢
- **支持 WebSocket**：终端、实时日志、Jupyter 等长连接场景可用
- **忽略后端证书**：目标为自签 https 时自动跳过证书校验
- **保存与一键登录**：勾选保存后可命名并填备注；已保存地址显示在右侧列表，点击即登录
- **备注识别**：备注显示在列表条目下，可通过 ✎ 内联编辑，方便区分多个相似地址
- **SQLite 持久化**：保存的地址存 SQLite（Node 22 内置驱动，零原生依赖），挂载卷即可跨重启保留
- **悬浮退出按钮**：被代理页面**左上角**自动追加「退出」小圆点（悬停展开、可拖动），随时返回登录页

## 代理模式

本网关**只有一种工作模式：透明代理**（nginx `proxy_pass` 语义）。

### 透明代理

**完全不碰响应体**：不重写 origin、不改写资源地址、不去 base；只做「换 Host 转发 + 透传状态码/响应头/Set-Cookie/Location」。
唯一改动是在 HTML 的 `</body>` 前追加一个悬浮「退出」按钮（可用 `INJECT_EXIT_BUTTON=false` 关闭），**只追加、不改写任何既有内容**。

为什么它最不容易白屏：改写 HTML/JS 是侵入式的，现代前端（Vite 的动态 `import()`、`__vite__mapDeps`、`modulepreload`、内联 worker、根绝对路径资源）一旦被改错一处就整页崩。透明转发让目标服务始终认为自己在根路径，前端拿到的是**一字未改**的原始代码，因此不存在「漏改」。

Cookie 也**原样透传**（只剔除网关自身的会话 Cookie）：目标下发的会话 Cookie 会完整回到浏览器并在后续请求中原样送达，因此目标的登录状态不会丢——不会出现「登录后提示登录已过期」。

**子路径部署**：登录地址里带路径（如 `192.168.1.10:8080/lucky/`）会作为 `base` 保留，所有出站请求自动补上该前缀（已带则不重复叠加），因此挂在子路径下的服务也能直接用 —— 这属于透明代理自身能力，不涉及任何内容改写。

### 退出即重置目标登录态

透明代理下浏览器认为所有内容都来自**网关这个源**，因此被代理页面自己的登录 Cookie 也记在网关源下。
若不清，下次代理同一服务会带着旧登录态、跳过目标自己的登录页。

「退出」时会做两件事（`CLEAR_TARGET_COOKIES_ON_EXIT=false` 可关闭）：

1. **服务端按台账精确过期登录 Cookie**：网关在转发时记录目标下发过的每个 `Set-Cookie` 的**名字 + Path**，退出时逐个下发 `Max-Age=0` 过期指令。这样即使 Cookie 是 `HttpOnly`（JS 读不到也删不掉）也能清除。
2. **前端清空同源 JS 存储**：`localStorage` / `sessionStorage` / `IndexedDB`（覆盖用前端存储 token 的服务）。

效果：退出后再代理该服务，**和第一次一样需要重新登录**。网关自身的 Token 门禁会话不受影响，下次打开网关无需重输 Token。

> 说明：删除 Cookie 必须 `名字 + Path` 精确匹配，因此台账记录的是目标**实际使用**的 Path（如 `/api` 而非笼统的 `/`），这是能真正删掉的关键。

### 关于 https 与混合内容

网关与目标之间**按目标自身 scheme 建连**（http ↔ https 可跨协议，自签证书已内置忽略），对外协议跟随网关本身，
因此不存在「http 页面请求 https 资源」的混合内容问题。

## 目录结构

```
simpleProxy/
├── server.js                       # 服务端：Token 校验 / 会话 / 代理 / SQLite
├── public/index.html               # 前端：门禁页 + 登录页 + 右侧保存列表
├── package.json
├── Dockerfile
├── docker-compose.yml              # Compose：默认拉取 GHCR 镜像
├── docker-compose.build.yml        # Compose 覆盖文件：改为本地源码构建
├── .env.example
├── .github/workflows/docker.yml    # CI：构建并推送镜像到 GHCR
└── data/                           # 运行时生成，SQLite 数据（已挂载）
```

## 快速开始

### 方式一：Docker Compose（推荐）

```bash
cp .env.example .env
# 编辑 .env，务必修改 TOKEN
docker compose up -d
```

> 默认使用 CI 构建好的镜像 `ghcr.io/virkingz/simpleproxy:latest`，如需基于本地源码构建，加上覆盖文件：
> ```bash
> docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
> ```

> **多架构**：CI 发布的是 **`linux/amd64` + `linux/arm64`** 多架构镜像（同一 tag 下的 manifest list），
> Docker 会按宿主机架构**自动选择**对应镜像 —— 在 x86 服务器、Apple Silicon（M 系芯片）、
> 树莓派 4/5、各类 arm64 NAS 上都能直接 `docker pull`，无需任何额外参数。

### 方式二：docker run 直接用镜像

```bash
# 镜像地址（public 仓库可直接拉取）
docker pull ghcr.io/virkingz/simpleproxy:latest

docker run -d --name simpleproxy \
  -p 8080:8080 \
  -e TOKEN=your-strong-secret-token \
  -v $(pwd)/data:/data \
  --restart unless-stopped \
  ghcr.io/virkingz/simpleproxy:latest
```

> 若仓库/包为 private，需先登录：`echo $GITHUB_TOKEN | docker login ghcr.io -u <你的用户名> --password-stdin`

### 方式三：手动构建

```bash
docker build -t simpleproxy .
docker run -d --name simpleproxy \
  -p 8080:8080 \
  -e TOKEN=your-strong-secret-token \
  -v $(pwd)/data:/data \
  --restart unless-stopped \
  simpleproxy
```

浏览器打开 `http://<宿主机IP>:8080`，输入设置的 `TOKEN` 即可进入。

`.env`：

```dotenv
TOKEN=your-strong-secret-token   # 进入网关的令牌，务必修改
GATE_PORT=8080                   # 宿主机映射端口
```

## CI / 镜像发布

`.github/workflows/docker.yml` 使用 GitHub Actions 自动构建镜像：

| 触发条件 | 行为 |
| --- | --- |
| push 到 `main` / `master` | 构建并推送，含 `latest` 标签 |
| push tag `v*` | 构建并推送语义化版本标签（如 `v1.2.0`、`1.2`） |
| Pull Request | 仅构建校验，不推送 |
| 手动触发（workflow_dispatch） | 构建并推送 |

镜像推送到 **GHCR**：`ghcr.io/virkingz/simpleproxy`，使用的标签由 `docker/metadata-action` 自动生成。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `TOKEN` | `changeme` | **必改**。进入网关页所需的访问令牌 |
| `PORT` | `8080` | 容器内监听端口 |
| `DATA_DIR` | `/data`（镜像内） | SQLite 数据目录 |
| `INJECT_EXIT_BUTTON` | `true` | 是否向被代理 HTML 注入左上角悬浮退出按钮 |
| `CLEAR_TARGET_COOKIES_ON_EXIT` | `true` | 退出代理时是否「重置目标登录态」。透明代理下被代理页面自己的登录 Cookie 也存在网关源下；开启后退出时会按台账逐个过期这些 Cookie（含 HttpOnly），并由前端清空同源 `localStorage/sessionStorage/IndexedDB`，使下次代理该服务**和第一次一样要重新登录**。设 `false` 保留登录态 |
| `AUTH_MAX_FAILS` | `5` | 连续失败达该次数后启动**指数退避**（返回 `429` + `Retry-After`），把爆破速率压到不可行 |
| `AUTH_LOCK_BASE_MS` | `1000` | 指数退避基准时长（毫秒），第 N 次超出阈值 → `base × 2^N`，上限 5 分钟 |
| `AUTH_FAIL_WINDOW_MS` | `900000` | 失败计数窗口（毫秒，默认 15 分钟） |
| `MAX_PENDING_SESSIONS` | `500` | **未认证会话**数量上限。超过时按「最久未活跃」即时淘汰。防止无 Cookie 狂刷 `/auth` 撑爆内存 |
| `MAX_SESSIONS` | `2000` | 会话总数硬上限。超过时优先淘汰未认证会话，仍超出则连已登录会话一起按最久未用淘汰，保证内存绝不无界增长 |
| `SECURITY_HEADERS` | `true` | 是否给**网关自身**页面下发安全响应头（`X-Frame-Options: DENY`、CSP、nosniff、Referrer-Policy、HSTS）。**不会加到被代理的内容上**，透明代理「零改写」不受影响 |
| `HSTS_MAX_AGE` | `15552000` | HSTS 有效期（秒，默认 180 天）。仅在 HTTPS 请求下下发；设 `0` 关闭 |
| `TRUST_PROXY` | `false` | 网关前有 CDN/反代时设为 `true`，才会采信 `X-Forwarded-For` / `X-Forwarded-Proto`（影响限速取 IP 与 `Secure` 判定、HSTS）。直连内网时保持 `false`，否则这些头可被伪造 |
| `COOKIE_SECURE` | `auto` | 会话 Cookie 的 `Secure` 策略。`auto`＝仅 HTTPS 请求加；`true`＝恒加。**仅当你的部署只通过 HTTPS 访问时**才设 `true`；若同时保留 HTTP 直连入口（如 `192.168.x.x:端口`），设 `true` 会导致浏览器拒收 Cookie、HTTP 下无法登录 |
| `NAVIGATE_ENABLED` | `true` | 是否允许**未通过校验**的访客进入界面（输入地址后由浏览器直接跳转）。设 `false` 则未通过校验者会停在令牌页 |
| `NAVIGATE_ALLOW_PUBLIC` | `false` | 未通过校验者是否允许跳转到任意地址（含域名/公网）。默认 `false`＝**只允许「字面量内网 IP + 显式端口」**（`10./172.16-31./192.168./127.` 及 IPv6 ULA/回环），**任何域名一律拒绝**，避免网关被当作开放重定向/内网探测跳板。**除非你明确需要，否则不要打开** |
| `NAVIGATE_LOG` | `true` | 是否把每次跳转记入服务端日志（含时间、来源 IP、目标 URL、User-Agent）。**仅记录被放行的请求**（被限流/被拒绝的不记，防止日志洪水） |
| `NAVIGATE_RATE_MAX` | `10` | 未通过校验者**每个 IP** 在窗口内可发起的跳转次数上限，超出返回 `429` + `Retry-After`（防无成本刷日志） |
| `NAVIGATE_RATE_WINDOW_MS` | `60000` | 上述限流的窗口长度（毫秒，默认 60 秒） |
| `STRIP_CLIENT_HEADERS` | `true` | 转发给目标时清洗 `X-Forwarded-*` 并把 `Referer`/`Origin` 伪装成目标自身（仅页面/接口请求；静态资源会还原浏览器原生的 `Sec-Fetch-*` 且不注入 `Origin`）。目标做防盗链/Host 校验返回 403 时保持默认即可；设为 `false` 可 A/B 对比 |
| `PROXY_LOG` | `false` | 设为 `true` 时打印每个代理请求的**实际转发路径**与上游状态码（`docker logs -f simpleproxy`），并在响应里加 `X-Gate-Outgoing` / `X-Gate-Upstream` 头，DevTools 里可直接看出 404 来自哪一层、路径被改成了什么 |
| `CACHE_CONTROL` | `private, no-store, max-age=0, must-revalidate` | 所有网关响应（含代理透传）强制使用的缓存头。前面套 CDN 时**必须禁止共享缓存**，否则 404 会被缓存固化。可放宽为 `private, max-age=600`（仍禁 CDN 共享缓存） |

## 使用流程

1. 打开网关地址 → 输入 **Token** 进入
2. 在「目标地址」输入 `内网IP:端口`，例如 `192.168.1.10:8080`
3. 需要下次一键登录就勾选「保存」，可填**显示名称**与**备注**（备注用于识别，例如「王掌的机器 / 生产环境」）
4. 点「进入」→ 浏览器跳转到目标服务首页，此后所有请求都原样代理到该地址
5. 左上角悬浮小圆点显示当前代理目标，鼠标移上去展开、点「退出」返回登录页
6. 保存过的地址显示在**右侧列表**，点「登录」即一键进入；点 **✎** 可随时修改名称与备注

## 代理宿主机上的服务

若目标服务跑在宿主机（如 `127.0.0.1:9000`），容器内需用 `host.docker.internal`：

1. 在 `docker-compose.yml` 打开 `extra_hosts` 注释（Linux 需要）
2. 登录时填 `host.docker.internal:9000`

## 安全说明

- Token 采用 SHA-256 + 恒定时间比较校验，防时序侧信道
- 会话 ID 为随机 UUID，存服务端内存，前端仅持 HttpOnly Cookie
- 本工具会代理内网服务，**请勿直接暴露在公网**；如需外网访问，建议置于反向代理 + HTTPS + IP 白名单之后
- 未设置 `TOKEN` 时使用默认值 `changeme`，启动会打印告警，请务必修改

### 未通过校验的访客（静默跳转）

**无论令牌是否正确，都会进入同一个界面**，且界面完全一致、不给任何提示 ——
访问者在页面上看不到「代理 / 导航 / 模式」之类的字眼，无法从界面判断令牌是否正确。

| | 令牌正确 | 令牌错误 / 未提供 |
| --- | --- | --- |
| 能否进页面 | ✅ | ✅（**完全一致，无提示**） |
| 输入地址后 | 网关**原样代理**，返回目标内容 | 浏览器**直接跳转**到该地址 |
| 网关是否接触内容 | 是 | **否**（只下发一个跳转地址） |
| 地址限制 | 任意 | 默认**仅内网 / 私有地址** |
| 是否记录日志 | — | ✅ 记录时间 / 来源 IP / 目标 URL / UA |

**为什么默认只允许内网 IP + 端口？** 该路径允许访客自填跳转目标，若放宽，任何人都能用你的公网域名
构造 `https://你的网关/?...→ 钓鱼站` 的链接，把你的网关当成**开放重定向**跳板。
因此默认闸门是「**字面量内网 IP + 显式端口**」，并且：

- **任何域名一律拒绝** —— 包括 `*.internal` / `*.local` / `localhost` 这些看似「内网」的名字
  （它们并非公网保留，但可被解析劫持，且不属于「内网 IP」的语义）；
- **`169.254.0.0/16` 拒绝** —— 云实例元数据 `169.254.169.254` 所在段，被用于跳转即是内网探测跳板；
- **`100.64.0.0/10`（CGNAT）、`fe80::/10`（IPv6 link-local）拒绝** —— 不属于真正的内网；
- **必须写端口** —— 如 `192.168.1.10:8080`，缺端口返回 `400`；
- **每 IP 限流**（`NAVIGATE_RATE_MAX`，默认 10 次/分钟），超出 `429`；限流挡掉的请求**不写日志**。

确有需要时设 `NAVIGATE_ALLOW_PUBLIC=true` 放开（自行承担风险）。
若完全不需要该路径，设 `NAVIGATE_ENABLED=false`，则未通过校验者会停在令牌页。

> 安全提醒：该路径**只做跳转、不代理**，因此它不会让未通过校验者访问到任何内网内容 ——
> 前提是被跳转的服务自己也在内网可达。如果该服务本身暴露在公网，那与网关无关。



Token 是唯一凭证，因此对**在线爆破**做了防爆破设计（简单、诚实、可审计）：

- **恒定时间比较**：token 用 `crypto.timingSafeEqual(sha256(a), sha256(b))` 比较，避免逐字符比较泄漏的时序侧信道。
- **显式 401 + 指数退避**：错误 token 返回 `401`，并按 IP 计数失败；连续失败达 `AUTH_MAX_FAILS`（默认 5）后，
  后续请求返回 **`429` + `Retry-After`**，等待时长指数增长（上限 5 分钟），把爆破速率压到不可行。
  正确 token 复位计数。
- **会话数量上限（防内存 DoS）**：每次无 Cookie 的 `POST /auth` 都会新建会话，
  因此对**未认证会话**（`MAX_PENDING_SESSIONS`）和**会话总数**（`MAX_SESSIONS`）设了上限。
  超限时按「最久未活跃」即时淘汰，且**优先淘汰未认证会话**，尽量不误伤正在使用的登录会话。

> **为什么不用「诱饵」（错误 token 也返回与成功一致的响应）？**
> 早期版本采用过该机制，但它有一个**无法修补**的缺陷：一旦登录成功，诱饵会话必须让它
> 「看起来像能正常代理」——否则攻击者只需「代理一个自己控制的可达地址，看是否 502/跳转」
> 即可 100% 判定 token 真假。而真要做到「看起来一样」，就只能让它**真的代理**，
> 那等于给了错 token 一个可用的开放代理（整站旁路），比预言机本身危险得多。
> 因此改为显式 401 + 退避：不隐藏、不误导。
>
> 安全性来自 **Token 的熵值** —— 请使用足够长的随机串，例如 `openssl rand -hex 24`。
> 一旦 token 被猜中，网关本身就是进入内网的跳板。

### 响应头与 Cookie

- **网关自身**页面下发：`X-Frame-Options: DENY`（防点击劫持）、严格 CSP（`frame-ancestors 'none'`）、
  `X-Content-Type-Options: nosniff`、`Referrer-Policy`，HTTPS 下额外下发 `Strict-Transport-Security`。
  可用 `SECURITY_HEADERS=false` 关闭。
- 这些头**不会加到被代理的内容上**（透明代理「零改写」不受影响）。
- `_gate_sid` 始终带 `HttpOnly` + `SameSite=Lax`；**HTTPS 时**额外带 `Secure`
  （内网 HTTP 直连不带，否则浏览器会拒收该 Cookie）。

## 常见问题

**Q：主文档能打开，但所有 JS/CSS 全部 403，页面空白？**
A：先看 403 的响应头。若是 `Server: nginx` / `Content-Length: 0`，说明 **403 来自被代理的目标服务**（网关自身不会返回 403，也不带 `Server: nginx`），
通常是目标做了 Referer 防盗链、Host 白名单或 Cookie 鉴权。网关默认会清洗 `X-Forwarded-*` / `Sec-Fetch-*` 并把 `Referer`/`Origin` 伪装成目标自身，
同时不再对 Cookie 值做 URL 编码（早期实现会把 token 里的 `+` `/` `=` 破坏掉导致鉴权失败）。
排查步骤：
1. 设 `PROXY_LOG=true` 后 `docker compose up -d`，再 `docker logs -f simpleproxy` 看上游状态码；
2. 用 `STRIP_CLIENT_HEADERS=false` 做 A/B 对比，确认是否由来源头引起；
3. 若仍 403，检查目标服务自身的访问控制（IP 白名单、安全入口、鉴权 Cookie 的 `Domain`/`Secure` 设置）。

**Q：主文档能打开，但所有 JS/CSS 全部 404（或 403），页面空白，且前面套了 CDN？**
A：**优先怀疑 CDN 缓存**。若响应头里有 `EO-Cache-Status: HIT` / `Age` / `X-Cache` 之类，说明 CDN 把某次「未登录 404」按 URL 缓存了，且缓存键不含 Cookie——之后带会话的浏览器请求同一 URL 也直接命中缓存的 404，根本不回源。同一会话切换目标时还会命中上一个目标的资源（串味）。
网关已做两层防护：
1. 所有响应（含代理透传）强制 `Cache-Control: private, no-store` + `Vary: Cookie`，覆盖上游的 `public` / `immutable` / `s-maxage`，CDN 不再缓存；
2. 转发时不会给 URL 追加任何参数（零改写），因此不存在「缓存键被污染」的问题。

若仍不行，在 CDN 控制台把该域名设为「不缓存 / 遵循源站 Cache-Control」并关闭「缓存 4xx」，然后清除一次缓存；再设 `PROXY_LOG=true` 看 `docker logs` 里上游状态码——若上游本身就是 404/403，则问题在目标服务侧而非网关。

**Q：不走 CDN、直连源站也一样 404，而且 `/login` 能开、所有 `/static/js/*.js` 全 404（响应带 `Server: Nginx`、约 146 字节）？**
A：**这是压缩协商问题，不是路径问题。** 这类设备（飞牛 fnOS 管理页、部分 iKuai）的静态资源**只提供 `.js.gz` / `.css.br` 预压缩文件**——客户端不声明 `Accept-Encoding: gzip`/`br` 时，Nginx 找不到未压缩文件就回 404；而 `/login` 是动态页所以正常。

网关已做处理：

- 统一把 `Accept-Encoding` **规范成网关能解码的编码**（`gzip, deflate, br`）：既满足预压缩资源的需求，又保证注入退出按钮时一定解得开 HTML；
- 现代 Chrome 会发 `gzip, deflate, br, zstd`，其中的 `zstd` 会被**剥离**（Node 解码表不含 zstd）。否则上游可能回 zstd，网关解不开 → 无法正确处理；
- 遇到**未知编码**时一律**原样透传**（保留 `content-encoding`），绝不按 utf8 处理，宁可少处理也不破坏内容；
- 已知目标依赖压缩协商时，客户端只声明 `identity` 的请求会自动兜底补 `gzip`。

**排查**：设 `PROXY_LOG=true`（`docker logs -f simpleproxy`）可看到每个请求转发到上游的**真实路径**与上游状态码，并能看到上游是否对某编码返回 404；响应头 `X-Gate-Outgoing` / `X-Gate-Upstream` 也可在浏览器 DevTools 里直接看到转发结果。

用真实数据实测（`192.168.3.1`）：`/static/js/polyfills-*.js` 带 gzip 返回 **200 / 49798 字节**，不带返回 **404 / 146 字节**——即**路径与协议都正确，唯一变量是 `Accept-Encoding`**。

**Q：登录后页面空白，或样式/图片 404？**
A：请先确认登录地址填的是「浏览器直连该服务时的完整地址（协议 + IP + 端口 + 子路径）」。
若该服务把子路径挂在别处（如资源在 `/web/...` 而入口在根），把登录地址改成对应子路径即可。
透明代理**不改写任何 HTML/JS/CSS**，因此不会出现「改写漏改导致白屏」的问题。

**Q：https 目标证书报错？**
A：网关已内置 `secure:false` 忽略后端证书校验，无需额外配置。

**Q：保存的地址重启后丢失？**
A：确认已挂载卷 `-v ./data:/data`（compose 已内置）。

## 本地开发

```bash
npm install
TOKEN=devtoken PORT=8080 node --no-warnings server.js
# 打开 http://127.0.0.1:8080
```

需要 Node.js **>= 22.5.0**（使用内置 `node:sqlite`）。

## License

MIT
