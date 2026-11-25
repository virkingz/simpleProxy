# SimpleProxy

[![Build and Push Docker Image](https://github.com/virkingz/simpleProxy/actions/workflows/docker.yml/badge.svg)](https://github.com/virkingz/simpleProxy/actions/workflows/docker.yml)

带 **Token 门禁**的网页版内网代理网关。通过浏览器访问网关，用 Token 进入后输入「内网 IP:端口」登录，
之后**该会话的所有请求都会被代理到目标地址**；保存过的地址显示在右侧，可一键登录；退出后回到登录页。

## 功能

- **Token 门禁**：必须先输入正确 Token 才能进入网关页面，会话保持 12 小时
- **目标登录**：输入 `内网IP:端口`（支持 `http://` / `https://`，省略协议默认 http）
- **全量代理**：登录后根路径 `/` 整体代理到目标，绝对路径资源不会错位
- **子资源不绕过**：自动把页面里硬编码的自身 origin（含 `<base href>`、内联脚本、CSS `url()`、JS 变量）改写成相对路径或网关地址，避免浏览器直连内网地址导致资源加载失败 / 页面空白
- **支持 WebSocket**：终端、实时日志、Jupyter 等长连接场景可用
- **忽略后端证书**：目标为自签 https 时自动跳过证书校验
- **保存与一键登录**：勾选保存后可命名并填备注；已保存地址显示在右侧列表，点击即登录
- **备注识别**：备注显示在列表条目下，可通过 ✎ 内联编辑，方便区分多个相似地址
- **SQLite 持久化**：保存的地址存 SQLite（Node 22 内置驱动，零原生依赖），挂载卷即可跨重启保留
- **悬浮退出按钮**：被代理页面右下角自动注入「退出」按钮，随时返回登录页
- **Cookie 隔离**：不同目标站点的 Cookie 按目标哈希加前缀隔离，互不串味

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
| `INJECT_EXIT_BUTTON` | `true` | 是否向被代理 HTML 注入右下角悬浮退出按钮 |
| `STRIP_CLIENT_HEADERS` | `true` | 转发给目标时清洗「网关来源」头（`X-Forwarded-*` / `Sec-Fetch-*`）并把 `Referer`/`Origin` 伪装成目标自身。目标做防盗链/Host 校验返回 403 时保持默认即可；设为 `false` 可 A/B 对比 |
| `PROXY_LOG` | `false` | 设为 `true` 时打印每个代理请求的上游状态码，`docker logs` 可看 4xx/5xx 来自哪一层 |

## 使用流程

1. 打开网关地址 → 输入 **Token** 进入
2. 在「目标地址」输入例如 `192.168.1.10:8080`
3. 需要下次一键登录就勾选「保存」，可填**显示名称**与**备注**（备注用于识别，例如「王掌的机器 / 生产环境」）
4. 点「登录并代理」→ 浏览器跳转到目标服务首页，此后所有请求都代理到该地址
5. 右下角悬浮按钮显示当前代理目标，点「退出」返回登录页
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

## 常见问题

**Q：主文档能打开，但所有 JS/CSS 全部 403，页面空白？**
A：先看 403 的响应头。若是 `Server: nginx` / `Content-Length: 0`，说明 **403 来自被代理的目标服务**（网关自身不会返回 403，也不带 `Server: nginx`），
通常是目标做了 Referer 防盗链、Host 白名单或 Cookie 鉴权。网关默认会清洗 `X-Forwarded-*` / `Sec-Fetch-*` 并把 `Referer`/`Origin` 伪装成目标自身，
同时不再对 Cookie 值做 URL 编码（早期实现会把 token 里的 `+` `/` `=` 破坏掉导致鉴权失败）。
排查步骤：
1. 设 `PROXY_LOG=true` 后 `docker compose up -d`，再 `docker logs -f simpleproxy` 看上游状态码；
2. 用 `STRIP_CLIENT_HEADERS=false` 做 A/B 对比，确认是否由来源头引起；
3. 若仍 403，检查目标服务自身的访问控制（IP 白名单、安全入口、鉴权 Cookie 的 `Domain`/`Secure` 设置）。

**Q：登录后页面空白，或样式/图片 404？**
A：通常是目标页面把「自身 origin」硬编码在 HTML/JS/CSS 里（如 `<base href="http://内网IP:端口/">`、`const API="http://内网IP:端口/api"`），
浏览器会直连该内网地址而绕过网关。网关已自动重写这些引用（含 `<base>`、内联脚本、CSS `url()`、JS 变量、`ws/wss`），
若仍有问题请把目标页面源码片段（含 `<base>` 与资源引用行）发出来。

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
