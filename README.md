# SimpleProxy

[![Build and Push Docker Image](https://github.com/virkingz/simpleProxy/actions/workflows/docker.yml/badge.svg)](https://github.com/virkingz/simpleProxy/actions/workflows/docker.yml)

带 **Token 门禁**的网页版内网代理网关。通过浏览器访问网关，用 Token 进入后输入「内网 IP:端口」登录，
之后**该会话的所有请求都会被代理到目标地址**；保存过的地址显示在右侧，可一键登录；退出后回到登录页。

## 功能

- **Token 门禁**：必须先输入正确 Token 才能进入网关页面，会话保持 12 小时
- **目标登录**：输入 `内网IP:端口`（支持 `http://` / `https://`，省略协议默认 http）
- **全量代理**：登录后根路径 `/` 整体代理到目标，绝对路径资源不会错位
- **支持 WebSocket**：终端、实时日志、Jupyter 等长连接场景可用
- **忽略后端证书**：目标为自签 https 时自动跳过证书校验
- **保存与一键登录**：勾选保存后可命名；已保存地址显示在右侧列表，点击即登录
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
├── docker-compose.yml
├── .env.example
├── .github/workflows/docker.yml    # CI：构建并推送镜像到 GHCR
└── data/                           # 运行时生成，SQLite 数据（已挂载）
```

## 快速开始

### 方式一：拉取 CI 构建好的镜像（推荐）

CI 会在每次推送后自动构建镜像并推送到 GHCR：

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

### 方式二：本地 Compose 构建

```bash
cp .env.example .env
# 编辑 .env，务必修改 TOKEN
docker compose up -d --build
```

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

## 使用流程

1. 打开网关地址 → 输入 **Token** 进入
2. 在「目标地址」输入例如 `192.168.1.10:8080`
3. 需要下次一键登录就勾选「保存」，可填显示名称
4. 点「登录并代理」→ 浏览器跳转到目标服务首页，此后所有请求都代理到该地址
5. 右下角悬浮按钮显示当前代理目标，点「退出」返回登录页
6. 保存过的地址显示在**右侧列表**，点「登录」即一键进入

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

**Q：目标页面样式/图片 404？**
A：说明目标站点用了绝对路径或独立域名。多数同域应用可正常代理；若目标前端硬编码了自身域名，需在目标侧调整。

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
