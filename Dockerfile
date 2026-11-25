# ---- 依赖层 ----
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json ./
# 仅两个纯 JS 依赖，无原生编译
RUN npm install --omit=dev --no-audit --no-fund

# ---- 运行层 ----
FROM node:22-alpine
LABEL org.opencontainers.image.title="simpleproxy" \
      org.opencontainers.image.description="SimpleProxy - 带 Token 门禁的内网 Web 代理网关" \
      org.opencontainers.image.source="https://github.com/virkingz/simpleProxy"

ENV NODE_ENV=production \
    PORT=8080 \
    DATA_DIR=/data \
    BUILD_ID=""

# 构建标识（CI 传入 commit sha）：用于静态资源缓存破坏，
# 每次升级镜像都会让旧的缓存响应立即失效
ARG BUILD_ID=""
ENV BUILD_ID=${BUILD_ID}

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json server.js ./
COPY public ./public

RUN mkdir -p /data && chown -R node:node /data /app
USER node

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/_gate/api/me').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--no-warnings", "server.js"]
