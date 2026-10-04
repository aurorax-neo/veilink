ARG NPM_REGISTRY=https://registry.npmmirror.com
ARG GOPROXY=https://goproxy.cn,direct
ARG APK_MIRROR=https://mirrors.ustc.edu.cn/alpine

# ============ 后端构建 ============
FROM --platform=$BUILDPLATFORM golang:1.27-alpine3.23 AS build-backend
WORKDIR /src/backend
ARG GOPROXY
ENV GOPROXY=${GOPROXY}
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG SOURCE_URL=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X veilink/internal/buildinfo.Version=${VERSION} -X veilink/internal/buildinfo.Commit=${COMMIT}" -o /out/veilink ./cmd/veilink

# ============ 前端构建 ============
FROM --platform=$BUILDPLATFORM node:22-alpine3.23 AS build-web
WORKDIR /src/frontend
ARG NPM_REGISTRY
RUN npm config set registry ${NPM_REGISTRY}
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ============ 后端镜像（纯 API + pull 前端） ============
FROM alpine:3.23 AS backend
ARG APK_MIRROR
ARG VERSION=dev
ARG COMMIT=unknown
ARG SOURCE_URL=unknown
RUN printf '%s/v3.23/main\n%s/v3.23/community\n' "$APK_MIRROR" "$APK_MIRROR" > /etc/apk/repositories \
 && apk add --no-cache ca-certificates tzdata sqlite su-exec \
 && mkdir -p /data/web \
 && adduser -D -u 65532 -g 65532 veilink \
 && chown -R veilink:veilink /data
LABEL org.opencontainers.image.title="veilink-backend" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="${SOURCE_URL}"
COPY docker-entrypoint.sh docker-healthcheck.sh /usr/local/bin/
COPY --from=build-backend /out/veilink /usr/local/bin/veilink
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh /usr/local/bin/docker-healthcheck.sh
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["master"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/docker-healthcheck.sh"]


# ============ 统一镜像（后端 + 预置前端，master 开箱即用） ============
FROM backend AS unified
ARG VERSION=dev
ARG COMMIT=unknown
ARG SOURCE_URL=unknown
LABEL org.opencontainers.image.title="veilink" \
      org.opencontainers.image.description="Veilink master/server/client with pre-bundled web UI" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="${SOURCE_URL}"
COPY --from=build-web /src/frontend/dist /opt/veilink-web/
ENV WEB_PREBUNDLED_DIR=/opt/veilink-web
