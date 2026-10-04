# 真实 mux 与地址模型发布验收

本记录是提交 `9c0f2b9eff20f6294dfba0e34285e2148fc96484` 的历史验收，不代表当前统一镜像的打包方式。下述三镜像方案已废弃，当前使用方式以 README 为准，统一镜像验收见 `unified-image-acceptance.md`。旧 `ux-report.md` 的 private-session、Podman 故障及生产 NO 同样是历史结果。

## 结果

在当时 README 明确的运行与协议边界内，本轮发布验收通过。未 push、未部署远端。产品部署模型纠正为：默认 HTTP，内置 HTTPS 可选；生产常见 nginx 等终止 HTTPS 后转发到 Veilink HTTP，可信内网也可直接 HTTP。首次注册要求可信网络防抢占，不以 HTTPS 为前提；仍须遵守一次性令牌清除和持久化目录要求。此处更新部署叙事，不改变下述历史测试事实，也不表示当时测试过 nginx。

- TCP mux 真正使用 sing-mux 的 smux/yamux/h2mux，默认关闭，开启空类型默认为 smux；旧类型拒绝。
- h2mux 使用 HTTP/2 CONNECT 发起端与 sing-mux codec/Service；真实 mux 流内的 Veilink FIN 记录只解决半关闭，不承担多路复用，不宣称 mihomo 节点直连互通。
- 每 binding/type 池最多 64 条活动/等待流；h2mux 单流 deadline 不支持，依靠上下文和 transport 生命周期关闭。
- 删除地址 kind 分类，拨号 Host/Port、监听和 SNI 独立；旧持久化字段报错且原数据不变。

## 实际执行

- `cd backend && go test ./...`、`cd backend && go vet ./...`：通过（Go 单测本轮部分命中缓存）。
- `cd backend && go test -race ./internal/model ./internal/store ./internal/tunnel ./internal/node ./internal/control ./internal/master ./internal/httpapi ./internal/logring`：通过。
- `cd backend && go test -tags integration ./tests/integration -count=1`：通过，138.538 秒。
- mux 数据面覆盖三类型 TLS/Vision 加密路径、混合类型并发、目标/协议/UDP 拒绝、大负载半关闭、重连、Apply 和取消。
- 前端 `node --test tests/*.mjs`：34/34；`npm run typecheck`、生产构建：通过。输出在 scratch，未覆盖历史 html。
- Dockerfile 兼容性修正后 `go test ./tests/deployment`：通过。
- 真实浏览器及八张新截图：见 [mux-address-acceptance.md](mux-address-acceptance.md)。未做人工像素审阅。
- `git diff --check`：通过。

## 镜像与运行

当前环境为 Docker 29.8.1 客户端 / Colima Docker 29.5.2 服务端，非此前 Podman。三角色 docker build 均通过；首轮 Alpine 索引超时后通过构建级清空代理恢复，传统构建器不支持 COPY --chmod，改为 COPY + RUN chmod 后通过。

- Server：`sha256:e92e216e876b9099d60dc4e160128966ddbcb11402076e8e8d52a6f9821715ab`
- Client：`sha256:4ee3e1155364999781c6f173def2f6ddfe3a3e91eee6fdb807c46ef8755c3408`
- Master：`sha256:b35f3c9c14e067f6f5605e8a197605eba5088f420e99a8ebe6478df4105e9244`

三个镜像的 `/usr/local/bin/veilink` SHA-256 均为 `3321390182c30560d05c4fe7a2869de6bae2728df11bb6f5320760ac22b8e3ad`，以角色参数选择运行模式。仅 Master 含 Web，均 UID/GID 65532，HEALTHCHECK 存在。

Master 在临时 tmpfs 数据目录实际启动，GET /api/setup 返回 registration_required=true，Docker 状态 running/healthy。Server/Client 使用测试接入参数实际运行，均 running/healthy；此检查仅证明进程存活，不代表注册成功或目标可达。授权接入及数据面由 integration 与 tunnel 测试覆盖。没有进行远端部署。

## 清理与范围

本轮临时容器及三个 `veilink-mux-acceptance` 镜像标签均已删除；浏览器及临时 Master 已退出，私密浏览器测试目录已删除。不执行全局 prune，不删除共享层、用户数据或历史 Podman 数据。既有历史性能材料不作为本轮性能证据，保留在工作区而不纳入本次提交。
