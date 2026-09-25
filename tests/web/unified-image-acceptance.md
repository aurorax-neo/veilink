# 统一镜像验收

本轮将此前按角色发布的镜像替换为一个最终镜像；Go/UI 编译阶段不是独立发布产品。入口为 `/usr/local/bin/veilink`，由 `master|server|client` 子命令选择角色。同一镜像包含 Web，只有 Master 启用 Web。无角色 Docker target、角色镜像 tag 或发布矩阵；仓库不存在需转换的 CI 发布矩阵、Compose 或安装脚本。

## 源码检查

实际执行并通过：

- `go test ./...`
- `go vet ./...`
- `go test -race ./internal/httpapi ./internal/cli ./internal/master ./internal/node ./internal/control ./internal/tunnel ./tests/deployment`
- `go test -tags integration ./tests/integration -count=1`：138.289 秒。
- frontend：`node --test tests/*.mjs`，34/34；`npm run typecheck`；`npm run build -- --outDir <scratch>/unified-acceptance/html`。
- `go test ./tests/deployment -v`：包含 HTTP/HTTPS、持久化监听配置、IPv6、显式 flags 覆盖、损坏数据库、节点分支和缺失/非法角色，均通过，无跳过。
- `git diff --check`。

首轮新增契约测试的 FROM 计数错误已修正，以上为修正后重跑结果。本轮没有重新进行浏览器交互验收。

## Docker CLI + Colima

Docker context：`colima`；Server：29.5.2，linux/arm64。仅执行一次统一镜像 build，成功：

```sh
docker build --build-arg HTTP_PROXY= --build-arg HTTPS_PROXY= \
  --build-arg http_proxy= --build-arg https_proxy= \
  -t veilink-unified-acceptance:latest .
```

所有主机命令均取消代理环境变量；没有修改 Docker daemon 的全局代理。Alpine 使用可覆盖的 USTC 源，按 linuxmirrors.cn 替换软件源的思路直接配置 repositories，不执行远程脚本。

镜像 ID：`sha256:e4e89687d11353833e9d47c9e0963089c805ac0282565a105a28760f68dd4675`。

同一镜像分别运行三个临时容器，均使用 UID/GID 65532、`-itd --restart unless-stopped --name ... -e TZ=Asia/Shanghai` 和临时 `/data` tmpfs（不触碰用户数据）：

- Master：Host 网络，`master -listen-addr 127.0.0.1:19843 -scheme http -html-dir /usr/local/html -embedded-server-enabled=false`；running/healthy，`/api/setup` 返回 `registration_required:true`，根路径返回 HTML。
- Server：Host 网络，`server` 子命令和测试节点接入 flags；running/healthy。
- Client：默认 Bridge 网络，`client` 子命令和测试节点接入 flags；running/healthy。

三个容器的 image ID 完全一致；都包含非空 `/usr/local/html/index.html`；二进制 SHA-256 均为 `66d987c4d019310624a1636fffc3a6c8bf25dbaa9bcf3c445c19ec233c75e9f4`。每个容器手动执行镜像内健康脚本也通过。无角色及非法角色启动均退出 1。

节点测试使用不可达的测试 Master 地址与假令牌：**Server/Client healthy 仅表示 PID 1 存活，不表示接入、授权或数据面就绪**。完整业务回归由上述 integration 测试覆盖。本轮 Master 使用默认 HTTP 做本机冒烟。产品默认 HTTP，内置 HTTPS 可选；生产可由 nginx 等终止 HTTPS 后转发到本机/内网 HTTP，可信网络也可直接 HTTP。首次注册须限制访问防抢占，不强制 HTTPS；此镜像验收未测试 nginx 反代。

## 清理与交付边界

本轮三个临时容器和验收镜像标签已删除；无角色/非法角色测试容器使用 `--rm` 自动移除。不执行全局 prune，不修改用户数据、历史研究文件或共享缓存。未 push、未远端部署。

生产构建命令为 `docker build -t veilink:latest .`；三种角色全部使用此镜像，完整 Docker Run、挂载与 TLS 参数见根目录 README。旧 `release-acceptance.md` 仅保留为历史证据，不再代表当前打包方式。
