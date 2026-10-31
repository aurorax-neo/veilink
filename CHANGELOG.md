# Changelog

本项目所有重要变更均记录于此文件。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循
[Semantic Versioning](https://semver.org/lang/zh-CN/)。正式发布时，GitHub Actions
只提取当前 SemVer 版本段落作为 Release Notes，不再把多个版本的内容拼接到同一条
Release。

## [Unreleased]

## [0.4.12] - 2026-10-31

### Bug Fixes

- 修复 REALITY listener 关闭生命周期：同时取消 REALITY 上下文、关闭包装 listener，并等待在途握手协程退出，避免连接和 cover 资源泄漏到后续会话。
- 降低连续协议矩阵运行时出现连接建立或 UDP 回包等待的概率。
- Master 嵌入式服务测试改用动态端口；失败时等待后台 Master 和 embedded server 完整退出。
- 普通 Go 包测试逐包执行并输出失败包诊断，移除 CI 对本地 `.gitignore` 参考目录 `ref/` 的错误依赖。

### Features

- 扩展原生协议回归覆盖：75 项 VLESS、REALITY、TLS、Hysteria2、mux、XUDP、XHTTP 往返矩阵。
- 增加 350 项 XHTTP 组合矩阵，以及 Hysteria2 绑定级凭据、跨绑定凭据和目标隔离验证。

### Maintenance

- 重构 GitHub Actions 发布流水线，拆分普通 Go 包、隧道回归、协议矩阵、XHTTP、vet、race、integration 和前端检查。
- 发布构建使用预编译二进制装配多架构 Docker 镜像，Docker 阶段不执行源码编译。
- 发布产物包含 Linux amd64/arm64、macOS amd64/arm64 和 Windows amd64 压缩包及 SHA256 校验和。

### Verification

- GHCR 发布 `linux/amd64` 与 `linux/arm64` 多架构镜像。

## [0.4.11] - 2026-10-29

### Bug Fixes

- 修复 `.table-scroll` 缺失 `overflow-y: hidden` 导致浏览器自动计算纵向滚动条的问题。
- 为 `.workspace` 明确指定 `overflow: hidden; height: 100%`，消除内容区与顶栏之间的滚动槽位争抢。
- 修复 HTML 元信息 `color-scheme`，保持浏览器系统控件主题一致。

### Maintenance

- 全站升级 `surface-0` 至 `surface-3` 暗色层级。
- 统一导航和操作按钮热区与按下反馈，加入精细暗色滚动条样式。

## [0.4.10] - 2026-10-29

### Features

- 重构“快捷接入”弹窗和表单，精简冗余文案。
- 将临时接入令与永久凭据重置解耦，把节点凭据重置移入高危操作区域并增加二次确认。

### Bug Fixes

- 移除根元素多余滚动槽位，杜绝切换视图时根视口与内容区双滚动条重叠闪烁。
- 优化暗色模式输入框聚焦样式和窄宽排版。

## [0.4.9] - 2026-10-29

### Features

- 支持节点凭据显式重置，重置后旧凭据立即失效。
- Master 启动时自动清理历史遗留的节点凭据过期时间戳，使存量凭据永久生效。

### Bug Fixes

- 修复节点凭据 30 天过期导致节点崩溃重启和断连的问题。
- 修复 Web 控制台切换视图时外层视口与内部内容滚动条同时出现的问题。

### Upgrade Notes

- 保持 schema 6 兼容；若节点本地 `state.json` 已被擦除并进入重启循环，升级 Master 后重新生成接入命令即可恢复。

## [0.4.8] - 2026-10-07

### Features

- 自动迁移 schema 5 数据库到 schema 6，并在迁移前备份包含 WAL 已提交数据的数据库和部署密钥。
- 支持新版种子配置，并兼容 v0.4.2 ML-DSA 展开私钥。
- 带宽上限改为纯数字输入，按映射共享双向独立令牌桶，支持 TCP 背压和限速热更新。
- 统一使用镜像内置 Web，发布统一的 master/server/client Docker 镜像。

### Bug Fixes

- 开启 TCP keepalive，修复 XHTTP 握手后残留的 15 秒写 deadline。
- 未知或损坏数据库结构继续严格拒绝，不覆盖或删除未知数据。

### Upgrade Notes

- Master、Server、Client 必须同步升级到 v0.4.8；升级前应备份持久化数据和部署密钥，不要同时运行新旧 Master。

## [0.4.7] - 2026-10-05

### Bug Fixes

- 调整 Mux 授权连接池调度，优先使用空闲且已授权的底层连接，避免慢读者阻塞仍有空闲连接的请求。
- 合并 Mux 应用记录的帧头和载荷写入，减少不必要的等待。

### Verification

- 通过 52 个 TCP 小数据组合、24 个非 XHTTP 慢读者组合和 4 种传输的 UDP 单包测试。
- 全量 Go 测试、go vet、integration、前端测试、生产构建和三角色本地统一镜像检查通过。

### Upgrade Notes

- 统一镜像为 `ghcr.io/aurorax-neo/veilink:v0.4.7`，支持 Linux amd64/arm64；前端资源版本为 `web-v0.4.7`。

## [0.4.6] - 2026-10-05

### Features

- 支持连接池增量扩缩容，保留未修改映射的监听器和已有业务连接。
- 缩容时排空退休连接，覆盖普通 TCP、UDP 控制连接以及 smux/yamux/h2mux。

### Bug Fixes

- 修复并发缩容时向排空连接分配新流的竞态和退休空闲 Mux 连接清理延迟。
- 配置应用失败不推进已应用修订，目标与授权撤销仍即时关闭受影响连接。

### Verification

- 通过 Go 全量测试、vet、integration、相关 race、前端构建和三角色本地启动检查。

## [0.4.5] - 2026-10-06

### Bug Fixes

- 为 REALITY 客户端握手增加 15 秒上限并响应取消。
- 将绑定认证改为不可变索引查找，避免认证成本随绑定数量线性增长。
- 修复 Xmux 最后租约释放后的空闲连接和配置键泄漏。
- 修复 XHTTP packet-up 上传路径、并发上传失败清理和写 deadline 更新。

### Verification

- 通过 579 个合法协议配置、5 条传输路径共 2895 项测量，以及追加的 120 项 XHTTP 测量。
- 通过 Go 全量测试、vet、race、integration、前端测试、生产构建和统一镜像三角色检查。

### Upgrade Notes

- 统一镜像为 `ghcr.io/aurorax-neo/veilink:v0.4.5`，后端修复需要更新镜像，单独拉取 Web 静态资源不会更新后端。

## [0.4.4] - 2026-10-05

### Bug Fixes

- 隧道配置增量应用时保留未变化的连接和监听器，应用失败保留最后成功配置。
- 修复 XHTTP 与 REALITY 的 HTTP/2、auto、stream-up、header/cookie 组合及非法请求校验。
- 修复 REALITY listener 关闭时的数据竞争和未完成握手的取消处理。
- 修复 Web auto 模式字段、REALITY 下错误强制填写 VLESS Encryption，以及窄屏设置页布局。

### Verification

- 通过 350 组有效 XHTTP 组合、17 组非法组合、24 组大数据组合和 8 组分离下行组合。
- 通过 Go 全仓测试、vet、相关 race、integration、前端测试、生产构建和统一 Docker 镜像检查。

### Upgrade Notes

- 三种角色使用统一镜像 `ghcr.io/aurorax-neo/veilink:v0.4.4`，前端资源版本为 `web-v0.4.4`。

## [0.4.3] - 2026-10-05

### Bug Fixes

- 修复 ML-DSA 握手、加密开关和 Web 发布更新流程。
- 该版本的原始线上 Release 仅包含自动比较链接，现已补齐为按 Tag 归档的版本条目。

## [0.4.2] - 2026-10-04

### Bug Fixes

- 修复 Web 更新超时、探测目标、设置页内边距、节点接入命令和刷新节流。
- 将镜像探测改为并发执行并限制单次探测超时，避免镜像不可用时阻塞页面。
- 修复节点刷新双击造成的重复请求。

## [0.4.1] - 2026-10-04

### Bug Fixes

- 增加可持久化的 Server URL 设置，并让登录、API 和 SSE 客户端使用该地址。
- 修复设置页居中、探测结果展示和预置 Web 模式下前端版本回退。
- 改进运行时镜像健康检查参数解析并补充 `curl`。

### Maintenance

- 修正 Master 卷挂载说明并统一镜像部署文档。

## [0.4.0] - 2026-10-04

### Bug Fixes

- 移除独立前端镜像和旧的 `-backend` 镜像别名，只发布统一 Veilink 镜像。
- 清理 Master 持久化的旧 `html_dir` 路径，启动时安全处理过期配置。
- 统一 Web 发布 Tag、候选资源路径和预置前端回退逻辑。

### Maintenance

- Docker 构建默认使用官方镜像源，修复跨架构 CI 构建依赖本地镜像配置的问题。
