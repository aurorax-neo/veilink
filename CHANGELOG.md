# Changelog

本项目所有重要变更均记录于此文件。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循
[Semantic Versioning](https://semver.org/lang/zh-CN/)。正式发布时，GitHub Actions
只提取当前 SemVer 版本段落作为 Release Notes，不再把多个版本的内容拼接到同一条
Release。

## [Unreleased]

## [0.4.18] - 2026-11-08

### Features & Improvements

- 支持 `server` / `client` 节点在无法连接 Hub（Master）时通过 Hub 直接导出含完整运行参数的脱机/混合版本：
  - Hub 的 `/api/v1/nodes/{id}/join` 接口及前端“快捷接入”弹窗新增一键复制 **脱机含参 Docker 启动命令**、**脱机含参单二进制启动命令**，并支持一键导出/复制 `state.json` 脱机配置文件。
  - `server` 与 `client` 子命令新增 `-bootstrap-state`（兼容 `-offline-state`）参数，支持传入 Base64 编码参数、JSON 字符串或脱机文件路径；首次启动即刻应用内嵌的隧道、绑定与端口映射配置，无需依赖 Hub 网络可达，且在网络恢复时自动使用预置长期凭据与 Hub 同步。

## [0.4.17] - 2026-11-05

### Bug Fixes

- 修复节点访问未备案域名或跨网控制面（如 `vl.vekt.cc.cd:8843`）被运营商 DPI 按 TLS `ClientHello` 明文 SNI 注入 `TCP RST`（`SSL_ERROR_SYSCALL` / `os error 104`）及公共 DNS 解析失败的问题：当常规 TLS 握手被重置或超时时，自动使用纯净 UDP DNS（`119.29.29.29` / `180.76.76.76`）并回退为省略明文 SNI 扩展的 TLS 握手（仍严格校验服务端 `*.vekt.cc.cd` 证书并携带加密层 `Host` 头路由），且支持 `-master-addr https://<IP>:端口 -control-server-name <域名>` 直连模式。
- 修复隧道双向打流期间 `ping_interval.tick()` 在 `tokio::select!` 中取消未完成的 `read_frame` 导致帧边界错位断流的问题：将会话保活 `FRAME_PING` 拆分为独立异步任务，并在发送 `FRAME_RESET` 前先释放流接收端以避免通道满时死锁，同时为 XHTTP 响应头统一立即 `flush`。

## [0.4.16] - 2026-11-05

### Bug Fixes

- 修复端口映射限速（`bandwidth_limit`）在高带宽（`>130Mbps`）或小分片下因 `sleep_us > 1000` 阈值截断失效以及多并发连接未共享配额的问题：引入映射级共享令牌桶 `BandwidthLimiter`（50ms 突发窗口 + 动态读取分片），将上行/下行限速置于流读取侧，并补齐 UDP 映射限速。
- 修复各节点状态刷新与事件上报不及时的问题：为 `Ring` 与 `tunnel::Runtime` 增加异步状态变更通知（`Notify`），移除 `refresh` 时多余的快照重拉取（`PATH_PULL`），在控制面 SSE `node` 事件中补齐 `node_id` 字段并优化刷新等待窗口，使节点链路建立/断开、日志与手动刷新在单次 RTT 内即时上报。
- 提升隧道在持续流量与高并发下的稳定性：为服务端与客户端隧道会话增加 15 秒 `FRAME_PING` 保活与 45 秒读空闲超时检测，移除收到 `FRAME_HALF` 后 10 秒强制中断活跃对端传输的逻辑，消除 `FRAME_PING` 回复与分流通道阻塞，并修复 XHTTP `packet-up` 会话按创建时间误淘汰活跃连接及上行连接断开后自动重连重放。

## [0.4.15] - 2026-11-05

### Bug Fixes

- 修复节点通过 HTTPS/反向代理连接 Master 控制面时偶发 `Connection reset by peer (os error 104)` 的问题：支持 TLS `h2` / `http/1.1` ALPN 协商与回退、持久连接池复用、TCP Keepalive、IPv4 优先双栈拨号及瞬时传输错误自动重试。
- 修复内嵌 `default` 节点心跳排空 Master 全局日志环形缓冲区导致远程节点与 Master 日志被覆盖为 `default` 的问题，并将 `Ring` 日志注入 `tunnel::Runtime` 以完整采集各节点隧道事件。

## [0.4.14] - 2026-11-05

### Features

- 后端全量迁移至 Rust（Tokio + Axum + Hyper + Rustls + Quinn），移除全部 Go 代码；单二进制通过 `rust-embed` 内嵌 Web 静态资源，统一承载 `master`、`server`、`client` 三种角色，100% 兼容既有 `veilink.db`、`master.key` 与节点 `state.json` 永久凭证。
- 控制面由 gRPC 切换为纯 HTTP JSON（`/api/control/{enroll,pull,events}`，支持 `?wait_ms=` 长轮询即时唤醒），天然兼容 Nginx / Caddy 等标准 HTTP 反向代理，无需配置 `grpc_pass`。
- 管理台接入服务端事件流 SSE（`/api/v1/events`），节点心跳、隧道状态、流量统计与日志变更实时推送至前端并按需增量刷新，显著降低操作与状态感知延迟。
- 原生 Rust 实现完整隧道与安全协议栈：VLESS、REALITY（TLS 1.3 + X25519 + ShortID + 回落保护 + ML-DSA-65 后量子证书签名 + Chrome/Firefox/iOS ClientHello 指纹）、VLESS Encryption（X25519 / ML-KEM-768 0-RTT/1-RTT + native/xorpub/random）、Vision（零任务状态机）、Hysteria2（QUIC/HTTP3 QPACK `/auth` `233`）、XHTTP（`packet-up` / `stream-one` / `stream-up` / `auto` 及分离下行端点）与多路复用（`smux` / `yamux` / `h2mux` / `XUDP`）。
- 优化 Web 控制台交互：节点与映射编辑器统一采用居中弹窗，打开已配置节点时自动解析并完整回填已存储配置（从 X.509 证书反推有效期天数、自动识别 VLESS Encryption 模式、恢复 Flow 与 XHTTP 参数）；优化设置页、审计页（分类筛选、检索与 100 条分批加载）与登录页（移除密钥框提示并将退出按钮改为“注销登录”）。
- 补齐节点接入令牌签发（`node.enroll.token`）、撤销（`node.enroll.revoke`）与凭证重置（`node.credential.reset`）的数据库审计记录及前端中文标签，并支持通过 `VEILINK_TRUSTED_PROXIES` 配置受信任反代 IP。

### Bug Fixes

- 对齐 Xray-core 的 XHTTP `auto` 模式选择策略（REALITY 默认选 `stream-one`、配置下载端点选 `stream-up`、非 REALITY 选 `packet-up`），修复 REALITY + XHTTP `auto` 组合校验并在前端编辑器自动显示为只读有效模式。
- 统一前后端时区为 `Asia/Shanghai`（`UTC+8`），并在前端同步服务端响应头时钟偏移，彻底消除浏览器与服务端微小时间差导致的“时钟超前”误报。
- 修复 `VisionStream` 与 `RealityTlsStream` 在底层连接返回 `Poll::Pending` 时的帧缓冲背压跟踪，防止高负载网络背压下重复编码发送或缓冲滞留。
- 为 Master 控制面 TCP/TLS 连接增加 75 秒读写空闲超时回收（`IdleTimeoutIo`）与 HTTP/2 Keep-Alive 探测，防止空闲连接长期占用连接池信号量。
- 修复删除旧 API Key 后新建未命名 Key 触发 `UNIQUE` 约束冲突的问题；修复多路复用流 ID 回绕时跳过保留 ID `0` 与活跃流 ID；将 `RealityReplayCache` 升级为 `HashMap + VecDeque` 实现 $O(1)$ 满容量淘汰；支持节点拨号与目标转发的 IPv4/IPv6 双栈 DNS 回退。
- 移除 Hysteria2 客户端 `SkipServerVerification`，未配置自定义 CA 时默认使用 `webpki-roots` 系统根证书池，非空无效 `ca_pem` 直接报错拒绝。
- 加固 XHTTP 服务端会话表：校验 `sid` 合法性、限制并发会话上限为 1024、采用 64 包有界通道与乱序窗口、增加 15 秒请求头读取超时与 4 MiB 请求体上限，并自动清理孤儿会话。
- 控制面接入 `auth_fails` 防爆破限流并增加 `X-Veilink-Auth-Rejected: 1` 认证拒绝响应头，防止反向代理或 WAF 返回的 401/403 误触发节点擦除本地永久凭证。
- 强化隧道加密初始化错误传播（禁止异常配置静默降级为明文）、服务端监听并发上限信号量、UDP `peer_streams` 回收、多路复用子流 10 秒阻塞超时、客户端异步 DNS 解析与指数退避重连，以及旧版 4032 字节 ML-DSA-65 私钥配对校验。

### Maintenance

- 对标 `clash-rs` 与 `meow-rs` 优化数据面热路径（REALITY 原地加解密与游标读取、VLESS AEAD 批量封装、XHTTP 单缓冲 chunked 写入与流水线、多路复用 16 KiB 对齐聚合读写），120 项全协议矩阵往返耗时缩短 40%~52%，单流吞吐最高提升 157%。
- 收敛 `.github/workflows/release.yml` 最小权限并补齐 `aarch64-unknown-linux-musl` 交叉编译链接器配置，更新 `README.md` 与 `THIRD_PARTY_NOTICES.md`。

## [0.4.13] - 2026-11-04

### Features

- Web 控制台构建产物通过 Go `//go:embed` 直接嵌入 `veilink` 单二进制，发布压缩包与 Docker 镜像不再依赖外部 `html/` 或 `/opt/veilink-web` 目录。
- 按照前端设计规范全面重构 Web 控制台界面：新增深色/浅色双主题切换与持久化、左侧导航 Lucide 图标、自定义版本浮层、侧边抽屉式（Drawer / 移动端 Bottom Sheet）节点与映射编辑器。
- 移除浏览器原生 `<dialog>` 与 `<details>`，统一改为受控 Teleport 浮层（400/520/720px 三档尺寸、高危操作独立 AlertDialog 与后果动作文案）及 CSS Grid `0fr -> 1fr` 折叠面板。
- 持久化当前工作台导航标签页至 `sessionStorage`，刷新页面保持上下文不丢失。

### Bug Fixes

- 彻底修复页面切换时出现两个滚动条闪烁消失的问题：移除侧栏独立滚动、表格行入场位移动画与隐藏 DOM 滚动容器，全站仅保留 `main#main.stage` 唯一垂直滚动区。
- 优化 1440px 桌面视口下服务端表格列宽与长字段换行布局，确保操作列按钮完整显示。

### Maintenance

- 更新 `.github/workflows/release.yml`、`.github/workflows/development-artifacts.yml`、`Dockerfile` 与 `Dockerfile.release` 构建与打包契约测试，适配单二进制内嵌 Web 产物。

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
