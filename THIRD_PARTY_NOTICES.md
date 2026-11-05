# 第三方组件与开源许可证声明

Veilink 原创代码及文档（另有声明者除外）采用 **GPL-3.0-or-later**：GNU GPL 第 3 版或由您选择的 FSF 后续版本。完整 GPLv3 正文见 [LICENSE](LICENSE)，授权声明见 [NOTICE](NOTICE)。第三方代码保持各自的版权、许可证与免责声明，不能用根许可证覆盖或删除。

本项目不运行 Xray、frp、mihomo 等外部代理内核二进制；后端自 `v0.4.14` 起已全部迁移至原生 Rust 实现（`backend/Cargo.toml`），不再包含或链接任何 Go 模块代码。

## 1. Rust 后端直接依赖许可核查

以下直接依赖来自 `backend/Cargo.toml`（精确锁定版本见 `backend/Cargo.lock`）。此表不替代上游完整法律文件，也不是所有传递依赖或发布镜像的完整清单。

| Crate 名称 | 用途 | 开源许可证 |
| :--- | :--- | :--- |
| `tokio`、`tokio-util`、`tokio-stream` | 异步运行时与 I/O 工具 | MIT |
| `axum`、`tower`、`http`、`http-body`、`http-body-util` | Web / API 与控制面 HTTP 路由处理 | MIT |
| `hyper`、`hyper-util`、`h2` | HTTP/1.1 与 HTTP/2 协议栈及 `h2mux` | MIT |
| `rustls`、`tokio-rustls`、`hyper-rustls`、`rustls-pemfile`、`rustls-pki-types` | TLS 1.2/1.3 协议栈与 PEM 解析 | Apache-2.0 OR ISC OR MIT |
| `webpki-roots` | Mozilla 根证书集 | MPL-2.0 |
| `quinn` | QUIC 传输层实现（用于 Hysteria2 与 HTTP/3） | MIT OR Apache-2.0 |
| `rusqlite`（含 `bundled` SQLite） | SQLite 数据库存储驱动 | MIT（SQLite 核心为 Public Domain） |
| `x25519-dalek`、`ed25519-dalek` | X25519 密钥交换与 Ed25519 签名 | BSD-3-Clause |
| `ml-kem`、`fips204` | ML-KEM-768 与 ML-DSA-65 后量子密码算法 | Apache-2.0 OR MIT |
| `aes`、`aes-gcm`、`chacha20poly1305`、`ctr`、`hkdf`、`hmac`、`sha2`、`subtle` | 对称加密、AEAD、摘要与常时间比较 | Apache-2.0 OR MIT |
| `blake3` | BLAKE3 哈希 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| `p256`、`rcgen` | ECDSA P-256 与自签/CA 证书生成 | Apache-2.0 OR MIT |
| `yamux` | Yamux 多路复用协议实现 | MIT OR Apache-2.0 |
| `rust-embed` | 前端静态资源单二进制内嵌 | MIT |
| `serde`、`serde_json`、`uuid`、`url`、`regex`、`chrono`、`base64`、`hex` | 序列化、编码与通用基础库 | MIT OR Apache-2.0 |
| `socket2`、`parking_lot`、`rand`、`anyhow`、`thiserror`、`tempfile` | 套接字控制、并发原语与错误处理 | MIT OR Apache-2.0 |

## 2. 协议参考与实现说明

- **协议设计参考**：VLESS、REALITY、VLESS Encryption、Vision、XHTTP 的握手报文格式与状态机转换对照 `Xray-core`、`clash-rs`、`meow-rs`、`mihomo` 的协议规范在 Rust 中独立编写，未嵌入上述外部项目的二进制或 Go 源码。
- **多路复用与 QUIC**：`yamux` 与 `h2` 直接使用对应开源 Rust crate；`smux` 与 `XUDP` 帧封装在 `backend/src/tunnel/` 中由 Rust 原生实现；Hysteria2 基于 `quinn` QUIC 传输层与标准 HTTP/3 `/auth` 握手协议实现。

## 3. 前端依赖与参考资料

`frontend/` 是 Vue 3 + TypeScript 静态页面，仅 Master 提供其构建产物。以下保留前端主要组件的许可索引；不是本次 Go 直接依赖核查的覆盖范围，发布应以锁文件与实际产物另行审计。

| 模块 | 用途 | 开源许可证 |
| :--- | :--- | :--- |
| `vue` | 前端 UI 框架 | MIT |
| `vite` | 构建工具（编译期） | MIT |
| `typescript` | 类型系统（编译期） | Apache-2.0 |
| `vue-tsc` | 类型检查（编译期） | MIT |
| `@vitejs/plugin-vue` | Vue SFC 编译插件（编译期） | MIT |
| `@vitejs/plugin-basic-ssl` | 开发 HTTPS 插件（编译期） | MIT |

`ref/frp-panel`（AGPL-3.0）仅作为架构参考，未引入其代码或界面资源。`ref/` 参考检出本身不是发布资源；从上游复制到正式源码目录或通过模块引用的代码仍属于第三方组件，不能用排除 `ref/` 打包来否认其许可义务。不要改写 `ref/` 或 vendor 内的第三方许可证。

## 4. 兼容性与分发义务

以下是工程合规说明，不是法律意见或兼容性保证；应按实际代码、分发方式和适用法律复核，必要时咨询专业人士。

1. **整体与组件许可分开**：MIT、BSD-3-Clause、Apache-2.0 通常允许与 GPLv3 作品组合，但仍须满足原许可的版权、许可副本、免责声明、修改标注及适用 NOTICE 等要求；Apache-2.0 与 GPLv3 的兼容性不表示它与 GPLv2-only 兼容。不能把所有依赖重新标成项目自己的 GPL 原创代码。
2. **MPL 与 GPL 的组合路径**：对于未被标为 Incompatible With Secondary Licenses 的 MPL-2.0 Covered Software，MPL 第 3.3 条允许在符合条件的 Larger Work 中额外按次级许可证（包括 GPLv3）分发，使接收者可按 MPL 或相应次级许可证继续分发。须履行 MPL 的原有要求并保留来源和声明；这不是任意删除 MPL 或把上游项目整体改为 GPL 的授权。若后续发现实际采用 Exhibit B 或其他不兼容条件，应停止沿用此结论并重新审查。
3. **源码分发**：保留适用版权、许可证及免责声明，清楚标注本地修改和日期。MPL 覆盖文件及其修改须按适用条款提供源码与许可告知，不应将复制的 MPL 内容混入标称纯原创的文件而不记录来源。
4. **二进制、镜像和前端产物分发**：按 GPL 第 6 条适用方式向接收者提供与实际产物匹配的完整 Corresponding Source，包括所需源码、依赖版本、本地补丁及构建/安装脚本；网络下载可按第 6(d) 条提供等价的免费源码下载并在产物旁明确指引。仅给项目主页、上游链接或 `go.mod` 不自动满足对应源码义务。涉及 User Product 时还须评估安装信息要求。
5. **随附法律材料**：分发时提供 `LICENSE`、`NOTICE`、本声明及实际组件的完整许可/版权材料；特别保留 gRPC 的 `NOTICE.txt`、REALITY 的 `LICENSE` 与 `LICENSE-Go`、Xray BBR 的 MPL 文本和 QUIC 的 MIT 文本。MPL 可执行形式分发须告知接收者对应 Covered Software 源码如何取得；二进制条款不得限制其源码权利。本索引不是这些完整法律文件的替代品，也不表示镜像已经包含它们。
6. **使用不等于分发**：GPL 不以单纯运行或无副本转移的网络交互为由自动要求公开私有修改；实际转交镜像、二进制或浏览器前端代码则须评估分发义务。基础镜像、系统软件与独立聚合组件仍分别适用其许可证。未经实际发布审计，不应声称整个镜像已完成法律合规。
