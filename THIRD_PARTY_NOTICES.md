# 第三方组件与开源许可证声明

Veilink 原创代码及文档（另有声明者除外）采用 **GPL-3.0-or-later**：GNU GPL 第 3 版或由您选择的 FSF 后续版本。完整 GPLv3 正文见 [LICENSE](LICENSE)，授权声明见 [NOTICE](NOTICE)。第三方代码保持各自的版权、许可证与免责声明，不能用根许可证覆盖或删除。

本项目不运行 Xray、frp 等外部代理内核二进制；这不等于没有第三方源码依赖。HY2 BBR 通过 Go 模块引用下述 Xray MPL 代码，并含一个 MPL 适配文件，不作“全部独立实现、从未复制或链接 Xray 代码”的笼统声明。

## 1. Go 直接依赖及 mux 传递依赖许可核查

以下版本来自本次核查时的 `go.mod`；smux/yamux 为传递依赖，其余列项为直接依赖。许可依据为这些精确版本的本地 Go 模块缓存内文件，不是仅凭项目名称推测。此表不替代上游完整法律文件，也不是所有传递依赖或发布镜像的完整清单。

| 模块与核查版本 | 许可结论 | 核查文件 |
| :--- | :--- | :--- |
| `github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e` | MIT | `LICENSE`（quic-go authors & Google, Inc.） |
| `github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af` | BSD-3-Clause | `LICENSE`（Go Authors） |
| `github.com/xtls/xray-core v1.260327.1-0.20260920225103-d562d8947d31` | MPL-2.0 | `LICENSE`（与 `ref/Xray-core/LICENSE` 一致） |
| `github.com/xtls/reality v0.0.0-20260908062103-8cdf7bf9c7f0` | MPL-2.0；Go 派生部分另保留 BSD-3-Clause | `LICENSE`（Copyright (c) 2023 RPRX）、`LICENSE-Go` |
| `golang.org/x/crypto v0.57.0` | BSD-3-Clause | `LICENSE` |
| `golang.org/x/net v0.59.0` | BSD-3-Clause | `LICENSE`（Go Authors） |
| `google.golang.org/grpc v1.83.2` | Apache-2.0 | `LICENSE`、`NOTICE.txt` |
| `google.golang.org/protobuf v1.36.12` | BSD-3-Clause | `LICENSE` |
| `lukechampine.com/blake3 v1.4.1` | MIT；该模块根许可并非 MIT / CC0 双许可 | `LICENSE`（Copyright (c) 2020 Luke Champine） |
| `modernc.org/sqlite v1.46.1` | 驱动 BSD-3-Clause；SQLite 核心 Public Domain | `LICENSE`、`SQLITE-LICENSE` |
| `github.com/metacubex/sing-mux v0.3.10` | GPL-3.0-or-later | `LICENSE`（Copyright (C) 2022 nekohasekai） |
| `github.com/metacubex/sing v0.5.8` | GPL-3.0-or-later | `LICENSE`（Copyright (C) 2022 nekohasekai） |
| `github.com/metacubex/smux v0.0.0-20260105030934-d0c8756d3141` | MIT | `LICENSE`（Copyright (c) 2016-2017 xtaci） |
| `github.com/metacubex/yamux v0.0.0-20250918083631-dd5f17c0be49` | MPL-2.0 | `LICENSE`；本次 Go 源码与 README 检索未见另行采用 Exhibit B |

### REALITY 的 MPL Exhibit B

该精确版本的 `LICENSE` 包含标准 MPL-2.0 全文及 Exhibit A、Exhibit B。Exhibit B 的示例句出现在标准许可证附录中，**仅出现这个附录不等于上游已对代码另行附加“不兼容次级许可证”声明**。本次检查模块内 34 个可读文本文件，相关语句仅在 `LICENSE` 的定义、条款和标准附录中出现，未发现文件头或其他法律声明另行采用 Exhibit B。因此本次记录为 MPL-2.0，而非凭附录直接判为 `MPL-2.0-no-copyleft-exception`；同时保留 `LICENSE-Go` 的 BSD 义务。这是对所检查版本的记录，不是对未来版本或所有潜在权利的保证。

## 2. HY2 BBR 的来源与集成清单

- **BBR 来源**：[XTLS/Xray-core](https://github.com/XTLS/Xray-core)，本地 `ref/Xray-core`，已核对 commit `d562d8947d3175db86b4fa849742433a9876cb63`，目录 `transport/internet/hysteria/congestion/bbr`，按该仓库 `LICENSE` 为 **MPL-2.0**。本次检索未在其标准 MPL 正文以外发现另行采用 Exhibit B 的声明。
- **QUIC 版本**：`github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e`，本地缓存 `LICENSE` 为 **MIT**，Copyright (c) 2016 the quic-go authors & Google, Inc.。它是独立的第三方组件，不因组合而丢失 MIT 声明。
- **集成方式**：固定版本 Go 模块引用，实际链接 Xray 的 `transport/internet/hysteria/congestion/bbr` 及 `congestion/common`；没有引入 Xray 代理内核。`internal/tunnel/hysteria_bbr.go` 改编自该 commit 的 `congestion/utils.go`，保留 MPL-2.0 文件头、版权与来源；本地修改为窄连接接口、固定 `standard` profile、去除 Brutal/Reno 选择，保留初始包大小保护。`internal/tunnel/hysteria.go` 在 Client/Server 认证成功后、业务流前调用适配器，测试位于 `hysteria_bbr_test.go`。模块引用仍须随分发提供适用法律文件和对应源码，不能以“没有复制到仓库”为由省略义务。
- 没有复制 mihomo 内核实现或 UI。TCP mux 对照 `ref/mihomo/docs/config.yaml` 的 `smux.protocol`，通过上述 Go 模块实际使用 `smux`、`yamux`、`h2mux` 协议；不把 Veilink 旧私有 framing 改名成这些协议。sing-mux/sing 的 GPL、smux 的 MIT、yamux 的 MPL 法律材料和对应源码须随分发按各自许可提供。`ref/mihomo/LICENSE` 同时是根目录标准 GPLv3 正文的本地来源。

## 3. 其他依赖与参考资料

Go 传递依赖还包括 `modernc.org/libc`、`modernc.org/mathutil`、`modernc.org/memory`、`golang.org/x/sys`、`golang.org/x/text`、`golang.org/x/exp`、`github.com/google/uuid` 等 BSD-3-Clause 组件，以及 `github.com/dustin/go-humanize` 等 MIT 组件。传递依赖、子目录另行声明及最终打包内容仍须逐项保留和复核；QUIC 组件应按最终依赖图区分 fork 与上游，不视为同一个版本。

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
