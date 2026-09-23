# 第三方组件与开源许可证声明

本项目采用 [Apache License 2.0](LICENSE) 开源发布。

Veilink 的控制面（TLS gRPC / HTTP REST API）和数据面（VLESS 反向隧道、私有多路复用 Mux 与 XUDP 数据报封装）均为 Go 语言原生进程内实现，**未嵌入或动态调用 Xray、frp 或任何其他第三方外部代理内核二进制**。

---

## 1. Go 直接与间接依赖组件

| 依赖模块 | 用途说明 | 开源许可证 |
| :--- | :--- | :--- |
| `google.golang.org/grpc` | 控制面双向通信、gRPC 事件流与配置同步 | Apache-2.0 |
| `google.golang.org/protobuf` | 控制协议序列化与反序列化 | BSD-3-Clause |
| `modernc.org/sqlite` | 纯 Go（无 CGO）嵌入式 SQLite 存储驱动 | BSD-3-Clause（底层 SQLite 核心为 Public Domain） |
| `modernc.org/libc`, `mathutil`, `memory` | modernc 运行时支撑库 | BSD-3-Clause |
| `golang.org/x/crypto` | 密码 Bcrypt 哈希、ChaCha20-Poly1305 加密 | BSD-3-Clause |
| `golang.org/x/net`, `sys`, `text`, `exp` | 网络传输与系统调用基础库 | BSD-3-Clause |
| `gopkg.in/yaml.v3` | 启动与运行时 YAML 配置文件编解码 | MIT / Apache-2.0 |
| `lukechampine.com/blake3` | VLESS Encryption 密钥派生与哈希计算 | MIT / CC0-1.0 |
| `github.com/xtls/reality` | 数据面可选 REALITY 服务端握手与认证回落 | MPL-2.0 |
| `github.com/refraction-networking/utls` | 数据面 REALITY 客户端 TLS 指纹模拟 | BSD-3-Clause |
| `github.com/quic-go/quic-go` | 数据面可选 Hysteria2 (QUIC) 传输支持 | MIT |
| `github.com/google/uuid` | UUID 规范校验与标识生成 | BSD-3-Clause |
| `github.com/dustin/go-humanize` | 人类可读格式化辅助 | MIT |

---

## 2. 前端管理控制台依赖 (`frontend/`)

`frontend/` 是独立的 Vue 3 + TypeScript 静态单页应用。构建产物输出为静态文件并由 Master 统一通过内置 HTTP 服务器提供服务，完全解耦。

| 模块 | 用途 | 开源许可证 |
| :--- | :--- | :--- |
| `vue` | 前端渐进式响应式 UI 框架 | MIT |
| `vite` | 前端构建与开发热重载工具（仅编译期） | MIT |
| `typescript` | 类型系统与类型检查（仅编译期） | Apache-2.0 |
| `vue-tsc` | Vue 单文件组件类型检查工具（仅编译期） | MIT |
| `@vitejs/plugin-vue` | Vite Vue 3 SFC 编译插件（仅编译期） | MIT |
| `@vitejs/plugin-basic-ssl` | 本地开发环境自签名 HTTPS 证书插件（仅编译期） | MIT |

---

## 3. 参考资料（不参与构建，不参与发布）

- `ref/Xray-core`（MPL-2.0）：
  仅作为协议细节设计（VLESS 协议帧结构、Vision 伪装模式特征及 VLESS Encryption 报文规范）的只读技术规范参考。本项目在 `internal/tunnel` 中根据规范进行了全新的独立原生 Go 代码实现，未直接复制、链接或篡改任何外部源码。
- `ref/frp-panel`（AGPL-3.0）：
  仅作为集群架构设计（Master 集中控制、节点长连接事件流与反向配置拉取）的架构思路参考。本项目所有业务逻辑、数据库模型、管理 API 及前端视图均为全新原创实现，未引用、复制或分发任何其代码或界面资源。

参考仓库 `ref/` 目录已被 `.dockerignore` 和构建脚本排除，**绝不参与任何构建、编译或镜像打包**。
