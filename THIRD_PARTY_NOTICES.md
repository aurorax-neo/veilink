# 第三方组件与参考资料

Veilink 的控制面和 VLESS 反向数据面均为进程内实现，不嵌入 Xray 或其他代理内核。使用下列第三方 Go 模块。实际固定版本及间接依赖以 `go.mod` / `go.sum` 为准；分发者还应保留其分发方式所需的第三方版权与许可证。

| 组件 | 用途 | 许可证 |
| --- | --- | --- |
| google.golang.org/grpc | 控制面 TLS RPC 与事件流 | Apache-2.0 |
| google.golang.org/protobuf | 控制协议消息 | BSD-3-Clause |
| modernc.org/sqlite | 无 CGO SQLite 驱动 | BSD-3-Clause（SQLite 核心为公有领域；其他间接模块见各自许可证） |
| golang.org/x/crypto | 密码哈希等密码学工具 | BSD-3-Clause |
| gopkg.in/yaml.v3 | 启动配置解析 | MIT / Apache-2.0 |

## 参考资料（不参与构建）

`ref/Xray-core` 使用 MPL-2.0，启动时提交为 `d562d894`。Veilink 只参考其 VLESS 请求头和 reverse bridge/portal 的职责划分，自行实现 TCP/TLS 上的 VLESS v0 握手和私有复用帧，不链接、不修改、不复制该仓库代码。

`ref/frp-panel` 启动时 HEAD 为 `1a58b85`，使用 AGPL-3.0。Veilink 仅参考其节点注册、双向事件通知、配置拉取和状态回报的架构思路；不复制其实现、页面、资源或生成代码，也不将 FRP 作为数据通道。

参考仓库不参与 Veilink 的构建；无需将 `ref/` 复制到构建环境中。

