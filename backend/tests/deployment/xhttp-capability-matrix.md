# Veilink XHTTP 能力边界

对照 `ref/Xray-core/transport/internet/splithttp/config.proto`。这是 **Veilink 双端原生协议**，不是与 Xray 对端互通的声明；未列为可配置的参考字段不能通过 Veilink JSON 偷渡：严格 JSON 会拒绝未知字段。Server 是唯一配置权威，Client 只接收派生模板。

| 参考字段 | Veilink 行为 |
| --- | --- |
| `host` | `host` 可选，限定小写 DNS 名或 IPv4、无端口；Client 只覆写 HTTP Host，Server 在创建会话前严格匹配；拨号地址及 TLS 证书验证名仍取授权连接入口，空值保持旧行为。反代必须保留 Host。 |
| `path` | `xhttp.path`；规范绝对路径，最多 256 字节；会话路径不允许重写。 |
| `mode` | 显式 `packet-up`、`stream-up`、`stream-one`；`auto` 按 Xray 的选择规则：非 REALITY 为 `packet-up`，REALITY 无下行端点为 `stream-one`，REALITY 配置下行端点为 `stream-up`。当前仍是 Veilink 双端实现，未完成 Xray 对端黑盒互通验证；见 `xhttp_auto_test.go`。 |
| `headers` | 可选受限 JSON 对象：`User-Agent`、`Accept-Language`、`X-Custom-*`，最多 8 项，每值 1–256 字节，规范化对象不超过 2048 字节；大小写重复、保留头和控制字符拒绝。GET、POST/PUT 与 HTTP/3 请求实际携带，服务端在创建会话前逐值匹配；不支持任意头（Host、Cookie、认证及转发头等会影响身份或安全边界）。见 `internal/model/xhttp_headers_test.go`、`internal/tunnel/xhttp_custom_headers_test.go`、`xhttp3_test.go`、`internal/store/xhttp_test.go`、`internal/httpapi/xhttp_test.go`。 |
| `xPaddingBytes` | 参考默认 100–1000；Veilink 空配置为兼容既有配置固定 100，新建 Web 表单默认设 100–1000。`padding_bytes` / `padding_max_bytes` 显式形成闭区间，两端随机选值；只给旧最小值时固定长度。 |
| `noGRPCHeader`, `noSSEHeader` | `no_grpc_header` 可在 `stream-up`/`stream-one` 省略流式上行请求的 `application/grpc`，`packet-up` 显式设置则拒绝；`no_sse_header` 可在所有模式省略下行 `text/event-stream`。默认保留原有类型头，禁用时仍保留无缓存和流式响应行为。 |
| `scMaxEachPostBytes` | 参考默认固定 1000000 字节；Veilink 为既有内存/请求体上限保留默认固定 32768，`max_each_post_bytes` 显式范围 1024–32768；可选 `post_bytes_max` 与其形成闭区间（不大于 32768），每个分片随机选长度，末段可短于下限。服务端按最大值限制单次请求，流模式拒绝这些字段。见 `xhttp_chunk_range_test.go`、`xhttp3_test.go`、存储/API/前端测试。 |
| `scMinPostsIntervalMs` | 参考默认固定 30 ms；Veilink 默认 0（保留旧行为，不额外等待）。packet-up 的 `min_posts_interval_ms` 可设 1–1000 ms，`max_posts_interval_ms` 可选且不得小于最小值，每次在闭区间内选择间隔；最大值为 0 时固定在最小值。从上次发起上行请求起计时，取消可打断等待。见 `xhttp_pacing_test.go`、`xhttp_pacing_range_test.go`、存储/API/前端测试。 |
| `scMaxBufferedPosts` | 参考默认队列 30；Veilink `max_buffered_posts` 为 0 时保留旧逐片背压，显式 1–32 限制服务端乱序序号窗口及等待请求数。额外 `max_concurrent_posts` 默认 1，显式 1–8 且不能超过缓冲数 + 1；Client 同一 Write 内按随机分片及节奏有限并发，Server 按序交付应用后才确认。重复、越窗、EOF 冲突拒绝，取消/超时关闭上传；只允许 packet-up/auto。见 `xhttp_buffer_test.go`、`xhttp_runtime_test.go`、`xhttp_h2c_test.go`、`xhttp3_test.go` 及 Store/API/前端测试。 |
| `scStreamUpServerSecs` | `stream_up_server_secs` / `stream_up_server_max_secs` 仅显式 stream-up：空值默认随机 20–80 秒；只给最小值时固定周期，显式范围 1–300 秒且最大值不得小于最小值。上传响应立即发送一段填充，随后按周期继续发送，Client 消费并丢弃此响应填充，不混入业务下行；上传 EOF 后结束并校验完成 trailer。取消或写入失败关闭上传并回收读取流程，不以超时或周期强行截断正常上传。HTTP/2/3 TLS 授权往返、真实响应周期/EOF/取消及 race、Store 重开/快照、API 保存和前端测试见 `xhttp_stream_policy_test.go`、`xhttp_runtime_test.go`、`xhttp3_test.go`、Store/API/节点编辑器测试。 |
| `xmux` | 显式 `xmux` 配置启用按授权入口、ServerName、CA 和完整 XHTTP 配置隔离的共享 HTTP transport 池；每个逻辑连接持有 lease，关闭只释放自身 lease，底层 transport 在无活动 lease 后按生命周期回收。HTTP/1.1、HTTP/2/h2c 和 HTTP/3 均复用对应 RoundTripper；不配置时保持每逻辑连接独立 transport。见 `xhttp_mux_test.go`、真实 XHTTP runtime/H2C/H3 回归。 |
| `xmux.maxConcurrency` | `max_concurrency` 默认 0（不限制）；显式 1–1024，达到单 transport 并发后新建 transport。 |
| `xmux.maxConnections` | `max_connections` 默认 0；显式 1–128 作为优先扩展目标，达到目标后优先复用，若并发上限要求仍可扩展；不强行中断已有连接。 |
| `xmux.cMaxReuseTimes` | `c_max_reuse_times` 默认 0（无限）；达到次数后 transport 退役，活动 lease 完成后关闭。范围 1–100000。 |
| `xmux.hMaxRequestTimes` | `h_max_request_times` 默认 0（无限）；按实际 RoundTrip 计数，达到次数后 transport 退役，活动请求完成后关闭。范围 1–100000。 |
| `xmux.hMaxReusableSecs` | `h_max_reusable_secs` 默认 0（无限）；从 transport 创建时计时，达到时长后退役，活动请求完成后关闭。范围 1–86400 秒。 |
| `xmux.hKeepAlivePeriod` | `keep_alive_period` 默认 0（关闭）；显式 1–3600 秒。H1/H2 使用授权拨号器并启用 HTTP/2 Ping，H3 使用 QUIC KeepAlive；REALITY 等自定义拨号链不被 xmux 绕过；底层 transport 由共享池 lease 生命周期管理。 |
| `downloadSettings` | `download_endpoint_id` 仅接受 Server 已启用连接入口 ID，保存/应用/绑定校验拒绝不存在或禁用入口、stream-one 和任意目的地；packet-up、stream-up 及协商为这两者的 auto，其 GET/下行使用独立授权 transport，POST/PUT/上行继续使用主入口；主/下行入口和 xmux 池隔离，入口或拨号器失败 fail closed。见 `xhttp_downlink_test.go`、XHTTP runtime、Store/API/前端测试。 |
| `xPaddingObfsMode`, `xPaddingKey`, `xPaddingHeader`, `xPaddingPlacement`, `xPaddingMethod` | `padding_obfs_mode` 启用后支持 `query_in_header`、`query`、`header`、私有 `x_` Cookie 四种请求位置，默认 `query_in_header` / `x_padding`；头仅允许 Referer（query_in_header）、X-Padding 或 X-Custom-*，与元数据/请求头配置碰撞拒绝。`repeat-x` 按原始字节区间生成；`tokenish` 使用无偏随机 base62，并按 HPACK Huffman 编码长度落在目标 ±2 字节。响应以配置头、X-Padding（query）或 Set-Cookie 携带填充并由 Client 校验；不是跨请求 Cookie 会话。未启用时保留旧 Referer 查询与响应 X-Padding，拒绝附加混淆字段。见 `xhttp_padding_test.go`、`xhttp_h2c_test.go`、`xhttp3_test.go`、Store/API/前端测试。 |
| `uplinkHTTPMethod` | `uplink_http_method` 默认 POST；显式仅允许 POST 或 PUT，三种模式均一致；下行 GET 不变。GET/HEAD/DELETE 等与下行或请求体语义冲突的方法在保存时拒绝。使用 PUT 时前置代理须允许 PUT 且禁用请求缓冲；不宣称任意 CDN 支持。 |
| `sessionIDPlacement`, `sessionIDKey`, `seqPlacement`, `seqKey` | 空值沿用规范 UUID/十进制序号的路径位置；显式 `path`、`query`、`header`、`cookie` 双端生效。query 键限 1–40 位小写 ASCII/数字/下划线，header 键限 `X-Veilink-*` 且不能覆盖 EOF/上传确认；Cookie 键必须是私有 `x_` 前缀，服务端拒绝重复、额外或畸形 Cookie，不与 Master Web 的 Cookie 认证混用。服务端还拒绝多值及多余路径/查询；序号字段仅 packet-up/auto，stream-one 无会话 ID。见 `xhttp_meta_test.go`、`xhttp3_test.go`、`xhttp_runtime_test.go`、存储/API/前端测试。 |
| `uplinkDataPlacement`, `uplinkDataKey`, `uplinkChunkSize` | `uplink_data_placement` 默认 body；packet-up 及协商为 packet-up 的 auto，其请求体仍为默认。显式 header 使用连续 `X-Veilink-Data-N` 私有头，显式 cookie 使用连续 `x_data_N` 私有 Cookie；内容为无填充 Base64URL，默认编码块分别为 4096/3072 字节，显式 `uplink_chunk_size` 为 64–8192。最多 32 块（含正好 32 块），Client 根据 Base64 编码开销、块数、填充及请求头预算自动缩小实际分片。配置阶段拒绝保留/非私有键、元数据/填充键冲突及流模式数据字段；接收阶段拒绝缺块、重复、非法编号/编码及混合请求体（包括未知长度请求体）。HTTP/1.1/2/3、缓冲并发、EOF/授权快照均有回归。 |
| `serverMaxHeaderBytes` | `server_max_header_bytes` 配置服务端请求头预算，0 默认 8192，显式仅允许 8192–32768；HTTP/1.1、HTTP/2、HTTP/3 监听器共用设置。Client 的响应头上限仍固定 8192，不随之放宽。 |
| `sessionIDTable`, `sessionIDLength` | 默认仍为规范 UUID v4；自定义可设 `hex`、`base62` 或 16–64 个互异 URL-safe ASCII 字符，长度 24–64 且须提供至少 128 位熵，使用无偏随机采样。stream-one 无会话 ID，不接受这些设置；低熵、非法字符和重复字符在保存/应用前拒绝。见 `xhttp_meta_test.go` 与存储/API/前端测试。 |

额外 Veilink 配置 `http_version`：显式 `1.1` 仅 packet-up；显式 `2` 支持 HTTPS、REALITY，以及 packet-up + 直连 HTTP + plain 回源 + VLESS Encryption 的 h2c prior-knowledge（不回退 HTTP/1.1）。REALITY 内的 HTTP/2 使用已经认证和加密的 REALITY 连接，不额外套 TLS，也不以明文传输。显式 `3` 要求 UDP 直连 HTTPS、TLS 回源且不能使用 REALITY。流模式支持 TLS 的 HTTP/2/3 和 REALITY 的 HTTP/2；REALITY 流模式缺省版本使用 HTTP/2，packet-up 缺省版本保持 HTTP/1.1。不保证 CDN 流式支持。`packet-up` 的 EOF 头和 `stream-up` 的上传完成 trailer 是 Veilink 私有扩展。健康/心跳/已应用确认不代表目标业务可达。

## 自动化覆盖

- `xhttp_matrix_test.go`：350 组有效组合，覆盖 TLS/plain/REALITY、默认及 HTTP/1.1/2/3、四种模式、Encryption 开关、REALITY ML-DSA-65 开关、TCP 无 mux/smux/yamux/h2mux 和 UDP；每组执行实际授权反向隧道往返、两个并发连接及 TCP 半关闭。另有 17 组不支持的组合明确拒绝。
- `xhttp_runtime_test.go`：24 组 header/cookie 大数据预算组合，覆盖 HTTP/1.1/2/3、缓冲开关和默认/64 字节编码块，传输 128 KiB。
- `xhttp_downlink_test.go`：8 组 TLS/plain/REALITY 分离下行往返，以及强制 GET 走下行、POST 走上行的双入口回归。
- `internal/store/xhttp_test.go`：REALITY + ML-DSA-65 四模式保存、数据库重开及授权快照派生，客户端快照不含服务端私钥/种子。
- `reality_listener_test.go`：REALITY 监听器并发关闭及父上下文取消，未完成握手的连接必须关闭，连接交接不能与关闭产生数据竞争。
- 其他 XHTTP 测试覆盖请求头、填充、元数据、PUT、乱序、取消、EOF、连接池生命周期、HTTP/3 及恶意输入。主矩阵不是所有配置字段的笛卡尔积，不构成任意 CDN 或 Xray 对端互通验证。
