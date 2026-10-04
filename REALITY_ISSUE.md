# REALITY 握手问题详细报告

## 问题描述
客户端连接 REALITY 服务端时，TLS 握手失败，报错 `outer TLS record too large`。

**错误位置**：`internal/tunnel/vision_transport.go:63`
**触发时机**：`uconn.HandshakeContext(ctx)` 执行期间（`internal/tunnel/reality.go:424`）
**影响范围**：所有 REALITY 连接无法建立（VLESS/TCP/REALITY、VLESS/XHTTP/REALITY）

## 环境信息
- **服务端**：xtls/reality 库 `v0.0.0-20260908062103-8cdf7bf9c7f0`（`go.mod`）
- **客户端**：自定义实现（`internal/tunnel/reality.go`），基于 `refraction-networking/utls`
- **测试目标**：`www.bilibili.com:443`（直连可达，TLS 1.3）
- **测试端口**：服务端 18521，客户端通过 master 18110 获取配置

## 已验证正常的部分
1. ✅ REALITY 节点可通过 API 创建（`transport_security: tls` + `reality` 对象）
2. ✅ 服务端可启动并监听（`server tunnel listening addr=127.0.0.1 port=18521`）
3. ✅ 客户端可从 master 获取配置并尝试连接
4. ✅ `www.bilibili.com:443` 直连可达，TLS 1.3 握手正常
5. ✅ X25519 密钥对生成正常，`DeriveX25519Public` 验证通过

## 已排除的原因
1. **Dest 不可达**：已验证 `www.bilibili.com:443` 直连成功
2. **节点配置错误**：之前误将 `transport_security` 设为 `reality`，已修正为 `tls` + 独立 `reality` 对象
3. **SessionId 版本字节**：用户指出不需要版本号验证，已确认 xtls/reality 库不检查 SessionId[0:4]，相关代码已移除
4. **Vision 误判**：曾怀疑 Vision 的 `eligible()` 过宽导致非 TLS 流量被误判，已回退该改动，但问题依旧

## 关键代码位置

### 客户端握手（`internal/tunnel/reality.go`）
```go
// 395-424 行：构建 ClientHello 并密封 SessionId
if err = uconn.BuildHandshakeState(); err != nil { ... }
hello := uconn.HandshakeState.Hello
// ... 获取 ECDHE 密钥，计算 authKey ...
if err = sealSessionID(authKey, hello, ids[0]); err != nil { ... }
if err = uconn.HandshakeContext(ctx); err != nil {  // <-- 在这里失败
    return nil, err
}
```

### SessionId 密封（`internal/tunnel/reality.go:452-480`）
```go
func sealSessionID(authKey []byte, hello *utls.PubClientHelloMsg, shortID [8]byte) error {
    // 使用 AES-GCM 加密 SessionId[:16]
    // 明文结构：[0:4]=0（版本留空）, [4:8]=timestamp, [8:16]=short_id
    // 密文写回 SessionId，并复制到 hello.Raw[39:]
}
```
**参考**：`/tmp/ref/xray/transport/internet/reality/reality.go:166-199`

### 错误抛出（`internal/tunnel/vision_transport.go:63`）
```go
c.left = int(binary.BigEndian.Uint16(c.header[3:]))
if c.left > 18432 {
    return n, errors.New("outer TLS record too large")
}
```
**注意**：此错误虽在 Vision 文件中抛出，但触发时机是 REALITY 握手阶段，说明 utls 在解析服务端回包时读到了异常大的记录长度。

## 可能的根因（待验证）
1. **库版本不兼容**：xtls/reality 库（2026-09-08）与客户端 utls 实现可能存在协议细节差异
2. **sealSessionID 实现 bug**：AEAD 加密的参数（nonce、AAD）可能与服务端期望的不一致，导致服务端解密失败，走回落代理，客户端解析回落包时出错
3. **服务端回落异常**：服务端未识别客户端为 REALITY，转而代理到 bilibili，但回包转发有问题

## 复现步骤
1. 启动 master：`/tmp/vl4/veilink master -database /tmp/vl4/master.db -deployment-key /tmp/vl4/master.key -listen-addr 127.0.0.1:18110 -web-mode=off -embedded-server-enabled=false`
2. 获取 API Key（从 master 日志）
3. 创建 REALITY 服务端节点（参考 `/tmp/vl4/retest.sh`）
4. 创建客户端节点，启动 server 和 client
5. 创建 mapping，观察客户端日志中的 `outer TLS record too large`

## 相关文件
- `internal/tunnel/reality.go`：客户端 REALITY 实现
- `internal/tunnel/vision_transport.go`：错误抛出位置
- `internal/tunnel/vision_recognition.go`：Vision 识别逻辑（已回退过度对齐）
- `/tmp/ref/xray/transport/internet/reality/reality.go`：xray 参考实现
- 测试脚本：`/tmp/vl4/retest.sh`
- 测试日志：`/tmp/vl4/srv2.log`, `/tmp/vl4/cli2.log`

## 建议排查方向
1. 对比 xray 客户端的 `sealSessionID` 实现，检查 nonce（`hello.Random[20:]`）、AAD（`hello.Raw`）是否一致
2. 在服务端开启 debug 日志，确认是否收到 ClientHello、解密是否成功、是否走回落
3. 抓包对比 xray 客户端与 veilink 客户端的 ClientHello 差异
4. 检查 xtls/reality 库的版本更新日志，看是否有协议变更
