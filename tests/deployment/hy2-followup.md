# HY2 半关闭缺陷续接复测

本轮开始 HEAD 为 `56c5d5d45bf7b3b2dc7ea8dcd242357732fc9690`。该提交已包含用户指定的 HY2 修复，不是待修复版本；本轮检查既有清单并重新执行测试，没有重复改写已修复生产代码或放宽测试。

## 根因与参考

Hysteria2 / 无 Encryption / 无 Vision / TCP / mux off 的并发半关闭 EOF 原因是：包装器缺少写侧半关闭，同时拨号端在流结束后立即关闭整个 QUIC 连接，截断排队响应。既有修复提供流级 CloseWrite/FIN，正常读 EOF 后保持连接至反向服务端消费响应 FIN，受运行取消/空闲超时约束；异常及时清理。

本轮核对 `ref/Xray-core/transport/internet/hysteria/conn.go`：其 interConn.Close 对流 CancelRead/Close，不在此处立即关闭整个共享 QUIC 连接。另核对使用中的 apernet/quic-go Stream.Close 为发送侧 FIN、Context 取消不等于数据已获确认。Veilink 连接生命周期不同，未照搬共享连接结构、未复制参考实现、未添加私有确认帧或固定 sleep 掩盖错误。

## 本轮实际命令与结果

- `go test ./internal/tunnel -run '^TestProtocolMatrixRoundTrip$/^hysteria2$/^encryption=false$/^vision=false$/^tcp$/^off$' -count=50 -timeout=3m`：通过，1.018 秒，无 unexpected EOF。
- `go test ./internal/tunnel -run 'TestProtocolMatrixRoundTrip|TestHysteriaGracefulCleanupBounded|TestHysteriaRejectsCredentialsAndCancellation' -count=1 -timeout=5m`：47 个矩阵组合、释放/取消/凭据拒绝测试通过，98.116 秒。
- 同一选择器加 `-race`：通过，28.122 秒，无 race 报告。
- `PYTHONDONTWRITEBYTECODE=1 python3 tests/deployment/soak.py --image veilink:gaps347 --duration 60 --output "$PI_SCRATCH_DIR/hy2-followup/soak"`：通过。包含 100 秒 Client 断网、离线配置漂移、恢复、三角色重启后新心跳、两轮滚动与 12 次业务采样；三角色 healthy、二进制哈希一致、cleanup_remaining 为空。此轮是短回归，不冒充多天长稳。
- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/deployment -p '*_test.py' -v`：4/4 通过。
- 在新建隔离 Docker 网络、Master/Client 上实际运行 `tools/verify-node.py`：独立镜像提取基准摘要通过；仅将期望 SHA-256 改为全零则 verified=false、退出 1，版本/commit 自报相同不能绕过文件校验。容器/网络 finally 清理。
- `git diff --check` 通过。本轮无 UI/生产代码变更，不重拍截图、不重复全量构建；上一修复提交的全量验收见 `production-gaps-347.md`。

无敏感数据的结果：`evidence/hy2-followup/{soak,verify-pass,verify-reject}.json`。原始日志：本会话 `$PI_SCRATCH_DIR/hy2-followup/`。本轮仅提交复测证据，未 push、未部署。

## 既有其余问题与未决项

已记录的 harness 问题（busybox 无 httpd、公开 CA 权限、重启检查读取旧心跳、Colima 路由限制、root 读取不同 UID 的 /proc 限制）在上一提交已分别修正或切换到受信 Docker 管理通道，本轮 soak/verify 再次通过。没有将环境限制伪装为产品缺陷。

未发现指定范围内尚未解决的复现缺陷。真实多机 24–72 小时长稳、剩余协议交叉和签名供应链基准仍是先前明确的验收边界，不属于本轮新需求；未宣称已完成。
