# 连接地址语义与自动派生配置验收

本记录对应同一提交中的代码；旧 post-3c3e7cc 截图不作为当前 UI 证据。

## 变更

- 服务端本地绑定使用「监听地址（IP）」「监听端口」。Client 拨号候选使用「主机/域名」「端口」，可多条并按序失败切换；帮助和错误提示不再把拨号地址称为监听地址。
- NodeEditor 删除独立下发配置分区、模板编辑/重置及相关状态，不读取或提交 client_tunnel。
- API 节点 POST/PUT 拒绝显式 client_tunnel（包括 null、空对象和大小写变体）；Store 仅从服务端隧道自动派生，已存结果必须与派生值一致。旧自定义模板明确报错，不自动迁移/覆盖/删库。客户端详情只读展示保留。

## 已执行验证

- 前端 30 项测试、TypeScript 检查及 Vite 生产构建通过；替换旧手改模板测试，覆盖禁止提交模板、文案、保存、生成与异步错误行为。
- Go 全量测试、vet、store/httpapi/control/node/tunnel race 通过；integration 端到端无缓存重跑通过（138.294s）。
- Playwright 驱动真实 Brave 无头浏览器，1440×1080 与 390×844，连接本地真实 HTTP Master，使用全新 scratch 数据库。未 mock API。
- UI 实际完成注册登录、创建 TLS 服务端、自签证书生成、多连接地址保存重开、创建客户端及关联映射。
- DOM 验证新标签和服务端无模板编辑按钮；节点写请求不含 client_tunnel。
- 映射创建后客户端只读详情包含派生 CA，不含服务端证书私钥/decryption；服务端重新生成证书并保存后，客户端详情 CA 随之更新。
- 浏览器 pageerror 为 0。六张新 PNG 已复制到 ~/Desktop/veilink-shots/，逐文件 SHA-256 一致。浏览器和测试 Master 已停止。
- 未进行像素级人工审图；客户端显示的是管理中心期望配置，未启动真实节点验证 applied_revision。本次未重跑 Docker 构建/角色健康检查，未 push 或部署。

## 当前截图

仓库目录 `tests/web/screenshots/`，桌面副本 `~/Desktop/veilink-shots/`，同名：

1. `auto-derived-01-server-addresses.png`：本地绑定与拨号候选文案分离。
2. `auto-derived-02-server-no-template-tab.png`：保存重开的服务端编辑页，无下发模板 Tab。
3. `auto-derived-03-mapping-created.png`：实际创建的关联映射。
4. `auto-derived-04-client-readonly.png`：映射关联后客户端只读派生配置。
5. `auto-derived-05-client-updated.png`：服务端证书更新后同步派生的只读配置。
6. `auto-derived-06-server-narrow.png`：窄屏服务端编辑页。
