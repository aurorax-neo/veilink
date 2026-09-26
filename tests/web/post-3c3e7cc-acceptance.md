# 3c3e7cc 后真实浏览器 Web 验收

## 环境与结果

- 被测源码：`3c3e7ccc29e0e5cb5863dfc6a408e9785f26a002`，未重做 Host/SNI/mux 代码修改。
- 本地 Go 构建 + Vue 生产构建；Master HTTP `127.0.0.1:19843`，独立 scratch 数据库/key，内置节点关闭。不使用用户数据库。
- Playwright 驱动本机 Brave/Chromium 无头真实浏览器，使用独立浏览器上下文。无 mock API；注册、登录、节点/映射写入均通过实际 UI 与真实后端完成。
- 桌面视口 1440×1000；窄屏视口 390×844。截图为 fullPage，长页面高度可超过视口。
- 30 张 PNG 已核对格式和尺寸，复制至 `~/Desktop/veilink-shots/`，逐文件 SHA-256 一致。
- 浏览器 pageerror 为 0；API 无非预期错误。预期的错误密码登录和未认证会话检查返回 401。
- 测试结束后浏览器关闭、测试 Master 停止；未 push、未部署，未修改/删除已有用户数据。

## 通过项

1. 首次注册、登录页、错误密码拒绝、正确登录、仪表盘空态与写入后状态。
2. 服务端创建：监听地址标签、多连接地址、自签证书生成、保存重开保留配置；无独立 SNI/优先级控件。查看下发客户端模板。
3. 客户端创建和名称编辑；关联映射后详情显示真实服务端下发模板，内容只读。
4. TCP mux 为单一下拉：关闭/smux/yamux/h2mux；默认关闭；四个选项逐个保存并重开确认。无 mux checkbox。
5. TCP → UDP 清空 mux 并禁用选择；切回 TCP 保持关闭。
6. 映射启用/停用确认与持久化；删除确认弹窗取消后数据保留。
7. 真实 Master INFO 日志显示、自动刷新启停；真实审计记录及搜索。
8. 节点搜索空态与恢复；快捷接入弹窗可打开/关闭。
9. 六个页面窄屏截图及 DOM 尺寸断言：无整页横向溢出，表格内部滚动保留。
10. 退出登录回到登录页，受保护 `/api/nodes` 返回 401。

## 边界与执行说明

- 首轮脚本误点顶部“停用”筛选按钮，后改为表格行操作定位；审计最初用表格断言，后按实际 `.timeline li` 修正。修正后相关验收通过，未因此修改产品代码。
- 未宣称逐像素人工审图；以上是浏览器操作、DOM/API 断言及实际截图证据。
- HTTP 环境未执行要求 HTTPS 的快捷接入命令生成/令牌吊销；未启动真实 Server/Client 节点，不验证在线心跳、配置应用和业务隧道吞吐。
- 未逐一验证 REALITY/Hysteria2/Encryption 配置组合、PEM 上传、所有错误/加载分支或实际删除节点；因此这里的“全页面验收”不是穷尽全部协议功能。
- 本次重新构建 Go 和前端生产资源，运行浏览器验收与 `git diff --check`；未重跑 Go/race/integration/Docker 全套测试，前次代码验收结果不计作本次重新执行。

## 截图列表

下列文件均位于 `tests/web/screenshots/`；桌面副本位于 `~/Desktop/veilink-shots/`，文件名相同。

- `post-3c3e7cc-01-register.png`
- `post-3c3e7cc-02-login.png`
- `post-3c3e7cc-03-login-error.png`
- `post-3c3e7cc-04-dashboard-empty.png`
- `post-3c3e7cc-05-server-editor.png`
- `post-3c3e7cc-06-server-persisted.png`
- `post-3c3e7cc-07-server-client-template.png`
- `post-3c3e7cc-08-servers.png`
- `post-3c3e7cc-09-clients.png`
- `post-3c3e7cc-10-mux-off.png`
- `post-3c3e7cc-11-mux-smux.png`
- `post-3c3e7cc-11-mux-yamux.png`
- `post-3c3e7cc-11-mux-h2mux.png`
- `post-3c3e7cc-11-mux-closed.png`
- `post-3c3e7cc-12-udp-cleared.png`
- `post-3c3e7cc-13-mappings.png`
- `post-3c3e7cc-14-dashboard.png`
- `post-3c3e7cc-15-logs-info.png`
- `post-3c3e7cc-16-audit.png`
- `post-3c3e7cc-17-narrow-dashboard.png`
- `post-3c3e7cc-17-narrow-servers.png`
- `post-3c3e7cc-17-narrow-clients.png`
- `post-3c3e7cc-17-narrow-proxies.png`
- `post-3c3e7cc-17-narrow-logs.png`
- `post-3c3e7cc-17-narrow-audit.png`
- `post-3c3e7cc-18-onboarding.png`
- `post-3c3e7cc-19-delete-confirm.png`
- `post-3c3e7cc-20-client-effective.png`
- `post-3c3e7cc-21-search-empty.png`
- `post-3c3e7cc-22-logout.png`
