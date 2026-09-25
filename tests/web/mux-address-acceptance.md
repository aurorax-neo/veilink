# mux / Server 公网地址浏览器验收

## 环境与边界

- 2026-09-25，本机 Playwright 1.63.0 驱动真实 headless Brave Chromium 153.0.8010.53；桌面 1440×1100，窄屏 390×844。
- 隔离 Go Master：`127.0.0.1:19743` HTTPS，全新 scratch DB/证书/部署密钥，关闭内置 Server。`go build ./cmd/veilink` 成功；使用指定 `$PI_SCRATCH_DIR/mihomo-mux-acceptance/html`，JS `index-CaXolzie.js`，CSS `index-DsD7caIv.css`，未使用仓库历史 `html/`。本轮未重跑前端构建/typecheck。
- 首次注册、登录、创建 Client/Server、生成 TLS 自签证书、编辑地址、创建及编辑映射均通过浏览器真实控件；没有 API 写入辅助、响应 mock 或 fixture 注入。API 辅助仅为登录会话中 GET `/api/mappings`，核对关闭及 UDP 状态的持久化值。
- 使用保留域名 `*.example.invalid` 和停用映射作为隔离测试数据；未启动外部 Server/Client、未测试三种 mux 的实际数据面或公网可达性。配置保存通过不代表隧道已应用或目标可达。

## 实测结果

| 项目 | 结果 |
|---|---|
| mux 默认及可选项 | 新建 TCP 默认未勾选且类型控件不存在；勾选默认 smux。真实 select 的 option 值精确为 smux/yamux/h2mux。 |
| 三 mux 保存重开 | 依次选 smux、yamux、h2mux，每次保存、整页刷新、重新编辑，checkbox 保持开启且选中值精确匹配。 |
| 关闭 mux | 从 h2mux 关闭后类型控件消失；保存重开仍关闭且无类型控件；GET 确认 mux=false，mux_type 为空或省略。 |
| UDP 清空 | 开启 yamux 后切 UDP，立即取消 mux、禁用 checkbox、移除类型控件；保存刷新重开仍一致，GET 确认 mux=false、mux_type 为空或省略。切回 TCP 不恢复 mux，再勾选回到默认 smux，而非旧 yamux。 |
| Server Host/Port/SNI | 浏览器创建后再编辑为 edge-edited.example.invalid / 25443 / tls-edited.example.invalid，按新 SNI 重新生成自签证书并保存；整页刷新重开三值精确保持。本地监听端口仍为 19744，与公网 Port 独立。页面无需 kind 分类控件。 |
| B3 label | 真实 DOM 中候选名称、Host、Port、SNI、优先级、启用六控件各有且仅有一个关联 label，id 唯一；点击 Host label 实际聚焦 Host，Tab 到 Port，computed outline=solid。 |
| B4 INFO | 真实 Master 日志页加载，点击 INFO 筛选后显示两条实际日志；每条日志正文区域包含 INFO、不包含 DEBUG。不是仅检查筛选按钮或源码默认值。 |
| 窄屏/键盘/减弱动效 | 390×844 编辑映射，body/root scrollWidth 均 390、dialog 宽 356，无整页水平溢出；Escape 关闭弹窗；真实浏览器 reduced-motion=reduce 媒体查询命中并截图。未测完整焦点循环、读屏或逐帧动画。 |

最终浏览器断言 `RESULT PASS`，pageerror 数组为空。本轮目标无阻塞；首次脚本在注册转登录阶段等待不足，修正测试脚本等待并重建独立数据库后完整重跑通过，未修改应用代码。

## 新增截图

以下均在 `tests/web/screenshots/`，未覆盖历史 PNG：

- `mux-address-smux.png` — 保存刷新后的 smux。
- `mux-address-yamux.png` — 保存刷新后的 yamux。
- `mux-address-h2mux.png` — 保存刷新后的 h2mux。
- `mux-address-off.png` — 关闭并保存重开的 TCP mux。
- `mux-address-udp-cleared.png` — UDP 保存刷新后 mux 禁用、类型消失。
- `mux-address-server-persisted.png` — 地址/SNI 保存刷新后的 Server 编辑表单。
- `mux-address-info.png` — INFO 筛选下两条真实日志。
- `mux-address-narrow.png` — 390×844 编辑映射及 reduced-motion 环境。

八张 PNG 已检查签名、非空字节、尺寸；除 narrow 外均为 1440×1100。截图对密码、私钥、VLESS 解密控件使用 mask；没有生成接入 token。通过 Playwright 检查真实渲染 DOM/焦点/布局并截图；工具没有图像读取能力，不声称人工像素级审阅。本轮没有视觉实现改动，不以 BrowserPreview 静态页面替代 HTTPS 应用验收。

## 清理与未运行项

- 已关闭自建 Brave 和 Master，确认 TCP 19743 无监听；已删除自建 `mihomo-mux-acceptance/ui-browser/`（二进制、npm、脚本、DB、证书、密钥、日志）。共享父目录中已有构建及主代理日志保持不动。
- `git diff --check` 通过。仅新增本报告和上述八张 PNG；未修改应用源码、未 commit/push/部署、未操作 Docker。
- 本轮为定向浏览器验收，未重跑 Go 全量测试/vet/race、前端单元测试/生产构建、integration 或镜像验收，交由主代理单独记录。
