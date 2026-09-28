# 软件版本与布局验收（2026-09-27）

> 历史验收快照：下文的修订数字列表、截图与「未 push/未发布」仅描述 2026-09-27 当时的实现和检查；v0.1.0 的节点列表只显示配置是否最新，当前发布与部署说明请以根目录 README 为准。

## 方案与参考

- `internal/buildinfo.Version/Commit` 是唯一构建身份来源，按常见 Go `-ldflags -X` 注入。开发版本为 `dev`，提交独立显示；版本 tag 可显式注入，不使用 git describe 长串或配置修订号拼装软件版本。
- CLI、认证 `/api/version`、统一镜像使用同一身份；手动 workflow 的六平台归档和镜像统一注入 `dev` / `GITHUB_SHA`，仍仅 workflow_dispatch，不新增推送或发布行为。
- 节点 `software_version/software_commit` 仅来自认证心跳，管理接口只读；未上报显示“未上报”，不拿 Master 版本代替。内存保存，重启待重新上报，不修改 schema，不进入授权快照。版本上报不是二进制真实性证明。
- rN 明确为“配置修订”，列表分行“期望 rN”“已应用 rN”；状态为尚无配置/待应用/已应用/应用失败/不再同步。r0/r0 不再误报版本一致。未实现软件自动升级，故没有虚构期望软件版本或自动升级成功状态。
- 参考 `ref/frp-panel/conf/version.go`、`build.sh` 的版本/提交分离；参考其 `www/components/ui/dialog.tsx` 居中弹窗和 `table.tsx` align-middle 单元格。保留 Vue/native dialog，不引入新 UI 框架。
- 参考 `ref/mihomo/docs/config.yaml` 的 smux/yamux/h2mux 协议名称，映射列表显示实际协议而非“mux 开”；保留默认关闭、UDP/XUDP 不受 TCP mux 影响，不声称与 mihomo 全协议互通。

## UI 修复

- 节点表格列宽按内容分配，单元格垂直居中；操作按钮不拆字，长 ID/版本列表省略，详情保留全文。
- Modal 显式水平/垂直居中，长表单仅内容区滚动，标题栏与按钮栏保持可见；两列表单对齐，窄屏单列。
- 顶部版本短标签从真实 API 获取，提交哈希独立详情；失败状态可重试，不阻断管理数据加载；窄屏详情限制在视口内。

## 实际检查

- `go test ./...`、`go vet ./...` 通过。
- `go test -race ./internal/store ./internal/control ./internal/node ./internal/httpapi ./internal/master ./internal/tunnel` 通过。
- `go test -tags integration -count=1 ./tests/integration` 通过，138.644 秒。
- 前端 `node --test tests/*.mjs` 32/32，TypeScript/Vite 生产构建通过。
- `actionlint .github/workflows/development-artifacts.yml` 与构建契约测试通过；未远端运行 workflow。
- 独立 scratch 数据库/密钥/状态、真实 Master/Server/Client 进程：节点报告 dev 和同一注入提交，配置 r8/r8 收敛；12 秒观察内心跳推进。TCP 关闭/smux/yamux/h2mux 分别回显 15360/16384/17408/17408 字节，UDP/XUDP 回显成功。
- Brave/Playwright 不 mock API；12 张 DPR=2 截图。6 组桌面/窄屏 Modal 断言中心误差为 0、未出视口、内容无横向溢出、按钮栏可见；桌面监听地址/端口输入框顶边对齐，表格 vertical-align=middle；浏览器 pageerror 为 0。
- `docker build --build-arg VERSION=dev --build-arg COMMIT=<验收时HEAD> -t veilink:version-ui .` 成功，镜像 ID `ef2e0ababf23`。三角色实际启动、注册/接入，均 healthy，静态 HTML 存在；容器节点配置 r2/r2 收敛。
- 三角色二进制 SHA-256 相同：`6cb9d2b95089bd9219eff8a06c485453263e0cbc9816d4fb665a8b386ad9c823`。CLI、Master API、节点上报均为 dev / `681d30f6a267a5c91c07b5f3f8176236da450f00`。这是验收构建时注入的前置 HEAD，包含当时未提交改动，不是本次最终提交或发布产物的身份声明。
- 容器 smoke 检查使用隔离网络命名空间，并非生产 Docker 网络拓扑；业务回显使用独立本机进程。
- 截图复制到桌面，逐文件 SHA-256 一致。`git diff --check` 通过。

## 本次截图

仅更新改动页面。仓库 `tests/web/screenshots/` 与桌面 `~/Desktop/veilink-shots/` 同名：

1. `version-ui-01-client-revisions.png`
2. `version-ui-02-build-details.png`
3. `version-ui-03-client-modal.png`
4. `version-ui-04-server-revisions.png`
5. `version-ui-05-server-form.png`
6. `version-ui-06-mapping-form.png`
7. `version-ui-07-mux-list.png`
8. `version-ui-08-dashboard.png`
9. `version-ui-09-client-narrow.png`
10. `version-ui-10-modal-narrow.png`
11. `version-ui-11-server-form-narrow.png`
12. `version-ui-12-mapping-narrow.png`

桌面截图 2880×2000，窄屏 780×1688。旧截图仅历史证据，本轮不删除无关图片。

## 剩余生产验证缺口

- 本轮成功标准已完成，不据此宣称所有生产环境就绪。公网/NAT/多机、丢包、长稳、容量及跨平台原生运行仍需目标环境验收。
- 没有穷举 REALITY/Vision/Encryption/Hysteria2 与 mux/UDP 所有组合，未重跑历史性能 benchmark。
- 未验证生产 HTTPS 终止/h2c 反代、远端 Actions/GHCR 权限和多架构远端构建；未 push、未发布、未部署。
- 软件身份是构建注入和认证节点自报，不是供应链签名验证；Web 身份来自 Master，不独立声称任意手工替换静态资源的版本。
- 截图通过 DOM/几何/像素尺寸与哈希断言，未做逐像素人工审图。
