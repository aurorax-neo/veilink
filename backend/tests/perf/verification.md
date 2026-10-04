# 验收与清理记录

## 验证

- 77 个合法配置 × TCP/UDP × 3 轮 = 462 条测量；重新运行汇总器与 `results.md` 完全一致。Pool=4 三组的三轮中位数已逐项核对。
- 已通过：`cd backend && go test ./...`、`cd backend && go vet ./...`、tunnel/node/control/master race、integration 端到端测试、前端 27 项测试、前端生产构建及 `git diff --check`。
- 另通过 QUIC 控制夹具的小样本 race 检查。
- 无 Docker CLI，使用 Podman 构建三角色目标并检查内容。Podman 默认 OCI 输出警告 HEALTHCHECK 被忽略，因此这不是 Docker HEALTHCHECK 运行验证。
- `git -C ref/Xray-core status --short` 为空。未 commit、push 或远程部署。

## 清理范围

仅清理本轮 `matrix-perf`、`xray-perf` 临时目录、`localhost/veilink-perf-check:{master,server,client}`、构建日志确认的两个中间镜像及本轮拉取的三个基础镜像。不使用全局 prune；保留其他项目镜像、既有 bin、web/dist、发布归档及共享工具链缓存。

清理已执行：两个临时目录已删除；Podman 已删除上述三角色、两个中间镜像及三个基础镜像，复查镜像列表不再含这些资源，`podman ps -a` 为空。进程检查未发现 `matrix-perf/` 或 `xray-perf/` 下的运行程序。清理后 `git diff --check` 通过。

## 未解决：原有 HTML 产物被生产构建覆盖

前端生产构建覆盖了原有的忽略目录 `html/`。基线哈希核对发现：

- `html/index.html` 原 SHA-256：`364e2ac1ed3868a9f07e5df435f32c2beea29db5ee75b2d63c3dc9e5c9124ae9`，当前内容已变。
- 原 `html/assets/index-DLTk8sSZ.js`（SHA-256：`d80f8e685771db2c269ba955a4c23dcc110fbf30a7f51d94ebd30ce636020038`）缺失，当前构建生成 `index-CCUzD_Yd.js`。
- CSS 与 favicon 和基线一致。

在工作区、当前会话 scratch 和既有发布归档中未找到原始 JS；归档中的其他 JS 不是同一版本，未冒充恢复。保留当前完整可用的构建输出，未仅替换 index 引用制造缺失资源。需要原始产物备份才能精确恢复。因此本轮**不能宣称零遗留或完全保留了原有构建产物**。其余基线记录文件只有本任务的 `performance_test.go` 发生变化。
