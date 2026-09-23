# Veilink 提示词

把下面某一段原样贴给编程代理。不要删约束。代理应先读仓库里的真实代码，再改；没跑过的检查不能写成已通过。

## 1. 新会话

```text
你在维护 Veilink，一个 Go 单二进制的 TCP 内网穿透工具。模块路径 veilink。角色是 master、server、client，由子命令区分。

数据面在 internal/tunnel，进程内实现 VLESS 反向通道和私有 mux。不要嵌入 Xray，不要改 ref/，不要声称能和 Xray 客户端互通。数据面不经过 master。只转发已配置的 TCP 目标，不做开放代理。UDP 映射、自动证书、多租户、P2P、远程 shell 都不做。

控制面是 TLS gRPC 加管理 API。master 的 bind_addr 同时做三件事：提供 html/ 静态页面、提供 /api、接受节点 gRPC。页面和 API 必须同源。不要再加一套明文管理端口，也不要让浏览器跨源直连 API。登录用 Secure Cookie 和 X-CSRF-Token，SameSite=Strict。跨站写请求保持拒绝。

发布物只有两份：bin/veilink 和 html/。html/ 由 frontend 里 npm run build 生成，不编进 Go 二进制。master 按 html_dir、VEILINK_HTML_DIR、./html、可执行文件旁的 html、可执行文件上一级的 html 查找 index.html。找不到时 API 仍要能用，GET / 说明文件缺失。

管理界面是 frontend/ 下的 Vue 3 + TypeScript + Vite。只展示 API 真实返回的节点、绑定、映射和审计。不要发明流量、在线布尔或目标可达。近期在线只是本机用 last_seen 做的 90 秒估算，必须写明。注册令牌只在对话框里出现一次，不进 localStorage。绑定没有更新接口，不能假装能编辑。

VLESS UUID 加密存储，管理 API 要脱敏。REALITY、Vision flow、VLESS Encryption、Hysteria2 仍是可选数据面，密钥留在节点本地 YAML，master 不下发。数据面外层传输只能是证书 TLS、REALITY、Hysteria2 三者之一。

改完运行与改动相关的 go test 和 frontend 的 npm run build。不要改 .pi/plan 里的历史计划，不要整文件重写 .gitignore。
```

## 2. 只改管理界面

```text
只改 frontend/。这是 Vue 3 + TypeScript + Vite，构建产物输出到仓库根的 html/。最终用户通过 veilink master 的 HTTPS 打开页面，不是长期开着 Vite。

开发时可以用 npm run dev，Vite 把 /api 代理到 https://127.0.0.1:8443，浏览器仍视为同源。生产路径是 npm run build 之后，由 internal/console 从 html/ 提供 index.html 和 assets。资源路径保持相对，能在 bind_addr 的根路径打开。不要加内联脚本，CSP 是 script-src 'self'。

接口保持：GET /api/session，POST /api/login 返回 csrf，POST /api/logout，写请求带 X-CSRF-Token，fetch 使用 credentials: 'same-origin' 和 cache: 'no-store'。节点、绑定、映射、审计的字段以 internal/model 和 internal/httpapi 为准。绑定只能创建和删除。映射启停走完整 PUT。

界面用中文。保留空态、错误、加载、确认和窄屏。不要虚构指标，不要把心跳写成服务可达。令牌关闭对话框后从 DOM 移除。改完执行 npm run build，并说明还没在浏览器里点过的流程。
```

## 3. 只改 master 如何提供页面

```text
管理页面的源码在 frontend/，发布目录是仓库根 html/。Go 侧只负责把这个目录从 master 的 bind_addr 提供出去，和 /api、节点 gRPC 共用一个 TLS 监听。实现放在 internal/console，不要把 Vue 打进二进制，也不要恢复旧的内嵌模板。

查找顺序：配置 html_dir、环境变量 VEILINK_HTML_DIR、进程当前目录 html/、可执行文件目录 html/、可执行文件上一级 html/。显式目录必须包含 index.html，否则 master 启动失败。自动查找失败时不要阻止 API，GET / 返回明文说明 console html not found。

静态文件禁止目录列出。HTML 不缓存。/assets/ 可以长缓存。只允许 GET 和 HEAD。沿用现有 CSP，不要放宽 script-src。Docker 镜像把构建好的 html 放到 /usr/local/html，对应二进制 /usr/local/bin/veilink 的上一级。补测试：缺文件、能读到 index.html、assets 不列目录。
```

## 4. 只改控制面 API 或节点同步

```text
只改控制面。涉及 internal/httpapi、internal/store、internal/control、internal/node、api/control/v1。不要改数据面帧格式，除非这项任务明确要求。

管理 API 继续：JSON、DisallowUnknownFields、Cookie 会话、CSRF、登录限速。未知 YAML 字段仍然失败。新增配置要用 VEILINK_ 前缀的环境变量覆盖，规则和现有 bool/int/string 一致。

节点同步保持：期望版本和已应用版本分开，心跳不是目标可达，Apply 失败不能报成功，重复修订号但内容不同要报错，更旧的修订号拒绝。配置应用可以短暂停连接。一次性注册令牌有过期时间。绑定 UUID 不出现在管理 API 响应里。

页面如果要展示新字段，只加 API 真实会返回的字段，并同时改 frontend/ 的类型和对应视图。不要让前端跨源调用。
```

## 5. 只改数据面

```text
只改 internal/tunnel 及其测试。这是进程内的 VLESS 反向通道，不是 Xray 适配层。可以参考 ref/Xray-core 的行为，不要复制它的代码，也不要改 ref/。

保持：VLESS v0、16 字节 UUID、只支持 TCP 命令、然后是私有 mux。UDP 仍然拒绝。每个绑定自己的 UUID、反向域名和路由。server 只接受已登记身份、反向域名和端口 0。client 只拨已启用映射的精确目标。

可选层仍然互斥：证书 TLS、REALITY、Hysteria2 三者只能开一个。flow 只有空、none、xtls-rprx-vision（-udp443 只是别名）。decryption 只在 server，encryption 只在 client，不能同时设置。Hysteria2 不是任意 UDP 代理，也没有 Salamander。pool 只属于 client，范围 1 到 32。

改协议时补往返测试。不要把密钥、short id、Hysteria2 密码放进 master 的下发快照。
```

## 6. 发布检查

```text
按发布形态检查，不要改功能。

1. cd frontend && npm run build，确认仓库根出现 html/index.html 和 html/assets。
2. go build -o bin/veilink ./cmd/veilink。从仓库根目录启动 master，浏览器打开 https://<bind_addr>/ 能看到登录页，/api/session 在同一主机名上返回 JSON。
3. 临时移走 html/index.html，确认 GET / 说明 console html not found，而 /api 仍可登录。
4. go test ./internal/console/ ./internal/master/ ./internal/config/ ./internal/httpapi/。
5. 确认 Docker 最终镜像同时有 /usr/local/bin/veilink 和 /usr/local/html/index.html。
6. 不要把 html/、bin/、证书、数据库提交进 git。
```

## 7. 不要做

```text
不要做这些事：

- 不要把 frontend 再嵌回 Go 模板，也不要引入第二套管理端口。
- 不要让页面和 API 分属两个源之后还指望 Cookie 登录成功。
- 不要在界面里写演示节点、假流量或“在线=目标端口通”。
- 不要把注册令牌、VLESS UUID、REALITY 私钥、Hysteria2 密码写进浏览器存储或管理 API 响应。
- 不要复制 ref/Xray-core 或 ref/frp-panel 的代码。
- 不要为了过编译去放宽 CSP、关掉 CSRF，或把 Sec-Fetch-Site 跨站拒绝删掉。
- 不要声称没运行的测试已经通过。
```
