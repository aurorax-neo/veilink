# Veilink 管理界面

Vue 3 源码在这里。发布时不把前端打进 Go 二进制。

`npm run build` 把静态文件写到仓库根目录的 `html/`。`veilink master` 从 `bind_addr` 提供这个目录，浏览器打开 `https://<bind_addr>/`，`/api` 与页面同源。

开发时可以单独起前端，Vite 只代理 `/api`：

```sh
npm install
npm run dev
```

打开 **https://127.0.0.1:5173**。证书不受信任，只用于本机。master 需已在 **https://127.0.0.1:8443** 运行。代理目标用 `VEILINK_API` 覆盖。

改完后执行 `npm run build`，再从仓库根目录启动 master 验收。找不到 `html/index.html` 时，API 仍可用。

界面只展示管理 API 的真实数据。没有流量图。注册令牌只在生成后的对话框里出现，关闭即从页面移除，不写入浏览器存储。
