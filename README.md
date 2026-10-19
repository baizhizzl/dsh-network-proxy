# dsh-network-proxy

DeepSeek Harness（DSH）插件：在 **设置 → 通用设置** 增加一行 **HTTP 代理**，支持 **直连 / 跟随系统 / 自定义** 三种模式，**保存后立即生效，无需重启 Harness**。

[![topic: dsh-plugin](https://img.shields.io/badge/topic-dsh--plugin-2b7489)](https://github.com/topics/dsh-plugin)

通过 GitHub `dsh-plugin` topic 发布与发现（无市场索引）。

- 包名：`@local/dsh-network-proxy`
- 平台：Windows（系统代理读取 WinINET）、macOS（`scutil --proxy`）
- 许可：MIT

## 为什么需要它

Harness 自带的 `@deepseek-ai/dsh-http-proxy` 只在启动时读一次 `HTTPS_PROXY` 等环境变量，且明确不读取操作系统代理设置（见其 README 的 “Known Limitations”）。于是：

- 只在代理软件里打开了“系统代理”的用户，模型请求仍然直连；
- 想换代理就得改环境变量并重启 Harness；
- MCP、命令工具、网页抓取各自为政。

本插件补上这一段运行时能力：读取操作系统代理（含 PAC），把它装到进程级 `fetch` dispatcher 上，并且**原地热切换**。

## 功能

1. **系统代理检测**
   - Windows：读取 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` 的 `ProxyEnable` / `ProxyServer` / `ProxyOverride` / `AutoConfigURL`；
   - 支持 `http=…;https=…` 分协议代理与 PAC 脚本（内置精简 PAC 求值器，按目标域名求值）；
   - macOS：`scutil --proxy`；
   - 系统代理开关关闭时，界面会显示检测到的代理地址，方便你去系统里打开。
2. **热切换**：从 Harness 自带的 `undici` 取全局 dispatcher，用 `ProxyAgent` 按目标 origin 路由；保存时直接替换，下一次请求即生效。模型、MCP HTTP、web 搜索/抓取、各命令工具里的 `fetch()` 全部覆盖。
3. **旁路**：`localhost`、`127.0.0.0/8`、`::1`、`0.0.0.0` 永远直连；系统旁路列表（`<local>`、`*.example.com`、`10.0.0.0/8`、`127.*` 等）一并生效。
4. **子进程**：把策略同步到 `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` / `NODE_USE_ENV_PROXY`，命令工具里的 `curl`、`git`、`pnpm` 会跟随。
5. **持久化**：选择写入 `$DSH_HOME/network-proxy.json`，下次启动由 Host 半自动应用；插件卸载/停用会恢复启动时的 dispatcher 与环境变量。

## 安装

### 方式一：让 Agent 用插件管理器安装

在 Harness 会话里说：

> 安装插件 https://github.com/baizhizzl/dsh-network-proxy

Agent 会调用 `plugin_manager` 的 `install_bundle`，参数为：

```
git+https://github.com/baizhizzl/dsh-network-proxy.git
```

### 方式二：本地目录

```text
plugin_manager install_bundle  target: /path/to/dsh-network-proxy
```

安装后打开 **设置 → 通用设置**，在“会话显示”下方即可看到 **HTTP 代理**。

> 修改过 Client 半之后如果页面没有立刻显示，关闭再打开设置（或刷新页面）即可；Host 半与设置值不需要重启。

## 三种模式

| 模式 | 行为 |
|---|---|
| 直连 | 丢弃代理；进程内 `fetch()` 与子进程都直连 |
| 跟随系统 | 读操作系统当前代理；系统代理开关关闭时直连，并在界面上显示检测到的代理地址 |
| 自定义 | 使用填写的 `http://host:port`（可带 `user:pass@`），保存后立即生效 |

默认是 **跟随系统**。

## 影响范围

- 覆盖：Harness 进程内所有走 Node 内置 `fetch()` 的出口（模型、MCP HTTP、web fetch/search、插件）。
- 子进程：同步代理环境变量（见上）。
- 不覆盖：桌面窗口自身的 Chromium 网络栈（它本来就跟随系统代理）；遥测（走 `node:http`，设计上直连）；模型生成的 PTC/workflow 子进程（其环境由 Harness 自己的代理策略管理）。

## 项目结构

```
index.js            Host 半：系统代理检测、dispatcher 安装与恢复、/api/network-proxy 路由
client.js           Client 半：settings.general.item 中的偏好行（中英文文案、状态展示）
cordis.patch.yml    插入 network-proxy 插件行
locale/{zh,en}.json 插件标题与描述（Plugin Manager 展示）
icon.svg            插件图标
test/host.test.mjs  Host 半验证脚本
```

## 本地验证

Host 半的验证脚本在真实的 Harness 运行时（Electron as Node）里执行，用本地假代理验证 HTTP 转发、HTTPS CONNECT、loopback 旁路、环境变量发布、持久化与卸载恢复；配置只写临时目录。

```powershell
$env:ELECTRON_RUN_AS_NODE = '1'
& '<Harness 安装目录>\DeepSeek Harness.exe' '<仓库目录>\test\host.test.mjs'
```

## 已知限制

- 只接受 `http://` / `https://` 代理；SOCKS 会被识别并在界面上提示“暂不支持”。
- PAC 求值器覆盖常见的 `shExpMatch` / `dnsDomainIs` / `isInNet` / `isPlainHostName` 等辅助函数；`dnsResolve` 返回空串（避免在同步求值里做 DNS），复杂 PAC 可能退化。
- 系统代理凭据（`ProxyServer` 里带用户名密码的少见情况）不会被解析；自定义模式支持 `user:pass@`。
- 修改系统代理本身（例如在代理软件里开关“系统代理”）不会被实时感知，点“重新检测”或重新打开设置即可刷新。

## License

[MIT](LICENSE)
