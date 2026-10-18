# CFnew 精简内核

[![内核版本](https://img.shields.io/badge/内核-2026.10.17.2-blue)](https://github.com/byJoey/cfnew/releases/latest)
[![Cloudflare Workers / Pages](https://img.shields.io/badge/Cloudflare-Workers%20%2F%20Pages-F38020)](https://developers.cloudflare.com/workers/)

把代理转发留在 Cloudflare，把控制台、优选操作和订阅生成交给独立面板。内核 **37,806 字节**，较原完整版本减少约 92%。节点流量直接连接你自己的 Worker。

**[打开面板](https://cfnew.xy.kg/) · [下载最新版](https://github.com/byJoey/cfnew/releases/latest) · [视频教程](https://www.youtube.com/watch?v=EfhHV62CuEU&t=2s) · [完整变量表](./docs/variables.md)**

当前默认分支是 `core-only`。旧完整版保留在 [`main`](https://github.com/byJoey/cfnew/tree/main)，旧版发行是 [v3.1](https://github.com/byJoey/cfnew/releases/tag/v3.1)。独立面板源码在 [cfnew-panel](https://github.com/byJoey/cfnew-panel)。

## 接入面板和客户端

1. 打开 **[cfnew.xy.kg](https://cfnew.xy.kg/)**，填写自己的 **Worker 域名**和同一个 **UUID**。域名填 HTTPS 根地址，不带 UUID、路径或查询参数。
2. 在配置管理中选择协议、优选来源、出站方式等，点击保存。未绑定 KV 时可以读取环境配置、生成订阅，不能在线保存。
3. 复制面板生成的订阅地址，导入对应客户端。订阅域名是面板，节点的 SNI / Host 和实际代理入口仍是你的 Worker。

也可以[自己部署面板](https://github.com/byJoey/cfnew-panel#一键部署)。Vercel 部署步骤和可选变量 `w` 见该仓库；`w` 设置在面板项目，不要填到 Worker。

UUID、自定义路径和完整订阅链接都能用于访问你的配置，请妥善保管。“记住节点”只保存在当前浏览器，删除已保存节点不会删除 Worker 或 KV 配置。

## 先选下载文件

Windows、macOS、Linux 都用同一份文件，按部署方式选择即可。

| 部署方式 | 下载文件 | 怎么用 |
| --- | --- | --- |
| Cloudflare Pages | [Pages.zip](https://github.com/byJoey/cfnew/releases/latest/download/Pages.zip) | 整包直接上传，不用解压。包根目录只有 `_worker.js`。 |
| Cloudflare Workers | [_worker.js](https://github.com/byJoey/cfnew/releases/latest/download/_worker.js) | 在 Worker 编辑器中完整替换代码，再部署。 |
| 校验下载 | [SHA256SUMS.txt](https://github.com/byJoey/cfnew/releases/latest/download/SHA256SUMS.txt) | 用 SHA-256 核对文件是否完整。 |

仓库里的 [`pages.zip`](./pages.zip) 与发行的 `Pages.zip` 字节一致。GitHub 自动生成的 **Source code (zip / tar.gz)** 是整个仓库源码，不能直接当 Pages 部署包上传。

## 第一次部署

准备一个 Cloudflare 账号，以及自己生成的 UUID。所有示例里的域名和凭据都要换成自己的。

### Cloudflare Pages

1. 下载上面的 `Pages.zip`。
2. Cloudflare 控制台 → **Workers 和 Pages** → 创建应用 → **Pages** → 直接上传 / 上传资产。创建项目，把整个 `Pages.zip` 上传并部署。
3. 项目设置 → 变量和机密，在**生产环境**添加文本变量 `u`，值填自己的 UUID。大写 `U` 也支持。
4. 需要在面板保存设置时，创建一个 Workers KV 命名空间，在 Pages 项目的绑定设置中添加 KV，绑定名称填 `C` 或 `c`。
5. 兼容日期设置为 **`2026-01-20`**。添加变量、绑定或更改兼容日期后，重新部署，使新设置进入生产版本。
6. 使用可访问的 `pages.dev` 地址，或给项目绑定自己的域名，然后按上面的步骤接入面板。

Pages 页面若只允许拖文件夹，可把压缩包解压后上传包含 `_worker.js` 的目录，确保它在上传内容的根目录。

### Cloudflare Workers

1. 新建 Worker，先完成初始部署，再进入代码编辑器。
2. 下载 `_worker.js`，把文件内容完整粘贴到编辑器。使用 ES Module 格式，保留 `import` 和 `export default`，保存并部署；不要复制 GitHub 网页的 HTML。
3. 在设置 → 变量和机密中添加 `u`，值填自己的 UUID；需要在线保存设置时，添加名为 `C` 或 `c` 的 KV 绑定。
4. 兼容日期设为 **`2026-01-20`**，重新部署后绑定可用域名。

打开 Worker 首页显示 **`hello`** 就是本版预期行为。管理页面和订阅已经移到独立面板，不在 Worker 首页。

## 常用变量

变量设置在 **Cloudflare Worker / Pages 项目**。除 `u` 和 KV 绑定外，大多数设置可以直接在面板修改，无需逐项添加环境变量。

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `u` / `U` | 请自行设置 | 代理 UUID，也是面板的登录凭据。 |
| `C` / `c` | 未绑定 | KV 命名空间绑定，用来在线保存配置。不是普通文本变量。 |
| `d` / `D` | 空 | 自定义面板登录路径，例如 `/Admin/Panel`。 |
| `ev`、`et`、`ex` | `yes`、`no`、`no` | 分别开启 VLESS WS、Trojan WS、VLESS XHTTP。 |
| `p` / `P` | 空 | 指定 ProxyIP，支持 `host:port` 与 `[IPv6]:port`。 |
| `s` / `S` | 空 | SOCKS5、HTTP 或 HTTPS 出站代理。 |
| `qj` / `QJ` | 空 | 出站策略：空为代理优先，`no` 为直连优先，`only` 为只走代理。详见完整变量表。 |
| `yx` / `YX` | 空 | 手填优选地址列表，每行一个，可带端口和备注。 |
| `yxURL` / `YXURL` / `YX_URL` | 空 | 在线优选列表地址，搭配“仓库优选”开关使用。 |
| `jk` / `JK` | `no` | 开启家宽链式订阅，面板会提供“CLASH 家宽”入口。 |
| `freeCpu` / `FREE_CPU` | `no` | Free CPU 预算保护，达到预算会断开连接。 |

**[全部 32 项配置、环境变量别名、默认值、请求参数和 API →](./docs/variables.md)**

配置优先级是 **KV 已保存的配置 > 环境变量 > 内置默认值**。因此修改环境变量后，KV 里保存过的同名值仍会覆盖它。通过面板修改并保存，或按完整变量表说明清理对应 KV 字段。环境变量更改后需要重新部署。

## 协议与订阅

| 功能 | 当前支持 |
| --- | --- |
| 代理入站 | VLESS WebSocket、Trojan WebSocket、VLESS XHTTP。 |
| XHTTP | HTTP/2，使用 **`stream-one`**；不要改成 `packet-up`、`stream-up`，`auto` 也不作为本版兼容保证。 |
| 出站 | 直连、ProxyIP 回退、SOCKS5、HTTP、HTTPS。 |
| DNS | VLESS 的 UDP DNS 转发；不提供通用 UDP、游戏 UDP 或 QUIC 隧道。 |
| 订阅格式 | Base64 / V2Ray、Clash、Stash、sing-box、Surge、Loon、Quantumult X，按客户端适配。 |
| 家宽链式 | 开启 `jk` 后使用面板的“CLASH 家宽”订阅；依赖外部节点，速度和可用性会变化。 |

sing-box 使用 **1.12 及以上**版本的配置格式。不同客户端能用的协议不同，优先用面板提供的对应入口。精简内核不提供 Shadowsocks 入站。

| 客户端 | 协议怎么开 |
| --- | --- |
| Surge | 开启 **`et=yes`**。当前 Surge 订阅只输出 Trojan，默认仅开 VLESS 时不会生成代理节点。 |
| Clash / Mihomo、sing-box、Loon、Quantumult X | 使用 VLESS 时保留 **`ev=yes`**。这些格式会把 XHTTP 来源转换成 WS，只开 `ex`、关闭 `ev` 会使生成的 VLESS 节点不可用。 |
| 支持 XHTTP 的客户端 | 开启 `ex=yes`，通过 Base64 / VLESS 分享链接导入，保持 HTTP/2、`stream-one`。 |

优选只改变客户端连接的入口地址，节点的 Host / SNI 仍使用你的 Worker 域名。第三方 ProxyIP、在线优选源、订阅转换服务和家宽节点的可用性由各自提供方决定。

## 优选地址怎么填

优选域名、优选 IP、仓库优选默认开启，IPv4 / IPv6 与三网筛选也默认开启。有手填列表时优先使用手填内容。

```text
104.16.1.1:443#手填IPv4
[2606:4700::1111]:8443#手填IPv6
edge.example.com:443#手填域名
```

每行一个，也支持英文逗号分隔。端口会保留到订阅；IPv6 带端口时必须加方括号。上述地址只用于说明格式，不代表从你的位置连接一定可用。

在线列表填到 `yxURL`，并开启“仓库优选”。可以获取在线列表、筛选、测试，然后把勾选结果覆盖或追加保存。

检测由面板服务器发起，使用你的 Worker 域名作为 Host / SNI。显示的是**面板服务器视角**的延迟，实际体验以客户端测试为准。Vercel 的 IPv6 在线检测可能受平台出站限制，不代表 IPv6 节点一定不可用。

手填优选列表上限 **262144 字符**，配置请求正文上限 **1 MiB**。更大的列表改用在线 URL。

## 自定义路径登录

设置 `d=/Admin/Panel` 后，在公共面板的第二项填 `/Admin/Panel` 或 `Admin/Panel` 即可。支持多级路径、中文与前后斜杠，**大小写必须一致**。

登录成功后面板会读取真正的代理 UUID，并用 UUID 生成稳定入口。因此更改 `d` 后，原来已复制的 UUID 订阅仍可用。`d` 是管理入口，`tp` 用于 Trojan 密码与 XHTTP 兼容路径，两者用途不同。UUID 和自定义路径接口可以同时使用。

旧内核若不支持自定义路径登录，可以先用 UUID 进入，再更新 `_worker.js`。

## Free CPU 保护

配套版本 **`2026.10.17.2`** 新增，默认关闭。可在面板开启并保存，或设置 Worker 变量 `freeCpu=yes` / `FREE_CPU=yes`；KV 中的设置优先。

开启后，单条连接上下载共用 **384 KiB / 96 个数据块**的预算。超过任一项就主动断开，客户端需要重新连接。新连接重新计算，重试出站不会重置当前预算。开关修改对新连接生效。

这是流量和处理次数预算，**不能保证免费账号 CPU 零超限**。正在进行的下载、视频和长连接可能中断，也不保证自动续传。旧内核缺少该功能时面板会提示升级。

## 从旧完整版升级

1. 备份原有 Worker 代码，记下原 `u`、KV 绑定、域名和兼容日期。
2. 上传本版 `_worker.js` 或 `Pages.zip`，**保留原 UUID 和原 KV 绑定**，兼容日期设为 `2026-01-20`，重新部署。
3. 打开独立面板，用原域名和 UUID 登录，确认保存的配置仍在。
4. **重新复制面板生成的订阅到客户端。** 旧 `https://Worker域名/UUID/sub` 或 Worker `/sub` 地址不再生成订阅。
5. 检查协议和客户端兼容性；本版 XHTTP 使用 `stream-one`，不支持的旧协议需在面板重新选择。

上传内核不会主动清空 KV。切换前保留旧代码，可以按原样重新上传回退；回退到完整版时也换回该版本的订阅入口。

面板与核心同版时不显示更新提示。不一致或旧内核没有版本标记时，面板会显示双方版本和下载入口。

## 常见问题

| 现象 | 先检查 |
| --- | --- |
| 打开 Worker 只有 `hello` | 正常。请从独立面板登录。 |
| 面板无法接入 / 鉴权失败 | 域名是否可公网访问、`u` 是否已部署、UUID 是否一致；自定义路径检查大小写。Cloudflare Access 或验证码挑战会阻断 API。 |
| 能生成订阅，但保存失败 | KV 是否绑定为 `C` 或 `c`，是否绑定到生产环境，绑定后是否重新部署。 |
| 改环境变量不生效 | 先重新部署，再检查 KV 里是否已有同名配置覆盖它。 |
| Worker 的旧订阅地址失效 | 从独立面板重新复制订阅。 |
| 客户端订阅拿到 `hello` / HTML | 检查是否用了 Worker 首页，或面板被 Vercel 登录保护拦住。 |
| XHTTP 不通 | 开启 `ex`，使用支持该协议的客户端、HTTP/2 和 `stream-one`。 |
| 下载一会儿就断 | 检查 Free CPU 保护；开启后达到预算会主动断开。 |
| Pages 上传失败 | 使用发行里的 `Pages.zip`，别上传整个源码包；解压检查 `_worker.js` 是否在根目录。 |

## 版本与发行

- 当前内核 / 配套面板版本：**2026.10.17.2**。
- [本版完整发行说明](./docs/releases/2026.10.17.2.md) · [历次发行](https://github.com/byJoey/cfnew/releases)。
- 本次补齐文档与发行入口，代理核心代码保持该版本，默认分支切换不会自动修改已经部署的 Worker。

维护者在 `core-only` 更新后，可运行以下命令校验和打包：

```bash
python3 scripts/package-release.py --output dist --tag v2026.10.17.2
```

脚本会检查内核版本、仓库 `pages.zip` 与 `_worker.js` 一致，再生成 `Pages.zip`、`_worker.js`、`SHA256SUMS.txt`。推送匹配版本的 `v20*` 标签后，由本分支工作流创建发行；每个版本的说明放在 `docs/releases/版本号.md`。不要对旧版 `main` 打新内核标签。

## 来源与交流

沿用项目来源说明：基于 [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel) 修改，ProxyIP 部分参考 [cmliu](https://github.com/cmliu)，反代 IP 来源包括 [qwer-search](https://github.com/qwer-search)，在线优选接口来源包括 [白嫖哥](https://t.me/bestcfipas)。独立面板及其第三方规则的许可见 [cfnew-panel](https://github.com/byJoey/cfnew-panel)。

[博客](https://joeyblog.net) · [YouTube](https://youtube.com/@joeyblog) · [Telegram](https://t.me/+ft-zI76oovgwNmRh)

本项目供学习与网络技术研究，请遵守当地法律及所用平台的服务条款。
