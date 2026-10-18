# 变量与接口参考

适用版本：CFnew 精简内核 `2026.10.17.2`。内核负责代理转发和配置接口；页面、优选列表处理及订阅生成由独立面板负责。

## 先分清两类设置

- **Cloudflare Worker / Pages 设置**：下面的 `u`、KV 绑定和 32 个配置项都放在这里。
- **独立面板设置**：`w` 只用于自建面板限定接入的 Worker，不能写到 Worker 里代替 `u`。详见 [独立面板说明](https://github.com/byJoey/cfnew-panel)。

`u` 必须换成自己生成的 UUID。`C` 是 KV 资源绑定，不是值为某个名称的文本变量。

## 配置优先级与保存

通常按 **KV 中已保存的值 → Worker 环境变量 → 内置默认值** 取值。环境变量有多个别名时，按下表从左到右使用第一个非空值；不要同时设置多种写法。

面板保存写入 Worker 绑定的 KV，不会修改 Cloudflare 环境变量。已经在面板保存过的字段，会覆盖后来改动的同名环境变量。需要回到环境配置时，在面板重置；通过接口提交空字符串或 `null` 也能删除对应 KV 覆盖项。

没有 KV 仍可读取环境配置并生成订阅，不能保存配置或管理优选地址。修改通常影响后续请求和新连接；既有长连接不会被重新配置。KV 跨地区同步与核心的 30 秒读取缓存可能造成短暂延迟，不能承诺所有地区立刻更新。

推荐开关统一写 `yes` / `no`。协议、ECH、Free CPU、优选来源、IP 版本、运营商、家宽开关还接受 `true/false`、`1/0`、`on/off`，并归一为 `yes/no`；`ae`、`dkby`、`yxby`、`rm`、`qj` 应使用下面表内的准确值。

## 身份和 KV 绑定

| 名称及别名 | 默认/要求 | 用途 |
| --- | --- | --- |
| `u`、`U` | 必须设置自己的 UUID | 代理身份与配置接口鉴权，采用标准 `8-4-4-4-12` 十六进制 UUID 格式，读取时转小写。只能在 Worker 环境中修改，不能通过面板或 KV 改 UUID。 |
| `C`、`c` | 可选 KV 命名空间绑定 | 面板保存与优选管理所需。优先使用 `C`。内部配置 JSON 存在键 `c`；更新还会写 `c_ver`。不建议手动编辑。 |

## 协议、认证和 CPU 保护

| 配置键及环境别名 | 默认值 | 用途 |
| --- | --- | --- |
| `ev`、`EV` | `yes` | 开启 VLESS over WebSocket。 |
| `et`、`ET` | `no` | 开启 Trojan over WebSocket。 |
| `ex`、`EX` | `no` | 开启 VLESS XHTTP，使用 HTTP/2、`stream-one`。需要客户端支持，建议直接导入面板生成的链接。 |
| `tp`、`TP` | 空 | Trojan 自定义密码，留空使用 UUID。核心也接受它作为额外的 XHTTP 路径别名，但面板生成的 XHTTP 链接仍使用 UUID 前 8 位。它不控制面板登录路径，也不修改 UUID。 |
| `freeCpu`、`FREE_CPU` | `no` | Free CPU 预算保护。开启后每条连接双向合计最多 384 KiB 或 96 个数据块，超过便断开；客户端需自行重连。不是实时 CPU 计时，也不保证免费账号零超限。 |

三个协议开关全关时，系统会重新开启 `ev`，避免生成没有协议的配置。核心只提供 VLESS WS、Trojan WS、VLESS XHTTP；订阅格式名称 `ss` / `ssr` 不代表提供 Shadowsocks 入站。VLESS 的 UDP 转发仅支持 DNS 53，不提供通用 UDP 中继。

Free CPU 保护对新连接生效，上下行、首包和重试共用预算，空消息也计一次。下载、视频或其他长连接可能中断，是否重连和续传取决于客户端。关闭后恢复原有传输行为。

## 面板入口与出站

| 配置键及环境别名 | 默认值 | 用途 |
| --- | --- | --- |
| `d`、`D` | 空 | 自定义配置入口，如 `/Admin/Panel`。在独立面板的 UUID/路径栏填写同一路径；支持多级和中文，大小写要一致。原 UUID 入口仍有效。 |
| `p`、`P` | 空 | 回退 ProxyIP，支持 IPv4、IPv6、域名及端口，如 `proxy.example.com:443`、`[2001:db8::1]:443`；省略端口时沿用目标端口。主要用于直连或代理路径失败后的回退，不是客户端的优选入口。 |
| `s`、`S` | 空 | 出站 SOCKS5 / HTTP / HTTPS 代理。见下方格式与 `qj` 行为。 |
| `qj`、`QJ` | 空 | 出站方式：空=优先代理，`no`=优先直连，`only`=只走代理。必须有有效的 `s` 才能走代理；`only` 不能代替代理配置。 |
| `wk`、`WK` | 空 | 回退地址的地区偏好，如 `HK`、`SG`、`US`、`JP`。留空使用官方直连回退模式，当前内置官方直连域名为 `pp.xy.kg`。并非强制 Worker 在指定地区执行。 |
| `rm`、`RM` | 空，启用匹配 | `no` 关闭回退地区匹配；其他值沿用开启。手填 `p` 时先用 `p`，跳过地区选择。 |

### `s` 的格式

| 写法 | 协议 | 端口要求 |
| --- | --- | --- |
| `proxy.example.com:1080` | SOCKS5 | 必填端口 |
| `socks5://proxy.example.com:1080` | SOCKS5 | 必填端口 |
| `socks://proxy.example.com:1080` | SOCKS5 别名 | 必填端口 |
| `http://proxy.example.com:8080` | HTTP CONNECT | 省略端口时为 80 |
| `https://proxy.example.com:443` | TLS 连接到 HTTP CONNECT 代理 | 省略端口时为 443 |

支持 `用户名:密码@主机:端口`，例如 `socks5://user:pass@proxy.example.com:1080`。IPv6 代理写成 `[2001:db8::1]:1080`。认证解析只支持一组 `用户名:密码`，不要假定用户名或密码中包含 `:`、`@`、`/` 会被正确处理，也不要依赖 URL 百分号编码自动解码。

### `qj` 的准确行为

| `qj` | 首次连接 | 失败后的处理 |
| --- | --- | --- |
| 空 | 有有效 `s` 时通过代理连接目标，否则直连目标 | 使用 `p` 或地区回退地址；有代理时，这次回退仍通过同一个代理连接。不能把默认模式当成“代理坏了必定直连”。 |
| `no` | 先直接连接目标 | 有有效 `s` 时再通过代理连接目标；代理仍失败，才直接连接 `p` 或地区回退地址。 |
| `only` | 有有效 `s` 时通过代理连接目标 | 代理失败便结束，不回落直连或 ProxyIP。未配置有效 `s` 时仍会走直连，不能靠 `only` 单独锁住出口。 |

## 优选地址与订阅来源

这些字段由核心保存并回传给面板，实际列表获取、节点组合与格式生成在面板服务器完成。

| 配置键及环境别名 | 默认值 | 用途 |
| --- | --- | --- |
| `yx`、`YX` | 空 | 手填优选 IP / 域名，每行一个，也支持英文逗号；格式 `地址:端口#备注`。显式 IPv6 端口用 `[IPv6]:端口`。 |
| `yxURL`、`YXURL`、`YX_URL` | 空 | 在线优选列表 URL。需启用 `egi`；填写后会替代默认优选 IP 来源。可用英文逗号分隔多个 URL。推荐使用一行一个 `IP:端口#备注` 的纯文本。 |
| `epd`、`EPD` | `yes` | 将优选域名加入订阅。手填 `yx` 有域名时控制这些域名；无手填时使用内置域名。 |
| `epi`、`EPI` | `yes` | 将优选 IP 加入订阅。手填 `yx` 有 IP 时控制这些 IP；无手填且未设置 `yxURL` 时使用内置默认 IP 来源。 |
| `egi`、`EGI` | `yes` | 开启在线列表来源；填了 `yxURL` 也需开启此项。 |
| `ena`、`ENA` | `no` | 将 Worker 自己的域名作为原生地址加入订阅。 |
| `yxby`、`YXBY` | 空 | `yes` 关闭优选来源；若还需要可用节点，应开启 `ena`。 |
| `ipv4`、`IPV4` | `yes` | 内置默认 IP 来源的 IPv4 筛选。 |
| `ipv6`、`IPV6` | `yes` | 内置默认 IP 来源的 IPv6 筛选。 |
| `ispMobile`、`ISPMOBILE`、`ISP_MOBILE` | `yes` | 内置默认 IP 来源的移动线路筛选。 |
| `ispUnicom`、`ISPUNICOM`、`ISP_UNICOM` | `yes` | 内置默认 IP 来源的联通线路筛选。 |
| `ispTelecom`、`ISPTELECOM`、`ISP_TELECOM` | `yes` | 内置默认 IP 来源的电信线路筛选。 |
| `jk`、`JK` | `no` | 开启家宽链式专属订阅，使用支持链式配置的 Clash / Mihomo 客户端。不会把所有普通订阅自动替换成家宽。 |

有手填 `yx` 时，优先使用手填来源，不再叠加内置域名、默认 IP 和 `yxURL`。手填内容仍受 `epd` / `epi` 控制。运营商和 IPv4/IPv6 开关只筛选内置默认 IP 列表，不应理解为全局禁止对应 IP 版本的网络通信，也不会过滤全部手填或在线列表。

示例：

```text
104.16.1.1:443#IPv4优选
[2606:4700::1111]:8443#IPv6优选
cf.example.com:443#域名优选
```

`yx` 最多 262144 字符，其余单个文本配置字段最多 16384 字符，完整配置写入请求最多 1 MiB。超出时改用 `yxURL`。端口是否可用仍由 Cloudflare 入口与客户端决定，不能只凭保存成功判断。

## TLS、ECH 和兼容字段

| 配置键及环境别名 | 默认值 | 用途 |
| --- | --- | --- |
| `ech`、`ECH` | `no` | 给订阅节点添加 ECH 参数；开启后自动仅生成 TLS 节点。需客户端支持。 |
| `customDNS`、`CUSTOMDNS`、`CUSTOM_DNS` | `https://223.5.5.5/dns-query` | 面板订阅中的 DoH / ECH DNS 设置。不会替换核心 VLESS UDP 53 转发内部使用的 DNS 目标。 |
| `customECHDomain`、`CUSTOMECHDOMAIN`、`CUSTOM_ECH_DOMAIN` | `cloudflare-ech.com` | ECH 查询/外层域名设置，随订阅交给客户端。 |
| `alpn`、`ALPN` | 空 | TLS WS 节点的 ALPN 参数。允许空、`h3`、`h2`、`http/1.1`、`h3,h2`、`h2,http/1.1`、`h3,h2,http/1.1`；其余值按空处理。XHTTP 固定使用 `h2`。 |
| `dkby`、`DKBY` | `no` | `yes` 仅生成 TLS 节点，不生成 HTTP 明文入口节点。它不会在核心网络层拒绝所有非 TLS 请求。 |
| `ae`、`AE` | 空，关闭 | 优选地址管理接口开关。当前版本请在面板开启“允许 API 管理”并保存到 KV；只有环境变量 `ae=yes` 不足以打开该接口，见下方说明。 |
| `homepage`、`HOMEPAGE` | 空 | 兼容保留字段，可存取；精简内核的根首页固定返回 `hello`，当前不会按该字段反代或展示其他主页。 |
| `scu`、`SCU` | `https://url.v1.mk/sub` | 兼容保留的订阅转换地址。当前独立面板内置生成上述订阅格式，不应把它当作必须部署或必定请求的外部转换服务。 |

节点真正连接的地址可以是优选 IP，但 TLS SNI 和 WS Host 仍应使用自己的 Worker 域名；面板已经替你生成，通常不要手改成面板域名。

## WebSocket 节点的 path 参数

只有下面四项能在单个 WebSocket 节点的 `path` 查询串里覆盖全局配置；名字必须使用小写。优先级为 **非空且有效的 path 参数 → KV → 环境变量 → 默认值**，不写回 KV。

| 参数 | 用途 | 示例 |
| --- | --- | --- |
| `p` | 当前连接的回退 ProxyIP | `p=proxy.example.com:443` |
| `wk` | 当前连接的回退地区 | `wk=SG` |
| `rm` | 当前连接是否匹配回退地区 | `rm=no` |
| `s` | 当前连接的出站代理 | `s=socks5://user:pass@proxy.example.com:1080` |

```text
/?ed=2048&p=proxy.example.com:443
/?ed=2048&wk=SG&rm=no
/?ed=2048&s=socks5%3A%2F%2Fuser%3Apass%40proxy.example.com%3A1080
```

编辑分享链接时，这是链接 `path` 字段内部的查询串；整个 `path` 再由客户端或链接编辑器编码，不能误写成分享链接的顶层参数。代理字符串包含 `&` 等保留字符时要对其作为参数值进行 URL 编码。

`p` 非空时优先用指定的回退地址，`wk` 不再负责选择回退目标。空参数不能用来清除全局配置；无法解析的 `s` 会回到全局代理。`qj`、`freeCpu`、`ev`、`yx` 等不支持 path 覆盖。XHTTP 不使用这四项 WS 覆盖逻辑，应通过面板/KV/环境配置。

## 核心配置接口

下面的 `<入口>` 为 UUID，或已设置的 `d`。这些接口在 **Worker 域名**下，和独立面板 `/sub` 不同。路径大小写要一致。

| 方法与路径 | 用途 | 条件 |
| --- | --- | --- |
| `GET /` | 返回 `hello` | 无需 UUID |
| `GET /<入口>/api/config` | 读取有效配置、`uuid`、`coreVersion`、`kvEnabled` | 入口正确；无 KV 也能读取 |
| `POST /<入口>/api/config` | 局部更新配置，只需传要改的字段 | 绑定 KV；JSON 对象 |
| `GET /<入口>/region` | 读取当前配置的地区、手动地区和回退信息 | 不是对实际出口 IP 的检测 |
| `GET /<入口>/test-api` | 检查配置接口可达 | 入口正确 |
| `GET /<入口>/api/preferred-ips` | 列出 KV 中保存的手填优选 | 绑定 KV，并在 KV 中保存 `ae=yes` |
| `POST /<入口>/api/preferred-ips` | 添加一条或多条手填优选 | 同上；对象或对象数组 |
| `DELETE /<入口>/api/preferred-ips` | 删除单项或清空 | 同上；JSON 对象 |

配置写入示例：

```json
{"et":"yes","freeCpu":"no","p":"proxy.example.com:443"}
```

撤销这几个字段的 KV 覆盖，让它们重新使用环境变量/默认值：

```json
{"et":"","freeCpu":null,"p":""}
```

写入只接受上述 32 个规范配置键；`u` 和 `C` 不能通过此接口更换。环境变量的大写别名不用于 JSON 键。为兼容旧面板，配置接口还接受 `customIP` 作为 `p` 的旧别名，同一请求同时包含时 `p` 优先。

优选添加：

```json
{"ip":"104.16.1.1","port":443,"name":"IPv4优选"}
```

优选删除或清空：

```json
{"ip":"104.16.1.1","port":443}
```

```json
{"all":true}
```

当前优选管理接口直接读 KV 的 `ae`、`yx`，因此只设置环境变量 `ae=yes` 会继续得到 403；列表也不包含仅存在于环境变量的 `yx`。通过面板打开“允许 API 管理”并保存，或向配置接口写入 `{"ae":"yes"}`。常规配置读取、面板保存和订阅生成不受这个开关限制。

UUID、自定义入口、订阅 URL 都属于访问凭据；自定义 `d` 是另一条入口，不会撤销 UUID 入口。不要公开自己的完整配置接口和订阅链接。

## 独立面板订阅 URL

建议在面板复制，避免手工拼接。通用面板支持：

```text
https://面板域名/panel?host=你的Worker域名&uuid=你的UUID或自定义路径
https://面板域名/sub?host=你的Worker域名&uuid=你的UUID&target=clash
```

自建面板设置小写 `w=https://你的Worker域名` 后，也支持：

```text
https://面板域名/你的UUID或自定义路径
https://面板域名/你的UUID/sub?target=clash
```

用自定义路径登录后，面板会读取真实 UUID，并用 UUID 生成后续 API/订阅地址，所以后来修改 `d` 不会直接废掉已复制的 UUID 订阅。所有节点流量仍直接连接 Worker；面板负责配置读取和订阅输出，会接触这些配置凭据。

| `target` | 返回格式 |
| --- | --- |
| 不填 | 根据客户端 User-Agent 自动识别；不能识别时返回 Base64 |
| `base64`、`v2ray` | Base64 编码的 VLESS/Trojan 等分享链接 |
| `clash`、`clashr`、`stash`、`meta`、`clashmeta` | Clash / Mihomo YAML |
| `singbox`、`sing-box` | sing-box JSON |
| `surge`、`surge2`、`surge3`、`surge4` | Surge 格式 |
| `loon` | Loon 格式 |
| `quanx`、`quantumult` | Quantumult X 格式 |
| `vg`、`jk`、`jiakuan` | 家宽链式 Clash YAML，需要 `jk=yes` |
| `ss`、`ssr` | 历史 Base64 输出别名，仍是现有协议链接，不会生成 SS / SSR 协议节点 |

客户端还必须支持实际启用的协议与传输。能够拿到一种订阅格式，不等于该客户端支持配置中的 XHTTP 或 ECH。核心自身不再提供页面或 `/sub`，旧的 Worker 订阅地址须换成面板生成的新地址。


| 客户端 | 必要设置 |
| --- | --- |
| Surge | 开启 `et=yes`。当前生成器只输出 Trojan，默认 `et=no` 不会生成代理节点。 |
| Clash / Mihomo、sing-box、Loon、Quantumult X | VLESS 节点使用 WS，保留 `ev=yes`。生成器会将 XHTTP 来源转换为 WS，因此只开 `ex`、关闭 `ev` 会使这些 VLESS 节点不可用。 |
| 支持 XHTTP 的客户端 | 开启 `ex=yes`，通过 Base64 / VLESS 分享链接导入真正的 XHTTP 节点，使用 HTTP/2、`stream-one`。 |

[返回部署说明](../README.md)
