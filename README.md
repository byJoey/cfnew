# CFnew - 终端 v3.0

**语言:** [中文](README.md) | [فارسی](فارسی.md)

[Telegram 交流群](https://t.me/+ft-zI76oovgwNmRh)

## 主要功能

- 多协议支持：VLESS、Trojan、xhttp，可以同时启用多个
- 自定义路径：不用UUID当路径了，可以自己设置，支持多级路径
- 延迟测试：内置测试工具，测IP延迟，自动获取机场码
- 订阅转换：可以自定义转换服务地址
- 图形化管理：用KV存配置，改完立即生效，不用重新部署
- API管理：支持通过API动态添加/删除优选IP
- 多客户端：支持 CLASH、SURGE、SING-BOX、LOON、QUANTUMULT X、V2RAY、Shadowrocket、STASH、NEKORAY、V2RAYNG
- 应用唤醒：点按钮自动打开对应客户端
- 自动识别：根据User-Agent自动返回对应格式
- 多语言：支持中文和波斯语，根据浏览器语言自动切换

## v3.0 更新

- ProxyIP 多了个「用官方直连」按钮，点一下自动填一个内置地址，不用自己去找
  - 内置 10 个实测可用的 Cloudflare 官方地址，分布在 10 个不同 /24 段
  - 全部离线内置，不请求任何外部接口
  - 连点会换一个，相邻两次不重复
- 说明：CF 是任播，同一个地址在不同位置访问会落到不同机房，所以这里不按地区分。
  想指定落地机房用 `wk` 变量，不是靠挑 IP

## v2.9.9 更新

- 出站代理支持 HTTP / HTTPS：`s` 变量按前缀区分协议，不写前缀仍是 SOCKS5，老配置不受影响
  - `http://user:pass@host:port` 明文连代理后建立隧道
  - `https://user:pass@host:port` 连代理这一跳走 TLS
  - 认证走 Basic，由 Worker 自动生成；`http` / `https` 可省略端口，默认 80 / 443
  - 节点 path 里的 `s=` 写法一致
- 出站方式改为三选一（`qj`），并把语义正过来
  - 留空：优先走代理（与旧版默认行为一致）
  - `no`：优先直连，失败再走代理（与旧版 `qj=no` 一致）
  - `only`：**只走代理，连不上直接断开**，不回落直连或备用地址，避免出口 IP 泄漏
  - 面板标签由「降级控制」改为「出站方式」，选项文案重写
- 详见「[出站代理](#出站代理)」

## v2.9.8c 更新

- 订阅转换内部实现：Clash / Stash / Sing-box / Surge / Loon / Quantumult X 配置全部由 Worker 直接生成，不再依赖任何外部 sub-converter
  - 完整规则集：Clash 使用 Loyalsoldier `rule-providers`；Sing-box 使用 MetaCubeX SRS；Surge / Loon / QuanX 使用 ACL4SSR / blackmatrix7 远端规则
  - 各策略分组均包含「策略组 + 全部节点」，可直接切换具体节点（已移除「自动选择」url-test，避免周期性测速浪费请求）
  - 修复 Clash IPv6 节点 `server` 被解析为数组、代理组 `🎯 全球直连` ↔ `🚀 节点选择` 循环引用等问题
- 传输优化：参考 GrainTCP 思路优化 WebSocket/TCP 转发，上行小包队列合并、下行小包聚合、大包直发，并优化 VLESS 解析热路径
- 图形化 ALPN：新增 `alpn` 下拉选项，留空时不写 `alpn`，也可选择 `h3`、`h2`、`http/1.1` 或组合值
- 节点别名简化：域名统一为 `优选域名-序号`，IPv6 统一为 `IPv6优选-序号`，IPv4 使用 `isp-colo-序号`
- KV 配置缓存：30s 短窗口 + 跨 isolate 版本键 `c_ver`，保存后无需刷新两次
- SOCKS5 降级超时：直连 3.5s 无数据自动走 fallback
- 标签：「启用 GitHub 默认优选」改为「启用自定义优选」
- 页面特效开关：`FX: ON / OFF`，选择 localStorage 持久化
- 提供混淆版本 `少年你相信光吗`，逻辑与 `明文源吗` 完全一致

## v2.9.7 更新

- 悬浮保存按钮：右下角常驻「保存全部」按钮，支持 `Ctrl+S` / `Cmd+S` 快捷键
  - 编辑任意字段后按钮自动进入「未保存」提示状态
  - 保存中 / 刷新中有进度反馈
- 通知体验优化：所有阻塞式弹窗替换为右上角浮动消息，自动消失、可悬停暂停、支持手动关闭
  - 4 种语义：success / info / warn / error
- 操作按钮整合：将分散在各区块的 4 个保存按钮合并为统一的悬浮操作组
- 提供混淆版本 `少年你相信光吗`，逻辑与 `明文源吗` 完全一致

## v2.9.6 更新

- 兼容 Xray-core v26.3.27
- 新增香港 (HK) 地区 ProxyIP 和地区选择
- KV 读取性能优化：5 小时内存缓存，减少 99% 以上的 KV 读取量
- 无效请求拦截：非法路径直接返回 404，不再触发 KV 读取
- 修复优选列表保存时 SOCKS5 配置 key 错误的问题

## v2.9.5 更新

- GitHub 默认优选地址默认关闭，需自行配置优选IP来源URL
- 新增「启用原生地址」开关，可在管理面板中控制是否生成原生地址节点（默认关闭）
- 兼容日期设置为 `2026-01-20`

## v2.9.4 更新

- 支持客户端通过 WebSocket path 参数覆盖连接级变量（`p`、`wk`、`rm`、`s`）
  - 无需为每个节点单独部署 Worker，在分享链接的 path 里直接写参数即可
  - 优先级：path 参数 > KV/环境变量全局配置 > 自动检测
  - 详见下方「[客户端 path 参数](#客户端-path-参数)」说明

## v2.9.3 更新

- 新增图形化自定义DNS和ECH域名功能
  - 可在界面中自定义DNS服务器地址（DoH格式）
  - 可在界面中自定义ECH域名
  - 支持动态更改，保存后立即生效
  - Clash配置中的ech-opts增加query-server-name参数，与v2ray保持一致

## v2.9.2 更新

- 修复 Clash 配置生成问题

## v2.9.1 更新

- ECH支持：新增 Encrypted Client Hello (ECH) 功能
  - 每次刷新订阅时自动获取最新的 ECH 配置
  - 启用 ECH 时自动启用"仅 TLS"模式，避免 80 端口干扰
  - 图形界面可一键开启/关闭 ECH 功能


## v2.9 更新

- 地区筛选：可以按地区筛选优选结果，支持多选
- 延迟筛选：新增"只显示最快的10个"选项
- 追加/替换模式：添加优选结果时可以追加或替换整个列表
- 结果展示优化：显示地区标签，按延迟排序
- 其他细节优化

---

### 相关工具

- 优选工具：https://github.com/byJoey/yx-tools/releases
- 文字教程：https://joeyblog.net/yuanchuang/1146.html
- Workers视频教程：https://www.youtube.com/watch?v=aYzTr8FafN4
- Pages视频教程：https://www.youtube.com/watch?v=JhVxJChDL-E
- Snippets视频教程：https://www.youtube.com/watch?v=xeFeH3Akcu8

### 部署

订阅每15分钟自动优选一次

#### 基础配置
| 变量名 | 值 | 说明 |
| :--- | :--- | :--- |
| `u` | 你的 UUID | 必需，用于访问订阅和配置界面 |
| `p` | proxyip | 可选，自定义ProxyIP地址和端口，支持 IPv4/IPv6/域名。设置后 `wk` 地区匹配失效（互斥）。也可在节点 path 里单独指定 |
| `s` | 出站代理地址 | 可选。支持 SOCKS5 和 HTTP/HTTPS 代理，见下方「[出站代理](#出站代理)」。也可在节点 path 里单独指定 |
| `d` | 自定义路径 | 可选，如 `/mypath` 或 `/path/to/sub`，不填用UUID路径。路径没 `/` 开头会自动补上 |
| `wk` | 地区代码 | 可选，手动指定Worker地区，如 `SG`、`HK`、`US`、`JP`。设置 `p` 后此项失效（互斥）。也可在节点 path 里单独指定 |

#### 协议配置

| 变量名 | 值 | 说明 |
| :--- | :--- | :--- |
| `ev` | yes/no | 可选，启用VLESS（默认启用） |
| `et` | yes/no | 可选，启用Trojan（默认禁用） |
| `ex` | yes/no | 可选，启用xhttp（默认禁用） |
| `tp` | 自定义密码 | 可选，Trojan密码，留空用UUID |
| `ech` | yes/no | 可选，启用ECH功能（默认禁用） |
| `alpn` | ALPN列表 | 可选，TLS节点ALPN参数。留空不写，由客户端协商；可选 `h3`、`h2`、`http/1.1`、`h3,h2`、`h2,http/1.1`、`h3,h2,http/1.1` |

#### 图形化配置（推荐）

1. 在Workers中创建KV命名空间，绑定环境变量 `C`
2. 部署后访问 `/{你的UUID}` 使用图形化配置
3. 改完配置立即生效，不用重新部署

#### 高级控制
| 变量名 | 值 | 说明 |
| :--- | :--- | :--- |
| `yx` | 自定义优选IP/域名 | 可选，支持命名，格式：`1.1.1.1:443#香港节点,8.8.8.8:53#Google DNS` |
| `yxURL` | 优选IP来源URL | 可选，自定义IP列表来源，留空用默认 |
| `scu` | 订阅转换地址 | 可选，默认：`https://url.v1.mk/sub` |
| `epd` | yes/no | 可选，启用优选域名（默认启用） |
| `epi` | yes/no | 可选，启用优选IP（默认启用） |
| `egi` | yes/no | 可选，启用GitHub默认优选（默认启用） |
| `qj` | no / only | 可选，出站方式。留空=优先走代理，`no`=优先直连、失败再走代理，`only`=只走代理不回落。见「[出站代理](#出站代理)」 |
| `dkby` | yes | 可选，设为`yes`只生成TLS节点 |
| `ech` | yes/no | 可选，启用ECH功能（默认禁用，启用后自动开启仅TLS模式） |
| `alpn` | ALPN列表 | 可选，只写入TLS节点链接参数，留空则不写 |
| `yxby` | yes | 可选，设为`yes`关闭所有优选功能 |
| `rm` | no | 可选，设为`no`关闭地区智能匹配 |
| `ae` | yes | 可选，设为`yes`允许API管理（默认关闭） |

#### KV存储设置（推荐）

1. 在Cloudflare Workers中创建KV命名空间
2. 在Workers设置中绑定KV，变量名设为 `C`
3. 重新部署
4. 访问 `/{你的UUID}` 使用图形化配置

#### API使用
1. 下载优选软件：https://github.com/byJoey/yx-tools/releases
2. 开启API：访问 `/{UUID}` 或 `/{自定义路径}`，找到"允许API管理"，开启后保存
3. 添加单个IP：
```bash
# 使用UUID路径
curl -X POST "https://your-worker.workers.dev/{UUID}/api/preferred-ips" \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "port": 443, "name": "香港节点"}'

# 使用自定义路径（如果设置了d变量）
curl -X POST "https://your-worker.workers.dev/{自定义路径}/api/preferred-ips" \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "port": 443, "name": "香港节点"}'
```
4. 批量添加IP：
```bash
curl -X POST "https://your-worker.workers.dev/{UUID或自定义路径}/api/preferred-ips" \
  -H "Content-Type: application/json" \
  -d '[
    {"ip": "1.2.3.4", "port": 443, "name": "节点1"},
    {"ip": "5.6.7.8", "port": 8443, "name": "节点2"}
  ]'
```
5. 清空所有IP：
```bash
curl -X DELETE "https://your-worker.workers.dev/{UUID或自定义路径}/api/preferred-ips" \
  -H "Content-Type: application/json" \
  -d '{"all": true}'
```

### 功能说明

#### 延迟测试

v2.7开始提供，v2.9增强了筛选功能

- 内置测试工具，不用装其他软件，直接在配置页面测IP延迟
- IP来源：
  - 手动输入：直接输IP或域名，支持批量（逗号分隔）
  - CF随机IP：从Cloudflare IP段随机生成
  - URL获取：从远程URL获取IP列表
- 支持1-50线程并发测试，默认5线程
- 自动获取机场码（如SJC、LAX）
- 自动映射中文机场名（SJC→圣何塞）
- 自动扣除DNS+TLS握手时间，显示真实延迟
- 设置自动保存到浏览器
- 支持按地区筛选
- 支持只显示最快的10个
- 支持追加或替换模式

#### 官方直连地址

v3.0 开始提供。以前填 ProxyIP 得自己去别处找一个能用的地址，现在面板里直接点。

位置：配置管理 → 自定义 ProxyIP (p) 输入框下方，点「🌐 用官方直连」。

内置 10 个地址，都是实测通过的 Cloudflare 官方 IP，分布在 10 个不同 /24 段，
避免整段被墙时全部失效。点一下随机填一个，不满意再点，连点不会给同一个。

几点说明：

- 完全离线，地址写死在代码里，不联网、不依赖任何外部数据源
- **不按地区区分**：CF 是任播（anycast），同一个 IP 在不同位置访问落到的机房不一样，
  挑 IP 并不能决定落地在哪。想指定地区请用 `wk` 变量
- 填了 ProxyIP 之后 `wk` 地区匹配会自动失效，这是原有的互斥逻辑，没变
- 地址可用性会随时间变化，填完可以用下面的延迟测试验一下，失效了手填别的也行

#### 多协议支持

- VLESS：默认启用
- Trojan：支持Trojan-WS-TLS，可以自定义密码，不填就用UUID
- xhttp：基于HTTP POST的伪装协议
- 可以同时启用多个协议，客户端会自动识别
- 图形界面一键开关
- 协议配置有独立保存按钮

#### ECH 功能 (Encrypted Client Hello)

- 支持 Encrypted Client Hello (ECH) 加密客户端握手
- 自动获取：每次刷新订阅时自动从 DoH 获取最新的 ECH 配置
- 优先使用 Google DNS，失败时自动尝试 Cloudflare DNS
- 智能模式：启用 ECH 时自动启用"仅 TLS"模式，避免 80 端口干扰
- 图形界面：可在协议配置区域一键开启/关闭
- 调试信息：在浏览器开发者工具的响应头中可查看详细的 ECH 获取过程
- 响应头信息：
  - `X-ECH-Status`: SUCCESS 或 FAILED
  - `X-ECH-Debug`: 详细的调试信息
  - `X-ECH-Config-Length`: ECH 配置长度（成功时）

#### 出站代理

`s` 变量用来指定出站代理，所有出站流量都会从它走。支持两类协议，靠前缀区分：

| 写法 | 走的协议 | 说明 |
| :--- | :--- | :--- |
| `host:port` | SOCKS5 | 不写前缀就是 SOCKS5，和以前一样 |
| `socks5://host:port` | SOCKS5 | 显式写法，等价于上面 |
| `http://host:port` | HTTP | 明文连代理，再发建隧请求 |
| `https://host:port` | HTTPS | 连代理这一跳走 TLS，适合代理本身要求加密的场景 |

带认证就在前面加 `用户名:密码@`：

```
user:pass@1.2.3.4:1080
socks5://user:pass@1.2.3.4:1080
http://user:pass@1.2.3.4:8080
https://user:pass@proxy.example.com:8443
```

说明几点：

- HTTP/HTTPS 代理的认证走 Basic，由 Worker 自动生成，不用自己拼。
- 只有 `http://` 和 `https://` 可以省略端口，分别默认 80 和 443；SOCKS5 必须写端口。
- 地址后面多写的路径会被忽略，`http://1.2.3.4:8080/xxx` 等同于 `http://1.2.3.4:8080`。
- 代理必须支持隧道转发（也就是能代理任意 TCP）。只能转发网页请求的代理用不了。
- 在节点 path 里单独指定时写法完全一样，如 `s=http://user:pass@host:8080`。

**出站方式（`qj`）**

配好 `s` 之后，用 `qj` 决定流量怎么走。面板里对应「出站方式」下拉框：

| `qj` | 行为 | 什么时候用 |
| :--- | :--- | :--- |
| 留空（默认） | 优先走代理，代理不通再回落 | 想走代理，但断了也别断网 |
| `no` | 优先直连，失败再走代理 | 只把代理当备用线路 |
| `only` | 只走代理，连不上直接断开 | 要求出口 IP 固定，不接受回落 |

`only` 和默认的区别在**失败时**：默认会回落到备用地址或直连，这时出口就变成 Worker
自己的 IP 了；`only` 宁可断开也不回落，出口 IP 不会漏。

没填 `s` 时三个选项都一样，都是直连。

#### 自定义路径（d变量）

- 不用UUID当路径了，可以自己设置
- 支持多级路径，如 `/path/to/sub`
- 路径没 `/` 开头会自动补上
- 自定义路径后UUID路径自动禁用
- 可以随时在图形界面改路径

#### 图形化配置

- 用Cloudflare KV存配置
- 访问 `/{你的UUID}` 或 `/{自定义路径}` 就能用
- 改完立即生效，不用重新部署
- 优先级：KV配置 > 环境变量 > 默认值

#### 多语言支持

- 根据浏览器语言自动选择中文或波斯语
- 右上角可以手动切换
- 语言选择会保存到浏览器
- 波斯语自动启用RTL布局

#### 订阅转换控制

- 可以自定义转换服务URL
- 可以单独控制优选域名、优选IP、GitHub优选
- 默认全部启用
- 改完立即生效

#### API管理

- 通过RESTful API管理优选IP，不用改代码
- 支持批量添加
- 支持清空所有IP
- 默认关闭，需要在图形界面开启
- API添加的IP和手动配置的yx变量会自动合并
- API端点：
  - `GET /{UUID或路径}/api/preferred-ips` - 查询列表
  - `POST /{UUID或路径}/api/preferred-ips` - 添加（单个/批量）
  - `DELETE /{UUID或路径}/api/preferred-ips` - 删除（单个/全部）

#### 客户端 path 参数

v2.9.4 新增。在 VLESS/Trojan 分享链接的 `path` 字段里追加查询参数，即可为**单个节点**单独指定连接级配置，无需额外部署 Worker。

| 参数 | 作用 | 示例 |
| :--- | :--- | :--- |
| `p` | 覆盖 ProxyIP（支持带端口） | `p=1.1.1.1` 或 `p=1.2.3.4:8443` |
| `wk` | 覆盖 Worker 地区 | `wk=jp`、`wk=us`、`wk=sg` |
| `rm` | 关闭地区智能匹配 | `rm=no` |
| `s` | 覆盖出站代理 | `s=user:pass@host:1080`、`s=http://user:pass@host:8080` |

**优先级：path 参数 > KV/环境变量 > 自动检测**

> ⚠️ **`p` 和 `wk` 互斥**：设置 `p` 后会直接使用指定的 ProxyIP，`wk` 的地区匹配逻辑被完全跳过，两者同时写只有 `p` 生效。

path 示例：
```
# 指定 ProxyIP（不要同时写 wk）
/?ed=2048&p=1.1.1.1
/?ed=2048&p=proxy.example.com:443
/?ed=2048&p=[2001:db8::1]:443

# 指定地区（让 Worker 自动选该地区的 ProxyIP）
/?ed=2048&wk=jp
/?ed=2048&wk=sg&rm=no

# 指定出站代理（可与 wk 搭配）
/?ed=2048&s=user:pass@proxy.host:1080&wk=us
/?ed=2048&s=http://user:pass@proxy.host:8080&wk=us
```

> 不在上表中的变量（如 `ev`、`et`、`yx` 等）属于订阅生成级配置，在 WebSocket 握手阶段已过路由，放在 path 里无效，仍需在环境变量或 KV 中设置。

#### 手动指定地区

- 可以手动指定Worker地区，覆盖自动检测
- 设置方式：`wk=SG` 或图形界面选择，或在节点 path 里加 `wk=SG`
- 支持：US、SG、JP、HK、KR、DE、SE、NL、FI、GB

#### 优选节点命名

- 订阅别名默认使用短名称，不再追加端口、协议、TLS/WS 等信息
- 域名节点：`优选域名-01`、`优选域名-02`
- IPv6节点：`IPv6优选-01`、`IPv6优选-02`
- IPv4节点：优先使用 `isp-colo-序号`，缺少运营商信息时回退为 `IPv4优选-序号`

#### 系统状态

- 显示Worker地区、检测方式、ProxyIP状态
- 选择逻辑：同地区 → 邻近地区 → 其他地区

#### 高级控制

- `rm=no` 关闭地区智能匹配
- `qj=no` 优先直连，失败再走代理；`qj=only` 只走代理，连不上直接断开
- `dkby=yes` 只生成TLS节点
- `ech=yes` 启用ECH功能（启用后自动开启仅TLS模式）
- `alpn=h3,h2` 指定TLS节点ALPN，留空则不写
- `yxby=yes` 关闭所有优选功能

#### 多客户端支持

支持10种客户端：CLASH、SURGE、SING-BOX、LOON、QUANTUMULT X、V2RAY、Shadowrocket、STASH、NEKORAY、V2RAYNG

- 根据客户端类型自动生成配置
- 图形界面一键生成订阅链接
- 点按钮自动打开对应客户端
- 根据User-Agent自动识别并返回对应格式
- 不同客户端自动适配最佳协议组合
- TLS 链接默认不写 `alpn`，可在图形界面或通过 `alpn` 配置指定

#### 性能优化

- 每15分钟自动优选一次
- 多重备用方案
- 智能缓存，减少重复计算

### 致谢

- 基于 [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel) 修改
- ProxyIP部分来自 [cmliu](https://github.com/cmliu)
- 反代IP来自 [qwer-search](https://github.com/qwer-search)
- 在线优选接口来自 [白嫖哥](https://t.me/bestcfipas)


## Star History

[![Star History Chart](https://star-history.dera.page/svg?repos=byJoey/cfnew&type=Timeline)](https://star-history.dera.page/#byJoey/cfnew&Timeline&LogScale)
