# CFnew - 终端 v2.9.3

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
| `p` | proxyip | 可选，自定义ProxyIP地址和端口 |
| `s` | 你的SOCKS5地址 | 可选，格式：`user:pass@host:port` 或 `host:port` |
| `d` | 自定义路径 | 可选，如 `/mypath` 或 `/path/to/sub`，不填用UUID路径。路径没 `/` 开头会自动补上 |
| `wk` | 地区代码 | 可选，手动指定Worker地区，如 `SG`、`HK`、`US`、`JP` |

#### 协议配置

| 变量名 | 值 | 说明 |
| :--- | :--- | :--- |
| `ev` | yes/no | 可选，启用VLESS（默认启用） |
| `et` | yes/no | 可选，启用Trojan（默认禁用） |
| `ex` | yes/no | 可选，启用xhttp（默认禁用） |
| `tp` | 自定义密码 | 可选，Trojan密码，留空用UUID |
| `ech` | yes/no | 可选，启用ECH功能（默认禁用） |

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
| `qj` | no | 可选，设为`no`启用降级：CF直连失败→SOCKS5→fallback |
| `dkby` | yes | 可选，设为`yes`只生成TLS节点 |
| `ech` | yes/no | 可选，启用ECH功能（默认禁用，启用后自动开启仅TLS模式） |
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

#### 手动指定地区

- 可以手动指定Worker地区，覆盖自动检测
- 设置方式：`wk=SG` 或图形界面选择
- 支持：US、SG、JP、HK、KR、DE、SE、NL、FI、GB

#### 优选节点命名

- 支持自定义名称，格式：`IP:端口#节点名称`
- 示例：`1.1.1.1:443#香港节点,8.8.8.8:53#Google DNS`
- 不设置名称会自动生成 `自定义优选-IP:端口`

#### 系统状态

- 显示Worker地区、检测方式、ProxyIP状态
- 选择逻辑：同地区 → 邻近地区 → 其他地区

#### 高级控制

- `rm=no` 关闭地区智能匹配
- `qj=no` 启用降级模式（CF直连失败→SOCKS5→fallback）
- `dkby=yes` 只生成TLS节点
- `ech=yes` 启用ECH功能（启用后自动开启仅TLS模式）
- `yxby=yes` 关闭所有优选功能

#### 多客户端支持

支持10种客户端：CLASH、SURGE、SING-BOX、LOON、QUANTUMULT X、V2RAY、Shadowrocket、STASH、NEKORAY、V2RAYNG

- 根据客户端类型自动生成配置
- 图形界面一键生成订阅链接
- 点按钮自动打开对应客户端
- 根据User-Agent自动识别并返回对应格式
- 不同客户端自动适配最佳协议组合
- 所有TLS链接自动包含 `h3,h2,http/1.1` 协议协商

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

[![Star History Chart](https://api.star-history.com/svg?repos=byJoey/cfnew&type=Timeline)](https://www.star-history.com/#byJoey/cfnew&Timeline&LogScale)
