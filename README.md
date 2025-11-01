# CFnew - v2.1

<div align="center">

**多协议支持 · 自定义路径 · 代码混淆增强 · 智能客户端识别**

[![Telegram](https://img.shields.io/badge/Telegram-交流群-blue?logo=telegram)](https://t.me/+ft-zI76oovgwNmRh)
[![Version](https://img.shields.io/badge/Version-2.1-green)]()
[![License](https://img.shields.io/badge/License-MIT-orange)]()

</div>

---

## 🚀 v2.1 全新特性

### 🎯 智能客户端识别
- **自动识别订阅格式** - 根据客户端 User-Agent 自动识别并返回对应订阅格式
- **一键唤醒应用** - 点击按钮优先尝试唤醒客户端应用，失败自动降级为复制
- **/auto 路径支持** - 提供 `/uuid/auto` 路径，服务器端自动识别客户端类型

### 📱 更多客户端支持
- **Shadowrocket** - 小火箭完整支持，一键唤醒
- **STASH** - 新增支持
- **NEKORAY** - 新增支持  
- **V2RayNG** - 新增支持
- 支持客户端总数：**10+**（Clash、Surge、Sing-Box、Loon、Quantumult X、V2Ray、Shadowrocket、STASH、NEKORAY、V2RayNG）

### 🔐 TLS 增强
- **ALPN 配置** - 全面支持 `h3,h2,http/1.1` ALPN 配置，提升连接兼容性
- 所有 TLS 链接自动添加 ALPN 参数

---

## ✨ v2.0 核心特性

- 🎭 **多协议支持** - VLESS + Trojan + xhttp，自由切换
- 🛤️ **自定义路径** - 告别UUID路径，自定义访问地址
- 🔐 **代码混淆** - 关键词编码，特征隐藏，安全增强
- 🔄 **订阅转换** - 自定义转换服务，优选类型细粒度控制
- 🎯 **图形化管理** - KV存储，实时配置，无需重新部署
- 🚀 **API管理** - RESTful API，批量操作，动态更新

---

## 📖 使用说明

### 🌐 订阅链接格式

**标准订阅路径：**
```
https://你的域名.workers.dev/你的UUID/sub
```

**自动识别订阅路径（推荐）：**
```
https://你的域名.workers.dev/你的UUID/auto
```
访问此路径时，服务器会根据客户端的 User-Agent 自动识别客户端类型并返回对应格式的订阅。

**自定义路径：**
```
https://你的域名.workers.dev/自定义路径/sub
https://你的域名.workers.dev/自定义路径/auto
```

### 🎨 图形化界面

访问 `https://你的域名.workers.dev/你的UUID` 即可使用图形化管理界面，支持：
- 一键生成各客户端订阅链接
- 自动识别客户端并生成订阅
- 实时配置管理
- 系统状态监控

### 📱 客户端唤醒功能

在图形化界面中：
- 点击客户端按钮会优先尝试通过 URL Scheme 唤醒对应应用
- 如果应用未安装或唤醒失败，会自动降级为复制链接到剪贴板
- 支持所有主流代理客户端的自动唤醒

---

## 🖼️ 界面预览

### 主界面

<img width="1708" height="884" alt="主界面" src="https://github.com/user-attachments/assets/ca35ae39-6971-4291-b182-28cb292c0353" />

**想加群的自己点击添加吧** tg交流群 https://t.me/+ft-zI76oovgwNmRh

### Snippets 配置

<img width="1128" height="801" alt="Snippets配置" src="https://github.com/user-attachments/assets/ae108dd2-c543-4a63-b448-d56d4d520e1d" />

**加入多客户端支持** - 访问 `域名/你的uuid` 即可看见

---

## 📚 配套工具

| 类型 | 描述 | 链接 |
| :--- | :--- | :--- |
| **文字教程** | 详细的部署与使用说明博客文章 | [https://joeyblog.net/yuanchuang/1146.html](https://joeyblog.net/yuanchuang/1146.html) |
| **Workers视频教程** | 直观的操作演示和功能讲解 | https://www.youtube.com/watch?v=aYzTr8FafN4 |
| **Snippets视频教程** | 直观的操作演示和功能讲解 | https://www.youtube.com/watch?v=xeFeH3Akcu8 |

---

## 🚀 部署

### ⚡ 快速部署

1. Fork 本仓库
2. 在 Cloudflare Workers 中创建新的 Worker
3. 复制 `cfnew` 文件内容到 Worker 编辑器中
4. 配置环境变量（见下方配置说明）
5. 部署即可使用

### 📝 重要更新

- ✅ **订阅自动优选** - 订阅每15分钟自动优选一次，确保最佳连接
- ✅ **自动识别客户端** - 服务器端根据 User-Agent 智能识别客户端类型
- ✅ **ALPN 全面支持** - 所有 TLS 链接自动添加 ALPN 配置

---

## 🔧 配置说明

### 基础配置

| 变量名 | 值 | 说明 |
| :--- | :--- | :--- |
| `u` | `你的 UUID` | **必需**。用于访问订阅和配置管理界面 |
| `p` | `proxyip` | **可选**。自定义ProxyIP地址和端口 |
| `s` | `你的SOCKS5地址` | **可选**。用于将所有出站流量通过 SOCKS5 代理转发，格式为 `user:pass@host:port` 或 `host:port` |
| `d` | `自定义路径` | **可选**。自定义订阅访问路径，如 `/mypath`，不填则使用 UUID 路径 |
| `wk` | `地区代码` | **可选**。手动指定Worker地区，如：`SG`、`HK`、`US`、`JP`等 |

### 协议配置

| 变量名 | 值 | 说明 |
| :--- | :--- | :--- |
| `ev` | `yes/no` | **可选**。启用VLESS协议（默认启用） |
| `et` | `yes/no` | **可选**。启用Trojan协议（默认禁用） |
| `ex` | `yes/no` | **可选**。启用xhttp协议（默认禁用） |
| `tp` | `自定义密码` | **可选**。Trojan协议密码，留空则使用UUID |

### 高级控制

| 变量名 | 值 | 说明 |
| :--- | :--- | :--- |
| `yx` | `自定义优选IP/域名` | **可选**。支持节点命名，格式：`1.1.1.1:443#香港节点,8.8.8.8:53#Google DNS` |
| `yxURL` | `优选IP来源URL` | **可选**。自定义优选IP列表来源URL，留空则使用默认地址 |
| `scu` | `订阅转换地址` | **可选**。自定义订阅转换服务URL，默认：`https://url.v1.mk/sub` |
| `epd` | `yes/no` | **可选**。启用优选域名（默认启用） |
| `epi` | `yes/no` | **可选**。启用优选IP（默认启用） |
| `egi` | `yes/no` | **可选**。启用GitHub默认优选（默认启用） |
| `qj` | `no` | **可选**。降级控制，设置为`no`时启用降级模式：CF直连失败→SOCKS5连接→fallback地址 |
| `dkby` | `yes` | **可选**。TLS控制，设置为`yes`时只生成TLS节点，不生成非TLS节点（如80端口） |

### 🎯 图形化配置（推荐）

- **KV存储配置**：在Workers中创建KV命名空间，绑定环境变量 `C`
- **访问界面**：部署后访问 `/{你的UUID}` 即可使用图形化配置管理
- **实时生效**：通过界面修改配置无需重新部署，立即生效

---

## 📋 支持的客户端

### iOS / macOS
- ✅ **Surge** - 完整支持，自动识别 Surge 2/3/4
- ✅ **Shadowrocket** - 小火箭，一键唤醒
- ✅ **Quantumult X** - 完整支持
- ✅ **Loon** - 完整支持
- ✅ **Clash for iOS** - 完整支持

### Android
- ✅ **Clash for Android** - 完整支持
- ✅ **V2RayNG** - 完整支持
- ✅ **Sing-Box** - 完整支持
- ✅ **NEKORAY** - 完整支持

### Windows / Linux
- ✅ **V2Ray** - 完整支持
- ✅ **Clash** - 完整支持
- ✅ **Sing-Box** - 完整支持
- ✅ **NEKORAY** - 完整支持

### 其他
- ✅ **STASH** - 完整支持

---

## 🆕 更新日志

### v2.1 (最新)
- ✨ 新增：智能客户端识别功能，根据 User-Agent 自动识别
- ✨ 新增：应用唤醒功能，优先尝试唤醒应用，失败降级复制
- ✨ 新增：/auto 路径支持，服务器端自动识别客户端
- ✨ 新增：Shadowrocket、STASH、NEKORAY、V2RayNG 客户端支持
- 🔐 增强：全面支持 ALPN 配置（h3,h2,http/1.1）
- 🔐 增强：所有 TLS 链接自动添加 ALPN 参数

### v2.0
- ✨ 多协议支持（VLESS + Trojan + xhttp）
- ✨ 自定义路径功能
- ✨ 代码混淆增强
- ✨ 图形化管理界面
- ✨ RESTful API 支持
- ✨ 订阅自动优选（每15分钟）

---

## 📄 许可证

MIT License

---

## ⭐ 致谢

感谢所有贡献者和使用者的支持！

**如有问题或建议，欢迎提交 Issue 或加入 Telegram 交流群**
