# cfnew-vue

Vue 3 + iOS 风格订阅转换管理界面

## 功能特性

- 🎨 **iOS 风格 UI** - 扁平化设计、明亮主题、圆角卡片
- 🌐 **多语言支持** - 中文 (zh) / 波斯语 (fa)
- 📱 **移动端友好** - 适配 iOS Safari 和 Android 浏览器
- ⚡ **实时延迟测试** - 支持批量测试 IP 延迟
- 💾 **KV 配置管理** - 保存/加载/重置配置

## 客户端支持

- Clash / Stash
- Surge
- sing-box
- Loon
- Quantumult X
- V2Ray / V2RayNG / NekoRay
- Shadowrocket

## 快速开始

### 开发模式

```bash
cd cfnew-vue
npm install
npm run dev
```

### 构建生产版本

```bash
npm run build
```

构建后的文件会输出到 `dist/` 目录。

## 部署到 Cloudflare Workers

### 方式一：部署到 Cloudflare Pages

1. 在 Cloudflare Dashboard 创建新的 Pages 项目
2. 上传 `dist/` 目录内容
3. 配置自定义域名即可

### 方式二：嵌入到 Worker 代码

由于 Cloudflare Workers 不能直接运行 Vue 构建产物，你需要将 Vue 界面嵌入到 Worker 的 HTML 返回中：

1. 构建 Vue 应用：`npm run build`
2. 将 `dist/index.html` 的内容提取出来
3. 将提取的 HTML/CSS/JS 嵌入到 Worker 代码的 HTML 模板中
4. 部署 Worker

### 方式三：单独部署 HTML

由于本项目设计为嵌入到现有的 cfnew Worker 中使用，你可以：

1. 构建项目
2. 将 `dist/assets/` 下的文件上传到你的 Worker 或 R2 Storage
3. 修改 Worker 代码引用这些资源

## 项目结构

```
cfnew-vue/
├── src/
│   ├── App.vue           # 主应用组件
│   ├── main.js           # 应用入口
│   ├── styles/
│   │   └── ios.css       # iOS 风格样式
│   └── locales/
│       ├── zh.json       # 中文翻译
│       └── fa.json       # 波斯语翻译
├── public/
├── index.html
├── package.json
├── vite.config.js
└── README.md
```

## 配置说明

| 参数 | 说明 |
|------|------|
| wk | 指定地区 (留空自动检测) |
| ev | 启用 VLESS 协议 |
| et | 启用 Trojan 协议 |
| ex | 启用 xhttp 协议 |
| ech | 启用 ECH |
| tp | Trojan 密码 |
| d | 自定义订阅路径 |
| p | 自定义 ProxyIP |
| yx | 优选 IP 列表 |
| yxURL | 优选 IP 来源 URL |
| scu | 订阅转换 API |
| ae | API 管理开关 |
| qj | 降级模式 |
| dkby | 仅 TLS 节点 |
| yxby | 内置优选开关 |

## 地区代码

| 代码 | 地区 |
|------|------|
| HK | 🇭🇰 香港 |
| US | 🇺🇸 美国 |
| SG | 🇸🇬 新加坡 |
| JP | 🇯🇵 日本 |
| KR | 🇰🇷 韩国 |
| DE | 🇩🇪 德国 |
| SE | 🇸🇪 瑞典 |
| NL | 🇳🇱 荷兰 |
| FI | 🇫🇮 芬兰 |
| GB | 🇬🇧 英国 |
| AU | 🇦🇺 澳洲 |
| BR | 🇧🇷 巴西 |
| CA | 🇨🇦 加拿大 |
| FR | 🇫🇷 法国 |
| CH | 🇨🇭 瑞士 |
| RU | 🇷🇺 俄罗斯 |
| IN | 🇮🇳 印度 |
| TW | 🇹🇼 台湾 |
| Oracle | 🟠 Oracle |
| DigitalOcean | 🔵 DigitalOcean |
| Vultr | 🟣 Vultr |
| Multacom | ⚫ Multacom |

## License

MIT
