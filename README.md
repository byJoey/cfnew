### 感觉跳转加群有点流氓行为 改成

<img width="1708" height="884" alt="image" src="https://github.com/user-attachments/assets/ca35ae39-6971-4291-b182-28cb292c0353" />


想加群的自己点击添加吧 tg交流群 https://t.me/+ft-zI76oovgwNmRh 

###  Snippets

<img width="1128" height="801" alt="image" src="https://github.com/user-attachments/assets/ae108dd2-c543-4a63-b448-d56d4d520e1d" />

#### 加入多客户端支持 域名/你的uuid即可看见

###  配套工具

| 类型 | 描述 | 链接 |
| :--- | :--- | :--- |
|  **文字教程** | 详细的部署与使用说明博客文章 | [https://joeyblog.net/yuanchuang/1146.html](https://joeyblog.net/yuanchuang/1146.html) |
|  **Workers视频教程** | 直观的操作演示和功能讲解 | https://youtu.be/Rlypv_iswD8 |
|  **Snippets视频教程** | 直观的操作演示和功能讲解 | https://www.youtube.com/watch?v=xeFeH3Akcu8 |

###  部署
	
加入了千呼万唤的订阅每15分钟自动优选一次
| 变量名 | 值 | 说明 |
| :--- | :--- | :--- |
| `u` | `你的 UUID` | **必需**。 |
| `p` | `proxyip` | **可选**但强烈推荐，填写一个稳定的用来访问 Cloudflare IP 可以用 ProxyIP.cmliussss.net CM提供的公益项目 在次感谢。 |
| `s` | `你的SOCKS5地址` | **可选**。用于将所有出站流量通过 SOCKS5 代理转发，格式为 `user:pass@host:port` 或 `host:port`。 |
| `d` | `你的订阅地址` | **可选**。不填就是/你的uuid |
| `yx` | `自定义优选IP/域名` | **可选**。自定义优选IP和域名，支持端口，格式：`1.1.1.1:8080,2.2.2.2,example.com:8443`。当设置此变量时，将只使用原生地址和自定义优选，不生成默认优选。 |
| `qj` | `no` | **可选**。SOCKS5降级控制，设置为`no`时启用降级模式：SOCKS5失败→fallback SOCKS5→直连fallback。 |

###  新功能

#### 自定义优选支持
- 支持自定义优选IP和域名，完全替代默认优选
- 格式：`yx=1.1.1.1:8080,2.2.2.2,example.com:8443`
- 支持IPv4/IPv6地址和域名，支持自定义端口
- 设置后只生成原生地址+自定义优选，跳过默认优选

#### SOCKS5智能降级
- 当SOCKS5代理不可用时自动降级
- 设置：`qj=no` 启用降级模式
- 降级流程：SOCKS5连接 → fallback SOCKS5 → 直连fallback
- 提高连接成功率，增强容错能力

###  致谢

  * 本项目基于 [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel) 修改，感谢原作者的贡献。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=byJoey/cfnew&type=Timeline)](https://www.star-history.com/#byJoey/cfnew&Timeline&LogScale)
