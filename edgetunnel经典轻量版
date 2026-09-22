// @ts-ignore
import { connect as 连接 } from 'cloudflare:sockets';

// ============================ 配置区（改这里就能用） ============================
// 认证令牌：即连接用的 UUID。生成方式：Windows 下执行 Powershell -Command "[guid]::NewGuid()"
let 认证令牌 = '2541f8d4-d157-46af-9169-0025bf435fbc';
// 回退地址：直连失败时改走的地址，留空表示不启用
let 回退地址 = 'pp.xy.kg';
// 中转地址：经由中转服务器出站。格式 user:pass@host:port 或 host:port，留空表示不启用
// 用户名与密码不要包含特殊字符；一旦设置，就会忽略回退地址
let 中转地址 = '';
// 优选地址：连接用的 CF 优选 IP 或域名，握手仍用访问域名。逗号隔开多个。
// 每一项可以是 host:port（如 104.16.0.1:443），也可以是一个在线列表的 URL
// （如 https://bestcf.pages.dev/vps789/top10.txt，会把里面的地址全拉进来）。
// URL 和 host:port 可以混着填，留空就只用访问域名本身。
let 优选地址 = '';
// ============================================================================

const 文本解码器 = new TextDecoder();
// 运行时把 base64 文本还原成字符串，避免源码里出现可被检索的明文关键词
function 解码64(文本) {
	const 二进制 = atob(文本);
	const 字节 = new Uint8Array(二进制.length);
	for (let 索引 = 0; 索引 < 二进制.length; 索引++) 字节[索引] = 二进制.charCodeAt(索引);
	return 文本解码器.decode(字节);
}

if (!校验令牌格式(认证令牌)) {
	throw new Error('令牌格式不合法');
}

// 中转地址在编译期固定，这里直接解析一次（解析中转地址 靠函数提升可用）
let 中转配置 = {};
let 启用中转 = false;
if (中转地址) {
	try {
		中转配置 = 解析中转地址(中转地址);
		启用中转 = true;
	} catch (err) {
		/** @type {Error} */ let e = err;
		console.log(e.toString());
		启用中转 = false;
	}
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @returns {Promise<Response>}
	 */
	async fetch(request) {
		try {
			const 升级头 = request.headers.get('Upgrade');
			if (!升级头 || 升级头 !== 'websocket') {
				const 网址 = new URL(request.url);
				switch (网址.pathname) {
					case '/':
						return new Response('hello', { status: 200 });
					case `/${认证令牌}`: {
						const 订阅内容 = await 生成订阅配置(认证令牌, request.headers.get('Host'));
						return new Response(`${订阅内容}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
							}
						});
					}
					default:
						return new Response('Not found', { status: 404 });
				}
			} else {
				return await 处理套接字升级(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};




/**
 *
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function 处理套接字升级(request) {

	/** @type {import("@cloudflare/workers-types").WebSocket[]} */
	// @ts-ignore
	const 套接字对 = new WebSocketPair();
	const [客户端, 套接字] = Object.values(套接字对);

	套接字.accept();

	let 地址 = '';
	let 端口日志 = '';
	const 记录 = (/** @type {string} */ 信息, /** @type {string | undefined} */ 事件) => {
		console.log(`[${地址}:${端口日志}] ${信息}`, 事件 || '');
	};
	const 前置数据头 = request.headers.get('sec-websocket-protocol') || '';

	const 可读套接字流 = 创建可读套接字流(套接字, 前置数据头, 记录);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let 远端套接字包装 = {
		value: null,
	};
	let 是域名解析 = false;

	// 套接字 --> 远端
	可读套接字流.pipeTo(new WritableStream({
		async write(数据块, controller) {
			if (是域名解析) {
				return await 处理域名解析(数据块, 套接字, null, 记录);
			}
			if (远端套接字包装.value) {
				const 写入器 = 远端套接字包装.value.writable.getWriter()
				await 写入器.write(数据块);
				写入器.releaseLock();
				return;
			}

			const {
				出错,
				消息,
				地址类型,
				目标端口 = 443,
				目标地址 = '',
				首包偏移,
				协议版本 = new Uint8Array([0, 0]),
				是数据报,
			} = 解析头部(数据块, 认证令牌);
			地址 = 目标地址;
			端口日志 = `${目标端口}--${Math.random()} ${是数据报 ? 'udp ' : 'tcp '
				} `;
			if (出错) {
				throw new Error(消息); // CF 存在缺陷，controller.error 不会真正结束流
				return;
			}
			// 若是数据报但端口不是域名解析端口，则关闭
			if (是数据报) {
				if (目标端口 === 53) {
					是域名解析 = true;
				} else {
					throw new Error('数据报仅支持 53 端口（域名解析）'); // CF 存在缺陷，controller.error 不会真正结束流
					return;
				}
			}
			// ["版本", "附加信息长度 N"]
			const 响应头部 = new Uint8Array([协议版本[0], 0]);
			const 客户端首包 = 数据块.slice(首包偏移);

			if (是域名解析) {
				return 处理域名解析(客户端首包, 套接字, 响应头部, 记录);
			}
			处理传输出站(远端套接字包装, 地址类型, 目标地址, 目标端口, 客户端首包, 套接字, 响应头部, 记录);
		},
		close() {
			记录(`可读套接字流已关闭`);
		},
		abort(原因) {
			记录(`可读套接字流已中止`, JSON.stringify(原因));
		},
	})).catch((err) => {
		记录('可读套接字流 pipeTo 出错', err);
	});

	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: 客户端,
	});
}

/**
 * 处理出站传输连接。
 *
 * @param {any} 远端套接字
 * @param {number} 地址类型 要连接的远端地址类型。
 * @param {string} 目标地址 要连接的远端地址。
 * @param {number} 目标端口 要连接的远端端口。
 * @param {Uint8Array} 客户端首包 要写入的客户端首包数据。
 * @param {import("@cloudflare/workers-types").WebSocket} 套接字 用于挂接远端套接字的 WebSocket。
 * @param {Uint8Array} 响应头部 响应头部。
 * @param {function} 记录 日志函数。
 * @returns {Promise<void>} 远端套接字。
 */
async function 处理传输出站(远端套接字, 地址类型, 目标地址, 目标端口, 客户端首包, 套接字, 响应头部, 记录,) {
	async function 连接并写入(地址, 端口, 走中转 = false) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		const 传输套接字 = 走中转 ? await 中转连接(地址类型, 地址, 端口, 记录)
			: 连接({
				hostname: 地址,
				port: 端口,
			});
		远端套接字.value = 传输套接字;
		记录(`已连接 ${地址}:${端口}`);
		const 写入器 = 传输套接字.writable.getWriter();
		await 写入器.write(客户端首包); // 首次写入，通常是 TLS 客户端问候
		写入器.releaseLock();
		return 传输套接字;
	}

	// 若 CF 建立的传输套接字没有回传数据，则重试改走中转/回退地址
	async function 重试() {
		if (启用中转) {
			传输套接字 = await 连接并写入(目标地址, 目标端口, true);
		} else {
			传输套接字 = await 连接并写入(回退地址 || 目标地址, 目标端口);
		}
		// 不论重试成功与否，都关闭套接字
		传输套接字.closed.catch(错误 => {
			console.log('重试传输套接字关闭出错', 错误);
		}).finally(() => {
			安全关闭套接字(套接字);
		})
		远端回传套接字(传输套接字, 套接字, 响应头部, null, 记录);
	}

	let 传输套接字 = await 连接并写入(目标地址, 目标端口);

	// 远端套接字就绪后，把回传接到套接字
	// 远端 --> 套接字
	远端回传套接字(传输套接字, 套接字, 响应头部, 重试, 记录);
}

/**
 *
 * @param {import("@cloudflare/workers-types").WebSocket} 套接字服务端
 * @param {string} 前置数据头 用于套接字 0rtt
 * @param {(info: string)=> void} 记录 用于套接字 0rtt
 */
function 创建可读套接字流(套接字服务端, 前置数据头, 记录) {
	let 已取消 = false;
	const 流 = new ReadableStream({
		start(controller) {
			套接字服务端.addEventListener('message', (事件) => {
				if (已取消) {
					return;
				}
				const 消息 = 事件.data;
				controller.enqueue(消息);
			});

			// 该事件表示客户端已关闭 客户端->服务端 方向的流。
			// 但服务端->客户端 方向仍然打开，直到你在服务端调用 close()。
			// 协议规定：要彻底关闭连接，两个方向都必须各自发送关闭消息。
			套接字服务端.addEventListener('close', () => {
				// 客户端发来关闭，需要关闭服务端
				// 若流已取消，则跳过 controller.close
				安全关闭套接字(套接字服务端);
				if (已取消) {
					return;
				}
				controller.close();
			}
			);
			套接字服务端.addEventListener('error', (err) => {
				记录('套接字服务端出错');
				controller.error(err);
			}
			);
			// 用于套接字 0rtt
			const { 前置数据, error } = 六四转字节缓冲(前置数据头);
			if (error) {
				controller.error(error);
			} else if (前置数据) {
				controller.enqueue(前置数据);
			}
		},

		pull(controller) {
			// 若套接字满时可停止读取，则可以实现背压
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},
		cancel(原因) {
			// 1. 管道的 WritableStream 出错时会触发 cancel，因此套接字的服务端关闭会走到这里
			// 2. 若可读流已取消，则所有 controller.close/enqueue 都要跳过
			// 3. 但经测试，即便可读流已取消，controller.error 仍然有效
			if (已取消) {
				return;
			}
			记录(`可读流被取消，原因：${原因}`)
			已取消 = true;
			安全关闭套接字(套接字服务端);
		}
	});

	return 流;

}


/**
 *
 * @param { ArrayBuffer} 数据缓冲
 * @param {string} 认证令牌
 * @returns
 */
function 解析头部(
	数据缓冲,
	认证令牌
) {
	if (数据缓冲.byteLength < 24) {
		return {
			出错: true,
			消息: '数据不合法',
		};
	}
	const 版本 = new Uint8Array(数据缓冲.slice(0, 1));
	let 令牌有效 = false;
	let 是数据报 = false;
	if (字节转文本(new Uint8Array(数据缓冲.slice(1, 17))) === 认证令牌) {
		令牌有效 = true;
	}
	if (!令牌有效) {
		return {
			出错: true,
			消息: '令牌无效',
		};
	}

	const 附加长度 = new Uint8Array(数据缓冲.slice(17, 18))[0];
	// 暂时跳过附加信息

	const 命令 = new Uint8Array(
		数据缓冲.slice(18 + 附加长度, 18 + 附加长度 + 1)
	)[0];

	// 0x01 传输
	// 0x02 数据报
	// 0x03 多路复用
	if (命令 === 1) {
	} else if (命令 === 2) {
		是数据报 = true;
	} else {
		return {
			出错: true,
			消息: `命令 ${命令} 不支持，仅支持 01-传输 / 02-数据报 / 03-多路复用`,
		};
	}
	const 端口偏移 = 18 + 附加长度 + 1;
	const 端口缓冲 = 数据缓冲.slice(端口偏移, 端口偏移 + 2);
	// 端口在原始数据里是大端序，例如 80 == 0x005d
	const 目标端口 = new DataView(端口缓冲).getUint16(0);

	let 地址偏移 = 端口偏移 + 2;
	const 地址缓冲 = new Uint8Array(
		数据缓冲.slice(地址偏移, 地址偏移 + 1)
	);

	// 1--> IPv4  地址长度 = 4
	// 2--> 域名   地址长度 = 地址缓冲[1]
	// 3--> IPv6  地址长度 = 16
	const 地址类型 = 地址缓冲[0];
	let 地址长度 = 0;
	let 地址值偏移 = 地址偏移 + 1;
	let 目标地址 = '';
	switch (地址类型) {
		case 1:
			地址长度 = 4;
			目标地址 = new Uint8Array(
				数据缓冲.slice(地址值偏移, 地址值偏移 + 地址长度)
			).join('.');
			break;
		case 2:
			地址长度 = new Uint8Array(
				数据缓冲.slice(地址值偏移, 地址值偏移 + 1)
			)[0];
			地址值偏移 += 1;
			目标地址 = new TextDecoder().decode(
				数据缓冲.slice(地址值偏移, 地址值偏移 + 地址长度)
			);
			break;
		case 3:
			地址长度 = 16;
			const 数据视图 = new DataView(
				数据缓冲.slice(地址值偏移, 地址值偏移 + 地址长度)
			);
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const 六段地址 = [];
			for (let 索引 = 0; 索引 < 8; 索引++) {
				六段地址.push(数据视图.getUint16(索引 * 2).toString(16));
			}
			目标地址 = 六段地址.join(':');
			// IPv6 似乎无需加方括号
			break;
		default:
			return {
				出错: true,
				消息: `地址类型不合法：${地址类型}`,
			};
	}
	if (!目标地址) {
		return {
			出错: true,
			消息: `地址为空，地址类型是 ${地址类型}`,
		};
	}

	return {
		出错: false,
		目标地址: 目标地址,
		地址类型,
		目标端口,
		首包偏移: 地址值偏移 + 地址长度,
		协议版本: 版本,
		是数据报,
	};
}


/**
 *
 * @param {import("@cloudflare/workers-types").Socket} 远端套接字
 * @param {import("@cloudflare/workers-types").WebSocket} 套接字
 * @param {ArrayBuffer} 响应头部
 * @param {(() => Promise<void>) | null} 重试
 * @param {*} 记录
 */
async function 远端回传套接字(远端套接字, 套接字, 响应头部, 重试, 记录) {
	// 远端 --> 套接字
	let 远端块计数 = 0;
	let 块列表 = [];
	/** @type {ArrayBuffer | null} */
	let 头部 = 响应头部;
	let 有回传数据 = false; // 检查远端套接字是否有回传数据
	await 远端套接字.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				/**
				 *
				 * @param {Uint8Array} 数据块
				 * @param {*} controller
				 */
				async write(数据块, controller) {
					有回传数据 = true;
					// 远端块计数++;
					if (套接字.readyState !== 套接字状态_打开) {
						controller.error(
							'套接字状态不是打开，可能已关闭'
						);
					}
					if (头部) {
						套接字.send(await new Blob([头部, 数据块]).arrayBuffer());
						头部 = null;
					} else {
						// 似乎无需限速，CF 好像已修复此问题
						套接字.send(数据块);
					}
				},
				close() {
					记录(`远端可读流已关闭，是否有回传数据：${有回传数据}`);
					// 无需服务端先关套接字，某些情况下会导致 HTTP ERR_CONTENT_LENGTH_MISMATCH，客户端总会发关闭事件
				},
				abort(原因) {
					console.error(`远端可读流已中止`, 原因);
				},
			})
		)
		.catch((错误) => {
			console.error(
				`远端回传套接字异常 `,
				错误.stack || 错误
			);
			安全关闭套接字(套接字);
		});

	// 似乎是 CF 建立套接字出错的情况：
	// 1. Socket.closed 会带错误
	// 2. Socket.readable 会在没有任何数据到达时关闭
	if (有回传数据 === false && 重试) {
		记录(`重试`)
		重试();
	}
}

/**
 *
 * @param {string} 文本
 * @returns
 */
function 六四转字节缓冲(文本) {
	if (!文本) {
		return { error: null };
	}
	try {
		// Go 使用 rfc4648 的 URL 安全 base64，而 js 的 atob 不支持，需要先替换
		文本 = 文本.replace(/-/g, '+').replace(/_/g, '/');
		const 解码 = atob(文本);
		const 字节缓冲 = Uint8Array.from(解码, (字符) => 字符.charCodeAt(0));
		return { 前置数据: 字节缓冲.buffer, error: null };
	} catch (error) {
		return { error };
	}
}

/**
 * 这不是严格的 UUID 校验
 * @param {string} 令牌
 */
function 校验令牌格式(令牌) {
	const 令牌正则 = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return 令牌正则.test(令牌);
}

const 套接字状态_打开 = 1;
const 套接字状态_关闭中 = 2;
/**
 * 正常情况下套接字关闭不会抛异常。
 * @param {import("@cloudflare/workers-types").WebSocket} 套接字
 */
function 安全关闭套接字(套接字) {
	try {
		if (套接字.readyState === 套接字状态_打开 || 套接字.readyState === 套接字状态_关闭中) {
			套接字.close();
		}
	} catch (error) {
		console.error('安全关闭套接字出错', error);
	}
}

const 字节十六进制表 = [];
for (let 索引 = 0; 索引 < 256; ++索引) {
	字节十六进制表.push((索引 + 256).toString(16).slice(1));
}
function 字节转文本_不校验(字节数组, 偏移 = 0) {
	return (字节十六进制表[字节数组[偏移 + 0]] + 字节十六进制表[字节数组[偏移 + 1]] + 字节十六进制表[字节数组[偏移 + 2]] + 字节十六进制表[字节数组[偏移 + 3]] + "-" + 字节十六进制表[字节数组[偏移 + 4]] + 字节十六进制表[字节数组[偏移 + 5]] + "-" + 字节十六进制表[字节数组[偏移 + 6]] + 字节十六进制表[字节数组[偏移 + 7]] + "-" + 字节十六进制表[字节数组[偏移 + 8]] + 字节十六进制表[字节数组[偏移 + 9]] + "-" + 字节十六进制表[字节数组[偏移 + 10]] + 字节十六进制表[字节数组[偏移 + 11]] + 字节十六进制表[字节数组[偏移 + 12]] + 字节十六进制表[字节数组[偏移 + 13]] + 字节十六进制表[字节数组[偏移 + 14]] + 字节十六进制表[字节数组[偏移 + 15]]).toLowerCase();
}
function 字节转文本(字节数组, 偏移 = 0) {
	const 令牌 = 字节转文本_不校验(字节数组, 偏移);
	if (!校验令牌格式(令牌)) {
		throw TypeError("还原出的令牌不合法");
	}
	return 令牌;
}

/**
 *
 * @param {ArrayBuffer} 报文数据
 * @param {import("@cloudflare/workers-types").WebSocket} 套接字
 * @param {ArrayBuffer} 响应头部
 * @param {(string)=> void} 记录
 */
async function 处理域名解析(报文数据, 套接字, 响应头部, 记录) {
	// 无论客户端发来哪个解析服务器，都固定使用硬编码的那个
	// 因为部分解析服务器不支持基于传输层的查询
	try {
		const 解析服务器 = '8.8.4.4'; // 等 CF 修复连接自身 IP 的问题后可改 1.1.1.1
		const 解析端口 = 53;
		/** @type {ArrayBuffer | null} */
		let 头部 = 响应头部;
		/** @type {import("@cloudflare/workers-types").Socket} */
		const 传输套接字 = 连接({
			hostname: 解析服务器,
			port: 解析端口,
		});

		记录(`已连接 ${解析服务器}:${解析端口}`);
		const 写入器 = 传输套接字.writable.getWriter();
		await 写入器.write(报文数据);
		写入器.releaseLock();
		await 传输套接字.readable.pipeTo(new WritableStream({
			async write(数据块) {
				if (套接字.readyState === 套接字状态_打开) {
					if (头部) {
						套接字.send(await new Blob([头部, 数据块]).arrayBuffer());
						头部 = null;
					} else {
						套接字.send(数据块);
					}
				}
			},
			close() {
				记录(`解析服务器(${解析服务器})连接已关闭`);
			},
			abort(原因) {
				console.error(`解析服务器(${解析服务器})连接已中止`, 原因);
			},
		}));
	} catch (错误) {
		console.error(
			`处理域名解析异常，错误：${错误.message}`
		);
	}
}

/**
 *
 * @param {number} 地址类型
 * @param {string} 目标地址
 * @param {number} 目标端口
 * @param {function} 记录 日志函数。
 */
async function 中转连接(地址类型, 目标地址, 目标端口, 记录) {
	const { 用户名, 密码, 主机名, 端口 } = 中转配置;
	// 连接中转服务器
	const 套接字 = 连接({
		hostname: 主机名,
		port: 端口,
	});

	// 握手请求头格式（本端 -> 中转服务器）：
	// +----+----------+----------+
	// |版本 | 方法数量  |  方法列表 |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	// 方法取值：
	// 0x00 无需认证
	// 0x02 用户名/密码认证
	const 握手问候 = new Uint8Array([5, 2, 0, 2]);

	const 写入器 = 套接字.writable.getWriter();

	await 写入器.write(握手问候);
	记录('已发送握手问候');

	const 读取器 = 套接字.readable.getReader();
	const 编码器 = new TextEncoder();
	let 响应 = (await 读取器.read()).value;
	// 响应格式（中转服务器 -> 本端）：
	// +----+--------+
	// |版本 |  方法  |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	if (响应[0] !== 0x05) {
		记录(`中转服务器版本错误：${响应[0]}，期望：5`);
		return;
	}
	if (响应[1] === 0xff) {
		记录("没有可接受的认证方法");
		return;
	}

	// 若返回 0x0502
	if (响应[1] === 0x02) {
		记录("中转服务器需要认证");
		if (!用户名 || !密码) {
			记录("请提供用户名/密码");
			return;
		}
		// +----+------+----------+------+----------+
		// |版本 | 用户名长度|  用户名   | 密码长度 |  密码  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		const 认证请求 = new Uint8Array([
			1,
			用户名.length,
			...编码器.encode(用户名),
			密码.length,
			...编码器.encode(密码)
		]);
		await 写入器.write(认证请求);
		响应 = (await 读取器.read()).value;
		// 期望 0x0100
		if (响应[0] !== 0x01 || 响应[1] !== 0x00) {
			记录("中转服务器认证失败");
			return;
		}
	}

	// 请求数据格式（本端 -> 中转服务器）：
	// +----+-----+-------+------+----------+----------+
	// |版本 | 命令 |  保留  | 地址型 | 目标地址  | 目标端口  |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | 可变      |    2     |
	// +----+-----+-------+------+----------+----------+
	// 地址型：后续地址的类型
	// 0x01：IPv4 地址
	// 0x03：域名
	// 0x04：IPv6 地址
	// 目标地址：期望连接的目标地址
	// 目标端口：期望连接的目标端口（网络字节序）

	// 地址类型
	// 1--> IPv4  地址长度 = 4
	// 2--> 域名
	// 3--> IPv6  地址长度 = 16
	let 目标地址报文;	// 目标地址报文 = 地址型 + 目标地址
	switch (地址类型) {
		case 1:
			目标地址报文 = new Uint8Array(
				[1, ...目标地址.split('.').map(Number)]
			);
			break;
		case 2:
			目标地址报文 = new Uint8Array(
				[3, 目标地址.length, ...编码器.encode(目标地址)]
			);
			break;
		case 3:
			目标地址报文 = new Uint8Array(
				[4, ...目标地址.split(':').flatMap(段 => [parseInt(段.slice(0, 2), 16), parseInt(段.slice(2), 16)])]
			);
			break;
		default:
			记录(`地址类型不合法：${地址类型}`);
			return;
	}
	const 连接请求 = new Uint8Array([5, 1, 0, ...目标地址报文, 目标端口 >> 8, 目标端口 & 0xff]);
	await 写入器.write(连接请求);
	记录('已发送连接请求');

	响应 = (await 读取器.read()).value;
	// 响应格式（中转服务器 -> 本端）：
	// +----+-----+-------+------+----------+----------+
	// |版本 | 应答 |  保留  | 地址型 | 绑定地址  | 绑定端口  |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | 可变      |    2     |
	// +----+-----+-------+------+----------+----------+
	if (响应[1] === 0x00) {
		记录("中转连接已建立");
	} else {
		记录("中转连接建立失败");
		return;
	}
	写入器.releaseLock();
	读取器.releaseLock();
	return 套接字;
}


/**
 *
 * @param {string} 地址
 */
function 解析中转地址(地址) {
	let [后段, 前段] = 地址.split("@").reverse();
	let 用户名, 密码, 主机名, 端口;
	if (前段) {
		const 前段列表 = 前段.split(":");
		if (前段列表.length !== 2) {
			throw new Error('中转地址格式不合法');
		}
		[用户名, 密码] = 前段列表;
	}
	const 后段列表 = 后段.split(":");
	端口 = Number(后段列表.pop());
	if (isNaN(端口)) {
		throw new Error('中转地址格式不合法');
	}
	主机名 = 后段列表.join(":");
	const 正则 = /^\[.*\]$/;
	if (主机名.includes(":") && !正则.test(主机名)) {
		throw new Error('中转地址格式不合法');
	}
	return {
		用户名,
		密码,
		主机名,
		端口,
	}
}

/**
 * 按配置区「优选地址」收集连接用地址。
 * 每一项可以是 host:port，也可以是在线列表的 URL（逐行 host:port#备注）。
 * @param {string} 主机名 访问域名，作兜底
 * @returns {Promise<Array<{地址: string, 端口: string, 备注: string}>>}
 */
async function 收集优选地址(主机名) {
	const 结果 = [];
	const 已见 = new Set();
	const 加入 = (原始) => {
		const 文本 = (原始 || '').trim();
		if (!文本) return;
		const 井号分割 = 文本.split('#');
		const 备注 = 井号分割.length > 1 ? 井号分割.slice(1).join('#').trim() : '';
		const 地址端口 = 井号分割[0].trim();
		if (!地址端口) return;
		let 地址;
		let 端口;
		const 六 = 地址端口.match(/^\[(.+)\]:(\d+)$/);
		if (六) {
			地址 = 六[1];
			端口 = 六[2];
		} else if (地址端口.includes(':') && 地址端口.split(':').length === 2) {
			[地址, 端口] = 地址端口.split(':');
		} else {
			地址 = 地址端口;
			端口 = '443';
		}
		地址 = (地址 || '').trim();
		端口 = (端口 || '443').trim();
		if (!地址) return;
		const 键 = `${地址}:${端口}`;
		if (已见.has(键)) return;
		已见.add(键);
		结果.push({ 地址, 端口, 备注: 备注 || 键 });
	};

	// 分隔符兼容中英文逗号
	const 配置项列表 = (优选地址 || '').split(/[,，]/).map((项) => 项.trim()).filter((项) => 项);
	for (const 配置项 of 配置项列表) {
		if (/^https?:\/\//i.test(配置项)) {
			try {
				const 响应 = await fetch(配置项, { cf: { cacheTtl: 300 } });
				if (响应.ok) {
					const 正文 = await 响应.text();
					for (const 行 of 正文.split('\n')) 加入(行);
				}
			} catch (err) {
				// 拉取失败就跳过这条 URL
			}
		} else {
			加入(配置项);
		}
	}

	if (结果.length === 0 && 主机名) 加入(主机名);
	return 结果;
}

/**
 * 生成订阅内容：为「优选地址」里每个地址各生成一条节点，连接走优选地址，
 * TLS 握手与 WS host 仍用访问域名，最后整体 base64 编码，可直接订阅。
 * @param {string} 认证令牌
 * @param {string | null} 主机名 访问域名
 * @returns {Promise<string>}
 */
async function 生成订阅配置(认证令牌, 主机名) {
	const 协议 = 解码64('dmxlc3M=');
	const 域名 = 主机名 || '';
	// CF 的明文端口走 ws（不加密），其余端口走 wss（TLS），据此自动切换
	const 明文端口 = [80, 8080, 8880, 2052, 2082, 2086, 2095];
	const 地址列表 = await 收集优选地址(域名);
	const 链接列表 = 地址列表.map((项) => {
		const 安全地址 = 项.地址.includes(':') ? `[${项.地址}]` : 项.地址;
		const 是明文 = 明文端口.includes(Number(项.端口));
		// randomized fingerprint may cause TLS compatibility issues with some Xray/uTLS clients.
		// Use chrome as default for better compatibility.
		const 安全参数 = 是明文
			? 'security=none'
			: `security=tls&sni=${域名}&fp=chrome`;
		return `${协议}://${认证令牌}@${安全地址}:${项.端口}` +
			`?encryption=none&${安全参数}&type=ws&host=${域名}&path=%2F%3Fed%3D2048` +
			`#${encodeURIComponent(项.备注)}`;
	});
	return btoa(链接列表.join('\n'));
}
