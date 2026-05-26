    // CFnew - 终端 v2.9.8
    // 版本: v2.9.8 
    import { connect } from 'cloudflare:sockets';
    let at = '351c9981-04b6-4103-aa4b-864aa9c91469';
    let fallbackAddress = '';
    let socks5Config = '';
    let customPreferredIPs = [];
    let customPreferredDomains = [];
    let enableSocksDowngrade = false;
    let disableNonTLS = false;
    let disablePreferred = false;
    let enableRegionMatching = true;
    let currentWorkerRegion = '';
    let manualWorkerRegion = '';
    let piu = '';
    let cp = '';  

    let ev = true;   
    let et = false; 
    let ex = false;  
    let tp = '';
    // 启用ECH功能（true启用，false禁用）
    let enableECH = false;  
    // 自定义DNS服务器（默认：https://223.5.5.5/dns-query）
    let customDNS = 'https://223.5.5.5/dns-query';
    // 自定义ECH域名（默认：cloudflare-ech.com）
    let customECHDomain = 'cloudflare-ech.com';
    let customALPN = '';

    let scu = 'https://url.v1.mk/sub';  
    // 远程配置URL（硬编码）
    const remoteConfigUrl = 'https://raw.githubusercontent.com/byJoey/test/refs/heads/main/tist.ini';

    let epd = true;   // 优选域名默认关闭
    let epi = true;       
    let egi = true;
    let ena = false;   // 原生地址默认关闭          

    let kvStore = null;
    let kvConfig = {};
    let kvConfigLastLoad = 0;
    const KV_CACHE_TTL = 30 * 1000; // 30秒缓存（短窗口内跳过版本检查）
    let kvConfigVersion = '';

    const regionMapping = {
        'HK': ['🇭🇰 香港', 'HK', 'Hong Kong'],
        'US': ['🇺🇸 美国', 'US', 'United States'],
        'SG': ['🇸🇬 新加坡', 'SG', 'Singapore'],
        'JP': ['🇯🇵 日本', 'JP', 'Japan'],
        'KR': ['🇰🇷 韩国', 'KR', 'South Korea'],
        'DE': ['🇩🇪 德国', 'DE', 'Germany'],
        'SE': ['🇸🇪 瑞典', 'SE', 'Sweden'],
        'NL': ['🇳🇱 荷兰', 'NL', 'Netherlands'],
        'FI': ['🇫🇮 芬兰', 'FI', 'Finland'],
        'GB': ['🇬🇧 英国', 'GB', 'United Kingdom'],
        'Oracle': ['甲骨文', 'Oracle'],
        'DigitalOcean': ['数码海', 'DigitalOcean'],
        'Vultr': ['Vultr', 'Vultr'],
        'Multacom': ['Multacom', 'Multacom']
    };

    let backupIPs = [
        { domain: 'ProxyIP.HK.CMLiussss.net', region: 'HK', regionCode: 'HK', port: 443 },
        { domain: 'ProxyIP.US.CMLiussss.net', region: 'US', regionCode: 'US', port: 443 },
        { domain: 'ProxyIP.SG.CMLiussss.net', region: 'SG', regionCode: 'SG', port: 443 },
        { domain: 'ProxyIP.JP.CMLiussss.net', region: 'JP', regionCode: 'JP', port: 443 },
        { domain: 'ProxyIP.KR.CMLiussss.net', region: 'KR', regionCode: 'KR', port: 443 },
        { domain: 'ProxyIP.DE.CMLiussss.net', region: 'DE', regionCode: 'DE', port: 443 },
        { domain: 'ProxyIP.SE.CMLiussss.net', region: 'SE', regionCode: 'SE', port: 443 },
        { domain: 'ProxyIP.NL.CMLiussss.net', region: 'NL', regionCode: 'NL', port: 443 },
        { domain: 'ProxyIP.FI.CMLiussss.net', region: 'FI', regionCode: 'FI', port: 443 },
        { domain: 'ProxyIP.GB.CMLiussss.net', region: 'GB', regionCode: 'GB', port: 443 },
        { domain: 'ProxyIP.Oracle.cmliussss.net', region: 'Oracle', regionCode: 'Oracle', port: 443 },
        { domain: 'ProxyIP.DigitalOcean.CMLiussss.net', region: 'DigitalOcean', regionCode: 'DigitalOcean', port: 443 },
        { domain: 'ProxyIP.Vultr.CMLiussss.net', region: 'Vultr', regionCode: 'Vultr', port: 443 },
        { domain: 'ProxyIP.Multacom.CMLiussss.net', region: 'Multacom', regionCode: 'Multacom', port: 443 }
    ];

    const directDomains = [
        { name: "cloudflare.182682.xyz", domain: "cloudflare.182682.xyz" }, { name: "speed.marisalnc.com", domain: "speed.marisalnc.com" },
        { domain: "freeyx.cloudflare88.eu.org" }, { domain: "bestcf.top" }, { domain: "cdn.2020111.xyz" }, { domain: "cfip.cfcdn.vip" },
        { domain: "cf.0sm.com" }, { domain: "cf.090227.xyz" }, { domain: "cf.zhetengsha.eu.org" }, { domain: "cloudflare.9jy.cc" },
        { domain: "cf.zerone-cdn.pp.ua" }, { domain: "cfip.1323123.xyz" }, { domain: "cnamefuckxxs.yuchen.icu" }, { domain: "cloudflare-ip.mofashi.ltd" },
        { domain: "115155.xyz" }, { domain: "cname.xirancdn.us" }, { domain: "f3058171cad.002404.xyz" }, { domain: "8.889288.xyz" },
        { domain: "cdn.tzpro.xyz" }, { domain: "cf.877771.xyz" }, { domain: "xn--b6gac.eu.org" }
    ];

    const E_INVALID_DATA = atob('aW52YWxpZCBkYXRh');
    const E_INVALID_USER = atob('aW52YWxpZCB1c2Vy');
    const E_UNSUPPORTED_CMD = atob('Y29tbWFuZCBpcyBub3Qgc3VwcG9ydGVk');
    const E_UDP_DNS_ONLY = atob('VURQIHByb3h5IG9ubHkgZW5hYmxlIGZvciBETlMgd2hpY2ggaXMgcG9ydCA1Mw==');
    const E_INVALID_ADDR_TYPE = atob('aW52YWxpZCBhZGRyZXNzVHlwZQ==');
    const E_EMPTY_ADDR = atob('YWRkcmVzc1ZhbHVlIGlzIGVtcHR5');
    const E_WS_NOT_OPEN = atob('d2ViU29ja2V0LmVhZHlTdGF0ZSBpcyBub3Qgb3Blbg==');
    const E_INVALID_ID_STR = atob('U3RyaW5naWZpZWQgaWRlbnRpZmllciBpcyBpbnZhbGlk');
    const E_INVALID_SOCKS_ADDR = atob('SW52YWxpZCBTT0NLUyBhZGRyZXNzIGZvcm1hdA==');
    const E_SOCKS_NO_METHOD = atob('bm8gYWNjZXB0YWJsZSBtZXRob2Rz');
    const E_SOCKS_AUTH_NEEDED = atob('c29ja3Mgc2VydmVyIG5lZWRzIGF1dGg=');
    const E_SOCKS_AUTH_FAIL = atob('ZmFpbCB0byBhdXRoIHNvY2tzIHNlcnZlcg==');
    const E_SOCKS_CONN_FAIL = atob('ZmFpbCB0byBvcGVuIHNvY2tzIGNvbm5lY3Rpb24=');

    let parsedSocks5Config = {};
    let isSocksEnabled = false;

    const ADDRESS_TYPE_IPV4 = 1;
    const ADDRESS_TYPE_URL = 2;
    const ADDRESS_TYPE_IPV6 = 3;
    const TRANSPORT_CHUNK_SIZE = 64 * 1024;
    const TRANSPORT_DN_PACK = 32 * 1024;
    const TRANSPORT_DN_TAIL = 512;
    const TRANSPORT_DN_DELAY = 0;
    const TRANSPORT_UP_PACK = 16 * 1024;
    const TRANSPORT_UP_Q_MAX = 256 * 1024;
    const TRANSPORT_CONNECT_RACE = 2;
    const FIRST_BYTE_TIMEOUT = 3500;
    const sharedDecoder = new TextDecoder();
    const uuidByteCache = new Map();

	function isValidFormat(str) {
        const userRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        return userRegex.test(str);
    }

    function isValidIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (ipv4Regex.test(ip)) return true;

        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        if (ipv6Regex.test(ip)) return true;

        const ipv6ShortRegex = /^::1$|^::$|^(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;
        if (ipv6ShortRegex.test(ip)) return true;

        return false;
    }

    function createNodeNamer(skip = false) {
        // 如果配置了 yxURL，则跳过编号
        const forceSkip = (typeof piu !== 'undefined' && piu && piu.trim());
        let skipNumbering = forceSkip || skip;
        const counters = {};

        function setSkipNumbering(flag) {
            if (!forceSkip) {
                skipNumbering = flag;
            }
        }

        function namer(baseName, nodeName = null) {
            if (skipNumbering || (baseName && baseName.includes('.'))) {
                return nodeName || baseName;
            }
            if (!counters[baseName]) counters[baseName] = 0;
            counters[baseName]++;
            const index = String(counters[baseName]).padStart(2, '0');
            return `${nodeName || baseName}-${index}`;
        }

        return { namer, setSkipNumbering };
    }

    function normalizeNodeHost(host) {
        return String(host || '').trim().replace(/^\[([^\]]+)\]$/, '$1');
    }

    function compactNodeAliasPart(value, fallback = 'Node') {
        let text = String(value || '').trim();
        if (!text || /^自定义优选-/i.test(text)) text = fallback;
        text = text
            .replace(/^\[([^\]]+)\]$/, '$1')
            .replace(/^https?:\/\//i, '')
            .replace(/[/?#].*$/, '')
            .replace(/\s+/g, '_');
        return text || fallback;
    }

    function getCompactNodeAliasBase(item) {
        const host = normalizeNodeHost(item?.ip || item?.domain || '');
        if (host && host.includes(':') && /^[0-9a-fA-F:.]+$/.test(host)) return 'IPv6优选';
        if (host && !isValidIP(host)) return '优选域名';

        const isp = compactNodeAliasPart(item?.isp || item?.name || '', 'IPv4优选');
        const colo = compactNodeAliasPart(item?.colo || '', '');
        return colo ? `${isp}-${colo}` : isp;
    }

    function createCompactNodeNamer(skipNumbering = false) {
        const counters = {};
        return (item) => {
            const base = getCompactNodeAliasBase(item);
            if (skipNumbering) return base;
            counters[base] = (counters[base] || 0) + 1;
            return `${base}-${String(counters[base]).padStart(2, '0')}`;
        };
    }

    function normalizeALPN(value) {
        const allowed = ['', 'h3', 'h2', 'http/1.1', 'h3,h2', 'h2,http/1.1', 'h3,h2,http/1.1'];
        const alpn = String(value || '').trim();
        return allowed.includes(alpn) ? alpn : '';
    }

    function applyALPNParam(params) {
        const alpn = normalizeALPN(customALPN);
        if (alpn) params.set('alpn', alpn);
    }

    async function initKVStore(env) {
        if (env.C) {
            try {
                kvStore = env.C;
                await loadKVConfig();
            } catch (error) {
                kvStore = null;
            }
        } else {
        }
    }

    async function loadKVConfig(force = false) {
        if (!kvStore) {
            return;
        }

        // 短窗口内完全信任缓存，避免高频请求时打爆 KV
        if (!force && kvConfigLastLoad > 0 && (Date.now() - kvConfigLastLoad) < KV_CACHE_TTL) {
            return;
        }

        try {
            // 读取小体积的版本键 c_ver（约 13B），用于跨 isolate 缓存失效
            let ver = '';
            try { ver = (await kvStore.get('c_ver')) || ''; } catch (_) {}

            // 版本未变化且已有缓存，仅刷新时间戳，跳过完整读取
            if (!force && ver && ver === kvConfigVersion && kvConfig && Object.keys(kvConfig).length > 0) {
                kvConfigLastLoad = Date.now();
                return;
            }

            const configData = await kvStore.get('c');
            if (configData) {
                kvConfig = JSON.parse(configData);
            }
            kvConfigVersion = ver;
            kvConfigLastLoad = Date.now();
        } catch (error) {
            // 读取失败时保留现有缓存，避免临时故障导致配置丢失
            if (!kvConfig) kvConfig = {};
        }
    }

    async function saveKVConfig() {
        if (!kvStore) {
            return;
        }

        try {
            const configString = JSON.stringify(kvConfig);
            await kvStore.put('c', configString);
            // 写入版本号，让其它 isolate 在下次请求时能立即看到变更
            const newVer = String(Date.now());
            kvConfigVersion = newVer;
            try { await kvStore.put('c_ver', newVer); } catch (_) {}
            kvConfigLastLoad = Date.now();
        } catch (error) {
            throw error; 
        }
    }

    function getConfigValue(key, defaultValue = '') {
        if (kvConfig[key] !== undefined) {
            return kvConfig[key];
        }
        return defaultValue;
    }

    async function setConfigValue(key, value) {
        kvConfig[key] = value;
        await saveKVConfig();
    }

    async function detectWorkerRegion(request) {
        try {
            const cfCountry = request.cf?.country;
            if (cfCountry) {
                const countryToRegion = {
                    'US': 'US', 'SG': 'SG', 'JP': 'JP', 'KR': 'KR',
                    'DE': 'DE', 'SE': 'SE', 'NL': 'NL', 'FI': 'FI', 'GB': 'GB',
                    'CN': 'SG', 'TW': 'JP', 'AU': 'SG', 'CA': 'US',
                    'FR': 'DE', 'IT': 'DE', 'ES': 'DE', 'CH': 'DE',
                    'AT': 'DE', 'BE': 'NL', 'DK': 'SE', 'NO': 'SE', 'IE': 'GB'
                };

                if (countryToRegion[cfCountry]) {
                    return countryToRegion[cfCountry];
                }
            }
            return 'SG';
            
        } catch (error) {
            return 'SG';
        }
    }

    async function checkIPAvailability(domain, port = 443, timeout = 2000) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);

            const response = await fetch(`https://${domain}`, {
                method: 'HEAD',
                signal: controller.signal,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Checker/1.0)'
                }
            });

            clearTimeout(timeoutId);
            return response.status < 500;
        } catch (error) {
            return true;
        }
    }

    async function getBestBackupIP(workerRegion = '', useRegionMatching = enableRegionMatching) {
        if (backupIPs.length === 0) {
            return null;
        }

        const availableIPs = backupIPs.map(ip => ({ ...ip, available: true }));

        if (useRegionMatching && workerRegion) {
            const sortedIPs = getSmartRegionSelection(workerRegion, availableIPs, useRegionMatching);
            if (sortedIPs.length > 0) {
                const selectedIP = sortedIPs[0];
                return selectedIP;
            }
        }

        const selectedIP = availableIPs[0];
        return selectedIP;
    }

    function getNearbyRegions(region) {
        const nearbyMap = {
            'US': ['SG', 'JP', 'KR'], 
            'SG': ['JP', 'KR', 'US'], 
            'JP': ['SG', 'KR', 'US'], 
            'KR': ['JP', 'SG', 'US'], 
            'DE': ['NL', 'GB', 'SE', 'FI'], 
            'SE': ['DE', 'NL', 'FI', 'GB'], 
            'NL': ['DE', 'GB', 'SE', 'FI'], 
            'FI': ['SE', 'DE', 'NL', 'GB'], 
            'GB': ['DE', 'NL', 'SE', 'FI']  
        };

        return nearbyMap[region] || [];
    }

    function getAllRegionsByPriority(region) {
        const nearbyRegions = getNearbyRegions(region);
        const allRegions = ['US', 'SG', 'JP', 'KR', 'DE', 'SE', 'NL', 'FI', 'GB'];

        return [region, ...nearbyRegions, ...allRegions.filter(r => r !== region && !nearbyRegions.includes(r))];
    }

    function getSmartRegionSelection(workerRegion, availableIPs, useRegionMatching = enableRegionMatching) {
        if (!useRegionMatching || !workerRegion) {
            return availableIPs;
        }

        const priorityRegions = getAllRegionsByPriority(workerRegion);

        const sortedIPs = [];

        for (const region of priorityRegions) {
            const regionIPs = availableIPs.filter(ip => ip.regionCode === region);
            sortedIPs.push(...regionIPs);
        }

        return sortedIPs;
    }

    function parseAddressAndPort(input) {
        if (input.includes('[') && input.includes(']')) {
            const match = input.match(/^\[([^\]]+)\](?::(\d+))?$/);
            if (match) {
                return {
                    address: match[1],
                    port: match[2] ? parseInt(match[2], 10) : null
                };
            }
        }

        const lastColonIndex = input.lastIndexOf(':');
        if (lastColonIndex > 0) {
            const address = input.substring(0, lastColonIndex);
            const portStr = input.substring(lastColonIndex + 1);
            const port = parseInt(portStr, 10);

            // address 含 ':' 说明是裸 IPv6（如 2001:db8::1），整体当地址，无端口
            if (!address.includes(':') && !isNaN(port) && port > 0 && port <= 65535) {
                return { address, port };
            }
        }

        return { address: input, port: null };
    }

    export default {
        async fetch(request, env, ctx) {
            try {
                const isWebSocket = request.headers.get('Upgrade') === atob('d2Vic29ja2V0');
                const isPost = request.method === 'POST';
                const reqUrl = new URL(request.url);
                const pathSegments = reqUrl.pathname.split('/').filter(p => p);

                if (!isWebSocket && !isPost && reqUrl.pathname !== '/') {
                    const tmpAt = (env.u || env.U || '').toLowerCase();
                    const tmpCp = (env.d || env.D || '').toLowerCase();
                    const firstSeg = pathSegments[0] || '';
                    const cleanCp = tmpCp.startsWith('/') ? tmpCp.substring(1) : tmpCp;
                    if (firstSeg !== tmpAt && (cleanCp ? firstSeg !== cleanCp : false)) {
                        return new Response('Not Found', { status: 404 });
                    }
                }

                await initKVStore(env);

                at = (env.u || env.U || at).toLowerCase();
                const subPath = (env.d || env.D || at).toLowerCase();

                const ci = getConfigValue('p', env.p || env.P);
                let useCustomIP = false;

                const manualRegion = getConfigValue('wk', env.wk || env.WK);
                if (manualRegion && manualRegion.trim()) {
                    manualWorkerRegion = manualRegion.trim().toUpperCase();
                    currentWorkerRegion = manualWorkerRegion;
            } else if (ci && ci.trim()) {
                    useCustomIP = true;
                    currentWorkerRegion = 'CUSTOM';
                } else {
                    currentWorkerRegion = await detectWorkerRegion(request);
                }

                const regionMatchingControl = env.rm || env.RM;
                if (regionMatchingControl && regionMatchingControl.toLowerCase() === 'no') {
                    enableRegionMatching = false;
                }

                const envFallback = getConfigValue('p', env.p || env.P);
                if (envFallback) {
                    fallbackAddress = envFallback.trim();
                }

                socks5Config = getConfigValue('s', env.s || env.S) || socks5Config;
                if (socks5Config) {
                    try {
                        parsedSocks5Config = parseSocksConfig(socks5Config);
                        isSocksEnabled = true;
                    } catch (err) {
                        isSocksEnabled = false;
                    }
                }

                const customPreferred = getConfigValue('yx', env.yx || env.YX);
                if (customPreferred) {
                    try {
                        const preferredList = customPreferred.split(',').map(item => item.trim()).filter(item => item);
                        customPreferredIPs = [];
                        customPreferredDomains = [];

                        preferredList.forEach(item => {

                            let nodeName = '';
                            let addressPart = item;

                            if (item.includes('#')) {
                                const parts = item.split('#');
                                addressPart = parts[0].trim();
                                nodeName = parts[1].trim();
                            }

                            const { address, port } = parseAddressAndPort(addressPart);

                            if (!nodeName) {
                                nodeName = '自定义优选-' + address + (port ? ':' + port : '');
                            }

                            if (isValidIP(address)) {
                                customPreferredIPs.push({ 
                                    ip: address, 
                                    port: port,
                                    isp: nodeName
                                });
                            } else {
                                customPreferredDomains.push({ 
                                    domain: address, 
                                    port: port,
                                    name: nodeName
                                });
                            }
                        });
                    } catch (err) {
                        customPreferredIPs = [];
                        customPreferredDomains = [];
                    }
                }

                const downgradeControl = getConfigValue('qj', env.qj || env.QJ);
                if (downgradeControl && downgradeControl.toLowerCase() === 'no') {
                    enableSocksDowngrade = true;
                }

                const dkbyControl = getConfigValue('dkby', env.dkby || env.DKBY);
                if (dkbyControl && dkbyControl.toLowerCase() === 'yes') {
                    disableNonTLS = true;
                }

                const yxbyControl = env.yxby || env.YXBY;
                if (yxbyControl && yxbyControl.toLowerCase() === 'yes') {
                    disablePreferred = true;
                }

                const vlessControl = getConfigValue('ev', env.ev);
                if (vlessControl !== undefined && vlessControl !== '') {
                    ev = vlessControl === 'yes' || vlessControl === true || vlessControl === 'true';
                }

                const tjControl = getConfigValue('et', env.et);
                if (tjControl !== undefined && tjControl !== '') {
                    et = tjControl === 'yes' || tjControl === true || tjControl === 'true';
                }

                tp = getConfigValue('tp', env.tp) || '';

                const xhttpControl = getConfigValue('ex', env.ex);
                if (xhttpControl !== undefined && xhttpControl !== '') {
                    ex = xhttpControl === 'yes' || xhttpControl === true || xhttpControl === 'true';
                }

                scu = getConfigValue('scu', env.scu) || 'https://url.v1.mk/sub';

                const preferredDomainsControl = getConfigValue('epd', env.epd || 'no');
                if (preferredDomainsControl !== undefined && preferredDomainsControl !== '') {
                    epd = preferredDomainsControl !== 'no' && preferredDomainsControl !== false && preferredDomainsControl !== 'false';
                }

                const preferredIPsControl = getConfigValue('epi', env.epi);
                if (preferredIPsControl !== undefined && preferredIPsControl !== '') {
                    epi = preferredIPsControl !== 'no' && preferredIPsControl !== false && preferredIPsControl !== 'false';
                }

                const githubIPsControl = getConfigValue('egi', env.egi);
                if (githubIPsControl !== undefined && githubIPsControl !== '') {
                    egi = githubIPsControl !== 'no' && githubIPsControl !== false && githubIPsControl !== 'false';
                }

                const nativeAddressControl = getConfigValue('ena', env.ena);
                if (nativeAddressControl !== undefined && nativeAddressControl !== '') {
                    ena = nativeAddressControl !== 'no' && nativeAddressControl !== false && nativeAddressControl !== 'false';
                }

                const echControl = getConfigValue('ech', env.ech);
                if (echControl !== undefined && echControl !== '') {
                    enableECH = echControl === 'yes' || echControl === true || echControl === 'true';
                }

                // 加载自定义DNS和ECH域名配置
                const customDNSValue = getConfigValue('customDNS', '');
                if (customDNSValue && customDNSValue.trim()) {
                    customDNS = customDNSValue.trim();
                }

                const customECHDomainValue = getConfigValue('customECHDomain', '');
                if (customECHDomainValue && customECHDomainValue.trim()) {
                    customECHDomain = customECHDomainValue.trim();
                }

                customALPN = normalizeALPN(getConfigValue('alpn', env.alpn || env.ALPN || ''));

                // 如果启用了ECH，自动启用仅TLS模式（避免80端口干扰）
                // ECH需要TLS才能工作，所以必须禁用非TLS节点
                if (enableECH) {
                    disableNonTLS = true;
                    // 检查 KV 中是否有 dkby: yes，没有就直接写入
                    const currentDkby = getConfigValue('dkby', '');
                    if (currentDkby !== 'yes') {
                        await setConfigValue('dkby', 'yes');
                    }
                }

                if (!ev && !et && !ex) {
                    ev = true;
                }

                piu = getConfigValue('yxURL', env.yxURL || env.YXURL) || '';

                cp = getConfigValue('d', env.d || env.D) || '';

                const url = new URL(request.url);

                if (url.pathname.includes('/api/config')) {
                    const pathParts = url.pathname.split('/').filter(p => p);

                    const apiIndex = pathParts.indexOf('api');
                    if (apiIndex > 0) {
                        const pathSegments = pathParts.slice(0, apiIndex);
                        const pathIdentifier = pathSegments.join('/');
                        
                    let isValid = false;
                    if (cp && cp.trim()) {
                        const cleanCustomPath = cp.trim().startsWith('/') ? cp.trim().substring(1) : cp.trim();
                        isValid = (pathIdentifier === cleanCustomPath);
                        } else {
                            isValid = (isValidFormat(pathIdentifier) && pathIdentifier === at);
                        }

                        if (isValid) {
                            return await handleConfigAPI(request);
                        } else {
                            return new Response(JSON.stringify({ error: '路径验证失败' }), { 
                                status: 403,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }
                    }

                    return new Response(JSON.stringify({ error: '无效的API路径' }), { 
                        status: 404,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                if (url.pathname.includes('/api/preferred-ips')) {
                    const pathParts = url.pathname.split('/').filter(p => p);
                    const apiIndex = pathParts.indexOf('api');
                    if (apiIndex > 0) {
                        const pathSegments = pathParts.slice(0, apiIndex);
                        const pathIdentifier = pathSegments.join('/');

                        let isValid = false;
                        if (cp && cp.trim()) {
                            const cleanCustomPath = cp.trim().startsWith('/') ? cp.trim().substring(1) : cp.trim();
                            isValid = (pathIdentifier === cleanCustomPath);
                        } else {
                            isValid = (isValidFormat(pathIdentifier) && pathIdentifier === at);
                        }

                        if (isValid) {
                            return await handlePreferredIPsAPI(request);
                        } else {
                            return new Response(JSON.stringify({ error: '路径验证失败' }), { 
                                status: 403,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }
                    }

                    return new Response(JSON.stringify({ error: '无效的API路径' }), { 
                        status: 404,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

            if (request.method === 'POST' && ex) {
                const r = await handleXhttpPost(request);
                if (r) {
                    ctx.waitUntil(r.closed);
                    return new Response(r.readable, {
                        headers: {
                            'X-Accel-Buffering': 'no',
                            'Cache-Control': 'no-store',
                            Connection: 'keep-alive',
                            'User-Agent': 'Go-http-client/2.0',
                            'Content-Type': 'application/grpc',
                        },
                    });
                }
                return new Response('Internal Server Error', { status: 500 });
            }

            if (request.headers.get('Upgrade') === atob('d2Vic29ja2V0')) {
                return await handleWsRequest(request);
                }

                if (request.method === 'GET') {
                    // 处理 /{UUID}/region 或 /{自定义路径}/region
                    if (url.pathname.endsWith('/region')) {
                        const pathParts = url.pathname.split('/').filter(p => p);

                        if (pathParts.length === 2 && pathParts[1] === 'region') {
                            const pathIdentifier = pathParts[0];
                            let isValid = false;

                            if (cp && cp.trim()) {
                                // 使用自定义路径
                                const cleanCustomPath = cp.trim().startsWith('/') ? cp.trim().substring(1) : cp.trim();
                                isValid = (pathIdentifier === cleanCustomPath);
                            } else {
                                // 使用UUID路径
                                isValid = (isValidFormat(pathIdentifier) && pathIdentifier === at);
                            }

                            if (isValid) {
                                const ci = getConfigValue('p', env.p || env.P);
                                const manualRegion = getConfigValue('wk', env.wk || env.WK);

                                if (manualRegion && manualRegion.trim()) {
                                    return new Response(JSON.stringify({
                                        region: manualRegion.trim().toUpperCase(),
                                        detectionMethod: '手动指定地区',
                                        manualRegion: manualRegion.trim().toUpperCase(),
                                        timestamp: new Date().toISOString()
                                    }), {
                                        headers: { 'Content-Type': 'application/json' }
                                    });
                                } else if (ci && ci.trim()) {
                                    return new Response(JSON.stringify({
                                        region: 'CUSTOM',
                                        detectionMethod: '自定义ProxyIP模式', ci: ci,
                                        timestamp: new Date().toISOString()
                                    }), {
                                        headers: { 'Content-Type': 'application/json' }
                                    });
                                } else {
                                    const detectedRegion = await detectWorkerRegion(request);
                                    return new Response(JSON.stringify({
                                        region: detectedRegion,
                                        detectionMethod: 'API检测',
                                        timestamp: new Date().toISOString()
                                    }), {
                                        headers: { 'Content-Type': 'application/json' }
                                    });
                                }
                            } else {
                                return new Response(JSON.stringify({ 
                                    error: '访问被拒绝',
                                    message: '路径验证失败'
                                }), { 
                                    status: 403,
                                    headers: { 'Content-Type': 'application/json' }
                                });
                            }
                        }
                    }

                    // 处理 /{UUID}/test-api 或 /{自定义路径}/test-api
                    if (url.pathname.endsWith('/test-api')) {
                        const pathParts = url.pathname.split('/').filter(p => p);

                        if (pathParts.length === 2 && pathParts[1] === 'test-api') {
                            const pathIdentifier = pathParts[0];
                            let isValid = false;

                            if (cp && cp.trim()) {
                                // 使用自定义路径
                                const cleanCustomPath = cp.trim().startsWith('/') ? cp.trim().substring(1) : cp.trim();
                                isValid = (pathIdentifier === cleanCustomPath);
                            } else {
                                // 使用UUID路径
                                isValid = (isValidFormat(pathIdentifier) && pathIdentifier === at);
                            }

                            if (isValid) {
                                try {
                                    const testRegion = await detectWorkerRegion(request);
                                    return new Response(JSON.stringify({
                                        detectedRegion: testRegion,
                                        message: 'API测试完成',
                                        timestamp: new Date().toISOString()
                                    }), {
                                        headers: { 'Content-Type': 'application/json' }
                                    });
                                } catch (error) {
                                    return new Response(JSON.stringify({
                                        error: error.message,
                                        message: 'API测试失败'
                                    }), {
                                        status: 500,
                                        headers: { 'Content-Type': 'application/json' }
                                    });
                                }
                            } else {
                                return new Response(JSON.stringify({ 
                                    error: '访问被拒绝',
                                    message: '路径验证失败'
                                }), { 
                                    status: 403,
                                    headers: { 'Content-Type': 'application/json' }
                                });
                            }
                        }
                    }

                    if (url.pathname === '/') {
                        // 检查是否有自定义首页URL配置
                        const customHomepage = getConfigValue('homepage', env.homepage || env.HOMEPAGE);
                        if (customHomepage && customHomepage.trim()) {
                            try {
                                // 从自定义URL获取内容
                                const homepageResponse = await fetch(customHomepage.trim(), {
                                    method: 'GET',
                                    headers: {
                                        'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0',
                                        'Accept': request.headers.get('Accept') || '*/*',
                                        'Accept-Language': request.headers.get('Accept-Language') || 'en-US,en;q=0.9',
                                    },
                                    redirect: 'follow'
                                });

                                if (homepageResponse.ok) {
                                    // 获取响应内容
                                    const contentType = homepageResponse.headers.get('Content-Type') || 'text/html; charset=utf-8';
                                    const content = await homepageResponse.text();
                                    
                                    // 返回自定义首页内容
                                    return new Response(content, {
                                        status: homepageResponse.status,
                                        headers: {
                                            'Content-Type': contentType,
                                            'Cache-Control': 'no-cache, no-store, must-revalidate',
                                        }
                                    });
                                }
                            } catch (error) {
                                // 如果获取失败，继续使用默认终端页面
                                console.error('获取自定义首页失败:', error);
                            }
                        }
                        // 优先检查Cookie中的语言设置
                        const cookieHeader = request.headers.get('Cookie') || '';
                        let langFromCookie = null;
                        if (cookieHeader) {
                            const cookies = cookieHeader.split(';').map(c => c.trim());
                            for (const cookie of cookies) {
                                if (cookie.startsWith('preferredLanguage=')) {
                                    langFromCookie = cookie.split('=')[1];
                                    break;
                                }
                            }
                        }

                        let isFarsi = false;

                        if (langFromCookie === 'fa' || langFromCookie === 'fa-IR') {
                            isFarsi = true;
                        } else if (langFromCookie === 'zh' || langFromCookie === 'zh-CN') {
                            isFarsi = false;
                        } else {
                            // 如果没有Cookie，使用浏览器语言检测
                            const acceptLanguage = request.headers.get('Accept-Language') || '';
                            const browserLang = acceptLanguage.split(',')[0].split('-')[0].toLowerCase();
                            isFarsi = browserLang === 'fa' || acceptLanguage.includes('fa-IR') || acceptLanguage.includes('fa');
                        }

                        const lang = isFarsi ? 'fa' : 'zh-CN';
                        const langAttr = isFarsi ? 'fa-IR' : 'zh-CN';
                            
                        const translations = {
                            zh: {
                                title: '终端 v2.9.8',
                                terminal: '终端 v2.9.8',
                                congratulations: '恭喜你来到这',
                                enterU: '请输入你U变量的值',
                                enterD: '请输入你D变量的值',
                                command: '命令: connect [',
                                uuid: 'UUID',
                                path: 'PATH',
                                inputU: '输入U变量的内容并且回车...',
                                inputD: '输入D变量的内容并且回车...',
                                connecting: '正在连接...',
                                invading: '正在入侵...',
                                success: '连接成功！返回结果...',
                                error: '错误: 无效的UUID格式',
                                 reenter: '请重新输入有效的UUID'
                            },
                            fa: {
                                title: 'ترمینال v2.9.8',
                                terminal: 'ترمینال v2.9.8',
                                congratulations: 'تبریک می‌گوییم به شما',
                                enterU: 'لطفا مقدار متغیر U خود را وارد کنید',
                                enterD: 'لطفا مقدار متغیر D خود را وارد کنید',
                                command: 'دستور: connect [',
                                uuid: 'UUID',
                                path: 'PATH',
                                inputU: 'محتویات متغیر U را وارد کرده و Enter را بزنید...',
                                inputD: 'محتویات متغیر D را وارد کرده و Enter را بزنید...',
                                connecting: 'در حال اتصال...',
                                invading: 'در حال نفوذ...',
                                success: 'اتصال موفق! در حال بازگشت نتیجه...',
                                error: 'خطا: فرمت UUID نامعتبر',
                                reenter: 'لطفا UUID معتبر را دوباره وارد کنید'
                            }
                        };
                            
                        const t = translations[isFarsi ? 'fa' : 'zh'];
                            
    const terminalHtml = `<!DOCTYPE html>
    <html lang="${langAttr}" dir="${isFarsi ? 'rtl' : 'ltr'}">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${t.title}</title>
        <style>
            :root {
                --cp-bg: #05030e;
                --cp-bg-2: #0a0820;
                --cp-cyan: #00f0ff;
                --cp-cyan-d: #00b8c4;
                --cp-pink: #ff2bd6;
                --cp-pink-d: #d1239f;
                --cp-purple: #a347ff;
                --cp-yellow: #fff200;
                --cp-mint: #00ff9d;
                --cp-red: #ff3860;
                --cp-text: #e6f5ff;
                --cp-text-dim: #7aa9c4;
                --cp-border: rgba(0, 240, 255, 0.55);
                --cp-grid: rgba(255, 43, 214, 0.16);
            }
            * { margin: 0; padding: 0; box-sizing: border-box; }
            html, body { height: 100%; }
            body {
                font-family: "JetBrains Mono", "Fira Code", "Courier New", monospace;
                background: radial-gradient(ellipse at 20% 10%, #2a0040 0%, var(--cp-bg) 55%, #000 100%);
                color: var(--cp-text);
                min-height: 100vh;
                overflow-x: hidden;
                position: relative;
                display: flex; justify-content: center; align-items: center;
            }
            body::before {
                content: ""; position: fixed; inset: 0;
                background-image:
                    linear-gradient(var(--cp-grid) 1px, transparent 1px),
                    linear-gradient(90deg, var(--cp-grid) 1px, transparent 1px);
                background-size: 48px 48px;
                mask-image: radial-gradient(ellipse at center, #000 30%, transparent 80%);
                z-index: -3;
                animation: cp-grid-slide 18s linear infinite;
            }
            body::after {
                content: ""; position: fixed; inset: 0;
                background: repeating-linear-gradient(
                    180deg,
                    rgba(255,255,255,0.04) 0,
                    rgba(255,255,255,0.04) 1px,
                    transparent 1px,
                    transparent 3px
                );
                pointer-events: none;
                z-index: 5;
                mix-blend-mode: overlay;
                animation: cp-scan-flicker 6s infinite;
            }
            @keyframes cp-grid-slide {
                0% { background-position: 0 0, 0 0; }
                100% { background-position: 48px 48px, 48px 48px; }
            }
            @keyframes cp-scan-flicker {
                0%, 100% { opacity: 0.6; }
                50% { opacity: 0.9; }
            }
            .matrix-bg {
                position: fixed; inset: 0;
                background:
                    radial-gradient(circle at 80% 90%, rgba(255,43,214,0.18) 0%, transparent 45%),
                    radial-gradient(circle at 10% 80%, rgba(0,240,255,0.18) 0%, transparent 45%);
                z-index: -2;
                pointer-events: none;
            }
            .matrix-rain { display: none; }
            .matrix-code-rain {
                position: fixed; inset: 0;
                pointer-events: none; z-index: -1;
                overflow: hidden;
            }
            .matrix-column {
                position: absolute; top: -120%; left: 0;
                color: var(--cp-cyan);
                font-family: "JetBrains Mono", "Courier New", monospace;
                font-size: 14px; line-height: 1.25;
                text-shadow: 0 0 6px var(--cp-cyan), 0 0 12px rgba(0,240,255,0.5);
                animation: cp-drop linear infinite;
            }
            @keyframes cp-drop {
                0%   { top: -120%; opacity: 0; }
                10%  { opacity: 0.85; }
                90%  { opacity: 0.4; }
                100% { top: 110vh; opacity: 0; }
            }
            .matrix-column:nth-child(odd)  { animation-duration: 12s; }
            .matrix-column:nth-child(even) { animation-duration: 18s; color: var(--cp-pink); text-shadow: 0 0 6px var(--cp-pink), 0 0 14px rgba(255,43,214,0.5); }
            .matrix-column:nth-child(3n)   { animation-duration: 20s; color: var(--cp-purple); text-shadow: 0 0 6px var(--cp-purple); }
            .matrix-column:nth-child(5n)   { animation-duration: 9s; opacity: 0.6; }

            .terminal {
                width: 92%; max-width: 860px; height: 540px;
                background:
                    linear-gradient(180deg, rgba(8,4,28,0.92) 0%, rgba(15,3,40,0.92) 100%);
                border: 1px solid var(--cp-border);
                border-radius: 0;
                box-shadow:
                    0 0 0 1px rgba(255,43,214,0.25),
                    0 0 28px rgba(0,240,255,0.35),
                    0 0 80px rgba(255,43,214,0.18),
                    inset 0 0 30px rgba(0,240,255,0.06);
                clip-path: polygon(
                    0 18px, 18px 0,
                    calc(100% - 60px) 0, calc(100% - 42px) 18px,
                    100% 18px, 100% calc(100% - 14px),
                    calc(100% - 14px) 100%, 42px 100%,
                    24px calc(100% - 14px), 0 calc(100% - 14px)
                );
                position: relative; z-index: 1;
                overflow: hidden;
            }
            .terminal::before {
                content: ""; position: absolute; inset: 0;
                background: repeating-linear-gradient(180deg, rgba(0,240,255,0.06) 0 1px, transparent 1px 4px);
                pointer-events: none;
                animation: cp-scan-flicker 5s infinite;
            }
            .terminal-header {
                background: linear-gradient(90deg, rgba(255,43,214,0.18), rgba(0,240,255,0.18));
                padding: 12px 18px;
                border-bottom: 1px solid rgba(0,240,255,0.5);
                display: flex; align-items: center; gap: 16px;
                position: relative;
            }
            .terminal-header::after {
                content: ""; position: absolute; left: 18px; right: 18px; bottom: -1px;
                height: 1px;
                background: linear-gradient(90deg, transparent, var(--cp-pink), var(--cp-cyan), transparent);
                animation: cp-scan-line 4s linear infinite;
            }
            @keyframes cp-scan-line {
                0% { transform: translateX(-30%); opacity: 0.4; }
                50% { opacity: 1; }
                100% { transform: translateX(30%); opacity: 0.4; }
            }
            .terminal-buttons {
                display: flex; gap: 8px;
            }
            .terminal-button {
                width: 12px; height: 12px;
                background: var(--cp-pink);
                box-shadow: 0 0 8px var(--cp-pink);
                border: none; transform: rotate(45deg);
            }
            .terminal-button:nth-child(2) { background: var(--cp-yellow); box-shadow: 0 0 8px var(--cp-yellow); }
            .terminal-button:nth-child(3) { background: var(--cp-mint); box-shadow: 0 0 8px var(--cp-mint); }
            .terminal-title {
                color: var(--cp-cyan);
                font-size: 13px; font-weight: 700;
                letter-spacing: 0.25em;
                text-transform: uppercase;
                text-shadow: 0 0 6px var(--cp-cyan);
            }
            .terminal-title::before { content: "// "; color: var(--cp-pink); }
            .terminal-body {
                padding: 24px; height: calc(100% - 52px);
                overflow-y: auto; font-size: 14px;
                line-height: 1.6;
                position: relative;
            }
            .terminal-body::-webkit-scrollbar { width: 6px; }
            .terminal-body::-webkit-scrollbar-thumb {
                background: linear-gradient(180deg, var(--cp-pink), var(--cp-cyan));
            }
            .terminal-line {
                margin-bottom: 8px; display: flex; align-items: center; gap: 8px;
                flex-wrap: wrap;
            }
            .terminal-prompt {
                color: var(--cp-pink);
                font-weight: 700;
                text-shadow: 0 0 6px var(--cp-pink);
                letter-spacing: 0.05em;
            }
            .terminal-prompt::before { content: "▍"; color: var(--cp-cyan); margin-right: 4px; }
            .terminal-input {
                background: transparent; border: none; outline: none;
                color: var(--cp-cyan);
                font-family: inherit;
                font-size: 14px; flex: 1; min-width: 0;
                caret-color: var(--cp-pink);
                text-shadow: 0 0 4px var(--cp-cyan);
            }
            .terminal-input::placeholder { color: var(--cp-text-dim); opacity: 0.75; }
            .terminal-cursor {
                display: inline-block; width: 9px; height: 16px;
                background: var(--cp-pink);
                margin-left: 2px;
                box-shadow: 0 0 8px var(--cp-pink);
                animation: cp-blink 1s steps(2, end) infinite;
            }
            @keyframes cp-blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0; }
            }
            .terminal-output { color: var(--cp-cyan); margin: 4px 0; }
            .terminal-error  { color: var(--cp-red); margin: 4px 0; text-shadow: 0 0 6px var(--cp-red); }
            .terminal-success{ color: var(--cp-mint); margin: 4px 0; text-shadow: 0 0 6px var(--cp-mint); }

            .cp-hud {
                position: fixed; top: 18px; right: 22px;
                color: var(--cp-cyan);
                font-family: "JetBrains Mono", monospace;
                font-size: 11px; letter-spacing: 0.2em;
                text-transform: uppercase;
                text-align: right;
                opacity: 0.85;
                z-index: 1000;
            }
            .cp-hud .cp-hud-label { color: var(--cp-pink); }
            .cp-hud .cp-hud-line { display: block; }
            .cp-lang-wrapper {
                position: fixed; top: 18px; left: 22px; z-index: 1000;
                display: flex; align-items: center; gap: 10px;
            }
            .cp-lang-tag {
                color: var(--cp-pink); font-size: 11px;
                letter-spacing: 0.25em; text-transform: uppercase;
                text-shadow: 0 0 6px var(--cp-pink);
            }
            #languageSelector {
                background: rgba(8,4,28,0.85);
                border: 1px solid var(--cp-cyan);
                color: var(--cp-cyan);
                padding: 6px 12px;
                font-family: inherit;
                font-size: 12px;
                cursor: pointer;
                letter-spacing: 0.12em;
                text-shadow: 0 0 6px var(--cp-cyan);
                box-shadow: 0 0 12px rgba(0,240,255,0.35);
                clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
            }
            #languageSelector option { background: var(--cp-bg-2); color: var(--cp-cyan); }

            /* FX toggle - 页面特效图形化开关 */
            .cp-fx-toggle {
                position: fixed; top: 68px; left: 22px; z-index: 1001;
                background: rgba(8,4,28,0.85);
                border: 1px solid var(--cp-mint);
                color: var(--cp-mint);
                padding: 6px 12px;
                font-family: inherit;
                font-size: 11px;
                letter-spacing: 0.18em;
                text-transform: uppercase;
                cursor: pointer;
                text-shadow: 0 0 6px var(--cp-mint);
                box-shadow: 0 0 10px rgba(0,255,157,0.35);
                clip-path: polygon(7px 0, 100% 0, 100% calc(100% - 7px), calc(100% - 7px) 100%, 0 100%, 0 7px);
                transition: all 0.2s ease;
                display: inline-flex; align-items: center; gap: 6px;
            }
            .cp-fx-toggle:hover { color: var(--cp-pink); border-color: var(--cp-pink); text-shadow: 0 0 8px var(--cp-pink); box-shadow: 0 0 16px rgba(255,43,214,0.55); }
            .cp-fx-toggle .cp-fx-dot { width: 6px; height: 6px; background: var(--cp-mint); border-radius: 50%; box-shadow: 0 0 8px var(--cp-mint); transition: all 0.2s; }
            body.fx-off .cp-fx-toggle { color: var(--cp-text-dim); border-color: var(--cp-text-dim); text-shadow: none; box-shadow: none; }
            body.fx-off .cp-fx-toggle .cp-fx-dot { background: transparent; border: 1px solid var(--cp-text-dim); box-shadow: none; }
            body.fx-off .matrix-bg,
            body.fx-off .matrix-code-rain,
            body.fx-off .matrix-column { display: none !important; }
            body.fx-off::before,
            body.fx-off::after { display: none !important; content: none !important; }
            body.fx-off { background: var(--cp-bg) !important; }
            body.fx-off * {
                animation: none !important;
                transition: color 0.15s, background-color 0.15s, border-color 0.15s, box-shadow 0.15s !important;
            }
            body.fx-off .cp-glitch::before,
            body.fx-off .cp-glitch::after { display: none !important; }
            body.fx-off .terminal-cursor::after { animation: none !important; }

            .cp-glitch {
                font-family: "JetBrains Mono", monospace;
                font-weight: 700;
                letter-spacing: 0.18em;
                text-transform: uppercase;
                color: var(--cp-cyan);
                text-shadow:
                    0 0 8px var(--cp-cyan),
                    -2px 0 var(--cp-pink),
                    2px 0 var(--cp-mint);
            }
        </style>
    </head>
    <body>
        <div class="matrix-bg"></div>
        <div class="matrix-code-rain" id="matrixCodeRain"></div>
            <div class="cp-hud">
                <span class="cp-hud-line"><span class="cp-hud-label">SYS::</span> ${t.terminal}</span>
                <span class="cp-hud-line"><span class="cp-hud-label">NODE::</span> NIGHT_CITY</span>
                <span class="cp-hud-line"><span class="cp-hud-label">LINK::</span> SECURE / ENC</span>
            </div>
            <div class="cp-lang-wrapper">
                <span class="cp-lang-tag">LANG_</span>
                <select id="languageSelector" onchange="changeLanguage(this.value)">
                    <option value="zh" ${!isFarsi ? 'selected' : ''}>🇨🇳 中文</option>
                    <option value="fa" ${isFarsi ? 'selected' : ''}>🇮🇷 فارسی</option>
                </select>
            </div>
            <button type="button" id="cpFxToggle" class="cp-fx-toggle" onclick="cpToggleFx()" title="${isFarsi ? 'تغییر افکت‌های صفحه' : '切换页面特效'}" aria-label="FX toggle">
                <span class="cp-fx-dot" aria-hidden="true"></span>
                <span id="cpFxLabel">FX: ON</span>
            </button>
        <div class="terminal">
            <div class="terminal-header">
                <div class="terminal-buttons">
                    <div class="terminal-button"></div>
                    <div class="terminal-button"></div>
                    <div class="terminal-button"></div>
                </div>
                    <div class="terminal-title cp-glitch">${t.terminal}</div>
            </div>
            <div class="terminal-body" id="terminalBody">
                <div class="terminal-line">
                    <span class="terminal-prompt">root:~$</span>
                        <span class="terminal-output">${t.congratulations}</span>
                </div>
                <div class="terminal-line">
                    <span class="terminal-prompt">root:~$</span>
                        <span class="terminal-output">${cp && cp.trim() ? t.enterD : t.enterU}</span>
                </div>
                <div class="terminal-line">
                    <span class="terminal-prompt">root:~$</span>
                        <span class="terminal-output">${t.command}${cp && cp.trim() ? t.path : t.uuid}]</span>
                </div>
                <div class="terminal-line">
                    <span class="terminal-prompt">root:~$</span>
                        <input type="text" class="terminal-input" id="uuidInput" placeholder="${cp && cp.trim() ? t.inputD : t.inputU}" autofocus>
                    <span class="terminal-cursor"></span>
                </div>
            </div>
        </div>
        <script>
            // 页面特效图形化开关 (localStorage 持久化)
            window.cpApplyFx = function() {
                var off = localStorage.getItem('cp-fx-off') === '1';
                document.body.classList.toggle('fx-off', off);
                var lbl = document.getElementById('cpFxLabel');
                if (lbl) lbl.textContent = off ? 'FX: OFF' : 'FX: ON';
                if (off) {
                    var rain = document.getElementById('matrixCodeRain');
                    if (rain) rain.innerHTML = '';
                } else if (typeof createMatrixRain === 'function') {
                    var r = document.getElementById('matrixCodeRain');
                    if (r && !r.firstChild) createMatrixRain();
                }
            };
            window.cpToggleFx = function() {
                var off = localStorage.getItem('cp-fx-off') === '1';
                localStorage.setItem('cp-fx-off', off ? '0' : '1');
                window.cpApplyFx();
            };
            (function() {
                if (localStorage.getItem('cp-fx-off') === '1') {
                    document.documentElement.classList.add('fx-off-preload');
                    document.addEventListener('DOMContentLoaded', function() {
                        document.body.classList.add('fx-off');
                    });
                }
            })();

            function createMatrixRain() {
                if (document.body && document.body.classList.contains('fx-off')) return;
                const matrixContainer = document.getElementById('matrixCodeRain');
                if (!matrixContainer) return;
                const cyberChars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ$%#@!?<>+=ABCDEF';
                const palette = ['#00f0ff', '#ff2bd6', '#a347ff', '#00ff9d'];
                const columns = Math.floor(window.innerWidth / 20);

                for (let i = 0; i < columns; i++) {
                    const column = document.createElement('div');
                    column.className = 'matrix-column';
                    column.style.left = (i * 20) + 'px';
                    column.style.animationDelay = (-Math.random() * 15) + 's';
                    column.style.animationDuration = (Math.random() * 14 + 8) + 's';
                    column.style.fontSize = (Math.random() * 4 + 12) + 'px';
                    column.style.opacity = (Math.random() * 0.7 + 0.3).toFixed(2);

                    let text = '';
                    const charCount = Math.floor(Math.random() * 30 + 18);
                    for (let j = 0; j < charCount; j++) {
                        const char = cyberChars[Math.floor(Math.random() * cyberChars.length)];
                        const useAccent = Math.random() > 0.85;
                        const color = useAccent ? palette[Math.floor(Math.random() * palette.length)] : '';
                        text += color
                            ? ('<span style="color:' + color + ';text-shadow:0 0 8px ' + color + ';">' + char + '</span><br>')
                            : ('<span>' + char + '</span><br>');
                    }
                    column.innerHTML = text;
                    matrixContainer.appendChild(column);
                }

                setInterval(function() {
                    const cols = matrixContainer.querySelectorAll('.matrix-column');
                    cols.forEach(function(column) {
                        if (Math.random() > 0.94) {
                            const chars = column.querySelectorAll('span');
                            if (chars.length > 0) {
                                const target = chars[Math.floor(Math.random() * chars.length)];
                                const prev = target.style.color;
                                target.style.color = '#ffffff';
                                target.style.textShadow = '0 0 10px #ffffff, 0 0 18px #00f0ff';
                                setTimeout(function() {
                                    target.style.color = prev;
                                    target.style.textShadow = '';
                                }, 200);
                            }
                        }
                    });
                }, 110);
            }

            function isValidUUID(uuid) {
                const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
                return uuidRegex.test(uuid);
            }

            function addTerminalLine(content, type = 'output') {
                const terminalBody = document.getElementById('terminalBody');
                const line = document.createElement('div');
                line.className = 'terminal-line';

                const prompt = document.createElement('span');
                prompt.className = 'terminal-prompt';
                prompt.textContent = 'root:~$';

                const output = document.createElement('span');
                output.className = 'terminal-' + type;
                output.textContent = content;

                line.appendChild(prompt);
                line.appendChild(output);
                terminalBody.appendChild(line);

                terminalBody.scrollTop = terminalBody.scrollHeight;
            }

            function handleUUIDInput() {
                const input = document.getElementById('uuidInput');
                const inputValue = input.value.trim();
                const cp = '${ cp }';

                if (inputValue) {
                    addTerminalLine(atob('Y29ubmVjdCA=') + inputValue, 'output');
                        const translations = {
                            zh: {
                                connecting: '正在连接...',
                                invading: '正在入侵...',
                                success: '连接成功！返回结果...',
                                error: '错误: 无效的UUID格式',
                                reenter: '请重新输入有效的UUID'
                            },
                            fa: {
                                connecting: 'در حال اتصال...',
                                invading: 'در حال نفوذ...',
                                success: 'اتصال موفق! در حال بازگشت نتیجه...',
                                error: 'خطا: فرمت UUID نامعتبر',
                                reenter: 'لطفا UUID معتبر را دوباره وارد کنید'
                            }
                        };
                        const browserLang = navigator.language || navigator.userLanguage || '';
                        const isFarsi = browserLang.includes('fa') || browserLang.includes('fa-IR');
                        const t = translations[isFarsi ? 'fa' : 'zh'];

                    if (cp) {
                        const cleanInput = inputValue.startsWith('/') ? inputValue : '/' + inputValue;
                            addTerminalLine(t.connecting, 'output');
                        setTimeout(() => {
                                addTerminalLine(t.success, 'success');
                            setTimeout(() => {
                                window.location.href = cleanInput;
                            }, 1000);
                        }, 500);
                    } else {
                        if (isValidUUID(inputValue)) {
                            addTerminalLine(t.invading, 'output');
                        setTimeout(() => {
                                addTerminalLine(t.success, 'success');
                            setTimeout(() => {
                                    window.location.href = '/' + inputValue;
                            }, 1000);
                        }, 500);
                    } else {
                            addTerminalLine(t.error, 'error');
                            addTerminalLine(t.reenter, 'output');
                        }
                    }

                    input.value = '';
                }
            }

            function changeLanguage(lang) {
                localStorage.setItem('preferredLanguage', lang);
                // 设置Cookie（有效期1年）
                const expiryDate = new Date();
                expiryDate.setFullYear(expiryDate.getFullYear() + 1);
                document.cookie = 'preferredLanguage=' + lang + '; path=/; expires=' + expiryDate.toUTCString() + '; SameSite=Lax';
                // 刷新页面，不使用URL参数
                window.location.reload();
            }

            // 页面加载时检查 localStorage 和 Cookie，并清理URL参数
            window.addEventListener('DOMContentLoaded', function() {
                function getCookie(name) {
                    const value = '; ' + document.cookie;
                    const parts = value.split('; ' + name + '=');
                    if (parts.length === 2) return parts.pop().split(';').shift();
                    return null;
                }

                const savedLang = localStorage.getItem('preferredLanguage') || getCookie('preferredLanguage');
                const urlParams = new URLSearchParams(window.location.search);
                const urlLang = urlParams.get('lang');

                // 如果URL中有语言参数，移除它并设置Cookie
                if (urlLang) {
                    const currentUrl = new URL(window.location.href);
                    currentUrl.searchParams.delete('lang');
                    const newUrl = currentUrl.toString();

                    // 设置Cookie
                    const expiryDate = new Date();
                    expiryDate.setFullYear(expiryDate.getFullYear() + 1);
                    document.cookie = 'preferredLanguage=' + urlLang + '; path=/; expires=' + expiryDate.toUTCString() + '; SameSite=Lax';
                    localStorage.setItem('preferredLanguage', urlLang);

                    // 使用history API移除URL参数，不刷新页面
                    window.history.replaceState({}, '', newUrl);
                } else if (savedLang) {
                    // 如果localStorage中有但Cookie中没有，同步到Cookie
                    const expiryDate = new Date();
                    expiryDate.setFullYear(expiryDate.getFullYear() + 1);
                    document.cookie = 'preferredLanguage=' + savedLang + '; path=/; expires=' + expiryDate.toUTCString() + '; SameSite=Lax';
                }
            });

            document.addEventListener('DOMContentLoaded', function() {
                try { createMatrixRain(); } catch (e) {}
                const input = document.getElementById('uuidInput');
                if (input) {
                    input.focus();
                    input.addEventListener('keypress', function(e) {
                        if (e.key === 'Enter') {
                            handleUUIDInput();
                        }
                    });
                }
            });
        </script>
    </body>
    </html>`;
            return new Response(terminalHtml, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        }
            if (cp && cp.trim()) {
                const cleanCustomPath = cp.trim().startsWith('/') ? cp.trim() : '/' + cp.trim();
                const normalizedCustomPath = cleanCustomPath.endsWith('/') && cleanCustomPath.length > 1 ? cleanCustomPath.slice(0, -1) : cleanCustomPath;
                const normalizedPath = url.pathname.endsWith('/') && url.pathname.length > 1 ? url.pathname.slice(0, -1) : url.pathname;

                    if (normalizedPath === normalizedCustomPath) {
                        return await handleSubscriptionPage(request, at);
                    }

                    if (normalizedPath === normalizedCustomPath + '/sub') {
                        return await handleSubscriptionRequest(request, at, url);
                    }

                    if (url.pathname.length > 1 && url.pathname !== '/') {
                        const user = url.pathname.replace(/\/$/, '').replace('/sub', '').substring(1);
                        if (isValidFormat(user)) {
                            return new Response(JSON.stringify({ 
                                error: '访问被拒绝',
                                message: '当前 Worker 已启用自定义路径模式，UUID 访问已禁用'
                            }), { 
                                status: 403,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }
                    }
                } else {
                    
                    if (url.pathname.length > 1 && url.pathname !== '/' && !url.pathname.includes('/sub')) {
                        const user = url.pathname.replace(/\/$/, '').substring(1);
                        if (isValidFormat(user)) {
                            if (user === at) {
                                return await handleSubscriptionPage(request, user);
                            } else {
                                return new Response(JSON.stringify({ error: 'UUID错误 请注意变量名称是u不是uuid' }), { 
                                    status: 403,
                                    headers: { 'Content-Type': 'application/json' }
                                });
                            }
                        }
                    }
                    if (url.pathname.includes('/sub')) {
                        const pathParts = url.pathname.split('/');
                        if (pathParts.length === 2 && pathParts[1] === 'sub') {
                            const user = pathParts[0].substring(1);
                            if (isValidFormat(user)) {
                                if (user === at) {
                                    return await handleSubscriptionRequest(request, user, url);
                                } else {
                                    return new Response(JSON.stringify({ error: 'UUID错误' }), { 
                                        status: 403,
                                        headers: { 'Content-Type': 'application/json' }
                                    });
                                }
                                }
                            }
                        }
                    }
                    if (url.pathname.toLowerCase().includes(`/${subPath}`)) {
                        return await handleSubscriptionRequest(request, at);
                    }
                }
                return new Response(JSON.stringify({ error: 'Not Found' }), { 
                    status: 404,
                    headers: { 'Content-Type': 'application/json' }
                });
            } catch (err) {
                return new Response(err.toString(), { status: 500 });
            }
        },
    };

    function generateQuantumultConfig(links) {
        return btoa(links.join('\n'));
    }

    // 解析 VLESS/Trojan 链接并生成 Clash 节点配置
    function parseLinkToClashNode(link) {
        try {
            // 解析 VLESS 链接
            if (link.startsWith('vless://')) {
                const url = new URL(link);
                const name = decodeURIComponent(url.hash.substring(1));
                const uuid = url.username;
                const server = url.hostname;
                const port = parseInt(url.port) || 443;
                const params = new URLSearchParams(url.search);

                const tls = params.get('security') === 'tls' || params.get('tls') === 'true';
                const network = params.get('type') || 'ws';
                const path = params.get('path') || '/?ed=2048';
                const host = params.get('host') || server;
                const servername = params.get('sni') || host;
                const alpnRaw = params.get('alpn') || '';
                const fingerprint = params.get('fp') || params.get('client-fingerprint') || 'chrome';
                const ech = params.get('ech');

                const node = {
                    name: name,
                    type: 'vless',
                    server: server,
                    port: port,
                    uuid: uuid,
                    tls: tls,
                    network: network,
                    'client-fingerprint': fingerprint
                };

                if (tls) {
                    node.servername = servername;
                    if (alpnRaw) node.alpn = alpnRaw.split(',').map(a => a.trim()).filter(Boolean);
                    node['skip-cert-verify'] = false;
                }

                if (network === 'ws') {
                    node['ws-opts'] = {
                        path: path,
                        headers: {
                            Host: host
                        }
                    };
                }

                if (ech) {
                    const echDomain = customECHDomain || 'cloudflare-ech.com';
                    node['ech-opts'] = {
                        enable: true,
                        'query-server-name': echDomain
                    };
                }

                return node;
            }
            
            // 解析 Trojan 链接
            if (link.startsWith('trojan://')) {
                const url = new URL(link);
                const name = decodeURIComponent(url.hash.substring(1));
                const password = url.username;
                const server = url.hostname;
                const port = parseInt(url.port) || 443;
                const params = new URLSearchParams(url.search);

                const network = params.get('type') || 'ws';
                const path = params.get('path') || '/?ed=2048';
                const host = params.get('host') || server;
                const sni = params.get('sni') || host;
                const alpnRaw = params.get('alpn') || '';
                const ech = params.get('ech');

                const node = {
                    name: name,
                    type: 'trojan',
                    server: server,
                    port: port,
                    password: password,
                    network: network,
                    sni: sni,
                    'skip-cert-verify': false
                };
                if (alpnRaw) node.alpn = alpnRaw.split(',').map(a => a.trim()).filter(Boolean);

                if (network === 'ws') {
                    node['ws-opts'] = {
                        path: path,
                        headers: {
                            Host: host
                        }
                    };
                }

                if (ech) {
                    const echDomain = customECHDomain || 'cloudflare-ech.com';
                    node['ech-opts'] = {
                        enable: true,
                        'query-server-name': echDomain
                    };
                }

                return node;
            }
        } catch (e) {
            return null;
        }
        return null;
    }

    // ============================================================
    // 内部订阅转换器 - 不依赖外部 sub-converter
    // ============================================================

    // 用于 YAML 引号包裹（避免 IPv6 方括号、逗号等被解析为数组）
    function yq(v) {
        if (v == null) return '""';
        const s = String(v);
        return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    }

    // URL.hostname 对 IPv6 会带方括号，直接写入 YAML 会被当成数组
    function normalizeServerHost(hostname) {
        if (!hostname) return hostname;
        const h = String(hostname);
        if (h.startsWith('[') && h.endsWith(']')) return h.slice(1, -1);
        return h;
    }

    // Clash 策略组 proxies：策略组 + 全部节点（避免分组里只有「节点选择」没有具体节点）
    function clashSelectProxies(names, opts = {}) {
        const { directFirst = false, extraGroups = [] } = opts;
        const nodeLines = names.length
            ? names.map(n => `      - ${yq(n)}`).join('\n')
            : '      - DIRECT';
        const lines = [];
        if (directFirst) {
            lines.push('      - "🎯 全球直连"', '      - "🚀 节点选择"');
        } else {
            lines.push('      - "🚀 节点选择"', '      - "🎯 全球直连"');
        }
        for (const g of extraGroups) lines.push(`      - ${yq(g)}`);
        lines.push(nodeLines);
        return lines.join('\n');
    }

    // Surge / Loon 策略组列表：策略组 + 全部节点
    function iniPolicyList(names, opts = {}) {
        const { directFirst = false, extraGroups = [], compact = false } = opts;
        const sep = compact ? ',' : ', ';
        const list = names.length ? names.join(sep) : 'DIRECT';
        const parts = [];
        if (directFirst) parts.push('🎯 全球直连', '🚀 节点选择');
        else parts.push('🚀 节点选择', '🎯 全球直连');
        parts.push(...extraGroups);
        if (names.length) parts.push(list);
        return parts.join(sep);
    }

    // 解析任意分享链接为通用节点对象 (vless / trojan / vless-xhttp)
    function parseShareLink(link) {
        try {
            if (link.startsWith('vless://')) {
                const url = new URL(link);
                const p = new URLSearchParams(url.search);
                return {
                    proto: 'vless',
                    name: decodeURIComponent(url.hash.substring(1)) || (url.hostname + ':' + url.port),
                    uuid: url.username,
                    server: normalizeServerHost(url.hostname),
                    port: parseInt(url.port) || 443,
                    tls: p.get('security') === 'tls' || p.get('security') === 'reality',
                    network: p.get('type') || 'ws',
                    path: p.get('path') || '/?ed=2048',
                    host: normalizeServerHost(p.get('host') || url.hostname),
                    sni: normalizeServerHost(p.get('sni') || p.get('host') || url.hostname),
                    alpn: (p.get('alpn') || '').split(',').map(s => s.trim()).filter(Boolean),
                    fp: p.get('fp') || 'chrome',
                    flow: p.get('flow') || '',
                    encryption: p.get('encryption') || 'none',
                    mode: p.get('mode') || '',
                    ech: p.get('ech') || ''
                };
            }
            if (link.startsWith('trojan://')) {
                const url = new URL(link);
                const p = new URLSearchParams(url.search);
                return {
                    proto: 'trojan',
                    name: decodeURIComponent(url.hash.substring(1)) || (url.hostname + ':' + url.port),
                    password: decodeURIComponent(url.username),
                    server: normalizeServerHost(url.hostname),
                    port: parseInt(url.port) || 443,
                    tls: true,
                    network: p.get('type') || 'ws',
                    path: p.get('path') || '/?ed=2048',
                    host: normalizeServerHost(p.get('host') || url.hostname),
                    sni: normalizeServerHost(p.get('sni') || p.get('host') || url.hostname),
                    alpn: (p.get('alpn') || '').split(',').map(s => s.trim()).filter(Boolean),
                    fp: p.get('fp') || 'chrome',
                    ech: p.get('ech') || ''
                };
            }
        } catch (e) {}
        return null;
    }

    // 单个节点 → Clash 块级 YAML（避免 flow style 解析错误）
    function buildClashNodeLine(n) {
        const lines = [];
        const server = normalizeServerHost(n.server);
        const host = normalizeServerHost(n.host) || server;
        const sni = normalizeServerHost(n.sni) || host;

        lines.push(`  - name: ${yq(n.name)}`);
        lines.push(`    type: ${n.proto}`);
        lines.push(`    server: ${yq(server)}`);
        lines.push(`    port: ${n.port}`);
        if (n.proto === 'vless') {
            lines.push(`    uuid: ${n.uuid}`);
            lines.push(`    udp: true`);
            lines.push(`    tls: ${n.tls ? 'true' : 'false'}`);
            if (n.flow) lines.push(`    flow: ${yq(n.flow)}`);
            lines.push(`    client-fingerprint: ${yq(n.fp || 'chrome')}`);
        } else if (n.proto === 'trojan') {
            lines.push(`    password: ${yq(n.password)}`);
            lines.push(`    udp: true`);
            lines.push(`    client-fingerprint: ${yq(n.fp || 'chrome')}`);
        }
        if (n.tls) {
            lines.push(`    servername: ${yq(sni)}`);
            if (n.alpn && n.alpn.length) {
                lines.push(`    alpn: [${n.alpn.map(a => yq(a)).join(', ')}]`);
            }
            lines.push(`    skip-cert-verify: false`);
        }
        if (n.network === 'ws' || n.network === 'xhttp') {
            lines.push(`    network: ws`);
            lines.push(`    ws-opts:`);
            lines.push(`      path: ${yq(n.path)}`);
            lines.push(`      headers:`);
            lines.push(`        Host: ${yq(host)}`);
        } else if (n.network === 'grpc') {
            lines.push(`    network: grpc`);
            lines.push(`    grpc-opts:`);
            lines.push(`      grpc-service-name: ${yq(n.path)}`);
        }
        if (n.ech) {
            const echDomain = customECHDomain || 'cloudflare-ech.com';
            lines.push(`    ech-opts:`);
            lines.push(`      enable: true`);
            lines.push(`      query-server-name: ${yq(echDomain)}`);
        }
        return lines.join('\n');
    }

    // 内部生成 Clash YAML（完整规则集：Loyalsoldier rule-providers）
    function generateClashYaml(links, opts = {}) {
        const nodes = links.map(parseShareLink).filter(n => n && (n.proto === 'vless' || n.proto === 'trojan'));
        const names = nodes.map(n => n.name);
        const dnsServer = customDNS || 'https://223.5.5.5/dns-query';

        const head = [
            'mixed-port: 7890',
            'allow-lan: true',
            'mode: rule',
            'log-level: info',
            'ipv6: true',
            'external-controller: 127.0.0.1:9090',
            'unified-delay: true',
            'tcp-concurrent: true',
            'geodata-mode: true',
            'geo-auto-update: true',
            'geo-update-interval: 24',
            'geox-url:',
            '  geoip: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"',
            '  geosite: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"',
            '  mmdb: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"',
            '  asn: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"',
            'sniffer:',
            '  enable: true',
            '  force-dns-mapping: true',
            '  parse-pure-ip: true',
            '  sniff:',
            '    HTTP:',
            '      ports: [80, 8080-8880]',
            '      override-destination: true',
            '    TLS:',
            '      ports: [443, 8443]',
            '    QUIC:',
            '      ports: [443, 8443]',
            'dns:',
            '  enable: true',
            '  listen: 0.0.0.0:1053',
            '  ipv6: true',
            '  enhanced-mode: fake-ip',
            '  fake-ip-range: 198.18.0.1/16',
            '  fake-ip-filter:',
            '    - "*.lan"',
            '    - "+.local"',
            '    - "+.market.xiaomi.com"',
            '    - "+.msftconnecttest.com"',
            '    - "+.msftncsi.com"',
            '    - "localhost.ptlogin2.qq.com"',
            '    - "+.srv.nintendo.net"',
            '    - "+.stun.playstation.net"',
            '    - "+.xboxlive.com"',
            '  default-nameserver:',
            '    - 223.5.5.5',
            '    - 119.29.29.29',
            '  nameserver:',
            `    - ${dnsServer}`,
            '    - https://119.29.29.29/dns-query',
            '  fallback:',
            '    - https://1.1.1.1/dns-query',
            '    - https://8.8.8.8/dns-query',
            '  fallback-filter:',
            '    geoip: true',
            '    geoip-code: CN',
            '    ipcidr:',
            '      - 240.0.0.0/4',
            ''
        ];

        const proxiesBlock = ['proxies:'];
        for (const n of nodes) proxiesBlock.push(buildClashNodeLine(n));

        const nodeOnly = names.length ? names.map(n => `      - ${yq(n)}`).join('\n') : '      - DIRECT';
        const proxyGroups = [
            'proxy-groups:',
            '  - name: "🚀 节点选择"',
            '    type: select',
            '    proxies:',
            '      - "🎯 全球直连"',
            nodeOnly,
            '  - name: "🌍 国外媒体"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names),
            '  - name: "📺 哔哩哔哩"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names, { directFirst: true }),
            '  - name: "📹 油管视频"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names, { extraGroups: ['🌍 国外媒体'] }),
            '  - name: "🎬 奈飞视频"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names, { extraGroups: ['🌍 国外媒体'] }),
            '  - name: "📲 电报信息"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names),
            '  - name: "🌐 谷歌服务"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names),
            '  - name: "🤖 OpenAI"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names),
            '  - name: "Ⓜ️ 微软服务"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names, { directFirst: true }),
            '  - name: "🍎 苹果服务"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names, { directFirst: true }),
            '  - name: "🎯 全球直连"',
            '    type: select',
            '    proxies:',
            '      - DIRECT',
            '  - name: "🛑 全球拦截"',
            '    type: select',
            '    proxies:',
            '      - REJECT',
            '      - DIRECT',
            '  - name: "🍃 应用净化"',
            '    type: select',
            '    proxies:',
            '      - REJECT',
            '      - DIRECT',
            '  - name: "🐟 漏网之鱼"',
            '    type: select',
            '    proxies:',
            clashSelectProxies(names),
            ''
        ];

        // Loyalsoldier rule-providers (Clash 经典格式) - CDN: jsDelivr
        const RP_BASE = 'https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release';
        const provider = (name, behavior) => [
            `  ${name}:`,
            `    type: http`,
            `    behavior: ${behavior}`,
            `    url: "${RP_BASE}/${name}.txt"`,
            `    path: ./rulesets/loyalsoldier/${name}.txt`,
            `    interval: 86400`
        ].join('\n');

        const ruleProviders = [
            'rule-providers:',
            provider('reject', 'domain'),
            provider('icloud', 'domain'),
            provider('apple', 'domain'),
            provider('google', 'domain'),
            provider('proxy', 'domain'),
            provider('direct', 'domain'),
            provider('private', 'domain'),
            provider('gfw', 'domain'),
            provider('greatfire', 'domain'),
            provider('tld-not-cn', 'domain'),
            provider('telegramcidr', 'ipcidr'),
            provider('cncidr', 'ipcidr'),
            provider('lancidr', 'ipcidr'),
            provider('applications', 'classical'),
            ''
        ];

        const rules = [
            'rules:',
            '  - DOMAIN-SUFFIX,acl4.ssr,🎯 全球直连',
            '  - DOMAIN-SUFFIX,local,🎯 全球直连',
            '  - DOMAIN,clash.razord.top,🎯 全球直连',
            '  - DOMAIN,yacd.haishan.me,🎯 全球直连',
            '  - DOMAIN,yacd.metacubex.one,🎯 全球直连',
            '  - DOMAIN,d.metacubex.one,🎯 全球直连',
            '  - DOMAIN-SUFFIX,googleapis.cn,🌐 谷歌服务',
            '  - DOMAIN-SUFFIX,gstatic.com,🌐 谷歌服务',
            '  - DOMAIN-SUFFIX,xn--ngstr-lra8j.com,🌐 谷歌服务',
            '  - DOMAIN-SUFFIX,googlevideo.com,📹 油管视频',
            '  - DOMAIN-SUFFIX,googleusercontent.com,🌐 谷歌服务',
            '  - DOMAIN-KEYWORD,youtube,📹 油管视频',
            '  - DOMAIN-SUFFIX,youtube.com,📹 油管视频',
            '  - DOMAIN-SUFFIX,youtu.be,📹 油管视频',
            '  - DOMAIN-KEYWORD,netflix,🎬 奈飞视频',
            '  - DOMAIN-SUFFIX,nflxext.com,🎬 奈飞视频',
            '  - DOMAIN-SUFFIX,nflxso.net,🎬 奈飞视频',
            '  - DOMAIN-SUFFIX,nflxvideo.net,🎬 奈飞视频',
            '  - DOMAIN-SUFFIX,nflximg.com,🎬 奈飞视频',
            '  - DOMAIN-SUFFIX,nflximg.net,🎬 奈飞视频',
            '  - DOMAIN-SUFFIX,netflix.com,🎬 奈飞视频',
            '  - DOMAIN-SUFFIX,netflix.net,🎬 奈飞视频',
            '  - DOMAIN-SUFFIX,bilibili.com,📺 哔哩哔哩',
            '  - DOMAIN-SUFFIX,bilivideo.com,📺 哔哩哔哩',
            '  - DOMAIN-SUFFIX,hdslb.com,📺 哔哩哔哩',
            '  - DOMAIN-KEYWORD,openai,🤖 OpenAI',
            '  - DOMAIN-KEYWORD,chatgpt,🤖 OpenAI',
            '  - DOMAIN-SUFFIX,openai.com,🤖 OpenAI',
            '  - DOMAIN-SUFFIX,chatgpt.com,🤖 OpenAI',
            '  - DOMAIN-SUFFIX,oaistatic.com,🤖 OpenAI',
            '  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 OpenAI',
            '  - DOMAIN-SUFFIX,anthropic.com,🤖 OpenAI',
            '  - DOMAIN-SUFFIX,claude.ai,🤖 OpenAI',
            '  - DOMAIN-SUFFIX,perplexity.ai,🤖 OpenAI',
            '  - DOMAIN-SUFFIX,gemini.google.com,🤖 OpenAI',
            '  - RULE-SET,applications,🎯 全球直连',
            '  - RULE-SET,private,🎯 全球直连',
            '  - RULE-SET,reject,🛑 全球拦截',
            '  - RULE-SET,icloud,🍎 苹果服务',
            '  - RULE-SET,apple,🍎 苹果服务',
            '  - RULE-SET,google,🌐 谷歌服务',
            '  - RULE-SET,proxy,🚀 节点选择',
            '  - RULE-SET,gfw,🚀 节点选择',
            '  - RULE-SET,greatfire,🚀 节点选择',
            '  - RULE-SET,tld-not-cn,🚀 节点选择',
            '  - RULE-SET,direct,🎯 全球直连',
            '  - RULE-SET,lancidr,🎯 全球直连,no-resolve',
            '  - RULE-SET,cncidr,🎯 全球直连,no-resolve',
            '  - RULE-SET,telegramcidr,📲 电报信息,no-resolve',
            '  - GEOIP,LAN,🎯 全球直连,no-resolve',
            '  - GEOIP,CN,🎯 全球直连,no-resolve',
            '  - MATCH,🐟 漏网之鱼'
        ];

        return [head.join('\n'), proxiesBlock.join('\n'), '', proxyGroups.join('\n'), ruleProviders.join('\n'), rules.join('\n'), ''].join('\n');
    }

    // 内部生成 Sing-box JSON 配置（完整规则集：MetaCubeX 镜像 rule-set）
    function generateSingBoxJson(links) {
        const nodes = links.map(parseShareLink).filter(n => n && (n.proto === 'vless' || n.proto === 'trojan'));
        const dnsServer = customDNS || 'https://223.5.5.5/dns-query';
        const outboundTags = nodes.map(n => n.name);

        function nodeToOutbound(n) {
            const out = {
                type: n.proto,
                tag: n.name,
                server: normalizeServerHost(n.server),
                server_port: n.port
            };
            if (n.proto === 'vless') {
                out.uuid = n.uuid;
                if (n.flow) out.flow = n.flow;
            } else {
                out.password = n.password;
            }
            if (n.tls) {
                out.tls = {
                    enabled: true,
                    server_name: n.sni,
                    insecure: false,
                    utls: { enabled: true, fingerprint: n.fp || 'chrome' }
                };
                if (n.alpn && n.alpn.length) out.tls.alpn = n.alpn;
                if (n.ech) {
                    out.tls.ech = { enabled: true, pq_signature_schemes_enabled: false, dynamic_record_sizing_disabled: false };
                }
            }
            if (n.network === 'ws' || n.network === 'xhttp') {
                out.transport = {
                    type: 'ws',
                    path: n.path,
                    headers: { Host: n.host },
                    max_early_data: 2048,
                    early_data_header_name: 'Sec-WebSocket-Protocol'
                };
            } else if (n.network === 'grpc') {
                out.transport = { type: 'grpc', service_name: n.path };
            }
            return out;
        }

        // sing-box rule-set 远端 SRS 文件（CDN：jsDelivr 镜像 MetaCubeX 转换的 SagerNet 数据）
        const SRS_BASE_SITE = 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite';
        const SRS_BASE_IP = 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip';
        const siteRule = (tag) => ({ tag: `geosite-${tag}`, type: 'remote', format: 'binary', url: `${SRS_BASE_SITE}/${tag}.srs`, download_detour: 'direct' });
        const ipRule = (tag) => ({ tag: `geoip-${tag}`, type: 'remote', format: 'binary', url: `${SRS_BASE_IP}/${tag}.srs`, download_detour: 'direct' });

        const config = {
            log: { level: 'info', timestamp: true },
            dns: {
                servers: [
                    { tag: 'remote', address: dnsServer, detour: 'select' },
                    { tag: 'local', address: '223.5.5.5', detour: 'direct' },
                    { tag: 'fakeip', address: 'fakeip' },
                    { tag: 'block', address: 'rcode://success' }
                ],
                rules: [
                    { outbound: 'any', server: 'local' },
                    { rule_set: 'geosite-category-ads-all', server: 'block' },
                    { rule_set: 'geosite-cn', server: 'local' },
                    { query_type: ['A', 'AAAA'], server: 'fakeip' }
                ],
                fakeip: { enabled: true, inet4_range: '198.18.0.0/15', inet6_range: 'fc00::/18' },
                independent_cache: true,
                strategy: 'ipv4_only'
            },
            inbounds: [
                {
                    type: 'mixed',
                    tag: 'mixed-in',
                    listen: '127.0.0.1',
                    listen_port: 2080,
                    sniff: true,
                    sniff_override_destination: true
                },
                {
                    type: 'tun',
                    tag: 'tun-in',
                    interface_name: 'sing-box',
                    address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
                    mtu: 9000,
                    auto_route: true,
                    strict_route: true,
                    stack: 'mixed',
                    sniff: true,
                    sniff_override_destination: true
                }
            ],
            outbounds: [
                { type: 'selector', tag: 'select', outbounds: ['direct', ...outboundTags], default: outboundTags[0] || 'direct' },
                { type: 'selector', tag: '🌍 国外媒体', outbounds: ['select', 'direct', ...outboundTags] },
                { type: 'selector', tag: '📲 电报信息', outbounds: ['select', 'direct', ...outboundTags] },
                { type: 'selector', tag: '🌐 谷歌服务', outbounds: ['select', 'direct', ...outboundTags] },
                { type: 'selector', tag: '🤖 OpenAI', outbounds: ['select', 'direct', ...outboundTags] },
                { type: 'selector', tag: 'Ⓜ️ 微软服务', outbounds: ['direct', 'select', ...outboundTags] },
                { type: 'selector', tag: '🍎 苹果服务', outbounds: ['direct', 'select', ...outboundTags] },
                { type: 'selector', tag: '📺 哔哩哔哩', outbounds: ['direct', 'select', ...outboundTags] },
                { type: 'selector', tag: '📹 油管视频', outbounds: ['select', '🌍 国外媒体', 'direct', ...outboundTags] },
                { type: 'selector', tag: '🎬 奈飞视频', outbounds: ['select', '🌍 国外媒体', 'direct', ...outboundTags] },
                { type: 'selector', tag: '🎯 全球直连', outbounds: ['direct'] },
                { type: 'selector', tag: '🐟 漏网之鱼', outbounds: ['select', 'direct', ...outboundTags] },
                ...nodes.map(nodeToOutbound),
                { type: 'direct', tag: 'direct' },
                { type: 'block', tag: 'block' },
                { type: 'dns', tag: 'dns-out' }
            ],
            route: {
                rule_set: [
                    siteRule('cn'),
                    siteRule('private'),
                    siteRule('apple'),
                    siteRule('apple-cn'),
                    siteRule('microsoft'),
                    siteRule('microsoft@cn'),
                    siteRule('google'),
                    siteRule('telegram'),
                    siteRule('openai'),
                    siteRule('anthropic'),
                    siteRule('youtube'),
                    siteRule('netflix'),
                    siteRule('disney'),
                    siteRule('spotify'),
                    siteRule('tiktok'),
                    siteRule('twitter'),
                    siteRule('facebook'),
                    siteRule('github'),
                    siteRule('geolocation-!cn'),
                    siteRule('category-ads-all'),
                    ipRule('cn'),
                    ipRule('private'),
                    ipRule('telegram')
                ],
                rules: [
                    { protocol: 'dns', outbound: 'dns-out' },
                    { ip_is_private: true, outbound: 'direct' },
                    { rule_set: 'geosite-category-ads-all', outbound: 'block' },
                    { rule_set: 'geosite-private', outbound: 'direct' },
                    { rule_set: 'geosite-apple-cn', outbound: 'direct' },
                    { rule_set: 'geosite-microsoft@cn', outbound: 'direct' },
                    { rule_set: 'geosite-apple', outbound: '🍎 苹果服务' },
                    { rule_set: 'geosite-microsoft', outbound: 'Ⓜ️ 微软服务' },
                    { rule_set: 'geosite-openai', outbound: '🤖 OpenAI' },
                    { rule_set: 'geosite-anthropic', outbound: '🤖 OpenAI' },
                    { rule_set: 'geosite-telegram', outbound: '📲 电报信息' },
                    { rule_set: 'geoip-telegram', outbound: '📲 电报信息' },
                    { rule_set: 'geosite-google', outbound: '🌐 谷歌服务' },
                    { rule_set: 'geosite-youtube', outbound: '🌍 国外媒体' },
                    { rule_set: 'geosite-netflix', outbound: '🌍 国外媒体' },
                    { rule_set: 'geosite-disney', outbound: '🌍 国外媒体' },
                    { rule_set: 'geosite-spotify', outbound: '🌍 国外媒体' },
                    { rule_set: 'geosite-tiktok', outbound: '🌍 国外媒体' },
                    { rule_set: 'geosite-twitter', outbound: '🌍 国外媒体' },
                    { rule_set: 'geosite-facebook', outbound: '🌍 国外媒体' },
                    { rule_set: 'geosite-github', outbound: 'select' },
                    { rule_set: 'geosite-geolocation-!cn', outbound: 'select' },
                    { rule_set: 'geosite-cn', outbound: 'direct' },
                    { rule_set: 'geoip-cn', outbound: 'direct' },
                    { ip_is_private: true, outbound: 'direct' }
                ],
                final: '🐟 漏网之鱼',
                auto_detect_interface: true
            },
            experimental: {
                cache_file: { enabled: true, store_fakeip: true },
                clash_api: { external_controller: '127.0.0.1:9090' }
            }
        };
        return JSON.stringify(config, null, 2);
    }

    // ACL4SSR 规则源（CDN：jsDelivr 镜像 GitHub）
    const ACL_BASE = 'https://fastly.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash';
    const aclRule = (name) => `${ACL_BASE}/${name}.list`;

    // 内部生成 Surge ini (完整 ACL4SSR 规则集；仅 Trojan，Surge 不原生支持 VLESS)
    function generateSurgeIni(links) {
        const nodes = links.map(parseShareLink).filter(n => n && n.proto === 'trojan');
        const dnsServer = customDNS || '223.5.5.5';
        const names = nodes.map(n => n.name);
        const lines = [
            '[General]',
            'loglevel = notify',
            'internet-test-url = http://www.apple.com/library/test/success.html',
            'proxy-test-url = http://www.gstatic.com/generate_204',
            'test-timeout = 3',
            `dns-server = ${dnsServer.replace(/^https?:\/\//, '').replace(/\/.*$/, '')}, 119.29.29.29, system`,
            'encrypted-dns-server = https://223.5.5.5/dns-query, https://1.12.12.12/dns-query',
            'ipv6 = true',
            'allow-wifi-access = false',
            'wifi-access-http-port = 6152',
            'wifi-access-socks5-port = 6153',
            'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com',
            'exclude-simple-hostnames = true',
            'show-error-page-for-reject = true',
            '',
            '[Proxy]',
        ];
        for (const n of nodes) {
            const sni = n.sni;
            lines.push(`${n.name} = trojan, ${n.server}, ${n.port}, password=${n.password}, sni=${sni}, ws=true, ws-path=${n.path}, ws-headers=Host:${n.host}, skip-cert-verify=false, tfo=true`);
        }
        if (!nodes.length) {
            lines.push('Direct = direct');
        }
        lines.push('');
        lines.push('[Proxy Group]');
        const list = names.length ? names.join(', ') : 'DIRECT';
        lines.push(`🚀 节点选择 = select, 🎯 全球直连, ${list}`);
        lines.push(`🌍 国外媒体 = select, ${iniPolicyList(names)}`);
        lines.push(`📺 哔哩哔哩 = select, ${iniPolicyList(names, { directFirst: true })}`);
        lines.push(`📹 油管视频 = select, ${iniPolicyList(names, { extraGroups: ['🌍 国外媒体'] })}`);
        lines.push(`🎬 奈飞视频 = select, ${iniPolicyList(names, { extraGroups: ['🌍 国外媒体'] })}`);
        lines.push(`📲 电报信息 = select, ${iniPolicyList(names)}`);
        lines.push(`🌐 谷歌服务 = select, ${iniPolicyList(names)}`);
        lines.push(`🤖 OpenAI = select, ${iniPolicyList(names)}`);
        lines.push(`Ⓜ️ 微软服务 = select, ${iniPolicyList(names, { directFirst: true })}`);
        lines.push(`🍎 苹果服务 = select, ${iniPolicyList(names, { directFirst: true })}`);
        lines.push(`🎯 全球直连 = select, DIRECT`);
        lines.push(`🛑 全球拦截 = select, REJECT, DIRECT`);
        lines.push(`🐟 漏网之鱼 = select, ${iniPolicyList(names)}`);
        lines.push('');
        lines.push('[Rule]');
        lines.push(`RULE-SET,${aclRule('LocalAreaNetwork')},🎯 全球直连`);
        lines.push(`RULE-SET,${aclRule('UnBan')},🎯 全球直连`);
        lines.push(`RULE-SET,${aclRule('BanAD')},🛑 全球拦截`);
        lines.push(`RULE-SET,${aclRule('BanProgramAD')},🛑 全球拦截`);
        lines.push(`RULE-SET,${aclRule('GoogleFCM')},🌐 谷歌服务`);
        lines.push(`RULE-SET,${aclRule('GoogleCN')},🎯 全球直连`);
        lines.push(`RULE-SET,${aclRule('SteamCN')},🎯 全球直连`);
        lines.push(`RULE-SET,${aclRule('Microsoft')},Ⓜ️ 微软服务`);
        lines.push(`RULE-SET,${aclRule('Apple')},🍎 苹果服务`);
        lines.push(`RULE-SET,${aclRule('Telegram')},📲 电报信息`);
        lines.push(`RULE-SET,${aclRule('OpenAi')},🤖 OpenAI`);
        lines.push(`RULE-SET,${aclRule('Claude')},🤖 OpenAI`);
        lines.push(`RULE-SET,${aclRule('Copilot')},🤖 OpenAI`);
        lines.push(`RULE-SET,${aclRule('Netflix')},🌍 国外媒体`);
        lines.push(`RULE-SET,${aclRule('YouTube')},🌍 国外媒体`);
        lines.push(`RULE-SET,${aclRule('Disney')},🌍 国外媒体`);
        lines.push(`RULE-SET,${aclRule('Spotify')},🌍 国外媒体`);
        lines.push(`RULE-SET,${aclRule('TikTok')},🌍 国外媒体`);
        lines.push(`RULE-SET,${aclRule('BiliBili')},📺 哔哩哔哩`);
        lines.push(`RULE-SET,${aclRule('ProxyMedia')},🌍 国外媒体`);
        lines.push(`RULE-SET,${aclRule('ProxyGFWlist')},🚀 节点选择`);
        lines.push(`RULE-SET,${aclRule('ChinaDomain')},🎯 全球直连`);
        lines.push(`RULE-SET,${aclRule('ChinaCompanyIp')},🎯 全球直连`);
        lines.push(`RULE-SET,${aclRule('ChinaIp')},🎯 全球直连`);
        lines.push('GEOIP,CN,🎯 全球直连');
        lines.push('FINAL,🐟 漏网之鱼,dns-failed');
        return lines.join('\n');
    }

    // 内部生成 Loon ini (完整 ACL4SSR 规则集；vless + trojan)
    function generateLoonIni(links) {
        const nodes = links.map(parseShareLink).filter(n => n && (n.proto === 'vless' || n.proto === 'trojan'));
        const names = nodes.map(n => n.name);
        const lines = [
            '[General]',
            'ip-mode = dual',
            `dns-server = ${(customDNS || '223.5.5.5').replace(/^https?:\/\//, '').replace(/\/.*$/, '')},119.29.29.29,system`,
            'doh-server = https://223.5.5.5/dns-query, https://1.12.12.12/dns-query',
            'allow-udp-proxy = true',
            'allow-wifi-access = false',
            'sni-sniffing = true',
            'skip-proxy = 127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com',
            'bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32',
            '',
            '[Proxy]'
        ];
        for (const n of nodes) {
            if (n.proto === 'vless') {
                const parts = [`${n.server}`, `${n.port}`, `udp=true`, `username=${n.uuid}`, `transport=ws`, `path=${n.path}`, `host=${n.host}`, `over-tls=${n.tls ? 'true' : 'false'}`];
                if (n.tls) {
                    parts.push(`tls-name=${n.sni}`);
                    if (n.alpn && n.alpn.length) parts.push(`alpn=${n.alpn.join(':')}`);
                    parts.push(`skip-cert-verify=false`);
                }
                lines.push(`${n.name} = vless,${parts.join(',')}`);
            } else {
                const parts = [`${n.server}`, `${n.port}`, `password=${n.password}`, `transport=ws`, `path=${n.path}`, `host=${n.host}`, `over-tls=true`, `tls-name=${n.sni}`];
                if (n.alpn && n.alpn.length) parts.push(`alpn=${n.alpn.join(':')}`);
                parts.push(`skip-cert-verify=false`);
                lines.push(`${n.name} = trojan,${parts.join(',')}`);
            }
        }
        lines.push('');
        lines.push('[Proxy Group]');
        const list = names.length ? names.join(',') : 'DIRECT';
        lines.push(`🚀 节点选择 = select,🎯 全球直连,${list}`);
        lines.push(`🌍 国外媒体 = select,${iniPolicyList(names, { compact: true })}`);
        lines.push(`📺 哔哩哔哩 = select,${iniPolicyList(names, { directFirst: true, compact: true })}`);
        lines.push(`📹 油管视频 = select,${iniPolicyList(names, { extraGroups: ['🌍 国外媒体'], compact: true })}`);
        lines.push(`🎬 奈飞视频 = select,${iniPolicyList(names, { extraGroups: ['🌍 国外媒体'], compact: true })}`);
        lines.push(`📲 电报信息 = select,${iniPolicyList(names, { compact: true })}`);
        lines.push(`🌐 谷歌服务 = select,${iniPolicyList(names, { compact: true })}`);
        lines.push(`🤖 OpenAI = select,${iniPolicyList(names, { compact: true })}`);
        lines.push(`Ⓜ️ 微软服务 = select,${iniPolicyList(names, { directFirst: true, compact: true })}`);
        lines.push(`🍎 苹果服务 = select,${iniPolicyList(names, { directFirst: true, compact: true })}`);
        lines.push(`🎯 全球直连 = select,DIRECT`);
        lines.push(`🛑 全球拦截 = select,REJECT,DIRECT`);
        lines.push(`🐟 漏网之鱼 = select,${iniPolicyList(names, { compact: true })}`);
        lines.push('');
        lines.push('[Remote Rule]');
        lines.push(`${aclRule('LocalAreaNetwork')}, policy=🎯 全球直连, tag=局域网, enabled=true`);
        lines.push(`${aclRule('BanAD')}, policy=🛑 全球拦截, tag=广告拦截, enabled=true`);
        lines.push(`${aclRule('BanProgramAD')}, policy=🛑 全球拦截, tag=应用广告, enabled=true`);
        lines.push(`${aclRule('GoogleCN')}, policy=🎯 全球直连, tag=GoogleCN, enabled=true`);
        lines.push(`${aclRule('SteamCN')}, policy=🎯 全球直连, tag=SteamCN, enabled=true`);
        lines.push(`${aclRule('Microsoft')}, policy=Ⓜ️ 微软服务, tag=微软, enabled=true`);
        lines.push(`${aclRule('Apple')}, policy=🍎 苹果服务, tag=苹果, enabled=true`);
        lines.push(`${aclRule('Telegram')}, policy=📲 电报信息, tag=电报, enabled=true`);
        lines.push(`${aclRule('OpenAi')}, policy=🤖 OpenAI, tag=OpenAI, enabled=true`);
        lines.push(`${aclRule('Netflix')}, policy=🌍 国外媒体, tag=Netflix, enabled=true`);
        lines.push(`${aclRule('YouTube')}, policy=🌍 国外媒体, tag=YouTube, enabled=true`);
        lines.push(`${aclRule('Disney')}, policy=🌍 国外媒体, tag=Disney, enabled=true`);
        lines.push(`${aclRule('Spotify')}, policy=🌍 国外媒体, tag=Spotify, enabled=true`);
        lines.push(`${aclRule('TikTok')}, policy=🌍 国外媒体, tag=TikTok, enabled=true`);
        lines.push(`${aclRule('BiliBili')}, policy=📺 哔哩哔哩, tag=哔哩哔哩, enabled=true`);
        lines.push(`${aclRule('ProxyMedia')}, policy=🌍 国外媒体, tag=代理媒体, enabled=true`);
        lines.push(`${aclRule('ProxyGFWlist')}, policy=🚀 节点选择, tag=代理列表, enabled=true`);
        lines.push(`${aclRule('ChinaDomain')}, policy=🎯 全球直连, tag=中国域名, enabled=true`);
        lines.push(`${aclRule('ChinaIp')}, policy=🎯 全球直连, tag=中国IP, enabled=true`);
        lines.push('');
        lines.push('[Rule]');
        lines.push('GEOIP,CN,🎯 全球直连');
        lines.push('FINAL,🐟 漏网之鱼');
        return lines.join('\n');
    }

    // 内部生成 Quantumult X 配置（完整 ACL4SSR 远端 filter 资源）
    function generateQuanxConf(links) {
        const nodes = links.map(parseShareLink).filter(n => n && (n.proto === 'vless' || n.proto === 'trojan'));
        const names = nodes.map(n => n.name);
        const QX_BASE = 'https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/QuantumultX';
        const lines = [
            '[general]',
            'network_check_url=http://www.gstatic.com/generate_204',
            'server_check_url=http://www.gstatic.com/generate_204',
            'profile_img_url=https://fastly.jsdelivr.net/gh/byJoey/cfnew@main/snippets/logo.png',
            'dns_exclusion_list=*.cmpassport.com, *.jegotrip.com.cn, *.icloud.com, *.icloud.com.cn, *.apple.com, *.weibo.com, *.qq.com',
            'running_mode_trigger=filter',
            '',
            '[dns]',
            `server=${(customDNS || '223.5.5.5').replace(/^https?:\/\//, '').replace(/\/.*$/, '')}`,
            'server=119.29.29.29',
            'server=https://223.5.5.5/dns-query',
            'server=https://1.12.12.12/dns-query',
            '',
            '[server_local]'
        ];
        for (const n of nodes) {
            if (n.proto === 'vless') {
                const parts = [`${n.server}:${n.port}`, `method=none`, `password=${n.uuid}`, `obfs=${n.tls ? 'wss' : 'ws'}`, `obfs-host=${n.host}`, `obfs-uri=${n.path}`];
                if (n.tls) parts.push(`tls-verification=true`, `tls13=true`);
                parts.push(`tag=${n.name}`);
                lines.push(`vless=${parts.join(', ')}`);
            } else {
                const parts = [`${n.server}:${n.port}`, `password=${n.password}`, `over-tls=true`, `tls-host=${n.sni}`, `obfs=wss`, `obfs-host=${n.host}`, `obfs-uri=${n.path}`, `tls-verification=true`, `tag=${n.name}`];
                lines.push(`trojan=${parts.join(', ')}`);
            }
        }
        lines.push('');
        lines.push('[policy]');
        const list = names.length ? names.join(', ') : 'direct';
        lines.push(`static=🚀 节点选择, ${list}, direct, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png`);
        lines.push(`static=🌍 国外媒体, ${iniPolicyList(names)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ForeignMedia.png`);
        lines.push(`static=📺 哔哩哔哩, ${iniPolicyList(names, { directFirst: true })}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/bilibili.png`);
        lines.push(`static=📹 油管视频, ${iniPolicyList(names, { extraGroups: ['🌍 国外媒体'] })}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png`);
        lines.push(`static=🎬 奈飞视频, ${iniPolicyList(names, { extraGroups: ['🌍 国外媒体'] })}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netflix.png`);
        lines.push(`static=📲 电报信息, ${iniPolicyList(names)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png`);
        lines.push(`static=🌐 谷歌服务, ${iniPolicyList(names)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Google.png`);
        lines.push(`static=🤖 OpenAI, ${iniPolicyList(names)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ChatGPT.png`);
        lines.push(`static=Ⓜ️ 微软服务, ${iniPolicyList(names, { directFirst: true })}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Microsoft.png`);
        lines.push(`static=🍎 苹果服务, ${iniPolicyList(names, { directFirst: true })}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Apple.png`);
        lines.push(`static=🎯 全球直连, direct, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png`);
        lines.push(`static=🛑 全球拦截, reject, direct, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Advertising.png`);
        lines.push(`static=🐟 漏网之鱼, ${iniPolicyList(names)}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Final.png`);
        lines.push('');
        lines.push('[filter_remote]');
        lines.push(`${QX_BASE}/Lan/Lan.list, tag=局域网, force-policy=🎯 全球直连, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Advertising/Advertising.list, tag=广告拦截, force-policy=🛑 全球拦截, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Microsoft/Microsoft.list, tag=微软, force-policy=Ⓜ️ 微软服务, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Apple/Apple.list, tag=苹果, force-policy=🍎 苹果服务, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Telegram/Telegram.list, tag=电报, force-policy=📲 电报信息, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Google/Google.list, tag=谷歌, force-policy=🌐 谷歌服务, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/OpenAI/OpenAI.list, tag=OpenAI, force-policy=🤖 OpenAI, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Claude/Claude.list, tag=Claude, force-policy=🤖 OpenAI, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/YouTube/YouTube.list, tag=YouTube, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Netflix/Netflix.list, tag=Netflix, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Disney/Disney.list, tag=Disney, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Spotify/Spotify.list, tag=Spotify, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/TikTok/TikTok.list, tag=TikTok, force-policy=🌍 国外媒体, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/BiliBili/BiliBili.list, tag=哔哩哔哩, force-policy=📺 哔哩哔哩, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/Global/Global.list, tag=全球加速, force-policy=🚀 节点选择, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push(`${QX_BASE}/ChinaMax/ChinaMax.list, tag=中国直连, force-policy=🎯 全球直连, update-interval=86400, opt-parser=false, enabled=true`);
        lines.push('');
        lines.push('[filter_local]');
        lines.push('geoip, cn, 🎯 全球直连');
        lines.push('final, 🐟 漏网之鱼');
        return lines.join('\n');
    }

    // 兼容旧调用名
    async function generateClashConfig(links) {
        return generateClashYaml(links);
    }
    function generateSurgeConfig(links) { return generateSurgeIni(links); }
    function generateLoonConfig(links) { return generateLoonIni(links); }
    function generateQuantumultXConfig(links) { return generateQuanxConf(links); }
    function generateSingBoxConfig(links) { return generateSingBoxJson(links); }
    function generateSSConfig(links) { return btoa(links.join('\n')); }
    function generateV2RayConfig(links) { return btoa(links.join('\n')); }

    // 全局变量存储ECH调试信息
    let echDebugInfo = '';

    async function fetchECHConfig(domain) {
        if (!enableECH) {
            echDebugInfo = 'ECH功能已禁用';
            return null;
        }

        echDebugInfo = '';
        const debugSteps = [];

        try {
            // 优先使用 Google DNS 查询 cloudflare-ech.com 的 ECH 配置
            debugSteps.push('尝试使用 Google DNS 查询 cloudflare-ech.com...');
            const echDomainUrl = `https://v.recipes/dns/dns.google/dns-query?name=cloudflare-ech.com&type=65`;
            const echResponse = await fetch(echDomainUrl, {
                headers: {
                    'Accept': 'application/json'
                }
            });

            debugSteps.push(`Google DNS 响应状态: ${echResponse.status}`);

            if (echResponse.ok) {
                const echData = await echResponse.json();
                debugSteps.push(`Google DNS 返回数据: ${JSON.stringify(echData).substring(0, 200)}...`);

                if (echData.Answer && echData.Answer.length > 0) {
                    debugSteps.push(`找到 ${echData.Answer.length} 条答案记录`);
                    for (const answer of echData.Answer) {
                        if (answer.data) {
                            debugSteps.push(`解析答案数据: ${typeof answer.data}, 长度: ${String(answer.data).length}`);
                            // Google DNS 返回的数据格式可能不同，需要解析
                            const dataStr = typeof answer.data === 'string' ? answer.data : JSON.stringify(answer.data);
                            const echMatch = dataStr.match(/ech=([^\s"']+)/);
                            if (echMatch && echMatch[1]) {
                                echDebugInfo = debugSteps.join('\\n') + '\\n✅ 成功从 Google DNS 获取 ECH 配置';
                                return echMatch[1];
                            }
                            // 如果没有找到，尝试直接使用 data（可能是 base64 编码的）
                            if (answer.data && !dataStr.includes('ech=')) {
                                try {
                                    const decoded = atob(answer.data);
                                    debugSteps.push(`尝试 base64 解码，解码后长度: ${decoded.length}`);
                                    const decodedMatch = decoded.match(/ech=([^\s"']+)/);
                                    if (decodedMatch && decodedMatch[1]) {
                                        echDebugInfo = debugSteps.join('\\n') + '\\n✅ 成功从 Google DNS (base64解码) 获取 ECH 配置';
                                        return decodedMatch[1];
                                    }
                                } catch (e) {
                                    debugSteps.push(`base64 解码失败: ${e.message}`);
                                }
                            }
                        }
                    }
                } else {
                    debugSteps.push('Google DNS 未返回答案记录');
                }
            } else {
                debugSteps.push(`Google DNS 请求失败: ${echResponse.status}`);
            }

            // 如果 cloudflare-ech.com 查询失败，尝试使用 Google DNS 查询目标域名的 HTTPS 记录
            debugSteps.push(`尝试使用 Google DNS 查询目标域名 ${domain}...`);
            const dohUrl = `https://v.recipes/dns/dns.google/dns-query?name=${encodeURIComponent(domain)}&type=65`;
            const response = await fetch(dohUrl, {
                headers: {
                    'Accept': 'application/json'
                }
            });

            debugSteps.push(`Google DNS (目标域名) 响应状态: ${response.status}`);

            if (response.ok) {
                const data = await response.json();
                debugSteps.push(`Google DNS (目标域名) 返回数据: ${JSON.stringify(data).substring(0, 200)}...`);

                if (data.Answer && data.Answer.length > 0) {
                    debugSteps.push(`找到 ${data.Answer.length} 条答案记录`);
                    for (const answer of data.Answer) {
                        if (answer.data) {
                            const dataStr = typeof answer.data === 'string' ? answer.data : JSON.stringify(answer.data);
                            const echMatch = dataStr.match(/ech=([^\s"']+)/);
                            if (echMatch && echMatch[1]) {
                                echDebugInfo = debugSteps.join('\\n') + '\\n✅ 成功从 Google DNS (目标域名) 获取 ECH 配置';
                                return echMatch[1];
                            }
                            // 尝试 base64 解码
                            try {
                                const decoded = atob(answer.data);
                                const decodedMatch = decoded.match(/ech=([^\s"']+)/);
                                if (decodedMatch && decodedMatch[1]) {
                                    echDebugInfo = debugSteps.join('\\n') + '\\n✅ 成功从 Google DNS (目标域名, base64解码) 获取 ECH 配置';
                                    return decodedMatch[1];
                                }
                            } catch (e) {
                                debugSteps.push(`base64 解码失败: ${e.message}`);
                            }
                        }
                    }
                } else {
                    debugSteps.push('Google DNS (目标域名) 未返回答案记录');
                }
            } else {
                debugSteps.push(`Google DNS (目标域名) 请求失败: ${response.status}`);
            }

            // 如果 Google DNS 失败，尝试使用 Cloudflare DNS 作为备选
            debugSteps.push('尝试使用 Cloudflare DNS 作为备选...');
            const cfEchUrl = `https://cloudflare-dns.com/dns-query?name=cloudflare-ech.com&type=65`;
            const cfResponse = await fetch(cfEchUrl, {
                headers: {
                    'Accept': 'application/dns-json'
                }
            });

            debugSteps.push(`Cloudflare DNS 响应状态: ${cfResponse.status}`);

            if (cfResponse.ok) {
                const cfData = await cfResponse.json();
                debugSteps.push(`Cloudflare DNS 返回数据: ${JSON.stringify(cfData).substring(0, 200)}...`);

                if (cfData.Answer && cfData.Answer.length > 0) {
                    debugSteps.push(`找到 ${cfData.Answer.length} 条答案记录`);
                    for (const answer of cfData.Answer) {
                        if (answer.data) {
                            const echMatch = answer.data.match(/ech=([^\s"']+)/);
                            if (echMatch && echMatch[1]) {
                                echDebugInfo = debugSteps.join('\\n') + '\\n✅ 成功从 Cloudflare DNS 获取 ECH 配置';
                                return echMatch[1];
                            }
                        }
                    }
                } else {
                    debugSteps.push('Cloudflare DNS 未返回答案记录');
                }
            } else {
                debugSteps.push(`Cloudflare DNS 请求失败: ${cfResponse.status}`);
            }

            echDebugInfo = debugSteps.join('\\n') + '\\n❌ 所有DNS查询均失败，未获取到ECH配置';
            return null;
        } catch (error) {
            echDebugInfo = debugSteps.join('\\n') + '\\n❌ 获取ECH配置时发生错误: ' + error.message;
            return null;
        }
    }

    async function handleSubscriptionRequest(request, user, url = null) {
        if (!url) url = new URL(request.url);

        const finalLinks = [];
        const workerDomain = url.hostname;
        const target = url.searchParams.get('target') || 'base64';
        const aliasNamer = createCompactNodeNamer(false);

        // 如果启用了ECH，使用自定义值
        let echConfig = null;
        if (enableECH) {
            const dnsServer = customDNS || 'https://223.5.5.5/dns-query';
            const echDomain = customECHDomain || 'cloudflare-ech.com';
            echConfig = `${echDomain}+${dnsServer}`;
        }

        async function addNodesFromList(list) {
            if (ev) {
                finalLinks.push(...generateLinksFromSource(list, user, workerDomain, echConfig, false, aliasNamer));
            }
            if (et) {
                finalLinks.push(...await generateTrojanLinksFromSource(list, user, workerDomain, echConfig, false, aliasNamer));
            }
            if (ex) {
                finalLinks.push(...generateXhttpLinksFromSource(list, user, workerDomain, echConfig, false, aliasNamer));
            }
        }

        if (ena) {
            if (currentWorkerRegion === 'CUSTOM') {
                const nativeList = [{ ip: workerDomain, isp: '原生地址' }];
                await addNodesFromList(nativeList);
            } else {
                try {
                    const nativeList = [{ ip: workerDomain, isp: '原生地址' }];
                    await addNodesFromList(nativeList);
                } catch (error) {
                    if (!currentWorkerRegion) {
                        currentWorkerRegion = await detectWorkerRegion(request);
                    }

                    const bestBackupIP = await getBestBackupIP(currentWorkerRegion);
                    if (bestBackupIP) {
                        fallbackAddress = bestBackupIP.domain + ':' + bestBackupIP.port;
                        const backupList = [{ ip: bestBackupIP.domain, isp: 'ProxyIP-' + currentWorkerRegion }];
                        await addNodesFromList(backupList);
                    } else {
                        const nativeList = [{ ip: workerDomain, isp: '原生地址' }];
                        await addNodesFromList(nativeList);
                    }
                }
            }
        }

        const hasCustomPreferred = customPreferredIPs.length > 0 || customPreferredDomains.length > 0;

        if (disablePreferred) {
        } else if (hasCustomPreferred) {
            if (customPreferredIPs.length > 0 && epi) {
                await addNodesFromList(customPreferredIPs);
            }

            if (customPreferredDomains.length > 0 && epd) {
                const customDomainList = customPreferredDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain }));
                await addNodesFromList(customDomainList);
            }
        } else {
            if (epd) {
            const domainList = directDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain }));
                await addNodesFromList(domainList);
            }

            if (epi) {
                if (!piu) {
                try {
                    const dynamicIPList = await fetchDynamicIPs();
                    if (dynamicIPList.length > 0) {
                            await addNodesFromList(dynamicIPList);
                    }
                } catch (error) {
                    if (!currentWorkerRegion) {
                        currentWorkerRegion = await detectWorkerRegion(request);
                    }
                    
                    const bestBackupIP = await getBestBackupIP(currentWorkerRegion);
                    if (bestBackupIP) {
                        fallbackAddress = bestBackupIP.domain + ':' + bestBackupIP.port;
                        
                        const backupList = [{ ip: bestBackupIP.domain, isp: 'ProxyIP-' + currentWorkerRegion }];
                            await addNodesFromList(backupList);
                        }
                    }
                }
            }

            if (egi) {
            try {
                    const newIPList = await fetchAndParseNewIPs();
                if (newIPList.length > 0) {
                    if (ev) {
                        finalLinks.push(...generateLinksFromNewIPs(newIPList, user, workerDomain, echConfig, false, aliasNamer));
                    }
                    if (et) {
                        finalLinks.push(...await generateTrojanLinksFromNewIPs(newIPList, user, workerDomain, echConfig, false, aliasNamer));
                    }
                    if (ex) {
                         finalLinks.push(...generateXhttpLinksFromSource(newIPList, user, workerDomain, echConfig, false, aliasNamer));
                    }
                }
            } catch (error) {
                if (!currentWorkerRegion) {
                    currentWorkerRegion = await detectWorkerRegion(request);
                }

                const bestBackupIP = await getBestBackupIP(currentWorkerRegion);
                if (bestBackupIP) {
                    fallbackAddress = bestBackupIP.domain + ':' + bestBackupIP.port;
                    
                    const backupList = [{ ip: bestBackupIP.domain, isp: 'ProxyIP-' + currentWorkerRegion }];
                        await addNodesFromList(backupList);
                    }
                }
            }
        }

        if (finalLinks.length === 0) {
            const errorRemark = "所有节点获取失败";
            const proto = atob('dmxlc3M=');
            const errorLink = `${proto}://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=ws&host=error.com&path=%2F#${encodeURIComponent(errorRemark)}`;
            finalLinks.push(errorLink);
        }

        let subscriptionContent;
        let contentType = 'text/plain; charset=utf-8';

        switch (target.toLowerCase()) {
            case atob('Y2xhc2g='):     // clash
            case atob('Y2xhc2hy'):     // clashr
            case 'stash':
            case 'meta':
            case 'clashmeta':
                subscriptionContent = generateClashYaml(finalLinks);
                contentType = 'text/yaml; charset=utf-8';
                break;
            case atob('c3VyZ2U='):     // surge
            case atob('c3VyZ2Uy'):
            case atob('c3VyZ2Uz'):
            case atob('c3VyZ2U0'):
                subscriptionContent = generateSurgeIni(finalLinks);
                contentType = 'text/plain; charset=utf-8';
                break;
            case atob('cXVhbnR1bXVsdA=='):  // quantumult
            case atob('cXVhbng='):          // quanx
            case 'quanx':
                subscriptionContent = generateQuanxConf(finalLinks);
                contentType = 'text/plain; charset=utf-8';
                break;
            case atob('c3M='):
            case atob('c3Ny'):
                subscriptionContent = btoa(finalLinks.join('\n'));
                break;
            case atob('djJyYXk='):
                subscriptionContent = btoa(finalLinks.join('\n'));
                break;
            case atob('bG9vbg=='):
                subscriptionContent = generateLoonIni(finalLinks);
                contentType = 'text/plain; charset=utf-8';
                break;
            case atob('c2luZ2JveA=='):  // singbox
            case 'sing-box':
            case 'singbox':
                subscriptionContent = generateSingBoxJson(finalLinks);
                contentType = 'application/json; charset=utf-8';
                break;
            default:
                subscriptionContent = btoa(finalLinks.join('\n'));
        }

        const responseHeaders = { 
            'Content-Type': contentType,
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        };

        // 添加ECH状态到响应头
        if (enableECH) {
            responseHeaders['X-ECH-Status'] = 'ENABLED';
            if (echConfig) {
                responseHeaders['X-ECH-Config-Length'] = String(echConfig.length);
            }
        }

        return new Response(subscriptionContent, {
            headers: responseHeaders,
        });
    }

    function generateLinksFromSource(list, user, workerDomain, echConfig = null, skipNumbering = false, aliasNamer = null) {
        const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
        const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

        const defaultHttpsPorts = [443];
        const defaultHttpPorts = disableNonTLS ? [] : [80];
        const links = [];
        const wsPath = '/?ed=2048';
        const proto = atob('dmxlc3M=');

        const makeNodeName = aliasNamer || createCompactNodeNamer(skipNumbering);

        for (const item of list) {
            const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;

            let portsToGenerate = [];
            if (item.port) {
                const port = item.port;
                if (CF_HTTPS_PORTS.includes(port)) {
                    portsToGenerate.push({ port: port, tls: true });
                } else if (CF_HTTP_PORTS.includes(port)) {
                    if (!disableNonTLS) {
                        portsToGenerate.push({ port: port, tls: false });
                    }
                } else {
                    portsToGenerate.push({ port: port, tls: true });
                }
            } else {
                defaultHttpsPorts.forEach(port => {
                    portsToGenerate.push({ port: port, tls: true });
                });
                defaultHttpPorts.forEach(port => {
                    portsToGenerate.push({ port: port, tls: false });
                });
            }

            for (const { port, tls } of portsToGenerate) {
                const wsNodeName = makeNodeName(item);

                if (tls) {
                    const wsParams = new URLSearchParams({ 
                        encryption: 'none', 
                        security: 'tls', 
                        sni: workerDomain, 
                        fp: enableECH ? 'chrome' : 'randomized',
                        type: 'ws', 
                        host: workerDomain, 
                        path: wsPath
                    });
                    applyALPNParam(wsParams);

                    // 如果启用了ECH，添加ech参数（ECH需要伪装成Chrome浏览器）
                    if (enableECH) {
                        const dnsServer = customDNS || 'https://223.5.5.5/dns-query';
                        const echDomain = customECHDomain || 'cloudflare-ech.com';
                        wsParams.set('ech', `${echDomain}+${dnsServer}`);
                    }

                    links.push(`${proto}://${user}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
                } else {
                    const wsParams = new URLSearchParams({
                        encryption: 'none',
                        security: 'none',
                        type: 'ws',
                        host: workerDomain,
                        path: wsPath
                    });

                    links.push(`${proto}://${user}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
                }
            }
        }
        return links;
    }

    async function generateTrojanLinksFromSource(list, user, workerDomain, echConfig = null, skipNumbering = false, aliasNamer = null) {
        const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
        const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

        const defaultHttpsPorts = [443];
        const defaultHttpPorts = disableNonTLS ? [] : [80];
        const links = [];
        const wsPath = '/?ed=2048';

        const password = tp || user;

        const makeNodeName = aliasNamer || createCompactNodeNamer(skipNumbering);

        for (const item of list) {
            const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;

            let portsToGenerate = [];
            if (item.port) {
                const port = item.port;
                if (CF_HTTPS_PORTS.includes(port)) {
                    portsToGenerate.push({ port: port, tls: true });
                } else if (CF_HTTP_PORTS.includes(port)) {
                    if (!disableNonTLS) {
                        portsToGenerate.push({ port: port, tls: false });
                    }
                } else {
                    portsToGenerate.push({ port: port, tls: true });
                }
            } else {
                defaultHttpsPorts.forEach(port => {
                    portsToGenerate.push({ port: port, tls: true });
                });
                defaultHttpPorts.forEach(port => {
                    portsToGenerate.push({ port: port, tls: false });
                });
            }

            for (const { port, tls } of portsToGenerate) {
                const wsNodeName = makeNodeName(item);

                if (tls) {
                    const wsParams = new URLSearchParams({ 
                        security: 'tls', 
                        sni: workerDomain, 
                        fp: 'chrome',
                        type: 'ws', 
                        host: workerDomain, 
                        path: wsPath
                    });
                    applyALPNParam(wsParams);

                    // 如果启用了ECH，添加ech参数（ECH需要伪装成Chrome浏览器）
                    if (enableECH) {
                        const dnsServer = customDNS || 'https://223.5.5.5/dns-query';
                        const echDomain = customECHDomain || 'cloudflare-ech.com';
                        wsParams.set('ech', `${echDomain}+${dnsServer}`);
                    }

                    links.push(`${atob('dHJvamFuOi8v')}${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
                } else {
                    const wsParams = new URLSearchParams({
                        security: 'none',
                        type: 'ws',
                        host: workerDomain,
                        path: wsPath
                    });

                    links.push(`${atob('dHJvamFuOi8v')}${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
                }
            }
        }
        return links;
    }

    async function fetchDynamicIPs() {
        const v4Url1 = "https://www.wetest.vip/page/cloudflare/address_v4.html";
        const v6Url1 = "https://www.wetest.vip/page/cloudflare/address_v6.html";
        let results = [];

        // 读取筛选配置（默认全部启用）
        const ipv4Enabled = getConfigValue('ipv4', '') === '' || getConfigValue('ipv4', 'yes') !== 'no';
        const ipv6Enabled = getConfigValue('ipv6', '') === '' || getConfigValue('ipv6', 'yes') !== 'no';
        const ispMobile = getConfigValue('ispMobile', '') === '' || getConfigValue('ispMobile', 'yes') !== 'no';
        const ispUnicom = getConfigValue('ispUnicom', '') === '' || getConfigValue('ispUnicom', 'yes') !== 'no';
        const ispTelecom = getConfigValue('ispTelecom', '') === '' || getConfigValue('ispTelecom', 'yes') !== 'no';

        try {
            const fetchPromises = [];
            if (ipv4Enabled) {
                fetchPromises.push(fetchAndParseWetest(v4Url1));
            } else {
                fetchPromises.push(Promise.resolve([]));
            }
            if (ipv6Enabled) {
                fetchPromises.push(fetchAndParseWetest(v6Url1));
            } else {
                fetchPromises.push(Promise.resolve([]));
            }

            const [ipv4List, ipv6List] = await Promise.all(fetchPromises);
            results = [...ipv4List, ...ipv6List];

            // 按运营商筛选
            if (results.length > 0) {
                results = results.filter(item => {
                    const isp = item.isp || '';
                    if (isp.includes('移动') && !ispMobile) return false;
                    if (isp.includes('联通') && !ispUnicom) return false;
                    if (isp.includes('电信') && !ispTelecom) return false;
                    return true;
                });
            }

            if (results.length > 0) {
                return results;
            }
        } catch (e) {
        }
        return [];
    }

    async function fetchAndParseWetest(url) {
        try {
            const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
            if (!response.ok) {
                return [];
            }
            const html = await response.text();
            const results = [];
            const rowRegex = /<tr[\s\S]*?<\/tr>/g;
            const cellRegex = /<td data-label="线路名称">(.+?)<\/td>[\s\S]*?<td data-label="优选地址">([\d.:a-fA-F]+)<\/td>[\s\S]*?<td data-label="数据中心">(.+?)<\/td>/;

            let match;
            while ((match = rowRegex.exec(html)) !== null) {
                const rowHtml = match[0];
                const cellMatch = rowHtml.match(cellRegex);
                if (cellMatch && cellMatch[1] && cellMatch[2]) {
                    const colo = cellMatch[3] ? cellMatch[3].trim().replace(/<.*?>/g, '') : '';
                    results.push({
                        isp: cellMatch[1].trim().replace(/<.*?>/g, ''),
                        ip: cellMatch[2].trim(),
                        colo: colo
                    });
                }
            }

            if (results.length === 0) {
            }

            return results;
        } catch (error) {
            return [];
        }
    }

    async function handleWsRequest(request) {
        // 从请求URL的path query中读取客户端自定义参数
        // p=ProxyIP, wk=Worker地区, rm=地区匹配(no关闭), s=socks5代理
        const reqUrl = new URL(request.url);
        const reqFallback = reqUrl.searchParams.get('p') || '';
        const reqRegion = (reqUrl.searchParams.get('wk') || '').toUpperCase();
        const reqRmStr = reqUrl.searchParams.get('rm') || '';
        const reqRm = reqRmStr ? reqRmStr.toLowerCase() !== 'no' : null;
        const reqSocksStr = reqUrl.searchParams.get('s') || '';
        let reqSocksConfig = null;
        if (reqSocksStr) {
            try { reqSocksConfig = parseSocksConfig(reqSocksStr); } catch (_) {}
        }

        // 检测并设置当前Worker地区，确保WebSocket请求能正确进行就近匹配
        // 优先级：客户端path参数wk > 全局manualWorkerRegion > 自动检测
        let effectiveRegion = currentWorkerRegion;
        if (!effectiveRegion || effectiveRegion === '') {
            if (reqRegion) {
                effectiveRegion = reqRegion;
            } else if (manualWorkerRegion && manualWorkerRegion.trim()) {
                effectiveRegion = manualWorkerRegion.trim().toUpperCase();
            } else {
                effectiveRegion = await detectWorkerRegion(request);
            }
        } else if (reqRegion) {
            effectiveRegion = reqRegion;
        }

        const wsPair = new WebSocketPair();
        const [clientSock, serverSock] = Object.values(wsPair);
        serverSock.accept();
        serverSock.binaryType = 'arraybuffer';

        let remoteConnWrapper = { socket: null, writer: null, drainUpload: null };
        let isDnsQuery = false;
        let protocolType = null; 
        let uploadBusy = false;
        let transportClosed = false;
        const uploadQueue = createChunkQueue(TRANSPORT_UP_PACK, TRANSPORT_UP_Q_MAX, TRANSPORT_UP_Q_MAX >> 8);
        const requestFetcher = request.fetcher;

        function releaseRemoteWriter() {
            try { remoteConnWrapper.writer?.releaseLock(); } catch (_) {}
            remoteConnWrapper.writer = null;
        }

        function closeTransport() {
            if (transportClosed) return;
            transportClosed = true;
            uploadQueue.clear();
            releaseRemoteWriter();
            try { remoteConnWrapper.socket?.close(); } catch (_) {}
            closeSocketQuietly(serverSock);
        }

        function queueUpload(chunk) {
            const data = toUint8Array(chunk);
            if (!data.byteLength) return true;
            if (!uploadQueue.sow(data)) {
                closeTransport();
                return false;
            }
            remoteConnWrapper.drainUpload();
            return true;
        }

        async function drainUpload() {
            if (uploadBusy || transportClosed || !remoteConnWrapper.writer) return;
            uploadBusy = true;
            try {
                for (;;) {
                    if (transportClosed || !remoteConnWrapper.writer) break;
                    const [data] = uploadQueue.bundle();
                    if (!data) break;
                    await remoteConnWrapper.writer.write(data);
                }
            } catch (_) {
                closeTransport();
            } finally {
                uploadBusy = false;
                if (!uploadQueue.empty && !transportClosed && remoteConnWrapper.writer) queueMicrotask(drainUpload);
            }
        }

        remoteConnWrapper.drainUpload = () => {
            if (!uploadBusy && !uploadQueue.empty && remoteConnWrapper.writer) queueMicrotask(drainUpload);
        };

        const earlyData = request.headers.get(atob('c2VjLXdlYnNvY2tldC1wcm90b2NvbA==')) || '';
        const readable = makeReadableStream(serverSock, earlyData);

        readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (transportClosed) return;
                const data = toUint8Array(chunk);
                if (isDnsQuery) return await forwardUDP(data, serverSock, null, requestFetcher);
                if (remoteConnWrapper.socket && remoteConnWrapper.writer) {
                    if (!queueUpload(data)) throw new Error('upload queue overflow');
                    return;
                }

                if (protocolType) {
                    if (!queueUpload(data)) throw new Error('upload queue overflow');
                    return;
                }

                if (!protocolType) {
                    if (ev && data.byteLength >= 24) {
                        const vlessResult = parseWsPacketHeader(data, at);
                        if (!vlessResult.hasError) {
                            protocolType = 'vless';
                            const { addressType, port, hostname, rawIndex, version, isUDP } = vlessResult;
                if (isUDP) {
                    if (port === 53) isDnsQuery = true;
                    else throw new Error(E_UDP_DNS_ONLY);
                }
                const respHeader = new Uint8Array([version[0], 0]);
                const rawData = data.subarray(rawIndex);
                if (isDnsQuery) return forwardUDP(rawData, serverSock, respHeader, requestFetcher);
                    await forwardTCP(addressType, hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, reqFallback, effectiveRegion, reqRm, reqSocksConfig, requestFetcher);
                            return;
                        }
                    }

                    if (et && data.byteLength >= 56) {
                        const tjResult = await parseTrojanHeader(data, at);
                        if (!tjResult.hasError) {
                            protocolType = atob('dHJvamFu');
                            const { addressType, port, hostname, rawClientData } = tjResult;
                            await forwardTCP(addressType, hostname, port, rawClientData, serverSock, null, remoteConnWrapper, reqFallback, effectiveRegion, reqRm, reqSocksConfig, requestFetcher);
                            return;
                        }
                    }

                    throw new Error('Invalid protocol or authentication failed');
                }
            },
        })).catch((err) => { closeTransport(); });

        return new Response(null, { status: 101, webSocket: clientSock });
    }

    async function forwardTCP(addrType, host, portNum, rawData, ws, respHeader, remoteConnWrapper, reqFallback = '', reqRegion = '', reqRm = null, reqSocksConfig = null, requestFetcher = null) {
        // 优先使用客户端path参数，其次回退到全局配置
        const effectiveFallback = reqFallback || fallbackAddress;
        const effectiveRegion = reqRegion || currentWorkerRegion;
        const effectiveRegionMatching = reqRm !== null ? reqRm : enableRegionMatching;
        const effectiveSocksConfig = reqSocksConfig || parsedSocks5Config;
        const effectiveSocksEnabled = reqSocksConfig ? true : isSocksEnabled;
        const initialData = toUint8Array(rawData);

        async function connectAndSend(address, port, useSocks = false) {
            const remoteSock = useSocks ?
                await establishSocksConnection(addrType, address, port, effectiveSocksConfig) :
                await connectTcpSocket(address, port, requestFetcher, TRANSPORT_CONNECT_RACE);
            const writer = remoteSock.writable.getWriter();
            if (initialData.byteLength) await writer.write(initialData);
            return { remoteSock, writer };
        }

        function detachIfCurrent(remoteSock, writer) {
            if (remoteConnWrapper.socket !== remoteSock) return;
            try { writer?.releaseLock(); } catch (_) {}
            remoteConnWrapper.socket = null;
            remoteConnWrapper.writer = null;
        }

        function attachRemote(remoteSock, writer, retryFunc) {
            try {
                if (remoteConnWrapper.writer && remoteConnWrapper.writer !== writer) {
                    remoteConnWrapper.writer.releaseLock();
                }
            } catch (_) {}
            remoteConnWrapper.socket = remoteSock;
            remoteConnWrapper.writer = writer;
            remoteConnWrapper.drainUpload?.();
            remoteSock.closed.catch(() => {}).finally(() => {
                if (remoteConnWrapper.socket === remoteSock) closeSocketQuietly(ws);
            });
            connectStreams(remoteSock, ws, respHeader, retryFunc).finally(() => {
                if (remoteConnWrapper.socket === remoteSock) {
                    try { writer.releaseLock(); } catch (_) {}
                    remoteConnWrapper.writer = null;
                }
            });
        }

        async function retryConnection() {
            if (enableSocksDowngrade && effectiveSocksEnabled) {
                try {
                    const { remoteSock: socksSocket, writer: socksWriter } = await connectAndSend(host, portNum, true);
                    attachRemote(socksSocket, socksWriter, null);
                    return;
                } catch (socksErr) {
                    let backupHost, backupPort;
                    if (effectiveFallback && effectiveFallback.trim()) {
                        const parsed = parseAddressAndPort(effectiveFallback);
                        backupHost = parsed.address;
                        backupPort = parsed.port || portNum;
                    } else {
                        const bestBackupIP = await getBestBackupIP(effectiveRegion, effectiveRegionMatching);
                        backupHost = bestBackupIP ? bestBackupIP.domain : host;
                        backupPort = bestBackupIP ? bestBackupIP.port : portNum;
                    }

                    try {
                        const { remoteSock: fallbackSocket, writer: fallbackWriter } = await connectAndSend(backupHost, backupPort, false);
                        attachRemote(fallbackSocket, fallbackWriter, null);
                    } catch (fallbackErr) {
                        closeSocketQuietly(ws);
                    }
                }
            } else {
                let backupHost, backupPort;
                if (effectiveFallback && effectiveFallback.trim()) {
                    const parsed = parseAddressAndPort(effectiveFallback);
                    backupHost = parsed.address;
                    backupPort = parsed.port || portNum;
                } else {
                    const bestBackupIP = await getBestBackupIP(effectiveRegion, effectiveRegionMatching);
                    backupHost = bestBackupIP ? bestBackupIP.domain : host;
                    backupPort = bestBackupIP ? bestBackupIP.port : portNum;
                }

                try {
                    const { remoteSock: fallbackSocket, writer: fallbackWriter } = await connectAndSend(backupHost, backupPort, effectiveSocksEnabled);
                    attachRemote(fallbackSocket, fallbackWriter, null);
                } catch (fallbackErr) {
                    closeSocketQuietly(ws);
                }
            }
        }
        
        try {
            const { remoteSock: initialSocket, writer: initialWriter } = await connectAndSend(host, portNum, enableSocksDowngrade ? false : effectiveSocksEnabled);
            attachRemote(initialSocket, initialWriter, () => {
                detachIfCurrent(initialSocket, initialWriter);
                retryConnection();
            });
        } catch (err) {
            await retryConnection();
        }
    }

    function toUint8Array(chunk) {
        if (chunk instanceof Uint8Array) return chunk;
        if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk);
        if (ArrayBuffer.isView(chunk)) return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
        return new Uint8Array(chunk);
    }

    function joinUint8Array(head, body) {
        const h = toUint8Array(head);
        const b = toUint8Array(body);
        const out = new Uint8Array(h.byteLength + b.byteLength);
        out.set(h);
        out.set(b, h.byteLength);
        return out;
    }

    function createChunkQueue(cap, qCap = cap, itemsMax = Math.max(1, qCap >> 8)) {
        let queue = [];
        let head = 0;
        let queuedBytes = 0;
        let bundleBuffer = null;

        function trim() {
            if (head > 32 && head * 2 >= queue.length) {
                queue = queue.slice(head);
                head = 0;
            }
        }

        function take() {
            if (head >= queue.length) return null;
            const data = queue[head];
            queue[head++] = undefined;
            queuedBytes -= data.byteLength;
            trim();
            return data;
        }

        return {
            get empty() { return head >= queue.length; },
            clear() {
                queue = [];
                head = 0;
                queuedBytes = 0;
            },
            sow(data) {
                const n = data?.byteLength || 0;
                if (!n) return true;
                if (queuedBytes + n > qCap || queue.length - head >= itemsMax) return false;
                queue.push(data);
                queuedBytes += n;
                return true;
            },
            bundle(data = null) {
                data ||= take();
                if (!data || head >= queue.length || data.byteLength >= cap) return [data, false];
                let total = data.byteLength;
                let end = head;
                while (end < queue.length) {
                    const next = queue[end];
                    const nextTotal = total + next.byteLength;
                    if (nextTotal > cap) break;
                    total = nextTotal;
                    end++;
                }
                if (end === head) return [data, false];
                const out = bundleBuffer ||= new Uint8Array(cap);
                out.set(data);
                let offset = data.byteLength;
                while (head < end) {
                    const next = queue[head];
                    queue[head++] = undefined;
                    queuedBytes -= next.byteLength;
                    out.set(next, offset);
                    offset += next.byteLength;
                }
                trim();
                return [out.subarray(0, total), true];
            }
        };
    }

    function createDownlinkGrain(webSocket) {
        const cap = TRANSPORT_DN_PACK;
        const tail = TRANSPORT_DN_TAIL;
        const lowWater = Math.max(4096, tail << 3);
        let pending = new Uint8Array(cap);
        let pendingBytes = 0;
        let timer = 0;
        let microtaskQueued = false;
        let generation = 0;
        let quietKey = 0;
        let quietRounds = 0;

        function flush() {
            if (timer) clearTimeout(timer);
            timer = 0;
            microtaskQueued = false;
            if (!pendingBytes) return;
            if (webSocket.readyState === 1) webSocket.send(pending.subarray(0, pendingBytes).slice());
            pending = new Uint8Array(cap);
            pendingBytes = 0;
            quietRounds = 0;
        }

        function schedule() {
            if (timer || microtaskQueued) return;
            microtaskQueued = true;
            quietKey = generation;
            queueMicrotask(() => {
                microtaskQueued = false;
                if (!pendingBytes || timer) return;
                if (cap - pendingBytes < tail) return flush();
                timer = setTimeout(() => {
                    timer = 0;
                    if (!pendingBytes) return;
                    if (cap - pendingBytes < tail) return flush();
                    if (quietRounds < 2 && (generation !== quietKey || pendingBytes < lowWater)) {
                        quietRounds++;
                        quietKey = generation;
                        return schedule();
                    }
                    flush();
                }, Math.max(TRANSPORT_DN_DELAY, 1));
            });
        }

        return {
            send(chunk) {
                const data = toUint8Array(chunk);
                let offset = 0;
                const total = data.byteLength;
                if (!total) return;
                while (offset < total) {
                    if (!pendingBytes && total - offset >= cap) {
                        const size = Math.min(cap, total - offset);
                        if (webSocket.readyState === 1) webSocket.send(offset || size !== total ? data.subarray(offset, offset + size) : data);
                        offset += size;
                        continue;
                    }
                    const size = Math.min(cap - pendingBytes, total - offset);
                    pending.set(data.subarray(offset, offset + size), pendingBytes);
                    pendingBytes += size;
                    offset += size;
                    generation++;
                    if (pendingBytes === cap || cap - pendingBytes < tail) flush();
                    else schedule();
                }
            },
            flush
        };
    }

    function openTcpSocket(address, port, requestFetcher = null) {
        const target = { hostname: address, port };
        if (requestFetcher && typeof requestFetcher.connect === 'function') return requestFetcher.connect(target);
        return connect(target);
    }

    async function openTcpSocketReady(address, port, requestFetcher = null) {
        try {
            const socket = openTcpSocket(address, port, requestFetcher);
            if (socket?.opened) await socket.opened;
            return socket;
        } catch (error) {
            if (!requestFetcher) throw error;
            const socket = connect({ hostname: address, port });
            if (socket?.opened) await socket.opened;
            return socket;
        }
    }

    async function connectTcpSocket(address, port, requestFetcher = null, raceCount = 1) {
        const count = Math.max(1, raceCount | 0);
        if (count <= 1) return openTcpSocketReady(address, port, requestFetcher);
        const attempts = Array.from({ length: count }, () => openTcpSocketReady(address, port, requestFetcher));
        const winner = await Promise.any(attempts);
        attempts.forEach((attempt) => {
            attempt.then((socket) => {
                if (socket !== winner) {
                    try { socket.close(); } catch (_) {}
                }
            }, () => {});
        });
        return winner;
    }

    function getUuidBytes(token) {
        if (uuidByteCache.has(token)) return uuidByteCache.get(token);
        const hex = String(token || '').replace(/-/g, '');
        if (hex.length !== 32) return null;
        const bytes = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            const value = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
            if (Number.isNaN(value)) return null;
            bytes[i] = value;
        }
        if (uuidByteCache.size > 16) uuidByteCache.clear();
        uuidByteCache.set(token, bytes);
        return bytes;
    }

    function matchesUuid(bytes, offset, token) {
        const id = getUuidBytes(token);
        return !!id &&
            bytes[offset] === id[0] && bytes[offset + 1] === id[1] &&
            bytes[offset + 2] === id[2] && bytes[offset + 3] === id[3] &&
            bytes[offset + 4] === id[4] && bytes[offset + 5] === id[5] &&
            bytes[offset + 6] === id[6] && bytes[offset + 7] === id[7] &&
            bytes[offset + 8] === id[8] && bytes[offset + 9] === id[9] &&
            bytes[offset + 10] === id[10] && bytes[offset + 11] === id[11] &&
            bytes[offset + 12] === id[12] && bytes[offset + 13] === id[13] &&
            bytes[offset + 14] === id[14] && bytes[offset + 15] === id[15];
    }

    function parseWsPacketHeader(chunk, token) {
        const bytes = toUint8Array(chunk);
        if (bytes.byteLength < 24) return { hasError: true, message: E_INVALID_DATA };
        const version = bytes.subarray(0, 1);
        if (!matchesUuid(bytes, 1, token)) return { hasError: true, message: E_INVALID_USER };
        const optLen = bytes[17];
        const cmdIdx = 18 + optLen;
        if (bytes.byteLength < cmdIdx + 5) return { hasError: true, message: E_INVALID_DATA };
        const cmd = bytes[cmdIdx];
        let isUDP = false;
        if (cmd === 1) {} else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: E_UNSUPPORTED_CMD }; }
        const portIdx = 19 + optLen;
        const port = (bytes[portIdx] << 8) | bytes[portIdx + 1];
        let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
        const addressType = bytes[addrIdx];
        switch (addressType) {
            case ADDRESS_TYPE_IPV4:
                addrLen = 4;
                if (bytes.byteLength < addrValIdx + addrLen) return { hasError: true, message: E_INVALID_DATA };
                hostname = `${bytes[addrValIdx]}.${bytes[addrValIdx + 1]}.${bytes[addrValIdx + 2]}.${bytes[addrValIdx + 3]}`;
                break;
            case ADDRESS_TYPE_URL:
                if (bytes.byteLength < addrValIdx + 1) return { hasError: true, message: E_INVALID_DATA };
                addrLen = bytes[addrValIdx++];
                if (bytes.byteLength < addrValIdx + addrLen) return { hasError: true, message: E_INVALID_DATA };
                hostname = sharedDecoder.decode(bytes.subarray(addrValIdx, addrValIdx + addrLen));
                break;
            case ADDRESS_TYPE_IPV6:
                addrLen = 16;
                if (bytes.byteLength < addrValIdx + addrLen) return { hasError: true, message: E_INVALID_DATA };
                const ipv6 = [];
                const ipv6View = new DataView(bytes.buffer, bytes.byteOffset + addrValIdx, addrLen);
                for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
                hostname = ipv6.join(':');
                break;
            default: return { hasError: true, message: `${E_INVALID_ADDR_TYPE}: ${addressType}` };
        }
        if (!hostname) return { hasError: true, message: `${E_EMPTY_ADDR}: ${addressType}` };
        return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
    }

    function makeReadableStream(socket, earlyDataHeader) {
        let cancelled = false;
        return new ReadableStream({
            start(controller) {
                socket.addEventListener('message', (event) => { if (!cancelled) controller.enqueue(toUint8Array(event.data)); });
                socket.addEventListener('close', () => { if (!cancelled) { closeSocketQuietly(socket); controller.close(); } });
                socket.addEventListener('error', (err) => controller.error(err));
                const { earlyData, error } = base64ToArray(earlyDataHeader);
                if (error) controller.error(error); else if (earlyData) controller.enqueue(toUint8Array(earlyData));
            },
            cancel() { cancelled = true; closeSocketQuietly(socket); }
        });
    }

    async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
        let header = headerData, hasData = false, retried = false;

        // 关键：CF 直连有时握手成功但远端长时间无数据，需要超时触发 SOCKS5 降级
        let firstByteTimer = null;
        if (retryFunc) {
            firstByteTimer = setTimeout(() => {
                if (!hasData && !retried) {
                    retried = true;
                    try { remoteSocket.close && remoteSocket.close(); } catch (_) {}
                    retryFunc();
                }
            }, FIRST_BYTE_TIMEOUT);
        }

        const tx = createDownlinkGrain(webSocket);
        let reader = null;
        let byob = true;
        let buffer = new ArrayBuffer(TRANSPORT_CHUNK_SIZE);

        try {
            try {
                reader = remoteSocket.readable.getReader({ mode: 'byob' });
            } catch (_) {
                byob = false;
                reader = remoteSocket.readable.getReader();
            }

            for (;;) {
                const result = byob ? await reader.read(new Uint8Array(buffer, 0, TRANSPORT_CHUNK_SIZE)) : await reader.read();
                if (result.done) break;
                const readValue = result.value;
                let chunk = toUint8Array(readValue);
                const reusableBuffer = byob && readValue?.buffer instanceof ArrayBuffer && readValue.buffer.byteLength >= TRANSPORT_CHUNK_SIZE
                    ? readValue.buffer
                    : new ArrayBuffer(TRANSPORT_CHUNK_SIZE);
                if (!chunk.byteLength) continue;

                if (!hasData) {
                    hasData = true;
                    if (firstByteTimer) { clearTimeout(firstByteTimer); firstByteTimer = null; }
                }

                if (webSocket.readyState !== 1) throw new Error(E_WS_NOT_OPEN);
                if (header) {
                    chunk = joinUint8Array(header, chunk);
                    header = null;
                }

                if (chunk.byteLength >= (TRANSPORT_CHUNK_SIZE >> 1)) {
                    tx.flush();
                    webSocket.send(chunk);
                    if (byob) buffer = new ArrayBuffer(TRANSPORT_CHUNK_SIZE);
                } else {
                    tx.send(chunk.slice());
                    if (byob) buffer = reusableBuffer;
                }
            }
            tx.flush();
        } catch (error) {
            // 已经触发 retry 时不要关闭 WS（retry 会重新挂载新 socket）
            if (!retried) closeSocketQuietly(webSocket);
        } finally {
            try { tx.flush(); } catch (_) {}
            try { reader?.releaseLock(); } catch (_) {}
        }

        if (firstByteTimer) { clearTimeout(firstByteTimer); firstByteTimer = null; }
        if (!hasData && !retried && retryFunc) retryFunc();
    }

    async function forwardUDP(udpChunk, webSocket, respHeader, requestFetcher = null) {
        try {
            const tcpSocket = await connectTcpSocket('8.8.4.4', 53, requestFetcher, 1);
            let header = respHeader;
            const writer = tcpSocket.writable.getWriter();
            await writer.write(udpChunk);
            writer.releaseLock();
            await connectStreams(tcpSocket, webSocket, header, null);
        } catch (error) { }
    }

    async function establishSocksConnection(addrType, address, port, socksConfig = parsedSocks5Config) {
        const { username, password, hostname, socksPort } = socksConfig;
        const socket = connect({ hostname, port: socksPort });
        const writer = socket.writable.getWriter();
        await writer.write(new Uint8Array(username ? [5, 2, 0, 2] : [5, 1, 0]));
        const reader = socket.readable.getReader();
        let res = (await reader.read()).value;
        if (res[0] !== 5 || res[1] === 255) throw new Error(E_SOCKS_NO_METHOD);
        if (res[1] === 2) {
            if (!username || !password) throw new Error(E_SOCKS_AUTH_NEEDED);
            const encoder = new TextEncoder();
            const authRequest = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
            await writer.write(authRequest);
            res = (await reader.read()).value;
            if (res[0] !== 1 || res[1] !== 0) throw new Error(E_SOCKS_AUTH_FAIL);
        }
        const encoder = new TextEncoder(); let DSTADDR;
        switch (addrType) {
            case ADDRESS_TYPE_IPV4: DSTADDR = new Uint8Array([1, ...address.split('.').map(Number)]); break;
            case ADDRESS_TYPE_URL: DSTADDR = new Uint8Array([3, address.length, ...encoder.encode(address)]); break;
            case ADDRESS_TYPE_IPV6: DSTADDR = new Uint8Array([4, ...address.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]); break;
            default: throw new Error(E_INVALID_ADDR_TYPE);
        }
        await writer.write(new Uint8Array([5, 1, 0, ...DSTADDR, port >> 8, port & 255]));
        res = (await reader.read()).value;
        if (res[1] !== 0) throw new Error(E_SOCKS_CONN_FAIL);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    }

    function parseSocksConfig(address) {
        let [latter, former] = address.split("@").reverse(); 
        let username, password, hostname, socksPort;

        if (former) { 
            const formers = former.split(":"); 
            if (formers.length !== 2) throw new Error(E_INVALID_SOCKS_ADDR);
            [username, password] = formers; 
        }

        const latters = latter.split(":"); 
        socksPort = Number(latters.pop()); 
        if (isNaN(socksPort)) throw new Error(E_INVALID_SOCKS_ADDR);

        hostname = latters.join(":"); 
        if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) throw new Error(E_INVALID_SOCKS_ADDR);

        return { username, password, hostname, socksPort };
    }

    async function handleSubscriptionPage(request, user = null) {
        if (!user) user = at;

        const url = new URL(request.url);
        // 优先检查Cookie中的语言设置
        const cookieHeader = request.headers.get('Cookie') || '';
        let langFromCookie = null;
        if (cookieHeader) {
            const cookies = cookieHeader.split(';').map(c => c.trim());
            for (const cookie of cookies) {
                if (cookie.startsWith('preferredLanguage=')) {
                    langFromCookie = cookie.split('=')[1];
                    break;
                }
            }
        }

        let isFarsi = false;

        if (langFromCookie === 'fa' || langFromCookie === 'fa-IR') {
            isFarsi = true;
        } else if (langFromCookie === 'zh' || langFromCookie === 'zh-CN') {
            isFarsi = false;
        } else {
            // 如果没有Cookie，使用浏览器语言检测
            const acceptLanguage = request.headers.get('Accept-Language') || '';
            const browserLang = acceptLanguage.split(',')[0].split('-')[0].toLowerCase();
            isFarsi = browserLang === 'fa' || acceptLanguage.includes('fa-IR') || acceptLanguage.includes('fa');
        }

        const langAttr = isFarsi ? 'fa-IR' : 'zh-CN';
            
        const translations = {
            zh: {
                title: '订阅中心',
                subtitle: '多客户端支持 • 智能优选 • 一键生成',
                selectClient: '[ 选择客户端 ]',
                systemStatus: '[ 系统状态 ]',
                configManagement: '[ 配置管理 ]',
                relatedLinks: '[ 相关链接 ]',
                checking: '检测中...',
                workerRegion: 'Worker地区: ',
                detectionMethod: '检测方式: ',
                proxyIPStatus: 'ProxyIP状态: ',
                currentIP: '当前使用IP: ',
                regionMatch: '地区匹配: ',
                selectionLogic: '选择逻辑: ',
                kvStatusChecking: '检测KV状态中...',
                kvEnabled: '✅ KV存储已启用，可以使用配置管理功能',
                kvDisabled: '⚠️ KV存储未启用或未配置',
                specifyRegion: '指定地区 (wk):',
                autoDetect: '自动检测',
                saveRegion: '保存地区配置',
                protocolSelection: '协议选择:',
                enableVLESS: '启用 VLESS 协议',
                enableTrojan: '启用 Trojan 协议',
                enableXhttp: '启用 xhttp 协议',
                trojanPassword: 'Trojan 密码 (可选):',
                customPath: '自定义路径 (d):',
                customIP: '自定义ProxyIP (p):',
                preferredIPs: '优选IP列表 (yx):',
                preferredIPsURL: '优选IP来源URL (yxURL):',
                latencyTest: '延迟测试',
                latencyTestIP: '测试IP/域名:',
                latencyTestIPPlaceholder: '输入IP或域名，多个用逗号分隔',
                latencyTestPort: '端口:',
                startTest: '开始测试',
                stopTest: '停止测试',
                testResult: '测试结果:',
                addToYx: '添加到优选列表',
                addSelectedToYx: '添加选中项到优选列表',
                selectAll: '全选',
                deselectAll: '取消全选',
                testingInProgress: '测试中...',
                testComplete: '测试完成',
                latencyMs: '延迟',
                timeout: '超时',
                ipSource: 'IP来源:',
                manualInput: '手动输入',
                cfRandomIP: 'CF随机IP',
                urlFetch: 'URL获取',
                randomCount: '生成数量:',
                fetchURL: '获取URL:',
                fetchURLPlaceholder: '输入优选IP的URL地址',
                generateIP: '生成IP',
                fetchIP: '获取IP',
                socks5Config: 'SOCKS5配置 (s):',
                customHomepage: '自定义首页URL (homepage):',
                customHomepagePlaceholder: '例如: https://example.com',
                customHomepageHint: '设置自定义URL作为首页伪装。访问根路径 / 时将显示该URL的内容。留空则显示默认终端页面。',
                saveConfig: '保存配置',
                advancedControl: '高级控制',
                subscriptionConverter: '订阅转换地址:',
                builtinPreferred: '内置优选类型:',
                enablePreferredDomain: '启用优选域名',
                enablePreferredIP: '启用优选 IP',
                enableNativeAddress: '启用原生地址',
                enableGitHubPreferred: '启用自定义优选',
                allowAPIManagement: '允许API管理 (ae):',
                regionMatching: '地区匹配 (rm):',
                downgradeControl: '降级控制 (qj):',
                tlsControl: 'TLS控制 (dkby):',
                preferredControl: '优选控制 (yxby):',
                saveAdvanced: '保存高级配置',
                loading: '加载中...',
                currentConfig: '📍 当前路径配置',
                refreshConfig: '刷新配置',
                resetConfig: '重置配置',
                subscriptionCopied: '订阅链接已复制',
                autoSubscriptionCopied: '自动识别订阅链接已复制，客户端访问时会根据User-Agent自动识别并返回对应格式',
                trojanPasswordPlaceholder: '留空则自动使用 UUID',
                trojanPasswordHint: '设置自定义 Trojan 密码。留空则使用 UUID。客户端会自动对密码进行 SHA224 哈希。',
                protocolHint: '可以同时启用多个协议。订阅将生成选中协议的节点。<br>• VLESS WS: 基于 WebSocket 的标准协议<br>• Trojan: 使用 SHA224 密码认证<br>• xhttp: 基于 HTTP POST 的伪装协议（需要绑定自定义域名并开启 gRPC）',
                enableECH: '启用 ECH (Encrypted Client Hello)',
                enableECHHint: '启用后，每次刷新订阅时会自动从 DoH 获取最新的 ECH 配置并添加到链接中',
                customDNS: '自定义 DNS 服务器',
                customDNSPlaceholder: '例如: https://223.5.5.5/dns-query',
                customDNSHint: '用于ECH配置查询的DNS服务器地址（DoH格式）',
                customECHDomain: '自定义 ECH 域名',
                customECHDomainPlaceholder: '例如: cloudflare-ech.com',
                customECHDomainHint: 'ECH配置中使用的域名，留空则使用默认值',
                alpn: 'TLS ALPN',
                alpnDefault: '默认（留空，由客户端协商）',
                alpnHint: '仅添加到 TLS 节点链接参数；留空则不写 alpn。',
                saveProtocol: '保存协议配置',
                subscriptionConverterPlaceholder: '默认: https://url.v1.mk/sub',
                subscriptionConverterHint: '订阅转换已内部实现，无需外部 API。此项仅作兼容保留，可留空。',
                builtinPreferredHint: '控制订阅中包含哪些内置优选节点。默认全部启用。',
                apiEnabledDefault: '默认（关闭API）',
                apiEnabledYes: '开启API管理',
                apiEnabledHint: '⚠️ 安全提醒：开启后允许通过API动态添加优选IP。建议仅在需要时开启。',
                regionMatchingDefault: '默认（启用地区匹配）',
                regionMatchingNo: '关闭地区匹配',
                regionMatchingHint: '设置为"关闭"时不进行地区智能匹配',
                downgradeControlDefault: '默认（不启用降级）',
                downgradeControlNo: '启用降级模式',
                downgradeControlHint: '设置为"启用"时：CF直连失败→SOCKS5连接→fallback地址',
                tlsControlDefault: '默认（保留所有节点）',
                tlsControlYes: '仅TLS节点',
                tlsControlHint: '设置为"仅TLS节点"时只生成带TLS的节点，不生成非TLS节点（如80端口）',
                preferredControlDefault: '默认（启用优选）',
                preferredControlYes: '关闭优选',
                preferredControlHint: '设置为"关闭优选"时只使用原生地址，不生成优选IP和域名节点',
                regionNames: {
                    HK: '🇭🇰 香港', US: '🇺🇸 美国', SG: '🇸🇬 新加坡', JP: '🇯🇵 日本',
                    KR: '🇰🇷 韩国', DE: '🇩🇪 德国', SE: '🇸🇪 瑞典', NL: '🇳🇱 荷兰',
                    FI: '🇫🇮 芬兰', GB: '🇬🇧 英国'
                },
                terminal: '终端 v2.9.8',
                githubProject: 'GitHub 项目',
                autoDetectClient: '自动识别',
                selectionLogicText: '同地区 → 邻近地区 → 其他地区',
                customIPDisabledHint: '使用自定义ProxyIP时，地区选择已禁用',
                customIPMode: '自定义ProxyIP模式 (p变量启用)',
                customIPModeDesc: '自定义IP模式 (已禁用地区匹配)',
                usingCustomProxyIP: '使用自定义ProxyIP: ',
                customIPConfig: ' (p变量配置)',
                customIPModeDisabled: '自定义IP模式，地区选择已禁用',
                manualRegion: '手动指定地区',
                manualRegionDesc: ' (手动指定)',
                proxyIPAvailable: '10/10 可用 (ProxyIP域名预设可用)',
                smartSelection: '智能就近选择中',
                sameRegionIP: '同地区IP可用 (1个)',
                cloudflareDetection: 'Cloudflare内置检测',
                detectionFailed: '检测失败',
                apiTestResult: 'API检测结果: ',
                apiTestTime: '检测时间: ',
                apiTestFailed: 'API检测失败: ',
                unknownError: '未知错误',
                apiTestError: 'API测试失败: ',
                kvNotConfigured: 'KV存储未配置，无法使用配置管理功能。\\n\\n请在Cloudflare Workers中:\\n1. 创建KV命名空间\\n2. 绑定环境变量 C\\n3. 重新部署代码',
                kvNotEnabled: 'KV存储未配置',
                kvCheckFailed: 'KV存储检测失败: 响应格式错误',
                kvCheckFailedStatus: 'KV存储检测失败 - 状态码: ',
                kvCheckFailedError: 'KV存储检测失败 - 错误: '
            },
            fa: {
                title: 'مرکز اشتراک',
                subtitle: 'پشتیبانی چند کلاینت • انتخاب هوشمند • تولید یک کلیکی',
                selectClient: '[ انتخاب کلاینت ]',
                systemStatus: '[ وضعیت سیستم ]',
                configManagement: '[ مدیریت تنظیمات ]',
                relatedLinks: '[ لینک‌های مرتبط ]',
                checking: 'در حال بررسی...',
                workerRegion: 'منطقه Worker: ',
                detectionMethod: 'روش تشخیص: ',
                proxyIPStatus: 'وضعیت ProxyIP: ',
                currentIP: 'IP فعلی: ',
                regionMatch: 'تطبیق منطقه: ',
                selectionLogic: 'منطق انتخاب: ',
                kvStatusChecking: 'در حال بررسی وضعیت KV...',
                kvEnabled: '✅ ذخیره‌سازی KV فعال است، می‌توانید از مدیریت تنظیمات استفاده کنید',
                kvDisabled: '⚠️ ذخیره‌سازی KV فعال نیست یا پیکربندی نشده است',
                specifyRegion: 'تعیین منطقه (wk):',
                autoDetect: 'تشخیص خودکار',
                saveRegion: 'ذخیره تنظیمات منطقه',
                protocolSelection: 'انتخاب پروتکل:',
                enableVLESS: 'فعال‌سازی پروتکل VLESS',
                enableTrojan: 'فعال‌سازی پروتکل Trojan',
                enableXhttp: 'فعال‌سازی پروتکل xhttp',
                enableECH: 'فعال‌سازی ECH (Encrypted Client Hello)',
                enableECHHint: 'پس از فعال‌سازی، در هر بار تازه‌سازی اشتراک، پیکربندی ECH به‌روز به‌طور خودکار از DoH دریافت شده و به لینک‌ها اضافه می‌شود',
                customDNS: 'سرور DNS سفارشی',
                customDNSPlaceholder: 'مثال: https://223.5.5.5/dns-query',
                customDNSHint: 'آدرس سرور DNS برای جستجوی پیکربندی ECH (فرمت DoH)',
                customECHDomain: 'دامنه ECH سفارشی',
                customECHDomainPlaceholder: 'مثال: cloudflare-ech.com',
                customECHDomainHint: 'دامنه استفاده شده در پیکربندی ECH، خالی بگذارید تا از مقدار پیش‌فرض استفاده شود',
                trojanPassword: 'رمز عبور Trojan (اختیاری):',
                customPath: 'مسیر سفارشی (d):',
                customIP: 'ProxyIP سفارشی (p):',
                preferredIPs: 'لیست IP ترجیحی (yx):',
                preferredIPsURL: 'URL منبع IP ترجیحی (yxURL):',
                latencyTest: 'تست تاخیر',
                latencyTestIP: 'IP/دامنه تست:',
                latencyTestIPPlaceholder: 'IP یا دامنه وارد کنید، چند مورد با کاما جدا شوند',
                latencyTestPort: 'پورت:',
                startTest: 'شروع تست',
                stopTest: 'توقف تست',
                testResult: 'نتیجه تست:',
                addToYx: 'افزودن به لیست ترجیحی',
                addSelectedToYx: 'افزودن موارد انتخاب شده',
                selectAll: 'انتخاب همه',
                deselectAll: 'لغو انتخاب',
                testingInProgress: 'در حال تست...',
                testComplete: 'تست کامل شد',
                latencyMs: 'تاخیر',
                timeout: 'زمان تمام شد',
                ipSource: 'منبع IP:',
                manualInput: 'ورودی دستی',
                cfRandomIP: 'IP تصادفی CF',
                urlFetch: 'دریافت از URL',
                randomCount: 'تعداد تولید:',
                fetchURL: 'URL دریافت:',
                fetchURLPlaceholder: 'آدرس URL لیست IP را وارد کنید',
                generateIP: 'تولید IP',
                fetchIP: 'دریافت IP',
                socks5Config: 'تنظیمات SOCKS5 (s):',
                customHomepage: 'URL صفحه اصلی سفارشی (homepage):',
                customHomepagePlaceholder: 'مثال: https://example.com',
                customHomepageHint: 'تنظیم URL سفارشی به عنوان استتار صفحه اصلی. هنگام دسترسی به مسیر اصلی / محتوای این URL نمایش داده می‌شود. اگر خالی بگذارید صفحه ترمینال پیش‌فرض نمایش داده می‌شود.',
                saveConfig: 'ذخیره تنظیمات',
                advancedControl: 'کنترل پیشرفته',
                subscriptionConverter: 'آدرس تبدیل اشتراک:',
                builtinPreferred: 'نوع ترجیحی داخلی:',
                enablePreferredDomain: 'فعال‌سازی دامنه ترجیحی',
                enablePreferredIP: 'فعال‌سازی IP ترجیحی',
                enableNativeAddress: 'فعال‌سازی آدرس اصلی',
                enableGitHubPreferred: 'فعال‌سازی ترجیح سفارشی',
                allowAPIManagement: 'اجازه مدیریت API (ae):',
                regionMatching: 'تطبیق منطقه (rm):',
                downgradeControl: 'کنترل کاهش سطح (qj):',
                tlsControl: 'کنترل TLS (dkby):',
                preferredControl: 'کنترل ترجیحی (yxby):',
                saveAdvanced: 'ذخیره تنظیمات پیشرفته',
                loading: 'در حال بارگذاری...',
                currentConfig: '📍 پیکربندی مسیر فعلی',
                refreshConfig: 'تازه‌سازی تنظیمات',
                resetConfig: 'بازنشانی تنظیمات',
                subscriptionCopied: 'لینک اشتراک کپی شد',
                autoSubscriptionCopied: 'لینک اشتراک تشخیص خودکار کپی شد، کلاینت هنگام دسترسی بر اساس User-Agent به طور خودکار تشخیص داده و قالب مربوطه را برمی‌گرداند',
                trojanPasswordPlaceholder: 'خالی بگذارید تا از UUID استفاده شود',
                trojanPasswordHint: 'رمز عبور Trojan سفارشی را تنظیم کنید. اگر خالی بگذارید از UUID استفاده می‌شود. کلاینت به طور خودکار رمز عبور را با SHA224 هش می‌کند.',
                protocolHint: 'می‌توانید چندین پروتکل را همزمان فعال کنید. اشتراک گره‌های پروتکل‌های انتخاب شده را تولید می‌کند.<br>• VLESS WS: پروتکل استاندارد مبتنی بر WebSocket<br>• Trojan: احراز هویت با رمز عبور SHA224<br>• xhttp: پروتکل استتار مبتنی بر HTTP POST (نیاز به اتصال دامنه سفارشی و فعال‌سازی gRPC دارد)',
                alpn: 'TLS ALPN',
                alpnDefault: 'پیش‌فرض (خالی، مذاکره توسط کلاینت)',
                alpnHint: 'فقط به لینک‌های TLS اضافه می‌شود؛ اگر خالی باشد alpn نوشته نمی‌شود.',
                saveProtocol: 'ذخیره تنظیمات پروتکل',
                subscriptionConverterPlaceholder: 'پیش‌فرض: https://url.v1.mk/sub',
                subscriptionConverterHint: 'تبدیل اشتراک به صورت داخلی پیاده‌سازی شده است و نیازی به API خارجی ندارد. این فیلد فقط برای سازگاری حفظ شده و می‌توان آن را خالی گذاشت.',
                builtinPreferredHint: 'کنترل اینکه کدام گره‌های ترجیحی داخلی در اشتراک گنجانده شوند. به طور پیش‌فرض همه فعال هستند.',
                apiEnabledDefault: 'پیش‌فرض (بستن API)',
                apiEnabledYes: 'فعال‌سازی مدیریت API',
                apiEnabledHint: '⚠️ هشدار امنیتی: فعال‌سازی این گزینه اجازه می‌دهد IP های ترجیحی از طریق API به طور پویا اضافه شوند. توصیه می‌شود فقط در صورت نیاز فعال کنید.',
                regionMatchingDefault: 'پیش‌فرض (فعال‌سازی تطبیق منطقه)',
                regionMatchingNo: 'بستن تطبیق منطقه',
                regionMatchingHint: 'وقتی "بستن" تنظیم شود، تطبیق هوشمند منطقه انجام نمی‌شود',
                downgradeControlDefault: 'پیش‌فرض (عدم فعال‌سازی کاهش سطح)',
                downgradeControlNo: 'فعال‌سازی حالت کاهش سطح',
                downgradeControlHint: 'وقتی "فعال" تنظیم شود: اتصال مستقیم CF ناموفق → اتصال SOCKS5 → آدرس fallback',
                tlsControlDefault: 'پیش‌فرض (حفظ همه گره‌ها)',
                tlsControlYes: 'فقط گره‌های TLS',
                tlsControlHint: 'وقتی "فقط گره‌های TLS" تنظیم شود، فقط گره‌های با TLS تولید می‌شوند، گره‌های غیر TLS (مانند پورت 80) تولید نمی‌شوند',
                preferredControlDefault: 'پیش‌فرض (فعال‌سازی ترجیح)',
                preferredControlYes: 'بستن ترجیح',
                preferredControlHint: 'وقتی "بستن ترجیح" تنظیم شود، فقط از آدرس اصلی استفاده می‌شود، گره‌های IP و دامنه ترجیحی تولید نمی‌شوند',
                regionNames: {
                    HK: '🇭🇰 هنگ کنگ', US: '🇺🇸 آمریکا', SG: '🇸🇬 سنگاپور', JP: '🇯🇵 ژاپن',
                    KR: '🇰🇷 کره جنوبی', DE: '🇩🇪 آلمان', SE: '🇸🇪 سوئد', NL: '🇳🇱 هلند',
                    FI: '🇫🇮 فنلاند', GB: '🇬🇧 بریتانیا'
                },
                terminal: 'ترمینال v2.9.8',
                githubProject: 'پروژه GitHub',
                autoDetectClient: 'تشخیص خودکار',
                selectionLogicText: 'هم‌منطقه → منطقه مجاور → سایر مناطق',
                customIPDisabledHint: 'هنگام استفاده از ProxyIP سفارشی، انتخاب منطقه غیرفعال است',
                customIPMode: 'حالت ProxyIP سفارشی (متغیر p فعال است)',
                customIPModeDesc: 'حالت IP سفارشی (تطبیق منطقه غیرفعال است)',
                usingCustomProxyIP: 'استفاده از ProxyIP سفارشی: ',
                customIPConfig: ' (پیکربندی متغیر p)',
                customIPModeDisabled: 'حالت IP سفارشی، انتخاب منطقه غیرفعال است',
                manualRegion: 'تعیین منطقه دستی',
                manualRegionDesc: ' (تعیین دستی)',
                proxyIPAvailable: '10/10 در دسترس (دامنه پیش‌فرض ProxyIP در دسترس است)',
                smartSelection: 'انتخاب هوشمند نزدیک در حال انجام است',
                sameRegionIP: 'IP هم‌منطقه در دسترس است (1)',
                cloudflareDetection: 'تشخیص داخلی Cloudflare',
                detectionFailed: 'تشخیص ناموفق',
                apiTestResult: 'نتیجه تشخیص API: ',
                apiTestTime: 'زمان تشخیص: ',
                apiTestFailed: 'تشخیص API ناموفق: ',
                unknownError: 'خطای ناشناخته',
                apiTestError: 'تست API ناموفق: ',
                kvNotConfigured: 'ذخیره‌سازی KV پیکربندی نشده است، نمی‌توانید از عملکرد مدیریت تنظیمات استفاده کنید.\\n\\nلطفا در Cloudflare Workers:\\n1. فضای نام KV ایجاد کنید\\n2. متغیر محیطی C را پیوند دهید\\n3. کد را دوباره مستقر کنید',
                kvNotEnabled: 'ذخیره‌سازی KV پیکربندی نشده است',
                kvCheckFailed: 'بررسی ذخیره‌سازی KV ناموفق: خطای فرمت پاسخ',
                kvCheckFailedStatus: 'بررسی ذخیره‌سازی KV ناموفق - کد وضعیت: ',
                kvCheckFailedError: 'بررسی ذخیره‌سازی KV ناموفق - خطا: '
            }
        };

        const t = translations[isFarsi ? 'fa' : 'zh'];

    const pageHtml = `<!DOCTYPE html>
    <html lang="${langAttr}" dir="${isFarsi ? 'rtl' : 'ltr'}">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${t.title}</title>
        <style>
            :root {
                --cp-bg: #05030e;
                --cp-bg-2: #0a0820;
                --cp-bg-3: #110835;
                --cp-cyan: #00f0ff;
                --cp-cyan-d: #00b8c4;
                --cp-pink: #ff2bd6;
                --cp-pink-d: #d1239f;
                --cp-purple: #a347ff;
                --cp-yellow: #fff200;
                --cp-mint: #00ff9d;
                --cp-amber: #ffb400;
                --cp-red: #ff3860;
                --cp-text: #e6f5ff;
                --cp-text-dim: #7aa9c4;
                --cp-border: rgba(0, 240, 255, 0.55);
                --cp-border-pink: rgba(255, 43, 214, 0.55);
                --cp-grid: rgba(255, 43, 214, 0.16);
            }
            * { margin: 0; padding: 0; box-sizing: border-box; }
            html, body { min-height: 100%; }
            body {
                font-family: "JetBrains Mono", "Fira Code", "Courier New", monospace;
                background: radial-gradient(ellipse at 80% -10%, #2a0040 0%, var(--cp-bg) 50%, #000 100%);
                color: var(--cp-text);
                min-height: 100vh;
                overflow-x: hidden;
                position: relative;
            }
            body::before {
                content: ""; position: fixed; inset: 0;
                background-image:
                    linear-gradient(var(--cp-grid) 1px, transparent 1px),
                    linear-gradient(90deg, var(--cp-grid) 1px, transparent 1px);
                background-size: 48px 48px;
                mask-image: radial-gradient(ellipse at center, #000 30%, transparent 85%);
                z-index: -3;
                animation: cp-grid-slide 22s linear infinite;
                pointer-events: none;
            }
            body::after {
                content: ""; position: fixed; inset: 0;
                background: repeating-linear-gradient(
                    180deg,
                    rgba(255,255,255,0.035) 0,
                    rgba(255,255,255,0.035) 1px,
                    transparent 1px,
                    transparent 3px
                );
                pointer-events: none;
                z-index: 6;
                mix-blend-mode: overlay;
                animation: cp-scan-flicker 6s infinite;
            }
            @keyframes cp-grid-slide {
                0% { background-position: 0 0, 0 0; }
                100% { background-position: 48px 48px, 48px 48px; }
            }
            @keyframes cp-scan-flicker {
                0%, 100% { opacity: 0.55; }
                50% { opacity: 0.85; }
            }
            .matrix-bg {
                position: fixed; inset: 0;
                background:
                    radial-gradient(circle at 85% 15%, rgba(255,43,214,0.18) 0%, transparent 45%),
                    radial-gradient(circle at 10% 85%, rgba(0,240,255,0.18) 0%, transparent 45%),
                    radial-gradient(circle at 55% 50%, rgba(163,71,255,0.10) 0%, transparent 60%);
                z-index: -2;
                pointer-events: none;
            }
            .matrix-rain { display: none; }
            .matrix-code-rain {
                position: fixed; inset: 0;
                pointer-events: none; z-index: -1;
                overflow: hidden;
            }
            .matrix-column {
                position: absolute; top: -120%; left: 0;
                color: var(--cp-cyan);
                font-family: "JetBrains Mono", "Courier New", monospace;
                font-size: 14px; line-height: 1.25;
                text-shadow: 0 0 6px var(--cp-cyan), 0 0 12px rgba(0,240,255,0.5);
                animation: cp-drop linear infinite;
            }
            @keyframes cp-drop {
                0%   { top: -120%; opacity: 0; }
                10%  { opacity: 0.85; }
                90%  { opacity: 0.4; }
                100% { top: 110vh; opacity: 0; }
            }
            .matrix-column:nth-child(odd)  { animation-duration: 12s; }
            .matrix-column:nth-child(even) { animation-duration: 18s; color: var(--cp-pink); text-shadow: 0 0 6px var(--cp-pink), 0 0 14px rgba(255,43,214,0.5); }
            .matrix-column:nth-child(3n)   { animation-duration: 20s; color: var(--cp-purple); text-shadow: 0 0 6px var(--cp-purple); }
            .matrix-column:nth-child(5n)   { animation-duration: 9s; opacity: 0.6; }

            ::selection { background: var(--cp-pink); color: var(--cp-bg); }

            .container {
                max-width: 1180px;
                margin: 0 auto;
                padding: 110px 24px 60px;
                position: relative;
                z-index: 1;
            }
            .header {
                text-align: center;
                margin-bottom: 36px;
                padding: 28px 24px;
                position: relative;
                border: 1px solid var(--cp-border);
                background: linear-gradient(135deg, rgba(15,3,40,0.6), rgba(40,5,70,0.45));
                clip-path: polygon(
                    0 14px, 14px 0,
                    calc(100% - 80px) 0, calc(100% - 60px) 14px,
                    100% 14px, 100% calc(100% - 14px),
                    calc(100% - 14px) 100%, 80px 100%,
                    60px calc(100% - 14px), 0 calc(100% - 14px)
                );
                box-shadow: 0 0 30px rgba(0,240,255,0.25), 0 0 60px rgba(255,43,214,0.18);
            }
            .header::before {
                content: "// SYS_ID / CFNEW / NIGHTCITY.NET";
                position: absolute; top: 8px; left: 24px;
                font-size: 10px; letter-spacing: 0.35em;
                color: var(--cp-pink);
                text-shadow: 0 0 6px var(--cp-pink);
            }
            .header::after {
                content: "STATUS // ONLINE";
                position: absolute; top: 8px; right: 24px;
                font-size: 10px; letter-spacing: 0.35em;
                color: var(--cp-mint);
                text-shadow: 0 0 6px var(--cp-mint);
            }
            .title {
                font-size: clamp(2.2rem, 5vw, 3.4rem);
                font-weight: 800;
                margin: 14px 0 8px;
                color: var(--cp-cyan);
                letter-spacing: 0.08em;
                text-transform: uppercase;
                text-shadow:
                    0 0 12px var(--cp-cyan),
                    0 0 28px rgba(0,240,255,0.5),
                    -2px 0 var(--cp-pink),
                    2px 0 var(--cp-mint);
                position: relative;
                animation: cp-title-flicker 6s infinite;
            }
            @keyframes cp-title-flicker {
                0%, 92%, 100% { opacity: 1; }
                94%, 96% { opacity: 0.65; }
            }
            .subtitle {
                color: var(--cp-text-dim);
                margin-bottom: 0;
                font-size: 0.95rem;
                letter-spacing: 0.25em;
                text-transform: uppercase;
            }
            .subtitle::before { content: "▸ "; color: var(--cp-pink); }

            .card {
                background:
                    linear-gradient(180deg, rgba(8,4,28,0.85) 0%, rgba(15,3,40,0.78) 100%);
                border: 1px solid var(--cp-border);
                border-radius: 0;
                padding: 26px 28px 28px;
                margin-bottom: 22px;
                position: relative;
                backdrop-filter: blur(8px);
                width: 100%;
                box-shadow:
                    0 0 0 1px rgba(255,43,214,0.18),
                    0 0 22px rgba(0,240,255,0.18),
                    0 0 60px rgba(255,43,214,0.06),
                    inset 0 0 24px rgba(0,240,255,0.05);
                clip-path: polygon(
                    0 16px, 16px 0,
                    calc(100% - 56px) 0, calc(100% - 40px) 16px,
                    100% 16px, 100% calc(100% - 14px),
                    calc(100% - 14px) 100%, 40px 100%,
                    24px calc(100% - 14px), 0 calc(100% - 14px)
                );
            }
            .card::after {
                content: ""; position: absolute; top: 0; left: 0; right: 0;
                height: 1px;
                background: linear-gradient(90deg, transparent, var(--cp-pink), var(--cp-cyan), transparent);
                opacity: 0.7;
            }
            .card-title {
                font-size: 1.1rem;
                margin: 0 0 20px;
                color: var(--cp-cyan);
                letter-spacing: 0.25em;
                text-transform: uppercase;
                text-shadow: 0 0 8px var(--cp-cyan);
                display: flex; align-items: center; gap: 12px;
                font-weight: 700;
            }
            .card-title::before {
                content: ""; display: inline-block;
                width: 14px; height: 14px;
                background: var(--cp-pink);
                box-shadow: 0 0 10px var(--cp-pink);
                transform: rotate(45deg);
            }
            .card-title::after {
                content: ""; flex: 1; height: 1px;
                background: linear-gradient(90deg, var(--cp-cyan), transparent);
                margin-left: 6px;
            }
            h3, h4 {
                color: var(--cp-cyan);
                letter-spacing: 0.18em;
                text-transform: uppercase;
                text-shadow: 0 0 6px var(--cp-cyan);
                font-weight: 700;
            }

            .client-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 14px;
                margin: 12px 0 18px;
            }
            .client-btn {
                background: linear-gradient(135deg, rgba(0,240,255,0.08), rgba(255,43,214,0.08));
                border: 1px solid var(--cp-border);
                padding: 14px 18px;
                color: var(--cp-cyan);
                font-family: inherit;
                font-weight: 700;
                font-size: 0.85rem;
                letter-spacing: 0.18em;
                text-transform: uppercase;
                cursor: pointer;
                transition: all 0.3s ease;
                text-align: center;
                position: relative;
                overflow: hidden;
                text-shadow: 0 0 6px var(--cp-cyan);
                clip-path: polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px);
            }
            .client-btn::before {
                content: ""; position: absolute; inset: 0; left: -100%;
                background: linear-gradient(90deg, transparent, rgba(0,240,255,0.35), transparent);
                transition: left 0.6s ease;
            }
            .client-btn:hover::before { left: 100%; }
            .client-btn:hover {
                color: var(--cp-pink);
                border-color: var(--cp-pink);
                background: linear-gradient(135deg, rgba(255,43,214,0.18), rgba(0,240,255,0.10));
                box-shadow: 0 0 14px rgba(255,43,214,0.55), 0 0 28px rgba(0,240,255,0.30);
                transform: translateY(-2px);
                text-shadow: 0 0 8px var(--cp-pink);
            }

            #clientSubscriptionUrl,
            .subscription-url,
            [class*='subscription-url'],
            [class*='c3Vic2NyaXB0aW9u'] {
                background: rgba(0,0,0,0.7) !important;
                border: 1px dashed var(--cp-pink) !important;
                padding: 14px 16px !important;
                word-break: break-all;
                font-family: inherit;
                color: var(--cp-mint) !important;
                margin-top: 18px;
                box-shadow: inset 0 0 12px rgba(255,43,214,0.18), 0 0 18px rgba(0,255,157,0.18) !important;
                position: relative;
                overflow-wrap: break-word;
                overflow-x: auto;
                max-width: 100%;
                font-size: 0.85rem;
                line-height: 1.6;
                text-shadow: 0 0 6px var(--cp-mint);
            }
            #clientSubscriptionUrl:empty { display: none !important; }

            .cp-hud {
                position: fixed; top: 18px; right: 22px;
                color: var(--cp-cyan);
                font-family: "JetBrains Mono", monospace;
                font-size: 11px; letter-spacing: 0.2em;
                text-transform: uppercase;
                text-align: right;
                opacity: 0.85;
                z-index: 1000;
            }
            .cp-hud .cp-hud-label { color: var(--cp-pink); }
            .cp-hud .cp-hud-line { display: block; }
            .cp-lang-wrapper {
                position: fixed; top: 18px; left: 22px; z-index: 1000;
                display: flex; align-items: center; gap: 10px;
            }
            .cp-lang-tag {
                color: var(--cp-pink); font-size: 11px;
                letter-spacing: 0.25em; text-transform: uppercase;
                text-shadow: 0 0 6px var(--cp-pink);
            }
            #languageSelector {
                background: rgba(8,4,28,0.85);
                border: 1px solid var(--cp-cyan);
                color: var(--cp-cyan);
                padding: 6px 12px;
                font-family: inherit;
                font-size: 12px;
                cursor: pointer;
                letter-spacing: 0.12em;
                text-shadow: 0 0 6px var(--cp-cyan);
                box-shadow: 0 0 12px rgba(0,240,255,0.35);
                clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
            }
            #languageSelector option { background: var(--cp-bg-2); color: var(--cp-cyan); }

            /* FX toggle - 页面特效图形化开关 */
            .cp-fx-toggle {
                position: fixed; top: 68px; left: 22px; z-index: 1001;
                background: rgba(8,4,28,0.85);
                border: 1px solid var(--cp-mint);
                color: var(--cp-mint);
                padding: 6px 12px;
                font-family: inherit;
                font-size: 11px;
                letter-spacing: 0.18em;
                text-transform: uppercase;
                cursor: pointer;
                text-shadow: 0 0 6px var(--cp-mint);
                box-shadow: 0 0 10px rgba(0,255,157,0.35);
                clip-path: polygon(7px 0, 100% 0, 100% calc(100% - 7px), calc(100% - 7px) 100%, 0 100%, 0 7px);
                transition: all 0.2s ease;
                display: inline-flex; align-items: center; gap: 6px;
            }
            .cp-fx-toggle:hover {
                color: var(--cp-pink);
                border-color: var(--cp-pink);
                text-shadow: 0 0 8px var(--cp-pink);
                box-shadow: 0 0 16px rgba(255,43,214,0.55);
            }
            .cp-fx-toggle .cp-fx-dot {
                width: 6px; height: 6px;
                background: var(--cp-mint);
                border-radius: 50%;
                box-shadow: 0 0 8px var(--cp-mint);
                transition: all 0.2s;
            }
            body.fx-off .cp-fx-toggle {
                color: var(--cp-text-dim);
                border-color: var(--cp-text-dim);
                text-shadow: none;
                box-shadow: none;
            }
            body.fx-off .cp-fx-toggle .cp-fx-dot {
                background: transparent;
                border: 1px solid var(--cp-text-dim);
                box-shadow: none;
            }
            /* FX OFF: 关闭所有装饰性特效，保留布局和配色 */
            body.fx-off .matrix-bg,
            body.fx-off .matrix-code-rain,
            body.fx-off .matrix-column { display: none !important; }
            body.fx-off::before,
            body.fx-off::after { display: none !important; content: none !important; }
            body.fx-off { background: var(--cp-bg) !important; }
            body.fx-off * {
                animation: none !important;
                transition: color 0.15s, background-color 0.15s, border-color 0.15s, box-shadow 0.15s !important;
            }
            body.fx-off .cp-glitch::before,
            body.fx-off .cp-glitch::after { display: none !important; }
            body.fx-off .terminal-cursor::after,
            body.fx-off .cp-fab-save .cp-fab-dot { animation: none !important; }
            body.fx-off .cp-fab-save:hover { transform: none !important; }
            body.fx-off .cp-action-bar.cp-dirty::before { animation: none !important; }
            body.fx-off .header::before { display: none !important; }
            body.fx-off .card { backdrop-filter: none !important; }
            body.fx-off select, body.fx-off input, body.fx-off textarea { backdrop-filter: none !important; }

            /* Status panel inside card */
            #systemStatus {
                background: linear-gradient(135deg, rgba(0,240,255,0.05), rgba(255,43,214,0.05)) !important;
                border: 1px solid var(--cp-border) !important;
                padding: 18px 20px !important;
                margin: 14px 0 0 !important;
                box-shadow: inset 0 0 16px rgba(0,240,255,0.12) !important;
                position: relative;
                clip-path: polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px);
            }
            #systemStatus > div {
                color: var(--cp-text) !important;
                text-shadow: none !important;
                font-family: inherit !important;
                margin: 6px 0 !important;
                font-size: 0.85rem !important;
                letter-spacing: 0.05em;
            }
            #systemStatus > div:first-child {
                color: var(--cp-pink) !important;
                font-weight: 700 !important;
                letter-spacing: 0.25em !important;
                text-shadow: 0 0 6px var(--cp-pink) !important;
                margin-bottom: 14px !important;
                text-transform: uppercase;
            }

            /* Force inputs / selects to cyberpunk */
            input[type="text"], input[type="number"], input[type="password"],
            select, textarea {
                background: rgba(0,0,0,0.6) !important;
                border: 1px solid var(--cp-border) !important;
                color: var(--cp-cyan) !important;
                font-family: inherit !important;
                font-size: 13px !important;
                padding: 10px 12px !important;
                outline: none;
                transition: border-color 0.2s, box-shadow 0.2s;
                box-shadow: inset 0 0 8px rgba(0,240,255,0.08) !important;
                letter-spacing: 0.04em;
            }
            input::placeholder { color: var(--cp-text-dim) !important; opacity: 0.7; }
            input:focus, select:focus, textarea:focus {
                border-color: var(--cp-pink) !important;
                box-shadow: 0 0 0 1px var(--cp-pink), 0 0 14px rgba(255,43,214,0.4) !important;
            }
            select option { background: var(--cp-bg-2); color: var(--cp-cyan); }
            input[type="checkbox"], input[type="radio"] {
                accent-color: var(--cp-pink);
            }

            label {
                color: var(--cp-cyan) !important;
                letter-spacing: 0.05em;
                text-shadow: 0 0 4px rgba(0,240,255,0.4);
            }
            label[style*="font-weight"], label[style*="bold"] {
                font-weight: 700 !important;
                color: var(--cp-pink) !important;
                text-shadow: 0 0 6px var(--cp-pink) !important;
                letter-spacing: 0.15em !important;
                text-transform: uppercase;
                font-size: 0.78rem !important;
            }
            small {
                color: var(--cp-text-dim) !important;
                font-size: 0.78rem !important;
                letter-spacing: 0.04em;
                line-height: 1.5;
            }

            /* Buttons inside forms - global override */
            button, input[type="submit"] {
                background: linear-gradient(135deg, rgba(0,240,255,0.15), rgba(255,43,214,0.15)) !important;
                border: 1px solid var(--cp-border) !important;
                color: var(--cp-cyan) !important;
                font-family: inherit !important;
                font-weight: 700 !important;
                cursor: pointer;
                padding: 10px 18px !important;
                letter-spacing: 0.18em !important;
                text-transform: uppercase;
                font-size: 0.78rem !important;
                text-shadow: 0 0 6px var(--cp-cyan) !important;
                transition: all 0.25s ease;
                clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
                box-shadow: 0 0 10px rgba(0,240,255,0.25);
            }
            button:hover, input[type="submit"]:hover {
                color: var(--cp-pink) !important;
                border-color: var(--cp-pink) !important;
                box-shadow: 0 0 16px rgba(255,43,214,0.45), 0 0 32px rgba(0,240,255,0.20) !important;
                transform: translateY(-1px);
                text-shadow: 0 0 8px var(--cp-pink) !important;
            }
            button[id*="Reset"], button[onclick*="reset"], button[style*="ff0000"] {
                color: var(--cp-red) !important;
                border-color: var(--cp-red) !important;
                text-shadow: 0 0 6px var(--cp-red) !important;
                background: linear-gradient(135deg, rgba(255,56,96,0.15), rgba(255,43,214,0.10)) !important;
            }
            button[id*="Reset"]:hover, button[onclick*="reset"]:hover, button[style*="ff0000"]:hover {
                box-shadow: 0 0 16px rgba(255,56,96,0.5) !important;
            }
            button[id="stopLatencyTest"] {
                color: var(--cp-red) !important;
                border-color: var(--cp-red) !important;
            }

            /* Form sub-cards */
            .card form > div[style*="background: rgba(15, 3, 40"],
            .card form > div[style*="background: rgba(20, 5, 50"],
            div[style*="background: rgba(15, 3, 40"],
            div[style*="background: rgba(20, 5, 50"] {
                background: linear-gradient(135deg, rgba(0,240,255,0.04), rgba(255,43,214,0.04)) !important;
                border: 1px solid var(--cp-border-pink) !important;
                box-shadow: inset 0 0 12px rgba(255,43,214,0.06) !important;
                border-radius: 0 !important;
            }

            /* kvStatus / statusMessage / currentConfig / pathTypeInfo */
            #kvStatus, #statusMessage, #currentConfig, #pathTypeInfo {
                background: rgba(0,0,0,0.55) !important;
                border: 1px solid var(--cp-border) !important;
                color: var(--cp-cyan) !important;
                font-family: inherit !important;
                box-shadow: inset 0 0 10px rgba(0,240,255,0.10) !important;
                padding: 12px 14px !important;
                font-size: 0.85rem !important;
                letter-spacing: 0.04em;
            }
            #pathTypeInfo div:first-child {
                color: var(--cp-pink) !important;
                text-shadow: 0 0 6px var(--cp-pink) !important;
                letter-spacing: 0.2em !important;
            }

            /* Latency Result list */
            #latencyResultsList {
                background: rgba(0,0,0,0.5) !important;
                border: 1px solid var(--cp-border) !important;
            }
            #latencyResultsList > div {
                border-bottom: 1px dashed rgba(0,240,255,0.18) !important;
            }
            #cityFilterContainer {
                background: rgba(0,0,0,0.55) !important;
                border: 1px solid var(--cp-border-pink) !important;
            }

            /* Related links area */
            .card a {
                color: var(--cp-cyan) !important;
                text-decoration: none;
                text-shadow: 0 0 6px var(--cp-cyan);
                letter-spacing: 0.15em;
                text-transform: uppercase;
                font-size: 0.85rem;
                padding: 4px 0;
                border-bottom: 1px dashed transparent;
                transition: all 0.25s;
            }
            .card a:hover {
                color: var(--cp-pink) !important;
                border-bottom-color: var(--cp-pink);
                text-shadow: 0 0 8px var(--cp-pink);
            }

            /* Scrollbars */
            ::-webkit-scrollbar { width: 8px; height: 8px; }
            ::-webkit-scrollbar-track { background: rgba(0,0,0,0.4); }
            ::-webkit-scrollbar-thumb {
                background: linear-gradient(180deg, var(--cp-pink), var(--cp-cyan));
            }

            .cp-glitch {
                position: relative;
                display: inline-block;
            }

            /* Floating action dock - bottom-right anchored FAB cluster */
            .cp-action-bar {
                position: fixed;
                right: 22px;
                bottom: 22px;
                z-index: 99999;
                isolation: isolate;
                display: flex;
                flex-direction: row-reverse;
                align-items: center;
                gap: 10px;
                padding: 0;
                background: transparent;
                border: 0;
                box-shadow: none;
                max-width: calc(100vw - 32px);
                pointer-events: auto;
            }
            /* Primary SAVE FAB - large, magenta, pulses when dirty */
            .cp-fab-save {
                position: relative;
                min-width: 188px;
                padding: 16px 26px !important;
                font-size: 0.92rem !important;
                font-weight: 800 !important;
                letter-spacing: 0.22em !important;
                text-transform: uppercase;
                color: var(--cp-pink) !important;
                background:
                    linear-gradient(135deg, rgba(255,43,214,0.45) 0%, rgba(0,240,255,0.25) 100%) !important;
                border: 2px solid var(--cp-pink) !important;
                text-shadow: 0 0 10px var(--cp-pink) !important;
                box-shadow:
                    0 0 0 1px rgba(0,240,255,0.4),
                    0 0 24px rgba(255,43,214,0.7),
                    0 0 48px rgba(255,43,214,0.35),
                    inset 0 0 18px rgba(255,43,214,0.25) !important;
                clip-path: polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px);
                cursor: pointer;
                transition: transform 0.18s ease, box-shadow 0.25s ease;
                display: inline-flex; align-items: center; gap: 10px;
                white-space: nowrap;
                font-family: inherit !important;
                animation: cp-fab-breathe 3.4s ease-in-out infinite;
            }
            @keyframes cp-fab-breathe {
                0%, 100% {
                    box-shadow:
                        0 0 0 1px rgba(0,240,255,0.4),
                        0 0 24px rgba(255,43,214,0.7),
                        0 0 48px rgba(255,43,214,0.35),
                        inset 0 0 18px rgba(255,43,214,0.25);
                }
                50% {
                    box-shadow:
                        0 0 0 1px rgba(0,240,255,0.55),
                        0 0 32px rgba(255,43,214,0.9),
                        0 0 80px rgba(255,43,214,0.45),
                        inset 0 0 24px rgba(255,43,214,0.4);
                }
            }
            .cp-fab-save:hover {
                transform: translateY(-3px) scale(1.03);
                color: #fff !important;
                text-shadow: 0 0 14px #fff, 0 0 22px var(--cp-pink) !important;
            }
            .cp-fab-save .cp-fab-icon {
                font-size: 1.15em;
                line-height: 1;
                color: var(--cp-cyan);
                text-shadow: 0 0 10px var(--cp-cyan);
            }
            .cp-fab-save .cp-fab-dot {
                width: 8px; height: 8px;
                background: var(--cp-mint);
                box-shadow: 0 0 8px var(--cp-mint);
                transform: rotate(45deg);
                margin-left: 4px;
                opacity: 0.5;
                transition: all 0.2s;
            }
            .cp-action-bar.cp-dirty .cp-fab-save {
                animation: cp-fab-dirty 1.1s ease-in-out infinite;
                color: #fff !important;
            }
            .cp-action-bar.cp-dirty .cp-fab-save .cp-fab-dot {
                background: var(--cp-pink);
                box-shadow: 0 0 12px var(--cp-pink), 0 0 24px var(--cp-pink);
                opacity: 1;
            }
            @keyframes cp-fab-dirty {
                0%, 100% {
                    box-shadow:
                        0 0 0 1px var(--cp-pink),
                        0 0 24px rgba(255,43,214,0.85),
                        0 0 60px rgba(255,43,214,0.5),
                        inset 0 0 22px rgba(255,43,214,0.45);
                    transform: scale(1);
                }
                50% {
                    box-shadow:
                        0 0 0 2px var(--cp-pink),
                        0 0 40px rgba(255,43,214,1),
                        0 0 100px rgba(255,43,214,0.7),
                        inset 0 0 30px rgba(255,43,214,0.6);
                    transform: scale(1.04);
                }
            }
            /* Secondary mini buttons - icon-first */
            .cp-action-btn {
                background: rgba(8,4,28,0.85) !important;
                border: 1px solid var(--cp-border) !important;
                color: var(--cp-cyan) !important;
                font-family: inherit !important;
                font-weight: 700 !important;
                cursor: pointer;
                width: 46px; height: 46px;
                padding: 0 !important;
                letter-spacing: 0 !important;
                font-size: 1.05rem !important;
                text-shadow: 0 0 6px var(--cp-cyan) !important;
                transition: all 0.25s ease;
                clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
                box-shadow: 0 0 10px rgba(0,240,255,0.35);
                display: inline-flex; align-items: center; justify-content: center;
                white-space: nowrap;
                position: relative;
            }
            .cp-action-btn .cp-btn-label { display: none; }
            .cp-action-btn::after {
                content: attr(data-tip);
                position: absolute;
                bottom: 100%; right: 50%;
                transform: translate(50%, -8px);
                background: rgba(8,4,28,0.95);
                color: var(--cp-cyan);
                font-size: 10px;
                letter-spacing: 0.18em;
                text-transform: uppercase;
                padding: 5px 9px;
                border: 1px solid var(--cp-border);
                opacity: 0; pointer-events: none;
                transition: opacity 0.2s;
                white-space: nowrap;
                text-shadow: 0 0 5px var(--cp-cyan);
                box-shadow: 0 0 10px rgba(0,240,255,0.4);
            }
            .cp-action-btn:hover::after { opacity: 1; }
            .cp-action-btn:hover {
                color: var(--cp-pink) !important;
                border-color: var(--cp-pink) !important;
                box-shadow: 0 0 16px rgba(255,43,214,0.55) !important;
                transform: translateY(-2px);
                text-shadow: 0 0 8px var(--cp-pink) !important;
            }
            .cp-action-btn-danger {
                color: var(--cp-red) !important;
                border-color: var(--cp-red) !important;
                text-shadow: 0 0 6px var(--cp-red) !important;
                box-shadow: 0 0 10px rgba(255,56,96,0.45) !important;
            }
            .cp-action-btn-danger:hover {
                color: #fff !important;
                box-shadow: 0 0 20px rgba(255,56,96,0.85) !important;
                transform: translateY(-2px);
            }
            .cp-action-btn-saving,
            .cp-fab-save.cp-action-btn-saving {
                opacity: 0.7;
                pointer-events: none;
                animation: cp-pulse-pink 0.9s ease-in-out infinite !important;
            }
            @keyframes cp-pulse-pink {
                0%, 100% { box-shadow: 0 0 12px rgba(255,43,214,0.45); }
                50%      { box-shadow: 0 0 36px rgba(255,43,214,0.95); }
            }
            .container { padding-bottom: 130px; }
            .cp-action-status {
                position: fixed;
                right: 22px;
                bottom: 86px;
                z-index: 99998;
                padding: 9px 16px;
                background: rgba(8,4,28,0.95);
                border: 1px solid var(--cp-mint);
                color: var(--cp-mint);
                font-size: 0.78rem;
                letter-spacing: 0.16em;
                text-transform: uppercase;
                text-shadow: 0 0 6px var(--cp-mint);
                box-shadow: 0 0 14px rgba(0,255,157,0.45);
                clip-path: polygon(6px 0, 100% 0, 100% calc(100% - 6px), calc(100% - 6px) 100%, 0 100%, 0 6px);
                opacity: 0;
                transform: translateY(8px);
                transition: opacity 0.25s, transform 0.25s;
                pointer-events: none;
                white-space: nowrap;
                max-width: calc(100vw - 44px);
                overflow: hidden; text-overflow: ellipsis;
            }
            .cp-action-status.cp-show { opacity: 1; transform: translateY(0); }
            .cp-action-status.cp-err {
                border-color: var(--cp-red);
                color: var(--cp-red);
                text-shadow: 0 0 6px var(--cp-red);
                box-shadow: 0 0 14px rgba(255,56,96,0.55);
            }
            /* Toast notification stack (top-right) */
            .cp-toast-stack {
                position: fixed;
                top: 88px;
                right: 22px;
                z-index: 100000;
                display: flex;
                flex-direction: column;
                gap: 10px;
                max-width: min(420px, calc(100vw - 32px));
                pointer-events: none;
            }
            .cp-toast {
                position: relative;
                display: flex;
                align-items: flex-start;
                gap: 12px;
                padding: 12px 16px 12px 14px;
                background: linear-gradient(135deg, rgba(8,4,28,0.96) 0%, rgba(20,5,50,0.92) 100%);
                border: 1px solid var(--cp-mint);
                color: var(--cp-mint);
                font-size: 0.82rem;
                line-height: 1.45;
                letter-spacing: 0.06em;
                text-shadow: 0 0 6px var(--cp-mint);
                box-shadow:
                    0 0 0 1px rgba(0,255,157,0.25),
                    0 0 18px rgba(0,255,157,0.45),
                    0 8px 28px rgba(0,0,0,0.55);
                backdrop-filter: blur(8px);
                clip-path: polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px);
                transform: translateX(120%);
                opacity: 0;
                transition: transform 0.35s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.25s;
                pointer-events: auto;
                overflow: hidden;
                word-break: break-all;
            }
            .cp-toast.cp-show { transform: translateX(0); opacity: 1; }
            .cp-toast.cp-hide { transform: translateX(120%); opacity: 0; }
            .cp-toast::before {
                content: "";
                position: absolute;
                left: 0; top: 0; bottom: 0;
                width: 3px;
                background: var(--cp-mint);
                box-shadow: 0 0 10px var(--cp-mint);
            }
            .cp-toast-icon {
                font-size: 1.1rem;
                line-height: 1;
                margin-top: 1px;
                flex-shrink: 0;
                color: var(--cp-mint);
                text-shadow: 0 0 8px var(--cp-mint);
            }
            .cp-toast-body { flex: 1; min-width: 0; }
            .cp-toast-title {
                font-size: 0.72rem;
                font-weight: 800;
                letter-spacing: 0.22em;
                text-transform: uppercase;
                opacity: 0.85;
                margin-bottom: 2px;
            }
            .cp-toast-msg { white-space: pre-wrap; }
            .cp-toast-close {
                position: absolute;
                top: 6px; right: 8px;
                background: transparent;
                border: 0;
                color: inherit;
                font-size: 14px;
                cursor: pointer;
                opacity: 0.55;
                padding: 2px 4px;
                line-height: 1;
                transition: opacity 0.2s;
            }
            .cp-toast-close:hover { opacity: 1; }
            .cp-toast::after {
                content: "";
                position: absolute;
                left: 0; bottom: 0;
                height: 2px;
                width: 100%;
                background: linear-gradient(90deg, var(--cp-mint), transparent);
                box-shadow: 0 0 6px var(--cp-mint);
                transform-origin: left;
                animation: cp-toast-bar var(--cp-toast-dur, 3200ms) linear forwards;
            }
            @keyframes cp-toast-bar {
                from { transform: scaleX(1); }
                to   { transform: scaleX(0); }
            }
            .cp-toast.cp-toast-success { border-color: var(--cp-mint); color: var(--cp-mint); text-shadow: 0 0 6px var(--cp-mint); }
            .cp-toast.cp-toast-success::before,
            .cp-toast.cp-toast-success::after { background: var(--cp-mint); box-shadow: 0 0 10px var(--cp-mint); }
            .cp-toast.cp-toast-success .cp-toast-icon { color: var(--cp-mint); text-shadow: 0 0 8px var(--cp-mint); }
            .cp-toast.cp-toast-info { border-color: var(--cp-cyan); color: var(--cp-cyan); text-shadow: 0 0 6px var(--cp-cyan); box-shadow: 0 0 0 1px rgba(0,240,255,0.25), 0 0 18px rgba(0,240,255,0.45), 0 8px 28px rgba(0,0,0,0.55); }
            .cp-toast.cp-toast-info::before,
            .cp-toast.cp-toast-info::after { background: var(--cp-cyan); box-shadow: 0 0 10px var(--cp-cyan); }
            .cp-toast.cp-toast-info .cp-toast-icon { color: var(--cp-cyan); text-shadow: 0 0 8px var(--cp-cyan); }
            .cp-toast.cp-toast-warn { border-color: var(--cp-amber); color: var(--cp-amber); text-shadow: 0 0 6px var(--cp-amber); box-shadow: 0 0 0 1px rgba(255,176,46,0.25), 0 0 18px rgba(255,176,46,0.45), 0 8px 28px rgba(0,0,0,0.55); }
            .cp-toast.cp-toast-warn::before,
            .cp-toast.cp-toast-warn::after { background: var(--cp-amber); box-shadow: 0 0 10px var(--cp-amber); }
            .cp-toast.cp-toast-warn .cp-toast-icon { color: var(--cp-amber); text-shadow: 0 0 8px var(--cp-amber); }
            .cp-toast.cp-toast-error { border-color: var(--cp-red); color: var(--cp-red); text-shadow: 0 0 6px var(--cp-red); box-shadow: 0 0 0 1px rgba(255,56,96,0.30), 0 0 18px rgba(255,56,96,0.55), 0 8px 28px rgba(0,0,0,0.55); }
            .cp-toast.cp-toast-error::before,
            .cp-toast.cp-toast-error::after { background: var(--cp-red); box-shadow: 0 0 10px var(--cp-red); }
            .cp-toast.cp-toast-error .cp-toast-icon { color: var(--cp-red); text-shadow: 0 0 8px var(--cp-red); }

            /* Tiny floating "unsaved" badge on the FAB */
            .cp-action-bar.cp-dirty::before {
                content: "● UNSAVED";
                position: absolute;
                top: -22px; right: 6px;
                font-size: 9px;
                letter-spacing: 0.3em;
                color: var(--cp-pink);
                text-shadow: 0 0 6px var(--cp-pink);
                background: rgba(8,4,28,0.92);
                padding: 3px 8px;
                border: 1px solid var(--cp-pink);
                box-shadow: 0 0 10px rgba(255,43,214,0.6);
                animation: cp-pulse-pink 1.6s ease-in-out infinite;
            }

            @media (max-width: 720px) {
                .container { padding: 100px 14px 140px; }
                .card { padding: 22px 18px; }
                .header { padding: 22px 18px; }
                .title { font-size: 2rem; }
                .cp-hud { font-size: 9px; }
                .cp-action-bar {
                    right: 50%;
                    bottom: 14px;
                    transform: translateX(50%);
                    gap: 8px;
                }
                .cp-fab-save {
                    min-width: 0;
                    padding: 13px 18px !important;
                    font-size: 0.8rem !important;
                    letter-spacing: 0.16em !important;
                }
                .cp-action-btn { width: 42px; height: 42px; }
                .cp-action-status { right: 50%; transform: translate(50%, 8px); }
                .cp-action-status.cp-show { transform: translate(50%, 0); }
            }
        </style>
    </head>
    <body>
        <div class="matrix-bg"></div>
        <div class="matrix-code-rain" id="matrixCodeRain"></div>
            <div class="cp-hud">
                <span class="cp-hud-line"><span class="cp-hud-label">SYS::</span> ${t.terminal}</span>
                <span class="cp-hud-line"><span class="cp-hud-label">NODE::</span> NIGHT_CITY</span>
                <span class="cp-hud-line"><span class="cp-hud-label">LINK::</span> SECURE / ENC</span>
            </div>
            <div class="cp-lang-wrapper">
                <span class="cp-lang-tag">LANG_</span>
                <select id="languageSelector" onchange="changeLanguage(this.value)">
                    <option value="zh" ${!isFarsi ? 'selected' : ''}>🇨🇳 中文</option>
                    <option value="fa" ${isFarsi ? 'selected' : ''}>🇮🇷 فارسی</option>
                </select>
            </div>
            <button type="button" id="cpFxToggle" class="cp-fx-toggle" onclick="cpToggleFx()" title="${isFarsi ? 'تغییر افکت‌های صفحه' : '切换页面特效'}" aria-label="FX toggle">
                <span class="cp-fx-dot" aria-hidden="true"></span>
                <span id="cpFxLabel">FX: ON</span>
            </button>
        <div class="container">
            <div class="header">
                    <h1 class="title cp-glitch" data-text="${t.title}">${t.title}</h1>
                    <p class="subtitle">${t.subtitle}</p>
            </div>
            <div class="card">
                    <h2 class="card-title">${t.selectClient}</h2>
                <div class="client-grid">
                    <button class="client-btn" onclick="generateClientLink(atob('Y2xhc2g='), 'CLASH')">CLASH</button>
                    <button class="client-btn" onclick="generateClientLink(atob('Y2xhc2g='), 'STASH')">STASH</button>
                    <button class="client-btn" onclick="generateClientLink(atob('c3VyZ2U='), 'SURGE')">SURGE</button>
                    <button class="client-btn" onclick="generateClientLink(atob('c2luZ2JveA=='), 'SING-BOX')">SING-BOX</button>
                    <button class="client-btn" onclick="generateClientLink(atob('bG9vbg=='), 'LOON')">LOON</button>
                    <button class="client-btn" onclick="generateClientLink(atob('cXVhbng='), 'QUANTUMULT X')">QUANTUMULT X</button>
                    <button class="client-btn" onclick="generateClientLink(atob('djJyYXk='), 'V2RAY')">V2RAY</button>
                    <button class="client-btn" onclick="generateClientLink(atob('djJyYXk='), 'V2RAYNG')">V2RAYNG</button>
                    <button class="client-btn" onclick="generateClientLink(atob('djJyYXk='), 'NEKORAY')">NEKORAY</button>
                    <button class="client-btn" onclick="generateClientLink(atob('djJyYXk='), 'Shadowrocket')">Shadowrocket</button>
                </div>
                <div class=atob('c3Vic2NyaXB0aW9uLXVybA==') id="clientSubscriptionUrl"></div>
            </div>
            <div class="card">
                    <h2 class="card-title">${t.systemStatus}</h2>
                <div id="systemStatus" style="margin: 20px 0; padding: 15px; background: rgba(8, 4, 28, 0.8); border: 2px solid #00f0ff; box-shadow: 0 0 20px rgba(0, 240, 255, 0.3), inset 0 0 15px rgba(0, 240, 255, 0.1); position: relative; overflow: hidden;">
                        <div style="color: #00f0ff; margin-bottom: 15px; font-weight: bold; text-shadow: 0 0 5px #00f0ff;">[ ${t.checking} ]</div>
                        <div id="regionStatus" style="margin: 8px 0; color: #00f0ff; font-family: 'Courier New', monospace; text-shadow: 0 0 3px #00f0ff;">${t.workerRegion}${t.checking}</div>
                        <div id="geoInfo" style="margin: 8px 0; color: #7aa9c4; font-family: 'Courier New', monospace; font-size: 0.9rem; text-shadow: 0 0 3px #7aa9c4;">${t.detectionMethod}${t.checking}</div>
                        <div id="backupStatus" style="margin: 8px 0; color: #00f0ff; font-family: 'Courier New', monospace; text-shadow: 0 0 3px #00f0ff;">${t.proxyIPStatus}${t.checking}</div>
                        <div id="currentIP" style="margin: 8px 0; color: #00f0ff; font-family: 'Courier New', monospace; text-shadow: 0 0 3px #00f0ff;">${t.currentIP}${t.checking}</div>
                        <div id="echStatus" style="margin: 8px 0; color: #00f0ff; font-family: 'Courier New', monospace; text-shadow: 0 0 3px #00f0ff; font-size: 0.9rem;">ECH状态: ${t.checking}</div>
                        <div id="regionMatch" style="margin: 8px 0; color: #00f0ff; font-family: 'Courier New', monospace; text-shadow: 0 0 3px #00f0ff;">${t.regionMatch}${t.checking}</div>
                        <div id="selectionLogic" style="margin: 8px 0; color: #7aa9c4; font-family: 'Courier New', monospace; font-size: 0.9rem; text-shadow: 0 0 3px #7aa9c4;">${t.selectionLogic}${t.selectionLogicText}</div>
                </div>
            </div>
            <div class="card" id="configCard" style="display: none;">
                    <h2 class="card-title">${t.configManagement}</h2>
                <div id="kvStatus" style="margin-bottom: 20px; padding: 10px; background: rgba(8, 4, 28, 0.8); border: 1px solid #00f0ff; color: #00f0ff;">
                    ${t.kvStatusChecking}
                </div>
                <div id="configContent" style="display: none;">
                    <form id="regionForm" style="margin-bottom: 20px;">
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.specifyRegion}</label>
                            <select id="wkRegion" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.autoDetect}</option>
                                    <option value="HK">${t.regionNames.HK}</option>
                                    <option value="US">${t.regionNames.US}</option>
                                    <option value="SG">${t.regionNames.SG}</option>
                                    <option value="JP">${t.regionNames.JP}</option>
                                    <option value="KR">${t.regionNames.KR}</option>
                                    <option value="DE">${t.regionNames.DE}</option>
                                    <option value="SE">${t.regionNames.SE}</option>
                                    <option value="NL">${t.regionNames.NL}</option>
                                    <option value="FI">${t.regionNames.FI}</option>
                                    <option value="GB">${t.regionNames.GB}</option>
                            </select>
                                <small id="wkRegionHint" style="color: #7aa9c4; font-size: 0.85rem; display: none;">⚠️ ${t.customIPDisabledHint}</small>
                        </div>
                    </form>
                    <form id="otherConfigForm" style="margin-bottom: 20px;">
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.protocolSelection}</label>
                            <div style="padding: 15px; background: rgba(15, 3, 40, 0.6); border: 1px solid #00f0ff; border-radius: 5px;">
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                        <input type="checkbox" id="ev" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enableVLESS}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                        <input type="checkbox" id="et" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enableTrojan}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                        <input type="checkbox" id="ex" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enableXhttp}</span>
                                    </label>
                                </div>
                                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(0, 240, 255, 0.3);">
                                    <div style="margin-bottom: 10px;">
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                            <input type="checkbox" id="ech" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                                <span style="font-size: 1.1rem;">${t.enableECH}</span>
                                        </label>
                                        <small style="color: #7aa9c4; font-size: 0.8rem; display: block; margin-top: 5px; margin-left: 26px;">${t.enableECHHint}</small>
                                    </div>
                                    <div style="margin-top: 15px; margin-bottom: 10px;">
                                        <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-size: 0.95rem;">${t.customDNS}</label>
                                        <input type="text" id="customDNS" placeholder="${t.customDNSPlaceholder}" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px;">
                                        <small style="color: #7aa9c4; font-size: 0.8rem; display: block; margin-top: 5px;">${t.customDNSHint}</small>
                                    </div>
                                    <div style="margin-bottom: 10px;">
                                        <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-size: 0.95rem;">${t.customECHDomain}</label>
                                        <input type="text" id="customECHDomain" placeholder="${t.customECHDomainPlaceholder}" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px;">
                                        <small style="color: #7aa9c4; font-size: 0.8rem; display: block; margin-top: 5px;">${t.customECHDomainHint}</small>
                                    </div>
                                    <div style="margin-bottom: 10px;">
                                        <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-size: 0.95rem;">${t.alpn}</label>
                                        <select id="alpn" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px;">
                                            <option value="">${t.alpnDefault}</option>
                                            <option value="h3">h3</option>
                                            <option value="h2">h2</option>
                                            <option value="http/1.1">http/1.1</option>
                                            <option value="h3,h2">h3,h2</option>
                                            <option value="h2,http/1.1">h2,http/1.1</option>
                                            <option value="h3,h2,http/1.1">h3,h2,http/1.1</option>
                                        </select>
                                        <small style="color: #7aa9c4; font-size: 0.8rem; display: block; margin-top: 5px;">${t.alpnHint}</small>
                                    </div>
                                </div>
                                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(0, 240, 255, 0.3);">
                                        <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-size: 0.95rem;">${t.trojanPassword}</label>
                                        <input type="text" id="tp" placeholder="${t.trojanPasswordPlaceholder}" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px;">
                                        <small style="color: #7aa9c4; font-size: 0.8rem; display: block; margin-top: 5px;">${t.trojanPasswordHint}</small>
                                </div>
                                    <small style="color: #7aa9c4; font-size: 0.85rem; display: block; margin-top: 10px;">${t.protocolHint}</small>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.customHomepage}</label>
                                <input type="text" id="customHomepage" placeholder="${t.customHomepagePlaceholder}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${t.customHomepageHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.customPath}</label>
                                <input type="text" id="customPath" placeholder="${isFarsi ? 'مثال: /mypath یا خالی بگذارید تا از UUID استفاده شود' : '例如: /mypath 或留空使用 UUID'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${isFarsi ? 'مسیر اشتراک سفارشی. اگر خالی بگذارید از UUID به عنوان مسیر استفاده می‌شود.' : '自定义订阅路径。留空则使用 UUID 作为路径。'}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.customIP}</label>
                                <input type="text" id="customIP" placeholder="${isFarsi ? 'مثال: 1.2.3.4:443' : '例如: 1.2.3.4:443'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${isFarsi ? 'آدرس و پورت ProxyIP سفارشی' : '自定义ProxyIP地址和端口'}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.preferredIPs}</label>
                                <input type="text" id="yx" placeholder="${isFarsi ? 'مثال: 1.2.3.4:443#گره هنگ‌کنگ,5.6.7.8:80#گره آمریکا,example.com:8443#گره سنگاپور' : '例如: 1.2.3.4:443#日本节点,5.6.7.8:80#美国节点,example.com:8443#新加坡节点'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${isFarsi ? 'فرمت: IP:پورت#نام گره یا IP:پورت (بدون # از نام پیش‌فرض استفاده می‌شود). پشتیبانی از چندین مورد، با کاما جدا می‌شوند. <span style="color: #ffb400;">IP های اضافه شده از طریق API به طور خودکار در اینجا نمایش داده می‌شوند.</span>' : '格式: IP:端口#节点名称 或 IP:端口 (无#则使用默认名称)。支持多个，用逗号分隔。<span style="color: #ffb400;">API添加的IP会自动显示在这里。</span>'}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.preferredIPsURL}</label>
                                <input type="text" id="yxURL" placeholder="${isFarsi ? 'URL منبع لیست IP ترجیحی را وارد کنید' : '输入优选IP列表来源URL'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${isFarsi ? 'URL منبع لیست IP ترجیحی سفارشی، اگر خالی بگذارید از آدرس پیش‌فرض استفاده می‌شود' : '自定义优选IP列表来源URL，留空则使用默认地址'}</small>
                        </div>
                        
                        <div style="margin-bottom: 20px; padding: 15px; background: rgba(20, 5, 50, 0.6); border: 2px solid #7aa9c4; border-radius: 8px;">
                            <h4 style="color: #00f0ff; margin: 0 0 15px 0; font-size: 1.1rem; text-shadow: 0 0 5px #00f0ff;">⚡ ${t.latencyTest}</h4>
                            <div style="display: flex; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; align-items: center;">
                                <div style="min-width: 120px;">
                                    <label style="display: block; margin-bottom: 5px; color: #00f0ff; font-size: 0.9rem;">${t.ipSource}</label>
                                    <select id="ipSourceSelect" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px; cursor: pointer;">
                                        <option value="manual">${t.manualInput}</option>
                                        <option value="cfRandom">${t.cfRandomIP}</option>
                                        <option value="urlFetch">${t.urlFetch}</option>
                                    </select>
                                </div>
                                <div style="width: 100px;">
                                    <label style="display: block; margin-bottom: 5px; color: #00f0ff; font-size: 0.9rem;">${t.latencyTestPort}</label>
                                    <input type="number" id="latencyTestPort" value="443" min="1" max="65535" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px;">
                                </div>
                                <div id="randomCountDiv" style="width: 100px; display: none;">
                                    <label style="display: block; margin-bottom: 5px; color: #00f0ff; font-size: 0.9rem;">${t.randomCount}</label>
                                    <input type="number" id="randomIPCount" value="20" min="1" max="100" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px;">
                                </div>
                                <div style="width: 80px;">
                                    <label style="display: block; margin-bottom: 5px; color: #00f0ff; font-size: 0.9rem;">${isFarsi ? 'رشته‌ها' : '线程'}</label>
                                    <input type="number" id="testThreads" value="5" min="1" max="50" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px;">
                                </div>
                            </div>
                            <div id="manualInputDiv" style="margin-bottom: 10px;">
                                <label style="display: block; margin-bottom: 5px; color: #00f0ff; font-size: 0.9rem;">${t.latencyTestIP}</label>
                                <input type="text" id="latencyTestInput" placeholder="${t.latencyTestIPPlaceholder}" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px;">
                            </div>
                            <div id="urlFetchDiv" style="margin-bottom: 10px; display: none;">
                                <label style="display: block; margin-bottom: 5px; color: #00f0ff; font-size: 0.9rem;">${t.fetchURL}</label>
                                <div style="display: flex; gap: 8px;">
                                    <input type="text" id="fetchURLInput" placeholder="${t.fetchURLPlaceholder}" style="flex: 1; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 13px;">
                                    <button type="button" id="fetchIPBtn" style="background: rgba(0, 200, 255, 0.2); border: 1px solid #00aaff; padding: 8px 16px; color: #00aaff; font-family: 'Courier New', monospace; cursor: pointer; white-space: nowrap;">⬇ ${t.fetchIP}</button>
                                </div>
                            </div>
                            <div id="cfRandomDiv" style="margin-bottom: 10px; display: none;">
                                <button type="button" id="generateCFIPBtn" style="background: rgba(0, 240, 255, 0.15); border: 1px solid #00f0ff; padding: 10px 20px; color: #00f0ff; font-family: 'Courier New', monospace; cursor: pointer; width: 100%; transition: all 0.3s;">🎲 ${t.generateIP}</button>
                            </div>
                            <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                                <button type="button" id="startLatencyTest" style="background: rgba(0, 240, 255, 0.2); border: 1px solid #00f0ff; padding: 8px 16px; color: #00f0ff; font-family: 'Courier New', monospace; cursor: pointer; transition: all 0.3s;">▶ ${t.startTest}</button>
                                <button type="button" id="stopLatencyTest" style="background: rgba(255, 0, 0, 0.2); border: 1px solid #ff3860; padding: 8px 16px; color: #ff3860; font-family: 'Courier New', monospace; cursor: pointer; display: none; transition: all 0.3s;">⏹ ${t.stopTest}</button>
                            </div>
                            <div id="latencyTestStatus" style="color: #7aa9c4; font-size: 0.9rem; margin-bottom: 10px; display: none;"></div>
                            <div id="latencyTestResults" style="max-height: 250px; overflow-y: auto; display: none;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                                    <span style="color: #00f0ff; font-weight: bold;">${t.testResult}</span>
                                    <div style="display: flex; gap: 8px;">
                                        <button type="button" id="selectAllResults" style="background: transparent; border: 1px solid #7aa9c4; padding: 4px 10px; color: #7aa9c4; font-size: 0.8rem; cursor: pointer;">${t.selectAll}</button>
                                        <button type="button" id="deselectAllResults" style="background: transparent; border: 1px solid #7aa9c4; padding: 4px 10px; color: #7aa9c4; font-size: 0.8rem; cursor: pointer;">${t.deselectAll}</button>
                                    </div>
                                </div>
                                <div id="cityFilterContainer" style="margin-bottom: 10px; padding: 10px; background: rgba(15, 3, 40, 0.6); border: 1px solid #7aa9c4; border-radius: 4px; display: none;">
                                    <div style="margin-bottom: 8px;">
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff; font-size: 0.9rem;">
                                            <input type="radio" name="cityFilterMode" value="all" checked style="margin-right: 6px; width: 16px; height: 16px; cursor: pointer;">
                                            <span>${isFarsi ? '全部城市' : '全部城市'}</span>
                                        </label>
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff; font-size: 0.9rem; margin-left: 15px;">
                                            <input type="radio" name="cityFilterMode" value="fastest10" style="margin-right: 6px; width: 16px; height: 16px; cursor: pointer;">
                                            <span>${isFarsi ? '只选择最快的10个' : '只选择最快的10个'}</span>
                                        </label>
                                    </div>
                                    <div id="cityCheckboxesContainer" style="display: flex; flex-wrap: wrap; gap: 8px; max-height: 80px; overflow-y: auto; padding: 5px;"></div>
                                </div>
                                <div id="latencyResultsList" style="background: rgba(0, 0, 0, 0.5); border: 1px solid #004400; border-radius: 4px; padding: 10px;"></div>
                                <div style="margin-top: 10px; display: flex; gap: 10px;">
                                    <button type="button" id="overwriteSelectedToYx" style="flex: 1; background: rgba(0, 220, 130, 0.3); border: 1px solid #00f0ff; padding: 10px 20px; color: #00f0ff; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; transition: all 0.3s;">${isFarsi ? '覆盖添加' : '覆盖添加'}</button>
                                    <button type="button" id="appendSelectedToYx" style="flex: 1; background: rgba(0, 178, 110, 0.3); border: 1px solid #7aa9c4; padding: 10px 20px; color: #7aa9c4; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; transition: all 0.3s;">${isFarsi ? '追加添加' : '追加添加'}</button>
                                </div>
                            </div>
                        </div>

                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.socks5Config}</label>
                                <input type="text" id="socksConfig" placeholder="${isFarsi ? 'مثال: user:pass@host:port یا host:port' : '例如: user:pass@host:port 或 host:port'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${isFarsi ? 'آدرس پروکسی SOCKS5، برای انتقال تمام ترافیک خروجی استفاده می‌شود' : 'SOCKS5代理地址，用于转发所有出站流量'}</small>
                        </div>
                    </form>

                    <h3 style="color: #00f0ff; margin: 20px 0 15px 0; font-size: 1.2rem;">${t.advancedControl}</h3>
                    <form id="advancedConfigForm" style="margin-bottom: 20px;">
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.subscriptionConverter}</label>
                                <input type="text" id="scu" placeholder="${t.subscriptionConverterPlaceholder}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${t.subscriptionConverterHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.builtinPreferred}</label>
                            <div style="padding: 15px; background: rgba(15, 3, 40, 0.6); border: 1px solid #00f0ff; border-radius: 5px;">
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                        <input type="checkbox" id="ena" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enableNativeAddress}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                        <input type="checkbox" id="epd" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enablePreferredDomain}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                        <input type="checkbox" id="epi" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enablePreferredIP}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                        <input type="checkbox" id="egi" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enableGitHubPreferred}</span>
                                    </label>
                                </div>
                                    <small style="color: #7aa9c4; font-size: 0.85rem; display: block; margin-top: 10px;">${t.builtinPreferredHint}</small>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">优选IP筛选设置</label>
                            <div style="padding: 15px; background: rgba(15, 3, 40, 0.6); border: 1px solid #00f0ff; border-radius: 5px;">
                                <div style="margin-bottom: 15px;">
                                    <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">IP版本选择</label>
                                    <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                            <input type="checkbox" id="ipv4Enabled" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">IPv4</span>
                                        </label>
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                            <input type="checkbox" id="ipv6Enabled" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">IPv6</span>
                                        </label>
                                    </div>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">运营商选择</label>
                                    <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                            <input type="checkbox" id="ispMobile" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">移动</span>
                                        </label>
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                            <input type="checkbox" id="ispUnicom" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">联通</span>
                                        </label>
                                        <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff;">
                                            <input type="checkbox" id="ispTelecom" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1rem;">电信</span>
                                        </label>
                                    </div>
                                </div>
                                    <small style="color: #7aa9c4; font-size: 0.85rem; display: block; margin-top: 10px;">选择要使用的IP版本和运营商，未选中的将被过滤</small>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.allowAPIManagement}</label>
                            <select id="apiEnabled" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.apiEnabledDefault}</option>
                                    <option value="yes">${t.apiEnabledYes}</option>
                            </select>
                                <small style="color: #ffb400; font-size: 0.85rem;">${t.apiEnabledHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.regionMatching}</label>
                            <select id="regionMatching" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.regionMatchingDefault}</option>
                                    <option value="no">${t.regionMatchingNo}</option>
                            </select>
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${t.regionMatchingHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.downgradeControl}</label>
                            <select id="downgradeControl" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.downgradeControlDefault}</option>
                                    <option value="no">${t.downgradeControlNo}</option>
                            </select>
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${t.downgradeControlHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.tlsControl}</label>
                            <select id="portControl" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.tlsControlDefault}</option>
                                    <option value="yes">${t.tlsControlYes}</option>
                            </select>
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${t.tlsControlHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00f0ff; font-weight: bold; text-shadow: 0 0 3px #00f0ff;">${t.preferredControl}</label>
                            <select id="preferredControl" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00f0ff; color: #00f0ff; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.preferredControlDefault}</option>
                                    <option value="yes">${t.preferredControlYes}</option>
                            </select>
                                <small style="color: #7aa9c4; font-size: 0.85rem;">${t.preferredControlHint}</small>
                        </div>
                    </form>
                    <div id="currentConfig" style="background: rgba(0, 0, 0, 0.9); border: 1px solid #00f0ff; padding: 15px; margin: 10px 0; font-family: 'Courier New', monospace; color: #00f0ff;">
                            ${t.loading}
                    </div>
                    <div id="pathTypeInfo" style="background: rgba(15, 3, 40, 0.7); border: 1px solid #00f0ff; padding: 15px; margin: 10px 0; font-family: 'Courier New', monospace; color: #00f0ff;">
                            <div style="font-weight: bold; margin-bottom: 8px; color: #00ff9d; text-shadow: 0 0 5px #00ff9d;">${t.currentConfig}</div>
                            <div id="pathTypeStatus">${t.checking}</div>
                    </div>
                </div>
                <div id="statusMessage" style="display: none; padding: 10px; margin: 10px 0; border: 1px solid #00f0ff; background: rgba(8, 4, 28, 0.8); color: #00f0ff; text-shadow: 0 0 5px #00f0ff;"></div>
            </div>
            
            <div class="card">
                    <h2 class="card-title">${t.relatedLinks}</h2>
                <div style="text-align: center; margin: 20px 0;">
                        <a href="https://github.com/byJoey/cfnew" target="_blank" style="color: #00f0ff; text-decoration: none; margin: 0 20px; font-size: 1.2rem; text-shadow: 0 0 5px #00f0ff;">${t.githubProject}</a>
                    <a href="https://www.youtube.com/@joeyblog" target="_blank" style="color: #00f0ff; text-decoration: none; margin: 0 20px; font-size: 1.2rem; text-shadow: 0 0 5px #00f0ff;">YouTube @joeyblog</a>
                </div>
            </div>
        </div>
        <div id="cpToastStack" class="cp-toast-stack" aria-live="polite" aria-atomic="false"></div>
        <div id="cpActionStatus" class="cp-action-status" role="status" aria-live="polite"></div>
        <div id="cpActionBar" class="cp-action-bar" role="toolbar" aria-label="${t.configManagement}">
            <button type="button" id="cpBtnSaveAll" class="cp-fab-save" title="${isFarsi ? 'ذخیره همه تنظیمات' : '保存所有配置 (Ctrl+S)'}">
                <span class="cp-fab-icon">▣</span>
                <span>${isFarsi ? 'ذخیره همه' : '保 存 全 部'}</span>
                <span class="cp-fab-dot" aria-hidden="true"></span>
            </button>
            <button type="button" id="cpBtnRefresh" class="cp-action-btn" data-tip="${t.refreshConfig}" aria-label="${t.refreshConfig}">
                <span aria-hidden="true">↻</span>
                <span class="cp-btn-label">${t.refreshConfig}</span>
            </button>
            <button type="button" id="cpBtnReset" class="cp-action-btn cp-action-btn-danger" data-tip="${t.resetConfig}" aria-label="${t.resetConfig}">
                <span aria-hidden="true">⌫</span>
                <span class="cp-btn-label">${t.resetConfig}</span>
            </button>
        </div>
        <script>
            // 订阅转换地址（从服务器配置注入）
            var SUB_CONVERTER_URL = "${ scu }";
            // 远程配置URL（硬编码）
            var REMOTE_CONFIG_URL = "${ remoteConfigUrl }";

            // 翻译对象
            const translations = {
                zh: {
                    subscriptionCopied: '订阅链接已复制',
                    autoSubscriptionCopied: '自动识别订阅链接已复制，客户端访问时会根据User-Agent自动识别并返回对应格式'
                },
                fa: {
                    subscriptionCopied: 'لینک اشتراک کپی شد',
                    autoSubscriptionCopied: 'لینک اشتراک تشخیص خودکار کپی شد، کلاینت هنگام دسترسی بر اساس User-Agent به طور خودکار تشخیص داده و قالب مربوطه را برمی‌گرداند'
                }
            };

            function getCookie(name) {
                const value = '; ' + document.cookie;
                const parts = value.split('; ' + name + '=');
                if (parts.length === 2) return parts.pop().split(';').shift();
                return null;
            }

            const browserLang = navigator.language || navigator.userLanguage || '';
            const savedLang = localStorage.getItem('preferredLanguage') || getCookie('preferredLanguage');
            let isFarsi = false;
                
            if (savedLang === 'fa' || savedLang === 'fa-IR') {
                isFarsi = true;
            } else if (savedLang === 'zh' || savedLang === 'zh-CN') {
                isFarsi = false;
            } else {
                isFarsi = browserLang.includes('fa') || browserLang.includes('fa-IR');
            }

            const t = translations[isFarsi ? 'fa' : 'zh'];

            function changeLanguage(lang) {
                localStorage.setItem('preferredLanguage', lang);
                // 设置Cookie（有效期1年）
                const expiryDate = new Date();
                expiryDate.setFullYear(expiryDate.getFullYear() + 1);
                document.cookie = 'preferredLanguage=' + lang + '; path=/; expires=' + expiryDate.toUTCString() + '; SameSite=Lax';
                // 刷新页面，不使用URL参数
                 window.location.reload();
            }

            // 页面加载时检查 localStorage 和 Cookie，并清理URL参数
            window.addEventListener('DOMContentLoaded', function() {
                const savedLang = localStorage.getItem('preferredLanguage') || getCookie('preferredLanguage');
                const urlParams = new URLSearchParams(window.location.search);
                const urlLang = urlParams.get('lang');

                // 如果URL中有语言参数，移除它并设置Cookie
                if (urlLang) {
                    const currentUrl = new URL(window.location.href);
                    currentUrl.searchParams.delete('lang');
                    const newUrl = currentUrl.toString();

                    // 设置Cookie
                    const expiryDate = new Date();
                    expiryDate.setFullYear(expiryDate.getFullYear() + 1);
                    document.cookie = 'preferredLanguage=' + urlLang + '; path=/; expires=' + expiryDate.toUTCString() + '; SameSite=Lax';
                    localStorage.setItem('preferredLanguage', urlLang);

                    // 使用history API移除URL参数，不刷新页面
                    window.history.replaceState({}, '', newUrl);
                } else if (savedLang) {
                    // 如果localStorage中有但Cookie中没有，同步到Cookie
                    const expiryDate = new Date();
                    expiryDate.setFullYear(expiryDate.getFullYear() + 1);
                     document.cookie = 'preferredLanguage=' + savedLang + '; path=/; expires=' + expiryDate.toUTCString() + '; SameSite=Lax';
                }
            });

            // 赛博朋克风 toast 通知 (替代 alert)
            window.cpToast = function(message, type, options) {
                options = options || {};
                var stack = document.getElementById('cpToastStack');
                if (!stack) return;
                var typeMap = { success: '✓', info: '⌬', warn: '⚠', error: '✕' };
                var titleMap = { success: 'SUCCESS', info: 'INFO', warn: 'WARN', error: 'ERROR' };
                type = typeMap[type] ? type : 'success';
                var duration = options.duration || 3200;
                var toast = document.createElement('div');
                toast.className = 'cp-toast cp-toast-' + type;
                toast.style.setProperty('--cp-toast-dur', duration + 'ms');
                var icon = document.createElement('span');
                icon.className = 'cp-toast-icon';
                icon.textContent = typeMap[type];
                var body = document.createElement('div');
                body.className = 'cp-toast-body';
                var title = document.createElement('div');
                title.className = 'cp-toast-title';
                title.textContent = options.title || titleMap[type];
                var msg = document.createElement('div');
                msg.className = 'cp-toast-msg';
                msg.textContent = String(message == null ? '' : message);
                body.appendChild(title);
                body.appendChild(msg);
                var close = document.createElement('button');
                close.type = 'button';
                close.className = 'cp-toast-close';
                close.setAttribute('aria-label', 'close');
                close.textContent = '✕';
                toast.appendChild(icon);
                toast.appendChild(body);
                toast.appendChild(close);
                stack.appendChild(toast);
                requestAnimationFrame(function() { toast.classList.add('cp-show'); });
                var dismissed = false;
                function dismiss() {
                    if (dismissed) return;
                    dismissed = true;
                    toast.classList.remove('cp-show');
                    toast.classList.add('cp-hide');
                    setTimeout(function() {
                        if (toast.parentNode) toast.parentNode.removeChild(toast);
                    }, 400);
                }
                close.addEventListener('click', dismiss);
                var timer = setTimeout(dismiss, duration);
                toast.addEventListener('mouseenter', function() { clearTimeout(timer); });
                toast.addEventListener('mouseleave', function() { timer = setTimeout(dismiss, 1200); });
                return { dismiss: dismiss, element: toast };
            };

            function tryOpenApp(schemeUrl, fallbackCallback, timeout) {
                timeout = timeout || 2500;
                var appOpened = false;
                var callbackExecuted = false;
                var startTime = Date.now();

                var blurHandler = function() {
                    var elapsed = Date.now() - startTime;
                    if (elapsed < 3000 && !callbackExecuted) {
                        appOpened = true;
                    }
                };

                window.addEventListener('blur', blurHandler);

                var hiddenHandler = function() {
                    var elapsed = Date.now() - startTime;
                    if (elapsed < 3000 && !callbackExecuted) {
                        appOpened = true;
                    }
                };

                document.addEventListener('visibilitychange', hiddenHandler);

                var iframe = document.createElement('iframe');
                iframe.style.display = 'none';
                iframe.style.width = '1px';
                iframe.style.height = '1px';
                iframe.src = schemeUrl;
                document.body.appendChild(iframe);

                setTimeout(function() {
                    iframe.parentNode && iframe.parentNode.removeChild(iframe);
                    window.removeEventListener('blur', blurHandler);
                    document.removeEventListener('visibilitychange', hiddenHandler);

                    if (!callbackExecuted) {
                        callbackExecuted = true;
                        if (!appOpened && fallbackCallback) {
                            fallbackCallback();
                        }
                    }
                }, timeout);
            }

            function generateClientLink(clientType, clientName) {
                var currentUrl = window.location.href;
                var subscriptionUrl = currentUrl + "/sub";
                var schemeUrl = '';
                var displayName = clientName || '';
                var finalUrl = subscriptionUrl;

                if (clientType === atob('djJyYXk=')) {
                    finalUrl = subscriptionUrl;
                    var urlElement = document.getElementById("clientSubscriptionUrl");
                    urlElement.textContent = finalUrl;
                    urlElement.style.display = "block";
                    urlElement.style.overflowWrap = "break-word";
                    urlElement.style.wordBreak = "break-all";
                    urlElement.style.overflowX = "auto";
                    urlElement.style.maxWidth = "100%";
                    urlElement.style.boxSizing = "border-box";

                    if (clientName === 'V2RAY') {
                        navigator.clipboard.writeText(finalUrl).then(function() {
                            cpToast(displayName + " " + t.subscriptionCopied, 'success');
                        });
                    } else if (clientName === 'Shadowrocket') {
                        schemeUrl = 'shadowrocket://add/' + encodeURIComponent(finalUrl);
                        tryOpenApp(schemeUrl, function() {
                            navigator.clipboard.writeText(finalUrl).then(function() {
                                cpToast(displayName + " " + t.subscriptionCopied, 'success');
                            });
                        });
                    } else if (clientName === 'V2RAYNG') {
                        schemeUrl = 'v2rayng://install?url=' + encodeURIComponent(finalUrl);
                        tryOpenApp(schemeUrl, function() {
                            navigator.clipboard.writeText(finalUrl).then(function() {
                                cpToast(displayName + " " + t.subscriptionCopied, 'success');
                            });
                        });
                    } else if (clientName === 'NEKORAY') {
                        schemeUrl = 'nekoray://install-config?url=' + encodeURIComponent(finalUrl);
                        tryOpenApp(schemeUrl, function() {
                            navigator.clipboard.writeText(finalUrl).then(function() {
                                cpToast(displayName + " " + t.subscriptionCopied, 'success');
                            });
                        });
                    }
                } else {
                    // 统一走内部订阅转换 (?target=xxx)，不再依赖外部 sub-converter
                    finalUrl = subscriptionUrl + (subscriptionUrl.includes('?') ? '&' : '?') + "target=" + clientType;
                    var urlElement = document.getElementById("clientSubscriptionUrl");
                    urlElement.textContent = finalUrl;
                    urlElement.style.display = "block";
                    urlElement.style.overflowWrap = "break-word";
                    urlElement.style.wordBreak = "break-all";
                    urlElement.style.overflowX = "auto";
                    urlElement.style.maxWidth = "100%";
                    urlElement.style.boxSizing = "border-box";

                    if (clientType === atob('Y2xhc2g=')) {
                        if (clientName === 'STASH') {
                            schemeUrl = 'stash://install?url=' + encodeURIComponent(finalUrl);
                            displayName = 'STASH';
                        } else {
                            schemeUrl = 'clash://install-config?url=' + encodeURIComponent(finalUrl);
                            displayName = 'CLASH';
                        }
                    } else if (clientType === atob('c3VyZ2U=')) {
                        schemeUrl = 'surge:///install-config?url=' + encodeURIComponent(finalUrl);
                        displayName = 'SURGE';
                    } else if (clientType === atob('c2luZ2JveA==')) {
                        schemeUrl = 'sing-box://install-config?url=' + encodeURIComponent(finalUrl);
                        displayName = 'SING-BOX';
                    } else if (clientType === atob('bG9vbg==')) {
                        schemeUrl = 'loon://install?url=' + encodeURIComponent(finalUrl);
                        displayName = 'LOON';
                    } else if (clientType === atob('cXVhbng=')) {
                        schemeUrl = 'quantumult-x://install-config?url=' + encodeURIComponent(finalUrl);
                        displayName = 'QUANTUMULT X';
                    }

                    if (schemeUrl) {
                        tryOpenApp(schemeUrl, function() {
                            navigator.clipboard.writeText(finalUrl).then(function() {
                                cpToast(displayName + " " + t.subscriptionCopied, 'success');
                            });
                        });
                    } else {
                        navigator.clipboard.writeText(finalUrl).then(function() {
                            cpToast(displayName + " " + t.subscriptionCopied, 'success');
                        });
                    }
                }
            }

            // 页面特效图形化开关 (localStorage 持久化)
            window.cpApplyFx = function() {
                var off = localStorage.getItem('cp-fx-off') === '1';
                document.body.classList.toggle('fx-off', off);
                var lbl = document.getElementById('cpFxLabel');
                if (lbl) lbl.textContent = off ? 'FX: OFF' : 'FX: ON';
                if (off) {
                    var rain = document.getElementById('matrixCodeRain');
                    if (rain) rain.innerHTML = '';
                } else if (typeof createMatrixRain === 'function') {
                    var r = document.getElementById('matrixCodeRain');
                    if (r && !r.firstChild) createMatrixRain();
                }
            };
            window.cpToggleFx = function() {
                var off = localStorage.getItem('cp-fx-off') === '1';
                localStorage.setItem('cp-fx-off', off ? '0' : '1');
                window.cpApplyFx();
            };
            (function() {
                if (localStorage.getItem('cp-fx-off') === '1') {
                    document.addEventListener('DOMContentLoaded', function() {
                        document.body.classList.add('fx-off');
                        var lbl = document.getElementById('cpFxLabel');
                        if (lbl) lbl.textContent = 'FX: OFF';
                    });
                }
            })();

            function createMatrixRain() {
                if (document.body && document.body.classList.contains('fx-off')) return;
                const matrixContainer = document.getElementById('matrixCodeRain');
                if (!matrixContainer) return;
                const cyberChars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ$%#@!?<>+=ABCDEF';
                const palette = ['#00f0ff', '#ff2bd6', '#a347ff', '#00ff9d'];
                const columns = Math.floor(window.innerWidth / 20);

                for (let i = 0; i < columns; i++) {
                    const column = document.createElement('div');
                    column.className = 'matrix-column';
                    column.style.left = (i * 20) + 'px';
                    column.style.animationDelay = (-Math.random() * 15) + 's';
                    column.style.animationDuration = (Math.random() * 14 + 8) + 's';
                    column.style.fontSize = (Math.random() * 4 + 12) + 'px';
                    column.style.opacity = (Math.random() * 0.7 + 0.3).toFixed(2);

                    let text = '';
                    const charCount = Math.floor(Math.random() * 30 + 18);
                    for (let j = 0; j < charCount; j++) {
                        const char = cyberChars[Math.floor(Math.random() * cyberChars.length)];
                        const useAccent = Math.random() > 0.85;
                        const color = useAccent ? palette[Math.floor(Math.random() * palette.length)] : '';
                        text += color
                            ? ('<span style="color:' + color + ';text-shadow:0 0 8px ' + color + ';">' + char + '</span><br>')
                            : ('<span>' + char + '</span><br>');
                    }
                    column.innerHTML = text;
                    matrixContainer.appendChild(column);
                }

                setInterval(function() {
                    const cols = matrixContainer.querySelectorAll('.matrix-column');
                    cols.forEach(function(column) {
                        if (Math.random() > 0.94) {
                            const chars = column.querySelectorAll('span');
                            if (chars.length > 0) {
                                const target = chars[Math.floor(Math.random() * chars.length)];
                                const prev = target.style.color;
                                target.style.color = '#ffffff';
                                target.style.textShadow = '0 0 10px #ffffff, 0 0 18px #00f0ff';
                                setTimeout(function() {
                                    target.style.color = prev;
                                    target.style.textShadow = '';
                                }, 200);
                            }
                        }
                    });
                }, 110);
            }

            async function checkSystemStatus() {
                try {
                    const cfStatus = document.getElementById('cfStatus');
                    const regionStatus = document.getElementById('regionStatus');
                    const geoInfo = document.getElementById('geoInfo');
                    const backupStatus = document.getElementById('backupStatus');
                    const currentIP = document.getElementById('currentIP');
                    const regionMatch = document.getElementById('regionMatch');

                    // 获取当前语言设置（优先从Cookie/localStorage读取）
                    function getCookie(name) {
                        const value = '; ' + document.cookie;
                        const parts = value.split('; ' + name + '=');
                        if (parts.length === 2) return parts.pop().split(';').shift();
                        return null;
                    }

                    const browserLang = navigator.language || navigator.userLanguage || '';
                    const savedLang = localStorage.getItem('preferredLanguage') || getCookie('preferredLanguage');
                    let isFarsi = false;

                    if (savedLang === 'fa' || savedLang === 'fa-IR') {
                        isFarsi = true;
                    } else if (savedLang === 'zh' || savedLang === 'zh-CN') {
                        isFarsi = false;
                    } else {
                        isFarsi = browserLang.includes('fa') || browserLang.includes('fa-IR');
                    }

                    const translations = {
                        zh: {
                            workerRegion: 'Worker地区: ',
                            detectionMethod: '检测方式: ',
                            proxyIPStatus: 'ProxyIP状态: ',
                            currentIP: '当前使用IP: ',
                            regionMatch: '地区匹配: ',
                            regionNames: {
                                'HK': '🇭🇰 香港', 'US': '🇺🇸 美国', 'SG': '🇸🇬 新加坡', 'JP': '🇯🇵 日本',
                                'KR': '🇰🇷 韩国', 'DE': '🇩🇪 德国', 'SE': '🇸🇪 瑞典', 'NL': '🇳🇱 荷兰',
                                'FI': '🇫🇮 芬兰', 'GB': '🇬🇧 英国'
                            },
                            customIPMode: '自定义ProxyIP模式 (p变量启用)',
                            customIPModeDesc: '自定义IP模式 (已禁用地区匹配)',
                            usingCustomProxyIP: '使用自定义ProxyIP: ',
                            customIPConfig: ' (p变量配置)',
                            customIPModeDisabled: '自定义IP模式，地区选择已禁用',
                            manualRegion: '手动指定地区',
                            manualRegionDesc: ' (手动指定)',
                            proxyIPAvailable: '10/10 可用 (ProxyIP域名预设可用)',
                            smartSelection: '智能就近选择中',
                            sameRegionIP: '同地区IP可用 (1个)',
                            cloudflareDetection: 'Cloudflare内置检测',
                            detectionFailed: '检测失败',
                            unknown: '未知'
                        },
                        fa: {
                            workerRegion: 'منطقه Worker: ',
                            detectionMethod: 'روش تشخیص: ',
                            proxyIPStatus: 'وضعیت ProxyIP: ',
                            currentIP: 'IP فعلی: ',
                            regionMatch: 'تطبیق منطقه: ',
                            regionNames: {
                                'HK': '🇭🇰 هنگ کنگ', 'US': '🇺🇸 آمریکا', 'SG': '🇸🇬 سنگاپور', 'JP': '🇯🇵 ژاپن',
                                'KR': '🇰🇷 کره جنوبی', 'DE': '🇩🇪 آلمان', 'SE': '🇸🇪 سوئد', 'NL': '🇳🇱 هلند',
                                'FI': '🇫🇮 فنلاند', 'GB': '🇬🇧 بریتانیا'
                            },
                            customIPMode: 'حالت ProxyIP سفارشی (متغیر p فعال است)',
                            customIPModeDesc: 'حالت IP سفارشی (تطبیق منطقه غیرفعال است)',
                            usingCustomProxyIP: 'استفاده از ProxyIP سفارشی: ',
                            customIPConfig: ' (پیکربندی متغیر p)',
                            customIPModeDisabled: 'حالت IP سفارشی، انتخاب منطقه غیرفعال است',
                            manualRegion: 'تعیین منطقه دستی',
                            manualRegionDesc: ' (تعیین دستی)',
                            proxyIPAvailable: '10/10 در دسترس (دامنه پیش‌فرض ProxyIP در دسترس است)',
                            smartSelection: 'انتخاب هوشمند نزدیک در حال انجام است',
                            sameRegionIP: 'IP هم‌منطقه در دسترس است (1)',
                            cloudflareDetection: 'تشخیص داخلی Cloudflare',
                            detectionFailed: 'تشخیص ناموفق',
                            unknown: 'ناشناخته'
                        }
                    };

                    const t = translations[isFarsi ? 'fa' : 'zh'];

                    let detectedRegion = 'US'; // 默认值
                    let isCustomIPMode = false;
                    let isManualRegionMode = false;
                    try {
                        const response = await fetch(window.location.pathname + '/region');
                        const data = await response.json();

                        if (data.region === 'CUSTOM') {
                            isCustomIPMode = true;
                            detectedRegion = 'CUSTOM';

                            // 获取自定义IP的详细信息
                            const customIPInfo = data.ci || t.unknown;
                            geoInfo.innerHTML = t.detectionMethod + '<span style="color: #ffb400;">⚙️ ' + t.customIPMode + '</span>';
                            regionStatus.innerHTML = t.workerRegion + '<span style="color: #ffb400;">🔧 ' + t.customIPModeDesc + '</span>';

                            // 显示自定义IP配置状态，包含具体IP
                            if (backupStatus) backupStatus.innerHTML = t.proxyIPStatus + '<span style="color: #ffb400;">🔧 ' + t.usingCustomProxyIP + customIPInfo + '</span>';
                            if (currentIP) currentIP.innerHTML = t.currentIP + '<span style="color: #ffb400;">✅ ' + customIPInfo + t.customIPConfig + '</span>';
                            if (regionMatch) regionMatch.innerHTML = t.regionMatch + '<span style="color: #ffb400;">⚠️ ' + t.customIPModeDisabled + '</span>';

                            return; // 提前返回，不执行后续的地区匹配逻辑
                        } else if (data.detectionMethod === '手动指定地区' || data.detectionMethod === 'تعیین منطقه دستی') {
                            isManualRegionMode = true;
                            detectedRegion = data.region;

                            geoInfo.innerHTML = t.detectionMethod + '<span style="color: #00b380;">' + t.manualRegion + '</span>';
                            regionStatus.innerHTML = t.workerRegion + '<span style="color: #00ff9d;">🎯 ' + t.regionNames[detectedRegion] + t.manualRegionDesc + '</span>';

                            // 显示配置状态而不是检测状态
                            if (backupStatus) backupStatus.innerHTML = t.proxyIPStatus + '<span style="color: #00ff9d;">✅ ' + t.proxyIPAvailable + '</span>';
                            if (currentIP) currentIP.innerHTML = t.currentIP + '<span style="color: #00ff9d;">✅ ' + t.smartSelection + '</span>';
                            if (regionMatch) regionMatch.innerHTML = t.regionMatch + '<span style="color: #00ff9d;">✅ ' + t.sameRegionIP + '</span>';

                            return; // 提前返回，不执行后续的地区匹配逻辑
                        } else if (data.region && t.regionNames[data.region]) {
                            detectedRegion = data.region;
                    }

                    geoInfo.innerHTML = t.detectionMethod + '<span style="color: #00ff9d;">' + t.cloudflareDetection + '</span>';

                    } catch (e) {
                        geoInfo.innerHTML = t.detectionMethod + '<span style="color: #ff3860;">' + t.detectionFailed + '</span>';
                    }

                    regionStatus.innerHTML = t.workerRegion + '<span style="color: #00ff9d;">✅ ' + t.regionNames[detectedRegion] + '</span>';

                    // 直接显示配置状态，不再进行检测
                    if (backupStatus) {
                        backupStatus.innerHTML = t.proxyIPStatus + '<span style="color: #00ff9d;">✅ ' + t.proxyIPAvailable + '</span>';
                    }

                    if (currentIP) {
                        currentIP.innerHTML = t.currentIP + '<span style="color: #00ff9d;">✅ ' + t.smartSelection + '</span>';
                    }

                    if (regionMatch) {
                        regionMatch.innerHTML = t.regionMatch + '<span style="color: #00ff9d;">✅ ' + t.sameRegionIP + '</span>';
                    }
                } catch (error) {
                    function getCookie(name) {
                        const value = '; ' + document.cookie;
                        const parts = value.split('; ' + name + '=');
                        if (parts.length === 2) return parts.pop().split(';').shift();
                        return null;
                    }

                    const browserLang = navigator.language || navigator.userLanguage || '';
                    const savedLang = localStorage.getItem('preferredLanguage') || getCookie('preferredLanguage');
                    let isFarsi = false;

                    if (savedLang === 'fa' || savedLang === 'fa-IR') {
                        isFarsi = true;
                    } else {
                        isFarsi = browserLang.includes('fa') || browserLang.includes('fa-IR');
                    }

                    const translations = {
                        zh: {
                            workerRegion: 'Worker地区: ',
                            detectionMethod: '检测方式: ',
                            proxyIPStatus: 'ProxyIP状态: ',
                            currentIP: '当前使用IP: ',
                            regionMatch: '地区匹配: ',
                            detectionFailed: '检测失败'
                        },
                        fa: {
                            workerRegion: 'منطقه Worker: ',
                            detectionMethod: 'روش تشخیص: ',
                            proxyIPStatus: 'وضعیت ProxyIP: ',
                            currentIP: 'IP فعلی: ',
                            regionMatch: 'تطبیق منطقه: ',
                            detectionFailed: 'تشخیص ناموفق'
                        }
                    };

                    const t = translations[isFarsi ? 'fa' : 'zh'];

                    document.getElementById('regionStatus').innerHTML = t.workerRegion + '<span style="color: #ff3860;">❌ ' + t.detectionFailed + '</span>';
                    document.getElementById('geoInfo').innerHTML = t.detectionMethod + '<span style="color: #ff3860;">❌ ' + t.detectionFailed + '</span>';
                    document.getElementById('backupStatus').innerHTML = t.proxyIPStatus + '<span style="color: #ff3860;">❌ ' + t.detectionFailed + '</span>';
                    document.getElementById('currentIP').innerHTML = t.currentIP + '<span style="color: #ff3860;">❌ ' + t.detectionFailed + '</span>';
                    document.getElementById('regionMatch').innerHTML = t.regionMatch + '<span style="color: #ff3860;">❌ ' + t.detectionFailed + '</span>';
                }
            }

            async function testAPI() {
                try {
                    function getCookie(name) {
                        const value = '; ' + document.cookie;
                        const parts = value.split('; ' + name + '=');
                        if (parts.length === 2) return parts.pop().split(';').shift();
                        return null;
                    }

                    const browserLang = navigator.language || navigator.userLanguage || '';
                    const savedLang = localStorage.getItem('preferredLanguage') || getCookie('preferredLanguage');
                    let isFarsi = false;

                    if (savedLang === 'fa' || savedLang === 'fa-IR') {
                        isFarsi = true;
                    } else {
                        isFarsi = browserLang.includes('fa') || browserLang.includes('fa-IR');
                    }

                    const translations = {
                        zh: {
                            apiTestResult: 'API检测结果: ',
                            apiTestTime: '检测时间: ',
                            apiTestFailed: 'API检测失败: ',
                            unknownError: '未知错误',
                            apiTestError: 'API测试失败: '
                        },
                        fa: {
                            apiTestResult: 'نتیجه تشخیص API: ',
                            apiTestTime: 'زمان تشخیص: ',
                            apiTestFailed: 'تشخیص API ناموفق: ',
                            unknownError: 'خطای ناشناخته',
                            apiTestError: 'تست API ناموفق: '
                        }
                    };

                    const t = translations[isFarsi ? 'fa' : 'zh'];

                    const response = await fetch(window.location.pathname + '/test-api');
                    const data = await response.json();

                    if (data.detectedRegion) {
                        cpToast(t.apiTestResult + data.detectedRegion + '\\n' + t.apiTestTime + data.timestamp, 'info', { duration: 5000 });
                    } else {
                        cpToast(t.apiTestFailed + (data.error || t.unknownError), 'error', { duration: 4500 });
                    }
                } catch (error) {
                    function getCookie(name) {
                        const value = '; ' + document.cookie;
                        const parts = value.split('; ' + name + '=');
                        if (parts.length === 2) return parts.pop().split(';').shift();
                        return null;
                    }

                    const browserLang = navigator.language || navigator.userLanguage || '';
                    const savedLang = localStorage.getItem('preferredLanguage') || getCookie('preferredLanguage');
                    let isFarsi = false;

                    if (savedLang === 'fa' || savedLang === 'fa-IR') {
                        isFarsi = true;
                    } else {
                        isFarsi = browserLang.includes('fa') || browserLang.includes('fa-IR');
                    }

                    const translations = {
                        zh: { apiTestError: 'API测试失败: ' },
                        fa: { apiTestError: 'تست API ناموفق: ' }
                    };

                    const t = translations[isFarsi ? 'fa' : 'zh'];
                    cpToast(t.apiTestError + error.message, 'error', { duration: 4500 });
                }
            }
            
            // 配置管理相关函数
            async function checkKVStatus() {
                const apiUrl = window.location.pathname + '/api/config';
                try {
                    const response = await fetch(apiUrl);
                    function getCookie(name) {
                        const value = '; ' + document.cookie;
                        const parts = value.split('; ' + name + '=');
                        if (parts.length === 2) return parts.pop().split(';').shift();
                        return null;
                    }

                    const browserLang = navigator.language || navigator.userLanguage || '';
                    const savedLang = localStorage.getItem('preferredLanguage') || getCookie('preferredLanguage');
                    let isFarsi = false;

                    if (savedLang === 'fa' || savedLang === 'fa-IR') {
                        isFarsi = true;
                    } else {
                        isFarsi = browserLang.includes('fa') || browserLang.includes('fa-IR');
                    }

                    const translations = {
                        zh: {
                            kvDisabled: '⚠️ KV存储未启用或未配置',
                            kvNotConfigured: 'KV存储未配置，无法使用配置管理功能。\\n\\n请在Cloudflare Workers中:\\n1. 创建KV命名空间\\n2. 绑定环境变量 C\\n3. 重新部署代码',
                            kvNotEnabled: 'KV存储未配置',
                            kvEnabled: '✅ KV存储已启用，可以使用配置管理功能',
                            kvCheckFailed: '⚠️ KV存储检测失败',
                            kvCheckFailedFormat: 'KV存储检测失败: 响应格式错误',
                            kvCheckFailedStatus: 'KV存储检测失败 - 状态码: ',
                            kvCheckFailedError: 'KV存储检测失败 - 错误: '
                        },
                        fa: {
                            kvDisabled: '⚠️ ذخیره‌سازی KV فعال نیست یا پیکربندی نشده است',
                            kvNotConfigured: 'ذخیره‌سازی KV پیکربندی نشده است، نمی‌توانید از عملکرد مدیریت تنظیمات استفاده کنید.\\n\\nلطفا در Cloudflare Workers:\\n1. فضای نام KV ایجاد کنید\\n2. متغیر محیطی C را پیوند دهید\\n3. کد را دوباره مستقر کنید',
                            kvNotEnabled: 'ذخیره‌سازی KV پیکربندی نشده است',
                            kvEnabled: '✅ ذخیره‌سازی KV فعال است، می‌توانید از مدیریت تنظیمات استفاده کنید',
                            kvCheckFailed: '⚠️ بررسی ذخیره‌سازی KV ناموفق',
                            kvCheckFailedFormat: 'بررسی ذخیره‌سازی KV ناموفق: خطای فرمت پاسخ',
                            kvCheckFailedStatus: 'بررسی ذخیره‌سازی KV ناموفق - کد وضعیت: ',
                            kvCheckFailedError: 'بررسی ذخیره‌سازی KV ناموفق - خطا: '
                        }
                    };

                    const t = translations[isFarsi ? 'fa' : 'zh'];

                    if (response.status === 503) {
                        // KV未配置
                        document.getElementById('kvStatus').innerHTML = '<span style="color: #ffb400;">' + t.kvDisabled + '</span>';
                        document.getElementById('configCard').style.display = 'block';
                        document.getElementById('currentConfig').textContent = t.kvNotConfigured;
                    } else if (response.ok) {
                        try {
                        const data = await response.json();

                        // 检查响应是否包含KV配置信息
                        if (data && data.kvEnabled === true) {
                            document.getElementById('kvStatus').innerHTML = '<span style="color: #00ff9d;">' + t.kvEnabled + '</span>';
                            document.getElementById('configContent').style.display = 'block';
                            document.getElementById('configCard').style.display = 'block';
                            await loadCurrentConfig();
                        } else {
                            document.getElementById('kvStatus').innerHTML = '<span style="color: #ffb400;">' + t.kvDisabled + '</span>';
                            document.getElementById('configCard').style.display = 'block';
                            document.getElementById('currentConfig').textContent = t.kvNotEnabled;
                        }
                    } catch (jsonError) {
                        document.getElementById('kvStatus').innerHTML = '<span style="color: #ffb400;">' + t.kvCheckFailed + '</span>';
                        document.getElementById('configCard').style.display = 'block';
                        document.getElementById('currentConfig').textContent = t.kvCheckFailedFormat;
                        }
                    } else {
                        document.getElementById('kvStatus').innerHTML = '<span style="color: #ffb400;">' + t.kvDisabled + '</span>';
                        document.getElementById('configCard').style.display = 'block';
                        document.getElementById('currentConfig').textContent = t.kvCheckFailedStatus + response.status;
                    }
                } catch (error) {
                    function getCookie(name) {
                        const value = '; ' + document.cookie;
                        const parts = value.split('; ' + name + '=');
                        if (parts.length === 2) return parts.pop().split(';').shift();
                        return null;
                    }

                    const browserLang = navigator.language || navigator.userLanguage || '';
                    const savedLang = localStorage.getItem('preferredLanguage') || getCookie('preferredLanguage');
                    let isFarsi = false;

                    if (savedLang === 'fa' || savedLang === 'fa-IR') {
                        isFarsi = true;
                    } else {
                        isFarsi = browserLang.includes('fa') || browserLang.includes('fa-IR');
                    }

                    const translations = {
                        zh: {
                            kvDisabled: '⚠️ KV存储未启用或未配置',
                            kvCheckFailedError: 'KV存储检测失败 - 错误: '
                        },
                        fa: {
                            kvDisabled: '⚠️ ذخیره‌سازی KV فعال نیست یا پیکربندی نشده است',
                            kvCheckFailedError: 'بررسی ذخیره‌سازی KV ناموفق - خطا: '
                        }
                    };

                    const t = translations[isFarsi ? 'fa' : 'zh'];

                    document.getElementById('kvStatus').innerHTML = '<span style="color: #ffb400;">' + t.kvDisabled + '</span>';
                    document.getElementById('configCard').style.display = 'block';
                    document.getElementById('currentConfig').textContent = t.kvCheckFailedError + error.message;
                }
            }

            async function loadCurrentConfig() {
                const apiUrl = window.location.pathname + '/api/config';
                try {
                    const response = await fetch(apiUrl);

                    if (response.status === 503) {
                        document.getElementById('currentConfig').textContent = 'KV存储未配置，无法加载配置';
                        return;
                    }
                    if (!response.ok) {
                        const errorText = await response.text();
                        document.getElementById('currentConfig').textContent = '加载配置失败: ' + errorText;
                        return;
                    }
                    const config = await response.json();

                    // 过滤掉内部字段 kvEnabled
                    const displayConfig = {};
                    for (const [key, value] of Object.entries(config)) {
                        if (key !== 'kvEnabled') {
                            displayConfig[key] = value;
                        }
                    }

                    let configText = '当前配置:\\n';
                    if (Object.keys(displayConfig).length === 0) {
                        configText += '(暂无配置)';
                    } else {
                        for (const [key, value] of Object.entries(displayConfig)) {
                            configText += key + ': ' + (value || '(未设置)') + '\\n';
                        }
                    }

                    document.getElementById('currentConfig').textContent = configText;

                    // 更新表单值
                    document.getElementById('wkRegion').value = config.wk || '';
                    document.getElementById('ev').checked = config.ev !== 'no';
                    document.getElementById('et').checked = config.et === 'yes';
                    document.getElementById('ex').checked = config.ex === 'yes';
                    document.getElementById('ech').checked = config.ech === 'yes';
                    document.getElementById('tp').value = config.tp || '';
                    if (document.getElementById('customDNS')) {
                        document.getElementById('customDNS').value = config.customDNS || '';
                    }
                    if (document.getElementById('customECHDomain')) {
                        document.getElementById('customECHDomain').value = config.customECHDomain || '';
                    }
                    if (document.getElementById('alpn')) {
                        document.getElementById('alpn').value = config.alpn || '';
                    }
                    document.getElementById('scu').value = config.scu || '';
                    document.getElementById('ena').checked = config.ena === 'yes';
                    document.getElementById('epd').checked = config.epd !== 'no';
                    document.getElementById('epi').checked = config.epi !== 'no';
                    document.getElementById('egi').checked = config.egi !== 'no';
                    if (document.getElementById('ipv4Enabled')) document.getElementById('ipv4Enabled').checked = config.ipv4 !== 'no';
                    if (document.getElementById('ipv6Enabled')) document.getElementById('ipv6Enabled').checked = config.ipv6 !== 'no';
                    if (document.getElementById('ispMobile')) document.getElementById('ispMobile').checked = config.ispMobile !== 'no';
                    if (document.getElementById('ispUnicom')) document.getElementById('ispUnicom').checked = config.ispUnicom !== 'no';
                    if (document.getElementById('ispTelecom')) document.getElementById('ispTelecom').checked = config.ispTelecom !== 'no';
                    document.getElementById('customPath').value = config.d || '';
                    document.getElementById('customIP').value = config.p || '';
                    document.getElementById('yx').value = config.yx || '';
                    document.getElementById('yxURL').value = config.yxURL || '';
                    document.getElementById('socksConfig').value = config.s || '';
                    document.getElementById('customHomepage').value = config.homepage || '';
                    document.getElementById('apiEnabled').value = config.ae || '';
                    document.getElementById('regionMatching').value = config.rm || '';
                    document.getElementById('downgradeControl').value = config.qj || '';
                    document.getElementById('portControl').value = config.dkby || '';
                    document.getElementById('preferredControl').value = config.yxby || '';

                    // 更新路径类型显示
                    updatePathTypeStatus(config.d);

                    // 检查p变量，如果有值则禁用wk地区选择
                    updateWkRegionState();

                } catch (error) {
                    document.getElementById('currentConfig').textContent = '加载配置失败: ' + error.message;
                }
            }

            // 更新路径类型显示
            function updatePathTypeStatus(cp) {
                const pathTypeStatus = document.getElementById('pathTypeStatus');
                const currentUrl = window.location.href;
                const pathParts = window.location.pathname.split('/').filter(p => p);
                const currentPath = pathParts.length > 0 ? pathParts[0] : '';

                if (cp && cp.trim()) {
                    // 使用自定义路径 (d)
                    pathTypeStatus.innerHTML = '<div style="color: #00ff9d;">使用类型: <strong>自定义路径 (d)</strong></div>' +
                        '<div style="margin-top: 5px; color: #00f0ff;">当前路径: <span style="color: #ffb400;">' + cp + '</span></div>' +
                        '<div style="margin-top: 5px; font-size: 0.9rem; color: #7aa9c4;">访问地址: ' + 
                        (currentUrl.split('/')[0] + '//' + currentUrl.split('/')[2]) + cp + '/sub</div>';
                } else {
                    // 使用 UUID (u)
                    pathTypeStatus.innerHTML = '<div style="color: #00ff9d;">使用类型: <strong>UUID 路径 (u)</strong></div>' +
                        '<div style="margin-top: 5px; color: #00f0ff;">当前路径: <span style="color: #ffb400;">' + (currentPath || '(UUID)') + '</span></div>' +
                        '<div style="margin-top: 5px; font-size: 0.9rem; color: #7aa9c4;">访问地址: ' + currentUrl.split('/sub')[0] + '/sub</div>';
                }
            }

            // 更新wk地区选择的启用/禁用状态
            function updateWkRegionState() {
                const customIPInput = document.getElementById('customIP');
                const wkRegion = document.getElementById('wkRegion');
                const wkRegionHint = document.getElementById('wkRegionHint');

                if (customIPInput && wkRegion) {
                    const hasCustomIP = customIPInput.value.trim() !== '';
                    wkRegion.disabled = hasCustomIP;

                    // 添加视觉反馈
                    if (hasCustomIP) {
                        wkRegion.style.opacity = '0.5';
                        wkRegion.style.cursor = 'not-allowed';
                        wkRegion.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
                        // 显示提示信息
                        if (wkRegionHint) {
                            wkRegionHint.style.display = 'block';
                            wkRegionHint.style.color = '#ffb400';
                        }
                    } else {
                        wkRegion.style.opacity = '1';
                        wkRegion.style.cursor = 'pointer';
                        wkRegion.style.backgroundColor = 'rgba(0, 0, 0, 0.8)';
                        // 隐藏提示信息
                        if (wkRegionHint) {
                            wkRegionHint.style.display = 'none';
                        }
                    }
                }
            }

            async function saveConfig(configData) {
                const apiUrl = window.location.pathname + '/api/config';

                try {
                    const response = await fetch(apiUrl, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(configData)
                    });

                    if (response.status === 503) {
                        showStatus('KV存储未配置，无法保存配置。请先在Cloudflare Workers中配置KV存储。', 'error');
                        return;
                    }

                    if (!response.ok) {
                        const errorText = await response.text();

                        // 尝试解析 JSON 错误信息
                        try {
                            const errorData = JSON.parse(errorText);
                            showStatus(errorData.message || '保存失败', 'error');
                        } catch (parseError) {
                            // 如果不是 JSON，直接显示文本
                            showStatus('保存失败: ' + errorText, 'error');
                        }
                        return;
                    }

                    const result = await response.json();

                    showStatus(result.message, result.success ? 'success' : 'error');

                    if (result.success) {
                        await loadCurrentConfig();
                        // 更新wk地区选择状态
                        updateWkRegionState();
                        // 保存成功后刷新页面以更新系统状态
                        setTimeout(function() {
                            window.location.reload();
                        }, 1500);
                    } else {
                    }
                } catch (error) {
                    showStatus('保存失败: ' + error.message, 'error');
                }
            }

            function showStatus(message, type) {
                const statusDiv = document.getElementById('statusMessage');
                if (statusDiv) {
                    statusDiv.textContent = message;
                    statusDiv.style.display = 'block';
                    statusDiv.style.color = type === 'success' ? '#00f0ff' : '#ff3860';
                    statusDiv.style.borderColor = type === 'success' ? '#00f0ff' : '#ff3860';

                    setTimeout(function() {
                        statusDiv.style.display = 'none';
                    }, 3000);
                }
                // 同步在底部操作条上方弹出霓虹反馈
                if (typeof window.flashActionStatus === 'function') {
                    window.flashActionStatus(message, type === 'success' ? 'ok' : 'err');
                }
            }

            async function resetAllConfig() {
                if (confirm('确定要重置所有配置吗？这将清空所有KV配置，恢复为环境变量设置。')) {
                    try {
                        const response = await fetch(window.location.pathname + '/api/config', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ 
                                wk: '',
                                d: '',
                                p: '',
                                yx: '',
                                yxURL: '',
                                s: '', ae: '',
                                rm: '',
                                qj: '',
                                dkby: '',
                                yxby: '', ev: '', et: '', ex: '', tp: '', scu: '', epd: '', epi: '', egi: '',
                                ipv4: '', ipv6: '', ispMobile: '', ispUnicom: '', ispTelecom: '',
                                homepage: '',
                                alpn: ''
                            })
                        });

                        if (response.status === 503) {
                            showStatus('KV存储未配置，无法重置配置。', 'error');
                            return;
                        }

                        if (!response.ok) {
                            const errorText = await response.text();

                            // 尝试解析 JSON 错误信息
                            try {
                                const errorData = JSON.parse(errorText);
                                showStatus(errorData.message || '重置失败', 'error');
                            } catch (parseError) {
                                // 如果不是 JSON，直接显示文本
                                showStatus('重置失败: ' + errorText, 'error');
                            }
                            return;
                        }

                        const result = await response.json();
                        showStatus(result.message || '配置已重置', result.success ? 'success' : 'error');

                        if (result.success) {
                            await loadCurrentConfig();
                            // 更新wk地区选择状态
                            updateWkRegionState();
                            // 刷新页面以更新系统状态
                            setTimeout(function() {
                                window.location.reload();
                            }, 1500);
                        }
                    } catch (error) {
                        showStatus('重置失败: ' + error.message, 'error');
                    }
                }
            }

            async function checkECHStatus() {
                const echStatusEl = document.getElementById('echStatus');

                if (!echStatusEl) return;

                try {
                    const currentUrl = window.location.href;
                    const subscriptionUrl = currentUrl + '/sub';

                    echStatusEl.innerHTML = 'ECH状态: <span style="color: #ffb400;">检测中...</span>';

                    const response = await fetch(subscriptionUrl, {
                        method: 'GET',
                        headers: {
                            'Accept': 'text/plain'
                        }
                    });

                    const echStatusHeader = response.headers.get('X-ECH-Status');
                    const echConfigLength = response.headers.get('X-ECH-Config-Length');

                    if (echStatusHeader === 'ENABLED') {
                        echStatusEl.innerHTML = 'ECH状态: <span style="color: #00ff9d;">✅ 已启用' + (echConfigLength ? ' (配置长度: ' + echConfigLength + ')' : '') + '</span>';
                    } else {
                        echStatusEl.innerHTML = 'ECH状态: <span style="color: #ffb400;">⚠️ 未启用</span>';
                    }
                } catch (error) {
                    echStatusEl.innerHTML = 'ECH状态: <span style="color: #ff3860;">❌ 检测失败: ' + error.message + '</span>';
                }
            }

            document.addEventListener('DOMContentLoaded', function() {
                createMatrixRain();
                checkSystemStatus();
                checkKVStatus();
                checkECHStatus();

                // ECH 开启时自动联动开启仅TLS
                const echCheckbox = document.getElementById('ech');
                const portControl = document.getElementById('portControl');
                if (echCheckbox && portControl) {
                    echCheckbox.addEventListener('change', function() {
                        if (this.checked) {
                            // ECH 开启时，自动设置仅TLS为 yes
                            portControl.value = 'yes';
                        }
                    });

                    // 页面加载时，如果 ECH 已勾选，也自动设置仅TLS
                    if (echCheckbox.checked) {
                        portControl.value = 'yes';
                    }
                }

                // 监听customIP输入框变化，实时更新wk地区选择状态
                const customIPInput = document.getElementById('customIP');
                if (customIPInput) {
                    customIPInput.addEventListener('input', function() {
                        updateWkRegionState();
                    });
                }

                // 阻止表单默认提交（保存按钮已统一到底部操作条）
                ['regionForm', 'otherConfigForm', 'advancedConfigForm'].forEach(function(fid) {
                    const f = document.getElementById(fid);
                    if (f) f.addEventListener('submit', function(e) { e.preventDefault(); });
                });

                // 在任意输入框按下回车，触发统一保存
                document.querySelectorAll('#configContent input[type="text"], #configContent input[type="number"]').forEach(function(el) {
                    el.addEventListener('keydown', function(e) {
                        if (e.key === 'Enter') {
                            e.preventDefault();
                            saveAllConfig();
                        }
                    });
                });

                // 统一保存：一次性收齐所有字段
                function collectAllConfig() {
                    function val(id) { const el = document.getElementById(id); return el ? el.value : ''; }
                    function chk(id, def) { const el = document.getElementById(id); if (!el) return def; return el.checked ? 'yes' : 'no'; }
                    return {
                        wk: val('wkRegion'),
                        ev: chk('ev', 'yes'), et: chk('et', 'no'), ex: chk('ex', 'no'), ech: chk('ech', 'no'),
                        tp: val('tp'),
                        customDNS: val('customDNS'),
                        customECHDomain: val('customECHDomain'),
                        alpn: val('alpn'),
                        d: val('customPath'),
                        p: val('customIP'),
                        yx: val('yx'),
                        yxURL: val('yxURL'),
                        s: val('socksConfig'),
                        homepage: val('customHomepage'),
                        scu: val('scu'),
                        ena: chk('ena', 'no'),
                        epd: chk('epd', 'yes'), epi: chk('epi', 'yes'), egi: chk('egi', 'yes'),
                        ae: val('apiEnabled'),
                        rm: val('regionMatching'),
                        qj: val('downgradeControl'),
                        dkby: val('portControl'),
                        yxby: val('preferredControl'),
                        ipv4: chk('ipv4Enabled', 'yes'), ipv6: chk('ipv6Enabled', 'yes'),
                        ispMobile: chk('ispMobile', 'yes'), ispUnicom: chk('ispUnicom', 'yes'), ispTelecom: chk('ispTelecom', 'yes')
                    };
                }

                async function saveAllConfig() {
                    // 至少启用一个协议
                    const evEl = document.getElementById('ev'), etEl = document.getElementById('et'), exEl = document.getElementById('ex');
                    if (evEl && etEl && exEl && !evEl.checked && !etEl.checked && !exEl.checked) {
                        flashActionStatus('${isFarsi ? 'حداقل یک پروتکل را فعال کنید!' : '至少需要启用一个协议！'}', 'err');
                        cpToast('${isFarsi ? 'حداقل یک پروتکل را فعال کنید!' : '至少需要启用一个协议！'}', 'warn');
                        return;
                    }
                    const btn = document.getElementById('cpBtnSaveAll');
                    if (btn) { btn.classList.add('cp-action-btn-saving'); btn.disabled = true; }
                    try {
                        await saveConfig(collectAllConfig());
                    } finally {
                        if (btn) { btn.classList.remove('cp-action-btn-saving'); btn.disabled = false; }
                    }
                }
                window.saveAllConfig = saveAllConfig;

                function flashActionStatus(msg, type) {
                    const el = document.getElementById('cpActionStatus');
                    if (!el) return;
                    el.textContent = msg;
                    el.classList.toggle('cp-err', type === 'err');
                    el.classList.add('cp-show');
                    clearTimeout(flashActionStatus._t);
                    flashActionStatus._t = setTimeout(function() {
                        el.classList.remove('cp-show');
                    }, 2400);
                }
                window.flashActionStatus = flashActionStatus;

                // 绑定底部统一操作条
                const cpActionBar = document.getElementById('cpActionBar');
                const cpBtnSaveAll = document.getElementById('cpBtnSaveAll');
                if (cpBtnSaveAll) cpBtnSaveAll.addEventListener('click', async function() {
                    cpBtnSaveAll.classList.add('cp-action-btn-saving');
                    try {
                        await saveAllConfig();
                        if (cpActionBar) cpActionBar.classList.remove('cp-dirty');
                    } finally {
                        cpBtnSaveAll.classList.remove('cp-action-btn-saving');
                    }
                });
                const cpBtnRefresh = document.getElementById('cpBtnRefresh');
                if (cpBtnRefresh) cpBtnRefresh.addEventListener('click', async function() {
                    cpBtnRefresh.classList.add('cp-action-btn-saving');
                    try {
                        await loadCurrentConfig();
                        if (cpActionBar) cpActionBar.classList.remove('cp-dirty');
                        flashActionStatus('${isFarsi ? 'تنظیمات تازه‌سازی شد' : '配置已刷新'}');
                    } finally {
                        cpBtnRefresh.classList.remove('cp-action-btn-saving');
                    }
                });
                const cpBtnReset = document.getElementById('cpBtnReset');
                if (cpBtnReset) cpBtnReset.addEventListener('click', resetAllConfig);

                // 修改字段时把 FAB 标记为 "未保存"
                function markDirty() {
                    if (cpActionBar) cpActionBar.classList.add('cp-dirty');
                }
                const dirtyScope = document.getElementById('configContent') || document;
                ['input', 'change'].forEach(function(evt) {
                    dirtyScope.addEventListener(evt, function(e) {
                        const tgt = e.target;
                        if (!tgt || !tgt.tagName) return;
                        const tag = tgt.tagName.toLowerCase();
                        if (tag === 'input' || tag === 'select' || tag === 'textarea') {
                            // 跳过延迟测试相关输入，避免误触
                            if (tgt.id && /^(latencyTestInput|fetchURLInput|latencyTestPort|randomIPCount|testThreads|ipSourceSelect)$/.test(tgt.id)) return;
                            markDirty();
                        }
                    });
                });

                // Ctrl+S / Cmd+S 触发保存
                window.addEventListener('keydown', function(e) {
                    if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
                        e.preventDefault();
                        if (cpBtnSaveAll && !cpBtnSaveAll.classList.contains('cp-action-btn-saving')) {
                            cpBtnSaveAll.click();
                        }
                    }
                });

                let testAbortController = null;
                let testResults = [];

                const startTestBtn = document.getElementById('startLatencyTest');
                const stopTestBtn = document.getElementById('stopLatencyTest');
                const testStatus = document.getElementById('latencyTestStatus');
                const testResultsDiv = document.getElementById('latencyTestResults');
                const resultsList = document.getElementById('latencyResultsList');
                const overwriteSelectedBtn = document.getElementById('overwriteSelectedToYx');
                const appendSelectedBtn = document.getElementById('appendSelectedToYx');
                const selectAllBtn = document.getElementById('selectAllResults');
                const deselectAllBtn = document.getElementById('deselectAllResults');
                const ipSourceSelect = document.getElementById('ipSourceSelect');
                const manualInputDiv = document.getElementById('manualInputDiv');
                const urlFetchDiv = document.getElementById('urlFetchDiv');
                const latencyTestInput = document.getElementById('latencyTestInput');
                const fetchURLInput = document.getElementById('fetchURLInput');
                const latencyTestPort = document.getElementById('latencyTestPort');
                const randomIPCount = document.getElementById('randomIPCount');
                const cfRandomDiv = document.getElementById('cfRandomDiv');
                const randomCountDiv = document.getElementById('randomCountDiv');
                const generateCFIPBtn = document.getElementById('generateCFIPBtn');
                const fetchIPBtn = document.getElementById('fetchIPBtn');

                if (latencyTestInput) {
                    const savedTestInput = localStorage.getItem('latencyTestInput');
                    if (savedTestInput) latencyTestInput.value = savedTestInput;
                    latencyTestInput.addEventListener('input', function() {
                        localStorage.setItem('latencyTestInput', this.value);
                    });
                }
                if (fetchURLInput) {
                    const savedFetchURL = localStorage.getItem('fetchURLInput');
                    if (savedFetchURL) fetchURLInput.value = savedFetchURL;
                    fetchURLInput.addEventListener('input', function() {
                        localStorage.setItem('fetchURLInput', this.value);
                    });
                }
                if (latencyTestPort) {
                    const savedPort = localStorage.getItem('latencyTestPort');
                    if (savedPort) latencyTestPort.value = savedPort;
                    latencyTestPort.addEventListener('input', function() {
                        localStorage.setItem('latencyTestPort', this.value);
                    });
                }
                if (randomIPCount) {
                    const savedCount = localStorage.getItem('randomIPCount');
                    if (savedCount) randomIPCount.value = savedCount;
                    randomIPCount.addEventListener('input', function() {
                        localStorage.setItem('randomIPCount', this.value);
                    });
                    // 初始化时，如果默认是隐藏的，则禁用输入框
                    if (randomCountDiv && randomCountDiv.style.display === 'none') {
                        randomIPCount.disabled = true;
                    }
                }
                const testThreadsInput = document.getElementById('testThreads');
                if (testThreadsInput) {
                    const savedThreads = localStorage.getItem('testThreads');
                    if (savedThreads) testThreadsInput.value = savedThreads;
                    testThreadsInput.addEventListener('input', function() {
                        localStorage.setItem('testThreads', this.value);
                    });
                }
                if (ipSourceSelect) {
                    const savedSource = localStorage.getItem('ipSourceSelect');
                    const currentSource = savedSource || ipSourceSelect.value || 'manual';
                    if (savedSource) {
                        ipSourceSelect.value = savedSource;
                    }
                    manualInputDiv.style.display = currentSource === 'manual' ? 'block' : 'none';
                    urlFetchDiv.style.display = currentSource === 'urlFetch' ? 'block' : 'none';
                    cfRandomDiv.style.display = currentSource === 'cfRandom' ? 'block' : 'none';
                    randomCountDiv.style.display = currentSource === 'cfRandom' ? 'block' : 'none';
                    // 当隐藏时禁用输入框，避免表单验证错误
                    if (randomIPCount) {
                        randomIPCount.disabled = currentSource !== 'cfRandom';
                    }
                }

                const CF_CIDR_LIST = [
                    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
                    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
                    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
                ];

                function generateRandomIPFromCIDR(cidr) {
                    const [baseIP, prefixLength] = cidr.split('/');
                    const prefix = parseInt(prefixLength);
                    const hostBits = 32 - prefix;
                    const ipParts = baseIP.split('.').map(p => parseInt(p));
                    const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
                    const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
                    const mask = (0xFFFFFFFF << hostBits) >>> 0;
                    const randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
                    return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
                }

                function generateCFRandomIPs(count, port) {
                    const ips = [];
                    for (let i = 0; i < count; i++) {
                        const cidr = CF_CIDR_LIST[Math.floor(Math.random() * CF_CIDR_LIST.length)];
                        const ip = generateRandomIPFromCIDR(cidr);
                        ips.push(ip + ':' + port);
                    }
                    return ips;
                }

                if (ipSourceSelect) {
                    ipSourceSelect.addEventListener('change', function() {
                        const value = this.value;
                        localStorage.setItem('ipSourceSelect', value);
                        manualInputDiv.style.display = value === 'manual' ? 'block' : 'none';
                        urlFetchDiv.style.display = value === 'urlFetch' ? 'block' : 'none';
                        cfRandomDiv.style.display = value === 'cfRandom' ? 'block' : 'none';
                        randomCountDiv.style.display = value === 'cfRandom' ? 'block' : 'none';
                        // 当隐藏时禁用输入框，避免表单验证错误
                        if (randomIPCount) {
                            randomIPCount.disabled = value !== 'cfRandom';
                        }
                    });
                }

                if (generateCFIPBtn) {
                    generateCFIPBtn.addEventListener('click', function() {
                        const count = parseInt(document.getElementById('randomIPCount').value) || 20;
                        const port = document.getElementById('latencyTestPort').value || '443';
                        const ips = generateCFRandomIPs(count, port);
                        document.getElementById('latencyTestInput').value = ips.join(',');
                        manualInputDiv.style.display = 'block';
                        showStatus('${isFarsi ? 'تولید شد' : '已生成'} ' + count + ' ${isFarsi ? 'IP تصادفی CF' : '个CF随机IP'}', 'success');
                    });
                }

                if (fetchIPBtn) {
                    fetchIPBtn.addEventListener('click', async function() {
                        const urlInput = document.getElementById('fetchURLInput');
                        const fetchUrl = urlInput.value.trim();
                        if (!fetchUrl) {
                            cpToast('${isFarsi ? 'لطفا URL را وارد کنید' : '请输入URL'}', 'warn');
                            return;
                        }

                        fetchIPBtn.disabled = true;
                        fetchIPBtn.textContent = '${isFarsi ? 'در حال دریافت...' : '获取中...'}';

                        try {
                            // 支持多个 URL（逗号分隔）以及返回内容中逗号分隔的多个 IP/节点
                            const urlList = Array.from(new Set(
                                fetchUrl.split(',').map(u => u.trim()).filter(u => u)
                            ));

                            const allItems = [];

                            for (const u of urlList) {
                                const response = await fetch(u);
                                if (!response.ok) {
                                    throw new Error('HTTP ' + response.status + ' @ ' + u);
                                }
                                const text = await response.text();

                                // 先按行分割，再在每行内按逗号分割，兼容“多行 + 逗号分隔”两种格式
                                const perUrlItems = text
                                    .split(/\\r?\\n/)
                                    .map(l => l.trim())
                                    .filter(l => l && !l.startsWith('#'))
                                    .flatMap(l => l.split(',').map(p => p.trim()).filter(p => p));

                                allItems.push(...perUrlItems);
                            }

                            if (allItems.length > 0) {
                                document.getElementById('latencyTestInput').value = allItems.join(',');
                                manualInputDiv.style.display = 'block';
                                showStatus('${isFarsi ? 'دریافت شد' : '已获取'} ' + allItems.length + ' ${isFarsi ? 'IP' : '个IP'}', 'success');
                            } else {
                                showStatus('${isFarsi ? 'داده‌ای یافت نشد' : '未获取到数据'}', 'error');
                            }
                        } catch (err) {
                            showStatus('${isFarsi ? 'خطا در دریافت' : '获取失败'}: ' + err.message, 'error');
                        } finally {
                            fetchIPBtn.disabled = false;
                            fetchIPBtn.textContent = '⬇ ${isFarsi ? 'دریافت IP' : '获取IP'}';
                        }
                    });
                }

                if (startTestBtn) {
                    startTestBtn.addEventListener('click', async function() {
                        const inputField = document.getElementById('latencyTestInput');
                        const portField = document.getElementById('latencyTestPort');
                        const threadsField = document.getElementById('testThreads');
                        const inputValue = inputField.value.trim();
                        const defaultPort = portField.value || '443';
                        const threads = parseInt(threadsField.value) || 5;

                        if (!inputValue) {
                            showStatus('${isFarsi ? 'لطفا IP یا دامنه وارد کنید' : '请输入IP或域名'}', 'error');
                            return;
                        }

                        const targets = inputValue.split(',').map(t => t.trim()).filter(t => t);
                        if (targets.length === 0) return;

                        startTestBtn.style.display = 'none';
                        stopTestBtn.style.display = 'inline-block';
                        testStatus.style.display = 'block';
                        testResultsDiv.style.display = 'block';
                        resultsList.innerHTML = '';
                        testResults = [];
                        if (cityFilterContainer) {
                            cityFilterContainer.style.display = 'none';
                        }

                        testAbortController = new AbortController();

                        let completed = 0;
                        const total = targets.length;

                        function parseTarget(target) {
                            let host = target;
                            let port = defaultPort;
                            let nodeName = '';

                            if (target.includes('#')) {
                                const parts = target.split('#');
                                nodeName = parts[1] || '';
                                host = parts[0];
                            }

                            if (host.includes(':') && !host.startsWith('[')) {
                                const lastColon = host.lastIndexOf(':');
                                const possiblePort = host.substring(lastColon + 1);
                                if (/^[0-9]+$/.test(possiblePort)) {
                                    port = possiblePort;
                                    host = host.substring(0, lastColon);
                                }
                            } else if (host.includes(']:')) {
                                const parts = host.split(']:');
                                host = parts[0] + ']';
                                port = parts[1];
                            }
                            return { host, port, nodeName };
                        }

                        function renderResult(result, index, shouldShow = true) {
                            // 只展示在线优选成功的结果，失败/超时的不再显示
                            if (!result.success) {
                                return null;
                            }

                            const resultItem = document.createElement('div');
                            resultItem.style.cssText = 'display: flex; align-items: center; padding: 8px; border-bottom: 1px solid #003300; gap: 10px;';
                            resultItem.dataset.index = index;
                            resultItem.dataset.colo = result.colo || '';
                            if (!shouldShow) {
                                resultItem.style.display = 'none';
                            }

                            const checkbox = document.createElement('input');
                            checkbox.type = 'checkbox';
                            checkbox.checked = true;
                            checkbox.disabled = false;
                            checkbox.dataset.index = index;
                            checkbox.style.cssText = 'width: 18px; height: 18px; cursor: pointer;';

                            const info = document.createElement('div');
                            info.style.cssText = 'flex: 1; font-family: monospace; font-size: 13px;';

                            const coloName = result.colo ? getColoName(result.colo) : '';
                            const coloDisplay = coloName ? ' <span style="color: #00aaff;">[' + coloName + ']</span>' : '';
                            info.innerHTML = '<span style="color: #00f0ff;">' + result.host + ':' + result.port + '</span>' + coloDisplay + ' <span style="color: #ffff00;">' + result.latency + 'ms</span>';

                            resultItem.appendChild(checkbox);
                            resultItem.appendChild(info);
                            resultsList.appendChild(resultItem);
                            return resultItem;
                        }

                        async function testOne(target) {
                            if (testAbortController.signal.aborted) return null;
                            const { host, port, nodeName } = parseTarget(target);
                            const result = await testLatency(host, port, testAbortController.signal);
                            result.host = host;
                            result.port = port;
                            result.nodeName = (result.success && result.colo) ? (nodeName || ('CF-' + result.colo)) : (nodeName || host);
                            return result;
                        }

                        for (let i = 0; i < total; i += threads) {
                            if (testAbortController.signal.aborted) break;
                            
                            const batch = targets.slice(i, Math.min(i + threads, total));
                            testStatus.textContent = '${isFarsi ? 'در حال تست' : '测试中'}: ' + (i + 1) + '-' + Math.min(i + threads, total) + '/' + total + ' (${isFarsi ? 'رشته‌ها' : '线程'}: ' + threads + ')';

                            const results = await Promise.all(batch.map(t => testOne(t)));

                            for (const result of results) {
                                if (result) {
                                    const idx = testResults.length;
                                    testResults.push(result);
                                    renderResult(result, idx);
                                    completed++;
                                }
                            }
                        }

                        testStatus.textContent = '${isFarsi ? 'تست کامل شد' : '测试完成'}: ' + completed + '/' + total;
                        startTestBtn.style.display = 'inline-block';
                        stopTestBtn.style.display = 'none';

                        // 更新城市选择器
                        updateCityFilter();
                    });
                }

                if (stopTestBtn) {
                    stopTestBtn.addEventListener('click', function() {
                        if (testAbortController) {
                            testAbortController.abort();
                        }
                        startTestBtn.style.display = 'inline-block';
                        stopTestBtn.style.display = 'none';
                        testStatus.textContent = '${isFarsi ? 'تست متوقف شد' : '测试已停止'}';
                    });
                }

                if (selectAllBtn) {
                    selectAllBtn.addEventListener('click', function() {
                        const checkboxes = resultsList.querySelectorAll('input[type="checkbox"]:not(:disabled)');
                        checkboxes.forEach(cb => cb.checked = true);
                    });
                }

                if (deselectAllBtn) {
                    deselectAllBtn.addEventListener('click', function() {
                        const checkboxes = resultsList.querySelectorAll('input[type="checkbox"]');
                        checkboxes.forEach(cb => cb.checked = false);
                    });
                }

                // 获取选中项的通用函数
                function getSelectedItems() {
                    const checkboxes = resultsList.querySelectorAll('input[type="checkbox"]:checked');
                    if (checkboxes.length === 0) {
                        showStatus('${isFarsi ? 'لطفا حداقل یک مورد انتخاب کنید' : '请至少选择一项'}', 'error');
                        return null;
                    }

                    const selectedItems = [];
                    checkboxes.forEach(cb => {
                        const idx = parseInt(cb.dataset.index);
                        const result = testResults[idx];
                        if (result && result.success) {
                            const coloName = result.colo ? getColoName(result.colo) : result.nodeName;
                            const itemStr = result.host + ':' + result.port + '#' + coloName;
                            selectedItems.push(itemStr);
                        }
                    });

                    return selectedItems;
                }

                // 覆盖添加
                if (overwriteSelectedBtn) {
                    overwriteSelectedBtn.addEventListener('click', async function() {
                        const selectedItems = getSelectedItems();
                        if (!selectedItems || selectedItems.length === 0) return;

                        const yxInput = document.getElementById('yx');
                        const newValue = selectedItems.join(',');
                        yxInput.value = newValue;

                        overwriteSelectedBtn.disabled = true;
                        appendSelectedBtn.disabled = true;
                        overwriteSelectedBtn.textContent = '${isFarsi ? 'در حال ذخیره...' : '保存中...'}';

                        try {
                            const configData = {
                                customIP: document.getElementById('customIP').value,
                                yx: newValue,
                                yxURL: document.getElementById('yxURL').value,
                                s: document.getElementById('socksConfig').value
                            };
                            await saveConfig(configData);
                            showStatus('${isFarsi ? 'موفقیت‌آمیز بود' : '已覆盖'} ' + selectedItems.length + ' ${isFarsi ? 'مورد و ذخیره شد' : '项并已保存'}', 'success');
                        } catch (err) {
                            showStatus('${isFarsi ? 'خطا در ذخیره' : '保存失败'}: ' + err.message, 'error');
                        } finally {
                            overwriteSelectedBtn.disabled = false;
                            appendSelectedBtn.disabled = false;
                            overwriteSelectedBtn.textContent = '${isFarsi ? '覆盖添加' : '覆盖添加'}';
                        }
                    });
                }

                // 追加添加
                if (appendSelectedBtn) {
                    appendSelectedBtn.addEventListener('click', async function() {
                        const selectedItems = getSelectedItems();
                        if (!selectedItems || selectedItems.length === 0) return;

                        const yxInput = document.getElementById('yx');
                        const currentValue = yxInput.value.trim();
                        const newItems = selectedItems.join(',');
                        const newValue = currentValue ? (currentValue + ',' + newItems) : newItems;
                        yxInput.value = newValue;

                        overwriteSelectedBtn.disabled = true;
                        appendSelectedBtn.disabled = true;
                        appendSelectedBtn.textContent = '${isFarsi ? 'در حال ذخیره...' : '保存中...'}';

                        try {
                            const configData = {
                                customIP: document.getElementById('customIP').value,
                                yx: newValue,
                                yxURL: document.getElementById('yxURL').value,
                                s: document.getElementById('socksConfig').value
                            };
                            await saveConfig(configData);
                            showStatus('${isFarsi ? 'موفقیت‌آمیز بود' : '已追加'} ' + selectedItems.length + ' ${isFarsi ? 'مورد و ذخیره شد' : '项并已保存'}', 'success');
                        } catch (err) {
                            showStatus('${isFarsi ? 'خطا در ذخیره' : '保存失败'}: ' + err.message, 'error');
                        } finally {
                            overwriteSelectedBtn.disabled = false;
                            appendSelectedBtn.disabled = false;
                            appendSelectedBtn.textContent = '${isFarsi ? '追加添加' : '追加添加'}';
                        }
                    });
                }

                function ipToHex(ip) {
                    const parts = ip.split('.');
                    if (parts.length !== 4) return null;
                    let hex = '';
                    for (let i = 0; i < 4; i++) {
                        const num = parseInt(parts[i]);
                        if (isNaN(num) || num < 0 || num > 255) return null;
                        hex += num.toString(16).padStart(2, '0');
                    }
                    return hex;
                }

                const coloMap = {
                    'SJC': '🇺🇸 圣何塞', 'LAX': '🇺🇸 洛杉矶', 'SEA': '🇺🇸 西雅图', 'SFO': '🇺🇸 旧金山', 'DFW': '🇺🇸 达拉斯',
                    'ORD': '🇺🇸 芝加哥', 'IAD': '🇺🇸 华盛顿', 'ATL': '🇺🇸 亚特兰大', 'MIA': '🇺🇸 迈阿密', 'DEN': '🇺🇸 丹佛',
                    'PHX': '🇺🇸 凤凰城', 'BOS': '🇺🇸 波士顿', 'EWR': '🇺🇸 纽瓦克', 'JFK': '🇺🇸 纽约', 'LAS': '🇺🇸 拉斯维加斯',
                    'MSP': '🇺🇸 明尼阿波利斯', 'DTW': '🇺🇸 底特律', 'PHL': '🇺🇸 费城', 'CLT': '🇺🇸 夏洛特', 'SLC': '🇺🇸 盐湖城',
                    'PDX': '🇺🇸 波特兰', 'SAN': '🇺🇸 圣地亚哥', 'TPA': '🇺🇸 坦帕', 'IAH': '🇺🇸 休斯顿', 'MCO': '🇺🇸 奥兰多',
                    'AUS': '🇺🇸 奥斯汀', 'BNA': '🇺🇸 纳什维尔', 'RDU': '🇺🇸 罗利', 'IND': '🇺🇸 印第安纳波利斯', 'CMH': '🇺🇸 哥伦布',
                    'MCI': '🇺🇸 堪萨斯城', 'OMA': '🇺🇸 奥马哈', 'ABQ': '🇺🇸 阿尔伯克基', 'OKC': '🇺🇸 俄克拉荷马城', 'MEM': '🇺🇸 孟菲斯',
                    'JAX': '🇺🇸 杰克逊维尔', 'RIC': '🇺🇸 里士满', 'BUF': '🇺🇸 布法罗', 'PIT': '🇺🇸 匹兹堡', 'CLE': '🇺🇸 克利夫兰',
                    'CVG': '🇺🇸 辛辛那提', 'MKE': '🇺🇸 密尔沃基', 'STL': '🇺🇸 圣路易斯', 'SAT': '🇺🇸 圣安东尼奥', 'HNL': '🇺🇸 檀香山',
                    'ANC': '🇺🇸 安克雷奇', 'SMF': '🇺🇸 萨克拉门托', 'ONT': '🇺🇸 安大略', 'OAK': '🇺🇸 奥克兰',
                    'HKG': '🇭🇰 香港', 'TPE': '🇹🇼 台北', 'TSA': '🇹🇼 台北松山', 'KHH': '🇹🇼 高雄',
                    'NRT': '🇯🇵 东京成田', 'HND': '🇯🇵 东京羽田', 'KIX': '🇯🇵 大阪关西', 'ITM': '🇯🇵 大阪伊丹', 'NGO': '🇯🇵 名古屋',
                    'FUK': '🇯🇵 福冈', 'CTS': '🇯🇵 札幌', 'OKA': '🇯🇵 冲绳',
                    'ICN': '🇰🇷 首尔仁川', 'GMP': '🇰🇷 首尔金浦', 'PUS': '🇰🇷 釜山',
                    'SIN': '🇸🇬 新加坡', 'BKK': '🇹🇭 曼谷', 'DMK': '🇹🇭 曼谷廊曼', 'KUL': '🇲🇾 吉隆坡', 'CGK': '🇮🇩 雅加达',
                    'MNL': '🇵🇭 马尼拉', 'CEB': '🇵🇭 宿务', 'HAN': '🇻🇳 河内', 'SGN': '🇻🇳 胡志明', 'DAD': '🇻🇳 岘港',
                    'RGN': '🇲🇲 仰光', 'PNH': '🇰🇭 金边', 'REP': '🇰🇭 暹粒', 'VTE': '🇱🇦 万象',
                    'BOM': '🇮🇳 孟买', 'DEL': '🇮🇳 新德里', 'MAA': '🇮🇳 金奈', 'BLR': '🇮🇳 班加罗尔', 'CCU': '🇮🇳 加尔各答',
                    'HYD': '🇮🇳 海得拉巴', 'AMD': '🇮🇳 艾哈迈达巴德', 'COK': '🇮🇳 科钦', 'PNQ': '🇮🇳 浦那', 'GOI': '🇮🇳 果阿',
                    'CMB': '🇱🇰 科伦坡', 'DAC': '🇧🇩 达卡', 'KTM': '🇳🇵 加德满都', 'ISB': '🇵🇰 伊斯兰堡', 'KHI': '🇵🇰 卡拉奇', 'LHE': '🇵🇰 拉合尔',
                    'LHR': '🇬🇧 伦敦希思罗', 'LGW': '🇬🇧 伦敦盖特威克', 'STN': '🇬🇧 伦敦斯坦斯特德', 'LTN': '🇬🇧 伦敦卢顿', 'MAN': '🇬🇧 曼彻斯特', 'EDI': '🇬🇧 爱丁堡', 'BHX': '🇬🇧 伯明翰',
                    'CDG': '🇫🇷 巴黎戴高乐', 'ORY': '🇫🇷 巴黎奥利', 'MRS': '🇫🇷 马赛', 'LYS': '🇫🇷 里昂', 'NCE': '🇫🇷 尼斯',
                    'FRA': '🇩🇪 法兰克福', 'MUC': '🇩🇪 慕尼黑', 'TXL': '🇩🇪 柏林', 'BER': '🇩🇪 柏林勃兰登堡', 'HAM': '🇩🇪 汉堡', 'DUS': '🇩🇪 杜塞尔多夫', 'CGN': '🇩🇪 科隆', 'STR': '🇩🇪 斯图加特',
                    'AMS': '🇳🇱 阿姆斯特丹', 'BRU': '🇧🇪 布鲁塞尔', 'LUX': '🇱🇺 卢森堡',
                    'ZRH': '🇨🇭 苏黎世', 'GVA': '🇨🇭 日内瓦', 'BSL': '🇨🇭 巴塞尔',
                    'VIE': '🇦🇹 维也纳', 'PRG': '🇨🇿 布拉格', 'BUD': '🇭🇺 布达佩斯', 'WAW': '🇵🇱 华沙', 'KRK': '🇵🇱 克拉科夫',
                    'MXP': '🇮🇹 米兰马尔彭萨', 'LIN': '🇮🇹 米兰利纳特', 'FCO': '🇮🇹 罗马', 'VCE': '🇮🇹 威尼斯', 'NAP': '🇮🇹 那不勒斯', 'FLR': '🇮🇹 佛罗伦萨', 'BGY': '🇮🇹 贝加莫',
                    'MAD': '🇪🇸 马德里', 'BCN': '🇪🇸 巴塞罗那', 'PMI': '🇪🇸 帕尔马', 'AGP': '🇪🇸 马拉加', 'VLC': '🇪🇸 瓦伦西亚', 'SVQ': '🇪🇸 塞维利亚', 'BIO': '🇪🇸 毕尔巴鄂',
                    'LIS': '🇵🇹 里斯本', 'OPO': '🇵🇹 波尔图', 'FAO': '🇵🇹 法鲁',
                    'DUB': '🇮🇪 都柏林', 'CPH': '🇩🇰 哥本哈根', 'ARN': '🇸🇪 斯德哥尔摩', 'GOT': '🇸🇪 哥德堡',
                    'OSL': '🇳🇴 奥斯陆', 'BGO': '🇳🇴 卑尔根', 'HEL': '🇫🇮 赫尔辛基', 'RIX': '🇱🇻 里加', 'TLL': '🇪🇪 塔林', 'VNO': '🇱🇹 维尔纽斯',
                    'ATH': '🇬🇷 雅典', 'SKG': '🇬🇷 塞萨洛尼基', 'SOF': '🇧🇬 索非亚', 'OTP': '🇷🇴 布加勒斯特', 'BEG': '🇷🇸 贝尔格莱德', 'ZAG': '🇭🇷 萨格勒布', 'LJU': '🇸🇮 卢布尔雅那',
                    'KBP': '🇺🇦 基辅', 'IEV': '🇺🇦 基辅茹良尼', 'ODS': '🇺🇦 敖德萨',
                    'SVO': '🇷🇺 莫斯科谢列梅捷沃', 'DME': '🇷🇺 莫斯科多莫杰多沃', 'VKO': '🇷🇺 莫斯科伏努科沃', 'LED': '🇷🇺 圣彼得堡',
                    'IST': '🇹🇷 伊斯坦布尔', 'SAW': '🇹🇷 伊斯坦布尔萨比哈', 'ESB': '🇹🇷 安卡拉', 'AYT': '🇹🇷 安塔利亚', 'ADB': '🇹🇷 伊兹密尔',
                    'TLV': '🇮🇱 特拉维夫', 'AMM': '🇯🇴 安曼', 'BEY': '🇱🇧 贝鲁特', 'BAH': '🇧🇭 巴林', 'KWI': '🇰🇼 科威特',
                    'DXB': '🇦🇪 迪拜', 'AUH': '🇦🇪 阿布扎比', 'SHJ': '🇦🇪 沙迦', 'DOH': '🇶🇦 多哈', 'MCT': '🇴🇲 马斯喀特',
                    'RUH': '🇸🇦 利雅得', 'JED': '🇸🇦 吉达', 'DMM': '🇸🇦 达曼',
                    'CAI': '🇪🇬 开罗', 'HBE': '🇪🇬 亚历山大', 'SSH': '🇪🇬 沙姆沙伊赫',
                    'CMN': '🇲🇦 卡萨布兰卡', 'RAK': '🇲🇦 马拉喀什', 'TUN': '🇹🇳 突尼斯', 'ALG': '🇩🇿 阿尔及尔',
                    'LOS': '🇳🇬 拉各斯', 'ABV': '🇳🇬 阿布贾', 'ACC': '🇬🇭 阿克拉', 'NBO': '🇰🇪 内罗毕', 'MBA': '🇰🇪 蒙巴萨', 'ADD': '🇪🇹 亚的斯亚贝巴', 'DAR': '🇹🇿 达累斯萨拉姆',
                    'JNB': '🇿🇦 约翰内斯堡', 'CPT': '🇿🇦 开普敦', 'DUR': '🇿🇦 德班', 'HRE': '🇿🇼 哈拉雷', 'LUN': '🇿🇲 卢萨卡',
                    'MRU': '🇲🇺 毛里求斯', 'SEZ': '🇸🇨 塞舌尔',
                    'SYD': '🇦🇺 悉尼', 'MEL': '🇦🇺 墨尔本', 'BNE': '🇦🇺 布里斯班', 'PER': '🇦🇺 珀斯', 'ADL': '🇦🇺 阿德莱德', 'CBR': '🇦🇺 堪培拉', 'OOL': '🇦🇺 黄金海岸', 'CNS': '🇦🇺 凯恩斯',
                    'AKL': '🇳🇿 奥克兰', 'WLG': '🇳🇿 惠灵顿', 'CHC': '🇳🇿 基督城', 'ZQN': '🇳🇿 皇后镇',
                    'NAN': '🇫🇯 楠迪', 'PPT': '🇵🇫 帕皮提', 'GUM': '🇬🇺 关岛',
                    'GRU': '🇧🇷 圣保罗瓜鲁柳斯', 'CGH': '🇧🇷 圣保罗孔戈尼亚斯', 'GIG': '🇧🇷 里约热内卢', 'BSB': '🇧🇷 巴西利亚', 'CNF': '🇧🇷 贝洛奥里藏特', 'POA': '🇧🇷 阿雷格里港', 'CWB': '🇧🇷 库里蒂巴', 'FOR': '🇧🇷 福塔莱萨', 'REC': '🇧🇷 累西腓', 'SSA': '🇧🇷 萨尔瓦多',
                    'EZE': '🇦🇷 布宜诺斯艾利斯', 'AEP': '🇦🇷 布宜诺斯艾利斯城', 'COR': '🇦🇷 科尔多瓦', 'MDZ': '🇦🇷 门多萨',
                    'SCL': '🇨🇱 圣地亚哥', 'LIM': '🇵🇪 利马', 'BOG': '🇨🇴 波哥大', 'MDE': '🇨🇴 麦德林', 'CLO': '🇨🇴 卡利',
                    'UIO': '🇪🇨 基多', 'GYE': '🇪🇨 瓜亚基尔', 'CCS': '🇻🇪 加拉加斯', 'MVD': '🇺🇾 蒙得维的亚', 'ASU': '🇵🇾 亚松森',
                    'PTY': '🇵🇦 巴拿马城', 'SJO': '🇨🇷 圣何塞', 'GUA': '🇬🇹 危地马拉城', 'SAL': '🇸🇻 圣萨尔瓦多', 'TGU': '🇭🇳 特古西加尔巴', 'MGA': '🇳🇮 马那瓜', 'BZE': '🇧🇿 伯利兹城',
                    'MEX': '🇲🇽 墨西哥城', 'GDL': '🇲🇽 瓜达拉哈拉', 'MTY': '🇲🇽 蒙特雷', 'CUN': '🇲🇽 坎昆', 'TIJ': '🇲🇽 蒂华纳', 'SJD': '🇲🇽 圣何塞德尔卡沃',
                    'YYZ': '🇨🇦 多伦多', 'YVR': '🇨🇦 温哥华', 'YUL': '🇨🇦 蒙特利尔', 'YYC': '🇨🇦 卡尔加里', 'YEG': '🇨🇦 埃德蒙顿', 'YOW': '🇨🇦 渥太华', 'YWG': '🇨🇦 温尼伯', 'YHZ': '🇨🇦 哈利法克斯',
                    'HAV': '🇨🇺 哈瓦那', 'SJU': '🇵🇷 圣胡安', 'SDQ': '🇩🇴 圣多明各', 'PAP': '🇭🇹 太子港', 'KIN': '🇯🇲 金斯顿', 'NAS': '🇧🇸 拿骚', 'MBJ': '🇯🇲 蒙特哥贝'
                };

                function getColoName(colo) {
                    return coloMap[colo] || colo;
                }

                // 城市筛选相关函数
                const cityFilterContainer = document.getElementById('cityFilterContainer');
                const cityCheckboxesContainer = document.getElementById('cityCheckboxesContainer');

                function updateCityFilter() {
                    if (!cityFilterContainer || !cityCheckboxesContainer) return;

                    // 从测试结果中提取所有可用的城市
                    const cityMap = new Map();
                    testResults.forEach((result, index) => {
                        if (result.success && result.colo) {
                            const colo = result.colo;
                            if (!cityMap.has(colo)) {
                                cityMap.set(colo, {
                                    colo: colo,
                                    name: getColoName(colo),
                                    count: 0
                                });
                            }
                            cityMap.get(colo).count++;
                        }
                    });

                    if (cityMap.size === 0) {
                        cityFilterContainer.style.display = 'none';
                        return;
                    }

                    cityFilterContainer.style.display = 'block';
                    cityCheckboxesContainer.innerHTML = '';

                    // 按城市名称排序
                    const cities = Array.from(cityMap.values()).sort((a, b) => a.name.localeCompare(b.name));

                    cities.forEach(city => {
                        const label = document.createElement('label');
                        label.style.cssText = 'display: inline-flex; align-items: center; cursor: pointer; color: #00f0ff; font-size: 0.85rem; padding: 4px 8px; background: rgba(20, 5, 50, 0.4); border: 1px solid #7aa9c4; border-radius: 4px;';

                        const checkbox = document.createElement('input');
                        checkbox.type = 'checkbox';
                        checkbox.value = city.colo;
                        checkbox.checked = true;
                        checkbox.dataset.colo = city.colo;
                        checkbox.style.cssText = 'margin-right: 6px; width: 16px; height: 16px; cursor: pointer;';

                        const span = document.createElement('span');
                        span.textContent = city.name + ' (' + city.count + ')';
                        
                        label.appendChild(checkbox);
                        label.appendChild(span);
                        cityCheckboxesContainer.appendChild(label);

                        checkbox.addEventListener('change', filterResultsByCity);
                    });
                    
                    // 监听筛选模式变化
                    const filterModeRadios = document.querySelectorAll('input[name="cityFilterMode"]');
                    filterModeRadios.forEach(radio => {
                        radio.addEventListener('change', function() {
                            if (this.value === 'all') {
                                // 切换到"全部城市"模式时，自动选中所有城市复选框
                                const cityCheckboxes = cityCheckboxesContainer.querySelectorAll('input[type="checkbox"]');
                                cityCheckboxes.forEach(cb => {
                                    cb.checked = true;
                                    cb.disabled = false;
                                });
                            }
                            filterResultsByCity();
                        });
                    });
                }

                function filterResultsByCity() {
                    if (!resultsList || !cityCheckboxesContainer) return;

                    const filterMode = document.querySelector('input[name="cityFilterMode"]:checked')?.value || 'all';
                    const resultItems = resultsList.querySelectorAll('[data-index]');
                    const cityCheckboxes = cityCheckboxesContainer.querySelectorAll('input[type="checkbox"]');

                    if (filterMode === 'fastest10') {
                        // 只选择最快的10个
                        const sortedResults = testResults
                            .map((result, index) => ({ result, index }))
                            .filter(item => item.result.success)
                            .sort((a, b) => a.result.latency - b.result.latency)
                            .slice(0, 10);

                        const fastestIndices = new Set(sortedResults.map(item => item.index));

                        resultItems.forEach(item => {
                            const index = parseInt(item.dataset.index);
                            const checkbox = item.querySelector('input[type="checkbox"]');
                            if (fastestIndices.has(index)) {
                                item.style.display = 'flex';
                                if (checkbox) checkbox.checked = true;
                            } else {
                                item.style.display = 'none';
                                if (checkbox) checkbox.checked = false;
                            }
                        });

                        // 禁用城市复选框
                        cityCheckboxes.forEach(cb => cb.disabled = true);
                    } else {
                        // 根据选中的城市筛选
                        const selectedCities = new Set();
                        cityCheckboxes.forEach(cb => {
                            if (cb.checked) {
                                selectedCities.add(cb.value);
                            }
                        });

                        // 如果所有城市都被选中（或没有选中任何城市），显示所有结果
                        const allChecked = cityCheckboxes.length > 0 && selectedCities.size === cityCheckboxes.length;
                        const noneChecked = selectedCities.size === 0;

                        resultItems.forEach(item => {
                            const colo = item.dataset.colo || '';
                            const checkbox = item.querySelector('input[type="checkbox"]');
                            if (allChecked || noneChecked || selectedCities.has(colo)) {
                                item.style.display = 'flex';
                                // 同步更新结果项复选框的选中状态
                                if (checkbox) {
                                    if (allChecked) {
                                        // 所有城市都选中时，所有结果项复选框都选中
                                        checkbox.checked = true;
                                    } else if (noneChecked) {
                                        // 没有选中任何城市时，所有结果项复选框都取消选中
                                        checkbox.checked = false;
                                    } else {
                                        // 根据城市选择状态同步复选框
                                        checkbox.checked = selectedCities.has(colo);
                                    }
                                }
                            } else {
                                item.style.display = 'none';
                                // 取消选中隐藏的结果项复选框
                                if (checkbox) {
                                    checkbox.checked = false;
                                }
                            }
                        });

                        // 启用城市复选框
                        cityCheckboxes.forEach(cb => cb.disabled = false);
                    }
                }

                async function testLatency(host, port, signal) {
                    const timeout = 8000;
                    let colo = '';
                    let testUrl = '';

                    try {
                        const controller = new AbortController();
                        const timeoutId = setTimeout(() => controller.abort(), timeout);

                        if (signal) {
                            signal.addEventListener('abort', () => controller.abort());
                        }

                        const cleanHost = host.replace(/^\\[|\\]$/g, '');
                        const hexIP = ipToHex(cleanHost);
                        const testDomain = hexIP ? (hexIP + '.nip.lfree.org') : (cleanHost + '.nip.lfree.org');
                        testUrl = 'https://' + testDomain + ':' + port + '/';

                        console.log('[LatencyTest] Testing:', testUrl, 'Original:', host + ':' + port, 'HexIP:', hexIP);

                        const firstStart = Date.now();
                        const response1 = await fetch(testUrl, { 
                            signal: controller.signal
                        });
                        const firstTime = Date.now() - firstStart;

                        if (!response1.ok) {
                            clearTimeout(timeoutId);
                            return { success: false, latency: firstTime, error: 'HTTP ' + response1.status + ' ' + response1.statusText, colo: '', testUrl: testUrl };
                        }

                        try {
                            const text = await response1.text();
                            console.log('[LatencyTest] Response body:', text.substring(0, 200));
                            const data = JSON.parse(text);
                            if (data.colo) {
                                colo = data.colo;
                            }
                        } catch (e) {
                            console.log('[LatencyTest] Parse error:', e.message);
                        }

                        const secondStart = Date.now();
                        const response2 = await fetch(testUrl, { 
                            signal: controller.signal
                        });
                        await response2.text();
                        const latency = Date.now() - secondStart;

                        clearTimeout(timeoutId);

                        console.log('[LatencyTest] First:', firstTime + 'ms (DNS+TLS+RTT)', 'Second:', latency + 'ms (RTT only)');

                        return { success: true, latency: latency, colo: colo, testUrl: testUrl };
                    } catch (error) {
                        const errorMsg = error.name === 'AbortError' ? '${isFarsi ? 'زمان تمام شد' : '超时'}' : error.message;
                        console.log('[LatencyTest] Error:', errorMsg, 'URL:', testUrl);
                        return { success: false, latency: -1, error: errorMsg, colo: '', testUrl: testUrl };
                    }
                }
            });
        </script>
    </body>
    </html>`;
        return new Response(pageHtml, { 
            status: 200, 
            headers: { 'Content-Type': 'text/html; charset=utf-8' } 
        });
    }

    async function parseTrojanHeader(buffer, ut) {
        const bytes = toUint8Array(buffer);
        const passwordToHash = tp || ut;
        const sha224Password = await sha224Hash(passwordToHash);

        if (bytes.byteLength < 56) {
            return {
                hasError: true,
                message: "invalid " + atob('dHJvamFu') + " data - too short"
            };
        }
        let crLfIndex = 56;
        if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) {
            return {
                hasError: true,
                message: "invalid " + atob('dHJvamFu') + " header format (missing CR LF)"
            };
        }
        const password = sharedDecoder.decode(bytes.subarray(0, crLfIndex));
        if (password !== sha224Password) {
            return {
                hasError: true,
                message: "invalid " + atob('dHJvamFu') + " password"
            };
        }

        const socks5DataBuffer = bytes.subarray(crLfIndex + 2);
        if (socks5DataBuffer.byteLength < 6) {
            return {
                hasError: true,
                message: atob('aW52YWxpZCBTT0NLUzUgcmVxdWVzdCBkYXRh')
            };
        }

        const view = new DataView(socks5DataBuffer.buffer, socks5DataBuffer.byteOffset, socks5DataBuffer.byteLength);
        const cmd = view.getUint8(0);
        if (cmd !== 1) {
            return {
                hasError: true,
                message: "unsupported command, only TCP (CONNECT) is allowed"
            };
        }

        const atype = view.getUint8(1);
        let addressLength = 0;
        let addressIndex = 2;
        let address = "";
        switch (atype) {
            case 1:
                addressLength = 4;
                address = socks5DataBuffer.subarray(addressIndex, addressIndex + addressLength).join(".");
                break;
            case 3:
                addressLength = socks5DataBuffer[addressIndex];
                addressIndex += 1;
                address = sharedDecoder.decode(socks5DataBuffer.subarray(addressIndex, addressIndex + addressLength));
                break;
            case 4:
                addressLength = 16;
                const dataView = new DataView(socks5DataBuffer.buffer, socks5DataBuffer.byteOffset + addressIndex, addressLength);
                const ipv6 = [];
                for (let i = 0; i < 8; i++) {
                    ipv6.push(dataView.getUint16(i * 2).toString(16));
                }
                address = ipv6.join(":");
                break;
            default:
                return {
                    hasError: true,
                    message: `invalid addressType is ${atype}`
                };
        }

        if (!address) {
            return {
                hasError: true,
                message: `address is empty, addressType is ${atype}`
            };
        }

        const portIndex = addressIndex + addressLength;
        const portRemote = new DataView(socks5DataBuffer.buffer, socks5DataBuffer.byteOffset + portIndex, 2).getUint16(0);

        return {
            hasError: false,
            addressRemote: address,
            addressType: atype,
            port: portRemote,
            hostname: address,
            rawClientData: socks5DataBuffer.subarray(portIndex + 4)
        };
    }

    async function sha224Hash(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);

        const K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];

        let H = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ];

        const msgLen = data.length;
        const bitLen = msgLen * 8;
        const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
        const padded = new Uint8Array(paddedLen);
        padded.set(data);
        padded[msgLen] = 0x80;

        const view = new DataView(padded.buffer);
        view.setUint32(paddedLen - 4, bitLen, false);

        for (let chunk = 0; chunk < paddedLen; chunk += 64) {
            const W = new Uint32Array(64);

            for (let i = 0; i < 16; i++) {
                W[i] = view.getUint32(chunk + i * 4, false);
            }

            for (let i = 16; i < 64; i++) {
                const s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >>> 3);
                const s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >>> 10);
                W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
            }

            let [a, b, c, d, e, f, g, h] = H;

            for (let i = 0; i < 64; i++) {
                const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
                const ch = (e & f) ^ (~e & g);
                const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
                const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const temp2 = (S0 + maj) >>> 0;

                h = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }

            H[0] = (H[0] + a) >>> 0;
            H[1] = (H[1] + b) >>> 0;
            H[2] = (H[2] + c) >>> 0;
            H[3] = (H[3] + d) >>> 0;
            H[4] = (H[4] + e) >>> 0;
            H[5] = (H[5] + f) >>> 0;
            H[6] = (H[6] + g) >>> 0;
            H[7] = (H[7] + h) >>> 0;
        }

        const result = [];
        for (let i = 0; i < 7; i++) {
            result.push(
                ((H[i] >>> 24) & 0xff).toString(16).padStart(2, '0'),
                ((H[i] >>> 16) & 0xff).toString(16).padStart(2, '0'),
                ((H[i] >>> 8) & 0xff).toString(16).padStart(2, '0'),
                (H[i] & 0xff).toString(16).padStart(2, '0')
            );
        }

        return result.join('');
    }

    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }

    let ACTIVE_CONNECTIONS = 0;
    const XHTTP_BUFFER_SIZE = 128 * 1024;
    const CONNECT_TIMEOUT_MS = 5000;
    const IDLE_TIMEOUT_MS = 45000;
    const MAX_RETRIES = 2;
    const MAX_CONCURRENT = 32;

    function xhttp_sleep(ms) {
        return new Promise((r) => setTimeout(r, ms));
    }

    function validate_uuid_xhttp(id, uuid) {
        for (let index = 0; index < 16; index++) {
            if (id[index] !== uuid[index]) {
                return false;
            }
        }
        return true;
    }

    class XhttpCounter {
        #total

        constructor() {
            this.#total = 0;
        }

        get() {
            return this.#total;
        }

        add(size) {
            this.#total += size;
        }
    }

    function concat_typed_arrays(first, ...args) {
        let len = first.length;
        for (let a of args) {
            len += a.length;
        }
        const r = new first.constructor(len);
        r.set(first, 0);
        len = first.length;
        for (let a of args) {
            r.set(a, len);
            len += a.length;
        }
        return r;
    }

    function parse_uuid_xhttp(uuid) {
        uuid = uuid.replaceAll('-', '');
        const r = [];
        for (let index = 0; index < 16; index++) {
            const v = parseInt(uuid.substr(index * 2, 2), 16);
            r.push(v);
        }
        return r;
    }

    function get_xhttp_buffer(size) {
        return new Uint8Array(new ArrayBuffer(size || XHTTP_BUFFER_SIZE));
    }

    async function read_xhttp_header(readable, uuid_str) {
        const reader = readable.getReader({ mode: 'byob' });

        try {
            let r = await reader.readAtLeast(1 + 16 + 1, get_xhttp_buffer());
            let rlen = 0;
            let idx = 0;
            let cache = r.value;
            rlen += r.value.length;

            const version = cache[0];
            const id = cache.slice(1, 1 + 16);
            const uuid = parse_uuid_xhttp(uuid_str);
            if (!validate_uuid_xhttp(id, uuid)) {
                return `invalid UUID`;
            }
            const pb_len = cache[1 + 16];
            const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1;

            if (addr_plus1 + 1 > rlen) {
                if (r.done) {
                    return `header too short`;
                }
                idx = addr_plus1 + 1 - rlen;
                r = await reader.readAtLeast(idx, get_xhttp_buffer());
                rlen += r.value.length;
                cache = concat_typed_arrays(cache, r.value);
            }

            const cmd = cache[1 + 16 + 1 + pb_len];
            if (cmd !== 1) {
                return `unsupported command: ${cmd}`;
            }
            const port = (cache[addr_plus1 - 1 - 2] << 8) + cache[addr_plus1 - 1 - 1];
            const atype = cache[addr_plus1 - 1];
            let header_len = -1;
            if (atype === ADDRESS_TYPE_IPV4) {
                header_len = addr_plus1 + 4;
            } else if (atype === ADDRESS_TYPE_IPV6) {
                header_len = addr_plus1 + 16;
            } else if (atype === ADDRESS_TYPE_URL) {
                header_len = addr_plus1 + 1 + cache[addr_plus1];
            }

            if (header_len < 0) {
                return 'read address type failed';
            }

            idx = header_len - rlen;
            if (idx > 0) {
                if (r.done) {
                    return `read address failed`;
                }
                r = await reader.readAtLeast(idx, get_xhttp_buffer());
                rlen += r.value.length;
                cache = concat_typed_arrays(cache, r.value);
            }

            let hostname = '';
            idx = addr_plus1;
            switch (atype) {
                case ADDRESS_TYPE_IPV4:
                    hostname = cache.slice(idx, idx + 4).join('.');
                    break;
                case ADDRESS_TYPE_URL:
                    hostname = new TextDecoder().decode(
                        cache.slice(idx + 1, idx + 1 + cache[idx]),
                    );
                    break;
                case ADDRESS_TYPE_IPV6:
                    hostname = cache
                        .slice(idx, idx + 16)
                        .reduce(
                            (s, b2, i2, a) =>
                                i2 % 2
                                    ? s.concat(((a[i2 - 1] << 8) + b2).toString(16))
                                    : s,
                            [],
                        )
                        .join(':');
                    break;
            }

            if (hostname.length < 1) {
                return 'failed to parse hostname';
            }

            const data = cache.slice(header_len);
            return {
                hostname,
                port,
                data,
                resp: new Uint8Array([version, 0]),
                reader,
                done: r.done,
            };
        } catch (error) {
            try { reader.releaseLock(); } catch (_) {}
            throw error;
        }
    }

    async function upload_to_remote_xhttp(counter, writer, httpx) {
        async function inner_upload(d) {
            if (!d || d.length === 0) {
                return;
            }
            counter.add(d.length);
            try {
                await writer.write(d);
            } catch (error) {
                throw error;
            }
        }

        try {
            await inner_upload(httpx.data);
            let chunkCount = 0;
            while (!httpx.done) {
                const r = await httpx.reader.read(get_xhttp_buffer());
                if (r.done) break;
                await inner_upload(r.value);
                httpx.done = r.done;
                chunkCount++;
                if (chunkCount % 10 === 0) {
                    await xhttp_sleep(0);
                }
                if (!r.value || r.value.length === 0) {
                    await xhttp_sleep(2);
                }
            }
        } catch (error) {
            throw error;
        }
    }

    function create_xhttp_uploader(httpx, writable) {
        const counter = new XhttpCounter();
        const writer = writable.getWriter();

        const done = (async () => {
            try {
                await upload_to_remote_xhttp(counter, writer, httpx);
            } catch (error) {
                throw error;
            } finally {
                try {
                    await writer.close();
                } catch (error) {
                    
                }
            }
        })();

        return {
            counter,
            done,
            abort: () => {
                try { writer.abort(); } catch (_) {}
            }
        };
    }

    function create_xhttp_downloader(resp, remote_readable) {
        const counter = new XhttpCounter();
        let stream;

        const done = new Promise((resolve, reject) => {
            stream = new TransformStream(
                {
                    start(controller) {
                        counter.add(resp.length);
                        controller.enqueue(resp);
                    },
                    transform(chunk, controller) {
                        counter.add(chunk.length);
                        controller.enqueue(chunk);
                    },
                    cancel(reason) {
                        reject(`download cancelled: ${reason}`);
                    },
                },
                null,
                new ByteLengthQueuingStrategy({ highWaterMark: XHTTP_BUFFER_SIZE }),
            );

            let lastActivity = Date.now();
            const idleTimer = setInterval(() => {
                if (Date.now() - lastActivity > IDLE_TIMEOUT_MS) {
                    try {
                        stream.writable.abort?.('idle timeout');
                    } catch (_) {}
                    clearInterval(idleTimer);
                    reject('idle timeout');
                }
            }, 5000);

            const reader = remote_readable.getReader();
            const writer = stream.writable.getWriter();

            ;(async () => {
                try {
                    let chunkCount = 0;
                    while (true) {
                        const r = await reader.read();
                        if (r.done) {
                            break;
                        }
                        lastActivity = Date.now();
                        await writer.write(r.value);
                        chunkCount++;
                        if (chunkCount % 5 === 0) {
                            await xhttp_sleep(0);
                        }
                    }
                    await writer.close();
                    resolve();
                } catch (err) {
                    reject(err);
                } finally {
                    try { 
                        reader.releaseLock(); 
                    } catch (_) {}
                    try { 
                        writer.releaseLock(); 
                    } catch (_) {}
                    clearInterval(idleTimer);
                }
            })();
        });

        return {
            readable: stream.readable,
            counter,
            done,
            abort: () => {
                try { stream.readable.cancel(); } catch (_) {}
                try { stream.writable.abort(); } catch (_) {}
            }
        };
    }

    async function connect_to_remote_xhttp(httpx, ...remotes) {
        let attempt = 0;
        let lastErr;

        const connectionList = [httpx.hostname, ...remotes.filter(r => r && r !== httpx.hostname)];

        for (const hostname of connectionList) {
            if (!hostname) continue;

            attempt = 0;
            while (attempt < MAX_RETRIES) {
                attempt++;
                try {
                    const remote = connect({ hostname, port: httpx.port });
                    const timeoutPromise = xhttp_sleep(CONNECT_TIMEOUT_MS).then(() => {
                        throw new Error(atob('Y29ubmVjdCB0aW1lb3V0'));
                    });

                    await Promise.race([remote.opened, timeoutPromise]);

                    const uploader = create_xhttp_uploader(httpx, remote.writable);
                    const downloader = create_xhttp_downloader(httpx.resp, remote.readable);

                    return { 
                        downloader, 
                        uploader,
                        close: () => {
                            try { remote.close(); } catch (_) {}
                        }
                    };
                } catch (err) {
                    lastErr = err;
                    if (attempt < MAX_RETRIES) {
                        await xhttp_sleep(500 * attempt);
                    }
                }
            }
        }

        return null;
    }

    async function handle_xhttp_client(body, uuid) {
        if (ACTIVE_CONNECTIONS >= MAX_CONCURRENT) {
            return new Response('Too many connections', { status: 429 });
        }

        ACTIVE_CONNECTIONS++;
        
        let cleaned = false;
        const cleanup = () => {
            if (!cleaned) {
                ACTIVE_CONNECTIONS = Math.max(0, ACTIVE_CONNECTIONS - 1);
                cleaned = true;
            }
        };

        try {
            const httpx = await read_xhttp_header(body, uuid);
            if (typeof httpx !== 'object' || !httpx) {
                return null;
            }

            const remoteConnection = await connect_to_remote_xhttp(httpx, fallbackAddress, '13.230.34.30');
            if (remoteConnection === null) {
                return null;
            }

            const connectionClosed = Promise.race([
                (async () => {
                    try {
                        await remoteConnection.downloader.done;
                    } catch (err) {
                        
                    }
                })(),
                (async () => {
                    try {
                        await remoteConnection.uploader.done;
                    } catch (err) {
                        
                    }
                })(),
                xhttp_sleep(IDLE_TIMEOUT_MS).then(() => {
                    
                })
            ]).finally(() => {
                try { remoteConnection.close(); } catch (_) {}
                try { remoteConnection.downloader.abort(); } catch (_) {}
                try { remoteConnection.uploader.abort(); } catch (_) {}
                
                cleanup();
            });

            return {
                readable: remoteConnection.downloader.readable,
                closed: connectionClosed
            };
        } catch (error) {
            cleanup();
            return null;
        }
    }

    async function handleXhttpPost(request) {
        try {
            return await handle_xhttp_client(request.body, at);
        } catch (err) {
            return null;
        }
    }

    function base64ToArray(b64Str) {
        if (!b64Str) return { error: null };
        try { b64Str = b64Str.replace(/-/g, '+').replace(/_/g, '/'); return { earlyData: Uint8Array.from(atob(b64Str), (c) => c.charCodeAt(0)).buffer, error: null }; } 
        catch (error) { return { error }; }
    }

    function closeSocketQuietly(socket) { try { if (socket.readyState === 1 || socket.readyState === 2) socket.close(); } catch (error) {} }

    const hexTable = Array.from({ length: 256 }, (v, i) => (i + 256).toString(16).slice(1));
    function formatIdentifier(arr, offset = 0) {
        const id = (hexTable[arr[offset]]+hexTable[arr[offset+1]]+hexTable[arr[offset+2]]+hexTable[arr[offset+3]]+"-"+hexTable[arr[offset+4]]+hexTable[arr[offset+5]]+"-"+hexTable[arr[offset+6]]+hexTable[arr[offset+7]]+"-"+hexTable[arr[offset+8]]+hexTable[arr[offset+9]]+"-"+hexTable[arr[offset+10]]+hexTable[arr[offset+11]]+hexTable[arr[offset+12]]+hexTable[arr[offset+13]]+hexTable[arr[offset+14]]+hexTable[arr[offset+15]]).toLowerCase();
        if (!isValidFormat(id)) throw new TypeError(E_INVALID_ID_STR);
        return id;
    }

    async function fetchAndParseNewIPs() {
        const url = piu;
        try {
            const urls = url.includes(',') ? url.split(',').map(u => u.trim()).filter(u => u) : [url];
            const apiResults = await fetchPreferredAPI(urls, '443', 5000);

            if (apiResults.length > 0) {
                const results = [];
                const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
                
                for (const item of apiResults) {
                    const match = item.match(regex);
                    if (match) {
                        results.push({
                            ip: match[1],
                            port: parseInt(match[2] || '443', 10),
                            name: match[3]?.trim() || match[1]
                        });
                    }
                }
                return results;
            }

            const response = await fetch(url);
            if (!response.ok) return [];
            const text = await response.text();
            const results = [];
            const lines = text.trim().replace(/\r/g, "").split('\n');
            const simpleRegex = /^([^:]+):(\d+)#(.*)$/;

            for (const line of lines) {
                const trimmedLine = line.trim();
                if (!trimmedLine) continue;
                const match = trimmedLine.match(simpleRegex);
                if (match) {
                    results.push({
                        ip: match[1],
                        port: parseInt(match[2], 10),
                        name: match[3].trim() || match[1]
                    });
                }
            }
            return results;
        } catch (error) {
            return [];
        }
    }

    function generateLinksFromNewIPs(list, user, workerDomain, echConfig = null, skipNumbering = false, aliasNamer = null) {
        const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
        const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
        const links = [];
        const wsPath = '/?ed=2048';
        const proto = atob('dmxlc3M=');

        const makeNodeName = aliasNamer || createCompactNodeNamer(skipNumbering);

        for (const item of list) {
            const port = item.port;
            const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;

            if (CF_HTTPS_PORTS.includes(port)) {
                const wsNodeName = makeNodeName(item);
                let link = `${proto}://${user}@${safeIP}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=${enableECH ? 'chrome' : 'randomized'}&type=ws&host=${workerDomain}&path=${wsPath}`;
                if (customALPN) link += `&alpn=${encodeURIComponent(customALPN)}`;

                // 如果启用了ECH，添加ech参数（ECH需要伪装成Chrome浏览器）
                if (enableECH) {
                    const dnsServer = customDNS || 'https://223.5.5.5/dns-query';
                    const echDomain = customECHDomain || 'cloudflare-ech.com';
                    link += `&ech=${encodeURIComponent(`${echDomain}+${dnsServer}`)}`;
                }

                link += `#${encodeURIComponent(wsNodeName)}`;
                links.push(link);
            } else if (CF_HTTP_PORTS.includes(port)) {
                if (!disableNonTLS) {
                    const wsNodeName = makeNodeName(item);
                    const link = `${proto}://${user}@${safeIP}:${port}?encryption=none&security=none&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
                    links.push(link);
                }
            } else {
                const wsNodeName = makeNodeName(item);
                let link = `${proto}://${user}@${safeIP}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=${enableECH ? 'chrome' : 'randomized'}&type=ws&host=${workerDomain}&path=${wsPath}`;
                if (customALPN) link += `&alpn=${encodeURIComponent(customALPN)}`;

                // 如果启用了ECH，添加ech参数（ECH需要伪装成Chrome浏览器）
                if (enableECH) {
                    const dnsServer = customDNS || 'https://223.5.5.5/dns-query';
                    const echDomain = customECHDomain || 'cloudflare-ech.com';
                    link += `&ech=${encodeURIComponent(`${echDomain}+${dnsServer}`)}`;
                }

                link += `#${encodeURIComponent(wsNodeName)}`;
                links.push(link);
            }
        }
        return links;
    }

    function generateXhttpLinksFromSource(list, user, workerDomain, echConfig = null, skipNumbering = false, aliasNamer = null) {
        const links = [];
        const nodePath = user.substring(0, 8);

        const makeNodeName = aliasNamer || createCompactNodeNamer(skipNumbering);

        for (const item of list) {
            const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;
            const port = item.port || 443;
            const wsNodeName = makeNodeName(item);

            const params = new URLSearchParams({
                encryption: 'none',
                security: 'tls',
                sni: workerDomain,
                fp: 'chrome',
                type: 'xhttp',
                host: workerDomain,
                path: `/${nodePath}`,
                mode: 'stream-one'
            });
            applyALPNParam(params);

            if (enableECH) {
                const dnsServer = customDNS || 'https://223.5.5.5/dns-query';
                const echDomain = customECHDomain || 'cloudflare-ech.com';
                params.set('ech', `${echDomain}+${dnsServer}`);
            }

            links.push(`vless://${user}@${safeIP}:${port}?${params.toString()}#${encodeURIComponent(wsNodeName)}`);
        }
        return links;
    }

    async function generateTrojanLinksFromNewIPs(list, user, workerDomain, echConfig = null, skipNumbering = false, aliasNamer = null) {
        const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
        const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

        const links = [];
        const wsPath = '/?ed=2048';

        const password = tp || user;

        const makeNodeName = aliasNamer || createCompactNodeNamer(skipNumbering);

        for (const item of list) {
            const port = item.port;
            const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;

            if (CF_HTTPS_PORTS.includes(port)) {
                const wsNodeName = makeNodeName(item);
                let link = `${atob('dHJvamFuOi8v')}${password}@${safeIP}:${port}?security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}`;
                if (customALPN) link += `&alpn=${encodeURIComponent(customALPN)}`;

                // 如果启用了ECH，添加ech参数（ECH需要伪装成Chrome浏览器）
                if (enableECH) {
                    const dnsServer = customDNS || 'https://223.5.5.5/dns-query';
                    const echDomain = customECHDomain || 'cloudflare-ech.com';
                    link += `&ech=${encodeURIComponent(`${echDomain}+${dnsServer}`)}`;
                }

                link += `#${encodeURIComponent(wsNodeName)}`;
                links.push(link);
            } else if (CF_HTTP_PORTS.includes(port)) {
                if (!disableNonTLS) {
                    const wsNodeName = makeNodeName(item);
                    const link = `${atob('dHJvamFuOi8v')}${password}@${safeIP}:${port}?security=none&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
                    links.push(link);
                }
            } else {
                const wsNodeName = makeNodeName(item);
                let link = `${atob('dHJvamFuOi8v')}${password}@${safeIP}:${port}?security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}`;
                if (customALPN) link += `&alpn=${encodeURIComponent(customALPN)}`;

                // 如果启用了ECH，添加ech参数（ECH需要伪装成Chrome浏览器）
                if (enableECH) {
                    const dnsServer = customDNS || 'https://223.5.5.5/dns-query';
                    const echDomain = customECHDomain || 'cloudflare-ech.com';
                    link += `&ech=${encodeURIComponent(`${echDomain}+${dnsServer}`)}`;
                }
                link += `#${encodeURIComponent(wsNodeName)}`;
                links.push(link);
            }
        }
        return links;
    }

    async function handleConfigAPI(request) {
        if (request.method === 'GET') {

            if (!kvStore) {
                return new Response(JSON.stringify({
                    error: 'KV存储未配置',
                    kvEnabled: false
                }), {
                    status: 503,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            return new Response(JSON.stringify({
                ...kvConfig,
                kvEnabled: true
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        } else if (request.method === 'POST') {
            
            if (!kvStore) {
                return new Response(JSON.stringify({
                    success: false,
                    message: 'KV存储未配置，无法保存配置'
                }), {
                    status: 503,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            try {
                const newConfig = await request.json();
                
                for (const [key, value] of Object.entries(newConfig)) {
                    if (value === '' || value === null || value === undefined) {
                        delete kvConfig[key];
                    } else {
                        kvConfig[key] = value;
                    }
                }

                await saveKVConfig();

                updateConfigVariables();
                
                if (newConfig.yx !== undefined) {
                    updateCustomPreferredFromYx();
                }

                return new Response(JSON.stringify({
                    success: true,
                    message: '配置已保存',
                    config: kvConfig
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            } catch (error) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '保存配置失败: ' + error.message
                }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }

        return new Response(JSON.stringify({ error: 'Method not allowed' }), { 
            status: 405,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    async function handlePreferredIPsAPI(request) {
        if (!kvStore) {
            return new Response(JSON.stringify({
                success: false,
                error: 'KV存储未配置',
                message: '需要配置KV存储才能使用此功能'
            }), {
                status: 503,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const ae = getConfigValue('ae', '') === 'yes';
        if (!ae) {
            return new Response(JSON.stringify({
                success: false,
                error: 'API功能未启用',
                message: '出于安全考虑，优选IP API功能默认关闭。请在配置管理页面开启"允许API管理"选项后使用。'
            }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        try {
            if (request.method === 'GET') {
                
                const yxValue = getConfigValue('yx', '');
                const pi = parseYxToArray(yxValue);
                
                return new Response(JSON.stringify({
                    success: true,
                    count: pi.length,
                    data: pi
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            } else if (request.method === 'POST') {
                const body = await request.json();
                const ipsToAdd = Array.isArray(body) ? body : [body];

                if (ipsToAdd.length === 0) {
                    return new Response(JSON.stringify({
                        success: false,
                        error: '请求数据为空',
                        message: '请提供IP数据'
                    }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                const yxValue = getConfigValue('yx', '');
                let pi = parseYxToArray(yxValue);

                const addedIPs = [];
                const skippedIPs = [];
                const errors = [];

                for (const item of ipsToAdd) {
                    if (!item.ip) {
                        errors.push({ ip: '未知', reason: 'IP地址是必需的' });
                        continue;
                    }

                    const port = item.port || 443;
                    const name = item.name || `API优选-${item.ip}:${port}`;

                    if (!isValidIP(item.ip) && !isValidDomain(item.ip)) {
                        errors.push({ ip: item.ip, reason: '无效的IP或域名格式' });
                        continue;
                    }

                    const exists = pi.some(existItem => 
                        existItem.ip === item.ip && existItem.port === port
                    );

                    if (exists) {
                        skippedIPs.push({ ip: item.ip, port: port, reason: '已存在' });
                        continue;
                    }

                    const newIP = {
                        ip: item.ip,
                        port: port,
                        name: name,
                        addedAt: new Date().toISOString()
                    };

                    pi.push(newIP);
                    addedIPs.push(newIP);
                }

                if (addedIPs.length > 0) {
                    const newYxValue = arrayToYx(pi);
                    await setConfigValue('yx', newYxValue);
                    updateCustomPreferredFromYx();
                }

                return new Response(JSON.stringify({
                    success: addedIPs.length > 0,
                    message: `成功添加 ${addedIPs.length} 个IP`,
                    added: addedIPs.length,
                    skipped: skippedIPs.length,
                    errors: errors.length,
                    data: {
                        addedIPs: addedIPs,
                        skippedIPs: skippedIPs.length > 0 ? skippedIPs : undefined,
                        errors: errors.length > 0 ? errors : undefined
                    }
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            } else if (request.method === 'DELETE') {
                const body = await request.json();

                if (body.all === true) {
                    const yxValue = getConfigValue('yx', '');
                    const pi = parseYxToArray(yxValue);
                    const deletedCount = pi.length;

                    await setConfigValue('yx', '');
                    updateCustomPreferredFromYx();

                    return new Response(JSON.stringify({
                        success: true,
                        message: `已清空所有优选IP，共删除 ${deletedCount} 个`,
                        deletedCount: deletedCount
                    }), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                if (!body.ip) {
                    return new Response(JSON.stringify({
                        success: false,
                        error: 'IP地址是必需的',
                        message: '请提供要删除的ip字段，或使用 {"all": true} 清空所有'
                    }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                const port = body.port || 443;

                const yxValue = getConfigValue('yx', '');
                let pi = parseYxToArray(yxValue);
                const initialLength = pi.length;

                const filteredIPs = pi.filter(item => 
                    !(item.ip === body.ip && item.port === port)
                );

                if (filteredIPs.length === initialLength) {
                    return new Response(JSON.stringify({
                        success: false,
                        error: '优选IP不存在',
                        message: `${body.ip}:${port} 未找到`
                    }), {
                        status: 404,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                const newYxValue = arrayToYx(filteredIPs);
                await setConfigValue('yx', newYxValue);
                updateCustomPreferredFromYx();

                return new Response(JSON.stringify({
                    success: true,
                    message: '优选IP已删除',
                    deleted: { ip: body.ip, port: port }
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            } else {
                return new Response(JSON.stringify({
                    success: false,
                    error: '不支持的请求方法',
                    message: '支持的方法: GET, POST, DELETE'
                }), {
                    status: 405,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        } catch (error) {
            return new Response(JSON.stringify({
                success: false,
                error: '处理请求失败',
                message: error.message
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    function updateConfigVariables() {
        const manualRegion = getConfigValue('wk', '');
        if (manualRegion && manualRegion.trim()) {
            manualWorkerRegion = manualRegion.trim().toUpperCase();
            currentWorkerRegion = manualWorkerRegion;
        } else {
            const ci = getConfigValue('p', '');
            if (ci && ci.trim()) {
                currentWorkerRegion = 'CUSTOM';
            } else {
                manualWorkerRegion = '';
            }
        }

        const regionMatchingControl = getConfigValue('rm', '');
        if (regionMatchingControl && regionMatchingControl.toLowerCase() === 'no') {
            enableRegionMatching = false;
        } else {
            enableRegionMatching = true;
        }

        const vlessControl = getConfigValue('ev', '');
        if (vlessControl !== undefined && vlessControl !== '') {
            ev = vlessControl === 'yes' || vlessControl === true || vlessControl === 'true';
        }

        const tjControl = getConfigValue('et', '');
        if (tjControl !== undefined && tjControl !== '') {
            et = tjControl === 'yes' || tjControl === true || tjControl === 'true';
        }

        tp = getConfigValue('tp', '') || '';

        const xhttpControl = getConfigValue('ex', '');
        if (xhttpControl !== undefined && xhttpControl !== '') {
            ex = xhttpControl === 'yes' || xhttpControl === true || xhttpControl === 'true';
        }

        if (!ev && !et && !ex) {
            ev = true;
        }

        scu = getConfigValue('scu', '') || 'https://url.v1.mk/sub';

        const preferredDomainsControl = getConfigValue('epd', 'no');
        if (preferredDomainsControl !== undefined && preferredDomainsControl !== '') {
            epd = preferredDomainsControl !== 'no' && preferredDomainsControl !== false && preferredDomainsControl !== 'false';
        }

        const preferredIPsControl = getConfigValue('epi', '');
        if (preferredIPsControl !== undefined && preferredIPsControl !== '') {
            epi = preferredIPsControl !== 'no' && preferredIPsControl !== false && preferredIPsControl !== 'false';
        }

        const githubIPsControl = getConfigValue('egi', '');
        if (githubIPsControl !== undefined && githubIPsControl !== '') {
            egi = githubIPsControl !== 'no' && githubIPsControl !== false && githubIPsControl !== 'false';
        }

        const nativeAddressControl = getConfigValue('ena', '');
        if (nativeAddressControl !== undefined && nativeAddressControl !== '') {
            ena = nativeAddressControl !== 'no' && nativeAddressControl !== false && nativeAddressControl !== 'false';
        }

        const echControl = getConfigValue('ech', '');
        if (echControl !== undefined && echControl !== '') {
            enableECH = echControl === 'yes' || echControl === true || echControl === 'true';
        }

        // 更新自定义DNS和ECH域名
        const customDNSValue = getConfigValue('customDNS', '');
        if (customDNSValue && customDNSValue.trim()) {
            customDNS = customDNSValue.trim();
        } else {
            customDNS = 'https://223.5.5.5/dns-query';
        }

        const customECHDomainValue = getConfigValue('customECHDomain', '');
        if (customECHDomainValue && customECHDomainValue.trim()) {
            customECHDomain = customECHDomainValue.trim();
        } else {
            customECHDomain = 'cloudflare-ech.com';
        }

        customALPN = normalizeALPN(getConfigValue('alpn', ''));

        // 如果启用了ECH，自动启用仅TLS模式（避免80端口干扰）
        // ECH需要TLS才能工作，所以必须禁用非TLS节点
        if (enableECH) {
            disableNonTLS = true;
        }

        // 检查dkby配置（如果手动设置了dkby=yes，也会启用仅TLS）
        const dkbyControl = getConfigValue('dkby', '');
        if (dkbyControl && dkbyControl.toLowerCase() === 'yes') {
            disableNonTLS = true;
        }

        cp = getConfigValue('d', '') || '';

        piu = getConfigValue('yxURL', '') || '';

        const envFallback = getConfigValue('p', '');
        if (envFallback) {
            fallbackAddress = envFallback.trim();
        } else {
            fallbackAddress = '';
        }

        socks5Config = getConfigValue('s', '') || '';
        if (socks5Config) {
            try {
                parsedSocks5Config = parseSocksConfig(socks5Config);
                isSocksEnabled = true;
            } catch (err) {
                isSocksEnabled = false;
            }
        } else {
            isSocksEnabled = false;
        }

        const yxbyControl = getConfigValue('yxby', '');
        if (yxbyControl && yxbyControl.toLowerCase() === 'yes') {
            disablePreferred = true;
        } else {
            disablePreferred = false;
        }
    }

    function updateCustomPreferredFromYx() {
        const yxValue = getConfigValue('yx', '');
        if (yxValue) {
            try {
                const preferredList = yxValue.split(',').map(item => item.trim()).filter(item => item);
                customPreferredIPs = [];
                customPreferredDomains = [];

                preferredList.forEach(item => {
                    let nodeName = '';
                    let addressPart = item;

                    if (item.includes('#')) {
                        const parts = item.split('#');
                        addressPart = parts[0].trim();
                        nodeName = parts[1].trim();
                    }

                    const { address, port } = parseAddressAndPort(addressPart);

                    if (!nodeName) {
                        nodeName = '自定义优选-' + address + (port ? ':' + port : '');
                    }

                    if (isValidIP(address)) {
                        customPreferredIPs.push({ 
                            ip: address, 
                            port: port,
                            isp: nodeName
                        });
                    } else {
                        customPreferredDomains.push({ 
                            domain: address, 
                            port: port,
                            name: nodeName
                        });
                    }
                });
            } catch (err) {
                customPreferredIPs = [];
                customPreferredDomains = [];
            }
        } else {
            customPreferredIPs = [];
            customPreferredDomains = [];
        }
    }

    function parseYxToArray(yxValue) {
        if (!yxValue || !yxValue.trim()) return [];

        const items = yxValue.split(',').map(item => item.trim()).filter(item => item);
        const result = [];

        for (const item of items) {
            let nodeName = '';
            let addressPart = item;

            if (item.includes('#')) {
                const parts = item.split('#');
                addressPart = parts[0].trim();
                nodeName = parts[1].trim();
            }

            const { address, port } = parseAddressAndPort(addressPart);

            if (!nodeName) {
                nodeName = address + (port ? ':' + port : '');
            }

            result.push({
                ip: address,
                port: port || 443,
                name: nodeName,
                addedAt: new Date().toISOString()
            });
        }

        return result;
    }

    function arrayToYx(array) {
        if (!array || array.length === 0) return '';

        return array.map(item => {
            const port = item.port || 443;
            return `${item.ip}:${port}#${item.name}`;
        }).join(',');
    }

    function isValidDomain(domain) {
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        return domainRegex.test(domain);
    }

    async function parseTextToArray(content) {
        var processed = content.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
        if (processed.charAt(0) == ',') processed = processed.slice(1);
        if (processed.charAt(processed.length - 1) == ',') processed = processed.slice(0, processed.length - 1);
        return processed.split(',');
    }

    async function fetchPreferredAPI(urls, defaultPort = '443', timeout = 3000) {
        if (!urls?.length) return [];
        const results = new Set();
        await Promise.allSettled(urls.map(async (url) => {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), timeout);
                const response = await fetch(url, { signal: controller.signal });
                clearTimeout(timeoutId);
                let text = '';
                try {
                    const buffer = await response.arrayBuffer();
                    const contentType = (response.headers.get('content-type') || '').toLowerCase();
                    const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

                    let decoders = ['utf-8', 'gb2312'];
                    if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
                        decoders = ['gb2312', 'utf-8'];
                    }

                    let decodeSuccess = false;
                    for (const decoder of decoders) {
                        try {
                            const decoded = new TextDecoder(decoder).decode(buffer);
                            if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
                                text = decoded;
                                decodeSuccess = true;
                                break;
                            } else if (decoded && decoded.length > 0) {
                                continue;
                            }
                        } catch (e) {
                            continue;
                        }
                    }

                    if (!decodeSuccess) {
                        text = await response.text();
                    }

                    if (!text || text.trim().length === 0) {
                        return;
                    }
                } catch (e) {
                    return;
                }
                const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
                const isCSV = lines.length > 1 && lines[0].includes(',');
                const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
                if (!isCSV) {
                    lines.forEach(line => {
                        const hashIndex = line.indexOf('#');
                        const [hostPart, remark] = hashIndex > -1 ? [line.substring(0, hashIndex), line.substring(hashIndex)] : [line, ''];
                        let hasPort = false;
                        if (hostPart.startsWith('[')) {
                            hasPort = /\]:(\d+)$/.test(hostPart);
                        } else {
                            const colonIndex = hostPart.lastIndexOf(':');
                            hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
                        }
                        const port = new URL(url).searchParams.get('port') || defaultPort;
                        results.add(hasPort ? line : `${hostPart}:${port}${remark}`);
                    });
                } else {
                    const headers = lines[0].split(',').map(h => h.trim());
                    const dataLines = lines.slice(1);
                    if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
                        const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
                        const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
                            headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
                        const tlsIdx = headers.indexOf('TLS');
                        dataLines.forEach(line => {
                            const cols = line.split(',').map(c => c.trim());
                            if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
                            const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                            results.add(`${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`);
                        });
                    } else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
                        const ipIdx = headers.findIndex(h => h.includes('IP'));
                        const delayIdx = headers.findIndex(h => h.includes('延迟'));
                        const speedIdx = headers.findIndex(h => h.includes('下载速度'));
                        const port = new URL(url).searchParams.get('port') || defaultPort;
                        dataLines.forEach(line => {
                            const cols = line.split(',').map(c => c.trim());
                            const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                            results.add(`${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`);
                        });
                    }
                }
            } catch (e) { }
        }));
        return Array.from(results);
    }
