    import { connect } from 'cloudflare:sockets';

    let at = '351c9981-04b6-4103-aa4b-864aa9c91469';
    let fallbackAddress = '';
    let fallbackPort = '443';
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

    let scu = 'https://url.v1.mk/sub';  
    // 远程配置URL（硬编码）
    const remoteConfigUrl = 'https://raw.githubusercontent.com/byJoey/test/refs/heads/main/tist.ini';

    let epd = true;   
    let epi = true;       
    let egi = true;          

    let kvStore = null;
    let kvConfig = {};

    const regionMapping = {
        'US': ['🇺🇸 美国', 'US', 'United States'],
        'SG': ['🇸🇬 新加坡', 'SG', 'Singapore'],
        'JP': ['🇯🇵 日本', 'JP', 'Japan'],
        'HK': ['🇭🇰 香港', 'HK', 'Hong Kong'],
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
        { domain: 'ProxyIP.US.CMLiussss.net', region: 'US', regionCode: 'US', port: 443 },
        { domain: 'ProxyIP.SG.CMLiussss.net', region: 'SG', regionCode: 'SG', port: 443 },
        { domain: 'ProxyIP.JP.CMLiussss.net', region: 'JP', regionCode: 'JP', port: 443 },
        { domain: 'ProxyIP.HK.CMLiussss.net', region: 'HK', regionCode: 'HK', port: 443 },
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

    async function loadKVConfig() {
        
        if (!kvStore) {
            return;
        }
        
        try {
            const configData = await kvStore.get('c');
            
            if (configData) {
                kvConfig = JSON.parse(configData);
            } else {
            }
        } catch (error) {
            kvConfig = {};
        }
    }

    async function saveKVConfig() {
        if (!kvStore) {
            return;
        }
        
        try {
            const configString = JSON.stringify(kvConfig);
            await kvStore.put('c', configString);
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
                    'US': 'US', 'SG': 'SG', 'JP': 'JP', 'HK': 'HK', 'KR': 'KR',
                    'DE': 'DE', 'SE': 'SE', 'NL': 'NL', 'FI': 'FI', 'GB': 'GB',
                    'CN': 'HK', 'TW': 'HK', 'AU': 'SG', 'CA': 'US',
                    'FR': 'DE', 'IT': 'DE', 'ES': 'DE', 'CH': 'DE',
                    'AT': 'DE', 'BE': 'NL', 'DK': 'SE', 'NO': 'SE', 'IE': 'GB'
                };
                
                if (countryToRegion[cfCountry]) {
                    return countryToRegion[cfCountry];
                }
            }
            
            return 'HK';
            
        } catch (error) {
            return 'HK';
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

    async function getBestBackupIP(workerRegion = '') {
        
        if (backupIPs.length === 0) {
            return null;
        }
        
        const availableIPs = backupIPs.map(ip => ({ ...ip, available: true }));
        
        if (enableRegionMatching && workerRegion) {
            const sortedIPs = getSmartRegionSelection(workerRegion, availableIPs);
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
            'US': ['SG', 'JP', 'HK', 'KR'], 
            'SG': ['JP', 'HK', 'KR', 'US'], 
            'JP': ['SG', 'HK', 'KR', 'US'], 
            'HK': ['SG', 'JP', 'KR', 'US'], 
            'KR': ['JP', 'HK', 'SG', 'US'], 
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
        const allRegions = ['US', 'SG', 'JP', 'HK', 'KR', 'DE', 'SE', 'NL', 'FI', 'GB'];
        
        return [region, ...nearbyRegions, ...allRegions.filter(r => r !== region && !nearbyRegions.includes(r))];
    }

    function getSmartRegionSelection(workerRegion, availableIPs) {
        
        if (!enableRegionMatching || !workerRegion) {
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
            
            if (!isNaN(port) && port > 0 && port <= 65535) {
                return { address, port };
            }
        }
        
        return { address: input, port: null };
    }

    export default {
        async fetch(request, env, ctx) {
            try {
                
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
                    const fallbackValue = envFallback.toLowerCase();
                    if (fallbackValue.includes(']:')) {
                        const lastColonIndex = fallbackValue.lastIndexOf(':');
                        fallbackPort = fallbackValue.slice(lastColonIndex + 1);
                        fallbackAddress = fallbackValue.slice(0, lastColonIndex);
                    } else if (!fallbackValue.includes(']:') && !fallbackValue.includes(']')) {
                        [fallbackAddress, fallbackPort = '443'] = fallbackValue.split(':');
                    } else {
                        fallbackAddress = fallbackValue;
                        fallbackPort = '443';
                    }
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
                
                const preferredDomainsControl = getConfigValue('epd', env.epd);
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
                
                if (!ev && !et && !ex) {
                    ev = true;
                }

            piu = getConfigValue('yxURL', env.yxURL || env.YXURL) || 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';
            
            cp = getConfigValue('d', env.d || env.D) || '';
            
                const defaultURL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';
            if (piu !== defaultURL) {
                    directDomains.length = 0;
                    customPreferredIPs = [];
                    customPreferredDomains = [];
                }

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
                                    title: '终端',
                                    terminal: '终端',
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
                                    title: 'ترمینال',
                                    terminal: 'ترمینال',
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
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: "Courier New", monospace;
                background: #000; color: #00ff00; min-height: 100vh;
                overflow-x: hidden; position: relative;
                display: flex; justify-content: center; align-items: center;
            }
            .matrix-bg {
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: linear-gradient(45deg, #000 0%, #001100 50%, #000 100%);
                z-index: -1;
                animation: bg-pulse 8s ease-in-out infinite;
            }
            @keyframes bg-pulse {
                0%, 100% { background: linear-gradient(45deg, #000 0%, #001100 50%, #000 100%); }
                50% { background: linear-gradient(45deg, #000 0%, #002200 50%, #000 100%); }
            }
            .matrix-rain {
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,0,0.03) 2px, rgba(0,255,0,0.03) 4px);
                animation: matrix-fall 20s linear infinite;
                z-index: -1;
            }
            @keyframes matrix-fall {
                0% { transform: translateY(-100%); }
                100% { transform: translateY(100vh); }
            }
            .matrix-code-rain {
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                pointer-events: none; z-index: -1;
                overflow: hidden;
            }
            .matrix-column {
                position: absolute; top: -100%; left: 0;
                color: #00ff00; font-family: "Courier New", monospace;
                font-size: 14px; line-height: 1.2;
                animation: matrix-drop 15s linear infinite;
                text-shadow: 0 0 5px #00ff00;
            }
            @keyframes matrix-drop {
                0% { top: -100%; opacity: 1; }
                10% { opacity: 1; }
                90% { opacity: 0.3; }
                100% { top: 100vh; opacity: 0; }
            }
            .matrix-column:nth-child(odd) {
                animation-duration: 12s;
                animation-delay: -2s;
            }
            .matrix-column:nth-child(even) {
                animation-duration: 18s;
                animation-delay: -5s;
            }
            .matrix-column:nth-child(3n) {
                animation-duration: 20s;
                animation-delay: -8s;
            }
            .terminal {
                width: 90%; max-width: 800px; height: 500px;
                background: rgba(0, 0, 0, 0.9);
                border: 2px solid #00ff00;
                border-radius: 8px;
                box-shadow: 0 0 30px rgba(0, 255, 0, 0.5), inset 0 0 20px rgba(0, 255, 0, 0.1);
                backdrop-filter: blur(10px);
                position: relative; z-index: 1;
                overflow: hidden;
            }
            .terminal-header {
                background: rgba(0, 20, 0, 0.8);
                padding: 10px 15px;
                border-bottom: 1px solid #00ff00;
                display: flex; align-items: center;
            }
            .terminal-buttons {
                display: flex; gap: 8px;
            }
            .terminal-button {
                width: 12px; height: 12px; border-radius: 50%;
                background: #ff5f57; border: none;
            }
            .terminal-button:nth-child(2) { background: #ffbd2e; }
            .terminal-button:nth-child(3) { background: #28ca42; }
            .terminal-title {
                margin-left: 15px; color: #00ff00;
                font-size: 14px; font-weight: bold;
            }
            .terminal-body {
                padding: 20px; height: calc(100% - 50px);
                overflow-y: auto; font-size: 14px;
                line-height: 1.4;
            }
            .terminal-line {
                margin-bottom: 8px; display: flex; align-items: center;
            }
            .terminal-prompt {
                color: #00ff00; margin-right: 10px;
                font-weight: bold;
            }
            .terminal-input {
                background: transparent; border: none; outline: none;
                color: #00ff00; font-family: "Courier New", monospace;
                font-size: 14px; flex: 1;
                caret-color: #00ff00;
            }
            .terminal-input::placeholder {
                color: #00aa00; opacity: 0.7;
            }
            .terminal-cursor {
                display: inline-block; width: 8px; height: 16px;
                background: #00ff00; animation: blink 1s infinite;
                margin-left: 2px;
            }
            @keyframes blink {
                0%, 50% { opacity: 1; }
                51%, 100% { opacity: 0; }
            }
            .terminal-output {
                color: #00aa00; margin: 5px 0;
            }
            .terminal-error {
                color: #ff4444; margin: 5px 0;
            }
            .terminal-success {
                color: #44ff44; margin: 5px 0;
            }
            .matrix-text {
                position: fixed; top: 20px; right: 20px;
                color: #00ff00; font-family: "Courier New", monospace;
                font-size: 0.8rem; opacity: 0.6;
                animation: matrix-flicker 3s infinite;
            }
            @keyframes matrix-flicker {
                0%, 100% { opacity: 0.6; }
                50% { opacity: 1; }
            }
        </style>
    </head>
    <body>
        <div class="matrix-bg"></div>
        <div class="matrix-rain"></div>
        <div class="matrix-code-rain" id="matrixCodeRain"></div>
            <div class="matrix-text">${t.terminal}</div>
            <div style="position: fixed; top: 20px; left: 20px; z-index: 1000;">
                <select id="languageSelector" style="background: rgba(0, 20, 0, 0.9); border: 2px solid #00ff00; color: #00ff00; padding: 8px 12px; font-family: 'Courier New', monospace; font-size: 14px; cursor: pointer; text-shadow: 0 0 5px #00ff00; box-shadow: 0 0 15px rgba(0, 255, 0, 0.4);" onchange="changeLanguage(this.value)">
                    <option value="zh" ${!isFarsi ? 'selected' : ''}>🇨🇳 中文</option>
                    <option value="fa" ${isFarsi ? 'selected' : ''}>🇮🇷 فارسی</option>
                </select>
            </div>
        <div class="terminal">
            <div class="terminal-header">
                <div class="terminal-buttons">
                    <div class="terminal-button"></div>
                    <div class="terminal-button"></div>
                    <div class="terminal-button"></div>
                </div>
                    <div class="terminal-title">${t.terminal}</div>
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
            function createMatrixRain() {
                const matrixContainer = document.getElementById('matrixCodeRain');
                const matrixChars = '01ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
                const columns = Math.floor(window.innerWidth / 18);
                
                for (let i = 0; i < columns; i++) {
                    const column = document.createElement('div');
                    column.className = 'matrix-column';
                    column.style.left = (i * 18) + 'px';
                    column.style.animationDelay = Math.random() * 15 + 's';
                    column.style.animationDuration = (Math.random() * 15 + 8) + 's';
                    column.style.fontSize = (Math.random() * 4 + 12) + 'px';
                    column.style.opacity = Math.random() * 0.8 + 0.2;
                    
                    let text = '';
                    const charCount = Math.floor(Math.random() * 30 + 20);
                    for (let j = 0; j < charCount; j++) {
                        const char = matrixChars[Math.floor(Math.random() * matrixChars.length)];
                        const brightness = Math.random() > 0.1 ? '#00ff00' : '#00aa00';
                        text += '<span style="color: ' + brightness + ';">' + char + '</span><br>';
                    }
                    column.innerHTML = text;
                    matrixContainer.appendChild(column);
                }
                
                setInterval(function() {
                    const columns = matrixContainer.querySelectorAll('.matrix-column');
                    columns.forEach(function(column) {
                        if (Math.random() > 0.95) {
                            const chars = column.querySelectorAll('span');
                            if (chars.length > 0) {
                                const randomChar = chars[Math.floor(Math.random() * chars.length)];
                                randomChar.style.color = '#ffffff';
                                setTimeout(function() {
                                    randomChar.style.color = '#00ff00';
                                }, 200);
                            }
                        }
                    });
                }, 100);
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
                createMatrixRain();
                
                const input = document.getElementById('uuidInput');
                input.focus();
                input.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        handleUUIDInput();
                    }
                });
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

    async function handleSubscriptionRequest(request, user, url = null) {
        if (!url) url = new URL(request.url);
        
        const finalLinks = [];
        const workerDomain = url.hostname;
        const target = url.searchParams.get('target') || 'base64';

        async function addNodesFromList(list) {
            if (ev) {
                finalLinks.push(...generateLinksFromSource(list, user, workerDomain));
            }
            if (et) {
                finalLinks.push(...await generateTrojanLinksFromSource(list, user, workerDomain));
            }
            if (ex) {
                finalLinks.push(...generateXhttpLinksFromSource(list, user, workerDomain));
            }
        }

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
                    fallbackAddress = bestBackupIP.domain;
                    fallbackPort = bestBackupIP.port.toString();
                    const backupList = [{ ip: fallbackAddress, isp: 'ProxyIP-' + currentWorkerRegion }];
                    await addNodesFromList(backupList);
                } else {
                    const nativeList = [{ ip: workerDomain, isp: '原生地址' }];
                    await addNodesFromList(nativeList);
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
            const defaultURL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';
                if (piu === defaultURL) {
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
                        fallbackAddress = bestBackupIP.domain;
                        fallbackPort = bestBackupIP.port.toString();
                        
                        const backupList = [{ ip: fallbackAddress, isp: 'ProxyIP-' + currentWorkerRegion }];
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
                    finalLinks.push(...generateLinksFromNewIPs(newIPList, user, workerDomain));
                        }
                        if (et) {
                            finalLinks.push(...await generateTrojanLinksFromNewIPs(newIPList, user, workerDomain));
                        }
                }
            } catch (error) {
                if (!currentWorkerRegion) {
                    currentWorkerRegion = await detectWorkerRegion(request);
                }
                
                const bestBackupIP = await getBestBackupIP(currentWorkerRegion);
                if (bestBackupIP) {
                    fallbackAddress = bestBackupIP.domain;
                    fallbackPort = bestBackupIP.port.toString();
                    
                    const backupList = [{ ip: fallbackAddress, isp: 'ProxyIP-' + currentWorkerRegion }];
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
            case atob('Y2xhc2g='):
            case atob('Y2xhc2hy'):
                subscriptionContent = await generateClashConfig(finalLinks);
                contentType = 'text/yaml; charset=utf-8';
                break;
            case atob('c3VyZ2U='):
            case atob('c3VyZ2Uy'):
            case atob('c3VyZ2Uz'):
            case atob('c3VyZ2U0'):
                subscriptionContent = generateSurgeConfig(finalLinks);
                break;
            case atob('cXVhbnR1bXVsdA=='):
            case atob('cXVhbng='):
            case 'quanx':
                subscriptionContent = generateQuantumultConfig(finalLinks);
                break;
            case atob('c3M='):
            case atob('c3Ny'):
                subscriptionContent = generateSSConfig(finalLinks);
                break;
            case atob('djJyYXk='):
                subscriptionContent = generateV2RayConfig(finalLinks);
                break;
            case atob('bG9vbg=='):
                subscriptionContent = generateLoonConfig(finalLinks);
                break;
            default:
                subscriptionContent = btoa(finalLinks.join('\n'));
        }
        
        return new Response(subscriptionContent, {
            headers: { 
                'Content-Type': contentType,
                'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            },
        });
    }

    function generateLinksFromSource(list, user, workerDomain) {
        
        const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
        const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
        
        const defaultHttpsPorts = [443];
        const defaultHttpPorts = disableNonTLS ? [] : [80];
        const links = [];
        const wsPath = '/?ed=2048';
        const proto = atob('dmxlc3M=');

        list.forEach(item => {
            const nodeNameBase = item.isp.replace(/\s/g, '_');
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

            portsToGenerate.forEach(({ port, tls }) => {
                if (tls) {
                    
                    const wsNodeName = `${nodeNameBase}-${port}-WS-TLS`;
                    const wsParams = new URLSearchParams({ 
                        encryption: 'none', 
                        security: 'tls', 
                        sni: workerDomain, 
                        fp: 'chrome', 
                        type: 'ws', 
                        host: workerDomain, 
                        path: wsPath
                    });
                    links.push(`${proto}://${user}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
                } else {
                    
                    const wsNodeName = `${nodeNameBase}-${port}-WS`;
                    const wsParams = new URLSearchParams({
                        encryption: 'none',
                        security: 'none',
                        type: 'ws',
                        host: workerDomain,
                        path: wsPath
                    });
                    links.push(`${proto}://${user}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
                }
            });
        });
        return links;
    }

    async function generateTrojanLinksFromSource(list, user, workerDomain) {
        
        const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
        const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
        
        const defaultHttpsPorts = [443];
        const defaultHttpPorts = disableNonTLS ? [] : [80];
        const links = [];
        const wsPath = '/?ed=2048';
        
        const password = tp || user;

        list.forEach(item => {
            const nodeNameBase = item.isp.replace(/\s/g, '_');
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

            portsToGenerate.forEach(({ port, tls }) => {
                if (tls) {
                    
                    const wsNodeName = `${nodeNameBase}-${port}-${atob('VHJvamFu')}-WS-TLS`;
                    const wsParams = new URLSearchParams({ 
                        security: 'tls', 
                        sni: workerDomain, 
                        fp: 'chrome', 
                        type: 'ws', 
                        host: workerDomain, 
                        path: wsPath
                    });
                    links.push(`${atob('dHJvamFuOi8v')}${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
                } else {
                    
                    const wsNodeName = `${nodeNameBase}-${port}-${atob('VHJvamFu')}-WS`;
                    const wsParams = new URLSearchParams({
                        security: 'none',
                        type: 'ws',
                        host: workerDomain,
                        path: wsPath
                    });
                    links.push(`${atob('dHJvamFuOi8v')}${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
                }
            });
        });
        return links;
    }

    async function fetchDynamicIPs() {
        const v4Url1 = "https://www.wetest.vip/page/cloudflare/address_v4.html";
        const v6Url1 = "https://www.wetest.vip/page/cloudflare/address_v6.html";
        let results = [];

        try {
            const [ipv4List, ipv6List] = await Promise.all([
                fetchAndParseWetest(v4Url1),
                fetchAndParseWetest(v6Url1)
            ]);
            results = [...ipv4List, ...ipv6List];
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
            const cellRegex = /<td data-label="线路名称">(.+?)<\/td>[\s\S]*?<td data-label="优选地址">([\d.:a-fA-F]+)<\/td>/;

            let match;
            while ((match = rowRegex.exec(html)) !== null) {
                const rowHtml = match[0];
                const cellMatch = rowHtml.match(cellRegex);
                if (cellMatch && cellMatch[1] && cellMatch[2]) {
                    results.push({
                        isp: cellMatch[1].trim().replace(/<.*?>/g, ''),
                        ip: cellMatch[2].trim()
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
        // 检测并设置当前Worker地区，确保WebSocket请求能正确进行就近匹配
        if (!currentWorkerRegion || currentWorkerRegion === '') {
            if (manualWorkerRegion && manualWorkerRegion.trim()) {
                currentWorkerRegion = manualWorkerRegion.trim().toUpperCase();
            } else {
                currentWorkerRegion = await detectWorkerRegion(request);
            }
        }
        
        const wsPair = new WebSocketPair();
        const [clientSock, serverSock] = Object.values(wsPair);
        serverSock.accept();

        let remoteConnWrapper = { socket: null };
        let isDnsQuery = false;
        let protocolType = null; 

        const earlyData = request.headers.get(atob('c2VjLXdlYnNvY2tldC1wcm90b2NvbA==')) || '';
        const readable = makeReadableStream(serverSock, earlyData);

        readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (isDnsQuery) return await forwardUDP(chunk, serverSock, null);
                if (remoteConnWrapper.socket) {
                    const writer = remoteConnWrapper.socket.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                    return;
                }
                
                if (!protocolType) {
                    
                    if (ev && chunk.byteLength >= 24) {
                        const vlessResult = parseWsPacketHeader(chunk, at);
                        if (!vlessResult.hasError) {
                            protocolType = 'vless';
                            const { addressType, port, hostname, rawIndex, version, isUDP } = vlessResult;
                if (isUDP) {
                    if (port === 53) isDnsQuery = true;
                    else throw new Error(E_UDP_DNS_ONLY);
                }
                const respHeader = new Uint8Array([version[0], 0]);
                const rawData = chunk.slice(rawIndex);
                if (isDnsQuery) return forwardUDP(rawData, serverSock, respHeader);
                await forwardTCP(addressType, hostname, port, rawData, serverSock, respHeader, remoteConnWrapper);
                            return;
                        }
                    }
                    
                    if (et && chunk.byteLength >= 56) {
                        const tjResult = await parseTrojanHeader(chunk, at);
                        if (!tjResult.hasError) {
                            protocolType = atob('dHJvamFu');
                            const { addressType, port, hostname, rawClientData } = tjResult;
                            await forwardTCP(addressType, hostname, port, rawClientData, serverSock, null, remoteConnWrapper);
                            return;
                        }
                    }
                    
                    throw new Error('Invalid protocol or authentication failed');
                }
            },
        })).catch((err) => { });

        return new Response(null, { status: 101, webSocket: clientSock });
    }

    async function forwardTCP(addrType, host, portNum, rawData, ws, respHeader, remoteConnWrapper) {
        async function connectAndSend(address, port, useSocks = false) {
            const remoteSock = useSocks ?
                await establishSocksConnection(addrType, address, port) :
                connect({ hostname: address, port: port });
            const writer = remoteSock.writable.getWriter();
            await writer.write(rawData);
            writer.releaseLock();
            return remoteSock;
        }
        
        async function retryConnection() {
            if (enableSocksDowngrade && isSocksEnabled) {
                try {
                    const socksSocket = await connectAndSend(host, portNum, true);
                    remoteConnWrapper.socket = socksSocket;
                    socksSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
                    connectStreams(socksSocket, ws, respHeader, null);
                    return;
                } catch (socksErr) {
                    let backupHost, backupPort;
                    if (fallbackAddress && fallbackAddress.trim() && fallbackPort) {
                        backupHost = fallbackAddress;
                        backupPort = parseInt(fallbackPort, 10) || portNum;
                    } else {
                        const bestBackupIP = await getBestBackupIP(currentWorkerRegion);
                        backupHost = bestBackupIP ? bestBackupIP.domain : host;
                        backupPort = bestBackupIP ? bestBackupIP.port : portNum;
                    }
                    
                    try {
                        const fallbackSocket = await connectAndSend(backupHost, backupPort, false);
                        remoteConnWrapper.socket = fallbackSocket;
                        fallbackSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
                        connectStreams(fallbackSocket, ws, respHeader, null);
                    } catch (fallbackErr) {
                        closeSocketQuietly(ws);
                    }
                }
            } else {
                let backupHost, backupPort;
                if (fallbackAddress && fallbackAddress.trim() && fallbackPort) {
                    backupHost = fallbackAddress;
                    backupPort = parseInt(fallbackPort, 10) || portNum;
                } else {
                    const bestBackupIP = await getBestBackupIP(currentWorkerRegion);
                    backupHost = bestBackupIP ? bestBackupIP.domain : host;
                    backupPort = bestBackupIP ? bestBackupIP.port : portNum;
                }
                
                try {
                    const fallbackSocket = await connectAndSend(backupHost, backupPort, isSocksEnabled);
                    remoteConnWrapper.socket = fallbackSocket;
                    fallbackSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
                    connectStreams(fallbackSocket, ws, respHeader, null);
                } catch (fallbackErr) {
                    closeSocketQuietly(ws);
                }
            }
        }
        
        try {
            const initialSocket = await connectAndSend(host, portNum, enableSocksDowngrade ? false : isSocksEnabled);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, retryConnection);
        } catch (err) {
            retryConnection();
        }
    }

    function parseWsPacketHeader(chunk, token) {
        if (chunk.byteLength < 24) return { hasError: true, message: E_INVALID_DATA };
        const version = new Uint8Array(chunk.slice(0, 1));
        if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: E_INVALID_USER };
        const optLen = new Uint8Array(chunk.slice(17, 18))[0];
        const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
        let isUDP = false;
        if (cmd === 1) {} else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: E_UNSUPPORTED_CMD }; }
        const portIdx = 19 + optLen;
        const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
        let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
        const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
        switch (addressType) {
            case ADDRESS_TYPE_IPV4: addrLen = 4; hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); break;
            case ADDRESS_TYPE_URL: addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0]; addrValIdx += 1; hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); break;
            case ADDRESS_TYPE_IPV6: addrLen = 16; const ipv6 = []; const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); hostname = ipv6.join(':'); break;
            default: return { hasError: true, message: `${E_INVALID_ADDR_TYPE}: ${addressType}` };
        }
        if (!hostname) return { hasError: true, message: `${E_EMPTY_ADDR}: ${addressType}` };
        return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
    }

    function makeReadableStream(socket, earlyDataHeader) {
        let cancelled = false;
        return new ReadableStream({
            start(controller) {
                socket.addEventListener('message', (event) => { if (!cancelled) controller.enqueue(event.data); });
                socket.addEventListener('close', () => { if (!cancelled) { closeSocketQuietly(socket); controller.close(); } });
                socket.addEventListener('error', (err) => controller.error(err));
                const { earlyData, error } = base64ToArray(earlyDataHeader);
                if (error) controller.error(error); else if (earlyData) controller.enqueue(earlyData);
            },
            cancel() { cancelled = true; closeSocketQuietly(socket); }
        });
    }

    async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
        let header = headerData, hasData = false;
        await remoteSocket.readable.pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    hasData = true;
                    if (webSocket.readyState !== 1) controller.error(E_WS_NOT_OPEN);
                    if (header) { webSocket.send(await new Blob([header, chunk]).arrayBuffer()); header = null; } 
                    else { webSocket.send(chunk); }
                },
                abort(reason) { },
            })
        ).catch((error) => { closeSocketQuietly(webSocket); });
        if (!hasData && retryFunc) retryFunc();
    }

    async function forwardUDP(udpChunk, webSocket, respHeader) {
        try {
            const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
            let header = respHeader;
            const writer = tcpSocket.writable.getWriter();
            await writer.write(udpChunk);
            writer.releaseLock();
            await tcpSocket.readable.pipeTo(new WritableStream({
                async write(chunk) {
                    if (webSocket.readyState === 1) {
                        if (header) { webSocket.send(await new Blob([header, chunk]).arrayBuffer()); header = null; } 
                        else { webSocket.send(chunk); }
                    }
                },
            }));
        } catch (error) { }
    }

    async function establishSocksConnection(addrType, address, port) {
        const { username, password, hostname, socksPort } = parsedSocks5Config;
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
                    enableGitHubPreferred: '启用 GitHub 默认优选',
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
                    saveProtocol: '保存协议配置',
                    subscriptionConverterPlaceholder: '默认: https://url.v1.mk/sub',
                    subscriptionConverterHint: '自定义订阅转换API地址，留空则使用默认地址',
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
                        US: '🇺🇸 美国', SG: '🇸🇬 新加坡', JP: '🇯🇵 日本', HK: '🇭🇰 香港',
                        KR: '🇰🇷 韩国', DE: '🇩🇪 德国', SE: '🇸🇪 瑞典', NL: '🇳🇱 荷兰',
                        FI: '🇫🇮 芬兰', GB: '🇬🇧 英国'
                    },
                    terminal: '终端 v2.5.0',
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
                    trojanPassword: 'رمز عبور Trojan (اختیاری):',
                    customPath: 'مسیر سفارشی (d):',
                    customIP: 'ProxyIP سفارشی (p):',
                    preferredIPs: 'لیست IP ترجیحی (yx):',
                    preferredIPsURL: 'URL منبع IP ترجیحی (yxURL):',
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
                    enableGitHubPreferred: 'فعال‌سازی ترجیح پیش‌فرض GitHub',
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
                    saveProtocol: 'ذخیره تنظیمات پروتکل',
                    subscriptionConverterPlaceholder: 'پیش‌فرض: https://url.v1.mk/sub',
                    subscriptionConverterHint: 'آدرس API تبدیل اشتراک سفارشی، اگر خالی بگذارید از آدرس پیش‌فرض استفاده می‌شود',
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
                        US: '🇺🇸 آمریکا', SG: '🇸🇬 سنگاپور', JP: '🇯🇵 ژاپن', HK: '🇭🇰 هنگ‌کنگ',
                        KR: '🇰🇷 کره جنوبی', DE: '🇩🇪 آلمان', SE: '🇸🇪 سوئد', NL: '🇳🇱 هلند',
                        FI: '🇫🇮 فنلاند', GB: '🇬🇧 بریتانیا'
                    },
                    terminal: 'ترمینال v2.5.0',
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
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: "Courier New", monospace;
                background: #000; color: #00ff00; min-height: 100vh;
                overflow-x: hidden; position: relative;
            }
            .matrix-bg {
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: linear-gradient(45deg, #000 0%, #001100 50%, #000 100%);
                z-index: -1;
                animation: bg-pulse 8s ease-in-out infinite;
            }
            @keyframes bg-pulse {
                0%, 100% { background: linear-gradient(45deg, #000 0%, #001100 50%, #000 100%); }
                50% { background: linear-gradient(45deg, #000 0%, #002200 50%, #000 100%); }
            }
            .matrix-rain {
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,0,0.03) 2px, rgba(0,255,0,0.03) 4px);
                animation: matrix-fall 20s linear infinite;
                z-index: -1;
            }
            @keyframes matrix-fall {
                0% { transform: translateY(-100%); }
                100% { transform: translateY(100vh); }
            }
            .matrix-code-rain {
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                pointer-events: none; z-index: -1;
                overflow: hidden;
            }
            .matrix-column {
                position: absolute; top: -100%; left: 0;
                color: #00ff00; font-family: "Courier New", monospace;
                font-size: 14px; line-height: 1.2;
                animation: matrix-drop 15s linear infinite;
                text-shadow: 0 0 5px #00ff00;
            }
            @keyframes matrix-drop {
                0% { top: -100%; opacity: 1; }
                10% { opacity: 1; }
                90% { opacity: 0.3; }
                100% { top: 100vh; opacity: 0; }
            }
            .matrix-column:nth-child(odd) {
                animation-duration: 12s;
                animation-delay: -2s;
            }
            .matrix-column:nth-child(even) {
                animation-duration: 18s;
                animation-delay: -5s;
            }
            .matrix-column:nth-child(3n) {
                animation-duration: 20s;
                animation-delay: -8s;
            }
            .container { max-width: 900px; margin: 0 auto; padding: 20px; position: relative; z-index: 1; }
            .header { text-align: center; margin-bottom: 40px; }
            .title {
                font-size: 3.5rem; font-weight: bold;
                text-shadow: 0 0 10px #00ff00, 0 0 20px #00ff00, 0 0 30px #00ff00, 0 0 40px #00ff00;
                margin-bottom: 10px;
                animation: matrix-glow 1.5s ease-in-out infinite alternate, matrix-pulse 3s ease-in-out infinite;
                position: relative;
                background: linear-gradient(45deg, #00ff00, #00aa00, #00ff00);
                background-size: 200% 200%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            @keyframes matrix-glow {
                from { text-shadow: 0 0 10px #00ff00, 0 0 20px #00ff00, 0 0 30px #00ff00, 0 0 40px #00ff00; }
                to { text-shadow: 0 0 20px #00ff00, 0 0 30px #00ff00, 0 0 40px #00ff00, 0 0 50px #00ff00; }
            }
            @keyframes matrix-pulse {
                0%, 100% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
            }
            .subtitle { color: #00aa00; margin-bottom: 30px; font-size: 1.2rem; }
            .card {
                background: rgba(0, 20, 0, 0.9);
                border: 2px solid #00ff00;
                border-radius: 0; padding: 30px; margin-bottom: 20px;
                box-shadow: 0 0 30px rgba(0, 255, 0, 0.5), inset 0 0 20px rgba(0, 255, 0, 0.1);
                position: relative;
                backdrop-filter: blur(10px);
                animation: card-glow 4s ease-in-out infinite;
                box-sizing: border-box;
                width: 100%;
                max-width: 100%;
            }
            @keyframes card-glow {
                0%, 100% { box-shadow: 0 0 30px rgba(0, 255, 0, 0.5), inset 0 0 20px rgba(0, 255, 0, 0.1); }
                50% { box-shadow: 0 0 40px rgba(0, 255, 0, 0.7), inset 0 0 30px rgba(0, 255, 0, 0.2); }
            }
            .card::before {
                content: ""; position: absolute; top: 0; left: 0;
                width: 100%; height: 100%;
                background: linear-gradient(45deg, transparent 49%, #00ff00 50%, transparent 51%);
                opacity: 0.2; pointer-events: none;
                animation: scan-line 3s linear infinite;
            }
            @keyframes scan-line {
                0% { transform: translateX(-100%); }
                100% { transform: translateX(100%); }
            }
            .card-title {
                font-size: 1.8rem; margin-bottom: 20px;
                color: #00ff00; text-shadow: 0 0 5px #00ff00;
            }
            .client-grid {
                display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                gap: 15px; margin: 20px 0;
            }
            .client-btn {
                background: rgba(0, 20, 0, 0.8);
                border: 2px solid #00ff00;
                padding: 15px 20px; color: #00ff00;
                font-family: "Courier New", monospace; font-weight: bold;
                cursor: pointer; transition: all 0.4s ease;
                text-align: center; position: relative;
                overflow: hidden;
                text-shadow: 0 0 5px #00ff00;
                box-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
            }
            .client-btn::before {
                content: ""; position: absolute; top: 0; left: -100%;
                width: 100%; height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0,255,0,0.4), transparent);
                transition: left 0.6s ease;
            }
            .client-btn::after {
                content: ""; position: absolute; top: 0; left: 0;
                width: 100%; height: 100%;
                background: linear-gradient(45deg, transparent 30%, rgba(0,255,0,0.1) 50%, transparent 70%);
                opacity: 0;
                transition: opacity 0.3s ease;
            }
            .client-btn:hover::before { left: 100%; }
            .client-btn:hover::after { opacity: 1; }
            .client-btn:hover {
                background: rgba(0, 255, 0, 0.3);
                box-shadow: 0 0 25px #00ff00, 0 0 35px rgba(0, 255, 0, 0.5);
                transform: translateY(-3px) scale(1.05);
                text-shadow: 0 0 10px #00ff00, 0 0 20px #00ff00;
            }
            .generate-btn {
                background: rgba(0, 255, 0, 0.15);
                border: 2px solid #00ff00; padding: 15px 30px;
                color: #00ff00; font-family: "Courier New", monospace;
                font-weight: bold; cursor: pointer;
                transition: all 0.4s ease; margin-right: 15px;
                text-shadow: 0 0 8px #00ff00;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.4);
                position: relative;
                overflow: hidden;
            }
            .generate-btn::before {
                content: ""; position: absolute; top: 0; left: -100%;
                width: 100%; height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0,255,0,0.5), transparent);
                transition: left 0.8s ease;
            }
            .generate-btn:hover::before { left: 100%; }
            .generate-btn:hover {
                background: rgba(0, 255, 0, 0.4);
                box-shadow: 0 0 30px #00ff00, 0 0 40px rgba(0, 255, 0, 0.6);
                transform: translateY(-4px) scale(1.08);
                text-shadow: 0 0 15px #00ff00, 0 0 25px #00ff00;
            }
            .atob('c3Vic2NyaXB0aW9u')-url {
                background: rgba(0, 0, 0, 0.9);
                border: 2px solid #00ff00; padding: 15px;
                word-break: break-all; font-family: "Courier New", monospace;
                color: #00ff00; margin-top: 20px; display: none;
                box-shadow: inset 0 0 15px rgba(0, 255, 0, 0.4), 0 0 20px rgba(0, 255, 0, 0.3);
                border-radius: 5px;
                animation: url-glow 2s ease-in-out infinite alternate;
                position: relative;
                overflow-wrap: break-word;
                overflow-x: auto;
                max-width: 100%;
                box-sizing: border-box;
            }
            @keyframes url-glow {
                from { box-shadow: inset 0 0 15px rgba(0, 255, 0, 0.4), 0 0 20px rgba(0, 255, 0, 0.3); }
                to { box-shadow: inset 0 0 20px rgba(0, 255, 0, 0.6), 0 0 30px rgba(0, 255, 0, 0.5); }
            }
            .atob('c3Vic2NyaXB0aW9u')-url::before {
                content: ""; position: absolute; top: 0; left: -100%;
                width: 100%; height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0,255,0,0.1), transparent);
                animation: url-scan 3s linear infinite;
            }
            @keyframes url-scan {
                0% { left: -100%; }
                100% { left: 100%; }
            }
            .matrix-text {
                position: fixed; top: 20px; right: 20px;
                color: #00ff00; font-family: "Courier New", monospace;
                font-size: 0.8rem; opacity: 0.6;
                animation: matrix-flicker 3s infinite;
            }
            @keyframes matrix-flicker {
                0%, 100% { opacity: 0.6; }
                50% { opacity: 1; }
            }
        </style>
    </head>
    <body>
        <div class="matrix-bg"></div>
        <div class="matrix-rain"></div>
        <div class="matrix-code-rain" id="matrixCodeRain"></div>
            <div class="matrix-text">${t.terminal}</div>
            <div style="position: fixed; top: 20px; left: 20px; z-index: 1000;">
                <select id="languageSelector" style="background: rgba(0, 20, 0, 0.9); border: 2px solid #00ff00; color: #00ff00; padding: 8px 12px; font-family: 'Courier New', monospace; font-size: 14px; cursor: pointer; text-shadow: 0 0 5px #00ff00; box-shadow: 0 0 15px rgba(0, 255, 0, 0.4);" onchange="changeLanguage(this.value)">
                    <option value="zh" ${!isFarsi ? 'selected' : ''}>🇨🇳 中文</option>
                    <option value="fa" ${isFarsi ? 'selected' : ''}>🇮🇷 فارسی</option>
                </select>
            </div>
        <div class="container">
            <div class="header">
                    <h1 class="title">${t.title}</h1>
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
                <div id="systemStatus" style="margin: 20px 0; padding: 15px; background: rgba(0, 20, 0, 0.8); border: 2px solid #00ff00; box-shadow: 0 0 20px rgba(0, 255, 0, 0.3), inset 0 0 15px rgba(0, 255, 0, 0.1); position: relative; overflow: hidden;">
                        <div style="color: #00ff00; margin-bottom: 15px; font-weight: bold; text-shadow: 0 0 5px #00ff00;">[ ${t.checking} ]</div>
                        <div id="regionStatus" style="margin: 8px 0; color: #00ff00; font-family: 'Courier New', monospace; text-shadow: 0 0 3px #00ff00;">${t.workerRegion}${t.checking}</div>
                        <div id="geoInfo" style="margin: 8px 0; color: #00aa00; font-family: 'Courier New', monospace; font-size: 0.9rem; text-shadow: 0 0 3px #00aa00;">${t.detectionMethod}${t.checking}</div>
                        <div id="backupStatus" style="margin: 8px 0; color: #00ff00; font-family: 'Courier New', monospace; text-shadow: 0 0 3px #00ff00;">${t.proxyIPStatus}${t.checking}</div>
                        <div id="currentIP" style="margin: 8px 0; color: #00ff00; font-family: 'Courier New', monospace; text-shadow: 0 0 3px #00ff00;">${t.currentIP}${t.checking}</div>
                        <div id="regionMatch" style="margin: 8px 0; color: #00ff00; font-family: 'Courier New', monospace; text-shadow: 0 0 3px #00ff00;">${t.regionMatch}${t.checking}</div>
                        <div id="selectionLogic" style="margin: 8px 0; color: #00aa00; font-family: 'Courier New', monospace; font-size: 0.9rem; text-shadow: 0 0 3px #00aa00;">${t.selectionLogic}${t.selectionLogicText}</div>
                </div>
            </div>
            <div class="card" id="configCard" style="display: none;">
                    <h2 class="card-title">${t.configManagement}</h2>
                <div id="kvStatus" style="margin-bottom: 20px; padding: 10px; background: rgba(0, 20, 0, 0.8); border: 1px solid #00ff00; color: #00ff00;">
                        ${t.kvStatusChecking}
                </div>
                <div id="configContent" style="display: none;">
                    <form id="regionForm" style="margin-bottom: 20px;">
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.specifyRegion}</label>
                            <select id="wkRegion" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.autoDetect}</option>
                                    <option value="US">${t.regionNames.US}</option>
                                    <option value="SG">${t.regionNames.SG}</option>
                                    <option value="JP">${t.regionNames.JP}</option>
                                    <option value="HK">${t.regionNames.HK}</option>
                                    <option value="KR">${t.regionNames.KR}</option>
                                    <option value="DE">${t.regionNames.DE}</option>
                                    <option value="SE">${t.regionNames.SE}</option>
                                    <option value="NL">${t.regionNames.NL}</option>
                                    <option value="FI">${t.regionNames.FI}</option>
                                    <option value="GB">${t.regionNames.GB}</option>
                            </select>
                                <small id="wkRegionHint" style="color: #00aa00; font-size: 0.85rem; display: none;">⚠️ ${t.customIPDisabledHint}</small>
                        </div>
                            <button type="submit" style="background: rgba(0, 255, 0, 0.15); border: 2px solid #00ff00; padding: 12px 24px; color: #00ff00; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; margin-right: 10px; text-shadow: 0 0 8px #00ff00; transition: all 0.4s ease;">${t.saveRegion}</button>
                    </form>
                    <form id="otherConfigForm" style="margin-bottom: 20px;">
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.protocolSelection}</label>
                            <div style="padding: 15px; background: rgba(0, 20, 0, 0.6); border: 1px solid #00ff00; border-radius: 5px;">
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00ff00;">
                                        <input type="checkbox" id="ev" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enableVLESS}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00ff00;">
                                        <input type="checkbox" id="et" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enableTrojan}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00ff00;">
                                        <input type="checkbox" id="ex" style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enableXhttp}</span>
                                    </label>
                                </div>
                                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(0, 255, 0, 0.3);">
                                        <label style="display: block; margin-bottom: 8px; color: #00ff00; font-size: 0.95rem;">${t.trojanPassword}</label>
                                        <input type="text" id="tp" placeholder="${t.trojanPasswordPlaceholder}" style="width: 100%; padding: 10px; background: rgba(0, 0, 0, 0.8); border: 1px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 13px;">
                                        <small style="color: #00aa00; font-size: 0.8rem; display: block; margin-top: 5px;">${t.trojanPasswordHint}</small>
                                </div>
                                    <small style="color: #00aa00; font-size: 0.85rem; display: block; margin-top: 10px;">${t.protocolHint}</small>
                                    <button type="button" id="saveProtocolBtn" style="margin-top: 15px; background: rgba(0, 255, 0, 0.15); border: 2px solid #00ff00; padding: 10px 20px; color: #00ff00; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; text-shadow: 0 0 8px #00ff00; transition: all 0.4s ease; width: 100%;">${t.saveProtocol}</button>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.customHomepage}</label>
                                <input type="text" id="customHomepage" placeholder="${t.customHomepagePlaceholder}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #00aa00; font-size: 0.85rem;">${t.customHomepageHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.customPath}</label>
                                <input type="text" id="customPath" placeholder="${isFarsi ? 'مثال: /mypath یا خالی بگذارید تا از UUID استفاده شود' : '例如: /mypath 或留空使用 UUID'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #00aa00; font-size: 0.85rem;">${isFarsi ? 'مسیر اشتراک سفارشی. اگر خالی بگذارید از UUID به عنوان مسیر استفاده می‌شود.' : '自定义订阅路径。留空则使用 UUID 作为路径。'}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.customIP}</label>
                                <input type="text" id="customIP" placeholder="${isFarsi ? 'مثال: 1.2.3.4:443' : '例如: 1.2.3.4:443'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #00aa00; font-size: 0.85rem;">${isFarsi ? 'آدرس و پورت ProxyIP سفارشی' : '自定义ProxyIP地址和端口'}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.preferredIPs}</label>
                                <input type="text" id="preferredIPs" placeholder="${isFarsi ? 'مثال: 1.2.3.4:443#گره هنگ‌کنگ,5.6.7.8:80#گره آمریکا,example.com:8443#گره سنگاپور' : '例如: 1.2.3.4:443#香港节点,5.6.7.8:80#美国节点,example.com:8443#新加坡节点'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #00aa00; font-size: 0.85rem;">${isFarsi ? 'فرمت: IP:پورت#نام گره یا IP:پورت (بدون # از نام پیش‌فرض استفاده می‌شود). پشتیبانی از چندین مورد، با کاما جدا می‌شوند. <span style="color: #ffaa00;">IP های اضافه شده از طریق API به طور خودکار در اینجا نمایش داده می‌شوند.</span>' : '格式: IP:端口#节点名称 或 IP:端口 (无#则使用默认名称)。支持多个，用逗号分隔。<span style="color: #ffaa00;">API添加的IP会自动显示在这里。</span>'}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.preferredIPsURL}</label>
                                <input type="text" id="preferredIPsURL" placeholder="${isFarsi ? 'پیش‌فرض: https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt' : '默认: https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #00aa00; font-size: 0.85rem;">${isFarsi ? 'URL منبع لیست IP ترجیحی سفارشی، اگر خالی بگذارید از آدرس پیش‌فرض استفاده می‌شود' : '自定义优选IP列表来源URL，留空则使用默认地址'}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.socks5Config}</label>
                                <input type="text" id="socksConfig" placeholder="${isFarsi ? 'مثال: user:pass@host:port یا host:port' : '例如: user:pass@host:port 或 host:port'}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #00aa00; font-size: 0.85rem;">${isFarsi ? 'آدرس پروکسی SOCKS5، برای انتقال تمام ترافیک خروجی استفاده می‌شود' : 'SOCKS5代理地址，用于转发所有出站流量'}</small>
                        </div>
                            <button type="submit" style="background: rgba(0, 255, 0, 0.15); border: 2px solid #00ff00; padding: 12px 24px; color: #00ff00; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; margin-right: 10px; text-shadow: 0 0 8px #00ff00; transition: all 0.4s ease;">${t.saveConfig}</button>
                    </form>
                    
                        <h3 style="color: #00ff00; margin: 20px 0 15px 0; font-size: 1.2rem;">${t.advancedControl}</h3>
                    <form id="advancedConfigForm" style="margin-bottom: 20px;">
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.subscriptionConverter}</label>
                                <input type="text" id="scu" placeholder="${t.subscriptionConverterPlaceholder}" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                <small style="color: #00aa00; font-size: 0.85rem;">${t.subscriptionConverterHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.builtinPreferred}</label>
                            <div style="padding: 15px; background: rgba(0, 20, 0, 0.6); border: 1px solid #00ff00; border-radius: 5px;">
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00ff00;">
                                        <input type="checkbox" id="epd" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enablePreferredDomain}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00ff00;">
                                        <input type="checkbox" id="epi" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enablePreferredIP}</span>
                                    </label>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label style="display: inline-flex; align-items: center; cursor: pointer; color: #00ff00;">
                                        <input type="checkbox" id="egi" checked style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                            <span style="font-size: 1.1rem;">${t.enableGitHubPreferred}</span>
                                    </label>
                                </div>
                                    <small style="color: #00aa00; font-size: 0.85rem; display: block; margin-top: 10px;">${t.builtinPreferredHint}</small>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.allowAPIManagement}</label>
                            <select id="apiEnabled" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.apiEnabledDefault}</option>
                                    <option value="yes">${t.apiEnabledYes}</option>
                            </select>
                                <small style="color: #ffaa00; font-size: 0.85rem;">${t.apiEnabledHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.regionMatching}</label>
                            <select id="regionMatching" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.regionMatchingDefault}</option>
                                    <option value="no">${t.regionMatchingNo}</option>
                            </select>
                                <small style="color: #00aa00; font-size: 0.85rem;">${t.regionMatchingHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.downgradeControl}</label>
                            <select id="downgradeControl" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.downgradeControlDefault}</option>
                                    <option value="no">${t.downgradeControlNo}</option>
                            </select>
                                <small style="color: #00aa00; font-size: 0.85rem;">${t.downgradeControlHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.tlsControl}</label>
                            <select id="portControl" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.tlsControlDefault}</option>
                                    <option value="yes">${t.tlsControlYes}</option>
                            </select>
                                <small style="color: #00aa00; font-size: 0.85rem;">${t.tlsControlHint}</small>
                        </div>
                        <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 8px; color: #00ff00; font-weight: bold; text-shadow: 0 0 3px #00ff00;">${t.preferredControl}</label>
                            <select id="preferredControl" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff00; color: #00ff00; font-family: 'Courier New', monospace; font-size: 14px;">
                                    <option value="">${t.preferredControlDefault}</option>
                                    <option value="yes">${t.preferredControlYes}</option>
                            </select>
                                <small style="color: #00aa00; font-size: 0.85rem;">${t.preferredControlHint}</small>
                        </div>
                            <button type="submit" style="background: rgba(0, 255, 0, 0.15); border: 2px solid #00ff00; padding: 12px 24px; color: #00ff00; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; margin-right: 10px; text-shadow: 0 0 8px #00ff00; transition: all 0.4s ease;">${t.saveAdvanced}</button>
                    </form>
                    <div id="currentConfig" style="background: rgba(0, 0, 0, 0.9); border: 1px solid #00ff00; padding: 15px; margin: 10px 0; font-family: 'Courier New', monospace; color: #00ff00;">
                            ${t.loading}
                    </div>
                    <div id="pathTypeInfo" style="background: rgba(0, 20, 0, 0.7); border: 1px solid #00ff00; padding: 15px; margin: 10px 0; font-family: 'Courier New', monospace; color: #00ff00;">
                            <div style="font-weight: bold; margin-bottom: 8px; color: #44ff44; text-shadow: 0 0 5px #44ff44;">${t.currentConfig}</div>
                            <div id="pathTypeStatus">${t.checking}</div>
                    </div>
                        <button onclick="loadCurrentConfig()" style="background: rgba(0, 255, 0, 0.15); border: 2px solid #00ff00; padding: 12px 24px; color: #00ff00; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; margin-right: 10px; text-shadow: 0 0 8px #00ff00; transition: all 0.4s ease;">${t.refreshConfig}</button>
                        <button onclick="resetAllConfig()" style="background: rgba(255, 0, 0, 0.15); border: 2px solid #ff0000; padding: 12px 24px; color: #ff0000; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; text-shadow: 0 0 8px #ff0000; transition: all 0.4s ease;">${t.resetConfig}</button>
                </div>
                <div id="statusMessage" style="display: none; padding: 10px; margin: 10px 0; border: 1px solid #00ff00; background: rgba(0, 20, 0, 0.8); color: #00ff00; text-shadow: 0 0 5px #00ff00;"></div>
            </div>
            
            <div class="card">
                    <h2 class="card-title">${t.relatedLinks}</h2>
                <div style="text-align: center; margin: 20px 0;">
                        <a href="https://github.com/byJoey/cfnew" target="_blank" style="color: #00ff00; text-decoration: none; margin: 0 20px; font-size: 1.2rem; text-shadow: 0 0 5px #00ff00;">${t.githubProject}</a>
                    <a href="https://www.youtube.com/@joeyblog" target="_blank" style="color: #00ff00; text-decoration: none; margin: 0 20px; font-size: 1.2rem; text-shadow: 0 0 5px #00ff00;">YouTube @joeyblog</a>
                </div>
            </div>
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
                                alert(displayName + " " + t.subscriptionCopied);
                        });
                    } else if (clientName === 'Shadowrocket') {
                        schemeUrl = 'shadowrocket://add/' + encodeURIComponent(finalUrl);
                        tryOpenApp(schemeUrl, function() {
                            navigator.clipboard.writeText(finalUrl).then(function() {
                                    alert(displayName + " " + t.subscriptionCopied);
                            });
                        });
                    } else if (clientName === 'V2RAYNG') {
                        schemeUrl = 'v2rayng://install?url=' + encodeURIComponent(finalUrl);
                        tryOpenApp(schemeUrl, function() {
                            navigator.clipboard.writeText(finalUrl).then(function() {
                                    alert(displayName + " " + t.subscriptionCopied);
                            });
                        });
                    } else if (clientName === 'NEKORAY') {
                        schemeUrl = 'nekoray://install-config?url=' + encodeURIComponent(finalUrl);
                        tryOpenApp(schemeUrl, function() {
                            navigator.clipboard.writeText(finalUrl).then(function() {
                                    alert(displayName + " " + t.subscriptionCopied);
                            });
                        });
                    }
                } else {
                    var encodedUrl = encodeURIComponent(subscriptionUrl);
                    finalUrl = SUB_CONVERTER_URL + "?target=" + clientType + "&url=" + encodedUrl + "&insert=false&config=" + encodeURIComponent(REMOTE_CONFIG_URL) + "&emoji=true&list=false&xudp=false&udp=false&tfo=false&expand=true&scv=false&fdn=false&new_name=true";
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
                                    alert(displayName + " " + t.subscriptionCopied);
                            });
                        });
                    } else {
                        navigator.clipboard.writeText(finalUrl).then(function() {
                                alert(displayName + " " + t.subscriptionCopied);
                        });
                    }
                }
            }
            
            function createMatrixRain() {
                const matrixContainer = document.getElementById('matrixCodeRain');
                const matrixChars = '01ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
                const columns = Math.floor(window.innerWidth / 18);
                
                for (let i = 0; i < columns; i++) {
                    const column = document.createElement('div');
                    column.className = 'matrix-column';
                    column.style.left = (i * 18) + 'px';
                    column.style.animationDelay = Math.random() * 15 + 's';
                    column.style.animationDuration = (Math.random() * 15 + 8) + 's';
                    column.style.fontSize = (Math.random() * 4 + 12) + 'px';
                    column.style.opacity = Math.random() * 0.8 + 0.2;
                    
                    let text = '';
                    const charCount = Math.floor(Math.random() * 30 + 20);
                    for (let j = 0; j < charCount; j++) {
                        const char = matrixChars[Math.floor(Math.random() * matrixChars.length)];
                        const brightness = Math.random() > 0.1 ? '#00ff00' : '#00aa00';
                        text += '<span style="color: ' + brightness + ';">' + char + '</span><br>';
                    }
                    column.innerHTML = text;
                    matrixContainer.appendChild(column);
                }
                
                setInterval(function() {
                    const columns = matrixContainer.querySelectorAll('.matrix-column');
                    columns.forEach(function(column) {
                        if (Math.random() > 0.95) {
                            const chars = column.querySelectorAll('span');
                            if (chars.length > 0) {
                                const randomChar = chars[Math.floor(Math.random() * chars.length)];
                                randomChar.style.color = '#ffffff';
                                setTimeout(function() {
                                    randomChar.style.color = '#00ff00';
                                }, 200);
                            }
                        }
                    });
                }, 100);
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
                        'US': '🇺🇸 美国', 'SG': '🇸🇬 新加坡', 'JP': '🇯🇵 日本', 'HK': '🇭🇰 香港',
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
                                    'US': '🇺🇸 آمریکا', 'SG': '🇸🇬 سنگاپور', 'JP': '🇯🇵 ژاپن', 'HK': '🇭🇰 هنگ‌کنگ',
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
                            
                                geoInfo.innerHTML = t.detectionMethod + '<span style="color: #ffaa00;">⚙️ ' + t.customIPMode + '</span>';
                                regionStatus.innerHTML = t.workerRegion + '<span style="color: #ffaa00;">🔧 ' + t.customIPModeDesc + '</span>';
                            
                            // 显示自定义IP配置状态，包含具体IP
                                if (backupStatus) backupStatus.innerHTML = t.proxyIPStatus + '<span style="color: #ffaa00;">🔧 ' + t.usingCustomProxyIP + customIPInfo + '</span>';
                                if (currentIP) currentIP.innerHTML = t.currentIP + '<span style="color: #ffaa00;">✅ ' + customIPInfo + t.customIPConfig + '</span>';
                                if (regionMatch) regionMatch.innerHTML = t.regionMatch + '<span style="color: #ffaa00;">⚠️ ' + t.customIPModeDisabled + '</span>';
                            
                            return; // 提前返回，不执行后续的地区匹配逻辑
                            } else if (data.detectionMethod === '手动指定地区' || data.detectionMethod === 'تعیین منطقه دستی') {
                            isManualRegionMode = true;
                            detectedRegion = data.region;
                            
                                geoInfo.innerHTML = t.detectionMethod + '<span style="color: #44aa44;">' + t.manualRegion + '</span>';
                                regionStatus.innerHTML = t.workerRegion + '<span style="color: #44ff44;">🎯 ' + t.regionNames[detectedRegion] + t.manualRegionDesc + '</span>';
                            
                            // 显示配置状态而不是检测状态
                                if (backupStatus) backupStatus.innerHTML = t.proxyIPStatus + '<span style="color: #44ff44;">✅ ' + t.proxyIPAvailable + '</span>';
                                if (currentIP) currentIP.innerHTML = t.currentIP + '<span style="color: #44ff44;">✅ ' + t.smartSelection + '</span>';
                                if (regionMatch) regionMatch.innerHTML = t.regionMatch + '<span style="color: #44ff44;">✅ ' + t.sameRegionIP + '</span>';
                            
                            return; // 提前返回，不执行后续的地区匹配逻辑
                            } else if (data.region && t.regionNames[data.region]) {
                            detectedRegion = data.region;
                        }
                        
                            geoInfo.innerHTML = t.detectionMethod + '<span style="color: #44ff44;">' + t.cloudflareDetection + '</span>';
                        
                    } catch (e) {
                            geoInfo.innerHTML = t.detectionMethod + '<span style="color: #ff4444;">' + t.detectionFailed + '</span>';
                    }
                    
                        regionStatus.innerHTML = t.workerRegion + '<span style="color: #44ff44;">✅ ' + t.regionNames[detectedRegion] + '</span>';
                    
                    // 直接显示配置状态，不再进行检测
                    if (backupStatus) {
                            backupStatus.innerHTML = t.proxyIPStatus + '<span style="color: #44ff44;">✅ ' + t.proxyIPAvailable + '</span>';
                    }
                    
                    if (currentIP) {
                            currentIP.innerHTML = t.currentIP + '<span style="color: #44ff44;">✅ ' + t.smartSelection + '</span>';
                    }
                    
                    if (regionMatch) {
                            regionMatch.innerHTML = t.regionMatch + '<span style="color: #44ff44;">✅ ' + t.sameRegionIP + '</span>';
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
                        
                        document.getElementById('regionStatus').innerHTML = t.workerRegion + '<span style="color: #ff4444;">❌ ' + t.detectionFailed + '</span>';
                        document.getElementById('geoInfo').innerHTML = t.detectionMethod + '<span style="color: #ff4444;">❌ ' + t.detectionFailed + '</span>';
                        document.getElementById('backupStatus').innerHTML = t.proxyIPStatus + '<span style="color: #ff4444;">❌ ' + t.detectionFailed + '</span>';
                        document.getElementById('currentIP').innerHTML = t.currentIP + '<span style="color: #ff4444;">❌ ' + t.detectionFailed + '</span>';
                        document.getElementById('regionMatch').innerHTML = t.regionMatch + '<span style="color: #ff4444;">❌ ' + t.detectionFailed + '</span>';
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
                            alert(t.apiTestResult + data.detectedRegion + '\\n' + t.apiTestTime + data.timestamp);
                    } else {
                            alert(t.apiTestFailed + (data.error || t.unknownError));
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
                        alert(t.apiTestError + error.message);
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
                            document.getElementById('kvStatus').innerHTML = '<span style="color: #ffaa00;">' + t.kvDisabled + '</span>';
                            document.getElementById('configCard').style.display = 'block';
                            document.getElementById('currentConfig').textContent = t.kvNotConfigured;
                    } else if (response.ok) {
                        try {
                        const data = await response.json();
                        
                            // 检查响应是否包含KV配置信息
                            if (data && data.kvEnabled === true) {
                                document.getElementById('kvStatus').innerHTML = '<span style="color: #44ff44;">' + t.kvEnabled + '</span>';
                                document.getElementById('configContent').style.display = 'block';
                                document.getElementById('configCard').style.display = 'block';
                                await loadCurrentConfig();
                            } else {
                                document.getElementById('kvStatus').innerHTML = '<span style="color: #ffaa00;">' + t.kvDisabled + '</span>';
                                document.getElementById('configCard').style.display = 'block';
                                document.getElementById('currentConfig').textContent = t.kvNotEnabled;
                                }
                        } catch (jsonError) {
                            document.getElementById('kvStatus').innerHTML = '<span style="color: #ffaa00;">' + t.kvCheckFailed + '</span>';
                            document.getElementById('configCard').style.display = 'block';
                            document.getElementById('currentConfig').textContent = t.kvCheckFailedFormat;
                        }
                    } else {
                        document.getElementById('kvStatus').innerHTML = '<span style="color: #ffaa00;">' + t.kvDisabled + '</span>';
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
                    
                    document.getElementById('kvStatus').innerHTML = '<span style="color: #ffaa00;">' + t.kvDisabled + '</span>';
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
                    document.getElementById('tp').value = config.tp || '';
                    document.getElementById('scu').value = config.scu || '';
                    document.getElementById('epd').checked = config.epd !== 'no';
                    document.getElementById('epi').checked = config.epi !== 'no';
                    document.getElementById('egi').checked = config.egi !== 'no';
                    document.getElementById('customPath').value = config.d || '';
                    document.getElementById('customIP').value = config.p || '';
                    document.getElementById('preferredIPs').value = config.yx || '';
                    document.getElementById('preferredIPsURL').value = config.yxURL || '';
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
                    pathTypeStatus.innerHTML = '<div style="color: #44ff44;">使用类型: <strong>自定义路径 (d)</strong></div>' +
                        '<div style="margin-top: 5px; color: #00ff00;">当前路径: <span style="color: #ffaa00;">' + cp + '</span></div>' +
                        '<div style="margin-top: 5px; font-size: 0.9rem; color: #00aa00;">访问地址: ' + 
                        (currentUrl.split('/')[0] + '//' + currentUrl.split('/')[2]) + cp + '/sub</div>';
                } else {
                    // 使用 UUID (u)
                    pathTypeStatus.innerHTML = '<div style="color: #44ff44;">使用类型: <strong>UUID 路径 (u)</strong></div>' +
                        '<div style="margin-top: 5px; color: #00ff00;">当前路径: <span style="color: #ffaa00;">' + (currentPath || '(UUID)') + '</span></div>' +
                        '<div style="margin-top: 5px; font-size: 0.9rem; color: #00aa00;">访问地址: ' + currentUrl.split('/sub')[0] + '/sub</div>';
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
                            wkRegionHint.style.color = '#ffaa00';
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
                statusDiv.textContent = message;
                statusDiv.style.display = 'block';
                statusDiv.style.color = type === 'success' ? '#00ff00' : '#ff0000';
                statusDiv.style.borderColor = type === 'success' ? '#00ff00' : '#ff0000';
                
                setTimeout(function() {
                    statusDiv.style.display = 'none';
                }, 3000);
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
                                homepage: ''
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
            
            document.addEventListener('DOMContentLoaded', function() {
                createMatrixRain();
                checkSystemStatus();
                checkKVStatus();
                
                // 监听customIP输入框变化，实时更新wk地区选择状态
                const customIPInput = document.getElementById('customIP');
                if (customIPInput) {
                    customIPInput.addEventListener('input', function() {
                        updateWkRegionState();
                    });
                }
                
                // 绑定表单事件
                const regionForm = document.getElementById('regionForm');
                if (regionForm) {
                    regionForm.addEventListener('submit', async function(e) {
                        e.preventDefault();
                        const wkRegion = document.getElementById('wkRegion').value;
                        await saveConfig({ wk: wkRegion });
                    });
                }
                
                const saveProtocolBtn = document.getElementById('saveProtocolBtn');
                if (saveProtocolBtn) {
                    saveProtocolBtn.addEventListener('click', async function(e) {
                        e.preventDefault();
                        const configData = { 
                            ev: document.getElementById('ev').checked ? 'yes' : 'no', 
                            et: document.getElementById('et').checked ? 'yes' : 'no', 
                            ex: document.getElementById('ex').checked ? 'yes' : 'no', 
                            tp: document.getElementById('tp').value
                        };
                        
                        if (!document.getElementById('ev').checked && 
                            !document.getElementById('et').checked && 
                            !document.getElementById('ex').checked) {
                            alert('至少需要启用一个协议！');
                            return;
                        }
                        
                        await saveConfig(configData);
                    });
                }
                
                const otherConfigForm = document.getElementById('otherConfigForm');
                if (otherConfigForm) {
                    otherConfigForm.addEventListener('submit', async function(e) {
                        e.preventDefault();
                        const configData = { ev: document.getElementById('ev').checked ? 'yes' : 'no', et: document.getElementById('et').checked ? 'yes' : 'no', ex: document.getElementById('ex').checked ? 'yes' : 'no', tp: document.getElementById('tp').value,
                            d: document.getElementById('customPath').value,
                            p: document.getElementById('customIP').value,
                            yx: document.getElementById('preferredIPs').value,
                            yxURL: document.getElementById('preferredIPsURL').value,
                            s: document.getElementById('socksConfig').value,
                            homepage: document.getElementById('customHomepage').value
                        };
                        
                        // 确保至少选择一个协议
                        if (!document.getElementById('ev').checked && 
                            !document.getElementById('et').checked && 
                            !document.getElementById('ex').checked) {
                            alert('至少需要启用一个协议！');
                            return;
                        }
                        
                        await saveConfig(configData);
                    });
                }
                
                const advancedConfigForm = document.getElementById('advancedConfigForm');
                if (advancedConfigForm) {
                    advancedConfigForm.addEventListener('submit', async function(e) {
                        e.preventDefault();
                        const configData = { scu: document.getElementById('scu').value, epd: document.getElementById('epd').checked ? 'yes' : 'no', epi: document.getElementById('epi').checked ? 'yes' : 'no', egi: document.getElementById('egi').checked ? 'yes' : 'no', ae: document.getElementById('apiEnabled').value,
                            rm: document.getElementById('regionMatching').value,
                            qj: document.getElementById('downgradeControl').value,
                            dkby: document.getElementById('portControl').value,
                            yxby: document.getElementById('preferredControl').value
                        };
                        await saveConfig(configData);
                    });
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
        
        const passwordToHash = tp || ut;
        const sha224Password = await sha224Hash(passwordToHash);
        
        if (buffer.byteLength < 56) {
            return {
                hasError: true,
                message: "invalid " + atob('dHJvamFu') + " data - too short"
            };
        }
        let crLfIndex = 56;
        if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
            return {
                hasError: true,
                message: "invalid " + atob('dHJvamFu') + " header format (missing CR LF)"
            };
        }
        const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
        if (password !== sha224Password) {
            return {
                hasError: true,
                message: "invalid " + atob('dHJvamFu') + " password"
            };
        }

        const socks5DataBuffer = buffer.slice(crLfIndex + 2);
        if (socks5DataBuffer.byteLength < 6) {
            return {
                hasError: true,
                message: atob('aW52YWxpZCBTT0NLUzUgcmVxdWVzdCBkYXRh')
            };
        }

        const view = new DataView(socks5DataBuffer);
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
                address = new Uint8Array(
                socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
                ).join(".");
                break;
            case 3:
                addressLength = new Uint8Array(
                socks5DataBuffer.slice(addressIndex, addressIndex + 1)
                )[0];
                addressIndex += 1;
                address = new TextDecoder().decode(
                socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
                );
                break;
            case 4:
                addressLength = 16;
                const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
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
        const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
        const portRemote = new DataView(portBuffer).getUint16(0);
        
        return {
            hasError: false,
            addressRemote: address,
            addressType: atype,
            port: portRemote,
            hostname: address,
            rawClientData: socks5DataBuffer.slice(portIndex + 4)
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
        
        const url = piu || "https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt";
        try {
            const response = await fetch(url);
            if (!response.ok) return [];
            const text = await response.text();
            const results = [];
            const lines = text.trim().replace(/\r/g, "").split('\n');
            const regex = /^([^:]+):(\d+)#(.*)$/;

            for (const line of lines) {
                const trimmedLine = line.trim();
                if (!trimmedLine) continue;
                const match = trimmedLine.match(regex);
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

    function generateLinksFromNewIPs(list, user, workerDomain) {
        
        const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
        const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
        
        const links = [];
        const wsPath = '/?ed=2048';
        const proto = atob('dmxlc3M=');
        
        list.forEach(item => {
            const nodeName = item.name.replace(/\s/g, '_');
            const port = item.port;
            
            if (CF_HTTPS_PORTS.includes(port)) {
                
                const wsNodeName = `${nodeName}-${port}-WS-TLS`;
                const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
                links.push(link);
            } else if (CF_HTTP_PORTS.includes(port)) {
                
                if (!disableNonTLS) {
                    const wsNodeName = `${nodeName}-${port}-WS`;
                    const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=none&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
                    links.push(link);
                }
            } else {
                
                const wsNodeName = `${nodeName}-${port}-WS-TLS`;
                const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
                links.push(link);
            }
        });
        return links;
    }

    function generateXhttpLinksFromSource(list, user, workerDomain) {
        const links = [];
        const nodePath = user.substring(0, 8);
        
        list.forEach(item => {
            const nodeNameBase = item.isp.replace(/\s/g, '_');
            const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;
            const port = item.port || 443;
            
            const wsNodeName = `${nodeNameBase}-${port}-xhttp`;
            const params = new URLSearchParams({
                encryption: 'none',
                security: 'tls',
                sni: workerDomain,
                fp: 'chrome',
                allowInsecure: '1',
                type: 'xhttp',
                host: workerDomain,
                path: `/${nodePath}`,
                mode: 'stream-one'
            });
            
            links.push(`vless://${user}@${safeIP}:${port}?${params.toString()}#${encodeURIComponent(wsNodeName)}`);
        });
        
        return links;
    }

    async function generateTrojanLinksFromNewIPs(list, user, workerDomain) {
        
        const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
        const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
        
        const links = [];
        const wsPath = '/?ed=2048';
        
        const password = tp || user;
        
        list.forEach(item => {
            const nodeName = item.name.replace(/\s/g, '_');
            const port = item.port;
            
            if (CF_HTTPS_PORTS.includes(port)) {
                
                const wsNodeName = `${nodeName}-${port}-${atob('VHJvamFu')}-WS-TLS`;
                const link = `${atob('dHJvamFuOi8v')}${password}@${item.ip}:${port}?security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
                links.push(link);
            } else if (CF_HTTP_PORTS.includes(port)) {
                
                if (!disableNonTLS) {
                    const wsNodeName = `${nodeName}-${port}-${atob('VHJvamFu')}-WS`;
                    const link = `${atob('dHJvamFuOi8v')}${password}@${item.ip}:${port}?security=none&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
                    links.push(link);
                }
            } else {
                
                const wsNodeName = `${nodeName}-${port}-${atob('VHJvamFu')}-WS-TLS`;
                const link = `${atob('dHJvamFuOi8v')}${password}@${item.ip}:${port}?security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
                links.push(link);
            }
        });
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
                
                const newPreferredIPsURL = getConfigValue('yxURL', '') || 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';
                const defaultURL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';
                if (newPreferredIPsURL !== defaultURL) {
                    directDomains.length = 0;
                    customPreferredIPs = [];
                    customPreferredDomains = [];
                } else {
                    backupIPs = [
                        { domain: 'ProxyIP.US.CMLiussss.net', region: 'US', regionCode: 'US', port: 443 },
                        { domain: 'ProxyIP.SG.CMLiussss.net', region: 'SG', regionCode: 'SG', port: 443 },
                        { domain: 'ProxyIP.JP.CMLiussss.net', region: 'JP', regionCode: 'JP', port: 443 },
                        { domain: 'ProxyIP.HK.CMLiussss.net', region: 'HK', regionCode: 'HK', port: 443 },
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
                    directDomains.length = 0;
                    directDomains.push(
                        { name: "cloudflare.182682.xyz", domain: "cloudflare.182682.xyz" }, 
                        { name: "speed.marisalnc.com", domain: "speed.marisalnc.com" },
                        { domain: "freeyx.cloudflare88.eu.org" }, 
                        { domain: "bestcf.top" }, 
                        { domain: "cdn.2020111.xyz" }, 
                        { domain: "cfip.cfcdn.vip" },
                        { domain: "cf.0sm.com" }, 
                        { domain: "cf.090227.xyz" }, 
                        { domain: "cf.zhetengsha.eu.org" }, 
                        { domain: "cloudflare.9jy.cc" },
                        { domain: "cf.zerone-cdn.pp.ua" }, 
                        { domain: "cfip.1323123.xyz" }, 
                        { domain: "cnamefuckxxs.yuchen.icu" }, 
                        { domain: "cloudflare-ip.mofashi.ltd" },
                        { domain: "115155.xyz" }, 
                        { domain: "cname.xirancdn.us" }, 
                        { domain: "f3058171cad.002404.xyz" }, 
                        { domain: "8.889288.xyz" },
                        { domain: "cdn.tzpro.xyz" }, 
                        { domain: "cf.877771.xyz" }, 
                        { domain: "xn--b6gac.eu.org" }
                    );
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
        
        const preferredDomainsControl = getConfigValue('epd', '');
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
        
        cp = getConfigValue('d', '') || '';
        
        piu = getConfigValue('yxURL', '') || 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';
        
        const envFallback = getConfigValue('p', '');
        if (envFallback) {
            const fallbackValue = envFallback.toLowerCase();
            if (fallbackValue.includes(']:')) {
                const lastColonIndex = fallbackValue.lastIndexOf(':');
                fallbackPort = fallbackValue.slice(lastColonIndex + 1);
                fallbackAddress = fallbackValue.slice(0, lastColonIndex);
            } else if (!fallbackValue.includes(']:') && !fallbackValue.includes(']')) {
                [fallbackAddress, fallbackPort = '443'] = fallbackValue.split(':');
            } else {
                fallbackAddress = fallbackValue;
                fallbackPort = '443';
            }
        } else {
            fallbackAddress = '';
            fallbackPort = '443';
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
        
        const defaultURL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';
        if (piu !== defaultURL) {
            directDomains.length = 0;
            customPreferredIPs = [];
            customPreferredDomains = [];
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
