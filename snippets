import { connect } from 'cloudflare:sockets';

// --- 硬编码配置 ---
const authToken = 'f64bdc57-0f54-4705-bf75-cfd646d98c06';
let fallbackAddress = '';
const socks5Config = '';
// 手动指定地区（留空则自动检测，可选值：US、SG、JP、HK、KR、DE、SE、NL、FI、GB）
const manualWorkerRegion = '';
// D短地址（自定义路径，留空则使用UUID路径，支持多级路径如：mypath 或 path/to/sub）
const customPath = '';
// GitHub订阅URL（硬编码）
const githubPreferredURL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';
// 启用GitHub优选IP（true启用，false禁用）
const enableGitHubPreferred = true;
// 启用其他优选（域名优选，true启用，false禁用）
const enableOtherPreferred = true;
// API地址配置（订阅转换服务）
const apiBaseUrl = 'https://url.v1.mk/sub';

const directDomains = [
  { name: "cloudflare.182682.xyz", domain: "cloudflare.182682.xyz" },
  { name: "speed.marisalnc.com", domain: "speed.marisalnc.com" },
  { domain: "freeyx.cloudflare88.eu.org" }, { domain: "bestcf.top" },
  { domain: "cdn.2020111.xyz" }, { domain: "cfip.cfcdn.vip" },
  { domain: "cf.0sm.com" }, { domain: "cf.090227.xyz" },
  { domain: "cf.zhetengsha.eu.org" }, { domain: "cloudflare.9jy.cc" },
  { domain: "cf.zerone-cdn.pp.ua" }, { domain: "cfip.1323123.xyz" },
  { domain: "cnamefuckxxs.yuchen.icu" }, { domain: "cloudflare-ip.mofashi.ltd" },
  { domain: "115155.xyz" }, { domain: "cname.xirancdn.us" },
  { domain: "f3058171cad.002404.xyz" }, { domain: "8.889288.xyz" },
  { domain: "cdn.tzpro.xyz" }, { domain: "cf.877771.xyz" },
  { domain: "xn--b6gac.eu.org" }
];

const parsedSocks5Config = {};
const isSocksEnabled = false;

let enableRegionMatching = true;
let currentWorkerRegion = '';

const backupIPs = [
  { domain: 'ProxyIP.US.CMLiussss.net', region: 'US', regionCode: 'US', port: 443 },
  { domain: 'ProxyIP.SG.CMLiussss.net', region: 'SG', regionCode: 'SG', port: 443 },
  { domain: 'ProxyIP.JP.CMLiussss.net', region: 'JP', regionCode: 'JP', port: 443 },
  { domain: 'ProxyIP.HK.CMLiussss.net', region: 'HK', regionCode: 'HK', port: 443 },
  { domain: 'ProxyIP.KR.CMLiussss.net', region: 'KR', regionCode: 'KR', port: 443 },
  { domain: 'ProxyIP.DE.CMLiussss.net', region: 'DE', regionCode: 'DE', port: 443 },
  { domain: 'ProxyIP.SE.CMLiussss.net', region: 'SE', regionCode: 'SE', port: 443 },
  { domain: 'ProxyIP.NL.CMLiussss.net', region: 'NL', regionCode: 'NL', port: 443 },
  { domain: 'ProxyIP.FI.CMLiussss.net', region: 'FI', regionCode: 'FI', port: 443 },
  { domain: 'ProxyIP.GB.CMLiussss.net', region: 'GB', regionCode: 'GB', port: 443 }
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

const ADDRESS_TYPE_IPV4 = 1;
const ADDRESS_TYPE_URL = 2;
const ADDRESS_TYPE_IPV6 = 3;

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
      if (countryToRegion[cfCountry]) return countryToRegion[cfCountry];
    }
    return 'HK';
  } catch (error) {
    return 'HK';
  }
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
  if (!enableRegionMatching || !workerRegion) return availableIPs;
  const priorityRegions = getAllRegionsByPriority(workerRegion);
  const sortedIPs = [];
  for (const region of priorityRegions) {
    const regionIPs = availableIPs.filter(ip => ip.regionCode === region);
    sortedIPs.push(...regionIPs);
  }
  return sortedIPs;
}

async function getBestBackupIP(workerRegion = '') {
  if (backupIPs.length === 0) return null;
  const availableIPs = backupIPs.map(ip => ({ ...ip, available: true }));
  if (enableRegionMatching && workerRegion) {
    const sortedIPs = getSmartRegionSelection(workerRegion, availableIPs);
    if (sortedIPs.length > 0) return sortedIPs[0];
  }
  return availableIPs[0];
}

function parseAddressAndPort(input) {
  if (!input) return { address: '', port: null };
  if (input.includes('[') && input.includes(']')) {
    const match = input.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (match) {
      return { address: match[1], port: match[2] ? parseInt(match[2], 10) : null };
    }
  }
  const lastColonIndex = input.lastIndexOf(':');
  if (lastColonIndex > 0) {
    const address = input.substring(0, lastColonIndex);
    const portStr = input.substring(lastColonIndex + 1);
    const port = parseInt(portStr, 10);
    if (!isNaN(port) && port > 0 && port <= 65535) return { address, port };
  }
  return { address: input, port: null };
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      if (manualWorkerRegion && manualWorkerRegion.trim()) {
        currentWorkerRegion = manualWorkerRegion.trim().toUpperCase();
      } else {
        currentWorkerRegion = await detectWorkerRegion(request);
      }

      let currentFallbackAddress = fallbackAddress;
      if (!currentFallbackAddress && currentWorkerRegion) {
        const bestBackupIP = await getBestBackupIP(currentWorkerRegion);
        if (bestBackupIP) currentFallbackAddress = bestBackupIP.domain + ':' + bestBackupIP.port;
      }

      if (request.headers.get('Upgrade') === 'websocket') {
        return await handleWsRequest(request, currentFallbackAddress);
      } else if (request.method === 'GET') {
        if (url.pathname === '/') {
          const successHtml = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>服务正常</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background-color:#121212;color:#e0e0e0;text-align:center;}.container{padding:2rem;border-radius:8px;background-color:#1e1e1e;box-shadow:0 4px 6px rgba(0,0,0,0.1);}h1{color:#4caf50;}</style></head><body><div class="container"><h1>✅ 服务正常</h1><p>请继续后面的操作。</p></div></body></html>`;
          return new Response(successHtml, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        }

        if (customPath && customPath.trim()) {
          const cleanCustomPath = customPath.trim().startsWith('/') ? customPath.trim() : '/' + customPath.trim();
          const normalizedCustomPath = cleanCustomPath.endsWith('/') && cleanCustomPath.length > 1 ? cleanCustomPath.slice(0, -1) : cleanCustomPath;
          const normalizedPath = url.pathname.endsWith('/') && url.pathname.length > 1 ? url.pathname.slice(0, -1) : url.pathname;

          if (normalizedPath === normalizedCustomPath) {
            return await handleSubscriptionPage(request, authToken);
          }

          if (normalizedPath === normalizedCustomPath + '/sub') {
            return await handleSubscriptionRequest(request, authToken, url);
          }

          if (url.pathname.length > 1 && url.pathname !== '/') {
            const user = url.pathname.replace(/\/$/, '').replace('/sub', '').substring(1);
            if (isValidFormat(user)) {
              return new Response(JSON.stringify({
                error: '访问被拒绝',
                message: '当前 Worker 已启用自定义路径模式，UUID 访问已禁用'
              }), {
                status: 403,
                headers: { 'Content-Type': 'application/json; charset=utf-8' }
              });
            }
          }
        } else {
          if (url.pathname.length > 1 && url.pathname !== '/' && !url.pathname.includes('/sub')) {
            const uuid = url.pathname.replace(/\/$/, '').substring(1);
            if (isValidFormat(uuid)) {
              if (uuid === authToken) return await handleSubscriptionPage(request, uuid);
              return new Response('UUID错误', { status: 403 });
            }
          }

          if (url.pathname.includes('/sub')) {
            const pathParts = url.pathname.split('/');
            if (pathParts.length === 2 && pathParts[1] === 'sub') {
              const uuid = pathParts[0].substring(1);
              if (isValidFormat(uuid)) {
                if (uuid === authToken) return await handleSubscriptionRequest(request, uuid, url);
                return new Response('UUID错误', { status: 403 });
              }
            }
          }

          if (url.pathname.toLowerCase().includes(`/${authToken}`)) {
            return await handleSubscriptionRequest(request, authToken);
          }
        }
      }
      return new Response('Not Found', { status: 404 });
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

async function handleSubscriptionPage(request, uuid = null) {
  if (!uuid) uuid = authToken;

  const pageHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>订阅中心</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Courier New",monospace;background:#000;color:#00ff00;min-height:100vh;overflow-x:hidden;position:relative}
.matrix-bg{position:fixed;top:0;left:0;width:100%;height:100%;background:linear-gradient(45deg,#000 0%,#001100 50%,#000 100%);z-index:-1}
.matrix-rain{position:fixed;top:0;left:0;width:100%;height:100%;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,0,0.03) 2px,rgba(0,255,0,0.03) 4px);animation:matrix-fall 20s linear infinite;z-index:-1}
@keyframes matrix-fall{0%{transform:translateY(-100%)}100%{transform:translateY(100vh)}}
.container{max-width:900px;margin:0 auto;padding:20px;position:relative;z-index:1}
.header{text-align:center;margin-bottom:40px}
.title{font-size:3rem;font-weight:bold;text-shadow:0 0 10px #00ff00,0 0 20px #00ff00,0 0 30px #00ff00;margin-bottom:10px;animation:matrix-glow 2s ease-in-out infinite alternate}
@keyframes matrix-glow{from{text-shadow:0 0 10px #00ff00,0 0 20px #00ff00,0 0 30px #00ff00}to{text-shadow:0 0 20px #00ff00,0 0 30px #00ff00,0 0 40px #00ff00}}
.subtitle{color:#00aa00;margin-bottom:30px;font-size:1.2rem}
.card{background:rgba(0,20,0,0.8);border:2px solid #00ff00;border-radius:0;padding:30px;margin-bottom:20px;box-shadow:0 0 20px rgba(0,255,0,0.3);position:relative}
.card::before{content:"";position:absolute;top:0;left:0;width:100%;height:100%;background:linear-gradient(45deg,transparent 49%,#00ff00 50%,transparent 51%);opacity:0.1;pointer-events:none}
.card-title{font-size:1.8rem;margin-bottom:20px;color:#00ff00;text-shadow:0 0 5px #00ff00}
.client-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:15px;margin:20px 0}
.client-btn{background:rgba(0,20,0,0.6);border:2px solid #00ff00;padding:15px 20px;color:#00ff00;font-family:"Courier New",monospace;font-weight:bold;cursor:pointer;transition:all 0.3s ease;text-align:center;position:relative;overflow:hidden}
.client-btn::before{content:"";position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(0,255,0,0.3),transparent);transition:left 0.5s ease}
.client-btn:hover::before{left:100%}
.client-btn:hover{background:rgba(0,255,0,0.2);box-shadow:0 0 15px #00ff00;transform:translateY(-2px)}
.generate-btn{background:rgba(0,255,0,0.1);border:2px solid #00ff00;padding:15px 30px;color:#00ff00;font-family:"Courier New",monospace;font-weight:bold;cursor:pointer;transition:all 0.3s ease;margin-right:15px}
.generate-btn:hover{background:rgba(0,255,0,0.3);box-shadow:0 0 20px #00ff00;transform:translateY(-2px)}
.subscription-url{background:rgba(0,0,0,0.8);border:1px solid #00ff00;padding:15px;word-break:break-all;font-family:"Courier New",monospace;color:#00ff00;margin-top:20px;display:none;box-shadow:inset 0 0 10px rgba(0,255,0,0.3)}
.matrix-text{position:fixed;top:20px;right:20px;color:#00ff00;font-family:"Courier New",monospace;font-size:0.8rem;opacity:0.6;animation:matrix-flicker 3s infinite}
@keyframes matrix-flicker{0%,100%{opacity:0.6}50%{opacity:1}}
</style>
</head>
<body>
<div class="matrix-bg"></div>
<div class="matrix-rain"></div>
<div class="matrix-text">代理订阅中心精简版 v2.1</div>
<div class="container">
<div class="header">
<h1 class="title">代理订阅中心</h1>
<p class="subtitle">多客户端支持 • 智能优选 • 一键生成</p>
</div>
<div class="card">
<h2 class="card-title">[ 选择客户端 ]</h2>
<div class="client-grid">
<button class="client-btn" onclick="generateClientLink('clash','CLASH')">CLASH</button>
<button class="client-btn" onclick="generateClientLink('surge','SURGE')">SURGE</button>
<button class="client-btn" onclick="generateClientLink('singbox','SING-BOX')">SING-BOX</button>
<button class="client-btn" onclick="generateClientLink('loon','LOON')">LOON</button>
<button class="client-btn" onclick="generateClientLink('quanx','QUANTUMULT X')">QUANTUMULT X</button>
<button class="client-btn" onclick="generateClientLink('v2ray','V2RAY')">V2RAY</button>
<button class="client-btn" onclick="generateClientLink('v2ray','Shadowrocket')">Shadowrocket</button>
<button class="client-btn" onclick="generateClientLink('v2ray','V2RAYNG')">V2RAYNG</button>
<button class="client-btn" onclick="generateClientLink('v2ray','NEKORAY')">NEKORAY</button>
<button class="client-btn" onclick="generateClientLink('clash','STASH')">STASH</button>
</div>
<div class="subscription-url" id="clientSubscriptionUrl"></div>
</div>
<div class="card">
<h2 class="card-title">[ 快速获取 ]</h2>
<button class="generate-btn" onclick="getBase64Subscription()">获取订阅链接</button>
<div class="subscription-url" id="base64SubscriptionUrl"></div>
</div>
<div class="card">
<h2 class="card-title">[ 相关链接 ]</h2>
<div style="text-align:center;margin:20px 0">
<a href="https://github.com/byJoey/cfnew" target="_blank" style="color:#00ff00;text-decoration:none;margin:0 20px;font-size:1.2rem;text-shadow:0 0 5px #00ff00">GitHub 项目</a>
<a href="https://www.youtube.com/@joeyblog" target="_blank" style="color:#00ff00;text-decoration:none;margin:0 20px;font-size:1.2rem;text-shadow:0 0 5px #00ff00">YouTube @joeyblog</a>
</div>
</div>
</div>
<script>
var SUB_CONVERTER_URL="${apiBaseUrl}";
function tryOpenApp(schemeUrl,fallbackCallback,timeout){
timeout=timeout||2500;
var appOpened=false;
var callbackExecuted=false;
var startTime=Date.now();
var blurHandler=function(){
var elapsed=Date.now()-startTime;
if(elapsed<3000&&!callbackExecuted){appOpened=true;}
};
window.addEventListener('blur',blurHandler);
var hiddenHandler=function(){
var elapsed=Date.now()-startTime;
if(elapsed<3000&&!callbackExecuted){appOpened=true;}
};
document.addEventListener('visibilitychange',hiddenHandler);
var iframe=document.createElement('iframe');
iframe.style.display='none';
iframe.style.width='1px';
iframe.style.height='1px';
iframe.src=schemeUrl;
document.body.appendChild(iframe);
setTimeout(function(){
if(iframe.parentNode)iframe.parentNode.removeChild(iframe);
window.removeEventListener('blur',blurHandler);
document.removeEventListener('visibilitychange',hiddenHandler);
if(!callbackExecuted){
callbackExecuted=true;
if(!appOpened&&fallbackCallback)fallbackCallback();
}
},timeout);
}
function generateClientLink(clientType,clientName){
var currentUrl=window.location.href;
var subscriptionUrl=currentUrl+"/sub";
var schemeUrl='';
var displayName=clientName||'';
var finalUrl=subscriptionUrl;
if(clientType==='v2ray'){
finalUrl=subscriptionUrl;
document.getElementById("clientSubscriptionUrl").textContent=finalUrl;
document.getElementById("clientSubscriptionUrl").style.display="block";
if(clientName==='V2RAY'){
navigator.clipboard.writeText(finalUrl).then(function(){alert(displayName+" 订阅链接已复制");});
}else if(clientName==='Shadowrocket'){
schemeUrl='shadowrocket://add/'+encodeURIComponent(finalUrl);
tryOpenApp(schemeUrl,function(){
navigator.clipboard.writeText(finalUrl).then(function(){alert(displayName+" 订阅链接已复制");});
});
}else if(clientName==='V2RAYNG'){
schemeUrl='v2rayng://install?url='+encodeURIComponent(finalUrl);
tryOpenApp(schemeUrl,function(){
navigator.clipboard.writeText(finalUrl).then(function(){alert(displayName+" 订阅链接已复制");});
});
}else if(clientName==='NEKORAY'){
schemeUrl='nekoray://install-config?url='+encodeURIComponent(finalUrl);
tryOpenApp(schemeUrl,function(){
navigator.clipboard.writeText(finalUrl).then(function(){alert(displayName+" 订阅链接已复制");});
});
}
}else{
var encodedUrl=encodeURIComponent(subscriptionUrl);
finalUrl=SUB_CONVERTER_URL+"?target="+clientType+"&url="+encodedUrl+"&insert=false";
document.getElementById("clientSubscriptionUrl").textContent=finalUrl;
document.getElementById("clientSubscriptionUrl").style.display="block";
if(clientType==='clash'){
if(clientName==='STASH'){
schemeUrl='stash://install?url='+encodeURIComponent(finalUrl);
displayName='STASH';
}else{
schemeUrl='clash://install-config?url='+encodeURIComponent(finalUrl);
displayName='CLASH';
}
}else if(clientType==='surge'){
schemeUrl='surge:///install-config?url='+encodeURIComponent(finalUrl);
displayName='SURGE';
}else if(clientType==='singbox'){
schemeUrl='sing-box://install-config?url='+encodeURIComponent(finalUrl);
displayName='SING-BOX';
}else if(clientType==='loon'){
schemeUrl='loon://install?url='+encodeURIComponent(finalUrl);
displayName='LOON';
}else if(clientType==='quanx'){
schemeUrl='quantumult-x://install-config?url='+encodeURIComponent(finalUrl);
displayName='QUANTUMULT X';
}
if(schemeUrl){
tryOpenApp(schemeUrl,function(){
navigator.clipboard.writeText(finalUrl).then(function(){alert(displayName+" 订阅链接已复制");});
});
}else{
navigator.clipboard.writeText(finalUrl).then(function(){alert(displayName+" 订阅链接已复制");});
}
}
}
function getBase64Subscription(){
var currentUrl=window.location.href;
var subscriptionUrl=currentUrl+"/sub";
fetch(subscriptionUrl).then(function(response){return response.text();}).then(function(base64Content){
document.getElementById("base64SubscriptionUrl").textContent=base64Content;
document.getElementById("base64SubscriptionUrl").style.display="block";
navigator.clipboard.writeText(base64Content).then(function(){alert("Base64订阅内容已复制");});
}).catch(function(error){alert("获取订阅失败，请重试");});
}
</script>
</body>
</html>`;

  return new Response(pageHtml, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

async function handleSubscriptionRequest(request, uuid, url = null) {
  if (!url) url = new URL(request.url);

  const finalLinks = [];
  const workerDomain = url.hostname;

  const nativeList = [{ ip: workerDomain, isp: '原生地址' }];
  finalLinks.push(...generateLinksFromSource(nativeList, uuid, workerDomain));

  if (enableOtherPreferred) {
    const domainList = directDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain }));
    finalLinks.push(...generateLinksFromSource(domainList, uuid, workerDomain));
  }

  if (enableGitHubPreferred) {
    const newIPList = await fetchAndParseNewIPs();
    if (newIPList.length > 0) finalLinks.push(...generateLinksFromNewIPs(newIPList, uuid, workerDomain));
  }

  if (finalLinks.length === 0) {
    const errorRemark = "所有节点获取失败";
    const errorLink = `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=ws&host=error.com&path=%2F#${encodeURIComponent(errorRemark)}`;
    finalLinks.push(errorLink);
  }

  const subscriptionContent = btoa(finalLinks.join('\n'));

  return new Response(subscriptionContent, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    },
  });
}

function generateLinksFromSource(list, uuid, workerDomain) {
  const httpsPorts = [443];
  const links = [];
  const wsPath = '/?ed=2048';
  const proto = 'vless';

  list.forEach(item => {
    const nodeNameBase = item.isp.replace(/\s/g, '_');
    const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;

    httpsPorts.forEach(port => {
      const wsNodeName = `${nodeNameBase}-${port}-WS-TLS`;
      const wsParams = new URLSearchParams({
        encryption: 'none',
        security: 'tls',
        sni: workerDomain,
        fp: 'randomized',
        type: 'ws',
        host: workerDomain,
        path: wsPath
      });
      links.push(`${proto}://${uuid}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
    });
  });

  return links;
}

async function fetchAndParseNewIPs() {
  const url = githubPreferredURL;
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

function generateLinksFromNewIPs(list, uuid, workerDomain) {
  const links = [];
  const wsPath = '/?ed=2048';
  const proto = 'vless';

  list.forEach(item => {
    const nodeName = item.name;
    const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;
    const params = {
      encryption: 'none',
      security: 'tls',
      sni: workerDomain,
      fp: 'randomized',
      type: 'ws',
      host: workerDomain,
      path: wsPath
    };
    const wsParams = new URLSearchParams(params);
    links.push(`${proto}://${uuid}@${safeIP}:${item.port}?${wsParams.toString()}#${encodeURIComponent(nodeName)}`);
  });

  return links;
}

async function handleWsRequest(request, currentFallbackAddress = null) {
  const wsPair = new WebSocketPair();
  const [clientSock, serverSock] = Object.values(wsPair);
  serverSock.accept();

  let remoteConnWrapper = { socket: null };
  let isDnsQuery = false;

  const fbAddr = currentFallbackAddress || fallbackAddress;

  const earlyData = request.headers.get('sec-websocket-protocol') || '';
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
      const { hasError, message, addressType, port, hostname, rawIndex, version, isUDP } = parseWsPacketHeader(chunk, authToken);
      if (hasError) throw new Error(message);

      if (isUDP) {
        if (port === 53) isDnsQuery = true;
        else throw new Error(E_UDP_DNS_ONLY);
      }
      const respHeader = new Uint8Array([version[0], 0]);
      const rawData = chunk.slice(rawIndex);

      if (isDnsQuery) return forwardUDP(rawData, serverSock, respHeader);
      await forwardTCP(addressType, hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, fbAddr);
    },
  })).catch((err) => { console.log('WS Stream Error:', err); });

  return new Response(null, { status: 101, webSocket: clientSock });
}

async function forwardTCP(addrType, host, portNum, rawData, ws, respHeader, remoteConnWrapper, fbAddr = null) {
  async function connectAndSend(address, port) {
    const remoteSock = connect({ hostname: address, port: port });
    const writer = remoteSock.writable.getWriter();
    await writer.write(rawData);
    writer.releaseLock();
    return remoteSock;
  }

  async function retryConnection() {
    let fallbackHost, fallbackPort;
    if (fbAddr && fbAddr.trim()) {
      const parsed = parseAddressAndPort(fbAddr);
      fallbackHost = parsed.address;
      fallbackPort = parsed.port || portNum;
    } else if (fallbackAddress && fallbackAddress.trim()) {
      const parsed = parseAddressAndPort(fallbackAddress);
      fallbackHost = parsed.address;
      fallbackPort = parsed.port || portNum;
    } else {
      const bestBackupIP = await getBestBackupIP(currentWorkerRegion);
      fallbackHost = bestBackupIP ? bestBackupIP.domain : host;
      fallbackPort = bestBackupIP ? bestBackupIP.port : portNum;
    }
    const newSocket = await connectAndSend(fallbackHost || host, fallbackPort);
    remoteConnWrapper.socket = newSocket;
    newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
    connectStreams(newSocket, ws, respHeader, null);
  }

  try {
    const initialSocket = await connectAndSend(host, portNum);
    remoteConnWrapper.socket = initialSocket;
    connectStreams(initialSocket, ws, respHeader, retryConnection);
  } catch (err) {
    console.log('Initial connection failed, trying fallback:', err);
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
  if (cmd === 1) { }
  else if (cmd === 2) { isUDP = true; }
  else { return { hasError: true, message: E_UNSUPPORTED_CMD }; }

  const portIdx = 19 + optLen;
  const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
  let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
  const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];

  switch (addressType) {
    case ADDRESS_TYPE_IPV4:
      addrLen = 4;
      hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
      break;
    case ADDRESS_TYPE_URL:
      addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
      addrValIdx += 1;
      hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
      break;
    case ADDRESS_TYPE_IPV6:
      addrLen = 16;
      const ipv6 = [];
      const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
      for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
      hostname = ipv6.join(':');
      break;
    default:
      return { hasError: true, message: `${E_INVALID_ADDR_TYPE}: ${addressType}` };
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
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
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
        if (header) {
          webSocket.send(await new Blob([header, chunk]).arrayBuffer());
          header = null;
        } else {
          webSocket.send(chunk);
        }
      },
      abort(reason) { console.error("Readable aborted:", reason); },
    })
  ).catch((error) => { console.error("Stream connection error:", error); closeSocketQuietly(webSocket); });

  if (!hasData && retryFunc) retryFunc();
}

async function forwardUDP(udpChunk, webSocket, respHeader) {
  try {
    const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
    let vlessHeader = respHeader;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();
    await tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        if (webSocket.readyState === 1) {
          if (vlessHeader) {
            webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
            vlessHeader = null;
          } else {
            webSocket.send(chunk);
          }
        }
      },
    }));
  } catch (error) {
    console.error(`DNS forward error: ${error.message}`);
  }
}

function base64ToArray(b64Str) {
  if (!b64Str) return { error: null };
  try {
    b64Str = b64Str.replace(/-/g, '+').replace(/_/g, '/');
    return { earlyData: Uint8Array.from(atob(b64Str), (c) => c.charCodeAt(0)).buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function isValidFormat(uuid) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

function closeSocketQuietly(socket) {
  try { if (socket.readyState === 1 || socket.readyState === 2) socket.close(); }
  catch (error) { }
}

const hexTable = Array.from({ length: 256 }, (v, i) => (i + 256).toString(16).slice(1));

function formatIdentifier(arr, offset = 0) {
  const id = (
    hexTable[arr[offset]] + hexTable[arr[offset + 1]] + hexTable[arr[offset + 2]] + hexTable[arr[offset + 3]] + "-" +
    hexTable[arr[offset + 4]] + hexTable[arr[offset + 5]] + "-" +
    hexTable[arr[offset + 6]] + hexTable[arr[offset + 7]] + "-" +
    hexTable[arr[offset + 8]] + hexTable[arr[offset + 9]] + "-" +
    hexTable[arr[offset + 10]] + hexTable[arr[offset + 11]] + hexTable[arr[offset + 12]] + hexTable[arr[offset + 13]] +
    hexTable[arr[offset + 14]] + hexTable[arr[offset + 15]]
  ).toLowerCase();
  if (!isValidFormat(id)) throw new TypeError(E_INVALID_ID_STR);
  return id;
}
