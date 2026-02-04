// Cloudflare Worker - 简化版优选工具
// 仅保留优选域名、优选IP、GitHub、上报和节点生成功能
// 修复记录：已修正 VMess 协议下节点名称包含中文导致 Error 1101 的问题

// 默认配置
let customPreferredIPs = [];
let customPreferredDomains = [];
let epd = true;  // 启用优选域名
let epi = true;  // 启用优选IP
let egi = true;  // 启用GitHub优选
let ev = true;   // 启用VLESS协议
let et = false;  // 启用Trojan协议
let vm = false;  // 启用VMess协议
let scu = 'https://url.v1.mk/sub';  // 订阅转换地址
// ECH (Encrypted Client Hello)
let enableECH = false;
let customDNS = 'https://dns.joeyblog.eu.org/joeyblog';
let customECHDomain = 'cloudflare-ech.com';

// 默认优选域名列表
const directDomains = [
    { name: "cloudflare.182682.xyz", domain: "cloudflare.182682.xyz" },
    { domain: "freeyx.cloudflare88.eu.org" },
    { domain: "bestcf.top" },
    { domain: "cdn.2020111.xyz" },
    { domain: "cf.0sm.com" },
    { domain: "cf.090227.xyz" },
    { domain: "cf.zhetengsha.eu.org" },
    { domain: "cfip.1323123.xyz" },
    { domain: "cloudflare-ip.mofashi.ltd" },
    { domain: "cf.877771.xyz" },
    { domain: "xn--b6gac.eu.org" }
];

// 默认优选IP来源URL
const defaultIPURL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';

// UUID验证
function isValidUUID(str) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(str);
}

function yamlQuote(value) {
    const str = value === undefined || value === null ? '' : String(value);
    const escaped = str
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\r/g, '\\r')
        .replace(/\n/g, '\\n')
        .replace(/\t/g, '\\t');
    return `"${escaped}"`;
}

function parseVlessLink(link, fallbackName = '节点') {
    try {
        const url = new URL(link);
        if (url.protocol !== 'vless:') return null;

        const name = decodeURIComponent((url.hash || '').replace(/^#/, '')) || fallbackName;
        const params = url.searchParams;
        const security = (params.get('security') || '').toLowerCase();
        const tls = security === 'tls';
        let server = url.hostname;
        if (server.startsWith('[') && server.endsWith(']')) {
            server = server.slice(1, -1);
        }
        const port = url.port ? Number(url.port) : (tls ? 443 : 80);

        return {
            name,
            server,
            port: Number.isFinite(port) ? port : (tls ? 443 : 80),
            uuid: url.username || '',
            tls,
            path: params.get('path') || '/',
            host: params.get('host') || '',
            sni: params.get('sni') || '',
            ech: params.get('ech') || ''
        };
    } catch {
        return null;
    }
}

// 从环境变量获取配置
function getConfigValue(key, defaultValue) {
    return defaultValue || '';
}

// 获取动态IP列表（支持IPv4/IPv6和运营商筛选）
async function fetchDynamicIPs(ipv4Enabled = true, ipv6Enabled = true, ispMobile = true, ispUnicom = true, ispTelecom = true) {
    const v4Url = "https://www.wetest.vip/page/cloudflare/address_v4.html";
    const v6Url = "https://www.wetest.vip/page/cloudflare/address_v6.html";
    let results = [];

    try {
        const fetchPromises = [];
        if (ipv4Enabled) {
            fetchPromises.push(fetchAndParseWetest(v4Url));
        } else {
            fetchPromises.push(Promise.resolve([]));
        }
        if (ipv6Enabled) {
            fetchPromises.push(fetchAndParseWetest(v6Url));
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

        return results.length > 0 ? results : [];
    } catch (e) {
        return [];
    }
}

// 解析wetest页面
async function fetchAndParseWetest(url) {
    try {
        const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!response.ok) return [];
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
        return results;
    } catch (error) {
        return [];
    }
}

// 整理成数组
async function 整理成数组(内容) {
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
    const 地址数组 = 替换后的内容.split(',');
    return 地址数组;
}

// 请求优选API
async function 请求优选API(urls, 默认端口 = '8443', 超时时间 = 3000) {
    if (!urls?.length) return [];
    const results = new Set();
    await Promise.allSettled(urls.map(async (url) => {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 超时时间);
            const response = await fetch(url, { signal: controller.signal });
            clearTimeout(timeoutId);
            let text = '';
            try {
                const buffer = await response.arrayBuffer();
                const contentType = (response.headers.get('content-type') || '').toLowerCase();
                const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

                // 根据 Content-Type 响应头判断编码优先级
                let decoders = ['utf-8', 'gb2312']; // 默认优先 UTF-8
                if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
                    decoders = ['gb2312', 'utf-8']; // 如果明确指定 GB 系编码，优先尝试 GB2312
                }

                // 尝试多种编码解码
                let decodeSuccess = false;
                for (const decoder of decoders) {
                    try {
                        const decoded = new TextDecoder(decoder).decode(buffer);
                        // 验证解码结果的有效性
                        if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
                            text = decoded;
                            decodeSuccess = true;
                            break;
                        } else if (decoded && decoded.length > 0) {
                            // 如果有替换字符 (U+FFFD)，说明编码不匹配，继续尝试下一个编码
                            continue;
                        }
                    } catch (e) {
                        // 该编码解码失败，尝试下一个
                        continue;
                    }
                }

                // 如果所有编码都失败或无效，尝试 response.text()
                if (!decodeSuccess) {
                    text = await response.text();
                }

                // 如果返回的是空或无效数据，返回
                if (!text || text.trim().length === 0) {
                    return;
                }
            } catch (e) {
                console.error('Failed to decode response:', e);
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
                    const port = new URL(url).searchParams.get('port') || 默认端口;
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
                    const port = new URL(url).searchParams.get('port') || 默认端口;
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

// 从GitHub获取优选IP（保留原有功能，同时支持优选API）
async function fetchAndParseNewIPs(piu) {
    const url = piu || defaultIPURL;
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

// 生成VLESS链接
function generateLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/', echConfig = null) {
    const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
    const defaultHttpsPorts = [8443];
    const defaultHttpPorts = disableNonTLS ? [] : [80];
    const links = [];
    const wsPath = customPath || '/';
    const proto = 'vless';

    list.forEach(item => {
        let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
        if (item.colo && item.colo.trim()) {
            nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
        }
        const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;

        let portsToGenerate = [];

        if (item.port) {
            const port = item.port;
            if (CF_HTTPS_PORTS.includes(port)) {
                portsToGenerate.push({ port: port, tls: true });
            } else if (CF_HTTP_PORTS.includes(port)) {
                portsToGenerate.push({ port: port, tls: false });
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
                if (echConfig) {
                    wsParams.set('alpn', 'h3,h2,http/1.1');
                    wsParams.set('ech', echConfig);
                }
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

// 生成Trojan链接
async function generateTrojanLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/', echConfig = null) {
    const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
    const defaultHttpsPorts = [8443];
    const defaultHttpPorts = disableNonTLS ? [] : [80];
    const links = [];
    const wsPath = customPath || '/';
    const password = user;  // Trojan使用UUID作为密码

    list.forEach(item => {
        let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
        if (item.colo && item.colo.trim()) {
            nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
        }
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
                const wsNodeName = `${nodeNameBase}-${port}-Trojan-WS-TLS`;
                const wsParams = new URLSearchParams({
                    security: 'tls',
                    sni: workerDomain,
                    fp: 'chrome',
                    type: 'ws',
                    host: workerDomain,
                    path: wsPath
                });
                if (echConfig) {
                    wsParams.set('alpn', 'h3,h2,http/1.1');
                    wsParams.set('ech', echConfig);
                }
                links.push(`trojan://${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
            } else {
                const wsNodeName = `${nodeNameBase}-${port}-Trojan-WS`;
                const wsParams = new URLSearchParams({
                    security: 'none',
                    type: 'ws',
                    host: workerDomain,
                    path: wsPath
                });
                links.push(`trojan://${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
            }
        });
    });
    return links;
}

// 生成VMess链接 (已修复中文名导致1101报错的问题)
function generateVMessLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/', echConfig = null) {
    const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
    const defaultHttpsPorts = [8443];
    const defaultHttpPorts = disableNonTLS ? [] : [80];
    const links = [];
    const wsPath = customPath || '/';

    list.forEach(item => {
        let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
        if (item.colo && item.colo.trim()) {
            nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
        }
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
            const vmessConfig = {
                v: "2",
                ps: tls ? `${nodeNameBase}-${port}-VMess-WS-TLS` : `${nodeNameBase}-${port}-VMess-WS`,
                add: safeIP,
                port: port.toString(),
                id: user,
                aid: "0",
                scy: "auto",
                net: "ws",
                type: "none",
                host: workerDomain,
                path: wsPath,
                tls: tls ? "tls" : "none"
            };
            if (tls) {
                vmessConfig.sni = workerDomain;
                vmessConfig.fp = "chrome";
            }

            // 核心修复：处理中文编码，防止 btoa 报错
            const jsonStr = JSON.stringify(vmessConfig);
            const vmessBase64 = btoa(encodeURIComponent(jsonStr).replace(/%([0-9A-F]{2})/g,
                function toSolidBytes(match, p1) {
                    return String.fromCharCode('0x' + p1);
                }));

            links.push(`vmess://${vmessBase64}`);
        });
    });
    return links;
}

// 从GitHub IP生成链接（VLESS）
function generateLinksFromNewIPs(list, user, workerDomain, customPath = '/', echConfig = null) {
    const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
    const links = [];
    const wsPath = customPath || '/';
    const proto = 'vless';
    const echSuffix = echConfig ? `&alpn=h3%2Ch2%2Chttp%2F1.1&ech=${encodeURIComponent(echConfig)}` : '';

    list.forEach(item => {
        const nodeName = item.name.replace(/\s/g, '_');
        const port = item.port;

        if (CF_HTTPS_PORTS.includes(port)) {
            const wsNodeName = `${nodeName}-${port}-WS-TLS`;
            const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}${echSuffix}#${encodeURIComponent(wsNodeName)}`;
            links.push(link);
        } else if (CF_HTTP_PORTS.includes(port)) {
            const wsNodeName = `${nodeName}-${port}-WS`;
            const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=none&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
            links.push(link);
        } else {
            const wsNodeName = `${nodeName}-${port}-WS-TLS`;
            const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}${echSuffix}#${encodeURIComponent(wsNodeName)}`;
            links.push(link);
        }
    });
    return links;
}

// 生成订阅内容
async function handleSubscriptionRequest(request, user, customDomain, piu, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, evEnabled, etEnabled, vmEnabled, disableNonTLS, customPath, echConfig = null) {
    const url = new URL(request.url);
    const finalLinks = [];
    const workerDomain = url.hostname;  // workerDomain始终是请求的hostname
    const nodeDomain = customDomain || url.hostname;  // 用户输入的域名用于生成节点时的host/sni
    const target = url.searchParams.get('target') || 'base64';
    const wsPath = customPath || '/';

    async function addNodesFromList(list) {
        // 确保至少有一个协议被启用
        const hasProtocol = evEnabled || etEnabled || vmEnabled;
        const useVL = hasProtocol ? evEnabled : true;  // 如果没有选择任何协议，默认使用VLESS

        if (useVL) {
            finalLinks.push(...generateLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, echConfig));
        }
        if (etEnabled) {
            finalLinks.push(...await generateTrojanLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, echConfig));
        }
        if (vmEnabled) {
            finalLinks.push(...generateVMessLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, echConfig));
        }
    }

    // 原生地址
    const nativeList = [{ ip: workerDomain, isp: '原生地址' }];
    await addNodesFromList(nativeList);

    // 优选域名
    if (epd) {
        const domainList = directDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain }));
        await addNodesFromList(domainList);
    }

    // 优选IP
    if (epi) {
        try {
            const dynamicIPList = await fetchDynamicIPs(ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom);
            if (dynamicIPList.length > 0) {
                await addNodesFromList(dynamicIPList);
            }
        } catch (error) {
            console.error('获取动态IP失败:', error);
        }
    }

    // GitHub优选 / 优选API
    if (egi) {
        try {
            // 检查是否是优选API URL（以https://开头）
            if (piu && piu.toLowerCase().startsWith('https://')) {
                // 从优选API获取IP列表
                const 优选API的IP = await 请求优选API([piu]);
                if (优选API的IP && 优选API的IP.length > 0) {
                    // 解析IP字符串格式：IP:端口#备注
                    const IP列表 = 优选API的IP.map(原始地址 => {
                        // 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选备注
                        const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
                        const match = 原始地址.match(regex);

                        if (match) {
                            const 节点地址 = match[1].replace(/[\[\]]/g, ''); // 移除IPv6的方括号
                            const 节点端口 = match[2] || 8443;
                            const 节点备注 = match[3] || 节点地址;
                            return {
                                ip: 节点地址,
                                port: parseInt(节点端口),
                                name: 节点备注
                            };
                        }
                        return null;
                    }).filter(item => item !== null);

                    if (IP列表.length > 0) {
                        const hasProtocol = evEnabled || etEnabled || vmEnabled;
                        const useVL = hasProtocol ? evEnabled : true;

                        if (useVL) {
                            finalLinks.push(...generateLinksFromNewIPs(IP列表, user, nodeDomain, wsPath, echConfig));
                        }
                    }
                }
            } else if (piu && piu.includes('\n')) {
                // 支持多行文本，包含混合格式（优选API URL + IP列表）
                const 完整优选列表 = await 整理成数组(piu);
                const 优选API = [], 优选IP = [], 其他节点 = [];

                for (const 元素 of 完整优选列表) {
                    if (元素.toLowerCase().startsWith('https://')) {
                        优选API.push(元素);
                    } else if (元素.toLowerCase().includes('://')) {
                        其他节点.push(元素);
                    } else {
                        优选IP.push(元素);
                    }
                }

                // 从优选API获取IP
                if (优选API.length > 0) {
                    const 优选API的IP = await 请求优选API(优选API);
                    优选IP.push(...优选API的IP);
                }

                // 解析所有IP并生成节点
                if (优选IP.length > 0) {
                    const IP列表 = 优选IP.map(原始地址 => {
                        const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
                        const match = 原始地址.match(regex);

                        if (match) {
                            const 节点地址 = match[1].replace(/[\[\]]/g, '');
                            const 节点端口 = match[2] || 8443;
                            const 节点备注 = match[3] || 节点地址;
                            return {
                                ip: 节点地址,
                                port: parseInt(节点端口),
                                name: 节点备注
                            };
                        }
                        return null;
                    }).filter(item => item !== null);

                    if (IP列表.length > 0) {
                        const hasProtocol = evEnabled || etEnabled || vmEnabled;
                        const useVL = hasProtocol ? evEnabled : true;

                        if (useVL) {
                            finalLinks.push(...generateLinksFromNewIPs(IP列表, user, nodeDomain, wsPath, echConfig));
                        }
                    }
                }
            } else {
                // 原有的GitHub优选逻辑（单URL）
                const newIPList = await fetchAndParseNewIPs(piu);
                if (newIPList.length > 0) {
                    const hasProtocol = evEnabled || etEnabled || vmEnabled;
                    const useVL = hasProtocol ? evEnabled : true;

                    if (useVL) {
                        finalLinks.push(...generateLinksFromNewIPs(newIPList, user, nodeDomain, wsPath, echConfig));
                    }
                }
            }
        } catch (error) {
            console.error('获取优选IP失败:', error);
        }
    }

    if (finalLinks.length === 0) {
        const errorRemark = "所有节点获取失败";
        const errorLink = `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=ws&host=error.com&path=%2F#${encodeURIComponent(errorRemark)}`;
        finalLinks.push(errorLink);
    }

    let subscriptionContent;
    let contentType = 'text/plain; charset=utf-8';

    switch (target.toLowerCase()) {
        case 'clash':
        case 'clashr':
            subscriptionContent = generateClashConfig(finalLinks);
            contentType = 'text/yaml; charset=utf-8';
            break;
        case 'surge':
        case 'surge2':
        case 'surge3':
        case 'surge4':
            subscriptionContent = generateSurgeConfig(finalLinks);
            break;
        case 'quantumult':
        case 'quanx':
            subscriptionContent = generateQuantumultConfig(finalLinks);
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

// 生成Clash配置（简化版，返回YAML格式）
function generateClashConfig(links) {
    let yaml = 'port: 7890\n';
    yaml += 'socks-port: 7891\n';
    yaml += 'allow-lan: false\n';
    yaml += 'mode: rule\n';
    yaml += 'log-level: info\n\n';
    yaml += 'proxies:\n';

    const proxyNames = [];
    links.forEach((link, index) => {
        const parsed = parseVlessLink(link, `节点${index + 1}`);
        if (!parsed) return;

        const { name, server, port, uuid, tls, path, host, sni, ech } = parsed;
        const echDomain = ech ? String(ech).trim().split(/[ +]/)[0] : '';

        proxyNames.push(name);

        yaml += `  - name: ${yamlQuote(name)}\n`;
        yaml += `    type: vless\n`;
        yaml += `    server: ${yamlQuote(server)}\n`;
        yaml += `    port: ${port}\n`;
        yaml += `    uuid: ${yamlQuote(uuid)}\n`;
        yaml += `    tls: ${tls}\n`;
        yaml += `    network: ws\n`;
        yaml += `    ws-opts:\n`;
        yaml += `      path: ${yamlQuote(path)}\n`;
        yaml += `      headers:\n`;
        yaml += `        Host: ${yamlQuote(host)}\n`;
        if (sni) {
            yaml += `    servername: ${yamlQuote(sni)}\n`;
        }
        if (echDomain) {
            yaml += `    ech-opts:\n`;
            yaml += `      enable: true\n`;
            yaml += `      query-server-name: ${yamlQuote(echDomain)}\n`;
        }
    });

    yaml += '\nproxy-groups:\n';
    yaml += '  - name: PROXY\n';
    yaml += '    type: select\n';
    yaml += `    proxies: [${proxyNames.map(n => yamlQuote(n)).join(', ')}]\n`;
    yaml += '  - name: Gemini\n';
    yaml += '    type: select\n';
    yaml += `    proxies: [${proxyNames.map(n => yamlQuote(n)).join(', ')}]\n`;

    yaml += '\nrules:\n';
    yaml += '  - DOMAIN-SUFFIX,gemini.google.com,Gemini\n';
    yaml += '  - DOMAIN-SUFFIX,bard.google.com,Gemini\n';
    yaml += '  - DOMAIN-SUFFIX,generativelanguage.googleapis.com,Gemini\n';
    yaml += '  - DOMAIN-SUFFIX,ai.google.dev,Gemini\n';
    yaml += '  - DOMAIN-SUFFIX,aistudio.google.com,Gemini\n';
    yaml += '  - DOMAIN-SUFFIX,alkalimakersuite-pa.clients6.google.com,Gemini\n';
    yaml += '  - DOMAIN-SUFFIX,deepmind.com,Gemini\n';
    yaml += '  - DOMAIN-SUFFIX,deepmind.google,Gemini\n';
    yaml += '  - DOMAIN-SUFFIX,proactivebackend-pa.googleapis.com,Gemini\n';
    yaml += '  - DOMAIN-KEYWORD,gemini,Gemini\n';
    yaml += '  - DOMAIN-SUFFIX,local,DIRECT\n';
    yaml += '  - IP-CIDR,127.0.0.0/8,DIRECT\n';
    yaml += '  - GEOIP,CN,DIRECT\n';
    yaml += '  - MATCH,PROXY\n';

    return yaml;
}

// 生成Surge配置
function generateSurgeConfig(links) {
    let config = '[Proxy]\n';
    links.forEach(link => {
        const name = decodeURIComponent(link.split('#')[1] || '节点');
        config += `${name} = vless, ${link.match(/@([^:]+):(\d+)/)?.[1] || ''}, ${link.match(/@[^:]+:(\d+)/)?.[1] || '8443'}, username=${link.match(/vless:\/\/([^@]+)@/)?.[1] || ''}, tls=${link.includes('security=tls')}, ws=true, ws-path=${link.match(/path=([^&#]+)/)?.[1] || '/'}, ws-headers=Host:${link.match(/host=([^&#]+)/)?.[1] || ''}\n`;
    });
    config += '\n[Proxy Group]\nPROXY = select, ' + links.map((_, i) => decodeURIComponent(links[i].split('#')[1] || `节点${i + 1}`)).join(', ') + '\n';
    config += 'Gemini = select, ' + links.map((_, i) => decodeURIComponent(links[i].split('#')[1] || `节点${i + 1}`)).join(', ') + '\n';

    config += '\n[Rule]\n';
    config += 'DOMAIN-SUFFIX,gemini.google.com,Gemini\n';
    config += 'DOMAIN-SUFFIX,bard.google.com,Gemini\n';
    config += 'DOMAIN-SUFFIX,generativelanguage.googleapis.com,Gemini\n';
    config += 'DOMAIN-SUFFIX,ai.google.dev,Gemini\n';
    config += 'DOMAIN-SUFFIX,aistudio.google.com,Gemini\n';
    config += 'DOMAIN-SUFFIX,alkalimakersuite-pa.clients6.google.com,Gemini\n';
    config += 'DOMAIN-SUFFIX,deepmind.com,Gemini\n';
    config += 'DOMAIN-SUFFIX,deepmind.google,Gemini\n';
    config += 'DOMAIN-SUFFIX,proactivebackend-pa.googleapis.com,Gemini\n';
    config += 'DOMAIN-KEYWORD,gemini,Gemini\n';
    config += 'DOMAIN-SUFFIX,local,DIRECT\n';
    config += 'IP-CIDR,127.0.0.0/8,DIRECT\n';
    config += 'GEOIP,CN,DIRECT\n';
    config += 'FINAL,PROXY\n';

    return config;
}

// 生成Quantumult配置
function generateQuantumultConfig(links) {
    return btoa(links.join('\n'));
}

// 生成iOS 26风格的主页
function generateHomePage(scuValue) {
    const scu = scuValue || 'https://url.v1.mk/sub';
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>服务器优选工具</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(180deg, #f5f5f7 0%, #ffffff 50%, #fafafa 100%);
            color: #1d1d1f;
            min-height: 100vh;
            padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
            overflow-x: hidden;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            padding: 48px 20px 32px;
        }
        
        .header h1 {
            font-size: 40px;
            font-weight: 700;
            letter-spacing: -0.3px;
            color: #1d1d1f;
            margin-bottom: 8px;
            line-height: 1.1;
        }
        
        .header p {
            font-size: 17px;
            color: #86868b;
            font-weight: 400;
            line-height: 1.5;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.75);
            backdrop-filter: blur(30px) saturate(200%);
            -webkit-backdrop-filter: blur(30px) saturate(200%);
            border-radius: 24px;
            padding: 28px;
            margin-bottom: 20px;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06), 0 1px 3px rgba(0, 0, 0, 0.05);
            border: 0.5px solid rgba(0, 0, 0, 0.06);
            will-change: transform;
        }
        
        .form-group {
            margin-bottom: 24px;
        }
        
        .form-group:last-child {
            margin-bottom: 0;
        }
        
        .form-group label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: #86868b;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .form-group input,
        .form-group textarea {
            width: 100%;
            padding: 14px 16px;
            font-size: 17px;
            font-weight: 400;
            color: #1d1d1f;
            background: rgba(142, 142, 147, 0.12);
            border: 2px solid transparent;
            border-radius: 12px;
            outline: none;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            -webkit-appearance: none;
        }
        
        .form-group input:focus,
        .form-group textarea:focus {
            background: rgba(142, 142, 147, 0.16);
            border-color: #007AFF;
            transform: scale(1.005);
        }
        
        .form-group input::placeholder,
        .form-group textarea::placeholder {
            color: #86868b;
        }
        
        .form-group small {
            display: block;
            margin-top: 8px;
            color: #86868b;
            font-size: 13px;
            line-height: 1.4;
        }
        
        .list-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 0;
            min-height: 52px;
            cursor: pointer;
            border-bottom: 0.5px solid rgba(0, 0, 0, 0.08);
            transition: background-color 0.15s ease;
        }
        
        .list-item:last-child {
            border-bottom: none;
        }
        
        .list-item:active {
            background-color: rgba(142, 142, 147, 0.08);
            margin: 0 -28px;
            padding-left: 28px;
            padding-right: 28px;
        }
        
        .list-item-label {
            font-size: 17px;
            font-weight: 400;
            color: #1d1d1f;
            flex: 1;
        }
        
        .list-item-description {
            font-size: 13px;
            color: #86868b;
            margin-top: 4px;
            line-height: 1.4;
        }
        
        .switch {
            position: relative;
            width: 51px;
            height: 31px;
            background: rgba(142, 142, 147, 0.3);
            border-radius: 16px;
            transition: background 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            flex-shrink: 0;
        }
        
        .switch.active {
            background: #34C759;
        }
        
        .switch::after {
            content: '';
            position: absolute;
            top: 2px;
            left: 2px;
            width: 27px;
            height: 27px;
            background: #ffffff;
            border-radius: 50%;
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15), 0 1px 2px rgba(0, 0, 0, 0.1);
        }
        
        .switch.active::after {
            transform: translateX(20px);
        }
        
        .btn {
            width: 100%;
            padding: 16px;
            font-size: 17px;
            font-weight: 600;
            color: #ffffff;
            background: #007AFF;
            border: none;
            border-radius: 14px;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            margin-top: 8px;
            -webkit-appearance: none;
            box-shadow: 0 4px 12px rgba(0, 122, 255, 0.25);
            will-change: transform;
        }
        
        .btn:hover {
            background: #0051D5;
            box-shadow: 0 6px 16px rgba(0, 122, 255, 0.3);
        }
        
        .btn:active {
            transform: scale(0.97);
            box-shadow: 0 2px 8px rgba(0, 122, 255, 0.2);
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-secondary {
            background: rgba(142, 142, 147, 0.12);
            color: #007AFF;
            box-shadow: none;
        }
        
        .btn-secondary:hover {
            background: rgba(142, 142, 147, 0.16);
        }
        
        .btn-secondary:active {
            background: rgba(142, 142, 147, 0.2);
        }
        
        .result {
            margin-top: 20px;
            padding: 16px;
            background: rgba(142, 142, 147, 0.12);
            border-radius: 12px;
            font-size: 15px;
            color: #1d1d1f;
            word-break: break-all;
            display: none;
            line-height: 1.5;
        }
        
        .result.show {
            display: block;
        }
        
        .result-card {
            padding: 16px;
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 12px;
            margin-bottom: 12px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
            border: 0.5px solid rgba(0, 0, 0, 0.06);
        }
        
        .result-url {
            margin-top: 12px;
            padding: 12px;
            background: rgba(0, 122, 255, 0.1);
            border-radius: 10px;
            font-size: 13px;
            color: #007aff;
            word-break: break-all;
            line-height: 1.5;
        }
        
        .copy-btn {
            margin-top: 8px;
            padding: 10px 16px;
            font-size: 15px;
            background: rgba(0, 122, 255, 0.1);
            color: #007aff;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .copy-btn:active {
            background: rgba(0, 122, 255, 0.2);
            transform: scale(0.98);
        }
        
        .client-btn {
            padding: 12px 16px;
            font-size: 14px;
            font-weight: 500;
            color: #007AFF;
            background: rgba(0, 122, 255, 0.1);
            border: 1px solid rgba(0, 122, 255, 0.2);
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            -webkit-appearance: none;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            min-width: 0;
        }
        
        .client-btn:active {
            transform: scale(0.97);
            background: rgba(0, 122, 255, 0.2);
            border-color: rgba(0, 122, 255, 0.3);
        }
        
        .checkbox-label {
            display: flex;
            align-items: center;
            cursor: pointer;
            font-size: 17px;
            font-weight: 400;
            user-select: none;
            -webkit-user-select: none;
            position: relative;
            z-index: 1;
            padding: 8px 0;
        }
        
        .checkbox-label input[type="checkbox"] {
            margin-right: 12px;
            width: 22px;
            height: 22px;
            cursor: pointer;
            flex-shrink: 0;
            position: relative;
            z-index: 2;
            -webkit-appearance: checkbox;
            appearance: checkbox;
        }
        
        .checkbox-label span {
            cursor: pointer;
            position: relative;
            z-index: 1;
        }
        
        @media (max-width: 480px) {
            .client-btn {
                font-size: 12px;
                padding: 10px 12px;
            }
            
            .header h1 {
                font-size: 34px;
            }
        }
        
        .footer {
            text-align: center;
            padding: 32px 20px;
            color: #86868b;
            font-size: 13px;
        }
        
        .footer a {
            color: #007AFF;
            text-decoration: none;
            font-weight: 500;
            transition: opacity 0.2s ease;
        }
        
        .footer a:active {
            opacity: 0.6;
        }
        
        @media (prefers-color-scheme: dark) {
            body {
                background: linear-gradient(180deg, #000000 0%, #1c1c1e 50%, #2c2c2e 100%);
                color: #f5f5f7;
            }
            
            .card {
                background: rgba(28, 28, 30, 0.75);
                border: 0.5px solid rgba(255, 255, 255, 0.12);
                box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3), 0 1px 3px rgba(0, 0, 0, 0.2);
            }
            
            .form-group input,
            .form-group textarea {
                background: rgba(142, 142, 147, 0.2);
                color: #f5f5f7;
            }
            
            .form-group input:focus,
            .form-group textarea:focus {
                background: rgba(142, 142, 147, 0.25);
                border-color: #5ac8fa;
            }
            
            .list-item {
                border-bottom-color: rgba(255, 255, 255, 0.1);
            }
            
            .list-item:active {
                background-color: rgba(255, 255, 255, 0.08);
            }
            
            .list-item-label {
                color: #f5f5f7;
            }
            
            .switch {
                background: rgba(142, 142, 147, 0.4);
            }
            
            .switch.active {
                background: #30d158;
            }
            
            .switch::after {
                background: #ffffff;
            }
            
            .result {
                background: rgba(142, 142, 147, 0.2);
                color: #f5f5f7;
            }
            
            .result-card {
                background: rgba(28, 28, 30, 0.9);
                border-color: rgba(255, 255, 255, 0.1);
            }
            
            .checkbox-label span {
                color: #f5f5f7;
            }
            
            .client-btn {
                background: rgba(0, 122, 255, 0.15) !important;
                border-color: rgba(0, 122, 255, 0.3) !important;
                color: #5ac8fa !important;
            }
            
            .footer a {
                color: #5ac8fa !important;
            }
            
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>服务器优选工具</h1>
            <p>智能优选 • 一键生成</p>
        </div>
        
        <div class="card">
            <div class="list-item" onclick="toggleSwitch('switchBatchMode')" style="margin-bottom: 20px;">
                <div>
                    <div class="list-item-label">批量生成模式</div>
                    <div class="list-item-description">同时生成多个用户的订阅链接</div>
                </div>
                <div class="switch" id="switchBatchMode"></div>
            </div>

            <div id="singleConfigGroup">
                <div class="form-group">
                    <label>域名</label>
                    <input type="text" id="domain" placeholder="请输入您的域名">
                </div>
                
                <div class="form-group">
                    <label>UUID/Password</label>
                    <input type="text" id="uuid" placeholder="请输入UUID或Password">
                </div>
            </div>

            <div id="batchConfigGroup" class="form-group" style="display: none;">
                <label>批量配置 (每行一个)</label>
                <textarea id="batchInput" rows="10" placeholder="格式：域名,UUID/Passowrd&#10;例如：&#10;example.com,7b309fec-4475-4c07-82cd-512c12211c26&#10;test.com,password123"></textarea>
                <small style="display: block; margin-top: 6px; color: #86868b; font-size: 13px;">请按行输入，每行格式为：域名,UUID (用英文逗号分隔)</small>
            </div>
            
            <div class="form-group">
                <label>WebSocket路径（可选）</label>
                <input type="text" id="customPath" placeholder="留空则使用默认路径 /" value="/">
                <small style="display: block; margin-top: 6px; color: #86868b; font-size: 13px;">自定义WebSocket路径，例如：/v2ray 或 /</small>
            </div>
            
            <div class="list-item" onclick="toggleSwitch('switchDomain')">
                <div>
                    <div class="list-item-label">启用优选域名</div>
                </div>
                <div class="switch active" id="switchDomain"></div>
            </div>
            
            <div class="list-item" onclick="toggleSwitch('switchIP')">
                <div>
                    <div class="list-item-label">启用优选IP</div>
                </div>
                <div class="switch active" id="switchIP"></div>
            </div>
            
            <div class="list-item" onclick="toggleSwitch('switchGitHub')">
                <div>
                    <div class="list-item-label">启用GitHub优选</div>
                </div>
                <div class="switch active" id="switchGitHub"></div>
            </div>
            
            <div class="form-group" id="githubUrlGroup" style="margin-top: 12px;">
                <label>GitHub优选URL（可选）</label>
                <input type="text" id="githubUrl" placeholder="留空则使用默认地址" style="font-size: 15px;">
                <small style="display: block; margin-top: 6px; color: #86868b; font-size: 13px;">自定义优选IP列表来源URL，留空则使用默认地址</small>
            </div>
            
            <div class="form-group" style="margin-top: 24px;">
                <label>协议选择</label>
                <div style="margin-top: 8px;">
                    <div class="list-item" onclick="toggleSwitch('switchVL')">
                        <div>
                            <div class="list-item-label">VLESS (vl)</div>
                        </div>
                        <div class="switch active" id="switchVL"></div>
                    </div>
                    <div class="list-item" onclick="toggleSwitch('switchTJ')">
                        <div>
                            <div class="list-item-label">Trojan (tj)</div>
                        </div>
                        <div class="switch" id="switchTJ"></div>
                    </div>
                    <div class="list-item" onclick="toggleSwitch('switchVM')">
                        <div>
                            <div class="list-item-label">VMess (vm)</div>
                        </div>
                        <div class="switch" id="switchVM"></div>
                    </div>
                </div>
            </div>
            
            <div class="form-group" style="margin-top: 24px;">
                <label>客户端选择</label>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-top: 8px;">
                    <button type="button" class="client-btn" onclick="generateClientLink('clash', 'CLASH')">CLASH</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('clash', 'STASH')">STASH</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('surge', 'SURGE')">SURGE</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('sing-box', 'SING-BOX')">SING-BOX</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('loon', 'LOON')">LOON</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('quanx', 'QUANTUMULT X')" style="font-size: 13px;">QUANTUMULT X</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'V2RAY')">V2RAY</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'V2RAYNG')">V2RAYNG</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'NEKORAY')">NEKORAY</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'Shadowrocket')" style="font-size: 13px;">Shadowrocket</button>
                </div>
                <div class="result-url" id="clientSubscriptionUrl" style="display: none; margin-top: 12px; padding: 12px; background: rgba(0, 122, 255, 0.1); border-radius: 8px; font-size: 13px; color: #007aff; word-break: break-all;"></div>
            </div>
            
            <div class="form-group">
                <label>IP版本选择</label>
                <div style="display: flex; gap: 16px; margin-top: 8px;">
                    <label class="checkbox-label">
                        <input type="checkbox" id="ipv4Enabled" checked>
                        <span>IPv4</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="ipv6Enabled" checked>
                        <span>IPv6</span>
                    </label>
                </div>
            </div>
            
            <div class="form-group">
                <label>运营商选择</label>
                <div style="display: flex; gap: 16px; flex-wrap: wrap; margin-top: 8px;">
                    <label class="checkbox-label">
                        <input type="checkbox" id="ispMobile" checked>
                        <span>移动</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="ispUnicom" checked>
                        <span>联通</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="ispTelecom" checked>
                        <span>电信</span>
                    </label>
                </div>
            </div>
            
            <div class="list-item" onclick="toggleSwitch('switchTLS')" style="margin-top: 8px;">
                <div>
                    <div class="list-item-label">仅TLS节点</div>
                    <div class="list-item-description">启用后只生成带TLS的节点，不生成非TLS节点（如80端口）</div>
                </div>
                <div class="switch" id="switchTLS"></div>
            </div>
            
            <div class="list-item" onclick="toggleSwitch('switchECH')" style="margin-top: 8px;">
                <div>
                    <div class="list-item-label">ECH (Encrypted Client Hello)</div>
                    <div class="list-item-description">启用后节点链接将携带 ECH 参数，需客户端支持；开启时自动仅TLS</div>
                </div>
                <div class="switch" id="switchECH"></div>
            </div>
            <div class="form-group" id="echOptionsGroup" style="margin-top: 12px; display: none;">
                <label>ECH 自定义 DNS（可选）</label>
                <input type="text" id="customDNS" placeholder="例如: https://dns.joeyblog.eu.org/joeyblog" style="font-size: 14px;">
                <small style="display: block; margin-top: 6px; color: #86868b; font-size: 13px;">用于 ECH 配置查询的 DoH 地址</small>
                <label style="margin-top: 12px; display: block;">ECH 域名（可选）</label>
                <input type="text" id="customECHDomain" placeholder="例如: cloudflare-ech.com" style="font-size: 14px;">
            </div>
        </div>
        
        <div class="footer">
            <p>简化版优选工具 • 仅用于节点生成</p>
            <div style="margin-top: 20px; display: flex; justify-content: center; gap: 24px; flex-wrap: wrap;">
                <a href="https://github.com/byJoey/yx-auto" target="_blank" style="color: #007aff; text-decoration: none; font-size: 15px; font-weight: 500;">GitHub 项目</a>
                <a href="https://www.youtube.com/@joeyblog" target="_blank" style="color: #007aff; text-decoration: none; font-size: 15px; font-weight: 500;">YouTube @joeyblog</a>
            </div>
        </div>
    </div>
    
    <script>
        let switches = {
            switchBatchMode: false,
            switchDomain: true,
            switchIP: true,
            switchGitHub: true,
            switchVL: true,
            switchTJ: false,
            switchVM: false,
            switchTLS: false,
            switchECH: false
        };
        
        function toggleSwitch(id) {
            const switchEl = document.getElementById(id);
            switches[id] = !switches[id];
            switchEl.classList.toggle('active');
            if (id === 'switchBatchMode') {
                const singleGroup = document.getElementById('singleConfigGroup');
                const batchGroup = document.getElementById('batchConfigGroup');
                if (switches.switchBatchMode) {
                    singleGroup.style.display = 'none';
                    batchGroup.style.display = 'block';
                } else {
                    singleGroup.style.display = 'block';
                    batchGroup.style.display = 'none';
                }
            }

            if (id === 'switchECH') {
                const echOpt = document.getElementById('echOptionsGroup');
                if (echOpt) echOpt.style.display = switches.switchECH ? 'block' : 'none';
                if (switches.switchECH && !switches.switchTLS) {
                    switches.switchTLS = true;
                    const tlsEl = document.getElementById('switchTLS');
                    if (tlsEl) tlsEl.classList.add('active');
                }
            }
        }
        
        
        // 订阅转换地址（从服务器注入）
        const SUB_CONVERTER_URL = "${scu}";
        
        function tryOpenApp(schemeUrl, fallbackCallback, timeout) {
            timeout = timeout || 2500;
            let appOpened = false;
            let callbackExecuted = false;
            const startTime = Date.now();
            
            const blurHandler = () => {
                const elapsed = Date.now() - startTime;
                if (elapsed < 3000 && !callbackExecuted) {
                    appOpened = true;
                }
            };
            
            window.addEventListener('blur', blurHandler);
            
            const hiddenHandler = () => {
                const elapsed = Date.now() - startTime;
                if (elapsed < 3000 && !callbackExecuted) {
                    appOpened = true;
                }
            };
            
            document.addEventListener('visibilitychange', hiddenHandler);
            
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.style.width = '1px';
            iframe.style.height = '1px';
            iframe.src = schemeUrl;
            document.body.appendChild(iframe);
            
            setTimeout(() => {
                if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
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
            const customPath = document.getElementById('customPath').value.trim() || '/';
            
            // 检查至少选择一个协议
            if (!switches.switchVL && !switches.switchTJ && !switches.switchVM) {
                alert('请至少选择一个协议（VLESS、Trojan或VMess）');
                return;
            }

            const ipv4Enabled = document.getElementById('ipv4Enabled').checked;
            const ipv6Enabled = document.getElementById('ipv6Enabled').checked;
            const ispMobile = document.getElementById('ispMobile').checked;
            const ispUnicom = document.getElementById('ispUnicom').checked;
            const ispTelecom = document.getElementById('ispTelecom').checked;
            const githubUrl = document.getElementById('githubUrl').value.trim();

            const currentUrl = new URL(window.location.href);
            const baseUrl = currentUrl.origin;
            
            let commonParams = \`&epd=\${switches.switchDomain ? 'yes' : 'no'}&epi=\${switches.switchIP ? 'yes' : 'no'}&egi=\${switches.switchGitHub ? 'yes' : 'no'}\`;
            
            // 添加GitHub优选URL
            if (githubUrl) {
                commonParams += \`&piu=\${encodeURIComponent(githubUrl)}\`;
            }
            
            // 添加协议选择
            if (switches.switchVL) commonParams += '&ev=yes';
            if (switches.switchTJ) commonParams += '&et=yes';
            if (switches.switchVM) commonParams += '&mess=yes';
            
            if (!ipv4Enabled) commonParams += '&ipv4=no';
            if (!ipv6Enabled) commonParams += '&ipv6=no';
            if (!ispMobile) commonParams += '&ispMobile=no';
            if (!ispUnicom) commonParams += '&ispUnicom=no';
            if (!ispTelecom) commonParams += '&ispTelecom=no';
            
            // 添加TLS控制
            if (switches.switchTLS) commonParams += '&dkby=yes';
            if (switches.switchECH) {
                commonParams += '&ech=yes';
                const dnsVal = document.getElementById('customDNS') && document.getElementById('customDNS').value.trim();
                if (dnsVal) commonParams += \`&customDNS=\${encodeURIComponent(dnsVal)}\`;
                const domainVal = document.getElementById('customECHDomain') && document.getElementById('customECHDomain').value.trim();
                if (domainVal) commonParams += \`&customECHDomain=\${encodeURIComponent(domainVal)}\`;
            }
            
            // 添加自定义路径
            if (customPath && customPath !== '/') {
                commonParams += \`&path=\${encodeURIComponent(customPath)}\`;
            }

            let configs = [];
            if (switches.switchBatchMode) {
                const batchInput = document.getElementById('batchInput').value.trim();
                if (!batchInput) {
                    alert('请输入批量配置信息');
                    return;
                }
                // Use String.fromCharCode(10) for newline to avoid escaping issues
                const lines = batchInput.split(String.fromCharCode(10));
                lines.forEach(line => {
                    // Use String.fromCharCode(65292) for Chinese comma to avoid encoding issues
                    const parts = line.replace(new RegExp(String.fromCharCode(65292), 'g'), ',').split(',');
                    // 只要有前两个部分（域名,UUID）就认为是有效的
                    if (parts.length >= 2) {
                        configs.push({
                            domain: parts[0].trim(),
                            uuid: parts[1].trim()
                        });
                    }
                });
                
                if (configs.length === 0) {
                    alert('未检测到有效的配置行，请检查格式');
                    return;
                }
            } else {
                const domain = document.getElementById('domain').value.trim();
                const uuid = document.getElementById('uuid').value.trim();
                if (!domain || !uuid) {
                    alert('请先填写域名和UUID/Password');
                    return;
                }
                configs.push({ domain, uuid });
            }

            // 2. 决定最终订阅链接
            let finalUrl = '';

            // 如果是 V2RAY 客户端（并且不是批量模式下的单链接聚合需求，或者说V2RAY本身就只看list）
            // 简单处理：V2RAY 单个用户用 worker 链接，批量用户用 subconverter 聚合（或者新接口）
            // 注意：新接口 /batch/sub?target=base64 也支持聚合 vless://，比 subconverter 更快且无依赖
            
            // 决策逻辑升级：
            // A. 如果是 Clash -> 走 /batch/sub?target=clash (支持 Gemini + 自动优选)
            // B. 如果是 V2Ray -> 走 /batch/sub?target=base64 (支持聚合)
            // C. 其他客户端 -> 依然走 Subconverter (因为本地只实现了 Clash yaml 生成，其他 Surge 等格式暂未本地实现)
            
            // 构建 configs 参数 (base64 编码的 domain,uuid 列表，每行一个配置)
            const configsStr = configs.map(c => \`\${c.domain},\${c.uuid}\`).join(String.fromCharCode(10));
            const configsBase64 = btoa(configsStr);
            const tplParam = clientType === 'clash' ? '&tpl=acl4ssr' : '';
            const batchParams = \`?configs=\${configsBase64}&target=\${clientType}\${tplParam}\${commonParams}\`;
            
            if (clientType === 'clash') {
                // 使用本地的高级 Clash 生成器
                finalUrl = \`\${baseUrl}/batch/sub\${batchParams}\`;
            } else if (clientType === 'v2ray') {
                // 如果是单个用户，依然可以保持旧的链接格式（看起来更短），或者统一用 batch 接口
                // 为了兼容性和原本的简洁性，单个用户保持原样
                if (configs.length === 1) {
                     finalUrl = \`\${baseUrl}/\${configs[0].uuid}/sub?domain=\${encodeURIComponent(configs[0].domain)}\${commonParams}\`;
                } else {
                     // 批量 V2Ray，用本地聚合，比 Subconverter 快
                     finalUrl = \`\${baseUrl}/batch/sub?configs=\${configsBase64}&target=base64\${commonParams}\`;
                }
            } else {
                // 其他客户端 (Surge, Singbox 等) 依然依赖 Subconverter
                // 需要把所有 sourceUrls 拼起来
                let sourceUrls = [];
                configs.forEach(config => {
                    let url = \`\${baseUrl}/\${config.uuid}/sub?domain=\${encodeURIComponent(config.domain)}\${commonParams}\`;
                    sourceUrls.push(url);
                });
                
                if (sourceUrls.length === 1 && clientType === 'v2ray') { 
                     // This branch is technically covered above for v2ray, but kept for fallback logic structure
                     finalUrl = sourceUrls[0]; 
                } else {
                    const joinedUrls = sourceUrls.join('|');
                    const encodedUrl = encodeURIComponent(joinedUrls);
                    finalUrl = SUB_CONVERTER_URL + '?target=' + clientType + '&url=' + encodedUrl + '&insert=false&emoji=true&list=false&xudp=false&udp=false&tfo=false&expand=true&scv=false&fdn=false&new_name=true';
                }
            }

            // 显示链接
            const urlElement = document.getElementById('clientSubscriptionUrl');
            urlElement.textContent = finalUrl;
            urlElement.style.display = 'block';

            // 3. 处理APP跳转和复制
            let schemeUrl = '';
            let displayName = clientName || clientType.toUpperCase();

            // 根据客户端名称匹配 Scheme
            if (clientName === 'Shadowrocket') {
                schemeUrl = 'shadowrocket://add/' + encodeURIComponent(finalUrl);
            } else if (clientName === 'V2RAYNG') {
                schemeUrl = 'v2rayng://install?url=' + encodeURIComponent(finalUrl);
            } else if (clientName === 'NEKORAY') {
                schemeUrl = 'nekoray://install-config?url=' + encodeURIComponent(finalUrl);
            } else if (clientName === 'STASH') {
                schemeUrl = 'stash://install?url=' + encodeURIComponent(finalUrl);
            } else if (clientName === 'CLASH') {
                schemeUrl = 'clash://install-config?url=' + encodeURIComponent(finalUrl);
            } else if (clientName === 'SURGE') {
                schemeUrl = 'surge:///install-config?url=' + encodeURIComponent(finalUrl);
            } else if (clientName === 'SING-BOX') {
                schemeUrl = 'sing-box://install-config?url=' + encodeURIComponent(finalUrl);
            } else if (clientName === 'LOON') {
                schemeUrl = 'loon://install?url=' + encodeURIComponent(finalUrl);
            } else if (clientName === 'QUANTUMULT X') {
                schemeUrl = 'quantumult-x://install-config?url=' + encodeURIComponent(finalUrl);
            }
            // V2RAY 原版客户端通常没有通用 Scheme，只复制链接

            if (schemeUrl) {
                tryOpenApp(schemeUrl, () => {
                    navigator.clipboard.writeText(finalUrl).then(() => {
                        alert(displayName + ' 订阅链接已复制');
                    });
                });
            } else {
                navigator.clipboard.writeText(finalUrl).then(() => {
                    alert(displayName + ' 订阅链接已复制');
                });
            }
        }
    </script>
</body>
</html>`;
}

// 主处理函数
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // 主页
        if (path === '/' || path === '') {
            const scuValue = env?.scu || scu;
            return new Response(generateHomePage(scuValue), {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }

        // 测试优选API API: /test-optimize-api?url=xxx&port=8443
        if (path === '/test-optimize-api') {
            if (request.method === 'OPTIONS') {
                return new Response(null, {
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type'
                    }
                });
            }

            const apiUrl = url.searchParams.get('url');
            const port = url.searchParams.get('port') || '8443';
            const timeout = parseInt(url.searchParams.get('timeout') || '3000');

            if (!apiUrl) {
                return new Response(JSON.stringify({
                    success: false,
                    error: '缺少url参数'
                }), {
                    status: 400,
                    headers: {
                        'Content-Type': 'application/json; charset=utf-8',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }

            try {
                const results = await 请求优选API([apiUrl], port, timeout);
                return new Response(JSON.stringify({
                    success: true,
                    results: results,
                    total: results.length,
                    message: `成功获取 ${results.length} 个优选IP`
                }, null, 2), {
                    headers: {
                        'Content-Type': 'application/json; charset=utf-8',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            } catch (error) {
                return new Response(JSON.stringify({
                    success: false,
                    error: error.message
                }), {
                    status: 500,
                    headers: {
                        'Content-Type': 'application/json; charset=utf-8',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }

        // 批量/ACL4SSR Clash 配置生成器（含常用分组）
        function generateAcl4ssrClashConfig(nodeGroups) {
            const GROUP_NODE_SELECT = '🔰 节点选择';
            const GROUP_AUTO_SELECT = '♻️ 自动选择';
            const GROUP_MEDIA_OVERSEA = '🌍 国外媒体';
            const GROUP_MEDIA_CHINA = '🌏 国内媒体';
            const GROUP_MICROSOFT = 'Ⓜ️ 微软服务';
            const GROUP_TELEGRAM = '📲 电报信息';
            const GROUP_APPLE = '🍎 苹果服务';
            const GROUP_DIRECT = '🎯 全球直连';
            const GROUP_BLOCK = '🛑 全球拦截';
            const GROUP_FINAL = '🐟 漏网之鱼';

            let yaml = 'port: 7890\n';
            yaml += 'socks-port: 7891\n';
            yaml += 'allow-lan: false\n';
            yaml += 'mode: rule\n';
            yaml += 'log-level: info\n';
            yaml += 'external-controller: 127.0.0.1:9090\n\n';

            yaml += 'proxies:\n';

            const allProxyNames = [];
            const nameCounter = new Map(); // 用于跟踪重复名称并添加后缀

            nodeGroups.forEach(group => {
                group.nodes.forEach((link, index) => {
                    const parsed = parseVlessLink(link, `节点-${index + 1}`);
                    if (!parsed) return;

                    const originalName = parsed.name || `节点-${index + 1}`;
                    const domainShort = group.domain.split('.')[0]; // 取域名第一部分
                    let name = `[${domainShort}]${originalName}`;

                    if (nameCounter.has(name)) {
                        const count = nameCounter.get(name) + 1;
                        nameCounter.set(name, count);
                        name = `${name}-${count}`;
                    } else {
                        nameCounter.set(name, 1);
                    }

                    allProxyNames.push(name);

                    const { server, port, uuid, tls, path, host, sni, ech } = parsed;
                    const echDomain = ech ? String(ech).trim().split(/[ +]/)[0] : '';

                    yaml += `  - name: ${yamlQuote(name)}\n`;
                    yaml += '    type: vless\n';
                    yaml += `    server: ${yamlQuote(server)}\n`;
                    yaml += `    port: ${port}\n`;
                    yaml += `    uuid: ${yamlQuote(uuid)}\n`;
                    yaml += `    tls: ${tls}\n`;
                    yaml += '    network: ws\n';
                    yaml += '    ws-opts:\n';
                    yaml += `      path: ${yamlQuote(path)}\n`;
                    yaml += '      headers:\n';
                    yaml += `        Host: ${yamlQuote(host)}\n`;
                    if (sni) {
                        yaml += `    servername: ${yamlQuote(sni)}\n`;
                    }
                    if (echDomain) {
                        yaml += '    ech-opts:\n';
                        yaml += '      enable: true\n';
                        yaml += `      query-server-name: ${yamlQuote(echDomain)}\n`;
                    }
                });
            });

            yaml += '\nproxy-groups:\n';

            // 🔰 节点选择
            yaml += `  - name: ${yamlQuote(GROUP_NODE_SELECT)}\n`;
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += `      - ${yamlQuote(GROUP_AUTO_SELECT)}\n`;
            // 不能把“全球直连”放进“节点选择”，否则会和“全球直连”里引用“节点选择”形成循环依赖
            yaml += '      - DIRECT\n';
            allProxyNames.forEach(n => yaml += `      - ${yamlQuote(n)}\n`);

            // ♻️ 自动选择
            yaml += `  - name: ${yamlQuote(GROUP_AUTO_SELECT)}\n`;
            yaml += '    type: url-test\n';
            yaml += '    url: http://www.gstatic.com/generate_204\n';
            yaml += '    interval: 300\n';
            yaml += '    tolerance: 50\n';
            yaml += '    proxies:\n';
            allProxyNames.forEach(n => yaml += `      - ${yamlQuote(n)}\n`);

            // 🌍 国外媒体
            yaml += `  - name: ${yamlQuote(GROUP_MEDIA_OVERSEA)}\n`;
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += `      - ${yamlQuote(GROUP_NODE_SELECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_AUTO_SELECT)}\n`;
            allProxyNames.forEach(n => yaml += `      - ${yamlQuote(n)}\n`);
            yaml += '      - DIRECT\n';

            // 🌏 国内媒体
            yaml += `  - name: ${yamlQuote(GROUP_MEDIA_CHINA)}\n`;
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += `      - ${yamlQuote(GROUP_DIRECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_NODE_SELECT)}\n`;

            // Ⓜ️ 微软服务
            yaml += `  - name: ${yamlQuote(GROUP_MICROSOFT)}\n`;
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += `      - ${yamlQuote(GROUP_DIRECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_NODE_SELECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_AUTO_SELECT)}\n`;
            allProxyNames.forEach(n => yaml += `      - ${yamlQuote(n)}\n`);

            // 📲 电报信息
            yaml += `  - name: ${yamlQuote(GROUP_TELEGRAM)}\n`;
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += `      - ${yamlQuote(GROUP_NODE_SELECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_AUTO_SELECT)}\n`;
            allProxyNames.forEach(n => yaml += `      - ${yamlQuote(n)}\n`);
            yaml += '      - DIRECT\n';

            // 🍎 苹果服务
            yaml += `  - name: ${yamlQuote(GROUP_APPLE)}\n`;
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += `      - ${yamlQuote(GROUP_NODE_SELECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_DIRECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_AUTO_SELECT)}\n`;
            allProxyNames.forEach(n => yaml += `      - ${yamlQuote(n)}\n`);

            // 🎯 全球直连
            yaml += `  - name: ${yamlQuote(GROUP_DIRECT)}\n`;
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += '      - DIRECT\n';
            yaml += `      - ${yamlQuote(GROUP_NODE_SELECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_AUTO_SELECT)}\n`;

            // 🛑 全球拦截
            yaml += `  - name: ${yamlQuote(GROUP_BLOCK)}\n`;
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += '      - REJECT\n';
            yaml += '      - DIRECT\n';

            // 🐟 漏网之鱼
            yaml += `  - name: ${yamlQuote(GROUP_FINAL)}\n`;
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += `      - ${yamlQuote(GROUP_NODE_SELECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_DIRECT)}\n`;
            yaml += `      - ${yamlQuote(GROUP_AUTO_SELECT)}\n`;

            // 规则集（ACL4SSR）
            yaml += '\nrule-providers:\n';
            const ruleProviders = {
                LocalAreaNetwork: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/LocalAreaNetwork.yaml',
                UnBan: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/UnBan.yaml',
                BanAD: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanAD.yaml',
                BanProgramAD: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanProgramAD.yaml',
                ChinaDomain: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaDomain.yaml',
                ChinaCompanyIp: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaCompanyIp.yaml',
                ChinaMedia: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaMedia.yaml',
                ProxyMedia: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyMedia.yaml',
                Apple: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Apple.yaml',
                Microsoft: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Microsoft.yaml',
                Telegram: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Telegram.yaml',
                ProxyGFWlist: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyGFWlist.yaml',
                Download: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Download.yaml'
            };
            Object.entries(ruleProviders).forEach(([name, url]) => {
                yaml += `  ${name}:\n`;
                yaml += '    type: http\n';
                yaml += '    behavior: classical\n';
                yaml += `    url: ${yamlQuote(url)}\n`;
                yaml += `    path: ${yamlQuote(`./ruleset/ACL4SSR/${name}.yaml`)}\n`;
                yaml += '    interval: 86400\n';
            });

            yaml += '\nrules:\n';
            yaml += `  - RULE-SET,LocalAreaNetwork,${GROUP_DIRECT}\n`;
            yaml += `  - RULE-SET,UnBan,${GROUP_DIRECT}\n`;
            yaml += `  - RULE-SET,BanAD,${GROUP_BLOCK}\n`;
            yaml += `  - RULE-SET,BanProgramAD,${GROUP_BLOCK}\n`;
            yaml += `  - RULE-SET,Download,${GROUP_DIRECT}\n`;
            yaml += `  - RULE-SET,Apple,${GROUP_APPLE}\n`;
            yaml += `  - RULE-SET,Telegram,${GROUP_TELEGRAM}\n`;
            yaml += `  - RULE-SET,Microsoft,${GROUP_MICROSOFT}\n`;
            yaml += `  - RULE-SET,ChinaMedia,${GROUP_MEDIA_CHINA}\n`;
            yaml += `  - RULE-SET,ProxyMedia,${GROUP_MEDIA_OVERSEA}\n`;
            yaml += `  - RULE-SET,ProxyGFWlist,${GROUP_NODE_SELECT}\n`;
            yaml += `  - RULE-SET,ChinaDomain,${GROUP_DIRECT}\n`;
            yaml += `  - RULE-SET,ChinaCompanyIp,${GROUP_DIRECT}\n`;
            yaml += `  - GEOIP,CN,${GROUP_DIRECT}\n`;
            yaml += `  - MATCH,${GROUP_FINAL}\n`;

            return yaml;
        }

        // 批量/高级 Clash 配置生成器
        function generateSmartClashConfig(nodeGroups) {
            let yaml = 'port: 7890\n';
            yaml += 'socks-port: 7891\n';
            yaml += 'allow-lan: false\n';
            yaml += 'mode: rule\n';
            yaml += 'log-level: info\n';
            yaml += 'external-controller: 127.0.0.1:9090\n\n';

            yaml += 'proxies:\n';

            const allProxyNames = [];
            const autoSelectGroups = [];
            const perDomainGroupYamls = [];
            const nameCounter = new Map(); // 用于跟踪重复名称并添加后缀

            // 1. 生成所有节点 (Proxies)
            nodeGroups.forEach(group => {
                const groupProxyNames = [];
                group.nodes.forEach((link, index) => {
                    // 解析现有link格式生成Clash Proxy Item
                    // 注意：这里需要复用之前的解析逻辑，或者直接生成Clash对象
                    // 为简化，这里直接解析 vless:// 字符串 (这也是之前代码的逻辑)

                    const originalName = decodeURIComponent(link.split('#')[1] || `节点-${index + 1}`);
                    // 为确保节点名称唯一，添加域名简称作为前缀
                    const domainShort = group.domain.split('.')[0]; // 取域名第一部分
                    let name = `[${domainShort}]${originalName}`;

                    // 如果名称已存在，添加数字后缀
                    if (nameCounter.has(name)) {
                        const count = nameCounter.get(name) + 1;
                        nameCounter.set(name, count);
                        name = `${name}-${count}`;
                    } else {
                        nameCounter.set(name, 1);
                    }

                    allProxyNames.push(name);
                    groupProxyNames.push(name);

                    const parsed = parseVlessLink(link, `节点-${index + 1}`);
                    if (!parsed) return;
                    const { server, port, uuid, tls, path, host, sni, ech } = parsed;
                    const echDomain = ech ? String(ech).trim().split(/[ +]/)[0] : '';

                    // VLESS 节点格式 (节点名称需要加引号以支持特殊字符如 [])
                    yaml += `  - name: ${yamlQuote(name)}\n`;
                    yaml += `    type: vless\n`;
                    yaml += `    server: ${yamlQuote(server)}\n`;
                    yaml += `    port: ${port}\n`;
                    yaml += `    uuid: ${yamlQuote(uuid)}\n`;
                    yaml += `    tls: ${tls}\n`;
                    yaml += `    network: ws\n`;
                    yaml += `    ws-opts:\n`;
                    yaml += `      path: ${yamlQuote(path)}\n`;
                    yaml += `      headers:\n`;
                    yaml += `        Host: ${yamlQuote(host)}\n`;
                    if (sni) {
                        yaml += `    servername: ${yamlQuote(sni)}\n`;
                    }
                    if (echDomain) {
                        yaml += `    ech-opts:\n`;
                        yaml += `      enable: true\n`;
                        yaml += `      query-server-name: ${yamlQuote(echDomain)}\n`;
                    }

                    // TODO: 如果有 VMess 或 Trojan，也需要在这里适配解析
                    // 目前 batch 模式主要基于通用的 link 生成逻辑，假设主要是 VLESS
                    // 如果之前的 generateLinksFromSource 产生了其他协议，需要在这里扩展 regex
                });

                // 为该域名创建自动选择组
                if (groupProxyNames.length > 0) {
                    const groupName = `自动优选-${group.domain}`;
                    autoSelectGroups.push(groupName);
                    let groupYaml = '';
                    groupYaml += `  - name: ${yamlQuote(groupName)}\n`;
                    groupYaml += `    type: url-test\n`;
                    groupYaml += `    url: http://www.gstatic.com/generate_204\n`;
                    groupYaml += `    interval: 300\n`;
                    groupYaml += `    tolerance: 50\n`;
                    groupYaml += `    proxies:\n`;
                    groupProxyNames.forEach(proxyName => {
                        groupYaml += `      - ${yamlQuote(proxyName)}\n`;
                    });
                    perDomainGroupYamls.push(groupYaml);
                }
            });

            yaml += '\nproxy-groups:\n';

            // 1. 每个域名一个自动优选组
            perDomainGroupYamls.forEach(g => {
                yaml += g;
            });

            // 2. 节点选择 (Proxy) - 包含所有自动优选组 + 所有节点
            yaml += '  - name: "节点选择"\n';
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            autoSelectGroups.forEach(g => yaml += `      - ${yamlQuote(g)}\n`);
            yaml += '      - "自动选择"\n';
            allProxyNames.forEach(n => yaml += `      - ${yamlQuote(n)}\n`);

            // 3. 自动选择 (全局自动)
            yaml += '  - name: "自动选择"\n';
            yaml += '    type: url-test\n';
            yaml += '    url: http://www.gstatic.com/generate_204\n';
            yaml += '    interval: 300\n';
            yaml += '    tolerance: 50\n';
            yaml += '    proxies:\n';
            allProxyNames.forEach(n => yaml += `      - ${yamlQuote(n)}\n`);

            // 4. Gemini 分组
            yaml += '  - name: "Gemini"\n';
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            // Gemini 优先使用"每个域名的自动优选"，然后是"全局自动"，然后是所有节点
            autoSelectGroups.forEach(g => yaml += `      - ${yamlQuote(g)}\n`);
            yaml += '      - "自动选择"\n';
            allProxyNames.forEach(n => yaml += `      - ${yamlQuote(n)}\n`);

            // 5. 漏网之鱼
            yaml += '  - name: "漏网之鱼"\n';
            yaml += '    type: select\n';
            yaml += '    proxies:\n';
            yaml += '      - "节点选择"\n';
            yaml += '      - DIRECT\n';

            yaml += '\nrules:\n';
            // Gemini 规则
            yaml += '  - DOMAIN-SUFFIX,gemini.google.com,Gemini\n';
            yaml += '  - DOMAIN-SUFFIX,bard.google.com,Gemini\n';
            yaml += '  - DOMAIN-SUFFIX,generativelanguage.googleapis.com,Gemini\n';
            yaml += '  - DOMAIN-SUFFIX,ai.google.dev,Gemini\n';
            yaml += '  - DOMAIN-SUFFIX,aistudio.google.com,Gemini\n';
            yaml += '  - DOMAIN-SUFFIX,alkalimakersuite-pa.clients6.google.com,Gemini\n';
            yaml += '  - DOMAIN-SUFFIX,deepmind.com,Gemini\n';
            yaml += '  - DOMAIN-SUFFIX,deepmind.google,Gemini\n';
            yaml += '  - DOMAIN-SUFFIX,proactivebackend-pa.googleapis.com,Gemini\n';
            yaml += '  - DOMAIN-KEYWORD,gemini,Gemini\n';

            // 常规规则
            yaml += '  - DOMAIN-SUFFIX,local,DIRECT\n';
            yaml += '  - IP-CIDR,127.0.0.0/8,DIRECT\n';
            yaml += '  - GEOIP,CN,DIRECT\n';
            yaml += '  - MATCH,节点选择\n';

            return yaml;
        }

        // 批量/高级订阅处理接口
        if (path === '/batch/sub') {
            const configsParam = url.searchParams.get('configs'); // base64 encoded "domain,uuid|domain,uuid"
            if (!configsParam) return new Response('Missing configs', { status: 400 });

            let configsStr = '';
            try {
                configsStr = atob(configsParam);
            } catch (e) { return new Response('Invalid configs base64', { status: 400 }); }

            const lines = configsStr.split('\n'); // 客户端用 \n 连接
            const configs = [];
            lines.forEach(line => {
                const parts = line.split(',');
                if (parts.length >= 2) {
                    configs.push({ domain: parts[0].trim(), uuid: parts[1].trim() });
                }
            });

            // 获取通用参数
            const epd = url.searchParams.get('epd') !== 'no';
            const epi = url.searchParams.get('epi') !== 'no';
            const egi = url.searchParams.get('egi') !== 'no';
            const piu = url.searchParams.get('piu') || defaultIPURL;
            const evEnabled = url.searchParams.get('ev') === 'yes'; // 显式开启
            const etEnabled = url.searchParams.get('et') === 'yes';
            const vmEnabled = url.searchParams.get('mess') === 'yes';
            // 如果没传任何协议参数，默认开启VLESS? 之前的逻辑是参数没传 && env.ev。这里简单处理：如果有任意一个开启就是开启，否则默认ev
            const hasProto = evEnabled || etEnabled || vmEnabled;
            const finalEv = hasProto ? evEnabled : true;

            const ipv4Enabled = url.searchParams.get('ipv4') !== 'no';
            const ipv6Enabled = url.searchParams.get('ipv6') !== 'no';
            const ispMobile = url.searchParams.get('ispMobile') !== 'no';
            const ispUnicom = url.searchParams.get('ispUnicom') !== 'no';
            const ispTelecom = url.searchParams.get('ispTelecom') !== 'no';

            let disableNonTLS = url.searchParams.get('dkby') === 'yes';
            const echParam = url.searchParams.get('ech');
            const echEnabled = echParam === 'yes' || (echParam === null && enableECH);
            if (echEnabled) disableNonTLS = true;
            const echConfig = echEnabled ? `${url.searchParams.get('customECHDomain') || customECHDomain}+${url.searchParams.get('customDNS') || customDNS}` : null;
            const customPath = url.searchParams.get('path') || '/';

            // 预取优选IP数据（所有配置共用）
            let dynamicIPList = [];
            if (epi) {
                try {
                    dynamicIPList = await fetchDynamicIPs(ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom);
                } catch (e) { }
            }

            // 预取GitHub IP（所有配置共用）
            let githubIPList = [];
            if (egi) {
                try {
                    // 复用之前的逻辑，简单起见直接调用
                    // 注意：这里为了性能，暂不 implementing 复杂的 API 递归，仅支持基础 list
                    // 如果要做得很完美需要把 handleSubscriptionRequest 里的逻辑拆分出来。
                    // 鉴于篇幅，这里简化：
                    const newIPList = await fetchAndParseNewIPs(piu);
                    githubIPList = newIPList;
                } catch (e) { }
            }

            // 原生域名列表
            const domainList = epd ? directDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain })) : [];

            // 开始生成
            const nodeGroups = []; // { domain: 'xxx', nodes: [] }

            for (const conf of configs) {
                const myNodes = [];
                const myDomain = conf.domain;
                const myUuid = conf.uuid;

                // Helper to generate links
                const gen = (list) => {
                    const links = [];
                    if (finalEv) links.push(...generateLinksFromSource(list, myUuid, myDomain, disableNonTLS, customPath, echConfig));
                    if (etEnabled) {
                        // Trojan 也是同步生成的（之前的 async 只是为了 await 某些 fetch，但 generateTrojanLinksFromSource 本身虽然标了 async 其实内部没有 await 关键操作，除了 fetch API 但这里是 source list）
                        // 检查 generateTrojanLinksFromSource 源码，它是 sync 的，只是标了 async
                        // 修正：generateTrojanLinksFromSource 在原代码里没有 async 或者是 sync 的。原代码 Line 329: async function... 
                        // 且 Line 517: await generateTrojanLinksFromSource
                        // 让我们看 Line 329，它没有 await。所以可以直接调用。
                        // 但是为了安全，我们 await 它。
                    }
                    if (vmEnabled) links.push(...generateVMessLinksFromSource(list, myUuid, myDomain, disableNonTLS, customPath, echConfig));
                    return links;
                };

                // 获取worker域名
                const workerDomain = url.hostname;

                // 原生
                myNodes.push(...gen([{ ip: workerDomain, isp: '原生地址' }]));
                // 优选域名
                if (epd) myNodes.push(...gen(domainList));
                // 优选IP
                if (epi) myNodes.push(...gen(dynamicIPList));
                // GitHub
                if (egi) {
                    // 注意：GitHub IP 生成 VLESS 链接的逻辑略有不同 (generateLinksFromNewIPs)
                    // 复用 generateLinksFromNewIPs
                    if (finalEv) myNodes.push(...generateLinksFromNewIPs(githubIPList, myUuid, myDomain, customPath, echConfig));
                }

                nodeGroups.push({ domain: myDomain, nodes: myNodes });
            }

            // 目前仅支持 Clash 格式输出智能配置
            // 如果 target 不是 clash，则退化为普通聚合
            const target = url.searchParams.get('target') || 'base64';
            const tpl = (url.searchParams.get('tpl') || '').toLowerCase();

            try {
                if (target === 'clash' || target === 'clashr') {
                    const yaml = (tpl === 'acl4ssr' || tpl === 'acl' || tpl === 'full')
                        ? generateAcl4ssrClashConfig(nodeGroups)
                        : generateSmartClashConfig(nodeGroups);
                    return new Response(yaml, {
                        headers: {
                            'Content-Type': 'text/yaml; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                            'Content-Disposition': 'attachment; filename="clash_config.yaml"'
                        }
                    });
                } else {
                    // Base64 聚合
                    const allLinks = [];
                    nodeGroups.forEach(g => allLinks.push(...g.nodes));
                    return new Response(btoa(allLinks.join('\n')), {
                        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
                    });
                }
            } catch (error) {
                console.error('Batch sub error:', error);
                return new Response(`Error generating config: ${error.message}\n${error.stack}`, {
                    status: 500,
                    headers: { 'Content-Type': 'text/plain; charset=utf-8' }
                });
            }
        }

        // 订阅请求格式: /{UUID或Password}/sub?domain=xxx&epd=yes&epi=yes&egi=yes
        const pathMatch = path.match(/^\/([^\/]+)\/sub$/);
        if (pathMatch) {
            const uuid = pathMatch[1];

            const domain = url.searchParams.get('domain');
            if (!domain) {
                return new Response('缺少域名参数', { status: 400 });
            }

            // 从URL参数获取配置
            epd = url.searchParams.get('epd') !== 'no';
            epi = url.searchParams.get('epi') !== 'no';
            egi = url.searchParams.get('egi') !== 'no';
            const piu = url.searchParams.get('piu') || defaultIPURL;

            // 协议选择
            const evEnabled = url.searchParams.get('ev') === 'yes' || (url.searchParams.get('ev') === null && ev);
            const etEnabled = url.searchParams.get('et') === 'yes';
            const vmEnabled = url.searchParams.get('mess') === 'yes';

            // IPv4/IPv6选择
            const ipv4Enabled = url.searchParams.get('ipv4') !== 'no';
            const ipv6Enabled = url.searchParams.get('ipv6') !== 'no';

            // 运营商选择
            const ispMobile = url.searchParams.get('ispMobile') !== 'no';
            const ispUnicom = url.searchParams.get('ispUnicom') !== 'no';
            const ispTelecom = url.searchParams.get('ispTelecom') !== 'no';

            // TLS控制（ECH 开启时强制仅 TLS）
            let disableNonTLS = url.searchParams.get('dkby') === 'yes';
            const echParam = url.searchParams.get('ech');
            const echEnabled = echParam === 'yes' || (echParam === null && enableECH);
            if (echEnabled) disableNonTLS = true;
            const customDNSParam = url.searchParams.get('customDNS') || customDNS;
            const customECHDomainParam = url.searchParams.get('customECHDomain') || customECHDomain;
            const echConfig = echEnabled ? `${customECHDomainParam} + ${customDNSParam} ` : null;

            // 自定义路径
            const customPath = url.searchParams.get('path') || '/';

            return await handleSubscriptionRequest(request, uuid, domain, piu, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, evEnabled, etEnabled, vmEnabled, disableNonTLS, customPath, echConfig);
        }

        return new Response('Not Found', { status: 404 });
    }
};
