import { exec } from 'child_process'
import dns from 'dns/promises'
import dotenv from 'dotenv'
import express from 'express'
import fs from 'fs'
import multer from 'multer'
import os from 'os'
import path from 'path'
import initSqlJs from 'sql.js'
import { fileURLToPath } from 'url'



const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
dotenv.config({ path: path.join(__dirname, '..', '.env'), override: true })
const app = express()
const upload = multer()

const port = Number(process.env.PORT || 3000)
const dbFilePath = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'domains.sqlite')
const logFilePath = process.env.OP_LOG_PATH || path.join(__dirname, '..', 'logs', 'backend.log')

let SQL = null
let db = null
let autoCheckTimer = null
let certQueueTimer = null
let certQueueProcessing = false
const certQueue = []
const certQueueSet = new Set()
const certStatusSubscribers = new Set()
let dbLastMtimeMs = 0

const ensureDir = () => {
    const dir = path.dirname(dbFilePath)
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true })
    }
}

const persistDb = () => {
    if (!db) return
    ensureDir()
    const data = db.export()
    const buffer = Buffer.from(data)
    fs.writeFileSync(dbFilePath, buffer)
    try {
        const stat = fs.statSync(dbFilePath)
        dbLastMtimeMs = stat.mtimeMs
    } catch {
    }
}

const appendLog = (type, message) => {
    try {
        const dir = path.dirname(logFilePath)
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true })
        }
        const now = new Date()
        const pad = (value) => String(value).padStart(2, '0')
        const timestamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`
        fs.appendFileSync(logFilePath, `[${timestamp}] [${type}] ${message}\n`)
    } catch {
    }
}

const readRows = (sql, params = []) => {
    if (SQL && db && fs.existsSync(dbFilePath)) {
        try {
            const stat = fs.statSync(dbFilePath)
            if (stat.mtimeMs > dbLastMtimeMs) {
                const fileBuffer = fs.readFileSync(dbFilePath)
                db = new SQL.Database(fileBuffer)
                dbLastMtimeMs = stat.mtimeMs
            }
        } catch {
        }
    }
    const stmt = db.prepare(sql)
    stmt.bind(params)
    const rows = []
    while (stmt.step()) {
        rows.push(stmt.getAsObject())
    }
    stmt.free()
    return rows
}

const readRow = (sql, params = []) => readRows(sql, params)[0] || null

const run = (sql, params = []) => {
    db.run(sql, params)
}

const hasColumn = (table, column) => {
    const columns = readRows(`PRAGMA table_info(${table})`)
    return columns.some((col) => col.name === column)
}

const addColumnIfMissing = (table, column, ddl) => {
    if (!hasColumn(table, column)) {
        run(ddl)
        return true
    }
    return false
}

const ensureSchema = () => {
    run(`CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        registrar TEXT NOT NULL,
        registrar_link TEXT,
        registrar_date TEXT NOT NULL,
        expiry_date TEXT NOT NULL,
        service_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT '离线',
        cert_status TEXT NOT NULL DEFAULT '无',
        cert_retry_count INTEGER DEFAULT 0,
        cert_retry_at TEXT,
        tgsend INTEGER DEFAULT 1,
        st_tgsend INTEGER DEFAULT 1,
        site_id INTEGER,
        cf_hosted INTEGER DEFAULT 0,
        cf_account_id INTEGER,
        memo TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
    run(`CREATE TABLE IF NOT EXISTS websitecfg (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        filename TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
    run(`CREATE TABLE IF NOT EXISTS alertcfg (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tg_token TEXT,
        tg_userid TEXT,
        wx_api TEXT,
        wx_token TEXT,
        auto_check_enabled INTEGER DEFAULT 0,
        auto_check_interval INTEGER DEFAULT 30,
        days INTEGER NOT NULL DEFAULT 30,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
    run(`CREATE TABLE IF NOT EXISTS cf_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        token TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
    addColumnIfMissing('domains', 'cf_hosted', 'ALTER TABLE domains ADD COLUMN cf_hosted INTEGER DEFAULT 0')
    addColumnIfMissing('domains', 'cf_account_id', 'ALTER TABLE domains ADD COLUMN cf_account_id INTEGER')
    if (hasColumn('domains', 'cert_status')) {
        run(`UPDATE domains SET cert_status = '无' WHERE cert_status IS NULL`)
    }
    const websiteCount = readRow('SELECT COUNT(*) AS count FROM websitecfg')
    if (!websiteCount || websiteCount.count === 0) {
        const defaults = [
            { name: '樱花博客', filename: 'sakura.html' },
            { name: '圣诞贺卡', filename: 'christmas.html' },
            { name: '李明的简历', filename: 'resume.html' },
            { name: '人力资源网站', filename: 'hr.html' },
            { name: '游戏门户', filename: 'game.html' },
            { name: '德一教育', filename: 'deyiedu.html' }
        ]
        for (const item of defaults) {
            run('INSERT INTO websitecfg (name, filename) VALUES (?, ?)', [item.name, item.filename])
        }
    }
    persistDb()
}

const getBearerToken = (req) => {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null
    return authHeader.replace('Bearer ', '').trim()
}

const getAuthToken = (req) => {
    const headerToken = getBearerToken(req)
    if (headerToken) return headerToken
    if (typeof req.query.token === 'string') return req.query.token
    return null
}

const requireAuth = (req, res, next) => {
    const token = getAuthToken(req)
    if (!token) {
        return res.status(401).json({ status: 401, message: '未授权访问', data: null })
    }
    return next()
}

const requireApiToken = (req, res, next) => {
    const tokenParam = req.query.token
    const headerToken = getBearerToken(req)
    const token = tokenParam || headerToken
    if (!token || token !== process.env.API_TOKEN) {
        return res.status(401).json({ status: 401, message: '无效的访问令牌', data: null })
    }
    return next()
}

const calculateRemainingDays = (expiryDate) => {
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const expiry = new Date(expiryDate)
    expiry.setHours(0, 0, 0, 0)
    const diffTime = expiry.getTime() - today.getTime()
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    return Math.max(0, diffDays)
}

const checkDomainStatus = async (domain) => {
    const tryFetch = async (protocol) => {
        for (let attempt = 1; attempt <= 2; attempt++) {
            try {
                const controller = new AbortController()
                const timeoutId = setTimeout(() => controller.abort(), 10000)
                const targetUrl = `${protocol}://${domain}`
                const response = await fetch(targetUrl, {
                    method: 'GET',
                    redirect: 'follow',
                    signal: controller.signal,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
                    }
                })
                clearTimeout(timeoutId)
                if (response.ok) {
                    return true
                }
            } catch (error) {
                if (error && error.name === 'AbortError') {
                    continue
                }
            }
        }
        return false
    }
    if (await tryFetch('https')) {
        return true
    }
    return await tryFetch('http')
}

const execCommand = (command, options = {}) => new Promise((resolve, reject) => {
    const execOptions = {}
    if (options.timeoutMs) {
        execOptions.timeout = options.timeoutMs
    }
    exec(command, execOptions, (error, stdout, stderr) => {
        if (error) {
            reject(new Error(stderr || error.message))
            return
        }
        resolve(stdout)
    })
})

const getWebsitesDir = () => process.env.WEBSITES_DIR || path.join(__dirname, '..', 'websites')

const listWebsiteFiles = () => {
    const dir = getWebsitesDir()
    if (!fs.existsSync(dir)) {
        return []
    }
    return fs.readdirSync(dir, { withFileTypes: true }).map((entry) => entry.name)
}

const resolveWebsiteRoot = (filename) => {
    const dir = getWebsitesDir()
    const filePath = path.join(dir, filename)
    if (!fs.existsSync(filePath)) {
        return null
    }
    const stat = fs.statSync(filePath)
    if (stat.isDirectory()) {
        return { root: filePath, index: 'index.html' }
    }
    return { root: dir, index: filename }
}

const normalizeIp = (address) => address.split('%')[0].toLowerCase()

const isPrivateIPv4 = (ip) => {
    return ip.startsWith('10.')
        || ip.startsWith('127.')
        || ip.startsWith('169.254.')
        || ip.startsWith('192.168.')
        || /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
}

const isGlobalIPv6 = (ip) => {
    if (ip === '::' || ip === '::1') return false
    if (ip.startsWith('fe80')) return false
    if (ip.startsWith('fc') || ip.startsWith('fd')) return false
    if (ip.startsWith('ff')) return false
    return true
}

const getServerIpCandidates = () => {
    const interfaces = os.networkInterfaces()
    const ipv6Global = []
    const ipv6Other = []
    const ipv4Public = []
    const ipv4Private = []
    for (const name of Object.keys(interfaces)) {
        for (const net of interfaces[name] || []) {
            if (net.internal) continue
            const address = normalizeIp(net.address)
            if (net.family === 'IPv6') {
                if (isGlobalIPv6(address)) {
                    ipv6Global.push(address)
                } else {
                    ipv6Other.push(address)
                }
            } else if (net.family === 'IPv4') {
                if (isPrivateIPv4(address)) {
                    ipv4Private.push(address)
                } else if (address !== '0.0.0.0') {
                    ipv4Public.push(address)
                }
            }
        }
    }
    return { ipv6Global, ipv6Other, ipv4Public, ipv4Private }
}

const getServerIp = () => {
    const { ipv6Global, ipv6Other, ipv4Public, ipv4Private } = getServerIpCandidates()
    if (ipv4Public.length > 0) return ipv4Public[0]
    if (ipv6Global.length > 0) return ipv6Global[0]
    if (ipv6Other.length > 0) return ipv6Other[0]
    if (ipv4Private.length > 0) return ipv4Private[0]
    return '127.0.0.1'
}

const writeNginxConfig = async (domain, filename) => {
    const nginxSitesDir = process.env.NGINX_SITES_DIR
    if (!nginxSitesDir) {
        appendLog('nginx', `skip write config for ${domain}: NGINX_SITES_DIR not set`)
        return
    }
    const resolved = resolveWebsiteRoot(filename)
    if (!resolved) {
        appendLog('nginx', `skip write config for ${domain}: website file missing ${filename}`)
        return
    }
    if (!fs.existsSync(nginxSitesDir)) {
        fs.mkdirSync(nginxSitesDir, { recursive: true })
    }
    const certDir = `/etc/letsencrypt/live/${domain}`
    const certFile = path.join(certDir, 'fullchain.pem')
    const keyFile = path.join(certDir, 'privkey.pem')
    const hasCert = fs.existsSync(certFile) && fs.existsSync(keyFile)
    const config = [
        'server {',
        '    listen 80;',
        '    listen [::]:80;',
        ...(hasCert ? ['    listen 443 ssl;', '    listen [::]:443 ssl;'] : []),
        `    server_name ${domain};`,
        `    root ${resolved.root};`,
        `    index ${resolved.index};`,
        '    location / {',
        '        try_files $uri $uri/ =404;',
        '    }',
        ...(hasCert ? [
            `    ssl_certificate ${certFile};`,
            `    ssl_certificate_key ${keyFile};`,
            '    include /etc/letsencrypt/options-ssl-nginx.conf;',
            '    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;'
        ] : []),
        '}',
        ''
    ].join('\n')
    const configPath = path.join(nginxSitesDir, `${domain}.conf`)
    fs.writeFileSync(configPath, config)
    appendLog('nginx', `write config ${configPath} for ${domain}`)
    const reloadCmd = process.env.NGINX_RELOAD_CMD
    if (reloadCmd) {
        appendLog('nginx', `reload command ${reloadCmd}`)
        await execCommand(reloadCmd)
    } else {
        appendLog('nginx', 'reload skipped: NGINX_RELOAD_CMD not set')
    }
}

const removeNginxConfig = async (domain) => {
    const nginxSitesDir = process.env.NGINX_SITES_DIR
    if (!nginxSitesDir) {
        appendLog('nginx', `skip remove config for ${domain}: NGINX_SITES_DIR not set`)
        return
    }
    const configPath = path.join(nginxSitesDir, `${domain}.conf`)
    if (fs.existsSync(configPath)) {
        fs.unlinkSync(configPath)
        appendLog('nginx', `remove config ${configPath} for ${domain}`)
    }
    const reloadCmd = process.env.NGINX_RELOAD_CMD
    if (reloadCmd) {
        appendLog('nginx', `reload command ${reloadCmd}`)
        await execCommand(reloadCmd)
    } else {
        appendLog('nginx', 'reload skipped: NGINX_RELOAD_CMD not set')
    }
}

const getWildcardCandidate = (domain) => {
    if (!domain || !domain.includes('.')) return null
    if (domain.startsWith('*.')) return domain
    const parts = domain.split('.').filter(Boolean)
    if (parts.length < 2) return null
    if (parts.length === 2) return `*.${domain}`
    return `*.${parts.slice(1).join('.')}`
}

const hasWildcardCertificate = async (domain) => {
    const wildcard = getWildcardCandidate(domain)
    if (!wildcard) return false
    const certbotListCmd = process.env.CERTBOT_CERTS_CMD || 'certbot certificates'
    try {
        const output = await execCommand(certbotListCmd)
        const domainLines = output
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.startsWith('Domains:'))
        for (const line of domainLines) {
            const domains = line.replace('Domains:', '').trim().split(/\s+/)
            if (domains.includes(wildcard)) {
                appendLog('certbot', `wildcard exists ${wildcard}, skip ${domain}`)
                return true
            }
        }
        return false
    } catch (error) {
        appendLog('certbot', `wildcard check failed: ${error instanceof Error ? error.message : String(error)}`)
        return false
    }
}

const listCertbotDomains = async () => {
    const certbotListCmd = process.env.CERTBOT_CERTS_CMD || 'certbot certificates'
    try {
        const output = await execCommand(certbotListCmd)
        const domainLines = output
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.startsWith('Domains:'))
        const domains = new Set()
        for (const line of domainLines) {
            const items = line.replace('Domains:', '').trim().split(/\s+/).filter(Boolean)
            for (const item of items) {
                domains.add(item)
            }
        }
        return domains
    } catch (error) {
        appendLog('certbot', `list certificates failed: ${error instanceof Error ? error.message : String(error)}`)
        return new Set()
    }
}

const resolveDomainIps = async (domain) => {
    const ipv4 = []
    const ipv6 = []
    try {
        const records4 = await dns.resolve4(domain)
        ipv4.push(...records4)
    } catch {
    }
    try {
        const records6 = await dns.resolve6(domain)
        ipv6.push(...records6)
    } catch {
    }
    return { ipv4, ipv6 }
}

const isDnsPointingToServer = async (domain) => {
    const { ipv4Public, ipv6Global } = getServerIpCandidates()
    if (ipv4Public.length === 0 && ipv6Global.length === 0) {
        return true
    }
    const serverIpv4 = new Set(ipv4Public)
    const serverIpv6 = new Set(ipv6Global.map((ip) => normalizeIp(ip)))
    const { ipv4, ipv6 } = await resolveDomainIps(domain)
    const matchIpv4 = ipv4.some((ip) => serverIpv4.has(ip))
    const matchIpv6 = ipv6.some((ip) => serverIpv6.has(normalizeIp(ip)))
    return matchIpv4 || matchIpv6
}

const normalizeDomain = (value) => (value || '').trim().toLowerCase()

const matchZoneForDomain = (domain, zones) => {
    const target = normalizeDomain(domain)
    let best = null
    for (const zone of zones || []) {
        const name = normalizeDomain(zone?.name)
        if (!name) continue
        if (target === name || target.endsWith(`.${name}`)) {
            if (!best || name.length > best.name.length) {
                best = zone
            }
        }
    }
    return best
}

const maskToken = (token) => {
    if (!token) return ''
    const visible = token.slice(-5)
    return `${'*'.repeat(Math.max(0, token.length - 5))}${visible}`
}

const buildCfHeaders = (token, email, useKeyAuth) => {
    if (useKeyAuth) {
        return {
            'Content-Type': 'application/json',
            'X-Auth-Email': email || '',
            'X-Auth-Key': token || '',
            'User-Agent': 'Domains-Support'
        }
    }
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        'User-Agent': 'Domains-Support'
    }
}

const cfRequest = async (token, url, options = {}, email) => {
    const send = async (useKeyAuth) => {
        const response = await fetch(url, {
            ...options,
            headers: {
                ...buildCfHeaders(token, email, useKeyAuth),
                ...(options.headers || {})
            }
        })
        const data = await response.json()
        if (!response.ok || data?.success === false) {
            const message = data?.errors?.[0]?.message || response.statusText || 'Cloudflare request failed'
            const error = new Error(message)
            error.status = response.status
            throw error
        }
        return data
    }
    try {
        return await send(false)
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        const shouldFallback = [
            'Invalid request headers',
            'Unable to authenticate request',
            'Invalid API token',
            'Invalid API key',
            'Authentication error'
        ].some((text) => message.includes(text))
        if (email && shouldFallback) {
            return await send(true)
        }
        throw error
    }
}

const upsertCfRecord = async (token, email, zoneId, type, name, content) => {
    const listUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(name)}`
    const list = await cfRequest(token, listUrl, {}, email)
    const existing = Array.isArray(list.result) && list.result.length > 0 ? list.result[0] : null
    const payload = { type, name, content, ttl: 1, proxied: false }
    if (existing) {
        const updateUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${existing.id}`
        await cfRequest(token, updateUrl, { method: 'PUT', body: JSON.stringify(payload) }, email)
        return
    }
    const createUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`
    await cfRequest(token, createUrl, { method: 'POST', body: JSON.stringify(payload) }, email)
}

const bindCfDnsRecords = async (domain, cfAccountId) => {
    const account = readRow('SELECT * FROM cf_accounts WHERE id = ?', [cfAccountId])
    if (!account) {
        throw new Error('CF账号不存在')
    }
    let zones = []
    let page = 1
    let totalPages = 1
    while (page <= totalPages) {
        const list = await cfRequest(
            account.token,
            `https://api.cloudflare.com/client/v4/zones?per_page=50&page=${page}`,
            {},
            account.email
        )
        if (Array.isArray(list?.result)) {
            zones.push(...list.result)
        }
        totalPages = Number(list?.result_info?.total_pages || totalPages)
        page += 1
    }
    const zone = matchZoneForDomain(domain, zones)
    if (!zone?.id) {
        throw new Error('未找到对应的CF Zone')
    }
    const { ipv4Public, ipv6Global } = getServerIpCandidates()
    if (ipv4Public.length === 0 && ipv6Global.length === 0) {
        throw new Error('未检测到服务器公网IP')
    }
    for (const ip of ipv4Public) {
        await upsertCfRecord(account.token, account.email, zone.id, 'A', domain, ip)
    }
    for (const ip of ipv6Global) {
        await upsertCfRecord(account.token, account.email, zone.id, 'AAAA', domain, ip)
    }
}

const cleanValue = (value) => {
    if (!value) return ''
    return value.trim().replace(/^['"`]+|['"`]+$/g, '')
}

const runAsyncTask = (label, task) => {
    Promise.resolve()
        .then(task)
        .catch((error) => {
            appendLog('system', `${label} failed: ${error instanceof Error ? error.message : String(error)}`)
        })
}

const isCertbotRunning = async () => {
    try {
        const output = await execCommand("pgrep -f '[c]ertbot'")
        return output.trim().length > 0
    } catch {
        return false
    }
}

const enqueueCertRequest = (domain, siteId, options = {}) => {
    if (!siteId || certQueueSet.has(domain)) return
    certQueue.push({ domain, siteId })
    certQueueSet.add(domain)
    if (options.setStatus !== false) {
        updateCertStatus(domain, '申请中', { retryAt: null, retryCount: 0 })
    }
}

const processCertQueue = async () => {
    if (certQueueProcessing) return
    if (certQueue.length === 0) return
    if (await isCertbotRunning()) return
    const task = certQueue.shift()
    if (!task) return
    certQueueSet.delete(task.domain)
    certQueueProcessing = true
    try {
        const domainRow = readRow('SELECT cf_hosted, cf_account_id FROM domains WHERE domain = ?', [task.domain])
        const site = readRow('SELECT * FROM websitecfg WHERE id = ?', [task.siteId])
        if (!site) {
            updateCertStatus(task.domain, '失败', { retryAt: null, retryCount: 0 })
            appendLog('nginx', `skip binding for ${task.domain}: site not found ${task.siteId}`)
            return
        }
        await writeNginxConfig(task.domain, site.filename)
        const dnsOk = await isDnsPointingToServer(task.domain)
        if (!dnsOk) {
            updateCertStatus(task.domain, '未设置DNS', { retryAt: null, retryCount: 0 })
            appendLog('certbot', `skip for ${task.domain}: dns not pointing to server`)
            if (domainRow?.cf_hosted === 1 && task.siteId) {
                enqueueCertRequest(task.domain, task.siteId, { setStatus: false })
            }
            return
        }
        const certDomains = await listCertbotDomains()
        const wildcard = getWildcardCandidate(task.domain)
        const hasExistingCert = certDomains.has(task.domain) || (wildcard ? certDomains.has(wildcard) : false)
        if (hasExistingCert) {
            updateCertStatus(task.domain, '成功', { retryAt: null, retryCount: 0 })
            appendLog('certbot', `skip for ${task.domain}: cert exists`)
            return
        }
        await applyCertbot(task.domain)
    } catch (error) {
        updateCertStatus(task.domain, '失败', { retryAt: null, retryCount: 0 })
        appendLog('certbot', `failed for ${task.domain}: ${error instanceof Error ? error.message : String(error)}`)
    } finally {
        certQueueProcessing = false
    }
}

const initCertQueue = () => {
    const rows = readRows(`SELECT domain, site_id FROM domains
        WHERE service_type = '伪装网站'
        AND cert_status = '申请中'
        AND site_id IS NOT NULL`)
    for (const row of rows) {
        enqueueCertRequest(row.domain, row.site_id)
    }
}

const notifyCertStatusChange = (payload) => {
    if (certStatusSubscribers.size === 0) return
    const data = `data: ${JSON.stringify(payload)}\n\n`
    for (const res of certStatusSubscribers) {
        try {
            res.write(data)
        } catch {
            certStatusSubscribers.delete(res)
        }
    }
}

const updateCertStatus = (domain, status, options = {}) => {
    const fields = ['cert_status = ?']
    const params = [status]
    if ('retryAt' in options) {
        fields.push('cert_retry_at = ?')
        params.push(options.retryAt)
    }
    if ('retryCount' in options) {
        fields.push('cert_retry_count = ?')
        params.push(options.retryCount)
    }
    params.push(domain)
    run(`UPDATE domains SET ${fields.join(', ')} WHERE domain = ?`, params)
    persistDb()
    notifyCertStatusChange({ type: 'cert_status_updated', domain, status })
}

const syncCertStatusFromCertbot = async () => {
    const certDomains = await listCertbotDomains()
    if (certDomains.size === 0) return
    const rows = readRows(`SELECT domain, cert_status FROM domains WHERE service_type = '伪装网站'`)
    let updatedCount = 0
    for (const row of rows) {
        const wildcard = getWildcardCandidate(row.domain)
        const hasCert = certDomains.has(row.domain) || (wildcard ? certDomains.has(wildcard) : false)
        if (hasCert && row.cert_status !== '成功') {
            updateCertStatus(row.domain, '成功', { retryAt: null, retryCount: 0 })
            updatedCount += 1
        }
    }
    if (updatedCount > 0) {
        appendLog('certbot', `cert status sync updated ${updatedCount}`)
    }
}

const syncCertStatusAndFetchDomains = async () => {
    await syncCertStatusFromCertbot()
    return readRows('SELECT * FROM domains ORDER BY created_at DESC')
}

const applyCertbot = async (domain) => {
    const certbotCmd = process.env.CERTBOT_CMD
    if (!certbotCmd) {
        appendLog('certbot', `skip for ${domain}: CERTBOT_CMD not set`)
        updateCertStatus(domain, '无', { retryAt: null, retryCount: 0 })
        return
    }
    const timeoutValue = Number(process.env.CERTBOT_TIMEOUT_MS || 120000)
    const timeoutMs = Number.isFinite(timeoutValue) && timeoutValue > 0 ? timeoutValue : 120000
    const acmeServer = cleanValue(process.env.ACME_SERVER)
    const eabKid = cleanValue(process.env.ACME_EAB_KID)
    const eabHmacKey = cleanValue(process.env.ACME_EAB_HMAC_KEY)
    const defaultAcmeServer = 'https://acme-v02.api.letsencrypt.org/directory'
    const useZeroSsl = acmeServer && acmeServer.includes('zerossl.com')
    let effectiveAcmeServer = acmeServer
    if (useZeroSsl && (!eabKid || !eabHmacKey)) {
        effectiveAcmeServer = defaultAcmeServer
        appendLog('certbot', `acme server fallback ${defaultAcmeServer}`)
    }
    if (!effectiveAcmeServer) {
        effectiveAcmeServer = defaultAcmeServer
        appendLog('certbot', `acme server ${defaultAcmeServer}`)
    }
    let command = certbotCmd.includes('{domain}') ? certbotCmd.replace('{domain}', domain) : `${certbotCmd} -d ${domain}`
    if (effectiveAcmeServer && !command.includes('--server')) {
        command = `${command} --server ${effectiveAcmeServer}`
        if (acmeServer && acmeServer !== effectiveAcmeServer) {
            appendLog('certbot', `acme server ${effectiveAcmeServer}`)
        } else if (acmeServer) {
            appendLog('certbot', `acme server ${acmeServer}`)
        }
    }
    if (eabKid && eabHmacKey && !command.includes('--eab-kid') && !command.includes('--eab-hmac-key')) {
        command = `${command} --eab-kid ${eabKid} --eab-hmac-key ${eabHmacKey}`
        appendLog('certbot', 'eab enabled')
    }
    appendLog('certbot', `command ${command}`)
    try {
        await execCommand(command, { timeoutMs })
        updateCertStatus(domain, '成功', { retryAt: null, retryCount: 0 })
        appendLog('certbot', `success for ${domain}`)
    } catch (error) {
        updateCertStatus(domain, '失败', { retryAt: null, retryCount: 0 })
        appendLog('certbot', `failed for ${domain}: ${error instanceof Error ? error.message : String(error)}`)
    }
}

const applyWebsiteBinding = async (domain, siteId) => {
    appendLog('certbot', `queue ${domain} site ${siteId}`)
    enqueueCertRequest(domain, siteId)
}

const removeWebsiteBinding = async (domain) => {
    appendLog('nginx', `remove binding ${domain}`)
    await removeNginxConfig(domain)
}

const sendTelegramMessage = async (token, chatId, message) => {
    if (!token || !chatId) {
        throw new Error('Telegram token 或 chat ID 未配置')
    }
    const url = `https://api.telegram.org/bot${token}/sendMessage`
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            chat_id: chatId,
            text: message,
            parse_mode: 'Markdown'
        })
    })
    const responseData = await response.json()
    if (!response.ok) {
        throw new Error(`Failed to send Telegram message: ${response.statusText}, Details: ${JSON.stringify(responseData)}`)
    }
}

const sendWeChatMessage = async (apiUrl, token, title, text) => {
    if (!apiUrl || !token) {
        return
    }
    const body = `title=${encodeURIComponent(title)}&content=${encodeURIComponent(text)}&token=${encodeURIComponent(token)}`
    await fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body
    })
}

const runWithConcurrency = async (items, limit, task) => {
    const results = new Array(items.length)
    let nextIndex = 0
    const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
        while (nextIndex < items.length) {
            const currentIndex = nextIndex
            nextIndex += 1
            results[currentIndex] = await task(items[currentIndex], currentIndex)
        }
    })
    await Promise.all(workers)
    return results
}

const checkAllDomains = async () => {
    const domainList = readRows('SELECT * FROM domains ORDER BY created_at DESC')
    if (domainList.length === 0) {
        return []
    }
    const updatedDomains = await runWithConcurrency(domainList, 10, async (domain) => {
        const isOnline = await checkDomainStatus(domain.domain)
        const status = isOnline ? '在线' : '离线'
        run('UPDATE domains SET status = ? WHERE id = ?', [status, domain.id])
        return { ...domain, status }
    })
    persistDb()
    return updatedDomains
}

const checkAndNotifyDomains = async () => {
    console.log('[checkAndNotify] 开始执行定时检查...')
    const config = readRow('SELECT * FROM alertcfg LIMIT 1')
    if (!config) {
        console.log('[checkAndNotify] 未找到告警配置(alertcfg), 跳过')
        return { total: 0, notified: 0 }
    }
    console.log(`[checkAndNotify] 告警配置: days=${config.days}, tg_token=${config.tg_token ? '已配置' : '未配置'}, tg_userid=${config.tg_userid || '未配置'}, auto_check_enabled=${config.auto_check_enabled}, interval=${config.auto_check_interval}分钟`)
    const domains = readRows('SELECT domain, expiry_date, tgsend, st_tgsend FROM domains WHERE tgsend = 1 OR st_tgsend = 1')
    if (domains.length === 0) {
        console.log('[checkAndNotify] 没有开启通知的域名, 跳过')
        return { total: 0, notified: 0 }
    }
    console.log(`[checkAndNotify] 共有 ${domains.length} 个域名需要检查`)
    const results = await runWithConcurrency(domains, 10, async (domain) => {
        const remainingDays = calculateRemainingDays(domain.expiry_date)
        const isOnline = await checkDomainStatus(domain.domain)
        const status = isOnline ? '在线' : '离线'
        run('UPDATE domains SET status = ? WHERE domain = ?', [status, domain.domain])
        console.log(`[checkAndNotify]   ${domain.domain}: 状态=${status}, 剩余=${remainingDays}天, 到期日=${domain.expiry_date}, tgsend=${domain.tgsend}, st_tgsend=${domain.st_tgsend}`)
        return { ...domain, status, remainingDays }
    })
    const offlineDomains = results.filter((d) => d.status === '离线' && d.st_tgsend === 1)
    const expiringDomains = results.filter((d) => d.remainingDays <= config.days && d.tgsend === 1)
    console.log(`[checkAndNotify] 检查结果: 离线=${offlineDomains.length}个, 即将过期=${expiringDomains.length}个 (阈值<=${config.days}天)`)
    if (offlineDomains.length > 0) {
        const offlineDetails = offlineDomains.map((d) => `\`${d.domain}\``).join('\n')
        const message = `*🔔 Domains-Support 通知*\n\n⚠️ *域名服务离线告警*\n\n以下域名无法访问，请立即检查：\n${offlineDetails}\n\n⏰ 时间：${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`
        try {
            if (config.tg_token && config.tg_userid) {
                console.log(`[checkAndNotify] 发送Telegram离线告警: ${offlineDomains.map(d => d.domain).join(', ')}`)
                await sendTelegramMessage(config.tg_token, config.tg_userid, message)
                console.log('[checkAndNotify] Telegram离线告警发送成功')
            } else {
                console.log('[checkAndNotify] Telegram未配置, 跳过离线告警发送')
            }
            if (config.wx_api && config.wx_token) {
                await sendWeChatMessage(config.wx_api, config.wx_token, '域名服务离线告警', message)
            }
        } catch (error) {
            console.log(`[checkAndNotify] 离线告警发送失败: ${error instanceof Error ? error.message : String(error)}`)
        }
    }
    if (expiringDomains.length > 0) {
        const expiringDetails = expiringDomains
            .map((d) => `\`${d.domain}\` (还剩 ${d.remainingDays} 天, ${d.expiry_date})`)
            .join('\n')
        const message = `*🔔 Domains-Support 通知*\n\n⚠️ *域名即将过期提醒*\n\n以下域名即将在 ${config.days} 天内过期，请及时续费：\n${expiringDetails}\n\n⏰ 时间：${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`
        try {
            if (config.tg_token && config.tg_userid) {
                console.log(`[checkAndNotify] 发送Telegram到期提醒: ${expiringDomains.map(d => `${d.domain}(${d.remainingDays}天)`).join(', ')}`)
                await sendTelegramMessage(config.tg_token, config.tg_userid, message)
                console.log('[checkAndNotify] Telegram到期提醒发送成功')
            } else {
                console.log('[checkAndNotify] Telegram未配置, 跳过到期提醒发送')
            }
            if (config.wx_api && config.wx_token) {
                await sendWeChatMessage(config.wx_api, config.wx_token, '域名即将过期提醒', message)
            }
        } catch (error) {
            console.log(`[checkAndNotify] 到期提醒发送失败: ${error instanceof Error ? error.message : String(error)}`)
        }
    }
    if (offlineDomains.length === 0 && expiringDomains.length === 0) {
        console.log('[checkAndNotify] 本次检查无需发送通知')
    }
    persistDb()
    return { total: results.length, notified: offlineDomains.length + expiringDomains.length }
}

const stopAutoCheck = () => {
    if (autoCheckTimer) {
        clearInterval(autoCheckTimer)
        autoCheckTimer = null
    }
}

const applyAutoCheckConfig = (config) => {
    stopAutoCheck()
    if (!config || config.auto_check_enabled !== 1) return
    const intervalMinutes = Number(config.auto_check_interval || 0)
    if (intervalMinutes <= 0) return
    autoCheckTimer = setInterval(() => {
        checkAndNotifyDomains().catch(() => {})
    }, intervalMinutes * 60 * 1000)
}

const startServer = async () => {
    SQL = await initSqlJs()
    if (fs.existsSync(dbFilePath)) {
        const fileBuffer = fs.readFileSync(dbFilePath)
        db = new SQL.Database(fileBuffer)
        try {
            const stat = fs.statSync(dbFilePath)
            dbLastMtimeMs = stat.mtimeMs
        } catch {
        }
    } else {
        db = new SQL.Database()
    }
    ensureSchema()
    const initialConfig = readRow('SELECT * FROM alertcfg LIMIT 1')
    applyAutoCheckConfig(initialConfig)
    runAsyncTask('cert status sync', syncCertStatusFromCertbot)
    runAsyncTask('cert queue init', () => {
        initCertQueue()
        return processCertQueue()
    })
    if (certQueueTimer) {
        clearInterval(certQueueTimer)
        certQueueTimer = null
    }
    certQueueTimer = setInterval(() => {
        runAsyncTask('cert queue tick', processCertQueue)
    }, 60 * 1000)
    appendLog('system', `server start port ${port} log ${logFilePath}`)

    app.use(express.json({ limit: '5mb' }))

    app.use('/api', (req, res, next) => {
        if (req.path === '/login') return next()
        if (req.path.startsWith('/check') || req.path.startsWith('/addrec')) {
            return requireApiToken(req, res, next)
        }
        return requireAuth(req, res, next)
    })

    app.post('/api/login', (req, res) => {
        try {
            const { username, password } = req.body || {}
            const expectedUsername = process.env.USER
            const expectedPassword = process.env.PASS
            if (!expectedUsername || !expectedPassword) {
                return res.status(500).json({ status: 500, message: '系统配置错误：未设置用户名或密码', data: null })
            }
            if (username === expectedUsername && password === expectedPassword) {
                const token = Buffer.from(JSON.stringify({ username, timestamp: new Date().getTime() })).toString('base64')
                return res.json({ status: 200, message: '登录成功', data: { token } })
            }
            return res.status(401).json({ status: 401, message: '用户名或密码错误', data: null })
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '登录失败', data: null })
        }
    })

    app.get('/api/system/ip', (_req, res) => {
        return res.json({ status: 200, message: '获取成功', data: { ip: getServerIp() } })
    })

    app.get('/api/domains', (req, res) => {
        try {
            const rows = readRows('SELECT * FROM domains ORDER BY created_at DESC')
            return res.json({ status: 200, message: '获取成功', data: rows })
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '获取域名列表失败', data: [] })
        }
    })

    app.get('/api/events/cert-status', (req, res) => {
        res.setHeader('Content-Type', 'text/event-stream; charset=utf-8')
        res.setHeader('Cache-Control', 'no-cache')
        res.setHeader('Connection', 'keep-alive')
        res.setHeader('X-Accel-Buffering', 'no')
        if (typeof res.flushHeaders === 'function') {
            res.flushHeaders()
        }
        if (res.socket && typeof res.socket.setTimeout === 'function') {
            res.socket.setTimeout(0)
        }
        res.write('data: {"type":"connected"}\n\n')
        const pingTimer = setInterval(() => {
            try {
                res.write('event: ping\ndata: {}\n\n')
            } catch {
                clearInterval(pingTimer)
                certStatusSubscribers.delete(res)
            }
        }, 25000)
        certStatusSubscribers.add(res)
        req.on('close', () => {
            clearInterval(pingTimer)
            certStatusSubscribers.delete(res)
        })
    })

    app.post('/api/domains', async (req, res) => {
        try {
            const data = req.body || {}
            const requiredFields = ['domain', 'registrar', 'registrar_date', 'expiry_date', 'service_type', 'status']
            for (const field of requiredFields) {
                if (!data[field]) {
                    return res.status(400).json({ status: 400, message: `${field} 是必填字段`, data: null })
                }
            }
            if (data.service_type === '伪装网站' && !data.site_id) {
                return res.status(400).json({ status: 400, message: '请选择网站', data: null })
            }
            if (data.service_type === '伪装网站' && Number(data.cf_hosted) === 1 && !data.cf_account_id) {
                return res.status(400).json({ status: 400, message: '请选择CF账号', data: null })
            }
            const initialCertStatus = data.service_type === '伪装网站' ? '申请中' : '无'
            run(`INSERT INTO domains (
                domain, registrar, registrar_link, registrar_date,
                expiry_date, service_type, status, cert_status,
                tgsend, st_tgsend, site_id, cf_hosted, cf_account_id, memo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                data.domain,
                data.registrar,
                data.registrar_link || '',
                data.registrar_date,
                data.expiry_date,
                data.service_type,
                data.status,
                initialCertStatus,
                data.tgsend ?? 1,
                data.st_tgsend ?? 0,
                data.site_id || null,
                data.service_type === '伪装网站' ? Number(data.cf_hosted || 0) : 0,
                data.service_type === '伪装网站' ? (data.cf_account_id || null) : null,
                data.memo || ''
            ])
            const created = readRow('SELECT * FROM domains WHERE id = last_insert_rowid()')
            persistDb()
            res.json({ status: 200, message: '创建成功', data: created })
            notifyCertStatusChange({ type: 'cert_status_updated', domain: data.domain, status: initialCertStatus })
            if (data.service_type === '伪装网站' && data.site_id) {
                runAsyncTask(`apply binding ${data.domain}`, async () => {
                    try {
                        if (Number(data.cf_hosted) === 1 && data.cf_account_id) {
                            await bindCfDnsRecords(data.domain, data.cf_account_id)
                        }
                        applyWebsiteBinding(data.domain, data.site_id)
                    } catch (error) {
                        updateCertStatus(data.domain, '失败', { retryAt: null, retryCount: 0 })
                        appendLog('certbot', `cf bind failed for ${data.domain}: ${error instanceof Error ? error.message : String(error)}`)
                    }
                })
            }
            return
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '创建域名失败', data: null })
        }
    })

    app.put('/api/domains/:id', async (req, res) => {
        try {
            const id = req.params.id
            const data = req.body || {}
            const requiredFields = ['domain', 'registrar', 'registrar_date', 'expiry_date', 'service_type', 'status']
            for (const field of requiredFields) {
                if (!data[field]) {
                    return res.status(400).json({ status: 400, message: `${field} 是必填字段`, data: null })
                }
            }
            if (data.service_type === '伪装网站' && !data.site_id) {
                return res.status(400).json({ status: 400, message: '请选择网站', data: null })
            }
            if (data.service_type === '伪装网站' && Number(data.cf_hosted) === 1 && !data.cf_account_id) {
                return res.status(400).json({ status: 400, message: '请选择CF账号', data: null })
            }
            const existing = readRow('SELECT * FROM domains WHERE id = ?', [id])
            if (!existing) {
                return res.status(404).json({ status: 404, message: '域名不存在', data: null })
            }
            const cfHostedValue = data.service_type === '伪装网站' ? Number(data.cf_hosted || 0) : 0
            const cfAccountIdValue = data.service_type === '伪装网站' ? (data.cf_account_id || null) : null
            const cfChanged = existing.cf_hosted !== cfHostedValue || existing.cf_account_id !== cfAccountIdValue
            let nextCertStatus = existing.cert_status || '无'
            let nextRetryCount = existing.cert_retry_count || 0
            let nextRetryAt = existing.cert_retry_at || null
            if (data.service_type !== '伪装网站') {
                nextCertStatus = '无'
                nextRetryCount = 0
                nextRetryAt = null
            } else if (existing.service_type !== '伪装网站' || existing.domain !== data.domain || existing.site_id !== data.site_id || cfChanged) {
                nextCertStatus = '申请中'
                nextRetryCount = 0
                nextRetryAt = null
            }
            run(`UPDATE domains SET
                domain = ?,
                registrar = ?,
                registrar_link = ?,
                registrar_date = ?,
                expiry_date = ?,
                service_type = ?,
                status = ?,
                cert_status = ?,
                cert_retry_count = ?,
                cert_retry_at = ?,
                tgsend = ?,
                st_tgsend = ?,
                site_id = ?,
                cf_hosted = ?,
                cf_account_id = ?,
                memo = ?
            WHERE id = ?`, [
                data.domain,
                data.registrar,
                data.registrar_link || '',
                data.registrar_date,
                data.expiry_date,
                data.service_type,
                data.status,
                nextCertStatus,
                nextRetryCount,
                nextRetryAt,
                data.tgsend || 0,
                data.st_tgsend ?? 1,
                data.service_type === '伪装网站' ? data.site_id : null,
                cfHostedValue,
                cfAccountIdValue,
                data.memo || '',
                id
            ])
            const updated = readRow('SELECT * FROM domains WHERE id = ?', [id])
            persistDb()
            res.json({ status: 200, message: '更新成功', data: updated })
            if (existing.cert_status !== nextCertStatus) {
                notifyCertStatusChange({ type: 'cert_status_updated', domain: data.domain, status: nextCertStatus })
            }
            if (existing.service_type === '伪装网站' && data.service_type !== '伪装网站') {
                runAsyncTask(`remove binding ${existing.domain}`, () => removeWebsiteBinding(existing.domain))
            }
            if (existing.service_type === '伪装网站' && data.service_type === '伪装网站' && existing.domain !== data.domain) {
                runAsyncTask(`remove binding ${existing.domain}`, () => removeWebsiteBinding(existing.domain))
            }
            if (data.service_type === '伪装网站' && data.site_id && nextCertStatus === '申请中') {
                runAsyncTask(`apply binding ${data.domain}`, async () => {
                    try {
                        if (cfHostedValue === 1 && cfAccountIdValue) {
                            await bindCfDnsRecords(data.domain, cfAccountIdValue)
                        }
                        applyWebsiteBinding(data.domain, data.site_id)
                    } catch (error) {
                        updateCertStatus(data.domain, '失败', { retryAt: null, retryCount: 0 })
                        appendLog('certbot', `cf bind failed for ${data.domain}: ${error instanceof Error ? error.message : String(error)}`)
                    }
                })
            }
            return
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '更新域名失败', data: null })
        }
    })

    app.delete('/api/domains/:id', async (req, res) => {
        try {
            const id = req.params.id
            const existing = readRow('SELECT * FROM domains WHERE id = ?', [id])
            run('DELETE FROM domains WHERE id = ?', [id])
            persistDb()
            res.json({ status: 200, message: '删除成功', data: null })
            if (existing?.service_type === '伪装网站') {
                runAsyncTask(`remove binding ${existing.domain}`, () => removeWebsiteBinding(existing.domain))
            }
            return
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '删除域名失败', data: null })
        }
    })

    app.post('/api/domains/status', (req, res) => {
        try {
            const { domain, status } = req.body || {}
            run('UPDATE domains SET status = ? WHERE domain = ?', [status, domain])
            const updated = readRow('SELECT * FROM domains WHERE domain = ?', [domain])
            if (!updated) {
                return res.status(500).json({ status: 500, message: '更新状态失败', data: null })
            }
            persistDb()
            return res.json({ status: 200, message: '更新成功', data: updated })
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '更新域名状态失败', data: null })
        }
    })

    app.post('/api/domains/check', async (req, res) => {
        try {
            const { domain } = req.body || {}
            const isOnline = await checkDomainStatus(domain)
            return res.json({ status: 200, message: '检查完成', data: { status: isOnline ? '在线' : '离线' } })
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '检查失败', data: null })
        }
    })

    app.post('/api/domains/check-all', async (_req, res) => {
        try {
            const updatedDomains = await checkAllDomains()
            return res.json({ status: 200, message: '检查完成', data: updatedDomains })
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '检查失败', data: null })
        }
    })

    app.post('/api/domains/cert-sync', async (_req, res) => {
        try {
            const updatedDomains = await syncCertStatusAndFetchDomains()
            return res.json({ status: 200, message: '检查完成', data: updatedDomains })
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '检查失败', data: null })
        }
    })

    app.get('/api/domains/export', (req, res) => {
        try {
            const rows = readRows('SELECT domain, registrar, registrar_link, registrar_date, expiry_date, service_type, status, cert_status, memo, tgsend, st_tgsend, site_id, cf_hosted, cf_account_id FROM domains')
            const filename = `domains-export-${new Date().toISOString().split('T')[0]}.json`
            res.setHeader('Content-Type', 'application/json')
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)
            return res.send(JSON.stringify(rows, null, 2))
        } catch (error) {
            return res.status(500).json({ status: 500, message: '导出数据失败: ' + (error instanceof Error ? error.message : ''), data: null })
        }
    })

    app.post('/api/domains/import', upload.single('file'), (req, res) => {
        try {
            let domains = []
            const contentType = req.headers['content-type'] || ''
            if (contentType.includes('application/json')) {
                domains = Array.isArray(req.body) ? req.body : req.body?.domains || req.body
            } else if (contentType.includes('multipart/form-data')) {
                if (!req.file) {
                    return res.status(400).json({ status: 400, message: '未提供有效的文件', data: null })
                }
                domains = JSON.parse(req.file.buffer.toString('utf-8'))
            } else {
                return res.status(400).json({ status: 400, message: '不支持的内容类型', data: null })
            }
            if (!Array.isArray(domains)) {
                if (domains && typeof domains === 'object' && 'domains' in domains) {
                    const nestedDomains = domains.domains
                    if (Array.isArray(nestedDomains)) {
                        domains = nestedDomains
                    } else {
                        return res.status(400).json({ status: 400, message: '无效的数据格式：domains 字段不是数组', data: null })
                    }
                } else {
                    return res.status(400).json({ status: 400, message: '无效的数据格式：应为数组或包含 domains 数组的对象', data: null })
                }
            }
            const results = { total: domains.length, success: 0, failed: 0, errors: [] }
            let shouldNotifyCertStatus = false
            for (const domain of domains) {
                try {
                    if (!domain.domain) {
                        throw new Error('域名字段缺失')
                    }
                    const importCertStatus = domain.cert_status || (domain.service_type === '伪装网站' ? '申请中' : '无')
                    const existing = readRow('SELECT id FROM domains WHERE domain = ?', [domain.domain])
                    if (existing) {
                        run(`UPDATE domains SET 
                            registrar = ?, 
                            registrar_link = ?, 
                            registrar_date = ?, 
                            expiry_date = ?, 
                            service_type = ?, 
                            status = ?, 
                            cert_status = ?,
                            memo = ?, 
                            tgsend = ?, 
                            st_tgsend = ?,
                            site_id = ?,
                            cf_hosted = ?,
                            cf_account_id = ?
                        WHERE domain = ?`, [
                            domain.registrar || '',
                            domain.registrar_link || '',
                            domain.registrar_date || '',
                            domain.expiry_date || '',
                            domain.service_type || '',
                            domain.status || '离线',
                            importCertStatus,
                            domain.memo || '',
                            domain.tgsend || 0,
                            domain.st_tgsend || 0,
                            domain.site_id || null,
                            Number(domain.cf_hosted || 0),
                            domain.cf_account_id || null,
                            domain.domain
                        ])
                    } else {
                        run(`INSERT INTO domains 
                            (domain, registrar, registrar_link, registrar_date, expiry_date, service_type, status, cert_status, memo, tgsend, st_tgsend, site_id, cf_hosted, cf_account_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                            domain.domain,
                            domain.registrar || '',
                            domain.registrar_link || '',
                            domain.registrar_date || '',
                            domain.expiry_date || '',
                            domain.service_type || '',
                            domain.status || '离线',
                            importCertStatus,
                            domain.memo || '',
                            domain.tgsend || 0,
                            domain.st_tgsend || 0,
                            domain.site_id || null,
                            Number(domain.cf_hosted || 0),
                            domain.cf_account_id || null
                        ])
                    }
                    shouldNotifyCertStatus = true
                    results.success += 1
                } catch (error) {
                    results.failed += 1
                    results.errors.push({
                        domain: domain.domain || '未知域名',
                        error: error instanceof Error ? error.message : String(error)
                    })
                }
            }
            persistDb()
            if (shouldNotifyCertStatus) {
                notifyCertStatusChange({ type: 'cert_status_batch' })
            }
            return res.json({ status: 200, message: `导入完成: ${results.success} 成功, ${results.failed} 失败`, data: results })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '导入数据失败: ' + (error instanceof Error ? error.message : ''), data: null })
        }
    })

    app.get('/api/alertconfig', (req, res) => {
        try {
            const config = readRow('SELECT * FROM alertcfg LIMIT 1')
            return res.json({ status: 200, message: '获取成功', data: config || null })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '获取配置失败', data: null })
        }
    })

    app.post('/api/alertconfig', (req, res) => {
        try {
            const data = req.body || {}
            if (!data.days) {
                return res.status(400).json({ status: 400, message: 'days 是必填字段', data: null })
            }
            if (data.auto_check_enabled === 1 && (!data.auto_check_interval || data.auto_check_interval < 1)) {
                return res.status(400).json({ status: 400, message: 'auto_check_interval 是必填字段', data: null })
            }
            const existing = readRow('SELECT id FROM alertcfg LIMIT 1')
            if (existing) {
                run(`UPDATE alertcfg
                    SET tg_token = ?, tg_userid = ?, wx_api = ?, wx_token = ?, auto_check_enabled = ?, auto_check_interval = ?, days = ?
                    WHERE id = ?`, [
                    data.tg_token || '',
                    data.tg_userid || '',
                    data.wx_api || '',
                    data.wx_token || '',
                    data.auto_check_enabled ?? 0,
                    data.auto_check_interval ?? 30,
                    data.days,
                    existing.id
                ])
            } else {
                run(`INSERT INTO alertcfg (tg_token, tg_userid, wx_api, wx_token, auto_check_enabled, auto_check_interval, days)
                    VALUES (?, ?, ?, ?, ?, ?, ?)`, [
                    data.tg_token || '',
                    data.tg_userid || '',
                    data.wx_api || '',
                    data.wx_token || '',
                    data.auto_check_enabled ?? 0,
                    data.auto_check_interval ?? 30,
                    data.days
                ])
            }
            const config = readRow('SELECT * FROM alertcfg LIMIT 1')
            persistDb()
            applyAutoCheckConfig(config)
            return res.json({ status: 200, message: existing ? '更新成功' : '保存成功', data: config })
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '保存配置失败', data: null })
        }
    })

    app.get('/api/websites', (_req, res) => {
        try {
            const rows = readRows('SELECT * FROM websitecfg ORDER BY created_at DESC')
            return res.json({ status: 200, message: '获取成功', data: rows })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '获取失败', data: [] })
        }
    })

    app.get('/api/websites/files', (_req, res) => {
        try {
            const files = listWebsiteFiles()
            return res.json({ status: 200, message: '获取成功', data: files })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '获取失败', data: [] })
        }
    })

    app.get('/api/cf-accounts', (_req, res) => {
        try {
            const rows = readRows('SELECT id, email, token FROM cf_accounts ORDER BY created_at DESC')
            const masked = rows.map((row) => ({
                id: row.id,
                email: row.email,
                token: maskToken(row.token)
            }))
            return res.json({ status: 200, message: '获取成功', data: masked })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '获取失败', data: [] })
        }
    })

    app.post('/api/cf-accounts', (req, res) => {
        try {
            const data = req.body || {}
            if (!data.email || !data.token) {
                return res.status(400).json({ status: 400, message: 'email 和 token 是必填字段', data: null })
            }
            const existing = readRow('SELECT id FROM cf_accounts WHERE email = ?', [data.email])
            if (existing) {
                return res.status(409).json({ status: 409, message: '账号已存在', data: null })
            }
            run('INSERT INTO cf_accounts (email, token) VALUES (?, ?)', [data.email, data.token])
            const created = readRow('SELECT id, email, token FROM cf_accounts WHERE id = last_insert_rowid()')
            persistDb()
            return res.json({
                status: 200,
                message: '创建成功',
                data: { id: created.id, email: created.email, token: maskToken(created.token) }
            })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '创建失败', data: null })
        }
    })

    app.delete('/api/cf-accounts', (req, res) => {
        try {
            const data = req.body || {}
            const ids = Array.isArray(data.ids) ? data.ids.filter(Boolean) : []
            if (ids.length === 0) {
                return res.status(400).json({ status: 400, message: 'ids 是必填字段', data: null })
            }
            const placeholders = ids.map(() => '?').join(',')
            const usage = readRow(`SELECT COUNT(1) as count FROM domains WHERE cf_account_id IN (${placeholders})`, ids)
            if (usage?.count > 0) {
                return res.status(400).json({ status: 400, message: '存在已绑定的域名，无法删除', data: null })
            }
            run(`DELETE FROM cf_accounts WHERE id IN (${placeholders})`, ids)
            persistDb()
            return res.json({ status: 200, message: '删除成功', data: null })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '删除失败', data: null })
        }
    })

    app.post('/api/websites', (req, res) => {
        try {
            const data = req.body || {}
            if (!data.name || !data.filename) {
                return res.status(400).json({ status: 400, message: 'name 和 filename 是必填字段', data: null })
            }
            const files = listWebsiteFiles()
            if (!files.includes(data.filename)) {
                return res.status(400).json({ status: 400, message: '文件不存在', data: null })
            }
            const existing = readRow('SELECT id FROM websitecfg WHERE name = ?', [data.name])
            if (existing) {
                return res.status(409).json({ status: 409, message: '网站名称已存在', data: null })
            }
            run('INSERT INTO websitecfg (name, filename) VALUES (?, ?)', [data.name, data.filename])
            const created = readRow('SELECT * FROM websitecfg WHERE id = last_insert_rowid()')
            persistDb()
            return res.json({ status: 200, message: '创建成功', data: created })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '创建失败', data: null })
        }
    })

    app.delete('/api/websites', (req, res) => {
        try {
            const data = req.body || {}
            const ids = Array.isArray(data.ids) ? data.ids.filter(Boolean) : []
            if (ids.length === 0) {
                return res.status(400).json({ status: 400, message: 'ids 是必填字段', data: null })
            }
            const placeholders = ids.map(() => '?').join(',')
            const usage = readRow(`SELECT COUNT(1) as count FROM domains WHERE site_id IN (${placeholders})`, ids)
            if (usage?.count > 0) {
                return res.status(400).json({ status: 400, message: '存在已绑定的域名，无法删除', data: null })
            }
            run(`DELETE FROM websitecfg WHERE id IN (${placeholders})`, ids)
            persistDb()
            return res.json({ status: 200, message: '删除成功', data: null })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '删除失败', data: null })
        }
    })

    const handleCheck = async (req, res) => {
        try {
            let requestedDomains = []
            const queryDomains = req.query.domains
            if (Array.isArray(queryDomains)) {
                requestedDomains = queryDomains
            } else if (typeof queryDomains === 'string') {
                requestedDomains = queryDomains.split(',').map((item) => item.trim()).filter(Boolean)
            } else if (Array.isArray(req.body)) {
                requestedDomains = req.body
            } else {
                requestedDomains = req.body?.domains
            }
            if (!Array.isArray(requestedDomains) || requestedDomains.length === 0) {
                return res.status(400).json({ status: 400, message: '请求参数错误, 需要提供一个包含域名的数组', data: null })
            }
            const config = readRow('SELECT * FROM alertcfg LIMIT 1')
            if (!config) {
                return res.status(404).json({ status: 404, message: '未找到告警配置', data: null })
            }
            const placeholders = requestedDomains.map(() => '?').join(',')
            const domains = readRows(
                `SELECT domain, expiry_date, tgsend, st_tgsend FROM domains WHERE (tgsend = 1 OR st_tgsend = 1) AND domain IN (${placeholders})`,
                requestedDomains
            )
            const notifiedDomains = []
            const offlineDomains = []
            const expiringDomains = []
            for (const domain of domains) {
                const remainingDays = calculateRemainingDays(domain.expiry_date)
                const isOnline = await checkDomainStatus(domain.domain)
                const newStatus = isOnline ? '在线' : '离线'
                run('UPDATE domains SET status = ? WHERE domain = ?', [newStatus, domain.domain])
                if (newStatus === '离线' && domain.st_tgsend === 1) {
                    offlineDomains.push(domain)
                }
                if (remainingDays <= config.days && domain.tgsend === 1) {
                    expiringDomains.push({ ...domain, remainingDays })
                }
            }
            if (offlineDomains.length > 0) {
                const offlineDetails = offlineDomains.map((d) => `\`${d.domain}\``).join('\n')
                const message = `*🔔 Domains-Support 通知*\n\n⚠️ *域名服务离线告警*\n\n以下域名无法访问，请立即检查：\n${offlineDetails}\n\n⏰ 时间：${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`
                try {
                    if (config.tg_token && config.tg_userid) {
                        await sendTelegramMessage(config.tg_token, config.tg_userid, message)
                    }
                    if (config.wx_api && config.wx_token) {
                        await sendWeChatMessage(config.wx_api, config.wx_token, '域名服务离线告警', message)
                    }
                } catch (error) {
                }
            }
            if (expiringDomains.length > 0) {
                const expiringDetails = expiringDomains
                    .map((d) => `\`${d.domain}\` (还剩 ${d.remainingDays} 天, ${d.expiry_date})`)
                    .join('\n')
                const message = `*🔔 Domains-Support 通知*\n\n⚠️ *域名即将过期提醒*\n\n以下域名即将在 ${config.days} 天内过期，请及时续费：\n${expiringDetails}\n\n⏰ 时间：${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`
                try {
                    if (config.tg_token && config.tg_userid) {
                        await sendTelegramMessage(config.tg_token, config.tg_userid, message)
                    }
                    if (config.wx_api && config.wx_token) {
                        await sendWeChatMessage(config.wx_api, config.wx_token, '域名即将过期提醒', message)
                    }
                    notifiedDomains.push(...expiringDomains.map((d) => ({
                        domain: d.domain,
                        remainingDays: d.remainingDays,
                        expiry_date: d.expiry_date
                    })))
                } catch (error) {
                }
            }
            persistDb()
            return res.json({
                status: 200,
                message: '检查完成',
                data: {
                    total_domains: domains.length,
                    notified_domains: notifiedDomains
                }
            })
        } catch (error) {
            return res.status(500).json({ status: 500, message: '检查执行失败: ' + (error instanceof Error ? error.message : ''), data: null })
        }
    }

    app.post('/api/check', handleCheck)
    app.get('/api/check', handleCheck)

    app.post('/api/addrec', (req, res) => {
        try {
            const data = req.body || {}
            const requiredFields = ['domain', 'registrar', 'registrar_date', 'expiry_date', 'service_type', 'status']
            for (const field of requiredFields) {
                if (!data[field]) {
                    return res.status(400).json({ status: 400, message: `${field} 是必填字段`, data: null })
                }
            }
            const domainRegex = /^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/
            if (!domainRegex.test(data.domain)) {
                return res.status(400).json({ status: 400, message: '域名格式不正确', data: null })
            }
            const dateRegex = /^\d{4}-\d{2}-\d{2}$/
            if (!dateRegex.test(data.registrar_date) || !dateRegex.test(data.expiry_date)) {
                return res.status(400).json({ status: 400, message: '日期格式不正确，应为 YYYY-MM-DD', data: null })
            }
            const existing = readRow('SELECT id, cert_status, cf_hosted, cf_account_id FROM domains WHERE domain = ?', [data.domain])
            if (existing) {
                const nextCertStatus = data.cert_status || (data.service_type === '伪装网站' ? '申请中' : '无')
                run(`UPDATE domains 
                    SET service_type = ?, status = ?, cert_status = ?, memo = ?, cf_hosted = ?, cf_account_id = ?
                    WHERE domain = ?`, [
                    data.service_type,
                    data.status,
                    nextCertStatus,
                    data.memo,
                    Number(data.cf_hosted || 0),
                    data.cf_account_id || null,
                    data.domain
                ])
                const updatedDomain = readRow('SELECT * FROM domains WHERE domain = ?', [data.domain])
                persistDb()
                if (existing.cert_status !== nextCertStatus) {
                    notifyCertStatusChange({ type: 'cert_status_updated', domain: data.domain, status: nextCertStatus })
                }
                return res.json({ status: 200, message: '更新成功', data: updatedDomain })
            }
            const initialCertStatus = data.cert_status || (data.service_type === '伪装网站' ? '申请中' : '无')
            run(`INSERT INTO domains (
                domain, registrar, registrar_link, registrar_date,
                expiry_date, service_type, status, cert_status, tgsend, st_tgsend, cf_hosted, cf_account_id, memo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                data.domain,
                data.registrar,
                data.registrar_link || '',
                data.registrar_date,
                data.expiry_date,
                data.service_type,
                data.status,
                initialCertStatus,
                data.tgsend ?? 1,
                data.st_tgsend ?? 0,
                Number(data.cf_hosted || 0),
                data.cf_account_id || null,
                data.memo || ''
            ])
            const newDomain = readRow('SELECT * FROM domains WHERE id = last_insert_rowid()')
            persistDb()
            notifyCertStatusChange({ type: 'cert_status_updated', domain: data.domain, status: initialCertStatus })
            return res.json({ status: 200, message: '创建成功', data: newDomain })
        } catch (error) {
            return res.status(500).json({ status: 500, message: error instanceof Error ? error.message : '创建域名失败', data: null })
        }
    })

    app.get('/api/debug-check', async (req, res) => {
        const domain = req.query.domain
        if (!domain) {
            return res.status(400).json({ error: 'Missing domain parameter' })
        }
        const results = []
        try {
            const controller = new AbortController()
            const timeoutId = setTimeout(() => controller.abort(), 10000)
            const startTime = Date.now()
            const response = await fetch(`https://${domain}`, {
                method: 'GET',
                redirect: 'follow',
                signal: controller.signal,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'close',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1'
                }
            })
            clearTimeout(timeoutId)
            const duration = Date.now() - startTime
            const text = await response.text()
            const headers = {}
            response.headers.forEach((value, key) => {
                headers[key] = value
            })
            results.push({
                protocol: 'HTTPS',
                status: response.status,
                statusText: response.statusText,
                ok: response.ok,
                duration: `${duration}ms`,
                headers,
                body: text.substring(0, 1000),
                isOnline: response.status < 520
            })
        } catch (error) {
            results.push({
                protocol: 'HTTPS',
                error: error instanceof Error ? error.message : String(error),
                name: error instanceof Error ? error.name : 'UnknownError'
            })
        }
        try {
            const controller = new AbortController()
            const timeoutId = setTimeout(() => controller.abort(), 10000)
            const startTime = Date.now()
            const response = await fetch(`http://${domain}`, {
                method: 'GET',
                redirect: 'follow',
                signal: controller.signal,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    'Connection': 'close'
                }
            })
            clearTimeout(timeoutId)
            const duration = Date.now() - startTime
            const headers = {}
            response.headers.forEach((value, key) => {
                headers[key] = value
            })
            results.push({
                protocol: 'HTTP',
                status: response.status,
                statusText: response.statusText,
                ok: response.ok,
                duration: `${duration}ms`,
                headers,
                isOnline: response.status < 520
            })
        } catch (error) {
            results.push({
                protocol: 'HTTP',
                error: error instanceof Error ? error.message : String(error),
                name: error instanceof Error ? error.name : 'UnknownError'
            })
        }
        return res.json({
            domain,
            timestamp: new Date().toISOString(),
            results
        })
    })

    app.use(express.static(path.join(__dirname, '..', 'dist')))

    app.get('*', (req, res) => {
        return res.sendFile(path.join(__dirname, '..', 'dist', 'index.html'))
    })

    app.listen(port, () => {
    })
}

startServer()
