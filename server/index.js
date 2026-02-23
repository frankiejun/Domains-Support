import { exec } from 'child_process'
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
}

const appendLog = (type, message) => {
    try {
        const dir = path.dirname(logFilePath)
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true })
        }
        const timestamp = new Date().toISOString()
        fs.appendFileSync(logFilePath, `[${timestamp}] [${type}] ${message}\n`)
    } catch {
    }
}

const readRows = (sql, params = []) => {
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
        tgsend INTEGER DEFAULT 0,
        st_tgsend INTEGER DEFAULT 1,
        site_id INTEGER,
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
    if (!hasColumn('domains', 'st_tgsend')) {
        run('ALTER TABLE domains ADD COLUMN st_tgsend INTEGER DEFAULT 1')
    }
    if (!hasColumn('domains', 'site_id')) {
        run('ALTER TABLE domains ADD COLUMN site_id INTEGER')
    }
    if (!hasColumn('alertcfg', 'wx_api')) {
        run('ALTER TABLE alertcfg ADD COLUMN wx_api TEXT')
    }
    if (!hasColumn('alertcfg', 'wx_token')) {
        run('ALTER TABLE alertcfg ADD COLUMN wx_token TEXT')
    }
    if (!hasColumn('alertcfg', 'auto_check_enabled')) {
        run('ALTER TABLE alertcfg ADD COLUMN auto_check_enabled INTEGER DEFAULT 0')
    }
    if (!hasColumn('alertcfg', 'auto_check_interval')) {
        run('ALTER TABLE alertcfg ADD COLUMN auto_check_interval INTEGER DEFAULT 30')
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

const requireAuth = (req, res, next) => {
    const token = getBearerToken(req)
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

const execCommand = (command) => new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
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

const getServerIp = () => {
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
    if (ipv6Global.length > 0) return ipv6Global[0]
    if (ipv4Public.length > 0) return ipv4Public[0]
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
    const config = [
        'server {',
        '    listen 80;',
        `    server_name ${domain};`,
        `    root ${resolved.root};`,
        `    index ${resolved.index};`,
        '    location / {',
        '        try_files $uri $uri/ =404;',
        '    }',
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

const applyCertbot = async (domain) => {
    const certbotCmd = process.env.CERTBOT_CMD
    if (!certbotCmd) {
        appendLog('certbot', `skip for ${domain}: CERTBOT_CMD not set`)
        return
    }
    const hasWildcard = await hasWildcardCertificate(domain)
    if (hasWildcard) {
        return
    }
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
        await execCommand(command)
        appendLog('certbot', `success for ${domain}`)
    } catch (error) {
        appendLog('certbot', `failed for ${domain}: ${error instanceof Error ? error.message : String(error)}`)
        throw error
    }
}

const applyWebsiteBinding = async (domain, siteId) => {
    appendLog('nginx', `apply binding ${domain} site ${siteId}`)
    const site = readRow('SELECT * FROM websitecfg WHERE id = ?', [siteId])
    if (!site) {
        appendLog('nginx', `skip binding for ${domain}: site not found ${siteId}`)
        return
    }
    await writeNginxConfig(domain, site.filename)
    await applyCertbot(domain)
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
    const config = readRow('SELECT * FROM alertcfg LIMIT 1')
    if (!config) {
        return { total: 0, notified: 0 }
    }
    const domains = readRows('SELECT domain, expiry_date, tgsend, st_tgsend FROM domains WHERE tgsend = 1 OR st_tgsend = 1')
    if (domains.length === 0) {
        return { total: 0, notified: 0 }
    }
    const results = await runWithConcurrency(domains, 10, async (domain) => {
        const remainingDays = calculateRemainingDays(domain.expiry_date)
        const isOnline = await checkDomainStatus(domain.domain)
        const status = isOnline ? '在线' : '离线'
        run('UPDATE domains SET status = ? WHERE domain = ?', [status, domain.domain])
        return { ...domain, status, remainingDays }
    })
    const offlineDomains = results.filter((d) => d.status === '离线' && d.st_tgsend === 1)
    const expiringDomains = results.filter((d) => d.remainingDays <= config.days && d.tgsend === 1)
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
        } catch (error) {
        }
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
    } else {
        db = new SQL.Database()
    }
    ensureSchema()
    const initialConfig = readRow('SELECT * FROM alertcfg LIMIT 1')
    applyAutoCheckConfig(initialConfig)
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
            run(`INSERT INTO domains (
                domain, registrar, registrar_link, registrar_date,
                expiry_date, service_type, status, tgsend, st_tgsend, site_id, memo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                data.domain,
                data.registrar,
                data.registrar_link || '',
                data.registrar_date,
                data.expiry_date,
                data.service_type,
                data.status,
                data.tgsend ?? 1,
                data.st_tgsend ?? 0,
                data.site_id || null,
                data.memo || ''
            ])
            const created = readRow('SELECT * FROM domains WHERE id = last_insert_rowid()')
            persistDb()
            res.json({ status: 200, message: '创建成功', data: created })
            if (data.service_type === '伪装网站' && data.site_id) {
                runAsyncTask(`apply binding ${data.domain}`, () => applyWebsiteBinding(data.domain, data.site_id))
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
            const existing = readRow('SELECT * FROM domains WHERE id = ?', [id])
            if (!existing) {
                return res.status(404).json({ status: 404, message: '域名不存在', data: null })
            }
            run(`UPDATE domains SET
                domain = ?,
                registrar = ?,
                registrar_link = ?,
                registrar_date = ?,
                expiry_date = ?,
                service_type = ?,
                status = ?,
                tgsend = ?,
                st_tgsend = ?,
                site_id = ?,
                memo = ?
            WHERE id = ?`, [
                data.domain,
                data.registrar,
                data.registrar_link || '',
                data.registrar_date,
                data.expiry_date,
                data.service_type,
                data.status,
                data.tgsend || 0,
                data.st_tgsend ?? 1,
                data.service_type === '伪装网站' ? data.site_id : null,
                data.memo || '',
                id
            ])
            const updated = readRow('SELECT * FROM domains WHERE id = ?', [id])
            persistDb()
            res.json({ status: 200, message: '更新成功', data: updated })
            if (existing.service_type === '伪装网站' && data.service_type !== '伪装网站') {
                runAsyncTask(`remove binding ${existing.domain}`, () => removeWebsiteBinding(existing.domain))
            }
            if (existing.service_type === '伪装网站' && data.service_type === '伪装网站' && existing.domain !== data.domain) {
                runAsyncTask(`remove binding ${existing.domain}`, () => removeWebsiteBinding(existing.domain))
            }
            if (data.service_type === '伪装网站' && data.site_id) {
                runAsyncTask(`apply binding ${data.domain}`, () => applyWebsiteBinding(data.domain, data.site_id))
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

    app.get('/api/domains/export', (req, res) => {
        try {
            const rows = readRows('SELECT domain, registrar, registrar_link, registrar_date, expiry_date, service_type, status, memo, tgsend, st_tgsend, site_id FROM domains')
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
            for (const domain of domains) {
                try {
                    if (!domain.domain) {
                        throw new Error('域名字段缺失')
                    }
                    const existing = readRow('SELECT id FROM domains WHERE domain = ?', [domain.domain])
                    if (existing) {
                        run(`UPDATE domains SET 
                            registrar = ?, 
                            registrar_link = ?, 
                            registrar_date = ?, 
                            expiry_date = ?, 
                            service_type = ?, 
                            status = ?, 
                            memo = ?, 
                            tgsend = ?, 
                            st_tgsend = ?,
                            site_id = ?
                        WHERE domain = ?`, [
                            domain.registrar || '',
                            domain.registrar_link || '',
                            domain.registrar_date || '',
                            domain.expiry_date || '',
                            domain.service_type || '',
                            domain.status || '离线',
                            domain.memo || '',
                            domain.tgsend || 0,
                            domain.st_tgsend || 0,
                            domain.site_id || null,
                            domain.domain
                        ])
                    } else {
                        run(`INSERT INTO domains 
                            (domain, registrar, registrar_link, registrar_date, expiry_date, service_type, status, memo, tgsend, st_tgsend, site_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                            domain.domain,
                            domain.registrar || '',
                            domain.registrar_link || '',
                            domain.registrar_date || '',
                            domain.expiry_date || '',
                            domain.service_type || '',
                            domain.status || '离线',
                            domain.memo || '',
                            domain.tgsend || 0,
                            domain.st_tgsend || 0,
                            domain.site_id || null
                        ])
                    }
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
            const existing = readRow('SELECT id FROM domains WHERE domain = ?', [data.domain])
            if (existing) {
                run(`UPDATE domains 
                    SET service_type = ?, status = ?, memo = ?
                    WHERE domain = ?`, [
                    data.service_type,
                    data.status,
                    data.memo,
                    data.domain
                ])
                const updatedDomain = readRow('SELECT * FROM domains WHERE domain = ?', [data.domain])
                persistDb()
                return res.json({ status: 200, message: '更新成功', data: updatedDomain })
            }
            run(`INSERT INTO domains (
                domain, registrar, registrar_link, registrar_date,
                expiry_date, service_type, status, tgsend, st_tgsend, memo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                data.domain,
                data.registrar,
                data.registrar_link || '',
                data.registrar_date,
                data.expiry_date,
                data.service_type,
                data.status,
                data.tgsend ?? 1,
                data.st_tgsend ?? 0,
                data.memo || ''
            ])
            const newDomain = readRow('SELECT * FROM domains WHERE id = last_insert_rowid()')
            persistDb()
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
