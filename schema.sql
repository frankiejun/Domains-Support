drop table domains;

-- 创建域名表
CREATE TABLE IF NOT EXISTS domains (
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
    tgsend  INTEGER DEFAULT 0,
    st_tgsend INTEGER DEFAULT 1,
    site_id INTEGER,
    memo TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
); 

--通知配置表
CREATE TABLE IF NOT EXISTS alertcfg (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_token TEXT NOT NULL,
    tg_userid TEXT NOT NULL,
    wx_api TEXT,
    wx_token TEXT,
    auto_check_enabled INTEGER DEFAULT 0,
    auto_check_interval INTEGER DEFAULT 30,
    days INTEGER NOT NULL DEFAULT 30,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
); 
CREATE TABLE IF NOT EXISTS websitecfg (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    filename TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
