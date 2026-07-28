![Domain-Support](https://look.pics.cloudns.ch/img/cover2.png)

<div align="center">

# Domains-Support

</div>

一个基于 Node.js + SQLite 的域名管理系统，帮助您轻松管理和监控多个域名的状态、到期时间等信息。VPS 版本在此基础上增加了 SSL 证书自动申请、Nginx 站点绑定、Cloudflare DNS 自动管理等功能。

## 视频教学
[Domains-Support 配合SERV00/hostUNO，堪称养域名神器！](https://youtu.be/gPJ7tjRKnzo?si=X7zD4eiW7AyeXshQ)

## 功能特点

### 基础功能
- 域名管理：添加、编辑、删除、导入、导出域名信息
- 状态监控：自动检查域名在线状态
- 到期提醒：设置域名到期提醒时间
- 多注册商支持：支持多个域名注册商的信息记录
- Telegram / 微信通知：支持通过 Telegram 或微信发送到期提醒
- 响应式设计：支持移动端和桌面端访问
- 安全认证：基于用户名密码的访问控制

### VPS 版新增功能
- **SSL 证书自动申请**：集成 Certbot，域名设为"伪装网站"后自动申请 Let's Encrypt / ZeroSSL 证书
- **Nginx 站点自动绑定**：申请证书时自动生成 Nginx 配置并 reload
- **Cloudflare DNS 自动管理**：绑定 CF 账号后自动添加 A/AAAA 记录指向服务器
- **伪装网站模板**：内置 6 套网站模板（樱花博客、圣诞贺卡、简历、人力资源、游戏门户、教育网站）
- **证书状态实时推送**：通过 SSE 实时显示证书申请进度
- **CF 多账号管理**：支持添加多个 Cloudflare 账号，按域名分配
- **自定义网站模板**：支持上传自定义 HTML 文件作为伪装网站
- **批量证书续约脚本**：`sh/cert_renew.sh` 批量续约指定域名的证书
- **CF DNS IP 替换脚本**：`sh/cf_dns_ip_replace.sh` 批量替换 Cloudflare A 记录中的 IP

## 界面展示
![alt text](image/image.png)

## 批量导入说明

系统支持通过JSON文件批量导入域名数据。导入格式如下：

```json
[
  {
    "domain": "example.com",
    "registrar": "Cloudflare",
    "registrar_link": "https://dash.cloudflare.com",
    "registrar_date": "2023-01-01",
    "expiry_date": "2024-01-01",
    "service_type": "网站",
    "memo": "主站"
  },
  {
    "domain": "example.org",
    "registrar": "Namecheap",
    "registrar_link": "https://www.namecheap.com",
    "registrar_date": "2023-02-15",
    "expiry_date": "2024-02-15",
    "service_type": "API服务",
    "memo": "API文档站点"
  }
]
```

### 导入字段说明

- `domain`：域名（必填）
- `registrar`：注册商名称
- `registrar_link`：注册商管理链接
- `registrar_date`：注册日期，格式为YYYY-MM-DD
- `expiry_date`：到期日期，格式为YYYY-MM-DD
- `service_type`：服务类型
- `memo`：备注信息

导入时，系统会自动验证数据格式，并给出成功和失败的详细信息。

## 安装部署

### 方式一：一键脚本部署（推荐）

适用于全新 VPS，自动安装所有依赖（Nginx、Certbot、Node.js、PM2）。

```bash
git clone https://github.com/frankiejun/Domains-Support.git
cd Domains-Support
git checkout vps-beta

# 一键安装，参数为你的管理面板域名
bash ds.sh install your-domain.com
```

安装完成后访问 `https://your-domain.com/` 即可。

#### 脚本管理命令

```bash
# 更新到最新版本
bash ds.sh update

# 卸载
bash ds.sh uninstall
```

### 方式二：手动部署

#### 前置要求

- Node.js 18+
- Nginx
- Certbot（如需 SSL 证书自动申请）
- PM2（推荐，用于进程守护）

#### 安装步骤

1. 克隆仓库并切换分支
   ```bash
   git clone https://github.com/frankiejun/Domains-Support.git
   cd Domains-Support
   git checkout vps-beta
   ```

2. 安装依赖并构建前端
   ```bash
   npm install
   npm run build
   ```

3. 配置环境变量（创建 `.env` 文件）
   ```env
   # 必填
   USER=your_username
   PASS=your_password
   API_TOKEN=your_api_token

   # 可选
   PORT=3000
   DB_PATH=/path/to/domains.sqlite
   OP_LOG_PATH=/path/to/backend.log

   # SSL 证书申请相关（如需自动申请证书）
   CERTBOT_CMD=certbot certonly --webroot -w /var/www/Domains-Support --non-interactive --agree-tos --email your@email.com
   CERTBOT_CERTS_CMD=certbot certificates
   CERTBOT_TIMEOUT_MS=120000

   # ACME 服务器（推荐 ZeroSSL）
   #ACME_SERVER=https://acme-v02.api.letsencrypt.org/directory
   ACME_SERVER=https://acme.zerossl.com/v2/DV90
   ACME_EAB_KID=your_eab_kid
   ACME_EAB_HMAC_KEY=your_eab_hmac_key

   # Nginx 配置管理
   NGINX_SITES_DIR=/etc/nginx/conf.d
   NGINX_RELOAD_CMD=systemctl reload nginx

   # 伪装网站文件目录
   WEBSITES_DIR=/var/www/Domains-Support
   ```

4. 启动服务
   ```bash
   # 直接启动
   npm run start

   # 或使用 PM2 守护
   pm2 start server/index.js --name ds
   pm2 save
   ```

5. 配置 Nginx 反向代理（管理面板）
   ```nginx
   server {
       listen 443 ssl;
       server_name your-domain.com;

       ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

       location / {
           proxy_pass http://127.0.0.1:3000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_http_version 1.1;
           proxy_set_header Connection "";
           proxy_buffering off;
           proxy_cache off;
           proxy_read_timeout 3600s;
       }
   }
   ```

6. 配置 Certbot 自动续约 deploy hook
   ```bash
   mkdir -p /etc/letsencrypt/renewal-hooks/deploy
   cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh << 'EOF'
   #!/bin/bash
   systemctl reload nginx
   EOF
   chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
   ```

## 环境变量说明

### 基础配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `USER` | - | 管理员用户名（必填） |
| `PASS` | - | 管理员密码（必填） |
| `API_TOKEN` | - | API 访问令牌（必填） |
| `PORT` | `3000` | 服务监听端口 |
| `DB_PATH` | `data/domains.sqlite` | 数据库文件路径 |
| `OP_LOG_PATH` | `logs/backend.log` | 操作日志文件路径 |

### SSL 证书配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CERTBOT_CMD` | - | Certbot 申请证书命令，支持 `{domain}` 占位符 |
| `CERTBOT_CERTS_CMD` | `certbot certificates` | 列出已有证书的命令 |
| `CERTBOT_TIMEOUT_MS` | `120000` | Certbot 命令超时时间（毫秒） |
| `ACME_SERVER` | Let's Encrypt | ACME 服务器地址 |
| `ACME_EAB_KID` | - | ZeroSSL EAB KID |
| `ACME_EAB_HMAC_KEY` | - | ZeroSSL EAB HMAC Key |

### Nginx 配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `NGINX_SITES_DIR` | - | Nginx 站点配置目录（如 `/etc/nginx/conf.d`） |
| `NGINX_RELOAD_CMD` | - | Nginx reload 命令（如 `systemctl reload nginx`） |
| `WEBSITES_DIR` | `websites/` | 伪装网站 HTML 文件目录 |

### DNS 生效检测配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DNS_PROPAGATION_MAX_ATTEMPTS` | `30` | DNS 生效检测最大尝试次数 |
| `DNS_PROPAGATION_INTERVAL_MS` | `10000` | DNS 生效检测轮询间隔（毫秒） |

> 默认最长等待 5 分钟（30 次 × 10 秒），通过公共 DNS（1.1.1.1 / 8.8.8.8）检测。

## 证书申请工作流程

将域名设为"伪装网站"并绑定网站模板后，系统自动执行：

```
1. （若开启托管CF）通过 Cloudflare API 自动设置 DNS A/AAAA 记录指向本服务器
2. （若开启托管CF）等待 DNS 记录生效（通过公共 DNS 轮询检测，默认最长 5 分钟）
3. 写入 Nginx 配置（监听 80 端口，指向伪装网站）
4. 检查 DNS 是否指向本服务器
5. 检查证书是否已存在（含通配符证书匹配）
6. 调用 Certbot 申请证书（HTTP-01 验证）
7. 证书申请成功后更新状态
8. 下次 Nginx reload 时自动加载 SSL 配置
```

证书申请通过队列机制串行处理，每 60 秒检查一次队列，避免并发触发 rate limit。

> **说明**：开启"托管CF"后，DNS 记录由程序自动设置并等待生效，无需手动添加 A 记录。DNS 生效过程中证书状态显示为"等待DNS生效"。未开启"托管CF"时，需手动添加 A 记录指向本服务器 IP。

> **注意**：证书的自动续约由系统 certbot timer 负责，本项目只处理首次申请。请确保 `certbot.timer` 已启用，并配置了 deploy hook 以在续约后 reload nginx。

## 辅助脚本

### 批量续约证书

```bash
# 准备域名文件（一行一个域名）
cat > /tmp/domains.txt << 'EOF'
abc.pp.ua
efg.pp.ua
cja.pp.ua
EOF

# 模拟运行
./sh/cert_renew.sh --dry-run /tmp/domains.txt

# 正式续约
./sh/cert_renew.sh /tmp/domains.txt
```

### 批量替换 Cloudflare DNS A 记录 IP

编辑 `sh/cf_dns_ip_replace.sh` 开头的配置后运行：

```bash
./sh/cf_dns_ip_replace.sh
```

## API 文档

### 认证方式

| 类型 | 适用接口 | 说明 |
|------|---------|------|
| 登录认证 | 除 `/api/check`、`/api/addrec` 外的所有接口 | 登录后获取 Token，请求头 `Authorization: Bearer <token>` |
| API Token | `/api/check`、`/api/addrec` | 请求头 `Authorization: Bearer <API_TOKEN>` 或查询参数 `?token=<API_TOKEN>` |

### 域名管理

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/api/domains` | GET | 登录 | 获取域名列表 |
| `/api/domains` | POST | 登录 | 创建域名 |
| `/api/domains/:id` | PUT | 登录 | 更新域名 |
| `/api/domains/:id` | DELETE | 登录 | 删除域名 |
| `/api/domains/export` | GET | 登录 | 导出域名 |
| `/api/domains/import` | POST | 登录 | 导入域名 |
| `/api/domains/status` | POST | 登录 | 更新域名状态 |
| `/api/domains/check` | POST | 登录 | 检查单个域名 |
| `/api/domains/check-all` | POST | 登录 | 检查所有域名 |
| `/api/domains/cert-sync` | POST | 登录 | 同步证书状态 |

### 证书状态

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/api/events/cert-status` | GET (SSE) | 登录 | 证书状态实时推送 |

### 网站模板管理

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/api/websites` | GET | 登录 | 获取网站模板列表 |
| `/api/websites` | POST | 登录 | 创建网站模板 |
| `/api/websites` | DELETE | 登录 | 删除网站模板 |
| `/api/websites/files` | GET | 登录 | 获取可用 HTML 文件列表 |

### Cloudflare 账号管理

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/api/cf-accounts` | GET | 登录 | 获取 CF 账号列表 |
| `/api/cf-accounts` | POST | 登录 | 创建 CF 账号 |
| `/api/cf-accounts` | DELETE | 登录 | 删除 CF 账号 |

### 告警配置

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/api/alertconfig` | GET | 登录 | 获取告警配置 |
| `/api/alertconfig` | POST | 登录 | 保存告警配置 |

### 外部接口

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/api/check` | POST/GET | API Token | 域名到期检查与通知 |
| `/api/addrec` | POST | API Token | 外部新增域名 |

### 域名检查 API

**端点**: `/api/check`
**方法**: POST
**认证**: 需要 API Token

**请求体 (JSON)**:
```json
{
    "domains": [
        "a.com",
        "b.com",
        "c.com"
    ]
}
```

响应：
```json
{
    "status": 200,
    "message": "检查完成",
    "data": {
        "total_domains": 10,
        "notified_domains": [
            {
                "domain": "example.com",
                "remainingDays": 15,
                "expiry_date": "2024-03-01"
            }
        ]
    }
}
```

## 调度器

建议使用系统的定时任务或 [DScheck](https://github.com/frankiejun/DScheck) 定期调用 `/api/check`。

## 贡献指南

欢迎提交 Issue 和 Pull Request！

## 许可证

本项目基于 MIT 许可证开源 - 查看 [LICENSE](LICENSE) 文件了解更多详情。

## 赞助

| 赞助人 | 赞助方式 | 备注 |
| ------ | -------- | ---- |
| [ZMTO](https://www.zmto.com/) | 免费提供服务器 | - |

## 作者

饭奇骏 ([@frankiejun](https://github.com/frankiejun))
