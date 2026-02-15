![Domain-Support](https://look.pics.cloudns.ch/img/cover2.png)

<div align="center">

# Domains-Support

</div>



一个基于 Node.js + SQLite 的域名管理系统，帮助您轻松管理和监控多个域名的状态、到期时间等信息。需配合serv00或者[DScheck](https://github.com/frankiejun/DScheck)使用.

## 视频教学  
[Domains-Support 配合SERV00/hostUNO，堪称养域名神器！](https://youtu.be/gPJ7tjRKnzo?si=X7zD4eiW7AyeXshQ)

## 功能特点

- 域名管理：添加、编辑、删除、导入、导出域名信息
- 状态监控：自动检查域名在线状态
- 到期提醒：设置域名到期提醒时间
- 多注册商支持：支持多个域名注册商的信息记录
- Telegram 通知：支持通过 Telegram 发送到期提醒
- 响应式设计：支持移动端和桌面端访问
- 安全认证：基于用户名密码的访问控制

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

## 快速开始

### 前置要求

- Node.js 18+ 环境

### 安装步骤

1. 克隆仓库并安装依赖
   ```
   git clone <your-repo-url>
   cd domains-support
   npm install
   ```

2. 构建前端
   ```
   npm run build
   ```

3. 配置环境变量
   ```
   USER=your_username
   PASS=your_password
   API_TOKEN=your_api_token
   PORT=3000
   DB_PATH=/path/to/domains.sqlite
   ```

4. 启动服务
   ```
   npm run start
   ```

默认会在 `data/domains.sqlite` 创建数据库文件，`PORT` 默认为 3000。

## API 文档

### 1. 域名检查 API

**端点**: `/api/check`
**方法**: POST
**认证**: 需要 API Token（通过 Bearer Token 或查询参数）

**请求体 (JSON)**:
当使用 `POST` 方法时，请求体必须为 JSON 格式，包含一个 `domains` 数组。
```json
{
    "domains": [
        "a.com",
        "b.com",
        "c.com"
    ]
}
```
**说明**:
- `domains`: 包含要检查的域名字符串数组。程序将只对这些域名进行检查，并确保它们在数据库中存在且启用了通知。

认证方式： 

 Bearer Token：`Authorization: Bearer your_token`

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
**注意**: 离线和过期通知现在会进行汇总，以减少子请求数量。通知详情将通过 Telegram 或微信发送。

### 2. 域名新增 API

**端点**: `/api/addrec`
**方法**: POST
**认证**: 需要 API Token

响应：
```json
{
    "status": 200,
    "message": "获取成功",
    "data": [
        {
            "id": 1,
            "domain": "example.com",
            "registrar": "Cloudflare",
            "registrar_link": "https://cloudflare.com",
            "registrar_date": "2023-01-01",
            "expiry_date": "2024-01-01",
            "service_type": "网站",
            "status": "在线",
            "memo": "主站"
        }
    ]
}
```

## 配置说明

### 环境变量

- `USER`: 管理员用户名
- `PASS`: 管理员密码
- `API_TOKEN`: API 访问令牌

## 调度器

建议使用系统的定时任务或 [DScheck](https://github.com/frankiejun/DScheck) 定期调用 `/api/check`。

## 贡献指南

欢迎提交 Issue 和 Pull Request！

## 许可证

本项目基于 MIT 许可证开源 - 查看 [LICENSE](LICENSE) 文件了解更多详情。

## 赞助

| 赞助人                                                                                                                 | 赞助方式                 | 备注 |
| ---------------------------------------------------------------------------------------------------------------------- | ------------------------ | ---- |
| [ZMTO](https://www.zmto.com/) | 免费提供服务器 | - |

## 作者

饭奇骏 ([@frankiejun](https://github.com/frankiejun))

