# HTML 托管面板

![Node](https://img.shields.io/badge/node-%E2%89%A520-339933?logo=node.js\&logoColor=white)

![Express](https://img.shields.io/badge/express-4.x-black)

![WebAuthn](https://img.shields.io/badge/auth-Passkey%20%2F%20WebAuthn-4f46e5)

![Docker](https://img.shields.io/badge/deploy-Docker%20Compose-2496ED?logo=docker\&logoColor=white)

![License](https://img.shields.io/badge/license-MIT-blue)

把 AI Agent 生成的 HTML 文件拖进浏览器，立刻得到可访问的链接——不用再翻面板文件管理器。

一个**单文件、零构建**的自托管 HTML 静态页托管服务：后端只有一个 `server.js`，前端页面内嵌其中，配上 Docker Compose 即可在任意 VPS / NAS 上一键跑起来。

## ✨ 功能特性

- **拖上去就能用**：拖拽 / 点击 / `Ctrl+V` 粘贴上传，支持多文件、`.html` / `.htm` / `.svg`
- **秒开直链**：单文件上传后自动在新标签页打开；直链格式 `https://你的域名/f/文件名.html`，**无需登录**，方便直接分享
- **Passkey 免密登录**：指纹 / 人脸 / Windows Hello PIN 一按即进，不用记密码；支持多设备，面板内可添加 / 查看 / 删除已注册密钥
- **文件管理**：列表搜索、打开、复制链接、删除；中文文件名安全保留，重名自动加序号
- **安全为先**：托管页 CSP sandbox 隔离、写接口 Origin 校验、首次注册口令闸门、内存限流、非 root 容器——已通过三轮独立安全审查（见 [security-review.md](security-review.md)）

## 🚀 快速开始（Docker Compose，推荐）

前置条件：一台有 Docker 的服务器 + 一个已解析的域名。**HTTPS 是必需的**（Passkey 的硬性要求，localhost 除外）。

```bash
git clone <本仓库地址>
cd html-host-panel
```

1. **编辑 `docker-compose.yml`**，把 `SETUP_TOKEN=please-change-me` 改成你自己的随机强口令（这是首次注册的闸门，防止服务刚上线被别人抢注）
2. 生产环境建议同时在 compose 里取消注释，固定你的域名：
   ```yaml
   - RP_ID=html.example.com
   - ORIGIN=https://html.example.com
   ```
3. 启动：
   ```bash
   docker compose up -d --build
   ```
4. 用反向代理（1Panel / Nginx Proxy Manager / Caddy 均可）把域名代理到 `http://127.0.0.1:3000` 并开启 HTTPS
5. 浏览器打开 `https://你的域名`，输入注册口令，按系统提示录入指纹 / 人脸 / PIN——完成

## 🔧 不用 Docker（Node 直跑）

```bash
npm install --omit=dev
SETUP_TOKEN=你的口令 PORT=3000 node server.js
```

要求 Node.js ≥ 20。

## ⚙️ 环境变量

| 变量                 | 默认值         | 说明                             |
| ------------------ | ----------- | ------------------------------ |
| `PORT`             | `3000`      | 监听端口                           |
| `SETUP_TOKEN`      | 空           | 首次注册口令；**不设则首个密钥谁都能注册，强烈建议设置** |
| `UPLOAD_DIR`       | `./uploads` | 上传文件存放目录                       |
| `DATA_DIR`         | `./data`    | 通行密钥凭证目录                       |
| `RP_NAME`          | `HTML 托管面板` | 系统录入通行密钥时显示的名称                 |
| `RP_ID` / `ORIGIN` | 自动探测        | 生产环境建议固定设置为你的域名，不依赖请求头         |

## 🔐 关于通行密钥

- 通行密钥**绑定域名且要求 HTTPS**（localhost 除外）。请用最终访问的域名注册；换域名后旧密钥失效，需重新注册
- `SETUP_TOKEN` 只在**还没有任何密钥**时生效；注册完第一个密钥后，添加新设备必须先登录，口令不再使用
- 凭证保存在 `data/credentials.json`（compose 已挂载到宿主机），删掉它等于重置所有密钥
- Windows 上走 Windows Hello（PIN / 指纹 / 人脸）；也可以选「手机扫码」把手机当密钥用

## 🛡️ 安全设计

| 威胁              | 对策                                                                                     |
| --------------- | -------------------------------------------------------------------------------------- |
| 托管 HTML 窃取面板登录态 | `/f/` 响应带 `Content-Security-Policy: sandbox`，页面运行在独立不透明源，拿不到会话 cookie，调不动面板接口          |
| CSRF / 跨站调用     | 面板写接口强制校验 `Origin` 必须存在且等于自身 host；cookie `HttpOnly + SameSite=Lax`，HTTPS 下自动加 `Secure` |
| 服务上线被抢注         | `SETUP_TOKEN` 首次注册闸门，常量时间比较防时序侧信道                                                      |
| 暴力破解 / 接口滥用     | WebAuthn 与上传接口内存限流（20 / 30 次每分钟），挑战单次使用且 5 分钟过期                                        |
| 磁盘放大攻击          | 类型白名单 + 单文件 50MB + 单次请求 150MB 上限                                                       |
| 容器逃逸            | 容器内以非 root 用户 `node` 运行（entrypoint 修正卷属主后立即降权）                                         |
| 登录绕过            | 登录强制用户验证（`userVerification: required`）；会话 30 天服务端过期                                    |

完整的威胁建模与三轮审计记录见 [security-review.md](security-review.md)（含修复前后的逐项验证）。

## 📁 项目结构

```
├── server.js              # 全部后端逻辑 + 内嵌前端页面(单文件,零构建)
├── package.json
├── package-lock.json
├── Dockerfile             # node:22-alpine,非 root 运行
├── docker-entrypoint.sh   # 修正挂载卷属主后降权为 node
├── docker-compose.yml
├── LICENSE                # MIT
├── security-review.md     # 三轮安全审查报告
├── uploads/               # 上传文件(运行时生成,已挂载)
└── data/                  # 通行密钥凭证(运行时生成,已挂载)
```

## 🧰 技术栈

- **后端**：Node.js + Express 4 + [SimpleWebAuthn](https://simplewebauthn.dev/) v10 + multer 2
- **前端**：无框架、无构建——登录页与面板页直接内嵌在 `server.js` 中，nonce-based CSP
- **部署**：Docker（`node:22-alpine`）+ Docker Compose

## ⚠️ 部署前自查清单

- [ ] `SETUP_TOKEN` 已改为随机强口令（不要留在默认值）
- [ ] 反代已开启 HTTPS（Passkey 必需）
- [ ] 生产环境已固定 `RP_ID` / `ORIGIN`
- [ ] `uploads/` 与 `data/` 已挂载到宿主机（compose 默认已配置）

## 📄 License

本项目基于 [MIT License](LICENSE) 开源。
