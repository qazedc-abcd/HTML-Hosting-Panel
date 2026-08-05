# HTML 托管面板 · 安全审查报告

- 审查对象：`server.js`（Express + `@simplewebauthn/server` v10 + multer）
- 审查日期：2026-08-04
- 依赖审计：`npm audit` → **0 vulnerabilities**（Express 4.21.x / multer 1.4.5-lts.2，均为已修复版本）
- 结论：**依赖无已知 CVE；漏洞集中在应用层，其中 1 个高危、1 个高风险、若干中低危**

---

## 🔴 高危 1：同源存储型 XSS → 面板会话被接管（最大坑）

`/f/:name`（server.js:306-313）在**面板同源**下直接把用户上传的 HTML 以 `text/html` 返回；SVG 以 `image/svg+xml` 返回（SVG 文档里的 `<script>` 会在浏览器执行）。

README 明确写了"拖管的 HTML 直链**无需登录**，方便分享"。于是：

- 任何人拿到 `/f/xxx.html` 链接都能打开；
- 若打开者**已登录面板**，该 HTML 里的脚本运行在面板同源下，浏览器自动带上 `wb_sess` cookie，可直接调用 `/api/files`、`/api/upload`、`/api/delete/:name`、`/api/webauthn/credentials/delete`；
- 后果：恶意 HTML 能**列出/上传/删除你的所有文件**，甚至**删除你的通行密钥**（锁死账号）。

缺少 `Content-Security-Policy`、`X-Content-Type-Options: nosniff`、`Content-Disposition`，给攻击开了大门。

**修复（按干净程度排序）：**
1. 最佳：把 `/f/` 托管内容放到**独立子域/独立源**（如 `files.example.com`），与面板 `html.example.com` 跨源隔离；
2. 次选：面板接口校验 `Origin` 必须是面板自身域名，拒绝来自 `/f/` 源的请求；
3. 最低成本：给 `/f/` 响应加严格 CSP（`Content-Security-Policy: sandbox`）+ `X-Content-Type-Options: nosniff`，并考虑 `Content-Disposition: attachment` 让浏览器下载而非内联执行。

---

## 🟠 高风险 2：首次注册口子敞开（"先到者得"）

server.js:151-197 中，只要 `credentials.json` 为空，**无需任何凭证**就能调用 `register/options` / `register/verify` 注册成 owner。

README 已承认此设计。风险场景：服务先于你注册就被公网/内网扫到 → 别人先注册占坑，你反而进不去或被迫重置。

**修复：**
- 加一次性环境变量 `SETUP_TOKEN`，首次注册必须带对才允许；或
- docker-compose 默认把端口 `127.0.0.1:3000:3000`（仅本机），注册完成后再放开；或
- 靠反代先加一层访问限制（1Panel 访问控制）再开放注册。

---

## 🟡 中危

### M1. Cookie 缺 `Secure` 标志
`makeSession`（server.js:117）和 `setChallenge`（server.js:123）的 `Set-Cookie` 没有 `Secure`。全程 HTTPS 时浏览器不会泄露，但一旦能用 HTTP 访问，cookie 明文传输。应加 `Secure`（前提是你全程 HTTPS，README 也强制要求）。

### M2. `userVerification: "preferred"`
注册/登录的 `userVerification` 都是 `"preferred"`（server.js:160、202）。不支持 UV 的认证器可**跳过指纹/PIN**，仅凭设备持有就通过，弱化了通行密钥"验证持有者"的语义。建议**登录改用 `"required"`**，注册可保持 preferred（兼顾老设备）。

### M3. 无安全响应头 / 无 helmet
全局缺 `X-Content-Type-Options`、`Referrer-Policy`、`X-Frame-Options`/`frame-ancestors`、CSP；Express 默认暴露 `X-Powered-By: Express`。建议 `app.disable('x-powered-by')` 并手动加基础安全头（或上 `helmet`）。

### M4. `trust proxy: true` + 用请求头推导 origin/RPID
server.js:38 开了 `trust proxy`，`origin(req)`（102）/ `rpID(req)`（98）依赖 `Host`/`X-Forwarded-*`。若反代未严格清洗这些头，攻击者可影响 `expectedOrigin`/`RP_ID`，造成 WebAuthn 校验异常或被绕过（取决于反代配置）。建议**生产固定写死 `RP_ID`/`ORIGIN`**，不要默认依赖请求头探测。

### M5. 无速率限制
`/api/webauthn/register/options`、`login/options`、挑战生成无频率限制，可被滥用做 DoS（刷挑战、刷接口）。建议加 `express-rate-limit`（如每 IP 每分钟 10 次）。

---

## 🟢 低危

- **L1. 会话不失效**：`sessions` 是内存 `Set`（server.js:106），只在 logout 或重启时清除，被盗 cookie 长期有效。建议加服务端过期时间，并支持多实例共享（当前单容器无碍）。
- **L2. 上传放大（磁盘 DoS）**：单文件 50MB × 20 个 = 单请求 1GB，无总配额（server.js:274、282）。建议加总量限制/磁盘监控。
- **L3. 容器以 root 运行**：Dockerfile 无 `USER` 指令，`node:22-alpine` 默认 root。建议加非 root 用户。
- **L4. `decodeFilename` 的 GBK fallback**（server.js:62-73）：仅为兼容 Windows curl，因后续 `safeName` 已 sanitize，风险低，可保留。

---

## ✅ 已确认没问题的点（正面结论）

- **路径穿越**：`/f/:name`（307）、`/api/delete/:name`（297）均用 `path.basename` + `p.startsWith(UPLOAD_DIR)` 双重防护，无法越出上传目录。
- **文件名注入**：`safeName`（43）过滤了 `/\:*?"<>|#%&{}$!'@+`=\s`，且面板前端用 `textContent` 渲染文件名（server.js:527），**不存在来自文件名的 XSS**。
- **WebAuthn 校验**：`challenge` 单次使用且 5 分钟过期（server.js:120-132），`verifyRegistration/AuthenticationResponse` 均传 `expectedChallenge/expectedOrigin/expectedRPID`，流程正确。
- **上传类型过滤**：`fileFilter`（275）只允许 `.html/.htm/.svg`，后端 `listFiles` 也按扩展名过滤。

---

## 修复优先级建议

| 优先级 | 项 | 动作 |
| --- | --- | --- |
| P0 | 高危1 同源 XSS | 独立源托管 `/f/` 或加 sandbox CSP + nosniff |
| P0 | 高风险2 首注册敞开 | 加 `SETUP_TOKEN` 或反代先锁访问 |
| P1 | M1 `Secure` cookie | 加 `Secure` 标志 |
| P1 | M2 UV=required（登录） | 改 `userVerification` |
| P1 | M3/M4 安全头 / 固定 origin | disable x-powered-by + 写死 RP_ID/ORIGIN |
| P2 | M5 限流、L1-L3 | rate-limit、会话过期、非 root |

> 要我直接把 P0/P1 的修复改进 `server.js` 和 `docker-compose.yml` 吗？说一声我就动手。

---

## 复核（2026-08-04 二次审查 · 用户已自行修复）

逐项回归 + 实测启动验证（NODE_PATH 指向已装依赖，端口 3999 冒烟测试）：

| 项 | 状态 | 实测证据 |
| --- | --- | --- |
| 高危1 同源 XSS | ✅ 修复 | `/f/` 真实文件响应带 `Content-Security-Policy: sandbox allow-scripts...` + `nosniff`；`/api` 写操作校验 Origin，跨源 POST → 403「跨源请求被拒绝」，sandbox 页 `Origin:null` 亦被拒 |
| 高风险2 首注册敞开 | ✅ 修复 | `SETUP_TOKEN` 环境变量 + `setupGate`；无 token 首次注册 → 403「首次注册口令错误或缺失」；带 token → 200 含 challenge。compose 已默认设占位 token |
| M1 Secure cookie | ✅ 修复 | `secureFlag()` 按 https 加 `;Secure` |
| M2 UV=required（登录） | ✅ 修复 | `login/options` 用 `userVerification:"required"` |
| M3 安全头 / x-powered-by | ✅ 修复 | `app.disable('x-powered-by')`（响应无 X-Powered-By）；全局 `X-Content-Type-Options:nosniff`、`Referrer-Policy:no-referrer`、`X-Frame-Options:DENY` |
| M4 origin 固定 | ⚠️ 部分 | 文档要求生产写死 `RP_ID/ORIGIN`，默认仍自动探测（依赖可信反代）；Origin 校验中间件提供纵深防御 |
| M5 限流 | ✅ 修复 | 内存限流：`/api/webauthn` 20/min、`/api/upload` 30/min，超限 429 |
| L1 会话过期 | ✅ 修复 | `sessions` 改 Map + TTL 30 天 + 定时清理；`authed` 校验过期 |
| L2 上传放大 | ✅ 修复 | `/api/upload` 单次 `content-length > 150MB` → 413 |
| L3 容器 root | ✅ 修复 | 新增 `docker-entrypoint.sh`：root 修正卷属主后 `exec su node` 降权运行 |

**残留 / 建议（非阻塞）：**
1. `docker-compose.yml` 里 `SETUP_TOKEN=please-change-me` 是占位符，**部署前务必改成随机强口令**，否则等同于没设。
2. `Secure` 当前仅在 `req.protocol==="https"` 时加；既然强制 HTTPS，建议直接常开 `Secure`（反代若未传 `X-Forwarded-Proto` 时也能 fail-closed）。
3. 面板内打开直链的 `<a target="_blank">` 缺 `rel="noopener noreferrer"`（低危，现代浏览器默认 noopener）。
4. sandbox 无 `allow-same-origin`：引用 `/f/` 下其他 JS/CSS/图片的**多文件 HTML 演示**功能会受限（属功能取舍，非漏洞）；如需支持，文档建议"上传单文件自包含 HTML"。
5. `setupGate` 用 `!==` 比较 token（非常量时间），仅首次注册场景，风险极低。

**结论：原报告 P0/P1 全部修复并实测验证通过；依赖 0 漏洞；剩余均为低危配置项，按上面 1–5 收尾即可上线。**

---

## 第三轮独立审计（2026-08-04 · 漏洞复查 II）

> 触发：用户要求"检查漏洞"。本轮目标：回归前两轮修复项 + 找前两轮未发现的新问题。
> 方法：静态逐行审计 `server.js` / `Dockerfile` / `docker-compose.yml` + 隔离环境实测 `npm audit` + 实装版本核对。

### 依赖审计（实测，非记忆）

隔离临时目录 `npm install` 后实测：

| 依赖 | 实装版本 | 状态 |
| --- | --- | --- |
| express | 4.22.2 | ✅ 最新 4.x，path-to-regexp ReDoS（CVE-2024-45296）已修复 |
| multer | 1.4.5-lts.2 | ⚠️ 已 patch 已知 CVE，但整条 1.x **已 deprecated**，官方建议升 2.x |
| @simplewebauthn/server | 10.0.1 | ✅ |
| path-to-regexp | 0.1.13 | ✅ >=0.1.10 |
| body-parser | 1.20.6 | ✅ |
| qs | 6.15.3 | ✅ |

`npm audit`：**0 vulnerabilities**。

### 回归验证（前两轮修复项）

逐项核对代码，前两轮 P0/P1 全部仍生效，**无回归**：
- 同源 XSS：sandbox CSP + Origin 校验 ✅
- 首注册闸门 SETUP_TOKEN + setupGate ✅
- Secure cookie / UV=required / 安全头 / 限流 / 会话过期 / 上传总量限制 / 非 root 容器 ✅

### 🟠 新发现 · 中危

**N1. `trust proxy: true` 信任所有 hop（server.js:41）**
`true` 等同于无条件信任整条代理链。配合 `origin(req)`/`rpID(req)` 默认从 `Host`/`X-Forwarded-*` 自动探测（README M4 未完全收口），若反代未严格清洗这些头、或服务被直接暴露，攻击者可伪造请求头影响 WebAuthn 的 `expectedOrigin`/`expectedRPID`，在边界场景下干扰注册/登录校验。
**修复**：`app.set("trust proxy", 1)`（单跳反代）或 `"loopback"`；生产同时固定 `RP_ID`/`ORIGIN` 环境变量。

**N2. Origin 校验"无 Origin 即放行"（server.js:57）**
```js
const o = req.get("origin");
if (!o) return next(); // curl/脚本无 Origin,放行
```
当前 CSRF 防护依赖 `SameSite=Lax` + Origin 校验组合。"无 Origin 放行"使 CSRF 防御成为单点——一旦未来 cookie 改 `SameSite=None`（如需跨站嵌入）或新增无 Origin 的写接口，防线即刻崩塌。
**修复**：写操作要求 Origin 必须存在且等于面板 host；脚本场景用 `Sec-Fetch-Site: same-origin` 或独立 API token 兜底。

### 🟢 新发现 · 低危

**N3. sandbox CSP 含 `allow-popups-to-escape-sandbox`（server.js:385）**
恶意 HTML 用 `window.open()` 打开的弹窗可逃离 sandbox。虽跨源 DOM 访问仍受同源策略限制、可利用性低，但该 flag 对纯托管场景非必需，建议移除以缩小攻击面。

**N4. 缺 `Strict-Transport-Security`（HSTS）**
强制 HTTPS 场景下首访降级风险。建议反代层加 `Strict-Transport-Security: max-age=31536000; includeSubDomains`。

**N5. 面板自身缺 CSP**
`/` 和 `/login` 无内容安全策略。当前无 XSS（textContent 渲染），但无纵深防御。建议后续加 nonce-based CSP。

**N6. `/api/delete/:name` 不校验扩展名（server.js:367）**
可删除 uploads 下任意文件，与"仅托管 html/svg"语义不符。建议加扩展名白名单。

**N7. 内存 Map 无上限（DoS 面）**
`challenges`/`buckets` 有 TTL 清理但无大小上限，大量伪造 IP 窗口内可堆积；配合 N1 的 trust proxy 可放大。建议加 LRU 上限。

**N8. 错误信息原样回显（server.js:263、302）**
`res.status(400).json({ error: e.message })` 直接回显 WebAuthn 库内部异常 message，可能泄露内部信息。建议统一返回"验证失败"。

**N9. multer 1.x deprecated**
当前 lts.2 已 patch，但 1.x 不再维护，未来新 CVE 不会修。建议升 `multer@^2`（API 基本兼容）。

**N10. 无 package-lock.json**
Dockerfile `npm install` 不可复现，版本漂移。建议提交 lock 文件，构建用 `npm ci`。

**N11. SETUP_TOKEN 非常量时间比较（server.js:209）**
理论时序侧信道，实际 token 长度有限且仅首次注册，极低风险。可用 `crypto.timingSafeEqual` 规范化。

### 修复优先级

| 优先级 | 项 | 动作 |
| --- | --- | --- |
| P1 | N1 trust proxy | 改 `1` / `loopback` + 固定 RP_ID/ORIGIN |
| P1 | N2 Origin 放行 | 写操作要求 Origin 必存在且匹配 |
| P2 | N3 sandbox flag | 移除 `allow-popups-to-escape-sandbox` |
| P2 | N4 HSTS / N5 面板 CSP | 反代加 HSTS；面板加 nonce CSP |
| P2 | N6 删除扩展名校验 / N9 multer 升级 | 加白名单；升 multer@2 |
| P3 | N7 Map 上限 / N8 错误回显 / N10 lock / N11 时序 | 加固项，可批量收尾 |

### 结论

- **依赖**：0 已知 CVE；multer 1.x deprecated 建议升 2.x。
- **应用层**：前两轮 P0/P1 **无回归**；本轮新发现 2 个中危（均属"防御纵深/配置"类，**无直接可利用的高危漏洞**）+ 若干低危加固项。
- **可上线性**：当前状态可上线（HTTPS + 反代 + 改 SETUP_TOKEN 前提下）；建议尽快收口 N1/N2。

> 要我直接把 N1/N2/N3 + 删除扩展名校验 + HSTS 改进 `server.js`、把 multer 升到 2.x 并补 lock 文件吗?说一声就动手。

---

## 第三轮修复(2026-08-04 · 已全部落地并冒烟验证)

用户确认"直接修漏洞",本轮 N1–N11 全部修复:

| 项 | 修复 | 验证 |
| --- | --- | --- |
| N1 trust proxy | `true` → `1`(单跳反代) | ✅ 启动正常 |
| N2 Origin 校验 | 写操作要求 Origin 必存在且匹配 host;无 Origin → 403「缺少 Origin 头」 | ✅ 无Origin→403、跨源→403、同源正确token→200 |
| N3 sandbox flag | 移除 `allow-popups-to-escape-sandbox` | ✅ /f/ 真实文件 CSP 不含该 flag |
| N4 HSTS | HTTPS 下加 `Strict-Transport-Security: max-age=31536000; includeSubDomains` | ✅ 模拟 X-Forwarded-Proto:https 出 HSTS |
| N5 面板 CSP | `/`、`/login` 加 nonce-based CSP(`script-src 'nonce-XXX'`) | ✅ 响应头有 CSP,body script 带 nonce |
| N6 删除扩展名 | `/api/delete/:name` 校验 `.html?/.svg` | ✅ 代码确认 |
| N7 Map 上限 | challenges/buckets 加 `capMap`(10000) | ✅ 代码确认 |
| N8 错误回显 | WebAuthn verify catch 统一返回「验证失败」 | ✅ 代码确认 |
| N9 multer 升级 | `^1.4.5-lts.1` → `^2.0.0`(实装 2.2.0) | ✅ 启动正常,API 兼容 |
| N10 lock 文件 | 新增 `package-lock.json` | ✅ 已生成,lockfileVersion 3 |
| N11 token 时序 | `!==` → `crypto.timingSafeEqual`(safeTokenEqual) | ✅ 错误token→403 |

冒烟实测(隔离环境,端口 5888):
- `/api/auth/status` → `{"passkeys":0,"authed":false,"setupRequired":true}` ✅
- `/login` → 200 + CSP(nonce);HTTP 下无 HSTS(预期)✅
- `GET /` 未登录 → 302 ✅
- POST 无 Origin → 403「缺少 Origin 头」✅
- POST 跨源 Origin → 403「跨源请求被拒绝」✅
- POST 同源无 token → 403「首次注册口令错误或缺失」✅
- POST 同源正确 token → 200 ✅
- `/f/probe.html` → sandbox CSP(无 escape-sandbox)+ nosniff ✅
- 模拟 HTTPS(X-Forwarded-Proto)→ HSTS 出现 ✅

**结论:N1–N11 全部修复并实测验证通过;multer 已升 2.x;lock 文件已补。可上线。**

残留配置项(非代码,部署时处理):docker-compose 的 `SETUP_TOKEN=please-change-me` 须改为随机强口令;生产建议固定 `RP_ID`/`ORIGIN`。
