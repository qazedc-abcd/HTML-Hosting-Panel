/**
 * HTML 托管面板 —— 上传 Agent 生成的 HTML,浏览器直接打开
 * 登录方式:通行密钥(Passkey / WebAuthn),指纹/人脸/PIN 一按即进
 *
 * 环境变量:
 *   PORT        端口,默认 3000
 *   UPLOAD_DIR  上传目录,默认 ./uploads
 *   DATA_DIR    凭证/配置目录,默认 ./data
 *   RP_NAME     通行密钥显示名,默认 "HTML 托管面板"
 *   RP_ID       覆盖自动探测的域名(生产环境建议固定设置)
 *   ORIGIN      覆盖自动探测的来源(生产环境建议固定设置)
 *   SETUP_TOKEN 首次注册口令(强烈建议设置):注册第一个通行密钥时必须提供
 *
 * 注意:通行密钥绑定域名。请用最终访问的域名(HTTPS)注册;
 * localhost 下注册的密钥只在 localhost 有效。
 */
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const PORT = parseInt(process.env.PORT || "3000", 10);
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, "uploads"));
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, "data"));
const RP_NAME = process.env.RP_NAME || "HTML 托管面板";
const SETUP_TOKEN = process.env.SETUP_TOKEN || "";
const CRED_FILE = path.join(DATA_DIR, "credentials.json");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1); // 单跳反代(1Panel/nginx)取真实域名与协议;多层反代改为对应跳数
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// ---------- 基础安全头 ----------
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  if (req.protocol === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

// ---------- 写操作 Origin 校验(防同源托管页面/跨站带 cookie 调接口) ----------
app.use("/api", (req, res, next) => {
  if (req.method === "GET" || req.method === "HEAD") return next();
  // 写操作要求 Origin 必须存在且等于面板自身 host(防 CSRF;与 SameSite=Lax 双保险)
  // 浏览器同源/跨源 POST 必带 Origin;sandbox 托管页 Origin 为 "null" 会被拒
  const o = req.get("origin");
  if (!o) return res.status(403).json({ error: "缺少 Origin 头" });
  try {
    if (new URL(o).host !== req.get("host")) return res.status(403).json({ error: "跨源请求被拒绝" });
  } catch {
    return res.status(403).json({ error: "非法 Origin" });
  }
  next();
});

// ---------- 内存限流(认证与上传接口) ----------
const buckets = new Map(); // ip -> [timestamps]
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const now = Date.now();
    const arr = (buckets.get(req.ip) || []).filter((t) => now - t < windowMs);
    if (arr.length >= max) {
      buckets.set(req.ip, arr);
      return res.status(429).json({ error: "请求过于频繁,请稍后再试" });
    }
    arr.push(now);
    buckets.set(req.ip, arr);
    capMap(buckets, MAX_BUCKETS);
    next();
  };
}
app.use("/api/webauthn", rateLimit(20, 60 * 1000));
app.use("/api/upload", rateLimit(30, 60 * 1000));

// ---------- 工具 ----------
const MAX_CHALLENGES = 10000;
const MAX_BUCKETS = 10000;
function capMap(map, max) {
  // 超出上限则删最早 key(Map 保持插入顺序),防内存 DoS
  while (map.size > max) map.delete(map.keys().next().value);
}
function safeTokenEqual(a, b) {
  // 常量时间比较,防时序侧信道
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function safeName(name) {
  // 仅保留安全字符,防路径穿越;中文名保留
  const base = path.basename(name).replace(/[\\/:*?"<>|#%&{}$!'@+`=\s]+/g, "_");
  return base || "file.html";
}

function uniqueName(name) {
  let candidate = name;
  const ext = path.extname(name);
  const stem = name.slice(0, name.length - ext.length);
  let i = 1;
  while (fs.existsSync(path.join(UPLOAD_DIR, candidate))) {
    candidate = `${stem}_${i}${ext}`;
    i++;
  }
  return candidate;
}

// 浏览器发 UTF-8,Windows curl 等老工具可能发 GBK;两种都兼容
function decodeFilename(name) {
  const buf = Buffer.from(name, "latin1");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buf);
  } catch {
    try {
      return new TextDecoder("gbk", { fatal: true }).decode(buf);
    } catch {
      return name;
    }
  }
}

function listFiles() {
  return fs
    .readdirSync(UPLOAD_DIR)
    .filter((f) => /\.(html?|svg)$/i.test(f))
    .map((f) => {
      const st = fs.statSync(path.join(UPLOAD_DIR, f));
      return { name: f, size: st.size, mtime: st.mtimeMs };
    })
    .sort((a, b) => b.mtime - a.mtime);
}

// ---------- 通行密钥存储 ----------
function loadCreds() {
  try {
    return JSON.parse(fs.readFileSync(CRED_FILE, "utf8"));
  } catch {
    return [];
  }
}
function saveCreds(creds) {
  fs.writeFileSync(CRED_FILE, JSON.stringify(creds, null, 2));
}

function rpID(req) {
  return process.env.RP_ID || req.hostname;
}
function origin(req) {
  return process.env.ORIGIN || `${req.protocol}://${req.get("host")}`;
}

// ---------- 会话与挑战 ----------
const sessions = new Map(); // sid -> expires(30 天,与 cookie 同寿)
const challenges = new Map(); // challengeKey -> { challenge, expires }
const SESSION_TTL = 30 * 24 * 3600 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of challenges) if (v.expires < now) challenges.delete(k);
  for (const [k, v] of sessions) if (v < now) sessions.delete(k);
  for (const [k, v] of buckets) if (v.every((t) => now - t > 60 * 1000)) buckets.delete(k);
}, 60 * 1000).unref();

function secureFlag(req) {
  return req.protocol === "https" ? "; Secure" : "";
}

function makeSession(req, res) {
  const sid = crypto.randomBytes(32).toString("hex");
  sessions.set(sid, Date.now() + SESSION_TTL);
  res.setHeader("Set-Cookie", `wb_sess=${sid}; Path=/; HttpOnly; Max-Age=2592000; SameSite=Lax${secureFlag(req)}`);
}

function setChallenge(req, res, challenge) {
  const key = crypto.randomBytes(16).toString("hex");
  challenges.set(key, { challenge, expires: Date.now() + 5 * 60 * 1000 });
  capMap(challenges, MAX_CHALLENGES);
  res.setHeader("Set-Cookie", `wb_chal=${key}; Path=/; HttpOnly; Max-Age=300; SameSite=Lax${secureFlag(req)}`);
}

function takeChallenge(req) {
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)wb_chal=([a-f0-9]{32})/);
  if (!m) return null;
  const rec = challenges.get(m[1]);
  challenges.delete(m[1]);
  return rec && rec.expires > Date.now() ? rec.challenge : null;
}

function authed(req) {
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)wb_sess=([a-f0-9]{64})/);
  if (!m) return false;
  const exp = sessions.get(m[1]);
  if (!exp) return false;
  if (exp < Date.now()) {
    sessions.delete(m[1]);
    return false;
  }
  return true;
}

function requireAuth(req, res, next) {
  if (authed(req)) return next();
  if (req.path.startsWith("/api/")) return res.status(401).json({ error: "unauthorized" });
  return res.redirect("/login");
}

// ---------- WebAuthn 接口 ----------
app.get("/api/auth/status", (req, res) => {
  const n = loadCreds().length;
  res.json({ passkeys: n, authed: authed(req), setupRequired: n === 0 && !!SETUP_TOKEN });
});

// 首次注册闸门:设置了 SETUP_TOKEN 且尚无密钥时,注册必须带对口令
function setupGate(req, res) {
  if (loadCreds().length === 0 && SETUP_TOKEN && !safeTokenEqual(req.body.token, SETUP_TOKEN)) {
    res.status(403).json({ error: "首次注册口令错误或缺失" });
    return false;
  }
  return true;
}

// 注册:仅当(尚未注册任何密钥)或(已登录)时允许
app.post("/api/webauthn/register/options", async (req, res) => {
  const creds = loadCreds();
  if (creds.length > 0 && !authed(req)) return res.status(401).json({ error: "unauthorized" });
  if (!setupGate(req, res)) return;
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpID(req),
    userName: "owner",
    userDisplayName: "Owner",
    attestationType: "none",
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
    excludeCredentials: creds.map((c) => ({ id: c.id, transports: c.transports })),
  });
  setChallenge(req, res, options.challenge);
  res.json(options);
});

app.post("/api/webauthn/register/verify", async (req, res) => {
  const creds = loadCreds();
  if (creds.length > 0 && !authed(req)) return res.status(401).json({ error: "unauthorized" });
  if (!setupGate(req, res)) return;
  const expectedChallenge = takeChallenge(req);
  if (!expectedChallenge) return res.status(400).json({ error: "挑战已过期,请重试" });
  try {
    const verification = await verifyRegistrationResponse({
      response: req.body.attestation,
      expectedChallenge,
      expectedOrigin: origin(req),
      expectedRPID: rpID(req),
    });
    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: "验证失败" });
    }
    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
    creds.push({
      id: credentialID, // v10 起已是 base64url 字符串,直接存
      publicKey: Buffer.from(credentialPublicKey).toString("base64url"),
      counter,
      transports: req.body.attestation.response.transports || [],
      name: (req.body.name || "我的设备").slice(0, 50),
      createdAt: Date.now(),
    });
    saveCreds(creds);
    makeSession(req, res);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: "验证失败" });
  }
});

app.post("/api/webauthn/login/options", async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: rpID(req),
    userVerification: "required", // 登录强制用户验证(指纹/人脸/PIN)
    // 带上已注册凭证 ID,认证器按 ID 匹配,兼容性最好
    allowCredentials: loadCreds().map((c) => ({ id: c.id, transports: c.transports })),
  });
  setChallenge(req, res, options.challenge);
  res.json(options);
});

app.post("/api/webauthn/login/verify", async (req, res) => {
  const expectedChallenge = takeChallenge(req);
  if (!expectedChallenge) return res.status(400).json({ error: "挑战已过期,请重试" });
  const creds = loadCreds();
  const cred = creds.find((c) => c.id === req.body.assertion.id);
  if (!cred) return res.status(400).json({ error: "未注册的密钥" });
  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body.assertion,
      expectedChallenge,
      expectedOrigin: origin(req),
      expectedRPID: rpID(req),
      authenticator: {
        credentialID: cred.id, // base64url 字符串
        credentialPublicKey: Buffer.from(cred.publicKey, "base64url"),
        counter: cred.counter,
      },
    });
    if (!verification.verified) return res.status(400).json({ error: "验证失败" });
    cred.counter = verification.authenticationInfo.newCounter;
    saveCreds(creds);
    makeSession(req, res);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: "验证失败" });
  }
});

app.get("/api/webauthn/credentials", requireAuth, (req, res) => {
  res.json({
    credentials: loadCreds().map((c) => ({ id: c.id, name: c.name, createdAt: c.createdAt })),
  });
});

app.post("/api/webauthn/credentials/delete", requireAuth, (req, res) => {
  let creds = loadCreds();
  if (creds.length <= 1) return res.status(400).json({ error: "至少保留一个通行密钥" });
  const before = creds.length;
  creds = creds.filter((c) => c.id !== req.body.id);
  if (creds.length === before) return res.status(404).json({ error: "not found" });
  saveCreds(creds);
  res.json({ ok: true });
});

app.get("/login", (req, res) => {
  if (authed(req)) return res.redirect("/");
  const nonce = crypto.randomBytes(16).toString("base64");
  res.setHeader(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
  );
  res.send(loginPage(nonce));
});

app.get("/logout", (req, res) => {
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)wb_sess=([a-f0-9]{64})/);
  if (m) sessions.delete(m[1]);
  res.setHeader("Set-Cookie", "wb_sess=; Path=/; Max-Age=0");
  res.redirect("/login");
});

// ---------- 上传 ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => {
      cb(null, uniqueName(safeName(decodeFilename(file.originalname))));
    },
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/\.(html?|svg)$/i.test(file.originalname)) return cb(null, true);
    cb(new Error("仅支持 .html / .htm / .svg 文件"));
  },
});

app.post("/api/upload", requireAuth, (req, res) => {
  // 单次请求总量上限(防 50MB×20 的磁盘放大)
  const total = parseInt(req.headers["content-length"] || "0", 10);
  if (total > 150 * 1024 * 1024) return res.status(413).json({ error: "单次上传总量超过 150MB" });
  upload.array("files", 20)(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    const files = (req.files || []).map((f) => ({
      name: f.filename,
      url: "/f/" + encodeURIComponent(f.filename),
    }));
    res.json({ ok: true, files });
  });
});

app.get("/api/files", requireAuth, (req, res) => {
  res.json({ files: listFiles() });
});

app.post("/api/delete/:name", requireAuth, (req, res) => {
  const name = path.basename(req.params.name);
  if (!/\.(html?|svg)$/i.test(name)) return res.status(400).json({ error: "仅支持删除 html/svg 文件" });
  const p = path.join(UPLOAD_DIR, name);
  if (!p.startsWith(UPLOAD_DIR) || !fs.existsSync(p)) return res.status(404).json({ error: "not found" });
  fs.unlinkSync(p);
  res.json({ ok: true });
});

// ---------- 访问 HTML ----------
// 直链无需登录,方便分享给任何人打开。
// 关键防护:sandbox CSP 让托管页面运行在"独立不透明源"里——脚本可执行,
// 但拿不到面板会话 cookie、也无法同源调用 /api/*(Origin 为 null 会被拒)。
app.get("/f/:name", (req, res) => {
  const name = path.basename(req.params.name);
  const p = path.join(UPLOAD_DIR, name);
  if (!p.startsWith(UPLOAD_DIR) || !fs.existsSync(p)) return res.status(404).send("Not found");
  res.setHeader(
    "Content-Security-Policy",
    "sandbox allow-scripts allow-forms allow-modals allow-popups allow-downloads"
  );
  if (/\.svg$/i.test(name)) return res.sendFile(p);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.sendFile(p);
});

app.get("/", requireAuth, (req, res) => {
  const nonce = crypto.randomBytes(16).toString("base64");
  res.setHeader(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
  );
  res.send(indexPage(nonce));
});

// ---------- 页面 ----------
const BASE_STYLE = `
  *{box-sizing:border-box}
  body{margin:0;background:#f1f5f9;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#0f172a}
  .btn{display:inline-block;padding:12px 24px;border:0;border-radius:8px;background:#4f46e5;color:#fff;font-size:14px;cursor:pointer;text-decoration:none}
  .btn:hover{background:#4338ca}
  .btn:disabled{opacity:.5;cursor:default}
  .err{color:#dc2626;font-size:13px;margin-top:12px;min-height:18px}
`;

// 登录页与面板页共用的 WebAuthn 前端助手
const WEBAUTHN_JS = `
function b64ToBuf(b){const s=b.replace(/-/g,"+").replace(/_/g,"/");const bin=atob(s);const a=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i);return a.buffer;}
function bufToB64(buf){const a=new Uint8Array(buf);let s="";a.forEach(b=>s+=String.fromCharCode(b));return btoa(s).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"");}

async function doRegister(name, token){
  const r = await fetch("/api/webauthn/register/options",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token})});
  if(!r.ok) throw new Error((await r.json()).error || "获取注册选项失败");
  const options = await r.json();
  options.challenge = b64ToBuf(options.challenge);
  options.user.id = b64ToBuf(options.user.id);
  (options.excludeCredentials||[]).forEach(c=>c.id=b64ToBuf(c.id));
  const cred = await navigator.credentials.create({publicKey: options});
  const attestation = {
    id: cred.id, rawId: bufToB64(cred.rawId), type: cred.type,
    response: {
      clientDataJSON: bufToB64(cred.response.clientDataJSON),
      attestationObject: bufToB64(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
  const v = await fetch("/api/webauthn/register/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({attestation,name,token})});
  const d = await v.json();
  if(!v.ok) throw new Error(d.error || "注册失败");
}

async function doLogin(){
  const r = await fetch("/api/webauthn/login/options",{method:"POST"});
  if(!r.ok) throw new Error((await r.json()).error || "获取登录选项失败");
  const options = await r.json();
  options.challenge = b64ToBuf(options.challenge);
  (options.allowCredentials||[]).forEach(c=>c.id=b64ToBuf(c.id));
  const cred = await navigator.credentials.get({publicKey: options});
  const assertion = {
    id: cred.id, rawId: bufToB64(cred.rawId), type: cred.type,
    response: {
      clientDataJSON: bufToB64(cred.response.clientDataJSON),
      authenticatorData: bufToB64(cred.response.authenticatorData),
      signature: bufToB64(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64(cred.response.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
  const v = await fetch("/api/webauthn/login/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({assertion})});
  const d = await v.json();
  if(!v.ok) throw new Error(d.error || "登录失败");
}
`;

function loginPage(nonce) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · HTML 托管</title>
<style>
  ${BASE_STYLE}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center}
  .card{background:#fff;padding:40px;border-radius:16px;box-shadow:0 4px 24px rgba(15,23,42,.08);width:340px;text-align:center}
  h1{font-size:20px;margin:0 0 8px}
  .sub{font-size:13px;color:#64748b;margin-bottom:28px}
  .btn{width:100%}
  .inp{width:100%;box-sizing:border-box;padding:12px;border:1px solid #e2e8f0;border-radius:8px;font-size:14px;margin-bottom:12px;display:none}
</style></head><body>
<div class="card">
  <h1>🔐 HTML 托管面板</h1>
  <div class="sub" id="sub">正在检查通行密钥…</div>
  <input class="inp" type="password" id="setupToken" placeholder="首次注册口令" autocomplete="off">
  <button class="btn" id="go" disabled>…</button>
  <div class="err" id="err"></div>
</div>
<script nonce="${nonce}">
${WEBAUTHN_JS}
(async () => {
  if(!window.PublicKeyCredential){
    document.getElementById("sub").textContent = "当前浏览器不支持通行密钥,请换 Chrome / Edge / Safari";
    return;
  }
  const s = await (await fetch("/api/auth/status")).json();
  const btn = document.getElementById("go");
  const first = s.passkeys === 0;
  document.getElementById("sub").textContent = first
    ? "首次使用:创建一个通行密钥,之后指纹/人脸/PIN 即可进入"
    : "使用通行密钥解锁";
  btn.textContent = first ? "✨ 创建通行密钥" : "🔑 使用通行密钥进入";
  if(first && s.setupRequired) document.getElementById("setupToken").style.display = "block";
  btn.disabled = false;
  btn.onclick = async () => {
    btn.disabled = true;
    document.getElementById("err").textContent = "";
    try {
      if(first){
        const t = document.getElementById("setupToken").value;
        if(s.setupRequired && !t) throw new Error("请输入首次注册口令");
        await doRegister("主设备", t);
      } else {
        await doLogin();
      }
      location.href = "/";
    } catch(e) {
      document.getElementById("err").textContent = e.message || String(e);
      btn.disabled = false;
    }
  };
})();
</script></body></html>`;
}

function indexPage(nonce) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HTML 托管面板</title>
<style>
  ${BASE_STYLE}
  .wrap{max-width:880px;margin:0 auto;padding:32px 20px 64px}
  header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
  h1{font-size:22px;margin:0}
  h1 span{font-size:13px;color:#64748b;font-weight:400;margin-left:8px}
  .nav a{font-size:13px;color:#64748b;text-decoration:none;margin-left:16px;cursor:pointer}
  .nav a:hover{color:#4f46e5}
  #drop{border:2px dashed #c7d2fe;border-radius:16px;background:#fff;padding:44px 24px;text-align:center;cursor:pointer;transition:.15s}
  #drop.over{border-color:#4f46e5;background:#eef2ff}
  #drop p{margin:0 0 6px;font-size:16px}
  #drop small{color:#94a3b8}
  #progress{margin-top:14px;font-size:13px;color:#4f46e5;display:none}
  .toolbar{display:flex;align-items:center;justify-content:space-between;margin:28px 0 12px}
  .toolbar h2{font-size:15px;margin:0;color:#334155}
  #search{padding:8px 12px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;width:220px}
  .file{display:flex;align-items:center;gap:12px;background:#fff;border-radius:12px;padding:14px 16px;margin-bottom:8px;box-shadow:0 1px 3px rgba(15,23,42,.05)}
  .file .icon{font-size:20px}
  .file .meta{flex:1;min-width:0}
  .file .name{font-size:14px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .file .sub{font-size:12px;color:#94a3b8;margin-top:2px}
  .file a.open{flex-shrink:0;padding:7px 16px;border-radius:8px;background:#4f46e5;color:#fff;font-size:13px;text-decoration:none}
  .file a.open:hover{background:#4338ca}
  .file button,.row button{flex-shrink:0;padding:7px 12px;border-radius:8px;border:1px solid #e2e8f0;background:#fff;font-size:13px;cursor:pointer;color:#64748b}
  .file button.copy:hover{color:#4f46e5;border-color:#4f46e5}
  .file button.del:hover,.row button.del:hover{color:#dc2626;border-color:#dc2626}
  .empty{text-align:center;color:#94a3b8;padding:40px 0;font-size:14px}
  #toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#0f172a;color:#fff;padding:10px 20px;border-radius:8px;font-size:13px;opacity:0;transition:.2s;pointer-events:none}
  #keys{display:none;margin-top:28px}
  .row{display:flex;align-items:center;gap:12px;background:#fff;border-radius:12px;padding:12px 16px;margin-bottom:8px;font-size:13px;box-shadow:0 1px 3px rgba(15,23,42,.05)}
  .row .meta{flex:1}
  .row .sub{font-size:12px;color:#94a3b8;margin-top:2px}
</style></head><body>
<div class="wrap">
  <header>
    <h1>📄 HTML 托管面板<span>上传 · 打开 · 分享</span></h1>
    <div class="nav">
      <a id="toggleKeys">通行密钥</a>
      <a href="/logout">退出</a>
    </div>
  </header>

  <div id="drop">
    <p>把 HTML 文件拖到这里,或点击选择</p>
    <small>支持 .html / .htm / .svg,单文件最大 50MB,可多选;也可以直接 Ctrl+V 粘贴</small>
    <input type="file" id="picker" accept=".html,.htm,.svg" multiple hidden>
    <div id="progress"></div>
  </div>

  <div class="toolbar">
    <h2>已托管文件 <span id="count"></span></h2>
    <input id="search" placeholder="搜索文件名…">
  </div>
  <div id="list"></div>

  <div id="keys">
    <div class="toolbar">
      <h2>已注册通行密钥</h2>
      <button class="row btn-add" id="addKey" style="padding:7px 12px;border-radius:8px;border:1px solid #e2e8f0;background:#fff;font-size:13px;cursor:pointer;color:#4f46e5">+ 添加此设备</button>
    </div>
    <div id="keyList"></div>
  </div>
</div>
<div id="toast"></div>

<script nonce="${nonce}">
${WEBAUTHN_JS}
const $ = (s) => document.querySelector(s);
let files = [];

function fmtSize(n){ if(n<1024) return n+" B"; if(n<1048576) return (n/1024).toFixed(1)+" KB"; return (n/1048576).toFixed(1)+" MB"; }
function fmtTime(t){ const d=new Date(t); const p=(x)=>String(x).padStart(2,"0"); return d.getFullYear()+"-"+p(d.getMonth()+1)+"-"+p(d.getDate())+" "+p(d.getHours())+":"+p(d.getMinutes()); }
function toast(msg){ const t=$("#toast"); t.textContent=msg; t.style.opacity=1; setTimeout(()=>t.style.opacity=0,1800); }

async function load(){
  const r = await fetch("/api/files");
  const d = await r.json();
  files = d.files;
  render();
}

function render(){
  const q = $("#search").value.trim().toLowerCase();
  const list = files.filter(f=>!q || f.name.toLowerCase().includes(q));
  $("#count").textContent = "("+files.length+")";
  $("#list").innerHTML = list.length ? "" : '<div class="empty">还没有文件,先上传一个吧</div>';
  for(const f of list){
    const url = "/f/"+encodeURIComponent(f.name);
    const el = document.createElement("div");
    el.className = "file";
    el.innerHTML =
      '<div class="icon">🌐</div>' +
      '<div class="meta"><div class="name"></div><div class="sub">'+fmtSize(f.size)+" · "+fmtTime(f.mtime)+'</div></div>' +
      '<a class="open" href="'+url+'" target="_blank">打开</a>' +
      '<button class="copy">复制链接</button>' +
      '<button class="del">删除</button>';
    el.querySelector(".name").textContent = f.name;
    el.querySelector(".copy").onclick = async () => {
      await navigator.clipboard.writeText(location.origin + url);
      toast("链接已复制");
    };
    el.querySelector(".del").onclick = async () => {
      if(!confirm("确定删除 " + f.name + " ?")) return;
      await fetch("/api/delete/"+encodeURIComponent(f.name), {method:"POST"});
      toast("已删除"); load();
    };
    $("#list").appendChild(el);
  }
}

async function upload(fileList){
  if(!fileList.length) return;
  const fd = new FormData();
  for(const f of fileList) fd.append("files", f);
  $("#progress").style.display = "block";
  $("#progress").textContent = "上传中…";
  const r = await fetch("/api/upload", {method:"POST", body:fd});
  const d = await r.json();
  $("#progress").style.display = "none";
  if(d.ok){
    toast("已上传 " + d.files.length + " 个文件");
    if(d.files.length === 1) window.open(d.files[0].url, "_blank");
    load();
  } else {
    toast("上传失败:" + (d.error || "未知错误"));
  }
}

// ---- 通行密钥管理 ----
async function loadKeys(){
  const d = await (await fetch("/api/webauthn/credentials")).json();
  $("#keyList").innerHTML = d.credentials.length ? "" : '<div class="empty">暂无</div>';
  for(const c of d.credentials){
    const el = document.createElement("div");
    el.className = "row";
    el.innerHTML = '<div>🔑</div><div class="meta"><div class="kname"></div><div class="sub">注册于 '+fmtTime(c.createdAt)+'</div></div><button class="del">删除</button>';
    el.querySelector(".kname").textContent = c.name;
    el.querySelector(".del").onclick = async () => {
      if(!confirm("删除这个通行密钥?对应设备将无法再登录")) return;
      const r = await fetch("/api/webauthn/credentials/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:c.id})});
      const d2 = await r.json();
      if(!r.ok) return toast(d2.error || "删除失败");
      toast("已删除"); loadKeys();
    };
    $("#keyList").appendChild(el);
  }
}
$("#toggleKeys").onclick = () => {
  const k = $("#keys");
  k.style.display = k.style.display === "block" ? "none" : "block";
  if(k.style.display === "block") loadKeys();
};
$("#addKey").onclick = async () => {
  const name = prompt("给这台设备起个名字:", "新设备");
  if(name === null) return;
  try { await doRegister(name || "新设备"); toast("已添加"); loadKeys(); }
  catch(e){ toast(e.message || String(e)); }
};

const drop = $("#drop");
drop.onclick = () => $("#picker").click();
$("#picker").onchange = (e) => { upload(e.target.files); e.target.value=""; };
["dragover","dragenter"].forEach(ev=>drop.addEventListener(ev,(e)=>{e.preventDefault();drop.classList.add("over");}));
["dragleave","drop"].forEach(ev=>drop.addEventListener(ev,(e)=>{e.preventDefault();drop.classList.remove("over");}));
drop.addEventListener("drop",(e)=>upload(e.dataTransfer.files));
document.addEventListener("paste",(e)=>{
  const items = [...(e.clipboardData?.files||[])];
  if(items.length) upload(items);
});
$("#search").oninput = render;
load();
</script>
</body></html>`;
}

app.listen(PORT, () => {
  console.log(`HTML 托管面板已启动: http://localhost:${PORT}`);
  console.log(`上传目录: ${UPLOAD_DIR}`);
  console.log(`数据目录: ${DATA_DIR}`);
  console.log(
    loadCreds().length === 0
      ? "尚未注册通行密钥:请尽快用最终域名(HTTPS)打开并创建"
      : `已注册 ${loadCreds().length} 个通行密钥`
  );
});
