/**
 * EdgeTunnel Personal Panel
 * Cloudflare Workers + KV
 *
 * Required bindings:
 *   KV Namespace: DATA
 *   Secret: ADMIN_PASSWORD
 *   Secret: SESSION_SECRET
 */

const COOKIE = "et_session";
const SESSION_SECONDS = 8 * 60 * 60;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      if (path === "/") {
        return new Response(PAGE, {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy":
              "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
          },
        });
      }

      if (!env.DATA || !env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
        return json({
          error: "Missing DATA, ADMIN_PASSWORD or SESSION_SECRET binding",
        }, 500);
      }

      // Public subscription endpoint
      if (path.startsWith("/sub/") && method === "GET") {
        const token = path.slice(5);
        if (!/^[a-f0-9]{64}$/.test(token)) {
          return new Response("Not found", { status: 404 });
        }

        const mapping = await env.DATA.get(`sub:${token}`, "json");
        if (!mapping) return new Response("Not found", { status: 404 });

        const user = await env.DATA.get(`user:${mapping.userId}`, "json");
        if (!user || user.disabled) {
          return new Response("Subscription disabled", { status: 403 });
        }

        const nodes = await listRecords(env.DATA, "node:");
        const links = nodes
          .filter(n => n.enabled !== false)
          .map(n => makeVlessLink(n, user.uuid));

        const body = base64Utf8(links.join("\n"));
        return new Response(body, {
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
            "Profile-Title": encodeURIComponent("EdgeTunnel"),
            "Profile-Update-Interval": "6",
          },
        });
      }

      if (path === "/api/login" && method === "POST") {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const rateKey = `login-rate:${ip}`;
        const attempts = Number(await env.DATA.get(rateKey) || 0);

        if (attempts >= 10) {
          return json({ error: "登录尝试过多，请 10 分钟后重试" }, 429);
        }

        const body = await request.json().catch(() => ({}));
        if (
          typeof body.password !== "string" ||
          !constantTimeEqual(body.password, env.ADMIN_PASSWORD)
        ) {
          await env.DATA.put(rateKey, String(attempts + 1), {
            expirationTtl: 600,
          });
          return json({ error: "管理员密码错误" }, 401);
        }

        await env.DATA.delete(rateKey);

        const token = await signSession(env.SESSION_SECRET);
        return json({ ok: true }, 200, {
          "Set-Cookie":
            `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`,
        });
      }

      if (path === "/api/logout" && method === "POST") {
        return json({ ok: true }, 200, {
          "Set-Cookie":
            `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
        });
      }

      if (!(await verifySession(request, env.SESSION_SECRET))) {
        return json({ error: "请先登录管理员账号" }, 401);
      }

      if (
        ["POST", "PUT", "DELETE"].includes(method) &&
        request.headers.get("Origin") !== url.origin
      ) {
        return json({ error: "Origin rejected" }, 403);
      }

      if (path === "/api/bootstrap" && method === "GET") {
        const [users, nodes] = await Promise.all([
          listRecords(env.DATA, "user:"),
          listRecords(env.DATA, "node:"),
        ]);

        return json({
          users: users.map(u => ({
            id: u.id,
            name: u.name,
            uuid: u.uuid,
            token: u.token,
            disabled: !!u.disabled,
            createdAt: u.createdAt,
          })),
          nodes,
          origin: url.origin,
        });
      }

      // Create user with independent UUID and subscription token
      if (path === "/api/users" && method === "POST") {
        const body = await request.json();
        const name = cleanText(body.name, 60);

        if (!name) return json({ error: "请输入用户名称" }, 400);

        const id = crypto.randomUUID();
        const uuid = crypto.randomUUID();
        const token = randomHex(32);

        const user = {
          id,
          name,
          uuid,
          token,
          disabled: false,
          createdAt: new Date().toISOString(),
        };

        await env.DATA.put(`user:${id}`, JSON.stringify(user));
        await env.DATA.put(
          `sub:${token}`,
          JSON.stringify({ userId: id })
        );

        return json({ ok: true, user });
      }

      const userMatch = path.match(/^\/api\/users\/([0-9a-f-]+)$/i);
      if (userMatch) {
        const id = userMatch[1];
        const key = `user:${id}`;
        const user = await env.DATA.get(key, "json");

        if (!user) return json({ error: "用户不存在" }, 404);

        if (method === "DELETE") {
          await env.DATA.delete(key);
          await env.DATA.delete(`sub:${user.token}`);
          return json({ ok: true });
        }

        if (method === "PUT") {
          const body = await request.json();

          if (typeof body.disabled === "boolean") {
            user.disabled = body.disabled;
          }

          if (body.regenerateUuid === true) {
            user.uuid = crypto.randomUUID();
          }

          if (body.regenerateToken === true) {
            await env.DATA.delete(`sub:${user.token}`);
            user.token = randomHex(32);
            await env.DATA.put(
              `sub:${user.token}`,
              JSON.stringify({ userId: user.id })
            );
          }

          if (typeof body.name === "string") {
            const name = cleanText(body.name, 60);
            if (!name) return json({ error: "用户名称不能为空" }, 400);
            user.name = name;
          }

          await env.DATA.put(key, JSON.stringify(user));
          return json({ ok: true, user });
        }
      }

      // Create and manage nodes
      if (path === "/api/nodes" && method === "POST") {
        const body = await request.json();
        const node = validateNode(body);
        if (node.error) return json({ error: node.error }, 400);

        node.id = crypto.randomUUID();
        node.createdAt = new Date().toISOString();
        await env.DATA.put(`node:${node.id}`, JSON.stringify(node));

        return json({ ok: true, node });
      }

      const nodeMatch = path.match(/^\/api\/nodes\/([0-9a-f-]+)$/i);
      if (nodeMatch) {
        const id = nodeMatch[1];
        const key = `node:${id}`;
        const old = await env.DATA.get(key, "json");

        if (!old) return json({ error: "节点不存在" }, 404);

        if (method === "DELETE") {
          await env.DATA.delete(key);
          return json({ ok: true });
        }

        if (method === "PUT") {
          const body = await request.json();
          const updated = validateNode({ ...old, ...body });

          if (updated.error) return json({ error: updated.error }, 400);

          updated.id = old.id;
          updated.createdAt = old.createdAt;
          await env.DATA.put(key, JSON.stringify(updated));

          return json({ ok: true, node: updated });
        }
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      return json({ error: "服务器内部错误" }, 500);
    }
  },
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

async function listRecords(kv, prefix) {
  const result = [];
  let cursor;

  do {
    const page = await kv.list({ prefix, cursor, limit: 1000 });
    for (const item of page.keys) {
      const value = await kv.get(item.name, "json");
      if (value) result.push(value);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return result;
}

function cleanText(value, maxLength) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function validateNode(body) {
  const name = cleanText(body.name, 80);
  const address = cleanText(body.address, 253);
  const host = cleanText(body.host || body.address, 253);
  const path = cleanText(body.path || "/", 200);
  const port = Number(body.port || 443);

  if (!name || !address || !host) {
    return { error: "节点名称、地址和 Host 不能为空" };
  }

  if (
    /[\s/@?#]/.test(address) ||
    !/^[a-zA-Z0-9.:[\]-]+$/.test(address)
  ) {
    return { error: "节点地址格式无效" };
  }

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { error: "端口必须为 1–65535 的整数" };
  }

  if (!path.startsWith("/") || /[\r\n]/.test(path)) {
    return { error: "WS Path 必须以 / 开头" };
  }

  return {
    name,
    address,
    host,
    port,
    path,
    tls: body.tls !== false,
    enabled: body.enabled !== false,
  };
}

function makeVlessLink(node, uuid) {
  const params = new URLSearchParams({
    encryption: "none",
    security: node.tls ? "tls" : "none",
    type: "ws",
    host: node.host,
    path: node.path || "/",
  });

  if (node.tls) params.set("sni", node.host);

  const name = encodeURIComponent(node.name);
  return `vless://${uuid}@${node.address}:${node.port}?${params.toString()}#${name}`;
}

function randomHex(bytes) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(data, b => b.toString(16).padStart(2, "0")).join("");
}

function base64Utf8(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function constantTimeEqual(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);

  for (let i = 0; i < n; i++) {
    diff |= (x[i % (x.length || 1)] || 0) ^
            (y[i % (y.length || 1)] || 0);
  }

  return diff === 0;
}

async function signSession(secret) {
  const payload = btoa(JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS,
    nonce: randomHex(16),
  })).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );

  const sig = Array.from(new Uint8Array(signature),
    b => b.toString(16).padStart(2, "0")).join("");

  return `${payload}.${sig}`;
}

async function verifySession(request, secret) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!match) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const [payload, signature] = parts;
  const expected = await signHmacHex(secret, payload);
  if (!constantTimeEqual(signature, expected)) return false;

  try {
    const encoded = payload.replace(/-/g, "+").replace(/_/g, "/");
    const data = JSON.parse(atob(encoded));
    return Number.isFinite(data.exp) &&
      data.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function signHmacHex(secret, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );

  return Array.from(new Uint8Array(signature),
    b => b.toString(16).padStart(2, "0")).join("");
}

const PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EdgeTunnel · Control Center</title>
<style>
:root{color-scheme:dark;--bg:#080c16;--panel:#111827;--line:#253248;--text:#e6edf8;--muted:#8fa2bd;--blue:#59a7ff;--green:#48d6a0;--red:#ff647c}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#13243c 0,#080c16 55%);color:var(--text);font:14px system-ui,-apple-system,sans-serif;min-height:100vh}
button,input,select{font:inherit}button{cursor:pointer;border:1px solid #315078;background:#18365b;color:#eaf4ff;padding:10px 14px;border-radius:9px}button:hover{filter:brightness(1.15)}button.danger{background:#431e2b;border-color:#713047}input,select{background:#0a1220;border:1px solid var(--line);color:var(--text);padding:11px;border-radius:8px;width:100%;min-width:0}label{display:block;color:var(--muted);font-size:12px;margin:0 0 6px}.wrap{max-width:1180px;margin:auto;padding:28px 18px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:24px}.brand{font-size:22px;font-weight:800;letter-spacing:.4px}.brand span{color:var(--blue)}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.panel{background:linear-gradient(145deg,#121d2e,#0e1522);border:1px solid var(--line);border-radius:15px;padding:18px;box-shadow:0 12px 35px #0002}.panel h2{font-size:16px;margin:0 0 15px}.formgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.wide{grid-column:1/-1}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.list{display:grid;gap:10px;margin-top:14px}.item{border:1px solid var(--line);background:#0b1320;border-radius:10px;padding:13px;min-width:0}.itemhead{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.item strong{overflow-wrap:anywhere}.tag{font-size:11px;color:var(--green);border:1px solid #225944;border-radius:20px;padding:3px 7px;white-space:nowrap}.tag.off{color:var(--red);border-color:#713047}.small{font-size:12px;color:var(--muted);overflow-wrap:anywhere;margin-top:8px;line-height:1.6}.empty{padding:22px;text-align:center;color:var(--muted)}#login{max-width:400px;margin:10vh auto}#app{display:none}.notice{margin:12px 0;color:var(--blue);overflow-wrap:anywhere}.foot{margin-top:20px;font-size:12px;color:var(--muted)}@media(max-width:750px){.grid{grid-template-columns:1fr}.wrap{padding:16px 12px}.top{align-items:flex-start}.brand{font-size:19px}.formgrid{grid-template-columns:1fr}.wide{grid-column:auto}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div><div class="brand">EDGE<span>TUNNEL</span></div><div class="muted">PERSONAL CONTROL CENTER</div></div>
    <div id="topActions" style="display:none"><button onclick="logout()">退出登录</button></div>
  </div>

  <section id="login" class="panel">
    <h2>管理员身份验证</h2>
    <p class="muted">登录你的 EdgeTunnel 控制面板</p>
    <form id="loginForm">
      <label>ADMIN PASSWORD</label>
      <input id="password" type="password" autocomplete="current-password" required>
      <div class="actions"><button type="submit">安全登录</button></div>
    </form>
    <div id="loginMsg" class="notice"></div>
  </section>

  <section id="app">
    <div class="grid">
      <div class="panel">
        <h2>创建用户</h2>
        <form id="userForm">
          <label>用户名称</label>
          <input id="userName" maxlength="60" placeholder="例如：User-001" required>
          <div class="actions"><button>＋ 创建用户 / UUID</button></div>
        </form>
        <div class="small">每位用户自动分配独立 UUID 和订阅令牌。</div>
        <div id="users" class="list"></div>
      </div>

      <div class="panel">
        <h2>添加节点</h2>
        <form id="nodeForm" class="formgrid">
          <div><label>节点名称</label><input id="nodeName" placeholder="Tokyo-01" required></div>
          <div><label>节点地址 / IP</label><input id="nodeAddress" placeholder="example.com" required></div>
          <div><label>端口</label><input id="nodePort" type="number" min="1" max="65535" value="443" required></div>
          <div><label>Host / SNI</label><input id="nodeHost" placeholder="example.com"></div>
          <div class="wide"><label>WebSocket Path</label><input id="nodePath" value="/"></div>
          <div class="wide"><label><input id="nodeTls" type="checkbox" checked style="width:auto;min-width:auto"> 启用 TLS</label></div>
          <div class="wide actions"><button>＋ 保存节点</button></div>
        </form>
        <div class="small">节点必须对应真实可用的服务端配置。这里生成的是 VLESS + WebSocket 订阅项。</div>
        <div id="nodes" class="list"></div>
      </div>
    </div>
    <div class="foot">EdgeTunnel Personal · 管理接口需要管理员会话认证</div>
  </section>
</div>

<script>
const $=id=>document.getElementById(id);
async function api(path,method="GET",data){
  const r=await fetch(path,{method,headers:data?{"Content-Type":"application/json"}:{},body:data?JSON.stringify(data):undefined,credentials:"same-origin"});
  const j=await r.json().catch(()=>({error:"服务器返回无效数据"}));
  if(!r.ok)throw Error(j.error||("HTTP "+r.status));
  return j;
}
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function showApp(){ $("login").style.display="none";$("app").style.display="block";$("topActions").style.display="block"; }
async function refresh(){
  const d=await api("/api/bootstrap");
  $("users").innerHTML=d.users.length?d.users.map(u=>{
    const sub=d.origin+"/sub/"+u.token;
    return '<div class="item"><div class="itemhead"><strong>'+esc(u.name)+'</strong><span class="tag '+(u.disabled?"off":"")+'">'+(u.disabled?"已停用":"正常")+'</span></div>'+
    '<div class="small">UUID：'+esc(u.uuid)+'<br>订阅：'+esc(sub)+'</div>'+
    '<div class="actions"><button onclick="copyText('+JSON.stringify(sub).replace(/</g,"\\\\u003c")+')">复制订阅</button>'+
    '<button onclick="userAction('+JSON.stringify(u.id)+',\\'regenerateUuid\\')">重置 UUID</button>'+
    '<button onclick="userAction('+JSON.stringify(u.id)+',\\'toggle\\')">'+(u.disabled?"启用":"停用")+'</button>'+
    '<button class="danger" onclick="deleteUser('+JSON.stringify(u.id)+')">删除</button></div></div>';
  }).join(""):'<div class="empty">还没有用户</div>';

  $("nodes").innerHTML=d.nodes.length?d.nodes.map(n=>
    '<div class="item"><div class="itemhead"><strong>'+esc(n.name)+'</strong><span class="tag '+(n.enabled===false?"off":"")+'">'+(n.enabled===false?"已停用":"已启用")+'</span></div>'+
    '<div class="small">'+esc(n.address)+':'+esc(n.port)+'<br>Host：'+esc(n.host)+'<br>Path：'+esc(n.path)+' · TLS：'+(n.tls?"开":"关")+'</div>'+
    '<div class="actions"><button onclick="toggleNode('+JSON.stringify(n.id)+','+(n.enabled===false?'true':'false')+')">'+(n.enabled===false?"启用":"停用")+'</button>'+
    '<button class="danger" onclick="deleteNode('+JSON.stringify(n.id)+')">删除节点</button></div></div>'
  ).join(""):'<div class="empty">还没有节点</div>';
}
async function copyText(s){
  try{await navigator.clipboard.writeText(s);alert("已复制");}
  catch{prompt("请手动复制",s);}
}
async function userAction(id,action){
  try{
    if(action==="regenerateUuid"&&!confirm("重置 UUID 后，旧 UUID 将失效。继续？"))return;
    if(action==="toggle"){
      const d=await api("/api/bootstrap");
      const u=d.users.find(x=>x.id===id);
      await api("/api/users/"+id,"PUT",{disabled:!u.disabled});
    }else{
      await api("/api/users/"+id,"PUT",{[action]:true});
    }
    await refresh();
  }catch(e){alert(e.message);}
}
async function deleteUser(id){
  if(!confirm("确定删除该用户并撤销其订阅？"))return;
  try{await api("/api/users/"+id,"DELETE");await refresh();}catch(e){alert(e.message);}
}
async function toggleNode(id,enabled){
  try{await api("/api/nodes/"+id,"PUT",{enabled});await refresh();}catch(e){alert(e.message);}
}
async function deleteNode(id){
  if(!confirm("确定删除该节点？"))return;
  try{await api("/api/nodes/"+id,"DELETE");await refresh();}catch(e){alert(e.message);}
}
$("loginForm").onsubmit=async e=>{
  e.preventDefault();$("loginMsg").textContent="正在登录…";
  try{await api("/api/login","POST",{password:$("password").value});$("password").value="";showApp();await refresh();}
  catch(err){$("loginMsg").textContent=err.message;}
};
$("userForm").onsubmit=async e=>{
  e.preventDefault();
  try{await api("/api/users","POST",{name:$("userName").value});$("userName").value="";await refresh();}
  catch(err){alert(err.message);}
};
$("nodeForm").onsubmit=async e=>{
  e.preventDefault();
  try{
    await api("/api/nodes","POST",{
      name:$("nodeName").value,address:$("nodeAddress").value,
      port:Number($("nodePort").value),
      host:$("nodeHost").value||$("nodeAddress").value,
      path:$("nodePath").value,tls:$("nodeTls").checked,enabled:true
    });
    $("nodeName").value="";await refresh();
  }catch(err){alert(err.message);}
};
async function logout(){
  try{await api("/api/logout","POST",{});}catch{}
  $("app").style.display="none";$("topActions").style.display="none";$("login").style.display="block";
}
(async()=>{
  try{await api("/api/bootstrap");showApp();await refresh();}
  catch{}
})();
</script>
</body>
</html>`;