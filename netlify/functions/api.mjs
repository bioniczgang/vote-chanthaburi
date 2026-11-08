// Backend for the voting site: auth, document store with access rules, live sync, presence, uploads, AI slip reading.
// Storage: Netlify Blobs (no extra database needed).
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const ADMIN_USERS = (process.env.ADMIN_USERS || "test").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const st = name => getStore({ name, consistency: "strong" });
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const fail = (code, error, status) => json({ code, error }, status);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const rid = (n = 10) => crypto.randomBytes(n).toString("base64url").replace(/[-_]/g, "x").slice(0, n);

/* ---------- sessions ---------- */
let SECRET = null;
async function secret() {
  if (SECRET) return SECRET;
  if (process.env.SESSION_SECRET) return (SECRET = process.env.SESSION_SECRET);
  const s = st("sys");
  let v = await s.get("secret");
  if (!v) { const n = crypto.randomBytes(32).toString("hex"); const w = await s.set("secret", n, { onlyIfNew: true }); v = w.modified ? n : await s.get("secret"); }
  return (SECRET = v);
}
const hmac = async p => crypto.createHmac("sha256", await secret()).update(p).digest("base64url");
async function signToken(u) { const p = Buffer.from(JSON.stringify({ uid: u.uid, n: u.username, tv: u.tv || 0, iat: Date.now() })).toString("base64url"); return p + "." + (await hmac(p)); }
const userCache = new Map();
async function getUserByName(username) { return await st("users").get("u:" + username, { type: "json" }); }
async function getUserByUid(uid) {
  const c = userCache.get(uid); if (c && Date.now() - c.at < 10000) return c.u;
  const name = await st("users").get("id:" + uid); if (!name) return null;
  const u = await getUserByName(name); userCache.set(uid, { u, at: Date.now() }); return u;
}
async function auth(req) {
  const h = req.headers.get("authorization") || ""; const tok = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!tok) return null; const [p, sig] = tok.split("."); if (!p || !sig || (await hmac(p)) !== sig) return null;
  let pl; try { pl = JSON.parse(Buffer.from(p, "base64url").toString()); } catch { return null; }
  const u = await getUserByUid(pl.uid); if (!u || (u.tv || 0) !== pl.tv) return null;
  return { uid: u.uid, username: u.username, admin: ADMIN_USERS.includes(u.username) };
}
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString("hex");

/* ---------- access rules ---------- */
const PUB_ADMIN = ["settings", "polls", "approvals", "shop", "deliveries", "schoolvote"]; // everyone reads, admin writes
const PUB_SELF = ["profiles", "ballots", "chat", "orders"];                               // everyone reads, owner-of-doc or admin writes
const PRIV_SELF = ["topups", "orderinfo"];                                                // owner-of-doc + admin read, owner-of-doc writes
const ADMIN_ONLY = ["verify", "adminlog"];
function splitPath(path) {
  const seg = String(path || "").split("/").filter(Boolean);
  if (seg.length < 2 || seg.length % 2 || seg.some(s => !/^[A-Za-z0-9_.~:@+\-]{1,200}$/.test(s) || s === "." || s === "..")) return null;
  return { col: seg.slice(0, -1).join("/"), id: seg[seg.length - 1] };
}
function privOwner(col) { const m = /^data\/users\/([^/]+)$/.exec(col); return m ? m[1] : null; }
function canReadCol(u, col) {
  if (col === "settings") return true;
  if (!u) return false;
  if (privOwner(col)) return privOwner(col) === u.uid;
  if (PUB_ADMIN.includes(col) || PUB_SELF.includes(col) || PRIV_SELF.includes(col)) return true; // PRIV_SELF filtered per doc
  if (ADMIN_ONLY.includes(col)) return u.admin;
  return false;
}
function canReadDoc(u, col, id) { if (!canReadCol(u, col)) return false; if (PRIV_SELF.includes(col)) return u.admin || id === u.uid; return true; }
function canWrite(u, col, id) {
  if (!u) return false;
  if (privOwner(col)) return privOwner(col) === u.uid;
  if (PUB_ADMIN.includes(col) || ADMIN_ONLY.includes(col)) return u.admin;
  if (PUB_SELF.includes(col)) return u.admin || id === u.uid;
  if (PRIV_SELF.includes(col)) return id === u.uid;
  return false;
}
const blobKey = col => "c:" + col;
async function readCol(col) { return (await st("db").get(blobKey(col), { type: "json" })) || { docs: {} }; }
async function mutateCol(col, fn) {
  const s = st("db");
  for (let i = 0; i < 12; i++) {
    const r = await s.getWithMetadata(blobKey(col), { type: "json" });
    const cur = r && r.data ? r.data : { docs: {} };
    if (fn(cur) === false) return true;
    const size = JSON.stringify(cur).length; if (size > 4_500_000) throw Object.assign(new Error("full"), { code: "quota_exceeded" });
    const w = await s.setJSON(blobKey(col), cur, r ? { onlyIfMatch: r.etag } : { onlyIfNew: true });
    if (w.modified) return true;
    await sleep(20 + Math.random() * 60 * (i + 1));
  }
  throw Object.assign(new Error("busy"), { code: "resource_exhausted" });
}
function viewCol(u, col, data) {
  const out = {}; for (const [id, d] of Object.entries(data.docs || {})) { if (!canReadDoc(u, col, id)) continue; out[id] = col === "profiles" ? decorateProfile(d) : d; }
  return out;
}
function decorateProfile(d) { return { ...d, role: ADMIN_USERS.includes(String(d.username || "").toLowerCase()) ? "admin" : "member" }; }
function cleanForWrite(u, col, id, data, prev) {
  if (!data || typeof data !== "object" || Array.isArray(data)) throw Object.assign(new Error("bad body"), { code: "invalid_argument" });
  if (JSON.stringify(data).length > 256 * 1024) throw Object.assign(new Error("too large"), { code: "invalid_argument" });
  if (col === "profiles") {
    const real = id === u.uid ? u.username : (prev && prev.username) || "";
    data = { ...data, username: real }; delete data.role;
  }
  return data;
}

/* ---------- presence ---------- */
let peersCache = { at: 0, list: [] };
async function readPeers() {
  if (Date.now() - peersCache.at < 3000) return peersCache.list;
  const s = st("presence"); const { blobs } = await s.list(); const now = Date.now(); const list = [];
  await Promise.all(blobs.slice(0, 400).map(async b => { const v = await s.get(b.key, { type: "json" }); if (!v) return; if (now - v.ts > 30000) { if (now - v.ts > 3600_000) s.delete(b.key).catch(() => {}); return; } list.push(v); }));
  peersCache = { at: Date.now(), list }; return list;
}

/* ---------- handlers ---------- */
async function handleAuth(req, u) {
  if (req.method === "GET") { if (!u) return fail("unauth", "not signed in", 401); return json({ uid: u.uid, username: u.username, role: u.admin ? "admin" : "member" }); }
  const b = await req.json().catch(() => ({})); const users = st("users");
  if (b.action === "register") {
    const username = String(b.username || "").trim().toLowerCase(), pw = String(b.password || ""), nick = String(b.nick || "").trim().slice(0, 20);
    if (!/^[a-z0-9_.]{3,20}$/.test(username)) return fail("invalid_argument", "ชื่อผู้ใช้ใช้ a-z, 0-9, _ หรือ . ยาว 3-20 ตัว", 400);
    if (pw.length < 6) return fail("invalid_argument", "รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร", 400);
    if (!nick) return fail("invalid_argument", "ใส่ชื่อเล่นด้วยนะ", 400);
    const uid = "u_" + rid(14), salt = rid(16);
    const rec = { uid, username, salt, hash: hashPw(pw, salt), tv: 0, createdAt: Date.now() };
    const w = await users.setJSON("u:" + username, rec, { onlyIfNew: true });
    if (!w.modified) return fail("taken", "ชื่อผู้ใช้นี้มีคนใช้แล้ว ลองชื่ออื่น", 409);
    await users.set("id:" + uid, username);
    await mutateCol("profiles", c => { c.docs[uid] = { username, nick, av: String(b.av || "🐰").slice(0, 8), joinedAt: Date.now() }; });
    return json({ token: await signToken(rec) });
  }
  if (b.action === "login") {
    const username = String(b.username || "").trim().toLowerCase(); const rec = await getUserByName(username);
    if (!rec || hashPw(b.password || "", rec.salt) !== rec.hash) { await sleep(400); return fail("bad_login", "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", 401); }
    return json({ token: await signToken(rec) });
  }
  if (!u) return fail("unauth", "not signed in", 401);
  if (b.action === "changePassword") {
    const rec = await getUserByName(u.username); if (hashPw(b.old || "", rec.salt) !== rec.hash) return fail("bad_login", "รหัสผ่านเดิมไม่ถูกต้อง", 400);
    if (String(b.password || "").length < 6) return fail("invalid_argument", "รหัสผ่านใหม่ต้องยาวอย่างน้อย 6 ตัวอักษร", 400);
    rec.salt = rid(16); rec.hash = hashPw(b.password, rec.salt); rec.tv = (rec.tv || 0) + 1; await users.setJSON("u:" + u.username, rec); userCache.delete(u.uid);
    return json({ token: await signToken(rec) });
  }
  if (b.action === "adminReset") {
    if (!u.admin) return fail("invalid_argument", "เฉพาะแอดมิน", 403);
    const name = await users.get("id:" + String(b.uid || "")); if (!name) return fail("invalid_argument", "ไม่พบผู้ใช้", 404);
    if (String(b.password || "").length < 6) return fail("invalid_argument", "รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร", 400);
    const rec = await getUserByName(name); rec.salt = rid(16); rec.hash = hashPw(b.password, rec.salt); rec.tv = (rec.tv || 0) + 1; await users.setJSON("u:" + name, rec); userCache.delete(rec.uid);
    return json({ ok: true });
  }
  if (b.action === "logoutAll") { const rec = await getUserByName(u.username); rec.tv = (rec.tv || 0) + 1; await users.setJSON("u:" + u.username, rec); userCache.delete(u.uid); return json({ ok: true }); }
  return fail("invalid_argument", "unknown action", 400);
}

async function handleDb(req, u) {
  const b = await req.json().catch(() => ({}));
  if (b.op === "sync") {
    const subs = Array.isArray(b.subs) ? b.subs.slice(0, 40) : []; const known = b.known || {}; const out = {}; const cols = {};
    const need = new Set(subs.map(s => s.t === "c" ? s.p : (splitPath(s.p) || {}).col).filter(Boolean));
    await Promise.all([...need].map(async col => { if (canReadCol(u, col)) cols[col] = await readCol(col); }));
    for (const s of subs) {
      const key = s.t + ":" + s.p; let v;
      if (s.t === "c") { if (!cols[s.p]) v = {}; else v = viewCol(u, s.p, cols[s.p]); }
      else { const sp = splitPath(s.p); const c = sp && cols[sp.col]; const d = c && canReadDoc(u, sp.col, sp.id) ? c.docs[sp.id] : undefined; v = d === undefined ? null : (sp.col === "profiles" ? decorateProfile(d) : d); }
      const h = crypto.createHash("md5").update(JSON.stringify(v)).digest("base64");
      if (known[key] !== h) out[key] = { h, v };
    }
    let peers;
    if (u) {
      if (b.pres && typeof b.pres === "object" && JSON.stringify(b.pres).length < 4096) { const v = { uid: u.uid, p: b.pres, ts: Date.now() }; await st("presence").setJSON(u.uid, v); const i = peersCache.list.findIndex(x => x.uid === u.uid); if (i >= 0) peersCache.list[i] = v; else peersCache.list.push(v); }
      if (b.peers) peers = (await readPeers()).map(x => ({ uid: x.uid, p: x.p, ts: x.ts }));
    }
    return json({ r: out, peers });
  }
  if (!u) return fail("unauth", "not signed in", 401);
  const sp = splitPath(b.path); if (!sp) return fail("invalid_argument", "bad path", 400);
  if (b.op === "get") { if (!canReadCol(u, sp.col) || !canReadDoc(u, sp.col, sp.id)) return json({ exists: false }); const c = await readCol(sp.col); const d = c.docs[sp.id]; return json(d === undefined ? { exists: false } : { exists: true, data: sp.col === "profiles" ? decorateProfile(d) : d }); }
  if (!canWrite(u, sp.col, sp.id)) return fail("invalid_argument", "ไม่มีสิทธิ์", 403);
  try {
    if (b.op === "set") await mutateCol(sp.col, c => { c.docs[sp.id] = cleanForWrite(u, sp.col, sp.id, b.data, c.docs[sp.id]); });
    else if (b.op === "update") await mutateCol(sp.col, c => { if (c.docs[sp.id] === undefined) throw Object.assign(new Error("missing"), { code: "invalid_argument" }); c.docs[sp.id] = cleanForWrite(u, sp.col, sp.id, { ...c.docs[sp.id], ...b.data }, c.docs[sp.id]); });
    else if (b.op === "delete") await mutateCol(sp.col, c => { if (!(sp.id in c.docs)) return false; delete c.docs[sp.id]; });
    else return fail("invalid_argument", "bad op", 400);
  } catch (e) { return fail(e.code || "unavailable", e.message, e.code === "invalid_argument" ? 400 : e.code === "quota_exceeded" ? 507 : 503); }
  return json({ ok: true });
}

async function handleAsset(req, u, rest) {
  const s = st("assets");
  if (req.method === "GET") {
    const id = rest[0]; if (!id || !/^[A-Za-z0-9]{8,40}$/.test(id)) return new Response("not found", { status: 404 });
    const r = await s.getWithMetadata(id, { type: "arrayBuffer" }); if (!r) return new Response("not found", { status: 404 });
    return new Response(r.data, { headers: { "content-type": r.metadata.ct || "application/octet-stream", "cache-control": "private, max-age=86400" } });
  }
  if (!u) return fail("unauth", "not signed in", 401);
  const ct = req.headers.get("content-type") || ""; if (!/^image\/(png|jpe?g|webp|gif)$/.test(ct)) return fail("invalid_argument", "รองรับเฉพาะไฟล์รูปภาพ", 400);
  const buf = await req.arrayBuffer(); if (buf.byteLength > 8 * 1024 * 1024) return fail("invalid_argument", "ไฟล์ใหญ่เกิน 8MB", 400);
  const id = rid(20); await s.set(id, buf, { metadata: { ct, by: u.uid, at: Date.now() } });
  return json({ id, url: "/api/asset/" + id, sizeBytes: buf.byteLength, contentType: ct });
}

async function handleAI(req, u) {
  if (!u || !u.admin) return fail("invalid_argument", "เฉพาะแอดมิน", 403);
  const key = process.env.ANTHROPIC_API_KEY; if (!key) return fail("not_granted", "ยังไม่ได้ตั้งค่า ANTHROPIC_API_KEY", 501);
  const b = await req.json().catch(() => ({}));
  const content = [];
  for (const im of (b.images || []).slice(0, 2)) content.push({ type: "image", source: { type: "base64", media_type: im.media_type, data: im.data } });
  content.push({ type: "text", text: String(b.prompt || "").slice(0, 20000) });
  const r = await fetch("https://api.anthropic.com/v1/messages", { method: "POST", headers: { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || "claude-sonnet-5-5", max_tokens: 1200, messages: [{ role: "user", content }] }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) return fail(r.status === 429 ? "rate_limited" : "upstream_error", (j.error && j.error.message) || "AI error", 502);
  return json({ text: (j.content || []).filter(c => c.type === "text").map(c => c.text).join("") });
}

export default async (req) => {
  try {
    const url = new URL(req.url); const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean); const route = parts[0] || "";
    if (route === "config") return json({ ai: !!process.env.ANTHROPIC_API_KEY });
    const u = await auth(req);
    if (route === "auth") return await handleAuth(req, u);
    if (route === "db") return await handleDb(req, u);
    if (route === "asset") return await handleAsset(req, u, parts.slice(1));
    if (route === "ai") return await handleAI(req, u);
    return fail("not_found", "not found", 404);
  } catch (e) { console.error(e); return fail("unavailable", "server error", 500); }
};
