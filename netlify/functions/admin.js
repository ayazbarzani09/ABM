import { getStore } from "@netlify/blobs";

const store = getStore({ name: "abm-admin", consistency: "strong" });
const enc = new TextEncoder();
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json; charset=utf-8", ...headers }
});
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const random = (n = 32) => crypto.getRandomValues(new Uint8Array(n));
async function hashPassword(password, salt = random(16)) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, key, 256);
  return { salt: b64(salt), hash: b64(bits) };
}
async function verifyPassword(password, user) {
  const result = await hashPassword(password, unb64(user.salt));
  const a = unb64(result.hash), b = unb64(user.hash);
  return a.length === b.length && a.every((v, i) => v === b[i]);
}
async function digest(value) {
  return b64(await crypto.subtle.digest("SHA-256", enc.encode(value)));
}
function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
function getCookie(request, name) {
  const part = (request.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return part ? part.slice(name.length + 1) : "";
}
async function users() { return (await store.get("users", { type: "json" })) || []; }
async function saveUsers(value) { await store.setJSON("users", value); }
const defaultContent = { heroTitle:"ABM", heroText:"بەخێربێیت بۆ جیهانی ABM؛ شوێنێک بۆ ناساندنی بیرۆکە، کار و هەنگاوە نوێکان.", aboutTitle:"دەربارەی ABM", aboutText:"ئەم پەڕەیە بۆ ناساندنی ABM و پیشاندانی کار و پڕۆژەکان دروست کراوە. لێرەدا دەتوانیت زانیاری و نوێکارییەکان بە شێوەیەکی ڕێکخراو ببینیت.", workTitle:"بوارەکان و پڕۆژەکان", card1Title:"تەکنەلۆژیا", card1Text:"بیرۆکە و پڕۆژە نوێکانی بواری تەکنەلۆژیا.", card2Title:"دیزاین", card2Text:"دیزاین و ناوەڕۆکی جوان و تایبەت.", card3Title:"پەرەپێدان", card3Text:"هەنگاوە نوێکان بۆ فێربوون و گەشەکردن.", contactTitle:"پەیوەندیمان پێوە بکە", contactText:"لە ڕێگەی ئیمەیڵەوە پەیوەندیمان پێوە بکە.", email:"hello@example.com" };
async function bootstrap() {
  const list = await users();
  if (list.length) return list;
  const username = (Netlify.env.get("ADMIN_OWNER_USERNAME") || "").trim();
  const password = Netlify.env.get("ADMIN_OWNER_PASSWORD") || "";
  if (!username || password.length < 12) throw new Error("Owner setup is incomplete. Set ADMIN_OWNER_USERNAME and ADMIN_OWNER_PASSWORD (12+ characters) in Netlify environment variables.");
  const pass = await hashPassword(password);
  const owner = { id: crypto.randomUUID(), username, role: "owner", ...pass, createdAt: new Date().toISOString() };
  await saveUsers([owner]);
  return [owner];
}
async function currentUser(request) {
  const token = getCookie(request, "abm_session");
  if (!token) return null;
  const session = await store.get("session:" + await digest(token), { type: "json" });
  if (!session || session.expiresAt < Date.now()) return null;
  const list = await users();
  return list.find(u => u.id === session.userId) || null;
}
export default async (request) => {
  try {
    const url = new URL(request.url);
    const action = url.searchParams.get("action") || "";
    if (request.method === "OPTIONS") return new Response(null, { status: 204 });
    if (request.method !== "POST" && !["me", "list", "content"].includes(action)) return json({ error: "Method not allowed" }, 405);
    let list = await bootstrap();

    if (action === "login") {
      const body = await request.json();
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      const user = list.find(u => u.username.toLowerCase() === username.toLowerCase());
      if (!user || !(await verifyPassword(password, user))) return json({ error: "ناو یان وشەی نهێنی هەڵەیە." }, 401);
      const token = b64(random(32)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      await store.setJSON("session:" + await digest(token), { userId: user.id, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
      return json({ ok: true, user: { username: user.username, role: user.role } }, 200, { "set-cookie": cookie("abm_session", token, 28800) });
    }

    const user = await currentUser(request);
    if (action === "logout") {
      const token = getCookie(request, "abm_session");
      if (token) await store.delete("session:" + await digest(token));
      return json({ ok: true }, 200, { "set-cookie": cookie("abm_session", "", 0) });
    }
    if (!user) return json({ error: "تکایە بچۆ ژوورەوە." }, 401);
    if (action === "me") return json({ user: { username: user.username, role: user.role } });
    if (action === "save-content") {
      const body = await request.json();
      const clean = {};
      for (const key of Object.keys(defaultContent)) {
        const value = String(body[key] ?? "").trim();
        if (value.length > 3000) return json({ error: "دەقەکە زۆر درێژە." }, 400);
        clean[key] = value;
      }
      if (clean.email && !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(clean.email)) return json({ error: "ئیمەیڵەکە دروست نییە." }, 400);
      await store.setJSON("site-content", clean);
      return json({ ok: true });
    }
    if (action === "list") {
      if (user.role !== "owner") return json({ error: "تەنها خاوەنی ماڵپەڕ دەتوانێت ئەدمینەکان ببینێت." }, 403);
      return json({ admins: list.map(u => ({ id: u.id, username: u.username, role: u.role, createdAt: u.createdAt })) });
    }
    if (action === "add") {
      if (user.role !== "owner") return json({ error: "تەنها خاوەنی ماڵپەڕ دەتوانێت ئەدمین زیاد بکات." }, 403);
      const body = await request.json();
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) return json({ error: "ناوی بەکارهێنەر دەبێت ٣ تا ٣٢ پیت و ژمارە بێت." }, 400);
      if (password.length < 12) return json({ error: "وشەی نهێنی دەبێت لانیکەم ١٢ پیت بێت." }, 400);
      if (list.some(u => u.username.toLowerCase() === username.toLowerCase())) return json({ error: "ئەم ناوە پێشتر هەیە." }, 409);
      const pass = await hashPassword(password);
      list.push({ id: crypto.randomUUID(), username, role: "admin", ...pass, createdAt: new Date().toISOString() });
      await saveUsers(list);
      return json({ ok: true });
    }
    if (action === "remove") {
      if (user.role !== "owner") return json({ error: "تەنها خاوەنی ماڵپەڕ دەتوانێت ئەدمین بسڕێتەوە." }, 403);
      const body = await request.json();
      const target = list.find(u => u.id === body.id);
      if (!target || target.role === "owner") return json({ error: "ئەم ئەدمینە ناتوانرێت بسڕدرێتەوە." }, 400);
      list = list.filter(u => u.id !== target.id);
      await saveUsers(list);
      return json({ ok: true });
    }
    return json({ error: "Unknown action" }, 404);
  } catch (error) {
    console.error(error);
    return json({ error: "هەڵەیەک ڕوویدا. ڕێکخستنەکانی ماڵپەڕ بپشکنە." }, 500);
  }
};
