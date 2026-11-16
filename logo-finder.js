/**
 * logo-finder.js — جلب شعارات القنوات تلقائياً من قاعدة iptv-org العامة
 *   https://iptv-org.github.io/api/channels.json  (الأسماء والأسماء البديلة)
 *   https://iptv-org.github.io/api/logos.json     (روابط الشعارات)
 *
 * - يحمّل الملفين مرة كل 24 ساعة ويبني فهرساً صغيراً في الذاكرة (ثم يحرّر الأصل).
 * - المطابقة بالاسم بعد التطبيع (حروف صغيرة، حذف HD/4K والأقواس والرموز، توحيد الأحرف العربية).
 * - مطابقة تامة فقط → لا شعار خاطئ؛ ما لا يُطابَق يبقى بلا شعار (يعرض التطبيق الحروف الأولى).
 * - يفضّل PNG/JPEG/WebP لأن Flutter لا يعرض SVG مباشرة.
 */
const BASE = 'https://iptv-org.github.io/api/';
const TTL = 24 * 60 * 60 * 1000;
const RETRY = 10 * 60 * 1000;

let index = null;          // Map<normName, logoUrl>
let loadedAt = 0;
let failedAt = 0;
let loading = null;

/* ---------- تطبيع الأسماء ---------- */
function norm(s) {
  return String(s || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')            // علامات لاتينية
    .replace(/[ً-ٰٟـ]/g, '') // تشكيل وتطويل عربي
    .replace(/[أإآ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه')
    .replace(/[\[\(\{][^\]\)\}]*[\]\)\}]/g, ' ')  // (HD) [Geo-blocked]
    .replace(/\b(fhd|uhd|hd|sd|hevc|h265|4k|8k|1080p|720p|480p|hq|lq|backup|vip|premium)\b/g, ' ')
    .replace(/[^\p{L}\p{N}]+/gu, '');
}
function variants(name) {
  const out = new Set();
  const full = norm(name);
  if (full) out.add(full);
  // بادئات القوائم: "AR | اسم" أو "AR: اسم" أو "اسم - HD"
  const tail = String(name || '').split(/[|:]/).pop();
  const t = norm(tail);
  if (t) out.add(t);
  const dash = norm(String(name || '').split(/\s[-–—]\s/)[0]);
  if (dash) out.add(dash);
  for (const v of [...out]) if (v.length > 3 && v.endsWith('tv')) out.add(v.slice(0, -2));
  return [...out];
}

/* ---------- بناء الفهرس ---------- */
const FORMAT_SCORE = { PNG: 60, WEBP: 50, JPEG: 40, JPG: 40, GIF: 10 }; // SVG/AVIF مستبعدة

function pickLogos(logos) {
  const best = new Map(); // channelId -> {score,url}
  for (const l of logos) {
    if (!l || !l.channel || !l.url) continue;
    const fmt = String(l.format || '').toUpperCase();
    if (!(fmt in FORMAT_SCORE)) continue;
    if (!/^https?:\/\//i.test(l.url)) continue;
    const w = Number(l.width) || 0;
    const score =
      (l.in_use === false ? 0 : 1000) +
      FORMAT_SCORE[fmt] +
      (l.feed ? 0 : 20) +
      Math.min(w, 600) / 10 - (w > 1200 ? 30 : 0);
    const cur = best.get(l.channel);
    if (!cur || score > cur.score) best.set(l.channel, { score, url: l.url });
  }
  return best;
}

function buildIndex(channels, logos) {
  const best = pickLogos(logos);
  const idx = new Map();
  // القنوات غير المغلقة أولاً حتى تفوز عند تشابه الأسماء
  const sorted = [...channels].sort((a, b) => (a.closed ? 1 : 0) - (b.closed ? 1 : 0));
  for (const ch of sorted) {
    const logo = best.get(ch.id);
    if (!logo) continue;
    for (const n of [ch.name, ...(ch.alt_names || [])]) {
      const k = norm(n);
      if (k.length >= 2 && !idx.has(k)) idx.set(k, logo.url);
    }
    // نسخة بدون لاحقة tv (Nessma TV ← Nessma) بأولوية أقل
    for (const n of [ch.name, ...(ch.alt_names || [])]) {
      const k = norm(n);
      if (k.length > 4 && k.endsWith('tv')) { const b = k.slice(0, -2); if (!idx.has(b)) idx.set(b, logo.url); }
    }
  }
  return idx;
}

/* ---------- التحميل ---------- */
async function getJson(path) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 90000);
  try {
    const res = await fetch(BASE + path, { signal: ctrl.signal, headers: { 'User-Agent': 'HA-TV-Panel' } });
    if (!res.ok) throw new Error(path + ' → HTTP ' + res.status);
    return await res.json();
  } finally { clearTimeout(timer); }
}

function ensureLoaded() {
  const fresh = index && Date.now() - loadedAt < TTL;
  if (fresh) return Promise.resolve(index);
  if (loading) return loading;
  if (!index && failedAt && Date.now() - failedAt < RETRY) return Promise.reject(new Error('مصدر الشعارات غير متاح مؤقتاً'));
  loading = (async () => {
    try {
      let channels = await getJson('channels.json');
      let logos = await getJson('logos.json');
      index = buildIndex(channels, logos);
      channels = logos = null; // تحرير الذاكرة
      loadedAt = Date.now(); failedAt = 0;
      return index;
    } catch (e) {
      failedAt = Date.now();
      if (index) return index; // نبقى على الفهرس القديم إن وُجد
      throw e;
    } finally { loading = null; }
  })();
  return loading;
}

/* ---------- الواجهة ---------- */
function lookup(idx, name) {
  for (const v of variants(name)) {
    const u = idx.get(v);
    if (u) return u;
  }
  return null;
}
/** فوري: من الذاكرة فقط (يبدأ التحميل في الخلفية إن لم يكن جاهزاً). */
function peek(name) {
  if (!index) { ensureLoaded().catch(() => {}); return null; }
  return lookup(index, name);
}
/** ينتظر التحميل ثم يطابق قائمة أسماء. يرجع Map(name → url). */
async function findMany(names) {
  const idx = await ensureLoaded();
  const out = new Map();
  for (const n of names) { const u = lookup(idx, n); if (u) out.set(n, u); }
  return out;
}

module.exports = { peek, findMany, norm, variants, buildIndex, lookup };
