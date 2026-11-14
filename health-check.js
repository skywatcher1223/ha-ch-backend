/**
 * health-check.js — فحص حقيقي لروابط البث (Node 18+)
 *
 * يفعل ما يلي لكل قناة:
 *  1) يطلب الرابط فعلياً (مع تتبّع التحويلات يدوياً وفحص كل قفزة).
 *  2) إن كان HLS (m3u8): يتحقق أن الملف قائمة تشغيل صالحة، ثم يجلب
 *     أول مقطع فيديو ويتأكد أنه يرجع بيانات فعلاً.
 *  3) إن كان بثاً مباشراً (ts / mp4 / ...): يقرأ أول بايتات ويتأكد أنها ليست صفحة HTML.
 *  4) يقيس زمن أول استجابة بالميلي ثانية.
 *
 * الاستخدام في server.js:
 *   const registerHealthRoutes = require('./health-check');
 *   registerHealthRoutes(app, {
 *     getChannels: async () => (await pool.query('SELECT name, primary_url FROM channels')).rows,
 *     logAudit:    async (operator, action, details) => { ...اختياري... }
 *   });
 *
 * ويستبدل المسار القديم POST /admin/check-streams ويضيف POST /admin/check-stream (قناة واحدة).
 */
const dns = require('dns').promises;
const net = require('net');

const TIMEOUT_MS = 8000;     // مهلة كل طلب
const CONCURRENCY = 10;      // عدد القنوات المفحوصة معاً
const MAX_REDIRECTS = 5;
const UA = 'VLC/3.0.20 LibVLC/3.0.20';

class CheckError extends Error {
  constructor(reason, message, httpStatus) { super(message || reason); this.reason = reason; this.httpStatus = httpStatus; }
}

/* ---------- حماية: لا نسمح بفحص عناوين داخلية (SSRF) ---------- */
function isPrivateIp(ip) {
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === '::1' || l === '::') return true;
    if (l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80')) return true;
    if (l.startsWith('::ffff:')) return isPrivateIp(l.slice(7));
    return false;
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => Number.isNaN(n))) return true;
  return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
}
async function assertPublic(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { throw new CheckError('bad_url', 'رابط غير صالح'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new CheckError('bad_url', 'بروتوكول غير مدعوم');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) { if (isPrivateIp(host)) throw new CheckError('blocked', 'عنوان داخلي'); return; }
  let addrs;
  try { addrs = await dns.lookup(host, { all: true }); }
  catch { throw new CheckError('dns', 'تعذّر تحليل اسم النطاق'); }
  if (addrs.some(a => isPrivateIp(a.address))) throw new CheckError('blocked', 'عنوان داخلي');
}

/* ---------- طلب HTTP حقيقي ---------- */
async function readUpTo(res, max) {
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks = []; let n = 0;
  try {
    while (n < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value)); n += value.length;
    }
  } finally { try { await reader.cancel(); } catch {} }
  return Buffer.concat(chunks).subarray(0, max);
}
function mapNetError(e) {
  if (e instanceof CheckError) return e;
  if (e && e.name === 'AbortError') return new CheckError('timeout', 'انتهت المهلة');
  const code = (e && e.cause && e.cause.code) || (e && e.code) || '';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return new CheckError('dns', 'تعذّر تحليل اسم النطاق');
  if (code === 'ECONNREFUSED' || code === 'ECONNRESET' || code === 'EHOSTUNREACH' || code === 'ETIMEDOUT')
    return new CheckError('connection', 'فشل الاتصال بالسيرفر');
  if (String(code).startsWith('ERR_TLS') || String(code).includes('CERT')) return new CheckError('tls', 'خطأ في شهادة SSL');
  return new CheckError('connection', (e && e.message) || 'فشل الاتصال');
}
async function request(url, { maxBytes = 262144, range, timeout } = {}) {
  let current = url;
  const t0 = Date.now();
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await assertPublic(current);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout || TIMEOUT_MS);
    try {
      const res = await fetch(current, {
        method: 'GET', redirect: 'manual', signal: ctrl.signal,
        headers: { 'User-Agent': UA, Accept: '*/*', ...(range ? { Range: range } : {}) }
      });
      const loc = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && loc) {
        try { await res.body?.cancel(); } catch {}
        current = new URL(loc, current).href;
        continue;
      }
      const ttfb = Date.now() - t0;
      const body = await readUpTo(res, maxBytes);
      return { status: res.status, type: (res.headers.get('content-type') || '').toLowerCase(), ms: ttfb, body, url: current };
    } catch (e) { throw mapNetError(e); }
    finally { clearTimeout(timer); }
  }
  throw new CheckError('http_error', 'تحويلات كثيرة');
}

/* ---------- منطق الفحص ---------- */
const firstUri = text => text.split(/\r?\n/).map(l => l.trim()).find(l => l && !l.startsWith('#'));
const isHtml = t => t.includes('text/html');

// هل البيانات تشبه فيديو/صوتاً فعلاً؟ (نوع المحتوى أو أول بايتات الملف)
function looksLikeMedia(buf, type) {
  if (/^(video|audio)\//.test(type) || /mpegurl|mp2t|mp4|x-flv|ogg/.test(type)) return true;
  if (buf.length >= 189 && buf[0] === 0x47 && buf[188] === 0x47) return true;           // MPEG-TS
  if (buf.length >= 8 && buf.toString('latin1', 4, 8) === 'ftyp') return true;           // MP4
  if (buf.length >= 3 && buf.toString('latin1', 0, 3) === 'ID3') return true;            // MP3
  if (buf.length >= 2 && buf[0] === 0xff && (buf[1] & 0xe0) === 0xe0) return true;       // AAC/MP3
  if (buf.length >= 4 && (buf.toString('latin1', 0, 3) === 'FLV' || buf.toString('latin1', 0, 4) === 'OggS')) return true;
  return false;
}

async function checkStream(url) {
  const base = { checked_at: new Date().toISOString() };
  try {
    const first = await request(url);
    if (first.status < 200 || first.status >= 300)
      throw new CheckError('http_error', 'استجابة غير ناجحة', first.status);

    const text = first.body.toString('utf8');
    let type = 'stream';

    if (text.trimStart().startsWith('#EXTM3U')) {
      type = 'hls';
      let playlistText = text, playlistUrl = first.url;
      // قد تكون قائمة رئيسية تشير إلى قائمة فرعية؛ ننزل مستويين كحد أقصى
      for (let depth = 0; depth < 2; depth++) {
        const target = firstUri(playlistText);
        if (!target) throw new CheckError('bad_playlist', 'قائمة التشغيل فارغة', first.status);
        const targetUrl = new URL(target, playlistUrl).href;
        const isPlaylist = /\.m3u8?(\?|$)/i.test(targetUrl);
        if (isPlaylist) {
          const sub = await request(targetUrl);
          if (sub.status < 200 || sub.status >= 300) throw new CheckError('http_error', 'تعذّر جلب القائمة الفرعية', sub.status);
          const subText = sub.body.toString('utf8');
          if (!subText.trimStart().startsWith('#EXTM3U')) throw new CheckError('bad_playlist', 'قائمة فرعية غير صالحة', sub.status);
          playlistText = subText; playlistUrl = sub.url;
          continue;
        }
        const seg = await request(targetUrl, { maxBytes: 4096, range: 'bytes=0-4095' });
        if (seg.status !== 200 && seg.status !== 206) throw new CheckError('http_error', 'تعذّر جلب مقطع الفيديو', seg.status);
        if (!seg.body.length) throw new CheckError('empty', 'المقطع فارغ', seg.status);
        if (isHtml(seg.type) || /^(text\/|application\/json)/.test(seg.type)) throw new CheckError('html_page', 'المقطع ليس فيديو', seg.status);
        return { ...base, status: 'online', response_time_ms: first.ms, http_status: first.status, reason: 'ok', type };
      }
      throw new CheckError('bad_playlist', 'لم يتم العثور على مقاطع فيديو', first.status);
    }

    // بث مباشر مباشر (ts / mp4 / mp3 ...)
    if (isHtml(first.type) || /^\s*<(!doctype|html)/i.test(text.slice(0, 200)))
      throw new CheckError('html_page', 'الرابط يرجع صفحة ويب وليس بثاً', first.status);
    if (!first.body.length) throw new CheckError('empty', 'لا توجد بيانات', first.status);
    if (!looksLikeMedia(first.body, first.type))
      throw new CheckError('not_stream', 'الرابط لا يرجع بثاً (نوع المحتوى: ' + (first.type || 'غير معروف') + ')', first.status);
    return { ...base, status: 'online', response_time_ms: first.ms, http_status: first.status, reason: 'ok', type };
  } catch (e) {
    const err = e instanceof CheckError ? e : mapNetError(e);
    return { ...base, status: 'offline', response_time_ms: null, http_status: err.httpStatus || null, reason: err.reason, message: err.message };
  }
}

async function checkMany(channels) {
  const out = new Array(channels.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(CONCURRENCY, channels.length) }, async () => {
    while (i < channels.length) {
      const idx = i++;
      const ch = channels[idx];
      out[idx] = { id: ch.id, name: ch.name, ...(await checkStream(ch.primary_url)) };
    }
  });
  await Promise.all(workers);
  return out;
}

/* ---------- المسارات ---------- */
module.exports = function registerHealthRoutes(app, { getChannels, logAudit, saveResults } = {}) {
  app.get(['/admin/health-version', '/api/admin/health-version'], (req, res) => res.json({ success: true, version: '2026-11-14-iptv' }));

  app.post(['/admin/check-streams', '/api/admin/check-streams'], async (req, res) => {
    try {
      const channels = await getChannels();
      const data = await checkMany(channels);
      if (saveResults) { try { await saveResults(data); } catch (e) { console.error('saveResults:', e.message); } }
      const online = data.filter(d => d.status === 'online').length;
      if (logAudit) await logAudit((req.body && req.body.operator_name) || 'Master Admin', 'HEALTH_CHECK', `فحص ${data.length} قناة: ${online} تعمل / ${data.length - online} منقطعة`);
      res.json({ success: true, data });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });

  app.post(['/admin/check-stream', '/api/admin/check-stream'], async (req, res) => {
    try {
      const url = req.body && req.body.url;
      if (!url) return res.status(400).json({ success: false, message: 'الرابط مطلوب' });
      const result = await checkStream(url);
      res.json({ success: true, data: { name: (req.body && req.body.name) || '', ...result } });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });

  /* ---------- فاحص IPTV: جلب قائمة M3U من رابط ---------- */
  app.post(['/admin/fetch-playlist', '/api/admin/fetch-playlist'], async (req, res) => {
    try {
      const url = req.body && req.body.url;
      if (!url) return res.status(400).json({ success: false, message: 'الرابط مطلوب' });
      const MAX = 8 * 1024 * 1024;
      const r = await request(url, { maxBytes: MAX, timeout: 30000 });
      if (r.status < 200 || r.status >= 300)
        return res.status(502).json({ success: false, message: 'سيرفر المزوّد رد بالحالة ' + r.status });
      const text = r.body.toString('utf8');
      if (!text.includes('#EXTINF') && !text.trimStart().startsWith('#EXTM3U'))
        return res.status(422).json({ success: false, message: 'الرابط لا يرجع قائمة M3U صالحة' });
      res.json({ success: true, data: { content: text, bytes: r.body.length, truncated: r.body.length >= MAX } });
    } catch (e) {
      const err = e instanceof CheckError ? e : mapNetError(e);
      res.status(502).json({ success: false, message: err.message });
    }
  });

  /* ---------- فاحص IPTV: فحص دفعة قنوات (حتى 25 في الطلب) ---------- */
  app.post(['/admin/check-batch', '/api/admin/check-batch'], async (req, res) => {
    try {
      const items = Array.isArray(req.body && req.body.items) ? req.body.items.slice(0, 25) : [];
      if (!items.length) return res.status(400).json({ success: false, message: 'لا توجد قنوات للفحص' });
      const data = await checkMany(items.map(i => ({ name: i.name, primary_url: i.url })));
      res.json({ success: true, data });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });

  /* ---------- فاحص IPTV: حالة حساب Xtream Codes ---------- */
  app.post(['/admin/xtream-info', '/api/admin/xtream-info'], async (req, res) => {
    try {
      const { host, username, password, operator_name } = req.body || {};
      if (!host || !username || !password)
        return res.status(400).json({ success: false, message: 'أدخل عنوان السيرفر واسم المستخدم وكلمة المرور' });
      let base;
      try { base = new URL(/^https?:\/\//i.test(host) ? host : 'http://' + host); }
      catch { return res.status(400).json({ success: false, message: 'عنوان السيرفر غير صالح' }); }

      const q = 'username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password);
      const r = await request(base.origin + '/player_api.php?' + q, { maxBytes: 1024 * 1024, timeout: 15000 });
      if (r.status !== 200)
        return res.status(502).json({ success: false, message: 'سيرفر المزوّد رد بالحالة ' + r.status });
      let j;
      try { j = JSON.parse(r.body.toString('utf8')); }
      catch { return res.status(422).json({ success: false, message: 'الرد ليس بصيغة Xtream Codes (قد يكون العنوان خاطئاً)' }); }

      const ui = j && j.user_info;
      if (!ui) return res.status(422).json({ success: false, message: 'الرد لا يحتوي معلومات حساب' });
      const auth = ui.auth === true || Number(ui.auth) === 1;
      const toIso = v => { const n = Number(v); return n > 0 ? new Date(n * 1000).toISOString() : null; };
      const exp = toIso(ui.exp_date);
      const daysLeft = exp ? Math.floor((new Date(exp).getTime() - Date.now()) / 86400000) : null;

      if (logAudit) { try { await logAudit(operator_name || 'Master Admin', 'XTREAM_CHECK', 'فحص حساب Xtream على ' + base.host); } catch {} }

      res.json({
        success: true,
        data: {
          auth,
          status: ui.status || null,
          exp_date: exp,
          days_left: daysLeft,
          is_trial: Number(ui.is_trial) === 1,
          active_connections: Number(ui.active_cons) || 0,
          max_connections: Number(ui.max_connections) || 0,
          created_at: toIso(ui.created_at),
          m3u_url: base.origin + '/get.php?' + q + '&type=m3u_plus&output=ts'
        }
      });
    } catch (e) {
      const err = e instanceof CheckError ? e : mapNetError(e);
      res.status(502).json({ success: false, message: err.message });
    }
  });
};

module.exports.checkStream = checkStream;
module.exports.checkMany = checkMany;
