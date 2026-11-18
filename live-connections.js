// live-connections.js — يضيف GET /admin/live-connections (الاتصالات المباشرة) بدون أي تغيير في كود server.js الحالي.
// الاستعمال في server.js (بعد استدعاء registerHealthRoutes وقبل مسارات المشغلين):
//     require('./live-connections')(app, { supabase });
//
// يعتمد على:
//  - جدول code_devices (last_seen / last_channel) الذي يحدّثه /heartbeat
//  - IP و User-Agent يُلتقطان من نبضات التطبيق (في الذاكرة، لا يلزم تعديل قاعدة البيانات)
//  - جدول code_login_log كاحتياط للـ IP، ثم بحث جغرافي (البلد/المدينة/المزوّد) بذاكرة مؤقتة
const WINDOW_MS = 5 * 60 * 1000;          // الجهاز "متصل" إن نبض خلال آخر 5 دقائق (مثل /admin/live)
const GEO_TTL_MS = 24 * 3600 * 1000;       // نحتفظ بنتيجة البحث الجغرافي 24 ساعة
const GEO_FAIL_TTL_MS = 10 * 60 * 1000;    // وعند الفشل نعيد المحاولة بعد 10 دقائق

const cleanIp = (ip) => String(ip || '').replace(/^::ffff:/i, '').trim();
const isPrivate = (ip) => !ip || /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|f[cd][0-9a-f]{2}:|fe80:)/i.test(ip);

module.exports = function registerLiveConnections(app, { supabase }) {
    const meta = new Map(); // "codeId:deviceId" -> { ip, ua, at }
    const geo = new Map();  // ip -> { at, ttl, v }

    // يُسجَّل قبل مسار /heartbeat الأصلي: يلتقط IP و User-Agent ثم يمرّر الطلب كما هو
    app.post(['/heartbeat', '/api/heartbeat'], (req, res, next) => {
        try {
            if (req.device) meta.set(req.device.cid + ':' + req.device.did, {
                ip: cleanIp(req.ip), ua: String(req.headers['user-agent'] || '').slice(0, 300), at: Date.now()
            });
        } catch (e) {}
        next();
    });
    setInterval(() => {
        const old = Date.now() - 30 * 60 * 1000;
        for (const [k, v] of meta) if (v.at < old) meta.delete(k);
        for (const [k, v] of geo) if (Date.now() - v.at > v.ttl) geo.delete(k);
    }, 10 * 60 * 1000).unref();

    async function lookup(ip) {
        const c = geo.get(ip);
        if (c && Date.now() - c.at < c.ttl) return c.v;
        const ctrl = new AbortController(), t = setTimeout(() => ctrl.abort(), 4000);
        try {
            const r = await fetch('https://ipwho.is/' + encodeURIComponent(ip), { signal: ctrl.signal });
            const j = await r.json();
            if (j && j.success) {
                const v = { country_code: j.country_code || '', city: j.city || '', isp: (j.connection && (j.connection.isp || j.connection.org)) || '' };
                geo.set(ip, { at: Date.now(), ttl: GEO_TTL_MS, v });
                return v;
            }
        } catch (e) {} finally { clearTimeout(t); }
        geo.set(ip, { at: Date.now(), ttl: GEO_FAIL_TTL_MS, v: {} });
        return {};
    }

    app.get(['/admin/live-connections', '/api/admin/live-connections'], async (req, res) => {
        try {
            const since = new Date(Date.now() - WINDOW_MS).toISOString();
            const { data: devs, error } = await supabase.from('code_devices')
                .select('code_id, device_id, device_name, last_seen, last_channel')
                .gte('last_seen', since).order('last_seen', { ascending: false }).limit(500);
            if (error) throw error;
            if (!devs || !devs.length) return res.json({ success: true, data: [] });

            const ids = [...new Set(devs.map(d => d.code_id))];
            const { data: codes } = await supabase.from('activation_codes').select('id, code, customer_name').in('id', ids);
            const codeMap = new Map((codes || []).map(c => [c.id, c]));

            // احتياط: آخر IP سُجّل عند التفعيل (إن لم يصل نبض بعد إعادة تشغيل السيرفر)
            const loginIp = new Map();
            try {
                const { data: logs } = await supabase.from('code_login_log').select('code_id, device_id, ip').in('code_id', ids).order('id', { ascending: false }).limit(2000);
                (logs || []).forEach(l => { const k = l.code_id + ':' + l.device_id; if (!loginIp.has(k)) loginIp.set(k, cleanIp(l.ip)); });
            } catch (e) {}

            const rows = devs.map(d => {
                const k = d.code_id + ':' + d.device_id, m = meta.get(k), c = codeMap.get(d.code_id) || {};
                return { d, c, ip: (m && m.ip) || loginIp.get(k) || '', ua: (m && m.ua) || '' };
            });

            const ips = [...new Set(rows.map(r => r.ip).filter(ip => ip && !isPrivate(ip)))];
            for (let i = 0; i < ips.length; i += 5) await Promise.all(ips.slice(i, i + 5).map(lookup));

            res.json({
                success: true,
                data: rows.map(({ d, c, ip, ua }) => {
                    const g = (ip && geo.get(ip) && geo.get(ip).v) || {};
                    return {
                        user: c.code || String(d.code_id), customer_name: c.customer_name || '', device_name: d.device_name || '',
                        stream: d.last_channel || '', user_agent: ua, ip,
                        country_code: g.country_code || '', isp: g.isp || '', city: g.city || '',
                        at: d.last_seen, status: 'active'
                    };
                })
            });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });
};
