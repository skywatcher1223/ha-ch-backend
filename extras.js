// extras.js — ميزات إضافية للسيرفر دون تعديل أي مسار قائم في server.js:
//   1) جدولة الإشعارات واستهدافها لعملاء معيّنين
//   2) إحصاءات المشاهدة (أكثر القنوات مشاهدة + أوقات الذروة)
//   3) استرجاع النسخة الاحتياطية (للمدير فقط، دمج بدون حذف)
//   4) ترتيب القنوات (سحب وإفلات من اللوحة)
//
// التركيب في server.js: سطر واحد مباشرة بعد إنشاء supabase:
//     require('./extras')(app, { supabase, fetchAll, logAction });
// ثم نفّذ ملف extras.sql في Supabase (SQL Editor).
//
// المصادقة والصلاحيات: تتم في الـ middleware الموجود أصلاً في server.js
// (مسارات /admin/* و /notifications/:id للمدير والمشغل "كاملة" فقط، و /channels/* للمشغلين أيضاً).

module.exports = function registerExtras(app, { supabase, fetchAll, logAction }) {
    const isMissing = (e) => /schema cache|does not exist|could not find|column .* of relation/i.test(String(e && e.message));
    const SQL_HINT = 'نفّذ ملف extras.sql في Supabase أولاً';

    // ---------------------------------------------------------------------
    // 1) الإشعارات: جدولة + استهداف
    // ---------------------------------------------------------------------
    const parseCodes = (v) => {
        let a = v;
        if (typeof a === 'string') { try { a = JSON.parse(a); } catch (e) { a = []; } }
        if (!Array.isArray(a)) return [];
        return [...new Set(a.map(Number).filter(n => Number.isInteger(n) && n > 0))];
    };

    // يُسجَّل قبل مسار GET /notifications الأصلي فيأخذ الأولوية
    app.get(['/notifications', '/api/notifications'], async (req, res) => {
        try {
            const { data, error } = await supabase.from('system_notifications')
                .select('*').order('created_at', { ascending: false });
            if (error) throw error;
            const now = Date.now();
            if (req.device) {
                // التطبيق: لا يرى المجدولة غير المستحقة ولا ما استُهدف به غيره
                const cid = Number(req.device.cid);
                const out = (data || []).filter(n => {
                    if (n.send_at && new Date(n.send_at).getTime() > now) return false;
                    const t = parseCodes(n.target_codes);
                    return !t.length || t.includes(cid);
                }).map(n => {
                    const { target_codes, send_at, ...rest } = n;
                    return { ...rest, created_at: send_at || n.created_at }; // وقت الاستحقاق = وقت الظهور
                }).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
                return res.json({ success: true, data: out });
            }
            res.json({
                success: true,
                data: (data || []).map(n => ({
                    ...n,
                    target_codes: parseCodes(n.target_codes),
                    pending: !!(n.send_at && new Date(n.send_at).getTime() > now)
                }))
            });
        } catch (err) {
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.post(['/notifications', '/api/notifications'], async (req, res) => {
        try {
            const { title, body, target_group, operator_name, send_at, target_codes } = req.body || {};
            if (!String(title || '').trim() || !String(body || '').trim())
                return res.status(400).json({ success: false, message: 'العنوان والمحتوى مطلوبان' });
            const row = { title: String(title).slice(0, 80), body: String(body).slice(0, 400), target_group: target_group || 'all' };
            let when = null;
            if (send_at) {
                when = new Date(send_at);
                if (isNaN(when)) return res.status(400).json({ success: false, message: 'وقت الجدولة غير صالح' });
                row.send_at = when.toISOString();
            }
            const codes = parseCodes(target_codes);
            if (codes.length > 2000) return res.status(400).json({ success: false, message: 'عدد العملاء المستهدفين كبير جداً' });
            if (codes.length) row.target_codes = codes;

            const { data, error } = await supabase.from('system_notifications').insert([row]).select();
            if (error) {
                if ((row.send_at || row.target_codes) && isMissing(error))
                    return res.status(500).json({ success: false, message: 'أعمدة الجدولة/الاستهداف غير موجودة: ' + SQL_HINT });
                throw error;
            }
            await logAction(operator_name, 'إرسال إشعار',
                `${when ? 'جدولة' : 'أرسل'} إشعاراً بعنوان: (${row.title})` +
                (codes.length ? ` لـ ${codes.length} عميل محدد` : ' لكل العملاء') +
                (when ? ` في ${when.toISOString()}` : ''));
            res.json({ success: true, message: when ? 'تمت جدولة الإشعار' : 'تم إرسال وحفظ الإشعار بنجاح', data });
        } catch (err) {
            res.status(500).json({ success: false, error: err.message, message: err.message });
        }
    });

    app.delete(['/notifications/:id', '/api/notifications/:id'], async (req, res) => {
        try {
            const id = Number(req.params.id);
            if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ success: false, message: 'معرّف غير صالح' });
            const { error } = await supabase.from('system_notifications').delete().eq('id', id);
            if (error) throw error;
            await logAction(req.user && req.user.name, 'حذف إشعار', 'حذف/إلغاء الإشعار رقم ' + id);
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    // ---------------------------------------------------------------------
    // 2) إحصاءات المشاهدة
    //    نلتقط نبضات /heartbeat (قبل المسار الأصلي) ونجمّعها بالساعة في الذاكرة،
    //    ثم نحفظها كل دقيقة في جدول watch_stats.
    // ---------------------------------------------------------------------
    const devState = new Map();      // "cid:did" -> { ch, at }
    let pending = new Map();         // "hourISO|channel" -> { hour, channel, views, seconds }
    let flushing = false, lastWarn = 0, lastPurge = 0;

    const bump = (hour, channel, views, seconds) => {
        const k = hour + '|' + channel;
        const e = pending.get(k) || { hour, channel, views: 0, seconds: 0 };
        e.views += views; e.seconds += seconds;
        pending.set(k, e);
    };

    app.post(['/heartbeat', '/api/heartbeat'], (req, res, next) => {
        try {
            if (req.device) {
                const ch = req.body && req.body.channel_name ? String(req.body.channel_name).slice(0, 120).trim() : '';
                const k = req.device.cid + ':' + req.device.did, now = Date.now(), prev = devState.get(k);
                if (ch) {
                    const hour = new Date(Math.floor(now / 3600000) * 3600000).toISOString();
                    const sameSession = prev && prev.ch === ch && now - prev.at <= 5 * 60 * 1000;
                    // مشاهدة جديدة عند تغيّر القناة أو بعد انقطاع أكثر من 5 دقائق
                    // والمدة = الفاصل بين نبضتين متتاليتين لنفس القناة (بحد أقصى دقيقتين للنبضة)
                    bump(hour, ch, sameSession ? 0 : 1, sameSession ? Math.min(now - prev.at, 120000) / 1000 : 0);
                    devState.set(k, { ch, at: now });
                } else if (prev) devState.delete(k);
            }
        } catch (e) { /* لا نعطّل النبضة أبداً */ }
        next();
    });

    async function flush() {
        if (flushing || !pending.size) return;
        flushing = true;
        const batch = [...pending.values()];
        pending = new Map();
        try {
            const hours = [...new Set(batch.map(e => e.hour))];
            const { data: ex, error } = await supabase.from('watch_stats').select('hour, channel, views, seconds').in('hour', hours);
            if (error) throw error;
            const cur = new Map((ex || []).map(r => [new Date(r.hour).toISOString() + '|' + r.channel, r]));
            const rows = batch.map(e => {
                const r = cur.get(e.hour + '|' + e.channel);
                return { hour: e.hour, channel: e.channel, views: (r ? r.views : 0) + e.views, seconds: (r ? r.seconds : 0) + Math.round(e.seconds) };
            });
            for (let i = 0; i < rows.length; i += 500) {
                const { error: uErr } = await supabase.from('watch_stats').upsert(rows.slice(i, i + 500), { onConflict: 'hour,channel' });
                if (uErr) throw uErr;
            }
            // تنظيف يومي: نحتفظ بآخر 90 يوماً فقط
            if (Date.now() - lastPurge > 24 * 3600 * 1000) {
                lastPurge = Date.now();
                await supabase.from('watch_stats').delete().lt('hour', new Date(Date.now() - 90 * 864e5).toISOString());
            }
        } catch (e) {
            if (Date.now() - lastWarn > 30 * 60 * 1000) { lastWarn = Date.now(); console.warn('watch_stats:', e.message); }
            for (const e2 of batch) bump(e2.hour, e2.channel, e2.views, e2.seconds); // نعيدها للمحاولة لاحقاً
            if (pending.size > 20000) pending = new Map(); // سقف لمنع تضخّم الذاكرة
        } finally { flushing = false; }
    }
    setInterval(flush, 60 * 1000).unref();
    setInterval(() => { const old = Date.now() - 30 * 60 * 1000; for (const [k, v] of devState) if (v.at < old) devState.delete(k); }, 10 * 60 * 1000).unref();

    const hourFmt = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', hourCycle: 'h23', timeZone: 'Africa/Tunis' });
    app.get(['/admin/watch-stats', '/api/admin/watch-stats'], async (req, res) => {
        try {
            const days = Math.min(90, Math.max(1, parseInt(req.query.days, 10) || 7));
            const since = new Date(Date.now() - days * 864e5).toISOString();
            let rows;
            try {
                rows = await fetchAll(() => supabase.from('watch_stats').select('hour, channel, views, seconds')
                    .gte('hour', since).order('hour').order('channel'));
            } catch (e) {
                if (isMissing(e)) return res.status(500).json({ success: false, message: 'جدول watch_stats غير موجود: ' + SQL_HINT });
                throw e;
            }
            // ندمج ما لم يُحفظ بعد (آخر دقيقة)
            rows = rows.concat([...pending.values()].filter(e => e.hour >= since));
            const top = new Map(), hours = Array.from({ length: 24 }, (_, h) => ({ h, minutes: 0, views: 0 }));
            let totalSec = 0, totalViews = 0;
            for (const r of rows) {
                const sec = Number(r.seconds) || 0, v = Number(r.views) || 0;
                const t = top.get(r.channel) || { channel: r.channel, views: 0, seconds: 0 };
                t.views += v; t.seconds += sec; top.set(r.channel, t);
                const h = parseInt(hourFmt.format(new Date(r.hour)), 10) % 24;
                hours[h].minutes += sec / 60; hours[h].views += v;
                totalSec += sec; totalViews += v;
            }
            res.json({
                success: true,
                data: {
                    days, total_minutes: Math.round(totalSec / 60), total_views: totalViews, channels_count: top.size,
                    top: [...top.values()].sort((a, b) => b.seconds - a.seconds || b.views - a.views).slice(0, 25)
                        .map(t => ({ channel: t.channel, views: t.views, minutes: Math.round(t.seconds / 60) })),
                    hours: hours.map(x => ({ h: x.h, minutes: Math.round(x.minutes), views: x.views }))
                }
            });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    // ---------------------------------------------------------------------
    // 3) استرجاع النسخة الاحتياطية (للمدير فقط) — دمج (upsert) بدون أي حذف
    //    اللوحة ترسل الجداول على دفعات صغيرة (لا نتجاوز حد 5MB للطلب الواحد).
    //    جدول operators مستثنى عمداً (النسخة لا تحوي كلمات المرور).
    // ---------------------------------------------------------------------
    const RESTORE = {
        categories: 'id', plans: 'id', activation_codes: 'id', code_devices: 'code_id,device_id', code_payments: 'id',
        channels: 'id', matches_schedule: 'id', system_notifications: 'id', channel_reports: 'id', app_settings: 'key'
    };
    const COL = /^[a-z_][a-z0-9_]*$/i;
    const clean = (table, r) => {
        if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
        const o = {};
        for (const [k, v] of Object.entries(r)) { if (COL.test(k) && !(table === 'code_devices' && k === 'id')) o[k] = v; }
        return Object.keys(o).length ? o : null;
    };

    app.post(['/admin/restore-chunk', '/api/admin/restore-chunk'], async (req, res) => {
        try {
            if (!req.user || req.user.role !== 'master') return res.status(403).json({ success: false, message: 'للمدير فقط' });
            const b = req.body || {};
            if (!b.table && b.note) { // تسجيل بداية/نهاية الاسترجاع في سجل العمليات
                await logAction(req.user.name, 'استرجاع نسخة احتياطية', String(b.note).slice(0, 300));
                return res.json({ success: true });
            }
            const table = String(b.table || '');
            if (!Object.prototype.hasOwnProperty.call(RESTORE, table)) return res.status(400).json({ success: false, message: 'جدول غير مسموح بالاسترجاع' });
            if (!Array.isArray(b.rows) || !b.rows.length || b.rows.length > 1000) return res.status(400).json({ success: false, message: 'دفعة غير صالحة' });
            const rows = b.rows.map(r => clean(table, r)).filter(Boolean);
            const onConflict = RESTORE[table];
            let ok = 0, failed = 0, firstError = '';

            const { error } = await supabase.from(table).upsert(rows, { onConflict });
            if (!error) ok = rows.length;
            else {
                // نعزل الصفوف المعطوبة: صف بصف على دفعات صغيرة
                for (let i = 0; i < rows.length; i += 10) {
                    await Promise.all(rows.slice(i, i + 10).map(async r => {
                        const { error: e1 } = await supabase.from(table).upsert([r], { onConflict });
                        if (e1) { failed++; if (!firstError) firstError = e1.message; } else ok++;
                    }));
                }
            }
            res.json({ success: true, ok, failed, error: firstError });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    // ---------------------------------------------------------------------
    // 4) ترتيب القنوات
    //    عمود channels.sort_order (فارغ = الترتيب الأصلي). نعيد ترتيب مصفوفة /channels
    //    قبل إرسالها، فيستفيد التطبيق واللوحة دون تغيير مسار /channels الأصلي.
    // ---------------------------------------------------------------------
    const byOrder = (arr) => arr.map((c, i) => ({ c, i })).sort((a, b) => {
        const x = a.c && a.c.sort_order, y = b.c && b.c.sort_order, hx = x != null, hy = y != null;
        if (hx && hy) return (x - y) || (a.i - b.i);
        if (hx !== hy) return hx ? -1 : 1;
        return a.i - b.i;
    }).map(o => o.c);

    app.get(['/channels', '/api/channels'], (req, res, next) => {
        const orig = res.json.bind(res);
        res.json = (body) => {
            try {
                if (body && body.success && Array.isArray(body.data) && body.data.some(c => c && c.sort_order != null)) body.data = byOrder(body.data);
            } catch (e) { /* نُرجع البيانات كما هي */ }
            return orig(body);
        };
        next();
    });

    app.post(['/channels/reorder', '/api/channels/reorder'], async (req, res) => {
        try {
            const b = req.body || {};
            const ids = [...new Set((Array.isArray(b.ids) ? b.ids : []).map(Number).filter(n => Number.isInteger(n) && n > 0))];
            if (!ids.length || ids.length > 5000) return res.status(400).json({ success: false, message: 'قائمة القنوات غير صالحة' });
            let failed = 0, firstError = '';
            for (let i = 0; i < ids.length; i += 20) {
                await Promise.all(ids.slice(i, i + 20).map(async (id, j) => {
                    const { error } = await supabase.from('channels').update({ sort_order: i + j + 1 }).eq('id', id);
                    if (error) { failed++; if (!firstError) firstError = error.message; }
                }));
            }
            if (failed === ids.length && /sort_order|schema cache|column/i.test(firstError))
                return res.status(500).json({ success: false, message: 'عمود sort_order غير موجود: ' + SQL_HINT });
            await logAction(b.operator_name, 'ترتيب القنوات', `إعادة ترتيب ${ids.length} قناة` + (b.category ? ` في التصنيف: (${String(b.category).slice(0, 60)})` : ''));
            res.json({ success: failed === 0, updated: ids.length - failed, failed, message: failed ? firstError : undefined });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });
};
