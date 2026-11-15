const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const registerHealthRoutes = require('./health-check');

const app = express();
app.use(express.json());
const crypto = require('crypto');
app.set('trust proxy', 1); // خلف Render: للحصول على IP الحقيقي

// CORS: حدّد دومين اللوحة في CORS_ORIGIN (يفصل بينها بفاصلة)، وإن تُرك فارغاً يُسمح للجميع
const corsOrigins = (process.env.CORS_ORIGIN || '').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors(corsOrigins.length ? { origin: corsOrigins } : {}));

// ================= المصادقة =================
const ADMIN_KEY = process.env.ADMIN_KEY;       // المفتاح الرئيسي للمدير (يُكتب في خانة اسم المستخدم)
const AUTH_SECRET = process.env.AUTH_SECRET;   // سر توقيع التوكن (نص عشوائي طويل)
if (!ADMIN_KEY || !AUTH_SECRET) {
    console.error('❌ يجب ضبط ADMIN_KEY و AUTH_SECRET في متغيرات البيئة (Render → Environment).');
    process.exit(1);
}
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const hmac = (body) => crypto.createHmac('sha256', AUTH_SECRET).update(body).digest('base64url');
function signToken(payload, ttl = TOKEN_TTL_MS) {
    const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + ttl })).toString('base64url');
    return body + '.' + hmac(body);
}
function verifyToken(token) {
    try {
        const [body, sig] = String(token || '').split('.');
        if (!body || !sig) return null;
        const a = Buffer.from(sig), b = Buffer.from(hmac(body));
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
        const p = JSON.parse(Buffer.from(body, 'base64url').toString());
        return p.exp > Date.now() ? p : null;
    } catch (e) { return null; }
}
const safeEq = (a, b) => crypto.timingSafeEqual(
    crypto.createHash('sha256').update(String(a)).digest(),
    crypto.createHash('sha256').update(String(b)).digest());

const scrypt = require('util').promisify(crypto.scrypt);
async function hashPw(pw) {
    const salt = crypto.randomBytes(16).toString('hex');
    return 'scrypt$' + salt + '$' + (await scrypt(String(pw), salt, 64)).toString('hex');
}
async function checkPw(pw, stored) {
    if (!stored) return false;
    if (!String(stored).startsWith('scrypt$')) return safeEq(pw, stored); // كلمة مرور قديمة نصية: تُرقّى عند أول دخول
    const [, salt, hex] = String(stored).split('$');
    const calc = await scrypt(String(pw), salt, 64), want = Buffer.from(hex, 'hex');
    return calc.length === want.length && crypto.timingSafeEqual(calc, want);
}

// جلب كل الصفوف على دفعات (Supabase يعيد 1000 صف كحد أقصى في الطلب الواحد)
async function fetchAll(build) {
    const out = [];
    for (let from = 0; ; from += 1000) {
        const { data, error } = await build().range(from, from + 999);
        if (error) throw error;
        out.push(...data);
        if (data.length < 1000) break;
    }
    return out;
}
// تنبيهات تلغرام (اختياري): TELEGRAM_BOT_TOKEN و TELEGRAM_CHAT_ID
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN, TG_CHAT = process.env.TELEGRAM_CHAT_ID;
const tgLast = new Map();
async function notifyTG(text, key) {
    if (!TG_TOKEN || !TG_CHAT) return false;
    const now = Date.now();
    if (key) { if (now - (tgLast.get(key) || 0) < 30 * 60 * 1000) return false; tgLast.set(key, now); }
    try {
        const r = await fetch('https://api.telegram.org/bot' + TG_TOKEN + '/sendMessage', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: TG_CHAT, text: String(text).slice(0, 3500) })
        });
        return r.ok;
    } catch (e) { return false; }
}
process.on('unhandledRejection', (e) => { console.error('unhandledRejection:', e && e.message); notifyTG('❗ خطأ غير معالج في السيرفر: ' + (e && e.message), 'unhandled'); });
const opCache = new Map(); // حالة المشغلين (تُحدَّث كل 15 ثانية)
const linkStatus = new Map(); // نتائج فحص الروابط (للتبديل التلقائي)
const makeLimiter = (max, windowMs) => {
    const m = new Map();
    return {
        blocked: (k) => { const f = m.get(k); return !!f && f.n >= max && f.until > Date.now(); },
        fail: (k) => { const f = m.get(k), now = Date.now(); if (!f || f.until <= now) m.set(k, { n: 1, until: now + windowMs }); else f.n++; }
    };
};
const codeLimiter = makeLimiter(20, 15 * 60 * 1000); // 20 كوداً خاطئاً لكل IP كل 15 دقيقة

// تحديد محاولات الدخول الفاشلة: 5 محاولات لكل IP كل 15 دقيقة
const loginFails = new Map();
const loginBlocked = (ip) => { const f = loginFails.get(ip); return !!f && f.n >= 5 && f.until > Date.now(); };
const loginFail = (ip) => {
    const f = loginFails.get(ip), now = Date.now();
    if (!f || f.until <= now) loginFails.set(ip, { n: 1, until: now + 15 * 60 * 1000 }); else f.n++;
};
setInterval(() => { const n = Date.now(); for (const [k, v] of loginFails) if (v.until <= n) loginFails.delete(k); }, 3600000).unref();

// المسارات المفتوحة (يستعملها تطبيق التلفاز) — أي مسار غيرها يتطلب توكناً
const PUBLIC_ROUTES = new Set(['GET /', 'GET /app-config', 'POST /verify-code', 'POST /operator-login']);
// مسارات يقرؤها تطبيق التلفاز: تتطلب تذكرة جهاز عند تفعيل REQUIRE_DEVICE_AUTH=1 في Render
const DEVICE_ROUTES = new Set(['GET /channels', 'GET /categories', 'GET /matches', 'GET /notifications', 'POST /heartbeat', 'POST /report-channel']);
const REQUIRE_DEVICE_AUTH = process.env.REQUIRE_DEVICE_AUTH === '1';
const DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
// مشغل بصلاحية "قنوات فقط" يصل لهذه المسارات فقط
const LIMITED_OK = /^\/(channels|categories|matches|stats|admin\/check-streams?)(\/|$)/;

app.use(async (req, res, next) => {
    try {
        if (req.method === 'OPTIONS') return next();
        const path = req.path.replace(/^\/api(?=\/|$)/, '') || '/';
        const key = req.method + ' ' + path;
        if (PUBLIC_ROUTES.has(key)) return next();

        const h = req.headers.authorization || '';
        const user = verifyToken(h.startsWith('Bearer ') ? h.slice(7) : '');

        if (DEVICE_ROUTES.has(key)) {
            if (!user) {
                if (!REQUIRE_DEVICE_AUTH) return next(); // وضع الانتقال: ما زال مفتوحاً
                return res.status(401).json({ success: false, message: 'يلزم تفعيل التطبيق بكود صالح' });
            }
            if (user.role === 'device') {
                // نتحقق من حالة الكود في كل طلب، فيسري الحظر والانتهاء فوراً
                const { data } = await supabase.from('activation_codes')
                    .select('is_blocked, status, expires_at, used_by_device').eq('id', user.cid).single();
                let okDev = false;
                if (data) {
                    let { data: row, error: rErr } = await supabase.from('code_devices').select('id, is_blocked').eq('code_id', user.cid).eq('device_id', user.did).maybeSingle();
                    if (rErr) ({ data: row } = await supabase.from('code_devices').select('id').eq('code_id', user.cid).eq('device_id', user.did).maybeSingle());
                    okDev = row ? !row.is_blocked : data.used_by_device === user.did;
                }
                if (!data || data.is_blocked || isExpired(data) || !okDev)
                    return res.status(403).json({ success: false, message: 'الكود غير صالح أو منتهي أو مرتبط بجهاز آخر' });
                req.device = user;
                return next();
            }
            // مستخدم اللوحة: يتابع الفحوص أدناه
        } else if (!user) {
            return res.status(401).json({ success: false, message: 'يلزم تسجيل الدخول' });
        }
        if (user.role === 'device')
            return res.status(403).json({ success: false, message: 'غير مسموح' });

        if (user.role !== 'master') {
            // إيقاف أو حذف المشغل يسري فوراً، وتغيير صلاحيته يُؤخذ من القاعدة لا من التوكن
            let row = opCache.get(user.name);
            if (!row || row.at < Date.now() - 15000) {
                const { data: ops } = await supabase.from('operators').select('is_active, role').eq('name', user.name).limit(1);
                row = { at: Date.now(), data: ops && ops[0] };
                opCache.set(user.name, row);
            }
            if (!row.data || !row.data.is_active) return res.status(401).json({ success: false, message: 'الحساب موقوف أو محذوف' });
            user.role = row.data.role;
        }
        const master = user.role === 'master';
        if (/^\/operators(\/|$)/.test(path) && !master)
            return res.status(403).json({ success: false, message: 'هذه العملية للمدير فقط' });
        if (!master && user.role !== 'كاملة' && !LIMITED_OK.test(path))
            return res.status(403).json({ success: false, message: 'صلاحيتك لا تسمح بهذه العملية' });

        req.user = user;
        // هوية المشغل تُؤخذ من التوكن لا من الطلب (لمنع تزوير سجل العمليات)
        if (req.body && typeof req.body === 'object') req.body.operator_name = user.name;
        next();
    } catch (err) {
        res.status(500).json({ success: false, message: 'خطأ في التحقق' });
    }
});

// الاتصال بقاعدة بيانات Supabase — القيم تُقرأ من متغيرات البيئة (لا تكتب المفتاح داخل الكود)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
if (!supabaseUrl || !supabaseKey) {
    console.error('❌ يجب ضبط SUPABASE_URL و SUPABASE_KEY في متغيرات البيئة (Render → Environment).');
    process.exit(1);
}
const supabase = createClient(supabaseUrl, supabaseKey);

// دالة مساعدة لتسجيل العمليات تلقائياً في جدول audit_logs
async function logAction(operatorName, actionType, details) {
    try {
        await supabase.from('audit_logs').insert([{
            operator_name: operatorName || 'Master Admin',
            action_type: actionType,
            details: details
        }]);
    } catch (err) {
        console.error('خطأ أثناء تسجيل العمليات:', err.message);
    }
}

// هل انتهت صلاحية الكود فعلياً؟ (حسب التاريخ وليس فقط حقل status)
function isExpired(code) {
    if (code.status === 'expired') return true;
    return !!(code.expires_at && new Date(code.expires_at).getTime() < Date.now());
}

// لا نُرجع كلمة مرور المشغل للمتصفح أبداً
const safeOp = (o) => { if (!o) return o; const { password, ...rest } = o; return rest; };

// المسار الجذري
app.get('/', (req, res) => {
    res.status(200).json({
        status: 'success',
        message: '🚀 HA TV Backend is running successfully!'
    });
});

// 1. مسارات القنوات
app.get(['/channels', '/api/channels'], async (req, res) => {
    try {
        const data = await fetchAll(() => supabase.from('channels').select('*').order('id'));
        // active_url: الرابط الذي يجب أن يستعمله التطبيق (يتبدّل للبديل عند تفعيل AUTO_FAILOVER)
        res.json({ success: true, data: data.filter(c => req.user || c.status !== 'hidden').map(c => { const st = linkStatus.get(c.id); return { ...c, active_url: (st && st.active_url) || c.primary_url, failover: !!(st && !st.down && !st.primary_ok), link_down: !!(st && st.down) }; }) });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/channels', '/api/channels'], async (req, res) => {
    try {
        const { name, category, primary_url, alt_url_1, alt_url_2, alt_url_3, logo_url, tvg_id, operator_name } = req.body;
        const row = { name, category, primary_url, alt_url_1, alt_url_2, alt_url_3 };
        // الحقلان يتطلبان تنفيذ ALTER TABLE أولاً؛ نرسلهما فقط عند وجود قيمة
        if (logo_url) row.logo_url = logo_url;
        if (tvg_id) row.tvg_id = tvg_id;
        const { data, error } = await supabase.from('channels').insert([row]);

        if (error) throw error;

        await logAction(operator_name, 'إضافة قناة', `أضاف القناة: ${name}`);

        res.json({ success: true, message: 'تم إضافة القناة بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/channels/delete-all', '/api/channels/delete-all'], async (req, res) => {
    try {
        if (!req.user || req.user.role !== 'master') return res.status(403).json({ success: false, message: 'للمدير الرئيسي فقط' });
        const { confirm_text, operator_name } = req.body;
        if (confirm_text !== 'حذف الكل') return res.status(400).json({ success: false, message: 'عبارة التأكيد غير صحيحة' });
        await supabase.from('channel_health_logs').delete().not('id', 'is', null);
        const { error, count } = await supabase.from('channels').delete({ count: 'exact' }).not('id', 'is', null);
        if (error) throw error;
        linkStatus.clear();
        await logAction(operator_name, 'حذف كل القنوات', `حُذفت ${count == null ? 'كل' : count} قناة`);
        res.json({ success: true, deleted: count });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post(['/channels/bulk-alt', '/api/channels/bulk-alt'], async (req, res) => {
    try {
        const { slot, items, operator_name } = req.body;
        const n = parseInt(slot);
        if (![1, 2, 3].includes(n) || !Array.isArray(items) || !items.length)
            return res.status(400).json({ success: false, message: 'بيانات غير صالحة' });
        const col = 'alt_url_' + n;
        const list = items.slice(0, 1000).filter(i => i && i.id != null && typeof i.url === 'string' && /^https?:\/\//i.test(i.url.trim()));
        let ok = 0, fail = 0;
        for (let i = 0; i < list.length; i += 10) {
            await Promise.all(list.slice(i, i + 10).map(async it => {
                const { error } = await supabase.from('channels').update({ [col]: it.url.trim() }).eq('id', it.id);
                error ? fail++ : ok++;
            }));
        }
        await logAction(operator_name, 'روابط احتياطية', `حُفظ «احتياطي ${n}» لـ ${ok} قناة`);
        res.json({ success: true, updated: ok, failed: fail });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post(['/channels/bulk-category', '/api/channels/bulk-category'], async (req, res) => {
    try {
        const { ids, category, operator_name } = req.body;
        if (!Array.isArray(ids) || !ids.length || !category) return res.status(400).json({ success: false, message: 'حدد القنوات والتصنيف' });
        const { data, error } = await supabase.from('channels').update({ category }).in('id', ids).select('id');
        if (error) throw error;
        await logAction(operator_name, 'نقل قنوات', `نقل ${data.length} قناة إلى التصنيف: ${category}`);
        res.json({ success: true, updated: data.length });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

app.put(['/channels/:id', '/api/channels/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { name, category, primary_url, operator_name } = req.body;
        const alts = {};
        ['alt_url_1', 'alt_url_2', 'alt_url_3'].forEach(k => { if (req.body[k] !== undefined) alts[k] = req.body[k] || null; });
        if (!name || !primary_url) return res.status(400).json({ success: false, message: 'الاسم والرابط مطلوبان' });
        const { data, error } = await supabase
            .from('channels')
            .update({ name, category, primary_url, ...alts })
            .eq('id', id)
            .select();
        if (error) throw error;
        if (!data || !data.length) return res.status(404).json({ success: false, message: 'القناة غير موجودة' });

        await logAction(operator_name, 'تعديل قناة', `عدّل القناة: ${name} (ID: ${id})`);
        res.json({ success: true, message: 'تم حفظ التعديل', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

app.delete(['/channels/:id', '/api/channels/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { operator_name } = req.body || {};
        // حذف سجلات الفحص المرتبطة أولاً حتى لا يفشل الحذف بسبب مفتاح خارجي (إن وُجد)
        await supabase.from('channel_health_logs').delete().eq('channel_id', id);
        const { data, error } = await supabase.from('channels').delete().eq('id', id).select();
        if (error) throw error;
        if (!data || !data.length) return res.status(404).json({ success: false, message: 'القناة غير موجودة' });

        await logAction(operator_name, 'حذف قناة', `حذف القناة: ${data[0].name} (ID: ${id})`);
        res.json({ success: true, message: 'تم حذف القناة' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

// 2. مسارات التصنيفات (Categories)
app.get(['/categories', '/api/categories'], async (req, res) => {
    try {
        const { data, error } = await supabase.from('categories').select('*');
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/categories', '/api/categories'], async (req, res) => {
    try {
        const { operator_name } = req.body;
        const name = String(req.body.name || '').replace(/\s+/g, ' ').trim().slice(0, 60);
        if (!name) return res.status(400).json({ success: false, message: 'اسم التصنيف مطلوب' });
        const { data: ex } = await supabase.from('categories').select('name');
        if ((ex || []).some(c => String(c.name).trim().toLowerCase() === name.toLowerCase()))
            return res.status(409).json({ success: false, message: 'التصنيف موجود مسبقاً' });
        const { data, error } = await supabase.from('categories').insert([{ name }]);
        if (error) throw error;

        await logAction(operator_name, 'إضافة تصنيف', `أضاف التصنيف: ${name}`);

        res.json({ success: true, message: 'تم إضافة التصنيف بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/categories/bulk', '/api/categories/bulk'], async (req, res) => {
    try {
        const { names, operator_name } = req.body;
        if (!Array.isArray(names) || !names.length) return res.status(400).json({ success: false, message: 'لا توجد تصنيفات' });
        const norm = (n) => String(n || '').replace(/\s+/g, ' ').trim().slice(0, 60);
        const clean = [...new Set(names.map(norm).filter(Boolean))].slice(0, 500);
        const { data: ex, error: e1 } = await supabase.from('categories').select('name');
        if (e1) throw e1;
        const canon = new Map((ex || []).map(c => [String(c.name).trim().toLowerCase(), c.name]));
        const toAdd = clean.filter(n => !canon.has(n.toLowerCase()));
        if (toAdd.length) {
            const { error } = await supabase.from('categories').insert(toAdd.map(name => ({ name })));
            if (error) throw error;
            toAdd.forEach(n => canon.set(n.toLowerCase(), n));
            await logAction(operator_name, 'إضافة تصنيفات', `أُنشئت تلقائياً من M3U: ${toAdd.slice(0, 10).join('، ')}${toAdd.length > 10 ? '…' : ''}`);
        }
        // map: الاسم المُرسل -> الاسم المعتمد في القاعدة (لتفادي اختلاف حالة الأحرف)
        const map = {};
        clean.forEach(n => { map[n] = canon.get(n.toLowerCase()) || n; });
        res.json({ success: true, created: toAdd, map });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put(['/categories/:id', '/api/categories/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { operator_name } = req.body;
        const n = String(req.body.name || '').replace(/\s+/g, ' ').trim().slice(0, 60);
        if (!n) return res.status(400).json({ success: false, message: 'الاسم الجديد مطلوب' });
        const { data: all, error: e0 } = await supabase.from('categories').select('id, name');
        if (e0) throw e0;
        const cur = all.find(c => String(c.id) === String(id));
        if (!cur) return res.status(404).json({ success: false, message: 'التصنيف غير موجود' });
        if (all.some(c => String(c.id) !== String(id) && String(c.name).trim().toLowerCase() === n.toLowerCase()))
            return res.status(409).json({ success: false, message: 'يوجد تصنيف بهذا الاسم' });
        const { error } = await supabase.from('categories').update({ name: n }).eq('id', id);
        if (error) throw error;
        const { data: moved } = await supabase.from('channels').update({ category: n }).eq('category', cur.name).select('id');
        await logAction(operator_name, 'تعديل تصنيف', `أعاد تسمية التصنيف «${cur.name}» إلى «${n}» (${moved ? moved.length : 0} قناة)`);
        res.json({ success: true, updated: moved ? moved.length : 0 });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete(['/categories/:id', '/api/categories/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { operator_name } = req.body || {};
        const { data: cat } = await supabase.from('categories').select('name').eq('id', id).maybeSingle();
        if (!cat) return res.status(404).json({ success: false, message: 'التصنيف غير موجود' });
        const { error } = await supabase.from('categories').delete().eq('id', id);
        if (error) throw error;
        // القنوات التي كانت في هذا التصنيف تنتقل إلى «عامة» بدل أن تبقى مرتبطة باسم محذوف
        let moved = 0;
        if (cat.name !== 'عامة') {
            const { data: m } = await supabase.from('channels').update({ category: 'عامة' }).eq('category', cat.name).select('id');
            moved = m ? m.length : 0;
            if (moved) {
                const { data: g } = await supabase.from('categories').select('id').eq('name', 'عامة').limit(1);
                if (!g || !g.length) await supabase.from('categories').insert([{ name: 'عامة' }]);
            }
        }
        await logAction(operator_name, 'حذف تصنيف', `حذف التصنيف «${cat.name}» (نُقلت ${moved} قناة إلى «عامة»)`);
        res.json({ success: true, message: 'تم حذف التصنيف بنجاح', moved });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

// 3. مسار توليد وحفظ كود التفعيل في Supabase
app.post(['/generate-code', '/api/generate-code'], async (req, res) => {
    try {
        const { duration, max_devices, customer_name, customer_phone, amount, note, operator_name } = req.body;

        const ALPH = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        const rc = (n) => Array.from(crypto.randomBytes(n), b => ALPH[b % 32]).join('');
        const randomCode = 'HATV-' + rc(6) + '-' + rc(4); // عشوائي آمن (crypto) بدل Math.random

        const dur = (duration === undefined || duration === '') ? 30 : parseInt(duration);
        const maxDev = (max_devices === undefined || max_devices === '') ? 1 : parseInt(max_devices);
        if (!Number.isInteger(dur) || dur < 1 || dur > 3650) return res.status(400).json({ success: false, message: 'مدة الاشتراك غير صالحة (من 1 إلى 3650 يوماً)' });
        if (!Number.isInteger(maxDev) || maxDev < 1 || maxDev > 10) return res.status(400).json({ success: false, message: 'عدد الأجهزة يجب أن يكون بين 1 و10' });
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + dur);

        const { data, error } = await supabase
            .from('activation_codes')
            .insert([{
                code: randomCode,
                duration_days: dur,
                max_devices: maxDev,
                status: 'active',
                is_blocked: false,
                expires_at: expiresAt.toISOString(),
                // يتطلب عمودي customer_name و note في activation_codes؛ يُرسلان فقط عند وجود قيمة
                ...(customer_name ? { customer_name: String(customer_name).slice(0, 80) } : {}),
                ...(note ? { note: String(note).slice(0, 300) } : {}),
                ...(customer_phone ? { customer_phone: String(customer_phone).slice(0, 30) } : {}),
                ...(amount !== undefined && amount !== '' && Number(amount) >= 0 && Number(amount) <= 10000000 ? { amount: Number(amount) } : {}),
                ...(operator_name ? { created_by: operator_name } : {})
            }])
            .select();

        if (error) throw error;

        await logAction(operator_name, 'توليد كود', `ولّد كود تفعيل جديد: ${randomCode} لمدة ${dur} يوم`);

        res.json({ success: true, message: 'تم توليد وحفظ الكود بنجاح', code: randomCode, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 4. مسار التحقق من أكواد التفعيل وتسجيل الجهاز المستخدم
app.post(['/verify-code', '/api/verify-code'], async (req, res) => {
    try {
        const { code, device_id } = req.body;
        const device_name = req.body.device_name ? String(req.body.device_name).trim().slice(0, 80) : '';
        if (!code || !device_id) return res.status(400).json({ success: false, message: 'الكود ومعرّف الجهاز مطلوبان' });
        if (codeLimiter.blocked(req.ip)) return res.status(429).json({ success: false, message: 'محاولات كثيرة. حاول بعد 15 دقيقة' });
        const { data, error } = await supabase
            .from('activation_codes')
            .select('*')
            .eq('code', code)
            .single();

        if (error || !data) {
            codeLimiter.fail(req.ip);
            return res.status(404).json({ success: false, message: 'كود التفعيل غير صالح أو غير موجود' });
        }

        if (data.is_blocked) {
            return res.status(403).json({ success: false, message: 'عذراً، هذا الكود تم تعطيله أو حظره من قبل الإدارة' });
        }

        // التحقق من انتهاء الصلاحية حسب التاريخ الفعلي
        if (isExpired(data)) {
            if (data.status !== 'expired') {
                await supabase.from('activation_codes').update({ status: 'expired' }).eq('id', data.id);
            }
            return res.status(400).json({ success: false, message: 'عذراً، هذا الكود منتهي الصلاحية' });
        }

        // الأجهزة: يُسمح بـ max_devices جهازاً لكل كود، وتصفير الكود من اللوحة يفرّغها
        const maxDev = Math.max(1, parseInt(data.max_devices) || 1);
        let { data: devs, error: dErr } = await supabase.from('code_devices').select('device_id, is_blocked').eq('code_id', data.id);
        if (dErr) ({ data: devs, error: dErr } = await supabase.from('code_devices').select('device_id').eq('code_id', data.id));
        if (dErr) throw dErr;
        const mine = (devs || []).find(d => d.device_id === device_id);
        if (mine && mine.is_blocked) return res.status(403).json({ success: false, message: 'تم حظر هذا الجهاز من قبل الإدارة' });
        const known = new Set((devs || []).map(d => d.device_id));
        if (data.used_by_device) known.add(data.used_by_device);
        if (!known.has(device_id) && known.size >= maxDev) {
            return res.status(403).json({ success: false, message: maxDev > 1
                ? 'تم بلوغ الحد الأقصى للأجهزة (' + maxDev + ') لهذا الكود. تواصل مع الدعم.'
                : 'هذا الكود مرتبط بجهاز آخر. تواصل مع الدعم لنقله.' });
        }
        const nowIso = new Date().toISOString();
        const { error: uErr } = await supabase.from('code_devices').upsert(
            [{ code_id: data.id, device_id, device_name: device_name || null, last_seen: nowIso }],
            { onConflict: 'code_id,device_id' });
        if (uErr) throw uErr;
        // حماية من التفعيل المتزامن لجهازين على كود بجهاز واحد
        const { count } = await supabase.from('code_devices').select('id', { count: 'exact', head: true }).eq('code_id', data.id);
        if (count > maxDev) {
            await supabase.from('code_devices').delete().eq('code_id', data.id).eq('device_id', device_id);
            return res.status(403).json({ success: false, message: 'هذا الكود مرتبط بجهاز آخر. تواصل مع الدعم لنقله.' });
        }
        const upd = { last_login_at: nowIso, ...(device_name ? { device_name } : {}) };
        if (!data.used_by_device) upd.used_by_device = device_id;
        await supabase.from('activation_codes').update(upd).eq('id', data.id);
        data.used_by_device = data.used_by_device || device_id;

        // تذكرة الجهاز: يرسلها التطبيق مع طلبات القنوات (Authorization: Bearer ...)
        const token = signToken({ role: 'device', cid: data.id, did: device_id }, DEVICE_TTL_MS);
        try { await supabase.from('code_login_log').insert([{ code_id: data.id, device_id, device_name: device_name || null, ip: req.ip }]); } catch (e) {}
        // نُرجع الحقول اللازمة للتطبيق فقط (بدون اسم العميل أو هاتفه أو المبلغ أو الملاحظة)
        res.json({ success: true, message: 'تم تفعيل التطبيق بنجاح', token,
            data: { code: data.code, expires_at: data.expires_at, duration_days: data.duration_days, max_devices: data.max_devices, status: 'active', device_id } });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 5. مسارات الإدارة: جلب كافة الأكواد ومن يستعملها (الحالة تُحسب من تاريخ الانتهاء الفعلي)
app.get(['/admin/codes', '/api/admin/codes'], async (req, res) => {
    try {
        const data = await fetchAll(() => supabase.from('activation_codes').select('*').order('id', { ascending: false }));
        let byCode = {};
        try {
            const devs = await fetchAll(() => supabase.from('code_devices').select('*').order('id'));
            (devs || []).forEach(d => { (byCode[d.code_id] = byCode[d.code_id] || []).push(d); });
        } catch (e) {}
        const withStatus = data.map(c => ({ ...c, status: isExpired(c) ? 'expired' : 'active', devices: byCode[c.id] || [] }));
        res.json({ success: true, data: withStatus });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 6. مسار إدارة وحظر أو تفعيل كود محدد عن بعد
app.post(['/admin/toggle-code-block', '/api/admin/toggle-code-block'], async (req, res) => {
    try {
        const { id, is_blocked, operator_name } = req.body;
        const { data, error } = await supabase
            .from('activation_codes')
            .update({ is_blocked })
            .eq('id', id)
            .select();
        if (error) throw error;

        const actionText = is_blocked ? 'حظر كود تفعيل' : 'تفعيل كود تفعيل';
        await logAction(operator_name, actionText, `تم تغيير حالة الكود ID: ${id} إلى (محظور: ${is_blocked})`);

        res.json({ success: true, message: 'تم تحديث حالة الكود بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 6.0 تمديد اشتراك كود / تعديل بيانات العميل / حذف كود
app.post(['/admin/extend-code', '/api/admin/extend-code'], async (req, res) => {
    try {
        const { id, days, amount, operator_name } = req.body;
        const d = parseInt(days);
        if (!d || d < 1 || d > 3650) return res.status(400).json({ success: false, message: 'عدد الأيام غير صالح' });
        const { data: cur, error: e1 } = await supabase.from('activation_codes').select('code, expires_at').eq('id', id).single();
        if (e1 || !cur) return res.status(404).json({ success: false, message: 'الكود غير موجود' });
        // التمديد يبدأ من تاريخ الانتهاء إن كان في المستقبل، وإلا من اليوم
        const base = cur.expires_at && new Date(cur.expires_at) > new Date() ? new Date(cur.expires_at) : new Date();
        base.setDate(base.getDate() + d);
        const { data, error } = await supabase.from('activation_codes')
            .update({ expires_at: base.toISOString(), status: 'active' }).eq('id', id).select();
        if (error) throw error;
        if (amount !== undefined && amount !== '' && Number(amount) > 0 && Number(amount) <= 10000000) {
            try { await supabase.from('code_payments').insert([{ code_id: id, amount: Number(amount), kind: 'renew', created_by: operator_name }]); } catch (e) {}
        }
        await logAction(operator_name, 'تمديد كود', `مدّد الكود ${cur.code} بمقدار ${d} يوم`);
        res.json({ success: true, message: 'تم تمديد الاشتراك', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

app.put(['/admin/codes/:id', '/api/admin/codes/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { customer_name, customer_phone, note, operator_name } = req.body;
        const { data, error } = await supabase.from('activation_codes')
            .update({ customer_name: customer_name || null, customer_phone: customer_phone || null, note: note || null }).eq('id', id).select();
        if (error) throw error;
        if (!data || !data.length) return res.status(404).json({ success: false, message: 'الكود غير موجود' });
        await logAction(operator_name, 'تعديل كود', `عدّل بيانات الكود ${data[0].code}`);
        res.json({ success: true, message: 'تم الحفظ', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

app.delete(['/admin/codes/:id', '/api/admin/codes/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { operator_name } = req.body || {};
        const { data, error } = await supabase.from('activation_codes').delete().eq('id', id).select();
        if (error) throw error;
        if (!data || !data.length) return res.status(404).json({ success: false, message: 'الكود غير موجود' });
        await logAction(operator_name, 'حذف كود', `حذف الكود ${data[0].code}`);
        res.json({ success: true, message: 'تم حذف الكود' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

// 6.1 مسار تصفير الجهاز المرتبط بكود التفعيل
app.post(['/admin/reset-device', '/api/admin/reset-device'], async (req, res) => {
    try {
        const { id, operator_name } = req.body;
        await supabase.from('code_devices').delete().eq('code_id', id);
        const { data, error } = await supabase
            .from('activation_codes')
            .update({
                used_by_device: null,
                device_name: null,
                last_login_at: null
            })
            .eq('id', id)
            .select();

        if (error) throw error;

        await logAction(operator_name, 'تصفير جهاز', `تم تصفير الجهاز المرتبط بالكود ID: ${id}`);

        res.json({ success: true, message: 'تم تصفير الجهاز المرتبط بالكود بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 6.2 فحص سلامة روابط البث — فحص حقيقي (HLS + جلب مقطع فعلي) في ملف health-check.js
//     يسجّل النتائج في جدول channel_health_logs ويضيف /admin/check-stream لفحص قناة واحدة
// تجميع سجلات الفحص: سطر واحد كل 10 دقائق لكل مشغل بدل سطر لكل قناة (يمنع امتلاء سجل العمليات)
const auditThrottle = new Map();
registerHealthRoutes(app, {
    getChannels: async () => {
        const { data, error } = await supabase.from('channels').select('id, name, primary_url');
        if (error) throw error;
        return data;
    },
    logAudit: (operator, action, details) => {
        const key = operator || 'Master Admin', now = Date.now();
        const st = auditThrottle.get(key) || { last: 0, skipped: 0 };
        if (now - st.last < 10 * 60 * 1000) { st.skipped++; auditThrottle.set(key, st); return; }
        const extra = st.skipped ? ` (+${st.skipped} فحصاً إضافياً خلال الدقائق الماضية)` : '';
        auditThrottle.set(key, { last: now, skipped: 0 });
        return logAction(operator, 'فحص الروابط', String(details || '') + extra);
    },
    saveResults: async (results) => {
        const rows = results.map(r => ({
            channel_id: r.id,
            channel_name: r.name,
            status: r.status,
            response_time_ms: r.response_time_ms || 0
        }));
        if (rows.length) await supabase.from('channel_health_logs').insert(rows);
    }
});

// 7. مسارات إدارة المشغلين (Operators)
app.get(['/operators', '/api/operators'], async (req, res) => {
    try {
        const { data, error } = await supabase.from('operators').select('*').order('id', { ascending: false });
        if (error) throw error;
        res.json({ success: true, data: data.map(safeOp) });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/operators', '/api/operators'], async (req, res) => {
    try {
        const { password, role, operator_name } = req.body;
        const name = String(req.body.name || '').replace(/\s+/g, ' ').trim().slice(0, 40);
        if (!name || !password || String(password).length < 6) return res.status(400).json({ success: false, message: 'الاسم مطلوب وكلمة المرور 6 أحرف على الأقل' });
        if (!['كاملة', 'قنوات فقط'].includes(role)) return res.status(400).json({ success: false, message: 'صلاحية غير صالحة' });
        const { data: names } = await supabase.from('operators').select('name');
        if (name.toLowerCase() === 'master admin' || (names || []).some(o => String(o.name).trim().toLowerCase() === name.toLowerCase()))
            return res.status(409).json({ success: false, message: 'يوجد مشغل بهذا الاسم مسبقاً' });
        const { data, error } = await supabase
            .from('operators')
            .insert([{ name, password: await hashPw(password), role, is_active: true }])
            .select();
        if (error) throw error;

        await logAction(operator_name, 'إضافة مشغل', `أنشأ حساب مشغل جديد باسم: ${name} بصلاحية (${role})`);

        res.json({ success: true, message: 'تم إضافة المشغل بنجاح', data: (data || []).map(safeOp) });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/operators/toggle', '/api/operators/toggle'], async (req, res) => {
    try {
        const { id, is_active, operator_name } = req.body;
        if (typeof is_active !== 'boolean') return res.status(400).json({ success: false, message: 'قيمة غير صالحة' });
        const { data, error } = await supabase
            .from('operators')
            .update({ is_active })
            .eq('id', id)
            .select();
        if (error) throw error;

        opCache.clear();
        await logAction(operator_name, 'تعديل مشغل', `قام بتغيير حالة حساب المشغل ID: ${id} إلى (نشط: ${is_active})`);

        res.json({ success: true, message: 'تم تحديث حالة المشغل', data: (data || []).map(safeOp) });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/operators/password', '/api/operators/password'], async (req, res) => {
    try {
        const { id, password, operator_name } = req.body;
        if (!password || String(password).length < 6) return res.status(400).json({ success: false, message: 'كلمة المرور 6 أحرف على الأقل' });
        const { data, error } = await supabase.from('operators').update({ password: await hashPw(password) }).eq('id', id).select();
        if (error) throw error;
        if (!data || !data.length) return res.status(404).json({ success: false, message: 'المشغل غير موجود' });
        await logAction(operator_name, 'تغيير كلمة مرور', `غيّر كلمة مرور المشغل: ${data[0].name}`);
        res.json({ success: true, message: 'تم تغيير كلمة المرور' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

app.delete(['/operators/:id', '/api/operators/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { operator_name } = req.body || {};
        const { data, error } = await supabase.from('operators').delete().eq('id', id).select();
        if (error) throw error;
        if (!data || !data.length) return res.status(404).json({ success: false, message: 'المشغل غير موجود' });
        opCache.clear();
        await logAction(operator_name, 'حذف مشغل', `حذف حساب المشغل: ${data[0].name}`);
        res.json({ success: true, message: 'تم حذف المشغل' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

app.post(['/operator-login', '/api/operator-login'], async (req, res) => {
    try {
        const { name, password } = req.body;
        const ip = req.ip;
        if (loginBlocked(ip)) return res.status(429).json({ success: false, message: 'محاولات كثيرة. حاول بعد 15 دقيقة' });

        if (name && safeEq(name, ADMIN_KEY)) {
            loginFails.delete(ip);
            await logAction('Master Admin', 'تسجيل دخول', 'دخل المدير الرئيسي');
            return res.json({ success: true, token: signToken({ name: 'Master Admin', role: 'master' }), name: 'Master Admin', role: 'master' });
        }

        const { data, error } = await supabase
            .from('operators')
            .select('*')
            .eq('name', name)
            .single();

        if (error || !data || !(await checkPw(password, data.password))) {
            loginFail(ip);
            return res.status(401).json({ success: false, message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }

        if (!data.is_active) {
            return res.status(403).json({ success: false, message: 'عذراً، هذا الحساب موقوف من قبل الإدارة' });
        }

        await logAction(name, 'تسجيل دخول', `قام المشغل ${name} بتسجيل الدخول بنجاح`);

        loginFails.delete(ip);
        if (!String(data.password).startsWith('scrypt$')) {
            try { await supabase.from('operators').update({ password: await hashPw(password) }).eq('id', data.id); } catch (e) {}
        }
        res.json({ success: true, message: 'تم تسجيل الدخول بنجاح', token: signToken({ name: data.name, role: data.role }), name: data.name, role: data.role, data: safeOp(data) });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 8. مسارات جلب سجل العمليات (Audit Logs)
app.get(['/audit-logs', '/api/audit-logs'], async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('audit_logs')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(500);
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ==========================================
// 9. مسارات الإحصائيات (Dashboard Analytics)
// ==========================================
const ACTIVE_WINDOW_MIN = 30; // الجهاز يُعدّ نشطاً إذا سجّل دخوله خلال آخر 30 دقيقة

app.get(['/api/stats', '/stats'], async (req, res) => {
    try {
        const { count: channelsCount, error: chError } = await supabase
            .from('channels')
            .select('*', { count: 'exact', head: true });

        let codesData = [], codesError = null;
        try { codesData = await fetchAll(() => supabase.from('activation_codes').select('is_blocked, status, expires_at, last_login_at').order('id')); } catch (e) { codesError = e; }

        if (chError || codesError) throw new Error('فشل جلب إحصائيات قاعدة البيانات');

        const since = Date.now() - ACTIVE_WINDOW_MIN * 60 * 1000;
        const totalCodes = codesData.length;
        const activeCodes = codesData.filter(c => !c.is_blocked && !isExpired(c)).length;
        const blockedCodes = codesData.filter(c => c.is_blocked).length;
        // رقم حقيقي: عدد الأجهزة التي سجّلت نشاطاً مؤخراً (بدل الرقم العشوائي السابق)
        let recentlyActive = codesData.filter(c =>
            !c.is_blocked && c.last_login_at && new Date(c.last_login_at).getTime() >= since).length;
        const { data: live, error: liveErr } = await supabase.from('code_devices').select('id').gte('last_seen', new Date(since).toISOString());
        if (!liveErr && live) recentlyActive = live.length;

        res.json({
            success: true,
            data: {
                total_channels: channelsCount || 0,
                total_codes: totalCodes,
                active_codes: activeCodes,
                blocked_codes: blockedCodes,
                active_streams: recentlyActive
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ==========================================
// 10. مسارات نظام الإشعارات المتقدمة
// ==========================================
app.get(['/api/notifications', '/notifications'], async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('system_notifications')
            .select('*')
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/api/notifications', '/notifications'], async (req, res) => {
    try {
        const { title, body, target_group, operator_name } = req.body;
        const { data, error } = await supabase
            .from('system_notifications')
            .insert([{ title, body, target_group: target_group || 'all' }])
            .select();

        if (error) throw error;

        await logAction(operator_name, 'إرسال إشعار', `أرسل إشعاراً بعنوان: (${title}) للفئة: (${target_group || 'all'})`);

        res.json({ success: true, message: 'تم إرسال وحفظ الإشعار بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ==========================================
// 11. مسارات جدول المباريات والـ EPG
// ==========================================
app.get(['/api/matches', '/matches'], async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('matches_schedule')
            .select('*')
            .order('match_time', { ascending: true });
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/api/matches', '/matches'], async (req, res) => {
    try {
        const { match_title, tournament, channel_name, match_time, operator_name } = req.body;
        const { data, error } = await supabase
            .from('matches_schedule')
            .insert([{ match_title, tournament, channel_name, match_time }])
            .select();

        if (error) throw error;

        await logAction(operator_name, 'إضافة مباراة', `أضاف جدول مباراة: ${match_title} على قناة ${channel_name}`);

        res.json({ success: true, message: 'تمت إضافة المباريات بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put(['/api/matches/:id', '/matches/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { match_title, tournament, channel_name, match_time, operator_name } = req.body;
        const { data, error } = await supabase.from('matches_schedule')
            .update({ match_title, tournament, channel_name, match_time }).eq('id', id).select();
        if (error) throw error;
        if (!data || !data.length) return res.status(404).json({ success: false, message: 'المباراة غير موجودة' });
        await logAction(operator_name, 'تعديل مباراة', `عدّل المباراة: ${match_title}`);
        res.json({ success: true, message: 'تم حفظ التعديل', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, message: err.message });
    }
});

app.delete(['/api/matches/:id', '/matches/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabase.from('matches_schedule').delete().eq('id', id);
        if (error) throw error;
        res.json({ success: true, message: 'تم حذف المباراة بنجاح' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// تشغيل الخادم
const PORT = process.env.PORT || 3000;
// ================= إعدادات التطبيق (صيانة / رسائل / إصدار أدنى) =================
const CFG_KEYS = ['maintenance', 'maintenance_message', 'welcome_message', 'min_version'];
async function readCfg() {
    const out = { maintenance: false, maintenance_message: '', welcome_message: '', min_version: '' };
    try {
        const { data } = await supabase.from('app_settings').select('key, value');
        (data || []).forEach(r => { if (CFG_KEYS.includes(r.key)) out[r.key] = r.key === 'maintenance' ? r.value === 'true' : (r.value || ''); });
    } catch (e) {}
    return out;
}
app.get(['/app-config', '/api/app-config'], async (req, res) => res.json({ success: true, data: await readCfg() }));
app.put(['/admin/app-config', '/api/admin/app-config'], async (req, res) => {
    try {
        const b = req.body;
        const rows = [
            { key: 'maintenance', value: b.maintenance ? 'true' : 'false' },
            { key: 'maintenance_message', value: String(b.maintenance_message || '').slice(0, 200) },
            { key: 'welcome_message', value: String(b.welcome_message || '').slice(0, 200) },
            { key: 'min_version', value: String(b.min_version || '').slice(0, 20) }
        ];
        const { error } = await supabase.from('app_settings').upsert(rows, { onConflict: 'key' });
        if (error) throw error;
        await logAction(b.operator_name, 'إعدادات التطبيق', b.maintenance ? 'تفعيل وضع الصيانة' : 'حفظ إعدادات التطبيق');
        res.json({ success: true, message: 'تم الحفظ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================= نبضات التطبيق والمشاهدة الآن =================
app.post(['/heartbeat', '/api/heartbeat'], async (req, res) => {
    try {
        if (!req.device) return res.status(401).json({ success: false, message: 'يلزم تفعيل التطبيق' });
        const ch = req.body && req.body.channel_name ? String(req.body.channel_name).slice(0, 120) : null;
        const { error } = await supabase.from('code_devices').upsert(
            [{ code_id: req.device.cid, device_id: req.device.did, last_seen: new Date().toISOString(), last_channel: ch }],
            { onConflict: 'code_id,device_id' });
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
app.get(['/admin/live', '/api/admin/live'], async (req, res) => {
    try {
        const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();
        const { data, error } = await supabase.from('code_devices').select('last_channel').gte('last_seen', since);
        if (error) throw error;
        const m = {};
        data.forEach(r => { const k = r.last_channel || 'غير محدد'; m[k] = (m[k] || 0) + 1; });
        res.json({ success: true, data: { active: data.length, channels: Object.entries(m).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count) } });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================= نسخة احتياطية (للمدير فقط) =================
app.get(['/admin/backup', '/api/admin/backup'], async (req, res) => {
    try {
        if (!req.user || req.user.role !== 'master') return res.status(403).json({ success: false, message: 'للمدير فقط' });
        const tables = ['activation_codes', 'code_devices', 'channels', 'categories', 'matches_schedule', 'system_notifications', 'operators', 'app_settings', 'plans', 'code_payments', 'channel_reports'];
        const out = {};
        for (const t of tables) {
            try {
                const data = await fetchAll(() => supabase.from(t).select('*'));
                out[t] = t === 'operators' ? data.map(safeOp) : data;
            } catch (e) { out[t] = { error: e.message }; }
        }
        res.json({ success: true, data: { exported_at: new Date().toISOString(), tables: out } });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================= التبديل التلقائي للرابط البديل (اختياري: AUTO_FAILOVER=1) =================
async function probe(url) {
    if (!url) return false;
    const ctrl = new AbortController(), t = setTimeout(() => ctrl.abort(), 8000);
    try {
        const r = await fetch(url, { method: 'GET', headers: { Range: 'bytes=0-1023' }, signal: ctrl.signal, redirect: 'follow' });
        try { r.body && r.body.cancel(); } catch (e) {}
        return r.status < 400;
    } catch (e) { return false; } finally { clearTimeout(t); }
}
async function runLinkCheck() {
    try {
        const data = await fetchAll(() => supabase.from('channels').select('id, name, primary_url, alt_url_1, alt_url_2, alt_url_3').order('id'));
        const queue = [...data], newlyDown = [], newlyAlt = [];
        await Promise.all(Array.from({ length: 6 }, async () => {
            while (queue.length) {
                const c = queue.shift();
                let active = null;
                for (const u of [c.primary_url, c.alt_url_1, c.alt_url_2, c.alt_url_3]) { if (u && await probe(u)) { active = u; break; } }
                const prev = linkStatus.get(c.id);
                const cur = { active_url: active || c.primary_url, down: !active, primary_ok: active === c.primary_url, checked_at: new Date().toISOString() };
                if (cur.down && !(prev && prev.down)) newlyDown.push(c.name);
                else if (!cur.down && !cur.primary_ok && !(prev && !prev.down && !prev.primary_ok)) newlyAlt.push(c.name);
                linkStatus.set(c.id, cur);
            }
        }));
        const list = (arr) => arr.slice(0, 25).map(n => '- ' + n).join('\n') + (arr.length > 25 ? '\n…' : '');
        if (newlyDown.length) await notifyTG('⚠️ قنوات تعطلت كل روابطها (' + newlyDown.length + '):\n' + list(newlyDown), 'down');
        if (newlyAlt.length) await notifyTG('🔁 قنوات تحوّلت إلى رابط بديل (' + newlyAlt.length + '):\n' + list(newlyAlt), 'alt');
    } catch (e) { console.error('link check:', e.message); }
}
if (process.env.AUTO_FAILOVER === '1') {
    setTimeout(runLinkCheck, 30000);
    setInterval(runLinkCheck, 60 * 60 * 1000);
}
app.get(['/admin/link-status', '/api/admin/link-status'], (req, res) =>
    res.json({ success: true, enabled: process.env.AUTO_FAILOVER === '1', data: [...linkStatus].map(([id, v]) => ({ id, ...v })) }));

// ================= إخفاء/إظهار القنوات =================
app.post(['/channels/set-status', '/api/channels/set-status'], async (req, res) => {
    try {
        const { ids, status, operator_name } = req.body;
        if (!Array.isArray(ids) || !ids.length || !['hidden', 'active'].includes(status))
            return res.status(400).json({ success: false, message: 'بيانات غير صالحة' });
        let n = 0;
        for (let i = 0; i < ids.length; i += 200) {
            const { data, error } = await supabase.from('channels').update({ status }).in('id', ids.slice(i, i + 200)).select('id');
            if (error) throw error;
            n += data.length;
        }
        await logAction(operator_name, status === 'hidden' ? 'إخفاء قنوات' : 'إظهار قنوات', `${n} قناة`);
        res.json({ success: true, updated: n });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================= بلاغات المشتركين =================
app.post(['/report-channel', '/api/report-channel'], async (req, res) => {
    try {
        if (!req.device) return res.status(401).json({ success: false, message: 'يلزم تفعيل التطبيق' });
        const channel_id = req.body.channel_id != null ? parseInt(req.body.channel_id) : null;
        let name = req.body.channel_name ? String(req.body.channel_name).slice(0, 120) : null;
        const reason = req.body.reason ? String(req.body.reason).slice(0, 120) : null;
        if ((channel_id == null || isNaN(channel_id)) && !name) return res.status(400).json({ success: false, message: 'حدد القناة' });
        const byId = channel_id != null && !isNaN(channel_id);
        let dup = supabase.from('channel_reports').select('id').eq('device_id', req.device.did)
            .gte('created_at', new Date(Date.now() - 3600000).toISOString()).limit(1);
        dup = byId ? dup.eq('channel_id', channel_id) : dup.eq('channel_name', name);
        const { data: d } = await dup;
        if (d && d.length) return res.json({ success: true, duplicate: true });
        if (byId && !name) { const { data: c } = await supabase.from('channels').select('name').eq('id', channel_id).maybeSingle(); name = c && c.name; }
        const { error } = await supabase.from('channel_reports').insert([{ channel_id: byId ? channel_id : null, channel_name: name, device_id: req.device.did, reason }]);
        if (error) throw error;
        let cnt = supabase.from('channel_reports').select('id', { count: 'exact', head: true }).gte('created_at', new Date(Date.now() - 86400000).toISOString());
        cnt = byId ? cnt.eq('channel_id', channel_id) : cnt.eq('channel_name', name);
        const { count } = await cnt;
        if (count >= 5) notifyTG('📢 ' + count + ' بلاغات خلال 24 ساعة على القناة «' + (name || channel_id) + '»', 'rep:' + (byId ? channel_id : name));
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
app.get(['/admin/reports', '/api/admin/reports'], async (req, res) => {
    try {
        const since = new Date(Date.now() - 7 * 86400000).toISOString();
        const rows = await fetchAll(() => supabase.from('channel_reports').select('*').gte('created_at', since).order('id', { ascending: false }));
        const day = Date.now() - 86400000, m = new Map();
        rows.forEach(r0 => {
            const key = r0.channel_id != null ? 'i' + r0.channel_id : 'n' + r0.channel_name;
            const g = m.get(key) || { channel_id: r0.channel_id, channel_name: r0.channel_name, total_7d: 0, total_24h: 0, last_at: r0.created_at, reasons: {} };
            g.total_7d++;
            if (new Date(r0.created_at).getTime() >= day) g.total_24h++;
            if (r0.reason) g.reasons[r0.reason] = (g.reasons[r0.reason] || 0) + 1;
            if (r0.created_at > g.last_at) g.last_at = r0.created_at;
            m.set(key, g);
        });
        const data = [...m.values()].map(g => ({ ...g, reasons: Object.entries(g.reasons).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => k + ' (' + v + ')') }))
            .sort((a, b) => b.total_24h - a.total_24h || b.total_7d - a.total_7d);
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
app.post(['/admin/reports/clear', '/api/admin/reports/clear'], async (req, res) => {
    try {
        const { channel_id, channel_name, operator_name } = req.body;
        if (channel_id == null && !channel_name) return res.status(400).json({ success: false, message: 'حدد القناة' });
        let qd = supabase.from('channel_reports').delete();
        qd = channel_id != null ? qd.eq('channel_id', channel_id) : qd.eq('channel_name', channel_name);
        const { error } = await qd;
        if (error) throw error;
        await logAction(operator_name, 'مسح بلاغات', `مسح بلاغات القناة: ${channel_name || channel_id}`);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================= الباقات والأسعار =================
const planOk = (b) => {
    const name = String(b.name || '').trim().slice(0, 60), dur = parseInt(b.duration_days), price = Number(b.price || 0), dev = parseInt(b.max_devices || 1);
    if (!name || !Number.isInteger(dur) || dur < 1 || dur > 3650 || !(price >= 0 && price <= 10000000) || !Number.isInteger(dev) || dev < 1 || dev > 10) return null;
    return { name, duration_days: dur, price, max_devices: dev, is_active: b.is_active !== false };
};
app.get(['/admin/plans', '/api/admin/plans'], async (req, res) => {
    try {
        const { data, error } = await supabase.from('plans').select('*').order('duration_days', { ascending: true });
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.post(['/admin/plans', '/api/admin/plans'], async (req, res) => {
    try {
        const row = planOk(req.body);
        if (!row) return res.status(400).json({ success: false, message: 'بيانات الباقة غير صالحة' });
        const { data, error } = await supabase.from('plans').insert([row]).select();
        if (error) throw error;
        await logAction(req.body.operator_name, 'إضافة باقة', `${row.name} — ${row.duration_days} يوم — ${row.price}`);
        res.json({ success: true, data });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.put(['/admin/plans/:id', '/api/admin/plans/:id'], async (req, res) => {
    try {
        const row = planOk(req.body);
        if (!row) return res.status(400).json({ success: false, message: 'بيانات الباقة غير صالحة' });
        const { data, error } = await supabase.from('plans').update(row).eq('id', req.params.id).select();
        if (error) throw error;
        if (!data.length) return res.status(404).json({ success: false, message: 'الباقة غير موجودة' });
        await logAction(req.body.operator_name, 'تعديل باقة', `${row.name}`);
        res.json({ success: true, data });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.delete(['/admin/plans/:id', '/api/admin/plans/:id'], async (req, res) => {
    try {
        const { data, error } = await supabase.from('plans').delete().eq('id', req.params.id).select();
        if (error) throw error;
        if (!data.length) return res.status(404).json({ success: false, message: 'الباقة غير موجودة' });
        await logAction((req.body || {}).operator_name, 'حذف باقة', data[0].name);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ================= التقارير =================
app.get(['/admin/analytics', '/api/admin/analytics'], async (req, res) => {
    try {
        const now = new Date(), keys = [];
        for (let i = 5; i >= 0; i--) keys.push(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1)).toISOString().slice(0, 7));
        const start = keys[0] + '-01T00:00:00Z';
        const rows = Object.fromEntries(keys.map(k => [k, { month: k, new_codes: 0, revenue_new: 0, renewals: 0, revenue_renew: 0 }]));
        const codes = await fetchAll(() => supabase.from('activation_codes').select('created_at, amount').gte('created_at', start).order('id'));
        codes.forEach(c => { const k = String(c.created_at || '').slice(0, 7); if (rows[k]) { rows[k].new_codes++; rows[k].revenue_new += Number(c.amount) || 0; } });
        try {
            const pays = await fetchAll(() => supabase.from('code_payments').select('created_at, amount').gte('created_at', start).order('id'));
            pays.forEach(p => { const k = String(p.created_at || '').slice(0, 7); if (rows[k]) { rows[k].renewals++; rows[k].revenue_renew += Number(p.amount) || 0; } });
        } catch (e) {}
        res.json({ success: true, data: keys.map(k => rows[k]) });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ================= أجهزة الكود: حظر / إزالة / سجل الدخول =================
app.post(['/admin/device-block', '/api/admin/device-block'], async (req, res) => {
    try {
        const { code_id, device_id, blocked, operator_name } = req.body;
        if (code_id == null || !device_id || typeof blocked !== 'boolean') return res.status(400).json({ success: false, message: 'بيانات غير صالحة' });
        const { data, error } = await supabase.from('code_devices').update({ is_blocked: blocked }).eq('code_id', code_id).eq('device_id', device_id).select();
        if (error) throw error;
        if (!data.length) return res.status(404).json({ success: false, message: 'الجهاز غير موجود' });
        await logAction(operator_name, blocked ? 'حظر جهاز' : 'رفع حظر جهاز', `الكود ID ${code_id} — الجهاز ${data[0].device_name || device_id}`);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.post(['/admin/device-remove', '/api/admin/device-remove'], async (req, res) => {
    try {
        const { code_id, device_id, operator_name } = req.body;
        if (code_id == null || !device_id) return res.status(400).json({ success: false, message: 'بيانات غير صالحة' });
        await supabase.from('code_devices').delete().eq('code_id', code_id).eq('device_id', device_id);
        const { data: code } = await supabase.from('activation_codes').select('used_by_device').eq('id', code_id).maybeSingle();
        if (code && code.used_by_device === device_id) {
            const { data: rest } = await supabase.from('code_devices').select('device_id, device_name').eq('code_id', code_id).limit(1);
            await supabase.from('activation_codes').update({ used_by_device: rest && rest[0] ? rest[0].device_id : null, device_name: rest && rest[0] ? rest[0].device_name : null }).eq('id', code_id);
        }
        await logAction(operator_name, 'إزالة جهاز', `الكود ID ${code_id} — الجهاز ${device_id}`);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.get(['/admin/code-logins/:id', '/api/admin/code-logins/:id'], async (req, res) => {
    try {
        const { data, error } = await supabase.from('code_login_log').select('device_id, device_name, ip, created_at')
            .eq('code_id', req.params.id).order('id', { ascending: false }).limit(50);
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ================= تلغرام + مهمة يومية =================
app.post(['/admin/test-telegram', '/api/admin/test-telegram'], async (req, res) => {
    if (!TG_TOKEN || !TG_CHAT) return res.json({ success: false, message: 'لم تُضبط TELEGRAM_BOT_TOKEN و TELEGRAM_CHAT_ID في Render' });
    const ok = await notifyTG('✅ اختبار تنبيهات HA TV من لوحة التحكم');
    res.json({ success: ok, message: ok ? 'أُرسلت رسالة الاختبار' : 'فشل الإرسال، تأكد من صحة القيمتين' });
});
async function dailyJob() {
    try {
        await supabase.from('code_login_log').delete().lt('created_at', new Date(Date.now() - 90 * 86400000).toISOString());
        await supabase.from('channel_reports').delete().lt('created_at', new Date(Date.now() - 30 * 86400000).toISOString());
        if (!TG_TOKEN) return;
        const codes = await fetchAll(() => supabase.from('activation_codes').select('code, customer_name, expires_at, is_blocked').order('id'));
        const soon = codes.filter(c => !c.is_blocked && c.expires_at && (new Date(c.expires_at) - Date.now()) > 0 && (new Date(c.expires_at) - Date.now()) <= 3 * 86400000);
        if (soon.length) await notifyTG('⏰ ' + soon.length + ' اشتراك ينتهي خلال 3 أيام:\n' + soon.slice(0, 15).map(c => '- ' + (c.customer_name || c.code) + ' (' + new Date(c.expires_at).toISOString().slice(0, 10) + ')').join('\n'));
    } catch (e) { console.error('daily job:', e.message); }
}
setTimeout(dailyJob, 60000).unref();
setInterval(dailyJob, 24 * 3600 * 1000).unref();

app.listen(PORT, () => {
    console.log(`🚀 HA TV Backend running successfully on port ${PORT}`);
});
