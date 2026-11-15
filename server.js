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
const ADMIN_KEY = 'HA_TV_ADMIN_chaouki_1920';       // المفتاح الرئيسي للمدير (يُكتب في خانة اسم المستخدم)
const AUTH_SECRET = 'OYy1yHjmCZogGn5p1LSyFgnKlGapUAJobsqHYwwxPD6BZLEd';   // سر توقيع التوكن (نص عشوائي طويل)
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
const DEVICE_ROUTES = new Set(['GET /channels', 'GET /categories', 'GET /matches', 'GET /notifications', 'POST /heartbeat']);
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
                let okDev = !!data && data.used_by_device === user.did;
                if (data && !okDev) {
                    const { data: row } = await supabase.from('code_devices').select('id').eq('code_id', user.cid).eq('device_id', user.did).maybeSingle();
                    okDev = !!row;
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
const supabaseUrl = 'https://mgtpspudobzouvipgdhw.supabase.co';
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1ndHBzcHVkb2J6b3V2aXBnZGh3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc5NDU1OTQ1NiwiZXhwIjoyMTEwMTM1NDU2fQ.FEy5hg8B21h3nSANpZDi1T-P1cNR4jyqTgMjIfOrMwY';
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
        const { data, error } = await supabase.from('channels').select('*');
        if (error) throw error;
        // active_url: الرابط الذي يجب أن يستعمله التطبيق (يتبدّل للبديل عند تفعيل AUTO_FAILOVER)
        res.json({ success: true, data: data.map(c => { const st = linkStatus.get(c.id); return { ...c, active_url: (st && st.active_url) || c.primary_url, failover: !!(st && !st.down && !st.primary_ok), link_down: !!(st && st.down) }; }) });
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
        const { name, operator_name } = req.body;
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

app.delete(['/categories/:id', '/api/categories/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { operator_name } = req.body || {};
        const { error } = await supabase.from('categories').delete().eq('id', id);
        if (error) throw error;

        await logAction(operator_name, 'حذف تصنيف', `حذف التصنيف برقم ID: ${id}`);

        res.json({ success: true, message: 'تم حذف التصنيف بنجاح' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 3. مسار توليد وحفظ كود التفعيل في Supabase
app.post(['/generate-code', '/api/generate-code'], async (req, res) => {
    try {
        const { duration, max_devices, customer_name, customer_phone, amount, note, operator_name } = req.body;

        const ALPH = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        const rc = (n) => Array.from(crypto.randomBytes(n), b => ALPH[b % 32]).join('');
        const randomCode = 'HATV-' + rc(6) + '-' + rc(4); // عشوائي آمن (crypto) بدل Math.random

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + parseInt(duration || 30));

        const { data, error } = await supabase
            .from('activation_codes')
            .insert([{
                code: randomCode,
                duration_days: parseInt(duration),
                max_devices: parseInt(max_devices || 1),
                status: 'active',
                is_blocked: false,
                expires_at: expiresAt.toISOString(),
                // يتطلب عمودي customer_name و note في activation_codes؛ يُرسلان فقط عند وجود قيمة
                ...(customer_name ? { customer_name } : {}),
                ...(note ? { note } : {}),
                ...(customer_phone ? { customer_phone } : {}),
                ...(amount !== undefined && amount !== '' && !isNaN(Number(amount)) ? { amount: Number(amount) } : {}),
                ...(operator_name ? { created_by: operator_name } : {})
            }])
            .select();

        if (error) throw error;

        await logAction(operator_name, 'توليد كود', `ولّد كود تفعيل جديد: ${randomCode} لمدة ${duration} يوم`);

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
        const { data: devs, error: dErr } = await supabase.from('code_devices').select('device_id').eq('code_id', data.id);
        if (dErr) throw dErr;
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
        res.json({ success: true, message: 'تم تفعيل التطبيق بنجاح', token, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 5. مسارات الإدارة: جلب كافة الأكواد ومن يستعملها (الحالة تُحسب من تاريخ الانتهاء الفعلي)
app.get(['/admin/codes', '/api/admin/codes'], async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('activation_codes')
            .select('*')
            .order('id', { ascending: false });
        if (error) throw error;
        let byCode = {};
        try {
            const { data: devs } = await supabase.from('code_devices').select('code_id, device_id, device_name, last_seen');
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
        const { id, days, operator_name } = req.body;
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
registerHealthRoutes(app, {
    getChannels: async () => {
        const { data, error } = await supabase.from('channels').select('id, name, primary_url');
        if (error) throw error;
        return data;
    },
    logAudit: (operator, action, details) => logAction(operator, 'فحص الروابط', details),
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
        const { name, password, role, operator_name } = req.body;
        if (!name || !password || String(password).length < 6) return res.status(400).json({ success: false, message: 'الاسم مطلوب وكلمة المرور 6 أحرف على الأقل' });
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
        const { data, error } = await supabase
            .from('operators')
            .update({ is_active })
            .eq('id', id)
            .select();
        if (error) throw error;

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

        const { data: codesData, error: codesError } = await supabase
            .from('activation_codes')
            .select('is_blocked, status, expires_at, last_login_at');

        if (chError || codesError) throw new Error('فشل جلب إحصائيات قاعدة البيانات');

        const since = Date.now() - ACTIVE_WINDOW_MIN * 60 * 1000;
        const totalCodes = codesData.length;
        const activeCodes = codesData.filter(c => !c.is_blocked && !isExpired(c)).length;
        const blockedCodes = codesData.filter(c => c.is_blocked).length;
        // رقم حقيقي: عدد الأجهزة التي سجّلت نشاطاً مؤخراً (بدل الرقم العشوائي السابق)
        const recentlyActive = codesData.filter(c =>
            !c.is_blocked && c.last_login_at && new Date(c.last_login_at).getTime() >= since).length;

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
        const tables = ['activation_codes', 'code_devices', 'channels', 'categories', 'matches_schedule', 'system_notifications', 'operators', 'app_settings'];
        const out = {};
        for (const t of tables) {
            const { data, error } = await supabase.from(t).select('*');
            out[t] = error ? { error: error.message } : (t === 'operators' ? data.map(safeOp) : data);
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
        const { data } = await supabase.from('channels').select('id, primary_url, alt_url_1, alt_url_2, alt_url_3');
        if (!data) return;
        const queue = [...data];
        await Promise.all(Array.from({ length: 6 }, async () => {
            while (queue.length) {
                const c = queue.shift();
                let active = null;
                for (const u of [c.primary_url, c.alt_url_1, c.alt_url_2, c.alt_url_3]) { if (u && await probe(u)) { active = u; break; } }
                linkStatus.set(c.id, { active_url: active || c.primary_url, down: !active, primary_ok: active === c.primary_url, checked_at: new Date().toISOString() });
            }
        }));
    } catch (e) { console.error('link check:', e.message); }
}
if (process.env.AUTO_FAILOVER === '1') {
    setTimeout(runLinkCheck, 30000);
    setInterval(runLinkCheck, 60 * 60 * 1000);
}
app.get(['/admin/link-status', '/api/admin/link-status'], (req, res) =>
    res.json({ success: true, enabled: process.env.AUTO_FAILOVER === '1', data: [...linkStatus].map(([id, v]) => ({ id, ...v })) }));

app.listen(PORT, () => {
    console.log(`🚀 HA TV Backend running successfully on port ${PORT}`);
});
