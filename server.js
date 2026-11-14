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
function signToken(payload) {
    const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + TOKEN_TTL_MS })).toString('base64url');
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

// تحديد محاولات الدخول الفاشلة: 5 محاولات لكل IP كل 15 دقيقة
const loginFails = new Map();
const loginBlocked = (ip) => { const f = loginFails.get(ip); return !!f && f.n >= 5 && f.until > Date.now(); };
const loginFail = (ip) => {
    const f = loginFails.get(ip), now = Date.now();
    if (!f || f.until <= now) loginFails.set(ip, { n: 1, until: now + 15 * 60 * 1000 }); else f.n++;
};
setInterval(() => { const n = Date.now(); for (const [k, v] of loginFails) if (v.until <= n) loginFails.delete(k); }, 3600000).unref();

// المسارات المفتوحة (يستعملها تطبيق التلفاز) — أي مسار غيرها يتطلب توكناً
const PUBLIC_ROUTES = new Set([
    'GET /', 'GET /channels', 'GET /categories', 'GET /matches', 'GET /notifications',
    'POST /verify-code', 'POST /operator-login'
]);
// مشغل بصلاحية "قنوات فقط" يصل لهذه المسارات فقط
const LIMITED_OK = /^\/(channels|categories|matches|stats|admin\/check-streams?)(\/|$)/;

app.use((req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    const path = req.path.replace(/^\/api(?=\/|$)/, '') || '/';
    if (PUBLIC_ROUTES.has(req.method + ' ' + path)) return next();

    const h = req.headers.authorization || '';
    const user = verifyToken(h.startsWith('Bearer ') ? h.slice(7) : '');
    if (!user) return res.status(401).json({ success: false, message: 'يلزم تسجيل الدخول' });

    const master = user.role === 'master';
    if (/^\/operators(\/|$)/.test(path) && !master)
        return res.status(403).json({ success: false, message: 'هذه العملية للمدير فقط' });
    if (!master && user.role !== 'كاملة' && !LIMITED_OK.test(path))
        return res.status(403).json({ success: false, message: 'صلاحيتك لا تسمح بهذه العملية' });

    req.user = user;
    // هوية المشغل تُؤخذ من التوكن لا من الطلب (لمنع تزوير سجل العمليات)
    if (req.body && typeof req.body === 'object') req.body.operator_name = user.name;
    next();
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
        const { data, error } = await supabase.from('channels').select('*');
        if (error) throw error;
        res.json({ success: true, data });
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

app.put(['/channels/:id', '/api/channels/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { name, category, primary_url, operator_name } = req.body;
        if (!name || !primary_url) return res.status(400).json({ success: false, message: 'الاسم والرابط مطلوبان' });
        const { data, error } = await supabase
            .from('channels')
            .update({ name, category, primary_url })
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
        const { duration, max_devices, customer_name, note, operator_name } = req.body;

        const randomCode = 'HATV-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();

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
                ...(note ? { note } : {})
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
        const { data, error } = await supabase
            .from('activation_codes')
            .select('*')
            .eq('code', code)
            .single();

        if (error || !data) {
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

        // ربط الكود بجهاز واحد: لا يُستبدل الجهاز إلا بتصفير من اللوحة
        if (!data.used_by_device) {
            const { data: bound, error: bErr } = await supabase
                .from('activation_codes')
                .update({ used_by_device: device_id, last_login_at: new Date(), ...(device_name ? { device_name } : {}) })
                .eq('id', data.id).is('used_by_device', null).select();
            if (bErr) throw bErr;
            if (!bound || !bound.length) return res.status(403).json({ success: false, message: 'هذا الكود مرتبط بجهاز آخر' });
            data.used_by_device = device_id;
        } else if (data.used_by_device === device_id) {
            await supabase.from('activation_codes').update({ last_login_at: new Date(), ...(device_name ? { device_name } : {}) }).eq('id', data.id);
        } else {
            return res.status(403).json({ success: false, message: 'هذا الكود مرتبط بجهاز آخر. تواصل مع الدعم لنقله.' });
        }

        res.json({ success: true, message: 'تم تفعيل التطبيق بنجاح', data });
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
        const withStatus = data.map(c => ({ ...c, status: isExpired(c) ? 'expired' : 'active' }));
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
        const { customer_name, note, operator_name } = req.body;
        const { data, error } = await supabase.from('activation_codes')
            .update({ customer_name: customer_name || null, note: note || null }).eq('id', id).select();
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
        const { data, error } = await supabase
            .from('operators')
            .insert([{ name, password, role, is_active: true }])
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
            .eq('password', password)
            .single();

        if (error || !data) {
            loginFail(ip);
            return res.status(401).json({ success: false, message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }

        if (!data.is_active) {
            return res.status(403).json({ success: false, message: 'عذراً، هذا الحساب موقوف من قبل الإدارة' });
        }

        await logAction(name, 'تسجيل دخول', `قام المشغل ${name} بتسجيل الدخول بنجاح`);

        loginFails.delete(ip);
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
            .limit(100);
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
app.listen(PORT, () => {
    console.log(`🚀 HA TV Backend running successfully on port ${PORT}`);
});
