const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use(cors());

// الاتصال بقاعدة بيانات Supabase
const supabaseUrl = 'https://mgtpspudobzouvipgdhw.supabase.co';
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1ndHBzcHVkb2J6b3V2aXBnZGh3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc5NDU1OTQ1NiwiZXhwIjoyMTEwMTM1NDU2fQ.FEy5hg8B21h3nSANpZDi1T-P1cNR4jyqTgMjIfOrMwY';
const supabase = createClient(supabaseUrl, supabaseKey);

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
        const { name, category, primary_url, alt_url_1, alt_url_2, alt_url_3 } = req.body;
        const { data, error } = await supabase
            .from('channels')
            .insert([{ name, category, primary_url, alt_url_1, alt_url_2, alt_url_3 }]);
        
        if (error) throw error;
        res.json({ success: true, message: 'تم إضافة القناة بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
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
        const { name } = req.body;
        const { data, error } = await supabase.from('categories').insert([{ name }]);
        if (error) throw error;
        res.json({ success: true, message: 'تم إضافة التصنيف بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete(['/categories/:id', '/api/categories/:id'], async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabase.from('categories').delete().eq('id', id);
        if (error) throw error;
        res.json({ success: true, message: 'تم حذف التصنيف بنجاح' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 3. مسار توليد وحفظ كود التفعيل في Supabase
app.post(['/generate-code', '/api/generate-code'], async (req, res) => {
    try {
        const { duration, max_devices } = req.body;
        
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
                expires_at: expiresAt.toISOString()
            }])
            .select();

        if (error) throw error;
        res.json({ success: true, message: 'تم توليد وحفظ الكود بنجاح', code: randomCode, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 4. مسار التحقق من أكواد التفعيل وتجسيل الجهاز المستخدم
app.post(['/verify-code', '/api/verify-code'], async (req, res) => {
    try {
        const { code, device_id } = req.body;
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

        if (data.status === 'expired') {
            return res.status(400).json({ success: false, message: 'عذراً، هذا الكود منتهي الصلاحية' });
        }

        await supabase
            .from('activation_codes')
            .update({ 
                used_by_device: device_id || 'جهاز مستخدم', 
                last_login_at: new Date() 
            })
            .eq('code', code);

        res.json({ success: true, message: 'تم تفعيل التطبيق بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 5. مسارات الإدارة: جلب كافة الأكواد ومن يستعملها
app.get(['/admin/codes', '/api/admin/codes'], async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('activation_codes')
            .select('*')
            .order('id', { ascending: false });
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 6. مسار إدارة وحظر أو تفعيل كود محدد عن بعد
app.post(['/admin/toggle-code-block', '/api/admin/toggle-code-block'], async (req, res) => {
    try {
        const { id, is_blocked } = req.body;
        const { data, error } = await supabase
            .from('activation_codes')
            .update({ is_blocked })
            .eq('id', id)
            .select();
        if (error) throw error;
        res.json({ success: true, message: 'تم تحديث حالة الكود بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 7. مسارات إدارة المشغلين (Operators)
app.get(['/operators', '/api/operators'], async (req, res) => {
    try {
        const { data, error } = await supabase.from('operators').select('*').order('id', { ascending: false });
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/operators', '/api/operators'], async (req, res) => {
    try {
        const { name, password, role } = req.body;
        const { data, error } = await supabase
            .from('operators')
            .insert([{ name, password, role, is_active: true }])
            .select();
        if (error) throw error;
        res.json({ success: true, message: 'تم إضافة المشغل بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/operators/toggle', '/api/operators/toggle'], async (req, res) => {
    try {
        const { id, is_active } = req.body;
        const { data, error } = await supabase
            .from('operators')
            .update({ is_active })
            .eq('id', id)
            .select();
        if (error) throw error;
        res.json({ success: true, message: 'تم تحديث حالة المشغل', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/operator-login', '/api/operator-login'], async (req, res) => {
    try {
        const { name, password } = req.body;
        const { data, error } = await supabase
            .from('operators')
            .select('*')
            .eq('name', name)
            .eq('password', password)
            .single();

        if (error || !data) {
            return res.status(401).json({ success: false, message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }

        if (!data.is_active) {
            return res.status(403).json({ success: false, message: 'عذراً، هذا الحساب موقوف من قبل الإدارة' });
        }

        res.json({ success: true, message: 'تم تسجيل الدخول بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// تشغيل الخادم
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 HA TV Backend running successfully on port ${PORT}`);
});
