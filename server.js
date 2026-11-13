const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use(cors());

// الاتصال بقاعدة بيانات Supabase (باستخدام القيم المباشرة الصحيحة التي وضعتها)
const supabaseUrl = 'https://mgtpspudobzouvipgdhw.supabase.co';
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1ndHBzcHVkb2J6b3V2aXBnZGh3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc5NDU1OTQ1NiwiZXhwIjoyMTEwMTM1NDU2fQ.FEy5hg8B21h3nSANpZDi1T-P1cNR4jyqTgMjIfOrMwY';
const supabase = createClient(supabaseUrl, supabaseKey);

// 1. مسار لجلب جميع القنوات والبدائل (يستخدمه تطبيق Flutter ولوحة التحكم)
app.get('/api/channels', async (req, res) => {
    try {
        const { data, error } = await supabase.from('channels').select('*');
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 2. مسار لإضافة قناة جديدة مع بدائل البث
app.post('/api/channels', async (req, res) => {
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

// 3. مسار للتحقق من أكواد التفعيل الخاصة بالمشتركين
app.post('/api/verify-code', async (req, res) => {
    try {
        const { code } = req.body;
        const { data, error } = await supabase
            .from('activation_codes')
            .select('*')
            .eq('code', code)
            .single();

        if (error || !data) {
            return res.status(404).json({ success: false, message: 'كود التفعيل غير صالح أو غير موجود' });
        }

        if (data.status === 'expired') {
            return res.status(400).json({ success: false, message: 'عذراً، هذا الكود منتهي الصلاحية' });
        }

        res.json({ success: true, message: 'تم تفعيل التطبيق بنجاح', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// تشغيل الخادم على المنفذ المحدد
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 HA TV Backend running successfully on port ${PORT}`);
});