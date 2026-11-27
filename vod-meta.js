// vod-meta.js — مخزن بيانات TMDB (الممثلون، المخرجون، المقاطع الدعائية، حلقات المواسم، صفحات الأشخاص).
// طبقتان: ذاكرة السيرفر (سريعة) + جدول vod_meta في Supabase (يبقى بعد إعادة تشغيل Render).
// إن لم يوجد الجدول بعد يعمل كل شيء بالذاكرة فقط ودون أخطاء — نفّذ vod_meta.sql لتفعيل الحفظ الدائم.
module.exports = function createMetaStore(supabase) {
    const MEM_MS = 6 * 60 * 60 * 1000;
    const mem = new Map(); // key -> { at, data }
    let offUntil = 0;      // بعد فشل الجدول نتجاهله 10 دقائق ثم نعيد المحاولة
    const isMissing = (e) => /schema cache|does not exist|could not find|relation/i.test(String(e && e.message));

    async function get(key, maxAgeMs) {
        const h = mem.get(key);
        if (h && Date.now() - h.at < Math.min(MEM_MS, maxAgeMs)) return h.data;
        if (Date.now() < offUntil) return null;
        try {
            const { data, error } = await supabase.from('vod_meta').select('data, fetched_at').eq('key', key).maybeSingle();
            if (error) { if (isMissing(error)) offUntil = Date.now() + 10 * 60 * 1000; return null; }
            if (data && Date.now() - new Date(data.fetched_at).getTime() < maxAgeMs) {
                mem.set(key, { at: Date.now(), data: data.data });
                return data.data;
            }
        } catch (e) { /* نكمل بدونه */ }
        return null;
    }

    async function set(key, data) {
        mem.set(key, { at: Date.now(), data });
        if (mem.size > 2000) { // نحذف أقدم 500 مدخل
            [...mem].sort((a, b) => a[1].at - b[1].at).slice(0, 500).forEach(([k]) => mem.delete(k));
        }
        if (Date.now() < offUntil) return;
        try {
            const { error } = await supabase.from('vod_meta').upsert({ key, data, fetched_at: new Date().toISOString() }, { onConflict: 'key' });
            if (error && isMissing(error)) offUntil = Date.now() + 10 * 60 * 1000;
        } catch (e) { /* الذاكرة تكفي */ }
    }

    return { get, set };
};
