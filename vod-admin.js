// vod-admin.js — أدوات إصلاح إثراء الأفلام والمسلسلات من لوحة التحكم:
//   GET  /admin/vod/find?q=          بحث عن عناصر بالاسم (للربط اليدوي)
//   POST /admin/vod/set-tmdb         { id, tmdb_id } ربط عنصر بمعرّف TMDB صحيح وتحديث بياناته فوراً
//   POST /admin/enrich-retry         { kind } إعادة العناصر «غير الموجودة» إلى قائمة الإثراء من جديد
// الصلاحيات: مسارات /admin/* للمدير والمشغل «كاملة» فقط (من الـ middleware في server.js).
module.exports = function registerVodAdmin(app, { supabase, tmdb, hasTmdb, TMDB_IMG, logAction, invalidateVod }) {
    const kindOf = (k) => (String(k) === 'series' ? 'series' : 'movie');
    const like = (q) => '%' + String(q).replace(/[%_\\,()]/g, ' ').trim() + '%';

    app.get(['/admin/vod/find', '/api/admin/vod/find'], async (req, res) => {
        try {
            const q = String(req.query.q || '').trim();
            if (q.length < 2) return res.json({ success: true, data: [] });
            const { data, error } = await supabase.from('channels')
                .select('id, name, kind, year, tmdb_id, logo_url').in('kind', ['movie', 'series'])
                .ilike('name', like(q)).order('id', { ascending: false }).limit(15);
            if (error) throw new Error(error.message);
            res.json({ success: true, data: data || [] });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    app.post(['/admin/vod/set-tmdb', '/api/admin/vod/set-tmdb'], async (req, res) => {
        try {
            if (!hasTmdb()) return res.status(400).json({ success: false, message: 'لم يُضبط TMDB_TOKEN في Render' });
            const id = parseInt(req.body && req.body.id, 10), tid = parseInt(req.body && req.body.tmdb_id, 10);
            if (!id || !(tid > 0)) return res.status(400).json({ success: false, message: 'المعرّف ومعرّف TMDB مطلوبان' });
            const { data: row, error } = await supabase.from('channels').select('id, name, kind, logo_url').eq('id', id).maybeSingle();
            if (error) throw new Error(error.message);
            if (!row || (row.kind !== 'movie' && row.kind !== 'series')) return res.status(404).json({ success: false, message: 'العنصر غير موجود' });
            const isTv = row.kind === 'series';
            let d;
            try { d = await tmdb((isTv ? '/tv/' : '/movie/') + tid); }
            catch (e) { return res.status(400).json({ success: false, message: 'لا يوجد ' + (isTv ? 'مسلسل' : 'فيلم') + ' بهذا المعرّف في TMDB (' + e.message + ')' }); }
            let overview = d.overview;
            if (!overview) { try { overview = (await tmdb((isTv ? '/tv/' : '/movie/') + tid, { language: 'en-US' })).overview; } catch (e) {} }
            // الربط اليدوي تصحيح لمطابقة خاطئة: نستبدل البيانات (لا نكتفي بملء الفارغ)
            const upd = {
                tmdb_id: tid,
                plot: String(overview || '').slice(0, 1500) || null,
                backdrop_url: d.backdrop_path ? TMDB_IMG + 'w780' + d.backdrop_path : null,
                runtime: (isTv ? (d.episode_run_time && d.episode_run_time[0]) : d.runtime) || null,
                genres: (d.genres || []).map(g => g.name).join(', ') || null,
            };
            if (d.vote_average > 0) upd.rating = Math.round(d.vote_average * 10) / 10;
            const y = parseInt(String(d.release_date || d.first_air_date || '').slice(0, 4), 10);
            if (y) upd.year = y;
            if (req.body.replace_poster && d.poster_path) upd.logo_url = TMDB_IMG + 'w500' + d.poster_path;
            else if (!String(row.logo_url || '').trim() && d.poster_path) upd.logo_url = TMDB_IMG + 'w500' + d.poster_path;
            const { error: uerr } = await supabase.from('channels').update(upd).eq('id', id);
            if (uerr) throw new Error(uerr.message);
            invalidateVod();
            await logAction(req.body.operator_name, 'ربط TMDB', row.name + ' ← ' + tid);
            res.json({ success: true, matched: d.title || d.name || null, year: upd.year || null });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });

    app.post(['/admin/enrich-retry', '/api/admin/enrich-retry'], async (req, res) => {
        try {
            const kind = kindOf(req.body && req.body.kind);
            let q = supabase.from('channels').update({ tmdb_id: null }, { count: 'exact' }).eq('kind', kind).eq('tmdb_id', -1);
            if (kind === 'series') q = q.not('series_id', 'is', null);
            const { error, count } = await q;
            if (error) throw new Error(error.message);
            await logAction(req.body.operator_name, 'إعادة محاولة الإثراء', (kind === 'series' ? 'مسلسلات' : 'أفلام') + ': ' + (count || 0));
            res.json({ success: true, reset: count || 0 });
        } catch (err) { res.status(500).json({ success: false, message: err.message }); }
    });
};
