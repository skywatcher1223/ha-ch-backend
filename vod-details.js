// vod-details.js — تفاصيل فيلم/مسلسل للتطبيق: الممثلون، المخرج، المقاطع الدعائية، التقييم، التصنيف العمري، مصادر التشغيل.
//   GET /vod/:id/details        (يصل إليه جهاز مفعَّل بكود صالح — انظر DEVICE_PATTERNS في server.js)
//   GET /series/:id/meta?s=1,2  معلومات حلقات المواسم من TMDB: العنوان والوصف وتاريخ العرض والصورة والتقييم
//
// التركيب في server.js: مباشرة بعد تعريف دوال TMDB (بعد سطر enrichItem):
//     require('./vod-details')(app, { supabase, tmdb, hasTmdb: () => !!TMDB_TOKEN, TMDB_IMG, store });
//
// يعتمد على tmdb_id المحفوظ عند «إثراء الأفلام» من اللوحة. إن لم يُثرَ العنصر بعد
// تُرجَع مصادر التشغيل فقط، ويبقى الباقي فارغاً دون أي خطأ.

module.exports = function registerVodDetails(app, { supabase, tmdb, hasTmdb, TMDB_IMG, store }) {
    const DETAIL_TTL = 14 * 24 * 60 * 60 * 1000; // التفاصيل تتغير ببطء
    const SEASON_TTL = 3 * 24 * 60 * 60 * 1000;  // حلقات جديدة قد تُضاف للمواسم الجارية
    const VER = 2; // ارفعه عند تغيير شكل البيانات المحفوظة ليُعاد جلبها

    const youtube = (key) => 'https://www.youtube.com/watch?v=' + key;

    // مصادر التشغيل: الرابط الأساسي ثم البدائل، بلا تكرار
    function buildSources(row) {
        const seen = new Set(), out = [];
        [row.primary_url, row.alt_url_1, row.alt_url_2, row.alt_url_3].forEach((u) => {
            const url = String(u || '').trim();
            if (url && !seen.has(url)) { seen.add(url); out.push({ label: 'المصدر ' + (out.length + 1), url }); }
        });
        return out;
    }

    function pickTrailers(videos) {
        const list = ((videos && videos.results) || []).filter(v => v.site === 'YouTube' && v.key);
        const rank = (v) =>
            (v.type === 'Trailer' ? 0 : v.type === 'Teaser' ? 10 : 20) +
            (v.official ? 0 : 3) +
            (v.iso_639_1 === 'ar' ? 0 : v.iso_639_1 === 'en' ? 1 : 2);
        return list.sort((a, b) => rank(a) - rank(b)).slice(0, 3)
            .map(v => ({ name: v.name || 'مقطع دعائي', key: v.key, url: youtube(v.key) }));
    }

    function certification(d, isTv) {
        try {
            if (isTv) {
                const r = ((d.content_ratings && d.content_ratings.results) || []).find(x => x.iso_3166_1 === 'US');
                return (r && r.rating) || null;
            }
            const us = ((d.release_dates && d.release_dates.results) || []).find(x => x.iso_3166_1 === 'US');
            const c = us && (us.release_dates || []).map(x => x.certification).find(Boolean);
            return c || null;
        } catch (e) { return null; }
    }

    async function loadTmdb(kind, tmdbId) {
        const key = kind + ':' + tmdbId;
        const hit = await store.get(key, DETAIL_TTL);
        if (hit && hit._v === VER) return hit;
        const isTv = kind === 'series';
        let d;
        try {
            d = await tmdb((isTv ? '/tv/' : '/movie/') + tmdbId, {
                append_to_response: isTv ? 'credits,videos,content_ratings' : 'credits,videos,release_dates',
                include_video_language: 'ar,en,null',
            });
        } catch (e) { // عند تعطّل TMDB نُرجع النسخة المحفوظة ولو قديمة
            const old = await store.get(key, Infinity);
            if (old && old._v === VER) return old;
            throw e;
        }
        const crew = (d.credits && d.credits.crew) || [];
        const person = (p) => ({ id: p.id, name: p.name, photo: p.profile_path ? TMDB_IMG + 'w185' + p.profile_path : null });
        const dirs = isTv ? (d.created_by || []) : crew.filter(p => p.job === 'Director');
        const data = {
            _v: VER,
            tagline: d.tagline || null,
            original_title: d.original_title || d.original_name || null,
            vote_average: d.vote_average > 0 ? Math.round(d.vote_average * 10) / 10 : null,
            vote_count: d.vote_count || 0,
            release_date: d.release_date || d.first_air_date || null,
            status: d.status || null,
            countries: ((d.production_countries || d.origin_country || [])).map(c => (c && c.name) || c).filter(Boolean).slice(0, 3),
            certification: certification(d, isTv),
            directors: dirs.map(p => p.name).filter(Boolean).slice(0, 3),
            director_people: dirs.slice(0, 3).map(person),
            // صور بدقة أعلى لرأس الصفحة (القوائم تبقى بالحجم الصغير)
            poster_hd: d.poster_path ? TMDB_IMG + 'w780' + d.poster_path : null,
            backdrop_hd: d.backdrop_path ? TMDB_IMG + 'w1280' + d.backdrop_path : null,
            season_numbers: isTv ? (d.seasons || []).map(x => x.season_number).filter(n => Number.isInteger(n)) : [],
            cast: ((d.credits && d.credits.cast) || []).slice(0, 15).map(p => ({
                id: p.id,
                name: p.name,
                character: p.character || null,
                photo: p.profile_path ? TMDB_IMG + 'w185' + p.profile_path : null,
            })),
            trailers: pickTrailers(d.videos),
        };
        await store.set(key, data);
        return data;
    }

    // معلومات موسم واحد: {name, overview, air_date, poster, episodes:{ "1": {title, overview, air_date, still, rating, runtime} }}
    async function loadSeason(tmdbId, n) {
        const key = 'season:' + tmdbId + ':' + n;
        const hit = await store.get(key, SEASON_TTL);
        if (hit && hit._v === VER) return hit;
        let d;
        try { d = await tmdb('/tv/' + tmdbId + '/season/' + n); }
        catch (e) { const old = await store.get(key, Infinity); if (old && old._v === VER) return old; throw e; }
        let en = null;
        if ((d.episodes || []).some(e => !e.overview)) { // وصف إنجليزي لما ينقصه وصف عربي (طلب واحد للموسم)
            try { en = await tmdb('/tv/' + tmdbId + '/season/' + n, { language: 'en-US' }); } catch (e) {}
        }
        const enBy = new Map(((en && en.episodes) || []).map(e => [e.episode_number, e.overview]));
        const episodes = {};
        (d.episodes || []).forEach(e => {
            episodes[e.episode_number] = {
                title: e.name || null,
                overview: String(e.overview || enBy.get(e.episode_number) || '').slice(0, 800) || null,
                air_date: e.air_date || null,
                still: e.still_path ? TMDB_IMG + 'w300' + e.still_path : null,
                rating: e.vote_average > 0 ? Math.round(e.vote_average * 10) / 10 : null,
                runtime: e.runtime || null,
            };
        });
        const data = {
            _v: VER, name: d.name || null, overview: d.overview || null, air_date: d.air_date || null,
            poster: d.poster_path ? TMDB_IMG + 'w342' + d.poster_path : null, episodes,
        };
        await store.set(key, data);
        return data;
    }

    app.get(['/series/:id/meta', '/api/series/:id/meta'], async (req, res) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (!id) return res.status(400).json({ success: false, message: 'معرّف غير صالح' });
            const { data: row, error } = await supabase.from('channels').select('id, kind, status, tmdb_id').eq('id', id).maybeSingle();
            if (error) throw new Error(error.message);
            if (!row || row.kind !== 'series' || (row.status === 'hidden' && !req.user)) return res.status(404).json({ success: false, message: 'غير موجود' });
            if (!hasTmdb() || !(row.tmdb_id > 0)) return res.json({ success: true, enriched: false, seasons: {} });
            const want = String(req.query.s || '').split(',').map(x => parseInt(x, 10)).filter(Number.isInteger);
            let nums = want;
            if (!nums.length) nums = (await loadTmdb('series', row.tmdb_id)).season_numbers || [];
            nums = [...new Set(nums)].slice(0, 30);
            const seasons = {};
            let next = 0;
            const worker = async () => {
                while (next < nums.length) {
                    const n = nums[next++];
                    try { const { _v, ...rest } = await loadSeason(row.tmdb_id, n); seasons[n] = rest; } catch (e) { /* موسم غير موجود في TMDB */ }
                }
            };
            await Promise.all(Array.from({ length: 4 }, worker));
            res.json({ success: true, enriched: true, seasons });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    app.get(['/vod/:id/details', '/api/vod/:id/details'], async (req, res) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (!id) return res.status(400).json({ success: false, message: 'معرّف غير صالح' });
            const { data: row, error } = await supabase.from('channels')
                .select('id, kind, status, tmdb_id, primary_url, alt_url_1, alt_url_2, alt_url_3').eq('id', id).maybeSingle();
            if (error) throw new Error(error.message);
            if (!row || (row.kind !== 'movie' && row.kind !== 'series')) return res.status(404).json({ success: false, message: 'غير موجود' });
            if (row.status === 'hidden' && !req.user) return res.status(404).json({ success: false, message: 'غير موجود' });

            // مسلسل: الحلقات لها مسارها الخاص، فلا نكشف روابط هنا
            const sources = row.kind === 'movie' ? buildSources(row) : [];
            let extra = {};
            if (hasTmdb() && row.tmdb_id && row.tmdb_id > 0) {
                try { extra = await loadTmdb(row.kind, row.tmdb_id); }
                catch (e) { console.warn('vod-details TMDB:', e.message); } // نُرجع المصادر حتى لو فشل TMDB
            }
            res.json({
                success: true,
                id,
                enriched: !!extra.cast,
                tagline: null, original_title: null, vote_average: null, vote_count: 0, release_date: null,
                countries: [], certification: null, directors: [], cast: [], trailers: [],
                ...extra,
                _v: undefined,
                sources,
            });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });
};
