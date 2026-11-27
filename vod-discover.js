// vod-discover.js — الاكتشاف والبحث للأفلام والمسلسلات:
//   GET /vod/suggest?q=&kind=     اقتراحات البحث أثناء الكتابة (وبدون q: الأكثر مشاهدة)
//   GET /vod/:id/similar?limit=   محتويات مشابهة (توصيات TMDB مطابَقة لمكتبتك + تشابه الأنواع)
//   GET /vod/person/:pid          صفحة ممثل: نبذة + أعماله الموجودة في مكتبتك فقط
//
// التركيب في server.js بعد سطر require('./vod-details'):
//     require('./vod-discover')(app, { loadVod, vodItem, tmdb, hasTmdb: () => !!TMDB_TOKEN, TMDB_IMG });
//
// الصلاحيات: مسارات الجهاز تُعرَّف في DEVICE_ROUTES / DEVICE_PATTERNS داخل server.js.

module.exports = function registerVodDiscover(app, { loadVod, vodItem, tmdb, hasTmdb, TMDB_IMG, store }) {
    const CACHE_MS = 6 * 60 * 60 * 1000;
    const PERSON_TTL = 30 * 24 * 60 * 60 * 1000; // نبذة الشخص وأعماله تتغير ببطء (محفوظة في vod_meta)
    const PERSON_VER = 2;
    const recCache = new Map();    // 'movie:123' -> { at, ids:[tmdb ids بالترتيب] }

    // توحيد النص العربي واللاتيني للبحث: حروف صغيرة، بلا تشكيل، توحيد الألف والياء والتاء المربوطة
    const norm = (t) => String(t || '').toLowerCase().normalize('NFKD')
        .replace(/[\u064B-\u065F\u0670\u0300-\u036f]/g, '')
        .replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه')
        .replace(/[^\p{L}\p{N}]+/gu, ' ').trim();

    // فهرس الأسماء المطبَّعة، يُعاد بناؤه فقط عند تغيّر مصفوفة الصفوف (تجديد الذاكرة المؤقتة)
    let idxRows = null, idx = null;
    function indexOf(rows) {
        if (idxRows !== rows) { idx = rows.map(c => ({ c, n: norm(c.name) })); idxRows = rows; }
        return idx;
    }
    const visible = (rows, req) => rows.filter(c => req.user || c.status !== 'hidden');
    const kindOk = (c, kind) => kind === 'series' ? c.kind === 'series' : kind === 'movie' ? c.kind === 'movie' : true;
    const brief = (c) => ({ id: c.id, name: c.name, kind: c.kind, year: c.year || null, logo_url: c.logo_url || null });

    // ---------------------------------------------------------------- اقتراحات البحث
    app.get(['/vod/suggest', '/api/vod/suggest'], async (req, res) => {
        try {
            const kind = String(req.query.kind || '');
            const q = norm(req.query.q);
            const rows = visible(await loadVod(), req).filter(c => kindOk(c, kind));
            if (!q) { // لا نص بعد: الأكثر مشاهدة
                const top = [...rows].sort((a, b) => (b.views || 0) - (a.views || 0)).slice(0, 10).map(brief);
                return res.json({ success: true, trending: top, suggestions: [] });
            }
            const okIds = new Set(rows.map(c => c.id));
            const hits = [];
            for (const { c, n } of indexOf(await loadVod())) {
                if (!okIds.has(c.id) || !n) continue;
                const pos = n.indexOf(q);
                if (pos < 0) continue;
                const rank = pos === 0 ? 0 : n[pos - 1] === ' ' ? 1 : 2; // بداية الاسم، بداية كلمة، أو داخل كلمة
                hits.push({ c, rank });
            }
            hits.sort((a, b) => a.rank - b.rank || (b.c.views || 0) - (a.c.views || 0));
            // نُسقط التكرار بنفس الاسم (نسخ بجودات مختلفة)
            const seen = new Set(), out = [];
            for (const { c } of hits) {
                const k = c.kind + ':' + norm(c.name);
                if (seen.has(k)) continue;
                seen.add(k); out.push(brief(c));
                if (out.length >= 8) break;
            }
            res.json({ success: true, suggestions: out, trending: [] });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    // ---------------------------------------------------------------- محتويات مشابهة
    async function tmdbRecs(kind, tmdbId) {
        const key = kind + ':' + tmdbId;
        const hit = recCache.get(key);
        if (hit && Date.now() - hit.at < CACHE_MS) return hit.ids;
        const base = (kind === 'series' ? '/tv/' : '/movie/') + tmdbId;
        const ids = [];
        for (const part of ['/recommendations', '/similar']) {
            try {
                const d = await tmdb(base + part, { page: 1 });
                (d.results || []).forEach(r => { if (!ids.includes(r.id)) ids.push(r.id); });
            } catch (e) { /* نكتفي بما وصلنا */ }
        }
        recCache.set(key, { at: Date.now(), ids });
        if (recCache.size > 1000) { for (const [k, v] of recCache) if (Date.now() - v.at > CACHE_MS) recCache.delete(k); }
        return ids;
    }

    const genresOf = (c) => new Set(String(c.genres || '').split(',').map(g => g.trim()).filter(Boolean));

    app.get(['/vod/:id/similar', '/api/vod/:id/similar'], async (req, res) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (!id) return res.status(400).json({ success: false, message: 'معرّف غير صالح' });
            const limit = Math.min(40, Math.max(1, parseInt(req.query.limit, 10) || 20));
            const all = visible(await loadVod(), req);
            const me = all.find(c => c.id === id);
            if (!me) return res.status(404).json({ success: false, message: 'غير موجود' });

            let recRank = new Map(); // tmdb_id -> ترتيب التوصية
            if (hasTmdb() && me.tmdb_id && me.tmdb_id > 0) {
                try { (await tmdbRecs(me.kind, me.tmdb_id)).forEach((t, i) => recRank.set(t, i)); } catch (e) {}
            }
            const myG = genresOf(me);
            const scored = [];
            for (const c of all) {
                if (c.id === me.id || c.kind !== me.kind) continue;
                let s = 0;
                if (c.tmdb_id > 0 && recRank.has(c.tmdb_id)) s += 60 - Math.min(40, recRank.get(c.tmdb_id)); // توصيات TMDB أولاً
                const g = genresOf(c);
                if (myG.size && g.size) {
                    let inter = 0; g.forEach(x => { if (myG.has(x)) inter++; });
                    s += (inter / (myG.size + g.size - inter)) * 30; // Jaccard
                }
                if (s === 0 && c.category !== me.category) continue; // لا صلة تُذكر
                if (c.category === me.category) s += 8;
                if (c.lang && me.lang && c.lang === me.lang) s += 4;
                if (c.year && me.year) s += Math.max(0, 4 - Math.abs(c.year - me.year));
                if (c.rating != null && me.rating != null) s += Math.max(0, 3 - Math.abs(Number(c.rating) - Number(me.rating)));
                scored.push({ c, s });
            }
            scored.sort((a, b) => b.s - a.s || (b.c.views || 0) - (a.c.views || 0));
            // نسقط تكرار نفس العمل بنسخ مختلفة (بنفس tmdb_id أو الاسم)
            const seen = new Set(), items = [];
            for (const { c } of scored) {
                const k = c.tmdb_id > 0 ? 't' + c.tmdb_id : 'n' + norm(c.name);
                if (seen.has(k)) continue;
                seen.add(k); items.push(vodItem(c));
                if (items.length >= limit) break;
            }
            res.json({ success: true, source: recRank.size ? 'tmdb+local' : 'local', items });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    // ---------------------------------------------------------------- صفحة ممثل
    async function loadPerson(pid) {
        const key = 'person:' + pid;
        const hit = await store.get(key, PERSON_TTL);
        if (hit && hit._v === PERSON_VER) return hit;
        let p;
        try { p = await tmdb('/person/' + pid, { append_to_response: 'combined_credits' }); }
        catch (e) { const old = await store.get(key, Infinity); if (old && old._v === PERSON_VER) return old; throw e; }
        let bio = String(p.biography || '').trim();
        if (!bio) { try { bio = String((await tmdb('/person/' + pid, { language: 'en-US' })).biography || '').trim(); } catch (e) {} }
        const cc = p.combined_credits || {};
        const asCredit = (c) => ({ kind: c.media_type === 'tv' ? 'series' : 'movie', tmdb_id: c.id, pop: c.popularity || 0 });
        const isMedia = (c) => c.media_type === 'movie' || c.media_type === 'tv';
        const data = {
            _v: PERSON_VER,
            person: {
                id: p.id, name: p.name,
                photo: p.profile_path ? TMDB_IMG + 'w342' + p.profile_path : null,
                biography: bio.slice(0, 2500) || null,
                birthday: p.birthday || null, deathday: p.deathday || null,
                place_of_birth: p.place_of_birth || null,
                known_for: p.known_for_department || null,
            },
            // التمثيل + الإخراج (للمخرجين تُضاف الأفلام التي أخرجوها)
            credits: [
                ...(cc.cast || []).filter(isMedia).map(asCredit),
                ...(cc.crew || []).filter(c => isMedia(c) && c.job === 'Director').map(asCredit),
            ],
        };
        await store.set(key, data);
        return data;
    }

    app.get(['/vod/person/:pid', '/api/vod/person/:pid'], async (req, res) => {
        try {
            const pid = parseInt(req.params.pid, 10);
            if (!pid) return res.status(400).json({ success: false, message: 'معرّف غير صالح' });
            if (!hasTmdb()) return res.status(400).json({ success: false, message: 'لم يُضبط TMDB_TOKEN في Render' });
            const { person, credits } = await loadPerson(pid);
            const all = visible(await loadVod(), req);
            const byKey = new Map();
            all.forEach(c => { if (c.tmdb_id > 0) { const k = c.kind + ':' + c.tmdb_id; if (!byKey.has(k)) byKey.set(k, c); } });
            const seen = new Set(), items = [];
            [...credits].sort((a, b) => b.pop - a.pop).forEach(cr => {
                const k = cr.kind + ':' + cr.tmdb_id;
                const row = byKey.get(k);
                if (row && !seen.has(k)) { seen.add(k); items.push(vodItem(row)); }
            });
            res.json({ success: true, person, items: items.slice(0, 60), credits_total: credits.length });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });
};
