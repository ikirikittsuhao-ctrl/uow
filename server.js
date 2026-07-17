const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('mongo-sanitize');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://zcwvrtkleplyhujovxxp.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inpjd3ZydGtsZXBseWh1am92eHhwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQyODgxOTMsImV4cCI6MjA5OTg2NDE5M30.qcL9zHr757Yc_yqoIy1EsPbUa0gyYggukJ1Y-yEq-H4';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const SESSION_COOKIE_NAME = 'sasuty_session';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30日
const HANDLE_REGEX = /^[a-zA-Z0-9_]{3,15}$/;
const MAX_POST_LENGTH = 280;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ================ セキュリティ対策 ================

// Helmet.js: HTTP ヘッダーセキュリティ
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://*.supabase.co"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// レート制限（DDoS対策）
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15分
    max: 100, // 15分間に100リクエスト
    message: 'Too many requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/' // 静的コンテンツはスキップ
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // 15分間に5回まで
    message: 'Too many login attempts',
    skipSuccessfulRequests: true
});

const postLimiter = rateLimit({
    windowMs: 60 * 1000, // 1分
    max: 10, // 1分間に10投稿
    message: 'Too many posts, please try again later'
});

const viewLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30, // 1分間に30閲覧登録
    message: 'Too many view registrations'
});

app.use(generalLimiter);

// リクエスト本文パース
app.use(express.json({ limit: '10kb' })); // リクエストサイズ制限
app.use(express.urlencoded({ limit: '10kb', extended: false }));

// Cookie パーサー
app.use(cookieParser());

// MongoDB インジェクション対策（値のサニタイズ）
app.use((req, res, next) => {
    if (req.body) {
        req.body = mongoSanitize()(req.body);
    }
    if (req.query) {
        req.query = mongoSanitize()(req.query);
    }
    if (req.params) {
        req.params = mongoSanitize()(req.params);
    }
    next();
});

// 静的ファイル配信
app.use(express.static('public'));

// ================ セッション管理 ================

async function resolveSession(req, res, next) {
    const token = req.cookies[SESSION_COOKIE_NAME];
    req.currentUser = null;

    if (token && typeof token === 'string' && token.length === 64) {
        try {
            const { data: session } = await supabase
                .from('sessions')
                .select('*, users(*)')
                .eq('token', token)
                .maybeSingle();

            if (session && new Date(session.expires_at) > new Date()) {
                req.currentUser = session.users;
            }
        } catch (e) {
            console.error('Session resolution error:', e);
        }
    }
    next();
}

app.use(resolveSession);

function requireAuth(req, res, next) {
    if (!req.currentUser) {
        return res.status(401).json({ error: 'ログインが必要です' });
    }
    next();
}

// ================ ルート ================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/config', (req, res) => {
    res.json({
        supabaseUrl: SUPABASE_URL,
        supabaseKey: SUPABASE_ANON_KEY
    });
});

// 現在のログイン状態を返す
app.get('/api/me', (req, res) => {
    if (!req.currentUser) {
        return res.json({ loggedIn: false });
    }
    const u = req.currentUser;
    res.json({
        loggedIn: true,
        user: {
            id: u.id,
            handle: u.handle,
            display_name: u.display_name,
            bio: u.bio,
            location: u.location,
            website: u.website,
            birth: u.birth,
            banner_color: u.banner_color
        }
    });
});

// ================ 認証エンドポイント ================

// 新規登録
app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { handle, password, display_name } = req.body;

        // 入力検証
        if (!handle || typeof handle !== 'string' || !password || typeof password !== 'string') {
            return res.status(400).json({ error: 'ユーザー名とパスワードは必須です' });
        }

        const trimmedHandle = handle.trim();
        const trimmedPassword = password.trim();

        if (!HANDLE_REGEX.test(trimmedHandle)) {
            return res.status(400).json({ error: 'ユーザー名は3〜15文字の半角英数字とアンダースコアのみ使用できます' });
        }
        if (trimmedPassword.length < 6 || trimmedPassword.length > 100) {
            return res.status(400).json({ error: 'パスワードは6〜100文字にしてください' });
        }

        // 既存ユーザーチェック
        const { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('handle', trimmedHandle)
            .maybeSingle();

        if (existing) {
            return res.status(409).json({ error: 'このユーザー名は既に使用されています' });
        }

        const passwordHash = await bcrypt.hash(trimmedPassword, 12);
        const sanitizedDisplayName = display_name && typeof display_name === 'string'
            ? display_name.trim().substring(0, 50)
            : trimmedHandle;

        const { data: newUser, error } = await supabase
            .from('users')
            .insert([{
                handle: trimmedHandle,
                password_hash: passwordHash,
                display_name: sanitizedDisplayName
            }])
            .select()
            .single();

        if (error) {
            console.error('Register error:', error);
            return res.status(500).json({ error: '登録に失敗しました' });
        }

        await createSessionAndSetCookie(res, newUser.id);

        res.status(201).json({
            success: true,
            user: {
                id: newUser.id,
                handle: newUser.handle,
                display_name: newUser.display_name
            }
        });
    } catch (e) {
        console.error('Register error:', e);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

// ログイン
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { handle, password } = req.body;

        if (!handle || typeof handle !== 'string' || !password || typeof password !== 'string') {
            return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
        }

        const trimmedHandle = handle.trim();
        const trimmedPassword = password.trim();

        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('handle', trimmedHandle)
            .maybeSingle();

        if (!user || !await bcrypt.compare(trimmedPassword, user.password_hash)) {
            return res.status(401).json({ error: 'ユーザー名またはパスワードが違います' });
        }

        await createSessionAndSetCookie(res, user.id);

        res.json({
            success: true,
            user: {
                id: user.id,
                handle: user.handle,
                display_name: user.display_name
            }
        });
    } catch (e) {
        console.error('Login error:', e);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

// ログアウト
app.post('/api/logout', async (req, res) => {
    const token = req.cookies[SESSION_COOKIE_NAME];
    if (token && typeof token === 'string') {
        try {
            await supabase.from('sessions').delete().eq('token', token);
        } catch (e) {
            console.error('Logout error:', e);
        }
    }
    res.clearCookie(SESSION_COOKIE_NAME);
    res.json({ success: true });
});

// ================ プロフィール ================

app.put('/api/profile', requireAuth, async (req, res) => {
    try {
        const { display_name, bio, location, website, birth, banner_color } = req.body;

        // 入力検証
        const sanitizedData = {
            display_name: typeof display_name === 'string' ? display_name.trim().substring(0, 50) : req.currentUser.display_name,
            bio: typeof bio === 'string' ? bio.substring(0, 160) : '',
            location: typeof location === 'string' ? location.substring(0, 30) : '',
            website: typeof website === 'string' ? website.substring(0, 100) : '',
            birth: typeof birth === 'string' ? birth : '',
            banner_color: /^#[0-9a-f]{6}$/i.test(banner_color) ? banner_color : '#1d9bf0'
        };

        const { data, error } = await supabase
            .from('users')
            .update(sanitizedData)
            .eq('id', req.currentUser.id)
            .select()
            .single();

        if (error) {
            return res.status(500).json({ error: 'プロフィール更新に失敗しました' });
        }

        // ユーザーのすべての投稿を更新
        await supabase
            .from('posts')
            .update({ display_name: sanitizedData.display_name })
            .eq('user_id', req.currentUser.id);

        res.json({ success: true, user: data });
    } catch (e) {
        console.error('Profile update error:', e);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

// ================ 投稿 ================

app.post('/api/posts', requireAuth, postLimiter, async (req, res) => {
    try {
        const { content, parent_id } = req.body;

        if (!content || typeof content !== 'string') {
            return res.status(400).json({ error: '投稿内容を入力してください' });
        }

        const trimmedContent = content.trim();
        if (trimmedContent.length === 0 || trimmedContent.length > MAX_POST_LENGTH) {
            return res.status(400).json({ error: `投稿は1〜${MAX_POST_LENGTH}文字にしてください` });
        }

        // parent_id の検証（UUIDなら有効）
        let validParentId = null;
        if (parent_id) {
            if (typeof parent_id === 'string' && UUID_REGEX.test(parent_id)) {
                // 親投稿が実際に存在するか確認
                const { data: parentPost } = await supabase
                    .from('posts')
                    .select('id')
                    .eq('id', parent_id)
                    .maybeSingle();
                
                if (parentPost) {
                    validParentId = parent_id;
                }
            }
        }

        const { data, error } = await supabase
            .from('posts')
            .insert([{
                user_id: req.currentUser.id,
                display_name: req.currentUser.display_name,
                handle: req.currentUser.handle,
                content: trimmedContent,
                parent_id: validParentId
            }])
            .select()
            .single();

        if (error) {
            console.error('Post create error:', error);
            return res.status(500).json({ error: '投稿に失敗しました' });
        }

        res.status(201).json({ success: true, post: data });
    } catch (e) {
        console.error('Post create error:', e);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

// ================ インプレッション（閲覧数） ================

// インプレッション登録：1ユーザー1投稿につき1回だけカウント
app.post('/api/posts/:id/view', viewLimiter, async (req, res) => {
    try {
        const { id } = req.params;

        // ID の検証
        if (!id || typeof id !== 'string' || !UUID_REGEX.test(id)) {
            return res.status(400).json({ error: 'Invalid post ID' });
        }

        // タイムスタンプ検証（リプレイ攻撃対策）
        const { timestamp } = req.body;
        if (timestamp && Math.abs(Date.now() - timestamp) > 60000) {
            return res.status(400).json({ error: 'Request expired' });
        }

        // クライアント IP を記録して、同じ投稿の同じ IP からの複数ビューを防ぐ
        const clientIp = req.ip || req.connection.remoteAddress || 'unknown';

        // ユーザーエージェント
        const userAgent = req.get('user-agent') || 'unknown';

        // 同じ投稿に対するこのセッション/IP からの最近のビューをチェック
        // （実装はSupabaseのRPCで処理することをお勧め）
        
        // Supabase RPC: increment_impression
        const { data, error } = await supabase.rpc('increment_impression', { 
            p_post_id: id,
            p_client_ip: clientIp,
            p_user_agent: userAgent
        });

        if (error) {
            console.error('View registration error:', error);
            return res.status(500).json({ error: '閲覧登録に失敗しました' });
        }

        res.json({ success: true, views: data });
    } catch (e) {
        console.error('View registration error:', e);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

// ================ フォロー機能 ================

app.post('/api/follows', requireAuth, async (req, res) => {
    try {
        const { following_handle } = req.body;

        if (!following_handle || typeof following_handle !== 'string') {
            return res.status(400).json({ error: 'Invalid handle' });
        }

        const trimmedHandle = following_handle.trim();

        if (!HANDLE_REGEX.test(trimmedHandle)) {
            return res.status(400).json({ error: 'Invalid handle format' });
        }

        if (trimmedHandle === req.currentUser.handle) {
            return res.status(400).json({ error: '自分自身はフォローできません' });
        }

        // フォロー対象ユーザーが存在するか確認
        const { data: targetUser } = await supabase
            .from('users')
            .select('id')
            .eq('handle', trimmedHandle)
            .maybeSingle();

        if (!targetUser) {
            return res.status(404).json({ error: 'ユーザーが見つかりません' });
        }

        // 既にフォローしているか確認
        const { data: existingFollow } = await supabase
            .from('follows')
            .select('id')
            .eq('follower_handle', req.currentUser.handle)
            .eq('following_handle', trimmedHandle)
            .maybeSingle();

        if (existingFollow) {
            return res.status(409).json({ error: '既にフォローしています' });
        }

        const { error } = await supabase
            .from('follows')
            .insert([{
                follower_handle: req.currentUser.handle,
                following_handle: trimmedHandle
            }]);

        if (error) {
            console.error('Follow error:', error);
            return res.status(500).json({ error: 'フォローに失敗しました' });
        }

        res.status(201).json({ success: true });
    } catch (e) {
        console.error('Follow error:', e);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

app.delete('/api/follows/:handle', requireAuth, async (req, res) => {
    try {
        const { handle } = req.params;

        if (!handle || typeof handle !== 'string') {
            return res.status(400).json({ error: 'Invalid handle' });
        }

        const trimmedHandle = handle.trim();

        if (!HANDLE_REGEX.test(trimmedHandle)) {
            return res.status(400).json({ error: 'Invalid handle format' });
        }

        const { error } = await supabase
            .from('follows')
            .delete()
            .match({
                follower_handle: req.currentUser.handle,
                following_handle: trimmedHandle
            });

        if (error) {
            console.error('Unfollow error:', error);
            return res.status(500).json({ error: 'アンフォローに失敗しました' });
        }

        res.json({ success: true });
    } catch (e) {
        console.error('Unfollow error:', e);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

// ================ ユーティリティ ================

async function createSessionAndSetCookie(res, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

    try {
        await supabase.from('sessions').insert([{
            token,
            user_id: userId,
            expires_at: expiresAt.toISOString()
        }]);

        res.cookie(SESSION_COOKIE_NAME, token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: SESSION_TTL_MS,
            sameSite: 'lax',
            path: '/'
        });
    } catch (e) {
        console.error('Session creation error:', e);
        throw e;
    }
}

// エラーハンドリングミドルウェア
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'An unexpected error occurred' });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
