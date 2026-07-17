const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
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

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public')); // フロントエンドのHTMLを配置するディレクトリ

async function resolveSession(req, res, next) {
    const token = req.cookies[SESSION_COOKIE_NAME];
    req.currentUser = null;

    if (token) {
        const { data: session } = await supabase
            .from('sessions')
            .select('*, users(*)')
            .eq('token', token)
            .maybeSingle();

        if (session && new Date(session.expires_at) > new Date()) {
            req.currentUser = session.users;
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

// ============================================
// ルートパス
// ============================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// フロントエンドが認証情報を取得するためのエンドポイント
app.get('/api/config', (req, res) => {
    res.json({
        supabaseUrl: SUPABASE_URL,
        supabaseKey: SUPABASE_ANON_KEY
    });
});

// ============================================
// 現在のログイン状態を返す
// ============================================
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

// ============================================
// 新規登録
// ============================================
app.post('/api/register', async (req, res) => {
    try {
        const { handle, password, display_name } = req.body;

        if (!handle || !password) {
            return res.status(400).json({ error: 'ユーザー名とパスワードは必須です' });
        }
        if (!HANDLE_REGEX.test(handle)) {
            return res.status(400).json({ error: 'ユーザー名は3〜15文字の半角英数字とアンダースコアのみ使用できます' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'パスワードは6文字以上にしてください' });
        }

        // 既存ユーザーチェック
        const { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('handle', handle)
            .maybeSingle();

        if (existing) {
            return res.status(409).json({ error: 'このユーザー名は既に使用されています' });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const { data: newUser, error } = await supabase
            .from('users')
            .insert([{
                handle,
                password_hash: passwordHash,
                display_name: display_name && display_name.trim() ? display_name.trim() : handle
            }])
            .select()
            .single();

        if (error) {
            console.error('登録エラー:', error);
            return res.status(500).json({ error: '登録に失敗しました' });
        }

        await createSessionAndSetCookie(res, newUser.id);

        res.json({
            success: true,
            user: {
                id: newUser.id,
                handle: newUser.handle,
                display_name: newUser.display_name
            }
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { handle, password } = req.body;

        if (!handle || !password) {
            return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
        }

        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('handle', handle)
            .maybeSingle();

        if (!user) {
            return res.status(401).json({ error: 'ユーザー名またはパスワードが違います' });
        }

        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
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
        console.error(e);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

// ============================================
// ログアウト
// ============================================
app.post('/api/logout', async (req, res) => {
    const token = req.cookies[SESSION_COOKIE_NAME];
    if (token) {
        await supabase.from('sessions').delete().eq('token', token);
    }
    res.clearCookie(SESSION_COOKIE_NAME);
    res.json({ success: true });
});

// ============================================
// プロフィール更新
// ============================================
app.put('/api/profile', requireAuth, async (req, res) => {
    const { display_name, bio, location, website, birth, banner_color } = req.body;

    const { data, error } = await supabase
        .from('users')
        .update({
            display_name: display_name || req.currentUser.display_name,
            bio: bio ?? '',
            location: location ?? '',
            website: website ?? '',
            birth: birth ?? '',
            banner_color: banner_color || '#1d9bf0'
        })
        .eq('id', req.currentUser.id)
        .select()
        .single();

    if (error) {
        return res.status(500).json({ error: 'プロフィール更新に失敗しました' });
    }

    await supabase
        .from('posts')
        .update({ display_name: data.display_name })
        .eq('user_id', req.currentUser.id);

    res.json({ success: true, user: data });
});

app.post('/api/posts', requireAuth, async (req, res) => {
    const { content, parent_id } = req.body;

    if (!content || !content.trim()) {
        return res.status(400).json({ error: '投稿内容を入力してください' });
    }
    if (content.length > MAX_POST_LENGTH) {
        return res.status(400).json({ error: `投稿は${MAX_POST_LENGTH}文字以内にしてください` });
    }

    const { data, error } = await supabase
        .from('posts')
        .insert([{
            user_id: req.currentUser.id,
            display_name: req.currentUser.display_name,
            handle: req.currentUser.handle,
            content: content.trim(),
            parent_id: parent_id || null
        }])
        .select()
        .single();

    if (error) {
        console.error('投稿エラー:', error);
        return res.status(500).json({ error: '投稿に失敗しました' });
    }

    res.json({ success: true, post: data });
});

app.post('/api/posts/:id/view', async (req, res) => {
    const { id } = req.params;
    const { data, error } = await supabase.rpc('increment_impression', { p_post_id: id });

    if (error) {
        console.error('インプレッション加算エラー:', error);
        return res.status(500).json({ error: '失敗しました' });
    }

    res.json({ success: true, views: data });
});

async function createSessionAndSetCookie(res, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

    await supabase.from('sessions').insert([{
        token,
        user_id: userId,
        expires_at: expiresAt.toISOString()
    }]);

    res.cookie(SESSION_COOKIE_NAME, token, {
        httpOnly: true,
        maxAge: SESSION_TTL_MS,
        sameSite: 'lax'
    });
}

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
