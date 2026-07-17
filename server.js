const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Supabase接続用の環境変数 (事前に.env等に定義してください)
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://zcwvrtkleplyhujovxxp.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inpjd3ZydGtsZXBseWh1am92eHhwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQyODgxOTMsImV4cCI6MjA5OTg2NDE5M30.qcL9zHr757Yc_yqoIy1EsPbUa0gyYggukJ1Y-yEq-H4';

// CORSやJSONパースのミドルウェア
app.use(express.json());
app.use(express.static('public')); // フロントエンドのHTMLを配置するディレクトリ

// ルートパスにアクセスした際に index.html を返す
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

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
