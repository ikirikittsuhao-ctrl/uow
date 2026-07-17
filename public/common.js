// ================ グローバル設定 ================

const MAX_POST_LENGTH = 280;
let currentUser = null; // { id, handle, display_name, bio, location, website, birth, banner_color }

// ================ セキュリティ対策 ================

// XSS対策：HTML エスケープ
function escapeHTML(str) {
    if (!str) return '';
    if (typeof str !== 'string') return String(str);
    
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '/': '&#x2F;'
    };
    
    return str.replace(/[&<>"'\/]/g, char => map[char] || char);
}

// URL パラメータの安全な抽出
function getSafeQueryParam(paramName) {
    const params = new URLSearchParams(window.location.search);
    const value = params.get(paramName);
    
    // 値を検証（UUIDなら）
    if (value && /^[0-9a-f-]{36}$/.test(value)) {
        return value;
    } else if (value && /^[a-zA-Z0-9_]{3,15}$/.test(value)) {
        // ハンドル形式なら
        return value;
    }
    
    return null;
}

// ================ ユーザー認証 ================

// ログイン状態をサーバーに問い合わせる
async function fetchCurrentUser() {
    try {
        const res = await fetch('/api/me', {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include' // Cookie を含める
        });
        
        if (!res.ok) {
            currentUser = null;
            return null;
        }
        
        const data = await res.json();
        currentUser = data.loggedIn ? data.user : null;
        return currentUser;
    } catch (e) {
        console.error('Failed to fetch current user:', e);
        currentUser = null;
        return null;
    }
}

// 未ログインならログインページへリダイレクト
async function requireLoginOrRedirect() {
    await fetchCurrentUser();
    if (!currentUser) {
        window.location.href = '/login.html';
        return false;
    }
    return true;
}

// ログアウト
async function logout() {
    try {
        await fetch('/api/logout', { 
            method: 'POST',
            credentials: 'include'
        });
    } catch (e) {
        console.error('Logout error:', e);
    }
    window.location.href = '/login.html';
}

// ================ 日時フォーマット ================

// 相対時間フォーマッタ（例：「2分前」）
function getRelativeTime(dateTimeStr) {
    try {
        const now = new Date();
        const past = new Date(dateTimeStr);
        
        if (isNaN(past.getTime())) {
            return '不明';
        }
        
        const msPerMinute = 60 * 1000;
        const msPerHour = msPerMinute * 60;
        const msPerDay = msPerHour * 24;
        const msPerWeek = msPerDay * 7;
        const msPerMonth = msPerDay * 30;
        const msPerYear = msPerDay * 365;
        
        const elapsed = now - past;
        
        if (elapsed < msPerMinute) {
            return Math.max(1, Math.round(elapsed / 1000)) + '秒前';
        } else if (elapsed < msPerHour) {
            return Math.round(elapsed / msPerMinute) + '分前';
        } else if (elapsed < msPerDay) {
            return Math.round(elapsed / msPerHour) + '時間前';
        } else if (elapsed < msPerWeek) {
            return Math.round(elapsed / msPerDay) + '日前';
        } else if (elapsed < msPerMonth) {
            return Math.round(elapsed / msPerWeek) + '週前';
        } else if (elapsed < msPerYear) {
            return Math.round(elapsed / msPerMonth) + 'か月前';
        } else {
            return Math.round(elapsed / msPerYear) + '年前';
        }
    } catch (e) {
        console.error('getRelativeTime error:', e);
        return '不明';
    }
}

// 日時をローカル形式でフォーマット
function formatDateTime(dateTimeStr, options = {}) {
    try {
        const date = new Date(dateTimeStr);
        if (isNaN(date.getTime())) {
            return '不明';
        }
        
        const defaultOptions = {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        };
        
        return date.toLocaleString('ja-JP', { ...defaultOptions, ...options });
    } catch (e) {
        console.error('formatDateTime error:', e);
        return '不明';
    }
}

// ================ 入力バリデーション ================

// ハンドルの検証
function isValidHandle(handle) {
    const HANDLE_REGEX = /^[a-zA-Z0-9_]{3,15}$/;
    return typeof handle === 'string' && HANDLE_REGEX.test(handle);
}

// パスワードの検証
function isValidPassword(password) {
    return typeof password === 'string' && password.length >= 6 && password.length <= 100;
}

// メールアドレスの検証（簡易）
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return typeof email === 'string' && emailRegex.test(email) && email.length <= 100;
}

// 投稿内容の検証
function isValidPostContent(content) {
    if (typeof content !== 'string') return false;
    const trimmed = content.trim();
    return trimmed.length > 0 && trimmed.length <= MAX_POST_LENGTH;
}

// ================ ローカルストレージ操作（安全版） ================

const SafeStorage = {
    // キーを namespace で隔離
    getKey: (key) => `sasuty_${key}`,
    
    setItem: (key, value) => {
        try {
            localStorage.setItem(SafeStorage.getKey(key), JSON.stringify(value));
            return true;
        } catch (e) {
            console.error('LocalStorage setItem error:', e);
            return false;
        }
    },
    
    getItem: (key) => {
        try {
            const value = localStorage.getItem(SafeStorage.getKey(key));
            return value ? JSON.parse(value) : null;
        } catch (e) {
            console.error('LocalStorage getItem error:', e);
            return null;
        }
    },
    
    removeItem: (key) => {
        try {
            localStorage.removeItem(SafeStorage.getKey(key));
            return true;
        } catch (e) {
            console.error('LocalStorage removeItem error:', e);
            return false;
        }
    },
    
    clear: () => {
        try {
            // sasuty_ で始まるキーだけを削除
            const keys = Object.keys(localStorage).filter(k => k.startsWith('sasuty_'));
            keys.forEach(k => localStorage.removeItem(k));
            return true;
        } catch (e) {
            console.error('LocalStorage clear error:', e);
            return false;
        }
    }
};

// ================ API リクエスト（共通処理） ================

// ジェネリック API リクエスト関数
async function apiRequest(endpoint, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        credentials: 'include' // Cookie を含める
    };
    
    try {
        const response = await fetch(endpoint, { ...defaultOptions, ...options });
        
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || `HTTP ${response.status}`);
        }
        
        return await response.json();
    } catch (e) {
        console.error(`API request failed (${endpoint}):`, e);
        throw e;
    }
}

// ログイン
async function login(handle, password) {
    return apiRequest('/api/login', {
        method: 'POST',
        body: JSON.stringify({ handle, password })
    });
}

// 登録
async function register(handle, password, displayName) {
    return apiRequest('/api/register', {
        method: 'POST',
        body: JSON.stringify({ handle, password, display_name: displayName })
    });
}

// プロフィール更新
async function updateProfile(profileData) {
    return apiRequest('/api/profile', {
        method: 'PUT',
        body: JSON.stringify(profileData)
    });
}

// 投稿作成
async function createPost(content, parentId = null) {
    return apiRequest('/api/posts', {
        method: 'POST',
        body: JSON.stringify({ content, parent_id: parentId })
    });
}

// ================ ユーティリティ関数 ================

// テキストをコピーしてクリップボードに保存
async function copyToClipboard(text) {
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
            return true;
        } else {
            // フォールバック（古いブラウザ対応）
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            return true;
        }
    } catch (e) {
        console.error('Copy to clipboard error:', e);
        return false;
    }
}

// URL を新しいタブで開く
function openInNewTab(url) {
    const validUrl = new URL(url, window.location.origin);
    window.open(validUrl.href, '_blank', 'noopener,noreferrer');
}

// ネットワーク接続状態を確認
function isOnline() {
    return navigator.onLine;
}

// デバイスが低速ネットワークかチェック
async function isSlowConnection() {
    if ('connection' in navigator) {
        const connection = navigator.connection;
        const effectiveType = connection.effectiveType;
        return effectiveType === '3g' || effectiveType === '4g' && connection.saveData;
    }
    return false;
}

// ページが見えているかチェック（フォーカス状態）
function isPageVisible() {
    return !document.hidden;
}

// ================ エラーハンドリング ================

// グローバル エラーハンドラ
window.addEventListener('error', (event) => {
    console.error('Uncaught error:', event.error);
    // 本番環境ではエラーログサーバーに送信
});

// Promise Rejection ハンドラ
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    // 本番環境ではエラーログサーバーに送信
});

// ================ 初期化 ================

// ページロード時に実行
document.addEventListener('DOMContentLoaded', () => {
    // ネットワーク接続状態の監視
    window.addEventListener('online', () => {
        console.log('Network connection restored');
    });
    
    window.addEventListener('offline', () => {
        console.warn('Network connection lost');
    });
    
    // セッションの定期更新（デバッグ用）
    // fetchCurrentUser(); // 必要に応じて各ページで呼び出す
});

// ================ デバッグ関数（開発環境のみ） ================

const DebugTools = {
    // ローカルストレージをクリア
    clearStorage: () => {
        SafeStorage.clear();
        console.log('LocalStorage cleared');
    },
    
    // 現在のユーザー情報をログ出力
    logCurrentUser: () => {
        console.log('Current user:', currentUser);
    },
    
    // Supabase の接続テスト
    testSupabaseConnection: async () => {
        try {
            const res = await fetch('/api/config');
            const config = await res.json();
            console.log('Supabase config:', config);
            return true;
        } catch (e) {
            console.error('Supabase connection error:', e);
            return false;
        }
    }
};

// 開発環境のみアクセス可能に
if (process.env.NODE_ENV === 'development' || window.location.hostname === 'localhost') {
    window.debug = DebugTools;
}

console.log('common.js loaded successfully');
