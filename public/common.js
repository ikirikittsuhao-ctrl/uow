const MAX_POST_LENGTH = 280;

let currentUser = null; // { id, handle, display_name, bio, location, website, birth, banner_color }

// ログイン状態をサーバーに問い合わせる
async function fetchCurrentUser() {
    try {
        const res = await fetch('/api/me');
        const data = await res.json();
        currentUser = data.loggedIn ? data.user : null;
        return currentUser;
    } catch (e) {
        console.error('ログイン状態の取得に失敗しました:', e);
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

async function logout() {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
}

function escapeHTML(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag));
}

// 相対時間フォーマッタ
function getRelativeTime(dateTimeStr) {
    const now = new Date();
    const past = new Date(dateTimeStr);
    const msPerMinute = 60 * 1000;
    const msPerHour = msPerMinute * 60;
    const msPerDay = msPerHour * 24;
    const elapsed = now - past;

    if (elapsed < msPerMinute) {
        return Math.max(1, Math.round(elapsed / 1000)) + '秒';
    } else if (elapsed < msPerHour) {
        return Math.round(elapsed / msPerMinute) + '分';
    } else if (elapsed < msPerDay) {
        return Math.round(elapsed / msPerHour) + '時間';
    } else {
        return past.toLocaleDateString([], { month: '2-digit', day: '2-digit' });
    }
}
