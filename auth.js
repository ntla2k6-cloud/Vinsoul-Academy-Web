// ═══════════════════════════════════════════════════
//  auth.js – Vinsoul Academy (đặt trong public/)
//  Load TRƯỚC app.js trong index.html
// ═══════════════════════════════════════════════════

// ── Tự động gắn token vào MỌI fetch gọi /api/ ──
// Làm điều này TRƯỚC KHI app.js chạy để mọi save/load đều có token
const _originalFetch = window.fetch.bind(window);
window.fetch = function(url, opts = {}) {
  if (typeof url === 'string' && url.startsWith('/api/')) {
    const token = localStorage.getItem('vs_token');
    if (token) {
      opts.headers = { ...(opts.headers || {}), 'Authorization': token };
    }
  }
  return _originalFetch(url, opts).then(res => {
    // Nếu bất kỳ API nào trả về 401 thì tự logout
    if (res.status === 401 && typeof url === 'string' && url.startsWith('/api/') && !url.includes('/auth/')) {
      VS_AUTH.logout();
    }
    return res;
  });
};

const VS_AUTH = {

  // Đăng xuất
  logout: () => {
    localStorage.removeItem('vs_token');
    location.reload();
  },

  // Kiểm tra token khi load trang
  check: async () => {
    const token = localStorage.getItem('vs_token');
    if (!token) {
      VS_AUTH.showLoginForm();
      return;
    }
    try {
      const r = await _originalFetch('/api/auth/me', {
        headers: { 'Authorization': token }
      });
      if (!r.ok) throw new Error();
      const user = await r.json();

      // Token hợp lệ, hiện app
      const nameEl = document.getElementById('sidebar-user-name');
      const roleEl = document.getElementById('sidebar-user-role');
      if (nameEl) nameEl.textContent = user.displayName || user.username;
      if (roleEl) roleEl.textContent = user.role === 'admin' ? 'Quản Trị Viên' : 'Nhân Viên';

      const appEl = document.getElementById('vs-app');
      if (appEl) appEl.style.display = 'block';

      // Gọi init của app.js nếu có
      if (typeof window.initAppAfterLogin === 'function') {
        window.initAppAfterLogin();
      }
    } catch {
      localStorage.removeItem('vs_token');
      VS_AUTH.showLoginForm();
    }
  },

  // Hiển thị form đăng nhập
  showLoginForm: () => {
    // Ẩn app
    const appEl = document.getElementById('vs-app');
    if (appEl) appEl.style.display = 'none';

    // Xóa form cũ nếu có
    const old = document.getElementById('vs-login-overlay');
    if (old) old.remove();

    const overlay = document.createElement('div');
    overlay.id = 'vs-login-overlay';
    overlay.innerHTML = `
      <style>
        #vs-login-overlay {
          position:fixed;inset:0;z-index:99999;
          background:linear-gradient(135deg,#1a2f3a 0%,#234A5B 100%);
          display:flex;align-items:center;justify-content:center;
          font-family:'Be Vietnam Pro',sans-serif;
        }
        .vsl-card {
          background:#fff;border-radius:20px;padding:40px 36px;
          width:100%;max-width:380px;
          box-shadow:0 20px 60px rgba(0,0,0,0.4);
        }
        .vsl-logo {
          text-align:center;margin-bottom:28px;
        }
        .vsl-logo-badge {
          display:inline-flex;align-items:center;justify-content:center;
          width:52px;height:52px;border-radius:14px;
          background:linear-gradient(135deg,#234A5B,#2d5f75);
          font-size:13px;font-weight:900;color:#F69922;letter-spacing:1px;
          margin-bottom:10px;
        }
        .vsl-title { font-size:22px;font-weight:900;color:#234A5B;letter-spacing:1px;text-transform:uppercase; }
        .vsl-sub   { font-size:11px;color:#7a9aaa;margin-top:2px; }
        .vsl-label { font-size:13px;font-weight:600;color:#234A5B;display:block;margin-bottom:6px; }
        .vsl-input {
          width:100%;border:1.5px solid #e0e0e0;border-radius:10px;
          padding:11px 14px;font-size:14px;font-family:'Be Vietnam Pro',sans-serif;
          outline:none;transition:border-color .2s;margin-bottom:16px;
          color:#1a1a1a;background:#fff;
        }
        .vsl-input:focus { border-color:#F69922; }
        .vsl-btn {
          width:100%;background:linear-gradient(135deg,#F69922,#e08515);
          color:#1a1a1a;border:none;border-radius:10px;
          padding:13px;font-size:15px;font-weight:700;cursor:pointer;
          font-family:'Be Vietnam Pro',sans-serif;transition:opacity .2s;
        }
        .vsl-btn:hover { opacity:0.88; }
        .vsl-btn:disabled { opacity:0.55;cursor:not-allowed; }
        .vsl-error {
          background:#fff0f0;border:1px solid #f5c6cb;color:#D94F4F;
          border-radius:8px;padding:10px 14px;font-size:13px;
          margin-bottom:14px;display:none;
        }
        .vsl-pass-wrap { position:relative;margin-bottom:16px; }
        .vsl-pass-wrap .vsl-input { margin-bottom:0; }
        .vsl-pass-eye {
          position:absolute;right:12px;top:50%;transform:translateY(-50%);
          cursor:pointer;color:#7a9aaa;font-size:13px;user-select:none;
        }
        .vsl-footer { text-align:center;font-size:11px;color:#bbb;margin-top:18px; }
      </style>
      <div class="vsl-card">
        <div class="vsl-logo">
          <div class="vsl-logo-badge">VS</div>
          <div class="vsl-title">VINSOUL</div>
          <div class="vsl-sub">Âm Nhạc & Nghệ Thuật – Quản Lý</div>
        </div>
        <div id="vsl-error" class="vsl-error"></div>
        <label class="vsl-label">Tên đăng nhập</label>
        <input id="vsl-u" class="vsl-input" type="text" placeholder="Nhập tên đăng nhập"
          autocomplete="username" autocapitalize="none" spellcheck="false" />
        <label class="vsl-label">Mật khẩu</label>
        <div class="vsl-pass-wrap">
          <input id="vsl-p" class="vsl-input" type="password" placeholder="Nhập mật khẩu"
            autocomplete="current-password" />
          <span class="vsl-pass-eye" id="vsl-eye" onclick="
            const i=document.getElementById('vsl-p');
            i.type=i.type==='password'?'text':'password';
            this.textContent=i.type==='password'?'Hiện':'Ẩn';
          ">Hiện</span>
        </div>
        <button id="vsl-btn" class="vsl-btn" onclick="VS_AUTH._doLogin()">ĐĂNG NHẬP</button>
        <div class="vsl-footer">Vinsoul Academy</div>
      </div>
    `;
    document.body.appendChild(overlay);

    // Focus vào ô username
    setTimeout(() => {
      const el = document.getElementById('vsl-u');
      if (el) el.focus();
    }, 50);

    // Enter để submit
    overlay.addEventListener('keydown', e => {
      if (e.key === 'Enter') VS_AUTH._doLogin();
    });
  },

  // Xử lý đăng nhập
  _doLogin: async () => {
    const u      = (document.getElementById('vsl-u')?.value || '').trim();
    const p      = document.getElementById('vsl-p')?.value || '';
    const errEl  = document.getElementById('vsl-error');
    const btn    = document.getElementById('vsl-btn');

    if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }

    if (!u || !p) {
      if (errEl) { errEl.textContent = 'Vui lòng nhập tên đăng nhập và mật khẩu'; errEl.style.display = 'block'; }
      return;
    }

    if (btn) { btn.disabled = true; btn.textContent = 'Đang xác thực...'; }

    try {
      const res  = await _originalFetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p })
      });
      const data = await res.json();

      if (!res.ok) {
        if (errEl) { errEl.textContent = data.error || 'Đăng nhập thất bại'; errEl.style.display = 'block'; }
        if (btn) { btn.disabled = false; btn.textContent = 'ĐĂNG NHẬP'; }
        return;
      }

      // Lưu token và reload
      localStorage.setItem('vs_token', data.token);
      location.reload();

    } catch {
      if (errEl) { errEl.textContent = 'Lỗi kết nối đến server'; errEl.style.display = 'block'; }
      if (btn) { btn.disabled = false; btn.textContent = 'ĐĂNG NHẬP'; }
    }
  }
};

// ── Chạy khi DOM sẵn sàng ──
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', VS_AUTH.check);
} else {
  VS_AUTH.check();
}