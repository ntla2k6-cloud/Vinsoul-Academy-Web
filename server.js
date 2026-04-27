const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcryptjs');

const app    = express();
const PORT   = process.env.PORT || 3000;
const DB     = path.join(__dirname, 'database.json');
const USERS  = path.join(__dirname, 'users.json');
const SECRET = 'vinsoul_secret_key_2025';

app.use(cors());
app.use(express.json({ limit: '20mb' }));

// ── Chặn file nhạy cảm ──
// Chặn file nhạy cảm phía server (KHÔNG chặn auth.js vì đó là file frontend)
['server.js','users.json','database.json'].forEach(file => {
  app.get('/' + file, (_, res) => res.status(403).end());
});

// ── Database ──
const EMPTY = { students:[], staff:[], leads:[], classes:[], attendance:[], makeups:[], templates:[], customCourses:[], customPrices:{} };

function loadDB() {
  try { return { ...EMPTY, ...JSON.parse(fs.readFileSync(DB,'utf8')) }; }
  catch { return {...EMPTY}; }
}
function saveDB(d) {
  fs.writeFileSync(DB + '.tmp', JSON.stringify(d,null,2));
  fs.renameSync(DB + '.tmp', DB);
}

// ── Users ──
function loadUsers() {
  if (!fs.existsSync(USERS)) {
    const def = [{ id:1, username:'admin', passwordHash: bcrypt.hashSync('Vinsoul@2024',10), displayName:'Quản Trị Viên', role:'admin' }];
    fs.writeFileSync(USERS, JSON.stringify(def,null,2));
    return def;
  }
  try { return JSON.parse(fs.readFileSync(USERS,'utf8')); }
  catch { return []; }
}
function saveUsers(u) { fs.writeFileSync(USERS, JSON.stringify(u,null,2)); }

// ── Brute force ──
const tries = new Map();
function locked(ip) {
  const r = tries.get(ip); if (!r) return false;
  if (Date.now() > r.reset) { tries.delete(ip); return false; }
  return r.n >= 5;
}
function fail(ip) {
  const r = tries.get(ip) || { n:0, reset: Date.now()+900000 };
  if (Date.now() > r.reset) { r.n=0; r.reset=Date.now()+900000; }
  r.n++; tries.set(ip,r);
}

// ── Auth middleware ──
function auth(req, res, next) {
  const h = req.headers['authorization'] || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : h;
  if (!t) return res.status(401).json({ error:'Chưa đăng nhập' });
  try { req.user = jwt.verify(t, SECRET); next(); }
  catch { res.status(401).json({ error:'Phiên đăng nhập hết hạn' }); }
}
function admin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error:'Chỉ quản trị viên mới có quyền này' });
  next();
}

// ════════════════════════════
//  AUTH
// ════════════════════════════
app.post('/api/auth/login', (req, res) => {
  const ip = req.ip || '';
  if (locked(ip)) return res.status(429).json({ error:'Tạm khóa do đăng nhập sai nhiều lần. Thử lại sau 15 phút.' });
  const { username='', password='' } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'Vui lòng nhập tên đăng nhập và mật khẩu' });
  const users = loadUsers();
  const user  = users.find(u => u.username === username.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    fail(ip);
    const r = tries.get(ip);
    return res.status(401).json({ error:`Sai tên đăng nhập hoặc mật khẩu. Còn ${Math.max(0,5-(r?r.n:1))} lần thử.` });
  }
  tries.delete(ip);
  const token = jwt.sign({ id:user.id, username:user.username, displayName:user.displayName, role:user.role }, SECRET, { expiresIn:'8h' });
  res.json({ token, username:user.username, displayName:user.displayName, role:user.role });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ username:req.user.username, displayName:req.user.displayName, role:req.user.role });
});

app.post('/api/auth/change-password', auth, (req, res) => {
  const { currentPassword='', newPassword='' } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error:'Vui lòng nhập đầy đủ thông tin' });
  if (newPassword.length < 8) return res.status(400).json({ error:'Mật khẩu mới phải có ít nhất 8 ký tự' });
  const users = loadUsers();
  const i = users.findIndex(u => u.id === req.user.id);
  if (i === -1) return res.status(404).json({ error:'Không tìm thấy tài khoản' });
  if (!bcrypt.compareSync(currentPassword, users[i].passwordHash)) return res.status(401).json({ error:'Mật khẩu hiện tại không đúng' });
  users[i].passwordHash = bcrypt.hashSync(newPassword, 10);
  saveUsers(users);
  res.json({ ok:true });
});

// ════════════════════════════
//  QUẢN TRỊ TÀI KHOẢN
// ════════════════════════════
app.get('/api/users', auth, admin, (req, res) => {
  res.json(loadUsers().map(u => ({ id:u.id, username:u.username, displayName:u.displayName, role:u.role })));
});

app.post('/api/users', auth, admin, (req, res) => {
  const { username='', password='', displayName='', role='' } = req.body || {};
  if (!username||!password||!displayName||!role) return res.status(400).json({ error:'Vui lòng nhập đầy đủ thông tin' });
  if (!['admin','staff'].includes(role)) return res.status(400).json({ error:'Phân quyền không hợp lệ' });
  if (password.length < 8) return res.status(400).json({ error:'Mật khẩu phải có ít nhất 8 ký tự' });
  const users = loadUsers();
  if (users.find(u => u.username === username.trim().toLowerCase())) return res.status(409).json({ error:'Tên đăng nhập đã tồn tại' });
  const u = { id:Date.now(), username:username.trim().toLowerCase(), passwordHash:bcrypt.hashSync(password,10), displayName:displayName.trim(), role };
  users.push(u); saveUsers(users);
  res.json({ ok:true, id:u.id });
});

app.put('/api/users/:id', auth, admin, (req, res) => {
  const id = Number(req.params.id);
  const { displayName, role, password } = req.body || {};
  const users = loadUsers();
  const i = users.findIndex(u => u.id === id);
  if (i === -1) return res.status(404).json({ error:'Không tìm thấy tài khoản' });
  if (users[i].id === req.user.id && role && role !== 'admin') return res.status(400).json({ error:'Không thể hạ cấp quyền của chính mình' });
  if (displayName) users[i].displayName = displayName.trim();
  if (role && ['admin','staff'].includes(role)) users[i].role = role;
  if (password) {
    if (password.length < 8) return res.status(400).json({ error:'Mật khẩu phải có ít nhất 8 ký tự' });
    users[i].passwordHash = bcrypt.hashSync(password, 10);
  }
  saveUsers(users);
  res.json({ ok:true });
});

app.delete('/api/users/:id', auth, admin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error:'Không thể xóa tài khoản của chính mình' });
  const users = loadUsers();
  const i = users.findIndex(u => u.id === id);
  if (i === -1) return res.status(404).json({ error:'Không tìm thấy tài khoản' });
  if (users[i].role === 'admin' && users.filter((_,j)=>j!==i&&_.role==='admin').length === 0) return res.status(400).json({ error:'Phải còn ít nhất 1 quản trị viên' });
  users.splice(i,1); saveUsers(users);
  res.json({ ok:true });
});

// ════════════════════════════
//  DỮ LIỆU
// ════════════════════════════
app.get('/api/load',   auth, (req, res) => res.json(loadDB()));

app.post('/api/save',  auth, (req, res) => {
  try {
    const db = loadDB();
    Object.keys(EMPTY).forEach(k => { if (req.body[k] !== undefined) db[k] = req.body[k]; });
    saveDB(db); res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/backup', auth, (req, res) => {
  const fn = `vinsoul_backup_${new Date().toISOString().slice(0,10)}.json`;
  res.setHeader('Content-Disposition', `attachment; filename="${fn}"`);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.send(JSON.stringify(loadDB(), null, 2));
});

app.post('/api/restore', auth, (req, res) => {
  try {
    if (typeof req.body !== 'object' || Array.isArray(req.body)) return res.status(400).json({ error:'Dữ liệu không hợp lệ' });
    saveDB({ ...EMPTY, ...req.body }); res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/export/:type', auth, (req, res) => {
  const { type } = req.params;
  const db = loadDB();
  const BOM = '\uFEFF';
  const fd = d => d ? new Date(d).toLocaleDateString('vi-VN') : '';
  const fn = n => Number(n||0).toLocaleString('vi-VN');
  const q  = v => `"${String(v||'').replace(/"/g,'""')}"`;
  let csv = BOM, filename = '';
  if (type === 'students') {
    filename = 'HocVien.csv';
    csv += ['#','Họ Tên','Ngày Sinh','Phụ Huynh','SĐT','Môn Học','Gói Lớp','Ngày BĐ','Ngày KT','Hình Thức','Số Tiền','Ngày Nộp','Ghi Chú'].map(q).join(',') + '\n';
    (db.students||[]).forEach((s,i) => { csv += [i+1,s.name,fd(s.dob),s.parent,s.phone,s.subject,s.pkg||'',fd(s.start),fd(s.end),s.payment,fn(s.amount),fd(s.paydate),s.note||''].map(q).join(',') + '\n'; });
  } else if (type === 'staff') {
    filename = 'NhanSu.csv';
    csv += ['#','Họ Tên','Ngày Sinh','SĐT','Vị Trí','Tình Trạng','Ghi Chú'].map(q).join(',') + '\n';
    (db.staff||[]).forEach((s,i) => { csv += [i+1,s.name,fd(s.dob),s.phone,s.role,s.status,s.note||''].map(q).join(',') + '\n'; });
  } else if (type === 'leads') {
    filename = 'HVTiemNang.csv';
    csv += ['#','Họ Tên','Ngày Sinh','Phụ Huynh','SĐT','Khóa Học','Nguồn','Tình Trạng','Ghi Chú'].map(q).join(',') + '\n';
    (db.leads||[]).forEach((l,i) => { csv += [i+1,l.name,fd(l.dob),l.parent,l.phone,l.course,l.source,l.status,l.note||''].map(q).join(',') + '\n'; });
  } else if (type === 'revenue') {
    filename = 'DoanhThu.csv';
    csv += ['#','Họ Tên','Môn Học','Gói Lớp','Hình Thức','Số Tiền','Ngày Nộp'].map(q).join(',') + '\n';
    const paid = (db.students||[]).filter(s => s.payment !== 'Chưa Thanh Toán' && s.amount);
    paid.forEach((s,i) => { csv += [i+1,s.name,s.subject,s.pkg||'',s.payment,fn(s.amount),fd(s.paydate)].map(q).join(',') + '\n'; });
    const total = paid.reduce((a,s) => a+Number(s.amount||0), 0);
    csv += `"","","","","TỔNG",${q(fn(total))},""\n`;
  } else return res.status(404).json({ error:'Loại không hợp lệ' });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
  res.send(csv);
});

// ── Static (sau tất cả API) ──
app.use(express.static(__dirname));

// ── Fallback về index.html ──
app.use((req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.status(404).send('Không tìm thấy trang');
});

// ── Error handler ──
app.use((err, req, res, next) => {
  console.error('[LỖI]', err.stack || err.message);
  if (req.path.startsWith('/api/')) return res.status(500).json({ error: err.message });
  res.status(500).send('Lỗi server: ' + err.message);
});

app.listen(PORT, () => {
  loadUsers();
  console.log('\n  ✅ Vinsoul Academy đang chạy tại: http://localhost:' + PORT);
  console.log('  📋 Tài khoản: admin / Vinsoul@2024\n');
});

process.on('uncaughtException', err => {
  console.error('\n[LỖI NGHIÊM TRỌNG]', err.message);
  console.error(err.stack);
});
process.on('unhandledRejection', (reason) => {
  console.error('\n[LỖI PROMISE]', reason);
});