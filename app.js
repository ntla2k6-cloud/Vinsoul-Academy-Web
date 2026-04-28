// ── STATE ──
let students      = [];
let classes       = [];
let customCourses = [];
let customPrices  = {};
let staff         = [];
let leads         = [];
let attendance    = [];
let makeups       = [];
let templates     = [];
let editStudentId = null;
let editStaffId   = null;
let editLeadId    = null;
let editMakeupId  = null;
let editTemplateId= null;
let studentFilter = 'all';
let studentClassFilter = 'all';
let studentSubjectFilter = 'all';
let staffFilter   = 'all';
let leadFilter    = 'all';
let makeupFilter  = 'all';
let consultTab    = 'process';


// ── STATIC COURSE LIST FOR FILTER TABS ──
const STATIC_COURSES = [
  {name:'Piano',      emoji:'🎹', match:'Piano'},
  {name:'Guitar',     emoji:'🎸', match:'Guitar'},
  {name:'Violin',     emoji:'🎻', match:'Violin'},
  {name:'Ukulele',    emoji:'🪕', match:'Ukulele'},
  {name:'Vẽ',         emoji:'🎨', match:'Vẽ'},
  {name:'Ballet',     emoji:'🩰', match:'Ballet'},
  {name:'Dance',      emoji:'💃', match:'Dance'},
  {name:'Khiêu Vũ',   emoji:'🕺', match:'Khiêu Vũ'},
  {name:'Múa Cổ Trang',emoji:'👘', match:'Múa Cổ Trang'},
  {name:'Thanh Nhạc', emoji:'🎤', match:'Thanh Nhạc'},
  {name:'Luyện Thi',  emoji:'🏆', match:'Luyện Thi'},
  {name:'Cảm Thụ Âm Nhạc', emoji:'🎼', match:'Cảm Thụ Âm Nhạc'},
  {name:'Piano Đệm Hát',   emoji:'🎹🎤', match:'Piano Đệm Hát'},
  {name:'Trống',      emoji:'🥁', match:'Trống'},
];

// ── HELPERS ──
const fmt     = n => Number(n||0).toLocaleString('vi-VN') + ' đ';
const fmtDate = d => { if (!d) return '–'; const p = d.split('-'); if (p.length === 3) return p[2]+'/'+p[1]+'/'+p[0]; return d; };
// Lưu dữ liệu lên server (không chặn UI)
function save() {
  fetch('/api/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ students, staff, leads, classes, attendance, makeups, templates, customCourses, customPrices })
  }).catch(e => console.error('Lỗi lưu server:', e));
}

// Lưu dữ liệu lên server và chờ kết quả (dùng khi cần chắc chắn)
async function saveAsync() {
  try {
    const r = await fetch('/api/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ students, staff, leads, classes, attendance, makeups, templates, customCourses, customPrices })
    });
    if (!r.ok) {
      const d = await r.json();
      showToast('Lỗi lưu dữ liệu: ' + (d.error || r.status), true);
      return false;
    }
    return true;
  } catch (e) {
    showToast('Mất kết nối đến server!', true);
    return false;
  }
}

// ── DELETE MODAL ──
function confirmDelete(name, fn) {
  document.getElementById('del-modal-name').textContent = name;
  document.getElementById('del-confirm-btn').onclick = () => { fn(); closeDelModal(); };
  document.getElementById('del-modal').classList.add('open');
}
function closeDelModal() { document.getElementById('del-modal').classList.remove('open'); }

// ── NAVIGATION ──
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n => {
    const oc = n.getAttribute('onclick') || '';
    if (oc.includes("'" + id + "'") || oc.includes('"' + id + '"')) n.classList.add('active');
  });
  const map = { students: renderStudentTable, staff: renderStaffTable, dashboard: renderDashboard, revenue: renderRevenue, leads: renderLeadTable, classes: renderClassTable, 'class-detail':()=>{}, schedule: renderSchedule, attendance: initAttendancePage, makeup: renderMakeupTable, consult: initConsultPage, accounts: renderAccountsPage };
  if (map[id]) map[id]();
}
function startAddStudent() { editStudentId = null; clearStudentForm(); showPage('add-student'); }
function startAddClass()   { editClassId   = null; clearClassForm();   showPage('add-class'); }
function startAddStaff()   { editStaffId   = null; clearStaffForm();   showPage('add-staff'); }
function startAddLead()    { editLeadId    = null; clearLeadForm();    showPage('add-lead'); }

// ── COURSE DATA ──
const CD={
  piano:{name:'PIANO',emoji:'🎹',sections:[{title:'Lớp Thông Thường',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:5400000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:7200000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:12000000},{desc:'Lớp 3-1 · 1 tháng/8 buổi',amount:2000000},{desc:'Lớp 2-1 · 1 tháng/8 buổi',amount:2600000},{desc:'Lớp 1-1 · 1 tháng/8 buổi',amount:4200000}]},{title:'Đóng 2 Lần (Ưu Đãi)',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:2700000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:6000000}]}]},
  guitar:{name:'GUITAR',emoji:'🎸',sections:[{title:'Lớp Thông Thường',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:5400000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:7200000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:12000000},{desc:'Lớp 3-1 · 1 tháng/8 buổi',amount:2000000},{desc:'Lớp 2-1 · 1 tháng/8 buổi',amount:2600000},{desc:'Lớp 1-1 · 1 tháng/8 buổi',amount:4200000}]},{title:'Đóng 2 Lần (Ưu Đãi)',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:2700000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:6000000}]}]},
  violin:{name:'VIOLIN',emoji:'🎻',sections:[{title:'Lớp Thông Thường',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:5400000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:7200000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:12000000},{desc:'Lớp 3-1 · 1 tháng/8 buổi',amount:2000000},{desc:'Lớp 2-1 · 1 tháng/8 buổi',amount:2600000},{desc:'Lớp 1-1 · 1 tháng/8 buổi',amount:4200000}]},{title:'Đóng 2 Lần (Ưu Đãi)',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:2700000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:6000000}]}]},
  ukulele:{name:'UKULELE',emoji:'🪕',sections:[{title:'Lớp Thông Thường',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:5400000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:7200000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:12000000},{desc:'Lớp 3-1 · 1 tháng/8 buổi',amount:2000000},{desc:'Lớp 2-1 · 1 tháng/8 buổi',amount:2600000},{desc:'Lớp 1-1 · 1 tháng/8 buổi',amount:4200000}]},{title:'Đóng 2 Lần (Ưu Đãi)',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:2700000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:6000000}]}]},
  ve:{name:'VẼ',emoji:'🎨',sections:[{title:'Vẽ Mầm Non',rows:[{desc:'Lớp nhóm · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp nhóm · 1 tháng/8 buổi',amount:1400000},{desc:'Đóng 2 lần · 3 tháng/24 buổi',amount:1800000}]},{title:'Vẽ Căn Bản',rows:[{desc:'Lớp nhóm · 3 tháng/24 buổi',amount:3300000},{desc:'Lớp nhóm · 1 tháng/8 buổi',amount:1300000},{desc:'Đóng 2 lần · 3 tháng/24 buổi',amount:1650000}]},{title:'Ký Họa / Màu Nước / Màu Marker',rows:[{desc:'Lớp nhóm · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp nhóm · 1 tháng/8 buổi',amount:1400000},{desc:'Đóng 2 lần · 3 tháng/24 buổi',amount:1800000}]},{title:'Màu Acrylic / Digital Art',rows:[{desc:'Lớp nhóm · 3 tháng/24 buổi',amount:4800000},{desc:'Lớp nhóm · 1 tháng/8 buổi',amount:1800000},{desc:'Đóng 2 lần · 3 tháng/24 buổi',amount:2400000}]}]},
  ballet:{name:'BALLET',emoji:'🩰',sections:[{title:'Ballet 3–5 Tuổi',rows:[{desc:'Lớp nhóm · 3 tháng/24 buổi',amount:3000000},{desc:'Lớp nhóm · 1 tháng/8 buổi',amount:1200000},{desc:'Đóng 2 lần · 3 tháng/24 buổi',amount:1500000}]},{title:'Ballet 6–9 Tuổi',rows:[{desc:'Lớp nhóm · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp nhóm · 1 tháng/8 buổi',amount:1400000},{desc:'Đóng 2 lần · 3 tháng/24 buổi',amount:1800000}]}]},
  dance:{name:'DANCE',emoji:'💃',sections:[{title:'Dance',rows:[{desc:'Lớp nhóm · 3 tháng/24 buổi',amount:3000000},{desc:'Lớp nhóm · 1 tháng/8 buổi',amount:1200000},{desc:'Đóng 2 lần · 3 tháng/24 buổi',amount:1500000}]}]},
  'khieuvũ':{name:'KHIÊU VŨ',emoji:'🕺',sections:[{title:'Khiêu Vũ',rows:[{desc:'Lớp nhóm · 3 tháng/24 buổi',amount:3000000},{desc:'Lớp nhóm · 1 tháng/8 buổi',amount:1200000},{desc:'Đóng 2 lần · 3 tháng/24 buổi',amount:1500000}]}]},
  muacotrang:{name:'MÚA CỔ TRANG',emoji:'👘',sections:[{title:'Múa Cổ Trang',rows:[{desc:'Lớp nhóm · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp nhóm · 1 tháng/8 buổi',amount:1400000},{desc:'Đóng 2 lần · 3 tháng/24 buổi',amount:1800000}]}]},
  thanhnhac:{name:'THANH NHẠC',emoji:'🎤',sections:[{title:'Căn Bản',rows:[{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:7200000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:12000000},{desc:'Lớp 2-1 · 1 tháng/8 buổi',amount:2600000},{desc:'Lớp 1-1 · 1 tháng/8 buổi',amount:4200000}]},{title:'Đóng 2 Lần (Ưu Đãi)',rows:[{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:6000000}]}]},
  'luyen-thi':{name:'LUYỆN THI QUỐC TẾ',emoji:'🏆',sections:[{title:'Luyện Thi – Guitar',rows:[{desc:'Luyện 3-1 · 3T/24b',amount:6000000},{desc:'Luyện 2-1 · 3T/24b',amount:8400000},{desc:'Luyện 1-1 · 3T/24b',amount:12000000},{desc:'Luyện 3-1 · 1T/8b',amount:2200000},{desc:'Luyện 2-1 · 1T/8b',amount:3000000},{desc:'Luyện 1-1 · 1T/8b',amount:4200000}]},{title:'Luyện Thi – Violin',rows:[{desc:'Luyện 3-1 · 3T/24b',amount:6000000},{desc:'Luyện 2-1 · 3T/24b',amount:8400000},{desc:'Luyện 1-1 · 3T/24b',amount:12000000}]},{title:'Luyện Thi – Piano',rows:[{desc:'Luyện 3-1 · 3T/24b',amount:6000000},{desc:'Luyện 2-1 · 3T/24b',amount:8400000},{desc:'Luyện 1-1 · 3T/24b',amount:12000000}]},{title:'Luyện Thi – Vẽ',rows:[{desc:'Lớp nhóm · 3T/24b',amount:7200000},{desc:'Lớp nhóm · 1T/8b',amount:2600000},{desc:'Đóng 2 lần · 3T/24b',amount:3600000}]}]},
  hocthu:{name:'HỌC THỬ',emoji:'⭐',sections:[{title:'Các Loại Học Thử',rows:[{desc:'Học thử lớp nhóm',amount:100000},{desc:'Học thử 2-1',amount:250000},{desc:'Học thử 1-1',amount:500000}]}]},
  camthu:{name:'CẢM THỤ ÂM NHẠC',emoji:'🎼',sections:[{title:'Cảm Thụ Âm Nhạc Miễn Phí',rows:[{desc:'Lớp nhóm · 24 buổi · Miễn phí',amount:0}]}]},
  pianodemhat:{name:'PIANO ĐỆM HÁT',emoji:'🎹🎤',sections:[{title:'Lớp Thông Thường',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:5400000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:7200000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:12000000},{desc:'Lớp 3-1 · 1 tháng/8 buổi',amount:2000000},{desc:'Lớp 2-1 · 1 tháng/8 buổi',amount:2600000},{desc:'Lớp 1-1 · 1 tháng/8 buổi',amount:4200000}]},{title:'Đóng 2 Lần (Ưu Đãi)',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:2700000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:6000000}]}]},
  trong:{name:'TRỐNG',emoji:'🥁',sections:[{title:'Lớp Thông Thường',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:5400000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:7200000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:12000000},{desc:'Lớp 3-1 · 1 tháng/8 buổi',amount:2000000},{desc:'Lớp 2-1 · 1 tháng/8 buổi',amount:2600000},{desc:'Lớp 1-1 · 1 tháng/8 buổi',amount:4200000}]},{title:'Đóng 2 Lần (Ưu Đãi)',rows:[{desc:'Lớp 3-1 · 3 tháng/24 buổi',amount:2700000},{desc:'Lớp 2-1 · 3 tháng/24 buổi',amount:3600000},{desc:'Lớp 1-1 · 3 tháng/24 buổi',amount:6000000}]}]},
  khac:{name:'MỤC KHÁC',emoji:'🗂️',sections:[
    {title:'⭐ Học Thử',rows:[{desc:'Học thử lớp nhóm (10:1)',amount:100000},{desc:'Học thử 2-1',amount:250000},{desc:'Học thử 1-1',amount:500000}]},
    {title:'🩰 Đồ Ballet',rows:[{desc:'Đồ rời – Size 130(4bộ) · 140(2bộ) · 150(2bộ) · 160(1bộ) · 170(1bộ)',amount:300000},{desc:'Đồ liền',amount:200000}]},
    {title:'📚 Sách',rows:[{desc:'Sách Grade',amount:50000},{desc:'Sách Faber AVT (in VN: 250k / in Mỹ: 450k)',amount:60000},{desc:'Sách Guitar',amount:50000},{desc:'Sách người lớn',amount:100000}]},
    {title:'👟 Giày & Tất',rows:[{desc:'Giày 1 đôi lớn',amount:150000},{desc:'Giày 1 đôi bé cao cấp',amount:120000},{desc:'Giày 1 đôi bé thường',amount:60000},{desc:'Tất 1 đôi',amount:50000}]},
    {title:'🏠 Phòng Nhảy',rows:[{desc:'Phòng lớn Tầng 1 (không ML: 230k)',amount:300000},{desc:'Phòng nhỏ Tầng 2 (không ML: 200k)',amount:250000},{desc:'Thuê tháng từ 1 tháng',amount:5000000},{desc:'Thuê tháng từ 3 tháng',amount:4000000}]},
    {title:'🎹 Thuê Phòng Piano',rows:[{desc:'Theo giờ (check lịch trống)',amount:150000},{desc:'Gói 3 tháng – 2 buổi/tuần cố định',amount:3000000}]}
  ]}
};

function getAllCourses() {
  // Merge static CD + customCourses
  const all = {...CD};
  customCourses.forEach(c => { all[c.key] = c; });
  return all;
}

function openCourse(key){
  const allC = getAllCourses();
  const c = allC[key];
  if (!c) return;
  document.getElementById('modal-emoji').textContent = c.emoji;
  document.getElementById('modal-title').textContent = c.name;
  renderCourseModalContent(key, c);
  document.getElementById('course-modal').classList.add('open');
}

function renderCourseModalContent(key, c) {
  const prices = customPrices[key] || {};
  let html = `<div style="display:flex;justify-content:flex-end;margin-bottom:10px;">
    <button class="btn btn-outline" style="font-size:10px;padding:5px 12px;" onclick="toggleCourseEdit('${key}')">✏️ Chỉnh Sửa Học Phí</button>
  </div>`;
  c.sections.forEach((s,si)=>{
    html+=`<div class="price-section"><div class="price-section-title">${s.title}</div>`;
    s.rows.forEach((r,ri)=>{
      const priceKey = si+'_'+ri;
      const curAmount = prices[priceKey] !== undefined ? prices[priceKey] : r.amount;
      html+=`<div class="price-row">
        <div class="price-desc">${r.desc}</div>
        <div class="price-amount" id="pa_${key}_${priceKey}">${curAmount===0?'Miễn phí':fmt(curAmount)}</div>
        <input type="number" class="price-edit-input" id="pi_${key}_${priceKey}" value="${curAmount}" style="display:none;width:130px;padding:5px 8px;border:1.5px solid var(--gold);border-radius:8px;font-size:12px;font-weight:700;color:var(--navy);background:var(--cream);text-align:right;" min="0">
      </div>`;
    });
    html+='</div>';
  });
  html+=`<div id="course-edit-actions" style="display:none;margin-top:14px;padding-top:14px;border-top:1.5px solid var(--cream2);display:none;gap:9px;" class="form-actions">
    <button class="btn btn-gold" onclick="saveCourseEdit('${key}')">💾 Lưu Học Phí</button>
    <button class="btn btn-outline" onclick="resetCourseEdit('${key}')">↺ Khôi Phục Mặc Định</button>
  </div>`;
  document.getElementById('modal-content').innerHTML = html;
}

function toggleCourseEdit(key) {
  const inputs = document.querySelectorAll(`[id^="pi_${key}_"]`);
  const amounts = document.querySelectorAll(`[id^="pa_${key}_"]`);
  const actions = document.getElementById('course-edit-actions');
  const isEditing = inputs[0] && inputs[0].style.display !== 'none';
  inputs.forEach(el => el.style.display = isEditing ? 'none' : 'inline-block');
  amounts.forEach(el => el.style.display = isEditing ? '' : 'none');
  if (actions) actions.style.display = isEditing ? 'none' : 'flex';
}

function saveCourseEdit(key) {
  const allC = getAllCourses();
  const c = allC[key];
  if (!c) return;
  if (!customPrices[key]) customPrices[key] = {};
  c.sections.forEach((s,si) => {
    s.rows.forEach((r,ri) => {
      const priceKey = si+'_'+ri;
      const input = document.getElementById(`pi_${key}_${priceKey}`);
      if (input) customPrices[key][priceKey] = Number(input.value) || 0;
    });
  });
  save();
  renderCourseModalContent(key, c);
  showToast('Đã lưu học phí!');
}

function resetCourseEdit(key) {
  if (customPrices[key]) { delete customPrices[key]; save(); }
  const allC = getAllCourses();
  renderCourseModalContent(key, allC[key]);
  showToast('Đã khôi phục học phí mặc định!');
}

// ── PACKAGE OPTIONS PER COURSE ──
const COURSE_PACKAGES = {
  'Piano':                              ['Lớp 3-1 · 3 tháng/24 buổi','Lớp 2-1 · 3 tháng/24 buổi','Lớp 1-1 · 3 tháng/24 buổi','Lớp 3-1 · 1 tháng/8 buổi','Lớp 2-1 · 1 tháng/8 buổi','Lớp 1-1 · 1 tháng/8 buổi','Đóng 2 lần – Lớp 3-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 2-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 1-1 · 3 tháng/24 buổi'],
  'Guitar':                             ['Lớp 3-1 · 3 tháng/24 buổi','Lớp 2-1 · 3 tháng/24 buổi','Lớp 1-1 · 3 tháng/24 buổi','Lớp 3-1 · 1 tháng/8 buổi','Lớp 2-1 · 1 tháng/8 buổi','Lớp 1-1 · 1 tháng/8 buổi','Đóng 2 lần – Lớp 3-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 2-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 1-1 · 3 tháng/24 buổi'],
  'Violin':                             ['Lớp 3-1 · 3 tháng/24 buổi','Lớp 2-1 · 3 tháng/24 buổi','Lớp 1-1 · 3 tháng/24 buổi','Lớp 3-1 · 1 tháng/8 buổi','Lớp 2-1 · 1 tháng/8 buổi','Lớp 1-1 · 1 tháng/8 buổi','Đóng 2 lần – Lớp 3-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 2-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 1-1 · 3 tháng/24 buổi'],
  'Ukulele':                            ['Lớp 3-1 · 3 tháng/24 buổi','Lớp 2-1 · 3 tháng/24 buổi','Lớp 1-1 · 3 tháng/24 buổi','Lớp 3-1 · 1 tháng/8 buổi','Lớp 2-1 · 1 tháng/8 buổi','Lớp 1-1 · 1 tháng/8 buổi','Đóng 2 lần – Lớp 3-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 2-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 1-1 · 3 tháng/24 buổi'],
  'Vẽ Mầm Non':                         ['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Vẽ Căn Bản':                         ['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Vẽ - Ký Họa / Màu Nước / Màu Marker':['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Vẽ - Màu Acrylic Canvas / Digital Art':['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Ballet (3-5 tuổi)':                  ['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Ballet (6-9 tuổi)':                  ['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Dance':                              ['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Khiêu Vũ':                           ['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Múa Cổ Trang':                       ['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Thanh Nhạc':                         ['Lớp 2-1 · 3 tháng/24 buổi','Lớp 1-1 · 3 tháng/24 buổi','Lớp 2-1 · 1 tháng/8 buổi','Lớp 1-1 · 1 tháng/8 buổi','Đóng 2 lần – Lớp 2-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 1-1 · 3 tháng/24 buổi'],
  'Luyện Thi - Piano':                  ['Luyện 3-1 · 3 tháng/24 buổi','Luyện 2-1 · 3 tháng/24 buổi','Luyện 1-1 · 3 tháng/24 buổi'],
  'Luyện Thi - Guitar':                 ['Luyện 3-1 · 3 tháng/24 buổi','Luyện 2-1 · 3 tháng/24 buổi','Luyện 1-1 · 3 tháng/24 buổi','Luyện 3-1 · 1 tháng/8 buổi','Luyện 2-1 · 1 tháng/8 buổi','Luyện 1-1 · 1 tháng/8 buổi'],
  'Luyện Thi - Violin':                 ['Luyện 3-1 · 3 tháng/24 buổi','Luyện 2-1 · 3 tháng/24 buổi','Luyện 1-1 · 3 tháng/24 buổi'],
  'Luyện Thi - Vẽ':                     ['Lớp nhóm · 3 tháng/24 buổi','Lớp nhóm · 1 tháng/8 buổi','Đóng 2 lần · 3 tháng/24 buổi'],
  'Cảm Thụ Âm Nhạc':                   ['Miễn Phí · 24 buổi'],
  'Piano Đệm Hát':                      ['Lớp 3-1 · 3 tháng/24 buổi','Lớp 2-1 · 3 tháng/24 buổi','Lớp 1-1 · 3 tháng/24 buổi','Lớp 3-1 · 1 tháng/8 buổi','Lớp 2-1 · 1 tháng/8 buổi','Lớp 1-1 · 1 tháng/8 buổi','Đóng 2 lần – Lớp 3-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 2-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 1-1 · 3 tháng/24 buổi'],
  'Trống':                               ['Lớp 3-1 · 3 tháng/24 buổi','Lớp 2-1 · 3 tháng/24 buổi','Lớp 1-1 · 3 tháng/24 buổi','Lớp 3-1 · 1 tháng/8 buổi','Lớp 2-1 · 1 tháng/8 buổi','Lớp 1-1 · 1 tháng/8 buổi','Đóng 2 lần – Lớp 3-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 2-1 · 3 tháng/24 buổi','Đóng 2 lần – Lớp 1-1 · 3 tháng/24 buổi'],
};

function populatePackages(selectedPkg) {
  const subj = document.getElementById('f-subject').value;
  const pkgSel = document.getElementById('f-package');
  const pkgs = COURSE_PACKAGES[subj] || [];
  pkgSel.innerHTML = pkgs.length
    ? '<option value="">-- Chọn gói --</option>' + pkgs.map(p => `<option${p===selectedPkg?' selected':''}>${p}</option>`).join('')
    : '<option value="">-- Chọn khóa học trước --</option>';
  // populate class dropdown
  const clSel = document.getElementById('f-classid');
  if (clSel) {
    const filtered = classes.filter(c => !subj || c.subject === subj);
    clSel.innerHTML = '<option value="">-- Chọn lớp (nếu có) --</option>'
      + filtered.map(c => `<option value="${c.id}">[${c.code}] ${c.name}</option>`).join('');
  }
}
function onClassSelect() {
  // tự động điền tên lớp nếu chọn
}

function setStudentClassFilter(f, el) {
  studentClassFilter = f;
  document.querySelectorAll('#filter-class-tabs .filter-tab').forEach(t => t.classList.remove('active'));
  if(el) el.classList.add('active');
  renderStudentTable();
}
function renderClassFilterBtns() {
  const wrap = document.getElementById('class-filter-btns');
  if (!wrap) return;
  const allActive = studentClassFilter==='all' ? ' active' : '';
  wrap.innerHTML = `<button class="filter-tab${allActive}" onclick="setStudentClassFilter('all',this)">Tất Cả</button>`
    + classes.map(c => `<button class="filter-tab${studentClassFilter===c.id?' active':''}" onclick="setStudentClassFilter('${c.id}',this)">[${c.code}] ${c.name}</button>`).join('');
}
function setStudentSubjectFilter(f, el) {
  studentSubjectFilter = f;
  document.querySelectorAll('#filter-subject-tabs .filter-tab').forEach(t => t.classList.remove('active'));
  if (el) el.classList.add('active');
  renderStudentTable();
}

function renderSubjectFilterBtns() {
  const wrap = document.getElementById('subject-filter-btns');
  if (!wrap) return;
  // Build full list: static + custom (dedup by name)
  const staticNames = new Set(STATIC_COURSES.map(c => c.name));
  const allTabs = [...STATIC_COURSES];
  customCourses.forEach(c => {
    if (!staticNames.has(c.name)) allTabs.push({name: c.name, emoji: c.emoji||'📚', match: c.name});
  });
  const allBtn = `<button class="filter-tab${studentSubjectFilter==='all'?' active':''}" onclick="setStudentSubjectFilter('all',this)">Tất Cả</button>`;
  const tabBtns = allTabs.map(c => {
    const active = (studentSubjectFilter === c.match || studentSubjectFilter === c.name) ? ' active' : '';
    return `<button class="filter-tab${active}" onclick="setStudentSubjectFilter('${c.match}',this)">${c.emoji} ${c.name}</button>`;
  }).join('');
  wrap.innerHTML = allBtn + tabBtns;
}

function closeCourse(){document.getElementById('course-modal').classList.remove('open');}
function closeCourseModal(e){if(e.target===document.getElementById('course-modal'))closeCourse();}

// ── STUDENTS ──
function saveStudent(){
  const g=id=>{const el=document.getElementById(id);return el?(el.value.trim?el.value.trim():el.value):'';};
  const name=g('f-name'),dob=g('f-dob'),parent=g('f-parent'),phone=g('f-phone'),
        subject=g('f-subject'),pkg=g('f-package'),
        classid=Number(document.getElementById('f-classid')?document.getElementById('f-classid').value:'')||0,
        start=g('f-start'),end=g('f-end'),
        payment=g('f-payment'),amount=g('f-amount'),paydate=g('f-paydate'),note=g('f-note');
  if(!name||!parent||!phone||!subject||!start||!payment){
    showToast('Vui lòng điền đầy đủ các trường bắt buộc (*)',true);return;
  }
  const isEdit=editStudentId!==null;
  const obj={id:isEdit?editStudentId:Date.now(),name,dob,parent,phone,subject,pkg,classid,
             start,end,payment,amount:Number(amount)||0,paydate,note};
  if(isEdit){
    const i=students.findIndex(s=>s.id===editStudentId);
    if(i!==-1)students[i]=obj; else{showToast('Không tìm thấy học viên!',true);return;}
    editStudentId=null;
  } else students.push(obj);
  saveAsync().then(ok=>{
    if(ok){
      showToast(isEdit?'Đã cập nhật học viên thành công!':'Đã thêm học viên thành công!');
      const back=window._addStudentForClassId; clearStudentForm(); window._addStudentForClassId=null;
      if(!isEdit&&back) viewClassDetail(back); else showPage('students');
    } else { if(!isEdit) students.pop(); }
  });
}
function clearStudentForm(){
  ['f-name','f-dob','f-parent','f-phone','f-package','f-start','f-end','f-note','f-amount','f-paydate'].forEach(id=>document.getElementById(id).value='');
  ['f-subject','f-payment'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('f-package').innerHTML='<option value="">-- Chọn khóa học trước --</option>';
  const clSel=document.getElementById('f-classid');if(clSel)clSel.innerHTML='<option value="">-- Chọn lớp (nếu có) --</option>';
  editStudentId=null; document.getElementById('form-title').innerHTML='Thêm <span>Học Viên</span>';
}
function editStudent(id){
  const s=students.find(x=>x.id===id); if(!s)return; editStudentId=id;
  document.getElementById('f-name').value=s.name;
  document.getElementById('f-dob').value=s.dob||'';
  document.getElementById('f-parent').value=s.parent;
  document.getElementById('f-phone').value=s.phone;
  document.getElementById('f-subject').value=s.subject;
  populatePackages(s.pkg||'');
  const clSel = document.getElementById('f-classid'); if(clSel && s.classid) { clSel.value = s.classid; }
  document.getElementById('f-start').value=s.start;
  document.getElementById('f-end').value=s.end||'';
  document.getElementById('f-payment').value=s.payment;
  document.getElementById('f-amount').value=s.amount||'';
  document.getElementById('f-paydate').value=s.paydate||'';
  document.getElementById('f-note').value=s.note||'';
  document.getElementById('form-title').innerHTML='Chỉnh Sửa <span>Học Viên</span>';
  showPage('add-student');
}
function deleteStudent(id) {
  const s = students.find(x => x.id === id); if (!s) return;
  confirmDelete(s.name, () => {
    students = students.filter(x => x.id !== id);
    save(); renderStudentTable(); renderDashboard();
    showToast('Đã xóa học viên ' + s.name + '.');
  });
}
function setStudentFilter(f,el){
  studentFilter=f;
  document.querySelectorAll('#page-students .filter-tab').forEach(t=>t.classList.remove('active'));
  if(el) el.classList.add('active');
  renderStudentTable();
}

// Đếm buổi đã học của 1 học viên (từ điểm danh + bù lịch)
function countStudentSessions(studentId, classId) {
  let count = 0;
  attendance.forEach(a => {
    if (classId && String(a.classId) !== String(classId)) return;
    if (a.records && a.records[String(studentId)] === 'present') count++;
  });
  makeups.forEach(m => {
    if (String(m.studentId) === String(studentId) && m.status === 'done') count++;
  });
  return count;
}

function extractTotalSessions(pkg) {
  if (!pkg) return 0;
  const m = pkg.match(/(\d+)\s*buổi/);
  return m ? parseInt(m[1]) : 0;
}


function isExpiringSoon(s) {
  if (!s.end) return false;
  const d = Math.ceil((new Date(s.end) - new Date()) / (1000*60*60*24));
  return d >= 0 && d <= 14;
}
function renderExpiryBanner() {
  const el = document.getElementById('expiry-banner');
  if (!el) return;
  const exp = students.filter(s => isExpiringSoon(s) && s.subject !== 'Học Thử');
  if (!exp.length) { el.style.display='none'; return; }
  el.style.display='';
  el.innerHTML = '<span style="font-weight:700;color:#dc2626;">⏰ '
    + exp.length + ' học viên sắp hết khóa:</span> '
    + exp.map(s=>'<span style="font-weight:600">'+s.name+'</span>').join(', ');
}
function renderStudentTable(){
  renderClassFilterBtns();
  renderSubjectFilterBtns();
  renderExpiryBanner();
  const q=(document.getElementById('search-input').value||'').toLowerCase();
  const filtered=students.filter(s=>{
    const mq=!q||s.name.toLowerCase().includes(q)||s.phone.includes(q)||s.subject.toLowerCase().includes(q)||(s.parent&&s.parent.toLowerCase().includes(q));
    let mf=true;
    if(studentFilter==='hoc-thu') mf=s.subject==='Học Thử';
    else if(studentFilter==='sap-het-khoa') mf=isExpiringSoon(s)&&s.subject!=='Học Thử';
    else if(studentFilter!=='all') mf=s.payment===studentFilter;
    const mc=studentClassFilter==='all'||Number(s.classid)===Number(studentClassFilter);
    const ms=studentSubjectFilter==='all'||s.subject===studentSubjectFilter||(studentSubjectFilter==='Vẽ'&&s.subject&&s.subject.startsWith('Vẽ'))||(studentSubjectFilter==='Ballet'&&s.subject&&s.subject.startsWith('Ballet'))||(studentSubjectFilter==='Luyện Thi'&&s.subject&&s.subject.startsWith('Luyện Thi'));
    return mq&&mf&&ms&&mc;
  });
  const tbody=document.getElementById('student-table-body');
  if(!filtered.length){tbody.innerHTML=`<tr><td colspan="12"><div class="empty-state"><div class="empty-icon">📋</div><div class="empty-text">Không tìm thấy học viên nào</div></div></td></tr>`;return;}
  const pb=p=>p==='Đã Chuyển Khoản'?`<span class="badge badge-paid">✓ CK</span>`:p==='Tiền Mặt'?`<span class="badge badge-cash">💵 TM</span>`:`<span class="badge badge-unpaid">⚠ Chưa TT</span>`;
  tbody.innerHTML=filtered.map((s,i)=>{
    const isHocThu = s.subject==='Học Thử';
    const expiring = isExpiringSoon(s)&&!isHocThu;
    const daysLeft = s.end ? Math.ceil((new Date(s.end)-new Date())/(1000*60*60*24)) : null;
    const expiryTag = expiring&&daysLeft!==null ? `<br><span style="font-size:10px;color:#dc2626;font-weight:700">⏰ còn ${daysLeft} ngày</span>` : '';
    const hocThuTag = isHocThu ? `<br><span style="font-size:10px;background:#fde047;color:#713f12;padding:1px 6px;border-radius:4px;font-weight:700">⭐ HỌC THỬ</span>` : '';
    const rowStyle = isHocThu?'background:linear-gradient(90deg,#fefce8,#fff);':expiring?'background:linear-gradient(90deg,#fff7ed,#fff);':'';
    // Tính buổi học
    const totalPkg = extractTotalSessions(s.pkg);
    const doneSessions = countStudentSessions(s.id, s.classid);
    const pct = totalPkg ? Math.min(100, Math.round(doneSessions/totalPkg*100)) : 0;
    const sessionColor = pct>=100?'#16a34a':pct>=60?'#d97706':'var(--navy)';
    const sessionCell = totalPkg
      ? `<div style="font-size:12px;font-weight:700;color:${sessionColor}">${doneSessions}/${totalPkg}</div>
         <div style="width:60px;height:5px;background:var(--cream2);border-radius:4px;margin-top:3px;overflow:hidden;">
           <div style="width:${pct}%;height:100%;background:${sessionColor};border-radius:4px;"></div>
         </div>`
      : `<span style="color:var(--muted);font-size:11px;">–</span>`;
    return `<tr style="${rowStyle}">
      <td>${i+1}</td>
      <td class="td-name">${s.name}${hocThuTag}</td>
      <td>${fmtDate(s.dob)}</td>
      <td>${s.parent}</td>
      <td>${s.phone}</td>
      <td style="font-weight:600;color:var(--navy)">${s.subject}${s.pkg?`<br><span style="font-size:10px;color:var(--muted);font-weight:400">${s.pkg}</span>`:''}</td>
      <td>${(()=>{const cl=classes.find(c=>Number(c.id)===Number(s.classid));return cl?`<span class='pos-badge'>[${cl.code}]<br>${cl.name}</span>`:'–';})()}</td>
      <td style="font-size:11.5px">${fmtDate(s.start)}<br><span style="color:var(--muted)">→ ${fmtDate(s.end)}</span>${expiryTag}</td>
      <td>${pb(s.payment)}</td>
      <td style="font-weight:700;color:var(--gold)">${s.amount?fmt(s.amount):'–'}</td>
      <td style="text-align:center;">${sessionCell}</td>
      <td><div class="action-btns"><button class="btn-icon" onclick="editStudent(${s.id})" title="Sửa">✎</button><button class="btn-icon del" onclick="deleteStudent(${s.id})" title="Xóa">✕</button></div></td>
    </tr>`;
  }).join('');
}

// ── STAFF ──
function saveStaff(){
  const g=id=>document.getElementById(id).value.trim?document.getElementById(id).value.trim():document.getElementById(id).value;
  const name=g('sf-name'),dob=g('sf-dob'),phone=g('sf-phone'),role=g('sf-role'),status=g('sf-status'),note=g('sf-note');
  if(!name||!phone||!role||!status){showToast('Vui lòng điền đầy đủ các trường bắt buộc (*)',true);return;}
  const obj={id:editStaffId||Date.now(),name,dob,phone,role,status,note};
  if(editStaffId!==null){const i=staff.findIndex(s=>s.id===editStaffId);if(i!==-1)staff[i]=obj;editStaffId=null;}
  else staff.push(obj);
  saveAsync().then(ok => {
    if (ok) { showToast('Đã lưu nhân sự thành công!'); clearStaffForm(); showPage('staff'); }
  });
}
function clearStaffForm(){
  ['sf-name','sf-dob','sf-phone','sf-note'].forEach(id=>document.getElementById(id).value='');
  ['sf-role','sf-status'].forEach(id=>document.getElementById(id).value='');
  editStaffId=null; document.getElementById('staff-form-title').innerHTML='Thêm <span>Nhân Sự</span>';
}
function editStaffMember(id){
  const s=staff.find(x=>x.id===id); if(!s)return; editStaffId=id;
  document.getElementById('sf-name').value=s.name;
  document.getElementById('sf-dob').value=s.dob||'';
  document.getElementById('sf-phone').value=s.phone;
  document.getElementById('sf-role').value=s.role;
  document.getElementById('sf-status').value=s.status;
  document.getElementById('sf-note').value=s.note||'';
  document.getElementById('staff-form-title').innerHTML='Chỉnh Sửa <span>Nhân Sự</span>';
  showPage('add-staff');
}
function deleteStaff(id) {
  const s = staff.find(x => x.id === id); if (!s) return;
  confirmDelete(s.name, () => {
    staff = staff.filter(x => x.id !== id);
    save(); renderStaffTable(); renderDashboard();
    showToast('Đã xóa nhân sự ' + s.name + '.');
  });
}
function setStaffFilter(f,el){staffFilter=f;document.querySelectorAll('#page-staff .filter-tab').forEach(t=>t.classList.remove('active'));el.classList.add('active');renderStaffTable();}

function renderStaffTable(){
  const q=(document.getElementById('staff-search').value||'').toLowerCase();
  const filtered=staff.filter(s=>{
    const mq=!q||s.name.toLowerCase().includes(q)||s.phone.includes(q)||s.role.toLowerCase().includes(q);
    let mf=true;
    if(staffFilter==='Giáo Viên') mf=s.role.startsWith('Giáo Viên');
    else if(staffFilter==='Nhân Viên') mf=!s.role.startsWith('Giáo Viên');
    else if(staffFilter!=='all') mf=s.status===staffFilter;
    return mq&&mf;
  });
  const tbody=document.getElementById('staff-table-body');
  if(!filtered.length){tbody.innerHTML=`<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">👥</div><div class="empty-text">Không tìm thấy nhân sự nào</div></div></td></tr>`;return;}
  tbody.innerHTML=filtered.map((s,i)=>`
    <tr>
      <td>${i+1}</td>
      <td class="td-name">${s.name}</td>
      <td>${fmtDate(s.dob)}</td>
      <td>${s.phone}</td>
      <td><span class="pos-badge">${s.role}</span></td>
      <td>${s.status==='Đang hoạt động'?`<span class="badge badge-active">● Hoạt Động</span>`:`<span class="badge badge-offline">○ Offline</span>`}</td>
      <td><div class="action-btns"><button class="btn-icon" onclick="editStaffMember(${s.id})" title="Sửa">✎</button><button class="btn-icon del" onclick="deleteStaff(${s.id})" title="Xóa">✕</button></div></td>
    </tr>`).join('');
}

// ── LEADS ──
// Show/hide học thử fields based on status
function onLeadStatusChange() {
  const status = document.getElementById('lf-status').value;
  const isHocThu = status === 'Đăng ký học thử';
  ['lf-hocthu-wrap','lf-hocthu-fee-wrap','lf-dungcu-wrap'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = isHocThu ? '' : 'none';
  });
  if (isHocThu && !document.getElementById('lf-dungcu-rows').children.length) {
    // keep empty, user can add
  }
}

function addDungcuRow(name='', price=0) {
  const wrap = document.getElementById('lf-dungcu-rows');
  const div = document.createElement('div');
  div.style.cssText = 'display:flex;gap:8px;align-items:center;';
  div.innerHTML = `
    <input type="text" class="search-box dc-name" placeholder="Tên dụng cụ (VD: Sách Grade)" value="${name}" style="flex:2;padding:7px 10px;font-size:12px;" oninput="calcDungcuTotal()">
    <input type="number" class="search-box dc-price" placeholder="Giá (đ)" value="${price||''}" min="0" style="flex:1;padding:7px 10px;font-size:12px;" oninput="calcDungcuTotal()">
    <button type="button" class="btn-icon del" onclick="this.parentElement.remove();calcDungcuTotal();" title="Xóa">✕</button>`;
  wrap.appendChild(div);
  calcDungcuTotal();
}

function calcDungcuTotal() {
  let total = 0;
  document.querySelectorAll('#lf-dungcu-rows .dc-price').forEach(el => {
    total += Number(el.value) || 0;
  });
  const t = document.getElementById('lf-dungcu-total');
  if (t) t.textContent = total.toLocaleString('vi-VN') + ' đ';
}

function getDungcuItems() {
  const items = [];
  document.querySelectorAll('#lf-dungcu-rows > div').forEach(div => {
    const name = div.querySelector('.dc-name').value.trim();
    const price = Number(div.querySelector('.dc-price').value) || 0;
    if (name) items.push({ name, price });
  });
  return items;
}

function saveLead() {
  const g = id => document.getElementById(id).value.trim ? document.getElementById(id).value.trim() : document.getElementById(id).value;
  const name=g('lf-name'),dob=g('lf-dob'),parent=g('lf-parent'),phone=g('lf-phone'),
        course=g('lf-course'),source=g('lf-source'),status=g('lf-status'),note=g('lf-note');
  if (!name||!parent||!phone||!course||!source||!status) { showToast('Vui lòng điền đầy đủ các trường bắt buộc (*)', true); return; }
  const existing = editLeadId ? (leads.find(l => l.id === editLeadId) || {}) : {};
  // Học thử
  const hocThuTypeSel = document.getElementById('lf-hocthu-type');
  const hocThuFeeSel  = document.getElementById('lf-hocthu-fee');
  const hocThuType = hocThuTypeSel ? hocThuTypeSel.options[hocThuTypeSel.selectedIndex]?.text || '' : '';
  const hocThuFee  = hocThuFeeSel  ? Number(hocThuFeeSel.value) || 0 : 0;
  // Dụng cụ
  const dungcu = getDungcuItems();
  const dungcuTotal = dungcu.reduce((a,i) => a+i.price, 0);
  const totalThu = hocThuFee + dungcuTotal;
  const obj = { id: editLeadId || Date.now(), name, dob, parent, phone, course, source, status, note,
    hocThuType, hocThuFee, dungcu, dungcuTotal, totalThu,
    createdAt: existing.createdAt || new Date().toISOString().slice(0,10) };
  if (editLeadId !== null) {
    const i = leads.findIndex(l => l.id === editLeadId);
    if (i !== -1) leads[i] = obj;
    editLeadId = null;
  } else leads.push(obj);
  saveAsync().then(ok => {
    if (ok) { showToast('Đã lưu học viên tiềm năng!'); clearLeadForm(); showPage('leads'); }
  });
}

function clearLeadForm() {
  ['lf-name','lf-dob','lf-parent','lf-phone','lf-note'].forEach(id => document.getElementById(id).value = '');
  ['lf-course','lf-source','lf-status'].forEach(id => document.getElementById(id).value = '');
  const ht = document.getElementById('lf-hocthu-type'); if(ht) ht.value='';
  const hf = document.getElementById('lf-hocthu-fee'); if(hf) hf.value='';
  const dr = document.getElementById('lf-dungcu-rows'); if(dr) dr.innerHTML='';
  ['lf-hocthu-wrap','lf-hocthu-fee-wrap','lf-dungcu-wrap'].forEach(id => {
    const el = document.getElementById(id); if(el) el.style.display='none';
  });
  editLeadId = null;
  document.getElementById('lead-form-title').innerHTML = 'Thêm <span>HV Tiềm Năng</span>';
}

function editLead(id) {
  const l = leads.find(x => x.id === id); if (!l) return;
  editLeadId = id;
  document.getElementById('lf-name').value   = l.name;
  document.getElementById('lf-dob').value    = l.dob||'';
  document.getElementById('lf-parent').value = l.parent;
  document.getElementById('lf-phone').value  = l.phone;
  document.getElementById('lf-course').value = l.course;
  document.getElementById('lf-source').value = l.source;
  document.getElementById('lf-status').value = l.status;
  document.getElementById('lf-note').value   = l.note||'';
  // Restore học thử
  onLeadStatusChange();
  const ht = document.getElementById('lf-hocthu-type'); if(ht && l.hocThuFee) ht.value = l.hocThuFee;
  const hf = document.getElementById('lf-hocthu-fee'); if(hf) hf.value = l.hocThuFee||'';
  // Restore dụng cụ
  const dr = document.getElementById('lf-dungcu-rows'); if(dr) dr.innerHTML='';
  (l.dungcu||[]).forEach(dc => addDungcuRow(dc.name, dc.price));
  document.getElementById('lead-form-title').innerHTML = 'Chỉnh Sửa <span>HV Tiềm Năng</span>';
  showPage('add-lead');
}

function deleteLead(id) {
  const l = leads.find(x => x.id === id); if (!l) return;
  confirmDelete(l.name, () => {
    leads = leads.filter(x => x.id !== id);
    save(); renderLeadTable(); renderDashboard();
    showToast('Đã xóa học viên tiềm năng ' + l.name + '.');
  });
}

function setLeadFilter(f, el) {
  leadFilter = f;
  document.querySelectorAll('#page-leads .filter-tab').forEach(t => t.classList.remove('active'));
  if (el) el.classList.add('active');
  renderLeadTable();
}

function renderLeadTable() {
  const q = (document.getElementById('lead-search').value || '').toLowerCase();
  const filtered = leads.filter(l => {
    const mq = !q || l.name.toLowerCase().includes(q) || (l.phone||'').includes(q) || (l.course||'').toLowerCase().includes(q) || (l.parent||'').toLowerCase().includes(q);
    const mf = leadFilter === 'all' || l.status === leadFilter || l.source === leadFilter;
    return mq && mf;
  });
  const tbody = document.getElementById('lead-table-body');
  if (!filtered.length) { tbody.innerHTML = `<tr><td colspan="13"><div class="empty-state"><div class="empty-icon">🎯</div><div class="empty-text">Không tìm thấy học viên tiềm năng nào</div></div></td></tr>`; return; }
  const srcBadge = s => {
    if (s === 'Facebook') return `<span class="badge badge-src-fb">📘 FB</span>`;
    if (s === 'Tiktok')   return `<span class="badge badge-src-tt">🎵 TT</span>`;
    return `<span class="badge badge-src-direct">🏠 TT</span>`;
  };
  const stBadge = s => {
    if (s === 'Đã tư vấn')        return `<span class="badge badge-consulted">✓ Đã TV</span>`;
    if (s === 'Đăng ký học thử')  return `<span class="badge" style="background:#fef9c3;color:#713f12;border:1.5px solid #fcd34d;">⭐ HT</span>`;
    if (s === 'Đã đăng ký học')   return `<span class="badge" style="background:#dcfce7;color:#15803d;border:1.5px solid #4ade80;">✅ ĐK</span>`;
    return `<span class="badge badge-new">○ Chưa LH</span>`;
  };
  tbody.innerHTML = filtered.map((l, i) => {
    const hocThuFmt = l.hocThuFee ? `<div style="font-size:11px;color:var(--navy);font-weight:600;">${l.hocThuType||'Học thử'}</div><div style="font-size:11px;color:var(--gold);font-weight:700;">${Number(l.hocThuFee).toLocaleString('vi-VN')} đ</div>` : '–';
    const dungcuFmt = (l.dungcu||[]).length
      ? `<div style="font-size:10.5px;color:var(--navy);">${l.dungcu.map(d=>`${d.name}: ${Number(d.price).toLocaleString('vi-VN')}đ`).join('<br>')}</div>`
      : '–';
    const totalFmt = (l.totalThu||0) > 0 ? `<span style="font-weight:800;color:var(--gold);">${Number(l.totalThu).toLocaleString('vi-VN')} đ</span>` : '–';
    return `<tr>
      <td>${i+1}</td>
      <td class="td-name">${l.name}</td>
      <td>${fmtDate(l.dob)}</td>
      <td>${l.parent}</td>
      <td>${l.phone}</td>
      <td style="font-weight:600;color:var(--navy)">${l.course}</td>
      <td>${srcBadge(l.source)}</td>
      <td>${stBadge(l.status)}</td>
      <td style="font-size:11px;color:var(--muted);max-width:120px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${l.note||''}">${l.note||'–'}</td>
      <td>${hocThuFmt}</td>
      <td>${dungcuFmt}</td>
      <td>${totalFmt}</td>
      <td><div class="action-btns">
        <button class="btn-icon" onclick="editLead(${l.id})" title="Sửa">✎</button>
        <button class="btn-icon del" onclick="deleteLead(${l.id})" title="Xóa">✕</button>
      </div></td>
    </tr>`;
  }).join('');
}

// ── REVENUE ──
function initRevSelectors(){
  const mSel=document.getElementById('rev-month');
  const ySel=document.getElementById('rev-year');
  const months=['Tháng 1','Tháng 2','Tháng 3','Tháng 4','Tháng 5','Tháng 6','Tháng 7','Tháng 8','Tháng 9','Tháng 10','Tháng 11','Tháng 12'];
  if(!mSel.options.length){
    months.forEach((m,i)=>{const o=document.createElement('option');o.value=i+1;o.textContent=m;mSel.appendChild(o);});
    const curY=new Date().getFullYear();
    for(let y=curY-2;y<=curY+1;y++){const o=document.createElement('option');o.value=y;o.textContent=y;ySel.appendChild(o);}
  }
  const now=new Date();
  mSel.value=now.getMonth()+1;
  ySel.value=now.getFullYear();
}
function setRevToday(){const now=new Date();document.getElementById('rev-month').value=now.getMonth()+1;document.getElementById('rev-year').value=now.getFullYear();renderRevenue();}

function renderRevenue(){
  const m=parseInt(document.getElementById('rev-month').value);
  const y=parseInt(document.getElementById('rev-year').value);
  const paid=students.filter(s=>{
    if(!s.paydate||s.payment==='Chưa Thanh Toán')return false;
    const d=new Date(s.paydate);
    return d.getFullYear()===y&&(d.getMonth()+1)===m;
  });
  const unpaidMonth=students.filter(s=>{
    if(s.payment!=='Chưa Thanh Toán')return false;
    const d=new Date(s.start);
    return d.getFullYear()===y&&(d.getMonth()+1)===m;
  });
  // Thu từ leads (học thử + dụng cụ) trong tháng
  const paidLeads = leads.filter(l => {
    if (!l.totalThu || l.totalThu <= 0) return false;
    const d = new Date(l.createdAt||'');
    return d.getFullYear()===y && (d.getMonth()+1)===m;
  });
  const leadRevenue = paidLeads.reduce((a,l) => a + Number(l.totalThu||0), 0);

  const studentTotal = paid.reduce((a,s)=>a+Number(s.amount||0),0);
  const total = studentTotal + leadRevenue;

  document.getElementById('rev-total-value').textContent=fmt(total);
  document.getElementById('rev-total-count').textContent=paid.length + paidLeads.length;
  document.getElementById('rev-unpaid-count').textContent=unpaidMonth.length;

  const breakdown={};
  paid.forEach(s=>{
    const key=s.subject||'Khác';
    if(!breakdown[key])breakdown[key]={total:0,count:0};
    breakdown[key].total+=Number(s.amount||0);
    breakdown[key].count++;
  });
  if (leadRevenue > 0) {
    breakdown['Học Thử & Dụng Cụ'] = { total: leadRevenue, count: paidLeads.length };
  }
  const bEl=document.getElementById('rev-breakdown');
  const entries=Object.entries(breakdown).sort((a,b)=>b[1].total-a[1].total);
  bEl.innerHTML=entries.length?entries.map(([k,v])=>`
    <div class="rev-cat">
      <div class="rev-cat-name">${k}</div>
      <div class="rev-cat-amount">${fmt(v.total)}</div>
      <div class="rev-cat-count">${v.count} khoản</div>
    </div>`).join(''):'<p style="color:var(--muted);font-size:13px;padding:12px 0;">Không có dữ liệu trong tháng này.</p>';

  const tbody=document.getElementById('rev-table-body');
  const pb=p=>p==='Đã Chuyển Khoản'?`<span class="badge badge-paid">✓ CK</span>`:`<span class="badge badge-cash">💵 TM</span>`;
  const allRows = [
    ...paid.map((s,i)=>`<tr>
      <td>${i+1}</td>
      <td class="td-name">${s.name}</td>
      <td style="color:var(--navy);font-weight:600">${s.subject}</td>
      <td style="font-size:11px;color:var(--muted)">${s.pkg||'–'}</td>
      <td style="font-weight:800;color:var(--gold)">${fmt(s.amount)}</td>
      <td>${fmtDate(s.paydate)}</td>
      <td>${pb(s.payment)}</td>
    </tr>`),
    ...paidLeads.map((l,i)=>`<tr style="background:#fefce8;">
      <td>${paid.length+i+1}</td>
      <td class="td-name">${l.name}</td>
      <td style="color:var(--navy);font-weight:600">${l.hocThuType||'Học Thử/Dụng Cụ'}</td>
      <td style="font-size:11px;color:var(--muted)">${(l.dungcu||[]).map(d=>d.name).join(', ')||'–'}</td>
      <td style="font-weight:800;color:var(--gold)">${fmt(l.totalThu)}</td>
      <td>${fmtDate(l.createdAt)}</td>
      <td><span class="badge badge-cash">💵 Mục Khác</span></td>
    </tr>`),
  ];
  if(!allRows.length){tbody.innerHTML=`<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">💰</div><div class="empty-text">Chưa có khoản thu nào trong tháng này</div></div></td></tr>`;return;}
  tbody.innerHTML = allRows.join('');
}

// ── DASHBOARD ──
function renderDashboard(){
  document.getElementById('stat-total').textContent   = students.length;
  document.getElementById('stat-paid').textContent    = students.filter(s=>s.payment!=='Chưa Thanh Toán').length;
  document.getElementById('stat-unpaid').textContent  = students.filter(s=>s.payment==='Chưa Thanh Toán').length;
  document.getElementById('stat-staff').textContent   = staff.length;
  document.getElementById('stat-leads').textContent   = leads.length;
  const recent=[...students].reverse().slice(0,5);
  const pb=p=>p==='Đã Chuyển Khoản'?`<span class="badge badge-paid" style="font-size:10px">✓ CK</span>`:p==='Tiền Mặt'?`<span class="badge badge-cash" style="font-size:10px">TM</span>`:`<span class="badge badge-unpaid" style="font-size:10px">Chưa</span>`;
  const dtEl=document.getElementById('dashboard-table');
  dtEl.innerHTML=recent.length?recent.map(s=>`<tr><td class="td-name">${s.name}</td><td style="font-size:11.5px">${s.subject}</td><td>${pb(s.payment)}</td></tr>`).join(''):`<tr><td colspan="3"><div class="empty-state" style="padding:20px"><div class="empty-text">Chưa có học viên nào</div></div></td></tr>`;
  const now=new Date();
  const m=now.getMonth()+1,y=now.getFullYear();
  const paidM=students.filter(s=>{if(!s.paydate||s.payment==='Chưa Thanh Toán')return false;const d=new Date(s.paydate);return d.getFullYear()===y&&(d.getMonth()+1)===m;});
  const totalM=paidM.reduce((a,s)=>a+Number(s.amount||0),0);
  document.getElementById('dash-revenue-summary').innerHTML=`
    <div style="text-align:center;padding:20px 0;">
      <div style="font-size:9.5px;letter-spacing:2.5px;text-transform:uppercase;color:var(--muted);font-weight:700;margin-bottom:8px;">Tháng ${m}/${y}</div>
      <div style="font-size:32px;font-weight:800;color:var(--gold);letter-spacing:-1px">${fmt(totalM)}</div>
      <div style="font-size:12px;color:var(--muted);margin-top:6px;font-weight:400;">từ ${paidM.length} học viên đã thanh toán</div>
    </div>
    ${totalM===0?'<p style="text-align:center;font-size:12px;color:var(--muted2);padding-bottom:8px;">Chưa có khoản thu nào trong tháng này</p>':''}`;
}

// ── XUẤT EXCEL ──
function exportExcel(type) {
  // Thử gọi server trước; nếu không có server thì xuất CSV trực tiếp từ browser
  const serverUrl = `http://localhost:3000/api/export/${type}`;

  fetch(serverUrl, { method: 'GET' })
    .then(res => {
      if (!res.ok) throw new Error('Server lỗi');
      return res.blob();
    })
    .then(blob => {
      const names = { students: 'HocVien', staff: 'NhanSu', leads: 'HVTiemNang', revenue: 'DoanhThu' };
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${names[type]}_${new Date().toLocaleDateString('vi-VN').replace(/\//g,'-')}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Đã xuất file Excel thành công!');
    })
    .catch(() => {
      // Fallback: xuất thẳng từ dữ liệu localStorage
      exportCSVLocal(type);
    });
}

function exportCSVLocal(type) {
  const BOM = '\uFEFF';
  const fmtDate = d => d ? new Date(d).toLocaleDateString('vi-VN') : '';
  const fmtNum  = n => Number(n || 0).toLocaleString('vi-VN');
  const q = v  => `"${String(v || '').replace(/"/g, '""')}"`;

  let csv = BOM;
  let filename = '';

  if (type === 'students') {
    filename = `HocVien_${new Date().toLocaleDateString('vi-VN').replace(/\//g,'-')}.csv`;
    csv += ['#','Họ Tên','Ngày Sinh','Phụ Huynh (Zalo)','SĐT','Môn Học','Gói / Lớp','Ngày BĐ','Ngày KT','Học Phí','Số Tiền (đ)','Ngày Nộp','Ghi Chú'].map(q).join(',') + '\n';
    students.forEach((s, i) => {
      csv += [i+1,s.name,fmtDate(s.dob),s.parent,s.phone,s.subject,s.pkg||'',fmtDate(s.start),fmtDate(s.end),s.payment,fmtNum(s.amount),fmtDate(s.paydate),s.note||''].map(q).join(',') + '\n';
    });
  } else if (type === 'staff') {
    filename = `NhanSu_${new Date().toLocaleDateString('vi-VN').replace(/\//g,'-')}.csv`;
    csv += ['#','Họ Tên','Ngày Sinh','SĐT','Vị Trí','Tình Trạng','Ghi Chú'].map(q).join(',') + '\n';
    staff.forEach((s, i) => {
      csv += [i+1,s.name,fmtDate(s.dob),s.phone,s.role,s.status,s.note||''].map(q).join(',') + '\n';
    });
  } else if (type === 'leads') {
    filename = `HVTiemNang_${new Date().toLocaleDateString('vi-VN').replace(/\//g,'-')}.csv`;
    csv += ['#','Họ Tên HV','Ngày Sinh','Phụ Huynh (Zalo)','SĐT','Khóa Học','Nguồn Data','Tình Trạng','Ghi Chú'].map(q).join(',') + '\n';
    leads.forEach((l, i) => {
      csv += [i+1,l.name,fmtDate(l.dob),l.parent,l.phone,l.course,l.source,l.status,l.note||''].map(q).join(',') + '\n';
    });
  } else if (type === 'revenue') {
    filename = `DoanhThu_${new Date().toLocaleDateString('vi-VN').replace(/\//g,'-')}.csv`;
    csv += ['#','Họ Tên','Môn Học','Gói / Lớp','Hình Thức','Số Tiền (đ)','Ngày Nộp'].map(q).join(',') + '\n';
    const paid = students.filter(s => s.payment !== 'Chưa Thanh Toán' && s.amount);
    paid.forEach((s, i) => {
      csv += [i+1,s.name,s.subject,s.pkg||'',s.payment,fmtNum(s.amount),fmtDate(s.paydate)].map(q).join(',') + '\n';
    });
    const total = paid.reduce((a, s) => a + Number(s.amount || 0), 0);
    csv += ['','','','',q('TỔNG'),q(fmtNum(total)),q('')].join(',') + '\n';
  }

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Đã xuất file Excel thành công!');
}


function showToast(msg,err){
  const t=document.getElementById('toast');
  document.getElementById('toast-msg').textContent=msg;
  t.style.borderLeftColor=err?'var(--red)':'var(--gold)';
  t.className='toast show';
  setTimeout(()=>t.className='toast',3200);
}


// ── CLASSES ──
let editClassId = null;
const DAYS = ['Thứ 2','Thứ 3','Thứ 4','Thứ 5','Thứ 6','Thứ 7','Chủ Nhật'];

function addScheduleRow(day, timeStart, timeEnd) {
  const list = document.getElementById('cl-schedule-list');
  const idx = list.children.length;
  const div = document.createElement('div');
  div.style.cssText = 'display:flex;gap:8px;align-items:center;';
  div.innerHTML = `
    <select class="rev-month-select cl-day" style="flex:1">
      ${DAYS.map(d=>`<option${d===(day||'')?' selected':''}>${d}</option>`).join('')}
    </select>
    <input type="time" class="search-box cl-time-start" value="${timeStart||''}" style="flex:1;padding:8px 10px;" placeholder="Giờ bắt đầu">
    <input type="time" class="search-box cl-time-end" value="${timeEnd||''}" style="flex:1;padding:8px 10px;" placeholder="Giờ kết thúc">
    <button type="button" class="btn-icon del" onclick="this.parentElement.remove()" title="Xóa">✕</button>`;
  list.appendChild(div);
}

function getScheduleRows() {
  const rows = [];
  document.querySelectorAll('#cl-schedule-list > div').forEach(div => {
    const day   = div.querySelector('.cl-day').value;
    const start = div.querySelector('.cl-time-start').value;
    const end   = div.querySelector('.cl-time-end').value;
    if (day) rows.push({day, start, end});
  });
  return rows;
}

function saveClass() {
  const g = id => document.getElementById(id).value.trim();
  const code = g('cl-code'), name = g('cl-name'), subject = g('cl-subject'),
        teacher = g('cl-teacher'), room = g('cl-room'), note = g('cl-note');
  if (!code || !name || !subject) { showToast('Vui lòng điền Mã Lớp, Tên Lớp và Khóa Học (*)', true); return; }
  if (classes.find(c => c.code === code && c.id !== editClassId)) { showToast('Mã lớp đã tồn tại!', true); return; }
  const schedule = getScheduleRows();
  const isNew=editClassId===null;
  const obj={id:isNew?Date.now():editClassId,code,name,subject,teacher,room,note,schedule};
  if(!isNew){const i=classes.findIndex(c=>c.id===editClassId);if(i!==-1)classes[i]=obj;else{showToast('Không tìm thấy lớp!',true);return;}}
  else classes.push(obj);
  editClassId=null; const savedId=obj.id;
  saveAsync().then(ok=>{
    if(ok){
      if(isNew){showToast('Đã tạo lớp thành công!');viewClassDetail(savedId);}
      else{showToast('Đã cập nhật lớp thành công!');showPage('classes');}
    } else { if(isNew) classes.pop(); }
  });
}

function clearClassForm() {
  ['cl-code','cl-name','cl-teacher','cl-room','cl-note'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('cl-subject').value = '';
  document.getElementById('cl-schedule-list').innerHTML = '';
  editClassId = null;
  document.getElementById('class-form-title').innerHTML = 'Thêm <span>Lớp Học</span>';
}

function editClass(id) {
  const c = classes.find(x => x.id === id); if (!c) return;
  editClassId = id;
  document.getElementById('cl-code').value    = c.code;
  document.getElementById('cl-name').value    = c.name;
  document.getElementById('cl-subject').value = c.subject;
  document.getElementById('cl-teacher').value = c.teacher || '';
  document.getElementById('cl-room').value    = c.room || '';
  document.getElementById('cl-note').value    = c.note || '';
  document.getElementById('cl-schedule-list').innerHTML = '';
  (c.schedule || []).forEach(s => addScheduleRow(s.day, s.start, s.end));
  document.getElementById('class-form-title').innerHTML = 'Chỉnh Sửa <span>Lớp Học</span>';
  showPage('add-class');
}

function deleteClass(id) {
  const c = classes.find(x => x.id === id); if (!c) return;
  confirmDelete(c.name, () => {
    classes = classes.filter(x => x.id !== id);
    save(); renderClassTable(); renderDashboard();
    showToast('Đã xóa lớp ' + c.name + '.');
  });
}

function renderClassTable() {
  const q = (document.getElementById('class-search').value || '').toLowerCase();
  const filtered = classes.filter(c =>
    !q || c.code.toLowerCase().includes(q) || c.name.toLowerCase().includes(q) || c.subject.toLowerCase().includes(q)
  );
  const tbody = document.getElementById('class-table-body');
  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state"><div class="empty-icon">🏫</div><div class="empty-text">Chưa có lớp nào</div></div></td></tr>`;
    return;
  }
  tbody.innerHTML = filtered.map((c, i) => {
    const hvCount = students.filter(s => Number(s.classid) === Number(c.id)).length;
    const sched = (c.schedule || []).map(s => `${s.day} ${s.start}–${s.end}`).join('<br>') || '–';
    return `<tr>
      <td>${i+1}</td>
      <td><span class="pos-badge">${c.code}</span></td>
      <td class="td-name">${c.name}</td>
      <td style="color:var(--navy);font-weight:600">${c.subject}</td>
      <td style="font-size:11.5px">${c.teacher||'–'}</td>
      <td style="font-size:11px;color:var(--muted)">${sched}</td>
      <td style="font-size:11.5px">${c.room||'–'}</td>
      <td style="font-weight:700;color:var(--navy)">${hvCount}</td>
      <td><div class="action-btns">
        <button class="btn-icon" onclick="viewClassDetail(${c.id})" title="Xem">👁</button>
        <button class="btn-icon" onclick="editClass(${c.id})" title="Sửa">✎</button>
        <button class="btn-icon del" onclick="deleteClass(${c.id})" title="Xóa">✕</button>
      </div></td>
    </tr>`;
  }).join('');
}

// ── SCHEDULE / TKB ──
function renderSchedule() {
  const filterSubj = document.getElementById('tkb-filter-subject').value;
  const filteredClasses = filterSubj === 'all' ? classes : classes.filter(c => c.subject === filterSubj);

  // Build grid: rows = giờ slot, cols = thứ
  const dayOrder = ['Thứ 2','Thứ 3','Thứ 4','Thứ 5','Thứ 6','Thứ 7','Chủ Nhật'];

  // Collect all time slots
  const slots = new Set();
  filteredClasses.forEach(c => (c.schedule||[]).forEach(s => {
    if (s.start) slots.add(s.start);
  }));
  const sortedSlots = [...slots].sort();

  if (!filteredClasses.length || !sortedSlots.length) {
    document.getElementById('schedule-grid').innerHTML =
      '<div class="empty-state" style="padding:60px 0"><div class="empty-icon">📅</div><div class="empty-text">Chưa có lịch học nào. Hãy tạo lớp và thêm buổi học.</div></div>';
    return;
  }

  // Build lookup: day -> timeStart -> [{class, students}]
  const lookup = {};
  dayOrder.forEach(d => { lookup[d] = {}; });
  filteredClasses.forEach(c => {
    const classStudents = students.filter(s => Number(s.classid) === Number(c.id));
    (c.schedule||[]).forEach(s => {
      if (!s.day || !s.start) return;
      if (!lookup[s.day]) lookup[s.day] = {};
      if (!lookup[s.day][s.start]) lookup[s.day][s.start] = [];
      lookup[s.day][s.start].push({ cls: c, studs: classStudents, end: s.end });
    });
  });

  let html = `<div class="table-wrap"><table style="min-width:900px;">
    <thead><tr><th style="width:90px">Giờ</th>${dayOrder.map(d=>`<th>${d}</th>`).join('')}</tr></thead>
    <tbody>`;

  sortedSlots.forEach(slot => {
    html += `<tr><td class="tkb-time-cell">${slot}</td>`;
    dayOrder.forEach(day => {
      const entries = (lookup[day] && lookup[day][slot]) || [];
      if (!entries.length) {
        html += `<td style="background:rgba(251,237,211,.15)"></td>`;
      } else {
        html += `<td>`;
        entries.forEach(e => {
          const endStr = e.end ? `–${e.end}` : '';
          const studsHtml = e.studs.length
            ? e.studs.map(s=>`<div class="tkb-cell-student">👤 ${s.name}</div>`).join('')
            : `<div class="tkb-empty">Chưa có HV</div>`;
          html += `<div class="tkb-cell">
            <div class="tkb-cell-code">[${e.cls.code}] ${e.cls.name}</div>
            <div class="tkb-cell-info">🕐 ${slot}${endStr} · ${e.cls.subject}</div>
            ${e.cls.teacher?`<div class="tkb-cell-teacher">👩‍🏫 ${e.cls.teacher}</div>`:''}
            ${studsHtml}
          </div>`;
        });
        html += `</td>`;
      }
    });
    html += `</tr>`;
  });

  html += `</tbody></table></div>`;
  document.getElementById('schedule-grid').innerHTML = html;
}


// ── CUSTOM COURSES CRUD ──
let editCustomCourseKey = null;

function startAddCourse() {
  editCustomCourseKey = null;
  document.getElementById('cc-key').value = '';
  document.getElementById('cc-name').value = '';
  document.getElementById('cc-emoji').value = '';
  document.getElementById('cc-rows-wrap').innerHTML = '';
  addCustomCourseRow();
  document.getElementById('custom-course-modal').classList.add('open');
}

function editCustomCourse(key) {
  const c = customCourses.find(x => x.key === key);
  if (!c) return;
  editCustomCourseKey = key;
  document.getElementById('cc-key').value = key;
  document.getElementById('cc-name').value = c.name;
  document.getElementById('cc-emoji').value = c.emoji || '';
  const wrap = document.getElementById('cc-rows-wrap');
  wrap.innerHTML = '';
  (c.sections||[]).forEach(sec => {
    (sec.rows||[]).forEach(r => addCustomCourseRow(sec.title, r.desc, r.amount));
  });
  document.getElementById('custom-course-modal').classList.add('open');
}

function deleteCustomCourse(key) {
  const c = customCourses.find(x => x.key === key);
  if (!c) return;
  confirmDelete(c.name, () => {
    customCourses = customCourses.filter(x => x.key !== key);
    if (customPrices[key]) delete customPrices[key];
    save(); renderCoursesPage(); showToast('Đã xóa khóa học ' + c.name);
  });
}

function addCustomCourseRow(section, desc, amount) {
  const wrap = document.getElementById('cc-rows-wrap');
  const div = document.createElement('div');
  div.style.cssText = 'display:grid;grid-template-columns:1fr 2fr 1fr auto;gap:8px;align-items:center;margin-bottom:8px;';
  div.innerHTML = `
    <input type="text" class="search-box cc-section" placeholder="Tên nhóm gói" value="${section||''}" style="padding:8px 10px;font-size:12px;">
    <input type="text" class="search-box cc-desc" placeholder="Mô tả gói học" value="${desc||''}" style="padding:8px 10px;font-size:12px;">
    <input type="number" class="search-box cc-amount" placeholder="Học phí (đ)" value="${amount||0}" min="0" style="padding:8px 10px;font-size:12px;">
    <button type="button" class="btn-icon del" onclick="this.parentElement.remove()" title="Xóa">✕</button>`;
  wrap.appendChild(div);
}

function saveCustomCourse() {
  const key = document.getElementById('cc-key').value.trim().replace(/\s+/g,'_').toLowerCase();
  const name = document.getElementById('cc-name').value.trim();
  const emoji = document.getElementById('cc-emoji').value.trim() || '📚';
  if (!key || !name) { showToast('Vui lòng điền Mã khóa và Tên khóa học!', true); return; }
  if (!editCustomCourseKey && (CD[key] || customCourses.find(c=>c.key===key))) {
    showToast('Mã khóa học đã tồn tại!', true); return;
  }
  // Build sections from rows
  const rows = document.querySelectorAll('#cc-rows-wrap > div');
  const sectMap = {};
  rows.forEach(div => {
    const sec = div.querySelector('.cc-section').value.trim() || 'Học Phí';
    const desc = div.querySelector('.cc-desc').value.trim();
    const amount = Number(div.querySelector('.cc-amount').value) || 0;
    if (!desc) return;
    if (!sectMap[sec]) sectMap[sec] = [];
    sectMap[sec].push({desc, amount});
  });
  const sections = Object.entries(sectMap).map(([title, rows]) => ({title, rows}));
  if (!sections.length) { showToast('Vui lòng thêm ít nhất 1 gói học phí!', true); return; }
  const obj = {key, name, emoji, sections};
  // packages
  const pkgList = [];
  sections.forEach(s => s.rows.forEach(r => pkgList.push(r.desc)));
  if (editCustomCourseKey) {
    const i = customCourses.findIndex(c => c.key === editCustomCourseKey);
    if (i !== -1) customCourses[i] = obj;
  } else {
    customCourses.push(obj);
  }
  // update COURSE_PACKAGES dynamically
  COURSE_PACKAGES[name] = pkgList;
  save(); closeCustomCourseModal(); renderCoursesPage();
  showToast('Đã lưu khóa học ' + name + '!');
}

function closeCustomCourseModal() {
  document.getElementById('custom-course-modal').classList.remove('open');
  editCustomCourseKey = null;
}

function renderCoursesPage() {
  renderSubjectFilterBtns();
  // Re-render course cards including custom ones
  const grid = document.getElementById('courses-grid');
  if (!grid) return;
  // static cards are already in HTML, just append/re-render custom ones
  let customHtml = '';
  customCourses.forEach(c => {
    const totalPkg = c.sections ? c.sections.reduce((a,s)=>a+s.rows.length,0) : 0;
    customHtml += `<div class="course-card" onclick="openCourse('${c.key}')">
      <span class="course-emoji">${c.emoji||'📚'}</span>
      <div class="course-name">${c.name}</div>
      <div class="course-count">${totalPkg} gói học phí</div>
      <div style="display:flex;gap:5px;margin-top:8px;">
        <button class="btn-icon" onclick="event.stopPropagation();editCustomCourse('${c.key}')" title="Sửa">✎</button>
        <button class="btn-icon del" onclick="event.stopPropagation();deleteCustomCourse('${c.key}')" title="Xóa">✕</button>
      </div>
    </div>`;
  });
  document.getElementById('custom-courses-container').innerHTML = customHtml;
  // Sync COURSE_PACKAGES for all custom
  customCourses.forEach(c => {
    const pkgList = [];
    (c.sections||[]).forEach(s => s.rows.forEach(r => pkgList.push(r.desc)));
    COURSE_PACKAGES[c.name] = pkgList;
  });
  // Sync f-subject selects
  syncCourseSelects();
}

function syncCourseSelects() {
  ['f-subject','cl-subject','lf-course','tkb-filter-subject'].forEach(id => {
    const sel = document.getElementById(id);
    if (!sel) return;
    [...sel.querySelectorAll('option.custom-opt')].forEach(o => o.remove());
    customCourses.forEach(c => {
      const o = document.createElement('option');
      o.textContent = c.name;
      o.className = 'custom-opt';
      sel.appendChild(o);
    });
  });
}

// ── INIT (gọi sau khi đăng nhập xong) ──
initRevSelectors();

// ════════════════════════════════════════
// ── ĐIỂM DANH ──
// ════════════════════════════════════════
function initAttendancePage() {
  // Populate class dropdown
  const sel = document.getElementById('att-class');
  sel.innerHTML = '<option value="">-- Chọn lớp --</option>'
    + classes.map(c => `<option value="${c.id}">[${c.code}] ${c.name} – ${c.subject}</option>`).join('');
  // Default date = today
  const d = document.getElementById('att-date');
  if (!d.value) d.value = new Date().toISOString().slice(0,10);
  document.getElementById('att-content').innerHTML = `<div class="empty-state"><div class="empty-icon">✅</div><div class="empty-text">Chọn lớp và ngày rồi nhấn "Tải Danh Sách"</div></div>`;
}

function loadAttStudents() {
  const classId = document.getElementById('att-class').value;
  const date    = document.getElementById('att-date').value;
  const session = document.getElementById('att-session').value;
  if (!classId || !date) { showToast('Vui lòng chọn lớp và ngày học', true); return; }

  const cls = classes.find(c => String(c.id) === String(classId));
  const classStudents = students.filter(s => String(s.classid) === String(classId));
  if (!classStudents.length) {
    document.getElementById('att-content').innerHTML = `<div class="empty-state"><div class="empty-icon">👤</div><div class="empty-text">Lớp này chưa có học viên nào</div></div>`;
    return;
  }

  // Find existing attendance record for this class+date
  const existing = attendance.find(a => String(a.classId) === String(classId) && a.date === date);
  const records  = existing ? existing.records : {};

  // Extract total sessions from pkg string
  function extractTotalSessions(pkg) {
    if (!pkg) return 0;
    const m = pkg.match(/(\d+)\s*buổi/);
    return m ? parseInt(m[1]) : 0;
  }

  // Count buổi đã có mặt cho mỗi HV (từ tất cả attendance records của lớp + makeup done)
  function countDoneSessions(studentId) {
    let count = 0;
    attendance.forEach(a => {
      if (String(a.classId) !== String(classId)) return;
      if (a.records && a.records[studentId] === 'present') count++;
    });
    // Cộng thêm buổi bù đã hoàn thành
    makeups.forEach(m => {
      if (String(m.studentId) === String(studentId) && m.status === 'done') count++;
    });
    return count;
  }

  let html = `
    <div class="card" style="margin-bottom:12px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px;">
        <div>
          <div class="card-title" style="margin-bottom:2px;">Điểm Danh: [${cls?cls.code:'?'}] ${cls?cls.name:''}</div>
          <div style="font-size:12px;color:var(--muted);">Ngày: <b>${new Date(date+'T00:00:00').toLocaleDateString('vi-VN')}</b>${session?' · Buổi số <b>'+session+'</b>':''} · <b>${classStudents.length}</b> học viên</div>
        </div>
        <button class="btn btn-gold" onclick="saveAttendance('${classId}','${date}')">💾 Lưu Điểm Danh</button>
      </div>
      <div id="att-rows">`;

  classStudents.forEach(s => {
    const cur = records[s.id] || '';
    const totalPkg = extractTotalSessions(s.pkg);
    const done = countDoneSessions(s.id);
    const pct  = totalPkg ? Math.min(100, Math.round(done / totalPkg * 100)) : 0;
    const remaining = totalPkg ? Math.max(0, totalPkg - done) : null;
    const doneColor = pct >= 100 ? '#16a34a' : pct >= 70 ? '#d97706' : 'var(--gold)';

    html += `
      <div class="att-student-row" id="att-row-${s.id}">
        <div style="flex:1;min-width:0;">
          <div class="att-student-name">${s.name}</div>
          <div class="att-student-info">${s.subject}${s.pkg?' · <span style="color:var(--navy);font-weight:600">'+s.pkg+'</span>':''}</div>
          ${totalPkg ? `
          <div style="margin-top:6px;max-width:240px;">
            <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--muted);margin-bottom:3px;">
              <span>Tiến độ: <b style="color:${doneColor}">${done}</b>/${totalPkg} buổi</span>
              <span style="color:${pct>=100?'#16a34a':'var(--muted)'};">${pct>=100?'✅ Hoàn thành':'còn '+remaining+' buổi'}</span>
            </div>
            <div class="att-progress"><div class="att-progress-bar" style="width:${pct}%;background:${doneColor};"></div></div>
          </div>` : `<div style="font-size:10px;color:var(--muted);margin-top:4px;">Chưa có gói – không tính tiến độ</div>`}
        </div>
        <div class="att-radio-group" style="flex-shrink:0;">
          <button class="att-radio-btn${cur==='present'?' present':''}" onclick="setAtt('${s.id}','present',this)">✅ Có Mặt</button>
          <button class="att-radio-btn${cur==='absent-ex'?' absent-ex':''}" onclick="setAtt('${s.id}','absent-ex',this)">📋 Vắng Có Phép</button>
          <button class="att-radio-btn${cur==='absent-no'?' absent-no':''}" onclick="setAtt('${s.id}','absent-no',this)">❌ Vắng Không Phép</button>
        </div>
      </div>`;
  });
  html += `</div></div>`;
  document.getElementById('att-content').innerHTML = html;
}

let currentAttRecords = {};
function setAtt(studentId, status, btn) {
  currentAttRecords[studentId] = status;
  // Update button styles
  const row = document.getElementById('att-row-'+studentId);
  row.querySelectorAll('.att-radio-btn').forEach(b => {
    b.classList.remove('present','absent-ex','absent-no');
  });
  const cls = status==='present'?'present':status==='absent-ex'?'absent-ex':'absent-no';
  btn.classList.add(cls);
}

function saveAttendance(classId, date) {
  const rows = document.querySelectorAll('[id^="att-row-"]');
  const records = {};
  rows.forEach(row => {
    const sid = row.id.replace('att-row-','');
    const active = row.querySelector('.att-radio-btn.present,.att-radio-btn.absent-ex,.att-radio-btn.absent-no');
    if (active) {
      records[sid] = active.classList.contains('present') ? 'present'
        : active.classList.contains('absent-ex') ? 'absent-ex' : 'absent-no';
    }
  });

  const idx = attendance.findIndex(a => String(a.classId)===String(classId) && a.date===date);
  const session = document.getElementById('att-session').value;
  const obj = { id: Date.now(), classId, date, session: Number(session)||0, records };
  if (idx !== -1) attendance[idx] = { ...attendance[idx], ...obj };
  else attendance.push(obj);

  // Auto-create makeup for absent-ex
  Object.entries(records).forEach(([sid, status]) => {
    if (status === 'absent-ex') {
      const alreadyExists = makeups.find(m => m.studentId === Number(sid) && m.absentDate === date);
      if (!alreadyExists) {
        const st = students.find(s => String(s.id) === String(sid));
        makeups.push({
          id: Date.now() + Math.random(),
          studentId: Number(sid),
          studentName: st ? st.name : '',
          classId,
          absentDate: date,
          absentType: 'Vắng có phép',
          makeupDate: '',
          status: 'pending',
          note: 'Tự động tạo từ điểm danh'
        });
      }
    }
  });

  save();
  showToast('Đã lưu điểm danh thành công!');
  loadAttStudents();
}

// ════════════════════════════════════════
// ── BÙ LỊCH ──
// ════════════════════════════════════════
function initMakeupSelects() {
  const sel = document.getElementById('mk-student');
  if (sel) {
    sel.innerHTML = '<option value="">-- Chọn học viên --</option>'
      + students.map(s => `<option value="${s.id}">${s.name} – ${s.subject}</option>`).join('');
  }
  const csel = document.getElementById('mk-class');
  if (csel) {
    csel.innerHTML = '<option value="">-- Chọn lớp --</option>'
      + classes.map(c => `<option value="${c.id}">[${c.code}] ${c.name}</option>`).join('');
  }
}

function setMakeupFilter(f, el) {
  makeupFilter = f;
  document.querySelectorAll('#page-makeup .filter-tab').forEach(t => t.classList.remove('active'));
  if (el) el.classList.add('active');
  renderMakeupTable();
}

function renderMakeupTable() {
  const q = (document.getElementById('makeup-search').value||'').toLowerCase();
  const filtered = makeups.filter(m => {
    const mq = !q || (m.studentName||'').toLowerCase().includes(q);
    const mf = makeupFilter==='all' || (makeupFilter==='pending'&&m.status==='pending') || (makeupFilter==='done'&&m.status==='done');
    return mq && mf;
  });
  // Stats
  document.getElementById('mk-total').textContent   = makeups.length;
  document.getElementById('mk-pending').textContent = makeups.filter(m=>m.status==='pending').length;
  document.getElementById('mk-done').textContent    = makeups.filter(m=>m.status==='done').length;

  const tbody = document.getElementById('makeup-table-body');
  if (!filtered.length) { tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state"><div class="empty-icon">🔄</div><div class="empty-text">Không có buổi bù nào</div></div></td></tr>`; return; }
  tbody.innerHTML = filtered.map((m,i) => {
    const cls = classes.find(c => String(c.id)===String(m.classId));
    const statusBadge = m.status==='done'
      ? `<span class="badge badge-paid">✅ Đã Bù</span>`
      : `<span class="badge badge-unpaid">⏳ Chưa Bù</span>`;
    const typeBadge = m.absentType==='Vắng có phép'
      ? `<span class="badge" style="background:#fff7ed;color:#92400e;border:1.5px solid #f59e0b;">📋 Có Phép</span>`
      : `<span class="badge" style="background:#fef2f2;color:#dc2626;border:1.5px solid #f87171;">❌ Không Phép</span>`;
    return `<tr>
      <td>${i+1}</td>
      <td class="td-name">${m.studentName||'–'}</td>
      <td>${cls?`<span class="pos-badge">[${cls.code}]</span>`:'–'}</td>
      <td style="font-size:11.5px;">${fmtDate(m.absentDate)}</td>
      <td>${typeBadge}</td>
      <td style="font-size:11.5px;">${m.makeupDate?fmtDate(m.makeupDate):'<span style="color:var(--muted)">Chưa xếp</span>'}</td>
      <td>${statusBadge}</td>
      <td style="font-size:11px;color:var(--muted);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${m.note||''}">${m.note||'–'}</td>
      <td><div class="action-btns">
        ${m.status==='pending'?`<button class="btn-icon" onclick="markMakeupDone(${m.id})" title="Đánh dấu đã bù" style="color:#16a34a;border-color:#4ade80;">✓</button>`:''}
        <button class="btn-icon" onclick="editMakeup(${m.id})" title="Sửa">✎</button>
        <button class="btn-icon del" onclick="deleteMakeup(${m.id})" title="Xóa">✕</button>
      </div></td>
    </tr>`;
  }).join('');
}

function markMakeupDone(id) {
  const m = makeups.find(x => x.id===id); if(!m) return;
  m.status = 'done';
  if (!m.makeupDate) m.makeupDate = new Date().toISOString().slice(0,10);
  save(); renderMakeupTable(); showToast('Đã đánh dấu buổi bù hoàn thành!');
}

function openAddMakeup() {
  editMakeupId = null;
  initMakeupSelects();
  document.getElementById('mk-absent-date').value = '';
  document.getElementById('mk-makeup-date').value = '';
  document.getElementById('mk-absent-type').value = '';
  document.getElementById('mk-status').value = 'pending';
  document.getElementById('mk-note').value = '';
  document.getElementById('makeup-modal-title').textContent = 'Thêm Buổi Bù';
  document.getElementById('makeup-modal').classList.add('open');
}

function editMakeup(id) {
  const m = makeups.find(x => x.id===id); if(!m) return;
  editMakeupId = id;
  initMakeupSelects();
  document.getElementById('mk-student').value     = m.studentId||'';
  document.getElementById('mk-class').value       = m.classId||'';
  document.getElementById('mk-absent-date').value = m.absentDate||'';
  document.getElementById('mk-absent-type').value = m.absentType||'';
  document.getElementById('mk-makeup-date').value = m.makeupDate||'';
  document.getElementById('mk-status').value      = m.status||'pending';
  document.getElementById('mk-note').value        = m.note||'';
  document.getElementById('makeup-modal-title').textContent = 'Sửa Buổi Bù';
  document.getElementById('makeup-modal').classList.add('open');
}

function saveMakeup() {
  const studentId   = Number(document.getElementById('mk-student').value);
  const classId     = document.getElementById('mk-class').value;
  const absentDate  = document.getElementById('mk-absent-date').value;
  const absentType  = document.getElementById('mk-absent-type').value;
  const makeupDate  = document.getElementById('mk-makeup-date').value;
  const status      = document.getElementById('mk-status').value;
  const note        = document.getElementById('mk-note').value.trim();
  if (!studentId || !absentDate || !absentType) { showToast('Vui lòng điền đầy đủ thông tin bắt buộc', true); return; }
  const st = students.find(s => s.id===studentId);
  const obj = { id: editMakeupId||Date.now(), studentId, studentName: st?st.name:'', classId, absentDate, absentType, makeupDate, status, note };
  if (editMakeupId) {
    const i = makeups.findIndex(m => m.id===editMakeupId);
    if (i!==-1) makeups[i] = obj;
    editMakeupId = null;
  } else makeups.push(obj);
  save(); closeMakeupModal(); renderMakeupTable(); showToast('Đã lưu buổi bù!');
}

function deleteMakeup(id) {
  const m = makeups.find(x => x.id===id); if(!m) return;
  confirmDelete(m.studentName+' ('+fmtDate(m.absentDate)+')', () => {
    makeups = makeups.filter(x => x.id!==id);
    save(); renderMakeupTable(); showToast('Đã xóa buổi bù.');
  });
}

function closeMakeupModal() { document.getElementById('makeup-modal').classList.remove('open'); }

// ════════════════════════════════════════
// ── TƯ VẤN & TIN NHẮN MẪU ──
// ════════════════════════════════════════
function initConsultPage() {
  setConsultTab(consultTab, null);
  renderTemplates();
}

function setConsultTab(tab, el) {
  consultTab = tab;
  document.querySelectorAll('#page-consult .filter-tab').forEach(t => t.classList.remove('active'));
  if (el) el.classList.add('active');
  else {
    document.querySelectorAll('#page-consult .filter-tab').forEach(t => {
      if ((t.textContent||'').includes(tab==='process'?'Quy Trình':'Tin Nhắn')) t.classList.add('active');
    });
  }
  ['process','templates'].forEach(t => {
    const el = document.getElementById('consult-tab-'+t);
    if (el) el.style.display = t===tab ? '' : 'none';
  });
  if (tab==='templates') renderTemplates();
}

function generateGroupMsg() {
  const name   = document.getElementById('cf-name').value.trim();
  const age    = document.getElementById('cf-age').value.trim();
  const parent = document.getElementById('cf-parent').value.trim();
  const course = document.getElementById('cf-course').value.trim();
  const note   = document.getElementById('cf-note').value.trim();
  if (!name) { showToast('Vui lòng nhập tên học viên', true); return; }
  const now = new Date();
  const timeStr = now.toLocaleDateString('vi-VN') + ' ' + now.toLocaleTimeString('vi-VN',{hour:'2-digit',minute:'2-digit'});
  const text = `KH MỚI – ${timeStr}\n${'─'.repeat(30)}\nHọc Viên  : ${name}\nĐộ Tuổi   : ${age||'–'}\nPH Zalo   : ${parent||'–'}\nMôn Học   : ${course||'–'}\nGhi Chú   : ${note||'–'}\n${'─'.repeat(30)}\nTrạng Thái: Đang tư vấn`;
  document.getElementById('cf-output').textContent = text;
  document.getElementById('cf-output-wrap').style.display = 'block';
}

function copyGroupMsg() {
  const text = document.getElementById('cf-output').textContent;
  navigator.clipboard.writeText(text).then(()=>{}).catch(()=>{const ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);});
  const cf = document.getElementById('cf-copied');
  cf.style.display='block'; setTimeout(()=>cf.style.display='none',3000);
}

let activeCourseGroup = null;

function renderTemplates() {
  const q = (document.getElementById('template-search')||{value:''}).value.toLowerCase();
  const grid = document.getElementById('templates-grid');
  if (!grid) return;

  // Build groups
  const groups = {};
  templates.forEach(t => {
    if (!groups[t.course]) groups[t.course] = { emoji: t.emoji||'💬', items: [] };
    groups[t.course].items.push(t);
  });

  // Filter by search
  const filteredGroups = {};
  Object.entries(groups).forEach(([course, g]) => {
    const matchGroup = !q || course.toLowerCase().includes(q);
    const matchItems = g.items.filter(t => !q || t.content.toLowerCase().includes(q) || course.toLowerCase().includes(q));
    if (matchGroup || matchItems.length) {
      filteredGroups[course] = { ...g, items: matchGroup ? g.items : matchItems };
    }
  });

  if (!Object.keys(filteredGroups).length) {
    grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1;padding:40px;"><div class="empty-icon">💬</div><div class="empty-text">Chưa có tin nhắn mẫu nào.<br>Nhấn "+ Thêm Tin Nhắn Mẫu" để tạo mới.</div></div>`;
    return;
  }

  // If search active, show all flat
  if (q) {
    activeCourseGroup = null;
    let html = `<div style="grid-column:1/-1;display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px;">`;
    Object.entries(filteredGroups).forEach(([course, g]) => {
      g.items.forEach(t => {
        html += buildTemplateCard(t);
      });
    });
    html += '</div>';
    grid.innerHTML = html;
    return;
  }

  // Level 1: môn tabs (if no group selected)
  if (!activeCourseGroup || !filteredGroups[activeCourseGroup]) {
    activeCourseGroup = null;
    grid.innerHTML = `
      <div style="grid-column:1/-1;">
        <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:6px;">
          ${Object.entries(filteredGroups).map(([course, g]) => `
            <button onclick="selectCourseGroup('${course.replace(/'/g,"\\'")}');"
              style="display:flex;align-items:center;gap:8px;background:var(--white);border:1.5px solid rgba(200,146,42,.15);border-radius:12px;padding:10px 16px;cursor:pointer;transition:all .2s;font-family:'Be Vietnam Pro',sans-serif;min-width:160px;"
              onmouseover="this.style.borderColor='var(--gold)';this.style.background='var(--cream)';"
              onmouseout="this.style.borderColor='rgba(200,146,42,.15)';this.style.background='var(--white)';">
              <span style="font-size:22px;">${g.emoji}</span>
              <div style="text-align:left;">
                <div style="font-size:12px;font-weight:800;color:var(--navy);">${course}</div>
                <div style="font-size:10px;color:var(--muted);">${g.items.length} tin nhắn mẫu</div>
              </div>
              <span style="margin-left:auto;color:var(--gold);font-size:16px;">›</span>
            </button>`).join('')}
          <button onclick="openAddTemplate();" style="display:flex;align-items:center;gap:8px;background:var(--cream);border:1.5px dashed var(--gold);border-radius:12px;padding:10px 16px;cursor:pointer;font-family:'Be Vietnam Pro',sans-serif;min-width:160px;color:var(--gold);font-weight:700;font-size:12px;">
            <span style="font-size:22px;">＋</span> Thêm Mẫu Mới
          </button>
        </div>
      </div>`;
    return;
  }

  // Level 2: cards in selected group
  const g = filteredGroups[activeCourseGroup];
  grid.innerHTML = `
    <div style="grid-column:1/-1;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
        <button onclick="activeCourseGroup=null;renderTemplates();" style="background:var(--cream);border:1.5px solid var(--cream2);border-radius:8px;padding:6px 14px;cursor:pointer;font-size:12px;font-weight:700;color:var(--navy);font-family:'Be Vietnam Pro',sans-serif;">← Quay lại</button>
        <span style="font-size:22px;">${g.emoji}</span>
        <div style="font-size:16px;font-weight:800;color:var(--navy);">${activeCourseGroup}</div>
        <button onclick="openAddTemplate('${activeCourseGroup.replace(/'/g,"\\'")}');" style="margin-left:auto;background:var(--gold);color:#fff;border:none;border-radius:8px;padding:7px 16px;cursor:pointer;font-size:11px;font-weight:700;font-family:'Be Vietnam Pro',sans-serif;">+ Thêm mẫu</button>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;">
        ${g.items.map(t => buildTemplateCard(t)).join('')}
      </div>
    </div>`;
}

function buildTemplateCard(t) {
  const preview = t.content.length > 120 ? t.content.slice(0, 120) + '…' : t.content;
  return `<div style="background:var(--white);border-radius:12px;border:1.5px solid rgba(200,146,42,.12);box-shadow:var(--shadow-sm);overflow:hidden;display:flex;flex-direction:column;">
    <div style="background:var(--navy);padding:10px 14px;">
      <div style="font-size:11px;font-weight:800;color:var(--gold);letter-spacing:.5px;">${t.course}</div>
    </div>
    <div style="padding:12px 14px;flex:1;">
      <div style="background:var(--cream);border-radius:8px;padding:10px;font-size:11.5px;color:#1a1a1a;line-height:1.7;white-space:pre-wrap;font-family:'Be Vietnam Pro',sans-serif;max-height:180px;overflow-y:auto;">${t.content}</div>
    </div>
    <div style="padding:10px 14px 12px;display:flex;gap:7px;border-top:1px solid var(--cream2);">
      <button onclick="copyTemplate(${t.id})" style="background:var(--gold);color:#fff;border:none;border-radius:8px;padding:7px 0;font-size:11px;font-weight:700;cursor:pointer;font-family:'Be Vietnam Pro',sans-serif;flex:1;">📋 Sao Chép</button>
      <button onclick="editTemplate(${t.id})" style="background:var(--white);border:1.5px solid var(--cream2);color:var(--navy);border-radius:8px;padding:7px 11px;font-size:13px;cursor:pointer;" title="Sửa">✎</button>
      <button onclick="deleteTemplate(${t.id})" style="background:#fff5f5;border:1.5px solid #fca5a5;color:#dc2626;border-radius:8px;padding:7px 11px;font-size:14px;cursor:pointer;" title="Xóa">🗑</button>
    </div>
  </div>`;
}

function selectCourseGroup(course) {
  activeCourseGroup = course;
  renderTemplates();
}

function copyTemplate(id) {
  const t = templates.find(x => x.id===id); if(!t) return;
  navigator.clipboard.writeText(t.content).then(() => showToast('Đã sao chép tin nhắn! Dán vào Zalo ngay.')).catch(()=>{
    const ta = document.createElement('textarea'); ta.value=t.content; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
    showToast('Đã sao chép!');
  });
}

function openAddTemplate(prefillCourse) {
  editTemplateId = null;
  document.getElementById('tpl-course').value  = prefillCourse || '';
  document.getElementById('tpl-emoji').value   = '';
  document.getElementById('tpl-content').value = '';
  document.getElementById('template-modal-title').textContent = 'Thêm Tin Nhắn Mẫu';
  document.getElementById('template-modal').classList.add('open');
}

function editTemplate(id) {
  const t = templates.find(x => x.id===id); if(!t) return;
  editTemplateId = id;
  document.getElementById('tpl-course').value  = t.course;
  document.getElementById('tpl-emoji').value   = t.emoji||'';
  document.getElementById('tpl-content').value = t.content;
  document.getElementById('template-modal-title').textContent = 'Sửa Tin Nhắn Mẫu';
  document.getElementById('template-modal').classList.add('open');
}

function saveTemplate() {
  const course  = document.getElementById('tpl-course').value.trim();
  const emoji   = document.getElementById('tpl-emoji').value.trim() || '💬';
  const content = document.getElementById('tpl-content').value.trim();
  if (!course || !content) { showToast('Vui lòng điền tên môn và nội dung', true); return; }
  const obj = { id: editTemplateId||Date.now(), course, emoji, content };
  if (editTemplateId) {
    const i = templates.findIndex(t => t.id===editTemplateId);
    if (i!==-1) templates[i] = obj;
    editTemplateId = null;
  } else templates.push(obj);
  save(); closeTemplateModal(); renderTemplates(); showToast('Đã lưu tin nhắn mẫu!');
}

function deleteTemplate(id) {
  const t = templates.find(x => x.id===id); if(!t) return;
  confirmDelete(t.course, () => {
    templates = templates.filter(x => x.id!==id);
    save(); renderTemplates(); showToast('Đã xóa tin nhắn mẫu.');
  });
}

function closeTemplateModal() { document.getElementById('template-modal').classList.remove('open'); }

// Form thu thập thông tin tư vấn
function copyConsultForm() {
  const name   = document.getElementById('cf-name').value.trim();
  const age    = document.getElementById('cf-age').value.trim();
  const parent = document.getElementById('cf-parent').value.trim();
  const phone  = document.getElementById('cf-phone').value.trim();
  const course = document.getElementById('cf-course').value;
  const note   = document.getElementById('cf-note').value.trim();
  if (!name||!parent||!phone) { showToast('Vui lòng điền đủ tên HV, tên PH và SĐT', true); return; }
  const text = `HV MỚI 🎵\n- Tên HV: ${name}${age?' ('+age+')':''}\n- Phụ huynh: ${parent}\n- SĐT: ${phone}${course?'\n- Môn quan tâm: '+course:''}${note?'\n- Lưu ý: '+note:''}`;
  navigator.clipboard.writeText(text).then(() => {}).catch(()=>{ const ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta); });
  const cf = document.getElementById('cf-copied');
  cf.style.display='block'; setTimeout(()=>cf.style.display='none',3000);
}

function saveLeadFromForm() {
  const name   = document.getElementById('cf-name').value.trim();
  const age    = document.getElementById('cf-age').value.trim();
  const parent = document.getElementById('cf-parent').value.trim();
  const course = document.getElementById('cf-course').value.trim();
  const note   = document.getElementById('cf-note').value.trim();
  if (!name||!parent) { showToast('Vui lòng điền tên HV và tên phụ huynh', true); return; }
  leads.push({ id: Date.now(), name, dob:'', parent, phone:'', course: course||'Chưa xác định', source:'Trực tiếp', status:'Đã tư vấn', note: (age?'Độ tuổi: '+age+'. ':'')+(note||''), createdAt: new Date().toISOString().slice(0,10) });
  save(); clearConsultForm(); showToast('Đã lưu vào HV Tiềm Năng!');
}

function clearConsultForm() {
  ['cf-name','cf-age','cf-parent','cf-course','cf-note'].forEach(id => { const el=document.getElementById(id); if(el) el.value=''; });
  const wrap = document.getElementById('cf-output-wrap');
  if (wrap) wrap.style.display='none';
}

function copyGroupTemplate() {
  const text = 'HV MỚI 🎵\n- Tên HV: [Tên học viên]\n- Độ tuổi: [Tuổi]\n- Phụ huynh: [Tên PH]\n- SĐT: [Số điện thoại]\n- Môn quan tâm: [Môn học]\n- Lưu ý: [Ghi chú thêm]';
  navigator.clipboard.writeText(text).then(()=>showToast('Đã sao chép mẫu gửi nhóm!')).catch(()=>{const ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);showToast('Đã sao chép!');});
}

// Backup / Restore
function exportBackup() {
  const data = { students, staff, leads, classes, attendance, makeups, templates, customCourses, customPrices };
  const blob = new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`vinsoul_backup_${new Date().toISOString().slice(0,10)}.json`; a.click();
  showToast('Đã tải file backup!');
}

function importBackup() {
  const input = document.createElement('input'); input.type='file'; input.accept='.json';
  input.onchange = e => {
    const file = e.target.files[0]; if(!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      try {
        const data = JSON.parse(ev.target.result);
        if (data.students) students = data.students;
        if (data.staff)    staff    = data.staff;
        if (data.leads)    leads    = data.leads;
        if (data.classes)  classes  = data.classes;
        if (data.attendance) attendance = data.attendance;
        if (data.makeups)    makeups    = data.makeups;
        if (data.templates)  templates  = data.templates;
        if (data.customCourses) customCourses = data.customCourses;
        if (data.customPrices)  customPrices  = data.customPrices;
        saveAsync().then(ok => { if (ok) { renderDashboard(); renderCoursesPage(); showToast('Khôi phục dữ liệu thành công!'); } });
      } catch { showToast('File backup không hợp lệ!', true); }
    };
    reader.readAsText(file);
  };
  input.click();
}

// ── SEED TIN NHẮN MẪU (từ data chính thức) ──
function seedTemplatesIfEmpty() {
  if (templates.length > 0) return;
  const N = 'Anh/chị có thể tham gia buổi học trải nghiệm trước khi đăng ký lớp chính thức ạ.';
  const N5 = 'Anh/chị có thể tham gia buổi học trải nghiệm (500.000đ) trước khi đăng ký lớp chính thức ạ.';
  const N1 = 'Anh/chị có thể tham gia buổi học trải nghiệm (100.000đ) trước khi đăng ký lớp chính thức ạ.';

  function mk(course, emoji, items) {
    return items.map(([title, fee, time, buoi, freq, dong2, noi_dung, after, note]) => ({
      id: Date.now() + Math.random(),
      course, emoji,
      content: `${title}\n💰 Học phí: ${fee}\n⏱ Thời lượng: ${time} (${buoi})\n📅 Tần suất: ${freq}${dong2 ? '\n💳 Đóng 2 lần: ' + dong2 : ''}\n\n📚 Nội dung khóa học:\n${noi_dung}\n\n✨ ${after}\n${note}`
    }));
  }

  const GUITAR_ND = `1️⃣ Làm quen guitar và kỹ thuật cơ bản\n2️⃣ Học hợp âm, tiết tấu\n3️⃣ Học cách đệm các bài hát quen thuộc\n4️⃣ Thực hành đệm và biểu diễn các bài yêu thích`;
  const GUITAR_AF = 'Sau khóa học, học viên có thể tự đệm và trình diễn tự tin cùng nhạc cụ.';
  const LTG_ND = `1️⃣ Ôn luyện kỹ thuật guitar chuyên sâu\n2️⃣ Học và luyện các bài thi theo giáo trình chuẩn\n3️⃣ Rèn luyện tốc độ, độ chính xác và biểu cảm\n4️⃣ Thực hành thi thử và nhận xét chi tiết`;
  const LTG_AF = 'Sau khóa học, học viên sẵn sàng tham gia các kỳ thi guitar với kỹ thuật vững chắc.';

  const VIOLIN_ND = `1️⃣ Làm quen violin và tư thế cầm đàn đúng\n2️⃣ Học kỹ thuật kéo vĩ cung cơ bản\n3️⃣ Học đọc nhạc và luyện tập giai điệu\n4️⃣ Thực hành biểu diễn các bản nhạc đơn giản`;
  const VIOLIN_AF = 'Sau khóa học, học viên có thể chơi được các bản nhạc cơ bản và tự tin biểu diễn.';
  const LTV_ND = `1️⃣ Ôn luyện kỹ thuật violin chuyên sâu\n2️⃣ Học và luyện các bài thi theo giáo trình chuẩn\n3️⃣ Rèn luyện tốc độ, độ chính xác và biểu cảm\n4️⃣ Thực hành thi thử và nhận xét chi tiết`;
  const LTV_AF = 'Sau khóa học, học viên sẵn sàng tham gia các kỳ thi violin với kỹ thuật vững chắc.';

  const PIANO_ND = `1️⃣ Làm quen piano và hợp âm cơ bản\n2️⃣ Học đọc nhạc và luyện ngón tay\n3️⃣ Học đệm và chơi các bản nhạc đơn giản\n4️⃣ Thực hành chơi các bài nhạc yêu thích`;
  const PIANO_AF = 'Sau khóa học, học viên có thể tự chơi piano và đệm hát một số bài hát phổ biến.';
  const LTP_ND = `1️⃣ Ôn luyện kỹ thuật piano chuyên sâu\n2️⃣ Học và luyện các bài thi theo giáo trình chuẩn\n3️⃣ Rèn luyện tốc độ, độ chính xác và biểu cảm\n4️⃣ Thực hành thi thử và nhận xét chi tiết`;
  const LTP_AF = 'Sau khóa học, học viên sẵn sàng tham gia các kỳ thi piano với kỹ thuật vững chắc.';

  const PDH_ND = `1️⃣ Làm quen piano và hợp âm cơ bản\n2️⃣ Học cách đệm hát các bài hát quen thuộc\n3️⃣ Học pattern đệm piano đơn giản\n4️⃣ Thực hành đệm và hát các bài yêu thích`;
  const PDH_AF = 'Sau khóa học, học viên có thể tự đệm và hát một số bài hát phổ biến.';

  const UKU_ND = `1️⃣ Làm quen ukulele và tiết tấu cơ bản\n2️⃣ Học hợp âm và kỹ thuật gảy đàn\n3️⃣ Học đệm các bài hát vui và dễ chơi\n4️⃣ Thực hành đệm hát các bài yêu thích`;
  const UKU_AF = 'Sau khóa học, học viên có thể tự đệm hát được nhiều bài nhạc phổ biến một cách tự tin.';

  const TN_ND = `1️⃣ Luyện giọng và hơi thở cơ bản\n2️⃣ Học kỹ thuật hát rõ lời, lấy hơi đúng\n3️⃣ Học xử lý cảm xúc qua giọng hát\n4️⃣ Thực hành thể hiện các bài hát yêu thích`;
  const TN_AF = 'Sau khóa học, học viên có thể hát đúng kỹ thuật và tự tin biểu diễn trước đám đông.';

  const MN_ND = `1️⃣ Làm quen màu sắc và hình khối cơ bản\n2️⃣ Vẽ các hình đơn giản theo chủ đề\n3️⃣ Phát triển sự sáng tạo qua các bài tập\n4️⃣ Tạo ra các tác phẩm nghệ thuật đơn giản`;
  const CB_ND = `1️⃣ Kỹ thuật vẽ phác thảo và đường nét\n2️⃣ Học bố cục, ánh sáng và bóng đổ\n3️⃣ Vẽ tĩnh vật và phong cảnh cơ bản\n4️⃣ Thực hành hoàn thiện các bài vẽ hoàn chỉnh`;
  const KH_ND = `1️⃣ Làm quen chất liệu và dụng cụ vẽ chuyên biệt\n2️⃣ Học kỹ thuật xử lý màu đặc trưng theo từng chất liệu\n3️⃣ Thực hành vẽ các chủ đề đa dạng\n4️⃣ Hoàn thiện bài vẽ bằng chất liệu đã chọn`;
  const AC_ND = `1️⃣ Làm quen với canvas hoặc bảng vẽ kỹ thuật số\n2️⃣ Học kỹ thuật pha màu và xây dựng lớp màu\n3️⃣ Thực hành vẽ tác phẩm trên canvas hoặc phần mềm\n4️⃣ Hoàn thiện và trình bày tác phẩm cá nhân`;
  const LTV_ND2 = `1️⃣ Ôn luyện kỹ thuật vẽ chuyên sâu theo đề thi\n2️⃣ Học bố cục, tỉ lệ và biểu đạt cảm xúc trên tranh\n3️⃣ Luyện tập theo đúng thể thức và thời gian thi\n4️⃣ Thực hành thi thử và nhận xét chi tiết`;

  const B35_ND = `1️⃣ Làm quen với âm nhạc và chuyển động cơ bản\n2️⃣ Học tư thế đứng đúng và khả năng cân bằng\n3️⃣ Luyện tập các bước nhảy ballet đơn giản\n4️⃣ Biểu diễn các bài múa ngắn theo chủ đề`;
  const B69_ND = `1️⃣ Ôn luyện tư thế và kỹ thuật ballet cơ bản\n2️⃣ Học các bước nhảy và chuyển động trung cấp\n3️⃣ Luyện tập phối hợp nhịp điệu và âm nhạc\n4️⃣ Biểu diễn bài múa hoàn chỉnh cuối khóa`;
  const DA_ND = `1️⃣ Khởi động cơ thể và học nhịp điệu cơ bản\n2️⃣ Học các vũ đạo hiện đại phổ biến\n3️⃣ Luyện tập phối hợp nhóm và đồng điệu\n4️⃣ Biểu diễn bài múa nhóm cuối khóa`;
  const KV_ND = `1️⃣ Làm quen các điệu nhảy khiêu vũ cơ bản\n2️⃣ Học tư thế, bước đi và dẫn dắt\n3️⃣ Luyện tập phối hợp cặp đôi hoặc nhóm\n4️⃣ Thực hành nhảy trong các tình huống thực tế`;
  const MCT_ND = `1️⃣ Tìm hiểu về múa cổ trang và văn hóa dân tộc\n2️⃣ Học các động tác tay, chân đặc trưng\n3️⃣ Luyện tập biểu cảm và dáng điệu trên nhạc cụ thể\n4️⃣ Biểu diễn bài múa hoàn chỉnh theo chủ đề cổ trang`;
  const HT_ND = `1️⃣ Tìm hiểu môn học và không gian lớp học\n2️⃣ Trải nghiệm trực tiếp cùng giáo viên\n3️⃣ Nhận tư vấn lộ trình học phù hợp\n4️⃣ Giải đáp mọi thắc mắc trước khi đăng ký`;

  const allTemplates = [
    ...mk('Guitar','🎸', [
      ['🎸 GUITAR — LỚP NHÓM 3 HỌC VIÊN (3 THÁNG)','5.400.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','2.700.000đ/lần',GUITAR_ND,GUITAR_AF,N],
      ['🎸 GUITAR — LỚP NHÓM 3 HỌC VIÊN (1 THÁNG)','2.000.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',GUITAR_ND,GUITAR_AF,N],
      ['🎸 GUITAR — LỚP 2 HỌC VIÊN (3 THÁNG)','7.200.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.600.000đ/lần',GUITAR_ND,GUITAR_AF,N],
      ['🎸 GUITAR — LỚP 2 HỌC VIÊN (1 THÁNG)','2.600.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',GUITAR_ND,GUITAR_AF,N],
      ['🎸 GUITAR — LỚP 1-1 CÁ NHÂN (3 THÁNG)','12.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','6.000.000đ/lần',GUITAR_ND,GUITAR_AF,N5],
      ['🎸 GUITAR — LỚP 1-1 CÁ NHÂN (1 THÁNG)','4.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',GUITAR_ND,GUITAR_AF,N5],
    ]),
    ...mk('Luyện Thi Guitar','🏆', [
      ['🎸 LUYỆN THI GUITAR — NHÓM 3 HỌC VIÊN (3 THÁNG)','6.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.000.000đ/lần',LTG_ND,LTG_AF,N],
      ['🎸 LUYỆN THI GUITAR — NHÓM 3 HỌC VIÊN (1 THÁNG)','2.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTG_ND,LTG_AF,N],
      ['🎸 LUYỆN THI GUITAR — LỚP 2 HỌC VIÊN (3 THÁNG)','8.400.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','4.200.000đ/lần',LTG_ND,LTG_AF,N],
      ['🎸 LUYỆN THI GUITAR — LỚP 2 HỌC VIÊN (1 THÁNG)','3.000.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTG_ND,LTG_AF,N],
      ['🎸 LUYỆN THI GUITAR — LỚP 1-1 CÁ NHÂN (3 THÁNG)','12.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','6.000.000đ/lần',LTG_ND,LTG_AF,N5],
      ['🎸 LUYỆN THI GUITAR — LỚP 1-1 CÁ NHÂN (1 THÁNG)','4.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTG_ND,LTG_AF,N5],
    ]),
    ...mk('Violin','🎻', [
      ['🎻 VIOLIN — LỚP NHÓM 3 HỌC VIÊN (3 THÁNG)','5.400.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','2.700.000đ/lần',VIOLIN_ND,VIOLIN_AF,N],
      ['🎻 VIOLIN — LỚP NHÓM 3 HỌC VIÊN (1 THÁNG)','2.000.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',VIOLIN_ND,VIOLIN_AF,N],
      ['🎻 VIOLIN — LỚP 2 HỌC VIÊN (3 THÁNG)','7.200.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.600.000đ/lần',VIOLIN_ND,VIOLIN_AF,N],
      ['🎻 VIOLIN — LỚP 2 HỌC VIÊN (1 THÁNG)','2.600.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',VIOLIN_ND,VIOLIN_AF,N],
      ['🎻 VIOLIN — LỚP 1-1 CÁ NHÂN (3 THÁNG)','12.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','6.000.000đ/lần',VIOLIN_ND,VIOLIN_AF,N5],
      ['🎻 VIOLIN — LỚP 1-1 CÁ NHÂN (1 THÁNG)','4.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',VIOLIN_ND,VIOLIN_AF,N5],
    ]),
    ...mk('Luyện Thi Violin','🏆', [
      ['🎻 LUYỆN THI VIOLIN — NHÓM 3 HỌC VIÊN (3 THÁNG)','6.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.000.000đ/lần',LTV_ND,LTV_AF,N],
      ['🎻 LUYỆN THI VIOLIN — NHÓM 3 HỌC VIÊN (1 THÁNG)','2.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTV_ND,LTV_AF,N],
      ['🎻 LUYỆN THI VIOLIN — LỚP 2 HỌC VIÊN (3 THÁNG)','8.400.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','4.200.000đ/lần',LTV_ND,LTV_AF,N],
      ['🎻 LUYỆN THI VIOLIN — LỚP 2 HỌC VIÊN (1 THÁNG)','3.000.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTV_ND,LTV_AF,N],
      ['🎻 LUYỆN THI VIOLIN — LỚP 1-1 CÁ NHÂN (3 THÁNG)','12.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','6.000.000đ/lần',LTV_ND,LTV_AF,N5],
      ['🎻 LUYỆN THI VIOLIN — LỚP 1-1 CÁ NHÂN (1 THÁNG)','4.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTV_ND,LTV_AF,N5],
    ]),
    ...mk('Piano','🎹', [
      ['🎹 PIANO — LỚP NHÓM 3 HỌC VIÊN (3 THÁNG)','5.400.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','2.700.000đ/lần',PIANO_ND,PIANO_AF,N],
      ['🎹 PIANO — LỚP NHÓM 3 HỌC VIÊN (1 THÁNG)','2.000.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',PIANO_ND,PIANO_AF,N],
      ['🎹 PIANO — LỚP 2 HỌC VIÊN (3 THÁNG)','7.200.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.600.000đ/lần',PIANO_ND,PIANO_AF,N],
      ['🎹 PIANO — LỚP 2 HỌC VIÊN (1 THÁNG)','2.600.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',PIANO_ND,PIANO_AF,N],
      ['🎹 PIANO — LỚP 1-1 CÁ NHÂN (3 THÁNG)','12.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','6.000.000đ/lần',PIANO_ND,PIANO_AF,N5],
      ['🎹 PIANO — LỚP 1-1 CÁ NHÂN (1 THÁNG)','4.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',PIANO_ND,PIANO_AF,N5],
    ]),
    ...mk('Luyện Thi Piano','🏆', [
      ['🎹 LUYỆN THI PIANO — NHÓM 3 HỌC VIÊN (3 THÁNG)','6.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.000.000đ/lần',LTP_ND,LTP_AF,N],
      ['🎹 LUYỆN THI PIANO — NHÓM 3 HỌC VIÊN (1 THÁNG)','2.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTP_ND,LTP_AF,N],
      ['🎹 LUYỆN THI PIANO — LỚP 2 HỌC VIÊN (3 THÁNG)','8.400.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','4.200.000đ/lần',LTP_ND,LTP_AF,N],
      ['🎹 LUYỆN THI PIANO — LỚP 2 HỌC VIÊN (1 THÁNG)','3.000.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTP_ND,LTP_AF,N],
      ['🎹 LUYỆN THI PIANO — LỚP 1-1 CÁ NHÂN (3 THÁNG)','12.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','6.000.000đ/lần',LTP_ND,LTP_AF,N5],
      ['🎹 LUYỆN THI PIANO — LỚP 1-1 CÁ NHÂN (1 THÁNG)','4.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTP_ND,LTP_AF,N5],
    ]),
    ...mk('Piano Đệm Hát','🎹🎤', [
      ['🎹🎤 PIANO ĐỆM HÁT — LỚP NHÓM 3 HỌC VIÊN (3 THÁNG)','5.400.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','2.700.000đ/lần',PDH_ND,PDH_AF,N],
      ['🎹🎤 PIANO ĐỆM HÁT — LỚP NHÓM 3 HỌC VIÊN (1 THÁNG)','2.000.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',PDH_ND,PDH_AF,N],
      ['🎹🎤 PIANO ĐỆM HÁT — LỚP 2 HỌC VIÊN (3 THÁNG)','7.200.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.600.000đ/lần',PDH_ND,PDH_AF,N],
      ['🎹🎤 PIANO ĐỆM HÁT — LỚP 2 HỌC VIÊN (1 THÁNG)','2.600.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',PDH_ND,PDH_AF,N],
      ['🎹🎤 PIANO ĐỆM HÁT — LỚP 1-1 CÁ NHÂN (3 THÁNG)','4.200.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','2.100.000đ/lần',PDH_ND,PDH_AF,'Anh/chị có thể tham gia buổi workshop cảm thụ âm nhạc trước khi đăng ký ạ.'],
      ['🎹🎤 PIANO ĐỆM HÁT — LỚP 1-1 CÁ NHÂN (1 THÁNG)','2.600.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',PDH_ND,PDH_AF,'Anh/chị có thể tham gia buổi workshop cảm thụ âm nhạc trước khi đăng ký ạ.'],
    ]),
    ...mk('Ukulele','🪕', [
      ['🪕 UKULELE — LỚP NHÓM 3 HỌC VIÊN (3 THÁNG)','5.400.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','2.700.000đ/lần',UKU_ND,UKU_AF,N],
      ['🪕 UKULELE — LỚP NHÓM 3 HỌC VIÊN (1 THÁNG)','2.000.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',UKU_ND,UKU_AF,N],
      ['🪕 UKULELE — LỚP 2 HỌC VIÊN (3 THÁNG)','7.200.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.600.000đ/lần',UKU_ND,UKU_AF,N],
      ['🪕 UKULELE — LỚP 2 HỌC VIÊN (1 THÁNG)','2.600.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',UKU_ND,UKU_AF,N],
      ['🪕 UKULELE — LỚP 1-1 CÁ NHÂN (3 THÁNG)','12.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','6.000.000đ/lần',UKU_ND,UKU_AF,N5],
      ['🪕 UKULELE — LỚP 1-1 CÁ NHÂN (1 THÁNG)','4.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',UKU_ND,UKU_AF,N5],
    ]),
    ...mk('Thanh Nhạc','🎤', [
      ['🎤 THANH NHẠC — LỚP 2 HỌC VIÊN (3 THÁNG)','7.200.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.600.000đ/lần',TN_ND,TN_AF,N],
      ['🎤 THANH NHẠC — LỚP 2 HỌC VIÊN (1 THÁNG)','2.600.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',TN_ND,TN_AF,N],
      ['🎤 THANH NHẠC — LỚP 1-1 CÁ NHÂN (3 THÁNG)','12.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','6.000.000đ/lần',TN_ND,TN_AF,N5],
      ['🎤 THANH NHẠC — LỚP 1-1 CÁ NHÂN (1 THÁNG)','4.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',TN_ND,TN_AF,N5],
    ]),
    ...mk('Vẽ – Mầm Non','🖍️', [
      ['🖍️ VẼ MẦM NON — LỚP NHÓM (3 THÁNG)','3.600.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','1.800.000đ/lần',MN_ND,'Sau khóa học, bé có nền tảng cảm nhận màu sắc, hình dạng và khả năng sáng tạo tự do.',N1],
      ['🖍️ VẼ MẦM NON — LỚP NHÓM (1 THÁNG)','1.400.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',MN_ND,'Sau khóa học, bé có nền tảng cảm nhận màu sắc, hình dạng và khả năng sáng tạo tự do.',N1],
    ]),
    ...mk('Vẽ – Căn Bản','✏️', [
      ['✏️ VẼ CĂN BẢN — LỚP NHÓM (3 THÁNG)','3.300.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','1.650.000đ/lần',CB_ND,'Sau khóa học, học viên có nền tảng vẽ căn bản vững chắc để học các kỹ thuật nâng cao hơn.',N1],
      ['✏️ VẼ CĂN BẢN — LỚP NHÓM (1 THÁNG)','1.300.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',CB_ND,'Sau khóa học, học viên có nền tảng vẽ căn bản vững chắc để học các kỹ thuật nâng cao hơn.',N1],
    ]),
    ...mk('Vẽ – Ký Họa / Màu Nước / Marker','🖊️', [
      ['🖊️ KÝ HỌA / MÀU NƯỚC / MÀU MARKER — LỚP NHÓM (3 THÁNG)','3.600.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','1.800.000đ/lần',KH_ND,'Sau khóa học, học viên có thể sử dụng thành thạo chất liệu đã học và thể hiện phong cách riêng.',N1],
      ['🖊️ KÝ HỌA / MÀU NƯỚC / MÀU MARKER — LỚP NHÓM (1 THÁNG)','1.400.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',KH_ND,'Sau khóa học, học viên có thể sử dụng thành thạo chất liệu đã học và thể hiện phong cách riêng.',N1],
    ]),
    ...mk('Vẽ – Acrylic / Digital Art','🖼️', [
      ['🖼️ MÀU ACRYLIC CANVAS / DIGITAL ART — LỚP NHÓM (3 THÁNG)','4.800.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','2.400.000đ/lần',AC_ND,'Sau khóa học, học viên có thể tạo ra các tác phẩm hội họa hoàn chỉnh trên canvas hoặc môi trường số.',N1],
      ['🖼️ MÀU ACRYLIC CANVAS / DIGITAL ART — LỚP NHÓM (1 THÁNG)','1.800.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',AC_ND,'Sau khóa học, học viên có thể tạo ra các tác phẩm hội họa hoàn chỉnh trên canvas hoặc môi trường số.',N1],
    ]),
    ...mk('Luyện Thi Vẽ','🎨', [
      ['🎨 LUYỆN THI VẼ — LỚP NHÓM (3 THÁNG)','7.200.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','3.600.000đ/lần',LTV_ND2,'Sau khóa học, học viên sẵn sàng tham gia các kỳ thi mỹ thuật với kỹ năng và sự tự tin cao.',N1],
      ['🎨 LUYỆN THI VẼ — LỚP NHÓM (1 THÁNG)','2.600.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',LTV_ND2,'Sau khóa học, học viên sẵn sàng tham gia các kỳ thi mỹ thuật với kỹ năng và sự tự tin cao.',N1],
    ]),
    ...mk('Ballet 3–5 Tuổi','🩰', [
      ['🩰 BALLET 3–5 TUỔI — LỚP NHÓM (3 THÁNG)','3.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','1.500.000đ/lần',B35_ND,'Sau khóa học, bé phát triển sự dẻo dai, phối hợp cơ thể và tình yêu thích âm nhạc nghệ thuật.',N1],
      ['🩰 BALLET 3–5 TUỔI — LỚP NHÓM (1 THÁNG)','1.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',B35_ND,'Sau khóa học, bé phát triển sự dẻo dai, phối hợp cơ thể và tình yêu thích âm nhạc nghệ thuật.',N1],
    ]),
    ...mk('Ballet 6–9 Tuổi','🩰', [
      ['🩰 BALLET 6–9 TUỔI — LỚP NHÓM (3 THÁNG)','3.600.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','1.800.000đ/lần',B69_ND,'Sau khóa học, học viên đạt được sự thành thục trong kỹ thuật ballet và tự tin trên sân khấu.',N1],
      ['🩰 BALLET 6–9 TUỔI — LỚP NHÓM (1 THÁNG)','1.400.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',B69_ND,'Sau khóa học, học viên đạt được sự thành thục trong kỹ thuật ballet và tự tin trên sân khấu.',N1],
    ]),
    ...mk('Dance','💃', [
      ['💃 DANCE (NHẢY HIỆN ĐẠI) — LỚP NHÓM (3 THÁNG)','3.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','1.500.000đ/lần',DA_ND,'Sau khóa học, học viên có thể nhảy các phong cách hiện đại và tự tin biểu diễn trước mọi người.',N1],
      ['💃 DANCE (NHẢY HIỆN ĐẠI) — LỚP NHÓM (1 THÁNG)','1.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',DA_ND,'Sau khóa học, học viên có thể nhảy các phong cách hiện đại và tự tin biểu diễn trước mọi người.',N1],
    ]),
    ...mk('Khiêu Vũ','🕺', [
      ['🕺 KHIÊU VŨ — LỚP NHÓM (3 THÁNG)','3.000.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','1.500.000đ/lần',KV_ND,'Sau khóa học, học viên có thể khiêu vũ tự tin trong các sự kiện, tiệc, giao lưu xã hội.',N1],
      ['🕺 KHIÊU VŨ — LỚP NHÓM (1 THÁNG)','1.200.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',KV_ND,'Sau khóa học, học viên có thể khiêu vũ tự tin trong các sự kiện, tiệc, giao lưu xã hội.',N1],
    ]),
    ...mk('Múa Cổ Trang','🏮', [
      ['🏮 MÚA CỔ TRANG — LỚP NHÓM (3 THÁNG)','3.600.000đ / khóa','3 tháng','24 buổi','2 buổi/tuần','1.800.000đ/lần',MCT_ND,'Sau khóa học, học viên có thể biểu diễn múa cổ trang đúng phong cách và tự tin trên sân khấu.',N1],
      ['🏮 MÚA CỔ TRANG — LỚP NHÓM (1 THÁNG)','1.400.000đ / tháng','1 tháng','8 buổi','2 buổi/tuần','',MCT_ND,'Sau khóa học, học viên có thể biểu diễn múa cổ trang đúng phong cách và tự tin trên sân khấu.',N1],
    ]),
    ...mk('Học Thử','⭐', [
      ['🔔 HỌC THỬ — LỚP NHÓM (10:1)','100.000đ / buổi','1 buổi trải nghiệm','1 buổi','','',HT_ND,'Buổi học thử giúp anh/chị cảm nhận thực tế trước khi quyết định đăng ký khóa học chính thức.',''],
      ['🔔 HỌC THỬ — LỚP 2 HỌC VIÊN (2-1)','250.000đ / buổi','1 buổi trải nghiệm','1 buổi','','',HT_ND,'Buổi học thử giúp anh/chị cảm nhận thực tế trước khi quyết định đăng ký khóa học chính thức.',''],
      ['🔔 HỌC THỬ — LỚP 1-1 CÁ NHÂN','500.000đ / buổi','1 buổi trải nghiệm','1 buổi','','',HT_ND,'Buổi học thử giúp anh/chị cảm nhận thực tế trước khi quyết định đăng ký khóa học chính thức.',''],
    ]),
  ];

  let baseId = Date.now();
  allTemplates.forEach((t, i) => { t.id = baseId + i; templates.push(t); });
  save();
}
// seedTemplatesIfEmpty se duoc goi trong initAppAfterLogin
// ── CHANGE PASSWORD MODAL ──
function showChangePasswordModal() {
  document.getElementById('cp-current').value = '';
  document.getElementById('cp-new').value = '';
  document.getElementById('cp-confirm').value = '';
  document.getElementById('cp-error').style.display = 'none';
  document.getElementById('cp-success').style.display = 'none';
  const modal = document.getElementById('change-pass-modal');
  modal.style.display = 'flex';
}

function closeChangePasswordModal() {
  document.getElementById('change-pass-modal').style.display = 'none';
}

async function submitChangePassword() {
  const current  = document.getElementById('cp-current').value;
  const newPass  = document.getElementById('cp-new').value;
  const confirm  = document.getElementById('cp-confirm').value;
  const errEl    = document.getElementById('cp-error');
  const succEl   = document.getElementById('cp-success');

  errEl.style.display = 'none';
  succEl.style.display = 'none';

  if (!current || !newPass || !confirm) {
    errEl.textContent = 'Vui lòng nhập đủ thông tin'; errEl.style.display = 'block'; return;
  }
  if (newPass.length < 8) {
    errEl.textContent = 'Mật khẩu mới phải có ít nhất 8 ký tự'; errEl.style.display = 'block'; return;
  }
  if (newPass !== confirm) {
    errEl.textContent = 'Mật khẩu xác nhận không khớp'; errEl.style.display = 'block'; return;
  }

  try {
    const r = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: current, newPassword: newPass })
    });
    const data = await r.json();
    if (!r.ok) { errEl.textContent = data.error || 'Lỗi'; errEl.style.display = 'block'; return; }
    succEl.textContent = 'Đổi mật khẩu thành công!'; succEl.style.display = 'block';
    setTimeout(closeChangePasswordModal, 1500);
  } catch {
    errEl.textContent = 'Lỗi kết nối'; errEl.style.display = 'block';
  }
}

window.initAppAfterLogin = async function() {
  try {
    const r    = await fetch('/api/load');
    if (!r.ok) throw new Error('Lỗi tải dữ liệu: ' + r.status);
    const data = await r.json();
    if (data.students)      students      = data.students;
    if (data.staff)         staff         = data.staff;
    if (data.leads)         leads         = data.leads;
    if (data.classes)       classes       = data.classes;
    if (data.attendance)    attendance    = data.attendance;
    if (data.makeups)       makeups       = data.makeups;
    if (data.templates)     templates     = data.templates;
    if (data.customCourses) customCourses = data.customCourses;
    if (data.customPrices)  customPrices  = data.customPrices;
    renderDashboard();
    renderCoursesPage();
    seedTemplatesIfEmpty();

    // Hien menu Quan Tri Tai Khoan neu la admin
    try {
      const meRes = await fetch('/api/auth/me');
      if (meRes.ok) {
        const me = await meRes.json();
        if (me.role === 'admin') {
          const navSec = document.getElementById('nav-section-accounts');
          if (navSec) navSec.style.display = '';
        }
      }
    } catch {}
  } catch(e) {
    console.error('Lỗi load dữ liệu:', e);
    showToast('Lỗi kết nối server!', true);
  }
};

// ════════════════════════════════════════
//  QUẢN TRỊ TÀI KHOẢN
// ════════════════════════════════════════

async function renderAccountsPage() {
  const wrap = document.getElementById('accounts-table-wrap');
  if (!wrap) return;
  wrap.innerHTML = '<div style="color:#aaa;font-size:13px;padding:10px;">Đang tải...</div>';
  try {
    const r = await fetch('/api/users');
    if (!r.ok) { wrap.innerHTML = '<div style="color:#D94F4F;font-size:13px;padding:10px;">Lỗi tải danh sách tài khoản</div>'; return; }
    const users = await r.json();
    const roleLabel = role => role === 'admin'
      ? '<span style="display:inline-block;background:#FFF3CD;color:#7a6000;border:1.5px solid #FFE08A;border-radius:20px;padding:4px 14px;font-size:11px;font-weight:700;white-space:nowrap;">Quản trị viên</span>'
      : '<span style="display:inline-block;background:#E8F5E9;color:#2E7D32;border:1.5px solid #A5D6A7;border-radius:20px;padding:4px 14px;font-size:11px;font-weight:700;white-space:nowrap;">Nhân viên</span>';
    const rows=users.map((u,i)=>`<tr>
      <td style="width:48px;text-align:center;color:var(--muted);font-size:12px;font-weight:700;">${i+1}</td>
      <td><div style="font-weight:700;color:var(--navy);font-size:13px;">${u.username}</div></td>
      <td><div style="font-weight:600;font-size:13px;">${u.displayName}</div></td>
      <td>${roleLabel(u.role)}</td>
      <td style="width:100px;text-align:center;">
        <div class="action-btns" style="justify-content:center;">
          <button class="btn-icon" onclick="openEditAccountModal(${u.id},'${u.username}','${u.displayName.replace(/'/g,"\'")}','${u.role}')" title="Sửa">✎</button>
          <button class="btn-icon del" onclick="deleteAccount(${u.id},'${u.username}')" title="Xóa">✕</button>
        </div>
      </td>
    </tr>`).join('');
    wrap.innerHTML=`<div class="table-wrap"><table style="min-width:500px;">
      <thead><tr>
        <th style="width:48px;text-align:center;">#</th>
        <th>Tên Đăng Nhập</th>
        <th>Họ Tên Hiển Thị</th>
        <th>Phân Quyền</th>
        <th style="width:100px;text-align:center;">Thao Tác</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
  } catch {
    wrap.innerHTML = '<div style="color:#D94F4F;font-size:13px;padding:10px;">Lỗi kết nối server</div>';
  }
}

function openCreateAccountModal() {
  document.getElementById('account-modal-title').textContent = 'Cấp Tài Khoản Mới';
  document.getElementById('acc-edit-id').value = '';
  document.getElementById('acc-username').value = '';
  document.getElementById('acc-username').disabled = false;
  document.getElementById('acc-displayname').value = '';
  document.getElementById('acc-password').value = '';
  document.getElementById('acc-password').placeholder = 'Ít nhất 8 ký tự';
  document.getElementById('acc-role').value = 'staff';
  document.getElementById('acc-error').style.display = 'none';
  document.getElementById('acc-pass-hint').style.display = 'none';
  document.getElementById('account-modal').classList.add('open');
}

function openEditAccountModal(id, username, displayName, role) {
  document.getElementById('account-modal-title').textContent = 'Sửa Tài Khoản';
  document.getElementById('acc-edit-id').value = id;
  document.getElementById('acc-username').value = username;
  document.getElementById('acc-username').disabled = true;
  document.getElementById('acc-displayname').value = displayName;
  document.getElementById('acc-password').value = '';
  document.getElementById('acc-password').placeholder = 'Để trống = giữ nguyên mật khẩu';
  document.getElementById('acc-role').value = role;
  document.getElementById('acc-error').style.display = 'none';
  document.getElementById('acc-pass-hint').style.display = '';
  document.getElementById('account-modal').classList.add('open');
}

function closeAccountModal() {
  document.getElementById('account-modal').classList.remove('open');
}

async function submitAccountForm() {
  const editId      = document.getElementById('acc-edit-id').value;
  const username    = document.getElementById('acc-username').value.trim();
  const displayName = document.getElementById('acc-displayname').value.trim();
  const password    = document.getElementById('acc-password').value;
  const role        = document.getElementById('acc-role').value;
  const errEl       = document.getElementById('acc-error');
  errEl.style.display = 'none';
  if (!displayName || !role) { errEl.textContent = 'Vui lòng điền đầy đủ thông tin'; errEl.style.display = 'block'; return; }
  if (!editId && (!username || !password)) { errEl.textContent = 'Tên đăng nhập và mật khẩu là bắt buộc'; errEl.style.display = 'block'; return; }
  if (password && password.length < 8) { errEl.textContent = 'Mật khẩu ít nhất 8 ký tự'; errEl.style.display = 'block'; return; }
  try {
    let res;
    if (editId) {
      const body = { displayName, role };
      if (password) body.password = password;
      res = await fetch('/api/users/' + editId, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } else {
      res = await fetch('/api/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, displayName, password, role }) });
    }
    const data = await res.json();
    if (!res.ok) { errEl.textContent = data.error || 'Lỗi server'; errEl.style.display = 'block'; return; }
    closeAccountModal();
    showToast(editId ? 'Đã cập nhật tài khoản!' : 'Đã cấp tài khoản mới!');
    renderAccountsPage();
  } catch { errEl.textContent = 'Lỗi kết nối server'; errEl.style.display = 'block'; }
}

async function deleteAccount(id, username) {
  confirmDelete('tài khoản "' + username + '"', async () => {
    try {
      const res = await fetch('/api/users/' + id, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) { showToast(data.error || 'Lỗi xóa tài khoản', true); return; }
      showToast('Đã xóa tài khoản!');
      renderAccountsPage();
    } catch { showToast('Lỗi kết nối server', true); }
  });
}
function viewClassDetail(classId){
  const c=classes.find(x=>Number(x.id)===Number(classId));
  if(!c){showPage('classes');return;}
  const page=document.getElementById('page-class-detail');
  if(!page)return;
  const sched=(c.schedule||[]).map(s=>`<span class="pos-badge" style="font-size:11px;margin-right:4px;">${s.day} ${s.start}–${s.end}</span>`).join('')||'<span style="color:var(--muted)">Chưa có lịch</span>';
  const cs=students.filter(s=>Number(s.classid)===Number(classId));
  const pb=p=>p==='Đã Chuyển Khoản'?`<span class="badge badge-paid">CK</span>`:p==='Tiền Mặt'?`<span class="badge badge-cash">TM</span>`:`<span class="badge badge-unpaid">Chưa TT</span>`;
  const rows=cs.length===0
    ?`<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">👤</div><div class="empty-text">Chưa có học viên nào trong lớp</div></div></td></tr>`
    :cs.map((s,i)=>`<tr>
      <td>${i+1}</td><td class="td-name">${s.name}</td>
      <td>${s.parent||'–'}</td><td>${s.phone||'–'}</td>
      <td style="font-weight:600;color:var(--navy)">${s.subject}${s.pkg?`<br><span style="font-size:10px;color:var(--muted)">${s.pkg}</span>`:''}</td>
      <td>${pb(s.payment)}</td>
      <td><div class="action-btns">
        <button class="btn-icon" onclick="editStudent(${s.id})" title="Sửa">✎</button>
        <button class="btn-icon del" onclick="removeStudentFromClass(${s.id},${classId})" title="Gỡ">✕</button>
      </div></td></tr>`).join('');
  page.innerHTML=`
    <div class="page-header">
      <div class="page-title">Chi Tiết <span>Lớp Học</span></div>
      <div class="page-sub">[${c.code}] ${c.name} – ${c.subject}</div>
    </div>
    <div class="card" style="margin-bottom:14px;">
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:16px;">
        <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px;">Mã Lớp</div><div style="font-weight:800;color:var(--navy);font-size:16px;">${c.code}</div></div>
        <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px;">Khóa Học</div><div style="font-weight:700;color:var(--navy)">${c.subject}</div></div>
        <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px;">Giáo Viên</div><div style="font-weight:600;">${c.teacher||'–'}</div></div>
        <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px;">Phòng</div><div style="font-weight:600;">${c.room||'–'}</div></div>
        <div><div style="font-size:11px;color:var(--muted);margin-bottom:3px;">Số Học Viên</div><div style="font-weight:800;color:var(--gold);font-size:22px;">${cs.length}</div></div>
      </div>
      <div><div style="font-size:11px;color:var(--muted);margin-bottom:6px;">Lịch Học</div><div>${sched}</div></div>
      ${c.note?`<div style="margin-top:10px;font-size:12px;color:var(--muted);border-top:1px solid var(--cream2);padding-top:10px;">Ghi chú: ${c.note}</div>`:''}
    </div>
    <div class="card">
      <div class="toolbar" style="margin-bottom:16px;">
        <div style="font-weight:700;font-size:15px;color:var(--navy)">Danh Sách Học Viên <span style="color:var(--gold)">(${cs.length})</span></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-gold" onclick="addStudentToClass(${classId})">+ Thêm Học Viên</button>
          <button class="btn btn-outline" onclick="editClass(${classId})">✎ Sửa Lớp</button>
          <button class="btn btn-outline" onclick="showPage('classes')">← Danh Sách Lớp</button>
        </div>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>#</th><th>Họ Tên</th><th>Phụ Huynh</th><th>SĐT</th><th>Khóa Học</th><th>Học Phí</th><th>Thao Tác</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>`;
  showPage('class-detail');
}
function addStudentToClass(classId){
  editStudentId=null; clearStudentForm();
  const cls=classes.find(c=>Number(c.id)===Number(classId));
  showPage('add-student');
  setTimeout(()=>{
    if(cls){
      const se=document.getElementById('f-subject');
      if(se){se.value=cls.subject;populatePackages('');}
      setTimeout(()=>{
        const ce=document.getElementById('f-classid'); if(ce) ce.value=classId;
        const te=document.getElementById('form-title');
        if(te) te.innerHTML=`Thêm Học Viên vào <span>[${cls.code}] ${cls.name}</span>`;
        window._addStudentForClassId=classId;
      },60);
    }
  },60);
}
function removeStudentFromClass(studentId,classId){
  const s=students.find(x=>x.id===studentId); if(!s)return;
  confirmDelete('gỡ học viên '+s.name+' khỏi lớp',()=>{
    const i=students.findIndex(x=>x.id===studentId);
    if(i!==-1) students[i]={...students[i],classid:0};
    saveAsync().then(ok=>{if(ok){showToast('Đã gỡ '+s.name+' khỏi lớp.');viewClassDetail(classId);}});
  });
}