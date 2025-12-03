// js/main.js
// Secure LocalStorage-based backend for Hostel Leave Management (client-side)
// - SHA-256 hashing via Web Crypto API
// - Strong password validation
// - RBAC (student/admin), session management, notifications
// - Persistent DB in localStorage under key 'HLM_DB'

// ----------------- Persistence -----------------
const STORAGE_KEY = 'HLM_DB';
let DB = {
  students: [],      // {name,email,phone,room,passHash,role,date}
  leaves: [],        // {id,name,room,email,phone,from,to,reason,status,date}
  notifications: [], // {id,toUser,toRole,message,read,date}
  leaveId: 1,
  notifId: 1
};

function loadDB() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) DB = JSON.parse(raw);
    else saveDB();
  } catch (e) {
    console.error('Failed to load DB', e);
    saveDB();
  }
}
function saveDB() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(DB));
}
loadDB();

// ----------------- Crypto (SHA-256) -----------------
async function hashPassword(password) {
  const enc = new TextEncoder();
  const data = enc.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ----------------- Session helpers -----------------
const SESSION_USER_KEY = 'HLM_user';
const SESSION_ROLE_KEY = 'HLM_role';

function setSession(userName, role) {
  localStorage.setItem(SESSION_USER_KEY, userName);
  localStorage.setItem(SESSION_ROLE_KEY, role);
  updateHeaderForSession();
}
function clearSession() {
  localStorage.removeItem(SESSION_USER_KEY);
  localStorage.removeItem(SESSION_ROLE_KEY);
  updateHeaderForSession();
}
function getSession() {
  return {
    user: localStorage.getItem(SESSION_USER_KEY),
    role: localStorage.getItem(SESSION_ROLE_KEY)
  };
}

// ----------------- UI helpers -----------------
function showMsg(id, msg, duration = 4000) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
  setTimeout(() => el.style.display = 'none', duration);
}
function showInlineMsgEl(el, msg, duration = 4000) {
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
  setTimeout(() => el.style.display = 'none', duration);
}
function escapeHtml(s){ if(!s) return ''; return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

// ----------------- Validation -----------------
function isStrongPassword(p) {
  // min 8, uppercase, lowercase, digit, special char
  return (
    typeof p === 'string' &&
    p.length >= 8 &&
    /[A-Z]/.test(p) &&
    /[a-z]/.test(p) &&
    /[0-9]/.test(p) &&
    /[!@#$%^&*(),.?":{}|<>]/.test(p)
  );
}

// ----------------- Registration (student/admin) -----------------
async function registerStudent() {
  const name = (document.getElementById('regName')||{}).value?.trim() || '';
  const email = (document.getElementById('regEmail')||{}).value?.trim() || '';
  const phone = (document.getElementById('regPhone')||{}).value?.trim() || '';
  const room = (document.getElementById('regRoom')||{}).value?.trim() || '';
  const pass = (document.getElementById('regPass')||{}).value || '';
  const passConfirm = (document.getElementById('regPassConfirm')||{}).value || '';
  const role = (document.getElementById('regRole')||{}).value || 'student';

  if (!name || !email || !phone || !room || !pass || !passConfirm) {
    showMsg('regError', 'Please fill all fields');
    return;
  }
  if (!/^\d{10}$/.test(phone)) {
    showMsg('regError', 'Phone must be exactly 10 digits');
    return;
  }
  if (!isStrongPassword(pass)) {
    showMsg('regError', 'Password must be 8+ chars, include uppercase, lowercase, number and special char');
    return;
  }
  if (pass !== passConfirm) {
    showMsg('regError', 'Passwords do not match');
    return;
  }

  // duplicates by name OR email OR phone
  const dup = DB.students.find(s =>
    s.name.toLowerCase() === name.toLowerCase() ||
    s.email.toLowerCase() === email.toLowerCase() ||
    s.phone === phone
  );
  if (dup) {
    showMsg('regError', 'Duplicate detected: same name, email, or phone exists');
    return;
  }

  const passHash = await hashPassword(pass);

  DB.students.push({
    name, email, phone, room,
    passHash, role,
    date: new Date().toLocaleString()
  });
  saveDB();
  showMsg('regSuccess', 'Registration successful. You can login now.');
  // clear form fields if present
  ['regName','regEmail','regPhone','regRoom','regPass','regPassConfirm'].forEach(id=>{
    const e = document.getElementById(id); if(e) e.value = '';
  });
}

// ----------------- Login (student or admin) -----------------
async function loginUser() {
  const name = (document.getElementById('loginName')||{}).value?.trim() || '';
  const pass = (document.getElementById('loginPass')||{}).value || '';
  const roleWanted = (document.getElementById('loginRole')||{}).value || 'student';
  const errEl = document.getElementById('loginError');

  if (!name || !pass) {
    showInlineMsgEl(errEl, 'Please enter both name and password');
    return;
  }

  const user = DB.students.find(s => s.name.toLowerCase() === name.toLowerCase());
  if (!user) {
    showInlineMsgEl(errEl, 'Account not found. Please register first.');
    return;
  }

  const hash = await hashPassword(pass);
  if (hash !== user.passHash) {
    showInlineMsgEl(errEl, 'Incorrect password');
    return;
  }

  if (user.role !== roleWanted) {
    showInlineMsgEl(errEl, 'Role mismatch. Choose correct role to login.');
    return;
  }

  setSession(user.name, user.role);

  // redirect based on role
  if (user.role === 'admin') window.location.href = 'admin.html';
  else window.location.href = 'my_leaves.html';
}

// ----------------- Logout -----------------
function logout() {
  clearSession();
  window.location.href = 'login.html';
}

// ----------------- Apply Leave (protected) -----------------
async function submitLeave() {
  const name = (document.getElementById('leaveName')||{}).value?.trim() || '';
  const pass = (document.getElementById('leavePass')||{}).value || '';
  const from = (document.getElementById('fromDate')||{}).value || '';
  const to = (document.getElementById('toDate')||{}).value || '';
  const reason = (document.getElementById('reason')||{}).value?.trim() || '';

  if (!name || !pass || !from || !to || !reason) {
    showMsg('leaveError', 'Please fill all fields');
    return;
  }
  if (new Date(to) < new Date(from)) {
    showMsg('leaveError', 'To date must be after From date');
    return;
  }

  const student = DB.students.find(s => s.name.toLowerCase()===name.toLowerCase() && s.role==='student');
  if (!student) { showMsg('leaveError', 'Student not found'); return; }
  const hash = await hashPassword(pass);
  if (hash !== student.passHash) { showMsg('leaveError', 'Incorrect password'); return; }

  // overlapping check
  const overlap = DB.leaves.some(l => l.name.toLowerCase()===name.toLowerCase() &&
    (new Date(from) <= new Date(l.to) && new Date(to) >= new Date(l.from)));
  if (overlap) { showMsg('leaveError','Overlapping leave exists'); return; }

  const leave = {
    id: DB.leaveId++,
    name: student.name,
    room: student.room,
    email: student.email,
    phone: student.phone,
    from, to, reason,
    status: 'pending',
    date: new Date().toLocaleString()
  };
  DB.leaves.push(leave);

  // notify all admins
  DB.students.filter(s=>s.role==='admin').forEach(admin=>{
    DB.notifications.push({
      id: DB.notifId++,
      toUser: admin.name,
      toRole: 'admin',
      message: `New leave #${leave.id} by ${leave.name}`,
      read: false,
      date: new Date().toLocaleString()
    });
  });

  saveDB();
  showMsg('leaveSuccess', `Leave submitted (ID ${leave.id})`);
  ['leavePass','fromDate','toDate','reason'].forEach(id=>{ const e=document.getElementById(id); if(e) e.value=''; });
  // optionally refresh admin view if on admin page
  if (typeof updateAdmin === 'function') updateAdmin();
}

// ----------------- Admin functions -----------------
function updateAdmin() {
  // populate stats and list (only if elements exist)
  const totalEl = document.getElementById('statTotal');
  if (!totalEl) return;
  totalEl.textContent = DB.leaves.length;
  document.getElementById('statPending').textContent = DB.leaves.filter(l=>l.status==='pending').length;
  document.getElementById('statApproved').textContent = DB.leaves.filter(l=>l.status==='approved').length;
  document.getElementById('statRejected').textContent = DB.leaves.filter(l=>l.status==='rejected').length;

  const list = document.getElementById('leaveList');
  if (!list) return;

  if (DB.leaves.length === 0) { list.innerHTML = '<div class="empty-state">No leave requests yet</div>'; return; }

  let html = '';
  DB.leaves.slice().reverse().forEach(leave => {
    html += `<div class="leave-item ${leave.status}">
      <div style="display:flex;justify-content:space-between;flex-wrap:wrap;">
        <div><h3>${escapeHtml(leave.name)}</h3><span class="status ${leave.status}">${leave.status.toUpperCase()}</span></div>
        <div>`;
    if (leave.status === 'pending') {
      html += `<button class="btn btn-small btn-approve" onclick="changeStatus(${leave.id},'approved')">Approve</button>
               <button class="btn btn-small btn-reject" onclick="changeStatus(${leave.id},'rejected')">Reject</button>`;
    }
    html += `<button class="btn btn-small btn-delete" onclick="deleteLeave(${leave.id})">Delete</button>
        </div>
      </div>
      <p><strong>ID:</strong> ${leave.id} | <strong>Room:</strong> ${escapeHtml(leave.room)}</p>
      <p><strong>Email:</strong> ${escapeHtml(leave.email)} | <strong>Phone:</strong> ${escapeHtml(leave.phone)}</p>
      <p><strong>Duration:</strong> ${escapeHtml(leave.from)} to ${escapeHtml(leave.to)}</p>
      <p><strong>Reason:</strong> ${escapeHtml(leave.reason)}</p>
    </div>`;
  });
  list.innerHTML = html;
}

function changeStatus(id, status) {
  const leave = DB.leaves.find(l => l.id === id);
  if (!leave) return;
  leave.status = status;
  DB.notifications.push({
    id: DB.notifId++,
    toUser: leave.name,
    toRole: 'student',
    message: `Your leave #${leave.id} has been ${status}`,
    read: false,
    date: new Date().toLocaleString()
  });
  saveDB();
  updateAdmin();
  showMsg('adminSuccess', `Request #${id} ${status}`);
}

function deleteLeave(id) {
  if (!confirm('Delete this request?')) return;
  DB.leaves = DB.leaves.filter(l => l.id !== id);
  saveDB();
  updateAdmin();
  showMsg('adminSuccess', 'Request deleted');
}

// ----------------- Students list & search -----------------
function updateStudentList() {
  const container = document.getElementById('studentList');
  if (!container) return;
  const filter = ((document.getElementById('studentSearch')||{}).value||'').trim().toLowerCase();

  let students = DB.students.slice();
  if (filter) {
    students = students.filter(s =>
      s.name.toLowerCase().includes(filter) ||
      s.email.toLowerCase().includes(filter) ||
      s.phone.includes(filter) ||
      (s.room||'').toLowerCase().includes(filter)
    );
  }

  if (students.length === 0) { container.innerHTML = '<div class="empty-state">No students found</div>'; return; }

  let html = '<table><tr><th>Name</th><th>Email</th><th>Phone</th><th>Room</th><th>Role</th><th>Registered</th></tr>';
  students.forEach(s => {
    html += `<tr>
      <td>${escapeHtml(s.name)}</td>
      <td>${escapeHtml(s.email)}</td>
      <td>${escapeHtml(s.phone)}</td>
      <td>${escapeHtml(s.room)}</td>
      <td>${escapeHtml(s.role)}</td>
      <td>${escapeHtml(s.date)}</td>
    </tr>`;
  });
  html += '</table>';
  container.innerHTML = html;
}

// ----------------- My leaves (student) -----------------
function searchMyLeaves() {
  const name = ((document.getElementById('searchName')||{}).value||'').trim();
  const container = document.getElementById('myLeavesList');
  if (!container) return;
  if (!name) { container.innerHTML = '<p style="text-align:center;color:#999">Enter your name</p>'; return; }

  const myLeaves = DB.leaves.filter(l => l.name.toLowerCase()===name.toLowerCase());
  if (myLeaves.length===0) { container.innerHTML = '<div class="empty-state">No leaves found</div>'; return; }

  let html = '';
  myLeaves.slice().reverse().forEach(leave => {
    html += `<div class="leave-item ${leave.status}">
      <h3>Request #${leave.id}</h3>
      <span class="status ${leave.status}">${leave.status.toUpperCase()}</span>
      <p><strong>Duration:</strong> ${escapeHtml(leave.from)} to ${escapeHtml(leave.to)}</p>
      <p><strong>Applied:</strong> ${escapeHtml(leave.date)}</p>
      <p><strong>Reason:</strong> ${escapeHtml(leave.reason)}</p>
    </div>`;
  });
  container.innerHTML = html;
}

// ----------------- Notifications -----------------
function getNotificationsFor(user, role) {
  return DB.notifications.filter(n => (n.toUser === user) || (n.toRole === role));
}
function markNotificationRead(id) {
  const n = DB.notifications.find(x => x.id === id);
  if (n) { n.read = true; saveDB(); }
}
function renderNotificationsList(containerId) {
  const sess = getSession();
  const container = document.getElementById(containerId);
  if (!container) return;
  const notes = getNotificationsFor(sess.user, sess.role) || [];
  if (notes.length===0) { container.innerHTML = '<div class="empty-state">No notifications</div>'; return; }
  let html = '';
  notes.slice().reverse().forEach(n => {
    html += `<div class="card" style="margin-bottom:8px;">
      <p style="margin:0;"><strong>${escapeHtml(n.message)}</strong></p>
      <p style="color:#777;margin:6px 0 0 0;font-size:0.9em">${escapeHtml(n.date)}</p>
      <div style="margin-top:8px;">
        ${n.read ? '<small style="color:green">Read</small>' : `<button class="btn btn-small" onclick="markNotificationRead(${n.id});renderNotificationsList('${containerId}');">Mark read</button>`}
      </div>
    </div>`;
  });
  container.innerHTML = html;
}

// ----------------- Profile -----------------
function renderProfile() {
  const sess = getSession();
  if (!sess.user) { window.location.href='login.html'; return; }
  const user = DB.students.find(s => s.name === sess.user);
  if (!user) { showMsg('profileMsg','User not found'); return; }
  const set = (id, v) => { const e=document.getElementById(id); if(e) e.value = v || ''; };
  set('profileName', user.name);
  set('profileEmail', user.email);
  set('profilePhone', user.phone);
  set('profileRoom', user.room);
  const roleEl = document.getElementById('profileRole'); if(roleEl) roleEl.textContent = user.role;
  const regEl = document.getElementById('profileRegistered'); if(regEl) regEl.textContent = user.date;
}
function updateProfile() {
  const sess = getSession();
  if (!sess.user) return;
  const user = DB.students.find(s => s.name === sess.user);
  if (!user) return showMsg('profileMsg','User not found');
  const email = (document.getElementById('profileEmail')||{}).value.trim();
  const phone = (document.getElementById('profilePhone')||{}).value.trim();
  const room = (document.getElementById('profileRoom')||{}).value.trim();
  const pass = (document.getElementById('profilePass')||{}).value || '';

  const otherDup = DB.students.find(s => s.name !== user.name && (s.email.toLowerCase() === email.toLowerCase() || s.phone === phone));
  if (otherDup) return showMsg('profileMsg','Email or phone used by another account');
  if (phone && !/^\d{10}$/.test(phone)) return showMsg('profileMsg','Phone must be 10 digits');

  if (pass) {
    if (!isStrongPassword(pass)) return showMsg('profileMsg','Password must be 8+ chars include upper,lower,num,special');
    hashPassword(pass).then(hash => {
      user.passHash = hash;
      user.email = email || user.email;
      user.phone = phone || user.phone;
      user.room = room || user.room;
      saveDB();
      showMsg('profileMsg','Profile updated');
      document.getElementById('profilePass').value = '';
    });
  } else {
    user.email = email || user.email;
    user.phone = phone || user.phone;
    user.room = room || user.room;
    saveDB();
    showMsg('profileMsg','Profile updated');
  }
}

// ----------------- Page protection helpers -----------------
function protectAdminPage() {
  const sess = getSession();
  if (!sess.user || sess.role !== 'admin') {
    alert('Admin login required');
    window.location.href = 'login.html';
    return false;
  }
  updateHeaderForSession();
  return true;
}
function protectStudentPage() {
  const sess = getSession();
  if (!sess.user || sess.role !== 'student') {
    alert('Student login required');
    window.location.href = 'login.html';
    return false;
  }
  updateHeaderForSession();
  return true;
}
function protectApplyLeavePage() {
  if (!protectStudentPage()) return;
  const user = getSession().user;
  const el = document.getElementById('leaveName'); if (el) el.value = user;
}
function protectMyLeavesPage() {
  if (!protectStudentPage()) return;
  const user = getSession().user;
  const el = document.getElementById('searchName'); if (el) el.value = user;
  renderNotificationsList('studentNotifs');
}
function protectStudentsPage() {
  protectAdminPage();
  renderNotificationsList('adminNotifs');
}

// ----------------- Header update / small UI helpers -----------------
function updateHeaderForSession() {
  const sess = getSession();
  const loginStatusElList = document.querySelectorAll('#loginStatus');
  loginStatusElList.forEach(loginStatusEl => {
    if (!loginStatusEl) return;
    if (sess.user) {
      loginStatusEl.innerHTML = `Hello, ${escapeHtml(sess.user)} (${escapeHtml(sess.role)}) <button class="btn btn-small" onclick="logout()">Logout</button> <a class="btn btn-small" href="profile.html">Profile</a>`;
    } else {
      loginStatusEl.innerHTML = `<a class="btn btn-small" href="login.html">Login</a> <a class="btn btn-small" href="register.html">Register</a>`;
    }
  });

  // update notif count if element present
  const notifCountElList = document.querySelectorAll('#notifCount');
  notifCountElList.forEach(notifCountEl => {
    const notes = getNotificationsFor(sess.user, sess.role);
    const unread = notes ? notes.filter(n=>!n.read).length : 0;
    notifCountEl.textContent = unread ? `(${unread})` : '';
  });
}

// ----------------- Index helper redirects used by index buttons -----------------
function goApplyLeave() {
  const sess = getSession();
  if (!sess.user || sess.role !== 'student') {
    alert('You must login as a Student to apply for leave.');
    window.location.href = 'login.html';
    return;
  }
  window.location.href = 'apply_leave.html';
}
function goMyLeaves() {
  const sess = getSession();
  if (!sess.user || sess.role !== 'student') {
    alert('You must login as a Student to view your leave history.');
    window.location.href = 'login.html';
    return;
  }
  window.location.href = 'my_leaves.html';
}
function goStudentList() {
  const sess = getSession();
  if (!sess.user || sess.role !== 'admin') {
    alert('Only Admins can view registered students.');
    window.location.href = 'login.html';
    return;
  }
  window.location.href = 'students.html';
}
function goAdminDashboard() {
  const sess = getSession();
  if (!sess.user || sess.role !== 'admin') {
    alert('Only Admins can access the Admin Dashboard.');
    window.location.href = 'login.html';
    return;
  }
  window.location.href = 'admin.html';
}

// ----------------- Init on DOM ready -----------------
document.addEventListener('DOMContentLoaded', function(){
  loadDB();
  updateHeaderForSession();
});

// Expose globally used by HTML
window.registerStudent = registerStudent;
window.loginUser = loginUser;
window.logout = logout;
window.submitLeave = submitLeave;
window.updateAdmin = updateAdmin;
window.changeStatus = changeStatus;
window.deleteLeave = deleteLeave;
window.updateStudentList = updateStudentList;
window.searchMyLeaves = searchMyLeaves;
window.renderNotificationsList = renderNotificationsList;
window.protectAdminPage = protectAdminPage;
window.protectStudentPage = protectStudentPage;
window.protectApplyLeavePage = protectApplyLeavePage;
window.protectMyLeavesPage = protectMyLeavesPage;
window.protectStudentsPage = protectStudentsPage;
window.renderProfile = renderProfile;
window.updateProfile = updateProfile;
window.hashPassword = hashPassword;
