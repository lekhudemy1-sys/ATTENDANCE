const sb = supabase.createClient(
  'https://mwluvdedgdshbdnmyjyl.supabase.co',
  'sb_publishable_pT4vjOCHqiiqZxZAcxHpjg_neX05R-M'
);

const $ = (id) => document.getElementById(id);

const esc = (v) =>
  String(v ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );

function msg(t, type = 'info') {
  const s = $('status');
  if (!s) return;
  s.style.display = 'block';
  s.className = 'status ' + type;
  s.innerHTML = t;
}

function setBusy(btn, busy) {
  if (!btn) return;
  btn.disabled = !!busy;
  if (busy) {
    btn.dataset._label = btn.textContent;
    btn.textContent = 'Please wait…';
  } else if (btn.dataset._label) {
    btn.textContent = btn.dataset._label;
    delete btn.dataset._label;
  }
}

// ---- brand mark: fills any <div data-brand> ----
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-brand]').forEach((el) => {
    el.className = 'brand';
    el.innerHTML =
      '<span class="mark"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">' +
      '<path d="M8 21 10.5 3M16 21 13.5 3"/><path d="M12 5v3M12 11v3M12 17v3" stroke="#e8590c" stroke-width="2.2"/></svg></span>' +
      '<span><b>Prithvi Realcon</b><small>Transport · PRTPL</small></span>';
  });
});

// ---- device id (one per browser; survives logout) ----
const DEVICE_KEY = 'dev_id';

function getDeviceId() {
  let id = localStorage.getItem(DEVICE_KEY);
  if (!id) {
    id =
      (window.crypto && crypto.randomUUID && crypto.randomUUID()) ||
      Date.now().toString(36) + '-' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    localStorage.setItem(DEVICE_KEY, id);
  }
  return id;
}

// ---- session (name + password auth) ----
const TOKEN_KEY = 'emp_token';
const NAME_KEY = 'emp_name';

function getToken() {
  return sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY) || '';
}

function getEmpName() {
  return sessionStorage.getItem(NAME_KEY) || localStorage.getItem(NAME_KEY) || '';
}

function saveSession(token, name) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(NAME_KEY, name);
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(NAME_KEY);
}

function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(NAME_KEY);
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(NAME_KEY);
}

async function need() {
  const token = getToken();
  if (!token) {
    location.href = 'index.html';
    return null;
  }
  return token;
}

async function logout() {
  const token = getToken();
  if (token) {
    try {
      await sb.rpc('emp_logout', { p_token: token });
    } catch (_) {}
  }
  clearSession();
  location.href = 'index.html';
}

const todayIST = () =>
  new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });

// ---- shared UI helpers ----
const pill = (s, label) =>
  '<span class="pill ' + esc(s) + '">' + esc(label || String(s).replace('_', ' ')) + '</span>';

const fmtDate = (d) =>
  new Date(d + 'T00:00:00').toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });

const fmtRange = (a, b) => fmtDate(a) + (b !== a ? ' → ' + fmtDate(b) : '');

const initials = (n) =>
  String(n || '?').trim().split(/\s+/).slice(0, 2).map((w) => w[0]).join('').toUpperCase();
