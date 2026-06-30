/**
 * Secure Vault — Shared Auth & RBAC Helper
 * ------------------------------------------------------------------
 * Include on every page with:  <script src="auth.js"></script>
 *
 * Responsibilities:
 *   1. Shared API/auth helpers (authHeaders, logout) — single source
 *      of truth instead of each page defining its own copy.
 *   2. Decode the user's role directly from the JWT payload.
 *      NOTE: the backend has no /api/auth/me endpoint in this RBAC
 *      pass, so role detection happens client-side by decoding the
 *      "role" claim that JwtUtil.generateToken() embeds at login.
 *      This is read-only decoding (no signature verification needed
 *      here — every protected API call is still independently
 *      verified server-side by JwtFilter, so a tampered token simply
 *      fails there regardless of what this file shows on screen).
 *   3. Apply role-based visibility to any element marked
 *      data-role="ADMIN" (used for admin sidebar links).
 *   4. Populate the sidebar user chip (avatar, name, role label).
 */

const API = 'http://localhost:8080';

function getToken() {
  return localStorage.getItem('token');
}

function authHeaders() {
  return { 'Authorization': 'Bearer ' + getToken() };
}

function logout() {
  localStorage.clear();
  window.location.href = 'login.html';
}

/**
 * Decodes the JWT payload (the middle, base64url-encoded segment)
 * and returns it as an object, e.g. { sub: "admin", role: "ADMIN", ... }.
 * Returns null if there's no token or it isn't shaped like a JWT.
 */
function decodeToken(token) {
  if (!token || token.split('.').length !== 3) return null;
  try {
    const payload = token.split('.')[1];
    // base64url -> base64
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('')
    );
    return JSON.parse(json);
  } catch (e) {
    console.error('Failed to decode token:', e);
    return null;
  }
}

function getRole() {
  const decoded = decodeToken(getToken());
  return decoded?.role || 'USER';
}

function getUsername() {
  const decoded = decodeToken(getToken());
  return decoded?.sub || localStorage.getItem('username') || 'User';
}

function isAdmin() {
  return getRole() === 'ADMIN';
}

/**
 * Call once on every protected page load:
 *
 *   const me = initAuth();
 *   if (me) { ...page-specific loading code... }
 *
 * Returns { username, role } or null (and redirects to login.html)
 * if there's no usable token.
 *
 * Pages that are admin-only should call initAuth(true) — a non-admin
 * landing there (stale bookmark, manual URL entry) gets bounced to
 * dashboard.html instead of seeing a page with no data / a 403 storm.
 */
function initAuth(requireAdmin = false) {
  const token = getToken();
  const decoded = decodeToken(token);

  if (!decoded) {
    window.location.href = 'login.html';
    return null;
  }

  const role = decoded.role || 'USER';
  const username = decoded.sub || 'User';

  // Cache for convenience / other pages that read localStorage directly.
  localStorage.setItem('username', username);
  localStorage.setItem('role', role);

  if (requireAdmin && role !== 'ADMIN') {
    window.location.href = 'dashboard.html';
    return null;
  }

  applyRoleVisibility(role);
  populateSidebarUser(username, role);

  return { username, role };
}

// Hides any element with data-role="ADMIN" unless the user is an admin.
function applyRoleVisibility(role) {
  document.querySelectorAll('[data-role="ADMIN"]').forEach(el => {
    el.style.display = (role === 'ADMIN') ? '' : 'none';
  });
}

function populateSidebarUser(username, role) {
  const nameEl   = document.getElementById('sidebarUser');
  const avatarEl = document.getElementById('sidebarAvatar');
  const roleEl   = document.getElementById('sidebarRole');

  if (nameEl)   nameEl.textContent = username;
  if (avatarEl) avatarEl.textContent = username[0].toUpperCase();
  if (roleEl)   roleEl.textContent = role === 'ADMIN' ? 'Administrator' : 'Vault User';
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}