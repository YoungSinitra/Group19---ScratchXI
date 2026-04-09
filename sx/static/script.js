/**
 * script.js — Dashboard & Admin Real-Time Logic
 * ================================================
 * Powers live alert feed, status updates, deletions,
 * emergency broadcasts, and admin controls.
 *
 * SocketIO flow:
 *   1. Page loads → connect to Flask-SocketIO
 *   2. Server emits events → JS listeners update the page
 *   3. Admin clicks → JS calls API or emits events to server
 *   4. No page refresh needed — everything is live!
 */

const socket = io();

socket.on('connect',    () => console.log('✅ Connected — real-time active'));
socket.on('disconnect', () => console.log('❌ Disconnected'));


// ── Receive New Alert ────────────────────────────────────────
// Fires on ALL connected users' screens when security pushes a new alert
socket.on('receive_alert', function (data) {
    const alertList = document.getElementById('alert-list');
    if (!alertList) return;

    const empty = document.getElementById('no-alerts');
    if (empty) empty.remove();

    const sev = data.severity || 'medium';
    const imageHTML = data.image_filename
        ? `<img src="/static/uploads/${escapeHTML(data.image_filename)}"
               alt="Incident" style="max-width:200px;border-radius:6px;margin-top:0.5rem;">`
        : '';

    const item = document.createElement('div');
    item.className = 'alert-item new-alert';
    item.id = 'alert-' + data.id;
    item.innerHTML =
        `<div class="alert-stripe sev-${sev}"></div>` +
        `<div class="alert-content">` +
            `<div class="alert-title">${escapeHTML(data.incident_type)} ` +
                `<span class="sev-label sev-${sev}">${sev}</span></div>` +
            `<div class="alert-desc">${escapeHTML(data.description)}</div>` +
            imageHTML +
            `<div class="alert-meta">` +
                `<span class="meta-tag">🏛️ ${escapeHTML(data.campus || 'Unknown')}</span>` +
                `<span class="meta-tag">📍 ${escapeHTML(data.location || '')}</span>` +
                `<span class="meta-tag">🕐 Just now</span>` +
            `</div>` +
        `</div>` +
        `<div class="alert-right">` +
            `<span class="status-badge status-active" id="status-${data.id}">Active</span>` +
        `</div>`;

    alertList.insertBefore(item, alertList.firstChild);
    showToast('🚨 New alert: ' + data.incident_type + ' at ' + (data.campus || data.location), 'error');
});


// ── Alert Status Updated ─────────────────────────────────────
socket.on('alert_status_update', function (data) {
    // Update badge on dashboard feed
    const badge = document.getElementById('status-' + data.alert_id);
    if (badge) {
        badge.className = 'status-badge status-' + data.new_status;
        badge.textContent = capitalise(data.new_status);
        badge.style.transform = 'scale(1.15)';
        setTimeout(() => badge.style.transform = 'scale(1)', 200);
    }
    // Update badge in admin table
    const tableBadge = document.getElementById('badge-' + data.alert_id);
    if (tableBadge) {
        tableBadge.className = 'status-badge status-' + data.new_status;
        tableBadge.textContent = capitalise(data.new_status);
    }
    showToast('Status → ' + capitalise(data.new_status), 'success');
});


// ── Alert Deleted ────────────────────────────────────────────
socket.on('alert_deleted', function (data) {
    // Remove from dashboard feed
    const card = document.getElementById('alert-' + data.alert_id);
    if (card) {
        card.style.transition = 'opacity 0.3s,transform 0.3s';
        card.style.opacity = '0';
        card.style.transform = 'translateX(-16px)';
        setTimeout(() => card.remove(), 300);
    }
    // Remove from admin table
    const row = document.getElementById('row-' + data.alert_id);
    if (row) {
        row.style.transition = 'opacity 0.3s';
        row.style.opacity = '0';
        setTimeout(() => row.remove(), 300);
    }
});


// ── Emergency Broadcast ──────────────────────────────────────
socket.on('emergency_broadcast', function (data) {
    // Sticky banner at top of page
    const banner = document.getElementById('emergency-banner');
    if (banner) {
        banner.textContent = '🚨 SECURITY BROADCAST: ' + data.message + '  —  ' + data.timestamp;
        banner.style.display = 'block';
        playAlertSound();
    }

    // Append to broadcast log on page
    const log = document.getElementById('broadcast-log');
    if (log) {
        const empty = document.getElementById('no-broadcasts');
        if (empty) empty.remove();

        const entry = document.createElement('div');
        entry.className = 'alert-item new-alert';
        entry.innerHTML =
            '<div class="alert-stripe" style="background:var(--brand);"></div>' +
            '<div class="alert-content">' +
                '<div class="alert-title">' + escapeHTML(data.message) + '</div>' +
                '<div class="alert-meta">' +
                    '<span class="meta-tag">📢 ' + escapeHTML(data.sender) + '</span>' +
                    '<span class="meta-tag">🕐 ' + escapeHTML(data.timestamp) + '</span>' +
                '</div>' +
            '</div>' +
            '<div class="alert-right">' +
                '<span class="status-badge" style="background:var(--brand-light);color:var(--brand);">Broadcast</span>' +
            '</div>';
        log.insertBefore(entry, log.firstChild);
    }

    showToast('📢 Emergency Broadcast: ' + data.message, 'info', 8000);
});


// ── Send Emergency Broadcast (admin only) ────────────────────
function sendBroadcast() {
    const input = document.getElementById('broadcast-input');
    const message = input ? input.value.trim() : '';
    if (!message) { showToast('Enter a broadcast message first.', 'error'); return; }

    socket.emit('broadcast_alert', { message });
    input.value = '';
    showToast('Broadcast sent to all users!', 'success');
}


// ── Update Alert Status (admin table buttons) ────────────────
async function updateAlertStatus(alertId, newStatus) {
    try {
        const res  = await fetch('/admin/update_status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert_id: alertId, status: newStatus })
        });
        const data = await res.json();
        if (!data.success) showToast('Failed to update.', 'error');
    } catch {
        showToast('Network error.', 'error');
    }
}


// ── Delete Alert (admin table) ───────────────────────────────
async function deleteAlert(alertId) {
    if (!confirm('Remove this alert? This cannot be undone.')) return;
    try {
        const res  = await fetch('/admin/delete_alert', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert_id: alertId })
        });
        const data = await res.json();
        if (data.success) showToast('Alert removed.', 'success');
        else showToast('Failed to remove.', 'error');
    } catch {
        showToast('Network error.', 'error');
    }
}


// ── Toast Notifications ──────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText =
            'position:fixed;bottom:1.5rem;right:1.5rem;' +
            'display:flex;flex-direction:column;gap:0.5rem;' +
            'z-index:9999;max-width:300px;';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.style.cssText =
        'background:#fff;border:1px solid #DDD4D4;border-radius:8px;' +
        'padding:0.7rem 1rem;font-size:0.81rem;color:#121212;' +
        'font-family:"Plus Jakarta Sans",sans-serif;' +
        'box-shadow:0 4px 16px rgba(18,18,18,0.10);cursor:pointer;line-height:1.5;';
    toast.textContent = message;
    toast.onclick = () => toast.remove();
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.transition = 'opacity 0.2s';
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 200);
    }, duration);
}


// ── Utilities ────────────────────────────────────────────────
function escapeHTML(str) {
    const d = document.createElement('div');
    d.textContent = str || '';
    return d.innerHTML;
}

function capitalise(str) {
    return str ? str.charAt(0).toUpperCase() + str.slice(1) : '';
}

function playAlertSound() {
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        osc.type = 'square';
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.setValueAtTime(660, ctx.currentTime + 0.15);
        osc.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + 0.3);
    } catch (e) {}
}


// ── Input Clear (X) Button ────────────────────────────────────────────────────
// Wraps all text/search inputs and adds an X button that clears the field
(function initClearButtons() {
  function attachClear(input) {
    // Skip if already wrapped or is a password/file/checkbox input
    if (input.type === 'password' || input.type === 'file' || input.type === 'checkbox') return;
    if (input.closest('.input-wrap') || input.closest('.pw-wrap')) return;

    const wrap = document.createElement('div');
    wrap.className = 'input-wrap';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'input-clear';
    btn.title = 'Clear';
    btn.textContent = '✕';
    wrap.appendChild(btn);

    function updateVisibility() {
      btn.classList.toggle('visible', input.value.length > 0);
    }

    input.addEventListener('input', updateVisibility);
    btn.addEventListener('click', function() {
      input.value = '';
      input.focus();
      input.dispatchEvent(new Event('input', { bubbles: true }));
      updateVisibility();
    });

    updateVisibility();
  }

  function initAll() {
    document.querySelectorAll('input[type="text"], input[type="email"], input[type="search"], textarea')
      .forEach(attachClear);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAll);
  } else {
    initAll();
  }
})();
