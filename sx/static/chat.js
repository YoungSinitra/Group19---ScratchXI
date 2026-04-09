/**
 * chat.js — Real-Time Campus Chat + Moderation
 * =============================================
 * Features:
 *   - Daily message limit for students & staff
 *   - Profanity filtering (server-side)
 *   - Per-message cooldown (server-side)
 *   - Mute / unmute (admin + security)
 *   - Chat lockdown (admin + security)
 *   - Message deletion (admin + security)
 *   - Live moderation panel (admin + security only)
 */

const CURRENT_USER = document.getElementById('current-user-name')?.dataset.name || 'Unknown';
const CURRENT_ROLE = document.getElementById('current-user-name')?.dataset.role || 'student';
const CURRENT_UID  = parseInt(document.getElementById('current-user-name')?.dataset.uid || '0');
const CHAT_LIMIT   = parseInt(document.getElementById('chat-limit-data')?.dataset.limit || '20');
const IS_MOD       = ['admin', 'security'].includes(CURRENT_ROLE);

let localCountToday = parseInt(document.getElementById('chat-limit-data')?.dataset.today || '0');
let isMutedLocally  = false;   // flipped by server events
let isLockedLocally = document.getElementById('chat-lock-state')?.dataset.locked === '1';

const chatSocket = io();

// ── Connection ────────────────────────────────────────────────
chatSocket.on('connect', () => {
    chatSocket.emit('join_room_event', { room: 'main_chat' });
    appendSystemMessage('Connected to campus chat.');
    updateLockUI();
});

chatSocket.on('disconnect', () => {
    appendSystemMessage('Disconnected. Reconnecting…');
});

chatSocket.on('system_msg', d => appendSystemMessage(d.text));


// ── Incoming messages ──────────────────────────────────────────
chatSocket.on('receive_message', function (data) {
    if (data.room && data.room !== 'main_chat') return;
    appendMessage(data);
    scrollToBottom();
    if (data.sender_name === CURRENT_USER && !IS_MOD) {
        localCountToday++;
        updateLimitDisplay();
    }
});


// ── Server errors (limit, profanity, cooldown, mute, lock) ────
chatSocket.on('chat_error', function (data) {
    appendSystemMessage('⚠️ ' + data.message);
    scrollToBottom();
});


// ── Message deleted ────────────────────────────────────────────
chatSocket.on('message_deleted', function (data) {
    const el = document.querySelector(`.chat-msg[data-id="${data.message_id}"]`);
    if (el) {
        el.style.transition = 'opacity 0.3s';
        el.style.opacity = '0';
        setTimeout(() => el.remove(), 300);
    }
});


// ── Emergency broadcast ────────────────────────────────────────
chatSocket.on('emergency_broadcast', function (data) {
    appendSystemMessage('🚨 EMERGENCY BROADCAST: ' + data.message);
    scrollToBottom();
});


// ════════════════════════════════════════════════════════════
//  MODERATION EVENTS (received by all clients)
// ════════════════════════════════════════════════════════════

// You personally were muted
chatSocket.on('you_are_muted', function (data) {
    isMutedLocally = true;
    updateInputState();
    appendSystemMessage('🔇 ' + data.message);
    scrollToBottom();
});

// You personally were unmuted
chatSocket.on('you_are_unmuted', function (data) {
    isMutedLocally = false;
    updateInputState();
    appendSystemMessage('🔊 ' + data.message);
    scrollToBottom();
});

// Entire chat locked
chatSocket.on('chat_lockdown', function (data) {
    isLockedLocally = true;
    updateInputState();
    updateLockUI();
    appendSystemMessage(data.message);
    scrollToBottom();
});

// Chat unlocked
chatSocket.on('chat_unlocked', function (data) {
    isLockedLocally = false;
    updateInputState();
    updateLockUI();
    appendSystemMessage(data.message);
    scrollToBottom();
});

// Moderator panel: someone was muted — update button state
chatSocket.on('user_muted', function (data) {
    const btn = document.querySelector(`[data-mod-uid="${data.user_id}"]`);
    if (btn) {
        btn.textContent = 'Unmute';
        btn.classList.replace('mod-mute-btn', 'mod-unmute-btn');
        btn.dataset.muted = '1';
    }
    const row = document.querySelector(`[data-mod-row="${data.user_id}"]`);
    if (row) row.classList.add('mod-row-muted');
});

// Moderator panel: someone was unmuted
chatSocket.on('user_unmuted', function (data) {
    const btn = document.querySelector(`[data-mod-uid="${data.user_id}"]`);
    if (btn) {
        btn.textContent = 'Mute';
        btn.classList.replace('mod-unmute-btn', 'mod-mute-btn');
        btn.dataset.muted = '0';
    }
    const row = document.querySelector(`[data-mod-row="${data.user_id}"]`);
    if (row) row.classList.remove('mod-row-muted');
});

// Moderator panel: someone was banned (permanent)
chatSocket.on('user_muted', function (data) {
    const banBtn = document.querySelector(`[data-ban-uid="${data.user_id}"]`);
    if (banBtn && banBtn.dataset.banned === '1') {
        // Already handled above; if it's a permanent ban update the ban btn
        banBtn.textContent = 'Unban';
        banBtn.classList.replace('mod-ban-btn', 'mod-unban-btn');
        banBtn.dataset.banned = '1';
        const badge = document.querySelector(`[data-ban-uid="${data.user_id}"]`)
            ?.closest('.mod-user-row')?.querySelector('.mod-muted-badge');
    }
});


// ════════════════════════════════════════════════════════════
//  SEND
// ════════════════════════════════════════════════════════════

function sendMessage() {
    const input   = document.getElementById('chat-input');
    const message = input ? input.value.trim() : '';
    if (!message) return;

    if (!IS_MOD) {
        if (isMutedLocally) {
            appendSystemMessage('⚠️ You are muted and cannot send messages.');
            return;
        }
        if (isLockedLocally) {
            appendSystemMessage('⚠️ Chat is locked. Only security personnel can send messages.');
            return;
        }
        if (localCountToday >= CHAT_LIMIT) {
            appendSystemMessage('⚠️ Daily message limit reached. Resets at midnight.');
            return;
        }
    }

    chatSocket.emit('send_message', {
        message,
        sender_name: CURRENT_USER,
        sender_role: CURRENT_ROLE,
        room: 'main_chat',
    });

    input.value = '';
    input.focus();
}


// ════════════════════════════════════════════════════════════
//  MODERATION ACTIONS (called from panel buttons)
// ════════════════════════════════════════════════════════════

function toggleMute(uid, currentlyMuted) {
    if (currentlyMuted) {
        chatSocket.emit('unmute_user', { user_id: uid });
    } else {
        chatSocket.emit('mute_user', { user_id: uid });
    }
}

async function toggleBan(uid, currentlyBanned, btn) {
    const route = currentlyBanned ? `/chat/unban/${uid}` : `/chat/ban/${uid}`;
    const label = currentlyBanned ? 'Unban' : 'Ban';
    if (!currentlyBanned && !confirm(`Permanently ban this user from chat? This persists until lifted.`)) return;
    btn.disabled = true;
    btn.textContent = '...';
    try {
        const res  = await fetch(route, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        const data = await res.json();
        if (!data.success) { alert(data.error || 'Action failed.'); }
    } catch { alert('Network error.'); }
    btn.disabled = false;
}

function toggleChatLock() {
    if (isLockedLocally) {
        chatSocket.emit('unlock_chat');
    } else {
        chatSocket.emit('lockdown_chat');
    }
}

// HTTP-based delete (existing route, also emits socket event server-side)
async function deleteMessage(messageId) {
    if (!confirm('Remove this message from the chat?')) return;
    try {
        const res  = await fetch('/delete_message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message_id: messageId, reason: 'Moderation' }),
        });
        const data = await res.json();
        if (!data.success) alert('Could not remove message.');
    } catch {
        alert('Network error — could not remove message.');
    }
}


// ════════════════════════════════════════════════════════════
//  UI HELPERS
// ════════════════════════════════════════════════════════════

function updateInputState() {
    if (IS_MOD) return;   // moderators always have input access
    const input  = document.getElementById('chat-input');
    const button = document.querySelector('.chat-input-bar .btn');
    const blocked = isMutedLocally || (isLockedLocally && !IS_MOD);
    if (input)  input.disabled  = blocked || (localCountToday >= CHAT_LIMIT);
    if (button) button.disabled = blocked || (localCountToday >= CHAT_LIMIT);
}

function updateLockUI() {
    const btn = document.getElementById('chat-lock-btn');
    if (!btn) return;
    if (isLockedLocally) {
        btn.textContent = '🔓 Unlock Chat';
        btn.classList.add('mod-locked-active');
    } else {
        btn.textContent = '🔒 Lock Chat';
        btn.classList.remove('mod-locked-active');
    }
}

function appendMessage(data) {
    const chatBox = document.getElementById('chat-box');
    if (!chatBox) return;

    const isOwn      = data.sender_name === CURRENT_USER;
    const isSecurity = ['security', 'admin'].includes(data.sender_role);
    const isStaff    = data.sender_role === 'staff';
    const roleIcon   = isSecurity ? '🛡️ Security' : isStaff ? '🏫 Staff' : '🎓 Student';

    const div = document.createElement('div');
    div.className = 'chat-msg' +
        (isOwn      ? ' own'      : ' other') +
        (isSecurity ? ' security' : '');
    div.dataset.id = data.id || '';

    div.innerHTML =
        `<div class="chat-meta">` +
            `${roleIcon} — ${escapeHTML(data.sender_name)} · ${data.timestamp || 'now'}` +
            (CURRENT_ROLE === 'admin' && data.id
                ? ` <button onclick="deleteMessage(${data.id})"
                     style="margin-left:.5rem;font-size:.7rem;color:var(--brand);
                            cursor:pointer;border:none;background:none;padding:0;">Remove</button>`
                : '') +
        `</div>` +
        `<div class="chat-bubble">${escapeHTML(data.message)}</div>`;

    chatBox.appendChild(div);
}

function updateLimitDisplay() {
    const counter = document.getElementById('limit-count');
    if (counter) counter.textContent = localCountToday;
    if (localCountToday >= CHAT_LIMIT && !IS_MOD) {
        const input  = document.getElementById('chat-input');
        const button = document.querySelector('.chat-input-bar .btn');
        if (input)  input.disabled  = true;
        if (button) button.disabled = true;
        const banner = document.getElementById('limit-banner');
        if (banner) {
            banner.innerHTML =
                `⚠️ You have used all <strong>${CHAT_LIMIT} messages</strong> for today. ` +
                `Your limit resets at midnight.`;
        }
    }
}

function appendSystemMessage(text) {
    const chatBox = document.getElementById('chat-box');
    if (!chatBox) return;
    const div = document.createElement('div');
    div.className = 'chat-system';
    div.textContent = text;
    chatBox.appendChild(div);
}

function scrollToBottom() {
    const chatBox = document.getElementById('chat-box');
    if (chatBox) chatBox.scrollTop = chatBox.scrollHeight;
}

function escapeHTML(str) {
    const d = document.createElement('div');
    d.textContent = str || '';
    return d.innerHTML;
}


// ── Init ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('chat-input');
    if (input) {
        input.addEventListener('keydown', e => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }
    scrollToBottom();
    updateLockUI();
    updateInputState();

    // Clear-button for input
    if (input && !input.closest('.input-wrap')) {
        const wrap = document.createElement('div');
        wrap.className = 'input-wrap';
        wrap.style.flex = '1';
        input.parentNode.insertBefore(wrap, input);
        wrap.appendChild(input);
        const btn = document.createElement('button');
        btn.type = 'button'; btn.className = 'input-clear'; btn.title = 'Clear'; btn.textContent = '✕';
        wrap.appendChild(btn);
        input.addEventListener('input', () => btn.classList.toggle('visible', input.value.length > 0));
        btn.addEventListener('click', () => { input.value = ''; input.focus(); btn.classList.remove('visible'); });
    }
});
