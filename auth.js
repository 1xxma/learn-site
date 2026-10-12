/* =========================================================
   auth.js — авторизация с хешированием паролей (PBKDF2)
   ========================================================= */

const AUTH_STORAGE_KEY = 'learn_users';
const SESSION_KEY = 'learn_session';

function bufToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function generateSalt() {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    return bufToHex(salt);
}

async function hashPassword(password, saltHex) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    const baseKey = await crypto.subtle.importKey(
        'raw', passwordBytes, 'PBKDF2', false, ['deriveBits']
    );

    const saltBytes = new Uint8Array(
        saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16))
    );

    const derivedBits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
        baseKey,
        256
    );

    return bufToHex(derivedBits);
}

function getUsers() {
    try { return JSON.parse(localStorage.getItem(AUTH_STORAGE_KEY)) || {}; }
    catch { return {}; }
}

function saveUsers(users) {
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(users));
}

async function register(name, email, password) {
    const users = getUsers();
    const emailKey = email.trim().toLowerCase();

    if (users[emailKey]) {
        return { ok: false, error: 'Пользователь с таким email уже существует' };
    }

    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    users[emailKey] = {
        name: name.trim(),
        email: emailKey,
        salt: salt,
        hash: hash,
        createdAt: Date.now()
    };
    saveUsers(users);
    setSession(emailKey);

    return { ok: true };
}

async function login(email, password) {
    const users = getUsers();
    const emailKey = email.trim().toLowerCase();

    const user = users[emailKey];
    if (!user) return { ok: false, error: 'Пользователь не найден' };

    const hash = await hashPassword(password, user.salt);
    if (hash !== user.hash) return { ok: false, error: 'Неверный пароль' };

    setSession(emailKey);
    return { ok: true };
}

function logout() {
    localStorage.removeItem(SESSION_KEY);
    window.location.href = 'index.html';
}

function setSession(emailKey) {
    localStorage.setItem(SESSION_KEY, JSON.stringify({
        email: emailKey,
        loginAt: Date.now()
    }));
}

function getCurrentUser() {
    try {
        const session = JSON.parse(localStorage.getItem(SESSION_KEY));
        if (!session || !session.email) return null;

        const users = getUsers();
        const user = users[session.email];
        if (!user) return null;

        return { name: user.name, email: user.email };
    } catch {
        return null;
    }
}
