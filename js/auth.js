/* =========================================================
  auth.js — "나만의 자리"를 패스키로 여는 브라우저 쪽 코드
  - 비밀번호 입력은 어디에도 없습니다.
  - 서버가 준 일회용 질문(challenge)에 기기가 서명하고, 그 답만 서버로 보냅니다.
    개인키는 기기 밖으로 나가지 않아서, 이 파일에도 서버로 보내는 코드에도 개인키가 등장하지 않습니다.
  - 서버 주소는 같은 출처의 /api/* 입니다. (vercel.json이 Supabase Edge Function으로 이어 줍니다)
  - 비공개 항목의 내용은 로그인한 뒤 /api/private/notes 응답으로만 받아서 textContent로 그립니다.
============================================================ */
(() => {
  const $ = (id) => document.getElementById(id);
  const el = {
    locked: $('vaultLocked'), open: $('vaultOpen'), msg: $('vaultMessage'),
    loginBtn: $('loginBtn'), registerForm: $('registerForm'), registerBtn: $('registerBtn'),
    handle: $('handleInput'), firstName: $('firstPasskeyName'),
    who: $('vaultWho'), logoutBtn: $('logoutBtn'), notes: $('vaultNotes'),
    table: $('passkeyTable'), addForm: $('addPasskeyForm'), addBtn: $('addPasskeyBtn'), newName: $('newPasskeyName'),
  };
  if (!el.locked) return;

  // ---------- base64url <-> ArrayBuffer ----------
  const toBuf = (s) => {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  };
  const toB64u = (buf) => {
    let s = '';
    new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  // ---------- 화면 메시지 ----------
  function say(text, kind) {
    el.msg.textContent = text || '';
    el.msg.classList.toggle('is-error', kind === 'error');
    el.msg.classList.toggle('is-ok', kind === 'ok');
  }
  function busy(on) {
    [el.loginBtn, el.registerBtn, el.addBtn, el.logoutBtn].forEach((b) => { if (b) b.disabled = on; });
  }

  // ---------- 서버 호출 ----------
  async function api(method, path, body) {
    const res = await fetch('/api' + path, {
      method,
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
    let data = null;
    try { data = await res.json(); } catch { /* 본문 없음 */ }
    if (!res.ok) {
      const err = new Error((data && data.message) || `요청이 실패했습니다 (${res.status})`);
      err.status = res.status;
      err.code = data && data.error;
      throw err;
    }
    return data;
  }

  // ---------- 지원 여부 ----------
  function supportProblem() {
    if (!window.isSecureContext) return '패스키는 https 주소(개발 중에는 localhost)에서만 동작합니다.';
    if (!window.PublicKeyCredential || !navigator.credentials) return '이 브라우저는 패스키를 지원하지 않습니다. 최신 Chrome·Safari·Edge·Firefox를 사용해 보세요.';
    return '';
  }

  // ---------- WebAuthn 옵션/응답 변환 ----------
  const creationOptions = (o) => ({
    challenge: toBuf(o.challenge),
    rp: o.rp,
    user: { id: toBuf(o.user.id), name: o.user.name, displayName: o.user.displayName },
    pubKeyCredParams: o.pubKeyCredParams,
    timeout: o.timeout,
    attestation: o.attestation,
    authenticatorSelection: o.authenticatorSelection,
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: toBuf(c.id) })),
  });
  const requestOptions = (o) => ({
    challenge: toBuf(o.challenge),
    rpId: o.rpId,
    timeout: o.timeout,
    userVerification: o.userVerification,
    allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: toBuf(c.id) })),
  });
  const attestationJSON = (c) => ({
    id: c.id, rawId: toB64u(c.rawId), type: c.type,
    authenticatorAttachment: c.authenticatorAttachment || undefined,
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
    response: {
      clientDataJSON: toB64u(c.response.clientDataJSON),
      attestationObject: toB64u(c.response.attestationObject),
      transports: c.response.getTransports ? c.response.getTransports() : [],
    },
  });
  const assertionJSON = (c) => ({
    id: c.id, rawId: toB64u(c.rawId), type: c.type,
    authenticatorAttachment: c.authenticatorAttachment || undefined,
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
    response: {
      clientDataJSON: toB64u(c.response.clientDataJSON),
      authenticatorData: toB64u(c.response.authenticatorData),
      signature: toB64u(c.response.signature),
      userHandle: c.response.userHandle ? toB64u(c.response.userHandle) : undefined,
    },
  });

  // 사용자가 창을 닫거나 취소하면 NotAllowedError가 옵니다.
  const cancelled = (e) => e && (e.name === 'NotAllowedError' || e.name === 'AbortError');

  // ---------- 화면 그리기 (모든 값은 textContent로만 넣습니다) ----------
  function h(tag, props, ...kids) {
    const n = document.createElement(tag);
    Object.entries(props || {}).forEach(([k, v]) => {
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else n.setAttribute(k, v);
    });
    kids.forEach((k) => n.append(k));
    return n;
  }
  const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString('ko-KR', { year: 'numeric', month: 'long', day: 'numeric' }) : '아직 없음');
  const fmtDateTime = (iso) => (iso ? new Date(iso).toLocaleString('ko-KR') : '아직 없음');

  function showLocked(note) {
    el.open.hidden = true;
    el.locked.hidden = false;
    el.notes.replaceChildren();
    el.table.querySelector('tbody').replaceChildren();
    el.who.textContent = '';
    if (note) say(note);
  }

  async function showOpen(account) {
    el.who.textContent = account.handle;
    el.locked.hidden = true;
    el.open.hidden = false;
    await Promise.all([renderNotes(), renderPasskeys()]);
  }

  async function renderNotes() {
    const data = await api('GET', '/private/notes');
    el.notes.replaceChildren(...data.notes.map((n) =>
      h('article', { class: 'vault-note-card' },
        h('p', { class: 'vault-note-kind', text: n.kind }),
        h('h4', { text: n.title }),
        h('p', { text: n.body }))));
  }

  async function renderPasskeys() {
    const data = await api('GET', '/passkeys');
    const tbody = el.table.querySelector('tbody');
    tbody.replaceChildren(...data.passkeys.map((p) => {
      const del = h('button', { type: 'button', class: 'btn-danger', text: '삭제', 'aria-label': `${p.name} 패스키 삭제` });
      del.addEventListener('click', () => deletePasskey(p));
      const nameCell = h('td', { text: p.name });
      if (p.id === data.currentPasskeyId) nameCell.append(h('span', { class: 'vault-current', text: '지금 로그인에 사용' }));
      return h('tr', { 'data-passkey-id': p.id },
        nameCell,
        h('td', { text: fmtDate(p.createdAt) }),
        h('td', { text: p.storedIn }),
        h('td', { text: fmtDateTime(p.lastUsedAt) }),
        h('td', {}, del));
    }));
  }

  // ---------- 등록 ----------
  async function register(ev) {
    ev.preventDefault();
    const problem = supportProblem();
    if (problem) return say(problem, 'error');
    const handle = el.handle.value.trim().toLowerCase();
    busy(true);
    say('서버에서 등록용 질문을 받는 중…');
    let challenge = null;
    try {
      const opts = await api('POST', '/register/options', { handle, passkeyName: el.firstName.value.trim() });
      challenge = opts.challenge;
      say('기기의 패스키 창에서 확인해 주세요…');
      const cred = await navigator.credentials.create({ publicKey: creationOptions(opts) });
      say('공개키를 서버에 보내는 중…');
      const out = await api('POST', '/register/verify', { response: attestationJSON(cred) });
      say(`등록 완료. 서버에는 공개키만 저장됐습니다.`, 'ok');
      await showOpen(out.account);
    } catch (e) {
      if (cancelled(e)) {
        if (challenge) { try { await api('POST', '/register/cancel', { challenge }); } catch { /* 질문은 5분 뒤 어차피 만료 */ } }
        say('등록을 취소했습니다. 서버에는 계정도 패스키도 저장되지 않았습니다.');
      } else if (e.name === 'InvalidStateError') {
        say('이 기기에는 이미 이 계정의 패스키가 등록되어 있습니다.', 'error');
      } else {
        say(e.message, 'error');
      }
    } finally {
      busy(false);
    }
  }

  // ---------- 로그인 ----------
  async function login() {
    const problem = supportProblem();
    if (problem) return say(problem, 'error');
    busy(true);
    say('서버에서 새 질문을 받는 중…');
    try {
      const opts = await api('POST', '/login/options', {});
      say('기기의 패스키 창에서 확인해 주세요…');
      const cred = await navigator.credentials.get({ publicKey: requestOptions(opts) });
      say('서명을 서버로 보내 확인하는 중…');
      const out = await api('POST', '/login/verify', { response: assertionJSON(cred) });
      say('들어왔습니다.', 'ok');
      await showOpen(out.account);
    } catch (e) {
      if (cancelled(e)) say('로그인을 취소했습니다.');
      else say(e.message, 'error');
    } finally {
      busy(false);
    }
  }

  // ---------- 로그아웃 ----------
  async function logout() {
    busy(true);
    try {
      await api('POST', '/logout', {});
      showLocked('로그아웃했습니다. 서버의 세션이 지워졌습니다.');
    } catch (e) {
      say(e.message, 'error');
    } finally {
      busy(false);
    }
  }

  // ---------- 패스키 추가/삭제 ----------
  async function addPasskey(ev) {
    ev.preventDefault();
    const problem = supportProblem();
    if (problem) return say(problem, 'error');
    busy(true);
    say('서버에서 등록용 질문을 받는 중…');
    let challenge = null;
    try {
      const opts = await api('POST', '/passkeys/options', { passkeyName: el.newName.value.trim() });
      challenge = opts.challenge;
      say('기기의 패스키 창에서 확인해 주세요…');
      const cred = await navigator.credentials.create({ publicKey: creationOptions(opts) });
      await api('POST', '/passkeys/verify', { response: attestationJSON(cred) });
      el.newName.value = '';
      say('패스키를 추가했습니다.', 'ok');
      await renderPasskeys();
    } catch (e) {
      if (cancelled(e)) {
        if (challenge) { try { await api('POST', '/register/cancel', { challenge }); } catch { /* 무시 */ } }
        say('추가를 취소했습니다. 서버에는 아무것도 저장되지 않았습니다.');
      } else if (e.name === 'InvalidStateError') {
        say('이 기기(또는 이 패스키 관리자)에는 이미 등록된 패스키가 있습니다. 다른 기기나 다른 브라우저에서 등록해 보세요.', 'error');
      } else if (e.status === 401) {
        showLocked('세션이 끝났습니다. 다시 들어가 주세요.');
      } else {
        say(e.message, 'error');
      }
    } finally {
      busy(false);
    }
  }

  async function deletePasskey(p) {
    if (!window.confirm(`'${p.name}' 패스키를 지울까요?`)) return;
    busy(true);
    try {
      const out = await api('DELETE', '/passkeys/' + encodeURIComponent(p.id));
      if (out.endedCurrentSession) {
        showLocked('지운 패스키로 열어 둔 로그인은 끝났습니다. 남은 패스키로 다시 들어가 주세요.');
      } else {
        say(`삭제했습니다. 남은 패스키는 ${out.remaining}개입니다.`, 'ok');
        await renderPasskeys();
      }
    } catch (e) {
      if (e.status === 401) showLocked('세션이 끝났습니다. 다시 들어가 주세요.');
      else say(e.message, 'error'); // 마지막 하나를 지우려 하면 서버가 409로 거절하고, 그 이유가 그대로 보입니다.
    } finally {
      busy(false);
    }
  }

  // ---------- 시작 ----------
  el.loginBtn.addEventListener('click', login);
  el.registerForm.addEventListener('submit', register);
  el.logoutBtn.addEventListener('click', logout);
  el.addForm.addEventListener('submit', addPasskey);

  (async () => {
    const problem = supportProblem();
    if (problem) say(problem);
    try {
      const me = await api('GET', '/me');
      await showOpen(me.account);
    } catch {
      showLocked(); // 세션이 없으면(401) 잠긴 채로 둡니다.
    }
  })();
})();
