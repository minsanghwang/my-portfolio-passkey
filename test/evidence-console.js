// 확인 기록용 콘솔 도구 — 배포된 사이트 화면에서 F12 → Console에 통째로 붙여 넣어 쓰세요.
// (붙여 넣기가 막혀 있으면 "allow pasting"이라고 먼저 입력)
//
// 하는 일
//  1) 사이트가 서버(/api/…)로 보내는 요청과 응답을 기록합니다. 긴 값(서명·공개키 등)은 앞부분만 남깁니다.
//  2) 확인 네 가지를 한 줄 명령으로 실행하고, 성공 요청과 거절된 요청을 나란히 보여 줍니다.
//  3) ev.report()로 결과를 표(마크다운)로 복사합니다.
// 이 도구는 서버를 우회하지 않습니다. 사이트가 하는 것과 같은 요청을 같은 출처에서 보낼 뿐입니다.
(() => {
  if (window.ev && window.ev._v) { console.log("ev는 이미 설치되어 있습니다. ev.help()"); return; }

  const KEY = "ev-state-v1";
  const load = () => { try { return JSON.parse(sessionStorage.getItem(KEY)) || {}; } catch { return {}; } };
  const state = Object.assign({ log: [], results: [], accounts: {} }, load());
  const save = () => { try { sessionStorage.setItem(KEY, JSON.stringify(state)); } catch { /* 저장 못 해도 동작에는 지장 없음 */ } };

  const SECRETISH = /signature|attestationObject|clientDataJSON|authenticatorData|rawId|userHandle|publicKey/i;
  function red(v, k = "") {
    if (typeof v === "string") return v.length > 40 && (SECRETISH.test(k) || v.length > 80) ? v.slice(0, 10) + "…(" + v.length + "자 생략)" : v;
    if (Array.isArray(v)) return v.map((x) => red(x, k));
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([a, b]) => [a, red(b, a)]));
    return v;
  }
  const pathOf = (u) => { const x = new URL(u, location.href); return x.pathname + x.search; };
  const orig = window.fetch.bind(window);
  const last = {};

  async function record(url, init, res) {
    const path = pathOf(url);
    if (!path.startsWith("/api/")) return;
    let resBody = null;
    try { resBody = await res.clone().json(); } catch { /* 본문 없음 */ }
    let reqBody = null;
    try { reqBody = init && init.body ? JSON.parse(init.body) : null; } catch { /* JSON 아님 */ }
    if (path === "/api/login/verify" && (init || {}).body) last.loginVerify = { url, init: { ...init } };
    state.log.push({
      t: new Date().toISOString().slice(11, 19),
      method: (init && init.method) || "GET",
      path,
      status: res.status,
      req: reqBody ? red(reqBody) : null,
      res: resBody ? red(resBody) : null,
    });
    state.log = state.log.slice(-80);
    save();
  }
  window.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input.url;
    const res = await orig(input, init);
    record(url, init, res);
    return res;
  };

  async function call(label, method, path, opts = {}) {
    const init = { method, credentials: opts.omit ? "omit" : "same-origin", cache: "no-store", headers: {} };
    if (opts.body) { init.body = JSON.stringify(opts.body); init.headers["Content-Type"] = "application/json"; }
    const res = await window.fetch(path, init);
    let body = null;
    try { body = await res.clone().json(); } catch { /* 본문 없음 */ }
    const ok = res.status === opts.expect;
    const row = {
      확인: label, 요청: method + " " + path, 기대: opts.expect, 실제: res.status,
      판정: ok ? "일치" : "불일치", 서버말: body ? (body.error || (body.count !== undefined ? "notes " + body.count + "개" : "OK")) : "",
    };
    state.results.push(row); save();
    return { row, body };
  }
  const show = (rows) => console.table(rows.map((r) => r.row || r));

  const ev = {
    _v: 1, state, last,
    help() {
      console.log([
        "ev.noLogin()          1) 로그인 없이 열기 → 401 기대 (쿠키 없이 보냄) + 소스에 비공개 내용 없음 확인",
        "ev.freshChallenges()  3번 받아 질문(challenge)이 모두 다른지 확인",
        "ev.me()               지금 로그인한 계정 id·핸들 기록",
        "ev.replay()           방금 쓴 로그인 응답을 그대로 다시 보내기 → challenge_already_used 기대",
        "ev.cross(상대id[,상대패스키id])  남의 계정 접근 → 403, 쿼리·경로 무시, 전후 개수 비교",
        "ev.passkeys()         내 패스키 목록(이름·날짜·저장 위치)",
        "ev.tryDeleteLast()    패스키가 1개일 때 지우기 시도 → 409 기대",
        "ev.bodyCheck()        마지막 등록·로그인 요청 본문에 개인키·비밀번호 항목이 없는지",
        "ev.ids()              기록된 계정 id",
        "ev.report()           결과를 마크다운으로 복사",
      ].join("\n"));
    },
    async noLogin() {
      const fake = "00000000-0000-4000-8000-000000000000";
      const rows = [
        await call("로그인 없이 열기", "GET", "/api/me", { omit: true, expect: 401 }),
        await call("로그인 없이 열기", "GET", "/api/private/notes", { omit: true, expect: 401 }),
        await call("로그인 없이 열기", "GET", "/api/passkeys", { omit: true, expect: 401 }),
        await call("로그인 없이 열기", "GET", `/api/private/accounts/${fake}/notes`, { omit: true, expect: 401 }),
        await call("로그인 없이 열기", "DELETE", "/api/passkeys/abc", { omit: true, expect: 401 }),
      ];
      show(rows);
      const marks = ["※ 데모용으로 만들어 넣은 예시 내용입니다", "프로젝트 메모 ", "지원 후보 목록 ", "스스로 쓰는 회고 "];
      const files = ["/", "/js/auth.js", "/js/main.js", "/css/styles.css"];
      const out = [];
      for (const f of files) {
        const t = await (await orig(f, { credentials: "omit", cache: "no-store" })).text();
        const hit = marks.filter((m) => t.includes(m));
        out.push({ 파일: f, 글자수: t.length, "비공개 내용 포함": hit.length ? "포함: " + hit.join(" | ") : "없음", "비밀번호 입력칸": /type=["']?password/i.test(t) ? "있음" : "없음" });
      }
      console.table(out);
      state.results.push({ 확인: "소스에 비공개 내용 없음", 요청: "GET " + files.join(", "), 기대: "없음", 실제: out.every((o) => o["비공개 내용 포함"] === "없음") ? "없음" : "있음", 판정: out.every((o) => o["비공개 내용 포함"] === "없음") ? "일치" : "불일치", 서버말: "" });
      save();
    },
    async freshChallenges() {
      const got = [];
      for (let i = 0; i < 3; i++) {
        const res = await window.fetch("/api/login/options", { method: "POST", credentials: "omit", headers: { "Content-Type": "application/json" }, body: "{}" });
        got.push((await res.json()).challenge);
      }
      console.table(got.map((c, i) => ({ 회차: i + 1, challenge: c })));
      const distinct = new Set(got).size === got.length;
      state.results.push({ 확인: "질문은 매번 새것", 요청: "POST /api/login/options ×3", 기대: "서로 다름", 실제: distinct ? "서로 다름" : "겹침", 판정: distinct ? "일치" : "불일치", 서버말: "" });
      save();
    },
    async me() {
      const r = await call("내 계정", "GET", "/api/me", { expect: 200 });
      if (r.body && r.body.account) { state.accounts[r.body.account.handle] = r.body.account.id; save(); }
      show([r]); console.log("기록된 계정:", state.accounts);
    },
    async replay() {
      const l = last.loginVerify;
      if (!l) return console.warn("방금 UI로 로그인한 적이 없습니다. 먼저 '패스키로 들어가기'로 로그인한 뒤(페이지를 새로고침하지 말고) 다시 실행하세요.");
      const res = await orig(l.url, l.init);
      let body = null; try { body = await res.json(); } catch { /* 본문 없음 */ }
      const row = { 확인: "쓴 질문 재사용", 요청: "POST /api/login/verify (방금 성공한 본문 그대로)", 기대: 400, 실제: res.status, 판정: res.status === 400 ? "일치" : "불일치", 서버말: body ? body.error : "" };
      state.results.push(row); save(); show([row]);
    },
    async cross(otherId, otherPasskeyId) {
      if (!otherId) return console.warn("상대 계정 id가 필요합니다. ev.ids()로 확인하세요.");
      const before = await (await orig("/api/private/notes", { credentials: "same-origin", cache: "no-store" })).json();
      const rows = [
        await call("내 경로로 내 자료", "GET", "/api/me", { expect: 200 }),
      ];
      const me = rows[0].body.account;
      rows.push(await call("내 계정 id를 주소에 쓰면 열림", "GET", `/api/private/accounts/${me.id}/notes`, { expect: 200 }));
      rows.push(await call("남의 계정 id를 주소에 쓰면 거절", "GET", `/api/private/accounts/${otherId}/notes`, { expect: 403 }));
      const q = await call("남의 id를 쿼리에 써도 무시", "GET", `/api/private/notes?account=${otherId}`, { expect: 200 });
      rows.push(q);
      if (otherPasskeyId) rows.push(await call("남의 패스키 지우기 시도", "DELETE", `/api/passkeys/${otherPasskeyId}`, { expect: 404 }));
      const after = await (await orig("/api/private/notes", { credentials: "same-origin", cache: "no-store" })).json();
      const ignored = q.body && q.body.owner === me.handle;
      const row = { 확인: "전후 개수·소유자", 요청: "GET /api/private/notes (전/후)", 기대: "같음", 실제: `전 ${before.count} / 후 ${after.count}, 쿼리 응답 owner=${q.body && q.body.owner}`, 판정: before.count === after.count && ignored ? "일치" : "불일치", 서버말: `내 핸들 ${me.handle}` };
      state.results.push(row); save();
      show([...rows, row]);
    },
    async passkeys() {
      const r = await call("내 패스키 목록", "GET", "/api/passkeys", { expect: 200 });
      if (!r.body) return;
      console.table(r.body.passkeys.map((p) => ({ 이름: p.name, 만든날: p.createdAt, 마지막사용: p.lastUsedAt, "저장 위치(추정)": p.storedIn, id앞부분: p.id.slice(0, 10) + "…", 지금세션: p.id === r.body.currentPasskeyId ? "●" : "" })));
    },
    async tryDeleteLast() {
      const l = await (await orig("/api/passkeys", { credentials: "same-origin", cache: "no-store" })).json();
      if (!l.passkeys || l.passkeys.length !== 1) return console.warn("패스키가 정확히 1개일 때만 실행합니다. 지금:", l.passkeys && l.passkeys.length);
      const r = await call("마지막 패스키 지우기", "DELETE", "/api/passkeys/" + l.passkeys[0].id, { expect: 409 });
      show([r]);
    },
    bodyCheck() {
      const rows = state.log.filter((e) => /\/(register|login|passkeys)\/verify$/.test(e.path) && e.req).slice(-3);
      if (!rows.length) return console.warn("등록·로그인 요청 기록이 없습니다.");
      const keysOf = (o, p = "") => Object.entries(o || {}).flatMap(([k, v]) => (v && typeof v === "object" && !Array.isArray(v)) ? keysOf(v, p + k + ".") : [p + k]);
      for (const e of rows) {
        const ks = keysOf(e.req);
        const bad = ks.filter((k) => /private|password|passwd|secret/i.test(k));
        console.log(`${e.method} ${e.path} → ${e.status}`, "\n보낸 항목:", ks.join(", "), "\n개인키·비밀번호 항목:", bad.length ? bad : "없음", "\n본문(긴 값 생략):", e.req);
      }
    },
    ids() { console.log(state.accounts); return state.accounts; },
    report() {
      const esc = (s) => String(s).replace(/\|/g, "\\|");
      const head = "| 확인 | 요청 | 기대 | 실제 | 판정 | 서버 말 |\n|---|---|---|---|---|---|\n";
      const body = state.results.map((r) => `| ${esc(r.확인)} | ${esc(r.요청)} | ${esc(r.기대)} | ${esc(r.실제)} | ${esc(r.판정)} | ${esc(r.서버말)} |`).join("\n");
      const log = "\n\n요청 기록(최근, 긴 값 생략)\n" + state.log.map((e) => `${e.t} ${e.method} ${e.path} → ${e.status}` + (e.res && e.res.error ? ` (${e.res.error})` : "")).join("\n");
      const text = head + body + log;
      try { copy(text); console.log("복사했습니다. 채팅에 붙여 넣어 주세요."); } catch { console.log(text); }
      return text;
    },
    reset() { state.log = []; state.results = []; save(); console.log("기록을 비웠습니다."); },
  };
  window.ev = ev;
  console.log("ev 설치 완료. 이제 사이트가 보내는 요청이 기록됩니다. ev.help()");
})();
