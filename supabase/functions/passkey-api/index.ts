// 패스키(WebAuthn) 인증 서버 — Supabase Edge Function (Deno)
//
// 네 가지 흐름이 지나는 자리 (설명서 ③과 같은 번호):
//   등록          POST /register/options → POST /register/verify (취소: POST /register/cancel)
//   로그인        POST /login/options    → POST /login/verify
//   로그아웃      POST /logout
//   비공개 조회   GET  /private/notes, GET /private/accounts/:accountId/notes  (requireSession → requireOwner)
// 패스키 관리     GET /passkeys, POST /passkeys/options → /passkeys/verify, DELETE /passkeys/:id
//
// 이 서버가 저장하는 것은 공개키(passkeys.public_key)뿐입니다. 비밀번호도, 개인키도 받지 않습니다.
import { createClient } from "npm:@supabase/supabase-js@2";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "npm:@simplewebauthn/server@^13";

// ───────────────────────── 설정 ─────────────────────────
const RP_NAME = "패스키 데모 포트폴리오";
// 요청의 Origin이 이 목록에 있을 때만 받습니다. rpID는 그 Origin의 호스트 이름입니다.
const ALLOWED_ORIGINS = (Deno.env.get("ALLOWED_ORIGINS") ??
  "https://my-portfolio-passkey.vercel.app,http://localhost:8787").split(",").map((s) => s.trim());
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 질문은 5분 안에, 딱 한 번만 통과합니다
const SESSION_TTL_MS = 60 * 60 * 1000; // 로그인 유지 1시간 (절대 만료)
const COOKIE_NAME = "__Host-sid";
const MAX_BODY_CHARS = 20000;

const db = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { persistSession: false, autoRefreshToken: false } },
);

// ───────────────────────── 작은 도구들 ─────────────────────────
class HttpError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function json(status: number, body: unknown, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS, ...extra },
  });
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
async function sha256hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function readJson(req: Request): Promise<any> {
  const text = await req.text();
  if (text.length > MAX_BODY_CHARS) throw new HttpError(413, "body_too_large", "요청이 너무 큽니다.");
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "bad_json", "요청 본문이 JSON이 아닙니다.");
  }
}

// 상태를 바꾸는 요청(POST/DELETE)은 허용된 Origin에서 온 것만 받습니다. (쿠키는 SameSite=Strict와 함께 쓰는 이중 방어)
function requireAllowedOrigin(req: Request): string {
  const origin = req.headers.get("origin") ?? "";
  if (!ALLOWED_ORIGINS.includes(origin)) {
    throw new HttpError(403, "origin_not_allowed", "허용되지 않은 출처의 요청입니다.");
  }
  return origin;
}

function getCookie(req: Request, name: string): string | null {
  const raw = req.headers.get("cookie") ?? "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

// 패스키가 어디에 저장됐는지 "추정"합니다. AAGUID는 인증기 종류를 알려 주지만 attestation을 받지 않으면 0으로 올 수 있습니다.
const AAGUID_LABELS: Record<string, string> = {
  "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "구글 비밀번호 관리자",
  "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome(맥) 프로필 인증기",
  "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud 키체인",
  "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
  "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
};
function describeStorage(p: any): string {
  const label = p.aaguid ? AAGUID_LABELS[p.aaguid] : undefined;
  if (label) return label;
  const t: string[] = p.transports ?? [];
  const external = t.length > 0 && !t.includes("internal") && !t.includes("hybrid");
  if (external && (t.includes("usb") || t.includes("nfc") || t.includes("ble"))) return "보안 키(외부 장치)";
  if (p.device_type === "multiDevice" || p.backed_up) return "동기화되는 패스키(구글 비밀번호 관리자·iCloud 키체인 등)";
  return "이 기기 자체(기기 밖으로 복사되지 않음)";
}
function publicPasskey(p: any) {
  return {
    id: p.id,
    name: p.name,
    createdAt: p.created_at,
    lastUsedAt: p.last_used_at,
    deviceType: p.device_type,
    backedUp: p.backed_up,
    transports: p.transports ?? [],
    storedIn: describeStorage(p),
  };
}

// ───────────────────────── 만들어 넣은 비공개 항목 ─────────────────────────
// 실제 개인정보가 아닙니다. 계정마다 조금씩 다르게 만들어 넣습니다.
function seedNotes(handle: string) {
  let h = 0;
  for (const c of handle) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const pick = <T>(arr: T[], off = 0) => arr[(h + off) % arr.length];
  const tag = "※ 데모용으로 만들어 넣은 예시 내용입니다. ";
  return [
    {
      kind: "프로젝트 메모",
      title: `[${handle}] ` + pick(["미니 가계부 앱 구상", "포트폴리오 다크 모드", "날씨 알림 봇 개선"]),
      body: tag + pick([
        "입력 화면은 세 칸 이내로, 월별 합계는 표 한 장으로 끝내기.",
        "색 토큰부터 정리하고, 대비 비율을 먼저 확인한 뒤 컴포넌트에 적용하기.",
        "지역 코드를 설정 파일로 빼고, 알림 시각은 사용자가 고르게 하기.",
      ], 1),
    },
    {
      kind: "지원 후보 목록",
      title: `[${handle}] ` + pick(["가상회사 가나다 (백엔드 신입)", "예시주식회사 라마바 (QA)", "샘플테크 사아자 (데이터)"], 2),
      body: tag + pick([
        "서류 마감까지 포트폴리오 링크와 자격증 일정 정리가 필요함.",
        "채용 공고의 우대 사항에 맞춰 프로젝트 설명을 두 줄로 줄이기.",
        "면접 전에 네트워크 기초 복습 목록 만들기.",
      ], 3),
    },
    {
      kind: "스스로 쓰는 회고",
      title: `[${handle}] ` + pick(["이번 주 회고", "공부 습관 점검", "다음 달 목표"], 4),
      body: tag + pick([
        "잘한 것: 매일 같은 시간에 앉기. 아쉬운 것: 기록을 미루는 버릇.",
        "잘한 것: 막힐 때 질문을 구체적으로 적기. 다음 주: 복습 시간 고정.",
        "목표는 작게: 하루 한 문제, 주말에 한 번 되돌아보기.",
      ], 5),
    },
  ];
}

// ───────────────────────── 질문(challenge) ─────────────────────────
async function cleanup() {
  const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  await db.from("challenges").delete().lt("created_at", hourAgo);
  await db.from("sessions").delete().lt("expires_at", new Date().toISOString());
}

async function storeChallenge(row: Record<string, unknown>) {
  const { error } = await db.from("challenges").insert({
    ...row,
    expires_at: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString(),
  });
  if (error) throw error;
}

// 질문은 "아직 안 쓴 것"을 한 번에 표시(used_at)하는 단일 UPDATE로만 꺼냅니다.
// 같은 질문이 두 번 도착해도 한쪽만 성공합니다. (이미 쓴 질문 재사용 거절의 근거)
async function consumeChallenge(challenge: string, purpose: string) {
  const now = new Date().toISOString();
  const { data, error } = await db.from("challenges").update({ used_at: now })
    .eq("challenge", challenge).eq("purpose", purpose).is("used_at", null).gt("expires_at", now)
    .select().maybeSingle();
  if (error) throw error;
  if (data) return data;
  const { data: existing } = await db.from("challenges").select("purpose, used_at").eq("challenge", challenge).maybeSingle();
  if (!existing) throw new HttpError(400, "challenge_unknown", "서버가 낸 적 없는 질문입니다.");
  if (existing.purpose !== purpose) throw new HttpError(400, "challenge_wrong_purpose", "다른 용도의 질문입니다.");
  if (existing.used_at) throw new HttpError(400, "challenge_already_used", "이미 한 번 쓴 질문입니다. 새 질문을 받아 다시 시도하세요.");
  throw new HttpError(400, "challenge_expired", "질문의 유효 시간(5분)이 지났습니다.");
}

function challengeFromResponse(response: any): string {
  try {
    const cd = JSON.parse(new TextDecoder().decode(fromB64url(response.response.clientDataJSON)));
    if (typeof cd.challenge === "string") return cd.challenge;
  } catch { /* 아래에서 거절 */ }
  throw new HttpError(400, "bad_response", "clientDataJSON에서 질문을 읽을 수 없습니다.");
}

// ───────────────────────── 세션 ─────────────────────────
async function createSession(accountId: string, passkeyId: string) {
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const expires = new Date(Date.now() + SESSION_TTL_MS);
  const { error } = await db.from("sessions").insert({
    token_hash: await sha256hex(token),
    account_id: accountId,
    passkey_id: passkeyId,
    expires_at: expires.toISOString(),
  });
  if (error) throw error;
  const cookie = `${COOKIE_NAME}=${token}; Max-Age=${SESSION_TTL_MS / 1000}; Path=/; HttpOnly; Secure; SameSite=Strict`;
  return { cookie, expires };
}

type Session = { accountId: string; handle: string; passkeyId: string | null; expiresAt: string };

// 비공개 자료와 패스키 관리는 모두 여기를 먼저 지납니다. 세션이 없으면 401.
async function requireSession(req: Request): Promise<Session> {
  const token = getCookie(req, COOKIE_NAME);
  if (!token) throw new HttpError(401, "unauthenticated", "로그인이 필요합니다.");
  const { data } = await db.from("sessions").select("account_id, passkey_id, expires_at, accounts(handle)")
    .eq("token_hash", await sha256hex(token)).gt("expires_at", new Date().toISOString()).maybeSingle();
  if (!data) throw new HttpError(401, "unauthenticated", "세션이 없거나 만료됐습니다. 다시 로그인하세요.");
  return {
    accountId: data.account_id,
    handle: (data as any).accounts.handle,
    passkeyId: data.passkey_id,
    expiresAt: data.expires_at,
  };
}

// 주소에 적힌 계정이 "내 계정"일 때만 통과. 남의 계정이면 403.
function requireOwner(session: Session, accountIdInPath: string) {
  if (accountIdInPath !== session.accountId) {
    throw new HttpError(403, "forbidden_other_account", "다른 계정의 비공개 자료는 읽을 수 없습니다.");
  }
}

async function loadNotes(accountId: string) {
  const { data, error } = await db.from("private_notes").select("id, kind, title, body, created_at")
    .eq("account_id", accountId).order("created_at", { ascending: true }).order("kind", { ascending: true });
  if (error) throw error;
  return data ?? [];
}

// ───────────────────────── 핸들러 ─────────────────────────
const HANDLE_RE = /^[a-z0-9][a-z0-9_-]{2,23}$/;

function cleanName(v: unknown, fallback: string): string {
  const s = typeof v === "string" ? v.trim().slice(0, 40) : "";
  return s || fallback;
}

// 1) 등록: 서버가 질문을 만들어 보관하고 브라우저에 넘깁니다. 아직 아무 계정도 만들지 않습니다.
async function registerOptions(req: Request, origin: string) {
  const body = await readJson(req);
  const handle = String(body.handle ?? "").trim().toLowerCase();
  if (!HANDLE_RE.test(handle)) {
    throw new HttpError(400, "bad_handle", "계정 이름은 영문 소문자·숫자·_·- 3~24자입니다.");
  }
  const { data: taken } = await db.from("accounts").select("id").eq("handle", handle).maybeSingle();
  if (taken) throw new HttpError(409, "handle_taken", "이미 있는 계정 이름입니다. 로그인하려면 '패스키로 들어가기'를 누르세요.");
  const userHandle = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: new URL(origin).hostname,
    userName: handle,
    userDisplayName: handle,
    userID: fromB64url(userHandle),
    attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    timeout: 60000,
  });
  await cleanup();
  await storeChallenge({
    challenge: options.challenge,
    purpose: "register",
    handle,
    user_handle: userHandle,
    passkey_name: cleanName(body.passkeyName, "첫 번째 패스키"),
  });
  return json(200, options);
}

async function registerVerify(req: Request, origin: string) {
  const body = await readJson(req);
  const response = body.response;
  if (!response?.response?.clientDataJSON) throw new HttpError(400, "bad_response", "등록 응답이 올바르지 않습니다.");
  const row = await consumeChallenge(challengeFromResponse(response), "register");
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: row.challenge,
      expectedOrigin: origin,
      expectedRPID: new URL(origin).hostname,
      requireUserVerification: true,
    });
  } catch (e) {
    throw new HttpError(400, "registration_invalid", `등록 응답 검증 실패: ${(e as Error).message}`);
  }
  if (!verification.verified || !verification.registrationInfo) {
    throw new HttpError(400, "registration_invalid", "등록 응답을 확인하지 못했습니다.");
  }
  const info = verification.registrationInfo;

  // 서명 확인이 끝난 "지금"에서야 계정과 공개키를 저장합니다. (그 전에 취소하면 저장되는 것이 없습니다)
  const { count: accountCount } = await db.from("accounts").select("id", { count: "exact", head: true });
  if ((accountCount ?? 0) >= 50) throw new HttpError(503, "account_limit", "데모 계정 수 한도에 도달했습니다.");

  const { data: created, error: accountErr } = await db.from("accounts")
    .insert({ handle: row.handle, user_handle: row.user_handle }).select("id").single();
  if (accountErr) {
    if (accountErr.code === "23505") throw new HttpError(409, "already_registered", "이미 등록된 계정 이름입니다.");
    throw accountErr;
  }
  const accountId = created!.id as string;
  // 이후 단계가 실패하면 방금 만든 계정을 지워(공개키·항목은 연쇄 삭제) 반쪽짜리 계정이 남지 않게 합니다.
  const undo = () => db.from("accounts").delete().eq("id", accountId);

  const { error: keyErr } = await db.from("passkeys").insert({
    id: info.credential.id,
    account_id: accountId,
    name: row.passkey_name,
    public_key: b64url(info.credential.publicKey), // 공개키만. 개인키는 서버에 온 적이 없습니다.
    counter: info.credential.counter,
    device_type: info.credentialDeviceType,
    backed_up: info.credentialBackedUp,
    transports: info.credential.transports ?? response.response.transports ?? [],
    aaguid: info.aaguid,
  });
  if (keyErr) {
    await undo();
    if (keyErr.code === "23505") throw new HttpError(409, "already_registered", "이미 등록된 패스키입니다.");
    throw keyErr;
  }
  const { error: noteErr } = await db.from("private_notes")
    .insert(seedNotes(row.handle).map((n) => ({ ...n, account_id: accountId })));
  if (noteErr) {
    await undo();
    throw noteErr;
  }
  const { cookie, expires } = await createSession(accountId, info.credential.id);
  return json(200, { verified: true, account: { id: accountId, handle: row.handle }, sessionExpiresAt: expires.toISOString() }, {
    "Set-Cookie": cookie,
  });
}

// 등록을 중간에 취소하면 보관해 둔 질문만 지웁니다. 계정·패스키는 만든 적이 없으므로 남는 것이 없습니다.
async function registerCancel(req: Request) {
  const body = await readJson(req);
  if (typeof body.challenge === "string") {
    await db.from("challenges").delete().eq("challenge", body.challenge).in("purpose", ["register", "add"]).is("used_at", null);
  }
  return json(200, { cancelled: true });
}

// 2) 로그인: 매번 새 질문
async function loginOptions(_req: Request, origin: string) {
  const options = await generateAuthenticationOptions({
    rpID: new URL(origin).hostname,
    userVerification: "required",
    timeout: 60000,
  });
  await cleanup();
  await storeChallenge({ challenge: options.challenge, purpose: "login" });
  return json(200, options);
}

async function loginVerify(req: Request, origin: string) {
  const body = await readJson(req);
  const response = body.response;
  if (!response?.id || !response?.response?.clientDataJSON) throw new HttpError(400, "bad_response", "로그인 응답이 올바르지 않습니다.");
  // 서명이 맞든 틀리든, 질문은 이 시점에 "쓴 것"이 됩니다.
  const row = await consumeChallenge(challengeFromResponse(response), "login");
  const { data: pk } = await db.from("passkeys").select("*").eq("id", response.id).maybeSingle();
  if (!pk) throw new HttpError(401, "passkey_not_registered", "서버에 등록되어 있지 않은(또는 삭제된) 패스키입니다.");
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: row.challenge,
      expectedOrigin: origin,
      expectedRPID: new URL(origin).hostname,
      requireUserVerification: true,
      credential: {
        id: pk.id,
        publicKey: fromB64url(pk.public_key),
        counter: Number(pk.counter),
        transports: pk.transports ?? undefined,
      },
    });
  } catch (e) {
    throw new HttpError(401, "signature_invalid", `서명 확인 실패: ${(e as Error).message}`);
  }
  if (!verification.verified) throw new HttpError(401, "signature_invalid", "서명을 확인하지 못했습니다.");
  await db.from("passkeys").update({
    counter: verification.authenticationInfo.newCounter,
    last_used_at: new Date().toISOString(),
  }).eq("id", pk.id);
  const { data: account } = await db.from("accounts").select("id, handle").eq("id", pk.account_id).single();
  const { cookie, expires } = await createSession(account!.id, pk.id);
  return json(200, { verified: true, account: { id: account!.id, handle: account!.handle }, sessionExpiresAt: expires.toISOString() }, {
    "Set-Cookie": cookie,
  });
}

// 3) 로그아웃: 서버의 세션 행을 지웁니다. 같은 쿠키 값으로 다시 요청하면 401.
async function logout(req: Request) {
  const token = getCookie(req, COOKIE_NAME);
  if (token) await db.from("sessions").delete().eq("token_hash", await sha256hex(token));
  return json(200, { loggedOut: true }, {
    "Set-Cookie": `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`,
  });
}

async function me(req: Request) {
  const s = await requireSession(req);
  const { count } = await db.from("passkeys").select("id", { count: "exact", head: true }).eq("account_id", s.accountId);
  return json(200, { account: { id: s.accountId, handle: s.handle }, passkeyCount: count ?? 0, sessionExpiresAt: s.expiresAt });
}

// 4) 비공개 자료 조회: 항상 "세션의 계정" 기준. 주소·본문에 적은 계정은 읽지 않습니다.
async function privateNotes(req: Request) {
  const s = await requireSession(req);
  const notes = await loadNotes(s.accountId);
  return json(200, { owner: s.handle, count: notes.length, notes });
}
async function privateNotesOfAccount(req: Request, accountId: string) {
  const s = await requireSession(req);
  requireOwner(s, accountId);
  const notes = await loadNotes(s.accountId);
  return json(200, { owner: s.handle, count: notes.length, notes });
}

// 패스키 관리
async function listPasskeys(req: Request) {
  const s = await requireSession(req);
  const { data, error } = await db.from("passkeys").select("*").eq("account_id", s.accountId).order("created_at");
  if (error) throw error;
  return json(200, { passkeys: (data ?? []).map(publicPasskey), currentPasskeyId: s.passkeyId });
}

async function addPasskeyOptions(req: Request, origin: string) {
  const s = await requireSession(req);
  const body = await readJson(req);
  const { data: acct } = await db.from("accounts").select("user_handle").eq("id", s.accountId).single();
  const { data: existing } = await db.from("passkeys").select("id, transports").eq("account_id", s.accountId);
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: new URL(origin).hostname,
    userName: s.handle,
    userDisplayName: s.handle,
    userID: fromB64url(acct!.user_handle),
    attestationType: "none",
    // 이미 등록된 패스키는 제외하라고 기기에 알립니다. (같은 기기에 중복 등록 방지)
    excludeCredentials: (existing ?? []).map((p: any) => ({ id: p.id, transports: p.transports ?? undefined })),
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    timeout: 60000,
  });
  await storeChallenge({
    challenge: options.challenge,
    purpose: "add",
    account_id: s.accountId,
    passkey_name: cleanName(body.passkeyName, `패스키 ${(existing?.length ?? 0) + 1}`),
  });
  return json(200, options);
}

async function addPasskeyVerify(req: Request, origin: string) {
  const s = await requireSession(req);
  const body = await readJson(req);
  const response = body.response;
  if (!response?.response?.clientDataJSON) throw new HttpError(400, "bad_response", "등록 응답이 올바르지 않습니다.");
  const row = await consumeChallenge(challengeFromResponse(response), "add");
  if (row.account_id !== s.accountId) throw new HttpError(403, "forbidden_other_account", "다른 계정이 시작한 등록입니다.");
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: row.challenge,
      expectedOrigin: origin,
      expectedRPID: new URL(origin).hostname,
      requireUserVerification: true,
    });
  } catch (e) {
    throw new HttpError(400, "registration_invalid", `등록 응답 검증 실패: ${(e as Error).message}`);
  }
  if (!verification.verified || !verification.registrationInfo) {
    throw new HttpError(400, "registration_invalid", "등록 응답을 확인하지 못했습니다.");
  }
  const info = verification.registrationInfo;
  const { data, error } = await db.from("passkeys").insert({
    id: info.credential.id,
    account_id: s.accountId,
    name: row.passkey_name,
    public_key: b64url(info.credential.publicKey),
    counter: info.credential.counter,
    device_type: info.credentialDeviceType,
    backed_up: info.credentialBackedUp,
    transports: info.credential.transports ?? response.response.transports ?? [],
    aaguid: info.aaguid,
  }).select().single();
  if (error) {
    if (error.code === "23505") throw new HttpError(409, "already_registered", "이미 등록된 패스키입니다.");
    throw error;
  }
  return json(200, { verified: true, passkey: publicPasskey(data) });
}

async function deletePasskey(req: Request, passkeyId: string) {
  const s = await requireSession(req);
  const lastPasskey = () => new HttpError(409, "last_passkey",
    "마지막 패스키는 지울 수 없습니다. 이 데모에는 계정 복구 수단이 없어, 지우면 영영 못 들어옵니다. 먼저 다른 패스키를 등록하세요.");

  // 항상 "세션의 계정" 안에서만 찾습니다. 남의 패스키 id를 보내도 여기서는 없는 것으로 보입니다(404).
  const { data: own, error: listErr } = await db.from("passkeys").select("*").eq("account_id", s.accountId);
  if (listErr) throw listErr;
  const target = (own ?? []).find((p: any) => p.id === passkeyId);
  if (!target) throw new HttpError(404, "passkey_not_found", "내 계정에 그런 패스키가 없습니다.");
  if ((own ?? []).length <= 1) throw lastPasskey();

  const { error: delErr } = await db.from("passkeys").delete().eq("id", passkeyId).eq("account_id", s.accountId);
  if (delErr) throw delErr;

  // 거의 동시에 두 패스키를 지워 0개가 되어 버렸다면 되돌립니다. (DB 함수 없이 지키는 방식이라 남은 허점은 설명서 ⑥에 적었습니다)
  const { count } = await db.from("passkeys").select("id", { count: "exact", head: true }).eq("account_id", s.accountId);
  if ((count ?? 0) === 0) {
    await db.from("passkeys").insert(target);
    throw lastPasskey();
  }
  // 지운 패스키로 열린 세션은 즉시 끊습니다.
  await db.from("sessions").delete().eq("account_id", s.accountId).eq("passkey_id", passkeyId);
  return json(200, { deleted: true, remaining: count ?? 0, endedCurrentSession: passkeyId === s.passkeyId });
}

// ───────────────────────── 라우터 ─────────────────────────
Deno.serve(async (req: Request) => {
  try {
    const url = new URL(req.url);
    const route = url.pathname.replace(/^.*\/passkey-api/, "") || "/";
    const method = req.method;
    const mutating = method === "POST" || method === "DELETE";
    const origin = mutating ? requireAllowedOrigin(req) : "";

    if (method === "GET" && route === "/health") return json(200, { ok: true });
    if (method === "GET" && route === "/me") return await me(req);
    if (method === "GET" && route === "/private/notes") return await privateNotes(req);
    if (method === "GET" && route === "/passkeys") return await listPasskeys(req);

    const acct = route.match(/^\/private\/accounts\/([0-9a-f-]{36})\/notes$/);
    if (method === "GET" && acct) return await privateNotesOfAccount(req, acct[1]);

    if (method === "POST" && route === "/register/options") return await registerOptions(req, origin);
    if (method === "POST" && route === "/register/verify") return await registerVerify(req, origin);
    if (method === "POST" && route === "/register/cancel") return await registerCancel(req);
    if (method === "POST" && route === "/login/options") return await loginOptions(req, origin);
    if (method === "POST" && route === "/login/verify") return await loginVerify(req, origin);
    if (method === "POST" && route === "/logout") return await logout(req);
    if (method === "POST" && route === "/passkeys/options") return await addPasskeyOptions(req, origin);
    if (method === "POST" && route === "/passkeys/verify") return await addPasskeyVerify(req, origin);

    const del = route.match(/^\/passkeys\/([A-Za-z0-9_-]{1,512})$/);
    if (method === "DELETE" && del) return await deletePasskey(req, del[1]);

    throw new HttpError(404, "not_found", "없는 주소입니다.");
  } catch (e) {
    if (e instanceof HttpError) return json(e.status, { error: e.code, message: e.message });
    console.error("unhandled", e);
    return json(500, { error: "server_error", message: "서버 오류가 났습니다." });
  }
});
