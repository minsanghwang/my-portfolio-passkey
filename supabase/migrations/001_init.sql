-- 패스키 로그인 데모 스키마
-- 비밀번호 칼럼은 어디에도 없습니다. 서버가 가진 것은 공개키(passkeys.public_key)뿐입니다.
-- 모든 테이블은 RLS를 켜고 정책을 만들지 않아, 공개 API 키로는 읽을 수 없습니다.
-- 서버(Edge Function)만 service role 키로 접근합니다.

create table public.accounts (
  id           uuid primary key default gen_random_uuid(),
  handle       text not null unique check (handle ~ '^[a-z0-9][a-z0-9_-]{2,23}$'),
  user_handle  text not null unique,           -- WebAuthn user.id (무작위, 개인정보 아님)
  created_at   timestamptz not null default now()
);

create table public.passkeys (
  id            text primary key,              -- credential ID (base64url)
  account_id    uuid not null references public.accounts(id) on delete cascade,
  name          text not null check (char_length(name) between 1 and 40),
  public_key    text not null,                 -- COSE 공개키 (base64url). 개인키는 서버에 오지 않습니다.
  counter       bigint not null default 0,
  device_type   text not null,                 -- singleDevice | multiDevice
  backed_up     boolean not null,
  transports    text[],
  aaguid        text,
  created_at    timestamptz not null default now(),
  last_used_at  timestamptz
);
create index passkeys_account_idx on public.passkeys(account_id);

-- 서버가 만든 일회용 질문(challenge). 확인될 때까지 서버가 보관하고, 쓰면 used_at이 찍힙니다.
create table public.challenges (
  challenge     text primary key,              -- 무작위 32바이트 (base64url)
  purpose       text not null check (purpose in ('register', 'add', 'login')),
  handle        text,
  user_handle   text,
  account_id    uuid references public.accounts(id) on delete cascade,
  passkey_name  text,
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  used_at       timestamptz
);

create table public.sessions (
  token_hash  text primary key,                -- 세션 토큰의 SHA-256. 원문은 서버에도 남기지 않습니다.
  account_id  uuid not null references public.accounts(id) on delete cascade,
  passkey_id  text,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null
);
create index sessions_account_idx on public.sessions(account_id);

-- 나만의 자리에 들어가는 항목 (모두 만들어 넣은 내용입니다)
create table public.private_notes (
  id          uuid primary key default gen_random_uuid(),
  account_id  uuid not null references public.accounts(id) on delete cascade,
  kind        text not null,
  title       text not null,
  body        text not null,
  created_at  timestamptz not null default now()
);
create index private_notes_account_idx on public.private_notes(account_id);

alter table public.accounts      enable row level security;
alter table public.passkeys      enable row level security;
alter table public.challenges    enable row level security;
alter table public.sessions      enable row level security;
alter table public.private_notes enable row level security;

revoke all on public.accounts, public.passkeys, public.challenges, public.sessions, public.private_notes
  from anon, authenticated;

-- 참고: 처음에는 계정 생성/패스키 삭제를 DB 함수로 묶으려 했지만, 이 환경에서는 함수 정의 적용이 계속 취소되어
-- 같은 일을 Edge Function 코드(registerVerify, deletePasskey)에서 하도록 바꿨습니다. 위 SQL이 실제로 적용된 전부입니다.
