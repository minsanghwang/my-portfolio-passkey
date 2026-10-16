-- 패스키 로그인 데모 스키마
-- 비밀번호 칼럼은 어디에도 없습니다. 서버가 가진 것은 공개키(passkeys.public_key)뿐입니다.
-- 모든 테이블은 RLS를 켜고 정책을 만들지 않아, 공개 API 키로는 읽을 수 없습니다.
-- 서버(Edge Function)만 service role 키로 접근합니다.

create extension if not exists pgcrypto;

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

-- 등록 마무리: 계정 + 첫 패스키 + 비공개 항목을 한 번에(원자적으로) 만듭니다.
create or replace function public.register_account(
  p_handle text, p_user_handle text,
  p_credential_id text, p_public_key text, p_counter bigint,
  p_device_type text, p_backed_up boolean, p_transports text[], p_aaguid text,
  p_passkey_name text, p_notes jsonb
) returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account uuid;
begin
  if (select count(*) from accounts) >= 50 then
    raise exception 'account_limit' using errcode = 'P0001';
  end if;
  insert into accounts(handle, user_handle) values (p_handle, p_user_handle) returning id into v_account;
  insert into passkeys(id, account_id, name, public_key, counter, device_type, backed_up, transports, aaguid)
    values (p_credential_id, v_account, p_passkey_name, p_public_key, p_counter, p_device_type, p_backed_up, p_transports, p_aaguid);
  insert into private_notes(account_id, kind, title, body)
    select v_account, n->>'kind', n->>'title', n->>'body' from jsonb_array_elements(p_notes) n;
  return v_account;
end;
$$;

-- 패스키 삭제: 계정 행을 잠근 뒤 "마지막 하나"인지 세고 지웁니다. 동시에 두 개를 지워도 하나는 남습니다.
create or replace function public.delete_passkey_guarded(p_account uuid, p_passkey text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_count int;
begin
  perform 1 from accounts where id = p_account for update;
  if not exists (select 1 from passkeys where id = p_passkey and account_id = p_account) then
    return 'not_found';
  end if;
  select count(*) into v_count from passkeys where account_id = p_account;
  if v_count <= 1 then
    return 'last_passkey';
  end if;
  delete from passkeys where id = p_passkey and account_id = p_account;
  -- 지운 패스키로 만든 세션은 즉시 끊습니다.
  delete from sessions where account_id = p_account and passkey_id = p_passkey;
  return 'deleted';
end;
$$;

revoke execute on function public.register_account(text,text,text,text,bigint,text,boolean,text[],text,text,jsonb) from public, anon, authenticated;
revoke execute on function public.delete_passkey_guarded(uuid,text) from public, anon, authenticated;
