-- 계정 생성과 패스키 삭제를 "한 번에(원자적으로)" 처리하는 DB 함수 두 개.
-- 서버(Edge Function)만 service role 키로 부릅니다. 공개 API 키(anon/authenticated)는 실행 권한을 회수했습니다.
-- (함수 본문은 따옴표 본문의 SQL 함수로 썼습니다. 이 환경에서는 $$ 본문의 plpgsql 정의가 적용되지 않았습니다.)

-- 등록 마무리: 계정 + 첫 패스키(공개키) + 비공개 항목을 한 문장으로 만듭니다.
-- 중간에 하나라도 실패하면 전부 취소됩니다. 계정이 50개 이상이면 아무것도 만들지 않고 null을 돌려줍니다.
create or replace function public.register_account(
  p_handle text, p_user_handle text,
  p_credential_id text, p_public_key text, p_counter bigint,
  p_device_type text, p_backed_up boolean, p_transports text[], p_aaguid text,
  p_passkey_name text, p_notes jsonb
)
returns uuid
language sql
volatile
set search_path = public
as '
with a as (
  insert into accounts(handle, user_handle)
  select p_handle, p_user_handle where (select count(*) from accounts) < 50
  returning id
),
p as (
  insert into passkeys(id, account_id, name, public_key, counter, device_type, backed_up, transports, aaguid)
  select p_credential_id, a.id, p_passkey_name, p_public_key, p_counter, p_device_type, p_backed_up, p_transports, p_aaguid
  from a
  returning 1
),
n as (
  insert into private_notes(account_id, kind, title, body)
  select a.id, x->>''kind'', x->>''title'', x->>''body'' from a, jsonb_array_elements(p_notes) as x
  returning 1
)
select id from a
';

-- 패스키 삭제: 계정 행을 먼저 잠근 뒤(= 같은 계정의 다른 삭제 요청은 기다림) "마지막 하나인지" 세고 지웁니다.
-- 'deleted' | 'last_passkey' | 'not_found' 를 돌려줍니다. 지운 패스키로 열린 세션도 함께 지웁니다.
create or replace function public.delete_passkey_guarded(p_account uuid, p_passkey text)
returns text
language sql
volatile
set search_path = public
as '
select id from accounts where id = p_account for update;
with mine as (
  select 1 from passkeys where id = p_passkey and account_id = p_account
),
cnt as (
  select count(*) as c from passkeys where account_id = p_account
),
del as (
  delete from passkeys
  where id = p_passkey and account_id = p_account
    and exists (select 1 from mine) and (select c from cnt) > 1
  returning 1
),
dsess as (
  delete from sessions
  where account_id = p_account and passkey_id = p_passkey and exists (select 1 from del)
  returning 1
)
select case
  when not exists (select 1 from mine) then ''not_found''
  when (select c from cnt) <= 1 then ''last_passkey''
  else ''deleted''
end;
';

revoke execute on function public.register_account(text,text,text,text,bigint,text,boolean,text[],text,text,jsonb) from public, anon, authenticated;
revoke execute on function public.delete_passkey_guarded(uuid,text) from public, anon, authenticated;
