-- Chatterbox: user blocking
-- Run this file once in Supabase SQL Editor.
--
-- A block is private to the account that created it. Users can only read,
-- add and remove their own block-list rows. The status RPC reveals only
-- whether the caller and one specified account have blocked each other.

begin;

create table if not exists public.user_blocks (
  blocker_id uuid not null references auth.users(id) on delete cascade,
  blocked_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  constraint user_blocks_no_self_block check (blocker_id <> blocked_id)
);

alter table public.user_blocks enable row level security;

drop policy if exists user_blocks_select_own on public.user_blocks;
create policy user_blocks_select_own
  on public.user_blocks
  for select
  to authenticated
  using (blocker_id = auth.uid());

drop policy if exists user_blocks_insert_own on public.user_blocks;
create policy user_blocks_insert_own
  on public.user_blocks
  for insert
  to authenticated
  with check (blocker_id = auth.uid() and blocked_id <> auth.uid());

drop policy if exists user_blocks_delete_own on public.user_blocks;
create policy user_blocks_delete_own
  on public.user_blocks
  for delete
  to authenticated
  using (blocker_id = auth.uid());

revoke all on public.user_blocks from anon;
grant select, insert, delete on public.user_blocks to authenticated;

-- Returns only the relationship between the signed-in account and p_user.
create or replace function public.get_block_status(p_user uuid)
returns table(i_blocked boolean, they_blocked_me boolean)
language sql
stable
security definer
set search_path = public, auth
as $$
  select
    exists (
      select 1
      from public.user_blocks b
      where b.blocker_id = auth.uid()
        and b.blocked_id = p_user
    ) as i_blocked,
    exists (
      select 1
      from public.user_blocks b
      where b.blocker_id = p_user
        and b.blocked_id = auth.uid()
    ) as they_blocked_me
  where auth.uid() is not null
    and p_user is not null
    and p_user <> auth.uid();
$$;

revoke all on function public.get_block_status(uuid) from public;
grant execute on function public.get_block_status(uuid) to authenticated;

-- Prevent either side of a blocked pair from sending a direct-message row.
-- Group messages remain available; this keeps existing group conversations usable.
create or replace function public.reject_blocked_direct_messages()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if exists (
    select 1
    from public.conversations c
    join public.conversation_members recipient
      on recipient.conversation_id = c.id
     and recipient.user_id <> new.sender_id
    where c.id = new.conversation_id
      and coalesce(c.is_group, false) = false
      and exists (
        select 1
        from public.user_blocks b
        where (b.blocker_id = new.sender_id and b.blocked_id = recipient.user_id)
           or (b.blocker_id = recipient.user_id and b.blocked_id = new.sender_id)
      )
  ) then
    raise exception 'Message blocked: one of these users has blocked the other.'
      using errcode = '42501';
  end if;

  return new;
end;
$$;

drop trigger if exists reject_blocked_direct_messages on public.messages;
create trigger reject_blocked_direct_messages
  before insert on public.messages
  for each row
  execute function public.reject_blocked_direct_messages();

-- Prevent blocked pairs from ringing, joining or exchanging WebRTC signalling.
create or replace function public.reject_blocked_call_signals()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if exists (
    select 1
    from public.user_blocks b
    where (b.blocker_id = new.from_user and b.blocked_id = new.to_user)
       or (b.blocker_id = new.to_user and b.blocked_id = new.from_user)
  ) then
    raise exception 'Call blocked: one of these users has blocked the other.'
      using errcode = '42501';
  end if;

  return new;
end;
$$;

drop trigger if exists reject_blocked_call_signals on public.call_signals;
create trigger reject_blocked_call_signals
  before insert on public.call_signals
  for each row
  execute function public.reject_blocked_call_signals();

commit;
