-- ====================================================================
-- Prithvi Realcon Transport — Attendance System
-- schema.sql  (v3)  — ONE file. Replaces BOTH old schema.sql and migration.sql.
--
-- HOW TO RUN
--   1. Edit the admin password in STEP 3 below (search for  v_admin_pw ).
--   2. Supabase dashboard -> SQL Editor -> paste this whole file -> Run.
--   3. Safe to run again later: employees, attendance and leave data are KEPT.
--
-- WHAT THIS VERSION FIXES / ADDS
--   * Login errors are specific: name not found / wrong password / account
--     not created / device limit / device used by someone else / locked.
--   * Passwords: trailing/leading spaces (phone keyboards) are ignored, and
--     names ignore extra spaces and capital letters.
--   * Sessions are tracked live: logout deletes the row immediately, every
--     open dashboard sends a heartbeat (last_seen), admin sees who is online.
--   * Up to N devices per employee at the same time (config: max_devices,
--     default 2). Idle devices free their slot automatically.
--   * Location: the app sends GPS accuracy; errors say exactly what is wrong
--     (too far / accuracy too low / empty location).
--   * Security: internal helpers live in a private schema (the old public
--     cfg() function could be called by anyone and leaked the admin password).
--     Admin password is now stored hashed; admin uses a login token; wrong
--     password attempts are rate-limited.
--   * Auto sign-out at 23:59 IST (pg_cron if available, otherwise lazily).
-- ====================================================================

create extension if not exists pgcrypto with schema extensions;

create schema if not exists app_private;
revoke all on schema app_private from public, anon, authenticated;


-- ====================================================================
-- STEP 1 — TABLES (existing data is kept)
-- ====================================================================

create table if not exists public.employees (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  password_hash text,                              -- null = not registered yet
  active        boolean not null default true,
  notes         text,
  created_at    timestamptz default now()
);

create table if not exists public.sessions (
  token       uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.employees(id) on delete cascade,
  created_at  timestamptz default now(),
  expires_at  timestamptz not null default (now() + interval '30 days')
);
alter table public.sessions add column if not exists device_id    text;
alter table public.sessions add column if not exists device_label text;
alter table public.sessions add column if not exists last_seen    timestamptz not null default now();
create index if not exists sessions_employee_idx on public.sessions (employee_id);

create table if not exists public.config (
  key   text primary key,
  value text
);

create table if not exists public.attendance (
  id          uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.employees(id) on delete cascade,
  date        date not null,
  time        time not null,
  status      text not null check (status in ('sign_in', 'sign_out')),
  lat         float,
  lng         float,
  note        text,
  source      text not null default 'self' check (source in ('self', 'admin')),
  created_at  timestamptz default now(),
  unique (employee_id, date, status)
);
alter table public.attendance add column if not exists device_id    text;
alter table public.attendance add column if not exists auto_signout boolean not null default false;
alter table public.attendance add column if not exists accuracy_m   float;
create index if not exists attendance_date_status_idx on public.attendance (date, status);
create index if not exists attendance_device_idx      on public.attendance (device_id, date);

create table if not exists public.leave_requests (
  id           uuid primary key default gen_random_uuid(),
  employee_id  uuid not null references public.employees(id) on delete cascade,
  leave_type   text not null check (leave_type in ('single_day', 'long_leave')),
  start_date   date not null,
  end_date     date not null,
  reason       text,
  status       text not null default 'pending'
               check (status in ('pending', 'approved', 'rejected', 'cancelled')),
  approved_by  text,
  approved_at  timestamptz,
  cancelled_at timestamptz,
  cancelled_by text,
  created_at   timestamptz default now(),
  check (end_date >= start_date)
);
create index if not exists leave_employee_idx on public.leave_requests (employee_id);
create index if not exists leave_status_idx   on public.leave_requests (status);

drop table if exists public.time_change_requests;

-- private tables (never reachable from the browser)
create table if not exists app_private.admin_sessions (
  token      uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '12 hours')
);

create table if not exists app_private.auth_attempts (
  scope        text not null,
  key          text not null,
  fails        int  not null default 0,
  window_start timestamptz not null default now(),
  locked_until timestamptz,
  primary key (scope, key)
);

alter table public.employees          enable row level security;
alter table public.sessions           enable row level security;
alter table public.config             enable row level security;
alter table public.attendance         enable row level security;
alter table public.leave_requests     enable row level security;
alter table app_private.admin_sessions enable row level security;
alter table app_private.auth_attempts  enable row level security;

revoke all on public.employees, public.sessions, public.config,
              public.attendance, public.leave_requests from anon, authenticated;


-- ====================================================================
-- STEP 2 — DEFAULT SETTINGS  (existing values are never overwritten)
-- ====================================================================

insert into public.config (key, value) values
  ('company_name',            'Prithvi Realcon Transport'),
  ('office_lat',              '21.2758151'),
  ('office_lng',              '81.6322723'),
  ('office_radius_m',         '50'),    -- must be within this many metres of the office
  ('accuracy_allowance_m',    '20'),    -- GPS error forgiven (max); set 0 to be strict
  ('max_accuracy_m',          '150'),   -- reject readings worse than this (e.g. Wi-Fi guesses)
  ('max_devices',             '2'),     -- devices one employee can be logged in on at once
  ('session_idle_minutes',    '10'),    -- a device with no heartbeat this long frees its slot
  ('one_device_one_employee', 'on')     -- on = a phone that signed in for A today cannot log in as B
on conflict (key) do nothing;

-- Old versions stored the admin password in plain text and exposed it through
-- a public function. It is deleted below; you must set a NEW one in STEP 3.
-- (lunch_minutes was never used by the app.)
delete from public.config where key = 'lunch_minutes';


-- ====================================================================
-- STEP 3 — ADMIN PASSWORD
--   Fresh install / upgrade from the old version: EDIT the line below.
--   Re-running this file later: this step is skipped, password unchanged.
--   Forgot it? See the "RESET ADMIN PASSWORD" snippet at the very bottom.
-- ====================================================================

do $$
declare
  v_admin_pw constant text := 'PUT-YOUR-NEW-ADMIN-PASSWORD-HERE';     -- <<< EDIT THIS (min 8 chars)
begin
  if not exists (select 1 from public.config where key = 'admin_password_hash') then
    if v_admin_pw = 'PUT-YOUR-NEW-ADMIN-PASSWORD-HERE' or length(v_admin_pw) < 8 then
      raise exception 'Edit v_admin_pw in STEP 3 of this file (min 8 characters), then run it again. Nothing was changed.';
    end if;
    insert into public.config (key, value)
    values ('admin_password_hash', extensions.crypt(v_admin_pw, extensions.gen_salt('bf', 10)));
  end if;
  delete from public.config where key = 'admin_password';   -- old plain-text password
end $$;


-- ====================================================================
-- STEP 4 — REMOVE OLD FUNCTIONS (all signatures from earlier versions)
-- ====================================================================

do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure as sig
    from pg_proc p
    where p.pronamespace = 'public'::regnamespace
      and p.proname = any (array[
        'cfg','ist_today','ist_now_time','on_leave','emp_from_token','chk',
        'office_distance','device_used_by_other','check_device_login','auto_signout_all',
        'emp_register','emp_login','emp_logout','emp_me','day_info','mark_attendance',
        'request_leave','cancel_leave','my_leaves',
        'admin_login','admin_logout','admin_data','admin_leave_action','admin_add_employee',
        'admin_del_employee','admin_reset_password','admin_set_employee_active',
        'admin_set_employee_notes','admin_set_attendance','admin_clear_attendance',
        'admin_clear_sessions','admin_update_config','admin_change_password'
      ])
  loop
    execute 'drop function if exists ' || r.sig || ' cascade';
  end loop;
end $$;

-- name matching ignores case and extra spaces ("  Ravi   KUMAR " = "ravi kumar")
create or replace function app_private.norm_name(t text) returns text
  language sql immutable parallel safe as $$
  select lower(btrim(regexp_replace(coalesce(t, ''), '\s+', ' ', 'g')))
$$;

create unique index if not exists employees_name_norm_unique
  on public.employees (app_private.norm_name(name));
drop index if exists public.employees_name_unique;


-- ====================================================================
-- STEP 5 — PRIVATE HELPERS (not callable from the browser)
-- ====================================================================

create or replace function app_private.cfg(k text, d text default null) returns text
  language sql stable security definer set search_path = public, pg_temp as $$
  select coalesce((select value from public.config where key = k), d)
$$;

create or replace function app_private.ist_today() returns date
  language sql stable as $$ select (now() at time zone 'Asia/Kolkata')::date $$;

create or replace function app_private.ist_now_time() returns time
  language sql stable as $$ select (now() at time zone 'Asia/Kolkata')::time(0) $$;

create or replace function app_private.fail(p_code text, p_msg text) returns json
  language sql immutable as $$
  select json_build_object('ok', false, 'code', p_code, 'message', p_msg)
$$;

create or replace function app_private.on_leave(e uuid, d date) returns boolean
  language sql stable security definer set search_path = public, pg_temp as $$
  select exists (
    select 1 from public.leave_requests
    where employee_id = e and status = 'approved' and d between start_date and end_date
  )
$$;

-- Resolves a login token to an employee and records a heartbeat.
-- Raises a message starting with "Not logged in" (SQLSTATE AU001) when the
-- session no longer exists, so the app can send the user back to the login page.
create or replace function app_private.session_emp(p_token uuid) returns uuid
  language plpgsql security definer set search_path = public, pg_temp as $$
declare
  s public.sessions;
  a boolean;
begin
  select * into s from public.sessions where token = p_token and expires_at > now();
  if not found then
    raise exception 'Not logged in: your session has ended (you logged out, logged in on too many other devices, admin cleared it, or it expired). Please log in again.'
      using errcode = 'AU001';
  end if;
  select active into a from public.employees where id = s.employee_id;
  if a is not true then
    raise exception 'Not logged in: your account is deactivated. Contact admin.' using errcode = 'AU001';
  end if;
  if s.last_seen < now() - interval '20 seconds' then
    update public.sessions set last_seen = now() where token = p_token;
  end if;
  return s.employee_id;
end $$;

create or replace function app_private.office_distance(p_lat float8, p_lng float8) returns float8
  language sql stable security definer set search_path = public, pg_temp as $$
  select 6371000 * 2 * asin(sqrt(
    sin(radians(p_lat - o.lat) / 2) ^ 2 +
    cos(radians(o.lat)) * cos(radians(p_lat)) * sin(radians(p_lng - o.lng) / 2) ^ 2
  ))
  from (select app_private.cfg('office_lat')::float8 as lat,
               app_private.cfg('office_lng')::float8 as lng) o
$$;

-- true if this device already signed in today for a DIFFERENT employee
create or replace function app_private.device_conflict(p_device text, e uuid) returns boolean
  language sql stable security definer set search_path = public, pg_temp as $$
  select app_private.cfg('one_device_one_employee', 'on') = 'on'
     and exists (
       select 1 from public.attendance
       where device_id = p_device
         and date = app_private.ist_today()
         and status = 'sign_in'
         and employee_id <> e
     )
$$;

-- human readable list of an employee's logged-in devices (for error messages)
create or replace function app_private.devices_text(e uuid) returns text
  language sql stable security definer set search_path = public, pg_temp as $$
  select string_agg(
           coalesce(device_label, 'Unknown device') || ' (' ||
           case when last_seen > now() - interval '1 minute' then 'active now'
                else 'last active ' || greatest(1, (extract(epoch from now() - last_seen) / 60)::int) || ' min ago' end
           || ')', ', ' order by last_seen desc)
  from public.sessions where employee_id = e and expires_at > now()
$$;

-- ---- wrong-password rate limit -------------------------------------
create or replace function app_private.throttle_locked(p_scope text, p_key text) returns text
  language plpgsql security definer set search_path = public, pg_temp as $$
declare lu timestamptz;
begin
  select locked_until into lu from app_private.auth_attempts where scope = p_scope and key = p_key;
  if lu is not null and lu > now() then
    return 'Too many wrong attempts. Try again in ' ||
           greatest(1, ceil(extract(epoch from lu - now()) / 60)::int) || ' minute(s).';
  end if;
  return null;
end $$;

create or replace function app_private.throttle_fail(p_scope text, p_key text, p_max int, p_lock_min int) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
declare r app_private.auth_attempts; nf int;
begin
  insert into app_private.auth_attempts (scope, key) values (p_scope, p_key) on conflict do nothing;
  select * into r from app_private.auth_attempts where scope = p_scope and key = p_key for update;
  if r.window_start < now() - interval '15 minutes' then
    r.fails := 0; r.window_start := now();
  end if;
  nf := r.fails + 1;
  update app_private.auth_attempts
  set fails        = case when nf >= p_max then 0 else nf end,
      window_start = r.window_start,
      locked_until = case when nf >= p_max then now() + make_interval(mins => p_lock_min) else locked_until end
  where scope = p_scope and key = p_key;
end $$;

create or replace function app_private.throttle_ok(p_scope text, p_key text) returns void
  language sql security definer set search_path = public, pg_temp as $$
  delete from app_private.auth_attempts where scope = p_scope and key = p_key
$$;

-- ---- auto sign-out ---------------------------------------------------
-- Closes every open sign-in dated <= p_through by recording a 23:59 sign-out.
create or replace function app_private.auto_signout(p_through date) returns int
  language sql security definer set search_path = public, pg_temp as $$
  with ins as (
    insert into public.attendance (employee_id, date, time, status, auto_signout, source)
    select a.employee_id, a.date, time '23:59:00', 'sign_out', true, 'self'
    from public.attendance a
    where a.status = 'sign_in'
      and a.date <= p_through
      and not exists (
        select 1 from public.attendance o
        where o.employee_id = a.employee_id and o.date = a.date and o.status = 'sign_out')
    on conflict do nothing
    returning 1
  )
  select count(*)::int from ins
$$;

create or replace function app_private.admin_check(p_token uuid) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if p_token is null or not exists (
    select 1 from app_private.admin_sessions where token = p_token and expires_at > now()
  ) then
    raise exception 'Admin session expired. Please log in again.' using errcode = 'AU002';
  end if;
end $$;


-- ====================================================================
-- STEP 6 — EMPLOYEE LOGIN / LOGOUT  (return {ok:false, code, message} on
--          expected problems so wrong-password counting is not rolled back)
-- ====================================================================

create or replace function public.emp_register(
  p_name text, p_password text, p_device text, p_device_label text default null
) returns json
  language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare
  e   public.employees;
  tok uuid;
  n   text := app_private.norm_name(p_name);
  pw  text := btrim(coalesce(p_password, ''));
begin
  if length(n) < 2 then
    return app_private.fail('NAME_REQUIRED', 'Enter your full name (at least 2 characters).');
  end if;
  if length(pw) < 4 then
    return app_private.fail('PASSWORD_SHORT', 'Password must be at least 4 characters (spaces at the start or end are ignored).');
  end if;
  if p_device is null or length(p_device) < 8 then
    return app_private.fail('BAD_DEVICE', 'This device could not be identified. Reload the page and try again.');
  end if;

  select * into e from public.employees where app_private.norm_name(name) = n for update;
  if not found then
    return app_private.fail('NAME_NOT_FOUND',
      'The name "' || btrim(p_name) || '" has not been added by admin. Check the spelling or ask admin to add you first.');
  end if;
  if e.active is not true then
    return app_private.fail('DEACTIVATED', 'This account is deactivated. Contact admin.');
  end if;
  if e.password_hash is not null then
    return app_private.fail('ALREADY_REGISTERED',
      'An account already exists for "' || e.name || '". Go back and log in. If you forgot the password, ask admin to reset it.');
  end if;
  if app_private.device_conflict(p_device, e.id) then
    return app_private.fail('DEVICE_USED_BY_OTHER',
      'This device was already used to sign in for another employee today. Use your own phone or ask admin.');
  end if;

  update public.employees set password_hash = crypt(pw, gen_salt('bf', 10)) where id = e.id;
  delete from public.sessions where employee_id = e.id;
  insert into public.sessions (employee_id, device_id, device_label)
  values (e.id, p_device, left(p_device_label, 60))
  returning token into tok;

  return json_build_object('ok', true, 'token', tok, 'name', e.name, 'id', e.id);
end $$;


create or replace function public.emp_login(
  p_name text, p_password text, p_device text, p_device_label text default null
) returns json
  language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare
  e        public.employees;
  tok      uuid;
  n        text := app_private.norm_name(p_name);
  lock_msg text;
  maxd     int  := greatest(1, coalesce(app_private.cfg('max_devices', '2')::int, 2));
  idle     interval := make_interval(mins => greatest(1, coalesce(app_private.cfg('session_idle_minutes', '10')::int, 10)));
  used     int;
  pw_ok    boolean;
begin
  if n = '' then
    return app_private.fail('NAME_REQUIRED', 'Enter your name.');
  end if;
  if coalesce(p_password, '') = '' then
    return app_private.fail('PASSWORD_REQUIRED', 'Enter your password.');
  end if;
  if p_device is null or length(p_device) < 8 then
    return app_private.fail('BAD_DEVICE', 'This device could not be identified. Reload the page and try again.');
  end if;

  lock_msg := app_private.throttle_locked('emp', n);
  if lock_msg is not null then
    return app_private.fail('LOCKED', lock_msg);
  end if;

  select * into e from public.employees where app_private.norm_name(name) = n for update;
  if not found then
    return app_private.fail('NAME_NOT_FOUND',
      'No employee named "' || btrim(p_name) || '" was found. Type the name exactly as admin added it.');
  end if;
  if e.active is not true then
    return app_private.fail('DEACTIVATED', 'This account is deactivated. Contact admin.');
  end if;
  if e.password_hash is null then
    return app_private.fail('NOT_REGISTERED', 'This account has no password yet. Tap "First time? Create your account".');
  end if;

  -- exact password, or the same password without stray spaces (phone keyboards)
  pw_ok := e.password_hash = crypt(p_password, e.password_hash)
        or (btrim(p_password) <> p_password and e.password_hash = crypt(btrim(p_password), e.password_hash));
  if not pw_ok then
    perform app_private.throttle_fail('emp', n, 10, 5);
    return app_private.fail('WRONG_PASSWORD', 'Wrong password for "' || e.name || '". Try again.');
  end if;
  perform app_private.throttle_ok('emp', n);

  if app_private.device_conflict(p_device, e.id) then
    return app_private.fail('DEVICE_USED_BY_OTHER',
      'This device was already used to sign in for another employee today. Use your own phone or ask admin.');
  end if;

  -- housekeeping: expired sessions, this device's old login, idle devices
  delete from public.sessions where expires_at < now();
  delete from public.sessions where employee_id = e.id and device_id = p_device;
  delete from public.sessions where employee_id = e.id and last_seen < now() - idle;
  perform app_private.auto_signout(app_private.ist_today() - 1);

  select count(*) into used from public.sessions where employee_id = e.id;
  if used >= maxd then
    return app_private.fail('DEVICE_LIMIT',
      'You are already logged in on ' || used || ' device(s): ' || app_private.devices_text(e.id) ||
      '. Log out on one of them, wait until it has been idle for ' || (extract(epoch from idle) / 60)::int ||
      ' minutes, or ask admin to clear your login.');
  end if;

  insert into public.sessions (employee_id, device_id, device_label)
  values (e.id, p_device, left(p_device_label, 60))
  returning token into tok;

  return json_build_object('ok', true, 'token', tok, 'name', e.name, 'id', e.id);
end $$;


-- Logout removes the session row right away.
create or replace function public.emp_logout(p_token uuid) returns void
  language sql security definer set search_path = public, pg_temp as $$
  delete from public.sessions where token = p_token
$$;

create or replace function public.emp_me(p_token uuid) returns json
  language plpgsql security definer set search_path = public, pg_temp as $$
declare e public.employees; eid uuid := app_private.session_emp(p_token);
begin
  select * into e from public.employees where employees.id = eid;
  return json_build_object('id', e.id, 'name', e.name);
end $$;


-- ====================================================================
-- STEP 7 — ATTENDANCE
-- ====================================================================

-- Also acts as the heartbeat: the dashboard calls it every 30 s.
create or replace function public.day_info(p_token uuid) returns json
  language plpgsql security definer set search_path = public, pg_temp as $$
declare
  e  uuid := app_private.session_emp(p_token);
  d  date := app_private.ist_today();
  si time;
  so time;
  st text := 'none';
begin
  perform app_private.auto_signout(d - 1);
  select time into si from public.attendance where employee_id = e and date = d and status = 'sign_in';
  select time into so from public.attendance where employee_id = e and date = d and status = 'sign_out';
  if app_private.on_leave(e, d) then st := 'leave';
  elsif so is not null then st := 'signed_out';
  elsif si is not null then st := 'signed_in';
  end if;
  return json_build_object('now', now(), 'status', st, 'sign_in', si, 'sign_out', so);
end $$;


create or replace function public.mark_attendance(
  p_token uuid, p_kind text, p_lat float8, p_lng float8, p_device text, p_accuracy float8 default null
) returns text
  language plpgsql security definer set search_path = public, pg_temp as $$
declare
  e      uuid := app_private.session_emp(p_token);
  d      date := app_private.ist_today();
  t      time := app_private.ist_now_time();
  sdev   text;
  dist   float8;
  radius float8 := coalesce(app_private.cfg('office_radius_m', '50')::float8, 50);
  allow  float8 := coalesce(app_private.cfg('accuracy_allowance_m', '20')::float8, 0);
  maxacc float8 := coalesce(app_private.cfg('max_accuracy_m', '150')::float8, 150);
  acc    float8 := greatest(coalesce(p_accuracy, 0), 0);
begin
  if p_device is null or length(p_device) < 8 then
    raise exception 'This device could not be identified. Reload the page and try again.';
  end if;
  select device_id into sdev from public.sessions where token = p_token;
  if sdev is distinct from p_device then
    raise exception 'Not logged in: this login belongs to a different device. Please log out and log in again on this device.'
      using errcode = 'AU001';
  end if;
  if p_kind not in ('sign_in', 'sign_out') then
    raise exception 'Bad request.';
  end if;
  if app_private.on_leave(e, d) then
    raise exception 'You are on approved leave today. Cancel your leave before marking attendance.';
  end if;

  -- location is compulsory for BOTH sign in and sign out
  if p_lat is null or p_lng is null then
    raise exception 'Location is required. Allow location access in your browser and try again.';
  end if;
  if p_lat not between -90 and 90 or p_lng not between -180 and 180 then
    raise exception 'Your device sent an invalid location. Turn GPS off and on, then try again.';
  end if;
  if p_lat = 0 and p_lng = 0 then
    raise exception 'Your device reported an empty location (0, 0). Turn GPS on, wait a few seconds and try again.';
  end if;
  if p_accuracy is not null and p_accuracy > maxacc then
    raise exception 'GPS accuracy is too low (±% m; needs ±% m or better). Move near a window or outdoors, switch on high-accuracy location and try again.',
      round(p_accuracy)::int, round(maxacc)::int;
  end if;

  dist := app_private.office_distance(p_lat, p_lng);
  if dist - least(acc, allow) > radius then
    raise exception 'You are about % m from the office (allowed: within % m%). Sign In and Sign Out only work at the office.',
      round(dist)::int, round(radius)::int,
      case when p_accuracy is null then '' else '; your GPS accuracy was ±' || round(acc)::int || ' m' end;
  end if;

  if p_kind = 'sign_in' then
    if exists (select 1 from public.attendance where employee_id = e and date = d and status = 'sign_in') then
      raise exception 'You have already signed in today.';
    end if;
    if app_private.device_conflict(p_device, e) then
      raise exception 'This device was already used to sign in for another employee today.';
    end if;
  else
    if not exists (select 1 from public.attendance where employee_id = e and date = d and status = 'sign_in') then
      raise exception 'Sign in first.';
    end if;
    if exists (select 1 from public.attendance where employee_id = e and date = d and status = 'sign_out') then
      raise exception 'You have already signed out today.';
    end if;
  end if;

  begin
    insert into public.attendance (employee_id, date, time, status, lat, lng, device_id, accuracy_m)
    values (e, d, t, p_kind, p_lat, p_lng, p_device, p_accuracy);
  exception when unique_violation then
    raise exception 'You have already % today.', case when p_kind = 'sign_in' then 'signed in' else 'signed out' end;
  end;

  return initcap(replace(p_kind, '_', ' ')) || ' successful at ' || t;
end $$;


-- ====================================================================
-- STEP 8 — LEAVE
-- ====================================================================

create or replace function public.request_leave(
  p_token uuid, p_type text, p_start date, p_end date, p_reason text
) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
declare e uuid := app_private.session_emp(p_token);
begin
  if p_type not in ('single_day', 'long_leave') then raise exception 'Invalid leave type.'; end if;
  if p_type = 'single_day' then p_end := p_start; end if;
  if p_start is null or p_end is null then raise exception 'Select the leave dates.'; end if;
  if p_end < p_start then raise exception 'End date cannot be before the start date.'; end if;
  if p_start < app_private.ist_today() then raise exception 'You cannot request leave for a past date.'; end if;
  if p_end > app_private.ist_today() + 366 then raise exception 'Leave cannot be requested more than a year ahead.'; end if;
  if exists (
    select 1 from public.leave_requests
    where employee_id = e and status in ('pending', 'approved')
      and start_date <= p_end and end_date >= p_start
  ) then
    raise exception 'You already have a pending or approved leave overlapping these dates.';
  end if;
  insert into public.leave_requests (employee_id, leave_type, start_date, end_date, reason)
  values (e, p_type, p_start, p_end, nullif(left(btrim(p_reason), 500), ''));
end $$;

create or replace function public.cancel_leave(p_token uuid, p_id uuid) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
declare
  e uuid := app_private.session_emp(p_token);
  r public.leave_requests;
  d date := app_private.ist_today();
begin
  select * into r from public.leave_requests where id = p_id and employee_id = e;
  if not found then raise exception 'Leave request not found.'; end if;
  if r.status not in ('pending', 'approved') then
    raise exception 'This leave is already %.', r.status;
  end if;
  if r.status = 'approved' then
    if r.end_date < d then raise exception 'A past leave cannot be cancelled.'; end if;
    if r.start_date <= d and exists (
      select 1 from public.attendance where employee_id = e and date = d and status = 'sign_in'
    ) then
      raise exception 'Today''s leave cannot be cancelled after you have signed in.';
    end if;
  end if;
  update public.leave_requests
  set status = 'cancelled', cancelled_at = now(),
      cancelled_by = (select name from public.employees where id = e)
  where id = p_id;
end $$;

create or replace function public.my_leaves(p_token uuid) returns json
  language plpgsql security definer set search_path = public, pg_temp as $$
declare e uuid := app_private.session_emp(p_token);
begin
  return coalesce((
    select json_agg(x order by x.created_at desc)
    from (
      select id, leave_type, start_date, end_date, reason, status, created_at
      from public.leave_requests where employee_id = e
    ) x
  ), '[]'::json);
end $$;


-- ====================================================================
-- STEP 9 — ADMIN
-- ====================================================================

create or replace function public.admin_login(pw text) returns json
  language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare
  h        text;
  tok      uuid;
  lock_msg text := app_private.throttle_locked('admin', 'admin');
begin
  if lock_msg is not null then return app_private.fail('LOCKED', lock_msg); end if;
  if coalesce(pw, '') = '' then return app_private.fail('PASSWORD_REQUIRED', 'Enter the admin password.'); end if;
  select value into h from public.config where key = 'admin_password_hash';
  if h is null or h <> crypt(pw, h) then
    perform app_private.throttle_fail('admin', 'admin', 5, 15);
    return app_private.fail('WRONG_PASSWORD', 'Wrong admin password.');
  end if;
  perform app_private.throttle_ok('admin', 'admin');
  delete from app_private.admin_sessions where expires_at < now();
  insert into app_private.admin_sessions default values returning token into tok;
  return json_build_object('ok', true, 'token', tok);
end $$;

create or replace function public.admin_logout(p_token uuid) returns void
  language sql security definer set search_path = public, pg_temp as $$
  delete from app_private.admin_sessions where token = p_token
$$;

create or replace function public.admin_data(p_token uuid) returns json
  language plpgsql security definer set search_path = public, pg_temp as $$
begin
  perform app_private.admin_check(p_token);
  perform app_private.auto_signout(app_private.ist_today() - 1);
  return json_build_object(
    'now', now(),
    'config', (
      select coalesce(json_object_agg(key, value), '{}'::json)
      from public.config where key <> 'admin_password_hash'
    ),
    'employees', (
      select coalesce(json_agg(json_build_object(
        'id', e.id, 'name', e.name,
        'registered', e.password_hash is not null,
        'active', e.active, 'notes', e.notes, 'created_at', e.created_at,
        'devices', (
          select coalesce(json_agg(json_build_object(
            'label', coalesce(s.device_label, 'Unknown device'),
            'last_seen', s.last_seen,
            'online', s.last_seen > now() - interval '2 minutes'
          ) order by s.last_seen desc), '[]'::json)
          from public.sessions s where s.employee_id = e.id and s.expires_at > now()
        )
      ) order by e.name), '[]'::json)
      from public.employees e
    ),
    'leaves', (
      select coalesce(json_agg(x), '[]'::json)
      from (
        select l.*, emp.name
        from public.leave_requests l join public.employees emp on emp.id = l.employee_id
        order by l.created_at desc limit 500
      ) x
    ),
    'attendance', (
      select coalesce(json_agg(a), '[]'::json)
      from (
        select a.id, a.date, a.time, a.status, a.auto_signout, a.source, a.note,
               a.accuracy_m, emp.name, emp.id as employee_id
        from public.attendance a join public.employees emp on emp.id = a.employee_id
        order by a.date desc, a.time desc limit 5000
      ) a
    )
  );
end $$;

create or replace function public.admin_leave_action(p_token uuid, p_id uuid, p_action text) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
declare n int;
begin
  perform app_private.admin_check(p_token);
  if p_action = 'approve' then
    update public.leave_requests set status = 'approved', approved_by = 'admin', approved_at = now()
    where id = p_id and status = 'pending';
  elsif p_action = 'reject' then
    update public.leave_requests set status = 'rejected', approved_by = 'admin', approved_at = now()
    where id = p_id and status = 'pending';
  elsif p_action = 'cancel' then
    update public.leave_requests set status = 'cancelled', cancelled_at = now(), cancelled_by = 'admin'
    where id = p_id and status in ('pending', 'approved');
  else
    raise exception 'Unknown action.';
  end if;
  get diagnostics n = row_count;
  if n = 0 then raise exception 'This request was already handled or no longer exists. Refresh the page.'; end if;
end $$;

create or replace function public.admin_add_employee(p_token uuid, p_name text) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
declare n text := btrim(regexp_replace(coalesce(p_name, ''), '\s+', ' ', 'g'));
begin
  perform app_private.admin_check(p_token);
  if length(n) < 2 then raise exception 'Enter a name (at least 2 characters).'; end if;
  if length(n) > 80 then raise exception 'Name is too long.'; end if;
  insert into public.employees (name) values (n);
exception when unique_violation then
  raise exception 'An employee with this name already exists.';
end $$;

create or replace function public.admin_del_employee(p_token uuid, p_id uuid) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
begin
  perform app_private.admin_check(p_token);
  delete from public.employees where id = p_id;
  if not found then raise exception 'Employee not found.'; end if;
end $$;

create or replace function public.admin_reset_password(p_token uuid, p_id uuid) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
begin
  perform app_private.admin_check(p_token);
  update public.employees set password_hash = null where id = p_id;
  if not found then raise exception 'Employee not found.'; end if;
  delete from public.sessions where employee_id = p_id;
end $$;

create or replace function public.admin_clear_sessions(p_token uuid, p_id uuid) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
begin
  perform app_private.admin_check(p_token);
  delete from public.sessions where employee_id = p_id;
end $$;

create or replace function public.admin_set_employee_active(p_token uuid, p_id uuid, p_active boolean) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
begin
  perform app_private.admin_check(p_token);
  update public.employees set active = coalesce(p_active, true) where id = p_id;
  if not found then raise exception 'Employee not found.'; end if;
  if not coalesce(p_active, true) then
    delete from public.sessions where employee_id = p_id;
  end if;
end $$;

-- Manual correction (forgot to sign in/out). Either time may be null.
create or replace function public.admin_set_attendance(
  p_token uuid, p_employee_id uuid, p_date date, p_sign_in time, p_sign_out time, p_note text default null
) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
begin
  perform app_private.admin_check(p_token);
  if p_employee_id is null or p_date is null then raise exception 'Choose an employee and a date.'; end if;
  if not exists (select 1 from public.employees where id = p_employee_id) then raise exception 'Employee not found.'; end if;
  if p_sign_in is null and p_sign_out is null then raise exception 'Enter a sign-in time, a sign-out time, or both.'; end if;
  if p_sign_in is not null and p_sign_out is not null and p_sign_out < p_sign_in then
    raise exception 'Sign-out cannot be earlier than sign-in.';
  end if;
  if p_sign_in is not null then
    insert into public.attendance (employee_id, date, time, status, source, note)
    values (p_employee_id, p_date, p_sign_in, 'sign_in', 'admin', nullif(btrim(p_note), ''))
    on conflict (employee_id, date, status) do update
      set time = excluded.time, source = 'admin', auto_signout = false,
          note = coalesce(excluded.note, public.attendance.note);
  end if;
  if p_sign_out is not null then
    insert into public.attendance (employee_id, date, time, status, source, note)
    values (p_employee_id, p_date, p_sign_out, 'sign_out', 'admin', nullif(btrim(p_note), ''))
    on conflict (employee_id, date, status) do update
      set time = excluded.time, source = 'admin', auto_signout = false,
          note = coalesce(excluded.note, public.attendance.note);
  end if;
end $$;

create or replace function public.admin_clear_attendance(p_token uuid, p_employee_id uuid, p_date date) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
begin
  perform app_private.admin_check(p_token);
  delete from public.attendance where employee_id = p_employee_id and date = p_date;
  if not found then raise exception 'There is no attendance on that date for this employee.'; end if;
end $$;

create or replace function public.admin_update_config(p_token uuid, p_key text, p_value text) returns void
  language plpgsql security definer set search_path = public, pg_temp as $$
declare v text := btrim(coalesce(p_value, '')); x numeric;
begin
  perform app_private.admin_check(p_token);
  if p_key not in ('company_name','office_lat','office_lng','office_radius_m','accuracy_allowance_m',
                   'max_accuracy_m','max_devices','session_idle_minutes','one_device_one_employee') then
    raise exception 'Unknown setting.';
  end if;
  if p_key = 'company_name' then
    if length(v) < 1 or length(v) > 80 then raise exception 'Company name must be 1-80 characters.'; end if;
  elsif p_key = 'one_device_one_employee' then
    if v not in ('on', 'off') then raise exception 'Value must be on or off.'; end if;
  else
    if v !~ '^-?[0-9]+(\.[0-9]+)?$' then raise exception 'Enter a number for %.', p_key; end if;
    x := v::numeric;
    if p_key = 'office_lat'            and x not between -90 and 90      then raise exception 'Latitude must be between -90 and 90.'; end if;
    if p_key = 'office_lng'            and x not between -180 and 180    then raise exception 'Longitude must be between -180 and 180.'; end if;
    if p_key = 'office_radius_m'       and x not between 5 and 5000      then raise exception 'Radius must be between 5 and 5000 metres.'; end if;
    if p_key = 'accuracy_allowance_m'  and x not between 0 and 200       then raise exception 'Allowance must be between 0 and 200 metres.'; end if;
    if p_key = 'max_accuracy_m'        and x not between 10 and 2000     then raise exception 'Max accuracy must be between 10 and 2000 metres.'; end if;
    if p_key = 'max_devices'           and (x not between 1 and 10 or x <> trunc(x)) then raise exception 'Devices must be a whole number from 1 to 10.'; end if;
    if p_key = 'session_idle_minutes'  and (x not between 1 and 1440 or x <> trunc(x)) then raise exception 'Idle minutes must be a whole number from 1 to 1440.'; end if;
  end if;
  insert into public.config (key, value) values (p_key, v)
  on conflict (key) do update set value = excluded.value;
end $$;

create or replace function public.admin_change_password(p_token uuid, p_new_password text) returns void
  language plpgsql security definer set search_path = public, extensions, pg_temp as $$
begin
  perform app_private.admin_check(p_token);
  if p_new_password is null or length(btrim(p_new_password)) < 8 then
    raise exception 'New password must be at least 8 characters.';
  end if;
  update public.config set value = crypt(btrim(p_new_password), gen_salt('bf', 10))
  where key = 'admin_password_hash';
  -- other admin logins are signed out; keep none so the new password is required everywhere
  delete from app_private.admin_sessions where token <> p_token;
end $$;


-- ====================================================================
-- STEP 10 — PERMISSIONS: only the functions above are reachable from the
--           browser; all tables and every app_private object are locked.
-- ====================================================================

do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure as sig
    from pg_proc p
    where p.pronamespace = 'public'::regnamespace
      and p.proname = any (array[
        'emp_register','emp_login','emp_logout','emp_me','day_info','mark_attendance',
        'request_leave','cancel_leave','my_leaves',
        'admin_login','admin_logout','admin_data','admin_leave_action','admin_add_employee',
        'admin_del_employee','admin_reset_password','admin_clear_sessions',
        'admin_set_employee_active','admin_set_attendance','admin_clear_attendance',
        'admin_update_config','admin_change_password'
      ])
  loop
    execute 'revoke all on function ' || r.sig || ' from public, anon, authenticated';
    execute 'grant execute on function ' || r.sig || ' to anon, authenticated';
  end loop;

  for r in select p.oid::regprocedure as sig from pg_proc p where p.pronamespace = 'app_private'::regnamespace
  loop
    execute 'revoke all on function ' || r.sig || ' from public, anon, authenticated';
  end loop;
end $$;


-- ====================================================================
-- STEP 11 — AUTO SIGN-OUT AT 23:59 IST
--   Needs pg_cron (Dashboard -> Database -> Extensions -> pg_cron).
--   Without it the app still closes yesterday's open sign-ins automatically
--   the next time anyone logs in or the admin opens the console.
-- ====================================================================

do $$
begin
  begin
    create extension if not exists pg_cron;
  exception when others then
    raise notice 'pg_cron could not be enabled automatically (%). Enable it in Dashboard -> Database -> Extensions for exact 23:59 auto sign-out.', sqlerrm;
  end;
  begin
    perform cron.unschedule(jobid) from cron.job where jobname = 'auto-signout';
    perform cron.schedule('auto-signout', '29 18 * * *',            -- 18:29 UTC = 23:59 IST
                          'select app_private.auto_signout(app_private.ist_today())');
  exception when others then
    raise notice 'Auto sign-out cron job not scheduled: %', sqlerrm;
  end;
end $$;


select 'Attendance schema v3 installed.' as result;


-- ====================================================================
-- RECOVERY SNIPPETS (run separately when needed, not part of the install)
--
-- RESET ADMIN PASSWORD:
--   update public.config
--      set value = extensions.crypt('your-new-password', extensions.gen_salt('bf', 10))
--    where key = 'admin_password_hash';
--
-- LOG EVERYONE OUT:                delete from public.sessions;
-- ALLOW ONE PHONE FOR TWO PEOPLE:  update public.config set value='off' where key='one_device_one_employee';
-- ALLOW 3 DEVICES PER EMPLOYEE:    update public.config set value='3'   where key='max_devices';
-- ====================================================================
