-- ============================================================
-- Prithvi Realcon Transport — MIGRATION v2
--
-- Run this ONCE in the Supabase SQL editor on your existing database.
-- (For a brand-new database: run schema.sql first, then this file.)
--
-- Before running:
--   Supabase dashboard → Database → Extensions → enable "pg_cron"
--
-- What this adds:
--   1. Office location is compulsory for BOTH Sign In and Sign Out
--   2. Auto Sign Out at 23:59 IST for anyone who forgot to sign out
--   3. One login per employee at a time (one device only)
--   4. A device that signed in for one employee today cannot be
--      used to sign in / log in for any other employee today
--   5. Admin can clear an employee's login (for lost phones)
-- ============================================================


-- ---------- 1. new columns ----------
alter table sessions   add column if not exists device_id text;
alter table attendance add column if not exists device_id text;
alter table attendance add column if not exists auto_signout boolean not null default false;


-- ---------- 2. remove old function versions (signatures changed) ----------
drop function if exists emp_register(text, text);
drop function if exists emp_login(text, text);
drop function if exists mark_attendance(uuid, text, float, float);


-- ---------- 3. helpers ----------

-- Distance in metres from the office
create or replace function office_distance(p_lat float, p_lng float) returns float
  language plpgsql security definer set search_path = public as $$
declare
  olat float;
  olng float;
begin
  olat := cfg('office_lat')::float;
  olng := cfg('office_lng')::float;
  return 6371000 * 2 * asin(sqrt(
    sin(radians(p_lat - olat) / 2) ^ 2 +
    cos(radians(olat)) * cos(radians(p_lat)) * sin(radians(p_lng - olng) / 2) ^ 2
  ));
end $$;

-- True if this device already signed in today for a DIFFERENT employee
create or replace function device_used_by_other(p_device text, e uuid) returns boolean
  language sql security definer set search_path = public as $$
  select exists (
    select 1 from attendance
    where device_id = p_device
      and date = ist_today()
      and status = 'sign_in'
      and employee_id <> e
  )
$$;

-- Checks run before any login / register is allowed
create or replace function check_device_login(e uuid, p_device text) returns void
  language plpgsql security definer set search_path = public as $$
begin
  -- employee already logged in on another device
  if exists (
    select 1 from sessions
    where employee_id = e
      and expires_at > now()
      and device_id is distinct from p_device
  ) then
    raise exception 'You are already logged in on another device. Log out there first, or ask admin to clear your login.';
  end if;

  -- this device was used to sign in for someone else today
  if device_used_by_other(p_device, e) then
    raise exception 'This device was already used to sign in for another employee today.';
  end if;
end $$;


-- ---------- 4. employee auth (with device + single login) ----------

create or replace function emp_register(p_name text, p_password text, p_device text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare
  e employees;
  tok uuid;
  n text := lower(trim(p_name));
begin
  if n is null or length(n) < 2 then
    raise exception 'Enter a valid name';
  end if;
  if p_password is null or length(p_password) < 4 then
    raise exception 'Password must be at least 4 characters';
  end if;
  if p_device is null or length(p_device) < 8 then
    raise exception 'Device not recognised. Please reload the page and try again.';
  end if;

  select * into e from employees where lower(trim(name)) = n;
  if not found then
    raise exception 'This name is not registered by admin. Ask admin to add you first.';
  end if;
  if e.password_hash is not null then
    raise exception 'Account already exists. Please log in.';
  end if;

  perform check_device_login(e.id, p_device);

  update employees
  set password_hash = crypt(p_password, gen_salt('bf'))
  where id = e.id;

  delete from sessions where employee_id = e.id;

  insert into sessions (employee_id, device_id) values (e.id, p_device)
  returning token into tok;

  return json_build_object('token', tok, 'name', e.name, 'id', e.id);
end $$;

create or replace function emp_login(p_name text, p_password text, p_device text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare
  e employees;
  tok uuid;
  n text := lower(trim(p_name));
begin
  if n is null or length(n) < 1 then
    raise exception 'Enter name';
  end if;
  if p_password is null or length(p_password) < 1 then
    raise exception 'Enter password';
  end if;
  if p_device is null or length(p_device) < 8 then
    raise exception 'Device not recognised. Please reload the page and try again.';
  end if;

  select * into e from employees where lower(trim(name)) = n;
  if not found then
    raise exception 'Wrong name or password';
  end if;
  if e.password_hash is null then
    raise exception 'Account not created yet. Use "Create account" first.';
  end if;
  if e.password_hash <> crypt(p_password, e.password_hash) then
    raise exception 'Wrong name or password';
  end if;

  perform check_device_login(e.id, p_device);

  -- one session per employee: replace any old one (same device re-login)
  delete from sessions where employee_id = e.id;

  insert into sessions (employee_id, device_id) values (e.id, p_device)
  returning token into tok;

  return json_build_object('token', tok, 'name', e.name, 'id', e.id);
end $$;


-- ---------- 5. attendance (location for both, device bound) ----------

create or replace function mark_attendance(p_token uuid, p_kind text, p_lat float, p_lng float, p_device text) returns text
  language plpgsql security definer set search_path = public as $$
declare
  e uuid := emp_from_token(p_token);
  d date := ist_today();
  t time := ist_now_time();
  dist float;
  radius float;
begin
  if e is null then raise exception 'Not logged in'; end if;
  if p_device is null or length(p_device) < 8 then
    raise exception 'Device not recognised. Please reload the page and try again.';
  end if;
  if p_kind not in ('sign_in', 'sign_out') then
    raise exception 'Bad request';
  end if;
  if on_leave(e, d) then
    raise exception 'You are on approved leave today. Cancel your leave before marking attendance.';
  end if;

  -- location is compulsory for BOTH sign in and sign out
  if p_lat is null or p_lng is null then
    raise exception 'Location is required. Allow location access and try again.';
  end if;
  radius := coalesce(cfg('office_radius_m')::float, 50);
  dist := office_distance(p_lat, p_lng);
  if dist > radius then
    raise exception 'You are too far from the office (% m). Allowed only within % m.',
      round(dist), round(radius);
  end if;

  if p_kind = 'sign_in' then
    if exists (select 1 from attendance where employee_id = e and date = d and status = 'sign_in') then
      raise exception 'Already signed in today';
    end if;
    if device_used_by_other(p_device, e) then
      raise exception 'This device was already used to sign in for another employee today.';
    end if;
  else
    if not exists (select 1 from attendance where employee_id = e and date = d and status = 'sign_in') then
      raise exception 'Sign in first';
    end if;
    if exists (select 1 from attendance where employee_id = e and date = d and status = 'sign_out') then
      raise exception 'Already signed out today';
    end if;
  end if;

  insert into attendance (employee_id, date, time, status, lat, lng, device_id)
  values (e, d, t, p_kind, p_lat, p_lng, p_device);

  return initcap(replace(p_kind, '_', ' ')) || ' successful at ' || t;
end $$;


-- ---------- 6. auto sign out at 23:59 IST ----------

-- Closes every open sign-in (today, or left open on an earlier day)
-- by recording a sign-out at 23:59 of that day.
create or replace function auto_signout_all() returns int
  language sql security definer set search_path = public as $$
  with ins as (
    insert into attendance (employee_id, date, time, status, auto_signout)
    select a.employee_id, a.date, time '23:59:00', 'sign_out', true
    from attendance a
    where a.status = 'sign_in'
      and a.date <= ist_today()
      and not exists (
        select 1 from attendance o
        where o.employee_id = a.employee_id
          and o.date = a.date
          and o.status = 'sign_out'
      )
    returning 1
  )
  select count(*)::int from ins
$$;

-- 23:59 IST = 18:29 UTC, every day
do $$ begin
  perform cron.unschedule('auto-signout');
exception when others then
  null;
end $$;

select cron.schedule('auto-signout', '29 18 * * *', 'select auto_signout_all();');


-- ---------- 7. admin ----------

-- Admin view now also shows which sign-outs were automatic
create or replace function admin_data(pw text) returns json
  language plpgsql security definer set search_path = public as $$
begin
  perform chk(pw);
  return json_build_object(
    'employees', (
      select coalesce(json_agg(
        json_build_object(
          'id', e.id,
          'name', e.name,
          'registered', (e.password_hash is not null),
          'created_at', e.created_at
        ) order by e.name
      ), '[]')
      from employees e
    ),
    'leaves', (
      select coalesce(json_agg(x), '[]')
      from (
        select l.*, emp.name
        from leave_requests l
        join employees emp on emp.id = l.employee_id
        order by l.created_at desc
        limit 500
      ) x
    ),
    'attendance', (
      select coalesce(json_agg(a), '[]')
      from (
        select a.id, a.date, a.time, a.status, a.auto_signout, emp.name
        from attendance a
        join employees emp on emp.id = a.employee_id
        order by a.date desc, a.time desc
        limit 5000
      ) a
    )
  );
end $$;

-- Admin: log an employee out of every device (lost phone, stuck login)
create or replace function admin_clear_sessions(pw text, p_id uuid) returns void
  language plpgsql security definer set search_path = public as $$
begin
  perform chk(pw);
  delete from sessions where employee_id = p_id;
end $$;
