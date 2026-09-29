-- ============================================================
-- Prithvi Realcon Transport — simple name + password auth
-- Run this in Supabase SQL editor.
--
-- No email. No Supabase Auth for employees.
-- Admin adds a name → employee registers with that name + password
-- → login with name + password.
-- ============================================================

-- Enable password hashing (Supabase puts it in the "extensions" schema)
create extension if not exists pgcrypto with schema extensions;

-- ---------- tables ----------
create table if not exists employees (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  password_hash text,                          -- null = not registered yet
  created_at timestamptz default now()
);

-- Case-insensitive unique name
create unique index if not exists employees_name_unique
  on employees (lower(trim(name)));

create table if not exists sessions (
  token uuid primary key default gen_random_uuid(),
  employee_id uuid not null references employees(id) on delete cascade,
  created_at timestamptz default now(),
  expires_at timestamptz not null default (now() + interval '30 days')
);

create table if not exists config (
  key text primary key,
  value text
);

-- CHANGE THIS after first deploy
insert into config values ('admin_password', 'CHANGE_ME_NOW') on conflict do nothing;
insert into config values ('office_lat', '21.2758151') on conflict do nothing;
insert into config values ('office_lng', '81.6322723') on conflict do nothing;
insert into config values ('office_radius_m', '50') on conflict do nothing;

create table if not exists attendance (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references employees(id) on delete cascade,
  date date not null,
  time time not null,
  status text not null check (status in ('sign_in', 'sign_out')),
  lat float,
  lng float,
  created_at timestamptz default now(),
  unique (employee_id, date, status)
);

create table if not exists leave_requests (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references employees(id) on delete cascade,
  leave_type text not null check (leave_type in ('single_day', 'long_leave')),
  start_date date not null,
  end_date date not null,
  reason text,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'cancelled')),
  approved_by text,
  approved_at timestamptz,
  cancelled_at timestamptz,
  cancelled_by text,
  created_at timestamptz default now(),
  check (end_date >= start_date)
);

-- Drop old unused table if present
drop table if exists time_change_requests;

-- ---------- RLS (all access via security-definer functions) ----------
alter table employees enable row level security;
alter table sessions enable row level security;
alter table config enable row level security;
alter table attendance enable row level security;
alter table leave_requests enable row level security;

-- No direct client policies — everything goes through RPCs below.

-- ---------- helpers ----------
create or replace function cfg(k text) returns text
  language sql security definer set search_path = public as $$
  select value from config where key = k
$$;

create or replace function ist_today() returns date
  language sql stable as $$
  select (now() at time zone 'Asia/Kolkata')::date
$$;

create or replace function ist_now_time() returns time
  language sql stable as $$
  select (now() at time zone 'Asia/Kolkata')::time(0)
$$;

create or replace function on_leave(e uuid, d date) returns boolean
  language sql security definer set search_path = public as $$
  select exists (
    select 1 from leave_requests
    where employee_id = e and status = 'approved'
      and d between start_date and end_date
  )
$$;

-- Resolve employee from session token (passed by client)
create or replace function emp_from_token(tok uuid) returns uuid
  language sql security definer set search_path = public as $$
  select employee_id from sessions
  where token = tok and expires_at > now()
$$;

-- ---------- employee auth (name + password) ----------

-- Register: name must already exist (added by admin) and not yet have a password
create or replace function emp_register(p_name text, p_password text) returns json
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

  select * into e from employees where lower(trim(name)) = n;
  if not found then
    raise exception 'This name is not registered by admin. Ask admin to add you first.';
  end if;
  if e.password_hash is not null then
    raise exception 'Account already exists. Please log in.';
  end if;

  update employees
  set password_hash = crypt(p_password, gen_salt('bf'))
  where id = e.id;

  -- auto-login after register
  insert into sessions (employee_id) values (e.id)
  returning token into tok;

  return json_build_object('token', tok, 'name', e.name, 'id', e.id);
end $$;

-- Login with name + password
create or replace function emp_login(p_name text, p_password text) returns json
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

  -- clean expired sessions
  delete from sessions where employee_id = e.id and expires_at < now();

  insert into sessions (employee_id) values (e.id)
  returning token into tok;

  return json_build_object('token', tok, 'name', e.name, 'id', e.id);
end $$;

-- Logout (invalidate token)
create or replace function emp_logout(p_token uuid) returns void
  language plpgsql security definer set search_path = public as $$
begin
  delete from sessions where token = p_token;
end $$;

-- Who am I
create or replace function emp_me(p_token uuid) returns json
  language plpgsql security definer set search_path = public as $$
declare
  e employees;
begin
  select emp.* into e
  from employees emp
  join sessions s on s.employee_id = emp.id
  where s.token = p_token and s.expires_at > now();
  if not found then raise exception 'Not logged in'; end if;
  return json_build_object('id', e.id, 'name', e.name);
end $$;

-- ---------- attendance ----------
create or replace function day_info(p_token uuid) returns json
  language plpgsql security definer set search_path = public as $$
declare
  e uuid := emp_from_token(p_token);
  d date := ist_today();
  si time;
  so time;
  st text := 'none';
begin
  if e is null then raise exception 'Not logged in'; end if;
  select time into si from attendance where employee_id = e and date = d and status = 'sign_in';
  select time into so from attendance where employee_id = e and date = d and status = 'sign_out';
  if on_leave(e, d) then st := 'leave';
  elsif so is not null then st := 'signed_out';
  elsif si is not null then st := 'signed_in';
  end if;
  return json_build_object('now', now(), 'status', st, 'sign_in', si, 'sign_out', so);
end $$;

create or replace function mark_attendance(p_token uuid, p_kind text, p_lat float, p_lng float) returns text
  language plpgsql security definer set search_path = public as $$
declare
  e uuid := emp_from_token(p_token);
  d date := ist_today();
  t time := ist_now_time();
  olat float;
  olng float;
  radius float;
  dist float;
begin
  if e is null then raise exception 'Not logged in'; end if;
  if on_leave(e, d) then
    raise exception 'You are on approved leave today. Cancel your leave before marking attendance.';
  end if;

  if p_kind = 'sign_in' then
    if exists (select 1 from attendance where employee_id = e and date = d and status = 'sign_in') then
      raise exception 'Already signed in today';
    end if;
    if p_lat is null or p_lng is null then
      raise exception 'Location required for Sign In';
    end if;
    olat := cfg('office_lat')::float;
    olng := cfg('office_lng')::float;
    radius := coalesce(cfg('office_radius_m')::float, 50);
    dist := 6371000 * 2 * asin(sqrt(
      sin(radians(p_lat - olat) / 2) ^ 2 +
      cos(radians(olat)) * cos(radians(p_lat)) * sin(radians(p_lng - olng) / 2) ^ 2
    ));
    if dist > radius then
      raise exception 'You are too far from office (% m). Sign In only allowed within % m of office.',
        round(dist), round(radius);
    end if;
  elsif p_kind = 'sign_out' then
    if not exists (select 1 from attendance where employee_id = e and date = d and status = 'sign_in') then
      raise exception 'Sign in first';
    end if;
    if exists (select 1 from attendance where employee_id = e and date = d and status = 'sign_out') then
      raise exception 'Already signed out today';
    end if;
  else
    raise exception 'Bad request';
  end if;

  insert into attendance (employee_id, date, time, status, lat, lng)
  values (e, d, t, p_kind, nullif(p_lat, 0), nullif(p_lng, 0));

  return initcap(replace(p_kind, '_', ' ')) || ' successful at ' || t;
end $$;

-- ---------- leave ----------
create or replace function request_leave(p_token uuid, p_type text, p_start date, p_end date, p_reason text) returns void
  language plpgsql security definer set search_path = public as $$
declare
  e uuid := emp_from_token(p_token);
begin
  if e is null then raise exception 'Not logged in'; end if;
  if p_type not in ('single_day', 'long_leave') then raise exception 'Invalid leave type'; end if;
  if p_type = 'single_day' then p_end := p_start; end if;
  if p_end is null or p_start is null then raise exception 'Dates required'; end if;
  if p_end < p_start then raise exception 'End date cannot be before start date'; end if;
  if p_start < ist_today() then raise exception 'Cannot request leave in the past'; end if;
  if exists (
    select 1 from leave_requests
    where employee_id = e
      and status in ('pending', 'approved')
      and start_date <= p_end and end_date >= p_start
  ) then
    raise exception 'You already have overlapping leave for these dates';
  end if;
  insert into leave_requests (employee_id, leave_type, start_date, end_date, reason)
  values (e, p_type, p_start, p_end, nullif(trim(p_reason), ''));
end $$;

create or replace function cancel_leave(p_token uuid, p_id uuid) returns void
  language plpgsql security definer set search_path = public as $$
declare
  e uuid := emp_from_token(p_token);
  r leave_requests;
  d date := ist_today();
begin
  if e is null then raise exception 'Not logged in'; end if;
  select * into r from leave_requests where id = p_id and employee_id = e;
  if not found then raise exception 'Leave not found'; end if;
  if r.status not in ('pending', 'approved') then
    raise exception 'Leave is already %', r.status;
  end if;
  if r.status = 'approved' then
    if r.end_date < d then raise exception 'Past leave cannot be cancelled'; end if;
    if r.start_date <= d and exists (
      select 1 from attendance where employee_id = e and date = d and status = 'sign_in'
    ) then
      raise exception 'Today''s leave cannot be cancelled after Sign In';
    end if;
  end if;
  update leave_requests
  set status = 'cancelled', cancelled_at = now(),
      cancelled_by = (select name from employees where id = e)
  where id = p_id;
end $$;

create or replace function my_leaves(p_token uuid) returns json
  language plpgsql security definer set search_path = public as $$
declare
  e uuid := emp_from_token(p_token);
begin
  if e is null then raise exception 'Not logged in'; end if;
  return coalesce((
    select json_agg(x order by x.created_at desc)
    from (
      select id, leave_type, start_date, end_date, reason, status, created_at
      from leave_requests where employee_id = e
    ) x
  ), '[]'::json);
end $$;

-- ---------- admin ----------
create or replace function chk(pw text) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if pw is null or length(trim(pw)) = 0 then raise exception 'Password required'; end if;
  if pw is distinct from (select value from config where key = 'admin_password') then
    raise exception 'Wrong password';
  end if;
end $$;

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
        select a.id, a.date, a.time, a.status, emp.name
        from attendance a
        join employees emp on emp.id = a.employee_id
        order by a.date desc, a.time desc
        limit 5000
      ) a
    )
  );
end $$;

create or replace function admin_leave_action(pw text, p_id uuid, p_action text) returns void
  language plpgsql security definer set search_path = public as $$
begin
  perform chk(pw);
  if p_action = 'approve' then
    update leave_requests
    set status = 'approved', approved_by = 'admin', approved_at = now()
    where id = p_id and status = 'pending';
  elsif p_action = 'reject' then
    update leave_requests
    set status = 'rejected', approved_by = 'admin', approved_at = now()
    where id = p_id and status = 'pending';
  elsif p_action = 'cancel' then
    update leave_requests
    set status = 'cancelled', cancelled_at = now(), cancelled_by = 'admin'
    where id = p_id and status in ('pending', 'approved');
  else
    raise exception 'Unknown action';
  end if;
end $$;

-- Admin only adds a name (no email)
create or replace function admin_add_employee(pw text, p_name text) returns void
  language plpgsql security definer set search_path = public as $$
declare
  n text := trim(p_name);
begin
  perform chk(pw);
  if n is null or length(n) < 2 then
    raise exception 'Name required (min 2 characters)';
  end if;
  insert into employees (name) values (n);
exception
  when unique_violation then
    raise exception 'Employee with this name already exists';
end $$;

create or replace function admin_del_employee(pw text, p_id uuid) returns void
  language plpgsql security definer set search_path = public as $$
begin
  perform chk(pw);
  if p_id is null then raise exception 'Employee id required'; end if;
  delete from employees where id = p_id;
end $$;

-- Admin can reset an employee's password so they can register again
create or replace function admin_reset_password(pw text, p_id uuid) returns void
  language plpgsql security definer set search_path = public as $$
begin
  perform chk(pw);
  update employees set password_hash = null where id = p_id;
  delete from sessions where employee_id = p_id;
end $$;
