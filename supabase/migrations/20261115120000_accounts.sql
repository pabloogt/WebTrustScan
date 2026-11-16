-- WebTrustScan · cuentas, espacios de trabajo, historial, consumo y planes.
--
-- Principios:
--   * Usuarios, contraseñas y sesiones viven en Supabase Auth (auth.users).
--     Aquí no se guarda ninguna contraseña ni token.
--   * Todas las tablas tienen Row Level Security. Lo que un usuario puede
--     leer o tocar lo decide la base de datos, no el código de la aplicación.
--   * Plan, rol, consumo y suscripción NO son modificables por el usuario:
--     no tiene permiso de escritura sobre esas tablas.
--   * Las funciones que consumen cuota solo puede ejecutarlas el servidor
--     (rol service_role).

-- ---------------------------------------------------------------- tablas --

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text check (char_length(display_name) <= 80),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- El rol de administrador vive en una tabla aparte, sin ninguna política de
-- acceso para usuarios: no se puede leer ni modificar desde el navegador.
-- No tiene relación con el plan: un administrador puede ser Free o Pro.
create table public.app_admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  name text not null check (char_length(name) between 1 and 80),
  is_personal boolean not null default true,
  created_at timestamptz not null default now()
);
-- Cada cuenta tiene exactamente un espacio personal.
create unique index workspaces_one_personal_per_owner
  on public.workspaces (owner_id) where is_personal;

create table public.workspace_members (
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null check (role in ('owner', 'member')),
  created_at timestamptz not null default now(),
  primary key (workspace_id, user_id)
);
create index workspace_members_user_idx on public.workspace_members (user_id);

-- Estado de la suscripción. `provider = 'none'` mientras no haya pagos.
create table public.subscriptions (
  workspace_id uuid primary key references public.workspaces (id) on delete cascade,
  plan text not null default 'free' check (plan in ('free', 'pro')),
  status text not null default 'active'
    check (status in ('active', 'trialing', 'past_due', 'canceled', 'incomplete')),
  provider text not null default 'none' check (provider in ('none', 'manual', 'stripe')),
  provider_customer_id text,
  provider_subscription_id text,
  current_period_start timestamptz,
  current_period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (current_period_end is null or current_period_start is null
         or current_period_end > current_period_start)
);
create unique index subscriptions_provider_subscription_idx
  on public.subscriptions (provider, provider_subscription_id)
  where provider_subscription_id is not null;

-- Historial de análisis. `report` es el informe estructurado del motor: no
-- contiene el HTML de la web analizada ni valores de cookies.
create table public.audits (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  user_id uuid references auth.users (id) on delete set null,
  hostname text not null check (char_length(hostname) between 1 and 253),
  status text not null default 'completed' check (status in ('completed')),
  engine_version text not null check (char_length(engine_version) <= 20),
  web_score smallint check (web_score between 0 and 100),
  web_grade text check (web_grade in ('A', 'B', 'C', 'D', 'F')),
  web_coverage smallint not null check (web_coverage between 0 and 100),
  mail_score smallint check (mail_score between 0 and 100),
  open_findings smallint not null check (open_findings >= 0),
  report jsonb not null
    check (jsonb_typeof(report) = 'object' and octet_length(report::text) <= 400000),
  created_at timestamptz not null default now()
);
create index audits_workspace_created_idx
  on public.audits (workspace_id, created_at desc);

-- Registro de consumo. Es la fuente de verdad de la cuota: borrar un
-- análisis del historial NO borra su consumo (audit_id pasa a null).
--   reserved  → aceptado por el servidor, en curso. Cuenta.
--   completed → análisis entregado. Cuenta.
--   failed    → el destino no respondió o no era analizable. Cuenta: el
--               servidor hizo el trabajo y, si no contara, un reintento
--               infinito sería gratis.
--   released  → fallo interno del servicio. No cuenta.
create table public.usage_events (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  user_id uuid references auth.users (id) on delete set null,
  request_id uuid not null,
  period_start timestamptz not null,
  status text not null check (status in ('reserved', 'completed', 'failed', 'released')),
  audit_id uuid references public.audits (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- Una misma petición (o su reintento) solo puede consumir una vez.
  unique (workspace_id, request_id)
);
create index usage_events_period_idx
  on public.usage_events (workspace_id, period_start);

-- Consumo que sobrevive al borrado de una cuenta, para que darse de baja y
-- volver a registrarse con el mismo correo no reinicie la cuota del periodo.
-- Solo guarda un HMAC del correo (no reversible sin la clave del servidor).
create table public.usage_carryover (
  email_hash text not null check (char_length(email_hash) = 64),
  period_start timestamptz not null,
  used integer not null check (used >= 0),
  created_at timestamptz not null default now(),
  primary key (email_hash, period_start)
);

-- Eventos de facturación ya procesados (idempotencia de webhooks futuros).
create table public.billing_webhook_events (
  provider text not null check (provider in ('stripe')),
  event_id text not null check (char_length(event_id) <= 255),
  type text not null check (char_length(type) <= 120),
  received_at timestamptz not null default now(),
  processed_at timestamptz,
  primary key (provider, event_id)
);

-- Eventos de seguridad. Sin contraseñas, tokens ni IP en claro.
create table public.security_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  type text not null check (char_length(type) <= 60),
  ip_hash text check (char_length(ip_hash) <= 64),
  metadata jsonb not null default '{}'::jsonb
    check (octet_length(metadata::text) <= 2000),
  created_at timestamptz not null default now()
);
create index security_events_created_idx on public.security_events (created_at);
create index security_events_user_idx on public.security_events (user_id, created_at desc);

-- ------------------------------------------------------------- funciones --

create function public.set_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  return new;
end $$;

create trigger profiles_set_updated_at before update on public.profiles
  for each row execute function public.set_updated_at();
create trigger subscriptions_set_updated_at before update on public.subscriptions
  for each row execute function public.set_updated_at();

-- Al crearse un usuario en Supabase Auth: perfil, espacio personal,
-- pertenencia como propietario y suscripción Free. Siempre Free.
create function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_workspace uuid;
begin
  insert into public.profiles (id) values (new.id);
  insert into public.workspaces (owner_id, name, is_personal)
    values (new.id, 'Espacio personal', true)
    returning id into v_workspace;
  insert into public.workspace_members (workspace_id, user_id, role)
    values (v_workspace, new.id, 'owner');
  insert into public.subscriptions (workspace_id) values (v_workspace);
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ¿El usuario de la sesión pertenece a ese espacio? SECURITY DEFINER para
-- que las políticas no se consulten a sí mismas de forma recursiva.
create function public.is_workspace_member(p_workspace uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.workspace_members m
    where m.workspace_id = p_workspace and m.user_id = (select auth.uid())
  );
$$;

-- Plan efectivo: Pro solo si la suscripción está activa o en prueba.
create function public.effective_plan(p_workspace uuid)
returns text language sql stable security definer set search_path = '' as $$
  select case
    when s.plan = 'pro' and s.status in ('active', 'trialing') then 'pro'
    else 'free'
  end
  from public.subscriptions s where s.workspace_id = p_workspace;
$$;

-- Periodo de consumo vigente. Free: mes natural en UTC. Pro con un ciclo de
-- facturación vigente: ese ciclo; si no lo hay, mes natural en UTC.
create function public.usage_period(
  p_workspace uuid,
  p_now timestamptz,
  out period_start timestamptz,
  out period_end timestamptz
) language plpgsql stable security definer set search_path = '' as $$
declare
  v_sub public.subscriptions;
begin
  select * into v_sub from public.subscriptions s where s.workspace_id = p_workspace;

  if public.effective_plan(p_workspace) = 'pro'
     and v_sub.current_period_start is not null
     and v_sub.current_period_end is not null
     and p_now >= v_sub.current_period_start
     and p_now < v_sub.current_period_end then
    period_start := v_sub.current_period_start;
    period_end := v_sub.current_period_end;
  else
    period_start := date_trunc('month', p_now at time zone 'UTC') at time zone 'UTC';
    period_end := (date_trunc('month', p_now at time zone 'UTC') + interval '1 month')
                  at time zone 'UTC';
  end if;
end $$;

-- Consumo del periodo en curso de la cuenta. Solo servidor.
create function public.workspace_usage(
  p_user uuid,
  p_email_hash text default null,
  p_now timestamptz default now()
) returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
  v_workspace uuid;
  v_start timestamptz;
  v_end timestamptz;
  v_used integer;
begin
  select w.id into v_workspace from public.workspaces w
    where w.owner_id = p_user and w.is_personal;
  if v_workspace is null then
    return jsonb_build_object('outcome', 'no_workspace');
  end if;

  select p.period_start, p.period_end into v_start, v_end
    from public.usage_period(v_workspace, p_now) p;

  select count(*) into v_used from public.usage_events u
    where u.workspace_id = v_workspace and u.period_start = v_start
      and u.status <> 'released';

  v_used := v_used + coalesce((
    select c.used from public.usage_carryover c
    where c.email_hash = p_email_hash and c.period_start = v_start), 0);

  return jsonb_build_object(
    'outcome', 'ok',
    'workspace_id', v_workspace,
    'plan', public.effective_plan(v_workspace),
    'used', v_used,
    'period_start', v_start,
    'period_end', v_end);
end $$;

-- Reserva un análisis de forma atómica. Solo servidor.
--
-- Bloquea la fila de la suscripción: dos reservas simultáneas del mismo
-- espacio se ejecutan una detrás de otra, así que la concurrencia no puede
-- superar el límite. `p_limits` es {"free": N, "pro": M}: el plan se lee
-- aquí, dentro del bloqueo, nunca de la petición.
create function public.reserve_audit(
  p_user uuid,
  p_request uuid,
  p_limits jsonb,
  p_max_concurrent integer,
  p_email_hash text default null,
  p_now timestamptz default now()
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_workspace uuid;
  v_plan text;
  v_limit integer;
  v_start timestamptz;
  v_end timestamptz;
  v_used integer;
  v_running integer;
  v_existing public.usage_events;
  v_id uuid;
begin
  select w.id into v_workspace from public.workspaces w
    where w.owner_id = p_user and w.is_personal;
  if v_workspace is null then
    return jsonb_build_object('outcome', 'no_workspace');
  end if;

  perform 1 from public.subscriptions s where s.workspace_id = v_workspace for update;

  -- Reintento de una petición ya vista: no consume otra vez.
  select * into v_existing from public.usage_events u
    where u.workspace_id = v_workspace and u.request_id = p_request;
  if found then
    return jsonb_build_object(
      'outcome', 'duplicate',
      'usage_id', v_existing.id,
      'status', v_existing.status,
      'audit_id', v_existing.audit_id);
  end if;

  v_plan := public.effective_plan(v_workspace);
  v_limit := (p_limits ->> v_plan)::integer;
  if v_limit is null or v_limit < 0 then
    raise exception 'Límite no definido para el plan %', v_plan;
  end if;

  select p.period_start, p.period_end into v_start, v_end
    from public.usage_period(v_workspace, p_now) p;

  select count(*) into v_used from public.usage_events u
    where u.workspace_id = v_workspace and u.period_start = v_start
      and u.status <> 'released';

  v_used := v_used + coalesce((
    select c.used from public.usage_carryover c
    where c.email_hash = p_email_hash and c.period_start = v_start), 0);

  if v_used >= v_limit then
    return jsonb_build_object(
      'outcome', 'quota_exceeded', 'plan', v_plan,
      'used', v_used, 'limit', v_limit, 'period_end', v_end);
  end if;

  -- Análisis en curso (una reserva de más de 2 minutos ya no está en curso:
  -- el análisis dura 30 s como mucho; sigue contando como consumo).
  select count(*) into v_running from public.usage_events u
    where u.workspace_id = v_workspace and u.status = 'reserved'
      and u.created_at > p_now - interval '2 minutes';
  if v_running >= p_max_concurrent then
    return jsonb_build_object('outcome', 'too_many_concurrent', 'running', v_running);
  end if;

  insert into public.usage_events
      (workspace_id, user_id, request_id, period_start, status, created_at, updated_at)
    values (v_workspace, p_user, p_request, v_start, 'reserved', p_now, p_now)
    returning id into v_id;

  return jsonb_build_object(
    'outcome', 'reserved', 'usage_id', v_id, 'workspace_id', v_workspace,
    'plan', v_plan, 'used', v_used + 1, 'limit', v_limit,
    'period_start', v_start, 'period_end', v_end);
end $$;

-- Cierra una reserva guardando el informe y recorta el historial. Solo servidor.
create function public.complete_audit(
  p_usage uuid,
  p_hostname text,
  p_report jsonb,
  p_history_limit integer,
  p_now timestamptz default now()
) returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_usage public.usage_events;
  v_audit uuid;
begin
  select * into v_usage from public.usage_events u where u.id = p_usage for update;
  if not found or v_usage.status <> 'reserved' then
    raise exception 'La reserva % no existe o ya está cerrada', p_usage;
  end if;

  insert into public.audits
      (workspace_id, user_id, hostname, engine_version, web_score, web_grade,
       web_coverage, mail_score, open_findings, report, created_at)
    values (
      v_usage.workspace_id, v_usage.user_id, p_hostname,
      p_report ->> 'engineVersion',
      (p_report -> 'web' ->> 'score')::smallint,
      p_report -> 'web' ->> 'grade',
      (p_report -> 'web' ->> 'coverage')::smallint,
      (p_report -> 'dnsEmail' ->> 'score')::smallint,
      (select count(*) from jsonb_array_elements(p_report -> 'findings') f
        where f ->> 'status' in ('fail', 'warning'))::smallint,
      p_report, p_now)
    returning id into v_audit;

  update public.usage_events
    set status = 'completed', audit_id = v_audit, updated_at = p_now
    where id = p_usage;

  -- El historial conserva los N más recientes. El consumo NO se toca.
  delete from public.audits a
    where a.workspace_id = v_usage.workspace_id and a.id not in (
      select k.id from public.audits k
      where k.workspace_id = v_usage.workspace_id
      order by k.created_at desc, k.id desc
      limit greatest(p_history_limit, 1));

  return v_audit;
end $$;

-- Cierra una reserva sin informe. 'failed' cuenta; 'released' no. Solo servidor.
create function public.finish_audit(p_usage uuid, p_status text, p_now timestamptz default now())
returns void language plpgsql security definer set search_path = '' as $$
begin
  if p_status not in ('failed', 'released') then
    raise exception 'Estado no válido: %', p_status;
  end if;

  update public.usage_events
    set status = p_status, updated_at = p_now
    where id = p_usage and status = 'reserved';
end $$;

-- Antes de borrar una cuenta: conserva su consumo del periodo bajo un HMAC
-- del correo, para que volver a registrarse no lo reinicie. Solo servidor.
create function public.record_account_deletion(
  p_user uuid,
  p_email_hash text,
  p_now timestamptz default now()
) returns void language plpgsql security definer set search_path = '' as $$
declare
  v_usage jsonb;
begin
  v_usage := public.workspace_usage(p_user, p_email_hash, p_now);

  if v_usage ->> 'outcome' = 'ok' and (v_usage ->> 'used')::integer > 0 then
    insert into public.usage_carryover (email_hash, period_start, used)
      values (p_email_hash, (v_usage ->> 'period_start')::timestamptz,
              (v_usage ->> 'used')::integer)
      on conflict (email_hash, period_start) do update set used = excluded.used;
  end if;

  -- Los arrastres de periodos ya cerrados no sirven para nada: se borran.
  delete from public.usage_carryover c
    where c.period_start < p_now - interval '62 days';
end $$;

-- Conservación: borra eventos de seguridad antiguos. Solo servidor.
create function public.purge_security_events(p_keep interval default interval '90 days')
returns integer language plpgsql security definer set search_path = '' as $$
declare
  v_deleted integer;
begin
  delete from public.security_events e where e.created_at < now() - p_keep;
  get diagnostics v_deleted = row_count;
  return v_deleted;
end $$;

-- ------------------------------------------------ seguridad a nivel de fila --

alter table public.profiles enable row level security;
alter table public.app_admins enable row level security;
alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.subscriptions enable row level security;
alter table public.audits enable row level security;
alter table public.usage_events enable row level security;
alter table public.usage_carryover enable row level security;
alter table public.billing_webhook_events enable row level security;
alter table public.security_events enable row level security;

-- Perfil: cada usuario ve y edita solo el suyo.
create policy profiles_select_own on public.profiles
  for select to authenticated using (id = (select auth.uid()));
create policy profiles_update_own on public.profiles
  for update to authenticated
  using (id = (select auth.uid())) with check (id = (select auth.uid()));

-- Espacios: solo los propios. El propietario puede cambiar el nombre.
create policy workspaces_select_member on public.workspaces
  for select to authenticated using (public.is_workspace_member(id));
create policy workspaces_update_owner on public.workspaces
  for update to authenticated
  using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));

-- Pertenencias: cada usuario ve las suyas. Nadie puede añadirse a un espacio.
create policy workspace_members_select_own on public.workspace_members
  for select to authenticated using (user_id = (select auth.uid()));

-- Suscripción y consumo: solo lectura, y solo de los espacios propios.
create policy subscriptions_select_member on public.subscriptions
  for select to authenticated using (public.is_workspace_member(workspace_id));
create policy usage_events_select_member on public.usage_events
  for select to authenticated using (public.is_workspace_member(workspace_id));

-- Historial: leer y borrar los análisis de los espacios propios.
create policy audits_select_member on public.audits
  for select to authenticated using (public.is_workspace_member(workspace_id));
create policy audits_delete_member on public.audits
  for delete to authenticated using (public.is_workspace_member(workspace_id));

-- app_admins, usage_carryover, billing_webhook_events y security_events no
-- tienen ninguna política: con RLS activado, nadie salvo el servidor accede.

-- ---------------------------------------------------------------- permisos --
-- RLS filtra filas; los permisos deciden qué operaciones existen. Se parte
-- de cero y se concede solo lo imprescindible.

revoke all on all tables in schema public from anon, authenticated;
revoke execute on all functions in schema public from public, anon, authenticated;
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke execute on functions from public, anon, authenticated;

grant select on public.profiles, public.workspaces, public.workspace_members,
  public.subscriptions, public.audits, public.usage_events to authenticated;
-- Solo estas columnas son editables por el usuario.
grant update (display_name) on public.profiles to authenticated;
grant update (name) on public.workspaces to authenticated;
grant delete on public.audits to authenticated;

grant execute on function public.is_workspace_member(uuid) to authenticated;

grant all on all tables in schema public to service_role;
grant execute on all functions in schema public to service_role;
