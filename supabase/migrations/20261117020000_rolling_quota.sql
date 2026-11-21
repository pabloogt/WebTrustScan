-- =============================================================================
-- Cuota en ventana móvil de 7 días
--
-- Cada análisis consumido cuenta durante los 7 días siguientes al momento en
-- que se hizo (UTC); pasado ese plazo, ese uso se libera. Sustituye al
-- periodo mensual.
--
-- Transición segura:
--   · No modifica ni borra ninguna fila existente: `usage_events`, `audits` y
--     `usage_carryover` quedan como están. El consumo ya registrado sigue
--     contando con su fecha real (`usage_events.created_at`).
--   · No modifica las funciones anteriores (`workspace_usage`,
--     `reserve_audit`, `record_account_deletion`): la versión desplegada
--     sigue funcionando hasta que se publique el código nuevo. Orden:
--     1) aplicar esta migración, 2) desplegar.
--   · Los nuevos consumos siguen guardando `period_start` (mes UTC) para que
--     volver a la versión anterior no rompa nada.
--   · Esta migración NO recorta historiales. El recorte lo hace
--     `complete_audit` al guardar un análisis nuevo, con el límite que le
--     pase la aplicación (ver docs/PLANS_AND_QUOTAS.md).
-- =============================================================================

-- Contar por fecha de consumo dentro de cada espacio.
create index if not exists usage_events_workspace_created_idx
  on public.usage_events (workspace_id, created_at);

-- Consumo que sobrevive a la baja de una cuenta, ahora con la fecha de cada
-- uso (en la ventana móvil cada uno se libera en un momento distinto). Solo
-- guarda un HMAC del correo. La tabla anterior `usage_carryover` se sigue
-- leyendo (sus filas cuentan 7 días desde la baja) y no se borra.
create table public.usage_carryover_events (
  id uuid primary key default gen_random_uuid(),
  email_hash text not null check (char_length(email_hash) = 64),
  used_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index usage_carryover_events_hash_idx
  on public.usage_carryover_events (email_hash, used_at);

-- Igual que las demás tablas internas: RLS activado y ninguna política, así
-- que solo el servidor (service_role) puede leerla o escribirla.
alter table public.usage_carryover_events enable row level security;
revoke all on public.usage_carryover_events from public, anon, authenticated;
grant all on public.usage_carryover_events to service_role;

-- Ventana en días que recibe la aplicación, validada aquí.
create function public.quota_window(p_days integer)
returns interval language plpgsql immutable set search_path = '' as $$
begin
  if p_days is null or p_days < 1 or p_days > 31 then
    raise exception 'Ventana de cuota no válida: %', p_days;
  end if;
  return make_interval(days => p_days);
end $$;

-- Consumo de un espacio en la ventana que termina en `p_now`.
--   used             → usos que cuentan ahora.
--   next_release_at  → cuándo se libera el uso más antiguo (null si no hay).
--   available_at     → si se ha llegado al límite, cuándo vuelve a quedar
--                      al menos un análisis disponible (null si ya lo hay).
create function public.rolling_usage(
  p_workspace uuid,
  p_email_hash text,
  p_now timestamptz,
  p_window interval,
  p_limit integer,
  out used integer,
  out next_release_at timestamptz,
  out available_at timestamptz
) language plpgsql stable security definer set search_path = '' as $$
declare
  v_times timestamptz[];
begin
  select coalesce(array_agg(s.t order by s.t), '{}'::timestamptz[]) into v_times
  from (
    -- Consumo propio. 'released' (fallo interno del servicio) no cuenta.
    select u.created_at as t from public.usage_events u
      where u.workspace_id = p_workspace and u.status <> 'released'
        and u.created_at > p_now - p_window and u.created_at <= p_now
    union all
    -- Consumo de cuentas anteriores con el mismo correo (nueva tabla).
    select c.used_at from public.usage_carryover_events c
      where p_email_hash is not null and c.email_hash = p_email_hash
        and c.used_at > p_now - p_window and c.used_at <= p_now
    union all
    -- Arrastres del sistema mensual anterior: cuentan desde la baja.
    select o.created_at from public.usage_carryover o
      cross join lateral generate_series(1, o.used) g
      where p_email_hash is not null and o.email_hash = p_email_hash
        and o.created_at > p_now - p_window and o.created_at <= p_now
  ) s;

  used := cardinality(v_times);
  next_release_at := case when used > 0 then v_times[1] + p_window end;
  -- Para volver a tener uno libre deben caducar (used - limit + 1) usos.
  available_at := case
    when p_limit is not null and p_limit > 0 and used >= p_limit
      then v_times[used - p_limit + 1] + p_window
  end;
end $$;

-- Consumo actual de la cuenta. Solo servidor.
create function public.workspace_usage_rolling(
  p_user uuid,
  p_limits jsonb,
  p_window_days integer,
  p_email_hash text default null,
  p_now timestamptz default now()
) returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
  v_workspace uuid;
  v_plan text;
  v_limit integer;
  v_window interval := public.quota_window(p_window_days);
  v_usage record;
begin
  select w.id into v_workspace from public.workspaces w
    where w.owner_id = p_user and w.is_personal;
  if v_workspace is null then
    return jsonb_build_object('outcome', 'no_workspace');
  end if;

  v_plan := public.effective_plan(v_workspace);
  v_limit := (p_limits ->> v_plan)::integer;
  if v_limit is null or v_limit < 0 then
    raise exception 'Límite no definido para el plan %', v_plan;
  end if;

  select * into v_usage
    from public.rolling_usage(v_workspace, p_email_hash, p_now, v_window, v_limit);

  return jsonb_build_object(
    'outcome', 'ok',
    'workspace_id', v_workspace,
    'plan', v_plan,
    'used', v_usage.used,
    'limit', v_limit,
    'window_days', p_window_days,
    'next_release_at', v_usage.next_release_at,
    'available_at', v_usage.available_at);
end $$;

-- Reserva un análisis de forma atómica. Solo servidor.
--
-- Bloquea la fila de la suscripción como `reserve_audit`: dos reservas
-- simultáneas del mismo espacio se ejecutan una detrás de otra, así que la
-- concurrencia no puede superar el límite. El plan se lee aquí, nunca de la
-- petición.
create function public.reserve_audit_rolling(
  p_user uuid,
  p_request uuid,
  p_limits jsonb,
  p_window_days integer,
  p_max_concurrent integer,
  p_email_hash text default null,
  p_now timestamptz default now()
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_workspace uuid;
  v_plan text;
  v_limit integer;
  v_window interval := public.quota_window(p_window_days);
  v_usage record;
  v_running integer;
  v_existing public.usage_events;
  v_period timestamptz;
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

  select * into v_usage
    from public.rolling_usage(v_workspace, p_email_hash, p_now, v_window, v_limit);

  if v_usage.used >= v_limit then
    return jsonb_build_object(
      'outcome', 'quota_exceeded', 'plan', v_plan,
      'used', v_usage.used, 'limit', v_limit,
      'available_at', v_usage.available_at,
      'next_release_at', v_usage.next_release_at);
  end if;

  -- Análisis en curso (una reserva de más de 2 minutos ya no está en curso:
  -- el análisis dura 30 s como mucho; sigue contando como consumo).
  select count(*) into v_running from public.usage_events u
    where u.workspace_id = v_workspace and u.status = 'reserved'
      and u.created_at > p_now - interval '2 minutes';
  if v_running >= p_max_concurrent then
    return jsonb_build_object('outcome', 'too_many_concurrent', 'running', v_running);
  end if;

  -- `period_start` ya no decide la cuota; se rellena como antes (mes UTC)
  -- para que la versión anterior de la aplicación siga siendo compatible.
  select p.period_start into v_period from public.usage_period(v_workspace, p_now) p;

  insert into public.usage_events
      (workspace_id, user_id, request_id, period_start, status, created_at, updated_at)
    values (v_workspace, p_user, p_request, v_period, 'reserved', p_now, p_now)
    returning id into v_id;

  select * into v_usage
    from public.rolling_usage(v_workspace, p_email_hash, p_now, v_window, v_limit);

  return jsonb_build_object(
    'outcome', 'reserved', 'usage_id', v_id, 'workspace_id', v_workspace,
    'plan', v_plan, 'used', v_usage.used, 'limit', v_limit,
    'next_release_at', v_usage.next_release_at,
    'available_at', v_usage.available_at);
end $$;

-- Antes de borrar una cuenta: conserva, bajo un HMAC del correo, la fecha de
-- cada uso que aún cuenta, para que volver a registrarse no reinicie la
-- cuota. Solo servidor.
create function public.record_account_deletion_rolling(
  p_user uuid,
  p_email_hash text,
  p_window_days integer,
  p_now timestamptz default now()
) returns void language plpgsql security definer set search_path = '' as $$
declare
  v_window interval := public.quota_window(p_window_days);
begin
  insert into public.usage_carryover_events (email_hash, used_at)
    select p_email_hash, u.created_at
    from public.usage_events u
    join public.workspaces w on w.id = u.workspace_id
    where w.owner_id = p_user and w.is_personal
      and u.status <> 'released'
      and u.created_at > p_now - v_window and u.created_at <= p_now;

  -- Lo que ya no puede contar en ninguna ventana se borra.
  delete from public.usage_carryover_events c
    where c.used_at < p_now - interval '31 days';
end $$;

-- Las funciones nuevas solo las ejecuta el servidor.
revoke execute on function public.quota_window(integer) from public, anon, authenticated;
revoke execute on function public.rolling_usage(uuid, text, timestamptz, interval, integer)
  from public, anon, authenticated;
revoke execute on function public.workspace_usage_rolling(uuid, jsonb, integer, text, timestamptz)
  from public, anon, authenticated;
revoke execute on function public.reserve_audit_rolling(uuid, uuid, jsonb, integer, integer, text, timestamptz)
  from public, anon, authenticated;
revoke execute on function public.record_account_deletion_rolling(uuid, text, integer, timestamptz)
  from public, anon, authenticated;

grant execute on function public.quota_window(integer) to service_role;
grant execute on function public.rolling_usage(uuid, text, timestamptz, interval, integer) to service_role;
grant execute on function public.workspace_usage_rolling(uuid, jsonb, integer, text, timestamptz) to service_role;
grant execute on function public.reserve_audit_rolling(uuid, uuid, jsonb, integer, integer, text, timestamptz) to service_role;
grant execute on function public.record_account_deletion_rolling(uuid, text, integer, timestamptz) to service_role;
