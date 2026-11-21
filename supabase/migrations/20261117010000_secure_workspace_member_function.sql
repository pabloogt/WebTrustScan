
-- Keep the workspace membership helper outside the exposed API schema.
create schema if not exists private;

-- No public or anonymous access to the private schema.
revoke all on schema private from public, anon, authenticated;

-- Authenticated users need schema usage and function execution
-- because RLS policies call this helper.
grant usage on schema private to authenticated, service_role;

-- Move the existing function without changing its implementation.
-- Existing RLS policies keep their function dependency.
alter function public.is_workspace_member(uuid) set schema private;

-- Preserve the permissions required by RLS and the backend.
revoke execute on function private.is_workspace_member(uuid)
  from public, anon;

grant execute on function private.is_workspace_member(uuid)
  to authenticated, service_role;
