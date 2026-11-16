-- SOLO PARA DESARROLLO LOCAL. Asigna un plan a una cuenta para poder probar
-- Pro antes de que existan los pagos.
--
-- Cómo usarlo: abre Supabase Studio local (http://127.0.0.1:54323), entra en
-- «SQL Editor», pega este fichero, cambia el correo y el plan, y ejecútalo.
--
-- No existe ninguna ruta de la aplicación que haga esto: el plan no se puede
-- cambiar desde el navegador. En producción, hasta que se integre Stripe,
-- todas las cuentas deben quedarse en Free.

update public.subscriptions
   set plan = 'pro',          -- 'pro' o 'free'
       status = 'active',
       provider = 'manual'
 where workspace_id = (
   select w.id
     from public.workspaces w
     join auth.users u on u.id = w.owner_id
    where u.email = 'CAMBIA-ESTE-CORREO@ejemplo.test' and w.is_personal
 )
returning workspace_id, plan, status, provider;
