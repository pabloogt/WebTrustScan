/**
 * Migraciones de la base de datos, en orden. Nunca se edita una migración ya
 * publicada: se añade otra.
 *
 * Regla de aislamiento: toda tabla con datos de cliente lleva
 * `organization_id`, y todo acceso filtra por él (ver lib/pro/*.ts).
 */
export const MIGRATIONS: { id: string; statements: string[] }[] = [
  {
    id: "001_base",
    statements: [
      `create table users (
        id uuid primary key,
        email text not null,
        password_hash text not null,
        created_at timestamptz not null default now()
      )`,
      `create unique index users_email_key on users (lower(email))`,

      `create table organizations (
        id uuid primary key,
        name text not null,
        plan text not null default 'free' check (plan in ('free', 'pro', 'agency')),
        created_at timestamptz not null default now()
      )`,

      `create table memberships (
        user_id uuid not null references users (id) on delete cascade,
        organization_id uuid not null references organizations (id) on delete cascade,
        role text not null check (role in ('owner', 'admin', 'member', 'viewer')),
        created_at timestamptz not null default now(),
        primary key (user_id, organization_id)
      )`,

      // Del token de sesión solo se guarda su SHA-256.
      `create table sessions (
        token_hash text primary key,
        user_id uuid not null references users (id) on delete cascade,
        created_at timestamptz not null default now(),
        expires_at timestamptz not null
      )`,
      `create index sessions_user_idx on sessions (user_id)`,

      `create table domains (
        id uuid primary key,
        organization_id uuid not null references organizations (id) on delete cascade,
        hostname text not null,
        verification_token text not null,
        verified_at timestamptz,
        verified_method text,
        created_at timestamptz not null default now(),
        unique (organization_id, hostname)
      )`,

      `create table audits (
        id uuid primary key,
        organization_id uuid not null references organizations (id) on delete cascade,
        domain_id uuid not null references domains (id) on delete cascade,
        created_by uuid references users (id) on delete set null,
        engine_version text not null,
        web_score integer,
        web_grade text,
        web_coverage integer not null,
        mail_score integer,
        open_findings integer not null,
        report jsonb not null,
        created_at timestamptz not null default now()
      )`,
      `create index audits_domain_idx on audits (domain_id, created_at desc)`,
      `create index audits_org_idx on audits (organization_id, created_at desc)`,

      `create table activity_log (
        id uuid primary key,
        organization_id uuid not null references organizations (id) on delete cascade,
        user_id uuid,
        action text not null,
        target text,
        created_at timestamptz not null default now()
      )`,
      `create index activity_org_idx on activity_log (organization_id, created_at desc)`,
    ],
  },
];
