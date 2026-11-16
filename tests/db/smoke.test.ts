import { afterAll, beforeAll, expect, it } from "vitest";
import { createTestDb, type TestDb } from "./harness";

let db: TestDb;

beforeAll(async () => {
  db = await createTestDb();
});
afterAll(() => db.close());

it("las migraciones se aplican y el alta crea perfil, espacio, pertenencia y plan Free", async () => {
  const user = await db.createUser("a@ejemplo.test");
  const rows = await db.sql(
    `select p.id, w.name, w.is_personal, m.role, s.plan, s.status, s.provider
       from public.profiles p
       join public.workspaces w on w.owner_id = p.id
       join public.workspace_members m on m.workspace_id = w.id and m.user_id = p.id
       join public.subscriptions s on s.workspace_id = w.id
      where p.id = $1`,
    [user],
  );

  expect(rows).toEqual([
    {
      id: user,
      name: "Espacio personal",
      is_personal: true,
      role: "owner",
      plan: "free",
      status: "active",
      provider: "none",
    },
  ]);
});
