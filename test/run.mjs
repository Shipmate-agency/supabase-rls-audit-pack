// Runs audit-rls.sql against test/fixture.sql in a throwaway database and checks every row.
// DATABASE_URL must point at a disposable local Postgres 15+ as a superuser, never at a real project:
//   DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres npm test
import assert from "node:assert/strict";
import fs from "node:fs";
import pg from "pg";

const read = (f) => fs.readFileSync(new URL(f, import.meta.url), "utf8");
const url = new URL(process.env.DATABASE_URL ?? "postgres://postgres@127.0.0.1:5432/postgres");
const db = "rls_audit_test";

const admin = new pg.Client({ connectionString: url.href });
await admin.connect();
await admin.query(`DROP DATABASE IF EXISTS ${db}`);
await admin.query(`CREATE DATABASE ${db}`);
url.pathname = `/${db}`;
const c = new pg.Client({ connectionString: url.href });

try {
  await c.connect();
  console.log((await c.query("SHOW server_version")).rows[0].server_version);
  await c.query(read("./fixture.sql"));

  // Read-only transaction: any write in the audit would fail here.
  const audit = async () => {
    await c.query("BEGIN READ ONLY");
    const { rows } = await c.query(read("../audit-rls.sql"));
    await c.query("ROLLBACK");
    return rows;
  };

  const rows = await audit();
  assert.deepEqual(rows.map((r) => `${r.issue} ${r.object_name}`), [
    "policy_using_true_write public.flag_policies (all_public_true)",
    "policy_using_true_write public.flag_policies (delete_one_eq_one)",
    "policy_using_true_write public.flag_policies (delete_true)",
    "policy_using_true_write public.flag_policies (insert_anon_true)",
    "policy_using_true_write public.flag_policies (mixed_roles_true)",
    "policy_using_true_write public.flag_policies (update_check_true)",
    "rls_disabled_in_public public.Flag Mixed Case",
    "rls_disabled_in_public public.flag_partitioned",
    "rls_disabled_in_public public.flag_rls_off",
    "security_definer_view public.flag_view_default",
    "security_definer_view public.flag_view_invoker_false",
  ]);

  // The suggested ALTER statements must run and clear their rows.
  for (const r of rows) {
    const sql = r.remediation.match(/^Run: (ALTER [^;]+;)/)?.[1];
    if (sql) await c.query(sql);
  }
  assert.deepEqual((await audit()).map((r) => r.issue), Array(6).fill("policy_using_true_write"));

  console.log("ok");
} finally {
  await c.end();
  await admin.query(`DROP DATABASE IF EXISTS ${db}`);
  await admin.end();
}
