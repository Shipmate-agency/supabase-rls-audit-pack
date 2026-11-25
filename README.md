<p align="center">
  <a href="https://shipmate.agency/articles/supabase-rls-disabled-in-public-fix">
    <img src="./assets/banner.png" alt="Supabase RLS Audit Pack by Shipmate — Find rls_disabled_in_public and open policies" width="840" />
  </a>
</p>

# Supabase RLS Audit Pack (1-Query Postgres Check)

[![Fix Guide](https://img.shields.io/badge/Step--by--Step_Fix-shipmate.agency-1E57A8?style=flat-square)](https://shipmate.agency/articles/supabase-rls-disabled-in-public-fix)
[![Two-Account Test](https://img.shields.io/badge/Two--Account_Test-Read_Guide-11141C?style=flat-square)](https://shipmate.agency/articles/supabase-rls-two-account-test)
[![License: MIT](https://img.shields.io/badge/License-MIT-11141C?style=flat-square)](./LICENSE)

Paste [`audit-rls.sql`](./audit-rls.sql) directly into the **Supabase SQL Editor** (read-only `SELECT` query, zero mutations) to surface the three misconfigurations that leak customer rows through your public `anon` key:

1. **`rls_disabled_in_public`** — Every `public.*` table with Row Level Security turned off.
2. **`policy_using_true_write`** — Every permissive `ALL` / `INSERT` / `UPDATE` / `DELETE` policy for `anon`, `authenticated` or `public` that allows everyone via `USING (true)` / `WITH CHECK (true)` (or `1 = 1`).
3. **`security_definer_view`** — Every `public.*` view missing `security_invoker = true` (which silently bypasses underlying table RLS).

Objects owned by extensions installed into `public` (e.g. PostGIS `spatial_ref_sys`) are skipped because you can't alter them; move the extension to the `extensions` schema instead. Tested on Postgres 15 and 17, the versions Supabase runs (see [Tests](#tests)).

Each row is one finding: `issue` (which check), `object_name` (table, `table (policy)` or view) and `remediation` (the statement to run or the change to make). No rows means none of these three checks fired.

## What It Does Not Catch
This is a first pass, not proof of isolation:
- Only the `public` schema. If you exposed other schemas in API settings, change `= 'public'` to include them.
- Policies that are open without being literally `true`, e.g. `auth.role() = 'authenticated'` or `auth.uid() IS NOT NULL` (any logged-in user gets every row).
- `SELECT ... USING (true)` policies are not reported, since public read is often intended. Check each one really is public data.
- `SECURITY DEFINER` functions callable by `anon`, materialized views and foreign tables in the API, and storage bucket policies.
- Tables with RLS off are listed even if you revoked `anon`/`authenticated` grants on them; enabling RLS is still the safe default.

## How to Run
1. Open **Supabase Dashboard → SQL Editor → New Query**.
2. Paste [`audit-rls.sql`](./audit-rls.sql) and click **Run**.
3. Fix each returned row with its `remediation` text. Enabling RLS with no policies blocks `anon` and `authenticated` entirely, so add policies such as `USING ((select auth.uid()) = user_id)` for reads and `WITH CHECK ((select auth.uid()) = user_id)` for inserts/updates. Full patterns in [How to fix `rls_disabled_in_public` & `security_definer_view`](https://shipmate.agency/articles/supabase-rls-disabled-in-public-fix).
4. Verify multi-tenant boundaries with a real [two-account RLS isolation test](https://shipmate.agency/articles/supabase-rls-two-account-test).

## Tests
`npm install && DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres npm test` loads [`test/fixture.sql`](./test/fixture.sql) (every detected condition plus safe look-alikes) into a throwaway database on a **disposable local** Postgres, runs the audit in a read-only transaction, checks the exact rows, and checks the suggested `ALTER`s clear them.

## Want a Human to Check Every Table, RPC & API Route?
- **Free passive check ($0, no card):** https://shipmate.agency/check
- **Launch Lockdown ($950 once, 1 PR) · Pentest + Letter ($2,950 once):** https://shipmate.agency
- **Related:** [`shipready` CLI](https://github.com/Shipmate-agency/shipready) · [`shipready-mcp`](https://github.com/Shipmate-agency/shipready-mcp) · [Shipmate Open Source](https://github.com/Shipmate-agency)
