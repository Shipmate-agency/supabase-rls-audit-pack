# Supabase RLS Audit Pack (1-Query SQL Check)

Drop [`audit-rls.sql`](./audit-rls.sql) into the Supabase SQL Editor to immediately find:
1. Every `public.*` table with **Row Level Security disabled** (`rls_disabled_in_public`).
2. Every RLS policy allowing **everyone to write** via `USING (true)` or `WITH CHECK (true)`.
3. Every `public.*` view still running as `SECURITY DEFINER` (`security_definer_view`).

- **Step-by-step fix guide:** https://shipmate.agency/articles/supabase-rls-disabled-in-public-fix
- **Two-account isolation test guide:** https://shipmate.agency/articles/supabase-rls-two-account-test
- **Want a human to audit your full app & ship fixes in 1 PR ($950)?** https://shipmate.agency
