-- Shipmate Supabase RLS Audit Pack (read-only diagnostic query)
-- Docs & fixes: https://shipmate.agency/articles/supabase-rls-disabled-in-public-fix

-- 1. Public tables with Row Level Security DISABLED
SELECT
  'rls_disabled_in_public' AS issue,
  schemaname || '.' || tablename AS object_name,
  'Run: ALTER TABLE ' || quote_ident(schemaname) || '.' || quote_ident(tablename) || ' ENABLE ROW LEVEL SECURITY;' AS remediation
FROM pg_tables
WHERE schemaname = 'public'
  AND rowsecurity = false

UNION ALL

-- 2. Overly permissive write policies using (true)
SELECT
  'policy_using_true_write' AS issue,
  schemaname || '.' || tablename || ' (' || policyname || ')' AS object_name,
  'Bind ' || cmd || ' policy to auth.uid() or verified workspace membership.' AS remediation
FROM pg_policies
WHERE schemaname = 'public'
  AND cmd IN ('ALL', 'INSERT', 'UPDATE', 'DELETE')
  AND (
    lower(coalesce(qual, '')) IN ('true', '(true)')
    OR lower(coalesce(with_check, '')) IN ('true', '(true)')
  )

UNION ALL

-- 3. Views missing security_invoker = true (Postgres 15+)
SELECT
  'security_definer_view' AS issue,
  n.nspname || '.' || c.relname AS object_name,
  'Run: ALTER VIEW ' || quote_ident(n.nspname) || '.' || quote_ident(c.relname) || ' SET (security_invoker = true);' AS remediation
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'v'
  AND NOT coalesce('security_invoker=true' = ANY(c.reloptions), false)
ORDER BY issue, object_name;
