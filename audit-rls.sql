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
  -- skip tables owned by an extension (e.g. PostGIS spatial_ref_sys); you can't ALTER those
  AND NOT EXISTS (
    SELECT 1 FROM pg_depend d
    WHERE d.classid = 'pg_class'::regclass
      AND d.objid = (quote_ident(schemaname) || '.' || quote_ident(tablename))::regclass
      AND d.deptype = 'e'
  )

UNION ALL

-- 2. Overly permissive write policies using (true) that API clients can use
--    (RESTRICTIVE policies only narrow access; service_role bypasses RLS anyway)
SELECT
  'policy_using_true_write' AS issue,
  schemaname || '.' || tablename || ' (' || policyname || ')' AS object_name,
  'Bind ' || cmd || ' policy to auth.uid() or verified workspace membership.' AS remediation
FROM pg_policies
WHERE schemaname = 'public'
  AND cmd IN ('ALL', 'INSERT', 'UPDATE', 'DELETE')
  AND permissive = 'PERMISSIVE'
  AND roles && ARRAY['public', 'anon', 'authenticated']::name[]
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
  -- reloptions keep the value as written (true/on/1/yes), so cast it like Postgres does
  AND NOT coalesce((
    SELECT split_part(opt, '=', 2)::boolean
    FROM unnest(c.reloptions) AS opt
    WHERE opt LIKE 'security_invoker=%'
  ), false)
  -- skip views owned by an extension (e.g. pg_stat_statements installed into public)
  AND NOT EXISTS (
    SELECT 1 FROM pg_depend d
    WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'
  )
ORDER BY issue, object_name;
