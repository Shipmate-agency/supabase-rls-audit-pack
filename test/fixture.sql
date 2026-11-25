-- Fixture for test/run.mjs: each audit finding (flag_*) plus safe look-alikes (ok_*).
-- Loaded into a throwaway database; never run this against a real project.

-- Supabase-like roles and auth.uid()
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF;
END $$;
CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;

-- rls_disabled_in_public
CREATE TABLE public.flag_rls_off (id int, user_id uuid);
CREATE TABLE public."Flag Mixed Case" (id int);
CREATE TABLE public.flag_partitioned (id int) PARTITION BY RANGE (id);

-- policy_using_true_write
CREATE TABLE public.flag_policies (id int, user_id uuid);
ALTER TABLE public.flag_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY insert_anon_true ON public.flag_policies FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY all_public_true ON public.flag_policies FOR ALL USING (true);
CREATE POLICY update_check_true ON public.flag_policies FOR UPDATE TO authenticated
  USING (auth.uid() = user_id) WITH CHECK (true);
CREATE POLICY delete_true ON public.flag_policies FOR DELETE TO authenticated USING (TRUE);
CREATE POLICY delete_one_eq_one ON public.flag_policies FOR DELETE TO anon USING (1 = 1);
CREATE POLICY mixed_roles_true ON public.flag_policies FOR UPDATE TO service_role, authenticated USING (true);

-- security_definer_view
CREATE VIEW public.flag_view_default AS SELECT id FROM public.flag_policies;
CREATE VIEW public.flag_view_invoker_false WITH (security_invoker = false) AS SELECT id FROM public.flag_policies;

-- Safe look-alikes: must NOT be reported
CREATE TABLE public.ok_owned (id int, user_id uuid);
ALTER TABLE public.ok_owned ENABLE ROW LEVEL SECURITY;
CREATE POLICY own_select ON public.ok_owned FOR SELECT TO authenticated USING ((select auth.uid()) = user_id);
CREATE POLICY own_insert ON public.ok_owned FOR INSERT TO authenticated WITH CHECK ((select auth.uid()) = user_id);
CREATE POLICY own_update ON public.ok_owned FOR UPDATE TO authenticated
  USING ((select auth.uid()) = user_id) WITH CHECK ((select auth.uid()) = user_id);
CREATE POLICY restrictive_true ON public.ok_owned AS RESTRICTIVE FOR ALL TO authenticated USING (true);

CREATE TABLE public.ok_public_read (id int);
ALTER TABLE public.ok_public_read ENABLE ROW LEVEL SECURITY;
CREATE POLICY read_all ON public.ok_public_read FOR SELECT TO anon, authenticated USING (true);

CREATE TABLE public.ok_no_policies (id int);
ALTER TABLE public.ok_no_policies ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.ok_service_only (id int);
ALTER TABLE public.ok_service_only ENABLE ROW LEVEL SECURITY;
CREATE POLICY service_all ON public.ok_service_only FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE VIEW public.ok_view_invoker_true WITH (security_invoker = true) AS SELECT id FROM public.ok_owned;
CREATE VIEW public.ok_view_invoker_on WITH (security_invoker = on) AS SELECT id FROM public.ok_owned;
CREATE VIEW public.ok_view_invoker_bare WITH (security_invoker) AS SELECT id FROM public.ok_owned;

-- Extension-owned view in public (users can't ALTER these; Supabase's linter skips them too)
CREATE EXTENSION pg_buffercache SCHEMA public;
CREATE TABLE public.ok_extension_table (id int); -- stands in for PostGIS spatial_ref_sys
ALTER EXTENSION pg_buffercache ADD TABLE public.ok_extension_table;

-- Non-exposed schema: out of scope
CREATE SCHEMA private;
CREATE TABLE private.ok_rls_off (id int);
CREATE TABLE private.ok_true_policy (id int);
ALTER TABLE private.ok_true_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON private.ok_true_policy FOR ALL TO anon USING (true);
CREATE VIEW private.ok_view AS SELECT 1 AS x;
