-- CREATE AN AUTHORIZE HELPER TO CREATE ACCESS POLICIES
CREATE OR REPLACE FUNCTION public.authorize(requested_permission TEXT) RETURNS boolean AS $$
DECLARE
    user_role TEXT;
BEGIN
    -- Fetch user role once and store it to reduce number of calls
    SELECT (auth.jwt()->>'user_role')::TEXT INTO user_role;

    -- Check for existence instead of counting
    RETURN EXISTS (
        SELECT 1
        FROM public.workspace_permissions
        WHERE workspace_permissions.permission = requested_permission
          AND workspace_permissions.role = user_role
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = '';




-- workspaces policies
-- -- -- -- --
CREATE POLICY "workspace isolation policy"
ON base.workspaces
as RESTRICTIVE
to authenticated
USING (id = (((SELECT auth.jwt())  -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);


create policy "Allow Authorized select access"
on public.workspaces
as PERMISSIVE
for SELECT
to authenticated
using (
  ( SELECT authorize('workspaces.read') AS user_has_permissions)
);


create policy "update for workspaces"
on public.workspaces
as PERMISSIVE
for UPDATE
to authenticated
using (
  ( SELECT authorize('workspaces.update') AS user_has_permissions)
);

-- insert on workspaces should only be done from an authentic source i.e. service_role in supabase
create policy "insert for workspaces"
on public.workspaces
as PERMISSIVE
for INSERT
to service_role
WITH CHECK (
true
);


-- users policies
-- -- -- -- --
create policy "select for users"
on "base"."users"
as PERMISSIVE
for SELECT
to authenticated
using (
  ( SELECT authorize('users.read') AS user_has_permissions)
);

-- any user with permissions or self
create policy "update for users"
on "base"."users"
as PERMISSIVE
for UPDATE
to authenticated
using (
  ( SELECT authorize('users.update') AS user_has_permissions) OR (id = ( SELECT auth.uid() AS uid))
);




-- workspace_users policies
-- -- -- -- --
CREATE POLICY "workspace isolation policy"
ON base.workspace_users
as RESTRICTIVE
to authenticated
USING (workspace_id = (((SELECT auth.jwt())  -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);


create policy "select for only workspace users"
on "base"."workspace_users"
as PERMISSIVE
for SELECT
to authenticated
using (
  ( SELECT authorize('users.read') AS user_has_permissions)
);

create policy "insert for workspace users"
on "base"."workspace_users"
as PERMISSIVE
for INSERT
to authenticated
with check (
  ( SELECT authorize('users.create') AS user_has_permissions)
);

-- update should be enabled for the current user
create policy "update for workspace users or self"
on "base"."workspace_users"
as PERMISSIVE
for UPDATE
to authenticated
using (
  ( SELECT authorize('users.update') AS user_has_permissions) OR (user_id = ( SELECT auth.uid() AS uid))
);

-- delete should be enabled for the current user
create policy "delete for workspace users or self"
on "base"."workspace_users"
as PERMISSIVE
for DELETE
to authenticated
using (
  ( SELECT authorize('users.delete') AS user_has_permissions) OR (user_id = ( SELECT auth.uid() AS uid))
);


-- workspace_user_permissions policies
create policy "select for workspace user permissions to supabase_auth_admin"
on "base"."workspace_user_permissions"
as PERMISSIVE
for SELECT
to supabase_auth_admin
using (
  true
);
