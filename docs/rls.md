# Database Policies and Functions README

This document explains the database functions and policies implemented for managing access control and permissions in our application.

## Table of Contents

1. [Functions](#functions)
   - [authorize](#function-authorize)
2. [Policies](#policies)
   - [Workspaces Policies](#workspaces-policies)
   - [Users Policies](#users-policies)
   - [Workspace Users Policies](#workspace-users-policies)
   - [Workspace User Permissions Policies](#workspace-user-permissions-policies)

## Functions

### Function: authorize

This function checks if a user has the requested permissions based on their JWT token.

```sql
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
```

## Policies

### Workspaces Policies

#### Workspace Isolation Policy

Restricts access to workspaces based on the user's workspace_id in their JWT token.

```sql
CREATE POLICY "workspace isolation policy"
ON public.workspaces
as RESTRICTIVE
to authenticated
USING (id = (((SELECT auth.jwt()) -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);
```

#### Select for Workspaces

Allows authenticated users with 'workspaces.read' permission to select workspaces.

```sql
create policy "select for workspaces"
on "base"."workspaces"
as PERMISSIVE
for SELECT
to authenticated
using (
 ( SELECT public.authorize('workspaces.read'))
);
```

#### Update for Workspaces

Allows authenticated users with 'workspaces.update' permission to update workspaces.

```sql
create policy "update for workspaces"
on "base"."workspaces"
as PERMISSIVE
for UPDATE
to authenticated
using (
 ( SELECT public.authorize('workspaces.update'))
);
```

#### Insert for Workspaces

Allows only service_role to insert new workspaces.

```sql
create policy "insert for workspaces"
on "base"."workspaces"
as PERMISSIVE
for INSERT
to service_role
WITH CHECK (
 true
);
```

### Users Policies

#### Select for Users

Allows authenticated users with 'users.read' permission to select users.

```sql
create policy "select for users"
on "base"."users"
as PERMISSIVE
for SELECT
to authenticated
using (
 ( SELECT public.authorize('users.read'))
);
```

#### Update for Users

Allows authenticated users with 'users.update' permission or the user themselves to update user information.

```sql
create policy "update for users"
on "base"."users"
as PERMISSIVE
for UPDATE
to authenticated
using (
 ( SELECT public.authorize('users.update')) OR (id = ( SELECT auth.uid() AS uid))
);
```

### Workspace Users Policies

#### Workspace Isolation Policy

Restricts access to workspace users based on the user's workspace_id in their JWT token.

```sql
CREATE POLICY "workspace isolation policy"
ON public.workspace_users
as RESTRICTIVE
to authenticated
USING (workspace_id = (((SELECT auth.jwt()) -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);
```

#### Select for Workspace Users

Allows authenticated users with 'users.read' permission to select workspace users.

```sql
create policy "select for only workspace users"
on "base"."workspace_users"
as PERMISSIVE
for SELECT
to authenticated
using (
 ( SELECT public.authorize('users.read'))
);
```

#### Insert for Workspace Users

Allows authenticated users with 'users.create' permission to insert new workspace users.

```sql
create policy "insert for workspace users"
on "base"."workspace_users"
as PERMISSIVE
for INSERT
to authenticated
with check (
 ( SELECT public.authorize('users.create'))
);
```

#### Update for Workspace Users

Allows authenticated users with 'users.update' permission or the user themselves to update workspace user information.

```sql
create policy "update for workspace users or self"
on "base"."workspace_users"
as PERMISSIVE
for UPDATE
to authenticated
using (
 ( SELECT public.authorize('users.update')) OR (user_id = ( SELECT auth.uid() AS uid))
);
```

#### Delete for Workspace Users

Allows authenticated users with 'users.delete' permission or the user themselves to delete workspace user information.

```sql
create policy "delete for workspace users or self"
on "base"."workspace_users"
as PERMISSIVE
for DELETE
to authenticated
using (
 ( SELECT public.authorize('users.delete')) OR (user_id = ( SELECT auth.uid() AS uid))
);
```

### Workspace User Permissions Policies

#### Select for Workspace User Permissions

Allows supabase_auth_admin to select workspace user permissions.

```sql
create policy "select for workspace user permissions to supabase_auth_admin"
on "base"."workspace_user_permissions"
as PERMISSIVE
for SELECT
to supabase_auth_admin
using (
 true
);
```
