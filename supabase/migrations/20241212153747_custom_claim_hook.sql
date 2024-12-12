-- Create the auth hook function
-- TODO enable this function in supabase dashboard --> Autorization > Hooks
CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb) RETURNS jsonb language plpgsql stable AS $$
DECLARE claims jsonb;

user_role  public.app_role;

BEGIN claims := event->'claims';

-- Fetch the user role in the user_roles table
SELECT role INTO user_role
FROM public.workspace_members
WHERE user_id = (event->>'user_id')::uuid
    AND workspace_id = (
        (claims->'app_metadata')::jsonb->>'workspace_id'
    )::uuid;

IF user_role IS NOT NULL THEN -- Set the claim
claims := jsonb_set(claims, '{user_role}', to_jsonb(user_role))
ELSE claims := jsonb_set(claims, '{user_role}', 'null');

END IF;

-- Update the 'claims' object in the original event
event := jsonb_set(event, '{claims}', claims);

-- Return the modified or original event
RETURN event;

END;

$$;

GRANT USAGE ON schema public TO supabase_auth_admin;

GRANT EXECUTE ON FUNCTION public.custom_access_token_hook TO supabase_auth_admin;

REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook
FROM authenticated,
    anon,
    public;

GRANT ALL ON TABLE public.user_roles TO supabase_auth_admin;

REVOKE ALL ON TABLE public.user_roles
FROM authenticated,
    anon,
    public;

CREATE policy "Allow auth admin to read user roles" ON public.user_roles AS permissive FOR
SELECT TO supabase_auth_admin USING (TRUE)
