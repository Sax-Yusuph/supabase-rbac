CREATE TYPE "billing_plans_interval" AS ENUM ('day', 'week', 'month', 'year');

CREATE TYPE "billing_subscription_status" AS ENUM (
    'incomplete',
    'incomplete_expired',
    'trialing',
    'active',
    'past_due',
    'canceled',
    'unpaid',
    'paused'
);

-- Table for Billing Accounts
CREATE TABLE "billing_accounts" (
    id TEXT PRIMARY KEY REFERENCES "workspaces" (id) ON DELETE CASCADE,
    -- stripe customerId
    customer_id TEXT UNIQUE,
    email TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);



-- Restrictive policy for restricting
CREATE POLICY "workspace isolation policy"
ON public.billing_accounts
as RESTRICTIVE
to authenticated
USING (workspace_id = (((SELECT auth.jwt())  -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);

create policy "select policy"
ON public.billing_accounts
as PERMISSIVE
for SELECT
to authenticated
using (
  ( SELECT public.authorize('billing_accounts.read')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);

create policy "insert policy"
ON public.billing_accounts
as PERMISSIVE
for INSERT
to authenticated
with check (
  ( SELECT public.authorize('billing_accounts.create'))
);

create policy "update policy"
ON public.billing_accounts
as PERMISSIVE
for UPDATE
to authenticated
using (
  ( SELECT public.authorize('billing_accounts.update')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);

create policy "delete policy"
ON public.billing_accounts
as PERMISSIVE
for DELETE
to authenticated
using (
  ( SELECT public.authorize('billing_accounts.delete')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);
