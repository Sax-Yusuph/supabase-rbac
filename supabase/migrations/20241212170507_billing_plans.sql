
-- Table for Billing Plans
CREATE TABLE "billing_plans" (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    price REAL,
    currency TEXT NOT NULL DEFAULT 'USD',
    INTERVAL public.billing_plans_interval NOT NULL DEFAULT 'month',
    trial_period_days REAL,
    features JSONB,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);


-- RLS Policies
-- Restrictive policy for restricting
CREATE POLICY "workspace isolation policy"
ON public.billing_plans
as RESTRICTIVE
to authenticated
USING (workspace_id = (((SELECT auth.jwt())  -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);

create policy "select policy"
ON public.billing_plans
as PERMISSIVE
for SELECT
to authenticated
using (
  ( SELECT public.authorize('billing_plans.read')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);

create policy "insert policy"
ON public.billing_plans
as PERMISSIVE
for INSERT
to authenticated
with check (
  ( SELECT public.authorize('billing_plans.create'))
);

create policy "update policy"
ON public.billing_plans
as PERMISSIVE
for UPDATE
to authenticated
using (
  ( SELECT public.authorize('billing_plans.update')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);

create policy "delete policy"
ON public.billing_plans
as PERMISSIVE
for DELETE
to authenticated
using (
  ( SELECT public.authorize('billing_plans.delete')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);
