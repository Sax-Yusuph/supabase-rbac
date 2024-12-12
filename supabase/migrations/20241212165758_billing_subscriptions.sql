
-- Table for Billing Subscriptions
CREATE TABLE "billing_subscriptions" (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    STATUS "billing_subscription_status" NOT NULL,
    quantity REAL NOT NULL,
    started_at TIMESTAMP NOT NULL,
    cancel_at TIMESTAMP WITH TIME ZONE,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    canceled_at TIMESTAMP WITH TIME ZONE,
    current_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    current_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    ended_at TIMESTAMP WITH TIME ZONE,
    trial_ends_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT fk_billing_accounts FOREIGN KEY (account_id) REFERENCES "billing_accounts" (id) ON DELETE CASCADE
);


-- RLS Policies
-- Restrictive policy for restricting
CREATE POLICY "workspace isolation policy"
ON public.billing_subscriptions
as RESTRICTIVE
to authenticated
USING (workspace_id = (((SELECT auth.jwt())  -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);

create policy "select policy"
ON public.billing_subscriptions
as PERMISSIVE
for SELECT
to authenticated
using (
  ( SELECT public.authorize('billing_subscriptions.read')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);

create policy "insert policy"
ON public.billing_subscriptions
as PERMISSIVE
for INSERT
to authenticated
with check (
  ( SELECT public.authorize('billing_subscriptions.create'))
);

create policy "update policy"
ON public.billing_subscriptions
as PERMISSIVE
for UPDATE
to authenticated
using (
  ( SELECT public.authorize('billing_subscriptions.update')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);

create policy "delete policy"
ON public.billing_subscriptions
as PERMISSIVE
for DELETE
to authenticated
using (
  ( SELECT public.authorize('billing_subscriptions.delete')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);
