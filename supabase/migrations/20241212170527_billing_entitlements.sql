
-- Table for Billing Entitlements
CREATE TABLE "billing_entitlements" (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id TEXT NOT NULL,
    feature TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    LIMIT REAL, created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT fk_billing_accounts FOREIGN KEY (account_id) REFERENCES "billing_accounts" (id) ON DELETE CASCADE,
    CONSTRAINT billing_entitlements_idx UNIQUE (account_id, feature)
);

ALTER TABLE "billing_subscriptions"
ADD CONSTRAINT fk_account_subscription FOREIGN KEY (account_id) REFERENCES "billing_accounts" (id) ON DELETE CASCADE;




-- RLS Policies
-- Restrictive policy for restricting
CREATE POLICY "workspace isolation policy"
ON public.billing_entitlements
as RESTRICTIVE
to authenticated
USING (workspace_id = (((SELECT auth.jwt())  -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);

create policy "select policy"
ON public.billing_entitlements
as PERMISSIVE
for SELECT
to authenticated
using (
  ( SELECT public.authorize('billing_entitlements.read')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);

create policy "insert policy"
ON public.billing_entitlements
as PERMISSIVE
for INSERT
to authenticated
with check (
  ( SELECT public.authorize('billing_entitlements.create'))
);

create policy "update policy"
ON public.billing_entitlements
as PERMISSIVE
for UPDATE
to authenticated
using (
  ( SELECT public.authorize('billing_entitlements.update')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);

create policy "delete policy"
ON public.billing_entitlements
as PERMISSIVE
for DELETE
to authenticated
using (
  ( SELECT public.authorize('billing_entitlements.delete')) OR (created_by_id = ( SELECT auth.uid() AS uid))
);
