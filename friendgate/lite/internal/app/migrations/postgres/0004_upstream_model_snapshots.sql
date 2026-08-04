-- Raw upstream model discovery is retained separately from the public model
-- catalogue.  Nothing in this table is automatically published to Chat,
-- Agent, or external API clients.
CREATE TABLE IF NOT EXISTS upstream_model_snapshots (
  id UUID PRIMARY KEY,
  upstream_account_id UUID NOT NULL REFERENCES upstream_accounts(id) ON DELETE CASCADE,
  real_model_id TEXT NOT NULL,
  descriptor JSONB NOT NULL DEFAULT '{}'::jsonb,
  capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'unknown')),
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (upstream_account_id, real_model_id)
);
CREATE INDEX IF NOT EXISTS idx_upstream_model_snapshots_account ON upstream_model_snapshots(upstream_account_id, status, real_model_id);
