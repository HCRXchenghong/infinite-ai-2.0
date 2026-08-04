-- The unified product schema is deliberately isolated from the legacy local
-- gateway tables. A verified importer is responsible for moving data between
-- them; this migration never mutates or deletes prior data.

CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  email TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
  password_hash TEXT NOT NULL DEFAULT '',
  email_verified_at TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_users_tenant_status ON users(tenant_id, status);

CREATE TABLE IF NOT EXISTS user_auth_identities (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('password', 'oauth', 'admin')),
  issuer TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  credential_enc TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, kind, issuer),
  UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS user_sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_token_hash TEXT NOT NULL,
  ip_prefix TEXT NOT NULL DEFAULT '',
  user_agent_hash TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
  expires_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_status ON user_sessions(user_id, status, expires_at);

CREATE TABLE IF NOT EXISTS user_devices (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key BYTEA NOT NULL UNIQUE,
  public_key_fingerprint TEXT NOT NULL UNIQUE,
  mac_address TEXT NOT NULL,
  device_name TEXT NOT NULL DEFAULT '',
  platform TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'reverify_required', 'revoked')),
  registered_ip TEXT NOT NULL DEFAULT '',
  last_ip TEXT NOT NULL DEFAULT '',
  last_seen_at TIMESTAMPTZ,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, mac_address)
);
CREATE INDEX IF NOT EXISTS idx_user_devices_user_status ON user_devices(user_id, status);

CREATE TABLE IF NOT EXISTS platform_models (
  id UUID PRIMARY KEY,
  model_key TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'chat' CHECK (category IN ('chat', 'image', 'audio', 'embedding', 'multimodal')),
  capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
  billing JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'disabled')),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_platform_models_status ON platform_models(status, model_key);

CREATE TABLE IF NOT EXISTS product_model_publications (
  id UUID PRIMARY KEY,
  model_id UUID NOT NULL REFERENCES platform_models(id) ON DELETE CASCADE,
  product_scope TEXT NOT NULL CHECK (product_scope IN ('chat', 'agent', 'external_api')),
  protocol TEXT NOT NULL CHECK (protocol IN ('responses', 'chat_completions', 'messages', 'generate_content')),
  enabled BOOLEAN NOT NULL DEFAULT true,
  default_for_scope BOOLEAN NOT NULL DEFAULT false,
  plan_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (model_id, product_scope, protocol)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_publication_default_per_scope
  ON product_model_publications(product_scope) WHERE default_for_scope AND enabled;

CREATE TABLE IF NOT EXISTS provider_connections (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  provider_kind TEXT NOT NULL CHECK (provider_kind IN ('oauth', 'openai_compatible', 'anthropic_compatible', 'gemini_compatible')),
  provider_name TEXT NOT NULL,
  base_url TEXT NOT NULL DEFAULT '',
  credential_enc TEXT NOT NULL DEFAULT '',
  settings JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'disabled', 'error')),
  last_health_at TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_provider_connections_tenant_status ON provider_connections(tenant_id, status);

CREATE TABLE IF NOT EXISTS proxy_pools (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS proxy_endpoints (
  id UUID PRIMARY KEY,
  pool_id UUID NOT NULL REFERENCES proxy_pools(id) ON DELETE CASCADE,
  endpoint_enc TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100 CHECK (priority >= 0),
  weight INTEGER NOT NULL DEFAULT 100 CHECK (weight > 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'cooldown')),
  health_score NUMERIC(5,2) NOT NULL DEFAULT 100 CHECK (health_score >= 0 AND health_score <= 100),
  cooldown_until TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_proxy_endpoints_pool_status ON proxy_endpoints(pool_id, status, priority);

CREATE TABLE IF NOT EXISTS upstream_accounts (
  id UUID PRIMARY KEY,
  connection_id UUID NOT NULL REFERENCES provider_connections(id) ON DELETE CASCADE,
  proxy_pool_id UUID REFERENCES proxy_pools(id) ON DELETE SET NULL,
  external_account_ref_hash TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL,
  credential_enc TEXT NOT NULL DEFAULT '',
  model_catalog JSONB NOT NULL DEFAULT '[]'::jsonb,
  quota_state JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'cooldown', 'reauthorization_required', 'exhausted')),
  health_score NUMERIC(5,2) NOT NULL DEFAULT 100 CHECK (health_score >= 0 AND health_score <= 100),
  cooldown_until TIMESTAMPTZ,
  reset_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (connection_id, external_account_ref_hash)
);
CREATE INDEX IF NOT EXISTS idx_upstream_accounts_select ON upstream_accounts(connection_id, status, reset_at, cooldown_until);

CREATE TABLE IF NOT EXISTS route_pools (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  selection_policy TEXT NOT NULL DEFAULT 'quota_aware' CHECK (selection_policy IN ('quota_aware', 'fixed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS route_pool_members (
  id UUID PRIMARY KEY,
  route_pool_id UUID NOT NULL REFERENCES route_pools(id) ON DELETE CASCADE,
  upstream_account_id UUID NOT NULL REFERENCES upstream_accounts(id) ON DELETE CASCADE,
  priority INTEGER NOT NULL DEFAULT 100 CHECK (priority >= 0),
  weight INTEGER NOT NULL DEFAULT 100 CHECK (weight > 0),
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (route_pool_id, upstream_account_id)
);
CREATE INDEX IF NOT EXISTS idx_route_pool_members_select ON route_pool_members(route_pool_id, enabled, priority);

CREATE TABLE IF NOT EXISTS model_route_targets (
  id UUID PRIMARY KEY,
  model_id UUID NOT NULL REFERENCES platform_models(id) ON DELETE CASCADE,
  product_scope TEXT NOT NULL CHECK (product_scope IN ('chat', 'agent', 'external_api')),
  protocol TEXT NOT NULL CHECK (protocol IN ('responses', 'chat_completions', 'messages', 'generate_content')),
  route_pool_id UUID NOT NULL REFERENCES route_pools(id) ON DELETE RESTRICT,
  upstream_model_id TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100 CHECK (priority >= 0),
  enabled BOOLEAN NOT NULL DEFAULT true,
  capability_overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (model_id, product_scope, protocol, route_pool_id, upstream_model_id)
);
CREATE INDEX IF NOT EXISTS idx_model_route_targets_lookup ON model_route_targets(model_id, product_scope, protocol, enabled, priority);

CREATE TABLE IF NOT EXISTS route_affinities (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  scope_hash TEXT NOT NULL,
  route_pool_id UUID NOT NULL REFERENCES route_pools(id) ON DELETE CASCADE,
  upstream_account_id UUID NOT NULL REFERENCES upstream_accounts(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, scope_hash)
);
CREATE INDEX IF NOT EXISTS idx_route_affinities_expiry ON route_affinities(expires_at);

CREATE TABLE IF NOT EXISTS plans (
  id UUID PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  sort_order INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'retired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plan_versions (
  id UUID PRIMARY KEY,
  plan_id UUID NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
  version INTEGER NOT NULL CHECK (version > 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  monthly_price_minor BIGINT NOT NULL DEFAULT 0 CHECK (monthly_price_minor >= 0),
  chat_monthly_tokens BIGINT NOT NULL CHECK (chat_monthly_tokens >= 0),
  agent_monthly_tokens BIGINT NOT NULL CHECK (agent_monthly_tokens >= 0),
  chat_rolling_5h_tokens BIGINT NOT NULL CHECK (chat_rolling_5h_tokens >= 0),
  agent_rolling_5h_tokens BIGINT NOT NULL CHECK (agent_rolling_5h_tokens >= 0),
  entitlements JSONB NOT NULL DEFAULT '{}'::jsonb,
  model_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
  starts_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ends_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (plan_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_versions_current ON plan_versions(plan_id) WHERE ends_at IS NULL;

CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  plan_version_id UUID NOT NULL REFERENCES plan_versions(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('trialing', 'active', 'past_due', 'cancelled', 'expired')),
  source TEXT NOT NULL CHECK (source IN ('free_assignment', 'admin_grant', 'payment')),
  starts_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ NOT NULL,
  snapshot JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_active ON subscriptions(user_id, status, starts_at, ends_at);

CREATE TABLE IF NOT EXISTS wallet_accounts (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_scope TEXT NOT NULL CHECK (product_scope IN ('chat', 'agent', 'external_api')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, product_scope)
);

CREATE TABLE IF NOT EXISTS quota_buckets (
  id UUID PRIMARY KEY,
  wallet_account_id UUID NOT NULL REFERENCES wallet_accounts(id) ON DELETE CASCADE,
  window_kind TEXT NOT NULL CHECK (window_kind IN ('monthly', 'rolling_5h', 'grant')),
  starts_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ NOT NULL,
  granted_tokens BIGINT NOT NULL CHECK (granted_tokens >= 0),
  reserved_tokens BIGINT NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
  settled_tokens BIGINT NOT NULL DEFAULT 0 CHECK (settled_tokens >= 0),
  source_subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (reserved_tokens + settled_tokens <= granted_tokens)
);
CREATE INDEX IF NOT EXISTS idx_quota_buckets_available ON quota_buckets(wallet_account_id, window_kind, starts_at, ends_at);

CREATE TABLE IF NOT EXISTS ledger_entries (
  id UUID PRIMARY KEY,
  wallet_account_id UUID NOT NULL REFERENCES wallet_accounts(id) ON DELETE RESTRICT,
  quota_bucket_id UUID REFERENCES quota_buckets(id) ON DELETE RESTRICT,
  entry_type TEXT NOT NULL CHECK (entry_type IN ('recharge', 'grant', 'reserve', 'settle', 'release', 'refund', 'adjustment', 'expire')),
  tokens BIGINT NOT NULL,
  reference_type TEXT NOT NULL DEFAULT '',
  reference_id TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_wallet_created ON ledger_entries(wallet_account_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ledger_reference ON ledger_entries(wallet_account_id, quota_bucket_id, entry_type, reference_type, reference_id) WHERE reference_id <> '';

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  selected_model_id UUID REFERENCES platform_models(id) ON DELETE SET NULL,
  tool_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, name)
);

CREATE TABLE IF NOT EXISTS api_keys_v2 (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  route_pool_id UUID REFERENCES route_pools(id) ON DELETE SET NULL,
  label TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_enc TEXT NOT NULL,
  key_version BIGINT NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'deleted')),
  expires_at TIMESTAMPTZ,
  ip_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  device_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  last_used_at TIMESTAMPTZ,
  disabled_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_v2_user_status ON api_keys_v2(user_id, status);

CREATE TABLE IF NOT EXISTS api_key_scopes (
  api_key_id UUID NOT NULL REFERENCES api_keys_v2(id) ON DELETE CASCADE,
  product_scope TEXT NOT NULL CHECK (product_scope IN ('chat', 'agent', 'external_api')),
  model_id UUID REFERENCES platform_models(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (api_key_id, product_scope, model_id)
);

CREATE TABLE IF NOT EXISTS usage_records (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  api_key_id UUID REFERENCES api_keys_v2(id) ON DELETE SET NULL,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  device_id UUID REFERENCES user_devices(id) ON DELETE SET NULL,
  model_id UUID REFERENCES platform_models(id) ON DELETE SET NULL,
  upstream_account_id UUID REFERENCES upstream_accounts(id) ON DELETE SET NULL,
  product_scope TEXT NOT NULL CHECK (product_scope IN ('chat', 'agent', 'external_api')),
  protocol TEXT NOT NULL,
  request_id TEXT NOT NULL,
  session_scope_hash TEXT NOT NULL DEFAULT '',
  status_code INTEGER NOT NULL,
  input_tokens BIGINT NOT NULL DEFAULT 0,
  cached_input_tokens BIGINT NOT NULL DEFAULT 0,
  output_tokens BIGINT NOT NULL DEFAULT 0,
  reasoning_tokens BIGINT NOT NULL DEFAULT 0,
  billed_tokens BIGINT NOT NULL DEFAULT 0,
  estimated BOOLEAN NOT NULL DEFAULT false,
  tool_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  cost_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_code TEXT NOT NULL DEFAULT '',
  duration_ms BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_usage_user_scope_time ON usage_records(user_id, product_scope, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_tenant_time ON usage_records(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  actor_kind TEXT NOT NULL,
  action TEXT NOT NULL,
  target_kind TEXT NOT NULL,
  target_id TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS payment_providers (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  provider_type TEXT NOT NULL,
  merchant_id TEXT NOT NULL DEFAULT '',
  configuration_enc TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT false,
  health_status TEXT NOT NULL DEFAULT 'unconfigured' CHECK (health_status IN ('unconfigured', 'healthy', 'error')),
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, provider_type, merchant_id)
);

CREATE TABLE IF NOT EXISTS payment_orders (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  provider_id UUID REFERENCES payment_providers(id) ON DELETE RESTRICT,
  order_no TEXT NOT NULL UNIQUE,
  product_scope TEXT NOT NULL CHECK (product_scope IN ('chat', 'agent', 'external_api')),
  amount_minor BIGINT NOT NULL CHECK (amount_minor >= 0),
  currency TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('created', 'pending', 'paid', 'closed', 'refunded')),
  product_snapshot JSONB NOT NULL,
  provider_trade_no TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ NOT NULL,
  paid_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider_id, provider_trade_no)
);

CREATE TABLE IF NOT EXISTS invitations_v2 (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  role_label TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  code_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'revoked', 'expired', 'deleted')),
  policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  expires_at TIMESTAMPTZ NOT NULL,
  claimed_by UUID REFERENCES users(id) ON DELETE SET NULL,
  claimed_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_invitations_v2_tenant_status ON invitations_v2(tenant_id, status, expires_at);

CREATE TABLE IF NOT EXISTS ip_bans_v2 (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  ip_or_prefix TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'all' CHECK (scope IN ('all', 'api', 'portal', 'guide', 'admin')),
  reason TEXT NOT NULL,
  permanent BOOLEAN NOT NULL DEFAULT false,
  expires_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  CHECK ((permanent AND expires_at IS NULL) OR (NOT permanent AND expires_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_ip_bans_v2_active ON ip_bans_v2(tenant_id, ip_or_prefix, scope, expires_at) WHERE revoked_at IS NULL;
