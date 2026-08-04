-- PostgreSQL-native desktop Agent identity. The legacy desktop bridge is not
-- consulted once the platform gateway switch is enabled.

ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS mac_proof_hash TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS platform_device_auth_flows (
  id UUID PRIMARY KEY,
  device_code_hash TEXT NOT NULL UNIQUE,
  user_code_hash TEXT NOT NULL UNIQUE,
  public_key BYTEA NOT NULL,
  device_name TEXT NOT NULL,
  platform TEXT NOT NULL,
  mac_hash TEXT NOT NULL,
  mac_proof_hash TEXT NOT NULL,
  mac_enc TEXT NOT NULL DEFAULT '',
  request_ip TEXT NOT NULL DEFAULT '',
  browser_ip TEXT NOT NULL DEFAULT '',
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','consumed','expired','revoked')),
  expires_at TIMESTAMPTZ NOT NULL,
  approved_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_platform_device_flow_code ON platform_device_auth_flows(user_code_hash, status, expires_at);

CREATE TABLE IF NOT EXISTS platform_device_sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
  access_hash TEXT NOT NULL UNIQUE,
  refresh_hash TEXT NOT NULL UNIQUE,
  access_expires_at TIMESTAMPTZ NOT NULL,
  refresh_expires_at TIMESTAMPTZ NOT NULL,
  last_ip TEXT NOT NULL DEFAULT '',
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_platform_device_sessions_active ON platform_device_sessions(user_id, device_id, revoked_at, refresh_expires_at);

CREATE TABLE IF NOT EXISTS platform_device_nonces (
  session_id UUID NOT NULL REFERENCES platform_device_sessions(id) ON DELETE CASCADE,
  nonce_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (session_id, nonce_hash)
);
CREATE INDEX IF NOT EXISTS idx_platform_device_nonces_expiry ON platform_device_nonces(expires_at);

CREATE TABLE IF NOT EXISTS agent_sub_keys (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_enc TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','expired')),
  expires_at TIMESTAMPTZ NOT NULL,
  last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_sub_keys_active ON agent_sub_keys(device_id, status, expires_at);
