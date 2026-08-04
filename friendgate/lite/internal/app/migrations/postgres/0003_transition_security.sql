-- Transition metadata is isolated from product data.  It makes a legacy
-- import reproducible and auditable without ever making it an implicit side
-- effect of starting the service.

CREATE TABLE IF NOT EXISTS legacy_import_runs (
  id UUID PRIMARY KEY,
  source_fingerprint TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('dry_run', 'apply')),
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
  report JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  error_text TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_legacy_import_runs_source ON legacy_import_runs(source_fingerprint, started_at DESC);

-- The IDs are deterministic UUIDs derived from the source row identity.  The
-- map documents every relationship used by the importer and lets verification
-- distinguish "not present in the old product" from an import defect.
CREATE TABLE IF NOT EXISTS legacy_identity_map (
  source_kind TEXT NOT NULL,
  source_id TEXT NOT NULL,
  target_id UUID NOT NULL,
  import_run_id UUID NOT NULL REFERENCES legacy_import_runs(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (source_kind, source_id)
);
CREATE INDEX IF NOT EXISTS idx_legacy_identity_map_target ON legacy_identity_map(target_id);

-- These settings are the unified authority for product policies.  They are
-- tenant scoped so a future multi-tenant deployment cannot accidentally
-- share a registration or payment switch.
CREATE TABLE IF NOT EXISTS platform_settings (
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  value JSONB NOT NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, key)
);

-- The original column name suggested plaintext storage.  Retaining a raw MAC
-- address in the product database is unnecessary and makes a database export
-- more sensitive.  The renamed field contains a non-reversible keyed digest;
-- the optional ciphertext exists only for a controlled device re-verification
-- flow and is never returned by regular APIs.
ALTER TABLE user_devices RENAME COLUMN mac_address TO mac_hash;
ALTER TABLE user_devices ADD COLUMN mac_enc TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS administrators (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  totp_secret_enc TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'owner' CHECK (role IN ('owner', 'operations', 'upstream', 'security_auditor')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
