-- A request reserves and settles both its monthly and rolling quota buckets.
-- Reference uniqueness must therefore include the bucket, otherwise the
-- second legitimate reserve row is rejected on installations that received
-- the first schema revision.
DROP INDEX IF EXISTS uq_ledger_reference;
CREATE UNIQUE INDEX uq_ledger_reference
  ON ledger_entries(wallet_account_id, quota_bucket_id, entry_type, reference_type, reference_id)
  WHERE reference_id <> '';
