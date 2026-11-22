CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  owner TEXT,
  repo TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  scan_hash TEXT NOT NULL,
  score NUMERIC(5,2) NOT NULL,
  grade CHAR(1) NOT NULL,
  files_scanned INTEGER NOT NULL,
  parse_errors INTEGER NOT NULL,
  ignored_files INTEGER NOT NULL,
  languages JSONB NOT NULL,
  summary JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  snippet TEXT NOT NULL,
  sink_type TEXT NOT NULL,
  pii_category TEXT NOT NULL,
  dpdp_section TEXT NOT NULL,
  data JSONB NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  verified_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS verified_fixes (
  source_scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  verified_scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  patch_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(source_scan_id, finding_id)
);

CREATE TABLE IF NOT EXISTS analysis_audit (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID,
  event TEXT NOT NULL,
  outcome TEXT NOT NULL,
  metadata JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id);
CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at DESC);
