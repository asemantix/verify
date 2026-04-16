-- AUTHENTIX SIGN — Migration 002
-- Public key sharing via tokenized URL

CREATE TABLE IF NOT EXISTS key_requests (
  token TEXT PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organisations(id),
  recipient_name TEXT NOT NULL,
  recipient_email TEXT NOT NULL,
  public_key TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  received_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_key_requests_org ON key_requests(org_id);
CREATE INDEX IF NOT EXISTS idx_key_requests_status ON key_requests(status);
