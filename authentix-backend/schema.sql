-- AUTHENTIX SIGN — Backend D1 Schema

CREATE TABLE IF NOT EXISTS organisations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nom TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organisations(id),
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organisations(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS destinataires (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organisations(id),
  nom TEXT NOT NULL,
  email TEXT NOT NULL,
  cle_publique TEXT,
  date_ajout TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS envois (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organisations(id),
  destinataire_nom TEXT NOT NULL,
  destinataire_email TEXT NOT NULL,
  doc_hash TEXT NOT NULL,
  doc_name TEXT,
  statut TEXT NOT NULL DEFAULT 'envoye',
  relay_id TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

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

CREATE INDEX IF NOT EXISTS idx_sessions_org ON sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_destinataires_org ON destinataires(org_id);
CREATE INDEX IF NOT EXISTS idx_envois_org ON envois(org_id);
CREATE INDEX IF NOT EXISTS idx_key_requests_org ON key_requests(org_id);
CREATE INDEX IF NOT EXISTS idx_key_requests_status ON key_requests(status);

-- Données de test
-- code_hash = SHA-256 du code en clair (calculé par le worker au login)
-- Ici on insère directement les hash SHA-256 précalculés :
-- SHA-256("BNP2026")    = placeholder (sera inséré par le seed script)
-- SHA-256("NOTAIRE2026") = placeholder (sera inséré par le seed script)
