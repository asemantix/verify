INSERT OR IGNORE INTO organisations (nom, email, code_hash) VALUES
  ('BNP Paribas', 'bnp@authentix.fr', '0dcabd6f43f8c9b4055ba5d65f7a0a1427c432438b6e6d0b1debfee167f060cb'),
  ('Cabinet Notaire Dupont', 'notaire@authentix.fr', '467174461490b30695fce7968afbc52a9898508ad3266d2cb9cf2a3d5a846ebb');

INSERT OR IGNORE INTO users (org_id, email, role) VALUES
  (1, 'bnp@authentix.fr', 'admin'),
  (2, 'notaire@authentix.fr', 'admin');
