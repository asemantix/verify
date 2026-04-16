ALTER TABLE organisations ADD COLUMN plan TEXT NOT NULL DEFAULT 'gratuit';
ALTER TABLE organisations ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE organisations ADD COLUMN confirm_token TEXT;
