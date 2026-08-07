CREATE TABLE bootlogs (
  dongle_id  TEXT NOT NULL REFERENCES devices(dongle_id) ON DELETE CASCADE,
  filename   TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  owner_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  PRIMARY KEY (dongle_id, filename)
);
