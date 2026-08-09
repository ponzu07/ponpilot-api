CREATE TABLE device_shares (
  dongle_id TEXT NOT NULL REFERENCES devices(dongle_id) ON DELETE CASCADE,
  owner_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (dongle_id, user_id)
);
