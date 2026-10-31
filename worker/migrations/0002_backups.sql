-- Nightly Google Drive backups: where they go and how the last one went.
ALTER TABLE users ADD COLUMN backup_folder_id TEXT;
ALTER TABLE users ADD COLUMN last_backup_at INTEGER;
ALTER TABLE users ADD COLUMN last_backup_status TEXT;   -- ok | error | needs_drive | skipped_empty
ALTER TABLE users ADD COLUMN last_backup_error TEXT;
ALTER TABLE users ADD COLUMN last_backup_file TEXT;
