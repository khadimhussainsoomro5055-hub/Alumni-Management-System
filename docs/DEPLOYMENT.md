# Deployment Guide

## Before deployment

- Run `npm install`, `npm run check` and `npm test`.
- Back up MySQL and the profile uploads directory.
- Use a dedicated MySQL user with only required privileges.
- Set `NODE_ENV=production`, `PORT`, DB variables and a random `SESSION_SECRET` (32+ characters).
- Keep secrets in the platform's secret manager, never in source control.

## Runtime

Run the application with a process manager (for example, systemd, PM2 or the hosting platform's Node runtime). Terminate TLS at a trusted reverse proxy and ensure Express trusts only the correct proxy hop. Do not expose the MySQL port publicly.

The app creates the `app_sessions` table on startup. Grant the app database user permission to create that table during initial deployment, or create it in advance:

```sql
CREATE TABLE IF NOT EXISTS app_sessions (
  session_id VARCHAR(128) NOT NULL PRIMARY KEY,
  data MEDIUMTEXT NOT NULL,
  expires_at DATETIME NOT NULL,
  INDEX idx_app_sessions_expiry (expires_at)
);
```

## Storage and scaling

The session store is MySQL-backed. Uploaded profile photos remain on local disk, so mount durable storage at `public/uploads/profiles`. If running multiple instances, mount shared storage or move uploads to object storage. Authentication throttling currently uses process memory; replace it with a shared rate-limit store before running multiple instances.

## Backups and recovery

Schedule encrypted database and upload backups. Periodically perform a restore drill into a non-production environment. Never test restore procedures against the live database.

## Security operations

- Rotate credentials that may have appeared in Git history.
- Restrict admin promotion to trusted database operators.
- Monitor authentication failures, server errors and disk usage.
- Keep Node.js and npm dependencies patched.
- Use HTTPS-only secure cookies in production.
