# Alumni Management System

An alumni portal built with Node.js, Express 5, EJS and MySQL. It supports alumni registration, authentication, profiles, a searchable directory, events, jobs and administrator CRUD.

## Requirements

- Node.js 18+
- MySQL 8+ (or a compatible MySQL server)
- npm

## Local setup

1. Clone the repository and run `npm install`.
2. Import `database.sql` into MySQL. It creates the `alumni_system` database and the application tables.
3. Copy `.env.example` to `.env` and set your database values.
4. Generate a unique session secret (at least 32 characters) and set `SESSION_SECRET`.
5. Run `npm start`, then open `http://localhost:3000`.

Example PowerShell commands:

```powershell
Copy-Item .env.example .env
npm install
npm start
```

Do not commit `.env`, database passwords, session secrets or uploaded user data.

## Administrator setup

1. Register through the normal signup page.
2. Promote the intended account using a trusted MySQL administrator account:

```sql
UPDATE alumni SET role='admin' WHERE email='your-admin-email@example.com';
```

3. Sign out and sign in again. Admins are redirected to `/admin`.

Administrators can manage alumni accounts, events and jobs. Public signup never accepts an administrator role. The application prevents an administrator from deleting their own account.

## Features

- Alumni signup/signin/logout with bcrypt password hashing
- Profile editing and profile-photo upload (2 MB maximum; JPG, PNG and WEBP)
- Session-bound CSRF protection, including multipart profile updates
- MySQL-backed persistent sessions in the `app_sessions` table
- Authentication attempt throttling and baseline HTTP security headers
- Alumni directory search and 12-record pagination
- Authenticated password change
- Admin CRUD for alumni, events and job opportunities
- Responsive layout and empty states

## Commands

- `npm start` — start the server
- `npm run check` — syntax-check the server
- `npm test` — run automated regression checks

## Database and backups

Back up the database before importing schema changes or deploying an update:

```bash
mysqldump -u YOUR_DB_USER -p alumni_system > alumni_system_backup.sql
```

Restore only after reviewing the target database:

```bash
mysql -u YOUR_DB_USER -p alumni_system < alumni_system_backup.sql
```

The app creates `app_sessions` at startup. Expired sessions are cleaned during startup; periodically remove expired rows on long-running deployments.

## Production checklist

- Set `NODE_ENV=production` and a strong, unique `SESSION_SECRET`.
- Use HTTPS and configure the reverse proxy correctly.
- Use a dedicated least-privilege MySQL account, not root.
- Restrict database network access and keep credentials in the hosting provider's secret manager.
- Configure automated database backups and test restoration.
- Persist `public/uploads/profiles` on durable storage and back it up.
- Configure log collection, monitoring and a process manager.
- Review rate-limit behavior for multi-instance deployments; the built-in limiter is process-local and should be moved to a shared store for a cluster.
- Rotate any database credentials that were ever committed to Git. Removing a secret from the latest source does not erase it from Git history; use GitHub's secret-scanning guidance and a coordinated history rewrite if necessary.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and [docs/TEST_PLAN.md](docs/TEST_PLAN.md).

## Known limitations

- Password reset by email is not implemented because no email provider or verified delivery configuration is part of this project. Use the authenticated password-change flow.
- Uploads are stored on the application filesystem; use durable shared storage for multiple app instances.
- Login throttling is process-local; use a shared store when horizontally scaling.
