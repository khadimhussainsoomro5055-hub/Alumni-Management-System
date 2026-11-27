# Alumni Management System

An alumni portal built with Node.js, Express 5, EJS and MySQL. It supports alumni registration, authentication, profiles, a searchable directory, events, jobs and administrator CRUD.

## Requirements

- Node.js 18+
- MySQL 8+ (or a compatible MySQL server)
- npm

## Brand assets

The public landing page uses the Sukkur IBA Administration Block photograph at `public/images/iba-administration-block.jpg` and the IBA Alumni Connect wordmark at `public/images/iba-alumni-connect.svg`. Keep both files in that directory when deploying the application. The SVG logo is tracked in the repository; copy the supplied campus photograph into `public/images/` as `iba-administration-block.jpg`.

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

## First administrator setup and login

There is **no default administrator username or password**. For security, the application does not create a hard-coded admin account.

1. Start the application and open `http://localhost:3000/signup`.
2. Create your account using your own email address and a strong password. Choose your department and graduation year as normal.
3. Open phpMyAdmin (or MySQL Workbench), select the `alumni_system` database, open the SQL tab and run the following statement with the exact email used during signup:

```sql
UPDATE alumni
SET role = 'admin'
WHERE email = 'your-admin-email@example.com';
```

4. Confirm that the account was promoted:

```sql
SELECT id, full_name, email, role
FROM alumni
WHERE email = 'your-admin-email@example.com';
```

The `role` result must be `admin`. If it reports `alumni` or no row is returned, check the email address and run the update again.

5. Sign out of Alumni Connect, then sign in at `http://localhost:3000/signin` using the same email and password you registered with. The application checks the database role and redirects an administrator to `/admin`; regular alumni go to `/dashboard`.

Administrators can manage alumni accounts, events and job opportunities from the admin dashboard. Public signup never accepts an administrator role. The application prevents an administrator from deleting their own account and prevents demoting the last administrator.

**Important:** Do not share your database administrator password or add a plain-text admin password to source code. Only promote trusted accounts using a MySQL administrator connection.

## SMTP email configuration

The registration form sends a welcome email after account creation. The public contact form sends submitted messages to the configured `SMTP_FROM` mailbox and sets the sender as `Reply-To`.

1. Copy `.env.example` to `.env`.
2. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS` and `SMTP_FROM` for your email provider.
3. For Gmail, enable 2-Step Verification and use a Google App Password; do not use your normal account password. For university SMTP, use the host, port and TLS settings supplied by your IT administrator.
4. Restart the Node.js server after changing `.env`.

If SMTP is not configured or the provider rejects a message, account creation still succeeds but the sign-in page warns that the welcome email could not be sent. Contact submissions show a send failure so the sender can retry. Never commit SMTP credentials.

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
