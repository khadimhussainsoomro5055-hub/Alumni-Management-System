# Alumni Management System

Express, EJS and MySQL alumni portal.

## Requirements
- Node.js 18 or newer
- MySQL 8 or compatible

## Setup
1. Clone this repository.
2. Run `npm install`.
3. Import `database.sql` into MySQL (it creates the database/tables and adds the role column for existing databases).
4. Copy `.env.example` to `.env` and enter your local MySQL credentials.
5. Set `SESSION_SECRET` to a long random value (at least 32 characters).
6. Run `npm start` and open `http://localhost:3000`.

## Administrator access
1. Register a normal account through the signup page.
2. In phpMyAdmin or MySQL, promote the intended account:
   ```sql
   UPDATE alumni SET role='admin' WHERE email='your-admin-email@example.com';
   ```
3. Sign out and sign in again. Administrators are redirected to `/admin`.
4. Admins can edit/delete alumni and create, edit and delete events and job listings.

Never allow public signup to select an administrator role. Do not delete your own current administrator account.

## Security and deployment
- Never commit `.env` or real credentials.
- A database password was previously committed publicly. Rotate that password in MySQL; removing it from the current source does not erase it from Git history.
- Uploaded profile images have a 2 MB limit, MIME filtering and file-signature checks.
- Session cookies use HttpOnly and SameSite settings. Use HTTPS and set `NODE_ENV=production` in production.
- The default Express MemoryStore is suitable only for local development. Configure a persistent session store before deploying multiple instances or production traffic.
- Add CSRF protection and login rate limiting before exposing the app to the public internet.

## Notes
The application requires the latest `database.sql` schema. If you see a missing-column or missing-table error, import the schema and check that the `alumni`, `events` and `jobs` tables exist.
