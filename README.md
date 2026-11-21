# Alumni Management System

Express, EJS and MySQL alumni portal.

## Requirements
- Node.js 18 or newer
- MySQL 8 or compatible

## Setup
1. Clone this repository.
2. Run `npm install`.
3. Import `database.sql` into MySQL.
4. Copy `.env.example` to `.env` and enter your local MySQL credentials. Generate a long random `SESSION_SECRET`.
5. Run `npm start` and open `http://localhost:3000`.

## Security
- Never commit `.env` or real credentials.
- A database password was previously committed publicly. Change that password in MySQL immediately; removing it from the latest source does not erase it from Git history.
- Uploaded profile images are checked by MIME type and detected file signature.
- Session cookies use HttpOnly and SameSite protections. Set `NODE_ENV=production` behind HTTPS.

## Administrator role
The schema adds `alumni.role` (`alumni` by default). After creating your account, promote the intended administrator directly in MySQL:

```sql
UPDATE alumni SET role='admin' WHERE email='your-admin-email@example.com';
```

Never allow public registration to choose an administrator role.
