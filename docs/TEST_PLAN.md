# Regression Test Plan

Run `npm run check` and `npm test` before merging or deploying. The automated tests currently verify important route and form safeguards from source. They do not replace integration tests against a disposable MySQL database.

## Manual integration checklist

1. Import `database.sql` into a clean MySQL database and start the server.
2. Register an alumni account; verify duplicate email and passwords shorter than eight characters are rejected.
3. Sign in and sign out; verify a session remains valid across server restarts and expires after its configured lifetime.
4. Submit a profile update with no photo and with each supported image type; verify invalid MIME/signature and files over 2 MB are rejected.
5. Submit profile, admin edit, listing create/edit and delete forms; verify missing/invalid CSRF tokens are rejected.
6. Search the alumni directory and navigate pages; verify search terms persist between pages and no duplicate/missing records appear.
7. Change password with a wrong current password, mismatched confirmation and a valid new password.
8. As an administrator, create, edit and delete alumni/events/jobs. Verify non-admin users receive HTTP 403 on admin routes.
9. Verify an administrator cannot delete their own account and that account access is correct after role changes.
10. Test the layout at desktop and mobile widths.
11. Back up and restore the database and uploaded files in a non-production environment.

## Important environment boundary

Automated source checks do not validate SQL compatibility, database permissions, file-system permissions, reverse-proxy configuration or browser behavior. Those checks must be performed in the target environment.
