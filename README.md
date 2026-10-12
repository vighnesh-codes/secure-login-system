# SecureSpace — Secure Login System

A beginner-friendly full-stack authentication project built with HTML, CSS, JavaScript, Node.js, Express, SQLite, bcrypt, and server-side sessions.

## Features

- User registration and login
- bcrypt password hashing (cost factor 12)
- Server-side SQLite database with parameterized queries
- Input validation and generic invalid-login responses
- Server-side sessions stored in SQLite
- Session ID regeneration after login/registration
- HTTP-only, SameSite=Lax session cookie; Secure cookies in production
- Login and registration rate limiting
- Protected dashboard and logout
- Helmet security headers
- Responsive dark-blue and white UI

## Requirements

- Node.js 20 or newer
- npm

## Run locally

1. Extract the project ZIP and open a terminal in the `secure-login-system` folder.
2. Install dependencies:

   ```bash
   npm install
   ```

3. Copy `.env.example` to `.env`.

   On Windows Command Prompt:

   ```bat
   copy .env.example .env
   ```

   On PowerShell:

   ```powershell
   Copy-Item .env.example .env
   ```

4. Edit `.env` and set `SESSION_SECRET` to a long, random value of at least 32 characters. Do not commit `.env` to GitHub.
5. Start the server:

   ```bash
   npm start
   ```

6. Open `http://localhost:3000` in your browser.

Register an account, and the app will take you to the protected dashboard. You can also visit `/register` to create an account or use the Log out button.

## Database

The app creates `database/users.sqlite` and `database/sessions.sqlite` on first run. These are runtime files and are excluded from Git.

## Deploying

Deploy on a Node.js host that supports persistent storage. Set `SESSION_SECRET` and `NODE_ENV=production` in the host's environment variables, enable HTTPS, and ensure the `database` directory is writable and persists between deploys. `Secure` cookies are enabled in production. Do not deploy this SQLite configuration to an ephemeral filesystem without persistent storage.

## Security notes

This is a learning project, not a security audit or a production identity platform. Before using it for real users, add CSRF protection appropriate to the deployment, email verification, password reset, account lockout/abuse monitoring, dependency updates, backups, and security testing. Consider Argon2id for new systems. Do not reuse passwords from other services.

## API endpoints

- `POST /api/register` — create account
- `POST /api/login` — authenticate
- `GET /api/me` — return current authenticated user
- `POST /api/logout` — destroy the current session
- `GET /dashboard` — protected dashboard page
