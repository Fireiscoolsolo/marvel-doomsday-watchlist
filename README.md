# Marvel Doomsday Watchlist

Run `node server.mjs` with Node.js 24 or newer and open `http://localhost:3000`. No package installation is needed.

Visitors can create an account with a username and password. Guest checkmarks stay in the local browser and are separate from account progress. There is no email verification, outside sign-in provider, or password recovery.

## Free hosting with Render and Neon

1. Create a Neon Postgres project on the Free plan. Copy its pooled connection string with TLS enabled. Keep it private.
2. Create a Render Web Service and connect this repository's `main` branch. Select Node and the Free instance.
3. Set the build command to `npm ci` and the start command to `npm start`.
4. In Render's environment settings, set `NODE_VERSION` to `24` and `DATABASE_URL` to the Neon connection string. Render supplies `PORT` and `RENDER_EXTERNAL_URL`.
5. Deploy. The service creates its tables on startup. To verify sync, create an account, check off a title, and sign in from a separate browser session.

Neon stores accounts, sessions, and checkmarks independently of Render. The first request after inactivity may take a minute while Render wakes up. Free-tier quotas apply.

## Other deployments

Use HTTPS and set `PUBLIC_ORIGIN` to the site's HTTPS origin. Set `DATABASE_URL` and install dependencies with `npm ci` to use Postgres. For a persistent SQLite deployment, omit `DATABASE_URL` and set `WATCHLIST_DATA_DIR` to a private, persistent directory. The app binds to loopback by default outside Render. Set `HOST` and `PORT` as needed.

GitHub Pages serves static files. The account-enabled site uses a Node service plus SQLite or Postgres. A private GitHub repository can hold its source. Keep connection strings, database files, and backups outside the repository and public web directories.

Passwords are stored as salted scrypt hashes. Sessions use random tokens held in HttpOnly cookies, with the token hashes stored in the database. HTTPS deployments use Secure cookies. The app limits sign-in attempts in memory and restricts each session to its own progress. Behind a reverse proxy, the address-based limit applies to the proxy address. For a public launch at scale, configure per-client rate limiting at the HTTPS proxy.
