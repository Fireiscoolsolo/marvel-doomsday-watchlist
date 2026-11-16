# Marvel Doomsday Watchlist

Run `node server.mjs` with Node.js 24 or newer and open `http://localhost:3000`. No package installation is needed.

Visitors can create an account with a username and password. Signed-in checkmarks sync through SQLite. Guest checkmarks stay in the local browser and are separate from account progress. There is no email verification, outside sign-in provider, or password recovery.

For deployment, run the Node app on a server with HTTPS and a persistent private disk. Set `PUBLIC_ORIGIN` to the public HTTPS address and `WATCHLIST_DATA_DIR` to the persistent directory. Point the server’s HTTPS proxy at the app's listening port. The app binds to loopback by default. Use `HOST` and `PORT` when your host needs different settings. A hosting plan must be able to run Node continuously and accommodate scrypt's memory use.

GitHub Pages serves static files. The account-enabled site needs the Node app and database to run together on a server. A private GitHub repository can hold the source. Keep database files and any backups outside the repository and public web directories.

Passwords are stored as salted scrypt hashes. Sessions use random tokens held in HttpOnly cookies, with the token hashes stored in SQLite. HTTPS deployments use Secure cookies. The app limits sign-in attempts in memory and restricts each session to its own progress. Behind a reverse proxy, the address-based limit applies to the proxy address. For a public launch at scale, configure per-client rate limiting at the HTTPS proxy.
