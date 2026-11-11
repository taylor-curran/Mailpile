# Mailpile threat model

_Built from the code at 741e610f. Items marked **[user]** were stated by the maintainer; everything else is inferred from the code. Security scans use this document to prioritize findings._

## System overview

Mailpile is a self-hosted, Python 2 webmail client and search engine with built-in OpenPGP/Autocrypt support. One Mailpile process belongs to one Unix user: it fetches mail (IMAP/POP3/local mailboxes), indexes it locally (optionally encrypted), and serves a web UI + JSON API on `http://localhost:33411/` (`mailpile/httpd.py`, `sys.http_host` defaults to `localhost` in `mailpile/config/defaults.py`). It sends mail via SMTP (`mailpile/smtp_client.py`) and can route traffic through Tor (`mailpile/conn_brokers.py`, `mailpile/crypto/tor.py`).

**[user] Primary deployment: self-hosted via Docker, with the web UI exposed on a LAN or the internet** (`Dockerfile` binds `0.0.0.0:33411`). Treat the web UI as network-reachable by untrusted hosts, not as a localhost-only app.

Deployments seen in the repo:
- **Desktop / localhost** (default): `mp`, GUI launcher (`shared-data/mailpile-gui`), OS packages (`packages/`).
- **Docker**: `Dockerfile` runs `mailpile --www=0.0.0.0:33411/` and exposes the port; `docker-compose.yml` publishes `33411:33411`.
- **Multipile** (`shared-data/multipile`): Apache reverse proxy maps Unix users to per-user Mailpile processes on localhost ports; `mailpile-admin.py` (CGI) launches `mailpile-launcher.py` via `sudo`.

## Components

| Name | Covers |
|---|---|
| **Web UI & API** | `mailpile/httpd.py`, `mailpile/urlmap.py`, `mailpile/commands.py`, `mailpile/www/`, `mailpile/plugins/*` HTTP commands (incl. `webterminal.py`, `html_magic.py` `http_proxy`, `setup_magic.py`), `shared-data/default-theme`, `mailpile/ui.py` |
| **Auth & Sessions** | `mailpile/auth.py`, `mailpile/security.py` (CSRF, lockdown, CSP, passphrase storage), session cookie handling in `httpd.py` |
| **Mail Parsing & Rendering** | `mailpile/mailutils/` (MIME, HTML cleaning via `lxml.html.clean`), `mailpile/mailboxes/`, `mailpile/vcard.py`, `mailpile/plugins/vcard_*`, `mailpile/spambayes/`, attachment handling |
| **Crypto** | `mailpile/crypto/` (GnuPG wrapper `gpgi.py`, Autocrypt, AES records, streamer), `mailpile/plugins/crypto_*`, `mailpile/plugins/keylookup/` |
| **Mail Transport** | `mailpile/mail_source/` (IMAP/POP3/local), `mailpile/smtp_client.py`, `mailpile/plugins/smtp_server.py`, `mailpile/plugins/oauth.py`, `mailpile/conn_brokers.py`, `mailpile/crypto/tor.py` |
| **Storage & Config** | `mailpile/config/`, `mailpile/index/`, `mailpile/postinglist.py`, `mailpile/vfs.py`, `mailpile/plugins/backups.py`, `mailpile/plugins/migrate.py`, `mailpile/plugins/exporters.py` |
| **Deployment & Packaging** | `Dockerfile*`, `docker-compose*.yml`, `packages/`, `shared-data/multipile/`, `scripts/`, `mailpile/safe_popen.py`, `mailpile/platforms.py` |

## Trust boundaries

1. **Internet email → Mailpile**: every incoming message (headers, MIME parts, HTML, attachments, PGP/Autocrypt headers, vCards) is attacker-controlled.
2. **Browser → Web UI & API**: the user's browser talks to localhost; other websites in that browser can send cross-origin requests to `localhost:33411` (CSRF, DNS rebinding).
3. **Network → Docker/Multipile**: when bound to `0.0.0.0` or proxied, the web UI is reachable by anyone on the network.
4. **Mailpile → remote servers**: IMAP/POP3/SMTP/HTTPS/key servers/OAuth providers; network attackers sit in between.
5. **Mailpile → local OS**: GnuPG and other subprocesses (`safe_popen.py`), the filesystem (`vfs.py`, mailbox paths, `open_in_browser`), Multipile `sudo` launcher.
6. **Unix user boundary**: on multi-user hosts, other local users must not reach this user's data, sockets or ports.

## Entry points

- HTTP UI/API on port 33411: every `Command` with `HTTP_CALLABLE`; auth enforced in `UrlMap.map` when `HTTP_AUTH_REQUIRED`; POSTs require a CSRF token (`security.valid_csrf_token`). Static files under `/static/` and `/bower_components/` (`send_file`).
- Login (`auth/login`): passphrase checked against GnuPG/master key; falls back to a `DEFAULT` user with **no password** when GnuPG/keys are absent (`auth.py`, "FIXME: Unauthorized login allowed").
- Web terminal (`terminal_*` API in `plugins/webterminal.py`): runs arbitrary Mailpile CLI commands, blacklist of three commands.
- `http_proxy` (`plugins/html_magic.py`): authenticated GET of an arbitrary http(s) URL.
- Local SMTP server plugin (`plugins/smtp_server.py`, `sys.smtpd`, off by default): accepts mail with hashcash.
- Mail fetched from IMAP/POP3/local mailboxes; key lookups (WKD/keyservers), gravatar/libravatar, CardDAV, MOTD fetches (`secure_urlget`).
- CLI (`mp`) and config files in the Mailpile home directory.

## Assets

- Mail content and the search index (highly sensitive; optionally encrypted).
- OpenPGP private keys and passphrases (`SecurePassphraseStorage`), master key, `mailpile.sec` user secret.
- IMAP/POP3/SMTP passwords and OAuth2 tokens in the config.
- Contacts / vCards, tags, filters, event log.
- Integrity of outgoing mail (signing/encryption decisions, recipients) and of key trust state.
- The user's OS account (subprocess execution, filesystem access).

## Attacker profiles

**[user] All attacker profiles below are in scope.**

- **Remote email sender**: sends crafted messages to the user (XSS via HTML mail, MIME/PGP parser bugs, tracking pixels, key/Autocrypt injection).
- **Malicious website**: runs JS in the user's browser targeting `localhost:33411` (CSRF, DNS rebinding, clickjacking).
- **Network attacker**: MITM on IMAP/SMTP/HTTP fetches, TLS downgrade, Tor bypass.
- **Network-adjacent host**: reaches an exposed Docker/Multipile web UI directly (weak/absent auth).
- **Local user / co-tenant**: another Unix user on the same host (Multipile, shared machines).

## Existing controls

- Web UI binds `localhost` by default; random per-start session cookie name and server secret (`httpd.py`).
- CSRF tokens on POSTs (`security.make_csrf_token`), 48h validity.
- CSP header (`security.http_content_security_policy`) — weak: allows `unsafe-inline` and `unsafe-eval`.
- HTML mail cleaned with `lxml.html.clean` (`mailutils/html.py`).
- Lockdown levels gating dangerous commands (`security.py` `CC_*` lists, `forbid_config_change`).
- `secure_urlget` restricts schemes and honours `prefs.web_content`; ConnBroker enforces Tor/anonymity policies.
- Passphrase KDFs (PBKDF2 400k / scrypt), in-memory obfuscated passphrase storage, `RestrictReadAccess` on secrets.
- Subprocesses via `safe_popen.py` (no shell).

## Out of scope / accepted risk

**[user] Nothing is out of scope or accepted risk** — including Python 2 / outdated dependencies, packaging, Multipile, demo/lockdown mode and local attackers.

## Infrastructure

**[user] No separate infrastructure repository**; the in-repo `Dockerfile`, `docker-compose*.yml`, `packages/docker` and `shared-data/multipile` are the deployment description.

## Open questions

- Which assets matter most (mail content, PGP keys, mail-account credentials, the host OS account)? Not yet ranked by the user, so no finding is raised for asset criticality.
