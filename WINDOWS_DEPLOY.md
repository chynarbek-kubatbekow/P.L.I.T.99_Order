# Windows Physical Server Deploy

This guide describes deployment on a physical Windows server.

Read [SECURITY.md](SECURITY.md) before exposing the server. It contains the current
hardening changes, test results, backup/upgrade steps, and remaining server checks.
Never serve the project directory directly from IIS.
For subsequent releases, follow [REDEPLOY.md](REDEPLOY.md), including backups and rollback.

Recommended stack:

1. Windows Server 2019/2022 or Windows 10/11 Pro on a physical machine
2. Python 3.11
3. PostgreSQL for Windows
4. Waitress as the WSGI application server
5. IIS with URL Rewrite and Application Request Routing as the public reverse proxy
6. NSSM or Windows Task Scheduler to keep the app running

## Production Layout

Recommended directories:

```text
C:\plit99\
  app\
  data\
  venv\
```

Where:

- `app\` is the Django project
- `data\` stores uploaded media and runtime files
- `venv\` stores Python packages

## 1. Install Software

Install:

1. Python 3.11 for Windows
2. Git for Windows
3. PostgreSQL for Windows
4. IIS
5. URL Rewrite for IIS
6. Application Request Routing for IIS
7. NSSM, if you want to run the site as a Windows service

During Python installation, enable `Add python.exe to PATH`.

## 2. Copy Or Clone The Project

Open PowerShell as Administrator:

```powershell
New-Item -ItemType Directory -Force C:\plit99
Set-Location C:\plit99
git clone <YOUR_REPO_URL> app
Set-Location C:\plit99\app
```

If the project is copied manually, place it in `C:\plit99\app`.

## 3. Create Virtual Environment

```powershell
py -3.11 -m venv C:\plit99\venv
C:\plit99\venv\Scripts\Activate.ps1
python -m pip install --only-binary=:all: -r requirements.txt
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 4. Create PostgreSQL Database

Open `psql` from the Start menu or run it from the PostgreSQL `bin` folder.

Run:

```sql
CREATE ROLE plit99_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE plit99_user LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
\password plit99_owner
\password plit99_user
CREATE DATABASE plit99_db OWNER plit99_owner;
\connect plit99_db
REVOKE ALL ON DATABASE plit99_db FROM PUBLIC;
GRANT CONNECT ON DATABASE plit99_db TO plit99_user;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO plit99_owner;
GRANT USAGE ON SCHEMA public TO plit99_user;
ALTER DEFAULT PRIVILEGES FOR ROLE plit99_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO plit99_user;
ALTER DEFAULT PRIVILEGES FOR ROLE plit99_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO plit99_user;
ALTER ROLE plit99_user SET client_encoding TO 'UTF8';
ALTER ROLE plit99_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE plit99_user SET timezone TO 'Asia/Bishkek';
-- For an existing database, also grant on the already-created application tables:
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO plit99_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO plit99_user;
```

## 5. Create Data Directory

```powershell
New-Item -ItemType Directory -Force C:\plit99\data\media
```

## 6. Create Environment File

Create `C:\plit99\app\.env` from `.env.example`.

Production example:

```text
DEBUG=False
APP_ENV=production
SECRET_KEY=replace-with-a-long-random-secret
ALLOWED_HOSTS=your-domain.com,www.your-domain.com,server-ip,localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://your-domain.com,https://www.your-domain.com
APP_DATA_DIR=C:\plit99\data
PYTHON_EXECUTABLE=C:/plit99/venv/Scripts/python.exe
DATABASE_URL=postgresql://APP_USER:URL_ENCODED_PASSWORD@DB_HOST/plit99_db?sslmode=verify-full
SERVE_MEDIA_FILES=True
WAITRESS_PORT=8000
WAITRESS_THREADS=4
WAITRESS_HOST=127.0.0.1
WAITRESS_TRUSTED_PROXY=127.0.0.1
TRUST_PROXY_HEADERS=False
```

Configure a trusted PostgreSQL CA/certificate matching DB_HOST. Generate a random
SECRET_KEY of at least 50 characters. Create the administrator interactively after
migrations; existing passwords are not changed automatically. Give the service account only the required NTFS
rights; Unix permission bits alone do not configure Windows ACLs.

For a local-only test you may keep SQLite:

```text
DATABASE_URL=sqlite:///C:/plit99/data/db.sqlite3
```

For a real public website, PostgreSQL is recommended.

## 7. Build The Project

```powershell
Set-Location C:\plit99\app
C:\plit99\venv\Scripts\Activate.ps1
# Supply MIGRATION_DATABASE_URL through a protected operator environment for
# PostgreSQL DDL as plit99_owner. Do not put the owner password in service .env.
.\build.ps1
if (-not $?) { throw "Build failed; do not start the service." }
Remove-Item Env:MIGRATION_DATABASE_URL -ErrorAction SilentlyContinue
.\manage.ps1 createsuperuser
```

Build defaults to `APP_ENV=production`, installs pinned wheels, checks settings,
collects the production static manifest and applies migrations. Service startup
checks for unapplied migrations and refuses to listen if any remain. It does not
create accounts or apply schema changes. The management wrapper loads the same
`.env` and Python interpreter as the service; plain `python manage.py` does not load `.env`.

## 8. Test Waitress Manually

```powershell
Set-Location C:\plit99\app
C:\plit99\venv\Scripts\Activate.ps1
.\start.ps1
```

For production, verify through the HTTPS IIS endpoint. Direct HTTP requests to
Waitress redirect to HTTPS; Waitress itself does not terminate TLS. For an isolated
local test, use `python manage.py runserver` with `APP_ENV=local` and the local
HTTPS/cookie flags disabled in that test process only:

```text
http://127.0.0.1:8000/
```

If the site opens, continue.

## 9. Run As A Windows Service With NSSM

Download NSSM and place `nssm.exe` somewhere permanent, for example:

```text
C:\nssm\nssm.exe
```

Create the service:

```powershell
C:\nssm\nssm.exe install plit99
```

Use these values in the NSSM window:

```text
Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Startup directory: C:\plit99\app
Arguments: -ExecutionPolicy Bypass -NoProfile -File C:\plit99\app\start.ps1
```

Then start it:

```powershell
C:\nssm\nssm.exe start plit99
```

Useful commands:

```powershell
C:\nssm\nssm.exe restart plit99
C:\nssm\nssm.exe stop plit99
C:\nssm\nssm.exe edit plit99
```

## 10. Configure IIS Reverse Proxy

Enable IIS, then install:

1. URL Rewrite
2. Application Request Routing

In IIS Manager:

1. Open the server node.
2. Open `Application Request Routing Cache`.
3. Open `Server Proxy Settings`.
4. Enable proxy.

Create a site for the domain and point it to any empty folder, for example:

```text
C:\plit99\iis-root
```

Add a reverse proxy rule:

```text
Pattern: (.*)
Rewrite URL: http://127.0.0.1:8000/{R:1}
```

IIS must strip client X-Forwarded-For/X-Forwarded-Proto and supply the actual client
address and HTTPS scheme. Waitress trusts only WAITRESS_TRUSTED_PROXY, never `*`.
Preserve the original validated public Host header when proxying; verify it matches
ALLOWED_HOSTS and that HTTPS admin forms do not loop or fail CSRF validation.
Do not open port 8000 to external clients. Restrict `/admin/` by VPN/IP and add MFA
at the access proxy where possible. Schedule `clear_login_throttles` and
`clearsessions` daily through `.\manage.ps1` with the same service environment.

The Django app serves static files through WhiteNoise and media files through the project when `SERVE_MEDIA_FILES=True`.

## 11. Firewall

Open only public web ports:

```powershell
New-NetFirewallRule -DisplayName "HTTP 80" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "HTTPS 443" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
```

Keep port `8000` private unless you intentionally want direct local-network access.

## 12. HTTPS

For a public domain, add an SSL certificate in IIS:

1. Use your hosting provider certificate, or
2. Use a Windows ACME client such as `win-acme`.

After the certificate is installed, bind it to the IIS site on port `443`.

## 13. Update After Future Changes

Use the stop/backup/update/build/start sequence in [REDEPLOY.md](REDEPLOY.md).
If the build fails, keep the service stopped until the error is resolved or the
previous code and a compatible database are restored.

## 14. What Should Be Stored Where

PostgreSQL:

- news
- gallery entries
- categories
- users
- admin data
- sessions

Filesystem in `C:\plit99\data\media`:

- uploaded images
- media files

## 15. Final Check

Check:

1. Main page opens through the domain.
2. `/admin/` opens.
3. Static CSS and JS load correctly.
4. Uploaded images are visible after refresh.
5. Service restarts after Windows reboot.
6. Database data remains after project updates.
