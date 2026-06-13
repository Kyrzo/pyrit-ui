# VPS Deployment Guide

Deploy PyRIT UI on a Linux VPS with Apache reverse proxy and Let's Encrypt SSL.

Tested on: **Ubuntu 24.04 LTS** with **Plesk Obsidian**

---

## Prerequisites

- VPS with Ubuntu 20.04+ (min 1GB RAM, 20GB disk)
- Domain pointing to your server IP (DNS A record)
- Root or sudo access

---

## Step 1 — Install dependencies

```bash
apt update
apt install python3 python3-pip python3-venv git apache2 certbot -y
```

---

## Step 2 — Clone and install

```bash
git clone https://github.com/Kyrzo/pyrit-ui /opt/pyrit-ui
cd /opt/pyrit-ui/backend

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# For real PyRIT scans (requires Azure credentials)
pip install "azure-ai-evaluation[redteam]" azure-identity
```

---

## Step 3 — Configure

```bash
cp .env.example .env
nano .env
```

Fill in all required values. Generate secure tokens:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## Step 4 — Create admin user

```bash
source venv/bin/activate
python3 create_user.py create --username admin --password yourpassword --role admin

# Or use the interactive menu
python3 create_user.py
```

---

## Step 5 — Install systemd service

Edit `pyrit-ui.service` to match your paths:

```bash
# Update paths if you used a different directory
nano pyrit-ui.service

# Install
cp pyrit-ui.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable pyrit-ui
systemctl start pyrit-ui

# Verify
systemctl status pyrit-ui
curl http://127.0.0.1:8000/api/health
```

---

## Step 6 — Get SSL certificate

```bash
# Point your domain to the server first (DNS A record)
certbot certonly --webroot -w /var/www/html -d your-domain.com \
  --non-interactive --agree-tos -m your@email.com
```

---

## Step 7 — Configure Apache reverse proxy

Enable required modules:

```bash
a2enmod proxy proxy_http ssl rewrite headers
```

Create virtual host config:

```bash
cat > /etc/apache2/sites-available/pyrit-ui.conf << 'EOF'
<VirtualHost *:80>
    ServerName your-domain.com
    RewriteEngine On
    RewriteRule ^(.*)$ https://your-domain.com$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName your-domain.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/your-domain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/your-domain.com/privkey.pem

    # Serve frontend
    DocumentRoot /opt/pyrit-ui/frontend

    # Proxy API to backend
    ProxyPreserveHost On
    ProxyPass /api/ http://127.0.0.1:8000/api/
    ProxyPassReverse /api/ http://127.0.0.1:8000/api/

    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
</VirtualHost>
EOF

a2ensite pyrit-ui.conf
apache2ctl configtest
systemctl reload apache2
```

---

## Step 8 — Azure CLI authentication

```bash
az login --use-device-code
```

---

## Verify everything works

```bash
# Backend health
curl https://your-domain.com/api/health

# Open in browser
open https://your-domain.com
```

Login with the admin credentials you created in Step 4.

---

## Maintenance

```bash
# View logs
journalctl -u pyrit-ui -f

# Restart backend
systemctl restart pyrit-ui

# Update
cd /opt/pyrit-ui
git pull
systemctl restart pyrit-ui

# Add users
cd /opt/pyrit-ui/backend
source venv/bin/activate
python3 create_user.py
```

---

## Plesk-specific setup

If your VPS uses Plesk, configure the proxy through Plesk's vhost config instead:

```bash
# Edit Plesk's custom vhost SSL config
nano /var/www/vhosts/system/your-domain.com/conf/vhost_ssl.conf

# Add:
ProxyPreserveHost On
ProxyRequests Off
ProxyPass /api/ http://127.0.0.1:8000/api/
ProxyPassReverse /api/ http://127.0.0.1:8000/api/

# Regenerate Plesk config
plesk repair web your-domain.com -y
```
