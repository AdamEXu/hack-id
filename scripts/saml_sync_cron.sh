#!/bin/bash
set -euo pipefail

cat > /etc/cron.d/hackid-saml-sync <<'CRON'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 3 * * * root cd /app && python scripts/saml_metadata_sync.py >> /var/log/saml-sync.log 2>&1
CRON

chmod 0644 /etc/cron.d/hackid-saml-sync
crontab /etc/cron.d/hackid-saml-sync

touch /var/log/saml-sync.log

cron

tail -F /var/log/saml-sync.log
