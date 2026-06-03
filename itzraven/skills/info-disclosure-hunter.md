---
name: info-disclosure-hunter
description: Information disclosure discovery — admin panels, default credentials, .git/.env leaks, debug endpoints, exposed configs
category: recon
---

# Information Disclosure Hunter

> Uncover leaked data, exposed configs, debug endpoints, and admin panels.

## PHASE 1 — Exposed Files

### Git Exposure
```bash
# Check for .git directory exposure
curl -sL "https://target.com/.git/config" | grep -q "\[core\]" && echo "GIT LEAK!"
# Tools: git-dumper, GitTools
git-dumper https://target.com/.git/ leaked_git/
```

### Environment Files
```bash
# Common env file paths
/.env /env /.env.production /.env.development /.env.local /config.env
curl -sL "https://target.com/.env" | grep -q "API_KEY\|PASSWORD\|SECRET"
```

### Other Exposed Files
```
/.htaccess
/robots.txt
/sitemap.xml
/crossdomain.xml
/clientaccesspolicy.xml
/trace.axd (ASP.NET)
/Elmah.axd (ASP.NET)
/phpinfo.php
/info.php
/server-status
/server-info
/.DS_Store
/backup.sql
/dump.sql
```

## PHASE 2 — Admin Panel Discovery
```bash
# Common admin paths
/admin /administrator /adminpanel /dashboard /cpanel /portal /login
/backend /secure /adm /manage /controlpanel /admin/login

# Technology-specific
/wordpress/wp-admin
/joomla/administrator
/drupal/admin
/magento/admin
/phpmyadmin
```

## PHASE 3 — Default Credentials Testing
| Software | Username | Password |
|----------|----------|----------|
| Tomcat | admin | admin |
| Tomcat | tomcat | tomcat |
| Jenkins | admin | admin |
| PHPMyAdmin | root | (empty) |
| Wordpress | admin | admin |
| Joomla | admin | admin |
| Drupal | admin | admin |
| Kibana | elastic | changeme |

## PHASE 4 — Debug Endpoints
```bash
# Debug / diagnostic endpoints
/actuator (Spring Boot)
/actuator/health
/actuator/env
/actuator/beans
/swagger-ui.html
/api-docs
/graphql?query={__schema{types{name}}}
/console (H2 DB console)
/debug
/.well-known/
```

## PHASE 5 — Source Maps & JS Endpoints
```bash
# Source map extraction
curl -sL "https://target.com/static/js/main.js.map" | grep -oP '"[^"]+"'

# Common source map paths
/static/js/*.map
/build/static/js/*.map
/dist/js/*.map
```

## PHASE 6 — Cloud Metadata
```bash
# AWS
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/user-data/

# GCP
curl http://metadata.google.internal/computeMetadata/v1/ -H "Metadata-Flavor: Google"

# Azure
curl http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H "Metadata: true"
```
