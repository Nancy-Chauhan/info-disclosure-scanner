# Information Disclosure Scan Report

**Target:** http://localhost:3000
**Scan Date:** 2026-01-19 12:21:24
**Total Findings:** 82

## Summary

| Severity | Count |
|----------|-------|
| 🔴 HIGH | 14 |
| 🟠 MEDIUM | 33 |
| 🟡 LOW | 7 |
| 🔵 INFO | 28 |

## Findings

### 🔴 HIGH Severity

#### Git repository exposed - /.git/config

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/.git/config  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Git HEAD file exposed - /.git/HEAD

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/.git/HEAD  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Environment file exposed - /.env

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/.env  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### PHP config file - /config.php

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/config.php  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### PHP config backup - /config.php.bak

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/config.php.bak  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### YAML config file - /config.yml

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/config.yml  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### JSON config file - /config.json

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/config.json  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### IIS config exposed - /web.config

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/web.config  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Backup directory - /backup

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/backup  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Backup directory - /backup/

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/backup/  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Database dump - /db.sql

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/db.sql  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Database dump - /database.sql

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/database.sql  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Database dump - /dump.sql

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/dump.sql  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Password found in main.js

**Category:** JavaScript Disclosure  
**Description:** Sensitive data in JavaScript file: http://localhost:3000/main.js  

```
[('password', 'password'), ('Password', 'IamUsedForTesting')]
```

---

### 🟠 MEDIUM Severity

#### Debug endpoint - /debug

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/debug  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Debug directory - /debug/

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/debug/  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Admin panel - /admin

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/admin  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Administrator panel - /administrator

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/administrator  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Spring actuator - /actuator

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/actuator  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Spring health endpoint - /actuator/health

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/actuator/health  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Spring environment - /actuator/env

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/actuator/env  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Debug log - /debug.log

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/debug.log  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Products API - /api/Products

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/api/Products  

```
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-01-19T15:32:25.795Z","updatedAt":"2026-01-19T15:32:25.795Z","deletedAt":null},{"id":2,"name":"Orange Juice (1000ml)","description":"Made from oranges hand-picked by Uncle Dittmeyer.","price":2.99,"deluxePrice":2.49,"image":"orange_juice.jpg","createdAt":"2026-01-19T15:32:25.795Z","updatedAt":"2026-01-19T15:32:25.795Z",
```

---

#### Feedbacks API - /api/Feedbacks

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/api/Feedbacks  

```
{"status":"success","data":[{"UserId":1,"id":1,"comment":"I love this shop! Best products in town! Highly recommended! (***in@juice-sh.op)","rating":5,"createdAt":"2026-01-19T15:32:24.918Z","updatedAt":"2026-01-19T15:32:24.918Z"},{"UserId":2,"id":2,"comment":"Great shop! Awesome service! (***@juice-sh.op)","rating":4,"createdAt":"2026-01-19T15:32:24.919Z","updatedAt":"2026-01-19T15:32:24.919Z"},{"UserId":3,"id":3,"comment":"Nothing useful available here! (***der@juice-sh.op)","rating":1,"created
```

---

#### Stack trace exposed via SQL error trigger (quote)

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?id='  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via SQL error trigger (comment)

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?id=1'--  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via SQL error trigger (OR)

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?id=1 OR 1=1  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via Path traversal test

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?file=../../../etc/passwd  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via Path traversal bypass

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?page=....//....//etc/passwd  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via Array parameter

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?id[]=1  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via Null value

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?id=null  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via Undefined value

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?id=undefined  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via Negative ID

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?id=-1  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via Large ID

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?id=99999999  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via Zero ID

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?id=0  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via XSS probe

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?q=<script>  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via SSTI probe

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?q={{7*7}}  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via Expression injection

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/?q=${7*7}  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via 404 error page

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/nonexistent12345  

```
['error', 'error', 'error']
```

---

#### Stack trace exposed via API 404 error

**Category:** Error Disclosure  
**Description:** Verbose error found at: http://localhost:3000/api/nonexistent12345  

```
['Error', 'Error']
```

---

#### Developer comment found in vendor.js

**Category:** JavaScript Disclosure  
**Description:** Sensitive data in JavaScript file: http://localhost:3000/vendor.js  

```
['todo', 'ToDo']
```

---

#### Debug logging found in vendor.js

**Category:** JavaScript Disclosure  
**Description:** Sensitive data in JavaScript file: http://localhost:3000/vendor.js  

```
['log', 'log']
```

---

#### Secret/Token found in main.js

**Category:** JavaScript Disclosure  
**Description:** Sensitive data in JavaScript file: http://localhost:3000/main.js  

```
[('token', '+e)}saveLastLoginIp(){return this.http.get(this.hostServer+'), ('token', ')?{consumed:n}:null},data:{params:window.location.href.substr(window.location.href.indexOf(')]
```

---

#### Developer comment found in main.js

**Category:** JavaScript Disclosure  
**Description:** Sensitive data in JavaScript file: http://localhost:3000/main.js  

```
['Hack', 'Hack']
```

---

#### Debug logging found in main.js

**Category:** JavaScript Disclosure  
**Description:** Sensitive data in JavaScript file: http://localhost:3000/main.js  

```
['log', 'log']
```

---

#### [AI] Technology Stack Disclosure

**Category:** AI Analysis  
**Description:** Application identifies itself as OWASP Juice Shop, an intentionally insecure web application used for security testing  

```
<title>OWASP Juice Shop</title> and <meta name="description" content="Probably the most modern and sophisticated insecure web application">
```

---

#### [AI] Internal path disclosure

**Category:** AI Analysis  
**Description:** robots.txt reveals the existence of an internal /ftp directory that may contain sensitive files or provide unauthorized access to file transfer functionality  

```
Disallow: /ftp
```

---

### 🟡 LOW Severity

#### Robots.txt file - /robots.txt

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/robots.txt  

```
User-agent: *
Disallow: /ftp
```

---

#### Sitemap file - /sitemap.xml

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/sitemap.xml  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### NPM package file - /package.json

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/package.json  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### [AI] Copyright Information Disclosure

**Category:** AI Analysis  
**Description:** HTML comments reveal project timeline and contributor information  

```
<!-- ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors. ~ SPDX-License-Identifier: MIT -->
```

---

#### [AI] Technology Stack Disclosure

**Category:** AI Analysis  
**Description:** Frontend technology stack revealed through CSS framework identification  

```
Angular Material CSS variables (--mat-*) and Roboto font references indicate Angular Material framework usage
```

---

#### [AI] External Dependencies Disclosure

**Category:** AI Analysis  
**Description:** External CDN dependencies and their versions are exposed  

```
//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/ and //cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
```

---

#### [AI] Asset Path Disclosure

**Category:** AI Analysis  
**Description:** Internal asset structure and file paths are revealed  

```
href="assets/public/favicon_js.ico"
```

---

### 🔵 INFO Severity

#### Missing X-XSS-Protection header

**Category:** Missing Security Header  
**Description:** The X-XSS-Protection header is not set  

---

#### Missing Strict-Transport-Security header

**Category:** Missing Security Header  
**Description:** The Strict-Transport-Security header is not set  

---

#### Missing Content-Security-Policy header

**Category:** Missing Security Header  
**Description:** The Content-Security-Policy header is not set  

---

#### SVN repository exposed - /.svn/entries

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/.svn/entries  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Mercurial repository exposed - /.hg/hgrc

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/.hg/hgrc  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Django settings exposed - /settings.py

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/settings.py  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Apache htaccess exposed - /.htaccess

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/.htaccess  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Nginx config exposed - /nginx.conf

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/nginx.conf  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Flash crossdomain policy - /crossdomain.xml

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/crossdomain.xml  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Silverlight policy - /clientaccesspolicy.xml

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/clientaccesspolicy.xml  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Security.txt file - /security.txt

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/security.txt  

```
Contact: mailto:donotreply@owasp-juice.shop
Encryption: https://keybase.io/bkimminich/pgp_keys.asc?fingerprint=19c01cb7157e4645e9e2c863062a85a8cbfbdcda
Acknowledgements: /#/score-board
Preferred-languages: en, ar, az, bg, bn, ca, cs, da, de, ga, el, es, et, fi, fr, ka, he, hi, hu, id, it, ja, ko, lv, my, nl, no, pl, pt, ro, ru, si, sv, th, tr, uk, zh
Hiring: /#/jobs
Csaf: http://localhost:3000/.well-known/csaf/provider-metadata.json
Expires: Tue, 19 Jan 2027 15:32:24 GMT
```

---

#### Security.txt (well-known) - /.well-known/security.txt

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/.well-known/security.txt  

```
Contact: mailto:donotreply@owasp-juice.shop
Encryption: https://keybase.io/bkimminich/pgp_keys.asc?fingerprint=19c01cb7157e4645e9e2c863062a85a8cbfbdcda
Acknowledgements: /#/score-board
Preferred-languages: en, ar, az, bg, bn, ca, cs, da, de, ga, el, es, et, fi, fr, ka, he, hi, hu, id, it, ja, ko, lv, my, nl, no, pl, pt, ro, ru, si, sv, th, tr, uk, zh
Hiring: /#/jobs
Csaf: http://localhost:3000/.well-known/csaf/provider-metadata.json
Expires: Tue, 19 Jan 2027 15:32:24 GMT
```

---

#### PHP info page - /phpinfo.php

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/phpinfo.php  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### PHP info page - /info.php

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/info.php  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Console access - /console

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/console  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Swagger JSON - /swagger.json

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/swagger.json  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### macOS metadata - /.DS_Store

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/.DS_Store  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Windows thumbnails - /Thumbs.db

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/Thumbs.db  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Logs directory - /logs

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/logs  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Log directory - /log

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/log  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Error log - /error.log

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/error.log  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Access log - /access.log

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/access.log  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### NPM lock file - /package-lock.json

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/package-lock.json  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Composer file - /composer.json

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/composer.json  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Ruby Gemfile - /Gemfile

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/Gemfile  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### Python requirements - /requirements.txt

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/requirements.txt  

```
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <meta name="description" content="Probably the most modern and sophisticated insecure web application">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/f
```

---

#### FTP directory (Juice Shop) - /ftp

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/ftp  

```
<!DOCTYPE html>
<html>
  <head>
    <meta charset='utf-8'> 
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
    <title>listing directory /ftp</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}

body {
  padding: 80px 100px;
  font: 13px "Helvetica Neue", "Lucida Grande", "Arial";
  background: #ECE9E9 -webkit-gradient(linear, 0% 0%, 0% 100%, from(#fff), to(#ECE9E9));
  background: #ECE9E9 -moz-linear-gradient(top, #
```

---

#### Encryption keys (Juice Shop) - /encryptionkeys

**Category:** Sensitive Path  
**Description:** Found accessible path: http://localhost:3000/encryptionkeys  

```
<!DOCTYPE html>
<html>
  <head>
    <meta charset='utf-8'> 
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
    <title>listing directory /encryptionkeys</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}

body {
  padding: 80px 100px;
  font: 13px "Helvetica Neue", "Lucida Grande", "Arial";
  background: #ECE9E9 -webkit-gradient(linear, 0% 0%, 0% 100%, from(#fff), to(#ECE9E9));
  background: #ECE9E9 -moz-linear-grad
```

---

