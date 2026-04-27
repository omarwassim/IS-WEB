# VulnLab – Security Vulnerability Testing Site

A simple local web app for testing common web vulnerabilities. Educational use only.

## Setup

```bash
npm install
node app.js
```

Then open: http://localhost:3000

## Covered Vulnerabilities

| # | Type | Endpoint |
|---|------|----------|
| 1 | XSS – Reflected | GET /vuln/xss-reflected?input= |
| 2 | XSS – Stored | POST/GET /vuln/xss-stored |
| 3 | SQL Injection | POST /vuln/sqli |
| 4 | Command Injection | POST /vuln/cmdi |
| 5 | Path Traversal | GET /vuln/path-traversal?file= |
| 6 | Brute Force / No Rate Limiting | POST /vuln/bruteforce |
| 7 | IDOR | GET /vuln/idor?id= |
| 8 | Open Redirect | GET /vuln/open-redirect?url= |
| 9 | Sensitive Data Exposure | GET /vuln/sensitive-data |
| 10 | CSRF | POST /vuln/csrf |

## ⚠️ Warning

This app is intentionally insecure. Run only on localhost or isolated lab environments. Never expose to the internet.


## TO test the Website 
## make those endpoints on the postman or on the ThunderClient in the web project 
Using Thunder Client / Postman
Here are the key endpoints:

POST endpoints — set Content-Type: application/json

AttackMethodURLBodyDDoS POST/vuln/ddos{"rps":9000,"sourceIp":"192.168.1.105"}

Port Scan POST/vuln/portscan{"sourceIp":"10.0.0.55","ports":100}

DoS Hulk POST/vuln/dos-hulk{"sourceIp":"10.0.0.88","rps":5000}

GoldenEye POST/vuln/dos-goldeneye{"sourceIp":"10.0.0.99"}

Slowloris POST/vuln/dos-slowloris{"sourceIp":"10.0.0.71"}

Slow HTTP POST/vuln/dos-slowhttptest{"sourceIp":"10.0.0.62"}

FTP Brute POST/vuln/ftp-patator{"username":"ftpuser","password":"ftppass"}

SSH Brute POST/vuln/ssh-patator{"username":"root","password":"toor","sourceIp":"10.0.0.44"}

SQL Inject POST/vuln/sqli{"username":"' OR 1=1 --","password":"x"}

Web Brute POST/vuln/web-bruteforce{"username":"admin","password":"secret123"}

XSS Stored POST/vuln/xss-stored{"comment":"<script>alert(1)</script>"}

Heartbleed POST/vuln/heartbleed{"sourceIp":"192.168.1.200"}

Botnet C2 POST/vuln/botnet{"sourceIp":"10.0.0.77"}

Infiltration POST/vuln/infiltration{"sourceIp":"10.0.1.15"}

Zero-Day POST/vuln/zeroday{"payload":"AAAA"}

Benign POST/vuln/normal{}

GET endpoints — append query params to the URL

AttackURLXSS Reflected GET /vuln/xss-reflected?input=<script>alert(1)</script>

IDOR GET /vuln/idor?id=1Path 

Traversal GET /vuln/path-traversal?file=../../../../etc/passwd

View XSS comments GET /vuln/xss-storedMetricsGET /vuln/metrics


Tips for Successful Responses


FTP crack: use ftpuser / ftppass — success: true

SSH crack: use root / toor or admin / secret123

SQLi bypass: username ' OR 1=1 -- leaks all 3 users

Web brute crack: admin / secret123 or alice / pass456

IDOR: try IDs 1, 2, 3 — those are the only valid users



Every response returns a JSON object with label, severity, log, and attack-specific fields. The SSE stream at /vuln/stream also broadcasts every event in real time if you want to 
monitor all activity live.

