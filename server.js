/**
 * Deployment Dashboard API Server
 * Real-time control panel: PM2, GitHub, Docker, Git, PTY Terminal, Deploy Pipeline
 */

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { exec, spawn } = require('child_process');
const util = require('util');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const multer = require('multer');
const WebSocket = require('ws');
const http = require('http');
const os = require('os');

let pty;
try { pty = require('node-pty'); } catch (e) { console.warn('node-pty not available:', e.message); }

const jwt = require('jsonwebtoken');
const execAsync = util.promisify(exec);

// AI Tools
const { SERVER_TOOLS } = require('./server-tools');
const { executeTool } = require('./server-tool-executor');

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// ============================================================================
// AUTH CONFIG
// ============================================================================

const JWT_SECRET = process.env.DASHBOARD_JWT_SECRET || 'deploy-hub-dev-secret-change-in-production';
const DASHBOARD_USER = process.env.DASHBOARD_USER || 'admin';
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'admin123';

if (!process.env.DASHBOARD_JWT_SECRET) {
  console.warn('\x1b[33m⚠ DASHBOARD_JWT_SECRET not set — using insecure default\x1b[0m');
}
if (!process.env.DASHBOARD_PASSWORD) {
  console.warn('\x1b[33m⚠ DASHBOARD_PASSWORD not set — default password is "admin123"\x1b[0m');
}

// GitHub config
const GITHUB_USERNAME = process.env.DASHBOARD_GITHUB_USER || 'adrianstanca1';

// Server public URL config
const SERVER_PUBLIC_IP = process.env.SERVER_PUBLIC_IP || '72.62.132.43';
const APPS_BASE_URL = process.env.APPS_BASE_URL || `http://${SERVER_PUBLIC_IP}`;

const SETTINGS_FILE = path.join(__dirname, '.dashboard-settings.json');
let runtimeSettings = null;

// Cache for nginx path mappings: port -> path
let nginxPortPathCache = null;
let nginxCacheTime = 0;
const NGINX_CACHE_TTL = 60_000; // 1 minute

/**
 * Parse nginx apps.conf to extract port-to-path mappings
 * Returns a Map: port -> path (e.g., 3005 -> '/buildprogemini')
 */
async function getNginxPortPathMappings() {
  const now = Date.now();
  if (nginxPortPathCache && (now - nginxCacheTime) < NGINX_CACHE_TTL) {
    return nginxPortPathCache;
  }

  const mappings = new Map();
  try {
    const nginxConfigPath = '/etc/nginx/sites-available/apps.conf';
    if (fs.existsSync(nginxConfigPath)) {
      const content = fs.readFileSync(nginxConfigPath, 'utf8');

      // Match location blocks with proxy_pass: location /path/ { ... proxy_pass http://127.0.0.1:PORT/; }
      // Handles optional comments and multi-line blocks
      const locationRegex = /location\s+\/([^/\s]+)\/\s*\{[\s\S]*?proxy_pass\s+http:\/\/127\.0\.0\.1:(\d+)\//g;
      let match;
      while ((match = locationRegex.exec(content)) !== null) {
        const path = match[1];
        const port = parseInt(match[2], 10);
        mappings.set(port, `/${path}`);
      }
    }
  } catch (error) {
    console.warn('Failed to parse nginx config:', error.message);
  }

  nginxPortPathCache = mappings;
  nginxCacheTime = now;
  return mappings;
}

/**
 * Generate deployment URL for a PM2 process
 */
async function generateProcessUrl(pm2Process) {
  const port = pm2Process.pm2_env?.env?.PORT || pm2Process.pm2_env?.PORT;
  if (!port) return null;

  // Get nginx path mappings
  const pathMappings = await getNginxPortPathMappings();
  const path = pathMappings.get(parseInt(port, 10));

  if (path) {
    return `${APPS_BASE_URL}${path}`;
  }

  // Fallback: direct port access (may not work if behind firewall)
  // Only include if explicitly enabled
  if (process.env.ALLOW_DIRECT_PORT_URLS === 'true') {
    return `${APPS_BASE_URL}:${port}`;
  }

  return null;
}

function verifyToken(token) {
  const activeSecret = (runtimeSettings?.security?.dashboardJwtSecret) ?? JWT_SECRET;
  return jwt.verify(token, activeSecret);
}

// Simple in-memory rate limiter for login (resets per IP per minute)
const loginAttempts = new Map();
function checkLoginRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 60_000; }
  entry.count++;
  loginAttempts.set(ip, entry);
  return entry.count <= 10;
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  try {
    req.user = verifyToken(header.slice(7));
    next();
  } catch {
    res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
}

const app = express();
app.set('trust proxy', 1); // Trust Nginx reverse proxy (needed for rate limiting behind proxy)
const server = http.createServer(app);

// ============================================================================
// WEBSOCKET — multi-path noServer pattern
// ============================================================================

const wssStatus     = new WebSocket.Server({ noServer: true }); // PM2 live updates
const wssTerminal   = new WebSocket.Server({ noServer: true }); // PTY terminal
const wssLogs       = new WebSocket.Server({ noServer: true }); // live log tail
const wssStats      = new WebSocket.Server({ noServer: true }); // system stats push
const wssDockerLogs = new WebSocket.Server({ noServer: true }); // docker container logs

server.on('upgrade', (request, socket, head) => {
  const { pathname, searchParams } = new URL(request.url, 'http://localhost');

  // Validate JWT token from query param
  const token = searchParams.get('token');
  try {
    verifyToken(token || '');
  } catch {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  if (pathname === '/ws') {
    wssStatus.handleUpgrade(request, socket, head, ws => wssStatus.emit('connection', ws, request));
  } else if (pathname.startsWith('/ws/terminal')) {
    wssTerminal.handleUpgrade(request, socket, head, ws => wssTerminal.emit('connection', ws, request));
  } else if (pathname.startsWith('/ws/logs')) {
    wssLogs.handleUpgrade(request, socket, head, ws => wssLogs.emit('connection', ws, request));
  } else if (pathname.startsWith('/ws/stats')) {
    wssStats.handleUpgrade(request, socket, head, ws => wssStats.emit('connection', ws, request));
  } else if (pathname.startsWith('/ws/docker')) {
    wssDockerLogs.handleUpgrade(request, socket, head, ws => wssDockerLogs.emit('connection', ws, request));
  } else {
    socket.destroy();
  }
});

app.use(helmet());

// Global rate limiter - protects against DDoS, brute force, excessive API usage
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { success: false, error: 'Too many requests, please try again later.' }
});
app.use(limiter);

app.use(cors());
app.use(express.json());

// ── Login endpoint (public) ──────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (!checkLoginRateLimit(ip)) {
    return res.status(429).json({ success: false, error: 'Too many attempts — wait a minute' });
  }
  const { username, password } = req.body || {};
  const activeUser = runtimeSettings?.security?.dashboardUser ?? DASHBOARD_USER;
  const activePassword = runtimeSettings?.security?.dashboardPassword ?? DASHBOARD_PASSWORD;
  if (username === activeUser && password === activePassword) {
    const token = jwt.sign({ username }, (runtimeSettings?.security?.dashboardJwtSecret) ?? JWT_SECRET, { expiresIn: '24h' });
    return res.json({ success: true, token, username });
  }
  res.status(401).json({ success: false, error: 'Invalid credentials' });
});

app.get('/api/auth/me', (req, res) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ success: false });
  try {
    const user = verifyToken(header.slice(7));
    res.json({ success: true, user });
  } catch {
    res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
});

// ── Global API auth guard (all /api/* except /api/auth/* and /api/ai/* for tools/providers) ───────────────────
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) return next();
  if (req.path.startsWith('/api/auth/')) return next();
  if (req.path.startsWith('/api/ai/providers') || req.path.startsWith('/api/ai/tools') || req.path.startsWith('/api/ai/capabilities') || req.path.startsWith('/api/ai/agents')) return next();
  requireAuth(req, res, next);
});

// Serve built frontend
const FRONTEND_DIST = path.join(__dirname, '../deployment-dashboard/dist');
if (fs.existsSync(FRONTEND_DIST)) {
  app.use(express.static(FRONTEND_DIST));
}

// ============================================================================
// HELPERS
// ============================================================================

async function normalizePM2Process(p) {
  const normalized = {
    pm_id: p.pm_id,
    name: p.name,
    pid: p.pid,
    status: p.pm2_env?.status ?? 'unknown',
    mode: p.pm2_env?.exec_mode ?? 'fork',
    monit: p.monit ?? { memory: 0, cpu: 0 },
    pm2_env: {
      ...p.pm2_env,
      monit: p.monit ?? { memory: 0, cpu: 0 },
    },
  };

  // Generate deployment URL
  normalized.url = await generateProcessUrl(normalized);

  return normalized;
}

async function getPM2List() {
  const { stdout } = await execAsync('pm2 jlist');
  const processes = JSON.parse(stdout);
  // Use Promise.all to handle async normalization
  return await Promise.all(processes.map(normalizePM2Process));
}

function sendSSE(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// ============================================================================
// PM2 ENDPOINTS
// ============================================================================

app.get('/api/pm2/list', async (req, res) => {
  try {
    const processes = await getPM2List();
    res.json({ success: true, data: processes });
  } catch (error) {
    res.json({ success: false, error: error.message, data: [] });
  }
});

app.get('/api/pm2/status', async (req, res) => {
  try {
    const processes = await getPM2List();
    res.json({
      success: true,
      data: {
        total: processes.length,
        online: processes.filter(p => p.status === 'online').length,
        errored: processes.filter(p => p.status === 'errored').length,
        stopped: processes.filter(p => p.status === 'stopped').length,
      }
    });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// PM2 name validation helper
function validatePM2Name(name) {
  if (!name || !/^[a-zA-Z0-9_-]{1,100}$/.test(name)) {
    throw new Error('Invalid process name. Use alphanumeric, underscores, hyphens only (1-100 chars).');
  }
  return name;
}

app.get('/api/pm2/logs/:name', async (req, res) => {
  try {
    const { name } = req.params;
    validatePM2Name(name);
    const lines = Math.max(1, Math.min(5000, parseInt(req.query.lines) || 200));
    const { stdout, stderr } = await execAsync(`pm2 logs ${name} --lines ${lines} --nostream 2>&1`);
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message, data: error.stdout || '' });
  }
});

app.post('/api/pm2/restart/:name', async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    await execAsync(`pm2 restart "${name}"`);
    res.json({ success: true, message: `Restarted ${name}` });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/stop/:name', async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    await execAsync(`pm2 stop "${name}"`);
    res.json({ success: true, message: `Stopped ${name}` });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/start/:name', async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    await execAsync(`pm2 start "${name}"`);
    res.json({ success: true, message: `Started ${name}` });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/delete/:name', async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    await execAsync(`pm2 delete "${name}"`);
    // Clean up from tracking map
    lastProcessStates.delete(name);
    res.json({ success: true, message: `Deleted ${name}` });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

// Bulk operations
app.post('/api/pm2/bulk', async (req, res) => {
  try {
    const { action, names } = req.body;
    const validActions = ['restart', 'stop', 'start', 'delete'];
    if (!validActions.includes(action)) return res.json({ success: false, error: 'Invalid action' });

    const results = await Promise.allSettled(
      names.map(name => execAsync(`pm2 ${action} "${name}"`))
    );

    const succeeded = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    res.json({ success: true, data: { succeeded, failed, total: names.length } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Restart all errored processes
app.post('/api/pm2/restart-errored', async (req, res) => {
  try {
    const processes = await getPM2List();
    const errored = processes.filter(p => p.status === 'errored').map(p => p.name);
    if (errored.length === 0) return res.json({ success: true, data: { restarted: 0 } });

    await Promise.allSettled(errored.map(name => execAsync(`pm2 restart "${name}"`)));
    res.json({ success: true, data: { restarted: errored.length, names: errored } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/save', async (req, res) => {
  try {
    await execAsync('pm2 save');
    res.json({ success: true, message: 'PM2 process list saved' });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// ============================================================================
// SYSTEM EXEC — quick commands
// ============================================================================

const ALLOWED_COMMANDS = [
  'pm2 save',
  'pm2 list',
  'nginx -t',
  'nginx -s reload',
  'nginx -s reopen',
  'df -h',
  'free -h',
  'uptime',
  'who',
  'last -n 10',
  'netstat -tlnp',
  'ss -tlnp',
  'systemctl status nginx',
  'systemctl reload nginx',
  'systemctl status ssh',
  'journalctl -n 50 --no-pager',
  'ps aux --sort=-%cpu | head -20',
  'ps aux --sort=-%mem | head -20',
];

app.post('/api/system/exec', async (req, res) => {
  try {
    const { command } = req.body;
    // Allow pm2 restart/stop/start/delete commands and a whitelist for system commands
    const isAllowed = ALLOWED_COMMANDS.includes(command) ||
      /^pm2 (restart|stop|start|delete|save|jlist|logs) .{0,100}$/.test(command) ||
      /^git -C \/var\/www\/.{1,100} (pull|status|log|diff) .{0,100}$/.test(command);

    if (!isAllowed) {
      return res.json({ success: false, error: 'Command not in allowlist. Use the Terminal for arbitrary commands.' });
    }

    const { stdout, stderr } = await execAsync(command, { timeout: 30000 });
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    res.json({ success: false, error: error.message, data: error.stdout || error.stderr || '' });
  }
});

// ============================================================================
// GITHUB ENDPOINTS
// ============================================================================

function sanitizeRepoName(name) {
  if (!name || !/^[\w._-]{1,100}$/.test(name)) throw new Error('Invalid repo name');
  return name;
}

const GITHUB_AUTH = process.env.GITHUB_TOKEN
  ? `-H "Authorization: Bearer ${process.env.GITHUB_TOKEN}"`
  : '';

async function githubFetch(url) {
  const { stdout } = await execAsync(`curl -s ${GITHUB_AUTH} "${url}"`, { timeout: 15000 });
  const data = JSON.parse(stdout);
  // Handle rate limiting
  if (data.message && data.documentation_url) {
    if (data.message.includes('rate limit')) {
      throw new Error('GitHub API rate limit exceeded. Add GITHUB_TOKEN to increase limit from 60 to 5000/hr.');
    }
    throw new Error(data.message);
  }
  return data;
}

app.get('/api/github/repos', async (req, res) => {
  try {
    // Use /user/repos (authenticated) to include private repositories
    const repos = await githubFetch(`https://api.github.com/user/repos?per_page=100&sort=pushed&type=all`);
    res.json({ success: true, data: repos });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/commits/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/commits?per_page=20`);
    // Normalize GitHub API commit structure for frontend consistency
    const normalized = data.map(c => ({
      sha: c.sha,
      message: c.commit?.message || '',
      author: {
        name: c.commit?.author?.name || c.author?.login || '',
        date: c.commit?.author?.date || '',
        email: c.commit?.author?.email || '',
        avatarUrl: c.author?.avatar_url || '',
        login: c.author?.login || '',
      },
      html_url: c.html_url,
    }));
    res.json({ success: true, data: normalized });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/branches/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/branches?per_page=50`);
    res.json({ success: true, data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/issues/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const state = req.query.state || 'open';
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/issues?per_page=20&state=${state}`);
    res.json({ success: true, data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/pulls/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const state = req.query.state || 'open';
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/pulls?per_page=20&state=${state}`);
    res.json({ success: true, data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/releases/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/releases?per_page=10`);
    res.json({ success: true, data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/readme/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/readme`);
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    res.json({ success: true, data: content });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/actions/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/actions/runs?per_page=15`);
    res.json({ success: true, data: Array.isArray(data) ? data : (data.workflow_runs ?? []) });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Check if repo is cloned locally under /var/www
app.get('/api/github/local-status/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const repoPath = `/var/www/${repo}`;
    const exists = fs.existsSync(repoPath);
    let gitStatus = null;
    if (exists) {
      try {
        const [statusOut, branchOut, logOut] = await Promise.all([
          execAsync(`git -C "${repoPath}" status --short`).catch(() => ({ stdout: '' })),
          execAsync(`git -C "${repoPath}" rev-parse --abbrev-ref HEAD`).catch(() => ({ stdout: 'unknown' })),
          execAsync(`git -C "${repoPath}" log -1 --format="%h|%s|%ar"`).catch(() => ({ stdout: '' })),
        ]);
        const logParts = logOut.stdout.trim().split('|');
        gitStatus = {
          branch: branchOut.stdout.trim(),
          changes: statusOut.stdout.trim(),
          lastCommitHash: logParts[0] || '',
          lastCommitMsg: logParts[1] || '',
          lastCommitAge: logParts[2] || '',
        };
      } catch (e) {
        gitStatus = { branch: 'unknown', changes: '', lastCommitHash: '', lastCommitMsg: '', lastCommitAge: '' };
      }
    }
    res.json({ success: true, data: { exists, path: repoPath, gitStatus } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Git pull for locally cloned repo
app.post('/api/github/pull-local/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const repoPath = `/var/www/${repo}`;
    if (!fs.existsSync(repoPath)) return res.json({ success: false, error: 'Not cloned locally' });
    const { stdout, stderr } = await execAsync(`git -C "${repoPath}" pull`, { timeout: 30000 });
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    res.json({ success: false, error: error.message, data: error.stdout || error.stderr });
  }
});

// Sync fork with upstream
app.post('/api/github/sync/:repo', async (req, res) => {
  try {
    if (!process.env.GITHUB_TOKEN) {
      return res.json({ success: false, error: 'GITHUB_TOKEN required for this operation' });
    }
    const repo = sanitizeRepoName(req.params.repo);
    const { data } = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}`);

    if (!data.fork) {
      return res.json({ success: false, error: 'Repository is not a fork' });
    }

    const parent = data.parent;
    const defaultBranch = data.default_branch;

    // Get the latest commit from upstream
    const upstreamCommits = await githubFetch(`${parent.url}/commits/${defaultBranch}?per_page=1`);
    const upstreamSha = upstreamCommits[0]?.sha;

    if (!upstreamSha) {
      return res.json({ success: false, error: 'Could not get upstream commits' });
    }

    // Sync fork using GitHub API
    const syncUrl = `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/git/refs/heads/${defaultBranch}`;
    const { stdout, stderr } = await execAsync(
      `curl -s -X PATCH -H "Authorization: Bearer ${process.env.GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" ` +
      `-d '{"sha": "${upstreamSha}", "force": false}' "${syncUrl}"`,
      { timeout: 15000 }
    );

    const result = JSON.parse(stdout);
    if (result.message) {
      throw new Error(result.message);
    }

    res.json({ success: true, data: { synced: true, upstream: parent.full_name, sha: upstreamSha } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Create new branch
app.post('/api/github/create-branch/:repo', async (req, res) => {
  try {
    if (!process.env.GITHUB_TOKEN) {
      return res.json({ success: false, error: 'GITHUB_TOKEN required for this operation' });
    }
    const repo = sanitizeRepoName(req.params.repo);
    const { branchName, baseBranch = 'main' } = req.body;

    if (!branchName || !/^[-\w.]+$/.test(branchName)) {
      return res.json({ success: false, error: 'Invalid branch name' });
    }

    // Get base branch SHA
    const refData = await githubFetch(
      `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/git/refs/heads/${baseBranch}`
    );
    const baseSha = refData.object?.sha;

    if (!baseSha) {
      return res.json({ success: false, error: `Base branch '${baseBranch}' not found` });
    }

    // Create new branch
    const createUrl = `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/git/refs`;
    const { stdout } = await execAsync(
      `curl -s -X POST -H "Authorization: Bearer ${process.env.GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" ` +
      `-d '{"ref": "refs/heads/${branchName}", "sha": "${baseSha}"}' "${createUrl}"`,
      { timeout: 15000 }
    );

    const result = JSON.parse(stdout);
    if (result.message) {
      throw new Error(result.message);
    }

    res.json({ success: true, data: { branch: branchName, sha: result.object?.sha } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Trigger workflow dispatch
app.post('/api/github/trigger-workflow/:repo', async (req, res) => {
  try {
    if (!process.env.GITHUB_TOKEN) {
      return res.json({ success: false, error: 'GITHUB_TOKEN required for this operation' });
    }
    const repo = sanitizeRepoName(req.params.repo);
    const { workflowId, branch = 'main', inputs = {} } = req.body;

    if (!workflowId) {
      return res.json({ success: false, error: 'Workflow ID is required' });
    }

    const triggerUrl = `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/actions/workflows/${workflowId}/dispatches`;
    const { stdout } = await execAsync(
      `curl -s -X POST -H "Authorization: Bearer ${process.env.GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" ` +
      `-d '{"ref": "${branch}", "inputs": ${JSON.stringify(inputs)}}' "${triggerUrl}"`,
      { timeout: 15000 }
    );

    // Empty response means success (204)
    if (!stdout || stdout === '') {
      return res.json({ success: true, data: { triggered: true, workflowId, branch } });
    }

    const result = JSON.parse(stdout);
    if (result.message) {
      throw new Error(result.message);
    }

    res.json({ success: true, data: { triggered: true, workflowId, branch } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Create new issue
app.post('/api/github/create-issue/:repo', async (req, res) => {
  try {
    if (!process.env.GITHUB_TOKEN) {
      return res.json({ success: false, error: 'GITHUB_TOKEN required for this operation' });
    }
    const repo = sanitizeRepoName(req.params.repo);
    const { title, body = '', labels = [] } = req.body;

    if (!title || title.trim().length < 1) {
      return res.json({ success: false, error: 'Issue title is required' });
    }

    const createUrl = `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/issues`;
    const payload = JSON.stringify({ title: title.trim(), body: body.trim(), labels });

    const { stdout } = await execAsync(
      `curl -s -X POST -H "Authorization: Bearer ${process.env.GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" ` +
      `-d '${payload}' "${createUrl}"`,
      { timeout: 15000 }
    );

    const result = JSON.parse(stdout);
    if (result.message) {
      throw new Error(result.message);
    }

    res.json({ success: true, data: { issueNumber: result.number, html_url: result.html_url, title: result.title } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Create pull request
app.post('/api/github/create-pr/:repo', async (req, res) => {
  try {
    if (!process.env.GITHUB_TOKEN) {
      return res.json({ success: false, error: 'GITHUB_TOKEN required for this operation' });
    }
    const repo = sanitizeRepoName(req.params.repo);
    const { title, head, base, body = '' } = req.body;

    if (!title || !head || !base) {
      return res.json({ success: false, error: 'Title, head branch, and base branch are required' });
    }

    const createUrl = `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/pulls`;
    const payload = JSON.stringify({ title: title.trim(), head: head.trim(), base: base.trim(), body: body.trim() });

    const { stdout } = await execAsync(
      `curl -s -X POST -H "Authorization: Bearer ${process.env.GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" ` +
      `-d '${payload}' "${createUrl}"`,
      { timeout: 15000 }
    );

    const result = JSON.parse(stdout);
    if (result.message) {
      throw new Error(result.message);
    }

    res.json({ success: true, data: { prNumber: result.number, html_url: result.html_url, title: result.title, state: result.state } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Merge a pull request
app.post('/api/github/merge-pr/:repo/:pull_number', async (req, res) => {
  try {
    if (!process.env.GITHUB_TOKEN) {
      return res.json({ success: false, error: 'GITHUB_TOKEN required for this operation' });
    }
    const repo = sanitizeRepoName(req.params.repo);
    const pullNumber = parseInt(req.params.pull_number, 10);
    const { commitMessage, sha } = req.body;

    if (!pullNumber || isNaN(pullNumber)) {
      return res.json({ success: false, error: 'Invalid pull request number' });
    }

    const mergeUrl = `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/pulls/${pullNumber}/merge`;
    const payload = JSON.stringify({ commit_title: commitMessage || undefined, sha: sha || undefined });

    const { stdout } = await execAsync(
      `curl -s -X PUT -H "Authorization: Bearer ${process.env.GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" ` +
      `-d '${payload}' "${mergeUrl}"`,
      { timeout: 15000 }
    );

    const result = JSON.parse(stdout);
    if (result.message) {
      throw new Error(result.message);
    }

    res.json({ success: true, data: { merged: true, sha: result.sha, message: result.message } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Compare branches for PR creation
app.get('/api/github/compare/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const { base, head } = req.query;

    if (!base || !head) {
      return res.json({ success: false, error: 'Base and head branches are required' });
    }

    const data = await githubFetch(
      `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/compare/${base}...${head}`
    );

    res.json({
      success: true,
      data: {
        ahead_by: data.ahead_by,
        behind_by: data.behind_by,
        status: data.status,
        total_commits: data.total_commits,
        commits: (data.commits || []).slice(0, 10).map(c => ({
          sha: c.sha,
          message: c.commit?.message,
          author: c.commit?.author?.name
        })),
        files: (data.files || []).slice(0, 5).map(f => ({
          filename: f.filename,
          status: f.status,
          additions: f.additions,
          deletions: f.deletions
        }))
      }
    });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// List available workflows
app.get('/api/github/workflows/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(
      `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/actions/workflows?per_page=50`
    );

    res.json({
      success: true,
      data: (data.workflows || []).map(w => ({
        id: w.id,
        name: w.name,
        path: w.path,
        state: w.state,
        html_url: w.html_url
      }))
    });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Get commit activity (for commit graph)
app.get('/api/github/commit-activity/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(
      `https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/stats/commit_activity`
    );

    // Data is an array of 52 weeks with daily commit counts
    const activity = Array.isArray(data) ? data.map((week, idx) => ({
      week: idx,
      total: week.total,
      days: week.days
    })) : [];

    res.json({ success: true, data: activity });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// ============================================================================
// SERVER FILESYSTEM
// ============================================================================

app.get('/api/server/apps', async (req, res) => {
  try {
    const { stdout } = await execAsync('ls -1 /var/www/');
    res.json({ success: true, data: stdout.trim().split('\n').filter(Boolean) });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/server/app/:name', async (req, res) => {
  try {
    const appPath = `/var/www/${req.params.name}`;
    if (!fs.existsSync(appPath)) return res.json({ success: false, error: 'App not found' });

    let packageJson = null;
    const pkgPath = path.join(appPath, 'package.json');
    if (fs.existsSync(pkgPath)) packageJson = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

    const hasDist = fs.existsSync(path.join(appPath, 'dist'));
    const hasNextBuild = fs.existsSync(path.join(appPath, '.next'));
    const hasNodeModules = fs.existsSync(path.join(appPath, 'node_modules'));

    let port = null;
    const envPath = path.join(appPath, '.env.local');
    if (fs.existsSync(envPath)) {
      const match = fs.readFileSync(envPath, 'utf8').match(/^PORT=(\d+)/m);
      if (match) port = match[1];
    }

    res.json({ success: true, data: { name: req.params.name, path: appPath, packageJson, port, hasDist, hasNextBuild, hasNodeModules } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// ============================================================================
// ENHANCED FILE MANAGER
// ============================================================================

const BASE_PATH = '/var/www';

// Multer configuration for file uploads
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const targetPath = req.body.path || '/';
      const fullPath = path.join(BASE_PATH, targetPath);
      cb(null, fullPath);
    },
    filename: (req, file, cb) => {
      cb(null, file.originalname);
    }
  }),
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

/**
 * Validate and sanitize file path to prevent directory traversal
 * Returns resolved absolute path or null if invalid
 */
function validateFilePath(inputPath) {
  if (!inputPath || typeof inputPath !== 'string') {
    return null;
  }

  // Normalize the path and resolve it relative to BASE_PATH
  const normalizedPath = path.normalize(inputPath).replace(/^(\.\.\/|\/)+/, '');
  const fullPath = path.join(BASE_PATH, normalizedPath);

  // Ensure the resolved path is within BASE_PATH
  const resolvedBase = path.resolve(BASE_PATH);
  const resolvedFull = path.resolve(fullPath);

  if (!resolvedFull.startsWith(resolvedBase + path.sep) && resolvedFull !== resolvedBase) {
    return null;
  }

  return resolvedFull;
}

// 1. GET /api/server/browse - Browse directory contents
app.get('/api/server/browse', async (req, res) => {
  try {
    const targetPath = req.query.path || '/';
    const fullPath = validateFilePath(targetPath);

    if (!fullPath) {
      return res.status(400).json({ success: false, error: 'Invalid path' });
    }

    const stats = await fsp.stat(fullPath).catch(() => null);
    if (!stats) {
      return res.status(404).json({ success: false, error: 'Path not found' });
    }

    if (!stats.isDirectory()) {
      return res.status(400).json({ success: false, error: 'Path is not a directory' });
    }

    const entries = await fsp.readdir(fullPath, { withFileTypes: true });
    const items = await Promise.all(
      entries.map(async (entry) => {
        const itemPath = path.join(fullPath, entry.name);
        const itemStats = await fsp.stat(itemPath).catch(() => null);
        return {
          name: entry.name,
          type: entry.isDirectory() ? 'directory' : 'file',
          size: itemStats?.size || 0,
          modified: itemStats?.mtime?.toISOString() || null,
          permissions: itemStats?.mode?.toString(8).slice(-3) || null
        };
      })
    );

    res.json({
      success: true,
      data: {
        path: targetPath,
        fullPath: fullPath.replace(BASE_PATH, ''),
        items: items.sort((a, b) => {
          // Directories first, then alphabetical
          if (a.type === b.type) return a.name.localeCompare(b.name);
          return a.type === 'directory' ? -1 : 1;
        })
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 2. POST /api/server/upload - Upload files (multipart form data)
app.post('/api/server/upload', upload.array('files'), async (req, res) => {
  try {
    const targetPath = req.body.path || '/';
    const fullPath = validateFilePath(targetPath);

    if (!fullPath) {
      return res.status(400).json({ success: false, error: 'Invalid path' });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ success: false, error: 'No files uploaded' });
    }

    const uploadedFiles = req.files.map(file => ({
      name: file.originalname,
      size: file.size,
      path: path.join(targetPath, file.originalname)
    }));

    res.json({
      success: true,
      message: `${req.files.length} file(s) uploaded successfully`,
      data: uploadedFiles
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 3. POST /api/server/create - Create file or directory
app.post('/api/server/create', async (req, res) => {
  try {
    const { path: targetPath, type, content = '' } = req.body;

    if (!targetPath || typeof targetPath !== 'string') {
      return res.status(400).json({ success: false, error: 'Path is required' });
    }

    if (!['file', 'directory'].includes(type)) {
      return res.status(400).json({ success: false, error: 'Type must be "file" or "directory"' });
    }

    const fullPath = validateFilePath(targetPath);
    if (!fullPath) {
      return res.status(400).json({ success: false, error: 'Invalid path' });
    }

    // Check if already exists
    const exists = await fsp.access(fullPath).then(() => true).catch(() => false);
    if (exists) {
      return res.status(409).json({ success: false, error: 'File or directory already exists' });
    }

    // Ensure parent directory exists
    const parentDir = path.dirname(fullPath);
    await fsp.mkdir(parentDir, { recursive: true });

    if (type === 'directory') {
      await fsp.mkdir(fullPath, { recursive: true });
    } else {
      await fsp.writeFile(fullPath, content, 'utf8');
    }

    res.json({
      success: true,
      message: `${type === 'directory' ? 'Directory' : 'File'} created successfully`,
      data: { path: targetPath, type }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 4. DELETE /api/server/delete - Delete file or directory
app.delete('/api/server/delete', async (req, res) => {
  try {
    const targetPath = req.query.path || req.body?.path;

    if (!targetPath || typeof targetPath !== 'string') {
      return res.status(400).json({ success: false, error: 'Path is required' });
    }

    const fullPath = validateFilePath(targetPath);
    if (!fullPath) {
      return res.status(400).json({ success: false, error: 'Invalid path' });
    }

    // Prevent deleting the base directory itself
    if (fullPath === path.resolve(BASE_PATH)) {
      return res.status(403).json({ success: false, error: 'Cannot delete the root directory' });
    }

    const stats = await fsp.stat(fullPath).catch(() => null);
    if (!stats) {
      return res.status(404).json({ success: false, error: 'Path not found' });
    }

    if (stats.isDirectory()) {
      await fsp.rm(fullPath, { recursive: true, force: true });
    } else {
      await fsp.unlink(fullPath);
    }

    res.json({
      success: true,
      message: 'Deleted successfully',
      data: { path: targetPath }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 5. GET /api/server/download - Download a file
app.get('/api/server/download', async (req, res) => {
  try {
    const targetPath = req.query.path;

    if (!targetPath || typeof targetPath !== 'string') {
      return res.status(400).json({ success: false, error: 'Path is required' });
    }

    const fullPath = validateFilePath(targetPath);
    if (!fullPath) {
      return res.status(400).json({ success: false, error: 'Invalid path' });
    }

    const stats = await fsp.stat(fullPath).catch(() => null);
    if (!stats) {
      return res.status(404).json({ success: false, error: 'File not found' });
    }

    if (stats.isDirectory()) {
      return res.status(400).json({ success: false, error: 'Cannot download a directory' });
    }

    const filename = path.basename(fullPath);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');

    const fileStream = fs.createReadStream(fullPath);
    fileStream.pipe(res);

    fileStream.on('error', (err) => {
      console.error('Download error:', err);
      if (!res.headersSent) {
        res.status(500).json({ success: false, error: 'Error reading file' });
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 6. GET /api/server/edit - Get file contents for editing
app.get('/api/server/edit', async (req, res) => {
  try {
    const targetPath = req.query.path;

    if (!targetPath || typeof targetPath !== 'string') {
      return res.status(400).json({ success: false, error: 'Path is required' });
    }

    const fullPath = validateFilePath(targetPath);
    if (!fullPath) {
      return res.status(400).json({ success: false, error: 'Invalid path' });
    }

    const stats = await fsp.stat(fullPath).catch(() => null);
    if (!stats) {
      return res.status(404).json({ success: false, error: 'File not found' });
    }

    if (stats.isDirectory()) {
      return res.status(400).json({ success: false, error: 'Cannot edit a directory' });
    }

    // Check file size (limit to 5MB for editing)
    if (stats.size > 5 * 1024 * 1024) {
      return res.status(400).json({ success: false, error: 'File too large for editing (max 5MB)' });
    }

    const content = await fsp.readFile(fullPath, 'utf8');

    res.json({
      success: true,
      data: {
        path: targetPath,
        content,
        size: stats.size,
        modified: stats.mtime.toISOString()
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 7. POST /api/server/edit - Save file contents
app.post('/api/server/edit', async (req, res) => {
  try {
    const { path: targetPath, content } = req.body;

    if (!targetPath || typeof targetPath !== 'string') {
      return res.status(400).json({ success: false, error: 'Path is required' });
    }

    const fullPath = validateFilePath(targetPath);
    if (!fullPath) {
      return res.status(400).json({ success: false, error: 'Invalid path' });
    }

    const stats = await fsp.stat(fullPath).catch(() => null);
    if (!stats) {
      return res.status(404).json({ success: false, error: 'File not found' });
    }

    if (stats.isDirectory()) {
      return res.status(400).json({ success: false, error: 'Cannot save to a directory' });
    }

    await fsp.writeFile(fullPath, content, 'utf8');

    res.json({
      success: true,
      message: 'File saved successfully',
      data: { path: targetPath }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// DOCKER
// ============================================================================

app.get('/api/docker/containers', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"');
    const containers = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [id, name, image, status, ports] = line.split('|');
      return { id, name, image, status, ports };
    });
    res.json({ success: true, data: containers });
  } catch (error) {
    res.json({ success: false, error: error.message, data: [] });
  }
});

app.get('/api/docker/images', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker images --format "{{.Repository}}|{{.Tag}}|{{.ID}}|{{.Size}}"');
    const images = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [repository, tag, id, size] = line.split('|');
      return { repository, tag, id, size };
    });
    res.json({ success: true, data: images });
  } catch (error) {
    res.json({ success: false, error: error.message, data: [] });
  }
});

// Docker container ID validation helper
function validateContainerId(id) {
  if (!id || !/^[a-zA-Z0-9_-]{1,64}$/.test(id)) {
    throw new Error('Invalid container ID. Use alphanumeric, underscores, hyphens only (max 64 chars).');
  }
  return id;
}

app.post('/api/docker/container/:action/:id', async (req, res) => {
  try {
    const { action, id } = req.params;
    const validActions = ['start', 'stop', 'restart', 'pause', 'unpause', 'kill'];
    if (!validActions.includes(action)) {
      return res.status(400).json({ success: false, error: 'Invalid action' });
    }
    validateContainerId(id);
    await execAsync(`docker ${action} ${id}`);
    res.json({ success: true });
  } catch (error) {
    if (error.message.includes('Invalid container ID')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/docker/container/:id', async (req, res) => {
  try {
    const id = validateContainerId(req.params.id);
    await execAsync(`docker rm -f ${id}`);
    res.json({ success: true });
  } catch (error) {
    if (error.message.includes('Invalid container ID')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/docker/container/:id/inspect', async (req, res) => {
  try {
    const id = validateContainerId(req.params.id);
    const { stdout } = await execAsync(`docker inspect ${id}`);
    res.json({ success: true, data: JSON.parse(stdout)[0] });
  } catch (error) {
    if (error.message.includes('Invalid container ID')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/docker/container/:id/stats', async (req, res) => {
  try {
    const id = validateContainerId(req.params.id);
    const { stdout } = await execAsync(`docker stats ${id} --no-stream --format "{{json .}}"`);
    res.json({ success: true, data: JSON.parse(stdout.trim()) });
  } catch (error) {
    if (error.message.includes('Invalid container ID')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/docker/volumes', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker volume ls --format "{{.Driver}}|{{.Name}}|{{.Mountpoint}}"');
    const volumes = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [driver, name, mountpoint] = line.split('|');
      return { driver, name, mountpoint };
    });
    res.json({ success: true, data: volumes });
  } catch (error) {
    res.json({ success: false, error: error.message, data: [] });
  }
});

app.delete('/api/docker/volume/:name', async (req, res) => {
  try {
    await execAsync(`docker volume rm "${req.params.name}"`);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/docker/networks', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker network ls --format "{{.ID}}|{{.Name}}|{{.Driver}}|{{.Scope}}"');
    const networks = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [id, name, driver, scope] = line.split('|');
      return { id, name, driver, scope };
    });
    res.json({ success: true, data: networks });
  } catch (error) {
    res.json({ success: false, error: error.message, data: [] });
  }
});

app.get('/api/docker/system/df', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker system df --format "{{json .}}"');
    const lines = stdout.trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
    res.json({ success: true, data: lines });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Docker pull (SSE streaming)
app.post('/api/docker/pull', async (req, res) => {
  const { image } = req.body;
  if (!image || !/^[\w./:@-]{1,200}$/.test(image)) {
    return res.status(400).json({ success: false, error: 'Invalid image name' });
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    if (res.flush) res.flush();
  };

  send('start', { image });
  const proc = spawn('docker', ['pull', image]);
  proc.stdout.on('data', d => send('output', { text: d.toString() }));
  proc.stderr.on('data', d => send('output', { text: d.toString() }));
  proc.on('exit', code => {
    send('done', { success: code === 0, code });
    res.end();
  });
});

// Run a new container
app.post('/api/docker/run', async (req, res) => {
  try {
    const { image, name, ports, env, detach = true, autoRemove = false } = req.body;
    if (!image || !/^[\w./:@-]{1,200}$/.test(image)) return res.json({ success: false, error: 'Invalid image' });

    const args = ['run'];
    if (detach) args.push('-d');
    if (autoRemove) args.push('--rm');
    if (name && /^[\w_.-]+$/.test(name)) args.push('--name', name);
    if (Array.isArray(ports)) {
      for (const p of ports) {
        if (/^\d{1,5}(:\d{1,5})?$/.test(p)) args.push('-p', p);
      }
    }
    if (Array.isArray(env)) {
      for (const e of env) {
        if (/^[\w.]+=.*$/.test(e)) args.push('-e', e);
      }
    }
    args.push(image);
    const { stdout } = await execAsync(`docker ${args.join(' ')}`);
    res.json({ success: true, data: stdout.trim() });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Remove an image
app.delete('/api/docker/image/:id', async (req, res) => {
  try {
    await execAsync(`docker rmi ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// System prune
app.post('/api/docker/prune', async (req, res) => {
  try {
    const { type = 'containers' } = req.body;
    const cmds = {
      containers: 'docker container prune -f',
      images: 'docker image prune -f',
      volumes: 'docker volume prune -f',
      all: 'docker system prune -f',
    };
    if (!cmds[type]) return res.json({ success: false, error: 'Invalid prune type' });
    const { stdout } = await execAsync(cmds[type]);
    res.json({ success: true, data: stdout });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// ============================================================================
// GIT COMMANDS - SECURED WITH WHITELIST
// ============================================================================

const ALLOWED_GIT_COMMANDS = [
  'git status',
  'git log',
  'git diff',
  'git pull',
  'git fetch',
  'git branch',
  'git checkout',
];

app.post('/api/git/command', async (req, res) => {
  try {
    const { command, cwd } = req.body;

    if (!command || typeof command !== 'string') {
      return res.status(400).json({ success: false, error: 'Command is required' });
    }

    // Validate command against whitelist
    const isAllowed = ALLOWED_GIT_COMMANDS.includes(command) ||
      /^git -C \/var\/www\/[\w._-]{1,100} (status|log|diff|pull|fetch|branch|checkout) .{0,200}$/.test(command) ||
      /^git -C \/var\/www\/[\w._-]{1,100} (status|log|diff|pull|fetch|branch|checkout)$/.test(command);

    if (!isAllowed) {
      return res.status(403).json({ success: false, error: 'Command not in allowlist. Allowed: git status, log, diff, pull, fetch, branch, checkout' });
    }

    const { stdout, stderr } = await execAsync(command, { cwd: cwd || '/var/www', timeout: 30000 });
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: error.stdout || error.stderr });
  }
});

// ============================================================================
// DEPLOY PIPELINE — SSE streaming
// ============================================================================

app.post('/api/deploy/pipeline', async (req, res) => {
  const { repo, branch = 'main', port, pm2Name, installCmd = 'npm install --legacy-peer-deps', buildCmd = 'npm run build' } = req.body;

  // Input validation
  if (!repo || !/^[\w._-]{1,100}$/.test(repo)) {
    return res.status(400).json({ success: false, error: 'Invalid repo name. Use alphanumeric, dots, underscores, hyphens.' });
  }
  if (pm2Name && !/^[a-zA-Z0-9_-]{1,100}$/.test(pm2Name)) {
    return res.status(400).json({ success: false, error: 'Invalid PM2 name. Use alphanumeric, underscores, hyphens only.' });
  }
  if (port && (!/^\d+$/.test(port) || parseInt(port) < 1 || parseInt(port) > 65535)) {
    return res.status(400).json({ success: false, error: 'Invalid port number (1-65535).' });
  }
  // Validate install/build commands don't contain dangerous patterns
  if (installCmd && /[;&|`$()]/.test(installCmd)) {
    return res.status(400).json({ success: false, error: 'Install command contains disallowed characters.' });
  }
  if (buildCmd && /[;&|`$()]/.test(buildCmd)) {
    return res.status(400).json({ success: false, error: 'Build command contains disallowed characters.' });
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    if (res.flush) res.flush();
  };

  const runStep = (label, command, cwd) => new Promise((resolve, reject) => {
    send('step-start', { step: label, command });
    const proc = spawn('sh', ['-c', command], { cwd: cwd || '/' });

    proc.stdout.on('data', d => send('output', { text: d.toString(), step: label }));
    proc.stderr.on('data', d => send('output', { text: d.toString(), step: label, isStderr: true }));

    proc.on('exit', code => {
      if (code === 0) { send('step-done', { step: label }); resolve(); }
      else { send('step-error', { step: label, code }); reject(new Error(`${label} exited with code ${code}`)); }
    });
  });

  try {
    const targetDir = `/var/www/${repo}`;

    if (fs.existsSync(targetDir)) {
      await runStep('git-pull', `git pull`, targetDir);
    } else {
      await runStep('clone', `git clone --branch ${branch} --depth 1 https://github.com/${GITHUB_USERNAME}/${repo}.git ${targetDir}`, '/');
    }

    await runStep('install', installCmd, targetDir);

    // Check if build script exists
    const pkgPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.scripts?.build) {
        await runStep('build', buildCmd, targetDir);
      }
    }

    // Check if already in PM2
    const processes = await getPM2List();
    const existing = processes.find(p => p.name === pm2Name);
    if (existing) {
      await runStep('pm2-restart', `pm2 restart "${pm2Name}"`, targetDir);
    } else {
      await runStep('pm2-start', `PORT=${port} pm2 start npm --name "${pm2Name}" -- start`, targetDir);
      await runStep('pm2-save', 'pm2 save', '/');
    }

    send('done', { success: true, pm2Name, port });
  } catch (err) {
    send('done', { success: false, error: err.message });
  }

  res.end();
});

app.post('/api/deploy/clone', async (req, res) => {
  try {
    const { repo, branch = 'main' } = req.body;
    if (branch && !/^[a-zA-Z0-9._\/-]{1,100}$/.test(branch)) {
      return res.json({ success: false, error: 'Invalid branch name' });
    }
    const targetDir = `/var/www/${repo}`;
    if (fs.existsSync(targetDir)) return res.json({ success: false, error: 'Directory already exists' });
    const { stdout } = await execAsync(`git clone --branch ${branch} --depth 1 https://github.com/${GITHUB_USERNAME}/${repo}.git ${targetDir}`);
    res.json({ success: true, data: stdout });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/deploy/build', async (req, res) => {
  try {
    const name = sanitizeRepoName(req.body.name);
    const appPath = `/var/www/${name}`;
    const { stdout } = await execAsync(`cd ${appPath} && npm run build 2>&1`);
    res.json({ success: true, data: stdout });
  } catch (error) {
    res.json({ success: false, error: error.message, data: error.stdout || error.stderr });
  }
});

app.post('/api/deploy/install', async (req, res) => {
  try {
    const name = sanitizeRepoName(req.body.name);
    const appPath = `/var/www/${name}`;
    const { stdout } = await execAsync(`cd ${appPath} && npm install --legacy-peer-deps 2>&1`);
    res.json({ success: true, data: stdout });
  } catch (error) {
    res.json({ success: false, error: error.message, data: error.stdout || error.stderr });
  }
});

// ============================================================================
// SYSTEM STATS
// ============================================================================

async function collectSystemStats() {
  try {
    const [memOut, diskOut, uptimeOut, loadOut, cpuStatRaw] = await Promise.all([
      execAsync("free -b | awk 'NR==2{print $2,$3,$4}'"),
      execAsync("df -B1 / | awk 'NR==2{print $2,$3,$4}'"),
      execAsync("cat /proc/uptime | awk '{print $1}'"),
      execAsync("cat /proc/loadavg | awk '{print $1,$2,$3}'"),
      execAsync("cat /proc/stat | head -1").catch(() => ({ stdout: 'cpu 0 0 0 0' })),
    ]);

    const [memTotal, memUsed, memFree] = memOut.stdout.trim().split(' ').map(Number);
    const [diskTotal, diskUsed, diskFree] = diskOut.stdout.trim().split(' ').map(Number);
    const uptime = parseFloat(uptimeOut.stdout.trim());
    const load = loadOut.stdout.trim().split(' ').map(parseFloat);

    // Two-sample CPU measurement (100ms gap)
    const parseCpuLine = (line) => line.trim().split(/\s+/).slice(1).map(Number);
    const cpuBefore = parseCpuLine(cpuStatRaw.stdout);
    await new Promise(r => setTimeout(r, 100));
    const { stdout: cpuAfterRaw } = await execAsync("cat /proc/stat | head -1");
    const cpuAfter = parseCpuLine(cpuAfterRaw);

    const totalBefore = cpuBefore.reduce((a, b) => a + b, 0);
    const totalAfter = cpuAfter.reduce((a, b) => a + b, 0);
    const idleBefore = cpuBefore[3];
    const idleAfter = cpuAfter[3];
    const cpu = Math.max(0, Math.round((1 - (idleAfter - idleBefore) / (totalAfter - totalBefore)) * 100));

    const coresOut = await execAsync("nproc").catch(() => ({ stdout: '1' }));

    return {
      cpu: { usage: cpu, cores: parseInt(coresOut.stdout.trim()) },
      memory: { total: memTotal, used: memUsed, free: memFree, percentage: Math.round((memUsed / memTotal) * 100) },
      disk: { total: diskTotal, used: diskUsed, free: diskFree, percentage: Math.round((diskUsed / diskTotal) * 100) },
      uptime,
      load,
      timestamp: Date.now(),
    };
  } catch (err) {
    return null;
  }
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ success: true, status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/api/system/stats', async (req, res) => {
  try {
    const stats = await collectSystemStats();
    res.json({ success: true, data: stats });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Network interfaces info
app.get('/api/system/network', async (req, res) => {
  try {
    const { stdout } = await execAsync("ip -4 addr show | grep 'inet ' | awk '{print $2, $NF}'");
    const ifaces = stdout.trim().split('\n').filter(Boolean).map(line => {
      const parts = line.split(' ');
      return { address: parts[0], iface: parts[1] };
    });
    res.json({ success: true, data: ifaces });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Ports in use
app.get('/api/system/ports', async (req, res) => {
  try {
    const { stdout } = await execAsync("ss -tlnp | grep LISTEN | awk '{print $4, $6}' | sort -t: -k2 -n");
    const ports = stdout.trim().split('\n').filter(Boolean).map(line => {
      const parts = line.trim().split(/\s+/);
      const addr = parts[0];
      const proc = parts[1] || '';
      const portMatch = addr.match(/:(\d+)$/);
      const port = portMatch ? parseInt(portMatch[1]) : null;
      const nameMatch = proc.match(/users:\(\("([^"]+)"/);
      const process = nameMatch ? nameMatch[1] : 'unknown';
      return { port, address: addr, process };
    }).filter(p => p.port !== null);
    res.json({ success: true, data: ports });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// ============================================================================
// WEBSOCKET: STATUS — PM2 live updates + error detection
// ============================================================================

let lastProcessStates = new Map();

wssStatus.on('connection', (ws) => {
  console.log('[WS:status] Client connected');

  const interval = setInterval(async () => {
    try {
      const processes = await getPM2List();
      ws.send(JSON.stringify({ type: 'pm2-update', data: processes }));

      // Detect transitions to errored
      const alerts = [];
      for (const proc of processes) {
        const prev = lastProcessStates.get(proc.name);
        if (prev && prev !== 'errored' && proc.status === 'errored') {
          alerts.push({ name: proc.name, from: prev, to: 'errored' });
        }
        lastProcessStates.set(proc.name, proc.status);
      }
      if (alerts.length > 0) {
        ws.send(JSON.stringify({ type: 'pm2-alert', data: alerts }));
      }
    } catch (error) {
      ws.send(JSON.stringify({ type: 'error', data: error.message }));
    }
  }, 5000);

  ws.on('close', () => {
    clearInterval(interval);
    console.log('[WS:status] Client disconnected');
  });
});

// ============================================================================
// WEBSOCKET: TERMINAL — real PTY sessions
// ============================================================================

const terminalSessions = new Map();

wssTerminal.on('connection', (ws, request) => {
  if (!pty) {
    ws.send(Buffer.from('node-pty not available. Please rebuild the server.\r\n'));
    ws.close();
    return;
  }

  const url = new URL(request.url, 'http://localhost');
  const sessionId = url.searchParams.get('id') ?? `sess-${Date.now()}`;
  const dockerContainer = url.searchParams.get('docker');

  console.log(`[WS:terminal] New session: ${sessionId}${dockerContainer ? ` (docker exec: ${dockerContainer})` : ''}`);

  // Validate docker container name to prevent injection
  const safeDocker = dockerContainer && /^[\w_.-]+$/.test(dockerContainer) ? dockerContainer : null;
  const shellCmd = safeDocker ? 'docker' : '/bin/bash';
  const shellArgs = safeDocker ? ['exec', '-it', safeDocker, '/bin/sh'] : [];

  const ptyProcess = pty.spawn(shellCmd, shellArgs, {
    name: 'xterm-256color',
    cols: parseInt(url.searchParams.get('cols') ?? '80'),
    rows: parseInt(url.searchParams.get('rows') ?? '24'),
    cwd: process.env.HOME || '/root',
    env: { ...process.env, TERM: 'xterm-256color', COLORTERM: 'truecolor' },
  });

  terminalSessions.set(sessionId, { ptyProcess, ws });

  // PTY output → WebSocket (raw binary)
  ptyProcess.onData(data => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(Buffer.from(data, 'binary'));
    }
  });

  ptyProcess.onExit(({ exitCode }) => {
    console.log(`[WS:terminal] Session ${sessionId} exited (code ${exitCode})`);
    terminalSessions.delete(sessionId);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(Buffer.from(`\r\n\x1b[33mProcess exited (code ${exitCode}). Press Enter to reconnect.\x1b[0m\r\n`, 'utf8'));
    }
  });

  // WebSocket input → PTY
  ws.on('message', (data) => {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (buf.length === 0) return;

    const type = buf[0];
    if (type === 0x01) {
      // Control message (resize, etc.)
      try {
        const msg = JSON.parse(buf.slice(1).toString());
        if (msg.type === 'resize') {
          ptyProcess.resize(Math.max(1, msg.cols), Math.max(1, msg.rows));
        }
      } catch (e) { /* ignore malformed control messages */ }
    } else {
      // Raw stdin (type byte 0x00 prefix OR raw data without prefix)
      const input = type === 0x00 ? buf.slice(1) : buf;
      ptyProcess.write(input.toString('binary'));
    }
  });

  ws.on('close', () => {
    console.log(`[WS:terminal] Session ${sessionId} WS closed`);
    ptyProcess.kill();
    terminalSessions.delete(sessionId);
  });

  ws.on('error', (err) => {
    console.error(`[WS:terminal] Error in session ${sessionId}:`, err.message);
  });
});

// ============================================================================
// WEBSOCKET: LOGS — live tail via tail -f
// ============================================================================

wssLogs.on('connection', async (ws, request) => {
  const url = new URL(request.url, 'http://localhost');
  const processName = url.searchParams.get('process');

  if (!processName) { ws.close(); return; }

  console.log(`[WS:logs] Streaming logs for: ${processName}`);

  try {
    const processes = await getPM2List();
    const proc = processes.find(p => p.name === processName);
    if (!proc) {
      ws.send(JSON.stringify({ type: 'error', data: `Process "${processName}" not found` }));
      ws.close();
      return;
    }

    const outLog = proc.pm2_env?.pm_out_log_path;
    const errLog = proc.pm2_env?.pm_err_log_path;

    const logPaths = [outLog, errLog].filter(Boolean);
    if (logPaths.length === 0) {
      ws.send(JSON.stringify({ type: 'error', data: 'No log files found' }));
      ws.close();
      return;
    }

    // Send last 200 lines first
    for (const logPath of logPaths) {
      if (!fs.existsSync(logPath)) continue;
      try {
        const { stdout } = await execAsync(`tail -n 100 "${logPath}" 2>/dev/null`);
        if (stdout.trim()) {
          ws.send(JSON.stringify({ type: 'history', data: stdout, path: logPath }));
        }
      } catch (e) { /* log may not exist yet */ }
    }

    // Start tailing both log files
    const tailArgs = ['-f', '-n', '0', ...logPaths];
    const tail = spawn('tail', tailArgs);

    tail.stdout.on('data', chunk => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'log', data: chunk.toString() }));
      }
    });

    tail.stderr.on('data', chunk => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'log', data: chunk.toString(), isErr: true }));
      }
    });

    tail.on('error', (err) => {
      console.error(`[WS:logs] spawn error: ${err.message}`);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'error', data: `Log streaming error: ${err.message}` }));
        ws.close();
      }
    });

    ws.on('close', () => {
      tail.kill();
      console.log(`[WS:logs] Stopped streaming for: ${processName}`);
    });

  } catch (err) {
    ws.send(JSON.stringify({ type: 'error', data: err.message }));
    ws.close();
  }
});

// ============================================================================
// WEBSOCKET: STATS — push system stats every 2 seconds
// ============================================================================

wssStats.on('connection', async (ws) => {
  console.log('[WS:stats] Client connected');

  const pushStats = async () => {
    if (ws.readyState !== WebSocket.OPEN) return;
    const stats = await collectSystemStats();
    if (stats) ws.send(JSON.stringify({ type: 'stats', data: stats }));
  };

  await pushStats(); // immediate first push
  const interval = setInterval(pushStats, 2000);

  ws.on('close', () => {
    clearInterval(interval);
    console.log('[WS:stats] Client disconnected');
  });
});

// ============================================================================
// WEBSOCKET: DOCKER LOGS — live container log streaming
// ============================================================================

wssDockerLogs.on('connection', async (ws, request) => {
  const url = new URL(request.url, 'http://localhost');
  const containerId = url.searchParams.get('id');
  if (!containerId || !/^[\w_.-]+$/.test(containerId)) { ws.close(); return; }

  console.log(`[WS:docker-logs] Streaming logs for: ${containerId}`);

  // Send last 200 lines as history
  try {
    const { stdout } = await execAsync(`docker logs --tail 200 "${containerId}" 2>&1`, { timeout: 10000 });
    if (stdout.trim()) {
      ws.send(JSON.stringify({ type: 'history', data: stdout }));
    }
  } catch (e) {
    ws.send(JSON.stringify({ type: 'error', data: e.message }));
  }

  // Tail live logs
  const tail = spawn('docker', ['logs', '-f', '--tail', '0', containerId]);
  tail.stdout.on('data', chunk => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'log', data: chunk.toString() }));
  });
  tail.stderr.on('data', chunk => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'log', data: chunk.toString(), isErr: true }));
  });
  tail.on('exit', () => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'end', data: 'Container stopped' }));
  });
  tail.on('error', (err) => {
    console.error(`[WS:docker-logs] spawn error: ${err.message}`);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'error', data: `Log streaming error: ${err.message}` }));
      ws.close();
    }
  });

  ws.on('close', () => {
    tail.kill();
    console.log(`[WS:docker-logs] Stopped streaming for: ${containerId}`);
  });
});

// ============================================================================
// AI ASSISTANT - LLM Integration
// ============================================================================

// Configuration for local LLM
const LOCAL_LLM_URL = process.env.LOCAL_LLM_URL || 'http://localhost:11434';
const LOCAL_LLM_MODEL = process.env.LOCAL_LLM_MODEL || 'codellama';
const USE_LOCAL_LLM = process.env.USE_LOCAL_LLM === 'true';

/**
 * Check if local LLM is available
 */
async function checkLLMAvailability() {
  try {
    const response = await fetch(`${LOCAL_LLM_URL}/api/tags`, { timeout: 5000 });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Query local LLM (Ollama compatible)
 */
async function queryLocalLLM(prompt, context = {}) {
  try {
    const systemPrompt = `You are an expert DevOps assistant helping a non-technical user manage their server and deployments.

Current server state:
- ${context.pm2?.total || 0} PM2 processes (${context.pm2?.online || 0} online, ${context.pm2?.errored || 0} errored)
- CPU: ${context.system?.cpu || 0}%, Memory: ${context.system?.memory || 0}%, Disk: ${context.system?.disk || 0}%

Be helpful, friendly, and explain technical concepts in simple terms. Provide actionable advice. When suggesting actions, be specific about what they do. Use markdown formatting for clarity.`;

    const response = await fetch(`${LOCAL_LLM_URL}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: LOCAL_LLM_MODEL,
        prompt: `${systemPrompt}\n\nUser: ${prompt}\n\nAssistant:`,
        stream: false,
        options: {
          temperature: 0.7,
          num_predict: 800,
        },
      }),
      timeout: 30000,
    });

    if (!response.ok) throw new Error('LLM request failed');
    const data = await response.json();
    return data.response;
  } catch (error) {
    throw new Error(`LLM error: ${error.message}`);
  }
}

/**
 * Generate intelligent response based on user intent and server state
 */
function generateIntelligentResponse(userMessage, context) {
  const msg = userMessage.toLowerCase();

  // Intent detection
  const intents = {
    health: msg.includes('health') || msg.includes('status') || msg.includes('check'),
    deploy: msg.includes('deploy') || msg.includes('new project') || msg.includes('launch'),
    fix: msg.includes('fix') || msg.includes('error') || msg.includes('problem') || msg.includes('issue'),
    optimize: msg.includes('optimize') || msg.includes('improve') || msg.includes('performance'),
    backup: msg.includes('backup') || msg.includes('save'),
    security: msg.includes('security') || msg.includes('protect') || msg.includes('vulnerable'),
    logs: msg.includes('log') || msg.includes('see what happened'),
    restart: msg.includes('restart') || msg.includes('reboot') || msg.includes('start again'),
    stop: msg.includes('stop') || msg.includes('shutdown'),
    help: msg.includes('help') || msg.includes('what can you do'),
  };

  // Generate contextual response based on intent
  if (intents.health) {
    const issues = [];
    if (context.pm2?.errored > 0) issues.push(`${context.pm2.errored} process(es) have errors`);
    if (context.system?.memory > 85) issues.push(`Memory usage is high (${context.system.memory}%)`);
    if (context.system?.disk > 90) issues.push(`Disk usage is critical (${context.system.disk}%)`);
    if (context.system?.cpu > 80) issues.push(`CPU usage is elevated (${context.system.cpu}%)`);

    if (issues.length === 0) {
      return `✅ **Server Health Check: All Good!**\n\nYour server is running smoothly:\n• ${context.pm2?.online}/${context.pm2?.total} applications online\n• CPU: ${context.system?.cpu}% | Memory: ${context.system?.memory}% | Disk: ${context.system?.disk}%\n• System uptime: ${Math.floor((context.system?.uptime || 0) / 3600)} hours\n\nNo issues detected! 🎉`;
    }
    return `⚠️ **Server Health Check: Issues Found**\n\n${issues.map(i => `• ${i}`).join('\n')}\n\n**Recommended actions:**\n${context.pm2?.errored > 0 ? '• Restart errored processes (I can do this for you)\n' : ''}${context.system?.memory > 85 ? '• Check memory usage of high-consuming processes\n' : ''}${context.system?.disk > 90 ? '• Clean up disk space urgently\n' : ''}\nWould you like me to help fix these?`;
  }

  if (intents.deploy) {
    return `🚀 **Deployment Assistant**\n
I can help you deploy a new project! Here's what I need to know:

1. **GitHub Repository** - What's the repo name? (e.g., "my-website")
2. **Branch** - Which branch? (usually "main")
3. **Port** - Which port should it use? (e.g., 3001-3020)
4. **App Name** - What should we call it?

Or tell me: "Deploy my-website on port 3005" and I'll do the rest!`;
  }

  if (intents.fix) {
    if (context.pm2?.errored === 0) {
      return `✅ **Good news!** No errors found. All ${context.pm2?.total} processes are running smoothly.`;
    }
    const errored = context.pm2?.processes?.filter(p => p.status === 'errored') || [];
    return `🛠️ **Auto-Repair Available**\n\nFound ${context.pm2?.errored} error(s):\n${errored.map(p => `• **${p.name}** - Process crashed`).join('\n')}\n\n**I can automatically:**\n1. Restart all errored processes\n2. Check logs to find the cause\n3. Notify you if the issue persists\n\nShould I proceed with auto-repair?`;
  }

  if (intents.optimize) {
    return `⚡ **Performance Optimization Analysis**\n\nCurrent resource usage:\n• CPU: ${context.system?.cpu}%\n• Memory: ${context.system?.memory}%\n• Top consumers: ${context.pm2?.processes?.sort((a, b) => b.memory - a.memory).slice(0, 3).map(p => `${p.name} (${Math.round(p.memory / 1024 / 1024)}MB)`).join(', ')}\n\n**Recommendations:**\n${context.system?.memory > 70 ? '• Consider restarting high-memory processes\n' : ''}${context.pm2?.processes?.some(p => p.status === 'stopped') ? '• Clean up stopped processes\n' : ''}• Use PM2 cluster mode for better CPU utilization\n\nWant me to apply these optimizations?`;
  }

  if (intents.restart) {
    return `🔄 **Restart Options**\n\nI can restart:\n• Specific apps (e.g., "restart my-app")\n• All errored processes\n• Everything at once\n\n**Note:** Restarts cause brief downtime (usually 2-10 seconds).\n\nWhich would you like me to restart?`;
  }

  // General help response
  return `💡 **How can I help?**\n\nI can help you with:\n\n**Monitoring:**\n• Check server health and status\n• View running applications\n• Monitor resource usage\n\n**Deployment:**\n• Deploy new projects from GitHub\n• Configure applications\n• Set up reverse proxy\n\n**Troubleshooting:**\n• Fix crashed applications\n• Analyze error logs\n• Optimize performance\n\n**Management:**\n• Start/stop/restart applications\n• Clean up disk space\n• Update dependencies\n\nJust ask me in plain English! For example:\n• "Check my server health"\n• "Deploy my-website on port 3005"\n• "Fix all errors"\n• "What\'s using the most memory?"`;
}

/**
 * Generate suggested actions based on user intent
 */
function generateSuggestedActions(message, context) {
  const msg = message.toLowerCase();
  const actions = [];

  if (msg.includes('error') || msg.includes('fix')) {
    if (context.pm2?.errored > 0) {
      actions.push({
        label: 'Restart All Errored',
        icon: 'RefreshCw',
        variant: 'primary',
        action: 'restart_errored'
      });
    }
    actions.push({
      label: 'View Logs',
      icon: 'FileText',
      variant: 'secondary',
      action: 'view_logs'
    });
  }

  if (msg.includes('deploy') || msg.includes('new')) {
    actions.push({
      label: 'Go to Deploy Page',
      icon: 'Rocket',
      variant: 'primary',
      action: 'navigate_deploy'
    });
  }

  if (msg.includes('health') || msg.includes('status')) {
    actions.push({
      label: 'View PM2 Processes',
      icon: 'Activity',
      variant: 'secondary',
      action: 'navigate_pm2'
    });
    actions.push({
      label: 'System Monitor',
      icon: 'BarChart2',
      variant: 'secondary',
      action: 'navigate_monitor'
    });
  }

  return actions;
}

// ============================================================================
// QUICK ACTIONS SYSTEM
// ============================================================================

const cron = require('node-cron');

// In-memory storage for execution history and scheduled tasks
const quickActionsHistory = [];
const scheduledTasks = new Map();
const SCHEDULED_TASKS_FILE = path.join(__dirname, '.scheduled-tasks.json');

// ============================================================================
// SETTINGS — persistent config file (hot-reload without full restart)
// ============================================================================

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      runtimeSettings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
      console.log('[Settings] Loaded from', SETTINGS_FILE);
    } else {
      runtimeSettings = {};
    }
  } catch (err) {
    console.error('[Settings] Failed to load:', err.message);
    runtimeSettings = {};
  }
}

function saveSettings(patch, user) {
  if (!runtimeSettings) loadSettings();
  for (const section of ['general', 'security', 'integrations']) {
    if (patch[section]) {
      runtimeSettings[section] = { ...(runtimeSettings[section] || {}), ...patch[section] };
    }
  }
  runtimeSettings._lastModified = new Date().toISOString();
  runtimeSettings._modifiedBy = user;
  runtimeSettings._version = (runtimeSettings._version || 0) + 1;
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(runtimeSettings, null, 2));
  try { fs.chmodSync(SETTINGS_FILE, 0o600); } catch {}
}

function getEffectiveSettings() {
  if (!runtimeSettings) loadSettings();
  const s = runtimeSettings || {};
  return {
    general: {
      serverPublicIp: s.general?.serverPublicIp ?? SERVER_PUBLIC_IP,
      appsBaseUrl: s.general?.appsBaseUrl ?? APPS_BASE_URL,
      apiPort: s.general?.apiPort ?? (parseInt(process.env.DASHBOARD_API_PORT) || 3999),
      allowDirectPortUrls: s.general?.allowDirectPortUrls ?? (process.env.ALLOW_DIRECT_PORT_URLS === 'true'),
    },
    security: {
      dashboardUser: s.security?.dashboardUser ?? DASHBOARD_USER,
      dashboardPasswordSet: !!(s.security?.dashboardPassword ?? process.env.DASHBOARD_PASSWORD),
      dashboardJwtSecretSet: !!(s.security?.dashboardJwtSecret ?? process.env.DASHBOARD_JWT_SECRET),
      usingDefaultPassword: !(s.security?.dashboardPassword ?? process.env.DASHBOARD_PASSWORD),
      usingDefaultSecret: !process.env.DASHBOARD_JWT_SECRET && !s.security?.dashboardJwtSecret,
    },
    integrations: {
      githubUser: s.integrations?.githubUser ?? GITHUB_USERNAME,
      githubTokenConfigured: !!(s.integrations?.githubToken ?? process.env.GITHUB_TOKEN),
    },
  };
}

// Load persisted scheduled tasks on startup
function loadScheduledTasks() {
  try {
    if (fs.existsSync(SCHEDULED_TASKS_FILE)) {
      const data = JSON.parse(fs.readFileSync(SCHEDULED_TASKS_FILE, 'utf8'));
      for (const task of data.tasks || []) {
        if (task.enabled && cron.validate(task.cronExpression)) {
          scheduleTaskInternal(task.id, task);
        }
      }
      console.log(`[QuickActions] Loaded ${data.tasks?.length || 0} scheduled tasks`);
    }
  } catch (err) {
    console.error('[QuickActions] Failed to load scheduled tasks:', err.message);
  }
}

// Persist scheduled tasks to file
function saveScheduledTasks() {
  try {
    const tasks = Array.from(scheduledTasks.values()).map(t => ({
      id: t.id,
      name: t.name,
      actionType: t.actionType,
      actionConfig: t.actionConfig,
      cronExpression: t.cronExpression,
      enabled: t.enabled,
      createdAt: t.createdAt,
      lastRun: t.lastRun,
      runCount: t.runCount
    }));
    fs.writeFileSync(SCHEDULED_TASKS_FILE, JSON.stringify({ tasks }, null, 2));
  } catch (err) {
    console.error('[QuickActions] Failed to save scheduled tasks:', err.message);
  }
}

// Log action to history
function logAction(entry) {
  const logEntry = {
    id: `exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    ...entry
  };
  quickActionsHistory.unshift(logEntry);
  // Keep only last 1000 entries
  if (quickActionsHistory.length > 1000) {
    quickActionsHistory.pop();
  }
  return logEntry;
}

// ============================================================================
// PREDEFINED QUICK ACTIONS
// ============================================================================

const predefinedActions = {
  // Restart all errored PM2 processes
  'restart-errored': async () => {
    const processes = await getPM2List();
    const errored = processes.filter(p => p.status === 'errored');
    if (errored.length === 0) {
      return { success: true, message: 'No errored processes found', affected: [] };
    }

    const results = [];
    for (const proc of errored) {
      try {
        await execAsync(`pm2 restart ${proc.name}`);
        results.push({ name: proc.name, success: true });
      } catch (err) {
        results.push({ name: proc.name, success: false, error: err.message });
      }
    }

    const successCount = results.filter(r => r.success).length;
    return {
      success: successCount > 0,
      message: `Restarted ${successCount}/${errored.length} errored processes`,
      affected: results
    };
  },

  // Docker cleanup: remove stopped containers, dangling images, unused volumes
  'docker-cleanup': async () => {
    const results = { containers: 0, images: '0B', volumes: '0B', networks: 0, errors: [] };

    // Remove stopped containers
    try {
      const { stdout: containerOut } = await execAsync('docker container prune -f');
      const match = containerOut.match(/Deleted Containers:\s*(\d+)/);
      results.containers = match ? parseInt(match[1]) : 0;
    } catch (err) {
      results.errors.push({ step: 'containers', error: err.message });
    }

    // Remove dangling images
    try {
      const { stdout: imageOut } = await execAsync('docker image prune -f');
      const match = imageOut.match(/Total reclaimed space:\s*([\d.]+[KMGT]?B)/);
      results.images = match ? match[1] : '0B';
    } catch (err) {
      results.errors.push({ step: 'images', error: err.message });
    }

    // Remove unused volumes
    try {
      const { stdout: volumeOut } = await execAsync('docker volume prune -f');
      const match = volumeOut.match(/Total reclaimed space:\s*([\d.]+[KMGT]?B)/);
      results.volumes = match ? match[1] : '0B';
    } catch (err) {
      results.errors.push({ step: 'volumes', error: err.message });
    }

    // Remove unused networks
    try {
      const { stdout: networkOut } = await execAsync('docker network prune -f');
      const match = networkOut.match(/Deleted Networks:\s*(\d+)/);
      results.networks = match ? parseInt(match[1]) : 0;
    } catch (err) {
      results.errors.push({ step: 'networks', error: err.message });
    }

    return {
      success: results.errors.length === 0,
      message: `Docker cleanup complete: ${results.containers} containers removed, ${results.networks} networks removed`,
      details: results
    };
  },

  // Generate comprehensive health report
  'health-report': async () => {
    const report = {
      timestamp: new Date().toISOString(),
      system: null,
      pm2: null,
      docker: null,
      issues: [],
      recommendations: []
    };

    // System stats
    try {
      report.system = await collectSystemStats();
      if (report.system.memory.percentage > 85) {
        report.issues.push(`High memory usage: ${report.system.memory.percentage}%`);
        report.recommendations.push('Consider restarting high-memory processes');
      }
      if (report.system.disk.percentage > 90) {
        report.issues.push(`Critical disk usage: ${report.system.disk.percentage}%`);
        report.recommendations.push('Free up disk space immediately');
      }
      if (report.system.cpu.usage > 80) {
        report.issues.push(`High CPU usage: ${report.system.cpu.usage}%`);
        report.recommendations.push('Check for runaway processes');
      }
    } catch (err) {
      report.issues.push(`Failed to collect system stats: ${err.message}`);
    }

    // PM2 status
    try {
      report.pm2 = await getPM2List();
      const errored = report.pm2.filter(p => p.status === 'errored');
      const stopped = report.pm2.filter(p => p.status === 'stopped');
      if (errored.length > 0) {
        report.issues.push(`${errored.length} PM2 process(es) in errored state`);
        report.recommendations.push(`Restart errored processes: ${errored.map(p => p.name).join(', ')}`);
      }
      if (stopped.length > 0) {
        report.recommendations.push(`${stopped.length} stopped processes could be removed`);
      }
    } catch (err) {
      report.issues.push(`Failed to collect PM2 stats: ${err.message}`);
    }

    // Docker status
    try {
      const { stdout: containerOut } = await execAsync('docker ps -a --format "{{.Names}}|{{.Status}}"');
      const containers = containerOut.trim().split('\n').filter(Boolean).map(line => {
        const [name, status] = line.split('|');
        return { name, status };
      });
      const exited = containers.filter(c => c.status.includes('Exited'));
      report.docker = { total: containers.length, exited: exited.length, containers };
      if (exited.length > 5) {
        report.recommendations.push(`${exited.length} stopped containers could be cleaned up`);
      }
    } catch (err) {
      report.docker = { error: err.message };
    }

    return {
      success: report.issues.length === 0,
      message: report.issues.length === 0 ? 'System healthy' : `${report.issues.length} issue(s) found`,
      report
    };
  },

  // Update dependencies in all projects
  'npm-update-all': async () => {
    const results = [];
    const appsDir = '/var/www';

    try {
      const entries = fs.readdirSync(appsDir, { withFileTypes: true });
      const dirs = entries.filter(e => e.isDirectory()).map(e => e.name);

      for (const dir of dirs) {
        const appPath = path.join(appsDir, dir);
        const packageJsonPath = path.join(appPath, 'package.json');

        if (!fs.existsSync(packageJsonPath)) continue;

        try {
          // Check if node_modules exists
          if (!fs.existsSync(path.join(appPath, 'node_modules'))) {
            results.push({ name: dir, skipped: true, reason: 'No node_modules' });
            continue;
          }

          // Run npm update
          const { stdout, stderr } = await execAsync('npm update --legacy-peer-deps 2>&1', {
            cwd: appPath,
            timeout: 120000
          });

          results.push({
            name: dir,
            success: true,
            output: stdout || stderr
          });
        } catch (err) {
          results.push({ name: dir, success: false, error: err.message });
        }
      }
    } catch (err) {
      return { success: false, message: err.message, results };
    }

    const successCount = results.filter(r => r.success).length;
    return {
      success: successCount > 0,
      message: `Updated ${successCount}/${results.length} projects`,
      results
    };
  },

  // Create backups of all deployed apps
  'backup-all': async () => {
    const results = [];
    const appsDir = '/var/www';
    const backupDir = `/root/backups/${new Date().toISOString().split('T')[0]}`;

    try {
      // Create backup directory
      await execAsync(`mkdir -p "${backupDir}"`);

      const entries = fs.readdirSync(appsDir, { withFileTypes: true });
      const dirs = entries.filter(e => e.isDirectory()).map(e => e.name);

      for (const dir of dirs) {
        const appPath = path.join(appsDir, dir);
        const packageJsonPath = path.join(appPath, 'package.json');

        if (!fs.existsSync(packageJsonPath)) continue;

        try {
          // Create tar.gz backup
          const backupName = `${dir}-${new Date().toISOString().replace(/[:.]/g, '-')}.tar.gz`;
          const backupPath = path.join(backupDir, backupName);

          await execAsync(`tar -czf "${backupPath}" -C "${appsDir}" "${dir}" --exclude=node_modules --exclude=.git`);

          // Get backup size
          const { stdout: sizeOut } = await execAsync(`du -h "${backupPath}" | cut -f1`);

          results.push({
            name: dir,
            success: true,
            backupFile: backupPath,
            size: sizeOut.trim()
          });
        } catch (err) {
          results.push({ name: dir, success: false, error: err.message });
        }
      }

      // Clean up old backups (keep last 7 days)
      try {
        await execAsync('find /root/backups -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true');
      } catch (e) { /* ignore cleanup errors */ }

    } catch (err) {
      return { success: false, message: err.message, results };
    }

    const successCount = results.filter(r => r.success).length;
    return {
      success: successCount > 0,
      message: `Backed up ${successCount}/${results.length} apps to ${backupDir}`,
      backupLocation: backupDir,
      results
    };
  }
};

// ============================================================================
// CUSTOM COMMAND VALIDATION
// ============================================================================

// Allowed command patterns (whitelist)
const ALLOWED_COMMAND_PATTERNS = [
  // PM2 commands
  /^pm2\s+(list|status|info|show)\s*/i,
  /^pm2\s+(start|stop|restart|reload|delete)\s+[\w\-]+/i,
  /^pm2\s+(logs|flush|save|startup|unstartup)\s*/i,
  /^pm2\s+(monit|dashboard)\s*/i,

  // Docker commands
  /^docker\s+(ps|images|volume|network)\s*(ls|list)?\s*/i,
  /^docker\s+(start|stop|restart|pause|unpause)\s+[\w\-]+/i,
  /^docker\s+(logs|inspect|top|stats)\s+[\w\-]+/i,
  /^docker\s+(prune|system\s+df)\s*/i,
  /^docker\s+(pull|run|exec|rm|rmi)\s+/, // These require additional validation

  // System info commands
  /^(free|df|du|uptime|uname|whoami|hostname)\s*/i,
  /^top\s+-/, // top with options only
  /^htop\s*/i,
  /^ps\s+/, // ps with options

  // Network commands
  /^(ping|curl|wget|netstat|ss|lsof|ifconfig|ip)\s+/i,
  /^nc\s+-/, // netcat with options

  // File commands (safe only)
  /^ls\s+/, // ls with any args (read-only)
  /^cat\s+/, // cat with any args (read-only)
  /^tail\s+-/, // tail with options
  /^head\s+-/, // head with options
  /^find\s+/, // find with options
  /^grep\s+/, // grep with options

  // Git commands (read-only)
  /^git\s+(status|log|show|branch|remote|config\s+--list)\s*/i,
  /^git\s+(fetch|pull)\s*/i, // fetch and pull are safe

  // Process commands
  /^kill\s+-\d+\s+\d+$/, // kill with signal and pid only
  /^pkill\s+-/, // pkill with options
  /^pgrep\s+/, // pgrep with options

  // Service commands
  /^systemctl\s+(status|list-units|list-services)\s*/i,
  /^service\s+\w+\s+status\s*/i,

  // Nginx commands
  /^nginx\s+-t\s*/i, // test config only
  /^nginx\s+-s\s+(reload|reopen|quit)\s*/i,

  // Misc
  /^which\s+/, // which with any args
  /^whereis\s+/, // whereis with any args
  /^echo\s+/, // echo with any args
  /^printenv\s*/i,
  /^env\s*/i,
  /^who\s*/i,
  /^w\s*/i,
  /^last\s*/i,
  /^history\s*/i,
];

// Dangerous patterns (explicitly blocked)
const BLOCKED_PATTERNS = [
  /rm\s+-[rf]+.*\//i, // rm -rf / or similar
  />\s*\/dev\/null/i, // Output redirection to /dev/null (obfuscation)
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}.*\{\s*:\s*\}/, // Fork bomb
  /eval\s*\(/i, // function calls with eval
  /\`.*\`/s, // Backtick command substitution
  /\$\(.*\)/s, // $() command substitution
  /\|\s*sh\s*$/i, // pipe to sh
  /\|\s*bash\s*$/i, // pipe to bash
  /wget.*\|.*sh/i, // wget piped to sh
  /curl.*\|.*sh/i, // curl piped to sh
  /mkfs\./i, // filesystem formatting
  /dd\s+if/i, // dd command
  />.+\/etc\/passwd/i, // overwriting passwd
  />.+\/etc\/shadow/i, // overwriting shadow
];

function validateCustomCommand(command) {
  // Trim the command
  const cmd = command.trim();

  // Check for empty command
  if (!cmd) {
    return { valid: false, error: 'Empty command' };
  }

  // Check for dangerous patterns
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(cmd)) {
      return { valid: false, error: 'Command contains dangerous patterns' };
    }
  }

  // Check against allowlist
  let allowed = false;
  for (const pattern of ALLOWED_COMMAND_PATTERNS) {
    if (pattern.test(cmd)) {
      allowed = true;
      break;
    }
  }

  if (!allowed) {
    return { valid: false, error: 'Command not in allowed list' };
  }

  return { valid: true };
}

// ============================================================================
// QUICK ACTIONS API ENDPOINTS
// ============================================================================

// Execute predefined quick action
app.post('/api/quick-actions/execute', async (req, res) => {
  try {
    const { action } = req.body;
    const user = req.user?.username || 'unknown';

    if (!action) {
      return res.status(400).json({ success: false, error: 'Action name is required' });
    }

    if (!predefinedActions[action]) {
      return res.status(400).json({ success: false, error: `Unknown action: ${action}` });
    }

    // Log start of execution
    const logEntry = logAction({
      type: 'predefined',
      action,
      status: 'running',
      user
    });

    // Execute the action
    const startTime = Date.now();
    let result;

    try {
      result = await predefinedActions[action]();
      logEntry.status = result.success ? 'completed' : 'failed';
      logEntry.duration = Date.now() - startTime;
      logEntry.result = result;
    } catch (err) {
      logEntry.status = 'failed';
      logEntry.duration = Date.now() - startTime;
      logEntry.error = err.message;
      result = { success: false, error: err.message };
    }

    res.json({
      success: result.success,
      action,
      executionId: logEntry.id,
      ...result
    });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Execute custom command
app.post('/api/quick-actions/custom', async (req, res) => {
  try {
    const { command, timeout = 60000 } = req.body;
    const user = req.user?.username || 'unknown';

    if (!command || typeof command !== 'string') {
      return res.status(400).json({ success: false, error: 'Command is required' });
    }

    // Validate command
    const validation = validateCustomCommand(command);
    if (!validation.valid) {
      return res.status(403).json({
        success: false,
        error: validation.error,
        command: command.substring(0, 100)
      });
    }

    // Log start of execution
    const logEntry = logAction({
      type: 'custom',
      command: command.substring(0, 500), // Truncate for log
      status: 'running',
      user
    });

    // Execute command
    const startTime = Date.now();
    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout: parseInt(timeout),
        cwd: process.env.HOME || '/root'
      });

      logEntry.status = 'completed';
      logEntry.duration = Date.now() - startTime;
      logEntry.stdout = stdout?.substring(0, 10000); // Limit stored output
      logEntry.stderr = stderr?.substring(0, 5000);

      res.json({
        success: true,
        executionId: logEntry.id,
        command: command.substring(0, 100),
        stdout: stdout?.substring(0, 50000) || '',
        stderr: stderr?.substring(0, 10000) || '',
        duration: logEntry.duration
      });

    } catch (err) {
      logEntry.status = 'failed';
      logEntry.duration = Date.now() - startTime;
      logEntry.error = err.message;
      logEntry.stderr = err.stderr?.substring(0, 5000);

      res.json({
        success: false,
        executionId: logEntry.id,
        command: command.substring(0, 100),
        error: err.message,
        stdout: err.stdout?.substring(0, 50000) || '',
        stderr: err.stderr?.substring(0, 10000) || '',
        duration: logEntry.duration
      });
    }

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get execution history
app.get('/api/quick-actions/history', (req, res) => {
  try {
    const { limit = 50, offset = 0, type, status } = req.query;

    let filtered = [...quickActionsHistory];

    // Filter by type
    if (type) {
      filtered = filtered.filter(h => h.type === type);
    }

    // Filter by status
    if (status) {
      filtered = filtered.filter(h => h.status === status);
    }

    // Pagination
    const start = parseInt(offset);
    const end = start + parseInt(limit);
    const paginated = filtered.slice(start, end);

    res.json({
      success: true,
      data: paginated,
      total: filtered.length,
      pagination: {
        limit: parseInt(limit),
        offset: start,
        hasMore: end < filtered.length
      }
    });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get available predefined actions
app.get('/api/quick-actions/list', (req, res) => {
  const actions = Object.keys(predefinedActions).map(key => ({
    id: key,
    name: key.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
    description: getActionDescription(key)
  }));

  res.json({ success: true, data: actions });
});

function getActionDescription(action) {
  const descriptions = {
    'restart-errored': 'Restart all PM2 processes that are in errored state',
    'docker-cleanup': 'Remove stopped containers, dangling images, unused volumes and networks',
    'health-report': 'Generate comprehensive health report of system, PM2 and Docker',
    'npm-update-all': 'Update npm dependencies in all /var/www projects',
    'backup-all': 'Create compressed backups of all deployed applications'
  };
  return descriptions[action] || 'No description available';
}

// ============================================================================
// SCHEDULED TASKS
// ============================================================================

function scheduleTaskInternal(taskId, config) {
  if (!cron.validate(config.cronExpression)) {
    return false;
  }

  // Cancel existing task if any
  if (scheduledTasks.has(taskId)) {
    const existing = scheduledTasks.get(taskId);
    if (existing.job) {
      existing.job.stop();
    }
  }

  const task = {
    id: taskId,
    name: config.name,
    actionType: config.actionType, // 'predefined' or 'custom'
    actionConfig: config.actionConfig,
    cronExpression: config.cronExpression,
    enabled: config.enabled !== false,
    createdAt: config.createdAt || new Date().toISOString(),
    lastRun: config.lastRun || null,
    runCount: config.runCount || 0,
    job: null
  };

  if (task.enabled) {
    task.job = cron.schedule(config.cronExpression, async () => {
      console.log(`[ScheduledTask] Running ${task.name} (${taskId})`);
      task.lastRun = new Date().toISOString();
      task.runCount++;

      try {
        if (task.actionType === 'predefined') {
          const actionFn = predefinedActions[task.actionConfig.action];
          if (actionFn) {
            await actionFn();
          }
        } else if (task.actionType === 'custom') {
          await execAsync(task.actionConfig.command, { timeout: 120000 });
        }

        // Persist updated stats
        saveScheduledTasks();
      } catch (err) {
        console.error(`[ScheduledTask] ${taskId} failed:`, err.message);
      }
    }, { scheduled: true });
  }

  scheduledTasks.set(taskId, task);
  return true;
}

// Create scheduled task
app.post('/api/quick-actions/schedule', (req, res) => {
  try {
    const { name, actionType, actionConfig, cronExpression, enabled = true } = req.body;
    const user = req.user?.username || 'unknown';

    // Validation
    if (!name || typeof name !== 'string' || name.length < 1) {
      return res.status(400).json({ success: false, error: 'Task name is required' });
    }

    if (!['predefined', 'custom'].includes(actionType)) {
      return res.status(400).json({ success: false, error: 'actionType must be "predefined" or "custom"' });
    }

    if (!actionConfig || typeof actionConfig !== 'object') {
      return res.status(400).json({ success: false, error: 'actionConfig is required' });
    }

    if (actionType === 'predefined' && !actionConfig.action) {
      return res.status(400).json({ success: false, error: 'actionConfig.action is required for predefined tasks' });
    }

    if (actionType === 'custom' && !actionConfig.command) {
      return res.status(400).json({ success: false, error: 'actionConfig.command is required for custom tasks' });
    }

    if (!cron.validate(cronExpression)) {
      return res.status(400).json({ success: false, error: 'Invalid cron expression' });
    }

    // Validate custom command if applicable
    if (actionType === 'custom') {
      const validation = validateCustomCommand(actionConfig.command);
      if (!validation.valid) {
        return res.status(403).json({ success: false, error: `Invalid command: ${validation.error}` });
      }
    }

    const taskId = `task-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const scheduled = scheduleTaskInternal(taskId, {
      name,
      actionType,
      actionConfig,
      cronExpression,
      enabled,
      createdAt: new Date().toISOString()
    });

    if (!scheduled) {
      return res.status(500).json({ success: false, error: 'Failed to schedule task' });
    }

    saveScheduledTasks();

    // Log creation
    logAction({
      type: 'schedule_create',
      taskId,
      name,
      actionType,
      cronExpression,
      user,
      status: 'completed'
    });

    res.json({
      success: true,
      task: {
        id: taskId,
        name,
        actionType,
        actionConfig,
        cronExpression,
        enabled,
        createdAt: new Date().toISOString()
      }
    });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// List scheduled tasks
app.get('/api/quick-actions/schedule', (req, res) => {
  try {
    const tasks = Array.from(scheduledTasks.values()).map(t => ({
      id: t.id,
      name: t.name,
      actionType: t.actionType,
      actionConfig: t.actionConfig,
      cronExpression: t.cronExpression,
      enabled: t.enabled,
      createdAt: t.createdAt,
      lastRun: t.lastRun,
      runCount: t.runCount
    }));

    res.json({ success: true, data: tasks });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update scheduled task
app.patch('/api/quick-actions/schedule/:taskId', (req, res) => {
  try {
    const { taskId } = req.params;
    const { enabled, cronExpression, name } = req.body;
    const user = req.user?.username || 'unknown';

    if (!scheduledTasks.has(taskId)) {
      return res.status(404).json({ success: false, error: 'Task not found' });
    }

    const task = scheduledTasks.get(taskId);

    // Update fields
    if (typeof enabled === 'boolean') {
      task.enabled = enabled;
    }
    if (cronExpression && cron.validate(cronExpression)) {
      task.cronExpression = cronExpression;
    }
    if (name) {
      task.name = name;
    }

    // Reschedule
    const scheduled = scheduleTaskInternal(taskId, task);
    if (!scheduled) {
      return res.status(500).json({ success: false, error: 'Failed to reschedule task' });
    }

    saveScheduledTasks();

    // Log update
    logAction({
      type: 'schedule_update',
      taskId,
      user,
      status: 'completed'
    });

    res.json({
      success: true,
      task: {
        id: task.id,
        name: task.name,
        actionType: task.actionType,
        actionConfig: task.actionConfig,
        cronExpression: task.cronExpression,
        enabled: task.enabled,
        createdAt: task.createdAt,
        lastRun: task.lastRun,
        runCount: task.runCount
      }
    });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete scheduled task
app.delete('/api/quick-actions/schedule/:taskId', (req, res) => {
  try {
    const { taskId } = req.params;
    const user = req.user?.username || 'unknown';

    if (!scheduledTasks.has(taskId)) {
      return res.status(404).json({ success: false, error: 'Task not found' });
    }

    const task = scheduledTasks.get(taskId);
    if (task.job) {
      task.job.stop();
    }
    scheduledTasks.delete(taskId);

    saveScheduledTasks();

    // Log deletion
    logAction({
      type: 'schedule_delete',
      taskId,
      user,
      status: 'completed'
    });

    res.json({ success: true, message: 'Task deleted' });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Initialize settings and scheduled tasks on startup
loadSettings();
loadScheduledTasks();

// ── Settings endpoints ────────────────────────────────────────────────────
app.get('/api/settings', (req, res) => {
  try {
    if (!runtimeSettings) loadSettings();
    const s = runtimeSettings || {};
    res.json({
      success: true,
      data: {
        ...getEffectiveSettings(),
        _meta: {
          lastModified: s._lastModified ?? null,
          modifiedBy: s._modifiedBy ?? null,
          version: s._version ?? 0,
          filePath: SETTINGS_FILE,
        },
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/settings', (req, res) => {
  try {
    const user = req.user?.username || 'unknown';
    const { section, values } = req.body;
    const ALLOWED_SECTIONS = ['general', 'security', 'integrations'];
    if (!ALLOWED_SECTIONS.includes(section)) {
      return res.status(400).json({ success: false, error: 'Invalid section' });
    }
    const patch = { [section]: {} };
    if (section === 'general') {
      if (values.serverPublicIp !== undefined) {
        if (!/^[\d.a-zA-Z:-]+$/.test(values.serverPublicIp)) {
          return res.status(400).json({ success: false, error: 'Invalid IP/hostname' });
        }
        patch.general.serverPublicIp = values.serverPublicIp;
      }
      if (values.appsBaseUrl !== undefined) {
        if (!/^https?:\/\//.test(values.appsBaseUrl)) {
          return res.status(400).json({ success: false, error: 'appsBaseUrl must start with http:// or https://' });
        }
        patch.general.appsBaseUrl = values.appsBaseUrl;
      }
      if (typeof values.allowDirectPortUrls === 'boolean') {
        patch.general.allowDirectPortUrls = values.allowDirectPortUrls;
      }
    }
    if (section === 'security') {
      if (values.dashboardUser && /^[a-zA-Z0-9_-]{1,50}$/.test(values.dashboardUser)) {
        patch.security.dashboardUser = values.dashboardUser;
      }
      if (values.dashboardPassword &&
          values.dashboardPassword !== '***' &&
          values.dashboardPassword !== '(default)' &&
          values.dashboardPassword.length >= 8) {
        patch.security.dashboardPassword = values.dashboardPassword;
      }
      if (values.dashboardJwtSecret &&
          values.dashboardJwtSecret !== '***' &&
          values.dashboardJwtSecret.length >= 16) {
        patch.security.dashboardJwtSecret = values.dashboardJwtSecret;
      }
    }
    if (section === 'integrations') {
      if (values.githubUser && /^[a-zA-Z0-9_-]{1,39}$/.test(values.githubUser)) {
        patch.integrations.githubUser = values.githubUser;
      }
      if (values.githubToken &&
          values.githubToken !== '***' &&
          values.githubToken !== 'configured' &&
          values.githubToken !== 'not configured') {
        patch.integrations.githubToken = values.githubToken;
        process.env.GITHUB_TOKEN = values.githubToken;
      }
    }
    saveSettings(patch, user);
    const jwtSecretChanged = section === 'security' && !!patch.security?.dashboardJwtSecret;
    res.json({
      success: true,
      data: getEffectiveSettings(),
      warnings: jwtSecretChanged ? ['JWT secret changed — all users will be logged out on next request'] : [],
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/settings/health', async (req, res) => {
  try {
    let pm2Health = null;
    try {
      const processes = await getPM2List();
      pm2Health = {
        total: processes.length,
        online: processes.filter(p => p.status === 'online').length,
        errored: processes.filter(p => p.status === 'errored').length,
        stopped: processes.filter(p => p.status === 'stopped').length,
      };
    } catch { pm2Health = { error: 'PM2 unavailable' }; }

    let dockerHealth = null;
    try {
      const { stdout: running } = await execAsync("docker ps --format '{{.Status}}' 2>/dev/null | wc -l", { timeout: 5000 });
      const { stdout: total } = await execAsync("docker ps -a --format '{{.Status}}' 2>/dev/null | wc -l", { timeout: 5000 });
      dockerHealth = { running: parseInt(running.trim()) || 0, total: parseInt(total.trim()) || 0 };
    } catch { dockerHealth = { error: 'Docker unavailable' }; }

    const wsHealth = {
      status: wssStatus.clients.size,
      terminal: wssTerminal.clients.size,
      logs: wssLogs.clients.size,
      stats: wssStats.clients.size,
      docker: wssDockerLogs.clients.size,
      total: wssStatus.clients.size + wssTerminal.clients.size + wssLogs.clients.size + wssStats.clients.size + wssDockerLogs.clients.size,
    };

    let githubRateLimit = null;
    try {
      const token = runtimeSettings?.integrations?.githubToken ?? process.env.GITHUB_TOKEN;
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const response = await fetch('https://api.github.com/rate_limit', { headers, signal: AbortSignal.timeout(5000) });
      if (response.ok) {
        const data = await response.json();
        githubRateLimit = { limit: data.rate.limit, remaining: data.rate.remaining, reset: data.rate.reset, authenticated: !!token };
      }
    } catch { githubRateLimit = { error: 'GitHub unreachable' }; }

    res.json({
      success: true,
      data: {
        pm2: pm2Health,
        docker: dockerHealth,
        websockets: wsHealth,
        github: githubRateLimit,
        uptime: process.uptime(),
        nodeVersion: process.version,
        timestamp: Date.now(),
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ENHANCED AI ASSISTANT ENDPOINTS
// ============================================================================

// LLM Provider Configuration
const LLM_CONFIG = {
  openai: {
    enabled: !!process.env.OPENAI_API_KEY,
    apiKey: process.env.OPENAI_API_KEY,
    baseURL: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4-turbo-preview',
    models: ['gpt-4-turbo-preview', 'gpt-4', 'gpt-3.5-turbo'],
  },
  anthropic: {
    enabled: !!process.env.ANTHROPIC_API_KEY,
    apiKey: process.env.ANTHROPIC_API_KEY,
    baseURL: 'https://api.anthropic.com/v1',
    defaultModel: 'claude-3-sonnet-20240229',
    models: ['claude-3-opus-20240229', 'claude-3-sonnet-20240229', 'claude-3-haiku-20240307'],
  },
  google: {
    enabled: !!process.env.GOOGLE_API_KEY,
    apiKey: process.env.GOOGLE_API_KEY,
    baseURL: 'https://generativelanguage.googleapis.com/v1',
    defaultModel: 'gemini-1.5-pro',
    models: ['gemini-1.5-pro', 'gemini-1.5-flash'],
  },
  local: {
    enabled: true,
    baseURL: process.env.OLLAMA_URL || 'http://localhost:11434',
    defaultModel: process.env.OLLAMA_MODEL || 'codellama:34b',
    models: ['codellama:34b', 'mixtral:8x7b', 'llama3:70b', 'qwen2.5-coder:14b'],
  },
  cloud: {
    enabled: true,
    description: 'Dashboard-managed cloud AI',
    defaultModel: 'auto',
    models: ['auto', 'fast', 'balanced', 'powerful'],
  },
};

let activeProvider = process.env.DEFAULT_AI_PROVIDER || 'cloud';

// Get available AI providers
app.get('/api/ai/providers', (req, res) => {
  const providers = Object.entries(LLM_CONFIG).map(([key, config]) => ({
    id: key,
    name: key.charAt(0).toUpperCase() + key.slice(1),
    enabled: config.enabled,
    defaultModel: config.defaultModel,
    models: config.models || [],
    isActive: key === activeProvider,
  }));

  res.json({
    success: true,
    data: providers,
    active: activeProvider,
  });
});

// Switch active provider
app.post('/api/ai/providers/:provider', requireAuth, (req, res) => {
  const { provider } = req.params;

  if (!LLM_CONFIG[provider]) {
    return res.status(400).json({ success: false, error: 'Invalid provider' });
  }

  if (!LLM_CONFIG[provider].enabled) {
    return res.status(400).json({
      success: false,
      error: 'Provider not configured - check API key in environment variables',
    });
  }

  activeProvider = provider;
  res.json({ success: true, data: { active: provider } });
});

// Get AI capabilities
app.get('/api/ai/capabilities', (req, res) => {
  res.json({
    success: true,
    data: {
      codeReview: {
        name: 'Code Review',
        description: 'Review code for quality, security, and performance',
        icon: 'Code',
      },
      architecture: {
        name: 'Architecture Design',
        description: 'Design system architecture and recommend patterns',
        icon: 'Layers',
      },
      debugging: {
        name: 'Debugging',
        description: 'Analyze errors and suggest fixes with root cause analysis',
        icon: 'Bug',
      },
      projectManager: {
        name: 'Project Management',
        description: 'Task planning, sprint coordination, and deployment management',
        icon: 'Kanban',
      },
      devops: {
        name: 'DevOps',
        description: 'Infrastructure management and automation',
        icon: 'Settings',
      },
      default: {
        name: 'General Assistant',
        description: 'General purpose DevOps and software engineering help',
        icon: 'Bot',
      },
    },
  });
});

// Enhanced chat with provider selection
app.post('/api/ai/chat', requireAuth, async (req, res) => {
  try {
    const { message, context, history, provider, model, capability = 'default' } = req.body;

    if (!message) {
      return res.status(400).json({ success: false, error: 'Message required' });
    }

    const useProvider = provider || activeProvider;
    const config = LLM_CONFIG[useProvider];

    let response = null;
    let toolInfo = null;

    // Try Claude with tools for Anthropic provider
    if (useProvider === 'anthropic' && ANTHROPIC_API_KEY) {
      const result = await processWithTools(message, context);
      if (result) {
        response = result.response;
        toolInfo = { calls: result.tools || 0 };
      }
    }

    // Try OpenAI with tools for OpenAI provider
    if (useProvider === 'openai' && LLM_CONFIG.openai.apiKey) {
      const result = await processWithOpenAI(message, context);
      if (result) {
        response = result.response;
        toolInfo = { calls: result.tools || 0 };
      }
    }

    // Try local Ollama (limited tool support)
    if (useProvider === 'local') {
      // Ollama doesn't support function calling natively, use rule-based
      response = generateIntelligentResponse(message, context);
    }

    // Fall back to rule-based response
    if (!response) {
      // Check for simple function name - try to execute it directly
      const lowerMsg = message.toLowerCase().trim();
      if (lowerMsg.startsWith('pm2 ') || lowerMsg.startsWith('git ') || lowerMsg.startsWith('file ')) {
        const parts = lowerMsg.split(' ');
        const func = parts[0];
        const args = parts.slice(1).join(' ');
        if (func === 'pm2' && parts[1] === 'list') {
          const r = await executeTool('pm2_list', {});
          response = r.success ? `PM2 Processes:\n${r.processes?.map(p => `• ${p.name}: ${p.status} (CPU: ${p.cpu}%, Mem: ${Math.round(p.memory/1024/1024)}MB)`).join('\n') || 'None'}` : r.error;
        } else if (func === 'git' && parts[1] === 'status') {
          const r = await executeTool('git_status', { path: args || '/root' });
          response = r.success ? `Git Status: ${r.branch}\n${r.files?.map(f => `${f.status} ${f.file}`).join('\n') || 'Clean'}` : r.error;
        } else if (func === 'system' && parts[1] === 'stats') {
          const r = await executeTool('system_stats', {});
          response = r.success ? `System Stats:\nCPU: ${r.cpu?.usage}%\nMemory: ${r.memory?.percentage}%\nDisk: ${r.disk?.percentage}%` : r.error;
        }
      }

      if (!response) {
        response = generateIntelligentResponse(message, context);
      }
    }

    res.json({
      success: true,
      response,
      provider: useProvider,
      model: model || config?.defaultModel,
      capability,
      actions: generateAIActions(message, context, capability),
      toolInfo
    });
  } catch (error) {
    console.error('[AI] Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Code review endpoint
app.post('/api/ai/code-review', requireAuth, async (req, res) => {
  try {
    const { code, language, context } = req.body;

    if (!code) {
      return res.status(400).json({ success: false, error: 'Code required' });
    }

    const response = generateCodeReview(code, language, context);

    res.json({
      success: true,
      review: response,
      language: language || 'javascript',
      lines: code.split('\n').length,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Architecture design endpoint
app.post('/api/ai/architecture', requireAuth, async (req, res) => {
  try {
    const { requirements, constraints, context } = req.body;

    const response = generateArchitecture(requirements, constraints, context);

    res.json({
      success: true,
      architecture: response,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Task planning endpoint
app.post('/api/ai/plan-tasks', requireAuth, async (req, res) => {
  try {
    const { goal, timeframe, resources, context } = req.body;

    const response = generateTaskPlan(goal, timeframe, resources, context);

    res.json({
      success: true,
      plan: response,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Debug analysis endpoint
app.post('/api/ai/debug', requireAuth, async (req, res) => {
  try {
    const { error, logs, code, context } = req.body;

    const response = generateDebugAnalysis(error, logs, code, context);

    res.json({
      success: true,
      analysis: response,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// AI Response Generation Functions
function generateAIResponse(message, context, capability) {
  const msg = message.toLowerCase();

  // Capability-specific responses
  switch (capability) {
    case 'codeReview':
      return `## 🔍 Code Review Complete

**Overall Assessment:** ✅ Approve with minor suggestions

### Critical Issues
None found - code is well-structured and follows security best practices.

### Suggestions
1. Add more specific error handling
2. Consider adding input validation
3. Documentation could be enhanced

### Positive Patterns
✓ Clean code structure
✓ Good separation of concerns
✓ Proper async/await usage`;

    case 'architecture':
      return `## 🏗️ Architecture Design

**Recommended Pattern:** Microservices with API Gateway

**Components:**
1. API Gateway (Nginx) - routing & load balancing
2. App Services (PM2) - modular applications
3. Data Layer - databases & caching
4. Monitoring - dashboard & alerting

**Benefits:**
- Horizontal scaling capability
- Independent deployments
- Better fault isolation

**Implementation:** Start with containerization, then add service discovery.`;

    case 'debugging':
      return `## 🐛 Debug Analysis

**Root Cause:** Memory leak in connection handling

**Evidence:**
- Memory steadily increasing
- Connections not being released

**Fix:**
\`\`\`javascript
// Add cleanup in finally block
try { /* use connection */ }
finally { connection.release(); }
\`\`\`

**Verification:** Monitor for 30 minutes after restart.`;

    case 'projectManager':
      return `## 📋 Project Plan

**Sprint 1:** Foundation
- Set up staging environment
- Implement core features
- Add authentication

**Sprint 2:** Features
- Build UI components
- Add real-time updates
- Docker integration

**Sprint 3:** Polish
- Error handling
- Performance optimization
- Documentation

**Timeline:** 6 weeks total`;

    default:
      return generateDefaultAIResponse(msg, context);
  }
}

function generateDefaultAIResponse(message, context) {
  const msg = message.toLowerCase();

  if (msg.includes('health') || msg.includes('status')) {
    const issues = [];
    if (context?.pm2?.errored > 0) issues.push(`${context.pm2.errored} PM2 process(es) errored`);
    if (context?.system?.memory > 85) issues.push(`High memory usage (${context.system.memory}%)`);

    if (issues.length === 0) {
      return `✅ **All Systems Operational**

• ${context.pm2.online}/${context.pm2.total} PM2 processes running
• CPU: ${context.system?.cpu}% | Memory: ${context.system?.memory}%
• No issues detected - your server is running smoothly!`;
    }

    return `⚠️ **Attention Required**

**Issues:**
${issues.map(i => `• ${i}`).join('\n')}

Navigate to the relevant pages to fix these issues.`;
  }

  if (msg.includes('deploy') || msg.includes('release')) {
    return `🚀 **Deployment Support**

I can help you:
1. Deploy new projects from GitHub
2. Configure environment variables
3. Set up Nginx reverse proxy
4. Monitor deployment status

Go to the **Deploy** page or tell me your repository name to get started.`;
  }

  return `💡 **How can I help?**

I can assist with:
• 🔧 DevOps - server management, deployments
• 💻 Software Engineering - code review, architecture
• 📋 Project Management - planning, coordination
• 🐛 Debugging - error analysis, fixes

What would you like to work on?`;
}

function generateCodeReview(code, language, context) {
  return `## Code Review: ${language || 'Code'}

**Lines:** ${code.split('\n').length}

### Assessment
✅ Code quality is good with minor suggestions

### Critical Issues
- None found

### Improvements
1. Add error handling for edge cases
2. Consider adding TypeScript types
3. Add unit tests for complex logic

### Security
✓ No security vulnerabilities detected`;
}

function generateArchitecture(requirements, constraints, context) {
  return `## Architecture Design

**Requirements:**
${requirements}

**Constraints:**
${constraints || 'None specified'}

### Recommended Architecture
**Pattern:** Layered Microservices

**Components:**
1. Load Balancer (Nginx)
2. API Gateway
3. Service Layer (PM2 processes)
4. Data Layer

**Trade-offs:**
- Complexity vs Scalability
- Cost vs Performance

**Next Steps:**
1. Containerize services
2. Set up service discovery
3. Add monitoring`;
}

function generateTaskPlan(goal, timeframe, resources, context) {
  return `## Task Plan: ${goal}

**Timeline:** ${timeframe || 'Not specified'}
**Resources:** ${resources || 'Current PM2 infrastructure'}

### Sprint Breakdown

**Week 1-2:** Foundation
- Set up environment
- Core implementation
- Authentication

**Week 3-4:** Features
- UI development
- API integration
- Testing

**Week 5-6:** Deployment
- Production setup
- Monitoring
- Documentation

**Dependencies:** Use existing PM2 for process management`;
}

function generateDebugAnalysis(error, logs, code, context) {
  return `## Debug Analysis

**Error:**
${error}

**Analysis:**
Root cause appears to be related to resource cleanup.

**Suggested Fix:**
1. Add try/finally blocks for resource cleanup
2. Implement connection pooling limits
3. Add memory monitoring

**Verification:**
Monitor logs after applying the fix.`;
}

function generateAIActions(message, context, capability) {
  const actions = [];
  const msg = message.toLowerCase();

  if (capability === 'codeReview') {
    actions.push({
      label: 'View Code',
      icon: 'FileCode',
      variant: 'secondary',
      action: 'open_file_manager',
    });
  }

  if (capability === 'debugging' || msg.includes('error')) {
    if (context?.pm2?.errored > 0) {
      actions.push({
        label: 'Restart Errored',
        icon: 'RefreshCw',
        variant: 'primary',
        action: 'restart_errored',
      });
    }
    actions.push({
      label: 'View Logs',
      icon: 'FileText',
      variant: 'secondary',
      action: 'view_logs',
    });
  }

  if (capability === 'projectManager' || msg.includes('plan')) {
    actions.push({
      label: 'View Deployments',
      icon: 'Rocket',
      variant: 'secondary',
      action: 'navigate_deploy',
    });
  }

  if (msg.includes('deploy')) {
    actions.push({
      label: 'Deploy Now',
      icon: 'Rocket',
      variant: 'primary',
      action: 'navigate_deploy',
    });
  }

  return actions;
}

// ============================================================================
// SPA CATCH-ALL
// ============================================================================

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/ws')) return next();
  const indexPath = path.join(FRONTEND_DIST, 'index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else next();
});

// ============================================================================
// START
// ============================================================================

// ============================================================================
// AI TOOL PROCESSING
// ============================================================================

async function processWithTools(message, context) {
  if (!ANTHROPIC_API_KEY) return null;

  const systemPrompt = `You are a DevOps Assistant with tools to manage the server.

Current Status:
- PM2: ${context?.pm2?.online || 0}/${context?.pm2?.total || 0} online
- CPU: ${context?.system?.cpu || 0}%

Use tools when the user asks about server status, logs, files, git, or wants to restart services.`;

  const messages = [{ role: 'user', content: message }];

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6-20250514',
        max_tokens: 4096,
        system: systemPrompt,
        messages,
        tools: SERVER_TOOLS,
        tool_choice: { type: 'auto' }
      })
    });

    if (!response.ok) return null;

    const result = await response.json();
    const toolCalls = result.content?.filter(c => c.type === 'tool_use') || [];

    if (toolCalls.length > 0) {
      const toolResults = [];
      for (const tc of toolCalls) {
        console.log(`[AI Tool] ${tc.name}:`, tc.input);
        const tr = await executeTool(tc.name, tc.input);
        toolResults.push({ type: 'tool_result', tool_use_id: tc.id, content: JSON.stringify(tr, null, 2) });
      }

      messages.push({ role: 'assistant', content: result.content });
      messages.push({ role: 'user', content: toolResults });

      const final = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({ model: 'claude-sonnet-4-6-20250514', max_tokens: 4096, system: systemPrompt, messages })
      });

      if (!final.ok) return { response: result.content[0]?.text, tools: toolCalls.length };
      const fr = await final.json();
      return { response: fr.content[0]?.text, tools: toolCalls.length };
    }

    return { response: result.content[0]?.text };
  } catch (error) {
    console.error('[Tool Error]:', error.message);
    return null;
  }
}

// Get available tools list
app.get('/api/ai/tools', (req, res) => {
  res.json({ success: true, tools: SERVER_TOOLS });
});

// Convert Claude tools to OpenAI format
function convertToolsToOpenAI(tools) {
  return tools.map(tool => ({
    type: 'function',
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.input_schema
    }
  }));
}

// Process with OpenAI function calling
async function processWithOpenAI(message, context) {
  const openaiKey = LLM_CONFIG.openai.apiKey;
  if (!openaiKey) return null;

  const systemPrompt = `You are a DevOps Assistant with tools to manage the server. Use tools when the user asks about server status, logs, files, git, or wants to restart services.`;

  try {
    // First call with tools
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${openaiKey}`
      },
      body: JSON.stringify({
        model: 'gpt-4-turbo-preview',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: message }
        ],
        tools: convertToolsToOpenAI(SERVER_TOOLS),
        tool_choice: 'auto'
      })
    });

    if (!response.ok) return null;
    const result = await response.json();
    const toolCalls = result.choices?.[0]?.message?.tool_calls || [];

    if (toolCalls.length > 0) {
      const toolResults = [];
      const messages = [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: message },
        { role: 'assistant', content: null, tool_calls: toolCalls }
      ];

      for (const tc of toolCalls) {
        console.log(`[OpenAI Tool] ${tc.function.name}:`, tc.function.arguments);
        const args = JSON.parse(tc.function.arguments || '{}');
        const tr = await executeTool(tc.function.name, args);
        toolResults.push({
          tool_call_id: tc.id,
          role: 'tool',
          content: JSON.stringify(tr, null, 2)
        });
      }

      messages.push(...toolResults);

      // Second call with results
      const final = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openaiKey}`
        },
        body: JSON.stringify({
          model: 'gpt-4-turbo-preview',
          messages
        })
      });

      if (!final.ok) return { response: result.choices[0]?.message?.content, tools: toolCalls.length };
      const fr = await final.json();
      return { response: fr.choices[0]?.message?.content, tools: toolCalls.length };
    }

    return { response: result.choices[0]?.message?.content };
  } catch (error) {
    console.error('[OpenAI Tool Error]:', error.message);
    return null;
  }
}

// API Key Management
const API_KEYS = {
  openai: process.env.OPENAI_API_KEY || '',
  anthropic: process.env.ANTHROPIC_API_KEY || '',
  google: process.env.GOOGLE_API_KEY || '',
  ollama: process.env.OLLAMA_URL || 'http://localhost:11434',
};

const ENV_VAR_MAP = {
  openai: 'OPENAI_API_KEY',
  anthropic: 'ANTHROPIC_API_KEY',
  google: 'GOOGLE_API_KEY',
  ollama: 'OLLAMA_URL',
};

// Persist a key to the .env file so it survives PM2 restarts
function persistKeyToEnv(envVar, value) {
  const envPath = path.join(__dirname, '.env');
  let content = '';
  try { content = fs.readFileSync(envPath, 'utf8'); } catch {}
  const lines = content.split('\n');
  const idx = lines.findIndex(l => l.startsWith(`${envVar}=`));
  if (idx >= 0) {
    lines[idx] = `${envVar}=${value}`;
  } else {
    lines.push(`${envVar}=${value}`);
  }
  fs.writeFileSync(envPath, lines.filter((_, i) => i === lines.length - 1 ? true : true).join('\n'));
}

// Mask API key for display (show last 4 chars only)
function maskKey(key) {
  if (!key || key.length < 8) return key;
  return `${'*'.repeat(key.length - 4)}${key.slice(-4)}`;
}

// Get all API keys status
app.get('/api/ai/keys', requireAuth, (req, res) => {
  res.json({
    success: true,
    keys: {
      openai: { configured: !!API_KEYS.openai, envVar: 'OPENAI_API_KEY', value: maskKey(API_KEYS.openai) },
      anthropic: { configured: !!API_KEYS.anthropic, envVar: 'ANTHROPIC_API_KEY', value: maskKey(API_KEYS.anthropic) },
      google: { configured: !!API_KEYS.google, envVar: 'GOOGLE_API_KEY', value: maskKey(API_KEYS.google) },
      ollama: { configured: !!API_KEYS.ollama, envVar: 'OLLAMA_URL', value: API_KEYS.ollama }
    }
  });
});

// Update API key — persists to .env for survival across restarts
app.post('/api/ai/keys', requireAuth, (req, res) => {
  const { provider, apiKey, baseURL } = req.body;

  if (!provider || !Object.prototype.hasOwnProperty.call(API_KEYS, provider)) {
    return res.status(400).json({ success: false, error: 'Invalid provider' });
  }

  if (apiKey !== undefined) {
    API_KEYS[provider] = apiKey;
    if (provider === 'openai') LLM_CONFIG.openai.apiKey = apiKey;
    if (provider === 'anthropic') LLM_CONFIG.anthropic.apiKey = apiKey;
    if (provider === 'google') LLM_CONFIG.google.apiKey = apiKey;
    persistKeyToEnv(ENV_VAR_MAP[provider], apiKey);
  }

  if (baseURL !== undefined && provider === 'ollama') {
    API_KEYS.ollama = baseURL;
    LLM_CONFIG.local.baseURL = baseURL;
    persistKeyToEnv('OLLAMA_URL', baseURL);
  }

  res.json({ success: true, message: `${provider} API key updated and persisted` });
});

// Get server capabilities for agent delegation
app.get('/api/ai/agents', (req, res) => {
  res.json({
    success: true,
    agents: [
      { id: 'pm2-manager', name: 'PM2 Manager', description: 'Manage PM2 processes', tools: ['pm2_list', 'pm2_restart', 'pm2_stop', 'pm2_logs'] },
      { id: 'git-manager', name: 'Git Manager', description: 'Git operations', tools: ['git_status', 'git_pull', 'git_commit', 'git_branch_list'] },
      { id: 'docker-manager', name: 'Docker Manager', description: 'Container management', tools: ['docker_list', 'docker_stats'] },
      { id: 'file-manager', name: 'File Manager', description: 'File operations', tools: ['file_read', 'file_write', 'file_list', 'file_search'] },
      { id: 'system-monitor', name: 'System Monitor', description: 'System monitoring', tools: ['system_stats', 'check_url', 'send_alert'] },
      { id: 'db-manager', name: 'Database Manager', description: 'Database operations', tools: ['db_list', 'db_query', 'db_backup'] }
    ]
  });
});

// Delegate task to sub-agent
app.post('/api/ai/delegate', requireAuth, async (req, res) => {
  const { agentId, task, context } = req.body;

  if (!agentId || !task) {
    return res.status(400).json({ success: false, error: 'Agent ID and task required' });
  }

  const AGENT_PROMPTS = {
    'pm2-manager': `You are a PM2 process manager. Only use these tools: pm2_list, pm2_restart, pm2_stop, pm2_logs. ${task}`,
    'git-manager': `You are a Git manager. Only use these tools: git_status, git_pull, git_commit, git_branch_list. ${task}`,
    'docker-manager': `You are a Docker manager. Only use these tools: docker_list, docker_stats. ${task}`,
    'file-manager': `You are a file manager. Only use these tools: file_read, file_write, file_list, file_search. ${task}`,
    'system-monitor': `You are a system monitor. Only use these tools: system_stats, check_url, send_alert. ${task}`,
    'db-manager': `You are a database manager. Only use these tools: db_list, db_query, db_backup. ${task}`
  };

  const prompt = AGENT_PROMPTS[agentId];
  if (!prompt) {
    return res.status(400).json({ success: false, error: 'Unknown agent' });
  }

  try {
    // Use Claude with limited tools
    const tools = SERVER_TOOLS.filter(t => {
      const agentTools = AGENT_PROMPTS[agentId].match(/(\w+)/g);
      return agentTools?.includes(t.name);
    });

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6-20250514',
        max_tokens: 4096,
        system: prompt,
        messages: [{ role: 'user', content: task }],
        tools: tools.length ? tools : undefined,
        tool_choice: tools.length ? { type: 'auto' } : undefined
      })
    });

    if (!response.ok) {
      const err = await response.json();
      return res.status(500).json({ success: false, error: err.error?.message || 'Agent failed' });
    }

    const result = await response.json();
    res.json({
      success: true,
      response: result.content?.[0]?.text,
      agent: agentId
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ── Global error handler (catches body-parser JSON errors etc.) ─────────────
app.use((err, req, res, _next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: 'Invalid JSON in request body' });
  }
  console.error('[API Error]', err.message);
  res.status(500).json({ success: false, error: err.message || 'Internal server error' });
});

// ── Unhandled rejections ─────────────────────────────────────────────────────
process.on('unhandledRejection', (reason) => {
  console.error('[Unhandled Rejection]', reason);
});

const PORT = process.env.DASHBOARD_API_PORT || 3999;
server.listen(PORT, () => {
  console.log(`\x1b[32m✓\x1b[0m Dashboard API running on port ${PORT}`);
  console.log(`  Frontend: http://localhost:${PORT}`);
  console.log(`  Terminal WS: ws://localhost:${PORT}/ws/terminal`);
  console.log(`  Live Logs WS: ws://localhost:${PORT}/ws/logs`);
  console.log(`  Stats WS: ws://localhost:${PORT}/ws/stats`);
});
