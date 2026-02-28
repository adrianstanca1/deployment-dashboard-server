// Enhanced Deployment Dashboard Server v3.0 - Full AI Integration
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const si = require('systeminformation');
const { Octokit } = require('@octokit/rest');
const Docker = require('dockerode');
const dotenv = require('dotenv');

// Import enhanced AI module
const { setupEnhancedAI } = require('./ai-enhanced.js');

dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3999;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// WebSocket server
const wss = new WebSocket.Server({ server, path: '/ws' });
const docker = new Docker();

let octokit = null;
if (process.env.GITHUB_TOKEN) {
  octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
}

// Auth config
const JWT_SECRET = process.env.DASHBOARD_JWT_SECRET || 'deploy-hub-dev-secret-change-in-production';
const DASHBOARD_USER = process.env.DASHBOARD_USER || 'admin';
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'admin123';

// Auth middleware
const requireAuth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
};

// Setup Enhanced AI API
setupEnhancedAI(app, requireAuth);

// WebSocket handlers
wss.on('connection', (ws) => {
  console.log('[WebSocket] Client connected');
  let statsInterval = null;
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'subscribe_stats') {
        statsInterval = setInterval(async () => {
          const stats = await getSystemStats();
          ws.send(JSON.stringify({ type: 'stats', data: stats }));
        }, 2000);
      }
    } catch (err) {
      console.error('WS error:', err);
    }
  });
  
  ws.on('close', () => {
    if (statsInterval) clearInterval(statsInterval);
  });
});

// System stats helper
async function getSystemStats() {
  const [cpu, memory, disk, osInfo] = await Promise.all([
    si.currentLoad(),
    si.mem(),
    si.fsSize(),
    si.osInfo(),
  ]);
  return {
    cpu: { usage: cpu.currentLoad.toFixed(1), cores: cpu.cpus.length },
    memory: {
      total: (memory.total / 1024 / 1024 / 1024).toFixed(1),
      used: (memory.used / 1024 / 1024 / 1024).toFixed(1),
      percentage: (memory.used / memory.total * 100).toFixed(1),
    },
    disk: disk[0] ? {
      total: (disk[0].size / 1024 / 1024 / 1024).toFixed(0),
      used: (disk[0].used / 1024 / 1024 / 1024).toFixed(0),
      percentage: disk[0].use,
    } : null,
    os: { platform: osInfo.platform, distro: osInfo.distro },
    uptime: osInfo.uptime,
  };
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString(), uptime: process.uptime(), version: '3.0.0-enhanced' });
});

// Auth endpoints
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (username === DASHBOARD_USER && password === DASHBOARD_PASSWORD) {
    const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ success: true, token, user: { username, role: 'admin' } });
  }
  res.status(401).json({ success: false, error: 'Invalid credentials' });
});

app.get('/api/auth/me', (req, res) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ success: false });
  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ success: true, user: decoded });
  } catch (error) {
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
});

// Server stats
app.get('/api/server/stats', async (req, res) => {
  try {
    const stats = await getSystemStats();
    res.json({ success: true, data: stats });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/server/processes', async (req, res) => {
  try {
    const { stdout } = await execAsync('ps aux | head -20');
    res.json({ success: true, data: stdout });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/server/info', async (req, res) => {
  try {
    const osInfo = await si.osInfo();
    res.json({ success: true, data: { platform: osInfo.platform, distro: osInfo.distro, uptime: osInfo.uptime } });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Projects
app.get('/api/projects', async (req, res) => {
  try {
    const { stdout } = await execAsync('ls -1 /var/www 2>/dev/null || echo ""');
    const projects = stdout.trim().split('\n').filter(Boolean).map(name => ({ name, port: Math.floor(3000 + Math.random() * 1000) }));
    res.json({ success: true, data: projects });
  } catch (error) {
    res.json({ success: true, data: [] });
  }
});

app.post('/api/projects/:name/deploy', async (req, res) => {
  const { name } = req.params;
  const { port } = req.body;
  res.json({ success: true, message: `Deploying ${name} on port ${port || 'auto'}` });
});

// GitHub
app.get('/api/github/repos', async (req, res) => {
  try {
    const GITHUB_USERNAME = process.env.DASHBOARD_GITHUB_USER || 'adrianstanca1';
    const gh = new Octokit({ auth: process.env.GITHUB_TOKEN });
    const { data: repos } = await gh.repos.listForUser({ username: GITHUB_USERNAME, per_page: 100, sort: 'pushed' });
    res.json({ success: true, data: repos });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/repo/:owner/:repo', async (req, res) => {
  try {
    const { owner, repo } = req.params;
    const gh = new Octokit({ auth: process.env.GITHUB_TOKEN });
    const { data } = await gh.repos.get({ owner, repo });
    res.json({ success: true, data: data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/branches/:owner/:repo', async (req, res) => {
  try {
    const { owner, repo } = req.params;
    const gh = new Octokit({ auth: process.env.GITHUB_TOKEN });
    const { data } = await gh.repos.listBranches({ owner, repo, per_page: 50 });
    res.json({ success: true, data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/commits/:owner/:repo', async (req, res) => {
  try {
    const { owner, repo } = req.params;
    const gh = new Octokit({ auth: process.env.GITHUB_TOKEN });
    const { data } = await gh.repos.listCommits({ owner, repo, per_page: 30 });
    res.json({ success: true, data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/github/deploy', async (req, res) => {
  const { repoUrl, branch = 'main' } = req.body;
  res.json({ success: true, message: `Deploying ${repoUrl} from ${branch}` });
});

// Docker
app.get('/api/docker/containers', async (req, res) => {
  try {
    const containers = await docker.listContainers({ all: true });
    res.json({ success: true, data: containers });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/docker/images', async (req, res) => {
  try {
    const images = await docker.listImages();
    res.json({ success: true, data: images });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/docker/containers/:id/start', async (req, res) => {
  try {
    const container = docker.getContainer(req.params.id);
    await container.start();
    res.json({ success: true, message: 'Container started' });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/docker/containers/:id/stop', async (req, res) => {
  try {
    const container = docker.getContainer(req.params.id);
    await container.stop();
    res.json({ success: true, message: 'Container stopped' });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/docker/containers/:id/restart', async (req, res) => {
  try {
    const container = docker.getContainer(req.params.id);
    await container.restart();
    res.json({ success: true, message: 'Container restarted' });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/docker/containers/:id/logs', async (req, res) => {
  try {
    const container = docker.getContainer(req.params.id);
    const logs = await container.logs({ stdout: true, stderr: true, tail: 100 });
    res.json({ success: true, data: logs.toString('utf8') });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/docker/containers/:id/stats', async (req, res) => {
  try {
    const container = docker.getContainer(req.params.id);
    const stats = await container.stats({ stream: false });
    res.json({ success: true, data: stats });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// PM2
app.get('/api/pm2/list', async (req, res) => {
  try {
    const { stdout } = await execAsync('pm2 list --json 2>/dev/null || echo "[]"');
    const processes = JSON.parse(stdout || '[]');
    res.json({ success: true, data: processes });
  } catch (error) {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/pm2/status', async (req, res) => {
  try {
    const { stdout } = await execAsync('pm2 list --json 2>/dev/null || echo "[]"');
    const processes = JSON.parse(stdout || '[]');
    res.json({
      success: true,
      data: {
        total: processes.length,
        online: processes.filter(p => p.status === 'online').length,
        errored: processes.filter(p => p.status === 'errored').length,
        stopped: processes.filter(p => p.status === 'stopped').length,
      },
    });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/restart/:name', async (req, res) => {
  try {
    await execAsync(`pm2 restart ${req.params.name}`);
    res.json({ success: true, message: `Restarted ${req.params.name}` });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/stop/:name', async (req, res) => {
  try {
    await execAsync(`pm2 stop ${req.params.name}`);
    res.json({ success: true, message: `Stopped ${req.params.name}` });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/start/:name', async (req, res) => {
  try {
    await execAsync(`pm2 start ${req.params.name}`);
    res.json({ success: true, message: `Started ${req.params.name}` });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/pm2/logs/:name', async (req, res) => {
  try {
    const { stdout } = await execAsync(`pm2 logs ${req.params.name} --lines 100 --nostream`);
    res.json({ success: true, data: stdout });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// System commands
app.post('/api/system/exec', async (req, res) => {
  const { command } = req.body;
  const allowed = ['ls', 'pwd', 'whoami', 'uptime', 'free', 'df', 'top', 'ps', 'docker', 'git', 'npm', 'node'];
  const baseCommand = command.split(' ')[0];
  if (!allowed.includes(baseCommand)) {
    return res.status(403).json({ success: false, error: 'Command not allowed' });
  }
  try {
    const { stdout, stderr } = await execAsync(command);
    res.json({ success: true, stdout, stderr });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 Deployment Dashboard Server v3.0 with Full AI');
  console.log(`📊 Running on http://0.0.0.0:${PORT}`);
  console.log(`🔌 WebSocket: ws://localhost:${PORT}/ws`);
  console.log('\n📡 API Endpoints:');
  console.log('  /api/health - Health check');
  console.log('  /api/auth/* - Authentication');
  console.log('  /api/server/* - System monitoring');
  console.log('  /api/projects/* - Project management');
  console.log('  /api/github/* - GitHub integration');
  console.log('  /api/docker/* - Docker management');
  console.log('  /api/pm2/* - PM2 process manager');
  console.log('  /api/ai/* - AI Chat, Agents, Tools ✨');
  console.log('  /api/system/exec - System commands');
  console.log('\n🤖 AI Features:');
  console.log('  - 5 LLM Providers (Local, OpenAI, Anthropic, Google, OpenRouter)');
  console.log('  - Real-time AI Chat with context');
  console.log('  - 4 Specialized Agents');
  console.log('  - 5 AI Tools');
  console.log('  - 5 Capabilities (Code Review, Debugging, Architecture, DevOps, General)');
  console.log('');
});
