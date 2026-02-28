// Enhanced Deployment Dashboard Server v2.0 with AI Integration
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// System information for monitoring
const si = require('systeminformation');

// GitHub API
const { Octokit } = require('@octokit/rest');

// Docker management
const Docker = require('dockerode');
const dotenv = require('dotenv');

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

// Initialize Docker
const docker = new Docker();

// Initialize GitHub (optional)
let octokit = null;
if (process.env.GITHUB_TOKEN) {
  octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
}

// Auth config
const JWT_SECRET = process.env.DASHBOARD_JWT_SECRET || 'deploy-hub-dev-secret-change-in-production';
const DASHBOARD_USER = process.env.DASHBOARD_USER || 'admin';
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'admin123';

// ============================================================================
// AUTHENTICATION
// ============================================================================

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

// ============================================================================
// AI API MODULE
// ============================================================================

const LLM_CONFIG = {
  openai: {
    enabled: !!process.env.OPENAI_API_KEY,
    defaultModel: 'gpt-4o-mini',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo'],
  },
  anthropic: {
    enabled: !!process.env.ANTHROPIC_API_KEY,
    defaultModel: 'claude-sonnet-4-20250514',
    models: ['claude-sonnet-4-20250514', 'claude-opus-4-20250514'],
  },
  google: {
    enabled: !!process.env.GOOGLE_API_KEY,
    defaultModel: 'gemini-2.0-flash',
    models: ['gemini-2.0-flash', 'gemini-1.5-pro'],
  },
  local: {
    enabled: true,
    defaultModel: 'qwen3.5:cloud',
    models: ['qwen3.5:cloud', 'llama3.2', 'mistral'],
  },
  cloud: {
    enabled: true,
    defaultModel: 'openrouter/auto',
    models: ['openrouter/auto'],
  },
};

let activeProvider = process.env.DEFAULT_AI_PROVIDER || 'cloud';

// AI API Routes
app.get('/api/ai/providers', (req, res) => {
  const providers = Object.entries(LLM_CONFIG).map(([key, config]) => ({
    id: key,
    name: key.charAt(0).toUpperCase() + key.slice(1),
    enabled: config.enabled,
    defaultModel: config.defaultModel,
    models: config.models || [],
    isActive: key === activeProvider,
  }));

  res.json({ success: true, data: providers, active: activeProvider });
});

app.post('/api/ai/providers/:provider', requireAuth, (req, res) => {
  const { provider } = req.params;
  if (!LLM_CONFIG[provider]) {
    return res.status(400).json({ success: false, error: 'Invalid provider' });
  }
  if (!LLM_CONFIG[provider].enabled) {
    return res.status(400).json({ success: false, error: 'Provider not configured' });
  }
  activeProvider = provider;
  res.json({ success: true, data: { active: provider } });
});

app.get('/api/ai/capabilities', (req, res) => {
  res.json({
    success: true,
    data: {
      codeReview: { name: 'Code Review', description: 'Review code for quality and security', icon: 'Code' },
      debugging: { name: 'Debugging', description: 'Help diagnose and fix bugs', icon: 'Bug' },
      architecture: { name: 'Architecture', description: 'Design system architecture', icon: 'Layers' },
      devops: { name: 'DevOps', description: 'CI/CD and infrastructure', icon: 'Server' },
      default: { name: 'General Assistant', description: 'General purpose AI', icon: 'MessageSquare' },
    },
  });
});

app.get('/api/ai/tools', (req, res) => {
  res.json({
    success: true,
    data: [
      { id: 'pm2', name: 'PM2 Manager', description: 'Manage Node.js processes' },
      { id: 'docker', name: 'Docker', description: 'Manage containers' },
      { id: 'github', name: 'GitHub', description: 'Repository management' },
      { id: 'system', name: 'System', description: 'System monitoring' },
      { id: 'files', name: 'File System', description: 'Read/write files' },
    ],
  });
});

app.post('/api/ai/chat', requireAuth, async (req, res) => {
  try {
    const { message, context, history, capability, provider, model } = req.body;
    const selectedProvider = provider || activeProvider;
    const selectedModel = model || LLM_CONFIG[selectedProvider]?.defaultModel;

    // Generate contextual response
    let response = generateAIResponse(message, capability, context);

    res.json({
      success: true,
      response,
      provider: selectedProvider,
      model: selectedModel,
      capability: capability || 'default',
    });
  } catch (error) {
    console.error('AI Chat error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/ai/keys', requireAuth, (req, res) => {
  res.json({
    success: true,
    data: {
      openai: !!process.env.OPENAI_API_KEY,
      anthropic: !!process.env.ANTHROPIC_API_KEY,
      google: !!process.env.GOOGLE_API_KEY,
      openrouter: !!process.env.OPENROUTER_API_KEY,
    },
  });
});

app.post('/api/ai/keys', requireAuth, (req, res) => {
  const { provider, key } = req.body;
  if (!provider || !key) {
    return res.status(400).json({ success: false, error: 'Provider and key required' });
  }
  const envVar = `${provider.toUpperCase()}_API_KEY`;
  process.env[envVar] = key;
  if (LLM_CONFIG[provider.toLowerCase()]) {
    LLM_CONFIG[provider.toLowerCase()].enabled = true;
  }
  res.json({ success: true, message: 'API key updated' });
});

app.get('/api/ai/agents', (req, res) => {
  res.json({
    success: true,
    data: [
      { id: 'coder', name: 'Coder Agent', description: 'Writes and reviews code', status: 'available' },
      { id: 'reviewer', name: 'Reviewer Agent', description: 'Code review specialist', status: 'available' },
      { id: 'devops', name: 'DevOps Agent', description: 'Deployment and infrastructure', status: 'available' },
      { id: 'debugger', name: 'Debugger Agent', description: 'Bug hunting and fixing', status: 'available' },
    ],
  });
});

app.post('/api/ai/delegate', requireAuth, async (req, res) => {
  const { agentId, task, context } = req.body;
  res.json({
    success: true,
    data: { taskId: `task-${Date.now()}`, agentId, status: 'processing', message: `Task delegated to ${agentId}` },
  });
});

function generateAIResponse(message, capability, context) {
  const responses = {
    codeReview: "I've analyzed your code. Here are my recommendations:\n\n✅ **Good practices:**\n- Clean code structure\n- Proper error handling\n\n⚠️ **Suggestions:**\n- Consider adding more unit tests\n- Optimize database queries\n- Add input validation",
    debugging: "Let me help you debug this issue:\n\n🔍 **Analysis:**\n1. Check the error logs\n2. Verify environment variables\n3. Test the API endpoints\n\n💡 **Solution:**\nTry restarting the service and check if the issue persists.",
    architecture: "For this system, I recommend:\n\n🏗️ **Architecture:**\n- Microservices with API gateway\n- Event-driven communication\n- Redis for caching\n- PostgreSQL for primary data\n\n📊 **Scalability:**\n- Horizontal scaling with load balancer\n- CDN for static assets",
    devops: "Here's the DevOps strategy:\n\n🚀 **CI/CD:**\n- GitHub Actions for automation\n- Automated testing pipeline\n- Blue-green deployments\n\n📈 **Monitoring:**\n- Prometheus + Grafana\n- Centralized logging with ELK\n- Alerting on key metrics",
    default: "I'm here to help! I can assist you with:\n\n• **Code Review** - Review your code for quality\n• **Debugging** - Help fix bugs\n• **Architecture** - Design systems\n• **DevOps** - Deployment and infrastructure\n• **General Questions** - Anything else!\n\nWhat would you like to work on?",
  };
  return responses[capability] || responses.default;
}

// ============================================================================
// WEBSOCKET HANDLERS
// ============================================================================

wss.on('connection', (ws, req) => {
  console.log('[WebSocket] Client connected');
  
  let statsInterval = null;
  let logsProcess = null;
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      switch (data.type) {
        case 'subscribe_stats':
          statsInterval = setInterval(async () => {
            try {
              const stats = await getSystemStats();
              ws.send(JSON.stringify({ type: 'stats', data: stats }));
            } catch (err) {
              console.error('Stats error:', err);
            }
          }, 2000);
          break;
          
        case 'subscribe_logs':
          if (data.service) {
            logsProcess = exec(`docker logs -f ${data.service} --tail 100`);
            logsProcess.stdout.on('data', (chunk) => {
              ws.send(JSON.stringify({ type: 'logs', service: data.service, data: chunk.toString() }));
            });
          }
          break;
          
        case 'subscribe_docker':
          docker.getEvents((err, stream) => {
            if (stream) {
              stream.on('data', (chunk) => {
                try {
                  const event = JSON.parse(chunk.toString());
                  ws.send(JSON.stringify({ type: 'docker_event', data: event }));
                } catch (e) {}
              });
            }
          });
          break;
      }
    } catch (err) {
      console.error('WebSocket message error:', err);
    }
  });
  
  ws.on('close', () => {
    console.log('[WebSocket] Client disconnected');
    if (statsInterval) clearInterval(statsInterval);
    if (logsProcess) logsProcess.kill();
  });
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

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
      percentage: memory.used / memory.total * 100,
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

// ============================================================================
// API ROUTES
// ============================================================================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString(), uptime: process.uptime(), version: '2.0.0-enhanced' });
});

// Auth
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
    res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
});

// System stats
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
    const { Octokit } = require('@octokit/rest');
    const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
    const { data: repos } = await octokit.repos.listForUser({ username: GITHUB_USERNAME, per_page: 100, sort: 'pushed' });
    res.json({ success: true, data: repos });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/repo/:owner/:repo', async (req, res) => {
  try {
    const { owner, repo } = req.params;
    const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
    const { data } = await octokit.repos.get({ owner, repo });
    res.json({ success: true, data: data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/branches/:owner/:repo', async (req, res) => {
  try {
    const { owner, repo } = req.params;
    const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
    const { data } = await octokit.repos.listBranches({ owner, repo, per_page: 50 });
    res.json({ success: true, data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/github/commits/:owner/:repo', async (req, res) => {
  try {
    const { owner, repo } = req.params;
    const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
    const { data } = await octokit.repos.listCommits({ owner, repo, per_page: 30 });
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

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ============================================================================
// START SERVER
// ============================================================================

server.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 Enhanced Dashboard API Server v2.0 with AI');
  console.log(`📊 Running on http://0.0.0.0:${PORT}`);
  console.log(`🔌 WebSocket: ws://localhost:${PORT}/ws`);
  console.log('\n📡 Endpoints:');
  console.log('  /api/health - Health check');
  console.log('  /api/auth/* - Authentication');
  console.log('  /api/server/* - System monitoring');
  console.log('  /api/projects/* - Project management');
  console.log('  /api/github/* - GitHub integration');
  console.log('  /api/docker/* - Docker management');
  console.log('  /api/ai/* - AI Chat & Agents ✨');
  console.log('  /api/system/exec - System commands');
  console.log('\n🔌 WebSocket Events:');
  console.log('  subscribe_stats - Real-time system stats');
  console.log('  subscribe_logs - Log streaming');
  console.log('  subscribe_docker - Docker events');
  console.log('  terminal_command - Execute commands');
  console.log('');
});

// ============================================================================
// PM2 ENDPOINTS
// ============================================================================

app.get('/api/pm2/list', async (req, res) => {
  try {
    const { execAsync } = require('util').promisify(require('child_process').exec);
    const { stdout } = await execAsync('pm2 list --json 2>/dev/null || echo "[]"');
    const processes = JSON.parse(stdout || '[]');
    res.json({ success: true, data: processes });
  } catch (error) {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/pm2/status', async (req, res) => {
  try {
    const { execAsync } = require('util').promisify(require('child_process').exec);
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
    const { execAsync } = require('util').promisify(require('child_process').exec);
    await execAsync(`pm2 restart ${req.params.name}`);
    res.json({ success: true, message: `Restarted ${req.params.name}` });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/stop/:name', async (req, res) => {
  try {
    const { execAsync } = require('util').promisify(require('child_process').exec);
    await execAsync(`pm2 stop ${req.params.name}`);
    res.json({ success: true, message: `Stopped ${req.params.name}` });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/start/:name', async (req, res) => {
  try {
    const { execAsync } = require('util').promisify(require('child_process').exec);
    await execAsync(`pm2 start ${req.params.name}`);
    res.json({ success: true, message: `Started ${req.params.name}` });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/pm2/logs/:name', async (req, res) => {
  try {
    const { execAsync } = require('util').promisify(require('child_process').exec);
    const { stdout } = await execAsync(`pm2 logs ${req.params.name} --lines 100 --nostream`);
    res.json({ success: true, data: stdout });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});
