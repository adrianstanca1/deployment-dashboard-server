# Database Queries and Data Persistence Analysis

**Generated:** 2026-02-26
**Scope:** `/root/deployment-dashboard-server`

---

## Overview

This document catalogs all database queries and data persistence patterns in the Deploy Hub Dashboard server.

## Data Storage Architecture

The application uses a **file-based persistence strategy** with no external databases. All persistent data is stored in JSON files, while runtime state is maintained in JavaScript Maps and Arrays.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        IN-MEMORY STATE                              │
├─────────────────────────┬─────────────────┬───────────────────────┤
│  nginxPortPathCache     │  scheduledTasks │  lastProcessStates    │
│  (Map)                  │  (Map)          │  (Map)                │
│  60s TTL                │                 │                       │
├─────────────────────────┴─────────────────┴───────────────────────┤
│                     quickActionsHistory (Array)                     │
│                     terminalSessions (Map)                          │
└─────────────────────────────────────────────────────────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
┌────────────────────┐  ┌────────────────────┐  ┌──────────────────┐
│ .dashboard-        │  │ .scheduled-        │  │ External APIs    │
│ settings.json      │  │ tasks.json         │  │                  │
│                    │  │                    │  │ PM2 (JSON)       │
│ Security settings  │  │ Cron definitions   │  │ GitHub (REST)    │
│ General config     │  │ Task configs       │  │ Docker (CLI)     │
│ Integration tokens │  │                    │  │ Git (CLI)        │
└────────────────────┘  └────────────────────┘  │ System (proc)    │
                                                  └──────────────────┘
```

---

## Persistent JSON Files

### 1. Settings File (`.dashboard-settings.json`)

**Location:** `/root/deployment-dashboard-server/.dashboard-settings.json`

**Schema:**
```json
{
  "security": { "dashboardUser": "string" },
  "general": { "allowDirectPortUrls": "boolean" },
  "_lastModified": "ISO8601 timestamp",
  "_modifiedBy": "username",
  "_version": "integer"
}
```

**Read Operation:**
```javascript
// server.js:2326-2327
if (fs.existsSync(SETTINGS_FILE)) {
  runtimeSettings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
}
```

**Write Operation:**
```javascript
// Lines 2348-2349
fs.writeFileSync(SETTINGS_FILE, JSON.stringify(runtimeSettings, null, 2));
try { fs.chmodSync(SETTINGS_FILE, 0o600); } catch {}
```

**Update Pattern:**
- Partial updates via `saveSettings(patch, user)` function
- Automatic versioning: `_version` incremented on each save
- Metadata tracking: `_lastModified`, `_modifiedBy`

---

### 2. Scheduled Tasks File (`.scheduled-tasks.json`)

**Location:** `/root/deployment-dashboard-server/.scheduled-tasks.json`

**Schema:**
```json
{
  "tasks": [
    {
      "id": "string",
      "name": "string",
      "actionType": "string",
      "actionConfig": "object",
      "cronExpression": "string",
      "enabled": "boolean",
      "createdAt": "ISO8601 timestamp",
      "lastRun": "ISO8601 timestamp|null",
      "runCount": "integer"
    }
  ]
}
```

**Read Operation:**
```javascript
// Lines 2379-2380
if (fs.existsSync(SCHEDULED_TASKS_FILE)) {
  const data = JSON.parse(fs.readFileSync(SCHEDULED_TASKS_FILE, 'utf8'));
```

**Write Operation:**
```javascript
// Line 2407
fs.writeFileSync(SCHEDULED_TASKS_FILE, JSON.stringify({ tasks }, null, 2));
```

**Data Transformation:**
- Converts `Map` to `Array` for serialization: `Array.from(scheduledTasks.values())`
- Maps internal task objects to serializable format

---

## In-Memory Data Structures

### Runtime State Maps

| Variable | Type | Purpose | Location |
|----------|------|---------|----------|
| `nginxPortPathCache` | `Map` | Port-to-path nginx mappings cache | server.js:50,84 |
| `loginAttempts` | `Map` | Rate limiting per IP address | server.js:119 |
| `lastProcessStates` | `Map` | PM2 process status tracking | server.js:1761 |
| `terminalSessions` | `Map` | Active PTY terminal sessions | server.js:1798 |
| `quickActionsHistory` | `Array[]` | Last 1000 action execution logs | server.js:2316 |
| `scheduledTasks` | `Map` | Runtime scheduled task instances | server.js:2317 |

---

## File System Operations by Category

### A. Nginx Configuration Parsing

**Location:** `server.js:58-87`

**Purpose:** Parse `/etc/nginx/sites-available/apps.conf` for port-to-path mappings

**Pattern:**
```javascript
if (fs.existsSync(nginxConfigPath)) {
  const content = fs.readFileSync(nginxConfigPath, 'utf8');
  const locationRegex = /location\s+\/([^/\s]+)\/\s*\{[\s\S]*?proxy_pass\s+http:\/\/127\.0\.0\.1:(\d+)\//g;
  // Parse using regex
}
```

**Caching Strategy:**
- 60-second TTL cache (`NGINX_CACHE_TTL = 60_000`)
- Stored in `nginxPortPathCache` Map

---

### B. Application Discovery

**Location:** `server.js:914-945`

**Base Path:** `/var/www`

**Operations:**
```javascript
if (fs.existsSync(pkgPath)) packageJson = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
if (fs.existsSync(envPath)) {
  const match = fs.readFileSync(envPath, 'utf8').match(/^PORT=(\d+)/m);
}
```

---

### C. File Manager Operations

**Location:** `server.js:953-1200`

**Upload Configuration (Multer):**
```javascript
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
```

**CRUD Operations:**

| Operation | Function | Method |
|-----------|----------|--------|
| Browse | `fsp.readdir()`, `fsp.stat()` | server.js:1004-1026 |
| Upload | `upload.array('files')` middleware | server.js:1046 |
| Create | `fsp.mkdir()`, `fsp.writeFile()` | server.js:1076-1119 |
| Delete | `fsp.rm()` recursive | server.js:1120-1159 |
| Download | `res.download()` | server.js:1160-1199 |
| Edit | `fsp.readFile()`, `fsp.writeFile()` | server.js:1201-1243 |

---

### D. Quick Actions History

**Location:** `server.js:2413-2426`

**Write Pattern (In-Memory Only):**
```javascript
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
```

---

## External Data Sources

### A. PM2 Process Data

**Query Pattern:**
```javascript
// server.js:250
const { stdout } = await execAsync('pm2 jlist');
const processes = JSON.parse(stdout);
```

**Operations:**
- List: `pm2 jlist` (JSON output)
- Logs: `pm2 logs ${name} --lines ${lines} --nostream`
- Actions: `pm2 ${action} "${name}"`
- Save: `pm2 save`

---

### B. GitHub API

**Authentication:**
```javascript
const GITHUB_AUTH = process.env.GITHUB_TOKEN
  ? `-H "Authorization: Bearer ${process.env.GITHUB_TOKEN}"`
  : '';
```

**Query Patterns:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/user/repos` | GET | List repositories |
| `/repos/{user}/{repo}/commits` | GET | Get commits |
| `/repos/{user}/{repo}/branches` | GET | List branches |
| `/repos/{user}/{repo}/issues` | GET/POST | List/Create issues |
| `/repos/{user}/{repo}/pulls` | GET/POST | List/Create PRs |
| `/repos/{user}/{repo}/releases` | GET | List releases |
| `/repos/{user}/{repo}/actions/runs` | GET | List workflow runs |

---

### C. Docker Operations

**Read Operations:**
- `docker ps -a --format`
- `docker images --format`
- `docker volume ls --format`
- `docker network ls --format`
- `docker inspect ${id}`
- `docker stats ${id} --no-stream --format`

**Write Operations:**
- `docker start/stop/restart/pause/unpause ${id}`
- `docker rm -f ${id}`
- `docker volume rm "${name}"`
- `docker pull ${image}`
- `docker run`
- `docker prune`

---

### D. Git Operations

**Read:**
- `git status --short`
- `git rev-parse --abbrev-ref HEAD`
- `git log -1 --format="%h|%s|%ar"`

**Write:**
- `git pull`
- `git clone --branch ${branch} --depth 1`

---

### E. System Operations

**Read Commands:**
- `free -b | awk 'NR==2{print $2,$3,$4}'`
- `df -B1 / | awk 'NR==2{print $2,$3,$4}'`
- `cat /proc/uptime`
- `cat /proc/loadavg`
- `cat /proc/stat`
- `nproc`
- `ip -4 addr show`
- `ss -tlnp`

---

## Query Patterns Summary

### Read Patterns:

1. **File existence check:**
   ```javascript
   fs.existsSync(path)
   ```

2. **JSON parsing:**
   ```javascript
   JSON.parse(fs.readFileSync(path, 'utf8'))
   ```

3. **Text parsing:**
   ```javascript
   fs.readFileSync(path, 'utf8')
   ```

4. **Async streaming:**
   ```javascript
   spawn('tail', args)
   ```

5. **HTTP API:**
   ```javascript
   curl via execAsync
   ```

### Write Patterns:

1. **Atomic JSON write:**
   ```javascript
   fs.writeFileSync(path, JSON.stringify(data, null, 2))
   ```

2. **Permission setting:**
   ```javascript
   fs.chmodSync(path, 0o600)
   ```

3. **Streaming:**
   ```javascript
   pty.spawn(), spawn()
   ```

---

## Environment Variable Dependencies

| Variable | Purpose | Default |
|----------|---------|---------|
| `DASHBOARD_JWT_SECRET` | JWT signing secret | `'deploy-hub-dev-secret-change-in-production'` |
| `DASHBOARD_USER` | Dashboard username | `'admin'` |
| `DASHBOARD_PASSWORD` | Dashboard password | `'admin123'` |
| `DASHBOARD_GITHUB_USER` | GitHub username | `'adrianstanca1'` |
| `SERVER_PUBLIC_IP` | Server public IP | `'72.62.132.43'` |
| `APPS_BASE_URL` | Base URL for apps | `http://${SERVER_PUBLIC_IP}` |
| `GITHUB_TOKEN` | GitHub API authentication | `undefined` |
| `DASHBOARD_API_PORT` | API server port | `3999` |
| `ALLOW_DIRECT_PORT_URLS` | Allow direct port access | `'false'` |
| `OPENAI_API_KEY` | OpenAI LLM access | `undefined` |
| `ANTHROPIC_API_KEY` | Anthropic LLM access | `undefined` |
| `GOOGLE_API_KEY` | Google Gemini access | `undefined` |
| `OLLAMA_URL` | Local Ollama endpoint | `'http://localhost:11434'` |
| `OLLAMA_MODEL` | Default Ollama model | `'codellama:34b'` |
| `DEFAULT_AI_PROVIDER` | Default AI provider | `'cloud'` |
| `HOME` | Home directory for PTY | `'/root'` |

---

## Security Considerations

1. **Settings file:** Uses `0o600` permissions (owner read/write only)
2. **Path validation:** `validateFilePath()` prevents directory traversal
3. **Rate limiting:** In-memory `loginAttempts` Map with 10 attempts/minute
4. **Token-based auth:** JWT with configurable secret
5. **No SQL injection risk:** No SQL databases used

---

## Summary

- **Persistence Strategy:** File-based JSON
- **Persistent Files:** 2 (`.dashboard-settings.json`, `.scheduled-tasks.json`)
- **Runtime State:** JavaScript Maps and Arrays
- **External Data:** System commands (PM2, Docker, Git) and REST APIs (GitHub)
- **No External Databases:** No MongoDB, PostgreSQL, MySQL, or Redis connections
