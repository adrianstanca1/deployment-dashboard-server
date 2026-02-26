# API Route Map

**Generated:** 2026-02-26
**Scope:** `/root/deployment-dashboard-server`
**Base URL:** `http://localhost:3999` (configurable via `DASHBOARD_API_PORT`)

---

## Global Middleware Stack

| Order | Middleware | Description |
|-------|------------|-------------|
| 1 | `cors()` | Cross-origin resource sharing |
| 2 | `express.json()` | JSON body parsing |
| 3 | **Auth Guard** (lines 214-217) | JWT verification for all `/api/*` except `/api/auth/*` |

### Authentication Middleware

**File:** `server.js:129-140`

```javascript
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
```

---

## HTTP API Routes

### Authentication (`/api/auth/*`)

**Public Routes - No Authentication Required**

| Method | Path | Handler | Auth | Description |
|--------|------|---------|------|-------------|
| POST | `/api/auth/login` | Anonymous | No | Login with username/password, returns JWT |
| GET | `/api/auth/me` | Anonymous | Yes | Verify current token validity |

---

### PM2 Process Management (`/api/pm2/*`)

| Method | Path | Params | Auth | Description |
|--------|------|--------|------|-------------|
| GET | `/api/pm2/list` | - | Yes | List all PM2 processes |
| GET | `/api/pm2/status` | - | Yes | Get PM2 status summary |
| GET | `/api/pm2/logs/:name` | `:name` = process name | Yes | Fetch recent logs |
| POST | `/api/pm2/restart/:name` | `:name` = process name | Yes | Restart process |
| POST | `/api/pm2/stop/:name` | `:name` = process name | Yes | Stop process |
| POST | `/api/pm2/start/:name` | `:name` = process name | Yes | Start process |
| POST | `/api/pm2/delete/:name` | `:name` = process name | Yes | Delete process |
| POST | `/api/pm2/bulk` | Body: `{action, names[]}` | Yes | Bulk action on processes |
| POST | `/api/pm2/restart-errored` | - | Yes | Restart all errored processes |
| POST | `/api/pm2/save` | - | Yes | Save PM2 process list |

---

### GitHub Integration (`/api/github/*`)

| Method | Path | Params/Query | Auth | Description |
|--------|------|--------------|------|-------------|
| GET | `/api/github/repos` | - | Yes | List repositories |
| GET | `/api/github/commits/:repo` | `:repo` = repo name | Yes | Get recent commits |
| GET | `/api/github/branches/:repo` | `:repo` = repo name | Yes | List branches |
| GET | `/api/github/issues/:repo` | `:repo` = repo name | Yes | List issues |
| GET | `/api/github/pulls/:repo` | `:repo` = repo name | Yes | List pull requests |
| GET | `/api/github/releases/:repo` | `:repo` = repo name | Yes | List releases |
| GET | `/api/github/readme/:repo` | `:repo` = repo name | Yes | Get README content |
| GET | `/api/github/actions/:repo` | `:repo` = repo name | Yes | List workflow runs |
| GET | `/api/github/workflows/:repo` | `:repo` = repo name | Yes | List workflows |
| GET | `/api/github/commit-activity/:repo` | `:repo` = repo name | Yes | Get commit activity |
| GET | `/api/github/local-status/:repo` | `:repo` = repo name | Yes | Get local git status |
| POST | `/api/github/pull-local/:repo` | `:repo` = repo name | Yes | Pull latest changes |
| POST | `/api/github/sync/:repo` | `:repo` = repo name | Yes | Sync repository |
| POST | `/api/github/create-branch/:repo` | `:repo` = repo name | Yes | Create new branch |
| POST | `/api/github/trigger-workflow/:repo` | `:repo` = repo name | Yes | Trigger workflow |
| POST | `/api/github/create-issue/:repo` | `:repo` = repo name | Yes | Create issue |
| POST | `/api/github/create-pr/:repo` | `:repo` = repo name | Yes | Create PR |
| POST | `/api/github/merge-pr/:repo/:pull_number` | `:repo`, `:pull_number` | Yes | Merge PR |
| GET | `/api/github/compare/:repo` | Query: `base`, `head` | Yes | Compare branches |

---

### Server File Management (`/api/server/*`)

| Method | Path | Query/Body | Auth | Description |
|--------|------|------------|------|-------------|
| GET | `/api/server/apps` | - | Yes | List server applications |
| GET | `/api/server/app/:name` | `:name` = app name | Yes | Get app details |
| GET | `/api/server/browse` | Query: `path` | Yes | Browse directory |
| POST | `/api/server/upload` | Form: `files[]`, `path` | Yes | Upload files (multer) |
| POST | `/api/server/create` | Body: `path`, `type`, `content` | Yes | Create file/directory |
| DELETE | `/api/server/delete` | Body: `path`, `recursive` | Yes | Delete file/directory |
| GET | `/api/server/download` | Query: `path` | Yes | Download file |
| GET | `/api/server/edit` | Query: `path` | Yes | Get file for editing |
| POST | `/api/server/edit` | Body: `path`, `content` | Yes | Save file contents |

---

### Docker Management (`/api/docker/*`)

| Method | Path | Params/Body | Auth | Description |
|--------|------|-------------|------|-------------|
| GET | `/api/docker/containers` | - | Yes | List containers |
| GET | `/api/docker/images` | - | Yes | List images |
| GET | `/api/docker/volumes` | - | Yes | List volumes |
| GET | `/api/docker/networks` | - | Yes | List networks |
| GET | `/api/docker/system/df` | - | Yes | Get disk usage |
| POST | `/api/docker/container/:action/:id` | `:action`, `:id` | Yes | Container actions (start/stop/restart/pause/unpause) |
| DELETE | `/api/docker/container/:id` | `:id` = container ID | Yes | Remove container |
| GET | `/api/docker/container/:id/inspect` | `:id` = container ID | Yes | Inspect container |
| GET | `/api/docker/container/:id/stats` | `:id` = container ID | Yes | Container stats |
| DELETE | `/api/docker/volume/:name` | `:name` = volume name | Yes | Remove volume |
| POST | `/api/docker/pull` | Body: `image`, `tag` | Yes | Pull image (SSE) |
| POST | `/api/docker/run` | Body: options | Yes | Run container |
| DELETE | `/api/docker/image/:id` | `:id` = image ID | Yes | Remove image |
| POST | `/api/docker/prune` | Body: `type` | Yes | Prune resources |

---

### Deployment Pipeline (`/api/deploy/*`)

| Method | Path | Body | Auth | Description |
|--------|------|------|------|-------------|
| POST | `/api/deploy/pipeline` | `repoUrl`, `branch`, `buildCmd`, etc. | Yes | Full deploy (SSE) |
| POST | `/api/deploy/clone` | `repoUrl`, `targetDir` | Yes | Clone repository |
| POST | `/api/deploy/build` | `cwd`, `command` | Yes | Build application |
| POST | `/api/deploy/install` | `cwd`, `packageManager` | Yes | Install dependencies |

---

### System Information (`/api/system/*`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/system/exec` | Yes | Execute shell command |
| GET | `/api/system/stats` | Yes | System stats (CPU, memory, disk) |
| GET | `/api/system/network` | Yes | Network interfaces |
| GET | `/api/system/ports` | Yes | Listening ports |

---

### Git Commands (`/api/git/*`)

| Method | Path | Body | Auth | Description |
|--------|------|------|------|-------------|
| POST | `/api/git/command` | `cwd`, `command`, `args[]` | Yes | Execute git command |

---

### Quick Actions (`/api/quick-actions/*`)

| Method | Path | Body/Params | Auth | Description |
|--------|------|-------------|------|-------------|
| POST | `/api/quick-actions/execute` | `actionId`, `params` | Yes | Execute action |
| POST | `/api/quick-actions/custom` | `name`, `command`, `cwd` | Yes | Custom command |
| GET | `/api/quick-actions/history` | - | Yes | Get history |
| GET | `/api/quick-actions/list` | - | Yes | List actions |
| POST | `/api/quick-actions/schedule` | `name`, `command`, `schedule` | Yes | Create scheduled task |
| GET | `/api/quick-actions/schedule` | - | Yes | List scheduled tasks |
| PATCH | `/api/quick-actions/schedule/:taskId` | `:taskId` | Yes | Update task |
| DELETE | `/api/quick-actions/schedule/:taskId` | `:taskId` | Yes | Delete task |

---

### Settings (`/api/settings/*`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/settings` | Yes | Get settings |
| POST | `/api/settings` | Yes | Update settings |
| GET | `/api/settings/health` | Yes | Health check |

---

### AI Assistant (`/api/ai/*`)

| Method | Path | Body | Auth | Description |
|--------|------|------|------|-------------|
| GET | `/api/ai/providers` | - | Yes | List AI providers |
| POST | `/api/ai/providers/:provider` | `:provider` | Yes | Configure provider |
| GET | `/api/ai/capabilities` | - | Yes | Get capabilities |
| POST | `/api/ai/chat` | `message`, `context` | Yes | Chat with AI |
| POST | `/api/ai/code-review` | `code`, `language` | Yes | Code review |
| POST | `/api/ai/architecture` | `description` | Yes | Architecture suggestions |
| POST | `/api/ai/plan-tasks` | `description` | Yes | Generate task plan |
| POST | `/api/ai/debug` | `error`, `context` | Yes | Debugging help |

---

## WebSocket Endpoints

**Protocol:** WebSocket (ws/wss)
**Authentication:** JWT token via query parameter `?token=<jwt>`

| Path | Variable | Purpose | Events |
|------|----------|---------|--------|
| `/ws` | `wssStatus` | PM2 live updates | Emits `pm2-update` every 5s, `pm2-alert` on errors |
| `/ws/terminal` | `wssTerminal` | PTY terminal | Resize, docker exec via `?docker=<name>` |
| `/ws/terminal?id=<sess>` | `wssTerminal` | Named session | Resume session |
| `/ws/logs?process=<name>` | `wssLogs` | Live log tail | Last 200 lines + live `tail -f` |
| `/ws/stats` | `wssStats` | System stats | Emits `stats` every 2 seconds |
| `/ws/docker?id=<id>` | `wssDockerLogs` | Docker logs | Last 200 lines + live `docker logs -f` |

### WebSocket Message Types

**`/ws` (PM2 Status):**
```javascript
{ type: 'pm2-update', data: processes[] }
{ type: 'pm2-alert', data: alerts[] }
{ type: 'error', data: message }
```

**`/ws/terminal` (PTY):**
- Receives: Raw binary input
- Receives Control: `{ type: 'resize', cols, rows }`
- Sends: Raw binary PTY output

**`/ws/logs`:**
```javascript
{ type: 'log', data: line }
{ type: 'error', data: message }
```

**`/ws/stats`:**
```javascript
{ type: 'stats', data: { cpu, memory, disk, network } }
```

**`/ws/docker`:**
```javascript
{ type: 'history', data: lines }
{ type: 'log', data: line }
{ type: 'error', data: message }
{ type: 'end', data: 'Container stopped' }
```

---

## Static File Serving

| Path | Source | Condition |
|------|--------|-----------|
| `/` | `../deployment-dashboard/dist` | If directory exists |
| `*` | `index.html` | SPA fallback |

---

## Route Parameter Patterns

| Parameter | Pattern | Validation |
|-----------|---------|------------|
| `:name` | PM2 process name | String |
| `:repo` | GitHub repository | String |
| `:id` | Docker ID | `^[\w_.-]+$` |
| `:action` | Action type | Whitelist: start/stop/restart/pause/unpause |
| `:pull_number` | PR number | Integer |
| `:provider` | AI provider | String |
| `:taskId` | Task ID | String |

---

## Query Parameter Patterns

| Endpoint | Query Params |
|----------|--------------|
| `/api/server/browse` | `?path=/some/path` |
| `/api/server/download` | `?path=/some/file` |
| `/api/server/edit` | `?path=/some/file` |
| `/api/github/compare/:repo` | `?base=main&head=feature` |
| `/ws/terminal` | `?id=<sess>&docker=<name>&cols=80&rows=24` |
| `/ws/logs` | `?process=<name>` |
| `/ws/docker` | `?id=<container_id>` |

---

## Summary Statistics

- **Total HTTP Routes:** ~75
- **WebSocket Endpoints:** 5
- **Middleware Functions:** 4
- **Route Prefixes:** 11 (`/api/auth`, `/api/pm2`, `/api/github`, `/api/server`, `/api/docker`, `/api/deploy`, `/api/system`, `/api/git`, `/api/quick-actions`, `/api/settings`, `/api/ai`)
- **Protected Routes:** All except `/api/auth/login`

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `DASHBOARD_API_PORT` | `3999` | Server port |
| `DASHBOARD_JWT_SECRET` | - | JWT signing |
| `DASHBOARD_USER` | `admin` | Username |
| `DASHBOARD_PASSWORD` | `admin123` | Password |
| `DASHBOARD_GITHUB_USER` | `adrianstanca1` | GitHub user |
| `SERVER_PUBLIC_IP` | `72.62.132.43` | Public IP |
| `APPS_BASE_URL` | - | App base URL |
