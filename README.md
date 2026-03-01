# Deploy Hub — Backend Server

Express + WebSocket backend for the [Deploy Hub Dashboard](https://github.com/adrianstanca1/deployment-dashboard). Manages PM2 processes, Docker containers, real PTY terminal sessions, system stats, GitHub API proxy, deploy pipeline, and file manager — all over a single Node.js server.

**Live at:** http://srv1262179.hstgr.cloud:8080

---

## Features

- **PM2 management** — list, start, stop, restart, delete, logs, env vars, bulk operations
- **Docker management** — containers, images, volumes, networks, logs, inspect, exec, pull, run, prune
- **Real PTY terminal** — full interactive shell via `node-pty`, multiplexed over WebSocket with multi-session support; also supports `docker exec` sessions
- **System stats** — CPU, memory, disk, network interface info streamed over WebSocket
- **GitHub API proxy** — proxies GitHub REST API calls with optional token auth (5000 req/hr vs 60 unauthenticated)
- **Deploy pipeline** — clone → install → build → PM2 start, streamed via SSE
- **File manager** — browse, read, write, upload, download files under `/var/www`
- **JWT authentication** — all API routes and WebSocket upgrades require a valid token
- **Command runner** — whitelisted shell commands (git pull, npm, etc.) with execution history

## Tech Stack

- **Express** — HTTP server and REST API
- **ws** — WebSocket server (terminal, logs, stats, docker logs)
- **node-pty** — real PTY process spawning for terminal sessions
- **jsonwebtoken** — JWT auth
- **node-cron** — scheduled tasks
- **multer** — file uploads

## Getting Started

### Prerequisites

- Node.js 18+
- PM2 installed globally (`npm install -g pm2`)
- Docker installed (for Docker features)

### Install

```bash
npm install
```

### Configuration

Copy the ecosystem config and set your credentials:

```bash
cp ecosystem.config.js ecosystem.local.js
```

Edit `ecosystem.local.js`:

```js
env: {
  DASHBOARD_USER: 'admin',           // login username
  DASHBOARD_PASSWORD: 'yourpassword', // login password (change this!)
  DASHBOARD_JWT_SECRET: 'your-secret-here',
  GITHUB_TOKEN: 'ghp_...',           // optional — raises rate limit to 5000/hr
  GITHUB_USERNAME: 'your-username',
}
```

### Run with PM2

```bash
pm2 start ecosystem.config.js
pm2 save
```

Or directly:

```bash
node server.js
```

Server listens on port **3999** by default.

## API Routes

### Authentication
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Returns JWT token |
| `GET` | `/api/auth/verify` | Verify token validity |

### PM2
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/pm2/list` | List all processes |
| `POST` | `/api/pm2/:action/:name` | start / stop / restart / delete |
| `POST` | `/api/pm2/bulk` | Bulk action on multiple processes |
| `GET` | `/api/pm2/logs/:name` | Fetch recent logs |
| `POST` | `/api/pm2/save` | Save PM2 process list |

### Docker
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/docker/containers` | List containers |
| `GET` | `/api/docker/images` | List images |
| `GET` | `/api/docker/volumes` | List volumes |
| `GET` | `/api/docker/networks` | List networks |
| `POST` | `/api/docker/:action/:id` | start / stop / restart / pause / remove |
| `POST` | `/api/docker/run` | Run a new container |
| `POST` | `/api/docker/pull` | Pull image (SSE stream) |
| `DELETE` | `/api/docker/image/:id` | Remove image |
| `DELETE` | `/api/docker/volume/:name` | Remove volume |

### GitHub
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/github/repos` | List repos for configured user |
| `GET` | `/api/github/commits/:repo` | Recent commits |
| `GET` | `/api/github/branches/:repo` | Branches |
| `GET` | `/api/github/issues/:repo` | Issues |
| `GET` | `/api/github/pulls/:repo` | Pull requests |
| `GET` | `/api/github/releases/:repo` | Releases |
| `GET` | `/api/github/actions/:repo` | Workflow runs |
| `GET` | `/api/github/readme/:repo` | README content |

### System
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/system/info` | CPU, memory, disk, OS info |
| `GET` | `/api/system/ports` | Listening ports |
| `GET` | `/api/system/network` | Network interfaces |
| `POST` | `/api/system/exec` | Run whitelisted shell command |

### Deploy
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/deploy/pipeline` | Full deploy pipeline (SSE stream) |
| `POST` | `/api/deploy/clone` | Clone a repo |
| `POST` | `/api/deploy/build` | Build an app |
| `POST` | `/api/deploy/install` | Install dependencies |

## WebSocket Endpoints

All WebSocket connections require a valid JWT passed as `?token=` query param or `Authorization` header on the upgrade request.

| Path | Description |
|------|-------------|
| `/ws` | PM2 process status broadcast (5s interval) |
| `/ws/terminal?id=<session>` | PTY terminal session |
| `/ws/terminal?id=<session>&docker=<name>` | Docker exec session |
| `/ws/logs?process=<name>` | Live PM2 log tail |
| `/ws/stats` | System stats stream (CPU, RAM, disk, network) |
| `/ws/docker?id=<container>` | Docker container log tail |

## Security Notes

- All routes (except `/api/auth/login`) require JWT authentication
- PM2 process names and repo names are validated with strict regex before use in shell commands
- File manager paths are resolved and verified to stay within `/var/www`
- Branch and app names in deploy routes are validated before shell interpolation
- Rate limiting on login endpoint (in-memory, 10 attempts/min per IP)
- **Change the default password** (`admin123`) before exposing to the internet

## License

MIT
