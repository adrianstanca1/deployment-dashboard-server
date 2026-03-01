# Error Handling Pattern Catalog

**Generated:** 2026-02-26
**Scope:** `/root/deployment-dashboard-server`

---

## Overview

This document catalogs all error handling patterns used in the Deploy Hub Dashboard server, including try-catch blocks, promise error handling, HTTP responses, validation, and logging.

---

## Try-Catch Blocks

**Total Found:** ~140+ blocks

### Pattern Distribution

**server.js:** Lines 19, 65, 134, 160, 205, 265, 274, 299, 314, 327, 340, 353, 369, 388, 401, 435, 480, 489, 499, 509, 520, 531, 541, 552, 563, 569, 595, 608, 651, 693, 729, 762, 795, 829, 868, 891, 915, 924, 996, 1047, 1077, 1121, 1161, 1202, 1246, 1284, 1297, 1318, 1336, 1349, 1362, 1375, 1388, 1397, 1410, 1450, 1478, 1488, 1519, 1592, 1631, 1646, 1657, 1672, 1715, 1725, 1739, 1767, 1851, 1887, 1909, 1986, 2033, 2045, 2145, 2157, 2241, 2267, 2325, 2349, 2378, 2395, 2443, 2464, 2473, 2482, 2491, 2518, 2537, 2553, 2580, 2590, 2630, 2643, 2665, 2805, 2829, 2855, 2883, 2927, 3021, 3045, 3130, 3152, 3212, 3249, 3270, 3336, 3338, 3349, 3365, 3513, 3542, 3564, 3580, 3596, 3605

**ai-assistant.js:** Lines 585, 660, 699, 730, 759

---

## Common Patterns

### 1. Standard API Route Pattern

```javascript
// server.js:299-309
try {
  validatePM2Name(name);
  const { stdout } = await execAsync(`pm2 logs ${name} --lines ${lines} --nostream 2>&1`);
  res.json({ success: true, data: stdout || stderr });
} catch (error) {
  if (error.message.includes('Invalid process name')) {
    return res.status(400).json({ success: false, error: error.message });
  }
  res.status(500).json({ success: false, error: error.message, data: error.stdout || '' });
}
```

### 2. Optional Module Loading Pattern

```javascript
// server.js:19
try {
  pty = require('node-pty');
} catch (e) {
  console.warn('node-pty not available:', e.message);
}
```

### 3. Nested Try-Catch Pattern

```javascript
// server.js:569-583
try {
  // ... outer try
  try {
    // ... inner specific operation
  } catch (e) {
    // handle specific error
  }
} catch (error) {
  // outer error handler
}
```

### 4. Silent Error Swallowing

```javascript
// server.js:2349
try {
  fs.chmodSync(SETTINGS_FILE, 0o600);
} catch {}
```

---

## Promise Error Handling (.catch)

**Total Found:** ~15 handlers

### Pattern 1: Fallback Value Pattern

```javascript
// server.js:571-573
execAsync(`git -C "${repoPath}" status --short`).catch(() => ({ stdout: '' })),
execAsync(`git -C "${repoPath}" rev-parse --abbrev-ref HEAD`).catch(() => ({ stdout: 'unknown' })),
execAsync(`git -C "${repoPath}" log -1 --format="%h|%s|%ar"`).catch(() => ({ stdout: '' })),
```

### Pattern 2: Null Fallback Pattern

```javascript
// server.js:1004, 1017, 1138, 1173, 1214, 1258
const stats = await fsp.stat(fullPath).catch(() => null);
const itemStats = await fsp.stat(itemPath).catch(() => null);
```

### Pattern 3: Boolean Fallback Pattern

```javascript
// server.js:1094
const exists = await fsp.access(fullPath).then(() => true).catch(() => false);
```

### Pattern 4: Default Value Pattern

```javascript
// server.js:1678, 1699
execAsync("cat /proc/stat | head -1").catch(() => ({ stdout: 'cpu 0 0 0 0' })),
const coresOut = await execAsync("nproc").catch(() => ({ stdout: '1' }));
```

---

## HTTP Error Responses

### Status Code Distribution

| Status | Count | Usage |
|--------|-------|-------|
| **400** | ~70 | Bad Request |
| **401** | ~10 | Unauthorized |
| **403** | ~5 | Forbidden |
| **404** | ~15 | Not Found |
| **409** | 1 | Conflict |
| **429** | 1 | Rate Limited |
| **500** | ~60 | Internal Server Error |

### Response Structure

```javascript
// Standard error response
res.status(XXX).json({ success: false, error: 'Error message' });

// With additional data
res.status(500).json({ success: false, error: error.message, data: error.stdout || error.stderr });

// Without status
res.json({ success: false, error: error.message });
```

### 400 Bad Request

```javascript
// ai-assistant.js:564
return res.status(400).json({ success: false, error: 'Invalid provider' });

// server.js:1001
return res.status(400).json({ success: false, error: 'Invalid path' });

// server.js:1322
return res.status(400).json({ success: false, error: 'Invalid action' });
```

### 401 Unauthorized

```javascript
// server.js:132
return res.status(401).json({ success: false, error: 'Unauthorized' });

// server.js:138, 199, 209
res.status(401).json({ success: false, error: 'Invalid or expired token' });
```

### 403 Forbidden

```javascript
// server.js:1135
return res.status(403).json({ success: false, error: 'Cannot delete the root directory' });

// server.js:1532
return res.status(403).json({
  success: false,
  error: 'Command not in allowlist. Allowed: git status, log, diff, pull, fetch, branch, checkout'
});

// server.js:2866-2868
return res.status(403).json({
  success: false,
  error: validation.error,
  allowedPatterns: ALLOWED_COMMAND_PATTERNS.map(p => p.toString())
});
```

### 404 Not Found

```javascript
// server.js:1006
return res.status(404).json({ success: false, error: 'Path not found' });

// server.js:1138
return res.status(404).json({ success: false, error: 'File not found' });

// server.js:3158
return res.status(404).json({ success: false, error: 'Task not found' });
```

### 429 Rate Limited

```javascript
// server.js:190
return res.status(429).json({ success: false, error: 'Too many attempts — wait a minute' });
```

### 409 Conflict

```javascript
// server.js:1096
return res.status(409).json({ success: false, error: 'File or directory already exists' });
```

---

## Error Logging

**console.error Usage:** ~15 occurrences

### Standard Error Logging

```javascript
// server.js:1190
console.error('Download error:', err);

// server.js:1871
console.error(`[WS:terminal] Error in session ${sessionId}:`, err.message);

// server.js:1934
console.error(`[WS:logs] spawn error: ${err.message}`);

// server.js:2007
console.error(`[WS:docker-logs] spawn error: ${err.message}`);
```

### Contextual Error Logging

```javascript
// server.js:2301
console.error('[AI] Error:', error);

// server.js:2333
console.error('[Settings] Failed to load:', err.message);

// server.js:2389
console.error('[QuickActions] Failed to load scheduled tasks:', err.message);

// server.js:2409
console.error('[QuickActions] Failed to save scheduled tasks:', err.message);

// server.js:3034
console.error(`[ScheduledTask] ${taskId} failed:`, err.message);

// server.js:3535
console.error('[AI] Error:', error);

// ai-assistant.js:648
console.error('AI Chat Error:', error);
```

### Console Warnings

```javascript
// server.js:33-36
console.warn('\x1b[33m⚠ DASHBOARD_JWT_SECRET not set — using insecure default\x1b[0m');
console.warn('\x1b[33m⚠ DASHBOARD_PASSWORD not set — default password is "admin123"\x1b[0m');

// server.js:81
console.warn('Failed to parse nginx config:', error.message);
```

---

## Input Validation and Sanitization

### Validation Functions

#### 1. PM2 Name Validation (server.js:290-294)

```javascript
function validatePM2Name(name) {
  if (!name || !/^[a-zA-Z0-9_-]{1,100}$/.test(name)) {
    throw new Error('Invalid process name. Use alphanumeric, underscores, hyphens only (1-100 chars).');
  }
  return name;
}
```

#### 2. Repository Name Sanitization (server.js:457-460)

```javascript
function sanitizeRepoName(name) {
  if (!name || !/^[\w._-]{1,100}$/.test(name)) throw new Error('Invalid repo name');
  return name;
}
```

#### 3. Docker Container ID Validation (server.js:1309-1313)

```javascript
function validateContainerId(id) {
  if (!id || !/^[a-zA-Z0-9_-]{1,64}$/.test(id)) {
    throw new Error('Invalid container ID. Use alphanumeric, underscores, hyphens only (max 64 chars).');
  }
  return id;
}
```

#### 4. File Path Validation (server.js:974-992)

```javascript
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
```

#### 5. Dangerous Pattern Blocking (server.js:2749-2765)

```javascript
const BLOCKED_PATTERNS = [
  /rm\s+-[rf]+.*\//i,              // rm -rf /
  />\s*\/dev\/null/i,              // Output redirection
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}.*\{\s*:\s*\}/, // Fork bomb
  /eval\s*\(/i,                     // eval calls
  /\`.*\`/s,                        // Backtick command substitution
  /\$\(.*\)/s,                      // $() command substitution
  /\|\s*sh\s*$/i,                   // pipe to sh
  /\|\s*bash\s*$/i,                 // pipe to bash
  /wget.*\|.*sh/i,                  // wget piped to sh
  /curl.*\|.*sh/i,                  // curl piped to sh
  /mkfs\./i,                        // filesystem formatting
  /dd\s+if/i,                       // dd command
  />.+\/etc\/passwd/i,              // overwriting passwd
  />.+\/etc\/shadow/i,              // overwriting shadow
];
```

#### 6. Custom Command Validation (server.js:2767-2797)

```javascript
function validateCustomCommand(command) {
  const cmd = command.trim();

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
```

#### 7. Rate Limiting (server.js:118-127)

```javascript
const loginAttempts = new Map();

function checkLoginRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 60_000; }
  entry.count++;
  loginAttempts.set(ip, entry);
  return entry.count <= 10;
}
```

---

## Throw Patterns

**Total throw new Error:** ~15 occurrences

### Validation Errors

```javascript
// server.js:293
throw new Error('Invalid process name. Use alphanumeric, underscores, hyphens only (1-100 chars).');

// server.js:458
throw new Error('Invalid repo name');

// server.js:1312
throw new Error('Invalid container ID. Use alphanumeric, underscores, hyphens only (max 64 chars).');
```

### API/External Service Errors

```javascript
// server.js:472
throw new Error('GitHub API rate limit exceeded. Add GITHUB_TOKEN to increase limit from 60 to 5000/hr.');

// server.js:474
throw new Error(data.message);

// server.js:640, 682, 718, 751, 784, 818
throw new Error(result.message);

// server.js:2069
throw new Error('LLM request failed');

// server.js:2073
throw new Error(`LLM error: ${error.message}`);
```

### AI Provider Errors (ai-assistant.js)

```javascript
// Lines 257, 287, 312, 341
throw new Error(`OpenAI API error: ${error.error?.message || response.statusText}`);
throw new Error(`Anthropic API error: ${error.error?.message || response.statusText}`);
throw new Error(`Google API error: ${error.error?.message || response.statusText}`);
throw new Error(`Local LLM error: ${response.statusText}`);
```

---

## WebSocket Error Handling

### Error Message Sending to Clients

```javascript
// server.js:1784
ws.send(JSON.stringify({ type: 'error', data: error.message }));

// server.js:1891
ws.send(JSON.stringify({ type: 'error', data: `Process "${processName}" not found` }));

// server.js:1901
ws.send(JSON.stringify({ type: 'error', data: 'No log files found' }));

// server.js:1936
ws.send(JSON.stringify({ type: 'error', data: `Log streaming error: ${err.message}` }));

// server.js:1947
ws.send(JSON.stringify({ type: 'error', data: err.message }));

// server.js:1992
ws.send(JSON.stringify({ type: 'error', data: e.message }));

// server.js:2009
ws.send(JSON.stringify({ type: 'error', data: `Log streaming error: ${err.message}` }));
```

### WebSocket Error Event Handlers

```javascript
// server.js:1870
ws.on('error', (err) => {
  console.error(`[WS:terminal] Error in session ${sessionId}:`, err.message);
});

// Process errors
tail.on('error', (err) => {
  console.error(`[WS:logs] spawn error: ${err.message}`);
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'error', data: `Log streaming error: ${err.message}` }));
    ws.close();
  }
});
```

---

## Error Types Handled

| Category | Examples | Handling Pattern |
|----------|----------|------------------|
| **Validation Errors** | Invalid process name, invalid path, invalid container ID | Throw error → Catch → Return 400 |
| **Authentication Errors** | Missing/invalid token, expired JWT | Return 401 |
| **Authorization Errors** | Command not in allowlist | Return 403 |
| **Rate Limiting** | Too many login attempts | Return 429 |
| **Not Found Errors** | File/path/process not found | Return 404 |
| **Conflict Errors** | File/directory already exists | Return 409 |
| **External API Errors** | GitHub API rate limit, LLM API errors | Throw custom error → Return 500 |
| **Command Execution Errors** | PM2, Docker, Git command failures | Catch → Include stdout/stderr |
| **File System Errors** | Access denied, file not found | .catch() with fallback |
| **WebSocket Errors** | Connection errors, spawn errors | Log + Send error message |

---

## Fallback Patterns

### Silent Fallback to Default Values

```javascript
const stats = await fsp.stat(fullPath).catch(() => null);
const exists = await fsp.access(fullPath).then(() => true).catch(() => false);
```

### No Explicit Retry Logic

The codebase does not implement automatic retry mechanisms.

### Fallback AI Provider Pattern

```javascript
// ai-assistant.js:596-603
if (!config || !config.enabled) {
  return res.json({
    success: true,
    response: generateContextualResponse(message, context, capability),
    provider: 'fallback',
    capability,
  });
}
```

### Error Recovery in AI Chat

```javascript
// ai-assistant.js:647-655
} catch (error) {
  console.error('AI Chat Error:', error);
  res.json({
    success: true,  // Returns success:true with fallback
    response: generateContextualResponse(req.body.message, req.body.context, req.body.capability || 'default'),
    provider: 'fallback',
    error: error.message,
  });
}
```

---

## Consistency Analysis

### Strengths

1. **Consistent error response structure** - All errors use `{ success: false, error: message }`
2. **Validation helpers** - Reusable validation functions for names, IDs, paths
3. **Security-focused validation** - Blocked patterns for dangerous commands
4. **Path traversal protection** - `validateFilePath()` prevents directory traversal
5. **Rate limiting** - Login attempts are rate-limited
6. **External error details** - stdout/stderr included in command execution errors

### Inconsistencies Found

1. **Mixed Status Code Usage:**
   - Some endpoints return `res.json({ success: false, error: ... })` (200 status)
   - Others return `res.status(500).json({ success: false, error: ... })`

2. **Inconsistent Error Property Names:**
   - Most use `error` property
   - Some include additional `data` property

3. **Silent Error Handling Variations:**
   - Some log errors, some don't
   - Some have empty catch blocks

4. **Missing Error Middleware** - No centralized Express error handler

---

## Gaps and Missing Error Handling

### Critical Gaps

1. **No Global Error Handler:**
   - Missing Express error handling middleware
   - Unhandled errors may crash the server

2. **No JSON Parsing Error Handler:**
   - `JSON.parse()` calls without try-catch can crash

3. **Missing Validation:**
   - Some routes don't validate all input parameters

4. **Inconsistent Async Error Handling:**
   - Some async routes don't have try-catch

5. **No Request Size Limits:**
   - Missing `express.json()` size limit configuration

6. **Missing CORS Error Handling:**
   - CORS middleware applied but no error handling

7. **No Health Check Endpoint Error Handling:**
   - No dedicated health check with proper error reporting

8. **WebSocket Connection Loss:**
   - No reconnection logic for WebSocket clients

---

## Recommendations

### High Priority

1. **Add Express Error Handler:**
   ```javascript
   app.use((err, req, res, next) => {
     console.error('Unhandled error:', err);
     res.status(500).json({ success: false, error: 'Internal server error' });
   });
   ```

2. **Wrap JSON.parse in try-catch:**
   ```javascript
   let data;
   try {
     data = JSON.parse(stdout);
   } catch (e) {
     throw new Error('Invalid JSON response from API');
   }
   ```

3. **Add Request Validation Middleware**

4. **Standardize Error Responses** - Always use appropriate HTTP status codes

5. **Add JSON Body Size Limit:**
   ```javascript
   app.use(express.json({ limit: '10mb' }));
   ```

### Medium Priority

1. Add Retry Logic for external API calls
2. Implement Request ID tracking
3. Add Structured Logging
4. Create Error Classes for different error types

---

## Summary Statistics

| Pattern | Count |
|---------|-------|
| Try-Catch Blocks | ~140 |
| .catch() Handlers | ~15 |
| res.status() Calls | ~150 |
| console.error() | ~15 |
| throw new Error() | ~15 |
| Validation Functions | 7 |
| HTTP Status Codes Used | 7 (400, 401, 403, 404, 409, 429, 500) |

**Most Common Error Pattern:**
```javascript
try {
  // operation
  res.json({ success: true, data: result });
} catch (error) {
  res.status(500).json({ success: false, error: error.message });
}
```

**Most Common Validation Pattern:**
```javascript
if (!input || !/^[regex]$/.test(input)) {
  return res.status(400).json({ success: false, error: 'Invalid input' });
}
```
