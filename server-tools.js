/**
 * AI Assistant Tool Definitions
 */

const SERVER_TOOLS = [
  { name: "pm2_restart", description: "Restart a PM2 process", input_schema: { type: "object", properties: { processName: { type: "string" } }, required: ["processName"] }},
  { name: "pm2_stop", description: "Stop a PM2 process", input_schema: { type: "object", properties: { processName: { type: "string" } }, required: ["processName"] }},
  { name: "pm2_list", description: "List PM2 processes", input_schema: { type: "object", properties: {} }},
  { name: "pm2_logs", description: "Get PM2 logs", input_schema: { type: "object", properties: { processName: { type: "string" }, lines: { type: "number", default: 50 } }, required: ["processName"] }},
  { name: "deploy_app", description: "Deploy from GitHub", input_schema: { type: "object", properties: { repo: { type: "string" }, port: { type: "number" }, name: { type: "string" } }, required: ["repo", "port", "name"] }},
  { name: "db_list", description: "List databases", input_schema: { type: "object", properties: {} }},
  { name: "db_query", description: "Run SQL query", input_schema: { type: "object", properties: { database: { type: "string" }, query: { type: "string" } }, required: ["database", "query"] }},
  { name: "db_backup", description: "Backup database", input_schema: { type: "object", properties: { database: { type: "string" }, databaseType: { type: "string" } }, required: ["database", "databaseType"] }},
  { name: "git_status", description: "Git status", input_schema: { type: "object", properties: { path: { type: "string", default: "/root" } }}},
  { name: "git_pull", description: "Git pull", input_schema: { type: "object", properties: { path: { type: "string" }, branch: { type: "string", default: "main" } }, required: ["path"] }},
  { name: "git_commit", description: "Git commit", input_schema: { type: "object", properties: { path: { type: "string" }, message: { type: "string" } }, required: ["path", "message"] }},
  { name: "git_branch_list", description: "List branches", input_schema: { type: "object", properties: { path: { type: "string" } }}},
  { name: "github_create_pr", description: "Create GitHub PR", input_schema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" }, title: { type: "string" }, head: { type: "string" }, base: { type: "string", default: "main" } }, required: ["owner", "repo", "title", "head"] }},
  { name: "system_stats", description: "System stats", input_schema: { type: "object", properties: {} }},
  { name: "docker_stats", description: "Docker stats", input_schema: { type: "object", properties: { all: { type: "boolean", default: false } }}},
  { name: "docker_list", description: "List containers", input_schema: { type: "object", properties: { all: { type: "boolean", default: false } }}},
  { name: "check_url", description: "Check URL health", input_schema: { type: "object", properties: { url: { type: "string" }, expectedStatus: { type: "number", default: 200 } }, required: ["url"] }},
  { name: "send_alert", description: "Send alert", input_schema: { type: "object", properties: { message: { type: "string" }, severity: { type: "string", enum: ["info", "warning", "critical"] } }, required: ["message", "severity"] }},
  { name: "file_read", description: "Read file", input_schema: { type: "object", properties: { path: { type: "string" }, lines: { type: "number", default: 100 } }, required: ["path"] }},
  { name: "file_write", description: "Write file", input_schema: { type: "object", properties: { path: { type: "string" }, content: { type: "string" } }, required: ["path", "content"] }},
  { name: "file_search", description: "Search files", input_schema: { type: "object", properties: { pattern: { type: "string" }, path: { type: "string", default: "/root" }, fileType: { type: "string" } }, required: ["pattern"] }},
  { name: "file_list", description: "List directory", input_schema: { type: "object", properties: { path: { type: "string" }, pattern: { type: "string" } }}},
  { name: "file_exists", description: "Check file exists", input_schema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] }},
  { name: "file_get_info", description: "Get file info", input_schema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] }}
];

module.exports = { SERVER_TOOLS };
