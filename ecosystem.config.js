module.exports = {
  apps: [{
    name: 'dashboard-api',
    script: './server.js',
    env: {
      NODE_ENV: 'production',
      DASHBOARD_API_PORT: 3999,
      // ── Auth credentials ────────────────────────────────────────────────────
      // CHANGE THESE before exposing to the internet!
      DASHBOARD_USER: 'admin',
      DASHBOARD_PASSWORD: 'admin123',
      DASHBOARD_JWT_SECRET: 'deploy-hub-jwt-secret-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15),
      // GitHub token for API rate limit increase (60 → 5000 req/hour)
      GITHUB_TOKEN: process.env.GITHUB_TOKEN or '',
    },
  }],
};
