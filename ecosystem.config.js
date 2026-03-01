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
      DASHBOARD_PASSWORD: process.env.DASHBOARD_PASSWORD || 'admin123',
      DASHBOARD_JWT_SECRET: process.env.DASHBOARD_JWT_SECRET || 'deploy-hub-jwt-secret-change-me-in-production',
      // GitHub token for API rate limit increase (60 → 5000 req/hour)
      GITHUB_TOKEN: process.env.GITHUB_TOKEN || '',
    },
  }],
};
