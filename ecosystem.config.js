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
      DASHBOARD_JWT_SECRET: 'deploy-hub-change-this-secret-now',
    },
  }],
};
