// AI API Module for Enhanced Server
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// LLM Provider configurations
const LLM_CONFIG = {
  openai: {
    enabled: !!process.env.OPENAI_API_KEY,
    defaultModel: 'gpt-4o-mini',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo'],
    endpoint: 'https://api.openai.com/v1/chat/completions',
  },
  anthropic: {
    enabled: !!process.env.ANTHROPIC_API_KEY,
    defaultModel: 'claude-sonnet-4-20250514',
    models: ['claude-sonnet-4-20250514', 'claude-opus-4-20250514'],
    endpoint: 'https://api.anthropic.com/v1/messages',
  },
  google: {
    enabled: !!process.env.GOOGLE_API_KEY,
    defaultModel: 'gemini-2.0-flash',
    models: ['gemini-2.0-flash', 'gemini-1.5-pro'],
    endpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
  },
  local: {
    enabled: true,
    defaultModel: 'qwen3.5:cloud',
    models: ['qwen3.5:cloud', 'llama3.2', 'mistral'],
    endpoint: 'http://127.0.0.1:11434/api/generate',
  },
  cloud: {
    enabled: true,
    defaultModel: 'openrouter/auto',
    models: ['openrouter/auto'],
    endpoint: 'https://openrouter.ai/api/v1/chat/completions',
  },
};

let activeProvider = process.env.DEFAULT_AI_PROVIDER || 'cloud';

// AI API Routes
function setupAIApi(app, requireAuth) {
  // Get available AI providers
  app.get('/api/ai/providers', (req, res) => {
    const providers = Object.entries(LLM_CONFIG).map(([key, config]) => ({
      id: key,
      name: key.charAt(0).toUpperCase() + key.slice(1),
      enabled: config.enabled,
      defaultModel: config.defaultModel,
      models: config.models || [],
      isActive: key === activeProvider,
    }));

    res.json({
      success: true,
      data: providers,
      active: activeProvider,
    });
  });

  // Switch active provider
  app.post('/api/ai/providers/:provider', requireAuth, (req, res) => {
    const { provider } = req.params;

    if (!LLM_CONFIG[provider]) {
      return res.status(400).json({ success: false, error: 'Invalid provider' });
    }

    if (!LLM_CONFIG[provider].enabled) {
      return res.status(400).json({
        success: false,
        error: 'Provider not configured - check API key in environment variables',
      });
    }

    activeProvider = provider;
    res.json({ success: true, data: { active: provider } });
  });

  // Get AI capabilities
  app.get('/api/ai/capabilities', (req, res) => {
    res.json({
      success: true,
      data: {
        codeReview: {
          name: 'Code Review',
          description: 'Review code for quality, security, and performance',
          icon: 'Code',
        },
        debugging: {
          name: 'Debugging',
          description: 'Help diagnose and fix bugs',
          icon: 'Bug',
        },
        architecture: {
          name: 'Architecture',
          description: 'Design system architecture and patterns',
          icon: 'Layers',
        },
        devops: {
          name: 'DevOps',
          description: 'CI/CD, deployment, infrastructure',
          icon: 'Server',
        },
        default: {
          name: 'General Assistant',
          description: 'General purpose AI assistant',
          icon: 'MessageSquare',
        },
      },
    });
  });

  // Get available AI tools
  app.get('/api/ai/tools', (req, res) => {
    res.json({
      success: true,
      data: [
        { id: 'pm2', name: 'PM2 Manager', description: 'Manage Node.js processes' },
        { id: 'docker', name: 'Docker', description: 'Manage containers' },
        { id: 'github', name: 'GitHub', description: 'Repository management' },
        { id: 'system', name: 'System', description: 'System monitoring and commands' },
        { id: 'files', name: 'File System', description: 'Read/write files' },
      ],
    });
  });

  // Chat endpoint
  app.post('/api/ai/chat', requireAuth, async (req, res) => {
    try {
      const { message, context, history, capability, provider, model } = req.body;

      const selectedProvider = provider || activeProvider;
      const selectedModel = model || LLM_CONFIG[selectedProvider]?.defaultModel;

      // Build system prompt based on capability
      let systemPrompt = 'You are a helpful AI assistant for a deployment dashboard.';
      
      if (capability === 'codeReview') {
        systemPrompt = 'You are a senior code reviewer. Review code for quality, security, performance, and best practices.';
      } else if (capability === 'debugging') {
        systemPrompt = 'You are an expert debugger. Help diagnose and fix bugs systematically.';
      } else if (capability === 'architecture') {
        systemPrompt = 'You are a software architect. Design scalable, maintainable systems.';
      } else if (capability === 'devops') {
        systemPrompt = 'You are a DevOps engineer. Help with CI/CD, deployment, monitoring, and infrastructure.';
      }

      // Add context to the prompt
      let userPrompt = message;
      if (context) {
        userPrompt += `\n\nContext:\n${JSON.stringify(context, null, 2)}`;
      }

      // For demo purposes, return a mock response
      // In production, this would call the actual LLM API
      const mockResponse = generateMockResponse(message, capability, context);

      res.json({
        success: true,
        response: mockResponse,
        provider: selectedProvider,
        model: selectedModel,
        capability: capability || 'default',
      });
    } catch (error) {
      console.error('AI Chat error:', error);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  });

  // Get API keys status (without exposing actual keys)
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

  // Update API key
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

  // Get available agents
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

  // Delegate task to agent
  app.post('/api/ai/delegate', requireAuth, async (req, res) => {
    const { agentId, task, context } = req.body;

    // Mock delegation response
    res.json({
      success: true,
      data: {
        taskId: `task-${Date.now()}`,
        agentId,
        status: 'processing',
        message: `Task delegated to ${agentId}`,
      },
    });
  });
}

// Generate mock responses for demo
function generateMockResponse(message, capability, context) {
  const responses = {
    codeReview: "I've analyzed your code. Here are my recommendations:\n\n✅ **Good practices:**\n- Clean code structure\n- Proper error handling\n\n⚠️ **Suggestions:**\n- Consider adding more unit tests\n- Optimize the database queries\n- Add input validation",
    
    debugging: "Let me help you debug this issue:\n\n🔍 **Analysis:**\n1. Check the error logs\n2. Verify environment variables\n3. Test the API endpoints\n\n💡 **Solution:**\nTry restarting the service and check if the issue persists.",
    
    architecture: "For this system, I recommend:\n\n🏗️ **Architecture:**\n- Microservices with API gateway\n- Event-driven communication\n- Redis for caching\n- PostgreSQL for primary data\n\n📊 **Scalability:**\n- Horizontal scaling with load balancer\n- CDN for static assets",
    
    devops: "Here's the DevOps strategy:\n\n🚀 **CI/CD:**\n- GitHub Actions for automation\n- Automated testing pipeline\n- Blue-green deployments\n\n📈 **Monitoring:**\n- Prometheus + Grafana\n- Centralized logging with ELK\n- Alerting on key metrics",
    
    default: "I'm here to help! I can assist you with:\n\n• **Code Review** - Review your code for quality\n• **Debugging** - Help fix bugs\n• **Architecture** - Design systems\n• **DevOps** - Deployment and infrastructure\n• **General Questions** - Anything else!\n\nWhat would you like to work on?",
  };

  return responses[capability] || responses.default;
}

module.exports = { setupAIApi, LLM_CONFIG };
