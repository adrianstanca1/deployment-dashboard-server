// Enhanced AI Module with Real LLM Integration
const https = require('https');
const http = require('http');

// Store API keys in memory (in production, use environment variables or secure storage)
const apiKeys = {
  openai: process.env.OPENAI_API_KEY || '',
  anthropic: process.env.ANTHROPIC_API_KEY || '',
  google: process.env.GOOGLE_API_KEY || '',
  openrouter: process.env.OPENROUTER_API_KEY || '',
};

const baseUrls = {
  openai: process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1',
  anthropic: 'https://api.anthropic.com/v1',
  google: 'https://generativelanguage.googleapis.com/v1beta',
  openrouter: 'https://openrouter.ai/api/v1',
  local: 'http://127.0.0.1:11434',
};

// LLM Provider configurations
const LLM_CONFIG = {
  openai: {
    enabled: !!apiKeys.openai,
    defaultModel: 'gpt-4o-mini',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo'],
  },
  anthropic: {
    enabled: !!apiKeys.anthropic,
    defaultModel: 'claude-sonnet-4-20250514',
    models: ['claude-sonnet-4-20250514', 'claude-opus-4-20250514', 'claude-3-5-sonnet-20241022'],
  },
  google: {
    enabled: !!apiKeys.google,
    defaultModel: 'gemini-2.0-flash',
    models: ['gemini-2.0-flash', 'gemini-1.5-pro', 'gemini-1.5-flash'],
  },
  openrouter: {
    enabled: !!apiKeys.openrouter,
    defaultModel: 'openrouter/auto',
    models: ['openrouter/auto', 'anthropic/claude-3.5-sonnet', 'openai/gpt-4o', 'google/gemini-pro-1.5'],
  },
  local: {
    enabled: true,
    defaultModel: 'qwen3.5:cloud',
    models: ['qwen3.5:cloud', 'llama3.2', 'mistral', 'codellama'],
  },
};

let activeProvider = process.env.DEFAULT_AI_PROVIDER || 'local';

// Helper function to make HTTP requests
function makeRequest(url, options, body) {
  return new Promise((resolve, reject) => {
    const req = (url.startsWith('https') ? https : http).request(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve({ content: data });
        }
      });
    });
    
    req.on('error', reject);
    req.write(JSON.stringify(body));
    req.end();
  });
}

// Call LLM API
async function callLLM(provider, model, messages, systemPrompt) {
  try {
    let response;
    
    if (provider === 'local') {
      // Ollama local
      const ollamaUrl = `${baseUrls.local}/api/generate`;
      response = await makeRequest(ollamaUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, {
        model: model || LLM_CONFIG.local.defaultModel,
        prompt: messages[messages.length - 1].content,
        system: systemPrompt,
        stream: false,
      });
      return response.response;
    }
    
    if (provider === 'openai' || provider === 'openrouter') {
      const apiKey = apiKeys[provider];
      const baseUrl = baseUrls[provider];
      const url = `${baseUrl}/chat/completions`;
      
      response = await makeRequest(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`,
          ...(provider === 'openrouter' ? {
            'HTTP-Referer': 'http://localhost:3002',
            'X-Title': 'Deployment Dashboard',
          } : {}),
        },
      }, {
        model: model || LLM_CONFIG[provider].defaultModel,
        messages: [
          { role: 'system', content: systemPrompt || 'You are a helpful AI assistant.' },
          ...messages,
        ],
        max_tokens: 2000,
      });
      
      return response.choices?.[0]?.message?.content || 'No response';
    }
    
    if (provider === 'anthropic') {
      const apiKey = apiKeys.anthropic;
      const url = `${baseUrls.anthropic}/messages`;
      
      response = await makeRequest(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
      }, {
        model: model || LLM_CONFIG.anthropic.defaultModel,
        max_tokens: 2000,
        system: systemPrompt || 'You are a helpful AI assistant.',
        messages: messages.filter(m => m.role !== 'system'),
      });
      
      return response.content?.[0]?.text || 'No response';
    }
    
    if (provider === 'google') {
      const apiKey = apiKeys.google;
      const url = `${baseUrls.google}/models/${model || LLM_CONFIG.google.defaultModel}:generateContent?key=${apiKey}`;
      
      response = await makeRequest(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, {
        contents: [{
          parts: [{ text: messages[messages.length - 1].content }],
        }],
        systemInstruction: { parts: [{ text: systemPrompt || 'You are a helpful AI assistant.' }] },
      });
      
      return response.candidates?.[0]?.content?.parts?.[0]?.text || 'No response';
    }
    
    throw new Error(`Unknown provider: ${provider}`);
  } catch (error) {
    console.error(`LLM Error (${provider}):`, error.message);
    return `Error calling ${provider}: ${error.message}`;
  }
}

// Setup AI API routes
function setupEnhancedAI(app, requireAuth) {
  // Get providers
  app.get('/api/ai/providers', (req, res) => {
    const providers = Object.entries(LLM_CONFIG).map(([key, config]) => ({
      id: key,
      name: key.charAt(0).toUpperCase() + key.slice(1),
      enabled: config.enabled || key === 'local',
      defaultModel: config.defaultModel,
      models: config.models || [],
      isActive: key === activeProvider,
      configured: !!apiKeys[key] || key === 'local',
    }));

    res.json({ success: true, data: providers, active: activeProvider });
  });

  // Switch provider
  app.post('/api/ai/providers/:provider', requireAuth, (req, res) => {
    const { provider } = req.params;
    if (!LLM_CONFIG[provider]) {
      return res.status(400).json({ success: false, error: 'Invalid provider' });
    }
    activeProvider = provider;
    res.json({ success: true, data: { active: provider } });
  });

  // Get capabilities
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

  // Get tools
  app.get('/api/ai/tools', (req, res) => {
    res.json({
      success: true,
      data: [
        { id: 'pm2', name: 'PM2 Manager', description: 'Manage Node.js processes', icon: 'Activity' },
        { id: 'docker', name: 'Docker', description: 'Manage containers', icon: 'Database' },
        { id: 'github', name: 'GitHub', description: 'Repository management', icon: 'GitBranch' },
        { id: 'system', name: 'System', description: 'System monitoring', icon: 'Server' },
        { id: 'files', name: 'File System', description: 'Read/write files', icon: 'FileCode' },
      ],
    });
  });

  // Get API keys status
  app.get('/api/ai/keys', requireAuth, (req, res) => {
    res.json({
      success: true,
      data: {
        openai: { configured: !!apiKeys.openai, envVar: 'OPENAI_API_KEY' },
        anthropic: { configured: !!apiKeys.anthropic, envVar: 'ANTHROPIC_API_KEY' },
        google: { configured: !!apiKeys.google, envVar: 'GOOGLE_API_KEY' },
        openrouter: { configured: !!apiKeys.openrouter, envVar: 'OPENROUTER_API_KEY' },
      },
    });
  });

  // Update API key
  app.post('/api/ai/keys', requireAuth, (req, res) => {
    const { provider, apiKey, baseURL } = req.body;
    
    if (!provider) {
      return res.status(400).json({ success: false, error: 'Provider required' });
    }

    if (apiKey !== undefined) {
      apiKeys[provider] = apiKey;
      LLM_CONFIG[provider].enabled = !!apiKey;
    }

    if (baseURL !== undefined) {
      baseUrls[provider] = baseURL;
    }

    res.json({ success: true, message: 'API key updated' });
  });

  // Get agents
  app.get('/api/ai/agents', (req, res) => {
    res.json({
      success: true,
      data: [
        { id: 'coder', name: 'Coder Agent', description: 'Writes and reviews code', status: 'available', tools: ['files', 'github', 'system'] },
        { id: 'reviewer', name: 'Reviewer Agent', description: 'Code review specialist', status: 'available', tools: ['github', 'files'] },
        { id: 'devops', name: 'DevOps Agent', description: 'Deployment and infrastructure', status: 'available', tools: ['docker', 'pm2', 'system'] },
        { id: 'debugger', name: 'Debugger Agent', description: 'Bug hunting and fixing', status: 'available', tools: ['system', 'files', 'pm2'] },
      ],
    });
  });

  // Delegate to agent
  app.post('/api/ai/delegate', requireAuth, async (req, res) => {
    const { agentId, task, context } = req.body;
    
    const agents = {
      coder: { systemPrompt: 'You are an expert coder. Write clean, efficient, well-documented code.', capability: 'codeReview' },
      reviewer: { systemPrompt: 'You are a senior code reviewer. Focus on security, performance, and best practices.', capability: 'codeReview' },
      devops: { systemPrompt: 'You are a DevOps engineer. Focus on deployment, monitoring, and infrastructure.', capability: 'devops' },
      debugger: { systemPrompt: 'You are an expert debugger. Systematically diagnose and fix issues.', capability: 'debugging' },
    };

    const agent = agents[agentId];
    if (!agent) {
      return res.status(400).json({ success: false, error: 'Unknown agent' });
    }

    try {
      const response = await callLLM(activeProvider, null, [{ role: 'user', content: task }], agent.systemPrompt);
      
      res.json({
        success: true,
        data: {
          taskId: `task-${Date.now()}`,
          agentId,
          status: 'complete',
          response,
        },
      });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });

  // Chat endpoint with real LLM
  app.post('/api/ai/chat', requireAuth, async (req, res) => {
    try {
      const { message, context, history, capability, provider, model } = req.body;

      const selectedProvider = provider || activeProvider;
      const selectedModel = model || LLM_CONFIG[selectedProvider]?.defaultModel;

      // Build system prompt based on capability
      const systemPrompts = {
        codeReview: 'You are a senior code reviewer. Review code for quality, security, performance, and best practices. Provide constructive feedback.',
        debugging: 'You are an expert debugger. Help diagnose and fix bugs systematically. Ask clarifying questions when needed.',
        architecture: 'You are a software architect. Design scalable, maintainable systems. Consider trade-offs and best practices.',
        devops: 'You are a DevOps engineer. Help with CI/CD, deployment, monitoring, and infrastructure. Focus on reliability and automation.',
        default: 'You are a helpful AI assistant for a deployment dashboard. Help with coding, DevOps, system administration, and general questions.',
      };

      const systemPrompt = systemPrompts[capability || 'default'];

      // Build messages array
      const messages = [];
      if (history && Array.isArray(history)) {
        history.forEach(h => {
          if (h.role && h.content) {
            messages.push({ role: h.role, content: h.content });
          }
        });
      }
      
      // Add context if available
      let userMessage = message;
      if (context && Object.keys(context).length > 0) {
        userMessage += `\n\nContext:\n${JSON.stringify(context, null, 2)}`;
      }
      
      messages.push({ role: 'user', content: userMessage });

      // Call LLM
      const response = await callLLM(selectedProvider, selectedModel, messages, systemPrompt);

      res.json({
        success: true,
        response,
        provider: selectedProvider,
        model: selectedModel,
        capability: capability || 'default',
      });
    } catch (error) {
      console.error('AI Chat error:', error);
      res.status(500).json({
        success: false,
        error: error.message,
        response: 'I apologize, but I encountered an error processing your request.',
      });
    }
  });

  // Execute tool
  app.post('/api/ai/tool/execute', requireAuth, async (req, res) => {
    const { tool, action, params } = req.body;
    
    try {
      // Tool execution logic would go here
      // For now, return mock response
      res.json({
        success: true,
        data: {
          result: `Tool ${tool} executed with action ${action}`,
          output: 'Success',
        },
      });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });
}

module.exports = { setupEnhancedAI, apiKeys, baseUrls, LLM_CONFIG, callLLM };
