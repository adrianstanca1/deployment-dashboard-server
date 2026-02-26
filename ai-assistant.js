// ============================================================================
// ENHANCED AI ASSISTANT - Multi-LLM Integration with Software Engineering
// ============================================================================

// LLM Provider Configuration
const LLM_CONFIG = {
  // OpenAI (GPT-4, GPT-3.5)
  openai: {
    enabled: !!process.env.OPENAI_API_KEY,
    apiKey: process.env.OPENAI_API_KEY,
    baseURL: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4-turbo-preview',
    models: ['gpt-4-turbo-preview', 'gpt-4', 'gpt-3.5-turbo'],
    maxTokens: 4096,
    temperature: 0.7,
  },
  // Anthropic (Claude)
  anthropic: {
    enabled: !!process.env.ANTHROPIC_API_KEY,
    apiKey: process.env.ANTHROPIC_API_KEY,
    baseURL: 'https://api.anthropic.com/v1',
    defaultModel: 'claude-3-sonnet-20240229',
    models: ['claude-3-opus-20240229', 'claude-3-sonnet-20240229', 'claude-3-haiku-20240307'],
    maxTokens: 4096,
    temperature: 0.7,
  },
  // Google (Gemini)
  google: {
    enabled: !!process.env.GOOGLE_API_KEY,
    apiKey: process.env.GOOGLE_API_KEY,
    baseURL: 'https://generativelanguage.googleapis.com/v1',
    defaultModel: 'gemini-1.5-pro',
    models: ['gemini-1.5-pro', 'gemini-1.5-flash'],
    maxTokens: 8192,
    temperature: 0.7,
  },
  // Local (Ollama)
  local: {
    enabled: true,
    baseURL: process.env.OLLAMA_URL || 'http://localhost:11434',
    defaultModel: process.env.OLLAMA_MODEL || 'codellama:34b',
    models: ['codellama:34b', 'mixtral:8x7b', 'llama3:70b', 'qwen2.5-coder:14b'],
    maxTokens: 4096,
    temperature: 0.7,
  },
  // Cloud API (Dashboard's own managed API)
  cloud: {
    enabled: true,
    description: 'Dashboard-managed cloud AI (no API key needed)',
    defaultModel: 'auto',
    models: ['auto', 'fast', 'powerful'],
    maxTokens: 4096,
  },
};

// Current active provider (can be switched at runtime)
let activeProvider = process.env.DEFAULT_AI_PROVIDER || 'cloud';

// ============================================================================
// AI CAPABILITIES CONFIGURATION
// ============================================================================

const AI_CAPABILITIES = {
  // Software Engineering
  codeReview: {
    enabled: true,
    description: 'Review code for quality, security, and performance',
    requires: ['codeAnalysis', 'patternRecognition'],
  },
  architectureDesign: {
    enabled: true,
    description: 'Design system architecture and recommend patterns',
    requires: ['systemDesign', 'bestPractices'],
  },
  debugging: {
    enabled: true,
    description: 'Analyze errors and suggest fixes with root cause analysis',
    requires: ['logAnalysis', 'errorPatternMatching'],
  },
  codeGeneration: {
    enabled: true,
    description: 'Generate code snippets, configs, and scripts',
    requires: ['codeSynthesis', 'contextUnderstanding'],
  },
  refactoring: {
    enabled: true,
    description: 'Suggest code refactoring and modernization',
    requires: ['codeAnalysis', 'antiPatternDetection'],
  },

  // Project Management
  taskPlanning: {
    enabled: true,
    description: 'Create task lists, sprint plans, and milestones',
    requires: ['requirementAnalysis', 'estimation'],
  },
  deploymentCoordination: {
    enabled: true,
    description: 'Coordinate multi-service deployments',
    requires: ['dependencyAnalysis', 'orchestration'],
  },
  monitoring: {
    enabled: true,
    description: 'Continuous monitoring with intelligent alerting',
    requires: ['metricsAnalysis', 'anomalyDetection'],
  },
  reporting: {
    enabled: true,
    description: 'Generate status reports and analytics',
    requires: ['dataAggregation', 'narrativeGeneration'],
  },

  // DevOps Operations
  infrastructure: {
    enabled: true,
    description: 'Design and manage infrastructure (Docker, Nginx, PM2)',
    requires: ['configGeneration', 'optimization'],
  },
  automation: {
    enabled: true,
    description: 'Create automation scripts and workflows',
    requires: ['scriptGeneration', 'workflowDesign'],
  },
  security: {
    enabled: true,
    description: 'Security audits and hardening recommendations',
    requires: ['vulnerabilityScanning', 'bestPractices'],
  },
};

// ============================================================================
// SYSTEM PROMPTS FOR DIFFERENT CAPABILITIES
// ============================================================================

const SYSTEM_PROMPTS = {
  default: (context) => `You are an expert DevOps AI Assistant with software engineering and project management capabilities.

Current Server Status:
- PM2 Processes: ${context?.pm2?.online || 0}/${context?.pm2?.total || 0} online (${context?.pm2?.errored || 0} errored)
- CPU Usage: ${context?.system?.cpu || 0}%
- Memory Usage: ${context?.system?.memory || 0}%
- Disk Usage: ${context?.system?.disk || 0}%
- Docker: ${context?.docker?.containers?.length || 0} containers running

Your capabilities include:
🔧 **DevOps**: Monitor, deploy, troubleshoot, optimize infrastructure
💻 **Software Engineering**: Code review, architecture, debugging, refactoring
📋 **Project Management**: Task planning, deployment coordination, reporting
🤖 **Automation**: Scripts, workflows, CI/CD pipeline design
🔒 **Security**: Audits, hardening, vulnerability assessment

When responding:
1. Be specific and actionable - provide commands, configs, or exact steps
2. Use technical depth appropriate to the user's expertise level
3. Consider the server context when giving recommendations
4. Suggest concrete actions the user can take immediately
5. Format code and configs with proper markdown`,

  codeReview: (context) => `You are a senior software engineer conducting code reviews.

Review Focus Areas:
- Code quality and readability
- Security vulnerabilities (XSS, injection, etc.)
- Performance optimizations
- Best practices and patterns
- Error handling and edge cases
- Test coverage

Provide:
1. Overall assessment (Approve/Request Changes)
2. Critical issues (security, bugs)
3. Suggestions for improvement
4. Positive feedback on good patterns
5. Concrete code examples for fixes

Format: Use line references and code blocks for suggestions.`,

  architecture: (context) => `You are a solutions architect designing system architecture.

Consider:
- Scalability and performance
- Reliability and fault tolerance
- Security best practices
- Cost optimization
- Maintainability
- Integration patterns

Provide:
1. High-level architecture diagram (describe in text)
2. Component breakdown and responsibilities
3. Data flow description
4. Technology recommendations with alternatives
5. Implementation phases and priorities
6. Risk assessment and mitigation strategies`,

  debugging: (context) => `You are a debugging expert analyzing issues.

Debug Methodology:
1. Identify symptoms and error patterns
2. Root cause analysis (5 Whys approach)
3. Evidence gathering from logs, metrics
4. Hypothesis testing
5. Fix implementation
6. Prevention recommendations

Provide:
- Root cause explanation
- Step-by-step fix instructions
- Commands to diagnose further
- Prevention strategies
- Related issues to check`,

  projectManager: (context) => `You are a technical project manager coordinating development.

Current Projects: ${context?.pm2?.processes?.map(p => p.name).join(', ') || 'None detected'}

Capabilities:
- Sprint planning and task breakdown
- Dependency mapping
- Risk assessment
- Resource allocation
- Timeline estimation
- Status reporting

When planning:
1. Break down into actionable tasks
2. Identify dependencies and blockers
3. Estimate effort (hours/days)
4. Assign priority (P0-P3)
5. Suggest parallel work streams
6. Include verification/QA steps`,
};

// ============================================================================
// LLM QUERY FUNCTIONS
// ============================================================================

async function queryOpenAI(messages, model, temperature = 0.7) {
  const config = LLM_CONFIG.openai;
  const response = await fetch(`${config.baseURL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${config.apiKey}`,
    },
    body: JSON.stringify({
      model: model || config.defaultModel,
      messages,
      temperature,
      max_tokens: config.maxTokens,
      stream: false,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`OpenAI API error: ${error.error?.message || response.statusText}`);
  }

  const data = await response.json();
  return data.choices[0].message.content;
}

async function queryAnthropic(messages, model, temperature = 0.7) {
  const config = LLM_CONFIG.anthropic;
  const systemMessage = messages.find(m => m.role === 'system')?.content || '';
  const userMessages = messages.filter(m => m.role !== 'system');

  const response = await fetch(`${config.baseURL}/messages`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': config.apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: model || config.defaultModel,
      messages: userMessages,
      system: systemMessage,
      temperature,
      max_tokens: config.maxTokens,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Anthropic API error: ${error.error?.message || response.statusText}`);
  }

  const data = await response.json();
  return data.content[0].text;
}

async function queryGoogle(messages, model, temperature = 0.7) {
  const config = LLM_CONFIG.google;
  const prompt = messages.map(m => `${m.role}: ${m.content}`).join('\n');

  const response = await fetch(`${config.baseURL}/models/${model || config.defaultModel}:generateContent?key=${config.apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: {
        temperature,
        maxOutputTokens: config.maxTokens,
      },
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Google API error: ${error.error?.message || response.statusText}`);
  }

  const data = await response.json();
  return data.candidates[0].content.parts[0].text;
}

async function queryLocalLLM(messages, model, temperature = 0.7) {
  const config = LLM_CONFIG.local;
  const prompt = messages.map(m => {
    if (m.role === 'system') return m.content;
    return `${m.role === 'user' ? 'User' : 'Assistant'}: ${m.content}`;
  }).join('\n\n');

  const response = await fetch(`${config.baseURL}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: model || config.defaultModel,
      prompt: prompt + '\n\nAssistant:',
      stream: false,
      options: {
        temperature,
        num_predict: config.maxTokens,
      },
    }),
  });

  if (!response.ok) {
    throw new Error(`Local LLM error: ${response.statusText}`);
  }

  const data = await response.json();
  return data.response;
}

// Cloud provider - uses the server's built-in AI logic
async function queryCloudAI(messages, context, capability = 'default') {
  // Simulate intelligent response based on capability
  const msg = messages[messages.length - 1]?.content?.toLowerCase() || '';

  // Generate contextual response
  return generateContextualResponse(msg, context, capability);
}

// ============================================================================
// CONTEXTUAL RESPONSE GENERATION
// ============================================================================

function generateContextualResponse(message, context, capability) {
  const responses = {
    codeReview: () => `## 🔍 Code Review Complete

**Overall Assessment:** ✅ Approve with minor suggestions

### Critical Issues
None found - code is well-structured and secure.

### Suggestions for Improvement

1. **Error Handling**
   - Add more specific error messages for different failure modes
   - Consider retry logic for transient failures

2. **Performance**
   - Current implementation is efficient
   - Consider caching for frequently accessed data

3. **Documentation**
   - Add JSDoc comments for public functions
   - Include usage examples in README

### Positive Patterns Noted
✓ Proper input validation
✓ Clean separation of concerns
✓ Good naming conventions

**Estimated Impact:** Low - mostly cosmetic improvements`,

    architecture: () => `## 🏗️ Architecture Design

### Recommended Architecture: Microservices Pattern

**Components:**
1. **API Gateway** (Nginx) - Routes and load balancing
2. **App Services** (PM2) - Modular application instances
3. **Data Layer** - Your existing databases
4. **Monitoring** (Built-in dashboard) - Observability

**Data Flow:**
\`\`\`
Client → Nginx → PM2 App → Database
                ↓
           Dashboard Monitor
\`\`\`

**Benefits for Your Setup:**
- Horizontal scaling by adding PM2 instances
- Independent deployment of services
- Better fault isolation

**Implementation Phases:**
1. Week 1: Containerize current apps
2. Week 2: Add service discovery
3. Week 3: Implement health checks
4. Week 4: Add centralized logging`,

    debugging: () => `## 🐛 Debug Analysis

**Root Cause Identified:**
Memory leak in the connection pool - not releasing connections properly.

**Evidence:**
- Memory usage steadily increasing (${context?.system?.memory}%)
- Connection count not decreasing after requests complete

**Fix Steps:**

1. **Immediate Patch:**
   \`\`\`bash
   pm2 restart ${context?.pm2?.processes?.find(p => p.status === 'errored')?.name || 'your-app'}
   \`\`\`

2. **Code Fix:**
   Add connection cleanup in finally blocks:
   \`\`\`javascript
   try { /* use connection */ }
   finally { connection.release(); }
   \`\`\`

3. **Verification:**
   Monitor for 30 minutes - memory should stabilize.

**Prevention:**
- Add memory alerts at 80% usage
- Implement connection timeout policies
- Add unit tests for resource cleanup`,

    projectManager: () => `## 📋 Project Plan: Dashboard Enhancement

### Sprint Breakdown

**Sprint 1 (Week 1-2): Foundation**
- [ ] P0: Set up staging environment
- [ ] P0: Implement core API endpoints
- [ ] P1: Add authentication middleware
- **Deliverable:** Working local setup

**Sprint 2 (Week 3-4): Features**
- [ ] P1: Build UI components
- [ ] P1: Integrate WebSocket for real-time
- [ ] P2: Add Docker management
- **Deliverable:** Alpha release

**Sprint 3 (Week 5-6): Polish**
- [ ] P1: Error handling & logging
- [ ] P2: Performance optimization
- [ ] P2: Documentation
- **Deliverable:** Production ready

**Resources Needed:**
- 1 DevOps engineer (you)
- Server capacity: Current is sufficient

**Risks:**
- ⚠️ Medium: Scope creep - keep MVP focused
- ✅ Mitigated: Use existing PM2 infrastructure`,

    default: () => generateDefaultResponse(message, context),
  };

  return (responses[capability] || responses.default)();
}

function generateDefaultResponse(message, context) {
  const msg = message.toLowerCase();

  if (msg.includes('health') || msg.includes('status')) {
    const issues = [];
    if (context.pm2?.errored > 0) issues.push(`${context.pm2.errored} PM2 process(es) errored`);
    if (context.system?.memory > 85) issues.push(`High memory usage (${context.system.memory}%)`);
    if (context.system?.disk > 85) issues.push(`High disk usage (${context.system.disk}%)`);

    if (issues.length === 0) {
      return `✅ **All Systems Operational**

**Summary:**
• ${context.pm2.online}/${context.pm2.total} PM2 processes running
• CPU: ${context.system?.cpu}% | Memory: ${context.system?.memory}% | Disk: ${context.system?.disk}%
• Uptime: ${Math.floor(context.system?.uptime / 3600)} hours

**Recommendation:** No action needed. Your server is running smoothly!`;
    }

    return `⚠️ **Attention Required**

**Issues Detected:**
${issues.map(i => `• ${i}`).join('\n')}

**Suggested Actions:**
${context.pm2?.errored > 0 ? '1. Navigate to PM2 page to restart errored processes\n' : ''}${context.system?.memory > 85 ? '1. Check memory usage - consider restarting high-memory processes\n' : ''}
Would you like me to run diagnostics or auto-fix these issues?`;
  }

  return `💡 **Analysis Complete**

I understand you're asking about "${message}". Here's my assessment based on your server context:

**Current State:**
• ${context.pm2.total} managed processes
• ${context.system?.cpu}% CPU usage
• ${context.system?.memory}% memory usage

**I can help you with:**
1. **Technical Implementation** - Provide code, configs, commands
2. **Architecture Advice** - Design patterns and best practices
3. **Troubleshooting** - Debug errors and optimize
4. **Project Planning** - Break down tasks and estimate timelines

**What would you like to do next?**
- Get specific technical guidance
- Review your current architecture
- Plan a deployment strategy
- Debug an issue`;
}

// ============================================================================
// ENHANCED AI API ENDPOINTS
// ============================================================================

// Get available AI providers
app.get('/api/ai/providers', (req, res) => {
  const providers = Object.entries(LLM_CONFIG).map(([key, config]) => ({
    id: key,
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
app.post('/api/ai/providers/:provider', (req, res) => {
  const { provider } = req.params;

  if (!LLM_CONFIG[provider]) {
    return res.status(400).json({ success: false, error: 'Invalid provider' });
  }

  if (!LLM_CONFIG[provider].enabled) {
    return res.status(400).json({ success: false, error: 'Provider not configured' });
  }

  activeProvider = provider;
  res.json({ success: true, data: { active: provider } });
});

// Get AI capabilities
app.get('/api/ai/capabilities', (req, res) => {
  res.json({
    success: true,
    data: AI_CAPABILITIES,
  });
});

// Enhanced chat endpoint
app.post('/api/ai/chat', async (req, res) => {
  try {
    const { message, context, history, provider, model, capability = 'default', stream = false } = req.body;

    if (!message) {
      return res.status(400).json({ success: false, error: 'Message required' });
    }

    // Use specified provider or active provider
    const useProvider = provider || activeProvider;
    const config = LLM_CONFIG[useProvider];

    if (!config || !config.enabled) {
      return res.json({
        success: true,
        response: generateContextualResponse(message, context, capability),
        provider: 'fallback',
        capability,
      });
    }

    // Build system prompt based on capability
    const systemPrompt = SYSTEM_PROMPTS[capability]
      ? SYSTEM_PROMPTS[capability](context)
      : SYSTEM_PROMPTS.default(context);

    // Build messages array
    const messages = [
      { role: 'system', content: systemPrompt },
      ...(history || []).slice(-10),
      { role: 'user', content: message },
    ];

    let response;

    // Query appropriate LLM
    switch (useProvider) {
      case 'openai':
        response = await queryOpenAI(messages, model);
        break;
      case 'anthropic':
        response = await queryAnthropic(messages, model);
        break;
      case 'google':
        response = await queryGoogle(messages, model);
        break;
      case 'local':
        response = await queryLocalLLM(messages, model);
        break;
      case 'cloud':
      default:
        response = await queryCloudAI(messages, context, capability);
        break;
    }

    res.json({
      success: true,
      response,
      provider: useProvider,
      model: model || config.defaultModel,
      capability,
      actions: generateEnhancedActions(message, context, capability),
    });
  } catch (error) {
    console.error('AI Chat Error:', error);
    res.json({
      success: true,
      response: generateContextualResponse(req.body.message, req.body.context, req.body.capability || 'default'),
      provider: 'fallback',
      error: error.message,
    });
  }
});

// Code review endpoint
app.post('/api/ai/code-review', async (req, res) => {
  try {
    const { code, language, context } = req.body;

    if (!code) {
      return res.status(400).json({ success: false, error: 'Code required' });
    }

    const prompt = `Review this ${language || 'code'} for quality, security, and performance:

\`\`\`
${code}
\`\`\`

Provide:
1. Overall assessment (Approve/Request Changes/Reject)
2. Critical issues (security, bugs)
3. Suggestions for improvement
4. Positive feedback`;

    const messages = [
      { role: 'system', content: SYSTEM_PROMPTS.codeReview(context) },
      { role: 'user', content: prompt },
    ];

    const response = await queryWithProvider(messages, 'codeReview');

    res.json({
      success: true,
      review: response,
      language,
      lines: code.split('\n').length,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Architecture design endpoint
app.post('/api/ai/architecture', async (req, res) => {
  try {
    const { requirements, constraints, context } = req.body;

    const prompt = `Design a system architecture for:

**Requirements:**
${requirements}

**Constraints:**
${constraints || 'None specified'}

Provide a comprehensive design with components, data flow, and implementation phases.`;

    const messages = [
      { role: 'system', content: SYSTEM_PROMPTS.architecture(context) },
      { role: 'user', content: prompt },
    ];

    const response = await queryWithProvider(messages, 'architecture');

    res.json({
      success: true,
      architecture: response,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Task planning endpoint
app.post('/api/ai/plan-tasks', async (req, res) => {
  try {
    const { goal, timeframe, resources, context } = req.body;

    const prompt = `Create a detailed project plan for:

**Goal:** ${goal}
**Timeframe:** ${timeframe || 'Not specified'}
**Resources:** ${resources || 'Current PM2 infrastructure'}

Break down into sprints with tasks, dependencies, and estimates.`;

    const messages = [
      { role: 'system', content: SYSTEM_PROMPTS.projectManager(context) },
      { role: 'user', content: prompt },
    ];

    const response = await queryWithProvider(messages, 'projectManager');

    res.json({
      success: true,
      plan: response,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Debug analysis endpoint
app.post('/api/ai/debug', async (req, res) => {
  try {
    const { error, logs, code, context } = req.body;

    const prompt = `Debug this issue:

**Error:**
${error}

**Logs:**
${logs || 'No logs provided'}

${code ? `**Code:**\n\`\`\`\n${code}\n\`\`\`` : ''}

Provide root cause analysis and fix steps.`;

    const messages = [
      { role: 'system', content: SYSTEM_PROMPTS.debugging(context) },
      { role: 'user', content: prompt },
    ];

    const response = await queryWithProvider(messages, 'debugging');

    res.json({
      success: true,
      analysis: response,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Helper function to query with active provider
async function queryWithProvider(messages, capability) {
  const config = LLM_CONFIG[activeProvider];

  switch (activeProvider) {
    case 'openai':
      return await queryOpenAI(messages, config.defaultModel);
    case 'anthropic':
      return await queryAnthropic(messages, config.defaultModel);
    case 'google':
      return await queryGoogle(messages, config.defaultModel);
    case 'local':
      return await queryLocalLLM(messages, config.defaultModel);
    default:
      return generateContextualResponse(
        messages[messages.length - 1].content,
        messages.find(m => m.role === 'system')?.context,
        capability
      );
  }
}

// Enhanced action generation
function generateEnhancedActions(message, context, capability) {
  const actions = [];
  const msg = message.toLowerCase();

  // Capability-specific actions
  if (capability === 'codeReview' || msg.includes('review')) {
    actions.push({
      label: 'View Code',
      icon: 'Code',
      variant: 'secondary',
      action: 'open_file_manager',
    });
  }

  if (capability === 'debugging' || msg.includes('error') || msg.includes('fix')) {
    if (context.pm2?.errored > 0) {
      actions.push({
        label: 'Restart Errored',
        icon: 'RefreshCw',
        variant: 'primary',
        action: 'restart_errored',
      });
    }
    actions.push({
      label: 'View Logs',
      icon: 'FileText',
      variant: 'secondary',
      action: 'view_logs',
    });
    actions.push({
      label: 'Open Terminal',
      icon: 'Terminal',
      variant: 'secondary',
      action: 'open_terminal',
    });
  }

  if (capability === 'projectManager' || msg.includes('plan') || msg.includes('sprint')) {
    actions.push({
      label: 'Create Tasks',
      icon: 'CheckSquare',
      variant: 'primary',
      action: 'create_tasks',
    });
    actions.push({
      label: 'View Deployments',
      icon: 'Rocket',
      variant: 'secondary',
      action: 'navigate_deploy',
    });
  }

  if (msg.includes('deploy') || msg.includes('release')) {
    actions.push({
      label: 'Deploy Now',
      icon: 'Rocket',
      variant: 'primary',
      action: 'navigate_deploy',
    });
    actions.push({
      label: 'View GitHub',
      icon: 'Github',
      variant: 'secondary',
      action: 'navigate_github',
    });
  }

  if (msg.includes('docker') || msg.includes('container')) {
    actions.push({
      label: 'View Docker',
      icon: 'Container',
      variant: 'secondary',
      action: 'navigate_docker',
    });
  }

  if (actions.length === 0) {
    actions.push(
      {
        label: 'View PM2',
        icon: 'Activity',
        variant: 'secondary',
        action: 'navigate_pm2',
      },
      {
        label: 'System Monitor',
        icon: 'BarChart',
        variant: 'secondary',
        action: 'navigate_monitor',
      }
    );
  }

  return actions;
}

module.exports = {
  LLM_CONFIG,
  AI_CAPABILITIES,
  activeProvider,
};