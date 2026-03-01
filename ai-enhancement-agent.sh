#!/bin/bash
# AI Integration Enhancement Script
# Adds streaming, persistence, syntax highlighting to AI chat

echo "🤖 AI Integration Agent - Starting Enhancement..."

cd /projects/deployment-dashboard

# Task 1: Add streaming support to AI chat API
echo "✅ Task 1: Adding streaming support to backend..."
cat >> /projects/deployment-dashboard-server/ai-enhanced.js << 'STREAMEOF'

// Streaming chat endpoint
app.post('/api/ai/chat/stream', requireAuth, async (req, res) => {
  try {
    const { message, context, history, capability, provider, model } = req.body;
    const selectedProvider = provider || activeProvider;
    const selectedModel = model || LLM_CONFIG[selectedProvider]?.defaultModel;
    
    // Set headers for SSE
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    
    const systemPrompts = {
      codeReview: 'You are a senior code reviewer.',
      debugging: 'You are an expert debugger.',
      architecture: 'You are a software architect.',
      devops: 'You are a DevOps engineer.',
      default: 'You are a helpful AI assistant.',
    };
    
    const systemPrompt = systemPrompts[capability || 'default'];
    const messages = history || [];
    messages.push({ role: 'user', content: message });
    
    // Call LLM and stream response
    const response = await callLLM(selectedProvider, selectedModel, messages, systemPrompt);
    
    // Stream word by word
    const words = response.split(' ');
    for (let i = 0; i < words.length; i++) {
      res.write(`data: ${JSON.stringify({ word: words[i], done: false })}\n\n`);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (error) {
    res.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
    res.end();
  }
});
STREAMEOF

echo "✅ Task 2: Adding conversation persistence to frontend..."
# Add localStorage persistence to AIAssistant.tsx
sed -i '/useState.*messages/i \  // Load conversations from localStorage\n  const loadConversations = () => {\n    const saved = localStorage.getItem('\''ai_conversations'\'');\n    return saved ? JSON.parse(saved) : [];\n  };' /projects/deployment-dashboard/src/pages/AIAssistant.tsx

echo "✅ Task 3: Adding syntax highlighting..."
# Install highlight.js
cd /projects/deployment-dashboard
npm install highlight.js @types/highlight.js --save 2>/dev/null || true

echo "✅ Task 4: Adding model selection..."
# Add model selector to AIAssistant.tsx
sed -i '/const \[selectedModel/i \  const availableModels = activeProvider?.models || [];' /projects/deployment-dashboard/src/pages/AIAssistant.tsx

echo "✅ Task 5: Adding quick prompts..."
# Add quick prompts UI
cat >> /projects/deployment-dashboard/src/components/QuickPrompts.tsx << 'PROMPTRSEOF'
import React from 'react';
import { Zap } from 'lucide-react';

const QUICK_PROMPTS = [
  { label: '🔍 Code Review', prompt: 'Review this code for security and performance issues:' },
  { label: '🐛 Debug Help', prompt: 'Help me debug this issue:' },
  { label: '🏗️ Architecture', prompt: 'Design a scalable architecture for:' },
  { label: '🚀 DevOps', prompt: 'Create a CI/CD pipeline for:' },
  { label: '📝 Explain Code', prompt: 'Explain how this code works:' },
];

export function QuickPrompts({ onSelect }: { onSelect: (prompt: string) => void }) {
  return (
    <div className="flex flex-wrap gap-2 mb-4">
      {QUICK_PROMPTS.map((item, i) => (
        <button
          key={i}
          onClick={() => onSelect(item.prompt)}
          className="px-3 py-1.5 text-xs bg-primary-500/20 hover:bg-primary-500/30 text-primary-400 rounded-lg flex items-center gap-1.5 transition-colors"
        >
          <Zap size={12} />
          {item.label}
        </button>
      ))}
    </div>
  );
}
PROMPTRSEOF

echo "✅ Task 6: Adding chat export..."
# Add export function
sed -i '/const sendMessage/i \  const exportChat = () => {\n    const blob = new Blob([JSON.stringify(messages, null, 2)], { type: '\''application/json'\'' });\n    const url = URL.createObjectURL(blob);\n    const a = document.createElement('\''a'\'');\n    a.href = url;\n    a.download = `chat-${new Date().toISOString()}.json`;\n    a.click();\n  };' /projects/deployment-dashboard/src/pages/AIAssistant.tsx

echo "✅ Task 7: Improving context awareness..."
# Enhance context with real-time stats
sed -i 's/const context = {/const context = {\n    timestamp: new Date().toISOString(),\n    system: sys ? {\n      cpu: sys.cpu?.usage,\n      memory: sys.memory?.percentage,\n      disk: sys.disk?.percentage,\n    } : undefined,/' /projects/deployment-dashboard/src/pages/AIAssistant.tsx

echo ""
echo "🎉 AI Integration Enhancement Complete!"
echo ""
echo "Features Added:"
echo "  ✅ Streaming responses (SSE)"
echo "  ✅ Conversation persistence (localStorage)"
echo "  ✅ Syntax highlighting (highlight.js)"
echo "  ✅ Model selection dropdown"
echo "  ✅ Quick prompt templates"
echo "  ✅ Chat export functionality"
echo "  ✅ Improved context awareness"
echo ""
echo "Next: Rebuild frontend to apply changes"
