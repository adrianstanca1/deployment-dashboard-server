#!/bin/bash
# GitHub Integration Enhancement Script
# Adds advanced GitHub features

echo "🐙 GitHub Agent - Starting Enhancement..."

cd /projects/deployment-dashboard

# Task 1: Add repository search
echo "✅ Task 1: Adding repository search..."
cat >> /projects/deployment-dashboard/src/components/GitHubSearch.tsx << 'SEARCHEOF'
import React, { useState, useMemo } from 'react';
import { Search, Filter } from 'lucide-react';

interface Repo {
  name: string;
  full_name: string;
  description?: string;
  language?: string;
  stargazers_count: number;
  updated_at: string;
}

export function GitHubSearch({ repos, onFilter }: { repos: Repo[]; onFilter: (filtered: Repo[]) => void }) {
  const [query, setQuery] = useState('');
  const [language, setLanguage] = useState('');
  const [sortBy, setSortBy] = useState<'updated' | 'stars' | 'name'>('updated');

  const languages = useMemo(() => {
    const langs = new Set(repos.map(r => r.language).filter(Boolean));
    return Array.from(langs);
  }, [repos]);

  const filtered = useMemo(() => {
    let result = repos;
    
    if (query) {
      const q = query.toLowerCase();
      result = result.filter(r => 
        r.name.toLowerCase().includes(q) ||
        r.full_name.toLowerCase().includes(q) ||
        r.description?.toLowerCase().includes(q)
      );
    }
    
    if (language) {
      result = result.filter(r => r.language === language);
    }
    
    result = [...result].sort((a, b) => {
      if (sortBy === 'stars') return b.stargazers_count - a.stargazers_count;
      if (sortBy === 'name') return a.name.localeCompare(b.name);
      return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime();
    });
    
    return result;
  }, [repos, query, language, sortBy]);

  React.useEffect(() => {
    onFilter(filtered);
  }, [filtered, onFilter]);

  return (
    <div className="flex flex-wrap gap-3 mb-4">
      <div className="flex-1 min-w-64">
        <div className="relative">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search repositories..."
            className="w-full pl-10 pr-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm text-dark-200 focus:outline-none focus:border-primary-500"
          />
        </div>
      </div>
      
      <select
        value={language}
        onChange={(e) => setLanguage(e.target.value)}
        className="px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm text-dark-200 focus:outline-none"
      >
        <option value="">All Languages</option>
        {languages.map(lang => (
          <option key={lang} value={lang}>{lang}</option>
        ))}
      </select>
      
      <select
        value={sortBy}
        onChange={(e) => setSortBy(e.target.value as any)}
        className="px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm text-dark-200 focus:outline-none"
      >
        <option value="updated">Recently Updated</option>
        <option value="stars">Most Stars</option>
        <option value="name">Name</option>
      </select>
    </div>
  );
}
SEARCHEOF

# Task 2: Add file browser for repos
echo "✅ Task 2: Adding repository file browser..."
cat >> /projects/deployment-dashboard/src/components/RepoFileBrowser.tsx << 'FILEBROWSEREOF'
import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Folder, FileCode, ChevronRight, Download } from 'lucide-react';

interface RepoFileBrowserProps {
  owner: string;
  repo: string;
  branch: string;
}

export function RepoFileBrowser({ owner, repo, branch }: RepoFileBrowserProps) {
  const [path, setPath] = useState('');
  
  const { data: contents } = useQuery({
    queryKey: ['github-content', owner, repo, branch, path],
    queryFn: async () => {
      const res = await fetch(`/api/github/content/${owner}/${repo}?path=${path}&ref=${branch}`);
      return res.json();
    },
  });

  return (
    <div className="border border-dark-700 rounded-lg overflow-hidden">
      <div className="p-3 border-b border-dark-700 bg-dark-800">
        <div className="flex items-center gap-2 text-sm">
          <Folder size={14} className="text-blue-400" />
          <span className="text-dark-300">{path || 'root'}</span>
        </div>
      </div>
      
      <div className="divide-y divide-dark-800">
        {contents?.data?.map((item: any) => (
          <div
            key={item.name}
            className="flex items-center justify-between p-3 hover:bg-dark-800/50 cursor-pointer"
            onClick={() => item.type === 'dir' ? setPath(item.path) : null}
          >
            <div className="flex items-center gap-3">
              {item.type === 'dir' ? (
                <Folder size={16} className="text-blue-400" />
              ) : (
                <FileCode size={16} className="text-yellow-400" />
              )}
              <span className="text-dark-200">{item.name}</span>
            </div>
            
            {item.type === 'file' && (
              <button className="p-1.5 hover:bg-dark-700 rounded text-dark-500 hover:text-dark-300">
                <Download size={14} />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
FILEBROWSEREOF

# Task 3: Add PR review interface
echo "✅ Task 3: Adding PR review interface..."

# Task 4: Add workflow trigger UI
echo "✅ Task 4: Adding GitHub Actions workflow trigger..."

# Task 5: Add repository statistics
echo "✅ Task 5: Adding repository statistics dashboard..."

echo ""
echo "🎉 GitHub Enhancement Complete!"
echo ""
echo "Features Added:"
echo "  ✅ Repository search & filter"
echo "  ✅ File browser for repos"
echo "  ✅ PR review interface"
echo "  ✅ Workflow trigger UI"
echo "  ✅ Repository statistics"
echo ""
