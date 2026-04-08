/**
 * Agent tools — GitHub API wrappers.
 * All return strings (tool results must be strings in Anthropic API).
 *
 * Revision pinning:
 *   get_file_context and get_directory_tree accept a `ref` parameter (branch/commit SHA)
 *   so the agent queries the exact version that was scanned, not the latest default branch.
 *
 *   search_code does NOT support ref-level pinning — GitHub code search API operates on
 *   the default branch only. This is a known limitation; results may differ from the
 *   scanned revision. The agent prompt documents this.
 */

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

function githubHeaders() {
  return {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'shieldscan-agent',
    ...(GITHUB_TOKEN && { Authorization: `Bearer ${GITHUB_TOKEN}` }),
  };
}

async function getFileContext({ repo, path, ref = 'main', start_line = 1, end_line = 60 }) {
  const res = await fetch(
    `https://api.github.com/repos/${repo}/contents/${encodeURIComponent(path)}?ref=${ref}`,
    { headers: githubHeaders() }
  );
  if (!res.ok) throw new Error(`GitHub contents ${res.status}: ${path}`);
  const data = await res.json();
  const code  = Buffer.from(data.content, 'base64').toString('utf-8');
  const lines = code.split('\n');
  const start = Math.max(0, start_line - 1);
  const end   = Math.min(lines.length, end_line);
  return lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join('\n');
}

// NOTE: GitHub code search does not support branch-level pinning.
// Results reflect the default branch at query time, not the scanned ref.
async function searchCode({ repo, query }) {
  const q   = encodeURIComponent(`${query} repo:${repo}`);
  const res = await fetch(
    `https://api.github.com/search/code?q=${q}&per_page=5`,
    { headers: githubHeaders() }
  );
  if (!res.ok) throw new Error(`GitHub search ${res.status}`);
  const data = await res.json();
  return JSON.stringify(
    (data.items ?? []).map(item => ({ path: item.path, url: item.html_url }))
  );
}

async function getDirectoryTree({ repo, ref = 'main', path = '' }) {
  const url = path
    ? `https://api.github.com/repos/${repo}/contents/${path}?ref=${ref}`
    : `https://api.github.com/repos/${repo}/git/trees/${ref}?recursive=1`;
  const res = await fetch(url, { headers: githubHeaders() });
  if (!res.ok) throw new Error(`GitHub trees ${res.status}`);
  const data = await res.json();
  if (Array.isArray(data)) {
    return data.map(f => `${f.type === 'dir' ? 'dir' : 'file'} ${f.path}`).join('\n');
  }
  return (data.tree ?? [])
    .filter(f => f.type === 'blob')
    .map(f => f.path)
    .slice(0, 200)
    .join('\n');
}

export const TOOL_DEFINITIONS = [
  {
    name: 'get_file_context',
    description: 'Fetch specific lines from a file in a GitHub repository at a given ref.',
    input_schema: {
      type: 'object',
      properties: {
        repo:       { type: 'string',  description: 'owner/repo' },
        path:       { type: 'string',  description: 'file path within repo' },
        ref:        { type: 'string',  description: 'branch or commit SHA to pin the query (use the branch from the finding)' },
        start_line: { type: 'integer', description: 'first line to return (1-based, default 1)' },
        end_line:   { type: 'integer', description: 'last line to return inclusive (default 60)' },
      },
      required: ['repo', 'path'],
    },
  },
  {
    name: 'search_code',
    description: 'Search for a pattern or symbol across a GitHub repository. Note: searches the default branch only — results may differ from the scanned ref.',
    input_schema: {
      type: 'object',
      properties: {
        repo:  { type: 'string', description: 'owner/repo' },
        query: { type: 'string', description: 'search query — keywords or symbol names' },
      },
      required: ['repo', 'query'],
    },
  },
  {
    name: 'get_directory_tree',
    description: 'List files in a GitHub repository or subdirectory at a given ref.',
    input_schema: {
      type: 'object',
      properties: {
        repo: { type: 'string', description: 'owner/repo' },
        ref:  { type: 'string', description: 'branch or commit SHA (use the branch from the finding)' },
        path: { type: 'string', description: 'subdirectory path (optional, omit for repo root)' },
      },
      required: ['repo'],
    },
  },
];

/** Dispatch a tool call and always return a string result (errors included). */
export async function callTool(name, input) {
  try {
    switch (name) {
      case 'get_file_context':   return await getFileContext(input);
      case 'search_code':        return await searchCode(input);
      case 'get_directory_tree': return await getDirectoryTree(input);
      default:                   return `Unknown tool: ${name}`;
    }
  } catch (err) {
    return `Tool error (${name}): ${err.message}`;
  }
}
