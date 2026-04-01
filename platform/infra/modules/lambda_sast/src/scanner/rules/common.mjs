/**
 * Common rules — language-agnostic patterns applied to all supported file types.
 */

const LANG_MAP = {
  '.js':   'javascript',
  '.mjs':  'javascript',
  '.cjs':  'javascript',
  '.jsx':  'javascript',
  '.ts':   'javascript',
  '.tsx':  'javascript',
  '.py':   'python',
  '.java': 'java',
  '.go':   'go',
};

export function detectLanguage(filename) {
  const ext = filename.slice(filename.lastIndexOf('.')).toLowerCase();
  return LANG_MAP[ext] ?? 'unknown';
}

export const COMMON_RULES = [
  {
    id: 'HARDCODED_SECRET', name: 'Hardcoded Secret', severity: 'HIGH',
    patterns: [
      { regex: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/gi, desc: 'Hardcoded API key' },
      { regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi, desc: 'Hardcoded password' },
      { regex: /(?:secret[_-]?key|secretkey)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/gi, desc: 'Hardcoded secret key' },
      { regex: /(?:access[_-]?token|accesstoken)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/gi, desc: 'Hardcoded access token' },
      { regex: /(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['"][A-Z0-9]{20}['"]/gi, desc: 'AWS Access Key ID' },
      { regex: /(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi, desc: 'AWS Secret Access Key' },
      { regex: /['"]sk[_-]live[_-][a-zA-Z0-9]{24,}['"]/g, desc: 'Stripe secret key' },
      { regex: /['"]ghp_[a-zA-Z0-9]{36,}['"]/g, desc: 'GitHub personal access token' },
    ],
    message: 'Hardcoded secret detected. Move secrets to environment variables or a secrets manager.'
  },
  {
    id: 'HARDCODED_IP', name: 'Hardcoded IP Address', severity: 'MEDIUM',
    patterns: [
      { regex: /['"](?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)['"]/g, desc: 'Hardcoded IPv4 address' },
      { regex: /['"](?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d+['"]/g, desc: 'Hardcoded IP with port' },
    ],
    message: 'Hardcoded IP address found. Use environment variables or configuration files.'
  },
];
