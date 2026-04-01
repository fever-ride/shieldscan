/**
 * Python rules.
 */

export const PYTHON_RULES = [
  {
    id: 'SQL_INJECTION', name: 'SQL Injection Risk', severity: 'HIGH',
    patterns: [
      { regex: /execute\s*\(\s*f['"].*\{/gi, desc: 'f-string in SQL execute()' },
      { regex: /execute\s*\(\s*['"].*%\s*(?:\w|\()/gi, desc: '% formatting in SQL execute()' },
      { regex: /execute\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE).*\+/gi, desc: 'String concatenation in SQL execute()' },
      { regex: /cursor\.execute\s*\(\s*["'].*["']\s*%/gi, desc: '% interpolation in cursor.execute()' },
    ],
    message: 'Potential SQL injection. Use parameterized queries with placeholders (?, %s) instead.'
  },
  {
    id: 'XSS', name: 'Cross-Site Scripting (XSS)', severity: 'HIGH',
    patterns: [
      { regex: /\|\s*safe\b/g, desc: 'Jinja2 |safe filter bypasses escaping' },
      { regex: /Markup\s*\(/g, desc: 'Flask Markup() marks string as safe HTML' },
      { regex: /mark_safe\s*\(/g, desc: 'Django mark_safe() bypasses escaping' },
    ],
    message: 'Potential XSS. Avoid bypassing template auto-escaping unless input is fully sanitized.'
  },
  {
    id: 'PATH_TRAVERSAL', name: 'Path Traversal', severity: 'HIGH',
    patterns: [
      { regex: /open\s*\(\s*(?:request|req)\./gi, desc: 'User input directly in open()' },
      { regex: /open\s*\(\s*f['"].*\{(?:request|req)\./gi, desc: 'User input via f-string in open()' },
      { regex: /os\.path\.join\s*\([^)]*(?:request|req)\./gi, desc: 'User input in os.path.join()' },
      { regex: /['"][^'"]*\.\.\/[^'"]*['"]/g, desc: 'Path traversal sequence detected' },
    ],
    message: 'Potential path traversal. Validate and sanitize file paths.'
  },
  {
    id: 'INSECURE_FUNCTION', name: 'Insecure Function Usage', severity: 'HIGH',
    patterns: [
      { regex: /\beval\s*\(/g, desc: 'Usage of eval()' },
      { regex: /\bexec\s*\(/g, desc: 'Usage of exec()' },
      { regex: /pickle\.loads?\s*\(/g, desc: 'pickle.load() deserializes arbitrary objects' },
      { regex: /subprocess\.[a-z_]+\s*\([^)]*shell\s*=\s*True/gi, desc: 'subprocess with shell=True' },
      { regex: /os\.system\s*\(/g, desc: 'Usage of os.system()' },
      { regex: /yaml\.load\s*\([^)]*\)/g, desc: 'yaml.load() without Loader is unsafe' },
    ],
    message: 'Insecure function detected. This can lead to arbitrary code execution.'
  },
  {
    id: 'INSECURE_RANDOM', name: 'Insecure Randomness', severity: 'MEDIUM',
    patterns: [
      { regex: /\brandom\.random\s*\(\s*\)/g, desc: 'random.random() is not cryptographically secure' },
      { regex: /\brandom\.randint\s*\(/g, desc: 'random.randint() is not cryptographically secure' },
      { regex: /\brandom\.choice\s*\(/g, desc: 'random.choice() is not cryptographically secure' },
    ],
    message: 'The random module is not cryptographically secure. Use the secrets module instead.'
  },
  {
    id: 'WEAK_CRYPTO', name: 'Weak Cryptography', severity: 'MEDIUM',
    patterns: [
      { regex: /hashlib\.md5\s*\(/g, desc: 'MD5 hash usage' },
      { regex: /hashlib\.sha1\s*\(/g, desc: 'SHA1 hash usage' },
      { regex: /Crypto\.Cipher\.DES/g, desc: 'DES encryption usage' },
      { regex: /\b(?:DES|RC4|RC2|Blowfish)\b/gi, desc: 'Weak encryption algorithm' },
    ],
    message: 'Weak cryptographic algorithm detected. Use SHA-256 or AES instead.'
  },
  {
    id: 'SENSITIVE_DATA_LOG', name: 'Sensitive Data Logging', severity: 'MEDIUM',
    patterns: [
      { regex: /print\s*\([^)]*(?:password|passwd|pwd)[^)]*\)/gi, desc: 'Printing password' },
      { regex: /print\s*\([^)]*(?:token|secret|api_key)[^)]*\)/gi, desc: 'Printing sensitive token/key' },
      { regex: /logging\.\w+\s*\([^)]*(?:password|passwd|token|secret)[^)]*\)/gi, desc: 'Logging sensitive data' },
    ],
    message: 'Sensitive data may be logged. Remove or mask sensitive information.'
  },
];
