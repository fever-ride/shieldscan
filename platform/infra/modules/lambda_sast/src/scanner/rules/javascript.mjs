/**
 * JavaScript / TypeScript rules.
 */

export const JS_RULES = [
  {
    id: 'SQL_INJECTION', name: 'SQL Injection Risk', severity: 'HIGH',
    patterns: [
      { regex: /query\s*\(\s*['"`]SELECT.*\+/gi, desc: 'String concatenation in SELECT query' },
      { regex: /query\s*\(\s*['"`]INSERT.*\+/gi, desc: 'String concatenation in INSERT query' },
      { regex: /query\s*\(\s*['"`]UPDATE.*\+/gi, desc: 'String concatenation in UPDATE query' },
      { regex: /query\s*\(\s*['"`]DELETE.*\+/gi, desc: 'String concatenation in DELETE query' },
      { regex: /execute\s*\(\s*['"`].*\$\{/gi, desc: 'Template literal in SQL execute' },
      { regex: /query\s*\(\s*`[^`]*\$\{/gi, desc: 'Template literal in SQL query' },
    ],
    message: 'Potential SQL injection. Use parameterized queries instead of string concatenation.'
  },
  {
    id: 'NOSQL_INJECTION', name: 'NoSQL Injection Risk', severity: 'HIGH',
    patterns: [
      { regex: /\.find\s*\(\s*\{[^}]*\$where/gi, desc: '$where operator in MongoDB query' },
      { regex: /\.find\s*\(\s*\{[^}]*\$regex\s*:\s*[^/'"]/gi, desc: 'Unsanitized $regex in query' },
      { regex: /\.find\s*\(\s*req\.(body|query|params)/gi, desc: 'Direct user input in MongoDB find()' },
      { regex: /\.findOne\s*\(\s*req\.(body|query|params)/gi, desc: 'Direct user input in MongoDB findOne()' },
      { regex: /\.updateOne\s*\(\s*req\.(body|query|params)/gi, desc: 'Direct user input in MongoDB updateOne()' },
      { regex: /\.deleteOne\s*\(\s*req\.(body|query|params)/gi, desc: 'Direct user input in MongoDB deleteOne()' },
    ],
    message: 'Potential NoSQL injection. Sanitize user input before using in database queries.'
  },
  {
    id: 'XSS', name: 'Cross-Site Scripting (XSS)', severity: 'HIGH',
    patterns: [
      { regex: /\.innerHTML\s*=\s*[^'"]/gi, desc: 'Dynamic innerHTML assignment' },
      { regex: /\.outerHTML\s*=\s*[^'"]/gi, desc: 'Dynamic outerHTML assignment' },
      { regex: /document\.write\s*\(/gi, desc: 'Usage of document.write()' },
      { regex: /document\.writeln\s*\(/gi, desc: 'Usage of document.writeln()' },
      { regex: /\.insertAdjacentHTML\s*\(/gi, desc: 'Usage of insertAdjacentHTML()' },
      { regex: /dangerouslySetInnerHTML/gi, desc: 'React dangerouslySetInnerHTML usage' },
    ],
    message: 'Potential XSS vulnerability. Sanitize user input before rendering in HTML.'
  },
  {
    id: 'PATH_TRAVERSAL', name: 'Path Traversal', severity: 'HIGH',
    patterns: [
      { regex: /fs\.(readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync)\s*\(\s*req\.(body|query|params)/gi, desc: 'User input directly in file operation' },
      { regex: /fs\.(readFile|readFileSync|writeFile|writeFileSync)\s*\([^)]*\+\s*req\./gi, desc: 'User input concatenated in file path' },
      { regex: /path\.join\s*\([^)]*req\.(body|query|params)/gi, desc: 'User input in path.join()' },
      { regex: /['"][^'"]*\.\.\/[^'"]*['"]/g, desc: 'Path traversal sequence detected' },
    ],
    message: 'Potential path traversal. Validate and sanitize file paths.'
  },
  {
    id: 'INSECURE_RANDOM', name: 'Insecure Randomness', severity: 'MEDIUM',
    patterns: [
      { regex: /Math\.random\s*\(\s*\)/g, desc: 'Math.random() is not cryptographically secure' },
      { regex: /Math\.random\s*\(\s*\).*(?:token|password|secret|key|auth|session)/gi, desc: 'Math.random() used for security-sensitive value' },
    ],
    message: 'Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.randomUUID().'
  },
  {
    id: 'SENSITIVE_DATA_LOG', name: 'Sensitive Data Logging', severity: 'MEDIUM',
    patterns: [
      { regex: /console\.(log|info|debug|warn|error)\s*\([^)]*(?:password|passwd|pwd)[^)]*\)/gi, desc: 'Logging password' },
      { regex: /console\.(log|info|debug|warn|error)\s*\([^)]*(?:token|secret|apikey|api_key)[^)]*\)/gi, desc: 'Logging sensitive token/key' },
      { regex: /console\.(log|info|debug|warn|error)\s*\([^)]*(?:creditcard|credit_card|ssn|social_security)[^)]*\)/gi, desc: 'Logging sensitive personal data' },
    ],
    message: 'Sensitive data may be logged. Remove or mask sensitive information in logs.'
  },
  {
    id: 'INSECURE_FUNCTION', name: 'Insecure Function Usage', severity: 'HIGH',
    patterns: [
      { regex: /\beval\s*\(/g, desc: 'Usage of eval()' },
      { regex: /\bexecSync\s*\(/g, desc: 'Usage of execSync()' },
      { regex: /\bspawn\s*\([^)]*\$\{/g, desc: 'Unvalidated input in spawn()' },
      { regex: /new\s+Function\s*\(/g, desc: 'Usage of new Function()' },
      { regex: /child_process.*exec/g, desc: 'child_process exec usage' },
    ],
    message: 'Insecure function detected. These functions can execute arbitrary code.'
  },
  {
    id: 'WEAK_CRYPTO', name: 'Weak Cryptography', severity: 'MEDIUM',
    patterns: [
      { regex: /createHash\s*\(\s*['"]md5['"]\s*\)/gi, desc: 'MD5 hash usage' },
      { regex: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi, desc: 'SHA1 hash usage' },
      { regex: /crypto\.createCipher\s*\(/g, desc: 'Deprecated createCipher usage' },
      { regex: /crypto\.createDecipher\s*\(/g, desc: 'Deprecated createDecipher usage' },
      { regex: /\b(?:DES|RC4|RC2|Blowfish)\b/gi, desc: 'Weak encryption algorithm' },
    ],
    message: 'Weak cryptographic algorithm detected. Use SHA-256 or AES-256 instead.'
  },
];
