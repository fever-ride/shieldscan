/**
 * Go rules.
 */

export const GO_RULES = [
  {
    id: 'SQL_INJECTION', name: 'SQL Injection Risk', severity: 'HIGH',
    patterns: [
      { regex: /db\.\s*(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf/g, desc: 'fmt.Sprintf used to build SQL query' },
      { regex: /db\.\s*(?:Query|Exec|QueryRow)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*["']\s*\+/gi, desc: 'String concatenation in SQL query' },
      { regex: /\.Raw\s*\(\s*fmt\.Sprintf/g, desc: 'fmt.Sprintf in GORM Raw query' },
    ],
    message: 'Potential SQL injection. Use parameterized queries with ? or $N placeholders.'
  },
  {
    id: 'PATH_TRAVERSAL', name: 'Path Traversal', severity: 'HIGH',
    patterns: [
      { regex: /http\.ServeFile\s*\([^)]*r\.(?:URL|FormValue|PathValue)/gi, desc: 'User input in http.ServeFile()' },
      { regex: /os\.Open\s*\(\s*r\.(?:URL|FormValue)/gi, desc: 'User input in os.Open()' },
      { regex: /filepath\.Join\s*\([^)]*r\.(?:URL|FormValue)/gi, desc: 'User input in filepath.Join()' },
      { regex: /['"][^'"]*\.\.\/[^'"]*['"]/g, desc: 'Path traversal sequence detected' },
    ],
    message: 'Potential path traversal. Validate and clean file paths with filepath.Clean().'
  },
  {
    id: 'INSECURE_RANDOM', name: 'Insecure Randomness', severity: 'MEDIUM',
    patterns: [
      { regex: /math\/rand/g, desc: 'math/rand is not cryptographically secure' },
      { regex: /rand\.Intn\s*\(/g, desc: 'rand.Intn() is not cryptographically secure' },
      { regex: /rand\.Int63\s*\(/g, desc: 'rand.Int63() is not cryptographically secure' },
    ],
    message: 'math/rand is not cryptographically secure. Use crypto/rand for security-sensitive operations.'
  },
  {
    id: 'INSECURE_FUNCTION', name: 'Insecure Function Usage', severity: 'HIGH',
    patterns: [
      { regex: /exec\.Command\s*\([^)]*(?:r\.FormValue|r\.URL\.Query)/gi, desc: 'User input in exec.Command()' },
      { regex: /exec\.CommandContext\s*\([^)]*(?:r\.FormValue|r\.URL\.Query)/gi, desc: 'User input in exec.CommandContext()' },
    ],
    message: 'Insecure command execution. Avoid passing user input to OS commands.'
  },
  {
    id: 'WEAK_CRYPTO', name: 'Weak Cryptography', severity: 'MEDIUM',
    patterns: [
      { regex: /\bmd5\.New\s*\(\s*\)/g, desc: 'MD5 hash usage' },
      { regex: /\bsha1\.New\s*\(\s*\)/g, desc: 'SHA1 hash usage' },
      { regex: /"crypto\/md5"/g, desc: 'MD5 package imported' },
      { regex: /"crypto\/sha1"/g, desc: 'SHA1 package imported' },
    ],
    message: 'Weak cryptographic algorithm. Use sha256 or sha512 from crypto/sha256 or crypto/sha512.'
  },
];
