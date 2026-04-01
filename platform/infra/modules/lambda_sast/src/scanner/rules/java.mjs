/**
 * Java rules.
 */

export const JAVA_RULES = [
  {
    id: 'SQL_INJECTION', name: 'SQL Injection Risk', severity: 'HIGH',
    patterns: [
      { regex: /(?:execute|executeQuery|executeUpdate)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*"\s*\+/gi, desc: 'String concatenation in JDBC execute()' },
      { regex: /Statement\s*\.\s*execute(?:Query|Update)?\s*\(\s*[^"']/gi, desc: 'Non-literal passed to Statement.execute()' },
      { regex: /createQuery\s*\(\s*["'].*["']\s*\+/gi, desc: 'String concatenation in createQuery()' },
      { regex: /createNativeQuery\s*\(\s*["'].*["']\s*\+/gi, desc: 'String concatenation in createNativeQuery()' },
    ],
    message: 'Potential SQL injection. Use PreparedStatement with parameterized queries.'
  },
  {
    id: 'XSS', name: 'Cross-Site Scripting (XSS)', severity: 'HIGH',
    patterns: [
      { regex: /response\.getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write)\s*\(\s*request\./gi, desc: 'User input written directly to response' },
      { regex: /out\.print(?:ln)?\s*\(\s*request\.getParameter/gi, desc: 'getParameter() written to output without escaping' },
    ],
    message: 'Potential XSS. Encode/escape user input before writing to HTTP response.'
  },
  {
    id: 'PATH_TRAVERSAL', name: 'Path Traversal', severity: 'HIGH',
    patterns: [
      { regex: /new\s+File\s*\(\s*request\.getParameter/gi, desc: 'User input in File constructor' },
      { regex: /new\s+FileInputStream\s*\(\s*request\.getParameter/gi, desc: 'User input in FileInputStream' },
      { regex: /Paths\.get\s*\([^)]*request\.getParameter/gi, desc: 'User input in Paths.get()' },
      { regex: /['"][^'"]*\.\.\/[^'"]*['"]/g, desc: 'Path traversal sequence detected' },
    ],
    message: 'Potential path traversal. Validate and canonicalize file paths.'
  },
  {
    id: 'INSECURE_DESERIALIZE', name: 'Insecure Deserialization', severity: 'HIGH',
    patterns: [
      { regex: /new\s+ObjectInputStream\s*\(/g, desc: 'ObjectInputStream can deserialize arbitrary objects' },
      { regex: /\.readObject\s*\(\s*\)/g, desc: 'readObject() deserializes untrusted data' },
      { regex: /XMLDecoder\s*\(/g, desc: 'XMLDecoder is vulnerable to deserialization attacks' },
    ],
    message: 'Insecure deserialization detected. Validate input and use safer alternatives.'
  },
  {
    id: 'INSECURE_FUNCTION', name: 'Insecure Function Usage', severity: 'HIGH',
    patterns: [
      { regex: /Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/g, desc: 'Runtime.exec() executes system commands' },
      { regex: /new\s+ProcessBuilder\s*\([^)]*request\.getParameter/gi, desc: 'User input in ProcessBuilder' },
    ],
    message: 'Insecure command execution detected. Avoid passing user input to OS commands.'
  },
  {
    id: 'WEAK_CRYPTO', name: 'Weak Cryptography', severity: 'MEDIUM',
    patterns: [
      { regex: /MessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)/gi, desc: 'MD5 hash usage' },
      { regex: /MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\s*\)/gi, desc: 'SHA-1 hash usage' },
      { regex: /KeyGenerator\.getInstance\s*\(\s*["']DES["']\s*\)/gi, desc: 'DES key generation' },
      { regex: /Cipher\.getInstance\s*\(\s*["'](?:DES|RC4|RC2)[/"']/gi, desc: 'Weak cipher usage' },
    ],
    message: 'Weak cryptographic algorithm detected. Use SHA-256 or AES-256 instead.'
  },
];
