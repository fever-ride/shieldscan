/**
 * Investigation playbooks by vulnerability type.
 *
 * These playbooks make the agent more policy-driven: instead of deciding from
 * scratch how to investigate each finding, it gets a focused checklist based on
 * the rule ID. The checklists guide evidence gathering but do not force a fixed
 * sequence of tool calls.
 */

const GENERIC_PLAYBOOK = {
  id: 'GENERIC',
  title: 'Generic Security Investigation',
  goals: [
    'Confirm what the reported sink or risky construct actually does in code.',
    'Check whether user-controlled input can realistically reach the flagged location.',
    'Look for nearby defensive controls such as validation, sanitization, allowlists, or authentication checks.',
    'Use runtime evidence only as supporting context, not as the sole proof of exploitability.',
  ],
  checklist: [
    'Inspect the flagged file and nearby lines first.',
    'Look for callers, route handlers, or entry points that reach the code.',
    'Check whether the reported issue appears in executable code, not only comments or dead code.',
    'Prefer INCONCLUSIVE when key exploitability evidence is missing.',
  ],
  verdictGuidance: [
    'Use CONFIRMED when the vulnerable pattern is real, reachable, and not clearly mitigated.',
    'Use LIKELY_FALSE_POSITIVE when the finding is clearly non-executable, safely wrapped, or contradicted by code evidence.',
    'Use INCONCLUSIVE when the available code context is not enough to establish exploitability.',
  ],
};

const PLAYBOOKS = {
  SQL_INJECTION: {
    id: 'SQL_INJECTION',
    title: 'SQL Injection Investigation',
    goals: [
      'Identify whether user-controlled input reaches a SQL execution sink.',
      'Determine whether the query is parameterized or built through string interpolation/concatenation.',
      'Use matching DAST SQL evidence as supporting validation when available.',
    ],
    checklist: [
      'Identify the input source, such as request params, query strings, or body fields.',
      'Identify the SQL sink, for example query(), execute(), or raw SQL helpers.',
      'Check whether the query is assembled with string concatenation, template literals, or formatted strings.',
      'Look for parameterized queries, prepared statements, ORM binding, or allowlist validation.',
      'If DAST evidence exists, check whether the endpoint and method align with the code path under investigation.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when user input clearly reaches a real SQL sink without parameterization.',
      'Use LIKELY_FALSE_POSITIVE when the flagged line is not executable SQL, or when binding/validation clearly prevents injection.',
      'Use INCONCLUSIVE when the sink is visible but the source or protections cannot be established from the available context.',
    ],
  },
  NOSQL_INJECTION: {
    id: 'NOSQL_INJECTION',
    title: 'NoSQL Injection Investigation',
    goals: [
      'Determine whether untrusted input flows into a NoSQL query object or operator.',
      'Check whether dangerous operators such as $where or user-controlled objects are accepted without validation.',
      'Use DAST failures only as supporting evidence for runtime behavior.',
    ],
    checklist: [
      'Find the source of the query object or filter values.',
      'Check for direct use of req.body, req.query, or similar untrusted objects in database calls.',
      'Look for dangerous operators such as $where, $regex, or unvalidated nested objects.',
      'Check for schema validation, type coercion, or explicit field allowlists before the database call.',
      'If DAST evidence exists, compare the tested endpoint to the code path to see whether they plausibly match.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when attacker-controlled objects or operators can reach a database query without sanitization.',
      'Use LIKELY_FALSE_POSITIVE when input is constrained to a safe schema or the matched code is not truly query execution logic.',
      'Use INCONCLUSIVE when the query path is present but validation behavior is unclear.',
    ],
  },
  XSS: {
    id: 'XSS',
    title: 'Cross-Site Scripting Investigation',
    goals: [
      'Confirm whether the flagged code writes attacker-controlled data into a real HTML or script sink.',
      'Check whether escaping, sanitization, or safe templating prevents execution.',
      'Distinguish true rendering paths from dead code, comments, or safe wrappers.',
    ],
    checklist: [
      'Identify the sink, such as innerHTML, outerHTML, response writer output, or dangerous template bypasses.',
      'Trace whether the rendered value can come from user input.',
      'Look for sanitization helpers, escaping utilities, or framework auto-escaping.',
      'Check whether the sanitization is clearly applied before the sink.',
      'If the sink is wrapped in a helper function, inspect that helper before deciding.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when user-controlled data reaches an executable HTML or script sink without effective sanitization.',
      'Use LIKELY_FALSE_POSITIVE when the sink receives clearly sanitized or escaped data, or when the match is non-executable.',
      'Use INCONCLUSIVE when a helper appears to sanitize data but its implementation cannot be verified with confidence.',
    ],
  },
  PATH_TRAVERSAL: {
    id: 'PATH_TRAVERSAL',
    title: 'Path Traversal Investigation',
    goals: [
      'Determine whether user-controlled path input reaches file system operations.',
      'Check whether canonicalization, base-directory enforcement, or allowlists prevent traversal.',
      'Separate real filesystem access from harmless string handling.',
    ],
    checklist: [
      'Identify the path source, such as URL params, query strings, or request body values.',
      'Identify the file system sink, such as readFile, open, FileInputStream, or ServeFile.',
      'Check for path normalization, allowlists, basename extraction, or explicit base directory enforcement.',
      'Look for traversal blockers such as rejecting .. segments or resolving paths under a trusted root.',
      'Do not confirm purely on a literal ".." string unless it is tied to a real filesystem code path.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when user input reaches filesystem access without meaningful path restriction.',
      'Use LIKELY_FALSE_POSITIVE when strong path validation or root restriction clearly blocks traversal.',
      'Use INCONCLUSIVE when file access is real but the effective path constraints are unclear.',
    ],
  },
  JWT_MISUSE: {
    id: 'JWT_MISUSE',
    title: 'JWT Misuse Investigation',
    goals: [
      'Confirm whether token verification is bypassed or weakened in a way that affects authentication or authorization.',
      'Determine whether the flagged JWT operation is used in a security-sensitive path.',
      'Distinguish debugging or non-security code from real auth logic.',
    ],
    checklist: [
      'Inspect where jwt.decode, jwt.verify, or algorithm configuration is used.',
      'Check whether the decoded or verified token is trusted for auth or authorization decisions.',
      'Look for empty, null, or unsafe verification secrets and weak algorithm settings.',
      'Check whether the code path is part of request handling, middleware, or session logic.',
      'If the token operation is only for logging, debugging, or non-authoritative parsing, treat that as counter-evidence.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when insecure JWT handling directly affects authentication or authorization.',
      'Use LIKELY_FALSE_POSITIVE when the flagged JWT operation is non-authoritative or clearly not used for trust decisions.',
      'Use INCONCLUSIVE when the JWT usage is visible but its impact on access control is unclear.',
    ],
  },
  HARDCODED_SECRET: {
    id: 'HARDCODED_SECRET',
    title: 'Hardcoded Secret Investigation',
    goals: [
      'Determine whether the flagged value is a real credential, token, or secret-like material embedded in code.',
      'Distinguish real secrets from placeholders, examples, test fixtures, or obviously fake demo values.',
      'Check whether the value is used in a meaningful security-sensitive context.',
    ],
    checklist: [
      'Inspect the exact value and the surrounding code where it is defined.',
      'Check whether the value is referenced by authentication, payment, cloud, or API client logic.',
      'Look for cues that the value is a placeholder, test fixture, or documentation example.',
      'Check whether environment variables or secret managers override the hardcoded value in practice.',
      'Prefer caution when the value shape and surrounding usage both look production-real.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when the value appears to be a real embedded credential or token used by application logic.',
      'Use LIKELY_FALSE_POSITIVE when the value is clearly a placeholder, fake demo string, or unused example.',
      'Use INCONCLUSIVE when the value looks secret-like but its real usage cannot be established from context.',
    ],
  },
  PROTOTYPE_POLLUTION: {
    id: 'PROTOTYPE_POLLUTION',
    title: 'Prototype Pollution Investigation',
    goals: [
      'Determine whether attacker-controlled keys or objects are merged into application objects.',
      'Check whether dangerous keys such as __proto__, constructor, or prototype can survive validation.',
      'Distinguish shallow harmless copying from security-sensitive merge logic.',
    ],
    checklist: [
      'Identify the untrusted object source, such as request body, query params, or external JSON input.',
      'Identify the merge or assignment sink, for example Object.assign, spread syntax, deep merge helpers, or defaults utilities.',
      'Check whether dangerous keys are blocked, stripped, or validated before merge.',
      'Look for whether the target object is security-sensitive configuration, auth state, or shared global state.',
      'Treat merges into a fresh empty object as lower confidence than merges into existing live application objects.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when untrusted keys can flow into an existing object or deep merge path without key filtering.',
      'Use LIKELY_FALSE_POSITIVE when the input is clearly validated or the merge target is isolated in a way that blocks prototype abuse.',
      'Use INCONCLUSIVE when the merge is visible but key filtering or object lifetime cannot be established.',
    ],
  },
  INSECURE_FUNCTION: {
    id: 'INSECURE_FUNCTION',
    title: 'Insecure Function Investigation',
    goals: [
      'Determine whether the flagged dangerous function is actually executed in a security-relevant code path.',
      'Check whether user-controlled input reaches the dangerous function.',
      'Distinguish executable code from comments, examples, test fixtures, or dead code.',
    ],
    checklist: [
      'Inspect the matched line and nearby lines to confirm the function call is real executable code.',
      'Identify what arguments are passed into the dangerous function and whether they are attacker-controlled.',
      'Look for wrappers, allowlists, escaping, or other constraints around the dangerous call.',
      'Check callers or route handlers to see whether the path is reachable in normal request flow.',
      'Treat comment-only matches, examples, and test code as strong counter-evidence.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when a dangerous function is actually called with attacker-controlled or weakly constrained input.',
      'Use LIKELY_FALSE_POSITIVE when the match is clearly a comment, example, dead code, or strongly constrained safe wrapper.',
      'Use INCONCLUSIVE when the dangerous call exists but controllability or reachability is unclear.',
    ],
  },
  WEAK_CRYPTO: {
    id: 'WEAK_CRYPTO',
    title: 'Weak Cryptography Investigation',
    goals: [
      'Determine whether the weak algorithm is used in a security-sensitive context.',
      'Separate risky uses such as password hashing or signature verification from lower-risk non-security uses.',
      'Check whether the code is legacy, compatibility-only, or clearly non-production.',
    ],
    checklist: [
      'Identify the algorithm and the surrounding code that uses it.',
      'Check whether the weak crypto is used for passwords, tokens, signatures, encryption, or key derivation.',
      'Look for evidence that the algorithm is only used for cache keys, content deduplication, or compatibility metadata.',
      'Check whether a stronger algorithm is used alongside it for the real security boundary.',
      'Treat hard security uses as high confidence, and non-security utility uses as strong counter-evidence.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when the weak algorithm protects passwords, auth tokens, signatures, encryption, or similar trust boundaries.',
      'Use LIKELY_FALSE_POSITIVE when the algorithm is only used for non-security purposes like cache keys or content addressing.',
      'Use INCONCLUSIVE when the algorithm is present but the effective security role is unclear.',
    ],
  },
  INSECURE_RANDOM: {
    id: 'INSECURE_RANDOM',
    title: 'Insecure Randomness Investigation',
    goals: [
      'Determine whether non-cryptographic randomness is used for security-sensitive values.',
      'Distinguish auth or security tokens from low-risk UI or cache identifiers.',
      'Check whether a secure random API is used elsewhere for the true sensitive value.',
    ],
    checklist: [
      'Inspect the variable name, surrounding code, and downstream usage of the random value.',
      'Check whether the value is used for sessions, auth tokens, password reset links, CSRF tokens, OTPs, or keys.',
      'Look for whether the flagged random value is only used for presentation, deduplication, or non-security identifiers.',
      'Check whether a secure random source replaces or wraps the weak random call later in the flow.',
      'Treat comments and variable names carefully, since regex matches may overfire on nearby text.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when weak randomness feeds a real security-sensitive token or credential flow.',
      'Use LIKELY_FALSE_POSITIVE when the random value is clearly non-security, such as a UI key or cache identifier.',
      'Use INCONCLUSIVE when the random value looks important but its downstream use is ambiguous.',
    ],
  },
  CORS_MISCONFIGURATION: {
    id: 'CORS_MISCONFIGURATION',
    title: 'CORS Misconfiguration Investigation',
    goals: [
      'Determine whether the CORS policy meaningfully weakens browser-side access control.',
      'Check whether wildcard or reflected origins apply to sensitive authenticated endpoints.',
      'Distinguish harmless public API exposure from risky credentialed cross-origin access.',
    ],
    checklist: [
      'Inspect the origin policy, including wildcard origins and reflected request origins.',
      'Check whether credentials are allowed together with broad origins.',
      'Look for whether the affected routes expose authenticated or sensitive data.',
      'If DAST evidence exists, compare it with the code configuration to see whether runtime behavior matches the source.',
      'Treat broad CORS on public, unauthenticated, intentionally public data as lower confidence than on auth-protected APIs.',
    ],
    verdictGuidance: [
      'Use CONFIRMED when broad or reflected CORS applies to sensitive endpoints, especially with credentials enabled.',
      'Use LIKELY_FALSE_POSITIVE when the route is intentionally public and no sensitive browser-side boundary is weakened.',
      'Use INCONCLUSIVE when CORS looks broad but the sensitivity of the affected endpoints is unclear.',
    ],
  },
};

function formatBullets(items) {
  return items.map(item => `- ${item}`).join('\n');
}

function getRuleId(finding) {
  return finding?.id ?? finding?.rule ?? 'GENERIC';
}

export function getInvestigationPlaybook(finding) {
  const ruleId   = getRuleId(finding);
  const playbook = PLAYBOOKS[ruleId] ?? GENERIC_PLAYBOOK;

  return {
    id: playbook.id,
    title: playbook.title,
    promptSection: `## Investigation Playbook
Type: ${playbook.title}

Goals:
${formatBullets(playbook.goals)}

Checklist:
${formatBullets(playbook.checklist)}

Verdict guidance:
${formatBullets(playbook.verdictGuidance)}`,
  };
}
