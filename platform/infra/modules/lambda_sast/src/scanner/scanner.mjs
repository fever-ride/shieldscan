/**
 * SAST Scanner — multi-language edition
 * Routes each file to the appropriate language rule set, then runs common rules on top.
 */
import { detectLanguage, COMMON_RULES } from './rules/common.mjs';
import { JS_RULES }     from './rules/javascript.mjs';
import { PYTHON_RULES } from './rules/python.mjs';
import { JAVA_RULES }   from './rules/java.mjs';
import { GO_RULES }     from './rules/go.mjs';

const LANG_RULES = {
  javascript: JS_RULES,
  python:     PYTHON_RULES,
  java:       JAVA_RULES,
  go:         GO_RULES,
};

const getLineNumber = (code, index) =>
  code.substring(0, index).split('\n').length;

const getLineContent = (code, lineNumber) =>
  code.split('\n')[lineNumber - 1]?.trim() ?? '';

export const scanCode = (code, filename = 'untitled.js') => {
  const lang = detectLanguage(filename);
  const rules = [...COMMON_RULES, ...(LANG_RULES[lang] ?? [])];

  const vulnerabilities = [];

  for (const rule of rules) {
    for (const pattern of rule.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;

      while ((match = regex.exec(code)) !== null) {
        const lineNumber = getLineNumber(code, match.index);
        const lineContent = getLineContent(code, lineNumber);

        vulnerabilities.push({
          id: rule.id,
          name: rule.name,
          severity: rule.severity,
          description: pattern.desc,
          message: rule.message,
          language: lang,
          file: filename,
          line: lineNumber,
          column: match.index - code.lastIndexOf('\n', match.index - 1),
          evidence: lineContent.length > 100 ? lineContent.substring(0, 100) + '...' : lineContent
        });
      }
    }
  }

  // Deduplicate: same rule + file + line = same finding
  const seen = new Set();
  const deduped = vulnerabilities.filter(v => {
    const key = `${v.id}:${v.file}:${v.line}`;
    return seen.has(key) ? false : (seen.add(key), true);
  });

  const severityOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  deduped.sort((a, b) => {
    if (severityOrder[a.severity] !== severityOrder[b.severity]) {
      return severityOrder[a.severity] - severityOrder[b.severity];
    }
    return a.line - b.line;
  });

  return deduped;
};

export default { scanCode };
