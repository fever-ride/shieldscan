/**
 * SARIF 2.1.0 serializer for ShieldScan SAST findings.
 *
 * Maps the internal vulnerability format produced by scanner.mjs → a valid
 * SARIF 2.1.0 document that can be uploaded to GitHub Code Scanning.
 *
 * Internal finding schema (from scanner.mjs):
 *   { id, name, severity, file, line, message, description, evidence,
 *     language, finding_id, context? }
 */

const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

/** Maps ShieldScan severity → SARIF result level */
const severityToLevel = (severity) => {
  switch (severity?.toUpperCase()) {
    case 'HIGH':   return 'error';
    case 'MEDIUM': return 'warning';
    case 'LOW':    return 'note';
    default:       return 'none';
  }
};

/**
 * Builds the tool.driver.rules[] array from the unique set of rules
 * referenced in the findings.  One rule entry per unique `id` value.
 */
function buildRules(vulnerabilities) {
  const seen = new Map();

  for (const v of vulnerabilities) {
    if (seen.has(v.id)) continue;

    seen.set(v.id, {
      id: v.id,
      name: v.name || v.id,
      shortDescription: {
        text: v.description || v.message || v.name || v.id,
      },
      fullDescription: {
        text: v.message || v.description || v.name || v.id,
      },
      defaultConfiguration: {
        level: severityToLevel(v.severity),
      },
      properties: {
        tags: [v.language || 'unknown', 'security'],
        ...(v.category && { category: v.category }),
        severity: v.severity || 'UNKNOWN',
      },
    });
  }

  return [...seen.values()];
}

/**
 * Builds the runs[0].results[] array — one entry per finding.
 */
function buildResults(vulnerabilities) {
  return vulnerabilities.map((v) => {
    const result = {
      ruleId: v.id,
      level: severityToLevel(v.severity),
      message: {
        text: [v.message, v.description, v.evidence]
          .filter(Boolean)
          .join(' | ') || v.name || v.id,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: v.file || 'unknown',
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: typeof v.line === 'number' ? v.line : 1,
            },
          },
        },
      ],
      // Stable finding_id enables rule-suppression tracking across runs
      ...(v.finding_id && {
        fingerprints: {
          'shieldscan/finding_id/v1': v.finding_id,
        },
      }),
      // Attach short code context as a snippet when available
      ...(v.context && {
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: v.file || 'unknown',
                uriBaseId: '%SRCROOT%',
              },
              region: {
                startLine: typeof v.line === 'number' ? v.line : 1,
                snippet: { text: v.context },
              },
            },
          },
        ],
      }),
    };

    return result;
  });
}

/**
 * Converts a ShieldScan SAST report object into a SARIF 2.1.0 document.
 *
 * @param {object} report  - The full report as written to S3
 *   { scan_id, repo_name, branch, scanned_at, summary, vulnerabilities[] }
 * @returns {object}  SARIF document (ready for JSON.stringify)
 */
export function toSarif(report) {
  const vulnerabilities = report.vulnerabilities ?? report.findings ?? [];

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ShieldScan',
            version: '1.0.0',
            informationUri: 'https://github.com/shieldscan',
            rules: buildRules(vulnerabilities),
          },
        },
        // Bind result file URIs to the repo root so GitHub resolves paths correctly
        originalUriBaseIds: {
          '%SRCROOT%': { uri: '/' },
        },
        results: buildResults(vulnerabilities),
        // Capture scan provenance in run properties
        properties: {
          scan_id: report.scan_id,
          repo_name: report.repo_name,
          branch: report.branch,
          scanned_at: report.scanned_at,
          files_scanned: report.summary?.totalFiles ?? 0,
          total_findings: vulnerabilities.length,
        },
      },
    ],
  };
}
