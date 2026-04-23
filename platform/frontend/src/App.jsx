import { useEffect, useMemo, useState } from "react";
import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserPool,
} from "amazon-cognito-identity-js";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";
const USER_POOL_ID = import.meta.env.VITE_COGNITO_USER_POOL_ID || "";
const CLIENT_ID = import.meta.env.VITE_COGNITO_CLIENT_ID || "";

const TOKEN_STORAGE_KEY = "security-platform-id-token";
const EMAIL_STORAGE_KEY = "security-platform-email";

function isConfigured() {
  return Boolean(API_BASE_URL && USER_POOL_ID && CLIENT_ID);
}

function decodeAttr(value) {
  if (!value || typeof value !== "object") return value;
  if ("S" in value) return value.S;
  if ("N" in value) return Number(value.N);
  if ("BOOL" in value) return value.BOOL;
  if ("NULL" in value) return null;
  if ("SS" in value) return value.SS;
  if ("NS" in value) return value.NS.map(Number);
  if ("L" in value) return value.L.map(decodeAttr);
  if ("M" in value) {
    const result = {};
    for (const [k, v] of Object.entries(value.M)) {
      result[k] = decodeAttr(v);
    }
    return result;
  }
  return value;
}

function decodeItem(item) {
  if (!item || typeof item !== "object") return item;
  const result = {};
  for (const [k, v] of Object.entries(item)) {
    result[k] = decodeAttr(v);
  }
  return result;
}

function getUserPool() {
  return new CognitoUserPool({ UserPoolId: USER_POOL_ID, ClientId: CLIENT_ID });
}

async function apiRequest(path, token, options = {}) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });

  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body.error || body.message || `Request failed: ${res.status}`);
  }
  return body;
}

export default function App() {
  const [token, setToken]       = useState(localStorage.getItem(TOKEN_STORAGE_KEY) || "");
  const [email, setEmail]       = useState(localStorage.getItem(EMAIL_STORAGE_KEY) || "");
  const [password, setPassword] = useState("");
  const [loadingAuth, setLoadingAuth] = useState(false);

  const [statusMessage, setStatusMessage] = useState("");
  const [errorMessage, setErrorMessage]   = useState("");

  // ── Scans filters ────────────────────────────────────────────────────────
  const [scanType, setScanType]   = useState("");
  const [repoName, setRepoName]   = useState("");
  const [severity, setSeverity]   = useState("");
  const [appIdFilter, setAppIdFilter] = useState("");
  const [limit, setLimit]         = useState(20);

  const [scans, setScans]           = useState([]);
  const [loadingScans, setLoadingScans] = useState(false);

  // ── Apps ─────────────────────────────────────────────────────────────────
  const [apps, setApps]             = useState([]);
  const [loadingApps, setLoadingApps] = useState(false);

  // Register app form
  const [appTargetUrl, setAppTargetUrl]   = useState("");
  const [appRepoName, setAppRepoName]     = useState("");
  const [appName, setAppName]             = useState("");
  const [appOwner, setAppOwner]           = useState("");
  const [appSchedule, setAppSchedule]     = useState("manual_only");
  const [appTeam, setAppTeam]             = useState("default");

  // Manual pentest trigger
  const [manualTargetUrl, setManualTargetUrl]   = useState("");
  const [manualTargetName, setManualTargetName] = useState("");
  const [manualAppId, setManualAppId]           = useState("");

  const configured = useMemo(isConfigured, []);

  useEffect(() => {
    if (token) {
      loadScans();
      loadApps();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  function clearMessages() {
    setStatusMessage("");
    setErrorMessage("");
  }

  // ── Auth ─────────────────────────────────────────────────────────────────

  async function handleLogin(e) {
    e.preventDefault();
    clearMessages();
    if (!configured) { setErrorMessage("Missing env config."); return; }
    if (!email || !password) { setErrorMessage("Email and password required."); return; }

    setLoadingAuth(true);
    try {
      const session = await new Promise((resolve, reject) => {
        new CognitoUser({ Username: email, Pool: getUserPool() }).authenticateUser(
          new AuthenticationDetails({ Username: email, Password: password }),
          {
            onSuccess: resolve,
            onFailure: reject,
            newPasswordRequired: () => reject(new Error("Password reset required.")),
          }
        );
      });

      const idToken = session.getIdToken().getJwtToken();
      localStorage.setItem(TOKEN_STORAGE_KEY, idToken);
      localStorage.setItem(EMAIL_STORAGE_KEY, email);
      setToken(idToken);
      setStatusMessage("Login successful.");
      setPassword("");
    } catch (err) {
      setErrorMessage(err.message || "Login failed.");
    } finally {
      setLoadingAuth(false);
    }
  }

  function handleLogout() {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    localStorage.removeItem(EMAIL_STORAGE_KEY);
    setToken("");
    setScans([]);
    setApps([]);
    setStatusMessage("Logged out.");
    setErrorMessage("");
  }

  // ── Scans ─────────────────────────────────────────────────────────────────

  async function loadScans() {
    if (!token) return;
    clearMessages();
    setLoadingScans(true);
    try {
      const params = new URLSearchParams();
      if (appIdFilter) params.set("app_id", appIdFilter);
      else {
        if (scanType) params.set("scan_type", scanType);
        if (repoName) params.set("repo_name", repoName);
        if (severity) params.set("severity", severity);
      }
      params.set("limit", String(limit));

      const data = await apiRequest(`/scans?${params.toString()}`, token);
      const normalized = (data.scans || []).map(decodeItem);
      setScans(normalized);
      setStatusMessage(`Loaded ${normalized.length} scans.`);
    } catch (err) {
      setErrorMessage(err.message);
    } finally {
      setLoadingScans(false);
    }
  }

  async function openReport(scanId) {
    clearMessages();
    try {
      const data = await apiRequest(`/reports/${scanId}`, token);
      if (!data.report_url) throw new Error("No report URL returned.");
      window.open(data.report_url, "_blank", "noopener,noreferrer");
      setStatusMessage(`Report URL generated (expires in ${data.expires_in}s).`);
    } catch (err) {
      setErrorMessage(err.message);
    }
  }

  // ── Apps ──────────────────────────────────────────────────────────────────

  async function loadApps() {
    if (!token) return;
    clearMessages();
    setLoadingApps(true);
    try {
      const data = await apiRequest("/apps", token);
      const normalized = (data.apps || []).map(decodeItem);
      setApps(normalized);
      setStatusMessage(`Loaded ${normalized.length} apps.`);
    } catch (err) {
      setErrorMessage(err.message);
    } finally {
      setLoadingApps(false);
    }
  }

  async function addApp(e) {
    e.preventDefault();
    clearMessages();
    if (!appTargetUrl) { setErrorMessage("Target URL is required."); return; }

    try {
      await apiRequest("/apps", token, {
        method: "POST",
        body: JSON.stringify({
          target_url: appTargetUrl,
          repo_name:  appRepoName  || undefined,
          app_name:   appName      || undefined,
          owner:      appOwner     || undefined,
          schedule:   appSchedule,
          team:       appTeam,
        }),
      });
      setStatusMessage("App registered.");
      setAppTargetUrl("");
      setAppRepoName("");
      setAppName("");
      setAppOwner("");
      await loadApps();
    } catch (err) {
      setErrorMessage(err.message);
    }
  }

  function selectAppForManualScan(app) {
    setManualTargetUrl(app.target_url || "");
    setManualTargetName(app.app_name || "");
    setManualAppId(app.app_id || "");
  }

  // ── AI Triage ─────────────────────────────────────────────────────────────

  const [triageScanId, setTriageScanId]   = useState(null);
  const [triageData, setTriageData]       = useState(null);
  const [loadingTriage, setLoadingTriage] = useState(false);
  const [feedbackSent, setFeedbackSent]   = useState({}); // { [finding_id]: 'confirm' | 'dismiss' }

  const [agentScanId, setAgentScanId]     = useState(null);
  const [agentData, setAgentData]         = useState(null);
  const [loadingAgent, setLoadingAgent]   = useState(false);
  const [expandedChain, setExpandedChain] = useState(null); // finding_id whose chain is expanded

  async function openTriage(scanId) {
    clearMessages();
    setTriageScanId(scanId);
    setTriageData(null);
    setFeedbackSent({});
    setLoadingTriage(true);
    try {
      const [{ triage_url }, { feedback }] = await Promise.all([
        apiRequest(`/triage/${scanId}`, token),
        apiRequest(`/ai-feedback/${scanId}`, token).catch(() => ({ feedback: {} })),
      ]);
      const res = await fetch(triage_url);
      if (!res.ok) throw new Error(`Failed to fetch triage: ${res.status}`);
      const data = await res.json();
      setTriageData(data);
      setFeedbackSent(feedback ?? {});
    } catch (err) {
      setErrorMessage(`Triage not available: ${err.message}`);
      setTriageScanId(null);
    } finally {
      setLoadingTriage(false);
    }
  }

  async function openAgent(scanId) {
    clearMessages();
    setAgentScanId(scanId);
    setAgentData(null);
    setExpandedChain(null);
    setLoadingAgent(true);
    try {
      const { agent_url } = await apiRequest(`/agent/${scanId}`, token);
      const res = await fetch(agent_url);
      if (!res.ok) throw new Error(`Failed to fetch agent report: ${res.status}`);
      const data = await res.json();
      setAgentData(data);
    } catch (err) {
      setErrorMessage(`Agent report not available: ${err.message}`);
      setAgentScanId(null);
    } finally {
      setLoadingAgent(false);
    }
  }

  async function submitFeedback(findingId, action) {
    try {
      await apiRequest("/ai-feedback", token, {
        method: "POST",
        body: JSON.stringify({ scan_id: triageScanId, finding_id: findingId, action }),
      });
      setFeedbackSent((prev) => ({ ...prev, [findingId]: action }));
    } catch (err) {
      setErrorMessage(`Feedback error: ${err.message}`);
    }
  }

  // ── Manual pentest ────────────────────────────────────────────────────────

  async function triggerManualScan(e) {
    e.preventDefault();
    clearMessages();
    if (!manualTargetUrl) { setErrorMessage("Target URL is required."); return; }

    try {
      const data = await apiRequest("/scan/pentest", token, {
        method: "POST",
        body: JSON.stringify({
          target_url: manualTargetUrl,
          app_id:     manualAppId   || undefined,
          app_name:   manualTargetName || undefined,
        }),
      });
      setStatusMessage(`Pentest queued: ${data.scan_id}`);
      await loadScans();
    } catch (err) {
      setErrorMessage(err.message);
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  if (!configured) {
    return (
      <div className="container">
        <h1>ShieldScan Dashboard</h1>
        <p className="error">
          Missing env config. Create <code>frontend/.env</code> from <code>.env.example</code>.
        </p>
      </div>
    );
  }

  return (
    <div className="container">
      <header className="header">
        <h1>ShieldScan Dashboard</h1>
        {token ? (
          <div className="auth-pill">
            <span>{email}</span>
            <button onClick={handleLogout}>Logout</button>
          </div>
        ) : null}
      </header>

      {statusMessage ? <p className="status">{statusMessage}</p> : null}
      {errorMessage  ? <p className="error">{errorMessage}</p>  : null}

      {!token ? (
        <section className="card">
          <h2>Login</h2>
          <form className="grid-form" onSubmit={handleLogin}>
            <label>
              Email
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="admin@example.com" />
            </label>
            <label>
              Password
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Your password" />
            </label>
            <button type="submit" disabled={loadingAuth}>
              {loadingAuth ? "Signing in..." : "Sign in"}
            </button>
          </form>
        </section>
      ) : (
        <>
          {/* ── Scans ─────────────────────────────────────────────────── */}
          <section className="card">
            <h2>Scans</h2>
            <div className="inline-filters">
              <label>
                App
                <select
                  value={appIdFilter}
                  onChange={(e) => setAppIdFilter(e.target.value)}
                >
                  <option value="">All apps</option>
                  {apps.map((a) => (
                    <option key={a.app_id} value={a.app_id}>
                      {a.app_name || a.app_id}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Type
                <select value={scanType} onChange={(e) => setScanType(e.target.value)} disabled={!!appIdFilter}>
                  <option value="">All</option>
                  <option value="sast">SAST</option>
                  <option value="pentest">Pentest</option>
                </select>
              </label>
              <label>
                Repo / URL
                <input value={repoName} onChange={(e) => setRepoName(e.target.value)} placeholder="org/repo" disabled={!!appIdFilter} />
              </label>
              <label>
                Severity
                <select value={severity} onChange={(e) => setSeverity(e.target.value)} disabled={!!appIdFilter}>
                  <option value="">All</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="NONE">NONE</option>
                </select>
              </label>
              <label>
                Limit
                <input type="number" min="1" max="200" value={limit} onChange={(e) => setLimit(Number(e.target.value))} />
              </label>
              <button onClick={loadScans} disabled={loadingScans}>
                {loadingScans ? "Loading..." : "Refresh"}
              </button>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Scan ID</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>App</th>
                    <th>Repo / URL</th>
                    <th>Severity</th>
                    <th>AI Triage</th>
                    <th>Agent</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.length === 0 ? (
                    <tr><td colSpan="9">No scans found.</td></tr>
                  ) : (
                    scans.map((scan) => (
                      <tr key={scan.scan_id}>
                        <td className="mono">{scan.scan_id}</td>
                        <td>{scan.scan_type}</td>
                        <td>{scan.status}</td>
                        <td>{scan.app_id ? apps.find(a => a.app_id === scan.app_id)?.app_name || scan.app_id : "-"}</td>
                        <td>{scan.repo_name || scan.target_url || "-"}</td>
                        <td>{scan.severity || "-"}</td>
                        <td>
                          {scan.ai_analyzed ? (
                            <span className="ai-badge">
                              TP:{scan.ai_true_positive ?? 0} FP:{scan.ai_false_positive ?? 0} NR:{scan.ai_needs_review ?? 0}
                            </span>
                          ) : (
                            <span className="ai-pending">—</span>
                          )}
                        </td>
                        <td>
                          {scan.ai_agent_analyzed ? (
                            <span className="ai-badge">
                              {scan.ai_agent_count ?? "?"} investigated
                            </span>
                          ) : (
                            <span className="ai-pending">—</span>
                          )}
                        </td>
                        <td>{scan.created_at || "-"}</td>
                        <td style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                          <button onClick={() => openReport(scan.scan_id)} disabled={!scan.report_s3_key}>
                            Report
                          </button>
                          {scan.scan_type === "sast" && scan.ai_analyzed && (
                            <button onClick={() => openTriage(scan.scan_id)}>
                              Triage
                            </button>
                          )}
                          {scan.scan_type === "sast" && scan.ai_agent_analyzed && (
                            <button onClick={() => openAgent(scan.scan_id)}>
                              Agent
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>

          {/* ── AI Triage Panel ──────────────────────────────────────── */}
          {triageScanId && (
            <section className="card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <h2>AI Triage — <span className="mono">{triageScanId}</span></h2>
                <button onClick={() => { setTriageScanId(null); setTriageData(null); }}>Close</button>
              </div>
              <p className="ai-advisory-label">AI Suggestion — requires human review</p>

              {loadingTriage ? (
                <p>Loading triage...</p>
              ) : triageData ? (
                <>
                  <div className="ai-summary">
                    <span>Analyzed: {triageData.summary?.total_analyzed ?? 0}</span>
                    <span>True Positive: {triageData.summary?.true_positive ?? 0}</span>
                    <span>False Positive: {triageData.summary?.false_positive ?? 0}</span>
                    <span>Needs Review: {triageData.summary?.needs_review ?? 0}</span>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Finding ID</th>
                          <th>Label</th>
                          <th>Confidence</th>
                          <th>Reasoning</th>
                          <th>Remediation</th>
                          <th>Human Review</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(triageData.suggestions || []).map((s) => (
                          <tr key={s.finding_id}>
                            <td className="mono">{s.finding_id}</td>
                            <td>
                              <span className={`label-badge label-${s.label}`}>{s.label}</span>
                            </td>
                            <td>{(s.confidence * 100).toFixed(0)}%</td>
                            <td>{s.reasoning}</td>
                            <td>{s.remediation || "—"}</td>
                            <td>
                              {feedbackSent[s.finding_id] ? (
                                <span className="feedback-done">{feedbackSent[s.finding_id] === "confirm" ? "Confirmed" : "Dismissed"}</span>
                              ) : (
                                <div style={{ display: "flex", gap: "4px" }}>
                                  <button onClick={() => submitFeedback(s.finding_id, "confirm")}>Confirm</button>
                                  <button onClick={() => submitFeedback(s.finding_id, "dismiss")}>Dismiss</button>
                                </div>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : null}
            </section>
          )}

          {/* ── Agent Investigation Panel ────────────────────────────── */}
          {agentScanId && (
            <section className="card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <h2>Agent Investigation — <span className="mono">{agentScanId}</span></h2>
                <button onClick={() => { setAgentScanId(null); setAgentData(null); }}>Close</button>
              </div>
              <p className="ai-advisory-label">AI Suggestion — requires human review</p>

              {loadingAgent ? (
                <p>Loading agent report...</p>
              ) : agentData ? (
                <div className="agent-results">
                  {(agentData.results ?? []).map((r) => (
                    <div key={r.finding_id} className="agent-card">
                      <div className="agent-header">
                        <span className="mono">{r.finding_id}</span>
                        <span className={`verdict-badge verdict-${r.verdict}`}>{r.verdict}</span>
                        <span className="agent-confidence">{(r.confidence * 100).toFixed(0)}% confidence</span>
                        <span className="agent-tools">{r.tool_calls_used ?? 0} tool calls</span>
                      </div>

                      {r.attack_path && (
                        <div className="agent-section">
                          <strong>Attack Path</strong>
                          <p>{r.attack_path}</p>
                        </div>
                      )}

                      {r.remediation && (
                        <div className="agent-section">
                          <strong>Remediation</strong>
                          <p>{r.remediation}</p>
                        </div>
                      )}

                      {r.confidence_rationale && (
                        <div className="agent-section">
                          <strong>Confidence Rationale</strong>
                          <p>{r.confidence_rationale}</p>
                        </div>
                      )}

                      {r.supporting_evidence?.length > 0 && (
                        <div className="agent-section">
                          <strong>Supporting Evidence</strong>
                          <ul>
                            {r.supporting_evidence.map((item, idx) => (
                              <li key={`support-${idx}`}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {r.contradicting_evidence?.length > 0 && (
                        <div className="agent-section">
                          <strong>Contradicting Evidence</strong>
                          <ul>
                            {r.contradicting_evidence.map((item, idx) => (
                              <li key={`contradict-${idx}`}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {r.missing_evidence?.length > 0 && (
                        <div className="agent-section">
                          <strong>Missing Evidence</strong>
                          <ul>
                            {r.missing_evidence.map((item, idx) => (
                              <li key={`missing-${idx}`}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {r.investigation_trace?.length > 0 && (
                        <div className="agent-section">
                          <button
                            className="chain-toggle"
                            onClick={() => setExpandedChain(expandedChain === r.finding_id ? null : r.finding_id)}
                          >
                            {expandedChain === r.finding_id ? "Hide" : "Show"} investigation trace ({r.investigation_trace.length} steps)
                          </button>
                          {expandedChain === r.finding_id && (
                            <ol className="evidence-chain">
                              {r.investigation_trace.map((step) => (
                                <li key={step.step}>
                                  <span className="chain-tool">{step.tool}</span>
                                  <pre className="chain-input">{JSON.stringify(step.input, null, 2)}</pre>
                                  <pre className="chain-output">{step.output}</pre>
                                </li>
                              ))}
                            </ol>
                          )}
                        </div>
                      )}

                      {r.error && (
                        <p className="error">Error: {r.error}</p>
                      )}
                    </div>
                  ))}
                </div>
              ) : null}
            </section>
          )}

          {/* ── Register App + Manual Scan ────────────────────────────── */}
          <section className="card two-col">
            <div>
              <h2>Register App</h2>
              <form className="grid-form" onSubmit={addApp}>
                <label>
                  Target URL *
                  <input value={appTargetUrl} onChange={(e) => setAppTargetUrl(e.target.value)} placeholder="https://api.example.com" />
                </label>
                <label>
                  GitHub Repo
                  <input value={appRepoName} onChange={(e) => setAppRepoName(e.target.value)} placeholder="org/repo" />
                </label>
                <label>
                  App Name
                  <input value={appName} onChange={(e) => setAppName(e.target.value)} placeholder="Payments API" />
                </label>
                <label>
                  Owner
                  <input value={email} readOnly placeholder="set from your login" />
                </label>
                <label>
                  Schedule
                  <select value={appSchedule} onChange={(e) => setAppSchedule(e.target.value)}>
                    <option value="manual_only">manual_only</option>
                    <option value="daily">daily</option>
                    <option value="weekly">weekly</option>
                  </select>
                </label>
                <label>
                  Team
                  <input value={appTeam} onChange={(e) => setAppTeam(e.target.value)} placeholder="backend-team" />
                </label>
                <button type="submit">Register App</button>
              </form>
            </div>

            <div>
              <h2>Manual Pentest</h2>
              <form className="grid-form" onSubmit={triggerManualScan}>
                <label>
                  Target URL *
                  <input value={manualTargetUrl} onChange={(e) => setManualTargetUrl(e.target.value)} placeholder="https://api.example.com" />
                </label>
                <label>
                  App Name
                  <input value={manualTargetName} onChange={(e) => setManualTargetName(e.target.value)} placeholder="App label" />
                </label>
                <label>
                  App ID
                  <input value={manualAppId} onChange={(e) => setManualAppId(e.target.value)} placeholder="auto-filled from Apps table" readOnly={!!manualAppId} />
                </label>
                <button type="submit">Run Scan</button>
              </form>
            </div>
          </section>

          {/* ── Apps table ────────────────────────────────────────────── */}
          <section className="card">
            <h2>Apps</h2>
            <button onClick={loadApps} disabled={loadingApps}>
              {loadingApps ? "Loading..." : "Refresh Apps"}
            </button>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>App ID</th>
                    <th>Name</th>
                    <th>Target URL</th>
                    <th>Repo</th>
                    <th>Owner</th>
                    <th>Schedule</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {apps.length === 0 ? (
                    <tr><td colSpan="7">No apps registered.</td></tr>
                  ) : (
                    apps.map((app) => (
                      <tr key={app.app_id}>
                        <td className="mono">{app.app_id}</td>
                        <td>{app.app_name || "-"}</td>
                        <td>{app.target_url}</td>
                        <td>{app.repo_name || "-"}</td>
                        <td>{app.owner || "-"}</td>
                        <td>{app.schedule}</td>
                        <td>
                          <button onClick={() => selectAppForManualScan(app)}>
                            Use in Manual Scan
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
