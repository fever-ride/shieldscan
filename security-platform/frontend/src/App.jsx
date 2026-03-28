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
  return new CognitoUserPool({
    UserPoolId: USER_POOL_ID,
    ClientId: CLIENT_ID,
  });
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
    const errorMsg = body.error || body.message || `Request failed: ${res.status}`;
    throw new Error(errorMsg);
  }
  return body;
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem(TOKEN_STORAGE_KEY) || "");
  const [email, setEmail] = useState(localStorage.getItem(EMAIL_STORAGE_KEY) || "");
  const [password, setPassword] = useState("");
  const [loadingAuth, setLoadingAuth] = useState(false);

  const [statusMessage, setStatusMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  const [scanType, setScanType] = useState("");
  const [repoName, setRepoName] = useState("");
  const [severity, setSeverity] = useState("");
  const [limit, setLimit] = useState(20);

  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);
  const [loadingScans, setLoadingScans] = useState(false);
  const [loadingTargets, setLoadingTargets] = useState(false);

  const [targetUrl, setTargetUrl] = useState("");
  const [targetName, setTargetName] = useState("");
  const [targetSchedule, setTargetSchedule] = useState("manual_only");
  const [targetTeam, setTargetTeam] = useState("default");

  const [manualTargetUrl, setManualTargetUrl] = useState("");
  const [manualTargetName, setManualTargetName] = useState("");
  const [manualTargetId, setManualTargetId] = useState("");

  const configured = useMemo(isConfigured, []);

  useEffect(() => {
    if (token) {
      loadScans();
      loadTargets();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  function clearMessages() {
    setStatusMessage("");
    setErrorMessage("");
  }

  async function handleLogin(e) {
    e.preventDefault();
    clearMessages();

    if (!configured) {
      setErrorMessage("Missing env config. Set .env values first.");
      return;
    }

    if (!email || !password) {
      setErrorMessage("Email and password are required.");
      return;
    }

    setLoadingAuth(true);
    try {
      const authenticationDetails = new AuthenticationDetails({
        Username: email,
        Password: password,
      });

      const cognitoUser = new CognitoUser({
        Username: email,
        Pool: getUserPool(),
      });

      const session = await new Promise((resolve, reject) => {
        cognitoUser.authenticateUser(authenticationDetails, {
          onSuccess: resolve,
          onFailure: reject,
          newPasswordRequired: () => reject(new Error("Password reset required for this user.")),
        });
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
    setTargets([]);
    setStatusMessage("Logged out.");
    setErrorMessage("");
  }

  async function loadScans() {
    if (!token) return;
    clearMessages();
    setLoadingScans(true);
    try {
      const params = new URLSearchParams();
      if (scanType) params.set("scan_type", scanType);
      if (repoName) params.set("repo_name", repoName);
      if (severity) params.set("severity", severity);
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

  async function loadTargets() {
    if (!token) return;
    clearMessages();
    setLoadingTargets(true);
    try {
      const data = await apiRequest("/targets", token);
      const normalized = (data.targets || []).map(decodeItem);
      setTargets(normalized);
      setStatusMessage((prev) => prev || `Loaded ${normalized.length} targets.`);
    } catch (err) {
      setErrorMessage(err.message);
    } finally {
      setLoadingTargets(false);
    }
  }

  async function addTarget(e) {
    e.preventDefault();
    clearMessages();
    if (!targetUrl) {
      setErrorMessage("Target URL is required.");
      return;
    }

    try {
      await apiRequest(
        "/targets",
        token,
        {
          method: "POST",
          body: JSON.stringify({
            target_url: targetUrl,
            app_name: targetName,
            schedule: targetSchedule,
            team: targetTeam,
          }),
        }
      );
      setStatusMessage("Target added.");
      setTargetUrl("");
      setTargetName("");
      await loadTargets();
    } catch (err) {
      setErrorMessage(err.message);
    }
  }

  async function triggerManualScan(e) {
    e.preventDefault();
    clearMessages();
    if (!manualTargetUrl) {
      setErrorMessage("Manual scan target URL is required.");
      return;
    }

    try {
      const data = await apiRequest(
        "/scan/pentest",
        token,
        {
          method: "POST",
          body: JSON.stringify({
            target_url: manualTargetUrl,
            target_id: manualTargetId || undefined,
            app_name: manualTargetName || undefined,
          }),
        }
      );
      setStatusMessage(`Pentest queued: ${data.scan_id}`);
      await loadScans();
    } catch (err) {
      setErrorMessage(err.message);
    }
  }

  async function openReport(scanId) {
    clearMessages();
    try {
      const data = await apiRequest(`/reports/${scanId}`, token);
      if (!data.report_url) {
        throw new Error("No report URL returned.");
      }
      window.open(data.report_url, "_blank", "noopener,noreferrer");
      setStatusMessage(`Report URL generated for scan ${scanId} (expires in ${data.expires_in}s).`);
    } catch (err) {
      setErrorMessage(err.message);
    }
  }

  function selectTargetForManualScan(target) {
    setManualTargetUrl(target.target_url || "");
    setManualTargetName(target.app_name || "");
    setManualTargetId(target.target_id || "");
  }

  if (!configured) {
    return (
      <div className="container">
        <h1>Security Platform Dashboard</h1>
        <p className="error">
          Missing env config. Create <code>frontend/.env</code> from <code>.env.example</code>.
        </p>
      </div>
    );
  }

  return (
    <div className="container">
      <header className="header">
        <h1>Security Platform Dashboard</h1>
        {token ? (
          <div className="auth-pill">
            <span>{email}</span>
            <button onClick={handleLogout}>Logout</button>
          </div>
        ) : null}
      </header>

      {statusMessage ? <p className="status">{statusMessage}</p> : null}
      {errorMessage ? <p className="error">{errorMessage}</p> : null}

      {!token ? (
        <section className="card">
          <h2>Login</h2>
          <form className="grid-form" onSubmit={handleLogin}>
            <label>
              Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@example.com"
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Your password"
              />
            </label>
            <button type="submit" disabled={loadingAuth}>
              {loadingAuth ? "Signing in..." : "Sign in"}
            </button>
          </form>
        </section>
      ) : (
        <>
          <section className="card">
            <h2>Scans</h2>
            <div className="inline-filters">
              <label>
                Type
                <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
                  <option value="">All</option>
                  <option value="sast">SAST</option>
                  <option value="pentest">Pentest</option>
                </select>
              </label>
              <label>
                Repo / URL
                <input
                  value={repoName}
                  onChange={(e) => setRepoName(e.target.value)}
                  placeholder="org/repo or target URL"
                />
              </label>
              <label>
                Severity
                <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                  <option value="">All</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="NONE">NONE</option>
                </select>
              </label>
              <label>
                Limit
                <input
                  type="number"
                  min="1"
                  max="200"
                  value={limit}
                  onChange={(e) => setLimit(Number(e.target.value))}
                />
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
                    <th>Repo / URL</th>
                    <th>Severity</th>
                    <th>Created</th>
                    <th>Report</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.length === 0 ? (
                    <tr>
                      <td colSpan="7">No scans found.</td>
                    </tr>
                  ) : (
                    scans.map((scan) => (
                      <tr key={scan.scan_id}>
                        <td className="mono">{scan.scan_id}</td>
                        <td>{scan.scan_type}</td>
                        <td>{scan.status}</td>
                        <td>{scan.repo_name || scan.target_url || "-"}</td>
                        <td>{scan.severity || "-"}</td>
                        <td>{scan.created_at || "-"}</td>
                        <td>
                          <button
                            onClick={() => openReport(scan.scan_id)}
                            disabled={!scan.report_s3_key}
                          >
                            Open
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card two-col">
            <div>
              <h2>Register Pentest Target</h2>
              <form className="grid-form" onSubmit={addTarget}>
                <label>
                  Target URL
                  <input
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://api.example.com/health"
                  />
                </label>
                <label>
                  App Name
                  <input
                    value={targetName}
                    onChange={(e) => setTargetName(e.target.value)}
                    placeholder="Payments API"
                  />
                </label>
                <label>
                  Schedule
                  <select
                    value={targetSchedule}
                    onChange={(e) => setTargetSchedule(e.target.value)}
                  >
                    <option value="manual_only">manual_only</option>
                    <option value="daily">daily</option>
                    <option value="weekly">weekly</option>
                  </select>
                </label>
                <label>
                  Team
                  <input
                    value={targetTeam}
                    onChange={(e) => setTargetTeam(e.target.value)}
                    placeholder="backend-team"
                  />
                </label>
                <button type="submit">Add Target</button>
              </form>
            </div>

            <div>
              <h2>Manual Pentest Trigger</h2>
              <form className="grid-form" onSubmit={triggerManualScan}>
                <label>
                  Target URL
                  <input
                    value={manualTargetUrl}
                    onChange={(e) => setManualTargetUrl(e.target.value)}
                    placeholder="https://api.example.com"
                  />
                </label>
                <label>
                  App Name
                  <input
                    value={manualTargetName}
                    onChange={(e) => setManualTargetName(e.target.value)}
                    placeholder="App label"
                  />
                </label>
                <button type="submit">Run Scan</button>
              </form>
            </div>
          </section>

          <section className="card">
            <h2>Pentest Targets</h2>
            <button onClick={loadTargets} disabled={loadingTargets}>
              {loadingTargets ? "Loading..." : "Refresh Targets"}
            </button>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Target ID</th>
                    <th>URL</th>
                    <th>App</th>
                    <th>Schedule</th>
                    <th>Team</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.length === 0 ? (
                    <tr>
                      <td colSpan="6">No targets found.</td>
                    </tr>
                  ) : (
                    targets.map((target) => (
                      <tr key={target.target_id}>
                        <td className="mono">{target.target_id}</td>
                        <td>{target.target_url}</td>
                        <td>{target.app_name}</td>
                        <td>{target.schedule}</td>
                        <td>{target.team}</td>
                        <td>
                          <button onClick={() => selectTargetForManualScan(target)}>
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
