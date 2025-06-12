import React, { useState } from "react";
import axios from "axios";
import { FixedSizeList } from "react-window";
import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";
import "./LogAnalyzer.css";

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

const API_URL = "http://localhost:5000/api/upload-log";
const DOWNLOAD_URL = "http://localhost:5000/api/download-csv";

// Use CSS class for badge, with severity for color (class: badge-severity)
function severityBadge(level) {
  return (
    <span className={`severity-badge severity-${(level || 'info').toLowerCase()}`}>
      {level}
    </span>
  );
}

// Use class highlight-log and severity for color
function highlight(line, allFindings, lineNumber) {
  const item = allFindings.find(f => f.text === line && f.line === lineNumber);
  if (item) {
    const level = item.level || "Info";
    return (
      <span
        className={`highlight-log highlight-${level.toLowerCase()}`}
        title={level}
      >
        {line}
        {severityBadge(level)}
      </span>
    );
  }
  return line;
}

function getAllFindings(analysis, filters) {
  let arr = [];
  if (!analysis) return [];
  if (filters.failed) arr = arr.concat(analysis.failedLogins || []);
  if (filters.sensitive) arr = arr.concat(analysis.sensitiveAccess || []);
  if (filters.sqli) arr = arr.concat(analysis.sqlInjection || []);
  if (filters.xss) arr = arr.concat(analysis.xss || []);
  if (filters.dir) arr = arr.concat(analysis.dirTraversal || []);
  if (filters.agent) arr = arr.concat(analysis.suspiciousAgents || []);
  return arr;
}

function LogAnalyzer() {
  const [file, setFile] = useState(null);
  const [lines, setLines] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState({
    failed: true,
    sensitive: true,
    sqli: true,
    xss: true,
    dir: true,
    agent: true,
  });
  const [threshold, setThreshold] = useState(5);
  const [search, setSearch] = useState("");
  const [dark, setDark] = useState(false);

  const handleFileChange = e => {
    setFile(e.target.files[0]);
    setError("");
    setLines([]);
    setAnalysis(null);
  };

  const handleUpload = async e => {
    e.preventDefault();
    if (!file) {
      setError("Please select a log file first.");
      return;
    }
    setLoading(true);
    setError("");
    setAnalysis(null);
    setLines([]);
    try {
      const formData = new FormData();
      formData.append("logfile", file);
      formData.append("threshold", threshold);

      const res = await axios.post(API_URL, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setAnalysis(res.data.analysis);
      setLines(res.data.lines);
    } catch (err) {
      setError("Upload failed or server error.");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async () => {
    try {
      const response = await axios.post(DOWNLOAD_URL, { analysis }, { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", "log_analysis_report.csv");
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err) {
      alert("Could not download CSV report.");
    }
  };

  const handleFilterChange = e => {
    setFilters({ ...filters, [e.target.name]: e.target.checked });
  };

  // Merge all findings for highlighting
  const allFindings = getAllFindings(analysis, filters);

  // Search filter
  let displayedLines = lines;
  if (search.trim().length > 0) {
    displayedLines = lines.filter((line, idx) => line.includes(search) || (analysis?.failedLogins || []).some(f => f.line === idx + 1 && f.ip === search));
  }

  // Show only lines with findings if any filters are checked, or all lines otherwise
  if (Object.values(filters).some(Boolean)) {
    displayedLines = displayedLines.filter((line, idx) =>
      allFindings.some(f => f.text === line && f.line === idx + 1)
    );
  }

  const LogLine = ({ index, style }) => (
    <div style={style}>
      <span style={{ opacity: 0.4, marginRight: 6 }}>{displayedLines.length > 0 ? lines.indexOf(displayedLines[index]) + 1 : ""}.</span>
      {highlight(displayedLines[index], allFindings, lines.indexOf(displayedLines[index]) + 1)}
    </div>
  );

  const chartData = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [
      {
        label: "Threat Count",
        data: [
          analysis?.sqlInjection?.length || 0,
          (analysis?.xss?.length || 0) + (analysis?.dirTraversal?.length || 0) + (analysis?.bruteForceIps?.length || 0),
          (analysis?.failedLogins?.length || 0) + (analysis?.suspiciousAgents?.length || 0),
          analysis?.sensitiveAccess?.length || 0,
        ],
        backgroundColor: ["#ff4747", "#fbbf24", "#2563eb", "#0ea5e9"],
      },
    ],
  };

  const chartOptions = {
    scales: {
      y: {
        beginAtZero: true,
        title: { display: true, text: "Number of Threats" },
      },
    },
    plugins: {
      title: { display: true, text: "Threat Severity Distribution" },
      legend: { display: false },
    },
  };

  return (
    <div className={dark ? "log-analyzer-container dark" : "log-analyzer-container"}>
      <h2>Log File Analyzer</h2>
      <button
        className="mode-toggle-btn"
        style={{ position: "absolute", right: 20, top: 20 }}
        onClick={() => setDark(d => !d)}
        aria-label="Toggle dark mode"
      >
        {dark ? "🌞 Light Mode" : "🌚 Dark Mode"}
      </button>
      <form onSubmit={handleUpload}>
        <input
          type="file"
          accept=".log,.txt"
          onChange={handleFileChange}
          className="file-input"
          aria-label="Select log file"
        />
        <label>
          Brute-Force Threshold:
          <input
            type="number"
            min={1}
            value={threshold}
            onChange={e => setThreshold(Number(e.target.value))}
            className="brute-threshold-input"
          />
        </label>
        <button
          type="submit"
          className="analyze-btn"
          aria-label="Analyze selected log file"
        >
          Analyze Log
        </button>
      </form>
      {loading && <div className="loading">Analyzing...</div>}
      {error && <div className="error">{error}</div>}

      {analysis && (
        <>
          <div className="summary">
            <h3>Analysis Summary</h3>
            <div>Total lines: {analysis.totalLines}</div>
            <div>Unique IPs: {analysis.uniqueIps}</div>
            <div>Failed Logins: {analysis.failedLogins.length} {severityBadge("Medium")}</div>
            <div>Access to Sensitive URLs: {analysis.sensitiveAccess.length} {severityBadge("Low")}</div>
            <div>
              Brute Force IPs: {analysis.bruteForceIps.length} {severityBadge("High")}
              {analysis.bruteForceIps.length === 0
                ? ""
                : analysis.bruteForceIps.map(ip => (
                    <span className="brute-force-ip" key={ip.ip}>
                      {ip.ip} ({ip.count} failed logins)
                    </span>
                  ))}
            </div>
            <div>SQL Injection Attempts: {analysis.sqlInjection.length} {severityBadge("Critical")}</div>
            <div>XSS Attempts: {analysis.xss.length} {severityBadge("High")}</div>
            <div>Directory Traversal Attempts: {analysis.dirTraversal.length} {severityBadge("High")}</div>
            <div>Suspicious User-Agents: {analysis.suspiciousAgents.length} {severityBadge("Medium")}</div>
            <br /><button
              className="download-btn"
              onClick={handleDownload}
              aria-label="Download CSV report"
            >
              Download CSV Report
            </button>
          </div>
          <div className="chart-container">
            <Bar data={chartData} options={chartOptions} />
          </div>

          <div className="filters" style={{ margin: "1em 0" }}>
            <label>
              <input type="checkbox" name="failed" checked={filters.failed} onChange={handleFilterChange} />
              Failed Logins
            </label>
            <label>
              <input type="checkbox" name="sensitive" checked={filters.sensitive} onChange={handleFilterChange} />
              Sensitive URLs
            </label>
            <label>
              <input type="checkbox" name="sqli" checked={filters.sqli} onChange={handleFilterChange} />
              SQL Injection
            </label>
            <label>
              <input type="checkbox" name="xss" checked={filters.xss} onChange={handleFilterChange} />
              XSS
            </label>
            <label>
              <input type="checkbox" name="dir" checked={filters.dir} onChange={handleFilterChange} />
              Directory Traversal
            </label>
            <label>
              <input type="checkbox" name="agent" checked={filters.agent} onChange={handleFilterChange} />
              Suspicious Agents
            </label>
            <input
              type="text"
              placeholder="Search IP or keyword"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="search-input"
            />
          </div>

          {displayedLines.length > 0 && (
            <div className="log-viewer">
              <h3>Log Preview ({displayedLines.length} lines)</h3>
              <FixedSizeList
                height={400}
                width="100%"
                itemCount={displayedLines.length}
                itemSize={24}
              >
                {LogLine}
              </FixedSizeList>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default LogAnalyzer;
