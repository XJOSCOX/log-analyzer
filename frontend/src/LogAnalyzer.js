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

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

function highlight(line, failedLogins, sensitiveAccess, sqlInjection, xss, dirTraversal, suspiciousAgents) {
  if (failedLogins.some(f => f.text === line)) {
    return <span className="highlight-failed">{line}</span>;
  }
  if (sensitiveAccess.some(s => s.text === line)) {
    return <span className="highlight-sensitive">{line}</span>;
  }
  if (sqlInjection?.some(s => s.text === line)) {
    return <span className="highlight-sqli">{line}</span>;
  }
  if (xss?.some(s => s.text === line)) {
    return <span className="highlight-xss">{line}</span>;
  }
  if (dirTraversal?.some(s => s.text === line)) {
    return <span className="highlight-dir">{line}</span>;
  }
  if (suspiciousAgents?.some(s => s.text === line)) {
    return <span className="highlight-agent">{line}</span>;
  }
  return line;
}

const API_URL = "http://localhost:5000/api/upload-log";
const DOWNLOAD_URL = "http://localhost:5000/api/download-csv";

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

      const res = await axios.post(API_URL, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setAnalysis(res.data.analysis);
      setLines(res.data.lines);
    } catch (err) {
      setError(err.response?.data?.error || "Upload failed or server error.");
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

  const filteredLines = lines.filter(line =>
    (filters.failed && analysis?.failedLogins?.some(f => f.text === line)) ||
    (filters.sensitive && analysis?.sensitiveAccess?.some(s => s.text === line)) ||
    (filters.sqli && analysis?.sqlInjection?.some(s => s.text === line)) ||
    (filters.xss && analysis?.xss?.some(s => s.text === line)) ||
    (filters.dir && analysis?.dirTraversal?.some(s => s.text === line)) ||
    (filters.agent && analysis?.suspiciousAgents?.some(s => s.text === line)) ||
    (!Object.values(filters).some(f => f)) // Show all if no filters selected
  );

  const LogLine = ({ index, style }) => (
    <div style={style}>
      {highlight(
        filteredLines[index],
        analysis?.failedLogins || [],
        analysis?.sensitiveAccess || [],
        analysis?.sqlInjection || [],
        analysis?.xss || [],
        analysis?.dirTraversal || [],
        analysis?.suspiciousAgents || []
      )}
    </div>
  );

  // Chart data for threat severity
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
        backgroundColor: ["#FF4444", "#FF9999", "#FFCC99", "#66CCCC"],
      },
    ],
  };

  const chartOptions = {
    scales: {
      y: {
        beginAtZero: true,
        title: {
          display: true,
          text: "Number of Threats",
        },
      },
    },
    plugins: {
      title: {
        display: true,
        text: "Threat Severity Distribution",
      },
    },
  };

  return (
    <div className="log-analyzer-container">
      <h2>Log File Analyzer</h2>
      <form onSubmit={handleUpload}>
        <input
          type="file"
          accept=".log,.txt"
          onChange={handleFileChange}
          className="file-input"
          aria-label="Select log file"
        />
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
            <div>Total Lines: {analysis.totalLines}</div>
            <div>Failed Logins: {analysis.failedLogins?.length}</div>
            <div>Access to Sensitive URLs: {analysis.sensitiveAccess?.length}</div>
            <div>
              Brute Force IPs:{" "}
              {analysis.bruteForceIps.length === 0 ? (
                "None"
              ) : (
                analysis.bruteForceIps.map(ip => (
                  <span className="brute-force-ip" key={ip.ip}>
                    {ip.ip} ({ip.count} attempts)
                  </span>
                ))
              )}
            </div>
            <div>SQL Injection Attempts: {analysis.sqlInjection?.length}</div>
            <div>XSS Attempts: {analysis.xss?.length}</div>
            <div>Directory Traversal: {analysis.dirTraversal?.length}</div>
            <div>Suspicious User-Agents: {analysis.suspiciousAgents?.length}</div>
            <button
              className="download-btn"
              onClick={handleDownload}
              aria-label="Download CSV report"
            >
              Download CSV Report
            </button>
          </div>

          {/* Threat Severity Chart */}
          <div className="chart-container">
            <h3>Threat Severity Distribution</h3>
            <Bar data={chartData} options={chartOptions} />
          </div>

          {/* Filter Controls */}
          <div className="filters">
            <h3>Filter Log Preview</h3>
            <label>
              <input
                type="checkbox"
                name="failed"
                checked={filters.failed}
                onChange={handleFilterChange}
              />
              Failed Logins
            </label>
            <label>
              <input
                type="checkbox"
                name="sensitive"
                checked={filters.sensitive}
                onChange={handleFilterChange}
              />
              Sensitive URLs
            </label>
            <label>
              <input
                type="checkbox"
                name="sqli"
                checked={filters.sqli}
                onChange={handleFilterChange}
              />
              SQL Injection
            </label>
            <label>
              <input
                type="checkbox"
                name="xss"
                checked={filters.xss}
                onChange={handleFilterChange}
              />
              XSS
            </label>
            <label>
              <input
                type="checkbox"
                name="dir"
                checked={filters.dir}
                onChange={handleFilterChange}
              />
              Directory Traversal
            </label>
            <label>
              <input
                type="checkbox"
                name="agent"
                checked={filters.agent}
                onChange={handleFilterChange}
              />
              Suspicious Agents
            </label>
          </div>

          {/* Log Preview with Pagination */}
          {filteredLines.length > 0 && (
            <div className="log-viewer">
              <h3>Log Preview ({filteredLines.length} lines)</h3>
              <FixedSizeList
                height={400}
                width="100%"
                itemCount={filteredLines.length}
                itemSize={20}
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