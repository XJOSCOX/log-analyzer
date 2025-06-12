const express = require("express");
const cors = require("cors");
const multer = require("multer");
const Papa = require("papaparse");

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({ storage: multer.memoryStorage() });

function getSeverity(type) {
  switch (type) {
    case "sqlInjection":
      return { level: "Critical", color: "#FF4444" };
    case "xss":
    case "dirTraversal":
    case "bruteForce":
      return { level: "High", color: "#FF8800" };
    case "failedLogin":
    case "suspiciousAgent":
      return { level: "Medium", color: "#FFCC00" };
    case "sensitiveAccess":
      return { level: "Low", color: "#0099CC" };
    default:
      return { level: "Info", color: "#A0A0A0" };
  }
}

function analyzeLog(lines, bruteForceThreshold = 5) {
  let failedLogins = [];
  let suspiciousIps = {};
  let sensitiveAccess = [];
  let sqlInjection = [];
  let xss = [];
  let dirTraversal = [];
  let suspiciousAgents = [];
  let allIps = new Set();

  const badUserAgents = [
    "sqlmap", "acunetix", "nikto", "fuzz", "scanner", "nmap"
  ];

  lines.forEach((line, idx) => {
    // IP extraction (for stats)
    const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (ipMatch) allIps.add(ipMatch[1]);

    // Failed SSH login
    const failedMatch = line.match(/Failed password.*from (\d+\.\d+\.\d+\.\d+)/);
    if (failedMatch) {
      failedLogins.push({ line: idx + 1, ip: failedMatch[1], text: line, ...getSeverity("failedLogin") });
      suspiciousIps[failedMatch[1]] = (suspiciousIps[failedMatch[1]] || 0) + 1;
    }

    // Sensitive endpoint access
    if (line.match(/(\/admin|\/wp-login\.php)/i)) {
      sensitiveAccess.push({ line: idx + 1, text: line, ...getSeverity("sensitiveAccess") });
    }

    // SQL Injection detection
    if (line.match(/('|%27).*(--|%2D%2D|\bOR\b|\bAND\b).*('|%27)|UNION\s+SELECT|information_schema|sleep\(|benchmark\(|\b1=1\b/i)) {
      sqlInjection.push({ line: idx + 1, text: line, ...getSeverity("sqlInjection") });
    }

    // XSS detection
    if (line.match(/<script|onerror=|alert\s*\(|<img|<svg|document\.cookie/i)) {
      xss.push({ line: idx + 1, text: line, ...getSeverity("xss") });
    }

    // Directory traversal
    if (line.match(/\.\.\/|\.\.\\|\/etc\/passwd|c:\\windows\\system32/i)) {
      dirTraversal.push({ line: idx + 1, text: line, ...getSeverity("dirTraversal") });
    }

    // Suspicious user-agent detection (for common log format)
    const uaMatch = line.match(/"[^"]*"\s*"([^"]+)"$/);
    if (uaMatch && badUserAgents.some(ua => uaMatch[1].toLowerCase().includes(ua))) {
      suspiciousAgents.push({ line: idx + 1, text: line, ...getSeverity("suspiciousAgent") });
    }
  });

  // Brute force IPs
  const bruteForceIps = Object.entries(suspiciousIps)
    .filter(([ip, count]) => count >= bruteForceThreshold)
    .map(([ip, count]) => ({ ip, count, ...getSeverity("bruteForce") }));

  return {
    totalLines: lines.length,
    uniqueIps: Array.from(allIps).length,
    failedLogins,
    sensitiveAccess,
    bruteForceIps,
    sqlInjection,
    xss,
    dirTraversal,
    suspiciousAgents,
    bruteForceThreshold,
  };
}

app.post("/api/upload-log", upload.single("logfile"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No log file uploaded." });
  }
  const bruteForceThreshold = Number(req.body.threshold) || 5;
  const logText = req.file.buffer.toString("utf-8");
  const lines = logText.split(/\r?\n/).filter(Boolean);

  const analysis = analyzeLog(lines, bruteForceThreshold);

  res.json({
    analysis,
    lines,
  });
});

app.post("/api/download-csv", express.json(), (req, res) => {
  const { analysis } = req.body;
  if (!analysis) return res.status(400).json({ error: "No analysis data provided." });

  const rows = [];

  if (analysis.failedLogins && analysis.failedLogins.length) {
    analysis.failedLogins.forEach(item => {
      rows.push({ Type: "Failed Login", Severity: item.level, Line: item.line, IP: item.ip || "", Details: item.text });
    });
  }
  if (analysis.sensitiveAccess && analysis.sensitiveAccess.length) {
    analysis.sensitiveAccess.forEach(item => {
      rows.push({ Type: "Sensitive Access", Severity: item.level, Line: item.line, IP: "", Details: item.text });
    });
  }
  if (analysis.sqlInjection && analysis.sqlInjection.length) {
    analysis.sqlInjection.forEach(item => {
      rows.push({ Type: "SQL Injection", Severity: item.level, Line: item.line, IP: "", Details: item.text });
    });
  }
  if (analysis.xss && analysis.xss.length) {
    analysis.xss.forEach(item => {
      rows.push({ Type: "XSS Attempt", Severity: item.level, Line: item.line, IP: "", Details: item.text });
    });
  }
  if (analysis.dirTraversal && analysis.dirTraversal.length) {
    analysis.dirTraversal.forEach(item => {
      rows.push({ Type: "Directory Traversal", Severity: item.level, Line: item.line, IP: "", Details: item.text });
    });
  }
  if (analysis.suspiciousAgents && analysis.suspiciousAgents.length) {
    analysis.suspiciousAgents.forEach(item => {
      rows.push({ Type: "Suspicious Agent", Severity: item.level, Line: item.line, IP: "", Details: item.text });
    });
  }
  if (analysis.bruteForceIps && analysis.bruteForceIps.length) {
    analysis.bruteForceIps.forEach(item => {
      rows.push({ Type: "Brute Force IP", Severity: item.level, Line: "", IP: item.ip, Details: `${item.count} failed logins` });
    });
  }

  // Convert to CSV
  const csv = Papa.unparse(rows);

  res.header("Content-Type", "text/csv");
  res.attachment("log_analysis_report.csv");
  res.send(csv);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Log File Analyzer backend running on port ${PORT}`);
});
