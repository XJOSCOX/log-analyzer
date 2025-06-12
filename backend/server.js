const express = require('express');
const cors = require('cors');
const multer = require('multer');
const Papa = require('papaparse');

const app = express();
app.use(cors());
app.use(express.json());

// File upload configuration with validation
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    if (!file.originalname.match(/\.(log|txt)$/)) {
      return cb(new Error('Only .log and .txt files are allowed.'));
    }
    cb(null, true);
  },
});

function analyzeLog(lines) {
  let failedLogins = [];
  let suspiciousIps = {};
  let sensitiveAccess = [];
  let sqlInjection = [];
  let xss = [];
  let dirTraversal = [];
  let suspiciousAgents = [];
  const bruteForceThreshold = parseInt(process.env.BRUTE_FORCE_THRESHOLD) || 5;

  // Suspicious user-agents
  const badUserAgents = ['sqlmap', 'acunetix', 'nikto', 'fuzz', 'scanner', 'nmap'];

  try {
    lines.forEach((line, idx) => {
      // Extract IP from line (IPv4 only for simplicity)
      const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)/);
      const ip = ipMatch ? ipMatch[1] : '';

      // Failed SSH login
      const failedMatch = line.match(/Failed password.*from (\d+\.\d+\.\d+\.\d+)/);
      if (failedMatch) {
        failedLogins.push({ line: idx + 1, ip: failedMatch[1], text: line, severity: 'medium' });
        suspiciousIps[failedMatch[1]] = (suspiciousIps[failedMatch[1]] || 0) + 1;
      }

      // Sensitive endpoint access
      if (line.match(/(\/admin|\/wp-login\.php)/i)) {
        sensitiveAccess.push({ line: idx + 1, ip, text: line, severity: 'low' });
      }

      // SQL Injection detection
      if (line.match(/('|%27).*(--|%2D%2D|\bOR\b|\bAND\b).*('|%27)|UNION\s+SELECT|information_schema|sleep\(|benchmark\(|\b1=1\b/i)) {
        sqlInjection.push({ line: idx + 1, ip, text: line, severity: 'critical' });
      }

      // XSS detection
      if (line.match(/<script|onerror=|alert\s*\(|<img|<svg|document\.cookie/i)) {
        xss.push({ line: idx + 1, ip, text: line, severity: 'high' });
      }

      // Directory traversal
      if (line.match(/\.\.\/|\.\.\\|\/etc\/passwd|c:\\windows\\system32/i)) {
        dirTraversal.push({ line: idx + 1, ip, text: line, severity: 'high' });
      }

      // Suspicious user-agent detection
      const uaMatch = line.match(/"[^"]*"\s*"([^"]+)"$/);
      if (uaMatch && badUserAgents.some(ua => uaMatch[1].toLowerCase().includes(ua))) {
        suspiciousAgents.push({ line: idx + 1, ip, text: line, severity: 'medium' });
      }
    });

    // Brute force IPs
    const bruteForceIps = Object.entries(suspiciousIps)
      .filter(([ip, count]) => count >= bruteForceThreshold)
      .map(([ip, count]) => ({ ip, count, severity: 'high' }));

    return {
      totalLines: lines.length,
      failedLogins,
      sensitiveAccess,
      bruteForceIps,
      sqlInjection,
      xss,
      dirTraversal,
      suspiciousAgents,
    };
  } catch (err) {
    throw new Error(`Log analysis failed: ${err.message}`);
  }
}

app.post('/api/upload-log', upload.single('logfile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No log file uploaded.' });
    }

    const logText = req.file.buffer.toString('utf-8');
    const lines = logText.split(/\r?\n/).filter(Boolean);

    const analysis = analyzeLog(lines);

    res.json({
      analysis,
      lines,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/download-csv', express.json(), (req, res) => {
  const { analysis } = req.body;
  if (!analysis) return res.status(400).json({ error: 'No analysis data provided.' });

  const rows = [];

  if (analysis.failedLogins?.length) {
    analysis.failedLogins.forEach(item => {
      rows.push({ Type: 'Failed Login', Line: item.line, IP: item.ip, Severity: item.severity, Details: item.text });
    });
  }
  if (analysis.sensitiveAccess?.length) {
    analysis.sensitiveAccess.forEach(item => {
      rows.push({ Type: 'Sensitive Access', Line: item.line, IP: item.ip, Severity: item.severity, Details: item.text });
    });
  }
  if (analysis.sqlInjection?.length) {
    analysis.sqlInjection.forEach(item => {
      rows.push({ Type: 'SQL Injection', Line: item.line, IP: item.ip, Severity: item.severity, Details: item.text });
    });
  }
  if (analysis.xss?.length) {
    analysis.xss.forEach(item => {
      rows.push({ Type: 'XSS Attempt', Line: item.line, IP: item.ip, Severity: item.severity, Details: item.text });
    });
  }
  if (analysis.dirTraversal?.length) {
    analysis.dirTraversal.forEach(item => {
      rows.push({ Type: 'Directory Traversal', Line: item.line, IP: item.ip, Severity: item.severity, Details: item.text });
    });
  }
  if (analysis.suspiciousAgents?.length) {
    analysis.suspiciousAgents.forEach(item => {
      rows.push({ Type: 'Suspicious Agent', Line: item.line, IP: item.ip, Severity: item.severity, Details: item.text });
    });
  }
  if (analysis.bruteForceIps?.length) {
    analysis.bruteForceIps.forEach(item => {
      rows.push({ Type: 'Brute Force IP', Line: '', IP: item.ip, Severity: item.severity, Details: `${item.count} failed logins` });
    });
  }

  const csv = Papa.unparse(rows);

  res.header('Content-Type', 'text/csv');
  res.attachment('log_analysis_report.csv');
  res.send(csv);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Log File Analyzer backend running on port ${PORT}`);
});