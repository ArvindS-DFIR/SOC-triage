require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const SYSTEM_PROMPT = `You are an expert SOC/DFIR analyst AI. Analyze the security alert or incident description provided and return a structured JSON triage report.

IMPORTANT: Return ONLY raw valid JSON. No markdown, no backticks, no explanation before or after. Just the JSON object.

Use this exact structure:
{
  "severity": "CRITICAL",
  "confidence": 95,
  "alert_type": "Malware Execution",
  "summary": "2-3 sentence plain-English summary of what is happening.",
  "iocs": ["185.193.126.44", "file.docm", "sha256hash"],
  "mitre_tactics": ["Execution", "Command and Control"],
  "mitre_techniques": ["T1059.001 - PowerShell", "T1566.001 - Spearphishing Attachment"],
  "recommended_actions": ["Isolate host immediately", "Block destination IP", "Collect memory dump"],
  "false_positive_likelihood": "Low",
  "false_positive_reason": "WINWORD spawning hidden PowerShell with encoded command is a strong malware indicator.",
  "escalate": true,
  "escalation_reason": "Finance user, active C2 connection, and macro-enabled document indicate active compromise.",
  "missing_context": ["Parent and grandparent process lineage", "Command-line arguments of the process", "User context / privilege level"]
}

GUIDANCE ON missing_context:
- This field lists the most valuable pieces of information NOT present in the alert that would materially sharpen the triage verdict. Return an empty array [] only if the alert is genuinely complete (rare for EDR alerts).
- For EDR/endpoint alerts (CrowdStrike, Defender, SentinelOne, etc.), process lineage is critical. If the alert does not include the parent process, grandparent process, or full process tree, ALWAYS list that as missing context — e.g. "Parent/grandparent process lineage (was this spawned by a browser, Office app, or legitimate installer?)".
- High-value missing items to check for and flag if absent:
  * Parent and grandparent process names + paths
  * Full command-line of parent process
  * User/account context and privilege level (standard user vs admin vs SYSTEM)
  * Binary signing status and signer name
  * Network outcome — was the connection successful, what IPs did the domain resolve to, was data transferred
  * File creation events — did the suspicious process drop or modify files
  * Persistence indicators — registry run keys, scheduled tasks, services, startup folder entries created around the same time
  * Sibling/concurrent process activity on the host within the same time window
  * Whether the detection was prevented, blocked, or only logged (PatternDispositionDescription, NetworkContainmentState, etc.)
  * Originating email or web source (for phishing-adjacent alerts)
  * File hash if a payload was involved
- Keep each missing_context item short and specific — name the artifact and briefly why it matters.
- When key context like process lineage is missing, reflect this in your confidence score (lower it noticeably — typically by 20-30 points) rather than assuming the worst or best case.
- For "living off the land" / LOLBin alerts (regsvr32, rundll32, mshta, wscript, certutil, bitsadmin, etc.), parent process context is essential — these binaries are legitimate, so the malicious signal is entirely in WHO spawned them and WHY. Always flag missing parent context for these.

Be concise, technical, and accurate. Base your analysis strictly on the input. Do not fabricate process names, hashes, or IPs that are not in the alert.`;

// Helper: check if string is an IP address
function isIP(str) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(str.trim());
}

// Enrich a single IP via AbuseIPDB
async function enrichIP(ip) {
  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`,
      {
        headers: {
          "Key": process.env.ABUSEIPDB_API_KEY,
          "Accept": "application/json"
        }
      }
    );
    const data = await res.json();
    const d = data.data;
    return {
      ip,
      abuseScore: d.abuseConfidenceScore,
      country: d.countryCode,
      isp: d.isp,
      totalReports: d.totalReports,
      lastReported: d.lastReportedAt,
      usageType: d.usageType,
      isMalicious: d.abuseConfidenceScore > 20
    };
  } catch {
    return { ip, error: "Lookup failed" };
  }
}

// Triage endpoint
app.post("/api/triage", async (req, res) => {
  const { alert } = req.body;
  if (!alert || !alert.trim()) {
    return res.status(400).json({ error: "No alert text provided" });
  }

  try {
    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.GROQ_API_KEY}`
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          temperature: 0.2,
          max_tokens: 2000,
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: alert }
          ]
        })
      }
    );

    const data = await response.json();
    if (data.error) throw new Error(data.error.message);

    const raw = data.choices?.[0]?.message?.content || "";
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("No JSON in response");

    // Clean bad escape characters before parsing
    const cleaned = jsonMatch[0]
      .replace(/[\x00-\x1F\x7F]/g, " ")
      .replace(/\\(?!["\\/bfnrtu])/g, "\\\\");

    const result = JSON.parse(cleaned);

    // Auto-enrich any IPs found in the IOCs list
    const ips = (result.iocs || []).filter(isIP);
    if (ips.length > 0) {
      const enriched = await Promise.all(ips.map(enrichIP));
      result.ioc_enrichment = enriched;
    }

    res.json(result);
  } catch (err) {
    console.error("Triage error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Chat endpoint
app.post("/api/chat", async (req, res) => {
  const { alert, triage, messages } = req.body;
  if (!messages || !alert) return res.status(400).json({ error: "Missing data" });

  try {
    const systemPrompt = `You are a senior DFIR (Digital Forensics and Incident Response) analyst with deep, hands-on experience in incident response, threat hunting, EDR/SIEM investigation, malware triage, and cloud forensics. You think methodically, reason from evidence, and prioritize accuracy over speculation.

Original alert:
${alert}

Triage result:
${JSON.stringify(triage, null, 2)}

Help the analyst investigate this incident. You can:
- Answer questions about the alert grounded in the evidence provided
- Write ticket comments (clear, factual, ready to paste)
- Draft escalation emails
- Suggest forensic steps, artifacts to collect, and log sources to pull
- Explain MITRE ATT&CK techniques accurately
- Identify likely threat actor patterns and TTPs
- Give containment and remediation recommendations

CRITICAL accuracy rules:
- Base your answers on the evidence in the alert and triage result. Do not invent details that are not present.
- If you are uncertain about a CVE number, MITRE technique ID, threat actor attribution, or tool syntax, say so explicitly rather than guessing. It is better to say "I'm not certain" than to state a fabricated fact.
- Only cite a CVE if you are confident it is real and relevant. Do not generate plausible-looking but unverified CVE numbers.
- Only cite MITRE technique IDs you are confident exist. Use the official TNNNN / TNNNN.NNN format.
- When recommending commands or queries (PowerShell, KQL, SPL, etc.), note if syntax should be verified before running in production.
- Clearly separate what the evidence shows from what is inference or hypothesis.

Be concise, technical, and practical. Format ticket comments and emails clearly.`;

    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        temperature: 0.3,
        max_tokens: 1000,
        messages: [
          { role: "system", content: systemPrompt },
          ...messages.map(m => ({ role: m.role, content: m.content }))
        ]
      })
    });

    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    const reply = data.choices?.[0]?.message?.content || "No response";
    res.json({ reply });
  } catch (err) {
    console.error("Chat error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Standalone IP enrichment endpoint
app.post("/api/enrich", async (req, res) => {
  const { ip } = req.body;
  if (!ip || !isIP(ip)) {
    return res.status(400).json({ error: "Valid IP address required" });
  }
  try {
    const result = await enrichIP(ip);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

// MITRE ATT&CK cache — loaded once at startup
let MITRE_TECHNIQUES = new Set();
let MITRE_LOADED = false;

async function loadMITRE() {
  try {
    const res = await fetch("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json");
    const data = await res.json();
    data.objects?.forEach(obj => {
      if (obj.type === "attack-pattern" && obj.external_references) {
        const ref = obj.external_references.find(r => r.source_name === "mitre-attack");
        if (ref?.external_id) MITRE_TECHNIQUES.add(ref.external_id);
      }
    });
    MITRE_LOADED = true;
    console.log(`MITRE loaded: ${MITRE_TECHNIQUES.size} techniques`);
  } catch (e) {
    console.error("MITRE load failed:", e.message);
  }
}
loadMITRE();

// Validate a CVE against NVD (free, no auth)
async function validateCVE(cveId) {
  try {
    const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`);
    if (!res.ok) return { valid: false, reason: `NVD returned ${res.status}` };
    const data = await res.json();
    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) return { valid: false, reason: "Not found in NVD" };
    return {
      valid: true,
      description: vuln.descriptions?.[0]?.value?.slice(0, 200),
      severity: vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
                vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ||
                vuln.metrics?.cvssMetricV2?.[0]?.baseSeverity,
      score: vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
             vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ||
             vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore,
    };
  } catch (e) {
    return { valid: false, reason: e.message };
  }
}

// Validation endpoint — checks MITRE techniques and CVEs in any text
app.post("/api/validate", async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "No text provided" });

  const issues = [];

  // Extract MITRE IDs (Txxxx or Txxxx.xxx)
  const mitreMatches = [...text.matchAll(/\bT\d{4}(?:\.\d{3})?\b/g)].map(m => m[0]);
  const uniqueMitre = [...new Set(mitreMatches)];

  for (const id of uniqueMitre) {
    if (MITRE_LOADED && !MITRE_TECHNIQUES.has(id)) {
      issues.push({
        type: "invalid_mitre",
        severity: "warning",
        value: id,
        message: `${id} is not a valid MITRE ATT&CK technique`
      });
    }
  }

  // Extract CVEs
  const cveMatches = [...text.matchAll(/CVE-\d{4}-\d{4,7}/gi)].map(m => m[0].toUpperCase());
  const uniqueCVEs = [...new Set(cveMatches)];
  const currentYear = new Date().getFullYear();

  for (const cve of uniqueCVEs) {
    const year = parseInt(cve.split("-")[1]);
    if (year < 1999 || year > currentYear) {
      issues.push({
        type: "invalid_cve_year",
        severity: "warning",
        value: cve,
        message: `${cve} has invalid year (${year})`
      });
      continue;
    }
    const result = await validateCVE(cve);
    if (!result.valid) {
      issues.push({
        type: "invalid_cve",
        severity: "critical",
        value: cve,
        message: `${cve} not found in NVD — likely hallucinated`
      });
    }
  }

  res.json({
    mitre_checked: uniqueMitre,
    cves_checked: uniqueCVEs,
    issues,
    valid: issues.length === 0,
  });
});

// Threat Intel — auto-detect input and query multiple sources
function detectType(input) {
  const s = input.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return "ip";
  if (/^[a-fA-F0-9]{32}$/.test(s)) return "md5";
  if (/^[a-fA-F0-9]{40}$/.test(s)) return "sha1";
  if (/^[a-fA-F0-9]{64}$/.test(s)) return "sha256";
  if (/^https?:\/\//.test(s)) return "url";
  if (/^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/.test(s)) return "domain";
  return "unknown";
}

async function vtLookup(type, value) {
  let endpoint;
  if (type === "ip") endpoint = `ip_addresses/${value}`;
  else if (type === "domain") endpoint = `domains/${value}`;
  else if (type === "url") endpoint = `urls/${Buffer.from(value).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_")}`;
  else if (["md5", "sha1", "sha256"].includes(type)) endpoint = `files/${value}`;
  else return null;

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/${endpoint}`, {
      headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY }
    });
    if (!res.ok) return { error: `VT returned ${res.status}` };
    const data = await res.json();
    const attr = data.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
      reputation: attr.reputation,
      lastAnalysisDate: attr.last_analysis_date,
      meaningful_name: attr.meaningful_name,
      type_description: attr.type_description,
      tags: attr.tags || [],
      country: attr.country,
      as_owner: attr.as_owner,
      registrar: attr.registrar,
      creation_date: attr.creation_date,
    };
  } catch (e) {
    return { error: e.message };
  }
}

app.post("/api/threat-intel", async (req, res) => {
  const { indicator } = req.body;
  if (!indicator || !indicator.trim()) {
    return res.status(400).json({ error: "No indicator provided" });
  }

  const value = indicator.trim();
  const type = detectType(value);
  if (type === "unknown") {
    return res.status(400).json({ error: "Could not detect indicator type. Provide IP, domain, URL, MD5, SHA1, or SHA256." });
  }

  try {
    const sources = {};

    // VirusTotal lookup (works for all types)
    sources.virustotal = await vtLookup(type, value);

    // AbuseIPDB only for IPs
    if (type === "ip") {
      sources.abuseipdb = await enrichIP(value);
    }

    // AI summary
    const summaryPrompt = `You are a threat intel analyst. Summarize the following lookup data for indicator "${value}" (type: ${type}).

Data: ${JSON.stringify(sources)}

Return ONLY raw JSON with this structure:
{
  "verdict": "Malicious|Suspicious|Clean|Unknown",
  "confidence": 0-100,
  "risk_score": 0-100,
  "summary": "2-3 sentence analyst-friendly summary",
  "key_findings": ["finding 1", "finding 2", "finding 3"],
  "recommended_action": "Block/Monitor/Allow with brief reasoning"
}`;

    const aiRes = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        temperature: 0.2,
        max_tokens: 800,
        messages: [{ role: "user", content: summaryPrompt }]
      })
    });

    const aiData = await aiRes.json();
    let aiSummary = null;
    if (!aiData.error) {
      const raw = aiData.choices?.[0]?.message?.content || "";
      const match = raw.match(/\{[\s\S]*\}/);
      if (match) {
        try {
          const cleaned = match[0].replace(/[\x00-\x1F\x7F]/g, " ").replace(/\\(?!["\\/bfnrtu])/g, "\\\\");
          aiSummary = JSON.parse(cleaned);
        } catch {}
      }
    }

    res.json({
      indicator: value,
      type,
      sources,
      ai_summary: aiSummary,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Threat intel error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`SOC Triage backend running on port ${PORT}`));
