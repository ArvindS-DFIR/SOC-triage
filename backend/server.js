require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const SYSTEM_PROMPT = `You are an expert SOC analyst AI. Analyze the security alert or incident description provided and return a structured JSON triage report.

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
  "escalation_reason": "Finance user, active C2 connection, and macro-enabled document indicate active compromise."
}

Be concise, technical, and accurate. Base your analysis strictly on the input.`;

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
    const systemPrompt = `You are an expert SOC analyst AI assistant helping investigate a security alert.

Original alert:
${alert}

Triage result:
${JSON.stringify(triage, null, 2)}

Help the analyst investigate this incident. You can:
- Answer questions about the alert
- Write ticket comments
- Draft escalation emails
- Suggest forensic steps and log collection
- Explain MITRE techniques
- Identify threat actor patterns
- Give containment recommendations

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
