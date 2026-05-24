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

    const result = JSON.parse(jsonMatch[0]);

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

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`SOC Triage backend running on port ${PORT}`));
