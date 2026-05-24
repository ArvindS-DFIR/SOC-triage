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

app.post("/api/triage", async (req, res) => {
  const { alert } = req.body;

  if (!alert || !alert.trim()) {
    return res.status(400).json({ error: "No alert text provided" });
  }

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${process.env.GOOGLE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [
            {
              parts: [{ text: `${SYSTEM_PROMPT}\n\nAlert to analyze:\n${alert}` }]
            }
          ],
          generationConfig: {
            temperature: 0.2,
            maxOutputTokens: 2000,
          }
        })
      }
    );

    const data = await response.json();

    if (data.error) throw new Error(data.error.message);

    const raw = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("No JSON in response");

    const result = JSON.parse(jsonMatch[0]);
    res.json(result);
  } catch (err) {
    console.error("Triage error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`SOC Triage backend running on port ${PORT}`));
