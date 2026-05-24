import { useState, useRef, useEffect } from "react";

const SEVERITY_COLORS = {
  CRITICAL: { bg: "#ff2d2d", text: "#fff", glow: "0 0 20px rgba(255,45,45,0.6)" },
  HIGH: { bg: "#ff6b00", text: "#fff", glow: "0 0 20px rgba(255,107,0,0.5)" },
  MEDIUM: { bg: "#f5c400", text: "#000", glow: "0 0 20px rgba(245,196,0,0.4)" },
  LOW: { bg: "#00c896", text: "#000", glow: "0 0 20px rgba(0,200,150,0.4)" },
  INFO: { bg: "#4488ff", text: "#fff", glow: "0 0 20px rgba(68,136,255,0.4)" },
};

const SYSTEM_PROMPT = `You are an expert SOC analyst AI. Analyze the security alert or incident description provided and return a structured JSON triage report.

IMPORTANT: Return ONLY raw valid JSON. No markdown, no backticks, no explanation before or after. Just the JSON object.

Use this exact structure:
{
  "severity": "CRITICAL",
  "confidence": 95,
  "alert_type": "Malware Execution",
  "summary": "2-3 sentence plain-English summary of what is happening.",
  "iocs": ["185.193.126.44", "7c4d91d9f3c4e28b...", "Payment_Advice_May2026.docm"],
  "mitre_tactics": ["Execution", "Command and Control"],
  "mitre_techniques": ["T1059.001 - PowerShell", "T1566.001 - Spearphishing Attachment"],
  "recommended_actions": ["Isolate host immediately", "Block destination IP", "Collect memory dump"],
  "false_positive_likelihood": "Low",
  "false_positive_reason": "WINWORD spawning hidden PowerShell with encoded command is a strong malware indicator.",
  "escalate": true,
  "escalation_reason": "Finance user, active C2 connection, and macro-enabled document indicate active compromise."
}

Be concise, technical, and accurate. Base your analysis strictly on the input.`;

const EXAMPLE_ALERTS = [
  "CrowdStrike alert: Suspicious PowerShell execution detected on host CORP-WS-042. Command: powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwA= User: john.doe@corp.com, 2:34 AM local time",
  "Splunk alert: 47 failed login attempts in 3 minutes from IP 185.220.101.42 against Azure AD. Target accounts: admin@corp.com, ceo@corp.com, it-admin@corp.com. Source geo: Netherlands (Tor exit node).",
  "AWS GuardDuty: IAM user 'deploy-bot' called GetSecretValue on 23 secrets in 90 seconds. User last active 6 months ago. No associated EC2/Lambda activity. Source IP: 34.201.88.12",
];

function TypingIndicator() {
  return (
    <div style={{ display: "flex", gap: 6, alignItems: "center", padding: "16px 0" }}>
      {[0, 1, 2].map(i => (
        <div key={i} style={{
          width: 8, height: 8, borderRadius: "50%", background: "#4488ff",
          animation: "pulse 1.2s ease-in-out infinite",
          animationDelay: `${i * 0.2}s`,
        }} />
      ))}
    </div>
  );
}

function SeverityBadge({ severity }) {
  const c = SEVERITY_COLORS[severity] || SEVERITY_COLORS.INFO;
  return (
    <span style={{
      background: c.bg, color: c.text, boxShadow: c.glow,
      padding: "3px 12px", borderRadius: 4, fontFamily: "'Space Mono', monospace",
      fontSize: 12, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase",
    }}>{severity}</span>
  );
}

function MitrePill({ label }) {
  return (
    <span style={{
      background: "rgba(68,136,255,0.12)", border: "1px solid rgba(68,136,255,0.3)",
      color: "#7ab3ff", padding: "2px 10px", borderRadius: 3,
      fontFamily: "'Space Mono', monospace", fontSize: 11,
    }}>{label}</span>
  );
}

function TriageCard({ result }) {
  const c = SEVERITY_COLORS[result.severity] || SEVERITY_COLORS.INFO;
  return (
    <div style={{
      background: "rgba(10,14,24,0.9)", border: `1px solid ${c.bg}44`,
      borderRadius: 10, overflow: "hidden", animation: "fadeUp 0.4s ease",
    }}>
      {/* Header */}
      <div style={{
        background: `linear-gradient(135deg, ${c.bg}22, transparent)`,
        borderBottom: `1px solid ${c.bg}33`, padding: "18px 24px",
        display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <SeverityBadge severity={result.severity} />
          <span style={{ color: "#ccd6f6", fontWeight: 600, fontSize: 15 }}>{result.alert_type}</span>
        </div>
        <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
          <span style={{ color: "#8892b0", fontSize: 12, fontFamily: "'Space Mono', monospace" }}>
            confidence <span style={{ color: "#ccd6f6" }}>{result.confidence}%</span>
          </span>
          <span style={{
            background: result.escalate ? "#ff2d2d22" : "#00c89622",
            border: `1px solid ${result.escalate ? "#ff2d2d55" : "#00c89655"}`,
            color: result.escalate ? "#ff6b6b" : "#00c896",
            padding: "2px 10px", borderRadius: 3, fontSize: 11,
            fontFamily: "'Space Mono', monospace", fontWeight: 700,
          }}>
            {result.escalate ? "↑ ESCALATE" : "✓ NO ESCALATION"}
          </span>
        </div>
      </div>

      <div style={{ padding: "20px 24px", display: "flex", flexDirection: "column", gap: 20 }}>
        {/* Summary */}
        <div>
          <Label>Summary</Label>
          <p style={{ color: "#a8b2d8", lineHeight: 1.7, margin: 0, fontSize: 14 }}>{result.summary}</p>
        </div>

        {/* IOCs */}
        {result.iocs?.length > 0 && (
          <div>
            <Label>IOCs Identified</Label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {result.iocs.map((ioc, i) => (
                <span key={i} style={{
                  background: "#1a1f35", border: "1px solid #2d3555",
                  color: "#e6f1ff", padding: "3px 10px", borderRadius: 4,
                  fontFamily: "'Space Mono', monospace", fontSize: 11,
                }}>{ioc}</span>
              ))}
            </div>
          </div>
        )}

        {/* MITRE */}
        {(result.mitre_tactics?.length > 0 || result.mitre_techniques?.length > 0) && (
          <div>
            <Label>MITRE ATT&CK</Label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {result.mitre_tactics?.map((t, i) => <MitrePill key={"tac"+i} label={t} />)}
              {result.mitre_techniques?.map((t, i) => <MitrePill key={"tec"+i} label={t} />)}
            </div>
          </div>
        )}

        {/* Actions */}
        {result.recommended_actions?.length > 0 && (
          <div>
            <Label>Recommended Actions</Label>
            <ol style={{ margin: 0, padding: "0 0 0 18px", display: "flex", flexDirection: "column", gap: 6 }}>
              {result.recommended_actions.map((a, i) => (
                <li key={i} style={{ color: "#a8b2d8", fontSize: 14, lineHeight: 1.6 }}>{a}</li>
              ))}
            </ol>
          </div>
        )}

        {/* FP Assessment */}
        <div style={{
          background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 6, padding: "12px 16px",
          display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12,
        }}>
          <div>
            <Label small>False Positive Likelihood</Label>
            <span style={{
              color: result.false_positive_likelihood === "High" ? "#ff6b6b"
                : result.false_positive_likelihood === "Medium" ? "#f5c400" : "#00c896",
              fontWeight: 700, fontSize: 13,
            }}>{result.false_positive_likelihood}</span>
          </div>
          <div>
            <Label small>Reason</Label>
            <span style={{ color: "#8892b0", fontSize: 12, lineHeight: 1.5 }}>{result.false_positive_reason}</span>
          </div>
          {result.escalation_reason && (
            <div style={{ gridColumn: "1/-1" }}>
              <Label small>Escalation Note</Label>
              <span style={{ color: "#ff9999", fontSize: 12 }}>{result.escalation_reason}</span>
            </div>
          )}
        </div>

        {/* IOC Enrichment */}
        {result.ioc_enrichment?.length > 0 && (
          <div>
            <Label>IOC Enrichment — AbuseIPDB</Label>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {result.ioc_enrichment.map((e, i) => (
                <div key={i} style={{
                  background: e.isMalicious ? "rgba(255,45,45,0.08)" : "rgba(0,200,150,0.06)",
                  border: `1px solid ${e.isMalicious ? "rgba(255,45,45,0.3)" : "rgba(0,200,150,0.2)"}`,
                  borderRadius: 6, padding: "12px 16px",
                  display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 10,
                }}>
                  <div>
                    <Label small>IP</Label>
                    <span style={{ color: "#e6f1ff", fontFamily: "'Space Mono', monospace", fontSize: 12 }}>{e.ip}</span>
                  </div>
                  <div>
                    <Label small>Abuse Score</Label>
                    <span style={{
                      color: e.abuseScore > 50 ? "#ff6b6b" : e.abuseScore > 20 ? "#f5c400" : "#00c896",
                      fontWeight: 700, fontSize: 14,
                    }}>{e.abuseScore}%</span>
                  </div>
                  <div>
                    <Label small>Country</Label>
                    <span style={{ color: "#a8b2d8", fontSize: 12 }}>{e.country || "Unknown"}</span>
                  </div>
                  <div>
                    <Label small>ISP</Label>
                    <span style={{ color: "#a8b2d8", fontSize: 12 }}>{e.isp || "Unknown"}</span>
                  </div>
                  <div>
                    <Label small>Total Reports</Label>
                    <span style={{ color: "#a8b2d8", fontSize: 12 }}>{e.totalReports ?? 0}</span>
                  </div>
                  <div>
                    <Label small>Verdict</Label>
                    <span style={{
                      color: e.isMalicious ? "#ff6b6b" : "#00c896",
                      fontWeight: 700, fontSize: 12,
                    }}>{e.isMalicious ? "⚠ MALICIOUS" : "✓ CLEAN"}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Label({ children, small }) {
  return (
    <div style={{
      color: "#4488ff", fontFamily: "'Space Mono', monospace",
      fontSize: small ? 10 : 11, letterSpacing: 1.5, textTransform: "uppercase",
      marginBottom: small ? 4 : 8, fontWeight: 700,
    }}>{children}</div>
  );
}

export default function SOCTriage() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const textareaRef = useRef(null);

  const analyze = async (alertText) => {
    const text = alertText || input.trim();
    if (!text) return;
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const baseUrl = import.meta.env.VITE_API_URL || "";
      const response = await fetch(`${baseUrl}/api/triage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert: text }),
      });
      const data = await response.json();
      if (data.error) throw new Error(data.error);
      setResult(data);
      setHistory(h => [{ input: text, result: data, ts: new Date() }, ...h.slice(0, 9)]);
    } catch (e) {
      setError(`Analysis failed: ${e.message}`);
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const useExample = (ex) => {
    setInput(ex);
    textareaRef.current?.focus();
  };

  return (
    <div style={{
      minHeight: "100vh",
      background: "#070b16",
      fontFamily: "'IBM Plex Sans', sans-serif",
      color: "#ccd6f6",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=Space+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; }
        @keyframes pulse { 0%,100%{opacity:0.3;transform:scale(0.8)} 50%{opacity:1;transform:scale(1.2)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
        @keyframes scanline {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }
        textarea:focus { outline: none; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #2d3555; border-radius: 2px; }
      `}</style>

      {/* Scanline effect */}
      <div style={{
        position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
        pointerEvents: "none", zIndex: 0, overflow: "hidden", opacity: 0.03,
      }}>
        <div style={{
          position: "absolute", width: "100%", height: 2,
          background: "linear-gradient(transparent, #4488ff, transparent)",
          animation: "scanline 8s linear infinite",
        }} />
      </div>

      <div style={{ maxWidth: 860, margin: "0 auto", padding: "40px 20px", position: "relative", zIndex: 1 }}>
        {/* Header */}
        <div style={{ marginBottom: 36, borderBottom: "1px solid #1a2040", paddingBottom: 24 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 8 }}>
            <div style={{
              width: 10, height: 10, borderRadius: "50%", background: "#4488ff",
              boxShadow: "0 0 12px #4488ff",
            }} />
            <span style={{
              fontFamily: "'Space Mono', monospace", fontSize: 11,
              color: "#4488ff", letterSpacing: 3, textTransform: "uppercase",
            }}>SOC Triage AI // v0.1</span>
          </div>
          <h1 style={{
            margin: 0, fontSize: 28, fontWeight: 600, color: "#e6f1ff", letterSpacing: -0.5,
          }}>Security Alert Analyzer</h1>
          <p style={{ margin: "6px 0 0", color: "#4a5280", fontSize: 14 }}>
            Paste a raw security alert below — the AI will triage it instantly
          </p>
        </div>

        {/* What to paste guide */}
        <div style={{
          marginBottom: 24,
          background: "rgba(68,136,255,0.05)",
          border: "1px solid rgba(68,136,255,0.15)",
          borderRadius: 10, padding: "16px 20px",
        }}>
          <div style={{
            fontFamily: "'Space Mono', monospace", fontSize: 10,
            color: "#4488ff", letterSpacing: 2, textTransform: "uppercase", marginBottom: 12,
          }}>What can you paste here?</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10 }}>
            {[
              { icon: "🛡️", label: "EDR Alerts", desc: "CrowdStrike, Defender, SentinelOne detections" },
              { icon: "📊", label: "SIEM Results", desc: "Splunk search output, Sentinel incidents" },
              { icon: "☁️", label: "Cloud Alerts", desc: "AWS GuardDuty, Azure Defender, GCP SCC" },
              { icon: "🔥", label: "Firewall / Proxy Logs", desc: "Zscaler, Palo Alto, FortiGate log lines" },
              { icon: "📧", label: "Phishing Reports", desc: "Suspicious email headers, URLs, attachments" },
              { icon: "📝", label: "Raw Log Lines", desc: "Any Windows event logs, syslog, auth logs" },
            ].map((item, i) => (
              <div key={i} style={{
                display: "flex", gap: 10, alignItems: "flex-start",
                background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.06)",
                borderRadius: 6, padding: "10px 12px",
              }}>
                <span style={{ fontSize: 16 }}>{item.icon}</span>
                <div>
                  <div style={{ color: "#e6f1ff", fontSize: 12, fontWeight: 600, marginBottom: 2 }}>{item.label}</div>
                  <div style={{ color: "#8892b0", fontSize: 11, lineHeight: 1.5 }}>{item.desc}</div>
                </div>
              </div>
            ))}
          </div>
          <div style={{
            marginTop: 12, paddingTop: 12, borderTop: "1px solid rgba(68,136,255,0.1)",
            color: "#8892b0", fontSize: 12, lineHeight: 1.6,
          }}>
            💡 <span style={{ color: "#ccd6f6" }}>No special format needed.</span> Paste whatever you have — raw text, copied alert output, log dump, or even just describe the incident in plain English.
          </div>
        </div>

        {/* Input area */}
        <div style={{
          background: "rgba(13,17,30,0.8)", border: "1px solid #1e2847",
          borderRadius: 10, overflow: "hidden", marginBottom: 16,
          boxShadow: "0 4px 40px rgba(0,0,0,0.4)",
        }}>
          <div style={{
            padding: "10px 16px", background: "#0a0e1c",
            borderBottom: "1px solid #1e2847",
            display: "flex", justifyContent: "space-between", alignItems: "center",
          }}>
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#4a5280", letterSpacing: 1 }}>
              ALERT INPUT
            </span>
            <button onClick={() => setInput("")} style={{
              background: "none", border: "none", color: "#4a5280",
              cursor: "pointer", fontSize: 11, fontFamily: "'Space Mono', monospace",
            }}>clear</button>
          </div>
          <textarea
            ref={textareaRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder={"Paste your alert here...\n\nExamples:\n• CrowdStrike / Defender / SentinelOne alert\n• Splunk search result or Sentinel incident\n• AWS GuardDuty / Azure Defender finding\n• Raw Windows event log or syslog lines\n• Phishing email headers or suspicious URL report\n• Or just describe the incident in plain English"}
            style={{
              width: "100%", minHeight: 140, padding: "16px",
              background: "transparent", border: "none", resize: "vertical",
              color: "#ccd6f6", fontSize: 13, lineHeight: 1.7,
              fontFamily: "'IBM Plex Sans', sans-serif",
            }}
          />
          <div style={{
            padding: "10px 16px", background: "#0a0e1c",
            borderTop: "1px solid #1e2847",
            display: "flex", justifyContent: "space-between", alignItems: "center",
          }}>
            <span style={{ color: "#2d3555", fontSize: 11, fontFamily: "'Space Mono', monospace" }}>
              {input.length} chars
            </span>
            <button
              onClick={() => analyze()}
              disabled={loading || !input.trim()}
              style={{
                background: input.trim() && !loading ? "#4488ff" : "#1a2040",
                color: input.trim() && !loading ? "#fff" : "#2d3555",
                border: "none", padding: "8px 24px", borderRadius: 6,
                cursor: input.trim() && !loading ? "pointer" : "not-allowed",
                fontFamily: "'Space Mono', monospace", fontSize: 12,
                fontWeight: 700, letterSpacing: 1, transition: "all 0.2s",
                boxShadow: input.trim() && !loading ? "0 0 16px rgba(68,136,255,0.3)" : "none",
              }}
            >
              {loading ? "ANALYZING..." : "TRIAGE →"}
            </button>
          </div>
        </div>

        {/* Examples */}
        <div style={{ marginBottom: 32 }}>
          <span style={{ color: "#2d3555", fontSize: 11, fontFamily: "'Space Mono', monospace", marginRight: 10 }}>
            try example:
          </span>
          {["PowerShell", "Brute Force", "AWS IAM"].map((label, i) => (
            <button key={i} onClick={() => useExample(EXAMPLE_ALERTS[i])} style={{
              background: "none", border: "1px solid #1e2847", color: "#4a5280",
              padding: "3px 10px", borderRadius: 4, cursor: "pointer",
              fontFamily: "'Space Mono', monospace", fontSize: 10,
              marginRight: 6, transition: "all 0.15s",
            }}
              onMouseEnter={e => { e.target.style.borderColor = "#4488ff"; e.target.style.color = "#4488ff"; }}
              onMouseLeave={e => { e.target.style.borderColor = "#1e2847"; e.target.style.color = "#4a5280"; }}
            >{label}</button>
          ))}
        </div>

        {/* Loading */}
        {loading && (
          <div style={{
            background: "rgba(13,17,30,0.8)", border: "1px solid #1e2847",
            borderRadius: 10, padding: "16px 24px", marginBottom: 24,
          }}>
            <span style={{ color: "#4a5280", fontSize: 12, fontFamily: "'Space Mono', monospace" }}>
              analyzing alert...
            </span>
            <TypingIndicator />
          </div>
        )}

        {/* Error */}
        {error && (
          <div style={{
            background: "#ff2d2d11", border: "1px solid #ff2d2d44",
            borderRadius: 8, padding: "12px 16px", marginBottom: 24,
            color: "#ff6b6b", fontSize: 13,
          }}>{error}</div>
        )}

        {/* Result */}
        {result && <TriageCard result={result} />}

        {/* History */}
        {history.length > 1 && (
          <div style={{ marginTop: 40 }}>
            <div style={{
              fontFamily: "'Space Mono', monospace", fontSize: 10,
              color: "#2d3555", letterSpacing: 2, textTransform: "uppercase", marginBottom: 12,
            }}>Recent Triages</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {history.slice(1).map((h, i) => (
                <button key={i} onClick={() => { setInput(h.input); setResult(h.result); }}
                  style={{
                    background: "rgba(13,17,30,0.6)", border: "1px solid #1e2847",
                    borderRadius: 6, padding: "10px 16px", cursor: "pointer",
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                    textAlign: "left", color: "#8892b0", fontSize: 12, transition: "all 0.15s",
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = "#2d3555"}
                  onMouseLeave={e => e.currentTarget.style.borderColor = "#1e2847"}
                >
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                    {h.input.slice(0, 80)}...
                  </span>
                  <SeverityBadge severity={h.result.severity} />
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
