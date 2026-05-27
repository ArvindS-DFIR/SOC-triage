import { useState, useRef, useEffect } from "react";

const SEVERITY_COLORS = {
  CRITICAL: { bg: "#ff2d2d", text: "#fff", glow: "0 0 20px rgba(255,45,45,0.6)" },
  HIGH: { bg: "#ff6b00", text: "#fff", glow: "0 0 20px rgba(255,107,0,0.5)" },
  MEDIUM: { bg: "#f5c400", text: "#000", glow: "0 0 20px rgba(245,196,0,0.4)" },
  LOW: { bg: "#00c896", text: "#000", glow: "0 0 20px rgba(0,200,150,0.4)" },
  INFO: { bg: "#4488ff", text: "#fff", glow: "0 0 20px rgba(68,136,255,0.4)" },
};

const EXAMPLE_ALERTS = [
  "CrowdStrike alert: Suspicious PowerShell execution detected on host CORP-WS-042. Command: powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwA= User: john.doe@corp.com, 2:34 AM local time",
  "Splunk alert: 47 failed login attempts in 3 minutes from IP 185.220.101.42 against Azure AD. Target accounts: admin@corp.com, ceo@corp.com, it-admin@corp.com. Source geo: Netherlands (Tor exit node).",
  "AWS GuardDuty: IAM user 'deploy-bot' called GetSecretValue on 23 secrets in 90 seconds. User last active 6 months ago. No associated EC2/Lambda activity. Source IP: 34.201.88.12",
];

const QUICK_PROMPTS = [
  "Write a ticket comment for this alert",
  "Draft an escalation email to my manager",
  "What logs should I collect for forensics?",
  "What malware family is this likely linked to?",
  "What is the containment priority?",
  "Is this a known threat actor TTP?",
];

function TypingIndicator() {
  return (
    <div style={{ display: "flex", gap: 6, alignItems: "center", padding: "8px 0" }}>
      {[0, 1, 2].map(i => (
        <div key={i} style={{
          width: 7, height: 7, borderRadius: "50%", background: "#4488ff",
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
      fontSize: 11, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase",
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

function Label({ children, small }) {
  return (
    <div style={{
      color: "#4488ff", fontFamily: "'Space Mono', monospace",
      fontSize: small ? 10 : 11, letterSpacing: 1.5, textTransform: "uppercase",
      marginBottom: small ? 4 : 8, fontWeight: 700,
    }}>{children}</div>
  );
}

function formatTicketComment(r) {
  const lines = [];
  lines.push(`[${r.severity}] ${r.alert_type}`);
  lines.push(`Confidence: ${r.confidence}%`);
  lines.push("");
  lines.push(`Summary: ${r.summary}`);
  lines.push("");

  if (r.mitre_tactics?.length || r.mitre_techniques?.length) {
    const m = [...(r.mitre_tactics || []), ...(r.mitre_techniques || [])].join(", ");
    lines.push(`MITRE: ${m}`);
    lines.push("");
  }

  if (r.iocs?.length) {
    lines.push("IOCs:");
    r.iocs.forEach(ioc => {
      const enrich = r.ioc_enrichment?.find(e => e.ip === ioc);
      if (enrich) {
        lines.push(`- ${ioc} (${enrich.isMalicious ? "Malicious" : "Clean"} - AbuseIPDB ${enrich.abuseScore}%, ${enrich.country})`);
      } else {
        lines.push(`- ${ioc}`);
      }
    });
    lines.push("");
  }

  if (r.recommended_actions?.length) {
    lines.push("Recommended Actions:");
    r.recommended_actions.forEach((a, i) => lines.push(`${i + 1}. ${a}`));
    lines.push("");
  }

  lines.push(`False Positive: ${r.false_positive_likelihood} - ${r.false_positive_reason}`);
  if (r.escalate) {
    lines.push("");
    lines.push(`ESCALATION: ${r.escalation_reason}`);
  }
  lines.push("");
  lines.push("Triaged by: SOC Triage AI");
  return lines.join("\n");
}

function CopyButton({ text, label = "Copy as Ticket Comment" }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };
  return (
    <button onClick={copy} style={{
      background: copied ? "rgba(0,200,150,0.15)" : "rgba(68,136,255,0.1)",
      border: `1px solid ${copied ? "#00c896" : "#4488ff66"}`,
      color: copied ? "#00c896" : "#7ab3ff",
      padding: "5px 12px", borderRadius: 4, cursor: "pointer",
      fontFamily: "'Space Mono', monospace", fontSize: 10, fontWeight: 700,
      letterSpacing: 1, transition: "all 0.15s",
    }}>
      {copied ? "✓ COPIED" : `📋 ${label}`}
    </button>
  );
}

// Valid MITRE technique ID pattern: T followed by 4 digits, optionally .NNN
const MITRE_PATTERN = /^T\d{4}(\.\d{3})?$/;

function validateTriage(r) {
  const issues = [];

  // Check MITRE techniques have valid IDs
  if (r.mitre_techniques?.length) {
    r.mitre_techniques.forEach(t => {
      const idMatch = t.match(/^(T\d{4}(?:\.\d{3})?)/);
      if (!idMatch) {
        issues.push({
          type: "invalid_mitre",
          severity: "warning",
          message: `MITRE technique "${t}" doesn't match valid format (TNNNN or TNNNN.NNN)`
        });
      }
    });
  }

  // Check contradictions with IOC enrichment
  if (r.ioc_enrichment?.length) {
    r.ioc_enrichment.forEach(e => {
      // If AI says CRITICAL but all IPs are clean, flag it
      if ((r.severity === "CRITICAL" || r.severity === "HIGH") && !e.isMalicious && e.abuseScore < 10) {
        issues.push({
          type: "contradiction",
          severity: "warning",
          message: `IP ${e.ip} marked as IOC but AbuseIPDB shows clean (score ${e.abuseScore}%)`
        });
      }
      // If AI says LOW/INFO but IP is highly malicious, flag it
      if ((r.severity === "LOW" || r.severity === "INFO") && e.isMalicious && e.abuseScore > 70) {
        issues.push({
          type: "contradiction",
          severity: "critical",
          message: `IP ${e.ip} is highly malicious (${e.abuseScore}%) but alert marked ${r.severity}`
        });
      }
    });
  }

  // Check confidence vs severity sanity
  if (r.severity === "CRITICAL" && r.confidence < 60) {
    issues.push({
      type: "low_confidence",
      severity: "warning",
      message: `CRITICAL severity but confidence only ${r.confidence}% — consider manual review`
    });
  }

  // Check escalation logic
  if ((r.severity === "CRITICAL" || r.severity === "HIGH") && !r.escalate) {
    issues.push({
      type: "logic_error",
      severity: "warning",
      message: `${r.severity} severity but no escalation flagged — likely AI inconsistency`
    });
  }

  return issues;
}

function TriageCard({ result }) {
  const c = SEVERITY_COLORS[result.severity] || SEVERITY_COLORS.INFO;
  return (
    <div style={{
      background: "rgba(10,14,24,0.9)", border: `1px solid ${c.bg}44`,
      borderRadius: 10, overflow: "hidden", animation: "fadeUp 0.4s ease",
    }}>
      <div style={{
        background: `linear-gradient(135deg, ${c.bg}22, transparent)`,
        borderBottom: `1px solid ${c.bg}33`, padding: "16px 20px",
        display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <SeverityBadge severity={result.severity} />
          <span style={{ color: "#ccd6f6", fontWeight: 600, fontSize: 14 }}>{result.alert_type}</span>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ color: "#8892b0", fontSize: 11, fontFamily: "'Space Mono', monospace" }}>
            confidence <span style={{ color: "#ccd6f6" }}>{result.confidence}%</span>
          </span>
          <span style={{
            background: result.escalate ? "#ff2d2d22" : "#00c89622",
            border: `1px solid ${result.escalate ? "#ff2d2d55" : "#00c89655"}`,
            color: result.escalate ? "#ff6b6b" : "#00c896",
            padding: "2px 10px", borderRadius: 3, fontSize: 10,
            fontFamily: "'Space Mono', monospace", fontWeight: 700,
          }}>
            {result.escalate ? "↑ ESCALATE" : "✓ NO ESCALATION"}
          </span>
          <CopyButton text={formatTicketComment(result)} />
        </div>
      </div>

      <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 16 }}>
        {/* Hallucination/validation check */}
        {(() => {
          const issues = validateTriage(result);
          if (issues.length === 0) {
            return (
              <div style={{
                background: "rgba(0,200,150,0.06)",
                border: "1px solid rgba(0,200,150,0.2)",
                borderRadius: 6, padding: "8px 12px",
                display: "flex", alignItems: "center", gap: 8,
              }}>
                <span style={{ color: "#00c896", fontSize: 12 }}>✓</span>
                <span style={{ color: "#00c896", fontSize: 11, fontFamily: "'Space Mono', monospace", letterSpacing: 1 }}>
                  VALIDATION PASSED — no inconsistencies detected
                </span>
              </div>
            );
          }
          return (
            <div style={{
              background: "rgba(245,196,0,0.08)",
              border: "1px solid rgba(245,196,0,0.25)",
              borderRadius: 6, padding: "10px 14px",
            }}>
              <div style={{
                color: "#f5c400", fontSize: 11, fontFamily: "'Space Mono', monospace",
                letterSpacing: 1, marginBottom: 8, fontWeight: 700,
              }}>
                ⚠ {issues.length} POTENTIAL AI ISSUE{issues.length > 1 ? "S" : ""} DETECTED
              </div>
              <ul style={{ margin: 0, padding: "0 0 0 16px", color: "#d4b540", fontSize: 12, lineHeight: 1.6 }}>
                {issues.map((iss, i) => (
                  <li key={i} style={{ color: iss.severity === "critical" ? "#ff9999" : "#d4b540" }}>
                    {iss.message}
                  </li>
                ))}
              </ul>
            </div>
          );
        })()}

        <div>
          <Label>Summary</Label>
          <p style={{ color: "#a8b2d8", lineHeight: 1.7, margin: 0, fontSize: 13 }}>{result.summary}</p>
        </div>

        {result.iocs?.length > 0 && (
          <div>
            <Label>IOCs</Label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {result.iocs.map((ioc, i) => (
                <span key={i} style={{
                  background: "#1a1f35", border: "1px solid #2d3555",
                  color: "#e6f1ff", padding: "2px 8px", borderRadius: 4,
                  fontFamily: "'Space Mono', monospace", fontSize: 10,
                }}>{ioc}</span>
              ))}
            </div>
          </div>
        )}

        {(result.mitre_tactics?.length > 0 || result.mitre_techniques?.length > 0) && (
          <div>
            <Label>MITRE ATT&CK</Label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {result.mitre_tactics?.map((t, i) => <MitrePill key={"tac"+i} label={t} />)}
              {result.mitre_techniques?.map((t, i) => <MitrePill key={"tec"+i} label={t} />)}
            </div>
          </div>
        )}

        {result.recommended_actions?.length > 0 && (
          <div>
            <Label>Recommended Actions</Label>
            <ol style={{ margin: 0, padding: "0 0 0 16px", display: "flex", flexDirection: "column", gap: 4 }}>
              {result.recommended_actions.map((a, i) => (
                <li key={i} style={{ color: "#a8b2d8", fontSize: 13, lineHeight: 1.6 }}>{a}</li>
              ))}
            </ol>
          </div>
        )}

        <div style={{
          background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 6, padding: "10px 14px",
          display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10,
        }}>
          <div>
            <Label small>False Positive Likelihood</Label>
            <span style={{
              color: result.false_positive_likelihood === "High" ? "#ff6b6b"
                : result.false_positive_likelihood === "Medium" ? "#f5c400" : "#00c896",
              fontWeight: 700, fontSize: 12,
            }}>{result.false_positive_likelihood}</span>
          </div>
          <div>
            <Label small>Reason</Label>
            <span style={{ color: "#8892b0", fontSize: 11, lineHeight: 1.5 }}>{result.false_positive_reason}</span>
          </div>
          {result.escalation_reason && (
            <div style={{ gridColumn: "1/-1" }}>
              <Label small>Escalation Note</Label>
              <span style={{ color: "#ff9999", fontSize: 11 }}>{result.escalation_reason}</span>
            </div>
          )}
        </div>

        {result.ioc_enrichment?.length > 0 && (
          <div>
            <Label>IOC Enrichment — AbuseIPDB</Label>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {result.ioc_enrichment.map((e, i) => (
                <div key={i} style={{
                  background: e.isMalicious ? "rgba(255,45,45,0.08)" : "rgba(0,200,150,0.06)",
                  border: `1px solid ${e.isMalicious ? "rgba(255,45,45,0.3)" : "rgba(0,200,150,0.2)"}`,
                  borderRadius: 6, padding: "10px 14px",
                  display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 8,
                }}>
                  <div><Label small>IP</Label><span style={{ color: "#e6f1ff", fontFamily: "'Space Mono', monospace", fontSize: 11 }}>{e.ip}</span></div>
                  <div><Label small>Abuse Score</Label><span style={{ color: e.abuseScore > 50 ? "#ff6b6b" : e.abuseScore > 20 ? "#f5c400" : "#00c896", fontWeight: 700, fontSize: 13 }}>{e.abuseScore}%</span></div>
                  <div><Label small>Country</Label><span style={{ color: "#a8b2d8", fontSize: 11 }}>{e.country || "Unknown"}</span></div>
                  <div><Label small>ISP</Label><span style={{ color: "#a8b2d8", fontSize: 11 }}>{e.isp || "Unknown"}</span></div>
                  <div><Label small>Reports</Label><span style={{ color: "#a8b2d8", fontSize: 11 }}>{e.totalReports ?? 0}</span></div>
                  <div><Label small>Verdict</Label><span style={{ color: e.isMalicious ? "#ff6b6b" : "#00c896", fontWeight: 700, fontSize: 11 }}>{e.isMalicious ? "⚠ MALICIOUS" : "✓ CLEAN"}</span></div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ChatPanel({ alertText, triageResult, baseUrl }) {
  const [messages, setMessages] = useState([
    { role: "assistant", content: "Alert triaged. Ask me anything about this incident — I'll help you investigate, write ticket comments, draft escalation emails, or suggest forensic steps." }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const sendMessage = async (text) => {
    const msg = text || input.trim();
    if (!msg) return;
    setInput("");
    const newMessages = [...messages, { role: "user", content: msg }];
    setMessages(newMessages);
    setLoading(true);

    try {
      const res = await fetch(`${baseUrl}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert: alertText,
          triage: triageResult,
          messages: newMessages,
        }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setMessages(m => [...m, { role: "assistant", content: data.reply }]);
    } catch (e) {
      setMessages(m => [...m, { role: "assistant", content: `Error: ${e.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      display: "flex", flexDirection: "column", height: "100%",
      background: "rgba(8,12,22,0.95)", border: "1px solid #1e2847",
      borderRadius: 10, overflow: "hidden",
    }}>
      {/* Header */}
      <div style={{
        padding: "12px 16px", background: "#0a0e1c",
        borderBottom: "1px solid #1e2847",
        display: "flex", alignItems: "center", gap: 8,
      }}>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#00c896", boxShadow: "0 0 8px #00c896" }} />
        <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#4488ff", letterSpacing: 2 }}>
          INVESTIGATION CHAT
        </span>
      </div>

      {/* Quick prompts */}
      <div style={{ padding: "10px 12px", borderBottom: "1px solid #1e2847", display: "flex", flexWrap: "wrap", gap: 6 }}>
        {QUICK_PROMPTS.map((p, i) => (
          <button key={i} onClick={() => sendMessage(p)} style={{
            background: "rgba(68,136,255,0.08)", border: "1px solid rgba(68,136,255,0.2)",
            color: "#7ab3ff", padding: "3px 8px", borderRadius: 4,
            cursor: "pointer", fontSize: 10, fontFamily: "'IBM Plex Sans', sans-serif",
            transition: "all 0.15s",
          }}
            onMouseEnter={e => { e.target.style.background = "rgba(68,136,255,0.18)"; }}
            onMouseLeave={e => { e.target.style.background = "rgba(68,136,255,0.08)"; }}
          >{p}</button>
        ))}
      </div>

      {/* Messages */}
      <div style={{ flex: 1, overflowY: "auto", padding: "12px 16px", display: "flex", flexDirection: "column", gap: 12 }}>
        {messages.map((m, i) => (
          <div key={i} style={{
            display: "flex", flexDirection: "column",
            alignItems: m.role === "user" ? "flex-end" : "flex-start",
          }}>
            <div style={{
              maxWidth: "90%",
              background: m.role === "user" ? "rgba(68,136,255,0.15)" : "rgba(255,255,255,0.04)",
              border: `1px solid ${m.role === "user" ? "rgba(68,136,255,0.3)" : "rgba(255,255,255,0.08)"}`,
              borderRadius: 8, padding: "8px 12px",
              color: m.role === "user" ? "#b3d4ff" : "#a8b2d8",
              fontSize: 12, lineHeight: 1.7,
              whiteSpace: "pre-wrap",
            }}>{m.content}</div>
          </div>
        ))}
        {loading && (
          <div style={{ display: "flex", alignItems: "flex-start" }}>
            <div style={{
              background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: 8, padding: "6px 12px",
            }}>
              <TypingIndicator />
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div style={{
        padding: "10px 12px", borderTop: "1px solid #1e2847",
        display: "flex", gap: 8, background: "#0a0e1c",
      }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendMessage()}
          placeholder="Ask anything about this alert..."
          style={{
            flex: 1, background: "rgba(255,255,255,0.04)",
            border: "1px solid #1e2847", borderRadius: 6,
            padding: "8px 12px", color: "#ccd6f6", fontSize: 12,
            fontFamily: "'IBM Plex Sans', sans-serif", outline: "none",
          }}
        />
        <button
          onClick={() => sendMessage()}
          disabled={loading || !input.trim()}
          style={{
            background: input.trim() && !loading ? "#4488ff" : "#1a2040",
            color: input.trim() && !loading ? "#fff" : "#2d3555",
            border: "none", borderRadius: 6, padding: "8px 14px",
            cursor: input.trim() && !loading ? "pointer" : "not-allowed",
            fontFamily: "'Space Mono', monospace", fontSize: 11, fontWeight: 700,
          }}
        >→</button>
      </div>
    </div>
  );
}

function ThreatIntel({ baseUrl }) {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const lookup = async () => {
    const text = input.trim();
    if (!text) return;
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await fetch(`${baseUrl}/api/threat-intel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indicator: text }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const verdictColor = (v) => ({
    Malicious: "#ff2d2d",
    Suspicious: "#ff6b00",
    Clean: "#00c896",
    Unknown: "#8892b0",
  }[v] || "#8892b0");

  return (
    <div>
      {/* Input */}
      <div style={{
        background: "rgba(13,17,30,0.8)", border: "1px solid #1e2847",
        borderRadius: 10, overflow: "hidden", marginBottom: 20,
      }}>
        <div style={{
          padding: "8px 14px", background: "#0a0e1c",
          borderBottom: "1px solid #1e2847",
        }}>
          <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#4a5280", letterSpacing: 1 }}>
            INDICATOR LOOKUP
          </span>
        </div>
        <div style={{ display: "flex", gap: 0 }}>
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && lookup()}
            placeholder="Enter IP, domain, URL, MD5, SHA1, or SHA256..."
            style={{
              flex: 1, background: "transparent", border: "none",
              padding: "16px", color: "#ccd6f6", fontSize: 14,
              fontFamily: "'Space Mono', monospace", outline: "none",
            }}
          />
          <button
            onClick={lookup}
            disabled={loading || !input.trim()}
            style={{
              background: input.trim() && !loading ? "#4488ff" : "#1a2040",
              color: input.trim() && !loading ? "#fff" : "#2d3555",
              border: "none", padding: "0 24px",
              cursor: input.trim() && !loading ? "pointer" : "not-allowed",
              fontFamily: "'Space Mono', monospace", fontSize: 12,
              fontWeight: 700, letterSpacing: 1,
            }}
          >{loading ? "LOOKING UP..." : "LOOKUP →"}</button>
        </div>
      </div>

      {/* Examples */}
      <div style={{ marginBottom: 24 }}>
        <span style={{ color: "#2d3555", fontSize: 11, fontFamily: "'Space Mono', monospace", marginRight: 8 }}>try:</span>
        {["8.8.8.8", "google.com", "185.234.219.88"].map((ex, i) => (
          <button key={i} onClick={() => setInput(ex)} style={{
            background: "none", border: "1px solid #1e2847", color: "#4a5280",
            padding: "3px 10px", borderRadius: 4, cursor: "pointer",
            fontFamily: "'Space Mono', monospace", fontSize: 10, marginRight: 6,
          }}>{ex}</button>
        ))}
      </div>

      {loading && (
        <div style={{ background: "rgba(13,17,30,0.8)", border: "1px solid #1e2847", borderRadius: 10, padding: "14px 20px", marginBottom: 20 }}>
          <span style={{ color: "#4a5280", fontSize: 12, fontFamily: "'Space Mono', monospace" }}>querying threat intel sources...</span>
          <TypingIndicator />
        </div>
      )}

      {error && (
        <div style={{ background: "#ff2d2d11", border: "1px solid #ff2d2d44", borderRadius: 8, padding: "10px 14px", marginBottom: 20, color: "#ff6b6b", fontSize: 13 }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16, animation: "fadeUp 0.4s ease" }}>
          {/* Verdict card */}
          {result.ai_summary && (
            <div style={{
              background: "rgba(10,14,24,0.9)",
              border: `1px solid ${verdictColor(result.ai_summary.verdict)}44`,
              borderRadius: 10, overflow: "hidden",
            }}>
              <div style={{
                background: `linear-gradient(135deg, ${verdictColor(result.ai_summary.verdict)}22, transparent)`,
                borderBottom: `1px solid ${verdictColor(result.ai_summary.verdict)}33`,
                padding: "16px 20px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10,
              }}>
                <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                  <span style={{
                    background: verdictColor(result.ai_summary.verdict),
                    color: result.ai_summary.verdict === "Clean" ? "#000" : "#fff",
                    padding: "3px 14px", borderRadius: 4,
                    fontFamily: "'Space Mono', monospace", fontSize: 11,
                    fontWeight: 700, letterSpacing: 2, textTransform: "uppercase",
                    boxShadow: `0 0 16px ${verdictColor(result.ai_summary.verdict)}88`,
                  }}>{result.ai_summary.verdict}</span>
                  <span style={{ color: "#ccd6f6", fontFamily: "'Space Mono', monospace", fontSize: 13 }}>{result.indicator}</span>
                  <span style={{ color: "#4a5280", fontSize: 11, fontFamily: "'Space Mono', monospace" }}>({result.type})</span>
                </div>
                <div style={{ display: "flex", gap: 16 }}>
                  <span style={{ color: "#8892b0", fontSize: 11, fontFamily: "'Space Mono', monospace" }}>
                    confidence <span style={{ color: "#ccd6f6" }}>{result.ai_summary.confidence}%</span>
                  </span>
                  <span style={{ color: "#8892b0", fontSize: 11, fontFamily: "'Space Mono', monospace" }}>
                    risk <span style={{ color: result.ai_summary.risk_score > 60 ? "#ff6b6b" : result.ai_summary.risk_score > 30 ? "#f5c400" : "#00c896" }}>{result.ai_summary.risk_score}/100</span>
                  </span>
                </div>
              </div>
              <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 14 }}>
                <div>
                  <Label>Summary</Label>
                  <p style={{ color: "#a8b2d8", margin: 0, fontSize: 13, lineHeight: 1.7 }}>{result.ai_summary.summary}</p>
                </div>
                {result.ai_summary.key_findings?.length > 0 && (
                  <div>
                    <Label>Key Findings</Label>
                    <ul style={{ margin: 0, padding: "0 0 0 16px", color: "#a8b2d8", fontSize: 13, lineHeight: 1.7 }}>
                      {result.ai_summary.key_findings.map((f, i) => <li key={i}>{f}</li>)}
                    </ul>
                  </div>
                )}
                <div>
                  <Label>Recommended Action</Label>
                  <p style={{ color: "#a8b2d8", margin: 0, fontSize: 13 }}>{result.ai_summary.recommended_action}</p>
                </div>
              </div>
            </div>
          )}

          {/* VirusTotal raw */}
          {result.sources?.virustotal && !result.sources.virustotal.error && (
            <div style={{ background: "rgba(13,17,30,0.6)", border: "1px solid #1e2847", borderRadius: 10, padding: "16px 20px" }}>
              <Label>VirusTotal</Label>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 12, marginTop: 8 }}>
                <div><Label small>Malicious</Label><span style={{ color: "#ff6b6b", fontWeight: 700, fontSize: 14 }}>{result.sources.virustotal.malicious}</span></div>
                <div><Label small>Suspicious</Label><span style={{ color: "#f5c400", fontWeight: 700, fontSize: 14 }}>{result.sources.virustotal.suspicious}</span></div>
                <div><Label small>Harmless</Label><span style={{ color: "#00c896", fontWeight: 700, fontSize: 14 }}>{result.sources.virustotal.harmless}</span></div>
                <div><Label small>Undetected</Label><span style={{ color: "#8892b0", fontWeight: 700, fontSize: 14 }}>{result.sources.virustotal.undetected}</span></div>
                <div><Label small>Total Engines</Label><span style={{ color: "#ccd6f6", fontWeight: 700, fontSize: 14 }}>{result.sources.virustotal.total}</span></div>
                {result.sources.virustotal.reputation !== undefined && (
                  <div><Label small>Reputation</Label><span style={{ color: "#ccd6f6", fontSize: 13 }}>{result.sources.virustotal.reputation}</span></div>
                )}
                {result.sources.virustotal.country && (
                  <div><Label small>Country</Label><span style={{ color: "#a8b2d8", fontSize: 12 }}>{result.sources.virustotal.country}</span></div>
                )}
                {result.sources.virustotal.as_owner && (
                  <div><Label small>AS Owner</Label><span style={{ color: "#a8b2d8", fontSize: 12 }}>{result.sources.virustotal.as_owner}</span></div>
                )}
                {result.sources.virustotal.registrar && (
                  <div><Label small>Registrar</Label><span style={{ color: "#a8b2d8", fontSize: 12 }}>{result.sources.virustotal.registrar}</span></div>
                )}
              </div>
            </div>
          )}

          {/* AbuseIPDB raw */}
          {result.sources?.abuseipdb && !result.sources.abuseipdb.error && (
            <div style={{ background: "rgba(13,17,30,0.6)", border: "1px solid #1e2847", borderRadius: 10, padding: "16px 20px" }}>
              <Label>AbuseIPDB</Label>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 12, marginTop: 8 }}>
                <div><Label small>Abuse Score</Label><span style={{ color: result.sources.abuseipdb.abuseScore > 50 ? "#ff6b6b" : result.sources.abuseipdb.abuseScore > 20 ? "#f5c400" : "#00c896", fontWeight: 700, fontSize: 14 }}>{result.sources.abuseipdb.abuseScore}%</span></div>
                <div><Label small>Country</Label><span style={{ color: "#a8b2d8", fontSize: 12 }}>{result.sources.abuseipdb.country || "—"}</span></div>
                <div><Label small>ISP</Label><span style={{ color: "#a8b2d8", fontSize: 12 }}>{result.sources.abuseipdb.isp || "—"}</span></div>
                <div><Label small>Usage Type</Label><span style={{ color: "#a8b2d8", fontSize: 12 }}>{result.sources.abuseipdb.usageType || "—"}</span></div>
                <div><Label small>Total Reports</Label><span style={{ color: "#a8b2d8", fontSize: 12 }}>{result.sources.abuseipdb.totalReports ?? 0}</span></div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function SOCTriage() {
  const [tab, setTab] = useState("triage");
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState(() => {
    try {
      const saved = localStorage.getItem("soc_triage_history");
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });
  const [alertText, setAlertText] = useState("");
  const textareaRef = useRef(null);
  const baseUrl = import.meta.env.VITE_API_URL || "";

  // Save history to localStorage whenever it changes
  useEffect(() => {
    try {
      localStorage.setItem("soc_triage_history", JSON.stringify(history));
    } catch {}
  }, [history]);

  const analyze = async (alertInput) => {
    const text = alertInput || input.trim();
    if (!text) return;
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const response = await fetch(`${baseUrl}/api/triage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert: text }),
      });
      const data = await response.json();
      if (data.error) throw new Error(data.error);
      setResult(data);
      setAlertText(text);
      setHistory(h => [{ input: text, result: data, ts: new Date().toISOString() }, ...h.slice(0, 49)]);
    } catch (e) {
      setError(`Analysis failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const useExample = (ex) => {
    setInput(ex);
    textareaRef.current?.focus();
  };

  return (
    <div style={{ minHeight: "100vh", background: "#070b16", fontFamily: "'IBM Plex Sans', sans-serif", color: "#ccd6f6" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=Space+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; }
        @keyframes pulse { 0%,100%{opacity:0.3;transform:scale(0.8)} 50%{opacity:1;transform:scale(1.2)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #2d3555; border-radius: 2px; }
      `}</style>

      <div style={{ maxWidth: result ? "100%" : 860, margin: "0 auto", padding: result ? "24px 20px" : "40px 20px", transition: "max-width 0.3s" }}>
        {/* Header */}
        <div style={{ marginBottom: 24, borderBottom: "1px solid #1a2040", paddingBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 6 }}>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#4488ff", boxShadow: "0 0 12px #4488ff" }} />
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#4488ff", letterSpacing: 3, textTransform: "uppercase" }}>SOC Triage AI // v0.2</span>
          </div>
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 600, color: "#e6f1ff", letterSpacing: -0.5 }}>
            {tab === "triage" ? "Security Alert Analyzer" : "Threat Intel Lookup"}
          </h1>

          {/* Tabs */}
          <div style={{ display: "flex", gap: 4, marginTop: 16 }}>
            {[
              { id: "triage", label: "ALERT TRIAGE" },
              { id: "intel", label: "THREAT INTEL" },
            ].map(t => (
              <button key={t.id} onClick={() => setTab(t.id)} style={{
                background: tab === t.id ? "rgba(68,136,255,0.15)" : "transparent",
                border: `1px solid ${tab === t.id ? "#4488ff" : "#1e2847"}`,
                color: tab === t.id ? "#7ab3ff" : "#4a5280",
                padding: "6px 16px", borderRadius: 6, cursor: "pointer",
                fontFamily: "'Space Mono', monospace", fontSize: 11, fontWeight: 700, letterSpacing: 1.5,
                transition: "all 0.15s",
              }}>{t.label}</button>
            ))}
          </div>
        </div>

        {tab === "intel" ? (
          <ThreatIntel baseUrl={baseUrl} />
        ) : (
        <>
        {/* What to paste guide — only show before result */}
        {!result && (
          <div style={{ marginBottom: 20, background: "rgba(68,136,255,0.05)", border: "1px solid rgba(68,136,255,0.15)", borderRadius: 10, padding: "14px 18px" }}>
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#4488ff", letterSpacing: 2, textTransform: "uppercase", marginBottom: 10 }}>What can you paste here?</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 8 }}>
              {[
                { icon: "🛡️", label: "EDR Alerts", desc: "CrowdStrike, Defender, SentinelOne" },
                { icon: "📊", label: "SIEM Results", desc: "Splunk, Sentinel incidents" },
                { icon: "☁️", label: "Cloud Alerts", desc: "AWS GuardDuty, Azure Defender" },
                { icon: "🔥", label: "Firewall Logs", desc: "Zscaler, Palo Alto, FortiGate" },
                { icon: "📧", label: "Phishing Reports", desc: "Email headers, URLs" },
                { icon: "📝", label: "Raw Logs", desc: "Windows events, syslog" },
              ].map((item, i) => (
                <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 6, padding: "8px 10px" }}>
                  <span style={{ fontSize: 14 }}>{item.icon}</span>
                  <div>
                    <div style={{ color: "#e6f1ff", fontSize: 12, fontWeight: 600, marginBottom: 2 }}>{item.label}</div>
                    <div style={{ color: "#8892b0", fontSize: 11 }}>{item.desc}</div>
                  </div>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid rgba(68,136,255,0.1)", color: "#8892b0", fontSize: 12 }}>
              💡 <span style={{ color: "#ccd6f6" }}>No special format needed.</span> Paste whatever you have or describe the incident in plain English.
            </div>
          </div>
        )}

        {/* Input area */}
        <div style={{ background: "rgba(13,17,30,0.8)", border: "1px solid #1e2847", borderRadius: 10, overflow: "hidden", marginBottom: 12, boxShadow: "0 4px 40px rgba(0,0,0,0.4)" }}>
          <div style={{ padding: "8px 14px", background: "#0a0e1c", borderBottom: "1px solid #1e2847", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#4a5280", letterSpacing: 1 }}>ALERT INPUT</span>
            <button onClick={() => { setInput(""); setResult(null); setError(null); }} style={{ background: "none", border: "none", color: "#4a5280", cursor: "pointer", fontSize: 11, fontFamily: "'Space Mono', monospace" }}>clear</button>
          </div>
          <textarea
            ref={textareaRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder={"Paste your alert here...\n\nExamples:\n• CrowdStrike / Defender / SentinelOne alert\n• Splunk search result or Sentinel incident\n• AWS GuardDuty / Azure Defender finding\n• Raw Windows event log or syslog lines\n• Phishing email headers\n• Or just describe the incident in plain English"}
            style={{ width: "100%", minHeight: 120, padding: "14px", background: "transparent", border: "none", resize: "vertical", color: "#ccd6f6", fontSize: 13, lineHeight: 1.7, fontFamily: "'IBM Plex Sans', sans-serif", outline: "none" }}
          />
          <div style={{ padding: "8px 14px", background: "#0a0e1c", borderTop: "1px solid #1e2847", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ color: "#2d3555", fontSize: 11, fontFamily: "'Space Mono', monospace" }}>{input.length} chars</span>
            <button onClick={() => analyze()} disabled={loading || !input.trim()} style={{
              background: input.trim() && !loading ? "#4488ff" : "#1a2040",
              color: input.trim() && !loading ? "#fff" : "#2d3555",
              border: "none", padding: "7px 22px", borderRadius: 6,
              cursor: input.trim() && !loading ? "pointer" : "not-allowed",
              fontFamily: "'Space Mono', monospace", fontSize: 12, fontWeight: 700, letterSpacing: 1,
              boxShadow: input.trim() && !loading ? "0 0 16px rgba(68,136,255,0.3)" : "none",
            }}>{loading ? "ANALYZING..." : "TRIAGE →"}</button>
          </div>
        </div>

        {/* Examples */}
        <div style={{ marginBottom: 24 }}>
          <span style={{ color: "#2d3555", fontSize: 11, fontFamily: "'Space Mono', monospace", marginRight: 8 }}>try example:</span>
          {["PowerShell", "Brute Force", "AWS IAM"].map((label, i) => (
            <button key={i} onClick={() => useExample(EXAMPLE_ALERTS[i])} style={{
              background: "none", border: "1px solid #1e2847", color: "#4a5280",
              padding: "3px 10px", borderRadius: 4, cursor: "pointer",
              fontFamily: "'Space Mono', monospace", fontSize: 10, marginRight: 6,
            }}
              onMouseEnter={e => { e.target.style.borderColor = "#4488ff"; e.target.style.color = "#4488ff"; }}
              onMouseLeave={e => { e.target.style.borderColor = "#1e2847"; e.target.style.color = "#4a5280"; }}
            >{label}</button>
          ))}
        </div>

        {/* Loading */}
        {loading && (
          <div style={{ background: "rgba(13,17,30,0.8)", border: "1px solid #1e2847", borderRadius: 10, padding: "14px 20px", marginBottom: 20 }}>
            <span style={{ color: "#4a5280", fontSize: 12, fontFamily: "'Space Mono', monospace" }}>analyzing alert...</span>
            <TypingIndicator />
          </div>
        )}

        {/* Error */}
        {error && (
          <div style={{ background: "#ff2d2d11", border: "1px solid #ff2d2d44", borderRadius: 8, padding: "10px 14px", marginBottom: 20, color: "#ff6b6b", fontSize: 13 }}>{error}</div>
        )}

        {/* Result + Chat side by side */}
        {result && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 380px", gap: 20, alignItems: "start" }}>
            <TriageCard result={result} />
            <div style={{ position: "sticky", top: 20, height: "80vh" }}>
              <ChatPanel alertText={alertText} triageResult={result} baseUrl={baseUrl} />
            </div>
          </div>
        )}

        {/* History */}
        {history.length > 0 && (
          <div style={{ marginTop: 32 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#4488ff", letterSpacing: 2, textTransform: "uppercase" }}>
                History ({history.length}) — saved in your browser
              </div>
              <button onClick={() => { if (confirm("Clear all triage history?")) setHistory([]); }} style={{
                background: "none", border: "1px solid #1e2847", color: "#4a5280",
                padding: "3px 10px", borderRadius: 4, cursor: "pointer",
                fontFamily: "'Space Mono', monospace", fontSize: 10,
              }}>clear all</button>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {history.map((h, i) => {
                const ts = h.ts ? new Date(h.ts) : null;
                return (
                  <button key={i} onClick={() => { setInput(h.input); setResult(h.result); setAlertText(h.input); }}
                    style={{ background: "rgba(13,17,30,0.6)", border: "1px solid #1e2847", borderRadius: 6, padding: "8px 14px", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, textAlign: "left", color: "#8892b0", fontSize: 12 }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = "#2d3555"}
                    onMouseLeave={e => e.currentTarget.style.borderColor = "#1e2847"}
                  >
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                      <span style={{ color: "#ccd6f6" }}>{h.result.alert_type || "Alert"}</span>
                      <span style={{ color: "#4a5280", marginLeft: 8 }}>{h.input.slice(0, 70)}...</span>
                    </span>
                    {ts && (
                      <span style={{ color: "#4a5280", fontSize: 10, fontFamily: "'Space Mono', monospace", whiteSpace: "nowrap" }}>
                        {ts.toLocaleDateString()} {ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    )}
                    <SeverityBadge severity={h.result.severity} />
                  </button>
                );
              })}
            </div>
          </div>
        )}
        </>
        )}
      </div>
    </div>
  );
}
