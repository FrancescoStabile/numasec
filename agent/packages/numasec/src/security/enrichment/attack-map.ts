/**
 * MITRE ATT&CK technique mapping from CWE IDs.
 *
 * Maps common web application CWE weakness identifiers to ATT&CK for
 * Enterprise techniques, providing tactic context for each finding.
 */

export interface AttackTechnique {
  techniqueId: string
  techniqueName: string
  tactic: string
}

const CWE_TO_ATTACK: Record<string, AttackTechnique> = {
  // A01:2021 — Broken Access Control
  "CWE-22": { techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" },
  "CWE-23": { techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" },
  "CWE-284": { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  "CWE-285": { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  "CWE-352": { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" },
  "CWE-425": { techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" },
  "CWE-548": { techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" },
  "CWE-601": { techniqueId: "T1566.002", techniqueName: "Phishing: Spearphishing Link", tactic: "Initial Access" },
  "CWE-639": { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
  "CWE-862": { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  "CWE-863": { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  "CWE-269": { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  "CWE-942": { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },

  // A02:2021 — Cryptographic Failures
  "CWE-295": { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Credential Access" },
  "CWE-319": { techniqueId: "T1040", techniqueName: "Network Sniffing", tactic: "Credential Access" },
  "CWE-326": { techniqueId: "T1600", techniqueName: "Weaken Encryption", tactic: "Defense Evasion" },
  "CWE-327": { techniqueId: "T1600", techniqueName: "Weaken Encryption", tactic: "Defense Evasion" },
  "CWE-328": { techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access" },
  "CWE-330": { techniqueId: "T1552", techniqueName: "Unsecured Credentials", tactic: "Credential Access" },
  "CWE-347": { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Credential Access" },

  // A03:2021 — Injection
  "CWE-20": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "CWE-77": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  "CWE-78": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  "CWE-79": { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
  "CWE-89": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "CWE-90": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "CWE-94": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  "CWE-95": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  "CWE-98": { techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" },
  "CWE-611": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "CWE-643": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "CWE-917": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  "CWE-1336": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },

  // A07:2021 — Identification and Authentication Failures
  "CWE-287": { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
  "CWE-288": { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
  "CWE-306": { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
  "CWE-307": { techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access" },
  "CWE-384": { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" },
  "CWE-521": { techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access" },
  "CWE-798": { techniqueId: "T1078.001", techniqueName: "Valid Accounts: Default Accounts", tactic: "Initial Access" },

  // A08:2021 — Software and Data Integrity Failures
  "CWE-434": { techniqueId: "T1105", techniqueName: "Ingress Tool Transfer", tactic: "Command and Control" },
  "CWE-502": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  "CWE-829": { techniqueId: "T1195", techniqueName: "Supply Chain Compromise", tactic: "Initial Access" },
  "CWE-915": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },

  // A10:2021 — SSRF
  "CWE-918": { techniqueId: "T1090", techniqueName: "Proxy", tactic: "Command and Control" },
}

/** Return ATT&CK technique for a CWE ID, or undefined. */
export function getAttackTechnique(cweId: string): AttackTechnique | undefined {
  return CWE_TO_ATTACK[cweId]
}
