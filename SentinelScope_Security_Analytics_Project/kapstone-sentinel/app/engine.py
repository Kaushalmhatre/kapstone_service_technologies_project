"""Security log detection, correlation, and compliance mapping."""
from datetime import datetime, timezone
from collections import defaultdict
from .ml import load_or_train

SEVERITY_SCORE = {"info": 5, "low": 10, "medium": 35, "high": 65, "critical": 90}
CONTROL_MAP = {
 "authentication": ("NIST CSF 2.0 PR.AA", "Manage identities, authentication, and access controls", "Enforce MFA, review authentication policy, and investigate anomalous sign-ins."),
 "access": ("ISO 27001:2022 A.5.15", "Access control", "Review privileged access, revoke unapproved elevation, and enforce least privilege."),
 "network": ("NIST CSF 2.0 DE.CM", "Continuous monitoring", "Block confirmed malicious indicators, inspect network telemetry, and validate egress controls."),
 "endpoint": ("ISO 27001:2022 A.8.7", "Protection against malware", "Isolate affected endpoints, preserve evidence, and verify endpoint protection coverage."),
 "data": ("ISO 27001:2022 A.8.12", "Data leakage prevention", "Contain data movement, preserve audit records, and review DLP and removable-media policy."),
 "email": ("ISO 27001:2022 A.8.7", "Protection against malware", "Quarantine the message, inspect related endpoints, and block matching indicators."),
 "dns": ("NIST CSF 2.0 DE.CM", "Continuous monitoring", "Review DNS telemetry, block verified malicious domains, and check affected hosts."),
 "firewall": ("ISO 27001:2022 A.8.20", "Network security", "Review firewall rules, rate-limit scanning, and validate exposed services."),
}

def _parse_time(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def _risk_score(severity, probability, message):
    base = SEVERITY_SCORE.get(str(severity).lower(), 25)
    msg = str(message).lower()
    indicators = ["malware", "exfiltration", "command and control", "privilege escalation", "sensitive files", "port scanning", "failed login", "suspicious"]
    rule_boost = min(20, sum(4 for word in indicators if word in msg))
    return max(0, min(100, int(round(base * 0.55 + probability * 35 + rule_boost))))

def analyze_logs(logs):
    model = load_or_train()
    normalized=[]
    for i, raw in enumerate(logs):
        if not isinstance(raw, dict): continue
        message = str(raw.get("message", "")).strip()
        event_type = str(raw.get("event_type", "unknown")).strip().lower()
        severity = str(raw.get("severity", "medium")).strip().lower()
        if not message: continue
        normalized.append({"event_id": str(raw.get("event_id") or f"EVT-{i+1:04}"), "timestamp": str(raw.get("timestamp") or ""), "event_type": event_type, "source_ip": str(raw.get("source_ip") or "unknown"), "asset": str(raw.get("asset") or "unknown"), "severity": severity if severity in SEVERITY_SCORE else "medium", "message": message})
    texts=[f"{x['event_type']} {x['severity']} {x['message']}" for x in normalized]
    probabilities=model.predict_proba(texts) if texts else []
    classes=list(model.classes_)
    results=[]
    for item, probs in zip(normalized, probabilities):
        p=float(probs[classes.index("suspicious")]) if "suspicious" in classes else 0.0
        prediction=str(model.predict([f"{item['event_type']} {item['severity']} {item['message']}"])[0])
        risk=_risk_score(item["severity"],p,item["message"])
        rule_hits=[]
        m=item["message"].lower()
        for phrase in ["failed login", "privilege escalation", "malware", "command and control", "port scanning", "sensitive files", "exfiltration", "suspicious attachment", "unusual location"]:
            if phrase in m: rule_hits.append(phrase)
        suspicious = prediction == "suspicious" or risk >= 55 or bool(rule_hits)
        control, control_name, remediation=CONTROL_MAP.get(item["event_type"], ("NIST CSF 2.0 DE.AE", "Analyze adverse events", "Validate the alert, collect supporting logs, and follow the incident response process."))
        results.append({**item,"prediction":"suspicious" if suspicious else "normal","model_prediction":prediction,"suspicious_probability":round(p,4),"risk_score":risk,"risk_level":"Critical" if risk>=85 else "High" if risk>=65 else "Medium" if risk>=35 else "Low","rule_hits":rule_hits,"evidence":f"Model probability {p:.0%}; severity={item['severity']}; " + ("rule indicators: " + ", ".join(rule_hits) if rule_hits else "no explicit keyword rule matched"),"compliance":{"framework_control":control,"control_name":control_name,"remediation":remediation}})
    # Correlate by source IP or asset when events are close in time; unknown keys excluded.
    buckets=defaultdict(list)
    for event in results:
        dt=_parse_time(event["timestamp"])
        if event["source_ip"]!="unknown": buckets[("ip",event["source_ip"])].append((dt,event))
        if event["asset"]!="unknown": buckets[("asset",event["asset"])].append((dt,event))
    incident_sets=[]
    for (kind,key), entries in buckets.items():
        suspicious=[e for dt,e in entries if e["prediction"]=="suspicious"]
        if len(suspicious)<2: continue
        times=[_parse_time(e["timestamp"]) for e in suspicious]; valid=[t for t in times if t]
        if len(valid)>=2 and (max(valid)-min(valid)).total_seconds()>3600: continue
        ids=frozenset(e["event_id"] for e in suspicious)
        if len(ids)>=2: incident_sets.append((ids,kind,key))
    # Merge overlapping groups into one incident to avoid duplicate IP/asset incidents.
    merged=[]
    for ids,kind,key in incident_sets:
        overlap=next((x for x in merged if x["ids"] & ids),None)
        if overlap: overlap["ids"].update(ids); overlap["entities"].add(f"{kind}: {key}")
        else: merged.append({"ids":set(ids),"entities":{f"{kind}: {key}"}})
    incidents=[]
    byid={e["event_id"]:e for e in results}
    for n,group in enumerate(merged,1):
        events=[byid[x] for x in group["ids"] if x in byid]
        incidents.append({"incident_id":f"INC-{n:03}","title":_incident_title(events),"event_ids":[e["event_id"] for e in events],"entities":sorted(group["entities"]),"affected_assets":sorted({e["asset"] for e in events}),"severity":max((e["risk_score"] for e in events),default=0),"event_count":len(events),"summary":f"{len(events)} suspicious events share a source IP or asset within a one-hour window. Review evidence before confirming an incident."})
    suspicious=[x for x in results if x["prediction"]=="suspicious"]
    return {"summary":{"total_events":len(results),"suspicious_events":len(suspicious),"normal_events":len(results)-len(suspicious),"incidents":len(incidents),"critical_high":sum(x["risk_level"] in ("Critical","High") for x in suspicious),"avg_risk":round(sum(x["risk_score"] for x in results)/len(results),1) if results else 0},"events":results,"incidents":incidents}

def _incident_title(events):
    types={e["event_type"] for e in events}
    if "authentication" in types and ("access" in types or "data" in types): return "Possible account compromise and data access"
    if "network" in types or "firewall" in types: return "Suspicious network activity"
    if "endpoint" in types or "email" in types: return "Possible malware or endpoint incident"
    return "Correlated suspicious activity"
