"""Conservative, evidence-cited investigative rules and a local ATT&CK subset."""

import re

from .models import AttackMapping, Finding

CATALOG = {
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1105": "Ingress Tool Transfer",
}


def analyze(report):
    for e in report.evidence:
        v = e.normalized_value
        if e.evidence_type in {"signature", "sandbox_detection"}:
            report.findings.append(
                Finding(
                    finding_id="source-" + e.evidence_id,
                    kind="source_detection",
                    rule_id="sandbox-label-v1",
                    description="Sandbox-reported detection",
                    rationale="Source label is retained; it is not independently verified ground truth.",
                    evidence_ids=[e.evidence_id],
                )
            )
        if e.evidence_type == "registry" and isinstance(v, dict):
            path = str(v.get("path", "")).replace("/", "\\").lower()
            operation = str(v.get("operation", "")).lower()
            if re.search(r"\\currentversion\\run(?:once)?(?:\\|$)", path) and any(
                x in operation for x in ("write", "written", "set", "create")
            ):
                rationale = "Source reports modification of a Windows autostart Run key; value and execution require analyst verification."
                report.findings.append(
                    Finding(
                        finding_id="run-" + e.evidence_id,
                        kind="deterministic_interpretation",
                        rule_id="run-key-write-v1",
                        description="Potential persistence-related registry modification",
                        rationale=rationale,
                        evidence_ids=[e.evidence_id],
                    )
                )
                report.attack.append(
                    AttackMapping(
                        technique_id="T1547.001",
                        name=CATALOG["T1547.001"],
                        origin="system_inferred",
                        rationale=rationale,
                        evidence_ids=[e.evidence_id],
                    )
                )
        if e.evidence_type == "process" and isinstance(v, dict):
            name = str(v.get("process_name", "")).lower().replace("/", "\\").split("\\")[-1]
            if (
                name in {"powershell.exe", "pwsh.exe"}
                and isinstance(v.get("command_line"), str)
                and v["command_line"].strip()
            ):
                report.attack.append(
                    AttackMapping(
                        technique_id="T1059.001",
                        name=CATALOG["T1059.001"],
                        origin="system_inferred",
                        rationale="Observed PowerShell process with a command line supports a candidate interpreter mapping, not malicious intent.",
                        evidence_ids=[e.evidence_id],
                    )
                )
            parent = v.get("parent_name")
            if (
                isinstance(parent, str)
                and parent.lower() in {"winword.exe", "excel.exe", "outlook.exe"}
                and name in {"cmd.exe", "powershell.exe", "pwsh.exe"}
            ):
                report.findings.append(
                    Finding(
                        finding_id="child-" + e.evidence_id,
                        kind="deterministic_interpretation",
                        rule_id="office-shell-child-v1",
                        description="Office application reported spawning a command interpreter",
                        rationale="An explicit parent name and child process name support this investigative signal; legitimate automation is possible.",
                        evidence_ids=[e.evidence_id],
                    )
                )
        if e.evidence_type == "file" and isinstance(v, dict):
            path = str(v.get("path", v.get("filepath", ""))).lower().replace("/", "\\")
            operation = str(v.get("operation", "")).lower()
            if (
                path.endswith((".exe", ".dll", ".ps1", ".vbs", ".js", ".bat"))
                and any(segment in path for segment in ("\\temp\\", "\\appdata\\", "\\startup\\"))
                and any(op in operation for op in ("create", "write", "written"))
            ):
                report.findings.append(
                    Finding(
                        finding_id="file-" + e.evidence_id,
                        kind="deterministic_interpretation",
                        rule_id="noteworthy-file-creation-v1",
                        description="Executable or script reported written in a noteworthy location",
                        rationale="A creation/write summary and path extension support review; neither content nor execution is established.",
                        evidence_ids=[e.evidence_id],
                    )
                )
        if e.evidence_type in {"attack_source", "signature"} and isinstance(v, dict):
            ids = v.get("ttp", v.get("ttps", v.get("technique_id", [])))
            if isinstance(ids, str):
                ids = [ids]
            if isinstance(ids, list):
                for tid in ids:
                    if isinstance(tid, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid):
                        report.attack.append(
                            AttackMapping(
                                technique_id=tid,
                                name=CATALOG.get(tid, "Not in local catalog"),
                                origin="source_reported",
                                rationale="Sandbox mapping retained; supporting behavior has not been independently established.",
                                evidence_ids=[e.evidence_id],
                                status="unsupported_source_claim",
                            )
                        )
    for i in report.iocs:
        if i.type in {"domain", "ip", "url"} and len(i.evidence_ids) > 1:
            report.findings.append(
                Finding(
                    finding_id="repeat-" + i.evidence_ids[0] + "-" + i.type,
                    kind="deterministic_interpretation",
                    rule_id="repeated-network-indicator-v1",
                    description="Network indicator appears in multiple source records",
                    rationale="Repeated records may reflect retries or duplicated telemetry; not proof of distinct connections.",
                    evidence_ids=i.evidence_ids,
                )
            )
