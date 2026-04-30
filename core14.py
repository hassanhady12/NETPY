"""
core14.py — Nuclei Vulnerability Scanner
Runs nuclei against a target and streams JSON-line results.
"""

import os
import shutil
import subprocess
import json


def _get_nuclei_path():
    local = os.path.join(os.path.dirname(__file__), "nuclei.exe")
    if os.path.isfile(local):
        return local
    return shutil.which("nuclei") or shutil.which("nuclei.exe")


def run_nuclei(target, severity=None, tags=None, templates=None, timeout=300):
    """
    Run nuclei against *target* and return a list of finding dicts.

    Each dict contains: template_id, name, severity, host, matched_at,
    description, type, curl_command (optional).

    Args:
        target    – domain or URL, e.g. "example.com" or "https://example.com"
        severity  – comma-separated string: "critical,high,medium,low,info"
        tags      – comma-separated nuclei tags, e.g. "cve,sqli,xss"
        templates – path to a templates dir/file (defaults to nuclei's built-in)
        timeout   – subprocess timeout in seconds
    """
    binary = _get_nuclei_path()
    if not binary:
        return {"error": "nuclei not found — place nuclei.exe in project directory or PATH"}

    # pass plain domain — nuclei probes both http/https automatically

    cmd = [binary, "-u", target, "-jsonl", "-nc", "-silent", "-timeout", "5"]

    if severity:
        cmd += ["-severity", severity]
    if tags:
        cmd += ["-tags", tags]
    if templates:
        cmd += ["-t", templates]

    findings = []
    errors = []

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                finding = {
                    "template_id":   obj.get("template-id", ""),
                    "name":          info.get("name", ""),
                    "severity":      info.get("severity", "unknown"),
                    "host":          obj.get("host", ""),
                    "matched_at":    obj.get("matched-at", ""),
                    "type":          obj.get("type", ""),
                    "description":   info.get("description", ""),
                    "tags":          info.get("tags", []),
                    "curl_command":  obj.get("curl-command", ""),
                    "timestamp":     obj.get("timestamp", ""),
                }
                findings.append(finding)
            except json.JSONDecodeError:
                pass

        if proc.returncode not in (0, 1) and proc.stderr:
            errors.append(proc.stderr.strip()[:500])

    except subprocess.TimeoutExpired:
        errors.append(f"Scan timed out after {timeout}s")
    except Exception as e:
        errors.append(str(e))

    return {"target": target, "findings": findings, "errors": errors}


def run_nuclei_stream(target, severity=None, tags=None, templates=None, timeout=300):
    """
    Generator that yields finding dicts one-by-one as nuclei outputs them.
    Yields dicts with a 'type' key: 'finding' | 'error' | 'done'.
    """
    binary = _get_nuclei_path()
    if not binary:
        yield {"type": "error", "message": "nuclei not found — place nuclei.exe in project directory or PATH"}
        return

    # pass plain domain — nuclei probes both http/https automatically

    cmd = [binary, "-u", target, "-jsonl", "-nc", "-silent", "-timeout", "5"]

    if severity:
        cmd += ["-severity", severity]
    if tags:
        cmd += ["-tags", tags]
    if templates:
        cmd += ["-t", templates]

    count = 0
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                finding = {
                    "type":          "finding",
                    "template_id":   obj.get("template-id", ""),
                    "name":          info.get("name", ""),
                    "severity":      info.get("severity", "unknown"),
                    "host":          obj.get("host", ""),
                    "matched_at":    obj.get("matched-at", ""),
                    "vuln_type":     obj.get("type", ""),
                    "description":   info.get("description", ""),
                    "tags":          info.get("tags", []),
                    "curl_command":  obj.get("curl-command", ""),
                    "timestamp":     obj.get("timestamp", ""),
                }
                count += 1
                yield finding
            except json.JSONDecodeError:
                pass

        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        yield {"type": "error", "message": f"Scan timed out after {timeout}s"}
    except Exception as e:
        yield {"type": "error", "message": str(e)}

    yield {"type": "done", "total": count}
