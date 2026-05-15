"""
core19.py — Shannon Integration
https://github.com/KeygraphHQ/shannon

Shannon: Autonomous security testing tool
- يحلل الكود المصدري + يشغّل exploits حقيقية
- يتطلب: Node.js (npx) + Docker
- يدعم: OWASP Top 10 (XSS, SQLi, SSRF, Auth bypass, ...)
- يُخرج: تقرير Markdown في workspaces/

الاستخدام:
  npx @keygraph/shannon start -u <url> [-r <repo_path>]
"""

import os
import re
import shutil
import subprocess
import threading
import time
import glob as _glob


# ─── Prerequisites check ──────────────────────────────────────────────────────

def check_prerequisites():
    """
    يتحقق من وجود Node.js و Docker
    يُرجع dict: {ok: bool, missing: list, details: dict}
    """
    missing = []
    details = {}

    # Node.js / npx
    npx = shutil.which("npx")
    if npx:
        try:
            v = subprocess.check_output(["node", "--version"],
                                        capture_output=True, text=True, timeout=5)
            details["node"] = v.strip()
        except Exception:
            details["node"] = "found"
    else:
        missing.append("Node.js (npx)")
        details["node"] = None

    # Docker
    docker = shutil.which("docker")
    if docker:
        try:
            v = subprocess.check_output(["docker", "--version"],
                                        capture_output=True, text=True, timeout=5)
            # تحقق من تشغيل Docker daemon
            subprocess.check_output(["docker", "info"],
                                    capture_output=True, timeout=10)
            details["docker"] = v.strip()
        except subprocess.TimeoutExpired:
            missing.append("Docker (not running)")
            details["docker"] = "installed but not running"
        except Exception:
            missing.append("Docker (not running)")
            details["docker"] = "installed but not running"
    else:
        missing.append("Docker")
        details["docker"] = None

    return {
        "ok":      len(missing) == 0,
        "missing": missing,
        "details": details,
    }


# ─── Workspace reader ─────────────────────────────────────────────────────────

def _read_latest_report(workspace_dir="./workspaces"):
    """
    يقرأ أحدث تقرير Markdown من مجلد workspaces
    يُرجع نص التقرير أو None
    """
    try:
        pattern = os.path.join(workspace_dir, "**", "*.md")
        files   = _glob.glob(pattern, recursive=True)
        if not files:
            return None
        latest = max(files, key=os.path.getmtime)
        with open(latest, encoding="utf-8", errors="replace") as f:
            return f.read(), latest
    except Exception:
        return None


def _parse_report(md_text):
    """
    يحوّل تقرير Shannon Markdown لـ list من findings
    """
    findings = []
    if not md_text:
        return findings

    # Shannon يكتب sections بـ ## أو ### لكل ثغرة
    vuln_blocks = re.split(r'\n#{1,3}\s+', md_text)

    sev_map = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "low",
        "info":     "info",
    }

    for block in vuln_blocks:
        if not block.strip():
            continue

        lines = block.strip().splitlines()
        if not lines:
            continue

        title   = lines[0].strip()
        content = "\n".join(lines[1:]).strip()

        # اكتشاف الـ severity من الكلمات في الـ block
        sev = "info"
        block_lower = block.lower()
        for s in ("critical", "high", "medium", "low"):
            if s in block_lower:
                sev = s
                break

        # استخراج الـ URL/endpoint إذا وُجد
        url_match = re.search(r'(https?://[^\s\)\"\']+)', content)
        url = url_match.group(1) if url_match else ""

        # استخراج الـ proof/exploit
        proof = ""
        proof_match = re.search(r'(?:proof|exploit|payload|poc)[:\s]+(.{10,200})',
                                content, re.IGNORECASE)
        if proof_match:
            proof = proof_match.group(1).strip()

        if len(title) > 5:
            findings.append({
                "title":          title,
                "severity":       sev,
                "sev_color":      {"critical":"red","high":"red",
                                   "medium":"yellow","low":"blue","info":"green"}.get(sev,"blue"),
                "url":            url,
                "description":    content[:500],
                "proof":          proof,
            })

    return findings


# ─── Stream runner ────────────────────────────────────────────────────────────

def run_shannon_stream(target_url, repo_path=None, workspace_name=None, timeout=600):
    """
    Generator — يبث logs من Shannon واحدة واحدة.

    target_url     : URL للتطبيق المستهدف
    repo_path      : مسار الكود المصدري (اختياري — لـ white-box)
    workspace_name : اسم الـ workspace (اختياري)
    timeout        : ثانية قبل إيقاف الفحص (افتراضي 10 دقائق)
    """

    # تحقق من المتطلبات
    prereq = check_prerequisites()
    if not prereq["ok"]:
        yield {
            "type":    "error",
            "message": f"Missing prerequisites: {', '.join(prereq['missing'])}. "
                       f"Please install them first.",
            "details": prereq["details"],
        }
        return

    # بناء الأمر
    cmd = ["npx", "--yes", "@keygraph/shannon", "start", "-u", target_url]
    if repo_path and os.path.isdir(repo_path):
        cmd += ["-r", repo_path]
    if workspace_name:
        cmd += ["-w", workspace_name]

    yield {"type": "log", "message": f"🚀 Starting Shannon..."}
    yield {"type": "log", "message": f"   Target: {target_url}"}
    if repo_path:
        yield {"type": "log", "message": f"   Repo:   {repo_path}"}
    yield {"type": "log", "message": f"   CMD: {' '.join(cmd)}"}

    start_time = time.time()
    log_lines  = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # دمج stderr مع stdout
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        # قراءة الـ output سطراً سطراً
        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            if not line:
                continue

            log_lines.append(line)

            # تصنيف السطر
            line_lower = line.lower()
            if any(k in line_lower for k in ("error","failed","exception")):
                level = "error"
            elif any(k in line_lower for k in ("warning","warn")):
                level = "warn"
            elif any(k in line_lower for k in ("found","detected","vulnerable",
                                                "exploit","success","✓","✅")):
                level = "success"
            else:
                level = "info"

            yield {"type": "log", "message": line, "level": level}

            # timeout
            if time.time() - start_time > timeout:
                proc.terminate()
                yield {"type": "log", "message": "⏱️ Timeout reached — stopping scan",
                       "level": "warn"}
                break

        proc.wait(timeout=30)

    except FileNotFoundError:
        yield {"type": "error",
               "message": "npx not found. Please install Node.js from https://nodejs.org"}
        return
    except Exception as e:
        yield {"type": "error", "message": f"Shannon error: {e}"}
        return

    # قراءة التقرير من workspaces/
    yield {"type": "log", "message": "📄 Reading report..."}
    result = _read_latest_report()

    if result:
        report_text, report_path = result
        findings = _parse_report(report_text)

        yield {
            "type":        "report",
            "report_path": report_path,
            "report_md":   report_text,
            "findings":    findings,
        }
        yield {
            "type":     "done",
            "findings": len(findings),
            "duration": round(time.time() - start_time),
        }
    else:
        yield {"type": "log", "message": "⚠️ No report found in workspaces/"}
        yield {"type": "done", "findings": 0,
               "duration": round(time.time() - start_time)}
