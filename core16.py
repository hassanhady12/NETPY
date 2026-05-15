"""
core16.py — HTTPX Prober
يفحص قائمة hosts/subdomains ويكتشف:
  - Status Code
  - Title
  - Web Server
  - Tech Stack
  - IP
  - CDN
  - TLS Info
  - Response Time
"""

import os
import json
import shutil
import subprocess
import tempfile


def _get_httpx_path():
    local = os.path.join(os.path.dirname(__file__), "httpx.exe")
    if os.path.isfile(local):
        return local
    return shutil.which("httpx") or shutil.which("httpx.exe")


def run_httpx(targets, timeout=10, threads=50, follow_redirects=True):
    """
    يفحص قائمة targets دفعة واحدة.
    targets: list of domains/IPs/URLs
    يرجع list of dicts.
    """
    binary = _get_httpx_path()
    if not binary:
        return {"error": "httpx not found"}

    # اكتب الـ targets لملف مؤقت
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                     delete=False, encoding="utf-8") as f:
        f.write("\n".join(targets))
        tmp_path = f.name

    cmd = [
        binary,
        "-l", tmp_path,
        "-json",
        "-silent",
        "-threads", str(threads),
        "-timeout", str(timeout),
        "-title",
        "-status-code",
        "-tech-detect",
        "-web-server",
        "-ip",
        "-cdn",
        "-response-time",
        "-no-color",
    ]
    if follow_redirects:
        cmd.append("-follow-redirects")

    results = []
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            encoding="utf-8",
            errors="replace",
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append(_parse(obj))
            except json.JSONDecodeError:
                pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return results


def run_httpx_stream(targets, timeout=10, threads=50):
    """
    Generator — يبث النتائج واحدة واحدة.
    """
    binary = _get_httpx_path()
    if not binary:
        yield {"type": "error", "message": "httpx not found — place httpx.exe in project directory"}
        return

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                     delete=False, encoding="utf-8") as f:
        f.write("\n".join(targets))
        tmp_path = f.name

    cmd = [
        binary,
        "-l", tmp_path,
        "-json",
        "-silent",
        "-threads", str(threads),
        "-timeout", str(timeout),
        "-title",
        "-status-code",
        "-tech-detect",
        "-web-server",
        "-ip",
        "-cdn",
        "-response-time",
        "-follow-redirects",
        "-no-color",
    ]

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
                result = _parse(obj)
                result["type"] = "result"
                count += 1
                yield result
            except json.JSONDecodeError:
                pass
        proc.wait(timeout=10)
    except Exception as e:
        yield {"type": "error", "message": str(e)}
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    yield {"type": "done", "total": count}


def _parse(obj):
    """تحويل httpx JSON output لـ dict نظيف"""
    # Status code color
    sc = obj.get("status-code", 0)
    if 200 <= sc < 300:
        sc_color = "green"
    elif 300 <= sc < 400:
        sc_color = "yellow"
    elif sc >= 400:
        sc_color = "red"
    else:
        sc_color = "blue"

    return {
        "url":           obj.get("url", ""),
        "input":         obj.get("input", ""),
        "status_code":   sc,
        "sc_color":      sc_color,
        "title":         obj.get("title", ""),
        "webserver":     obj.get("webserver", ""),
        "tech":          obj.get("tech", []),
        "ip":            obj.get("host", "") or obj.get("a", [""])[0] if obj.get("a") else "",
        "cdn":           obj.get("cdn-name", "") or ("Yes" if obj.get("cdn") else ""),
        "response_time": obj.get("response-time", ""),
        "content_length": obj.get("content-length", ""),
        "lines":         obj.get("lines", ""),
        "words":         obj.get("words", ""),
        "failed":        obj.get("failed", False),
    }
