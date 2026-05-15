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

    # تتبع الـ targets التي استجابت
    seen_inputs = set()
    count = 0
    alive = 0
    httpx_failed = 0

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
                # سجّل الـ input لمعرفة من لم يستجب
                inp = obj.get("input", "").strip().lower().lstrip("http://").lstrip("https://").rstrip("/")
                if inp:
                    seen_inputs.add(inp)
                if result.get("failed"):
                    httpx_failed += 1
                else:
                    alive += 1
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

    # الدومينات التي لم يُخرج httpx أي نتيجة لها (DNS fail / no port open)
    dead_count = 0
    for t in targets:
        t_clean = t.strip().lower().lstrip("http://").lstrip("https://").rstrip("/")
        if t_clean and t_clean not in seen_inputs:
            dead_count += 1
            yield {
                "type":        "result",
                "input":       t.strip(),
                "url":         t.strip(),
                "status_code": 0,
                "sc_color":    "red",
                "title":       "",
                "webserver":   "",
                "tech":        [],
                "ip":          "",
                "cdn":         "",
                "response_time": "",
                "content_length": 0,
                "lines": 0,
                "words": 0,
                "failed":      True,
                "dead":        True,   # لم يستجب إطلاقاً
            }

    total_failed = httpx_failed + dead_count
    yield {
        "type":   "done",
        "total":  len(targets),
        "alive":  alive,
        "failed": total_failed,
        "dead":   dead_count,
    }


def _parse(obj):
    """تحويل httpx JSON output لـ dict نظيف"""
    # Status code — handle both dash and underscore variants across httpx versions
    sc = (obj.get("status-code")
          or obj.get("status_code")
          or obj.get("StatusCode")
          or 0)
    try:
        sc = int(sc)
    except (TypeError, ValueError):
        sc = 0

    if 200 <= sc < 300:
        sc_color = "green"
    elif 300 <= sc < 400:
        sc_color = "yellow"
    elif sc >= 400:
        sc_color = "red"
    else:
        sc_color = "blue"

    # IP — handle both old and new field names
    ip_val = (obj.get("host")
              or obj.get("ip")
              or (obj.get("a") or [""])[0])

    # CDN
    cdn_val = (obj.get("cdn-name")
               or obj.get("cdn_name")
               or ("✓" if obj.get("cdn") else ""))

    # Tech — can be list or dict in different versions
    tech_raw = obj.get("tech") or obj.get("technologies") or []
    if isinstance(tech_raw, dict):
        tech_raw = list(tech_raw.keys())

    return {
        "url":            obj.get("url", ""),
        "input":          obj.get("input", ""),
        "status_code":    sc,
        "sc_color":       sc_color,
        "title":          obj.get("title", ""),
        "webserver":      obj.get("webserver", "") or obj.get("web-server", ""),
        "tech":           tech_raw,
        "ip":             ip_val,
        "cdn":            cdn_val,
        "response_time":  obj.get("response-time", "") or obj.get("response_time", ""),
        "content_length": obj.get("content-length", 0),
        "lines":          obj.get("lines", 0),
        "words":          obj.get("words", 0),
        "failed":         obj.get("failed", False),
    }
