"""
core17.py — Web Fuzzer
يفحص URL مع wordlist ويكتشف:
  - Status Code
  - Content Length
  - Lines / Words
  - Redirect Location
  - Response Time

استخدام:
  - ضع FUZZ في أي مكان بالـ URL:  https://example.com/FUZZ
  - أو أعطه URL عادي:             https://example.com/  (يُلحق الكلمة تلقائياً)
"""

import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

HEADERS = {"User-Agent": USER_AGENTS[0], "Accept": "*/*"}


# ─── Single probe ─────────────────────────────────────────────────────────────

def _probe(url_template, word, timeout, session):
    """جرّب كلمة واحدة وأرجع dict النتيجة"""
    word = word.strip()
    if not word:
        return None

    target = url_template.replace("FUZZ", word)

    start = time.perf_counter()
    try:
        r = session.get(
            target,
            headers=HEADERS,
            timeout=timeout,
            verify=False,
            allow_redirects=False,   # نتحكم بالـ redirects يدوياً
        )
        elapsed = round((time.perf_counter() - start) * 1000)  # ms

        # تحديد لون الـ status
        sc = r.status_code
        if 200 <= sc < 300:
            sc_color = "green"
        elif 300 <= sc < 400:
            sc_color = "yellow"
        elif sc >= 400:
            sc_color = "red"
        else:
            sc_color = "blue"

        location = r.headers.get("Location", "")
        content  = r.text
        lines    = content.count("\n") + 1 if content else 0
        words    = len(content.split())  if content else 0
        cl       = len(r.content)

        return {
            "type":         "result",
            "word":         word,
            "url":          target,
            "status_code":  sc,
            "sc_color":     sc_color,
            "content_length": cl,
            "lines":        lines,
            "words":        words,
            "redirect":     location,
            "response_time": f"{elapsed}ms",
            "failed":       False,
        }

    except requests.exceptions.Timeout:
        return {
            "type":         "result",
            "word":         word,
            "url":          target,
            "status_code":  0,
            "sc_color":     "blue",
            "content_length": 0,
            "lines":        0,
            "words":        0,
            "redirect":     "",
            "response_time": "timeout",
            "failed":       True,
        }
    except Exception:
        return None   # تجاهل أخطاء الاتصال الكاملة


# ─── Stream generator ─────────────────────────────────────────────────────────

def run_fuzz_stream(url_template, words, threads=50, timeout=10,
                    match_codes=None, filter_codes=None):
    """
    Generator — يبث النتائج واحدة واحدة.

    url_template : مثل https://example.com/FUZZ
    words        : list of strings
    match_codes  : list of ints — إظهار هذه الكودات فقط (None = الكل)
    filter_codes : list of ints — إخفاء هذه الكودات (None = لا شيء)
    """
    if "FUZZ" not in url_template:
        # ألحق الكلمة في النهاية
        url_template = url_template.rstrip("/") + "/FUZZ"

    total   = len(words)
    found   = 0
    done    = 0

    session = requests.Session()
    session.max_redirects = 3

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_probe, url_template, w, timeout, session): w
            for w in words
        }
        for future in as_completed(futures):
            done += 1
            result = future.result()
            if result is None:
                continue

            sc = result["status_code"]

            # تطبيق الفلاتر
            if match_codes and sc not in match_codes:
                continue
            if filter_codes and sc in filter_codes:
                continue
            if result["failed"]:
                continue   # نتجاهل الـ timeout في العرض

            found += 1
            result["progress"] = round(done / total * 100)
            yield result

    yield {
        "type":  "done",
        "total": total,
        "found": found,
    }
