#!/usr/bin/env python3
"""
jsvulnscan - "Güncel Olmayan JavaScript Kütüphanelerinin Kullanılması" bulgusu
için tespit + doğrulama aracı.

Yöntem:
  1. Hedef sayfa(lar) taranır; <script src>, inline script ve (tarayıcı modunda)
     çalışma anında yüklenen tüm JS dosyaları toplanır.
  2. Her dosya Retire.js imza veritabanı ile analiz edilir
     (SHA1 hash, dosya içeriği banner/regex, dosya adı, URI).
  3. --browser ile sayfa headless Chromium'da (CDP, Node.js gerekmez) açılır ve sürüm canlı JS
     nesnesinden okunur (ör. jQuery.fn.jquery) -> kesin doğrulama.
  4. Bulunan sürüm, npm registry'deki son sürümle ve bilinen CVE aralıklarıyla
     karşılaştırılır.

Doğrulama seviyeleri:
  KESIN  : Sürüm çalışma anında (runtime) okundu, dosya hash'i bilinen sürümle
           birebir eşleşti veya sürüm dosyanın İÇERİĞİNDEN (banner) okundu.
  OLASI  : Sürüm yalnızca URL/dosya adından çıkarıldı (içerikle teyit edilemedi).
"""

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import html
import json
import os
import re
import shutil
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] 'requests' gerekli: sudo apt install python3-requests")

VERSION = "1.0.0"
REPO_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"
CACHE_DIR = os.path.expanduser("~/.cache/jsvulnscan")
REPO_CACHE = os.path.join(CACHE_DIR, "jsrepository-v4.json")
VERSION_RE = r"[0-9][0-9.a-z_\-]+"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
MAX_JS_SIZE = 15 * 1024 * 1024

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "": 0}
METHOD_RANK = {"runtime": 5, "hash": 4, "filecontent": 3, "filename": 2, "uri": 1}
METHOD_TR = {
    "runtime": "Çalışma anı (canlı JS nesnesi)",
    "hash": "SHA1 hash eşleşmesi",
    "filecontent": "Dosya içeriği (banner/kod)",
    "filename": "Dosya adı",
    "uri": "URL yolu",
}

C = {"r": "\033[91m", "y": "\033[93m", "g": "\033[92m", "b": "\033[94m", "c": "\033[96m",
     "m": "\033[95m", "B": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}


def log(msg, color=""):
    print(f"{C.get(color, '')}{msg}{C['x']}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Sürüm karşılaştırma (Retire.js ile aynı mantık)
# --------------------------------------------------------------------------- #
def _cmp_part(p):
    if p is None or p == "":
        return 0
    return int(p) if p.isdigit() else p


def version_cmp(a, b):
    pa, pb = re.split(r"[.\-]", a), re.split(r"[.\-]", b)
    for i in range(max(len(pa), len(pb))):
        x = _cmp_part(pa[i] if i < len(pa) else None)
        y = _cmp_part(pb[i] if i < len(pb) else None)
        if type(x) is not type(y):
            # sayı > metin  (1.0.0 > 1.0.0-beta)
            return 1 if isinstance(x, int) else -1
        if x > y:
            return 1
        if x < y:
            return -1
    return 0


def _rx(pattern):
    """JS regex -> Python. re derleyemezse (ör. değişken uzunluklu lookbehind)
    'regex' modülü, o da yoksa lookbehind'ı çıkarılmış hali denenir."""
    try:
        return re.compile(pattern)
    except re.error:
        pass
    try:
        import regex
        return regex.compile(pattern)
    except Exception:
        pass
    try:
        return re.compile(re.sub(r"\(\?<[=!][^()]*\)", "", pattern))
    except re.error:
        return None


# Retire.js'te runtime (func) imzası olmayan kütüphaneler için ek çalışma anı sorguları
EXTRA_FUNCS = {
    "lodash": ["(window._ && window._.flatMapDeep && window._.VERSION)"],
    "underscore.js": ["(window._ && !window._.flatMapDeep && window._.VERSION)"],
}


# Retire.js'in yalnızca AST ile yakaladığı minify edilmiş build'ler için ek içerik imzaları
EXTRA_CONTENT = {
    "lodash": [r'\.VERSION="(§§version§§)",[\w$]+\("bind bindKey curry curryRight partial partialRight"'],
}


# --------------------------------------------------------------------------- #
# Retire.js veritabanı
# --------------------------------------------------------------------------- #
class SignatureDB:
    def __init__(self, path=None, update=False, session=None):
        data = self._load(path, update, session)
        self.libs = {}
        for name, comp in data.items():
            if not isinstance(comp, dict):
                continue
            ex = comp.get("extractors", {})
            entry = {
                "npm": comp.get("npmname") or name,
                "vulns": comp.get("vulnerabilities", []),
                "func": ex.get("func", []) + EXTRA_FUNCS.get(name, []),
                "hashes": ex.get("hashes", {}),
                "uri": self._compile(ex.get("uri", [])),
                "filename": self._compile(ex.get("filename", [])),
                "filecontent": self._compile(ex.get("filecontent", []) + EXTRA_CONTENT.get(name, [])),
                "replace": self._compile_replace(ex.get("filecontentreplace", [])),
            }
            self.libs[name] = entry

    @staticmethod
    def _load(path, update, session):
        if path:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        os.makedirs(CACHE_DIR, exist_ok=True)
        fresh = os.path.exists(REPO_CACHE) and time.time() - os.path.getmtime(REPO_CACHE) < 86400
        if update or not fresh:
            try:
                log("[*] Retire.js imza veritabanı indiriliyor...", "b")
                r = (session or requests).get(REPO_URL, timeout=30)
                r.raise_for_status()
                data = r.json()
                with open(REPO_CACHE, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                return data
            except Exception as e:
                if not os.path.exists(REPO_CACHE):
                    sys.exit(f"[!] İmza veritabanı indirilemedi: {e}  (offline için --db <dosya>)")
                log(f"[!] Güncelleme başarısız ({e}), önbellek kullanılıyor.", "y")
        with open(REPO_CACHE, encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _compile(patterns):
        return [rx for rx in (_rx(p.replace("§§version§§", VERSION_RE)) for p in patterns) if rx]

    @staticmethod
    def _compile_replace(patterns):
        out = []
        for p in patterns:
            m = re.match(r"^/(.*[^\\])/([^/]+)/$", p)
            if not m:
                continue
            rx = _rx(m.group(1).replace("§§version§§", VERSION_RE))
            if rx:
                out.append((rx, re.sub(r"\$(\d)", r"\\\1", m.group(2))))
        return out

    def vulns_for(self, lib, version):
        res = []
        for v in self.libs[lib]["vulns"]:
            below, above = v.get("below"), v.get("atOrAbove")
            if below and version_cmp(version, below) >= 0:
                continue
            if above and version_cmp(version, above) < 0:
                continue
            res.append(v)
        return res


# --------------------------------------------------------------------------- #
# Tespit
# --------------------------------------------------------------------------- #
def _clean_ver(v):
    v = v.strip().rstrip(".-_")
    return v if re.match(r"^\d", v) else None


def _snippet(text, m, width=60):
    s, e = max(0, m.start() - width // 3), min(len(text), m.end() + width // 3)
    return text[s:e].replace("\n", " ").replace("\r", " ")


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def detect_in_url(db, url):
    hits = []
    path = urlparse(url).path
    fname = path.rsplit("/", 1)[-1]
    for lib, e in db.libs.items():
        for rx in e["uri"]:
            m = rx.search(url)
            if m and m.groups() and _clean_ver(m.group(1)):
                hits.append((lib, _clean_ver(m.group(1)), "uri", url, None, m.group(0)))
                break
        for rx in e["filename"]:
            m = rx.search(fname)
            if m and m.groups() and _clean_ver(m.group(1)):
                hits.append((lib, _clean_ver(m.group(1)), "filename", url, None, m.group(0)))
                break
    return hits


def detect_in_content(db, url, content):
    hits = []
    sha1 = hashlib.sha1(content.encode("utf-8", "surrogateescape")).hexdigest()
    for lib, e in db.libs.items():
        if sha1 in e["hashes"]:
            hits.append((lib, e["hashes"][sha1], "hash", url, None, f"sha1={sha1}"))
        for rx in e["filecontent"]:
            m = rx.search(content)
            if m and m.groups():
                ver = _clean_ver(m.group(1))
                if ver:
                    hits.append((lib, ver, "filecontent", url, _line_of(content, m.start()), _snippet(content, m)))
                    break
        for rx, repl in e["replace"]:
            m = rx.search(content)
            if m:
                try:
                    ver = _clean_ver(m.expand(repl))
                except Exception:
                    ver = None
                if ver:
                    hits.append((lib, ver, "filecontent", url, _line_of(content, m.start()), _snippet(content, m)))
                    break
    return hits


# --------------------------------------------------------------------------- #
# HTTP / tarama
# --------------------------------------------------------------------------- #
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts, self.inline, self.links = [], [], []
        self._in_script = False
        self._buf = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script, self._buf = True, []
        elif tag == "link" and a.get("href"):
            rel = (a.get("rel") or "").lower()
            if a.get("as") == "script" or "modulepreload" in rel:
                self.scripts.append(a["href"])
        elif tag in ("a", "iframe", "frame") and (a.get("href") or a.get("src")):
            self.links.append(a.get("href") or a.get("src"))

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            code = "".join(self._buf).strip()
            if code:
                self.inline.append(code)


# Hedefler arasında paylaşılan JS analiz önbelleği (aynı CDN dosyası tekrar indirilmez)
_JS_CACHE = {}   # url -> (info, hits)


class Scanner:
    def __init__(self, args, db):
        self.args, self.db = args, db
        self.s = requests.Session()
        self.s.verify = not args.insecure
        self.s.headers["User-Agent"] = args.user_agent
        for h in args.header or []:
            k, _, v = h.partition(":")
            self.s.headers[k.strip()] = v.strip()
        if args.cookie:
            self.s.headers["Cookie"] = args.cookie
        if args.proxy:
            self.s.proxies = {"http": args.proxy, "https": args.proxy}
        self.hits = []          # (lib, ver, method, source, line, evidence)
        self.js_seen = {}       # url -> {"sha1", "size", "status", "page"}
        self.pages = []
        self.errors = []

    def get(self, url):
        return self.s.get(url, timeout=self.args.timeout, allow_redirects=True, stream=True)

    def read_body(self, r):
        chunks, size = [], 0
        for c in r.iter_content(65536):
            chunks.append(c)
            size += len(c)
            if size > MAX_JS_SIZE:
                break
        raw = b"".join(chunks)
        enc = r.encoding or "utf-8"
        try:
            return raw.decode(enc, errors="surrogateescape") if enc.lower() in ("utf-8", "utf8") \
                else raw.decode(enc, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="surrogateescape")

    def in_scope(self, url, root):
        return urlparse(url).netloc == urlparse(root).netloc

    def crawl(self, start):
        queue, visited = [(start, 0)], set()
        while queue and len(visited) < self.args.max_pages:
            url, depth = queue.pop(0)
            url = urldefrag(url)[0]
            if url in visited:
                continue
            visited.add(url)
            try:
                r = self.get(url)
                body = self.read_body(r)
            except Exception as e:
                self.errors.append(f"{url}: {e}")
                log(f"[!] {url}: {e}", "r")
                continue
            ctype = r.headers.get("Content-Type", "")
            log(f"[+] Sayfa [{r.status_code}] {url}", "c")
            self.pages.append({"url": url, "status": r.status_code})
            if "html" not in ctype and "<script" not in body[:5000].lower():
                continue
            p = PageParser()
            try:
                p.feed(body)
            except Exception:
                pass
            for i, code in enumerate(p.inline):
                src = f"{r.url} (inline script #{i + 1})"
                self.hits += detect_in_content(self.db, src, code)
            for s in p.scripts:
                js = urldefrag(urljoin(r.url, s.strip()))[0]
                if js.startswith(("http://", "https://")):
                    self.js_seen.setdefault(js, {"page": r.url})
            if depth < self.args.depth:
                for l in p.links:
                    nxt = urldefrag(urljoin(r.url, l.strip()))[0]
                    if nxt.startswith(("http://", "https://")) and self.in_scope(nxt, start) \
                            and not re.search(r"\.(png|jpe?g|gif|svg|css|pdf|zip|ico|woff2?|ttf|mp4|js)(\?|$)", nxt, re.I) \
                            and not re.search(r"logout|signout|cikis|delete|remove", nxt, re.I):
                        queue.append((nxt, depth + 1))

    def fetch_js(self, url):
        try:
            r = self.get(url)
            body = self.read_body(r)
            info = {"status": r.status_code, "size": len(body),
                    "sha1": hashlib.sha1(body.encode("utf-8", "surrogateescape")).hexdigest()}
            hits = detect_in_url(self.db, url)
            if r.status_code == 200:
                hits += detect_in_content(self.db, url, body)
            return url, info, hits
        except Exception as e:
            return url, {"status": "ERR", "error": str(e)}, detect_in_url(self.db, url)

    def scan_js(self):
        todo = [u for u, i in self.js_seen.items() if "sha1" not in i and "status" not in i]
        log(f"[*] {len(todo)} JS dosyası analiz ediliyor...", "b")
        for url in [u for u in todo if u in _JS_CACHE]:
            info, hits = _JS_CACHE[url]
            self.js_seen[url].update(info)
            self.hits += hits
            log(f"    [önbellek] {url}" + (f"  -> {len(hits)} eşleşme" if hits else ""), "g" if hits else "")
        todo = [u for u in todo if u not in _JS_CACHE]
        with cf.ThreadPoolExecutor(self.args.threads) as ex:
            for url, info, hits in ex.map(self.fetch_js, todo):
                _JS_CACHE[url] = (info, hits)
                self.js_seen[url].update(info)
                self.hits += hits
                st = info.get("status")
                log(f"    [{st}] {url}" + (f"  -> {len(hits)} eşleşme" if hits else ""),
                    "g" if hits else "")

    # ---- Headless tarayıcı ile çalışma anı doğrulaması --------------------- #
    def browser_verify(self, urls):
        exe = self.args.chromium or shutil.which("chromium") or shutil.which("chromium-browser") \
            or shutil.which("google-chrome")
        if not exe:
            log("[!] Chromium bulunamadı: sudo apt install chromium", "r")
            return
        funcs = {lib: [f for f in e["func"] if not f.startswith("require(")]
                 for lib, e in self.db.libs.items() if e["func"]}
        probe = """(() => { const funcs = %s; const out = {};
            for (const [lib, list] of Object.entries(funcs)) {
                for (const f of list) {
                    try { const v = (0, eval)(f);
                          if (typeof v === 'string' && /^[0-9]/.test(v)) { out[lib] = [v, f]; break; } }
                    catch (e) {}
                }
            }
            return out; })()""" % json.dumps(funcs)
        extra = {k: v for k, v in self.s.headers.items()
                 if k.lower() not in ("user-agent", "accept-encoding", "connection", "accept")}
        try:
            cdp = CDPBrowser(exe, self.args)
        except Exception as e:
            log(f"[!] Chromium başlatılamadı: {e}", "r")
            return
        try:
            for url in urls:
                try:
                    found, loaded, final = cdp.inspect(url, probe, extra, self.args.timeout * 2)
                except Exception as e:
                    log(f"[!] Tarayıcı: {url}: {e}", "y")
                    continue
                for lib, (ver, expr) in found.items():
                    v = _clean_ver(ver)
                    if v:
                        log(f"    [runtime] {lib} {v}  ({expr})", "g")
                        self.hits.append((lib, v, "runtime", final, None, f"{expr}  =>  \"{ver}\""))
                new = [u for u in loaded if u.startswith("http") and urldefrag(u)[0] not in self.js_seen]
                for u in new:
                    self.js_seen[urldefrag(u)[0]] = {"page": url, "via": "browser"}
                if new:
                    log(f"[*] Tarayıcı {len(new)} ek (dinamik) JS dosyası buldu.", "b")
        finally:
            cdp.close()


class CDPBrowser:
    """Node.js/Playwright gerektirmeyen minimal Chrome DevTools Protocol istemcisi."""

    def __init__(self, exe, args):
        import subprocess
        import tempfile
        try:
            import websocket  # python3-websocket
        except ImportError:
            raise RuntimeError("python3-websocket gerekli: sudo apt install python3-websocket")
        self._ws_mod = websocket
        self.tmp = tempfile.mkdtemp(prefix="jsvulnscan-")
        cmd = [exe, "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
               "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--mute-audio",
               "--remote-debugging-port=0", "--remote-allow-origins=*", f"--user-data-dir={self.tmp}",
               f"--user-agent={args.user_agent}"]
        if args.insecure:
            cmd.append("--ignore-certificate-errors")
        if args.proxy:
            cmd += [f"--proxy-server={args.proxy}", "--proxy-bypass-list=<-loopback>"]
        cmd.append("about:blank")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        port_file = os.path.join(self.tmp, "DevToolsActivePort")
        for _ in range(150):
            if os.path.exists(port_file) and os.path.getsize(port_file) > 0:
                break
            if self.proc.poll() is not None:
                raise RuntimeError("Chromium beklenmedik şekilde kapandı")
            time.sleep(0.1)
        else:
            raise RuntimeError("DevTools portu açılmadı")
        with open(port_file) as f:
            self.port = int(f.readline().strip())
        self.http = requests.Session()
        self.http.trust_env = False

    def _new_tab(self):
        r = self.http.put(f"http://127.0.0.1:{self.port}/json/new?about:blank", timeout=10)
        if r.status_code == 405:
            r = self.http.get(f"http://127.0.0.1:{self.port}/json/new?about:blank", timeout=10)
        return r.json()

    def inspect(self, url, probe, headers, timeout):
        tab = self._new_tab()
        ws = self._ws_mod.create_connection(tab["webSocketDebuggerUrl"], timeout=5, suppress_origin=True)
        msg_id = [0]
        events = []

        def send(method, params=None):
            msg_id[0] += 1
            mid = msg_id[0]
            ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
            end = time.time() + timeout
            while time.time() < end:
                try:
                    m = json.loads(ws.recv())
                except self._ws_mod.WebSocketTimeoutException:
                    continue
                if m.get("id") == mid:
                    return m.get("result", {})
                events.append(m)
            raise TimeoutError(method)

        def pump(seconds):
            end = time.time() + seconds
            while time.time() < end:
                ws.settimeout(max(0.1, min(0.5, end - time.time())))
                try:
                    events.append(json.loads(ws.recv()))
                except self._ws_mod.WebSocketTimeoutException:
                    pass
            ws.settimeout(5)

        try:
            send("Network.enable")
            send("Page.enable")
            if headers:
                send("Network.setExtraHTTPHeaders", {"headers": headers})
            send("Page.navigate", {"url": url})
            end, last_net = time.time() + timeout, time.time()
            loaded = False
            while time.time() < end:
                n = len(events)
                pump(0.5)
                if any(e.get("method", "").startswith("Network.") for e in events[n:]):
                    last_net = time.time()
                if any(e.get("method") == "Page.loadEventFired" for e in events[n:]):
                    loaded = True
                if loaded and time.time() - last_net > 2:   # ağ boşta
                    break
            res = send("Runtime.evaluate", {"expression": probe, "returnByValue": True})
            found = res.get("result", {}).get("value") or {}
            final = send("Runtime.evaluate", {"expression": "location.href", "returnByValue": True}) \
                .get("result", {}).get("value") or url
            scripts = [e["params"]["response"]["url"] for e in events
                       if e.get("method") == "Network.responseReceived"
                       and (e["params"].get("type") == "Script"
                            or "javascript" in e["params"]["response"].get("mimeType", ""))]
            return found, scripts, final
        finally:
            try:
                ws.close()
                self.http.get(f"http://127.0.0.1:{self.port}/json/close/{tab['id']}", timeout=5)
            except Exception:
                pass

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(5)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)

# --------------------------------------------------------------------------- #
# Sonuçların birleştirilmesi
# --------------------------------------------------------------------------- #
_latest_cache = {}


def npm_latest(session, pkg):
    if pkg in _latest_cache:
        return _latest_cache[pkg]
    val = None
    try:
        r = session.get(f"https://registry.npmjs.org/{pkg.replace('/', '%2F')}/latest", timeout=15,
                        proxies={}, verify=True)
        if r.ok:
            val = r.json().get("version")
    except Exception:
        pass
    _latest_cache[pkg] = val
    return val


def aggregate(scanner, db, check_latest):
    # Aynı npm paketine ait alt bileşenler (ör. jquery-ui-dialog) tek bulguda birleşir
    groups = {}
    for lib, ver, method, src, line, ev in scanner.hits:
        groups.setdefault(db.libs[lib]["npm"], []).append({
            "lib": lib, "version": ver, "method": method, "source": src, "line": line, "evidence": ev})
    findings = []
    latest_sess = requests.Session()
    latest_sess.headers["User-Agent"] = f"jsvulnscan/{VERSION}"
    for npm, evs in groups.items():
        # Aynı kütüphanenin farklı sürümleri ayrı bulgu olabilir; içerik-tabanlı
        # sürümler URL-tabanlı tahminlerin önüne geçer.
        by_ver = {}
        for e in evs:
            by_ver.setdefault(e["version"], []).append(e)
        strong_vers = {v for v, l in by_ver.items() if any(METHOD_RANK[x["method"]] >= 3 for x in l)}
        for ver, lst in by_ver.items():
            best = max(METHOD_RANK[x["method"]] for x in lst)
            sources = {x["source"] for x in lst}
            # Sadece URL tahmini olan ve aynı dosyada içerikten farklı sürüm okunan kaydı ele
            if best < 3:
                contradicted = [v for v in strong_vers if any(
                    x["source"] in sources for x in by_ver[v])]
                if contradicted:
                    continue
            libs = sorted({x["lib"] for x in lst}, key=len)
            lib = libs[0]
            vulns, vkeys = [], set()
            for l in libs:
                for v in db.vulns_for(l, ver):
                    k = (v.get("identifiers", {}).get("summary"), v.get("below"), v.get("atOrAbove"))
                    if k not in vkeys:
                        vkeys.add(k)
                        vulns.append(v)
            latest = npm_latest(latest_sess, npm) if check_latest else None
            outdated = bool(latest and version_cmp(ver, latest) < 0)
            max_sev = max((SEV_ORDER.get(v.get("severity", ""), 0) for v in vulns), default=0)
            uniq, seen = [], set()
            for x in sorted(lst, key=lambda x: -METHOD_RANK[x["method"]]):
                k = (x["method"], x["source"], x["lib"] if x["method"] == "runtime" else "")
                if k not in seen:
                    seen.add(k)
                    uniq.append(x)
            findings.append({
                "library": lib, "components": libs, "npm": npm, "version": ver, "latest": latest,
                "outdated": outdated or bool(vulns),
                "confidence": "KESIN" if best >= 3 else "OLASI",
                "best_method": max(lst, key=lambda x: METHOD_RANK[x["method"]])["method"],
                "max_severity": [k for k, n in SEV_ORDER.items() if n == max_sev][0] if vulns else "none",
                "vulnerabilities": [{
                    "severity": v.get("severity", ""),
                    "cve": v.get("identifiers", {}).get("CVE", []),
                    "ghsa": v.get("identifiers", {}).get("githubID"),
                    "summary": v.get("identifiers", {}).get("summary", ""),
                    "range": (f">= {v['atOrAbove']} " if v.get("atOrAbove") else "") + f"< {v.get('below', '?')}",
                    "info": v.get("info", []),
                } for v in sorted(vulns, key=lambda v: -SEV_ORDER.get(v.get("severity", ""), 0))],
                "evidence": uniq,
                "verify_cmds": verify_commands(lib, ver, uniq, db, scanner.args),
            })
    findings.sort(key=lambda f: (-SEV_ORDER.get(f["max_severity"], 0), f["confidence"] != "KESIN",
                                 -len(f["vulnerabilities"]), f["library"]))
    return findings


def verify_commands(lib, ver, evidence, db, args):
    cmds = []
    k = "-k " if args.insecure else ""
    px = f"-x {args.proxy} " if args.proxy else ""
    for e in evidence:
        src = e["source"]
        if e["method"] == "runtime":
            expr = e["evidence"].split("  =>")[0]
            cmds.append(f"# Tarayıcı DevTools Console ({src}):\n{expr}")
        elif e["method"] in ("filecontent", "hash") and " (inline script" not in src:
            if e["method"] == "hash":
                cmds.append(f"curl -s {k}{px}'{src}' | sha1sum    # beklenen: {e['evidence'].split('=')[1]}")
            else:
                cmds.append(f"curl -s {k}{px}'{src}' | grep -o -m1 -F '{ver}' && "
                            f"curl -s {k}{px}'{src}' | head -c 400")
        elif " (inline script" in src:
            page = src.split(" (inline")[0]
            cmds.append(f"curl -s {k}{px}'{page}' | grep -n -F '{ver}'")
    if not cmds:
        cmds.append(f"curl -s {k}{px}'{evidence[0]['source']}' | head -c 600   # içerikte sürümü kontrol edin")
    out, seen = [], set()
    for c in cmds:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out[:4]


# --------------------------------------------------------------------------- #
# Raporlama
# --------------------------------------------------------------------------- #
SEV_COL = {"critical": "m", "high": "r", "medium": "y", "low": "b", "none": "g"}


def _status(f):
    if f["vulnerabilities"]:
        return "ZAFİYETLİ", SEV_COL.get(f["max_severity"], "")
    return ("GÜNCEL DEĞİL", "y") if f["outdated"] else ("GÜNCEL", "g")


def print_findings(findings):
    for f in findings:
        tag, col = _status(f)
        conf_col = "g" if f["confidence"] == "KESIN" else "y"
        print(f"\n{C['B']}{C[col]}[{tag}]{C['x']} {C['B']}{f['library']} {f['version']}{C['x']}"
              f"   son sürüm: {f['latest'] or '?'}   doğrulama: {C[conf_col]}{f['confidence']}{C['x']}"
              f" ({METHOD_TR[f['best_method']]})")
        for v in f["vulnerabilities"]:
            ids = ", ".join(v["cve"]) or v["ghsa"] or "-"
            print(f"   {C[SEV_COL.get(v['severity'], '')]}{v['severity'].upper():8}{C['x']} {ids:32} "
                  f"{v['range']:20} {v['summary'][:70]}")
        print(f"   {C['c']}Kanıt:{C['x']}")
        for e in f["evidence"][:5]:
            loc = f":{e['line']}" if e["line"] else ""
            print(f"     - [{e['method']}] {e['source']}{loc}")
            print(f"       {C['b']}{e['evidence'][:160]}{C['x']}")
        print(f"   {C['c']}Doğrulama komutu:{C['x']}")
        for c in f["verify_cmds"][:2]:
            print("     " + c.replace("\n", "\n     "))


def print_console(results):
    for r in results:
        print(f"\n{C['B']}{C['m']}{'#' * 90}\n  HEDEF: {r['target']}\n{'#' * 90}{C['x']}")
        if not r["findings"]:
            msg = "Hedefe erişilemedi" if r["errors"] and not r["pages"] else \
                "Güncel olmayan bir JavaScript kütüphanesi tespit edilmedi"
            print(f"{C['g'] if r['pages'] else C['r']}[{'✓' if r['pages'] else '!'}] {msg}.{C['x']}")
            continue
        print_findings(r["findings"])
    # Genel özet tablosu
    print(f"\n{C['B']}{'=' * 90}\n  ÖZET (hedef bazında)\n{'=' * 90}{C['x']}")
    for r in results:
        fs = r["findings"]
        libs = ", ".join(f"{f['library']} {f['version']}" for f in fs) or "-"
        nv = sum(1 for f in fs if f["vulnerabilities"])
        if not r["pages"] and r["errors"]:
            print(f"{C['r']}{'ERİŞİLEMEDİ':<28}{C['x']}  {r['target']}")
            continue
        col = "r" if nv else ("y" if fs else "g")
        print(f"{C[col]}{nv:>2} zafiyetli / {len(fs):>2} güncel değil{C['x']}  {r['target']}")
        if fs:
            print(f"      {libs}")


def _lib_matrix(results):
    """Kütüphane+sürüm -> etkilenen hedefler."""
    m = {}
    for r in results:
        for f in r["findings"]:
            k = (f["library"], f["version"])
            ent = m.setdefault(k, {"f": f, "targets": []})
            if r["target"] not in ent["targets"]:
                ent["targets"].append(r["target"])
            if f["confidence"] == "KESIN":
                ent["f"] = f
    return sorted(m.values(), key=lambda x: (-SEV_ORDER.get(x["f"]["max_severity"], 0),
                                             -len(x["targets"]), x["f"]["library"]))


def _card(f, idx, tid):
    e = html.escape
    vrows = "".join(
        f"<tr><td><span class='sev {e(v['severity'])}'>{e(v['severity'].upper())}</span></td>"
        f"<td>{'<br>'.join(e(c) for c in v['cve']) or e(v['ghsa'] or '-')}</td>"
        f"<td><code>{e(v['range'])}</code></td><td>{e(v['summary'])}"
        f"{''.join(f'<br><a href={chr(34)}{e(u)}{chr(34)} target=_blank rel=noopener>{e(u[:90])}</a>' for u in v['info'][:3])}"
        f"</td></tr>" for v in f["vulnerabilities"])
    vtable = (f"<table class='inner'><tr><th>Önem</th><th>CVE / ID</th><th>Etkilenen</th>"
              f"<th>Açıklama</th></tr>{vrows}</table>") if vrows else "<p class='muted'>Bilinen CVE yok.</p>"
    ev = "".join(
        f"<li><b>{e(METHOD_TR[x['method']])}</b> — <code>{e(x['source'])}"
        f"{':' + str(x['line']) if x['line'] else ''}</code><pre>{e(x['evidence'][:400])}</pre></li>"
        for x in f["evidence"][:8])
    cmds = "".join(f"<pre class='cmd'>{e(c)}</pre>" for c in f["verify_cmds"])
    status = "Zafiyetli" if f["vulnerabilities"] else ("Güncel değil" if f["outdated"] else "Güncel")
    scls = f["max_severity"] if f["vulnerabilities"] else ("medium" if f["outdated"] else "none")
    return f"""
<section class="card" id="{tid}-f{idx}">
  <h3 class="ct">{tid[1:]}.{idx} {e(f['library'])} <span class="ver">{e(f['version'])}</span>
    <span class="sev {scls}">{status}</span>
    <span class="conf {f['confidence']}">{'KESİN' if f['confidence'] == 'KESIN' else 'OLASI'}</span></h3>
  <dl><dt>Etkilenen hedef</dt><dd><code>{e(f['target'])}</code></dd>
      <dt>Tespit edilen sürüm</dt><dd><code>{e(f['version'])}</code></dd>
      <dt>Güncel sürüm (npm)</dt><dd><code>{e(f['latest'] or 'bilinmiyor')}</code></dd>
      <dt>Doğrulama yöntemi</dt><dd>{e(METHOD_TR[f['best_method']])}</dd></dl>
  <h4>Bilinen zafiyetler</h4>{vtable}
  <h4>Kanıtlar</h4><ul class="ev">{ev}</ul>
  <h4>Manuel doğrulama</h4>{cmds}
</section>"""


def _badge(f):
    e = html.escape
    cls = f["max_severity"] if f["vulnerabilities"] else "medium"
    return f"<span class='lib {cls}'>{e(f['library'])} {e(f['version'])}</span>"


def write_html(path, results, meta):
    e = html.escape
    all_f = [f for r in results for f in r["findings"]]

    # 1) Hedef bazında özet
    trows = []
    for i, r in enumerate(results, 1):
        fs = r["findings"]
        nv = sum(1 for f in fs if f["vulnerabilities"])
        top = max((SEV_ORDER.get(f["max_severity"], 0) for f in fs), default=0)
        topn = [k for k, n in SEV_ORDER.items() if n == top][0] if nv else ""
        if not r["pages"] and r["errors"]:
            state = "<span class='muted'>Erişilemedi</span>"
        elif not fs:
            state = "<span class='sev none'>Temiz</span>"
        else:
            state = f"<span class='sev {topn or 'medium'}'>{e((topn or 'güncel değil').upper())}</span>"
        trows.append(f"<tr><td>{i}</td><td><a href='#t{i}'>{e(r['target'])}</a></td><td>{state}</td>"
                     f"<td>{nv} / {len(fs)}</td><td>{' '.join(_badge(f) for f in fs) or '-'}</td></tr>")

    # 2) Kütüphane bazında etkilenen hedefler
    tidx = {r["target"]: i for i, r in enumerate(results, 1)}
    mrows = []
    for ent in _lib_matrix(results):
        f = ent["f"]
        cves = sorted({c for v in f["vulnerabilities"] for c in v["cve"]})
        cv = ", ".join(cves[:6]) + (f" (+{len(cves) - 6})" if len(cves) > 6 else "")
        mrows.append(
            f"<tr><td>{_badge(f)}</td><td><code>{e(f['latest'] or '?')}</code></td>"
            f"<td>{e(cv) or '-'}</td><td>{'KESİN' if f['confidence'] == 'KESIN' else 'OLASI'}</td>"
            f"<td>{'<br>'.join(f'<a href={chr(39)}#t{tidx[t]}{chr(39)}>{e(t)}</a>' for t in ent['targets'])}</td></tr>")

    # 3) Hedef bazında detaylar
    sections = []
    for i, r in enumerate(results, 1):
        body = "".join(_card(f, j, f"t{i}") for j, f in enumerate(r["findings"], 1))
        if not body:
            body = ("<p class='muted'>Hedefe erişilemedi: " + e("; ".join(r["errors"][:2])) + "</p>"
                    if not r["pages"] and r["errors"] else
                    "<p class='muted'>Güncel olmayan bir JavaScript kütüphanesi tespit edilmedi.</p>")
        pages = "".join(f"<li><code>{e(u)}</code></li>" for u in r["page_urls"][:30])
        sections.append(f"""
<section class="target" id="t{i}">
  <h2>Hedef {i}: {e(r['target'])}</h2>
  <p class="muted">Host: {e(r['host'])} · Taranan sayfa: {r['pages']} · JS dosyası: {len(r['js_files'])}</p>
  {f'<details><summary>Taranan sayfalar</summary><ul>{pages}</ul></details>' if pages else ''}
  {body}
</section>""")

    out = [f for f in all_f if f["outdated"]]
    doc = f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Kütüphane Raporu</title><style>
:root{{--bg:#fff;--fg:#1d2330;--mut:#667;--card:#f6f7f9;--bd:#dde1e7;--code:#eef0f4}}
@media (prefers-color-scheme:dark){{:root{{--bg:#14161b;--fg:#e4e6eb;--mut:#99a;--card:#1d2027;--bd:#30343d;--code:#262a33}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif;margin:0 auto;max-width:1150px;padding:24px 16px}}
h1{{margin:0 0 4px}} .muted{{color:var(--mut)}} code,pre{{font-family:ui-monospace,monospace;background:var(--code);border-radius:4px}}
code{{padding:1px 4px;word-break:break-all}} pre{{padding:8px;white-space:pre-wrap;word-break:break-all;margin:4px 0}}
h2.sec{{margin:28px 0 8px;font-size:20px}}
.target{{margin:32px 0}} .target>h2{{font-size:19px;margin:0 0 4px;padding:8px 12px;border-left:5px solid #1e6fd9;background:var(--card);word-break:break-all}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:16px;margin:14px 0 14px 16px}}
.card .ct{{margin:0 0 8px;font-size:17px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}} .ver{{font-family:monospace}}
h4{{font-size:14px;margin:14px 0 6px}} dl{{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:0}} dt{{color:var(--mut)}} dd{{margin:0}}
table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid var(--bd);padding:6px;text-align:left;vertical-align:top}}
.sev,.conf,.lib{{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;color:#fff;display:inline-block;margin:1px 0;white-space:nowrap}}
.critical{{background:#8b1fa9}}.high{{background:#c62828}}.medium{{background:#e08600}}.low{{background:#1e6fd9}}.none{{background:#2e7d32}}
.KESIN{{background:#2e7d32}}.OLASI{{background:#7a7a7a}} .ev{{padding-left:18px}} .cmd{{border-left:3px solid #1e6fd9}}
.inner td:nth-child(2),.inner td:nth-child(3){{white-space:nowrap}} .summary td:first-child{{color:var(--mut);width:220px}}
a{{color:#3b82f6}} .scroll{{overflow-x:auto}} td a{{word-break:break-all}} .scroll td:last-child{{min-width:220px}}
</style></head><body>
<h1>Güncel Olmayan JavaScript Kütüphaneleri</h1>
<p class="muted">jsvulnscan {VERSION} · {e(meta['date'])}</p>
<table class="summary">
<tr><td>Hedef sayısı</td><td>{len(results)}</td></tr>
<tr><td>Taranan sayfa / JS dosyası</td><td>{meta['pages']} / {meta['js_files']}</td></tr>
<tr><td>Tarayıcı (runtime) doğrulaması</td><td>{'Evet' if meta['browser'] else 'Hayır'}</td></tr>
<tr><td>Etkilenen hedef</td><td>{sum(1 for r in results if r['findings'])} / {len(results)}</td></tr>
<tr><td>Güncel olmayan kütüphane bulgusu</td><td>{len(out)} (kesin: {sum(1 for f in out if f['confidence'] == 'KESIN')})</td></tr>
</table>
<p class="muted">KESİN: sürüm çalışma anında, SHA1 hash ile veya dosya içeriğinden okunmuştur.
OLASI: sürüm yalnızca URL/dosya adından çıkarılmıştır; içerikle teyit edilmelidir.</p>

<h2 class="sec">Hedef bazında özet</h2>
<div class="scroll"><table><tr><th>#</th><th>Hedef</th><th>En yüksek önem</th><th>Zafiyetli / güncel değil</th><th>Kütüphaneler</th></tr>
{''.join(trows)}</table></div>

<h2 class="sec">Kütüphane bazında etkilenen hedefler</h2>
{('<div class="scroll"><table><tr><th>Kütüphane</th><th>Güncel sürüm</th><th>CVE</th><th>Doğrulama</th><th>Etkilenen hedefler</th></tr>' + ''.join(mrows) + '</table></div>') if mrows else '<p>Bulgu yok.</p>'}

<h2 class="sec">Hedef bazında detaylar</h2>
{''.join(sections)}
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Güncel olmayan / zafiyetli JavaScript kütüphanesi tespit ve doğrulama aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Örnekler:
  %(prog)s -u https://hedef.com
  %(prog)s -u https://hedef.com --browser -o rapor
  %(prog)s -l hedefler.txt --depth 1 -c 'SESSION=abc' --proxy http://127.0.0.1:8080 -k
  %(prog)s -u https://hedef.com/app --browser --only-confirmed --json-out sonuc.json""")
    ap.add_argument("-u", "--url", action="append", default=[], help="Hedef URL (birden çok verilebilir)")
    ap.add_argument("-l", "--list", help="Satır başına bir URL içeren dosya")
    ap.add_argument("-j", "--js", action="append", default=[], help="Doğrudan analiz edilecek JS URL'i")
    ap.add_argument("-d", "--depth", type=int, default=0, help="Aynı host içinde link takip derinliği (vars: 0)")
    ap.add_argument("--max-pages", type=int, default=30, help="Hedef başına en fazla sayfa (vars: 30)")
    ap.add_argument("-b", "--browser", action="store_true",
                    help="Headless Chromium ile çalışma anı doğrulaması + dinamik JS toplama")
    ap.add_argument("--chromium", help="Chromium binary yolu (vars: otomatik)")
    ap.add_argument("-H", "--header", action="append", help="Ek header ('Ad: Değer')")
    ap.add_argument("-c", "--cookie", help="Cookie header değeri")
    ap.add_argument("-x", "--proxy", help="Proxy (ör. http://127.0.0.1:8080)")
    ap.add_argument("-k", "--insecure", action="store_true", help="TLS sertifika doğrulamasını kapat")
    ap.add_argument("-t", "--threads", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--user-agent", default=UA)
    ap.add_argument("--db", help="Yerel jsrepository JSON dosyası (offline)")
    ap.add_argument("--update-db", action="store_true", help="İmza veritabanını zorla güncelle")
    ap.add_argument("--no-latest", action="store_true", help="npm'den son sürüm sorgulama")
    ap.add_argument("--only-confirmed", action="store_true", help="Sadece KESİN doğrulanmış bulguları göster")
    ap.add_argument("--show-all", action="store_true", help="Güncel kütüphaneleri de listele")
    ap.add_argument("-o", "--output", help="Rapor dosya öneki (<önek>.html ve <önek>.json üretir)")
    ap.add_argument("--json-out", help="JSON çıktı dosyası")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()

    targets = list(args.url)
    if args.list:
        with open(args.list, encoding="utf-8") as f:
            targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    targets = [t if re.match(r"^https?://", t) else "https://" + t for t in targets]
    if not targets and not args.js:
        ap.error("En az bir -u, -l veya -j gerekli")

    sc_sess = requests.Session()
    if args.proxy:
        sc_sess.proxies = {"http": args.proxy, "https": args.proxy}
    db = SignatureDB(args.db, args.update_db, sc_sess)
    log(f"[*] {len(db.libs)} kütüphane imzası yüklendi.", "b")

    # Her hedef ayrı taranır; bulgular hedef bazında raporlanır
    jobs = [(t, []) for t in targets] + [(j, [j]) for j in args.js]
    results = []
    for i, (target, js) in enumerate(jobs, 1):
        log(f"\n[=] Hedef {i}/{len(jobs)}: {target}", "m")
        results.append(scan_target(args, db, target, js))

    print_console(results)

    meta = {"date": dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "targets": [r["target"] for r in results],
            "pages": sum(r["pages"] for r in results), "js_files": len({u for r in results for u in r["js_files"]}),
            "browser": args.browser}
    result = {"tool": f"jsvulnscan {VERSION}", **meta, "results": results}
    jpath = args.json_out or (args.output + ".json" if args.output else None)
    if jpath:
        with open(jpath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        log(f"[*] JSON: {jpath}", "b")
    if args.output:
        write_html(args.output + ".html", results, meta)
        log(f"[*] HTML rapor: {args.output}.html", "b")
    all_f = [f for r in results for f in r["findings"]]
    sys.exit(2 if any(f["vulnerabilities"] for f in all_f) else (1 if all_f else 0))


def scan_target(args, db, target, js):
    sc = Scanner(args, db)
    if not js:
        sc.crawl(target)
    for j in js:
        sc.js_seen.setdefault(j, {"page": "-"})
    sc.scan_js()

    if args.browser and not js:
        log("[*] Headless Chromium ile çalışma anı doğrulaması yapılıyor...", "b")
        sc.browser_verify([p["url"] for p in sc.pages if p["status"] == 200] or [target])
        sc.scan_js()   # tarayıcının yakaladığı dinamik JS'ler

    findings = aggregate(sc, db, not args.no_latest)
    if args.only_confirmed:
        findings = [f for f in findings if f["confidence"] == "KESIN"]
    if not args.show_all:
        findings = [f for f in findings if f["outdated"] or f["latest"] is None]
    for f in findings:
        f["target"] = target
    return {"target": target, "host": urlparse(target).netloc, "pages": len(sc.pages),
            "page_urls": [p["url"] for p in sc.pages], "js_files": sc.js_seen,
            "errors": sc.errors, "findings": findings}


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] İptal edildi")
