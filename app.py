import base64
import hashlib
import hmac
import struct
import time

from flask import Flask, render_template_string, request

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------
TOTP_SECRET = "KNUDAODQIRTTI32XKBAXAWRUMNZFG2TK"  # Base32 Secret Key
TOTP_PERIOD = 300                                 # Zeitfenster in Sekunden (5 Min)
TOTP_DIGITS = 6                                   # Stellen des Codes
TOTP_DIGEST = hashlib.sha1                        # Hash-Algorithmus
VALID_WINDOW = 1                                  # +/- Fenster gegen Zeitversatz
SECRET_STRING = "007-offsite{h4ckedTOTP}"         # Anzeige bei Erfolg

app = Flask(__name__)


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) mit reiner Standardbibliothek
# ---------------------------------------------------------------------------
def _totp_at(counter, secret=TOTP_SECRET, digits=TOTP_DIGITS, digest=TOTP_DIGEST):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    msg = struct.pack(">Q", counter)
    hs = hmac.new(key, msg, digest).digest()
    offset = hs[-1] & 0x0F
    code = struct.unpack(">I", hs[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp(token, period=TOTP_PERIOD, valid_window=VALID_WINDOW):
    """Serverseitige Validierung. Prueft aktuelles Fenster +/- valid_window."""
    token = (token or "").strip()
    if not token.isdigit():
        return False
    counter = int(time.time()) // period
    for drift in range(-valid_window, valid_window + 1):
        # zeitkonstanter Vergleich gegen Timing-Angriffe
        if hmac.compare_digest(token, _totp_at(counter + drift)):
            return True
    return False


# ---------------------------------------------------------------------------
# Web-Oberflaeche
# ---------------------------------------------------------------------------
PAGE = """<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TOTP Login</title>
  <style>
    body { font-family: system-ui, sans-serif; background:#111; color:#eee;
           display:flex; min-height:100vh; align-items:center; justify-content:center; margin:0; }
    .card { background:#1c1c1c; padding:2.5rem; border-radius:12px; width:min(90vw,360px);
            box-shadow:0 8px 30px rgba(0,0,0,.5); }
    h1 { font-size:1.3rem; margin:0 0 1.2rem; }
    input { width:100%; padding:.7rem; font-size:1.2rem; letter-spacing:.2em; text-align:center;
            border:1px solid #333; border-radius:8px; background:#111; color:#fff; box-sizing:border-box; }
    button { margin-top:1rem; width:100%; padding:.7rem; font-size:1rem; border:0; border-radius:8px;
             background:#00a86b; color:#fff; cursor:pointer; }
    button:hover { background:#00c07d; }
    .msg { margin-top:1rem; padding:.7rem; border-radius:8px; text-align:center; }
    .ok { background:#053; color:#8f8; font-family:monospace; font-size:1.1rem; }
    .err { background:#511; color:#f99; }
  </style>
</head>
<body>
  <form class="card" method="post" autocomplete="off">
    <h1>TOTP-Token eingeben</h1>
    <input name="token" inputmode="numeric" pattern="[0-9]*" placeholder="000000"
           maxlength="8" autofocus>
    <button type="submit">Pruefen</button>
    {% if result == "ok" %}
      <div class="msg ok">{{ secret }}</div>
    {% elif result == "err" %}
      <div class="msg err">Ungueltiger Token.</div>
    {% endif %}
  </form>
</body>
</html>"""


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        result = "ok" if verify_totp(request.form.get("token")) else "err"
    return render_template_string(PAGE, result=result, secret=SECRET_STRING)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
