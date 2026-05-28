from datetime import datetime
from flask import Flask, request, Response, render_template, url_for
import requests
import urllib.parse
from sqlalchemy import func
from database import db, AttackLog
from waf import detect_attack
from logger import waf_logger
import os

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///attacks.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
with app.app_context():
    db.create_all()

TARGET = os.environ.get("JUICE_SHOP_TARGET", "http://127.0.0.1:3000")


@app.route("/dashboard")
def dashboard():
    attacks = AttackLog.query.order_by(AttackLog.id.desc()).limit(200).all()
    total_attacks = AttackLog.query.count()
    sql_count = AttackLog.query.filter(
        AttackLog.attack_type.ilike("%sql%") | AttackLog.attack_type.ilike("%injection%")
    ).count()
    xss_count = AttackLog.query.filter(
        AttackLog.attack_type.ilike("%xss%") | AttackLog.attack_type.ilike("%cross-site%")
    ).count()
    other_count = max(total_attacks - sql_count - xss_count, 0)
    last_attack = attacks[0] if attacks else None

    attack_type_stats = db.session.query(
        AttackLog.attack_type,
        func.count(AttackLog.id).label("count")
    ).group_by(AttackLog.attack_type).order_by(func.count(AttackLog.id).desc()).limit(5).all()
    top_attacks = [{"type": attack_type, "count": count} for attack_type, count in attack_type_stats]

    return render_template(
        "dashboard.html",
        attacks=attacks,
        total_attacks=total_attacks,
        sql_count=sql_count,
        xss_count=xss_count,
        other_count=other_count,
        last_attack=last_attack,
        top_attacks=top_attacks,
        target=TARGET,
    )


@app.route("/healthz")
def healthz():
    return Response("OK", status=200, mimetype="text/plain")


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
    raw_query = request.query_string.decode("utf-8", errors="replace")
    decoded_query = urllib.parse.unquote_plus(raw_query)
    payload = decoded_query + "\n" + request.get_data(as_text=True)
    attack_type = detect_attack(payload)
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

    if attack_type:
        waf_logger.warning("Blocked attack from %s type=%s path=%s", client_ip, attack_type, path)
        _store_attack(client_ip, attack_type, payload)
        return Response("Request blocked by WAF", status=403, mimetype="text/plain")

    upstream_url = f"{TARGET}/{path}" if path else TARGET
    try:
        upstream_headers = {
            key: value
            for key, value in request.headers
            if key.lower() not in {"host", "accept-encoding"}
        }
        upstream_headers["Accept-Encoding"] = "identity"

        response = requests.request(
            method=request.method,
            url=upstream_url,
            headers=upstream_headers,
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=15,
        )

        excluded_headers = {
            "content-encoding",
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "upgrade",
        }
        headers = [
            (name, value)
            for name, value in response.headers.items()
            if name.lower() not in excluded_headers
        ]

        return Response(response.content, response.status_code, headers)

    except requests.RequestException as exc:
        waf_logger.error("Upstream request failed: %s", exc)
        return Response(f"Upstream request failed: {exc}", status=502, mimetype="text/plain")
    except Exception as exc:
        waf_logger.exception("Unexpected error while proxying request")
        return Response(f"Internal server error: {exc}", status=500, mimetype="text/plain")


def _store_attack(ip: str, attack_type: str, payload: str) -> None:
    try:
        attack = AttackLog(
            ip=ip,
            attack_type=attack_type,
            payload=payload,
            timestamp=datetime.now(),
        )
        db.session.add(attack)
        db.session.commit()
    except Exception:
        db.session.rollback()
        waf_logger.exception("Failed to store attack log")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
