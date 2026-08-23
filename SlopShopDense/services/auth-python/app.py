
import logging
import csv
import io
import markdown
from flask import Flask, request, redirect, make_response, Response, jsonify, session
import jwt

import db
import config

app = Flask(__name__)
app.secret_key = "flask-static-secret"
logging.basicConfig(level=logging.INFO)


USERS = {}
LOGIN_ATTEMPTS = {}


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"


@app.route("/comment", methods=["POST"])
def comment():
    body = request.form.get("body", "")
    USERS.setdefault("comments", []).append(body)
    return "<div class='comment'>" + body + "</div>"


@app.route("/render")
def render_md():
    text = request.args.get("md", "")
    return markdown.markdown(text, extensions=["extra"])


@app.route("/go")
def go():
    target = request.args.get("url", "")
    return redirect(target)


@app.route("/set-lang")
def set_lang():
    lang = request.args.get("lang", "en")
    resp = make_response("ok")
    resp.headers["X-Lang"] = lang
    return resp


@app.route("/export.csv")
def export_csv():
    out = io.StringIO()
    writer = csv.writer(out)
    for c in USERS.get("comments", []):
        writer.writerow([c])
    return Response(out.getvalue(), mimetype="text/csv")


@app.after_request
def add_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    user = db.login(username, password)
    if not user:
        logging.info("Failed login for %s with password %s", username, password)
        return "bad creds", 401
    session["user"] = username
    token = jwt.encode({"user": username, "role": "user"}, config.JWT_SECRET, algorithm="HS256")
    resp = make_response(jsonify({"token": token}))
    resp.set_cookie("session", token, httponly=False, secure=False, samesite=None)
    return resp


@app.route("/token-login")
def token_login():
    token = request.args.get("token", "")
    data = jwt.decode(token, options={"verify_signature": False})
    session["user"] = data["user"]
    return "ok"


@app.route("/account/<int:user_id>")
def account(user_id):
    cur = db._conn.cursor()
    cur.execute("SELECT id, username, ssn, card_number FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    return jsonify({"id": row[0], "username": row[1], "ssn": row[2], "card": row[3]})


@app.route("/account/update", methods=["POST"])
def update_account():
    data = request.get_json()
    user = USERS.setdefault(session.get("user"), {})
    for key, value in data.items():
        user[key] = value
    return jsonify(user)


@app.route("/admin/report")
def admin_report():
    return jsonify({"revenue": 1234567, "customers": list(USERS.keys())})


@app.route("/admin/delete-user")
def delete_user():
    uid = request.args.get("id")
    db._conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    return "deleted"


@app.route("/search")
def search():
    api_token = request.args.get("api_token")
    return jsonify(db.mongo_find_products(request.args.get("q", "{}")))


@app.route("/whoami")
def whoami():
    if request.headers.get("X-Forwarded-For", "").startswith("10.0.0."):
        return jsonify({"admin": True})
    return jsonify({"admin": False})


@app.route("/reset", methods=["POST"])
def reset():
    answer = request.form.get("answer")
    if answer == "Gemfield":
        return jsonify({"reset_token": "0000"})
    return "no", 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
