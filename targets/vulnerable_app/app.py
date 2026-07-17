"""
targets/vulnerable_app/app.py
-----------------------------
An INTENTIONALLY VULNERABLE demo web app — Sentinel's first test subject.
Do NOT deploy this. Each 'VULN' comment marks a real, classic bug that Sentinel
should eventually discover on its own. These comments are our "ground truth."
"""

import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)

# VULN 1 (hardcoded secret): secrets should load from the environment, never be
# written directly in source code that gets committed to git.
SECRET_KEY = "super-secret-admin-password-123"


@app.route("/user")
def get_user():
    # 'username' comes straight from the URL, so it is attacker-controlled input.
    # In security terms this is a "source" of untrusted data.
    username = request.args.get("username", "")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULN 2 (SQL injection): the username is glued directly into the SQL text.
    # An attacker sending  username=' OR '1'='1  could dump every row. The
    # database call is the dangerous "sink" where the untrusted data lands.
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)

    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")

    # VULN 3 (command injection): user input is passed straight to the shell.
    # An attacker sending  host=8.8.8.8; rm -rf /  could run any command.
    os.system("ping -c 1 " + host)

    return "pinged " + host


if __name__ == "__main__":
    app.run(debug=True)