"""
targets/safe_app/app.py
-----------------------
A SECURE reference app with NO known vulnerabilities. Used to measure Sentinel's
false-positive rate: a good tool should find nothing to confirm here.
"""

import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Secret loaded from the environment, not hardcoded.
SECRET_KEY = os.environ.get("APP_SECRET_KEY", "")


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Parameterized query -> no SQL injection.
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # Argument list, no shell -> no command injection.
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    app.run()