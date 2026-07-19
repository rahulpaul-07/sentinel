"""
targets/traversal_app/app.py
----------------------------
Intentionally vulnerable: path traversal. For benchmark use only.
"""

import os

from flask import Flask, request

app = Flask(__name__)

BASE_DIR = "/var/www/files"


@app.route("/download")
def download():
    filename = request.args.get("file", "")

    # VULN (path traversal): 'filename' is joined without checking for '..', so
    # an attacker can request  ?file=../../etc/passwd  to read any file on disk.
    path = os.path.join(BASE_DIR, filename)
    with open(path) as handle:
        return handle.read()


if __name__ == "__main__":
    app.run()