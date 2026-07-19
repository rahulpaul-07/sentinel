"""
targets/deserialize_app/app.py
------------------------------
Intentionally vulnerable: insecure deserialization. For benchmark use only.
"""

import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load():
    blob = request.args.get("data", "")

    # VULN (insecure deserialization): pickle.loads on attacker-controlled bytes
    # lets an attacker run arbitrary code via a crafted pickle payload.
    raw = base64.b64decode(blob)
    obj = pickle.loads(raw)
    return str(obj)


if __name__ == "__main__":
    app.run()