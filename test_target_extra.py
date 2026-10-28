"""
test_target_extra.py -- second test file (new detection categories).

    python scan.py test_target_extra.py

VULN_*   -> should be flagged        SAFE_*   -> should NOT be flagged
"""
import hashlib
import os
import random
import ssl
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

import jwt
import requests
import yaml
from Crypto.Cipher import AES
from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)
app.secret_key = "change-me-please"          # module-level: not inside a function, ignored by scan


# ============================ VULNERABLE ============================

def VULN_ssrf_user_url():
    url = request.args.get("url")
    return requests.get(url).text


def VULN_ssrf_fstring():
    host = request.args.get("host")
    return requests.post(f"http://{host}/admin/reset")


def VULN_open_redirect():
    target = request.args.get("next")
    return redirect(target)


def VULN_template_injection():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")


def VULN_xxe_parse_user_xml():
    data = request.data
    return ET.fromstring(data)


def VULN_zip_slip_tar(path):
    with tarfile.open(path) as tf:
        tf.extractall("/tmp/out")


def VULN_zip_slip_zip(path):
    zipfile.ZipFile(path).extractall("/tmp/out")


def VULN_jwt_no_verify(token):
    return jwt.decode(token, options={"verify_signature": False})


def VULN_world_writable_file(path):
    os.chmod(path, 0o777)


def VULN_insecure_tempfile():
    name = tempfile.mktemp()
    with open(name, "w") as fh:
        fh.write("data")
    return name


def VULN_ecb_mode(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def VULN_ssl_cert_none():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def VULN_flask_debug_all_interfaces():
    app.run(host="0.0.0.0", port=8080, debug=True)


def VULN_hardcoded_secret_in_kwarg():
    return connect(host="db.internal", user="admin", password="hunter2hunter2")


def VULN_yaml_fullloader(raw):
    return yaml.load(raw, Loader=yaml.FullLoader)


def VULN_sha1_for_password(pw):
    return hashlib.sha1(pw.encode()).hexdigest()


def VULN_predictable_session_id():
    return random.getrandbits(32)


def VULN_exec_param_via_variable(snippet):
    code = "result = " + snippet
    exec(code)


def VULN_dynamic_import():
    mod = request.args.get("module")
    return __import__(mod)


def VULN_sql_via_intermediate_variable():
    uid = request.args.get("id")
    q = "SELECT * FROM orders WHERE user = " + uid
    cur = get_db().cursor()
    cur.execute(q)
    return cur.fetchall()


def VULN_delete_arbitrary_file():
    name = request.form["name"]
    os.remove("/srv/files/" + name)


# ============================== SAFE ================================

def SAFE_ssrf_fixed_url():
    return requests.get("https://api.example.com/status", timeout=5).text


def SAFE_redirect_constant():
    return redirect("/dashboard")


def SAFE_template_constant(name):
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


def SAFE_tar_extract_with_filter(path):
    with tarfile.open(path) as tf:
        tf.extractall("/tmp/out", filter="data")


def SAFE_jwt_verified(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])


def SAFE_chmod_private(path):
    os.chmod(path, 0o600)


def SAFE_tempfile_secure():
    fd, name = tempfile.mkstemp()
    os.close(fd)
    return name


def SAFE_yaml_safeloader(raw):
    return yaml.load(raw, Loader=yaml.SafeLoader)


def SAFE_flask_localhost():
    app.run(host="127.0.0.1", port=8080)


def SAFE_credentials_from_env():
    return connect(host="db.internal", user="admin", password=os.environ["DB_PASSWORD"])


def SAFE_sha256_checksum(data):
    return hashlib.sha256(data).hexdigest()


def SAFE_cursor_parameterized():
    uid = request.args.get("id")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM orders WHERE user = %s", (uid,))
    return cur.fetchall()


def SAFE_file_read_sanitized():
    name = request.args.get("file")
    path = os.path.join("/srv/files", os.path.basename(name))
    with open(path) as fh:
        return fh.read()


def SAFE_plain_logic(items):
    total = 0
    for it in items:
        if it.get("active"):
            total += it["price"] * it["qty"]
    return total
