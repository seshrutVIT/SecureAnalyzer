"""
test_target.py -- sample file to feed into scan.py.

    python scan.py test_target.py
    python scan.py test_target.py --watch      # edit & save to see live re-scans

Contains functions that are INTENTIONALLY vulnerable (VULN_*) and functions that are
safe equivalents (SAFE_*). Nothing here is ever executed by the scanner; it is only parsed.

What to look for:
  - VULN_* functions should be flagged ([!]) with evidence lines.
  - SAFE_* functions should NOT be flagged.
  - Anything in the "borderline" section is a stress test; the result depends on your model.
"""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import request, send_file


# =====================================================================
#  VULNERABLE (should be flagged)
# =====================================================================

def VULN_command_injection_os_system():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)


def VULN_command_injection_shell_true(filename):
    cmd = f"tar -czf backup.tar.gz {filename}"
    subprocess.call(cmd, shell=True)


def VULN_command_injection_popen():
    target = input("Enter host: ")
    out = os.popen("nslookup %s" % target).read()
    return out


def VULN_eval_user_input():
    expr = request.form["expr"]
    return eval(expr)


def VULN_exec_user_code(payload):
    exec(payload)


def VULN_sql_injection_fstring(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cur.fetchall()


def VULN_sql_injection_concat():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)
    return cur.fetchall()


def VULN_sql_injection_format(email):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE email = '{}'".format(email))
    conn.commit()


def VULN_insecure_deserialization_pickle():
    data = request.data
    obj = pickle.loads(data)
    return obj


def VULN_insecure_deserialization_yaml(raw):
    return yaml.load(raw)


def VULN_path_traversal_send_file():
    name = request.args.get("file")
    return send_file("/var/data/" + name)


def VULN_path_traversal_open(user_path):
    with open("/srv/uploads/" + user_path, "r") as fh:
        return fh.read()


def VULN_hardcoded_credentials():
    password = "SuperSecret123!"
    api_key = "sk-live-9f8a7b6c5d4e3f2a1b0c"
    db_token = "ghp_abcdefghijklmnopqrstuvwxyz012345"
    return connect_to_service(password, api_key, db_token)


def VULN_tls_verification_disabled(url):
    resp = requests.get(url, verify=False)
    return resp.text


def VULN_weak_crypto_password_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def VULN_weak_random_token():
    return str(random.randint(100000, 999999))


def VULN_swallowed_exception_auth(user, pw):
    try:
        check_credentials(user, pw)
    except Exception:
        pass
    return True


def VULN_multi_issue_kitchen_sink():
    password = "admin1234"
    user = request.args.get("user")
    os.system("useradd " + user)
    data = request.data
    cfg = pickle.loads(data)
    requests.post("https://internal.example", data=cfg, verify=False)
    return eval(request.args.get("x"))


# =====================================================================
#  SAFE (should NOT be flagged)
# =====================================================================

def SAFE_command_list_args(filename):
    subprocess.run(["tar", "-czf", "backup.tar.gz", filename], check=True)


def SAFE_command_constant():
    subprocess.run(["ls", "-l"], check=True)


def SAFE_sql_parameterized(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()


def SAFE_yaml_safe_load(raw):
    return yaml.safe_load(raw)


def SAFE_literal_parse(text):
    import ast
    return ast.literal_eval(text)


def SAFE_password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)


def SAFE_secure_token():
    import secrets
    return secrets.token_urlsafe(32)


def SAFE_secret_from_env():
    password = os.environ.get("DB_PASSWORD")
    return password


def SAFE_tls_verified(url):
    resp = requests.get(url, timeout=5)
    return resp.text


def SAFE_path_sanitized(name):
    base = "/srv/uploads"
    full = os.path.realpath(os.path.join(base, os.path.basename(name)))
    if not full.startswith(base):
        raise ValueError("bad path")
    with open(full, "r") as fh:
        return fh.read()


def SAFE_pure_math(a, b):
    total = 0
    for i in range(a):
        total += i * b
    return total


def SAFE_string_helpers(first, last):
    full = first.strip().title() + " " + last.strip().title()
    return full


def SAFE_exception_logged(user, pw):
    try:
        return check_credentials(user, pw)
    except ValueError as e:
        print("auth failed:", e)
        return False


# =====================================================================
#  BORDERLINE (stress tests -- results depend on the model)
# =====================================================================

def BORDER_sql_dynamic_table_name_allowlisted(table):
    allowed = {"users", "orders"}
    if table not in allowed:
        raise ValueError("bad table")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT COUNT(*) FROM {table}")
    return cur.fetchone()


def BORDER_eval_constant_only():
    return eval("1 + 2")


def BORDER_shell_true_constant():
    subprocess.call("ls -l /tmp", shell=True)


def BORDER_pickle_load_trusted_local():
    with open("cache.pkl", "rb") as fh:
        return pickle.load(fh)


def BORDER_variable_named_token_not_secret(token_count):
    token = "x" * token_count
    return token
