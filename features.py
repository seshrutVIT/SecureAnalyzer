"""
features.py  --  Stages 1-2 of the pipeline: Lexer -> Parser (AST) -> feature vector + rule findings.

Source code (Python) --tokenize--> tokens --ast.parse--> AST --walk--> numeric features
                                                              --rules--> human-readable findings

The numeric features are UNCHANGED from the previous version, so an existing model.joblib
keeps working. The rule engine (_rules) is new and independent of the model: scan.py uses it
to flag functions even when the model score is low.
"""
import ast
import io
import re
import textwrap
import tokenize
from collections import Counter

# ---------- 1. Fixed vocabulary of AST node types (structural features) ----------
NODE_TYPES = sorted(
    n for n in dir(ast)
    if isinstance(getattr(ast, n), type) and issubclass(getattr(ast, n), ast.AST)
    and n not in ("AST", "mod", "stmt", "expr", "expr_context", "boolop", "operator",
                  "unaryop", "cmpop", "slice", "type_ignore", "pattern", "excepthandler",
                  "Index", "ExtSlice", "Suite", "Param", "AugLoad", "AugStore",
                  "Num", "Str", "Bytes", "NameConstant", "Ellipsis")
)

# ---------- 2. Security-relevant sinks (dangerous function families) ----------
SINKS = {
    "cmd_exec":   {"os.system", "os.popen", "subprocess.call", "subprocess.run",
                   "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
                   "subprocess.getoutput", "commands.getoutput"},
    "code_exec":  {"eval", "exec", "compile", "__import__"},
    "deserialize": {"pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads",
                    "yaml.load", "yaml.unsafe_load", "shelve.open"},
    "sql_exec":   {"execute", "executemany", "executescript", "raw"},
    "file_io":    {"open", "os.remove", "os.unlink", "shutil.rmtree", "send_file",
                   "send_from_directory"},
    "weak_crypto": {"hashlib.md5", "hashlib.sha1", "random.random", "random.randint",
                    "random.choice"},
    "net_unsafe": {"requests.get", "requests.post", "urllib.request.urlopen",
                   "ssl._create_unverified_context"},
}
SINK_NAMES = list(SINKS)

# Where untrusted data typically comes from
SOURCES = {"input", "raw_input", "sys.argv", "os.environ", "os.getenv",
           "request.args", "request.form", "request.values", "request.json",
           "request.data", "request.GET", "request.POST", "request.cookies",
           "request.headers", "request.files", "flask.request"}

SECRET_NAME = re.compile(
    r"(pass(word|wd)?|secret|api_?key|token|private_?key|credential)", re.I)

# functions that normalise / validate a path -> suppress path-traversal findings
PATH_HELPERS = {"basename", "secure_filename",
                "realpath", "commonpath", "safe_join"}


def dotted(node):
    """ast node -> 'a.b.c' string (best effort)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def _sink_family(call):
    name = dotted(call.func)
    short = name.split(".")[-1]
    for fam, names in SINKS.items():
        if name in names:
            return fam
    if short in SINKS["sql_exec"]:      # cursor.execute / conn.execute / Model.objects.raw
        return "sql_exec"
    return None


def _is_dynamic_string(node):
    """f-string, 'a'+b, 'a%s'%b, 'a{}'.format(b)  ->  string built from variables."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _names_in(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


# ---------- 3. Feature extraction ----------
def tokenize_source(code):
    """Stage 1 - Lexer. Returns token type counts (kept as light features)."""
    counts = Counter()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            counts[tokenize.tok_name[tok.type]] += 1
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return counts


def extract(code):
    """
    Stage 2 - Parser + feature builder.
    Returns (feature_dict, findings) or (None, []) if the code does not parse.
    `findings` = sorted list of (line, family, message) produced by the rule engine.
    """
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return None, []

    feats = Counter()

    # structural: node-type histogram, size, depth
    n_nodes = 0
    for node in ast.walk(tree):
        feats[f"node_{type(node).__name__}"] += 1
        n_nodes += 1
    feats["n_nodes"] = n_nodes
    feats["max_depth"] = _depth(tree)

    # lexical
    for k, v in tokenize_source(code).items():
        feats[f"tok_{k}"] = v
    feats["n_lines"] = code.count("\n") + 1

    # taint-lite: variables assigned from untrusted sources (propagated 1 hop)
    tainted = set()
    params = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params |= {a.arg for a in node.args.args +
                       node.args.kwonlyargs} - {"self", "cls"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            src_hit = any(dotted(n) in SOURCES or dotted(n.value if isinstance(n, ast.Subscript) else n) in SOURCES
                          for n in ast.walk(node.value)
                          if isinstance(n, (ast.Call, ast.Attribute, ast.Subscript, ast.Name)))
            if src_hit or (_names_in(node.value) & tainted):
                for t in node.targets:
                    tainted |= _names_in(t)
    tainted_all = tainted | params
    feats["n_tainted_vars"] = len(tainted)
    feats["n_params"] = len(params)

    for node in ast.walk(tree):
        # ---- calls ----
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name in SOURCES or dotted(node.func) in SOURCES:
                feats["source_calls"] += 1
            fam = _sink_family(node)
            if fam:
                feats[f"sink_{fam}"] += 1
                args = list(node.args) + [k.value for k in node.keywords]
                dyn = any(_is_dynamic_string(a) for a in args)
                tnt = any(_names_in(a) & tainted_all for a in args)
                const_only = all(isinstance(a, ast.Constant)
                                 for a in args) if args else True
                shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                                 for k in node.keywords)
                if dyn:
                    feats[f"sink_{fam}_dynamic_arg"] += 1
                if tnt:
                    feats[f"sink_{fam}_tainted_arg"] += 1
                if const_only:
                    feats[f"sink_{fam}_const_arg"] += 1
                if shell_true:
                    feats["shell_true"] += 1
                if fam == "sql_exec" and not (dyn or tnt):
                    feats["sql_parameterized"] += 1
            if name == "yaml.load" and not any(k.arg == "Loader" for k in node.keywords):
                feats["yaml_load_no_loader"] += 1
            if name.startswith("requests.") and any(k.arg == "verify" and isinstance(k.value, ast.Constant)
                                                    and k.value.value is False for k in node.keywords):
                feats["tls_verify_off"] += 1
            if any(k.arg == "debug" and isinstance(k.value, ast.Constant) and k.value.value is True
                   for k in node.keywords):
                feats["debug_true"] += 1

        # ---- hard-coded credentials ----
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str) and len(node.value.value) >= 4:
            for t in node.targets:
                nm = t.id if isinstance(t, ast.Name) else t.attr if isinstance(
                    t, ast.Attribute) else ""
                if SECRET_NAME.search(nm):
                    feats["hardcoded_secret"] += 1

        # ---- exception swallowing ----
        if isinstance(node, ast.ExceptHandler) and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            feats["except_pass"] += 1

    return dict(feats), _rules(tree, tainted, params)


def _depth(node, d=0):
    try:
        kids = list(ast.iter_child_nodes(node))
        return d if not kids else max(_depth(k, d + 1) for k in kids)
    except RecursionError:
        return d


# ---------- 4. Rule engine (model-independent findings) ----------
def _is_const(node, value):
    return isinstance(node, ast.Constant) and node.value is value


def _has_source(node):
    return any(isinstance(n, (ast.Call, ast.Attribute, ast.Name)) and dotted(n) in SOURCES
               for n in ast.walk(node))


def _propagate(tree, seed):
    """Grow a set of 'tainted' variable names through simple assignments (3 passes)."""
    names = set(seed)
    for _ in range(3):
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and (_names_in(n.value) & names or _has_source(n.value)):
                for t in n.targets:
                    names |= {x.id for x in ast.walk(t) if isinstance(
                        x, ast.Name) and isinstance(x.ctx, ast.Store)}
    return names


def _why(node, names):
    """Why is this argument attacker-influenced? -> short reason or None."""
    if node is None or isinstance(node, ast.Constant):
        return None
    if _is_dynamic_string(node):
        return "dynamic string"
    if _has_source(node):
        return "untrusted input"
    if not isinstance(node, (ast.List, ast.Tuple, ast.Dict)) and _names_in(node) & names:
        return "tainted variable"
    return None


def _rules(tree, tainted, params):
    # sources + function parameters
    loose = _propagate(tree, tainted | params)
    strict = _propagate(tree, tainted)           # real untrusted sources only
    path_safe = any(isinstance(n, ast.Call) and dotted(n.func).split(".")[-1] in PATH_HELPERS
                    for n in ast.walk(tree))
    out = set()

    def add(node, fam, msg):
        out.add((node.lineno, fam, msg))

    for node in ast.walk(tree):
        # ============================ calls ============================
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            short = name.split(".")[-1]
            args = node.args
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            a0 = args[0] if args else None

            # --- command injection ---
            if name in SINKS["cmd_exec"]:
                shell = _is_true(kw.get("shell"))
                why = _why(a0, loose)
                if isinstance(a0, (ast.List, ast.Tuple)) and not shell:
                    pass                                    # list-form, no shell: safe
                elif shell:
                    add(node, "cmd_exec",
                        f"{name}(shell=True)" + (f" with {why}" if why else ""))
                elif why:
                    add(node, "cmd_exec", f"{name}() with {why}")

            # --- eval / exec / dynamic import ---
            if name in ("eval", "exec", "__import__") and a0 is not None and not isinstance(a0, ast.Constant):
                add(node, "code_exec",
                    f"{name}() on {_why(a0, loose) or 'non-constant argument'}")

            # --- insecure deserialization ---
            if name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "marshal.loads",
                        "marshal.load", "shelve.open", "dill.loads", "dill.load", "jsonpickle.decode"):
                add(node, "deserialize",
                    f"{name}() can execute code embedded in untrusted data")
            if name == "yaml.unsafe_load":
                add(node, "deserialize",
                    "yaml.unsafe_load() can construct arbitrary objects")
            if name in ("yaml.load", "yaml.load_all"):
                loader = kw.get("Loader") or (
                    args[1] if len(args) > 1 else None)
                if loader is None or "Safe" not in dotted(loader):
                    add(node, "deserialize", f"{name}() without SafeLoader")

            # --- SQL injection ---
            if short in ("execute", "executemany", "executescript", "raw", "RawSQL") and a0 is not None:
                why = _why(a0, loose)
                if why:
                    add(node, "sql_exec",
                        f"SQL query built from {why} in {name}()")

            # --- path traversal / arbitrary file access ---
            if name in ("open", "io.open", "os.remove", "os.unlink", "os.rename", "shutil.rmtree", "send_file"):
                why = _why(a0, strict)
                if why and not path_safe:
                    add(node, "path_traversal",
                        f"{name}() path from {why} (no sanitising)")
            if short in ("extractall", "unpack_archive") and "filter" not in kw:
                add(node, "path_traversal",
                    f"{name}() extracts archive without validating member paths (zip-slip)")

            # --- weak crypto / randomness ---
            if name in ("hashlib.md5", "hashlib.sha1"):
                add(node, "weak_crypto",
                    f"{name}() is a broken hash (use sha256+ / bcrypt / argon2 for passwords)")
            if name in ("random.random", "random.randint", "random.choice", "random.randrange",
                        "random.getrandbits", "random.sample"):
                add(node, "weak_crypto",
                    f"{name}() is not cryptographically secure (use the secrets module)")

            # --- TLS / certificates ---
            if _is_false(kw.get("verify")):
                add(node, "net_unsafe",
                    f"{name}(verify=False) disables certificate checking")
            if name == "ssl._create_unverified_context":
                add(node, "net_unsafe",
                    "ssl._create_unverified_context() disables certificate checking")

            # --- SSRF / open redirect / template injection ---
            if name in ("requests.get", "requests.post", "requests.put", "requests.delete", "requests.head",
                        "urllib.request.urlopen", "urlopen", "httpx.get", "httpx.post"):
                why = _why(a0, strict)
                if why:
                    add(node, "ssrf",
                        f"{name}() URL from {why} (possible SSRF)")
            if short == "redirect":
                why = _why(a0, strict)
                if why:
                    add(node, "open_redirect", f"redirect() target from {why}")
            if short == "render_template_string" or name in ("Template", "jinja2.Template"):
                why = _why(a0, loose)
                if why:
                    add(node, "template_injection",
                        f"{name}() template from {why} (SSTI)")

            # --- XML external entities ---
            if short in ("fromstring", "parse", "parseString") and \
                    name.split(".")[0] in ("ET", "etree", "ElementTree", "minidom", "xml", "lxml"):
                why = _why(a0, loose)
                if why:
                    add(node, "xxe",
                        f"{name}() parses XML from {why} (use defusedxml)")

            # --- JWT / permissions / misc ---
            if name == "jwt.decode":
                d = ast.dump(node)
                if _is_false(kw.get("verify")) or ("verify_signature" in d and "value=False" in d):
                    add(node, "auth",
                        "jwt.decode() with signature verification disabled")
            if name == "os.chmod" and len(args) > 1 and isinstance(args[1], ast.Constant) \
                    and isinstance(args[1].value, int) and args[1].value & 0o002:
                add(node, "permissions",
                    f"os.chmod() makes file world-writable ({oct(args[1].value)})")
            if name in ("tempfile.mktemp", "mktemp"):
                add(node, "insecure_temp",
                    "tempfile.mktemp() is race-prone (use mkstemp / NamedTemporaryFile)")
            if name in ("telnetlib.Telnet", "ftplib.FTP"):
                add(node, "cleartext",
                    f"{name}() sends credentials in clear text")
            if _is_true(kw.get("debug")):
                add(node, "config",
                    "debug=True exposes an interactive debugger / stack traces")
            if short == "run" and isinstance(kw.get("host"), ast.Constant) and kw["host"].value == "0.0.0.0":
                add(node, "config", "server binds to 0.0.0.0 (all network interfaces)")

            # --- secrets passed as literal keyword args ---
            for k in node.keywords:
                if k.arg and SECRET_NAME.search(k.arg) and isinstance(k.value, ast.Constant) \
                        and isinstance(k.value.value, str) and len(k.value.value) >= 4:
                    add(node, "hardcoded_cred", f"literal passed as {k.arg}=")

        # ====================== assignments / attributes ======================
        if isinstance(node, ast.Assign):
            for t in node.targets:
                nm = t.id if isinstance(t, ast.Name) else t.attr if isinstance(
                    t, ast.Attribute) else ""
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) \
                        and len(node.value.value) >= 4 and SECRET_NAME.search(nm):
                    add(node, "hardcoded_cred", f"literal assigned to '{nm}'")
                if nm == "check_hostname" and _is_false(node.value):
                    add(node, "net_unsafe", "check_hostname = False")

        if isinstance(node, ast.Attribute):
            if node.attr == "MODE_ECB":
                add(node, "weak_crypto", "ECB mode leaks plaintext patterns")
            if dotted(node) == "ssl.CERT_NONE":
                add(node, "net_unsafe", "ssl.CERT_NONE disables certificate checking")

        if isinstance(node, ast.ExceptHandler) and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            add(node, "error_handling",
                "exception silently swallowed (except: pass)")

    return sorted(out)


def _is_true(node):
    return node is not None and _is_const(node, True)


def _is_false(node):
    return node is not None and _is_const(node, False)


def split_functions(code):
    """Yield (name, start_line, source) for each top-level / method function; fall back to whole file."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return
    lines = code.splitlines()
    found = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found = True
            seg = "\n".join(lines[node.lineno - 1: node.end_lineno])
            # dedent so it parses standalone
            yield node.name, node.lineno, textwrap.dedent(seg)
    if not found:
        yield "<module>", 1, code
