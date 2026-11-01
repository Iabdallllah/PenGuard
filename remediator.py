import ast
import hashlib
import os
import re
from typing import Any, Dict, List, Optional

try:
    from github import Github, GithubException
    _has_github = True
except ImportError:
    _has_github = False


# Canonical vulnerable function per vector in the local target app. Keeping this
# mapping in one place lets the AST engine remediate every vector, not only XSS.
SCENARIO_FUNCTIONS: Dict[str, str] = {
    "idor": "get_user_profile",
    "sql_injection": "search_records",
    "business_logic": "process_checkout",
    "xss": "search_xss",
    "csrf": "transfer",
    "ssrf": "fetch_ssrf",
    "broken_auth": "login",
    "misconfig": "debug_info",
}


def _parse_statements(code: str) -> List[ast.stmt]:
    return ast.parse(code).body


def _insert_after_docstring(fn: ast.AST, statements: List[ast.stmt]) -> None:
    body = getattr(fn, "body", None)
    if body is None:
        return
    index = 0
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        index = 1
    body[index:index] = statements


def _dump_contains(node: ast.AST, needle: str) -> bool:
    try:
        return needle in ast.dump(node)
    except Exception:
        return False


def _remove_dict_key(return_node: ast.Return, key: str) -> bool:
    value = return_node.value
    if not isinstance(value, ast.Dict):
        return False
    removed = False
    keys: List[Optional[ast.expr]] = []
    values: List[ast.expr] = []
    for key_node, value_node in zip(value.keys, value.values):
        if isinstance(key_node, ast.Constant) and key_node.value == key:
            removed = True
            continue
        keys.append(key_node)
        values.append(value_node)
    if removed:
        value.keys = keys
        value.values = values
    return removed


class _ReplaceName(ast.NodeTransformer):
    """Replace a bare ``Name`` inside one return expression."""

    def __init__(self, old: str, new: str):
        self.old = old
        self.new = new

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if node.id == self.old:
            return ast.copy_location(ast.Name(id=self.new, ctx=node.ctx), node)
        return node


def _ensure_html_import(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Import) and any(alias.name == "html" for alias in node.names):
            return False
    tree.body.insert(0, ast.Import(names=[ast.alias(name="html")]))
    return True


def _transform_idor(fn: ast.AST, labels: List[str]) -> None:
    if not _dump_contains(fn, "Authorization"):
        _insert_after_docstring(fn, _parse_statements(
            'if request.headers.get("Authorization") != "Bearer admin-valid-token":\n'
            '    raise HTTPException(status_code=403, detail="Forbidden: unauthorized object access")'
        ))
        labels.append("If:authorization_gate")
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and _remove_dict_key(node, "secret_note"):
            labels.append("Dict:redact_secret_note")


def _transform_sql_injection(fn: ast.AST, labels: List[str]) -> None:
    parameterized = (
        '"SELECT id, patient_name, diagnosis FROM medical_records '
        'WHERE diagnosis LIKE ?"'
    )
    replaced_query = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "raw_sql":
                    if not (isinstance(node.value, ast.Constant) and "LIKE ?" in str(node.value.value)):
                        node.value = ast.parse(parameterized).body[0].value
                        labels.append("Assign:parameterized_query")
                    replaced_query = True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if (
                len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "raw_sql"
            ):
                param = ast.parse('f"%{query}%"').body[0].value
                node.args.append(ast.Tuple(elts=[param], ctx=ast.Load()))
                labels.append("Call:bind_query_parameter")
    if not replaced_query:
        # Unknown shape: add a defensive parameterized handler as a last resort.
        _insert_after_docstring(fn, _parse_statements(
            'safe_query = "SELECT id, patient_name, diagnosis FROM medical_records '
            'WHERE diagnosis LIKE ?"\n'
            'cur.execute(safe_query, (f"%{query}%",))\n'
            'rows = cur.fetchall()\n'
            'return [{"id": r[0], "patient_name": r[1], "diagnosis": r[2]} for r in rows]'
        ))
        labels.append("Assign:defensive_parameterized_query")


def _transform_business_logic(fn: ast.AST, labels: List[str]) -> None:
    if _dump_contains(fn, "server invariant"):
        return
    _insert_after_docstring(fn, _parse_statements(
        'if payload.quantity <= 0 or payload.unit_price <= 0:\n'
        '    raise HTTPException(status_code=400, detail="Validation Error: quantity and price must be positive (server invariant)")\n'
        'if payload.item_id in ITEM_CATALOG and payload.unit_price != ITEM_CATALOG[payload.item_id]:\n'
        '    raise HTTPException(status_code=400, detail="Validation Error: catalog price invariant violated")'
    ))
    labels.append("If:positive_quantity_gate")
    labels.append("If:catalog_price_gate")


def _transform_xss(fn: ast.AST, labels: List[str]) -> None:
    already_encoded = _dump_contains(fn, "html.escape")
    if not already_encoded:
        _insert_after_docstring(fn, _parse_statements(
            'if "<script" in q.lower() or "onerror" in q.lower() or "javascript:" in q.lower():\n'
            '    raise HTTPException(status_code=400, detail="Invalid input: potential XSS detected")\n'
            'safe_q = html.escape(q, quote=True)'
        ))
        labels.append("If:xss_input_filter")
        labels.append("Assign:html_escape_output")
    replaced = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and node.value is not None:
            before = ast.dump(node.value)
            node.value = _ReplaceName("q", "safe_q").visit(node.value)
            if ast.dump(node.value) != before:
                replaced = True
    if replaced:
        labels.append("Return:escaped_output")


def _transform_csrf(fn: ast.AST, labels: List[str]) -> None:
    if _dump_contains(fn, "valid-csrf-token"):
        return
    _insert_after_docstring(fn, _parse_statements(
        'if request.headers.get("x-csrf-token") != "valid-csrf-token":\n'
        '    raise HTTPException(status_code=403, detail="Forbidden: CSRF token missing/invalid")'
    ))
    labels.append("If:csrf_token_gate")


def _transform_ssrf(fn: ast.AST, labels: List[str]) -> None:
    if _dump_contains(fn, "Forbidden: SSRF blocked - private address"):
        return
    _insert_after_docstring(fn, _parse_statements(
        'if any(blocked in url.lower() for blocked in '
        '["169.254.169.254", "metadata", "localhost", "127.0.0.1", "0.0.0.0", "internal"]):\n'
        '    raise HTTPException(status_code=403, detail="Forbidden: SSRF blocked - private address")'
    ))
    labels.append("If:ssrf_private_address_gate")


def _transform_broken_auth(fn: ast.AST, labels: List[str]) -> None:
    if _dump_contains(fn, "admin password policy"):
        return
    _insert_after_docstring(fn, _parse_statements(
        'if payload.username == "admin" and payload.password != "AdminPass123!":\n'
        '    raise HTTPException(status_code=401, detail="Invalid credentials: admin password policy")'
    ))
    labels.append("If:admin_password_gate")


def _transform_misconfig(fn: ast.AST, labels: List[str]) -> None:
    safe_return = ast.parse(
        '{"debug": False, "message": "Debug endpoint disabled in production", "vulnerable": False}'
    ).body[0].value
    for node in ast.walk(fn):
        if isinstance(node, ast.Return):
            node.value = ast.parse(ast.unparse(safe_return)).body[0].value
            labels.append("Return:sanitize_debug_payload")


_TRANSFORMERS = {
    "idor": _transform_idor,
    "sql_injection": _transform_sql_injection,
    "business_logic": _transform_business_logic,
    "xss": _transform_xss,
    "csrf": _transform_csrf,
    "ssrf": _transform_ssrf,
    "broken_auth": _transform_broken_auth,
    "misconfig": _transform_misconfig,
}


def _result(
    scenario: str,
    function: str,
    source: str,
    patch: Optional[str],
    ast_verified: bool,
    transformed_nodes: List[str],
    applied: bool,
    **extra: Any,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "engine": "python-ast",
        "scenario": scenario,
        "function": function,
        "patch": source if patch is None else patch,
        "ast_verified": bool(ast_verified),
        "transformed_nodes": list(transformed_nodes),
        "applied": bool(applied),
        "original_sha256": hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest(),
    }
    if result["patch"] is not None:
        result["patch_sha256"] = hashlib.sha256(
            result["patch"].encode("utf-8", errors="replace")
        ).hexdigest()
    result.update(extra)
    return result


def remediate_source(scenario: str, source: str) -> Dict[str, Any]:
    """AST-remediate one vulnerable Python function for ``scenario``.

    Returns a metadata-rich result. The generated ``patch`` is only reported as
    ``ast_verified`` after a full ``ast.parse`` round-trip. Non-Python input is
    returned untouched with ``applied=False`` — never with a fabricated patch.
    """
    try:
        from security_model import normalize_scenario
        scenario = normalize_scenario(scenario) or str(scenario or "").strip().lower()
    except Exception:
        scenario = str(scenario or "").strip().lower()
    function = SCENARIO_FUNCTIONS.get(scenario, "")
    source = source or ""
    if not function:
        return _result(
            scenario, "", source, source, False, [], False,
            fallback_reason="unsupported-scenario",
        )
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return _result(
            scenario, function, source, source, False, [], False,
            fallback_reason="non-python-input",
            error=f"line {exc.lineno}: {exc.msg}" if exc.lineno else exc.msg,
        )
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function:
            fn = node
            break
    if fn is None:
        return _result(
            scenario, function, source, source, False, [], False,
            fallback_reason="function-not-found",
        )

    labels: List[str] = [f"{type(fn).__name__}:{function}"]
    try:
        if scenario == "xss" and _ensure_html_import(tree):
            labels.append("Import:html")
        _TRANSFORMERS[scenario](fn, labels)
        actions = [label for label in labels if not label.startswith(("AsyncFunctionDef:", "FunctionDef:"))]
        if not actions:
            return _result(
                scenario, function, source, source, False, labels, False,
                fallback_reason="no-transformable-nodes",
            )
        patch = ast.unparse(tree)
        ast.parse(patch)
        return _result(
            scenario, function, source, patch, True, labels, True,
        )
    except Exception as exc:
        return _result(
            scenario, function, source, source, False, labels, False,
            fallback_reason="transformation-failed",
            error=str(exc),
        )


def generate_ast_patch(scenario: str, source: str) -> str:
    """Return the AST-remediated source, or the original source on fallback."""
    return remediate_source(scenario, source)["patch"]


# Fallback patch for target_app.py XSS — escapes q with input filtering + 400
XSS_PATCH_TEMPLATE = """@app.get("/api/search")
async def search_xss(q: str = "", request: Request = None):
    client_ip = request.client.host if request else "unknown"
    logger.info(f"Search XSS q='{q}' from {client_ip}")
    # Patched: input filtering + output encoding (quote=True) to prevent reflected XSS
    if "<script" in q.lower() or "onerror" in q.lower() or "javascript:" in q.lower():
        raise HTTPException(status_code=400, detail="Invalid input: potential XSS detected")
    safe_q = html.escape(q, quote=True)
    return {"query": safe_q, "result": f"Results for: {safe_q}", "html": f"<div>Search: {safe_q}</div>"}"""

def generate_xss_patch(original_code: str) -> str:
    """AST-remediate XSS first; retain the LLM/template path as a fallback."""
    ast_result = remediate_source("xss", original_code)
    if ast_result["applied"] and ast_result["ast_verified"]:
        return ast_result["patch"]
    try:
        llm = None
        token = os.getenv("GROQ_API_KEY")
        if token:
            from langchain_groq import ChatGroq
            from langchain_core.prompts import ChatPromptTemplate
            llm = ChatGroq(model_name="openai/gpt-oss-20b", temperature=0)
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are a senior AppSec engineer. Patch the given Python FastAPI code to prevent reflected XSS by input filtering (reject <script/onerror with 400) and HTML-escaping the q parameter with html.escape(q, quote=True). Return ONLY the patched Python code, no markdown."),
                ("human", "Vulnerable code:\n{code}\n\nGenerate safe version:")
            ])
            resp = (prompt | llm).invoke({"code": original_code})
            text = resp.content if hasattr(resp, "content") else str(resp)
            # Extract code block if present
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("python"):
                    text = text[6:]
                text = text.strip()
            if "html.escape" in text and "def search_xss" in text:
                return text
    except Exception as e:
        print(f"[remediator] LLM patch generation failed: {e}")
    # Fallback deterministic
    if "html.escape" in original_code:
        return original_code
    return XSS_PATCH_TEMPLATE

def create_security_pr(
    file_path: str,
    patched_code: str,
    vuln_name: str,
    episode_id: str,
    validation_note: Optional[str] = None,
) -> str:
    token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_TARGET_REPO")  # e.g. Iabdallllah/PenGuard
    if not token or not repo_name:
        return "PR Skipped: GITHUB_TOKEN or GITHUB_TARGET_REPO not configured"
    if not _has_github:
        return "PR Skipped: PyGithub not installed"

    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        base_branch = repo.default_branch
        new_branch = f"patch/{vuln_name.lower().replace(' ', '-')}-{episode_id[:6]}"

        # Check if branch already exists
        try:
            repo.get_branch(new_branch)
            return f"PR Skipped: branch {new_branch} already exists"
        except Exception:
            pass

        base_ref = repo.get_git_ref(f"heads/{base_branch}")
        repo.create_git_ref(ref=f"refs/heads/{new_branch}", sha=base_ref.object.sha)

        # Get current file content on new branch (full file)
        try:
            file_content = repo.get_contents(file_path, ref=new_branch)
            sha = file_content.sha
            original_full = file_content.decoded_content.decode()
        except Exception:
            # File not found on new branch — try base
            try:
                file_content = repo.get_contents(file_path, ref=base_branch)
                sha = file_content.sha
                original_full = file_content.decoded_content.decode()
            except Exception as fe:
                return f"PR Failed: file {file_path} not found: {fe}"

        # If patched_code is a snippet (function only), replace inside full file
        # Otherwise if it looks like a full file (contains imports/SECURITY_RULES), use as is
        is_full_file = "import sqlite3" in patched_code or "SECURITY_RULES" in patched_code or patched_code.count("\n") > 50
        if not is_full_file and file_path == "target_app.py" and "def search_xss" in patched_code:
            # Replace only the search_xss function, preserving TransferPayload and other code
            vuln_start = original_full.find('@app.get("/api/search")')
            if vuln_start != -1:
                # The search_xss function ends right before "class TransferPayload" (which follows it)
                # Find that class to preserve it
                transfer_start = original_full.find("\nclass TransferPayload", vuln_start)
                if transfer_start != -1:
                    next_boundary = transfer_start
                else:
                    # Fallback: find next @app after the function
                    next_boundary = original_full.find("\n@app.", vuln_start + 1)
                    if next_boundary == -1:
                        next_boundary = len(original_full)
                # Construct full patched content
                before = original_full[:vuln_start]
                after = original_full[next_boundary:]
                # Ensure html import exists in full file
                if "import html" not in before and "import html" not in patched_code:
                    if "import sqlite3" in before:
                        before = before.replace("import sqlite3", "import html\nimport sqlite3")
                    else:
                        patched_code = "import html\n" + patched_code
                        # and also ensure full file has it
                        if "import html" not in before:
                            before = "import html\n" + before
                patched_full = before + patched_code.strip() + "\n" + after.lstrip("\n")
            else:
                # Fallback: just append
                patched_full = original_full + "\n\n" + patched_code
        else:
            patched_full = patched_code
            # Ensure html import in full file if needed
            if "import html" not in patched_full and "html.escape" in patched_full:
                if "import sqlite3" in patched_full:
                    patched_full = patched_full.replace("import sqlite3", "import html\nimport sqlite3")
                else:
                    patched_full = "import html\n" + patched_full

        repo.update_file(
            path=file_path,
            message=f"fix(security): mitigate {vuln_name} [PenGuard {episode_id[:6]}]",
            content=patched_full,
            sha=sha,
            branch=new_branch,
        )

        pr = repo.create_pull(
            title=f"🛡️ Security Mitigation: Automated Patch for {vuln_name}",
            body=(
                f"### PenGuard Autonomous Security Advisory\n\n"
                f"- **Target File:** `{file_path}`\n"
                f"- **Vulnerability Vector:** {vuln_name}\n"
                f"- **Episode:** `{episode_id}`\n"
                f"- **Status:** Exploit validated by Red Agent → Auto-patched by Blue Agent.\n"
                f"- **Validation:** {validation_note or 'Deterministic AST remediation applied and syntax-validated.'}\n\n"
                f"> Generated by PenGuard AI Detection Engine. Please review and merge once CI checks pass."
            ),
            head=new_branch,
            base=base_branch,
        )
        return pr.html_url
    except GithubException as ge:
        return f"PR Failed: GitHub API {ge.status} {ge.data.get('message', str(ge)) if hasattr(ge, 'data') else str(ge)}"
    except Exception as e:
        return f"PR Failed: {e}"


def post_pr_verdict(pr_url: str, verdict: str, episode_id: str) -> Optional[str]:
    """Post the automated re-test verdict as a PR comment. Returns the comment
    URL on success, None when skipped/unavailable (never raises)."""
    if not (pr_url or "").startswith("http"):
        return None
    token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_TARGET_REPO")
    if not token or not repo_name:
        print("[pr] verdict skipped: GITHUB_TOKEN or GITHUB_TARGET_REPO not configured")
        return None
    if not _has_github:
        print("[pr] verdict skipped: PyGithub not installed")
        return None
    m = re.search(r"/pull/(\d+)", pr_url)
    if not m:
        print(f"[pr] verdict skipped: no PR number in {pr_url}")
        return None
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        pr = repo.get_pull(int(m.group(1)))
        if (pr.html_url or "") != pr_url:
            print("[pr] verdict skipped: PR URL mismatch")
            return None
        body = (f"### PenGuard Automated Re-test Verdict\n\n{verdict}\n\n"
                f"- **Episode:** `{episode_id}`\n"
                f"> Posted by the Blue Agent after patch application. Re-run the episode to reproduce.")
        comment = pr.create_issue_comment(body)
        print(f"[pr] verdict posted: {comment.html_url}")
        return comment.html_url
    except Exception as e:
        print(f"[pr] verdict failed: {e}")
        return None
