import os
import html
from typing import Optional

try:
    from github import Github, GithubException
    _has_github = True
except ImportError:
    _has_github = False

# Fallback patch for target_app.py XSS — escapes q
XSS_PATCH_TEMPLATE = """@app.get("/api/search")
async def search_xss(q: str = "", request: Request = None):
    client_ip = request.client.host if request else "unknown"
    logger.info(f"Search XSS q='{q}' from {client_ip}")
    # Patched: output encoding to prevent reflected XSS
    safe_q = html.escape(q)
    return {"query": safe_q, "result": f"Results for: {safe_q}", "html": f"<div>Search: {safe_q}</div>"}"""

def generate_xss_patch(original_code: str) -> str:
    """Ask Groq to generate patched code; fallback to template if LLM unavailable."""
    try:
        llm = None
        token = os.getenv("GROQ_API_KEY")
        if token:
            from langchain_groq import ChatGroq
            from langchain_core.prompts import ChatPromptTemplate
            llm = ChatGroq(model_name="openai/gpt-oss-20b", temperature=0)
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are a senior AppSec engineer. Patch the given Python FastAPI code to prevent reflected XSS by HTML-escaping the q parameter with html.escape. Return ONLY the patched Python code, no markdown."),
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

def create_security_pr(file_path: str, patched_code: str, vuln_name: str, episode_id: str) -> str:
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
        except Exception as e:
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
                f"- **Validation:** Review `html.escape` and CSP. Preview deployment will be auto-verified.\n\n"
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
