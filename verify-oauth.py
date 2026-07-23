"""
Polymarket MCP — Full local OAuth flow + tools verification.
Bhai is verifying: OAuth 2.0 + PKCE flow + 13 tools + revocation + refresh.
"""

import subprocess
import time
import json
import sys
import os
import urllib.request
import urllib.parse
import urllib.error
import http.client as httpc
import hashlib
import base64
import secrets
import re

SERVER = r"C:\Users\RBTG\polymarket-mcp\dist\server-entry.js"
LOG = r"C:\Users\RBTG\polymarket-mcp\test-oauth.log"
BASE = "http://127.0.0.1:7842"

def b64url(b):
    if isinstance(b, str): b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def sha256_b64url(s):
    return b64url(hashlib.sha256(s.encode()).digest())

def http(method, path, data=None, headers=None, timeout=10):
    h = {"Accept": "application/json, text/event-stream"}
    if headers: h.update(headers)
    body = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode()
            h.setdefault("Content-Type", "application/json")
        elif isinstance(data, bytes):
            body = data
    if body is not None:
        h.setdefault("Content-Length", str(len(body)))
    req = urllib.request.Request(f"{BASE}{path}", data=body, method=method, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace"), dict(e.headers)

def post_form(path, fields):
    """POST form-urlencoded, no redirect follow."""
    data = urllib.parse.urlencode(fields).encode()
    conn = httpc.HTTPConnection("127.0.0.1", 7842, timeout=10)
    conn.request("POST", path, body=data, headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(data))})
    r = conn.getresponse()
    body = r.read().decode("utf-8", errors="replace")
    headers = dict(r.getheaders())
    conn.close()
    return r.status, body, headers

def post_form_no_redirect(path, fields):
    """POST form-urlencoded using a custom NoRedirect opener."""
    data = urllib.parse.urlencode(fields).encode()
    class NR(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            return None
        http_error_301 = http_error_303 = http_error_307 = http_error_302
    opener = urllib.request.build_opener(NR())
    req = urllib.request.Request(f"{BASE}{path}", data=data, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"})
    try:
        r = opener.open(req, timeout=10)
        return r.status, r.read().decode("utf-8", errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace"), dict(e.headers)

def post_json_mcp(payload, access_token, session_id=None):
    data = json.dumps(payload).encode()
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": f"Bearer {access_token}"}
    if session_id: h["mcp-session-id"] = session_id
    conn = httpc.HTTPConnection("127.0.0.1", 7842, timeout=10)
    conn.request("POST", "/mcp", body=data, headers=h)
    r = conn.getresponse()
    body = r.read().decode("utf-8", errors="replace")
    status = r.status
    headers = dict(r.getheaders())
    conn.close()
    return status, body, headers

def main():
    print("═" * 60)
    print(" Polymarket MCP — Full Local OAuth + Tools Verification")
    print("═" * 60)
    print()

    print("[1] Starting server subprocess...")
    try:
        subprocess.run(["powershell", "-Command", "Get-Process -Name node -ErrorAction SilentlyContinue | Stop-Process -Force"], timeout=5, capture_output=True)
    except: pass
    time.sleep(1)

    log_file = open(LOG, "w", encoding="utf-8")
    proc = subprocess.Popen(
        ["node", SERVER],
        stdout=log_file, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        cwd=r"C:\Users\RBTG\polymarket-mcp",
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    print(f"    spawned PID {proc.pid}")

    ready = False
    for i in range(30):
        time.sleep(0.3)
        if proc.poll() is not None:
            log_file.flush()
            with open(LOG, "r", encoding="utf-8") as f:
                print(f"    DIED early rc={proc.returncode}")
                print(f"    log: {f.read()[:500]}")
            sys.exit(1)
        try:
            r = http("GET", "/health", timeout=1)
            if r[0] == 200:
                print(f"    READY at {(i+1)*0.3:.1f}s — health: {r[1]}")
                ready = True
                break
        except: pass
    if not ready:
        log_file.flush()
        with open(LOG, "r", encoding="utf-8") as f:
            print(f"    TIMEOUT — log: {f.read()[:500]}")
        proc.kill()
        sys.exit(1)
    print()

    results = []
    def T(name, ok, info=""):
        results.append((ok, name, info))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({info})" if info else ""))
        return ok

    # Step 2: Discover
    print("[2] OAuth metadata discovery (RFC 8414)...")
    code, body, _ = http("GET", "/.well-known/oauth-authorization-server")
    meta = json.loads(body) if code == 200 else {}
    T("T2: /health responds", code == 200 and "ok" in http("GET", "/health")[1])
    T("T2: OAuth metadata returned", code == 200 and "authorization_endpoint" in meta)
    T("T2: PKCE S256 supported", "S256" in meta.get("code_challenge_methods_supported", []))
    T("T2: Dynamic Client Registration endpoint", "/oauth/register" in meta.get("registration_endpoint", ""))
    print(f"    issuer: {meta.get('issuer')}")
    print(f"    auth: {meta.get('authorization_endpoint')}")
    print(f"    token: {meta.get('token_endpoint')}")
    print()

    # Step 3: DCR
    print("[3] Dynamic Client Registration (RFC 7591)...")
    code, body, _ = http("POST", "/oauth/register", {
        "client_name": "local-test-script",
        "redirect_uris": ["http://127.0.0.1:9999/cb"],
        "client_uri": "https://github.com/fourlabsofficial/polymarket-mcp",
    })
    reg = json.loads(body) if code in (200, 201) else {}
    client_id = reg.get("client_id", "")
    client_secret = reg.get("client_secret", "")
    T("T3: DCR returns 201", code == 201)
    T("T3: client_id present", bool(client_id))
    T("T3: client_secret present", bool(client_secret))
    print(f"    client_id: {client_id[:24]}...")
    print(f"    client_secret: {client_secret[:12]}... (length={len(client_secret)})")
    print()

    # Step 4: PKCE
    print("[4] PKCE S256 generation...")
    verifier = b64url(secrets.token_bytes(48))[:64]
    challenge = sha256_b64url(verifier)
    state = b64url(secrets.token_bytes(16))
    T("T4: verifier 64 chars", len(verifier) == 64)
    T("T4: challenge != verifier", challenge != verifier)
    T("T4: state 22 chars", len(state) >= 22)
    print(f"    verifier (first 20): {verifier[:20]}...")
    print(f"    challenge (first 20): {challenge[:20]}...")
    print(f"    state: {state}")
    print()

    # Step 5: GET /oauth/authorize
    print("[5] /oauth/authorize (login + consent)...")
    auth_params = urllib.parse.urlencode(dict(
        response_type="code", client_id=client_id, redirect_uri="http://127.0.0.1:9999/cb",
        code_challenge=challenge, code_challenge_method="S256", state=state, scope="mcp:read mcp:trade"
    ))
    code, body, _ = http("GET", "/oauth/authorize?" + auth_params)
    T("T5: GET returns 200", code == 200)
    T("T5: login form rendered", "<form" in body)
    T("T5: PKCE hidden in form", challenge in body)
    T("T5: state hidden", state in body)
    print(f"    login page size: {len(body)} bytes")
    print()

    # Step 5b: POST dev_approve (local test)
    print("[5b] POST dev_approve (local test mode)...")
    code, body, hdrs = post_form_no_redirect("/oauth/authorize", dict(
        client_id=client_id, redirect_uri="http://127.0.0.1:9999/cb",
        scope="mcp:read mcp:trade", code_challenge=challenge,
        code_challenge_method="S256", state=state, action="dev_approve",
    ))
    T("T5b: dev_approve → 302", code == 302)
    loc = hdrs.get("Location", "")
    T("T5b: redirect has code", "code=" in loc)
    T("T5b: redirect has state", "state=" in loc)
    print(f"    Location: {loc[:150]}")
    auth_code = ""
    if "code=" in loc:
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(loc).query)
        auth_code = q.get("code", [""])[0]
        returned_state = q.get("state", [""])[0]
        print(f"    auth_code: {auth_code[:20]}...")
        print(f"    state matches: {returned_state == state}")
    print()

    # Step 6: Token exchange (use httpc — no redirect issue)
    print("[6] /oauth/token (code → tokens)...")
    code, body, _ = post_form("/oauth/token", dict(
        grant_type="authorization_code", code=auth_code, redirect_uri="http://127.0.0.1:9999/cb",
        client_id=client_id, client_secret=client_secret, code_verifier=verifier,
    ))
    T("T6: token endpoint returns 200", code == 200)
    tokens = json.loads(body) if code == 200 else {}
    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    T("T6: access_token present", bool(access_token))
    T("T6: refresh_token present", bool(refresh_token))
    T("T6: token_type=Bearer", tokens.get("token_type") == "Bearer")
    T("T6: expires_in positive", tokens.get("expires_in", 0) > 0)
    T("T6: scope echoed", "mcp:read" in tokens.get("scope", ""))
    print(f"    access_token: {access_token[:32]}... (len={len(access_token)})")
    print(f"    refresh_token: {refresh_token[:20]}... (len={len(refresh_token)})")
    print(f"    expires_in: {tokens.get('expires_in')}s")
    print(f"    scope: {tokens.get('scope')}")
    print(f"    has polymarket_credentials: {bool(tokens.get('polymarket_credentials'))}")
    print()

    # Step 7: /mcp with bearer
    print("[7] /mcp with bearer (initialize)...")
    init_payload = {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"local-test","version":"0.1"}}}
    code, body, hdrs = post_json_mcp(init_payload, access_token)
    T("T7: /mcp with valid bearer → 200", code == 200)
    session_id = hdrs.get("mcp-session-id", "")
    T("T7: session id issued", bool(session_id))
    print(f"    session_id: {session_id[:16]}...")
    print(f"    body: {body[:150]}")
    print()

    # Step 8: tools/list
    print("[8] /mcp tools/list...")
    code, body, _ = post_json_mcp({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}, access_token, session_id)
    T("T8: tools/list → 200", code == 200)
    tool_count = 0
    tool_names = []
    try:
        m = re.search(r"data: (\{.*\})", body, re.DOTALL)
        if m:
            payload = json.loads(m.group(1))
            tools = payload.get("result", {}).get("tools", [])
            tool_count = len(tools)
            tool_names = [t.get("name", "?") for t in tools]
    except Exception as e:
        print(f"    parse error: {e}")
    T("T8: tools registered (>= 10)", tool_count >= 10, f"got {tool_count}")
    print(f"    tools count: {tool_count}")
    print(f"    all names: {tool_names}")
    print()

    # Step 9: Revocation
    print("[9] Token revocation...")
    code, body, _ = post_form("/oauth/revoke", {"token": access_token})
    T("T9: revoke → 200", code == 200)
    revoked_ok = False
    try: revoked_ok = json.loads(body).get("revoked") == True
    except: pass
    T("T9: revoked=true", revoked_ok)
    # Now try to use revoked token
    init_payload = {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}
    code, body, _ = post_json_mcp(init_payload, access_token)
    T("T9: revoked token → 401", code == 401)
    T("T9: invalid_token in body", "invalid_token" in body)
    print(f"    revoked response: {body[:150]}")
    print()

    # Step 10: Refresh
    print("[10] Refresh token rotation...")
    code, body, _ = post_form("/oauth/token", {"grant_type":"refresh_token", "refresh_token": refresh_token})
    T("T10: refresh → 200", code == 200)
    new_tokens = json.loads(body) if code == 200 else {}
    T("T10: new access_token issued", bool(new_tokens.get("access_token")))
    T("T10: new refresh_token (rotation)", bool(new_tokens.get("refresh_token")) and new_tokens.get("refresh_token") != refresh_token)
    new_access = new_tokens.get("access_token", "")
    # Use new access token
    init_payload = {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}
    code, body, _ = post_json_mcp(init_payload, new_access)
    T("T10: new access token works → 200", code == 200)
    # Old refresh token now invalid
    code, body, _ = post_form("/oauth/token", {"grant_type":"refresh_token", "refresh_token": refresh_token})
    T("T10: old refresh token now invalid → 400", code == 400)
    print(f"    refresh rotation works")
    print()

    # Step 11: summary
    print()
    print("═" * 60)
    passes = sum(1 for ok, _, _ in results if ok)
    print(f" RESULTS: {passes}/{len(results)} tests passed")
    print("═" * 60)
    failed = [n for ok, n, _ in results if not ok]
    if failed:
        print(f" FAILED: {', '.join(failed)}")
    else:
        print(" ALL TESTS PASSED ✓")

    proc.terminate()
    try: proc.wait(timeout=3)
    except: proc.kill()
    log_file.close()
    with open(LOG, "r", encoding="utf-8") as f:
        log_content = f.read()
    print()
    print("═" * 60)
    print(" SERVER LOG")
    print("═" * 60)
    print(log_content[-1500:] if len(log_content) > 1500 else log_content)

    return 0 if not failed else 1

if __name__ == "__main__":
    sys.exit(main())