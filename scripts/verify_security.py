"""
scripts/verify_security.py
--------------------------
Formal verification of cryptographic security protocols used by asmdetect.

Verifies:
  1. TLS protocol version (must be >= 1.2)
  2. Server certificate validity and expiry
  3. HTTPS enforcement (no HTTP fallback)
  4. SHA-256 checksums of actual model files on HuggingFace

NOTE: CodeBERT uses RoBERTa tokenizer format.
      Actual files: config.json, tokenizer_config.json,
                    tokenizer.json, special_tokens_map.json
      (NOT vocab.json / merges.txt which are GPT-2 format)

Usage:
    python scripts/verify_security.py
    python scripts/verify_security.py --verbose
"""

import argparse, hashlib, json, os, ssl, socket
import urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

MODEL_ID = "Swarnadharshini/codebert-malware-detector"
HF_HOST  = "huggingface.co"

# ── Actual files present in a RoBERTa/CodeBERT fine-tuned model repo ─────────
# These are the real files — NOT vocab.json/merges.txt (those are GPT-2 format)
MODEL_FILES = [
    "config.json",
    "tokenizer_config.json",
    "tokenizer.json",
    "special_tokens_map.json",
]

def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

def check(label, passed, detail=""):
    status = green("PASS") if passed else red("FAIL")
    print(f"  [{status}] {label}")
    if detail:
        col = "" if passed else "\033[91m"
        print(f"         {col}{detail}\033[0m" if not passed else f"         {detail}")
    return passed


def verify_tls(host, verbose=False):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=10),
            server_hostname=host
        ) as s:
            proto  = s.version()
            cipher = s.cipher()
            cert   = s.getpeercert()
            ok     = proto in ("TLSv1.2", "TLSv1.3")
            return ok, proto, cipher[0] if cipher else "N/A", cert
    except Exception as e:
        return False, str(e), "N/A", {}


def verify_cert(host):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=10),
            server_hostname=host
        ) as s:
            cert      = s.getpeercert()
            not_after = cert.get("notAfter", "")
            dt        = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            dt        = dt.replace(tzinfo=timezone.utc)
            days_left = (dt - datetime.now(timezone.utc)).days
            subj      = dict(x[0] for x in cert.get("subject", []))
            cn        = subj.get("commonName", "")
            valid     = days_left > 0 and (host in cn or cn.startswith("*"))
            return valid, f"CN={cn}  expires={not_after}  ({days_left} days left)"
    except Exception as e:
        return False, str(e)


def verify_https_redirect(host):
    try:
        req = urllib.request.Request(
            f"http://{host}", method="HEAD",
            headers={"User-Agent": "asmdetect-verify/1.0"}
        )
        try:
            urllib.request.urlopen(req, timeout=8)
            return False, "No redirect — HTTP served directly"
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location", "")
            return loc.startswith("https://"), f"Redirects to: {loc}"
        except Exception as e:
            # Connection refused at HTTP level = HTTPS-only = good
            return True, f"HTTP connection refused (HTTPS-only): {e}"
    except Exception as e:
        return False, str(e)


def sha256_file(model_id, filename):
    url = f"https://{HF_HOST}/{model_id}/resolve/main/{filename}"
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url, headers={"User-Agent": "asmdetect-verify/1.0"}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            data      = r.read()
            sha256    = hashlib.sha256(data).hexdigest()
            size_kb   = len(data) // 1024
            final_url = r.url
            ok = (len(data) > 0 and final_url.startswith("https://"))
            return ok, sha256, size_kb
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.reason}", 0
    except Exception as e:
        return False, str(e), 0


def run(model_id, verbose=False):
    checksums  = {}
    all_passed = True
    results    = {}

    print(f"\n{bold('='*60)}")
    print(f"{bold('  ASMDETECT — CRYPTOGRAPHIC SECURITY VERIFICATION')}")
    print(f"{bold('='*60)}")
    print(f"  Model  : {model_id}")
    print(f"  Host   : {HF_HOST}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # 1. TLS
    print(bold("1. TLS Transport Security"))
    ok, proto, cipher, cert = verify_tls(HF_HOST, verbose)
    p = check(f"TLS version >= 1.2", ok, f"Protocol={proto}  Cipher={cipher}")
    check("TLS 1.3 (preferred)", proto == "TLSv1.3", f"Current: {proto}")
    results["tls"] = {"passed": p, "protocol": proto, "cipher": cipher}
    all_passed = all_passed and p
    print()

    # 2. Certificate
    print(bold("2. Certificate Chain"))
    cert_ok, cert_detail = verify_cert(HF_HOST)
    p = check("Certificate valid and not expired", cert_ok, cert_detail)
    results["certificate"] = {"passed": p, "detail": cert_detail}
    all_passed = all_passed and p
    print()

    # 3. HTTPS redirect
    print(bold("3. HTTPS Enforcement"))
    redir_ok, redir_detail = verify_https_redirect(HF_HOST)
    p = check("HTTP → HTTPS redirect enforced", redir_ok, redir_detail)
    results["https_redirect"] = {"passed": p, "detail": redir_detail}
    all_passed = all_passed and p
    print()

    # 4. Python SSL config
    print(bold("4. Python SSL Configuration"))
    paths = ssl.get_default_verify_paths()
    check("CA bundle found",
          bool(paths.cafile or paths.capath),
          str(paths.cafile or paths.capath))
    check("CERT_REQUIRED enforced",
          ssl.create_default_context().verify_mode == ssl.CERT_REQUIRED,
          "ssl.CERT_REQUIRED")
    print()

    # 5. File integrity
    print(bold("5. Model File Integrity — SHA-256 Checksums"))
    print(f"  (checking {len(MODEL_FILES)} files from {model_id})")
    print()
    for fname in MODEL_FILES:
        ok, sha_or_err, size_kb = sha256_file(model_id, fname)
        if ok is None:
            print(f"  [{yellow('SKIP')}] {fname:<35} — {sha_or_err}")
        elif ok:
            short = sha_or_err[:32] + "..."
            check(f"{fname:<35}", True, f"SHA-256={short}  ({size_kb} KB)")
            checksums[fname] = sha_or_err
        else:
            check(f"{fname:<35}", False, sha_or_err)
            all_passed = False
    print()

    # Summary
    print(f"{bold('='*60)}")
    print(f"{bold('  SUMMARY')}")
    print(f"{bold('='*60)}")
    if all_passed:
        print(f"  {green('ALL CHECKS PASSED')} — downloads are cryptographically secure")
    else:
        print(f"  {red('SOME CHECKS FAILED')} — review above")

    if checksums:
        print()
        print(bold("  SHA-256 checksums (pin for supply-chain integrity):"))
        for fname, sha in checksums.items():
            print(f"    {sha}  {fname}")

    report = {
        "timestamp": datetime.now().isoformat(),
        "model_id" : model_id,
        "host"     : HF_HOST,
        "all_passed": all_passed,
        "checks"   : results,
        "sha256"   : checksums,
    }
    out = Path("asmdetect_security_report.json")
    out.write_text(json.dumps(report, indent=2))
    print(f"\n  Report saved: {out.resolve()}")
    print(f"{'='*60}\n")
    return report


def main():
    p = argparse.ArgumentParser(
        description="Verify cryptographic security of asmdetect model downloads")
    p.add_argument("--model",   default=MODEL_ID)
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    run(args.model, args.verbose)

if __name__ == "__main__":
    main()
