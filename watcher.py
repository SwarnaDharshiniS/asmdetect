"""
watcher.py
----------
Real-time malware detection daemon.
Monitors multiple folders simultaneously for new executable files.
When a new .exe / .dll / .bin / .msi file appears:
  1. Disassembles it with objdump
  2. Runs asmdetect inference
  3. Sends desktop popup notification (plyer)
  4. Sends email alert (smtplib / Gmail)
  5. Logs everything to watcher.log

Monitored locations (auto-detected on Linux/Windows):
  - ~/Downloads
  - ~/Desktop
  - /tmp
  - Thunderbird / Evolution mail attachment cache
  - Browser download cache (Chrome, Firefox)
  - Any custom folders you add in CONFIG below

Install:
    pip install watchdog plyer

Run:
    python watcher.py                  # uses .env / config below
    python watcher.py --dry-run        # no email, just desktop alerts
    python watcher.py --folder /path   # add extra folder at runtime
"""

import os
import sys
import time
import logging
import argparse
import hashlib
import subprocess
import threading
import smtplib
import json
import signal
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("ERROR: watchdog not installed. Run: pip install watchdog")
    sys.exit(1)

try:
    from plyer import notification as desktop_notify
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    print("WARNING: plyer not installed. Desktop notifications disabled.")
    print("         Run: pip install plyer")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION — edit these or set as environment variables
# ══════════════════════════════════════════════════════════════════════════════
CONFIG = {
    # ── Email alert settings ──────────────────────────────────────────────
    "EMAIL_ENABLED"    : True,
    "SMTP_HOST"        : os.getenv("SMTP_HOST",     "smtp.gmail.com"),
    "SMTP_PORT"        : int(os.getenv("SMTP_PORT", "587")),
    "SMTP_USER"        : os.getenv("SMTP_USER",     "your-gmail@gmail.com"),
    "SMTP_PASSWORD"    : os.getenv("SMTP_PASSWORD", "your-app-password"),
    "ALERT_RECIPIENT"  : os.getenv("ALERT_RECIPIENT","your-gmail@gmail.com"),

    # ── Detection settings ────────────────────────────────────────────────
    "THRESHOLD"        : float(os.getenv("THRESHOLD", "0.62")),
    "ALERT_ON_MEDIUM"  : True,   # alert for MEDIUM risk too (not just HIGH)
    "SCAN_DELAY_SEC"   : 1.5,    # wait before scanning (file may still be writing)

    # ── File types to watch ───────────────────────────────────────────────
    "WATCH_EXTENSIONS" : {
        ".exe", ".dll", ".msi", ".bat", ".cmd",
        ".ps1", ".vbs", ".scr", ".com", ".pif",
        ".bin", ".sys", ".drv"
    },

    # ── Log file ──────────────────────────────────────────────────────────
    "LOG_FILE"         : os.path.expanduser("~/asmdetect_watcher.log"),

    # ── Max file size to scan (bytes) — skip very large files ────────────
    "MAX_FILE_SIZE"    : 50 * 1024 * 1024,  # 50 MB
}

# ── Auto-detect folders to watch ─────────────────────────────────────────────
HOME = Path.home()

DEFAULT_WATCH_FOLDERS = [
    HOME / "Downloads",
    HOME / "Desktop",
    Path("/tmp"),
    Path("/var/tmp"),
    # Thunderbird attachment cache
    HOME / ".thunderbird",
    # Evolution mail
    HOME / ".local/share/evolution",
    # Chrome downloads
    HOME / ".config/google-chrome/Default/Downloads",
    # Firefox downloads
    HOME / ".mozilla/firefox",
    # Snap downloads
    HOME / "snap",
]

# Filter to only folders that actually exist
DEFAULT_WATCH_FOLDERS = [f for f in DEFAULT_WATCH_FOLDERS if f.exists()]

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(CONFIG["LOG_FILE"]),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("asmdetect.watcher")

# ── Seen-files cache (avoid scanning same file twice) ─────────────────────────
_seen_hashes: set = set()
_seen_lock = threading.Lock()

# ── Detector (loaded once, shared across threads) ─────────────────────────────
_detector = None
_detector_lock = threading.Lock()


def get_detector():
    global _detector
    with _detector_lock:
        if _detector is None:
            log.info("Loading asmdetect model from HuggingFace Hub...")
            from asmdetect import MalwareDetector
            _detector = MalwareDetector.from_pretrained(threshold=CONFIG["THRESHOLD"])
            log.info("Model loaded and ready.")
    return _detector


# ══════════════════════════════════════════════════════════════════════════════
# DISASSEMBLY
# ══════════════════════════════════════════════════════════════════════════════

def disassemble_to_opcodes(filepath: str) -> str | None:
    """
    Runs objdump -d on the file and returns a space-joined opcode sequence.
    Returns None if objdump fails or produces no valid opcodes.
    """
    try:
        result = subprocess.run(
            ["objdump", "-d", "-M", "intel", filepath],
            capture_output=True, text=True, timeout=30,
            errors="ignore"
        )
        if result.returncode != 0 or not result.stdout:
            return None

        opcodes = []
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 3:
                op = parts[2].strip().split()[0].lower()
                if op.isalpha() or (len(op) > 1 and op[0].isalpha()):
                    opcodes.append(op)
                    if len(opcodes) >= 256:
                        break

        return " ".join(opcodes) if len(opcodes) >= 10 else None

    except subprocess.TimeoutExpired:
        log.warning(f"objdump timed out on {filepath}")
        return None
    except FileNotFoundError:
        log.error("objdump not found. Install with: sudo apt install binutils")
        return None
    except Exception as e:
        log.warning(f"Disassembly failed for {filepath}: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

def send_desktop_notification(title: str, message: str, urgency: str = "normal"):
    """Send a desktop popup notification using plyer."""
    if not PLYER_AVAILABLE:
        return
    try:
        desktop_notify.notify(
            title   = title,
            message = message,
            app_name= "AsmDetect Watcher",
            timeout = 15 if urgency == "critical" else 8,
        )
    except Exception as e:
        log.warning(f"Desktop notification failed: {e}")


def send_email_alert(subject: str, body: str, dry_run: bool = False):
    """Send an email alert via Gmail SMTP."""
    if not CONFIG["EMAIL_ENABLED"] or dry_run:
        log.info(f"[DRY-RUN] Email would be sent: {subject}")
        return

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = CONFIG["SMTP_USER"]
        msg["To"]      = CONFIG["ALERT_RECIPIENT"]

        # Plain text
        msg.attach(MIMEText(body, "plain"))

        # HTML version
        html_body = body.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")
        html = f"""
        <html><body>
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
        <div style="background:#c0392b;color:white;padding:16px;border-radius:8px 8px 0 0">
            <h2 style="margin:0">⚠️ AsmDetect Security Alert</h2>
        </div>
        <div style="background:#fff8f8;border:1px solid #e74c3c;padding:20px;border-radius:0 0 8px 8px">
            <p>{html_body}</p>
        </div>
        <p style="color:#999;font-size:12px;text-align:center">
            AsmDetect Watcher — Automated Malware Detection System
        </p>
        </div>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(CONFIG["SMTP_HOST"], CONFIG["SMTP_PORT"]) as server:
            server.ehlo()
            server.starttls()
            server.login(CONFIG["SMTP_USER"], CONFIG["SMTP_PASSWORD"])
            server.sendmail(CONFIG["SMTP_USER"], CONFIG["ALERT_RECIPIENT"], msg.as_string())

        log.info(f"Email alert sent: {subject}")

    except smtplib.SMTPAuthenticationError:
        log.error("Gmail authentication failed. Make sure you're using an App Password.")
        log.error("Guide: https://support.google.com/accounts/answer/185833")
    except Exception as e:
        log.error(f"Email send failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# SCAN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def scan_file(filepath: str, dry_run: bool = False):
    """
    Full pipeline: file → hash dedup → size check → disassemble → predict → alert.
    Runs in a background thread so the watcher is never blocked.
    """
    try:
        path = Path(filepath)
        ext  = path.suffix.lower()

        # Extension filter
        if ext not in CONFIG["WATCH_EXTENSIONS"]:
            return

        # Wait for file to finish writing
        time.sleep(CONFIG["SCAN_DELAY_SEC"])

        # Existence check (may have been moved/deleted)
        if not path.exists():
            return

        # Size check
        size = path.stat().st_size
        if size == 0:
            return
        if size > CONFIG["MAX_FILE_SIZE"]:
            log.info(f"Skipping (too large: {size//1024//1024} MB): {path.name}")
            return

        # Deduplication by SHA-256
        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        with _seen_lock:
            if sha256 in _seen_hashes:
                return
            _seen_hashes.add(sha256)

        log.info(f"New file detected: {path.name}  ({size//1024} KB)  [{sha256[:12]}...]")

        # Disassemble
        opcodes = disassemble_to_opcodes(filepath)
        if opcodes is None:
            log.warning(f"Could not disassemble {path.name} — may be packed or non-PE. Flagging as suspicious.")
            _alert_suspicious(path, sha256, "Could not disassemble — may be packed or encrypted", dry_run)
            return

        # Predict
        detector = get_detector()
        t0       = time.perf_counter()
        result   = detector.predict_text(opcodes)
        elapsed  = (time.perf_counter() - t0) * 1000

        log.info(
            f"  → {result.prediction.upper():8s} | "
            f"P(malware)={result.malware_probability:.3f} | "
            f"Risk={result.risk_level:6s} | "
            f"{elapsed:.0f}ms | {path.name}"
        )

        # Log full result to JSON log
        _log_result(path, sha256, result, elapsed)

        # Alert if malware or medium risk (configurable)
        should_alert = result.is_malware or (CONFIG["ALERT_ON_MEDIUM"] and result.risk_level == "MEDIUM")
        if should_alert:
            _send_alerts(path, sha256, result, elapsed, dry_run)
        else:
            log.info(f"  → BENIGN — no alert sent for {path.name}")

    except Exception as e:
        log.error(f"Scan error for {filepath}: {e}", exc_info=True)


def _alert_suspicious(path: Path, sha256: str, reason: str, dry_run: bool):
    """Alert for files that couldn't be disassembled (packed malware indicator)."""
    title   = f"⚠️ SUSPICIOUS FILE: {path.name}"
    message = (
        f"File: {path.name}\n"
        f"Path: {path.parent}\n"
        f"Reason: {reason}\n"
        f"SHA-256: {sha256}\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"Recommendation: Do not open. Submit to sandbox for dynamic analysis."
    )
    send_desktop_notification(title, message, urgency="critical")
    send_email_alert(f"[AsmDetect] SUSPICIOUS FILE — {path.name}", message, dry_run)


def _send_alerts(path: Path, sha256: str, result, elapsed: float, dry_run: bool):
    """Send both desktop and email alerts for a confirmed malware/medium-risk file."""
    risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡"}.get(result.risk_level, "🟡")

    title = f"{risk_emoji} MALWARE DETECTED: {path.name}"

    message = (
        f"MALWARE DETECTED — AsmDetect Alert\n"
        f"{'='*45}\n"
        f"File     : {path.name}\n"
        f"Location : {path.parent}\n"
        f"SHA-256  : {sha256}\n"
        f"Verdict  : {result.prediction.upper()}\n"
        f"Risk     : {result.risk_level}\n"
        f"P(malware): {result.malware_probability*100:.1f}%\n"
        f"Confidence: {result.confidence*100:.1f}%\n"
        f"Tokens   : {result.input_tokens}\n"
        f"Inference: {elapsed:.0f} ms\n"
        f"Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'='*45}\n"
        f"IMMEDIATE ACTION REQUIRED:\n"
        f"  1. Do NOT open or execute this file\n"
        f"  2. Quarantine: mv '{path}' ~/quarantine/\n"
        f"  3. Submit for sandbox analysis if needed\n"
        f"{'='*45}\n"
        f"Model    : Swarnadharshini/codebert-malware-detector\n"
        f"Threshold: {result.threshold_used}"
    )

    # Desktop notification (immediate)
    send_desktop_notification(title, message[:256], urgency="critical")

    # Email alert
    email_subject = f"[AsmDetect] {risk_emoji} {result.risk_level} RISK — {path.name}"
    send_email_alert(email_subject, message, dry_run)


def _log_result(path: Path, sha256: str, result, elapsed: float):
    """Append structured JSON log entry."""
    entry = {
        "timestamp"  : datetime.now().isoformat(),
        "file"       : str(path),
        "filename"   : path.name,
        "sha256"     : sha256,
        "size_kb"    : path.stat().st_size // 1024,
        "prediction" : result.prediction,
        "risk_level" : result.risk_level,
        "malware_p"  : round(result.malware_probability, 4),
        "confidence" : round(result.confidence, 4),
        "tokens"     : result.input_tokens,
        "elapsed_ms" : round(elapsed, 1),
    }
    json_log = Path(CONFIG["LOG_FILE"]).with_suffix(".jsonl")
    with open(json_log, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# WATCHDOG EVENT HANDLER
# ══════════════════════════════════════════════════════════════════════════════

class MalwareWatchHandler(FileSystemEventHandler):
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def on_created(self, event):
        if not event.is_directory:
            threading.Thread(
                target=scan_file,
                args=(event.src_path, self.dry_run),
                daemon=True
            ).start()

    def on_moved(self, event):
        # Catches files downloaded to temp then moved to Downloads (browser behavior)
        if not event.is_directory:
            threading.Thread(
                target=scan_file,
                args=(event.dest_path, self.dry_run),
                daemon=True
            ).start()

    def on_modified(self, event):
        # Catches partially-written files that complete writing
        if not event.is_directory:
            ext = Path(event.src_path).suffix.lower()
            if ext in CONFIG["WATCH_EXTENSIONS"]:
                threading.Thread(
                    target=scan_file,
                    args=(event.src_path, self.dry_run),
                    daemon=True
                ).start()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AsmDetect real-time malware watcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python watcher.py                          # watch all default folders
  python watcher.py --dry-run                # no email, desktop only
  python watcher.py --folder /mnt/usb        # add extra folder
  python watcher.py --threshold 0.50         # more sensitive detection
  python watcher.py --no-email               # desktop alerts only
        """
    )
    parser.add_argument("--folder",    type=str,  help="Extra folder to watch")
    parser.add_argument("--threshold", type=float, default=CONFIG["THRESHOLD"])
    parser.add_argument("--dry-run",   action="store_true", help="No email, desktop only")
    parser.add_argument("--no-email",  action="store_true", help="Disable email alerts")
    args = parser.parse_args()

    CONFIG["THRESHOLD"] = args.threshold
    if args.no_email:
        CONFIG["EMAIL_ENABLED"] = False

    # Build folder list
    watch_folders = list(DEFAULT_WATCH_FOLDERS)
    if args.folder:
        extra = Path(args.folder)
        if extra.exists():
            watch_folders.append(extra)
        else:
            log.warning(f"Extra folder not found: {args.folder}")

    if not watch_folders:
        log.error("No folders to watch. Check that ~/Downloads or ~/Desktop exists.")
        sys.exit(1)

    # Pre-load model in main thread
    log.info("Pre-loading detection model...")
    get_detector()

    # Start observers
    handler  = MalwareWatchHandler(dry_run=args.dry_run)
    observer = Observer()

    for folder in watch_folders:
        observer.schedule(handler, str(folder), recursive=True)
        log.info(f"Watching: {folder}")

    observer.start()

    ext_list = ", ".join(sorted(CONFIG["WATCH_EXTENSIONS"]))
    log.info(f"")
    log.info(f"AsmDetect Watcher ACTIVE")
    log.info(f"  Threshold : {CONFIG['THRESHOLD']}")
    log.info(f"  Extensions: {ext_list}")
    log.info(f"  Email     : {'ENABLED' if CONFIG['EMAIL_ENABLED'] and not args.dry_run else 'DISABLED'}")
    log.info(f"  Desktop   : {'ENABLED' if PLYER_AVAILABLE else 'DISABLED (install plyer)'}")
    log.info(f"  Log file  : {CONFIG['LOG_FILE']}")
    log.info(f"  Press Ctrl+C to stop.")
    log.info(f"")

    # Graceful shutdown
    def handle_shutdown(sig, frame):
        log.info("Shutting down watcher...")
        observer.stop()
        observer.join()
        log.info("Watcher stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handle_shutdown(None, None)


if __name__ == "__main__":
    main()
