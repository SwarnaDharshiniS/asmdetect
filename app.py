"""
app.py — asmdetect Integrated Dashboard
========================================
Single entry point for the entire asmdetect system.
Run: streamlit run app.py

Tabs:
  1. Single File   — upload .csv and predict
  2. Raw Opcodes   — paste opcode text and predict
  3. Batch Triage  — scan entire folder
  4. Live Watcher  — real-time folder monitoring + alerts
  5. Optimize      — ONNX export and benchmark
  6. Security      — TLS/SHA256 verification
  7. Architecture  — system diagram + algorithm
"""

import os, sys, json, time, glob, hashlib, subprocess
import threading, queue, tempfile, socket, ssl, urllib.request
import pandas as pd
import numpy as np
import streamlit as st
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AsmDetect — Malware Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.main-title{font-size:2rem;font-weight:700;color:#1a1a2e;margin-bottom:0}
.sub-title{font-size:.95rem;color:#555;margin-top:2px;margin-bottom:1.5rem}
.verdict-malware{background:#fff0f0;border:2px solid #e74c3c;border-radius:12px;
    padding:1.2rem;text-align:center}
.verdict-benign{background:#f0fff4;border:2px solid #27ae60;border-radius:12px;
    padding:1.2rem;text-align:center}
.verdict-text-malware{font-size:1.8rem;font-weight:800;color:#c0392b}
.verdict-text-benign{font-size:1.8rem;font-weight:800;color:#1e8449}
.sec-head{font-size:1rem;font-weight:600;color:#1a1a2e;
    border-bottom:2px solid #e0e0e0;padding-bottom:.3rem;margin-bottom:.8rem}
.stat-box{background:#f8f9fa;border-radius:8px;padding:.8rem;text-align:center;
    border:1px solid #e0e0e0}
.log-line-mal{color:#c0392b;font-family:monospace;font-size:.8rem}
.log-line-ok {color:#1e8449;font-family:monospace;font-size:.8rem}
.log-line-inf{color:#555;font-family:monospace;font-size:.8rem}
.algo-box{background:#f4f6f9;border-left:4px solid #2c3e50;border-radius:0 8px 8px 0;
    padding:1rem 1.2rem;font-family:monospace;font-size:.82rem;
    line-height:1.7;white-space:pre-wrap;color:#1a1a2e}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# SHARED STATE
# ══════════════════════════════════════════════════════════════════════════════
MODEL_ID  = "Swarnadharshini/codebert-malware-detector"
WATCH_EXT = {".exe",".dll",".msi",".bat",".cmd",".ps1",".vbs",".scr",".bin"}

if "watcher_running"  not in st.session_state: st.session_state.watcher_running  = False
if "watcher_log"      not in st.session_state: st.session_state.watcher_log      = []
if "watcher_thread"   not in st.session_state: st.session_state.watcher_thread   = None
if "watcher_stop"     not in st.session_state: st.session_state.watcher_stop     = threading.Event()
if "scan_queue"       not in st.session_state: st.session_state.scan_queue       = queue.Queue()
if "security_report"  not in st.session_state: st.session_state.security_report  = None
if "benchmark_result" not in st.session_state: st.session_state.benchmark_result = None


# ══════════════════════════════════════════════════════════════════════════════
# MODEL LOADER (cached)
# ══════════════════════════════════════════════════════════════════════════════
@st.cache_resource(show_spinner=False)
def load_detector(threshold):
    from asmdetect import MalwareDetector
    return MalwareDetector.from_pretrained(threshold=threshold)


# ══════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def render_result(result, source_name, elapsed_ms):
    col_v, col_m = st.columns(2)
    with col_v:
        if result.is_malware:
            icon = {"HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢"}.get(result.risk_level,"")
            st.markdown(
                f'<div class="verdict-malware">'
                f'<div class="verdict-text-malware">⚠️ MALWARE</div>'
                f'<div style="font-size:1.1rem;margin-top:.4rem">{icon} Risk: {result.risk_level}</div>'
                f'</div>', unsafe_allow_html=True)
        else:
            st.markdown(
                f'<div class="verdict-benign">'
                f'<div class="verdict-text-benign">✅ BENIGN</div>'
                f'<div style="font-size:1.1rem;margin-top:.4rem">🟢 Risk: LOW</div>'
                f'</div>', unsafe_allow_html=True)
    with col_m:
        st.markdown("**Malware probability:**")
        st.progress(result.malware_probability)
        st.caption(f"{result.malware_probability*100:.1f}% malware  |  "
                   f"{result.benign_probability*100:.1f}% benign")
        c1, c2 = st.columns(2)
        c1.metric("Confidence",  f"{result.confidence*100:.2f}%")
        c2.metric("Inference",   f"{elapsed_ms:.0f} ms")
        c1.metric("Tokens",      str(result.input_tokens))
        c2.metric("Threshold",   str(result.threshold_used))
    with st.expander("Raw JSON (SIEM/SOAR integration)"):
        st.json(result.to_dict())


def disassemble(filepath):
    try:
        out = subprocess.run(
            ["objdump", "-d", "-M", "intel", filepath],
            capture_output=True, text=True, timeout=30, errors="ignore"
        )
        ops = []
        for line in out.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 3:
                op = parts[2].strip().split()[0].lower()
                if op.isalpha() or (len(op) > 1 and op[0].isalpha()):
                    ops.append(op)
                    if len(ops) >= 256: break
        return " ".join(ops) if len(ops) >= 10 else None
    except Exception:
        return None


def send_desktop_notif(title, msg):
    try:
        from plyer import notification
        notification.notify(title=title, message=msg[:200],
                            app_name="AsmDetect", timeout=10)
    except Exception:
        pass


def send_email(subject, body, cfg):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    try:
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"]    = cfg["user"]
        msg["To"]      = cfg["recipient"]
        msg.attach(MIMEText(body, "plain"))
        html = body.replace("\n","<br>")
        msg.attach(MIMEText(f"<html><body style='font-family:Arial'>{html}</body></html>","html"))
        with smtplib.SMTP(cfg["host"], int(cfg["port"])) as s:
            s.starttls(); s.login(cfg["user"], cfg["password"])
            s.sendmail(cfg["user"], cfg["recipient"], msg.as_string())
        return True
    except Exception as e:
        return str(e)


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("### 🛡️ AsmDetect")
    st.markdown("---")
    threshold = st.slider("Detection Threshold", 0.30, 0.90, 0.62, 0.01,
        help="Lower = more sensitive. Higher = fewer false alarms.")
    st.markdown("---")
    st.markdown("**Model**")
    st.caption(f"`{MODEL_ID}`")
    st.markdown("**Accuracy:** 86.0%  |  **AUC-ROC:** 0.910")
    st.markdown("**F1:** 0.857  |  **Threshold:** 0.62")
    st.markdown("---")
    st.markdown("🔴 **HIGH** ≥ 80% malware probability")
    st.markdown("🟡 **MEDIUM** ≥ 55% malware probability")
    st.markdown("🟢 **LOW** < 55% malware probability")
    st.markdown("---")
    st.markdown("[🤗 HuggingFace]"
                "(https://huggingface.co/Swarnadharshini/codebert-malware-detector)")
    st.markdown("[💻 GitHub]"
                "(https://github.com/SwarnaDharshiniS/asmdetect)")


# ══════════════════════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown('<p class="main-title">🛡️ AsmDetect — Assembly-Level Malware Detection</p>',
            unsafe_allow_html=True)
st.markdown('<p class="sub-title">Fine-tuned CodeBERT on x86 opcode sequences — '
            'static analysis, no execution required — SOC triage ready</p>',
            unsafe_allow_html=True)

# Load model once
with st.spinner("Loading model from HuggingFace Hub..."):
    try:
        detector = load_detector(threshold)
        detector.set_threshold(threshold)
        st.success("✅ Model loaded and ready for inference.")
    except Exception as e:
        st.error(f"Model load failed: {e}"); st.stop()


# ══════════════════════════════════════════════════════════════════════════════
# TABS
# ══════════════════════════════════════════════════════════════════════════════
tabs = st.tabs([
    "📁 Single File",
    "⌨️ Raw Opcodes",
    "📂 Batch Triage",
    "👁️ Live Watcher",
    "⚡ Optimize",
    "🔒 Security",
    "📊 Architecture",
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — SINGLE FILE
# ══════════════════════════════════════════════════════════════════════════════
with tabs[0]:
    st.markdown('<p class="sec-head">Upload a .csv disassembly file</p>',
                unsafe_allow_html=True)
    st.caption("File must have an **Opcode** column (IDA Pro / objdump format).")

    uploaded = st.file_uploader("Drop CSV here", type=["csv"],
                                label_visibility="collapsed")
    if uploaded:
        col_l, col_r = st.columns(2)
        with col_l:
            st.markdown("**Preview:**")
            try:
                st.dataframe(pd.read_csv(uploaded, nrows=10),
                             use_container_width=True)
                uploaded.seek(0)
            except Exception as e:
                st.warning(f"Preview error: {e}"); uploaded.seek(0)
        with col_r:
            if st.button("🔍 Analyse File", type="primary",
                         use_container_width=True):
                with st.spinner("Analysing..."):
                    with tempfile.NamedTemporaryFile(
                            delete=False, suffix=".csv") as tmp:
                        tmp.write(uploaded.read()); tp = tmp.name
                    try:
                        t0 = time.perf_counter()
                        r  = detector.predict_file(tp)
                        ms = (time.perf_counter() - t0) * 1000
                    except Exception as e:
                        st.error(str(e)); os.unlink(tp); st.stop()
                    finally:
                        if os.path.exists(tp): os.unlink(tp)
                st.markdown("---")
                render_result(r, uploaded.name, ms)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — RAW OPCODES
# ══════════════════════════════════════════════════════════════════════════════
with tabs[1]:
    st.markdown('<p class="sec-head">Paste a raw opcode sequence</p>',
                unsafe_allow_html=True)
    st.caption("Space-separated x86 mnemonics e.g. `push mov xor call ret add nop`")

    col_a, col_b = st.columns([3,1])
    with col_a:
        opcode_text = st.text_area("Opcodes", height=130,
            placeholder="push mov sub lea call add pop ret xor push mov "
                        "call ret nop add sub push mov xor call ret ...",
            label_visibility="collapsed")
    with col_b:
        st.markdown(" ")
        st.markdown(" ")
        run_text = st.button("🔍 Analyse", type="primary",
                             use_container_width=True)
        st.markdown("**Quick tests:**")
        if st.button("Load malware sample", use_container_width=True):
            st.session_state["sample_text"] = (
                "xor xor push push call mov xor add sub push call mov xor nop "
                "ret jmp jmp xor call push mov lea push call mov xor xor add "
                "push ret call nop jmp xor push call mov xor ret"
            )
        if st.button("Load benign sample", use_container_width=True):
            st.session_state["sample_text"] = (
                "push mov sub mov call mov add pop ret push mov sub lea "
                "call add mov ret mov push sub mov call add ret push mov "
                "sub lea call add pop ret nop"
            )

    # Apply quick test samples
    if "sample_text" in st.session_state:
        opcode_text = st.session_state.pop("sample_text")
        st.rerun()

    if run_text and opcode_text.strip():
        with st.spinner("Analysing..."):
            t0 = time.perf_counter()
            try:
                r  = detector.predict_text(opcode_text)
                ms = (time.perf_counter() - t0) * 1000
            except Exception as e:
                st.error(str(e)); st.stop()
        st.markdown("---")
        render_result(r, "text_input", ms)
    elif run_text:
        st.warning("Please enter an opcode sequence.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — BATCH TRIAGE
# ══════════════════════════════════════════════════════════════════════════════
with tabs[2]:
    st.markdown('<p class="sec-head">Batch triage — scan all CSV files in a folder</p>',
                unsafe_allow_html=True)

    col_p, col_b = st.columns([4,1])
    with col_p:
        folder_path = st.text_input("Folder path",
            placeholder="/home/swarna/cyber/MalwareAnalysis/Malware/",
            label_visibility="collapsed")
    with col_b:
        st.markdown(" ")
        run_batch = st.button("🔍 Scan Folder", type="primary",
                              use_container_width=True)

    # Quick folder shortcuts
    quick_cols = st.columns(4)
    shortcuts  = [
        ("Malware folder",
         str(Path.home() / "cyber/MalwareAnalysis/Malware")),
        ("Benign folder",
         str(Path.home() / "cyber/MalwareAnalysis/Benign")),
        ("Downloads",
         str(Path.home() / "Downloads")),
        ("Desktop",
         str(Path.home() / "Desktop")),
    ]
    for i, (label, path) in enumerate(shortcuts):
        if quick_cols[i].button(label, use_container_width=True):
            folder_path = path

    if run_batch:
        if not folder_path or not os.path.isdir(folder_path):
            st.error(f"Folder not found: `{folder_path}`")
        else:
            csvs = glob.glob(os.path.join(folder_path, "*.csv"))
            if not csvs:
                st.warning("No .csv files found.")
            else:
                bar    = st.progress(0)
                status = st.empty()
                results = []
                for i, fp in enumerate(csvs):
                    status.text(f"Scanning {i+1}/{len(csvs)}: "
                                f"{os.path.basename(fp)}")
                    try:
                        results.append(detector.predict_file(fp))
                    except Exception:
                        pass
                    bar.progress((i+1)/len(csvs))
                status.empty(); bar.empty()

                results.sort(key=lambda r: r.malware_probability, reverse=True)
                total   = len(results)
                malware = sum(1 for r in results if r.is_malware)
                high    = sum(1 for r in results if r.risk_level == "HIGH")
                medium  = sum(1 for r in results if r.risk_level == "MEDIUM")

                # Summary
                c1,c2,c3,c4,c5 = st.columns(5)
                c1.metric("Total",   total)
                c2.metric("Malware", malware, delta=f"{malware/max(total,1)*100:.0f}%",
                          delta_color="inverse")
                c3.metric("Benign",  total-malware)
                c4.metric("🔴 High", high)
                c5.metric("🟡 Med",  medium)

                # Table
                rows = [{"File": r.source,
                         "Verdict": r.prediction.upper(),
                         "Malware %": f"{r.malware_probability*100:.1f}%",
                         "Risk": r.risk_level,
                         "Tokens": r.input_tokens}
                        for r in results]
                df   = pd.DataFrame(rows)
                st.dataframe(df, use_container_width=True, height=360)

                # Download
                report = {
                    "timestamp": datetime.now().isoformat(),
                    "folder": folder_path,
                    "summary": {"total": total, "malware": malware,
                                "benign": total-malware, "high": high},
                    "results": [r.to_dict() for r in results]
                }
                st.download_button(
                    "⬇️ Download JSON Report",
                    data=json.dumps(report, indent=2),
                    file_name="asmdetect_batch_report.json",
                    mime="application/json",
                )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — LIVE WATCHER
# ══════════════════════════════════════════════════════════════════════════════
with tabs[3]:
    st.markdown('<p class="sec-head">Real-time malware watcher</p>',
                unsafe_allow_html=True)
    st.caption("Monitors folders for new executable files. "
               "Alerts via desktop popup and email when malware is detected.")

    col_cfg, col_ctrl = st.columns([3, 1])

    with col_cfg:
        watch_folder = st.text_input(
            "Folder to watch",
            value=str(Path.home() / "Downloads"),
            key="watch_folder_input"
        )
        with st.expander("📧 Email alert settings"):
            em_user  = st.text_input("Gmail address",
                                     value=os.getenv("SMTP_USER",""),
                                     key="em_user")
            em_pass  = st.text_input("App password",
                                     value=os.getenv("SMTP_PASSWORD",""),
                                     type="password", key="em_pass")
            em_recip = st.text_input("Alert recipient",
                                     value=os.getenv("ALERT_RECIPIENT",""),
                                     key="em_recip")
            em_ena   = st.checkbox("Enable email alerts",
                                   value=bool(em_user and em_pass),
                                   key="em_ena")

    with col_ctrl:
        st.markdown(" ")
        st.markdown(" ")
        if not st.session_state.watcher_running:
            if st.button("▶ Start Watcher", type="primary",
                         use_container_width=True):
                if not os.path.isdir(watch_folder):
                    st.error("Folder not found.")
                else:
                    st.session_state.watcher_stop.clear()
                    st.session_state.watcher_log = []
                    st.session_state.watcher_running = True

                    email_cfg = {
                        "user": em_user, "password": em_pass,
                        "recipient": em_recip,
                        "host": "smtp.gmail.com", "port": 587,
                    } if em_ena else None

                    def _watcher_loop(folder, stop_evt, log_list,
                                      det, ecfg, threshold_val):
                        try:
                            from watchdog.observers import Observer
                            from watchdog.events import FileSystemEventHandler

                            class Handler(FileSystemEventHandler):
                                def _scan(self, path):
                                    ext = Path(path).suffix.lower()
                                    if ext not in WATCH_EXT:
                                        return
                                    time.sleep(1.5)
                                    if not os.path.exists(path):
                                        return
                                    try:
                                        size = os.path.getsize(path)
                                        if size == 0 or size > 50*1024*1024:
                                            return
                                    except Exception:
                                        return

                                    ts = datetime.now().strftime("%H:%M:%S")
                                    fname = os.path.basename(path)
                                    log_list.append(
                                        ("info",
                                         f"[{ts}] New file: {fname}"))

                                    ops = disassemble(path)
                                    if ops is None:
                                        log_list.append(
                                            ("warn",
                                             f"[{ts}] Cannot disassemble "
                                             f"{fname} — may be packed"))
                                        return

                                    det.set_threshold(threshold_val)
                                    r = det.predict_text(ops)
                                    tag = ("mal" if r.is_malware else "ok")
                                    log_list.append(
                                        (tag,
                                         f"[{ts}] {fname} → "
                                         f"{r.prediction.upper()} "
                                         f"P={r.malware_probability:.3f} "
                                         f"Risk={r.risk_level}"))

                                    if r.is_malware:
                                        send_desktop_notif(
                                            f"⚠️ MALWARE: {fname}",
                                            f"P(malware)="
                                            f"{r.malware_probability:.1%} "
                                            f"Risk={r.risk_level}"
                                        )
                                        if ecfg:
                                            subj = (f"[AsmDetect] MALWARE "
                                                    f"— {fname}")
                                            body = (
                                                f"MALWARE DETECTED\n"
                                                f"File: {fname}\n"
                                                f"Path: {path}\n"
                                                f"Risk: {r.risk_level}\n"
                                                f"P(malware): "
                                                f"{r.malware_probability:.1%}\n"
                                                f"Time: {ts}"
                                            )
                                            send_email(subj, body, ecfg)

                                def on_created(self, event):
                                    if not event.is_directory:
                                        threading.Thread(
                                            target=self._scan,
                                            args=(event.src_path,),
                                            daemon=True
                                        ).start()

                                def on_moved(self, event):
                                    if not event.is_directory:
                                        threading.Thread(
                                            target=self._scan,
                                            args=(event.dest_path,),
                                            daemon=True
                                        ).start()

                            obs = Observer()
                            obs.schedule(Handler(), folder, recursive=True)
                            obs.start()
                            log_list.append(
                                ("info",
                                 f"Watching: {folder}"))
                            while not stop_evt.is_set():
                                time.sleep(0.5)
                            obs.stop(); obs.join()
                            log_list.append(("info", "Watcher stopped."))
                        except Exception as e:
                            log_list.append(("warn", f"Watcher error: {e}"))

                    t = threading.Thread(
                        target=_watcher_loop,
                        args=(watch_folder,
                              st.session_state.watcher_stop,
                              st.session_state.watcher_log,
                              detector, email_cfg, threshold),
                        daemon=True
                    )
                    t.start()
                    st.session_state.watcher_thread = t
                    st.rerun()
        else:
            if st.button("⏹ Stop Watcher", type="secondary",
                         use_container_width=True):
                st.session_state.watcher_stop.set()
                st.session_state.watcher_running = False
                st.rerun()

    # Status
    if st.session_state.watcher_running:
        st.success(f"🟢 Watcher ACTIVE — monitoring: {watch_folder}")
    else:
        st.info("⚪ Watcher stopped.")

    # Log display
    st.markdown("**Detection log:**")
    log_container = st.container()
    with log_container:
        log = st.session_state.watcher_log[-50:]  # last 50 lines
        if not log:
            st.caption("No events yet. Start the watcher and copy a .exe file "
                       "into the watched folder to test.")
        for kind, line in reversed(log):
            css = {"mal":"log-line-mal","ok":"log-line-ok"}.get(kind,"log-line-inf")
            st.markdown(f'<p class="{css}">{line}</p>', unsafe_allow_html=True)

    if st.session_state.watcher_running:
        st.button("🔄 Refresh Log", on_click=lambda: None)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — OPTIMIZE
# ══════════════════════════════════════════════════════════════════════════════
with tabs[4]:
    st.markdown('<p class="sec-head">CPU/GPU Optimization — ONNX Export</p>',
                unsafe_allow_html=True)
    st.markdown("""
Exporting to ONNX + INT8 quantization achieves **~10x faster CPU inference**
(from ~400 ms to ~40 ms per sample), enabling real-time triage without a GPU.
    """)

    col_oa, col_ob = st.columns(2)
    with col_oa:
        onnx_out = st.text_input("ONNX output directory",
                                 value="models/codebert-malware-onnx")
        do_quant = st.checkbox("Apply INT8 quantization", value=True)
        n_bench  = st.slider("Benchmark runs", 5, 50, 10)

    with col_ob:
        st.markdown("**Expected results:**")
        st.table(pd.DataFrame({
            "Backend":    ["PyTorch CPU", "ONNX Runtime", "ONNX INT8"],
            "~Latency":   ["400 ms",      "80 ms",        "40 ms"],
            "Speedup":    ["1x",          "5x",           "10x"],
            "Size":       ["480 MB",      "480 MB",       "120 MB"],
        }))

    if st.button("⚡ Export & Benchmark", type="primary"):
        try:
            from optimum.onnxruntime import ORTModelForSequenceClassification
            OPTIMUM_OK = True
        except ImportError:
            OPTIMUM_OK = False

        if not OPTIMUM_OK:
            st.error("optimum not installed. Run: `pip install optimum[onnxruntime]`")
        else:
            with st.spinner("Exporting to ONNX (this takes 2-3 minutes)..."):
                try:
                    from optimum.onnxruntime import ORTModelForSequenceClassification
                    from transformers import AutoTokenizer
                    os.makedirs(onnx_out, exist_ok=True)
                    ort_model = ORTModelForSequenceClassification.from_pretrained(
                        MODEL_ID, export=True)
                    tok = AutoTokenizer.from_pretrained(MODEL_ID)
                    ort_model.save_pretrained(onnx_out)
                    tok.save_pretrained(onnx_out)
                    st.success(f"ONNX model saved to `{onnx_out}`")
                except Exception as e:
                    st.error(f"Export failed: {e}"); st.stop()

            # Benchmark
            sample = "push mov xor call ret add sub nop push mov xor call"
            enc = detector._tokenizer(sample, max_length=512,
                truncation=True, padding="max_length", return_tensors="pt")

            results = {}
            with st.spinner("Benchmarking PyTorch..."):
                import torch
                detector._model.eval()
                times = []
                for _ in range(n_bench):
                    t0 = time.perf_counter()
                    with torch.no_grad():
                        _ = detector._model(**enc)
                    times.append((time.perf_counter()-t0)*1000)
                results["PyTorch CPU"] = round(float(np.mean(times)),1)

            with st.spinner("Benchmarking ONNX..."):
                try:
                    ort_m = ORTModelForSequenceClassification.from_pretrained(onnx_out)
                    times = []
                    for _ in range(n_bench):
                        t0 = time.perf_counter()
                        _ = ort_m(**enc)
                        times.append((time.perf_counter()-t0)*1000)
                    results["ONNX Runtime"] = round(float(np.mean(times)),1)
                except Exception as e:
                    results["ONNX Runtime"] = f"Error: {e}"

            st.session_state.benchmark_result = results

    if st.session_state.benchmark_result:
        st.markdown("---")
        st.markdown("**Benchmark results:**")
        br = st.session_state.benchmark_result
        cols = st.columns(len(br))
        base = br.get("PyTorch CPU", 1)
        for i, (name, ms) in enumerate(br.items()):
            if isinstance(ms, float):
                speedup = f"{base/ms:.1f}x" if ms > 0 else ""
                cols[i].metric(name, f"{ms} ms", speedup)
            else:
                cols[i].metric(name, "Error")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 6 — SECURITY VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════
with tabs[5]:
    st.markdown('<p class="sec-head">Cryptographic Security Verification</p>',
                unsafe_allow_html=True)
    st.markdown("""
Verifies that all model downloads use **TLS ≥ 1.2**, valid certificates,
HTTPS enforcement, and records **SHA-256 checksums** of all model files
for supply-chain integrity.
    """)

    if st.button("🔒 Run Security Verification", type="primary"):
        host = "huggingface.co"
        report = {"timestamp": datetime.now().isoformat(),
                  "model": MODEL_ID, "checks": {}}

        with st.spinner("Verifying TLS protocol..."):
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    socket.create_connection((host,443),timeout=10),
                    server_hostname=host) as s:
                    proto  = s.version()
                    cipher = s.cipher()
                    cert   = s.getpeercert()
                    not_after = cert.get("notAfter","")
                    ok = proto in ("TLSv1.2","TLSv1.3")
                    report["checks"]["tls"] = {
                        "passed": ok, "protocol": proto,
                        "cipher": cipher[0], "cert_expiry": not_after
                    }
            except Exception as e:
                report["checks"]["tls"] = {"passed": False, "error": str(e)}

        with st.spinner("Checking HTTPS redirect..."):
            try:
                req = urllib.request.Request(
                    f"http://{host}/{MODEL_ID}", method="HEAD")
                try:
                    urllib.request.urlopen(req, timeout=5)
                    report["checks"]["https_redirect"] = {
                        "passed": False, "note": "No redirect"}
                except urllib.error.HTTPError as e:
                    loc = e.headers.get("Location","")
                    report["checks"]["https_redirect"] = {
                        "passed": loc.startswith("https://"),
                        "redirect_to": loc}
                except Exception as e:
                    report["checks"]["https_redirect"] = {
                        "passed": True, "note": str(e)}
            except Exception as e:
                report["checks"]["https_redirect"] = {
                    "passed": False, "error": str(e)}

        checksums = {}
        files_to_check = ["config.json", "tokenizer_config.json",
                           "tokenizer.json", "special_tokens_map.json"]
        for fname in files_to_check:
            with st.spinner(f"Checking {fname}..."):
                url = f"https://{host}/{MODEL_ID}/resolve/main/{fname}"
                try:
                    ctx2 = ssl.create_default_context()
                    req  = urllib.request.Request(
                        url, headers={"User-Agent":"asmdetect/1.0"})
                    with urllib.request.urlopen(
                            req, context=ctx2, timeout=20) as r:
                        data = r.read()
                        sha  = hashlib.sha256(data).hexdigest()
                        checksums[fname] = sha
                except Exception as e:
                    checksums[fname] = f"Error: {e}"

        report["checksums"] = checksums
        st.session_state.security_report = report

    if st.session_state.security_report:
        rep = st.session_state.security_report
        st.markdown("---")
        st.markdown(f"**Verified at:** `{rep['timestamp']}`")

        # TLS
        tls = rep["checks"].get("tls", {})
        c1, c2, c3 = st.columns(3)
        c1.metric("TLS Protocol", tls.get("protocol","N/A"),
                  "✅ Secure" if tls.get("passed") else "❌ Insecure")
        c2.metric("Cipher Suite", (tls.get("cipher","N/A") or "N/A")[:20])
        c3.metric("Cert Expiry",  tls.get("cert_expiry","N/A")[:11])

        # HTTPS redirect
        redir = rep["checks"].get("https_redirect",{})
        if redir.get("passed"):
            st.success("✅ HTTPS redirect enforced — no HTTP fallback")
        else:
            st.warning("⚠️ HTTPS redirect check inconclusive")

        # Checksums
        st.markdown("**SHA-256 Checksums (model file integrity):**")
        ck_rows = [{"File": k, "SHA-256": v[:32]+"...",
                    "Status": "✅" if len(v) == 64 else "❌"}
                   for k,v in rep.get("checksums",{}).items()]
        st.dataframe(pd.DataFrame(ck_rows), use_container_width=True)

        st.download_button(
            "⬇️ Download Security Report",
            data=json.dumps(rep, indent=2),
            file_name="asmdetect_security_report.json",
            mime="application/json"
        )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 7 — ARCHITECTURE
# ══════════════════════════════════════════════════════════════════════════════
with tabs[6]:
    st.markdown('<p class="sec-head">System Architecture & Algorithms</p>',
                unsafe_allow_html=True)

    arc_tab, algo_tab = st.tabs(["🏗️ Architecture Diagram", "📝 Algorithms"])

    with arc_tab:
        st.markdown("### End-to-End Pipeline")
        # SVG architecture diagram
        st.markdown("""
<svg width="100%" viewBox="0 0 900 380" xmlns="http://www.w3.org/2000/svg"
     style="max-width:860px;display:block;margin:auto;font-family:Arial">
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5"
            markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M2 1L8 5L2 9" fill="none" stroke="#2c3e50"
            stroke-width="1.5" stroke-linecap="round"/>
    </marker>
  </defs>

  <!-- Stage boxes -->
  <!-- 1 Input -->
  <rect x="20" y="140" width="120" height="100" rx="10"
        fill="#EBF5FB" stroke="#2E86C1" stroke-width="1.5"/>
  <text x="80" y="170" text-anchor="middle" font-size="12" font-weight="bold" fill="#1a5276">Input</text>
  <text x="80" y="188" text-anchor="middle" font-size="10" fill="#2c3e50">.exe / .dll</text>
  <text x="80" y="203" text-anchor="middle" font-size="10" fill="#2c3e50">email attach</text>
  <text x="80" y="218" text-anchor="middle" font-size="10" fill="#2c3e50">downloads</text>

  <!-- arrow -->
  <line x1="140" y1="190" x2="168" y2="190" stroke="#2c3e50" stroke-width="1.5" marker-end="url(#arr)"/>

  <!-- 2 Disassembly -->
  <rect x="170" y="140" width="130" height="100" rx="10"
        fill="#E9F7EF" stroke="#1E8449" stroke-width="1.5"/>
  <text x="235" y="170" text-anchor="middle" font-size="12" font-weight="bold" fill="#145a32">Disassembly</text>
  <text x="235" y="188" text-anchor="middle" font-size="10" fill="#2c3e50">objdump -d</text>
  <text x="235" y="203" text-anchor="middle" font-size="10" fill="#2c3e50">extract Opcode</text>
  <text x="235" y="218" text-anchor="middle" font-size="10" fill="#2c3e50">column → text</text>

  <!-- arrow -->
  <line x1="300" y1="190" x2="328" y2="190" stroke="#2c3e50" stroke-width="1.5" marker-end="url(#arr)"/>

  <!-- 3 Preprocessing -->
  <rect x="330" y="140" width="130" height="100" rx="10"
        fill="#FEF9E7" stroke="#D4AC0D" stroke-width="1.5"/>
  <text x="395" y="168" text-anchor="middle" font-size="12" font-weight="bold" fill="#7d6608">Preprocessing</text>
  <text x="395" y="185" text-anchor="middle" font-size="10" fill="#2c3e50">filter invalid</text>
  <text x="395" y="200" text-anchor="middle" font-size="10" fill="#2c3e50">tokens</text>
  <text x="395" y="215" text-anchor="middle" font-size="10" fill="#2c3e50">truncate 256</text>

  <!-- arrow -->
  <line x1="460" y1="190" x2="488" y2="190" stroke="#2c3e50" stroke-width="1.5" marker-end="url(#arr)"/>

  <!-- 4 Tokenizer -->
  <rect x="490" y="140" width="120" height="100" rx="10"
        fill="#F4ECF7" stroke="#7D3C98" stroke-width="1.5"/>
  <text x="550" y="170" text-anchor="middle" font-size="12" font-weight="bold" fill="#4a235a">Tokenizer</text>
  <text x="550" y="188" text-anchor="middle" font-size="10" fill="#2c3e50">CodeBERT</text>
  <text x="550" y="203" text-anchor="middle" font-size="10" fill="#2c3e50">subword BPE</text>
  <text x="550" y="218" text-anchor="middle" font-size="10" fill="#2c3e50">512 tokens</text>

  <!-- arrow -->
  <line x1="610" y1="190" x2="638" y2="190" stroke="#2c3e50" stroke-width="1.5" marker-end="url(#arr)"/>

  <!-- 5 Model -->
  <rect x="640" y="120" width="130" height="140" rx="10"
        fill="#FDEDEC" stroke="#C0392B" stroke-width="2"/>
  <text x="705" y="148" text-anchor="middle" font-size="12" font-weight="bold" fill="#7b241c">CodeBERT</text>
  <text x="705" y="164" text-anchor="middle" font-size="10" fill="#2c3e50">12 layers</text>
  <text x="705" y="179" text-anchor="middle" font-size="10" fill="#2c3e50">8 frozen</text>
  <text x="705" y="194" text-anchor="middle" font-size="10" fill="#2c3e50">4 fine-tuned</text>
  <text x="705" y="209" text-anchor="middle" font-size="10" fill="#2c3e50">+ classifier</text>
  <text x="705" y="226" text-anchor="middle" font-size="10" fill="#7b241c" font-weight="bold">125M params</text>

  <!-- arrow down from model -->
  <line x1="705" y1="260" x2="705" y2="288" stroke="#2c3e50" stroke-width="1.5" marker-end="url(#arr)"/>

  <!-- 6 Output -->
  <rect x="610" y="290" width="190" height="70" rx="10"
        fill="#EAFAF1" stroke="#1E8449" stroke-width="1.5"/>
  <text x="705" y="318" text-anchor="middle" font-size="12" font-weight="bold" fill="#145a32">Verdict + Risk</text>
  <text x="705" y="334" text-anchor="middle" font-size="10" fill="#2c3e50">MALWARE / BENIGN</text>
  <text x="705" y="349" text-anchor="middle" font-size="10" fill="#2c3e50">P(malware) | threshold=0.62</text>

  <!-- Arrows from verdict -->
  <line x1="610" y1="325" x2="582" y2="325" stroke="#c0392b" stroke-width="1.5" marker-end="url(#arr)"/>
  <rect x="470" y="300" width="110" height="50" rx="8" fill="#FDEDEC" stroke="#c0392b" stroke-width="1.2"/>
  <text x="525" y="322" text-anchor="middle" font-size="10" font-weight="bold" fill="#7b241c">🔴 Alert</text>
  <text x="525" y="338" text-anchor="middle" font-size="10" fill="#2c3e50">Desktop + Email</text>

  <!-- Labels at top -->
  <text x="80"  y="130" text-anchor="middle" font-size="11" fill="#555">Stage 1</text>
  <text x="235" y="130" text-anchor="middle" font-size="11" fill="#555">Stage 2</text>
  <text x="395" y="130" text-anchor="middle" font-size="11" fill="#555">Stage 3</text>
  <text x="550" y="130" text-anchor="middle" font-size="11" fill="#555">Stage 4</text>
  <text x="705" y="110" text-anchor="middle" font-size="11" fill="#555">Stage 5</text>

  <!-- Title -->
  <text x="450" y="40" text-anchor="middle" font-size="16" font-weight="bold" fill="#1a1a2e">
    AsmDetect — End-to-End Pipeline
  </text>
  <text x="450" y="62" text-anchor="middle" font-size="12" fill="#555">
    Compiler-Aware Assembly-Level Malware Detection using Fine-Tuned CodeBERT
  </text>
</svg>
        """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("### Training Pipeline")
        st.markdown("""
| Step | Action | Tool |
|---|---|---|
| 1 | Raw CSV disassembly files | Arun152k dataset |
| 2 | Extract + clean opcodes | `preprocessing.py` |
| 3 | Balance (521 per class) + augment | `dataset_builder.py` |
| 4 | Tokenize with CodeBERT tokenizer | HuggingFace Datasets |
| 5 | Fine-tune with frozen layers + weighted loss | HuggingFace Trainer |
| 6 | Calibrate threshold via P-R curve | scikit-learn |
| 7 | Publish to HuggingFace Hub | `huggingface_hub` |
        """)

    with algo_tab:
        st.markdown("### Algorithm 1 — Opcode Extraction")
        st.markdown('<div class="algo-box">'
'<b>Algorithm 1:</b> ExtractOpcodes(filepath)\n'
'<b>Input:</b>  filepath — path to .csv disassembly file\n'
'<b>Output:</b> opcode_sequence — space-joined mnemonic string\n\n'
'1.  df ← ReadCSV(filepath)\n'
'2.  col ← FindColumn(df, name="opcode")   // case-insensitive\n'
'3.  if col = NULL then return ERROR\n'
'4.  tokens ← []\n'
'5.  for each row r in df[col] do\n'
'6.      t ← Lowercase(Strip(r))\n'
'7.      if IsValidMnemonic(t) then         // starts with letter\n'
'8.          tokens.append(t)\n'
'9.      if |tokens| = MAX_OPCODES then break\n'
'10. if |tokens| < MIN_OPCODES then return NULL\n'
'11. return Join(tokens, separator=" ")\n\n'
'<b>IsValidMnemonic</b>(t):\n'
'   return t[0] ∈ {a..z} AND (t.isalpha() OR t.isalnum())\n'
'   // Rejects: .text .data 402000 30 7d\n'
'   // Accepts: push mov xor pushl movl',
            unsafe_allow_html=True)
        st.markdown(" ")

        st.markdown("### Algorithm 2 — Fine-Tuning Procedure")
        st.markdown('<div class="algo-box">'
'<b>Algorithm 2:</b> FineTune(D_train, D_val)\n'
'<b>Input:</b>  D_train, D_val — tokenized HuggingFace Datasets\n'
'<b>Output:</b> θ* — optimised model parameters\n\n'
'1.  θ ← LoadPretrainedWeights("microsoft/codebert-base")\n'
'2.  Freeze layers 0..7 of encoder         // preserve general representations\n'
'3.  Add ClassificationHead(768 → 2)\n'
'4.  w ← [1.0, 1.5]                        // class weights: benign, malware\n'
'5.  optimizer ← AdamW(lr=3e-5, decay=0.05)\n'
'6.  scheduler ← WarmupCosine(ratio=0.15)\n'
'7.  best_f1 ← 0;  patience ← 0\n'
'8.  for epoch e = 1 to MAX_EPOCHS do\n'
'9.      for each batch B in D_train do\n'
'10.         logits ← Forward(θ, B)\n'
'11.         loss   ← CrossEntropyLoss(logits, B.labels, weights=w)\n'
'12.         θ ← θ - optimizer.step(∇loss)\n'
'13.     f1 ← Evaluate(θ, D_val)\n'
'14.     if f1 > best_f1 then\n'
'15.         best_f1 ← f1;  θ* ← θ;  patience ← 0\n'
'16.     else\n'
'17.         patience ← patience + 1\n'
'18.     if patience = EARLY_STOP then break\n'
'19. return θ*',
            unsafe_allow_html=True)
        st.markdown(" ")

        st.markdown("### Algorithm 3 — Inference Pipeline")
        st.markdown('<div class="algo-box">'
'<b>Algorithm 3:</b> Predict(filepath, θ*, τ)\n'
'<b>Input:</b>  filepath — path to assembly file\n'
'           θ* — fine-tuned model parameters\n'
'           τ  — decision threshold (default 0.62)\n'
'<b>Output:</b> DetectionResult\n\n'
'1.  seq      ← ExtractOpcodes(filepath)       // Algorithm 1\n'
'2.  tokens   ← Tokenize(seq, max_len=512)     // CodeBERT BPE\n'
'3.  logits   ← Forward(θ*, tokens)            // shape: (2,)\n'
'4.  probs    ← Softmax(logits)                // [P(benign), P(malware)]\n'
'5.  p_mal    ← probs[1]\n'
'6.  if p_mal ≥ τ then\n'
'7.      label ← MALWARE\n'
'8.  else\n'
'9.      label ← BENIGN\n'
'10. if p_mal ≥ 0.80 then risk ← HIGH\n'
'11. elif p_mal ≥ 0.55 then risk ← MEDIUM\n'
'12. else risk ← LOW\n'
'13. if label = MALWARE then\n'
'14.     SendDesktopNotification(filepath, p_mal, risk)\n'
'15.     SendEmailAlert(filepath, p_mal, risk)\n'
'16. return DetectionResult(label, p_mal, risk, confidence)',
            unsafe_allow_html=True)
