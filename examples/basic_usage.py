"""
examples/basic_usage.py
-----------------------
Demonstrates all three prediction modes of the asmdetect library.
Loads Swarnadharshini/codebert-malware-detector from HuggingFace.

Run:
    python examples/basic_usage.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asmdetect import MalwareDetector

# ── 1. Load the model ─────────────────────────────────────────────────────────
detector = MalwareDetector.from_pretrained()
# Equivalent to:
# detector = MalwareDetector.from_pretrained("Swarnadharshini/codebert-malware-detector")

print("=" * 55)
print("  asmdetect — Basic Usage Examples")
print("=" * 55)

# ── 2. predict_text — raw opcode string ──────────────────────────────────────
print("\n[1] predict_text — malware-like opcodes")
result = detector.predict_text(
    "xor xor push push call mov xor add sub push call "
    "mov xor nop ret jmp xor call push mov lea ret nop"
)
print(result)

print("\n[2] predict_text — benign-like opcodes")
result = detector.predict_text(
    "push mov sub mov call mov add pop ret "
    "sub lea push call add mov ret mov push call ret"
)
print(result)

# ── 3. is_malware / is_benign properties ─────────────────────────────────────
print("\n[3] Using result properties")
result = detector.predict_text("push mov xor call ret")
if result.is_malware:
    print(f"  ALERT: {result.source} is malware! "
          f"Risk={result.risk_level}, P={result.malware_probability:.2%}")
else:
    print(f"  OK: {result.source} appears benign. "
          f"P(benign)={result.benign_probability:.2%}")

# ── 4. to_dict / to_json ──────────────────────────────────────────────────────
print("\n[4] JSON output (for SIEM/SOAR integration)")
import json
result = detector.predict_text("mov push call xor ret")
print(result.to_json())

# ── 5. Threshold tuning ───────────────────────────────────────────────────────
print("\n[5] Threshold tuning")
seq = "push mov xor call ret add xor push nop"

detector.set_threshold(0.40)   # sensitive — catch more
r_sensitive = detector.predict_text(seq)

detector.set_threshold(0.80)   # specific  — fewer alarms
r_specific  = detector.predict_text(seq)

print(f"  threshold=0.40 → {r_sensitive.prediction}  (P={r_sensitive.malware_probability:.2%})")
print(f"  threshold=0.80 → {r_specific.prediction}   (P={r_specific.malware_probability:.2%})")

detector.set_threshold(0.62)   # reset to default

# ── 6. Benchmark ──────────────────────────────────────────────────────────────
print("\n[6] Inference latency benchmark (5 runs)")
bench = detector.benchmark(n=5)
print(f"  mean={bench['mean_ms']} ms  "
      f"min={bench['min_ms']} ms  "
      f"max={bench['max_ms']} ms")
