"""
scripts/predict_from_hf.py
--------------------------
Standalone script to load Swarnadharshini/codebert-malware-detector
from HuggingFace and run predictions.

No installation needed — just run directly:
    python scripts/predict_from_hf.py

Or with a custom CSV file:
    python scripts/predict_from_hf.py --file path/to/sample.csv

Or with a raw opcode string:
    python scripts/predict_from_hf.py --text "push mov xor call ret"

Or batch-predict a folder:
    python scripts/predict_from_hf.py --batch path/to/folder/
"""

import argparse
import json
import sys
import os

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asmdetect import MalwareDetector


MODEL_ID  = "Swarnadharshini/codebert-malware-detector"
THRESHOLD = 0.62


def main():
    parser = argparse.ArgumentParser(
        description=f"Test {MODEL_ID} from HuggingFace Hub"
    )
    parser.add_argument("--file",      type=str, help="Path to .csv assembly file")
    parser.add_argument("--text",      type=str, help="Raw opcode sequence string")
    parser.add_argument("--batch",     type=str, help="Path to folder of .csv files")
    parser.add_argument("--threshold", type=float, default=THRESHOLD)
    parser.add_argument("--json",      action="store_true", help="Print raw JSON")
    args = parser.parse_args()

    print(f"\nLoading {MODEL_ID} ...")
    detector = MalwareDetector.from_pretrained(
        model_id  = MODEL_ID,
        threshold = args.threshold,
    )

    # ── Single file ───────────────────────────────────────────────────────
    if args.file:
        result = detector.predict_file(args.file)
        if args.json:
            print(result.to_json())
        else:
            print(result)

    # ── Raw text ──────────────────────────────────────────────────────────
    elif args.text:
        result = detector.predict_text(args.text)
        if args.json:
            print(result.to_json())
        else:
            print(result)

    # ── Batch ─────────────────────────────────────────────────────────────
    elif args.batch:
        results = detector.predict_batch(args.batch)
        if args.json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            for r in results:
                print(r)
            malware = sum(1 for r in results if r.is_malware)
            print(f"\nSummary: {malware}/{len(results)} files flagged as malware")

    # ── Demo mode (no args) ───────────────────────────────────────────────
    else:
        print("\nRunning built-in demo predictions...\n")

        test_cases = [
            ("Malware-like (xor-heavy)",
             "xor xor push push call mov mov xor add sub push call mov xor "
             "push push call mov xor nop ret jmp jmp xor call push mov lea "
             "push call mov xor xor add push ret call nop"),

            ("Benign-like (structured calls)",
             "push mov sub mov mov call mov add pop ret push mov "
             "sub lea push call add mov mov ret push mov sub lea "
             "call add pop ret mov push sub mov call add ret"),

            ("Mixed/ambiguous",
             "push mov xor call ret add sub push mov xor nop call "
             "ret push lea sub add xor mov push call ret nop"),
        ]

        for name, opcodes in test_cases:
            result = detector.predict_text(opcodes)
            icon   = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(result.risk_level, "")
            print(f"  {name}")
            print(f"    Verdict    : {result.prediction.upper()}  {icon} {result.risk_level}")
            print(f"    Malware P  : {result.malware_probability * 100:.1f}%")
            print(f"    Confidence : {result.confidence * 100:.1f}%")
            print()

        # Benchmark
        bench = detector.benchmark(n=5)
        print(f"  Inference latency: {bench['mean_ms']:.0f} ms avg  "
              f"(min={bench['min_ms']:.0f}  max={bench['max_ms']:.0f})")


if __name__ == "__main__":
    main()
