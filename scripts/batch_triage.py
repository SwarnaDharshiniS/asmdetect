"""
scripts/batch_triage.py
-----------------------
SOC batch triage script.
Scans a folder of .csv assembly files and produces a triage report
sorted by malware probability.

Usage
-----
    python scripts/batch_triage.py --folder /soc/incoming/
    python scripts/batch_triage.py --folder /soc/incoming/ --report report.json
    python scripts/batch_triage.py --folder /soc/incoming/ --threshold 0.70
"""

import argparse
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asmdetect import MalwareDetector


def main():
    parser = argparse.ArgumentParser(description="SOC batch triage using asmdetect")
    parser.add_argument("--folder",    required=True, help="Folder of .csv assembly files")
    parser.add_argument("--threshold", type=float, default=0.62, help="Decision threshold")
    parser.add_argument("--report",    type=str,   default=None,
                        help="Save JSON report to this path (optional)")
    args = parser.parse_args()

    print(f"\nasmdetect — SOC Batch Triage")
    print(f"Model     : Swarnadharshini/codebert-malware-detector")
    print(f"Folder    : {args.folder}")
    print(f"Threshold : {args.threshold}")
    print()

    detector = MalwareDetector.from_pretrained(threshold=args.threshold)
    results  = detector.predict_batch(args.folder)

    # ── Summary ───────────────────────────────────────────────────────────
    total   = len(results)
    malware = [r for r in results if r.is_malware]
    benign  = [r for r in results if r.is_benign]
    high    = [r for r in results if r.risk_level == "HIGH"]
    medium  = [r for r in results if r.risk_level == "MEDIUM"]
    errors  = [r for r in results if r.prediction == "error"]

    print(f"{'='*55}")
    print(f"  TRIAGE REPORT — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*55}")
    print(f"  Total scanned : {total}")
    print(f"  Malware       : {len(malware)}  ({len(malware)/max(total,1)*100:.1f}%)")
    print(f"  Benign        : {len(benign)}  ({len(benign)/max(total,1)*100:.1f}%)")
    print(f"  High risk     : {len(high)}")
    print(f"  Medium risk   : {len(medium)}")
    print(f"  Errors        : {len(errors)}")
    print(f"{'='*55}")

    if high:
        print(f"\n  [HIGH RISK — Immediate attention required]")
        for r in high:
            print(f"    {r.malware_probability*100:5.1f}%  {r.source}")

    if medium:
        print(f"\n  [MEDIUM RISK — Review recommended]")
        for r in medium:
            print(f"    {r.malware_probability*100:5.1f}%  {r.source}")

    # ── Save report ───────────────────────────────────────────────────────
    if args.report:
        report = {
            "timestamp"  : datetime.now().isoformat(),
            "model"      : "Swarnadharshini/codebert-malware-detector",
            "folder"     : args.folder,
            "threshold"  : args.threshold,
            "summary"    : {
                "total": total, "malware": len(malware),
                "benign": len(benign), "high": len(high),
                "medium": len(medium), "errors": len(errors),
            },
            "results"    : [r.to_dict() for r in results],
        }
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  Report saved: {args.report}")


if __name__ == "__main__":
    main()
