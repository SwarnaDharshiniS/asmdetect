"""
cli.py
------
Command-line interface for asmdetect.
Installed as the 'asmdetect' command via pyproject.toml [project.scripts].

Usage
-----
    asmdetect --file sample.csv
    asmdetect --text "push mov xor call ret"
    asmdetect --batch /soc/incoming/
    asmdetect --file sample.csv --threshold 0.70
    asmdetect --file sample.csv --json
    asmdetect --version
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from .detector import MalwareDetector, DEFAULT_MODEL_ID, DEFAULT_THRESHOLD
from .result   import DetectionResult
from .version  import __version__

_RISK_ICONS = {"HIGH": "[HIGH]", "MEDIUM": "[MED] ", "LOW": "[LOW] "}


def _print_result(result: DetectionResult, use_json: bool = False) -> None:
    if use_json:
        print(result.to_json())
        return
    icon = _RISK_ICONS.get(result.risk_level, "")
    print(f"\n  {'─'*46}")
    print(f"  File        : {result.source}")
    print(f"  Verdict     : {result.prediction.upper()}  {icon}")
    print(f"  Confidence  : {result.confidence * 100:.2f}%")
    print(f"  Malware P   : {result.malware_probability * 100:.2f}%")
    print(f"  Benign  P   : {result.benign_probability  * 100:.2f}%")
    print(f"  Tokens      : {result.input_tokens}  (truncated={result.truncated})")
    print(f"  Threshold   : {result.threshold_used}")
    print(f"  {'─'*46}")


def _print_batch_summary(results: list[DetectionResult]) -> None:
    total   = len(results)
    malware = sum(1 for r in results if r.prediction == "malware")
    high    = sum(1 for r in results if r.risk_level  == "HIGH")
    errors  = sum(1 for r in results if r.prediction  == "error")

    print(f"\n  {'='*46}")
    print(f"  BATCH SUMMARY")
    print(f"  {'='*46}")
    print(f"  Total files   : {total}")
    print(f"  Malware       : {malware}  ({malware / max(total, 1) * 100:.1f}%)")
    print(f"  Benign        : {total - malware - errors}")
    print(f"  High risk     : {high}")
    print(f"  Errors        : {errors}")
    print(f"  {'='*46}")
    if results:
        print(f"\n  Top 5 highest-risk files:")
        for r in results[:5]:
            if r.prediction != "error":
                print(f"    {r.malware_probability * 100:5.1f}%  {r.source}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog        = "asmdetect",
        description = "Assembly-Level Malware Detector — SOC triage tool\n"
                      f"Model: {DEFAULT_MODEL_ID}",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
examples:
  asmdetect --file suspicious.csv
  asmdetect --text "push mov xor call ret add"
  asmdetect --batch /soc/incoming/
  asmdetect --file suspicious.csv --threshold 0.70
  asmdetect --file suspicious.csv --json
        """,
    )

    parser.add_argument("--file",      type=str,   help="Path to a single .csv assembly file")
    parser.add_argument("--text",      type=str,   help="Raw opcode sequence string")
    parser.add_argument("--batch",     type=str,   help="Path to folder of .csv files")
    parser.add_argument("--model",     type=str,   default=DEFAULT_MODEL_ID,
                        help=f"HuggingFace model ID or local path  [default: {DEFAULT_MODEL_ID}]")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Decision threshold 0–1  [default: {DEFAULT_THRESHOLD}]")
    parser.add_argument("--json",      action="store_true", help="Output raw JSON")
    parser.add_argument("--version",   action="version",
                        version=f"asmdetect {__version__} | model: {DEFAULT_MODEL_ID}")

    args = parser.parse_args()

    if not any([args.file, args.text, args.batch]):
        parser.print_help()
        sys.exit(0)

    print(f"asmdetect v{__version__}")
    detector = MalwareDetector.from_pretrained(
        model_id  = args.model,
        threshold = args.threshold,
    )

    t0 = time.perf_counter()

    if args.file:
        result = detector.predict_file(args.file)
        _print_result(result, use_json=args.json)

    elif args.text:
        result = detector.predict_text(args.text)
        _print_result(result, use_json=args.json)

    elif args.batch:
        results = detector.predict_batch(args.batch)
        if args.json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            for r in results:
                _print_result(r)
            _print_batch_summary(results)

    if not args.json:
        print(f"\n  Inference time: {(time.perf_counter() - t0) * 1000:.0f} ms")


if __name__ == "__main__":
    main()
