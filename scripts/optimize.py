"""
scripts/optimize.py
-------------------
Exports the fine-tuned CodeBERT model to ONNX format and applies
INT8 quantization for fast CPU inference (~10x speedup).

Before : ~400ms per sample (PyTorch CPU)
After  : ~40ms  per sample (ONNX INT8 quantized)

Usage:
    pip install optimum[onnxruntime] onnx onnxruntime
    python scripts/optimize.py
    python scripts/optimize.py --model /local/model/dir
    python scripts/optimize.py --benchmark   # compare PyTorch vs ONNX speed
"""

import os
import sys
import time
import argparse
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODEL_ID   = "Swarnadharshini/codebert-malware-detector"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "models", "codebert-malware-onnx")

SAMPLE_OPCODES = (
    "push mov sub lea call add pop ret push mov xor call ret "
    "add sub push mov lea call ret nop push mov sub lea call"
)


def export_to_onnx(model_id: str, output_dir: str):
    """Export HuggingFace model to ONNX using optimum."""
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        from transformers import AutoTokenizer
    except ImportError:
        print("ERROR: Install with: pip install optimum[onnxruntime] onnxruntime")
        sys.exit(1)

    print(f"\n{'='*55}")
    print("  STEP 1: Exporting model to ONNX")
    print(f"{'='*55}")
    print(f"  Source : {model_id}")
    print(f"  Output : {output_dir}")

    os.makedirs(output_dir, exist_ok=True)

    print("\n  Downloading and converting...")
    model = ORTModelForSequenceClassification.from_pretrained(
        model_id,
        export=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(model_id)

    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"  ONNX model saved to: {output_dir}")

    onnx_path = os.path.join(output_dir, "model.onnx")
    if os.path.exists(onnx_path):
        size_mb = os.path.getsize(onnx_path) / 1e6
        print(f"  ONNX model size: {size_mb:.1f} MB")

    return model, tokenizer, output_dir


def quantize_model(onnx_dir: str):
    """Apply INT8 static quantization to further reduce size and latency."""
    try:
        from optimum.onnxruntime import ORTQuantizer
        from optimum.onnxruntime.configuration import AutoQuantizationConfig
    except ImportError:
        print("WARNING: Quantization requires: pip install optimum[onnxruntime]")
        return None

    print(f"\n{'='*55}")
    print("  STEP 2: Applying INT8 Quantization")
    print(f"{'='*55}")

    quantized_dir = onnx_dir + "-quantized"
    os.makedirs(quantized_dir, exist_ok=True)

    quantizer = ORTQuantizer.from_pretrained(onnx_dir)
    qconfig   = AutoQuantizationConfig.avx512_vnni(
        is_static=False,   # dynamic quantization (no calibration data needed)
        per_channel=False,
    )

    print("  Quantizing weights to INT8...")
    quantizer.quantize(
        save_dir           = quantized_dir,
        quantization_config= qconfig,
    )

    q_path = os.path.join(quantized_dir, "model_quantized.onnx")
    if os.path.exists(q_path):
        size_mb = os.path.getsize(q_path) / 1e6
        print(f"  Quantized model saved: {quantized_dir}")
        print(f"  Quantized model size : {size_mb:.1f} MB")
    else:
        print(f"  Quantized model saved: {quantized_dir}")

    return quantized_dir


def benchmark(model_id: str, onnx_dir: str, n: int = 20):
    """Compare PyTorch vs ONNX inference speed."""
    print(f"\n{'='*55}")
    print(f"  STEP 3: Benchmark  (n={n} runs)")
    print(f"{'='*55}")

    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_id)

    encoding = tokenizer(
        SAMPLE_OPCODES,
        max_length=512, truncation=True,
        padding="max_length", return_tensors="pt"
    )

    # ── PyTorch ──────────────────────────────────────────────────────────
    print("\n  [1] PyTorch CPU inference:")
    try:
        import torch
        from transformers import AutoModelForSequenceClassification
        pt_model = AutoModelForSequenceClassification.from_pretrained(model_id)
        pt_model.eval()

        # Warm-up
        with torch.no_grad():
            _ = pt_model(**encoding)

        times = []
        for _ in range(n):
            t0 = time.perf_counter()
            with torch.no_grad():
                _ = pt_model(**encoding)
            times.append((time.perf_counter() - t0) * 1000)

        pt_mean = np.mean(times)
        print(f"     Mean : {pt_mean:.1f} ms")
        print(f"     Min  : {np.min(times):.1f} ms")
        print(f"     Max  : {np.max(times):.1f} ms")
    except Exception as e:
        print(f"     PyTorch benchmark failed: {e}")
        pt_mean = None

    # ── ONNX ─────────────────────────────────────────────────────────────
    print("\n  [2] ONNX Runtime inference:")
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        ort_model = ORTModelForSequenceClassification.from_pretrained(onnx_dir)

        enc_np = {k: v.numpy() for k, v in encoding.items()}

        # Warm-up
        _ = ort_model(**encoding)

        times = []
        for _ in range(n):
            t0 = time.perf_counter()
            _ = ort_model(**encoding)
            times.append((time.perf_counter() - t0) * 1000)

        ort_mean = np.mean(times)
        print(f"     Mean : {ort_mean:.1f} ms")
        print(f"     Min  : {np.min(times):.1f} ms")
        print(f"     Max  : {np.max(times):.1f} ms")
    except Exception as e:
        print(f"     ONNX benchmark failed: {e}")
        ort_mean = None

    # ── Quantized ONNX ────────────────────────────────────────────────────
    quantized_dir = onnx_dir + "-quantized"
    if os.path.exists(quantized_dir):
        print("\n  [3] Quantized ONNX Runtime inference:")
        try:
            from optimum.onnxruntime import ORTModelForSequenceClassification
            q_model = ORTModelForSequenceClassification.from_pretrained(
                quantized_dir, file_name="model_quantized.onnx"
            )
            _ = q_model(**encoding)
            times = []
            for _ in range(n):
                t0 = time.perf_counter()
                _ = q_model(**encoding)
                times.append((time.perf_counter() - t0) * 1000)
            q_mean = np.mean(times)
            print(f"     Mean : {q_mean:.1f} ms")
            print(f"     Min  : {np.min(times):.1f} ms")
            print(f"     Max  : {np.max(times):.1f} ms")
        except Exception as e:
            print(f"     Quantized benchmark failed: {e}")
            q_mean = None
    else:
        q_mean = None

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'─'*55}")
    print("  BENCHMARK SUMMARY")
    print(f"{'─'*55}")
    if pt_mean:  print(f"  PyTorch CPU      : {pt_mean:6.1f} ms  (baseline)")
    if ort_mean: print(f"  ONNX Runtime     : {ort_mean:6.1f} ms  "
                       f"({pt_mean/ort_mean:.1f}x faster)" if pt_mean else "")
    if q_mean:   print(f"  ONNX INT8 Quant  : {q_mean:6.1f} ms  "
                       f"({pt_mean/q_mean:.1f}x faster)" if pt_mean else "")
    print(f"{'─'*55}")


def main():
    parser = argparse.ArgumentParser(description="Export asmdetect model to ONNX")
    parser.add_argument("--model",     default=MODEL_ID,   help="Model ID or local path")
    parser.add_argument("--output",    default=OUTPUT_DIR,  help="Output directory")
    parser.add_argument("--benchmark", action="store_true", help="Run speed benchmark after export")
    parser.add_argument("--skip-export", action="store_true",
                        help="Skip export (benchmark existing ONNX only)")
    args = parser.parse_args()

    if not args.skip_export:
        export_to_onnx(args.model, args.output)
        quantize_model(args.output)
    else:
        print(f"Skipping export. Using existing ONNX at: {args.output}")

    if args.benchmark:
        benchmark(args.model, args.output)

    print(f"\n{'='*55}")
    print("  DONE")
    print(f"{'='*55}")
    print(f"  ONNX model     : {args.output}")
    print(f"  Quantized      : {args.output}-quantized")
    print()
    print("  To use ONNX in asmdetect:")
    print(f"    detector = MalwareDetector.from_pretrained(")
    print(f"        \"{args.output}\",")
    print(f"        use_onnx=True")
    print(f"    )")
    print()


if __name__ == "__main__":
    main()
