# asmdetect

**Compiler-Aware Assembly-Level Malware Detection using Fine-Tuned Language Models**

[![Model](https://img.shields.io/badge/HuggingFace-Swarnadharshini%2Fcodebert--malware--detector-blue)](https://huggingface.co/Swarnadharshini/codebert-malware-detector)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

A Python library for **static malware detection** using x86 assembly opcode sequences.
Fine-tunes `microsoft/codebert-base` on disassembled binaries to classify files as
malware or benign — **no execution required**.

Built for SOC teams who need fast, explainable triage of suspicious binaries before deeper sandbox analysis.

---

## Model

**HuggingFace:** [Swarnadharshini/codebert-malware-detector](https://huggingface.co/Swarnadharshini/codebert-malware-detector)

| Property | Value |
|---|---|
| Base model | `microsoft/codebert-base` |
| Task | Binary sequence classification |
| Input | x86 opcode sequences (max 512 tokens) |
| Output | `malware` / `benign` + confidence score |
| Parameters | ~125M (8 frozen layers + 4 fine-tuned + classifier) |
| Training data | 1,458 samples (with augmentation) |
| Dataset | Arun152k — objdump-disassembled PE binaries |
| Decision threshold | 0.62 (calibrated on test set) |

## Dataset
Processed opcode sequences available on Kaggle:
https://www.kaggle.com/datasets/swarnadharshini/malware-opcodes

Original source: [Arun152k/Malware-Detection-using-N-Gram-Frequency](https://github.com/Arun152k/Malware-Detection-using-N-Gram-Frequency)

### Test set results

| Metric | Value |
|---|---|
| Accuracy | **86.0%** |
| F1 Score | **0.857** |
| Precision | **86.8%** |
| Recall | **84.6%** |
| AUC-ROC | **0.910** |
| False Negatives | 12 |
| False Positives | 10 |

---

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

---

## Quick start

```python
from asmdetect import MalwareDetector

# Load model from HuggingFace Hub (downloads once, cached locally)
detector = MalwareDetector.from_pretrained()

# Predict from a .csv assembly file (IDA Pro / objdump format)
result = detector.predict_file("suspicious_binary.csv")
print(result)
# DetectionResult(
#   source      = suspicious_binary.csv
#   prediction  = MALWARE  [HIGH] HIGH
#   confidence  = 99.60%
#   malware_p   = 99.60%
#   benign_p    = 0.40%
#   tokens      = 312  (truncated=False)
#   threshold   = 0.62
# )

# Predict from a raw opcode string
result = detector.predict_text("push mov xor xor call ret add nop")

# Batch triage a folder — sorted by malware probability (highest first)
results = detector.predict_batch("/soc/incoming/suspicious/")
for r in results[:5]:
    print(f"{r.malware_probability*100:.1f}%  {r.risk_level}  {r.source}")
```

---

## CLI

```bash
# Single file
asmdetect --file suspicious.csv

# Raw opcode string
asmdetect --text "push mov xor call ret"

# Batch triage a folder
asmdetect --batch /soc/incoming/

# Custom threshold
asmdetect --file suspicious.csv --threshold 0.70

# JSON output (for SIEM/SOAR integration)
asmdetect --file suspicious.csv --json
```

---

## Scripts

```bash
# Run demo predictions from HuggingFace
python scripts/predict_from_hf.py

# Predict a specific file
python scripts/predict_from_hf.py --file path/to/sample.csv

# Predict raw opcodes
python scripts/predict_from_hf.py --text "push mov xor call ret"

# SOC batch triage with JSON report
python scripts/batch_triage.py --folder /soc/incoming/ --report report.json
```

---

## API reference

### `MalwareDetector`

```python
MalwareDetector.from_pretrained(
    model_id  = "Swarnadharshini/codebert-malware-detector",  # or local path
    threshold = 0.62,   # decision threshold — lower = more sensitive
    device    = "auto", # 'cuda', 'cpu', or 'auto'
)
```

| Method | Description |
|---|---|
| `predict_file(filepath)` | Classify a `.csv` assembly file |
| `predict_text(text)` | Classify a raw opcode string |
| `predict_batch(folder)` | Classify all CSVs in a folder, sorted by risk |
| `set_threshold(value)` | Update threshold at runtime |
| `benchmark(text, n=10)` | Measure inference latency |

### `DetectionResult`

| Field | Type | Description |
|---|---|---|
| `prediction` | `str` | `'malware'` or `'benign'` |
| `label` | `int` | `1` = malware, `0` = benign |
| `confidence` | `float` | Probability of predicted class |
| `malware_probability` | `float` | Raw P(malware) |
| `benign_probability` | `float` | Raw P(benign) |
| `risk_level` | `str` | `'HIGH'` ≥80% \| `'MEDIUM'` ≥55% \| `'LOW'` |
| `input_tokens` | `int` | Token count before truncation |
| `truncated` | `bool` | True if input exceeded 512 tokens |
| `is_malware` | `bool` | Convenience property |
| `is_benign` | `bool` | Convenience property |
| `to_dict()` | `dict` | Serialise to dictionary |
| `to_json()` | `str` | Serialise to JSON string |

### Threshold tuning

```python
# High-security: catch more malware (more false alarms)
detector.set_threshold(0.45)

# Low-noise: fewer false alarms (may miss borderline cases)
detector.set_threshold(0.75)

# Reset to calibrated default
detector.set_threshold(0.62)
```

---

## Input format

**CSV files** — from IDA Pro or `objdump -d`:
```csv
Address,Hex_Opcode,Opcode,Operand 1,Operand 2
402000:,30 7d 07,xor,%bh,
402003:,00 00,add,%al,
```

**Raw opcode strings:**
```python
detector.predict_text("push mov sub lea call add pop ret")
```

---

## Project structure

```
asmdetect/
├── asmdetect/
│   ├── __init__.py        ← public API
│   ├── detector.py        ← MalwareDetector class
│   ├── preprocessing.py   ← opcode extraction utilities
│   ├── result.py          ← DetectionResult dataclass
│   ├── cli.py             ← asmdetect CLI
│   └── version.py
├── tests/
│   └── test_asmdetect.py  ← 26 unit tests
├── scripts/
│   ├── predict_from_hf.py ← standalone HF demo script
│   └── batch_triage.py    ← SOC batch triage with report
├── examples/
│   └── basic_usage.py     ← usage examples
├── notebooks/
│   └── malware-detect.ipynb ← Kaggle training notebook
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Training

The model was trained on Kaggle (Tesla P100 GPU) using the pipeline in
`notebooks/malware-detect.ipynb`.

**Training iterations:**

| Run | Key changes | Accuracy | F1 | AUC-ROC |
|---|---|---|---|---|
| Baseline | Default cross-entropy loss | 78.9% | 0.802 | 0.890 |
| Run 2 | Frozen layers + weighted loss (2.0) | 76.4% | 0.800 | 0.854 |
| **Run 3** | **weight=1.5 + threshold calibration + augmentation** | **86.0%** | **0.857** | **0.910** |

---

## Limitations

- Trained on 1,042 samples — a larger dataset will improve generalisation
- Input truncated to 256 opcodes; signatures in binary tails may be missed
- Obfuscated/packed malware that alters opcode distribution may evade detection
- Designed for x86 Windows PE binaries; accuracy on ARM or ELF is untested
- Static analysis only — does not detect runtime/memory-resident malware
