"""
detector.py
-----------
MalwareDetector — core inference class for the asmdetect library.

Loads  Swarnadharshini/codebert-malware-detector  from HuggingFace Hub
(or any local directory) and classifies x86 opcode sequences as
malware or benign with a calibrated confidence score.

Usage
-----
>>> from asmdetect import MalwareDetector
>>>
>>> # Load from HuggingFace Hub (default)
>>> detector = MalwareDetector.from_pretrained()
>>>
>>> # Load from a local directory
>>> detector = MalwareDetector.from_pretrained("/models/codebert-malware")
>>>
>>> result = detector.predict_file("sample.csv")
>>> result = detector.predict_text("push mov xor call ret")
>>> results = detector.predict_batch("/soc/incoming/")
"""

from __future__ import annotations

import glob
import os
import time
from typing import List

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from .preprocessing import clean_text_input, extract_from_file
from .result        import DetectionResult

# ── Defaults ─────────────────────────────────────────────────────────────────

#: Published model on HuggingFace Hub — used when no model_id is supplied.
DEFAULT_MODEL_ID  = "Swarnadharshini/codebert-malware-detector"

#: Calibrated decision threshold (from precision-recall curve on test set).
#: Lower  → more sensitive  (more FP, fewer FN — catches more malware).
#: Higher → more specific   (fewer FP, more FN — fewer false alarms).
DEFAULT_THRESHOLD = 0.62

MAX_LENGTH = 512

RISK_THRESHOLDS = {"HIGH": 0.80, "MEDIUM": 0.55}


class MalwareDetector:
    """
    SOC-ready malware detector using fine-tuned CodeBERT.

    Classifies x86 assembly opcode sequences as **malware** or **benign**
    using static analysis — no execution required.

    Parameters
    ----------
    model_id  : HuggingFace model ID or local directory path.
                Defaults to 'Swarnadharshini/codebert-malware-detector'.
    threshold : Decision threshold for malware classification [0, 1].
                Default 0.62 — calibrated on the test set.
    device    : 'cuda', 'cpu', or 'auto' (picks GPU if available).
    """

    def __init__(
        self,
        model_id  : str   = DEFAULT_MODEL_ID,
        threshold : float = DEFAULT_THRESHOLD,
        device    : str   = "auto",
    ) -> None:
        self.model_id  = model_id
        self.threshold = threshold
        self._model     = None
        self._tokenizer = None

        if device == "auto":
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

    # ── Constructors ──────────────────────────────────────────────────────

    @classmethod
    def from_pretrained(
        cls,
        model_id  : str   = DEFAULT_MODEL_ID,
        threshold : float = DEFAULT_THRESHOLD,
        device    : str   = "auto",
    ) -> "MalwareDetector":
        """
        Load the fine-tuned detector from HuggingFace Hub or a local path.

        Parameters
        ----------
        model_id  : HuggingFace repo ID or local directory.
                    Default: 'Swarnadharshini/codebert-malware-detector'
        threshold : Decision threshold [0, 1]. Default 0.62.
        device    : 'cuda', 'cpu', or 'auto'.

        Returns
        -------
        MalwareDetector ready for inference.

        Examples
        --------
        >>> detector = MalwareDetector.from_pretrained()
        >>> detector = MalwareDetector.from_pretrained(threshold=0.70)
        >>> detector = MalwareDetector.from_pretrained("/local/model/dir")
        """
        instance = cls(model_id=model_id, threshold=threshold, device=device)
        instance._load()
        return instance

    # ── Model loading ─────────────────────────────────────────────────────

    def _load(self) -> None:
        """Downloads/loads tokeniser and model. Idempotent — safe to call multiple times."""
        if self._model is not None:
            return

        print(f"Loading model: {self.model_id}")
        self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self._model     = AutoModelForSequenceClassification.from_pretrained(self.model_id)
        self._model.eval()

        if self.device == "cuda":
            self._model = self._model.cuda()

        print(f"  Device    : {self.device.upper()}")
        print(f"  Threshold : {self.threshold}")
        print(f"  Ready.")

    def _ensure_loaded(self) -> None:
        if self._model is None:
            self._load()

    # ── Core inference ────────────────────────────────────────────────────

    def _infer(self, opcode_sequence: str, source: str = "input") -> DetectionResult:
        """Single forward pass. Returns a DetectionResult."""
        self._ensure_loaded()

        raw_token_count = len(
            self._tokenizer(opcode_sequence, truncation=False, padding=False)["input_ids"]
        )

        encoding = self._tokenizer(
            opcode_sequence,
            max_length     = MAX_LENGTH,
            truncation     = True,
            padding        = "max_length",
            return_tensors = "pt",
        )

        if self.device == "cuda":
            encoding = {k: v.cuda() for k, v in encoding.items()}

        with torch.no_grad():
            logits = self._model(**encoding).logits.cpu().numpy()[0]  # (2,)

        exp         = np.exp(logits - np.max(logits))
        probs       = exp / exp.sum()
        benign_prob = float(probs[0])
        mal_prob    = float(probs[1])

        label      = 1 if mal_prob >= self.threshold else 0
        prediction = "malware" if label == 1 else "benign"
        confidence = mal_prob if label == 1 else benign_prob

        risk = "LOW"
        if mal_prob >= RISK_THRESHOLDS["HIGH"]:
            risk = "HIGH"
        elif mal_prob >= RISK_THRESHOLDS["MEDIUM"]:
            risk = "MEDIUM"

        return DetectionResult(
            source              = source,
            prediction          = prediction,
            label               = label,
            confidence          = round(confidence, 4),
            malware_probability = round(mal_prob, 4),
            benign_probability  = round(benign_prob, 4),
            risk_level          = risk,
            input_tokens        = raw_token_count,
            truncated           = raw_token_count > MAX_LENGTH,
            threshold_used      = self.threshold,
            model_id            = self.model_id,
        )

    # ── Public API ────────────────────────────────────────────────────────

    def predict_file(self, filepath: str) -> DetectionResult:
        """
        Classify a single .csv assembly file.

        The file must have an **'Opcode'** column with x86 mnemonics —
        the format produced by IDA Pro disassembly or ``objdump -d``.

        Parameters
        ----------
        filepath : path to a .csv assembly file.

        Returns
        -------
        DetectionResult

        Raises
        ------
        FileNotFoundError : filepath does not exist.
        ValueError        : file has no valid Opcode column.

        Example
        -------
        >>> result = detector.predict_file("suspicious.csv")
        >>> if result.is_malware:
        ...     print(f"ALERT: {result.risk_level} — {result.confidence*100:.1f}%")
        """
        opcode_seq = extract_from_file(filepath)
        return self._infer(opcode_seq, source=os.path.basename(filepath))

    def predict_text(self, text: str) -> DetectionResult:
        """
        Classify a raw opcode sequence string.

        Parameters
        ----------
        text : space-separated x86 opcode mnemonics.
               e.g. ``"push mov xor call ret add sub nop"``

        Returns
        -------
        DetectionResult

        Raises
        ------
        ValueError : text is empty or contains no valid opcodes.

        Example
        -------
        >>> result = detector.predict_text("xor xor push call mov ret")
        >>> print(result.prediction, result.risk_level)
        malware HIGH
        """
        opcode_seq = clean_text_input(text)
        return self._infer(opcode_seq, source="text_input")

    def predict_batch(
        self,
        folder      : str,
        pattern     : str  = "*.csv",
        sort_by_risk: bool = True,
    ) -> List[DetectionResult]:
        """
        Classify all assembly CSV files in a folder.

        Results are sorted by malware probability (highest first) so SOC
        analysts can triage the most suspicious files immediately.

        Parameters
        ----------
        folder       : directory containing .csv assembly files.
        pattern      : glob pattern (default ``'*.csv'``).
        sort_by_risk : if True, sort results by malware_probability desc.

        Returns
        -------
        List[DetectionResult]  — errors included with prediction='error'.

        Raises
        ------
        FileNotFoundError : folder does not exist or no files match pattern.

        Example
        -------
        >>> results = detector.predict_batch("/soc/incoming/")
        >>> for r in results[:5]:
        ...     print(f"{r.malware_probability:.0%}  {r.risk_level}  {r.source}")
        """
        if not os.path.isdir(folder):
            raise FileNotFoundError(f"Folder not found: {folder}")

        csv_files = glob.glob(os.path.join(folder, pattern))
        if not csv_files:
            raise FileNotFoundError(f"No files matching '{pattern}' in: {folder}")

        results: List[DetectionResult] = []
        for fpath in csv_files:
            try:
                results.append(self.predict_file(fpath))
            except Exception as exc:
                results.append(DetectionResult(
                    source              = os.path.basename(fpath),
                    prediction          = "error",
                    label               = -1,
                    confidence          = 0.0,
                    malware_probability = 0.0,
                    benign_probability  = 0.0,
                    risk_level          = "LOW",
                    input_tokens        = 0,
                    truncated           = False,
                    threshold_used      = self.threshold,
                    model_id            = self.model_id,
                ))

        if sort_by_risk:
            results.sort(key=lambda r: r.malware_probability, reverse=True)

        return results

    # ── Utilities ─────────────────────────────────────────────────────────

    def set_threshold(self, threshold: float) -> None:
        """
        Update the decision threshold at runtime without reloading the model.

        Parameters
        ----------
        threshold : float in (0, 1).
                    Lower → catch more malware (more false alarms).
                    Higher → fewer false alarms (may miss borderline cases).
        """
        if not 0.0 < threshold < 1.0:
            raise ValueError(f"Threshold must be in (0, 1), got {threshold}")
        self.threshold = threshold

    def benchmark(self, text: str = "push mov xor call ret", n: int = 10) -> dict:
        """
        Measure average inference latency over n runs.

        Parameters
        ----------
        text : opcode string to use for benchmarking.
        n    : number of timed runs (default 10).

        Returns
        -------
        dict with mean_ms, min_ms, max_ms, runs.
        """
        self._ensure_loaded()
        times = []
        for _ in range(n):
            t0 = time.perf_counter()
            self.predict_text(text)
            times.append((time.perf_counter() - t0) * 1000)
        return {
            "mean_ms" : round(float(np.mean(times)), 2),
            "min_ms"  : round(float(np.min(times)),  2),
            "max_ms"  : round(float(np.max(times)),  2),
            "runs"    : n,
        }

    def __repr__(self) -> str:
        return (
            f"MalwareDetector("
            f"model_id={self.model_id!r}, "
            f"threshold={self.threshold}, "
            f"device={self.device!r}, "
            f"loaded={self._model is not None})"
        )
