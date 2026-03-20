"""
result.py
---------
Typed return object for every MalwareDetector prediction.
Supports attribute access, dict conversion, and JSON serialisation.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
import json


@dataclass
class DetectionResult:
    """
    Returned by every MalwareDetector.predict_* call.

    Attributes
    ----------
    source              : filename or 'text_input'
    prediction          : 'malware' or 'benign'
    label               : 1 = malware, 0 = benign
    confidence          : probability of the predicted class  [0, 1]
    malware_probability : raw P(malware) from softmax         [0, 1]
    benign_probability  : raw P(benign)  from softmax         [0, 1]
    risk_level          : 'HIGH' (>=80%) | 'MEDIUM' (>=55%) | 'LOW'
    input_tokens        : token count before truncation
    truncated           : True if input exceeded 512 tokens
    threshold_used      : decision threshold applied
    model_id            : HuggingFace model id or local path
    """
    source              : str
    prediction          : str
    label               : int
    confidence          : float
    malware_probability : float
    benign_probability  : float
    risk_level          : str
    input_tokens        : int
    truncated           : bool
    threshold_used      : float
    model_id            : str

    # ── Convenience properties ────────────────────────────────────────────

    @property
    def is_malware(self) -> bool:
        return self.label == 1

    @property
    def is_benign(self) -> bool:
        return self.label == 0

    @property
    def risk_icon(self) -> str:
        return {"HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}.get(
            self.risk_level, ""
        )

    # ── Serialisation ─────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Return result as a plain dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Return result as a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    # ── Display ───────────────────────────────────────────────────────────

    def __str__(self) -> str:
        return (
            f"DetectionResult(\n"
            f"  source      = {self.source}\n"
            f"  prediction  = {self.prediction.upper()}  {self.risk_icon} {self.risk_level}\n"
            f"  confidence  = {self.confidence * 100:.2f}%\n"
            f"  malware_p   = {self.malware_probability * 100:.2f}%\n"
            f"  benign_p    = {self.benign_probability * 100:.2f}%\n"
            f"  tokens      = {self.input_tokens}  (truncated={self.truncated})\n"
            f"  threshold   = {self.threshold_used}\n"
            f"  model       = {self.model_id}\n"
            f")"
        )

    def __repr__(self) -> str:
        return (
            f"DetectionResult(prediction={self.prediction!r}, "
            f"confidence={self.confidence:.4f}, "
            f"risk_level={self.risk_level!r})"
        )
