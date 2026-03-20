"""
asmdetect
=========
Assembly-Level Malware Detection using Fine-Tuned CodeBERT.

Trained model: Swarnadharshini/codebert-malware-detector (HuggingFace Hub)

Quick start
-----------
>>> from asmdetect import MalwareDetector
>>> detector = MalwareDetector.from_pretrained()
>>> result = detector.predict_text("push mov xor call ret")
>>> print(result)
"""

from .detector      import MalwareDetector
from .result        import DetectionResult
from .version       import __version__

__all__ = ["MalwareDetector", "DetectionResult", "__version__"]
__author__  = "Swarnadharshini"
__model__   = "Swarnadharshini/codebert-malware-detector"
