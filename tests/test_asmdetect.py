"""
tests/test_asmdetect.py
-----------------------
Unit tests for the asmdetect library.
All tests run without the fine-tuned model — no network required.

Run
---
    pytest tests/ -v
    pytest tests/ -v --cov=asmdetect --cov-report=term-missing
"""

import json
import os
import tempfile

import pandas as pd
import pytest

from asmdetect.preprocessing import (
    _is_valid_opcode,
    clean_text_input,
    extract_from_dataframe,
    extract_from_file,
)
from asmdetect.result  import DetectionResult
from asmdetect.version import __version__


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_result(
    prediction="malware", label=1,
    mal_p=0.95, risk="HIGH",
) -> DetectionResult:
    return DetectionResult(
        source="test.csv", prediction=prediction, label=label,
        confidence=mal_p, malware_probability=mal_p,
        benign_probability=round(1 - mal_p, 4),
        risk_level=risk, input_tokens=200, truncated=False,
        threshold_used=0.62,
        model_id="Swarnadharshini/codebert-malware-detector",
    )


# ── DetectionResult ───────────────────────────────────────────────────────────

class TestDetectionResult:

    def test_is_malware_true(self):
        r = _make_result(prediction="malware", label=1)
        assert r.is_malware is True
        assert r.is_benign  is False

    def test_is_benign_true(self):
        r = _make_result(prediction="benign", label=0, mal_p=0.2, risk="LOW")
        assert r.is_benign  is True
        assert r.is_malware is False

    def test_to_dict_has_all_fields(self):
        r = _make_result()
        d = r.to_dict()
        for key in [
            "source", "prediction", "label", "confidence",
            "malware_probability", "benign_probability",
            "risk_level", "input_tokens", "truncated",
            "threshold_used", "model_id",
        ]:
            assert key in d, f"Missing key: {key}"

    def test_to_json_roundtrip(self):
        r    = _make_result()
        data = json.loads(r.to_json())
        assert data["prediction"] == "malware"
        assert data["model_id"]   == "Swarnadharshini/codebert-malware-detector"

    def test_str_contains_prediction(self):
        assert "malware" in str(_make_result()).lower()

    def test_repr_contains_class_name(self):
        assert "DetectionResult" in repr(_make_result())

    def test_risk_icons(self):
        assert _make_result(risk="HIGH").risk_icon   == "[HIGH]"
        assert _make_result(risk="MEDIUM").risk_icon == "[MED]"
        assert _make_result(risk="LOW").risk_icon    == "[LOW]"


# ── _is_valid_opcode ──────────────────────────────────────────────────────────

class TestIsValidOpcode:

    def test_plain_mnemonics(self):
        for tok in ["push", "mov", "xor", "ret", "call", "add", "nop"]:
            assert _is_valid_opcode(tok), f"Should accept: {tok}"

    def test_att_suffixed_mnemonics(self):
        for tok in ["pushl", "movl", "movq", "subl", "addl"]:
            assert _is_valid_opcode(tok), f"Should accept AT&T suffix: {tok}"

    def test_rejects_section_headers(self):
        for tok in [".text", ".data", ".bss", ".rodata"]:
            assert not _is_valid_opcode(tok), f"Should reject: {tok}"

    def test_rejects_hex_bytes(self):
        for tok in ["30", "7d", "00", "8b", "90"]:
            assert not _is_valid_opcode(tok), f"Should reject hex: {tok}"

    def test_accepts_ff_as_valid_mnemonic(self):
        # ff is a valid x86 opcode group prefix (objdump uses it for
        # indirect CALL/JMP/PUSH e.g. "ff d0" = call *%eax)
        assert _is_valid_opcode("ff"), "ff is a valid x86 mnemonic"

    def test_rejects_addresses(self):
        for tok in ["402000", "401000:", "0x401000"]:
            assert not _is_valid_opcode(tok), f"Should reject address: {tok}"

    def test_rejects_empty_string(self):
        assert not _is_valid_opcode("")
        assert not _is_valid_opcode("   ")


# ── clean_text_input ──────────────────────────────────────────────────────────

class TestCleanTextInput:

    def test_basic_sequence(self):
        assert clean_text_input("push mov xor call ret") == "push mov xor call ret"

    def test_uppercase_normalised(self):
        assert clean_text_input("PUSH MOV XOR") == "push mov xor"

    def test_strips_hex_and_addresses(self):
        result = clean_text_input("402000 30 push mov 7d xor")
        assert "push" in result and "mov" in result
        assert "402000" not in result
        assert "30"     not in result

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            clean_text_input("")

    def test_only_garbage_raises(self):
        with pytest.raises(ValueError, match="No valid opcodes"):
            clean_text_input("123 456 789")

    def test_truncates_to_256(self):
        long_seq = " ".join(["mov"] * 500)
        assert len(clean_text_input(long_seq).split()) == 256


# ── extract_from_dataframe ────────────────────────────────────────────────────

class TestExtractFromDataframe:

    def test_malware_csv_format(self):
        df = pd.DataFrame({
            "Address"    : ["402000:", "402003:"],
            "Hex_Opcode" : ["30 7d",   "00 00"],
            "Opcode"     : ["xor",     "add"],
            "Operand 1"  : ["%bh",     "%al"],
        })
        result = extract_from_dataframe(df)
        assert result == "xor add"

    def test_benign_csv_format(self):
        df = pd.DataFrame({
            "Line"    : ["401000:", "401001:"],
            "Opc"     : ["55",      "8b ec"],
            "Opcode"  : ["pushl",   "movl"],
            "Operand" : ["%ebp",    "%esp"],
        })
        result = extract_from_dataframe(df)
        assert result is not None
        assert "pushl" in result
        assert "movl"  in result

    def test_no_opcode_column_returns_none(self):
        df = pd.DataFrame({"Address": ["0x1"], "Hex": ["90"]})
        assert extract_from_dataframe(df) is None

    def test_section_headers_filtered(self):
        df     = pd.DataFrame({"Opcode": [".text", "push", ".data", "mov", "ret"]})
        result = extract_from_dataframe(df)
        assert result is not None
        assert ".text" not in result
        assert ".data" not in result
        assert "push"  in result

    def test_case_insensitive_column_match(self):
        df = pd.DataFrame({"OPCODE": ["push", "mov"]})
        assert extract_from_dataframe(df) is not None

    def test_whitespace_column_name(self):
        df = pd.DataFrame({" Opcode ": ["push", "mov"]})
        assert extract_from_dataframe(df) is not None


# ── extract_from_file ─────────────────────────────────────────────────────────

class TestExtractFromFile:

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            extract_from_file("/nonexistent/path/sample.csv")

    def test_valid_csv_returns_sequence(self):
        df = pd.DataFrame({
            "Opcode": ["push", "mov", "xor", "call", "ret",
                       "add",  "sub", "lea", "nop",  "pop"]
        })
        with tempfile.NamedTemporaryFile(
            suffix=".csv", mode="w", delete=False
        ) as f:
            df.to_csv(f, index=False)
            tmp = f.name
        try:
            result = extract_from_file(tmp)
            assert "push" in result
            assert "mov"  in result
        finally:
            os.unlink(tmp)

    def test_missing_opcode_column_raises(self):
        df = pd.DataFrame({"Address": ["0x1"], "Hex": ["90"]})
        with tempfile.NamedTemporaryFile(
            suffix=".csv", mode="w", delete=False
        ) as f:
            df.to_csv(f, index=False)
            tmp = f.name
        try:
            with pytest.raises(ValueError, match="No valid opcodes"):
                extract_from_file(tmp)
        finally:
            os.unlink(tmp)


# ── Version ───────────────────────────────────────────────────────────────────

class TestVersion:

    def test_version_is_string(self):
        assert isinstance(__version__, str)

    def test_version_semver_format(self):
        parts = __version__.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)


# ── Public API imports ────────────────────────────────────────────────────────

class TestPublicAPI:

    def test_all_symbols_importable(self):
        from asmdetect import MalwareDetector, DetectionResult, __version__
        assert MalwareDetector is not None
        assert DetectionResult is not None
        assert __version__     is not None

    def test_default_model_id(self):
        from asmdetect.detector import DEFAULT_MODEL_ID
        assert DEFAULT_MODEL_ID == "Swarnadharshini/codebert-malware-detector"

    def test_default_threshold(self):
        from asmdetect.detector import DEFAULT_THRESHOLD
        assert 0 < DEFAULT_THRESHOLD < 1
