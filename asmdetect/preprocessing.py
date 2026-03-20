"""
preprocessing.py
----------------
Opcode extraction and cleaning utilities.
Handles both CSV files (Arun152k format) and raw opcode strings.
"""

from __future__ import annotations
import os
import pandas as pd


MAX_OPCODES = 256   # max opcode tokens sent to the tokeniser
MIN_OPCODES = 1     # minimum valid opcodes to return a result

# x86 mnemonics always start with a letter
_ALPHA_START = set("abcdefghijklmnopqrstuvwxyz")


def _is_valid_opcode(token: str) -> bool:
    """
    Returns True if token looks like an x86 mnemonic.

    Accepts
    -------
    - plain mnemonics           : push, mov, xor, ret
    - AT&T size-suffixed forms  : pushl, movl, movq, subl
    - REP-prefixed              : repnz, repe

    Rejects
    -------
    - section headers : .text, .data   (start with '.')
    - hex bytes       : 30, 7d         (start with digit)
    - addresses       : 402000:        (start with digit)
    - empty strings
    """
    t = token.strip().lower()
    if not t or t[0] not in _ALPHA_START:
        return False
    return t.isalpha() or t.replace(".", "").isalnum()


def extract_from_dataframe(df: pd.DataFrame) -> str | None:
    """
    Extracts a clean opcode sequence string from a CSV DataFrame.

    Handles both Malware CSV format (columns: Address, Hex_Opcode, Opcode, ...)
    and Benign CSV format (columns: Line, Opc, Opcode, Operand).

    Returns
    -------
    Space-joined opcode string, or None if no Opcode column found.
    """
    opcode_col = None
    for col in df.columns:
        if col.strip().lower() == "opcode":
            opcode_col = col
            break

    if opcode_col is None:
        return None

    opcodes = (
        df[opcode_col]
        .dropna()
        .astype(str)
        .str.strip()
        .str.lower()
        .tolist()
    )
    opcodes = [o for o in opcodes if _is_valid_opcode(o)]
    opcodes = opcodes[:MAX_OPCODES]

    return " ".join(opcodes) if len(opcodes) >= MIN_OPCODES else None


def extract_from_file(filepath: str) -> str:
    """
    Reads a .csv assembly file and returns a clean opcode sequence string.

    Parameters
    ----------
    filepath : path to a CSV file with an 'Opcode' column.

    Returns
    -------
    Space-joined opcode string.

    Raises
    ------
    FileNotFoundError : file does not exist.
    ValueError        : file has no Opcode column or no valid opcodes.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    try:
        df = pd.read_csv(filepath, on_bad_lines="skip", low_memory=False)
    except Exception as exc:
        raise ValueError(f"Cannot parse CSV '{filepath}': {exc}") from exc

    seq = extract_from_dataframe(df)
    if not seq:
        raise ValueError(
            f"No valid opcodes found in '{filepath}'. "
            f"Ensure the file has an 'Opcode' column with x86 mnemonics."
        )
    return seq


def clean_text_input(text: str) -> str:
    """
    Cleans and normalises a raw opcode string.

    Parameters
    ----------
    text : space-separated opcode sequence, e.g. "push mov xor call ret"

    Returns
    -------
    Cleaned, lower-cased, truncated opcode string.

    Raises
    ------
    ValueError : text is empty or contains no valid opcodes.
    """
    if not text or not text.strip():
        raise ValueError("Input text is empty.")

    tokens = text.strip().lower().split()
    tokens = [t for t in tokens if _is_valid_opcode(t)]
    tokens = tokens[:MAX_OPCODES]

    if not tokens:
        raise ValueError(
            "No valid opcodes found in input text. "
            "Expected space-separated x86 mnemonics e.g. 'push mov xor call ret'."
        )
    return " ".join(tokens)
