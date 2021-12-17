import json

from compiler_idioms.instruction import from_anonymized_pattern
from config import ROOT

PATTERN_DIR = ROOT / "patterns"


def load_pattern_sequences_for_operation(operation):
    sequences = []
    try:
        for pattern_file in PATTERN_DIR.glob(f"*{operation}*"):
            with pattern_file.open("r") as f:
                data = json.load(f)
                for seq in data:
                    pattern = seq.get("sequence")
                    anonymized_instruction_list = from_anonymized_pattern(pattern)
                    if anonymized_instruction_list:
                        sequences.append(anonymized_instruction_list)
        sequences = sorted(sequences, key=len, reverse=False)
    except FileNotFoundError as e:
        print("No pattern file for division found")
    return sequences
