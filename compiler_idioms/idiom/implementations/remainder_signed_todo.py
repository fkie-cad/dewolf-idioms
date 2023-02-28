import json
from typing import Dict, List

from compiler_idioms.idiom.instruction_sequence import InstructionSequence
from compiler_idioms.idiom.utils.magic import compute_magic_numbers_if_not_exists
from compiler_idioms.instruction import Instruction, from_anonymized_pattern
from compiler_idioms.match import Match
from compiler_idioms.config import ROOT, TEST_DIR

# TEST_PATTERN_PATH = TEST_DIR / "mods-pointer.json"
TEST_PATTERN_PATH = TEST_DIR / "patterns-mods-O0.json"
PATTERN_DIR = ROOT / "patterns"

HEX_BASE = 16


class SignedRemainderInstructionSequence(InstructionSequence):
    def __init__(self):
        sequences = self._load_sequences_from_file()
        # with TEST_PATTERN_PATH.open('r') as f:
        #     seq = json.load(f)
        # print(seq)
        # sequences = [from_anonymized_pattern(seq['pattern'])]
        self.magic_table = compute_magic_numbers_if_not_exists()
        super().__init__(sequences)

    def search(self, sequence: List[Instruction], original_constants: Dict[str, str], original_registers: Dict[str, str]) -> Match:
        if match := super().search(sequence, original_constants, original_registers):
            match.operation = "modulo"
            match.operand = self._get_register_operand(original_registers)
            match.constant = self._get_original_constant_from_magic(original_constants)
            if not match.constant:
                return None
            return match

    def _get_register_operand(self, original_registers: Dict[str, str]):
        return original_registers.get("reg_1", [])

    def _get_original_constant_from_magic(self, original_constants: Dict[str, str]) -> int:
        magic = int(original_constants.get("const_0"), HEX_BASE)
        power = int(original_constants.get("const_1"), HEX_BASE) + int(original_constants.get("const_2"), HEX_BASE)
        return self.magic_table.get((magic, power))

    @staticmethod
    def _load_sequences_from_file():
        sequences = []
        for patter_file in PATTERN_DIR.glob("*mods*"):
            try:
                with patter_file.open("r") as f:
                    data = json.load(f)
                    for seq in data:
                        pattern = seq.get("sequence")
                        anonymized_instruction_list = from_anonymized_pattern(pattern)
                        if anonymized_instruction_list:
                            sequences.append(anonymized_instruction_list)
            except FileNotFoundError as e:
                print("No file for division found")
        return sequences


if __name__ == "__main__":
    idiom = SignedRemainderInstructionSequence()
    print(idiom.magic_table)
