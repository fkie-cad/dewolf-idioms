import ctypes
import logging
from typing import Dict, List

import yaml

logger = logging.getLogger("yaml")
logger.setLevel(level=logging.ERROR)

from compiler_idioms.idiom.instruction_sequence import InstructionSequence
from compiler_idioms.instruction import Instruction
from compiler_idioms.match import Match
from compiler_idioms.config import PATTERNS_DIR
from compiler_idioms.safe_eval import safe_eval

TEST_PATTERN_PATH = PATTERNS_DIR / "patterns-mul.yaml"


class SignedMultiplicationInstructionSequence(InstructionSequence):
    def __init__(self):
        sequences, constants = self._load_sequences_from_file()  # TODO: might make sense to move this to parent class
        super().__init__(sequences)
        self._constant_calculations = constants

    def search(self, sequence: List[Instruction], original_constants: Dict[str, str], original_registers: Dict[str, str]) -> Match:
        if match := super().search(sequence, original_constants, original_registers):
            match.operation = "multiplication"
            match.operand = self._get_register_operand(original_registers)
            match.constant = self._get_original_constant(sequence, original_constants)
            return match

    def _load_sequences_from_file(self) -> (List[List[Instruction]], List[str]):
        result = []
        constants = []
        with open(TEST_PATTERN_PATH) as f:
            for obj in yaml.load_all(f, Loader=yaml.FullLoader):
                for idiom_sequence in obj:
                    result.append(self._str_list_to_instr_list(idiom_sequence["pattern"]))
                    constants.append(idiom_sequence["constant"])
        return result, constants

    def _get_register_operand(self, original_registers: Dict[str, str]) -> str:
        return original_registers.get("reg_0", [])

    def _get_original_constant(self, sequence, original_constants: Dict[str, str]) -> int:
        original_constants = {name: self._get_constant_value(value) for name, value in original_constants.items()}
        return safe_eval(self._constant_calculations[self._last_matched_index], original_constants)

    def _get_constant_value(self, value):
        if value.startswith("-"):
            return int(value, 16)
        return ctypes.c_int(int(value, 16)).value

    def _str_list_to_instr_list(self, str_list: List[str]) -> List[Instruction]:
        return [
            Instruction(
                address=-1, mnemonic=(mnemonic := s.split(" ")[0]), operands=tuple(map(lambda x: x.strip(), s[len(mnemonic) :].split(",")))
            )
            for s in str_list
        ]
