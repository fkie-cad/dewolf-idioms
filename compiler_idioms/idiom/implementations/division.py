import ctypes
import json
from typing import Dict, List

from compiler_idioms.idiom.instruction_sequence import InstructionSequence
from compiler_idioms.idiom.utils.magic import compute_magic_numbers_if_not_exists
from compiler_idioms.idiom.utils.pattern_utils import load_pattern_sequences_for_operation
from compiler_idioms.instruction import Instruction, from_anonymized_pattern
from compiler_idioms.match import Match
from config import ROOT
from icecream import ic

# TEST_PATTERN_PATH = TEST_DIR / "divs.json"
TEST_PATTERN_PATH = ROOT / "patterns" / "patterns-divs-O0.json"
PATTERN_DIR = ROOT / "patterns"
HEX_BASE = 16


class SignedDivisionInstructionSequence(InstructionSequence):
    def __init__(self):
        sequences = load_pattern_sequences_for_operation("divs")
        self.magic_table = compute_magic_numbers_if_not_exists()
        super().__init__(sequences)

    def search(
        self,
        sequence: List[Instruction],
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
    ) -> Match:
        if match := super().search(sequence, original_constants, original_registers):
            return self.handle_match(match, original_constants, original_registers, sequence)

    def handle_match(
        self,
        match: Match,
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
        sequence,
    ):
        match.operation = "division"
        match.operand = self._get_register_operand(original_registers)
        if not (original_constants):
            # todo handle 03 -1
            match.constant = None
            # return match
        if match.length == 1 and sequence[0].mnemonic == "shr":
            return None
        if len(original_constants.values()) == 2:
            match = self.handle_powers_of_two(match, original_constants, sequence[: match.length])
        match = self.handle_magic_numbers_division(match, original_constants, original_registers, sequence[: match.length])
        if not match.constant:
            match = self.handle_match86(match, original_constants, original_registers, sequence[: match.length])
        return match

    def handle_powers_of_two(
        self,
        match: Match,
        original_constants: Dict[str, str],
        sequence: List[Instruction],
    ):
        """
        ...
        shr reg, const
        ...
        reg/2**const
        """

        constant = None
        for i in sequence:
            if i.mnemonic == "sar":
                constant = i.operands[1]
        if not constant:
            match.constant = None
            return match
        constant = 2 ** int(original_constants.get(constant), HEX_BASE)
        if sequence[-1].mnemonic == "neg":
            constant = -constant
        match.constant = constant
        return match

    def handle_magic_numbers_division(
        self,
        match: Match,
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
        sequence: List[Instruction],
    ):
        match.constant = None
        match.constant = self._get_original_constant_from_magic(original_constants, original_registers, sequence)
        # try:
        #     match.constant = self._get_original_constant_from_magic(original_constants, sequence)
        # except TypeError:
        #     pass
        return match

    def _get_register_operand(self, original_registers: Dict[str, str]):
        return original_registers.get("reg_1", [])

    def _get_original_constant_from_magic(
        self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]
    ) -> int:
        # case 3
        magic = 0
        power = 0
        extra = 0
        imul = None
        imul_index = 0
        for i, instr in enumerate(sequence):
            if instr.mnemonic == "imul":
                imul = instr
                imul_index = i
                for op in instr.operands:
                    if op.startswith("const"):
                        magic = int(original_constants.get(op), HEX_BASE)
                        break
        if not imul:
            return None
        if not magic:
            imul_op0 = imul.operands[0]
            imul_op1 = imul.operands[-1]
            original_register0 = original_registers[imul_op0]
            original_register1 = original_registers[imul_op1]
            lower0 = original_register0[1:]
            lower1 = original_register1[1:]

            for x in range(imul_index, -1, -1):

                current = sequence[x]
                if current.mnemonic == "mov":
                    register = original_registers[current.operands[0]]
                    if register == original_register0 or register.endswith(lower0):
                        ic(current)
                        if current.operands[-1].startswith("const"):
                            magic = int(original_constants.get(current.operands[-1]), HEX_BASE)
                            break
                    elif register == original_register1 or register.endswith(lower1):
                        if current.operands[-1].startswith("const"):
                            magic = int(original_constants.get(current.operands[-1]), HEX_BASE)
                            break
            ic(magic)

        power_instr = None
        for instr in sequence:
            if instr.mnemonic in {"sar", "shr"}:
                for op in instr.operands:
                    if op.startswith("const"):
                        val = int(original_constants.get(op), HEX_BASE)
                        if val >= 32 and not power:
                            power = val
                            power_instr = instr
                            break

        for instr in sequence:
            if instr == power_instr:
                continue
            if instr.mnemonic in {"sar", "shr"}:
                for op in instr.operands:
                    if op.startswith("const"):
                        val = int(original_constants.get(op), HEX_BASE)
                        if val < 0x1F and not extra:
                            extra = int(original_constants.get(op), HEX_BASE)
                            break

        # magic = int(original_constants.get("const_0"), HEX_BASE)
        # power = int(original_constants.get("const_1"), HEX_BASE)
        # extra = int(original_constants.get("const_2"), HEX_BASE)
        # if extra < 0x1F:
        #     # case 5
        #     power += extra
        power += extra

        if ctypes.c_int32(magic).value < 0:
            # case 7
            magic = ctypes.c_uint32(magic).value
        # return self.magic_table.get((magic, power))
        ic(magic)
        ic(power)
        quotient = self.magic_table.get((magic, power))
        ic(sequence)
        if not quotient:
            return None
        if self._is_negative(original_constants, original_registers, sequence):
            quotient = -quotient
        return quotient

    def _is_negative(self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]) -> int:
        # case 3
        sign_reg = None
        sub_instr = None
        sign_index = 0
        sub_index = 0
        for i, instr in enumerate(sequence):
            if instr.mnemonic in {"sar", "shr"}:
                op1 = instr.operands[0]
                op2 = instr.operands[1]
                if op2.startswith("const"):
                    ic(op2)
                    val = int(original_constants.get(op2), HEX_BASE)
                    if val == 31:
                        sign_reg = op1
                        sign_index = i
                        break

        for i, instr in enumerate(sequence):
            if instr.mnemonic == "sub":
                sub_instr = instr
                sub_index = i
        sign_reg = sequence[sign_index].operands[0]
        for i in range(sign_index, sub_index, 1):
            current = sequence[i]
            if current.mnemonic == "mov":
                if current.operands[-1] == sign_reg:
                    sign_reg = current.operands[0]
                    ic()
                    ic(sign_reg)

        ic()
        ic(sign_reg)

        if sub_instr.operands[0] == sign_reg:
            return True
        return False

    def handle_match86(
        self,
        match: Match,
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
        sequence,
    ):
        match.operation = "division"
        match.operand = self._get_register_operand(original_registers)
        if not (original_constants):
            # todo handle 03 -1
            match.constant = None
            return match
        imul = [x for x in sequence if x.mnemonic == "imul"]
        if not imul:
            return self.handle_powers_of_two86(match, original_constants, sequence[: match.length])
        return self.handle_magic_numbers_division86(match, original_constants, original_registers, sequence[: match.length])

    def handle_powers_of_two86(
        self,
        match: Match,
        original_constants: Dict[str, str],
        sequence: List[Instruction],
    ):
        """
        ...
        shr reg, const
        ...
        reg/2**const
        """
        constant = None
        for i in sequence:
            if i.mnemonic == "sar":
                constant = i.operands[1]
        if not constant:
            match.constant = None
            return match
        constant = 2 ** int(original_constants.get(constant), HEX_BASE)
        if sequence[-1].mnemonic == "neg":
            constant = -constant
        match.constant = constant
        return match

    def handle_magic_numbers_division86(
        self,
        match: Match,
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
        sequence: List[Instruction],
    ):
        match.constant = None
        match.constant = self._get_original_constant_from_magic86(original_constants, original_registers, sequence)
        return match

    def _get_original_constant_from_magic86(
        self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]
    ) -> int:
        # case 3
        ic(original_constants)
        ic(sequence)
        magic = 0
        power = 0
        extra = 0
        imul = None
        imul_index = 0
        for i, instr in enumerate(sequence):
            if instr.mnemonic == "imul":
                imul = instr
                imul_index = i
                for op in instr.operands:
                    if op.startswith("const"):
                        magic = int(original_constants.get(op), HEX_BASE)
                        break
        if not magic:
            if not imul:
                return
            imul_op0 = imul.operands[0]
            imul_op1 = imul.operands[-1]
            original_register0 = original_registers[imul_op0]
            original_register1 = original_registers[imul_op1]
            ic(original_register0)
            ic(original_register1)
            lower0 = original_register0[1:]
            lower1 = original_register1[1:]

            for x in range(imul_index, -1, -1):

                current = sequence[x]
                ic()
                ic(current)
                if current.mnemonic == "mov":
                    register = original_registers[current.operands[0]]
                    if register == original_register0 or register.endswith(lower0):
                        ic(current)
                        if current.operands[-1].startswith("const"):
                            magic = int(original_constants.get(current.operands[-1]), HEX_BASE)
                            ic()
                            break
                    elif register == original_register1 or register.endswith(lower1):
                        if current.operands[-1].startswith("const"):
                            magic = int(original_constants.get(current.operands[-1]), HEX_BASE)
                            ic()
                            break
            ic(magic)

        power_instr = None
        for instr in sequence:
            if instr.mnemonic in {"sar", "shr"}:
                for op in instr.operands:
                    if op.startswith("const"):
                        val = int(original_constants.get(op), HEX_BASE)
                        if val >= 32 and not power:
                            power = val
                            power_instr = instr
                            break

        for instr in sequence:
            if instr == power_instr:
                continue
            if instr.mnemonic in {"sar", "shr"}:
                for op in instr.operands:
                    if op.startswith("const"):
                        val = int(original_constants.get(op), HEX_BASE)
                        if val < 0x1F and not extra:
                            extra = int(original_constants.get(op), HEX_BASE)
                            break

        # magic = int(original_constants.get("const_0"), HEX_BASE)
        # power = int(original_constants.get("const_1"), HEX_BASE)
        # extra = int(original_constants.get("const_2"), HEX_BASE)
        # if extra < 0x1F:
        #     # case 5
        #     power += extra
        power += extra

        if ctypes.c_int32(magic).value < 0:
            # case 7
            magic = ctypes.c_uint32(magic).value
        # return self.magic_table.get((magic, power))
        ic(magic)
        ic(power)
        power += 32
        quotient = self.magic_table.get((magic, power))

        sign_reg = None
        sub_instr = None
        for instr in sequence:
            if instr == power_instr:
                continue
            if instr.mnemonic in {"sar", "shr"}:
                op1 = instr.operands[0]
                op2 = instr.operands[1]
                if op2.startswith("const"):
                    val = int(original_constants.get(op2), HEX_BASE)
                    if val == 31:
                        sign_reg = op1
            if instr.mnemonic == "sub":
                sub_instr = instr

        if not sub_instr:
            return quotient

        if sub_instr.operands[0] == sign_reg:
            quotient = -quotient

        return quotient


if __name__ == "__main__":
    idiom = SignedDivisionInstructionSequence()
    print(idiom.magic_table)
