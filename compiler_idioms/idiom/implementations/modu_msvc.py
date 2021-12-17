import ctypes
import json
from typing import Dict, List, Tuple

from compiler_idioms.idiom.instruction_sequence import InstructionSequence
from compiler_idioms.idiom.utils.magic import compute_magic_numbers_if_not_exists as magic
from compiler_idioms.idiom.utils.magic_unsigend import compute_magic_numbers_if_not_exists as magic_unsigned
from compiler_idioms.idiom.utils.pattern_utils import load_pattern_sequences_for_operation
from compiler_idioms.instruction import Instruction, from_anonymized_pattern
from compiler_idioms.match import Match
from config import ROOT

HEX_BASE = 16


# ic.disable()
class UnsignedModuloInstructionSequence(InstructionSequence):
    MUL = {"mul", "imul"}
    DIV = {"div", "idiv"}

    def __init__(self):
        sequences = load_pattern_sequences_for_operation("modu")
        sequences.append(
            [
                Instruction(address=4548, mnemonic="mov", operands=("reg_0", "reg_1"), matched=False),
                Instruction(address=4550, mnemonic="mov", operands=("reg_2", "reg_1"), matched=False),
                Instruction(address=4552, mnemonic="shr", operands=("reg_0", "const_0"), matched=False),
                Instruction(address=4555, mnemonic="imul", operands=("reg_3", "reg_3", "const_1"), matched=False),
                Instruction(address=4562, mnemonic="shr", operands=("reg_3", "const_2"), matched=False),
                Instruction(address=4566, mnemonic="imul", operands=("reg_0", "reg_0", "const_3"), matched=False),
                Instruction(address=4569, mnemonic="sub", operands=("reg_2", "reg_0"), matched=False),
                Instruction(address=4571, mnemonic="ret", operands=(), matched=False),
            ]
        )

        self.magic_table = magic_unsigned()
        self.signed_magic_table = magic()
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
        match.operation = "modulo unsigned"
        match.operand = self._get_register_operand(original_registers)
        if not original_constants:
            match.constant = None
            return match
        div = [x for x in sequence if x.mnemonic in self.DIV]
        if div:
            return self.handle_patterns_with_div(match, original_constants, sequence, original_registers)
        imul = [x for x in sequence if x.mnemonic in {"imul", "mul"}]
        if not imul:
            return self.handle_powers_of_two(match, original_constants, sequence)
        return self._handle_unsigned_magic_numbers_division(match, original_constants, original_registers, sequence)

    def handle_patterns_with_div(self, match, original_constants, sequence, original_registers):
        const = int(original_constants["const_0"], HEX_BASE)
        original_constant = ctypes.c_int32(const).value
        match.constant = original_constant
        if match.sequence[-1].mnemonic in self.DIV:
            if self._remainder_register_is_copied_after_div(match, sequence, original_registers):
                match.operation = "modulo unsigned"
            else:
                match.operation = "division unsigned"
        return match

    def _remainder_register_is_copied_after_div(self, match, sequence, original_registers):

        if len(sequence) > len(match.sequence) and match:
            next_after_div = sequence[len(match.sequence)]
            if next_after_div.mnemonic == "mov":
                source = next_after_div.operands[-1]
                if source in original_registers and original_registers[source] == "edx":
                    return True
        return False

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
            if i.mnemonic == "and":
                last_op = i.operands[1]
                if self._is_constant(last_op):
                    match.constant = 1 + int(original_constants.get(last_op), HEX_BASE)
                    return match

        return None

    def _handle_unsigned_magic_numbers_division(
        self,
        match: Match,
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
        sequence: List[Instruction],
    ):
        match.constant = self._get_original_constant_from_magic(original_constants, original_registers, sequence)
        return match

    def _get_original_constant_from_magic(
        self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]
    ) -> int:
        result = self._try_imul_cheating(original_constants, original_registers, sequence)
        if result:
            return result
        power = self._accumulate_shr_amount(sequence, original_constants)
        magic, mul_position = self._get_mul_constant_and_position(sequence, original_constants)
        if not magic:
            magic = self._backtrack_magic_number(mul_position, sequence, original_constants, original_registers)
        result = self.magic_table.get((magic, power))
        if not result:
            result = self.magic_table.get((magic, power + 32))
        return result

    def _get_register_operand(self, original_registers: Dict[str, str]):
        return original_registers.get("reg_1", [])

    def _try_imul_cheating(self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]):
        imul_count = 0
        first_imul_index = -1
        second_imul_index = -1
        for i, s in enumerate(sequence):
            if s.mnemonic in {"imul", "mul"} and first_imul_index == -1:
                first_imul_index = i
            elif s.mnemonic in {"imul", "mul"} and first_imul_index != -1 and second_imul_index == -1:
                second_imul_index = i
        if first_imul_index != -1 and second_imul_index != -1:
            cheat_imul = sequence[second_imul_index]
            last_op = cheat_imul.operands[-1]
            if last_op.startswith("const"):
                return int(original_constants.get(last_op), HEX_BASE)

    def _accumulate_shr_amount(self, sequence: List[Instruction], original_constants: Dict[str, str]) -> int:
        power = 0
        for x in sequence:
            if x.mnemonic == "shr":
                for op in x.operands:
                    if op.startswith("const"):
                        power += int(original_constants.get(op), HEX_BASE)
        return power

    def _backtrack_magic_number(
        self, imul_index: int, sequence: List[Instruction], original_constants: Dict[str, str], original_registers: Dict[str, str]
    ) -> int:
        magic_number = 0
        mul_instr = sequence[imul_index]
        for anonymized_operand in mul_instr.operands:
            if anonymized_operand not in original_registers:
                # loc0 etc
                register = "eax"
                lower = "ax"
            else:
                register = original_registers[anonymized_operand]
                lower = register[1:]
            # if len(mul_instr.operands) == 1 and not register.endswith('ax') and not register.endswith('dx'):
            #     register = 'eax'
            #     lower = 'ax'

            for i in range(imul_index - 1, -1, -1):
                current_instr = sequence[i]
                if current_instr.mnemonic == "mov":
                    destination = current_instr.operands[0]
                    # todo hotfix to rconst_n, remove
                    if destination not in original_registers:
                        continue
                    destination_register = original_registers.get(destination)

                    if destination_register == register or destination_register.endswith(lower):
                        if current_instr.operands[-1].startswith("const"):
                            magic_number = int(original_constants.get(current_instr.operands[-1]), HEX_BASE)
                            break
                        else:
                            register = original_registers.get(current_instr.operands[-1])
        if not magic_number:
            register = "eax"
            lower = "ax"
            for i in range(imul_index - 1, -1, -1):
                current_instr = sequence[i]
                if current_instr.mnemonic == "mov":
                    destination = current_instr.operands[0]
                    # todo hotfix to rconst_n, remove
                    if destination not in original_registers:
                        continue
                    destination_register = original_registers.get(destination)
                    if destination_register == register or destination_register.endswith(lower):
                        if current_instr.operands[-1].startswith("const"):
                            magic_number = int(original_constants.get(current_instr.operands[-1]), HEX_BASE)
                            break
                        else:
                            register = original_registers.get(current_instr.operands[-1])

        return magic_number

    def _starts_with_mul_not_shift(self, sequence: List[Instruction], mul_position):
        for i, instr in enumerate(sequence):
            if instr.mnemonic == "shr":
                return mul_position < i
        return False

    def _get_mul_constant_and_position(self, sequence: List[Instruction], original_constants: Dict[str, str]) -> Tuple[int, int]:
        magic = 0
        first_mul_index = 0
        for i, instr in enumerate(sequence):
            if instr.mnemonic in self.MUL:
                first_mul_index = i
                for op in instr.operands:
                    if op.startswith("const"):
                        magic = int(original_constants.get(op), HEX_BASE)
        return magic, first_mul_index

    @staticmethod
    def _is_constant(anonymized_operand: str):
        return anonymized_operand.startswith("const")


if __name__ == "__main__":
    idiom = UnsignedModuloInstructionSequence()
    print(idiom.magic_table)
