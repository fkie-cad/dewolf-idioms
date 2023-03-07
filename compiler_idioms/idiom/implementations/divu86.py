from typing import Dict, List, Tuple

from compiler_idioms.idiom.instruction_sequence import InstructionSequence
from compiler_idioms.idiom.utils.magic import compute_magic_numbers_if_not_exists as magic
from compiler_idioms.idiom.utils.magic_unsigend import compute_magic_numbers_if_not_exists as magic_unsigned
from compiler_idioms.idiom.utils.pattern_utils import load_pattern_sequences_for_operation
from compiler_idioms.instruction import Instruction
from compiler_idioms.match import Match
from icecream import ic

HEX_BASE = 16


# ic.disable()


class UnsignedDivisionInstructionSequence86(InstructionSequence):
    MUL = {"imul", "mul"}

    def __init__(self):
        sequences = load_pattern_sequences_for_operation("divu")
        # sequences = sorted(sequences, key=lambda x: len(x), reverse=False)
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
            ic(sequence)
            ic(sequence[: match.length])
            ic(match)
            return self.handle_match(match, original_constants, original_registers, sequence)

    def handle_match(
        self,
        match: Match,
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
        sequence,
    ):
        match.operation = "division unsigned"
        match.operand = self._get_register_operand(original_registers)
        if self._is_single_shift_right(sequence[: match.length]):
            return self._handle_unsigned_power_of_two_division(match, original_constants)
        return self._handle_unsigned_magic_numbers_division(match, original_constants, original_registers, sequence)

    @staticmethod
    def _get_register_operand(original_registers: Dict[str, str]):
        if "reg_1" not in original_registers:
            return original_registers.get("reg_0", [])
        return original_registers.get("reg_1", [])

    @staticmethod
    def _is_single_shift_right(sequence):
        return len(sequence) == 1 and sequence[0].mnemonic == "shr"

    @staticmethod
    def _handle_unsigned_power_of_two_division(match: Match, original_constants: Dict[str, str]):
        match.constant = 2 ** int(original_constants.get("const_0"), HEX_BASE)
        return match

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
        magic, imul_index = self._get_mul_constant_and_position(sequence, original_constants)
        if not magic:
            magic = self._backtrack_magic_number(imul_index, sequence, original_constants, original_registers)
        power = self._accumulate_shr_amount(sequence, original_constants)
        ic(sequence)
        ic(power)
        ic(power + 32)

        result = self.magic_table.get((magic, power + 32))
        ic(magic)
        ic()
        ic(result)

        # if self._starts_with_mul_not_shift(sequence, imul_index):
        #     result = self.magic_table.get((magic, power + 32))
        # else:
        #     # 56 (35) vs 7 (32)
        #     # 28
        #     result = self.magic_table.get((magic, power + 35))
        if not result:
            result = self._search_in_signed_magic_table(magic, power)
        if not result:
            result = self._deal_with_corner_cases_signed(magic, power)
        return result

    def _search_in_signed_magic_table(self, magic: int, power: int):
        """
        90 14 38 42 54 62 70 74
        """
        result = self.signed_magic_table.get((magic, power + 32))
        return result

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

    def _accumulate_shr_amount(self, sequence: List[Instruction], original_constants: Dict[str, str]) -> int:
        power = 0
        for x in sequence:
            if x.mnemonic == "shr":
                ic(x)
                for op in x.operands:
                    if op.startswith("const"):
                        power += int(original_constants.get(op), HEX_BASE)
                        ic(power)
        return power

    def _backtrack_magic_number(
        self, imul_index: int, sequence: List[Instruction], original_constants: Dict[str, str], original_registers: Dict[str, str]
    ) -> int:
        magic_number = 0
        mul_instr = sequence[imul_index]
        for anonymized_operand in mul_instr.operands:
            if anonymized_operand not in original_registers:
                register = "eax"
                lower = "ax"
            else:
                register = original_registers[anonymized_operand]
                lower = register[1:]

            for i in range(imul_index - 1, -1, -1):
                current_instr = sequence[i]
                if current_instr.mnemonic == "mov":
                    destination = current_instr.operands[0]
                    destination_register = original_registers.get(destination)
                    if destination_register == register or destination_register.endswith(lower):
                        if current_instr.operands[-1].startswith("const"):
                            magic_number = int(original_constants.get(current_instr.operands[-1]), HEX_BASE)
                            ic(magic_number)
                            break
                        else:
                            register = original_registers.get(current_instr.operands[-1])

        return magic_number

    def _starts_with_mul_not_shift(self, sequence: List[Instruction], mul_position):
        for i, instr in enumerate(sequence):
            if instr.mnemonic == "shr":
                return mul_position < i
        return False

    @staticmethod
    def _is_constant(anonymized_operand: str):
        return anonymized_operand.startswith("const")

    def _deal_with_corner_cases_signed(self, magic, shift_amount) -> int:
        # 76, 152
        ic()
        result = 0
        power = 32
        for i in range(20):
            new_magic = magic * (2 ** (shift_amount - 1)) - i
            new_pow = power + shift_amount + 2
            result = self.signed_magic_table.get((new_magic, new_pow))

            if result:
                ic("*****")
                ic(new_magic)
                ic(new_pow)
                ic(result)
                return result

        # 304, 608
        for i in range(20):
            new_magic = magic * (2 ** (shift_amount - 2)) - i
            new_power = power + shift_amount + 3
            result = self.signed_magic_table.get((new_magic, new_power))
            if result:
                ic("--------")
                ic(new_magic)
                ic(new_power)
                ic(result)
                return result

        # 1216
        for i in range(60):
            new_magic = magic * (2 ** (shift_amount - 4)) - i
            new_power = power + shift_amount + 2
            result = self.signed_magic_table.get((new_magic, new_power))
            if result:
                ic("ooooooooo")
                ic(new_magic)
                ic(new_power)
                ic(result)
                return result
        return result


if __name__ == "__main__":
    idiom = UnsignedDivisionInstructionSequence()
    print(idiom.magic_table)
