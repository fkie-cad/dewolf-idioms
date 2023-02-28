import ctypes
from typing import Dict, List, Tuple

from compiler_idioms.idiom.instruction_sequence import InstructionSequence
from compiler_idioms.idiom.utils.magic import compute_magic_numbers_if_not_exists as magic
from compiler_idioms.idiom.utils.magic_unsigend import compute_magic_numbers_if_not_exists as magic_unsigned
from compiler_idioms.idiom.utils.pattern_utils import load_pattern_sequences_for_operation
from compiler_idioms.instruction import Instruction
from compiler_idioms.match import Match

HEX_BASE = 16


# ic.disable()
class UnsignedDivisionInstructionSequence(InstructionSequence):
    MUL = {"imul", "mul"}
    DIV = {"div", "idiv"}

    def __init__(self):
        sequences = load_pattern_sequences_for_operation("divu")
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
        match.operation = "division unsigned"
        match.operand = self._get_register_operand(original_registers)
        div = [x for x in sequence if x.mnemonic in self.DIV]
        if div:
            return self.handle_patterns_with_div(match, original_constants)
        if self._is_single_shift_right(sequence[: match.length], original_constants):
            return self._handle_unsigned_power_of_two_division(match, original_constants)
        return self._handle_unsigned_magic_numbers_division(match, original_constants, original_registers, sequence)

    def handle_patterns_with_div(self, match, original_constants):
        const = int(original_constants["const_0"], HEX_BASE)
        original_constant = ctypes.c_int32(const).value
        match.constant = original_constant
        return match

    @staticmethod
    def _get_register_operand(original_registers: Dict[str, str]):
        if "reg_1" not in original_registers:
            return original_registers.get("reg_0", [])
        return original_registers.get("reg_1", [])

    @staticmethod
    def _is_single_shift_right(sequence, original_constants):
        return (len(original_constants.values()) == 1) or (len(sequence) == 1 and sequence[0].mnemonic == "shr")

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
        result = 0
        power = self._accumulate_shr_amount(sequence, original_constants)
        magic, mul_position = self._get_mul_constant_and_position(sequence, original_constants)
        if not magic:
            magic = self._backtrack_magic_number(mul_position, sequence, original_constants, original_registers)
        if self._starts_with_mul_not_shift(sequence, mul_position):
            result = self.magic_table.get((magic, power))
            if not result:
                result = self.magic_table.get((magic, power + 32))
        else:
            result = self.magic_table.get((magic, power + 5))
            if not result:
                result = self.magic_table.get((magic, power + 32 + 5))

        if not result:
            result = self._handle_as_signed(magic, power, sequence, original_constants)
            if not result:
                result = self._handle_as_signed(magic, power + 32, sequence, original_constants)
        return result

    def _handle_as_signed(self, magic, power, sequence: List[Instruction], original_constants: Dict[str, str]):
        result = self.signed_magic_table.get((magic, power))

        if not result:
            result = self.magic_table.get((magic, power + 3))
        if not result:
            for i in range(50):
                result = self.magic_table.get((magic - i, power + 3))
                if result:
                    break
        if not result:
            result = self._deal_with_corner_cases(magic, power, sequence, original_constants)
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

    @staticmethod
    def _is_constant(anonymized_operand: str):
        return anonymized_operand.startswith("const")

    def _deal_with_corner_cases(self, magic: int, power: int, sequence: List[Instruction], original_constants: Dict[str, str]):
        result = None
        shift_instr = None
        for i in sequence:
            if i.mnemonic == "shr":
                shift_instr = i
                break
        if not shift_instr:
            return 0

        shift = int(original_constants.get(shift_instr.operands[-1]), HEX_BASE)
        power += shift
        if shift < 32:

            for i in range(50):
                # 148 or 224
                new_magic = magic * (2 ** shift) - i
                result = self.signed_magic_table.get((new_magic, power))

                if result:
                    break
            if not result:
                # 152
                for i in range(50):
                    new_magic = magic * (2 ** (shift - 1)) - i
                    result = self.signed_magic_table.get((new_magic, power - 1))
                    if result:
                        break
            if not result:
                # 168
                for i in range(3):
                    new_magic = magic * (2 ** (shift - 2)) - i
                    # ic(new_magic)
                    # ic(power-shift+1)
                    result = self.signed_magic_table.get((new_magic, power - shift + 1))
                    if result:
                        break
            if not result:
                # 228
                for i in range(3):
                    new_magic = magic * (2 ** (shift + 2)) - i
                    # ic(new_magic)
                    # ic(power+shift)
                    result = self.signed_magic_table.get((new_magic, power + shift))
                    if result:
                        break

        if not result:
            new_magic = magic * (2 ** (shift + 1)) - 1
            result = self.signed_magic_table.get((new_magic, power + 1))

        if not result:
            # 280
            for i in range(8):
                new_magic = magic * (2 ** (shift + 1)) - i

                result = self.signed_magic_table.get((new_magic, power + shift - 2))
                if result:
                    break

        if not result:
            # 720
            for i in range(10):
                new_magic = magic * (2 ** (shift + 1)) - i
                # ic('----------------------')
                # ic(new_magic)
                # ic(power + shift - 3)

                result = self.signed_magic_table.get((new_magic, power + shift - 3))
                if result:
                    break

        if not result:
            # 1344, 672
            for i in range(12):
                new_magic = magic * 4 - i
                # ic(new_magic)
                result = self.signed_magic_table.get((new_magic, power - shift + 2))
                if result:
                    break

        if not result:
            # 336
            for i in range(3):
                new_magic = magic * (2) - i
                result = self.signed_magic_table.get((new_magic, power - shift + 1))
                if result:
                    break

        if not result:
            # 584
            for i in range(20):
                new_magic = magic * (2 ** (shift + 2)) - i
                result = self.signed_magic_table.get((new_magic, power + shift - 1))
                if result:
                    break

        if not result:
            # 608
            for i in range(20):
                new_magic = magic * (2 ** (shift - 2)) - i
                # ic(new_magic)
                # ic(power-shift+3)
                result = self.signed_magic_table.get((new_magic, power - shift + 3))
                if result:
                    break

        if not result:
            # 1218
            for i in range(25):
                new_magic = magic * (2 ** (shift - 3)) - i
                # ic(new_magic)
                # ic(power-shift+3)
                result = self.signed_magic_table.get((new_magic, power - shift + 3))
                if result:
                    break

        return result


if __name__ == "__main__":
    idiom = UnsignedDivisionInstructionSequence()
    print(idiom.magic_table)
