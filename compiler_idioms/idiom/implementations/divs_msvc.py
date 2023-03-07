import ctypes
from typing import Dict, List, Tuple

from compiler_idioms.idiom.instruction_sequence import InstructionSequence
from compiler_idioms.idiom.utils.magic import compute_magic_numbers_if_not_exists
from compiler_idioms.idiom.utils.magic_long import compute_magic_numbers_if_not_exists as compute_magic_long
from compiler_idioms.idiom.utils.pattern_utils import load_pattern_sequences_for_operation
from compiler_idioms.instruction import Instruction
from compiler_idioms.match import Match

HEX_BASE = 16
# ic.disable()


class SignedDivisionInstructionSequence(InstructionSequence):
    MUL = {"imul", "mul"}
    RIGHT_SHIFT = {"sar", "shr"}
    DIV = {"idiv", "div"}

    def __init__(self):
        self.abbrev_operation_name = "divs"
        self.operation_name = "division"
        sequences = load_pattern_sequences_for_operation(self.abbrev_operation_name)
        self.magic_table = compute_magic_numbers_if_not_exists()
        self.magic_table_long = compute_magic_long()
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
        match.operation = self.operation_name
        match.operand = self._get_register_operand(original_registers)
        if not (original_constants):
            # todo handle 03 -1
            match.constant = None
            return match
        # TODO handle idiv
        # todo let unsigned div to take care about shr reg const
        if match.length == 1 and sequence[0].mnemonic == "shr":
            return None
        # W match.length == 2 and sequence[0].mnemonic == 'mov' and sequence[1].mnemonic == 'shr': return None
        div = [x for x in sequence if x.mnemonic in self.DIV]
        if div:
            const = int(original_constants["const_0"], HEX_BASE)
            match.constant = ctypes.c_int32(const).value
            return match
        mul = [x for x in sequence if x.mnemonic in self.MUL]
        if not mul:
            match = self.handle_powers_of_two(match, original_constants, sequence[: match.length])
            return match
        match = self.handle_magic_numbers_division(match, original_constants, original_registers, sequence[: match.length])
        return match

    def handle_powers_of_two(
        self,
        match: Match,
        original_constants: Dict[str, str],
        sequence: List[Instruction],
    ):
        constant = None
        for i in sequence:
            if i.mnemonic == "sar":
                constant = i.operands[-1]
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
        return match

    def _get_register_operand(self, original_registers: Dict[str, str]):
        return original_registers.get("reg_1", [])

    def _get_original_constant_from_magic(
        self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]
    ) -> int:
        magic, imul_index = self._get_mul_constant_and_position(sequence, original_constants)
        if not magic:
            magic = self._backtrack_magic_number(imul_index, sequence, original_constants, original_registers)
        power = self._accumulate_shift_amount(sequence, original_constants)
        quotient = self._lookup(magic, power)
        if ctypes.c_int32(magic).value < 0:
            # case 7
            unsigned_magic = ctypes.c_uint32(magic).value
            quotient = self._lookup(unsigned_magic, power)
            if not quotient:
                negative_magic = ctypes.c_int32(magic).value
                quotient = self._lookup(negative_magic, power)

        if quotient and quotient < 0:
            return quotient
        if self._is_negative(original_constants, original_registers, sequence):
            quotient = -quotient
        if not quotient:
            quotient = self.magic_table_long.get((magic, 64 + power))

        return quotient

    def _lookup(self, magic: int, power: int) -> int:
        quotient = self._search_magic_table(magic, power)
        if not quotient:
            quotient = self._search_magic_table(magic, power + 32)
        return quotient

    def _is_negative(self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]) -> int:
        # case 3
        sign_reg = None
        sub_instr = None
        sign_index = 0
        sub_index = 0
        for i, instr in enumerate(sequence):
            if instr.mnemonic in self.RIGHT_SHIFT:
                destination = instr.operands[0]
                source = instr.operands[1]
                if self._is_constant(source):
                    val = int(original_constants.get(source), HEX_BASE)
                    if val == 31:
                        sign_reg = destination
                        sign_index = i
                        break

        for i, instr in enumerate(sequence):
            if instr.mnemonic == "sub":
                sub_instr = instr
                sub_index = i
        if not sign_reg:
            return False
        sign_reg = sequence[sign_index].operands[0]
        for i in range(sign_index, sub_index, 1):
            current = sequence[i]
            if current.mnemonic == "mov":
                if current.operands[-1] == sign_reg:
                    sign_reg = current.operands[0]
        if not sub_instr:
            return False

        if sub_instr.operands[0] == sign_reg:
            return True
        return False

    def _search_magic_table(self, magic: int, power: int) -> int:
        quotient = self.magic_table.get((magic, power))
        return quotient

    def _get_mul_constant_and_position(self, sequence: List[Instruction], original_constants: Dict[str, str]) -> Tuple[int, int]:
        magic = 0
        first_mul_index = 0
        for i, instr in enumerate(sequence):
            if instr.mnemonic in self.MUL:
                first_mul_index = i
                for op in instr.operands:
                    if self._is_constant(op):
                        magic = int(original_constants.get(op), HEX_BASE)
        return magic, first_mul_index

    def _accumulate_shift_amount(self, sequence: List[Instruction], original_constants: Dict[str, str]) -> int:
        result = 0
        for instr in sequence:
            if instr.mnemonic in self.RIGHT_SHIFT:
                for op in instr.operands:
                    if self._is_constant(op):
                        val = int(original_constants.get(op), HEX_BASE)
                        if val != 0x1F and val != 0x3F:
                            result += int(original_constants.get(op), HEX_BASE)
        return result

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
            if len(mul_instr.operands) == 1 and register == "ecx":
                register = "eax"

            for i in range(imul_index - 1, -1, -1):
                current_instr = sequence[i]
                if current_instr.mnemonic in {"mov", "movabs"}:
                    destination = current_instr.operands[0]
                    destination_register = original_registers.get(destination)
                    if destination_register == register or destination_register.endswith(lower):
                        if self._is_constant(current_instr.operands[-1]):
                            magic_number = int(original_constants.get(current_instr.operands[-1]), HEX_BASE)
                            return magic_number
                        else:
                            register = original_registers.get(current_instr.operands[-1])

        return magic_number

    @staticmethod
    def _is_constant(anonymized_operand: str) -> bool:
        return anonymized_operand.startswith("const")


if __name__ == "__main__":
    idiom = SignedDivisionInstructionSequence()
    print(idiom.magic_table)
