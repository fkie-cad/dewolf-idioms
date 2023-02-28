from typing import Dict, List

from compiler_idioms.idiom.instruction_sequence import InstructionSequence
from compiler_idioms.idiom.utils.magic import compute_magic_numbers_if_not_exists as magic
from compiler_idioms.idiom.utils.magic_unsigend import compute_magic_numbers_if_not_exists as magic_unsigned
from compiler_idioms.idiom.utils.pattern_utils import load_pattern_sequences_for_operation
from compiler_idioms.instruction import Instruction
from compiler_idioms.match import Match
from icecream import ic

HEX_BASE = 16

# ic.disable()
class UnsignedDivisionInstructionSequence(InstructionSequence):
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
            return self.handle_match(match, original_constants, original_registers, sequence[: match.length])

    def handle_match(
        self,
        match: Match,
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
        sequence,
    ):
        match.operation = "division unsigned"
        match.operand = self._get_register_operand(original_registers)
        if len(original_constants.values()) == 1:
            match.constant = 2 ** int(original_constants.get("const_0"), HEX_BASE)
            return match
        imul = [x for x in sequence if x.mnemonic in {"imul", "mul"}]
        if not imul:
            return self.handle_powers_of_two(match, original_constants, sequence)
        return self.handle_magic_numbers_division(match, original_constants, original_registers, sequence)

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
            if i.mnemonic in {"sar", "shr"}:
                constant = i.operands[1]
        if not constant:
            match.constant = None
            return match
        match.constant = 2 ** int(original_constants.get(constant), HEX_BASE)
        return match

    def handle_magic_numbers_division(
        self,
        match: Match,
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
        sequence: List[Instruction],
    ):
        ic()
        match.constant = self._get_original_constant_from_magic(original_constants, original_registers, sequence)
        return match

    def _get_register_operand(self, original_registers: Dict[str, str]):
        return original_registers.get("reg_1", [])

    def _get_original_constant_from_magic(
        self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]
    ) -> int:
        # case 3
        first_imul = False
        first_shift = False
        for instr in sequence:
            if instr.mnemonic == "shr":
                first_shift = True
                break
            if instr.mnemonic in {"imul", "mul"}:
                first_imul = True
                break
        if first_shift:
            return self._handle_as_signed(original_constants, original_registers, sequence)
        ic()
        magic = int(original_constants.get("const_0"), HEX_BASE)
        power = int(original_constants.get("const_1"), HEX_BASE)
        extra = 0
        ic(magic)
        if "const_2" in original_constants:
            extra = int(original_constants.get("const_2"), HEX_BASE)
            if extra < 0x1F:
                # case 5
                power += extra

        if "const_3" in original_constants:
            extra2 = int(original_constants.get("const_3"), HEX_BASE)
            power += extra2

        result = self.magic_table.get((magic, power))
        if not result:
            result = self.magic_table.get((magic, power + 32))
        # if not result:
        #     result = self._handle_as_signed86(original_constants, original_registers, sequence)
        return result

    def _handle_as_signed(self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]):
        magic = 0
        power = 0
        imul_index = 0
        for i, x in enumerate(sequence):
            if x.mnemonic in {"imul", "mul"}:
                imul_index = i
                for op in x.operands:
                    if op.startswith("const"):
                        magic = int(original_constants.get(op), HEX_BASE)

        imul = sequence[imul_index]
        if not magic:
            imul_op0 = imul.operands[0]
            imul_op1 = imul.operands[-1]
            original_register0 = original_registers[imul_op0]
            original_register1 = original_registers[imul_op1]
            lower0 = original_register0[1:]
            lower1 = original_register1[1:]

            for x in range(imul_index, 0, -1):
                current = sequence[x]
                if current.mnemonic == "mov":
                    register = original_registers[current.operands[0]]
                    if register == original_register0 or register.endswith(lower0):
                        if current.operands[-1].startswith("const"):
                            magic = int(original_constants.get(current.operands[-1]), HEX_BASE)
                            break
                    elif register == original_register1 or register.endswith(lower1):
                        if current.operands[-1].startswith("const"):
                            magic = int(original_constants.get(current.operands[-1]), HEX_BASE)
                            break
        for x in sequence:
            if x.mnemonic == "shr":
                for op in x.operands:
                    if op.startswith("const"):
                        power += int(original_constants.get(op), HEX_BASE)

        result = self.signed_magic_table.get((magic, power))
        if not result:
            result = self.signed_magic_table.get((magic, power + 32))
        if not result:
            result = self.magic_table.get((magic, power + 35))
        if not result:
            result = self.magic_table.get((magic, power + 3))

        if not result:
            for i in range(50):
                result = self.magic_table.get((magic - i, power + 3))
                if result:
                    break

        if not result:
            shift_instr = None
            for i in sequence:
                if i.mnemonic == "shr":
                    shift_instr = i
                    break
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

    def _handle_as_signed86(self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]):
        magic = 0
        imul_index = 0
        power = 32
        for i, x in enumerate(sequence):
            if x.mnemonic in {"imul", "mul"}:
                imul_index = i
                for op in x.operands:
                    if op.startswith("const"):
                        magic = int(original_constants.get(op), HEX_BASE)

        imul = sequence[imul_index]

        if not magic:
            imul_op0 = imul.operands[0]
            imul_op1 = imul.operands[-1]
            original_register0 = original_registers[imul_op0]
            original_register1 = original_registers[imul_op1]
            lower0 = original_register0[1:]
            lower1 = original_register1[1:]

            for x in range(imul_index, 0, -1):
                current = sequence[x]
                if current.mnemonic == "mov":
                    register = original_registers[current.operands[0]]
                    if register == original_register0 or register.endswith(lower0):
                        if current.operands[-1].startswith("const"):
                            magic = int(original_constants.get(current.operands[-1]), HEX_BASE)
                            break
                    elif register == original_register1 or register.endswith(lower1):
                        if current.operands[-1].startswith("const"):
                            magic = int(original_constants.get(current.operands[-1]), HEX_BASE)
                            break

        for x in sequence:
            if x.mnemonic == "shr":
                for op in x.operands:
                    if op.startswith("const"):
                        power += int(original_constants.get(op), HEX_BASE)

        result = self.signed_magic_table.get((magic, power))
        if not result:
            result = self.signed_magic_table.get((magic, power + 32))

        if not result:
            result = self.magic_table.get((magic, power + 3))

        if not result:
            for i in range(50):
                result = self.magic_table.get((magic - i, power + 3))
                if result:
                    break

        if not result:
            shift_instr = None
            for i in sequence:
                if i.mnemonic == "shr":
                    shift_instr = i
                    break
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

            # if not result:
            #     result = self.magic_table.get((magic, power + 3))
            #
            # if not result:
            #     for i in range(50):
            #         result = self.magic_table.get((magic-i, power + 3))
            #         if result:
            #             break

        return result


if __name__ == "__main__":
    idiom = UnsignedDivisionInstructionSequence()
    print(idiom.magic_table)
