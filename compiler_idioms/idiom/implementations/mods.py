import ctypes
from typing import Dict, List

from compiler_idioms.idiom.instruction_sequence import InstructionSequence
from compiler_idioms.idiom.utils.magic import compute_magic_numbers_if_not_exists
from compiler_idioms.idiom.utils.pattern_utils import load_pattern_sequences_for_operation
from compiler_idioms.instruction import Instruction
from compiler_idioms.match import Match
from icecream import ic

HEX_BASE = 16

# ic.disable()
class SignedModuloInstructionSequence(InstructionSequence):
    def __init__(self):
        sequences = load_pattern_sequences_for_operation("mods")
        self.magic_table = compute_magic_numbers_if_not_exists()
        super().__init__(sequences)

    def search(
        self,
        sequence: List[Instruction],
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
    ) -> Match:
        if match := super().search(sequence, original_constants, original_registers):
            ic()
            match.operation = "modulo"
            match.operand = self._get_register_operand(original_registers)
            imul_instr = [x for x in sequence if x.mnemonic in {"imul", "mul"}]
            ic(imul_instr)
            if not imul_instr:
                # if len(original_constants.values()) == 2:
                return self.handle_powers_of_two(match, original_constants, sequence)
            return self.handle_magic_numbers_modulo(match, original_constants, original_registers, sequence)

    # def handle_match(
    #         self,
    #         match: Match,
    #         original_constants: Dict[str, str],
    #         original_registers: Dict[str, str],
    #         sequence,
    # ):
    #     ic()
    #     match.operation = "modulo"
    #     match.operand = self._get_register_operand(original_registers)
    #     imul_instr = [x for x in sequence if x.mnemonic == 'imul']
    #     if not imul_instr:
    #         ic()
    #         return self.handle_powers_of_two(match, original_constants, sequence)
    #     return self.handle_magic_numbers_modulo(match, original_constants, original_registers, sequence)

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
                constant = i.operands[1]
                break
        if not constant:
            match.constant = None
            return match
        match.constant = int(original_constants.get(constant), HEX_BASE) + 1
        return match

    def handle_magic_numbers_modulo(
        self,
        match: Match,
        original_constants: Dict[str, str],
        original_registers: Dict[str, str],
        sequence: List[Instruction],
    ):
        match.constant = self._get_original_constant_from_magic(original_constants, original_registers, sequence)
        return match

    def _get_register_operand(self, original_registers: Dict[str, str]):
        return original_registers.get("reg_1", [])

    def _get_original_constant_from_magic(
        self, original_constants: Dict[str, str], original_registers: Dict[str, str], sequence: List[Instruction]
    ) -> int:
        # case 3
        # magic = int(original_constants.get("const_0"), HEX_BASE)
        # power = int(original_constants.get("const_1"), HEX_BASE)
        # extra = int(original_constants.get("const_2"), HEX_BASE)
        # if extra < 0x1F:
        #     # case 5
        #     power += extra
        # if ctypes.c_int32(magic).value < 0:
        #     # case 7
        #     magic = ctypes.c_uint32(magic).value
        magic = 0
        power = 0
        extra = 0
        imul = None
        imul_index = 0
        for i, instr in enumerate(sequence):
            if instr.mnemonic in {"imul", "mul"} and magic == 0:
                imul = instr
                imul_index = i
                ic()
                ic(imul)
                for op in instr.operands:
                    if op.startswith("const"):
                        magic = int(original_constants.get(op), HEX_BASE)
                        ic(magic)
                        break
                break

        if not magic and imul:
            ic(imul)
            ic(original_constants)
            ic(original_registers)
            imul_op0 = imul.operands[0]
            imul_op1 = imul.operands[-1]
            original_register0 = original_registers[imul_op0] if imul_op1 in original_registers else None
            original_register1 = original_registers[imul_op1] if imul_op1 in original_registers else None
            lower0 = original_register0[1:] if original_register0 else None
            lower1 = original_register1[1:] if original_register1 else None
            ic(imul)

            for x in range(imul_index, -1, -1):

                current = sequence[x]
                if current.mnemonic == "mov":
                    register = original_registers[current.operands[0]]
                    ic(current)
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
        # ic(magic)
        # ic(power)

        if ctypes.c_int32(magic).value < 0:
            # case 7
            magic = ctypes.c_uint32(magic).value
        # return self.magic_table.get((magic, power))
        quotient = self.magic_table.get((magic, power))
        if not quotient:
            # x86
            ic()
            ic(magic)
            ic(power)
            ic(power + 32)
            quotient = self.magic_table.get((magic, power + 32))
        return quotient
        return self.magic_table.get((magic, power))


if __name__ == "__main__":
    idiom = SignedModuloInstructionSequence()
    print(idiom.magic_table)
