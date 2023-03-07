import json
import pathlib
import sys

from compiler_idioms.disassembly.disassembly import Disassembly
from compiler_idioms.instruction import Instruction
from icecream import ic
from smda.Disassembler import Disassembler

MNEMONICS_TO_CONSIDER = {"movsxd": "movsx"}


class SMDADisassembly(Disassembly):
    """
    Class that generates assembly in got from SMDA.
    """

    def __init__(self, path, buffer=None):
        self._disassembler = Disassembler()
        if not buffer:
            self.disassembly = self._disassembler.disassembleFile(path)
        else:
            self.disassembly = self._disassembler.disassembleBuffer(*buffer)

    # def next_disassembly_function(self):
    #     """Generates a disassembly block as a list of AssemblyInstruction-s"""
    #     for _, smda_function in self.disassembly.xcfg.items():
    #         assembly_lines = []
    #         for block, instructions in smda_function.blocks.items():
    #
    #             for smda_instruction in instructions:
    #                 operands = [
    #                     self._remove_spaces_in_indirect_memory_operands(op) for op in smda_instruction.operands.split(",")
    #                 ]
    #                 if smda_instruction.mnemonic in {"jns", "js", "jmp", "je", "jne", "ja", "jb", "jae", "jbe", "jge", "jle"}:
    #                     operands = []
    #                 assembly_lines.append(
    #                     Instruction(
    #                         smda_instruction.offset,
    #                         self._get_mnemonic_smda(smda_instruction.mnemonic),
    #                         tuple(operands),
    #                         matched=False
    #                     )
    #                 )
    #         yield assembly_lines
    #
    #     with pathlib.Path("diassembly.json").open('w') as f:
    #         json.dump(self.disassembly.toDict(), f, indent=4)
    #
    #     self.disassembly.toDict()

    def next_disassembly_function(self):
        """Generates a disassembly block as a list of AssemblyInstruction-s"""
        for smda_function in self.disassembly.getFunctions():
            assembly_lines = []
            # print(smda_function)
            for smda_instruction in smda_function.getInstructions():

                operands = [self._remove_spaces_in_indirect_memory_operands(op) for op in smda_instruction.operands.split(",")]
                if smda_instruction.mnemonic in {"jns", "js", "jmp", "je", "jne", "ja", "jb", "jae", "jbe", "jge", "jle"}:
                    operands = []
                assembly_lines.append(
                    Instruction(smda_instruction.offset, self._get_mnemonic_smda(smda_instruction.mnemonic), tuple(operands), matched=False)
                )
            yield assembly_lines

        # with pathlib.Path("disassembly.json").open("w") as f:
        #     json.dump(self.disassembly.toDict(), f, indent=4)

        self.disassembly.toDict()

    def get_smda_function_at(self, address):
        """Normalize smda function by removing jump target locations and spaces in indirect memory accesses"""
        smda_function = self.disassembly.getFunction(address)
        assembly_lines = []
        for smda_instruction in smda_function.getInstructions():
            operands = [self._remove_spaces_in_indirect_memory_operands(op) for op in
                        smda_instruction.operands.split(",")]
            if smda_instruction.mnemonic in {"jns", "js", "jmp", "je", "jne", "ja", "jb", "jae", "jbe", "jge", "jle"}:
                operands = []
            assembly_lines.append(
                Instruction(smda_instruction.offset, self._get_mnemonic_smda(smda_instruction.mnemonic),
                            tuple(operands), matched=False)
            )
        return assembly_lines


    @staticmethod
    def _remove_spaces_in_indirect_memory_operands(operand: str) -> str:
        """[edi + ecx*4] -> [edi+ecx*4] -- during comparing anonymized godbolt and smda instructions we don't want to have
        errors introduces by missing/extra spaces
        #TODO test ' dword ptr [ebp - 8]'
        """
        operand = operand.strip()
        return operand.replace(" ", "") if operand.startswith("[") else operand

    @staticmethod
    def _get_mnemonic_smda(mnemonic: str) -> str:
        """Some mnemonics differ between godbolt and smda.
        E.g. smda specifies movsxd (d shows operand type) and godbolt limits to movsx, more general version.
        For pattern more general version is important.
        In such cases we replace more specific version with more general one.
        Still, in most cases mnemonics are the same.
        """
        if (original_mnemonic := mnemonic) in MNEMONICS_TO_CONSIDER:  # do not delete brackets, ow orig is True or False and not mnemonic
            return MNEMONICS_TO_CONSIDER.get(original_mnemonic)
        if mnemonic == "sal":
            return "shl"
        if mnemonic in {"jns", "js", "jmp", "je", "jne", "ja", "jb", "jae", "jbe", "jge", "jle"}:
            operands = []
        return mnemonic


if __name__ == "__main__":
    da = SMDADisassembly(sys.argv[1])
    for bb in da.next_disassembly_function():
        print(bb)
