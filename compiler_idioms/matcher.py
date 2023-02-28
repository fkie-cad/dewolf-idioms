import sys
from typing import List

from compiler_idioms.anonymization import anonymize_instruction, anonymize_instructions_smda
from compiler_idioms.disassembly.smda_disassembly import SMDADisassembly
from compiler_idioms.idiom.implementations.divs_msvc import SignedDivisionInstructionSequence
from compiler_idioms.idiom.implementations.divu_msvc import UnsignedDivisionInstructionSequence
from compiler_idioms.idiom.implementations.mods_msvc import SignedModuloInstructionSequence
from compiler_idioms.idiom.implementations.modu_msvc import UnsignedModuloInstructionSequence
from compiler_idioms.idiom.implementations.multiplication import SignedMultiplicationInstructionSequence
from compiler_idioms.instruction import Instruction
from compiler_idioms.match import Match


class Matcher:
    """ """

    def __init__(self):
        self.idioms = [
            SignedModuloInstructionSequence(),
            UnsignedModuloInstructionSequence(),
            SignedDivisionInstructionSequence(),
            UnsignedDivisionInstructionSequence(),
            SignedMultiplicationInstructionSequence(),
        ]

    def find_idioms_in_file(self, file_path: str = "", bv=None, buffer=None) -> List[Match]:
        """ """
        # ic("Path:", file_path)

        matches = []
        disassembly = SMDADisassembly(file_path, buffer=buffer)
        for function in disassembly.next_disassembly_function():
            for i, instruction in enumerate(function):
                for idiom in self.idioms:
                    if instruction.matched:  # jump over matched instructions
                        continue
                    anonymized_first_instruction = anonymize_instruction(instruction)

                    if idiom.matches_first_instruction(anonymized_first_instruction):
                        anonymized_first_instructions, orig_constants, orig_registers = anonymize_instructions_smda(
                            function[i:])
                        if match := idiom.search(anonymized_first_instructions, orig_constants, orig_registers):
                            if not match:
                                continue
                            self._mark_instructions_as_matched(
                                function[i: i + match.length]
                            )  # +1? mark matched instructions to not to search for other idioms there
                            # yield match
                            for instr in function[i: i + match.length]:
                                match.addresses.append(instr.address)
                            matches.append(match)
        return matches

    @staticmethod
    def _mark_instructions_as_matched(instructions: List[Instruction]):
        for instr in instructions:
            instr.matched = True



if __name__ == "__main__":
    matcher = Matcher()
    matcher.find_idioms_in_file(sys.argv[1])
