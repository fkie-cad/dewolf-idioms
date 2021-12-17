from typing import Dict, List

from compiler_idioms.idiom.idiom import Idiom
from compiler_idioms.instruction import Instruction
from compiler_idioms.match import Match
from icecream import ic

SHIFTS = {"sar", "sal", "shl", "shr"}


class InstructionSequence(Idiom):
    def __init__(self, sequences):
        """
        :param sequences: list? (what about set?) of patterns-/idiom-sequences
        Each idiom-sequence is a list of anonymized instructions with address -1
        """
        self.__sequences = sequences
        self._last_matched_index = 0

    def matches_first_instruction(self, instruction: Instruction) -> bool:
        return any(self._equal(instruction, idiom_seq[0]) for idiom_seq in self.__sequences)

    def search(self, sequence: List[Instruction], original_constants: Dict[str, str], original_registers: Dict[str, str]) -> Match:
        # we need to order the sequences from long to short to ensure that no incomplete idiom is matched.

        # Do not remove before we match all operations
        # one-liner is a hell for debugging
        for i, idiom_seq in sorted(enumerate(self.__sequences), key=lambda x: len(x[1]), reverse=True):
            if len(sequence) >= len(idiom_seq):
                paars = [(idiom_instr, sequence_instr) for idiom_instr, sequence_instr in zip(idiom_seq, sequence[: len(idiom_seq)])]
                # if sequence[0].address == 4560:
                #     if len(idiom_seq) > 4 and idiom_seq[2].mnemonic == 'imul' and idiom_seq[0].mnemonic == 'mov' and idiom_seq[3].mnemonic == 'sar':
                #         ic(paars)

                if all([self._equal(x, y, original_constants) for x, y in paars]):
                    # ic()
                    # ic('KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK')
                    # ic(hex(sequence[0].address))
                    self._last_matched_index = i
                    return Match(address=sequence[0].address, length=len(idiom_seq), sequence=idiom_seq)
            # if len(sequence) >= len(idiom_seq) and all(self._equal(idiom_instr, sequence_instr) for idiom_instr, sequence_instr in zip(idiom_seq, sequence[:len(idiom_seq)])):
            #     return Match(address=sequence[0].address, length=len(idiom_seq))

    def _equal(self, idiom_seq_instruction: Instruction, instruction: Instruction, original_constants: Dict[str, str] = None) -> bool:
        """
        We ignore the address of instruction when comparing with idiom instruction that has address -1
        """
        return (instruction.mnemonic, instruction.operands) == (idiom_seq_instruction.mnemonic, idiom_seq_instruction.operands)
