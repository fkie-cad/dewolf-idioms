from abc import ABC, abstractmethod
from typing import Dict, List

from compiler_idioms.instruction import Instruction
from compiler_idioms.match import Match


class Idiom(ABC):
    """
    Abstract class to represent either a single idiom of a set of idioms
    """

    @abstractmethod
    def matches_first_instruction(self, instruction: Instruction) -> bool:
        """
        Returns whether the given instruction could be the first instruction of this idiom.
        """
        return False

    @abstractmethod
    def search(self, sequence: List[Instruction], original_constants: Dict[str, str], original_registers: Dict[str, str]) -> Match:
        """ """
        pass
