from abc import ABC, abstractmethod


class Disassembly(ABC):
    @abstractmethod
    def next_disassembly_function(self):
        pass
