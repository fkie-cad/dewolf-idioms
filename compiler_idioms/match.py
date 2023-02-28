from dataclasses import dataclass
from operator import attrgetter
from typing import List


@dataclass
class Match:
    address: int
    length: int
    operation: str = ""
    operand: str = ""
    constant: int = 0
    sequence: List[str] = list
    addresses: List[int] = list

    def __str__(self):
        op = {
            "division": "/",
            "division unsigned": "/u",
            "modulo": "%",
            "modulo unsigned": "%u",
            "multiplication": "*",
            "multiplication unsigned": "*u",
        }
        return f"Match at 0x{self.address:08x}: {self.operand} {op[self.operation]} {self.constant} ({'; '.join(map(attrgetter('mnemonic'), self.sequence))})"
