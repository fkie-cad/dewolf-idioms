from dataclasses import dataclass
from typing import List


@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: tuple
    matched: bool = False


def from_anonymized_pattern(anonymized_pattern: List) -> List[Instruction]:
    """Creates Instruction-s list from anonymized pattern ("parsed" part from anon_asm.json)"""
    result = []
    for item in anonymized_pattern:
        result.append(Instruction(-1, item.get("opcode"), tuple(item.get("operands"))))
    return result


if __name__ == "__main__":
    pattern = [
        {
            "opcode": "movsx",
            "operands": ["reg_0", "reg_1"],
            "text": "movsx reg_0, reg_1",
        },
        {
            "opcode": "imul",
            "operands": ["reg_0", "reg_0", "const_0"],
            "text": "imul reg_0, reg_0, const_0",
        },
        {
            "opcode": "shr",
            "operands": ["reg_0", "const_1"],
            "text": "shr reg_0, const_1",
        },
        {
            "opcode": "sar",
            "operands": ["reg_1", "const_2"],
            "text": "sar reg_1, const_2",
        },
        {"opcode": "sub", "operands": ["reg_1", "reg_2"], "text": "sub reg_1, reg_2"},
    ]
    print(from_anonymized_pattern(pattern))
