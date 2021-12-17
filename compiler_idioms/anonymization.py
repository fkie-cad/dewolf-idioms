import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from compiler_idioms.instruction import Instruction
from compiler_idioms.registers import INTELx64_REGISTERS
from icecream import ic

MNEMONICS_TO_CONSIDER = {"movsxd": "movsx", "shl": "sal"}
CONSTANT = "const_"
REGISTER = "reg_"
VARIABLE = "loc"

CONSTANT_PATTERN = re.compile(r"(-*0x[A-Fa-f\d]+|-*\d+)")  # hex and decimal, positive & negative
# local variables (byte ptr [ebp-8], qword ptr [esp], ...) and arguments (dword [ebp+8], ...)
VARIABLE_PATTERN = re.compile(r"((d*q*word|byte|(D*WORD)|BYTE)+\s(ptr|PTR)\s+\[(esp|ebp|rsp|rbp)+\s*(-|\+)*\s*([0-9]|0x[A-Fa-f0-9]+)*\])")
# eax, ax, rax, r8 etc.
REGISTER_PATTERN = re.compile(f'{"|".join(INTELx64_REGISTERS)}')


def anonymize_instruction(instr: Instruction):
    anonimized_instructions, _, _ = anonymize_instructions_smda([instr])
    return anonimized_instructions[0]


@dataclass
class AnonymizedNames:
    """
    contains mappings from anonymized operands to their original names for variables, constants and registers:

    variables: {loc0: 'qword ptr [esp]', loc1: 'qword ptr [esp+8]'}
    constants: {const_0: "4", const_1: '0xbad'}
    registers: {reg_0: 'eax', reg_1: 'rax'}
    """

    variables: dict = field(default_factory=dict)
    constants: dict = field(default_factory=dict)
    registers: dict = field(default_factory=dict)


@dataclass
class Counters:
    """
    keeps track on max counter for new anonymized name:

    variables: loc[max_counter]
    constants: const_[max_counter]
    registers: reg_[max_counter]
    """

    variables: int = 0
    constants: int = 0
    registers: int = 0


def anonymize_instructions_smda(
    instructions: List[Instruction], window: int = 25
) -> Tuple[List[Instruction], Dict[str, str], Dict[str, str]]:
    """
    :param instructions: list of instructions to be anonymized
    :return: list of anonymized instructions, mappings from anonymized operands to their original values (constants and registers only?)


    Instruction(address=2013, mnemonic='sar', operands=('eax', '0x1f'), matched=False),
    Instruction(address=2016, mnemonic='sub', operands=('edx', 'eax'), matched=False),
    Instruction(address=2018, mnemonic='mov', operands=('eax', 'edx'), matched=False),
    Instruction(address=2020, mnemonic='mov', operands=('dword ptr [rbp - 4]', 'eax'), matched=False),
                                         |
                                         V
    Instruction(address=2013, mnemonic='sar', operands=('reg_0', 'const_0'), matched=False),
    Instruction(address=2016, mnemonic='sub', operands=('reg_1', 'reg_0'), matched=False),
    Instruction(address=2018, mnemonic='mov', operands=('reg_0', 'reg_1'), matched=False),
    Instruction(address=2020, mnemonic='mov', operands=('loc0', 'reg_0'), matched=False),

    original constants:
    const_0 -> 0x1f

    original registers:
    reg_0 -> eax
    reg_1 -> edx
    """
    anonymized_instructions = []
    counters = Counters()
    anonymized_names = AnonymizedNames()
    for instr in instructions[0:window]:
        # mnemonic = _get_mnemonic_smda(instr)
        new_operands = []
        for operand in instr.operands:
            if not operand:
                continue
            anonymized_operand = _anonymize_operand(operand, counters, anonymized_names)
            new_operands.append(anonymized_operand)
        anonymized_instructions.append(Instruction(instr.address, instr.mnemonic, tuple(new_operands)))
    return anonymized_instructions, anonymized_names.constants, anonymized_names.registers


def _anonymize_operand(operand: str, counters: Counters, anonymizes_names: AnonymizedNames) -> str:
    # result = _remove_spaces_in_indirect_memory_operands(operand)
    result = operand

    for m in VARIABLE_PATTERN.finditer(result):
        variable = m.group(0)
        anonymized_variable = _get_anonymized_variable_name(variable, anonymizes_names, counters)
        result = result.replace(variable, anonymized_variable)
        # since locations are always copied to registers before operations,
        # if we found location in the operand it is the only one
        # DWORD PTR [ebp-4], eax -> operand 1: DWORD PTR [ebp-4] -> loc0
        # DWORD PTR [ebp-4] + ..., eax -> operand 1: DWORD PTR [ebp-4]+... <-WRONG
        if result == anonymized_variable:
            return result
        else:
            pass
            # raise Exception(f"Something except of variable in operand {operand} -> |{result}|")

    # TODO can it happen that constant replaces counter in other const_n
    for const in CONSTANT_PATTERN.findall(result):
        anonymized_constant = _get_anonymized_constant_name(const, anonymizes_names, counters)
        result = result.replace(const, anonymized_constant)

    for register in REGISTER_PATTERN.findall(result):
        anonymized_register = _get_anonymized_register_name(register, anonymizes_names, counters)
        result = result.replace(register, anonymized_register)

    return result


def _get_anonymized_variable_name(variable: str, anonymized_names: AnonymizedNames, counters: Counters) -> str:
    if variable not in (anonymized_variables := _reverse_dict(anonymized_names.variables)):
        anonymized_names.variables[(name := f"{VARIABLE}{counters.variables}")] = variable
        counters.variables += 1
        return name
    return anonymized_variables[variable]


def _get_anonymized_constant_name(matched_constant: str, anonymized_names: AnonymizedNames, counters: Counters) -> str:
    if matched_constant not in (anonymized_constants := _reverse_dict(anonymized_names.constants)):
        anonymized_names.constants[(name := f"{CONSTANT}{counters.constants}")] = matched_constant
        counters.constants += 1
        return name
    return anonymized_constants[matched_constant]


def _get_anonymized_register_name(register: str, anonymized_names: AnonymizedNames, counters: Counters) -> str:
    if register not in (anonymized_registers := _reverse_dict(anonymized_names.registers)):
        anonymized_names.registers[(name := f"{REGISTER}{counters.registers}")] = register
        counters.registers += 1
        return name
    return anonymized_registers[register]


def _reverse_dict(d: Dict) -> Dict:
    return {v: k for k, v in d.items()}


# def _remove_spaces_in_indirect_memory_operands(operand: str) -> str:
#     """[edi + ecx*4] -> [edi+ecx*4] -- during comparing anonymized godbolt and smda instructions we don't want to have
#     errors introduces by missing/extra spaces
#     TODO: should this be part of disassembly instead?
#     """
#     return operand.replace(" ", '') if operand.startswith('[') else operand
#
#
# def _get_mnemonic_smda(instr: Instruction) -> str:
#     """Some mnemonics differ between godbolt and smda.
#     E.g. smda specifies movsxd (d shows operand type) and godbolt limits to movsx, more general version.
#     For pattern more general version is important.
#     In such cases we replace more specific version with more general one.
#     Still, in most cases mnemonics are the same.
#
#     #TODO should this be part of disassembly instead?
#     """
#     if (
#             original_mnemonic := instr.mnemonic
#     ) in MNEMONICS_TO_CONSIDER:  # do not delete brackets, ow orig is True or False and not mnemonic
#         return MNEMONICS_TO_CONSIDER.get(original_mnemonic)
#     if instr.mnemonic == "sal":
#         return "shl"
#     if instr.mnemonic in {"jns", "js", "jmp", "je", "jne", "ja", "jb", "jae", "jbe", "jge", "jle"}:
#         instr.operands = []
#     return instr.mnemonic
